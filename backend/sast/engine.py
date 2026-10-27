"""Scan orchestration: discovery -> detectors -> dedupe -> taxonomy -> optional AI -> summary."""
import ast
import difflib
import math
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .ast_go import AVAILABLE as GO_AST_AVAILABLE
from .ast_go import scan_go
from .ast_java import _PARSER as JAVA_PARSER
from .ast_java import AVAILABLE as JAVA_AST_AVAILABLE
from .ast_java import scan_java
from .ast_js import _PARSERS as JS_PARSERS
from .ast_js import AVAILABLE as JS_AST_AVAILABLE
from .ast_js import JSProject
from .ast_python import PythonProject
from .llm import FUNCTION_START
from .deps import scan_dependencies
from .discovery import discover
from .models import SEVERITY_ORDER, Finding
from .rules import scan_rules
from .incremental import changed_since, compare, file_hashes, with_neighbours
from .secret_scan import _match_line as match_secret
from .secret_scan import mask, scan_secrets
from .taxonomy import enrich

CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
DETECTOR_RANK = {"ast-python": 3, "ast-js": 3, "ast-java": 3, "ast-go": 3, "secrets": 2, "rules": 1, "deps": 1, "ai": 0}
SEVERITY_WEIGHT = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
CODE_LANGS = {"python", "javascript", "typescript", "java", "go"}


def scan(target, ai=False, ai_review=False, model=None, ai_limit=15, progress=None, scan_id=None,
         baseline=None, incremental=False, changed_files=None):
    """Scan `target`.

    baseline: a previous scan result of the same target. Findings are then marked new/existing
    and result["comparison"] lists what was fixed.
    incremental: with a baseline, re-analyze only files whose content changed (plus files that
    import them or that they import) and reuse the baseline's findings for the rest.
    changed_files: re-analyze only these repo-relative paths (CI: files changed since a git ref).
    """
    say = progress or (lambda msg: None)
    started = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    say("Discovering files")
    repo = discover(target)
    hashes = file_hashes(repo)
    texts, sources = {}, {}
    for sf in repo.files:
        try:
            sources[sf.rel] = Path(sf.path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        texts[sf.rel] = sources[sf.rel].splitlines()

    analyze, reused = {sf.rel for sf in repo.files}, []
    inc = None
    if changed_files is not None or (incremental and baseline and baseline.get("repo", {}).get("file_hashes")):
        changed = (set(changed_files) & analyze) if changed_files is not None else changed_since(hashes, baseline)
        analyze = with_neighbours(changed, repo, texts)
        if baseline:  # keep the baseline's findings for files that were not re-analyzed
            keep = (set(hashes) | set(repo.dependencies)) - analyze  # manifests are not source files
            fields = set(Finding.__dataclass_fields__)
            reused = [Finding(**{k: v for k, v in f.items() if k in fields}) for f in baseline.get("findings", [])
                      if f["file"] in keep]
        inc = {"mode": "git" if changed_files is not None else "content-hash", "changed": sorted(changed),
               "rescanned": len(analyze), "reused_files": len(hashes) - len(analyze),
               "reused_findings": len(reused)}
        say(f"Incremental: {len(changed)} changed, re-analyzing {len(analyze)} of {len(repo.files)} files")
    else:
        say(f"Scanning {len(repo.files)} files ({repo.total_loc} LOC)")

    findings = []
    python = PythonProject()  # all Python files together, so taint can cross files
    javascript = JSProject()
    for sf in repo.files:
        if sf.rel not in analyze or sf.rel not in sources:
            continue
        text, lines = sources[sf.rel], texts[sf.rel]
        findings += scan_secrets(sf, lines)
        if sf.language == "python":
            python.add(sf, text, lines)
        elif sf.language in {"javascript", "typescript"}:
            if JS_AST_AVAILABLE:
                javascript.add(sf, text, lines)
            else:
                findings += scan_rules(sf, lines, js_fallback=True)
        elif sf.language == "java" and JAVA_AST_AVAILABLE:
            findings += scan_java(sf, text, lines)
        elif sf.language == "go" and GO_AST_AVAILABLE:
            findings += scan_go(sf, text, lines)
        elif sf.language != "config":
            findings += scan_rules(sf, lines)
    findings += python.run()
    findings += javascript.run()
    if inc is None or set(repo.dependencies) & analyze or not baseline:
        findings += scan_dependencies(repo.root, repo.dependencies)
    else:  # no manifest changed: dependency advisories are the baseline's
        findings += [f for f in reused if f.detector == "deps"]
        reused = [f for f in reused if f.detector != "deps"]
    findings = [enrich(f) for f in _dedupe(findings)] + reused
    static_seconds = time.perf_counter() - started

    ai_status = {"enabled": False, "detail": "AI analysis not requested"}
    if ai or ai_review:
        from .llm import LocalLLM
        llm = LocalLLM(model)
        ok, detail = llm.status()
        ai_status = {"enabled": ok, "model": llm.model, "detail": detail, "triaged": 0, "reviewed_files": 0}
        if ok and ai:
            ai_status["triaged"] = _triage(llm, findings, texts, ai_limit, say)
            ai_status["patched"] = attach_patches(findings, texts)
        if ok and ai_review:
            new = _review(llm, repo, texts, findings, say, only=analyze)
            ai_status["reviewed_files"] = new[0]
            findings += new[1]

    findings.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.file, f.line))
    comparison = compare(findings, baseline) if baseline else None
    if comparison is not None:
        comparison["incremental"] = inc
    duration = time.perf_counter() - started
    say("Done")
    return {
        "id": scan_id or uuid.uuid4().hex[:12],
        "tool": {"name": "Local AI SAST Engine", "version": __version__},
        "target": str(Path(target).resolve()),
        "started_at": started_at,
        "duration_seconds": round(duration, 2),
        "static_seconds": round(static_seconds, 3),
        "repo": {
            "files_scanned": len(repo.files), "skipped": repo.skipped, "total_loc": repo.total_loc,
            "languages": repo.languages, "dependency_manifests": repo.dependencies,
            "js_engine": "tree-sitter" if JS_AST_AVAILABLE else "regex-fallback",
            "java_engine": "tree-sitter" if JAVA_AST_AVAILABLE else "regex-fallback",
            "go_engine": "tree-sitter" if GO_AST_AVAILABLE else "regex-fallback",
            "file_hashes": hashes,
        },
        "incremental": inc,
        "comparison": comparison,
        "ai": ai_status,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
        "fix_patch": combined_patch(findings, texts),
    }


def _replacement(lines, line, fixed_code):
    """The AI's fixed line(s), indented like the line they replace; None if unusable or unchanged."""
    code = fixed_code.strip("\n")
    if not code.strip() or not (0 < line <= len(lines)):
        return None
    new = code.splitlines()
    indent = lines[line - 1][: len(lines[line - 1]) - len(lines[line - 1].lstrip())]
    if not new[0].startswith((" ", "\t")):
        new = [indent + l if l.strip() else l for l in new]
    if [l.rstrip() for l in new] == [lines[line - 1].rstrip()]:
        return None
    if len(new) > 8 or (any(FUNCTION_START.match(l) for l in new) and not FUNCTION_START.match(lines[line - 1])):
        return None  # the model rewrote the whole function instead of the flagged line
    return new


def _parses(file, language, lines):
    """True if the patched file is still syntactically valid (a broken fix is worse than none)."""
    text = "\n".join(lines) + "\n"
    if language == "python":
        try:
            ast.parse(text)
            return True
        except SyntaxError:
            return False
    parser = JS_PARSERS.get("tsx" if file.endswith(".tsx") else language) if language != "java" else JAVA_PARSER
    if parser is None:
        return True  # no parser for this language: keep the suggestion, it is shown for review anyway
    return not parser.parse(text.encode("utf-8")).root_node.has_error


def _diff(file, old, new):
    return "\n".join(difflib.unified_diff(old, new, f"a/{file}", f"b/{file}", lineterm="")) + "\n"


def _mask_secrets(patch):
    """Mask secrets on every diff line (changed and context), as finding snippets are masked."""
    out = []
    for line in patch.split("\n"):
        hit = match_secret(line[1:]) if line[:1] in {" ", "+", "-"} and not line.startswith(("---", "+++")) else None
        out.append(line.replace(hit[3], mask(hit[3])) if hit else line)
    return "\n".join(out)


def attach_patches(findings, texts):
    """Turn each AI fixed_code into a unified diff against the real file (finding.ai["patch"])."""
    count = 0
    for f in findings:
        if not f.ai or f.ai.get("verdict") == "false_positive" or not f.ai.get("fixed_code"):
            continue
        lines = texts.get(f.file, [])
        new = _replacement(lines, f.line, f.ai["fixed_code"])
        if new is None:
            continue
        patched = lines[: f.line - 1] + new + lines[f.line:]
        if not _parses(f.file, f.language, patched):
            f.ai["patch_rejected"] = "The suggested fix does not parse, so no patch was produced."
            continue
        f.ai["patch"] = _mask_secrets(_diff(f.file, lines, patched))
        count += 1
    return count


def combined_patch(findings, texts):
    """One patch with every AI fix, applied bottom-up per file so line numbers stay valid (git apply)."""
    by_file = {}
    for f in findings:
        if f.ai and f.ai.get("patch"):
            by_file.setdefault(f.file, []).append(f)
    out = []
    for file, items in sorted(by_file.items()):
        lines = list(texts.get(file, []))
        new_lines, done = list(lines), set()
        for f in sorted(items, key=lambda x: -x.line):
            new = _replacement(lines, f.line, f.ai["fixed_code"])
            if new is not None and f.line not in done:  # two findings on one line: keep the first fix
                done.add(f.line)
                new_lines[f.line - 1: f.line] = new
        out.append(_diff(file, lines, new_lines))
    return "".join(out)


def _dedupe(findings):
    best = {}
    for f in findings:
        k = f.key()
        cur = best.get(k)
        if cur is None or (CONFIDENCE_RANK.get(f.confidence, 0), DETECTOR_RANK.get(f.detector, 0)) > \
                (CONFIDENCE_RANK.get(cur.confidence, 0), DETECTOR_RANK.get(cur.detector, 0)):
            best[k] = f
    return list(best.values())


def _triage(llm, findings, texts, limit, say):
    # Findings reused from a baseline scan keep their earlier AI result
    queue = [f for f in findings if f.severity in {"critical", "high"} and f.detector != "deps" and not f.ai]
    queue.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    done = 0
    for i, f in enumerate(queue[:limit], 1):
        say(f"AI triage {i}/{min(limit, len(queue))}: {f.title} in {f.file}:{f.line}")
        for attempt in range(2):  # first call can fail while Ollama loads the model into VRAM
            try:
                f.ai = llm.triage(f, texts.get(f.file, []))
                done += 1
                break
            except Exception as exc:  # one slow/failed call must not kill the scan
                f.ai = {"verdict": "needs_review", "explanation": f"AI analysis failed: {exc}"}
    return done


def _review(llm, repo, texts, findings, say, max_files=4, only=None):
    route_markers = ("@app.route", ".route(", "app.get(", "app.post(", "router.", "@router.", "@admin.")
    candidates = [sf for sf in repo.files if sf.language in CODE_LANGS and (only is None or sf.rel in only)
                  and any(m in "\n".join(texts.get(sf.rel, [])) for m in route_markers)]
    # The model tends to restate nearby static findings a line or two off; keep only new territory
    existing = {}
    for f in findings:
        existing.setdefault(f.file, []).append(f.line)
    near_existing = lambda file, line: any(abs(line - l) <= 4 for l in existing.get(file, []))
    new = []
    for i, sf in enumerate(candidates[:max_files], 1):
        say(f"AI code review {i}/{min(max_files, len(candidates))}: {sf.rel}")
        try:
            issues = llm.review_file(sf.rel, "\n".join(texts[sf.rel]))
        except Exception:
            continue
        lines = texts[sf.rel]
        for issue in issues:
            line = issue["line"] if 0 < issue["line"] <= len(lines) else 1
            if near_existing(sf.rel, line):
                continue
            sev = issue["severity"] if issue["severity"] in SEVERITY_ORDER else "medium"
            f = enrich(Finding(
                rule_id="AI-REVIEW", title=issue["title"], category=issue["category"], severity=sev,
                file=sf.rel, line=line, snippet=lines[line - 1].strip()[:300] if lines else "",
                message=issue["explanation"], detector="ai", confidence="low",
                language=sf.language, remediation=issue["fix"]))
            f.ai = {"model": llm.model, "verdict": "needs_review", "explanation": issue["explanation"],
                    "fix": issue["fix"], "source": "ai-review"}
            new.append(f)
    return min(max_files, len(candidates)), new


def summarize(findings):
    by_sev = {s: 0 for s in ("critical", "high", "medium", "low")}
    by_cat, by_owasp, by_cwe, by_file, by_detector = {}, {}, {}, {}, {}
    penalty = new_count = 0
    for f in findings:
        if f.ai and f.ai.get("verdict") == "false_positive":
            continue
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        if f.status == "new":
            new_count += 1
        for bucket, key in ((by_cat, f.category), (by_owasp, f.owasp), (by_cwe, f.cwe),
                            (by_file, f.file), (by_detector, f.detector)):
            bucket[key] = bucket.get(key, 0) + 1
        penalty += SEVERITY_WEIGHT.get(f.severity, 0)
    score = round(100 * math.exp(-penalty / 150))
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return {
        "total": sum(by_sev.values()),
        "ai_false_positives": sum(1 for f in findings if f.ai and f.ai.get("verdict") == "false_positive"),
        "by_severity": by_sev, "by_category": by_cat, "by_owasp": dict(sorted(by_owasp.items())),
        "by_cwe": by_cwe, "by_file": dict(sorted(by_file.items(), key=lambda kv: -kv[1])),
        "by_detector": by_detector, "security_score": score, "grade": grade,
        "secrets_exposed": by_cat.get("hardcoded_secret", 0),
        "new_since_last": new_count,
    }
