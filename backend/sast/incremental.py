"""Incremental scans and scan-to-scan comparison.

- file_hashes(): content hash of every discovered file, stored with each scan
- changed_since(): files whose hash differs from a baseline scan (or that are new)
- git_changed(): files changed since a git ref (CI: only what a pull request touches)
- with_neighbours(): add files that import, or are imported by, a changed file, so data flow
  across files is re-analyzed on both sides
- compare(): mark findings new/existing against a baseline and list what was fixed
"""
import hashlib
import re
import subprocess
from pathlib import Path, PurePosixPath

PY_IMPORT = re.compile(r"^\s*(?:from\s+([.\w]+)\s+import|import\s+([.\w]+))", re.M)
JS_IMPORT = re.compile(r"""(?:require\(\s*|from\s+)["'`](\.{1,2}/[^"'`]+)["'`]""")


def file_hashes(repo):
    out = {}
    for sf in repo.files:
        try:
            out[sf.rel] = hashlib.sha256(Path(sf.path).read_bytes()).hexdigest()[:16]
        except OSError:
            pass
    return out


def changed_since(hashes, baseline):
    old = (baseline or {}).get("repo", {}).get("file_hashes") or {}
    return {rel for rel, h in hashes.items() if old.get(rel) != h}


def git_changed(root, base):
    """Files changed since `base` (committed, staged, unstaged and untracked), relative to `root`."""
    root = Path(root).resolve()

    def git(*args):
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
        return r.stdout

    top = Path(git("rev-parse", "--show-toplevel").strip())
    names = set(git("diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD").split())
    names |= set(git("diff", "--name-only", "--diff-filter=ACMR").split())
    names |= set(git("diff", "--name-only", "--cached", "--diff-filter=ACMR").split())
    names |= set(git("ls-files", "--others", "--exclude-standard").split())
    out = set()
    for n in names:
        p = (top / n).resolve()
        try:
            out.add(p.relative_to(root).as_posix())
        except ValueError:
            pass  # outside the scanned folder
    return out


def _module_names(rel):
    p = PurePosixPath(rel)
    parts = list(p.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return {".".join(parts[i:]) for i in range(len(parts))}


def with_neighbours(changed, repo, texts):
    """changed + files that import a changed file + files a changed file imports (one hop)."""
    rels = {sf.rel: sf for sf in repo.files}
    by_module = {}
    for rel, sf in rels.items():
        if sf.language == "python":
            for m in _module_names(rel):
                by_module.setdefault(m, set()).add(rel)

    def imports(rel):
        sf, text = rels.get(rel), "\n".join(texts.get(rel, []))
        found = set()
        if sf is None:
            return found
        if sf.language == "python":
            for m in PY_IMPORT.finditer(text):
                name = (m.group(1) or m.group(2)).lstrip(".")
                found |= by_module.get(name, set())
                for imp in re.findall(r"import\s+([\w, ]+)", text[m.start():m.start() + 200].split("\n")[0])[:1]:
                    for n in imp.split(","):
                        found |= by_module.get(f"{name}.{n.strip()}" if name else n.strip(), set())
        elif sf.language in {"javascript", "typescript"}:
            base = PurePosixPath(rel).parent
            for spec in JS_IMPORT.findall(text):
                target = str(PurePosixPath(base, spec)).replace("\\", "/")
                parts = []
                for part in target.split("/"):
                    if part == "..":
                        parts = parts[:-1]
                    elif part not in {".", ""}:
                        parts.append(part)
                target = "/".join(parts)
                for ext in ("", ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", "/index.js", "/index.ts"):
                    if target + ext in rels:
                        found.add(target + ext)
        return found

    graph = {rel: imports(rel) for rel in rels}
    out = set(changed) | {rel for rel, deps in graph.items() if deps & changed}  # + files importing a change
    while True:  # + everything those files import (transitively), so calls into them still resolve
        more = set().union(*(graph.get(r, set()) for r in out)) - out
        if not more:
            return out
        out |= more


def fingerprint(f, seen):
    """Stable identity of a finding across scans: file, rule and the flagged code, not the line number."""
    d = f if isinstance(f, dict) else f.to_dict()
    code = " ".join(d.get("snippet", "").split())
    base = f"{d['file']}|{d['rule_id']}|{d['category']}|{code}"
    n = seen.get(base, 0)
    seen[base] = n + 1
    return hashlib.sha256(f"{base}|{n}".encode()).hexdigest()[:16]


def compare(findings, baseline):
    """Set finding.status to new/existing and summarise the difference from the baseline scan."""
    old_seen, new_seen = {}, {}
    old = {fingerprint(f, old_seen): f for f in baseline.get("findings", [])}
    current = set()
    for f in findings:
        fp = fingerprint(f, new_seen)
        f.fingerprint = fp
        f.status = "existing" if fp in old else "new"
        current.add(fp)
    fixed = [{k: f[k] for k in ("title", "severity", "file", "line", "category")}
             for fp, f in old.items() if fp not in current]
    return {
        "baseline_id": baseline.get("id"), "baseline_started_at": baseline.get("started_at"),
        "new": sum(1 for f in findings if f.status == "new"),
        "existing": sum(1 for f in findings if f.status == "existing"),
        "fixed": len(fixed), "fixed_findings": fixed,
    }
