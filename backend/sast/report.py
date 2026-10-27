"""Report exporters: JSON, SARIF 2.1.0, self-contained HTML, and PDF (via headless Edge/Chrome)."""
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .taxonomy import CATEGORIES

TEMPLATES = Path(__file__).resolve().parent / "templates"
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))


def to_json(result):
    # fix_patch holds unmasked source lines (git apply needs them); it is exported only as the .patch file
    return json.dumps({k: v for k, v in result.items() if k != "fix_patch"}, indent=2)


def to_sarif(result):
    rules, index = [], {}
    results = []
    for f in result["findings"]:
        rid = f["rule_id"]
        if rid not in index:
            index[rid] = len(rules)
            rules.append({
                "id": rid, "name": f["title"],
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": CATEGORIES.get(f["category"], ("", "", "", "", ""))[0] or f["title"]},
                "help": {"text": f["remediation"]},
                "properties": {"tags": ["security", f["cwe"], f["owasp"]],
                               "security-severity": SECURITY_SEVERITY.get(f["severity"], "5.0")},
            })
        msg = f["message"]
        if f.get("ai") and f["ai"].get("explanation"):
            msg += f" AI ({f['ai'].get('verdict')}): {f['ai']['explanation']}"
        results.append({
            "ruleId": rid, "ruleIndex": index[rid], "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": msg},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f["file"], "uriBaseId": "SRCROOT"},
                "region": {"startLine": max(1, f["line"]), "snippet": {"text": f["snippet"]}}}}],
            "properties": {"severity": f["severity"], "category": f["category"], "cwe": f["cwe"],
                           "owasp": f["owasp"], "confidence": f["confidence"], "detector": f["detector"]},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": result["tool"]["name"], "version": result["tool"]["version"],
                                "informationUri": "https://owasp.org/Top10/", "rules": rules}},
            "originalUriBaseIds": {"SRCROOT": {"uri": Path(result["target"]).as_uri() + "/"}},
            "results": results,
        }],
    }, indent=2)


def to_html(result):
    return _env.get_template("report.html").render(r=result, s=result["summary"])


def to_pdf(result, out_path):
    """Render the HTML report to PDF with a locally installed Chromium browser (no network)."""
    browser = _find_browser()
    if browser is None:
        raise RuntimeError("PDF export needs Microsoft Edge or Google Chrome installed")
    with tempfile.TemporaryDirectory() as tmp:
        html = Path(tmp) / "report.html"
        html.write_text(to_html(result), encoding="utf-8")
        subprocess.run([browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                        f"--print-to-pdf={Path(out_path).resolve()}", html.as_uri()],
                       check=True, capture_output=True, timeout=60)
    return out_path


def _find_browser():
    candidates = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("msedge")


def write_reports(result, out_dir, formats=("html", "json", "sarif")):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"sast-report-{result['id']}"
    written = []
    writers = {"json": to_json, "sarif": to_sarif, "html": to_html}
    for fmt in formats:
        fmt = fmt.strip().lower()
        path = out / f"{stem}.{fmt}"  # SARIF keeps the .sarif extension GitHub looks for
        if fmt == "patch":
            if not result.get("fix_patch"):
                continue  # no AI fixes (scan without --ai, or nothing to fix)
            path.write_text(result["fix_patch"], encoding="utf-8", newline="\n")
        elif fmt == "pdf":
            to_pdf(result, path)
        elif fmt in writers:
            path.write_text(writers[fmt](result), encoding="utf-8")
        else:
            continue
        written.append(str(path))
    return written
