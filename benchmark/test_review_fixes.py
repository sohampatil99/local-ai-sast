"""Checks for two AI-layer safeguards (no Ollama needed):

1. triage order: with a limit of 15, the findings with a proven path from user input are triaged first
2. patch vetting: a fix that still hardcodes a secret, or reads one from the environment with a hardcoded
   fallback, produces no patch

    python benchmark/test_review_fixes.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))

from sast.engine import SEVERITY_ORDER, attach_patches, scan, triage_queue  # noqa: E402
from sast.models import Finding  # noqa: E402
from sast.secret_scan import env_literal_fallback  # noqa: E402

FIXTURE = ROOT.parent / "samples" / "vuln-app"
failed = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")
    if not ok:
        failed.append(name)


# ---- 1. triage order -----------------------------------------------------------------------
result = scan(FIXTURE)
findings = [Finding(**{k: v for k, v in f.items() if k in Finding.__dataclass_fields__}) for f in result["findings"]]
LIMIT = 15
old = sorted([f for f in findings if f.severity in {"critical", "high"} and f.detector != "deps"],
             key=lambda f: -SEVERITY_ORDER[f.severity])[:LIMIT]  # the previous ordering: severity only
new = triage_queue(findings)[:LIMIT]
traced = [f for f in findings if f.severity in {"critical", "high"} and "User-controlled input reaches" in f.message]
in_old = sum(1 for f in traced if f in old)
in_new = sum(1 for f in traced if f in new)
check("more traced findings get an AI verdict than with the old order", in_new > in_old,
      f"{in_old} -> {in_new} of {len(traced)} traced findings (cut of {LIMIT})")
full = triage_queue(findings)
check("within a severity, no untraced finding ranks above a traced one",
      all(not (a.severity == b.severity and "User-controlled input reaches" not in a.message
               and "User-controlled input reaches" in b.message)
          for i, a in enumerate(full) for b in full[i + 1:]))
check("the SQL injection with a proven path (app.py:25) is triaged",
      any(f.file == "app.py" and f.line == 25 for f in new))
check("order is deterministic: same queue every time",
      [(f.file, f.line, f.rule_id) for f in triage_queue(findings)] ==
      [(f.file, f.line, f.rule_id) for f in triage_queue(list(reversed(findings)))])
check("criticals still come before highs",
      [SEVERITY_ORDER[f.severity] for f in full] == sorted((SEVERITY_ORDER[f.severity] for f in full), reverse=True))

# ---- 2. patch vetting -------------------------------------------------------------------------
cases = [
    ("python env lookup with fallback", "DB_PASSWORD = os.getenv('DB_PASSWORD', 'default_password')", True),
    ("python environ.get with fallback", "app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-123')", True),
    ("js process.env || literal", "const pw = process.env.DB_PASSWORD || 'hunter2hunter2'", True),
    ("js process.env ?? literal", "const t = process.env['API_TOKEN'] ?? 'abc123abc'", True),
    ("still a hardcoded literal", "DB_PASSWORD = 's3cr3tPassw0rd!'", True),
    ("python env lookup, no fallback", "DB_PASSWORD = os.getenv('DB_PASSWORD')", False),
    ("fallback is another call, not a literal", "SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(24))", False),
    ("non-secret variable with a default", "PORT = os.getenv('PORT', '8000')", False),
    ("js env lookup, no fallback", "const pw = process.env.DB_PASSWORD;", False),
]
SOURCES = {"python": ("a.py", ["import os", "DB_PASSWORD = 'x'"]),
           "javascript": ("a.js", ["const x = 1;", "const pw = 'x';"])}
for name, line, should_reject in cases:
    lang = "javascript" if "process.env" in line else "python"
    file, src = SOURCES[lang]
    f = Finding(rule_id="X", title="t", category="hardcoded_secret", severity="high", file=file, line=2,
                snippet="", message="", detector="secrets", language=lang)
    f.ai = {"verdict": "true_positive", "fixed_code": line}
    attach_patches([f], {file: src})
    rejected = "hardcodes a secret" in f.ai.get("patch_rejected", "")
    produced = bool(f.ai.get("patch"))
    check(f"patch {'rejected' if should_reject else 'kept'}: {name}",
          rejected if should_reject else produced and not rejected,
          f.ai.get("patch_rejected", "")[:90])

check("env_literal_fallback finds the literal", env_literal_fallback("x = os.getenv('DB_PASSWORD', 'abc12345')") == "abc12345")

print(f"\n{'ALL PASSED' if not failed else 'FAILED: ' + ', '.join(failed)}")
sys.exit(1 if failed else 0)
