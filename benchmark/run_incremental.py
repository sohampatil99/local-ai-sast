"""Check that an incremental scan gives the same findings as a full scan, and measure the speed-up.

Works on temporary copies, never on the samples themselves:
  1. vuln-app: fix one bug in app.py and add a new file with a new bug
  2. review1-check: change only storage.py, the callee side of a cross-file flow
  3. pip: change one file in 113k LOC (timing)

    python benchmark/run_incremental.py
"""
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))

from sast.engine import scan  # noqa: E402

PIP = ROOT.parent / ".venv" / "Lib" / "site-packages" / "pip"


def signature(result):
    """Everything a reader sees about the findings, minus line-independent ids and timings."""
    return sorted((f["file"], f["line"], f["rule_id"], f["severity"], f["message"], f.get("status", ""))
                  for f in result["findings"])


def case(name, src, edit):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / name
        shutil.copytree(src, work)
        base = scan(work)
        edit(work)
        t0 = time.perf_counter()
        inc = scan(work, baseline=base, incremental=True)
        t_inc = time.perf_counter() - t0
        t0 = time.perf_counter()
        full = scan(work, baseline=base)
        t_full = time.perf_counter() - t0
        same = signature(inc) == signature(full)
        c = inc["comparison"]
        row = {"case": name, "files": inc["repo"]["files_scanned"], "changed": inc["incremental"]["changed"],
               "re_analyzed": inc["incremental"]["rescanned"], "identical_to_full_scan": same,
               "new": c["new"], "fixed": c["fixed"], "unchanged": c["existing"],
               "seconds_incremental": round(t_inc, 2), "seconds_full": round(t_full, 2)}
        if not same:
            row["only_in_incremental"] = sorted(set(signature(inc)) - set(signature(full)))[:5]
            row["only_in_full"] = sorted(set(signature(full)) - set(signature(inc)))[:5]
        print(json.dumps(row))
        return row


def edit_vuln(work):
    app = work / "app.py"
    app.write_text(app.read_text(encoding="utf-8").replace(
        'cur.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))'), encoding="utf-8")
    (work / "export.py").write_text(
        "import os\nfrom flask import request\n\n\ndef export():\n"
        "    os.system(\"zip out.zip \" + request.args[\"name\"])\n", encoding="utf-8")


def edit_callee(work):
    p = work / "storage.py"
    p.write_text(p.read_text(encoding="utf-8") + "\n# reviewed\n", encoding="utf-8")


def edit_pip(work):
    p = work / "_internal" / "exceptions.py"
    p.write_text(p.read_text(encoding="utf-8") + "\n# touched\n", encoding="utf-8")


def main():
    rows = [case("vuln-app", ROOT.parent / "samples" / "vuln-app", edit_vuln),
            case("review1-check", ROOT.parent / "samples" / "review1-check", edit_callee)]
    if PIP.exists():
        rows.append(case("pip", PIP, edit_pip))
    (ROOT / "incremental_results.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    ok = all(r["identical_to_full_scan"] for r in rows)
    print("all incremental scans identical to full scans:", ok)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
