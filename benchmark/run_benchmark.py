"""Measure detection rate / false-positive rate on the fixture, and speed on real code.

    python benchmark/run_benchmark.py [--perf <dir>]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))

from sast.engine import scan  # noqa: E402

FIXTURE = ROOT.parent / "samples" / "vuln-app"
FIXTURE_EXTRA = ROOT.parent / "samples" / "lang-check"
FIXTURE_FLOW = ROOT.parent / "samples" / "flow-check"


def accuracy(fixture=FIXTURE, expected_file="expected.json"):
    expected = json.loads((ROOT / expected_file).read_text(encoding="utf-8"))
    result = scan(fixture)
    # Dependency advisories and AI review are reported separately: no line-level ground truth.
    findings = [f for f in result["findings"] if f["detector"] not in {"deps", "ai"}]
    matched_expected, true_pos, traced = set(), set(), set()
    for i, f in enumerate(findings):
        for j, e in enumerate(expected):
            if e["file"] == f["file"] and e["category"] == f["category"] and abs(e["line"] - f["line"]) <= 1:
                matched_expected.add(j)
                true_pos.add(i)
                if "User-controlled input reaches" in f["message"]:
                    traced.add(j)
    missed = [expected[j] for j in range(len(expected)) if j not in matched_expected]
    false_pos = [findings[i] for i in range(len(findings)) if i not in true_pos]
    recall = len(matched_expected) / len(expected)
    fp_rate = len(false_pos) / max(1, len(findings))
    return {
        "expected": len(expected), "detected": len(matched_expected), "reported": len(findings),
        "detection_rate": round(recall * 100, 1), "false_positive_rate": round(fp_rate * 100, 1),
        "traced_from_user_input": len(traced),
        "missed": missed,
        "false_positives": [{k: f[k] for k in ("file", "line", "category", "title")} for f in false_pos],
        "dependency_advisories": sum(1 for f in result["findings"] if f["detector"] == "deps"),
        "by_category": _per_category(expected, matched_expected),
    }


def _per_category(expected, matched):
    out = {}
    for j, e in enumerate(expected):
        hit, total = out.get(e["category"], (0, 0))
        out[e["category"]] = (hit + (j in matched), total + 1)
    return {k: f"{h}/{t}" for k, (h, t) in sorted(out.items())}


def performance(path):
    result = scan(path)
    loc = result["repo"]["total_loc"]
    return {"target": str(path), "files": result["repo"]["files_scanned"], "loc": loc,
            "seconds": result["static_seconds"],
            "loc_per_second": round(loc / max(result["static_seconds"], 1e-6)),
            "findings": result["summary"]["total"]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--perf", action="append", default=[], help="directory to time (repeatable)")
    p.add_argument("--out", default=str(ROOT / "results.json"))
    args = p.parse_args()
    report = {"accuracy": accuracy()}
    if (ROOT / "expected_extra.json").exists():
        # TypeScript, PHP, Go, C++ and extra secret formats, kept separate from the main fixture
        report["accuracy_extra"] = accuracy(FIXTURE_EXTRA, "expected_extra.json")
    if (ROOT / "expected_flow.json").exists():
        # Input passed through helper functions, sanitizers and constant-only SQL
        report["accuracy_flow"] = accuracy(FIXTURE_FLOW, "expected_flow.json")
    if (ROOT / "expected_review1.json").exists():
        # Review 1 next steps: input crossing files (Python, JS) and the Go analyzer
        report["accuracy_review1"] = accuracy(ROOT.parent / "samples" / "review1-check", "expected_review1.json")
    report["performance"] = [performance(Path(d)) for d in args.perf]
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
