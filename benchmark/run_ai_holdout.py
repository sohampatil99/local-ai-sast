"""Score the AI triage verdicts on the held-out set (samples/ai-holdout).

Every case is flagged by the static scanner; half are real bugs and half are safe because of a
check the pattern rules cannot judge (allow-list, anchored regex, realpath containment, generated
values). The prompt was not tuned on these cases.

    python benchmark/run_ai_holdout.py                                   # current prompt
    python benchmark/run_ai_holdout.py --prompt benchmark/prompts/triage_v1.txt --out ...
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "backend"))

from sast.engine import scan  # noqa: E402
from sast.llm import LocalLLM  # noqa: E402

FIXTURE = ROOT.parent / "samples" / "ai-holdout"
WANT = {"real": "true_positive", "safe": "false_positive"}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--prompt", help="triage prompt file (default: the prompt in sast/llm.py)")
    p.add_argument("--context", default="20,6", help="lines before,after the flagged line (v1 used 7,7)")
    p.add_argument("--set", default="ai", choices=["ai", "ai2"], help="ai2 = second set, written before v3")
    p.add_argument("--out", default=str(ROOT / "ai_holdout_results.json"))
    args = p.parse_args()
    fixture = FIXTURE if args.set == "ai" else ROOT.parent / "samples" / "ai-holdout-2"
    prompt = Path(args.prompt).read_text(encoding="utf-8") if args.prompt else None
    llm = LocalLLM(triage_prompt=prompt, context=tuple(int(x) for x in args.context.split(",")))
    ok, detail = llm.status()
    if not ok:
        sys.exit(f"AI unavailable: {detail}")

    expected = json.loads((ROOT / f"expected_{args.set}.json").read_text(encoding="utf-8"))
    result = scan(fixture)
    texts = {f: (fixture / f).read_text(encoding="utf-8").splitlines() for f in {e["file"] for e in expected}}
    from sast.models import Finding
    rows = []
    for e in expected:
        match = next((f for f in result["findings"] if f["file"] == e["file"] and abs(f["line"] - e["line"]) <= 1), None)
        if match is None:
            rows.append({**e, "verdict": "not flagged by static analysis", "correct": None})
            continue
        finding = Finding(**{k: v for k, v in match.items() if k in Finding.__dataclass_fields__})
        ai = llm.triage(finding, texts[e["file"]])
        rows.append({**e, "title": match["title"], "verdict": ai["verdict"], "confidence": ai["confidence"],
                     "correct": ai["verdict"] == WANT[e["label"]], "explanation": ai["explanation"]})
        print(f"{e['file']}:{e['line']:<4} {e['label']:5} -> {ai['verdict']}")

    def score(label):
        sub = [r for r in rows if r["label"] == label]
        return {"cases": len(sub), "correct": sum(1 for r in sub if r["correct"]),
                "needs_review": sum(1 for r in sub if r["verdict"] == "needs_review")}

    summary = {"prompt": args.prompt or "sast/llm.py", "model": llm.model,
               "real_confirmed": score("real"), "safe_dismissed": score("safe"),
               "accuracy": f"{sum(1 for r in rows if r['correct'])}/{len(rows)}"}
    Path(args.out).write_text(json.dumps({"summary": summary, "cases": rows}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
