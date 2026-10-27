"""Strip VULN tags from an annotated fixture into samples/ and write its ground truth.

    python benchmark/build_fixture.py            # annotated/       -> samples/vuln-app,   expected.json
    python benchmark/build_fixture.py --extra    # annotated-extra/ -> samples/lang-check, expected_extra.json
    python benchmark/build_fixture.py --flow     # annotated-flow/  -> samples/flow-check, expected_flow.json
    python benchmark/build_fixture.py --ai       # annotated-ai/    -> samples/ai-holdout, expected_ai.json

AI-holdout files are tagged AI:real or AI:safe instead of VULN:<category>.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TAG = re.compile(r"\s*(#|//|/\*)\s*(VULN|AI):([\w,]+)\s*(\*/)?")
SETS = {
    "main": (ROOT / "annotated", ROOT.parent / "samples" / "vuln-app", ROOT / "expected.json"),
    "extra": (ROOT / "annotated-extra", ROOT.parent / "samples" / "lang-check", ROOT / "expected_extra.json"),
    "flow": (ROOT / "annotated-flow", ROOT.parent / "samples" / "flow-check", ROOT / "expected_flow.json"),
    "ai": (ROOT / "annotated-ai", ROOT.parent / "samples" / "ai-holdout", ROOT / "expected_ai.json"),
    "ai2": (ROOT / "annotated-ai2", ROOT.parent / "samples" / "ai-holdout-2", ROOT / "expected_ai2.json"),
}


def main():
    chosen = next((name for name in SETS if f"--{name}" in sys.argv), "main")
    SRC, DST, EXPECTED = SETS[chosen]
    expected = []
    for src in sorted(SRC.rglob("*")):
        if not src.is_file():
            continue
        rel = src.relative_to(SRC).as_posix()
        out_lines = []
        for lineno, line in enumerate(src.read_text(encoding="utf-8").splitlines(), 1):
            m = TAG.search(line)
            if m and m.group(2) == "AI":
                expected.append({"file": rel, "line": lineno, "label": m.group(3)})
                line = line[: m.start()] + line[m.end():]
            elif m:
                for category in m.group(3).split(","):
                    expected.append({"file": rel, "line": lineno, "category": category})
                line = line[: m.start()] + line[m.end():]
            out_lines.append(line.rstrip())
        dst = DST / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    EXPECTED.write_text(json.dumps(expected, indent=2), encoding="utf-8")
    print(f"{len(expected)} ground-truth findings -> {DST}")


if __name__ == "__main__":
    main()
