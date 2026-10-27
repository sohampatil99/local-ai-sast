"""Command line entry point.

    python cli.py scan <path> [--ai] [--ai-review] [--out reports/] [--fail-on high]
    python cli.py serve [--port 8000]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sast.engine import scan  # noqa: E402

COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"
LEVELS = ["low", "medium", "high", "critical"]


def cmd_scan(args):
    result = scan(args.path, ai=args.ai, ai_review=args.ai_review, model=args.model,
                  ai_limit=args.ai_limit, progress=lambda m: print(f"  .. {m}", file=sys.stderr))
    s = result["summary"]
    for f in result["findings"]:
        color = COLORS.get(f["severity"], "")
        verdict = f" [AI: {f['ai']['verdict']}]" if f.get("ai") and f["ai"].get("verdict") else ""
        print(f"{color}{f['severity'].upper():8}{RESET} {f['file']}:{f['line']:<4} "
              f"{f['title']} ({f['cwe']}){verdict}")
    repo = result["repo"]
    print(f"\n{s['total']} findings | critical {s['by_severity']['critical']} | high {s['by_severity']['high']} | "
          f"medium {s['by_severity']['medium']} | low {s['by_severity']['low']}")
    print(f"{repo['files_scanned']} files, {repo['total_loc']} LOC in {result['duration_seconds']}s "
          f"(static {result['static_seconds']}s) | score {s['security_score']}/100 grade {s['grade']}")
    if result["ai"]["enabled"] or args.ai or args.ai_review:
        print(f"AI: {result['ai']['detail']}")
    if args.out:
        from sast.report import write_reports
        for path in write_reports(result, args.out, formats=args.format.split(",")):
            print(f"report: {path}")
    if args.fail_on:
        threshold = LEVELS.index(args.fail_on)
        if any(LEVELS.index(f["severity"]) >= threshold for f in result["findings"]
               if f["severity"] in LEVELS):
            return 1
    return 0


def cmd_serve(args):
    import uvicorn
    uvicorn.run("api:app", host=args.host, port=args.port, app_dir=str(Path(__file__).parent))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="local-sast", description="Offline AI-assisted SAST scanner")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path")
    s.add_argument("--ai", action="store_true", help="triage high/critical findings with the local LLM")
    s.add_argument("--ai-review", action="store_true", help="LLM review of route files for logic/auth flaws")
    s.add_argument("--model", default=None, help="Ollama model (default qwen2.5-coder:7b)")
    s.add_argument("--ai-limit", type=int, default=15)
    s.add_argument("--out", help="directory for reports")
    s.add_argument("--format", default="html,json,sarif", help="comma list: html,json,sarif,pdf,patch (patch = AI fixes, needs --ai)")
    s.add_argument("--fail-on", choices=LEVELS, help="exit 1 if any finding at or above this severity (CI)")
    s.set_defaults(func=cmd_scan)
    v = sub.add_parser("serve", help="start API + dashboard")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.set_defaults(func=cmd_serve)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
