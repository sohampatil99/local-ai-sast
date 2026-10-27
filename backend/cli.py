"""Command line entry point.

    python cli.py scan <path> [--ai] [--ai-review] [--out reports/] [--fail-on high]
    python cli.py scan <path> --diff-base origin/main --fail-on high      (CI: only changed files)
    python cli.py serve [--port 8000]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sast.engine import scan  # noqa: E402

COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"
LEVELS = ["low", "medium", "high", "critical"]


def cmd_scan(args):
    baseline = None
    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    if args.incremental and baseline is None:
        print("--incremental needs --baseline <previous report.json>", file=sys.stderr)
        return 2
    changed = None
    if args.diff_base:
        from sast.incremental import git_changed
        changed = git_changed(args.path, args.diff_base)
        print(f"  .. {len(changed)} files changed since {args.diff_base}", file=sys.stderr)
    result = scan(args.path, ai=args.ai, ai_review=args.ai_review, model=args.model,
                  ai_limit=args.ai_limit, progress=lambda m: print(f"  .. {m}", file=sys.stderr),
                  baseline=baseline, incremental=args.incremental, changed_files=changed)
    s = result["summary"]
    for f in result["findings"]:
        if args.new_only and f.get("status") == "existing":
            continue
        color = COLORS.get(f["severity"], "")
        verdict = f" [AI: {f['ai']['verdict']}]" if f.get("ai") and f["ai"].get("verdict") else ""
        tag = " [NEW]" if f.get("status") == "new" else ""
        print(f"{color}{f['severity'].upper():8}{RESET} {f['file']}:{f['line']:<4} "
              f"{f['title']} ({f['cwe']}){verdict}{tag}")
    repo = result["repo"]
    print(f"\n{s['total']} findings | critical {s['by_severity']['critical']} | high {s['by_severity']['high']} | "
          f"medium {s['by_severity']['medium']} | low {s['by_severity']['low']}")
    print(f"{repo['files_scanned']} files, {repo['total_loc']} LOC in {result['duration_seconds']}s "
          f"(static {result['static_seconds']}s) | score {s['security_score']}/100 grade {s['grade']}")
    if result["ai"]["enabled"] or args.ai or args.ai_review:
        print(f"AI: {result['ai']['detail']}")
    inc, cmp_ = result.get("incremental"), result.get("comparison")
    if inc:
        print(f"Incremental ({inc['mode']}): {len(inc['changed'])} changed, re-analyzed {inc['rescanned']} files, "
              f"reused {inc['reused_files']} files")
    if cmp_:
        print(f"Compared with scan {cmp_['baseline_id']}: {cmp_['new']} new, {cmp_['fixed']} fixed, "
              f"{cmp_['existing']} unchanged")
    if args.out:
        from sast.report import write_reports
        for path in write_reports(result, args.out, formats=args.format.split(",")):
            print(f"report: {path}")
    if args.fail_on:
        threshold = LEVELS.index(args.fail_on)
        counted = [f for f in result["findings"] if not (args.new_only and f.get("status") == "existing")]
        if any(LEVELS.index(f["severity"]) >= threshold for f in counted if f["severity"] in LEVELS):
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
    s.add_argument("--baseline", help="previous JSON report: mark findings new/existing and list what was fixed")
    s.add_argument("--incremental", action="store_true",
                   help="with --baseline: re-analyze only changed files (and their importers), reuse the rest")
    s.add_argument("--diff-base", help="git ref: analyze only files changed since it (pull requests in CI)")
    s.add_argument("--new-only", action="store_true",
                   help="with --baseline: print and --fail-on only findings that are new since the baseline")
    s.set_defaults(func=cmd_scan)
    v = sub.add_parser("serve", help="start API + dashboard")
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=8000)
    v.set_defaults(func=cmd_serve)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
