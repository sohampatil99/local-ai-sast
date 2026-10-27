# Local AI SAST Engine

Offline static application security testing. It scans a repository on your machine for injection
flaws, hardcoded secrets, weak cryptography and insecure configuration, maps every finding to CWE
and OWASP Top 10 (2021), and optionally uses a local LLM (Ollama) to triage findings and review
code for logic flaws. No source code leaves the machine.

## Features

- **Discovery:** recursive walk, 15 languages, dependency manifests, skips vendored/binary files
- **Secret detection:** provider patterns (AWS, GitHub, Stripe, Slack, Google, private keys, DB URLs) plus keyword assignments filtered by Shannon entropy; values are masked in reports
- **Python AST analysis:** import resolution and taint tracking from request data to sinks (SQL, shell, eval, pickle/yaml, file paths, outbound URLs, HTML responses). Taint crosses function calls in the same file, and findings name the call chain (`report() -> load_report(report_name)`)
- **JavaScript/TypeScript, Java and Go AST analysis** with tree-sitter (JS/TS taint also follows `require`/`import` into other files): string-built SQL, command execution, `eval`, `innerHTML`, reflected XSS, path traversal, SSRF, deserialization, weak crypto
- **Sanitizers and constants:** `int()`/`parseInt`/`Integer.parseInt` are safe everywhere, `shlex.quote` for shell, `html.escape` for HTML, `basename` for paths; strings built only from constants are not reported
- **Rule engine** for C/C++, PHP and Kotlin
- **Incremental scans:** re-analyze only changed files (content hash, or `--diff-base` in CI) with the same results as a full scan; every scan lists new and fixed findings since the previous one
- **Dependency check** against a bundled advisory table (OWASP A06)
- **Local AI** (Ollama, `qwen2.5-coder:7b`): for high/critical findings the model reports where the value comes from and each check before the call; fixed rules decide the verdict and say why. Fixes become a git patch (dropped if the patched file does not parse). Also reviews route files for authorization/logic flaws
- **Reports:** HTML, PDF, JSON, SARIF 2.1.0, `.patch` (AI fixes); security score and grade. Secrets are masked in snippets and displayed diffs
- **Dashboard** (Next.js + TypeScript + Tailwind + Recharts, served as static files): scan history, severity/OWASP/trend charts, searchable and filterable findings, verdict reasons, diffs with Copy patch
- **CI:** `--fail-on high` exit code and an example GitHub Actions workflow

## Quick start (Windows)

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r backend\requirements.txt

# CLI
.\.venv\Scripts\python backend\cli.py scan samples\vuln-app --out reports --format html,json,sarif,pdf

# Dashboard at http://127.0.0.1:8000
.\.venv\Scripts\python backend\cli.py serve
```

### Local AI (optional)

Install [Ollama](https://ollama.com), then:

```powershell
ollama pull qwen2.5-coder:7b
.\.venv\Scripts\python backend\cli.py scan samples\vuln-app --ai --ai-review
```

If Ollama is not running, scans still complete; the AI step is skipped and the report says so.

### Incremental scans and new/fixed findings

Every scan is compared with the previous scan of the same target: findings are marked new or
existing, and the fixed ones are listed (dashboard: "Since the scan of ..."; CLI: `--baseline`).

```powershell
python backend\cli.py scan app --out reports --format json                       # first scan
python backend\cli.py scan app --baseline reports\sast-report-<id>.json --incremental --new-only
python backend\cli.py scan app --diff-base origin/main --fail-on high           # CI: only what a PR changed
```

An incremental scan re-analyzes changed files, the files that import them and everything those import,
and reuses the previous findings (and AI verdicts) for the rest. `benchmark/run_incremental.py` checks it
gives exactly the same findings as a full scan: on pip, changing one file re-analyzes 151 of 403 files in
3.0 s instead of 5.8 s.

### Dashboard development

The built dashboard is committed in `backend/static`, so running it needs only Python. To change it:

```powershell
cd frontend
npm ci
npm run dev      # http://localhost:3000, API calls proxied to the backend on :8000
npm run build    # static export, copied into backend/static
```

### Storage

Scan history uses SQLite (`backend/data/sast.db`) by default. To use PostgreSQL:

```powershell
$env:SAST_DATABASE_URL = "postgresql://user:password@localhost:5432/sast"
```

## CI (GitHub Actions)

`.github/workflows/sast.yml` scans `backend/` on every push and pull request, fails the build on
high/critical findings (`--fail-on high`), uploads the SARIF report to GitHub code scanning and keeps
the HTML report as a build artifact. `samples/` and `benchmark/` are not scanned because they are
deliberately vulnerable. Code scanning on private repositories needs GitHub Advanced Security.

Checked locally: the workflow YAML parses, and its exact scan command passes (exit 0, `.sarif` and
`.html` written) from a fresh copy of the repo with a clean virtual environment built from
`backend/requirements.txt`. The GitHub-hosted run itself, including the SARIF upload step, has not
been executed.

## Docker

```powershell
docker compose up -d --build                      # dashboard on http://127.0.0.1:8000, PostgreSQL included
$env:SCAN_ROOT = "C:\path\to\repo"; docker compose up -d   # folder to scan, mounted read-only at /scan
```

The containers use Ollama running on the host (`host.docker.internal:11434`), so the GPU is used. An
optional containerised Ollama is available with `--profile ai` (CPU only unless GPU settings are added).
`backend/.dockerignore` keeps `.env` and local data out of the image. PDF export is not available in the
container (it needs Edge or Chrome); HTML, JSON and SARIF work.

Tested: image builds, PostgreSQL health check gates API start, `/scan/vuln-app` scans to 52 findings,
HTML/JSON/SARIF download (PDF returns an error as expected), the scan is stored in the compose
PostgreSQL, no `.env` or password in the image, and the container reaches host Ollama. A full AI
scan (triage + review) from inside the container also completed: 15/15 findings triaged with no
failures in about 4 minutes on a cold cache, AI text present in the HTML and SARIF reports.

## Benchmark

```powershell
.\.venv\Scripts\python benchmark\build_fixture.py      # regenerate samples/vuln-app + expected.json
.\.venv\Scripts\python benchmark\build_fixture.py --extra   # samples/lang-check + expected_extra.json
.\.venv\Scripts\python benchmark\run_benchmark.py --perf <dir>
```

`benchmark/annotated/` holds the fixture with `VULN:<category>` tags as ground truth;
`build_fixture.py` strips the tags into `samples/vuln-app/`. Results are written to
`benchmark/results.json`.

| Measure | Result |
|---|---|
| Fixture detection (46 planted bugs, 14 categories, 5 languages) | 46/46 |
| Fixture false positives | 0 of 46 reported |
| Real code: FastAPI, Starlette, Jinja2, httpx, pip (~158k LOC) | 25 findings, all genuine dangerous-API uses, none confirmed exploitable |
| Second fixture `samples/lang-check` (TypeScript, PHP, Go, C++, Stripe/Slack/Google keys) | 20/20, 0 false positives |
| Review 1 fixture `samples/review1-check` (input crossing files in Python and JS, a Go service) | 13/13, 0 false positives, 12 traced (before cross-file flow and the Go analyzer: 5/13, 2 false positives) |
| Data-flow fixture `samples/flow-check` (bugs through helper functions + 12 safe look-alikes) | 9/9, 0 false positives, 9/9 traced (before cross-function taint: 2/9, 12 false positives) |
| Real code re-run after cross-function taint (~159k LOC) | 27 findings; the 2 new ones are correct `sys.argv -> open()` traces in a pip helper, not exploitable |
| Speed (static analysis) | pip (113k LOC) in 3.3-5.8 s depending on machine load |

The fixture was written alongside the rules, so its score shows the detectors work as designed,
not how well they generalise. The real-code run is the fairer signal.

AI layer (`qwen2.5-coder:7b` on an RTX 3050 6 GB, fixture with `--ai --ai-review`): 15/15 high and
critical findings triaged at about 10 s each; the review found 3/3 planted logic flaws in `admin.py`
on one run and 2/3 on another (see `benchmark/ai_expected.md`): the IDOR and the predictable reset
token every time, the role trusted from the request body only sometimes, because LLM output varies
between runs; 13/15 suggested code fixes correct on manual inspection (the two Java fixes were not).

False-positive check (`samples/fp-check`: a constant SQL table name and an all-zero dummy AWS key in a
test): both are now cleared by the static rules, so they never reach the AI.

AI triage on unseen cases (`samples/ai-holdout`, 6 real + 6 safe, every one flagged by the static scanner;
`benchmark/run_ai_holdout.py`): the original prompt (`benchmark/prompts/triage_v1.txt`) called all 12 real
(6/12), and a prompt with more guidance did the same. The current method, where the model extracts facts
and rules decide, scores 11/12; the miss is a realpath containment check. A second set
(`samples/ai-holdout-2`, 6/6) exposed a context-window bug that was then fixed, so it is not an independent
test. All cases were written by the author. AI fixes on the main fixture: 12 patches, all apply with
`git apply`, 8 correct on manual review.

Input methods tested: local path, Git URL (clone, scan, clean-up), ZIP upload (same results as a folder
scan), and rejection of zip-slip archives (`../` paths) and invalid archives.

For a demo, double-click `start.bat`: it starts Ollama if needed, starts the dashboard and opens the browser.

## Layout

```
backend/
  sast/          discovery, secret_scan, ast_python, ast_js, rules, deps, taxonomy, llm, engine, report
  api.py         FastAPI (scans, history, reports, uploads) + static dashboard
  storage.py     PostgreSQL / SQLite
  cli.py         scan | serve
  static/        built dashboard (static export of frontend/)
frontend/        Next.js dashboard source (app/, components/, lib/)
benchmark/       annotated fixture, ground truth, benchmark runner
samples/vuln-app intentionally vulnerable test project
```

## Limitations

- Taint crosses files in Python and JavaScript (imports/require); Java and Go only within a file. JavaScript
  taint is tracked by variable name per file
- C/C++, PHP and Kotlin use regex rules, not AST analysis
- AI patches are suggestions: 4 of 12 on the fixture were wrong despite parsing
- The dependency advisory table is small and bundled; it is not a full vulnerability database
- AI verdicts are advisory: findings are never hidden, only excluded from the score
