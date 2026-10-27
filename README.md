# Local AI SAST Engine

Offline static application security testing. It scans a repository on your machine for injection
flaws, hardcoded secrets, weak cryptography and insecure configuration, maps every finding to CWE
and OWASP Top 10 (2021), and optionally uses a local LLM (Ollama) to triage findings and review
code for logic flaws. No source code leaves the machine.

## Features

- **Discovery:** recursive walk, 15 languages, dependency manifests, skips vendored/binary files
- **Secret detection:** provider patterns (AWS, GitHub, Stripe, Slack, Google, private keys, DB URLs) plus keyword assignments filtered by Shannon entropy; values are masked in reports
- **Python AST analysis:** import resolution and intra-function taint tracking from request data to sinks (SQL, shell, eval, pickle/yaml, file paths, outbound URLs, HTML responses)
- **JavaScript/TypeScript AST analysis** with tree-sitter: string-built SQL, `child_process.exec`, `eval`, `innerHTML`, reflected XSS, path traversal, weak hashes
- **Rule engine** for Java, C/C++, PHP and Go
- **Dependency check** against a bundled advisory table (OWASP A06)
- **Local AI** (Ollama, `qwen2.5-coder:7b`): verdict, explanation, attack scenario and fix for high/critical findings, plus a review of route files for authorization/logic flaws
- **Reports:** HTML, PDF, JSON, SARIF 2.1.0; security score and grade
- **Dashboard:** scan history, severity/OWASP/trend charts, searchable and filterable findings
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
| Speed (static analysis) | pip (113k LOC) in 3.3-5.8 s depending on machine load |

The fixture was written alongside the rules, so its score shows the detectors work as designed,
not how well they generalise. The real-code run is the fairer signal.

AI layer (`qwen2.5-coder:7b` on an RTX 3050 6 GB, fixture with `--ai --ai-review`): 15/15 high and
critical findings triaged at about 10 s each; the review found 3/3 planted logic flaws in `admin.py`
on one run and 2/3 on another (see `benchmark/ai_expected.md`): the IDOR and the predictable reset
token every time, the role trusted from the request body only sometimes, because LLM output varies
between runs; 13/15 suggested code fixes correct on manual inspection (the two Java fixes were not).

False-positive check (`samples/fp-check`: a constant SQL table name and an all-zero dummy AWS key in a
test): with the original triage prompt the model confirmed both as real; after adding guidance to check
whether data is attacker-controlled and whether secrets are placeholders, it dismissed the dummy key but
still confirmed the table name, while still confirming all 15 real fixture bugs. The prompt was tuned
after seeing these cases, so this is a weak test.

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
  static/        dashboard (HTML/CSS/JS, Chart.js vendored for offline use)
benchmark/       annotated fixture, ground truth, benchmark runner
samples/vuln-app intentionally vulnerable test project
```

## Limitations

- Taint tracking is intra-procedural (no cross-function or cross-file flow) and has no sanitizer model
- Java, C/C++, PHP and Go use regex rules, not AST analysis
- The dependency advisory table is small and bundled; it is not a full vulnerability database
- AI verdicts are advisory: findings are never hidden, only excluded from the score
