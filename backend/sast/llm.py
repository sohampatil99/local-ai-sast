"""Local LLM layer (Ollama). Nothing leaves the machine: the only endpoint is localhost."""
import hashlib
import json
import os
import re
from pathlib import Path

import httpx

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("SAST_MODEL", "qwen2.5-coder:7b")
CACHE_PATH = Path(__file__).resolve().parent.parent / "data" / "llm_cache.json"
REVIEW_CATEGORIES = {"access_control", "auth", "logic", "data_exposure", "insecure_config"}

TRIAGE_PROMPT = """You are a senior application security engineer reviewing a static-analysis finding.

File: {file} ({language})
Code (the flagged line is marked with >>):
{context}

Finding: {title} [{cwe}, {owasp}]
Detector message: {message}
Static data-flow result: {dataflow}

Do not decide yet whether this is a vulnerability. First record the facts:
1. "value": the variable or expression in the flagged call that the scanner is worried about.
2. "origin": where that value comes from: "request" (request parameters, headers, body, or a function
   argument the caller fills from them), "generated" (UUIDs, counters, timestamps the program creates),
   "constant" (literals, constants, fixed values in the code), or "unknown".
3. "checks": every statement between where the value is obtained and the flagged line that tests,
   converts or replaces it (if-conditions, regex tests, dictionary lookups, int() / parseInt, realpath).
   Copy the code exactly and classify each one as:
   "allow_list" (value must be one of a fixed set), "lookup" (value is mapped to fixed values),
   "anchored_regex" (pattern starts with ^ and ends with $, or uses fullmatch/matches),
   "unanchored_regex" (pattern without both anchors, or re.search), "type_conversion" (int, float, parseInt),
   "path_containment" (realpath/canonical path first, then a startswith check),
   "prefix_check" (startswith on a value that was not normalised first), "deny_list" (rejects some
   characters or words), "length_check", or "other". Use [] if there are none.
4. "placeholder": only for a hardcoded secret/credential finding: true if the value is a dummy (all zeros,
   "example", "changeme", a value in a test fixture), false if it looks like a real credential; null otherwise.

Respond with ONLY a JSON object:
{{"value": "...", "origin": "request" | "generated" | "constant" | "unknown", "placeholder": true | false | null,
  "checks": [{{"code": "exact code of the check", "kind": "allow_list" | "lookup" | "anchored_regex" |
              "unanchored_regex" | "type_conversion" | "path_containment" | "prefix_check" |
              "deny_list" | "length_check" | "other"}}],
  "confidence": number between 0 and 1,
  "explanation": "2-3 sentences on why this is or is not exploitable",
  "exploit_scenario": "one sentence: how an attacker would abuse it (empty if false positive)",
  "fix": "one or two sentences describing the secure fix",
  "fixed_code": "corrected replacement for the flagged line(s) only"}}"""

REVIEW_PROMPT = """You are a senior application security engineer doing a manual code review.
A pattern-based scanner has already reported injection, XSS, path traversal, SSRF, deserialization,
secrets, hashing and crypto issues, so do NOT report any of those, even in other words.
Look only for flaws a pattern matcher cannot see: missing or broken authorization (IDOR on resources
that belong to a user, role or permission checks that trust values sent by the client), authentication
weaknesses (predictable or guessable tokens, missing checks), business-logic flaws, and sensitive data
exposure. Report an endpoint only if you can name the concrete flaw; public endpoints are not flaws.

File: {file}
{code}

Respond with ONLY a JSON object: {{"issues": [{{"line": <int>, "category": "access_control" | "auth" | "logic" | "data_exposure",
"title": "<short title>", "severity": "critical" | "high" | "medium" | "low",
"explanation": "<2 sentences>", "fix": "<1-2 sentences>"}}]}}. Return {{"issues": []}} if there are none."""


class LocalLLM:
    def __init__(self, model=None, base_url=OLLAMA_URL, timeout=120, triage_prompt=None, context=(20, 6)):
        self.model = model or DEFAULT_MODEL
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.triage_prompt = triage_prompt or TRIAGE_PROMPT
        self.context = context  # lines shown before/after the flagged line (room for validation checks above it)
        self._cache = self._load_cache()

    def status(self):
        """Return (available, detail)."""
        try:
            r = httpx.get(f"{self.base_url}/api/tags", timeout=3)
            models = [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return False, "Ollama is not running on localhost:11434"
        if any(m == self.model or m.startswith(self.model + ":") for m in models):
            return True, self.model
        return False, f"Model {self.model} not pulled (have: {', '.join(models) or 'none'})"

    def _generate(self, prompt):
        key = hashlib.sha1(f"{self.model}\n{prompt}".encode(), usedforsecurity=False).hexdigest()  # cache key only
        if key in self._cache:
            return self._cache[key]
        r = httpx.post(f"{self.base_url}/api/generate", timeout=self.timeout, json={
            "model": self.model, "prompt": prompt, "stream": False, "format": "json",
            "options": {"temperature": 0.1, "num_ctx": 8192}})
        r.raise_for_status()
        data = _parse_json(r.json().get("response", ""))
        self._cache[key] = data
        self._save_cache()
        return data

    def triage(self, finding, lines):
        before, after = self.context
        start, end = max(0, finding.line - before - 1), min(len(lines), finding.line + after)
        # Start at the enclosing function so checks from a neighbouring function are not mistaken for this one's
        for i in range(finding.line - 1, start - 1, -1):
            if FUNCTION_START.match(lines[i]):
                start = i
                break
        context = "\n".join(f"{'>>' if i + 1 == finding.line else '  '} {i + 1:4d} | {lines[i]}"
                            for i in range(start, end))
        data = self._generate(self.triage_prompt.format_map(dict(
            file=finding.file, language=finding.language, context=context, title=finding.title,
            cwe=finding.cwe, owasp=finding.owasp, message=finding.message, dataflow=_dataflow(finding))))
        verdict, checks, reason = _verdict(data, lines, finding.category)
        return {
            "model": self.model, "verdict": verdict, "reason": reason,
            "origin": str(data.get("origin", "")), "checks": checks,
            "confidence": _float(data.get("confidence")),
            "explanation": str(data.get("explanation", "")).strip(),
            "exploit_scenario": str(data.get("exploit_scenario", "")).strip(),
            "fix": str(data.get("fix", "")).strip(),
            "fixed_code": str(data.get("fixed_code", "")).strip(),
        }

    def review_file(self, rel, text):
        numbered = "\n".join(f"{i:4d} | {l}" for i, l in enumerate(text.splitlines(), 1))
        data = self._generate(REVIEW_PROMPT.format(file=rel, code=numbered[:12000]))
        issues = []
        for item in data.get("issues", []) if isinstance(data.get("issues"), list) else []:
            if not isinstance(item, dict) or not str(item.get("line", "")).isdigit():
                continue  # an issue without a usable line can't be shown or verified
            category = str(item.get("category", "logic"))
            issues.append({
                "line": int(item["line"]),
                "category": category if category in REVIEW_CATEGORIES else "logic",
                "title": str(item.get("title", "Security logic flaw"))[:120],
                "severity": str(item.get("severity", "medium")).lower(),
                "explanation": str(item.get("explanation", "")),
                "fix": str(item.get("fix", "")),
            })
        return issues

    def _load_cache(self):
        try:
            return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_cache(self):
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(self._cache), encoding="utf-8")


FUNCTION_START = re.compile(
    r"^\s*(async\s+def |def |function[\s*]|(export\s+)?(async\s+)?function\b|"
    r"((public|private|protected|static|final|synchronized)\s+)+[\w<>\[\], ]+\s+\w+\s*\(|"
    r"\w+\.(get|post|put|delete|patch|use)\s*\(\s*[\"'`])")
COMPLETE_DEFENCES = {"allow_list", "lookup", "anchored_regex", "type_conversion", "path_containment"}


def _verdict(data, lines, category=""):
    """Decide the verdict from the facts the model extracted, by fixed rules.

    A small model reliably describes code but tends to agree with whatever it is asked to judge,
    so it reports where the value comes from and which checks guard it, and these rules decide.
    A check only counts if its code really appears in the file (guards against invented checks).
    """
    if "verdict" in data and "origin" not in data:  # older prompt that asks for a verdict directly
        v = str(data.get("verdict", "needs_review")).lower()
        return (v if v in {"true_positive", "false_positive", "needs_review"} else "needs_review"), [], ""
    source = "\n".join(lines)
    squash = lambda s: "".join(str(s).split())
    checks = []
    for c in data.get("checks") or []:
        if isinstance(c, dict) and c.get("code"):
            checks.append({"code": str(c["code"])[:200], "kind": str(c.get("kind", "other")),
                           "in_code": squash(c["code"]) in squash(source)})
    if category == "hardcoded_secret":  # a secret is a constant by definition; the question is whether it is real
        if data.get("placeholder") is True:
            return "false_positive", checks, "The value is a placeholder or test value, not a real credential."
        return "true_positive", checks, "The value looks like a real credential committed to source code."
    origin = str(data.get("origin", "unknown")).lower()
    if origin in {"generated", "constant"}:
        return "false_positive", checks, f"The value is {origin} in the code, so an attacker cannot control it."
    complete = [c for c in checks if c["in_code"] and c["kind"] in COMPLETE_DEFENCES]
    if complete:
        c = complete[0]
        return "false_positive", checks, \
            f"The value passes a complete check before the call: {c['code']} ({c['kind'].replace('_', ' ')})."
    if origin == "request":
        weak = [c for c in checks if c["in_code"] and c["kind"] != "other"]  # "other" is often the assignment itself
        why = "Request data reaches the call " + \
            (f"and the only checks ({', '.join(c['kind'].replace('_', ' ') for c in weak)}) can be bypassed."
             if weak else "with no check in between.")
        return "true_positive", checks, why
    return "needs_review", checks, "The code shown is not enough to tell where the value comes from."


def _dataflow(finding):
    """What the static data-flow analysis found, in words the model can weigh."""
    if "User-controlled input reaches" in finding.message:
        return "The analyzer traced request data / user input into this call: " + \
            finding.message.split("User-controlled input reaches", 1)[1].strip(" .") + "."
    if finding.detector in {"ast-python", "ast-js", "ast-java"}:
        return ("The analyzer did NOT find request data reaching this call inside this file. The value comes "
                "from a function parameter, a generated value, configuration or another non-request source.")
    return "Pattern match only: no data-flow information."


def _parse_json(text):
    try:
        return json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                pass
    return {}


def _float(v):
    try:
        return max(0.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return None
