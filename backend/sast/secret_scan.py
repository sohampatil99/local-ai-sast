"""Secret detection: provider-specific regexes, keyword assignments and Shannon entropy."""
import math
import re

from .models import Finding

PROVIDER_PATTERNS = [
    ("SEC001", "AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("SEC002", "AWS Secret Access Key",
     re.compile(r"(?i)aws.{0,20}(secret|private).{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"), "critical"),
    ("SEC003", "GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("SEC004", "Private Key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"), "critical"),
    ("SEC005", "Database URL with Credentials",
     re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s/'\"]+:[^@\s'\"]+@"), "high"),
    ("SEC006", "Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "high"),
    ("SEC007", "Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "high"),
    ("SEC008", "Stripe Secret Key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"), "critical"),
    ("SEC009", "JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "medium"),
]

KEYWORD_ASSIGN = re.compile(
    r"(?i)\b([\w.]*(?:password|passwd|pwd|pass|secret|api[_-]?key|apikey|token|credential|private[_-]?key|jwt)[\w.]*)"
    r"[\"'\]]*\s*(?:=|:|:=|=>)\s*[\"']([^\"']{6,})[\"']")
# Name must contain the keyword as its own word part (DB_PASS, jwtSecret), not _PassArg/author
SECRET_NAME = re.compile(
    r"(?i)(^|[_.\-]|(?<=[a-z]))(password|passwd|pwd|pass|secret|apikey|api_key|token|credentials?|"
    r"private_?key|jwt)(?=$|[_.\-A-Z0-9])")
NOT_SECRET_NAME = re.compile(r"(?i)(author|_PassArg|token_type|tokenizer|^TOKEN_|_url$|_path$|_file$|header)")
JWT_SIGN_LITERAL = re.compile(r"\bjwt\.(sign|encode)\s*\([^,]+,\s*[\"']([^\"']{6,})[\"']")
SECRET_SUFFIX = re.compile(r"(?i)(secret|key|token|pass)")
GENERIC_STRING = re.compile(r"[\"']([A-Za-z0-9+/=_\-]{32,})[\"']")
ENV_ACCESS = re.compile(r"(os\.environ|os\.getenv|getenv\(|process\.env|System\.getenv|\$\{)")
PLACEHOLDERS = re.compile(
    r"(?i)(changeme|change_me|your[_-]|example\.com|xxxx|placeholder|dummy|<[^>]+>|\*\*\*|"
    r"^test|^none$|^null$|^true$|^false$|^password$|^secret$|use a )")


def _looks_secret(value):
    """Reject identifier-like values ('context', 'eval_context', 'Bearer'): a secret mixes character classes."""
    classes = sum(bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if re.fullmatch(r"[A-Za-z_]+", value) or re.fullmatch(r"[\w.]+\.[A-Za-z_]+", value):
        return False
    return classes >= 2 and not re.fullmatch(r"[\d.]+", value)


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def mask(value):
    return value[:4] + "*" * min(len(value) - 4, 12) if len(value) > 4 else "****"


def scan_secrets(source_file, lines):
    findings = []
    for lineno, line in enumerate(lines, 1):
        if "nosast" in line or len(line) > 2000:
            continue
        hit = _match_line(line)
        if hit:
            rule_id, title, severity, value, confidence = hit
            findings.append(Finding(
                rule_id=rule_id, title=f"Hardcoded Secret: {title}", category="hardcoded_secret",
                severity=severity, file=source_file.rel, line=lineno,
                snippet=line.strip().replace(value, mask(value))[:300],
                message=f"{title} appears to be committed in source code "
                        f"(entropy {shannon_entropy(value):.2f}).",
                detector="secrets", confidence=confidence, language=source_file.language))
    return findings


def _is_dummy_key(value):
    """Documentation and test keys: AKIA0000000000000000, AKIAIOSFODNN7EXAMPLE, sk_live_xxxx..."""
    body = re.sub(r"^(AKIA|ASIA|gh[pousr]_|xox[baprs]-|AIza|[sr]k_live_)", "", value)
    return "EXAMPLE" in value.upper() or len(set(body)) <= 2 or bool(PLACEHOLDERS.search(body))


def _match_line(line):
    for rule_id, title, pattern, severity in PROVIDER_PATTERNS:
        m = pattern.search(line)
        if m:
            value = m.group(m.lastindex) if rule_id == "SEC002" else m.group(0)
            if rule_id != "SEC004" and _is_dummy_key(value):
                continue
            return rule_id, title, severity, value, "high"
    if ENV_ACCESS.search(line):
        return None
    m = JWT_SIGN_LITERAL.search(line)
    if m:
        return "SEC010", "JWT Signing Secret", "high", m.group(2), "high"
    m = KEYWORD_ASSIGN.search(line)
    if m:
        name, value = m.group(1), m.group(2)
        if SECRET_NAME.search(name) and not NOT_SECRET_NAME.search(name) \
                and not PLACEHOLDERS.search(value) and " " not in value.strip() and _looks_secret(value):
            entropy = shannon_entropy(value)
            if entropy >= 2.5:
                kind = "Password" if re.search(r"(?i)pass|pwd", name) else "Credential"
                conf = "high" if entropy >= 3.5 else "medium"
                return "SEC011", f"{kind} in '{name}'", "high", value, conf
    for m in GENERIC_STRING.finditer(line):
        value = m.group(1)
        prefix = line[: m.start()]
        if shannon_entropy(value) >= 4.5 and SECRET_SUFFIX.search(prefix):
            return "SEC012", "High-Entropy String", "medium", value, "low"
    return None
