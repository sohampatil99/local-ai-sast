"""Maps each finding category to CWE, OWASP Top 10 (2021) and remediation guidance."""

OWASP = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

# category: (title, CWE, OWASP key, default severity, remediation)
CATEGORIES = {
    "sqli": ("SQL Injection", "CWE-89", "A03", "high",
             "Use parameterized queries or an ORM; never build SQL by string concatenation or formatting."),
    "cmdi": ("OS Command Injection", "CWE-78", "A03", "high",
             "Pass arguments as a list without shell=True, validate input against an allow-list, or avoid the shell entirely."),
    "code_injection": ("Code Injection", "CWE-95", "A03", "critical",
                       "Never pass user input to eval/exec/Function; use a safe parser such as ast.literal_eval or JSON."),
    "xss": ("Cross-Site Scripting", "CWE-79", "A03", "high",
            "Escape output with the template engine's auto-escaping, use textContent instead of innerHTML, and never render user-controlled templates."),
    "path_traversal": ("Path Traversal", "CWE-22", "A01", "high",
                       "Resolve the path and verify it stays inside an allowed base directory; reject '..' and absolute paths."),
    "deserialization": ("Insecure Deserialization", "CWE-502", "A08", "critical",
                        "Do not deserialize untrusted data with pickle/ObjectInputStream; use JSON, or yaml.safe_load for YAML."),
    "weak_crypto": ("Weak Cryptography", "CWE-327", "A02", "medium",
                    "Use SHA-256+ for integrity and bcrypt/argon2/scrypt for passwords; MD5 and SHA-1 are broken."),
    "hardcoded_secret": ("Hardcoded Secret", "CWE-798", "A07", "high",
                         "Move the secret to an environment variable or secrets manager, rotate the exposed value, and purge it from git history."),
    "insecure_config": ("Insecure Configuration", "CWE-489", "A05", "medium",
                        "Disable debug mode in production and load configuration from the environment."),
    "ssrf": ("Server-Side Request Forgery", "CWE-918", "A10", "high",
             "Validate outbound URLs against an allow-list of hosts and block internal address ranges."),
    "insecure_tls": ("Disabled TLS Verification", "CWE-295", "A02", "medium",
                     "Keep certificate verification enabled (verify=True); pin a CA bundle if needed."),
    "unsafe_file": ("Unsafe File Operation", "CWE-377", "A04", "medium",
                    "Use tempfile.mkstemp/NamedTemporaryFile and restrictive permissions (e.g. 0o600/0o750)."),
    "buffer_overflow": ("Buffer Overflow", "CWE-120", "A04", "high",
                        "Use bounded functions (strncpy, snprintf) and check buffer sizes."),
    "format_string": ("Format String Vulnerability", "CWE-134", "A03", "high",
                      "Always pass a constant format string, e.g. printf(\"%s\", msg)."),
    "vulnerable_dependency": ("Vulnerable Dependency", "CWE-1104", "A06", "medium",
                              "Upgrade the package to a patched version and pin it in the lockfile."),
    "access_control": ("Broken Access Control", "CWE-285", "A01", "high",
                       "Enforce authorization server-side on every request, including ownership checks for object IDs."),
    "auth": ("Authentication Weakness", "CWE-287", "A07", "high",
             "Use vetted authentication flows with unpredictable, expiring tokens."),
    "logic": ("Security Logic Flaw", "CWE-840", "A04", "medium",
              "Review the business rule and add explicit server-side checks."),
    "data_exposure": ("Sensitive Data Exposure", "CWE-200", "A01", "medium",
                      "Return only the fields the caller is allowed to see; avoid leaking internals in errors."),
}


def enrich(finding):
    """Fill CWE/OWASP/remediation (and a title if missing) from the category table."""
    title, cwe, owasp_key, _sev, remediation = CATEGORIES.get(
        finding.category, CATEGORIES["logic"])
    finding.cwe = finding.cwe or cwe
    finding.owasp = finding.owasp or OWASP[owasp_key]
    finding.remediation = finding.remediation or remediation
    finding.title = finding.title or title
    return finding


def default_severity(category):
    return CATEGORIES.get(category, CATEGORIES["logic"])[3]
