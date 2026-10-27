"""Regex rules for languages without a dedicated AST analyzer (Java, C/C++, PHP, Go, ...).

JavaScript rules are only used as a fallback when tree-sitter is unavailable.
"""
import re

from .models import Finding
from .taxonomy import default_severity

# (rule_id, languages, category, title, pattern)
RULES = [
    # Java / Kotlin
    ("JAVA-SQLI", {"java", "kotlin"}, "sqli", "SQL Injection",
     r"\b(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|addBatch)\s*\(\s*(\"[^\"]*\"\s*\+|\w+\s*\+)"),
    ("JAVA-CMDI", {"java", "kotlin"}, "cmdi", "OS Command Injection",
     r"\bRuntime\.getRuntime\(\)\.exec\s*\((?!\s*\"[^\"]*\"\s*\))"),
    ("JAVA-WEAKHASH", {"java", "kotlin"}, "weak_crypto", "Weak Cryptography",
     r"\b(MessageDigest|Cipher)\.getInstance\s*\(\s*\"(MD5|SHA-?1|DES|RC4|[^\"]*/ECB/[^\"]*)\""),
    ("JAVA-DESER", {"java", "kotlin"}, "deserialization", "Insecure Deserialization",
     r"\bnew\s+(ObjectInputStream|XMLDecoder)\s*\("),
    ("JAVA-XSS", {"java"}, "xss", "Cross-Site Scripting",
     r"getWriter\(\)\.(print|println|write)\s*\(.*getParameter\s*\("),
    ("JAVA-PATH", {"java"}, "path_traversal", "Path Traversal",
     r"new\s+File(InputStream|Reader)?\s*\(.*getParameter\s*\("),
    # C / C++
    ("C-BOF", {"c", "cpp"}, "buffer_overflow", "Buffer Overflow",
     r"\b(strcpy|strcat|gets|sprintf|vsprintf|wcscpy)\s*\("),
    ("C-CMDI", {"c", "cpp"}, "cmdi", "OS Command Injection",
     r"\b(system|popen)\s*\(\s*(?!\")[A-Za-z_]"),
    ("C-FMT", {"c", "cpp"}, "format_string", "Format String Vulnerability",
     r"\b(printf|syslog)\s*\(\s*[A-Za-z_]\w*\s*\)|\bfprintf\s*\(\s*\w+\s*,\s*[A-Za-z_]\w*\s*\)"),
    ("C-WEAKCRYPTO", {"c", "cpp"}, "weak_crypto", "Weak Cryptography",
     r"\b(MD5_Init|MD5\s*\(|SHA1_Init|DES_\w+\s*\()"),
    # PHP
    ("PHP-SQLI", {"php"}, "sqli", "SQL Injection",
     r"\b(mysql_query|mysqli_query|->query)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)"),
    ("PHP-CMDI", {"php"}, "cmdi", "OS Command Injection",
     r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*.*\$"),
    ("PHP-EVAL", {"php"}, "code_injection", "Code Injection", r"\beval\s*\(\s*\$"),
    ("PHP-XSS", {"php"}, "xss", "Cross-Site Scripting", r"\becho\s+.*\$_(GET|POST|REQUEST)"),
    ("PHP-DESER", {"php"}, "deserialization", "Insecure Deserialization", r"\bunserialize\s*\(\s*\$"),
    ("PHP-INCLUDE", {"php"}, "path_traversal", "File Inclusion",
     r"\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)"),
    ("PHP-WEAKHASH", {"php"}, "weak_crypto", "Weak Cryptography", r"\b(md5|sha1)\s*\(\s*\$"),
    # Go
    ("GO-SQLI", {"go"}, "sqli", "SQL Injection",
     r"\.(Query|QueryRow|Exec)\s*\(\s*(fmt\.Sprintf|\"[^\"]*\"\s*\+)"),
    ("GO-CMDI", {"go"}, "cmdi", "OS Command Injection", r"exec\.Command\s*\(\s*\"(sh|bash|cmd)\""),
    ("GO-WEAKHASH", {"go"}, "weak_crypto", "Weak Cryptography", r"\b(md5|sha1|des)\.New"),
    ("GO-TLS", {"go"}, "insecure_tls", "Disabled TLS Verification", r"InsecureSkipVerify\s*:\s*true"),
    # JavaScript fallback (only when tree-sitter is not installed)
    ("JS-RX-EVAL", {"js-fallback"}, "code_injection", "Code Injection", r"\beval\s*\(\s*(?![\"'`])"),
    ("JS-RX-INNERHTML", {"js-fallback"}, "xss", "DOM-based XSS", r"\.innerHTML\s*=\s*(?![\"'`])"),
    ("JS-RX-SQLI", {"js-fallback"}, "sqli", "SQL Injection", r"\.query\s*\(\s*[\"'`][^\"'`]*[\"'`]?\s*\+|\.query\s*\(\s*`[^`]*\$\{"),
]
COMPILED = [(rid, langs, cat, title, re.compile(p)) for rid, langs, cat, title, p in RULES]
COMMENT = re.compile(r"^\s*(//|#(?!include)|/\*|\*)")


def scan_rules(source_file, lines, js_fallback=False):
    lang = source_file.language
    if lang in {"javascript", "typescript"}:
        if not js_fallback:
            return []
        lang = "js-fallback"
    findings = []
    for lineno, line in enumerate(lines, 1):
        if COMMENT.match(line) or "nosast" in line:
            continue
        for rid, langs, cat, title, rx in COMPILED:
            if lang in langs and rx.search(line):
                findings.append(Finding(
                    rule_id=rid, title=title, category=cat, severity=default_severity(cat),
                    file=source_file.rel, line=lineno, snippet=line.strip()[:300],
                    message=f"Pattern match for {title.lower()} ({rid}).", detector="rules",
                    confidence="medium", language=source_file.language))
    return findings
