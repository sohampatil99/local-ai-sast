"""Offline dependency check against a small bundled advisory table (OWASP A06)."""
import json
import re
from pathlib import Path

from .models import Finding

# package: (ecosystem, first fixed version, advisory id, summary)
ADVISORIES = {
    "flask": ("pypi", "2.2.5", "CVE-2023-30861", "Session cookie can be cached and leaked across users"),
    "requests": ("pypi", "2.31.0", "CVE-2023-32681", "Proxy-Authorization header leaked on redirect"),
    "pyyaml": ("pypi", "5.4", "CVE-2020-14343", "Arbitrary code execution via full_load/FullLoader"),
    "django": ("pypi", "4.2.16", "CVE-2024-45230", "Denial of service in urlize()"),
    "jinja2": ("pypi", "3.1.4", "CVE-2024-34064", "XSS via xmlattr filter keys"),
    "urllib3": ("pypi", "1.26.18", "CVE-2023-45803", "Request body not stripped on 303 redirect"),
    "pillow": ("pypi", "10.0.1", "CVE-2023-4863", "Heap overflow in libwebp"),
    "express": ("npm", "4.19.2", "CVE-2024-29041", "Open redirect in res.location/redirect"),
    "jsonwebtoken": ("npm", "9.0.0", "CVE-2022-23529", "Unsafe secretOrPublicKey handling"),
    "lodash": ("npm", "4.17.21", "CVE-2021-23337", "Command injection via template()"),
    "axios": ("npm", "1.6.0", "CVE-2023-45857", "XSRF-TOKEN leaked to third-party hosts"),
    "mysql": ("npm", "2.18.2", "GHSA-unmaintained", "Package is unmaintained; prefer mysql2 with prepared statements"),
    "minimist": ("npm", "1.2.6", "CVE-2021-44906", "Prototype pollution"),
}


def _ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def scan_dependencies(root, manifests):
    findings = []
    base = Path(root) if Path(root).is_dir() else Path(root).parent
    for rel in manifests:
        path = base / rel
        name = path.name.lower()
        try:
            if name == "requirements.txt":
                entries = _requirements(path)
            elif name == "package.json":
                entries = _package_json(path)
            else:
                continue
        except (OSError, ValueError):
            continue
        for pkg, version, line in entries:
            adv = ADVISORIES.get(pkg.lower())
            if not adv or not version or _ver(version) >= _ver(adv[1]):
                continue
            eco, fixed, adv_id, summary = adv
            findings.append(Finding(
                rule_id=f"DEP-{adv_id}", title=f"Vulnerable Dependency: {pkg} {version}",
                category="vulnerable_dependency", severity="medium", file=rel, line=line,
                snippet=f"{pkg} {version}", message=f"{adv_id}: {summary}. Fixed in {fixed}.",
                detector="deps", confidence="high", language=eco,
                remediation=f"Upgrade {pkg} to {fixed} or later."))
    return findings


def _requirements(path):
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8-sig", errors="ignore").splitlines(), 1):
        m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*(==|>=|~=)\s*([0-9][\w.]*)", line)
        if m:
            out.append((m.group(1), m.group(3), i))
    return out


def _package_json(path):
    text = path.read_text(encoding="utf-8-sig", errors="ignore")
    data = json.loads(text)
    lines = text.splitlines()
    out = []
    for section in ("dependencies", "devDependencies"):
        for pkg, spec in (data.get(section) or {}).items():
            version = re.sub(r"^[\^~>=<\s]+", "", str(spec))
            line = next((i for i, l in enumerate(lines, 1) if f'"{pkg}"' in l), 1)
            out.append((pkg, version, line))
    return out
