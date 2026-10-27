from dataclasses import asdict, dataclass, field
from typing import Optional

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class Finding:
    rule_id: str
    title: str
    category: str
    severity: str
    file: str
    line: int
    snippet: str
    message: str
    detector: str  # secrets | rules | ast-python | ast-js | ai
    confidence: str = "medium"  # high | medium | low
    language: str = ""
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""
    ai: Optional[dict] = None
    status: str = ""  # "new" or "existing" when compared with a previous scan
    fingerprint: str = ""

    def key(self):
        return (self.file, self.line, self.category)

    def to_dict(self):
        return asdict(self)


@dataclass
class SourceFile:
    path: str  # absolute
    rel: str  # repo-relative, forward slashes
    language: str
    loc: int


@dataclass
class RepoInfo:
    root: str
    files: list = field(default_factory=list)
    languages: dict = field(default_factory=dict)
    dependencies: list = field(default_factory=list)
    total_loc: int = 0
    skipped: int = 0
