from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other):
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)


@dataclass
class Finding:
    severity: Severity
    check: str
    description: str
    filename: Optional[str] = None
    detail: Optional[str] = None

    def __str__(self):
        loc = f" [{self.filename}]" if self.filename else ""
        detail = f": {self.detail}" if self.detail else ""
        return f"[{self.severity.value.upper()}] {self.check}{loc} — {self.description}{detail}"


@dataclass
class AnalysisResult:
    path: str
    findings: List[Finding] = field(default_factory=list)
    safe: bool = True
    error: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None

    def add(self, finding: Finding):
        self.findings.append(finding)
        if finding.severity in (Severity.HIGH, Severity.CRITICAL):
            self.safe = False

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def summary(self) -> str:
        if self.error:
            return f"ERROR: {self.error}"
        verdict = "SAFE" if self.safe else "UNSAFE"
        count = len(self.findings)
        sev = self.max_severity.value.upper() if self.max_severity else "none"
        return f"{verdict} — {count} finding(s), max severity: {sev}"
