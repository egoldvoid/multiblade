"""Apply user-defined detection rules to zip archive contents."""
import os
import re
import zipfile
from typing import List

from .models import Finding, Severity

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}

_TEXT_EXT = {
    ".txt", ".html", ".htm", ".xml", ".json", ".yaml", ".yml",
    ".cfg", ".ini", ".conf", ".env", ".sh", ".bat", ".ps1",
    ".py", ".js", ".php", ".rb", ".pl", ".vbs", ".hta", ".log",
}


def run_custom_checks(zf: zipfile.ZipFile, checks: list) -> List[Finding]:
    enabled = [c for c in checks if c.get("enabled")]
    if not enabled:
        return []

    findings: List[Finding] = []
    hit_ids: List[int] = []

    for info in zf.infolist():
        if info.is_dir():
            continue
        fname    = info.filename
        basename = os.path.basename(fname).lower()
        _, ext   = os.path.splitext(basename)

        for check in enabled:
            sev   = _SEV_MAP.get(check["severity"], Severity.MEDIUM)
            ctype = check["type"]
            pat   = check["pattern"]

            hit = False
            if ctype == "extension":
                norm = pat.lower().lstrip(".")
                hit  = ext.lstrip(".") == norm

            elif ctype == "filename":
                try:
                    hit = bool(re.search(pat, basename, re.I))
                except re.error:
                    hit = pat.lower() in basename

            elif ctype in ("regex", "string"):
                if ext not in _TEXT_EXT or info.file_size > 512 * 1024:
                    continue
                try:
                    with zf.open(info) as f:
                        content = f.read(65536)
                    if ctype == "string":
                        hit = pat.encode("utf-8", errors="replace") in content
                    else:
                        hit = bool(re.search(pat.encode("utf-8", errors="replace"), content, re.I))
                except Exception:
                    continue

            if hit:
                findings.append(Finding(
                    severity=sev,
                    check=f"custom_{check['id']}",
                    description=check.get("description") or f"Custom rule: {check['name']}",
                    filename=fname,
                    detail=f"rule={check['name']}",
                ))
                if check["id"] not in hit_ids:
                    hit_ids.append(check["id"])

    # Increment hit counters outside the main loop to avoid mid-scan DB writes
    if hit_ids:
        try:
            from .database import increment_check_hits
            for cid in hit_ids:
                increment_check_hits(cid)
        except Exception:
            pass

    return findings
