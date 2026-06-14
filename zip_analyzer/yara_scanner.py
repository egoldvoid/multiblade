"""YARA rule scanning for zip archive contents."""

import os
import zipfile
from typing import Dict, List, Optional, Tuple

from .models import Finding, Severity

_RULES_DIR = os.path.join(os.path.dirname(__file__), "rules")

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "info":     Severity.INFO,
}

# Scanning limits — prevent DoS via crafted archives
_MAX_BYTES        = 4 * 1024 * 1024   # 4 MB per file
_MAX_ENTRY_SIZE   = 50 * 1024 * 1024  # skip entries larger than 50 MB uncompressed
_MAX_ENTRIES      = 200               # max entries YARA will scan per archive
_MAX_TOTAL_BYTES  = 128 * 1024 * 1024 # stop after scanning 128 MB total
_MATCH_TIMEOUT_S  = 3                 # per-entry YARA match timeout (seconds)

# Compiled rules cache — loaded once per process
_compiled_rules = None
_rules_count    = 0
_yara_available = False
_load_error: Optional[str] = None

try:
    import yara as _yara_lib
    _yara_available = True
except ImportError:
    _yara_lib = None  # type: ignore


def _ensure_loaded() -> bool:
    global _compiled_rules, _rules_count, _load_error
    if not _yara_available:
        return False
    if _compiled_rules is not None:
        return True
    if _load_error is not None:
        return False

    rule_files: Dict[str, str] = {}
    if not os.path.isdir(_RULES_DIR):
        _load_error = f"Rules directory not found: {_RULES_DIR}"
        return False

    for fname in sorted(os.listdir(_RULES_DIR)):
        if fname.endswith((".yar", ".yara")):
            key = fname.rsplit(".", 1)[0]
            rule_files[key] = os.path.join(_RULES_DIR, fname)

    if not rule_files:
        _load_error = "No .yar files found in rules directory"
        return False

    try:
        _compiled_rules = _yara_lib.compile(filepaths=rule_files)
        for path in rule_files.values():
            try:
                ns = _yara_lib.compile(filepath=path)
                _rules_count += sum(1 for _ in ns)
            except Exception:
                pass
    except Exception as exc:
        _load_error = str(exc)
        return False

    return True


def is_available() -> bool:
    return _yara_available and _ensure_loaded()


def rules_count() -> int:
    _ensure_loaded()
    return _rules_count


def check_yara(zf: zipfile.ZipFile) -> Tuple[List[Finding], Dict]:
    """Scan zip entries against compiled YARA rules.

    Safety limits prevent DoS via crafted archives:
    - Per-entry read capped at _MAX_BYTES (4 MB)
    - Entries larger than _MAX_ENTRY_SIZE uncompressed are skipped
    - Total entries scanned capped at _MAX_ENTRIES
    - Total bytes decompressed capped at _MAX_TOTAL_BYTES
    """
    summary: Dict = {
        "enabled":       _yara_available,
        "rules_loaded":  0,
        "files_scanned": 0,
        "files_skipped": 0,
        "files_matched": 0,
        "matches":       [],
    }

    if not _ensure_loaded():
        summary["error"] = _load_error or "yara-python not installed"
        return [], summary

    summary["rules_loaded"] = _rules_count

    findings:   List[Finding] = []
    total_read: int           = 0
    scanned:    int           = 0

    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0:
            continue
        if info.flag_bits & 0x1:   # encrypted — can't scan
            summary["files_skipped"] += 1
            continue
        if info.file_size > _MAX_ENTRY_SIZE:
            # Entry too large — static checks already flagged it
            summary["files_skipped"] += 1
            continue
        if scanned >= _MAX_ENTRIES:
            summary["files_skipped"] += (
                sum(1 for e in zf.infolist() if not e.is_dir() and not (e.flag_bits & 0x1))
                - scanned
            )
            break
        if total_read >= _MAX_TOTAL_BYTES:
            break

        try:
            with zf.open(info) as f:
                data = f.read(_MAX_BYTES)
        except Exception:
            summary["files_skipped"] += 1
            continue

        total_read += len(data)
        scanned += 1
        summary["files_scanned"] += 1
        file_matched = False

        try:
            matches = _compiled_rules.match(data=data, timeout=_MATCH_TIMEOUT_S)
        except Exception:
            # Catches yara.TimeoutError (rule hit timeout) and any other error.
            # Skip the entry rather than aborting the whole scan.
            summary["files_skipped"] += 1
            continue

        seen_in_file: set = set()
        for match in matches:
            rule_name = match.rule
            if rule_name in seen_in_file:
                continue
            seen_in_file.add(rule_name)

            meta        = match.meta
            sev_str     = str(meta.get("severity", "medium")).lower()
            severity    = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
            description = meta.get("description", f"YARA rule match: {rule_name}")
            mitre       = meta.get("mitre", "")
            family      = meta.get("family", "")

            detail_parts = []
            if family:
                detail_parts.append(f"family={family}")
            if mitre:
                detail_parts.append(f"ATT&CK={mitre}")
            detail_parts.append(f"rule={rule_name}")

            findings.append(Finding(
                severity    = severity,
                check       = "yara_match",
                description = description,
                filename    = info.filename,
                detail      = " | ".join(detail_parts),
            ))

            summary["matches"].append({
                "filename":    info.filename,
                "rule":        rule_name,
                "family":      family,
                "mitre":       mitre,
                "severity":    sev_str,
                "description": description,
            })
            file_matched = True

        if file_matched:
            summary["files_matched"] += 1

    return findings, summary
