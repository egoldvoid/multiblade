"""VirusTotal v3 API — hash-based threat intelligence lookups."""

import hashlib
import os
import threading
import time
import zipfile
from typing import Dict, List, Optional, Tuple

from .models import Finding, Severity

VT_API_BASE      = "https://www.virustotal.com/api/v3"
_FREE_TIER_DELAY = 15.1   # 4 req/min = 1 per 15s
_MAX_FILES        = 25    # cap to avoid burning quota on large archives
_MAX_FILE_BYTES   = 50 * 1024 * 1024  # skip files over 50 MB

# Global lock so concurrent scan sessions don't exceed VT free-tier rate limit
_vt_lock = threading.Lock()

# Extension priority: executables & scripts first, then documents, then rest
_PRIORITY_EXT = {
    ".exe", ".dll", ".sys", ".ocx",
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sh",
    ".py", ".rb", ".pl", ".php",
    ".pdf", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx",
}


def _api_key() -> str:
    return os.environ.get("VT_API_KEY", "").strip()


def is_available() -> bool:
    if not _api_key():
        return False
    try:
        import requests  # noqa: F401
        return True
    except ImportError:
        return False


def _prioritize(entries: list) -> list:
    """Sort zip entries: prioritized extensions first, then by descending size."""
    def rank(info) -> int:
        _, ext = os.path.splitext(info.filename.lower())
        return 0 if ext in _PRIORITY_EXT else 1

    return sorted(entries, key=lambda x: (rank(x), -x.file_size))


def _verdict(stats: Dict) -> Tuple[str, int, int]:
    """Return (verdict, hit_count, total_scanners)."""
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values())
    if malicious >= 3:
        return "malicious", malicious, total
    if malicious > 0 or suspicious >= 3:
        return "suspicious", malicious + suspicious, total
    return "clean", 0, total


def check_virustotal(zf: zipfile.ZipFile) -> Tuple[List[Finding], Dict]:
    """Look up SHA256 hashes of zip entries against VirusTotal.

    Returns (findings, summary_dict).
    """
    key = _api_key()
    summary: Dict = {
        "enabled":       bool(key),
        "files_checked": 0,
        "malicious":     0,
        "suspicious":    0,
        "unknown":       0,
        "hits":          [],
    }

    if not key:
        return [], summary

    try:
        import requests
    except ImportError:
        summary["error"] = "requests library not installed — run: pip install requests"
        return [], summary

    # Select files to check
    candidates = [
        e for e in zf.infolist()
        if not e.is_dir()
        and e.file_size > 0
        and not (e.flag_bits & 0x1)  # skip encrypted
        and e.file_size <= _MAX_FILE_BYTES
    ]
    candidates = _prioritize(candidates)[:_MAX_FILES]

    findings: List[Finding] = []
    session = requests.Session()

    # Global lock so concurrent scan sessions don't race the VT free-tier rate limit
    with _vt_lock:
        for i, info in enumerate(candidates):
            if i > 0:
                time.sleep(_FREE_TIER_DELAY)

            try:
                with zf.open(info) as f:
                    data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
            except Exception:
                continue

            try:
                resp = session.get(
                    f"{VT_API_BASE}/files/{sha256}",
                    headers={"x-apikey": key},
                    timeout=15,
                )
            except Exception:
                continue

            summary["files_checked"] += 1

            if resp.status_code == 404:
                summary["unknown"] += 1
                continue
            if resp.status_code == 429:
                break  # rate limited — stop
            if resp.status_code != 200:
                continue

            try:
                vt_data = resp.json()
            except Exception:
                continue

            attrs  = vt_data.get("data", {}).get("attributes", {})
            stats  = attrs.get("last_analysis_stats", {})
            if not stats:
                continue

            verdict, hits, total = _verdict(stats)
            if verdict == "clean":
                continue

            vt_name    = attrs.get("meaningful_name", "")
            threat_obj = attrs.get("popular_threat_classification", {})
            label      = threat_obj.get("suggested_threat_label", "")
            tags       = attrs.get("tags", [])[:4]

            if verdict == "malicious":
                severity = Severity.CRITICAL
                desc     = f"VirusTotal: {hits}/{total} engines — MALICIOUS"
                summary["malicious"] += 1
            else:
                severity = Severity.HIGH
                desc     = f"VirusTotal: {hits}/{total} engines — SUSPICIOUS"
                summary["suspicious"] += 1

            detail_parts = [f"sha256={sha256[:16]}…"]
            if vt_name:
                detail_parts.append(f"name={vt_name}")
            if label:
                detail_parts.append(f"threat={label}")
            if tags:
                detail_parts.append(f"tags={','.join(tags)}")

            findings.append(Finding(
                severity    = severity,
                check       = "virustotal_hit",
                description = desc,
                filename    = info.filename,
                detail      = " | ".join(detail_parts),
            ))

            summary["hits"].append({
                "filename":        info.filename,
                "sha256":          sha256,
                "verdict":         verdict,
                "detections":      hits,
                "total_scanners":  total,
                "detection_ratio": f"{hits}/{total}",
                "threat_label":    label,
                "vt_name":         vt_name,
            })

    return findings, summary
