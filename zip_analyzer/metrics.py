"""Compute aggregate risk, confidence, and intelligence metrics from scan results."""

import hashlib
import math
import os
import re
import zipfile
from collections import Counter
from typing import Any, Dict, List, Optional

from .models import Finding, Severity

# ── Risk scoring ──────────────────────────────────────────────────────────────

_RISK_WEIGHTS = {
    Severity.CRITICAL: 45, Severity.HIGH:   22,
    Severity.MEDIUM:   10, Severity.LOW:     4, Severity.INFO: 1,
}

_RISK_LABELS = [(0,"NONE"),(15,"LOW"),(35,"MEDIUM"),(60,"HIGH"),(101,"CRITICAL")]

def _risk_label(score: int) -> str:
    for t, l in _RISK_LABELS:
        if score <= t: return l
    return "CRITICAL"


# ── MITRE ATT&CK mapping ──────────────────────────────────────────────────────

MITRE_MAP: Dict[str, tuple] = {
    "path_traversal":        ("T1190",     "Exploit Public-Facing Application"),
    "zip_bomb":              ("T1499.003", "Endpoint DoS: Service Exhaustion Flood"),
    "magic_mismatch":        ("T1036.005", "Masquerade: Match Legitimate Name/Location"),
    "double_extension":      ("T1036.007", "Masquerade: Double File Extension"),
    "suspicious_filename":   ("T1036",     "Masquerading"),
    "executable_binary":     ("T1204.002", "User Execution: Malicious File"),
    "high_entropy":          ("T1027",     "Obfuscated Files or Information"),
    "encrypted_entry":       ("T1027.002", "Obfuscated Files: Software Packing"),
    "symlink":               ("T1574",     "Hijack Execution Flow"),
    "macro_document":        ("T1137",     "Office Application Startup"),
    "suspicious_string":     ("T1140",     "Deobfuscate/Decode Files or Information"),
    "malicious_comment":     ("T1027",     "Obfuscated Files or Information"),
    "null_byte_filename":    ("T1036",     "Masquerading"),
    "rtlo_attack":           ("T1036.002", "Masquerade: Right-to-Left Override"),
    "homograph_attack":      ("T1036",     "Masquerading"),
    "impersonation":         ("T1036.005", "Masquerade: Match Legitimate Name/Location"),
    "duplicate_filename":    ("T1036",     "Masquerading"),
    "dga_domain":            ("T1568.002", "Dynamic Resolution: Domain Generation"),
    "c2_address":            ("T1571",     "Non-Standard Port"),
    "tor_onion_address":     ("T1090.003", "Multi-hop Proxy: Onion Routing"),
    "malicious_url":         ("T1105",     "Ingress Tool Transfer"),
    "vm_evasion":            ("T1497",     "Virtualization/Sandbox Evasion"),
    "wmi_persistence":       ("T1546.003", "Event Triggered Execution: WMI"),
    "ransomware_note":       ("T1486",     "Data Encrypted for Impact"),
    "pe_import":             ("T1059",     "Command and Scripting Interpreter"),
    "pdf_dangerous_key":     ("T1059.007", "Command and Scripting: JavaScript"),
    "office_vba_confirmed":  ("T1137.006", "Office Template Macros"),
    "office_external_link":  ("T1187",     "Forced Authentication"),
    "office_formula_injection":("T1059",   "Command and Scripting Interpreter"),
    "reg_persistence":       ("T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    "scheduled_task":        ("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    "malicious_lnk":         ("T1547.009", "Shortcut Modification"),
    "startup_path":          ("T1547.001", "Boot/Logon Autostart: Registry Run Keys"),
    "timestamp_future":      ("T1070.006", "Indicator Removal: Timestomp"),
    "timestamp_epoch":       ("T1070.006", "Indicator Removal: Timestomp"),
    "file_count":            ("T1499",     "Endpoint Denial of Service"),
    "nested_archive":        ("T1027",     "Obfuscated Files or Information"),
    "dangerous_extension":   ("T1204.002", "User Execution: Malicious File"),
    "hidden_file":           ("T1564.001", "Hide Artifacts: Hidden Files"),
    "script_file":           ("T1059",     "Command and Scripting Interpreter"),
    "setuid_file":           ("T1548.001", "Abuse Elevation: Setuid/Setgid"),
    # Threat intelligence checks
    "virustotal_hit":        ("T1588.001", "Obtain Capabilities: Malware"),
    "yara_match":            ("T1587.001", "Develop Capabilities: Malware"),
}

# ATT&CK technique names for IDs surfaced by YARA rule metadata
_ATT_CK_NAMES: Dict[str, str] = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.002": "OS Credential Dumping: SAM",
    "T1003.004": "OS Credential Dumping: LSA Secrets",
    "T1027":     "Obfuscated Files or Information",
    "T1027.010": "Obfuscated Files: Command Obfuscation",
    "T1055":     "Process Injection",
    "T1055.003": "Process Injection: Thread Execution Hijacking",
    "T1055.004": "Process Injection: Asynchronous Procedure Call",
    "T1056.001": "Input Capture: Keylogging",
    "T1059.001": "Command and Scripting: PowerShell",
    "T1059.006": "Command and Scripting: Python",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1105":     "Ingress Tool Transfer",
    "T1486":     "Data Encrypted for Impact",
    "T1497":     "Virtualization/Sandbox Evasion",
    "T1505.003": "Server Software Component: Web Shell",
    "T1546.003": "Event Triggered Execution: WMI",
    "T1555":     "Credentials from Password Stores",
    "T1587.001": "Develop Capabilities: Malware",
    "T1588.001": "Obtain Capabilities: Malware",
    "T1622":     "Debugger Evasion",
}

_NATURALLY_HIGH_ENTROPY = {
    ".jpg", ".jpeg", ".png", ".gif", ".mp3", ".mp4",
    ".zip", ".gz", ".bz2", ".docx", ".xlsx", ".pptx",
}

# ── IOC regex (mirrors what checks.py uses) ───────────────────────────────────
_RE_IP    = re.compile(rb'(?<!\d)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}(?!\d)')
_RE_URL   = re.compile(rb'https?://[^\s"\'<>\x00-\x1f]{8,}')
_RE_ONION = re.compile(rb'[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b', re.I)
_IOC_EXTS = {".txt",".html",".htm",".xml",".json",".yaml",".yml",".cfg",
             ".ini",".conf",".env",".sh",".bat",".ps1",".py",".js",".php",
             ".rb",".pl",".vbs",".hta",".log",""}

import ipaddress as _ip_mod


def _classify_ip(ip_str: str) -> str:
    try:
        obj = _ip_mod.ip_address(ip_str)
        if obj.is_loopback:   return "loopback"
        if obj.is_private:    return "private"
        if obj.is_multicast:  return "multicast"
        return "public"
    except Exception:
        return "unknown"


def _extract_iocs(zf: zipfile.ZipFile) -> Dict:
    ips: Dict[str, str] = {}   # ip -> classification
    urls:  list = []
    onions: list = []

    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0 or info.file_size > 512 * 1024:
            continue
        _, ext = os.path.splitext(info.filename.lower())
        if ext not in _IOC_EXTS:
            continue
        try:
            with zf.open(info) as f:
                raw = f.read(65536)
        except Exception:
            continue

        for m in _RE_IP.finditer(raw):
            ip_str = m.group(0).decode('ascii', errors='replace')
            if ip_str not in ips:
                ips[ip_str] = _classify_ip(ip_str)

        for m in _RE_URL.finditer(raw):
            url = m.group(0).decode('utf-8', errors='replace')
            if url not in urls:
                urls.append(url)

        for m in _RE_ONION.finditer(raw):
            addr = m.group(0).decode('ascii', errors='replace')
            if addr not in onions:
                onions.append(addr)

    return {
        "ips":    [{"ip": ip, "type": t} for ip, t in sorted(ips.items()) if t not in ("loopback",)],
        "urls":   urls[:40],
        "onions": onions,
        "total":  len(ips) + len(urls) + len(onions),
    }


def _compute_hashes(zf: zipfile.ZipFile) -> List[Dict]:
    hashes = []
    for info in sorted(zf.infolist(), key=lambda x: x.filename)[:50]:
        if info.is_dir() or info.file_size == 0:
            continue
        try:
            with zf.open(info) as f:
                data = f.read()
            hashes.append({
                "filename": info.filename,
                "size":     info.file_size,
                "sha256":   hashlib.sha256(data).hexdigest(),
                "md5":      hashlib.md5(data).hexdigest(),
            })
        except Exception:
            pass
    return hashes


def compute(
    zf: zipfile.ZipFile,
    findings: List[Finding],
    yara_summary: Optional[Dict] = None,
    vt_summary: Optional[Dict] = None,
) -> Dict:
    entries = zf.infolist()
    files   = [e for e in entries if not e.is_dir()]

    total_files        = len(files)
    total_uncompressed = sum(e.file_size    for e in entries)
    total_compressed   = sum(e.compress_size for e in entries if e.compress_size > 0)
    avg_ratio = round(total_uncompressed / total_compressed, 1) if total_compressed else 1.0

    encrypted_count = sum(1 for f in findings if f.check == "encrypted_entry")
    nested_count    = sum(1 for f in findings if f.check == "nested_archive")

    # ── Risk score ─────────────────────────────────────────────────
    # Base checks: diminishing returns per check name (first=1.0x, second=0.5x,
    # third+=0.25x) to prevent one noisy check flooding the score.
    #
    # Special cases:
    #   virustotal_hit — full weight per unique file (each is a confirmed-malicious
    #     file, deduplication already happened upstream); no diminishing returns.
    #   yara_match — diminishing returns keyed on rule name (from detail field)
    #     so the same rule on two files counts once fully + once at 0.5x, but two
    #     different rules each count fully on their first occurrence.
    vt_findings    = [f for f in findings if f.check == "virustotal_hit"]
    yara_findings_ = [f for f in findings if f.check == "yara_match"]
    other_findings = [f for f in findings if f.check not in ("virustotal_hit", "yara_match")]

    # VT: each confirmed-malicious file counts at full weight (no diminishing returns)
    vt_risk = sum(_RISK_WEIGHTS.get(f.severity, 0) for f in vt_findings)

    # YARA: diminishing returns keyed on rule name extracted from detail
    yara_seen: Counter = Counter()
    yara_risk = 0.0
    for f in sorted(yara_findings_, key=lambda x: _RISK_WEIGHTS.get(x.severity, 0), reverse=True):
        base = _RISK_WEIGHTS.get(f.severity, 0)
        rule_key = f.detail or f.description  # detail has "rule=RuleName"
        n = yara_seen[rule_key]
        factor = 1.0 if n == 0 else (0.5 if n == 1 else 0.25)
        yara_risk += base * factor
        yara_seen[rule_key] += 1

    # Other checks: standard diminishing returns per check name
    check_seen: Counter = Counter()
    static_risk = 0.0
    for f in sorted(other_findings, key=lambda x: _RISK_WEIGHTS.get(x.severity, 0), reverse=True):
        base   = _RISK_WEIGHTS.get(f.severity, 0)
        n      = check_seen[f.check]
        factor = 1.0 if n == 0 else (0.5 if n == 1 else 0.25)
        static_risk += base * factor
        check_seen[f.check] += 1

    raw_risk   = vt_risk + yara_risk + static_risk
    risk_score = min(100, round(raw_risk))
    risk_label = _risk_label(risk_score)

    # ── Confidence — proportional formula ─────────────────────────
    # Base: what fraction of files could we actually scan?
    unscanned      = encrypted_count + nested_count
    scanned        = max(0, total_files - unscanned)
    coverage_ratio = scanned / total_files if total_files else 1.0

    # Entropy drag: high-entropy files may be hiding threats even if readable
    entropy_findings  = [f for f in findings if f.check == "high_entropy"]
    hi_entropy_ratio  = len(entropy_findings) / total_files if total_files else 0
    entropy_drag      = min(hi_entropy_ratio * 0.25, 0.25)

    confidence = round(95 * coverage_ratio * (1.0 - entropy_drag))
    confidence = max(15, confidence)

    conf_note = None
    if encrypted_count and nested_count:
        conf_note = f"{encrypted_count} encrypted + {nested_count} nested archive(s) limit visibility"
    elif encrypted_count:
        conf_note = f"{encrypted_count} encrypted entr{'y' if encrypted_count==1 else 'ies'} skipped"
    elif nested_count:
        conf_note = f"{nested_count} nested archive(s) not recursively scanned"
    elif entropy_drag > 0.05:
        conf_note = f"{len(entropy_findings)} high-entropy file(s) may conceal additional threats"

    coverage = round(coverage_ratio * 100)

    # ── File-type breakdown ────────────────────────────────────────
    ext_counter: Counter = Counter()
    for e in files:
        _, ext = os.path.splitext(e.filename.lower())
        ext_counter[ext or "(none)"] += 1
    top_types = [{"ext": e, "count": c} for e, c in ext_counter.most_common(6)]

    # ── Unique threat categories ───────────────────────────────────
    threat_categories = list(dict.fromkeys(f.check for f in findings))

    # ── MITRE ATT&CK mapping ───────────────────────────────────────
    # Static check → technique
    seen_mitre: Dict[str, str] = {}
    for f in findings:
        if f.check in MITRE_MAP:
            tid, tname = MITRE_MAP[f.check]
            if tid not in seen_mitre:
                seen_mitre[tid] = tname
        # YARA findings carry their ATT&CK ID in the detail field
        if f.check == "yara_match" and f.detail:
            for part in f.detail.split("|"):
                part = part.strip()
                if part.startswith("ATT&CK="):
                    tid = part[7:].strip()
                    if tid and tid not in seen_mitre:
                        seen_mitre[tid] = _ATT_CK_NAMES.get(tid, tid)
    mitre_techniques = [{"id": tid, "name": tname} for tid, tname in sorted(seen_mitre.items())]

    # ── Entropy summary ────────────────────────────────────────────
    max_entropy_val  = 0.0
    max_entropy_file = None
    for f in entropy_findings:
        if f.detail:
            try:
                val = float(f.detail.split("entropy=")[1].split(",")[0])
                if val > max_entropy_val:
                    max_entropy_val  = val
                    max_entropy_file = f.filename
            except Exception:
                pass

    # Sample-based average entropy
    all_entropy_vals = []
    for info in files[:30]:
        _, ext = os.path.splitext(info.filename.lower())
        if ext in _NATURALLY_HIGH_ENTROPY or info.file_size < 256:
            continue
        try:
            with zf.open(info) as fh:
                sample = fh.read(8192)
            if sample:
                c = Counter(sample)
                n = len(sample)
                h = -sum((v/n)*math.log2(v/n) for v in c.values())
                all_entropy_vals.append(h)
        except Exception:
            pass
    avg_entropy = round(sum(all_entropy_vals)/len(all_entropy_vals), 2) if all_entropy_vals else None

    # ── Timestamp anomalies ────────────────────────────────────────
    ts_epoch   = sum(1 for f in findings if f.check == "timestamp_epoch")
    ts_future  = sum(1 for f in findings if f.check == "timestamp_future")
    ts_invalid = sum(1 for f in findings if f.check == "timestamp_invalid")
    years = [e.date_time[0] for e in files if e.date_time[0] > 1980]
    date_range = {"min": min(years), "max": max(years)} if years else None

    # ── Hidden files ───────────────────────────────────────────────
    hidden_count = sum(1 for f in findings if f.check == "hidden_file")

    # ── IOC extraction ─────────────────────────────────────────────
    ioc_summary = _extract_iocs(zf)

    # ── File hashes ────────────────────────────────────────────────
    file_hashes = _compute_hashes(zf)

    # ── Threat intelligence summary ────────────────────────────────
    threat_intelligence: Dict[str, Any] = {
        "yara":        yara_summary or {"enabled": False},
        "virustotal":  vt_summary   or {"enabled": False},
    }

    # Confidence boost: VT clean files increase certainty slightly
    if vt_summary and vt_summary.get("files_checked", 0) > 0:
        vt_clean = vt_summary["files_checked"] - vt_summary.get("malicious", 0) - vt_summary.get("suspicious", 0)
        if vt_clean > 0:
            confidence = min(confidence + min(vt_clean * 2, 8), 99)

    return {
        # Core scores
        "risk_score":         risk_score,
        "risk_label":         risk_label,
        "confidence":         confidence,
        "confidence_note":    conf_note,
        # Coverage
        "total_files":        total_files,
        "total_uncompressed": total_uncompressed,
        "avg_compression_ratio": avg_ratio,
        "scanned_files":      scanned,
        "unscanned_files":    unscanned,
        "coverage":           coverage,
        "encrypted_count":    encrypted_count,
        "nested_count":       nested_count,
        # Entropy
        "high_entropy_count": len(entropy_findings),
        "max_entropy":        round(max_entropy_val, 2) if max_entropy_val else None,
        "max_entropy_file":   max_entropy_file,
        "avg_entropy":        avg_entropy,
        # Timestamps
        "timestamp_anomalies": ts_epoch + ts_future + ts_invalid,
        "ts_epoch":            ts_epoch,
        "ts_future":           ts_future,
        "date_range":          date_range,
        # File types
        "top_file_types":      top_types,
        "threat_categories":   threat_categories,
        "hidden_count":        hidden_count,
        # Intelligence
        "mitre_techniques":    mitre_techniques,
        "ioc_summary":         ioc_summary,
        "file_hashes":         file_hashes,
        "threat_intelligence": threat_intelligence,
    }
