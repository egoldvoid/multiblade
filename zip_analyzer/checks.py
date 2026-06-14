"""Individual security checks for zip file contents."""

import io
import ipaddress
import os
import re
import struct
import unicodedata
import zipfile
from typing import List

from .models import Finding, Severity

# Extensions that are executable or commonly weaponized
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".com", ".bat", ".cmd", ".scr", ".pif", ".msi", ".msp",
    ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh",
    ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2",
    ".sh", ".bash", ".zsh", ".ksh", ".csh",
    ".py", ".rb", ".pl", ".php", ".asp", ".aspx", ".jsp",
    ".hta", ".cpl", ".inf", ".reg", ".lnk",
    ".jar", ".class",
}

# Office macro-enabled formats
MACRO_EXTENSIONS = {".xlsm", ".xlsb", ".docm", ".dotm", ".pptm", ".potm", ".ppam", ".ppsm"}

# Magic byte signatures: (offset, bytes) -> label
MAGIC_SIGNATURES = {
    b"MZ": "Windows PE executable",
    b"\x7fELF": "ELF binary (Linux executable)",
    b"\xca\xfe\xba\xbe": "Mach-O fat binary (macOS executable)",
    b"\xce\xfa\xed\xfe": "Mach-O 32-bit binary",
    b"\xcf\xfa\xed\xfe": "Mach-O 64-bit binary",
    b"#!/": "Shell script",
    b"#! /": "Shell script",
    b"PK\x03\x04": "ZIP archive (nested)",
    b"Rar!": "RAR archive (nested)",
    b"\x1f\x8b": "GZIP archive (nested)",
}

# Filenames that are suspicious regardless of context
SUSPICIOUS_NAMES = {
    "autorun.inf", ".htaccess", "web.config", ".bashrc", ".bash_profile",
    ".profile", ".zshrc", "passwd", "shadow", "sudoers",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "authorized_keys", "known_hosts",
}

MAX_SAFE_UNCOMPRESSED = 1 * 1024 * 1024 * 1024  # 1 GB
MAX_SAFE_COMPRESSION_RATIO = 100
MAX_SAFE_FILE_COUNT = 10_000
MAX_SAFE_FILENAME_LENGTH = 260


def check_path_traversal(zf: zipfile.ZipFile) -> List[Finding]:
    findings = []
    for info in zf.infolist():
        name = info.filename
        # Absolute paths or .. traversal
        if name.startswith("/") or name.startswith("\\"):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                check="path_traversal",
                description="Absolute path in zip entry — may overwrite system files on extraction",
                filename=name,
            ))
        elif ".." in name.replace("\\", "/").split("/"):
            findings.append(Finding(
                severity=Severity.CRITICAL,
                check="path_traversal",
                description="Directory traversal sequence in filename — may escape extraction directory",
                filename=name,
            ))
        # Windows drive letter (C:\...)
        elif len(name) >= 2 and name[1] == ":" and name[0].isalpha():
            findings.append(Finding(
                severity=Severity.CRITICAL,
                check="path_traversal",
                description="Windows absolute path in zip entry",
                filename=name,
            ))
    return findings


def check_zip_bomb(zf: zipfile.ZipFile) -> List[Finding]:
    findings = []
    total_uncompressed = 0
    worst_ratio = 0.0
    worst_file  = None
    high_ratio_count = 0

    for info in zf.infolist():
        total_uncompressed += info.file_size
        if info.compress_size > 0:
            ratio = info.file_size / info.compress_size
            if ratio > MAX_SAFE_COMPRESSION_RATIO:
                high_ratio_count += 1
                if ratio > worst_ratio:
                    worst_ratio = ratio
                    worst_file  = info.filename

    if total_uncompressed > MAX_SAFE_UNCOMPRESSED:
        gb = total_uncompressed / (1024 ** 3)
        findings.append(Finding(
            severity=Severity.CRITICAL,
            check="zip_bomb",
            description=f"Total uncompressed size {gb:.1f} GB exceeds safe limit — potential zip bomb",
        ))

    # One summary finding regardless of how many files exceed the ratio threshold.
    if high_ratio_count > 0:
        findings.append(Finding(
            severity=Severity.HIGH,
            check="zip_bomb",
            description=(
                f"{high_ratio_count} file{'s' if high_ratio_count > 1 else ''} with extreme compression "
                f"ratio (worst: {worst_ratio:.0f}:1) — potential zip bomb"
            ),
            filename=worst_file,
            detail=f"files_affected={high_ratio_count}, worst_ratio={worst_ratio:.1f}",
        ))

    return findings


def check_file_count(zf: zipfile.ZipFile) -> List[Finding]:
    count = len(zf.infolist())
    if count > MAX_SAFE_FILE_COUNT:
        return [Finding(
            severity=Severity.HIGH,
            check="file_count",
            description=f"Zip contains {count:,} files — may cause resource exhaustion on extraction",
        )]
    return []


def check_dangerous_extensions(zf: zipfile.ZipFile) -> List[Finding]:
    findings = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        _, ext = os.path.splitext(name.lower())

        if ext in DANGEROUS_EXTENSIONS:
            sev = Severity.HIGH if ext in {".exe", ".dll", ".bat", ".cmd", ".ps1", ".sh", ".vbs", ".hta"} else Severity.MEDIUM
            findings.append(Finding(
                severity=sev,
                check="dangerous_extension",
                description=f"Executable or script file type: {ext}",
                filename=name,
            ))
        elif ext in MACRO_EXTENSIONS:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                check="macro_document",
                description=f"Macro-enabled Office document: {ext}",
                filename=name,
            ))
    return findings


def check_double_extension(zf: zipfile.ZipFile) -> List[Finding]:
    """Detect files like document.pdf.exe that masquerade as benign types."""
    findings = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        basename = os.path.basename(name)
        parts = basename.split(".")
        if len(parts) >= 3:
            # Check if any non-last extension looks benign while last is dangerous
            last_ext = "." + parts[-1].lower()
            prev_ext = "." + parts[-2].lower()
            benign_looking = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx", ".txt", ".zip"}
            if last_ext in DANGEROUS_EXTENSIONS and prev_ext in benign_looking:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    check="double_extension",
                    description=f"Double extension camouflage: appears as {prev_ext} but is {last_ext}",
                    filename=name,
                ))
    return findings


def check_magic_bytes(zf: zipfile.ZipFile) -> List[Finding]:
    """Read first bytes of each entry and compare against known signatures."""
    findings = []
    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0:
            continue
        try:
            with zf.open(info) as f:
                header = f.read(8)
        except Exception:
            continue

        for magic, label in MAGIC_SIGNATURES.items():
            if header.startswith(magic):
                _, ext = os.path.splitext(info.filename.lower())
                is_nested = "archive" in label.lower()
                if is_nested:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        check="nested_archive",
                        description=f"Nested {label} — recursive extraction may be needed for full scan",
                        filename=info.filename,
                    ))
                elif "executable" in label.lower() or "binary" in label.lower():
                    # Binary disguised as something else?
                    if ext not in {".exe", ".dll", ".so", ".dylib", ".bin", ".com", ".elf", ""}:
                        findings.append(Finding(
                            severity=Severity.CRITICAL,
                            check="magic_mismatch",
                            description=f"File claims to be {ext or 'unknown'} but magic bytes indicate {label}",
                            filename=info.filename,
                        ))
                    else:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            check="executable_binary",
                            description=f"Confirmed {label} by magic bytes",
                            filename=info.filename,
                        ))
                elif "script" in label.lower():
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        check="script_file",
                        description=f"Detected {label} by shebang line",
                        filename=info.filename,
                    ))
                break
    return findings


def check_suspicious_names(zf: zipfile.ZipFile) -> List[Finding]:
    findings = []
    for info in zf.infolist():
        basename = os.path.basename(info.filename).lower()
        if basename in SUSPICIOUS_NAMES:
            findings.append(Finding(
                severity=Severity.HIGH,
                check="suspicious_filename",
                description=f"Sensitive or commonly-abused filename: {basename}",
                filename=info.filename,
            ))
        # Null bytes in filename
        if "\x00" in info.filename:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                check="null_byte_filename",
                description="Null byte in filename — can truncate paths on some systems",
                filename=repr(info.filename),
            ))
        # Excessively long filename
        if len(info.filename) > MAX_SAFE_FILENAME_LENGTH:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                check="long_filename",
                description=f"Filename length {len(info.filename)} exceeds {MAX_SAFE_FILENAME_LENGTH}",
                filename=info.filename[:80] + "...",
            ))
    return findings


def check_symlinks(zf: zipfile.ZipFile) -> List[Finding]:
    """Detect Unix symlinks (external_attr contains mode bits)."""
    findings = []
    for info in zf.infolist():
        # Unix symlink: high 4 bits of external_attr >> 16 == 0o120000
        unix_mode = (info.external_attr >> 16) & 0xFFFF
        if unix_mode and (unix_mode & 0o170000) == 0o120000:
            try:
                target = zf.read(info).decode("utf-8", errors="replace")
            except Exception:
                target = "<unreadable>"
            findings.append(Finding(
                severity=Severity.HIGH,
                check="symlink",
                description=f"Symlink may point outside extraction directory",
                filename=info.filename,
                detail=f"-> {target}",
            ))
    return findings


def check_encrypted(zf: zipfile.ZipFile) -> List[Finding]:
    findings = []
    for info in zf.infolist():
        if info.flag_bits & 0x1:  # bit 0 = encrypted
            findings.append(Finding(
                severity=Severity.MEDIUM,
                check="encrypted_entry",
                description="Encrypted entry cannot be scanned — contents unknown",
                filename=info.filename,
            ))
    return findings


def check_raw_bytes(data: bytes) -> List[Finding]:
    """Scan raw zip bytes for threats that Python's zipfile sanitizes away.

    Python strips null bytes from filenames on read, so we must parse
    the central directory ourselves to catch this attack vector.

    Central directory fixed header layout (46 bytes):
      4s sig | H vmade | H vneeded | H flags | H compress |
      H mtime | H mdate | I crc | I comp_sz | I uncomp_sz |
      H fname_len | H extra_len | H comment_len |
      H disk_start | H int_attr | I ext_attr | I local_offset
    """
    findings = []
    CD_SIG = b"PK\x01\x02"
    # fmt unpacks exactly what we need; fixed header is 46 bytes total
    FMT = "<4sHHHHHHIIIHHHHHII"
    HDR_SIZE = struct.calcsize(FMT)  # 46
    offset = 0

    while True:
        pos = data.find(CD_SIG, offset)
        if pos == -1:
            break
        if pos + HDR_SIZE > len(data):
            break

        fields = struct.unpack_from(FMT, data, pos)
        fname_len = fields[10]
        extra_len = fields[11]
        comment_len = fields[12]

        fname_bytes = data[pos + HDR_SIZE: pos + HDR_SIZE + fname_len]

        if b"\x00" in fname_bytes:
            visible = fname_bytes.split(b"\x00")[0].decode("utf-8", errors="replace")
            findings.append(Finding(
                severity=Severity.CRITICAL,
                check="null_byte_filename",
                description="Null byte in filename — truncates path on C-based extractors, enabling stealth overwrite",
                filename=repr(fname_bytes.decode("latin-1")),
                detail=f"visible portion: '{visible}'",
            ))

        offset = pos + HDR_SIZE + fname_len + extra_len + comment_len

    return findings


def shannon_entropy(data: bytes) -> float:
    import math
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Extensions where high entropy is expected (already compressed/encrypted formats)
_NATURALLY_HIGH_ENTROPY = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".flac",
    ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".docx", ".xlsx", ".pptx",  # office = zip internally
}


def _is_binary(data: bytes) -> bool:
    """Return True if data looks like a binary file (not safe to text-scan)."""
    if not data:
        return False
    # Null bytes are the strongest binary indicator
    if b'\x00' in data[:512]:
        return True
    # High proportion of non-printable bytes
    sample = data[:512]
    non_printable = sum(1 for b in sample if b < 9 or (13 < b < 32) or b > 126)
    return non_printable / len(sample) > 0.30


def check_entropy(zf: zipfile.ZipFile) -> List[Finding]:
    """Flag files with suspiciously high entropy — may be encrypted, packed, or obfuscated."""
    findings = []
    for info in zf.infolist():
        if info.is_dir() or info.file_size < 256:
            continue
        _, ext = os.path.splitext(info.filename.lower())
        if ext in _NATURALLY_HIGH_ENTROPY:
            continue
        try:
            with zf.open(info) as f:
                sample = f.read(65536)
        except Exception:
            continue
        entropy = shannon_entropy(sample)
        if entropy >= 7.2:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                check="high_entropy",
                description=f"Entropy {entropy:.2f}/8.0 — content appears encrypted, packed, or obfuscated",
                filename=info.filename,
                detail=f"entropy={entropy:.2f}, sample={min(len(sample), 65536)} bytes",
            ))
    return findings


def check_timestamps(zf: zipfile.ZipFile) -> List[Finding]:
    """Detect files with suspicious MS-DOS timestamps (default 1980, impossible dates, far future)."""
    import datetime
    findings = []
    current_year = datetime.datetime.now().year
    for info in zf.infolist():
        if info.is_dir():
            continue
        y, mo, d, h, mi, s = info.date_time
        # MS-DOS epoch default — zip was created without setting a real timestamp
        if (y, mo, d) == (1980, 1, 1) and (h, mi, s) == (0, 0, 0):
            findings.append(Finding(
                severity=Severity.LOW,
                check="timestamp_epoch",
                description="Timestamp is MS-DOS epoch (1980-01-01 00:00:00) — metadata may be stripped or spoofed",
                filename=info.filename,
            ))
        elif y > current_year + 1:
            findings.append(Finding(
                severity=Severity.LOW,
                check="timestamp_future",
                description=f"File timestamp is in the future ({y}) — likely spoofed",
                filename=info.filename,
                detail=f"date={y}-{mo:02d}-{d:02d}",
            ))
        elif mo == 0 or d == 0:
            findings.append(Finding(
                severity=Severity.LOW,
                check="timestamp_invalid",
                description=f"Impossible date in timestamp: {y}-{mo:02d}-{d:02d}",
                filename=info.filename,
            ))
    return findings


def check_hidden_files(zf: zipfile.ZipFile) -> List[Finding]:
    """Flag Unix-style hidden files and Windows system/hidden attribute files."""
    findings = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        basename = os.path.basename(info.filename)
        if basename.startswith(".") and len(basename) > 1:
            # .env, .bashrc, .ssh/config, etc. — often sensitive
            findings.append(Finding(
                severity=Severity.LOW,
                check="hidden_file",
                description=f"Hidden file (dot-prefixed) — may contain sensitive config or credentials",
                filename=info.filename,
            ))
    return findings


def check_suspicious_strings(zf: zipfile.ZipFile) -> List[Finding]:
    """Scan text-like file content for hardcoded IPs, suspicious URLs, and obfuscation patterns."""
    import re
    findings = []
    TEXT_EXTENSIONS = {
        ".txt", ".html", ".htm", ".xml", ".json", ".yaml", ".yml",
        ".cfg", ".ini", ".conf", ".env", ".sh", ".bat", ".ps1",
        ".py", ".js", ".php", ".rb", ".pl", ".vbs", ".hta", ".log",
    }
    # Patterns: (regex, label, severity)
    PATTERNS = [
        (re.compile(rb"(?:eval|exec)\s*\(\s*(?:base64[_-]decode|atob|decompress)", re.I),
         "eval(decode(...)) — classic obfuscation trampoline", Severity.HIGH),
        (re.compile(rb"[A-Za-z0-9+/]{60,}={0,2}"),
         "Large base64 blob — may contain encoded payload", Severity.MEDIUM),
        (re.compile(rb"(?:https?://|ftp://)[^\s\"'<>]{8,}(?:shell|payload|dropper|stage[012]|download|malware|rat\b|c2\b|cnc)", re.I),
         "URL with malware-related path component", Severity.HIGH),
        (re.compile(rb"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.\d{1,3}){3}:\d{2,5}\b"),
         "Hardcoded IP:port — possible C2 address", Severity.MEDIUM),
        (re.compile(rb"(?:cmd\.exe|powershell(?:\.exe)?)\s+.*(?:-enc|-encodedcommand|-nop|-w hidden)", re.I),
         "PowerShell/CMD with evasion flags", Severity.HIGH),
        (re.compile(rb"(?:wget|curl)\s+.*(?:\s+-O\s+|-o\s+).*(?:\.exe|\.sh|\.bat|\.ps1)", re.I),
         "Download-and-save command targeting executable path", Severity.HIGH),
    ]

    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0 or info.file_size > 512 * 1024:
            continue
        _, ext = os.path.splitext(info.filename.lower())
        if ext not in TEXT_EXTENSIONS:
            continue
        try:
            with zf.open(info) as f:
                content = f.read(65536)
        except Exception:
            continue
        if _is_binary(content):
            continue
        seen = set()
        for pattern, label, sev in PATTERNS:
            if pattern.search(content) and label not in seen:
                seen.add(label)
                findings.append(Finding(
                    severity=sev,
                    check="suspicious_string",
                    description=label,
                    filename=info.filename,
                ))
    return findings


def check_comment_injection(zf: zipfile.ZipFile) -> List[Finding]:
    """Check zip comment and file comments for suspicious content."""
    findings = []
    comment = zf.comment
    if comment:
        decoded = comment.decode("utf-8", errors="replace").lower()
        suspicious_terms = ["<script", "<?php", "eval(", "base64_decode", "powershell", "cmd.exe"]
        for term in suspicious_terms:
            if term in decoded:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    check="malicious_comment",
                    description=f"Zip comment contains suspicious code pattern: '{term}'",
                    detail=comment.decode("utf-8", errors="replace")[:200],
                ))
                break
    return findings


# ── IOC / Network Indicators ──────────────────────────────────────────────────

_RE_IP     = re.compile(rb'(?<!\d)(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}(?!\d)')
_RE_URL    = re.compile(rb'https?://[^\s"\'<>\x00-\x1f]{8,}')
_RE_ONION  = re.compile(rb'[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b', re.I)
_RE_DOMAIN = re.compile(rb'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,5}(?:ru|cn|tk|pw|top|xyz|onion|bit)\b')

# Ports strongly associated with C2 frameworks
_BAD_PORTS = {4444, 4445, 1337, 31337, 8443, 9001, 9050}  # msf/cs/tor defaults
_RE_PORT   = re.compile(rb'\b(\d{1,5})\b')

_IOC_TEXT_EXT = {
    ".txt", ".html", ".htm", ".xml", ".json", ".yaml", ".yml",
    ".cfg", ".ini", ".conf", ".env", ".sh", ".bat", ".ps1",
    ".py", ".js", ".php", ".rb", ".pl", ".vbs", ".hta", ".log",
}


def _is_dga_like(domain: str) -> bool:
    sub = domain.split('.')[0].lower()
    if len(sub) < 8:
        return False
    vowels = sum(1 for c in sub if c in 'aeiou')
    if len(sub) and vowels / len(sub) < 0.15:
        return True
    if re.search(r'[bcdfghjklmnpqrstvwxyz]{5,}', sub):
        return True
    return False


def check_ioc_strings(zf: zipfile.ZipFile) -> List[Finding]:
    """Extract network IOCs (IPs, URLs, .onion addresses) from readable file content."""
    findings = []
    seen_ips: set = set()
    seen_urls: set = set()

    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0 or info.file_size > 512 * 1024:
            continue
        _, ext = os.path.splitext(info.filename.lower())
        if ext not in _IOC_TEXT_EXT:
            continue
        try:
            with zf.open(info) as f:
                raw = f.read(65536)
        except Exception:
            continue
        if _is_binary(raw):
            continue

        # .onion addresses — always high confidence malicious
        for m in _RE_ONION.finditer(raw):
            addr = m.group(0).decode('ascii', errors='replace')
            findings.append(Finding(
                severity=Severity.HIGH,
                check="tor_onion_address",
                description="Tor .onion address found — likely C2 or illicit service",
                filename=info.filename,
                detail=addr,
            ))

        # Suspicious URLs with malware-path components
        for m in _RE_URL.finditer(raw):
            url = m.group(0).decode('utf-8', errors='replace')
            if url in seen_urls:
                continue
            seen_urls.add(url)
            url_lower = url.lower()
            if any(k in url_lower for k in ('shell', 'payload', 'stage', 'dropper', 'rat/', 'c2/', 'beacon', 'implant', 'backdoor')):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    check="malicious_url",
                    description="URL with malware-path component",
                    filename=info.filename,
                    detail=url[:200],
                ))

        # Public IPs — flag once per unique IP
        for m in _RE_IP.finditer(raw):
            ip_str = m.group(0).decode('ascii', errors='replace')
            if ip_str in seen_ips:
                continue
            seen_ips.add(ip_str)
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_unspecified:
                    continue
                if ip_obj.is_private:
                    continue  # internal IPs not noteworthy on their own
                # Check if port follows the IP in raw bytes
                pos = m.start()
                after = raw[m.end():m.end() + 6]
                port_match = re.match(rb':(\d{1,5})', after)
                if port_match:
                    port = int(port_match.group(1))
                    if port in _BAD_PORTS:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            check="c2_address",
                            description=f"Public IP with known C2/RAT port {port}",
                            filename=info.filename,
                            detail=f"{ip_str}:{port}",
                        ))
                        continue
                # DGA-like domain nearby?
            except ValueError:
                pass

        # DGA-like domains
        for m in _RE_DOMAIN.finditer(raw):
            domain = m.group(0).decode('ascii', errors='replace').lower()
            if _is_dga_like(domain):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    check="dga_domain",
                    description="Domain matches DGA heuristic (algorithmically generated name)",
                    filename=info.filename,
                    detail=domain,
                ))

    return findings


# ── PE Import Table Analysis ──────────────────────────────────────────────────

# Suspicious Windows API imports and what they indicate
_PE_API_THREATS = {
    # Process injection
    b"VirtualAllocEx":          ("T1055",     Severity.HIGH,     "Remote process memory allocation — injection setup"),
    b"WriteProcessMemory":      ("T1055",     Severity.HIGH,     "Write to remote process memory — injection"),
    b"CreateRemoteThread":      ("T1055.003", Severity.CRITICAL, "Remote thread creation — classic DLL/shellcode injection"),
    b"NtMapViewOfSection":      ("T1055.004", Severity.HIGH,     "Map section into remote process — injection"),
    b"QueueUserAPC":            ("T1055.004", Severity.HIGH,     "APC injection"),
    b"RtlCreateUserThread":     ("T1055",     Severity.CRITICAL, "Undocumented thread creation — advanced injection"),
    # Credential theft
    b"MiniDumpWriteDump":       ("T1003.001", Severity.CRITICAL, "LSASS memory dump — credential harvesting"),
    b"SamIConnect":             ("T1003.002", Severity.CRITICAL, "SAM database direct access — credential theft"),
    b"LsaRetrievePrivateData":  ("T1003.004", Severity.CRITICAL, "LSA secrets access — credential theft"),
    b"CryptUnprotectData":      ("T1555",     Severity.HIGH,     "DPAPI credential decryption"),
    # Anti-analysis / evasion
    b"IsDebuggerPresent":       ("T1622",     Severity.MEDIUM,   "Debugger detection"),
    b"CheckRemoteDebuggerPresent": ("T1622",  Severity.MEDIUM,   "Remote debugger detection"),
    b"NtQueryInformationProcess": ("T1622",   Severity.MEDIUM,   "Anti-debug via NtQueryInformationProcess"),
    b"OutputDebugString":       ("T1622",     Severity.LOW,      "Debug string output — anti-analysis probe"),
    # Keylogging
    b"SetWindowsHookEx":        ("T1056.001", Severity.HIGH,     "Keyboard/mouse hook — keylogger"),
    b"GetAsyncKeyState":        ("T1056.001", Severity.HIGH,     "Async key state polling — keylogger"),
    b"GetRawInputData":         ("T1056.001", Severity.HIGH,     "Raw input capture — keylogger"),
    # Download / dropper
    b"URLDownloadToFile":       ("T1105",     Severity.HIGH,     "Download file from URL — dropper"),
    b"InternetOpenUrl":         ("T1105",     Severity.MEDIUM,   "Open internet URL"),
    b"HttpSendRequest":         ("T1071.001", Severity.MEDIUM,   "HTTP request — C2 communication"),
    # Ransomware
    b"CryptEncrypt":            ("T1486",     Severity.HIGH,     "File encryption — ransomware pattern"),
    b"BCryptEncrypt":           ("T1486",     Severity.HIGH,     "CNG file encryption — ransomware pattern"),
    # Persistence
    b"RegSetValueExA":          ("T1547.001", Severity.MEDIUM,   "Registry write — possible persistence"),
    b"RegSetValueExW":          ("T1547.001", Severity.MEDIUM,   "Registry write — possible persistence"),
    b"SHGetFolderPath":         ("T1547.001", Severity.LOW,      "Startup folder path lookup"),
    # Reconnaissance
    b"CreateToolhelp32Snapshot": ("T1057",    Severity.MEDIUM,   "Process snapshot — recon/evasion"),
    b"Process32First":          ("T1057",     Severity.MEDIUM,   "Process enumeration"),
    b"NetUserEnum":             ("T1087.001", Severity.HIGH,     "User account enumeration"),
}


def _scan_pe_api_strings(data: bytes) -> List[str]:
    """Return list of suspicious API names found as strings in PE binary data."""
    found = []
    for api_bytes in _PE_API_THREATS:
        # Must be surrounded by non-alphanumeric to avoid partial matches
        pattern = b'(?<![A-Za-z])' + re.escape(api_bytes) + b'(?![A-Za-z])'
        if re.search(pattern, data):
            found.append(api_bytes.decode('ascii'))
    return found


def check_pe_imports(zf: zipfile.ZipFile) -> List[Finding]:
    """Scan PE binary content for suspicious Windows API import names."""
    findings = []
    PE_MAGIC = b"MZ"

    for info in zf.infolist():
        if info.is_dir() or info.file_size < 64:
            continue
        try:
            with zf.open(info) as f:
                header = f.read(2)
                if header != PE_MAGIC:
                    continue
                f2_buf = io.BytesIO(header)
                # Re-read full content (up to 4 MB — import table is near the beginning)
            with zf.open(info) as f:
                data = f.read(min(info.file_size, 4 * 1024 * 1024))
        except Exception:
            continue

        apis = _scan_pe_api_strings(data)
        if not apis:
            continue

        # Group by ATT&CK tactic for cleaner reporting
        seen_mitre: set = set()
        for api in apis:
            mitre, sev, desc = _PE_API_THREATS[api.encode('ascii')]
            key = (mitre, desc)
            if key in seen_mitre:
                continue
            seen_mitre.add(key)
            findings.append(Finding(
                severity=sev,
                check="pe_import",
                description=desc,
                filename=info.filename,
                detail=f"API: {api}  |  ATT&CK: {mitre}",
            ))

    return findings


# ── Social Engineering ────────────────────────────────────────────────────────

_RTLO = '‮'  # RIGHT-TO-LEFT OVERRIDE
_IMPERSONATION_KEYWORDS = {
    'setup', 'install', 'installer', 'update', 'updater', 'patch', 'patcher',
    'crack', 'keygen', 'activator', 'loader', 'bypass', 'unlocker', 'cheat',
    'hack', 'exploit', 'payload', 'invoice', 'receipt', 'statement',
}


def check_social_engineering(zf: zipfile.ZipFile) -> List[Finding]:
    """Detect RTLO, Unicode homographs, impersonation keywords, and duplicate filenames."""
    findings = []
    seen_norm: dict = {}

    for info in zf.infolist():
        name    = info.filename
        base    = os.path.basename(name)
        _, ext  = os.path.splitext(base.lower())

        # ── RTLO attack ──────────────────────────────────────────────
        if _RTLO in name:
            # Show what Windows Explorer would display
            visual = base.replace(_RTLO, '')[::-1]
            findings.append(Finding(
                severity=Severity.CRITICAL,
                check="rtlo_attack",
                description="Right-to-Left Override (U+202E) in filename — Windows Explorer shows reversed name",
                filename=name,
                detail=f"displayed as: '{visual}'",
            ))

        # ── Unicode homograph ────────────────────────────────────────
        suspicious_unicode = [
            c for c in base
            if ord(c) > 127 and unicodedata.category(c) in ('Ll', 'Lu', 'Lo', 'Nd')
            and unicodedata.name(c, '').startswith(('CYRILLIC', 'GREEK', 'LATIN SMALL LETTER DOTLESS'))
        ]
        if suspicious_unicode:
            findings.append(Finding(
                severity=Severity.HIGH,
                check="homograph_attack",
                description="Lookalike Unicode characters in filename — may impersonate a trusted file",
                filename=name,
                detail=f"chars: {[unicodedata.name(c, '?') for c in suspicious_unicode[:3]]}",
            ))

        # ── Impersonation keywords ───────────────────────────────────
        base_lower = base.lower()
        matched_kw = next((kw for kw in _IMPERSONATION_KEYWORDS if kw in base_lower), None)
        if matched_kw and ext in DANGEROUS_EXTENSIONS:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                check="impersonation",
                description=f"Executable uses social engineering keyword '{matched_kw}'",
                filename=name,
            ))

        # ── Duplicate filename (zip slip variant) ────────────────────
        norm = name.lower().strip('/')
        if norm in seen_norm:
            findings.append(Finding(
                severity=Severity.HIGH,
                check="duplicate_filename",
                description="Duplicate filename — which entry is extracted depends on the tool (zip slip variant)",
                filename=name,
                detail=f"conflicts with: {seen_norm[norm]}",
            ))
        else:
            seen_norm[norm] = name

    return findings


# ── Deep Document Analysis ────────────────────────────────────────────────────

_OFFICE_EXTENSIONS = {'.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm', '.dotm', '.potm'}

_PDF_DANGER_KEYS = {
    b'/JavaScript':  (Severity.HIGH,     "Embedded JavaScript"),
    b'/JS ':         (Severity.HIGH,     "Embedded JavaScript (abbreviated)"),
    b'/OpenAction':  (Severity.HIGH,     "Auto-execute action on open"),
    b'/Launch':      (Severity.CRITICAL, "Launch action — can execute arbitrary files"),
    b'/EmbeddedFile':(Severity.MEDIUM,   "Embedded file inside PDF"),
    b'/RichMedia':   (Severity.MEDIUM,   "Rich media — historical Flash exploit vector"),
    b'/XFA':         (Severity.MEDIUM,   "XFA forms — exploit vector"),
    b'/AA ':         (Severity.MEDIUM,   "Additional Actions — auto-execute on events"),
    b'/URI':         (Severity.LOW,      "External URI reference"),
}


_MAX_OFFICE_INNER_BYTES = 32 * 1024 * 1024   # 32 MB cap on Office inner-zip reads


def check_deep_documents(zf: zipfile.ZipFile) -> List[Finding]:
    """Recurse into Office docs (which are ZIPs) and scan PDFs for dangerous keys."""
    findings = []

    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0:
            continue
        _, ext = os.path.splitext(info.filename.lower())

        # ── Office documents ─────────────────────────────────────────
        if ext in _OFFICE_EXTENSIONS:
            # Cap the inner read to avoid memory exhaustion from a huge docm
            if info.file_size > _MAX_OFFICE_INNER_BYTES:
                continue
            try:
                with zf.open(info) as f:
                    inner_data = f.read(_MAX_OFFICE_INNER_BYTES)
                if not inner_data[:4] == b'PK\x03\x04':
                    continue
                with zipfile.ZipFile(io.BytesIO(inner_data)) as inner:
                    inner_names = {m.filename for m in inner.infolist()}

                    if any('vbaProject.bin' in n for n in inner_names):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            check="office_vba_confirmed",
                            description="Confirmed embedded VBA macro project (vbaProject.bin present)",
                            filename=info.filename,
                        ))

                    if any('externalLinks' in n for n in inner_names):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            check="office_external_link",
                            description="External data links — can force NTLM auth or load remote content on open",
                            filename=info.filename,
                        ))

                    # Scan workbook XML for suspicious formulas
                    for inner_info in inner.infolist():
                        if inner_info.filename.endswith('.xml') and inner_info.file_size < 128 * 1024:
                            try:
                                xml = inner.read(inner_info)
                                for kw in (b'HYPERLINK', b'WEBSERVICE', b'IMPORTDATA', b'cmd.exe', b'powershell'):
                                    if kw.lower() in xml.lower():
                                        findings.append(Finding(
                                            severity=Severity.HIGH,
                                            check="office_formula_injection",
                                            description=f"Suspicious formula/command in document XML: {kw.decode()}",
                                            filename=info.filename,
                                            detail=inner_info.filename,
                                        ))
                                        break
                            except Exception:
                                pass
            except Exception:
                pass

        # ── PDF documents ─────────────────────────────────────────────
        elif ext == '.pdf':
            try:
                with zf.open(info) as f:
                    content = f.read(min(info.file_size, 256 * 1024))
                seen = set()
                for keyword, (sev, label) in _PDF_DANGER_KEYS.items():
                    if keyword in content and label not in seen:
                        seen.add(label)
                        findings.append(Finding(
                            severity=sev,
                            check="pdf_dangerous_key",
                            description=f"PDF: {label}",
                            filename=info.filename,
                            detail=f"keyword: {keyword.decode('latin-1')}",
                        ))
            except Exception:
                pass

    return findings


# ── Behavioral / Evasion Indicators ──────────────────────────────────────────

_VM_STRINGS = [
    (b'VMware',         "VMware detection string"),
    (b'VBOX',           "VirtualBox detection string"),
    (b'VirtualBox',     "VirtualBox detection string"),
    (b'QEMU',           "QEMU detection string"),
    (b'vboxguest',      "VirtualBox guest driver"),
    (b'vmtoolsd',       "VMware Tools process"),
    (b'wireshark',      "Wireshark (sandbox indicator)"),
    (b'procmon',        "Process Monitor (sandbox indicator)"),
    (b'ollydbg',        "OllyDbg debugger"),
    (b'x64dbg',         "x64dbg debugger"),
    (b'SbieDll',        "Sandboxie DLL"),
    (b'SxIn',           "360 sandbox"),
    (b'Sf2',            "Avast sandbox"),
    (b'cmdvrt',         "Comodo sandbox"),
]

_RANSOMWARE_NOTE_NAMES = {
    'how_to_decrypt.txt', 'your_files_are_encrypted.txt',
    'restore_files.txt', 'recovery_instruction.txt', 'decrypt_instructions.txt',
    'help_decrypt.html', '_readme.txt', '!!readme!!!.txt', 'ransom_note.txt',
    'files_are_encrypted.html', 'how_to_restore_files.txt',
    'decrypt_my_files.txt', 'read_me_to_decrypt.txt', '!!!_warning_!!!.txt',
}

_WMI_PATTERNS = [
    (b'SELECT * FROM __InstanceModificationEvent', "WMI event subscription (persistence)"),
    (b'__EventFilter',    "WMI EventFilter (persistence)"),
    (b'ActiveScriptEventConsumer', "WMI script event consumer (execution)"),
    (b'CommandLineEventConsumer',  "WMI commandline consumer (execution)"),
]


def check_behavioral_evasion(zf: zipfile.ZipFile) -> List[Finding]:
    """Detect VM/sandbox/debugger evasion, ransomware patterns, and WMI persistence."""
    findings = []

    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0:
            continue

        base_lower = os.path.basename(info.filename).lower()

        # ── Ransomware note filenames ────────────────────────────────
        if base_lower in _RANSOMWARE_NOTE_NAMES:
            findings.append(Finding(
                severity=Severity.CRITICAL,
                check="ransomware_note",
                description="Filename matches known ransomware ransom note pattern",
                filename=info.filename,
            ))
            continue

        if info.file_size > 2 * 1024 * 1024:
            continue

        try:
            with zf.open(info) as f:
                data = f.read(min(info.file_size, 65536))
        except Exception:
            continue

        # ── VM / sandbox evasion strings ─────────────────────────────
        found_vm: list = []
        for pattern, label in _VM_STRINGS:
            if pattern.lower() in data.lower():
                found_vm.append(label)
        if found_vm:
            findings.append(Finding(
                severity=Severity.HIGH,
                check="vm_evasion",
                description=f"Virtualization/sandbox detection strings — file may refuse to run in analysis environments",
                filename=info.filename,
                detail="; ".join(found_vm[:4]),
            ))

        # ── WMI persistence ──────────────────────────────────────────
        for pattern, label in _WMI_PATTERNS:
            if pattern.lower() in data.lower():
                findings.append(Finding(
                    severity=Severity.HIGH,
                    check="wmi_persistence",
                    description=f"WMI persistence: {label}",
                    filename=info.filename,
                    detail=pattern.decode('ascii', errors='replace'),
                ))
                break

    return findings


# ── Persistence Mechanisms ────────────────────────────────────────────────────

_RUN_KEY_PATTERNS = [
    b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    b'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    b'SYSTEM\\CurrentControlSet\\Services',
    b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders',
]

_STARTUP_PATHS = [
    b'\\Start Menu\\Programs\\Startup',
    b'\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
]


def check_persistence(zf: zipfile.ZipFile) -> List[Finding]:
    """Detect registry Run keys, startup folder entries, and scheduled task XML."""
    findings = []

    for info in zf.infolist():
        if info.is_dir() or info.file_size == 0:
            continue
        _, ext = os.path.splitext(info.filename.lower())
        base   = os.path.basename(info.filename).lower()

        # ── .reg files with Run keys ─────────────────────────────────
        if ext == '.reg':
            try:
                with zf.open(info) as f:
                    content = f.read(min(info.file_size, 128 * 1024))
                content_lower = content.lower()
                for pattern in _RUN_KEY_PATTERNS:
                    if pattern.lower() in content_lower:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            check="reg_persistence",
                            description=f"Registry file sets autostart key: {pattern.decode('ascii', errors='replace').split(chr(92))[-1]}",
                            filename=info.filename,
                            detail=pattern.decode('ascii', errors='replace'),
                        ))
                        break
            except Exception:
                pass

        # ── Scheduled task XML ───────────────────────────────────────
        elif ext == '.xml' and 'task' in base:
            try:
                with zf.open(info) as f:
                    content = f.read(min(info.file_size, 64 * 1024))
                if b'<Task ' in content and (b'<Exec>' in content or b'<ComHandler>' in content):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        check="scheduled_task",
                        description="Windows scheduled task definition — may establish persistence",
                        filename=info.filename,
                    ))
            except Exception:
                pass

        # ── .lnk shortcut files ──────────────────────────────────────
        elif ext == '.lnk':
            try:
                with zf.open(info) as f:
                    lnk_data = f.read(min(info.file_size, 4096))
                # LNK files start with magic 4C000000 01140200
                if lnk_data[:4] == b'\x4c\x00\x00\x00':
                    # Look for suspicious target paths
                    decoded = lnk_data.decode('utf-16-le', errors='replace').replace('\x00', '')
                    if any(t in decoded.lower() for t in ('cmd', 'powershell', 'wscript', 'cscript', 'mshta')):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            check="malicious_lnk",
                            description="Windows shortcut (.lnk) points to interpreter — likely a dropper",
                            filename=info.filename,
                            detail=decoded[:200],
                        ))
            except Exception:
                pass

        # ── Startup folder paths in scripts ─────────────────────────
        elif ext in {'.bat', '.ps1', '.vbs', '.cmd'}:
            try:
                with zf.open(info) as f:
                    content = f.read(min(info.file_size, 32 * 1024))
                for pattern in _STARTUP_PATHS:
                    if pattern.lower() in content.lower():
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            check="startup_path",
                            description="Script references Windows Startup folder — may copy itself for persistence",
                            filename=info.filename,
                            detail=pattern.decode('ascii', errors='replace'),
                        ))
                        break
            except Exception:
                pass

    return findings
