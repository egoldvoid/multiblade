"""Analyzer for TAR archives (.tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.xz)."""

import math
import os
import tarfile
from collections import Counter
from pathlib import Path
from typing import Union

from .models import AnalysisResult, Finding, Severity
from .checks import (
    DANGEROUS_EXTENSIONS,
    MAGIC_SIGNATURES,
    SUSPICIOUS_NAMES,
    shannon_entropy,
)

_RISK_WEIGHTS = {
    Severity.CRITICAL: 45, Severity.HIGH: 22,
    Severity.MEDIUM: 10,   Severity.LOW: 4, Severity.INFO: 1,
}
_RISK_LABELS = [(0,"NONE"),(15,"LOW"),(35,"MEDIUM"),(60,"HIGH"),(101,"CRITICAL")]

def _risk_label(score):
    for t, l in _RISK_LABELS:
        if score <= t: return l
    return "CRITICAL"


class TarAnalyzer:
    """Scan TAR archives for the same threat classes as ZipAnalyzer."""

    def analyze(self, path: Union[str, Path]) -> AnalysisResult:
        path = str(path)
        result = AnalysisResult(path=path)

        if not tarfile.is_tarfile(path):
            result.error = "Not a valid TAR archive"
            result.safe = False
            return result

        try:
            with tarfile.open(path, "r:*") as tf:
                members = tf.getmembers()
                for m in members:
                    self._check_member(m, tf, result)
                result.metrics = self._compute_metrics(members, result.findings, tf)
        except tarfile.TarError as e:
            result.error = f"Corrupt or invalid TAR: {e}"
            result.safe = False
        except Exception as e:
            result.error = f"Unexpected error: {e}"
            result.safe = False

        return result

    def _add(self, result, finding):
        result.findings.append(finding)
        if finding.severity in (Severity.HIGH, Severity.CRITICAL):
            result.safe = False

    def _check_member(self, m, tf, result):
        name = m.name

        # ── Path traversal ──────────────────────────────────────────
        if name.startswith("/") or name.startswith("\\"):
            self._add(result, Finding(Severity.CRITICAL, "path_traversal",
                "Absolute path in TAR entry — may overwrite system files", filename=name))
        elif ".." in name.replace("\\", "/").split("/"):
            self._add(result, Finding(Severity.CRITICAL, "path_traversal",
                "Directory traversal sequence in filename", filename=name))

        # ── Symlinks ────────────────────────────────────────────────
        if m.issym():
            self._add(result, Finding(Severity.HIGH, "symlink",
                "Symlink may point outside extraction directory",
                filename=name, detail=f"-> {m.linkname}"))

        # ── Hard links ──────────────────────────────────────────────
        if m.islnk() and (".." in m.linkname or m.linkname.startswith("/")):
            self._add(result, Finding(Severity.HIGH, "hardlink_escape",
                "Hard link target escapes archive root",
                filename=name, detail=f"-> {m.linkname}"))

        # ── Device files ────────────────────────────────────────────
        if m.ischr() or m.isblk():
            self._add(result, Finding(Severity.CRITICAL, "device_file",
                f"{'Character' if m.ischr() else 'Block'} device file in archive — extracting may create real device",
                filename=name))

        # ── Dangerous extensions ────────────────────────────────────
        if m.isfile():
            _, ext = os.path.splitext(name.lower())
            if ext in DANGEROUS_EXTENSIONS:
                sev = Severity.HIGH if ext in {".exe",".dll",".bat",".ps1",".sh",".vbs",".hta"} else Severity.MEDIUM
                self._add(result, Finding(sev, "dangerous_extension",
                    f"Executable or script file: {ext}", filename=name))

        # ── Suspicious names ────────────────────────────────────────
        basename = os.path.basename(name).lower()
        if basename in SUSPICIOUS_NAMES:
            self._add(result, Finding(Severity.HIGH, "suspicious_filename",
                f"Sensitive or commonly-abused filename: {basename}", filename=name))

        # ── Magic bytes + entropy ───────────────────────────────────
        if m.isfile() and m.size > 0:
            try:
                fobj = tf.extractfile(m)
                if fobj:
                    sample = fobj.read(65536)
                    fobj.close()
                    # magic
                    for magic, label in MAGIC_SIGNATURES.items():
                        if sample[:8].startswith(magic):
                            _, ext = os.path.splitext(name.lower())
                            if "archive" in label.lower():
                                self._add(result, Finding(Severity.MEDIUM, "nested_archive",
                                    f"Nested {label}", filename=name))
                            elif "executable" in label.lower() or "binary" in label.lower():
                                if ext not in {".exe",".dll",".so",".elf",""}:
                                    self._add(result, Finding(Severity.CRITICAL, "magic_mismatch",
                                        f"Claims to be {ext or 'unknown'} but is {label}", filename=name))
                                else:
                                    self._add(result, Finding(Severity.HIGH, "executable_binary",
                                        f"Confirmed {label} by magic bytes", filename=name))
                            break
                    # entropy
                    _, ext = os.path.splitext(name.lower())
                    naturally_high = {".jpg",".png",".gz",".zip",".docx"}
                    if ext not in naturally_high and m.size >= 256:
                        h = shannon_entropy(sample)
                        if h >= 7.2:
                            self._add(result, Finding(Severity.MEDIUM, "high_entropy",
                                f"Entropy {h:.2f}/8.0 — may be encrypted or obfuscated",
                                filename=name, detail=f"entropy={h:.2f}"))
            except Exception:
                pass

        # ── Setuid/setgid ────────────────────────────────────────────
        if m.isfile() and m.mode & 0o4000:
            self._add(result, Finding(Severity.HIGH, "setuid_file",
                "Setuid bit set — file would run as owner when executed", filename=name))
        if m.isfile() and m.mode & 0o2000:
            self._add(result, Finding(Severity.HIGH, "setgid_file",
                "Setgid bit set — file would run with group privileges", filename=name))

    def _compute_metrics(self, members, findings, tf):
        files = [m for m in members if m.isfile()]
        total_files = len(files)
        total_uncompressed = sum(m.size for m in files)
        encrypted_count = sum(1 for f in findings if f.check == "encrypted_entry")
        nested_count    = sum(1 for f in findings if f.check == "nested_archive")

        raw_risk   = sum(_RISK_WEIGHTS.get(f.severity, 0) for f in findings)
        risk_score = min(100, raw_risk)

        ext_counter: Counter = Counter()
        for m in files:
            _, ext = os.path.splitext(m.name.lower())
            ext_counter[ext or "(none)"] += 1

        return {
            "risk_score":        risk_score,
            "risk_label":        _risk_label(risk_score),
            "confidence":        max(15, 95 - encrypted_count * 20 - nested_count * 8),
            "confidence_note":   None,
            "total_files":       total_files,
            "total_uncompressed": total_uncompressed,
            "avg_compression_ratio": "N/A",
            "scanned_files":     total_files - encrypted_count,
            "unscanned_files":   encrypted_count,
            "coverage":          round((total_files - encrypted_count) / total_files * 100) if total_files else 100,
            "encrypted_count":   encrypted_count,
            "nested_count":      nested_count,
            "threat_categories": list(dict.fromkeys(f.check for f in findings)),
            "top_file_types":    [{"ext": e, "count": c} for e, c in ext_counter.most_common(6)],
            "high_entropy_count": sum(1 for f in findings if f.check == "high_entropy"),
            "max_entropy":       None,
            "max_entropy_file":  None,
            "avg_entropy":       None,
            "timestamp_anomalies": 0,
            "ts_epoch": 0, "ts_future": 0,
            "date_range":        None,
            "hidden_count":      sum(1 for m in files if os.path.basename(m.name).startswith(".")),
        }
