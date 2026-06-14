import zipfile
from pathlib import Path
from typing import Union

from .checks import (
    check_behavioral_evasion,
    check_comment_injection,
    check_dangerous_extensions,
    check_deep_documents,
    check_double_extension,
    check_encrypted,
    check_entropy,
    check_file_count,
    check_hidden_files,
    check_ioc_strings,
    check_magic_bytes,
    check_path_traversal,
    check_pe_imports,
    check_persistence,
    check_raw_bytes,
    check_social_engineering,
    check_suspicious_names,
    check_suspicious_strings,
    check_symlinks,
    check_timestamps,
    check_zip_bomb,
)
from .metrics import compute as compute_metrics
from .models import AnalysisResult
from . import yara_scanner, virustotal
from .custom_check_engine import run_custom_checks


class ZipAnalyzer:
    """Scan a zip file for malware indicators, attack vectors, and safety issues."""

    CHECKS = [
        check_path_traversal,
        check_zip_bomb,
        check_file_count,
        check_dangerous_extensions,
        check_double_extension,
        check_magic_bytes,
        check_suspicious_names,
        check_symlinks,
        check_encrypted,
        check_comment_injection,
        check_entropy,
        check_timestamps,
        check_hidden_files,
        check_suspicious_strings,
        check_ioc_strings,
        check_pe_imports,
        check_social_engineering,
        check_deep_documents,
        check_behavioral_evasion,
        check_persistence,
    ]

    def analyze(self, path: Union[str, Path], custom_checks: list = None) -> AnalysisResult:
        path = str(path)
        result = AnalysisResult(path=path)

        try:
            raw = Path(path).read_bytes()
        except OSError as e:
            result.error = str(e)
            result.safe = False
            return result

        if not zipfile.is_zipfile(path):
            result.error = "Not a valid zip file"
            result.safe = False
            return result

        try:
            with zipfile.ZipFile(path, "r") as zf:
                for check_fn in self.CHECKS:
                    for finding in check_fn(zf):
                        result.add(finding)

                # ── Custom user-defined checks ────────────────────
                if custom_checks:
                    for finding in run_custom_checks(zf, custom_checks):
                        result.add(finding)

                # ── YARA rule scanning (optional) ──────────────────
                yara_findings, yara_summary = yara_scanner.check_yara(zf)
                for finding in yara_findings:
                    result.add(finding)

                # ── VirusTotal hash lookup (optional) ─────────────
                vt_findings, vt_summary = virustotal.check_virustotal(zf)
                for finding in vt_findings:
                    result.add(finding)

                result.metrics = compute_metrics(
                    zf,
                    result.findings,
                    yara_summary=yara_summary,
                    vt_summary=vt_summary,
                )

            for finding in check_raw_bytes(raw):
                result.add(finding)

        except zipfile.BadZipFile as e:
            result.error = f"Corrupt or invalid zip: {e}"
            result.safe = False
        except Exception as e:
            result.error = f"Unexpected error during analysis: {e}"
            result.safe = False

        return result
