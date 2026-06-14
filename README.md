# ZIP Analyzer — Security Scanner

A static analysis engine for archive files that detects malware, trojans, and attack vectors before extraction. Ships with a drag-and-drop web dashboard, a command-line interface, 19 sample archives covering every threat class, and live threat intelligence via YARA rules and VirusTotal.

---

## Quick start

```bash
git clone <repo-url>
cd zip-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./run.sh          # starts server on http://localhost:5002
```

`./run.sh` kills any existing process on port 5002 before starting and frees the port automatically on Ctrl+C or shell exit.

---

## Supported formats

| Format | Extensions |
|---|---|
| ZIP (and ZIP-based) | `.zip` `.jar` `.apk` `.war` `.ear` `.docx` `.xlsx` `.pptx` |
| TAR | `.tar` `.tar.gz` `.tgz` `.tar.bz2` `.tbz2` `.tar.xz` |

---

## Threat intelligence

Two optional enrichment layers activate automatically when their prerequisites are met.

### YARA rule scanning

Scans every readable file inside the archive against 25 bundled YARA rules across 8 malware families. Findings include the rule name, family, and ATT&CK technique ID.

**Setup:** `yara-python` must be installed (included in `requirements.txt`).

```bash
pip install yara-python      # already in requirements.txt
python cli.py suspect.zip    # YARA scanning activates automatically
```

Rules live in `zip_analyzer/rules/` and can be extended with any standard YARA syntax.

### VirusTotal hash lookup

Computes SHA-256 for each entry and queries VirusTotal's v3 API. Executable and script files are checked first; up to 25 files per archive. Free-tier rate limiting (4 req/min) is applied automatically.

**Setup:** export your API key before running:

```bash
export VT_API_KEY="your-key-here"   # get a free key at virustotal.com
python cli.py suspect.zip
```

Test the integration without real malware using the bundled EICAR sample:

```bash
VT_API_KEY="your-key" python cli.py samples/19_vt_eicar_test.zip
# → CRITICAL virustotal_hit on eicar.com (60+ engines detect it)
```

---

## Detection capabilities

### Archive structure
| Check | Severity | Description |
|---|---|---|
| **path_traversal** | Critical | `../` sequences or absolute paths that escape the extraction directory |
| **zip_bomb** | High | Compression ratio >100:1 or total uncompressed size >1 GB |
| **file_count** | High | >10,000 entries — resource exhaustion on extraction |
| **null_byte_filename** | Critical | Raw central-directory scan; Python silently strips these, other tools don't |
| **duplicate_filename** | High | Two entries with the same name — extraction result is tool-dependent |
| **symlink** | High | Unix symlinks pointing outside the extraction root |
| **device_file** | Critical | Character/block device files in TAR archives |
| **setuid_file** | High | Setuid/setgid bit set on executables in TAR archives |

### File identity
| Check | Severity | Description |
|---|---|---|
| **magic_mismatch** | Critical | File extension claims `.pdf` but magic bytes show `MZ` (Windows PE) |
| **executable_binary** | High | Confirmed PE / ELF / Mach-O by magic bytes |
| **double_extension** | High | `invoice.pdf.exe` — extension camouflage |
| **dangerous_extension** | High | `.exe` `.dll` `.ps1` `.bat` `.sh` `.vbs` `.hta` `.js` `.jar` … |
| **macro_document** | Medium | `.docm` `.xlsm` `.pptm` — macro-enabled Office formats |

### Masquerading / social engineering
| Check | Severity | Description |
|---|---|---|
| **rtlo_attack** | Critical | U+202E Right-to-Left Override reverses filename display in Windows Explorer |
| **homograph_attack** | High | Cyrillic/Greek lookalike characters impersonate Latin filenames |
| **impersonation** | Medium | Executables with social-engineering names: `setup`, `update`, `crack`, `invoice` … |

### Content analysis
| Check | Severity | Description |
|---|---|---|
| **pe_import** | Critical/High/Medium | Windows API names in PE binaries indicate intent: process injection, credential dumping, keylogging, ransomware, anti-debug … |
| **high_entropy** | Medium | Shannon entropy ≥ 7.2/8.0 — content is likely encrypted, packed, or obfuscated |
| **suspicious_string** | High/Medium | `eval(base64_decode(...))`, PowerShell `-EncodedCommand`, download-and-exec, hardcoded `IP:port` |
| **malicious_comment** | High | PHP/JS/PowerShell code injected into the zip comment field |
| **hidden_file** | Low | Dot-prefixed files (`.env`, `.bashrc`, `.ssh/config`) |

### Document deep-scan
| Check | Severity | Description |
|---|---|---|
| **office_vba_confirmed** | High | `vbaProject.bin` present inside `.docx`/`.xlsx` — confirmed macro code |
| **office_external_link** | High | External data links — can force NTLM authentication to attacker server |
| **office_formula_injection** | High | `HYPERLINK`, `WEBSERVICE`, or shell commands in worksheet XML |
| **pdf_dangerous_key** | Critical/High/Med | `/JavaScript` `/OpenAction` `/Launch` `/EmbeddedFile` `/XFA` `/RichMedia` |

### Network IOCs
| Check | Severity | Description |
|---|---|---|
| **c2_address** | High | Public IP on known C2/RAT port (4444, 31337, 1337, 8080 …) |
| **tor_onion_address** | High | `.onion` address — likely C2 or illicit service |
| **malicious_url** | High | URLs with path components matching malware patterns |
| **dga_domain** | Medium | Domain matches DGA heuristic (algorithmically generated name) |

### Evasion & persistence
| Check | Severity | Description |
|---|---|---|
| **vm_evasion** | High | VMware / VirtualBox / QEMU / Sandboxie detection strings — file may refuse to run in analysis environments |
| **wmi_persistence** | High | WMI event subscription (`__EventFilter`, `ActiveScriptEventConsumer`) |
| **reg_persistence** | High | `.reg` file writes to `HKLM\…\Run` or `RunOnce` autostart keys |
| **scheduled_task** | High | Windows scheduled task XML definition |
| **malicious_lnk** | High | `.lnk` shortcut whose target invokes `cmd`/`powershell`/`wscript` |
| **startup_path** | High | Script copies itself to Windows Startup folder |
| **ransomware_note** | Critical | Filename matches known ransom note patterns (`how_to_decrypt.txt` …) |

### Metadata anomalies
| Check | Severity | Description |
|---|---|---|
| **timestamp_epoch** | Low | MS-DOS epoch (1980-01-01) — timestamp stripped or spoofed |
| **timestamp_future** | Low | File date is in the future — timestomping indicator |
| **encrypted_entry** | Medium | Encrypted entries that cannot be scanned |
| **nested_archive** | Medium | ZIP/RAR/GZ inside archive — requires recursive scan for full coverage |
| **suspicious_filename** | High | `autorun.inf`, `id_rsa`, `.htaccess`, `passwd`, `authorized_keys` … |

### Threat intelligence
| Check | Severity | Description |
|---|---|---|
| **yara_match** | Critical–Medium | File content matched one or more bundled YARA rules; finding includes rule name, malware family, and ATT&CK technique ID |
| **virustotal_hit** | Critical/High | SHA-256 found in VirusTotal; severity reflects detection count (≥3 engines = CRITICAL, ≥1 = HIGH) |

---

## YARA rule families

25 rules across 8 families ship with the scanner. All rules are in `zip_analyzer/rules/` and follow standard YARA syntax.

| File | Rules | What they detect |
|---|---|---|
| `injection.yar` | 2 | `VirtualAllocEx`/`CreateRemoteThread` classic injection, APC/`NtMapViewOfSection` injection |
| `credential_theft.yar` | 3 | `MiniDumpWriteDump` LSASS dump, SAM/LSA secrets, DPAPI decryption |
| `ransomware.yar` | 3 | `CryptEncrypt`/`BCryptEncrypt`, ransom note text, file-search + encrypt combo |
| `webshell.yar` | 3 | PHP `system($_GET[...])`, PHP `eval(base64_decode(...))`, PHP arbitrary file write |
| `dropper.yar` | 4 | PowerShell IEX+DownloadString, PowerShell DownloadFile to temp/system path, Python `exec(base64.b64decode(...))`, wget/curl + chmod/bash |
| `evasion.yar` | 3 | VM/sandbox string clusters (VMware/VBOX/QEMU), multi-API anti-debug, WMI event subscription |
| `obfuscation.yar` | 3 | PowerShell `-EncodedCommand` + evasion flags, large base64 blob, hex-encoded shellcode |
| `c2_malware.yar` | 3 | Tor `.onion` + exec/base64 beacon, `URLDownloadToFile`, HTTP send-request API |
| `keylogger.yar` | 1 | `SetWindowsHookEx`/`GetAsyncKeyState`/`GetRawInputData` |

**Adding custom rules:** Drop any `.yar` file into `zip_analyzer/rules/` — it is compiled and merged at startup.

---

## Risk scoring

Risk scores are additive and capped at 100. Three classes of findings use different diminishing-returns formulas to prevent any single noisy check from dominating:

| Finding class | Diminishing returns |
|---|---|
| **VirusTotal hits** | None — each confirmed-malicious file counts at full weight |
| **YARA matches** | Per rule name: 1st occurrence 1.0×, 2nd 0.5×, 3rd+ 0.25× |
| **All other checks** | Per check name: 1st 1.0×, 2nd 0.5×, 3rd+ 0.25× |

Severity weights: CRITICAL 45 · HIGH 22 · MEDIUM 10 · LOW 4 · INFO 1

| Score | Label |
|---|---|
| 0 | NONE |
| 1–15 | LOW |
| 16–35 | MEDIUM |
| 36–60 | HIGH |
| 61–100 | CRITICAL |

---

## Dashboard metrics

### Scores
- **Risk Score (0–100)** — severity-weighted sum with per-class diminishing returns, capped at 100
- **Scan Confidence (0–99%)** — `95 × (scanned/total) × (1 − entropy_drag)`, boosted slightly by VT-verified clean files

### Panels
- **Archive Profile** — file count, uncompressed size, compression ratio, threat category chips
- **Entropy Analysis** — average and peak Shannon entropy bars (color-coded green→red)
- **File Composition** — stacked extension breakdown bar
- **Archive Health** — timestamp anomalies, hidden file count, year range
- **MITRE ATT&CK** — deduped technique chips from static checks, YARA metadata, and PE imports
- **Indicators of Compromise** — tabbed IP / URL / Onion table with classification
- **Threat Intelligence** — YARA and VirusTotal side-by-side panel; shows rules loaded, files matched, per-rule and per-file results
- **File Hashes** — SHA-256 + MD5 for every entry, one-click copy

---

## CLI

```bash
python cli.py <file.zip> [file2.zip ...]
```

Exit codes: `0` = safe, `1` = threats found, `2` = error/invalid file.

YARA scanning is always active when `yara-python` is installed. VT lookup activates when `VT_API_KEY` is set.

---

## Python API

```python
from zip_analyzer import ZipAnalyzer
import os

os.environ["VT_API_KEY"] = "your-key"   # optional

result = ZipAnalyzer().analyze("path/to/file.zip")

print(result.summary())                          # "UNSAFE — 71 finding(s), max severity: CRITICAL"
print(result.metrics["risk_score"])              # 100
print(result.metrics["confidence"])              # 95

# Threat intelligence
ti = result.metrics["threat_intelligence"]
print(ti["yara"]["rules_loaded"])                # 25
print(ti["yara"]["files_matched"])               # 6
print(ti["yara"]["matches"][0]["rule"])          # "ProcessInjection_ClassicTriad"
print(ti["yara"]["matches"][0]["mitre"])         # "T1055.003"

print(ti["virustotal"]["enabled"])               # True / False
print(ti["virustotal"]["malicious"])             # 2
print(ti["virustotal"]["hits"][0]["threat_label"])  # "trojan.emotet/agent"

# Standard fields
print(result.metrics["mitre_techniques"])        # [{id, name}, ...] — includes YARA-sourced ATT&CK IDs
print(result.metrics["ioc_summary"])             # {ips, urls, onions}
print(result.metrics["file_hashes"])             # [{filename, sha256, md5}, ...]
```

---

## Tests

```bash
python -m pytest tests/ -v
# 40 tests, all passing
```

---

## Sample archives

All 19 samples in `samples/` are inert — no real malware. Contents are crafted headers, dummy bytes, and realistic strings that exercise every detection check. Run `python samples/create_samples.py` to regenerate them.

| File | Risk | Key detections |
|---|---|---|
| `01_clean_documents.zip` | 0 — NONE | Safe baseline |
| `02_trojan_invoice.zip` | 45 — MEDIUM | `magic_mismatch` (PE disguised as PDF) |
| `03_dropper_bundle.zip` | 100 — CRITICAL | `autorun.inf`, double extension, PE binaries, scripts |
| `04_phishing_kit.zip` | 74 — HIGH | PHP webshell, `.htaccess`, `malicious_comment` |
| `05_zip_bomb.zip` | 66 — HIGH | ~500:1 compression ratio |
| `06_path_traversal.zip` | 100 — CRITICAL | `../../../etc/cron.d`, `authorized_keys`, `.bashrc` |
| `07_exfiltration_pack.zip` | 74 — HIGH | SSH private keys, `.env`, encrypted entries (conf 55%) |
| `08_macro_and_symlink.zip` | 94 — CRITICAL | `.docm`/`.xlsm`, ELF binary, symlink escape |
| `09_obfuscated_payload.zip` | 100 — CRITICAL | PE disguised as `.dat`, `eval(base64_decode)`, C2 strings |
| `10_hidden_credentials.zip` | 12 — LOW | `.aws/credentials`, `.env`, `.bash_history`, future timestamp |
| `11_pe_injection.zip` | 100 — CRITICAL | `VirtualAllocEx`, `CreateRemoteThread`, `MiniDumpWriteDump` + 3 YARA rules |
| `12_rtlo_and_homograph.zip` | 100 — CRITICAL | U+202E RTLO reversal, Cyrillic lookalike filenames |
| `13_ransomware_simulation.zip` | 100 — CRITICAL | Ransom note, `CryptEncrypt` API, high-entropy files + 3 YARA rules |
| `14_vm_sandbox_evasion.zip` | 100 — CRITICAL | VMware/VBOX/QEMU strings, WMI event subscription |
| `15_malicious_pdf.zip` | 100 — CRITICAL | `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile` |
| `16_office_deep_analysis.zip` | 100 — CRITICAL | `vbaProject.bin` confirmed, external NTLM link, formula injection |
| `17_ioc_heavy_c2.zip` | 100 — CRITICAL | Public C2 IPs on port 4444/31337, Tor `.onion`, DGA domains, 12 IOCs |
| `18_yara_strike.zip` | 100 — CRITICAL | **21 YARA hits** across 8 families: injection, credential theft, ransomware, webshell, dropper, VM evasion, obfuscation, C2 |
| `19_vt_eicar_test.zip` | 20 — MEDIUM (static) | Contains the EICAR test string; with `VT_API_KEY` set returns CRITICAL `virustotal_hit` (60+ engines) |

---

## Project structure

```
zip-analyzer/
├── zip_analyzer/
│   ├── __init__.py
│   ├── analyzer.py          # ZipAnalyzer orchestrator (static + YARA + VT)
│   ├── tar_analyzer.py      # TarAnalyzer (TAR-specific threats)
│   ├── checks.py            # Static detection functions (~1100 lines, 20 checks)
│   ├── metrics.py           # Risk score, confidence, MITRE, IOC, hashes, TI summary
│   ├── models.py            # Severity, Finding, AnalysisResult
│   ├── yara_scanner.py      # YARA rule scanning (optional — yara-python)
│   ├── virustotal.py        # VirusTotal v3 hash lookup (optional — VT_API_KEY)
│   └── rules/               # Bundled YARA rules (25 rules, 8 families)
│       ├── injection.yar
│       ├── credential_theft.yar
│       ├── ransomware.yar
│       ├── webshell.yar
│       ├── dropper.yar
│       ├── evasion.yar
│       ├── obfuscation.yar
│       ├── c2_malware.yar
│       └── keylogger.yar
├── templates/
│   └── index.html           # Web UI (findings, metrics, TI panel, MITRE, IOC, hashes)
├── tests/
│   ├── fixtures.py          # Programmatic ZIP builders for every threat class
│   └── test_analyzer.py     # 40 pytest tests
├── samples/
│   ├── create_samples.py    # Generates all 19 sample archives
│   └── *.zip                # Pre-generated samples (01–19)
├── app.py                   # Flask server + JSON error handling
├── cli.py                   # Colorized CLI
├── run.sh                   # Start script — frees port on exit
└── requirements.txt
```

---

## Implementation notes

**Null byte filenames** — Python's `zipfile` truncates filenames at `\x00` on read. The raw central-directory scanner in `checks.py` parses the binary directly with `struct` to catch this class of attack.

**YARA compilation** — Rules are compiled once at module import time and cached for the process lifetime. YARA-Python loads all `.yar` files from `zip_analyzer/rules/` using namespaced compilation so rule names don't collide across files. Encrypted entries are skipped (can't decompress).

**VT scoring — no diminishing returns** — Each VT-confirmed malicious file represents a uniquely-identified threat (different SHA-256). Unlike static heuristics where the same check fires on ten files (one noisy signal), each VT hit is a separate confirmed fact, so all count at full weight. A single confirmed-malicious file adds 45 points; two add 90; three guarantee a 100 CRITICAL score.

**YARA scoring — per rule, not per file** — The same YARA rule matching two different files does carry diminishing returns (second match 0.5×), because the rule is one signal observed twice. But two different rules are two independent signals and each counts fully on first match.

**Confidence formula** — proportional, not magic numbers:
```
coverage    = scanned_files / total_files
entropy_drag = min(high_entropy_files / total_files × 0.25, 0.25)
confidence   = round(95 × coverage × (1 − entropy_drag))
# VT clean files add up to +8 percentage points
```

**PE import detection** — Windows API import names appear as literal ASCII strings in PE binaries. No full PE parsing needed; regex scan of the binary catches them reliably and works on truncated/partial files.

**Office deep-scan** — `.docx`/`.xlsx` files are themselves ZIP archives. The analyzer recursively opens them with `zipfile.ZipFile(io.BytesIO(...))` to inspect for `vbaProject.bin`, `externalLinks/`, and suspicious XML content.

**MITRE ATT&CK** — Every static check maps to a technique ID in `metrics.py`. YARA findings carry their ATT&CK ID in the `detail` field and are parsed into the same `mitre_techniques` array. All techniques are deduplicated by ID before display.
