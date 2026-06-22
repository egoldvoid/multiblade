# Vantage — Security Operations Platform

A local-first security platform for penetration testers and security researchers. Ships as a self-hosted Flask app with three integrated wings: a 163-tool command generator, an archive malware analyzer, and a reference library — all behind a unified sidebar UI.

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

## What's inside

### Command Generators (`/generators`)

A searchable grid of 163 security tools across 18 categories. Each tool page is a data-driven form that builds the command string as you fill in flags and options.

**Features per tool page:**
- Form fields sync live into a command preview textarea
- Presets, flag reference table, share URL (base64 state), download `.sh`
- Copy / Copy one-liner / Reset
- Global Target bar — set once, propagates to target/host/IP fields across all tools
- Save to Playbook — saves the generated command to an engagement-named playbook

**Standalone generators:**
- **Reverse Shell Generator** (`/generators/revshells`) — 25 shell types, live IP/port, base64/URL encode toggles
- **Attack Workflows** (`/generators/workflows`) — 10 curated multi-tool chains (recon, webapp, AD, ransomware, etc.)
- **cURL Generator** (`/curl`) — dedicated cURL builder with more options than the generic system

**Standalone tools:**
- **Encoder / Decoder** (`/tools/encode`) — 13 transforms, fully client-side
- **Hash Identifier** (`/tools/hashid`) — 35+ algorithms, hashcat mode + john format

### Archive Analyzer (`/analyzer`)

Static analysis engine for ZIP and TAR archives. Detects 30+ threat classes before extraction.

**Supported formats:** `.zip` `.jar` `.apk` `.war` `.ear` `.docx` `.xlsx` `.pptx` `.tar` `.tar.gz` `.tgz` `.tar.bz2` `.tar.xz`

**Detection categories:** path traversal, zip bombs, null byte filenames, magic byte mismatches, RTLO/homograph attacks, PE import analysis, high entropy, C2 addresses, ransomware IOCs, Office macro analysis, PDF dangerous keys, YARA rule scanning, VirusTotal hash lookup — and more (see [Detection capabilities](#detection-capabilities) below).

**Additional analyzer tools:**
- **Triage** (`/triage`) — bulk queue, multiple files, ranked by risk score
- **Compare** (`/compare`) — diff two archive versions
- **History** (`/history`) — scan history with IOC pivot search
- **Campaigns** (`/campaigns`) — auto-clusters scans sharing IPs/onions/URLs
- **Watch Folders** (`/watch`) — monitor directories, trigger batch scans
- **YARA Playground** (`/yara`) — draft and test YARA rules live
- **Custom Checks** (`/custom-checks`) — define detection rules without code

### Reference Library

- **Port Reference** (`/reference/ports`) — 85-port database with risk levels, pentest notes, tool links
- **CVE Lookup** (`/reference/cve`) — live NVD API proxy, CVSS scores, Exploit-DB links, pagination
- **Wordlist Browser** (`/reference/wordlists`) — 40 SecLists entries, category filters, copy-path, tool links

### Engagement Features

- **Playbooks** (`/playbook`) — saved commands grouped by engagement name; add from any generator tool page via Save ↗
- **MITRE ATT&CK Browser** (`/mitre`) — 14 tactics, 50+ techniques, each linked to the relevant Vantage tools

---

## Tool categories

| Category | Tools | Color |
|---|---|---|
| Port Scanning | nmap, masscan, rustscan, naabu | |
| Web Fuzzing | ffuf, gobuster, feroxbuster, wpscan, dirsearch, wfuzz, dirb, joomscan, droopescan | |
| Vulnerability | nuclei, sqlmap, dalfox, nikto, commix, ssrfmap, tplmap, crlfuzz, interactsh, graphw00f, jwt_tool, corscanner, XSStrike, testssl, smuggler | |
| HTTP & Web | httpx, katana, whatweb, wafw00f, arjun, sslyze, gowitness, gospider, hakrawler, paramspider, cmseek, httprobe, sslscan, eyewitness, aquatone, kiterunner | |
| Recon & OSINT | subfinder, amass, waybackurls, gau, theHarvester, whois, shodan, assetfinder, findomain, recon-ng, spiderfoot, sherlock, uncover, asnmap, maigret, holehe | |
| DNS | dnsx, dig, tlsx, dnsrecon, dnstwist, fierce, massdns | |
| Active Directory | bloodhound-py, netexec, evil-winrm, secretsdump, getuserspns, psexec-py, kerbrute, responder, enum4linux-ng | |
| Exploitation | searchsploit, msfconsole, msfvenom | |
| Credentials | hydra, hashcat, medusa, spray, john | |
| Secrets | trufflehog, gitleaks, linkfinder, semgrep | |
| Forensics | volatility3, binwalk, exiftool, strings, file, xxd, yara-cli, oletools, foremost, clamav | |
| Reverse Engineering | ghidra, radare2, gdb, objdump, nm, strace, ltrace, pwndbg | |
| Cloud & Infra | s3scanner, pacu, trivy, grype, aws, gcloud, az, kubectl, checkov, prowler, terraform, cloudmapper, scoutsuite, snyk, hadolint, syft, cosign, dockle | |
| Mobile | frida, objection, apktool, jadx | |
| Network | nc, socat, tcpdump, tshark | |
| Password & Crypto | openssl, gpg, ssh-keygen, age, base64 | |
| Unix & Shell | grep, wget, find, ssh, rsync, scp, awk, sed, curl-unix, jq, xargs, tar, ps, netstat, cut, sort, uniq, wc, tr | |
| Misc | notify, interlace, gf, anew, qsreplace, unfurl | |

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
| **vm_evasion** | High | VMware / VirtualBox / QEMU / Sandboxie detection strings |
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

## Threat intelligence setup

### YARA rule scanning

Scans every readable file inside the archive against 25 bundled YARA rules across 8 malware families.

```bash
pip install yara-python      # already in requirements.txt
python cli.py suspect.zip    # YARA scanning activates automatically
```

Rules live in `zip_analyzer/rules/` — drop any `.yar` file there to extend coverage.

### VirusTotal hash lookup

```bash
export VT_API_KEY="your-key-here"   # get a free key at virustotal.com
python cli.py suspect.zip
```

Test with the bundled EICAR sample:
```bash
VT_API_KEY="your-key" python cli.py samples/19_vt_eicar_test.zip
# → CRITICAL virustotal_hit on eicar.com (60+ engines detect it)
```

---

## CLI

```bash
python cli.py <file.zip> [file2.zip ...]
```

Exit codes: `0` = safe, `1` = threats found, `2` = error/invalid file. YARA scanning activates when `yara-python` is installed; VT lookup activates when `VT_API_KEY` is set.

---

## Python API

```python
from zip_analyzer import ZipAnalyzer
import os

os.environ["VT_API_KEY"] = "your-key"   # optional

result = ZipAnalyzer().analyze("path/to/file.zip")
print(result.summary())                   # "UNSAFE — 71 finding(s), max severity: CRITICAL"
print(result.metrics["risk_score"])       # 100
print(result.metrics["mitre_techniques"]) # [{id, name}, ...]
print(result.metrics["ioc_summary"])      # {ips, urls, onions}
```

---

## Tests

```bash
python -m pytest tests/ -v
# 305 tests, all passing
```

---

## Sample archives

All 19 samples in `samples/` are inert — no real malware. Run `python samples/create_samples.py` to regenerate.

| File | Risk | Key detections |
|---|---|---|
| `01_clean_documents.zip` | 0 — NONE | Safe baseline |
| `02_trojan_invoice.zip` | 45 — MEDIUM | `magic_mismatch` (PE disguised as PDF) |
| `03_dropper_bundle.zip` | 100 — CRITICAL | `autorun.inf`, double extension, PE binaries, scripts |
| `04_phishing_kit.zip` | 74 — HIGH | PHP webshell, `.htaccess`, `malicious_comment` |
| `05_zip_bomb.zip` | 66 — HIGH | ~500:1 compression ratio |
| `06_path_traversal.zip` | 100 — CRITICAL | `../../../etc/cron.d`, `authorized_keys`, `.bashrc` |
| `07_exfiltration_pack.zip` | 74 — HIGH | SSH private keys, `.env`, encrypted entries |
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
| `18_yara_strike.zip` | 100 — CRITICAL | **21 YARA hits** across 8 families |
| `19_vt_eicar_test.zip` | 20 — MEDIUM (static) | EICAR test string; `virustotal_hit` CRITICAL with API key |

---

## Project structure

```
zip-analyzer/
├── zip_analyzer/
│   ├── analyzer.py          # ZipAnalyzer orchestrator (static + YARA + VT)
│   ├── tar_analyzer.py      # TarAnalyzer (TAR-specific threats)
│   ├── checks.py            # Static detection functions (~1100 lines, 30 checks)
│   ├── metrics.py           # Risk score, confidence, MITRE, IOC, hashes, TI
│   ├── models.py            # Severity, Finding, AnalysisResult
│   ├── yara_scanner.py      # YARA rule scanning (optional — yara-python)
│   ├── virustotal.py        # VirusTotal v3 hash lookup (optional — VT_API_KEY)
│   ├── database.py          # SQLite (vantage.db) — scans, IOCs, playbooks, watches
│   ├── tool_data.py         # 163-tool definitions for generator pages
│   ├── port_data.py         # 85-port reference database
│   ├── custom_check_engine.py
│   ├── stix_export.py       # STIX 2.1 + ATT&CK Navigator export
│   └── rules/               # Bundled YARA rules (25 rules, 8 families)
├── templates/
│   ├── _nav.html            # Fixed sidebar included in all inner pages
│   ├── landing.html         # Entry point (/)
│   ├── hub.html             # Platform hub (/platform)
│   ├── generators.html      # Tool grid (/generators)
│   ├── generator_tool.html  # Universal tool page (/generators/<slug>)
│   ├── playbook.html        # Saved commands (/playbook)
│   ├── mitre.html           # MITRE ATT&CK browser (/mitre)
│   ├── reference_ports.html # Port reference (/reference/ports)
│   ├── reference_cve.html   # CVE lookup (/reference/cve)
│   ├── reference_wordlists.html
│   └── ...                  # analyzer, triage, compare, history, campaigns, etc.
├── tests/
│   ├── fixtures.py          # Programmatic ZIP builders for every threat class
│   └── test_platform.py     # 305 pytest tests
├── samples/
│   ├── create_samples.py    # Generates all 19 sample archives
│   └── *.zip                # Pre-generated samples (01–19)
├── app.py                   # Flask server — all routes and REST API
├── cli.py                   # Colorized CLI
├── run.sh                   # Start script — frees port on exit
└── requirements.txt
```

---

## Risk scoring

Risk scores are additive and capped at 100.

| Finding class | Diminishing returns |
|---|---|
| **VirusTotal hits** | None — each confirmed-malicious file counts at full weight |
| **YARA matches** | Per rule name: 1st 1.0×, 2nd 0.5×, 3rd+ 0.25× |
| **All other checks** | Per check name: 1st 1.0×, 2nd 0.5×, 3rd+ 0.25× |

Severity weights: CRITICAL 45 · HIGH 22 · MEDIUM 10 · LOW 4 · INFO 1

| Score | Label |
|---|---|
| 0 | NONE |
| 1–15 | LOW |
| 16–35 | MEDIUM |
| 36–60 | HIGH |
| 61–100 | CRITICAL |
