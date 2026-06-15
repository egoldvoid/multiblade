# Security Policy

## Scope

Vantage is a **localhost-only developer tool** — it is not designed to be exposed
on a public network. The mitigations below reflect that deployment model.

---

## Implemented Mitigations

| Area | Mitigation |
|---|---|
| CSRF | Origin/Referer checked on all mutating endpoints; `application/x-www-form-urlencoded` rejected; Private Network Access policy (Chrome 94+/Firefox 90+) provides additional browser-level isolation |
| Security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Content-Security-Policy` (no `unsafe-eval`), `Permissions-Policy`, `X-Permitted-Cross-Domain-Policies: none` |
| File upload | Extension allowlist; `tempfile.mkstemp` with mode 600; `secure_filename` for display; `MAX_UPLOAD_MB` size cap (default 256 MB, enforced by Flask `MAX_CONTENT_LENGTH`) |
| Path traversal | `ZipAnalyzer` and `TarAnalyzer` both check for `..` in entry names, symlinks outside archive root, and absolute paths |
| Zip bombs | Uncompressed size cap (1 GB), compression ratio cap (100:1) |
| SQL injection | All SQLite queries are parameterised via `sqlite3` placeholder `?` |
| ReDoS | User-supplied regex patterns are validated at save time: max 1 000 chars, nested-quantifier patterns rejected; file content passed to `re.search` is capped at 64 KB |
| YARA | Rule content capped at 64 KB on submit; YARA scanner enforces per-entry 4 MB read limit, 200 entry limit, 128 MB total limit, and a 3-second per-entry match timeout |
| SSRF | VirusTotal URL is always `https://www.virustotal.com/api/v3/files/<sha256>` where `sha256` is computed server-side — no user input reaches the URL |
| IOC pivot DoS | Query must contain ≥ 3 non-wildcard characters to prevent `LIKE '%%%'` full-table scans |
| Error handling | Generic 500 handler returns no traceback; Werkzeug `version_string` masked |
| Dependency hygiene | See `requirements.txt`; run `pip-audit` periodically |

---

## Known Limitations / Out of Scope

- **Not safe for public exposure.** Do not bind to `0.0.0.0` or place behind a
  reverse proxy accessible from untrusted networks.
- **No authentication.** Anyone who can reach the web port has full access.
- **Stored XSS risk in filenames.** Uploaded filenames are `secure_filename`-
  sanitised for storage but displayed in templates. Templates use Jinja2
  auto-escaping, which prevents stored XSS via HTML injection; however, if this
  assumption changes, an explicit sanitisation pass is needed.
- **Watch folder.** User-supplied filesystem paths are used with `os.walk` — no
  restriction to a specific base directory. Intended for trusted local users only.
- **YARA draft content.** Drafts are compiled on test-request but not sandboxed.
  Very large or complex YARA rules could consume significant CPU.

---

## Dependency Audit

Run periodically:

```bash
pip install pip-audit
pip-audit -r requirements.txt
```
