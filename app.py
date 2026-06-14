import json
import os
import stat
import tempfile

from flask import Flask, jsonify, render_template, request, Response
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from zip_analyzer import ZipAnalyzer
from zip_analyzer.models import Severity
from zip_analyzer.tar_analyzer import TarAnalyzer
from zip_analyzer import database, stix_export

try:
    from werkzeug.serving import WSGIRequestHandler as _WRH
    _WRH.version_string = lambda self: "zip-analyzer"
except Exception:
    pass

_TAR_SUFFIXES = {".tar", ".tgz", ".tbz2", ".txz", ".tar.gz", ".tar.bz2", ".tar.xz"}
_MAX_MB  = int(os.environ.get("MAX_UPLOAD_MB", "256"))
_DEBUG   = os.environ.get("FLASK_DEBUG", "0") == "1"

_ALLOWED_EXT = {
    ".zip", ".jar", ".apk", ".war", ".ear",
    ".tar", ".tgz", ".tbz2", ".txz",
    ".gz", ".bz2", ".xz",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = _MAX_MB * 1024 * 1024

# Initialise database on startup
database.init()


# ── Security headers ──────────────────────────────────────────────────────────

@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'"
    )
    return response


# ── Helpers ───────────────────────────────────────────────────────────────────

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _allowed_file(filename: str) -> bool:
    lower = filename.lower()
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(compound):
            return True
    dot = lower.rfind(".")
    return dot != -1 and lower[dot:] in _ALLOWED_EXT


def _get_analyzer(filename: str):
    lower = filename.lower()
    if any(lower.endswith(s) for s in _TAR_SUFFIXES):
        return TarAnalyzer()
    return ZipAnalyzer()


def result_to_json(result, display_filename: str, filesize: int) -> dict:
    findings = []
    for f in sorted(result.findings, key=lambda x: SEV_ORDER.index(x.severity)):
        findings.append({
            "severity":    f.severity.value,
            "check":       f.check,
            "description": f.description,
            "filename":    f.filename,
            "detail":      f.detail,
        })
    return {
        "filename":       display_filename,
        "filesize":       filesize,
        "safe":           result.safe,
        "error":          result.error,
        "findings":       findings,
        "max_severity":   result.max_severity.value if result.max_severity else None,
        "finding_counts": {
            sev.value: sum(1 for f in result.findings if f.severity == sev)
            for sev in Severity
        },
        "metrics": result.metrics or {},
    }


def _csrf_check():
    origin  = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    if origin and not origin.startswith(("http://localhost", "http://127.0.0.1")):
        return False
    if referer and not referer.startswith(("http://localhost", "http://127.0.0.1")):
        return False
    return True


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(413)
def handle_too_large(_e):
    return jsonify({"error": f"File too large — maximum {_MAX_MB} MB"}), 413


@app.errorhandler(HTTPException)
def handle_http(e):
    return jsonify({"error": f"{e.code}: {e.description}"}), e.code


@app.errorhandler(Exception)
def handle_exc(_e):
    return jsonify({"error": "Internal server error"}), 500


# ── Page routes ───────────────────────────────────────────────────────────────

@app.route("/")
def hub():
    stats = database.scan_stats()
    return render_template("hub.html", stats=stats)


@app.route("/analyzer")
def analyzer():
    return render_template("index.html", active_page="analyzer")


@app.route("/history")
def history():
    return render_template("history.html", active_page="history")


@app.route("/triage")
def triage():
    return render_template("triage.html", active_page="triage")


@app.route("/compare")
def compare():
    return render_template("compare.html", active_page="compare")


@app.route("/yara")
def yara_page():
    return render_template("yara.html", active_page="yara")


@app.route("/campaigns")
def campaigns():
    return render_template("campaigns.html", active_page="campaigns")


@app.route("/custom-checks")
def custom_checks():
    return render_template("custom_checks.html", active_page="custom")


@app.route("/watch")
def watch():
    return render_template("watch.html", active_page="watch")


@app.route("/curl")
def curl_gen():
    return render_template("curl.html", active_page="curl")


# ── Core scan endpoint ────────────────────────────────────────────────────────

@app.route("/analyze", methods=["POST"])
def analyze():
    if not _csrf_check():
        return jsonify({"error": "Cross-origin requests are not permitted"}), 403

    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    if not _allowed_file(file.filename):
        return jsonify({"error": "Unsupported file type"}), 400

    display_name = secure_filename(file.filename) or "upload"

    fd, tmp_path = tempfile.mkstemp(suffix=".zip")
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    try:
        with os.fdopen(fd, "wb") as fh:
            file.save(fh)

        filesize  = os.path.getsize(tmp_path)
        scanner   = _get_analyzer(file.filename)

        # Load custom checks and pass them in
        custom = database.get_custom_checks()
        result = scanner.analyze(tmp_path, custom_checks=custom)

        data = result_to_json(result, display_name, filesize)

        # Auto-save to history
        try:
            scan_id = database.save_scan(data)
            data["scan_id"] = scan_id
        except Exception:
            pass

        return jsonify(data)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ── History API ───────────────────────────────────────────────────────────────

@app.route("/api/scans")
def api_scans():
    limit  = min(int(request.args.get("limit", 200)), 500)
    offset = int(request.args.get("offset", 0))
    return jsonify(database.get_scans(limit, offset))


@app.route("/api/scans/<int:scan_id>")
def api_scan(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan)


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
def api_delete_scan(scan_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_scan(scan_id)
    return jsonify({"ok": True})


@app.route("/api/scans/<int:scan_id>", methods=["PATCH"])
def api_update_scan(scan_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body   = request.get_json(silent=True) or {}
    notes  = body.get("notes")
    status = body.get("status")
    valid_statuses = {"new", "reviewed", "escalated", "false_positive"}
    if status and status not in valid_statuses:
        return jsonify({"error": "Invalid status"}), 400
    database.update_scan(scan_id, notes=notes, status=status)
    return jsonify({"ok": True})


@app.route("/api/ioc-pivot")
def api_ioc_pivot():
    q = request.args.get("q", "").strip()
    if len(q) < 3:
        return jsonify({"error": "Query too short (min 3 chars)"}), 400
    return jsonify(database.pivot_ioc(q))


# ── Export endpoints ──────────────────────────────────────────────────────────

@app.route("/api/scans/<int:scan_id>/stix")
def api_stix(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    bundle = stix_export.to_stix_bundle(scan)
    return Response(
        json.dumps(bundle, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="stix_{scan_id}.json"'},
    )


@app.route("/api/scans/<int:scan_id>/navigator")
def api_navigator(scan_id):
    scan = database.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Not found"}), 404
    layer = stix_export.to_navigator_layer(scan)
    return Response(
        json.dumps(layer, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="navigator_{scan_id}.json"'},
    )


# ── YARA playground API ───────────────────────────────────────────────────────

@app.route("/api/yara-drafts")
def api_yara_drafts():
    return jsonify(database.get_yara_drafts())


@app.route("/api/yara-drafts", methods=["POST"])
def api_save_yara_draft():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body = request.get_json(silent=True) or {}
    name    = (body.get("name") or "Untitled").strip()[:80]
    content = (body.get("content") or "").strip()
    draft_id = database.save_yara_draft(name, content)
    return jsonify({"id": draft_id})


@app.route("/api/yara-drafts/<int:draft_id>", methods=["PATCH"])
def api_update_yara_draft(draft_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body    = request.get_json(silent=True) or {}
    content = body.get("content")
    database.update_yara_draft(draft_id, content=content)
    return jsonify({"ok": True})


@app.route("/api/yara-drafts/<int:draft_id>", methods=["DELETE"])
def api_delete_yara_draft(draft_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_yara_draft(draft_id)
    return jsonify({"ok": True})


@app.route("/api/yara-test", methods=["POST"])
def api_yara_test():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403

    body    = request.get_json(silent=True) or {}
    rule    = (body.get("rule") or "").strip()
    scan_id = body.get("scan_id")

    if not rule:
        return jsonify({"error": "No rule provided"}), 400

    try:
        import yara as _yara
    except ImportError:
        return jsonify({"error": "yara-python not installed"}), 503

    try:
        compiled = _yara.compile(source=rule)
    except Exception as e:
        return jsonify({"error": f"Compile error: {e}"}), 400

    if not scan_id:
        return jsonify({"ok": True, "compiled": True, "matches": [], "note": "No scan selected — rule compiled OK"})

    scan = database.get_scan(int(scan_id))
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    # We don't have the original file anymore — test against stored hashes/findings only
    # Return a "compiled OK" result with note
    return jsonify({
        "ok": True,
        "compiled": True,
        "matches": [],
        "note": "Rule compiled successfully. Live testing against stored scans is not available (original files are not retained). Upload the archive via File Analyzer to test rules against it.",
    })


# ── Custom checks API ─────────────────────────────────────────────────────────

@app.route("/api/custom-checks")
def api_get_custom_checks():
    return jsonify(database.get_custom_checks())


@app.route("/api/custom-checks", methods=["POST"])
def api_save_custom_check():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body = request.get_json(silent=True) or {}
    name        = (body.get("name") or "").strip()[:80]
    type_       = (body.get("type") or "").strip()
    pattern     = (body.get("pattern") or "").strip()
    severity    = (body.get("severity") or "medium").strip().lower()
    description = (body.get("description") or "").strip()[:200]

    if not name or not type_ or not pattern:
        return jsonify({"error": "name, type, and pattern are required"}), 400
    if type_ not in ("regex", "string", "extension", "filename"):
        return jsonify({"error": "type must be: regex, string, extension, or filename"}), 400
    if severity not in ("critical", "high", "medium", "low", "info"):
        return jsonify({"error": "Invalid severity"}), 400

    if type_ == "regex":
        import re
        try:
            re.compile(pattern)
        except re.error as e:
            return jsonify({"error": f"Invalid regex: {e}"}), 400

    check_id = database.save_custom_check(name, type_, pattern, severity, description)
    return jsonify({"id": check_id})


@app.route("/api/custom-checks/<int:check_id>", methods=["DELETE"])
def api_delete_custom_check(check_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_custom_check(check_id)
    return jsonify({"ok": True})


@app.route("/api/custom-checks/<int:check_id>/toggle", methods=["POST"])
def api_toggle_custom_check(check_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body    = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))
    database.toggle_custom_check(check_id, enabled)
    return jsonify({"ok": True})


# ── Campaigns API ─────────────────────────────────────────────────────────────

@app.route("/api/campaigns")
def api_campaigns():
    return jsonify(database.get_campaigns())


# ── Watch folder API ──────────────────────────────────────────────────────────

@app.route("/api/watch-folders")
def api_get_watch_folders():
    return jsonify(database.get_watch_folders())


@app.route("/api/watch-folders", methods=["POST"])
def api_add_watch_folder():
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body = request.get_json(silent=True) or {}
    path = (body.get("path") or "").strip()
    if not path:
        return jsonify({"error": "path is required"}), 400
    if not os.path.isdir(path):
        return jsonify({"error": f"Directory not found: {path}"}), 400
    folder_id = database.add_watch_folder(path)
    return jsonify({"id": folder_id})


@app.route("/api/watch-folders/<int:folder_id>", methods=["DELETE"])
def api_delete_watch_folder(folder_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    database.delete_watch_folder(folder_id)
    return jsonify({"ok": True})


@app.route("/api/watch-folders/<int:folder_id>/toggle", methods=["POST"])
def api_toggle_watch_folder(folder_id):
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403
    body    = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))
    database.toggle_watch_folder(folder_id, enabled)
    return jsonify({"ok": True})


@app.route("/api/watch-folders/<int:folder_id>/scan", methods=["POST"])
def api_scan_watch_folder(folder_id):
    """Manually trigger a scan of all archives in a watched folder."""
    if not _csrf_check():
        return jsonify({"error": "Forbidden"}), 403

    folders = database.get_watch_folders()
    folder  = next((f for f in folders if f["id"] == folder_id), None)
    if not folder:
        return jsonify({"error": "Not found"}), 404

    path    = folder["path"]
    results = []
    custom  = database.get_custom_checks()

    archive_exts = {".zip", ".jar", ".apk", ".war", ".ear",
                    ".tar", ".tgz", ".tbz2", ".txz"}
    try:
        entries = [e for e in os.scandir(path) if e.is_file()]
    except OSError as e:
        return jsonify({"error": str(e)}), 400

    for entry in entries:
        lower = entry.name.lower()
        ext   = os.path.splitext(lower)[1]
        if ext not in archive_exts and not any(lower.endswith(s) for s in (".tar.gz", ".tar.bz2", ".tar.xz")):
            continue
        try:
            scanner = _get_analyzer(entry.name)
            result  = scanner.analyze(entry.path, custom_checks=custom)
            data    = result_to_json(result, entry.name, entry.stat().st_size)
            scan_id = database.save_scan(data)
            data["scan_id"] = scan_id
            results.append({"filename": entry.name, "scan_id": scan_id,
                             "risk_score": data["metrics"].get("risk_score", 0),
                             "safe": data["safe"]})
        except Exception as e:
            results.append({"filename": entry.name, "error": str(e)})

    database.mark_folder_scanned(folder_id)
    return jsonify({"scanned": len(results), "results": results})


if __name__ == "__main__":
    app.run(debug=_DEBUG, port=5002, use_reloader=False)
