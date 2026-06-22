"""SQLite persistence layer for Vantage platform."""
import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_DB_PATH = Path(__file__).parent.parent / "data" / "vantage.db"
_lock = threading.Lock()
_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _DB_PATH.parent.mkdir(exist_ok=True)
        _conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


def init():
    with _lock:
        c = _get_conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                filename     TEXT    NOT NULL,
                filesize     INTEGER DEFAULT 0,
                scanned_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                safe         INTEGER DEFAULT 1,
                risk_score   INTEGER DEFAULT 0,
                risk_label   TEXT    DEFAULT '',
                max_severity TEXT    DEFAULT '',
                findings_json TEXT   DEFAULT '[]',
                metrics_json  TEXT   DEFAULT '{}',
                notes        TEXT    DEFAULT '',
                status       TEXT    DEFAULT 'new'
            );
            CREATE TABLE IF NOT EXISTS iocs (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id  INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                type     TEXT,
                value    TEXT,
                context  TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS iocs_value ON iocs(value);
            CREATE INDEX IF NOT EXISTS iocs_scan  ON iocs(scan_id);
            CREATE TABLE IF NOT EXISTS custom_checks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                type        TEXT NOT NULL,
                pattern     TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'medium',
                description TEXT DEFAULT '',
                enabled     INTEGER DEFAULT 1,
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count   INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS yara_drafts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                name           TEXT NOT NULL,
                content        TEXT NOT NULL DEFAULT '',
                created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_tested_at TIMESTAMP,
                last_result    TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS watch_folders (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                path            TEXT NOT NULL UNIQUE,
                enabled         INTEGER DEFAULT 1,
                created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_scanned_at TIMESTAMP,
                total_scanned   INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS saved_commands (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement  TEXT NOT NULL DEFAULT 'default',
                tool_slug   TEXT NOT NULL,
                tool_name   TEXT NOT NULL,
                command     TEXT NOT NULL,
                note        TEXT NOT NULL DEFAULT '',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS sc_engagement ON saved_commands(engagement);
        """)
        c.commit()


# ── Scans ──────────────────────────────────────────────────────────────────────

def save_scan(result: Dict) -> int:
    metrics   = result.get("metrics", {})
    findings  = result.get("findings", [])
    ioc_data  = metrics.get("ioc_summary", {})
    hashes    = metrics.get("file_hashes", [])

    with _lock:
        c = _get_conn()
        cur = c.execute("""
            INSERT INTO scans
              (filename, filesize, safe, risk_score, risk_label, max_severity,
               findings_json, metrics_json)
            VALUES (?,?,?,?,?,?,?,?)
        """, (
            result.get("filename", ""),
            result.get("filesize", 0),
            1 if result.get("safe") else 0,
            metrics.get("risk_score", 0),
            metrics.get("risk_label", ""),
            result.get("max_severity") or "",
            json.dumps(findings),
            json.dumps(metrics),
        ))
        scan_id = cur.lastrowid

        rows: List[tuple] = []
        for ip_obj in ioc_data.get("ips", []):
            rows.append((scan_id, "ip", ip_obj["ip"], ip_obj.get("type", "")))
        for url in ioc_data.get("urls", []):
            rows.append((scan_id, "url", url, ""))
        for onion in ioc_data.get("onions", []):
            rows.append((scan_id, "onion", onion, ""))
        for h in hashes:
            rows.append((scan_id, "hash", h["sha256"], h.get("filename", "")))

        if rows:
            c.executemany(
                "INSERT INTO iocs (scan_id, type, value, context) VALUES (?,?,?,?)", rows
            )
        c.commit()
    return scan_id


def get_scans(limit: int = 200, offset: int = 0) -> List[Dict]:
    with _lock:
        c = _get_conn()
        rows = c.execute("""
            SELECT id, filename, filesize, scanned_at, safe,
                   risk_score, risk_label, max_severity, notes, status
            FROM scans
            ORDER BY scanned_at DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> Optional[Dict]:
    with _lock:
        c = _get_conn()
        row = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["findings"] = json.loads(d.pop("findings_json") or "[]")
    d["metrics"]  = json.loads(d.pop("metrics_json")  or "{}")
    return d


def delete_scan(scan_id: int):
    with _lock:
        c = _get_conn()
        c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        c.commit()


def update_scan(scan_id: int, notes: Optional[str] = None, status: Optional[str] = None):
    with _lock:
        c = _get_conn()
        if notes is not None:
            c.execute("UPDATE scans SET notes=? WHERE id=?", (notes, scan_id))
        if status is not None:
            c.execute("UPDATE scans SET status=? WHERE id=?", (status, scan_id))
        c.commit()


def pivot_ioc(query: str) -> List[Dict]:
    with _lock:
        c = _get_conn()
        rows = c.execute("""
            SELECT i.type, i.value, i.context,
                   s.id as scan_id, s.filename, s.scanned_at,
                   s.risk_score, s.risk_label, s.safe
            FROM iocs i
            JOIN scans s ON i.scan_id = s.id
            WHERE i.value LIKE ?
            ORDER BY s.scanned_at DESC
            LIMIT 100
        """, (f"%{query}%",)).fetchall()
    return [dict(r) for r in rows]


def scan_stats() -> Dict:
    with _lock:
        c = _get_conn()
        total    = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        unsafe   = c.execute("SELECT COUNT(*) FROM scans WHERE safe=0").fetchone()[0]
        last_row = c.execute("SELECT scanned_at FROM scans ORDER BY scanned_at DESC LIMIT 1").fetchone()
    return {
        "total":   total,
        "unsafe":  unsafe,
        "last_at": last_row[0] if last_row else None,
    }


# ── Custom checks ──────────────────────────────────────────────────────────────

def get_custom_checks() -> List[Dict]:
    with _lock:
        rows = _get_conn().execute(
            "SELECT * FROM custom_checks ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def save_custom_check(name: str, type_: str, pattern: str,
                      severity: str, description: str) -> int:
    with _lock:
        c = _get_conn()
        cur = c.execute(
            "INSERT INTO custom_checks (name,type,pattern,severity,description) VALUES (?,?,?,?,?)",
            (name, type_, pattern, severity, description),
        )
        c.commit()
    return cur.lastrowid


def toggle_custom_check(check_id: int, enabled: bool):
    with _lock:
        c = _get_conn()
        c.execute("UPDATE custom_checks SET enabled=? WHERE id=?",
                  (1 if enabled else 0, check_id))
        c.commit()


def delete_custom_check(check_id: int):
    with _lock:
        c = _get_conn()
        c.execute("DELETE FROM custom_checks WHERE id=?", (check_id,))
        c.commit()


def increment_check_hits(check_id: int):
    with _lock:
        c = _get_conn()
        c.execute("UPDATE custom_checks SET hit_count=hit_count+1 WHERE id=?", (check_id,))
        c.commit()


# ── YARA drafts ───────────────────────────────────────────────────────────────

def get_yara_drafts() -> List[Dict]:
    with _lock:
        rows = _get_conn().execute(
            "SELECT * FROM yara_drafts ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def save_yara_draft(name: str, content: str) -> int:
    with _lock:
        c = _get_conn()
        cur = c.execute("INSERT INTO yara_drafts (name,content) VALUES (?,?)", (name, content))
        c.commit()
    return cur.lastrowid


def update_yara_draft(draft_id: int, content: Optional[str] = None,
                      last_result: Optional[str] = None):
    with _lock:
        c = _get_conn()
        if content is not None:
            c.execute("UPDATE yara_drafts SET content=? WHERE id=?", (content, draft_id))
        if last_result is not None:
            c.execute(
                "UPDATE yara_drafts SET last_result=?, last_tested_at=CURRENT_TIMESTAMP WHERE id=?",
                (last_result, draft_id),
            )
        c.commit()


def delete_yara_draft(draft_id: int):
    with _lock:
        c = _get_conn()
        c.execute("DELETE FROM yara_drafts WHERE id=?", (draft_id,))
        c.commit()


# ── Watch folders ─────────────────────────────────────────────────────────────

def get_watch_folders() -> List[Dict]:
    with _lock:
        rows = _get_conn().execute("SELECT * FROM watch_folders ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


def add_watch_folder(path: str) -> int:
    with _lock:
        c = _get_conn()
        cur = c.execute("INSERT OR IGNORE INTO watch_folders (path) VALUES (?)", (path,))
        c.commit()
    return cur.lastrowid


def toggle_watch_folder(folder_id: int, enabled: bool):
    with _lock:
        c = _get_conn()
        c.execute("UPDATE watch_folders SET enabled=? WHERE id=?",
                  (1 if enabled else 0, folder_id))
        c.commit()


def delete_watch_folder(folder_id: int):
    with _lock:
        c = _get_conn()
        c.execute("DELETE FROM watch_folders WHERE id=?", (folder_id,))
        c.commit()


def mark_folder_scanned(folder_id: int):
    with _lock:
        c = _get_conn()
        c.execute(
            "UPDATE watch_folders SET last_scanned_at=CURRENT_TIMESTAMP, total_scanned=total_scanned+1 WHERE id=?",
            (folder_id,),
        )
        c.commit()


# ── Campaigns ─────────────────────────────────────────────────────────────────

def get_campaigns() -> List[Dict]:
    with _lock:
        c = _get_conn()
        rows = c.execute("""
            SELECT i.type, i.value,
                   COUNT(DISTINCT i.scan_id) AS scan_count,
                   GROUP_CONCAT(DISTINCT i.scan_id) AS scan_ids
            FROM iocs i
            WHERE i.type IN ('ip','onion','url')
              AND length(i.value) > 4
            GROUP BY i.type, i.value
            HAVING scan_count > 1
            ORDER BY scan_count DESC
            LIMIT 30
        """).fetchall()

        campaigns = []
        for row in rows:
            scan_ids = [int(x) for x in row["scan_ids"].split(",")]
            scans = []
            for sid in scan_ids[:8]:
                s = c.execute(
                    "SELECT id, filename, scanned_at, risk_score, risk_label, safe FROM scans WHERE id=?",
                    (sid,),
                ).fetchone()
                if s:
                    scans.append(dict(s))
            campaigns.append({
                "type":      row["type"],
                "indicator": row["value"],
                "scan_count": row["scan_count"],
                "scans":     scans,
            })
    return campaigns


# ── Playbooks ──────────────────────────────────────────────────────────────────

def save_playbook_entry(engagement: str, tool_slug: str, tool_name: str,
                        command: str, note: str = "") -> int:
    engagement = (engagement or "default").strip()[:100]
    with _lock:
        c = _get_conn()
        cur = c.execute(
            "INSERT INTO saved_commands (engagement,tool_slug,tool_name,command,note) VALUES (?,?,?,?,?)",
            (engagement, tool_slug, tool_name, command, note),
        )
        c.commit()
    return cur.lastrowid


def get_playbook_entries(engagement: Optional[str] = None) -> List[Dict]:
    with _lock:
        c = _get_conn()
        if engagement:
            rows = c.execute(
                "SELECT * FROM saved_commands WHERE engagement=? ORDER BY created_at DESC",
                (engagement,),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM saved_commands ORDER BY engagement, created_at DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def get_engagement_names() -> List[str]:
    with _lock:
        rows = _get_conn().execute(
            "SELECT DISTINCT engagement FROM saved_commands ORDER BY engagement"
        ).fetchall()
    return [r[0] for r in rows]


def delete_playbook_entry(entry_id: int):
    with _lock:
        c = _get_conn()
        c.execute("DELETE FROM saved_commands WHERE id=?", (entry_id,))
        c.commit()
