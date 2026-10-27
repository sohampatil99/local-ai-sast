"""Scan history storage: PostgreSQL when SAST_DATABASE_URL is set, otherwise a local SQLite file."""
import json
import os
import sqlite3
import threading
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent / ".env"


def _database_url():
    """SAST_DATABASE_URL from the environment, else from backend/.env (kept out of git)."""
    if os.environ.get("SAST_DATABASE_URL"):
        return os.environ["SAST_DATABASE_URL"]
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == "SAST_DATABASE_URL":
                return value.strip()
    return ""


DB_URL = _database_url()
SQLITE_PATH = Path(__file__).resolve().parent / "data" / "sast.db"
COLUMNS = ("id", "target", "status", "progress", "started_at", "duration", "score", "grade",
           "total", "summary", "result", "error")
SCHEMA = """CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, target TEXT NOT NULL, status TEXT NOT NULL, progress TEXT,
    started_at TEXT, duration REAL, score INTEGER, grade TEXT, total INTEGER,
    summary TEXT, result TEXT, error TEXT)"""


class Storage:
    def __init__(self, url=DB_URL):
        self.lock = threading.Lock()
        if url.startswith("postgres"):
            import psycopg
            self.kind, self.ph = "postgresql", "%s"
            self.conn = psycopg.connect(url, autocommit=True)
        else:
            SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.kind, self.ph = "sqlite", "?"
            self.conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
        self._exec(SCHEMA)

    def _exec(self, sql, params=(), fetch=False):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(sql.replace("?", self.ph), params)
            rows = cur.fetchall() if fetch else None
            if self.kind == "sqlite":
                self.conn.commit()
            return rows

    def create(self, scan_id, target, started_at):
        self._exec("INSERT INTO scans (id, target, status, progress, started_at) VALUES (?, ?, ?, ?, ?)",
                   (scan_id, target, "running", "Queued", started_at))

    def progress(self, scan_id, message):
        self._exec("UPDATE scans SET progress = ? WHERE id = ?", (message, scan_id))

    def finish(self, scan_id, result):
        s = result["summary"]
        self._exec("UPDATE scans SET status = ?, progress = ?, duration = ?, score = ?, grade = ?, total = ?, "
                   "summary = ?, result = ? WHERE id = ?",
                   ("done", "Done", result["duration_seconds"], s["security_score"], s["grade"], s["total"],
                    json.dumps(s), json.dumps(result), scan_id))

    def fail(self, scan_id, error):
        self._exec("UPDATE scans SET status = ?, error = ? WHERE id = ?", ("failed", error, scan_id))

    def list(self, limit=50):
        rows = self._exec("SELECT id, target, status, progress, started_at, duration, score, grade, total, "
                          "summary, error FROM scans ORDER BY started_at DESC LIMIT ?", (limit,), fetch=True)
        cols = [c for c in COLUMNS if c != "result"]
        out = []
        for row in rows:
            item = dict(zip(cols, row))
            item["summary"] = json.loads(item["summary"]) if item["summary"] else None
            out.append(item)
        return out

    def get(self, scan_id):
        rows = self._exec("SELECT " + ", ".join(COLUMNS) + " FROM scans WHERE id = ?", (scan_id,), fetch=True)
        if not rows:
            return None
        item = dict(zip(COLUMNS, rows[0]))
        item["summary"] = json.loads(item["summary"]) if item["summary"] else None
        item["result"] = json.loads(item["result"]) if item["result"] else None
        return item

    def delete(self, scan_id):
        self._exec("DELETE FROM scans WHERE id = ?", (scan_id,))
