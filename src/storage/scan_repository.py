"""
Persistent SQLite Scan Repository.
Stores real completed scan audits, prevents credential persistence,
and aggregates accurate metrics without data fabrication.
"""

import sqlite3
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from src.config import DATABASE_PATH
from src.utils.logging_config import logger
from src.utils.url_validation import redact_sensitive_query_params

class ScanRepository:
    """Manages scan history and telemetry in SQLite."""

    def __init__(self, db_path: str = None):
        self.db_path = Path(db_path) if db_path else DATABASE_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    url TEXT NOT NULL,
                    redacted_url TEXT NOT NULL,
                    verdict TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    cnn_probability REAL,
                    ml_probability REAL,
                    model_version TEXT,
                    scan_duration_ms INTEGER,
                    findings_json TEXT,
                    engine_results_json TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict)")
            conn.commit()

    def save_scan(self, scan_data: dict) -> int:
        """Saves a completed scan report into the database."""
        raw_url = scan_data.get("url", "")
        redacted = redact_sensitive_query_params(raw_url)
        timestamp = scan_data.get("timestamp") or datetime.now(timezone.utc).isoformat()

        findings_str = json.dumps(scan_data.get("findings", []))
        engine_str = json.dumps(scan_data.get("engine_results", {}))

        with self._get_connection() as conn:
            cur = conn.execute("""
                INSERT INTO scans (
                    timestamp, url, redacted_url, verdict, risk_score,
                    cnn_probability, ml_probability, model_version,
                    scan_duration_ms, findings_json, engine_results_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                redacted,  # Store redacted version to preserve privacy
                redacted,
                scan_data.get("verdict", "INCONCLUSIVE"),
                int(scan_data.get("risk_score", 0)),
                scan_data.get("cnn_probability"),
                scan_data.get("ml_probability"),
                scan_data.get("model_version", "2.5.0"),
                int(scan_data.get("scan_duration_ms", 0)),
                findings_str,
                engine_str
            ))
            conn.commit()
            return cur.lastrowid

    def get_recent_scans(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict_filter: str = None,
        search_term: str = None
    ) -> list[dict]:
        """Queries scan history with filtering, searching, and pagination."""
        query = "SELECT * FROM scans WHERE 1=1"
        params = []

        if verdict_filter and verdict_filter != "ALL":
            query += " AND verdict = ?"
            params.append(verdict_filter)

        if search_term and search_term.strip():
            query += " AND (url LIKE ? OR redacted_url LIKE ?)"
            term = f"%{search_term.strip()}%"
            params.extend([term, term])

        query += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            scans = []
            for r in rows:
                item = dict(r)
                try:
                    item["findings"] = json.loads(item.get("findings_json") or "[]")
                except Exception:
                    item["findings"] = []
                try:
                    item["engine_results"] = json.loads(item.get("engine_results_json") or "{}")
                except Exception:
                    item["engine_results"] = {}
                scans.append(item)
            return scans

    def get_scan_by_id(self, scan_id: int) -> dict:
        """Fetches a single scan audit record by primary key ID."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            if not row:
                return None
            item = dict(row)
            try:
                item["findings"] = json.loads(item.get("findings_json") or "[]")
                item["engine_results"] = json.loads(item.get("engine_results_json") or "{}")
            except Exception:
                pass
            return item

    def get_scan_statistics(self) -> dict:
        """
        Calculates real summary metrics strictly from stored scan records.
        Never invents or fabricates live numbers.
        """
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
            if total == 0:
                return {
                    "total_scans": 0,
                    "phishing_count": 0,
                    "suspicious_count": 0,
                    "safe_count": 0,
                    "inconclusive_count": 0,
                    "avg_risk_score": 0.0,
                    "timeline": []
                }

            phishing = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict LIKE '%PHISHING%'").fetchone()[0]
            suspicious = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict LIKE '%SUSPICIOUS%'").fetchone()[0]
            safe = conn.execute("SELECT COUNT(*) FROM scans WHERE verdict LIKE '%NO PHISHING%'").fetchone()[0]
            inconclusive = total - (phishing + suspicious + safe)
            avg_risk = conn.execute("SELECT AVG(risk_score) FROM scans").fetchone()[0] or 0.0

            # Last 7 records for activity trend
            trend_rows = conn.execute("""
                SELECT substr(timestamp, 1, 10) as day, COUNT(*) as count,
                       SUM(CASE WHEN verdict LIKE '%PHISHING%' THEN 1 ELSE 0 END) as phish_count
                FROM scans
                GROUP BY day
                ORDER BY day DESC
                LIMIT 7
            """).fetchall()

            timeline = [
                {"day": r[0], "total": r[1], "phishing": r[2]}
                for r in reversed(trend_rows)
            ]

            return {
                "total_scans": total,
                "phishing_count": phishing,
                "suspicious_count": suspicious,
                "safe_count": safe,
                "inconclusive_count": inconclusive,
                "avg_risk_score": round(float(avg_risk), 1),
                "timeline": timeline
            }

    def delete_scan(self, scan_id: int) -> bool:
        """Deletes a specific audit record."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            conn.commit()
            return cur.rowcount > 0

    def clear_all_scans(self) -> bool:
        """Purges the entire audit log."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM scans")
            conn.commit()
            return True
