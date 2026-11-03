"""
Phase 8: SQLite Database Management and Policy Persistence.
"""
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from app.config import DB_PATH, DEFAULT_SECURITY_POLICY


def get_db_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    if not db_path.parent.exists():
        try:
            db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(db_path: Path = DB_PATH) -> None:
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS security_audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            client_id TEXT NOT NULL,
            redacted_prompt TEXT NOT NULL,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL,
            threat_category TEXT NOT NULL,
            matched_security_rules TEXT NOT NULL,
            gateway_decision TEXT NOT NULL,
            decision_reason TEXT NOT NULL,
            output_inspection_result TEXT NOT NULL,
            redacted_response TEXT NOT NULL,
            processing_latency_ms REAL NOT NULL,
            final_request_status TEXT NOT NULL,
            entity_counts_json TEXT DEFAULT '{}'
        )
        """
    )

    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp
        ON security_audit_logs (timestamp)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_risk_level
        ON security_audit_logs (risk_level)
        """
    )
    cur.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_audit_threat_category
        ON security_audit_logs (threat_category)
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS gateway_policy_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            policy_json TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )

    cur.execute("SELECT policy_json FROM gateway_policy_config WHERE id = 1")
    if cur.fetchone() is None:
        now = datetime.now(timezone.utc).isoformat()
        cur.execute(
            "INSERT INTO gateway_policy_config (id, policy_json, updated_at) VALUES (1, ?, ?)",
            (json.dumps(DEFAULT_SECURITY_POLICY), now),
        )

    conn.commit()
    conn.close()


def load_active_policy(db_path: Path = DB_PATH) -> Dict[str, Any]:
    init_database(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT policy_json FROM gateway_policy_config WHERE id = 1")
    row = cur.fetchone()
    conn.close()
    policy = dict(DEFAULT_SECURITY_POLICY)
    if row:
        policy.update(json.loads(row["policy_json"]))
    return policy


def save_active_policy(new_policy: Dict[str, Any], db_path: Path = DB_PATH) -> Dict[str, Any]:
    init_database(db_path)
    merged = load_active_policy(db_path)
    merged.update(new_policy)
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        "UPDATE gateway_policy_config SET policy_json = ?, updated_at = ? WHERE id = 1",
        (json.dumps(merged), now),
    )
    conn.commit()
    conn.close()
    return merged
