"""
Phase 8: Security Audit Logger & Query Functions.
Stores only redacted prompts/responses and metadata so raw secrets are never persisted.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

from app.config import DB_PATH
from app.database.db import get_db_connection, init_database
from app.security.privacy_scanner import default_privacy_scanner


def insert_audit_event(
    event: Dict[str, Any],
    db_path: Path = DB_PATH,
) -> None:
    """
    Insert a security audit event into SQLite.
    Ensures prompt and response are sanitized before storage.
    """
    init_database(db_path)

    raw_or_sanitized_prompt = str(event.get("redacted_prompt", ""))
    # Enforce secret-free storage even if caller passed unsanitized text
    safe_prompt = default_privacy_scanner.scan_and_redact(raw_or_sanitized_prompt).sanitized_text

    raw_or_sanitized_resp = str(event.get("redacted_response", ""))
    safe_resp = default_privacy_scanner.scan_and_redact(raw_or_sanitized_resp).sanitized_text

    now = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    rules = event.get("matched_security_rules", [])
    if isinstance(rules, list):
        rules_json = json.dumps(rules)
    else:
        rules_json = str(rules)

    entity_counts = event.get("entity_counts", {})
    entity_counts_json = json.dumps(entity_counts) if isinstance(entity_counts, dict) else "{}"

    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR REPLACE INTO security_audit_logs (
            request_id, timestamp, client_id, redacted_prompt,
            risk_score, risk_level, threat_category, matched_security_rules,
            gateway_decision, decision_reason, output_inspection_result,
            redacted_response, processing_latency_ms, final_request_status,
            entity_counts_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(event.get("request_id", "")),
            now,
            str(event.get("client_id", "anonymous")),
            safe_prompt,
            float(event.get("risk_score", 0.0)),
            str(event.get("risk_level", "Low Risk")),
            str(event.get("threat_category", "benign")),
            rules_json,
            str(event.get("gateway_decision", "ALLOW")),
            str(event.get("decision_reason", "")),
            str(event.get("output_inspection_result", "PASSED")),
            safe_resp,
            float(event.get("processing_latency_ms", 0.0)),
            str(event.get("final_request_status", "COMPLETED")),
            entity_counts_json,
        ),
    )
    conn.commit()
    conn.close()


def _deserialize_row(row: Any) -> Dict[str, Any]:
    d = dict(row)
    try:
        d["matched_security_rules"] = json.loads(d.get("matched_security_rules") or "[]")
    except Exception:
        d["matched_security_rules"] = []
    try:
        d["entity_counts"] = json.loads(d.pop("entity_counts_json", "{}") or "{}")
    except Exception:
        d["entity_counts"] = {}
    return d


def get_recent_events(limit: int = 100, db_path: Path = DB_PATH) -> List[Dict[str, Any]]:
    init_database(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM security_audit_logs ORDER BY id DESC LIMIT ?",
        (int(limit),),
    )
    rows = cur.fetchall()
    conn.close()
    return [_deserialize_row(r) for r in rows]


def filter_events(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    risk_level: Optional[str] = None,
    threat_category: Optional[str] = None,
    gateway_decision: Optional[str] = None,
    search_query: Optional[str] = None,
    limit: int = 250,
    db_path: Path = DB_PATH,
) -> List[Dict[str, Any]]:
    """Filter audit events by date range, risk level, threat category, decision, or text search."""
    init_database(db_path)
    clauses: List[str] = []
    params: List[Any] = []

    if start_date:
        clauses.append("timestamp >= ?")
        params.append(start_date)
    if end_date:
        clauses.append("timestamp <= ?")
        params.append(end_date)
    if risk_level and risk_level != "All":
        clauses.append("risk_level = ?")
        params.append(risk_level)
    if threat_category and threat_category != "All":
        clauses.append("threat_category LIKE ?")
        params.append(f"%{threat_category}%")
    if gateway_decision and gateway_decision != "All":
        clauses.append("gateway_decision = ?")
        params.append(gateway_decision)
    if search_query and search_query.strip():
        clauses.append("(redacted_prompt LIKE ? OR decision_reason LIKE ? OR request_id LIKE ?)")
        q = f"%{search_query.strip()}%"
        params.extend([q, q, q])

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = f"SELECT * FROM security_audit_logs {where_sql} ORDER BY id DESC LIMIT ?"
    params.append(int(limit))

    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute(sql, tuple(params))
    rows = cur.fetchall()
    conn.close()
    return [_deserialize_row(r) for r in rows]


def get_summary_statistics(db_path: Path = DB_PATH) -> Dict[str, Any]:
    """Generate real-time summary statistics directly from SQLite audit records."""
    init_database(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) as total FROM security_audit_logs")
    total_requests = int(cur.fetchone()["total"])

    cur.execute(
        """
        SELECT gateway_decision, COUNT(*) as count
        FROM security_audit_logs
        GROUP BY gateway_decision
        """
    )
    decision_counts = {r["gateway_decision"]: int(r["count"]) for r in cur.fetchall()}

    cur.execute(
        """
        SELECT risk_level, COUNT(*) as count
        FROM security_audit_logs
        GROUP BY risk_level
        """
    )
    risk_level_counts = {r["risk_level"]: int(r["count"]) for r in cur.fetchall()}

    cur.execute(
        """
        SELECT threat_category, COUNT(*) as count
        FROM security_audit_logs
        WHERE threat_category != 'benign'
        GROUP BY threat_category
        """
    )
    threat_category_counts = {r["threat_category"]: int(r["count"]) for r in cur.fetchall()}

    cur.execute(
        """
        SELECT AVG(risk_score) as avg_risk, AVG(processing_latency_ms) as avg_latency
        FROM security_audit_logs
        """
    )
    agg = cur.fetchone()

    cur.execute(
        """
        SELECT COUNT(*) as cnt
        FROM security_audit_logs
        WHERE threat_category LIKE '%prompt_injection%'
           OR threat_category LIKE '%jailbreak%'
           OR threat_category LIKE '%system_prompt_extraction%'
           OR threat_category LIKE '%policy_bypass%'
           OR threat_category LIKE '%delimiter_injection%'
           OR threat_category LIKE '%indirect_injection%'
           OR threat_category LIKE '%encoded_injection%'
        """
    )
    prompt_injection_attempts = int(cur.fetchone()["cnt"])

    cur.execute(
        """
        SELECT COUNT(*) as cnt
        FROM security_audit_logs
        WHERE entity_counts_json != '{}'
           OR threat_category LIKE '%personal_identifiable_info%'
           OR threat_category LIKE '%secret_exposure%'
           OR threat_category LIKE '%government_identifier%'
           OR threat_category LIKE '%network_identifier%'
        """
    )
    sensitive_data_detections = int(cur.fetchone()["cnt"])

    conn.close()

    allowed = decision_counts.get("ALLOW", 0)
    sanitized = decision_counts.get("SANITIZE", 0)
    blocked = decision_counts.get("BLOCK", 0)
    total_threats = sum(threat_category_counts.values())

    return {
        "total_requests": total_requests,
        "allowed_requests": allowed,
        "sanitized_requests": sanitized,
        "blocked_requests": blocked,
        "total_detected_threats": total_threats,
        "prompt_injection_attempts": prompt_injection_attempts,
        "sensitive_data_detections": sensitive_data_detections,
        "high_risk_requests": risk_level_counts.get("High Risk", 0),
        "critical_risk_requests": risk_level_counts.get("Critical Risk", 0),
        "average_risk_score": round(float(agg["avg_risk"] or 0.0), 2),
        "average_latency_ms": round(float(agg["avg_latency"] or 0.0), 2),
        "decision_breakdown": decision_counts,
        "risk_level_breakdown": risk_level_counts,
        "threat_category_breakdown": threat_category_counts,
    }


def clear_audit_events(db_path: Path = DB_PATH) -> None:
    init_database(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM security_audit_logs")
    conn.commit()
    conn.close()
