"""
management/server.py - Central JOCKY management server
Flask REST API with JWT authentication and SQLite persistence.
"""

import os
import json
import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional

from flask import Flask, request, jsonify, g
import jwt


# ────────────────────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────────────────────

SECRET_KEY = os.environ.get("JOCKY_SECRET", "default_insecure_secret")
DATABASE = os.environ.get("JOCKY_DB", "jocky.db")
AGENT_TOKEN_EXPIRE_HOURS = 24


# ────────────────────────────────────────────────────────────────────────────
# Flask app setup
# ────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY


# ────────────────────────────────────────────────────────────────────────────
# Database initialization
# ────────────────────────────────────────────────────────────────────────────

def init_db():
    """Initialize SQLite database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Agents table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            platform TEXT NOT NULL,
            hostname TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            token_expires TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT DEFAULT 'active'
        )
    """)
    
    # Cases table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id TEXT PRIMARY KEY,
            manifest TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'active'
        )
    """)
    
    # Case-Agent associations
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS case_agents (
            case_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            deployed_at TEXT NOT NULL,
            PRIMARY KEY (case_id, agent_id),
            FOREIGN KEY (case_id) REFERENCES cases(id),
            FOREIGN KEY (agent_id) REFERENCES agents(id)
        )
    """)
    
    # Artifacts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS artifacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            blob BLOB,
            meta TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(id),
            FOREIGN KEY (case_id) REFERENCES cases(id)
        )
    """)
    
    # Findings table (rule_engine output)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            level TEXT NOT NULL,
            mitre_tags TEXT,
            artifact_id INTEGER,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (agent_id) REFERENCES agents(id),
            FOREIGN KEY (case_id) REFERENCES cases(id),
            FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
        )
    """)
    
    conn.commit()
    conn.close()


def get_db() -> sqlite3.Connection:
    """Get database connection."""
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection."""
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# ────────────────────────────────────────────────────────────────────────────
# JWT authentication
# ────────────────────────────────────────────────────────────────────────────

def generate_token(payload: Dict) -> str:
    """Generate JWT token."""
    payload["iat"] = datetime.utcnow()
    payload["exp"] = datetime.utcnow() + timedelta(hours=AGENT_TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> Optional[Dict]:
    """Verify and decode JWT token."""
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except (jwt.InvalidTokenError, jwt.ExpiredSignatureError):
        return None


def require_auth(f):
    """Decorator to require JWT authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization"}), 401
        
        token = auth_header[7:]
        payload = verify_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401
        
        g.auth_payload = payload
        return f(*args, **kwargs)
    
    return decorated_function


# ────────────────────────────────────────────────────────────────────────────
# REST endpoints
# ────────────────────────────────────────────────────────────────────────────

@app.route("/agent/register", methods=["POST"])
def agent_register():
    """POST /agent/register - Register a new agent."""
    data = request.get_json() or {}
    
    agent_id = data.get("agent_id")
    platform = data.get("platform", "unknown")
    hostname = data.get("hostname", "unknown")
    
    if not agent_id:
        return jsonify({"error": "Missing agent_id"}), 400
    
    # Generate agent token
    agent_token = secrets.token_urlsafe(32)
    now = datetime.utcnow().isoformat()
    expires = (datetime.utcnow() + timedelta(hours=AGENT_TOKEN_EXPIRE_HOURS)).isoformat()
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO agents (id, platform, hostname, token, token_expires, first_seen, last_seen, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
        """, (agent_id, platform, hostname, agent_token, expires, now, now))
        db.commit()
    except sqlite3.IntegrityError:
        # Agent already exists
        cursor.execute(
            "UPDATE agents SET last_seen = ?, status = 'active' WHERE id = ?",
            (now, agent_id)
        )
        db.commit()
        cursor.execute("SELECT token FROM agents WHERE id = ?", (agent_id,))
        agent_token = cursor.fetchone()[0]
    
    # Generate JWT for API access
    jwt_token = generate_token({"agent_id": agent_id, "type": "agent"})
    
    return jsonify({
        "token": jwt_token,
        "agent_token": agent_token,
        "expires_in": AGENT_TOKEN_EXPIRE_HOURS * 3600
    }), 201


@app.route("/agent/result", methods=["POST"])
@require_auth
def agent_result():
    """POST /agent/result - Submit task execution results."""
    data = request.get_json() or {}
    
    agent_id = g.auth_payload.get("agent_id")
    case_id = data.get("case_id")
    ledger = data.get("ledger", [])
    
    if not case_id:
        return jsonify({"error": "Missing case_id"}), 400
    
    db = get_db()
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()
    
    # Update agent last_seen
    cursor.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (now, agent_id))
    
    # Store artifacts and findings
    for entry in ledger:
        kind = entry.get("kind")
        blob = entry.get("blob", b"").encode() if isinstance(entry.get("blob"), str) else entry.get("blob", b"")
        meta = json.dumps(entry.get("meta", {}))
        
        cursor.execute("""
            INSERT INTO artifacts (agent_id, case_id, kind, blob, meta, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (agent_id, case_id, kind, blob, meta, now))
        
        # Extract findings if present
        anomalies = entry.get("anomalies", [])
        for anomaly in anomalies:
            if anomaly.get("type") == "finding":
                cursor.execute("""
                    INSERT INTO findings (agent_id, case_id, rule_name, level, mitre_tags, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    agent_id,
                    case_id,
                    anomaly.get("rule", "unknown"),
                    anomaly.get("level", "info"),
                    json.dumps(anomaly.get("mitre", [])),
                    now
                ))
    
    db.commit()
    
    return jsonify({"status": "ok"}), 200


@app.route("/agent/task", methods=["GET"])
@require_auth
def agent_task():
    """GET /agent/task - Retrieve pending tasks."""
    agent_id = g.auth_payload.get("agent_id")
    
    db = get_db()
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()
    
    # Update last_seen
    cursor.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (now, agent_id))
    db.commit()
    
    # Get next pending case for this agent
    cursor.execute("""
        SELECT c.id, c.manifest
        FROM cases c
        JOIN case_agents ca ON c.id = ca.case_id
        WHERE ca.agent_id = ? AND c.status = 'active'
        ORDER BY ca.deployed_at ASC
        LIMIT 1
    """, (agent_id,))
    
    row = cursor.fetchone()
    if not row:
        return "", 204  # No content
    
    case_id, manifest_str = row
    manifest = json.loads(manifest_str)
    
    return jsonify(manifest), 200


@app.route("/cases", methods=["GET"])
@require_auth
def list_cases():
    """GET /cases - List all cases with summaries."""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id, created_at, status FROM cases ORDER BY created_at DESC")
    rows = cursor.fetchall()
    
    cases = []
    for row in rows:
        case_id = row[0]
        
        # Count artifacts and anomalies
        cursor.execute("SELECT COUNT(*) FROM artifacts WHERE case_id = ?", (case_id,))
        artifact_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM findings WHERE case_id = ?", (case_id,))
        anomaly_count = cursor.fetchone()[0]
        
        # List agents
        cursor.execute("SELECT agent_id FROM case_agents WHERE case_id = ?", (case_id,))
        agents = [r[0] for r in cursor.fetchall()]
        
        cases.append({
            "case_id": case_id,
            "created_at": row[1],
            "status": row[2],
            "agents": agents,
            "artifact_count": artifact_count,
            "anomaly_count": anomaly_count
        })
    
    return jsonify({"cases": cases}), 200


@app.route("/cases", methods=["POST"])
@require_auth
def create_case():
    """POST /cases - Create and deploy a new case."""
    data = request.get_json() or {}
    
    case_id = data.get("case_id")
    manifest = data.get("manifest", {})
    
    if not case_id:
        return jsonify({"error": "Missing case_id"}), 400
    
    db = get_db()
    cursor = db.cursor()
    now = datetime.utcnow().isoformat()
    
    # Create case
    try:
        cursor.execute("""
            INSERT INTO cases (id, manifest, created_at, status)
            VALUES (?, ?, ?, 'active')
        """, (case_id, json.dumps(manifest), now))
        
        # Deploy to all active agents
        cursor.execute("SELECT id FROM agents WHERE status = 'active'")
        agents = [r[0] for r in cursor.fetchall()]
        
        for agent_id in agents:
            cursor.execute("""
                INSERT INTO case_agents (case_id, agent_id, deployed_at)
                VALUES (?, ?, ?)
            """, (case_id, agent_id, now))
        
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Case already exists"}), 409
    
    return jsonify({
        "case_id": case_id,
        "agents_deployed": len(agents)
    }), 201


@app.route("/cases/<case_id>/findings", methods=["GET"])
@require_auth
def case_findings(case_id: str):
    """GET /cases/<id>/findings - Get aggregated findings for a case."""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT agent_id, rule_name, level, mitre_tags, timestamp
        FROM findings
        WHERE case_id = ?
        ORDER BY timestamp DESC
    """, (case_id,))
    
    findings = []
    for row in cursor.fetchall():
        findings.append({
            "agent": row[0],
            "rule": row[1],
            "level": row[2],
            "mitre_tags": json.loads(row[3]),
            "timestamp": row[4]
        })
    
    # Return as JSONL
    response = "\n".join(json.dumps(f) for f in findings)
    return response, 200, {"Content-Type": "application/x-ndjson"}


@app.route("/health", methods=["GET"])
def health():
    """GET /health - Health check."""
    return jsonify({"status": "ok"}), 200


# ────────────────────────────────────────────────────────────────────────────
# Entry point
# ────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    
    # Use JOCKY_PORT environment variable, default to 5000
    port = int(os.environ.get("JOCKY_PORT", "5000"))
    debug = os.environ.get("JOCKY_DEBUG", "false").lower() == "true"
    
    app.run(host="0.0.0.0", port=port, debug=debug, threaded=True)
