import os
import sqlite3
from datetime import datetime, timezone
from typing import Any

from aegis.alerts import dispatch_alert

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "aegis", "data")
DB_PATH = os.path.join(DATA_DIR, "aegis.db")
SEVERITY_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def classify_event(event_type: str, command: str = "", path: str = "", method: str = "") -> str:
    signal = f"{command} {path}".lower()
    if any(token in signal for token in ("rm -rf", "/etc/shadow", "passwd", "chmod 777", "nc -e", "reverse shell")):
        return "CRITICAL"
    if any(token in signal for token in ("nmap", "masscan", "curl", "wget", "powershell", "/wp-admin", "/.env", "/admin")):
        return "HIGH"
    if event_type == "web_request" and method.upper() == "POST":
        return "MEDIUM"
    if any(token in signal for token in ("whoami", "uname", "find /", "/login", "passwd")):
        return "MEDIUM"
    return "LOW"


def initialize_database() -> str:
    os.makedirs(DATA_DIR, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                command TEXT,
                method TEXT,
                path TEXT,
                user_agent TEXT,
                details TEXT,
                severity TEXT NOT NULL DEFAULT 'LOW'
            )
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(events)").fetchall()}
        if "severity" not in columns:
            connection.execute("ALTER TABLE events ADD COLUMN severity TEXT NOT NULL DEFAULT 'LOW'")
        rows = connection.execute(
            "SELECT id, event_type, command, path, method, severity FROM events"
        ).fetchall()
        for event_id, event_type, command, path, method, severity in rows:
            calculated = classify_event(event_type, command or "", path or "", method or "")
            if severity != calculated:
                connection.execute("UPDATE events SET severity = ? WHERE id = ?", (calculated, event_id))
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)")
        connection.commit()
    finally:
        connection.close()
    return DB_PATH


def record_event(
    event_type: str,
    source_ip: str,
    *,
    username: str = "",
    command: str = "",
    method: str = "",
    path: str = "",
    user_agent: str = "",
    details: str = "",
    severity: str = "",
) -> None:
    initialize_database()
    severity = severity.upper() if severity.upper() in SEVERITY_LEVELS else classify_event(event_type, command, path, method)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    event = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "username": username,
        "command": command,
        "method": method,
        "path": path,
        "user_agent": user_agent,
        "details": details,
        "severity": severity,
    }
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.execute(
            """
            INSERT INTO events
                (timestamp, source_ip, event_type, username, command, method, path, user_agent, details, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (timestamp, source_ip, event_type, username, command, method, path, user_agent, details, severity),
        )
        connection.commit()
    finally:
        connection.close()
    dispatch_alert(event)


def fetch_events(limit: int = 100, event_type: str | None = None) -> list[dict[str, Any]]:
    initialize_database()
    query = "SELECT * FROM events"
    parameters: list[Any] = []
    if event_type:
        query += " WHERE event_type = ?"
        parameters.append(event_type)
    query += " ORDER BY id DESC LIMIT ?"
    parameters.append(max(1, min(limit, 1000)))
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(query, parameters).fetchall()]
    finally:
        connection.close()


def clear_events() -> None:
    initialize_database()
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.execute("DELETE FROM events")
        connection.commit()
    finally:
        connection.close()
