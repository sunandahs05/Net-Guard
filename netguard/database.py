"""SQLite storage for alerts and traffic statistics."""
import sqlite3
from contextlib import closing

import pandas as pd

from .config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT,
    alert_type TEXT,
    severity   TEXT,
    src_ip     TEXT,
    dst_ip     TEXT,
    details    TEXT,
    mode       TEXT
);
CREATE TABLE IF NOT EXISTS traffic (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    protocol  TEXT,
    packets   INTEGER,
    bytes     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_time ON traffic(timestamp);
"""

ALERT_COLUMNS = ["timestamp", "alert_type", "severity", "src_ip", "dst_ip", "details", "mode"]


def _connect(db_path=None):
    return sqlite3.connect(str(db_path or DB_PATH))


def init_db(db_path=None):
    """Create the tables if they do not exist yet."""
    with closing(_connect(db_path)) as conn, conn:
        conn.executescript(SCHEMA)


def insert_alerts(alerts, db_path=None):
    """Save a list of alert dictionaries."""
    if not alerts:
        return 0
    rows = [tuple(a.get(c, "") for c in ALERT_COLUMNS) for a in alerts]
    with closing(_connect(db_path)) as conn, conn:
        conn.executemany(
            "INSERT INTO alerts (timestamp, alert_type, severity, src_ip, dst_ip, details, mode) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
    return len(rows)


def insert_traffic(rows, db_path=None):
    """rows: list of (timestamp, protocol, packets, bytes)."""
    if not rows:
        return 0
    with closing(_connect(db_path)) as conn, conn:
        conn.executemany(
            "INSERT INTO traffic (timestamp, protocol, packets, bytes) VALUES (?, ?, ?, ?)", rows)
    return len(rows)


def get_alerts(db_path=None, limit=5000):
    with closing(_connect(db_path)) as conn:
        return pd.read_sql_query(
            "SELECT id, timestamp, alert_type, severity, src_ip, dst_ip, details, mode "
            "FROM alerts ORDER BY timestamp DESC, id DESC LIMIT ?", conn, params=(limit,))


def get_traffic(db_path=None, limit=50000):
    with closing(_connect(db_path)) as conn:
        return pd.read_sql_query(
            "SELECT timestamp, protocol, packets, bytes FROM traffic "
            "ORDER BY timestamp DESC LIMIT ?", conn, params=(limit,))


def clear_all(db_path=None):
    with closing(_connect(db_path)) as conn, conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM traffic")
