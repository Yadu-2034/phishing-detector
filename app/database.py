import sqlite3
import datetime
from typing import List, Dict, Any

DATABASE_PATH = "phishing_logs.db"

def init_database():
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            url_scanned TEXT NOT NULL,
            prediction  TEXT NOT NULL,
            risk_score  REAL NOT NULL,
            user_ip     TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    print("Database ready!")

def log_scan(url: str, prediction: str, risk_score: float, user_ip: str):
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO scan_logs (timestamp, url_scanned, prediction, risk_score, user_ip)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, url, prediction, risk_score, user_ip))
    conn.commit()
    conn.close()

def get_all_logs(limit: int = 50) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM scan_logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_statistics() -> Dict[str, Any]:
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM scan_logs")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE prediction = 'Phishing'")
    phishing_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scan_logs WHERE prediction = 'Safe'")
    safe_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT
            DATE(timestamp) as date,
            COUNT(*) as count
        FROM scan_logs
        WHERE timestamp >= DATE('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date
    """)
    daily_scans = [{"date": row[0], "count": row[1]} for row in cursor.fetchall()]

    conn.close()

    return {
        "total_scans": total,
        "phishing_count": phishing_count,
        "safe_count": safe_count,
        "daily_scans": daily_scans
    }