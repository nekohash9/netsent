import sqlite3
import time

# default database filename
DB_NAME = "netsent.db"


def init_db(db_path: str = DB_NAME):
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            pid INTEGER, process_name TEXT,
            local_ip TEXT, local_port INTEGER,
            remote_ip TEXT, remote_port INTEGER,
            status TEXT, proto TEXT DEFAULT 'TCP',
            ts REAL
        )""")
        # old databases were created without the epoch column
        columns = {row[1] for row in cursor.execute("PRAGMA table_info(network_events)")}
        if "ts" not in columns:
            cursor.execute("ALTER TABLE network_events ADD COLUMN ts REAL")
        # Индексы для быстрых запросов
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ts ON network_events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON network_events(event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_epoch ON network_events(ts)")
        conn.commit()

def save_events_batch(events: list, db_path: str = DB_NAME):
    """events: список кортежей (timestamp, event_type, pid, process_name, l_ip, l_port, r_ip, r_port, status, proto, ts)"""
    if not events: return
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.executemany("""INSERT INTO network_events
            (timestamp, event_type, pid, process_name, local_ip, local_port, remote_ip, remote_port, status, proto, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", events)
        conn.commit()

def load_events(db_path: str = DB_NAME) -> list:
    # rows logged before the epoch column existed cannot be windowed so they are skipped
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        return cursor.execute("""SELECT ts, event_type, process_name, remote_ip, remote_port,
            local_port, status, proto FROM network_events
            WHERE ts IS NOT NULL ORDER BY ts, id""").fetchall()
