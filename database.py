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
            status TEXT, proto TEXT DEFAULT 'TCP'
        )""")
        # Индексы для быстрых запросов
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_ts ON network_events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_event_type ON network_events(event_type)")
        conn.commit()

def save_events_batch(events: list, db_path: str = DB_NAME):
    """events: список кортежей (timestamp, event_type, pid, process_name, l_ip, l_port, r_ip, r_port, status, proto)"""
    if not events: return
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.executemany("""INSERT INTO network_events 
            (timestamp, event_type, pid, process_name, local_ip, local_port, remote_ip, remote_port, status, proto)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", events)
        conn.commit()
