import sqlite3
import time

# default database filename
DB_NAME = "netsent.db"


def init_db(db_path: str = DB_NAME):
    """initializes the sqlite database and creates the network_events table if it doesn't exist."""
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                pid INTEGER,
                process_name TEXT,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                status TEXT
            )
        """)
        conn.commit()


def save_event(event_type: str, pid: int, process_name: str, laddr, raddr, status: str, db_path: str = DB_NAME):
    """saves a single network event (new or closed connection) into the sqlite database."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    # safely parse local address tuple (ip, port)
    local_ip = laddr[0] if laddr else None
    local_port = laddr[1] if laddr else None
    
    # safely parse remote address tuple (ip, port)
    remote_ip = raddr[0] if raddr else None
    remote_port = raddr[1] if raddr else None

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO network_events (
                timestamp, event_type, pid, process_name, 
                local_ip, local_port, remote_ip, remote_port, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, event_type, pid, process_name,
            local_ip, local_port, remote_ip, remote_port, status
        ))
        conn.commit()