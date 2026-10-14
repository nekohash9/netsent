import os
import socket
import sys
import time
import numpy as np
import psutil
import database
from features import Event, Windower, build_windows, events_from_db_rows

MODEL_PATH = "model.npz"
WINDOW_SEC = 10.0

# cache dictionary to store process names: {pid: name}
_process_names_cache = {}


def check_root():
    """checks if the script is running with root/sudo privileges."""
    # windows has no geteuid and psutil sees all sockets there without elevation
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("(!) this script must be run as root. please run with sudo")
        print("    example: sudo .venv/bin/python3 main.py")
        sys.exit(1)

_process_names_cache = {}
def get_process_name(pid: int) -> str:
    if pid is None or pid == 0:
        return "N/A"
    
    cached = _process_names_cache.get(pid)
    if cached and time.time() - cached[1] < 3600:  # TTL 1 час
        try:
            proc = psutil.Process(pid)
            if abs(proc.create_time() - cached[1]) < 5.0:  # совпадение времени создания
                return cached[0]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        _process_names_cache[pid] = (name, proc.create_time())
        return name
    except Exception:
        return "Unknown/Terminated"

def get_connection_snapshot() -> dict:
    snapshot = {}
    for c in psutil.net_connections(kind='all'):  # or separately 'tcp', 'udp'
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        pname = get_process_name(c.pid)
        conn_id = (c.laddr, c.raddr, c.pid, proto)
        metadata = (c.status, pname, proto)
        snapshot[conn_id] = metadata
    return snapshot



def format_connection(conn_id, metadata, current_pid: int) -> str:
    """formats connection identity and metadata into a clean readable string."""
    laddr, raddr, pid, proto = conn_id
    status, pname, proto = metadata

    laddr_str = f"{laddr[0]}:{laddr[1]}" if laddr else "N/A"
    raddr_str = f"{raddr[0]}:{raddr[1]}" if raddr else "N/A"
    is_current = "Yes" if pid == current_pid else "No"
    
    return (f"Process: [{pname}] (PID: {pid}) | "
            f"Local: {laddr_str} | Remote: {raddr_str} | "
            f"Status: {status} | Protocol: {proto} | Current: {is_current}")


def show_active_sessions(current_pid: int, show_header: bool = True):
    """displays all currently active network connections once."""
    if show_header:
        print("(?) active_sessions command shows all active network connections on the system")
    
    snapshot = get_connection_snapshot()
    # sort by local ip address for clean display
    for conn_id in sorted(snapshot.keys(), key=lambda x: str(x[0])):
        print(format_connection(conn_id, snapshot[conn_id], current_pid))


def diff_snapshots(old_snapshot: dict, new_snapshot: dict, now: float):
    """returns db rows and model events for connections that appeared or disappeared"""
    current_time = time.strftime("%H:%M:%S", time.localtime(now))
    changes = []
    for kind, ids, source in (("NEW", new_snapshot.keys() - old_snapshot.keys(), new_snapshot),
                              ("CLOSED", old_snapshot.keys() - new_snapshot.keys(), old_snapshot)):
        for conn_id in sorted(ids, key=lambda x: str(x[0])):
            laddr, raddr, pid, proto = conn_id
            status, pname, proto = source[conn_id]
            l_ip, l_port = laddr if laddr else (None, None)
            r_ip, r_port = raddr if raddr else (None, None)
            row = (current_time, kind, pid, pname, l_ip, l_port, r_ip, r_port, status, proto, now)
            event = Event(now, kind, pname, r_ip, r_port, l_port, status, proto)
            changes.append((kind, conn_id, source[conn_id], row, event))
    return changes


def watch_active_sessions(current_pid: int):
    """monitors network connections, prints diffs, and saves events to sqlite."""
    print("(?) watch command monitors network connections and logs events to sqlite")
    print("press Ctrl+C to exit watch mode.\n")
    
    # 1. get the initial snapshot dictionary
    old_snapshot = get_connection_snapshot()
    print(f"[*] initial snapshot captured ({len(old_snapshot)} connections). waiting for changes...\n")
    
    try:
        while True:
            time.sleep(2)
            
            # 2. get the new snapshot dictionary
            new_snapshot = get_connection_snapshot()
            now = time.time()

            # 3. find connections that appeared or disappeared
            changes = diff_snapshots(old_snapshot, new_snapshot, now)

            # if changes detected, log to terminal and save to sqlite
            if changes:
                print(f"--- changes detected at {time.strftime('%H:%M:%S', time.localtime(now))} ---")
                for kind, marker in (("NEW", "+"), ("CLOSED", "-")):
                    group = [c for c in changes if c[0] == kind]
                    if group:
                        print(f"[{kind}]")
                    for _, conn_id, metadata, _, _ in group:
                        print(f"  {marker} {format_connection(conn_id, metadata, current_pid)}")
                        # clean up closed pids from name cache
                        if kind == "CLOSED":
                            _process_names_cache.pop(conn_id[2], None)
                database.save_events_batch([c[3] for c in changes])
                print()  # empty line for visual separation

            # 4. update baseline for the next iteration
            old_snapshot = new_snapshot
            
    except KeyboardInterrupt:
        print("\n exiting watch mode.")
    except Exception as e:
        print(f"[!] Watch loop error: {e}. Retrying in 5s...")
        time.sleep(5)


def train_model():
    """trains the autoencoder on everything logged by watch or detect so far"""
    from detector import Detector

    events = events_from_db_rows(database.load_events())
    rows, ip_history = build_windows(events, WINDOW_SEC)
    if len(rows) < 200:
        print(f"(!) only {len(rows)} windows of traffic logged. run watch for a few hours first")
        return
    hours = (events[-1].ts - events[0].ts) / 3600
    print(f"[*] {len(events)} events over {hours:.1f}h -> {len(rows)} windows of {WINDOW_SEC:g}s")

    detector = Detector().fit(np.stack([r.x for r in rows]))
    detector.ip_history = ip_history
    detector.save(MODEL_PATH)
    print(f"[*] model saved to {MODEL_PATH} (threshold {detector.threshold:.3f})")


def detect_anomalies(current_pid: int):
    """scores live traffic window by window and prints explained alerts"""
    from detector import Detector

    if not os.path.exists(MODEL_PATH):
        print("(!) no trained model found. run watch to collect normal traffic then train")
        return
    detector = Detector.load(MODEL_PATH)
    windower = Windower(WINDOW_SEC, detector.ip_history)
    print(f"(?) detect scores every {WINDOW_SEC:g}s window per process (threshold {detector.threshold:.3f})")
    print("press Ctrl+C to exit detect mode.\n")

    old_snapshot = get_connection_snapshot()
    try:
        while True:
            # shorter poll than watch so short lived connections are less likely to be missed
            time.sleep(1)
            new_snapshot = get_connection_snapshot()
            now = time.time()
            changes = diff_snapshots(old_snapshot, new_snapshot, now)
            old_snapshot = new_snapshot
            database.save_events_batch([c[3] for c in changes])

            rows = windower.flush(now)
            for c in changes:
                rows.extend(windower.push(c[4]))
            if not rows:
                continue

            scores = detector.score(np.stack([r.x for r in rows]))
            stamp = time.strftime("%H:%M:%S", time.localtime(rows[0].start))
            worst = max(range(len(rows)), key=lambda i: scores[i])
            print(f"[{stamp}] {len(rows)} active processes, max score {scores[worst]:.2f} ({rows[worst].pname})")
            for row, score in zip(rows, scores):
                if score > detector.threshold:
                    print(f"  (!) ALERT [{row.pname}] score {score:.2f}")
                    for _, share, text in detector.explain(row.x):
                        print(f"      - {text} [{share:.0%} of error]")
    except KeyboardInterrupt:
        print("\n exiting detect mode.")


def main():
    """main entry point and command router for the utility."""
    check_root()
    
    # initialize database and create table if needed
    database.init_db()
    
    print("netsent utility (sqlite logging enabled)")
    current_pid = os.getpid()

    while True:
        print("\ncommands: active_sessions, watch, train, detect, exit")
        command = input("> ").strip()

        match command:
            case "active_sessions":
                show_active_sessions(current_pid)
            case "watch":
                watch_active_sessions(current_pid)
            case "train":
                train_model()
            case "detect":
                detect_anomalies(current_pid)
            case "exit":
                break
            case _:
                print("(!) invalid command. please try again.")


if __name__ == "__main__":
    main()