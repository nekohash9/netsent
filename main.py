import os
import socket
import sys
import time
import psutil
import database

# cache dictionary to store process names: {pid: name}
_process_names_cache = {}


def check_root():
    """checks if the script is running with root/sudo privileges."""
    if os.geteuid() != 0:
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
            
            # 3. extract sets of connection identities (keys) to find diffs
            old_ids = set(old_snapshot.keys())
            new_ids = set(new_snapshot.keys())
            
            new_conns = new_ids - old_ids      # appeared in new snapshot
            closed_conns = old_ids - new_ids   # disappeared from new snapshot
            
            # if changes detected, log to terminal and save to sqlite
            if new_conns or closed_conns:
                current_time = time.strftime("%H:%M:%S")
                print(f"--- changes detected at {current_time} ---")
                
                if new_conns:
                    print("[NEW]")
                    batch = []
                    for conn_id in sorted(new_conns, key=lambda x: str(x[0])):
                        laddr, raddr, pid, proto = conn_id
                        status, pname, proto = new_snapshot[conn_id]
                        l_ip, l_port = laddr if laddr else (None, None)
                        r_ip, r_port = raddr if raddr else (None, None)
                        
                        # print to terminal
                        print(f"  + {format_connection(conn_id, (status, pname, proto), current_pid)}")
                        batch.append((current_time, "NEW", pid, pname, l_ip, l_port, r_ip, r_port, status, proto))

                    if batch:
                        database.save_events_batch(batch)
                
                if closed_conns:
                    print("[CLOSED]")
                    batch = []
                    for conn_id in sorted(closed_conns, key=lambda x: str(x[0])):
                        laddr, raddr, pid, proto = conn_id
                        status, pname, proto = old_snapshot[conn_id]
                        l_ip, l_port = laddr if laddr else (None, None)
                        r_ip, r_port = raddr if raddr else (None, None)
                        
                        # print to terminal
                        print(f"  - {format_connection(conn_id, (status, pname, proto), current_pid)}")
                        batch.append((current_time, "CLOSED", pid, pname, l_ip, l_port, r_ip, r_port, status, proto))
                        
                        # clean up closed pids from name cache
                        _process_names_cache.pop(pid, None)

                    if batch:
                        database.save_events_batch(batch)
                
                print()  # empty line for visual separation
            
            # 4. update baseline for the next iteration
            old_snapshot = new_snapshot
            
    except KeyboardInterrupt:
        print("\n exiting watch mode.")
    except Exception as e:
        print(f"[!] Watch loop error: {e}. Retrying in 5s...")
        time.sleep(5)


def main():
    """main entry point and command router for the utility."""
    check_root()
    
    # initialize database and create table if needed
    database.init_db()
    
    print("netsent utility (sqlite logging enabled)")
    current_pid = os.getpid()

    while True:
        print("\ncommands: active_sessions, watch, exit")
        command = input("> ").strip()

        match command:
            case "active_sessions":
                show_active_sessions(current_pid)
            case "watch":
                watch_active_sessions(current_pid)
            case "exit":
                break
            case _:
                print("(!) invalid command. please try again.")


if __name__ == "__main__":
    main()