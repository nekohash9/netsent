import os
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


def get_process_name(pid: int) -> str:
    """safely retrieves the name of a process by its pid using an internal cache."""
    if pid is None:
        return "N/A"
        
    if pid in _process_names_cache:
        return _process_names_cache[pid]
        
    try:
        name = psutil.Process(pid).name()
        _process_names_cache[pid] = name
        return name
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown/Terminated"


def get_connection_snapshot() -> dict:
    """collects connections into a dict: { (laddr, raddr, pid): (status, pname) }."""
    snapshot = {}
    for c in psutil.net_connections(kind='inet'):
        pname = get_process_name(c.pid)
        
        # connection identity is our dictionary key
        conn_id = (c.laddr, c.raddr, c.pid)
        # connection metadata is our dictionary value
        metadata = (c.status, pname)
        
        snapshot[conn_id] = metadata
    return snapshot


def format_connection(conn_id, metadata, current_pid: int) -> str:
    """formats connection identity and metadata into a clean readable string."""
    laddr, raddr, pid = conn_id
    status, pname = metadata
        
    laddr_str = f"{laddr[0]}:{laddr[1]}" if laddr else "N/A"
    raddr_str = f"{raddr[0]}:{raddr[1]}" if raddr else "N/A"
    is_current = "Yes" if pid == current_pid else "No"
    
    return (f"Process: [{pname}] (PID: {pid}) | "
            f"Local: {laddr_str} | Remote: {raddr_str} | "
            f"Status: {status} | Current: {is_current}")


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
                    for conn_id in sorted(new_conns, key=lambda x: str(x[0])):
                        laddr, raddr, pid = conn_id
                        status, pname = new_snapshot[conn_id]
                        
                        # print to terminal
                        print(f"  + {format_connection(conn_id, (status, pname), current_pid)}")
                        # save to database
                        database.save_event("NEW", pid, pname, laddr, raddr, status)
                
                if closed_conns:
                    print("[CLOSED]")
                    for conn_id in sorted(closed_conns, key=lambda x: str(x[0])):
                        laddr, raddr, pid = conn_id
                        status, pname = old_snapshot[conn_id]
                        
                        # print to terminal
                        print(f"  - {format_connection(conn_id, (status, pname), current_pid)}")
                        # save to database
                        database.save_event("CLOSED", pid, pname, laddr, raddr, status)
                        
                        # clean up closed pids from name cache
                        _process_names_cache.pop(pid, None)
                
                print()  # empty line for visual separation
            
            # 4. update baseline for the next iteration
            old_snapshot = new_snapshot
            
    except KeyboardInterrupt:
        print("\nexiting watch mode.")


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