from collections import defaultdict
from typing import NamedTuple

import numpy as np

# order matters because the model sees columns by index
FEATURE_NAMES = [
    "new_conns",     # new connections with a remote address
    "closed_conns",  # closed connections with a remote address
    "uniq_rports",   # distinct remote ports among new connections
    "uniq_rips",     # distinct remote hosts among new connections
    "fail_ratio",    # share of closed connections that never left syn_sent
    "new_ip_ratio",  # share of remote hosts this machine has never talked to
    "new_listen",    # new listening sockets
    "udp_ratio",     # share of new sockets that are udp
]

# count features get log1p before scaling so a burst of 500 does not dwarf everything
COUNT_FEATURES = {"new_conns", "closed_conns", "uniq_rports", "uniq_rips", "new_listen"}
COUNT_MASK = np.array([name in COUNT_FEATURES for name in FEATURE_NAMES])


class Event(NamedTuple):
    ts: float
    kind: str  # NEW or CLOSED
    pname: str
    r_ip: str | None
    r_port: int | None
    l_port: int | None
    status: str
    proto: str


class WindowRow(NamedTuple):
    start: float
    pname: str
    x: np.ndarray


def window_features(events: list, ip_history: dict) -> np.ndarray:
    new = [e for e in events if e.kind == "NEW"]
    remote_new = [e for e in new if e.r_ip]
    remote_closed = [e for e in events if e.kind == "CLOSED" and e.r_ip]

    rips = {e.r_ip for e in remote_new}
    failed = sum(1 for e in remote_closed if e.status == "SYN_SENT")
    unseen = sum(1 for ip in rips if ip_history.get(ip, 0) == 0)
    udp = sum(1 for e in new if e.proto == "UDP")

    return np.array([
        len(remote_new),
        len(remote_closed),
        len({e.r_port for e in remote_new}),
        len(rips),
        failed / len(remote_closed) if remote_closed else 0.0,
        unseen / len(rips) if rips else 0.0,
        sum(1 for e in new if e.status == "LISTEN"),
        udp / len(new) if new else 0.0,
    ], dtype=float)


class Windower:
    # groups a time ordered event stream into tumbling windows per process name
    # the same code path is used for training from sqlite and for live detection

    def __init__(self, window_sec: float = 10.0, ip_history: dict | None = None):
        self.window_sec = window_sec
        self.ip_history = dict(ip_history or {})  # remote ip to number of past connections
        self._current = None
        self._buckets = defaultdict(list)

    def push(self, ev: Event) -> list:
        idx = int(ev.ts // self.window_sec)
        rows = []
        if self._current is not None and idx > self._current:
            rows = self._close()
        if self._current is None or idx > self._current:
            self._current = idx
        self._buckets[ev.pname].append(ev)
        return rows

    def flush(self, now: float | None = None) -> list:
        # with now given the window is closed only once its time is over
        if self._current is None:
            return []
        if now is not None and int(now // self.window_sec) <= self._current:
            return []
        rows = self._close()
        self._current = None
        return rows

    def _close(self) -> list:
        start = self._current * self.window_sec
        # rarity is judged against history before this window so all processes see the same past
        rows = [WindowRow(start, pname, window_features(evs, self.ip_history))
                for pname, evs in self._buckets.items()]
        for evs in self._buckets.values():
            for e in evs:
                if e.kind == "NEW" and e.r_ip:
                    self.ip_history[e.r_ip] = self.ip_history.get(e.r_ip, 0) + 1
        self._buckets = defaultdict(list)
        return rows


def events_from_db_rows(db_rows: list) -> list:
    return [Event(ts, kind, pname or "N/A", r_ip, r_port, l_port, status or "", proto or "TCP")
            for ts, kind, pname, r_ip, r_port, l_port, status, proto in db_rows]


def build_windows(events: list, window_sec: float = 10.0, ip_history: dict | None = None):
    windower = Windower(window_sec, ip_history)
    rows = []
    for ev in events:
        rows.extend(windower.push(ev))
    rows.extend(windower.flush())
    return rows, windower.ip_history
