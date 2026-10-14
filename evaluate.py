import argparse

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score

import database
from detector import Detector, Scaler
from features import Event, build_windows, events_from_db_rows

# synthetic normal profiles
# name rate per second ip pool size ports proto mean lifetime failure probability
PROFILES = [
    ("firefox", 0.6, 400, [443] * 9 + [80], "TCP", 30.0, 0.01),
    ("slack", 0.03, 8, [443], "TCP", 300.0, 0.0),
    ("systemd-resolve", 0.4, 2, [53], "UDP", 1.0, 0.0),
    ("python3", 0.02, 40, [443, 8080], "TCP", 5.0, 0.05),
    ("apt", 0.005, 6, [80, 443], "TCP", 20.0, 0.02),
]


def _conn(events, ts, pname, ip, port, proto, life, failed):
    status = "SYN_SENT" if failed else ("NONE" if proto == "UDP" else "ESTABLISHED")
    events.append(Event(ts, "NEW", pname, ip, port, None, status, proto))
    events.append(Event(ts + life, "CLOSED", pname, ip, port, None, status, proto))


def simulate_normal(t0: float, duration: float, rng) -> list:
    events = []
    for p_idx, (pname, rate, pool, ports, proto, life, fail_p) in enumerate(PROFILES):
        n = rng.poisson(rate * duration)
        for ts in np.sort(rng.uniform(t0, t0 + duration, n)):
            # zipf popularity means a few hosts dominate and new ones keep trickling in
            host = (rng.zipf(1.3) - 1) % pool
            ip = f"10.{p_idx}.{host // 256}.{host % 256}"
            failed = rng.random() < fail_p
            _conn(events, ts, pname, ip, int(rng.choice(ports)), proto,
                  3.0 if failed else rng.exponential(life), failed)
    # closes are appended next to their opens so the stream has to be put back in time order
    return sorted(events, key=lambda e: e.ts)


# longest attack is the beacon at about 106s
ATTACK_SPAN = 130.0


def attack_events(kind: str, t0: float, rng, n: int = 0) -> list:
    # all attacks run under an existing process name so name alone cannot give them away
    # n makes targets unique per attack so one attack never warms up ip history for the next
    ev = []
    target = f"203.0.{n // 254}.{n % 254 + 1}"
    if kind == "port_scan":
        # connect scan of one host most ports closed or filtered
        n, span = rng.integers(100, 1000), rng.uniform(5, 30)
        for port in rng.choice(np.arange(1, 65536), n, replace=False):
            _conn(ev, t0 + rng.uniform(0, span), "python3", target, int(port), "TCP",
                  rng.uniform(0.5, 3), rng.random() < 0.95)
    elif kind == "slow_scan":
        # one port every couple of seconds for a minute
        for i, port in enumerate(rng.choice(np.arange(1, 1025), 30, replace=False)):
            _conn(ev, t0 + i * 2.0, "python3", target, int(port), "TCP", 3.0, rng.random() < 0.9)
    elif kind == "host_sweep":
        # same port across many hosts like a worm looking for smb
        for i in range(rng.integers(30, 200)):
            _conn(ev, t0 + rng.uniform(0, 20), "python3", f"198.{n}.{i // 256}.{i % 256}", 445,
                  "TCP", 3.0, rng.random() < 0.8)
    elif kind == "brute_force":
        # many short successful connections to one service
        for _ in range(rng.integers(100, 400)):
            _conn(ev, t0 + rng.uniform(0, 30), "python3", target, 22, "TCP",
                  rng.uniform(0.2, 1.0), False)
    elif kind == "beacon":
        # one quiet connection to a new host every 15s expected to be hard
        for i in range(8):
            _conn(ev, t0 + i * 15.0, "firefox", target, 443, "TCP", 1.0, False)
    elif kind == "backdoor":
        # a process starts listening and accepts a few inbound connections
        ev.append(Event(t0, "NEW", "python3", None, None, 4444, "LISTEN", "TCP"))
        for i in range(3):
            _conn(ev, t0 + 2 + i, "python3", target, int(rng.integers(40000, 60000)), "TCP", 30.0, False)
    return ev


ATTACKS = ["port_scan", "slow_scan", "host_sweep", "brute_force", "beacon", "backdoor"]


def label_rows(rows, attack_events_by_kind, window_sec):
    # a window is positive if any attack event landed in it for that process
    tags = {}
    for kind, evs in attack_events_by_kind:
        for e in evs:
            tags[(int(e.ts // window_sec), e.pname)] = kind
    labels = np.array([(int(r.start // window_sec), r.pname) in tags for r in rows])
    kinds = [tags.get((int(r.start // window_sec), r.pname)) for r in rows]
    return labels, kinds


def metrics(y, scores, threshold):
    pred = scores > threshold
    tp, fp = int((pred & y).sum()), int((pred & ~y).sum())
    fn = int((~pred & y).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "precision": precision, "recall": recall, "f1": f1,
        "roc_auc": roc_auc_score(y, scores), "pr_auc": average_precision_score(y, scores),
        "fp": fp, "pred": pred,
    }


def main():
    ap = argparse.ArgumentParser(description="compare the autoencoder with isolation forest")
    ap.add_argument("--db", help="use real logged traffic from this sqlite file as normal data")
    ap.add_argument("--hours", type=float, default=8.0, help="synthetic normal duration")
    ap.add_argument("--window", type=float, default=10.0)
    ap.add_argument("--attacks", type=int, default=8, help="injected attacks per kind")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)

    if args.db:
        normal = events_from_db_rows(database.load_events(args.db))
        if len(normal) < 1000:
            raise SystemExit(f"(!) only {len(normal)} timestamped events in {args.db} run watch for longer")
        t_start, t_end = normal[0].ts, normal[-1].ts
        source = f"real traffic from {args.db}"
    else:
        t_start, t_end = 0.0, args.hours * 3600
        normal = simulate_normal(t_start, t_end - t_start, rng)
        source = f"synthetic traffic ({args.hours:g}h)"

    # time based split so the test period is strictly after training
    t_split = t_start + 0.7 * (t_end - t_start)
    train_events = [e for e in normal if e.ts < t_split]
    test_normal = [e for e in normal if e.ts >= t_split]

    # each attack gets its own time slot so attacks never overlap inside one window
    kinds_order = rng.permutation(ATTACKS * args.attacks)
    slot = (t_end - t_split - 120) / len(kinds_order)
    if slot < ATTACK_SPAN + 20:
        raise SystemExit("(!) test period too short for that many attacks lower --attacks")
    injected = []
    for n, kind in enumerate(kinds_order):
        t = t_split + 60 + n * slot + rng.uniform(0, slot - ATTACK_SPAN)
        injected.append((str(kind), attack_events(str(kind), t, rng, n)))
    test_events = sorted(test_normal + [e for _, evs in injected for e in evs], key=lambda e: e.ts)

    train_rows, history = build_windows(train_events, args.window)
    # test windows continue from the training ip history like live detection would
    test_rows, _ = build_windows(test_events, args.window, history)
    X_train = np.stack([r.x for r in train_rows])
    X_test = np.stack([r.x for r in test_rows])
    y, kinds = label_rows(test_rows, injected, args.window)

    print(f"data: {source}")
    print(f"train windows {len(X_train)}  test windows {len(X_test)}  attack windows {int(y.sum())}\n")

    print("training autoencoder")
    det = Detector(seed=args.seed).fit(X_train)
    ae_scores = det.score(X_test)
    ae = metrics(y, ae_scores, det.threshold)

    # baseline sees the same scaled features and uses the same false alarm budget
    scaler = Scaler().fit(X_train)
    iso = IsolationForest(n_estimators=200, random_state=args.seed).fit(scaler.transform(X_train))
    iso_train = -iso.score_samples(scaler.transform(X_train))
    iso_scores = -iso.score_samples(scaler.transform(X_test))
    iso_m = metrics(y, iso_scores, float(np.quantile(iso_train, det.quantile)))

    test_hours = (t_end - t_split) / 3600
    print(f"\n{'model':<18}{'precision':>10}{'recall':>8}{'f1':>7}{'roc_auc':>9}{'pr_auc':>8}{'fp/hour':>9}")
    for name, m in [("autoencoder", ae), ("isolation forest", iso_m)]:
        print(f"{name:<18}{m['precision']:>10.3f}{m['recall']:>8.3f}{m['f1']:>7.3f}"
              f"{m['roc_auc']:>9.3f}{m['pr_auc']:>8.3f}{m['fp'] / test_hours:>9.1f}")

    print(f"\n{'recall by attack':<18}{'windows':>8}{'ae':>7}{'iforest':>9}")
    kinds = np.array([k or "" for k in kinds])
    for kind in ATTACKS:
        mask = kinds == kind
        if mask.any():
            print(f"{kind:<18}{int(mask.sum()):>8}{ae['pred'][mask].mean():>7.2f}{iso_m['pred'][mask].mean():>9.2f}")

    # one explained example per attack kind
    print("\nexample explanations")
    for kind in ATTACKS:
        hits = np.where((kinds == kind) & ae["pred"])[0]
        if len(hits):
            i = hits[np.argmax(ae_scores[hits])]
            reasons = "; ".join(text for _, _, text in det.explain(X_test[i]))
            print(f"  {kind:<12} score {ae_scores[i]:.2f}  {reasons}")


if __name__ == "__main__":
    main()
