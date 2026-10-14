import json

import numpy as np

from autoencoder import Autoencoder
from features import COUNT_MASK, FEATURE_NAMES

# std floor so a feature that was constant in training does not explode to huge z scores
MIN_STD = 0.1

# share of total error a feature needs to be named in an explanation
EXPLAIN_SHARE = 0.15

TEMPLATES = {
    "new_conns": "{v:.0f} new connections (expected ~{e:.0f})",
    "closed_conns": "{v:.0f} connections closed (expected ~{e:.0f})",
    "uniq_rports": "{v:.0f} distinct remote ports (expected ~{e:.0f})",
    "uniq_rips": "{v:.0f} distinct remote hosts (expected ~{e:.0f})",
    "fail_ratio": "{v:.0%} of closed connections were never established (expected ~{e:.0%})",
    "new_ip_ratio": "{v:.0%} of remote hosts never seen on this machine before (expected ~{e:.0%})",
    "new_listen": "{v:.0f} new listening sockets (expected ~{e:.0f})",
    "udp_ratio": "{v:.0%} of new sockets are udp (expected ~{e:.0%})",
}


def log_transform(X_raw: np.ndarray) -> np.ndarray:
    X = np.array(X_raw, dtype=float)
    X[:, COUNT_MASK] = np.log1p(X[:, COUNT_MASK])
    return X


def inverse_log_transform(X: np.ndarray) -> np.ndarray:
    X = np.array(X, dtype=float)
    X[:, COUNT_MASK] = np.expm1(X[:, COUNT_MASK])
    return X


class Scaler:
    # log1p on counts then z score with a std floor

    def fit(self, X_raw: np.ndarray) -> "Scaler":
        X = log_transform(X_raw)
        self.mu = X.mean(axis=0)
        self.sd = np.maximum(X.std(axis=0), MIN_STD)
        return self

    def transform(self, X_raw: np.ndarray) -> np.ndarray:
        return (log_transform(X_raw) - self.mu) / self.sd

    def inverse(self, Z: np.ndarray) -> np.ndarray:
        return inverse_log_transform(Z * self.sd + self.mu)


class Detector:
    def __init__(self, hidden: tuple = (6, 3), quantile: float = 0.995, seed: int = 0):
        self.hidden = hidden
        self.quantile = quantile
        self.seed = seed
        self.ip_history = {}

    def fit(self, X_raw: np.ndarray, verbose: bool = True, **fit_kwargs) -> "Detector":
        self.scaler = Scaler().fit(X_raw)
        Z = self.scaler.transform(X_raw)
        self.ae = Autoencoder(Z.shape[1], self.hidden, self.seed)
        self.history = self.ae.fit(Z, seed=self.seed, verbose=verbose, **fit_kwargs)
        # threshold is a high quantile of scores on normal traffic so it sets the false alarm budget
        self.threshold = float(np.quantile(self.score(X_raw), self.quantile))
        return self

    def feature_errors(self, X_raw: np.ndarray) -> np.ndarray:
        Z = self.scaler.transform(X_raw)
        return (self.ae.reconstruct(Z) - Z) ** 2

    def score(self, X_raw: np.ndarray) -> np.ndarray:
        return self.feature_errors(X_raw).mean(axis=1)

    def explain(self, x_raw: np.ndarray, max_reasons: int = 3) -> list:
        x_raw = np.asarray(x_raw, dtype=float).reshape(1, -1)
        Z = self.scaler.transform(x_raw)
        recon = self.ae.reconstruct(Z)
        errors = ((recon - Z) ** 2)[0]
        expected = np.maximum(self.scaler.inverse(recon)[0], 0.0)

        # every feature measures something suspicious so only values above expected count as reasons
        above = Z[0] > recon[0]
        candidates = np.where(above)[0] if above.any() else np.arange(len(errors))
        total = errors[candidates].sum() or 1.0
        reasons = []
        for j in candidates[np.argsort(errors[candidates])[::-1]][:max_reasons]:
            share = errors[j] / total
            if reasons and share < EXPLAIN_SHARE:
                break
            name = FEATURE_NAMES[j]
            text = TEMPLATES[name].format(v=x_raw[0, j], e=expected[j])
            reasons.append((name, float(share), text))
        return reasons

    def save(self, path: str):
        meta = {
            "features": FEATURE_NAMES,
            "hidden": list(self.hidden),
            "quantile": self.quantile,
            "threshold": self.threshold,
            "ip_history": self.ip_history,
        }
        np.savez(path, mu=self.scaler.mu, sd=self.scaler.sd,
                 meta=np.array(json.dumps(meta)), **self.ae.to_arrays())

    @classmethod
    def load(cls, path: str) -> "Detector":
        with np.load(path, allow_pickle=False) as data:
            meta = json.loads(str(data["meta"]))
            if meta["features"] != FEATURE_NAMES:
                raise ValueError("model was trained on a different feature set please retrain")
            det = cls(tuple(meta["hidden"]), meta["quantile"])
            det.scaler = Scaler()
            det.scaler.mu, det.scaler.sd = data["mu"], data["sd"]
            det.ae = Autoencoder.from_arrays(data)
        det.threshold = meta["threshold"]
        det.ip_history = meta["ip_history"]
        return det
