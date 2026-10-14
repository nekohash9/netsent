import numpy as np


class Autoencoder:
    # fully connected autoencoder in plain numpy
    # tanh on hidden layers and a linear output layer trained with mse and adam

    def __init__(self, n_in: int, hidden: tuple = (6, 3), seed: int = 0):
        # mirror the encoder so 8 6 3 becomes 8 6 3 6 8
        self.sizes = [n_in, *hidden, *reversed(hidden[:-1]), n_in]
        rng = np.random.default_rng(seed)
        # xavier init suits tanh
        self.W = [rng.normal(0.0, np.sqrt(2.0 / (a + b)), (a, b))
                  for a, b in zip(self.sizes[:-1], self.sizes[1:])]
        self.b = [np.zeros(b) for b in self.sizes[1:]]

    def _forward(self, X: np.ndarray) -> list:
        acts = [X]
        h = X
        last = len(self.W) - 1
        for i, (W, b) in enumerate(zip(self.W, self.b)):
            h = h @ W + b
            if i < last:
                h = np.tanh(h)
            acts.append(h)
        return acts

    def reconstruct(self, X: np.ndarray) -> np.ndarray:
        return self._forward(X)[-1]

    def _gradients(self, X: np.ndarray):
        acts = self._forward(X)
        diff = acts[-1] - X
        loss = float(np.mean(diff ** 2))
        # derivative of the mean over all cells
        delta = 2.0 * diff / diff.size
        gW, gb = [None] * len(self.W), [None] * len(self.b)
        for i in reversed(range(len(self.W))):
            gW[i] = acts[i].T @ delta
            gb[i] = delta.sum(axis=0)
            if i > 0:
                # acts i is the tanh output feeding layer i
                delta = (delta @ self.W[i].T) * (1.0 - acts[i] ** 2)
        return loss, gW, gb

    def fit(self, X: np.ndarray, epochs: int = 300, batch_size: int = 64, lr: float = 1e-3,
            weight_decay: float = 1e-5, val_frac: float = 0.1, patience: int = 25,
            seed: int = 0, verbose: bool = True) -> dict:
        rng = np.random.default_rng(seed)
        idx = rng.permutation(len(X))
        n_val = max(1, int(len(X) * val_frac)) if len(X) > 10 else 0
        X_val, X_train = X[idx[:n_val]], X[idx[n_val:]]
        if n_val == 0:
            X_val = X_train

        params = self.W + self.b
        m = [np.zeros_like(p) for p in params]
        v = [np.zeros_like(p) for p in params]
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        step = 0

        best_val, best_params, bad_epochs = np.inf, None, 0
        history = {"train": [], "val": []}

        for epoch in range(epochs):
            order = rng.permutation(len(X_train))
            losses = []
            for start in range(0, len(X_train), batch_size):
                batch = X_train[order[start:start + batch_size]]
                loss, gW, gb = self._gradients(batch)
                losses.append(loss)
                step += 1
                for j, (p, g) in enumerate(zip(params, gW + gb)):
                    g = g + weight_decay * p
                    m[j] = beta1 * m[j] + (1 - beta1) * g
                    v[j] = beta2 * v[j] + (1 - beta2) * g * g
                    m_hat = m[j] / (1 - beta1 ** step)
                    v_hat = v[j] / (1 - beta2 ** step)
                    # in place update keeps self W and self b pointing at the same arrays
                    p -= lr * m_hat / (np.sqrt(v_hat) + eps)

            val_loss = float(np.mean((self.reconstruct(X_val) - X_val) ** 2))
            history["train"].append(float(np.mean(losses)))
            history["val"].append(val_loss)

            if val_loss < best_val - 1e-6:
                best_val, bad_epochs = val_loss, 0
                best_params = [p.copy() for p in params]
            else:
                bad_epochs += 1

            if verbose and (epoch % 25 == 0 or bad_epochs == patience):
                print(f"  epoch {epoch:4d}  train {history['train'][-1]:.4f}  val {val_loss:.4f}")
            if bad_epochs >= patience:
                break

        # restore the best epoch
        for p, best in zip(params, best_params):
            p[...] = best
        return history

    def to_arrays(self, prefix: str = "ae_") -> dict:
        out = {f"{prefix}sizes": np.array(self.sizes)}
        for i, (W, b) in enumerate(zip(self.W, self.b)):
            out[f"{prefix}W{i}"] = W
            out[f"{prefix}b{i}"] = b
        return out

    @classmethod
    def from_arrays(cls, data, prefix: str = "ae_") -> "Autoencoder":
        sizes = [int(s) for s in data[f"{prefix}sizes"]]
        ae = cls.__new__(cls)
        ae.sizes = sizes
        ae.W = [data[f"{prefix}W{i}"] for i in range(len(sizes) - 1)]
        ae.b = [data[f"{prefix}b{i}"] for i in range(len(sizes) - 1)]
        return ae
