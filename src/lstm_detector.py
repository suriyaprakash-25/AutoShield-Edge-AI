"""
AutoShield Edge AI — Detection Model (Phase 2: LSTM Autoencoder)
================================================================
Upgrade over the Isolation Forest baseline: instead of scoring each
200ms window in isolation, the LSTM-Autoencoder learns the TEMPORAL
DYNAMICS of normal CAN traffic — how each ECU's behavior evolves across
consecutive windows. This catches attacks that unfold over 1-2 seconds
(e.g. a DoS flood ramping up) and distinguishes them from transient
benign bursts that resolve quickly, which directly improves precision
on DoS (the IsoForest's main weakness).

Architecture (encoder-decoder with bottleneck):
  Input:  [SEQ_LEN=10, n_features=9]   — 10 × 200ms = 2s temporal context
  Encoder: 2-layer LSTM → last hidden state → Linear → latent [LATENT_DIM=32]
  Decoder: latent → Linear → repeated input → 2-layer LSTM → output [SEQ_LEN, n_features]
  Score:   mean per-element MSE between input and reconstruction
           (higher MSE = more anomalous; normal traffic is reconstructed
           faithfully; attack traffic is not, because the model only
           ever saw normal during training)

External interface is identical to CANAnomalyDetector (fit / predict /
explain / classify_attack_type / save / load), so it's a drop-in replacement
for the response engine and training pipeline.
"""

import json
from collections import deque

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset

from detector import FEATURE_LABELS
from feature_extraction import FEATURE_COLUMNS

SEQ_LEN = 10       # 10 × 200 ms = 2 s of temporal context per sequence
HIDDEN_DIM = 64
LATENT_DIM = 32
NUM_LAYERS = 2


# ---------------------------------------------------------------------------
# Neural network module
# ---------------------------------------------------------------------------

class _LSTMAutoencoder(nn.Module):
    """Encoder-decoder LSTM that reconstructs sequences of CAN feature vectors."""

    def __init__(self, n_features: int):
        super().__init__()
        dropout = 0.1 if NUM_LAYERS > 1 else 0.0

        self.encoder = nn.LSTM(
            n_features, HIDDEN_DIM, NUM_LAYERS,
            batch_first=True, dropout=dropout,
        )
        self.enc_to_latent = nn.Linear(HIDDEN_DIM, LATENT_DIM)
        self.latent_to_dec = nn.Linear(LATENT_DIM, HIDDEN_DIM)
        self.decoder = nn.LSTM(
            HIDDEN_DIM, HIDDEN_DIM, NUM_LAYERS,
            batch_first=True, dropout=dropout,
        )
        self.output_proj = nn.Linear(HIDDEN_DIM, n_features)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x: [batch, seq_len, n_features]
        _, seq_len, _ = x.shape

        # Encode: compress full sequence to a latent vector via the last-layer
        # final hidden state (summarises the entire input sequence).
        _, (h_n, _) = self.encoder(x)           # h_n: [num_layers, batch, hidden_dim]
        latent = self.enc_to_latent(h_n[-1])     # [batch, latent_dim]

        # Decoder initialisation: project latent back to hidden_dim and
        # broadcast across all LSTM layers so each layer starts with the
        # encoded context rather than zeros.
        dec_h0 = self.latent_to_dec(latent)                      # [batch, hidden_dim]
        dec_h0 = dec_h0.unsqueeze(0).repeat(NUM_LAYERS, 1, 1)   # [num_layers, batch, hidden_dim]
        dec_c0 = torch.zeros_like(dec_h0)

        # Decoder input: repeat the top-layer latent-projected vector at every
        # time step. Combining a repeated input with a latent-initialised hidden
        # state gives the decoder both "what to output" and "where to start".
        dec_in = dec_h0[-1:].transpose(0, 1).repeat(1, seq_len, 1)  # [batch, seq_len, hidden_dim]
        dec_out, _ = self.decoder(dec_in, (dec_h0, dec_c0))          # [batch, seq_len, hidden_dim]

        return self.output_proj(dec_out)  # [batch, seq_len, n_features]


# ---------------------------------------------------------------------------
# Public detector class — same interface as CANAnomalyDetector
# ---------------------------------------------------------------------------

class LSTMAnomalyDetector:
    """
    Phase 2 anomaly detector using an LSTM Autoencoder.
    Drop-in replacement for CANAnomalyDetector: identical fit / predict /
    explain / classify_attack_type / save / load signatures.

    Key difference in predict() output: anomaly_score is reconstruction MSE
    (HIGHER = more anomalous), opposite sign to IsoForest's decision_function.
    The response engine only reads is_anomaly and confidence, so the sign
    change is transparent to downstream code.
    """

    def __init__(self, seq_len: int = SEQ_LEN, device: str | None = None):
        self.seq_len = seq_len
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.feature_columns = FEATURE_COLUMNS
        self.n_features = len(FEATURE_COLUMNS)

        self.scaler = StandardScaler()
        self.model: _LSTMAutoencoder | None = None
        self.train_means: pd.Series | None = None
        self.train_stds: pd.Series | None = None
        self.is_fitted = False

        self._recon_threshold: float | None = None   # MSE threshold for is_anomaly=1
        self._normal_p50: float | None = None        # confidence calibration anchors
        self._normal_p99: float | None = None

        # Rolling buffer for streaming inference (init_stream / predict_stream)
        self._stream_buffers: dict[str, deque] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_sequences(
        self, feature_df: pd.DataFrame
    ) -> tuple[np.ndarray, list[tuple[str, float]]]:
        """
        Returns (sequences, index_map):
          sequences  — float32 ndarray [N, seq_len, n_features] in scaled space
          index_map  — list of (CAN_ID, window_start) for the LAST window in each
                       sequence, so reconstruction errors can be mapped back to rows

        Built per CAN_ID, sorted by window_start. Windows without SEQ_LEN
        prior history are zero-padded on the left. Zeros in StandardScaler
        space equal the per-feature mean, i.e. "typical behaviour", which is
        a reasonable prior for missing history rather than fabricating data.
        """
        sequences: list[np.ndarray] = []
        index_map: list[tuple[str, float]] = []

        for can_id, grp in feature_df.groupby("CAN_ID"):
            grp = grp.sort_values("window_start")
            X = grp[self.feature_columns].fillna(0).values.astype(np.float32)  # [n_windows, n_feat]
            ws = grp["window_start"].values

            for i in range(len(X)):
                if i < self.seq_len - 1:
                    pad = np.zeros((self.seq_len - 1 - i, self.n_features), dtype=np.float32)
                    seq = np.vstack([pad, X[: i + 1]])
                else:
                    seq = X[i - self.seq_len + 1 : i + 1]
                sequences.append(seq)
                index_map.append((can_id, float(ws[i])))

        return np.array(sequences, dtype=np.float32), index_map

    def _score_to_confidence(self, error: float) -> float:
        """Map reconstruction MSE to calibrated [0, 1] confidence of an anomaly."""
        if error <= self._normal_p50:
            return 0.0
        if error >= self._normal_p99:
            return 1.0
        span = self._normal_p99 - self._normal_p50
        return float((error - self._normal_p50) / span) if span > 1e-9 else 0.5

    def _compute_recon_errors(self, feature_df: pd.DataFrame,
                              infer_batch: int = 512) -> dict[tuple[str, float], float]:
        """Build sequences from feature_df, run batched inference, return (CAN_ID, window_start)->MSE map."""
        df_scaled = feature_df.copy()
        df_scaled[self.feature_columns] = self.scaler.transform(
            feature_df[self.feature_columns].fillna(0).values
        )
        sequences, index_map = self._build_sequences(df_scaled)
        seqs_t = torch.tensor(sequences)   # keep on CPU; move per-batch

        self.model.eval()
        errors_list = []
        with torch.no_grad():
            for i in range(0, len(seqs_t), infer_batch):
                batch = seqs_t[i:i + infer_batch].to(self.device)
                recon = self.model(batch)
                errs  = ((batch - recon) ** 2).mean(dim=(1, 2)).cpu().numpy()
                errors_list.append(errs)
        errors = np.concatenate(errors_list) if errors_list else np.array([])

        return {key: float(err) for key, err in zip(index_map, errors)}

    # ------------------------------------------------------------------
    # Public API — mirrors CANAnomalyDetector
    # ------------------------------------------------------------------

    def fit(
        self,
        feature_df_normal: pd.DataFrame,
        epochs: int = 60,
        batch_size: int = 128,
        lr: float = 1e-3,
        val_fraction: float = 0.2,
        verbose: bool = True,
    ) -> "LSTMAnomalyDetector":
        """
        Train the LSTM-AE on normal-only traffic — genuine unsupervised setup,
        no attack examples needed at training time.

        Saves normal-traffic feature stats for the identical explain() logic
        used by CANAnomalyDetector, so the dashboard's incident-reason strings
        remain unchanged.
        """
        self.train_means = feature_df_normal[self.feature_columns].mean()
        self.train_stds = feature_df_normal[self.feature_columns].std().replace(0, 1e-6)

        # Fit and apply scaler on the raw normal features, then build sequences
        X_all = feature_df_normal[self.feature_columns].fillna(0).values
        self.scaler.fit(X_all)

        df_scaled = feature_df_normal.copy()
        df_scaled[self.feature_columns] = self.scaler.transform(X_all)

        sequences, _ = self._build_sequences(df_scaled)   # [N, seq_len, n_features]
        n = len(sequences)

        rng = np.random.default_rng(42)
        idx = rng.permutation(n)
        n_val = max(int(n * val_fraction), 1)
        train_seqs = torch.tensor(sequences[idx[n_val:]])
        val_seqs = torch.tensor(sequences[idx[:n_val]])

        train_loader = DataLoader(
            TensorDataset(train_seqs), batch_size=batch_size, shuffle=True
        )

        self.model = _LSTMAutoencoder(self.n_features).to(self.device)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=lr, weight_decay=1e-5)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=epochs)
        criterion = nn.MSELoss()

        best_val_loss = float("inf")
        best_state: dict = {}
        patience, patience_counter = 8, 0

        for epoch in range(1, epochs + 1):
            self.model.train()
            train_loss = 0.0
            for (batch,) in train_loader:
                batch = batch.to(self.device)
                optimizer.zero_grad()
                loss = criterion(self.model(batch), batch)
                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                train_loss += loss.item() * len(batch)
            train_loss /= len(train_seqs)

            self.model.eval()
            with torch.no_grad():
                val_b = val_seqs.to(self.device)
                val_loss = criterion(self.model(val_b), val_b).item()
            scheduler.step()

            if verbose and (epoch % 10 == 0 or epoch == 1):
                print(f"  Epoch {epoch:3d}/{epochs}  train MSE: {train_loss:.5f}  val MSE: {val_loss:.5f}")

            if val_loss < best_val_loss - 1e-7:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    if verbose:
                        print(f"  Early stopping at epoch {epoch}  (best val MSE: {best_val_loss:.5f})")
                    break

        self.model.load_state_dict(best_state)

        # Calibrate confidence using the reconstruction-error distribution on
        # normal TRAINING data. Run in batches to stay within GPU VRAM limits.
        self.model.eval()
        train_errors_list = []
        calib_batch = 512
        with torch.no_grad():
            for i in range(0, len(train_seqs), calib_batch):
                batch = train_seqs[i:i + calib_batch].to(self.device)
                recon = self.model(batch)
                errs  = ((batch - recon) ** 2).mean(dim=(1, 2)).cpu().numpy()
                train_errors_list.append(errs)
        train_errors = np.concatenate(train_errors_list)

        self._normal_p50 = float(np.percentile(train_errors, 50))
        self._normal_p99 = float(np.percentile(train_errors, 99))
        self._recon_threshold = self._normal_p99
        self.is_fitted = True

        if verbose:
            print(f"\n  Normal error dist — p50: {self._normal_p50:.5f}  p99: {self._normal_p99:.5f}")
            print(f"  Anomaly threshold (p99 of normal): {self._recon_threshold:.5f}")

        return self

    def predict(self, feature_df: pd.DataFrame) -> pd.DataFrame:
        """
        Returns feature_df with three new columns:
          anomaly_score — reconstruction MSE (higher = more anomalous)
          is_anomaly    — 1 if MSE exceeds the 99th-percentile normal threshold
          confidence    — calibrated [0, 1] anomaly confidence

        Same shape/column contract as CANAnomalyDetector.predict().
        """
        if not self.is_fitted:
            raise RuntimeError("Call .fit() before .predict()")

        error_map = self._compute_recon_errors(feature_df)

        errors = [
            error_map.get((cid, float(ws)), 0.0)
            for cid, ws in zip(feature_df["CAN_ID"], feature_df["window_start"])
        ]
        out = feature_df.copy()
        out["anomaly_score"] = errors
        out["is_anomaly"] = [1 if e > self._recon_threshold else 0 for e in errors]
        out["confidence"] = [self._score_to_confidence(e) for e in errors]
        return out

    def explain(self, row: pd.Series, top_k: int = 3) -> dict:
        """
        Feature-attribution explainability — identical logic to CANAnomalyDetector.
        The LSTM-AE's anomaly score is global per-sequence; explainability is still
        provided through per-feature z-score attribution against the normal baseline,
        giving the same human-readable "reasons" strings to the dashboard/response engine.
        """
        RAW_DUPLICATE_FEATURES = {"mean_iat", "mean_entropy"}
        ALREADY_DEVIATION_FEATURES = {"iat_zscore", "entropy_zscore"}

        deviations = []
        for col in self.feature_columns:
            if col in RAW_DUPLICATE_FEATURES:
                continue
            val = row[col]
            if col in ALREADY_DEVIATION_FEATURES:
                z = float(val)
                pct_change = None
            else:
                train_mean = self.train_means[col]
                train_std = self.train_stds[col]
                z = (val - train_mean) / train_std if train_std > 1e-9 else 0.0
                pct_change = None
                if col != "is_new_id" and abs(train_mean) > 1e-6:
                    pct_change = (val - train_mean) / abs(train_mean) * 100

            deviations.append({
                "feature": col,
                "value": float(val),
                "baseline_mean": float(self.train_means[col]) if col not in ALREADY_DEVIATION_FEATURES else 0.0,
                "zscore": float(z),
                "pct_change": float(pct_change) if pct_change is not None else None,
            })

        deviations.sort(key=lambda d: abs(d["zscore"]), reverse=True)
        top = deviations[:top_k]

        BUS_WIDE_FEATURES = {"unique_ids_in_window"}
        per_id_devs = [d for d in deviations if d["feature"] not in BUS_WIDE_FEATURES]
        per_id_top = per_id_devs[:top_k] if per_id_devs else top

        max_abs_z = max((abs(d["zscore"]) for d in per_id_top), default=0.0)
        is_severe = max_abs_z >= 3.0 or any(
            d["feature"] == "is_new_id" and d["value"] == 1 for d in per_id_top
        )

        uid_dev = next((d for d in deviations if d["feature"] == "unique_ids_in_window"), None)
        bus_under_congestion = bool(uid_dev and uid_dev["zscore"] >= 5.0)

        reasons = []
        for d in top:
            label = FEATURE_LABELS.get(d["feature"], d["feature"])
            if d["pct_change"] is not None and abs(d["pct_change"]) > 20:
                direction = "increased" if d["pct_change"] > 0 else "decreased"
                pct_disp = min(abs(d["pct_change"]), 999)
                reasons.append(
                    f"{label} {direction} {pct_disp:.0f}%+ vs. normal baseline"
                    if abs(d["pct_change"]) > 999
                    else f"{label} {direction} {pct_disp:.0f}% vs. normal baseline"
                )
            elif d["feature"] == "is_new_id" and d["value"] == 1:
                reasons.append(f"{label}: this CAN ID has never been seen in normal traffic")
            else:
                direction = "higher" if d["zscore"] > 0 else "lower"
                reasons.append(f"{label} is {abs(d['zscore']):.1f} sigma {direction} than normal")

        return {
            "top_features": top,
            "reasons": reasons,
            "is_severe": is_severe,
            "max_abs_zscore": max_abs_z,
            "bus_under_congestion": bus_under_congestion,
        }

    def classify_attack_type(self, row: pd.Series) -> str:
        """Rule-based attack classifier — identical to CANAnomalyDetector."""
        if row["is_new_id"] == 1 and row["unique_ids_in_window"] > self.train_means["unique_ids_in_window"] * 2:
            return "Fuzzy Attack"
        if row["msg_count"] > self.train_means["msg_count"] * 10 and row["is_new_id"] == 1:
            return "DoS Attack"
        if row["msg_count"] > self.train_means["msg_count"] * 5 and row["is_new_id"] == 0:
            return "Spoofing Attack"
        return "Unknown Anomaly"

    # ------------------------------------------------------------------
    # Streaming inference (for response engine / live vcan replay)
    # ------------------------------------------------------------------

    def init_stream(self) -> None:
        """Reset rolling per-CAN_ID buffers. Call once before processing a live stream."""
        self._stream_buffers = {}

    def predict_stream(self, can_id: str, feature_row: "pd.Series | dict") -> tuple[float, int, float]:
        """
        Single-window streaming inference. Maintains a SEQ_LEN rolling buffer
        per CAN_ID; no need for callers to manage state.

        Returns (anomaly_score: float, is_anomaly: 0|1, confidence: float).
        Compatible with response_engine.process_window_result().
        """
        if not self.is_fitted:
            raise RuntimeError("Call .fit() before streaming inference")

        if can_id not in self._stream_buffers:
            self._stream_buffers[can_id] = deque(maxlen=self.seq_len)

        buf = self._stream_buffers[can_id]
        feat_vec = np.array([feature_row[c] for c in self.feature_columns], dtype=np.float32)
        feat_scaled = self.scaler.transform(feat_vec.reshape(1, -1))[0]
        buf.append(feat_scaled)

        # Zero-pad left when buffer is not yet full (same convention as _build_sequences)
        seq = np.zeros((self.seq_len, self.n_features), dtype=np.float32)
        buf_arr = np.array(list(buf))
        seq[-len(buf_arr) :] = buf_arr

        seq_t = torch.tensor(seq).unsqueeze(0).to(self.device)
        self.model.eval()
        with torch.no_grad():
            recon = self.model(seq_t)
            error = float(((seq_t - recon) ** 2).mean().item())

        return error, int(error > self._recon_threshold), self._score_to_confidence(error)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path_prefix: str) -> None:
        torch.save(self.model.state_dict(), f"{path_prefix}_lstm.pt")
        joblib.dump(self.scaler, f"{path_prefix}_lstm_scaler.joblib")
        meta = {
            "seq_len": self.seq_len,
            "n_features": self.n_features,
            "feature_columns": self.feature_columns,
            "train_means": self.train_means.to_dict(),
            "train_stds": self.train_stds.to_dict(),
            "recon_threshold": self._recon_threshold,
            "normal_p50": self._normal_p50,
            "normal_p99": self._normal_p99,
        }
        with open(f"{path_prefix}_lstm_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, path_prefix: str, device: str | None = None) -> "LSTMAnomalyDetector":
        with open(f"{path_prefix}_lstm_meta.json") as f:
            meta = json.load(f)

        det = cls(seq_len=meta["seq_len"], device=device)
        det.feature_columns = meta["feature_columns"]
        det.n_features = meta["n_features"]
        det.train_means = pd.Series(meta["train_means"])
        det.train_stds = pd.Series(meta["train_stds"])
        det._recon_threshold = meta["recon_threshold"]
        det._normal_p50 = meta["normal_p50"]
        det._normal_p99 = meta["normal_p99"]

        det.model = _LSTMAutoencoder(det.n_features).to(det.device)
        det.model.load_state_dict(
            torch.load(f"{path_prefix}_lstm.pt", map_location=det.device)
        )
        det.model.eval()

        det.scaler = joblib.load(f"{path_prefix}_lstm_scaler.joblib")
        det.is_fitted = True
        return det
