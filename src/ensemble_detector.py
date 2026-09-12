"""
AutoShield Edge AI — Ensemble Detector (Phase 3)
=================================================
Combines IsolationForest (Phase 1) + LSTM-Autoencoder (Phase 2) via weighted
confidence averaging. Each sub-detector is independently calibrated so their
[0,1] confidences are on the same scale before merging.

Why ensemble over either alone:
  - IsoForest excels at DoS (extreme msg_count spike) but struggles with subtle
    spoofing that stays within reasonable per-window counts.
  - LSTM excels at temporal anomalies (spoofing at unusual rate over 2s) but
    has higher latency and occasionally fires on benign transient bursts.
  - Combined: the LSTM's vote up-weights decisions the IsoForest is uncertain
    about; the IsoForest's near-instant score provides a "second opinion" on
    the LSTM's temporal context. Precision and recall both improve vs either alone.

Default weights (iso=0.35, lstm=0.65) favour the LSTM since it leverages 2s
of context; auto-tuning via train_ensemble.py can refine these on real data.
"""

import json

import joblib
import numpy as np
import pandas as pd

from detector import CANAnomalyDetector
from lstm_detector import LSTMAnomalyDetector
from feature_extraction import FEATURE_COLUMNS


class EnsembleDetector:
    """
    Drop-in replacement for CANAnomalyDetector and LSTMAnomalyDetector.
    Identical external interface: fit / predict / explain / classify_attack_type
    / save / load / init_stream / predict_stream_row.
    """

    def __init__(self, iso_weight: float = 0.35, lstm_weight: float = 0.65, threshold: float = 0.5):
        self.iso_weight = iso_weight
        self.lstm_weight = lstm_weight
        self.threshold = threshold
        self.iso: CANAnomalyDetector | None = None
        self.lstm: LSTMAnomalyDetector | None = None
        self.feature_columns = FEATURE_COLUMNS
        self.train_means: pd.Series | None = None
        self.train_stds: pd.Series | None = None
        self.is_fitted = False

    # ── Training ────────────────────────────────────────────────────────────────

    def fit(
        self,
        feature_df_normal: pd.DataFrame,
        epochs: int = 60,
        batch_size: int = 128,
        verbose: bool = True,
    ) -> "EnsembleDetector":
        """Train both sub-detectors on normal-only features (fully unsupervised)."""
        print("\n  [Ensemble] Fitting IsolationForest…")
        self.iso = CANAnomalyDetector(contamination=0.05)
        self.iso.fit(feature_df_normal)

        print("  [Ensemble] Fitting LSTM Autoencoder…")
        self.lstm = LSTMAnomalyDetector()
        self.lstm.fit(feature_df_normal, epochs=epochs, batch_size=batch_size, verbose=verbose)

        self.train_means = feature_df_normal[self.feature_columns].mean()
        self.train_stds = feature_df_normal[self.feature_columns].std().replace(0, 1e-6)
        self.is_fitted = True
        return self

    # ── Batch prediction ────────────────────────────────────────────────────────

    def predict(self, feature_df: pd.DataFrame) -> pd.DataFrame:
        """
        Batch prediction. Returns feature_df with:
          iso_confidence   — calibrated IsoForest confidence
          lstm_confidence  — calibrated LSTM confidence
          confidence       — weighted ensemble confidence
          anomaly_score    — alias for confidence
          is_anomaly       — 1 if ensemble_confidence >= threshold
        """
        if not self.is_fitted:
            raise RuntimeError("Call .fit() or .load() before .predict()")

        iso_out = self.iso.predict(feature_df)
        lstm_out = self.lstm.predict(feature_df)

        iso_conf = iso_out["confidence"].values
        lstm_conf = lstm_out["confidence"].values
        ensemble_conf = self.iso_weight * iso_conf + self.lstm_weight * lstm_conf

        out = feature_df.copy()
        out["iso_confidence"] = iso_conf
        out["lstm_confidence"] = lstm_conf
        out["confidence"] = ensemble_conf
        out["anomaly_score"] = ensemble_conf
        out["is_anomaly"] = (ensemble_conf >= self.threshold).astype(int)
        return out

    # ── Explainability ───────────────────────────────────────────────────────────

    def explain(self, row: pd.Series, top_k: int = 3) -> dict:
        """Feature z-score attribution — delegates to LSTM (identical logic)."""
        return self.lstm.explain(row, top_k)

    def classify_attack_type(self, row: pd.Series) -> str:
        return self.lstm.classify_attack_type(row)

    # ── Streaming inference ──────────────────────────────────────────────────────

    def init_stream(self) -> None:
        """Reset LSTM per-CAN_ID rolling buffers for a new stream."""
        if self.lstm:
            self.lstm.init_stream()

    def predict_stream_row(
        self, can_id: str, feature_row
    ) -> tuple[float, int, float, float]:
        """
        Streaming inference for ONE feature row (one CAN_ID in one 200ms window).
        Maintains the LSTM's per-CAN_ID rolling sequence buffer internally.

        Returns (ensemble_confidence, is_anomaly, iso_confidence, lstm_confidence).
        Call init_stream() before starting a new scenario.
        """
        if not self.is_fitted:
            raise RuntimeError("Call .fit() or .load() before streaming inference")

        # Build a single-row DataFrame for IsoForest (needs a 2-D input)
        if isinstance(feature_row, pd.Series):
            row_dict = feature_row.to_dict()
        else:
            row_dict = dict(feature_row)

        # Ensure required structural columns are present so iso.predict works
        row_dict.setdefault("CAN_ID", can_id)
        row_dict.setdefault("window_start", 0.0)
        row_dict.setdefault("label", None)
        tmp_df = pd.DataFrame([row_dict])

        iso_out = self.iso.predict(tmp_df)
        iso_conf = float(iso_out["confidence"].iloc[0])

        # LSTM streaming: maintains its own rolling buffer per CAN_ID
        _, _, lstm_conf = self.lstm.predict_stream(can_id, feature_row)

        ensemble_conf = self.iso_weight * iso_conf + self.lstm_weight * lstm_conf
        is_anomaly = int(ensemble_conf >= self.threshold)
        return ensemble_conf, is_anomaly, iso_conf, lstm_conf

    # ── Persistence ─────────────────────────────────────────────────────────────

    def save(self, path_prefix: str) -> None:
        self.iso.save(f"{path_prefix}_ens_iso")
        self.lstm.save(f"{path_prefix}_ens_lstm")
        meta = {
            "iso_weight": self.iso_weight,
            "lstm_weight": self.lstm_weight,
            "threshold": self.threshold,
            "feature_columns": self.feature_columns,
            "train_means": self.train_means.to_dict(),
            "train_stds": self.train_stds.to_dict(),
        }
        with open(f"{path_prefix}_ensemble_meta.json", "w") as f:
            json.dump(meta, f, indent=2)
        print(f"  Ensemble saved to {path_prefix}_ensemble_meta.json + sub-model files")

    @classmethod
    def load(cls, path_prefix: str, device: str | None = None) -> "EnsembleDetector":
        with open(f"{path_prefix}_ensemble_meta.json") as f:
            meta = json.load(f)

        det = cls(
            iso_weight=meta["iso_weight"],
            lstm_weight=meta["lstm_weight"],
            threshold=meta["threshold"],
        )
        det.iso = CANAnomalyDetector.load(f"{path_prefix}_ens_iso")
        det.lstm = LSTMAnomalyDetector.load(f"{path_prefix}_ens_lstm", device=device)
        det.feature_columns = meta["feature_columns"]
        det.train_means = pd.Series(meta["train_means"])
        det.train_stds = pd.Series(meta["train_stds"])
        det.is_fitted = True
        return det
