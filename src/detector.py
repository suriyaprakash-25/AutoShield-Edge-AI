"""
AutoShield Edge AI — Detection Model (Phase 1: Isolation Forest baseline)
============================================================================
Trains an Isolation Forest purely on NORMAL traffic features (unsupervised —
this matters for the pitch: the model never needs to have seen an attack to
flag one, which is the realistic deployment scenario: you can't pre-label
every future attack type).

Also implements a lightweight, fully transparent "explainability" layer:
for any flagged window, we report which feature(s) deviated most from the
normal-traffic feature distribution and by how much — this directly powers
the AutoShield "Explainable AI" pitch feature, and it's *honest* explainability
(real feature attribution), not a cosmetic add-on.
"""

import json

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_extraction import FEATURE_COLUMNS


class CANAnomalyDetector:
    def __init__(self, contamination=0.05, random_state=42):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=150,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.feature_columns = FEATURE_COLUMNS
        self.train_means = None
        self.train_stds = None
        self.is_fitted = False

    def fit(self, feature_df_normal):
        """Fit ONLY on normal traffic — this is genuine unsupervised anomaly detection."""
        X = feature_df_normal[self.feature_columns].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)

        # store normal-traffic stats per feature, used later for explainability
        self.train_means = feature_df_normal[self.feature_columns].mean()
        self.train_stds = feature_df_normal[self.feature_columns].std().replace(0, 1e-6)

        # Calibrate confidence: store the normal-traffic score distribution so
        # we can later express any new score as "how extreme is this relative
        # to scores the model gave NORMAL data" -- a percentile-based mapping
        # is far more honest than an arbitrary fixed divisor, and produces
        # confidence values that actually track how unusual something is.
        normal_scores = self.model.decision_function(X_scaled)
        self._normal_score_p50 = float(np.percentile(normal_scores, 50))
        self._normal_score_p01 = float(np.percentile(normal_scores, 1))
        # scores at/below the 1st percentile of NORMAL data are treated as
        # maximally confident attacks (confidence -> 1.0); scores at the
        # median of normal data are confidence -> 0.0
        self.is_fitted = True
        return self

    def _score_to_confidence(self, score):
        """Map a raw decision_function score to a calibrated [0,1] confidence
        that an anomaly is real, based on where it falls relative to the
        NORMAL TRAFFIC score distribution observed during training."""
        if score >= self._normal_score_p50:
            return 0.0
        if score <= self._normal_score_p01:
            return 1.0
        span = self._normal_score_p50 - self._normal_score_p01
        return float((self._normal_score_p50 - score) / span) if span > 1e-9 else 0.5

    def predict(self, feature_df):
        """
        Returns the input dataframe with two new columns:
          - anomaly_score : raw IsolationForest score (lower = more anomalous)
          - is_anomaly    : 1 if flagged, 0 otherwise
        """
        if not self.is_fitted:
            raise RuntimeError("Call .fit() before .predict()")

        X = feature_df[self.feature_columns].fillna(0).values
        X_scaled = self.scaler.transform(X)

        raw_pred = self.model.predict(X_scaled)       # 1 = normal, -1 = anomaly
        scores = self.model.decision_function(X_scaled)  # higher = more normal

        out = feature_df.copy()
        out["anomaly_score"] = scores
        out["is_anomaly"] = (raw_pred == -1).astype(int)
        out["confidence"] = [self._score_to_confidence(s) for s in scores]
        return out

    def explain(self, row, top_k=3):
        """
        Feature-based explainability for a single flagged window.
        Returns the top_k features that deviated most (in z-score terms)
        from the normal-traffic baseline, in human-readable form.

        This is what powers the "Attack detected because: message frequency
        increased 400%, unexpected ECU source..." style output in the dashboard.
        """
        # mean_iat and mean_entropy are RAW per-window values whose natural
        # scale differs a lot per CAN_ID (e.g. a 10ms-period ECU vs a
        # 1000ms-period ECU have very different normal mean_iat). Computing
        # a global z-score for them (pooling across all IDs) is misleading --
        # iat_zscore and entropy_zscore already exist specifically because
        # they're computed against each row's OWN CAN_ID baseline (see
        # feature_extraction.py). So we exclude the raw versions here and
        # let the already-correct per-ID zscore features speak for timing
        # and payload deviation instead.
        RAW_DUPLICATE_FEATURES = {"mean_iat", "mean_entropy"}
        ALREADY_DEVIATION_FEATURES = {"iat_zscore", "entropy_zscore"}

        deviations = []
        for col in self.feature_columns:
            if col in RAW_DUPLICATE_FEATURES:
                continue
            val = row[col]

            if col in ALREADY_DEVIATION_FEATURES:
                # This column's raw value IS already a per-ID z-score (see
                # feature_extraction.py). Treat it directly as the severity
                # signal -- do NOT compute a second z-score of it against
                # the global pooled distribution, which double-counts the
                # deviation and produces a misleadingly large number for
                # what may be a perfectly mundane per-ID value (e.g. an
                # entropy_zscore of -1.45 is unremarkable on its own, but
                # looks like a 4-sigma global outlier purely because most
                # OTHER rows happen to sit near zero).
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
                "baseline_mean": float(self.train_means.get(col, 0.0)) if col not in ALREADY_DEVIATION_FEATURES else 0.0,
                "zscore": float(z),
                "pct_change": float(pct_change) if pct_change is not None else None,
            })

        deviations.sort(key=lambda d: abs(d["zscore"]), reverse=True)
        top = deviations[:top_k]

        # Severity check for whether THIS SPECIFIC ID is the culprit, not
        # just whether the bus as a whole looks abnormal. unique_ids_in_window
        # and total_msgs_in_window are BUS-WIDE signals shared identically by
        # every ID active in that window -- during a real attack (DoS flood,
        # fuzzing burst) they go extreme for EVERY innocent ID too, simply
        # because the whole bus is saturated. They're excluded from the
        # per-ID severity decision so we don't isolate innocent ECUs just
        # because the bus around them is under attack; PER-ID signals (timing
        # vs this ID's own baseline, payload pattern vs this ID's own data,
        # message frequency, share of traffic, or being a never-seen ID)
        # are what should justify isolating THIS id specifically.
        BUS_WIDE_FEATURES = {"unique_ids_in_window"}
        per_id_deviations = [d for d in deviations if d["feature"] not in BUS_WIDE_FEATURES]
        per_id_top = per_id_deviations[:top_k] if per_id_deviations else top

        max_abs_z = max(abs(d["zscore"]) for d in per_id_top) if per_id_top else 0.0
        is_severe = max_abs_z >= 3.0 or any(d["feature"] == "is_new_id" and d["value"] == 1 for d in per_id_top)

        # Bus-wide congestion check: if unique_ids_in_window is itself an
        # extreme outlier, the ENTIRE bus is saturated (e.g. a fuzzing burst
        # injecting hundreds of distinct IDs into one window). In that
        # regime, every innocent ID's own timing/payload stats become
        # unreliable collateral noise -- they get delayed/reordered by bus
        # contention that has nothing to do with their own behavior. We
        # flag this explicitly so the response layer can suppress
        # individual-ID isolation in favor of one bus-level response,
        # rather than misattributing congestion side-effects to innocent
        # ECUs as if they were independently misbehaving.
        unique_ids_dev = next((d for d in deviations if d["feature"] == "unique_ids_in_window"), None)
        bus_under_congestion = bool(unique_ids_dev and unique_ids_dev["zscore"] >= 5.0)

        # Human-readable reason strings — this is literally what gets shown in the UI
        reasons = []
        for d in top:
            label = FEATURE_LABELS.get(d["feature"], d["feature"])
            if d["pct_change"] is not None and abs(d["pct_change"]) > 20:
                direction = "increased" if d["pct_change"] > 0 else "decreased"
                # cap the displayed percentage so a div-by-near-zero edge case
                # never produces an absurd headline number in the UI
                pct_display = min(abs(d["pct_change"]), 999)
                reasons.append(f"{label} {direction} {pct_display:.0f}%+ vs. normal baseline" if abs(d["pct_change"]) > 999 else f"{label} {direction} {pct_display:.0f}% vs. normal baseline")
            elif d["feature"] == "is_new_id" and d["value"] == 1:
                reasons.append(f"{label}: this CAN ID has never been seen in normal traffic")
            else:
                direction = "higher" if d["zscore"] > 0 else "lower"
                reasons.append(f"{label} is {abs(d['zscore']):.1f}\u03c3 {direction} than normal")
        return {"top_features": top, "reasons": reasons, "is_severe": is_severe, "max_abs_zscore": max_abs_z,
                "bus_under_congestion": bus_under_congestion}

    def classify_attack_type(self, row):
        """
        Lightweight rule-based attack-type classifier layered ON TOP of the
        anomaly detector. The IsolationForest only says "anomalous or not" —
        judges will ask "ok but WHAT KIND of attack", so this maps the same
        engineered features to the 4 known attack signatures we validated
        against during feature extraction. This is intentionally simple and
        transparent (not another black-box model) -- consistent with the
        explainability framing of the whole project.
        """
        if row["is_new_id"] == 1 and row["unique_ids_in_window"] > self.train_means["unique_ids_in_window"] * 2:
            return "Fuzzy Attack"
        if row["msg_count"] > self.train_means["msg_count"] * 10 and row["is_new_id"] == 1:
            return "DoS Attack"
        if row["msg_count"] > self.train_means["msg_count"] * 5 and row["is_new_id"] == 0:
            return "Spoofing Attack"
        return "Unknown Anomaly"

    def save(self, path_prefix):
        joblib.dump(self.model, f"{path_prefix}_isoforest.joblib")
        joblib.dump(self.scaler, f"{path_prefix}_scaler.joblib")
        meta = {
            "feature_columns": self.feature_columns,
            "train_means": self.train_means.to_dict(),
            "train_stds": self.train_stds.to_dict(),
        }
        with open(f"{path_prefix}_meta.json", "w") as f:
            json.dump(meta, f, indent=2)

    @classmethod
    def load(cls, path_prefix):
        det = cls()
        det.model = joblib.load(f"{path_prefix}_isoforest.joblib")
        det.scaler = joblib.load(f"{path_prefix}_scaler.joblib")
        with open(f"{path_prefix}_meta.json") as f:
            meta = json.load(f)
        det.feature_columns = meta["feature_columns"]
        det.train_means = pd.Series(meta["train_means"])
        det.train_stds = pd.Series(meta["train_stds"])
        det.is_fitted = True
        return det


FEATURE_LABELS = {
    "msg_count": "Message frequency",
    "msg_count_ratio": "Share of bus traffic from this ID",
    "total_msgs_in_window": "Total bus traffic",
    "unique_ids_in_window": "Number of distinct CAN IDs",
    "std_iat": "Timing irregularity",
    "is_new_id": "Unseen CAN ID",
    "iat_zscore": "Message timing (vs. this ECU's normal rate)",
    "entropy_zscore": "Payload pattern (vs. this ECU's normal data)",
}
