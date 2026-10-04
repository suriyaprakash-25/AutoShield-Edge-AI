"""
AutoShield Edge AI — Feature Extraction
==========================================
Converts raw CAN bus frames into sliding-window features suitable for
anomaly detection. This is the core signal-processing layer: every attack
type (DoS, fuzzy, spoofing, replay) leaves a distinct fingerprint in these
features, even though the raw frames look superficially valid.

Why these specific features (each maps to a real attack signature):

  - msg_count_window      -> DoS floods spike this massively (one ID firing
                             every 0.3ms instead of every 10-100ms)
  - unique_ids_window     -> Fuzzy attacks inject many never-before-seen IDs,
                             spiking ID diversity in a short window
  - mean_iat / std_iat    -> Inter-arrival time. Spoofing keeps a *known* ID
                             but at an abnormal, unnaturally regular rate
                             (e.g., exactly every 1ms instead of its normal
                             10-100ms period) — IAT mean/variance catches this
  - payload_entropy       -> Fuzzy attacks use random payloads -> high entropy.
                             Spoofed payloads for a real signal (RPM, gear)
                             are often static/repeated -> unusually LOW entropy
                             relative to that ID's normal variability
  - new_id_flag           -> Binary: was this CAN ID ever seen in the
                             training/baseline period? Catches fuzzy attacks
                             and any genuinely novel ECU appearing.
  - id_freq_deviation     -> How far this window's frequency for a given ID
                             deviates from that ID's own historical baseline
                             frequency (z-score). Catches spoofing precisely
                             because spoofing reuses a KNOWN id at an
                             ABNORMAL rate -- global counts alone wouldn't
                             flag it, but per-ID deviation does.

All features are computed per (sliding window x CAN_ID) so a flood on one
ID doesn't mask a separate spoof of another ID happening in the same window.
"""

import numpy as np
import pandas as pd


def _hex_payload_entropy(row, data_cols):
    """Shannon entropy (bits) of the byte values in a single CAN frame payload."""
    bytes_vals = []
    for c in data_cols:
        v = row[c]
        if pd.isna(v) or v == "":
            continue
        bytes_vals.append(int(v, 16))
    if not bytes_vals:
        return 0.0
    counts = np.bincount(bytes_vals, minlength=256)
    probs = counts[counts > 0] / len(bytes_vals)
    return float(-np.sum(probs * np.log2(probs)))


def load_can_csv(path):
    """Load a CAN CSV (HCRL schema) and add a parsed payload-entropy column."""
    df = pd.read_csv(path, dtype={"CAN_ID": str})
    data_cols = [f"DATA{i}" for i in range(8)]
    df["payload_entropy"] = df.apply(lambda r: _hex_payload_entropy(r, data_cols), axis=1)
    df["Timestamp"] = df["Timestamp"].astype(float)
    return df


def build_baseline_profile(df_normal, min_std_iat=1e-4, min_std_entropy=0.15):
    """
    Learn per-CAN_ID 'normal' statistics from a clean traffic capture.
    This baseline is what every later window gets compared against —
    conceptually equivalent to a per-ECU fingerprint of expected behavior.

    min_std_iat / min_std_entropy: floors applied to the learned std values.
    WHY THIS MATTERS: payload entropy for an 8-byte payload with mostly-
    distinct bytes sits very close to its theoretical ceiling (log2(8)=3.0)
    almost all the time, so its TRUE sample std can be tiny (e.g. 0.08).
    Dividing by a near-zero std turns small, harmless quantization noise
    (one window landing at 2.75 instead of 3.00 purely by chance) into a
    huge, misleading z-score -- which would falsely flag a perfectly
    normal ECU as anomalous. Flooring the std to a sensible minimum
    reflects real-world tolerance instead of overfitting to a feature
    that has structurally little room to vary.
    """
    profile = {}
    for can_id, group in df_normal.groupby("CAN_ID"):
        ts = group["Timestamp"].sort_values().values
        iat = np.diff(ts) if len(ts) > 1 else np.array([0.0])
        raw_std_iat = float(np.std(iat)) if len(iat) > 1 else min_std_iat
        raw_std_entropy = float(group["payload_entropy"].std()) if len(group) > 1 else min_std_entropy
        profile[can_id] = {
            "mean_iat": float(np.mean(iat)),
            "std_iat": max(raw_std_iat, min_std_iat),
            "mean_entropy": float(group["payload_entropy"].mean()),
            "std_entropy": max(raw_std_entropy, min_std_entropy),
        }
    known_ids = set(profile.keys())
    return profile, known_ids


def extract_window_features(df, window_ms=200, baseline_profile=None, known_ids=None):
    """
    Slide a fixed-width time window across the CAN log and compute one
    feature row per (window, CAN_ID) pair that appeared in that window.

    Returns a DataFrame ready for model training/inference. The 'label'
    column (derived from the HCRL 'Flag' field) is included when present,
    so this same function is used for both labeled training data and
    unlabeled live inference (label will just be NaN/ignored at inference).
    """
    baseline_profile = baseline_profile or {}
    known_ids = known_ids or set()

    window_s = window_ms / 1000.0
    df = df.sort_values("Timestamp").reset_index(drop=True)
    t_min, t_max = df["Timestamp"].min(), df["Timestamp"].max()

    rows = []
    n_windows = int(np.ceil((t_max - t_min) / window_s)) + 1
    last_seen_ts = {}  # CAN_ID -> last timestamp seen, persists ACROSS windows
                        # (needed because low-frequency IDs, e.g. a 1000ms-period
                        # ambient temp sensor, may only fire once per several
                        # 200ms windows -- their true IAT can only be measured
                        # by looking across window boundaries, not within one)

    for w in range(n_windows):
        w_start = t_min + w * window_s
        w_end = w_start + window_s
        window_df = df[(df["Timestamp"] >= w_start) & (df["Timestamp"] < w_end)]
        if window_df.empty:
            continue

        total_msgs_in_window = len(window_df)
        unique_ids_in_window = window_df["CAN_ID"].nunique()

        for can_id, grp in window_df.groupby("CAN_ID"):
            ts = grp["Timestamp"].sort_values().values

            if len(ts) > 1:
                # multiple messages in this window: compute IAT directly
                iat = np.diff(ts)
            elif can_id in last_seen_ts:
                # exactly one message in this window, but we've seen this ID
                # before in an earlier window -- true IAT is the gap since then
                iat = np.array([ts[0] - last_seen_ts[can_id]])
            else:
                # first time ever seeing this ID, only one sample -- genuinely
                # no IAT signal available yet. Use NaN-safe sentinel (0) and
                # rely on is_new_id / other features rather than fabricating
                # a fake IAT that doesn't represent this ID's real behavior.
                iat = np.array([0.0])

            last_seen_ts[can_id] = ts[-1]

            mean_iat = float(np.mean(iat))
            std_iat = float(np.std(iat)) if len(iat) > 1 else 0.0
            mean_entropy = float(grp["payload_entropy"].mean())

            is_new_id = 1 if can_id not in known_ids else 0

            base = baseline_profile.get(can_id)
            if base is not None and base["std_iat"] > 1e-9:
                iat_z = (mean_iat - base["mean_iat"]) / base["std_iat"]
            else:
                iat_z = 0.0 if base is not None else 5.0  # unseen ID -> treat as strongly anomalous

            if base is not None and base["std_entropy"] > 1e-9:
                entropy_z = (mean_entropy - base["mean_entropy"]) / base["std_entropy"]
            else:
                entropy_z = 0.0 if base is not None else 5.0

            label = None
            if "Flag" in grp.columns:
                # window x ID is labeled 'attack' if ANY frame in it was injected
                label = 1 if (grp["Flag"] == "T").any() else 0

            rows.append({
                "window_start": w_start,
                "CAN_ID": can_id,
                "msg_count": len(grp),
                "msg_count_ratio": len(grp) / total_msgs_in_window,
                "total_msgs_in_window": total_msgs_in_window,
                "unique_ids_in_window": unique_ids_in_window,
                "mean_iat": mean_iat,
                "std_iat": std_iat,
                "mean_entropy": mean_entropy,
                "is_new_id": is_new_id,
                "iat_zscore": iat_z,
                "entropy_zscore": entropy_z,
                "label": label,
            })

    return pd.DataFrame(rows)


FEATURE_COLUMNS = [
    "msg_count",
    "msg_count_ratio",      # this ID's share of total bus traffic (replaces global total_msgs_in_window)
    "unique_ids_in_window",
    "mean_iat",
    "std_iat",
    "mean_entropy",
    "is_new_id",
    "iat_zscore",
    "entropy_zscore",
]
