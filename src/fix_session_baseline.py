"""
Verify that a session-matched baseline (built from R-rows in the SAME recording
as the attack) eliminates the 04B1/05A0 entropy-drift false positives in Spoof,
and also improves DoS and Fuzzy FP counts.

Run from src/:  python fix_session_baseline.py
"""
import sys, os, time
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from feature_extraction import (load_can_csv, build_baseline_profile,
                                 extract_window_features, FEATURE_COLUMNS)
from detector import CANAnomalyDetector

DATA_DIR  = "../data"
MODEL_DIR = "../models"

TARGET_NORMAL_ROWS = 300_000   # R-rows to sample for session baseline (fast)

# ── Global baseline (current approach) ────────────────────────────────────────
print("Loading global baseline (can_normal.csv = DoS-session R-rows)...")
t0 = time.time()
df_normal_global = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile_global, known_ids_global = build_baseline_profile(df_normal_global)
print(f"  {len(df_normal_global):,} rows, {len(known_ids_global)} ECU IDs  [{time.time()-t0:.1f}s]")

iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")


def extract_session_baseline(attack_csv: str, label: str) -> tuple:
    """Sample up to TARGET_NORMAL_ROWS R-flagged rows from the attack CSV itself."""
    print(f"  Sampling R-rows from {os.path.basename(attack_csv)}...")
    chunks = []
    total_r = 0
    for chunk in pd.read_csv(attack_csv, dtype={"CAN_ID": str}, chunksize=200_000):
        r_chunk = chunk[chunk["Flag"] == "R"]
        chunks.append(r_chunk)
        total_r += len(r_chunk)
        if total_r >= TARGET_NORMAL_ROWS:
            break
    df_r = pd.concat(chunks, ignore_index=True).head(TARGET_NORMAL_ROWS)
    # Add payload entropy (same as load_can_csv but skip re-reading the huge file)
    from feature_extraction import _compute_entropy_vectorized
    data_cols = [f"DATA{i}" for i in range(8)]
    df_r["payload_entropy"] = _compute_entropy_vectorized(df_r, data_cols)
    df_r["Timestamp"] = df_r["Timestamp"].astype(float)
    profile, known_ids = build_baseline_profile(df_r)
    print(f"  Session baseline: {len(df_r):,} R-rows, {len(known_ids)} ECU IDs")
    return profile, known_ids


def fp_summary(out: pd.DataFrame, mode: str, known_ids: set,
               true_attacker_ids: set, label: str):
    y_true = out["label"].fillna(0).astype(int)
    y_pred = out["is_anomaly"].astype(int)
    tp = ((y_pred==1)&(y_true==1)).sum()
    fp = ((y_pred==1)&(y_true==0)).sum()
    fn = ((y_pred==0)&(y_true==1)).sum()
    prec = tp/(tp+fp) if tp+fp else 0
    rec  = tp/(tp+fn) if tp+fn else 0
    f1   = 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0

    fp_rows = out[(y_pred==1)&(y_true==0)]
    if mode == "fuzzy":
        innocent = fp_rows[fp_rows["CAN_ID"].isin(known_ids)]
    else:
        innocent = fp_rows[~fp_rows["CAN_ID"].isin(true_attacker_ids)]

    top = innocent["CAN_ID"].value_counts().head(5)
    print(f"  [{label}] Prec={prec:.4f} Rec={rec:.4f} F1={f1:.4f} | "
          f"FP={fp:,} innocent={len(innocent):,}")
    for cid, cnt in top.items():
        print(f"    {cid}  {cnt:,}  ({100*cnt/max(len(innocent),1):.1f}%)")


TRUE_ATTACKERS = {
    "dos":   {"0000"},
    "fuzzy": set(),      # handled separately
    "spoof": {"0316", "043F"},
}

for mode in ["dos", "fuzzy", "spoof"]:
    print()
    print("=" * 70)
    print(f"SCENARIO: {mode.upper()}")
    print("=" * 70)

    attack_csv = f"{DATA_DIR}/can_{mode}.csv"

    # ── Session baseline ───────────────────────────────────────────────────────
    t0 = time.time()
    profile_sess, known_ids_sess = extract_session_baseline(attack_csv, mode)

    # ── Load full attack CSV once, share between both evaluations ─────────────
    print(f"  Loading full {mode} CSV...")
    df_atk = load_can_csv(attack_csv)
    print(f"  {len(df_atk):,} rows  [{time.time()-t0:.1f}s]")

    # ── Global baseline evaluation ─────────────────────────────────────────────
    print("  Extracting features with GLOBAL baseline...")
    feat_g = extract_window_features(df_atk, 200, profile_global, known_ids_global)
    out_g  = iso.predict(feat_g)
    fp_summary(out_g, mode, known_ids_global, TRUE_ATTACKERS[mode], "GLOBAL baseline")

    # ── Session baseline evaluation ────────────────────────────────────────────
    print("  Extracting features with SESSION baseline...")
    feat_s = extract_window_features(df_atk, 200, profile_sess, known_ids_sess)
    out_s  = iso.predict(feat_s)
    fp_summary(out_s, mode, known_ids_sess, TRUE_ATTACKERS[mode], "SESSION baseline")

    # ── Spoof: show 04B1 / 05A0 specifically ──────────────────────────────────
    if mode == "spoof":
        y_true_g = out_g["label"].fillna(0).astype(int)
        y_pred_g = out_g["is_anomaly"].astype(int)
        y_true_s = out_s["label"].fillna(0).astype(int)
        y_pred_s = out_s["is_anomaly"].astype(int)

        for target_id in ["04B1", "05A0", "0690"]:
            mask_g = (out_g["CAN_ID"]==target_id)&(y_pred_g==1)&(y_true_g==0)
            mask_s = (out_s["CAN_ID"]==target_id)&(y_pred_s==1)&(y_true_s==0)
            e_g = feat_g.loc[feat_g["CAN_ID"]==target_id, "entropy_zscore"].mean()
            e_s = feat_s.loc[feat_s["CAN_ID"]==target_id, "entropy_zscore"].mean()
            print(f"\n  {target_id} FP isolation count:"
                  f"  GLOBAL={mask_g.sum():,}  SESSION={mask_s.sum():,}"
                  f"  | entropy_zscore  GLOBAL={e_g:.2f}  SESSION={e_s:.2f}")

print("\nDone.")
