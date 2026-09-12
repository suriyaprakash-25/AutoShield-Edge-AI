"""
For the 25 innocent IDs isolated in DoS and Fuzzy:
  - Confirm IAT-zscore inflation from bus starvation is the dominant driver
  - Compare iat_zscore distribution: FP innocent windows vs TP attacker windows
  - Check for a clean separation (same question as Spoof/entropy)
  - Show msg_count_ratio and entropy_zscore for context

Run from src/:  python dos_fuzzy_fp_analysis.py
"""
import sys, time
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from feature_extraction import load_can_csv, build_baseline_profile, extract_window_features
from detector import CANAnomalyDetector

DATA_DIR  = "../data"
MODEL_DIR = "../models"

print("Loading global baseline + model...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"  done [{time.time()-t0:.1f}s]")


def analyse(mode, true_atk_ids):
    print(f"\n{'='*70}")
    print(f"SCENARIO: {mode.upper()}  — true attackers: {true_atk_ids or 'new IDs (fuzzy)'}")
    print(f"{'='*70}")

    t0 = time.time()
    df = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    print(f"  Loaded {len(df):,} rows [{time.time()-t0:.1f}s]")

    t0 = time.time()
    feat = extract_window_features(df, 200, profile, known_ids)
    out  = iso.predict(feat)
    print(f"  {len(feat):,} feature rows [{time.time()-t0:.1f}s]")

    # Build combined frame
    cols = ["CAN_ID", "window_start", "iat_zscore", "entropy_zscore",
            "msg_count", "msg_count_ratio", "unique_ids_in_window",
            "mean_iat", "std_iat"]
    df_f = feat[cols].copy()
    df_f["is_anomaly"] = out["is_anomaly"].values
    df_f["confidence"] = out["confidence"].values
    df_f["label"]      = out["label"].fillna(0).astype(int).values

    # Classify windows
    if true_atk_ids:
        # DoS: true TP = flagged AND label=1 AND in attacker IDs
        tp_mask = (df_f["CAN_ID"].isin(true_atk_ids) &
                   (df_f["is_anomaly"] == 1) & (df_f["label"] == 1))
        # FP = flagged AND label=0 AND NOT in attacker IDs
        fp_mask = ((df_f["is_anomaly"] == 1) & (df_f["label"] == 0) &
                   ~df_f["CAN_ID"].isin(true_atk_ids))
    else:
        # Fuzzy: TP = new IDs (is_new_id in feat), FP = known IDs flagged
        new_ids = set(feat.loc[feat["is_new_id"] == 1, "CAN_ID"].unique())
        tp_mask = (df_f["CAN_ID"].isin(new_ids) &
                   (df_f["is_anomaly"] == 1) & (df_f["label"] == 1))
        fp_mask = (df_f["CAN_ID"].isin(known_ids) &
                   (df_f["is_anomaly"] == 1) & (df_f["label"] == 0))

    df_tp = df_f[tp_mask]
    df_fp = df_f[fp_mask]

    print(f"  TP windows: {len(df_tp):,}  |  FP windows: {len(df_fp):,}")

    # ── True attacker: iat_zscore ──────────────────────────────────────────────
    print(f"\n  TRUE ATTACKER windows (TP):")
    if not df_tp.empty:
        iz = df_tp["iat_zscore"]
        ez = df_tp["entropy_zscore"]
        mr = df_tp["msg_count_ratio"]
        print(f"    iat_zscore    : min={iz.min():.2f}  max={iz.max():.2f}  "
              f"mean={iz.mean():.2f}  median={iz.median():.2f}")
        print(f"    |iat_z|       : min={iz.abs().min():.2f}  "
              f"pct>3={100*(iz.abs()>3).mean():.1f}%  "
              f"pct>5={100*(iz.abs()>5).mean():.1f}%  "
              f"pct>10={100*(iz.abs()>10).mean():.1f}%")
        print(f"    entropy_zscore: min={ez.min():.2f}  max={ez.max():.2f}  "
              f"mean={ez.mean():.2f}")
        print(f"    msg_count_ratio: mean={mr.mean():.3f}  max={mr.max():.3f}")

        # Primary driver
        iat_primary  = (iz.abs() > 3) & (iz.abs() >= ez.abs())
        ent_primary  = (ez.abs() > 3) & (ez.abs() > iz.abs())
        both_extreme = (iz.abs() > 3) & (ez.abs() > 3)
        neither      = (iz.abs() <= 3) & (ez.abs() <= 3)
        print(f"    Primary driver:")
        print(f"      IAT primary (|iz|>3 AND >=|ez|) : {100*iat_primary.mean():.1f}%")
        print(f"      entropy primary (|ez|>3 AND >|iz|): {100*ent_primary.mean():.1f}%")
        print(f"      both extreme (|iz|>3 AND |ez|>3)  : {100*both_extreme.mean():.1f}%")
        print(f"      neither (both <=3)                : {100*neither.mean():.1f}%")
        min_abs_iat_tp = iz.abs().min()
        print(f"\n    >>> MIN |iat_z| among TP windows: {min_abs_iat_tp:.4f}")
    else:
        print("    (no TP windows)")
        min_abs_iat_tp = None

    # ── False positives: iat_zscore ────────────────────────────────────────────
    print(f"\n  FALSE POSITIVE windows (innocent IDs flagged):")
    if not df_fp.empty:
        iz_fp = df_fp["iat_zscore"]
        ez_fp = df_fp["entropy_zscore"]
        mr_fp = df_fp["msg_count_ratio"]
        ub_fp = df_fp["unique_ids_in_window"]

        print(f"    iat_zscore    : min={iz_fp.min():.2f}  max={iz_fp.max():.2f}  "
              f"mean={iz_fp.mean():.2f}  median={iz_fp.median():.2f}")
        print(f"    |iat_z|       : pct>3={100*(iz_fp.abs()>3).mean():.1f}%  "
              f"pct>5={100*(iz_fp.abs()>5).mean():.1f}%  "
              f"pct>10={100*(iz_fp.abs()>10).mean():.1f}%")
        print(f"    entropy_zscore: min={ez_fp.min():.2f}  max={ez_fp.max():.2f}  "
              f"mean={ez_fp.mean():.2f}")
        print(f"    msg_count_ratio: mean={mr_fp.mean():.3f}  max={mr_fp.max():.3f}")
        print(f"    unique_ids_in_window: mean={ub_fp.mean():.1f}  max={ub_fp.max():.0f}")

        # Primary driver for FPs
        iat_primary_fp  = (iz_fp.abs() > 3) & (iz_fp.abs() >= ez_fp.abs())
        ent_primary_fp  = (ez_fp.abs() > 3) & (ez_fp.abs() > iz_fp.abs())
        both_fp         = (iz_fp.abs() > 3) & (ez_fp.abs() > 3)
        neither_fp      = (iz_fp.abs() <= 3) & (ez_fp.abs() <= 3)
        print(f"    Primary driver:")
        print(f"      IAT primary (|iz|>3 AND >=|ez|) : {100*iat_primary_fp.mean():.1f}%")
        print(f"      entropy primary (|ez|>3 AND >|iz|): {100*ent_primary_fp.mean():.1f}%")
        print(f"      both extreme (|iz|>3 AND |ez|>3)  : {100*both_fp.mean():.1f}%")
        print(f"      neither (both <=3)                : {100*neither_fp.mean():.1f}%")

        # Bus congestion proxy: unique_ids_zscore
        # Compute from the FP feature rows directly
        uid_global_mean = df_f.loc[df_f["label"]==0, "unique_ids_in_window"].mean()
        uid_global_std  = max(df_f.loc[df_f["label"]==0, "unique_ids_in_window"].std(), 1.0)
        uid_z_fp = (ub_fp - uid_global_mean) / uid_global_std
        bus_congested_fp = (uid_z_fp > 5.0).mean()
        print(f"    unique_ids_zscore > 5 (bus congestion proxy): "
              f"{100*bus_congested_fp:.1f}% of FP windows")

        max_abs_iat_fp = iz_fp.abs().max()
        print(f"\n    >>> MAX |iat_z| among FP windows: {max_abs_iat_fp:.4f}")

        # Per-CAN_ID breakdown of FP windows
        print(f"\n    Top FP CAN_IDs by window count:")
        top_fp = df_fp.groupby("CAN_ID").agg(
            count=("iat_zscore", "count"),
            mean_iat_z=("iat_zscore", "mean"),
            mean_ent_z=("entropy_zscore", "mean"),
            mean_uid=("unique_ids_in_window", "mean"),
        ).sort_values("count", ascending=False).head(10)
        print(f"    {'CAN_ID':<8}  {'FP wins':>8}  {'mean_iat_z':>10}  "
              f"{'mean_ent_z':>10}  {'mean_uid':>10}")
        for cid, row in top_fp.iterrows():
            print(f"    {cid:<8}  {row['count']:>8,}  {row['mean_iat_z']:>10.2f}  "
                  f"{row['mean_ent_z']:>10.2f}  {row['mean_uid']:>10.1f}")
    else:
        print("    (no FP windows)")
        max_abs_iat_fp = None

    # ── Threshold gap analysis ─────────────────────────────────────────────────
    if min_abs_iat_tp is not None and max_abs_iat_fp is not None:
        print(f"\n  THRESHOLD ANALYSIS:")
        print(f"    Min |iat_z| among TP windows  : {min_abs_iat_tp:.4f}")
        print(f"    Max |iat_z| among FP windows  : {max_abs_iat_fp:.4f}")
        gap = min_abs_iat_tp - max_abs_iat_fp
        print(f"    Gap (TP_min - FP_max)         : {gap:.4f}")
        if gap > 0:
            mid = (min_abs_iat_tp + max_abs_iat_fp) / 2
            print(f"    -> CLEAN separation. Midpoint: {mid:.1f}")
        else:
            print(f"    -> OVERLAP (gap={gap:.2f}) — no clean threshold.")
            print(f"       Threshold sweep (FP caught / TP lost):")
            iz_fp_abs = df_fp["iat_zscore"].abs()
            iz_tp_abs = df_tp["iat_zscore"].abs()
            for thresh in [3, 5, 8, 10, 15, 20]:
                fp_c = (iz_fp_abs >= thresh).mean()
                tp_s = (iz_tp_abs >= thresh).mean()
                print(f"       thresh={thresh:>2}: catches {100*fp_c:.1f}% FPs, "
                      f"TP windows with |iat_z|>={thresh}: {100*tp_s:.1f}%")


analyse("dos",   {"0000"})
analyse("fuzzy", None)
print("\nDone.")
