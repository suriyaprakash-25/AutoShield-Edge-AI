"""
Before implementing any response-engine gate, establish:
  1. entropy_zscore distribution for TRUE attacker windows (0316, 043F) in Spoof
  2. entropy_zscore distribution for 04B1 FP windows in Spoof
  3. Whether 04B1's anomaly is entropy-primary (iat_zscore near 0)
  4. Whether 0316/043F detections depend on entropy at all
  5. Whether bus_under_congestion overlaps with entropy-extreme windows

Run from src/:  python spoof_threshold_analysis.py
"""
import sys, time
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from feature_extraction import load_can_csv, build_baseline_profile, extract_window_features
from detector import CANAnomalyDetector

DATA_DIR  = "../data"
MODEL_DIR = "../models"

TRUE_ATTACKERS = {"0316", "043F"}
FP_TARGET      = "04B1"

print("Loading global baseline + model...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"  done [{time.time()-t0:.1f}s]")

print("Loading Spoof CSV...")
t0 = time.time()
df_spoof = load_can_csv(f"{DATA_DIR}/can_spoof.csv")
print(f"  {len(df_spoof):,} rows [{time.time()-t0:.1f}s]")

print("Extracting features...")
t0 = time.time()
feat = extract_window_features(df_spoof, 200, profile, known_ids)
out  = iso.predict(feat)
print(f"  {len(feat):,} feature rows [{time.time()-t0:.1f}s]")

# ── Build combined frame: features + predictions ───────────────────────────────
feat_cols = ["CAN_ID", "window_start", "entropy_zscore", "iat_zscore",
             "msg_count", "msg_count_ratio", "unique_ids_in_window"]
df = feat[feat_cols].copy()
df["is_anomaly"] = out["is_anomaly"].values
df["confidence"] = out["confidence"].values
df["label"]      = out["label"].fillna(0).astype(int).values

# ── 1. TRUE ATTACKER windows that ARE flagged (true positives) ─────────────────
tp_mask = df["CAN_ID"].isin(TRUE_ATTACKERS) & (df["is_anomaly"] == 1) & (df["label"] == 1)
df_tp   = df[tp_mask]

print(f"\n{'='*70}")
print(f"TRUE ATTACKER (0316 + 043F) — FLAGGED WINDOWS (true positives)")
print(f"{'='*70}")
print(f"  Count: {len(df_tp):,} windows")

for cid in sorted(TRUE_ATTACKERS):
    sub = df_tp[df_tp["CAN_ID"] == cid]
    if sub.empty:
        print(f"  {cid}: no TP windows")
        continue
    ez  = sub["entropy_zscore"]
    iz  = sub["iat_zscore"]
    print(f"\n  {cid}  ({len(sub):,} TP windows)")
    print(f"    entropy_zscore: min={ez.min():.2f}  max={ez.max():.2f}  "
          f"mean={ez.mean():.2f}  median={ez.median():.2f}")
    print(f"    |entropy_z|   : min={ez.abs().min():.2f}  pct<5={100*(ez.abs()<5).mean():.1f}%  "
          f"pct<10={100*(ez.abs()<10).mean():.1f}%")
    print(f"    iat_zscore    : min={iz.min():.2f}  max={iz.max():.2f}  "
          f"mean={iz.mean():.2f}  median={iz.median():.2f}")
    print(f"    Primary driver: entropy |z|>5 in "
          f"{100*(ez.abs()>5).mean():.1f}% of windows; "
          f"iat |z|>5 in {100*(iz.abs()>5).mean():.1f}% of windows")

# Global min |entropy_z| across all TP attacker windows
min_abs_ez_tp = df_tp["entropy_zscore"].abs().min()
print(f"\n  >>> MIN |entropy_z| across ALL TP attacker windows: {min_abs_ez_tp:.4f}")
print(f"  >>> (gate threshold must be ABOVE this to avoid missing any real detection)")

# ── 2. 04B1 FALSE POSITIVE windows ────────────────────────────────────────────
fp_mask = (df["CAN_ID"] == FP_TARGET) & (df["is_anomaly"] == 1) & (df["label"] == 0)
df_fp   = df[fp_mask]

print(f"\n{'='*70}")
print(f"04B1 FALSE POSITIVE WINDOWS")
print(f"{'='*70}")
print(f"  Count: {len(df_fp):,} windows")
ez_fp = df_fp["entropy_zscore"]
iz_fp = df_fp["iat_zscore"]
print(f"  entropy_zscore: min={ez_fp.min():.2f}  max={ez_fp.max():.2f}  "
      f"mean={ez_fp.mean():.2f}  median={ez_fp.median():.2f}")
print(f"  iat_zscore    : min={iz_fp.min():.2f}  max={iz_fp.max():.2f}  "
      f"mean={iz_fp.mean():.2f}  median={iz_fp.median():.2f}")
print(f"  04B1 entropy-primary (|entropy_z|>5 AND |iat_z|<3): "
      f"{100*((ez_fp.abs()>5) & (iz_fp.abs()<3)).mean():.1f}% of FP windows")

max_abs_ez_fp = ez_fp.abs().max()
print(f"\n  >>> MAX |entropy_z| for 04B1 FP windows: {max_abs_ez_fp:.4f}")
print(f"  >>> (gate threshold must be BELOW this to catch all FPs)")

# ── 3. Safe threshold window ───────────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"THRESHOLD ANALYSIS")
print(f"{'='*70}")
print(f"  Min |entropy_z| among TP attacker windows : {min_abs_ez_tp:.4f}")
print(f"  Max |entropy_z| among 04B1 FP windows     : {max_abs_ez_fp:.4f}")
gap = min_abs_ez_tp - max_abs_ez_fp
print(f"  Gap (TP_min - FP_max)                     : {gap:.4f}")
if gap > 0:
    midpoint = (min_abs_ez_tp + max_abs_ez_fp) / 2
    print(f"  -> Clean separation exists. Midpoint threshold: {midpoint:.1f}")
    print(f"     Any value in ({max_abs_ez_fp:.1f}, {min_abs_ez_tp:.1f}) works safely.")
else:
    print(f"  -> OVERLAP — no clean threshold exists. Gap={gap:.2f}")
    # Show percentile breakdown for FPs vs TPs
    for thresh in [5, 8, 10, 12, 14]:
        fp_caught  = (ez_fp.abs() >= thresh).mean()
        tp_lost    = (df_tp["entropy_zscore"].abs() < thresh).mean()
        print(f"     threshold={thresh}: catches {100*fp_caught:.1f}% FPs, "
              f"loses {100*tp_lost:.1f}% TPs")

# ── 4. Bus-congestion overlap check ───────────────────────────────────────────
print(f"\n{'='*70}")
print(f"BUS-CONGESTION OVERLAP (does entropy gate interact with congestion gate?)")
print(f"{'='*70}")
# unique_ids_zscore > 5.0 triggers bus_under_congestion in response engine
# Proxy: unique_ids_in_window vs baseline
uid_mean = df[df["label"]==0]["unique_ids_in_window"].mean()
uid_std  = df[df["label"]==0]["unique_ids_in_window"].std()
uid_std  = max(uid_std, 1.0)
df["uid_zscore"] = (df["unique_ids_in_window"] - uid_mean) / uid_std

congestion_proxy = df["uid_zscore"] > 5.0

# 04B1 FP windows: are any congested?
fp_congested = congestion_proxy[fp_mask].mean()
# TP attacker windows: are any congested?
tp_congested = congestion_proxy[tp_mask].mean()
# 04B1 entropy-extreme windows: overlap with congestion?
entropy_extreme = df["entropy_zscore"].abs() > 10
b1_extreme_congested = (congestion_proxy & entropy_extreme & (df["CAN_ID"]==FP_TARGET)).sum()

print(f"  04B1 FP windows where bus is congested    : {100*fp_congested:.1f}%")
print(f"  TP attacker windows where bus is congested: {100*tp_congested:.1f}%")
print(f"  04B1 entropy-extreme (|z|>10) AND congested: {b1_extreme_congested} windows")
print(f"  -> Entropy gate (|entropy_z|>threshold) operates on NON-congested windows.")
print(f"     The bus-congestion gate fires first (known ID + congested -> suspicious).")
print(f"     If 04B1 is sometimes congested AND entropy-extreme, both gates apply,")
print(f"     which is fine — congestion gate already handles that subset.")

# ── 5. What drives 0316/043F detection? ───────────────────────────────────────
print(f"\n{'='*70}")
print(f"PRIMARY DETECTION DRIVER FOR 0316 / 043F")
print(f"{'='*70}")
for cid in sorted(TRUE_ATTACKERS):
    sub = df_tp[df_tp["CAN_ID"] == cid]
    if sub.empty:
        continue
    ez_a = sub["entropy_zscore"].abs()
    iz_a = sub["iat_zscore"].abs()
    mc_r = sub["msg_count_ratio"]
    # Classify primary driver per window
    entropy_primary = (ez_a > 3) & (ez_a > iz_a)
    iat_primary     = (iz_a > 3) & (iz_a >= ez_a)
    both            = (ez_a > 3) & (iz_a > 3)
    neither         = (ez_a <= 3) & (iz_a <= 3)
    print(f"\n  {cid} ({len(sub):,} TP windows) — primary anomaly driver:")
    print(f"    entropy primary (|ez|>3 AND > |iz|)  : {100*entropy_primary.mean():.1f}%")
    print(f"    IAT primary     (|iz|>3 AND >= |ez|) : {100*iat_primary.mean():.1f}%")
    print(f"    Both signals    (|ez|>3 AND |iz|>3)  : {100*both.mean():.1f}%")
    print(f"    Neither         (both |z|<=3)         : {100*neither.mean():.1f}%")
    print(f"    msg_count_ratio : mean={mc_r.mean():.3f}  max={mc_r.max():.3f}")

print("\nDone.")
