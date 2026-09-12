"""
Surgical hybrid-baseline test:
  - Global profile for all IDs except 04B1
  - 04B1's mean_entropy / std_entropy replaced with Spoof-session values
  - IsoForest model unchanged (trained on global baseline features)
  - Re-run feature extraction + predict for DOS, FUZZY, SPOOF
  - Report F1 and 04B1-specific entropy_zscore before and after patch

Run from src/:  python hybrid_baseline_test.py
"""
import sys, os, time
import numpy as np
import pandas as pd

sys.path.insert(0, ".")
from feature_extraction import (load_can_csv, build_baseline_profile,
                                 extract_window_features, _compute_entropy_vectorized,
                                 FEATURE_COLUMNS)
from detector import CANAnomalyDetector

DATA_DIR  = "../data"
MODEL_DIR = "../models"

PATCH_ID = "04B1"
SAMPLE_R_ROWS = 50_000   # R-rows from Spoof to compute 04B1 entropy stats

# ── Global baseline ────────────────────────────────────────────────────────────
print("Loading global baseline (can_normal.csv)...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile_global, known_ids = build_baseline_profile(df_normal)
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"  {len(known_ids)} known IDs  [{time.time()-t0:.1f}s]")
print(f"  04B1 global baseline: "
      f"mean_entropy={profile_global[PATCH_ID]['mean_entropy']:.4f}  "
      f"std_entropy={profile_global[PATCH_ID]['std_entropy']:.4f}")

# ── Sample 04B1 R-rows from Spoof session ─────────────────────────────────────
print(f"\nSampling {PATCH_ID} R-rows from Spoof session...")
t0 = time.time()
b1_rows = []
for chunk in pd.read_csv(f"{DATA_DIR}/can_spoof.csv", dtype={"CAN_ID": str},
                          chunksize=200_000):
    sub = chunk[(chunk["CAN_ID"] == PATCH_ID) & (chunk["Flag"] == "R")]
    if not sub.empty:
        b1_rows.append(sub)
    if sum(len(x) for x in b1_rows) >= SAMPLE_R_ROWS:
        break

df_b1 = pd.concat(b1_rows, ignore_index=True).head(SAMPLE_R_ROWS)
data_cols = [f"DATA{i}" for i in range(8)]
df_b1["payload_entropy"] = _compute_entropy_vectorized(df_b1, data_cols)

b1_mean_entropy = float(df_b1["payload_entropy"].mean())
b1_std_entropy  = float(df_b1["payload_entropy"].std())
b1_std_entropy  = max(b1_std_entropy, 0.15)   # same floor as build_baseline_profile
print(f"  {len(df_b1):,} rows sampled  [{time.time()-t0:.1f}s]")
print(f"  04B1 Spoof-session: mean_entropy={b1_mean_entropy:.4f}  std_entropy={b1_std_entropy:.4f}")

# ── Build hybrid profile: patch ONLY 04B1 ─────────────────────────────────────
import copy
profile_hybrid = copy.deepcopy(profile_global)
profile_hybrid[PATCH_ID]["mean_entropy"] = b1_mean_entropy
profile_hybrid[PATCH_ID]["std_entropy"]  = b1_std_entropy
print(f"\nHybrid profile: all IDs unchanged except {PATCH_ID}")
print(f"  Before: entropy_zscore for 04B1 with entropy=0.354 → "
      f"z={(0.354 - profile_global[PATCH_ID]['mean_entropy'])/profile_global[PATCH_ID]['std_entropy']:.2f}")
print(f"  After:  entropy_zscore for 04B1 with entropy=0.354 → "
      f"z={(0.354 - b1_mean_entropy)/b1_std_entropy:.2f}")

# ── Evaluation helper ──────────────────────────────────────────────────────────
def evaluate(feat, mode, label, profile_used):
    out = iso.predict(feat)
    y_true = out["label"].fillna(0).astype(int)
    y_pred = out["is_anomaly"].astype(int)
    tp = ((y_pred==1)&(y_true==1)).sum()
    fp = ((y_pred==1)&(y_true==0)).sum()
    fn = ((y_pred==0)&(y_true==1)).sum()
    prec = tp/(tp+fp) if tp+fp else 0
    rec  = tp/(tp+fn) if tp+fn else 0
    f1   = 2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0

    # 04B1 stats
    b1 = out[out["CAN_ID"] == PATCH_ID]
    b1_fp   = ((b1["is_anomaly"]==1) & (b1["label"].fillna(0)==0)).sum()
    b1_ez   = feat.loc[feat["CAN_ID"]==PATCH_ID, "entropy_zscore"].mean()

    print(f"  [{label}] Prec={prec:.4f}  Rec={rec:.4f}  F1={f1:.4f}  | "
          f"04B1 FPs={b1_fp:,}  04B1 entropy_z={b1_ez:.2f}")
    return f1, b1_fp


# ── Run all three scenarios ────────────────────────────────────────────────────
results = {}

for mode, true_atk in [("dos",  {"0000"}),
                        ("fuzzy", None),
                        ("spoof", {"0316","043F"})]:
    print(f"\n{'='*70}")
    print(f"SCENARIO: {mode.upper()}")
    print(f"{'='*70}")
    t0 = time.time()
    df = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    print(f"  Loaded {len(df):,} rows  [{time.time()-t0:.1f}s]")

    # Global baseline features
    print("  Extracting features [GLOBAL]...")
    feat_g = extract_window_features(df, 200, profile_global, known_ids)
    f1_g, b1_fp_g = evaluate(feat_g, mode, "GLOBAL ", profile_global)

    # Hybrid baseline features (only 04B1 entropy differs)
    print("  Extracting features [HYBRID]...")
    feat_h = extract_window_features(df, 200, profile_hybrid, known_ids)
    f1_h, b1_fp_h = evaluate(feat_h, mode, "HYBRID ", profile_hybrid)

    delta_f1 = f1_h - f1_g
    delta_b1 = b1_fp_h - b1_fp_g
    print(f"  Delta: F1 {f1_g:.4f} -> {f1_h:.4f} ({delta_f1:+.4f})  "
          f"| 04B1 FPs {b1_fp_g} -> {b1_fp_h} ({delta_b1:+,})")
    results[mode] = dict(f1_g=f1_g, f1_h=f1_h, b1_g=b1_fp_g, b1_h=b1_fp_h)

# ── Summary ────────────────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("SUMMARY")
print(f"{'='*70}")
print(f"{'Scenario':<8}  {'F1 Global':>10}  {'F1 Hybrid':>10}  {'Delta F1':>10}  "
      f"{'04B1 FP Global':>16}  {'04B1 FP Hybrid':>16}")
print("-"*80)
for mode, r in results.items():
    print(f"{mode.upper():<8}  {r['f1_g']:>10.4f}  {r['f1_h']:>10.4f}  "
          f"{r['f1_h']-r['f1_g']:>+10.4f}  "
          f"{r['b1_g']:>16,}  {r['b1_h']:>16,}")
print()
print("Hypothesis: Spoof F1 improves, 04B1 FPs drop to near 0,")
print("            DoS/Fuzzy F1 unchanged (04B1 entropy in those sessions ~1.86,")
print("            which after patching gives high +entropy_z but IsoForest")
print("            may or may not flag that direction as anomalous).")
