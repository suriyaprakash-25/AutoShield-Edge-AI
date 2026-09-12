"""
Retrain IsoForest with is_new_id amplified (new_id_weight=10) and sentinel
iat_zscore/entropy_zscore zeroed for new IDs, then run the full 3-scenario
response engine evaluation.

Saves model to: ../models/can_isoforest_reweighted_*
Compares against baseline results in final table.

Run from src/:  python train_reweighted_eval.py
"""
import sys, time
import numpy as np
import pandas as pd
from collections import defaultdict

sys.path.insert(0, ".")
from feature_extraction import load_can_csv, build_baseline_profile, extract_window_features
from detector import CANAnomalyDetector
from response_engine import ResponseEngine

DATA_DIR  = "../data"
MODEL_DIR = "../models"
NEW_ID_WEIGHT = 10

TRUE_ATTACKERS = {
    "dos":   {"0000"},
    "fuzzy": None,
    "spoof": {"0316", "043F"},
}

# ── Baseline results for comparison (from previous full_re_test.py run) ────────
BASELINE = {
    "dos":   {"f1": 0.5634, "fp_iso": 763,  "fp_ids": 25},
    "fuzzy": {"f1": 0.9834, "fp_iso": 436,  "fp_ids": 25},
    "spoof": {"f1": 0.6012, "fp_iso": 501,  "fp_ids": 6},
}

print("=" * 70)
print(f"STEP 1: Load normal traffic + build baseline profile")
print("=" * 70)
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
print(f"  {len(df_normal):,} rows, {len(known_ids)} known IDs [{time.time()-t0:.1f}s]")

print()
print("=" * 70)
print(f"STEP 2: Extract normal features + train IsoForest (new_id_weight={NEW_ID_WEIGHT})")
print("=" * 70)
t0 = time.time()
feat_normal = extract_window_features(df_normal, 200, profile, known_ids)
print(f"  {len(feat_normal):,} normal feature rows [{time.time()-t0:.1f}s]")

detector = CANAnomalyDetector(contamination=0.05, new_id_weight=NEW_ID_WEIGHT)
detector.fit(feat_normal)
print(f"  Trained. is_new_id scale_={detector.scaler.scale_[detector.feature_columns.index('is_new_id')]:.4f} "
      f"(new IDs → {NEW_ID_WEIGHT} in scaled space)")
detector.save(f"{MODEL_DIR}/can_isoforest_reweighted")
print(f"  Saved to {MODEL_DIR}/can_isoforest_reweighted_*")

# ── Scenario evaluation ────────────────────────────────────────────────────────
print()
print("=" * 70)
print("STEP 3: Evaluate all three scenarios (feature extract + RE simulation)")
print("=" * 70)

results = {}

for mode in ["dos", "fuzzy", "spoof"]:
    print(f"\n--- {mode.upper()} ---")
    t0 = time.time()
    df = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    print(f"  Loaded {len(df):,} rows [{time.time()-t0:.1f}s]")

    t0 = time.time()
    feat = extract_window_features(df, 200, profile, known_ids)
    out  = detector.predict(feat)
    print(f"  {len(feat):,} feature rows [{time.time()-t0:.1f}s]")

    # Model-level F1
    y_true = out["label"].fillna(0).astype(int)
    y_pred = out["is_anomaly"].astype(int)
    tp_m = ((y_pred==1) & (y_true==1)).sum()
    fp_m = ((y_pred==1) & (y_true==0)).sum()
    fn_m = ((y_pred==0) & (y_true==1)).sum()
    f1_model = 2*tp_m / (2*tp_m+fp_m+fn_m) if (2*tp_m+fp_m+fn_m) else 0
    print(f"  Model F1={f1_model:.4f}  TP={tp_m:,} FP={fp_m:,} FN={fn_m:,}")

    # Response engine simulation
    engine = ResponseEngine(
        debounce_threshold=2,
        isolation_cooldown_windows=50,
        min_isolation_confidence=0.6,
    )
    isolation_events = defaultdict(int)
    for w_start in sorted(out["window_start"].unique()):
        for _, row in out[out["window_start"] == w_start].iterrows():
            action, _ = engine.process_window_result(
                row, detector.explain(row), detector.classify_attack_type(row))
            if action in ("isolated", "isolated_aggregated"):
                isolation_events[row["CAN_ID"]] += 1

    true_atk_ids = TRUE_ATTACKERS[mode]
    if true_atk_ids:
        fp_iso = {cid: cnt for cid, cnt in isolation_events.items()
                  if cid not in true_atk_ids}
        tp_iso = {cid: cnt for cid, cnt in isolation_events.items()
                  if cid in true_atk_ids}
    else:
        # fuzzy: new IDs are TPs
        new_ids = set(feat.loc[feat["is_new_id"]==1, "CAN_ID"].unique())
        fp_iso = {cid: cnt for cid, cnt in isolation_events.items()
                  if cid in known_ids}
        tp_iso = {cid: cnt for cid, cnt in isolation_events.items()
                  if cid not in known_ids}

    fp_count = sum(fp_iso.values())
    tp_count = sum(tp_iso.values())
    fp_ids   = len(fp_iso)

    print(f"  RE: TP isolations={tp_count:,}  FP isolations={fp_count:,}  "
          f"Innocent IDs isolated={fp_ids}")

    all_iso = sorted(isolation_events.items(), key=lambda x: -x[1])
    for cid, cnt in all_iso[:8]:
        tag = "TP" if cid in (true_atk_ids or new_ids) else "FP"
        print(f"    [{tag}] {cid}  {cnt:,} events")

    if mode == "spoof":
        print(f"  04B1: {isolation_events.get('04B1', 0):,} isolation events "
              f"({'FP - still firing' if isolation_events.get('04B1', 0) > 0 else 'CLEAN'})")
        print(f"  0316: {isolation_events.get('0316', 0):,}  "
              f"043F: {isolation_events.get('043F', 0):,}  (both must be isolated)")

    results[mode] = dict(f1=f1_model, fp_iso=fp_count, fp_ids=fp_ids,
                         tp_iso=tp_count)

# ── Final comparison table ─────────────────────────────────────────────────────
print()
print("=" * 70)
print("FINAL COMPARISON: Baseline  vs  Reweighted (new_id_weight=10)")
print("=" * 70)
print(f"{'Scenario':<8}  {'F1 Base':>8}  {'F1 New':>8}  {'dF1':>7}  "
      f"{'FP-iso Base':>12}  {'FP-iso New':>11}  {'FP-IDs Base':>12}  {'FP-IDs New':>11}")
print("-" * 85)
for mode, r in results.items():
    b = BASELINE[mode]
    df1 = r["f1"] - b["f1"]
    dfp = r["fp_iso"] - b["fp_iso"]
    dfp_ids = r["fp_ids"] - b["fp_ids"]
    print(f"{mode.upper():<8}  {b['f1']:>8.4f}  {r['f1']:>8.4f}  {df1:>+7.4f}  "
          f"{b['fp_iso']:>12,}  {r['fp_iso']:>11,}  {b['fp_ids']:>12,}  {r['fp_ids']:>11,}")
