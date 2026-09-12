"""
Full 3-scenario response engine test with two-stage attribution gate.
Compares against prior baseline (entropy-drift gate only, no attribution gate).

Run from src/:  python full_re_test_attributed.py
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

TRUE_ATTACKERS = {
    "dos":   {"0000"},
    "fuzzy": None,
    "spoof": {"0316", "043F"},
}

# Prior results (entropy-drift gate only, no attribution gate)
PRIOR = {
    "dos":   {"f1": 0.5634, "fp_iso": 763,  "fp_ids": 25},
    "fuzzy": {"f1": 0.9834, "fp_iso": 436,  "fp_ids": 25},
    "spoof": {"f1": 0.6012, "fp_iso": 501,  "fp_ids": 6},
}

print("Loading baseline + model...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"  done [{time.time()-t0:.1f}s]")

# Compute per-ID normal msg_count_ratio from normal features
print("Computing normal-traffic per-ID msg_count_ratio baseline...")
t0 = time.time()
feat_normal = extract_window_features(df_normal, 200, profile, known_ids)
normal_id_ratio = feat_normal.groupby("CAN_ID")["msg_count_ratio"].mean().to_dict()
print(f"  {len(normal_id_ratio)} IDs  [{time.time()-t0:.1f}s]")
print(f"  Sample: " + "  ".join(f"{k}={v:.4f}" for k, v in list(normal_id_ratio.items())[:5]))

results = {}

for mode in ["dos", "fuzzy", "spoof"]:
    print(f"\n{'='*70}")
    print(f"SCENARIO: {mode.upper()}")
    print(f"{'='*70}")

    t0 = time.time()
    df = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    feat = extract_window_features(df, 200, profile, known_ids)
    out  = iso.predict(feat)
    print(f"  {len(feat):,} feature rows [{time.time()-t0:.1f}s]")

    # Model-level F1
    y_true = out["label"].fillna(0).astype(int)
    y_pred = out["is_anomaly"].astype(int)
    tp_m = ((y_pred==1) & (y_true==1)).sum()
    fp_m = ((y_pred==1) & (y_true==0)).sum()
    fn_m = ((y_pred==0) & (y_true==1)).sum()
    f1_model = 2*tp_m / (2*tp_m+fp_m+fn_m) if (2*tp_m+fp_m+fn_m) else 0
    print(f"  Model F1={f1_model:.4f}  TP={tp_m:,} FP={fp_m:,} FN={fn_m:,}")

    # Response engine with attribution gate
    engine = ResponseEngine(
        debounce_threshold=2,
        isolation_cooldown_windows=50,
        min_isolation_confidence=0.6,
        normal_id_ratio=normal_id_ratio,
        attribution_ratio_mult=3.0,
    )

    action_counts = defaultdict(int)
    isolation_events = defaultdict(int)

    for w_start in sorted(out["window_start"].unique()):
        wdf = out[out["window_start"] == w_start]
        for _, row in wdf.iterrows():
            action, _ = engine.process_window_result(
                row, iso.explain(row), iso.classify_attack_type(row))
            action_counts[action] += 1
            if action in ("isolated", "isolated_aggregated"):
                isolation_events[row["CAN_ID"]] += 1

    true_atk_ids = TRUE_ATTACKERS[mode]
    if true_atk_ids:
        fp_iso = {cid: cnt for cid, cnt in isolation_events.items() if cid not in true_atk_ids}
        tp_iso = {cid: cnt for cid, cnt in isolation_events.items() if cid in true_atk_ids}
    else:
        new_ids = set(feat.loc[feat["is_new_id"]==1, "CAN_ID"].unique())
        fp_iso = {cid: cnt for cid, cnt in isolation_events.items() if cid in known_ids}
        tp_iso = {cid: cnt for cid, cnt in isolation_events.items() if cid not in known_ids}

    fp_count = sum(fp_iso.values())
    tp_count = sum(tp_iso.values())
    fp_ids   = len(fp_iso)

    print(f"  RE: TP isolations={tp_count:,}  FP isolations={fp_count:,}  Innocent IDs isolated={fp_ids}")
    print(f"  Action breakdown: " + "  ".join(f"{k}={v:,}" for k, v in sorted(action_counts.items())))

    all_iso = sorted(isolation_events.items(), key=lambda x: -x[1])
    for cid, cnt in all_iso[:10]:
        if true_atk_ids:
            tag = "TP" if cid in true_atk_ids else "FP"
        else:
            tag = "TP" if cid not in known_ids else "FP"
        print(f"    [{tag}] {cid}  {cnt:,} events")

    if mode == "spoof":
        print(f"  04B1: {isolation_events.get('04B1', 0):,} isolation events "
              f"({'CLEAN' if isolation_events.get('04B1', 0) == 0 else 'STILL FIRING'})")
        print(f"  0316: {isolation_events.get('0316', 0):,}   043F: {isolation_events.get('043F', 0):,}  (both must be isolated)")

    results[mode] = dict(f1=f1_model, fp_iso=fp_count, fp_ids=fp_ids, tp_iso=tp_count)

# Final comparison
print(f"\n{'='*70}")
print("COMPARISON: Prior (entropy-drift gate only) vs Now (+ attribution gate)")
print(f"{'='*70}")
print(f"{'Scenario':<8}  {'F1':>6}  {'FP-iso Prior':>13}  {'FP-iso Now':>11}  {'Delta':>7}  {'FP-IDs Prior':>13}  {'FP-IDs Now':>11}  {'Delta':>7}")
print("-" * 92)
for mode, r in results.items():
    p = PRIOR[mode]
    dfp  = r["fp_iso"]  - p["fp_iso"]
    dfpi = r["fp_ids"]  - p["fp_ids"]
    print(f"{mode.upper():<8}  {r['f1']:>6.4f}  {p['fp_iso']:>13,}  {r['fp_iso']:>11,}  {dfp:>+7,}  "
          f"{p['fp_ids']:>13,}  {r['fp_ids']:>11,}  {dfpi:>+7,}")

print("\nDone.")
