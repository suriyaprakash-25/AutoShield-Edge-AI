"""
Batch validation: run IsoForest baseline AND Ensemble through the full
attribution-gate pipeline and compare FP-isolation counts.

This is the same code path streamer.py uses — same imports, same
normal_id_ratio computation, same ResponseEngine config.

Run from src/:  python validate_model_choice.py
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

# ── Shared baseline (same as streamer.py load_models) ──────────────────────────
print("Loading baseline profile + normal_id_ratio...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
feat_normal = extract_window_features(df_normal, 200, profile, known_ids)
normal_id_ratio = feat_normal.groupby("CAN_ID")["msg_count_ratio"].mean().to_dict()
print(f"  done [{time.time()-t0:.1f}s]  {len(normal_id_ratio)} IDs in ratio dict")


def run_scenarios(detector, label):
    print(f"\n{'='*70}")
    print(f"MODEL: {label}")
    print(f"{'='*70}")
    results = {}

    for mode in ["dos", "fuzzy", "spoof"]:
        t0 = time.time()
        df   = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
        feat = extract_window_features(df, 200, profile, known_ids)
        out  = detector.predict(feat)
        print(f"\n  {mode.upper()} — {len(feat):,} rows [{time.time()-t0:.1f}s]")

        # Model F1
        y_true = out["label"].fillna(0).astype(int)
        y_pred = out["is_anomaly"].astype(int)
        tp_m = int(((y_pred==1)&(y_true==1)).sum())
        fp_m = int(((y_pred==1)&(y_true==0)).sum())
        fn_m = int(((y_pred==0)&(y_true==1)).sum())
        f1   = 2*tp_m/(2*tp_m+fp_m+fn_m) if (2*tp_m+fp_m+fn_m) else 0
        print(f"  Model  F1={f1:.4f}  TP={tp_m:,}  FP={fp_m:,}  FN={fn_m:,}")

        # RE simulation with attribution gate
        engine = ResponseEngine(normal_id_ratio=normal_id_ratio, attribution_ratio_mult=3.0)
        iso_events = defaultdict(int)

        for w_start in sorted(out["window_start"].unique()):
            wdf = out[out["window_start"] == w_start]
            for _, row in wdf.iterrows():
                action, _ = engine.process_window_result(
                    row, detector.explain(row), detector.classify_attack_type(row))
                if action in ("isolated", "isolated_aggregated"):
                    iso_events[row["CAN_ID"]] += 1

        ta = TRUE_ATTACKERS[mode]
        if ta:
            fp_iso = {c: n for c, n in iso_events.items() if c not in ta}
            tp_iso = {c: n for c, n in iso_events.items() if c in ta}
        else:
            new_ids = set(feat.loc[feat["is_new_id"]==1,"CAN_ID"].unique())
            fp_iso  = {c: n for c, n in iso_events.items() if c in known_ids}
            tp_iso  = {c: n for c, n in iso_events.items() if c not in known_ids}

        fp_cnt  = sum(fp_iso.values())
        fp_ids  = len(fp_iso)
        tp_cnt  = sum(tp_iso.values())

        print(f"  RE     TP-iso={tp_cnt:,}  FP-iso={fp_cnt}  FP-IDs={fp_ids}")
        for cid, cnt in sorted(iso_events.items(), key=lambda x:-x[1])[:6]:
            tag = "TP" if (ta and cid in ta) or (not ta and cid not in known_ids) else "FP"
            print(f"    [{tag}] {cid}  {cnt} events")

        results[mode] = dict(f1=f1, fp_iso=fp_cnt, fp_ids=fp_ids, tp_iso=tp_cnt)

    return results


# ── Run IsoForest (the validated/correct demo model) ──────────────────────────
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
iso_results = run_scenarios(iso, "IsolationForest baseline  <-- what streamer.py NOW loads")

# ── Run Ensemble (the wrong model streamer.py was using before the fix) ────────
try:
    from ensemble_detector import EnsembleDetector
    ens = EnsembleDetector.load(f"{MODEL_DIR}/can_ensemble")
    ens_results = run_scenarios(ens, "Ensemble (IsoForest + LSTM-AE)  <-- what streamer.py WAS loading (bug)")
except Exception as e:
    print(f"\nEnsemble load failed: {e}")
    ens_results = None

# ── Comparison table ───────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print("COMPARISON: IsoForest (fixed) vs Ensemble (was bugged into live mode)")
print(f"{'='*70}")
print(f"{'':10}  {'IsoForest':^26}  {'Ensemble':^26}")
print(f"{'Scenario':10}  {'F1':>6}  {'FP-iso':>8}  {'FP-IDs':>8}  {'F1':>6}  {'FP-iso':>8}  {'FP-IDs':>8}")
print("-"*68)
for mode in ["dos","fuzzy","spoof"]:
    r = iso_results[mode]
    if ens_results:
        e = ens_results[mode]
        print(f"{mode.upper():<10}  {r['f1']:>6.4f}  {r['fp_iso']:>8}  {r['fp_ids']:>8}  "
              f"{e['f1']:>6.4f}  {e['fp_iso']:>8}  {e['fp_ids']:>8}")
    else:
        print(f"{mode.upper():<10}  {r['f1']:>6.4f}  {r['fp_iso']:>8}  {r['fp_ids']:>8}  {'N/A':>6}  {'N/A':>8}  {'N/A':>8}")
print("\nDone.")
