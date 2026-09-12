"""
Full 3-scenario response engine test with the entropy-drift gate.
Reports F1 and false-positive isolation counts for DoS, Fuzzy, Spoof.
Explicitly verifies 0316 and 043F (true Spoof attackers) still get isolated.

Run from src/:  python full_re_test.py
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
    "fuzzy": None,        # new IDs; handled by is_new_id flag
    "spoof": {"0316", "043F"},
}

print("Loading global baseline + model...")
t0 = time.time()
df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
profile, known_ids = build_baseline_profile(df_normal)
iso = CANAnomalyDetector.load(f"{MODEL_DIR}/can_isoforest_baseline")
print(f"  done [{time.time()-t0:.1f}s]")


def run_scenario(mode):
    print(f"\n{'='*70}")
    print(f"SCENARIO: {mode.upper()}")
    print(f"{'='*70}")

    t0 = time.time()
    df = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    print(f"  Loaded {len(df):,} rows [{time.time()-t0:.1f}s]")

    print("  Extracting features...")
    t0 = time.time()
    feat = extract_window_features(df, 200, profile, known_ids)
    out  = iso.predict(feat)
    print(f"  {len(feat):,} feature rows [{time.time()-t0:.1f}s]")

    # ── IsoForest F1 (model-level, before response engine) ────────────────────
    y_true = out["label"].fillna(0).astype(int)
    y_pred = out["is_anomaly"].astype(int)
    tp_m = ((y_pred==1) & (y_true==1)).sum()
    fp_m = ((y_pred==1) & (y_true==0)).sum()
    fn_m = ((y_pred==0) & (y_true==1)).sum()
    f1_model = 2*tp_m/(2*tp_m+fp_m+fn_m) if (2*tp_m+fp_m+fn_m) else 0
    print(f"  IsoForest model F1 = {f1_model:.4f}  "
          f"(TP={tp_m:,} FP={fp_m:,} FN={fn_m:,})")

    # ── Response engine simulation (time-ordered) ──────────────────────────────
    engine = ResponseEngine(
        debounce_threshold=2,
        isolation_cooldown_windows=50,
        min_isolation_confidence=0.6,
    )

    isolation_events = defaultdict(int)   # can_id -> count of isolation events
    windows_sorted   = sorted(out["window_start"].unique())

    for w_start in windows_sorted:
        window_rows = out[out["window_start"] == w_start]
        for _, row in window_rows.iterrows():
            explanation  = iso.explain(row)
            attack_type  = iso.classify_attack_type(row)
            action, inc  = engine.process_window_result(row, explanation, attack_type)
            if action in ("isolated", "isolated_aggregated"):
                isolation_events[row["CAN_ID"]] += 1

    # ── Response-engine-level isolation counts ─────────────────────────────────
    true_atk_ids = TRUE_ATTACKERS[mode]

    # Classify each isolated ID
    all_isolated = sorted(isolation_events.items(), key=lambda x: -x[1])
    true_positives_re = {cid: cnt for cid, cnt in isolation_events.items()
                         if (true_atk_ids and cid in true_atk_ids)
                         or (mode == "fuzzy" and cid not in known_ids)}
    false_positives_re = {cid: cnt for cid, cnt in isolation_events.items()
                          if cid not in true_positives_re}

    print(f"\n  Response Engine — Isolated IDs:")
    for cid, cnt in all_isolated[:15]:
        tag = "TP" if cid in true_positives_re else "FP"
        print(f"    [{tag}] {cid}  isolated {cnt:,} times")

    tp_re = sum(true_positives_re.values())
    fp_re = sum(false_positives_re.values())

    print(f"\n  RE summary: TP isolations={tp_re:,}  FP isolations={fp_re:,}")
    print(f"  Innocent IDs isolated: {len(false_positives_re)}")

    # Spoof-specific: confirm 0316 and 043F get isolated
    if mode == "spoof":
        print(f"\n  SPOOF ATTACKER VERIFICATION:")
        for cid in ["0316", "043F"]:
            cnt = isolation_events.get(cid, 0)
            status = "ISOLATED" if cnt > 0 else "NOT ISOLATED"
            print(f"    {cid}: {status} ({cnt:,} isolation events)")
        print(f"    04B1 (innocent): {isolation_events.get('04B1', 0):,} isolation events "
              f"({'STILL FP' if isolation_events.get('04B1', 0) > 0 else 'CLEAN'})")

    return f1_model, fp_re, len(false_positives_re)


results = {}
for mode in ["dos", "fuzzy", "spoof"]:
    f1, fp_count, fp_ids = run_scenario(mode)
    results[mode] = (f1, fp_count, fp_ids)

print(f"\n{'='*70}")
print("FINAL SUMMARY")
print(f"{'='*70}")
print(f"{'Scenario':<8}  {'Model F1':>10}  {'FP Isolations':>14}  {'Innocent IDs Isolated':>22}")
print("-"*60)
for mode, (f1, fp_count, fp_ids) in results.items():
    print(f"{mode.upper():<8}  {f1:>10.4f}  {fp_count:>14,}  {fp_ids:>22,}")
print()
print("Note: Model F1 is IsoForest feature-level. Response engine reduces")
print("FP isolations via debounce + confidence + entropy-drift gates.")
