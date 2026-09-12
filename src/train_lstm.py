"""
AutoShield Edge AI — Train & Evaluate Phase 2 (LSTM Autoencoder)
===================================================================
1. Loads and featurises the same data as train_baseline.py
2. Trains the LSTM-AE on normal-only traffic
3. Loads the saved Phase 1 IsoForest for a direct comparison
4. Prints a side-by-side metrics table: Phase 1 vs Phase 2
5. Demonstrates the end-to-end explain() output on sample flagged windows
6. Saves the LSTM model to ../models/

The precision improvement on DoS (Phase 1's main weakness) is the headline
result — the LSTM's temporal context distinguishes a sustained flood from a
transient burst, which per-window scoring cannot.

Dependencies: torch (pip install torch)
"""

import os
import sys
import time

sys.path.insert(0, ".")

import pandas as pd
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from detector import CANAnomalyDetector
from feature_extraction import (
    build_baseline_profile,
    extract_window_features,
    load_can_csv,
)
from lstm_detector import LSTMAnomalyDetector

DATA_DIR = "../data"
MODEL_DIR = "../models"


def _metrics(detector, feat):
    result = detector.predict(feat)
    y_true = result["label"]
    y_pred = result["is_anomaly"]
    return (
        precision_score(y_true, y_pred, zero_division=0),
        recall_score(y_true, y_pred, zero_division=0),
        f1_score(y_true, y_pred, zero_division=0),
    )


def main():
    t0 = time.time()

    print("=" * 70)
    print("STEP 1: Load data + build per-ID baseline profile")
    print("=" * 70)
    df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
    profile, known_ids = build_baseline_profile(df_normal)
    print(f"  Normal frames: {len(df_normal)}, known ECU IDs: {len(known_ids)}")

    print()
    print("=" * 70)
    print("STEP 2: Extract sliding-window features")
    print("=" * 70)
    feat_normal = extract_window_features(
        df_normal, window_ms=200, baseline_profile=profile, known_ids=known_ids
    )
    print(f"  Normal: {len(feat_normal)} feature rows")

    attack_feats: dict[str, pd.DataFrame] = {}
    for mode in ["dos", "fuzzy", "spoof"]:
        df_atk = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
        feat = extract_window_features(
            df_atk, window_ms=200, baseline_profile=profile, known_ids=known_ids
        )
        attack_feats[mode] = feat
        print(f"  {mode}: {len(feat)} feature rows, {feat['label'].sum()} attack-labelled windows")

    print()
    print("=" * 70)
    print("STEP 3: Train LSTM-Autoencoder (Phase 2)")
    print("=" * 70)
    lstm_det = LSTMAnomalyDetector()
    print(f"  Device: {lstm_det.device}")
    lstm_det.fit(feat_normal, epochs=60, batch_size=128, verbose=True)

    print()
    print("=" * 70)
    print("STEP 4: Train Phase 1 (Isolation Forest) for comparison")
    print("=" * 70)
    # Retrain from the same normal data so both comparisons are identical in
    # inputs and not dependent on which model was last saved to disk.
    iso_det = CANAnomalyDetector(contamination=0.05)
    iso_det.fit(feat_normal)
    have_iso = True
    print("  Phase 1 model ready.")

    print()
    print("=" * 70)
    print("STEP 5: Evaluate & compare")
    print("=" * 70)

    COL = 12
    W = 10
    print(f"  {'Attack':<{COL}}  {'Phase 1 — Isolation Forest':^{W*3+4}}  {'Phase 2 — LSTM Autoencoder':^{W*3+4}}")
    print(f"  {'':^{COL}}  {'Precision':>{W}} {'Recall':>{W}} {'F1':>{W}}  {'Precision':>{W}} {'Recall':>{W}} {'F1':>{W}}")
    print(f"  {'-'*COL}  {'-'*(W*3+4)}  {'-'*(W*3+4)}")

    for mode, feat in attack_feats.items():
        p2, r2, f2 = _metrics(lstm_det, feat)
        if have_iso:
            p1, r1, f1 = _metrics(iso_det, feat)
            print(f"  {mode.upper():<{COL}}  {p1:>{W}.3f} {r1:>{W}.3f} {f1:>{W}.3f}  {p2:>{W}.3f} {r2:>{W}.3f} {f2:>{W}.3f}")
        else:
            print(f"  {mode.upper():<{COL}}  {'N/A':>{W}} {'N/A':>{W}} {'N/A':>{W}}  {p2:>{W}.3f} {r2:>{W}.3f} {f2:>{W}.3f}")

    print()
    print("=" * 70)
    print("STEP 6: Explainability demo on sample flagged windows")
    print("=" * 70)
    for mode, feat in attack_feats.items():
        result = lstm_det.predict(feat)
        flagged = result[result["is_anomaly"] == 1]
        if flagged.empty:
            print(f"\n  {mode.upper()}: no windows flagged (threshold may need tuning)")
            continue
        sample = flagged.iloc[len(flagged) // 2]
        expl = lstm_det.explain(sample, top_k=3)
        atype = lstm_det.classify_attack_type(sample)
        true_label = "attack" if sample["label"] == 1 else "normal"
        print(f"\n  {mode.upper()} — CAN_ID={sample['CAN_ID']}  true_label={true_label}")
        print(f"    Classified as : {atype}")
        print(f"    Anomaly score : {sample['anomaly_score']:.5f}  confidence: {sample['confidence']:.3f}")
        print(f"    Explanation:")
        for r in expl["reasons"]:
            print(f"      - {r}")

    print()
    print("=" * 70)
    print("STEP 7: Save LSTM model")
    print("=" * 70)
    os.makedirs(MODEL_DIR, exist_ok=True)
    lstm_det.save(f"{MODEL_DIR}/can_lstm_baseline")
    print(f"  Saved to {MODEL_DIR}/can_lstm_baseline_lstm*")

    print(f"\nTotal runtime: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
