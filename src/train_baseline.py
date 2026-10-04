"""
AutoShield Edge AI — Train & Evaluate Phase 1 (Isolation Forest)
===================================================================
1. Loads normal traffic, builds baseline profile
2. Extracts features from normal + all 3 attack datasets
3. Trains Isolation Forest on normal-only features (true unsupervised setup)
4. Evaluates against each attack type with precision/recall/F1
5. Demonstrates the explainability + attack classification layer on
   a handful of real flagged windows
6. Saves the trained model + metadata to ../models/
"""

import sys
import time

sys.path.insert(0, ".")

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from feature_extraction import (
    FEATURE_COLUMNS,
    build_baseline_profile,
    extract_window_features,
    load_can_csv,
)
from detector import CANAnomalyDetector

DATA_DIR = "../data"
MODEL_DIR = "../models"


def main():
    t0 = time.time()
    print("=" * 70)
    print("STEP 1: Load normal traffic and build per-ID baseline profile")
    print("=" * 70)
    df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
    profile, known_ids = build_baseline_profile(df_normal)
    print(f"Loaded {len(df_normal)} normal frames, {len(known_ids)} known ECU IDs")

    print()
    print("=" * 70)
    print("STEP 2: Extract sliding-window features")
    print("=" * 70)
    feat_normal = extract_window_features(df_normal, window_ms=200, baseline_profile=profile, known_ids=known_ids)
    print(f"Normal: {len(feat_normal)} feature rows")

    attack_feats = {}
    for mode in ["dos", "fuzzy", "spoof"]:
        df_attack = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
        feat = extract_window_features(df_attack, window_ms=200, baseline_profile=profile, known_ids=known_ids)
        attack_feats[mode] = feat
        print(f"{mode}: {len(feat)} feature rows, {feat['label'].sum()} labeled attack windows")

    print()
    print("=" * 70)
    print("STEP 3: Train Isolation Forest on NORMAL traffic only (unsupervised)")
    print("=" * 70)
    detector = CANAnomalyDetector(contamination=0.05)
    detector.fit(feat_normal)
    print("Model trained.")

    print()
    print("=" * 70)
    print("STEP 4: Evaluate against each attack type")
    print("=" * 70)
    for mode, feat in attack_feats.items():
        result = detector.predict(feat)
        y_true = result["label"]
        y_pred = result["is_anomaly"]
        print(f"\n--- {mode.upper()} ---")
        print(confusion_matrix(y_true, y_pred))
        print(classification_report(y_true, y_pred, target_names=["normal", "attack"], zero_division=0))

    print()
    print("=" * 70)
    print("STEP 5: Explainability + attack classification demo (sample flagged windows)")
    print("=" * 70)
    for mode, feat in attack_feats.items():
        result = detector.predict(feat)
        flagged = result[result["is_anomaly"] == 1]
        if flagged.empty:
            print(f"\n{mode.upper()}: no windows flagged")
            continue
        sample = flagged.iloc[len(flagged) // 2]  # a representative flagged window
        explanation = detector.explain(sample, top_k=3)
        attack_type = detector.classify_attack_type(sample)
        print(f"\n{mode.upper()} — sample flagged window (CAN_ID={sample['CAN_ID']}, true_label={'attack' if sample['label']==1 else 'normal'}):")
        print(f"  Classified as: {attack_type}")
        print(f"  Explanation:")
        for r in explanation["reasons"]:
            print(f"    - {r}")

    print()
    print("=" * 70)
    print("STEP 6: Save model")
    print("=" * 70)
    import os
    os.makedirs(MODEL_DIR, exist_ok=True)
    detector.save(f"{MODEL_DIR}/can_isoforest_baseline")
    print(f"Saved to {MODEL_DIR}/can_isoforest_baseline_*")

    print(f"\nTotal runtime: {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
