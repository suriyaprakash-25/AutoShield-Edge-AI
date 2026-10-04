"""
End-to-end test: feed real attack feature windows through detector ->
response engine, in chronological order, and verify isolation actually
triggers and incidents are generated sensibly.
"""

import sys
sys.path.insert(0, ".")

from feature_extraction import load_can_csv, build_baseline_profile, extract_window_features
from detector import CANAnomalyDetector
from response_engine import ResponseEngine

DATA_DIR = "../data"


def run_scenario(mode):
    print(f"\n{'='*70}\nSCENARIO: {mode.upper()} attack\n{'='*70}")

    df_normal = load_can_csv(f"{DATA_DIR}/can_normal.csv")
    profile, known_ids = build_baseline_profile(df_normal)
    feat_normal = extract_window_features(df_normal, window_ms=200, baseline_profile=profile, known_ids=known_ids)

    detector = CANAnomalyDetector(contamination=0.05)
    detector.fit(feat_normal)

    df_attack = load_can_csv(f"{DATA_DIR}/can_{mode}.csv")
    feat_attack = extract_window_features(df_attack, window_ms=200, baseline_profile=profile, known_ids=known_ids)
    feat_attack = feat_attack.sort_values("window_start").reset_index(drop=True)

    result = detector.predict(feat_attack)

    # ground truth: which CAN_ID is the actual injected attacker for this scenario
    true_attacker_ids = {"dos": {"0000"}, "spoof": {"0316", "0329"}}.get(mode, None)  # fuzzy: many random IDs, no fixed set

    engine = ResponseEngine(debounce_threshold=2, isolation_cooldown_windows=50, min_isolation_confidence=0.6)

    action_counts = {}
    isolated_ids_seen = set()
    false_positive_isolations = []

    for _, row in result.iterrows():
        explanation = detector.explain(row, top_k=3) if row["is_anomaly"] else {"reasons": [], "is_severe": False}
        attack_type = detector.classify_attack_type(row) if row["is_anomaly"] else "Normal"
        action, incident = engine.process_window_result(row, explanation, attack_type)
        action_counts[action] = action_counts.get(action, 0) + 1
        if incident:
            isolated_ids_seen.add(incident.can_id)
            if true_attacker_ids is not None and incident.can_id not in true_attacker_ids:
                false_positive_isolations.append(incident.can_id)

    print(f"Action summary: {action_counts}")
    print(f"Unique IDs isolated: {sorted(isolated_ids_seen)}")
    if true_attacker_ids is not None:
        correctly_isolated = isolated_ids_seen & true_attacker_ids
        print(f"True attacker ID(s): {sorted(true_attacker_ids)} -- correctly isolated: {sorted(correctly_isolated)}")
        if false_positive_isolations:
            print(f"!! FALSE POSITIVE isolations (innocent IDs isolated): {sorted(set(false_positive_isolations))}")
        else:
            print("No false-positive isolations of innocent ECUs.")
    else:
        print(f"(fuzzy attack uses random IDs each run -- {len(isolated_ids_seen)} unique IDs isolated, expected since each is a genuine never-seen-ID injection)")
    print(f"Total incidents: {len(engine.incident_log)}")


if __name__ == "__main__":
    for mode in ["dos", "fuzzy", "spoof"]:
        run_scenario(mode)
