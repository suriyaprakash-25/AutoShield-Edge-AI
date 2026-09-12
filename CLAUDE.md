# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

AutoShield Edge AI is a CAN bus (in-vehicle network) intrusion detection + autonomous
response system, built as a competition/POC project. It has two parallel implementations
of the **same** detection pipeline:

1. **Python (`src/`)** — the canonical, validated implementation. Trains a real
   IsolationForest, runs offline evaluation against labeled attack data.
2. **JS (`dashboard/`)** — a *faithful port* of the Python logic that runs entirely
   client-side (React + Vite + D3) for a portable, backend-free live demo. The
   IsolationForest is replaced by a calibrated rule-based scorer using the same
   z-score logic.

When you change detection behavior, the two implementations must stay in sync. The
JS side is the port and follows the Python side, not the other way around.

## Commands

### Python pipeline (`src/`)
No requirements file exists; deps are `numpy`, `pandas`, `scikit-learn`, `joblib`, `torch`.
Run from inside `src/` (scripts use relative paths like `../data`, `../models`).

```bash
cd src
# 1. Generate synthetic datasets (one per attack mode)
python generate_dataset.py --output ../data/can_normal.csv --mode normal --duration 120
python generate_dataset.py --output ../data/can_dos.csv   --mode dos   --duration 60
python generate_dataset.py --output ../data/can_fuzzy.csv --mode fuzzy --duration 60
python generate_dataset.py --output ../data/can_spoof.csv --mode spoof --duration 60

# 2a. Phase 1 — train + evaluate Isolation Forest, save to ../models/can_isoforest_baseline_*
python train_baseline.py

# 2b. Phase 2 — train + evaluate LSTM-AE, print Phase 1 vs Phase 2 comparison, save to ../models/can_lstm_baseline_*
python train_lstm.py       # ~45s on CPU, faster with CUDA

# 3. End-to-end detection -> response test (plain script, NOT pytest)
python test_response_engine.py
```

### Dashboard (`dashboard/`)
```bash
cd dashboard
npm install
npm run dev      # vite dev server, ~http://localhost:5173
npm run build    # production build -> dist/
npm run lint     # oxlint (react + oxc plugins)

# Validation harness — run after ANY change to dashboard/src/lib/
node src/lib/__test__/validate.mjs
```

The JS validation script asserts the port still matches the Python recall/precision
results. Per the dashboard README it has already caught two real porting bugs; treat a
failing run as a blocker, not a flake.

## Architecture

The pipeline is a four-stage chain. The same staging exists in both `src/*.py` and
`dashboard/src/lib/*.js`:

1. **Feature extraction** (`feature_extraction.py` / `featureExtraction.js`)
   Slides a fixed 200ms window over the CAN log and emits one feature row **per
   (window × CAN_ID)** — never per-window-global. This per-ID granularity is the
   central design decision: a flood on one ID must not mask a separate spoof of
   another ID in the same window.

2. **Baseline profiling** — `build_baseline_profile` learns per-CAN_ID normal stats
   (mean/std inter-arrival time, payload entropy) from clean traffic. Every later
   window is z-scored against *its own ID's* baseline (`iat_zscore`,
   `entropy_zscore`), not a global pooled average. std values are floored
   (`min_std_iat`, `min_std_entropy`) to avoid div-by-near-zero exploding harmless
   noise into huge z-scores.

3. **Detection + explainability** (`detector.py` / `lstm_detector.py` / `detector.js`)
   Two interchangeable detectors with identical external interfaces (`fit`, `predict`,
   `explain`, `classify_attack_type`, `save`, `load`):
   - **Phase 1 — IsolationForest** (`detector.py` / `CANAnomalyDetector`): per-window
     scoring. `confidence` calibrated via percentile mapping against normal-traffic scores.
   - **Phase 2 — LSTM-Autoencoder** (`lstm_detector.py` / `LSTMAnomalyDetector`):
     sequence scoring — 10 × 200ms windows (2s context) per CAN_ID. `anomaly_score` is
     reconstruction MSE (higher = worse, opposite sign from IsoForest). Adds
     `predict_stream()` for real-time per-window inference. `explain()` is identical to
     Phase 1 (same feature z-score attribution logic, same human-readable reason strings).
   Both use the same rule-based `classify_attack_type()` for DoS / Fuzzy / Spoofing labels.

4. **Response engine** (`response_engine.py` / `responseEngine.js`)
   Turns detections into isolation decisions. Key logic that must be preserved when
   editing: **debounce** (N consecutive flagged windows for the same ID before
   isolating), confidence+severity gating, **bus-congestion suppression** (when the
   whole bus is saturated, innocent ECUs' per-ID stats become collateral noise — do
   not isolate them), and **fuzzy-burst aggregation** (collapse hundreds of new-ID
   isolations into one incident).

### Critical invariants (these encode hard-won bug fixes — see code comments)

- **Per-ID vs bus-wide features.** `unique_ids_in_window` / `total_msgs_in_window` are
  bus-wide signals shared by *every* ID active in a window; during an attack they go
  extreme for innocent IDs too. They are deliberately excluded from the per-ID severity
  decision. Only per-ID signals justify isolating a specific ID.
- **Don't double-z-score.** `iat_zscore` / `entropy_zscore` are *already* per-ID
  z-scores. `explain()` uses their raw value directly and must not z-score them again
  against the global distribution. Likewise `mean_iat` / `mean_entropy` are raw per-ID-
  scaled values excluded from global attribution.
- **IAT across window boundaries.** Low-frequency IDs may fire once per several 200ms
  windows; `last_seen_ts` persists across windows so their true inter-arrival time is
  measurable. Don't reset it per window.
- `FEATURE_COLUMNS` in `feature_extraction.py` is the contract between extraction,
  training, and the saved `models/*_meta.json`. Changing it invalidates saved models.

## Data & models

- `data/can_{normal,dos,fuzzy,spoof}.csv` — HCRL Car Hacking Dataset schema
  (`Timestamp, CAN_ID, DLC, DATA0-7, Flag`); `Flag == "T"` marks an injected frame.
  Currently **synthetic** (generated by `generate_dataset.py`). The schema matches the
  real HCRL dataset exactly, so swapping in real data is a path change in
  `train_baseline.py`, not a rewrite.
- `models/can_isoforest_baseline_{isoforest,scaler}.joblib` + `_meta.json` — saved Phase 1
  model, scaler, and per-feature train means/stds used for explainability. The meta.json
  also stores `normal_score_p50`/`normal_score_p01` needed by `_score_to_confidence()`; a
  model saved before this fix will have those keys as `null` and must be retrained.
- `models/can_lstm_baseline_{lstm.pt,lstm_scaler.joblib,lstm_meta.json}` — saved Phase 2
  model. The meta includes `recon_threshold` (p99 of normal MSE), `normal_p50`, `normal_p99`.
- The dashboard reads the same CSVs from `dashboard/public/data/`.

## Project status

Synthetic data only; `vcan`/`python-can` live replay and real hardware (Pi/Jetson)
deployment are not yet wired up. Recall is prioritized over precision by design
(missing an attack is worse than a tunable false alarm). See `README.md` and
`dashboard/README.md` for the full build order, validated metrics, and known limitations.
