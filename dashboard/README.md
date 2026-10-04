# AutoShield Edge AI — Dashboard

A standalone React dashboard demonstrating live CAN bus intrusion detection,
autonomous response, and the vehicle cyber digital twin — runs entirely
client-side, no backend required (good for a portable laptop demo with no
internet dependency).

## What this is

This is a **faithful JS port** of the validated Python detection pipeline
(`../src/detector.py`, `../src/feature_extraction.py`, `../src/response_engine.py`),
not a separate reimplementation. Same sliding-window features, same per-ID
baseline z-scoring, same severity/confidence gating, same bus-congestion
suppression and fuzzy-burst aggregation logic that were debugged and
validated in Python.

**Why a separate JS port instead of running the trained Python model
in-browser:** the dashboard needs to run standalone with zero backend
dependency so the demo works on any laptop without a Python server —
important for a live jury presentation where you don't want a server
process to depend on. The underlying IsolationForest is replaced with a
calibrated rule-based scorer using the same z-score logic; see
`src/lib/detector.js` header comment for the full rationale.

**Validated to match (and in this case, slightly exceed) the Python
results** — run `node src/lib/__test__/validate.mjs` to reproduce:

| Attack | Recall | Precision | False-positive isolations |
|---|---|---|---|
| DoS | 1.00 | 0.94 | None |
| Fuzzy | 1.00 | 1.00 | None (isolates only genuinely-injected IDs) |
| Spoofing | 1.00 | 0.98 | None |

If you change the detection logic in `src/lib/`, **re-run this validation
script** before trusting the dashboard for a demo — it caught two real bugs
during development (a missing sort-before-slice equivalent issue, and a
global-z-scoring bug on `stdIat` that has per-ID-dependent natural scale).

## Design

Dark, instrument-panel aesthetic — signal cyan for healthy, amber for
suspicious, red for isolated/attacking. Monospace (IBM Plex Mono) for all
telemetry data, Inter for UI labels. The network topology graph (the
"digital twin") is the signature element: a real spoke-and-gateway layout
matching actual CAN bus topology, not a generic force-directed graph, with
nodes that pulse red the instant their ECU gets isolated.

## Running it

```bash
npm install
npm run dev      # development server with hot reload
npm run build    # production build -> dist/
npm run preview  # serve the production build locally
```

Open the printed local URL (typically `http://localhost:5173`).

## Using the demo

1. Select an attack scenario (DoS / Fuzzy / Spoofing) from the control bar
2. Press Play — CAN frames replay in real time, grouped into 200ms windows
3. Watch the digital twin: the attacking ECU's node turns amber (suspicious)
   then red (isolated) within ~2-3 windows, pulsing on the frame it's caught
4. The incident log on the right shows the explainability reasons for every
   detection — this is what to walk the jury through during Q&A
5. Adjust playback speed with the slider; Reset clears all state and starts
   the scenario over

## Known limitations (same as the Python side)

- Running on synthetic, schema-accurate data — swap in the real HCRL
  dataset before the actual POC demo (see main README)
- This is a software simulation of the response engine's isolation
  decisions; it does not yet drive a real CAN transceiver or gateway ECU.
  That hardware integration is a separate step (`vcan` + `python-can` on a
  Pi/Jetson) — see the main project README's "Next steps".

## File structure

```
src/
  lib/
    featureExtraction.js   — sliding-window feature extraction (JS port)
    detector.js             — severity/confidence scoring (JS port)
    responseEngine.js       — isolation decisions + incident aggregation (JS port)
    __test__/validate.mjs   — validation harness, run with `node` directly
  data/
    loadCanData.js          — CSV loading + ECU name lookup
  components/
    NetworkTopology.jsx     — the digital twin (D3)
    TrafficFeed.jsx         — live scrolling CAN frame feed
    IncidentLog.jsx         — explainability + incident history
    StatusBar.jsx           — top status bar
    ControlPanel.jsx        — scenario selection + playback controls
  App.jsx                   — simulation loop, wires everything together
public/data/                — the four CAN CSV datasets (bundled statically)
```
