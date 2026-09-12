"""
Validate that the live FastAPI backend (ws://localhost:8001/ws/stream) produces
the same isolation counts as the validated offline test path after the attribution
gate was wired into ResponseEngine.

Expected results (from full_re_test_attributed.py, baseline model, entropy+attribution gates):
  DoS:   FP isolations=3,   FP IDs=2   (0690×2, 00A0×1)   TP: 0000 isolated
  Fuzzy: FP isolations=16,  FP IDs=4                        TP: new IDs isolated
  Spoof: FP isolations=0,   FP IDs=0                        TP: 0316, 043F isolated

Note: live mode uses the Ensemble model (IsoForest + LSTM-AE), which may produce
slightly different raw detection numbers than the baseline-only IsoForest used in the
offline tests.  We report exact live-mode counts and flag any unexpected FP isolations.

Run from src/:  python validate_live_attribution.py
"""
import asyncio
import json
import sys

try:
    import websockets
except ImportError:
    print("ERROR: pip install websockets")
    sys.exit(1)

WS_URL = "ws://localhost:8001/ws/stream"
SPEED  = 200   # max speed — minimises wall-clock time

KNOWN_IDS = {
    "0316", "018F", "0260", "02A0", "0329",
    "0153", "043F", "05A0", "0220", "04B1",
}

TRUE_ATTACKERS = {
    "dos":   {"0000"},
    "fuzzy": None,   # anything not in KNOWN_IDS
    "spoof": {"0316", "043F"},
}


async def run_scenario(scenario: str) -> dict:
    """
    Stream one scenario end-to-end and return a dict of {canId: isolation_event_count}.
    """
    isolation_events: dict[str, int] = {}
    new_ids_seen: set[str] = set()

    async with websockets.connect(
        WS_URL,
        max_size=8 * 1024 * 1024,
        ping_interval=None,   # server is in a streaming loop and can't answer pings
        ping_timeout=None,
    ) as ws:
        await ws.send(json.dumps({"cmd": "start", "scenario": scenario, "speed": SPEED}))

        async for raw in ws:
            msg = json.loads(raw)
            t = msg.get("type")

            if t == "ready":
                print(f"  [{scenario}] ready — {msg.get('totalWindows', '?')} windows  model={msg.get('modelType','?')}")

            elif t == "window_result":
                for inc in msg.get("incidents", []):
                    cid = inc.get("canId", "")
                    action = inc.get("actionTaken", "")
                    # Count each isolation incident (action contains "Isolated")
                    if "isol" in action.lower():
                        isolation_events[cid] = isolation_events.get(cid, 0) + 1
                # Track new IDs from network state (for fuzzy TP identification)
                ns = msg.get("networkState", {})
                for cid, status in ns.items():
                    if cid not in KNOWN_IDS:
                        new_ids_seen.add(cid)

            elif t == "done":
                break

            elif t == "error":
                print(f"  [{scenario}] BACKEND ERROR: {msg.get('message')}")
                break

    return isolation_events, new_ids_seen


async def main():
    print(f"Connecting to {WS_URL} at speed={SPEED}x\n")

    results = {}
    for scenario in ["dos", "fuzzy", "spoof"]:
        print(f"Running {scenario.upper()}...")
        isolation_events, new_ids_seen = await run_scenario(scenario)
        results[scenario] = (isolation_events, new_ids_seen)
        print(f"  [{scenario}] done — {len(isolation_events)} distinct IDs isolated")
        for cid, cnt in sorted(isolation_events.items(), key=lambda x: -x[1]):
            tag = "?"
            ta = TRUE_ATTACKERS[scenario]
            if scenario == "fuzzy":
                tag = "TP" if cid not in KNOWN_IDS else "FP"
            elif ta and cid in ta:
                tag = "TP"
            else:
                tag = "FP"
            print(f"    [{tag}] {cid}: {cnt} isolation events")
        print()

    # ── Summary ──────────────────────────────────────────────────────────────────
    print("=" * 68)
    print("SUMMARY  (compare against validated offline: DoS=3FP, Fuzzy=16FP, Spoof=0FP)")
    print("=" * 68)
    print(f"{'Scenario':<8}  {'TP isolations':>14}  {'FP isolations':>14}  {'FP IDs':>7}")
    print("-" * 50)
    for scenario in ["dos", "fuzzy", "spoof"]:
        iso, new_ids = results[scenario]
        ta = TRUE_ATTACKERS[scenario]
        if scenario == "fuzzy":
            tp_iso = {cid: c for cid, c in iso.items() if cid not in KNOWN_IDS}
            fp_iso = {cid: c for cid, c in iso.items() if cid in KNOWN_IDS}
        else:
            tp_iso = {cid: c for cid, c in iso.items() if ta and cid in ta}
            fp_iso = {cid: c for cid, c in iso.items() if not ta or cid not in ta}
        tp_cnt = sum(tp_iso.values())
        fp_cnt = sum(fp_iso.values())
        fp_ids = len(fp_iso)
        print(f"{scenario.upper():<8}  {tp_cnt:>14,}  {fp_cnt:>14,}  {fp_ids:>7}")

    print("\nDone.")


asyncio.run(main())
