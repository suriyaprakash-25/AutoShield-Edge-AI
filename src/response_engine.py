"""
AutoShield Edge AI — Autonomous Response Engine
==================================================
This is what moves the system from DETECTION to PREVENTION.

What it actually does (and what it honestly does NOT do — see notes below):

1. ECU Isolation — once a CAN_ID is flagged as the source of an attack in
   consecutive windows (not a single blip), it's marked "isolated" in the
   system's internal state. Frames from an isolated ID are no longer
   forwarded to the rest of the pipeline (simulating a gateway dropping them).

2. Frame blocking — concretely: incoming frames from an isolated ID are
   logged but excluded from forwarded/"trusted" traffic. On real CAN
   hardware this maps to a gateway ECU or a CAN transceiver in listen-only
   mode refusing to relay frames from that arbitration ID — we simulate
   that decision in software here, which is the honest framing for a
   software-only / vcan-based demo.

3. Incident report generation — structured, timestamped record of what
   happened: attack type, source ID, detection confidence, action taken.
   This is cheap to build and high-value for the "product" feel of a demo.

WHAT THIS DELIBERATELY DOES NOT CLAIM:
- "Changes communication routes" — dropped from the original feature list.
  CAN bus is a broadcast bus, not a routable network; there is no path to
  reroute traffic onto, so this claim doesn't hold up under a technical
  Q&A and is intentionally not implemented or claimed here.
- Real-world ECU isolation would require integration with an actual gateway
  ECU or CAN transceiver firmware — this engine demonstrates the DECISION
  LOGIC (when/why/what to isolate), which is the part that's genuinely
  novel and demoable; the physical bus-level enforcement is a hardware
  integration step that depends on your specific demo rig.

Debounce logic (why isolation isn't instant on one flagged window):
A single anomalous window could be sensor noise rather than a real attack.
Requiring N consecutive flagged windows for the SAME CAN_ID before isolating
is both more realistic and a better story for judges: it shows you've
thought about false-positive cost, not just raw detection.
"""

import json
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Incident:
    incident_id: str
    timestamp: str
    can_id: str
    attack_type: str
    confidence: float
    reasons: list
    action_taken: str
    window_start: float

    def to_dict(self):
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "can_id": self.can_id,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "action_taken": self.action_taken,
            "window_start": self.window_start,
        }


class ResponseEngine:
    def __init__(self, debounce_threshold=2, isolation_cooldown_windows=50, min_isolation_confidence=0.6,
                 fuzzy_burst_window_s=2.0, fuzzy_burst_threshold=5):
        """
        debounce_threshold: number of CONSECUTIVE flagged windows for the
            same CAN_ID required before triggering isolation (noise filter)
        isolation_cooldown_windows: how many windows an ID stays isolated
            before being eligible for automatic re-evaluation (simulates
            a "recovery" period rather than permanent ban, which is a more
            realistic and defensible design than a one-way kill switch)
        min_isolation_confidence: an ID must have calibrated confidence >=
            this value before it's even eligible for isolation. WHY THIS
            MATTERS: during a real attack (e.g. a DoS flood on one ID),
            bus congestion mildly perturbs OTHER, innocent IDs' timing and
            entropy stats too -- they get flagged as low-confidence anomalies
            as collateral noise. Without this gate, the engine would isolate
            innocent ECUs alongside the real attacker, which is both wrong
            and a believability risk in a jury demo. Only high-confidence
            signals (the actual attacking ID) cross this bar.
        fuzzy_burst_window_s / fuzzy_burst_threshold: a fuzzy attack
            legitimately triggers isolation on every distinct random ID it
            injects -- potentially thousands per minute. Reporting each as
            its own incident is both technically correct AND useless for a
            human/dashboard. When isolations of NEW, NEVER-SEEN ids happen
            faster than fuzzy_burst_threshold within fuzzy_burst_window_s,
            we collapse them into one aggregated "Fuzzing attack in
            progress" incident instead of one row per ID.
        """
        self.debounce_threshold = debounce_threshold
        self.isolation_cooldown_windows = isolation_cooldown_windows
        self.min_isolation_confidence = min_isolation_confidence
        self.fuzzy_burst_window_s = fuzzy_burst_window_s
        self.fuzzy_burst_threshold = fuzzy_burst_threshold

        self._consecutive_flags = defaultdict(int)
        self.isolated_ids = {}  # can_id -> windows_remaining
        self.incident_log = []
        self.ecu_status = {}  # can_id -> "normal" | "suspicious" | "isolated"

        # fuzzy-burst aggregation state
        self._recent_new_id_isolations = deque()  # (window_start, can_id)
        self._active_fuzzy_incident = None  # the aggregated Incident currently being updated, or None

    def _now_iso(self):
        return datetime.now(timezone.utc).isoformat()

    def process_window_result(self, row, explanation, attack_type):
        """
        Call this once per (window, CAN_ID) prediction result.
        row: a pandas Series / dict with at least 'CAN_ID', 'is_anomaly',
             'anomaly_score', 'window_start'
        explanation: output of detector.explain(row)
        attack_type: output of detector.classify_attack_type(row)

        Returns: (action_taken: str, incident: Incident | None)
        """
        can_id = row["CAN_ID"]
        is_anomaly = bool(row["is_anomaly"])

        # decay isolation cooldowns each call (simulates time passing)
        expired = [cid for cid, remaining in self.isolated_ids.items() if remaining <= 0]
        for cid in expired:
            del self.isolated_ids[cid]
            self.ecu_status[cid] = "normal"

        for cid in list(self.isolated_ids.keys()):
            self.isolated_ids[cid] -= 1

        if can_id in self.isolated_ids:
            # already isolated -- frame is dropped, no new incident needed
            return "dropped_isolated", None

        if not is_anomaly:
            self._consecutive_flags[can_id] = 0
            self.ecu_status[can_id] = self.ecu_status.get(can_id, "normal")
            if self.ecu_status[can_id] == "suspicious":
                self.ecu_status[can_id] = "normal"  # recovered before isolation threshold
            return "forwarded", None

        # anomalous window for this ID
        confidence = float(row.get("confidence", 0.0))
        is_severe = explanation.get("is_severe", True)  # default True for backward compat
        bus_under_congestion = explanation.get("bus_under_congestion", False)
        is_never_seen_id = bool(row.get("is_new_id", 0))

        if bus_under_congestion and not is_never_seen_id:
            # The whole bus is saturated (e.g. mid-fuzzing-burst) and this
            # is a KNOWN, legitimate ECU -- its own timing/payload deviation
            # is most likely collateral noise from bus contention caused by
            # someone else's attack, not genuine misbehavior. We track it as
            # suspicious for dashboard visibility but do not isolate it: a
            # known ECU should not be treated as the attacker just because
            # the bus around it is currently hostile.
            self.ecu_status[can_id] = "suspicious"
            return "flagged_bus_congestion", None

        if confidence < self.min_isolation_confidence or not is_severe:
            # Flagged by the model, but not confidently AND severely enough
            # to act on. is_severe specifically filters out cases where the
            # model's anomaly score comes from an unusual COMBINATION of
            # individually-mild feature deviations (e.g. several |z|<2
            # values lining up) rather than one clearly severe signal
            # (e.g. a never-seen CAN ID, or a >3 sigma deviation). This is
            # the gate that prevents acting on statistically-real-but-weak
            # evidence, which matters for a system that takes autonomous
            # action, not just a passive alert.
            self.ecu_status[can_id] = "suspicious"
            return "flagged_low_confidence", None

        self._consecutive_flags[can_id] += 1
        self.ecu_status[can_id] = "suspicious"

        if self._consecutive_flags[can_id] >= self.debounce_threshold:
            # ISOLATE
            self.isolated_ids[can_id] = self.isolation_cooldown_windows
            self.ecu_status[can_id] = "isolated"
            self._consecutive_flags[can_id] = 0
            window_start = float(row["window_start"])
            is_never_seen_id = bool(row.get("is_new_id", 0))

            if is_never_seen_id:
                # Track this isolation in the burst window and check if
                # we're in a fuzzy-attack burst (many distinct new IDs
                # isolated in rapid succession).
                self._recent_new_id_isolations.append((window_start, can_id))
                while (self._recent_new_id_isolations and
                       window_start - self._recent_new_id_isolations[0][0] > self.fuzzy_burst_window_s):
                    self._recent_new_id_isolations.popleft()

                if len(self._recent_new_id_isolations) >= self.fuzzy_burst_threshold:
                    # We're in a burst -- aggregate instead of creating a new incident
                    burst_ids = [cid for _, cid in self._recent_new_id_isolations]
                    if self._active_fuzzy_incident is None:
                        self._active_fuzzy_incident = Incident(
                            incident_id=str(uuid.uuid4())[:8],
                            timestamp=self._now_iso(),
                            can_id=f"{len(set(burst_ids))} distinct IDs",
                            attack_type="Fuzzy Attack (aggregated)",
                            confidence=float(row.get("confidence", 0.0)),
                            reasons=["High-rate injection of never-seen CAN IDs", "Likely fuzzing attack in progress"],
                            action_taken=f"Isolating each injected ID on detection; {len(set(burst_ids))} unique IDs blocked so far",
                            window_start=window_start,
                        )
                        self.incident_log.append(self._active_fuzzy_incident)
                        return "isolated", self._active_fuzzy_incident
                    else:
                        # update the existing aggregated incident in place
                        self._active_fuzzy_incident.can_id = f"{len(set(burst_ids))} distinct IDs"
                        self._active_fuzzy_incident.action_taken = (
                            f"Isolating each injected ID on detection; {len(set(burst_ids))} unique IDs blocked so far"
                        )
                        return "isolated_aggregated", None

            # not part of a fuzzy burst -- normal individual incident
            incident = Incident(
                incident_id=str(uuid.uuid4())[:8],
                timestamp=self._now_iso(),
                can_id=can_id,
                attack_type=attack_type,
                confidence=round(confidence, 3),
                reasons=explanation["reasons"],
                action_taken=f"Isolated ECU {can_id}; blocking further frames for {self.isolation_cooldown_windows} windows",
                window_start=window_start,
            )
            self.incident_log.append(incident)
            return "isolated", incident

        return "flagged_monitoring", None

    def get_network_state(self, known_ids):
        """
        Returns a snapshot of every known ECU's current status, suitable
        for driving the live digital-twin visualization in the dashboard.
        """
        state = {}
        for can_id in known_ids:
            state[can_id] = self.ecu_status.get(can_id, "normal")
        # include any isolated/suspicious IDs not in known_ids (e.g. fuzzy-attack
        # injected IDs that were never part of the baseline)
        for can_id, status in self.ecu_status.items():
            state.setdefault(can_id, status)
        return state

    def export_incident_log(self, path=None):
        data = [i.to_dict() for i in self.incident_log]
        if path:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        return data
