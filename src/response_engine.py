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

# ── Isolation cooldown policy ─────────────────────────────────────────────────
# How many 200ms windows an isolated ECU stays blocked before becoming eligible
# for automatic re-evaluation.
#
# Short cooldown (e.g. 50 windows = 10 s): lets a falsely-isolated ECU
# auto-recover once the anomaly clears — preferable when false-positive cost
# is high (safety-critical ECU, reversible firmware bug, brief bus noise).
#
# Long cooldown (ISOLATION_COOLDOWN_WINDOWS = 10000 windows ≈ 33 min): keeps a
# confirmed persistent attacker isolated for the full demo or monitoring session
# — right for a sustained DoS or spoofing flood where releasing the attacker
# after 10 s just re-admits the same source.  Tune downward for deployments
# where ECU firmware resets are cheap and short-lived anomalies are common.
ISOLATION_COOLDOWN_WINDOWS = 10_000


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
    def __init__(self, debounce_threshold=2, isolation_cooldown_windows=ISOLATION_COOLDOWN_WINDOWS, min_isolation_confidence=0.6,
                 fuzzy_burst_window_s=2.0, fuzzy_burst_threshold=5,
                 normal_id_ratio=None, attribution_ratio_mult=3.0):
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
        normal_id_ratio: dict {CAN_ID: mean msg_count_ratio in normal traffic}.
            When provided, enables the two-stage attribution gate for known IDs:
            a known ECU whose msg_count_ratio is not > attribution_ratio_mult ×
            its normal share is classified as collateral noise (victim of someone
            else's flood) rather than an attacker, and skips isolation. New IDs
            (is_new_id=1) are always attributed by definition. Pass None to
            disable (backward compatible).
        attribution_ratio_mult: threshold multiplier for the attribution gate.
            Premise verified: at 3× the attacker is in the source set 100% of
            the time (DoS/Fuzzy), innocents are excluded 97-99% of the time,
            and 0% of attack windows have no attributed source.
        """
        self.debounce_threshold = debounce_threshold
        self.isolation_cooldown_windows = isolation_cooldown_windows
        self.min_isolation_confidence = min_isolation_confidence
        self.fuzzy_burst_window_s = fuzzy_burst_window_s
        self.fuzzy_burst_threshold = fuzzy_burst_threshold
        self._normal_id_ratio = normal_id_ratio  # {CAN_ID: mean msg_count_ratio in normal}
        self._attribution_ratio_mult = attribution_ratio_mult

        self._consecutive_flags = defaultdict(int)
        self.isolated_ids = {}  # can_id -> windows_remaining
        self.incident_log = []
        self.ecu_status = {}  # can_id -> "normal" | "suspicious" | "isolated"
        self._last_decay_window = None  # guard: decay runs once per real window, not per row

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
        window_start = float(row["window_start"])

        # Decay isolation cooldowns once per real 200ms window, not per row.
        # Without this guard the cooldown burns through N_IDs-per-window times
        # as fast as intended, de-isolating the attacker after ~2 windows instead of 50.
        if window_start != self._last_decay_window:
            self._last_decay_window = window_start
            for cid in list(self.isolated_ids.keys()):
                self.isolated_ids[cid] -= 1
            expired = [cid for cid, remaining in self.isolated_ids.items() if remaining <= 0]
            for cid in expired:
                del self.isolated_ids[cid]
                self.ecu_status[cid] = "normal"

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

        # ── Two-stage design: detection flags, attribution decides ───────────────
        # Reaching here means the anomaly model flagged this ID (Stage 1 passed).
        # That is necessary but NOT sufficient for isolation — isolation is a
        # destructive, autonomous action that removes an ECU from the bus if wrong.
        # The gates below form Stage 2 (attribution): each can return a
        # "flagged-but-protected" action (suspicious / collateral / entropy-drift)
        # instead of pulling the isolation trigger.
        #
        # Concretely: during a Fuzzy or DoS flood, innocent known ECUs are
        # perturbed by bus contention and pass Stage 1, but the attribution gate
        # (msg_count_ratio vs baseline) recognises they are not generating the
        # flood — they exit here as "collateral", not isolated.  This is why
        # the Fuzzy scenario shows ~155 flagged windows but only a handful of IDs
        # actually isolated: the detector sees anomalies everywhere; attribution
        # pins responsibility only to the true source(s).
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

        # Entropy-drift suppression gate:
        # Real spoof/DoS/fuzzy attacks on known ECUs are detected via
        # msg_count_ratio and IAT changes. A known ECU with |entropy_z|>10
        # but normal IAT (|iat_z|<3) is almost certainly a cross-session
        # baseline calibration artifact — a constant-payload ECU that sends
        # different fixed values across recording sessions, not an attacker.
        # Data: true Spoof attackers (0316, 043F) have max |entropy_z|=2.83
        # across 10,783 TP windows; 04B1 FPs have |entropy_z|=14.37 pinned
        # constant. The 11.54-wide gap (2.83 to 14.37) makes threshold=10
        # safe: 7.17 margin from nearest TP, 4.37 margin from the FP floor.
        # Gate does not fire for new IDs (handled by is_new_id path) or when
        # IAT is also anomalous (co-occurring IAT+entropy is a real signal).
        if not is_never_seen_id:
            entropy_z = abs(float(row.get("entropy_zscore", 0.0)))
            iat_z     = abs(float(row.get("iat_zscore", 0.0)))
            if entropy_z > 10.0 and iat_z < 3.0:
                self._consecutive_flags[can_id] = 0
                self.ecu_status[can_id] = "suspicious"
                return "flagged_entropy_drift", None

        # Two-stage attribution gate for known IDs:
        # During a bus flood (DoS single-ID, Fuzzy multi-ID burst), every
        # innocent ECU on the bus gets its timing/combination stats distorted
        # by contention — they appear anomalous but are structurally victims,
        # not attackers. A known ECU whose msg_count_ratio is NOT > MULT times
        # its normal share is not itself generating the flood; isolating it
        # misattributes congestion side-effects as misbehavior.
        # Premise verified: attackers (0000/new IDs) are in the attributed-source
        # set 100% of the time; 97-99% of innocent FP windows are excluded; 0%
        # of attack windows have no attributed source at 3× threshold.
        if not is_never_seen_id and self._normal_id_ratio is not None:
            baseline = self._normal_id_ratio.get(can_id, 0.0)
            current_ratio = float(row.get("msg_count_ratio", 0.0))
            if baseline > 0 and current_ratio <= self._attribution_ratio_mult * baseline:
                self._consecutive_flags[can_id] = 0
                self.ecu_status[can_id] = "collateral"
                return "flagged_collateral", None

        self._consecutive_flags[can_id] += 1
        self.ecu_status[can_id] = "suspicious"

        if self._consecutive_flags[can_id] >= self.debounce_threshold:
            # ISOLATE
            self.isolated_ids[can_id] = self.isolation_cooldown_windows
            self.ecu_status[can_id] = "isolated"
            self._consecutive_flags[can_id] = 0
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
                action_taken=f"Isolated ECU {can_id}; blocking all further frames from this ID",
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
