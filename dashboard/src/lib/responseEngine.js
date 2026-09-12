// AutoShield Edge AI — Response engine (JS port)
// Mirrors response_engine.py: debounce, confidence/severity gating,
// bus-congestion suppression, entropy-drift suppression, two-stage
// attribution gate, and fuzzy-burst aggregation.

// Isolation cooldown policy — see response_engine.py for full rationale.
// Short (e.g. 50 windows = 10 s): lets a falsely-isolated ECU auto-recover
// once the anomaly clears.  Long (10000 ≈ 33 min): keeps a confirmed
// persistent attacker isolated for the full demo session.  Tune downward when
// false-positive recovery cost matters more than sustained containment.
const ISOLATION_COOLDOWN_WINDOWS = 10_000;

let incidentCounter = 0;

export function createResponseEngine({
  debounceThreshold = 2,
  isolationCooldownWindows = ISOLATION_COOLDOWN_WINDOWS,
  minIsolationConfidence = 0.5,
  fuzzyBurstWindowS = 2.0,
  fuzzyBurstThreshold = 5,
  // Per-ID normal msg_count_ratio means (from normal-traffic feature extraction).
  // When provided, enables two-stage attribution gate: known ECUs whose ratio
  // isn't > attributionRatioMult × their normal share are classified as
  // collateral congestion victims, not attackers, and skipped for isolation.
  // Premise verified in Python: attackers in source set 100%, innocents
  // excluded 97-99% at 3× threshold, 0% of attack windows have no source.
  normalIdRatio = null,
  attributionRatioMult = 3.0,
} = {}) {
  const consecutiveFlags = {};
  const isolatedIds = {}; // canId -> windowsRemaining
  const ecuStatus = {}; // canId -> "normal"|"suspicious"|"collateral"|"isolated"
  const incidentLog = [];
  let recentNewIdIsolations = []; // [{windowStart, canId}]
  let activeFuzzyIncident = null;
  let lastDecayWindow = null; // guard: decay runs once per real window, not per row

  function makeIncident(canId, attackType, confidence, reasons, actionTaken, windowStart) {
    incidentCounter += 1;
    return {
      id: `INC-${String(incidentCounter).padStart(4, "0")}`,
      timestamp: new Date().toISOString(),
      canId,
      attackType,
      confidence: Math.round(confidence * 1000) / 1000,
      reasons,
      actionTaken,
      windowStart,
    };
  }

  function processWindowResult(row, score, attackType) {
    const canId = row.canId;
    const windowStart = row.windowStart;

    // Decay isolation cooldowns once per real 200ms window, not per row.
    // Without this guard the cooldown burns N_IDs-per-window times too fast,
    // de-isolating the attacker after ~2 windows instead of 50.
    if (windowStart !== lastDecayWindow) {
      lastDecayWindow = windowStart;
      for (const cid of Object.keys(isolatedIds)) {
        isolatedIds[cid] -= 1;
        if (isolatedIds[cid] <= 0) {
          delete isolatedIds[cid];
          ecuStatus[cid] = "normal";
        }
      }
    }

    if (isolatedIds[canId] !== undefined) {
      return { action: "dropped_isolated", incident: null };
    }

    if (!score.isAnomaly) {
      consecutiveFlags[canId] = 0;
      if (ecuStatus[canId] === "suspicious" || ecuStatus[canId] === "collateral") {
        ecuStatus[canId] = "normal";
      } else if (!ecuStatus[canId]) {
        ecuStatus[canId] = "normal";
      }
      return { action: "forwarded", incident: null };
    }

    // Two-stage design: detection flags, attribution decides — see response_engine.py.
    // Reaching here means the anomaly model flagged this ID (Stage 1 passed).
    // The gates below form Stage 2 (attribution): each can return flagged-but-protected
    // instead of isolating.  Innocent ECUs perturbed by a flood pass Stage 1 but
    // exit Stage 2 as "collateral" — explaining why Fuzzy shows ~155 flagged windows
    // but only a handful of IDs actually isolated.
    if (score.busUnderCongestion && row.isNewId === 0) {
      ecuStatus[canId] = "suspicious";
      return { action: "flagged_bus_congestion", incident: null };
    }

    if (score.confidence < minIsolationConfidence || !score.isSevere) {
      ecuStatus[canId] = "suspicious";
      return { action: "flagged_low_confidence", incident: null };
    }

    // Entropy-drift suppression gate (mirrors response_engine.py):
    // Known ECU with extreme entropy deviation but normal IAT is a
    // cross-session baseline artifact, not an attack.
    if (row.isNewId === 0) {
      const absEntropyZ = Math.abs(row.entropyZscore ?? 0);
      const absIatZ = Math.abs(row.iatZscore ?? 0);
      if (absEntropyZ > 10.0 && absIatZ < 3.0) {
        consecutiveFlags[canId] = 0;
        ecuStatus[canId] = "suspicious";
        return { action: "flagged_entropy_drift", incident: null };
      }
    }

    // Two-stage attribution gate (mirrors response_engine.py):
    // A known ECU whose msg_count_ratio is not > MULT × its normal share
    // is a bus-starvation victim, not the attacker — protect it from isolation.
    if (row.isNewId === 0 && normalIdRatio !== null) {
      const baseline = normalIdRatio[canId] ?? 0;
      const currentRatio = row.msgCountRatio ?? 0;
      if (baseline > 0 && currentRatio <= attributionRatioMult * baseline) {
        consecutiveFlags[canId] = 0;
        ecuStatus[canId] = "collateral"; // distinct from "suspicious": attribution-protected
        return { action: "flagged_collateral", incident: null };
      }
    }

    consecutiveFlags[canId] = (consecutiveFlags[canId] || 0) + 1;
    ecuStatus[canId] = "suspicious";

    if (consecutiveFlags[canId] >= debounceThreshold) {
      isolatedIds[canId] = isolationCooldownWindows;
      ecuStatus[canId] = "isolated";
      consecutiveFlags[canId] = 0;

      if (row.isNewId === 1) {
        recentNewIdIsolations.push({ windowStart: row.windowStart, canId });
        recentNewIdIsolations = recentNewIdIsolations.filter(
          (e) => row.windowStart - e.windowStart <= fuzzyBurstWindowS
        );

        if (recentNewIdIsolations.length >= fuzzyBurstThreshold) {
          const uniqueIds = new Set(recentNewIdIsolations.map((e) => e.canId));
          if (!activeFuzzyIncident) {
            activeFuzzyIncident = makeIncident(
              `${uniqueIds.size} distinct IDs`,
              "Fuzzy attack (aggregated)",
              score.confidence,
              ["High-rate injection of never-seen CAN IDs", "Likely fuzzing attack in progress"],
              `Isolating each injected ID on detection; ${uniqueIds.size} unique IDs blocked so far`,
              row.windowStart
            );
            incidentLog.push(activeFuzzyIncident);
            return { action: "isolated", incident: activeFuzzyIncident };
          }
          // Update existing aggregated incident in-place and return it so
          // the UI can replace the stale React state entry by id.
          activeFuzzyIncident.canId = `${uniqueIds.size} distinct IDs`;
          activeFuzzyIncident.actionTaken = `Isolating each injected ID on detection; ${uniqueIds.size} unique IDs blocked so far`;
          return { action: "isolated_aggregated", incident: activeFuzzyIncident };
        }
      }

      const incident = makeIncident(
        canId,
        attackType,
        score.confidence,
        score.reasons,
        `Isolated ECU ${canId}; blocking all further frames from this ID`,
        row.windowStart
      );
      incidentLog.push(incident);
      return { action: "isolated", incident };
    }

    return { action: "flagged_monitoring", incident: null };
  }

  function getNetworkState(knownIds) {
    const state = {};
    for (const id of knownIds) state[id] = ecuStatus[id] || "normal";
    for (const [id, status] of Object.entries(ecuStatus)) {
      if (!(id in state)) state[id] = status;
    }
    return state;
  }

  return {
    processWindowResult,
    getNetworkState,
    get incidentLog() {
      return incidentLog;
    },
    reset() {
      for (const k of Object.keys(consecutiveFlags)) delete consecutiveFlags[k];
      for (const k of Object.keys(isolatedIds)) delete isolatedIds[k];
      for (const k of Object.keys(ecuStatus)) delete ecuStatus[k];
      incidentLog.length = 0;
      recentNewIdIsolations = [];
      activeFuzzyIncident = null;
      lastDecayWindow = null;
    },
  };
}
