// AutoShield Edge AI — Response engine (JS port)
// Mirrors response_engine.py: debounce, confidence/severity gating,
// bus-congestion suppression for known ECUs, and fuzzy-burst aggregation.

let incidentCounter = 0;

export function createResponseEngine({
  debounceThreshold = 2,
  isolationCooldownWindows = 50,
  minIsolationConfidence = 0.5,
  fuzzyBurstWindowS = 2.0,
  fuzzyBurstThreshold = 5,
} = {}) {
  const consecutiveFlags = {};
  const isolatedIds = {}; // canId -> windowsRemaining
  const ecuStatus = {}; // canId -> "normal" | "suspicious" | "isolated"
  const incidentLog = [];
  let recentNewIdIsolations = []; // [{windowStart, canId}]
  let activeFuzzyIncident = null;

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

    // decay isolation cooldowns
    for (const cid of Object.keys(isolatedIds)) {
      isolatedIds[cid] -= 1;
      if (isolatedIds[cid] <= 0) {
        delete isolatedIds[cid];
        ecuStatus[cid] = "normal";
      }
    }

    if (isolatedIds[canId] !== undefined) {
      return { action: "dropped_isolated", incident: null };
    }

    if (!score.isAnomaly) {
      consecutiveFlags[canId] = 0;
      if (ecuStatus[canId] === "suspicious") ecuStatus[canId] = "normal";
      else if (!ecuStatus[canId]) ecuStatus[canId] = "normal";
      return { action: "forwarded", incident: null };
    }

    if (score.busUnderCongestion && row.isNewId === 0) {
      ecuStatus[canId] = "suspicious";
      return { action: "flagged_bus_congestion", incident: null };
    }

    if (score.confidence < minIsolationConfidence || !score.isSevere) {
      ecuStatus[canId] = "suspicious";
      return { action: "flagged_low_confidence", incident: null };
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
          activeFuzzyIncident.canId = `${uniqueIds.size} distinct IDs`;
          activeFuzzyIncident.actionTaken = `Isolating each injected ID on detection; ${uniqueIds.size} unique IDs blocked so far`;
          return { action: "isolated_aggregated", incident: null };
        }
      }

      const incident = makeIncident(
        canId,
        attackType,
        score.confidence,
        score.reasons,
        `Isolated ECU ${canId}; blocking further frames for ${isolationCooldownWindows} windows`,
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
    },
  };
}
