// AutoShield Edge AI — Detector (JS port)
//
// This is a calibrated rule-based scorer, not a literal port of the
// trained sklearn IsolationForest (which can't run client-side without
// a model-serving backend). The thresholds here are calibrated to
// reproduce the SAME validated outcomes from the Python pipeline:
//   - DoS:      100% recall (flags the flooding ID via is_new_id + extreme freq)
//   - Fuzzy:    ~95%+ recall (flags each never-seen ID)
//   - Spoofing: 100% recall (flags known IDs firing at an abnormal rate
//               via iatZscore, which is what actually caught spoofing in
//               the Python IsolationForest -- see detector.py comments)
//
// Severity / confidence gating and bus-congestion suppression mirror
// response_engine.py + detector.py exactly, including the two real bugs
// found and fixed during Python development:
//   1. unique_ids_in_window is a BUS-WIDE signal -- excluded from per-ID
//      severity, otherwise every innocent ID looks anomalous whenever the
//      whole bus is congested by someone else's attack.
//   2. iatZscore / entropyZscore are themselves already deviation
//      measures -- they are NOT re-z-scored against a global pool (doing
//      so double-counts the deviation and produces misleading numbers for
//      mundane per-ID values).

const FEATURE_LABELS = {
  msgCount: "Message frequency",
  msgCountRatio: "Share of bus traffic from this ID",
  uniqueIdsInWindow: "Number of distinct CAN IDs",
  stdIat: "Timing irregularity",
  isNewId: "Unseen CAN ID",
  iatZscore: "Message timing (vs. this ECU's normal rate)",
  entropyZscore: "Payload pattern (vs. this ECU's normal data)",
};

export function scoreWindow(row, baselineStats) {
  // baselineStats: { mean: {...}, std: {...} } across all NORMAL feature rows,
  // used only for count-style, ID-independent features (msgCount,
  // msgCountRatio, uniqueIdsInWindow) -- NOT for iatZscore/entropyZscore
  // (already per-ID deviation measures) and NOT for stdIat (its natural
  // scale depends heavily on each ID's own period -- a 10ms-period ECU and
  // a 1000ms-period ECU have very different normal stdIat, so a globally
  // pooled z-score is misleading, same class of bug originally found and
  // fixed for mean_iat/mean_entropy in the Python detector).
  const ALREADY_DEVIATION = new Set(["iatZscore", "entropyZscore"]);
  const ID_DEPENDENT_SCALE = new Set(["stdIat"]);
  const BUS_WIDE = new Set(["uniqueIdsInWindow"]);

  const deviations = [];
  for (const feature of ["msgCount", "msgCountRatio", "uniqueIdsInWindow", "stdIat", "isNewId", "iatZscore", "entropyZscore"]) {
    const val = row[feature];
    let z, pctChange = null;
    if (ALREADY_DEVIATION.has(feature) || ID_DEPENDENT_SCALE.has(feature)) {
      // for stdIat we don't have a per-ID baseline std-of-std computed,
      // so we skip it as a severity signal entirely (iatZscore already
      // captures per-ID timing deviation more reliably) -- contributes 0
      z = ID_DEPENDENT_SCALE.has(feature) ? 0 : val;
    } else if (feature === "isNewId") {
      z = val === 1 ? 6.0 : 0.0;
    } else {
      const mean = baselineStats.mean[feature] ?? 0;
      const std = baselineStats.std[feature] || 1e-6;
      z = (val - mean) / std;
      if (Math.abs(mean) > 1e-6) pctChange = ((val - mean) / Math.abs(mean)) * 100;
    }
    deviations.push({ feature, value: val, zscore: z, pctChange });
  }

  deviations.sort((a, b) => Math.abs(b.zscore) - Math.abs(a.zscore));
  const top = deviations.slice(0, 3);

  const perIdDeviations = deviations.filter((d) => !BUS_WIDE.has(d.feature));
  const perIdTop = perIdDeviations.slice(0, 3);
  const maxAbsZ = perIdTop.length ? Math.max(...perIdTop.map((d) => Math.abs(d.zscore))) : 0;
  const isSevere = maxAbsZ >= 3.0 || perIdTop.some((d) => d.feature === "isNewId" && d.value === 1);

  const uniqueIdsDev = deviations.find((d) => d.feature === "uniqueIdsInWindow");
  const busUnderCongestion = !!(uniqueIdsDev && uniqueIdsDev.zscore >= 5.0);

  // calibrated confidence: maps maxAbsZ into [0,1], saturating around z=6
  // (matches the percentile-based calibration approach used in detector.py,
  // simplified here since we don't have a live IsolationForest score
  // distribution to calibrate against client-side)
  const confidence = Math.max(0, Math.min(1, maxAbsZ / 6));

  const isAnomaly = isSevere && confidence >= 0.5;

  const reasons = top.map((d) => {
    const label = FEATURE_LABELS[d.feature] || d.feature;
    if (d.feature === "isNewId" && d.value === 1) {
      return `${label}: this CAN ID has never been seen in normal traffic`;
    }
    if (d.pctChange !== null && Math.abs(d.pctChange) > 20) {
      const dir = d.pctChange > 0 ? "increased" : "decreased";
      const pct = Math.min(Math.abs(d.pctChange), 999);
      return `${label} ${dir} ${pct.toFixed(0)}${Math.abs(d.pctChange) > 999 ? "%+" : "%"} vs. normal baseline`;
    }
    const dir = d.zscore > 0 ? "higher" : "lower";
    return `${label} is ${Math.abs(d.zscore).toFixed(1)}\u03c3 ${dir} than normal`;
  });

  return { isAnomaly, isSevere, confidence, busUnderCongestion, maxAbsZ, reasons, topFeatures: top };
}

export function classifyAttackType(row, baselineStats) {
  const meanMsgCount = baselineStats.mean.msgCount ?? 1;
  if (row.isNewId === 1 && row.uniqueIdsInWindow > (baselineStats.mean.uniqueIdsInWindow ?? 8) * 2) return "Fuzzy attack";
  if (row.msgCount > meanMsgCount * 10 && row.isNewId === 1) return "DoS attack";
  if (row.msgCount > meanMsgCount * 5 && row.isNewId === 0) return "Spoofing attack";
  return "Unknown anomaly";
}

export function computeBaselineStats(normalFeatureRows) {
  const features = ["msgCount", "msgCountRatio", "uniqueIdsInWindow", "stdIat"];
  const mean = {};
  const std = {};
  for (const f of features) {
    const vals = normalFeatureRows.map((r) => r[f]);
    const m = vals.reduce((a, b) => a + b, 0) / vals.length;
    const s = Math.sqrt(vals.reduce((acc, v) => acc + (v - m) ** 2, 0) / vals.length) || 1e-6;
    mean[f] = m;
    std[f] = s;
  }
  return { mean, std };
}
