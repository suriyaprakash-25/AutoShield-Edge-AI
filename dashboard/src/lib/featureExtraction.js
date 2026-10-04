// AutoShield Edge AI — Feature extraction (JS port)
//
// Mirrors src/feature_extraction.py exactly: same sliding-window approach,
// same per-ID baseline z-scoring, same fixes for the bugs we found and
// fixed during Python development (msg_count_ratio instead of raw global
// count, last-seen-timestamp IAT tracking across window boundaries, std
// floors to avoid quantization-noise false positives).
//
// WHY THIS IS A SEPARATE JS IMPLEMENTATION rather than running the trained
// Python IsolationForest in-browser: the dashboard needs to run standalone,
// client-side, with zero backend dependency, so the demo works on any
// laptop without a Python server running. Porting the validated FEATURE
// EXTRACTION + a calibrated rule-based detector (thresholds derived from
// the same z-score logic the Python IsolationForest converged on) keeps
// the detection logic faithful to what was actually validated, rather than
// inventing new logic for the demo.

const MIN_STD_IAT = 1e-4;
const MIN_STD_ENTROPY = 0.15;

export function hexPayloadEntropy(dataBytes) {
  const vals = dataBytes.filter((b) => b !== null && b !== undefined && b !== "");
  if (vals.length === 0) return 0;
  const counts = {};
  for (const v of vals) {
    const n = typeof v === "string" ? parseInt(v, 16) : v;
    counts[n] = (counts[n] || 0) + 1;
  }
  const total = vals.length;
  let entropy = 0;
  for (const c of Object.values(counts)) {
    const p = c / total;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function buildBaselineProfile(normalFrames) {
  const byId = {};
  for (const f of normalFrames) {
    if (!byId[f.canId]) byId[f.canId] = [];
    byId[f.canId].push(f);
  }
  const profile = {};
  for (const [canId, frames] of Object.entries(byId)) {
    const sorted = [...frames].sort((a, b) => a.timestamp - b.timestamp);
    const iats = [];
    for (let i = 1; i < sorted.length; i++) iats.push(sorted[i].timestamp - sorted[i - 1].timestamp);
    const meanIat = iats.length ? iats.reduce((a, b) => a + b, 0) / iats.length : 0;
    const stdIat = iats.length > 1 ? Math.sqrt(iats.reduce((s, v) => s + (v - meanIat) ** 2, 0) / iats.length) : MIN_STD_IAT;
    const entropies = sorted.map((f) => f.entropy);
    const meanEntropy = entropies.reduce((a, b) => a + b, 0) / entropies.length;
    const stdEntropy = entropies.length > 1
      ? Math.sqrt(entropies.reduce((s, v) => s + (v - meanEntropy) ** 2, 0) / entropies.length)
      : MIN_STD_ENTROPY;
    profile[canId] = {
      meanIat,
      stdIat: Math.max(stdIat, MIN_STD_IAT),
      meanEntropy,
      stdEntropy: Math.max(stdEntropy, MIN_STD_ENTROPY),
    };
  }
  return profile;
}

/**
 * Extracts one feature row per (window, CAN_ID) from a chronological list
 * of frames. Mirrors extract_window_features() in feature_extraction.py.
 */
export function extractWindowFeatures(frames, windowMs, baselineProfile, knownIds) {
  const windowS = windowMs / 1000;
  const sorted = [...frames].sort((a, b) => a.timestamp - b.timestamp);
  if (sorted.length === 0) return [];

  const tMin = sorted[0].timestamp;
  const tMax = sorted[sorted.length - 1].timestamp;
  const nWindows = Math.ceil((tMax - tMin) / windowS) + 1;

  const lastSeenTs = {};
  const rows = [];
  let frameIdx = 0;

  for (let w = 0; w < nWindows; w++) {
    const wStart = tMin + w * windowS;
    const wEnd = wStart + windowS;
    const windowFrames = [];
    while (frameIdx < sorted.length && sorted[frameIdx].timestamp < wEnd) {
      if (sorted[frameIdx].timestamp >= wStart) windowFrames.push(sorted[frameIdx]);
      frameIdx++;
    }
    if (windowFrames.length === 0) continue;

    const totalMsgsInWindow = windowFrames.length;
    const uniqueIdsInWindow = new Set(windowFrames.map((f) => f.canId)).size;

    const byId = {};
    for (const f of windowFrames) {
      if (!byId[f.canId]) byId[f.canId] = [];
      byId[f.canId].push(f);
    }

    for (const [canId, group] of Object.entries(byId)) {
      const ts = group.map((f) => f.timestamp).sort((a, b) => a - b);
      let iat;
      if (ts.length > 1) {
        iat = [];
        for (let i = 1; i < ts.length; i++) iat.push(ts[i] - ts[i - 1]);
      } else if (lastSeenTs[canId] !== undefined) {
        iat = [ts[0] - lastSeenTs[canId]];
      } else {
        iat = [0];
      }
      lastSeenTs[canId] = ts[ts.length - 1];

      const meanIat = iat.reduce((a, b) => a + b, 0) / iat.length;
      const stdIat = iat.length > 1 ? Math.sqrt(iat.reduce((s, v) => s + (v - meanIat) ** 2, 0) / iat.length) : 0;
      const meanEntropy = group.reduce((s, f) => s + f.entropy, 0) / group.length;
      const isNewId = knownIds.has(canId) ? 0 : 1;

      const base = baselineProfile[canId];
      let iatZ, entropyZ;
      if (base) {
        iatZ = base.stdIat > 1e-9 ? (meanIat - base.meanIat) / base.stdIat : 0;
        entropyZ = base.stdEntropy > 1e-9 ? (meanEntropy - base.meanEntropy) / base.stdEntropy : 0;
      } else {
        iatZ = 5.0;
        entropyZ = 5.0;
      }

      rows.push({
        windowStart: wStart,
        canId,
        msgCount: group.length,
        msgCountRatio: group.length / totalMsgsInWindow,
        totalMsgsInWindow,
        uniqueIdsInWindow,
        meanIat,
        stdIat,
        meanEntropy,
        isNewId,
        iatZscore: iatZ,
        entropyZscore: entropyZ,
        label: group.some((f) => f.flag === "T") ? 1 : 0,
      });
    }
  }
  return rows;
}
