// Validates the REAL exported JS functions (not a duplicate) against the
// same scenarios validated in the Python pipeline. Run this any time the
// detection logic changes, to catch regressions before they reach the demo.
//
//   node src/lib/__test__/validate.mjs
//
// Expected results (as of last validation):
//   DOS:    recall=1.00 precision=0.94  -- isolates only 0x0000
//   FUZZY:  recall=1.00 precision=1.00  -- isolates only genuinely-injected random IDs
//   SPOOF:  recall=1.00 precision=0.98  -- isolates only 0x0316 and 0x0329
// Zero false-positive isolations of innocent ECUs in all three scenarios.

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import Papa from "papaparse";
import { buildBaselineProfile, extractWindowFeatures, hexPayloadEntropy } from "../featureExtraction.js";
import { scoreWindow, computeBaselineStats } from "../detector.js";
import { createResponseEngine } from "../responseEngine.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadCsv(filePath) {
  const text = fs.readFileSync(filePath, "utf-8");
  const parsed = Papa.parse(text, { header: true, skipEmptyLines: true });
  return parsed.data.map((row) => {
    const dataBytes = [0, 1, 2, 3, 4, 5, 6, 7].map((i) => row[`DATA${i}`]).filter((v) => v !== "" && v !== undefined);
    return {
      timestamp: parseFloat(row.Timestamp),
      canId: row.CAN_ID,
      dataBytes,
      entropy: hexPayloadEntropy(dataBytes),
      flag: row.Flag,
    };
  });
}

const dataDir = path.join(__dirname, "../../../public/data");
const KNOWN_IDS = new Set(["0316", "018F", "0260", "02A0", "0329", "0153", "043F", "05A0", "0220", "04B1"]);

const normalFrames = loadCsv(path.join(dataDir, "can_normal.csv"));
const profile = buildBaselineProfile(normalFrames);
const normalFeatures = extractWindowFeatures(normalFrames, 200, profile, KNOWN_IDS);
const stats = computeBaselineStats(normalFeatures);

console.log("=".repeat(60));
console.log("JS PORT VALIDATION -- using REAL exported functions");
console.log("=".repeat(60));

const trueAttackerIds = { dos: new Set(["0000"]), spoof: new Set(["0316", "0329"]) };

for (const mode of ["dos", "fuzzy", "spoof"]) {
  const frames = loadCsv(path.join(dataDir, `can_${mode}.csv`));
  const features = extractWindowFeatures(frames, 200, profile, KNOWN_IDS).sort((a, b) => a.windowStart - b.windowStart);

  let tp = 0, fp = 0, tn = 0, fn = 0;
  const engine = createResponseEngine();
  const isolatedIds = new Set();
  let falsePositiveIsolations = [];

  for (const row of features) {
    const score = scoreWindow(row, stats);
    const predicted = score.isAnomaly ? 1 : 0;
    const actual = row.label;
    if (predicted === 1 && actual === 1) tp++;
    else if (predicted === 1 && actual === 0) fp++;
    else if (predicted === 0 && actual === 0) tn++;
    else fn++;

    const { incident } = engine.processWindowResult(row, score, "Test");
    if (incident && typeof incident.canId === "string" && !incident.canId.includes("distinct")) {
      isolatedIds.add(incident.canId);
      if (trueAttackerIds[mode] && !trueAttackerIds[mode].has(incident.canId)) {
        falsePositiveIsolations.push(incident.canId);
      }
    }
  }

  const precision = tp / (tp + fp) || 0;
  const recall = tp / (tp + fn) || 0;
  const f1 = (2 * precision * recall) / (precision + recall) || 0;
  console.log(`\n${mode.toUpperCase()}`);
  console.log(`  detection: precision=${precision.toFixed(2)} recall=${recall.toFixed(2)} f1=${f1.toFixed(2)} (tp=${tp} fp=${fp} fn=${fn} tn=${tn})`);
  console.log(`  response engine: isolated IDs = [${[...isolatedIds].join(", ")}]`);
  if (trueAttackerIds[mode]) {
    console.log(`  true attacker(s): [${[...trueAttackerIds[mode]].join(", ")}]`);
    console.log(`  false-positive isolations: ${falsePositiveIsolations.length ? [...new Set(falsePositiveIsolations)].join(", ") : "none"}`);
  }
}
