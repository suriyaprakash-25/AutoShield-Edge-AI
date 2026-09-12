import Papa from "papaparse";
import { hexPayloadEntropy } from "../lib/featureExtraction";

const NORMAL_ECU_NAMES = {
  "0316": "Engine RPM",
  "018F": "Wheel speed",
  "0260": "Steering angle",
  "02A0": "Brake pressure",
  "0329": "Gear position",
  "0153": "Throttle position",
  "043F": "Door status",
  "05A0": "Fuel level",
  "0220": "Ambient temp",
  "04B1": "Infotainment",
};

export function getEcuName(canId) {
  return NORMAL_ECU_NAMES[canId] || `Unknown (${canId})`;
}

export async function loadCanCsv(path) {
  const res = await fetch(path);
  const text = await res.text();
  const parsed = Papa.parse(text, { header: true, skipEmptyLines: true });
  return parsed.data.map((row) => {
    const dataBytes = [0, 1, 2, 3, 4, 5, 6, 7].map((i) => row[`DATA${i}`]).filter((v) => v !== "" && v !== undefined);
    return {
      timestamp: parseFloat(row.Timestamp),
      canId: row.CAN_ID,
      dlc: parseInt(row.DLC, 10),
      dataBytes,
      entropy: hexPayloadEntropy(dataBytes),
      flag: row.Flag,
    };
  });
}

export const SCENARIOS = {
  normal: { label: "Normal traffic", file: "/data/can_normal.csv", description: "Ambient driving, no attack" },
  dos: { label: "DoS attack", file: "/data/can_dos.csv", description: "Flooding CAN ID 0x000" },
  fuzzy: { label: "Fuzzy attack", file: "/data/can_fuzzy.csv", description: "Random IDs and payloads injected" },
  spoof: { label: "Spoofing attack", file: "/data/can_spoof.csv", description: "Forged RPM/gear messages" },
};
