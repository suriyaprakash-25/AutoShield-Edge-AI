const ECU_NAMES = {
  "0316": "Engine RPM",
  "018F": "Wheel speed",
  "0260": "Steering angle",
  "02A0": "Brake pressure",
  "0329": "Body controller",
  "0153": "Throttle position",
  "043F": "Gear position",
  "05A0": "Fuel level",
  "0220": "Ambient temp",
  "04B1": "Infotainment",
};

export function getEcuName(canId) {
  return ECU_NAMES[canId] || `Unknown (0x${canId})`;
}

export const SCENARIOS = {
  normal: { label: "Normal", description: "Commissioned traffic, no attack" },
  dos: { label: "DoS", description: "Per-ID rate policy violation" },
  fuzzy: { label: "Fuzzy", description: "Unknown CAN IDs injected" },
  rpm: { label: "RPM spoof", description: "Hybrid-v4 0x316 ML specialist" },
  gear: { label: "Gear spoof", description: "Hybrid-v4 0x43F ML specialist" },
  mix: { label: "Mix / Combo", description: "Interleaved DoS + Fuzzy + RPM spoof + Gear spoof attack stream" },
};
