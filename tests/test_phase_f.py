import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from simulator import DemoSimulator

class PhaseFDemonstrationTests(unittest.TestCase):
    def setUp(self):
        self.sim = DemoSimulator()

    def first_event(self, scenario):
        self.sim.reset(scenario)
        return self.sim.tick()

    def test_normal_has_no_alert(self):
        event = self.first_event("normal")
        self.assertFalse(event["evidence"]["alert"])
        self.assertEqual(event["evidence"]["action"], "ALLOW")
        self.assertEqual(event["evidence"]["reasons"], [])

    def test_dos_has_rate_evidence(self):
        event = self.first_event("dos")
        self.assertTrue(event["evidence"]["alert"])
        self.assertIn("RATE_LIMIT_EXCEEDED", event["evidence"]["reasons"])
        self.assertEqual(event["evidence"]["action"], "RATE_LIMIT")

    def test_fuzzy_has_unknown_id_evidence(self):
        event = self.first_event("fuzzy")
        self.assertTrue(event["evidence"]["alert"])
        self.assertIn("UNKNOWN_ID", event["evidence"]["reasons"])
        self.assertEqual(event["evidence"]["action"], "DROP")

    def test_rpm_spoof_uses_ml_specialist(self):
        event = self.first_event("rpm")
        self.assertEqual(event["evidence"]["reasons"], ["ML_RPM"])
        score = event["evidence"]["ml_scores"]["rpm"]
        self.assertGreater(score["probability"], score["threshold"])
        self.assertEqual(event["evidence"]["action"], "ALERT")

    def test_gear_spoof_uses_ml_specialist(self):
        event = self.first_event("gear")
        self.assertEqual(event["evidence"]["reasons"], ["ML_GEAR"])
        score = event["evidence"]["ml_scores"]["gear"]
        self.assertGreater(score["probability"], score["threshold"])
        self.assertEqual(event["evidence"]["action"], "ALERT")

    def test_mix_interleaves_all_attack_evidence(self):
        self.sim.reset("mix")
        events = [self.sim.tick() for _ in range(4)]
        self.assertEqual(
            [event["attackComponent"] for event in events],
            ["dos", "fuzzy", "rpm", "gear"],
        )
        reasons = {reason for event in events for reason in event["evidence"]["reasons"]}
        self.assertTrue({
            "RATE_LIMIT_EXCEEDED", "UNKNOWN_ID", "ML_RPM", "ML_GEAR"
        }.issubset(reasons))
        snapshot = self.sim.snapshot()
        self.assertEqual(snapshot["networkState"]["0316"], "suspicious")
        self.assertEqual(snapshot["networkState"]["043F"], "suspicious")

    def test_start_stop_reset_repeatability(self):
        self.sim.reset("rpm")
        self.sim.start()
        self.assertTrue(self.sim.snapshot()["running"])
        first = self.sim.tick()
        self.sim.stop()
        self.assertFalse(self.sim.snapshot()["running"])
        self.sim.reset("rpm")
        second = self.sim.tick()
        self.assertEqual(first["frame"], second["frame"])
        self.assertEqual(first["evidence"], second["evidence"])

if __name__ == "__main__":
    unittest.main()
