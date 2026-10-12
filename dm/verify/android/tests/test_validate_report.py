import copy
import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).parents[1] / "validate_report.py"


class ReportContractTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.exists(), "Evidence validator has not been implemented")
        spec = importlib.util.spec_from_file_location("validate_report", SCRIPT)
        self.validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.validator)
        self.report = {
            "schemaVersion": 1,
            "gamePlayable": False,
            "checks": [
                {"id": name, "status": "PASS", "detail": "synthetic fixture"}
                for name in self.validator.REQUIRED_CHECKS
            ],
        }

    def test_passed_fixtures_never_pass_game_gates(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase0Probes"], "PASS")
        self.assertEqual(result["gates"]["G0"], "NOT_VERIFIED")
        for gate in range(1, 7):
            self.assertEqual(result["gates"][f"G{gate}"], "NOT_RUN")
        self.assertFalse(result["gamePlayable"])

    def test_failure_is_not_masked_by_other_passes(self):
        self.report["checks"][0]["status"] = "FAIL"
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase0Probes"], "FAIL")

    def test_missing_duplicate_unknown_or_skipped_check_cannot_pass(self):
        for mutation in ("missing", "duplicate", "unknown", "skipped"):
            report = copy.deepcopy(self.report)
            if mutation == "missing":
                report["checks"].pop()
            elif mutation == "duplicate":
                report["checks"].append(report["checks"][0])
            elif mutation == "unknown":
                report["checks"][0]["status"] = "MAYBE"
            else:
                report["checks"][0]["status"] = "SKIP"
            with self.subTest(mutation=mutation):
                self.assertNotEqual(self.validator.summarize(report)["phase0Probes"], "PASS")

    def test_playable_or_invalid_schema_is_rejected(self):
        for key, value in (("gamePlayable", True), ("schemaVersion", 99)):
            report = copy.deepcopy(self.report)
            report[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validator.summarize(report)


if __name__ == "__main__":
    unittest.main()
