import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

DIRECTORY = pathlib.Path(__file__).parents[1]


def load_validator(name):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / f"{name}.py")
    validator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(validator)
    return validator


class GuestReportContractTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator("validate_guest_report")
        self.report = {
            "schemaVersion": 2,
            "phase": "1A",
            "syntheticOnly": True,
            "gamePlayable": False,
            "checks": [{"id": name, "status": "PASS", "detail": "self-authored fixture"}
                       for name in self.validator.REQUIRED_CHECKS],
            "gates": {f"G{i}": "NOT_RUN" for i in range(1, 7)},
            "environment": {"pageSize": 4096, "abi": "arm64-v8a", "guestAbi": 0x444D4101},
            "device": {"model": "synthetic validator fixture"},
        }

    def test_passed_fixtures_do_not_promote_game_or_installation_gates(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase1aFixtures"], "PASS")
        self.assertEqual(result["gates"], {"G0": "NOT_VERIFIED", **self.report["gates"]})
        self.assertIs(result["gamePlayable"], False)
        self.assertIs(result["syntheticOnly"], True)
        self.assertEqual(result["device"], self.report["device"])
        self.assertEqual(result["environment"], self.report["environment"])

    def test_failed_check_is_not_masked(self):
        self.report["checks"][2]["status"] = "FAIL"
        self.assertEqual(self.validator.summarize(self.report)["phase1aFixtures"], "FAIL")

    def test_schema_separation_is_bidirectional(self):
        phase0 = load_validator("validate_report")
        with self.assertRaises(ValueError):
            phase0.summarize(self.report)
        original = {"schemaVersion": 1, "gamePlayable": False,
                    "checks": [{"id": name, "status": "PASS"} for name in phase0.REQUIRED_CHECKS]}
        self.assertEqual(phase0.summarize(original)["phase0Probes"], "PASS")
        with self.assertRaises(ValueError):
            self.validator.summarize(original)

    def test_missing_duplicate_unknown_and_malformed_checks_are_rejected(self):
        mutations = {
            "missing": lambda report: report["checks"].pop(),
            "duplicate": lambda report: report["checks"].__setitem__(1, report["checks"][0]),
            "extra": lambda report: report["checks"].append(report["checks"][0]),
            "unknown": lambda report: report["checks"][0].update(id="abi"),
            "invalid ID type": lambda report: report["checks"][0].update(id=[]),
            "invalid check type": lambda report: report["checks"].__setitem__(0, None),
            "skipped": lambda report: report["checks"][0].update(status="SKIP"),
            "unknown status": lambda report: report["checks"][0].update(status="MAYBE"),
            "missing status": lambda report: report["checks"][0].pop("status"),
            "invalid status type": lambda report: report["checks"][0].update(status=[]),
        }
        for name, mutate in mutations.items():
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for checks in (None, {}, "PASS"):
            with self.subTest(checks=checks), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "checks": checks})

    def test_invalid_phase_flags_and_schema_are_rejected(self):
        for key, value in (("schemaVersion", 1), ("schemaVersion", 2.0), ("schemaVersion", True),
                           ("phase", "0"), ("phase", None), ("syntheticOnly", False),
                           ("syntheticOnly", 1), ("gamePlayable", True), ("gamePlayable", 0)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, key: value})
        for key in ("schemaVersion", "phase", "syntheticOnly", "gamePlayable"):
            report = copy.deepcopy(self.report)
            del report[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for report in (None, [], "report"):
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.validator.summarize(report)

    def test_promoted_missing_unknown_and_malformed_gates_are_rejected(self):
        for gate in range(1, 7):
            for status in ("PASS", "FAIL", "PENDING", None):
                report = copy.deepcopy(self.report)
                report["gates"][f"G{gate}"] = status
                with self.subTest(gate=gate, status=status), self.assertRaises(ValueError):
                    self.validator.summarize(report)
        for gates in (None, {}, [], {**self.report["gates"], "G0": "PASS"},
                      {**self.report["gates"], "G7": "NOT_RUN"}):
            with self.subTest(gates=gates), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "gates": gates})
        for status in ("PENDING", "NOT_VERIFIED", "NOT_RUN"):
            result = self.validator.summarize({**self.report, "gates": {"G0": status, **self.report["gates"]}})
            self.assertEqual(result["gates"]["G0"], "NOT_VERIFIED")

    def test_page_size_and_metadata_are_validated(self):
        for page_size in (4096, 16384):
            self.report["environment"]["pageSize"] = page_size
            self.assertEqual(self.validator.summarize(self.report)["environment"]["pageSize"], page_size)
        for page_size in (None, 0, -4096, 4095, True, 4096.0, "4096"):
            with self.subTest(page_size=page_size), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": {"pageSize": page_size}})
        for environment in (None, [], {}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": environment})
        with self.assertRaises(ValueError):
            self.validator.summarize({**self.report, "device": []})

    def test_duplicate_json_keys_are_rejected(self):
        for raw in ('{"schemaVersion":2,"schemaVersion":1}',
                    '{"checks":[{"id":"rewrite","id":"loader"}]}',
                    '{"gates":{"G1":"PASS","G1":"NOT_RUN"}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                json.loads(raw, object_pairs_hook=self.validator.unique_object)

    def test_cli_writes_summary_and_returns_failure_for_failed_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = pathlib.Path(temporary) / "report.json"
            output_path = pathlib.Path(temporary) / "summary.json"
            for status, exit_code in (("PASS", 0), ("FAIL", 1)):
                self.report["checks"][0]["status"] = status
                report_path.write_text(json.dumps(self.report), encoding="utf-8")
                result = subprocess.run([sys.executable, str(DIRECTORY / "validate_guest_report.py"),
                                         str(report_path), "--out", str(output_path)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                summary = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(summary["phase1aFixtures"], status)
                self.assertFalse(summary["gamePlayable"])
                self.assertTrue(all(summary["gates"][f"G{i}"] == "NOT_RUN" for i in range(1, 7)))


if __name__ == "__main__":
    unittest.main()
