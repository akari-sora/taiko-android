import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

DIRECTORY = pathlib.Path(__file__).parents[1]
CHECKS = ("account", "events", "time", "filesystem", "save_transactions", "lifetime")


def load_validator(name):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / f"{name}.py")
    validator = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(DIRECTORY))
    try:
        spec.loader.exec_module(validator)
    finally:
        sys.path.pop(0)
    return validator


class ServiceReportContractTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator("validate_service_report")
        self.report = {
            "schemaVersion": 5, "phase": "3", "syntheticOnly": True, "gamePlayable": False,
            "checks": [{"id": name, "status": "PASS", "detail": f"synthetic {name} contract"}
                       for name in CHECKS],
            "gates": {f"G{i}": "NOT_RUN" for i in range(1, 7)},
            "environment": {"pageSize": 4096, "abi": "arm64-v8a"},
            "device": {"model": "validator fixture"},
        }

    def test_pass_retains_service_evidence_without_claiming_original_saves_or_game(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase3Services"], "PASS")
        for key in ("schemaVersion", "phase", "checks", "environment", "device"):
            self.assertEqual(result[key], self.report[key])
        self.assertEqual(result["gates"], {"G0": "NOT_VERIFIED", **self.report["gates"]})
        self.assertIs(result["syntheticOnly"], True)
        self.assertIs(result["gamePlayable"], False)
        self.assertTrue(result["limitations"])

    def test_failure_in_each_service_remains_failure(self):
        for index, name in enumerate(CHECKS):
            report = copy.deepcopy(self.report)
            report["checks"][index].update(status="FAIL", detail=f"{name} failed")
            with self.subTest(name=name):
                result = self.validator.summarize(report)
                self.assertEqual(result["phase3Services"], "FAIL")
                self.assertEqual(result["checks"][index], report["checks"][index])

    def test_schema_phase_and_literal_boolean_flags_are_required(self):
        for key, values in {
            "schemaVersion": (1, 2, 3, 4, 5.0, True, "5", None),
            "phase": ("2", "Phase3", 3, None),
            "syntheticOnly": (False, 1, "true", None),
            "gamePlayable": (True, 0, "false", None),
        }.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.validator.summarize({**self.report, key: value})
        for key in ("schemaVersion", "phase", "syntheticOnly", "gamePlayable", "checks", "environment", "gates"):
            report = copy.deepcopy(self.report)
            del report[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for value in (None, [], "report", 5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validator.summarize(value)

    def test_all_other_report_schemas_are_separate(self):
        for name in ("validate_report", "validate_guest_report", "validate_module_report", "validate_kernel_report"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                load_validator(name).summarize(self.report)
        kernel = {**self.report, "schemaVersion": 4, "phase": "2"}
        with self.assertRaises(ValueError):
            self.validator.summarize(kernel)

    def test_exact_service_checks_prevent_missing_save_or_event_coverage(self):
        mutations = {
            "missing save": lambda r: r["checks"].pop(4),
            "duplicate": lambda r: r["checks"].__setitem__(1, r["checks"][0]),
            "extra": lambda r: r["checks"].append(r["checks"][0]),
            "wrong phase checks": lambda r: r["checks"][0].update(id="registry"),
            "unhashable ID": lambda r: r["checks"][0].update(id=[]),
            "missing ID": lambda r: r["checks"][0].pop("id"),
            "nonobject": lambda r: r["checks"].__setitem__(0, None),
            "missing status": lambda r: r["checks"][0].pop("status"),
            "skip": lambda r: r["checks"][0].update(status="SKIP"),
            "status object": lambda r: r["checks"][0].update(status={}),
            "missing detail": lambda r: r["checks"][0].pop("detail"),
            "empty detail": lambda r: r["checks"][0].update(detail=" \n"),
            "detail object": lambda r: r["checks"][0].update(detail={}),
        }
        for name, mutate in mutations.items():
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for value in (None, {}, "PASS"):
            with self.subTest(checks=value), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "checks": value})

    def test_gate_set_cannot_be_promoted_or_extended(self):
        for gate in range(1, 7):
            for status in ("PASS", "FAIL", "PENDING", None, []):
                report = copy.deepcopy(self.report)
                report["gates"][f"G{gate}"] = status
                with self.subTest(gate=gate, status=status), self.assertRaises(ValueError):
                    self.validator.summarize(report)
            report = copy.deepcopy(self.report)
            del report["gates"][f"G{gate}"]
            with self.subTest(missing=gate), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for gates in (None, [], {}, {**self.report["gates"], "G0": "PASS"},
                      {**self.report["gates"], "G0": "NOT_VERIFIED"}, {**self.report["gates"], "G7": "NOT_RUN"}):
            with self.subTest(gates=gates), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "gates": gates})

    def test_abi_and_page_size_are_strict(self):
        for page_size in (4096, 16384):
            self.validator.summarize({**self.report, "environment": {"pageSize": page_size, "abi": "arm64-v8a"}})
        for page_size in (None, 0, -4096, 4095, True, 4096.0, "4096"):
            with self.subTest(pageSize=page_size), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": {"pageSize": page_size, "abi": "arm64-v8a"}})
        for abi in (None, "", "arm64", "x86_64", 64, []):
            with self.subTest(abi=abi), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": {"pageSize": 4096, "abi": abi}})
        for environment in (None, [], {}, {"pageSize": 4096}, {"abi": "arm64-v8a"}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": environment})
        with self.assertRaises(ValueError):
            self.validator.summarize({**self.report, "device": []})

    def test_optional_device_and_check_order_do_not_change_evidence(self):
        report = copy.deepcopy(self.report)
        del report["device"]
        report["checks"].reverse()
        original = copy.deepcopy(report)
        result = self.validator.summarize(report)
        self.assertEqual(result["phase3Services"], "PASS")
        self.assertEqual(result["checks"], report["checks"])
        self.assertEqual(result["device"], {})
        self.assertEqual(report, original)

    def test_duplicate_json_fields_reject_overwritten_failure(self):
        for raw in ('{"schemaVersion":4,"schemaVersion":5}',
                    '{"checks":[{"status":"FAIL","status":"PASS"}]}',
                    '{"environment":{"abi":"x86_64","abi":"arm64-v8a"}}',
                    '{"gates":{"G1":"PASS","G1":"NOT_RUN"}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                json.loads(raw, object_pairs_hook=self.validator.unique_object)

    def test_native_contract_matches_validator(self):
        contract = json.loads((DIRECTORY.parents[1] / "android/native/tests/service_contract.json").read_text())
        self.assertEqual(contract["schemaVersion"], 5)
        self.assertEqual(contract["phase"], "3")
        self.assertEqual(contract["requiredCheckIds"], list(CHECKS))
        self.assertEqual(contract["requiredCheckIds"], list(self.validator.REQUIRED_CHECKS))
        self.assertEqual(contract["requiredGates"], self.report["gates"])
        self.assertEqual(contract["requiredAbi"], "arm64-v8a")
        self.assertIs(contract["syntheticOnly"], True)
        self.assertIs(contract["gamePlayable"], False)

    def test_cli_preserves_failures_and_explicit_synthetic_limitations(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = pathlib.Path(temporary) / "report.json"
            output_path = pathlib.Path(temporary) / "nested/summary.json"
            for status, exit_code in (("PASS", 0), ("FAIL", 1)):
                self.report["checks"][4]["status"] = status
                report_path.write_text(json.dumps(self.report), encoding="utf-8-sig")
                result = subprocess.run([sys.executable, str(DIRECTORY / "validate_service_report.py"),
                                         str(report_path), "--out", str(output_path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                summary = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(summary["phase3Services"], status)
                self.assertFalse(summary["gamePlayable"])
                self.assertTrue(summary["syntheticOnly"])
                self.assertTrue(all(summary["gates"][f"G{i}"] == "NOT_RUN" for i in range(1, 7)))

    def test_cli_does_not_write_success_for_malformed_or_native_error_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = pathlib.Path(temporary) / "report.json"
            output_path = pathlib.Path(temporary) / "summary.json"
            valid_raw = json.dumps(self.report)
            for raw in ("{", valid_raw.replace('"schemaVersion": 5', '"schemaVersion": 4, "schemaVersion": 5'),
                        valid_raw.replace('"gamePlayable": false', '"gamePlayable": true'),
                        *(valid_raw.replace('"validator fixture"', constant) for constant in ("NaN", "Infinity", "-Infinity")),
                        json.dumps({"schemaVersion": 5, "phase": "3", "syntheticOnly": True,
                                    "gamePlayable": False, "error": "service probe unavailable"})):
                report_path.write_text(raw, encoding="utf-8")
                result = subprocess.run([sys.executable, str(DIRECTORY / "validate_service_report.py"),
                                         str(report_path), "--out", str(output_path)], capture_output=True, text=True)
                with self.subTest(raw=raw):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
