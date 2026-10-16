import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

DIRECTORY = pathlib.Path(__file__).parents[1]
CHECKS = ("registry", "memory", "threads", "clock", "lifetime")


def load_validator(name):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / f"{name}.py")
    validator = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(DIRECTORY))
    try:
        spec.loader.exec_module(validator)
    finally:
        sys.path.pop(0)
    return validator


class KernelReportContractTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator("validate_kernel_report")
        self.report = {
            "schemaVersion": 4, "phase": "2", "syntheticOnly": True, "gamePlayable": False,
            "checks": [{"id": name, "status": "PASS", "detail": f"synthetic {name} contract"}
                       for name in CHECKS],
            "gates": {f"G{i}": "NOT_RUN" for i in range(1, 7)},
            "environment": {"pageSize": 4096, "abi": "arm64-v8a"},
            "device": {"model": "validator fixture"},
        }

    def test_success_preserves_evidence_without_promoting_original_game(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase2Kernel"], "PASS")
        for key in ("schemaVersion", "phase", "checks", "environment", "device"):
            self.assertEqual(result[key], self.report[key])
        self.assertEqual(result["gates"], {"G0": "NOT_VERIFIED", **self.report["gates"]})
        self.assertIs(result["syntheticOnly"], True)
        self.assertIs(result["gamePlayable"], False)
        self.assertTrue(result["limitations"])

    def test_each_failed_service_survives_summary(self):
        for index in range(len(CHECKS)):
            report = copy.deepcopy(self.report)
            report["checks"][index]["status"] = "FAIL"
            with self.subTest(check=CHECKS[index]):
                result = self.validator.summarize(report)
                self.assertEqual(result["phase2Kernel"], "FAIL")
                self.assertEqual(result["checks"][index], report["checks"][index])

    def test_reordered_checks_and_absent_optional_device_preserve_contract(self):
        report = copy.deepcopy(self.report)
        report["checks"].reverse()
        del report["device"]
        original = copy.deepcopy(report)
        result = self.validator.summarize(report)
        self.assertEqual(result["phase2Kernel"], "PASS")
        self.assertEqual(result["checks"], report["checks"])
        self.assertEqual(result["device"], {})
        self.assertEqual(report, original)

    def test_schema_phase_and_boolean_metadata_are_exact(self):
        for key, values in {
            "schemaVersion": (1, 2, 3, 4.0, True, "4", None),
            "phase": ("1B", "Phase2", 2, None),
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
        for value in (None, [], "report", 4):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validator.summarize(value)

    def test_other_report_validators_cannot_accept_kernel_evidence(self):
        for name in ("validate_report", "validate_guest_report", "validate_module_report"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                load_validator(name).summarize(self.report)

    def test_checks_require_exact_unique_ids_statuses_and_explanations(self):
        mutations = {
            "missing": lambda r: r["checks"].pop(),
            "duplicate": lambda r: r["checks"].__setitem__(1, r["checks"][0]),
            "extra": lambda r: r["checks"].append(r["checks"][0]),
            "unknown": lambda r: r["checks"][0].update(id="modules"),
            "list ID": lambda r: r["checks"][0].update(id=[]),
            "nonobject": lambda r: r["checks"].__setitem__(0, None),
            "missing status": lambda r: r["checks"][0].pop("status"),
            "skip": lambda r: r["checks"][0].update(status="SKIP"),
            "status list": lambda r: r["checks"][0].update(status=[]),
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

    def test_raw_gates_are_exact_and_never_mark_game_as_tested(self):
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
        for value in (None, [], {}, {**self.report["gates"], "G0": "PASS"},
                      {**self.report["gates"], "G0": "NOT_VERIFIED"},
                      {**self.report["gates"], "G7": "NOT_RUN"}):
            with self.subTest(gates=value), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "gates": value})

    def test_environment_abi_and_page_size_cannot_be_misrepresented(self):
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

    def test_duplicate_json_members_are_rejected_even_when_last_value_looks_safe(self):
        for raw in ('{"schemaVersion":3,"schemaVersion":4}',
                    '{"checks":[{"id":"registry","id":"memory"}]}',
                    '{"environment":{"abi":"x86_64","abi":"arm64-v8a"}}',
                    '{"gates":{"G1":"PASS","G1":"NOT_RUN"}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                json.loads(raw, object_pairs_hook=self.validator.unique_object)

    def test_native_contract_matches_validator(self):
        contract = json.loads((DIRECTORY.parents[1] / "android/native/tests/kernel_contract.json").read_text())
        self.assertEqual(contract["schemaVersion"], 4)
        self.assertEqual(contract["phase"], "2")
        self.assertEqual(contract["requiredCheckIds"], list(CHECKS))
        self.assertEqual(contract["requiredCheckIds"], list(self.validator.REQUIRED_CHECKS))
        self.assertEqual(contract["requiredGates"], self.report["gates"])
        self.assertEqual(contract["requiredAbi"], "arm64-v8a")
        self.assertIs(contract["syntheticOnly"], True)
        self.assertIs(contract["gamePlayable"], False)

    def test_cli_persists_summary_and_failure_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = pathlib.Path(temporary) / "report.json"
            output_path = pathlib.Path(temporary) / "nested/summary.json"
            for status, exit_code in (("PASS", 0), ("FAIL", 1)):
                self.report["checks"][0]["status"] = status
                report_path.write_text(json.dumps(self.report), encoding="utf-8-sig")
                result = subprocess.run([sys.executable, str(DIRECTORY / "validate_kernel_report.py"),
                                         str(report_path), "--out", str(output_path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                summary = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(summary["phase2Kernel"], status)
                self.assertFalse(summary["gamePlayable"])
                self.assertTrue(all(summary["gates"][f"G{i}"] == "NOT_RUN" for i in range(1, 7)))

    def test_cli_rejects_malformed_or_ambiguous_json_without_writing_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = pathlib.Path(temporary) / "report.json"
            output_path = pathlib.Path(temporary) / "summary.json"
            valid_raw = json.dumps(self.report)
            for raw in ("{", valid_raw.replace('"schemaVersion": 4', '"schemaVersion": 3, "schemaVersion": 4'),
                        valid_raw.replace('"gamePlayable": false', '"gamePlayable": true'),
                        json.dumps({"schemaVersion": 4, "phase": "2", "syntheticOnly": True,
                                    "gamePlayable": False, "error": "native probe unavailable"})):
                report_path.write_text(raw, encoding="utf-8")
                result = subprocess.run([sys.executable, str(DIRECTORY / "validate_kernel_report.py"),
                                         str(report_path), "--out", str(output_path)], capture_output=True, text=True)
                with self.subTest(raw=raw):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
