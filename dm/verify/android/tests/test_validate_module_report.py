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
    sys.path.insert(0, str(DIRECTORY))
    try:
        spec.loader.exec_module(validator)
    finally:
        sys.path.pop(0)
    return validator


class ModuleReportContractTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator("validate_module_report")
        self.report = {
            "schemaVersion": 3, "phase": "1B", "syntheticOnly": True, "gamePlayable": False,
            "checks": [{"id": name, "status": "PASS", "detail": "self-authored NSO fixture"}
                       for name in self.validator.REQUIRED_CHECKS],
            "gates": {f"G{i}": "NOT_RUN" for i in range(1, 7)},
            "environment": {"pageSize": 4096, "abi": "arm64-v8a"},
            "modules": [{"name": name, "buildId": f"{index:064x}",
                         "sourceSha256": f"{index + 10:064x}", "imageSha256": f"{index + 20:064x}"}
                        for index, name in enumerate(("rtld", "main", "sdk"), 1)],
            "device": {"model": "synthetic validator fixture"},
        }

    def test_pass_preserves_provenance_and_does_not_promote_gates(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase1bModules"], "PASS")
        self.assertEqual(result["schemaVersion"], 3)
        self.assertEqual(result["phase"], "1B")
        self.assertEqual(result["modules"], self.report["modules"])
        self.assertEqual(result["device"], self.report["device"])
        self.assertEqual(result["environment"], self.report["environment"])
        self.assertEqual(result["gates"], {"G0": "NOT_VERIFIED", **self.report["gates"]})
        self.assertIs(result["gamePlayable"], False)
        self.assertIs(result["syntheticOnly"], True)

    def test_every_failure_is_preserved(self):
        for index in range(6):
            report = copy.deepcopy(self.report)
            report["checks"][index]["status"] = "FAIL"
            with self.subTest(index=index):
                self.assertEqual(self.validator.summarize(report)["phase1bModules"], "FAIL")

    def test_all_three_report_schemas_are_separate(self):
        for name, schema in (("validate_report", 1), ("validate_guest_report", 2)):
            validator = load_validator(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                validator.summarize(self.report)
            original = {"schemaVersion": schema, "phase": "1A" if schema == 2 else "0",
                        "syntheticOnly": True, "gamePlayable": False,
                        "checks": [{"id": check_id, "status": "PASS"} for check_id in validator.REQUIRED_CHECKS],
                        "environment": {"pageSize": 4096}, "gates": self.report["gates"]}
            validator.summarize(original)
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                self.validator.summarize(original)

    def test_invalid_schema_flags_and_report_types_are_rejected(self):
        for key, value in (("schemaVersion", 2), ("schemaVersion", 3.0), ("schemaVersion", True),
                           ("phase", "1A"), ("phase", None), ("syntheticOnly", False),
                           ("syntheticOnly", 1), ("gamePlayable", True), ("gamePlayable", 0)):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, key: value})
        for key in ("schemaVersion", "phase", "syntheticOnly", "gamePlayable", "modules", "checks", "gates", "environment"):
            report = copy.deepcopy(self.report)
            del report[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for report in (None, [], "report", 3):
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.validator.summarize(report)

    def test_check_ids_and_statuses_are_exact(self):
        mutations = {
            "missing": lambda report: report["checks"].pop(),
            "duplicate": lambda report: report["checks"].__setitem__(1, report["checks"][0]),
            "extra": lambda report: report["checks"].append(report["checks"][0]),
            "unknown": lambda report: report["checks"][0].update(id="loader"),
            "invalid ID": lambda report: report["checks"][0].update(id=[]),
            "invalid check": lambda report: report["checks"].__setitem__(0, None),
            "skip": lambda report: report["checks"][0].update(status="SKIP"),
            "invalid status": lambda report: report["checks"][0].update(status=[]),
            "missing status": lambda report: report["checks"][0].pop("status"),
        }
        for name, mutate in mutations.items():
            report = copy.deepcopy(self.report)
            mutate(report)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for checks in (None, {}, "PASS"):
            with self.subTest(checks=checks), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "checks": checks})

    def test_module_count_names_and_provenance_are_strict(self):
        for modules in (None, {}, "modules", [], self.report["modules"][:2], self.report["modules"] * 2,
                        [None] * 3):
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "modules": modules})
        for key in ("name", "buildId", "sourceSha256", "imageSha256"):
            report = copy.deepcopy(self.report)
            del report["modules"][0][key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                self.validator.summarize(report)
        for name in (None, "", " ", [], 1):
            report = copy.deepcopy(self.report)
            report["modules"][0]["name"] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validator.summarize(report)
        report = copy.deepcopy(self.report)
        report["modules"][1]["name"] = report["modules"][0]["name"]
        with self.assertRaises(ValueError):
            self.validator.summarize(report)
        for key in ("buildId", "sourceSha256", "imageSha256"):
            for value in (None, [], 1, "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n", "0x" + "a" * 62):
                report = copy.deepcopy(self.report)
                report["modules"][0][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.validator.summarize(report)
            report = copy.deepcopy(self.report)
            report["modules"][0][key] = "ABCDEF01" * 8
            self.validator.summarize(report)

    def test_promoted_missing_unknown_and_malformed_gates_are_rejected(self):
        for gate in range(1, 7):
            for status in ("PASS", "FAIL", "PENDING", None, []):
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
            self.validator.summarize(self.report)
        for page_size in (None, 0, -4096, 4095, True, 4096.0, "4096"):
            with self.subTest(page_size=page_size), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": {"pageSize": page_size}})
        for environment in (None, [], {}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": environment})
        with self.assertRaises(ValueError):
            self.validator.summarize({**self.report, "device": []})

    def test_duplicate_json_keys_are_rejected_at_any_depth(self):
        for raw in ('{"schemaVersion":3,"schemaVersion":3}',
                    '{"modules":[{"name":"main","name":"rtld"}]}',
                    '{"modules":[{"sourceSha256":"a","sourceSha256":"b"}]}',
                    '{"checks":[{"id":"modules","id":"imports"}]}',
                    '{"gates":{"G1":"PASS","G1":"NOT_RUN"}}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                json.loads(raw, object_pairs_hook=self.validator.unique_object)

    def test_fixture_contract_matches_validator(self):
        contract = json.loads((DIRECTORY.parents[1] / "android/native/tests/module_contract.json").read_text())
        self.assertEqual(contract["schemaVersion"], 3)
        self.assertEqual(contract["phase"], "1B")
        self.assertEqual(contract["requiredCheckIds"], list(self.validator.REQUIRED_CHECKS))
        self.assertEqual(contract["requiredModuleCount"], 3)
        self.assertEqual(contract["requiredModuleFields"], ["name", "buildId", "sourceSha256", "imageSha256"])
        self.assertIs(contract["syntheticOnly"], True)
        self.assertIs(contract["gamePlayable"], False)

    def test_cli_writes_summary_and_returns_failure_for_failed_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            report_path = pathlib.Path(temporary) / "report.json"
            output_path = pathlib.Path(temporary) / "nested/summary.json"
            for status, exit_code in (("PASS", 0), ("FAIL", 1)):
                self.report["checks"][0]["status"] = status
                report_path.write_text(json.dumps(self.report), encoding="utf-8-sig")
                result = subprocess.run([sys.executable, str(DIRECTORY / "validate_module_report.py"),
                                         str(report_path), "--out", str(output_path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                summary = json.loads(output_path.read_text(encoding="utf-8"))
                self.assertEqual(summary["phase1bModules"], status)
                self.assertEqual(summary["modules"], self.report["modules"])
                self.assertFalse(summary["gamePlayable"])
                self.assertTrue(all(summary["gates"][f"G{i}"] == "NOT_RUN" for i in range(1, 7)))


if __name__ == "__main__":
    unittest.main()
