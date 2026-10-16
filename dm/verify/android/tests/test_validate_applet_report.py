"""Producer-shaped applet receipts and hostile evidence mutations."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_validate_service_report import load_validator

ROOT = Path(__file__).resolve().parents[4]
CHECKS = ("exports", "notifications", "parameters", "sdk_copy", "preflight", "lifetime")


def native_report():
    modules = []
    for directory, identity_class in (("observation_fixtures", 1), ("applet_fixtures", 0)):
        fixture = json.loads((ROOT / "dm/platform/android" / directory / "import.json").read_text())
        modules.append({"name": fixture["name"], "buildId": fixture["build_id"],
                        "sourceSha256": fixture["source_sha256"], "packageSha256": fixture["package_sha256"],
                        "profileClass": identity_class,
                        "profileDigest": fixture["rewrite"]["profile_digest"] if identity_class else "0" * 64})
    # Shape and field names are independently copied from the native producer,
    # not the validator's constants or expected-module helper.
    return {
        "schemaVersion": 7, "phase": "5", "syntheticOnly": True, "gamePlayable": False,
        "environment": {"pageSize": 4096, "abi": "arm64-v8a"}, "modules": modules,
        "capabilities": {"oeCore": True, "parameterBasis": True, "rendererResize": False,
                         "uiCorrection": False, "saveSuspend": False, "audioSuspend": False, "gpuSuspend": False},
        "checks": [{"id": name, "status": "PASS", "detail": f"public guest {name} receipt"} for name in CHECKS],
        "gates": {f"G{i}": "NOT_RUN" for i in range(1, 7)},
    }


class AppletReportTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator("validate_applet_report")
        self.report = native_report()

    def test_native_producer_shape_retains_scope_without_adding_g0(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase5Applets"], "PASS")
        self.assertEqual(result["gates"], {f"G{i}": "NOT_RUN" for i in range(1, 7)})
        self.assertNotIn("G0", result["gates"])
        self.assertFalse(result["gamePlayable"])
        self.assertEqual(result["modules"], self.report["modules"])
        self.assertTrue(any("OS lifecycle" in limitation for limitation in result["limitations"]))
        self.assertTrue(any("renderer resize" in limitation for limitation in result["limitations"]))

    def test_every_native_failure_remains_failed_even_when_capabilities_available(self):
        for index, check_id in enumerate(CHECKS):
            report = copy.deepcopy(self.report)
            report["checks"][index]["status"] = "FAIL"
            with self.subTest(check=check_id):
                self.assertEqual(self.validator.summarize(report)["phase5Applets"], "FAIL")

    def test_unavailable_required_capabilities_cannot_be_promoted_by_pass_checks(self):
        for name in ("oeCore", "parameterBasis"):
            report = copy.deepcopy(self.report)
            report["capabilities"][name] = False
            self.assertEqual(self.validator.summarize(report)["phase5Applets"], "FAIL")
            report["checks"][0]["status"] = "FAIL"
            self.assertEqual(self.validator.summarize(report)["phase5Applets"], "FAIL")

    def test_all_module_identity_fields_are_bound_to_both_preserved_fixtures(self):
        for index in range(2):
            for field in self.report["modules"][index]:
                report = copy.deepcopy(self.report)
                report["modules"][index][field] = 2 if field == "profileClass" else "forged"
                with self.subTest(module=index, field=field), self.assertRaises(ValueError):
                    self.validator.summarize(report)

    def test_integer_profile_classes_reject_boolean_equality_and_float_aliases(self):
        for index, values in ((0, (True, 1.0)), (1, (False, 0.0))):
            for value in values:
                report = copy.deepcopy(self.report)
                report["modules"][index]["profileClass"] = value
                with self.subTest(module=index, value=value), self.assertRaises(ValueError):
                    self.validator.summarize(report)

    def test_process_order_missing_duplicate_and_unknown_module_fields_are_rejected(self):
        modules = self.report["modules"]
        variants = (list(reversed(modules)), modules[:1], [], [modules[0], modules[0]],
                    modules + [modules[1]], [None, modules[1]], {"main": modules[0]})
        for replacement in variants:
            with self.subTest(modules=replacement), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "modules": replacement})
        report = copy.deepcopy(self.report)
        report["modules"][1]["approvedGame"] = True
        with self.assertRaises(ValueError):
            self.validator.summarize(report)
        del report["modules"][1]["approvedGame"]
        del report["modules"][0]["sourceSha256"]
        with self.assertRaises(ValueError):
            self.validator.summarize(report)

    def test_each_unimplemented_capability_and_unchecked_capability_is_rejected(self):
        for name in ("rendererResize", "uiCorrection", "saveSuspend", "audioSuspend", "gpuSuspend", "gameRenderer"):
            report = copy.deepcopy(self.report)
            report["capabilities"][name] = True
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validator.summarize(report)
        report = copy.deepcopy(self.report)
        del report["capabilities"]["gpuSuspend"]
        with self.assertRaises(ValueError):
            self.validator.summarize(report)

    def test_capability_values_require_actual_booleans(self):
        for name in self.report["capabilities"]:
            for value in (0, 1, None, "false", []):
                report = copy.deepcopy(self.report)
                report["capabilities"][name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    self.validator.summarize(report)

    def test_game_and_os_gate_promotions_or_missing_gates_are_rejected(self):
        variants = ({"G1": "PASS"}, {**self.report["gates"], "G0": "PASS"},
                    {**self.report["gates"], "G0": "NOT_VERIFIED"},
                    {**self.report["gates"], "G7": "NOT_RUN"})
        for gates in variants:
            with self.subTest(gates=gates), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "gates": gates})

    def test_wrong_schema_groups_status_detail_and_scope_are_rejected(self):
        for key, value in (("schemaVersion", 6), ("schemaVersion", 7.0), ("schemaVersion", True),
                           ("phase", 5), ("syntheticOnly", 1), ("gamePlayable", 0),
                           ("checks", []), ("checks", {})):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, key: value})
        for replacement in ({"id": "exports", "status": "SKIP", "detail": "skipped"},
                            {"id": "account", "status": "PASS", "detail": "wrong phase"},
                            {"id": "exports", "status": "PASS", "detail": " \n"},
                            {"id": [], "status": "PASS", "detail": "bad ID"}):
            report = copy.deepcopy(self.report)
            report["checks"][0] = replacement
            with self.subTest(check=replacement), self.assertRaises(ValueError):
                self.validator.summarize(report)
        report = copy.deepcopy(self.report)
        report["checks"][1] = report["checks"][0]
        with self.assertRaises(ValueError):
            self.validator.summarize(report)

    def test_only_supported_arm64_page_environments_are_accepted(self):
        for page in (4096, 16384):
            report = copy.deepcopy(self.report)
            report["environment"]["pageSize"] = page
            self.assertEqual(self.validator.summarize(report)["phase5Applets"], "PASS")
        for environment in ({"pageSize": True, "abi": "arm64-v8a"},
                            {"pageSize": 4096.0, "abi": "arm64-v8a"},
                            {"pageSize": 8192, "abi": "arm64-v8a"},
                            {"pageSize": 4096, "abi": "x86_64"}, {}, None):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, "environment": environment})

    def test_cli_writes_pass_and_native_fail_receipts_with_distinct_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "in.json", Path(directory) / "nested/out.json"
            command = [sys.executable, self.validator.__file__, str(source), "--out", str(output)]
            for failed in (False, True):
                self.report["checks"][3]["status"] = "FAIL" if failed else "PASS"
                source.write_text(json.dumps(self.report), encoding="utf-8-sig")
                result = subprocess.run(command, capture_output=True, text=True)
                self.assertEqual(result.returncode, int(failed), result.stderr)
                self.assertEqual(json.loads(output.read_text())["phase5Applets"], "FAIL" if failed else "PASS")

    def test_cli_rejects_nested_duplicate_json_keys_and_nonstandard_constants(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "in.json", Path(directory) / "out.json"
            command = [sys.executable, self.validator.__file__, str(source), "--out", str(output)]
            encoded = json.dumps(self.report)
            variants = (encoded.replace('"schemaVersion": 7', '"schemaVersion":7,"schemaVersion":7'),
                        encoded.replace('"oeCore": true', '"oeCore":true,"oeCore":true'),
                        encoded.replace('"pageSize": 4096', '"pageSize": NaN'))
            for invalid in variants:
                source.write_text(invalid, encoding="utf-8")
                result = subprocess.run(command, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
