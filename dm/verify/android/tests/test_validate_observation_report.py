import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_validate_service_report import load_validator


class ObservationReportTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator("validate_observation_report")
        self.report = {
            "schemaVersion": 6, "phase": "4", "syntheticOnly": True, "gamePlayable": False,
            "checks": [{"id": i, "status": "PASS", "detail": "public fixture contract"}
                       for i in self.validator.REQUIRED_CHECKS],
            "gates": dict(self.validator.REQUIRED_GATES),
            "module": self.validator.expected_module(),
            "environment": {"abi": "arm64-v8a", "pageSize": 4096, "frameBytes": 800,
                            "copyBackend": "owned-mapping-locks",
                            "parameterSeed": [720 << 32 | 1280, 1080 << 32 | 1920, 0x40071c72, 0x40071c72]},
        }
        # Native producer includes target; retain it independently of the
        # validator's expected-module helper to catch producer/schema drift.
        self.report["module"]["target"] = "android-arm64"

    def test_pass_retains_synthetic_scope_and_does_not_verify_installation(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result["phase4Observation"], "PASS")
        self.assertEqual(result["gates"]["G0"], "NOT_VERIFIED")
        self.assertFalse(result["gamePlayable"])
        self.assertTrue(result["limitations"])

    def test_each_failed_native_path_remains_failure(self):
        for i in range(6):
            report = copy.deepcopy(self.report)
            report["checks"][i]["status"] = "FAIL"
            self.assertEqual(self.validator.summarize(report)["phase4Observation"], "FAIL")

    def test_profile_claims_and_identity_changes_are_rejected(self):
        for field in self.report["module"]:
            report = copy.deepcopy(self.report)
            report["module"][field] = 2 if field == "profileClass" else "0" * 64
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validator.summarize(report)
        report = copy.deepcopy(self.report)
        report["module"]["profileClass"] = True
        with self.assertRaises(ValueError):
            self.validator.summarize(report)

    def test_schema_booleans_scope_and_incomplete_coverage_are_rejected(self):
        for key, bad in (("schemaVersion", 6.0), ("phase", 4), ("syntheticOnly", 1),
                         ("gamePlayable", 0), ("gates", {"G1": "PASS"}), ("checks", [])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validator.summarize({**self.report, key: bad})
        for replacement in ({"id": []}, {"id": "ui-clock", "status": "SKIP", "detail": "x"}):
            report = copy.deepcopy(self.report)
            report["checks"][0] = replacement
            with self.assertRaises(ValueError):
                self.validator.summarize(report)

    def test_missing_or_uninitialized_parameter_and_frame_evidence_is_rejected(self):
        for key, value in (("frameBytes", 799), ("copyBackend", "unchecked-memcpy"),
                           ("pageSize", True), ("pageSize", 1), ("pageSize", 8192),
                           ("parameterSeed", [1, 2, 3]), ("parameterSeed", [1, 2, 3, 0]),
                           ("parameterSeed", [1, 2, 3, True]), ("parameterSeed", [1, 2, 3, 2**64])):
            report = copy.deepcopy(self.report)
            report["environment"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.validator.summarize(report)

    def test_native_parameter_validation_is_preserved_in_evidence(self):
        for slot, bad in ((0, 1), (0, 720 << 32), (1, 4097 << 32 | 1920),
                          (2, 0x7f800000), (3, 0x7fc00000), (2, 0x40000000),
                          (3, 0x140071c72)):
            report = copy.deepcopy(self.report)
            report["environment"]["parameterSeed"][slot] = bad
            with self.subTest(slot=slot, bad=bad), self.assertRaises(ValueError):
                self.validator.summarize(report)
        report = copy.deepcopy(self.report)
        report["environment"]["pageSize"] = 16384
        self.assertEqual(self.validator.summarize(report)["phase4Observation"], "PASS")

    def test_cli_rejects_duplicate_json_keys_and_retains_failure_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "in.json", Path(directory) / "out.json"
            validator_path = Path(self.validator.__file__)
            source.write_text('{"schemaVersion":6,"schemaVersion":6}', encoding="utf-8")
            command = [sys.executable, str(validator_path), str(source), "--out", str(output)]
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertFalse(output.exists())
            self.report["checks"][0]["status"] = "FAIL"
            source.write_text(json.dumps(self.report), encoding="utf-8")
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 1)
            self.assertEqual(json.loads(output.read_text())["phase4Observation"], "FAIL")
