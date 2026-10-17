"""Host-only DMAMOD03 wire, digest and importer regressions."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[4]
LIVE = Path(os.environ.get("TAIKO_LIVE_REPO", ROOT))
sys.path[:0] = [str(ROOT / "dm/tools"), str(LIVE / "dm/tools")]

import android_guest_contract as contract
import android_import as importer
from android_rewrite import Gate, GateProvenance, Image


FIXTURE = ROOT / "dm/verify/android/fixtures/dmamod03_v1_golden.json"


class GuestContractRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.exact_bytes = bytes.fromhex(cls.golden["exact_record"]["hex"])
        cls.retire_bytes = bytes.fromhex(cls.golden["retire_record"]["hex"])

    def test_exact_record_matches_independent_288_byte_golden(self):
        record = contract.ExactGuestRecordV1.unpack(self.exact_bytes)
        self.assertEqual(record.pack(), self.exact_bytes)
        self.assertEqual(len(record.pack()), 288)
        self.assertEqual(record.original_br_offset, 0x140)
        self.assertEqual(record.target_register, 17)
        self.assertEqual(record.relocation_addend, -5)
        self.assertEqual(hashlib.sha256(record.pack()).hexdigest(), self.golden["exact_record"]["sha256"])

    def test_retire_record_matches_independent_192_byte_golden(self):
        record = contract.ReturningRetireRecordV1.unpack(self.retire_bytes)
        self.assertEqual(record.pack(), self.retire_bytes)
        self.assertEqual(len(record.pack()), 192)
        self.assertEqual(record.source_callsite, 0x300)
        self.assertEqual(record.stub_extent, 8)
        self.assertEqual(hashlib.sha256(record.pack()).hexdigest(), self.golden["retire_record"]["sha256"])

    def test_record_reserved_schema_register_and_range_negatives(self):
        for position in (55, 272, 287):
            bad = bytearray(self.exact_bytes); bad[position] ^= 1
            with self.subTest(exact_reserved=position), self.assertRaises(contract.GuestContractError):
                contract.ExactGuestRecordV1.unpack(bytes(bad))
        exact = contract.ExactGuestRecordV1.unpack(self.exact_bytes)
        for changed in (replace(exact, schema=2), replace(exact, flags=1),
                        replace(exact, target_register=16), replace(exact, original_br_word=0),
                        replace(exact, function_end=exact.function_start),
                        replace(exact, same_module_target_offset=exact.function_end)):
            with self.subTest(changed=changed), self.assertRaises(contract.GuestContractError):
                changed.pack()
        retire = contract.ReturningRetireRecordV1.unpack(self.retire_bytes)
        for changed in (replace(retire, schema=2), replace(retire, flags=1),
                        replace(retire, stub_extent=12), replace(retire, original_bl_word=0),
                        replace(retire, normal_return=retire.normal_return + 4),
                        replace(retire, matching_store=retire.function_end)):
            with self.subTest(changed=changed), self.assertRaises(contract.GuestContractError):
                changed.pack()

    def test_tables_require_pre_sorted_unique_typed_records(self):
        exact = contract.ExactGuestRecordV1.unpack(self.exact_bytes)
        later = replace(exact, original_br_offset=0x180)
        self.assertEqual(contract.pack_exact_guest_table((exact, later)), self.exact_bytes + later.pack())
        for rows in ((later, exact), (exact, exact)):
            with self.subTest(rows=rows), self.assertRaisesRegex(contract.GuestContractError, "sorted"):
                contract.pack_exact_guest_table(rows)
        retire = contract.ReturningRetireRecordV1.unpack(self.retire_bytes)
        later_retire = replace(retire, source_callsite=0x320, normal_return=0x324)
        self.assertEqual(contract.pack_returning_retire_table((retire, later_retire)),
                         self.retire_bytes + later_retire.pack())
        with self.assertRaises(contract.GuestContractError):
            contract.pack_returning_retire_table((later_retire, retire))

    def test_all_canonical_digest_domains_match_independent_golden(self):
        g = self.golden
        self.assertEqual(hashlib.sha256(bytes.fromhex(g["symbol_name"]["hex"])).hexdigest(), g["symbol_name"]["sha256"])
        self.assertEqual(hashlib.sha256(bytes.fromhex(g["function"]["hex"])).hexdigest(), g["function"]["sha256"])
        self.assertEqual(g["eh_kind_0_sha256"], "0" * 64)
        self.assertEqual(hashlib.sha256(bytes.fromhex(g["eh_kind_1"]["preimage_hex"])).hexdigest(), g["eh_kind_1"]["sha256"])
        self.assertEqual(hashlib.sha256(bytes.fromhex(g["roots"]["preimage_hex"])).hexdigest(), g["roots"]["sha256"])
        self.assertEqual(contract.canonical_json(g["ownership"]["object"]).decode(), g["ownership"]["canonical"])
        self.assertEqual(contract.ownership_proof_sha256(g["ownership"]["object"]).hex(), g["ownership"]["sha256"])
        self.assertEqual(contract.canonical_json(g["recipe"]["object"]).decode(), g["recipe"]["canonical"])
        self.assertEqual(contract.toolset_recipe_sha256(g["recipe"]["object"]).hex(), g["recipe"]["sha256"])
        self.assertEqual(contract.canonical_json(g["audit"]["object_without_identity"]).decode(), g["audit"]["canonical"])
        self.assertEqual(contract.audit_identity_sha256(g["audit"]["object_without_identity"]).hex(),
                         g["audit"]["audit_identity_sha256"])

    def test_strict_json_schemas_reject_extra_unsorted_or_stale_identity(self):
        g = self.golden
        recipe = json.loads(json.dumps(g["recipe"]["object"]))
        recipe["extra"] = 1
        with self.assertRaises(contract.GuestContractError):
            contract.toolset_recipe_sha256(recipe)
        recipe = json.loads(json.dumps(g["recipe"]["object"]))
        recipe["files"].reverse()
        with self.assertRaises(contract.GuestContractError):
            contract.toolset_recipe_sha256(recipe)
        proof = json.loads(json.dumps(g["ownership"]["object"]))
        proof["leave_monitor"]["terminal_facts"][0]["live"] = True
        with self.assertRaises(contract.GuestContractError):
            contract.ownership_proof_sha256(proof)
        audit = dict(g["audit"]["object_without_identity"])
        audit["audit_identity_sha256"] = g["audit"]["audit_identity_sha256"]
        contract.validate_trusted_audit_v1(audit)
        audit["audit_identity_sha256"] = "ff" * 32
        with self.assertRaisesRegex(contract.GuestContractError, "identity"):
            contract.validate_trusted_audit_v1(audit)


class GuestContractImporterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.golden = json.loads(FIXTURE.read_text(encoding="utf-8"))
        cls.exact = contract.ExactGuestRecordV1.unpack(bytes.fromhex(cls.golden["exact_record"]["hex"]))
        cls.retire = contract.ReturningRetireRecordV1.unpack(bytes.fromhex(cls.golden["retire_record"]["hex"]))
        cls.nso = SimpleNamespace(
            sections=(SimpleNamespace(offset=0, size=0x800),
                      SimpleNamespace(offset=0x800, size=0x200),
                      SimpleNamespace(offset=0xA00, size=0x200)),
            image=bytes(0xC00), bss_size=0,
            build_id=bytes.fromhex("22" * 32), source_sha256=bytes.fromhex("11" * 32))
        cls.metadata = SimpleNamespace(symbols=(object(),), string_size=64)

    def image(self, *, typed: bool) -> Image:
        body = bytearray(0x4200)
        gates = ()
        provenance = ()
        exact = ()
        retire = ()
        if typed:
            struct.pack_into("<I", body, self.exact.gate_return_offset - 4, 0xD63F03C0)
            struct.pack_into("<I", body, self.exact.original_br_offset, self.exact.original_br_word)
            gates = (Gate(self.exact.gate_return_offset, contract.DM_GUEST_EXACT_GUEST, 17),)
            provenance = (GateProvenance(self.exact.gate_return_offset,
                                         self.exact.original_br_offset,
                                         self.exact.original_br_word, 0),)
            exact = (self.exact,)
            retire = (self.retire,)
        return Image(bytes(body), 0, (), gates, (), gate_provenance=provenance,
                     package_version=3, checked_stack=True,
                     exact_guest_records=exact, returning_retire_records=retire)

    def test_canonical_empty_v3_geometry_and_distinguished_digests(self):
        package = importer.make_package("main", self.nso, self.metadata, self.image(typed=False), 0x4000, 3)
        self.assertEqual(package[:8], b"DMAMOD03")
        self.assertEqual(struct.unpack_from("<III", package, 8), (3, 0x444D4101, 512))
        self.assertEqual(struct.unpack_from("<I", package, 20)[0], 1)
        payload = struct.unpack_from("<Q", package, 112)[0]
        exact_offset, exact_count, exact_stride, exact_schema = struct.unpack_from("<QQII", package, 384)
        retire_offset, retire_count, retire_stride, retire_schema = struct.unpack_from("<QQII", package, 408)
        self.assertEqual((exact_offset, exact_count, exact_stride, exact_schema), (512, 0, 288, 1))
        self.assertEqual((retire_offset, retire_count, retire_stride, retire_schema), (512, 0, 192, 1))
        self.assertEqual(package[432:496], bytes(64))
        self.assertEqual(package[496:512], bytes(16))
        self.assertEqual(payload, 512)
        self.assertEqual(len(package), 512 + 0x4200)

    def test_canonical_nonempty_v3_geometry_bits_digests_and_final_padding(self):
        package = importer.make_package("sdk", self.nso, self.metadata, self.image(typed=True), 0x4000, 3)
        flags = struct.unpack_from("<I", package, 20)[0]
        self.assertEqual(flags, 1 | contract.DM_MODULE_REQUIRE_EXACT_GUEST_V1 |
                         contract.DM_MODULE_REQUIRE_RETURNING_RETIRE_V1)
        gate_offset, gate_count = struct.unpack_from("<QQ", package, 136)
        parameter_offset, parameter_count = struct.unpack_from("<QQ", package, 360)
        exact_offset, exact_count, exact_stride, exact_schema = struct.unpack_from("<QQII", package, 384)
        retire_offset, retire_count, retire_stride, retire_schema = struct.unpack_from("<QQII", package, 408)
        payload = struct.unpack_from("<Q", package, 112)[0]
        self.assertEqual((gate_offset, gate_count), (512, 1))
        self.assertEqual((parameter_offset, parameter_count), (544, 0))
        self.assertEqual((exact_offset, exact_count, exact_stride, exact_schema), (544, 1, 288, 1))
        self.assertEqual((retire_offset, retire_count, retire_stride, retire_schema), (832, 1, 192, 1))
        self.assertEqual(package[exact_offset:exact_offset + 288], self.exact.pack())
        self.assertEqual(package[retire_offset:retire_offset + 192], self.retire.pack())
        self.assertEqual(package[432:464], hashlib.sha256(self.exact.pack()).digest())
        self.assertEqual(package[464:496], hashlib.sha256(self.retire.pack()).digest())
        self.assertEqual(payload, 1024)
        self.assertEqual(package[retire_offset + 192:payload], b"")

    def test_typed_tables_cannot_be_smuggled_into_old_versions_or_without_stack(self):
        image = self.image(typed=True)
        for version in (1, 2):
            with self.subTest(version=version), self.assertRaises((importer.ImportError, ValueError)):
                importer.make_package("sdk", self.nso, self.metadata, image, 0x4000, version)
        with self.assertRaisesRegex((importer.ImportError, ValueError), "checked"):
            importer.make_package("sdk", self.nso, self.metadata, replace(image, checked_stack=False), 0x4000, 3)

    def test_frozen_v1_v2_complete_package_bytes_remain_identical(self):
        source = (LIVE / "dm/platform/android/module_fixtures/main.nso").read_bytes()
        expected = {
            1: (50000, 448, "5ca925cf41da3a420ca4a649168f9930c841a293f8a2948cdfafe555e109ad38"),
            2: (50064, 512, "7e0aa9f9f8728ac698a803c84d97c330a6b5d2a0cc927f61f2b0b893564445c3"),
        }
        for version, (size, payload, digest) in expected.items():
            with self.subTest(version=version):
                package, _ = importer.import_module(source, "main", package_version=version)
                self.assertEqual((len(package), struct.unpack_from("<Q", package, 112)[0], hashlib.sha256(package).hexdigest()),
                                 (size, payload, digest))
        ordinary, _ = importer.import_module(source, "main", package_version=2)
        audited, _ = importer.import_module(source, "main", package_version=2, callback_audit=True)
        self.assertEqual(audited, ordinary)

    def test_production_import_path_can_only_emit_canonical_empty_v3_foundation(self):
        source = (LIVE / "dm/platform/android/module_fixtures/main.nso").read_bytes()
        package, report = importer.import_module(source, "main", package_version=3)
        self.assertEqual(package[:8], b"DMAMOD03")
        self.assertEqual(struct.unpack_from("<I", package, 20)[0], 0)
        self.assertEqual(struct.unpack_from("<Q", package, 392)[0], 0)
        self.assertEqual(struct.unpack_from("<Q", package, 416)[0], 0)
        self.assertEqual(package[432:496], bytes(64))
        self.assertEqual(report["package_sha256"], hashlib.sha256(package).hexdigest())


if __name__ == "__main__":
    unittest.main(verbosity=2)
