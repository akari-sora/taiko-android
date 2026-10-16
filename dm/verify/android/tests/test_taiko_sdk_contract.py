"""Pinned SDK selection and independent, self-authored layout boundary tests."""
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
from nso_format import Nso, Section, parse_nso
import taiko_sdk_contract as contract
import android_import as importer
from nso_format import parse_metadata


class SyntheticLayoutTests(unittest.TestCase):
    def setUp(self):
        # Self-authored bytes have no production identity or authority. They
        # exercise the private boundary validator without changing any pin.
        image = bytearray(0x300)
        for offset in range(0x20, 0x20 + 244, 4):
            struct.pack_into('<I', image, offset, 0xD503201F)
        literal = 0x20 + 0x74
        struct.pack_into('<i', image, literal, 0x240 - literal)
        body = bytearray(image[0x20:0x20 + 244])
        body[0x74:0x78] = bytes(4)
        self.layout = contract.SdkInlineLayout(
            source_sha256='11' * 32, build_id='22' * 32,
            function_start=0x20, function_end=0x20 + 244,
            body_sha256=hashlib.sha256(body).hexdigest(), target_bss=0x240)
        self.nso = Nso(bytes(image),
                       (Section('text', 0, 0x120), Section('ro', 0x140, 0x40),
                        Section('data', 0x200, 0x20)),
                       0xE0, bytes.fromhex('22' * 32), bytes.fromhex('11' * 32),
                       0, (0, 0), (0, 0))

    def test_independent_boundary_fixture_never_receives_production_selection(self):
        self.assertEqual(contract._verify_layout(self.nso, self.layout), self.layout)
        self.assertIsNone(contract.select_sdk_inline_layout(self.nso))
        forged = replace(self.nso, source_sha256=bytes.fromhex(contract.SDK_SHA256),
                         build_id=bytes.fromhex(contract.SDK_BUILD_ID))
        self.assertIsNone(contract.select_sdk_inline_layout(forged))

    def test_body_mutations_receive_no_layout(self):
        for relative in (0, 0x70, 0x78, 0xDC, 0xE0, 0xE4, 0xE8, 0xF0):
            image = bytearray(self.nso.image)
            image[self.layout.function_start + relative] ^= 1
            with self.subTest(relative=relative):
                self.assertIsNone(contract._verify_layout(replace(self.nso, image=bytes(image)), self.layout))

    def test_signed_literal_target_and_28_byte_bss_object_fail_closed(self):
        literal = self.layout.literal_start
        for target in (0x10, 0x21C, 0x244, len(self.nso.image) - 24):
            image = bytearray(self.nso.image)
            struct.pack_into('<i', image, literal, target - literal)
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'BSS object'):
                contract._verify_layout(replace(self.nso, image=bytes(image)), self.layout)
        sections = self.nso.sections[:2] + (Section('data', 0x200, 0x44),)
        with self.assertRaisesRegex(ValueError, 'BSS object'):
            contract._verify_layout(replace(self.nso, sections=sections, bss_size=0xBC), self.layout)
        with self.assertRaisesRegex(ValueError, 'BSS extent'):
            contract._verify_layout(replace(self.nso, bss_size=0xDC), self.layout)
        exact_end = self.layout.target_bss + 28
        exact = replace(self.nso, image=self.nso.image[:exact_end],
                        bss_size=exact_end - self.nso.sections[2].end)
        self.assertEqual(contract._verify_layout(exact, self.layout), self.layout)
        short = replace(exact, image=exact.image[:-1], bss_size=exact.bss_size - 1)
        with self.assertRaisesRegex(ValueError, 'BSS object'):
            contract._verify_layout(short, self.layout)

    def test_helper_extent_must_be_fully_original_text(self):
        sections = (Section('text', 0, self.layout.function_end - 4),) + self.nso.sections[1:]
        self.assertIsNone(contract._verify_layout(replace(self.nso, sections=sections), self.layout))


SDK = Path('C:/Users/aa223/Documents/Codex/2026-10-12/10m-10s-jhaizhou-ops-d2r-mobile/games/taiko-extract/ExeFS/sdk')


@unittest.skipUnless(SDK.is_file(), 'local verified Taiko SDK required; no game bytes embedded')
class PinnedSdkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nso = parse_nso(SDK.read_bytes())
        cls.metadata = parse_metadata(cls.nso)

    def test_exact_original_selects_complete_relative_layout(self):
        layout = contract.select_sdk_inline_layout(self.nso)
        self.assertIsNotNone(layout)
        self.assertEqual((layout.function_start, layout.function_end, layout.call_offset,
                          layout.literal_start, layout.reader_offset, layout.target_bss),
                         (0x380758, 0x38084C, 0x3807C8, 0x3807CC, 0x3807D0, 0xD6E580))
        self.assertEqual(layout.restore_offsets, (0x380834, 0x380838, 0x38083C))
        self.assertEqual(layout.return_offsets, (0x380840,))

    def test_wrong_source_build_or_any_semantic_body_change_is_not_selected(self):
        self.assertIsNone(contract.select_sdk_inline_layout(replace(self.nso, source_sha256=bytes(32))))
        self.assertIsNone(contract.select_sdk_inline_layout(replace(self.nso, build_id=bytes(32))))
        for relative in (0, 0x70, 0x78, 0xDC, 0xE0, 0xE4, 0xE8, 0xF0):
            image = bytearray(self.nso.image)
            image[0x380758 + relative] ^= 1
            with self.subTest(relative=relative):
                self.assertIsNone(contract.select_sdk_inline_layout(replace(self.nso, image=bytes(image))))

    def test_pinned_literal_must_still_reference_exact_bss_object(self):
        image = bytearray(self.nso.image)
        struct.pack_into('<i', image, 0x3807CC, 4)
        with self.assertRaisesRegex(ValueError, 'BSS object'):
            contract.select_sdk_inline_layout(replace(self.nso, image=bytes(image)))
        with self.assertRaises(importer.ImportError):
            importer._sdk_inline_lr_literal(replace(self.nso, image=bytes(image)), self.metadata, set())

    def test_complete_original_lr_sp_proof_excludes_the_literal(self):
        proof = importer._sdk_inline_lr_literal(self.nso, self.metadata, {0x380758})
        self.assertEqual(proof['return_offsets'], [0x380840])
        self.assertEqual(len(proof['proven_instruction_offsets']), 60)
        self.assertNotIn(0x3807CC, proof['proven_instruction_offsets'])
        self.assertTrue({0x380758, 0x3807D0, 0x380834, 0x380838, 0x38083C}
                        <= set(proof['proven_instruction_offsets']))

    def test_independent_interior_roots_and_literal_metadata_are_rejected(self):
        for root in (0x3807CC, 0x3807D0, 0x380834, 0x380838, 0x38083C, 0x380840):
            with self.subTest(root=root), self.assertRaisesRegex(importer.ImportError, 'metadata/interior'):
                importer._sdk_inline_lr_literal(self.nso, self.metadata, {root})
        metadata = replace(self.metadata, protected=self.metadata.protected + ((0x3807CC, 0x3807D0),))
        with self.assertRaisesRegex(importer.ImportError, 'metadata/interior'):
            importer._sdk_inline_lr_literal(self.nso, metadata, set())

    def test_external_direct_and_materialized_interior_entries_are_rejected(self):
        pc = 0x380900
        for target in (0x3807CC, 0x3807D0, 0x38083C):
            image = bytearray(self.nso.image)
            struct.pack_into('<I', image, pc, 0x14000000 | (((target - pc) // 4) & 0x3FFFFFF))
            with self.subTest(branch_target=target), self.assertRaisesRegex(importer.ImportError, 'direct/interior'):
                importer._sdk_inline_lr_literal(replace(self.nso, image=bytes(image)), self.metadata, set())
        image = bytearray(self.nso.image)
        delta = (0x3807D0 - pc) & 0x1FFFFF
        struct.pack_into('<I', image, pc, 0x10000000 | (delta & 3) << 29 | (delta >> 2) << 5)
        with self.assertRaisesRegex(importer.ImportError, 'materialized interior'):
            importer._sdk_inline_lr_literal(replace(self.nso, image=bytes(image)), self.metadata, set())
        image = bytearray(self.nso.image)
        struct.pack_into('<II', image, pc, 0x90000000, 0x91000000 | (0x7D0 << 10))
        with self.assertRaisesRegex(importer.ImportError, 'materialized interior'):
            importer._sdk_inline_lr_literal(replace(self.nso, image=bytes(image)), self.metadata, set())


if __name__ == '__main__':
    unittest.main()
