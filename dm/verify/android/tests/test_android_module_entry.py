"""Metadata-backed analysis roots without treating an NSO header as code."""
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as ai
from nso_format import parse_nso, parse_metadata
from test_nso_format import mutable_source, write_image, dynamic_slot


def canonical_module():
    source = mutable_source()
    n = parse_nso(source)
    m = parse_metadata(n)
    absolute = [m.mod0 + x for x in struct.unpack_from('<6i', n.image, m.mod0 + 4)]
    absolute[3:5] = [0x4D00, 0x4D14]
    write_image(source, m.mod0, '<28s', bytes(28))
    write_image(source, 0, '<48s', bytes(48))
    write_image(source, 4, '<I', 8)
    write_image(source, 8, '<I6i', 0x30444F4D, *(x - 8 for x in absolute))
    entry = m.dynamic[12]
    write_image(source, 0x4D00, '<BBBBiIii', 1, 0x1B, 3, 0x3B,
                0x4F00 - 0x4D04, 1, entry - 0x4D00, 0x4F00 - 0x4D00)
    # A no-CRT0 module has no function symbol claiming its data header.
    index = next(i for i, symbol in enumerate(m.symbols) if symbol.name == 'fixture_entry')
    write_image(source, m.dynamic[6] + index * 24 + 4, '<BBHQQ', 0x11, 0, 1, 0, 0)
    return source, entry


class ModuleEntryTests(unittest.TestCase):
    def test_aligned_relative_metadata_values_remain_data_and_keep_relocations(self):
        original = mutable_source()
        m = parse_metadata(parse_nso(original))
        index = next(i for i, r in enumerate(m.relocations) if r.kind == 1027)
        for value in (4, m.mod0, m.mod0 + 24):
            source = bytearray(original)
            write_image(source, m.dynamic[7] + index * 24 + 16, '<q', value)
            with self.subTest(value=value):
                _, report = ai.import_module(source, 'main')
                self.assertEqual(report['relocations'][index]['addend'], value)
                self.assertNotIn(value, report['code_discovery']['roots'])
                write_image(source, 0, '<I', 0x14000000 | (value // 4))
                with self.assertRaisesRegex(ai.ImportError, 'control flow reaches MOD0/dynamic metadata'):
                    ai.import_module(source, 'main')
                self.assertEqual(m.relocations[index].offset, 0x8018)
                write_image(source, 0, '<I', 0x140000C0)
                write_image(source, 0x300, '<3I', 0x90000048, 0xF9400D09, 0xD61F0120)
                with self.assertRaisesRegex(ai.ImportError, 'control flow reaches MOD0/dynamic metadata'):
                    ai.import_module(source, 'main')

    def test_canonical_header_uses_corroborated_dt_init_only_as_analysis_entry(self):
        source, entry = canonical_module()
        m = parse_metadata(parse_nso(source))
        index = next(i for i, r in enumerate(m.relocations) if r.kind == 1027)
        write_image(source, m.dynamic[7] + index * 24 + 16, '<q', 0)
        package, report = ai.import_module(source, 'main', package_version=2, callback_audit=True,
                                          indirect_policy='guarded-host', checked_stack=True)
        self.assertEqual(report['rewrite']['entry_offset'], entry)
        self.assertEqual(report['code_discovery']['analysis_entry'], {
            'offset': entry, 'basis': 'canonical-no-crt0-dt-init-eh',
            'non_code_header': [0, 48], 'bootstrap_authority': False})
        self.assertFalse(any(p < 48 for p in report['code_discovery']['roots']))
        self.assertNotIn(0, report['callback_audit']['callback_roots'])
        self.assertEqual(report['relocations'][index]['addend'], 0)
        payload = struct.unpack_from('<Q', package, 112)[0]
        self.assertEqual(package[payload:payload + 48], parse_nso(source).image[:48])
        self.assertEqual(package[296:320], bytes(24))  # No entry/wire extension.

    def test_zero_entry_requires_exact_header_and_eh_corroborated_valid_init(self):
        for mutation, message in (
                ('no-eh', 'EH'), ('padding', 'header'), ('other-mod0', 'header'),
                ('protected-init', 'protected'), ('invalid-init', 'decoded')):
            source, _ = canonical_module()
            if mutation == 'no-eh':
                write_image(source, 8 + 16, '<ii', 0, 0)
            elif mutation == 'padding':
                write_image(source, 36, '<I', 0xD503201F)
            elif mutation == 'other-mod0':
                source = mutable_source()
                write_image(source, 0, '<I', 0)
            else:
                target = 8 if mutation == 'protected-init' else 0x300
                write_image(source, dynamic_slot(source, 12) + 8, '<Q', target)
                write_image(source, 0x4D0C, '<i', target - 0x4D00)
                if mutation == 'invalid-init':
                    write_image(source, target, '<I', 0xFFFFFFFF)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ai.ImportError, message):
                ai.import_module(source, 'main')

    def test_canonical_header_is_still_forbidden_as_actual_branch_target(self):
        source, entry = canonical_module()
        write_image(source, entry, '<I', 0x14000000 | ((-entry // 4) & 0x3FFFFFF))
        with self.assertRaisesRegex(ai.ImportError, 'control flow reaches.*header'):
            ai.import_module(source, 'main', package_version=2, checked_stack=True)

    def test_unaligned_materialized_pointer_before_metadata_remains_unproven(self):
        source = mutable_source()
        target = parse_metadata(parse_nso(source)).mod0 - 2
        delta = target - 0x300
        adr = 0x10000009 | ((delta & 3) << 29) | (((delta >> 2) & 0x7FFFF) << 5)
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<2I', adr, 0xD65F03C0)
        with self.assertRaisesRegex(ai.ImportError, 'unaligned materialized text address'):
            ai.import_module(source, 'main')

    def test_all_clobbered_slots_are_not_revisited_but_every_store_is_reported(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<6I', 0xF9000020, 0xF9000020, 0xF9000020,
                    0x90000048, 0xF9000D00, 0xD65F03C0)
        updates, scans_after_all = [], []
        class CountingSet(set):
            def update(self, values):
                if isinstance(values, dict):
                    updates.append(len(values))
                elif len(self) == len(metadata.relocations):
                    scans_after_all.append(True)
                return super().update(values)
        with patch.object(ai, 'set', CountingSet, create=True):
            _, report = ai.import_module(source, 'main', package_version=2, indirect_policy='guarded-host')
        self.assertEqual(updates, [len(metadata.relocations)])
        self.assertEqual(scans_after_all, [])
        discovery = report['code_discovery']
        self.assertEqual(discovery['relocation_slots_clobbered_by_code'], sorted(r.offset for r in metadata.relocations))
        stores = {row['instruction_offset']: row['range'] for row in discovery['reachable_memory_writes']}
        self.assertEqual({pc: stores[pc] for pc in (0x300, 0x304, 0x308, 0x310)},
                         {0x300: None, 0x304: None, 0x308: None, 0x310: (0x8018, 0x8020)})

    def test_shifted_immediate_sp_frames_preserve_original_instructions(self):
        for amount in (20, 256):  # Actual 80 KiB frame and the 1 MiB limit.
            source = mutable_source()
            write_image(source, 0, '<I', 0x140000C0)
            words = (0xD14003FF | amount << 10, 0x914003FF | amount << 10, 0xD65F03C0)
            write_image(source, 0x300, '<3I', *words)
            package, report = ai.import_module(source, 'main')
            payload = struct.unpack_from('<Q', package, 112)[0]
            self.assertEqual(package[payload + 0x300:payload + 0x30C], struct.pack('<3I', *words))
            self.assertFalse(any(0x300 <= s['offset'] < 0x30C for s in report['rewrite']['sites']))
            self.assertIn('1048576', report['code_discovery']['stack_pointer_policy'])

    def test_unaligned_oversized_and_register_sp_adjustments_remain_refused(self):
        for value in (0xD10007FF, 0xD14407FF, 0x9100011F, 0xCB2063FF):
            source = mutable_source()
            write_image(source, 0, '<I', 0x140000C0)
            write_image(source, 0x300, '<2I', value, 0xD65F03C0)
            with self.subTest(value=hex(value)), self.assertRaisesRegex(ai.ImportError, 'unsupported SP write/pivot'):
                ai.import_module(source, 'main')


if __name__ == '__main__':
    unittest.main()
