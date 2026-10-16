"""Self-authored forest dispatch executes on an actual AArch64 emulator."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import android_import as importer
import taiko_call_contract as contract
import test_taiko_checked_call as fixed
from unicorn import arm64_const as uc


def fixture(count=63):
    callback = fixed.fixture()[0][0x100:]
    targets = tuple(0x100 + index * 0x200 for index in range(count))
    source = bytearray(targets[-1] + len(callback))
    source[:8] = fixed.raw(0xD63F0240, 0xD4200020)
    ranges = [(0, 8)]
    for target in targets:
        source[target:target + len(callback)] = callback
        ranges.append((target, target + len(callback)))
    return bytes(source), ranges, targets


def rewritten(count=63, **options):
    source, ranges, targets = fixture(count)
    return ar.rewrite(source, code_ranges=ranges, entry_offsets=[0, *targets],
                      package_version=2, checked_stack=True,
                      checked_call_forest_offsets=(0,), checked_call_forest_targets=targets,
                      **options), targets


def destination(word, pc):
    displacement = word & 0x3FFFFFF
    if displacement & 0x2000000:
        displacement -= 0x4000000
    return pc + displacement * 4


class CallForestTests(unittest.TestCase):
    def test_explicit_entry_origins_require_every_forest_target_to_be_independent(self):
        _, _, targets = fixture(3)
        with self.assertRaisesRegex(ar.RewriteError, 'independent'):
            rewritten(3, independent_entry_offsets=(0, *targets[:-1]))
        rewritten(3, independent_entry_offsets=(0, *targets))

    def test_first_median_last_and_deep_leaf_preserve_real_callee_observations(self):
        image, targets = rewritten()
        for target in (targets[0], targets[len(targets) // 2], targets[-1], targets[5]):
            for flags in (0, 0xB0000000):
                with self.subTest(target=hex(target), flags=flags):
                    machine = fixed.CheckedCallTests()
                    machine.image = lambda: image
                    result = machine.execute(lambda base: base + target, flags=flags, target_offset=target)
                    self.assertTrue(result['target'])
                    self.assertTrue(result['returned'])
                    self.assertFalse(result['trapped'])
                    cpu, output = result['cpu'], result['output']
                    expected = result['expected'][:]
                    expected[18], expected[30] = result['virtual'], 0x10000004
                    self.assertEqual(expected, list(struct.unpack('<31Q', cpu.mem_read(output, 248))))
                    self.assertEqual((flags, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
                    self.assertEqual(result['arguments'], bytes(cpu.mem_read(output + 0x310, 16)))
                    for index, vector in enumerate(result['vectors']):
                        self.assertEqual(vector, int.from_bytes(cpu.mem_read(output + 0x100 + index * 16, 16), 'little'))

    def test_null_unknown_holes_interiors_and_cross_module_addresses_trap_after_restore(self):
        image, targets = rewritten()
        for value in (0, 0x10000000 + targets[0] + 4, 0x10000000 + targets[10] - 4,
                      0x10000000 + targets[-1] + 0x200, 0x20000000 + targets[0],
                      0x10000000 + targets[0] + 1, 0xFFFFFFFFFFFFFFFF):
            with self.subTest(value=hex(value)):
                machine = fixed.CheckedCallTests()
                machine.image = lambda: image
                result = machine.execute(value)
                self.assertTrue(result['trapped'])
                self.assertFalse(result['target'])
                self.assertFalse(result['returned'])
                cpu = result['cpu']
                for index, expected in enumerate(result['expected']):
                    self.assertEqual(expected, cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{index}')))
                for index, expected in enumerate(result['vectors']):
                    self.assertEqual(expected, cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{index}')))
                self.assertEqual(0xB0000000, cpu.reg_read(uc.UC_ARM64_REG_NZCV))

    def test_every_node_has_one_exact_target_and_only_expected_child_or_failure_edges(self):
        image, targets = rewritten(1023)
        geometry = image.metadata()['checked_call_forests'][0]
        source, _, _ = fixture(1023)
        self.assertEqual(len(source), geometry['start'])
        self.assertEqual(60, geometry['node_size'])
        self.assertEqual(60, geometry['stub_size'])
        self.assertEqual(64, geometry['frame_size'])
        self.assertEqual(len(targets), geometry['target_count'])
        self.assertEqual(hashlib.sha256(struct.pack('<' + 'Q' * len(targets), *targets)).hexdigest(), geometry['target_sha256'])
        self.assertEqual(geometry['start'] + 60 * len(targets), geometry['failure_offset'])
        self.assertEqual(geometry['failure_offset'] + 28, geometry['end'])
        observed = []
        def inspect(lo, hi, index, depth):
            middle = (lo + hi) // 2
            pc = geometry['start'] + index * 60
            words = struct.unpack_from('<15I', image.bytes, pc)
            self.assertEqual(0x90000001, words[0] & 0x9F00001F)
            immediate = (words[0] >> 29 & 3) | (words[0] >> 5 & 0x7FFFF) << 2
            if immediate & (1 << 20): immediate -= 1 << 21
            self.assertEqual(targets[middle], (pc & ~4095) + immediate * 4096 + (words[1] >> 10 & 4095))
            self.assertEqual((0xEB01001F, 0x54000080, 0x54000043), words[2:5])
            failure = geometry['failure_offset']
            right = geometry['start'] + (index + 1 + middle - lo) * 60 if middle + 1 < hi else failure
            left = geometry['start'] + (index + 1) * 60 if lo < middle else failure
            self.assertEqual(right, destination(words[5], pc + 20))
            self.assertEqual(left, destination(words[6], pc + 24))
            self.assertEqual(targets[middle], destination(words[14], pc + 56))
            observed.append(targets[middle])
            deepest = depth
            if lo < middle: deepest = max(deepest, inspect(lo, middle, index + 1, depth + 1))
            if middle + 1 < hi: deepest = max(deepest, inspect(middle + 1, hi, index + 1 + middle - lo, depth + 1))
            return deepest
        self.assertEqual(geometry['max_depth'], inspect(0, len(targets), 0, 1))
        self.assertEqual(list(targets), sorted(observed))
        self.assertEqual([], image.metadata()['gates'])

    def test_unchecked_unsorted_duplicate_unselected_and_overlapping_maps_fail_closed(self):
        source, ranges, targets = fixture(3)
        for invalid in ((targets[1], targets[0]), (*targets, targets[0]), (0,), (True,), (0x104,)):
            with self.subTest(targets=invalid), self.assertRaises(ar.RewriteError):
                ar.rewrite(source, code_ranges=ranges, entry_offsets=[0, *targets], package_version=2,
                           checked_stack=True, checked_call_forest_offsets=(0,), checked_call_forest_targets=invalid)
        for extra in ({}, {'package_version': 2}, {'checked_stack': True}):
            with self.subTest(options=extra), self.assertRaises(ar.RewriteError):
                ar.rewrite(source, code_ranges=ranges, entry_offsets=[0, *targets],
                           checked_call_forest_offsets=(0,), checked_call_forest_targets=targets, **extra)
        with self.assertRaises(ar.RewriteError):
            ar.rewrite(source, code_ranges=ranges, entry_offsets=[0, *targets], package_version=2,
                       checked_stack=True, checked_call_forest_offsets=(0,), checked_call_forest_targets=targets,
                       checked_call_targets={0: targets[0]})

    def test_direct_target_branch_range_overflow_is_a_specific_closed_failure(self):
        with self.assertRaisesRegex(ar.RewriteError, 'forest.*branch.*range'):
            rewritten(1, patch_offset=(1 << 27) + 4096)

    def test_compiled_selector_uses_full_validated_eh_set_and_propagates_parser_failure(self):
        nso, metadata, _ = fixed.CallContractTests().fixture()
        chain = (0xF9400F11, 0xF9406231, 0xF9401A32, 0xF9400252,
                 0xA90427E8, 0xB90053EA, 0xA90233EB, 0xA90337EE,
                 0xA9013FF0, 0xF9401A22, 0xD63F0240)
        nso.image.update({0x2927004 + index: value for index, value in enumerate(fixed.raw(*chain))})
        records = tuple(SimpleNamespace(start=start, end=end, fde=0x4000 + index * 32, cie=0x3000)
                        for index, (start, end) in enumerate(((0x100, 0x140), (0xDB9050, 0xDB9100),
                                                             (0x2926E60, 0x2927164))))
        digest = hashlib.sha256(struct.pack('<3Q', *(record.start for record in records))).hexdigest()
        parser = SimpleNamespace(validated_eh_functions=lambda n, m: records,
                                 eh_target_set_sha256=lambda r: digest)
        with patch.dict(sys.modules, {'nso_eh': parser}):
            selected = contract.select_checked_call_forest(nso, metadata)
            self.assertEqual(tuple(record.start for record in records), selected['targets'])
            self.assertEqual(digest, selected['target_sha256'])
            self.assertEqual(0x292702C, selected['offset'])
            import taiko_forest_audit as independent_audit
            self.assertEqual((selected['caller_eh_start'], selected['caller_eh_end'], selected['target_policy']),
                             (independent_audit.CALLER_START, independent_audit.CALLER_END,
                              independent_audit.POLICY))
            # This EH entry has no relocation-backed function-pointer intersection.
            self.assertIn(0x100, selected['targets'])
            nso.image[0x2927004] = nso.image.get(0x2927004, 0) ^ 1
            with self.assertRaisesRegex(ValueError, 'pointer chain changed'):
                contract.select_checked_call_forest(nso, metadata)
            nso.image[0x2927004] = nso.image.get(0x2927004, 0) ^ 1
            parser.validated_eh_functions = lambda n, m: (_ for _ in ()).throw(ValueError('bad CIE/FDE'))
            with self.assertRaisesRegex(ValueError, 'bad CIE/FDE'):
                contract.select_checked_call_forest(nso, metadata)
        nso.build_id = bytes(32)
        self.assertIsNone(contract.select_checked_call_forest(nso, metadata))

    def test_importer_audits_every_added_target_and_emits_compact_receipts_without_new_callbacks(self):
        from nso_format import parse_nso, parse_metadata
        from test_nso_format import mutable_source, write_image
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        main = next(symbol for symbol in metadata.symbols if symbol.name == 'fixture_main')
        entry = main.value
        replacement = [0xD63F0240, 0xD65F03C0] + [0xD503201F] * (main.size // 4 - 2)
        write_image(source, entry, '<' + 'I' * len(replacement), *replacement)
        write_image(source, 0x500, '<I', 0xD65F03C0)
        selected = dict(offset=entry, source_word=0xD63F0240, targets=(0x500,), target_count=1,
                        target_sha256=hashlib.sha256(struct.pack('<Q', 0x500)).hexdigest(),
                        rule='self-authored-test-selector')
        # Only the internal trusted selector is substituted; import exposes no target-list argument.
        with patch.object(importer, 'select_checked_call_forest', return_value=selected):
            _, report = importer.import_module(source, 'main', package_version=2, checked_stack=True,
                                               indirect_policy='guarded-host', callback_audit=True)
        self.assertIn(0x500, report['code_discovery']['roots'])
        self.assertTrue(any(lo <= 0x500 < hi for lo, hi in report['code_ranges']))
        self.assertNotIn(0x500, report['callback_audit']['callback_roots'])
        receipt = report['code_discovery']['versioned_checked_call_forests'][0]
        self.assertNotIn('targets', receipt)
        self.assertEqual(1, receipt['target_count'])
        self.assertEqual(1, report['rewrite']['checked_call_forests'][0]['node_count'])
        self.assertNotIn(entry, report['code_discovery']['guarded_indirect_sites'])


if __name__ == '__main__': unittest.main()
