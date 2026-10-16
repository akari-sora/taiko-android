"""A hoisted RO byte table with a preserved four-instruction ALU schedule."""
import hashlib
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_runtime_ro_table import assert_normalized_guard

VALUES = (86, 90, 95, 97, 99, 103, 106, 108, 110, 114, 117, 120, 0, 0, 0, 123, 126, 129, 133, 0, 136)
COMPARE, LOAD, BRANCH, BASE = 0x44C, 0x468, 0x474, 0x380


def fixture():
    source = source_base()
    write_image(source, 0x300, '<7I', 0x52800312, 0xD503201F, 0xD503201F, 0xD503201F,
                0x90000020, 0x91200000, ar.branch(0x318, COMPARE))
    write_image(source, COMPARE, '<11I',
                0x710052DF, 0x54000008 | (((BASE - (COMPARE + 4)) // 4 & 0x7FFFF) << 5),
                0xF940367A, 0x8B070AF5, 0x8B0A02B5, 0x9B0B68E7,
                adr(LOAD - 4, BASE, 26), 0x3876681B, 0x8B1B0B5A, 0x910110E7, 0xD61F0340)
    write_image(source, 0x4800, '<21B', *VALUES)
    write_image(source, BASE + VALUES[-1] * 4, '<3I', 0xD503201F, 0xB90000F2, 0xD65F03C0)
    return source


def plan(source, *, entries=(), readonly=((0x4000, 0x8000),)):
    raw = parse_nso(source).image
    by_pc = {}
    for pc in range(0x300, 0x1000, 4):
        instruction = ar.decode(struct.unpack_from('<I', raw, pc)[0], pc)
        by_pc[pc] = instruction if isinstance(instruction, ar.FatalWord) else ar.Instruction(instruction)
    return ar._scheduled_native_readonly_table(by_pc[BRANCH], by_pc, set(entries), raw, readonly)


def rewritten(source, **changes):
    nso = parse_nso(source)
    options = dict(entry_offset=0x300, text_size=nso.sections[0].size, code_ranges=((0x300, 0x1000),),
                   package_version=2, checked_stack=True, proven_guest_indirect_offsets=(BRANCH,),
                   readonly_ranges=((0x4000, 0x8000),))
    return ar.rewrite(nso.image, **(options | changes))


class TaikoSubsdkDispatchTests(unittest.TestCase):
    def test_full_import_discovers_last_w18_case_without_changing_scheduled_effects(self):
        source = fixture()
        package, report = ai.import_module(source, 'main', package_version=2,
                                           checked_stack=True, indirect_policy='guarded-host')
        proof = next(item for item in report['code_discovery']['readonly_guest_jump_tables'] if item['offset'] == BRANCH)
        self.assertEqual('runtime-native-backward-alu-byte-ro-lsl2-v1', proof['rule'])
        self.assertEqual((0x4800, 21, sorted(set(VALUES))),
                         (proof['table_offset'], proof['table_bytes'], proof['target_values']))
        self.assertEqual(hashlib.sha256(bytes(VALUES)).hexdigest(), proof['table_sha256'])
        last = BASE + VALUES[-1] * 4
        self.assertIn(last, report['code_discovery']['roots'])
        self.assertIn(last + 4, [item['offset'] for item in report['rewrite']['sites']])
        payload = struct.unpack_from('<Q', package, 112)[0]
        original = parse_nso(source).image
        for begin, end in ((COMPARE + 8, LOAD), (LOAD + 4, BRANCH + 4)):
            self.assertEqual(original[begin:end], package[payload + begin:payload + end])
        self.assertNotIn(BRANCH, report['code_discovery']['guarded_indirect_sites'])

    def test_actual_base_full_width_index_and_ro_table_are_checked_before_load(self):
        source = fixture()
        self.assertIsNotNone(plan(source))
        assert_normalized_guard(self, source, rewritten(source), BRANCH, planner=ar.readonly_guest_table)

    def test_shape_liveness_guard_ambiguity_and_independent_entrances_fail_closed(self):
        mutations = ((COMPARE, 0x710052BF), (COMPARE, 0x710102DF),
                     (COMPARE + 4, 0x54000028), (COMPARE + 8, 0xF9403676),
                     (COMPARE + 12, 0x8B070AF6), (COMPARE + 16, 0x8B0A02B6),
                     (COMPARE + 20, 0x9B0B68F6), (LOAD - 4, adr(LOAD - 4, BASE + 1, 26)),
                     (LOAD, 0x3875681B), (LOAD + 8, 0x910110FA))
        for pc, word in mutations:
            source = fixture(); write_image(source, pc, '<I', word)
            with self.subTest(pc=hex(pc), word=hex(word)):
                self.assertIsNone(plan(source))
        ambiguous = fixture()
        write_image(ambiguous, 0x304, '<2I', 0x90000020, 0x91240000)
        self.assertIsNone(plan(ambiguous))
        for entry in (COMPARE + 4, COMPARE + 8, LOAD + 4, LOAD + 8, BRANCH):
            with self.subTest(entry=hex(entry)):
                self.assertIsNone(plan(fixture(), entries=(entry,)))
        for readonly in ((), ((0x4800, 0x4814),)):
            self.assertIsNone(plan(fixture(), readonly=readonly))


if __name__ == '__main__': unittest.main()
