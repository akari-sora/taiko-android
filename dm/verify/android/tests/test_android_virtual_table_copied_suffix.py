"""A copied W-index and two original suffix effects follow a virtual RO table."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine

VALUES = tuple(range(26)) + tuple(range(12))
COMPARE, LOAD, BRANCH, BASE = 0x3C0, 0x3DC, 0x3EC, 0x3F0


def conditional(pc, target, condition):
    return 0x54000000 | (((target - pc) // 4 & 0x7FFFF) << 5) | condition


def fixture():
    source = source_base()
    write_image(source, 0x300, '<I', ar.branch(0x300, 0x3A8))
    # Earlier equality checks must never replace the real adjacent CMP/B.HI bound.
    write_image(source, 0x3A8, '<5I', 0x7100323F, conditional(0x3AC, 0x700, 0),
                0x7100463F, conditional(0x3B4, 0x700, 0), ar.branch(0x3B8, COMPARE))
    write_image(source, COMPARE, '<12I', 0x7100963F, conditional(COMPARE + 4, 0x700, 8),
                0xB940080F, 0x90000032, 0x91200252, 0x2A1103E3,
                adr(LOAD - 4, BASE, 5), 0x38636A46, 0x8B0608A5,
                0x528008D0, 0x2A1103F2, 0xD61F00A0)
    write_image(source, 0x4800, '<38B', *VALUES)
    write_image(source, BASE + 20 * 4, '<2I', 0x52800032, 0xD65F03C0)
    return source


def plan(source, *, entries=(), readonly=((0x4000, 0x8000),)):
    raw = parse_nso(source).image
    by_pc = {}
    for pc in range(0x300, 0x1000, 4):
        op = ar.decode(struct.unpack_from('<I', raw, pc)[0], pc)
        by_pc[pc] = op if isinstance(op, ar.FatalWord) else ar.Instruction(op)
    return ar._virtual_table_x18_native_target(by_pc[BRANCH], by_pc, set(entries), raw, readonly)


def rewritten(source, entry=0x300, **changes):
    return image_for(source, entry=entry, proven_guest_indirect_offsets=(BRANCH,), **changes)


class VirtualTableCopiedSuffixTests(unittest.TestCase):
    def test_correct_paired_guard_discovers_all_38_rows_and_26_distinct_targets(self):
        source = fixture()
        _, report = ai.import_module(source, 'main', package_version=2, checked_stack=True,
                                     indirect_policy='guarded-host')
        proof = next(item for item in report['code_discovery']['readonly_guest_jump_tables'] if item['offset'] == BRANCH)
        self.assertEqual('runtime-virtual-table-x18-native-target-u8-ro-copied-index-suffix-lsl2-v1', proof['rule'])
        self.assertEqual((37, 38, list(range(26))), (proof['index_bound'], proof['table_bytes'], proof['target_values']))
        self.assertEqual((COMPARE, COMPARE + 4), (proof['compare_offset'], proof['guard_offset']))
        self.assertEqual(17, proof['index_alias_source_register'])
        self.assertIn(BASE + 20 * 4, report['code_discovery']['roots'])
        self.assertIn(BASE + 20 * 4, [item['offset'] for item in report['rewrite']['sites']])
        self.assertNotIn(BRANCH, report['code_discovery']['guarded_indirect_sites'])

    def test_original_side_load_immediate_virtual_copy_and_native_target_survive(self):
        source = fixture(); image = rewritten(source, entry=COMPARE)
        original = parse_nso(source).image
        for begin, end in ((COMPARE + 8, COMPARE + 12), (LOAD - 8, LOAD), (LOAD + 4, LOAD + 12)):
            self.assertEqual(original[begin:end], image.bytes[begin:end])
        self.assertNotEqual(original[LOAD + 12:LOAD + 16], image.bytes[LOAD + 12:LOAD + 16])
        model = Machine(image); model.x[17] = 25; hardware = model.x[18]
        model.store(model.x[0] + 8, 0xCAFEBABE, 4)
        model.run()
        self.assertEqual((BASE + 25 * 4, 25, 25, 0x46, 0xCAFEBABE),
                         (model.x[5], model.x[6], model.x[3], model.x[16], model.x[15]))
        self.assertEqual((25, hardware, model.start_sp), (model.load(model.state, 8), model.x[18], model.sp))

    def test_bad_live_virtual_table_base_full_index_restore_before_trapping(self):
        image = rewritten(fixture(), entry=LOAD, entry_offsets=(LOAD,))
        for mode in ('null', 'table', 'base', 'upper', 'bound'):
            model = Machine(image); model.x[5] = BASE; model.x[3] = 0
            model.store(model.state, 0x4800, 8)
            if mode == 'null': model.store(model.state, 0, 8)
            elif mode == 'table': model.store(model.state, 0x4804, 8)
            elif mode == 'base': model.x[5] += 4
            elif mode == 'upper': model.x[3] = 1 << 32
            else: model.x[3] = 38
            model.flags = 0xA0000000; before = list(model.x); virtual = model.load(model.state, 8)
            with self.subTest(mode=mode), self.assertRaisesRegex(AssertionError, 'instruction brk'):
                model.run()
            self.assertEqual((before, model.start_sp, 0xA0000000, virtual),
                             (model.x, model.sp, model.flags, model.load(model.state, 8)))

    def test_alias_control_flags_virtual_reassignment_and_postload_entry_mutations_refuse(self):
        mutations = ((COMPARE, 0x7100961F), (COMPARE + 4, conditional(COMPARE + 4, 0x700, 0)),
                     (COMPARE + 8, 0xB9400811), (LOAD - 12, 0x52800252),
                     (LOAD - 8, 0xAA1103E3), (LOAD - 8, 0x2A1103E5),
                     (LOAD - 8, 0x2A1003E3), (LOAD + 8, 0x728008D0),
                     (LOAD + 8, 0x7100081F), (LOAD + 8, ar.branch(LOAD + 8, 0x700)),
                     (LOAD + 12, 0x2A1003F2), (LOAD + 12, 0x52800032))
        for pc, word in mutations:
            source = fixture(); write_image(source, pc, '<I', word)
            with self.subTest(pc=hex(pc), word=hex(word)):
                self.assertIsNone(plan(source))
        for entry in (LOAD + 4, LOAD + 8, LOAD + 12, BRANCH):
            self.assertIsNone(plan(fixture(), entries=(entry,)))
            with self.assertRaises(ar.RewriteError): rewritten(fixture(), entry_offsets=(entry,))
        for readonly in ((), ((0x4800, 0x4825),)):
            self.assertIsNone(plan(fixture(), readonly=readonly))


if __name__ == '__main__': unittest.main()
