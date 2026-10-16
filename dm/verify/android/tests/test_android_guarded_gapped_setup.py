"""A complete local guarded setup survives unrelated newly selected RO data."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine

LOAD, BRANCH = 0xD18, 0xD20


def fixture(earlier=True, width=2):
    source = source_base()
    write_image(source, 0x300, '<I', ar.branch(0x300, 0xD00))
    if earlier:
        # Another selected function composes a different immutable RO object.
        write_image(source, 0x340, '<4I', 0x9000002C, 0xAA1F03E0, 0x9124018C, 0xD65F03C0)
    write_image(source, 0xD00, '<9I', 0x71000D3F,
                0x54000008 | (((0xE00 - 0xD04) // 4) << 5),
                0x9000002C, 0xAA1F03E0, 0x9120018C, adr(0xD14, 0x600, 10),
                0x7869798B if width == 2 else 0x3869698B, 0x8B0B094A, 0xD61F0140)
    write_image(source, 0x4800, '<4' + ('H' if width == 2 else 'B'), 0, 2, 7, 12)
    write_image(source, 0x4900, '<4' + ('H' if width == 2 else 'B'), 0, 1, 3, 4)
    return source


def classify(source, entries=(), missing=(), readonly=((0x4000, 0x8000),)):
    raw = parse_nso(source).image
    by_pc = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc))
             for pc in range(0x300, 0x1000, 4) if pc not in missing}
    return ar._guarded_native_readonly_table(by_pc[BRANCH], by_pc, set(entries), raw, readonly)


class GuardedGappedSetupTests(unittest.TestCase):
    def test_newly_selected_earlier_object_does_not_change_complete_local_setup(self):
        for width in (1, 2):
            baseline = classify(fixture(False, width))
            expanded = classify(fixture(True, width))
            with self.subTest(width=width):
                self.assertIsNotNone(expanded)
                self.assertEqual(expanded, baseline)
                self.assertEqual((expanded['table_offset'], expanded['producer_offsets'][:2]),
                                 (0x4800, [0xD08, 0xD10]))

    def test_original_effects_and_all_table_indices_are_preserved(self):
        for width in (1, 2):
            source = fixture(True, width)
            image = image_for(source, entry=0x300, proven_guest_indirect_offsets=(BRANCH,))
            for index, tag in enumerate((0, 2, 7, 12)):
                model = Machine(image)
                model.x[9] = index
                before = list(model.x)
                model.run()
                before[0] = 0
                before[10], before[11], before[12] = 0x600 + tag * 4, tag, 0x4800
                self.assertEqual((model.x, model.sp), (before, model.start_sp))
            raw = parse_nso(source).image
            self.assertEqual(image.bytes[0xD08:LOAD], raw[0xD08:LOAD])
            self.assertEqual(image.bytes[LOAD + 4:BRANCH + 4], raw[LOAD + 4:BRANCH + 4])

    def test_importer_revalidates_when_a_verified_case_discovers_the_earlier_object(self):
        source = fixture(False)
        write_image(source, 0x380, '<4I', 0x9000002C, 0xAA1F03E0, 0x9124018C, 0xD65F03C0)
        write_image(source, 0xD14, '<I', adr(0xD14, 0x340, 10))
        write_image(source, 0x4800, '<4H', 0, 16, 16, 16)
        _, report = ai.import_module(source, 'main', package_version=2, checked_stack=True,
                                     indirect_policy='guarded-host')
        discovery = report['code_discovery']
        plan = next(plan for plan in discovery['readonly_guest_jump_tables'] if plan['offset'] == BRANCH)
        self.assertEqual((plan['table_offset'], plan['target_values']), (0x4800, [0, 16]))
        self.assertIn(0x380, discovery['roots'])
        self.assertIn(BRANCH, discovery['proven_indirect_sites'])
        self.assertNotIn(BRANCH, discovery['guarded_indirect_sites'])

    def test_preload_entries_still_guard_actual_base_and_full_index(self):
        source = fixture()
        for entry in (0xD08, 0xD0C, 0xD10, 0xD14, LOAD):
            self.assertIsNotNone(classify(source, entries=(entry,)))
        image = image_for(source, entry=LOAD, entry_offsets=(LOAD,),
                          proven_guest_indirect_offsets=(BRANCH,))
        for bad in ('table', 'base', 'bound', 'upper'):
            model = Machine(image)
            model.x[9], model.x[10], model.x[12] = 2, 0x600, 0x4800
            if bad == 'table':
                model.x[12] = 0x4900
            elif bad == 'base':
                model.x[10] += 4
            elif bad == 'bound':
                model.x[9] = 4
            else:
                model.x[9] |= 1 << 32
            model.flags = 0xA0000000
            before = list(model.x)
            with self.subTest(bad=bad), self.assertRaisesRegex(AssertionError, 'instruction brk'):
                model.run()
            self.assertEqual((model.x, model.sp, model.flags), (before, model.start_sp, 0xA0000000))

    def test_postload_independent_entry_cannot_bypass_actual_read_guard(self):
        source = fixture()
        for entry in (LOAD + 4, BRANCH):
            self.assertIsNone(classify(source, entries=(entry,)))
            with self.subTest(entry=entry), self.assertRaises(ar.RewriteError):
                image_for(source, entry=0x300, entry_offsets=(entry,),
                          proven_guest_indirect_offsets=(BRANCH,))

    def test_incomplete_clobbered_control_or_rewritten_gap_cannot_borrow_other_table(self):
        for word in (0xAA0003EC, 0x2A0003EC, ar.branch(0xD0C, 0xD10),
                     0x94000001, 0x910043FF, 0xAA1203E0, 0xB1000400):
            source = fixture()
            write_image(source, 0xD0C, '<I', word)
            with self.subTest(word=hex(word)):
                self.assertIsNone(classify(source))
        self.assertIsNone(classify(fixture(), missing=(0xD0C,)))

    def test_local_non_ro_or_partial_object_is_not_replaced_by_other_ro_candidate(self):
        source = fixture()
        for ranges in (((0x4900, 0x4908),), ((0x4800, 0x4807), (0x4900, 0x4908))):
            self.assertIsNone(classify(source, readonly=ranges))
        write_image(source, 0xD08, '<I', 0x9000004C)  # Its complete local value is writable data.
        self.assertIsNone(classify(source))

    def test_genuinely_ambiguous_remote_producers_remain_ambiguous(self):
        source = fixture()
        # The immediate ADD no longer consumes the local page; neither remote
        # constructor has the complete near ADD/ADR/LDR relationship.
        write_image(source, 0xD08, '<3I', 0xD503201F, 0xD503201F, 0xD503201F)
        write_image(source, 0x380, '<4I', 0x9000002C, 0xAA1F03E0, 0x9120018C, 0xD65F03C0)
        self.assertIsNone(classify(source))


if __name__ == '__main__':
    unittest.main()
