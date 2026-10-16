"""Four mode-selected dispatches retain one CMP over bounded CBZ paths."""
import struct
import unittest
from dataclasses import replace

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine
from nso_format import parse_metadata

CMP = 0x304
GUARDS = (0x310, 0x3D4, 0x460, 0x500)
BRANCHES = tuple(pc + 24 for pc in GUARDS)
TABLES = (0x4800, 0x4810, 0x4820, 0x4830)
WIDTHS = (1, 1, 2, 2)
LAST_TAGS = (100, 120, 140, 160)


def cbz(pc, target, register):
    return 0x34000000 | (((target - pc) // 4) & 0x7FFFF) << 5 | register


def fixture():
    source = source_base()
    write_image(source, 0x300, '<4I', 0x51000508, 0x71001D1F,
                cbz(0x308, 0x3D0, 4), cbz(0x30C, 0x460, 3))
    write_image(source, 0x3D0, '<I', cbz(0x3D0, 0x500, 3))
    for number, (guard, table, width, last) in enumerate(zip(GUARDS, TABLES, WIDTHS, LAST_TAGS)):
        branch = guard + 24
        write_image(source, guard, '<7I', 0x54000008 | (((0xE00 - guard) // 4) << 5),
                    0x90000029, 0x91000129 | ((table & 0xFFF) << 10),
                    adr(guard + 12, branch + 4, 10),
                    0x3868692B if width == 1 else 0x7868792B, 0x8B0B094A, 0xD61F0140)
        tags = (0, 2, 4, 6, 8, 10, 12, last)
        write_image(source, table, '<8' + ('B' if width == 1 else 'H'), *tags)
        target = branch + 4 + last * 4
        write_image(source, target, '<2I', 0x52800012 | ((number + 1) << 5), 0xD65F03C0)
    return source


def classify(source, branch, *, roots=(0x300,), entries=(), missing=(), known=(), readonly=((0x4000, 0x8000),)):
    raw = parse_nso(source).image
    by_pc = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc))
             for pc in range(0x300, 0x1000, 4) if pc not in missing}
    direct = set(entries)
    for op in by_pc.values():
        if op.mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or op.mnemonic.startswith('b.'):
            direct.add(op.operands[-1].imm)
    return ar._guarded_native_readonly_table(by_pc[branch], by_pc, direct | set(roots), raw,
                readonly, known_tables=known, root_entries=set(roots))


class SharedCmpCbzTests(unittest.TestCase):
    def test_distant_mode_tables_reuse_only_the_control_reaching_compare(self):
        for guard, branch, table, width in zip(GUARDS, BRANCHES, TABLES, WIDTHS):
            plan = classify(fixture(), branch)
            with self.subTest(branch=hex(branch)):
                self.assertIsNotNone(plan)
                self.assertEqual((plan['bound_candidate_offset'], plan['index_bound'], plan['table_offset'],
                                  plan['table_bytes']), (CMP, 7, table, 8 * width))
                if guard != GUARDS[0]:
                    self.assertEqual(plan['bound_candidate_kind'], 'cbz-shared-cmp')

    def test_every_mode_and_index_preserves_original_guarded_execution(self):
        source = fixture()
        image = image_for(source, entry=0x300, proven_guest_indirect_offsets=BRANCHES)
        for number, (w4, w3) in enumerate(((1, 1), (0, 1), (1, 0), (0, 0))):
            for index in range(8):
                model = Machine(image)
                model.x[8], model.x[4], model.x[3] = index + 1, w4, w3
                before = list(model.x)
                model.run()
                tag = index * 2 if index < 7 else LAST_TAGS[number]
                before[8], before[9] = index, TABLES[number]
                before[10], before[11] = BRANCHES[number] + 4 + tag * 4, tag
                self.assertEqual((model.x, model.sp), (before, model.start_sp))
                self.assertEqual(model.load(model.state, 8), number + 1 if index == 7 else 0)

    def test_importer_discovers_all_tail_cases_without_guessed_roots(self):
        _, report = ai.import_module(fixture(), 'main', package_version=2, checked_stack=True,
                                     indirect_policy='guarded-host')
        discovery = report['code_discovery']
        self.assertTrue(set(BRANCHES) <= set(discovery['proven_guest_indirect_sites']))
        for branch, last in zip(BRANCHES, LAST_TAGS):
            self.assertIn(branch + 4 + last * 4, discovery['roots'])
            self.assertNotIn(branch + 4 + last * 4, discovery['independent_roots'])

    def test_metadata_alias_at_the_same_trusted_cbz_guard_is_independent(self):
        nso = parse_nso(fixture())
        metadata = parse_metadata(nso)
        metadata = replace(metadata, eh_starts=metadata.eh_starts + (GUARDS[3],))
        with self.assertRaises(ai.ImportError):
            ai.discover_code(nso, metadata, checked_stack=True, indirect_policy='guarded-host')

    def test_later_callback_origin_invalidates_a_previously_proven_shared_plan(self):
        source = fixture()
        case = BRANCHES[3] + 4 + LAST_TAGS[3] * 4
        write_image(source, case, '<2I', adr(case, GUARDS[3], 5), 0xD65F03C0)
        with self.assertRaisesRegex(ai.ImportError, '0x518: guest table proof invalidated by another entry'):
            ai.import_module(source, 'main', package_version=2, checked_stack=True,
                             indirect_policy='guarded-host')

    def test_callback_and_verified_case_origin_overlap_retains_the_stronger_root(self):
        source = fixture()
        case = BRANCHES[3] + 4 + LAST_TAGS[3] * 4
        earlier_case = BRANCHES[0] + 4 + LAST_TAGS[0] * 4
        write_image(source, case, '<2I', adr(case, earlier_case, 5), 0xD65F03C0)
        _, report = ai.import_module(source, 'main', package_version=2, checked_stack=True,
                                     indirect_policy='guarded-host')
        self.assertIn(earlier_case, report['code_discovery']['roots'])
        self.assertIn(earlier_case, report['code_discovery']['independent_roots'])

    def test_standalone_independent_origin_list_is_checked_without_dropping_declared_entries(self):
        source = fixture()
        with self.assertRaises(ar.RewriteError):
            image_for(source, entry=0x300, entry_offsets=(GUARDS[3],),
                      independent_entry_offsets=(0x300, GUARDS[3]), proven_guest_indirect_offsets=BRANCHES)
        for independent in ((0x301,), (0x1000,), (True,), 3):
            with self.subTest(independent=independent), self.assertRaises(ar.RewriteError):
                image_for(source, entry=0x300, independent_entry_offsets=independent,
                          proven_guest_indirect_offsets=BRANCHES)

    def test_flag_index_calls_and_indirect_escape_break_the_shared_path(self):
        for word in (0x7100053F, 0x11000508, 0x94000001, 0xD61F00A0,
                     0xD4000001, 0x910043FF, 0xAA1203E0):
            source = fixture()
            write_image(source, 0x3D0, '<I', word)
            with self.subTest(word=hex(word)):
                self.assertIsNone(classify(source, BRANCHES[3]))
        self.assertIsNone(classify(fixture(), BRANCHES[3], missing=(0x308,)))

    def test_independent_guard_load_and_mode_entries_cannot_borrow_cmp_flags(self):
        for root in (0x308, 0x30C, 0x3D0, GUARDS[3], GUARDS[3] + 16):
            branch = BRANCHES[2] if root == 0x30C else BRANCHES[3]
            with self.subTest(root=hex(root)):
                self.assertIsNone(classify(fixture(), branch, roots=(0x300, root)))

    def test_external_direct_and_verified_table_edges_cannot_enter_shared_path(self):
        source = fixture()
        write_image(source, 0x900, '<I', ar.branch(0x900, GUARDS[3]))
        self.assertIsNone(classify(source, BRANCHES[3]))
        plan = dict(offset=0x904, base=GUARDS[3], target_values=[0])
        self.assertIsNone(classify(fixture(), BRANCHES[3], known=({0x904: plan},)))
        source = fixture()
        write_image(source, 0x900, '<I', adr(0x900, GUARDS[3], 5))
        self.assertIsNone(classify(source, BRANCHES[3]))

    def test_full_ro_object_bound_and_selected_path_are_required(self):
        for readonly in ((), ((0x4830, 0x483F),)):
            self.assertIsNone(classify(fixture(), BRANCHES[3], readonly=readonly))
        for word in (0x7101011F, 0xF1001D1F):  # CMP W8,#64 or CMP X8,#7.
            source = fixture()
            write_image(source, CMP, '<I', word)
            self.assertIsNone(classify(source, BRANCHES[3]))
        self.assertIsNone(classify(fixture(), BRANCHES[3], missing=(0x3D0,)))

    def test_actual_read_guard_still_rejects_wrong_live_values(self):
        source = fixture()
        load = GUARDS[3] + 16
        image = image_for(source, entry=0x300, proven_guest_indirect_offsets=BRANCHES)
        for bad in ('table', 'base', 'bound', 'upper'):
            model = Machine(replace(image, entry_offset=load))
            model.x[8], model.x[9], model.x[10] = 2, TABLES[3], BRANCHES[3] + 4
            if bad == 'table': model.x[9] += 2
            elif bad == 'base': model.x[10] += 4
            elif bad == 'bound': model.x[8] = 8
            else: model.x[8] |= 1 << 32
            model.flags = 0xA0000000
            before = list(model.x)
            with self.subTest(bad=bad), self.assertRaisesRegex(AssertionError, 'instruction brk'):
                model.run()
            self.assertEqual((model.x, model.sp, model.flags), (before, model.start_sp, 0xA0000000))


if __name__ == '__main__':
    unittest.main()
