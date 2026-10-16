"""A native u16 table may use live LR as data, without giving it call authority."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, write_image
from test_android_runtime_ro_backward import adr
from test_android_guarded_native_table import fixture as old_fixture, classify as old_classify
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

START, LOAD, BRANCH, TABLE, CASE_BASE = 0x100, 0xD0C, 0xD14, 0x6000, 0x800
TAGS = (0, 2, 7, 11, 23, 41, 89)


def adrp(pc, target, register):
    pages = (target >> 12) - (pc >> 12)
    return 0x90000000 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5 | register


def fixture():
    raw = bytearray(0x7000)
    gap = [adrp(START, TABLE, 30), 0xAA1F03F1, 0x4B1C0FF2, 0xA90283E8,
           0x91002068, 0x52800A89, 0x91001063, 0x52800104,
           0x52801FE5, 0x52800286, 0xF9000008, 0xD37FFB08,
           0x52800547, 0x2A1403E9, 0x910003DE | (TABLE & 4095) << 10,
           ar.branch(START + 60, 0xD00)]
    struct.pack_into('<16I', raw, START, *gap)
    struct.pack_into('<6I', raw, 0xD00, 0x7100493F,
                     0x54000008 | (((0x1900 - 0xD04) // 4) << 5),
                     adr(0xD08, CASE_BASE, 10), 0x78697BCB, 0x8B0B094A, 0xD61F0140)
    tags = tuple(TAGS[i % len(TAGS)] for i in range(19))
    struct.pack_into('<19H', raw, TABLE, *tags)
    targets = tuple(sorted({CASE_BASE + tag * 4 for tag in tags}))
    ranges = [(START, START + 64), (0xD00, BRANCH + 4), (0x1900, 0x1904)]
    for target in targets:
        struct.pack_into('<I', raw, target, 0xD65F03C0); ranges.append((target, target + 4))
    struct.pack_into('<I', raw, 0x1900, 0xD65F03C0)
    return bytes(raw), sorted(ranges), targets


def classify(raw, ranges, branch=BRANCH, entries=(), readonly=((0x6000, 0x7000),)):
    by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc))
          for begin, end in ranges for pc in range(begin, end, 4)}
    return ar._guarded_native_readonly_table(by[branch], by, set(entries), raw, readonly)


def image_for(raw, ranges, branch=BRANCH, entry=START, **options):
    return ar.rewrite(raw, entry_offset=entry, text_size=0x3000, code_ranges=ranges,
                      checked_stack=True, package_version=2, readonly_ranges=((0x6000, 0x7000),),
                      proven_guest_indirect_offsets=(branch,), **options)


class CpuCase(unittest.TestCase):
    def execute(self, raw, ranges, targets, *, branch, load, table, count, entry, index_register,
                table_register, target_register, case_base, index=0, bad=None, original=False, overrides=None):
        image = None if original else image_for(raw, ranges, branch, entry)
        base, state, helper, stack, payload = 0x10000000, 0x30000000, 0x30001000, 0x20008000, 0x30002000
        machine = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        machine.mem_map(base, 0x20000); machine.mem_map(state, 0x10000); machine.mem_map(0x20000000, 0x10000)
        machine.mem_write(base, raw if original else image.bytes)
        machine.mem_write(helper, struct.pack('<2IQ', 0x58000050, 0xD65F03C0, state))
        if image:
            for fixup in image.fixups:
                self.assertEqual(ar.STATE_HELPER, fixup.helper)
                machine.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x1234000000000000 + r * 0x101 for r in range(31)]
        registers[0], registers[1], registers[3], registers[21] = payload, payload + 16, payload + 32, payload + 48
        registers[9], registers[20], registers[28], registers[29] = 9, index, 0x234, stack + 0x80
        registers[index_register] = index
        registers[table_register], registers[target_register] = base + table, base + case_base
        virtual = 0xABCDEF0123456789
        registers[18] = virtual if original else 0x77AA000000000018
        for register, value in (overrides or {}).items(): registers[register] = value
        if bad == 'table': registers[table_register] = 0
        elif bad == 'wrong-table': registers[table_register] += 2
        elif bad == 'base': registers[target_register] += 4
        for r, value in enumerate(registers): machine.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): machine.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        machine.reg_write(uc.UC_ARM64_REG_SP, stack); machine.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        machine.mem_write(stack, bytes(range(192))); machine.mem_write(state, struct.pack('<Q', virtual))
        result = dict(trapped=False, reached=None, reads=0)
        def snapshot():
            return ([machine.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    machine.reg_read(uc.UC_ARM64_REG_SP), machine.reg_read(uc.UC_ARM64_REG_NZCV),
                    [machine.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(cpu, pc, size, _):
            if not original:
                self.assertFalse(ar.has18(ar.decode(struct.unpack('<I', cpu.mem_read(pc, 4))[0], pc)))
            if pc - base in targets:
                result['reached'] = pc - base; cpu.emu_stop()
        def trap(cpu, number, _): result['trapped'] = True; cpu.emu_stop()
        def read(cpu, access, address, size, value, _):
            if base + table <= address < base + table + count * 2: result['reads'] += 1
        machine.hook_add(UC_HOOK_CODE, code); machine.hook_add(UC_HOOK_INTR, trap); machine.hook_add(UC_HOOK_MEM_READ, read)
        result['initial'] = snapshot(); result['initial_memory'] = bytes(machine.mem_read(stack, 192))
        machine.emu_start(base + entry, base + 0x20000, count=10000)
        result.update(final=snapshot(), memory=bytes(machine.mem_read(stack, 192)),
                      payload=bytes(machine.mem_read(payload, 80)), virtual=struct.unpack('<Q', machine.mem_read(state, 8))[0], image=image)
        return result

    def assert_matches_source(self, original, rewritten):
        self.assertEqual((False, original['reached'], 1), (rewritten['trapped'], rewritten['reached'], rewritten['reads']))
        expected = original['final'][0][:]; expected[18] = rewritten['initial'][0][18]
        self.assertEqual((expected, *original['final'][1:]), rewritten['final'])
        self.assertEqual(original['final'][0][18], rewritten['virtual'])
        self.assertEqual((original['memory'], original['payload']), (rewritten['memory'], rewritten['payload']))


class NativeLrTableBaseTests(CpuCase):
    def run_case(self, index=0, **options):
        raw, ranges, targets = fixture()
        return self.execute(raw, ranges, targets, branch=BRANCH, load=LOAD, table=TABLE, count=19,
                            entry=options.pop('entry', START), index_register=9, table_register=30,
                            target_register=10, case_base=CASE_BASE, index=index, **options)

    def test_all_indices_match_original_lr_data_virtual_neg_and_frame_effects(self):
        for index in range(19):
            with self.subTest(index=index):
                self.assert_matches_source(self.run_case(index, original=True), self.run_case(index))
        raw, ranges, _ = fixture(); plan = classify(raw, ranges)
        self.assertEqual((30, 18, 56), (plan['table_register'], plan['index_bound'], plan['table_constructor_gap']))

    def test_invalid_live_lr_base_or_full_index_traps_without_read_or_state_changes(self):
        for index, bad in ((0, 'table'), (0, 'wrong-table'), (0, 'base'), (19, None), (1 << 32, None), (2**64 - 1, None)):
            result = self.run_case(index, entry=LOAD, bad=bad)
            self.assertEqual((True, None, 0), (result['trapped'], result['reached'], result['reads']))
            self.assertEqual(result['initial'], result['final']); self.assertEqual(result['initial_memory'], result['memory'])
            self.assertEqual(0xABCDEF0123456789, result['virtual'])

    def test_constructor_and_role_mutations_and_postload_entries_refuse(self):
        raw, ranges, _ = fixture()
        for pc, word in ((START + 4, 0xAA0003FE), (START + 4, 0x2A0003FE), (START + 4, 0xF84087FE),
                         (START + 4, 0x94000001), (START + 4, 0xB1000408), (START + 4, 0x910043FF),
                         (START + 56, 0x910007DE), (LOAD, 0x38696BCB), (LOAD, 0x787E7BCB),
                         (LOAD, 0x78697BAB), (LOAD, 0x78697BDE)):
            data = bytearray(raw); struct.pack_into('<I', data, pc, word)
            self.assertIsNone(classify(data, ranges), (hex(pc), hex(word)))
        for at in range(LOAD + 4, BRANCH + 4, 4):
            self.assertIsNone(classify(raw, ranges, entries=(at,)))
            with self.assertRaises(ar.RewriteError): image_for(raw, ranges, entry_offsets=(at,))
        self.assertIsNone(classify(raw, ranges, readonly=((TABLE, TABLE + 36),)))
        self.assertIsNone(classify(raw, ranges, entries=(START + 8,)))

    def test_leaf_guard_has_no_call_lr_write_or_helper_and_keeps_source_gap(self):
        raw, ranges, _ = fixture(); image = image_for(raw, ranges)
        trampoline = next(site.trampoline for site in image.sites if site.offset == LOAD)
        reads = 0
        for pc in range(trampoline, len(image.bytes), 4):
            instruction = ar.Instruction(ar.decode(struct.unpack_from('<I', image.bytes, pc)[0], pc))
            self.assertNotIn(instruction.mnemonic, ('bl', 'blr'))
            self.assertFalse(ar._native_table_writes(instruction) & {'x30'})
            reads += instruction.bytes == raw[LOAD:LOAD + 4]
            if instruction.mnemonic == 'brk': break
        self.assertEqual(1, reads)
        self.assertFalse(any(trampoline <= fixup.offset <= pc for fixup in image.fixups))
        for pc in range(START, START + 64, 4):
            if pc != START + 8:
                self.assertEqual(raw[pc:pc + 4], image.bytes[pc:pc + 4])
        for value in (0xFFFF,):
            changed = bytearray(raw); struct.pack_into('<H', changed, TABLE, value)
            with self.assertRaises(ar.RewriteError): image_for(changed, ranges)

    def test_flag_setting_target_writes_cannot_hide_behind_capstone_aliases(self):
        for word in (0x3100052A, 0x3100068A, 0xB100052A, 0x7200012A):
            source, branch = old_fixture(); write_image(source, 0x3D8, '<I', word)
            self.assertIsNone(old_classify(source, branch), hex(word))


if __name__ == '__main__': unittest.main()
