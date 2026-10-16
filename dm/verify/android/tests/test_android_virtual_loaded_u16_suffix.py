"""Inline virtual-loaded u16 dispatch preserves one ordinary W MOVZ suffix."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

CMP, LOAD, BRANCH, TABLE = 0x3C0, 0x3D4, 0x3E0, 0x4800
# Authored control offsets, not copied from either retail SDK table.
TAGS = tuple((0, 3, 11, 29)[index % 4] for index in range(16)) + (173,)


def fixture(roles=(16, 15, 14), immediate=2):
    table, index, suffix = roles; source = source_base()
    write_image(source, CMP, '<9I', 0x7100001F | 16 << 10 | index << 5,
                0x54000008 | (((0xB00 - CMP - 4) // 4) << 5),
                0x90000020 | table, 0x91200000 | table << 5 | table,
                adr(LOAD - 4, BRANCH + 4, 17), 0x78607812 | index << 16 | table << 5,
                0x8B120A31, 0x52800000 | immediate << 5 | suffix, 0xD61F0220)
    write_image(source, TABLE, '<17H', *TAGS)
    return source


def classify(source, *, entries=(), readonly=((0x4000, 0x8000),)):
    raw = parse_nso(source).image
    instructions = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc)) for pc in range(0x300, 0x1000, 4)}
    return ar._virtual_loaded_x18_native_target(instructions[BRANCH], instructions, set(entries), raw, readonly)


class VirtualLoadedU16SuffixTests(unittest.TestCase):
    def execute(self, index=0, *, roles=(16, 15, 14), entry=CMP, bad=None):
        source = fixture(roles); image = image_for(source, entry=CMP, proven_guest_indirect_offsets=(BRANCH,))
        table, idx, suffix = roles
        base, state, helper, stack = 0x10000000, 0x30000000, 0x30001000, 0x20008000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000); cpu.mem_map(state, 0x10000); cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_write(base, image.bytes); cpu.mem_write(helper, struct.pack('<IIQ', 0x58000050, 0xD65F03C0, state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper); cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x12340000 + r * 0x101 for r in range(31)]
        registers[table], registers[idx], registers[17], registers[18], registers[30] = base + TABLE, index, base + BRANCH + 4, 0x77AA000000000018, base + 0x80
        if bad == 'table': registers[table] = 0
        elif bad == 'base': registers[17] += 4
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        arguments = bytes(range(16)); cpu.mem_write(stack, arguments)
        cpu.mem_write(state, struct.pack('<Q', 0xABCDEF0123456789))
        result = dict(returned=False, trapped=False, reads=0)
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine, pc, size, _):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)))
            if pc == base + 0x80: result['returned'] = True; machine.emu_stop()
        def trap(machine, number, _): result['trapped'] = True; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base + TABLE <= address < base + TABLE + 34: result['reads'] += 1
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_INTR, trap); cpu.hook_add(UC_HOOK_MEM_READ, read)
        initial = snapshot(); cpu.emu_start(base + entry, base + len(image.bytes), count=10000)
        self.assertEqual(arguments, bytes(cpu.mem_read(stack, 16)))
        result.update(registers=registers, vectors=vectors, base=base, stack=stack, initial=initial,
                      final=snapshot(), virtual=struct.unpack('<Q', cpu.mem_read(state, 8))[0])
        return result

    def test_inline_actual_x16_table_alias_and_sibling_roles_all_indices_preserve_cpu_state(self):
        for roles in ((16, 15, 14), (15, 14, 13), (16, 15, 0)):
            for index, tag in enumerate(TAGS):
                with self.subTest(roles=roles, index=index):
                    result = self.execute(index, roles=roles)
                    self.assertEqual((True, False, 1), (result['returned'], result['trapped'], result['reads']))
                    expected = result['registers'][:]; expected[17] = result['base'] + BRANCH + 4 + tag * 4
                    expected[roles[2]] = 2
                    self.assertEqual((expected, result['stack'], 0x60000000 if index == 16 else 0x80000000, result['vectors']), result['final'])
                    self.assertEqual(tag, result['virtual'])

    def test_zero_read_failures_restore_native_args_flags_vectors_stack_lr_and_virtual_state(self):
        for roles in ((16, 15, 14), (15, 14, 13)):
            for index, bad in ((0, 'table'), (0, 'base'), (17, None), (1 << 32, None), (0xFFFFFFFFFFFFFFFF, None)):
                with self.subTest(roles=roles, index=index, bad=bad):
                    result = self.execute(index, roles=roles, entry=LOAD, bad=bad)
                    self.assertEqual((False, True, 0), (result['returned'], result['trapped'], result['reads']))
                    self.assertEqual(result['initial'], result['final']); self.assertEqual(0xABCDEF0123456789, result['virtual'])

    def test_inline_source_mov_word_is_preserved_and_all_authored_case_roots_are_audited(self):
        source = fixture(); plan = classify(source)
        self.assertIsNotNone(plan); self.assertEqual([LOAD + 8], plan['preserved_source_offsets'])
        image = image_for(source, entry=CMP, proven_guest_indirect_offsets=(BRANCH,))
        raw = parse_nso(source).image
        self.assertEqual(raw[LOAD + 8:BRANCH + 4], image.bytes[LOAD + 8:BRANCH + 4])
        _, report = ai.import_module(source, 'main', package_version=2, checked_stack=True, indirect_policy='guarded-host')
        self.assertTrue({BRANCH + 4 + tag * 4 for tag in TAGS} <= set(report['code_discovery']['roots']))
        self.assertIsNotNone(classify(fixture(immediate=65535)))

    def test_bad_suffix_roles_instructions_ro_and_postload_entries_refuse(self):
        for register in (17, 16, 15, 18, 29, 30, 31):
            self.assertIsNone(classify(fixture(roles=(16, 15, register))))
        for word in (0x5280004E | 1 << 21, 0x7280004E, 0xD280004E, 0x12001DCE, 0x710001DF):
            source = fixture(); write_image(source, LOAD + 8, '<I', word)
            self.assertIsNone(classify(source))
        for entry in (LOAD + 4, LOAD + 8, BRANCH):
            self.assertIsNone(classify(fixture(), entries=(entry,)))
            with self.assertRaises(ar.RewriteError): image_for(fixture(), entry=CMP, entry_offsets=(entry,), proven_guest_indirect_offsets=(BRANCH,))
        for readonly in ((), ((TABLE, TABLE + 33),)):
            self.assertIsNone(classify(fixture(), readonly=readonly))

    def test_neutral_mov_does_not_widen_old_hoisted_or_byte_table_forms(self):
        source = fixture(); write_image(source, 0x300, '<3I', 0x90000030, 0x91200210, ar.branch(0x308, CMP))
        write_image(source, LOAD - 12, '<2I', 0xD503201F, 0xD503201F)
        self.assertIsNone(classify(source))
        source = fixture(); write_image(source, LOAD, '<I', 0x386F6A12)
        self.assertIsNone(classify(source))


if __name__ == '__main__': unittest.main()
