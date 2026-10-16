"""The virtual index is distinct from a native table, result and BR target."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
import test_taiko_checked_call as fixed
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ, UcError
from unicorn import arm64_const as uc

# Self-authored offsets, independent of the locally inspected game's table.
VALUES = (0, 5, 17, 33, 52, 79, 114, 173)
START, LOAD, BRANCH, CASE_BASE, TABLE = 0x100, 0x11C, 0x124, 0x128, 0x4080


def conditional(pc, target, condition):
    return 0x54000000 | (((target - pc) // 4 & 0x7FFFF) << 5) | condition


def sequence(start, table, roles=(4, 5, 7, 21, 6)):
    target, loaded, base, alias, side = roles
    adr_pc, case_base = start + 24, start + 40
    delta = case_base - adr_pc
    page_delta = (table >> 12) - ((start + 16) >> 12)
    return [0x7100001F | 7 << 10 | alias << 5, conditional(start + 4, 0x1800, 8),
            0x39400240 | side, 0x2A0003F2 | alias << 16,
            0x90000000 | (page_delta & 3) << 29 | (page_delta >> 2 & 0x7FFFF) << 5 | base,
            0x91000000 | (table & 4095) << 10 | base << 5 | base,
            0x10000000 | (delta & 3) << 29 | (delta >> 2 & 0x7FFFF) << 5 | target,
            0x78727800 | base << 5 | loaded, 0x8B000800 | loaded << 16 | target << 5 | target,
            0xD61F0000 | target << 5]


def fixture(roles=(4, 5, 7, 21, 6)):
    data = bytearray(0x5000); words = sequence(START, TABLE, roles)
    data[START:START + 40] = fixed.raw(*words)
    alias = roles[3]
    for at in (0xE0, 0x1A00):
        data[at:at + 12] = fixed.raw(0x7100001F | 7 << 10 | alias << 5,
            conditional(at + 4, START + 8, 9), ar.branch(at + 8, 0x1800))
    struct.pack_into('<8H', data, TABLE, *VALUES)
    ranges = [(0xE0, 0xEC), (START, START + 40)]
    targets = tuple(CASE_BASE + value * 4 for value in VALUES)
    for target in targets:
        data[target:target + 4] = ar.word(ar.branch(target, 0x2000)); ranges.append((target, target + 4))
    data[0x1800:0x1804] = ar.word(0xD65F03C0)
    callback = fixed.fixture()[0][0x100:]
    data[0x2000:0x2000 + len(callback)] = callback
    ranges += [(0x1800, 0x1804), (0x1A00, 0x1A0C), (0x2000, 0x2000 + len(callback))]
    return bytes(data), sorted(ranges), targets


def rewritten(roles=(4, 5, 7, 21, 6), **changes):
    raw, ranges, _ = fixture(roles)
    options = dict(entry_offset=START, text_size=0x3000, code_ranges=ranges, package_version=2,
                   checked_stack=True, readonly_ranges=((0x4000, 0x5000),), proven_guest_indirect_offsets=(BRANCH,))
    return ar.rewrite(raw, **(options | changes))


class VirtualIndexX18Tests(unittest.TestCase):
    def execute(self, index=0, *, roles=(4, 5, 7, 21, 6), entry=START, virtual=None, table_base=None, case_base=None):
        image = rewritten(roles); target, loaded, base_reg, alias, side = roles
        targets = set(fixture(roles)[2])
        base, state, helper, output, pointer, stack = 0x10000000, 0x30000000, 0x30001000, 0x30002000, 0x30003000, 0x20008000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000); cpu.mem_map(state, 0x10000); cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_write(base, image.bytes)
        cpu.mem_write(helper, fixed.raw(0x58000050, 0xD65F03C0) + struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper); cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x12340000 + r * 0x101 for r in range(31)]
        registers[18], registers[28], registers[30], registers[alias] = 0x77AA000000000018, output, base + 0x80, index
        registers[base_reg] = base + TABLE if table_base is None else table_base
        registers[target] = base + CASE_BASE if case_base is None else case_base
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        arguments = bytes(range(16)); cpu.mem_write(stack, arguments); cpu.mem_write(pointer, b'\xab')
        initial_virtual = virtual if virtual is not None else index if entry == LOAD else pointer
        cpu.mem_write(state, struct.pack('<Q', initial_virtual))
        result = dict(trapped=False, returned=False, pointer_reads=0, table_reads=0, target=None)
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine, pc, size, _):
            ins = ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)
            self.assertFalse(ar.has18(ins), 'No executed instruction may use platform X18')
            if pc - base in targets: result['target'] = pc - base
            if pc == base + 0x80: result['returned'] = True; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if address == pointer: result['pointer_reads'] += 1
            if base + TABLE <= address < base + TABLE + 16: result['table_reads'] += 1
        def trap(machine, number, _): result['trapped'] = True; machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_MEM_READ, read); cpu.hook_add(UC_HOOK_INTR, trap)
        initial = snapshot(); cpu.emu_start(base + entry, base + len(image.bytes), count=20000)
        result.update(cpu=cpu, output=output, base=base, state=state, registers=registers, vectors=vectors,
                      stack=stack, arguments=arguments, initial=initial, final=snapshot(), initial_virtual=initial_virtual)
        self.assertEqual(registers[18], cpu.reg_read(uc.UC_ARM64_REG_X18))
        self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP)); self.assertEqual(arguments, bytes(cpu.mem_read(stack, 16)))
        return result

    def test_actual_cpu_all_indices_preserve_side_read_native_target_args_vectors_flags_and_lr(self):
        for roles in ((4, 5, 7, 21, 6), (0, 16, 2, 20, 3), (16, 0, 17, 22, 1)):
            for index, value in enumerate(VALUES):
                with self.subTest(roles=roles, index=index):
                    result = self.execute(index, roles=roles); cpu, output = result['cpu'], result['output']
                    self.assertEqual((False, True, 1, 1), (result['trapped'], result['returned'], result['pointer_reads'], result['table_reads']))
                    expected = result['registers'][:]; target, loaded, table, alias, side = roles
                    expected[target], expected[loaded], expected[table], expected[side], expected[18] = (
                        result['base'] + CASE_BASE + value * 4, value, result['base'] + TABLE, 0xAB, index)
                    self.assertEqual(expected, list(struct.unpack('<31Q', cpu.mem_read(output, 248))))
                    self.assertEqual(index, struct.unpack('<Q', cpu.mem_read(result['state'], 8))[0])
                    flags = 0x60000000 if index == 7 else 0x80000000
                    self.assertEqual((flags, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
                    for r, vector in enumerate(result['vectors']):
                        self.assertEqual(vector, int.from_bytes(cpu.mem_read(output + 0x100 + r * 16, 16), 'little'))

    def test_alternate_selected_guards_retain_pointer_read_before_index_copy(self):
        for entry in (0xE0, 0x1A00, START + 8):
            result = self.execute(7, entry=entry)
            self.assertEqual((True, 1, 1), (result['returned'], result['pointer_reads'], result['table_reads']))
        with self.assertRaises(UcError): self.execute(0, virtual=0)

    def test_unknown_table_target_base_and_high_full_virtual_indices_restore_before_read(self):
        for options in (dict(table_base=0), dict(table_base=0x10004084), dict(case_base=0),
                        dict(case_base=0x1000012C), dict(virtual=8), dict(virtual=1 << 32), dict(virtual=0xFFFFFFFFFFFFFFFF)):
            with self.subTest(options=options):
                result = self.execute(entry=LOAD, **options)
                self.assertEqual((True, 0, 0), (result['trapped'], result['pointer_reads'], result['table_reads']))
                self.assertEqual(result['initial'], result['final'])
                self.assertEqual(result['initial_virtual'], struct.unpack('<Q', result['cpu'].mem_read(result['state'], 8))[0])

    def test_full_import_exposes_all_original_u16_case_roots_and_virtual_case_assignment(self):
        source = source_base(); start, table = 0x3C0, 0x4800
        words = sequence(start, table)
        words[1] = conditional(start + 4, 0xF00, 8)
        write_image(source, start, '<10I', *words); write_image(source, table, '<8H', *VALUES)
        case = start + 40 + VALUES[-1] * 4
        write_image(source, case, '<I', 0x52800032)
        _, report = ai.import_module(source, 'main', checked_stack=True, package_version=2, indirect_policy='guarded-host')
        proof = report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual('runtime-virtual-index-x18-native-target-u16-ro-wcopy-pointer-read-v1', proof['rule'])
        self.assertEqual((18, 7, 16), (proof['virtual_index_register'], proof['index_bound'], proof['table_bytes']))
        self.assertIn(case, report['code_discovery']['roots']); self.assertIn(case, [site['offset'] for site in report['rewrite']['sites']])

    def test_missing_alias_proof_role_clobbers_ro_and_postload_entries_are_refused(self):
        raw, ranges, _ = fixture()
        def plan(data, entries=(), readonly=((0x4000, 0x5000),)):
            by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', data, pc)[0], pc)) for a, b in ranges for pc in range(a, b, 4)}
            return ar.virtual_index_x18_native_target(by[BRANCH], by, set(entries), data, readonly)
        self.assertIsNotNone(plan(raw))
        for pc, word in ((START, 0x71001E9F), (START + 4, conditional(START + 4, 0x1800, 0)),
                         (START + 8, 0x39400245), (START + 12, 0xAA1503F2),
                         (START + 12, 0x2A1403F2), (START + 16, 0x90000032),
                         (LOAD, 0x786778E5), (LOAD + 4, 0x8B0508A4)):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, pc, word)
            self.assertIsNone(plan(damaged))
        for entry in (LOAD + 4, BRANCH):
            self.assertIsNone(plan(raw, entries=(entry,)))
            with self.assertRaises(ar.RewriteError): rewritten(entry_offsets=(entry,))
        for readonly in ((), ((TABLE, TABLE + 14),)):
            self.assertIsNone(plan(raw, readonly=readonly))
        image = rewritten()
        self.assertEqual(raw[LOAD + 4:BRANCH + 4], image.bytes[LOAD + 4:BRANCH + 4])
        self.assertTrue({START + 8, START + 12, LOAD} <= {site.offset for site in image.sites})


if __name__ == '__main__': unittest.main()
