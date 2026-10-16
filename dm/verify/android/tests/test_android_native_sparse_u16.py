"""Sparse native u16 case offsets require no dense virtual-target veneer."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

ENTRY, CMP, LOAD, BRANCH, BASE, TABLE = 0x240, 0x400, 0x40C, 0x414, 0x300, 0x60080
TAGS = tuple((0, 3, 319, 1470, 5946)[index % 5] for index in range(31)) + (65535,)


def fixture(tags=TAGS):
    raw = bytearray(0x61000)
    raw[ENTRY:ENTRY + 12] = struct.pack('<3I', 0x9000030C, 0x9102018C, ar.branch(ENTRY + 8, CMP))
    raw[CMP:CMP + 24] = struct.pack('<6I', 0x71007D1F,
        0x54000008 | (((BASE - CMP - 4) // 4 & 0x7FFFF) << 5),
        adr(LOAD - 4, BASE, 9), 0x7868798A, 0x8B0A0929, 0xD61F0120)
    struct.pack_into('<32H', raw, TABLE, *tags)
    ranges = [(ENTRY, ENTRY + 12), (CMP, CMP + 24)]
    for tag in sorted(set(tags)):
        target = BASE + tag * 4; raw[target:target + 4] = ar.word(0xD65F03C0); ranges.append((target, target + 4))
    return bytes(raw), sorted(ranges)


def rewritten(**changes):
    raw, ranges = fixture()
    options = dict(entry_offset=ENTRY, text_size=0x50000, code_ranges=ranges, checked_stack=True,
                   package_version=2, readonly_ranges=((0x60000, 0x61000),), proven_guest_indirect_offsets=(BRANCH,))
    return ar.rewrite(raw, **(options | changes))


class NativeSparseU16Tests(unittest.TestCase):
    def execute(self, index=0, *, entry=ENTRY, bad=None):
        image = rewritten(); base, stack, state = 0x10000000, 0x20008000, 0x30000000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, (len(image.bytes) + 4095) & ~4095); cpu.mem_map(0x20000000, 0x10000); cpu.mem_map(state, 0x1000)
        cpu.mem_write(base, image.bytes); self.assertEqual((), image.fixups)
        registers = [0x12340000 + r * 0x101 for r in range(31)]
        registers[8], registers[9], registers[12], registers[18], registers[30] = index, base + BASE, base + TABLE, 0x77AA000000000018, base + 0x80
        if bad == 'table': registers[12] = 0
        elif bad == 'base': registers[9] += 4
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        arguments = bytes(range(16)); cpu.mem_write(stack, arguments); cpu.mem_write(state, struct.pack('<Q', 0xABCDEF0123456789))
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
            if base + TABLE <= address < base + TABLE + 64: result['reads'] += 1
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_INTR, trap); cpu.hook_add(UC_HOOK_MEM_READ, read)
        initial = snapshot(); cpu.emu_start(base + entry, base + len(image.bytes), count=10000)
        self.assertEqual(arguments, bytes(cpu.mem_read(stack, 16)))
        self.assertEqual(0xABCDEF0123456789, struct.unpack('<Q', cpu.mem_read(state, 8))[0])
        result.update(initial=initial, final=snapshot(), registers=registers, vectors=vectors, base=base, stack=stack)
        return result

    def test_all_indices_including_5946_and_max_u16_preserve_actual_cpu_state(self):
        for index, tag in enumerate(TAGS):
            with self.subTest(index=index, tag=tag):
                result = self.execute(index)
                self.assertEqual((True, False, 1), (result['returned'], result['trapped'], result['reads']))
                expected = result['registers'][:]
                expected[9], expected[10], expected[12] = result['base'] + BASE + tag * 4, tag, result['base'] + TABLE
                self.assertEqual((expected, result['stack'], 0x60000000 if index == 31 else 0x80000000, result['vectors']), result['final'])

    def test_bad_actual_values_restore_state_before_any_table_read(self):
        for index, bad in ((0, 'table'), (0, 'base'), (32, None), (1 << 32, None), (0xFFFFFFFFFFFFFFFF, None)):
            with self.subTest(index=index, bad=bad):
                result = self.execute(index, entry=LOAD, bad=bad)
                self.assertEqual((False, True, 0), (result['returned'], result['trapped'], result['reads']))
                self.assertEqual(result['initial'], result['final'])

    def test_large_offsets_do_not_expand_veneer_and_native_branch_and_ro_stay_identical(self):
        raw, _ = fixture(); image = rewritten()
        self.assertLess(len(image.bytes) - len(raw), 256)
        self.assertEqual(raw[LOAD + 4:BRANCH + 4], image.bytes[LOAD + 4:BRANCH + 4])
        self.assertEqual(raw[0x60000:0x61000], image.bytes[0x60000:0x61000])
        for entry in (LOAD + 4, BRANCH):
            with self.assertRaises(ar.RewriteError): rewritten(entry_offsets=(entry,))
        with self.assertRaises(ar.RewriteError): rewritten(readonly_ranges=((TABLE, TABLE + 60),))
        with self.assertRaises(ar.RewriteError): rewritten(code_ranges=fixture()[1][:-1])

    def test_original_text_and_protected_metadata_are_still_execution_boundaries(self):
        def source(tags, target_base=0x340):
            data = source_base()
            write_image(data, 0x300, '<3I', 0x9000002C, 0x9120018C, ar.branch(0x308, 0x3C0))
            write_image(data, 0x3C0, '<6I', 0x7100091F, 0x54000388,
                        adr(0x3C8, target_base, 9), 0x7868798A, 0x8B0A0929, 0xD61F0120)
            write_image(data, 0x4800, '<3H', *tags)
            return data
        with self.assertRaisesRegex(ai.ImportError, 'control flow outside original text'):
            ai.import_module(source((0, 3, 5946)), 'main', checked_stack=True, package_version=2, indirect_policy='guarded-host')
        with self.assertRaisesRegex(ai.ImportError, 'MOD0/dynamic metadata'):
            ai.import_module(source((0, 17, 3), target_base=0), 'main', checked_stack=True, package_version=2, indirect_policy='guarded-host')

    def test_source_bound_limit_and_virtual_table_families_keep_existing_caps(self):
        raw, ranges = fixture(); by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc)) for a, b in ranges for pc in range(a, b, 4)}
        proof = ar._guarded_native_readonly_table(by[BRANCH], by, set(), raw, ((0x60000, 0x61000),))
        self.assertIsNotNone(proof); self.assertIn(65535, proof['target_values'])
        damaged = bytearray(raw); struct.pack_into('<I', damaged, CMP, 0x7101011F)
        by[CMP] = ar.Instruction(ar.decode(0x7101011F, CMP))
        self.assertIsNone(ar._guarded_native_readonly_table(by[BRANCH], by, set(), damaged, ((0x60000, 0x61000),)))
        from test_android_virtual_table_x18 import fixture as virtual_fixture
        from test_android_virtual_ro_x18 import image_for
        data, _ = virtual_fixture(width=2, roles=(16, 17, 15))
        write_image(data, 0x4800, '<6H', 0, 2, 65535, 0, 2, 65535)
        with self.assertRaises(ar.RewriteError): image_for(data, entry=0x300, proven_guest_indirect_offsets=(0x3E0,))


if __name__ == '__main__': unittest.main()
