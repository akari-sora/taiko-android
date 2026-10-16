"""Inline u16 dispatch consumes virtual X18 without touching Android X18."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

CMP, LOAD, BRANCH, TABLE = 0x3C0, 0x3D4, 0x3DC, 0x4800
TAGS = tuple((0, 2, 7)[index % 3] for index in range(34)) + (120,)


def fixture():
    source = source_base()
    write_image(source, CMP, '<8I', 0x710089FF,
                0x54000008 | (((0x900 - CMP - 4) // 4) << 5),
                0x90000020, 0x91200000, adr(LOAD - 4, BRANCH + 4, 17),
                0x786F7812, 0x8B120A31, 0xD61F0220)
    write_image(source, TABLE, '<35H', *TAGS)
    for tag in set(TAGS):
        write_image(source, BRANCH + 4 + tag * 4, '<2I', 0x11000652, 0xD65F03C0)
    return source


def classify(source, *, entries=(), missing=(), readonly=((0x4000, 0x8000),)):
    raw = parse_nso(source).image
    instructions = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc))
                    for pc in range(0x300, 0x1000, 4) if pc not in missing}
    return ar._virtual_loaded_x18_native_target(instructions[BRANCH], instructions,
                                               set(entries), raw, readonly)


class VirtualLoadedInlineTests(unittest.TestCase):
    def execute(self, *, index=0, entry=CMP, bad=None):
        image = image_for(fixture(), entry=CMP, proven_guest_indirect_offsets=(BRANCH,))
        base, state, helper, stack = 0x10000000, 0x30000000, 0x30001000, 0x20008000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, max(0x10000, (len(image.bytes) + 4095) & ~4095))
        cpu.mem_map(0x20000000, 0x10000); cpu.mem_map(state, 0x10000)
        cpu.mem_write(base, image.bytes)
        cpu.mem_write(helper, struct.pack('<IIQ', 0x58000050, 0xD65F03C0, state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper)
            cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x1234567800000000 + register * 0x10101 for register in range(31)]
        registers[0], registers[15], registers[17] = base + TABLE, index, base + BRANCH + 4
        registers[18], registers[30] = 0x7FFF00000000ABCD, base + 0x80
        if bad == 'table': registers[0] += 2
        elif bad == 'base': registers[17] += 4
        for register, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{register}'), value)
        vectors = [int.from_bytes(bytes((register + byte) % 256 for byte in range(16)), 'little')
                   for register in range(32)]
        for register, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{register}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        arguments = bytes(range(16)); cpu.mem_write(stack, arguments)
        cpu.mem_write(state, struct.pack('<Q', 0xAABBCCDD11223344))
        observed = dict(returned=False, trapped=False, reads=0)
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{register}')) for register in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{register}')) for register in range(32)])
        def code(machine, pc, size, _):
            instruction = ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)
            self.assertFalse(ar.has18(instruction), 'Executed instruction must never access platform X18')
            if pc == base + 0x80: observed['returned'] = True; machine.emu_stop()
        def trap(machine, number, _): observed['trapped'] = True; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base + TABLE <= address < base + TABLE + len(TAGS) * 2: observed['reads'] += 1
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_INTR, trap); cpu.hook_add(UC_HOOK_MEM_READ, read)
        initial = snapshot()
        cpu.emu_start(base + entry, base + len(image.bytes), count=10000)
        self.assertEqual(arguments, bytes(cpu.mem_read(stack, len(arguments))))
        observed.update(initial=initial, final=snapshot(), registers=registers, vectors=vectors,
                        state_value=struct.unpack('<Q', cpu.mem_read(state, 8))[0], stack=stack, base=base)
        return observed

    def test_exact_inline_proof_and_imported_case_roots(self):
        plan = classify(fixture())
        self.assertIsNotNone(plan)
        self.assertEqual((plan['compare_offset'], plan['guard_offset'], plan['producer_offsets'][:2]),
                         (CMP, CMP + 4, [LOAD - 12, LOAD - 8]))
        self.assertEqual((plan['table_offset'], plan['table_bytes'], plan['index_bound']), (TABLE, 70, 34))
        _, report = ai.import_module(fixture(), 'main', package_version=2, checked_stack=True,
                                     indirect_policy='guarded-host')
        self.assertIn(BRANCH, report['code_discovery']['proven_guest_indirect_sites'])
        self.assertTrue({BRANCH + 4 + tag * 4 for tag in TAGS} <= set(report['code_discovery']['roots']))
        image = image_for(fixture(), entry=CMP, proven_guest_indirect_offsets=(BRANCH,))
        original = parse_nso(fixture()).image
        self.assertEqual(original[CMP:LOAD], image.bytes[CMP:LOAD])
        self.assertEqual(original[BRANCH:BRANCH + 4], image.bytes[BRANCH:BRANCH + 4])

    def test_actual_cpu_all_35_indices_preserve_gpr_q_flags_stack_lr(self):
        for index, tag in enumerate(TAGS):
            with self.subTest(index=index):
                result = self.execute(index=index)
                self.assertEqual((True, False, 1), (result['returned'], result['trapped'], result['reads']))
                expected = result['registers'][:]
                expected[0], expected[17] = result['base'] + TABLE, result['base'] + BRANCH + 4 + tag * 4
                self.assertEqual((expected, result['stack'], 0x60000000 if index == 34 else 0x80000000,
                                  result['vectors']), result['final'])
                self.assertEqual(tag + 1, result['state_value'])

    def test_actual_cpu_pre_read_failures_restore_all_state_without_loading(self):
        for index, bad in ((0, 'table'), (0, 'base'), (35, None), (1 << 32, None), (0xFFFFFFFFFFFFFFFF, None)):
            with self.subTest(index=index, bad=bad):
                result = self.execute(index=index, entry=LOAD, bad=bad)
                self.assertEqual((False, True, 0), (result['returned'], result['trapped'], result['reads']))
                self.assertEqual(result['initial'], result['final'])
                self.assertEqual(0xAABBCCDD11223344, result['state_value'])

    def test_missing_role_base_index_bound_and_control_mutations_refuse(self):
        for pc, word in ((CMP, 0x710105FF), (CMP + 4, 0x540000A8),
                         (LOAD - 12, 0x90000021), (LOAD - 8, 0x91200021),
                         (LOAD - 4, adr(LOAD - 4, 0x340, 17)),
                         (LOAD, 0x786F7A52), (LOAD, 0x786F7BF2),
                         (LOAD + 4, 0x8B120631), (BRANCH, 0xD63F0220)):
            source = fixture(); write_image(source, pc, '<I', word)
            with self.subTest(pc=hex(pc), word=hex(word)):
                self.assertIsNone(classify(source))
        for pc in (CMP, CMP + 4, LOAD - 12, LOAD - 8, LOAD - 4, LOAD):
            self.assertIsNone(classify(fixture(), missing=(pc,)))

    def test_only_guarded_preload_entries_are_admitted(self):
        for entry in (LOAD - 12, LOAD - 8, LOAD - 4, LOAD):
            self.assertIsNotNone(classify(fixture(), entries=(entry,)))
        for entry in (CMP + 4, LOAD + 4, BRANCH):
            with self.subTest(entry=entry):
                self.assertIsNone(classify(fixture(), entries=(entry,)))
                with self.assertRaises(ar.RewriteError):
                    image_for(fixture(), entry=CMP, entry_offsets=(entry,), proven_guest_indirect_offsets=(BRANCH,))

    def test_incomplete_inline_ro_cannot_borrow_an_earlier_candidate(self):
        for readonly in ((), ((TABLE, TABLE + 69),)):
            self.assertIsNone(classify(fixture(), readonly=readonly))
        source = fixture()
        write_image(source, 0x330, '<2I', 0x90000020, 0x91200000)
        write_image(source, LOAD - 12, '<I', 0x90000040)
        self.assertIsNone(classify(source))


if __name__ == '__main__':
    unittest.main()
