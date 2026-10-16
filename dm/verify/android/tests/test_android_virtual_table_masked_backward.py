"""A full64 low-two-bit index selects an earlier native target from virtual RO."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
import test_taiko_checked_call as fixed
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

# Self-authored case layout; the original game's table stays in ignored evidence.
VALUES = (0, 5, 19, 43)
TABLE, BASE, MASK, LOAD, BRANCH = 0x5080, 0x300, 0x614, 0x61C, 0x624


def fixture():
    raw = bytearray(0x6000)
    raw[0x200:0x20C] = fixed.raw(0xB0000032, 0x91020252, ar.branch(0x208, 0x600))
    raw[0x600:0x628] = fixed.raw(0xAA1E03F6, 0xAA1203F5, 0xD63F0120, 0xAA1503F2,
        0xAA1603FE, 0x9240050A, adr(0x618, BASE, 11), 0x386A6A4C, 0x8B0C096B, 0xD61F0160)
    # The guest callee deliberately changes virtual X18; the caller restores it.
    raw[0x1800:0x1808] = fixed.raw(0xD2801BD2, 0xD65F03C0)
    targets = tuple(BASE + value * 4 for value in VALUES)
    ranges = [(0x200, 0x20C), (0x600, 0x628), (0x1800, 0x1808)]
    for target in targets:
        raw[target:target + 4] = ar.word(ar.branch(target, 0x2000)); ranges.append((target, target + 4))
    callback = fixed.fixture()[0][0x100:]
    raw[0x2000:0x2000 + len(callback)] = callback; ranges.append((0x2000, 0x2000 + len(callback)))
    raw[TABLE:TABLE + 4] = bytes(VALUES)
    return bytes(raw), sorted(ranges), targets


def rewritten(**changes):
    raw, ranges, _ = fixture()
    options = dict(entry_offset=0x200, text_size=0x3000, code_ranges=ranges, package_version=2,
                   checked_stack=True, readonly_ranges=((0x4000, 0x6000),), proven_guest_indirect_offsets=(BRANCH,))
    return ar.rewrite(raw, **(options | changes))


class VirtualTableMaskedBackwardTests(unittest.TestCase):
    def execute(self, index=0, *, entry=0x200, virtual=None, target_base=None, live_index=None):
        image = rewritten(); base, state, helper, output, stack = 0x10000000, 0x30000000, 0x30001000, 0x30002000, 0x20008000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000); cpu.mem_map(state, 0x10000); cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_write(base, image.bytes); cpu.mem_write(helper, fixed.raw(0x58000050, 0xD65F03C0) + struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper); cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x12340000 + r * 0x101 for r in range(31)]
        registers[8], registers[9], registers[10] = 0x8000000100000000 | index, base + 0x1800, index if live_index is None else live_index
        registers[11], registers[18], registers[28], registers[30] = (base + BASE if target_base is None else target_base,
                                                                   0x77AA000000000018, output, base + 0x80)
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        arguments = bytes(range(16)); cpu.mem_write(stack, arguments)
        table_state = base + TABLE if virtual is None else virtual
        cpu.mem_write(state, struct.pack('<Q', table_state))
        result = dict(trapped=False, returned=False, reads=0, target=None)
        targets = set(fixture()[2])
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine, pc, size, _):
            ins = ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)
            self.assertFalse(ar.has18(ins), 'Executed instructions must never use platform X18')
            if pc - base in targets: result['target'] = pc - base
            if pc == base + 0x80: result['returned'] = True; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base + TABLE <= address < base + TABLE + 4: result['reads'] += 1
        def trap(machine, number, _): result['trapped'] = True; machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_MEM_READ, read); cpu.hook_add(UC_HOOK_INTR, trap)
        initial = snapshot(); cpu.emu_start(base + entry, base + len(image.bytes), count=20000)
        result.update(cpu=cpu, output=output, registers=registers, vectors=vectors, base=base, state=state,
                      stack=stack, arguments=arguments, table_state=table_state, initial=initial, final=snapshot())
        self.assertEqual(registers[18], cpu.reg_read(uc.UC_ARM64_REG_X18))
        self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP)); self.assertEqual(arguments, bytes(cpu.mem_read(stack, 16)))
        return result

    def test_four_upper_bit_inputs_and_postcall_restore_preserve_actual_cpu_state(self):
        for index, value in enumerate(VALUES):
            with self.subTest(index=index):
                result = self.execute(index); cpu, output, base = result['cpu'], result['output'], result['base']
                self.assertEqual((False, True, 1, BASE + value * 4), (result['trapped'], result['returned'], result['reads'], result['target']))
                expected = result['registers'][:]
                expected[10], expected[11], expected[12] = index, base + BASE + value * 4, value
                expected[18], expected[21], expected[22] = base + TABLE, base + TABLE, base + 0x80
                self.assertEqual(expected, list(struct.unpack('<31Q', cpu.mem_read(output, 248))))
                self.assertEqual(base + TABLE, struct.unpack('<Q', cpu.mem_read(result['state'], 8))[0])
                self.assertEqual((0xB0000000, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
                for r, vector in enumerate(result['vectors']):
                    self.assertEqual(vector, int.from_bytes(cpu.mem_read(output + 0x100 + r * 16, 16), 'little'))

    def test_loop_preload_paths_use_actual_state_without_constructor_dominance(self):
        for entry in (MASK, LOAD - 4, LOAD):
            result = self.execute(3, entry=entry)
            self.assertTrue(result['returned']); self.assertEqual(1, result['reads'])
            self.assertEqual(BASE + VALUES[3] * 4, result['target'])
        for options in (dict(virtual=0), dict(virtual=0x10005084), dict(target_base=0),
                        dict(target_base=0x10000304), dict(live_index=1 << 32), dict(live_index=4)):
            with self.subTest(options=options):
                result = self.execute(entry=LOAD, **options)
                self.assertEqual((True, 0), (result['trapped'], result['reads']))
                self.assertEqual(result['initial'], result['final'])
                self.assertEqual(result['table_state'], struct.unpack('<Q', result['cpu'].mem_read(result['state'], 8))[0])

    def test_full_import_finds_previously_unselected_original_virtual_base_restores(self):
        source = source_base()
        write_image(source, 0x300, '<3I', 0x90000032, 0x91200252, ar.branch(0x308, MASK))
        write_image(source, MASK, '<5I', 0x9240050A, adr(MASK + 4, 0x340, 11), 0x386A6A4C, 0x8B0C096B, 0xD61F0160)
        write_image(source, 0x4800, '<4B', *VALUES)
        case = 0x340 + VALUES[-1] * 4
        write_image(source, case, '<3I', 0x90000032, 0x91200252, 0xD65F03C0)
        _, report = ai.import_module(source, 'main', checked_stack=True, package_version=2, indirect_policy='guarded-host')
        proof = next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset'] == BRANCH)
        self.assertEqual('full64-low2-mask', proof['bound_candidate_kind'])
        self.assertEqual((3, 4), (proof['index_bound'], proof['table_bytes']))
        self.assertIn(case, report['code_discovery']['roots'])
        self.assertTrue({case, case + 4} <= {site['offset'] for site in report['rewrite']['sites']})

    def test_masks_aliases_ro_proof_postload_entries_and_role_mutations_refuse(self):
        raw, ranges, _ = fixture()
        def plan(data, entries=(), readonly=((0x4000, 0x6000),)):
            by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', data, pc)[0], pc)) for a, b in ranges for pc in range(a, b, 4)}
            return ar._guarded_native_readonly_table(by[BRANCH], by, set(entries), data, readonly, virtual_table=True)
        self.assertIsNotNone(plan(raw))
        for pc, word in ((MASK, 0x1200050A), (MASK, 0x9240090A), (MASK, 0x9240064A),
                         (MASK, 0x9240050B), (LOAD - 4, adr(LOAD - 4, BRANCH + 4, 11)),
                         (LOAD, 0x386B6A4C), (LOAD + 4, 0x8B0C096A)):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, pc, word)
            self.assertIsNone(plan(damaged))
        for entry in (LOAD + 4, BRANCH):
            self.assertIsNone(plan(raw, entries=(entry,)))
            with self.assertRaises(ar.RewriteError): rewritten(entry_offsets=(entry,))
        for readonly in ((), ((TABLE, TABLE + 3),)):
            self.assertIsNone(plan(raw, readonly=readonly))
        self.assertEqual(raw[LOAD + 4:BRANCH + 4], rewritten().bytes[LOAD + 4:BRANCH + 4])


if __name__ == '__main__': unittest.main()
