"""Four proven one-bit fields form a native u16 index, with a live read guard."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
import test_taiko_checked_call as fixed
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

START, LOAD, BRANCH, TABLE = 0x100, 0x144, 0x14C, 0x4080
CASE_BASE = BRANCH + 4
TAGS = (0, 3, 9, 17, 32, 57, 81, 99, 133, 177, 225, 269, 311, 353, 399, 457)


def sequence(start, table):
    load, branch = start + 68, start + 76
    pages = (table >> 12) - ((load - 12) >> 12)
    return [0xB94082EB, 0x531E7568, 0x121D010C, 0x294727E8,
            0x7100011F, 0x1A9FD7EA, 0x7100013F, 0x331E014C,
            0x1A9FD7EA, 0x331F014C, 0xB94043EA, 0x7100015F,
            0x1A9FD7ED, 0x2A0D018C,
            0x9000000D | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5,
            0x910001AD | (table & 4095) << 10, adr(load - 4, branch + 4, 14),
            0x786C79AF, 0x8B0F09CE, 0xD61F01C0]


def fixture():
    data = bytearray(0x5000); data[START:START + 80] = fixed.raw(*sequence(START, TABLE))
    struct.pack_into('<16H', data, TABLE, *TAGS)
    ranges = [(START, START + 80)]
    for tag in TAGS:
        target = CASE_BASE + tag * 4; data[target:target + 4] = ar.word(ar.branch(target, 0x2000)); ranges.append((target, target + 4))
    callback = fixed.fixture()[0][0x100:]; data[0x2000:0x2000 + len(callback)] = callback
    ranges.append((0x2000, 0x2000 + len(callback)))
    return bytes(data), sorted(ranges)


def rewritten(**changes):
    raw, ranges = fixture()
    options = dict(entry_offset=START, text_size=0x3000, code_ranges=ranges, package_version=2,
                   checked_stack=True, readonly_ranges=((0x4000, 0x5000),), proven_guest_indirect_offsets=(BRANCH,))
    return ar.rewrite(raw, **(options | changes))


def classify(raw, ranges, *, entries=(), readonly=((0x4000, 0x5000),), missing=()):
    by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc)) for a, b in ranges for pc in range(a, b, 4) if pc not in missing}
    return ar._guarded_native_readonly_table(by[BRANCH], by, set(entries), raw, readonly)


class NativeU16BooleanIndexTests(unittest.TestCase):
    def execute(self, bits=0, *, entry=START, live_index=None, bad=None):
        image = rewritten(); base, state, helper, output, pointer, stack = 0x10000000, 0x30000000, 0x30001000, 0x30002000, 0x30003000, 0x20008000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000); cpu.mem_map(state, 0x10000); cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_write(base, image.bytes); cpu.mem_write(helper, fixed.raw(0x58000050, 0xD65F03C0) + struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper); cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x1234567800000000 + r * 0x101 for r in range(31)]
        registers[12], registers[13], registers[14] = bits if live_index is None else live_index, base + TABLE, base + CASE_BASE
        registers[18], registers[23], registers[28], registers[30] = 0x77AA000000000018, pointer, output, base + 0x80
        if bad == 'table': registers[13] = 0
        elif bad == 'base': registers[14] += 4
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        payload = bytearray(range(128))
        first, second, third = (7 if bits & 4 else -4), (9 if bits & 2 else 0), (5 if bits & 1 else -1)
        struct.pack_into('<3i', payload, 0x38, first, second, third); cpu.mem_write(stack, bytes(payload))
        source_word = 0xA5A50000 | (2 if bits & 8 else 0)
        cpu.mem_write(pointer + 0x80, struct.pack('<I', source_word)); cpu.mem_write(state, struct.pack('<Q', 0xABCDEF0123456789))
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
            if base + TABLE <= address < base + TABLE + 32: result['reads'] += 1
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_INTR, trap); cpu.hook_add(UC_HOOK_MEM_READ, read)
        initial = snapshot(); cpu.emu_start(base + entry, base + len(image.bytes), count=10000)
        self.assertEqual(registers[18], cpu.reg_read(uc.UC_ARM64_REG_X18)); self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP))
        self.assertEqual(bytes(payload), bytes(cpu.mem_read(stack, 128)))
        self.assertEqual(0xABCDEF0123456789, struct.unpack('<Q', cpu.mem_read(state, 8))[0])
        result.update(cpu=cpu, output=output, base=base, registers=registers, vectors=vectors, stack=stack,
                      initial=initial, final=snapshot(), stack_values=(first, second, third), source_word=source_word)
        return result

    def test_all_sixteen_boolean_combinations_preserve_original_gpr_flags_q_sp_lr(self):
        for bits in range(16):
            with self.subTest(bits=bits):
                result = self.execute(bits); cpu, output = result['cpu'], result['output']
                self.assertEqual((True, False, 1), (result['returned'], result['trapped'], result['reads']))
                expected = result['registers'][:]
                expected[8], expected[9], expected[10] = tuple(value & 0xFFFFFFFF for value in result['stack_values'])
                expected[11], expected[12], expected[13] = result['source_word'], bits, result['base'] + TABLE
                expected[14], expected[15], expected[18] = result['base'] + CASE_BASE + TAGS[bits] * 4, TAGS[bits], 0xABCDEF0123456789
                self.assertEqual(expected, list(struct.unpack('<31Q', cpu.mem_read(output, 248))))
                self.assertEqual((0x20000000 if bits & 1 else 0xA0000000, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
                for r, vector in enumerate(result['vectors']):
                    self.assertEqual(vector, int.from_bytes(cpu.mem_read(output + 0x100 + r * 16, 16), 'little'))

    def test_contaminated_full_index_or_live_bases_trap_without_read_or_state_change(self):
        for index, bad in ((0, 'table'), (0, 'base'), (16, None), (1 << 32, None), (0xFFFFFFFFFFFFFFFF, None)):
            result = self.execute(entry=LOAD, live_index=index, bad=bad)
            self.assertEqual((False, True, 0), (result['returned'], result['trapped'], result['reads']))
            self.assertEqual(result['initial'], result['final'])

    def test_importer_exposes_all_finite_cases_and_preserves_boolean_source_words(self):
        source = source_base(); start, table = 0x3C0, 0x4800
        write_image(source, start, '<20I', *sequence(start, table)); write_image(source, table, '<16H', *TAGS)
        case = start + 80 + TAGS[-1] * 4; write_image(source, case, '<I', 0x52800032)
        package, report = ai.import_module(source, 'main', checked_stack=True, package_version=2, indirect_policy='guarded-host')
        proof = next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset'] == start + 76)
        self.assertEqual((15, 32, 'u16-boolean-composition'), (proof['index_bound'], proof['table_bytes'], proof['bound_candidate_kind']))
        self.assertIn(case, report['code_discovery']['roots'])
        payload = struct.unpack_from('<Q', package, 112)[0]; raw = parse_nso(source).image
        self.assertEqual(raw[start:start + 68], package[payload + start:payload + start + 68])
        self.assertEqual(raw[start + 72:start + 80], package[payload + start + 72:payload + start + 80])

    def test_boolean_roles_width_flags_clobbers_missing_words_ro_and_postload_roots_refuse(self):
        raw, ranges = fixture(); self.assertIsNotNone(classify(raw, ranges))
        for pc, word in ((LOAD - 64, 0x531D7168), (LOAD - 60, 0xB21D010C),
                         (LOAD - 56, 0x29C727E8), (LOAD - 48, 0x9A9FD7EA),
                         (LOAD - 48, 0x1A9F17EA), (LOAD - 40, 0x331E054C),
                         (LOAD - 36, 0x1A9FD7EC), (LOAD - 32, 0x331F012C),
                         (LOAD - 28, 0xB94043EC), (LOAD - 20, 0x1A9FD7EC),
                         (LOAD - 16, 0xAA0D018C), (LOAD - 16, 0x2A0A018C)):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, pc, word)
            self.assertIsNone(classify(damaged, ranges))
        for pc in range(LOAD - 64, LOAD - 12, 4):
            self.assertIsNone(classify(raw, ranges, missing=(pc,)))
        for entry in (LOAD + 4, BRANCH):
            self.assertIsNone(classify(raw, ranges, entries=(entry,)))
            with self.assertRaises(ar.RewriteError): rewritten(entry_offsets=(entry,))
        for readonly in ((), ((TABLE, TABLE + 30),)):
            self.assertIsNone(classify(raw, ranges, readonly=readonly))


if __name__ == '__main__': unittest.main()
