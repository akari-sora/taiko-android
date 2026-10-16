"""A bounded native-u16 schedule retains SP stores and four native MOV effects."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
import test_taiko_checked_call as fixed
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

START, COMPARE, LOAD, BRANCH, TABLE = 0x100, 0x108, 0x134, 0x14C, 0x4080
CASE_BASE = BRANCH + 4
AUTHORED_TAGS = (0, 3, 9, 17, 26, 42, 58, 71, 99, 124, 173, 241)


def sequence(start, table, bound=83):
    load, branch = start + 52, start + 76
    page_pc = load - 16; pages = (table >> 12) - (page_pc >> 12)
    return [0x38766AA8, 0x5100950A, 0x7100015F | bound << 10,
            0x290337E9, 0xB90023FB, 0x390093E8,
            0x54000008 | (((0x1800 - (start + 24)) // 4 & 0x7FFFF) << 5),
            0x910006CE, 0x8B0E02AB,
            0x90000010 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5,
            0x91000210 | (table & 4095) << 10, 0xF9000BEB,
            adr(load - 4, branch + 4, 15), 0x786A7A0B, 0x8B0B09EF,
            0x2A1F03EC, 0x2A1F03E8, 0x52800AEA, 0x2A1903EB, 0xD61F01E0]


def fixture(bound=83):
    raw = bytearray(0x5000); words = sequence(START, TABLE, bound)
    raw[START:START + 80] = fixed.raw(*words)
    tags = tuple(AUTHORED_TAGS[index % len(AUTHORED_TAGS)] for index in range(bound + 1))
    struct.pack_into('<' + 'H' * len(tags), raw, TABLE, *tags)
    ranges = [(START, START + 80), (0x1800, 0x1804)]
    raw[0x1800:0x1804] = ar.word(0xD65F03C0)
    for tag in sorted(set(tags)):
        target = CASE_BASE + tag * 4; raw[target:target + 4] = ar.word(ar.branch(target, 0x2000)); ranges.append((target, target + 4))
    callback = fixed.fixture()[0][0x100:]
    raw[0x2000:0x2000 + len(callback)] = callback; ranges.append((0x2000, 0x2000 + len(callback)))
    return bytes(raw), sorted(ranges), tags


def rewritten(bound=83, **changes):
    raw, ranges, tags = fixture(bound)
    options = dict(entry_offset=START, text_size=0x3000, code_ranges=ranges, checked_stack=True,
                   package_version=2, readonly_ranges=((0x4000, 0x5000),), proven_guest_indirect_offsets=(BRANCH,))
    return ar.rewrite(raw, **(options | changes))


def classify(raw, ranges, *, entries=(), readonly=((0x4000, 0x5000),)):
    by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc)) for a, b in ranges for pc in range(a, b, 4)}
    return ar._guarded_native_readonly_table(by[BRANCH], by, set(entries), raw, readonly)


class NativeU16SpStoreScheduleTests(unittest.TestCase):
    def execute(self, index=0, *, entry=START, bad=None):
        image = rewritten(); base, state, helper, output, pointer, stack = 0x10000000, 0x30000000, 0x30001000, 0x30002000, 0x30003000, 0x20008000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000); cpu.mem_map(state, 0x10000); cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_write(base, image.bytes); cpu.mem_write(helper, fixed.raw(0x58000050, 0xD65F03C0) + struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper); cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x1234567800000000 + r * 0x101 for r in range(31)]
        registers[10], registers[15], registers[16] = index, base + CASE_BASE, base + TABLE
        registers[18], registers[21], registers[22], registers[28], registers[30] = 0x77AA000000000018, pointer, 2, output, base + 0x80
        if bad == 'table': registers[16] = 0
        elif bad == 'base': registers[15] += 4
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        arguments = bytes(range(16)); cpu.mem_write(stack, arguments + bytes([0xCC] * 64))
        cpu.mem_write(pointer + 2, bytes([(index + 0x25) & 255])); cpu.mem_write(state, struct.pack('<Q', 0xABCDEF0123456789))
        result = dict(trapped=False, returned=False, reads=0)
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine, pc, size, _):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)))
            if pc == base + 0x80: result['returned'] = True; machine.emu_stop()
        def trap(machine, number, _): result['trapped'] = True; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base + TABLE <= address < base + TABLE + 168: result['reads'] += 1
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_INTR, trap); cpu.hook_add(UC_HOOK_MEM_READ, read)
        initial = snapshot(); initial_memory = bytes(cpu.mem_read(stack, 80))
        cpu.emu_start(base + entry, base + len(image.bytes), count=10000)
        self.assertEqual(registers[18], cpu.reg_read(uc.UC_ARM64_REG_X18)); self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP))
        self.assertEqual(arguments, bytes(cpu.mem_read(stack, 16)))
        self.assertEqual(0xABCDEF0123456789, struct.unpack('<Q', cpu.mem_read(state, 8))[0])
        result.update(cpu=cpu, output=output, base=base, registers=registers, vectors=vectors, pointer=pointer,
                      stack=stack, initial=initial, final=snapshot(), initial_memory=initial_memory)
        return result

    def test_all_84_indices_preserve_original_sp_effects_gpr_q_flags_sp_lr(self):
        for index in range(84):
            with self.subTest(index=index):
                result = self.execute(index); cpu, output = result['cpu'], result['output']
                self.assertEqual((False, True, 1), (result['trapped'], result['returned'], result['reads']))
                tag = AUTHORED_TAGS[index % len(AUTHORED_TAGS)]
                expected = result['registers'][:]
                expected[8], expected[10], expected[11], expected[12], expected[14] = 0, 0x57, expected[25] & 0xFFFFFFFF, 0, 3
                expected[15], expected[16], expected[18] = result['base'] + CASE_BASE + tag * 4, result['base'] + TABLE, 0xABCDEF0123456789
                self.assertEqual(expected, list(struct.unpack('<31Q', cpu.mem_read(output, 248))))
                flags = 0x60000000 if index == 83 else 0x80000000
                self.assertEqual((flags, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
                stored = struct.unpack('<QIIIB', cpu.mem_read(result['stack'] + 16, 21))
                self.assertEqual((result['pointer'] + 3, expected[9] & 0xFFFFFFFF, expected[13] & 0xFFFFFFFF,
                                  expected[27] & 0xFFFFFFFF, index + 0x25), stored)
                for r, vector in enumerate(result['vectors']):
                    self.assertEqual(vector, int.from_bytes(cpu.mem_read(output + 0x100 + r * 16, 16), 'little'))

    def test_invalid_live_bases_or_full_indices_trap_without_read_or_sp_payload_change(self):
        for index, bad in ((0, 'table'), (0, 'base'), (84, None), (1 << 32, None), (0xFFFFFFFFFFFFFFFF, None)):
            result = self.execute(index, entry=LOAD, bad=bad)
            self.assertEqual((False, True, 0), (result['returned'], result['trapped'], result['reads']))
            self.assertEqual(result['initial'], result['final'])
            self.assertEqual(result['initial_memory'], bytes(result['cpu'].mem_read(result['stack'], 80)))

    def test_importer_discovers_virtual_cases_and_keeps_all_original_store_suffix_bytes(self):
        source = source_base(); start, table = 0x3C0, 0x4800; words = sequence(start, table)
        words[6] = 0x54000008 | (((0xF00 - (start + 24)) // 4) << 5)
        write_image(source, start, '<20I', *words)
        tags = tuple(AUTHORED_TAGS[i % len(AUTHORED_TAGS)] for i in range(84)); write_image(source, table, '<84H', *tags)
        case_base = start + 80; case = case_base + AUTHORED_TAGS[-1] * 4
        write_image(source, case, '<I', 0x52800032)
        package, report = ai.import_module(source, 'main', package_version=2, checked_stack=True, indirect_policy='guarded-host')
        proof = next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset'] == start + 76)
        self.assertEqual(83, proof['index_bound']); self.assertIn(case, report['code_discovery']['roots'])
        self.assertEqual('scheduled-u16-sp-stores', proof['bound_candidate_kind'])
        payload = struct.unpack_from('<Q', package, 112)[0]; raw = parse_nso(source).image
        self.assertEqual(raw[start:start + 52], package[payload + start:payload + start + 52])
        self.assertEqual(raw[start + 56:start + 80], package[payload + start + 56:payload + start + 80])

    def test_flag_index_writeback_suffix_entry_ro_and_bounds_mutations_refuse(self):
        raw, ranges, _ = fixture(); self.assertIsNotNone(classify(raw, ranges))
        for pc, word in ((COMPARE + 4, 0x7100055F), (COMPARE + 4, 0x298337E9),
                         (COMPARE + 8, 0xB80087FB), (COMPARE + 12, 0x390093EA),
                         (COMPARE + 16, 0x54000000), (LOAD - 24, 0xB10006CE),
                         (LOAD - 24, 0x910006CA), (LOAD - 20, 0x8B0E02AA),
                         (LOAD - 8, 0xF8008FEB), (LOAD + 8, 0x2A1F03EF),
                         (LOAD + 12, 0x7100055F), (LOAD + 16, 0x72800AEA), (LOAD + 20, 0xAA1903EB)):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, pc, word)
            self.assertIsNone(classify(damaged, ranges))
        for entry in range(LOAD + 4, BRANCH + 4, 4):
            self.assertIsNone(classify(raw, ranges, entries=(entry,)))
            with self.assertRaises(ar.RewriteError): rewritten(entry_offsets=(entry,))
        self.assertIsNone(classify(raw, ranges, readonly=((TABLE, TABLE + 166),)))
        for bound in (64, 120, 255):
            data, domains, _ = fixture(bound); self.assertIsNotNone(classify(data, domains))
        data, domains, _ = fixture(256); self.assertIsNone(classify(data, domains))
        damaged = bytearray(raw); struct.pack_into('<I', damaged, LOAD, 0x386A6A0B)
        self.assertIsNone(classify(damaged, ranges))


if __name__ == '__main__': unittest.main()
