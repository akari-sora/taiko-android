"""A virtual table constructor retains one original non-writeback FP pair store."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
import test_taiko_checked_call as fixed
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

START, PAIR, LOAD, BRANCH, TABLE = 0x100, 0x110, 0x12C, 0x134, 0x4080
CASE_BASE = BRANCH + 4
TAGS = (0, 3, 11, 29, 53, 89, 137)


def fixture():
    data = bytearray(0x5000)
    words = [0x90000032, 0x2A1F03E0, 0x2A1F03EE, 0x910042D1, 0xA93F2BA8,
             0x910012A8, 0x52800038, 0x91020252, 0x7100193F,
             0x54000008 | (((0x1800 - 0x124) // 4) << 5), adr(LOAD - 4, CASE_BASE, 10),
             0x38696A4B, 0x8B0B094A, 0xD61F0140]
    data[START:START + len(words) * 4] = fixed.raw(*words)
    data[TABLE:TABLE + 7] = bytes(TAGS); data[0x1800:0x1804] = ar.word(0xD65F03C0)
    ranges = [(START, START + len(words) * 4), (0x1800, 0x1804)]
    for tag in TAGS:
        target = CASE_BASE + tag * 4; data[target:target + 4] = ar.word(ar.branch(target, 0x2000)); ranges.append((target, target + 4))
    callback = fixed.fixture()[0][0x100:]; data[0x2000:0x2000 + len(callback)] = callback
    ranges.append((0x2000, 0x2000 + len(callback)))
    return bytes(data), sorted(ranges)


def rewritten(**changes):
    raw, ranges = fixture()
    options = dict(entry_offset=START, text_size=0x3000, code_ranges=ranges, checked_stack=True,
                   package_version=2, readonly_ranges=((0x4000, 0x5000),), proven_guest_indirect_offsets=(BRANCH,))
    return ar.rewrite(raw, **(options | changes))


def classify(raw, ranges, *, entries=(), missing=(), readonly=((0x4000, 0x5000),)):
    by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc)) for a, b in ranges for pc in range(a, b, 4) if pc not in missing}
    return ar._guarded_native_readonly_table(by[BRANCH], by, set(entries), raw, readonly, virtual_table=True)


class VirtualTableFrameStoreGapTests(unittest.TestCase):
    def execute(self, index=0, *, entry=START, bad=None):
        image = rewritten(); base, state, helper, output, stack = 0x10000000, 0x30000000, 0x30001000, 0x30002000, 0x20008000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000); cpu.mem_map(state, 0x10000); cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_write(base, image.bytes); cpu.mem_write(helper, fixed.raw(0x58000050, 0xD65F03C0) + struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper); cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x1234567800000000 + r * 0x101 for r in range(31)]
        registers[9], registers[10], registers[18], registers[28], registers[29], registers[30] = index, base + CASE_BASE, 0x77AA000000000018, output, stack + 0x80, base + 0x80
        if bad == 'base': registers[10] += 4
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        payload = bytes(range(128)); cpu.mem_write(stack, payload)
        virtual = 0 if bad == 'null' else base + TABLE + (1 if bad == 'table' else 0)
        cpu.mem_write(state, struct.pack('<Q', virtual)); result = dict(returned=False, trapped=False, reads=0)
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine, pc, size, _):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)))
            if pc == base + 0x80: result['returned'] = True; machine.emu_stop()
        def trap(machine, number, _): result['trapped'] = True; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base + TABLE <= address < base + TABLE + 7: result['reads'] += 1
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_INTR, trap); cpu.hook_add(UC_HOOK_MEM_READ, read)
        initial = snapshot(); cpu.emu_start(base + entry, base + len(image.bytes), count=10000)
        self.assertEqual(registers[18], cpu.reg_read(uc.UC_ARM64_REG_X18)); self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP))
        self.assertEqual(payload[:112], bytes(cpu.mem_read(stack, 112)))
        result.update(cpu=cpu, output=output, base=base, registers=registers, vectors=vectors, stack=stack,
                      initial=initial, final=snapshot(), initial_payload=payload, initial_virtual=virtual, state=state)
        return result

    def test_all_seven_cases_store_old_arguments_and_preserve_original_cpu_state(self):
        for index, tag in enumerate(TAGS):
            result = self.execute(index); cpu, output = result['cpu'], result['output']
            self.assertEqual((True, False, 1), (result['returned'], result['trapped'], result['reads']))
            original = result['registers']; expected = original[:]
            expected[0], expected[8], expected[10], expected[11], expected[14], expected[17], expected[24] = (
                0, original[21] + 4, result['base'] + CASE_BASE + tag * 4, tag, 0, original[22] + 16, 1)
            expected[18] = result['base'] + TABLE
            self.assertEqual(expected, list(struct.unpack('<31Q', cpu.mem_read(output, 248))))
            self.assertEqual((original[8], original[10]), struct.unpack('<2Q', cpu.mem_read(result['stack'] + 0x70, 16)))
            flags = 0x60000000 if index == 6 else 0x80000000
            self.assertEqual((flags, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
            self.assertEqual(result['base'] + TABLE, struct.unpack('<Q', cpu.mem_read(result['state'], 8))[0])
            for r, vector in enumerate(result['vectors']):
                self.assertEqual(vector, int.from_bytes(cpu.mem_read(output + 0x100 + r * 16, 16), 'little'))

    def test_invalid_actual_state_is_zero_read_and_restores_all_args_and_frame_bytes(self):
        for index, bad in ((0, 'null'), (0, 'table'), (0, 'base'), (7, None), (1 << 32, None)):
            result = self.execute(index, entry=LOAD, bad=bad)
            self.assertEqual((False, True, 0), (result['returned'], result['trapped'], result['reads']))
            self.assertEqual(result['initial'], result['final'])
            self.assertEqual(result['initial_payload'], bytes(result['cpu'].mem_read(result['stack'], 128)))
            self.assertEqual(result['initial_virtual'], struct.unpack('<Q', result['cpu'].mem_read(result['state'], 8))[0])

    def test_full_import_unlocks_original_virtual_case_and_keeps_store_word_in_place(self):
        source = source_base(); start, table = 0x3C0, 0x4800; raw, _ = fixture()
        words = list(struct.unpack_from('<14I', raw, START)); words[0] = 0x90000032; words[7] = 0x91200252
        words[9] = 0x54000008 | (((0xF00 - (start + 36)) // 4) << 5)
        words[10] = adr(start + 40, start + 56, 10)
        write_image(source, start, '<14I', *words); write_image(source, table, '<7B', *TAGS)
        case = start + 56 + TAGS[-1] * 4; write_image(source, case, '<I', 0x52800032)
        package, report = ai.import_module(source, 'main', checked_stack=True, package_version=2, indirect_policy='guarded-host')
        self.assertIn(case, report['code_discovery']['roots'])
        payload = struct.unpack_from('<Q', package, 112)[0]
        self.assertEqual(0xA93F2BA8, struct.unpack_from('<I', package, payload + start + 16)[0])

    def test_writeback_wrong_base_virtual_source_clobber_flag_missing_and_entry_mutations_refuse(self):
        raw, ranges = fixture(); self.assertIsNotNone(classify(raw, ranges))
        for pc, word in ((PAIR, 0xA9BF2BA8), (PAIR, 0xA8BF2BA8), (PAIR, 0xA93F2B88),
                         (PAIR, 0xA93F2BB2), (PAIR, 0xA93F4BA8), (PAIR, 0xF81F03A8),
                         (START + 8, 0xAA1203EE), (START + 12, 0xB10042D1),
                         (START + 20, 0x910012B2)):
            data = bytearray(raw); struct.pack_into('<I', data, pc, word)
            self.assertIsNone(classify(data, ranges))
        self.assertIsNone(classify(raw, ranges, missing=(PAIR,)))
        for entry in (PAIR, START + 28, LOAD + 4, BRANCH):
            self.assertIsNone(classify(raw, ranges, entries=(entry,)))
            with self.assertRaises(ar.RewriteError): rewritten(entry_offsets=(entry,))
        for readonly in ((), ((TABLE, TABLE + 6),)):
            self.assertIsNone(classify(raw, ranges, readonly=readonly))


if __name__ == '__main__': unittest.main()
