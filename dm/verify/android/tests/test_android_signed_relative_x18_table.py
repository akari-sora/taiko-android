"""Signed RO offsets alias virtual X18's index, loaded offset and jump target."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import android_import as ai
import test_taiko_checked_call as fixed
from test_android_runtime_ro_sub_inline import source_base, write_image
from nso_format import parse_nso
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc


def prefix(start, table, default):
    pages = (table >> 12) - (start >> 12)
    page = 0x90000000 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5
    guard_pc = start + 60
    return [page | 11, 0x52A71C6C, page | 13, 0x9108868A, 0x321D03EE,
            0x9100016B | (table & 4095) << 10, 0x7291C72C, 0x910741AD,
            0x93407DCE, 0x8B0E0331, 0xB940022F, 0x53197DF2,
            0x530161F0, 0x120001EF, 0x7100225F,
            0x54000008 | (((default - guard_pc) // 4 & 0x7FFFF) << 5),
            0xB8B27972, 0x8B0B0252, 0xD61F0240]


def fixture():
    start, table = 0x100, 0x4080
    targets = (0x400, 0x500, 0x600, 0x700, 0x900, 0x900, 0x900, 0x900, 0x800)
    raw = bytearray(0x5000)
    words = prefix(start, table, targets[4])
    raw[start:start + len(words) * 4] = fixed.raw(*words)
    callback = fixed.fixture()[0][0x100:]
    ranges = [(start, start + len(words) * 4)]
    for target in sorted(set(targets)):
        raw[target:target + len(callback)] = callback
        ranges.append((target, target + len(callback)))
    struct.pack_into('<9i', raw, table, *(target - table for target in targets))
    return bytes(raw), ranges, targets, table, start


def rewritten(**changes):
    raw, ranges, targets, table, start = fixture()
    options = dict(entry_offset=start, text_size=0x2000, code_ranges=ranges,
                   package_version=2, checked_stack=True, readonly_ranges=((0x4000, 0x5000),))
    return ar.rewrite(raw, **(options | changes))


class SignedRelativeX18Tests(unittest.TestCase):
    def execute(self, *, index=0, entry=None, wrong_base=False, virtual=None, mutate=None):
        source, _, targets, table, start = fixture()
        # Metadata still declares the original entry; direct execution below
        # injects bad runtime state without admitting a post-load entry root.
        image = rewritten()
        base, state, helper, output, input_ = 0x10000000, 0x30000000, 0x30001000, 0x30002000, 0x30003000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000); cpu.mem_map(0x20000000, 0x10000); cpu.mem_map(state, 0x10000)
        cpu.mem_write(base, image.bytes)
        cpu.mem_write(helper, fixed.raw(0x58000050, 0xD65F03C0) + struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper)
            cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        registers = [0x12340000 + r * 0x101 for r in range(31)]
        registers[18], registers[25], registers[28], registers[30] = 0x77AAFFFF00000018, input_, output, base + 0x80
        registers[14] = 8
        registers[11] = 0 if wrong_base else base + table
        for r, value in enumerate(registers): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r + i) % 256 for i in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        stack = 0x20008000; cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        arguments = bytes(range(16)); cpu.mem_write(stack, arguments)
        cpu.mem_write(input_ + 8, struct.pack('<I', (index << 25) | 1))
        cpu.mem_write(state, struct.pack('<Q', index if virtual is None else virtual))
        if mutate is not None: cpu.mem_write(base + table, struct.pack('<i', mutate))
        observed = dict(trapped=False, returned=False, reads=0, before_jump=None, target=None)
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine, pc, size, _):
            instruction = ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)
            self.assertFalse(ar.has18(instruction), 'Executed instructions must never use platform X18')
            if pc == base + start + 72: observed['before_jump'] = snapshot()
            if pc - base in targets: observed['target'] = pc - base
            if pc == base + 0x80: observed['returned'] = True; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base + table <= address < base + table + 36: observed['reads'] += 1
        def trap(machine, number, _): observed['trapped'] = True; machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_INTR, trap); cpu.hook_add(UC_HOOK_MEM_READ, read)
        initial = snapshot()
        cpu.emu_start(base + (entry if entry is not None else start), base + len(image.bytes), count=20000)
        self.assertEqual(registers[18], cpu.reg_read(uc.UC_ARM64_REG_X18))
        self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP))
        self.assertEqual(arguments, bytes(cpu.mem_read(stack, 16)))
        observed.update(cpu=cpu, initial=initial, final=snapshot(), registers=registers, vectors=vectors,
                        state=state, output=output, base=base, stack=stack, arguments=arguments)
        return observed

    def test_actual_cpu_all_indices_signed_load_once_and_exact_case_state(self):
        _, _, targets, table, start = fixture()
        for index, target in enumerate(targets):
            with self.subTest(index=index):
                result = self.execute(index=index)
                self.assertEqual((False, True, 1, target),
                                 (result['trapped'], result['returned'], result['reads'], result['target']))
                cpu, output, base = result['cpu'], result['output'], result['base']
                expected = result['registers'][:]
                expected[10], expected[11], expected[12] = expected[20] + 0x221, base + table, 0x38E38E39
                expected[13], expected[14], expected[15], expected[16], expected[17] = base + 0x41D0, 8, 1, 0, 0x30003008
                expected[18] = base + target
                self.assertEqual(expected, list(struct.unpack('<31Q', cpu.mem_read(output, 248))))
                self.assertEqual(base + target, struct.unpack('<Q', cpu.mem_read(result['state'], 8))[0])
                flags = 0x60000000 if index == 8 else 0x80000000
                self.assertEqual((flags, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
                for r, vector in enumerate(result['vectors']):
                    self.assertEqual(vector, int.from_bytes(cpu.mem_read(output + 0x100 + r * 16, 16), 'little'))

    def test_pre_read_wrong_base_and_full_virtual_index_restore_everything(self):
        load = fixture()[4] + 64
        for value, wrong in ((0, True), (1 << 32, False), (9, False), (0xFFFFFFFFFFFFFFFF, False)):
            with self.subTest(value=value, wrong_base=wrong):
                result = self.execute(entry=load, virtual=value, wrong_base=wrong)
                self.assertTrue(result['trapped']); self.assertEqual(0, result['reads'])
                self.assertEqual(result['initial'], result['final'])
                self.assertEqual(value, struct.unpack('<Q', result['cpu'].mem_read(result['state'], 8))[0])

    def test_unknown_interior_null_targets_restore_old_lr_and_all_state(self):
        branch = fixture()[4] + 72
        for target in (0, 0x10000404, 0x10000000, 0x20000400, 0xFFFFFFFFFFFFFFFF):
            with self.subTest(target=hex(target)):
                result = self.execute(entry=branch, virtual=target)
                self.assertTrue(result['trapped']); self.assertFalse(result['returned'])
                self.assertEqual(result['initial'], result['final'])

    def test_corrupt_signed_offset_cannot_jump_outside_derived_exact_set(self):
        _, _, _, table, _ = fixture()
        result = self.execute(mutate=0x404 - table)
        self.assertTrue(result['trapped']); self.assertEqual(1, result['reads'])
        self.assertEqual(result['before_jump'], result['final'])
        self.assertEqual(0x10000404, struct.unpack('<Q', result['cpu'].mem_read(result['state'], 8))[0])

    def test_importer_records_distinct_signed_proof_and_all_six_original_case_roots(self):
        source = source_base(); start, table = 0x300, 0x4800
        targets = (0x500, 0x600, 0x700, 0x800, 0xA00, 0xA00, 0xA00, 0xA00, 0x900)
        write_image(source, start, '<19I', *prefix(start, table, targets[4]))
        write_image(source, table, '<9i', *(target - table for target in targets))
        write_image(source, 0x700, '<I', 0x52800032)
        _, report = ai.import_module(source, 'main', package_version=2, checked_stack=True, indirect_policy='guarded-host')
        proof = report['code_discovery']['signed_relative_jump_tables'][0]
        self.assertEqual('runtime-virtual-x18-signed32-relative-ro-v1', proof['rule'])
        self.assertEqual(sorted(set(targets)), proof['target_offsets'])
        self.assertTrue(set(targets) <= set(report['code_discovery']['roots']))
        self.assertEqual(hashlib.sha256(struct.pack('<9i', *(target - table for target in targets))).hexdigest(), proof['table_sha256'])

    def test_bad_signed_ranges_roles_postload_entries_and_protected_cases_refuse(self):
        raw, ranges, targets, table, start = fixture()
        def plan(data, entries=(), protected=()):
            instructions = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', data, pc)[0], pc))
                            for begin, end in ranges for pc in range(begin, end, 4)}
            return ar.signed_relative_x18_table(instructions[start + 72], instructions, set(entries), data,
                                              ((0x4000, 0x5000),), text_size=0x2000, protected_ranges=protected)
        self.assertIsNotNone(plan(raw))
        for offset in (-2147483648, 2147483647, 0x401 - table):
            damaged = bytearray(raw); struct.pack_into('<i', damaged, table, offset)
            self.assertIsNone(plan(damaged))
        for pc, word in ((start + 44, 0x53197E32), (start + 48, 0x530161F2),
                         (start + 52, 0x1200016B), (start + 64, 0xB8B27973),
                         (start + 68, 0x8B0A0252), (start + 60, 0x54000000)):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, pc, word)
            self.assertIsNone(plan(damaged))
        for entry in (start + 68, start + 72):
            self.assertIsNone(plan(raw, entries=(entry,)))
            with self.assertRaises(ar.RewriteError): rewritten(entry_offsets=(entry,))
        self.assertIsNone(plan(raw, protected=((targets[0], targets[0] + 4),)))
        with self.assertRaises(ar.RewriteError): rewritten(readonly_ranges=())

    def test_separate_earlier_constructor_is_not_the_loop_table_and_skipped_setup_stays_guarded(self):
        raw, ranges, targets, table, start = fixture()
        damaged = bytearray(raw)
        struct.pack_into('<3I', damaged, 0xC0, 0x9000002B, 0x9103016B, ar.branch(0xC8, start))
        image = ar.rewrite(bytes(damaged), entry_offset=0xC0, text_size=0x2000,
                           code_ranges=[(0xC0, 0xCC), *ranges], checked_stack=True,
                           package_version=2, readonly_ranges=((0x4000, 0x5000),))
        self.assertTrue(any(site.offset == start + 64 for site in image.sites))
        result = self.execute(entry=start + 32, index=8)
        self.assertTrue(result['returned']); self.assertEqual(1, result['reads'])
        self.assertEqual(targets[8], result['target'])
        bad = self.execute(entry=start + 32, wrong_base=True)
        self.assertTrue(bad['trapped']); self.assertEqual(0, bad['reads'])
        self.assertEqual(bad['registers'][30], bad['cpu'].reg_read(uc.UC_ARM64_REG_X30))


if __name__ == '__main__': unittest.main()
