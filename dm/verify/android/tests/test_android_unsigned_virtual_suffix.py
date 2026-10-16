"""Authored finite dispatch suffixes execute actual lowered A64 on Unicorn."""
import os
from pathlib import Path
import struct
import sys
import unittest

HERE = Path(__file__).resolve().parent
DEFAULT_TOOLS = HERE / 'tools' if (HERE / 'tools').is_dir() else Path(__file__).resolve().parents[4] / 'dm/tools'
sys.path.insert(0, os.environ.get('DM_SUFFIX_TOOLS', str(DEFAULT_TOOLS)))
import android_rewrite as ar
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

START, TABLE, BASE, DEFAULT = 0x100, 0x20000, 0x2000, 0x600

def pack(*words): return struct.pack('<' + 'I' * len(words), *words)

def adr(pc, target, register):
    delta = (target-pc) & 0x1fffff
    return 0x10000000 | (delta & 3) << 29 | (delta >> 2) << 5 | register

def fixture(kind='mov', suffix=None, prior_equal=False):
    width = 2 if kind == 'add' else 1
    target, loaded, table, index = 10, 11, 12, 9
    words = [0x9000010c, 0x9100018c]
    if prior_equal:
        words += [0xf100113f, 0x54000000 | ((DEFAULT-START-12)//4 << 5)]
    compare = START+len(words)*4
    words += [0x71000d3f, 0x54000008 | ((DEFAULT-compare-4)//4 << 5), adr(compare+8, BASE, target),
             (0x38606800 if width == 1 else 0x78607800) | index << 16 | table << 5 | loaded,
             0x8b000800 | loaded << 16 | target << 5 | target]
    suffix_words = [0x2a1f03f2, 0x2a1f03e8] if kind == 'zero_pair' else [0x52800092 if kind == 'mov' else 0x8b120228]
    if suffix is not None: suffix_words[0] = suffix
    suffix_pc = START+len(words)*4
    words += suffix_words+[0xd61f0000 | target << 5]
    raw = bytearray(0x21000)
    raw[START:START+len(words)*4] = pack(*words)
    raw[DEFAULT:DEFAULT+4] = pack(0xd4200000)
    values = (0, 2, 7, 200)
    raw[TABLE:TABLE+width*len(values)] = struct.pack('<4' + ('B' if width == 1 else 'H'), *values)
    ranges = [(START, START+len(words)*4), (DEFAULT, DEFAULT+4)]
    for tag in values:
        pc = BASE+tag*4
        raw[pc:pc+4] = pack(0xd4200000)
        ranges.append((pc, pc+4))
    return bytes(raw), sorted(ranges), dict(kind=kind, width=width, values=values,
        compare=compare, load=compare+12, addition=compare+16, suffix=suffix_pc,
        suffix_words=suffix_words, branch=START+(len(words)-1)*4,
        roles=(target, loaded, table, index))

def classify(raw, ranges, facts, entries=(), readonly=None):
    ops = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc))
           for lo, hi in ranges for pc in range(lo, hi, 4)}
    return ar._guarded_native_readonly_table(ops[facts['branch']], ops, set(entries), raw,
        ((TABLE, TABLE+facts['width']*4),) if readonly is None else readonly)

def rewritten(kind='mov', suffix=None, prior_equal=False, **changes):
    raw, ranges, facts = fixture(kind, suffix, prior_equal)
    options = dict(entry_offset=START, text_size=0x4000, code_ranges=ranges,
        package_version=2, checked_stack=True, readonly_ranges=((TABLE, TABLE+facts['width']*4),),
        proven_guest_indirect_offsets=(facts['branch'],))
    return ar.rewrite(raw, **(options | changes)), facts

class UnsignedVirtualSuffixTests(unittest.TestCase):
    def execute(self, image, facts, index, *, entry=None, bad=None, virtual=0xaabbccdd12345678):
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        base, stack, state = 0x10000000, 0x20008000, 0x30000000
        helper = state+0x1000
        cpu.mem_map(base, 0x40000); cpu.mem_map(0x20000000, 0x10000); cpu.mem_map(state, 0x10000)
        cpu.mem_write(base, image.bytes)
        cpu.mem_write(state, struct.pack('<Q', virtual))
        cpu.mem_write(helper, pack(0x58000050, 0xd65f03c0)+struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(fixup.helper, ar.STATE_HELPER)
            cpu.mem_write(base+fixup.offset, struct.pack('<Q', helper))
        before = [0x1234567800000000+r*0x101 for r in range(31)]
        target, loaded, table, idx = facts['roles']
        before[table] = base+TABLE; before[target] = base+BASE; before[idx] = index
        before[30] = base+0x80
        if bad == 'table': before[table] = 0
        if bad == 'base': before[target] += 4
        for r, value in enumerate(before): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        vectors = [int.from_bytes(bytes((r+j)%256 for j in range(16)), 'little') for r in range(32)]
        for r, value in enumerate(vectors): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xb0000000)
        stack_args = bytes(range(16)); cpu.mem_write(stack, stack_args)
        observed = dict(trapped=False, reached=None, reads=0)
        cases = {base+BASE+tag*4 for tag in facts['values']}
        def code(machine, pc, size, _):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)))
            if pc in cases:
                observed['reached'] = pc; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base+TABLE <= address < base+TABLE+facts['width']*4: observed['reads'] += 1
        def trap(machine, number, _):
            observed['trapped'] = True; machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_MEM_READ, read); cpu.hook_add(UC_HOOK_INTR, trap)
        cpu.emu_start(base+(START if entry is None else entry), base+len(image.bytes), count=10000)
        expected = list(before); expected_virtual = virtual
        expected_flags = 0xb0000000
        if observed['reached'] is not None:
            value = facts['values'][index]
            expected[target] = base+BASE+value*4; expected[loaded] = value
            if facts['kind'] == 'mov': expected_virtual = facts['suffix_words'][0] >> 5 & 0xffff
            elif facts['kind'] == 'zero_pair': expected_virtual = 0; expected[8] = 0
            else:
                word = facts['suffix_words'][0]
                expected[word & 31] = (before[word >> 5 & 31]+virtual) & 0xffffffffffffffff
            if entry is None: expected_flags = 0x60000000 if index == 3 else 0x80000000
        self.assertEqual(expected, [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)])
        self.assertEqual(expected_virtual, struct.unpack('<Q', cpu.mem_read(state, 8))[0])
        self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP))
        self.assertEqual(stack_args, bytes(cpu.mem_read(stack, 16)))
        self.assertEqual(expected_flags, cpu.reg_read(uc.UC_ARM64_REG_NZCV))
        for r, value in enumerate(vectors): self.assertEqual(value, cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')))
        return observed

    def test_exact_single_virtual_effect_is_admitted_and_existing_lowering_preserves_cpu(self):
        for kind in ('mov', 'add'):
            raw, ranges, facts = fixture(kind)
            plan = classify(raw, ranges, facts)
            self.assertIsNotNone(plan)
            self.assertEqual(plan['permitted_source_rewrite_offsets'], [facts['suffix']])
            self.assertEqual(plan['preserved_source_offsets'], [facts['suffix']])
            image, facts = rewritten(kind)
            self.assertEqual(raw[facts['branch']:facts['branch']+4], image.bytes[facts['branch']:facts['branch']+4])
            self.assertNotEqual(raw[facts['suffix']:facts['suffix']+4], image.bytes[facts['suffix']:facts['suffix']+4])
            for index in range(4):
                with self.subTest(kind=kind, index=index):
                    self.assertEqual(dict(trapped=False, reached=0x10000000+BASE+facts['values'][index]*4, reads=1),
                        self.execute(image, facts, index))

    def test_bad_actual_table_base_and_full64_index_fail_before_any_read_or_suffix(self):
        for kind in ('mov', 'add'):
            image, facts = rewritten(kind)
            for index, bad in ((0, 'table'), (0, 'base'), (4, None), ((1<<32)|2, None), (0xffffffffffffffff, None)):
                with self.subTest(kind=kind, index=index, bad=bad):
                    self.assertEqual(dict(trapped=True, reached=None, reads=0),
                        self.execute(image, facts, index, entry=facts['load'], bad=bad))

    def test_every_postload_entry_refuses_and_preload_entry_still_checks(self):
        for kind in ('mov', 'add'):
            raw, ranges, facts = fixture(kind)
            for at in range(facts['load']+4, facts['branch']+4, 4):
                self.assertIsNone(classify(raw, ranges, facts, entries=(at,)))
                with self.assertRaises(ar.RewriteError): rewritten(kind, entry_offsets=(at,))
            image, facts = rewritten(kind, entry_offset=facts['load'], entry_offsets=(facts['load'],))
            self.assertEqual(1, self.execute(image, facts, 2, entry=facts['load'])['reads'])

    def test_unsupported_virtual_effects_and_dispatch_role_clobbers_refuse(self):
        invalid_mov = (0xd2800092, 0x72a00092, 0x52a00092, 0x2a0903f2, 0x91000652, 0xf9400252)
        invalid_add = (0xab120228, 0x8b110248, 0x8b120628, 0x8b12023d, 0x8b12023e, 0x8b12023f,
                       *(0x8b120220 | r for r in (9, 10, 11, 12, 18)))
        for kind, words in (('mov', invalid_mov), ('add', invalid_add)):
            for word in words:
                with self.subTest(kind=kind, word=hex(word)):
                    raw, ranges, facts = fixture(kind, word)
                    self.assertIsNone(classify(raw, ranges, facts))
                    with self.assertRaises(ar.RewriteError): rewritten(kind, word)
            raw, ranges, facts = fixture(kind)
            for readonly in ((), ((TABLE, TABLE+facts['width']*4-1),)):
                self.assertIsNone(classify(raw, ranges, facts, readonly=readonly))
                with self.assertRaises(ar.RewriteError): rewritten(kind, readonly_ranges=readonly)

    def test_generic_immediates_and_native_scratch_aliases_preserve_cpu(self):
        for immediate in (0, 1, 0xffff):
            image, facts = rewritten('mov', 0x52800012 | immediate << 5)
            self.execute(image, facts, 2)
        for destination, source in ((3, 17), (16, 17), (17, 16), (17, 17)):
            image, facts = rewritten('add', 0x8b120000 | source << 5 | destination)
            self.execute(image, facts, 2)

    def test_serial_sentinel_equality_and_upper_guard_need_exact_facts(self):
        raw, ranges, facts = fixture('add', prior_equal=True)
        self.assertIsNotNone(classify(raw, ranges, facts))
        image, facts = rewritten('add', prior_equal=True)
        self.execute(image, facts, 2)
        for pc, word in ((facts['compare'], 0xd503201f),
                         (facts['compare']+4, 0x54000000 | ((DEFAULT-facts['compare']-4)//4 << 5)),
                         (facts['compare']+4, 0x54000028),
                         (facts['compare']-4, 0x54000001 | ((DEFAULT-facts['compare']+4)//4 << 5)),
                         (facts['compare']-8, 0xf100153f)):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, pc, word)
            self.assertIsNone(classify(damaged, ranges, facts))

    def test_exact_two_wzero_suffix_effects_preserve_virtual_and_native_state(self):
        raw, ranges, facts = fixture('zero_pair')
        self.assertIsNotNone(classify(raw, ranges, facts))
        image, facts = rewritten('zero_pair')
        for index in range(4): self.execute(image, facts, index)
        for index, bad in ((0, 'table'), (0, 'base'), (4, None), ((1<<32)|2, None)):
            self.assertEqual(dict(trapped=True, reached=None, reads=0),
                self.execute(image, facts, index, entry=facts['load'], bad=bad))
        for entry in range(facts['load']+4, facts['branch']+4, 4):
            self.assertIsNone(classify(raw, ranges, facts, entries=(entry,)))
        for word in (0x52800012, 0xaa1f03f2, 0x2a1103f2, 0x2a1003f2):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, facts['suffix'], word)
            self.assertIsNone(classify(damaged, ranges, facts))
        for register in (9, 10, 11, 12, 18, 29, 30, 31):
            damaged = bytearray(raw); struct.pack_into('<I', damaged, facts['suffix']+4, 0x2a1f03e0 | register)
            self.assertIsNone(classify(damaged, ranges, facts))

    def test_two_ordinary_zero_moves_keep_their_preexisting_nonvirtual_classification(self):
        # This is an existing safe native suffix, not a missing virtual-state
        # proof: changing W18 to W8 removes the virtual effect altogether.
        raw, ranges, facts = fixture('zero_pair', 0x2a1f03e8)
        plan = classify(raw, ranges, facts)
        self.assertIsNotNone(plan)
        self.assertNotIn('virtual_suffix_kind', plan)

if __name__ == '__main__': unittest.main()
