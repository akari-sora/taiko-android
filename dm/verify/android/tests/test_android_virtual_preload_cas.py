"""A virtual-x18 CAS retry keeps its native pointer preload in one frame."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
from capstone.arm64_const import ARM64_OP_MEM
from test_android_rewrite import Machine

ENTRY, PRELOAD, HEAD, SUCCESS, INVALID = 44, 52, 56, 92, 160


def words():
    source = [0xD503201F] * 42
    source[0], source[7] = ar.branch(0, ENTRY), ar.branch(28, ENTRY)
    source[8:23] = [0xD5033F5F, 0xAA1103F0, 0x370003D1,
                   0x8A0B020A, 0xAA0E014A, 0xF9400552,
                   0xC85F7D91, 0xEB10023F, 0x54FFFF01,
                   0x8A0B0252, 0xAA0F0252, 0x8A0D0210,
                   0x8B100250, 0xC8127D90, 0x35FFFE72]
    source[SUCCESS // 4] = source[INVALID // 4] = 0xD65F03C0
    return source


def raw(values):
    return struct.pack('<' + 'I' * len(values), *values)


def plan(values, roots=(0, ENTRY, SUCCESS, INVALID), overrides=None):
    instructions = [ar.decode(value, index * 4) for index, value in enumerate(values)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class PreloadCasMachine(Machine):
    """Execute emitted ARM64 with a monitor and a single declared preload.

    Every ordinary memory operation is forbidden while the monitor is live.
    Between failed STORE and the next LDXR, only the original mapped preload
    may read memory. Invalid-tag exit explicitly ends that retry interval.
    """
    def __init__(self, image, *, initial=0x1020, observed=None, failures=0):
        super().__init__(image)
        self.x[11:18] = [0xFF, 0x400000, 0xFFFFFFFFFFFFFF00, 0x500000, 0x100,
                         initial, 0x1122334455667788]
        self.q = tuple(bytes((index + lane) & 255 for lane in range(16)) for index in range(32))
        self.initial, self.observed, self.failures = initial, observed, failures
        self.monitor, self.failed_retry = None, False
        self.helper_calls = self.loads = self.stores = self.writes = self.clears = 0
        self.preloads = []
        sites = [site.trampoline for site in image.sites if site.offset == PRELOAD]
        assert len(sites) == 1
        self.preload_pc = sites[0]
        self.store(0x3FFFF8, 0x1122334455667788, 8)
        self.store(0x400000, initial, 8)
        self.store(0x400008, 0x8877665544332211, 8)
        self.store(0x500028, 0xABCDEF1200000040, 8)
        self.store(0x500048, 0xFEDCBA9800000060, 8)
        if initial == 0x1041:
            self.store(0x500049, 0x8899AABB00000060, 8)
        self.store(self.state, 0x0123456789ABCDEF, 8)
        self.store(self.state - 8, 0x1122334455667788, 8)
        self.store(self.state + 8, 0x8877665544332211, 8)
        self.store(self.start_sp - 40, 0x1928374655AABBCC, 8)
        self.store(self.start_sp, 0xAABBCCDDEEFF0011, 8)

    def compare(self, left, right, bits):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        left, right = left & mask, right & mask
        result = (left - right) & mask
        overflow = bool((left ^ right) & (left ^ result) & sign)
        self.flags = ((bool(result & sign) << 3) | ((result == 0) << 2) |
                      ((left >= right) << 1) | overflow) << 28

    def run(self):
        pc = self.image.entry_offset
        hardware18 = self.x[18]
        for _ in range(2000):
            if pc in (SUCCESS, INVALID):
                assert self.monitor is None and self.sp == self.start_sp
                return pc
            ins = ar.decode(self.load(pc, 4), pc)
            ops, name, next_pc = ins.operands, ins.mnemonic, pc + 4
            reg = lambda operand: self.name(ins, operand)
            value = lambda operand: self.value(ins, operand)
            if name == 'b':
                next_pc = ops[0].imm
            elif name == 'b.ne':
                if not self.flags & 0x40000000:
                    next_pc = ops[0].imm
            elif name in ('cbz', 'cbnz'):
                if (value(ops[0]) == 0) == (name == 'cbz'):
                    next_pc = ops[1].imm
            elif name == 'tbnz':
                assert reg(ops[0]) == 'w17' and ops[1].imm == 0
                if value(ops[0]) & 1:
                    self.failed_retry = False  # Real invalid-tag exit, not another attempt.
                    next_pc = ops[2].imm
            elif name == 'blr':
                assert self.monitor is None and not self.failed_retry
                assert value(ops[0]) == 0x100000 + ar.STATE_HELPER
                self.helper_calls += 1
                self.x[30], self.x[16] = next_pc, self.state
            elif name == 'mov':
                self.set_reg(reg(ops[0]), value(ops[1]))
            elif name in ('and', 'orr', 'add', 'sub'):
                left, right = value(ops[1]), value(ops[2])
                result = {'and': lambda: left & right, 'orr': lambda: left | right,
                          'add': lambda: left + right, 'sub': lambda: left - right}[name]()
                self.set_reg(reg(ops[0]), result)
            elif name == 'cmp':
                self.compare(value(ops[0]), value(ops[1]), 32 if reg(ops[0]).startswith('w') else 64)
            elif name == 'clrex':
                self.monitor = None
                self.clears += 1
            elif name in ('ldr', 'str', 'ldp', 'stp', 'ldxr', 'stxr'):
                mem = next((op for op in ops if op.type == ARM64_OP_MEM), None)
                address = (self.get_reg(ins.reg_name(mem.mem.base)) + mem.mem.disp
                           if mem is not None else ops[-1].imm)
                exclusive_load, exclusive_store = name == 'ldxr', name == 'stxr'
                data = ops[1:-1] if exclusive_store else ops[:-1]
                size = 4 if reg(data[0]).startswith('w') else 8
                if mem is not None and ins.reg_name(mem.mem.base) == 'sp':
                    assert self.sp <= address and address + size * len(data) <= self.start_sp
                if exclusive_load:
                    assert address == 0x400000 and size == 8
                    self.loads += 1
                    if self.loads == 1 and self.observed is not None:
                        self.store(address, self.observed, 8)
                    self.monitor, self.failed_retry = (address, size), False
                elif not exclusive_store:
                    assert self.monitor is None, 'ordinary memory access while reservation live'
                    if self.failed_retry:
                        assert pc == self.preload_pc, 'scratch memory before retry LDXR'
                    if pc == self.preload_pc:
                        assert name == 'ldr' and size == 8 and len(data) == 1
                        assert mem is not None and ins.reg_name(mem.mem.base) == 'x10' and mem.mem.disp == 8
                        self.preloads.append(address)
                success = True
                if exclusive_store:
                    assert self.monitor == (address, size)
                    self.stores += 1
                    success = self.stores > self.failures
                    self.set_reg(reg(ops[0]), 0 if success else 1)
                    self.monitor, self.failed_retry = None, not success
                    self.writes += int(success)
                if success:
                    for index, op in enumerate(data):
                        at = address + index * size
                        if name.startswith('ld'):
                            self.set_reg(reg(op), self.load(at, size))
                        else:
                            self.store(at, value(op), size)
            elif name != 'nop':
                raise AssertionError(f'unmodeled emitted instruction {name} {ins.op_str}')
            assert self.x[18] == hardware18, 'Android hardware x18 changed'
            pc = next_pc
        raise AssertionError('emitted virtual preload CAS did not finish')


class VirtualPreloadCasTests(unittest.TestCase):
    def test_complete_region_has_real_entry_and_only_real_exits(self):
        regions = plan(words())
        self.assertEqual(len(regions), 1)
        region = regions[0]
        self.assertEqual(region.entry, ENTRY)
        self.assertEqual({ins.address for ins in region.instructions}, set(range(32, 92, 4)))
        self.assertEqual(region.reservation_terminals, {32, 84})
        self.assertEqual(region.retry_edges, {(64, 32), (88, 36)})
        self.assertEqual(region.exit_edges, {(40, INVALID), (88, SUCCESS)})
        image = ar.rewrite(raw(words()), entry_offsets=(0, ENTRY, SUCCESS, INVALID))
        self.assertTrue(image.sites)

    def test_emitted_success_retry_mismatch_and_invalid_exits_preserve_machine_state(self):
        image = ar.rewrite(raw(words()), entry_offsets=(0, ENTRY, SUCCESS, INVALID))
        cases = ((0x1020, None, 0, SUCCESS, 0x1140, 0x1020, 0x500020, 0,
                  1, 1, 0, [0x500028], 0x1140, 0x60000000),
                 (0x1020, None, 3, SUCCESS, 0x1140, 0x1020, 0x500020, 0,
                  4, 4, 0, [0x500028] * 4, 0x1140, 0x60000000),
                 (0x1020, 0x1040, 0, SUCCESS, 0x1160, 0x1040, 0x500040, 0,
                  2, 1, 1, [0x500028, 0x500048], 0x1160, 0x60000000),
                 (0x1020, 0x1041, 0, INVALID, 0x1041, 0x1041, 0x500020, 0xABCDEF1200000040,
                  1, 0, 1, [0x500028], 0x1041, 0x20000000),
                 (0x1041, None, 1, INVALID, 0x1041, 0x1041, 0x500041, 1,
                  1, 1, 0, [0x500049], 0x1041, 0x60000000))
        for case in cases:
            initial, observed, failures, exit_pc, target, loaded, pointer, virtual, loads, stores, clears, preloads, final, flags = case
            with self.subTest(initial=initial, observed=observed, failures=failures):
                machine = PreloadCasMachine(image, initial=initial, observed=observed, failures=failures)
                before, before_q = machine.x.copy(), machine.q
                before_code = bytes(machine.load(pc, 1) for pc in range(len(image.bytes)))
                before_nodes = {address: machine.load(address, 8) for address in set(preloads)}
                self.assertEqual(machine.run(), exit_pc)
                before[10], before[16], before[17] = pointer, target, loaded
                self.assertEqual(machine.x, before)
                self.assertEqual(machine.q, before_q)
                self.assertEqual((machine.sp, machine.flags), (machine.start_sp, flags))
                self.assertEqual(machine.load(machine.state, 8), virtual)
                self.assertEqual((machine.helper_calls, machine.loads, machine.stores, machine.clears, machine.writes),
                                 (1, loads, stores, clears, int(exit_pc == SUCCESS)))
                self.assertEqual(machine.preloads, preloads)
                self.assertEqual(machine.load(0x400000, 8), final)
                self.assertEqual(bytes(machine.load(pc, 1) for pc in range(len(image.bytes))), before_code)
                for address, expected in before_nodes.items():
                    self.assertEqual(machine.load(address, 8), expected)
                for address, expected in ((0x3FFFF8, 0x1122334455667788), (0x400008, 0x8877665544332211),
                                          (machine.state - 8, 0x1122334455667788),
                                          (machine.state + 8, 0x8877665544332211),
                                          (machine.start_sp - 40, 0x1928374655AABBCC),
                                          (machine.start_sp, 0xAABBCCDDEEFF0011)):
                    self.assertEqual(machine.load(address, 8), expected)

    def test_only_declared_entry_accepts_metadata_roots_and_outside_edges(self):
        for at in sorted(set(range(32, 92, 4)) - {ENTRY}):
            with self.subTest(root=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                plan(words(), roots=(0, ENTRY, SUCCESS, INVALID, at))
            with self.subTest(edge=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                plan(words() + [ar.branch(168, at)])

    def test_partial_selection_and_source_rewrites_do_not_borrow_the_proof(self):
        for missing in (32, 36, 40, PRELOAD, HEAD, 84, 88):
            ranges = ((0, missing), (missing + 4, len(raw(words()))))
            with self.subTest(missing=missing), self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(words()), code_ranges=ranges, entry_offsets=(0, ENTRY, SUCCESS, INVALID))
        for at in range(32, 92, 4):
            for kind in ('parameter', 'parameter_tail', 'svc'):
                with self.subTest(at=at, kind=kind), self.assertRaises(ar.RewriteError):
                    plan(words(), overrides={at: kind})

    def test_changed_memory_stack_gate_branch_or_overlapping_reservation_is_rejected(self):
        changes = ((32, 0xD503201F), (40, 0x370803D1), (40, 0x37000051),
                   (44, 0x910043FF), (52, 0xF9400952), (56, 0xC85FFD91),
                   (64, 0x54FFFF00), (68, 0xD4000001), (84, 0xC8137D90),
                   (88, 0xB5FFFE72), (88, 0x35FFFEF2))
        for at, value in changes:
            source = words()
            source[at // 4] = value
            with self.subTest(at=at, value=f'{value:08x}'), self.assertRaises(ar.RewriteError):
                plan(source)
        source = words()
        source[4] = 0xC85F7C62  # Outer ldxr x2,[x3] reaches the inner live load.
        with self.assertRaisesRegex(ar.RewriteError, 'nested|overlap'):
            plan(source, roots=(0, 16, ENTRY, SUCCESS, INVALID))


if __name__ == '__main__':
    unittest.main()
