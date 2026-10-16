"""Only a fully closed native reservation can reach a shared slow-path call."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar


def words(prefix=None):
    prefix = [0xAA1303E0] if prefix is None else prefix  # mov x0,x19
    call = 28 + len(prefix) * 4
    success = call + 4
    # The public callee increments only the counter at [x0,#4], then returns.
    return ([0x885FFE68, 0x34000068, 0xD5033F5F, ar.branch(12, 28),
             0x52800028, 0x88097E68,
             0x34000009 | ((success - 24) // 4) << 5] + prefix +
            [0x94000004, 0xD65F03C0, 0xD503201F, 0xD503201F,
             0xB940040A, 0x1100054A, 0xB900040A, 0xD65F03C0])


def raw(values):
    return struct.pack('<' + 'I' * len(values), *values)


def plan(values, roots=(0, 36, 48), overrides=None):
    instructions = [ar.decode(value, index * 4) for index, value in enumerate(values)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class ClosedCallMachine:
    """Raw encoding model executing the actual BL and counter callee body.

    Execution stops at the caller's declared continuation, before its next
    instruction. A call therefore leaves the architectural LR at that address.
    """
    def __init__(self, source, initial, fail_store=False):
        self.source = source
        self.x = [0xDEADBEEF00000100 + index for index in range(31)]
        self.x[19] = 0x400000
        self.sp, self.flags = 0x200000, 0xA0000000
        self.memory = {0x3FFFFC: 0x11223344, 0x400000: initial,
                       0x400004: 41, 0x400008: 0x55667788}
        self.fail_store = fail_store
        self.loads = self.stores = self.lock_writes = self.counter_writes = self.clears = self.calls = 0

    @staticmethod
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    def run(self):
        pc, monitor = 0, None
        for _ in range(100):
            if pc == 36:
                assert monitor is None, 'continuation with a live reservation'
                return
            value = struct.unpack_from('<I', self.source, pc)[0]
            rt, rn = value & 31, value >> 5 & 31
            next_pc = pc + 4
            if value & 0xFFFFFC00 == 0x885FFC00:
                self.loads += 1
                self.x[rt] = self.memory[self.x[rn]] & 0xFFFFFFFF
                monitor = self.x[rn]
            elif value & 0xFFE0FC00 == 0x88007C00:
                status = value >> 16 & 31
                self.stores += 1
                success = monitor == self.x[rn] and not self.fail_store
                if success:
                    self.memory[self.x[rn]] = self.x[rt] & 0xFFFFFFFF
                    self.lock_writes += 1
                self.x[status] = 0 if success else 1
                monitor = None
            elif value == 0xD5033F5F:
                monitor = None
                self.clears += 1
            elif value & 0xFF000000 == 0x34000000:
                if self.x[rt] & 0xFFFFFFFF == 0:
                    next_pc = pc + self.signed(value >> 5 & 0x7FFFF, 19) * 4
            elif value & 0xFC000000 == 0x14000000:
                next_pc = pc + self.signed(value & 0x3FFFFFF, 26) * 4
            elif value & 0xFC000000 == 0x94000000:
                assert monitor is None, 'call with live reservation'
                self.calls += 1
                self.x[30] = next_pc
                next_pc = pc + self.signed(value & 0x3FFFFFF, 26) * 4
            elif value & 0xFFE0FFE0 == 0xAA0003E0:
                self.x[rt] = self.x[value >> 16 & 31]
            elif value & 0xFFE00000 == 0x52800000:
                self.x[rt] = value >> 5 & 0xFFFF
            elif value & 0xFFC00000 == 0xB9400000:
                self.x[rt] = self.memory[self.x[rn] + (value >> 10 & 0xFFF) * 4]
            elif value & 0xFFC00000 == 0x11000000:
                self.x[rt] = (self.x[rn] + (value >> 10 & 0xFFF)) & 0xFFFFFFFF
            elif value & 0xFFC00000 == 0xB9000000:
                address = self.x[rn] + (value >> 10 & 0xFFF) * 4
                assert address == 0x400004, 'callee wrote outside its declared counter'
                self.memory[address] = self.x[rt] & 0xFFFFFFFF
                self.counter_writes += 1
            elif value == 0xD65F03C0:
                next_pc = self.x[30]
            else:
                raise AssertionError(f'unmodeled instruction {value:08x}')
            pc = next_pc
        raise AssertionError('closed-call fixture did not finish')


class NativeClosedCallTests(unittest.TestCase):
    def test_native_closed_body_and_shared_argument_prefix_keep_original_bytes(self):
        source = raw(words())
        image = ar.rewrite(source, entry_offsets=(0, 36, 48))
        self.assertEqual(image.bytes, source)
        self.assertFalse(image.sites)
        self.assertFalse(image.fixups)
        self.assertEqual(plan(words()), ())
        # Exercise the accepted upper bound without relying on emitter padding
        # as evidence about the preserved source bytes.
        source = raw(words([0xAA1303E0] * 8))
        image = ar.rewrite(source, entry_offsets=(0, 64, 76))
        self.assertEqual(image.bytes[:len(source)], source)
        self.assertFalse(image.sites)
        self.assertFalse(image.fixups)

    def test_success_busy_and_failed_store_execute_declared_counter_callee(self):
        source = ar.rewrite(raw(words()), entry_offsets=(0, 36, 48)).bytes
        for initial, failed, called, status, loaded, stores, writes, clears in (
                (0, False, False, 0, 1, 1, 1, 0),
                (5, False, True, None, 5, 0, 0, 1),
                (0, True, True, 1, 1, 1, 0, 0)):
            with self.subTest(initial=initial, failed=failed):
                machine = ClosedCallMachine(source, initial, failed)
                before = machine.x.copy()
                machine.run()
                before[8] = loaded
                if status is not None:
                    before[9] = status
                if called:
                    before[0], before[10], before[30] = 0x400000, 42, 36
                self.assertEqual(machine.x, before)
                self.assertEqual((machine.sp, machine.flags), (0x200000, 0xA0000000))
                self.assertEqual((machine.loads, machine.stores, machine.lock_writes,
                                  machine.counter_writes, machine.clears, machine.calls),
                                 (1, stores, writes, int(called), clears, int(called)))
                self.assertEqual(machine.memory, {0x3FFFFC: 0x11223344,
                                                 0x400000: 1 if writes else initial,
                                                 0x400004: 42 if called else 41,
                                                 0x400008: 0x55667788})

    def test_every_admitted_tail_and_body_node_rejects_external_entry(self):
        for at in range(4, 32, 4):
            with self.subTest(root=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                plan(words(), roots=(0, 36, 48, at))
            with self.subTest(edge=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                plan(words() + [ar.branch(64, at)])

    def test_wrong_status_success_live_call_and_busy_terminal_are_rejected(self):
        changes = ((6, 0x34000068), (6, 0xB4000069), (6, 0x34000029),
                   (4, 0x94000008), (2, 0xD503201F),
                   (3, ar.branch(12, 32)), (8, 0xD63F0200),
                   (8, 0x97FFFFF8), (8, 0x94000400))
        for at, value in changes:
            source = words()
            source[at] = value
            with self.subTest(at=at, value=f'{value:08x}'), self.assertRaises(ar.RewriteError):
                plan(source)

    def test_recognized_union_stops_before_call_and_requires_a_finite_direct_call(self):
        def match(values):
            decoded = {index * 4: ar.decode(value, index * 4) for index, value in enumerate(values)}
            kinds = {pc: ar.site_kind(ins) for pc, ins in decoded.items()}
            return ar.android_exclusive.native_closed_call_tail(
                decoded[0], {0, 4, 8, 16, 20}, {8, 20}, decoded, kinds, ar)

        self.assertEqual(match(words()), set(range(0, 32, 4)))
        # These native programs can have other legitimate classifications;
        # neither is proof of this particular bounded direct-call shape.
        for replacement in (0xD65F03C0, ar.branch(32, 32)):
            source = words()
            source[8] = replacement
            with self.subTest(replacement=f'{replacement:08x}'):
                self.assertIsNone(match(source))

    def test_prefix_memory_stack_x18_gates_and_oversize_are_rejected(self):
        for prefix in ([0xF9400260], [0x910043FF], [0xAA1203E0], [0xD4000001],
                       [0xAA1303E0] * 9):
            source = words(prefix)
            call = 28 + len(prefix) * 4
            with self.subTest(prefix=prefix), self.assertRaises(ar.RewriteError):
                plan(source, roots=(0, call + 4, call + 16))
        for at in range(0, 32, 4):
            for kind in ('x18', 'parameter', 'parameter_tail'):
                with self.subTest(at=at, kind=kind), self.assertRaises(ar.RewriteError):
                    plan(words(), overrides={at: kind})


if __name__ == '__main__':
    unittest.main()
