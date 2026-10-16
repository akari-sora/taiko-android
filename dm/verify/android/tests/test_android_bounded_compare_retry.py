"""Native bounded CAS retries preserve the reload, limit and reservation flow."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar


def words(base=25, expected=8, status=9):
    """Public fourteen-word shape, with distinct success (56) and reject (64)."""
    return [0x88DFFC00 | base << 5 | expected,
            0x7100041F | expected << 5, 0x540000C9, ar.branch(12, 64),
            0xD5033F5F, 0x88DFFC00 | base << 5 | expected,
            0x7100041F | expected << 5, 0x54000128,
            0x885FFC00 | base << 5 | status,
            0x6B00001F | expected << 16 | status << 5, 0x54FFFF41,
            0x91000400 | expected << 5 | expected,
            0x8800FC00 | status << 16 | base << 5 | expected,
            0x35FFFF00 | status]


def raw(values):
    return struct.pack('<' + 'I' * len(values), *values)


def fixture(base=25, expected=8, status=9):
    # Keep the complete source aligned so emitter padding is not confused with
    # a change to the native lock instructions.
    return words(base, expected, status) + [0xD65F03C0, 0xD503201F, 0xD65F03C0, 0xD503201F]


def plan(values, roots=(0, 56, 64), overrides=None):
    instructions = [ar.decode(value, pc * 4) for pc, value in enumerate(values)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class BoundedCompareMachine:
    """Independent raw-instruction model; no planner edges or decoded operands.

    External writes can race the initial load or a failed exclusive store.
    Only successful STLXR counts as this operation's write.
    """
    def __init__(self, source, initial, *, mismatch=None, failures=0, failed_value=None):
        self.source = source
        self.x = [0xFEDCBA9800000100 + index for index in range(31)]
        self.x[25] = 0x400000
        self.sp, self.flags = 0x200000, 0x90000000
        self.memory = {0x3FFFFC: 0x11223344, 0x400000: initial, 0x400004: 0x55667788}
        self.mismatch, self.failures, self.failed_value = mismatch, failures, failed_value
        self.reads = self.exclusive_reads = self.stores = self.writes = self.clears = 0

    @staticmethod
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    def cmp(self, left, right):
        left, right = left & 0xFFFFFFFF, right & 0xFFFFFFFF
        result = (left - right) & 0xFFFFFFFF
        overflow = bool((left ^ right) & (left ^ result) & 0x80000000)
        self.flags = ((bool(result & 0x80000000) << 3) | ((result == 0) << 2) |
                      ((left >= right) << 1) | overflow) << 28

    def run(self):
        pc, monitor = 0, None
        for _ in range(200):
            if pc in (56, 64):
                return 'success' if pc == 56 else 'reject'
            value = struct.unpack_from('<I', self.source, pc)[0]
            rt, rn = value & 31, value >> 5 & 31
            next_pc = pc + 4
            if value & 0xFFFFFC00 == 0x88DFFC00:
                self.reads += 1
                self.x[rt] = self.memory[self.x[rn]]
            elif value & 0xFFFFFC00 == 0x885FFC00:
                self.exclusive_reads += 1
                if self.exclusive_reads == 1 and self.mismatch is not None:
                    self.memory[self.x[rn]] = self.mismatch
                self.x[rt] = self.memory[self.x[rn]]
                monitor = self.x[rn]
            elif value == 0xD5033F5F:
                monitor = None
                self.clears += 1
            elif value & 0xFFE0FC00 == 0x8800FC00:
                status = value >> 16 & 31
                self.stores += 1
                success = monitor == self.x[rn] and self.stores > self.failures
                if success:
                    self.memory[self.x[rn]] = self.x[rt] & 0xFFFFFFFF
                    self.writes += 1
                elif self.failed_value is not None:
                    self.memory[self.x[rn]] = self.failed_value
                self.x[status] = 0 if success else 1
                monitor = None
            elif value & 0xFFC0001F == 0x7100001F:
                self.cmp(self.x[rn], value >> 10 & 0xFFF)
            elif value & 0xFFE0FC1F == 0x6B00001F:
                self.cmp(self.x[rn], self.x[value >> 16 & 31])
            elif value & 0xFFC00000 == 0x91000000:
                self.x[rt] = (self.x[rn] + (value >> 10 & 0xFFF)) & 0xFFFFFFFFFFFFFFFF
            elif value & 0xFC000000 == 0x14000000:
                next_pc = pc + self.signed(value & 0x3FFFFFF, 26) * 4
            elif value & 0xFF000010 == 0x54000000:
                condition = value & 15
                carry, zero = bool(self.flags & 0x20000000), bool(self.flags & 0x40000000)
                taken = {1: not zero, 8: carry and not zero, 9: not carry or zero}[condition]
                if taken:
                    next_pc = pc + self.signed(value >> 5 & 0x7FFFF, 19) * 4
            elif value & 0xFF000000 == 0x35000000:
                if self.x[rt] & 0xFFFFFFFF:
                    next_pc = pc + self.signed(value >> 5 & 0x7FFFF, 19) * 4
            else:
                raise AssertionError(f'unmodeled instruction {value:08x}')
            pc = next_pc
        raise AssertionError('bounded compare fixture did not terminate')


class BoundedCompareRetryTests(unittest.TestCase):
    def test_exact_native_words_keep_original_bytes_and_need_no_helpers(self):
        self.assertEqual(words()[:3], [0x88DFFF28, 0x7100051F, 0x540000C9])
        self.assertEqual(words()[8:], [0x885FFF29, 0x6B08013F, 0x54FFFF41,
                                      0x91000508, 0x8809FF28, 0x35FFFF09])
        for roles in ((25, 8, 9), (0, 1, 2), (28, 16, 17)):
            with self.subTest(roles=roles):
                source = raw(fixture(*roles))
                image = ar.rewrite(source, entry_offsets=(0, 56, 64))
                self.assertEqual(image.bytes, source)
                self.assertFalse(image.sites)
                self.assertFalse(image.fixups)
                self.assertEqual(plan(fixture(*roles)), ())
        shifted = raw([ar.branch(0, 4)] + fixture() + [0xD503201F])
        image = ar.rewrite(shifted, entry_offsets=(0, 4, 60, 68))
        self.assertEqual(image.bytes, shifted)
        self.assertFalse(image.sites)
        self.assertFalse(image.fixups)

    def test_limit_compare_mismatch_and_store_failure_preserve_actual_state(self):
        source = ar.rewrite(raw(fixture()), entry_offsets=(0, 56, 64)).bytes
        # initial, mismatch, failures, competing value; exit, expected, status,
        # ordinary reads, exclusive reads, store attempts, clears, final memory.
        cases = ((0, None, 0, None, 'success', 1, 0, 1, 1, 1, 0, 1),
                 (1, None, 0, None, 'success', 2, 0, 1, 1, 1, 0, 2),
                 (2, None, 0, None, 'reject', 2, None, 1, 0, 0, 0, 2),
                 (0, 1, 0, None, 'success', 2, 0, 2, 2, 1, 1, 2),
                 (0, 2, 0, None, 'reject', 2, 2, 2, 1, 0, 1, 2),
                 (0, None, 2, None, 'success', 1, 0, 3, 3, 3, 0, 1),
                 (0, None, 1, 1, 'success', 2, 0, 2, 2, 2, 0, 2),
                 (0, None, 1, 2, 'reject', 2, 1, 2, 1, 1, 0, 2))
        for case in cases:
            initial, mismatch, failures, failed_value, result, expected, status, reads, loads, stores, clears, final = case
            with self.subTest(case=case):
                machine = BoundedCompareMachine(source, initial, mismatch=mismatch,
                                                failures=failures, failed_value=failed_value)
                before = machine.x.copy()
                self.assertEqual(machine.run(), result)
                before[8] = expected
                if status is not None:
                    before[9] = status
                self.assertEqual(machine.x, before)
                self.assertEqual(machine.sp, 0x200000)
                self.assertEqual(machine.flags, 0x60000000 if result == 'success' else 0x20000000)
                self.assertEqual((machine.reads, machine.exclusive_reads, machine.stores, machine.clears),
                                 (reads, loads, stores, clears))
                self.assertEqual(machine.writes, int(result == 'success'))
                self.assertEqual(machine.memory, {0x3FFFFC: 0x11223344, 0x400000: final,
                                                 0x400004: 0x55667788})

    def test_every_interior_root_and_outside_edge_is_rejected(self):
        for at in range(4, 56, 4):
            with self.subTest(root=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                plan(fixture(), roots=(0, 56, 64, at))
            with self.subTest(edge=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                plan(fixture() + [ar.branch(72, at)])

    def test_native_class_rejects_unobserved_widths_and_changed_control_flow(self):
        changes = ((0, 0xC8DFFF28), (0, 0x88DFFF48), (1, 0x7100091F),
                   (2, 0x540000A9), (3, ar.branch(12, 60)), (4, 0xD503201F),
                   (4, 0xD5033B5F), (5, 0x88DFFF48), (6, 0x7100091F),
                   (7, 0x54000108), (8, 0xC85FFF29), (8, 0x885FFF49),
                   (9, 0x6B0A013F), (10, 0x54FFFF61), (10, 0x54FFFF40),
                   (11, 0x11000508), (11, 0x91000908), (12, 0xC809FF28),
                   (12, 0x880AFF28), (12, 0x8809FF48),
                   (13, 0x35FFFF29), (13, 0x35FFFF08), (13, 0xB5FFFF09))
        for at, value in changes:
            source = fixture()
            source[at] = value
            with self.subTest(at=at, value=f'{value:08x}'), self.assertRaises(ar.RewriteError):
                plan(source)
        for count in (9, 12, 13):
            with self.subTest(truncated=count), self.assertRaises(ar.RewriteError):
                plan(words()[:count], roots=(0,))
        source = fixture()
        for at in (0, 5, 8, 12):
            source[at] |= 0x40000000
        with self.subTest(all_loads_and_store_64_bit=True), self.assertRaises(ar.RewriteError):
            plan(source)

    def test_distinct_ordinary_roles_and_no_source_rewrite_are_required(self):
        invalid = [(8, 8, 9), (25, 8, 8), (25, 8, 25)]
        for position in range(3):
            for register in (18, 29, 30, 31):
                roles = [25, 8, 9]
                roles[position] = register
                invalid.append(tuple(roles))
        for roles in invalid:
            with self.subTest(roles=roles), self.assertRaises(ar.RewriteError):
                plan(fixture(*roles))
        for at in range(0, 56, 4):
            for kind in ('x18', 'parameter', 'parameter_tail'):
                with self.subTest(at=at, kind=kind), self.assertRaises(ar.RewriteError):
                    plan(fixture(), overrides={at: kind})


if __name__ == '__main__':
    unittest.main()
