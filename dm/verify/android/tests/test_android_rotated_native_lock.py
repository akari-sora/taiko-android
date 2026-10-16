"""Native spinlocks can place their shared store before the exclusive entry."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar


def words(acquire=True, base=19, status=9, data=22):
    return [0x88007C00 | status << 16 | base << 5 | data,
            0x340000C0 | status,
            (0x885FFC00 if acquire else 0x885F7C00) | base << 5 | status,
            0x34FFFFA0 | status, 0xD5033F5F,
            0xD65F03C0, 0xD503201F, 0xD65F03C0]


def raw(values):
    return struct.pack('<' + 'I' * len(values), *values)


def plan(values, roots=(8, 20, 28), overrides=None):
    instructions = [ar.decode(value, index * 4) for index, value in enumerate(values)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class RotatedLockMachine:
    """Raw-word execution with a reservation and injected spurious failures.

    A competing actor may acquire the lock after a failed store. That change
    is distinct from this operation's successful memory writes.
    """
    def __init__(self, source, initial, *, failures=0, competing_value=None):
        self.source = source
        self.x = [0xDEADBEEF00000100 + index for index in range(31)]
        self.x[19], self.x[22] = 0x400000, 0x1234567800000001
        self.sp, self.flags = 0x200000, 0xA0000000
        self.memory = {0x3FFFFC: 0x11223344, 0x400000: initial, 0x400004: 0x55667788}
        self.failures, self.competing_value = failures, competing_value
        self.loads = self.stores = self.writes = self.clears = 0

    @staticmethod
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    def run(self):
        pc, monitor = 8, None
        for _ in range(100):
            if pc in (20, 28):
                return 'busy' if pc == 20 else 'acquired'
            value = struct.unpack_from('<I', self.source, pc)[0]
            rt, rn = value & 31, value >> 5 & 31
            next_pc = pc + 4
            if value & 0xFFFFFC00 in (0x885F7C00, 0x885FFC00):
                self.loads += 1
                self.x[rt] = self.memory[self.x[rn]] & 0xFFFFFFFF
                monitor = self.x[rn]
            elif value & 0xFFE0FC00 == 0x88007C00:
                status = value >> 16 & 31
                self.stores += 1
                success = monitor == self.x[rn] and self.stores > self.failures
                if success:
                    self.memory[self.x[rn]] = self.x[rt] & 0xFFFFFFFF
                    self.writes += 1
                elif self.competing_value is not None:
                    self.memory[self.x[rn]] = self.competing_value
                self.x[status] = 0 if success else 1
                monitor = None
            elif value & 0xFF000000 == 0x34000000:
                if self.x[rt] & 0xFFFFFFFF == 0:
                    next_pc = pc + self.signed(value >> 5 & 0x7FFFF, 19) * 4
            elif value == 0xD5033F5F:
                monitor = None
                self.clears += 1
            else:
                raise AssertionError(f'unmodeled instruction {value:08x}')
            pc = next_pc
        raise AssertionError('rotated spinlock did not finish')


class RotatedNativeLockTests(unittest.TestCase):
    def test_both_observed_loads_keep_native_bytes_without_helpers(self):
        self.assertEqual(words()[:5], [0x88097E76, 0x340000C9, 0x885FFE69,
                                      0x34FFFFA9, 0xD5033F5F])
        for acquire in (False, True):
            for roles in ((19, 9, 22), (19, 8, 22), (0, 1, 2), (28, 16, 17)):
                with self.subTest(acquire=acquire, roles=roles):
                    source = raw(words(acquire, *roles))
                    image = ar.rewrite(source, entry_offset=8, entry_offsets=(8, 20, 28))
                    self.assertEqual(image.bytes, source)
                    self.assertFalse(image.sites)
                    self.assertFalse(image.fixups)
                    self.assertEqual(plan(words(acquire, *roles)), ())
            self.assertEqual(plan(words(acquire) + [ar.branch(32, 8)]), ())

    def test_zero_busy_and_failed_store_paths_preserve_full_machine_state(self):
        # initial, failures, competing owner; result, status, loads, stores,
        # successful own writes, CLREX count, final memory.
        cases = ((0, 0, None, 'acquired', 0, 1, 1, 1, 0, 1),
                 (5, 0, None, 'busy', 5, 1, 0, 0, 1, 5),
                 (0, 2, None, 'acquired', 0, 3, 3, 1, 0, 1),
                 (0, 1, 3, 'busy', 3, 2, 1, 0, 1, 3))
        for acquire in (False, True):
            source = ar.rewrite(raw(words(acquire)), entry_offset=8,
                                entry_offsets=(8, 20, 28)).bytes
            for case in cases:
                initial, failures, competitor, result, status, loads, stores, writes, clears, final = case
                with self.subTest(acquire=acquire, case=case):
                    machine = RotatedLockMachine(source, initial, failures=failures,
                                                 competing_value=competitor)
                    before = machine.x.copy()
                    self.assertEqual(machine.run(), result)
                    before[9] = status
                    self.assertEqual(machine.x, before)
                    self.assertEqual((machine.sp, machine.flags), (0x200000, 0xA0000000))
                    self.assertEqual((machine.loads, machine.stores, machine.writes, machine.clears),
                                     (loads, stores, writes, clears))
                    self.assertEqual(machine.memory, {0x3FFFFC: 0x11223344, 0x400000: final,
                                                      0x400004: 0x55667788})

    def test_only_exclusive_head_accepts_external_roots_and_edges(self):
        for acquire in (False, True):
            for at in (0, 4, 12, 16):
                with self.subTest(acquire=acquire, root=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                    plan(words(acquire), roots=(8, 20, 28, at))
                with self.subTest(acquire=acquire, edge=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                    plan(words(acquire) + [ar.branch(32, at)])

    def test_changed_status_base_width_branches_and_clrex_are_rejected(self):
        changes = ((0, 0x880A7E76), (0, 0x88097E96), (0, 0xC8097E76),
                   (0, 0x8809FE76), (1, 0x340000CA), (1, 0x350000C9),
                   (1, 0x34000029), (2, 0x885FFE89), (2, 0xC85FFE69),
                   (3, 0x34FFFFAA), (3, 0x35FFFFA9), (3, 0x34FFFFC9),
                   (3, 0xB4FFFFA9), (4, 0xD503201F), (4, 0xD5033B5F))
        for at, value in changes:
            source = words()
            source[at] = value
            with self.subTest(at=at, value=f'{value:08x}'), self.assertRaises(ar.RewriteError):
                plan(source)
        source = words()
        source[0] |= 0x40000000
        source[2] |= 0x40000000
        source[3] |= 0x80000000
        with self.subTest(all_64_bit=True), self.assertRaises(ar.RewriteError):
            plan(source)

    def test_distinct_ordinary_roles_and_no_source_rewrite_are_required(self):
        invalid = [(19, 19, 22), (19, 9, 9), (19, 9, 19)]
        for position in range(3):
            for register in (18, 29, 30, 31):
                roles = [19, 9, 22]
                roles[position] = register
                invalid.append(tuple(roles))
        for roles in invalid:
            with self.subTest(roles=roles), self.assertRaises(ar.RewriteError):
                plan(words(True, *roles))
        for at in range(0, 20, 4):
            for kind in ('x18', 'parameter', 'parameter_tail'):
                with self.subTest(at=at, kind=kind), self.assertRaises(ar.RewriteError):
                    plan(words(), overrides={at: kind})


if __name__ == '__main__':
    unittest.main()
