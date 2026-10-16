"""The native two-load acquire lock is one indivisible, single-entry region."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar


def words(base=8, loaded=10, value=9):
    return [0x885FFC00 | base << 5 | loaded, 0x34000080 | loaded,
            0xD5033F5F, 0x885FFC00 | base << 5 | loaded,
            0x35FFFFC0 | loaded,
            0x8800FC00 | loaded << 16 | base << 5 | value,
            0x35FFFFA0 | loaded]


def raw(values):
    return struct.pack('<' + 'I' * len(values), *values)


def planned(values, roots=(0,), kind_override=None):
    instructions = [ar.decode(value, pc * 4) for pc, value in enumerate(values)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    kinds.update(kind_override or {})
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class NativeLockModel:
    """Raw-encoding model, with another actor releasing a busy lock.

    It executes the accepted bytes rather than depending on planner metadata.
    Spurious exclusive-store failure is injected before any memory write.
    """
    def __init__(self, source, *, busy_loads=0, failed_stores=0):
        self.source = source
        self.x = [0xABCDEF0000000100 + index for index in range(31)]
        self.x[8], self.x[9] = 0x400000, 0x1234567800000001
        self.sp, self.flags = 0x200000, 0xA0000000
        self.memory = {0x3FFFFC: 0x11223344, 0x400000: 7 if busy_loads else 0,
                       0x400004: 0x55667788}
        self.busy_loads, self.failed_stores = busy_loads, failed_stores
        self.loads = self.stores = self.writes = self.clears = 0

    def run(self):
        pc, monitor = 0, None
        for _ in range(100):
            if pc == 28:
                return
            word = struct.unpack_from('<I', self.source, pc)[0]
            rt, rn = word & 31, word >> 5 & 31
            if word & 0xFFFFFC00 == 0x885FFC00:
                self.loads += 1
                if self.busy_loads and self.loads > self.busy_loads:
                    self.memory[self.x[rn]] = 0  # External owner's release.
                self.x[rt] = self.memory[self.x[rn]]
                monitor = self.x[rn]
            elif word == 0xD5033F5F:
                monitor = None
                self.clears += 1
            elif word & 0xFFE0FC00 == 0x8800FC00:
                status = word >> 16 & 31
                self.stores += 1
                success = monitor == self.x[rn] and self.stores > self.failed_stores
                if success:
                    self.memory[self.x[rn]] = self.x[rt] & 0xFFFFFFFF
                    self.writes += 1
                self.x[status] = 0 if success else 1
                monitor = None
            elif word & 0x7E000000 == 0x34000000:
                offset = word >> 5 & 0x7FFFF
                if offset & 0x40000:
                    offset -= 0x80000
                nonzero = bool(word & 0x01000000)
                if (self.x[rt] & 0xFFFFFFFF != 0) == nonzero:
                    pc += offset * 4
                    continue
            else:
                raise AssertionError(f'unexpected instruction {word:08x}')
            pc += 4
        raise AssertionError('native lock did not finish')


class DualLoadLockTests(unittest.TestCase):
    def test_original_native_bytes_need_no_sites_helpers_or_relocation(self):
        self.assertEqual(words(), [0x885FFD0A, 0x3400008A, 0xD5033F5F,
                                   0x885FFD0A, 0x35FFFFCA, 0x880AFD09, 0x35FFFFAA])
        for registers in ((8, 10, 9), (0, 1, 2), (28, 16, 17)):
            with self.subTest(registers=registers):
                source = raw(words(*registers) + [0xD65F03C0])
                image = ar.rewrite(source, entry_offsets=(0, 28))
                self.assertEqual(image.bytes, source)
                self.assertFalse(image.sites)
                self.assertFalse(image.fixups)
                self.assertEqual(planned(words(*registers) + [0xD65F03C0]), ())

    def test_native_semantics_success_busy_release_and_failed_store(self):
        source = ar.rewrite(raw(words() + [0xD65F03C0])).bytes
        for busy, failures in ((0, 0), (3, 0), (0, 2), (3, 2)):
            with self.subTest(busy=busy, failures=failures):
                model = NativeLockModel(source, busy_loads=busy, failed_stores=failures)
                before_x, before_memory = model.x.copy(), model.memory.copy()
                model.run()
                expected = before_x.copy()
                expected[10] = 0  # Both LDAXR and STLXR write a zero-extended W10.
                self.assertEqual(model.x, expected)
                self.assertEqual((model.sp, model.flags), (0x200000, 0xA0000000))
                self.assertEqual((model.loads, model.stores, model.writes, model.clears),
                                 (1 + busy + failures, failures + 1, 1, busy))
                before_memory[0x400000] = 1
                self.assertEqual(model.memory, before_memory)

    def test_shifted_and_adjacent_locks_only_consume_the_second_head(self):
        values = [ar.branch(0, 4)] + words() + words(12, 14, 13) + [0xD65F03C0]
        source = raw(values)
        image = ar.rewrite(source, entry_offsets=(0, 4, 32, 60))
        self.assertEqual(image.bytes, source)
        self.assertFalse(image.sites)
        self.assertFalse(image.fixups)
        for root in (16, 44):
            with self.subTest(root=root), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                planned(values, roots=(0, 4, 32, root))

    def test_every_interior_root_and_outside_edge_is_rejected(self):
        for at in range(4, 28, 4):
            with self.subTest(root=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                planned(words() + [0xD65F03C0], roots=(0, at))
            values = words() + [ar.branch(28, at)]
            with self.subTest(edge=at), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                planned(values)

    def test_malformed_topology_does_not_gain_nested_cycle_support(self):
        mutations = ((1, 0x3500008A), (1, 0x34000089), (1, 0x3400006A),
                     (2, 0xD503201F), (2, 0xD5033F1F),
                     (3, 0x885FFD2A), (3, 0xC85FFD0A),
                     (4, 0x34FFFFCA), (4, 0x35FFFFC9), (4, 0x35FFFFAA),
                     (5, 0x880AFD29), (5, 0xC80AFD09),
                     (6, 0x34FFFFAA), (6, 0x35FFFFA9), (6, 0x35FFFF8A))
        for at, value in mutations:
            values = words()
            values[at] = value
            with self.subTest(at=at, value=f'{value:08x}'), self.assertRaises(ar.RewriteError):
                planned(values + [0xD65F03C0])

    def test_only_distinct_ordinary_registers_and_no_source_rewrites(self):
        forbidden = [(8, 8, 9), (8, 10, 10), (8, 10, 8)]
        for position in range(3):
            for register in (18, 29, 30, 31):
                registers = [8, 10, 9]
                registers[position] = register
                forbidden.append(tuple(registers))
        for registers in forbidden:
            with self.subTest(registers=registers), self.assertRaises(ar.RewriteError):
                planned(words(*registers) + [0xD65F03C0])
        for at in range(0, 28, 4):
            for kind in ('x18', 'parameter', 'parameter_tail'):
                with self.subTest(at=at, kind=kind), self.assertRaises(ar.RewriteError):
                    planned(words() + [0xD65F03C0], kind_override={at: kind})


if __name__ == '__main__':
    unittest.main()
