"""Native pointer refresh preserves payload memory ordering and CAS retries."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar


# Authored schedule: only the two outside edges are relocated to a local RET.
WORDS = (
    0xD5033F5F, 0x2A1F03EF, 0xAA0E03ED, 0x3500026F,
    0x8A0801AE, 0xAA0B01CE, 0xF900052E, 0xF940200E,
    0x8A0C01CC, 0x910005CF, 0x8A2E01AE, 0xAA0F018C,
    0x8B0E018C, 0xC85F7D4E, 0xEB0D01DF, 0x54FFFE21,
    0xC80DFD4C, 0x35FFFE0D, 0x5280002F, 0xAA0E03ED,
    0x34FFFE0F, 0x14000001,
)
FIELDS = (
    (), (0,), (0, 5, 16), (0,), (0, 5, 16), (0, 5, 16),
    (0, 5), (0, 5), (0, 5, 16), (0, 5), (0, 5, 16),
    (0, 5, 16), (0, 5, 16), (0, 5), (0, 5, 16), (),
    (0, 5, 16), (0,), (0,), (0, 5, 16), (0,), (),
)
ENTRY, HEAD, EXIT = 16, 52, 88


def words(mapping=None):
    mapping = mapping or {}
    result = []
    for original, fields in zip(WORDS, FIELDS):
        value = original
        for shift in fields:
            role = original >> shift & 31
            value = value & ~(31 << shift) | mapping.get(role, role) << shift
        result.append(value)
    return result + [0xD65F03C0, 0xD503201F]


def raw(values):
    return struct.pack('<' + 'I' * len(values), *values)


def decode(values):
    instructions = [ar.decode(value, index * 4) for index, value in enumerate(values)]
    return instructions, {ins.address: ins for ins in instructions}, {
        ins.address: ar.site_kind(ins) for ins in instructions}


def recognize(by_pc, kinds):
    recognizer = getattr(ar.android_exclusive, 'native_pointer_refresh', None)
    return None if recognizer is None else recognizer(by_pc[HEAD], by_pc, kinds, ar)


class PointerRefreshMachine:
    """Independent raw-instruction model; actors can invalidate or replace CAS."""
    def __init__(self, source, *, initial=0x1000, failures=0, competitor=None):
        self.source = source
        self.x = [0xAABB000000000000 + index * 256 for index in range(31)]
        self.x[0], self.x[8], self.x[9], self.x[10] = 0x3000, ~0xFF & ((1 << 64) - 1), 0x5000, 0x4000
        self.x[11], self.x[12], self.x[13] = 3, 0xFF, 0x1000
        self.q = tuple(bytes([index]) * 16 for index in range(32))
        self.sp, self.flags, self.monitor = 0x800000, 0x90000000, None
        self.memory = {0x3038: 0xAA11, 0x3040: 4, 0x3048: 0xBB22,
                       0x3FF8: 0xCC33, 0x4000: initial, 0x4008: 0xDD44,
                       0x5000: 0xEE55, 0x5008: 0, 0x5010: 0xFF66}
        self.failures, self.competitor = failures, competitor
        self.loads = self.stores = self.clears = self.writes = 0
        self.events = []

    @staticmethod
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    def run(self):
        pc = ENTRY
        for _ in range(400):
            if pc == EXIT:
                assert self.monitor is None
                return
            value = struct.unpack_from('<I', self.source, pc)[0]
            rt, rn, rm = value & 31, value >> 5 & 31, value >> 16 & 31
            next_pc = pc + 4
            if value & 0xFFFFFC00 == 0xC85F7C00:
                assert self.monitor is None
                self.x[rt], self.monitor = self.memory[self.x[rn]], self.x[rn]
                self.loads += 1
                self.events.append('load-exclusive')
            elif value & 0xFFE0FC00 == 0xC800FC00:
                assert self.monitor == self.x[rn]
                self.stores += 1
                success = self.stores > self.failures
                if success:
                    self.memory[self.x[rn]] = self.x[rt]
                    self.writes += 1
                elif self.competitor is not None:
                    self.memory[self.x[rn]] = self.competitor
                self.x[rm], self.monitor = int(not success), None
                self.events.append('store-release')
            elif value == 0xD5033F5F:
                self.monitor = None
                self.clears += 1
                self.events.append('clear')
            elif value & 0xFFC00000 in (0xF9000000, 0xF9400000):
                assert self.monitor is None, 'ordinary memory access while reservation live'
                address = self.x[rn] + (value >> 10 & 0xFFF) * 8
                if value & 0x00400000:
                    self.x[rt] = self.memory[address]
                    self.events.append('payload-load')
                else:
                    self.memory[address] = self.x[rt]
                    self.events.append('payload-store')
            elif value & 0xFFE0FC00 in (0x8A000000, 0xAA000000, 0x8A200000, 0x8B000000):
                left, right = (0 if reg == 31 else self.x[reg] for reg in (rn, rm))
                opcode = value & 0xFFE0FC00
                self.x[rt] = {0x8A000000: left & right, 0xAA000000: left | right,
                              0x8A200000: left & ~right, 0x8B000000: left + right}[opcode] & ((1 << 64) - 1)
            elif value & 0xFFE0FFE0 == 0x2A0003E0:
                self.x[rt] = 0 if rm == 31 else self.x[rm] & 0xFFFFFFFF
            elif value & 0xFFC00000 == 0x91000000:
                self.x[rt] = (self.x[rn] + (value >> 10 & 0xFFF)) & ((1 << 64) - 1)
            elif value & 0xFFFFFC00 == 0x52800000:
                self.x[rt] = value >> 5 & 0xFFFF
            elif value & 0xFFE0FC1F == 0xEB00001F:
                left, right = self.x[rn], self.x[rm]
                result = (left - right) & ((1 << 64) - 1)
                overflow = bool((left ^ right) & (left ^ result) & (1 << 63))
                self.flags = ((bool(result & (1 << 63)) << 3) | ((result == 0) << 2) |
                              ((left >= right) << 1) | overflow) << 28
            elif value & 0xFF00001F == 0x54000001:
                if not self.flags & 0x40000000:
                    next_pc = pc + self.signed(value >> 5 & 0x7FFFF, 19) * 4
            elif value & 0x7E000000 == 0x34000000:
                operand = self.x[rt] & 0xFFFFFFFF
                if bool(operand) == bool(value & 0x01000000):
                    next_pc = pc + self.signed(value >> 5 & 0x7FFFF, 19) * 4
            elif value & 0xFC000000 == 0x14000000:
                next_pc = pc + self.signed(value & 0x3FFFFFF, 26) * 4
            else:
                raise AssertionError(f'unmodeled pointer-refresh instruction {value:08x}')
            pc = next_pc
        raise AssertionError('pointer refresh did not finish')


class NativePointerRefreshTests(unittest.TestCase):
    def test_complete_union_keeps_one_head_and_the_ordinary_entry(self):
        for mapping in ({}, {0: 1, 8: 2, 9: 3, 10: 4, 11: 5, 12: 6, 13: 7, 14: 16, 15: 17}):
            instructions, by_pc, kinds = decode(words(mapping))
            self.assertEqual(recognize(by_pc, kinds), (set(range(0, 88, 4)), ENTRY, {HEAD}))
            source = raw(words(mapping))
            image = ar.rewrite(source, entry_offset=ENTRY, entry_offsets=(ENTRY, EXIT))
            self.assertEqual(image.bytes, source)
            self.assertFalse(image.sites)
            self.assertFalse(image.fixups)

    def test_native_payload_refresh_and_release_cas_preserve_state(self):
        source = ar.rewrite(raw(words()), entry_offset=ENTRY, entry_offsets=(ENTRY, EXIT)).bytes
        cases = ((0x1000, 0, None, 1, 1, 0, 0x1000, 0x1003),
                 (0x2000, 0, None, 2, 1, 1, 0x2000, 0x2003),
                 (0x1000, 2, None, 3, 3, 0, 0x1000, 0x1003),
                 (0x1000, 1, 0x3000, 3, 2, 1, 0x3000, 0x3003))
        for initial, failures, competitor, loads, stores, clears, loaded, side in cases:
            with self.subTest(initial=initial, failures=failures, competitor=competitor):
                machine = PointerRefreshMachine(source, initial=initial, failures=failures, competitor=competitor)
                before, q = machine.x.copy(), machine.q
                machine.run()
                # For owner value 4, the raw AND/ORR/BIC/ADD schedule yields
                # loaded|5, including after refreshing an already-updated X12.
                before[12] = loaded | 5
                before[13], before[14], before[15] = loaded, loaded, 1
                self.assertEqual(machine.x, before)
                self.assertEqual((machine.q, machine.sp, machine.flags), (q, 0x800000, 0x60000000))
                self.assertEqual((machine.loads, machine.stores, machine.clears, machine.writes),
                                 (loads, stores, clears, 1))
                self.assertEqual(machine.memory[0x5008], side)
                self.assertEqual(machine.memory[0x4000], loaded | 5)
                self.assertEqual({address: machine.memory[address] for address in
                                  (0x3038, 0x3048, 0x3FF8, 0x4008, 0x5000, 0x5010)},
                                 {0x3038: 0xAA11, 0x3048: 0xBB22, 0x3FF8: 0xCC33,
                                  0x4008: 0xDD44, 0x5000: 0xEE55, 0x5010: 0xFF66})
                self.assertEqual(machine.events[:3], ['payload-store', 'payload-load', 'load-exclusive'])

    def test_exact_native_width_order_and_register_coupling_are_required(self):
        for at, xor in ((13, 0x8000), (16, 0x8000), (6, 1 << 30), (7, 1 << 30),
                        (15, 1 << 5), (17, 1 << 5), (20, 1 << 5), (9, 1 << 10)):
            values = words()
            values[at] ^= xor
            _, by_pc, kinds = decode(values)
            self.assertIsNone(recognize(by_pc, kinds), (at, xor))
        for target in (0, 8, 9, 10, 11, 12, 14, 15, 18, 29, 30, 31):
            _, by_pc, kinds = decode(words({13: target}))
            self.assertIsNone(recognize(by_pc, kinds), target)
        values = words()
        values[16] ^= 1 << 16  # Status must remain the expected-value role.
        _, by_pc, kinds = decode(values)
        self.assertIsNone(recognize(by_pc, kinds))

    def test_partial_rewritten_or_unknown_exit_is_not_a_native_union(self):
        for at in range(0, 88, 4):
            _, by_pc, kinds = decode(words())
            head = by_pc[HEAD]
            del by_pc[at]
            helper = getattr(ar.android_exclusive, 'native_pointer_refresh', None)
            self.assertIsNotNone(helper)
            self.assertIsNone(helper(head, by_pc, kinds, ar), at)
            _, by_pc, kinds = decode(words())
            kinds[at] = 'x18'
            with self.assertRaisesRegex(ar.RewriteError, 'source rewrite'):
                recognize(by_pc, kinds)
        for change in ('missing', 'fatal', 'different', 'interior'):
            values = words()
            if change == 'fatal':
                values[22] = 0
            elif change == 'different':
                values.append(0xD65F03C0)
                values[21] = ar.branch(84, 92)
            elif change == 'interior':
                values[3] = 0x35000000 | ((ENTRY - 12) // 4) << 5 | 15
                values[21] = ar.branch(84, ENTRY)
            _, by_pc, kinds = decode(values)
            if change == 'missing':
                del by_pc[EXIT]
            self.assertIsNone(recognize(by_pc, kinds), change)

    def test_every_interior_entry_and_partial_independent_schedule_is_refused(self):
        instructions, by_pc, kinds = decode(words())
        result = recognize(by_pc, kinds)
        self.assertIsNotNone(result)
        nodes, entry, _ = result
        for at in nodes - {entry}:
            with self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                ar.android_exclusive.plan_regions(instructions, kinds, (entry, at, EXIT), ar)
            outside = ar.decode(ar.branch(96, at), 96)
            with self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                ar.android_exclusive.plan_regions(instructions + [outside], kinds | {96: None}, (entry, EXIT), ar)


if __name__ == '__main__':
    unittest.main()
