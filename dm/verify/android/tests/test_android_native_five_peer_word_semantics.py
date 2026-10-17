"""Independent functional evidence for self-authored five-peer word CAS code.

The operation model never reads instructions, closure matches or planner edges.
The interpreter consumes decoded instructions and a deterministic store/race
schedule. This is host functional evidence, not an Arm memory-ordering proof.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import struct
import unittest

from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from word_fixture import CLREX, HEADS, ar, decoded, fixture


U32, U64 = (1 << 32) - 1, (1 << 64) - 1
CELL, OUTPUT, STACK = 0x100400080, 0x200500080, 0x300800080
RETURN = 0xFFFFFFFFFFFFFFFC
RESTORES = ((0x20, 20, 19), (0x10, 22, 21), (0, 30, 23))
SAVED = {20: 0x1245789ABCDEF012, 19: 0x235689ABCDEF0123,
         22: 0x34679ABCDEF01234, 21: 0x4578ABCDEF012345,
         30: RETURN, 23: 0x5689BCDEF0123456}


@dataclass(frozen=True)
class Scenario:
    name: str
    initial: int = 0x89127345
    expected: int = 0x89127345
    replacement: int = 0xFEDCBA98
    failed_stores: int = 0
    races: dict = field(default_factory=dict)


@dataclass
class State:
    x: list
    sp: int
    nzcv: int
    memory: dict

    def read(self, address, size):
        return int.from_bytes(bytes(self.memory[address + i] for i in range(size)), 'little')

    def write(self, address, value, size):
        for i in range(size):
            assert address + i in self.memory, 'write outside authored data allocation'
            self.memory[address + i] = (value >> (i * 8)) & 255


def starting_state(case, alias):
    registers = [0xA691B2C300001000 + i * 0x103 for i in range(31)]
    registers[8] = 0xDCEFAB1200000000 | (case.replacement & U32)
    registers[10] = 0x6574839200000000 | (case.expected & U32)
    registers[19], registers[20] = CELL if alias else OUTPUT, CELL
    memory = {base + i: (i * 53 + (base >> 12) + 17) & 255
              for base in (CELL - 0x80, OUTPUT - 0x80, STACK - 0x80)
              for i in range(0x180)}
    state = State(registers, STACK, 0xB0000000, memory)
    state.write(CELL, case.initial, 4)
    for offset, first, second in RESTORES:
        state.write(STACK + offset, SAVED[first], 8)
        state.write(STACK + offset + 8, SAVED[second], 8)
    return state


class WordOperation:
    """A word compare/exchange, observed-value publication and ABI return."""

    def __init__(self, state, case, head):
        self.state, self.case, self.head = deepcopy(state), case, head
        self.monitor, self.events = None, []

    def run(self):
        s, case = self.state, self.case
        cell, output, frame = s.x[20], s.x[19], s.sp
        expected, replacement = s.x[10] & U32, s.x[8] & U32
        attempt = 0
        while True:
            assert attempt < 20 and self.monitor is None
            observed = s.read(cell, 4)
            s.x[9] = observed
            self.monitor = (cell, 4)
            self.events.append(('reserve', self.head, cell, 4, observed))
            delta = (observed - expected) & U32
            overflow = bool((observed ^ expected) & (observed ^ delta) & 0x80000000)
            s.nzcv = ((bool(delta & 0x80000000) << 31) | ((delta == 0) << 30) |
                      ((observed >= expected) << 29) | (overflow << 28))
            if observed != expected:
                s.x[8] = 0
                assert self.monitor == (cell, 4)
                self.events.append(('clear', CLREX, cell, 4))
                self.monitor = None
                s.x[0] = 0
                s.write(output, observed, 4)
                self.events.append(('publish', output, 4, observed))
                break
            attempt += 1
            accepted = attempt > case.failed_stores
            assert self.monitor == (cell, 4)
            self.monitor = None
            s.x[11] = int(not accepted)
            if accepted:
                s.write(cell, replacement, 4)
            elif attempt in case.races:
                s.write(cell, case.races[attempt], 4)
            self.events.append(('exclusive', self.head + 12, cell, 4, replacement, accepted))
            if accepted:
                s.x[8], s.x[0] = 1, 1
                break
        assert self.monitor is None
        for offset, first, second in RESTORES:
            s.x[first] = s.read(frame + offset, 8)
            s.x[second] = s.read(frame + offset + 8, 8)
            self.events.append(('restore', frame + offset, first, second))
        s.sp = frame + 0x30
        self.events.append(('return', RETURN))
        return s.x[0]


class DecodedExecution:
    """Execute only decoded fixture instructions, including width mutants."""

    def __init__(self, source, state, case, head):
        instructions, _ = decoded(source)
        self.code = {ins.address: ins for ins in instructions}
        self.state, self.case, self.pc = deepcopy(state), case, head
        self.monitor, self.events, self.attempts = None, [], 0

    @staticmethod
    def register_name(ins, operand):
        name = ins.reg_name(operand.reg)
        return {'lr': 'x30', 'fp': 'x29'}.get(name, name)

    def get(self, ins, operand):
        if operand.type == ARM64_OP_IMM:
            return operand.imm
        assert operand.type == ARM64_OP_REG
        name = self.register_name(ins, operand)
        if name in ('wzr', 'xzr'):
            return 0
        if name == 'sp':
            return self.state.sp
        assert name[0] in 'wx' and name[1:].isdigit(), name
        return self.state.x[int(name[1:])] & (U32 if name[0] == 'w' else U64)

    def put(self, ins, operand, value):
        name = self.register_name(ins, operand)
        if name in ('wzr', 'xzr'):
            return
        if name == 'sp':
            self.state.sp = value & U64
        else:
            assert name[0] in 'wx' and name[1:].isdigit(), name
            self.state.x[int(name[1:])] = value & (U32 if name[0] == 'w' else U64)

    def address(self, ins, operand):
        assert operand.type == ARM64_OP_MEM and not operand.mem.index
        base = ins.reg_name(operand.mem.base)
        assert base == 'sp' or (base.startswith('x') and base[1:].isdigit())
        value = self.state.sp if base == 'sp' else self.state.x[int(base[1:])]
        return (value + operand.mem.disp) & U64

    def width(self, ins, operand):
        if ins.mnemonic.endswith('h'):
            return 2
        return 4 if self.register_name(ins, operand).startswith('w') else 8

    def set_compare_flags(self, left, right, bits):
        modulus, sign = 1 << bits, 1 << (bits - 1)
        left, right = left % modulus, right % modulus
        answer = (left + modulus - right) % modulus
        signed_left = left if left < sign else left - modulus
        signed_right = right if right < sign else right - modulus
        overflow = not -sign <= signed_left - signed_right < sign
        carry = (left + ((modulus - 1) ^ right) + 1) >= modulus
        self.state.nzcv = ((answer >= sign) << 31) | ((answer == 0) << 30) | (carry << 29) | (overflow << 28)

    def run(self):
        s = self.state
        for _ in range(400):
            ins = self.code[self.pc]
            op, operands, next_pc = ins.mnemonic, ins.operands, self.pc + 4
            if op in ('ldxr', 'ldaxr', 'ldxrh', 'ldaxrh'):
                assert self.monitor is None, 'load replaced an active reservation'
                address, size = self.address(ins, operands[1]), self.width(ins, operands[0])
                value = s.read(address, size)
                self.put(ins, operands[0], value)
                self.monitor = (address, size)
                self.events.append(('reserve', self.pc, address, size, value))
            elif op in ('stxr', 'stlxr', 'stxrh', 'stlxrh'):
                address, size = self.address(ins, operands[2]), self.width(ins, operands[1])
                assert self.monitor == (address, size), 'store lacks matching reservation'
                value = self.get(ins, operands[1]) & ((1 << (8 * size)) - 1)
                self.attempts += 1
                accepted = self.attempts > self.case.failed_stores
                self.monitor = None
                self.put(ins, operands[0], int(not accepted))
                if accepted:
                    s.write(address, value, size)
                elif self.attempts in self.case.races:
                    s.write(address, self.case.races[self.attempts], size)
                self.events.append(('exclusive', self.pc, address, size, value, accepted))
            elif op == 'clrex':
                assert self.monitor is not None, 'CLREX reached without live reservation'
                self.events.append(('clear', self.pc, *self.monitor))
                self.monitor = None
            elif op == 'cmp':
                bits = 8 * self.width(ins, operands[0])
                self.set_compare_flags(self.get(ins, operands[0]), self.get(ins, operands[1]), bits)
            elif op in ('b.eq', 'b.ne'):
                equal = bool(s.nzcv & (1 << 30))
                if equal == (op == 'b.eq'):
                    next_pc = operands[0].imm
            elif op in ('cbz', 'cbnz'):
                if bool(self.get(ins, operands[0])) == (op == 'cbnz'):
                    next_pc = operands[1].imm
            elif op in ('tbz', 'tbnz'):
                set_bit = bool(self.get(ins, operands[0]) & (1 << operands[1].imm))
                if set_bit == (op == 'tbnz'):
                    next_pc = operands[2].imm
            elif op == 'b':
                next_pc = operands[0].imm
            elif op == 'mov':
                self.put(ins, operands[0], self.get(ins, operands[1]))
            elif op in ('str', 'strh'):
                assert self.monitor is None, 'publication preceded monitor retirement'
                address, size = self.address(ins, operands[1]), self.width(ins, operands[0])
                value = self.get(ins, operands[0]) & ((1 << (8 * size)) - 1)
                s.write(address, value, size)
                self.events.append(('publish', address, size, value))
            elif op == 'ldp':
                assert self.monitor is None, 'ABI restore preceded monitor retirement'
                address = self.address(ins, operands[2])
                first, second = s.read(address, 8), s.read(address + 8, 8)
                self.put(ins, operands[0], first)
                self.put(ins, operands[1], second)
                self.events.append(('restore', address, int(self.register_name(ins, operands[0])[1:]),
                                    int(self.register_name(ins, operands[1])[1:])))
                if ins.writeback:
                    assert ins.reg_name(operands[2].mem.base) == 'sp'
                    assert len(operands) == 4 and operands[3].type == ARM64_OP_IMM
                    s.sp = (s.sp + operands[3].imm) & U64
            elif op == 'ret':
                assert self.monitor is None, 'return preceded monitor retirement'
                target = self.get(ins, operands[0]) if operands else s.x[30]
                assert target == RETURN
                self.events.append(('return', target))
                return s.x[0]
            else:
                raise AssertionError(f'unsupported authored instruction: {op} {ins.op_str}')
            self.pc = next_pc
        raise AssertionError('decoded execution exceeded bounded retry schedule')


class FivePeerWordSemanticsTests(unittest.TestCase):
    def assert_contract(self, execution, initial, result):
        s = execution.state
        cell, output = initial.x[20], initial.x[19]
        mutable = set(range(cell, cell + 4)) | set(range(output, output + 4))
        self.assertEqual({a: b for a, b in s.memory.items() if a not in mutable},
                         {a: b for a, b in initial.memory.items() if a not in mutable})
        self.assertEqual(s.sp, initial.sp + 0x30)
        self.assertEqual({r: s.x[r] for r in SAVED}, SAVED)
        self.assertEqual((s.x[0], s.x[8]), (result, result))
        self.assertEqual(s.x[9] >> 32, 0, 'W9 load must zero the upper X9 half')
        self.assertIsNone(execution.monitor)
        events = execution.events
        self.assertEqual(sum(e[0] == 'restore' for e in events), 3)
        self.assertEqual(sum(e[0] == 'return' for e in events), 1)
        self.assertEqual(sum(e[0] == 'clear' for e in events), 1 - result)
        self.assertEqual(sum(e[0] == 'publish' for e in events), 1 - result)
        if result:
            self.assertEqual(s.x[11], 0, 'W11 status write must zero its upper X11 half')
            self.assertEqual(s.read(cell, 4), initial.x[8] & U32)
            if cell != output:
                self.assertEqual(s.read(output, 4), initial.read(output, 4))
        else:
            self.assertEqual(s.read(output, 4), s.x[9])

    def differential_cases(self, scenarios):
        source = fixture()
        heads = tuple(sorted(HEADS))
        self.assertEqual(heads, (8, 32, 56, 80, 104))
        for head in heads:
            image = ar.rewrite(source, entry_offset=head, entry_offsets=heads)
            self.assertEqual(image.bytes, source, 'complete word closure must stay native')
            self.assertEqual((image.sites, image.gates, image.fixups), ((), (), ()))
            for case in scenarios:
                for alias in (False, True):
                    with self.subTest(head=head, case=case.name, alias=alias):
                        initial = starting_state(case, alias)
                        self.assertTrue(all(initial.x[r] >> 32 for r in (0, 8, 9, 10, 11)))
                        operation = WordOperation(initial, case, head)
                        expected = operation.run()
                        self.assert_contract(operation, initial, expected)
                        for label, body in (('original', source), ('native rewrite', image.bytes)):
                            with self.subTest(program=label):
                                execution = DecodedExecution(body, initial, case, head)
                                self.assertEqual(execution.run(), expected)
                                self.assertEqual(execution.state, operation.state)
                                self.assertEqual(execution.events, operation.events)
                                self.assert_contract(execution, initial, expected)

    def test_every_head_retry_and_external_race_paths(self):
        self.differential_cases((
            Scenario('immediate acceptance'),
            Scenario('one failed store', failed_stores=1),
            Scenario('three failed stores', failed_stores=3),
            Scenario('compare mismatch', initial=0x89127346),
            Scenario('race creates mismatch', failed_stores=1, races={1: 0x73128945}),
            Scenario('later race creates mismatch', failed_stores=3, races={3: 0x10203040}),
        ))

    def test_word_boundaries_zero_extension_and_compare_flags(self):
        self.differential_cases((
            Scenario('zero to all bits', initial=0, expected=0, replacement=U32),
            Scenario('all bits to zero', initial=U32, expected=U32, replacement=0),
            Scenario('word sign bit', initial=0x80000000, expected=0x80000000, replacement=0x7FFFFFFF),
            Scenario('high word bits participate', initial=0x1234ABCD, expected=0x5678ABCD),
            Scenario('signed overflow mismatch', initial=0x7FFFFFFF, expected=0x80000000),
            Scenario('unsigned borrow mismatch', initial=0, expected=U32),
        ))

    def test_race_that_restores_expected_value_still_retries(self):
        self.differential_cases((Scenario('race leaves matching word', failed_stores=2,
                                         races={1: 0x89127345, 2: 0x89127345}),))

    def test_model_detects_both_reversed_carrier_branches(self):
        source = fixture()
        for pc, case in ((128, Scenario('success branch reversed')),
                         (144, Scenario('failure branch reversed', initial=0x31415926))):
            mutant = bytearray(source)
            word = struct.unpack_from('<I', mutant, pc)[0]
            struct.pack_into('<I', mutant, pc, word ^ (1 << 24))  # TBNZ -> TBZ.
            for head in sorted(HEADS):
                for alias in (False, True):
                    with self.subTest(pc=pc, head=head, alias=alias):
                        initial = starting_state(case, alias)
                        operation = WordOperation(initial, case, head)
                        expected = operation.run()
                        execution = DecodedExecution(bytes(mutant), initial, case, head)
                        self.assertNotEqual(execution.run(), expected)
                        self.assertNotEqual(execution.state, operation.state)
                        self.assertNotEqual(execution.events, operation.events)

    def test_model_detects_exclusive_and_publication_width_mutants(self):
        source = fixture()
        wide = bytearray(source)
        for head in HEADS:
            for pc in (head, head + 12):
                word = struct.unpack_from('<I', wide, pc)[0]
                struct.pack_into('<I', wide, pc, word ^ (1 << 30))  # W transfer -> X transfer.
        narrow = bytearray(source)
        word = struct.unpack_from('<I', narrow, 152)[0]
        struct.pack_into('<I', narrow, 152, word ^ (3 << 30))  # STR W9 -> STRH W9.
        for label, mutant, case in (
                ('eight-byte exclusive', bytes(wide), Scenario('wide exclusive')),
                ('two-byte publication', bytes(narrow), Scenario('narrow publication', initial=0x76543210))):
            for head in sorted(HEADS):
                for alias in (False, True):
                    with self.subTest(mutant=label, head=head, alias=alias):
                        initial = starting_state(case, alias)
                        operation = WordOperation(initial, case, head)
                        expected = operation.run()
                        execution = DecodedExecution(mutant, initial, case, head)
                        self.assertEqual(execution.run(), expected)
                        # Publishing the same observed value back to its cell is
                        # idempotent; the access event still exposes its width.
                        if label == 'two-byte publication' and alias:
                            self.assertEqual(execution.state, operation.state)
                        else:
                            self.assertNotEqual(execution.state, operation.state)
                        self.assertNotEqual(execution.events, operation.events)
                        if label == 'eight-byte exclusive':
                            self.assertNotEqual(execution.state.read(CELL + 4, 4), initial.read(CELL + 4, 4))
                            self.assertNotEqual(execution.state.x[9] >> 32, 0)
                        elif not alias:
                            self.assertNotEqual(execution.state.read(OUTPUT, 4), operation.state.read(OUTPUT, 4))


if __name__ == '__main__':
    unittest.main()
