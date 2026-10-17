"""Independent operation model and decoded execution of authored byte peers."""
from copy import deepcopy
from dataclasses import dataclass, field
import unittest

from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from test_android_native_five_peer_byte_union import (
    CLREX, HEADS, ar, decoded, fixture,
)


MASK64 = (1 << 64) - 1
CELL, OUTPUT, STACK = 0x400080, 0x500080, 0x800080
RETURN = 0xFFFFFFFFFFFFFFFC
SAVED = {
    20: 0x1122334455667788,
    19: 0x2233445566778899,
    22: 0x33445566778899AA,
    21: 0x445566778899AABB,
    30: RETURN,
    23: 0x5566778899AABBCC,
}


@dataclass(frozen=True)
class Case:
    name: str
    initial: int = 0x71
    expected: int = 0x71
    payload: int = 0xA5
    failures: int = 0
    races: dict = field(default_factory=dict)


def initial_state(case, alias_output):
    """Nonzero upper halves and guard bytes make unintended effects visible."""
    x = [0xA1B2C3D400001000 + index * 0x101 for index in range(31)]
    x[8] = 0xF0E1D2C300000000 | case.payload
    x[10] = 0xB8A7968500000000 | case.expected
    x[19], x[20] = CELL if alias_output else OUTPUT, CELL
    memory = {
        base + offset: (offset * 37 + base // 4096) & 0xFF
        for base in (CELL & ~0xFFF, OUTPUT & ~0xFFF, STACK & ~0xFFF)
        for offset in range(0x100)
    }
    memory[CELL] = case.initial
    for offset, first, second in ((0x20, 20, 19), (0x10, 22, 21), (0, 30, 23)):
        for register, address in ((first, STACK + offset), (second, STACK + offset + 8)):
            for byte, value in enumerate(SAVED[register].to_bytes(8, 'little')):
                memory[address + byte] = value
    return dict(x=x, sp=STACK, nzcv=0xB0000000, memory=memory)


class OperationModel:
    """CAS operation and return contract, without decoded instructions or CFGs."""
    def __init__(self, state, case, head):
        self.state = deepcopy(state)
        self.case, self.head = case, head
        self.monitor = None
        self.events = []
        self.counts = dict(loads=0, stores=0, clears=0, publishes=0, restores=0, returns=0)

    def run(self):
        state, x, memory = self.state, self.state['x'], self.state['memory']
        cell, output, original_sp = x[20], x[19], state['sp']
        for _ in range(32):
            assert self.monitor is None
            loaded = memory[cell]
            x[9] = loaded
            self.monitor = cell
            self.counts['loads'] += 1
            self.events.append(('load', self.head, cell, loaded, None, cell))
            expected = x[10] & 0xFFFFFFFF
            difference = (loaded - expected) & 0xFFFFFFFF
            overflow = bool((loaded ^ expected) & (loaded ^ difference) & 0x80000000)
            state['nzcv'] = ((int(bool(difference & 0x80000000)) << 3) |
                             ((difference == 0) << 2) | ((loaded >= expected) << 1) |
                             overflow) << 28
            if loaded != expected:
                x[8] = 0
                assert self.monitor == cell
                self.events.append(('clrex', CLREX, cell, None))
                self.monitor = None
                self.counts['clears'] += 1
                assert self.monitor is None
                x[0] = 0
                memory[output] = loaded
                self.events.append(('publish', output, loaded))
                self.counts['publishes'] += 1
                result = 0
                break
            self.counts['stores'] += 1
            success = self.counts['stores'] > self.case.failures
            assert self.monitor == cell
            payload = x[8] & 0xFF
            self.monitor = None
            x[11] = 0 if success else 1
            if success:
                memory[cell] = payload
            elif self.counts['stores'] in self.case.races:
                memory[cell] = self.case.races[self.counts['stores']]
            self.events.append(('store', self.head + 12, cell, payload, success, cell, None))
            if success:
                # This flag is assigned only after the successful status test.
                assert x[11] == 0 and self.monitor is None
                x[8], x[0] = 1, 1
                result = 1
                break
        else:
            raise AssertionError('independent operation exceeded its attempt bound')
        assert self.monitor is None
        for offset, first, second in ((0x20, 20, 19), (0x10, 22, 21), (0, 30, 23)):
            for register, address in ((first, original_sp + offset),
                                      (second, original_sp + offset + 8)):
                x[register] = int.from_bytes(bytes(memory[address + byte] for byte in range(8)), 'little')
            self.events.append(('restore', original_sp + offset, first, second))
            self.counts['restores'] += 1
        state['sp'] = original_sp + 0x30
        assert self.monitor is None and x[30] == RETURN
        self.events.append(('return', RETURN))
        self.counts['returns'] += 1
        return result


class DecodedMachine:
    """Small decoded interpreter; no matcher results or planner edges are used."""
    def __init__(self, source, state, case, head):
        instructions, _ = decoded(source)
        self.instructions = {ins.address: ins for ins in instructions}
        self.state = deepcopy(state)
        self.case, self.pc = case, head
        self.monitor = None
        self.events = []
        self.counts = dict(loads=0, stores=0, clears=0, publishes=0, restores=0, returns=0)

    @staticmethod
    def name(ins, register):
        name = ins.reg_name(register)
        return {'lr': 'x30', 'fp': 'x29'}.get(name, name)

    def read_register(self, ins, register):
        name = self.name(ins, register)
        if name in ('wzr', 'xzr'):
            return 0
        if name == 'sp':
            return self.state['sp']
        assert name[0] in 'wx' and name[1:].isdigit(), name
        return self.state['x'][int(name[1:])] & (0xFFFFFFFF if name[0] == 'w' else MASK64)

    def write_register(self, ins, register, value):
        name = self.name(ins, register)
        if name in ('wzr', 'xzr'):
            return
        if name == 'sp':
            self.state['sp'] = value & MASK64
            return
        assert name[0] in 'wx' and name[1:].isdigit(), name
        self.state['x'][int(name[1:])] = value & (0xFFFFFFFF if name[0] == 'w' else MASK64)

    def value(self, ins, operand):
        if operand.type == ARM64_OP_REG:
            return self.read_register(ins, operand.reg)
        assert operand.type == ARM64_OP_IMM
        return operand.imm

    def address(self, ins, operand):
        assert operand.type == ARM64_OP_MEM and not operand.mem.index
        return (self.read_register(ins, operand.mem.base) + operand.mem.disp) & MASK64

    def read(self, address, size):
        return sum(self.state['memory'][address + byte] << (8 * byte) for byte in range(size))

    def write(self, address, size, value):
        for byte in range(size):
            assert address + byte in self.state['memory']
            self.state['memory'][address + byte] = (value >> (8 * byte)) & 0xFF

    def compare(self, left, right, bits):
        mask, sign = (1 << bits) - 1, 1 << (bits - 1)
        left, right = left & mask, right & mask
        result = (left - right) & mask
        signed_left = left - (1 << bits) if left & sign else left
        signed_right = right - (1 << bits) if right & sign else right
        signed_result = signed_left - signed_right
        n, z = bool(result & sign), result == 0
        c = bool((left + ((~right) & mask) + 1) >> bits)
        v = not -sign <= signed_result < sign
        self.state['nzcv'] = (n << 31) | (z << 30) | (c << 29) | (v << 28)

    def run(self):
        for _ in range(512):
            ins = self.instructions[self.pc]
            ops, name, following = ins.operands, ins.mnemonic, self.pc + 4
            if name in ('ldxrb', 'ldaxrb'):
                assert self.monitor is None, 'new load before prior reservation retired'
                address = self.address(ins, ops[1])
                loaded = self.read(address, 1)
                self.write_register(ins, ops[0].reg, loaded)
                self.monitor = address
                self.counts['loads'] += 1
                self.events.append(('load', self.pc, address, loaded, None, address))
            elif name in ('stxrb', 'stlxrb'):
                address, payload = self.address(ins, ops[2]), self.value(ins, ops[1]) & 0xFF
                assert self.monitor == address, 'exclusive store without owning reservation'
                self.counts['stores'] += 1
                success = self.counts['stores'] > self.case.failures
                self.monitor = None  # Both successful and failed STXR retire it.
                self.write_register(ins, ops[0].reg, int(not success))
                if success:
                    self.write(address, 1, payload)
                elif self.counts['stores'] in self.case.races:
                    self.write(address, 1, self.case.races[self.counts['stores']])
                self.events.append(('store', self.pc, address, payload, success, address, None))
            elif name == 'clrex':
                assert self.monitor is not None, 'compare failure lost its reservation before CLREX'
                self.events.append(('clrex', self.pc, self.monitor, None))
                self.monitor = None
                self.counts['clears'] += 1
            elif name == 'cmp':
                bits = 32 if self.name(ins, ops[0].reg).startswith('w') else 64
                self.compare(self.value(ins, ops[0]), self.value(ins, ops[1]), bits)
            elif name == 'b.ne':
                if not self.state['nzcv'] & 0x40000000:
                    following = ops[0].imm
            elif name == 'cbnz':
                if self.value(ins, ops[0]):
                    following = ops[1].imm
            elif name in ('tbz', 'tbnz'):
                bit_set = bool(self.value(ins, ops[0]) & (1 << ops[1].imm))
                if bit_set == (name == 'tbnz'):
                    following = ops[2].imm
            elif name == 'b':
                following = ops[0].imm
            elif name == 'mov':
                self.write_register(ins, ops[0].reg, self.value(ins, ops[1]))
            elif name == 'strb':
                assert self.monitor is None, 'plain STRB reached before monitor retirement'
                address, value = self.address(ins, ops[1]), self.value(ins, ops[0]) & 0xFF
                assert self.name(ins, ops[0].reg) == 'w9', 'publish must use the last loaded byte'
                self.write(address, 1, value)
                self.events.append(('publish', address, value))
                self.counts['publishes'] += 1
            elif name == 'ldp':
                assert self.monitor is None, 'stack restore reached before monitor retirement'
                assert self.name(ins, ops[2].mem.base) == 'sp'
                address = self.address(ins, ops[2])
                first, second = self.read(address, 8), self.read(address + 8, 8)
                self.write_register(ins, ops[0].reg, first)
                self.write_register(ins, ops[1].reg, second)
                self.events.append(('restore', address, int(self.name(ins, ops[0].reg)[1:]),
                                    int(self.name(ins, ops[1].reg)[1:])))
                self.counts['restores'] += 1
                if ins.writeback:
                    assert len(ops) == 4 and ops[3].type == ARM64_OP_IMM
                    self.write_register(ins, ops[2].mem.base,
                                        self.read_register(ins, ops[2].mem.base) + ops[3].imm)
            elif name == 'ret':
                assert self.monitor is None, 'RET reached before monitor retirement'
                target = self.value(ins, ops[0]) if ops else self.state['x'][30]
                assert target == RETURN
                self.events.append(('return', target))
                self.counts['returns'] += 1
                return self.state['x'][0]
            else:
                raise AssertionError(f'unmodeled authored instruction: {name} {ins.op_str}')
            self.pc = following
        raise AssertionError('decoded authored program exceeded its execution bound')


class FivePeerByteSemanticsTests(unittest.TestCase):
    def assert_cases(self, cases):
        source = fixture()
        images = {}
        for head in sorted(HEADS):
            image = ar.rewrite(source, entry_offset=head, entry_offsets=tuple(sorted(HEADS)))
            self.assertEqual(image.bytes, source)
            self.assertEqual((image.sites, image.gates, image.fixups), ((), (), ()))
            images[head] = image.bytes
        for head in sorted(HEADS):
            for case in cases:
                for alias_output in (False, True):
                    with self.subTest(head=head, case=case.name, alias_output=alias_output):
                        initial = initial_state(case, alias_output)
                        model = OperationModel(initial, case, head)
                        expected = model.run()
                        for label, body in (('original', source), ('complete rewrite', images[head])):
                            with self.subTest(program=label):
                                machine = DecodedMachine(body, initial, case, head)
                                self.assertEqual(machine.run(), expected)
                                self.assertEqual(machine.state, model.state)
                                self.assertEqual(machine.events, model.events)
                                self.assertEqual(machine.counts, model.counts)
                                self.assertIsNone(machine.monitor)
                                self.assertEqual(machine.state['sp'], STACK + 0x30)
                                for register, value in SAVED.items():
                                    self.assertEqual(machine.state['x'][register], value)
                                self.assertEqual(machine.counts['restores'], 3)
                                self.assertEqual(machine.counts['returns'], 1)
                                if expected:
                                    self.assertEqual(machine.state['x'][11], 0)
                                    self.assertEqual(machine.counts['clears'], 0)
                                    self.assertEqual(machine.counts['publishes'], 0)
                                else:
                                    output = initial['x'][19]
                                    self.assertEqual(machine.state['memory'][output], machine.state['x'][9])
                                    self.assertEqual(machine.counts['clears'], 1)
                                    self.assertEqual(machine.counts['publishes'], 1)

    def test_all_heads_success_failures_and_mismatch_match_full_state(self):
        self.assert_cases((
            Case('success immediately'),
            Case('success after one failed store', failures=1),
            Case('success after multiple failed stores', failures=3),
            Case('initial compare mismatch', initial=0x72),
            Case('compare mismatch after failed store', failures=1, races={1: 0x99}),
            Case('compare mismatch after multiple failed stores', failures=3, races={3: 0x45}),
        ))

    def test_byte_extremes_and_full_word_comparison_match_full_state(self):
        self.assert_cases((
            Case('zero byte replaced by max byte', initial=0, expected=0, payload=0xFF),
            Case('max byte replaced by zero byte', initial=0xFF, expected=0xFF, payload=0),
            Case('expected register is not truncated to byte', expected=0x171),
            Case('expected word has sign bit set', expected=0x80000071),
        ))


if __name__ == '__main__':
    unittest.main()
