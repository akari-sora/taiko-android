"""Operation-model versus decoded execution of self-authored halfword peers.

The model does not consume matcher results or planner edges. Exclusive-store
outcomes and external races are supplied by each case. This exercises functional
state, access width and monitor retirement; it is not an Arm hardware execution
or an acquire/release memory-ordering proof.
"""
from copy import deepcopy
from dataclasses import dataclass, field
import struct
import unittest

from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from test_android_native_five_peer_halfword_union import CLREX, HEADS, ar, decoded, fixture


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
    initial: int = 0x7111
    expected: int = 0x7111
    payload: int = 0xA5B6
    failures: int = 0
    races: dict = field(default_factory=dict)


def initial_state(case, alias_output):
    """Upper X halves and surrounding bytes expose unintended side effects."""
    x = [0xA1B2C3D400001000 + index * 0x101 for index in range(31)]
    x[8] = 0xF0E1D2C300000000 | (case.payload & 0xFFFFFFFF)
    x[10] = 0xB8A7968500000000 | (case.expected & 0xFFFFFFFF)
    x[19], x[20] = CELL if alias_output else OUTPUT, CELL
    memory = {
        base + offset: (offset * 37 + base // 4096) & 0xFF
        for base in (CELL & ~0xFFF, OUTPUT & ~0xFFF, STACK & ~0xFFF)
        for offset in range(0x100)
    }
    for byte, value in enumerate((case.initial & 0xFFFF).to_bytes(2, 'little')):
        memory[CELL + byte] = value
    for offset, first, second in ((0x20, 20, 19), (0x10, 22, 21), (0, 30, 23)):
        for register, address in ((first, STACK + offset), (second, STACK + offset + 8)):
            for byte, value in enumerate(SAVED[register].to_bytes(8, 'little')):
                memory[address + byte] = value
    return dict(x=x, sp=STACK, nzcv=0xB0000000, memory=memory)


class OperationModel:
    """Halfword CAS and ABI return contract, without decoded instructions."""

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
            loaded = int.from_bytes(bytes(memory[cell + byte] for byte in range(2)), 'little')
            x[9] = loaded  # A halfword load zero-extends into W9 and therefore X9.
            self.monitor = cell
            self.counts['loads'] += 1
            self.events.append(('load', self.head, cell, loaded, None, cell))
            expected = x[10] & 0xFFFFFFFF  # The compare is full W32, not H16.
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
                for byte, value in enumerate(loaded.to_bytes(2, 'little')):
                    memory[output + byte] = value
                self.events.append(('publish', output, loaded))
                self.counts['publishes'] += 1
                result = 0
                break
            self.counts['stores'] += 1
            success = self.counts['stores'] > self.case.failures
            assert self.monitor == cell
            payload = x[8] & 0xFFFF
            self.monitor = None  # Both successful and failed stores retire it.
            x[11] = 0 if success else 1
            replacement = payload if success else self.case.races.get(self.counts['stores'])
            if replacement is not None:
                for byte, value in enumerate((replacement & 0xFFFF).to_bytes(2, 'little')):
                    memory[cell + byte] = value
            self.events.append(('store', self.head + 12, cell, payload, success, cell, None))
            if success:
                assert x[11] == 0 and self.monitor is None
                # MOV-one/TBNZ takes the success return; publication is dead.
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
    """Small decoded interpreter; matcher results and planner edges are unused."""

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
        n, z = bool(result & sign), result == 0
        c = bool((left + ((~right) & mask) + 1) >> bits)
        v = not -sign <= signed_left - signed_right < sign
        self.state['nzcv'] = (n << 31) | (z << 30) | (c << 29) | (v << 28)

    def run(self):
        for _ in range(512):
            ins = self.instructions[self.pc]
            ops, name, following = ins.operands, ins.mnemonic, self.pc + 4
            if name in ('ldxrh', 'ldaxrh'):
                assert self.monitor is None, 'new load before prior reservation retired'
                address = self.address(ins, ops[1])
                loaded = self.read(address, 2)
                self.write_register(ins, ops[0].reg, loaded)
                self.monitor = address
                self.counts['loads'] += 1
                self.events.append(('load', self.pc, address, loaded, None, address))
            elif name in ('stxrh', 'stlxrh'):
                address, payload = self.address(ins, ops[2]), self.value(ins, ops[1]) & 0xFFFF
                assert self.monitor == address, 'exclusive store without owning reservation'
                self.counts['stores'] += 1
                success = self.counts['stores'] > self.case.failures
                self.monitor = None
                self.write_register(ins, ops[0].reg, int(not success))
                if success:
                    self.write(address, 2, payload)
                elif self.counts['stores'] in self.case.races:
                    self.write(address, 2, self.case.races[self.counts['stores']])
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
            elif name == 'strh':
                assert self.monitor is None, 'plain STRH reached before monitor retirement'
                address, value = self.address(ins, ops[1]), self.value(ins, ops[0]) & 0xFFFF
                self.write(address, 2, value)
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


class HalfwordSemanticsTests(unittest.TestCase):
    def assert_effects(self, machine, initial, case, result):
        cell, output = initial['x'][20], initial['x'][19]
        memory = machine.state['memory']
        touched = {cell, cell + 1, output, output + 1}
        for address, value in initial['memory'].items():
            if address not in touched:
                self.assertEqual(memory[address], value, f'guard byte 0x{address:x}')
        self.assertIsNone(machine.monitor)
        self.assertEqual(machine.state['sp'], STACK + 0x30)
        for register, value in SAVED.items():
            self.assertEqual(machine.state['x'][register], value)
        self.assertEqual(machine.counts['restores'], 3)
        self.assertEqual(machine.counts['returns'], 1)
        self.assertLessEqual(machine.state['x'][9], 0xFFFF)
        self.assertEqual(machine.state['x'][8], result)
        self.assertEqual(machine.state['x'][0], result)
        if result:
            self.assertEqual(machine.state['x'][11], 0)
            self.assertEqual(machine.counts['clears'], 0)
            self.assertEqual(machine.counts['publishes'], 0)
            self.assertEqual(bytes(memory[cell + byte] for byte in range(2)),
                             (case.payload & 0xFFFF).to_bytes(2, 'little'))
            if output != cell:
                self.assertEqual(bytes(memory[output + byte] for byte in range(2)),
                                 bytes(initial['memory'][output + byte] for byte in range(2)))
        else:
            self.assertEqual(machine.counts['clears'], 1)
            self.assertEqual(machine.counts['publishes'], 1)
            self.assertEqual(bytes(memory[output + byte] for byte in range(2)),
                             machine.state['x'][9].to_bytes(2, 'little'))

    def assert_cases(self, cases):
        source, images = fixture(), {}
        for head in sorted(HEADS):
            try:
                image = ar.rewrite(source, entry_offset=head, entry_offsets=tuple(sorted(HEADS)))
            except ar.RewriteError as error:
                self.fail(f'authored halfword closure must remain native: {error}')
            self.assertEqual(image.bytes, source)
            self.assertEqual((image.sites, image.gates, image.fixups), ((), (), ()))
            images[head] = image.bytes
        for head in sorted(HEADS):
            for case in cases:
                for alias_output in (False, True):
                    with self.subTest(head=head, case=case.name, alias_output=alias_output):
                        initial = initial_state(case, alias_output)
                        self.assertTrue(all(initial['x'][register] >> 32
                                            for register in (0, 8, 9, 10, 11)))
                        model = OperationModel(initial, case, head)
                        expected = model.run()
                        self.assert_effects(model, initial, case, expected)
                        for label, body in (('original', source), ('complete rewrite', images[head])):
                            with self.subTest(program=label):
                                machine = DecodedMachine(body, initial, case, head)
                                self.assertEqual(machine.run(), expected)
                                self.assertEqual(machine.state, model.state)
                                self.assertEqual(machine.events, model.events)
                                self.assertEqual(machine.counts, model.counts)
                                self.assert_effects(machine, initial, case, expected)

    def test_all_heads_success_retries_and_compare_mismatch(self):
        self.assert_cases((
            Case('success immediately'),
            Case('success after one failed store', failures=1),
            Case('success after multiple failed stores', failures=3),
            Case('initial compare mismatch', initial=0x7212),
            Case('mismatch after one failed store', failures=1, races={1: 0x9988}),
            Case('mismatch after multiple failed stores', failures=3, races={3: 0x4567}),
        ))

    def test_halfword_boundaries_payload_width_and_full_word_expected(self):
        self.assert_cases((
            Case('zero replaced by maximum halfword', initial=0, expected=0, payload=0xFFFF),
            Case('maximum halfword replaced by zero', initial=0xFFFF, expected=0xFFFF, payload=0),
            Case('halfword sign bit remains zero extended', initial=0x8000, expected=0x8000, payload=0x7FFF),
            Case('largest signed halfword', initial=0x7FFF, expected=0x7FFF, payload=0x8000),
            Case('expected is not truncated to halfword', expected=0x17111),
            Case('expected word sign bit participates', expected=0x80007111),
            Case('all expected word bits participate', initial=0xFFFF, expected=0xFFFFFFFF),
            Case('exclusive store uses low sixteen payload bits', payload=0xC3D4A5B6),
        ))

    def test_independent_model_detects_reversed_success_and_failure_tests(self):
        source = fixture()
        instructions, _ = decoded(source)
        tests = [ins for ins in instructions if ins.mnemonic == 'tbnz']
        self.assertEqual(len(tests), 2)
        for target, case in ((tests[0], Case('reversed success test')),
                             (tests[1], Case('reversed failure test', initial=0x7212))):
            mutated = bytearray(source)
            encoded = struct.unpack_from('<I', mutated, target.address)[0]
            struct.pack_into('<I', mutated, target.address, encoded ^ (1 << 24))
            for head in sorted(HEADS):
                for alias_output in (False, True):
                    with self.subTest(test=target.address, head=head, alias_output=alias_output):
                        initial = initial_state(case, alias_output)
                        model = OperationModel(initial, case, head)
                        expected = model.run()
                        mutant = DecodedMachine(bytes(mutated), initial, case, head)
                        self.assertNotEqual(mutant.run(), expected)
                        self.assertNotEqual(mutant.state, model.state)
                        self.assertNotEqual(mutant.events, model.events)


if __name__ == '__main__':
    unittest.main()
