"""Exact decoded targets, signed ranges, and modulo-encoding alias negatives.

Sparse byte images use real decoder operands. Metadata-proxy cases separately
exercise defensive consistency when an instruction carries a decoded target
that differs by a whole encoding period while its bytes remain unchanged.
"""
from functools import lru_cache
import struct
from types import SimpleNamespace
import unittest

from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG
from word_fixture import (CLOSURE, HEADS, LEAVE, WITNESS, ar, branch,
                          decoded, fixture, helper, plan, word)


class OperandView:
    def __init__(self, instruction, operands):
        self.instruction, self.operands = instruction, operands

    def __getattr__(self, name):
        return getattr(self.instruction, name)


def operand_copy(instruction):
    return [SimpleNamespace(type=operand.type, reg=operand.reg, imm=operand.imm)
            for operand in instruction.operands]


@lru_cache(maxsize=None)
def sparse(shift, reverse=False, alias=False):
    """Move one side of the carrier proof; fill every gap with authored RETs."""
    source = fixture()
    instructions, _ = decoded(source)
    def remap(pc):
        moved = pc < 136 if reverse else pc >= 136
        return pc + shift if moved else pc
    end = max(remap(ins.address) + 4 for ins in instructions)
    if reverse and alias:
        end = max(end, LEAVE + shift + 4)
    result = bytearray(struct.pack('<I', 0xD65F03C0) * (end // 4))
    for instruction in instructions:
        pc = remap(instruction.address)
        encoded = word(instruction.address, source)
        if instruction.mnemonic in ('b', 'b.ne', 'cbnz', 'tbnz'):
            target = remap(instruction.operands[-1].imm)
            register = 8 if instruction.mnemonic == 'tbnz' else 11
            if alias and instruction.address == 128:
                # The original imm14 now reaches a gap RET, exactly 64 KiB
                # from the independently relocated common-success epilogue.
                encoded = word(128, source)
            else:
                encoded = branch(instruction.mnemonic, pc, target, register)
        struct.pack_into('<I', result, pc, encoded)
    return bytes(result), remap


class WordExactTargetTests(unittest.TestCase):
    def test_real_decoded_TBNZ_aliases_both_directions_refuse(self):
        closure = helper(self)
        for reverse in (False, True):
            source, remap = sparse(0x10000, reverse, True)
            instructions, kinds = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            actual = by_pc[remap(128)].operands[-1].imm
            expected = remap(172)
            with self.subTest(reverse=reverse):
                self.assertEqual(actual - expected, 0x10000 if reverse else -0x10000)
                self.assertEqual(by_pc[actual].mnemonic, 'ret')
                self.assertNotEqual(actual, expected)
                with self.assertRaises(ar.RewriteError):
                    closure(by_pc[remap(8)], by_pc, kinds, ar)
                with self.assertRaises(ar.RewriteError):
                    plan(source)

    def test_real_decoded_sparse_controls_include_signed_TBNZ_boundaries(self):
        closure = helper(self)
        for shift, reverse in ((0x1800, False), (0x1800, True),
                               (32720, False), (32812, True)):
            source, remap = sparse(shift, reverse)
            instructions, kinds = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            expected = tuple({remap(pc) for pc in group}
                             for group in (CLOSURE, HEADS, WITNESS))
            with self.subTest(shift=shift, reverse=reverse):
                self.assertEqual(closure(by_pc[remap(8)], by_pc, kinds, ar), expected)
                self.assertEqual(plan(source), ())
                target = by_pc[remap(128)].operands[-1].imm
                self.assertEqual(target, remap(172))
                if shift in (32720, 32812):
                    self.assertEqual(target - remap(128), -32768 if reverse else 32764)

    def test_decoded_target_metadata_cannot_alias_BNE_CBNZ_TBNZ_or_B(self):
        # B.NE/CBNZ period is 2 MiB, TBNZ 64 KiB, and B 256 MiB.
        # A high relocation keeps both signed target mutations nonnegative.
        relocation = 0x30000000
        instructions, defaults = decoded(base=relocation)
        original = {ins.address: ins for ins in instructions}
        closure = helper(self)
        cases = ((40, 'b.ne', 0x200000, 19, 5),
                 (24, 'cbnz', 0x200000, 19, 5),
                 (128, 'tbnz', 0x10000, 14, 5),
                 (144, 'tbnz', 0x10000, 14, 5),
                 (52, 'b', 0x10000000, 26, 0),
                 (132, 'b', 0x10000000, 26, 0))
        for pc, name, period, width, shift in cases:
            instruction = original[pc + relocation]
            self.assertEqual(instruction.mnemonic, name)
            correct = instruction.operands[-1].imm
            for sign in (-1, 1):
                target = correct + sign * period
                operands = operand_copy(instruction)
                operands[-1].imm = target
                view = OperandView(instruction, operands)
                by_pc = {**original, instruction.address: view,
                         target: ar.decode(0xD65F03C0, target)}
                kinds = {**defaults, target: None}
                mask = (1 << width) - 1
                with self.subTest(pc=pc, branch=name, delta=sign * period):
                    self.assertEqual(view.bytes, instruction.bytes)
                    self.assertEqual(target - correct, sign * period)
                    self.assertNotEqual(view.operands[-1].imm, correct)
                    self.assertEqual(((target - instruction.address) // 4) & mask,
                                     (word(pc) >> shift) & mask)
                    with self.assertRaises(ar.RewriteError):
                        closure(by_pc[8 + relocation], by_pc, kinds, ar)

    def test_carrier_decoded_operand_shape_is_authoritative(self):
        instructions, defaults = decoded()
        original = {ins.address: ins for ins in instructions}
        closure = helper(self)
        for pc in (128, 144):
            for malformed in ('missing_bit', 'register_is_imm', 'bit_is_reg', 'target_is_reg'):
                operands = operand_copy(original[pc])
                if malformed == 'missing_bit':
                    operands.pop(1)
                elif malformed == 'register_is_imm':
                    operands[0].type = ARM64_OP_IMM
                elif malformed == 'bit_is_reg':
                    operands[1].type = ARM64_OP_REG
                else:
                    operands[2].type = ARM64_OP_REG
                by_pc = {**original, pc: OperandView(original[pc], operands)}
                with self.subTest(pc=pc, shape=malformed):
                    with self.assertRaises(ar.RewriteError):
                        closure(by_pc[8], by_pc, defaults, ar)


if __name__ == '__main__':
    unittest.main()
