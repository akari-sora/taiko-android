"""LDAXRB, LDAXRH, and LDAXR compare failures may share the zeroing MOV before one CLREX."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

(LOAD1, CMP1, BNE1, STORE1, CBNZ1, LEAVE1,
 LOAD2, CMP2, BNE2, STORE2, CBNZ2, LEAVE2,
 MOV, CLREX, TBNZ, ZERO, STRB, RET,
 TAKEN, TAKEN_RET, ALIEN) = range(0, 84, 4)
FIRST = {LOAD1, CMP1, BNE1, STORE1, CBNZ1, MOV, CLREX}
SECOND = {LOAD2, CMP2, BNE2, STORE2, CBNZ2, MOV, CLREX}


def bne(pc, target):
    return 0x54000001 | ((((target - pc) // 4) & 0x7FFFF) << 5)


def cbnz(pc, reg, target):
    return 0x35000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def tbnz(pc, reg, bit, target):
    imm = (target - pc) // 4
    return 0x37000000 | ((bit & 32) << 26) | ((bit & 31) << 19) | ((imm & 0x3FFF) << 5) | reg


def words(overrides=()):
    # Both LDAXRB [x20] compare failures branch to MOV, not to CLREX.
    # MOV writes zero to w8, so TBNZ w8, #0 is dead. STRB uses x19.
    source = {
        LOAD1: 0x085FFE8A,  # ldaxrb w10, [x20]
        CMP1: 0x6B09015F,  # cmp w10, w9
        BNE1: bne(BNE1, MOV),
        STORE1: 0x080B7E88,  # stxrb w11, w8, [x20]
        CBNZ1: cbnz(CBNZ1, 11, LOAD1),
        LEAVE1: ar.branch(LEAVE1, TAKEN),
        LOAD2: 0x085FFE8A,  # ldaxrb w10, [x20]
        CMP2: 0x6B09015F,  # cmp w10, w9
        BNE2: bne(BNE2, MOV),
        STORE2: 0x080BFE88,  # stlxrb w11, w8, [x20]
        CBNZ2: cbnz(CBNZ2, 11, LOAD2),
        LEAVE2: ar.branch(LEAVE2, TAKEN),
        MOV: 0x2A1F03E8,  # mov w8, wzr
        CLREX: 0xD5033F5F,
        TBNZ: tbnz(TBNZ, 8, 0, TAKEN),
        ZERO: 0x2A1F03E0,  # mov w0, wzr
        STRB: 0x3900026A,  # strb w10, [x19]
        RET: 0xD65F03C0,
        TAKEN: 0x52800020,  # mov w0, #1
        TAKEN_RET: 0xD65F03C0,
        ALIEN: 0xD65F03C0,
    }
    source.update(overrides)
    return [source[pc] for pc in range(0, ALIEN + 4, 4)]


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, (), ar)


class ExclusiveMovBeforeClrexTests(unittest.TestCase):
    def test_shared_mov_exits_when_tbnz_is_dead(self):
        source = words()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (LOAD1, CMP1, BNE1, STORE1, MOV, CLREX, TBNZ, STRB)],
            ['ldaxrb', 'cmp', 'b.ne', 'stxrb', 'mov', 'clrex', 'tbnz', 'strb'])
        self.assertEqual(by_pc[LOAD1].op_str, 'w10, [x20]')
        self.assertEqual(by_pc[CMP1].op_str, 'w10, w9')
        self.assertEqual(by_pc[STORE2].op_str, 'w11, w8, [x20]')
        self.assertEqual(by_pc[MOV].op_str, 'w8, wzr')
        self.assertEqual(by_pc[TBNZ].op_str, f'w8, #0, #{TAKEN:#x}')
        self.assertEqual(by_pc[STRB].op_str, 'w10, [x19]')
        self.assertEqual(by_pc[BNE1].operands[-1].imm, MOV)
        self.assertEqual(by_pc[BNE2].operands[-1].imm, MOV)
        self.assertNotEqual(ar.android_exclusive.memory_base(by_pc[STRB]),
                            ar.android_exclusive.memory_base(by_pc[LOAD1]))
        predecessors = ar.android_exclusive.direct_predecessors(by_pc, MOV)
        self.assertEqual([ins.address for ins in predecessors], [BNE1, BNE2])
        exit_of = ar.android_exclusive.shared_compare_fail_mov_before_clrex
        self.assertFalse(ar.android_exclusive.shared_compare_fail_clrex_exit(
            by_pc, CLREX, FIRST, LOAD1, ar))
        self.assertTrue(exit_of(by_pc, CLREX, FIRST, LOAD1, ar))
        self.assertTrue(exit_of(by_pc, CLREX, SECOND, LOAD2, ar))
        self.assertEqual(plan(source), ())

    def test_shared_halfword_mov_exits_when_tbnz_is_dead(self):
        source = words({
            LOAD1: 0x485FFE8A,  # ldaxrh w10, [x20]
            LOAD2: 0x485FFE8A,  # ldaxrh w10, [x20]
            STORE1: 0x480B7E88,  # stxrh w11, w8, [x20]
            STORE2: 0x480BFE88,  # stlxrh w11, w8, [x20]
            STRB: 0x7900026A,  # strh w10, [x19]
        })
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (LOAD1, CMP1, BNE1, STORE1, STORE2, MOV, CLREX, TBNZ, STRB)],
            ['ldaxrh', 'cmp', 'b.ne', 'stxrh', 'stlxrh', 'mov', 'clrex', 'tbnz', 'strh'])
        self.assertEqual(by_pc[LOAD1].op_str, 'w10, [x20]')
        self.assertEqual(by_pc[LOAD2].op_str, 'w10, [x20]')
        self.assertEqual(by_pc[CMP1].op_str, 'w10, w9')
        self.assertEqual(by_pc[STORE1].op_str, 'w11, w8, [x20]')
        self.assertEqual(by_pc[STORE2].op_str, 'w11, w8, [x20]')
        self.assertEqual(by_pc[STRB].op_str, 'w10, [x19]')
        self.assertEqual(by_pc[BNE1].operands[-1].imm, MOV)
        self.assertEqual(by_pc[BNE2].operands[-1].imm, MOV)
        self.assertNotEqual(ar.android_exclusive.memory_base(by_pc[STRB]),
                            ar.android_exclusive.memory_base(by_pc[LOAD1]))
        predecessors = ar.android_exclusive.direct_predecessors(by_pc, MOV)
        self.assertEqual([ins.address for ins in predecessors], [BNE1, BNE2])
        exit_of = ar.android_exclusive.shared_compare_fail_mov_before_clrex
        self.assertFalse(ar.android_exclusive.shared_compare_fail_clrex_exit(
            by_pc, CLREX, FIRST, LOAD1, ar))
        self.assertTrue(exit_of(by_pc, CLREX, FIRST, LOAD1, ar))
        self.assertTrue(exit_of(by_pc, CLREX, SECOND, LOAD2, ar))
        self.assertEqual(plan(source), ())

    def test_shared_word_mov_exits_when_tbnz_is_dead(self):
        source = words({
            LOAD1: 0x885FFE8A,  # ldaxr w10, [x20]
            LOAD2: 0x885FFE8A,  # ldaxr w10, [x20]
            STORE1: 0x880B7E88,  # stxr w11, w8, [x20]
            STORE2: 0x880BFE88,  # stlxr w11, w8, [x20]
            STRB: 0xB900026A,  # str w10, [x19]
        })
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (LOAD1, CMP1, BNE1, STORE1, STORE2, MOV, CLREX, TBNZ, STRB)],
            ['ldaxr', 'cmp', 'b.ne', 'stxr', 'stlxr', 'mov', 'clrex', 'tbnz', 'str'])
        self.assertEqual(by_pc[LOAD1].op_str, 'w10, [x20]')
        self.assertEqual(by_pc[LOAD2].op_str, 'w10, [x20]')
        self.assertEqual(by_pc[CMP1].op_str, 'w10, w9')
        self.assertEqual(by_pc[STORE1].op_str, 'w11, w8, [x20]')
        self.assertEqual(by_pc[STORE2].op_str, 'w11, w8, [x20]')
        self.assertEqual(by_pc[STRB].op_str, 'w10, [x19]')
        self.assertEqual(by_pc[BNE1].operands[-1].imm, MOV)
        self.assertEqual(by_pc[BNE2].operands[-1].imm, MOV)
        self.assertNotEqual(ar.android_exclusive.memory_base(by_pc[STRB]),
                            ar.android_exclusive.memory_base(by_pc[LOAD1]))
        predecessors = ar.android_exclusive.direct_predecessors(by_pc, MOV)
        self.assertEqual([ins.address for ins in predecessors], [BNE1, BNE2])
        exit_of = ar.android_exclusive.shared_compare_fail_mov_before_clrex
        self.assertFalse(ar.android_exclusive.shared_compare_fail_clrex_exit(
            by_pc, CLREX, FIRST, LOAD1, ar))
        self.assertTrue(exit_of(by_pc, CLREX, FIRST, LOAD1, ar))
        self.assertTrue(exit_of(by_pc, CLREX, SECOND, LOAD2, ar))
        self.assertEqual(plan(source), ())

    def test_predecessor_that_is_not_a_compare_fail_stays_rejected(self):
        rejected = (
            words({ALIEN: ar.branch(ALIEN, MOV)}),
            words({CMP2: 0x6B0A013F}),  # cmp w9, w10; load destination is w10
        )
        for source in rejected:
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            with self.subTest(alien=f'{source[ALIEN // 4]:08x}', compare=f'{source[CMP2 // 4]:08x}'):
                self.assertFalse(ar.android_exclusive.shared_compare_fail_mov_before_clrex(
                    by_pc, CLREX, FIRST, LOAD1, ar))
                with self.assertRaisesRegex(ar.RewriteError, 'external entry into exclusive region interior'):
                    plan(source)

    def test_mov_that_does_not_zero_the_tested_register_stays_rejected(self):
        rejected = (
            words({MOV: 0x2A1F03E9}),  # mov w9, wzr
            words({MOV: 0x2A0903E8}),  # mov w8, w9
        )
        for source in rejected:
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            with self.subTest(mov=f'{source[MOV // 4]:08x}'):
                self.assertFalse(ar.android_exclusive.mov_zeros_tested_register(by_pc[MOV], by_pc[TBNZ]))
                self.assertFalse(ar.android_exclusive.shared_compare_fail_mov_before_clrex(
                    by_pc, CLREX, FIRST, LOAD1, ar))
                with self.assertRaisesRegex(ar.RewriteError, 'external entry into exclusive region interior'):
                    plan(source)

    def test_path_from_clrex_back_into_the_store_stays_rejected(self):
        source = words({RET: ar.branch(RET, STORE1)})
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(by_pc[RET].operands[-1].imm, STORE1)
        self.assertFalse(ar.android_exclusive.shared_compare_fail_mov_before_clrex(
            by_pc, CLREX, FIRST, LOAD1, ar))
        with self.assertRaisesRegex(ar.RewriteError, 'external entry into exclusive region interior'):
            plan(source)


if __name__ == '__main__':
    unittest.main()
