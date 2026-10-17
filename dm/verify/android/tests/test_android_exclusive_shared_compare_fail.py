"""Two LDAXRB compare failures may share one CLREX when re-entry is the load."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

(LOOP, GATE, LOAD1, CMP1, BNE1, STORE1, CBNZ1,
 OTHER, OCMP, OBNE, OSTORE, OCBNZ, OB, OCLREX, ODONE,
 LOAD2, CMP2, BNE2, STORE2, CBNZ2, LEAVE2,
 SHARED, ADD, BACK) = range(0, 96, 4)
FIRST = {LOAD1, CMP1, BNE1, STORE1, CBNZ1, SHARED}
SECOND = {LOAD2, CMP2, BNE2, STORE2, CBNZ2, SHARED}
PRIVATE = {OTHER, OCMP, OBNE, OSTORE, OCBNZ, OCLREX}
LATER = {CMP1, BNE1, STORE1, CBNZ1}


def bne(pc, target):
    return 0x54000001 | ((((target - pc) // 4) & 0x7FFFF) << 5)


def cbnz(pc, reg, target):
    return 0x35000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def words(overrides=()):
    # The shared CLREX is the compare-fail exit of both LDAXRB [x14] attempts.
    # ADD does not refresh x14. The loop reloads that pointer, then B.NE takes
    # the separate LDAXRB and falls through into the first load. That separate
    # attempt keeps its own CLREX.
    source = {
        LOOP: 0xF94001AE,  # ldr x14, [x13]
        GATE: bne(GATE, OTHER),
        LOAD1: 0x085FFDCF,  # ldaxrb w15, [x14]
        CMP1: 0x6B3401FF,  # cmp w15, w20, uxtb
        BNE1: bne(BNE1, SHARED),
        STORE1: 0x080FFDCA,  # stlxrb w15, w10, [x14]
        CBNZ1: cbnz(CBNZ1, 15, LOAD1),
        OTHER: 0x085FFDCF,  # ldaxrb w15, [x14]
        OCMP: 0x6B2801FF,  # cmp w15, w8, uxtb
        OBNE: bne(OBNE, OCLREX),
        OSTORE: 0x080FFDCB,  # stlxrb w15, w11, [x14]
        OCBNZ: cbnz(OCBNZ, 15, OTHER),
        OB: ar.branch(OB, ODONE),
        OCLREX: 0xD5033F5F,
        ODONE: 0xD65F03C0,
        LOAD2: 0x085FFDCF,  # ldaxrb w15, [x14]
        CMP2: 0x6B2901FF,  # cmp w15, w9, uxtb
        BNE2: bne(BNE2, SHARED),
        STORE2: 0x080FFDCA,  # stlxrb w15, w10, [x14]
        CBNZ2: cbnz(CBNZ2, 15, LOAD2),
        LEAVE2: 0xD65F03C0,
        SHARED: 0xD5033F5F,
        ADD: 0x9100058C,  # add x12, x12, #1
        BACK: ar.branch(BACK, LOOP),
    }
    source.update(overrides)
    return [source[pc] for pc in range(0, BACK + 4, 4)]


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, (), ar)


class ExclusiveSharedCompareFailTests(unittest.TestCase):
    def test_shared_clrex_exits_when_reentry_is_the_load(self):
        source = words()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (
                LOAD1, CMP1, BNE1, STORE1, CBNZ1, LOAD2, CMP2, BNE2, SHARED, ADD, BACK, LOOP, GATE)],
            ['ldaxrb', 'cmp', 'b.ne', 'stlxrb', 'cbnz', 'ldaxrb', 'cmp', 'b.ne', 'clrex', 'add', 'b',
             'ldr', 'b.ne'])
        self.assertEqual(by_pc[LOAD1].op_str, 'w15, [x14]')
        self.assertEqual(by_pc[CMP1].op_str, 'w15, w20, uxtb')
        self.assertEqual(by_pc[STORE1].op_str, 'w15, w10, [x14]')
        self.assertEqual(by_pc[CMP2].op_str, 'w15, w9, uxtb')
        self.assertEqual(by_pc[LOOP].op_str, 'x14, [x13]')
        self.assertEqual(by_pc[ADD].op_str, 'x12, x12, #1')
        self.assertEqual(by_pc[OTHER].op_str, 'w15, [x14]')
        self.assertEqual(by_pc[OCMP].op_str, 'w15, w8, uxtb')
        self.assertEqual(by_pc[OSTORE].op_str, 'w15, w11, [x14]')
        self.assertEqual(by_pc[BNE1].operands[-1].imm, SHARED)
        self.assertEqual(by_pc[BNE2].operands[-1].imm, SHARED)
        self.assertEqual(by_pc[GATE].operands[-1].imm, OTHER)
        self.assertEqual(by_pc[GATE].address + 4, LOAD1)
        self.assertEqual(by_pc[BACK].operands[-1].imm, LOOP)
        self.assertEqual(by_pc[OBNE].operands[-1].imm, OCLREX)
        for ins in (by_pc[pc] for pc in (SHARED, ADD, BACK, LOOP, GATE)):
            self.assertTrue(set(ar.android_exclusive.successors(ins)).isdisjoint(LATER))
        exit_of = ar.android_exclusive.shared_compare_fail_clrex_exit
        self.assertTrue(exit_of(by_pc, SHARED, FIRST, LOAD1, ar))
        self.assertTrue(exit_of(by_pc, SHARED, SECOND, LOAD2, ar))
        self.assertFalse(exit_of(by_pc, OCLREX, PRIVATE, OTHER, ar))
        self.assertEqual(plan(source), ())

    def test_second_load_branch_into_compare_or_store_stays_rejected(self):
        rejected = (
            words({BNE2: bne(BNE2, CMP1)}),
            words({BNE2: bne(BNE2, STORE1)}),
            words({CMP2: 0x6B34013F}),  # cmp w9, w20, uxtb; load destination is w15
        )
        for source in rejected:
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            with self.subTest(branch=f'{source[BNE2 // 4]:08x}', compare=f'{source[CMP2 // 4]:08x}'):
                self.assertFalse(ar.android_exclusive.shared_compare_fail_clrex_exit(
                    by_pc, SHARED, FIRST, LOAD1, ar))
                with self.assertRaisesRegex(ar.RewriteError, 'external entry into exclusive region interior'):
                    plan(source)

    def test_clrex_path_into_compare_or_store_stays_rejected(self):
        rejected = (
            words({BACK: ar.branch(BACK, CMP1)}),
            words({BACK: ar.branch(BACK, STORE1)}),
            words({LOOP: 0xD503201F}),  # nop; return to the load does not write x14
        )
        for source in rejected:
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            with self.subTest(back=f'{source[BACK // 4]:08x}', loop=f'{source[LOOP // 4]:08x}'):
                self.assertFalse(ar.android_exclusive.shared_compare_fail_clrex_exit(
                    by_pc, SHARED, FIRST, LOAD1, ar))
                with self.assertRaisesRegex(ar.RewriteError, 'external entry into exclusive region interior'):
                    plan(source)


if __name__ == '__main__':
    unittest.main()
