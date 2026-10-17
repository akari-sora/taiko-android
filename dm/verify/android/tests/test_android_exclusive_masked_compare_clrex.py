"""A masked fresh load may CLREX and leave; mismatch returns to the compare."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

(HEAD, MOV, COMPARE, STORE1, CBZ, RELOAD1, LINK1,
 BIT, ORR, STORE2, CBNZ2, PREP, ARG1, ARG2, CALL,
 SPILL, STATUS, FRESH, MASK, CMP, BEQ, MISMATCH,
 RELOAD2, LINK2, CLREX, EPILOGUE, EPILOGUE_LDP, EPILOGUE_ADD, EPILOGUE_RET,
 NONZERO, NONZERO_ADD, NONZERO_MOVS, NONZERO_BL, NONZERO_FALL,
 OUTSIDE, STUB, STUB_RET) = range(0, 148, 4)
BODY = {HEAD, MOV, COMPARE, STORE1, BIT, ORR, STORE2, PREP, ARG1, ARG2, CALL}
# Addresses the masked predicate keeps off the nonzero path. This is the
# fixture stand-in for the real attempt span 0x37f710..0x37f76c.
ATTEMPT = BODY | {CBNZ2, RELOAD2, LINK2, SPILL, STATUS, FRESH, MASK, CMP, BEQ, MISMATCH}


def cbz(pc, reg, target):
    return 0x34000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def cbnz(pc, reg, target):
    return 0x35000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def beq(pc, target):
    return 0x54000000 | ((((target - pc) // 4) & 0x7FFFF) << 5)


def tbnz(pc, reg, bit, target):
    imm = (target - pc) // 4
    return 0x37000000 | ((bit & 32) << 26) | ((bit & 31) << 19) | ((imm & 0x3FFF) << 5) | reg


def bl(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)


def words(overrides=()):
    source = {
        HEAD: 0x885FFC08,  # ldaxr w8, [x0]
        MOV: 0xAA0003F3,  # mov x19, x0
        COMPARE: cbnz(COMPARE, 8, BIT),
        STORE1: 0x8808FE74,  # stlxr w8, w20, [x19]
        CBZ: cbz(CBZ, 8, EPILOGUE),
        RELOAD1: 0x885FFE68,  # ldaxr w8, [x19]
        LINK1: ar.branch(LINK1, COMPARE),
        BIT: tbnz(BIT, 8, 30, PREP),
        ORR: 0x32020109,  # orr w9, w8, #0x40000000
        STORE2: 0x880AFE69,  # stlxr w10, w9, [x19]
        CBNZ2: cbnz(CBNZ2, 10, RELOAD2),
        PREP: 0x12017900,  # and w0, w8, #0xbfffffff
        ARG1: 0xAA1303E1,  # mov x1, x19
        ARG2: 0x2A1403E2,  # mov w2, w20
        CALL: bl(CALL, STUB),
        SPILL: 0xB9000BE0,  # str w0, [sp, #8]
        STATUS: cbnz(STATUS, 0, NONZERO),
        FRESH: 0x885FFE68,  # ldaxr w8, [x19]
        MASK: 0x12017909,  # and w9, w8, #0xbfffffff
        CMP: 0x6B14013F,  # cmp w9, w20
        BEQ: beq(BEQ, CLREX),
        MISMATCH: ar.branch(MISMATCH, COMPARE),
        RELOAD2: 0x885FFE68,  # ldaxr w8, [x19]
        LINK2: ar.branch(LINK2, COMPARE),
        CLREX: 0xD5033F5F,
        EPILOGUE: 0xA9424FF4,  # ldp x20, x19, [sp, #0x20]
        EPILOGUE_LDP: 0xA9417BFD,  # ldp x29, x30, [sp, #0x10]
        EPILOGUE_ADD: 0x9100C3FF,  # add sp, sp, #0x30
        EPILOGUE_RET: 0xD65F03C0,
        NONZERO: 0x90000008,  # adrp x8, #0
        NONZERO_ADD: 0x91000108,  # add x8, x8, #0
        NONZERO_MOVS: 0x6A090129,  # ands w9, w9, w9; flag-setting move (movs w9, w9)
        NONZERO_BL: bl(NONZERO_BL, OUTSIDE),
        NONZERO_FALL: 0xD65F03C0,  # bl fallthrough stays outside the attempt
        OUTSIDE: 0xD65F03C0,  # stub does not branch back into the attempt
        STUB: 0xD4000341,  # svc #0x1a
        STUB_RET: 0xD65F03C0,
    }
    source.update(overrides)
    return [source[pc] for pc in range(0, STUB_RET + 4, 4)]


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source, roots=(0, STUB)):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class ExclusiveMaskedCompareClrexTests(unittest.TestCase):
    def test_masked_fresh_load_clears_with_clrex_and_leaves(self):
        source = words()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(by_pc[MASK].op_str, 'w9, w8, #0xbfffffff')
        self.assertEqual(by_pc[CMP].op_str, 'w9, w20')
        self.assertEqual(by_pc[BEQ].operands[0].imm, CLREX)
        self.assertEqual(by_pc[MISMATCH].operands[0].imm, COMPARE)
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (CLREX, EPILOGUE, EPILOGUE_LDP, EPILOGUE_ADD, EPILOGUE_RET)],
            ['clrex', 'ldp', 'ldp', 'add', 'ret'])
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (NONZERO, NONZERO_ADD, NONZERO_MOVS, NONZERO_BL, OUTSIDE)],
            ['adrp', 'add', 'ands', 'bl', 'ret'])
        self.assertEqual(by_pc[NONZERO_BL].operands[-1].imm, OUTSIDE)
        self.assertNotIn(OUTSIDE, ATTEMPT)
        self.assertFalse(ar.android_exclusive.successors(by_pc[OUTSIDE]))
        self.assertFalse(ar.android_exclusive.direct_svc1a_ret_call(by_pc[NONZERO_BL], by_pc, ar))
        self.assertTrue(ar.android_exclusive.avoids_interior(by_pc, NONZERO, ATTEMPT, ar))
        tail, edges = ar.android_exclusive.retry_tail(by_pc, by_pc[STORE2], HEAD, BODY, ar)
        self.assertEqual(edges, {(LINK2, COMPARE), (MISMATCH, COMPARE)})
        self.assertTrue({CBNZ2, RELOAD2, LINK2, SPILL, STATUS, FRESH, MASK, CMP, BEQ, MISMATCH, CLREX} <= set(tail))
        self.assertTrue(ATTEMPT <= set(tail) | BODY)
        self.assertNotIn(NONZERO_BL, tail)
        self.assertEqual(plan(source), ())

    def test_unmasked_compare_body_branch_and_clobbered_address_stay_rejected(self):
        branched = words({BEQ: beq(BEQ, STUB_RET + 4)})
        branched.extend((0xD5033F5F, ar.branch(STUB_RET + 8, COMPARE)))
        rejected = (
            words({CMP: 0x6B14011F}),  # cmp w8, w20; w8 is the fresh load, not its mask
            branched,  # clrex then branches back into the body
        )
        for source in rejected:
            with self.subTest(cmp=f'{source[CMP // 4]:08x}', spill=f'{source[SPILL // 4]:08x}',
                              match=f'{source[BEQ // 4]:08x}'), \
                    self.assertRaises(ar.RewriteError):
                plan(source)
        clobbered = words({SPILL: 0xAA0103F3})  # mov x19, x1 clobbers the cell
        with self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven exclusive retry tail'):
            plan(clobbered)

    def test_nonzero_bl_that_enters_the_attempt_stays_rejected(self):
        direct = words({NONZERO_BL: bl(NONZERO_BL, COMPARE)})
        returning = words({OUTSIDE: ar.branch(OUTSIDE, COMPARE)})
        for source in (direct, returning):
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            target = by_pc[NONZERO_BL].operands[-1].imm
            with self.subTest(target=target):
                self.assertFalse(ar.android_exclusive.avoids_interior(by_pc, NONZERO, ATTEMPT, ar))
                with self.assertRaises(ar.RewriteError):
                    plan(source)


if __name__ == '__main__':
    unittest.main()
