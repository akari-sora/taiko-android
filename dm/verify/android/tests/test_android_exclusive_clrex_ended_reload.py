"""Failed STLXR may reload the same cell; CLREX ends the attempt."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

(HEAD, CMP, BNE, MOV, STORE, STATUS, RELOAD, AGAIN, BEQ, CLREX, POST, TBZ,
 NOT_TAKEN, LATER, AFTER, EPILOGUE, EPILOGUE_ADD, EPILOGUE_RET, STUB, STUB_RET,
 FAR, FAR_LDR, FAR_ADD, FAR_BR) = range(0, 96, 4)
BODY = {HEAD, CMP, BNE, MOV, STORE, CLREX}


def cbz(pc, reg, target):
    return 0x34000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def bne(pc, target):
    return 0x54000001 | ((((target - pc) // 4) & 0x7FFFF) << 5)


def beq(pc, target):
    return 0x54000000 | ((((target - pc) // 4) & 0x7FFFF) << 5)


def tbz(pc, reg, bit, target):
    imm = (target - pc) // 4
    return 0x36000000 | ((bit & 32) << 26) | ((bit & 31) << 19) | ((imm & 0x3FFF) << 5) | reg


def bl(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)


def words(overrides=()):
    # Failure falls through ldaxr / cmp / b.eq, then clrex. The post-clrex mov
    # and tbz are not an epilogue. Taken tbz is ldp / add sp / ret. Not taken
    # is bl to svc #0x1b; ret, then a later bl to adrp / ldr / add / br x17.
    source = {
        HEAD: 0x885FFC09,  # ldaxr w9, [x0]
        CMP: 0x6B08013F,  # cmp w9, w8
        BNE: bne(BNE, CLREX),
        MOV: 0x2A1F03E9,  # mov w9, wzr
        STORE: 0x880AFC09,  # stlxr w10, w9, [x0]
        STATUS: cbz(STATUS, 10, TBZ),
        RELOAD: 0x885FFC09,  # ldaxr w9, [x0]
        AGAIN: 0x6B08013F,  # cmp w9, w8
        BEQ: beq(BEQ, MOV),
        CLREX: 0xD5033F5F,
        POST: 0x2A0903E8,  # mov w8, w9
        TBZ: tbz(TBZ, 8, 30, EPILOGUE),
        NOT_TAKEN: bl(NOT_TAKEN, STUB),
        LATER: bl(LATER, FAR),
        AFTER: 0xD65F03C0,
        EPILOGUE: 0xA9424FF4,  # ldp x20, x19, [sp, #0x20]
        EPILOGUE_ADD: 0x9100C3FF,  # add sp, sp, #0x30
        EPILOGUE_RET: 0xD65F03C0,
        STUB: 0xD4000361,  # svc #0x1b
        STUB_RET: 0xD65F03C0,
        FAR: 0x90000010,  # adrp x16, #0
        FAR_LDR: 0xF9400211,  # ldr x17, [x16]
        FAR_ADD: 0x91000210,  # add x16, x16, #0
        FAR_BR: 0xD61F0220,  # br x17
    }
    source.update(overrides)
    return [source[pc] for pc in range(0, FAR_BR + 4, 4)]


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source, roots=(0,)):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class ExclusiveClrexEndedReloadTests(unittest.TestCase):
    def test_failed_store_reloads_same_cell_and_clrex_ends(self):
        source = words()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (
                HEAD, CMP, BNE, MOV, STORE, STATUS, RELOAD, AGAIN, BEQ, CLREX, POST, TBZ)],
            ['ldaxr', 'cmp', 'b.ne', 'mov', 'stlxr', 'cbz', 'ldaxr', 'cmp', 'b.eq', 'clrex', 'mov', 'tbz'])
        self.assertEqual(by_pc[HEAD].op_str, 'w9, [x0]')
        self.assertEqual(by_pc[CMP].op_str, 'w9, w8')
        self.assertEqual(by_pc[BNE].operands[0].imm, CLREX)
        self.assertEqual(by_pc[MOV].op_str, 'w9, wzr')
        self.assertEqual(by_pc[STORE].op_str, 'w10, w9, [x0]')
        self.assertEqual(by_pc[STATUS].operands[-1].imm, TBZ)
        self.assertEqual(by_pc[RELOAD].op_str, 'w9, [x0]')
        self.assertEqual(by_pc[AGAIN].op_str, 'w9, w8')
        self.assertEqual(by_pc[BEQ].operands[0].imm, MOV)
        self.assertEqual(by_pc[POST].op_str, 'w8, w9')
        self.assertEqual(by_pc[TBZ].op_str, 'w8, #0x1e, #0x3c')
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (EPILOGUE, EPILOGUE_ADD, EPILOGUE_RET)],
            ['ldp', 'add', 'ret'])
        self.assertEqual(by_pc[NOT_TAKEN].operands[-1].imm, STUB)
        self.assertEqual([by_pc[pc].mnemonic for pc in (STUB, STUB_RET)], ['svc', 'ret'])
        self.assertEqual(by_pc[STUB].op_str, '#0x1b')
        self.assertEqual(by_pc[LATER].operands[-1].imm, FAR)
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (FAR, FAR_LDR, FAR_ADD, FAR_BR)],
            ['adrp', 'ldr', 'add', 'br'])
        self.assertEqual(by_pc[FAR_BR].op_str, 'x17')
        self.assertFalse(ar.android_exclusive.plain_function_epilogue(
            by_pc, CLREX + 4, BODY | {STATUS, RELOAD, AGAIN, BEQ}, ar))
        tail, edges = ar.android_exclusive.retry_tail(by_pc, by_pc[STORE], HEAD, BODY, ar)
        self.assertEqual(tail, {STATUS, RELOAD, AGAIN, BEQ})
        self.assertEqual(edges, {(BEQ, MOV)})
        for pc in (POST, TBZ, NOT_TAKEN, LATER, AFTER, STUB, FAR, FAR_BR):
            self.assertNotIn(pc, tail)
        self.assertEqual(plan(source), ())

    def test_other_address_destination_and_reentry_stay_rejected(self):
        outside = words()
        outside_pc = len(outside) * 4
        outside.append(0x885FFC09)  # ldaxr w9, [x0]
        outside[STATUS // 4] = cbz(STATUS, 10, outside_pc)
        reentry = words({POST: ar.branch(POST, HEAD)})
        rejected = (
            words({RELOAD: 0x885FFC29}),  # ldaxr w9, [x1]
            words({RELOAD: 0x885FFC0B}),  # ldaxr w11, [x0]
            words({AGAIN: 0x6B0B013F}),  # cmp w9, w11
            words({BEQ: beq(BEQ, HEAD)}),
            words({STATUS: cbz(STATUS, 10, RELOAD)}),
            outside,
            reentry,
        )
        for source in rejected:
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            with self.subTest(reload=f'{source[RELOAD // 4]:08x}',
                              again=f'{source[AGAIN // 4]:08x}',
                              status=f'{source[STATUS // 4]:08x}',
                              post=f'{source[POST // 4]:08x}'):
                self.assertIsNone(ar.android_exclusive.compare_reload_clrex_end(
                    by_pc, by_pc[STORE], HEAD, BODY, ar))
                with self.assertRaises(ar.RewriteError):
                    plan(source)


if __name__ == '__main__':
    unittest.main()
