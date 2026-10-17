"""Failed STLXR may CMN the loaded value and retry only its owning load."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

(ADD, LDAR, PROBE, EARLY, HEAD, CMP, BNE, INC, STORE, STATUS, SUCCESS, JOIN,
 CLREX, ZERO, FLAG, COPY, CMN, RETRY, LEAVE, RET) = range(0, 80, 4)
BODY = {HEAD, CMP, BNE, INC, STORE, CLREX}
TAIL = {STATUS, SUCCESS, JOIN, ZERO, FLAG, COPY, CMN, RETRY}
WORDS = (
    0x91002008,  # add x8, x0, #8
    0xC8DFFD0A,  # ldar x10, [x8]
    0xB100055F,  # cmn x10, #1
    0x540001E0,  # b.eq leave
    0xC85FFD09,  # ldaxr x9, [x8]
    0xEB0A013F,  # cmp x9, x10
    0x540000C1,  # b.ne clrex
    0x9100054A,  # add x10, x10, #1
    0xC80BFD0A,  # stlxr w11, x10, [x8]
    0x3500008B,  # cbnz w11, zero
    0x5280002A,  # mov w10, #1
    0x14000003,  # b flag
    0xD5033F5F,  # clrex
    0x2A1F03EA,  # mov w10, wzr
    0x370000AA,  # tbnz w10, #0, ret
    0xAA0903EA,  # mov x10, x9
    0xB100053F,  # cmn x9, #1
    0x54FFFE61,  # b.ne head
    0xAA1F03E0,  # mov x0, xzr
    0xD65F03C0,  # ret
)


def bne(pc, target):
    return 0x54000001 | ((((target - pc) // 4) & 0x7FFFF) << 5)


def words(overrides=None):
    source = list(WORDS)
    for pc, word in (overrides or {}).items():
        source[pc // 4] = word
    return source


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, (), ar)


class ExclusiveConditionalReturnTests(unittest.TestCase):
    def test_not_taken_cmn_leaves_and_failure_retries_the_load(self):
        source = words()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (
                HEAD, CMP, BNE, INC, STORE, STATUS, SUCCESS, JOIN, CLREX, ZERO, FLAG, COPY, CMN, RETRY)],
            ['ldaxr', 'cmp', 'b.ne', 'add', 'stlxr', 'cbnz', 'mov', 'b', 'clrex', 'mov', 'tbnz',
             'mov', 'cmn', 'b.ne'])
        self.assertEqual(by_pc[HEAD].op_str, 'x9, [x8]')
        self.assertEqual(by_pc[CMP].op_str, 'x9, x10')
        self.assertEqual(by_pc[BNE].operands[0].imm, CLREX)
        self.assertEqual(by_pc[INC].op_str, 'x10, x10, #1')
        self.assertEqual(by_pc[STORE].op_str, 'w11, x10, [x8]')
        self.assertEqual(by_pc[STATUS].operands[-1].imm, ZERO)
        self.assertEqual(by_pc[SUCCESS].op_str, 'w10, #1')
        self.assertEqual(by_pc[JOIN].operands[0].imm, FLAG)
        self.assertEqual(by_pc[ZERO].op_str, 'w10, wzr')
        self.assertEqual(by_pc[FLAG].op_str, 'w10, #0, #0x4c')
        self.assertEqual(by_pc[FLAG].operands[-1].imm, RET)
        self.assertEqual(by_pc[COPY].op_str, 'x10, x9')
        self.assertEqual(by_pc[CMN].op_str, 'x9, #1')
        self.assertEqual(by_pc[RETRY].operands[0].imm, HEAD)
        self.assertEqual([by_pc[pc].mnemonic for pc in (LEAVE, RET)], ['mov', 'ret'])
        self.assertEqual(by_pc[LEAVE].op_str, 'x0, xzr')
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (SUCCESS, JOIN, FLAG, RET)],
            ['mov', 'b', 'tbnz', 'ret'])
        for pc in (ZERO, FLAG, COPY, CMN, RETRY):
            self.assertFalse(ar.android_exclusive.writes_register(by_pc[pc], 8))
            self.assertNotIn(by_pc[pc].mnemonic, ar.EXCLUSIVE_LOADS | ar.EXCLUSIVE_STORES | {'clrex'})
        self.assertIsNone(ar.android_exclusive.compare_reload_retry(by_pc, by_pc[STORE], HEAD, BODY, ar))
        self.assertIsNone(ar.android_exclusive.epilogue_reload_retry(by_pc, by_pc[STORE], HEAD, BODY, ar))
        self.assertIsNone(ar.android_exclusive.compare_reload_clrex_end(by_pc, by_pc[STORE], HEAD, BODY, ar))
        self.assertTrue(ar.android_exclusive.reaches_head(by_pc, STATUS, HEAD, ar))
        tail, edges = ar.android_exclusive.retry_tail(by_pc, by_pc[STORE], HEAD, BODY, ar)
        self.assertEqual(tail, TAIL)
        self.assertEqual(edges, {(RETRY, HEAD)})
        self.assertEqual(plan(source), ())

    def test_address_write_store_branch_and_compare_entry_stay_rejected(self):
        rejected = (
            ('address', words({COPY: 0xAA0903E8}), 'unsupported/unproven exclusive retry tail'),
            ('store', words({RETRY: bne(RETRY, STORE)}), 'external entry into exclusive region interior'),
            ('compare', words({LEAVE: ar.branch(LEAVE, CMP)}), 'unsupported/unproven exclusive retry tail'),
        )
        for name, source, message in rejected:
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            with self.subTest(name=name):
                self.assertIsNone(ar.android_exclusive.conditional_return_retry(
                    by_pc, by_pc[STORE], HEAD, BODY, ar))
                with self.assertRaisesRegex(ar.RewriteError, message):
                    plan(source)


if __name__ == '__main__':
    unittest.main()
