"""Ordinary W4 shared-fail control outside the five-peer claim boundary.

This is independently authored assembly, with separate payload/carrier roles,
four all-acquire peers separated by RET padding, and TBZ success continuation.
The baseline's smaller shared-fail proof accepts this program. No commercial
bytes, live repository, device, or prior frozen test source is an input.
"""
from functools import lru_cache
import unittest

from test_android_exclusive import assemble
from test_android_rewrite import ar


BODY = """ret
alpha: ldaxr w5, [x26]
cmp w5, w7
b.ne mismatch
stlxr w3, w4, [x26]
cbnz w3, alpha
b stored
ret
beta: ldaxr w5, [x26]
cmp w5, w7
b.ne mismatch
stlxr w3, w4, [x26]
cbnz w3, beta
b stored
ret
gamma: ldaxr w5, [x26]
cmp w5, w7
b.ne mismatch
stlxr w3, w4, [x26]
cbnz w3, gamma
b stored
ret
delta: ldaxr w5, [x26]
cmp w5, w7
b.ne mismatch
stlxr w3, w4, [x26]
cbnz w3, delta
b stored
ret
stored: mov w6, #1
tbz w6, #0, publish
b done
mismatch: mov w6, wzr
clrex
tbnz w6, #0, done
publish: mov w0, wzr
str w5, [x27]
done: ret
ret
"""

HEADS = (4, 32, 60, 88)
FAILURE, CLREX, FAILURE_TEST = 128, 132, 136


@lru_cache(maxsize=None)
def fixture():
    return assemble(BODY)


def decoded():
    source = fixture()
    instructions = tuple(ar.Instruction(ins) for ins in ar.MD.disasm(source, 0))
    if len(instructions) * 4 != len(source):
        raise AssertionError('incomplete decode of authored W4 scope fixture')
    return instructions, {ins.address: ar.site_kind(ins) for ins in instructions}


def word_claim(head):
    closure = getattr(ar.android_exclusive, 'native_five_peer_word_closure', None)
    if closure is None:
        return False, 'baseline word helper is absent and makes no claim'
    instructions, kinds = decoded()
    by_pc = {ins.address: ins for ins in instructions}
    try:
        result = closure(by_pc[head], by_pc, kinds, ar)
    except ar.RewriteError as error:
        return True, f'word helper claimed an ordinary four-peer program and raised: {error}'
    return result is not None, repr(result)


class OrdinaryFourPeerWordScopeTests(unittest.TestCase):
    def test_fixed_W4_layout_and_smaller_shared_fail_proof(self):
        instructions, kinds = decoded()
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(len(fixture()), 156)
        self.assertEqual(set(by_pc), set(range(0, 156, 4)))
        self.assertEqual({pc for pc, ins in by_pc.items()
                          if ins.mnemonic in ar.EXCLUSIVE_LOADS}, set(HEADS))
        self.assertEqual({pc for pc, ins in by_pc.items()
                          if ins.mnemonic in ar.EXCLUSIVE_STORES},
                         {head + 12 for head in HEADS})
        self.assertEqual([ins.address for ins in
                          ar.android_exclusive.direct_predecessors(by_pc, FAILURE)],
                         [12, 40, 68, 96])
        self.assertEqual([by_pc[pc].mnemonic for pc in (116, 120, 124, 128, 132, 136, 140, 144, 148)],
                         ['mov', 'tbz', 'b', 'mov', 'clrex', 'tbnz', 'mov', 'str', 'ret'])
        self.assertEqual(by_pc[120].operands[-1].imm, 140)
        self.assertEqual(by_pc[136].operands[-1].imm, 148)
        self.assertEqual(by_pc[144].op_str, 'w5, [x27]')
        for head in HEADS:
            with self.subTest(head=head):
                self.assertEqual(by_pc[head].op_str, 'w5, [x26]')
                self.assertEqual(by_pc[head].mnemonic, 'ldaxr')
                self.assertEqual(by_pc[head + 12].op_str, 'w3, w4, [x26]')
                self.assertEqual(by_pc[head + 12].mnemonic, 'stlxr')
                self.assertEqual(by_pc[head + 24].mnemonic, 'ret')
                attempt = set(range(head, head + 20, 4)) | {FAILURE, CLREX}
                self.assertTrue(ar.android_exclusive.shared_compare_fail_mov_before_clrex(
                    by_pc, CLREX, attempt, head, ar),
                    'each peer must satisfy the existing smaller native shared-fail proof')

    def test_legacy_planner_accepts_ordinary_four_peer_program(self):
        instructions, kinds = decoded()
        error = None
        try:
            ar.android_exclusive.plan_regions(instructions, kinds, HEADS, ar)
        except ar.RewriteError as caught:
            error = str(caught)
        self.assertIsNone(error, f'ordinary W4 legacy planning failed: {error}')

    def test_legacy_rewriter_accepts_each_four_peer_entry(self):
        for head in HEADS:
            with self.subTest(head=head):
                error, image = None, None
                try:
                    image = ar.rewrite(fixture(), entry_offset=head, entry_offsets=HEADS)
                except ar.RewriteError as caught:
                    error = str(caught)
                self.assertIsNone(error, f'ordinary W4 legacy rewrite failed: {error}')
                self.assertIsNotNone(image)
                self.assertTrue(image.bytes)

    def test_word_helper_does_not_claim_any_ordinary_four_peer_head(self):
        for head in HEADS:
            with self.subTest(head=head):
                chosen, detail = word_claim(head)
                self.assertFalse(chosen, detail)


if __name__ == '__main__':
    unittest.main()
