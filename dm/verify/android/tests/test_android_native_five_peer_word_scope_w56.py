"""Ordinary all-acquire W5/W6 shared-fail compatibility controls.

Self-authored source uses two RETs between attempts, payload W13 separate from
carrier W11, and all-acquire peers. These are ordinary legacy shared-fail
programs, not the mixed-order five-peer C27/H5/W19 contract. No commercial
binary, existing frozen test source, live repository or device is an input.
"""
from functools import lru_cache
import unittest

from test_android_exclusive import assemble
from test_android_rewrite import ar


def source_listing(count):
    assert count in (5, 6)
    blocks = ['ret\nret']
    for index in range(count):
        blocks.append(f'''attempt_{index}: ldaxr w15, [x24]
cmp w15, w14
b.ne observed_mismatch
stlxr w12, w13, [x24]
cbnz w12, attempt_{index}
b observed_success
ret
ret''')
    blocks.append('''observed_success: mov w11, #1
tbz w11, #0, publish
b done
observed_mismatch: mov w11, wzr
clrex
tbnz w11, #0, done
publish: mov w0, wzr
str w15, [x28]
done: ret
ret''')
    return '\n'.join(blocks) + '\n'


@lru_cache(maxsize=None)
def fixture(count):
    return assemble(source_listing(count))


def decoded(count):
    source = fixture(count)
    instructions = tuple(ar.Instruction(ins) for ins in ar.MD.disasm(source, 0))
    if len(instructions) * 4 != len(source):
        raise AssertionError('incomplete decode of authored W5/W6 scope control')
    return instructions, {ins.address: ar.site_kind(ins) for ins in instructions}


def word_claim(count, head):
    closure = getattr(ar.android_exclusive, 'native_five_peer_word_closure', None)
    if closure is None:
        return False, 'baseline word helper is absent and makes no claim'
    instructions, kinds = decoded(count)
    by_pc = {ins.address: ins for ins in instructions}
    try:
        selected = closure(by_pc[head], by_pc, kinds, ar)
    except ar.RewriteError as error:
        return True, f'word helper claimed ordinary all-acquire W{count} and raised: {error}'
    return selected is not None, repr(selected)


class OrdinaryAcquireWordScopeTests(unittest.TestCase):
    def assert_fixed_legacy_proof(self, count):
        instructions, kinds = decoded(count)
        by_pc = {ins.address: ins for ins in instructions}
        heads = tuple(8 + 32 * index for index in range(count))
        failure, clear, test = 20 + 32 * count, 24 + 32 * count, 28 + 32 * count
        self.assertEqual(len(fixture(count)), 48 + 32 * count)
        self.assertEqual(set(by_pc), set(range(0, 48 + 32 * count, 4)))
        self.assertEqual({pc for pc, ins in by_pc.items()
                          if ins.mnemonic in ar.EXCLUSIVE_LOADS}, set(heads))
        self.assertEqual([ins.address for ins in
                          ar.android_exclusive.direct_predecessors(by_pc, failure)],
                         [head + 8 for head in heads])
        self.assertEqual([by_pc[pc].mnemonic for pc in (failure, clear, test)],
                         ['mov', 'clrex', 'tbnz'])
        self.assertEqual(by_pc[failure].op_str, 'w11, wzr')
        self.assertEqual(by_pc[test + 8].op_str, 'w15, [x28]')
        for head in heads:
            with self.subTest(count=count, head=head):
                self.assertEqual(by_pc[head].mnemonic, 'ldaxr')
                self.assertEqual(by_pc[head].op_str, 'w15, [x24]')
                self.assertEqual(by_pc[head + 4].op_str, 'w15, w14')
                self.assertEqual(by_pc[head + 12].mnemonic, 'stlxr')
                self.assertEqual(by_pc[head + 12].op_str, 'w12, w13, [x24]')
                self.assertEqual(by_pc[head + 16].operands[-1].imm, head)
                self.assertEqual([by_pc[head + offset].mnemonic for offset in (20, 24, 28)],
                                 ['b', 'ret', 'ret'])
                attempt = set(range(head, head + 20, 4)) | {failure, clear}
                self.assertTrue(ar.android_exclusive.shared_compare_fail_mov_before_clrex(
                    by_pc, clear, attempt, head, ar),
                    'ordinary all-acquire peer must satisfy the existing shared-fail proof')
        return instructions, kinds, heads

    def assert_legacy_acceptance(self, count):
        instructions, kinds, heads = self.assert_fixed_legacy_proof(count)
        error = None
        try:
            ar.android_exclusive.plan_regions(instructions, kinds, heads, ar)
        except ar.RewriteError as caught:
            error = str(caught)
        self.assertIsNone(error, f'ordinary all-acquire W{count} plan failed: {error}')
        for head in heads:
            with self.subTest(count=count, rewrite_entry=head):
                error, image = None, None
                try:
                    image = ar.rewrite(fixture(count), entry_offset=head, entry_offsets=heads)
                except ar.RewriteError as caught:
                    error = str(caught)
                self.assertIsNone(error, f'ordinary all-acquire W{count} rewrite failed: {error}')
                self.assertIsNotNone(image)
                self.assertTrue(image.bytes)

    def test_ordinary_all_acquire_W5_keeps_legacy_proof_plan_and_rewrite(self):
        self.assert_legacy_acceptance(5)

    def test_ordinary_all_acquire_W6_keeps_legacy_proof_plan_and_rewrite(self):
        self.assert_legacy_acceptance(6)

    def test_word_helper_does_not_claim_ordinary_all_acquire_W5(self):
        for head in (8, 40, 72, 104, 136):
            with self.subTest(head=head):
                chosen, detail = word_claim(5, head)
                self.assertFalse(chosen, detail)

    def test_word_helper_does_not_claim_ordinary_all_acquire_W6(self):
        for head in (8, 40, 72, 104, 136, 168):
            with self.subTest(head=head):
                chosen, detail = word_claim(6, head)
                self.assertFalse(chosen, detail)


if __name__ == '__main__':
    unittest.main()
