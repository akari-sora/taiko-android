"""Independent small-family controls for the five-peer word claim boundary.

These fixtures are authored assembly, with unrelated registers and coordinates.
The single peer deliberately combines an immediate CMP, MOV-one/TBZ success,
and MOV-zero/CLREX/TBNZ mismatch. Ordinary legacy planning may create a generic
exclusive region; this suite does not require an empty plan or unchanged bytes.
An absent word helper means no claim on the baseline, with no skipped test.
Feature existence is established by the separate five-peer contract suite.
"""
from functools import lru_cache
import unittest

from test_android_exclusive import assemble
from test_android_rewrite import ar
from capstone.arm64_const import ARM64_OP_IMM


SINGLE = """ret
attempt: ldxr w12, [x24]
cmp w12, #7
b.ne mismatch
stlxr w13, wzr, [x24]
cbnz w13, attempt
mov w14, #1
tbz w14, #0, publish
b done
mismatch: mov w14, wzr
clrex
tbnz w14, #0, done
publish: mov w0, #3
str w12, [x25]
done: ret
ret
"""

# This independent two-head program is accepted by the existing
# native_shared_clear contract: state two is cleared, then state zero receives
# the payload; a shared CLREX/LDAR continuation returns to the fresh second load.
TWO_ACQUIRE = """wait: ret
classify: ret
ret
first: ldaxr w9, [x20]
cmp w9, #2
b.ne clear
stlxr w9, wzr, [x20]
cbnz w9, first
b success
second: ldaxr w9, [x20]
cbnz w9, clear
stlxr w9, w8, [x20]
cbnz w9, second
b wait
clear: clrex
ldar w9, [x20]
cbnz w9, classify
b second
ret
success: ret
"""


def shared_acquire_source(count):
    """Authored W2/W3 CAS peers with a legacy shared compare-fail exit."""
    assert count in (2, 3)
    parts = ['ret']
    for index in range(count):
        parts.append(f'''peer{index}: ldaxr w12, [x24]
cmp w12, w15
b.ne mismatch
stlxr w13, w16, [x24]
cbnz w13, peer{index}
b success''')
    parts.append('''success: mov w14, #1
tbz w14, #0, publish
b done
mismatch: mov w14, wzr
clrex
tbnz w14, #0, done
publish: mov w0, wzr
str w12, [x25]
done: ret
ret''')
    return '\n'.join(parts) + '\n'


@lru_cache(maxsize=None)
def fixture(body):
    return assemble(body)


def decoded(body):
    source = fixture(body)
    instructions = tuple(ar.Instruction(ins) for ins in ar.MD.disasm(source, 0))
    if len(instructions) * 4 != len(source):
        raise AssertionError('incomplete decode of authored scope control')
    return source, instructions, {ins.address: ar.site_kind(ins) for ins in instructions}


def planner_acceptance(body, heads):
    _, instructions, kinds = decoded(body)
    try:
        regions = ar.android_exclusive.plan_regions(instructions, kinds, heads, ar)
    except ar.RewriteError as error:
        return False, str(error)
    return True, repr(regions)


def rewrite_acceptance(body, head, heads):
    source = fixture(body)
    try:
        image = ar.rewrite(source, entry_offset=head, entry_offsets=heads)
    except ar.RewriteError as error:
        return False, str(error)
    return bool(image.bytes), f'{len(image.bytes)} rewritten bytes, {len(image.sites)} sites'


def word_claim(body, head):
    """Treat refusal exceptions as a claim error, never an unittest ERROR."""
    closure = getattr(ar.android_exclusive, 'native_five_peer_word_closure', None)
    if closure is None:
        return False, 'baseline has no word helper and therefore makes no claim'
    _, instructions, kinds = decoded(body)
    by_pc = {ins.address: ins for ins in instructions}
    try:
        result = closure(by_pc[head], by_pc, kinds, ar)
    except ar.RewriteError as error:
        return True, f'word helper claimed an ordinary smaller family and raised: {error}'
    return result is not None, repr(result)


class WordClaimScopeTests(unittest.TestCase):
    def test_single_peer_fixed_shape_and_immediate_compare_control(self):
        source, instructions, _ = decoded(SINGLE)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(len(source), 64)
        self.assertEqual({pc for pc, ins in by_pc.items()
                          if ins.mnemonic in ar.EXCLUSIVE_LOADS}, {4})
        self.assertEqual([by_pc[pc].mnemonic for pc in (4, 8, 12, 16, 20, 24, 28,
                                                       32, 36, 40, 44, 48, 52, 56)],
                         ['ldxr', 'cmp', 'b.ne', 'stlxr', 'cbnz', 'mov', 'tbz',
                          'b', 'mov', 'clrex', 'tbnz', 'mov', 'str', 'ret'])
        self.assertEqual(by_pc[8].operands[1].type, ARM64_OP_IMM)
        self.assertEqual(by_pc[8].operands[1].imm, 7)
        self.assertEqual(by_pc[12].operands[-1].imm, 36)
        self.assertEqual(by_pc[28].operands[-1].imm, 48)
        self.assertEqual(by_pc[44].operands[-1].imm, 56)
        predecessors = ar.android_exclusive.direct_predecessors(by_pc, 36)
        self.assertEqual([ins.address for ins in predecessors], [12])

    def test_single_peer_legacy_planner_and_rewriter_accept(self):
        accepted, detail = planner_acceptance(SINGLE, (4,))
        self.assertTrue(accepted, f'ordinary authored single peer must remain supported: {detail}')
        rewritten, detail = rewrite_acceptance(SINGLE, 4, (4,))
        self.assertTrue(rewritten, f'ordinary authored single peer rewrite failed: {detail}')

    def test_word_helper_does_not_claim_single_plain_peer(self):
        chosen, detail = word_claim(SINGLE, 4)
        self.assertFalse(chosen, detail)

    def test_two_acquire_legacy_native_shared_clear_remains_supported(self):
        source, instructions, kinds = decoded(TWO_ACQUIRE)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(len(source), 80)
        self.assertEqual({pc for pc, ins in by_pc.items()
                          if ins.mnemonic in ar.EXCLUSIVE_LOADS}, {12, 36})
        selected = ar.android_exclusive.native_shared_clear(by_pc[12], by_pc, kinds, ar)
        self.assertIsNotNone(selected, 'fixture must exercise the existing smaller native helper')
        self.assertEqual(selected, (set(range(12, 72, 4)), {12, 36}))
        # The smaller legacy native contract permits only its first head as a
        # metadata root, even though it internally consumes both fresh loads.
        accepted, detail = planner_acceptance(TWO_ACQUIRE, (12,))
        self.assertTrue(accepted, detail)
        rewritten, detail = rewrite_acceptance(TWO_ACQUIRE, 12, (12,))
        self.assertTrue(rewritten, detail)

    def test_word_helper_does_not_claim_two_acquire_native_heads(self):
        for head in (12, 36):
            with self.subTest(head=head):
                chosen, detail = word_claim(TWO_ACQUIRE, head)
                self.assertFalse(chosen, detail)

    def assert_shared_acquire_legacy_control(self, count):
        body = shared_acquire_source(count)
        source, instructions, kinds = decoded(body)
        by_pc = {ins.address: ins for ins in instructions}
        heads = tuple(4 + 24 * index for index in range(count))
        mismatch = 16 + 24 * count
        clear, test = mismatch + 4, mismatch + 8
        self.assertEqual(len(source), 44 + 24 * count)
        self.assertEqual({pc for pc, ins in by_pc.items()
                          if ins.mnemonic in ar.EXCLUSIVE_LOADS}, set(heads))
        self.assertEqual([ins.address for ins in
                          ar.android_exclusive.direct_predecessors(by_pc, mismatch)],
                         [head + 8 for head in heads])
        self.assertEqual([by_pc[pc].mnemonic for pc in (mismatch, clear, test)],
                         ['mov', 'clrex', 'tbnz'])
        for head in heads:
            self.assertEqual(by_pc[head].mnemonic, 'ldaxr')
            self.assertEqual(by_pc[head].reg_name(by_pc[head].operands[0].reg), 'w12')
            attempt = set(range(head, head + 20, 4)) | {mismatch, clear}
            self.assertTrue(ar.android_exclusive.shared_compare_fail_mov_before_clrex(
                by_pc, clear, attempt, head, ar),
                'fixture must exercise the existing smaller shared-fail proof')
        accepted, detail = planner_acceptance(body, heads)
        self.assertTrue(accepted, detail)
        for head in heads:
            with self.subTest(entry=head):
                rewritten, detail = rewrite_acceptance(body, head, heads)
                self.assertTrue(rewritten, detail)

    def test_two_acquire_shared_fail_peers_keep_legacy_acceptance(self):
        self.assert_shared_acquire_legacy_control(2)

    def test_three_acquire_shared_fail_peers_keep_legacy_acceptance(self):
        self.assert_shared_acquire_legacy_control(3)

    def test_word_helper_does_not_claim_two_acquire_shared_fail_peers(self):
        body = shared_acquire_source(2)
        for head in (4, 28):
            with self.subTest(head=head):
                chosen, detail = word_claim(body, head)
                self.assertFalse(chosen, detail)

    def test_word_helper_does_not_claim_three_acquire_shared_fail_peers(self):
        body = shared_acquire_source(3)
        for head in (4, 28, 52):
            with self.subTest(head=head):
                chosen, detail = word_claim(body, head)
                self.assertFalse(chosen, detail)


if __name__ == '__main__':
    unittest.main()
