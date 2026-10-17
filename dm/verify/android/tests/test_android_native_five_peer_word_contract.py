"""Fixed-oracle acceptance, roots, authority and shape tests for W32 closure."""
from collections import Counter
from unittest.mock import patch
import unittest

from word_fixture import (ALIEN, BODY, CLREX, CLOSURE, DEAD_B, FAILURE,
                          FAILURE_TEST, FAMILY, HEADS, LEAVE, PUBLISH, RESTORES,
                          STR, SUCCESS, SUCCESS_TEST, WITNESS, acceptance, ar,
                          branch, changed, decoded, fixture, helper, plan,
                          selected, word)


class AuthoredWordContractTests(unittest.TestCase):
    def test_existing_public_planner_accepts_word_family(self):
        accepted, detail = acceptance(entries=tuple(sorted(HEADS)))
        self.assertTrue(accepted, f'closed authored W32 five-peer family refused: {detail}')

    def test_fixed_C27_W19_H5_and_one_complete_consumption(self):
        self.assertEqual(len(CLOSURE), 27)
        self.assertEqual(len(WITNESS), 19)
        self.assertTrue(CLOSURE.isdisjoint(WITNESS))
        self.assertEqual(HEADS, {8, 32, 56, 80, 104})
        result = selected(self)
        self.assertIsNotNone(result)
        nodes, heads, witness = result
        self.assertEqual((nodes, heads, witness), (CLOSURE, HEADS, WITNESS))
        instructions, kinds = decoded()
        by_pc = {ins.address: ins for ins in instructions}
        closure = helper(self)
        for head in sorted(HEADS - {8}):
            with self.subTest(nonleader=head):
                self.assertIsNone(closure(by_pc[head], by_pc, kinds, ar))
        calls = []
        def observed(start, *args):
            calls.append(start.address)
            return closure(start, *args)
        with patch.object(ar.android_exclusive, 'native_five_peer_word_closure', observed):
            self.assertEqual(plan(entries=tuple(sorted(HEADS))), ())
        self.assertEqual(calls, [8])
        relocated = selected(self, base=0x2340)
        self.assertEqual(relocated, tuple({pc + 0x2340 for pc in group}
                                         for group in (CLOSURE, HEADS, WITNESS)))

    def test_every_head_rewrite_preserves_all_source_and_site_tables(self):
        source = fixture()
        for head in sorted(HEADS):
            with self.subTest(entry=head):
                image = ar.rewrite(source, entry_offset=head, entry_offsets=tuple(sorted(HEADS)))
                self.assertEqual(image.bytes, source)
                self.assertEqual((image.sites, image.gates, image.fixups), ((), (), ()))

    def test_every_C_and_W_metadata_root_has_explicit_authority(self):
        for target in sorted(CLOSURE | WITNESS):
            accepted, detail = acceptance(entries=(target,))
            with self.subTest(root=target):
                self.assertEqual(accepted, target in HEADS, detail)
        for target in sorted((CLOSURE | WITNESS) - HEADS):
            with self.subTest(all_heads_plus_root=target):
                accepted, detail = acceptance(entries=tuple(sorted(HEADS | {target})))
                self.assertFalse(accepted, detail)

    def test_every_C_and_W_alien_direct_entry_has_explicit_authority(self):
        # LEAVE begins a terminal success epilogue and can serve alien callers.
        # Its interior, every other witness, and non-head C words cannot.
        for target in sorted(CLOSURE | WITNESS):
            for name in ('b', 'bl', 'b.ne', 'cbnz', 'tbnz'):
                mutant = changed({ALIEN: branch(name, ALIEN, target)})
                accepted, detail = acceptance(mutant)
                with self.subTest(target=target, branch=name):
                    self.assertEqual(accepted, target in HEADS or target == LEAVE, detail)

    def test_every_C_and_W_kind_is_explicit_and_host_backed_kinds_refuse(self):
        _, defaults = decoded()
        kinds_to_test = ('missing', 'unknown', 'gate', 'parameter', 'parameter_tail',
                         'x18', 'checked_call', 'byte_jump', 'stack_check')
        for pc in sorted(CLOSURE | WITNESS):
            for value in kinds_to_test:
                kinds = dict(defaults)
                if value == 'missing':
                    kinds.pop(pc)
                else:
                    kinds[pc] = value
                accepted, detail = acceptance(kinds=kinds)
                with self.subTest(pc=pc, kind=value):
                    self.assertEqual(accepted, pc in RESTORES and value == 'stack_check', detail)

    def test_fixed_family_order_and_independent_permutation_control(self):
        instructions, _ = decoded()
        by_pc = {ins.address: ins for ins in instructions}
        pairs = tuple((by_pc[head].mnemonic, by_pc[head + 12].mnemonic)
                      for head in sorted(HEADS))
        self.assertEqual(pairs, FAMILY)
        self.assertEqual(Counter(pairs), Counter({('ldxr', 'stxr'): 1,
                                                ('ldxr', 'stlxr'): 1,
                                                ('ldaxr', 'stlxr'): 3}))
        permutation = (('ldxr', 'stlxr'), ('ldaxr', 'stlxr'), ('ldxr', 'stxr'),
                       ('ldaxr', 'stlxr'), ('ldaxr', 'stlxr'))
        changes = {}
        for head, (load, store) in zip(sorted(HEADS), permutation):
            changes[head] = (word(head) & ~0x8000) | (0x8000 if load == 'ldaxr' else 0)
            changes[head + 12] = (word(head + 12) & ~0x8000) | (0x8000 if store == 'stlxr' else 0)
        accepted, detail = acceptance(changed(changes))
        self.assertTrue(accepted, detail)

    def test_X_family_is_not_claimed_by_word_helper(self):
        replacements = {'ldaxr w9': 'ldaxr x9', 'ldxr w9': 'ldxr x9',
                        'cmp w9, w10': 'cmp x9, x10',
                        'stlxr w11, w8': 'stlxr w11, x8',
                        'stxr w11, w8': 'stxr w11, x8',
                        'str w9': 'str x9'}
        body = BODY
        for before, after in replacements.items():
            body = body.replace(before, after)
        instructions, kinds = decoded(fixture(body))
        by_pc = {ins.address: ins for ins in instructions}
        closure = helper(self)
        for head in sorted(HEADS):
            with self.subTest(x_family_start=head):
                self.assertIsNone(closure(by_pc[head], by_pc, kinds, ar))

    def test_peer_width_retry_order_and_shape_mutants_refuse(self):
        for head in sorted(HEADS):
            mutations = (
                (head, word(head) ^ 0x40000000),   # W32 -> X64
                (head, word(head) ^ 0x80000000),   # W32 -> B8
                (head, word(head) ^ 0x8000),       # exact family multiplicity
                (head + 4, word(head + 4) ^ 0x80000000),
                (head + 4, word(head + 4) | 1 << 10),
                (head + 8, branch('b.ne', head + 8, CLREX)),
                (head + 12, word(head + 12) ^ 0x40000000),
                (head + 12, word(head + 12) ^ 0x80000000),
                (head + 12, word(head + 12) ^ 0x8000),
                (head + 16, word(head + 16) ^ 0x80000000),
                (head + 16, word(head + 16) ^ 0x01000000),
                (head + 16, branch('cbnz', head + 16, head + 4)),
                (head + 16, branch('cbnz', head + 16, next(iter(HEADS - {head})))),
            )
            for pc, value in mutations:
                with self.subTest(head=head, pc=pc, value=hex(value)):
                    accepted, detail = acceptance(changed({pc: value}))
                    self.assertFalse(accepted, detail)

    def test_carrier_publication_epilogue_and_dead_edges_are_exact(self):
        mutations = {
            FAILURE: 0x52800008, CLREX: 0xD503201F,
            FAILURE_TEST: word(FAILURE_TEST) ^ 0x01000000,
            SUCCESS: word(SUCCESS) ^ 0x20,
            SUCCESS_TEST: word(SUCCESS_TEST) | 1 << 19,
            DEAD_B: branch('b', DEAD_B, LEAVE),
            PUBLISH: 0x52800000,
            STR: word(STR) ^ 0x40000000,
        }
        for pc, value in mutations.items():
            with self.subTest(pc=pc):
                accepted, detail = acceptance(changed({pc: value}))
                self.assertFalse(accepted, detail)
        for pc in (156, 160, 164, 168, 176, 180, 184, 188):
            for replacement in (0xD503201F, branch('b', pc, 8), 0xD61F0020, 0xD4200000):
                with self.subTest(epilogue=pc, replacement=hex(replacement)):
                    accepted, detail = acceptance(changed({pc: replacement}))
                    self.assertFalse(accepted, detail)
        for before, after in (
            ('str w9, [x19]', 'str w9, [x20]'),
            ('str w9, [x19]', 'str w9, [x19, #4]!'),
            ('str w9, [x19]', 'str w9, [x19], #4'),
            ('str w9, [x19]', 'str w9, [x19, x12]'),
            ('publish: mov w0, wzr', 'publish: mov w9, wzr'),
        ):
            with self.subTest(source_mutation=after):
                accepted, detail = acceptance(fixture(BODY.replace(before, after)))
                self.assertFalse(accepted, detail)


if __name__ == '__main__':
    unittest.main()
