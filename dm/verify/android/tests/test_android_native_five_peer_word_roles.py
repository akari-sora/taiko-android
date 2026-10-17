"""Complete six-role physical GPR collision matrix from fixed source fields."""
from itertools import permutations
import unittest

from word_fixture import HEADS, acceptance, ar, changed, decoded, fixture, word


ROLES = {'loaded': 9, 'expected': 10, 'desired': 8, 'status': 11,
         'cell': 20, 'output': 19}
SCRATCH = ('loaded', 'expected', 'desired', 'status')
SAVED_ADDRESS = frozenset((19, 20, 24, 25, 26, 27, 28))
ROLE_SITES = {
    'loaded': frozenset(((8, 0), (12, 5), (32, 0), (36, 5), (56, 0),
                         (60, 5), (80, 0), (84, 5), (104, 0), (108, 5), (152, 0))),
    'expected': frozenset(((12, 16), (36, 16), (60, 16), (84, 16), (108, 16))),
    'desired': frozenset(((20, 0), (44, 0), (68, 0), (92, 0), (116, 0),
                          (124, 0), (128, 0), (136, 0), (144, 0))),
    'status': frozenset(((20, 16), (24, 0), (44, 16), (48, 0), (68, 16),
                         (72, 0), (92, 16), (96, 0), (116, 16), (120, 0))),
    'cell': frozenset(((8, 5), (20, 5), (32, 5), (44, 5), (56, 5), (68, 5),
                       (80, 5), (92, 5), (104, 5), (116, 5), (156, 0), (176, 0))),
    'output': frozenset(((152, 5), (156, 10), (176, 10))),
}
SITE_COUNTS = {'loaded': 11, 'expected': 5, 'desired': 9, 'status': 10,
               'cell': 12, 'output': 3}
ADDRESS_COLLISIONS = frozenset((('cell', 'output'), ('output', 'cell')))
ADDRESS_RESTORE_PCS = frozenset((156, 176))

# Also pin non-role register fields, including implicit WZR/SP and RET X30.
FIXED_FIELDS = {
    (0, 5): 30, (4, 5): 30, (192, 5): 30, (196, 5): 30,
    (136, 5): 31, (136, 16): 31,
    (148, 0): 0, (148, 5): 31, (148, 16): 31, (172, 0): 0,
    (156, 5): 31, (176, 5): 31,
    (160, 0): 22, (160, 10): 21, (160, 5): 31,
    (180, 0): 22, (180, 10): 21, (180, 5): 31,
    (164, 0): 30, (164, 10): 23, (164, 5): 31,
    (184, 0): 30, (184, 10): 23, (184, 5): 31,
    (168, 5): 30, (188, 5): 30,
    (12, 0): 31, (36, 0): 31, (60, 0): 31, (84, 0): 31, (108, 0): 31,
}


def field(source, site):
    pc, shift = site
    return word(pc, source) >> shift & 31


def rename(source, role, number):
    changes, masks = {}, {}
    for pc, shift in ROLE_SITES[role]:
        mask = 31 << shift
        changes[pc] = (changes.get(pc, word(pc, source)) & ~mask) | number << shift
        masks[pc] = masks.get(pc, 0) | mask
    return changed(changes, source), masks


class WordPhysicalRoleTests(unittest.TestCase):
    def assert_fixture_map(self, source):
        self.assertEqual(len(source), 200)
        self.assertEqual(HEADS, {8, 32, 56, 80, 104})
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(set(by_pc), set(range(0, 200, 4)))
        occupied = set(FIXED_FIELDS)
        self.assertEqual(len(FIXED_FIELDS), 31)
        for role, sites in ROLE_SITES.items():
            self.assertEqual(len(sites), SITE_COUNTS[role])
            self.assertTrue(occupied.isdisjoint(sites))
            occupied.update(sites)
            for site in sites:
                self.assertEqual(field(source, site), ROLES[role], (role, site))
        for site, number in FIXED_FIELDS.items():
            self.assertEqual(field(source, site), number, site)
        self.assertEqual(sum(SITE_COUNTS.values()), 50)
        self.assertEqual(len(occupied), 81)
        self.assertEqual(by_pc[8].reg_name(by_pc[8].operands[0].reg), 'w9')
        self.assertEqual(by_pc[156].reg_name(by_pc[156].operands[0].reg), 'x20')
        self.assertEqual(by_pc[156].reg_name(by_pc[156].operands[1].reg), 'x19')

    def test_fixed_field_map_is_independent_of_matcher(self):
        self.assert_fixture_map(fixture())

    def assert_consistent_collision(self, source, before, after):
        """Prove a whole-role mutation before examining any refusal outcome."""
        mutant, masks = rename(source, before, ROLES[after])
        for role, sites in ROLE_SITES.items():
            expected = ROLES[after] if role == before else ROLES[role]
            for site in sites:
                self.assertEqual(field(mutant, site), expected, (role, site))
        for site, number in FIXED_FIELDS.items():
            self.assertEqual(field(mutant, site), number, site)
        self.assertEqual({field(mutant, site) for site in ROLE_SITES[before] |
                          ROLE_SITES[after]}, {ROLES[after]})
        for pc in range(0, len(source), 4):
            self.assertEqual(word(pc, mutant) & ~masks.get(pc, 0),
                             word(pc, source) & ~masks.get(pc, 0))
            self.assertEqual(word(pc, mutant) != word(pc, source), pc in masks)
        self.assertEqual(fixture(), source, 'the frozen source must not be mutated')
        return mutant

    def test_twenty_eight_matcher_refusals_keep_all_thirty_field_proofs(self):
        source = fixture()
        self.assert_fixture_map(source)
        pairs = tuple(permutations(ROLES, 2))
        self.assertEqual(len(pairs), 30)
        self.assertEqual(sum((a in SCRATCH) != (b in SCRATCH) for a, b in pairs), 16)
        matcher_cases, decoder_cases = set(), set()
        for before, after in pairs:
            with self.subTest(source_role=before, target_role=after):
                mutant = self.assert_consistent_collision(source, before, after)
                if (before, after) in ADDRESS_COLLISIONS:
                    # The separate test below proves the exact duplicate-Rt
                    # LDP decode refusal. These are not matcher-pass claims.
                    decoder_cases.add((before, after))
                    continue
                for pc in range(0, len(source), 4):
                    instruction = tuple(ar.MD.disasm(mutant[pc:pc + 4], pc))
                    self.assertEqual(len(instruction), 1, f'word at 0x{pc:x} must decode')
                    self.assertEqual(len(instruction[0].bytes), 4)
                accepted, detail = acceptance(mutant, entries=tuple(sorted(HEADS)))
                self.assertFalse(accepted, detail)
                matcher_cases.add((before, after))
        self.assertEqual(decoder_cases, ADDRESS_COLLISIONS)
        self.assertEqual(matcher_cases, set(pairs) - ADDRESS_COLLISIONS)
        self.assertEqual((len(matcher_cases), len(decoder_cases)), (28, 2))

    def test_two_address_collisions_have_exact_duplicate_LDP_decode_refusals(self):
        """Pin decoder-boundary evidence; never catch bulk-decode assertions."""
        source = fixture()
        self.assert_fixture_map(source)
        for before, after in sorted(ADDRESS_COLLISIONS):
            with self.subTest(source_role=before, target_role=after):
                mutant = self.assert_consistent_collision(source, before, after)
                duplicate = ROLES[after]
                register_mask = 31 | (31 << 10)
                for pc in sorted(ADDRESS_RESTORE_PCS):
                    encoded = word(pc, mutant)
                    # Exact 64-bit offset LDP, SP base, +32 displacement;
                    # only Rt/Rt2 are permitted to differ from the original.
                    self.assertEqual(encoded & ~register_mask,
                                     0xA9400000 | (4 << 15) | (31 << 5))
                    self.assertEqual(encoded & 31, duplicate)
                    self.assertEqual((encoded >> 10) & 31, duplicate)
                    self.assertEqual((encoded >> 5) & 31, 31)
                    self.assertEqual(((encoded >> 15) & 0x7f) * 8, 32)
                    self.assertEqual(tuple(ar.MD.disasm(mutant[pc:pc + 4], pc)), (),
                                     f'duplicate Rt/Rt2 X{duplicate} at 0x{pc:x}')
                refused, complete = set(), set()
                for pc in range(0, len(mutant), 4):
                    instruction = tuple(ar.MD.disasm(mutant[pc:pc + 4], pc))
                    if not instruction:
                        refused.add(pc)
                    else:
                        self.assertEqual(len(instruction), 1)
                        self.assertEqual(instruction[0].address, pc)
                        self.assertEqual(len(instruction[0].bytes), 4)
                        complete.add(pc)
                self.assertEqual(refused, ADDRESS_RESTORE_PCS)
                self.assertEqual(complete, set(range(0, 200, 4)) - ADDRESS_RESTORE_PCS)
                self.assertEqual((len(refused), len(complete)), (2, 48))

    def test_scratch_and_saved_address_domains_have_positive_controls(self):
        source = fixture()
        for role in SCRATCH:
            available = set(range(1, 18)) - {value for key, value in ROLES.items() if key != role}
            for number in sorted(available):
                with self.subTest(role=role, legal_gpr=number):
                    mutant, _ = rename(source, role, number)
                    accepted, detail = acceptance(mutant)
                    self.assertTrue(accepted, detail)
        for role in ('cell', 'output'):
            available = SAVED_ADDRESS - {value for key, value in ROLES.items() if key != role}
            for number in sorted(available):
                with self.subTest(role=role, legal_gpr=number):
                    mutant, _ = rename(source, role, number)
                    accepted, detail = acceptance(mutant)
                    self.assertTrue(accepted, detail)

    def test_zero_x18_and_unsupported_domains_refuse_in_each_role(self):
        source = fixture()
        for role in ROLES:
            forbidden = (0, 18, 19, 20, 30, 31) if role in SCRATCH else (0, 1, 17, 18, 21, 22, 23, 29, 30, 31)
            for number in forbidden:
                with self.subTest(role=role, forbidden_gpr=number):
                    mutant, _ = rename(source, role, number)
                    accepted, detail = acceptance(mutant)
                    self.assertFalse(accepted, detail)


if __name__ == '__main__':
    unittest.main()
