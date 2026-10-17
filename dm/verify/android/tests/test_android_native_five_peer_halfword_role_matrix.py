"""All ordered physical-GPR role collisions in an authored halfword closure.

Every mutant starts from the original fixture. Only explicitly mapped five-bit
GPR fields change; no instruction is assembled from an aliasing source spelling.
This suite does not consult the candidate's selected() ownership result.
"""
from itertools import permutations
import unittest

from test_android_native_five_peer_halfword_union import HEADS, ar, changed, decoded, fixture, plan, word


ROLES = {
    'loaded': 9,
    'expected': 10,
    'desired_carrier': 8,
    'status': 11,
    'cell': 20,
    'output': 19,
}
EXPECTED_HEADS = {0, 24, 48, 72, 96}
SCRATCH_ROLES = {'loaded', 'expected', 'desired_carrier', 'status'}
ADDRESS_ROLES = {'cell', 'output'}

# (PC, register-field shift) -> original architectural GPR number. Branch
# displacements, bit-test immediates, MOV immediates, and LDP offsets are absent.
# CMP and register-MOV include their implicit zero-register encoding fields so
# assertions also prove these constant register fields remain unchanged.
REGISTER_FIELDS = {}
EXPECTED_MNEMONICS = {}
for _head in sorted(EXPECTED_HEADS):
    REGISTER_FIELDS.update({
        (_head, 0): 9, (_head, 5): 20,
        (_head + 4, 0): 31, (_head + 4, 5): 9, (_head + 4, 16): 10,
        (_head + 12, 0): 8, (_head + 12, 5): 20, (_head + 12, 16): 11,
        (_head + 16, 0): 11,
    })
    EXPECTED_MNEMONICS.update({
        _head: {'ldxrh', 'ldaxrh'}, _head + 4: {'cmp'},
        _head + 8: {'b.ne'}, _head + 12: {'stxrh', 'stlxrh'},
        _head + 16: {'cbnz'},
    })
    if _head != 96:
        EXPECTED_MNEMONICS[_head + 20] = {'b'}

REGISTER_FIELDS.update({
    (116, 0): 8,                         # success MOV W8,#1
    (120, 0): 8,                         # success TBNZ W8,#0,leave
    (128, 0): 8, (128, 5): 31, (128, 16): 31,  # failure MOV W8,WZR
    (136, 0): 8,                         # failure TBNZ W8,#0,leave
    (140, 0): 0, (140, 5): 31, (140, 16): 31,  # publish MOV W0,WZR
    (144, 0): 9, (144, 5): 19,           # STRH W9,[X19]
    (164, 0): 0,                         # success return MOV W0,#1
})
EXPECTED_MNEMONICS.update({
    116: {'mov'}, 120: {'tbnz'}, 124: {'b'},
    128: {'mov'}, 132: {'clrex'}, 136: {'tbnz'}, 140: {'mov'},
    144: {'strh'}, 164: {'mov'},
})
for _pc in (148, 168):
    REGISTER_FIELDS.update({(_pc, 0): 20, (_pc, 5): 31, (_pc, 10): 19})
    EXPECTED_MNEMONICS[_pc] = {'ldp'}
for _pc in (152, 172):
    REGISTER_FIELDS.update({(_pc, 0): 22, (_pc, 5): 31, (_pc, 10): 21})
    EXPECTED_MNEMONICS[_pc] = {'ldp'}
for _pc in (156, 176):
    REGISTER_FIELDS.update({(_pc, 0): 30, (_pc, 5): 31, (_pc, 10): 23})
    EXPECTED_MNEMONICS[_pc] = {'ldp'}
for _pc in (160, 180, 184, 188):
    REGISTER_FIELDS[(_pc, 5)] = 30
    EXPECTED_MNEMONICS[_pc] = {'ret'}

# Independently enumerate each role's required sites, including both restore
# copies. These sets check that a mutation is consistent throughout the family.
ROLE_SITES = {
    'loaded': ({(head, 0) for head in EXPECTED_HEADS} |
               {(head + 4, 5) for head in EXPECTED_HEADS} | {(144, 0)}),
    'expected': {(head + 4, 16) for head in EXPECTED_HEADS},
    'desired_carrier': ({(head + 12, 0) for head in EXPECTED_HEADS} |
                        {(116, 0), (120, 0), (128, 0), (136, 0)}),
    'status': ({(head + 12, 16) for head in EXPECTED_HEADS} |
               {(head + 16, 0) for head in EXPECTED_HEADS}),
    'cell': ({(head, 5) for head in EXPECTED_HEADS} |
             {(head + 12, 5) for head in EXPECTED_HEADS} | {(148, 0), (168, 0)}),
    'output': {(144, 5), (148, 10), (168, 10)},
}
ROLE_SITE_COUNTS = {
    'loaded': 11, 'expected': 5, 'desired_carrier': 9,
    'status': 10, 'cell': 12, 'output': 3,
}


def register_field(source, site):
    pc, shift = site
    return (word(pc, source) >> shift) & 31


class HalfwordPhysicalRoleMatrixTests(unittest.TestCase):
    def assert_original_field_map(self, original):
        self.assertEqual(set(HEADS), EXPECTED_HEADS)
        instructions, _ = decoded(original)
        by_pc = {ins.address: ins for ins in instructions}
        self.assertEqual(len(original), 192)
        self.assertEqual(set(by_pc), set(range(0, 192, 4)))
        self.assertEqual(set(EXPECTED_MNEMONICS), set(by_pc))
        for pc, names in EXPECTED_MNEMONICS.items():
            self.assertIn(by_pc[pc].mnemonic, names, f'authored instruction 0x{pc:x}')
        self.assertEqual(len(REGISTER_FIELDS), 79)
        self.assertEqual(sum(ROLE_SITE_COUNTS.values()), 50)
        all_role_sites = set()
        for role, number in ROLES.items():
            sites = ROLE_SITES[role]
            self.assertEqual(len(sites), ROLE_SITE_COUNTS[role], role)
            self.assertEqual(sites, {site for site, value in REGISTER_FIELDS.items()
                                     if value == number}, role)
            self.assertTrue(all_role_sites.isdisjoint(sites), role)
            all_role_sites.update(sites)
        for site, number in REGISTER_FIELDS.items():
            self.assertEqual(register_field(original, site), number, site)
        # Explicit W/X witnesses prevent a textual register-name replacement
        # from being mistaken for a complete architectural-number mutation.
        self.assertEqual(by_pc[0].reg_name(by_pc[0].operands[0].reg), 'w9')
        self.assertEqual(by_pc[148].reg_name(by_pc[148].operands[0].reg), 'x20')
        self.assertEqual(by_pc[148].reg_name(by_pc[148].operands[1].reg), 'x19')

    def collision(self, original, source_role, target_role):
        source_number, target_number = ROLES[source_role], ROLES[target_role]
        self.assertNotEqual(source_number, target_number)
        changes, permitted_masks = {}, {}
        for pc, shift in ROLE_SITES[source_role]:
            self.assertEqual(register_field(original, (pc, shift)), source_number)
            mask = 31 << shift
            changes[pc] = ((changes.get(pc, word(pc, original)) & ~mask) |
                           (target_number << shift))
            permitted_masks[pc] = permitted_masks.get(pc, 0) | mask
        mutant = changed(changes, original)
        self.assertIsInstance(original, bytes)
        self.assertEqual(fixture(), original)
        self.assertNotEqual(mutant, original)
        # Every source-role occurrence now aliases the target role. Every
        # original target site, all other roles, and constant GPR fields retain
        # their values. Thus no peer/witness mismatch can explain the refusal.
        for role, sites in ROLE_SITES.items():
            expected = target_number if role == source_role else ROLES[role]
            for site in sites:
                self.assertEqual(register_field(mutant, site), expected,
                                 (source_role, target_role, role, site))
        for site, number in REGISTER_FIELDS.items():
            expected = target_number if number == source_number else number
            self.assertEqual(register_field(mutant, site), expected, site)
        collided_sites = ROLE_SITES[source_role] | ROLE_SITES[target_role]
        self.assertEqual({register_field(mutant, site) for site in collided_sites},
                         {target_number})
        self.assertEqual({register_field(mutant, site) for site in ROLE_SITES[source_role]},
                         {register_field(mutant, site) for site in ROLE_SITES[target_role]})
        for pc in range(0, len(original), 4):
            before, after = word(pc, original), word(pc, mutant)
            mask = permitted_masks.get(pc, 0)
            self.assertEqual(after & ~mask, before & ~mask, f'unrelated bits at 0x{pc:x}')
            self.assertEqual(after != before, pc in permitted_masks,
                             f'exact changed instruction set at 0x{pc:x}')
        return mutant

    def test_original_fixture_roles_and_native_control(self):
        original = fixture()
        self.assert_original_field_map(original)
        self.assertEqual(plan(original, entries=tuple(sorted(HEADS))), ())

    def test_all_thirty_ordered_physical_role_collisions_refuse(self):
        original = fixture()
        self.assert_original_field_map(original)
        self.assertEqual(plan(original, entries=tuple(sorted(HEADS))), ())
        pairs = tuple(permutations(ROLES, 2))
        self.assertEqual(len(pairs), 30)
        self.assertEqual(len(set(pairs)), 30)
        cross_width = {(source, target) for source, target in pairs
                       if ((source in SCRATCH_ROLES and target in ADDRESS_ROLES) or
                           (source in ADDRESS_ROLES and target in SCRATCH_ROLES))}
        self.assertEqual(len(cross_width), 16)
        self.assertTrue({('status', 'loaded'), ('loaded', 'status'),
                         ('status', 'expected'), ('expected', 'status'),
                         ('desired_carrier', 'expected'), ('expected', 'desired_carrier')} <= set(pairs))
        observed = set()
        for source_role, target_role in pairs:
            with self.subTest(source=source_role, target=target_role,
                              source_gpr=ROLES[source_role], target_gpr=ROLES[target_role]):
                mutant = self.collision(original, source_role, target_role)
                with self.assertRaises(ar.RewriteError):
                    plan(mutant, entries=tuple(sorted(HEADS)))
                observed.add((source_role, target_role))
        self.assertEqual(observed, set(pairs))


if __name__ == '__main__':
    unittest.main()
