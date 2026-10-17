"""Halfword-specific witness kinds and whole-role alias authority negatives."""
import re
import unittest
from test_android_native_five_peer_halfword_union import BODY,HEADS,EXPECTED_WITNESS,ar,changed,decoded,fixture,plan,selected,word

class HalfwordAuthorityTests(unittest.TestCase):
    def test_all_witness_kinds_are_explicit_and_host_backed_mutations_refuse(self):
        instructions,defaults=decoded()
        by_pc={ins.address:ins for ins in instructions}
        self.assertEqual(selected()[2],EXPECTED_WITNESS)
        for pc in EXPECTED_WITNESS:
            for kind in ('missing','unknown','gate','parameter','parameter_tail','x18','checked_call','byte_jump','stack_check'):
                kinds=dict(defaults)
                if kind=='missing':kinds.pop(pc)
                else:kinds[pc]=kind
                with self.subTest(pc=pc,kind=kind):
                    if by_pc[pc].mnemonic=='ldp' and kind=='stack_check':
                        self.assertEqual(plan(kinds=kinds),())
                    else:
                        with self.assertRaises(ar.RewriteError):plan(kinds=kinds)
        kinds=dict(defaults)
        for pc in EXPECTED_WITNESS:
            if by_pc[pc].mnemonic=='ldp':kinds[pc]='stack_check'
        self.assertEqual(plan(kinds=kinds),())

    def test_whole_role_aliases_cannot_change_carrier_status_or_cell_authority(self):
        for original,replacement in (('w9','w10'),('w11','w8'),('w8','w9'),('x19','x20')):
            body=re.sub(r'\b'+original+r'\b',replacement,BODY)
            if original=='w11':
                changes={head+12:(word(head+12)&~(31<<16))|(8<<16) for head in HEADS}
                changes.update({head+16:(word(head+16)&~31)|8 for head in HEADS})
                source=changed(changes)
            elif original=='x19':
                changes={144:(word(144)&~(31<<5))|(20<<5)}
                changes.update({pc:(word(pc)&~(31<<10))|(20<<10) for pc in (148,168)})
                source=changed(changes)
            else:source=fixture(body)
            with self.subTest(original=original,replacement=replacement):
                with self.assertRaises(ar.RewriteError):plan(source)

if __name__=='__main__':unittest.main()
