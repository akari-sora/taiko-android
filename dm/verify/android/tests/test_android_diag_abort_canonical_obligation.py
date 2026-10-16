"""The immutable source CFG alone owns the necessity proof."""
import unittest
from unittest.mock import patch
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[4]/'dm/tools'))
import android_diag_abort as diag
import android_import as importer
from nso_format import parse_nso,parse_metadata
from test_android_diag_abort_publication import public_nso,imported,pin,taiko_verify,stripped

class CanonicalObligationTests(unittest.TestCase):
    def test_real_canonical_roles_select_the_consumed_head_and_only_required_calls(self):
        for mode,calls,heads in [('used',[(0x180,0x20c)],{0x100}),('clrex',[],set()),('fresh-load',[],set())]:
            nso=parse_nso(public_nso(mode));metadata=parse_metadata(nso)
            original=importer.discover_code
            with self.subTest(mode=mode),patch.object(importer,'discover_code',wraps=original) as discover:
                proof,actual_heads=diag.publication_contract_obligation(nso,metadata)
                self.assertEqual(list(proof.calls),calls)
                self.assertEqual(actual_heads,heads)
                discover.assert_called_once_with(nso,metadata,indirect_policy='guarded-host',checked_stack=True)

    def test_unknown_canonical_discovery_refuses_instead_of_treating_absent_claims_as_optional(self):
        source=public_nso('used');package,report=imported(source);bad,r=stripped(package,report)
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            with self.subTest(generator=name),patch.object(importer,'discover_code',side_effect=importer.ImportError('unproved source CFG')):
                with self.assertRaisesRegex(ValueError,'canonical source discovery failed'):verify(source,bad,r)

if __name__=='__main__':unittest.main(verbosity=2)
