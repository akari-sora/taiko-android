"""Publication must never erase an incomplete canonical source proof."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "dm/tools"))

import android_diag_abort as diag
import android_rewrite as ar
from nso_format import parse_nso, parse_metadata
from test_nso_format import write_image
from test_android_diag_abort_contract import (
    ABORT, PLT, SYMBOL, public_nso, selected_source,
)


def uncovered_source(*, no_call):
    source = bytearray(public_nso("clrex"))
    original = parse_nso(source).image
    write_image(source, 0x300, "<4I", *struct.unpack_from("<4I", original, PLT))
    if no_call:
        write_image(source, ABORT + 4, "<I", ar.branch(ABORT + 4, PLT))
    return bytes(source)


def actual_proof(source):
    nso, _, _, selected = selected_source(source)
    return diag.selected_diag_abort_proof(nso, parse_metadata(nso), selected)


class PublicationCoverageTests(unittest.TestCase):
    def test_no_call_proof_with_coverage_error_refuses_before_empty_return(self):
        source = uncovered_source(no_call=True)
        proof = actual_proof(source)
        self.assertEqual(proof.calls, ())
        self.assertIn("uncovered or unselected", proof.coverage_error)
        nso = parse_nso(source)
        with self.assertRaisesRegex(ValueError, "uncovered or unselected"):
            diag.publication_contract_obligation(nso, parse_metadata(nso))

    def test_unconsumed_call_proof_with_coverage_error_refuses_before_reduction(self):
        source = uncovered_source(no_call=False)
        proof = actual_proof(source)
        self.assertEqual(proof.calls, ((ABORT + 4, PLT + 12),))
        self.assertIn("uncovered or unselected", proof.coverage_error)
        nso = parse_nso(source)
        with self.assertRaisesRegex(ValueError, "uncovered or unselected"):
            diag.publication_contract_obligation(nso, parse_metadata(nso))

    def test_clean_required_and_retired_controls_keep_their_existing_roles(self):
        expected = {
            "used": ([(ABORT, PLT + 12)], {0x100}),
            "clrex": ([], set()),
            "fresh-load": ([], set()),
        }
        for mode, (calls, heads) in expected.items():
            source = public_nso(mode)
            nso = parse_nso(source)
            proof, actual_heads = diag.publication_contract_obligation(nso, parse_metadata(nso))
            with self.subTest(mode=mode):
                self.assertEqual(list(proof.calls), calls)
                self.assertEqual(actual_heads, heads)

    def test_source_without_matching_abi_metadata_remains_optional(self):
        source = public_nso(symbol=SYMBOL + "_returning")
        nso = parse_nso(source)
        proof, heads = diag.publication_contract_obligation(nso, parse_metadata(nso))
        self.assertEqual(proof, diag.DiagAbortProof())
        self.assertEqual(heads, frozenset())


if __name__ == "__main__":
    unittest.main(verbosity=2)
