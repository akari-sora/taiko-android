"""An immediately consumed ADRP page is not an independent code pointer."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import Relocation, Symbol, parse_metadata, parse_nso
from test_nso_format import mutable_source


def fixture(producer=(0x90000001, 0x911F9021, 0xD65F03C0)):
    nso = parse_nso(mutable_source())
    metadata = parse_metadata(nso)
    image = bytearray(nso.image)
    # The public fixture has an unused gap before RO. Move the text end into
    # that gap so a page boundary can lie inside the SDK's ordinary atomic loop.
    struct.pack_into('<2048I', image, 0, *([0xD65F03C0] * 2048))
    struct.pack_into('<5I', image, 0xFFC,
                     0x885F7E68, 0x11000508, 0x88097E68, 0x35FFFFA9, 0xD65F03C0)
    struct.pack_into('<' + 'I' * len(producer), image, 0x1020, *producer)
    nso = replace(nso, image=bytes(image), sections=(replace(nso.sections[0], size=0x2000), *nso.sections[1:]))
    metadata = replace(metadata, symbols=(), relocations=(), init_addresses=(0xFFC, 0x1020),
                       eh_starts=(), protected=())
    return nso, metadata


def discover(nso, metadata):
    return ai.discover_code(nso, metadata, checked_stack=True, indirect_policy='guarded-host')


def rewrite(nso, ranges, report):
    return ar.rewrite(nso.image, text_size=nso.sections[0].size, code_ranges=ranges,
                      entry_offsets=report['roots'], package_version=2, checked_stack=True)


class AdrpConsumedPageTests(unittest.TestCase):
    def test_consumed_page_inside_atomic_is_not_an_entry_but_final_pointer_is(self):
        nso, metadata = fixture()
        ranges, report = discover(nso, metadata)
        self.assertNotIn(0x1000, report['roots'])
        self.assertNotIn(0x1000, report['address_taken_roots'])
        self.assertIn(0x17E4, report['address_taken_roots'])
        self.assertTrue(any(start <= 0x17E4 < end for start, end in ranges))
        image = rewrite(nso, ranges, report)
        self.assertEqual(image.bytes[0xFFC:0x100C], nso.image[0xFFC:0x100C])

    def test_independent_metadata_entries_survive_and_still_reject_atomic_interior(self):
        nso, metadata = fixture()
        variants = (replace(metadata, eh_starts=(0x1000,)),
                    replace(metadata, init_addresses=(*metadata.init_addresses, 0x1000)),
                    replace(metadata, symbols=(Symbol('page_entry', 0x1000, 4, 0, 2, 1, 0),)),
                    replace(metadata, relocations=(Relocation(0x8018, 1027, 0, 0x1000),)))
        for candidate in variants:
            with self.subTest(metadata=candidate):
                ranges, report = discover(nso, candidate)
                self.assertIn(0x1000, report['roots'])
                with self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                    rewrite(nso, ranges, report)

    def test_another_adr_or_unconsumed_adrp_keeps_the_page_root(self):
        for word in (0x10FFFE02, 0x90000002):  # ADR X2,0x1000 / ADRP X2,0x1000 at0x1040.
            nso, metadata = fixture()
            image = bytearray(nso.image)
            struct.pack_into('<2I', image, 0x1040, word, 0xD65F03C0)
            nso = replace(nso, image=bytes(image))
            metadata = replace(metadata, init_addresses=(*metadata.init_addresses, 0x1040))
            with self.subTest(word=hex(word)):
                _, report = discover(nso, metadata)
                self.assertIn(0x1000, report['address_taken_roots'])
                self.assertIn(0x17E4, report['address_taken_roots'])

    def test_delayed_or_escaped_page_values_remain_roots(self):
        # NOP, store the page, pass it through a call, and copy it to X2 all
        # prevent the adjacent single-use proof, even with a later overwrite.
        for word in (0xD503201F, 0xF9000041, 0x940001F7, 0xAA0103E2):
            nso, metadata = fixture((0x90000001, word, 0x911F9021, 0xD65F03C0))
            with self.subTest(word=hex(word)):
                _, report = discover(nso, metadata)
                self.assertIn(0x1000, report['address_taken_roots'])

    def test_other_add_forms_and_adr_remain_conservative(self):
        for first, second in ((0x90000001, 0x911F9022),  # ADD X2,X1,#0x7e4 preserves X1.
                              (0x90000001, 0x111F9021),  # 32-bit ADD.
                              (0x90000001, 0x915F9021),  # Shifted immediate.
                              (0x90000001, 0x91000021),  # ADD #0 does not kill the page.
                              (0x10FFFF01, 0x911F9021)):  # ADR X1,0x1000.
            nso, metadata = fixture((first, second, 0xD65F03C0))
            with self.subTest(first=hex(first), second=hex(second)):
                _, report = discover(nso, metadata)
                self.assertIn(0x1000, report['address_taken_roots'])

    def test_only_an_already_selected_complete_next_instruction_is_proof(self):
        adrp = ar.decode(0x90000001, 0x1020)
        add = ar.decode(0x911F9021, 0x1024)
        self.assertFalse(ai._adrp_page_is_consumed(adrp, {0x1020: adrp}))
        self.assertFalse(ai._adrp_page_is_consumed(adrp, {0x1020: adrp, 0x1028: add}))
        self.assertFalse(ai._adrp_page_is_consumed(adrp, {0x1020: adrp, 0x1024: ar.FatalWord(0x1024)}))
        for following in (SimpleNamespace(size=4, bytes=bytes(add.bytes)[:3]),
                          SimpleNamespace(size=2, bytes=bytes(add.bytes))):
            with self.subTest(following=following):
                self.assertFalse(ai._adrp_page_is_consumed(adrp, {0x1024: following}))
        self.assertTrue(ai._adrp_page_is_consumed(adrp, {0x1020: adrp, 0x1024: add}))


if __name__ == '__main__':
    unittest.main()
