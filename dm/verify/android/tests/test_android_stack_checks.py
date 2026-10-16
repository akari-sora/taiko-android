"""Opt-in v2 SP preflight; legacy images receive no implicit authority."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import android_import as ai
from test_nso_format import mutable_source, write_image
from test_android_module_entry import canonical_module
from nso_format import parse_nso, parse_metadata


def raw(*words):
    return struct.pack('<' + 'I' * len(words), *words)


class StackCheckTests(unittest.TestCase):
    def test_every_admitted_sp_writer_gets_exact_preflight_and_original_word(self):
        words = (0xD10043FF, 0x910043FF, 0xD14053FF, 0xD10143BF,
                 0x9100011F, 0xA8C27BFD, 0xA9BE7BFD, 0xF84107E8)
        image = ar.rewrite(raw(*words, 0xD65F03C0), package_version=2, checked_stack=True)
        self.assertTrue(image.metadata()['checked_stack'])
        self.assertEqual(len(image.gates), len(words))
        for index, (gate, origin) in enumerate(zip(image.gates, image.gate_provenance)):
            self.assertEqual((gate.kind, gate.argument, origin.original_word, origin.original_offset),
                             (5, words[index], words[index], index * 4))
            self.assertEqual(image.bytes[gate.return_offset:gate.return_offset + 12],
                             raw(ar.pair(True, 29, 30, 0), 0x910043FF, words[index]))
            self.assertEqual(struct.unpack_from('<I', image.bytes, gate.return_offset + 12)[0],
                             ar.branch(gate.return_offset + 12, index * 4 + 4))

    def test_checked_stack_requires_v2_and_rejects_unknown_x18_and_unaligned_writers(self):
        with self.assertRaisesRegex(ar.RewriteError, 'version 2'):
            ar.rewrite(raw(0xD10043FF, 0xD65F03C0), checked_stack=True)
        for word in (0x9100025F, 0xCB2063FF, 0xD10007FF, 0xD14407FF, 0xA8C24FF2):
            with self.subTest(word=hex(word)), self.assertRaisesRegex(ar.RewriteError, 'stack|SP|x18'):
                ar.rewrite(raw(word, 0xD65F03C0), package_version=2, checked_stack=True)
        legacy = raw(0xD10043FF, 0x910043FF, 0xD65F03C0, 0xD503201F)
        self.assertEqual(ar.rewrite(legacy).bytes, legacy)
        self.assertFalse(ar.rewrite(legacy).gates)

    def test_checked_sp_stores_cannot_claim_static_relocation_disjointness(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<3I', 0xD10043FF, 0xF90003E0, 0x910043FF)
        write_image(source, 0x30C, '<I', 0xD65F03C0)
        _, report = ai.import_module(source, 'main', package_version=2,
                                     indirect_policy='guarded-host', checked_stack=True)
        m = parse_metadata(parse_nso(source))
        self.assertEqual(report['code_discovery']['relocation_slots_clobbered_by_code'], sorted(r.offset for r in m.relocations))
        self.assertIn({'instruction_offset': 0x304, 'range': None}, report['code_discovery']['reachable_memory_writes'])
        self.assertTrue(report['rewrite']['checked_stack'])

    def test_canonical_original_header_cannot_publish_an_unchecked_package(self):
        source, _ = canonical_module()
        with self.assertRaisesRegex(ai.ImportError, 'checked.stack'):
            ai.import_module(source, 'main', package_version=2)
        package, report = ai.import_module(source, 'main', package_version=2,
                                          indirect_policy='guarded-host', checked_stack=True)
        self.assertEqual(package[:8], b'DMAMOD02')
        self.assertTrue(report['rewrite']['checked_stack'])

    def test_actual_original_stack_alignments_are_exact_masks_only(self):
        for value,low in ((0x9274CD3F,4095),(0x927BE93F,31),(0x927AE53F,63)):
            image=ar.rewrite(raw(value,0xD65F03C0),package_version=2,checked_stack=True)
            self.assertEqual(image.gates[0].argument,value)
            op=ar.stack_check_operation(value)
            self.assertEqual((op['source'],op['alignment_mask']),(9,0xFFFFFFFFFFFFFFFF-low))
        value=0x9274CD3F
        for other in (value^(1<<22),0x9274CE5F,0x9274CFFF):
            with self.subTest(word=hex(other)),self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(other,0xD65F03C0),package_version=2,checked_stack=True)

    def test_taiko_128_byte_alignment_preserves_instruction_and_stack_gate(self):
        # main+0x150f588: AND SP, X9, #0xffffffffffffff80.
        # The original instruction still runs after the same bounded preflight.
        value=0x9279E13F
        op=ar.stack_check_operation(value)
        self.assertIsNotNone(op)
        self.assertEqual(op,dict(source=9,delta=0,access_bytes=0,post_index=False,
                                 alignment_mask=0xFFFFFFFFFFFFFF80))
        image=ar.rewrite(raw(value,0xD65F03C0),package_version=2,checked_stack=True)
        self.assertEqual(len(image.gates),1)
        gate=image.gates[0]
        self.assertEqual((gate.kind,gate.argument),(5,value))
        self.assertEqual(struct.unpack_from('<I',image.bytes,gate.return_offset+8)[0],value)
        for source in (18,31):
            unsafe=(value&~(31<<5))|(source<<5)
            self.assertIsNone(ar.stack_check_operation(unsafe))
            with self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(unsafe,0xD65F03C0),package_version=2,checked_stack=True)


if __name__ == '__main__':
    unittest.main()
