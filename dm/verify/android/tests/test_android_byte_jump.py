"""Bounded guest byte-index dispatch is distinct from host pointer transfer."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import android_import as ai
from test_nso_format import mutable_source, write_image


def program():
    # ADR x18,16; LDRB w2,[x1]; ADD x18,x18,x2,LSL2; BR x18.
    return [0x10000092, 0x39400022, 0x8B020A52, 0xD61F0240] + [0xD65F03C0] * 256


class ByteJumpTests(unittest.TestCase):
    def test_checked_byte_dispatch_roots_and_restores_every_target(self):
        words = program()
        image = ar.rewrite(struct.pack('<260I', *words), package_version=2, checked_stack=True)
        site = next(x for x in image.sites if x.offset == 12)
        self.assertEqual(site.instruction, 'br x18')
        decoded = list(ar.MD.disasm(image.bytes[site.trampoline:], site.trampoline))
        # Every table destination restores the borrowed pair and original SP
        # before a direct branch to the selected original instruction.
        tails = [i for i,x in enumerate(decoded) if x.mnemonic == 'ldp' and x.op_str == 'x0, x1, [sp, #0x10]']
        self.assertEqual(len(tails), 256)
        for index, at in enumerate(tails):
            self.assertEqual(decoded[at + 1].op_str, 'sp, sp, #0x20')
            self.assertEqual((decoded[at + 2].mnemonic, decoded[at + 2].operands[0].imm), ('b', 16 + index * 4))
        self.assertFalse(any(x.mnemonic in ('cmp', 'subs', 'adds', 'msr') for x in decoded))
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<260I', *words)
        _, report = ai.import_module(source, 'main', package_version=2, checked_stack=True,
                                     indirect_policy='guarded-host')
        plans = report['code_discovery']['byte_jump_tables']
        self.assertEqual(plans[0]['offset'], 0x30C)
        self.assertEqual(plans[0]['base'], 0x310)
        self.assertEqual(plans[0]['count'], 256)
        self.assertTrue(set(range(0x310,0x710,4)) <= set(report['code_discovery']['roots']))

    def test_unproven_or_entered_producer_and_unselected_targets_refuse(self):
        words = program()
        for at, replacement in ((1,0x39800022), (2,0x8B020E52), (0,0x100000B2), (3,0xD63F0240)):
            candidate = words.copy(); candidate[at] = replacement
            with self.subTest(at=at), self.assertRaises(ar.RewriteError):
                ar.rewrite(struct.pack('<260I',*candidate),package_version=2,checked_stack=True)
        with self.assertRaises(ar.RewriteError):
            ar.rewrite(struct.pack('<260I',*words),package_version=2,checked_stack=True,entry_offsets=(8,))
        with self.assertRaises(ar.RewriteError):
            ar.rewrite(struct.pack('<260I',*words),package_version=2,checked_stack=True,code_ranges=((0,20),))
        with self.assertRaises(ar.RewriteError):
            ar.rewrite(struct.pack('<260I',*words))
        # A source branch is an entrance even without caller entry_offsets.
        bypass=[0x14000003,*words]
        with self.assertRaisesRegex(ar.RewriteError,'unproven byte dispatch'):
            ar.rewrite(struct.pack('<261I',*bypass),package_version=2,checked_stack=True)
        exception=[0x100000B2,0x39400022,0xD4000001,0x8B020A52,0xD61F0240]+[0xD65F03C0]*256
        with self.assertRaisesRegex(ar.RewriteError,'unproven byte dispatch'):
            ar.rewrite(struct.pack('<261I',*exception),package_version=2,checked_stack=True)

    def test_byte_target_cannot_turn_literal_or_exclusive_interior_into_an_entry(self):
        source=mutable_source()
        write_image(source,0,'<I',0x140000C0)
        write_image(source,0x300,'<261I',0x58000207,*program())  # LDR x7,0x340
        with self.assertRaisesRegex(ai.ImportError,'literal data overlaps discovered code'):
            ai.import_module(source,'main',package_version=2,checked_stack=True,
                             indirect_policy='guarded-host')
        words=program()
        # LDXR/STXR loop's second word becomes an external dispatch entry.
        words[4:8]=[0xC85F7C23,0xC8007C23,0x35FFFFC0,0xD65F03C0]
        with self.assertRaisesRegex(ar.RewriteError,'entry|exclusive'):
            ar.rewrite(struct.pack('<260I',*words),package_version=2,checked_stack=True)


if __name__ == '__main__':
    unittest.main()
