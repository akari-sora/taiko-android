"""Versioned real SDK proof; no game bytes are embedded in these tests."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso,parse_metadata

SDK=Path('C:/Users/aa223/dm-work/data/switch/3.3.94012/Update/ExeFS/sdk')


@unittest.skipUnless(SDK.is_file(),'local verified SDK required for exact assembly-helper regression')
class SdkInlineLrTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nso=parse_nso(SDK.read_bytes());cls.metadata=parse_metadata(cls.nso)
        assert cls.nso.source_sha256.hex()=='1c9f198a91c0bcfee5cf8f5b53fb941895e91334dfb766ce79fc68576797f017'

    def changed(self,pc,word):
        image=bytearray(self.nso.image);struct.pack_into('<I',image,pc,word)
        return replace(self.nso,image=bytes(image))

    def test_original_literal_read_returns_only_after_original_caller_lr_restored(self):
        proof=ai._sdk_inline_lr_literal(self.nso,self.metadata,set())
        self.assertEqual((proof['literal_start'],proof['literal_end'],proof['target_bss']),(0x3526CC,0x3526D0,0xCFF508))
        self.assertEqual(proof['return_offsets'],[0x352740])
        self.assertNotIn(0x3526CC,proof['proven_instruction_offsets'])
        self.assertTrue({0x352658,0x3526D0,0x352734,0x35273C,0x352740}<=set(proof['proven_instruction_offsets']))
        self.assertEqual(self.nso.image[0x3526CC:0x3526D0],bytes.fromhex('3cce9a00'))

    def test_mutated_read_save_restore_control_and_unknown_version_get_no_exemption(self):
        for pc,word in ((0x352658,0xD503201F),(0x3526C8,0x14000002),(0x3526D0,0xB94007C0),
                        (0x35273C,0xD503201F),(0x352748,ar.branch(0x352748,0x352740))):
            with self.subTest(pc=hex(pc)):
                self.assertIsNone(ai._sdk_inline_lr_literal(self.changed(pc,word),self.metadata,set()))
        self.assertIsNone(ai._sdk_inline_lr_literal(replace(self.nso,source_sha256=bytes(32)),self.metadata,set()))
        with self.assertRaises(ai.ImportError):ai._sdk_inline_lr_literal(self.changed(0x3526CC,4),self.metadata,set())
        with self.assertRaises(ai.ImportError):ai._sdk_inline_lr_literal(self.changed(0x3526CC,0x009ACE40),self.metadata,set())

    def test_literal_reader_and_restore_are_not_external_entries(self):
        for pc in (0x3526CC,0x3526D0,0x352734,0x35273C):
            with self.subTest(root=hex(pc)),self.assertRaises(ai.ImportError):
                ai._sdk_inline_lr_literal(self.nso,self.metadata,{pc})
        for target in (0x3526CC,0x3526D0,0x35273C):
            changed=self.changed(0x352800,ar.branch(0x352800,target))
            with self.subTest(target=hex(target)),self.assertRaises(ai.ImportError):
                ai._sdk_inline_lr_literal(changed,self.metadata,set())
        delta=(0x3526D0-0x352800)&0x1FFFFF
        changed=self.changed(0x352800,0x10000000|(delta&3)<<29|(delta>>2)<<5)
        with self.assertRaises(ai.ImportError):ai._sdk_inline_lr_literal(changed,self.metadata,set())


if __name__=='__main__':unittest.main()
