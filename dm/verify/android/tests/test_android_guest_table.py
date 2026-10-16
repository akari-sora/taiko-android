"""Actual missing-switch shape: native guest BR x10 needs finite RO CFG roots."""
from pathlib import Path
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso
from test_nso_format import mutable_source,write_image


def fixture():
    source=mutable_source()
    words=[0xD65F03C0]*24
    words[:9]=[0x51001108,0x71000D1F,0x54000248,0x90000029,
               0x91200529,0x1000008A,0x3868692B,0x8B0B094A,0xD61F0140]
    words[16]=0x52800552  # Case7 MOV w18,#42 was invisible to direct CFG.
    write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<24I',*words)
    write_image(source,0x4801,'4s',bytes((0,7,0,7)))
    return source


class GuestTableTests(unittest.TestCase):
    def test_exact_guest_switch_targets_expose_x18_case_without_host_gate(self):
        package,report=ai.import_module(fixture(),'main',package_version=2,checked_stack=True,
                                        indirect_policy='guarded-host')
        discovery=report['code_discovery']
        plan=discovery['readonly_guest_jump_tables'][0]
        self.assertEqual((plan['offset'],plan['table_offset'],plan['target_register']),(0x320,0x4801,10))
        self.assertEqual(plan['target_values'],[0,7])
        self.assertIn(0x340,discovery['roots'])
        self.assertIn(0x320,discovery['proven_indirect_sites'])
        self.assertNotIn(0x320,discovery['guarded_indirect_sites'])
        self.assertIn(0x340,[x['offset'] for x in report['rewrite']['sites']])
        self.assertNotIn(0x320,[x['offset'] for x in report['rewrite']['sites']])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<I',package,payload+0x320)[0],0xD61F0140)

    def test_independent_rewriter_guards_preload_entries_and_rejects_postload_entries(self):
        nso=parse_nso(fixture())
        options=dict(entry_offset=0x300,text_size=nso.sections[0].size,
                     code_ranges=((0x300,0x360),),package_version=2,checked_stack=True,
                     proven_guest_indirect_offsets=(0x320,),readonly_ranges=((0x4000,0x8000),))
        image=ar.rewrite(nso.image,**options)
        self.assertTrue(any(x.offset==0x340 for x in image.sites))
        for entry in range(0x304,0x31C,4):
            image=ar.rewrite(nso.image,**options,entry_offsets=(entry,))
            assert_normalized_guard(self,fixture(),image,0x320)
        for entry in range(0x31C,0x324,4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                ar.rewrite(nso.image,**options,entry_offsets=(entry,))
        for changes in ({'readonly_ranges':()}, {'guarded_indirect_offsets':(0x320,)},
                        {'checked_stack':False}):
            with self.subTest(changes=changes),self.assertRaises(ar.RewriteError):
                ar.rewrite(nso.image,**(options|changes))

    def test_promotion_does_not_classify_other_uncovered_words_as_code(self):
        source=fixture();write_image(source,0x3A0,'<I',0x52800552)
        with self.assertRaisesRegex(ai.ImportError,'0x3a0: uncovered rewrite candidate'):
            ai.import_module(source,'main',package_version=2,checked_stack=True,
                             indirect_policy='guarded-host')


if __name__=='__main__':
    unittest.main()
