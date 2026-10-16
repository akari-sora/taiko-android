"""Actual masked alias switch: bound the consumed index, not the source W8."""
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

VALUES=(0,2,2,2,2,2,4,2,7,6)


def fixture():
    source=mutable_source()
    write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<128I',*([0xD65F03C0]*128))
    write_image(source,0x300,'<3I',0x90000037,0x912002F7,0x1400005E)
    write_image(source,0x480,'<13I',0x5101890A,0x53196149,0x33011D49,0x12001D2A,
                0x91000B18,0x7100255F,0x54000128,0x92401D29,0x100000AA,
                0x38696AEB,0x8B0B094A,0x2A1B03E9,0xD61F0140)
    write_image(source,0x4C4,'<I',0x2A1203E9)
    write_image(source,0x4800,'10s',bytes(VALUES))
    return source


def rewrite(source,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,
                 code_ranges=((0x300,0x500),),package_version=2,checked_stack=True,
                 proven_guest_indirect_offsets=(0x4B0,),readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class RuntimeRoU8Tests(unittest.TestCase):
    def test_true_mask_alias_and_dead_index_suffix_expose_finite_case(self):
        package,report=ai.import_module(fixture(),'main',package_version=2,checked_stack=True,
                                       indirect_policy='guarded-host')
        discovery=report['code_discovery'];plan=discovery['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-mask-alias-lsl2-v1')
        self.assertEqual((plan['offset'],plan['load_offset'],plan['mask_alias_offset'],
                          plan['index_bound'],plan['table_bytes']),(0x4B0,0x4A4,0x48C,9,10))
        self.assertEqual(plan['target_values'],[0,2,4,6,7])
        self.assertIn(0x4C4,discovery['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<2I',package,payload+0x4AC),(0x2A1B03E9,0xD61F0140))
        image=rewrite(fixture());site=next(x for x in image.sites if x.offset==0x4A4)
        code=list(ar.MD.disasm(image.bytes[site.trampoline:site.trampoline+100],site.trampoline))
        self.assertIn(('cmp','x9, #9'),[(i.mnemonic,i.op_str) for i in code])

    def test_false_alias_offset_mask_clobber_and_every_bypass_refuse(self):
        for pc,value in ((0x48C,0x12001D0A), # alias reads W8, not W9
                         (0x48C,0x1100012A), # ADD instead of exact low8 alias
                         (0x490,0x91000529), # index clobber between alias and CMP
                         (0x490,0x1100054A), # compared value clobber
                         (0x49C,0x92401D09), # mask different source
                         (0x49C,0x92401929), # wrong mask
                         (0x4AC,0x2A1B03EA), # live target clobber
                         (0x4AC,0x2A1B03EB), # loaded value clobber
                         (0x4AC,0xD4000001)):
            candidate=fixture();write_image(candidate,pc,'<I',value)
            with self.subTest(pc=hex(pc),word=hex(value)),self.assertRaises(ar.RewriteError):rewrite(candidate)
        source=fixture();write_image(source,0x494,'<I',0x7100253F) # Actual consumed W9 now supplies finite candidate.
        assert_normalized_guard(self,source,rewrite(source),0x4B0)
        for pc in range(0x490,0x4B4,4):
            with self.subTest(entry=hex(pc)),self.assertRaises(ar.RewriteError):rewrite(fixture(),entry_offsets=(pc,))
        for changes in ({'readonly_ranges':()}, {'checked_stack':False},
                        {'code_ranges':((0x300,0x4C4),)}):
            with self.subTest(changes=changes),self.assertRaises(ar.RewriteError):rewrite(fixture(),**changes)

    def test_runtime_rule_does_not_add_unrelated_code_roots(self):
        source=fixture();write_image(source,0x4F0,'<I',0x52800552)
        with self.assertRaisesRegex(ai.ImportError,'0x4f0: uncovered rewrite candidate'):
            ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')


if __name__=='__main__':unittest.main()
