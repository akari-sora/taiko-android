"""Bounded u16 inline tables keep subtraction and scheduled-copy facts exact."""
from pathlib import Path
import struct
import sys
import unittest
from test_android_runtime_ro_table import assert_normalized_guard

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso
from test_nso_format import mutable_source,write_image


def source_base():
    source=mutable_source();write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<832I',*([0xD65F03C0]*832))
    write_image(source,0x300,'<I',0x14000030)
    return source


def sub_fixture(bound=134,index=8,source_reg=8,table=9,subtract=0x95):
    source=source_base();values=[2]*(bound+1);values[0]=0;values[-1]=430
    if bound>=78:values[78]=430
    write_image(source,0x3C0,'<9I',0x51000000|(subtract<<10)|(source_reg<<5)|index,
                0x7100001F|(bound<<10)|(index<<5),0x54000128,0x90000020|table,
                0x91200000|(table<<5)|table,0x1000008A,
                0x78607800|(index<<16)|(table<<5)|11,0x8B0B094A,0xD61F0140)
    write_image(source,0xA9C,'<I',0x52800552)
    write_image(source,0x4800,'<'+str(bound+1)+'H',*values)
    return source


def scheduled_fixture():
    source=source_base();values=[2]*30;values[0]=0;values[9]=699;values[-1]=699
    write_image(source,0x3C0,'<13I',0x7100771F,0xB9001FEB,0x540001A8,
                0xB0000029,0x91313129,0x8B38CD2F,0x2A1803E9,
                0x9000002A,0x9120014A,0x1000008B,0x7869794C,0x8B0C096B,0xD61F0160)
    write_image(source,0xEE0,'<I',0x52800552)  # base3f4 +699*4
    write_image(source,0x4800,'<30H',*values)
    return source


def rewrite(source,branch,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,code_ranges=((0x300,0x1000),),
                 package_version=2,checked_stack=True,proven_guest_indirect_offsets=(branch,),
                 readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class RuntimeRoSubInlineTests(unittest.TestCase):
    def test_sub_result_domain_and_complete_large_table_are_truthful(self):
        package,report=ai.import_module(sub_fixture(),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-sub-inline-lsl2-v1')
        self.assertEqual((plan['index_bound'],plan['table_bytes'],plan['index_subtract_immediate'],plan['index_source_register']),(134,270,149,8))
        self.assertIn(0xA9C,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<I',package,payload+0x3E0)[0],0xD61F0140)
        image=rewrite(sub_fixture(),0x3E0,entry_offsets=(0x3D0,0x3D8))
        site=next(x for x in image.sites if x.offset==0x3D8)
        code=list(ar.MD.disasm(image.bytes[site.trampoline:site.trampoline+100],site.trampoline))
        self.assertIn(('cmp','x8, #0x86'),[(i.mnemonic,i.op_str) for i in code])
        rewrite(sub_fixture(21,9,8,8,0x13E),0x3E0)
        rewrite(sub_fixture(255),0x3E0)
        with self.assertRaises(ar.RewriteError):rewrite(sub_fixture(256),0x3E0)
        from test_android_runtime_ro_table import fixture as old_fixture,rewrite as old_rewrite
        old=old_fixture();write_image(old,0x310,'<I',0x7101011F)
        with self.assertRaises(ar.RewriteError):old_rewrite(old)  # existing form retains63 cap

    def test_canonical_wide_form_preserves_prefix_effects_and_postload_entries_refuse(self):
        for value in (0xD1025508,0x71025508,0x51425508,0x11025508,0x51025648):
            source=sub_fixture();write_image(source,0x3C0,'<I',value)
            with self.subTest(word=hex(value)):
                image=rewrite(source,0x3E0)
                assert_normalized_guard(self,source,image,0x3E0,planner=ar.readonly_guest_table)
        for entry in (0x3C4,0x3C8,0x3DC,0x3E0):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):rewrite(sub_fixture(),0x3E0,entry_offsets=(entry,))
        with self.assertRaises(ar.RewriteError):rewrite(sub_fixture(),0x3E0,readonly_ranges=())

    def test_scheduled_copy_keeps_store_and_dead_index_lifetime_explicit(self):
        package,report=ai.import_module(scheduled_fixture(),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-scheduled-mov-inline-lsl2-v1')
        self.assertEqual((plan['index_bound'],plan['table_bytes'],plan['alias_source_register'],plan['dead_before_copy_register']),(29,60,24,9))
        self.assertEqual(plan['dead_before_copy_write_offsets'],[0x3CC,0x3D0])
        self.assertEqual(plan['preserved_store_offset'],0x3C4)
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<I',package,payload+0x3C4)[0],0xB9001FEB)
        self.assertIn(0xEE0,report['code_discovery']['roots'])
        rewrite(scheduled_fixture(),0x3F0,entry_offsets=(0x3E0,0x3E8))

    def test_scheduled_prefix_effects_are_preserved_and_unsafe_stack_or_postload_refuse(self):
        for pc,value in ((0x3C4,0xB8004FEB),(0x3C4,0x31000718),
                         (0x3CC,0xB0000038),(0x3D0,0xB1313129),
                         (0x3D4,0x8B39CD2F),(0x3D4,0x8B386D2F),
                         (0x3D4,0x8B38CD2B),(0x3D8,0xAA1803E9)):
            source=scheduled_fixture();write_image(source,pc,'<I',value)
            if value in (0xB8004FEB,0xAA1803E9):
                with self.subTest(pc=hex(pc),word=hex(value)),self.assertRaises(ar.RewriteError):rewrite(source,0x3F0)
            else:
                with self.subTest(pc=hex(pc),word=hex(value)):
                    assert_normalized_guard(self,source,rewrite(source,0x3F0),0x3F0)
        source=scheduled_fixture();write_image(source,0x3CC,'<2I',0x91313129,0xB0000029)
        assert_normalized_guard(self,source,rewrite(source,0x3F0),0x3F0)
        for entry in (0x3C4,0x3C8,0x3CC,0x3D0,0x3D4,0x3D8):
            assert_normalized_guard(self,scheduled_fixture(),rewrite(scheduled_fixture(),0x3F0,entry_offsets=(entry,)),0x3F0)
        for entry in (0x3EC,0x3F0):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):rewrite(scheduled_fixture(),0x3F0,entry_offsets=(entry,))


if __name__=='__main__':unittest.main()
