"""A backward byte switch retains its original zeroing suffix."""
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import unittest

from test_android_runtime_ro_backward import adr
from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(bound=19, suffix=0x2A1F03E9):
    source=source_base()
    write_image(source,0x300,'<I',ar.branch(0x300,0x3B8))
    write_image(source,0x3B8,'<9I',0x7100001F|(bound<<10)|(10<<5),0x54000228,
                0x9000002B,0x9120016B,adr(0x3C8,0x340,12),
                0x386A696D,0x8B0D098C,suffix,0xD61F0180)
    write_image(source,0x4800,'<'+str(bound+1)+'B',*([0]*bound+[200]))
    write_image(source,0x660,'<I',0x52800552)
    return source


class BackwardZeroSuffixTests(unittest.TestCase):
    def test_real_ro_targets_discover_the_case_and_keep_source_suffix(self):
        source=fixture()
        package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual((plan['base'],plan['index_bound'],plan['table_bytes']),(0x340,19,20))
        self.assertIn(0x660,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(package[payload+0x3D0:payload+0x3DC],parse_nso(source).image[0x3D0:0x3DC])

    def test_executed_zero_suffix_and_full_index_refusal(self):
        image=image_for(fixture(),entry=0x300,proven_guest_indirect_offsets=(0x3D8,))
        model=Machine(image);model.x[10]=19;hardware=model.x[18]
        model.run()
        self.assertEqual((model.x[9],model.x[12],model.x[13],model.x[18]),(0,0x660,200,hardware))
        self.assertEqual(model.load(model.state,8),42)
        for index in (1<<32,(1<<32)|19):
            model=Machine(image);model.x[10]=index
            old_loaded,old_zeroed=model.x[13],model.x[9]
            with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual((model.x[10],model.x[13],model.x[9],model.sp),
                             (index,old_loaded,old_zeroed,model.start_sp))
        # A direct load entry independently checks the actual full-width index.
        assert_normalized_guard(self,fixture(),image_for(fixture(),entry=0x3CC,proven_guest_indirect_offsets=(0x3D8,)),0x3D8)

    def test_ordinary_suffixes_and_preload_entries_keep_guard_while_target_clobbers_refuse(self):
        for suffix in (0x2A1F03EC,):
            with self.subTest(suffix=hex(suffix)),self.assertRaises(ar.RewriteError):
                image_for(fixture(suffix=suffix),entry=0x300,proven_guest_indirect_offsets=(0x3D8,))
        with self.assertRaises(ar.RewriteError):
            image_for(fixture(64),entry=0x300,proven_guest_indirect_offsets=(0x3D8,))
        with self.assertRaises(ar.RewriteError):
            image_for(fixture(),entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x3D8,))
        for suffix in (0x2A1F03ED,0xD503201F,0xAA1F03E9):
            source=fixture(suffix=suffix)
            assert_normalized_guard(self,source,image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3D8,)),0x3D8)
        for entry in range(0x3BC,0x3D0,4):
            assert_normalized_guard(self,fixture(),image_for(fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3D8,)),0x3D8)
        for entry in range(0x3D0,0x3DC,4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3D8,))


if __name__=='__main__':unittest.main()
