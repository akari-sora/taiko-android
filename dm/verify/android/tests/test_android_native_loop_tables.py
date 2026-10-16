"""Original two-entry switch loops keep their six ALU operations and suffixes."""
from test_android_runtime_ro_table import assert_normalized_guard
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def source_for(extended=False):
    source=source_base()
    write_image(source,0x300,'<2I',0x528003B2,ar.branch(0x304,0x360))
    write_image(source,0x360,'<3I',0x90000020,0x91200000,ar.branch(0x368,0x400))
    prefix=([0x1B147D22,0x2A0803E1,0xD37FF821,0x8B010183,0x1B177C41,0x1B167C42]
            if extended else [0x1B147D22,0x2A0803E1,0x8B0101A4,0x8B010183,0x1B167C41,0x1B157C42])
    target,loaded=(4,5) if extended else (5,6)
    suffix=[0x8B214661,0x8B2246A2] if extended else [0x8B010261,0x8B0202E2]
    write_image(source,0x400,'<14I',0x710065DF,0x54000FE8,*prefix,
                adr(0x420,0x340,target),0x38606800|(14<<16)|loaded,
                0x8B000800|(loaded<<16)|(target<<5)|target,*suffix,0xD61F0000|(target<<5))
    write_image(source,0x4800,'<26B',*([0]*25+[163]))
    write_image(source,0x5CC,'<I',0x1B1210C4) # Original virtual-x18 MADD in a discovered case.
    return source,0x434,0x424


class NativeLoopTableTests(unittest.TestCase):
    def configure(self, model, extended):
        model.x[14]=0;model.x[9]=3;model.x[20]=5;model.x[8]=7
        model.x[13]=0x1000;model.x[12]=0x2000;model.x[19]=0x3000
        model.x[22]=13 if extended else 11
        model.x[23]=11 if extended else 0x4000
        model.x[21]=0x4000 if extended else 13

    def test_complete_loop_discovery_and_original_parallel_effects(self):
        for extended in (False,True):
            source,branch,load=source_for(extended)
            with self.subTest(extended=extended):
                _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==branch)
                self.assertEqual((plan['index_bound'],plan['table_bytes']),(25,26))
                self.assertIn(0x5CC,report['code_discovery']['roots'])
                image=image_for(source,entry=0x300,entry_offsets=(0x408,),proven_guest_indirect_offsets=(branch,))
                model=Machine(image);hardware=model.x[18];self.configure(model,extended);model.run()
                expected=(0x314A,0x4186,0x200E,0x340,0) if extended else (0x30A5,0x40C3,0x2007,0x1007,0x340)
                self.assertEqual(tuple(model.x[1:6]),expected)
                self.assertEqual((model.x[18],model.load(model.state,8)),(hardware,29))

    def test_prefix_entry_uses_actual_full_index_and_preserves_executed_effects(self):
        for extended in (False,True):
            source,branch,load=source_for(extended)
            image=image_for(source,entry=0x408,entry_offsets=(0x408,),proven_guest_indirect_offsets=(branch,))
            model=Machine(image);self.configure(model,extended)
            model.x[14]=1<<32;model.x[0]=0x4800;model.flags=0xA0000000
            with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            expected=(165,195,0x200E,0x340) if extended else (165,195,0x2007,0x1007)
            self.assertEqual(tuple(model.x[1:5]),expected)
            self.assertEqual((model.x[14],model.sp,model.flags),(1<<32,model.start_sp,0xA0000000))

    def test_earlier_non_ro_object_is_not_a_table_but_distinct_ro_tables_refuse(self):
        for extended in (False,True):
            source,branch,_=source_for(extended)
            write_image(source,0x330,'<2I',0x90000040,0x91000000) # Unrelated BSS/data object.
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
            model=Machine(image);self.configure(model,extended);model.run()
            self.assertEqual(model.x[4 if extended else 5],0x340)
            write_image(source,0x330,'<2I',0x90000020,0x91240000) # Second complete RO candidate.
            with self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))

    def test_ordinary_prefix_variants_keep_guard_and_postload_or_incomplete_tables_refuse(self):
        for extended in (False,True):
            source,branch,load=source_for(extended)
            for entry in range(0x40C,0x420,4):
                image=image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
                assert_normalized_guard(self,source,image,branch)
            for entry in range(load+4,branch+4,4):
                with self.subTest(extended=extended,entry=hex(entry)),self.assertRaises(ar.RewriteError):
                    image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
            for pc in (0x408,0x410,0x41C,0x42C,0x430):
                altered=bytearray(source);write_image(altered,pc,'<I',0xD503201F)
                with self.subTest(extended=extended,pc=hex(pc)):
                    image=image_for(altered,entry=0x300,proven_guest_indirect_offsets=(branch,))
                    assert_normalized_guard(self,altered,image,branch)
            with self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,readonly_ranges=((0x4800,0x4819),),proven_guest_indirect_offsets=(branch,))


if __name__=='__main__':unittest.main()
