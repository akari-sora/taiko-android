"""Two observed byte-composition schedules keep all original X18 effects."""
from test_android_runtime_ro_table import assert_normalized_guard
import unittest
from test_android_runtime_ro_backward import adr
from test_android_runtime_ro_sub_inline import ar, ai, source_base, write_image
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(backward=False):
    source=source_base();write_image(source,0x300,'<I',ar.branch(0x300,0x380))
    table=17 if backward else 1
    write_image(source,0x380,'<3I',0x90000020|table,0x91200000|(table<<5)|table,ar.branch(0x388,0x400))
    if backward:
        words=(0x7100105F,0x54000FE8,0x39402972,0x39402D61,0xB3781E41,
               0x39402163,0x39402564,0x53185C63,0x8B0101B2,0x93403C61,0xAA040021,
               adr(0x42C,0x340,3),0x38626A24,0x8B040863,0xD61F0060)
        values=(25,29,0,33,37);branch,load=0x438,0x430;last=0x340+37*4
    else:
        words=(0x7100109F,0x54000FE8,0x39402A42,0x39402E43,0xB3781C43,
               0x39402246,0x39402645,0xB3781CC5,adr(0x420,0x438,6),
               0x38646827,0x8B0708C6,0x8B030223,0xD341FCA2,0xD61F00C0)
        values=(0,21,14,38,55);branch,load=0x434,0x424;last=0x438+55*4
    write_image(source,0x400,'<'+str(len(words))+'I',*words)
    write_image(source,0x4800,'<5B',*values)
    write_image(source,last,'<I',0x52800552)
    return source,branch,load,last


class ByteAssemblyTablesTests(unittest.TestCase):
    def test_real_control_discovery_and_original_byte_composition(self):
        for backward in (False,True):
            source,branch,load,last=fixture(backward)
            with self.subTest(backward=backward):
                _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                self.assertIn(last,report['code_discovery']['roots'])
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
                model=Machine(image);hardware=model.x[18]
                for offset,value in ((8,0x80),(9,3),(10,0xA1),(11,0xB2)):model.store(0x7000+offset,value,1)
                if backward:
                    model.x[2]=2;model.x[11]=0x7000;model.x[13]=0x9000
                else:
                    model.x[4]=0;model.x[17]=0x8000;model.store(model.state,0x7000,8)
                model.run()
                if backward:
                    self.assertEqual((model.x[1],model.x[3],model.x[4],model.load(model.state,8)),
                                     (0xFFFFFFFFFFFF8003,0x340,0,0x131B2))
                else:
                    self.assertEqual((model.x[2],model.x[3],model.x[5],model.x[6],model.load(model.state,8)),
                                     (0x4001,0x121B2,0x8003,0x438,0x7000))
                self.assertEqual((model.x[18],model.sp,model.flags),(hardware,model.start_sp,0x80000000))

    def test_prefix_variants_retain_guard_and_postload_entries_or_non_ro_refuse(self):
        for backward in (False,True):
            source,branch,load,_=fixture(backward)
            for entry in (0x408,load):
                image=image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
                assert_normalized_guard(self,source,image,branch)
            for entry in (load+4,branch):
                with self.subTest(backward=backward,entry=hex(entry)),self.assertRaises(ar.RewriteError):
                    image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
            changed=bytearray(source);write_image(changed,0x410,'<I',0xD503201F)
            image=image_for(changed,entry=0x300,proven_guest_indirect_offsets=(branch,))
            assert_normalized_guard(self,changed,image,branch)
            with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(branch,))


if __name__=='__main__':unittest.main()
