"""Original source masks/copies execute before the actual native-table guard."""
import unittest
from test_android_runtime_ro_table import assert_normalized_guard

from test_android_runtime_ro_sub_inline import ar,ai,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def side_copy():
    source=source_base()
    write_image(source,0x3C0,'<10I',0x71001EBF,0x54000CE8,0x39400005,0x2A1503E0,
                0x90000027,0x912000E7,adr(0x3D8,0x3E8,4),0x786078E6,0x8B060884,0xD61F0080)
    write_image(source,0x4800,'<8H',0,62,78,91,134,175,221,269)
    write_image(source,0x81C,'<I',0x52800552)
    return source,0x3E4,0x3DC


def large_sub():
    source=source_base()
    write_image(source,0x300,'<I',ar.branch(0x300,0x360))
    write_image(source,0x360,'<3I',0x9000003C,0x9120039C,ar.branch(0x368,0x4FC))
    write_image(source,0x4FC,'<7I',0x51000509,0x7103F53F,0x540007E8,
                adr(0x508,0x340,10),0x78697B8B,0x8B0B094A,0xD61F0140)
    write_image(source,0x4800,'<254H',*([0]*253+[200]))
    write_image(source,0x660,'<I',0x52800552)
    return source,0x514,0x50C


def masked_source(width=0):
    source=source_base()
    if width==0:
        write_image(source,0x300,'<I',ar.branch(0x300,0x360))
        write_image(source,0x360,'<3I',0x90000021,0x91200021,ar.branch(0x368,0x3C0))
        write_image(source,0x3C0,'<8I',0x12001D4F,0x510009EF,0x710011FF,0x54000CA8,
                    adr(0x3D0,0x340,16),0x386F6831,0x8B110A10,0xD61F0200)
        write_image(source,0x4800,'<5B',14,18,14,0,0);write_image(source,0x388,'<I',0x52800552)
        return source,0x3DC,0x3D4
    target,loaded,table,index,alias=(10,13,14,9,9) if width==1 else (13,14,15,10,13)
    write_image(source,0x3C0,'<10I',0x12001C00|(10<<5)|alias,0x7100181F|(alias<<5),0x54000CC8,
                0x92401C00|(10<<5)|index,0x90000020|table,0x91200000|(table<<5)|table,
                adr(0x3D8,0x3E8,target),(0x38606800 if width==1 else 0x78607800)|(index<<16)|(table<<5)|loaded,
                0x8B000800|(loaded<<16)|(target<<5)|target,0xD61F0000|(target<<5))
    values=[0,77,87,96,107,136,146] if width==1 else [0,131,194,256,316,364,427]
    write_image(source,0x4800,'<7'+('B' if width==1 else 'H'),*values)
    write_image(source,0x3E8+values[-1]*4,'<I',0x52800552)
    return source,0x3E4,0x3DC


class NativeAliasTableTests(unittest.TestCase):
    def test_masked_backward_and_both_low8_alias_widths_discover_and_execute(self):
        for width in (0,1,2):
            source,branch,load=masked_source(width)
            with self.subTest(width=width):
                _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==branch)
                self.assertEqual(plan['table_bytes'],5 if width==0 else 7*width)
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
                model=Machine(image);model.x[10]=(1<<40)|(3 if width==0 else 6);hardware=model.x[18];model.run()
                target,loaded,index=((16,17,15) if width==0 else (10,13,9) if width==1 else (13,14,10))
                self.assertEqual((model.x[target],model.x[loaded],model.x[index]),
                                 (0x388,18,1) if width==0 else (0x630,146,6) if width==1 else (0xA94,427,6))
                self.assertEqual((model.x[18],model.load(model.state,8)),(hardware,42))
                for entry in (load+4,branch):
                    with self.assertRaises(ar.RewriteError):
                        image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
        for width,pc in ((0,0x3C4),(1,0x3CC),(2,0x3CC)):
            source,branch,_=masked_source(width);write_image(source,pc,'<I',0xD503201F)
            if width in (0,1):
                # The actual index still has a finite CMP candidate; its full
                # value is rechecked after the unchanged NOP/prefix executes.
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
                assert_normalized_guard(self,source,image,branch)
            else:
                # W13 is only an alias here; there is no actual W10 CMP.
                with self.assertRaises(ar.RewriteError):
                    image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))

    def test_side_read_precedes_index_copy_for_normal_and_real_join_entry(self):
        source,branch,load=side_copy()
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        self.assertIn(0x81C,report['code_discovery']['roots'])
        for entry in (0x300,load-20):
            image=image_for(source,entry=entry,entry_offsets=(load-20,),proven_guest_indirect_offsets=(branch,))
            model=Machine(image);model.x[0]=0x7000;model.x[21]=1
            model.store(0x7000,0x55,1);hardware=model.x[18];model.run()
            self.assertEqual((model.x[0],model.x[4],model.x[5],model.x[6],model.x[18]),(1,0x4E0,0x55,62,hardware))
        image=image_for(source,entry=load,entry_offsets=(load,),proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[0]=1<<32;model.x[7]=0x4800;model.x[4]=0x3E8
        before=list(model.x);model.flags=0xA0000000
        with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
        self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))

    def test_large_subtract_one_table_checks_endpoint_complete_ro_and_full_index(self):
        source,branch,load=large_sub()
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==branch)
        self.assertEqual((plan['index_bound'],plan['table_bytes']),(253,508))
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[8]=254;model.run()
        self.assertEqual((model.x[9],model.x[10],model.x[11]),(253,0x660,200))
        for index in (254,1<<32):
            image=image_for(source,entry=load-4,entry_offsets=(load-4,),proven_guest_indirect_offsets=(branch,))
            model=Machine(image);model.x[9]=index;model.x[28]=0x4800;before=list(model.x)
            with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            before[10]=0x340;self.assertEqual(model.x,before)
        with self.assertRaises(ar.RewriteError):
            image_for(source,entry=0x300,readonly_ranges=((0x4800,0x49FB),),proven_guest_indirect_offsets=(branch,))
        for pc,word in ((0x4FC,0x51000909),(0x500,0x7103F93F)):
            altered=bytearray(source);write_image(altered,pc,'<I',word)
            with self.assertRaises(ar.RewriteError):image_for(altered,entry=0x300,proven_guest_indirect_offsets=(branch,))

    def test_side_copy_preserves_read_variants_and_rejects_missing_bound_or_late_entry(self):
        source,branch,load=side_copy()
        image=image_for(source,entry=0x300,entry_offsets=(load-24,),proven_guest_indirect_offsets=(branch,))
        assert_normalized_guard(self,source,image,branch)
        for entry in (load+4,branch):
            with self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
        for pc,word in ((load-20,0x39400405),(load-16,0xAA1503E0)):
            altered=bytearray(source);write_image(altered,pc,'<I',word)
            if pc==load-20:
                image=image_for(altered,entry=0x300,proven_guest_indirect_offsets=(branch,))
                assert_normalized_guard(self,altered,image,branch)
            else:
                with self.assertRaises(ar.RewriteError):
                    image_for(altered,entry=0x300,proven_guest_indirect_offsets=(branch,))


if __name__=='__main__':unittest.main()
