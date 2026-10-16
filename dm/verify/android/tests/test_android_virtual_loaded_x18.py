"""Read into guest virtual X18 without reading or writing platform X18."""
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(width=1):
    source=source_base();write_image(source,0x300,'<3I',0x9000002D,0x912001AD,ar.branch(0x308,0x3C0))
    write_image(source,0x3C0,'<6I',0x71000E1F,0x54FFFCC8,adr(0x3C8,0x340,17),
                (0x386069B2 if width==1 else 0x786079B2)|(16<<16),0x8B120A31,0xD61F0220)
    write_image(source,0x4800,'<4'+('B' if width==1 else 'H'),0,2,7,64)
    return source


class VirtualLoadedX18Tests(unittest.TestCase):
    def test_x_compare_uses_the_same_live_full64_guard_and_virtual_destination(self):
        for width in (1,2):
            source=fixture(width);write_image(source,0x3C0,'<I',0xF1000E1F)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual((plan['index_bound'],plan['virtual_loaded_register']),(3,18))
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3D4,))
            model=Machine(image);model.x[16]=2;hardware18=model.x[18];model.run()
            self.assertEqual((model.x[17],model.load(model.state,8),model.x[18],model.sp),
                             (0x35C,7,hardware18,model.start_sp))
            # ADR/load entries cannot borrow the earlier compare as authority.
            for entry in (0x3C8,0x3CC):
                image=image_for(source,entry=entry,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3D4,))
                for mode in ('upper','bound','table','base'):
                    model=Machine(image);model.x[13]=0x4800;model.x[17]=0x340;model.x[16]=0
                    model.store(model.state,0xAABBCCDD11223344,8);model.flags=0xA0000000
                    if mode=='upper':model.x[16]=1<<32
                    elif mode=='bound':model.x[16]=4
                    elif mode=='table':model.x[13]+=4
                    elif mode=='base':
                        if entry!=0x3CC:continue
                        model.x[17]=0
                    before=list(model.x)
                    if entry==0x3C8:before[17]=0x340
                    with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                    self.assertEqual((model.x,model.sp,model.flags,model.load(model.state,8)),
                                     (before,model.start_sp,0xA0000000,0xAABBCCDD11223344))
            for compare in (0xF1400E1F,0xF101021F,0xF1000DFF):
                changed=bytearray(source);write_image(changed,0x3C0,'<I',compare)
                with self.assertRaises(ar.RewriteError):image_for(changed,entry=0x300,proven_guest_indirect_offsets=(0x3D4,))

    def test_local_table_redefinition_retires_the_previous_switch_candidate(self):
        source=fixture()
        write_image(source,0x308,'<I',ar.branch(0x308,0x330))
        write_image(source,0x330,'<2I',0x9000002D,0x912401AD)
        write_image(source,0x338,'<34I',*([0xD503201F]*34))
        write_image(source,0x3C8,'<I',adr(0x3C8,0x3D8,17))
        write_image(source,0x4900,'<4B',0,2,7,64)
        write_image(source,0x4D8,'<I',0x52800552)
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual((plan['table_offset'],plan['reaching_table_producer_offsets']),(0x4900,[0x330,0x334]))
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3D4,))
        model=Machine(image);model.x[16]=2;hardware=model.x[18];model.run()
        self.assertEqual((model.x[17],model.load(model.state,8),model.x[18]),(0x3F4,7,hardware))
        image=image_for(source,entry=0x3CC,proven_guest_indirect_offsets=(0x3D4,))
        model=Machine(image);model.x[13]=0x4800;model.x[16]=2;model.x[17]=0x3D8
        before=list(model.x);model.flags=0xA0000000;model.store(model.state,0xABCDEF,8)
        with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
        self.assertEqual((model.x,model.sp,model.flags,model.load(model.state,8)),(before,model.start_sp,0xA0000000,0xABCDEF))
        for word in (0xAA0403ED,0x94000001): # An unknown table write or call destroys the local proof.
            altered=bytearray(source);write_image(altered,0x3B0,'<I',word)
            with self.assertRaises(ar.RewriteError):
                image_for(altered,entry=0x300,proven_guest_indirect_offsets=(0x3D4,))

    def test_success_writes_only_virtual_destination_then_original_add(self):
        for width in (1,2):
            source=fixture(width)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual((plan['virtual_loaded_register'],plan['loaded_register'],plan['table_bytes']),(18,18,width*4))
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3D4,))
            model=Machine(image);model.x[16]=2;model.store(model.state,0xABCD1234,8);hardware18=model.x[18]
            model.run()
            self.assertEqual((model.x[17],model.load(model.state,8),model.x[18]),(0x35C,7,hardware18))

    def test_pre_read_failure_retains_old_virtual18_and_every_gpr(self):
        for width in (1,2):
            image=image_for(fixture(width),entry=0x3CC,proven_guest_indirect_offsets=(0x3D4,))
            for mode in ('null','wrongtable','wrongbase','upper','bound'):
                model=Machine(image);model.x[13]=0x4800;model.x[17]=0x340;model.x[16]=0
                model.store(model.state,0xAABBCCDD11223344,8)
                if mode=='null':model.x[13]=0
                if mode=='wrongtable':model.x[13]=0x4804
                if mode=='wrongbase':model.x[17]=0
                if mode=='upper':model.x[16]=0x100000000
                if mode=='bound':model.x[16]=4
                before=list(model.x);model.flags=0xA0000000
                with self.subTest(width=width,mode=mode),self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))
                self.assertEqual(model.load(model.state,8),0xAABBCCDD11223344)

    def test_unknown_ro_and_postload_entry_remain_rejected(self):
        for entry in (0x3C4,0x3D0,0x3D4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3D4,))
        for entry in (0x3C8,0x3CC):
            image_for(fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3D4,))
        with self.assertRaises(ar.RewriteError):
            image_for(fixture(),entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x3D4,))


if __name__=='__main__':unittest.main()
