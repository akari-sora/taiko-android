"""A virtual table base is distinct from the platform X18 and native target."""
import struct
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(width=1,roles=(0,1,16)):
    target,loaded,index=roles;source=source_base()
    write_image(source,0x300,'<I',ar.branch(0x300,0x3C0))
    words=[0x7100141F|(index<<5),0x540004E8]
    if width==1:words += [0xB9405191]
    words += [0x90000032,0x91200252]
    at=0x3C0+4*len(words);words += [adr(at,0x3E4,target)]
    load=0x3C0+4*len(words)
    words += [(0x38606A40 if width==1 else 0x78607A40)|(index<<16)|loaded,
              0x8B000800|(loaded<<16)|(target<<5)|target]
    if width==2:words += [0xD1000B8D]
    words += [0xD61F0000|(target<<5)]
    write_image(source,0x3C0,'<'+str(len(words))+'I',*words)
    write_image(source,0x4800,'<6'+('B' if width==1 else 'H'),0,2,7,0,2,7)
    return source,load


class VirtualTableX18Tests(unittest.TestCase):
    def test_real_source_roles_have_guarded_virtual_table_and_native_branch(self):
        for width,roles in ((1,(0,1,16)),(1,(2,0,3)),(2,(16,17,15))):
            source,load=fixture(width,roles)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual((plan['virtual_table_register'],plan['target_register']),(18,roles[0]))
            self.assertEqual(plan['table_bytes'],6*width)
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3E0,))
            self.assertEqual(image.bytes[load+4:0x3E4],parse_nso(source).image[load+4:0x3E4])
            model=Machine(image);model.x[roles[2]]=2;hardware18=model.x[18]
            model.run()
            self.assertEqual((model.x[roles[0]],model.x[roles[1]]),(0x400,7))
            self.assertEqual((model.x[18],model.load(model.state,8),model.sp),(hardware18,0x4800,model.start_sp))

    def test_bad_actual_virtual_table_target_or_index_traps_before_original_read(self):
        for width,roles in ((1,(0,1,16)),(1,(2,0,3)),(2,(16,17,15))):
            source,load=fixture(width,roles)
            image=image_for(source,entry=load,proven_guest_indirect_offsets=(0x3E0,))
            for mode in ('null','table','base','upper','bound'):
                model=Machine(image);target,loaded,index=roles
                model.x[target]=0x3E4;model.x[index]=0;model.store(model.state,0x4800,8)
                if mode=='null':model.store(model.state,0,8)
                if mode=='table':model.store(model.state,0x4804,8)
                if mode=='base':model.x[target]=0
                if mode=='upper':model.x[index]=0x100000000
                if mode=='bound':model.x[index]=6
                before=list(model.x);virtual=model.load(model.state,8);model.flags=0xF0000000
                with self.subTest(width=width,roles=roles,mode=mode),self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xF0000000))
                self.assertEqual(model.load(model.state,8),virtual)

    def test_preload_entries_keep_effects_and_postload_entries_remain_rejected(self):
        for width in (1,2):
            source,load=fixture(width)
            for entry in range(load-12,load+4,4):
                image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3E0,))
            # Entering after CMP is safe only because the load checks the live
            # full-width index independently of the skipped compare/branch.
            image=image_for(source,entry=0x3C4,entry_offsets=(0x3C4,),proven_guest_indirect_offsets=(0x3E0,))
            for index in (2,6,1<<32):
                model=Machine(image);model.x[16]=index;hardware18=model.x[18]
                model.store(model.x[12]+80,0xCAFEBABE,4)
                if index==2:
                    model.run()
                    self.assertEqual((model.x[0],model.x[1]),(0x400,7))
                else:
                    before=list(model.x);before[0]=0x3E4
                    if width==1:before[17]=0xCAFEBABE
                    with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                    self.assertEqual(model.x,before)
                self.assertEqual((model.x[18],model.load(model.state,8),model.sp,model.flags),
                                 (hardware18,0x4800,model.start_sp,0x60000000))
                if width==1:self.assertEqual(model.x[17],0xCAFEBABE)
            for entry in (load+4,0x3E0):
                with self.subTest(width=width,entry=hex(entry)),self.assertRaises(ar.RewriteError):
                    image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3E0,))
            with self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x3E0,))
        source,_=fixture();write_image(source,0x3C8,'<I',0xB9405591)
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3E0,))
        model=Machine(image);model.x[16]=2
        model.store(model.x[12]+80,0xDEADBEEF,4);model.store(model.x[12]+84,0xCAFEBABE,4)
        model.run()
        self.assertEqual((model.x[0],model.x[1],model.x[17]),(0x400,7,0xCAFEBABE))


if __name__=='__main__':unittest.main()
