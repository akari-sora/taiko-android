"""UTF conversion switches retain their exact post-load byte masks."""
import unittest
from test_android_guarded_native_table import fixture as native_fixture
from test_android_virtual_loaded_x18 import fixture as loaded_fixture
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,write_image
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(virtual_loaded):
    if virtual_loaded:
        source=loaded_fixture();suffix,branch=0x3D4,0x3D8
        write_image(source,suffix,'<2I',0x12001DEF,0xD61F0220)
        return source,0x3CC,suffix,branch,(13,16,17)
    source,branch=native_fixture();suffix=branch-4
    write_image(source,suffix,'<I',0x12001E52)
    return source,0x3D0,suffix,branch,(12,9,10)


class VirtualAndSuffixTests(unittest.TestCase):
    def test_original_mask_updates_only_its_guest_destination_after_the_read(self):
        for virtual_loaded in (False,True):
            source,load,suffix,branch,(table,index,target)=fixture(virtual_loaded)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==branch)
            self.assertEqual(plan['permitted_source_rewrite_offsets'],[load,load+4] if virtual_loaded else [suffix])
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
            model=Machine(image);model.x[index]=2;model.x[15]=0xFEDCBA9876543210
            model.store(model.state,0xAABBCCDD12345678,8);before=list(model.x)
            model.run()
            before[table]=0x4800;before[target]=0x35C
            if virtual_loaded:before[15]=0x10
            else:before[4]=(before[3]+9)&0xFFFFFFFF;before[11]=7
            self.assertEqual((model.x,model.load(model.state,8),model.sp,model.flags),
                             (before,7 if virtual_loaded else 0x78,model.start_sp,0x80000000))
            raw=parse_nso(source).image
            self.assertEqual(image.bytes[branch:branch+4],raw[branch:branch+4])
            self.assertEqual(image.bytes[suffix:suffix+4]==raw[suffix:suffix+4],virtual_loaded)

    def test_before_read_failure_does_not_run_either_mask(self):
        for virtual_loaded in (False,True):
            source,load,suffix,branch,(table,index,target)=fixture(virtual_loaded)
            image=image_for(source,entry=load,proven_guest_indirect_offsets=(branch,))
            for mode in ('upper','bound','table','base'):
                model=Machine(image);model.x[table]=0x4800;model.x[index]=0;model.x[target]=0x340
                model.x[15]=0xFEDCBA9876543210;model.store(model.state,0xAABBCCDD12345678,8)
                if mode=='upper':model.x[index]=(1<<32)|2
                elif mode=='bound':model.x[index]=4
                elif mode=='table':model.x[table]+=4
                else:model.x[target]=0
                before=list(model.x);model.flags=0xA0000000
                with self.subTest(virtual_loaded=virtual_loaded,mode=mode),self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                self.assertEqual((model.x,model.load(model.state,8),model.sp,model.flags),
                                 (before,0xAABBCCDD12345678,model.start_sp,0xA0000000))

    def test_only_the_exact_single_mask_and_preload_entry_are_admitted(self):
        for virtual_loaded in (False,True):
            source,load,suffix,branch,(table,index,target)=fixture(virtual_loaded)
            for entry in range(load+4,branch+4,4):
                with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
            reg=15 if virtual_loaded else 18
            invalid=(0x72001C00|(reg<<5)|reg,0x12001800|(reg<<5)|reg,
                     0x12001C00|(2<<5)|reg,0xAA1203EF)
            if virtual_loaded:invalid+=tuple(0x12001C00|(r<<5)|r for r in (table,index,target,18,29,30,31))
            for word in invalid:
                changed=bytearray(source);write_image(changed,suffix,'<I',word)
                with self.subTest(virtual_loaded=virtual_loaded,word=hex(word)),self.assertRaises(ar.RewriteError):
                    image_for(changed,entry=0x300,proven_guest_indirect_offsets=(branch,))
            with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(branch,))


if __name__=='__main__':unittest.main()
