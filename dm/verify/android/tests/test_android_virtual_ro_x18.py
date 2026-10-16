"""Virtual target, actual table/index, and before-read restoration are distinct."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_rewrite import Machine


def fixture(width=1,roles=(1,11,17),backward=True):
    loaded,table,index=roles;base=0x340 if backward else 0x3D8
    source=source_base();write_image(source,0x300,'<I',ar.branch(0x300,0x3B8))
    load=(0x78607800 if width==2 else 0x38606800)|(index<<16)|(table<<5)|loaded
    write_image(source,0x3B8,'<8I',0x7100141F|(index<<5),0x54000308,
                0x90000020|table,0x91200000|(table<<5)|table,adr(0x3C8,base,18),load,
                0x8B000A52|(loaded<<16),0xD61F0240)
    values=(0,2,32,64,128,200)
    write_image(source,0x4800,'<6'+('H' if width==2 else 'B'),*values)
    return source,base,load


def image_for(source,entry=0x3CC,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=entry,text_size=nso.sections[0].size,code_ranges=((0x300,0x1000),),
                 package_version=2,checked_stack=True,readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class VirtualRoX18Tests(unittest.TestCase):
    def test_finite_original_roles_prefer_real_table_targets_over_all256(self):
        for width in (1,2):
            source,base,_=fixture(width)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plans=report['code_discovery']['halfword_jump_tables']
            plan=next(p for p in plans if p['offset']==0x3D4)
            self.assertEqual((plan['load_offset'],plan['base'],plan['table_bytes']),(0x3CC,base,6*width))
            self.assertEqual(plan['target_values'],[0,2,32,64,128,200])
            self.assertEqual(plan['virtual_target_register'],18)

    def test_new_call_guard_preserves_every_unconsumed_gpr_and_flags(self):
        for roles in ((1,11,17),(1,11,16),(1,16,17),(16,11,17)):
            source,base,_=fixture(1,roles);image=image_for(source)
            for index in (0,5):
                model=Machine(image);loaded,table,idx=roles
                model.store(model.state,base,8);model.x[table]=0x4800;model.x[idx]=index
                model.flags=0xA0000000;before=list(model.x)
                model.run()
                expected=before;expected[loaded]=(0,2,32,64,128,200)[index]
                self.assertEqual(model.x,expected)
                self.assertEqual(model.load(model.state,8),base+4*expected[loaded])
                self.assertEqual((model.sp,model.flags),(model.start_sp,0xA0000000))

    def test_bad_full64_index_base_and_table_restore_before_original_read(self):
        source,base,_=fixture();image=image_for(source)
        for mode in ('base','table','index','upper','max'):
            model=Machine(image);model.store(model.state,base,8);model.x[11]=0x4800;model.x[17]=0
            if mode=='base':model.store(model.state,base+4,8)
            if mode=='table':model.x[11]=0
            if mode=='index':model.x[17]=6
            if mode=='upper':model.x[17]=0x100000000
            if mode=='max':model.x[17]=0xFFFFFFFFFFFFFFFF
            before=list(model.x);original_virtual=model.load(model.state,8);model.flags=0xF0000000
            with self.subTest(mode=mode),self.assertRaisesRegex(AssertionError,'instruction brk'):
                model.run()
            self.assertEqual(model.x,before)
            self.assertEqual((model.sp,model.flags),(model.start_sp,0xF0000000))
            self.assertEqual(model.load(model.state,8),original_virtual)

    def test_after_load_entries_unknown_table_and_source_clobbers_refuse(self):
        source,_,_=fixture()
        for entry in (0x3D0,0x3D4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(source,entry_offsets=(entry,))
        with self.assertRaises(ar.RewriteError):image_for(source,readonly_ranges=())
        changed=bytearray(source);write_image(changed,0x3D0,'<I',0x8B020A52)
        with self.assertRaises(ar.RewriteError):image_for(changed)


if __name__=='__main__':unittest.main()
