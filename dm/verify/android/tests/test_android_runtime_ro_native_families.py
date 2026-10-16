"""Bounded backward u16 and post-consumption MOV tails keep native BRs."""
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def backward_fixture(roles=(9,10,25,8),duplicate=False,forward=False):
    target,loaded,table,index=roles;source=source_base()
    prefix=[0x90000020|table,0x91200000|(table<<5)|table]
    if duplicate:prefix+=prefix
    prefix+=[ar.branch(0x300+4*len(prefix),0x3C0)]
    write_image(source,0x300,'<'+str(len(prefix))+'I',*prefix)
    base=0x3D8 if forward else 0x340
    write_image(source,0x3C0,'<6I',0x7100181F|(index<<5),0x54FFFDC8,
                adr(0x3C8,base,target),0x78607800|(index<<16)|(table<<5)|loaded,
                0x8B000800|(loaded<<16)|(target<<5)|target,0xD61F0000|(target<<5))
    write_image(source,0x4800,'<7H',0,*([64]*6))
    write_image(source,base+256,'<2I',0x52800312,0xD65F03C0)
    return source


def mov_fixture():
    source=source_base()
    write_image(source,0x300,'<3I',0x90000023,0x91200063,ar.branch(0x308,0x3C0))
    write_image(source,0x3C0,'<8I',0x710014DF,0x540002E8,adr(0x3C8,0x3E0,7),
                0x38666860,0x8B0008E7,0xAA1503E0,0xAA0103E4,0xD61F00E0)
    write_image(source,0x4800,'<6B',0,2,7,0,2,7)
    return source


def inline_fixture():
    source=source_base();write_image(source,0x300,'<I',ar.branch(0x300,0x3C0))
    write_image(source,0x3C0,'<8I',0x71001ADF,0x54000308,0x90000028,0x91200108,
                adr(0x3D0,0x3E0,9),0x7876790A,0x8B0A0929,0xD61F0120)
    write_image(source,0x4800,'<7H',0,*([64]*6))
    write_image(source,0x4E0,'<2I',0x52800312,0xD65F03C0)
    return source


class NativeTableFamilyTests(unittest.TestCase):
    def test_forward_halfword_direct_cmp_uses_prior_actual_ro_table(self):
        for roles in ((6,7,5,4),(9,10,25,8)):
            _,report=ai.import_module(backward_fixture(roles,forward=True),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-direct-cmp-prior-table-lsl2-v1')
            self.assertIn(0x4D8,report['code_discovery']['roots'])

    def test_u16_inline_direct_cmp_uses_actual_full64_without_zero_copy(self):
        _,report=ai.import_module(inline_fixture(),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-direct-cmp-inline-lsl2-v1')
        self.assertIn(0x4E0,report['code_discovery']['roots'])
        for entry in (0x3C8,0x3CC,0x3D0,0x3D4):
            image_for(inline_fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3DC,))
        source=inline_fixture()
        assert_normalized_guard(self,source,image_for(source,entry=0x300,entry_offsets=(0x3C4,),proven_guest_indirect_offsets=(0x3DC,)),0x3DC)
        for entry in (0x3D8,0x3DC):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(inline_fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3DC,))

    def test_u16_backward_full_index_and_equivalent_table_candidates(self):
        for roles in ((9,10,25,8),(7,19,1,6),(13,12,11,10)):
            for duplicate in (False,True):
                _,report=ai.import_module(backward_fixture(roles,duplicate),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                plan=report['code_discovery']['readonly_guest_jump_tables'][0]
                self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-backward-cmp-no-suffix-lsl2-v1')
                self.assertEqual((plan['base'],plan['table_bytes'],plan['target_values']),(0x340,14,[0,64]))
                self.assertIn(0x440,report['code_discovery']['roots'])

    def test_two_native_mov_tails_may_overwrite_consumed_loaded_register(self):
        source=mov_fixture()
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-cmp-two-mov-suffix-lsl2-v1')
        self.assertEqual(plan['preserved_source_offsets'],[0x3D4,0x3D8])
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3DC,))
        self.assertEqual(image.bytes[0x3D0:0x3E0],parse_nso(source).image[0x3D0:0x3E0])
        model=Machine(image);model.x[6]=2;model.x[21]=0xABCD1234;model.x[1]=0x1234ABCD
        model.run()
        self.assertEqual((model.x[0],model.x[4],model.x[7]),(0xABCD1234,0x1234ABCD,0x3FC))

    def test_ordinary_tail_keeps_guard_and_target_clobbers_or_postload_entries_refuse(self):
        source=backward_fixture()
        assert_normalized_guard(self,source,image_for(source,entry=0x300,entry_offsets=(0x3C4,),proven_guest_indirect_offsets=(0x3D4,)),0x3D4)
        for entry in (0x3D0,0x3D4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(backward_fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3D4,))
        with self.assertRaises(ar.RewriteError):
            image_for(backward_fixture(),entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x3D4,))
        for pc,word in ((0x3D4,0xAA1503E7),(0x3D8,0xAA0103E7),(0x3D4,0xAA1203E0)):
            source=mov_fixture();write_image(source,pc,'<I',word)
            with self.subTest(pc=hex(pc)),self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3DC,))
        source=mov_fixture();write_image(source,0x3D8,'<I',0x91000424)
        assert_normalized_guard(self,source,image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3DC,)),0x3DC)
        for entry in (0x3D0,0x3D4,0x3D8,0x3DC):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(mov_fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3DC,))

    def test_backward_preload_entrances_still_check_actual_values_before_read(self):
        for entry in (0x3C8,0x3CC):
            image_for(backward_fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3D4,))
        image=image_for(backward_fixture(),entry=0x3CC,proven_guest_indirect_offsets=(0x3D4,))
        for mode in ('upper','bound','table','base'):
            model=Machine(image);model.x[9]=0x340;model.x[25]=0x4800;model.x[8]=0
            if mode=='upper':model.x[8]=0x100000000
            if mode=='bound':model.x[8]=7
            if mode=='table':model.x[25]=0
            if mode=='base':model.x[9]=0
            before=list(model.x);model.flags=0xF0000000
            with self.subTest(mode=mode),self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xF0000000))


if __name__=='__main__':unittest.main()
