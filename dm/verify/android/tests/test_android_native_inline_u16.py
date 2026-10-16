"""Canonical inline native u16 tables retain a finite 256-entry limit."""
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(bound):
    source=source_base()
    guard=0x54000008|((0x900-0x3C4)//4<<5)
    write_image(source,0x3C0,'<8I',0x7100015F|(bound<<10),guard,0x9000002C,0x9120018C,
                adr(0x3D0,0x3E0,14),0x786A7990,0x8B1009CE,0xD61F01C0)
    write_image(source,0x4800,'<'+str(bound+1)+'H',*([0]*bound+[200]))
    write_image(source,0x700,'<I',0x52800552)
    return source


def alias_fixture(bound):
    source=source_base()
    guard=0x54000008|((0x900-0x3C4)//4<<5)
    write_image(source,0x3C0,'<9I',0x7100015F|(bound<<10),guard,0x2A0A03EE,0x9000002C,0x9120018C,
                adr(0x3D4,0x3E4,15),0x786E7990,0x8B1009EF,0xD61F01E0)
    write_image(source,0x4800,'<'+str(bound+1)+'H',*([0]*bound+[200]))
    write_image(source,0x704,'<I',0x52800552)
    return source


class NativeInlineU16Tests(unittest.TestCase):
    def test_canonical_wcopy_alias_preserves_copy_entry_and_checks_live_index(self):
        for bound in (120,255):
            source=alias_fixture(bound)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==0x3E0)
            self.assertEqual((plan['index_bound'],plan['table_bytes'],plan['bound_candidate_kind']),(bound,(bound+1)*2,'wcopy-cmp'))
            image=image_for(source,entry=0x3C8,entry_offsets=(0x3C8,),proven_guest_indirect_offsets=(0x3E0,))
            model=Machine(image);model.x[10]=(1<<32)|bound;hardware=model.x[18];model.run()
            self.assertEqual((model.x[14],model.x[15],model.x[16],model.x[18]),(bound,0x704,200,hardware))
            image=image_for(source,entry=0x3D8,entry_offsets=(0x3D8,),proven_guest_indirect_offsets=(0x3E0,))
            model=Machine(image);model.x[14]=(1<<32)|bound;model.x[12]=0x4800;model.x[15]=0x3E4
            before=list(model.x);model.flags=0xA0000000
            with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))
        with self.assertRaises(ar.RewriteError):image_for(alias_fixture(256),entry=0x300,proven_guest_indirect_offsets=(0x3E0,))
        source=alias_fixture(120);write_image(source,0x3C8,'<I',0xAA0A03EE)
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3E0,))

    def test_wide_alias_cannot_fall_back_to_prior_ro_if_inline_extent_is_invalid(self):
        for page,add in ((0x9000004C,0x9120018C),(0xF000002C,0x913FC18C)):
            source=alias_fixture(120)
            write_image(source,0x330,'<2I',0x9000002C,0x9120018C) # Earlier valid table4800.
            write_image(source,0x3CC,'<2I',page,add) # InlineBSS8800 or incompleteRO7ff0.
            with self.subTest(page=hex(page)),self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3E0,))

    def test_complete_64_120_and_255_bounds_discover_and_execute(self):
        for bound in (64,120,255):
            source=fixture(bound)
            with self.subTest(bound=bound):
                _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==0x3DC)
                self.assertEqual((plan['index_bound'],plan['table_bytes']),(bound,(bound+1)*2))
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3DC,))
                model=Machine(image);model.x[10]=bound;hardware=model.x[18];model.run()
                self.assertEqual((model.x[14],model.x[16],model.x[18],model.load(model.state,8)),(0x700,200,hardware,42))
                for index in (bound+1,(1<<32)|bound):
                    image=image_for(source,entry=0x3D4,entry_offsets=(0x3D4,),proven_guest_indirect_offsets=(0x3DC,))
                    model=Machine(image);model.x[10]=index;model.x[12]=0x4800;model.x[14]=0x3E0
                    before=list(model.x);model.flags=0xA0000000
                    with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                    self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))

    def test_larger_domain_noninline_or_incomplete_table_and_postload_entry_refuse(self):
        with self.assertRaises(ar.RewriteError):image_for(fixture(256),entry=0x300,proven_guest_indirect_offsets=(0x3DC,))
        source=fixture(120)
        for entry in (0x3D8,0x3DC):
            with self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3DC,))
        with self.assertRaises(ar.RewriteError):
            image_for(source,entry=0x300,readonly_ranges=((0x4800,0x48F1),),proven_guest_indirect_offsets=(0x3DC,))
        write_image(source,0x3C8,'<I',0xD503201F)
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3DC,))


if __name__=='__main__':unittest.main()
