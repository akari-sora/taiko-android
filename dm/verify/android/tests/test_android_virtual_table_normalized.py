"""Ordinary prefix/suffix effects around a checked virtual-X18 table read."""
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(width=1):
    source=source_base()
    write_image(source,0x300,'<3I',0x90000032,0x91200252,ar.branch(0x308,0x3C0))
    write_image(source,0x3C0,'<8I',0x710075FF,0x540029E8,0x8B0E0014,adr(0x3CC,0x3E0,16),
                0x386F6A51 if width==1 else 0x786F7A51,0x8B110A10,0x8B0D028E,0xD61F0200)
    values=[0]*30;values[15]=7;values[-1]=53
    write_image(source,0x4800,'<30'+('B' if width==1 else 'H'),*values)
    write_image(source,0x4B4,'<I',0x52800552)
    return source


class NormalizedVirtualTableTests(unittest.TestCase):
    def test_two_original_add_effects_and_virtual_table_survive_the_actual_guard(self):
        for width in (1,2):
            source=fixture(width)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==0x3DC)
            self.assertEqual((plan['virtual_table_register'],plan['permitted_source_rewrite_offsets']),(18,[0x3D0]))
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3DC,))
            model=Machine(image);model.x[15]=15;model.x[0]=1000;model.x[14]=2000;model.x[13]=30;hardware=model.x[18];model.run()
            self.assertEqual((model.x[20],model.x[14],model.x[16],model.x[17],model.x[18],model.load(model.state,8)),
                             (3000,3030,0x3FC,7,hardware,0x4800))
            self.assertEqual(model.flags,0x80000000)
            raw=parse_nso(source).image
            for pc in (0x3C8,0x3CC,0x3D4,0x3D8,0x3DC):self.assertEqual(image.bytes[pc:pc+4],raw[pc:pc+4])

    def test_direct_entry_full_values_and_prefix_effects_are_checked_before_read(self):
        for entry in (0x3C8,0x3CC,0x3D0):
            image=image_for(fixture(),entry=entry,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3DC,))
            for bad in ('table','base','upper','bound'):
                if bad=='base' and entry!=0x3D0:continue
                model=Machine(image);model.x[0]=1000;model.x[14]=2000;model.x[15]=0;model.x[16]=0x3E0
                model.store(model.state,0x4800,8);model.flags=0xA0000000
                if bad=='table':model.store(model.state,0,8)
                elif bad=='base':model.x[16]+=4
                else:model.x[15]=1<<32 if bad=='upper' else 30
                before=list(model.x);state=model.load(model.state,8)
                with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                if entry==0x3C8:before[20]=3000
                if entry!=0x3D0:before[16]=0x3E0
                self.assertEqual((model.x,model.sp,model.flags,model.load(model.state,8)),(before,model.start_sp,0xA0000000,state))

    def test_no_postload_entry_target_change_extra_x18_or_wide_virtual_domain(self):
        source=fixture()
        for entry in (0x3D4,0x3D8,0x3DC):
            with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3DC,))
        for pc,value in ((0x3D8,0xAA0D03F0),(0x3D8,0xAA1203EE),(0x3D8,0x94000001),(0x3C0,0x710101FF)):
            changed=bytearray(source);write_image(changed,pc,'<I',value)
            with self.assertRaises(ar.RewriteError):image_for(changed,entry=0x300,proven_guest_indirect_offsets=(0x3DC,))
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x3DC,))


if __name__=='__main__':unittest.main()
