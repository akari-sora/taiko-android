"""Hoisted virtual-X18 table candidates still require the actual guarded read."""
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(width=1):
    source=source_base()
    write_image(source,0x300,'<3I',0x90000032,0x91200252,ar.branch(0x308,0x7D4))
    write_image(source,0x7D4,'<6I',0x71000D1F,0x54000948,adr(0x7DC,0x7EC,9),
                0x38686A4A if width==1 else 0x78687A4A,0x8B0A0929,0xD61F0120)
    write_image(source,0x4800,'<4'+('B' if width==1 else 'H'),0,2,53,60)
    write_image(source,0x8DC,'<I',0x52800552)
    return source


class HoistedVirtualTableTests(unittest.TestCase):
    def test_selected_hoisted_constructor_unlocks_full_ro_targets(self):
        for width in (1,2):
            source=fixture(width)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==0x7E8)
            self.assertEqual((plan['virtual_table_register'],plan['table_offset'],plan['table_bytes']),(18,0x4800,4*width))
            self.assertEqual(plan['permitted_source_rewrite_offsets'],[0x7E0])
            self.assertIn(0x8DC,report['code_discovery']['roots'])
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x7E8,))
            model=Machine(image);model.x[8]=2;hardware=model.x[18];model.run()
            self.assertEqual((model.x[9],model.x[10],model.load(model.state,8),model.x[18]),(0x8C0,53,0x4800,hardware))

    def test_load_entry_checks_full_index_and_virtual_table_before_read(self):
        image=image_for(fixture(),entry=0x7E0,entry_offsets=(0x7E0,),proven_guest_indirect_offsets=(0x7E8,))
        for bad in ('table','base','upper','bound'):
            model=Machine(image);model.x[8]=0;model.x[9]=0x7EC;model.store(model.state,0x4800,8)
            if bad=='table':model.store(model.state,0x4804,8)
            elif bad=='base':model.x[9]+=4
            else:model.x[8]=1<<32 if bad=='upper' else 4
            before=list(model.x);state=model.load(model.state,8);model.flags=0xA0000000
            with self.subTest(bad=bad),self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual((model.x,model.sp,model.flags,model.load(model.state,8)),(before,model.start_sp,0xA0000000,state))

    def test_missing_or_ambiguous_ro_candidate_and_postload_entry_refuse(self):
        source=fixture()
        for entry in (0x7E4,0x7E8):
            with self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x7E8,))
        with self.assertRaises(ar.RewriteError):
            image_for(source,entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x7E8,))
        nso=parse_nso(source)
        by_pc={pc:ar.decode(int.from_bytes(nso.image[pc:pc+4],'little'),pc) for pc in range(0x7D4,0x7EC,4)}
        self.assertIsNone(ar._virtual_table_x18_native_target(by_pc[0x7E8],by_pc,set(),nso.image,((0x4000,0x8000),)))
        write_image(source,0x308,'<I',ar.branch(0x308,0x3C0))
        write_image(source,0x3C0,'<3I',0x90000032,0x91240252,ar.branch(0x3C8,0x7D4))
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x7E8,))


if __name__=='__main__':unittest.main()
