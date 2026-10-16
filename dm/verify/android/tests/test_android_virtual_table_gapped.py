"""Selected ordinary setup between a virtual table's page and low address."""
import unittest
from test_android_virtual_table_hoisted import fixture as hoisted_fixture
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,write_image
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine

SIDE=(0xAA0003F4,0x91000835,0x52824696,0xAA1F03F7,0x12800018,0x11000739,0xAA0003F4)


def fixture(count=5):
    source=hoisted_fixture()
    write_image(source,0x304,'<'+str(count+2)+'I',*SIDE[:count],0x91200252,ar.branch(0x308+count*4,0x7D4))
    return source


class GappedVirtualTableTests(unittest.TestCase):
    def test_selected_gap_keeps_each_original_effect_and_the_actual_table_guard(self):
        for count in (1,5,6):
            source=fixture(count)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==0x7E8)
            self.assertEqual((plan['producer_offsets'][:2],plan['permitted_source_rewrite_offsets']),([0x300,0x304+count*4],[0x7E0]))
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x7E8,))
            model=Machine(image);model.x[8]=2;before=list(model.x);model.run()
            effects=(before[0],before[1]+2,0x1234,0,0xFFFFFFFF,(before[25]+1)&0xFFFFFFFF)
            for index,value in enumerate(effects[:count]):before[20+index]=value
            before[9]=0x8C0;before[10]=53
            self.assertEqual((model.x,model.load(model.state,8),model.sp,model.flags),(before,0x4800,model.start_sp,0x80000000))
            raw=parse_nso(source).image
            self.assertEqual(image.bytes[0x304:0x304+count*4],raw[0x304:0x304+count*4])

    def test_skipped_constructor_cannot_supply_a_wrong_table_or_full64_index(self):
        source=fixture();image=image_for(source,entry=0x7E0,proven_guest_indirect_offsets=(0x7E8,))
        for mode in ('table','base','upper','bound'):
            model=Machine(image);model.x[8]=2;model.x[9]=0x7EC;model.store(model.state,0x4800,8)
            if mode=='table':model.store(model.state,0x4804,8)
            elif mode=='base':model.x[9]=0
            else:model.x[8]=(1<<32)|2 if mode=='upper' else 4
            before=list(model.x);state=model.load(model.state,8);model.flags=0xA0000000
            with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual((model.x,model.load(model.state,8),model.sp,model.flags),(before,state,model.start_sp,0xA0000000))

    def test_gaps_must_be_complete_short_ordinary_setup(self):
        for word in (0xAA1203F4,0xAA0003F2,0x910043FF,0xAA1D03F4,0xAA1E03F4,0xB1000439,0xB9400014,0x94000001):
            source=fixture();write_image(source,0x30C,'<I',word)
            with self.subTest(word=hex(word)),self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x7E8,))
        with self.assertRaises(ar.RewriteError):image_for(fixture(7),entry=0x300,proven_guest_indirect_offsets=(0x7E8,))
        source=fixture();nso=parse_nso(source)
        by_pc={pc:ar.decode(int.from_bytes(nso.image[pc:pc+4],'little'),pc) for pc in range(0x300,0x1000,4)}
        del by_pc[0x30C]
        self.assertIsNone(ar._guarded_native_readonly_table(by_pc[0x7E8],by_pc,set(),nso.image,((0x4000,0x8000),),virtual_table=True))
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x7E8,))


if __name__=='__main__':unittest.main()
