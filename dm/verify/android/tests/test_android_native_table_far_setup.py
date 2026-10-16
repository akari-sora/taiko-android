"""Far u16 setup retains ordinary arithmetic and a non-writeback stack store."""
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine

SIDE=(0xAA1F03F0,0x4B1C0C51,0x52800102,0x91002863,0xA90003E8,0x90000028,0x910E2108,0x52800284,0x52800545)


def fixture(extra=False):
    source=source_base();write_image(source,0x300,'<2I',0xD10083FF,0x9000002C)
    side=SIDE+((0xAA0003F5,) if extra else ())
    add=0x308+len(side)*4
    write_image(source,0x308,'<'+str(len(side)+2)+'I',*side,0x9120018C,ar.branch(add+4,0xD00))
    write_image(source,0xD00,'<6I',0x71000D3F,0x540003E8,adr(0xD08,0x340,10),0x7869798B,0x8B0B094A,0xD61F0140)
    write_image(source,0x4800,'<4H',0,2,7,12)
    for target in (0x340,0x348,0x35C,0x370):write_image(source,target,'<2I',0x910083FF,0xD65F03C0)
    return source


class FarNativeTableSetupTests(unittest.TestCase):
    def test_byte_setup_allows_ten_original_operations_and_retains_frame_read(self):
        source=fixture(True);write_image(source,0x32C,'<I',0xF85A03B7)
        write_image(source,0xD0C,'<I',0x3869698B);write_image(source,0x4800,'<4B',0,2,7,12)
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0xD14,))
        model=Machine(image);model.x[9]=2;model.x[29]=0x7000;model.store(0x6FA0,0xAABBCCDD12345678,8)
        hardware18=model.x[18];model.run()
        self.assertEqual((model.x[10],model.x[11],model.x[12],model.x[23],model.x[18],model.sp),
                         (0x35C,7,0x4800,0xAABBCCDD12345678,hardware18,model.start_sp))
        raw=parse_nso(source).image
        self.assertEqual(image.bytes[0x308:0x330],raw[0x308:0x330])
        write_image(source,0x330,'<3I',0x910006B5,0x9120018C,ar.branch(0x338,0xD00))
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(0xD14,))

    def test_u16_setup_wide_compare_keeps_complete_ro_and_full64_guard(self):
        for bound in (84,255):
            source=fixture();write_image(source,0xD00,'<I',0x7100013F|(bound<<10))
            tags=[(0,2,7,12)[i%4] for i in range(bound+1)]
            write_image(source,0x4800,'<'+str(len(tags))+'H',*tags)
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0xD14,))
            for index in (0,63,64,bound):
                model=Machine(image);model.x[9]=index;model.run()
                self.assertEqual((model.x[10],model.x[11],model.sp),(0x340+4*tags[index],tags[index],model.start_sp))
            raw=parse_nso(source).image
            self.assertEqual(image.bytes[0x4800:0x4800+2*len(tags)],raw[0x4800:0x4800+2*len(tags)])
            from dataclasses import replace
            for index in (bound+1,(1<<32)|2):
                model=Machine(replace(image,entry_offset=0xD0C));model.x[9]=index;model.x[10]=0x340;model.x[12]=0x4800
                before=list(model.x);model.flags=0xA0000000
                with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))
        write_image(source,0xD00,'<I',0x7104013F) # 256 exceeds this finite sibling.
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(0xD14,))
        source=fixture();write_image(source,0xD00,'<I',0x7101513F)
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,readonly_ranges=((0x4800,0x48A9),),proven_guest_indirect_offsets=(0xD14,))

    def test_original_setup_store_and_guarded_u16_result_are_preserved(self):
        source=fixture()
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==0xD14)
        self.assertEqual((plan['producer_offsets'][:2],plan.get('permitted_source_rewrite_offsets',[])),([0x304,0x32C],[]))
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0xD14,))
        model=Machine(image);model.x[9]=2;before=list(model.x);model.run()
        before[16]=0;before[17]=(before[2]-(before[28]<<3))&0xFFFFFFFF;before[2]=8
        before[3]+=10;before[8]=0x4388;before[4]=0x14;before[5]=0x2A
        before[12]=0x4800;before[10]=0x35C;before[11]=7
        self.assertEqual((model.x,model.sp),(before,model.start_sp))
        self.assertEqual((model.load(model.start_sp-32,8),model.load(model.start_sp-24,8)),(0x108,0x100))
        raw=parse_nso(source).image
        self.assertEqual(image.bytes[0x308:0x32C],raw[0x308:0x32C])

    def test_skipped_setup_checks_live_values_before_read(self):
        image=image_for(fixture(),entry=0xD0C,proven_guest_indirect_offsets=(0xD14,))
        for mode in ('table','base','upper','bound'):
            model=Machine(image);model.x[12]=0x4800;model.x[10]=0x340;model.x[9]=2
            if mode=='table':model.x[12]+=2
            elif mode=='base':model.x[10]=0
            else:model.x[9]=(1<<32)|2 if mode=='upper' else 4
            before=list(model.x);model.flags=0xA0000000
            with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))

    def test_long_missing_or_clobbering_setup_and_ambiguous_tables_refuse(self):
        for value in (0xAA0003EC,0xAA1203F0,0x910043FF,0xB1000430,0x94000001):
            source=fixture();write_image(source,0x310,'<I',value)
            with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(0xD14,))
        with self.assertRaises(ar.RewriteError):image_for(fixture(True),entry=0x300,proven_guest_indirect_offsets=(0xD14,))
        source=fixture();nso=parse_nso(source)
        by_pc={pc:ar.decode(int.from_bytes(nso.image[pc:pc+4],'little'),pc) for pc in range(0x300,0x1000,4)}
        del by_pc[0x310]
        self.assertIsNone(ar._guarded_native_readonly_table(by_pc[0xD14],by_pc,set(),nso.image,((0x4000,0x8000),)))
        # A second genuinely composed far address is not resolved by proximity.
        source=fixture();write_image(source,0x380,'<3I',0x9000002C,0xAA0003F0,0x9124018C)
        with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(0xD14,))


if __name__=='__main__':unittest.main()
