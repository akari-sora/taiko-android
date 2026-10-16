"""The 160-byte table keeps its intervening virtual-x18 store effect."""
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(roles=(3,4,2,1),bound=159,sp_store=False):
    target,loaded,table,index=roles;source=source_base()
    if sp_store:
        write_image(source,0x300,'<2I',0xD10103FF,ar.branch(0x304,0x3C0))
        for pc in (0x3E8,0x3F8):write_image(source,pc,'<2I',0x910103FF,0xD65F03C0)
    else:
        write_image(source,0x300,'<I',ar.branch(0x300,0x3C0))
    write_image(source,0x3C0,'<10I',(0x51000800 if sp_store else 0x51000400)|(index<<5)|index,
                0x7100001F|(bound<<10)|(index<<5),0xF9001BE0|target if sp_store else 0xB9000012|(target<<5),0x54000488,
                0x90000020|table,0x91200000|(table<<5)|table,adr(0x3D8,0x3E8,target),
                0x38606800|(index<<16)|(table<<5)|loaded,
                0x8B000800|(loaded<<16)|(target<<5)|target,0xD61F0000|(target<<5))
    write_image(source,0x4800,'<160B',0,*([4]*159))
    return source


class ScheduledStoreTests(unittest.TestCase):
    def test_old_target_saved_to_sp30_before_adr_is_not_discarded(self):
        source=fixture((9,10,11,8),3,True)
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual((plan['rule'],plan['table_bytes']),('runtime-base-index-u8-ro-sub-cmp-store-target-sp30-inline-lsl2-v1',4))
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3E4,))
        self.assertEqual(image.bytes[0x3C8:0x3CC],parse_nso(source).image[0x3C8:0x3CC])
        model=Machine(image);model.x[8]=3;model.x[9]=0x1122334455667788
        model.run()
        self.assertEqual((model.load(model.start_sp-16,8),model.x[9]),(0x1122334455667788,0x3F8))

    def test_full160_byte_table_and_original_virtual_store_are_retained(self):
        for roles in ((3,4,2,1),(9,10,11,8)):
            source=fixture(roles)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual((plan['rule'],plan['table_bytes']),('runtime-base-index-u8-ro-sub-cmp159-store-x18-inline-lsl2-v1',160))
            self.assertEqual(plan['permitted_source_rewrite_offsets'],[0x3C8])
            self.assertTrue(any(site['offset']==0x3C8 and 'w18' in site['instruction'] for site in report['rewrite']['sites']))
        image=image_for(fixture(),entry=0x3C0,proven_guest_indirect_offsets=(0x3E4,))
        model=Machine(image);model.x[1]=2;model.x[3]=0x9000;model.store(model.state,0x11223344,8)
        model.run()
        self.assertEqual(model.load(0x9000,4),0x11223344)
        self.assertEqual(model.x[3],0x3F8)

    def test_store_schedule_domain_and_postload_entries_remain_closed(self):
        for entry in (0x3D0,0x3D4,0x3D8,0x3DC):
            image_for(fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3E4,))
        for entry in (0x3C4,0x3C8,0x3CC,0x3E0,0x3E4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3E4,))
        for pc,word in ((0x3C0,0x51000821),(0x3C8,0xB9000472),(0x3C8,0xF9000072)):
            source=fixture();write_image(source,pc,'<I',word)
            with self.subTest(pc=hex(pc)),self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3E4,))
        source=fixture(bound=63)
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3E4,))
        assert_normalized_guard(self,source,image,0x3E4)
        for bound in (64,158,160):
            with self.subTest(bound=bound),self.assertRaises(ar.RewriteError):
                image_for(fixture(bound=bound),entry=0x300,proven_guest_indirect_offsets=(0x3E4,))


if __name__=='__main__':unittest.main()
