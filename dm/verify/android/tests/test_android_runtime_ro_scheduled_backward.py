"""The real subsdk schedule must expose its RO-selected x18 case tails."""
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for


def fixture(roles=(26,27,0,22)):
    target,loaded,table,index=roles
    source=source_base()
    write_image(source,0x300,'<3I',0x90000020|table,0x91200000|(table<<5)|table,ar.branch(0x308,0x3C0))
    write_image(source,0x3C0,'<12I',0x7100501F|(index<<5),0x54FFFBC8,0xF9403660|target,
                0x93407CE7,0x8B070AF5,0x8B0A02B5,0x9B0B00E7|(target<<10),
                adr(0x3DC,0x340,target),0x38606800|(index<<16)|(table<<5)|loaded,
                0x8B000800|(loaded<<16)|(target<<5)|target,0x910110E7,0xD61F0000|(target<<5))
    write_image(source,0x4800,'<21B',0,*([64]*20))
    write_image(source,0x440,'<2I',0x52800312,0xD65F03C0)
    return source


class ScheduledBackwardTests(unittest.TestCase):
    def test_real_schedule_ro_targets_expose_and_rewrite_case_tail(self):
        for roles in ((26,27,0,22),(10,11,9,8),(26,0,17,16)):
            source=fixture(roles)
            package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==0x3EC)
            self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-scheduled-backward-cmp20-lsl2-v1')
            self.assertEqual((plan['table_offset'],plan['table_bytes'],plan['target_values']),(0x4800,21,[0,64]))
            self.assertIn(0x440,report['code_discovery']['roots'])
            self.assertTrue(any(site['offset']==0x440 for site in report['rewrite']['sites']))
            payload=struct.unpack_from('<Q',package,112)[0]
            original=parse_nso(source).image
            for start,end in ((0x3C8,0x3DC),(0x3E4,0x3F0)):
                self.assertEqual(package[payload+start:payload+end],original[start:end])

    def test_prefix_variants_keep_actual_read_guard_without_host_branch_authority(self):
        for pc,word in ((0x3C0,0x710056DF),(0x3C8,0xF9403A7A),(0x3D8,0x9B0B6CE7),
                        (0x3E8,0x910114E7),(0x3E8,0x910110F6)):
            source=fixture();write_image(source,pc,'<I',word)
            with self.subTest(pc=hex(pc),word=hex(word)):
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(0x3EC,))
                assert_normalized_guard(self,source,image,0x3EC)
        for entry in range(0x3C4,0x3E4,4):
            source=fixture()
            image=image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3EC,))
            assert_normalized_guard(self,source,image,0x3EC)
        for entry in range(0x3E4,0x3F0,4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(fixture(),entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(0x3EC,))
        with self.assertRaises(ar.RewriteError):
            image_for(fixture(),entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(0x3EC,))


if __name__=='__main__':unittest.main()
