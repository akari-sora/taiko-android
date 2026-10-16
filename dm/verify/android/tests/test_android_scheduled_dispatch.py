"""Finite scheduled loads and the two bound paths feeding virtual x18."""
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image, rewrite
from test_android_runtime_ro_backward import adr


def side_fixture(width,inline):
    source=source_base();write_image(source,0x300,'<I',ar.branch(0x300,0x3B8))
    compare,guard,side=0x7100143F,0x54000408,0xB942A111
    page,add=0x90000030,0x91200210
    prefix=(compare,guard,side,page,add) if inline else (page,add,compare,guard,side)
    load=(0x78607800 if width==2 else 0x38606800)|(1<<16)|(16<<5)|3
    write_image(source,0x3B8,'<9I',*prefix,adr(0x3CC,0x3DC,2),load,0x8B030842,0xD61F0040)
    write_image(source,0x4800,'<6'+('H' if width==2 else 'B'),0,2,32,64,128,200)
    write_image(source,0x6FC,'<I',0x52800552)
    return source


def dual_fixture():
    source=source_base()
    write_image(source,0x300,'<2I',0xB4000660,ar.branch(0x304,0x3C0))
    words=(0x710095BF,0x540000E9,ar.branch(0x3C8,0xA00),0xF9400C08,0xF940090B,0x2A1F03E8,
           0x710095BF,0x54003128,0xB940080A,0x90000030,0x91200210,0x2A0D03F1,
           adr(0x3F0,0x410,18),0x78717A07,0x8B070A52,0xAA1F03EE,0xAA1F03EC,0x528008CF,
           0x2A0D03F0,0xD61F0240)
    write_image(source,0x3C0,'<20I',*words)
    values=[2]*38;values[0]=0;values[-1]=400
    write_image(source,0x4800,'<38H',*values);write_image(source,0xA50,'<I',0x52800552)
    return source


class ScheduledDispatchTests(unittest.TestCase):
    def test_observed_68_and_18_side_loads_retain_virtual_x18_effects(self):
        for opcode in (0xB9406A52,0xB9401ACA):
            source=side_fixture(1,False);write_image(source,0x3C8,'<I',opcode)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual(plan['preserved_source_offsets'],[0x3C8])
            if opcode==0xB9406A52:
                self.assertTrue(any(site['offset']==0x3C8 and 'w18' in site['instruction'] for site in report['rewrite']['sites']))
        source=side_fixture(1,False);write_image(source,0x3C8,'<I',0xB9407252)
        # This ordinary x18 load uses the existing independent x18 rewrite.
        assert_normalized_guard(self,source,rewrite(source,0x3D8),0x3D8)

    def test_parallel_side_load_schedules_keep_effects_and_actual_guard(self):
        for width,inline in ((1,False),(1,True),(2,True)):
            source=side_fixture(width,inline)
            package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual(plan['rule'],f'runtime-base-index-u{width*8}-ro-cmp5-side-load-lsl2-v1')
            self.assertEqual((plan['index_bound'],plan['table_bytes']),(5,6*width))
            self.assertIn(0x6FC,report['code_discovery']['roots'])
            payload=struct.unpack_from('<Q',package,112)[0]
            side=0x3C0 if inline else 0x3C8
            self.assertEqual(struct.unpack_from('<I',package,payload+side)[0],0xB942A111)
            for entry in range((0x3B8 if inline else 0x3C0)+4,0x3DC,4):
                if entry<=0x3D0:
                    assert_normalized_guard(self,source,rewrite(source,0x3D8,entry_offsets=(entry,)),0x3D8)
                else:
                    with self.subTest(width=width,inline=inline,entry=hex(entry)),self.assertRaises(ar.RewriteError):
                        rewrite(source,0x3D8,entry_offsets=(entry,))
            for opcode in (0xB942A101,0xB942A112,0xF9415101,0xB942A511):
                changed=bytearray(source);write_image(changed,side,'<I',opcode)
                assert_normalized_guard(self,changed,rewrite(changed,0x3D8),0x3D8)

    def test_dual_guards_copy_only_proved_w_domain_and_keep_four_suffix_effects(self):
        source=dual_fixture()
        package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['halfword_jump_tables'][0]
        self.assertEqual(plan['rule'],'adr-br-next-u16-ro-dual-cmp37-wcopy-lsl2-v1')
        self.assertEqual((plan['table_bytes'],plan['count']),(76,512))
        self.assertIn(0xA50,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(package[payload+0x3FC:payload+0x40C],parse_nso(source).image[0x3FC:0x40C])
        rewrite(source,0x40C,proven_guest_indirect_offsets=())

    def test_dual_join_root_unknown_edge_and_producer_bypasses_refuse(self):
        source=dual_fixture()
        for entry in (0x3C4,0x3C8,*range(0x3DC,0x410,4)):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                rewrite(source,0x40C,proven_guest_indirect_offsets=(),entry_offsets=(entry,))
        changed=bytearray(source);write_image(changed,0x320,'<I',ar.branch(0x320,0x3E0))
        with self.assertRaises(ar.RewriteError):rewrite(changed,0x40C,proven_guest_indirect_offsets=())
        for pc,opcode in ((0x3C0,0x710099BF),(0x3D8,0x710091BF),(0x3EC,0xAA0D03F1),
                          (0x408,0x2A0D03E7),(0x3FC,0xAA1F03F2)):
            changed=bytearray(source);write_image(changed,pc,'<I',opcode)
            with self.subTest(pc=hex(pc)),self.assertRaises(ar.RewriteError):rewrite(changed,0x40C,proven_guest_indirect_offsets=())


if __name__=='__main__':unittest.main()
