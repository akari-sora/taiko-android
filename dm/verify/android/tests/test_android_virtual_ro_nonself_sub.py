"""The SDK nonself-SUB schedule admits only guarded pre-load entrances."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture():
    source=source_base();write_image(source,0x300,'<I',ar.branch(0x300,0x3C0))
    write_image(source,0x3C0,'<10I',0x51008130,0x7100421F,0x54000608,
                0x90000031,0x91200231,adr(0x3D4,0x3E8,18),0x78707A20,
                0x8B000A52,0x5280004C,0xD61F0240)
    values=(0,2,4,6,7,13,32)+(0,)*10
    write_image(source,0x4800,'<17H',*values)
    return source


class VirtualNonselfSubTests(unittest.TestCase):
    def test_sdk_schedule_keeps_suffix_and_guards_each_preload_entry(self):
        source=fixture()
        for entry in (0x3CC,0x3D0,0x3D4,0x3D8):
            image=image_for(source,entry=0x3C0,entry_offsets=(entry,))
            plan=ar.x18_jump_table(ar.Instruction(next(ar.MD.disasm(parse_nso(source).image[0x3E4:0x3E8],0x3E4))),
                {op.address:ar.Instruction(op) for op in ar.MD.disasm(parse_nso(source).image[0x300:0x1000],0x300)},
                {entry},parse_nso(source).image,((0x4000,0x8000),),root_entries={entry})
            self.assertEqual(plan['rule'],'runtime-virtual-x18-u16-nonself-sub-inline-mov-lsl2-v1')
            self.assertEqual((plan['index_source_register'],plan['table_bytes']),(9,34))
            self.assertEqual(struct.unpack_from('<I',image.bytes,0x3E0)[0],0x5280004C)
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        self.assertEqual(report['code_discovery']['halfword_jump_tables'][0]['table_offset'],0x4800)

    def test_old_static_entry_policies_and_non_schedule_changes_still_refuse(self):
        for entry in (0x3C4,0x3C8,0x3DC,0x3E0,0x3E4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                image_for(fixture(),entry=0x3C0,entry_offsets=(entry,))
        for pc,word in ((0x3C0,0x51008210), # self-SUB is the existing static class
                        (0x3C0,0xD1008130), # X SUB does not zero-extend
                        (0x3C8,0x54000602), # wrong comparison condition
                        (0x3E0,0x52800050), # suffix overwrites live index
                        (0x3E0,0x52800040), # suffix overwrites loaded value
                        (0x3E0,0x9100058C)): # a different instruction family
            source=fixture();write_image(source,pc,'<I',word)
            with self.subTest(pc=hex(pc),word=hex(word)),self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x3C0,entry_offsets=(0x3CC,))
        with self.assertRaises(ar.RewriteError):
            image_for(fixture(),entry=0x3C0,entry_offsets=(0x3CC,),readonly_ranges=())

    def test_actual_load_guard_refuses_full64_before_read_and_restores_state(self):
        image=image_for(fixture(),entry=0x3D8,entry_offsets=(0x3CC,))
        for index in (17,0x100000000,0xFFFFFFFFFFFFFFFF):
            model=Machine(image);model.store(model.state,0x3E8,8)
            model.x[17]=0x4800;model.x[16]=index;model.flags=0xA0000000
            before=list(model.x)
            with self.subTest(index=index),self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual(model.x,before)
            self.assertEqual((model.sp,model.flags),(model.start_sp,0xA0000000))


if __name__=='__main__':unittest.main()
