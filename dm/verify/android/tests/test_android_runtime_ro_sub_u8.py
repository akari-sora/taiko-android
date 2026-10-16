"""A byte switch keeps its original SUB and validates its full64 load index."""
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image, rewrite


def fixture(bound=40, source_register=12):
    source=source_base()
    words=(0x53107D4C,0x5100440B|(source_register<<5),0x7100001F|(bound<<10)|(11<<5),
           0x54000128,0x9000002E,0x912001CE,0x1000008C,0x386B69CD,0x8B0D098C,0xD61F0180)
    write_image(source,0x3BC,'<10I',*words)
    values=[23]*(bound+1);values[0]=0;values[-1]=200
    write_image(source,0x4800,'<'+str(bound+1)+'B',*values)
    write_image(source,0x704,'<I',0x52800552)
    return source


class RuntimeRoSubU8Tests(unittest.TestCase):
    def test_cross_register_sub_is_preserved_and_full64_index_checked(self):
        source=fixture()
        package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-sub-inline-lsl2-v1')
        self.assertEqual((plan['index_bound'],plan['table_bytes'],plan['index_source_register'],plan['index_subtract_immediate']),(40,41,12,17))
        self.assertIn(0x704,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(package[payload+0x3BC:payload+0x3C4],parse_nso(source).image[0x3BC:0x3C4])
        result=rewrite(source,0x3E0)
        load=next(site for site in result.sites if site.offset==0x3D8)
        code=list(ar.MD.disasm(result.bytes[load.trampoline:load.trampoline+100],load.trampoline))
        self.assertIn(('cmp','x11, #0x28'),[(op.mnemonic,op.op_str) for op in code])
        rewrite(fixture(source_register=11),0x3E0)
        rewrite(fixture(63),0x3E0)

    def test_all_preload_entries_recheck_actual_values_and_no_bypass_enters(self):
        for pc in (0x3CC,0x3D0,0x3D4,0x3D8):
            with self.subTest(pc=hex(pc)):rewrite(fixture(),0x3E0,entry_offsets=(pc,))
        for pc in (0x3C4,0x3C8):
            assert_normalized_guard(self,fixture(),rewrite(fixture(),0x3E0,entry_offsets=(pc,)),0x3E0)
        for pc in (0x3DC,0x3E0):
            with self.subTest(pc=hex(pc)),self.assertRaises(ar.RewriteError):
                rewrite(fixture(),0x3E0,entry_offsets=(pc,))

    def test_ordinary_index_transforms_remain_guarded_and_missing_safety_facts_refuse(self):
        with self.assertRaises(ar.RewriteError):rewrite(fixture(64),0x3E0)
        source=fixture(source_register=11)
        assert_normalized_guard(self,source,rewrite(source,0x3E0,entry_offsets=(0x3D8,)),0x3E0)
        for opcode in (0xD100458B,0x7100458B,0x5140458B,0x1100458B,0x5100464B):
            source=fixture();write_image(source,0x3C0,'<I',opcode)
            with self.subTest(word=hex(opcode)):
                assert_normalized_guard(self,source,rewrite(source,0x3E0),0x3E0)
        with self.assertRaises(ar.RewriteError):rewrite(fixture(),0x3E0,readonly_ranges=())
        with self.assertRaises(ar.RewriteError):rewrite(fixture(),0x3E0,checked_stack=False)


if __name__=='__main__':unittest.main()
