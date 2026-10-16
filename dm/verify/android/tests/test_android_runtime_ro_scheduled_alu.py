"""The observed three-ALU u16 prefix preserves all original data effects."""
from pathlib import Path
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso
from test_nso_format import write_image
from test_android_runtime_ro_sub_inline import source_base

VALUES=(0,14,70,130,187,244,247,244,305,358,244,244,415)
GAP=(0x1B087DCE,0x8B2EC529,0x8B2DC529)


def fixture(bound=12):
    source=source_base()
    write_image(source,0x3C0,'<11I',0x710001FF|(bound<<10),0x54000188,
                *GAP,0x9000002D,0x912001AD,0x1000008E,
                0x786F79B0,0x8B1009CE,0xD61F01C0)
    values=(VALUES+tuple(0 for _ in range(max(0,bound+1-len(VALUES)))))[:bound+1]
    write_image(source,0x4800,'<'+str(bound+1)+'H',*values)
    write_image(source,0x5F4,'<I',0x52800552)  # case3: base3ec +130*4
    return source


def rewrite(source,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,
                 code_ranges=((0x300,0x1000),),package_version=2,checked_stack=True,
                 proven_guest_indirect_offsets=(0x3E8,),readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class RuntimeRoScheduledAluTests(unittest.TestCase):
    def test_exact_three_alu_effects_and_finite_case_are_preserved(self):
        package,report=ai.import_module(fixture(),'main',package_version=2,
                                        checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-scheduled-alu-inline-lsl2-v1')
        self.assertEqual((plan['index_bound'],plan['table_bytes'],plan['target_values']),
                         (12,26,sorted(set(VALUES))))
        self.assertEqual(plan['preserved_scheduled_alu_offsets'],[0x3C8,0x3CC,0x3D0])
        self.assertNotIn('zero_extend_offset',plan)
        self.assertIn(0x5F4,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<3I',package,payload+0x3C8),GAP)
        self.assertEqual(struct.unpack_from('<I',package,payload+0x3E8)[0],0xD61F01C0)
        image=rewrite(fixture())
        site=next(x for x in image.sites if x.offset==0x3E0)
        ops=list(ar.MD.disasm(image.bytes[site.trampoline:site.trampoline+100],site.trampoline))
        self.assertIn(('cmp','x15, #0xc'),[(i.mnemonic,i.op_str) for i in ops])
        rewrite(fixture(63))
        with self.assertRaises(ar.RewriteError):rewrite(fixture(64))

    def test_ordinary_gap_effects_and_order_are_preserved_with_actual_guard(self):
        for pc,value in ((0x3C0,0x710031DF),(0x3C0,0xF10031FF),
                         (0x3C4,0x54000182),(0x3C8,0x1B087DCF),
                         (0x3C8,0x1B097DCE),(0x3CC,0xAB2EC529),
                         (0x3CC,0x8B2EC52F),(0x3CC,0x8B2E6529),
                         (0x3CC,0xF900012E),(0x3D0,0x8B2CC529),
                         (0x3D4,0x9000002C),(0x3DC,0x100000AE)):
            source=fixture();write_image(source,pc,'<I',value)
            if (pc,value) in ((0x3C0,0x710031DF),(0x3D4,0x9000002C)):
                with self.subTest(pc=hex(pc),word=hex(value)),self.assertRaises(ar.RewriteError):rewrite(source)
            else:
                with self.subTest(pc=hex(pc),word=hex(value)):
                    assert_normalized_guard(self,source,rewrite(source),0x3E8)
        source=fixture();write_image(source,0x3CC,'<2I',GAP[2],GAP[1])
        assert_normalized_guard(self,source,rewrite(source),0x3E8)
        with self.assertRaises(ar.RewriteError):rewrite(fixture(),readonly_ranges=())

    def test_all_preload_entries_reach_guard_and_postload_entries_refuse(self):
        for pc in (0x3D4,0x3D8,0x3DC,0x3E0):
            with self.subTest(entry=hex(pc)):rewrite(fixture(),entry_offsets=(pc,))
        for pc in (0x3C4,0x3C8,0x3CC,0x3D0):
            assert_normalized_guard(self,fixture(),rewrite(fixture(),entry_offsets=(pc,)),0x3E8)
        for pc in (0x3E4,0x3E8):
            with self.subTest(entry=hex(pc)),self.assertRaises(ar.RewriteError):rewrite(fixture(),entry_offsets=(pc,))
        source=fixture();write_image(source,0x300,'<I',ar.branch(0x300,0x3E4))
        with self.assertRaises(ar.RewriteError):rewrite(source)


if __name__=='__main__':unittest.main()
