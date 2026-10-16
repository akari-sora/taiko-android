"""A direct CMP u8 switch obtains all memory/target facts at runtime."""
from pathlib import Path
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso
from test_nso_format import mutable_source,write_image

VALUES=bytes.fromhex('003ed6d6d644d6d6d6d64a50565c62d668d6d6d6d66e747bd6d6d6d6d6d6d6d6d6d6d682d6d6d6d6d68990979ea5d6acd6b3bac1')


def fixture():
    source=mutable_source();write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<320I',*([0xD65F03C0]*320))
    write_image(source,0x300,'<3I',0x9000002D,0x912001AD,0x1400002E)
    write_image(source,0x3C0,'<8I',0x3940073C,0x33181D1C,0x7100CF9F,0x54001B68,
                0x10000088,0x387C69A9,0x8B090908,0xD61F0100)
    write_image(source,0x508,'<I',0xAA1203E9)
    write_image(source,0x4800,'52s',VALUES)
    return source


def rewrite(source,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,code_ranges=((0x300,0x800),),
                 package_version=2,checked_stack=True,proven_guest_indirect_offsets=(0x3DC,),
                 readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class RuntimeRoDirectTests(unittest.TestCase):
    def test_exact_finite_targets_need_no_bfi_or_zero_extension_assumption(self):
        package,report=ai.import_module(fixture(),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-direct-cmp-lsl2-v1')
        self.assertEqual((plan['index_bound'],plan['table_bytes'],len(plan['target_values'])),(51,52,23))
        self.assertNotIn('zero_extend_offset',plan)
        self.assertIn(0x508,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<I',package,payload+0x3DC)[0],0xD61F0100)
        source=fixture();write_image(source,0x3C4,'<I',0xAA0103FC)  # arbitrary full X28
        image=rewrite(source);site=next(x for x in image.sites if x.offset==0x3D4)
        code=list(ar.MD.disasm(image.bytes[site.trampoline:site.trampoline+100],site.trampoline))
        self.assertIn(('cmp','x28, #0x33'),[(i.mnemonic,i.op_str) for i in code])

    def test_prefix_variants_keep_actual_guard_and_wrong_core_or_postload_entries_refuse(self):
        for pc,value in ((0x3CC,0x54001B62),(0x3D0,0x100000A8)):
            source=fixture();write_image(source,pc,'<I',value)
            assert_normalized_guard(self,source,rewrite(source),0x3DC)
        for pc,value in ((0x3C8,0x7100CF7F),(0x3D4,0x387C79A9),(0x3D8,0x8B0A0908)):
            source=fixture();write_image(source,pc,'<I',value)
            with self.subTest(pc=hex(pc)),self.assertRaises(ar.RewriteError):rewrite(source)
        for pc in range(0x3CC,0x3D8,4):
            assert_normalized_guard(self,fixture(),rewrite(fixture(),entry_offsets=(pc,)),0x3DC)
        for pc in range(0x3D8,0x3E0,4):
            with self.subTest(entry=hex(pc)),self.assertRaises(ar.RewriteError):rewrite(fixture(),entry_offsets=(pc,))
        with self.assertRaises(ar.RewriteError):rewrite(fixture(),readonly_ranges=())

    def test_uncovered_window_is_bounded_and_never_publishes(self):
        source=fixture()
        for pc in (0x900,0x908,0x910):write_image(source,pc,'<I',0x52800552)
        with self.assertRaisesRegex(ai.ImportError,'0x900: uncovered rewrite candidate') as caught:
            ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        window=caught.exception.uncovered_window
        self.assertEqual([x['offset'] for x in window['sites']],[0x900,0x908,0x910])
        self.assertLessEqual(window['end']-window['start'],65536)
        self.assertFalse(window['truncated'])
        for pc in range(0x900,0xA40,4):write_image(source,pc,'<I',0x52800552)
        with self.assertRaises(ai.ImportError) as caught:
            ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        self.assertEqual(len(caught.exception.uncovered_window['sites']),64)
        self.assertTrue(caught.exception.uncovered_window['truncated'])
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'input').mkdir();(root/'input/main').write_bytes(source)
            with self.assertRaises(ai.ImportError):
                ai.import_directory(root/'input',root/'out',['main'],package_version=2,checked_stack=True,indirect_policy='guarded-host')
            self.assertFalse(list((root/'out').glob('*.dmag')))
            import json
            report=json.loads((root/'out/import.json').read_text())
            self.assertEqual(report['status'],'rejected')
            self.assertEqual(len(report['modules'][0]['code_discovery']['uncovered_window']['sites']),64)

    def test_diagnostic_tail_does_not_skip_an_unknown_encoding_or_system_word(self):
        for value,reason in ((0xFFFFFFFF,'unallocated-word'),(0xD53B4220,'unsupported-system-register')):
            source=fixture();write_image(source,0x900,'<3I',0x52800552,value,0x52800552)
            with self.subTest(value=hex(value)),self.assertRaisesRegex(ai.ImportError,'0x900: uncovered rewrite candidate') as caught:
                ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            self.assertEqual(caught.exception.uncovered_window['stop_reason'],reason)
            self.assertEqual(caught.exception.uncovered_window['sites'],[{'offset':0x900,'kind':'x18'}])
            self.assertTrue(caught.exception.uncovered_window['truncated'])


if __name__=='__main__':unittest.main()
