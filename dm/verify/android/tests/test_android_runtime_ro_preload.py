"""Only inline-prefix entries dominated by the emitted load guard may enter."""
from pathlib import Path
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from nso_format import parse_nso
from test_android_runtime_ro_mov import fixture,rewrite


class RuntimeRoPreloadTests(unittest.TestCase):
    def test_inline_base_and_at_load_entries_still_execute_the_same_preflight(self):
        baseline=rewrite(fixture())
        original=next(s for s in baseline.sites if s.offset==0x318)
        for entry in (0x30C,0x310,0x314,0x318):
            image=rewrite(fixture(),entry_offsets=(entry,))
            site=next(s for s in image.sites if s.offset==0x318)
            self.assertEqual(site.trampoline,original.trampoline)
            self.assertEqual(image.bytes,baseline.bytes)
            # Every path through the inline producer reaches this patched LDR;
            # the preflight checks actual table, target and complete index.
            patched=ar.decode(struct.unpack_from('<I',image.bytes,0x318)[0],0x318)
            self.assertEqual((patched.mnemonic,patched.operands[0].imm),('b',site.trampoline))

    def test_pre_copy_entries_check_actual_values_and_postload_bypasses_refuse(self):
        for entry in (0x304,0x308):
            assert_normalized_guard(self,fixture(),rewrite(fixture(),entry_offsets=(entry,)),0x324)
        for entry in (0x31C,0x320,0x324):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):rewrite(fixture(),entry_offsets=(entry,))
        # A real direct edge to the unguarded target ADD is also rejected.
        source=fixture()
        from test_nso_format import write_image
        write_image(source,0x7E0,'<I',ar.branch(0x7E0,0x31C))
        with self.assertRaises(ar.RewriteError):rewrite(source)

    def test_native_direct_and_static_forms_also_guard_at_the_actual_read(self):
        from test_android_guest_table import fixture as static_fixture
        source=static_fixture();nso=parse_nso(source)
        image=ar.rewrite(nso.image,entry_offset=0x300,text_size=nso.sections[0].size,code_ranges=((0x300,0x360),),
                         package_version=2,checked_stack=True,readonly_ranges=((0x4000,0x8000),),
                         proven_guest_indirect_offsets=(0x320,),entry_offsets=(0x318,))
        assert_normalized_guard(self,source,image,0x320)
        from test_android_runtime_ro_direct import fixture as direct_fixture,rewrite as direct_rewrite
        source=direct_fixture()
        assert_normalized_guard(self,source,direct_rewrite(source,entry_offsets=(0x3D4,)),0x3DC)


if __name__=='__main__':unittest.main()
