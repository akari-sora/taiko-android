"""Exact CMP/MOV alias followed by inline table-base construction."""
from pathlib import Path
import struct
import sys
import unittest
from test_android_runtime_ro_table import assert_normalized_guard

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso
from test_nso_format import mutable_source,write_image

VALUES=bytes.fromhex('00834f5e168dc176')


def fixture():
    source=mutable_source();write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<320I',*([0xD65F03C0]*320))
    write_image(source,0x300,'<10I',0x71001C1F,0x54002768,0x2A0003E8,0x90000029,
                0x91200129,0x100000AA,0x3868692B,0x8B0B094A,0x9106A3F5,0xD61F0140)
    write_image(source,0x55C,'<I',0x52800552)
    write_image(source,0x4800,'8s',VALUES)
    return source


def rewrite(source,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,code_ranges=((0x300,0x800),),
                 package_version=2,checked_stack=True,proven_guest_indirect_offsets=(0x324,),
                 readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class RuntimeRoMovTests(unittest.TestCase):
    def test_existing_direct_cmp_with_a_prior_w_mov_keeps_its_proof(self):
        from test_android_runtime_ro_direct import fixture as direct_fixture, rewrite as direct_rewrite
        source=direct_fixture();write_image(source,0x3C4,'<I',0x2A0103FC)
        self.assertTrue(any(s.offset==0x3D4 for s in direct_rewrite(source).sites))

    def test_true_w_copy_and_inline_base_prove_only_exact_targets(self):
        package,report=ai.import_module(fixture(),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-mov-alias-inline-lsl2-v1')
        self.assertEqual((plan['alias_source_register'],plan['zero_extend_offset'],plan['proof_start_offset']),(0,0x308,0x300))
        self.assertEqual((plan['index_bound'],plan['table_bytes'],plan['producer_offsets'][:2]),(7,8,[0x30C,0x310]))
        self.assertEqual(plan['target_values'],sorted(VALUES))
        self.assertIn(0x55C,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<2I',package,payload+0x320),(0x9106A3F5,0xD61F0140))
        image=rewrite(fixture());site=next(s for s in image.sites if s.offset==0x318)
        code=list(ar.MD.disasm(image.bytes[site.trampoline:site.trampoline+100],site.trampoline))
        self.assertIn(('cmp','x8, #7'),[(i.mnemonic,i.op_str) for i in code])

    def test_alias_candidates_guard_new_preload_entries_and_reject_wrong_core(self):
        for pc,value in ((0x308,0xAA0003E8),(0x308,0x2A0103E8),(0x308,0x11000008),
                         (0x30C,0x9000002A),(0x310,0x91200149),(0x310,0x91600129),
                         (0x314,0x100000CA),(0x320,0xAA0003EA),(0x320,0xAA0003EB),(0x320,0xD4000001)):
            source=fixture();write_image(source,pc,'<I',value)
            if (pc,value) in ((0x314,0x100000CA),(0x320,0xAA0003EB)):
                with self.subTest(pc=hex(pc),word=hex(value)):
                    assert_normalized_guard(self,source,rewrite(source),0x324)
            else:
                with self.subTest(pc=hex(pc),word=hex(value)),self.assertRaises(ar.RewriteError):rewrite(source)
        for entry in (0x304,0x308):
            assert_normalized_guard(self,fixture(),rewrite(fixture(),entry_offsets=(entry,)),0x324)
        for entry in (0x31C,0x320,0x324):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):rewrite(fixture(),entry_offsets=(entry,))
        with self.assertRaises(ar.RewriteError):rewrite(fixture(),readonly_ranges=())
        source=fixture();write_image(source,0x7E0,'<I',ar.branch(0x7E0,0x31C))
        with self.assertRaises(ar.RewriteError):rewrite(source)


if __name__=='__main__':unittest.main()
