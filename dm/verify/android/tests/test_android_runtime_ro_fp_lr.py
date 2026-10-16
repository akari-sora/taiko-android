"""Observed BR X29 / LDRB W30: numeric GPRs with original LR write semantics."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso
from test_nso_format import mutable_source,write_image

VALUES=bytes.fromhex('1400080c10191e2328')


def fixture(target=29,loaded=30,bound=8):
    source=mutable_source();write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<128I',*([0xD65F03C0]*128))
    write_image(source,0x300,'<3I',0x90000033,0x91200273,0x1400002E)
    write_image(source,0x3C0,'<8I',0x510004C6,0x710000DF|(bound<<10),0x54000148,
                0x100000A0|target,0x38666A60|loaded,
                0x8B000800|(loaded<<16)|(target<<5)|target,0x2A1F03FC,0xD61F0000|(target<<5))
    write_image(source,0x444,'<2I',0x1AD2083D,0x1B1287BC)
    write_image(source,0x4800,'9s',VALUES)
    return source


def rewrite(source,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,code_ranges=((0x300,0x500),),
                 package_version=2,checked_stack=True,proven_guest_indirect_offsets=(0x3DC,),
                 readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class RuntimeRoFpLrTests(unittest.TestCase):
    def test_exact_observed_numeric_pair_loads_lr_and_keeps_native_branch(self):
        package,report=ai.import_module(fixture(),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual((plan['target_register'],plan['loaded_register'],plan['index_bound'],plan['table_bytes']),(29,30,8,9))
        self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-fp-lr-pair-lsl2-v1')
        self.assertEqual(plan['target_values'],sorted(VALUES))
        self.assertIn(0x444,report['code_discovery']['roots'])
        self.assertIn(0x448,[s['offset'] for s in report['rewrite']['sites']])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<I',package,payload+0x3DC)[0],0xD61F03A0)
        image=rewrite(fixture());site=next(s for s in image.sites if s.offset==0x3D0)
        code=[]
        for i in ar.MD.disasm(image.bytes[site.trampoline:],site.trampoline):
            code.append(i)
            if i.mnemonic=='brk':break
        self.assertFalse(any(i.mnemonic in ('bl','blr') for i in code))
        loaded=next(i for i in code if i.bytes==ar.word(0x38666A7E))
        self.assertEqual(code[code.index(loaded)-1].op_str,'sp, sp, #0x20')

    def test_other_high_register_pairs_and_fp_lr_clobbers_remain_refused(self):
        for target,loaded in ((29,9),(30,29),(30,9),(8,30),(29,29)):
            with self.subTest(target=target,loaded=loaded),self.assertRaises(ar.RewriteError):rewrite(fixture(target,loaded))
        with self.assertRaises(ar.RewriteError):rewrite(fixture(bound=9))
        for value in (0xAA0003FD,0xAA0003FE,0x2A0003FD,0x2A0003FE,0xD4000001):
            source=fixture();write_image(source,0x3D8,'<I',value)
            with self.subTest(word=hex(value)),self.assertRaises(ar.RewriteError):rewrite(source)
        for entry in range(0x3C8,0x3E0,4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):rewrite(fixture(),entry_offsets=(entry,))
        with self.assertRaises(ar.RewriteError):rewrite(fixture(),readonly_ranges=())


if __name__=='__main__':unittest.main()
