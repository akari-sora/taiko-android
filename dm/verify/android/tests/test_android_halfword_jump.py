"""Guarded unsigned-halfword table proofs use exact read-only target values."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso,parse_metadata
from test_nso_format import mutable_source,write_image


def fixture(values=(0,2,7)):
    source=mutable_source()
    words=[0xD65F03C0]*24
    words[:9]=[0x51006821,0x7100083F,0x54000248,0x90000031,
               0x91200231,0x10000092,0x78617A20,0x8B000A52,0xD61F0240]
    write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<24I',*words)
    write_image(source,0x4800,'<3H',*values)
    return source


def rewrite(source,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,
                 code_ranges=((0x300,0x360),),package_version=2,checked_stack=True,
                 readonly_ranges=((nso.sections[1].offset,nso.sections[1].end),))
    options.update(changes)
    return ar.rewrite(nso.image,**options)


class HalfwordJumpTests(unittest.TestCase):
    def test_other_w_register_source_keeps_zero_extension_and_entry_contract(self):
        source=fixture();original=0x51006800|(9<<5)|1
        write_image(source,0x300,'<I',original)  # SUB W1,W9,#26, as in the SDK.
        image=rewrite(source)
        self.assertEqual(struct.unpack_from('<I',image.bytes,0x300)[0],original)
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,
                                  indirect_policy='guarded-host')
        plan=report['code_discovery']['halfword_jump_tables'][0]
        self.assertEqual((plan['zero_extend_offset'],plan['index_bound']),(0x300,2))
        for entry in range(0x304,0x324,4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                rewrite(source,entry_offsets=(entry,))

    def test_exact_readonly_values_only_get_restoring_veneers(self):
        source=fixture()
        image=rewrite(source)
        site=next(x for x in image.sites if x.offset==0x320)
        code=list(ar.MD.disasm(image.bytes[site.trampoline:],site.trampoline))
        tails=[i for i,x in enumerate(code) if x.mnemonic=='ldp' and x.op_str=='x0, x1, [sp, #0x10]']
        self.assertEqual(len(tails),3)
        self.assertEqual([code[i+2].operands[0].imm for i in tails],[0x324,0x32C,0x340])
        for i in tails:
            self.assertEqual((code[i+1].mnemonic,code[i+1].op_str),('add','sp, sp, #0x20'))
        trap=next(x.address for x in code if x.mnemonic=='brk')
        self.assertEqual(sum(x.mnemonic=='b' and x.operands[0].imm==trap for x in code),5)
        self.assertFalse(any(x.mnemonic in ('cmp','subs','adds','msr') for x in code))
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,
                                  indirect_policy='guarded-host')
        plan=report['code_discovery']['halfword_jump_tables'][0]
        self.assertEqual((plan['offset'],plan['table_offset'],plan['index_bound']),(0x320,0x4800,2))
        self.assertEqual(plan['target_values'],[0,2,7])
        self.assertEqual(plan['count'],8)
        self.assertTrue({0x324,0x32C,0x340}<=set(report['code_discovery']['roots']))
        self.assertNotIn(0x328,report['code_discovery']['roots'])

    def test_guard_zero_extension_and_every_producer_entrance_are_required(self):
        for pc,word in ((0x300,0xD1006821),(0x304,0x7101003F),(0x308,0x54000242),
                        (0x318,0x78A17A20),(0x310,0x91200211)):
            candidate=fixture();write_image(candidate,pc,'<I',word)
            with self.subTest(pc=hex(pc)),self.assertRaises(ar.RewriteError):
                rewrite(candidate)
        for entry in range(0x304,0x324,4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                rewrite(fixture(),entry_offsets=(entry,))
        candidate=fixture();write_image(candidate,0x300,'<I',0x14000005)
        with self.assertRaises(ar.RewriteError):
            rewrite(candidate)
        for word in (0xAA0203E1,0xD4000001):  # MOV x1,x2 or SVC after the index guard.
            candidate=fixture()
            nso=parse_nso(candidate)
            words=list(struct.unpack_from('<24I',nso.image,0x300))
            words.insert(3,word)
            words.pop()
            write_image(candidate,0x300,'<24I',*words)
            with self.subTest(word=hex(word)),self.assertRaises(ar.RewriteError):
                rewrite(candidate)

    def test_missing_readonly_fact_and_unbounded_or_unselected_targets_refuse(self):
        with self.assertRaises(ar.RewriteError):
            rewrite(fixture(),readonly_ranges=())
        with self.assertRaises(ar.RewriteError):
            rewrite(fixture(),readonly_ranges=((0x8000,0x9000),))
        with self.assertRaises(ar.RewriteError):
            rewrite(fixture((0,2,65535)))
        with self.assertRaises(ar.RewriteError):
            rewrite(fixture(),code_ranges=((0x300,0x340),))
        candidate=fixture();write_image(candidate,0x310,'<I',0x91200231|1<<22)
        with self.assertRaises(ar.RewriteError):
            rewrite(candidate)


if __name__=='__main__':
    unittest.main()
