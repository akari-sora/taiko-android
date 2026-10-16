"""Exact reload, low8 and mask3 source effects precede the existing load guard."""
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


def fixture(kind):
    source=source_base()
    if kind=='reload':
        words=(0x12001F68,0x7100111F,0x540003C8,0xF94013EB,
               0x9000002A,0x9120014A,0x10000088,0x386B6949,0x8B090908,0xD61F0100)
        values,width,load,branch=(0,104,85,40,0),1,0x3DC,0x3E4
    elif kind=='low8':
        words=(0x12001C48,0x7100111F,0x540003C8,0x92401C48,
               0x90000029,0x91200129,0x100000CA,0x7868792B,0x8B0B094A,
               0x2A0003FB,0xF90057E1,0xD61F0140)
        values,width,load,branch=(0,364,89,327,23),2,0x3DC,0x3EC
    elif kind=='parallel':
        words=(0x90000020,0x91200000,0x8B0F0A23,0x0B1E00B9,0x51000739,
               0x12000739,0x1000009A,0x38796808,0x8B080B5A,0xD61F0340)
        values,width,load,branch=(0,30,10,20),1,0x3DC,0x3E4
    else:
        restore=kind=='restore'
        words=(0x120004A8 if restore else 0x12000508,0x9000003A,0x9120035A,
               0x100000B0 if restore else 0x10000090,0x38686B59,0x8B190A10,
               *((0xF9408BFE,) if restore else ()),0xD61F0200)
        values,width,load,branch=(0,23,7,15),1,0x3D0,0x3DC if restore else 0x3D8
    write_image(source,0x3C0,'<'+str(len(words))+'I',*words)
    write_image(source,0x4800,'<'+str(len(values))+('B' if width==1 else 'H'),*values)
    if kind=='parallel':
        loop=load+0xC0
        case=branch+4+30*4
        write_image(source,case,'<I',ar.branch(case,loop-4))
        write_image(source,loop-4,'<2I',0x110007DE,0x35FFF990)
    role=branch+4+4*values[2]
    write_image(source,role,'<I',0x52800552)
    return source,branch,load,role,words


def rewrite(kind,source=None,**changes):
    original,branch,load,role,words=fixture(kind)
    nso=parse_nso(original if source is None else source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,
                 code_ranges=((0x300,0x1000),),package_version=2,checked_stack=True,
                 proven_guest_indirect_offsets=(branch,),readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


class RuntimeRoIndexPrefixTests(unittest.TestCase):
    def test_reload_is_original_full64_data_and_not_a_spill_equality_claim(self):
        source,branch,load,role,words=fixture('reload')
        package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-sp-reload-observed-lsl2-v1')
        self.assertEqual((plan['index_register'],plan['index_bound'],plan['table_bytes']),(11,4,5))
        self.assertIn('no spill equivalence',plan['bound_basis'])
        self.assertEqual(plan['preserved_source_offsets'],[0x3CC])
        self.assertIn(role,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<I',package,payload+0x3CC)[0],0xF94013EB)
        image=rewrite('reload');site=next(x for x in image.sites if x.offset==load)
        ops=list(ar.MD.disasm(image.bytes[site.trampoline:site.trampoline+100],site.trampoline))
        self.assertIn(('cmp','x11, #4'),[(i.mnemonic,i.op_str) for i in ops])

    def test_low8_original_wide_mask_and_suffix_store_are_preserved(self):
        source,branch,load,role,words=fixture('low8')
        package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=report['code_discovery']['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-low8-observed-lsl2-v1')
        self.assertEqual((plan['index_bound'],plan['table_bytes']),(4,10))
        self.assertIn(role,report['code_discovery']['roots'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<2I',package,payload+0x3E4),(0x2A0003FB,0xF90057E1))
        self.assertEqual(plan['preserved_source_offsets'],[0x3CC,0x3E4,0x3E8])

    def test_observed_mask3_parallel_reads_and_lr_reload_are_original_effects(self):
        for kind in ('parallel','restore','self-mask'):
            source,branch,load,role,words=fixture(kind)
            package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=report['code_discovery']['readonly_guest_jump_tables'][0]
            self.assertEqual(plan['rule'],'runtime-base-index-u8-ro-mask3-observed-lsl2-v1')
            self.assertEqual((plan['index_bound'],plan['table_bytes']),(3,4))
            self.assertNotIn('compare_offset',plan)
            self.assertIn(role,report['code_discovery']['roots'])
            payload=struct.unpack_from('<Q',package,112)[0]
            # Byte equality retains original uint32 ADD/SUB carry/wrap/lowbits
            # for every input, rather than replacing them with a guessed index.
            for pc in plan['preserved_source_offsets']+plan.get('observed_loop_source_offsets',[]):
                self.assertEqual(package[payload+pc:payload+pc+4],parse_nso(source).image[pc:pc+4])
            rewrite(kind)

    def test_direct_index_prefix_variants_are_guarded_and_unproved_aliases_refuse(self):
        changes={
            'reload':((0x3C0,0x12001F48),(0x3C4,0x7100151F),(0x3C8,0x540003C2),
                      (0x3CC,0xB94023EB),(0x3CC,0xF94017EB),(0x3E0,0x8B090928)),
            'low8':((0x3C0,0x12001C68),(0x3C4,0x7100151F),(0x3CC,0x12401C48),
                    (0x3CC,0x92401C68),(0x3E4,0x2A0003FC),(0x3E8,0xF9005BE1)),
            'parallel':((0x3C8,0x8B0F0A24),(0x3CC,0x0B1D00B9),
                        (0x3D0,0x71000739),(0x3D4,0x12000B39)),
            'restore':((0x3C0,0x120004C8),(0x3D8,0xF9408FFE)),
            'self-mask':((0x3C0,0x92400508),(0x3C0,0x12000528)),
        }
        for kind,mutations in changes.items():
            for pc,value in mutations:
                source,*_=fixture(kind);write_image(source,pc,'<I',value)
                if kind=='low8' and value!=0x12401C48:
                    with self.subTest(kind=kind,pc=hex(pc),word=hex(value)):
                        assert_normalized_guard(self,source,rewrite(kind,source),fixture(kind)[1])
                else:
                    with self.subTest(kind=kind,pc=hex(pc),word=hex(value)),self.assertRaises(ar.RewriteError):rewrite(kind,source)
        for kind in changes:
            with self.subTest(kind=kind),self.assertRaises(ar.RewriteError):rewrite(kind,readonly_ranges=())

    def test_preload_entries_pass_guard_and_every_suffix_entry_refuses(self):
        for kind in ('reload','low8','parallel','restore','self-mask'):
            source,branch,load,role,words=fixture(kind)
            allowed=(0x3C0,0x3C4,load-4,load) if kind=='parallel' else tuple(range(load-12,load+4,4))
            if kind=='parallel':allowed=(*allowed,load-16)  # observed CBNZ loop to index ADD
            for pc in allowed:
                with self.subTest(kind=kind,allowed=hex(pc)):rewrite(kind,entry_offsets=(pc,))
            for pc in range(0x3C4,branch+4,4):
                if pc not in allowed:
                    if kind=='low8' and pc<=load:
                        assert_normalized_guard(self,source,rewrite(kind,entry_offsets=(pc,)),branch)
                    else:
                        with self.subTest(kind=kind,forbidden=hex(pc)),self.assertRaises(ar.RewriteError):rewrite(kind,entry_offsets=(pc,))
            write_image(source,0x300,'<I',ar.branch(0x300,load+4))
            with self.subTest(kind=kind),self.assertRaises(ar.RewriteError):rewrite(kind,source)

    def test_parallel_observed_loop_entry_still_must_pass_actual_fact_guard(self):
        source,branch,load,role,words=fixture('parallel')
        image=rewrite('parallel',source)
        self.assertTrue(any(site.offset==load for site in image.sites))
        self.assertEqual(parse_nso(source).image[load+0xBC:load+0xC4],struct.pack('<2I',0x110007DE,0x35FFF990))
        for pc,value in ((load+0xBC,0x11000BDE),(load+0xC0,0x35FFF991),
                         (load+0xC0,0x35FFF970)):
            changed=bytearray(source);write_image(changed,pc,'<I',value)
            with self.subTest(source=hex(pc)),self.assertRaises(ar.RewriteError):rewrite('parallel',changed,entry_offsets=(load-16,))
        for entry in (load-20,load-12,load-8,load+4,branch):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):rewrite('parallel',entry_offsets=(entry,))


if __name__=='__main__':unittest.main()
