"""Two observed backward-ADR switch shapes retain their source suffixes."""
from test_android_runtime_ro_table import assert_normalized_guard
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image, rewrite


def adr(pc,target,register):
    delta=(target-pc)&0x1FFFFF
    return 0x10000000|(delta&3)<<29|(delta>>2)<<5|register


def fixture(width,base=0x340,bound=13):
    source=source_base();write_image(source,0x300,'<I',ar.branch(0x300,0x3B8))
    if width==2:
        words=(0x90000037,0x912002F7,0x7100001F|bound<<10|9<<5,0x54000228,
               adr(0x3C8,base,10),0x78697AEB,0x8B0B094A,0x91036908,0xD61F0140)
    else:
        prefix=(0x9000002B,0x9120016B,0x7100001F|bound<<10|8<<5,0x54000228) if base==0x3DC else (
                0x7100001F|bound<<10|8<<5,0x54000228,0x9000002B,0x9120016B)
        words=(*prefix,adr(0x3C8,base,9),0x3868696A,0x8B0A0929,0x2A1803E8,0xD61F0120)
    write_image(source,0x3B8,'<9I',*words)
    values=[0]*(bound+1);values[-1]=200
    write_image(source,0x4800,'<'+str(bound+1)+('H' if width==2 else 'B'),*values)
    write_image(source,base+800,'<I',0x52800552)
    return source


class RuntimeRoBackwardTests(unittest.TestCase):
    def test_actual_earlier_base_and_original_suffix_determine_finite_targets(self):
        for width in (1,2):
            with self.subTest(width=width):
                source=fixture(width)
                package,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                plan=report['code_discovery']['readonly_guest_jump_tables'][0]
                self.assertEqual(plan['rule'],f'runtime-base-index-u{width*8}-ro-backward-direct-cmp-lsl2-v1')
                self.assertEqual((plan['base'],plan['index_bound'],plan['table_bytes']),(0x340,13,14*width))
                self.assertIn(0x660,report['code_discovery']['roots'])
                payload=struct.unpack_from('<Q',package,112)[0]
                self.assertEqual(package[payload+0x3D0:payload+0x3DC],parse_nso(source).image[0x3D0:0x3DC])
                image=rewrite(source,0x3D8)
                load=next(site for site in image.sites if site.offset==0x3CC)
                ops=list(ar.MD.disasm(image.bytes[load.trampoline:load.trampoline+100],load.trampoline))
                self.assertTrue(any(op.mnemonic=='add' and op.op_str.endswith('#0x340') for op in ops))

    def test_backward_preload_entries_check_actual_values_and_postload_refuses(self):
        for width in (1,2):
            for pc in range(0x3BC if width==1 else 0x3C4,0x3D0,4):
                image=rewrite(fixture(width),0x3D8,entry_offsets=(pc,))
                assert_normalized_guard(self,fixture(width),image,0x3D8)
            for pc in range(0x3D0,0x3DC,4):
                with self.subTest(width=width,pc=hex(pc)),self.assertRaises(ar.RewriteError):
                    rewrite(fixture(width),0x3D8,entry_offsets=(pc,))
            with self.assertRaises(ar.RewriteError):rewrite(fixture(width),0x3D8,readonly_ranges=())
            with self.assertRaises(ar.RewriteError):rewrite(fixture(width),0x3D8,code_ranges=((0x3B8,0x1000),))
        # This was already the ordinary direct-CMP byte form. Matching its
        # register tuple/suffix must not steal its BR+4 rule or entry policy.
        image=rewrite(fixture(1,base=0x3DC),0x3D8)
        self.assertTrue(image.sites)

    def test_bounded_native_variants_keep_effects_and_invalid_targets_refuse(self):
        for width in (1,2):
            for bound in (12,14):
                source=fixture(width,bound=bound)
                assert_normalized_guard(self,source,rewrite(source,0x3D8),0x3D8)
            with self.assertRaises(ar.RewriteError):rewrite(fixture(width,bound=64),0x3D8)
            for opcode in (0xD503201F,0xF100051F):
                source=fixture(width);write_image(source,0x3D4,'<I',opcode)
                assert_normalized_guard(self,source,rewrite(source,0x3D8),0x3D8)
            source=fixture(width);write_image(source,0x3D4,'<I',0x91036929)
            if width==1:
                with self.assertRaises(ar.RewriteError):rewrite(source,0x3D8) # Target overwrite.
            else:assert_normalized_guard(self,source,rewrite(source,0x3D8),0x3D8)
            source=fixture(width,base=0x400)
            assert_normalized_guard(self,source,rewrite(source,0x3D8),0x3D8)
            with self.assertRaises(ar.RewriteError):rewrite(fixture(width,base=0x341),0x3D8)
            source=fixture(width);write_image(source,0x3C8,'<I',adr(0x3C8,0x200,10 if width==2 else 9))
            with self.assertRaises(ar.RewriteError):rewrite(source,0x3D8)
            source=fixture(width)
            load=0x78697AEC if width==2 else 0x3868696C
            addition=0x8B0C094A if width==2 else 0x8B0C0929
            write_image(source,0x3CC,'<2I',load,addition)
            assert_normalized_guard(self,source,rewrite(source,0x3D8),0x3D8)

    def test_repeated_u16_table_constants_are_not_a_dominance_assumption(self):
        for table_add,accept in ((0x912002F7,True),(0x912402F7,False)):
            source=fixture(2)
            write_image(source,0x3A0,'<3I',0x90000037,table_add,ar.branch(0x3A8,0x3B8))
            write_image(source,0x300,'<I',ar.branch(0x300,0x3A0))
            if accept:
                _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                plan=report['code_discovery']['readonly_guest_jump_tables'][0]
                self.assertEqual(plan['equivalent_table_producer_offsets'],[0x3A0,0x3B8])
            else:
                with self.assertRaises(ar.RewriteError):rewrite(source,0x3D8)


if __name__=='__main__':unittest.main()
