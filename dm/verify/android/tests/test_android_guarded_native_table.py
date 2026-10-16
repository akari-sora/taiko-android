"""The finite native read guard is independent of ordinary prefix scheduling."""
import unittest

from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(suffix_count=1):
    source=source_base()
    write_image(source,0x300,'<I',ar.branch(0x300,0x360))
    write_image(source,0x360,'<3I',0x9000002C,0x9120018C,ar.branch(0x368,0x3C0))
    write_image(source,0x3C0,'<6I',0x71000D3F,0x540019E8,0x11002464,
                adr(0x3CC,0x340,10),0x3869698B,0x8B0B094A)
    write_image(source,0x3D8,'<'+str(suffix_count)+'I',0x91001CC5,*([0xD503201F]*(suffix_count-1)))
    branch=0x3D8+suffix_count*4
    write_image(source,branch,'<I',0xD61F0140)
    write_image(source,0x4800,'<4B',0,2,7,200);write_image(source,0x660,'<I',0x52800552)
    return source,branch


def classify(source,branch,entries=()):
    nso=parse_nso(source)
    by_pc={pc:ar.decode(int.from_bytes(nso.image[pc:pc+4],'little'),pc) for pc in range(0x300,0x1000,4)}
    return ar._guarded_native_readonly_table(by_pc[branch],by_pc,set(entries),nso.image,((0x4000,0x8000),))


class GuardedNativeTableTests(unittest.TestCase):
    def test_x_compare_applies_to_new_rotated_index_not_the_prior_w_value(self):
        source,branch=fixture();write_image(source,0x3B0,'<I',0x7100253F)
        write_image(source,0x368,'<I',ar.branch(0x368,0x3B8))
        write_image(source,0x3B8,'<2I',0x93D706E9,0xD503201F) # ROR X9,X23,#1.
        write_image(source,0x3C0,'<I',0xF1000D3F)
        plan=classify(source,branch)
        self.assertEqual((plan['index_bound'],plan['bound_candidate_offset']),(3,0x3C0))
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[23]=4;model.run()
        self.assertEqual((model.x[9],model.x[10],model.x[11]),(2,0x35C,7))

    def test_earlier_bound_is_retired_only_by_an_actual_index_redefinition(self):
        source,branch=fixture()
        write_image(source,0x3B0,'<I',0x7100253F) # Previous function compares old W9 with9.
        self.assertIsNone(classify(source,branch)) # Same live version: ambiguity is retained.
        write_image(source,0x368,'<I',ar.branch(0x368,0x3B8))
        write_image(source,0x3B8,'<2I',0xB9400369,0xD503201F) # This function loads a fresh W9.
        plan=classify(source,branch)
        self.assertEqual((plan['index_bound'],plan['bound_candidate_offset']),(3,0x3C0))
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[27]=0x7000;model.store(0x7000,2,4);model.run()
        self.assertEqual((model.x[9],model.x[10],model.x[11]),(2,0x35C,7))
        write_image(source,0x3B8,'<I',0xB9400368) # Loading W8 does not retire a W9 bound.
        self.assertIsNone(classify(source,branch))

    def test_inline_table_is_stable_when_other_case_constructors_are_discovered(self):
        for width in (1,2):
            source,branch=fixture()
            write_image(source,0x364,'<I',0x9124018C) # An earlier complete RO candidate at4900.
            write_image(source,0x3C4,'<2I',0x9000002C,0x9120018C) # Exact inline definition at4800.
            if width==2:
                write_image(source,0x3D0,'<I',0x7869798B)
                write_image(source,0x4800,'<4H',0,2,7,200)
            plan=classify(source,branch)
            self.assertEqual((plan['table_offset'],plan['equivalent_table_producer_offsets']),(0x4800,[0x3C4]))
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
            model=Machine(image);model.x[9]=2;model.run()
            self.assertEqual((model.x[10],model.x[11],model.x[12]),(0x35C,7,0x4800))
            image=image_for(source,entry=0x3D0,entry_offsets=(0x3D0,),proven_guest_indirect_offsets=(branch,))
            model=Machine(image);model.x[9]=2;model.x[10]=0x340;model.x[12]=0x4900
            before=list(model.x);model.flags=0xA0000000
            with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
            self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))

    def test_bounded_bitfield_and_wcopy_alias_are_candidates_not_dominance_claims(self):
        for kind in ('bitfield','copy'):
            source,branch=fixture()
            write_image(source,0x3C0,'<I',0x53010AE9 if kind=='bitfield' else 0x71000C3F)
            if kind=='copy':write_image(source,0x3C8,'<I',0x2A0103E9)
            plan=classify(source,branch)
            with self.subTest(kind=kind):
                self.assertEqual((plan['index_bound'],plan['bound_candidate_kind']),
                                 (3,'unsigned-bitfield') if kind=='bitfield' else (3,'wcopy-cmp'))
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
                model=Machine(image);model.x[23]=5;model.x[1]=2;model.x[9]=0xFFFFFFFF00000000;hardware=model.x[18]
                model.run()
                self.assertEqual((model.x[9],model.x[10],model.x[11],model.x[18]),(2,0x35C,7,hardware))
                image=image_for(source,entry=0x3D0,entry_offsets=(0x3D0,),proven_guest_indirect_offsets=(branch,))
                model=Machine(image);model.x[9]=(1<<32)|2;model.x[10]=0x340;model.x[12]=0x4800
                before=list(model.x);model.flags=0xA0000000
                with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))
            for word in ((0x530122E9,0x53017AE9) if kind=='bitfield' else (0x7101003F,0xAA0103E9)):
                altered=bytearray(source);write_image(altered,0x3C0 if kind=='bitfield' or word==0x7101003F else 0x3C8,'<I',word)
                self.assertIsNone(classify(altered,branch))

    def test_normalized_source_discovery_and_prefix_suffix_effects(self):
        source,branch=fixture();plan=classify(source,branch)
        self.assertEqual((plan['rule'],plan['index_bound'],plan['table_bytes']),('runtime-native-guarded-readonly-lsl2-v1',3,4))
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        self.assertIn(0x660,report['code_discovery']['roots'])
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[9]=2;hardware=model.x[18];before=list(model.x);model.run()
        before[4]=(before[3]+9)&0xFFFFFFFF;before[5]=before[6]+7
        before[10]=0x35C;before[11]=7;before[12]=0x4800;before[9]=2
        self.assertEqual((model.x,model.sp,model.x[18]),(before,model.start_sp,hardware))
        original=parse_nso(source).image
        for pc in (0x3C8,0x3CC,0x3D4,0x3D8,branch):
            self.assertEqual(image.bytes[pc:pc+4],original[pc:pc+4])

    def test_prefix_and_adr_entries_still_check_actual_values_before_read(self):
        source,branch=fixture()
        for entry in (0x3C8,0x3CC,0x3D0):
            image=image_for(source,entry=entry,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
            for bad in ('table','target','index','upper'):
                if bad=='target' and entry!=0x3D0:continue # ADR executes on these paths.
                model=Machine(image);model.x[9]=2;model.x[12]=0x4800;model.x[10]=0x340
                if bad=='table':model.x[12]+=1
                elif bad=='target':model.x[10]+=4
                else:model.x[9]=4 if bad=='index' else (1<<32)|2
                model.flags=0xA0000000;before=list(model.x)
                with self.subTest(entry=entry,bad=bad),self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                if entry==0x3C8:before[4]=(before[3]+9)&0xFFFFFFFF
                if entry!=0x3D0:before[10]=0x340
                self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))

    def test_postload_entry_target_write_control_and_source_rewrite_refuse(self):
        source,branch=fixture()
        for entry in range(0x3D4,branch+4,4):
            self.assertIsNone(classify(source,branch,(entry,)))
            with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
        for word in (0xAA0C03EA,0x14000002,0x94000002,0xD65F03C0,0xD4000001,0x910043FF,0xAA1203E5):
            altered=bytearray(source);write_image(altered,0x3D8,'<I',word)
            self.assertIsNone(classify(altered,branch))
            with self.assertRaises(ar.RewriteError):image_for(altered,entry=0x300,proven_guest_indirect_offsets=(branch,))
        altered=bytearray(source);write_image(altered,0x3D8,'<I',0xD53BE045) # Timer rewrite, not copied source.
        with self.assertRaises(ar.RewriteError):image_for(altered,entry=0x300,proven_guest_indirect_offsets=(branch,))

    def test_finite_unique_candidates_complete_ro_and_core_are_mandatory(self):
        source,branch=fixture()
        for word in (0x7101013F,0x7100093F): # Bound64, or conflicting bound2 beside bound3.
            altered=bytearray(source);write_image(altered,0x3B0,'<I',word)
            self.assertIsNone(classify(altered,branch))
        altered=bytearray(source);write_image(altered,0x330,'<2I',0x9000004C,0x9100018C) # non-RO object
        self.assertIsNotNone(classify(altered,branch))
        write_image(altered,0x330,'<2I',0x9000002C,0x9124018C) # distinct complete RO candidate
        self.assertIsNone(classify(altered,branch))
        for pc,word in ((0x3D0,0x3869498B),(0x3D4,0x8B0B054A),(0x3D0,0x3869698A),(0x3DC,0xD63F0140)):
            altered=bytearray(source);write_image(altered,pc,'<I',word)
            self.assertIsNone(classify(altered,branch))
        for options in ({'readonly_ranges':((0x4800,0x4803),)}, {'code_ranges':((0x300,0x650),)}, {'checked_stack':False}):
            with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,),**options)
        for count in (1,5,6):
            altered,at=fixture(count)
            self.assertEqual(classify(altered,at) is not None,count<=5)


if __name__=='__main__':unittest.main()
