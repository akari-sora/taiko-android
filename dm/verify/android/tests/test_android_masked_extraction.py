"""A masked wide extraction supplies a finite candidate, never dominance."""
import unittest
from test_android_runtime_ro_sub_inline import ar,ai,parse_nso,source_base,write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def fixture(virtual_loaded=False,gap=False,suffix_count=1):
    source=source_base();write_image(source,0x300,'<3I',0x9000002C,0x9120018C,ar.branch(0x308,0x3B0))
    write_image(source,0x3B0,'<6I',0x7100013F,0xD503201F,0x924039CE if gap else 0xD503201F,
                0x9000002C if gap else 0xD503201F,0x9120018C if gap else 0x924039CE,0xD34D7DC9)
    write_image(source,0x3C8,'<3I',adr(0x3C8,0x340,10),0x38696992 if virtual_loaded else 0x3869698B,
                0x8B12094A if virtual_loaded else 0x8B0B094A)
    suffix=(0x2A0103F4,0x910012B5,0x90000029,0x91240129,0x9000002B,0x9120016B) if suffix_count==6 else (0x91000694,)
    branch=0x3D4+4*len(suffix)
    write_image(source,0x3D4,'<'+str(len(suffix)+1)+'I',*suffix,0xD61F0140)
    write_image(source,0x4800,'<4B',0,2,7,12)
    return source,branch


class MaskedExtractionTests(unittest.TestCase):
    def test_all_four_indices_retire_old_cmp_and_keep_original_effects(self):
        for virtual_loaded,gap,count in ((False,False,1),(False,True,6),(True,False,1),(True,True,1)):
            source,branch=fixture(virtual_loaded,gap,count)
            _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
            plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==branch)
            self.assertEqual((plan['index_bound'],plan['bound_candidate_offset'],plan['bound_mask_offset']),(3,0x3C4,0x3B8 if gap else 0x3C0))
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
            for index,tag in enumerate((0,2,7,12)):
                model=Machine(image);model.x[9]=0;model.x[14]=0xF000000000000123|(index<<13)
                model.store(model.state,0xAABBCCDD12345678,8);before=list(model.x);model.run()
                before[9]=index;before[10]=0x340+tag*4;before[12]=0x4800;before[14]=(index<<13)|0x123
                if not virtual_loaded:before[11]=tag
                if count==6:
                    before[20]=before[1]&0xFFFFFFFF;before[21]+=4;before[9]=0x4900;before[11]=0x4800
                else:before[20]+=1
                self.assertEqual((model.x,model.load(model.state,8),model.sp,model.flags),
                                 (before,tag if virtual_loaded else 0xAABBCCDD12345678,model.start_sp,0x60000000))
            raw=parse_nso(source).image
            self.assertEqual(image.bytes[0x3D4:branch+4],raw[0x3D4:branch+4])

    def test_bypassed_producer_checks_live_full64_table_and_base_before_read(self):
        for virtual_loaded in (False,True):
            source,branch=fixture(virtual_loaded)
            image=image_for(source,entry=0x3CC,proven_guest_indirect_offsets=(branch,))
            for mode in ('upper','bound','table','base'):
                model=Machine(image);model.x[9]=2;model.x[10]=0x340;model.x[12]=0x4800
                model.store(model.state,0xAABBCCDD12345678,8);model.flags=0xA0000000
                if mode=='upper':model.x[9]|=1<<32
                elif mode=='bound':model.x[9]=4
                elif mode=='table':model.x[12]+=4
                else:model.x[10]=0
                before=list(model.x)
                with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                self.assertEqual((model.x,model.load(model.state,8),model.sp,model.flags),
                                 (before,0xAABBCCDD12345678,model.start_sp,0xA0000000))

    def test_missing_definition_alias_clobber_wide_domain_and_middle_entry_refuse(self):
        for virtual_loaded in (False,True):
            source,branch=fixture(virtual_loaded,True)
            for pc,value in ((0x3B8,0x924039CD),(0x3BC,0xAA0003EE),(0x3BC,0x2A0003EE),
                             (0x3BC,0x94000001),(0x3B8,0x92404DCE),(0x3C4,0xD35F35C9)):
                changed=bytearray(source);write_image(changed,pc,'<I',value)
                with self.subTest(virtual_loaded=virtual_loaded,pc=hex(pc),word=hex(value)),self.assertRaises(ar.RewriteError):
                    image_for(changed,entry=0x300,proven_guest_indirect_offsets=(branch,))
            for entry in range(0x3D0,branch+4,4):
                with self.assertRaises(ar.RewriteError):image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
            # A same-version later compare cannot silently reduce the domain.
            changed,_=fixture(virtual_loaded)
            write_image(changed,0x3B8,'<4I',0x924039CE,0xD34D7DC9,0x7100013F,0xD503201F)
            with self.assertRaises(ar.RewriteError):image_for(changed,entry=0x300,proven_guest_indirect_offsets=(branch,))


if __name__=='__main__':unittest.main()
