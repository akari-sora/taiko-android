"""Observed native switch schedules preserve parallel arithmetic and copies."""
from test_android_runtime_ro_table import assert_normalized_guard
import unittest

from test_android_runtime_ro_backward import adr
from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_virtual_ro_x18 import image_for
from test_android_rewrite import Machine


def source_for(kind):
    source=source_base();write_image(source,0x300,'<I',ar.branch(0x300,0x3C0))
    if kind=='pair-byte':
        write_image(source,0x300,'<I',ar.branch(0x300,0x480))
        write_image(source,0x480,'<3I',0x9000002D,0x912001AD,ar.branch(0x488,0x500))
        write_image(source,0x500,'<8I',0x7100C35F,0x2944E6F8,0x540007C8,
                    adr(0x50C,0x340,27),0x387A69BC,0x8B1C0B7B,0x52800037,0xD61F0360)
        values=[0]*49;values[0]=9;values[-1]=77
        write_image(source,0x4800,'<49B',*values);write_image(source,0x474,'<I',0x52800552)
        return source,0x51C,0x510
    if kind=='save-target-halfword':
        write_image(source,0x300,'<I',ar.branch(0x300,0x380))
        write_image(source,0x380,'<3I',0x9000003B,0x9120037B,ar.branch(0x388,0x3C0))
        write_image(source,0x3C0,'<7I',0x71001B3F,0x540009E8,0x2A0803F7,
                    adr(0x3CC,0x3DC,8),0x78797B69,0x8B090908,0xD61F0100)
        write_image(source,0x4800,'<7H',283,0,26,70,149,190,215)
        write_image(source,0x738,'<I',0x52800552)
        return source,0x3D8,0x3D0
    if kind=='backward-store':
        write_image(source,0x300,'<2I',0xD10103FF,ar.branch(0x304,0x3C0))
        write_image(source,0x3C0,'<10I',0x510059AD,0x710275BF,0x540009C8,
                    0x90000031,0x91200231,adr(0x3D4,0x340,15),
                    0x786D7A30,0x8B1009EF,0xA9015BFC,0xD61F01E0)
        write_image(source,0x4800,'<158H',*([0]*157+[200]))
        write_image(source,0x340,'<I',ar.branch(0x340,0x900))
        write_image(source,0x660,'<2I',0x52800552,ar.branch(0x664,0x900))
        write_image(source,0x900,'<2I',0x910103FF,0xD65F03C0)
        return source,0x3E4,0x3D8
    if kind=='parallel':
        words=(0x71000D3F,0x540009E8,0x8B180B48,0x5287080A,
               0x9000002C,0x9120018C,0x8B0A0108,adr(0x3DC,0x340,10),
               0x3869698B,0x8B0B094A,0xD61F0140)
        write_image(source,0x3C0,'<11I',*words)
        write_image(source,0x4800,'<4B',0,2,7,200)
        write_image(source,0x660,'<I',0x52800552)
        return source,0x3E8,0x3E0
    if kind=='zero-halfword':
        write_image(source,0x3C0,'<9I',0x7100753F,0x540009E8,0x9000002C,0x9120018C,
                    adr(0x3D0,0x3E4,10),0x7869798B,0x8B0B094A,0x2A1F03E0,0xD61F0140)
        write_image(source,0x4800,'<30H',*([0]*29+[200]))
        write_image(source,0x704,'<I',0x52800552)
        return source,0x3E0,0x3D4
    if kind=='self-copy-halfword':
        write_image(source,0x3C0,'<9I',0x7100451F,0x540009E8,0x2A0803E8,
                    0x9000002B,0x9120016B,adr(0x3D4,0x340,9),0x7868796A,0x8B0A0929,0xD61F0120)
        write_image(source,0x4800,'<18H',*([0]*17+[200]))
        write_image(source,0x660,'<I',0x52800552)
        return source,0x3E0,0x3D8
    words=(0x7100961F,0x540009E8,0xB940080F,0x90000023,0x91200063,
           0x2A1003E6,adr(0x3D8,0x3F8,7),0x78667873,0x8B1308E7,
           0xAA1F03F2,0xAA1F03F1,0x528008C5,0x2A1003E3,0xD61F00E0)
    write_image(source,0x3C0,'<14I',*words)
    write_image(source,0x4800,'<38H',*([0]*37+[200]))
    write_image(source,0x718,'<I',0x52800552)
    return source,0x3F4,0x3DC


class NativeScheduledTablesTests(unittest.TestCase):
    def test_backward_sub_table_retains_store_inside_its_real_frame(self):
        source,branch,_=source_for('backward-store')
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==branch)
        self.assertEqual((plan['base'],plan['table_bytes']),(0x340,316))
        self.assertIsNone(ar.stack_check_operation(0xA9015BFC)) # No SP writeback.
        image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[13]=179;model.run()
        self.assertEqual((model.x[15],model.x[16],model.sp),(0x660,200,model.start_sp))
        self.assertEqual(model.load(model.start_sp-48,8),model.x[28])
        self.assertEqual(model.load(model.start_sp-40,8),model.x[22])

    def test_sparse_native_u16_offsets_do_not_require_a_dense_veneer(self):
        source,branch,_=source_for('backward-store');nso=parse_nso(source)
        raw=bytearray(0x19000)
        raw[:0x10000]=b'\xc0\x03\x5f\xd6'*(0x10000//4)
        raw[:0x1000]=nso.image[:0x1000]
        import struct
        struct.pack_into('<2I',raw,0x3CC,0x900000D1,0x91000231)
        struct.pack_into('<158H',raw,0x18000,*([0]*157+[4589]))
        destination=0x340+4589*4
        struct.pack_into('<2I',raw,destination,0x52800552,ar.branch(destination+4,0x900))
        options=dict(entry_offset=0x300,text_size=0x10000,code_ranges=((0x300,0x10000),),
                     readonly_ranges=((0x18000,0x19000),),package_version=2,checked_stack=True,
                     proven_guest_indirect_offsets=(branch,))
        image=ar.rewrite(bytes(raw),**options)
        model=Machine(image);model.x[13]=179;model.run()
        self.assertEqual((model.x[15],model.x[16],model.sp),(destination,4589,model.start_sp))
        struct.pack_into('<H',raw,0x18000+157*2,0xFFFF)
        with self.assertRaises(ar.RewriteError):ar.rewrite(bytes(raw),**options)

    def test_original_schedules_discover_cases_without_changing_effects(self):
        for kind,last in (('parallel',0x660),('copy',0x718),('zero-halfword',0x704),('self-copy-halfword',0x660),
                          ('pair-byte',0x474),('save-target-halfword',0x738)):
            source,branch,load=source_for(kind)
            with self.subTest(kind=kind):
                _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
                plan=next(p for p in report['code_discovery']['readonly_guest_jump_tables'] if p['offset']==branch)
                self.assertEqual(plan['table_offset'],0x4800)
                self.assertIn(last,report['code_discovery']['roots'])
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
                model=Machine(image);hardware=model.x[18]
                if kind=='parallel':
                    model.x[9]=3;model.x[26]=0x7000;model.x[24]=5
                elif kind=='zero-halfword':
                    model.x[9]=29
                elif kind=='self-copy-halfword':
                    model.x[8]=(1<<32)|17
                elif kind=='pair-byte':
                    model.x[26]=0;model.x[23]=0x7000
                    model.store(0x7024,0x11223344,4);model.store(0x7028,0x55667788,4)
                elif kind=='save-target-halfword':
                    model.x[25]=1;model.x[8]=0x1122334455667788
                else:
                    model.x[0]=0x7000;model.store(0x7008,0x77,4);model.x[16]=1<<32
                    model.store(model.state,0x1122334455667788,8)
                model.run()
                if kind=='parallel':
                    self.assertEqual((model.x[8],model.x[10],model.x[11]),(0xA854,0x660,200))
                elif kind=='zero-halfword':
                    self.assertEqual((model.x[0],model.x[10],model.x[11]),(0,0x704,200))
                elif kind=='self-copy-halfword':
                    self.assertEqual((model.x[8],model.x[9],model.x[10]),(17,0x660,200))
                elif kind=='pair-byte':
                    self.assertEqual((model.x[23],model.x[24],model.x[25],model.x[27],model.x[28]),
                                     (1,0x11223344,0x55667788,0x364,9))
                elif kind=='save-target-halfword':
                    self.assertEqual((model.x[8],model.x[9],model.x[23]),(0x3DC,0,0x55667788))
                else:
                    self.assertEqual((model.x[3],model.x[5],model.x[6],model.x[7],model.x[15],model.x[17]),(0,70,0,0x3F8,0x77,0))
                    self.assertEqual(model.load(model.state,8),0)
                self.assertEqual(model.x[18],hardware)

    def test_full_index_and_postload_entries_remain_checked(self):
        for kind in ('parallel','copy','zero-halfword','self-copy-halfword','pair-byte','save-target-halfword'):
            source,branch,load=source_for(kind)
            for entry in range(load+4,branch+4,4):
                with self.subTest(kind=kind,entry=hex(entry)),self.assertRaises(ar.RewriteError):
                    image_for(source,entry=0x300,entry_offsets=(entry,),proven_guest_indirect_offsets=(branch,))
            with self.assertRaises(ar.RewriteError):
                image_for(source,entry=0x300,readonly_ranges=(),proven_guest_indirect_offsets=(branch,))
        source,branch,load=source_for('copy')
        image=image_for(source,entry=load,entry_offsets=(load,),proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[3]=0x4800;model.x[6]=1<<32;model.x[7]=0x3F8
        model.store(model.state,0x12345678,8);before=list(model.x);model.flags=0xA0000000
        with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
        self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))
        self.assertEqual(model.load(model.state,8),0x12345678)

    def test_real_saved_target_entry_does_not_borrow_cmp_or_undo_its_move(self):
        source,branch,load=source_for('save-target-halfword')
        image=image_for(source,entry=load-8,entry_offsets=(load-8,),proven_guest_indirect_offsets=(branch,))
        model=Machine(image);model.x[8]=0x1122334455667788;model.x[25]=1<<32;model.x[27]=0x4800
        model.flags=0xA0000000;before=list(model.x)
        with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
        before[8]=0x3DC;before[23]=0x55667788
        self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))

    def test_ordinary_nop_preserves_source_and_actual_read_guard(self):
        for kind,pc in (('parallel',0x3C8),('parallel',0x3D8)):
            source,branch,_=source_for(kind);write_image(source,pc,'<I',0xD503201F)
            with self.subTest(kind=kind,pc=hex(pc)):
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
                assert_normalized_guard(self,source,image,branch)

    def test_removing_virtual_x18_suffix_allows_guarded_native_core(self):
        for pc in (0x3E4,0x3EC):
            source,branch,_=source_for('copy');write_image(source,pc,'<I',0xD503201F)
            if pc==0x3E4:
                image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))
                assert_normalized_guard(self,source,image,branch)
            else:
                # The virtual-x18 operation is still present in this suffix.
                with self.subTest(pc=hex(pc)),self.assertRaises(ar.RewriteError):
                    image_for(source,entry=0x300,proven_guest_indirect_offsets=(branch,))


if __name__=='__main__':unittest.main()
