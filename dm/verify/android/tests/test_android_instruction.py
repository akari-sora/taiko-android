"""Detached instruction storage must preserve the installed decoder's facts."""
import gc
from pathlib import Path
import struct
import sys
import unittest
import weakref

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from android_instruction import Instruction


class InstructionTests(unittest.TestCase):
    def compare(self,original):
        compact=Instruction(original)
        for name in ('id','address','size','bytes','mnemonic','op_str','writeback','cc','update_flags','post_index'):
            self.assertEqual(getattr(compact,name),getattr(original,name),name)
        self.assertEqual(tuple(map(tuple,compact.regs_access())),tuple(map(tuple,original.regs_access())))
        for group in range(256):self.assertEqual(compact.group(group),original.group(group))
        self.assertEqual(len(compact.operands),len(original.operands))
        for left,right in zip(compact.operands,original.operands):
            self.assertEqual(bytes(left),bytes(right))  # entire union: mem/shift/access/vector/ext/fp
            self.assertIsNone(left._b_base_)
            self.assertFalse(left._objects)
            self.assertIsNot(left,right)
        for reg in set(sum((list(x) for x in original.regs_access()),[])):
            self.assertEqual(compact.reg_name(reg),original.reg_name(reg))
        reference=weakref.ref(original)
        return compact,reference

    def test_instruction_families_and_no_decoder_lifetime_alias(self):
        # integer/FP/SIMD, memory offset/index/writeback, exclusive, branches,
        # system registers, traps and PC-relative producers.
        words=(0x8B020020,0xAA0203E0,0xF100491F,0x2A0803E8,0x1E622820,0x4E228420,
               0xF9400820,0xF85F8C20,0xA9BF7BFD,0xA8C17BFD,0x78687B2A,0x3868692B,
               0xC85F7C20,0xC8027C20,0xD61F0120,0xD63F0200,0xD65F03C0,0x54000088,
               0xD53B4200,0xD51B4200,0xD53BD040,0xD4000001,0xD4200000,0x90000039)
        for pc,value in enumerate(words):
            original=ar.decode(value,pc*4);compact,reference=self.compare(original)
            del original;gc.collect()
            self.assertIsNone(reference())
            self.assertEqual(struct.unpack('<I',compact.bytes)[0],value)
            self.assertFalse(hasattr(compact,'_raw'))
            self.assertFalse(hasattr(compact,'_cs'))

    def test_bounded_actual_nso_stream_matches_all_consumed_facts(self):
        # Authored checked-in NSO, always available; includes real decoded text.
        from nso_format import parse_nso
        from test_nso_format import mutable_source
        nso=parse_nso(mutable_source());count=0
        for pc in range(0,nso.sections[0].size,4):
            original=next(ar.MD.disasm(nso.image[pc:pc+4],pc,count=1),None)
            if original is not None:
                self.compare(original);count+=1
        self.assertGreater(count,100)

    def test_existing_runtime_guard_bytes_remain_exact(self):
        raw=bytearray(0x8000);struct.pack_into('<I',raw,0x104,0xD65F03C0)
        struct.pack_into('<3H',raw,0x4000,0,2,7)
        emitter=ar.Emitter(raw);start=emitter.pc
        emitter.readonly_table_load(Instruction(ar.decode(0x78687B2A,0x100)),dict(
            target_register=9,table_register=25,index_register=8,index_bound=2,table_offset=0x4000,base=0x200))
        emitter.data[0x100:0x104]=ar.word(ar.branch(0x100,start))
        frozen=(ROOT/'.omx/android-runtime-ro-table/guard.bin').read_bytes()
        self.assertEqual(bytes(emitter.data),frozen)


if __name__=='__main__':unittest.main()
