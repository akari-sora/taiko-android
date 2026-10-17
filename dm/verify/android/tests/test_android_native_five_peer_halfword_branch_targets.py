"""Authored sparse layouts test exact decoded TBNZ targets and signed bounds."""
from functools import lru_cache
import struct
import unittest
from types import SimpleNamespace
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG
from test_android_native_five_peer_halfword_union import fixture,decoded,ar,plan,HEADS,EXPECTED_WITNESS

def tbnz(pc,target,register=8):
    delta=target-pc
    assert delta%4==0 and -32768<=delta<=32764
    return 0x37000000|((delta//4)&0x3fff)<<5|register

@lru_cache(maxsize=None)
def sparse(shift,reverse=False,alias=False):
    original=fixture()
    instructions,_=decoded(original)
    remap=lambda pc: pc+shift if (pc<128 if reverse else pc>=128) else pc
    end=max(max(remap(op.address) for op in instructions)+4,
            164+shift+4 if reverse and alias else 0)
    output=bytearray(struct.pack('<I',0xD65F03C0)*(end//4))
    for op in instructions:
        pc=remap(op.address)
        word=struct.unpack_from('<I',original,op.address)[0]
        if op.mnemonic=='b':word=ar.branch(pc,remap(op.operands[-1].imm))
        elif op.mnemonic=='b.ne':word=0x54000001|(((remap(op.operands[-1].imm)-pc)//4)&0x7ffff)<<5
        elif op.mnemonic=='cbnz':word=0x3500000b|(((remap(op.operands[-1].imm)-pc)//4)&0x7ffff)<<5
        elif op.mnemonic=='tbnz':
            if alias and op.address==120:
                # Deliberately retain the original imm14. The real decoded
                # destination differs from the derived leave by exactly 64KiB.
                word=struct.unpack_from('<I',original,op.address)[0]
            else:word=tbnz(pc,remap(op.operands[-1].imm))
        struct.pack_into('<I',output,pc,word)
    return bytes(output),{remap(h) for h in HEADS},{remap(pc) for pc in EXPECTED_WITNESS}

class HalfwordBranchTargetTests(unittest.TestCase):
    def test_malformed_decoded_carrier_operand_shapes_refuse(self):
        class OperandProxy:
            def __init__(self,original,operands):self.original,self.operands=original,operands
            def __getattr__(self,name):return getattr(self.original,name)
        instructions,kinds=decoded();base={op.address:op for op in instructions}
        for pc in (120,136):
            original=base[pc]
            for shape in ('short','register_is_immediate','bit_is_register','target_is_register'):
                operands=[SimpleNamespace(type=op.type,reg=op.reg,imm=op.imm) for op in original.operands]
                if shape=='short':operands=[operands[0],operands[2]]
                elif shape=='register_is_immediate':operands[0].type=ARM64_OP_IMM
                elif shape=='bit_is_register':operands[1].type=ARM64_OP_REG
                else:operands[2].type=ARM64_OP_REG
                by_pc={**base,pc:OperandProxy(original,operands)}
                with self.subTest(pc=pc,shape=shape),self.assertRaises(ar.RewriteError):
                    ar.android_exclusive.native_five_peer_halfword_closure(by_pc[0],by_pc,kinds,ar)

    def test_forward_and_reverse_64KiB_target_aliases_refuse(self):
        for reverse in (False,True):
            source,_,_=sparse(0x10000,reverse,True)
            instructions,kinds=decoded(source);ops={op.address:op for op in instructions}
            test=120+0x10000 if reverse else 120
            leave=164 if reverse else 164+0x10000
            actual=ops[test].operands[-1].imm
            self.assertEqual(abs(actual-leave),0x10000)
            self.assertTrue(actual in ops, 'alias target must name an authored gap RET')
            self.assertEqual(ops[actual].mnemonic,'ret')
            with self.subTest(reverse=reverse),self.assertRaises(ar.RewriteError):plan(source)

    def test_legal_sparse_forward_reverse_and_signed_boundaries_remain_native(self):
        for shift,reverse in ((0x1000,False),(0x1000,True),(32720,False),(32812,True)):
            source,heads,witness=sparse(shift,reverse,False)
            instructions,kinds=decoded(source);ops={op.address:op for op in instructions}
            helper=ar.android_exclusive.native_five_peer_halfword_closure
            nodes,actual_heads,actual_witness=helper(ops[min(heads)],ops,kinds,ar)
            with self.subTest(shift=shift,reverse=reverse):
                self.assertEqual(actual_heads,heads)
                self.assertEqual(actual_witness,witness)
                self.assertEqual(len(nodes),27)
                self.assertEqual(plan(source),())
                test=120+shift if reverse else 120
                leave=164 if reverse else 164+shift
                self.assertEqual(ops[test].operands[-1].imm,leave)

    def test_witness_oracle_has_every_fixed_authored_word(self):
        instructions,kinds=decoded();ops={op.address:op for op in instructions}
        _,_,observed=ar.android_exclusive.native_five_peer_halfword_closure(ops[0],ops,kinds,ar)
        self.assertEqual(observed,EXPECTED_WITNESS)
        for omitted in EXPECTED_WITNESS:
            self.assertNotEqual(observed-{omitted},EXPECTED_WITNESS)

if __name__=='__main__':unittest.main()
