"""Exercise the real iOS exclusive emitter without running its game-file CLI."""
import ast
from itertools import combinations
from pathlib import Path
import re
import struct
import unittest

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ROOT=Path(__file__).resolve().parents[4]


def emitter():
    source=ast.parse((ROOT/'dm/tools/patch_nso.py').read_text(encoding='utf-8'))
    names={'here','emit','emit_key_addr','emit_slot_addr','B','STP','LDP',
           'MRS_TPIDRRO','ADRP','ADDR','LDRX','STRX','dis','regset','num',
           'has18','regs_in','pick','subst','site_window'}
    selected=[node for node in source.body if isinstance(node,ast.FunctionDef) and node.name in names]
    assert {node.name for node in selected}==names
    md=Cs(CS_ARCH_ARM64,CS_MODE_ARM);md.detail=True
    namespace=dict(struct=struct,re=re,combinations=combinations,md=md,
                   PATCH_OFF=0x8000,KEY_PAGE_OFF=0x9000,KEY_INDEX={'K18':0},
                   patch=bytearray(),fix=[],NOP=0xD503201F)
    exec(compile(ast.Module(body=selected,type_ignores=[]),'patch_nso.py:test-functions','exec'),namespace)
    return namespace


class IosExclusiveExitTests(unittest.TestCase):
    def build(self,external=True):
        ns=emitter()
        # ldxr x18,[x0]; cmp x18,x1; b.ne outside;
        # stlxr w2,x3,[x0]; cbnz w2,retry.
        words=[0xC85F7C12,0xEB01025F,0x540001C1,0xC802FC03,0x35FFFF82]
        if not external:words[2]=0xD503201F
        raw=struct.pack('<5I',*words)
        instructions=list(ns['md'].disasm(raw,0x100))
        self.assertEqual(len(instructions),5)
        self.assertEqual([i.mnemonic for i in instructions],['ldxr','cmp','b.ne' if external else 'nop','stlxr','cbnz'])
        start,lo,hi=ns['site_window'](instructions)
        emitted=list(ns['md'].disasm(bytes(ns['patch']),start))
        copied=next(i.address for i in emitted if i.mnemonic=='ldxr')
        return ns,{i.address:i for i in emitted},copied,hi

    def follow(self,ops,pc,*,unequal=False,retries=0):
        for _ in range(100):
            if pc not in ops:return pc
            ins=ops[pc]
            if ins.mnemonic=='b':pc=ins.operands[0].imm
            elif ins.mnemonic=='b.ne':pc=ins.operands[0].imm if unequal else pc+4
            elif ins.mnemonic=='cbnz':
                take=retries>0;retries-=int(take)
                pc=ins.operands[-1].imm if take else pc+4
            else:pc+=4
        self.fail('copied window did not reach a bounded exit')

    def test_compare_equal_success_falls_out_to_original_hi(self):
        _,ops,copy,hi=self.build()
        self.assertEqual(self.follow(ops,copy),hi)

    def test_compare_unequal_uses_external_exit_and_preserves_retry_mapping(self):
        _,ops,copy,hi=self.build()
        self.assertEqual(self.follow(ops,copy,unequal=True),0x140)
        self.assertEqual(self.follow(ops,copy,retries=2),hi)
        stubs=[i for i in ops.values() if i.mnemonic=='b' and i.operands[0].imm in (hi,0x140)]
        self.assertEqual(len(stubs),2)
        for branch in stubs:
            self.assertEqual([ops[branch.address-d].mnemonic for d in (8,4)],['str','ldp'])

    def test_internal_retry_only_window_retains_fallthrough(self):
        _,ops,copy,hi=self.build(external=False)
        self.assertEqual(self.follow(ops,copy,retries=2),hi)


if __name__=='__main__':unittest.main()
