"""Native publication reloads a guarded payload only after reservation retirement."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar

BEGIN,ENTRY,HEAD,END,FALLBACK = 16,32,36,60,72
TEMPLATE = (0xD5033F5F,0xAA0A03E9,0xB940026A,0x3400020A,0xF9000309,
            0xC85F7D0A,0xEB09015F,0x54FFFF21,0xC80BFD18,0xAA0A03E9,0x35FFFF0B)
FIELDS = ((),(0,16),(0,5),(0,),(0,5),(0,5),(5,16),(),(0,5,16),(0,16),(0,))


def fixture(rename=None):
    block = list(TEMPLATE)
    for index,shifts in enumerate(FIELDS):
        for shift in shifts:
            role = TEMPLATE[index]>>shift&31
            if rename:
                block[index]=block[index]&~(31<<shift)|rename.get(role,role)<<shift
    block[3] = block[3]&~(0x7FFFF<<5)|((FALLBACK-(BEGIN+12))//4)<<5
    values = [ar.branch(0,ENTRY),0xD503201F,0xD503201F,ar.branch(12,ENTRY)]+block+[0xD65F03C0]*4
    if len(values)%2:
        values.append(0xD503201F)
    return values


def raw(values):
    return struct.pack('<'+'I'*len(values),*values)


def decode(values):
    instructions=[ar.decode(word,index*4) for index,word in enumerate(values)]
    return instructions,{ins.address:ar.site_kind(ins) for ins in instructions}


def plan(values,roots=(0,ENTRY,END,FALLBACK),overrides=None):
    instructions,kinds=decode(values)
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions,kinds,roots,ar)


class Machine:
    """Raw-word model with explicit competitors and flag changes after failed stores."""
    def __init__(self,values,initial,expected=1,flag=1,failures=0,competitor=None,
                 flags_after_failures=()):
        self.values=values
        self.x=[0xAABB000000001000+i for i in range(31)]
        self.x[8],self.x[9],self.x[19],self.x[24]=0x400000,expected,0x500000,0x600000
        self.sp,self.nzcv=0x800000,0xB0000000
        self.q=tuple(bytes([i])*16 for i in range(32))
        self.memory={0x3FFFF8:0xABABABABABABABAB,0x400000:initial,0x400008:0xCDCDCDCDCDCDCDCD,
                     0x4FFFFC:0x12121212,0x500000:flag,0x500004:0x34343434,
                     0x5FFFF8:0x5656565656565656,0x600000:0xFEEDFEEDFEEDFEED,0x600008:0x7878787878787878}
        self.failures,self.competitor,self.flags_after_failures=failures,competitor,flags_after_failures
        self.loads=self.stores=self.clears=self.flag_reads=self.payload_writes=self.writes=0

    @staticmethod
    def signed(value,bits):
        return value-(1<<bits) if value&(1<<(bits-1)) else value

    def compare(self,left,right):
        result=(left-right)&0xFFFFFFFFFFFFFFFF
        overflow=bool((left^right)&(left^result)&0x8000000000000000)
        self.nzcv=((int(bool(result&0x8000000000000000))<<3)|((result==0)<<2)|
                   ((left>=right)<<1)|overflow)<<28

    def run(self):
        pc,monitor=0,None
        for _ in range(300):
            if pc in (END,FALLBACK):
                assert monitor is None
                return 'success' if pc==END else 'fallback'
            word=self.values[pc//4]
            rt,rn=word&31,word>>5&31
            next_pc=pc+4
            if word==0xD5033F5F:
                self.clears+=1;monitor=None
            elif word&0xFFE0FFE0==0xAA0003E0:
                self.x[rt]=self.x[word>>16&31]
            elif word&0xFFC00000==0xB9400000:
                assert monitor is None
                self.flag_reads+=1
                self.x[rt]=self.memory[self.x[rn]+(word>>10&0xFFF)*4]&0xFFFFFFFF
            elif word&0xFFC00000==0xF9000000:
                assert monitor is None
                self.payload_writes+=1
                self.memory[self.x[rn]+(word>>10&0xFFF)*8]=self.x[rt]
            elif word&0xFFFFFC00==0xC85F7C00:
                self.loads+=1
                self.x[rt]=self.memory[self.x[rn]]
                monitor=self.x[rn]
            elif word&0xFFE0FC1F==0xEB00001F:
                self.compare(self.x[rn],self.x[word>>16&31])
            elif word&0xFFE0FC00==0xC800FC00:
                self.stores+=1
                assert monitor==self.x[rn]
                success=self.stores>self.failures
                if success:
                    self.memory[self.x[rn]]=self.x[rt]
                    self.writes+=1
                elif self.competitor is not None:
                    self.memory[self.x[rn]]=self.competitor
                if not success and self.stores<=len(self.flags_after_failures):
                    self.memory[0x500000]=self.flags_after_failures[self.stores-1]
                self.x[word>>16&31]=0 if success else 1
                monitor=None
            elif word&0xFF000010==0x54000000:
                assert word&15==1
                if not self.nzcv&0x40000000:
                    next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0x7E000000==0x34000000:
                bits=64 if word>>31 else 32
                if bool(self.x[rt]&((1<<bits)-1))==bool(word&0x01000000):
                    next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0xFC000000==0x14000000:
                next_pc=pc+self.signed(word&0x3FFFFFF,26)*4
            else:
                raise AssertionError(f'unmodeled {pc:x}: {word:08x}')
            pc=next_pc
        raise AssertionError('nonterminating authored model')


class NativeGuardedPublishTests(unittest.TestCase):
    def test_native_union_and_renamed_roles_keep_original_bytes(self):
        for rename in (None,{8:0,9:3,10:16,11:17,19:25,24:27}):
            values=fixture(rename)
            with self.subTest(rename=rename):
                self.assertEqual(plan(values),())
                image=ar.rewrite(raw(values),entry_offsets=(0,ENTRY,END,FALLBACK))
                self.assertEqual(image.bytes,raw(values))
                self.assertFalse(image.sites);self.assertFalse(image.fixups)

    def test_raw_paths_publish_last_attempt_preserve_full_state_and_closed_memory_access(self):
        values=fixture()
        image=ar.rewrite(raw(values),entry_offsets=(0,ENTRY,END,FALLBACK))
        emitted=list(struct.unpack('<'+'I'*(len(image.bytes)//4),image.bytes))
        # initial, expected, flag, failures, competitor, flag updates;
        # result, final expected, final loaded, last node.next, counts L/S/C/F/P, NZCV.
        cases=((1,1,1,0,None,(),'success',1,1,1,(1,1,0,0,1),0x60000000),
               (1,1,0,0,None,(),'success',1,1,1,(1,1,0,0,1),0x60000000),
               (2,1,0,0,None,(),'fallback',2,0,1,(1,0,1,1,1),0x20000000),
               (2,1,1,0,None,(),'success',2,2,2,(2,1,1,1,2),0x60000000),
               (1,1,1,3,None,(),'success',1,1,1,(4,4,0,3,4),0x60000000),
               (1,1,1,1,7,(),'success',7,7,7,(3,2,1,2,3),0x60000000),
               (1,1,1,1,None,(0,),'fallback',1,0,1,(1,1,0,1,1),0x60000000),
               (1,1,1,2,9,(1,0),'fallback',9,0,9,(3,2,1,3,3),0x60000000),
               (0x100000001,1,1,0,None,(),'success',0x100000001,0x100000001,
                0x100000001,(2,1,1,1,2),0x60000000))
        for initial,expected,flag,failures,competitor,changes,result,ex,loaded,next_value,counts,nzcv in cases:
            with self.subTest(initial=initial,failures=failures,competitor=competitor,flags=changes):
                machine=Machine(emitted,initial,expected,flag,failures,competitor,changes)
                registers,memory=machine.x.copy(),machine.memory.copy()
                self.assertEqual(machine.run(),result)
                registers[9],registers[10]=ex,loaded
                if counts[1]:
                    registers[11]=0 if result=='success' else 1
                self.assertEqual(machine.x,registers)
                memory[0x400000]=0x600000 if result=='success' else competitor if competitor is not None else initial
                memory[0x600000]=next_value
                if changes:
                    memory[0x500000]=changes[min(counts[1],len(changes))-1]
                self.assertEqual(machine.memory,memory)
                self.assertEqual((machine.loads,machine.stores,machine.clears,machine.flag_reads,machine.payload_writes),counts)
                self.assertEqual((machine.sp,machine.nzcv,machine.q),
                                 (0x800000,nzcv,tuple(bytes([i])*16 for i in range(32))))
                self.assertEqual(machine.writes,int(result=='success'))

    def test_union_rejects_every_other_entry_and_outside_edge(self):
        for pc in range(BEGIN,END,4):
            if pc==ENTRY:
                continue
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):
                plan(fixture(),roots=(0,ENTRY,END,FALLBACK,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):
                plan(values)

    def test_exact_width_order_offsets_roles_conditions_and_complete_selected_union(self):
        helper=ar.android_exclusive.native_conditional_refresh
        instructions,kinds=decode(fixture());by_pc={i.address:i for i in instructions}
        self.assertEqual(helper(by_pc[HEAD],by_pc,kinds,ar),
                         (set(range(BEGIN,END,4)),ENTRY,{HEAD}))
        mutations=((0,0xD503201F),(1,TEMPLATE[1]^0x80000000),(2,TEMPLATE[2]^0x40000000),
                   (2,TEMPLATE[2]+0x400),(3,TEMPLATE[3]^0x01000000),
                   (3,TEMPLATE[3]^0x80000000),(4,TEMPLATE[4]+0x400),
                   (4,TEMPLATE[4]^0x40000000),(5,TEMPLATE[5]^0x8000),
                   (5,TEMPLATE[5]^0x40000000),(6,TEMPLATE[6]^0x80000000),
                   (7,TEMPLATE[7]^1),(8,TEMPLATE[8]^0x8000),
                   (8,TEMPLATE[8]^0x40000000),(9,TEMPLATE[9]^0x80000000),
                   (10,TEMPLATE[10]^0x80000000),(10,TEMPLATE[10]+(1<<5)))
        for index,word in mutations:
            values=fixture();values[BEGIN//4+index]=word
            ins,ks=decode(values)
            with self.subTest(index=index,word=hex(word)):
                self.assertIsNone(helper(ins[HEAD//4],{i.address:i for i in ins},ks,ar))
        for role in (8,9,10,11,19,24):
            for forbidden in (18,29,30,31,9 if role!=9 else 8):
                ins,ks=decode(fixture({role:forbidden}))
                with self.subTest(role=role,forbidden=forbidden):
                    self.assertIsNone(helper(ins[HEAD//4],{i.address:i for i in ins},ks,ar))
        for pc in range(BEGIN,END,4):
            self.assertIsNone(helper(by_pc[HEAD],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))
            with self.assertRaises(ar.RewriteError):
                plan(fixture(),overrides={pc:'x18'})
        for target in (END,FALLBACK):
            bad=by_pc.copy();bad.pop(target)
            self.assertIsNone(helper(by_pc[HEAD],bad,kinds,ar))
            bad=by_pc.copy();bad[target]=ar.decode(0,target)
            self.assertIsNone(helper(by_pc[HEAD],bad,kinds,ar))


if __name__=='__main__':
    unittest.main()
