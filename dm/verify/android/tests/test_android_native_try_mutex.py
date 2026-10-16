"""Nonblocking busy-mutex retry islands exclude the ordinary SP epilogue."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar

BEGIN,EPILOGUE,END,CALLEE=16,72,168,180
WORDS=(0x79420274,0x11000696,0x91004015,0xF98002B0,0x79020276,0x885FFEA8,
       0x34000188,0xD5033F5F,0x79020274,0x35000094,0x79420668,0x34000048,
       0x94016870,0x2A1F03E0,0xA9427BFD,0xA9414FF4,0xA8C357F6,0xD65F03C0,
       0x34000194,0x52800020,0x88087EA0,0x34FFFF28,0x79020274,0x79020276,
       0x885FFEA8,0x34FFFF68,0x17FFFFED,0x79020276,0x885FFEA8,0x35FFFD48,
       0x52800020,0x88087EA0,0x34FFFDC8,0x7902027F,0x79420668,0x34FFFF08,
       0x94016858,0x17FFFFF6)
FIELDS=((0,5),(0,5),(0,5),(5,),(0,5),(0,5),(0,),(),(0,5),(0,),
        (0,5),(0,),(),(0,),(),(0,10),(0,10),(),(0,),(0,),(0,5,16),(0,),
        (0,5),(0,5),(0,5),(0,),(),(0,5),(0,5),(0,),(0,),(0,5,16),(0,),
        (0,5),(0,5),(0,),(),())
NODES=set(range(BEGIN,EPILOGUE,4))|set(range(EPILOGUE+16,END,4))


def raw(values):return struct.pack('<'+'I'*len(values),*values)


def fixture(rename=None):
    block=list(WORDS)
    for index,fields in enumerate(FIELDS):
        for shift in fields:
            role=WORDS[index]>>shift&31
            if rename and role!=31:
                block[index]=block[index]&~(31<<shift)|rename.get(role,role)<<shift
    for index in (12,36):
        block[index]=0x94000000|((CALLEE-(BEGIN+index*4))//4)&0x3FFFFFF
    tlr=rename.get(19,19) if rename else 19
    return [ar.branch(0,BEGIN-4),0xD503201F,0xD503201F,0xD53BD060|tlr]+block+[
        0xD503201F,0xD503201F,0xD503201F,0xD40006C1,0xD65F03C0,0xD503201F]


def decode(values):
    instructions=[ar.decode(word,index*4) for index,word in enumerate(values)]
    return instructions,{i.address:ar.site_kind(i) for i in instructions}


def plan(values,roots=(0,BEGIN-4,CALLEE),overrides=None):
    instructions,kinds=decode(values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions,kinds,roots,ar)


class Machine:
    """Execute authored raw opcodes through success/busy exits before ABI restore."""
    def __init__(self,values,old,busy=0,failures=0,competitor=None,interrupt=0):
        self.values=values;self.x=[0xAABB000000001000+i for i in range(31)]
        self.x[0],self.x[19]=0x400000,0x500000
        self.sp,self.nzcv,self.q=0x800000,0xB0000000,tuple(bytes([i])*16 for i in range(32))
        self.memory={0x40000C:0x12345678,0x400010:busy,0x400014:0x87654321,
                     0x5000FE:0xABCD,0x500100:old,0x500102:interrupt,0x500104:0xFEDC}
        self.failures,self.competitor=failures,competitor
        self.loads=self.stores=self.clears=self.flag_reads=self.calls=0

    @staticmethod
    def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value

    def run(self):
        pc,monitor=0,None
        for _ in range(300):
            if pc==EPILOGUE:
                assert monitor is None
                return bool(self.x[0])
            word=self.values[pc//4];rt,rn=word&31,word>>5&31;next_pc=pc+4
            if word&0xFFFFFFE0==0xD53BD060:self.x[rt]=0x500000
            elif word&0xFFC00000==0x79400000:
                address=self.x[rn]+(word>>10&0xFFF)*2
                self.flag_reads+=int(address==0x500102);self.x[rt]=self.memory[address]&0xFFFF
            elif word&0xFFC00000==0x79000000:
                self.memory[self.x[rn]+(word>>10&0xFFF)*2]=0 if rt==31 else self.x[rt]&0xFFFF
            elif word&0xFFC00000 in (0x91000000,0x11000000):
                bits=64 if word>>31 else 32
                self.x[rt]=(self.x[rn]+(word>>10&0xFFF))&((1<<bits)-1)
            elif word&0xFFE00000==0x52800000:self.x[rt]=word>>5&0xFFFF
            elif word&0xFFE0FFE0==0x2A0003E0:
                source=word>>16&31;self.x[rt]=0 if source==31 else self.x[source]&0xFFFFFFFF
            elif word&0xFFFFFC00==0x885FFC00:
                self.loads+=1;self.x[rt]=self.memory[self.x[rn]]&0xFFFFFFFF;monitor=self.x[rn]
            elif word&0xFFE0FC00==0x88007C00:
                self.stores+=1;assert monitor==self.x[rn]
                success=self.stores>self.failures
                if success:self.memory[self.x[rn]]=self.x[rt]&0xFFFFFFFF
                elif self.competitor is not None:self.memory[self.x[rn]]=self.competitor
                self.x[word>>16&31]=0 if success else 1;monitor=None
            elif word==0xD5033F5F:self.clears+=1;monitor=None
            elif word&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(word&0x01000000):
                    next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0xFC000000==0x94000000:
                self.calls+=1;assert monitor is None
                raise ValueError('nonzero interrupt flag requires unsupported pin model')
            elif word&0xFC000000==0x14000000:
                next_pc=pc+self.signed(word&0x3FFFFFF,26)*4
            elif word&0xFFC00000==0xF9800000:pass
            else:raise AssertionError(f'unmodeled {pc:x}: {word:08x}')
            pc=next_pc
        raise AssertionError('unbounded model execution')


class NativeTryMutexTests(unittest.TestCase):
    def test_native_retry_islands_and_renaming_preserve_source(self):
        for rename in (None,{0:1,8:3,19:23,20:24,21:25,22:26}):
            values=fixture(rename)
            with self.subTest(rename=rename):
                self.assertEqual(plan(values),())
                image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN-4,CALLEE))
                for pc in NODES:self.assertEqual(image.bytes[pc:pc+4],raw(values)[pc:pc+4])
                self.assertFalse(any(s.offset in NODES for s in image.sites))

    def test_raw_success_busy_retry_and_competing_owner_keep_full_state_and_guards(self):
        cases=((0,0,0,None,True,1,1,0,0,0),(7,0,0,None,True,1,1,0,0,0),
               (0,1,0,None,False,1,0,1,1,0),(7,1,0,None,False,1,0,1,0,1),
               (0,0,3,None,True,4,4,0,3,0),(7,0,3,None,True,4,4,0,0,0),
               (0,0,1,9,False,2,1,1,2,0),(7,0,1,9,False,2,1,1,0,9),
               (0xFFFF,0,2,None,True,3,3,0,0,0))
        for old,busy,failures,competitor,result,loads,stores,clears,flags,loaded in cases:
            with self.subTest(old=old,busy=busy,failures=failures,competitor=competitor):
                machine=Machine(fixture(),old,busy,failures,competitor)
                before,memory=machine.x.copy(),machine.memory.copy()
                self.assertEqual(machine.run(),result)
                before[0],before[8],before[20],before[21],before[22]=int(result),loaded,old,0x400010,old+1
                self.assertEqual(machine.x,before)
                memory[0x400010]=1 if result else competitor if competitor is not None else busy
                memory[0x500100]=(old+1)&0xFFFF if result else old
                self.assertEqual(machine.memory,memory)
                self.assertEqual((machine.loads,machine.stores,machine.clears,machine.flag_reads),(loads,stores,clears,flags))
                self.assertEqual((machine.sp,machine.nzcv,machine.q),
                                 (0x800000,0xB0000000,tuple(bytes([i])*16 for i in range(32))))
                self.assertEqual(machine.calls,0)
        for busy,failures in ((1,0),(0,1)):
            machine=Machine(fixture(),0,busy,failures,interrupt=1)
            with self.assertRaisesRegex(ValueError,'unsupported pin model'):machine.run()
            self.assertEqual(machine.memory[0x500102],1)

    def test_no_interior_entry_or_edge_bypasses_the_union(self):
        for pc in sorted(NODES-{BEGIN}):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):
                plan(fixture(),roots=(0,BEGIN-4,CALLEE,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(values)

    def test_exact_tpl_tls_calls_order_roles_hole_and_selected_nodes_are_required(self):
        helper=ar.android_exclusive.native_try_mutex
        instructions,kinds=decode(fixture());by_pc={i.address:i for i in instructions}
        self.assertEqual(helper(by_pc[BEGIN+20],by_pc,kinds,ar),
                         (NODES,BEGIN,{BEGIN+20,BEGIN+96,BEGIN+112}))
        for slot in range(38):
            values=fixture();index=BEGIN//4+slot
            if slot in (12,36):values[index]=0x94000000|((END-(BEGIN+slot*4))//4)&0x3FFFFFF
            else:values[index]^=0x8000 if slot in (5,24,28,20,31) else 1
            try:ins,ks=decode(values)
            except ar.RewriteError:continue
            with self.subTest(slot=slot):
                self.assertIsNone(helper(ins[(BEGIN+20)//4],{i.address:i for i in ins},ks,ar))
        for role in (0,8,19,20,21,22):
            for forbidden in (18,29,30,31,8 if role!=8 else 19):
                try:ins,ks=decode(fixture({role:forbidden}))
                except ar.RewriteError:continue
                self.assertIsNone(helper(ins[(BEGIN+20)//4],{i.address:i for i in ins},ks,ar))
        for pc in range(BEGIN,END,4):
            self.assertIsNone(helper(by_pc[BEGIN+20],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))
            if pc in NODES:
                with self.assertRaises(ar.RewriteError):plan(fixture(),overrides={pc:'x18'})
        for pc in (BEGIN-4,CALLEE,CALLEE+4):
            self.assertIsNone(helper(by_pc[BEGIN+20],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))
        for prefix in (0xD503201F,0xD53BD053,0xD53BD074):
            values=fixture();values[(BEGIN-4)//4]=prefix;ins,ks=decode(values)
            self.assertIsNone(helper(ins[(BEGIN+20)//4],{i.address:i for i in ins},ks,ar))


if __name__=='__main__':unittest.main()
