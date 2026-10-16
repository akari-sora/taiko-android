"""Two fresh reservation heads share a cleared reload, not a callback entry."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar

BEGIN,SECOND,END,WAIT,CLASSIFY,SUCCESS=64,88,124,16,32,160
WORDS=(0x885FFE68,0x7100091F,0x54000121,0x8808FE7F,0x35FFFF88,
       0x1400002C,0x885FFE68,0x35000088,0x8808FE75,0x35FFFFA8,
       0x17FFFFE8,0xD5033F5F,0x88DFFE68,0x35FFFDE8,0x17FFFFF8)
FIELDS=((0,5),(5,),(),(0,5,16),(0,),(),(0,5),(0,),(0,5,16),(0,),(),(),(0,5),(0,),())


def raw(values):return struct.pack('<'+'I'*len(values),*values)


def fixture(rename=None):
    block=list(WORDS)
    for index,fields in enumerate(FIELDS):
        for shift in fields:
            role=WORDS[index]>>shift&31
            if rename and role!=31:
                block[index]=block[index]&~(31<<shift)|rename.get(role,role)<<shift
    for index,target in ((5,SUCCESS),(10,WAIT)):
        block[index]=ar.branch(BEGIN+index*4,target)
    block[13]=block[13]&~(0x7FFFF<<5)|(((CLASSIFY-(BEGIN+52))//4)&0x7FFFF)<<5
    values=[0xD503201F]*42
    values[0]=ar.branch(0,BEGIN)
    values[3]=ar.branch(12,SECOND)
    # A second selected ordinary predecessor targets the fresh load only.
    loaded=rename.get(8,8) if rename else 8
    values[5]=0x34000000|(((SECOND-20)//4)&0x7FFFF)<<5|loaded
    values[BEGIN//4:END//4]=block
    for pc in (WAIT,CLASSIFY,SUCCESS):values[pc//4]=0xD65F03C0
    return values


def decode(values):
    ins=[ar.decode(word,index*4) for index,word in enumerate(values)]
    return ins,{i.address:ar.site_kind(i) for i in ins}


def plan(values,roots=(0,BEGIN,WAIT,CLASSIFY,SUCCESS),overrides=None):
    ins,kinds=decode(values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ins,kinds,roots,ar)


class Machine:
    """Raw-word execution stops at proven external exits, never fake HLE calls."""
    def __init__(self,values,initial,second=False,failures=0,competitor=None,clear_value=None,payload=1):
        self.values=values;self.pc=SECOND if second else BEGIN
        self.x=[0xAABB000000001000+i for i in range(31)]
        self.x[19],self.x[21]=0x400000,0xFEED000000000000|payload
        self.sp,self.nzcv,self.q=0x800000,0xB0000000,tuple(bytes([i])*16 for i in range(32))
        self.memory={0x3FFFFC:0x12345678,0x400000:initial,0x400004:0x87654321}
        self.failures,self.competitor,self.clear_value=failures,competitor,clear_value
        self.loads=self.stores=self.clears=self.acquire_reads=0

    @staticmethod
    def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value

    def compare(self,left,right):
        left&=0xFFFFFFFF;right&=0xFFFFFFFF;result=(left-right)&0xFFFFFFFF
        overflow=bool((left^right)&(left^result)&0x80000000)
        self.nzcv=((int(bool(result&0x80000000))<<3)|((result==0)<<2)|((left>=right)<<1)|overflow)<<28

    def run(self):
        monitor=None
        for _ in range(200):
            if self.pc in (WAIT,CLASSIFY,SUCCESS):
                assert monitor is None
                return {WAIT:'wait',CLASSIFY:'classify',SUCCESS:'consume'}[self.pc]
            pc=self.pc;word=self.values[pc//4];rt,rn=word&31,word>>5&31;next_pc=pc+4
            if word&0xFFFFFC00==0x885FFC00:
                self.loads+=1;self.x[rt]=self.memory[self.x[rn]]&0xFFFFFFFF;monitor=self.x[rn]
            elif word&0xFFFFFC00==0x88DFFC00:
                assert monitor is None
                self.acquire_reads+=1;self.x[rt]=self.memory[self.x[rn]]&0xFFFFFFFF
            elif word&0xFFE0FC00==0x8800FC00:
                self.stores+=1;assert monitor==self.x[rn]
                success=self.stores>self.failures
                if success:self.memory[self.x[rn]]=0 if rt==31 else self.x[rt]&0xFFFFFFFF
                elif self.competitor is not None:self.memory[self.x[rn]]=self.competitor
                self.x[word>>16&31]=0 if success else 1;monitor=None
            elif word&0xFFC0001F==0x7100001F:self.compare(self.x[rn],word>>10&0xFFF)
            elif word&0xFF000010==0x54000000:
                assert word&15==1
                if not self.nzcv&0x40000000:next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(word&0x01000000):
                    next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word==0xD5033F5F:
                self.clears+=1;monitor=None
                if self.clear_value is not None:self.memory[0x400000]=self.clear_value
            elif word&0xFC000000==0x14000000:
                next_pc=pc+self.signed(word&0x3FFFFFF,26)*4
            else:raise AssertionError(f'unmodeled {pc:x}: {word:08x}')
            self.pc=next_pc
        raise AssertionError('unbounded source model')


class NativeSharedClearTests(unittest.TestCase):
    def test_selected_ordinary_edges_enter_only_fresh_heads_and_keep_bytes_native(self):
        for rename in (None,{19:24,8:16,21:27}):
            values=fixture(rename)
            with self.subTest(rename=rename):
                self.assertEqual(plan(values),())
                image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,WAIT,CLASSIFY,SUCCESS))
                self.assertEqual(image.bytes,raw(values))
                self.assertFalse(image.sites);self.assertFalse(image.fixups)

    def test_raw_consume_mark_wait_refresh_and_retry_preserve_full_state(self):
        # initial, second, failures, competitor, clear value, payload;
        # exit, finalcell, loaded/status, LDXR/STXR/CLREX/LDAR counts, flags.
        cases=((2,False,0,None,None,1,'consume',0,0,(1,1,0,0),0x60000000),
               (2,False,3,None,None,1,'consume',0,0,(4,4,0,0),0x60000000),
               (1,False,0,None,None,1,'classify',1,1,(1,0,1,1),0x80000000),
               (0,False,0,None,None,1,'wait',1,0,(2,1,1,1),0x80000000),
               (0,True,0,None,None,1,'wait',1,0,(1,1,0,0),0xB0000000),
               (0,True,0,None,None,3,'wait',3,0,(1,1,0,0),0xB0000000),
               (1,True,0,None,None,1,'classify',1,1,(1,0,1,1),0xB0000000),
               (2,True,0,None,None,1,'classify',2,2,(1,0,1,1),0xB0000000),
               (2,False,1,0,None,1,'wait',1,0,(3,2,1,1),0x80000000),
               (2,False,1,1,None,1,'classify',1,1,(2,1,1,1),0x80000000),
               (1,True,0,None,0,1,'wait',1,0,(2,1,1,1),0xB0000000),
               (0x80000000,False,0,None,None,1,'classify',0x80000000,0x80000000,(1,0,1,1),0x30000000))
        for initial,second,failures,competitor,clear,payload,result,cell,loaded,counts,flags in cases:
            with self.subTest(initial=initial,second=second,failures=failures,competitor=competitor):
                machine=Machine(fixture(),initial,second,failures,competitor,clear,payload)
                registers,memory=machine.x.copy(),machine.memory.copy()
                self.assertEqual(machine.run(),result)
                registers[8]=loaded;memory[0x400000]=cell
                self.assertEqual(machine.x,registers);self.assertEqual(machine.memory,memory)
                self.assertEqual((machine.loads,machine.stores,machine.clears,machine.acquire_reads),counts)
                self.assertEqual((machine.sp,machine.nzcv,machine.q),
                                 (0x800000,flags,tuple(bytes([i])*16 for i in range(32))))

    def test_callback_roots_cannot_be_confused_with_direct_fresh_head_edges(self):
        for pc in range(BEGIN+4,END,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):
                plan(fixture(),roots=(0,BEGIN,WAIT,CLASSIFY,SUCCESS,pc))
        for pc in set(range(BEGIN,END,4))-{BEGIN,SECOND}:
            values=fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(values)

    def test_exact_shared_clear_roles_order_control_flow_and_all_selected_words(self):
        helper=ar.android_exclusive.native_shared_clear
        ins,kinds=decode(fixture());by_pc={i.address:i for i in ins}
        self.assertEqual(helper(by_pc[BEGIN],by_pc,kinds,ar),(set(range(BEGIN,END,4)),{BEGIN,SECOND}))
        for slot in range(15):
            values=fixture();index=BEGIN//4+slot
            if slot in (5,10,13):
                values[index]=ar.branch(BEGIN+slot*4,BEGIN) if slot!=13 else 0x35FFFFE8
            else:values[index]^=0x8000 if slot in (0,3,6,8,12) else 1
            try:changed,ks=decode(values)
            except ar.RewriteError:continue
            with self.subTest(slot=slot):
                self.assertIsNone(helper(changed[BEGIN//4],{i.address:i for i in changed},ks,ar))
        for role in (19,8,21):
            for forbidden in (18,29,30,31,8 if role!=8 else 19):
                changed,ks=decode(fixture({role:forbidden}))
                self.assertIsNone(helper(changed[BEGIN//4],{i.address:i for i in changed},ks,ar))
        for pc in range(BEGIN,END,4):
            self.assertIsNone(helper(by_pc[BEGIN],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))
            with self.assertRaises(ar.RewriteError):plan(fixture(),overrides={pc:'x18'})
        for target in (WAIT,CLASSIFY,SUCCESS):
            bad=by_pc.copy();bad.pop(target)
            self.assertIsNone(helper(by_pc[BEGIN],bad,kinds,ar))
            bad=by_pc.copy();bad[target]=ar.decode(0,target)
            self.assertIsNone(helper(by_pc[BEGIN],bad,kinds,ar))


if __name__=='__main__':unittest.main()
