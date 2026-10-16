"""Single-load native scans retain their counter and closed-monitor retry paths."""
from pathlib import Path
import struct
import sys
import unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,HEAD,END,SUCCESS=16,36,56,64
TEMPLATE=(0xD5033F5F,0x9100054A,0x91004129,0xF104015F,0x540000C0,
          0x885F7D2C,0x35FFFF4C,0x880C7D2B,0x35FFFF2C,0x14000003)
FIELDS=((),(0,5),(0,5),(5,),(),(0,5),(0,),(0,5,16),(0,),())
def fixture(rename=None,register_bound=False):
    template=(0xD5033F5F,0x9100054A,0x91004129,0xEB0A017F,0x540000C0,
              0x885F7D2D,0x35FFFF4D,0x880D7D2C,0x35FFFF2D,0x14000003) if register_bound else TEMPLATE
    block=list(template)
    for i,shifts in enumerate(((),(0,5),(0,5),(5,16),(),(0,5),(0,),(0,5,16),(0,),()) if register_bound else FIELDS):
        for shift in shifts:
            role=template[i]>>shift&31
            if rename:block[i]=block[i]&~(31<<shift)|rename.get(role,role)<<shift
    return [ar.branch(0,HEAD),0xD503201F,0xD503201F,ar.branch(12,HEAD)]+block+[0xD65F03C0,0xD503201F,0xD65F03C0,0xD503201F]
def raw(values):return struct.pack('<'+'I'*len(values),*values)
def decoded(values):
    ops=[ar.decode(word,i*4) for i,word in enumerate(values)]
    return ops,{op.address:ar.site_kind(op) for op in ops}
def match(values,overrides=None):
    ops,kinds=decoded(values);kinds.update(overrides or {})
    return ar.android_exclusive.native_conditional_refresh(ops[HEAD//4],{op.address:op for op in ops},kinds,ar)
def plan(values,roots=(0,HEAD,END,SUCCESS),overrides=None):
    ops,kinds=decoded(values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ops,kinds,roots,ar)
class RawMachine:
    def __init__(self,source,index,cells,failures=0,competitor=None,*,bound=256):
        self.source=source;self.x=[0xABCD000000000100+i for i in range(31)]
        self.x[9]=0x400000;self.x[10]=index
        self.register_bound=source[(BEGIN+12)//4]&0xFF000000==0xEB000000
        self.x[11]=bound if self.register_bound else 0xAABBCCDDFFFFFFFF
        if self.register_bound:self.x[12]=0xAABBCCDDFFFFFFFF
        self.sp=0x800000;self.flags=0xB0000000;self.q=tuple(range(32))
        self.memory={0x400000+i*16:value for i,value in enumerate(cells)}
        self.failures=failures;self.competitor=competitor
        self.loads=self.stores=self.clears=self.writes=0
    @staticmethod
    def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value
    def run(self):
        pc,monitor=0,None
        for _ in range(200):
            if pc in (END,SUCCESS):
                assert monitor is None
                return 'success' if pc==SUCCESS else 'exhausted'
            word=self.source[pc//4];rt,rn=word&31,word>>5&31;next_pc=pc+4
            if word==0xD5033F5F:monitor=None;self.clears+=1
            elif word&0xFFC00000==0x91000000:self.x[rt]=(self.x[rn]+(word>>10&4095))&0xFFFFFFFFFFFFFFFF
            elif word&0xFFC0001F==0xF100001F:
                left,right=self.x[rn],word>>10&4095;value=(left-right)&0xFFFFFFFFFFFFFFFF
                overflow=bool((left^right)&(left^value)&(1<<63))
                self.flags=((bool(value&(1<<63))<<3)|((value==0)<<2)|((left>=right)<<1)|overflow)<<28
            elif word&0xFFE0FC1F==0xEB00001F:
                left,right=self.x[rn],self.x[word>>16&31];value=(left-right)&0xFFFFFFFFFFFFFFFF
                overflow=bool((left^right)&(left^value)&(1<<63))
                self.flags=((bool(value&(1<<63))<<3)|((value==0)<<2)|((left>=right)<<1)|overflow)<<28
            elif word&0xFFFFFC00==0x885F7C00:self.loads+=1;monitor=self.x[rn];self.x[rt]=self.memory[monitor]&0xFFFFFFFF
            elif word&0xFFE0FC00==0x88007C00:
                self.stores+=1;address=self.x[rn];success=monitor==address and self.stores>self.failures
                if success:self.memory[address]=self.x[rt]&0xFFFFFFFF;self.writes+=1
                elif self.competitor is not None:self.memory[address]=self.competitor
                self.x[word>>16&31]=0 if success else 1;monitor=None
            elif word&0xFF000010==0x54000000:
                assert word&15==0
                if self.flags&0x40000000:next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0xFF000000==0x35000000:
                if self.x[rt]&0xFFFFFFFF:next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0xFC000000==0x14000000:next_pc=pc+self.signed(word&0x3FFFFFF,26)*4
            else:raise AssertionError(f'unmodeled {pc:x}: {word:08x}')
            pc=next_pc
        raise AssertionError('scan did not terminate')
class NativeRotatedScanTests(unittest.TestCase):
    def test_exact_native_union_and_injective_roles_need_no_helpers(self):
        for rename in (None,{9:0,10:1,11:2,12:3},{9:16,10:17,11:27,12:28}):
            values=fixture(rename)
            self.assertEqual(match(values),(set(range(BEGIN,END,4)),HEAD,{HEAD}))
            self.assertEqual(plan(values),())
            image=ar.rewrite(raw(values),entry_offsets=(0,HEAD,END,SUCCESS))
            self.assertEqual(image.bytes,raw(values));self.assertEqual((image.sites,image.fixups,image.gates),((),(),()))
    def test_only_fresh_head_accepts_metadata_and_external_direct_entries(self):
        for pc in set(range(BEGIN,END,4))-{HEAD}:
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):plan(fixture(),roots=(0,HEAD,END,SUCCESS,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(values)
    def test_width_steps_bound_order_roles_edges_and_rewrites_fail_closed(self):
        changes=((0,0xD503201F),(1,0x1100054A),(1,0x9100094A),(2,0x91002129),
                 (3,0x7104015F),(3,0xF108015F),(4,0x540000C1),(4,0x54000020),
                 (5,0x885FFD2C),(5,0xC85F7D2C),(6,0x35FFFF2C),
                 (7,0x880CFD2B),(7,0xC80C7D2B),(8,0x35FFFF0C),(8,0x35FFFF4C),
                 (9,0x94000003),(9,ar.branch(BEGIN+36,HEAD)))
        for slot,word in changes:
            values=fixture();values[BEGIN//4+slot]=word
            with self.subTest(slot=slot,word=hex(word)):self.assertIsNone(match(values))
        for role in (9,10,11,12):
            for register in (18,29,30,31,*({9,10,11,12}-{role})):
                with self.subTest(role=role,register=register):self.assertIsNone(match(fixture({role:register})))
        for slot in range(len(TEMPLATE)):
            for word in (0xD4000001,0x94000000,0xF94003E9):
                values=fixture();values[BEGIN//4+slot]=word
                self.assertIsNone(match(values))
            for kind in ('x18','gate','parameter','parameter_tail'):
                with self.assertRaises(ar.RewriteError):match(fixture(),{BEGIN+slot*4:kind})
    def test_register_bound_order_and_distinct_roles_are_exact(self):
        for rename in (None,{9:0,10:1,11:2,12:3,13:4}):
            values=fixture(rename,register_bound=True)
            self.assertEqual(match(values),(set(range(BEGIN,END,4)),HEAD,{HEAD}))
            self.assertEqual(plan(values),())
            self.assertEqual(ar.rewrite(raw(values),entry_offsets=(0,HEAD,END,SUCCESS)).bytes,raw(values))
        for slot,word in ((3,0xEB0B015F),(3,0x6B0A017F),(5,0x885FFD2D),(7,0x880DFD2C),(8,0x35FFFF4D)):
            values=fixture(register_bound=True);values[BEGIN//4+slot]=word
            self.assertIsNone(match(values))
        for pc in set(range(BEGIN,END,4))-{HEAD}:
            with self.assertRaises(ar.RewriteError):plan(fixture(register_bound=True),roots=(0,HEAD,END,SUCCESS,pc))

    def test_unicorn_busy_failures_exhaustion_competitor_and_counter64_preserve_state(self):
        base_cases=((8,(0,),0,None),(8,(7,0),0,None),(254,(7,9),0,None),(255,(0,),1,None),
               (254,(0,0),1,5),(254,(7,0),1,3),((1<<32)+255,(1,0),0,None),
               (0xFFFFFFFFFFFFFFFF,(7,0),0,None))
        cases=[(register_bound,256,*case) for register_bound in (False,True) for case in base_cases]
        cases += [(True,9,8,(7,),0,None),(True,(1<<32)+256,(1<<32)+255,(7,),0,None)]
        for register_bound,bound,index,cells,failures,competitor in cases:
            with self.subTest(register_bound=register_bound,bound=bound,index=index,cells=cells,failures=failures):
                values=fixture(register_bound=register_bound);image=ar.rewrite(raw(values),entry_offsets=(0,HEAD,END,SUCCESS))
                model=RawMachine(values,index,cells,failures,competitor,bound=bound);expected=model.run()
                base=0x100000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);cpu.mem_map(base,4096);cpu.mem_map(0x400000,4096)
                cpu.mem_write(base,image.bytes);cpu.mem_write(base+0x100,raw([0xD5033F5F,ar.branch(base+0x104,base+BEGIN+28)]))
                before=[0xABCD000000000100+i for i in range(31)];before[9]=0x400000;before[10]=index;before[11]=bound if register_bound else 0xAABBCCDDFFFFFFFF
                if register_bound:before[12]=0xAABBCCDDFFFFFFFF
                for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
                for i,value in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
                cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,model.flags)
                for i,value in enumerate(cells):cpu.mem_write(0x400000+i*16,struct.pack('<IIII',value,0x11223344,0x55667788,0x99AABBCC))
                seen=dict(loads=0,stores=0,clears=0,detour=False,outcome=None)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at in (END,SUCCESS):seen['outcome']='success' if at==SUCCESS else 'exhausted';machine.emu_stop()
                    elif at==HEAD:seen['loads']+=1
                    elif at==BEGIN:seen['clears']+=1
                    elif at==BEGIN+28:
                        if seen['detour']:seen['detour']=False
                        else:
                            seen['stores']+=1
                            if seen['stores']<=failures:
                                if competitor is not None:machine.mem_write(machine.reg_read(uc.UC_ARM64_REG_X9),struct.pack('<I',competitor))
                                seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,base+0x100)
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=500)
                self.assertEqual(seen['outcome'],expected)
                self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                for address,value in model.memory.items():
                    self.assertEqual(struct.unpack('<IIII',cpu.mem_read(address,16)),(value,0x11223344,0x55667788,0x99AABBCC))
                self.assertEqual(tuple(seen[k] for k in ('loads','stores','clears')),(model.loads,model.stores,model.clears))
if __name__=='__main__':unittest.main()
