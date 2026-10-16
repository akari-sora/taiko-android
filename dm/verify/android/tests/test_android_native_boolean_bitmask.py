"""Native boolean bitmask retries keep their zero/one joins and loaded value."""
from pathlib import Path
import sys,struct,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from test_android_native_expected_refresh import Model
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,HEAD,END=16,44,80
BLOCK=(3573759839, 706675692, 706675688, 889192876, 168362349, 705364972, 889192781, 2287959371, 1795948927, 1426063073, 705233288, 2282519880, 905969324, 1384120364, 706675688, 889192108)
def words():return [ar.branch(0,HEAD),0xD503201F,0xD503201F,ar.branch(12,HEAD)]+list(BLOCK)+[0xD65F03C0,0xD503201F]
def raw(v):return struct.pack('<'+'I'*len(v),*v)
def ops(v):
    o=[ar.decode(w,i*4) for i,w in enumerate(v)];return o,{x.address:x for x in o},{x.address:ar.site_kind(x) for x in o}
def match(v):
    o,b,k=ops(v);return ar.android_exclusive.native_conditional_refresh(b[HEAD],b,k,ar)
class BitmapModel(Model):
    def run(self):
        pc,monitor=0,None
        for _ in range(300):
            if pc==END:assert monitor is None;return
            w=self.values[pc//4];rt,rn=w&31,w>>5&31;nxt=pc+4
            if w&0xFFFFFC00==0x885F7C00:self.loads+=1;monitor=self.x[rn];self.x[rt]=self.memory
            elif w&0xFFE0FC00==0x88007C00:
                self.stores+=1;success=monitor==self.x[rn] and self.stores>self.failures
                if success:self.memory=self.x[rt]&0xFFFFFFFF;self.writes+=1
                elif self.competitor is not None:self.memory=self.competitor
                self.x[w>>16&31]=0 if success else 1;monitor=None
            elif w==0xD5033F5F:monitor=None;self.clears+=1
            elif w&0xFFE0FC1F==0x6B00001F:self.cmp(self.x[rn],self.x[w>>16&31])
            elif w&0xFFE0FFE0==0x2A0003E0:self.x[rt]=0 if w>>16&31==31 else self.x[w>>16&31]&0xFFFFFFFF
            elif w&0xFFE0FC00==0x0A000000:self.x[rt]=(self.x[rn]&self.x[w>>16&31])&0xFFFFFFFF
            elif w&0xFFE0FC00==0x2A000000:self.x[rt]=(self.x[rn]|self.x[w>>16&31])&0xFFFFFFFF
            elif w&0xFFFFFC00==0x52800000:self.x[rt]=w>>5&65535
            elif w&0xFF000010==0x54000000:
                assert w&15==1
                if not self.flags&0x40000000:nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0xFC000000==0x14000000:nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            else:raise AssertionError(hex(w))
            pc=nxt
        raise AssertionError('bitmap retry did not exit')
class NativeBooleanBitmaskTests(unittest.TestCase):
    def test_exact_source_union_stays_native(self):
        self.assertEqual(match(words()),(set(range(BEGIN,END,4)),HEAD,{HEAD}))
        image=ar.rewrite(raw(words()),entry_offsets=(0,HEAD,END));self.assertEqual(image.bytes,raw(words()));self.assertFalse(image.sites)
    def test_interior_entries_width_order_boolean_and_memory_mutations_refuse(self):
        for pc in set(range(BEGIN,END,4))-{HEAD}:
            o,b,k=ops(words())
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(0,HEAD,END,pc),ar)
            v=words();v[1]=ar.branch(4,pc)
            o,b,k=ops(v)
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(0,HEAD,END),ar)
        for slot in range(len(BLOCK)):
            for w in (0xD4000001,0x94000000,0xF9400008):
                v=words();v[BEGIN//4+slot]=w;self.assertIsNone(match(v))
            o,b,k=ops(words());k[BEGIN+slot*4]='parameter'
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.native_conditional_refresh(b[HEAD],b,k,ar)
        for slot,bit in ((1,31),(3,31),(4,31),(7,15),(8,31),(11,15),(13,5),(15,24)):
            v=words();v[BEGIN//4+slot]^=1<<bit;self.assertIsNone(match(v))
    def test_cpu_matches_independent_boolean_retry_model(self):
        image=ar.rewrite(raw(words()),entry_offsets=(0,HEAD,END))
        for initial,expected,failures,competitor in ((0,0,0,None),(4,0,0,None),(8,0,0,None),
                (0,0,2,None),(0,0,1,8),(0,0,1,4),(0xFFFFFFFF,0xFFFFFFFF,0,None)):
            with self.subTest(initial=initial,expected=expected,failures=failures,competitor=competitor):
                model=BitmapModel(words(),initial,expected,failures,competitor)
                model.x[9]=0xAABB000000000004;model.x[10]=0x400000;model.x[12]=0xCCDD000000000000|expected
                before=model.x.copy();model.run();base,stub=0x100000,0x700000
                cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                for address in (base,stub,0x400000):cpu.mem_map(address,4096)
                cpu.mem_write(base,image.bytes);cpu.mem_write(0x400000,struct.pack('<II',initial,0x11223344))
                for i,v in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),v)
                for i,v in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),v)
                cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
                state=dict(attempts=0,detour=False,done=False)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at==END:state['done']=True;machine.emu_stop()
                    elif at==BEGIN+44:
                        if state['detour']:state['detour']=False
                        else:
                            state['attempts']+=1
                            if state['attempts']<=failures:
                                if competitor is not None:machine.mem_write(0x400000,struct.pack('<I',competitor))
                                machine.mem_write(stub,struct.pack('<2I',0xD5033F5F,ar.branch(stub+4,pc)));state['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,stub)
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=1000)
                self.assertTrue(state['done']);self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                self.assertEqual(struct.unpack('<II',cpu.mem_read(0x400000,8)),(model.memory,0x11223344))
if __name__=='__main__':unittest.main()
