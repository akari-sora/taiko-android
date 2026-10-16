"""A native publication CAS retires its monitor before reload and cleanup calls."""
from pathlib import Path
import sys,struct,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,CLEANUP,JOIN,CALLEE=16,80,84,112
BLOCK=(0xC85F7D09,0xB40000A9,0xD5033F5F,0x2A1F03EA,0x360000CA,0x1400000C,
       0xC80AFD00,0x340000CA,0x2A1F03EA,0x3700010A,0xF9400FA0,0xB4FFFEA9,
       0x14000004,0x5280002A,0x3607FF8A,0x14000002)
def words():
    v=[0xD503201F]*32
    v[0]=ar.branch(0,BEGIN);v[3]=ar.branch(12,BEGIN);v[4:20]=BLOCK
    v[20]=0x94000008;v[21]=0xD65F03C0;v[28:32]=[0xB940000B,0x1100056B,0xB900000B,0xD65F03C0]
    return v
def raw(v):return struct.pack('<32I',*v)
def decoded(v):
    o=[ar.decode(w,i*4) for i,w in enumerate(v)];return o,{x.address:x for x in o},{x.address:ar.site_kind(x) for x in o}
def match(v,kinds=None):
    o,b,k=decoded(v);k.update(kinds or {});return ar.android_exclusive.native_conditional_refresh(b[BEGIN],b,k,ar)
class Model:
    def __init__(self,initial,failures=0,competitor=None,slot=None):
        self.x=[0xAABB000000000100+i for i in range(31)];self.x[0]=0x500000;self.x[8]=0x400000;self.x[29]=0x800000
        self.memory={0x400000:initial,0x400008:0x1122334455667788,0x800018:0x500000,0x500000:41,0x501000:57}
        self.sp,self.flags=0x900000,0xB0000000;self.q=tuple(range(32));self.failures,self.competitor,self.slot=failures,competitor,slot
        self.loads=self.stores=self.clears=self.calls=0
    @staticmethod
    def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
    def run(self):
        pc,monitor=0,None
        for _ in range(300):
            if pc==JOIN:assert monitor is None;return
            w=words()[pc//4];rt,rn=w&31,w>>5&31;nxt=pc+4
            if w&0xFFFFFC00==0xC85F7C00:self.loads+=1;monitor=self.x[rn];self.x[rt]=self.memory[monitor]
            elif w&0xFFE0FC00==0xC800FC00:
                self.stores+=1;success=monitor==self.x[rn] and self.stores>self.failures
                if success:self.memory[self.x[rn]]=self.x[rt]
                elif self.competitor is not None:self.memory[self.x[rn]]=self.competitor
                self.x[w>>16&31]=0 if success else 1;monitor=None
            elif w==0xD5033F5F:monitor=None;self.clears+=1
            elif w&0xFFC00000==0xF9400000:
                if self.slot is not None:self.memory[0x800018]=self.slot
                self.x[rt]=self.memory[self.x[rn]+(w>>10&4095)*8]
            elif w&0xFFC00000==0xB9400000:self.x[rt]=self.memory[self.x[rn]+(w>>10&4095)*4]&0xFFFFFFFF
            elif w&0xFFC00000==0xB9000000:self.memory[self.x[rn]+(w>>10&4095)*4]=self.x[rt]&0xFFFFFFFF
            elif w&0xFFC00000==0x11000000:self.x[rt]=(self.x[rn]+(w>>10&4095))&0xFFFFFFFF
            elif w&0xFFE0FFE0==0x2A0003E0:self.x[rt]=0 if w>>16&31==31 else self.x[w>>16&31]&0xFFFFFFFF
            elif w&0xFFFFFC00==0x52800000:self.x[rt]=w>>5&65535
            elif w&0x7E000000==0x34000000:
                value=self.x[rt] if w>>31 else self.x[rt]&0xFFFFFFFF
                if bool(value)==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0x7E000000==0x36000000:
                bit=(w>>31)*32+(w>>19&31)
                if bool(self.x[rt]&(1<<bit))==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x3FFF,14)*4
            elif w&0xFC000000==0x94000000:
                assert monitor is None;self.calls+=1;self.x[30]=0x100000+pc+4;nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            elif w&0xFC000000==0x14000000:nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            elif w==0xD65F03C0:assert monitor is None;nxt=self.x[30]-0x100000
            else:raise AssertionError(hex(w))
            pc=nxt
        raise AssertionError('publication did not finish')
class NativePublicationCasTests(unittest.TestCase):
    def test_exact_union_stays_native_and_keeps_cleanup_outside(self):
        self.assertEqual(match(words()),(set(range(BEGIN,CLEANUP,4)),BEGIN,{BEGIN}))
        image=ar.rewrite(raw(words()),entry_offsets=(0,BEGIN,CLEANUP,JOIN,CALLEE))
        self.assertEqual(image.bytes,raw(words()));self.assertFalse(image.sites)
    def test_every_interior_entry_and_missing_word_refuse(self):
        for pc in range(BEGIN+4,CLEANUP,4):
            o,b,k=decoded(words())
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(0,BEGIN,CLEANUP,JOIN,CALLEE,pc),ar)
            v=words();v[1]=ar.branch(4,pc);o,b,k=decoded(v)
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(0,BEGIN,CLEANUP,JOIN,CALLEE),ar)
        for pc in range(BEGIN,CLEANUP,4):
            o,b,k=decoded(words());del b[pc]
            self.assertIsNone(ar.android_exclusive.native_conditional_refresh(o[BEGIN//4],b,k,ar))
    def test_width_order_fp_slot_boolean_and_gate_mutations_refuse(self):
        for i,w in ((0,0xC85FFD09),(0,0x885F7D09),(1,0x340000A9),(2,0xD503201F),
                    (4,0x360800CA),(6,0xC80A7D00),(7,0xB40000CA),(9,0x3708010A),
                    (10,0xF9400BA0),(10,0xF9400F80),(10,0xB9400FA0),(11,0x34FFFEA9),
                    (13,0x5280004A),(14,0x360FFF8A),(15,0x94000002)):
            v=words();v[BEGIN//4+i]=w;self.assertIsNone(match(v))
        for pc in range(BEGIN,CLEANUP,4):
            with self.assertRaises(ar.RewriteError):match(words(),{pc:'parameter'})
    def test_cpu_executes_real_returning_cleanup_only_after_closed_reservation(self):
        image=ar.rewrite(raw(words()),entry_offsets=(0,BEGIN,CLEANUP,JOIN,CALLEE))
        for initial,failures,competitor,slot in ((0,0,None,None),(0x501000,0,None,None),
                (0,2,None,None),(0,1,None,0x501000),(0,1,0x501000,None),
                (1<<32,0,None,None),(0,1,1<<32,0x501000)):
            with self.subTest(initial=initial,failures=failures,competitor=competitor,slot=slot):
                model=Model(initial,failures,competitor,slot);before=model.x.copy();model.run()
                base,stub=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                for address in (base,stub,0x400000,0x500000,0x501000,0x800000):cpu.mem_map(address,4096)
                cpu.mem_write(base,image.bytes);cpu.mem_write(stub,struct.pack('<2I',0xD5033F5F,ar.branch(stub+4,base+BEGIN+24)))
                for i,v in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),v)
                for i,v in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),v)
                cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,model.flags)
                cpu.mem_write(0x400000,struct.pack('<QQ',initial,0x1122334455667788));cpu.mem_write(0x800018,struct.pack('<Q',0x500000))
                cpu.mem_write(0x500000,struct.pack('<II',41,0x55667788));cpu.mem_write(0x501000,struct.pack('<II',57,0x99AABBCC))
                seen=dict(loads=0,stores=0,clears=0,calls=0,detour=False,live=False,done=False)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at==JOIN:self.assertFalse(seen['live']);seen['done']=True;machine.emu_stop()
                    elif at==BEGIN:seen['loads']+=1;seen['live']=True
                    elif at==BEGIN+8:seen['clears']+=1;seen['live']=False
                    elif at==BEGIN+24:
                        if seen['detour']:seen['detour']=False
                        else:
                            seen['stores']+=1
                            if seen['stores']<=failures:
                                if competitor is not None:machine.mem_write(0x400000,struct.pack('<Q',competitor))
                                seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,stub)
                        seen['live']=False
                    elif at==BEGIN+40 and slot is not None:machine.mem_write(0x800018,struct.pack('<Q',slot))
                    elif at==CLEANUP:self.assertFalse(seen['live']);seen['calls']+=1
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+128,count=1000)
                self.assertTrue(seen['done']);self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                for address,v in model.memory.items():self.assertEqual(int.from_bytes(cpu.mem_read(address,4 if address in (0x500000,0x501000) else 8),'little'),v)
                self.assertEqual(tuple(seen[k] for k in ('loads','stores','clears','calls')),(model.loads,model.stores,model.clears,model.calls))
if __name__=='__main__':unittest.main()
