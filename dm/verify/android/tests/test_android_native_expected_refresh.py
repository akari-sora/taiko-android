"""A native expected-value refresh preserves status flags and reservation closure."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,END,REJECT=16,80,96
TEMPLATE=(0x885F7F09,0x6B0A013F,0x540000E1,0x1100054A,0x880B7F0A,0x350000AB,
          0x5280002A,0x360000AA,0x14000008,0xD5033F5F,0x2A1F03EA,0x370000AA,
          0x7100053F,0x2A0903EA,0x54FFFE4A,0x14000005)
FIELDS=((0,5),(5,16),(),(0,5),(0,5,16),(0,),(0,),(0,),(),(),(0,),(0,),(5,),(0,16),(),())
def fixture(rename=None):
    block=list(TEMPLATE)
    for i,fields in enumerate(FIELDS):
        for shift in fields:
            role=TEMPLATE[i]>>shift&31
            if rename:block[i]=block[i]&~(31<<shift)|rename.get(role,role)<<shift
    return [ar.branch(0,BEGIN),0xD503201F,0xD503201F,ar.branch(12,BEGIN)]+block+[
        0xD65F03C0,0xD503201F,0xD503201F,0xD503201F,0xD65F03C0,0xD503201F]
def raw(values):return struct.pack('<'+'I'*len(values),*values)
def decoded(values):
    ops=[ar.decode(word,i*4) for i,word in enumerate(values)];return ops,{o.address:ar.site_kind(o) for o in ops}
def match(values,overrides=None):
    ops,kinds=decoded(values);kinds.update(overrides or {})
    return ar.android_exclusive.native_conditional_refresh(ops[BEGIN//4],{o.address:o for o in ops},kinds,ar)
def plan(values,roots=(0,BEGIN,END,REJECT),overrides=None):
    ops,kinds=decoded(values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ops,kinds,roots,ar)
class Model:
    def __init__(self,values,initial,expected,failures=0,competitor=None):
        self.values=values;self.x=[0xAABB000000000100+i for i in range(31)]
        self.x[24]=0x400000;self.x[10]=0xCCDD000000000000|expected
        self.sp=0x800000;self.flags=0xB0000000;self.q=tuple(range(32));self.memory=initial
        self.failures=failures;self.competitor=competitor;self.loads=self.stores=self.clears=self.writes=0
    @staticmethod
    def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
    def cmp(self,left,right):
        left&=0xFFFFFFFF;right&=0xFFFFFFFF;v=(left-right)&0xFFFFFFFF
        overflow=bool((left^right)&(left^v)&0x80000000)
        self.flags=((bool(v&0x80000000)<<3)|((v==0)<<2)|((left>=right)<<1)|overflow)<<28
    def run(self):
        pc,monitor=0,None
        for _ in range(300):
            if pc in (END,REJECT):
                assert monitor is None
                return 'success' if pc==END else 'reject'
            w=self.values[pc//4];rt,rn=w&31,w>>5&31;next_pc=pc+4
            if w&0xFFFFFC00==0x885F7C00:self.loads+=1;monitor=self.x[rn];self.x[rt]=self.memory
            elif w&0xFFE0FC00==0x88007C00:
                self.stores+=1;success=monitor==self.x[rn] and self.stores>self.failures
                if success:self.memory=self.x[rt]&0xFFFFFFFF;self.writes+=1
                elif self.competitor is not None:self.memory=self.competitor
                self.x[w>>16&31]=0 if success else 1;monitor=None
            elif w==0xD5033F5F:monitor=None;self.clears+=1
            elif w&0xFFE0FC1F==0x6B00001F:self.cmp(self.x[rn],self.x[w>>16&31])
            elif w&0xFFC0001F==0x7100001F:self.cmp(self.x[rn],w>>10&4095)
            elif w&0xFFC00000==0x11000000:self.x[rt]=(self.x[rn]+(w>>10&4095))&0xFFFFFFFF
            elif w&0xFFFFFC00==0x52800000:self.x[rt]=w>>5&65535
            elif w&0xFFE0FFE0==0x2A0003E0:self.x[rt]=0 if w>>16&31==31 else self.x[w>>16&31]&0xFFFFFFFF
            elif w&0xFF000010==0x54000000:
                condition=w&15;n,v=bool(self.flags&0x80000000),bool(self.flags&0x10000000)
                taken=not bool(self.flags&0x40000000) if condition==1 else n==v if condition==10 else None
                assert taken is not None
                if taken:next_pc=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(w&0x1000000):next_pc=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0x7E000000==0x36000000:
                bit=(w>>31)*32+(w>>19&31)
                if bool(self.x[rt]&(1<<bit))==bool(w&0x1000000):next_pc=pc+self.signed(w>>5&0x3FFF,14)*4
            elif w&0x7C000000==0x14000000:next_pc=pc+self.signed(w&0x3FFFFFF,26)*4
            else:raise AssertionError(hex(w))
            pc=next_pc
        raise AssertionError('refresh did not terminate')
class NativeExpectedRefreshTests(unittest.TestCase):
    def test_exact_row_and_ordinary_role_renames_keep_bytes(self):
        for rename in (None,{24:0,9:1,10:2,11:3},{24:28,9:16,10:17,11:27}):
            values=fixture(rename);self.assertEqual(match(values),(set(range(BEGIN,END,4)),BEGIN,{BEGIN}))
            self.assertEqual(plan(values),());image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,END,REJECT))
            self.assertEqual(image.bytes,raw(values));self.assertEqual((image.sites,image.fixups,image.gates),((),(),()))
    def test_every_interior_entry_is_rejected(self):
        for pc in range(BEGIN+4,END,4):
            with self.assertRaises(ar.RewriteError):plan(fixture(),roots=(0,BEGIN,END,REJECT,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.assertRaises(ar.RewriteError):plan(values)
    def test_width_order_bits_flags_alias_and_rewrites_are_exact(self):
        for slot,w in ((0,0x885FFF09),(0,0xC85F7F09),(1,0x6B0B013F),(2,0x540000E0),
                       (3,0x9100054A),(4,0x880BFF0A),(5,0x340000AB),(7,0x360800AA),
                       (8,0x14000007),(9,0xD503201F),(10,0x2A0903EA),(11,0x370800AA),
                       (12,0x7100093F),(13,0xAA0903EA),(14,0x54FFFE4B),(15,0x94000005)):
            values=fixture();values[BEGIN//4+slot]=w;self.assertIsNone(match(values))
        for role in (24,9,10,11):
            for bad in (18,29,30,31,*({24,9,10,11}-{role})):self.assertIsNone(match(fixture({role:bad})))
        for pc in range(BEGIN,END,4):
            for kind in ('x18','gate','parameter','parameter_tail'):
                with self.assertRaises(ar.RewriteError):match(fixture(),{pc:kind})
    def test_unicorn_matches_independent_flags_status_and_competition_model(self):
        values=fixture();image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,END,REJECT))
        cases=((2,2,0,None),(3,2,0,None),(0,2,0,None),(0xFFFFFFFF,2,0,None),
               (2,2,1,None),(2,2,1,0),(2,2,1,3),(2,2,2,3),(0xFFFFFFFF,0xFFFFFFFF,0,None))
        for initial,expected,failures,competitor in cases:
            with self.subTest(initial=initial,expected=expected,failures=failures,competitor=competitor):
                model=Model(values,initial,expected,failures,competitor);outcome=model.run()
                base=0x100000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);cpu.mem_map(base,4096);cpu.mem_map(0x400000,4096)
                cpu.mem_write(base,image.bytes);cpu.mem_write(base+0x100,raw([0xD5033F5F,ar.branch(base+0x104,base+BEGIN+16)]))
                before=[0xAABB000000000100+i for i in range(31)];before[24]=0x400000;before[10]=0xCCDD000000000000|expected
                for i,v in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),v)
                for i,v in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),v)
                cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,model.flags)
                cpu.mem_write(0x400000,struct.pack('<II',initial,0x11223344));seen=dict(loads=0,stores=0,clears=0,detour=False,outcome=None)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at in (END,REJECT):seen['outcome']='success' if at==END else 'reject';machine.emu_stop()
                    elif at==BEGIN:seen['loads']+=1
                    elif at==BEGIN+36:seen['clears']+=1
                    elif at==BEGIN+16:
                        if seen['detour']:seen['detour']=False
                        else:
                            seen['stores']+=1
                            if seen['stores']<=failures:
                                if competitor is not None:machine.mem_write(0x400000,struct.pack('<I',competitor))
                                seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,base+0x100)
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=600)
                self.assertEqual(seen['outcome'],outcome)
                self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                self.assertEqual(struct.unpack('<II',cpu.mem_read(0x400000,8)),(model.memory,0x11223344))
                self.assertEqual(tuple(seen[k] for k in ('loads','stores','clears')),(model.loads,model.stores,model.clears))
if __name__=='__main__':unittest.main()
