"""Raw original TryLock43 fixtures keep nonzero pin-state explicitly unsupported."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,END,CALLEE=0x100,0x1AC,0x200
PRODUCER,ENTRY,HEAD=BEGIN+16,BEGIN+20,BEGIN+36
HOLE=set(range(BEGIN+72,BEGIN+88,4))
NODES=set(range(ENTRY,END,4))-HOLE
HEADS={HEAD,BEGIN+116,BEGIN+132}
CELL,TLR,STACK=0x400000,0x500000,0x800000
MASK=(1<<64)-1
WORDS=(
    0xA9BD7BFD, 0xA90157F6, 0x910003FD, 0xA9024FF4,
    0xD53BD074, 0x79420295, 0xF9800010, 0x110006B6,
    0x79020296, 0x885FFC08, 0x34000188, 0xD5033F5F,
    0x79020295, 0x35000095, 0x79420688, 0x34000048,
    0x94016E4E, 0x2A1F03E0, 0xA9424FF4, 0xA94157F6,
    0xA8C37BFD, 0xD65F03C0, 0xAA0003F3, 0x34000195,
    0x52800020, 0x88087E60, 0x34FFFF08, 0x79020295,
    0x79020296, 0x885FFE68, 0x34FFFF68, 0x17FFFFEC,
    0x79020296, 0x885FFE68, 0x35FFFD28, 0x52800020,
    0x88087E60, 0x34FFFDA8, 0x7902029F, 0x79420688,
    0x34FFFF08, 0x94016E35, 0x17FFFFF6,
)

def raw(values):return struct.pack('<'+'I'*len(values),*values)
def fixture():
    v=[0xD503201F]*(0x220//4);v[BEGIN//4:END//4]=WORDS
    for at in (BEGIN+64,BEGIN+164):v[at//4]=0x94000000|((CALLEE-at)//4)&0x3FFFFFF
    v[CALLEE//4:CALLEE//4+2]=[0xD40006C1,0xD65F03C0]
    return v

def decoded(v):
    ops=[ar.decode(w,i*4) for i,w in enumerate(v)];return ops,{i.address:ar.site_kind(i) for i in ops}

def require_helper(test):
    helper=getattr(ar.android_exclusive,'native_try_mutex',None)
    test.assertTrue(callable(helper),'Shared native_try_mutex not integrated yet')
    return helper

class RawTryModel:
    """Independent raw A64 model; nonzero interrupt pin-state has no success model."""
    def __init__(self,values,old,busy=0,failures=0,competitor=None,interrupt=0):
        self.values=values;self.x=[0xAABB000000001000+i*0x101 for i in range(31)]
        self.x[0]=CELL;self.x[30]=0xFFFFFFFFFFFFFFFC
        self.sp=STACK+0x800;self.nzcv=0xB0000000;self.q=tuple(int.from_bytes(bytes([i])*16,'little') for i in range(32))
        self.pages={a:bytearray((i*13+7)%256 for i in range(4096)) for a in (CELL,TLR,STACK)}
        self.write(CELL,4,busy);self.write(TLR+0x100,2,old);self.write(TLR+0x102,2,interrupt)
        self.failures,self.competitor=failures,competitor
        self.loads=self.stores=self.clears=self.flag_reads=self.calls=0;self.counter_writes=[]
    def read(self,address,size):base=address&~4095;return int.from_bytes(self.pages[base][address-base:address-base+size],'little')
    def write(self,address,size,value):
        base=address&~4095;self.pages[base][address-base:address-base+size]=(value&((1<<(size*8))-1)).to_bytes(size,'little')
    @staticmethod
    def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
    def run(self):
        pc,monitor=BEGIN,None
        for _ in range(1000):
            w=self.values[pc//4];rt,rn=w&31,w>>5&31;nxt=pc+4
            if w==0xD65F03C0:
                assert monitor is None and self.x[30]==0xFFFFFFFFFFFFFFFC
                return bool(self.x[0])
            if w&0x3A000000==0x28000000:
                mode=w>>23&3;delta=self.signed(w>>15&127,7)*8;base=self.sp if rn==31 else self.x[rn]
                address=base if mode==1 else base+delta;rt2=w>>10&31
                if w>>22&1:self.x[rt],self.x[rt2]=self.read(address,8),self.read(address+8,8)
                else:self.write(address,8,self.x[rt]);self.write(address+8,8,self.x[rt2])
                if mode in (1,3):
                    if rn==31:self.sp=(base+delta)&MASK
                    else:self.x[rn]=(base+delta)&MASK
            elif w&0xFFFFFFE0==0xD53BD060:self.x[rt]=TLR
            elif w==0x910003FD:self.x[29]=self.sp
            elif w&0xFFC00000==0x79400000:
                address=self.x[rn]+(w>>10&4095)*2;self.flag_reads+=address==TLR+0x102;self.x[rt]=self.read(address,2)
            elif w&0xFFC00000==0x79000000:
                address=self.x[rn]+(w>>10&4095)*2;value=0 if rt==31 else self.x[rt]&0xFFFF
                assert monitor is None;self.write(address,2,value);self.counter_writes.append((address,value))
            elif w&0xFFC00000==0x11000000:self.x[rt]=(self.x[rn]+(w>>10&4095))&0xFFFFFFFF
            elif w&0x7FE0FFE0==0x2A0003E0:
                value=0 if w>>16&31==31 else self.x[w>>16&31];self.x[rt]=value if w>>31 else value&0xFFFFFFFF
            elif w&0xFFE00000==0x52800000:self.x[rt]=w>>5&65535
            elif w&0xFFFFFC00==0x885FFC00:
                self.loads+=1;assert monitor is None;monitor=self.x[rn];self.x[rt]=self.read(self.x[rn],4)
            elif w&0xFFE0FC00==0x88007C00:
                assert monitor==self.x[rn];self.stores+=1;success=self.stores>self.failures
                if success:self.write(self.x[rn],4,self.x[rt])
                elif self.competitor is not None:self.write(CELL,4,self.competitor)
                self.x[w>>16&31]=0 if success else 1;monitor=None
            elif w==0xD5033F5F:monitor=None;self.clears+=1
            elif w&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0xFC000000==0x94000000:
                self.calls+=1;assert monitor is None
                raise ValueError('nonzero pin-state: voidSVC36 runtime remains unsupported by this raw fixture model')
            elif w&0xFC000000==0x14000000:nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            elif w&0xFFC00000==0xF9800000:pass
            else:raise AssertionError((hex(pc),hex(w)))
            pc=nxt
        raise AssertionError('TryLock43 source did not terminate')

class NativeTryMutex43Tests(unittest.TestCase):
    def test_observed_source_union_heads_and_ordinary_stack_hole(self):
        v=fixture();ops,kinds=decoded(v);by={i.address:i for i in ops};helper=require_helper(self)
        self.assertEqual(helper(by[HEAD],by,kinds,ar),(NODES,ENTRY,HEADS))
        self.assertEqual(ar.android_exclusive.plan_regions(ops,kinds,(BEGIN,CALLEE),ar),())
        image=ar.rewrite(raw(v),entry_offset=BEGIN,entry_offsets=(BEGIN,CALLEE),package_version=2,checked_stack=True)
        for pc in NODES:self.assertEqual(image.bytes[pc:pc+4],raw(v)[pc:pc+4])
        self.assertTrue(any(s.offset==PRODUCER for s in image.sites))
        self.assertFalse(any(s.offset in NODES for s in image.sites))
    def test_producer_inclusive_external_entry_and_typed_transfer_refusals(self):
        v=fixture();ops,kinds=decoded(v);require_helper(self)
        for pc in sorted(NODES):
            with self.subTest(root=hex(pc)),self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,kinds,(BEGIN,CALLEE,pc),ar)
            changed=list(v);changed[0]=ar.branch(0,pc);o,k=decoded(changed)
            with self.subTest(edge=hex(pc)),self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(BEGIN,CALLEE),ar)
    def test_exact_fixed_bits_missing_source_stub_TLS_and_hole_facts_refuse(self):
        fields=((0,5),(5,),(0,5),(0,5),(0,5),(0,),(),(0,5),(0,),(0,5),(0,),(),(0,),(0,10),(0,10),(),(),(0,16),(0,),(0,),(0,5,16),(0,),(0,5),(0,5),(0,5),(0,),(),(0,5),(0,5),(0,),(0,),(0,5,16),(0,),(0,5),(0,5),(0,),(),())
        v=fixture();ops,kinds=decoded(v);by={i.address:i for i in ops};helper=require_helper(self)
        for index,shifts in enumerate(fields):
            pc=ENTRY+index*4;w=v[pc//4]
            mask=sum(31<<shift for shift in shifts if (w>>shift&31) not in (0,31))
            if index in (11,36):mask|=0x3FFFFFF
            for bit in range(32):
                if mask>>bit&1:continue
                changed=dict(by)
                try:
                    changed[pc]=ar.decode(w^(1<<bit),pc);ck=dict(kinds);ck[pc]=ar.site_kind(changed[pc]);r=helper(changed[HEAD],changed,ck,ar)
                except ar.RewriteError:r=None
                self.assertIsNone(r,(index,bit))
        for pc in range(ENTRY,END,4):
            missing=dict(by);del missing[pc];self.assertIsNone(helper(by[HEAD],missing,kinds,ar))
            if pc in NODES:
                for kind in ('gate','x18','parameter','parameter_tail','missing'):
                    ck=dict(kinds)
                    if kind=='missing':del ck[pc]
                    else:ck[pc]=kind
                    with self.assertRaises(ar.RewriteError):helper(by[HEAD],by,ck,ar)
        for pc in (PRODUCER,CALLEE,CALLEE+4):
            missing=dict(by);del missing[pc];self.assertIsNone(helper(by[HEAD],missing,kinds,ar))
            ck=dict(kinds);del ck[pc];self.assertIsNone(helper(by[HEAD],by,ck,ar))
            ck=dict(kinds);ck[pc]='x18';self.assertIsNone(helper(by[HEAD],by,ck,ar))
        for pc in (CALLEE,CALLEE+4):
            changed=dict(by);changed[pc]=ar.decode(0xD503201F,pc);self.assertIsNone(helper(by[HEAD],changed,kinds,ar))
        changed=dict(by);at=BEGIN+64;changed[at]=ar.decode(0x94000000|((CALLEE+4-at)//4)&0x3FFFFFF,at)
        self.assertIsNone(helper(by[HEAD],changed,kinds,ar))
        # Fixed ABI0; every other ordinary role remains injective, including both
        # halves of the source's X0->X19 bridge and all source epilogue operands.
        def rename(mapping):
            changed=list(v)
            for index,shifts in enumerate(fields):
                at=ENTRY+index*4;w=v[at//4]
                for shift in shifts:
                    role=v[at//4]>>shift&31
                    if role!=31:w=(w&~(31<<shift))|(mapping.get(role,role)<<shift)
                changed[at//4]=w
            changed[PRODUCER//4]=0xD53BD060|mapping.get(20,20)
            try:o,k=decoded(changed)
            except ar.RewriteError:return None # invalid architectural register combinations already refuse
            b={i.address:i for i in o};return helper(b[HEAD],b,k,ar)
        self.assertIsNotNone(rename({8:9,19:23,20:24,21:25,22:26}))
        roles={0,8,19,20,21,22}
        for role in roles:
            for bad in (18,29,30,31,*sorted(roles-{role})):
                self.assertIsNone(rename({role:bad}),(role,bad))
        self.assertIsNone(rename({0:1}))
    def test_raw_indirect_offsets_do_not_replace_processed_transfer_facts(self):
        v=fixture();v[0]=0xD61F0120;ops,kinds=decoded(v);require_helper(self)
        for facts in (None,{0}, {0:None},{0:('host',(ENTRY,))},{0:('finite',(ENTRY,))},{0:('finite',())}):
            with self.subTest(facts=facts),self.assertRaises(ar.RewriteError):
                ar.android_exclusive.plan_regions(ops,kinds,(BEGIN,CALLEE),ar,native_wait_transfers=facts)
        kinds[0]='gate' # fact is valid only after the normal checked-host lowering
        self.assertEqual(ar.android_exclusive.plan_regions(ops,kinds,(BEGIN,CALLEE),ar,native_wait_transfers={0:('host',())}),())
        ck=dict(kinds);ck[0]=None
        with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,ck,(BEGIN,CALLEE),ar,native_wait_transfers={0:('host',())})
        # A validated finite/checked-call target may enter only the TLS producer.
        for opcode,kind,fact in ((0xD61F0120,None,'finite'),(0xD63F0120,'checked_call','checked-call'),(0xD63F0120,'checked_call_forest_stub','checked-call-forest')):
            changed=list(v);changed[0]=opcode;o,k=decoded(changed);k[0]=kind
            self.assertEqual(ar.android_exclusive.plan_regions(o,k,(BEGIN,CALLEE,PRODUCER),ar,native_wait_transfers={0:(fact,(PRODUCER,))}),())
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(BEGIN,CALLEE,ENTRY),ar,native_wait_transfers={0:(fact,(ENTRY,))})
        v=fixture();v[0]=0xD65F0120;o,k=decoded(v)
        with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(BEGIN,CALLEE),ar)
    def test_producer_ownership_reuses_existing_previous_and_next_window_checks(self):
        from types import SimpleNamespace
        from test_android_native_wait_mutex import assert_producer_ownership_exclusive
        import test_android_native_try_mutex as old
        def ownership_fixture():
            # Synthetic recognizer ownership test, not a source execution case:
            # direct the ordinary prologue fallthrough to the fake previous entry.
            values=fixture();values[(PRODUCER-4)//4]=ar.branch(PRODUCER-4,4);return values
        assert_producer_ownership_exclusive(self,SimpleNamespace(BEGIN=ENTRY,END=END,CALLEE=CALLEE,fixture=ownership_fixture))
        assert_producer_ownership_exclusive(self,old)
    def test_raw_original_cpu_full_stack_counter_and_both_retry_islands(self):
        cases=((0,0,0,None),(7,0,0,None),(0,1,0,None),(7,1,0,None),(0,0,3,None),(7,0,3,None),(0,0,1,9),(7,0,1,9),(0xFFFF,0,2,None))
        v=fixture();image=raw(v)
        for old,busy,failures,competitor in cases:
            with self.subTest(old=old,busy=busy,failures=failures,competitor=competitor):
                model=RawTryModel(v,old,busy,failures,competitor);before=model.x.copy();pages={a:bytes(b) for a,b in model.pages.items()};want=model.run()
                base,stub=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                for address in (base,stub,*pages):cpu.mem_map(address,4096)
                cpu.mem_write(base,image)
                stores=(BEGIN+100,BEGIN+144)
                for i,store in enumerate(stores):cpu.mem_write(stub+i*8,struct.pack('<2I',0xD5033F5F,ar.branch(stub+i*8+4,base+store)))
                for address,data in pages.items():cpu.mem_write(address,data)
                for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
                for i,value in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
                cpu.reg_write(uc.UC_ARM64_REG_SP,STACK+0x800);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000);cpu.reg_write(uc.UC_ARM64_REG_TPIDRRO_EL0,TLR)
                seen=dict(done=False,live=False,loads=0,stores=0,clears=0,flag_reads=0,counter_writes=[],detour=False)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at==BEGIN+84:
                        self.assertFalse(seen['live']);seen['done']=True;machine.emu_stop();return
                    if at in HEADS:self.assertFalse(seen['live']);seen['live']=True;seen['loads']+=1
                    elif at==BEGIN+44:seen['live']=False;seen['clears']+=1
                    elif at in stores:
                        if seen['detour']:seen['detour']=False
                        else:
                            seen['stores']+=1
                            if seen['stores']<=failures:
                                if competitor is not None:machine.mem_write(CELL,struct.pack('<I',competitor))
                                seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,stub+stores.index(at)*8)
                        seen['live']=False
                    if BEGIN<=at<END:
                        w=v[at//4];rt,rn=w&31,w>>5&31
                        if w&0xFFC00000==0x79000000:
                            self.assertFalse(seen['live']);address=machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{rn}'))+(w>>10&4095)*2
                            value=0 if rt==31 else machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{rt}'))&0xFFFF;seen['counter_writes'].append((address,value))
                        elif w&0xFFC00000==0x79400000:seen['flag_reads']+=rn==20 and (w>>10&4095)*2==0x102
                        elif w&0xFC000000==0x94000000:self.fail('Raw CPU case unexpectedly entered unsupported SVC36 path')
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base+BEGIN,base+len(image),count=3000)
                self.assertTrue(seen['done']);self.assertEqual(bool(cpu.reg_read(uc.UC_ARM64_REG_X0)),want)
                self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.nzcv))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                for address,data in model.pages.items():self.assertEqual(bytes(cpu.mem_read(address,4096)),bytes(data))
                self.assertEqual(tuple(seen[k] for k in ('loads','stores','clears','flag_reads','counter_writes')),(model.loads,model.stores,model.clears,model.flag_reads,model.counter_writes))
    def test_nonzero_pin_state_never_claims_voidSVC36_success(self):
        for busy,failures in ((1,0),(0,1)):
            model=RawTryModel(fixture(),0,busy,failures,interrupt=1)
            with self.assertRaisesRegex(ValueError,'nonzero pin-state'):model.run()
            self.assertEqual(model.read(TLR+0x102,2),1)
            self.assertEqual(model.calls,1)
if __name__=='__main__':unittest.main()
