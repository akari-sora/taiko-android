"""Exact sparse nativeWFE source; retirement capability and hardware claims separate."""
from pathlib import Path
from types import SimpleNamespace
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
ENTRY,PRODUCER,CALLEE=0x20,0x1C,0x220
SUCCESS=ENTRY+92
OBJECT,TLR=0x400000,0x500000
CELL=OBJECT+24
WORDS=(
    0x794202C8, 0xAA0103F4, 0xAA0003F3, 0x91006015,
    0xF98002B0, 0x11000517, 0x34000948, 0x52800029,
    0x790202D7, 0x885FFEAA, 0x350000CA, 0x1400000A,
    0x790202C8, 0x790202D7, 0x885FFEAA, 0x340000CA,
    0x790202C8, 0xD503205F, 0x790202D7, 0x885FFEAA,
    0x35FFFF8A, 0x880A7EA9, 0x35FFFECA, 0x52800038,
    0x14000002, 0xD503205F, 0x790202D7, 0x885FFEA8,
    0x340000C8, 0x790202DF, 0x794206C8, 0x34FFFF48,
    0x94016560, 0x17FFFFF8, 0x88087EB8, 0x34FFF768,
    0x790202DF, 0x794206C8, 0x34FFFE88, 0x94016559,
    0x17FFFFF2,
)
FIELDS=((0, 5), (0, 16), (0, 16), (0, 5), (5,), (0, 5), (0,), (0,), (0, 5), (0, 5), (0,), (), (0, 5), (0, 5), (0, 5), (0,), (0, 5), (), (0, 5), (0, 5), (0,), (0, 5, 16), (0,), (0,), (), (), (0, 5), (0, 5), (0,), (0, 5), (0, 5), (0,), (), (), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())
OFFSETS=(0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 320, 324, 328, 332, 336, 340, 344, 348, 352, 356, 360, 364, 368, 372, 376, 380, 384, 388)
NODES={ENTRY+n for n in OFFSETS}
HEADS={ENTRY+n for n in (36,56,76,336)}
STORES=(ENTRY+84,ENTRY+364)

def api_policy(policy):
    values=dict(vars(ar));values['SVC_MONITOR_RETIRE']=policy
    return SimpleNamespace(**values)

def fixture():
    v=[0xD503201F]*(0x240//4);v[0]=ar.branch(0,PRODUCER);v[PRODUCER//4]=0xD53BD076
    for offset,word in zip(OFFSETS,WORDS):v[(ENTRY+offset)//4]=word
    for index in (32,39):
        at=ENTRY+OFFSETS[index];v[at//4]=0x94000000|((CALLEE-at)//4)&0x3FFFFFF
    v[SUCCESS//4]=0xD65F03C0
    # The original ordinary gap ends in a B past the second island; a NOP
    # here would invent an exterior fallthrough into its protected entry.
    v[(ENTRY+316)//4]=ar.branch(ENTRY+316,ENTRY+396);v[(ENTRY+396)//4]=0xD65F03C0
    v[CALLEE//4:CALLEE//4+2]=[0xD40006C1,0xD65F03C0]
    return v

def raw(v):return struct.pack('<'+'I'*len(v),*v)
def decoded(v):
    ops=[ar.decode(w,i*4) for i,w in enumerate(v)];return ops,{i.address:ar.site_kind(i) for i in ops}
def helper_case(api,values=None):
    v=fixture() if values is None else values;o,k=decoded(v);by={x.address:x for x in o}
    return ar.android_exclusive.native_wait_mutex(by[ENTRY+36],by,k,api)

class SparseWaitModel:
    def __init__(self,v,old,busy=0,release=1,failures=0,competitor=None,interrupt=0):
        self.v=v;self.x=[0xAABB000000001000+i*0x101 for i in range(31)];self.x[0]=OBJECT
        self.sp,self.flags,self.q=0x800000,0xB0000000,tuple(int.from_bytes(bytes([i])*16,'little') for i in range(32))
        self.pages={a:bytearray((i*17+9)%256 for i in range(4096)) for a in (OBJECT,TLR)}
        self.write(CELL,4,busy);self.write(TLR+0x100,2,old);self.write(TLR+0x102,2,interrupt)
        self.release,self.failures,self.competitor=release,failures,competitor
        self.loads=self.stores=self.waits=self.calls=self.flag_reads=0;self.counter_writes=[];self.wait_live=[]
    def read(self,address,size):base=address&~4095;return int.from_bytes(self.pages[base][address-base:address-base+size],'little')
    def write(self,address,size,value):
        base=address&~4095;self.pages[base][address-base:address-base+size]=(value&((1<<(size*8))-1)).to_bytes(size,'little')
    @staticmethod
    def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
    def run(self):
        pc,monitor=0,None
        for _ in range(1200):
            if pc==SUCCESS:assert monitor is None;return
            w=self.v[pc//4];rt,rn=w&31,w>>5&31;nxt=pc+4
            if w&0xFFFFFFE0==0xD53BD060:self.x[rt]=TLR
            elif w&0xFFC00000==0x79400000:
                address=self.x[rn]+(w>>10&4095)*2;self.flag_reads+=address==TLR+0x102;self.x[rt]=self.read(address,2)
            elif w&0xFFC00000==0x79000000:
                address=self.x[rn]+(w>>10&4095)*2;value=0 if rt==31 else self.x[rt]&0xFFFF
                self.write(address,2,value);self.counter_writes.append((address,value))
            elif w&0xFFC00000 in (0x11000000,0x91000000):
                self.x[rt]=(self.x[rn]+(w>>10&4095))&((1<<(64 if w>>31 else 32))-1)
            elif w&0xFFE0FFE0==0xAA0003E0:self.x[rt]=self.x[w>>16&31]
            elif w&0xFFE00000==0x52800000:self.x[rt]=w>>5&65535
            elif w&0xFFFFFC00==0x885FFC00:
                self.loads+=1;monitor=self.x[rn];self.x[rt]=self.read(self.x[rn],4)
            elif w&0xFFE0FC00==0x88007C00:
                assert monitor==self.x[rn];self.stores+=1;ok=self.stores>self.failures
                if ok:self.write(self.x[rn],4,self.x[rt])
                elif self.competitor is not None:self.write(CELL,4,self.competitor)
                self.x[w>>16&31]=0 if ok else 1;monitor=None
            elif w==0xD503205F:
                self.waits+=1;self.wait_live.append(monitor is not None)
                if self.waits>=self.release:self.write(CELL,4,0) # authored competing unlock event, not hardware wake timing
            elif w&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0xFC000000==0x94000000:
                self.calls+=1
                raise ValueError('nonzero pin-state remains unsupported; no SVC36 success model')
            elif w&0xFC000000==0x14000000:nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            elif w&0xFFC00000==0xF9800000:pass
            elif w!=0xD503201F:raise AssertionError((hex(pc),hex(w)))
            pc=nxt
        raise AssertionError('sparse wait did not complete')

class NativeSparseWaitTests(unittest.TestCase):
    def test_missing_retirement_policy_refuses_new_and_old_native_wait_layouts(self):
        api=api_policy(frozenset())
        with self.assertRaisesRegex(ar.RewriteError,'SVC36.*preframe retirement'):helper_case(api)
        import test_android_native_wait_mutex as old
        import test_android_native_wait_mutex_compact as compact
        for module in (old,compact):
            v=module.fixture();o,k=old.decode(v);b={i.address:i for i in o}
            with self.assertRaisesRegex(ar.RewriteError,'SVC36.*preframe retirement'):
                ar.android_exclusive.native_wait_mutex(b[module.BEGIN+28],b,k,api)
    def test_exact_geometry_only_accepts_declared_common_gate_policy_fixture(self):
        api=api_policy(frozenset((0x36,))) # synthetic matcher capability, not actual runtime/wholemodule authority
        self.assertEqual(helper_case(api),(NODES,ENTRY,HEADS))
        o,k=decoded(fixture());self.assertEqual(ar.android_exclusive.plan_regions(o,k,(0,PRODUCER,CALLEE,SUCCESS),api),())
        for policy in (None,True,(0x36,),{0x36:True},frozenset((0x1A,))):
            with self.assertRaises(ar.RewriteError):helper_case(api_policy(policy))
    def test_every_fixed_word_role_and_source_context_keeps_exact_semantics(self):
        api=api_policy(frozenset((0x36,)));v=fixture();o,k=decoded(v);by={i.address:i for i in o}
        for index,(offset,shifts) in enumerate(zip(OFFSETS,FIELDS)):
            pc=ENTRY+offset;w=v[pc//4];mask=sum(31<<shift for shift in shifts if (w>>shift&31)!=31)
            if index in (32,39):mask|=0x3FFFFFF
            for bit in range(32):
                if mask>>bit&1:continue
                changed=dict(by)
                try:
                    changed[pc]=ar.decode(w^(1<<bit),pc);ck=dict(k);ck[pc]=ar.site_kind(changed[pc]);result=ar.android_exclusive.native_wait_mutex(changed[ENTRY+36],changed,ck,api)
                except ar.RewriteError:result=None
                self.assertIsNone(result,(index,bit))
        for pc in NODES:
            partial=dict(by);del partial[pc];self.assertIsNone(ar.android_exclusive.native_wait_mutex(by[ENTRY+36],partial,k,api))
            for kind in ('gate','x18','parameter','parameter_tail','missing'):
                ck=dict(k)
                if kind=='missing':del ck[pc]
                else:ck[pc]=kind
                with self.assertRaises(ar.RewriteError):ar.android_exclusive.native_wait_mutex(by[ENTRY+36],by,ck,api)
        for pc in (PRODUCER,CALLEE,CALLEE+4,SUCCESS):
            partial=dict(by);del partial[pc];self.assertIsNone(ar.android_exclusive.native_wait_mutex(by[ENTRY+36],partial,k,api))
        for pc,w in ((PRODUCER,0xD53BD074),(CALLEE,0xD4000341),(CALLEE+4,0xD503201F),(SUCCESS,0)):
            changed=dict(by);changed[pc]=ar.decode(w,pc);self.assertIsNone(ar.android_exclusive.native_wait_mutex(by[ENTRY+36],changed,k,api))
        values=fixture();fake_stub=ENTRY+128;values[fake_stub//4:fake_stub//4+2]=[0xD40006C1,0xD65F03C0]
        for index in (32,39):
            at=ENTRY+OFFSETS[index];values[at//4]=0x94000000|((fake_stub-at)//4)&0x3FFFFFF
        self.assertIsNone(helper_case(api,values)) # exactstub in ordinary gap is not an externalcallee
        def renamed(mapping):
            values=fixture()
            for offset,fields in zip(OFFSETS,FIELDS):
                at=ENTRY+offset;word=values[at//4];before=word
                for shift in fields:
                    role=before>>shift&31
                    if role!=31:word=(word&~(31<<shift))|(mapping.get(role,role)<<shift)
                values[at//4]=word
            values[PRODUCER//4]=0xD53BD060|mapping.get(22,22)
            try:return helper_case(api,values)
            except ar.RewriteError:return None
        self.assertIsNotNone(renamed({0:2,1:3,8:4,9:5,10:6,19:7,20:8,21:9,22:10,23:11,24:12}))
        roles={0,1,8,9,10,19,20,21,22,23,24}
        for role in roles:
            for bad in (18,29,30,31,*sorted(roles-{role})):self.assertIsNone(renamed({role:bad}),(role,bad))
    def test_all_native_entries_and_unknown_indirect_transfers_refuse(self):
        api=api_policy(frozenset((0x36,)));v=fixture();o,k=decoded(v);roots=(0,PRODUCER,CALLEE,SUCCESS)
        for pc in NODES:
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(*roots,pc),api)
            values=list(v);values[1]=ar.branch(4,pc);ops,ks=decoded(values)
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,ks,roots,api)
        values=list(v);values[1]=0xD61F0120;ops,ks=decoded(values)
        for facts in (None,{4},{4:('host',(ENTRY,))},{4:('finite',())},{4:('finite',(ENTRY,))}):
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,ks,roots,api,native_wait_transfers=facts)
        ks[4]='gate';self.assertEqual(ar.android_exclusive.plan_regions(ops,ks,roots,api,native_wait_transfers={4:('host',())}),())
        for word,kind,fact in ((0xD61F0120,None,'finite'),(0xD63F0120,'checked_call','checked-call'),(0xD63F0120,'checked_call_forest_stub','checked-call-forest')):
            values=list(v);values[1]=word;ops,ks=decoded(values);ks[4]=kind
            self.assertEqual(ar.android_exclusive.plan_regions(ops,ks,roots,api,native_wait_transfers={4:(fact,(PRODUCER,))}),())
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,ks,(*roots,ENTRY),api,native_wait_transfers={4:(fact,(ENTRY,))})
    def test_existing_consumer_protects_producer_ownership_and_closed_try_is_unrestricted(self):
        from test_android_native_wait_mutex import assert_producer_ownership_exclusive
        def ownership_fixture():
            values=fixture();values[(PRODUCER-4)//4]=ar.branch(PRODUCER-4,4);return values
        assert_producer_ownership_exclusive(self,SimpleNamespace(BEGIN=ENTRY,END=ENTRY+392,CALLEE=CALLEE,fixture=ownership_fixture))
        import test_android_native_try_mutex as old
        import test_android_native_try_mutex43 as direct
        api=api_policy(frozenset())
        for module,roots in ((old,(0,old.BEGIN-4,old.CALLEE)),(direct,(direct.BEGIN,direct.CALLEE))):
            values=module.fixture();ops,ks=decoded(values)
            self.assertEqual(ar.android_exclusive.plan_regions(ops,ks,roots,api),())
    def test_composed_capsule_keeps_native_wait_bytes_and_retires_before_frame(self):
        values=fixture();image=ar.rewrite(raw(values),entry_offsets=(0,PRODUCER,CALLEE,SUCCESS),package_version=2,checked_stack=True)
        for pc in NODES:self.assertEqual(image.bytes[pc:pc+4],raw(values)[pc:pc+4])
        self.assertFalse(any(site.offset in NODES for site in image.sites))
        site=next(site for site in image.sites if site.offset==CALLEE)
        self.assertEqual(struct.unpack_from('<3I',image.bytes,site.trampoline),(0xD5033F5F,0xD10043FF,ar.pair(False,29,30,0)))
    def test_raw_cpu_flagzero_waits_keep_monitor_and_refresh_both_retry_islands(self):
        cases=((0,0,1,0,None),(7,0,1,0,None),(0xFFFF,0,1,2,None),
               (0,1,1,0,None),(0,1,4,2,None),(7,1,1,0,None),(7,1,4,2,None),
               (0,0,1,1,9),(7,0,1,1,9))
        v=fixture();image=raw(v)
        for old,busy,release,failures,competitor in cases:
            with self.subTest(old=old,busy=busy,release=release,failures=failures,competitor=competitor):
                model=SparseWaitModel(v,old,busy,release,failures,competitor);before=model.x.copy();pages={a:bytes(b) for a,b in model.pages.items()};model.run()
                base,stub=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                for address in (base,stub,*pages):cpu.mem_map(address,4096)
                cpu.mem_write(base,image)
                for i,store in enumerate(STORES):cpu.mem_write(stub+i*8,struct.pack('<2I',0xD5033F5F,ar.branch(stub+i*8+4,base+store)))
                for address,data in pages.items():cpu.mem_write(address,data)
                for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
                for i,value in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
                cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,model.flags);cpu.reg_write(uc.UC_ARM64_REG_TPIDRRO_EL0,TLR)
                seen=dict(done=False,live=False,loads=0,stores=0,waits=0,flag_reads=0,counter_writes=[],wait_live=[],detour=False)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at==SUCCESS:self.assertFalse(seen['live']);seen['done']=True;machine.emu_stop();return
                    if at in HEADS:seen['live']=True;seen['loads']+=1
                    elif at in STORES:
                        if seen['detour']:seen['detour']=False
                        else:
                            seen['stores']+=1
                            if seen['stores']<=failures:
                                if competitor is not None:machine.mem_write(CELL,struct.pack('<I',competitor))
                                seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,stub+STORES.index(at)*8)
                        seen['live']=False
                    if at in NODES:
                        w=v[at//4];rt,rn=w&31,w>>5&31
                        if w==0xD503205F:
                            seen['waits']+=1;seen['wait_live'].append(seen['live'])
                            if seen['waits']>=release:machine.mem_write(CELL,struct.pack('<I',0))
                        elif w&0xFFC00000==0x79000000:
                            address=machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{rn}'))+(w>>10&4095)*2
                            value=0 if rt==31 else machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{rt}'))&0xFFFF;seen['counter_writes'].append((address,value))
                        elif w&0xFFC00000==0x79400000:seen['flag_reads']+=(w>>10&4095)*2==0x102
                        elif w&0xFC000000==0x94000000:self.fail('raw CPU fixture must not enter unsupported nonzero pin path')
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image),count=5000)
                self.assertTrue(seen['done']);self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                for address,data in model.pages.items():self.assertEqual(bytes(cpu.mem_read(address,4096)),bytes(data))
                self.assertEqual(tuple(seen[k] for k in ('loads','stores','waits','flag_reads','counter_writes','wait_live')),(model.loads,model.stores,model.waits,model.flag_reads,model.counter_writes,model.wait_live))
    def test_nonzero_pin_stays_unsupported_without_clearing_flag(self):
        model=SparseWaitModel(fixture(),0,1,interrupt=1)
        with self.assertRaisesRegex(ValueError,'nonzero pin-state'):model.run()
        self.assertEqual(model.read(TLR+0x102,2),1)
if __name__=='__main__':unittest.main()
