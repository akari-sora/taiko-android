"""A guarded64-bit publication CAS retains pre-reservation side effects."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from test_android_native_boolean_schedules import fixture
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
WORDS=(0xD5033F5F,0x2A1F03EB,0xAA0903EA,0x3500018B,0xB9400269,
       0x34000249,0xF900030A,0xC85F7D09,0xEB0A013F,0x54FFFEE1,
       0xC80AFD18,0x35FFFECA,0x5280002B,0xAA0903EA,0x34FFFECB)
FIELDS=((),(0,16),(0,16),(0,),(0,5),(0,),(0,5),(0,5),(5,16),(),
        (0,5,16),(0,),(0,),(0,16),(0,))
CASE=dict(name='guarded-publication64',begin=0,end=60,entry=16,head=28,
          words=WORDS,fields=FIELDS,external_bits={5:19})
GUARD,CELL,NODE=0x400000,0x400100,0x400200
MASK=(1<<64)-1

def renamed(rename):
    result=[]
    for word,fields in zip(WORDS,FIELDS):
        original=word
        for shift in fields:
            role=original>>shift&31
            word=(word&~(31<<shift))|(rename.get(role,role)<<shift)
        result.append(word)
    return tuple(result)

def setup(words=WORDS):
    return fixture(dict(CASE,words=words))

def match(words=WORDS):
    v,o,b,k,begin,entry,head,end,exits=setup()
    for i,word in enumerate(words):
        pc=begin+i*4;b[pc]=ar.decode(word,pc);k[pc]=ar.site_kind(b[pc])
    return ar.android_exclusive.native_conditional_refresh(b[head],b,k,ar)

class RawModel:
    """Independent raw instruction semantics, byte memory and reservation state."""
    def __init__(self,values,exits,guard,initial,expected,failures=0,competitor=None,guard_after_failure=None,node_after_failure=None):
        self.values,self.exits=values,exits
        self.x=[0xAABB000000000100+i for i in range(31)]
        self.x[8],self.x[19],self.x[24],self.x[10]=CELL,GUARD,NODE,expected
        self.sp,self.flags,self.q=0x800000,0xB0000000,tuple(range(32))
        self.mem=bytearray((i*17+9)%256 for i in range(4096))
        self.write(GUARD,4,guard);self.write(CELL,8,initial)
        self.failures,self.competitor=failures,competitor
        self.guard_after_failure,self.node_after_failure=guard_after_failure,node_after_failure
        self.loads=self.stores=self.clears=0;self.publications=[]
    def read(self,address,size):return int.from_bytes(self.mem[address-GUARD:address-GUARD+size],'little')
    def write(self,address,size,value):self.mem[address-GUARD:address-GUARD+size]=(value&((1<<(size*8))-1)).to_bytes(size,'little')
    @staticmethod
    def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value
    def run(self):
        pc,monitor=0,None
        for _ in range(800):
            if pc in self.exits:assert monitor is None;return pc
            w=self.values[pc//4];rt,rn=w&31,w>>5&31;nxt=pc+4
            if w&0xFFFFFC00==0xC85F7C00:
                self.loads+=1;monitor=self.x[rn];self.x[rt]=self.read(self.x[rn],8)
            elif w&0xFFE0FC00==0xC800FC00:
                self.stores+=1;success=monitor==self.x[rn] and self.stores>self.failures
                if success:self.write(self.x[rn],8,self.x[rt])
                else:
                    if self.competitor is not None:self.write(CELL,8,self.competitor)
                    if self.guard_after_failure is not None:self.write(GUARD,4,self.guard_after_failure)
                    if self.node_after_failure is not None:self.write(NODE,8,self.node_after_failure)
                self.x[w>>16&31]=0 if success else 1;monitor=None
            elif w==0xD5033F5F:monitor=None;self.clears+=1
            elif w&0xFFC00000==0xB9400000:self.x[rt]=self.read(self.x[rn]+(w>>10&4095)*4,4)
            elif w&0xFFC00000==0xF9000000:
                address=self.x[rn]+(w>>10&4095)*8;self.write(address,8,self.x[rt]);self.publications.append((address,self.x[rt]))
            elif w&0xFFE0FC1F==0xEB00001F:
                left,right=self.x[rn],self.x[w>>16&31];v=(left-right)&MASK
                overflow=bool((left^right)&(left^v)&(1<<63))
                self.flags=((bool(v>>63)<<3)|((v==0)<<2)|((left>=right)<<1)|overflow)<<28
            elif w&0x7FE0FFE0==0x2A0003E0:
                value=0 if w>>16&31==31 else self.x[w>>16&31]
                self.x[rt]=value if w>>31 else value&0xFFFFFFFF
            elif w&0xFFFFFC00==0x52800000:self.x[rt]=w>>5&65535
            elif w&0xFF000010==0x54000000:
                assert w&15==1
                if not self.flags&0x40000000:nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0x7E000000==0x34000000:
                assert not w>>31
                if bool(self.x[rt]&0xFFFFFFFF)==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0xFC000000==0x14000000:nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            elif w!=0xD503201F:raise AssertionError(hex(w))
            pc=nxt
        raise AssertionError('publication loop did not exit')

class NativeGuardedPublication64Tests(unittest.TestCase):
    def test_exact_row_and_injective_ordinary_renames_remain_native(self):
        for mapping in ({},{8:1,9:2,10:3,11:4,19:5,24:6},{8:17,9:16,10:28,11:27,19:26,24:25}):
            words=renamed(mapping);v,o,b,k,begin,entry,head,end,exits=setup(words)
            self.assertEqual(match(words),(set(range(begin,end,4)),entry,{head}))
            image=ar.rewrite(struct.pack('<512I',*v),entry_offsets=(0,entry,*exits))
            self.assertEqual(image.bytes,struct.pack('<512I',*v));self.assertEqual((image.sites,image.gates,image.fixups),((),(),()))
    def test_all_fixed_bits_and_register_aliases_preserve_order_width_and_publication(self):
        for i,w in enumerate(WORDS):
            mask=sum(31<<shift for shift in FIELDS[i])
            if i==5:mask|=((1<<19)-1)<<5
            for bit in range(32):
                if mask>>bit&1:continue
                changed=list(WORDS);changed[i]=w^(1<<bit)
                try:r=match(tuple(changed))
                except ar.RewriteError:r=None
                self.assertIsNone(r,(i,bit))
        roles={8,9,10,11,19,24}
        for role in roles:
            for bad in (18,29,30,31,*sorted(roles-{role})):self.assertIsNone(match(renamed({role:bad})),(role,bad))
        for i,fields in enumerate(FIELDS):
            for shift in fields:
                changed=list(WORDS);role=changed[i]>>shift&31
                changed[i]=(changed[i]&~(31<<shift))|((0 if role==31 else 31)<<shift)
                self.assertIsNone(match(tuple(changed)),(i,shift))
    def test_missing_sources_host_rewrites_and_unproved_exit_refuse(self):
        v,o,b,k,begin,entry,head,end,exits=setup()
        for pc in range(begin,end,4):
            partial=dict(b);del partial[pc];self.assertIsNone(ar.android_exclusive.native_conditional_refresh(b[head],partial,k,ar))
            for kind in ('x18','gate','parameter','parameter_tail','missing'):
                ck=dict(k)
                if kind=='missing':del ck[pc]
                else:ck[pc]=kind
                with self.assertRaises(ar.RewriteError):ar.android_exclusive.native_conditional_refresh(b[head],b,ck,ar)
        for target in exits:
            partial=dict(b);del partial[target];self.assertIsNone(ar.android_exclusive.native_conditional_refresh(b[head],partial,k,ar))
            partial=dict(b);partial[target]=ar.decode(0,target);self.assertIsNone(ar.android_exclusive.native_conditional_refresh(b[head],partial,k,ar))
        for target in range(begin,end,4):
            changed=list(WORDS);changed[5]=0x34000009|((((target-(begin+20))//4)&0x7FFFF)<<5)
            self.assertIsNone(match(tuple(changed)),hex(target))
    def test_only_original_preload_entry_allows_metadata_and_outside_edges(self):
        v,o,b,k,begin,entry,head,end,exits=setup()
        for pc in set(range(begin,end,4))-{entry}:
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(0,entry,*exits,pc),ar)
            changed=list(v);changed[1]=ar.branch(4,pc);bo=[ar.decode(w,i*4) for i,w in enumerate(changed)];ko={i.address:ar.site_kind(i) for i in bo}
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(bo,ko,(0,entry,*exits),ar)
    def test_unicorn_full64_retries_competition_and_preload_side_effects_match_source(self):
        cases=(dict(guard=1,initial=0x100000005,expected=0x100000005),
               dict(guard=0,initial=0x100000005,expected=0x200000005),
               dict(guard=1,initial=0x100000005,expected=0x200000005),
               dict(guard=1,initial=0xFFFFFFFFFFFFFFFF,expected=0xFFFFFFFFFFFFFFFF),
               dict(guard=1,initial=0x100000005,expected=0x100000005,failures=1,competitor=0xFEDCBA9876543210),
               dict(guard=1,initial=0x100000005,expected=0x100000005,failures=2),
               dict(guard=1,initial=0x100000005,expected=0x100000005,failures=1,guard_after_failure=0,competitor=0x200000005),
               dict(guard=1,initial=0x100000005,expected=0x100000005,failures=1,node_after_failure=0xFEEDFACE12345678))
        v,o,b,k,begin,entry,head,end,exits=setup();image=ar.rewrite(struct.pack('<512I',*v),entry_offsets=(0,entry,*exits));store=begin+40
        for case in cases:
            with self.subTest(case=case):
                model=RawModel(v,exits,**case);before=model.x.copy();memory=bytes(model.mem);target=model.run()
                base,stub=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                for address in (base,stub,GUARD):cpu.mem_map(address,4096)
                cpu.mem_write(base,image.bytes);cpu.mem_write(stub,struct.pack('<2I',0xD5033F5F,ar.branch(stub+4,base+store)));cpu.mem_write(GUARD,memory)
                for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
                for i,value in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
                cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
                seen=dict(target=None,loads=0,stores=0,clears=0,publications=[],detour=False,live=False)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at in exits:self.assertFalse(seen['live']);seen['target']=at;machine.emu_stop()
                    elif at==head:self.assertFalse(seen['live']);seen['live']=True;seen['loads']+=1
                    elif at==begin:seen['live']=False;seen['clears']+=1
                    elif at==begin+24:
                        self.assertFalse(seen['live']);seen['publications'].append((machine.reg_read(uc.UC_ARM64_REG_X24),machine.reg_read(uc.UC_ARM64_REG_X10)))
                    elif at==store:
                        if seen['detour']:seen['detour']=False
                        else:
                            seen['stores']+=1
                            if seen['stores']<=case.get('failures',0):
                                for key,address,width in (('competitor',CELL,8),('guard_after_failure',GUARD,4),('node_after_failure',NODE,8)):
                                    if key in case:machine.mem_write(address,case[key].to_bytes(width,'little'))
                                seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,stub)
                        seen['live']=False
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=3000)
                self.assertEqual(seen['target'],target)
                self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                self.assertEqual(bytes(cpu.mem_read(GUARD,4096)),bytes(model.mem))
                self.assertEqual(tuple(seen[x] for x in ('loads','stores','clears','publications')),(model.loads,model.stores,model.clears,model.publications))
if __name__=='__main__':unittest.main()
