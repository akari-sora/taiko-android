"""Native increment CAS keeps the existing dispatcher target authority."""
from pathlib import Path
import sys,struct,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from test_android_native_boolean_schedules import fixture
from test_android_native_expected_refresh import Model
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
CASES=[{'name': 'increment',
  'words': [2287992073,
            1795817791,
            1409286337,
            285214026,
            2282454282,
            889192587,
            1384120362,
            335544323,
            3573759839,
            706675690,
            706675680,
            922747018,
            1895826751,
            705233898,
            1426062922],
  'fields': [[0, 5],
             [5, 16],
             [],
             [0, 5],
             [0, 5, 16],
             [0],
             [0],
             [],
             [],
             [0, 16],
             [0, 16],
             [0],
             [5],
             [0, 16],
             []],
  'external_bits': {},
  'base': 8,
  'loaded': 9,
  'expected': 10,
  'status': 11,
  'begin': 0,
  'end': 60,
  'entry': 0,
  'head': 0}]
class CounterModel(Model):
    def __init__(self,case,values,entry,end,exits,initial,expected,failures=0,competitor=None):
        super().__init__(values,initial,expected,failures,competitor)
        self.case,self.entry,self.end,self.exits=case,entry,end,exits
        self.x=[0xAABB000000000100+i for i in range(31)];self.x[case['base']]=0x400000
        self.x[case['expected']]=0xCCDD000000000000|expected
    def run(self):
        pc,monitor=0,None
        for _ in range(500):
            if pc in self.exits:assert monitor is None;return pc
            w=self.values[pc//4];rt,rn=w&31,w>>5&31;nxt=pc+4
            if w&0xFFFF7C00==0x885F7C00:self.loads+=1;monitor=self.x[rn];self.x[rt]=self.memory
            elif w&0xFFE07C00==0x88007C00:
                self.stores+=1;success=monitor==self.x[rn] and self.stores>self.failures
                if success:self.memory=0 if rt==31 else self.x[rt]&0xFFFFFFFF;self.writes+=1
                elif self.competitor is not None:self.memory=self.competitor
                self.x[w>>16&31]=0 if success else 1;monitor=None
            elif w==0xD5033F5F:monitor=None;self.clears+=1
            elif w&0xFFE0FC1F==0x6B00001F:self.cmp(self.x[rn],self.x[w>>16&31])
            elif w&0xFFC0001F==0x7100001F:self.cmp(self.x[rn],w>>10&4095)
            elif w&0xFFC00000==0x11000000:self.x[rt]=(self.x[rn]+(w>>10&4095))&0xFFFFFFFF
            elif w&0xFFE0FFE0==0x2A0003E0:self.x[rt]=0 if w>>16&31==31 else self.x[w>>16&31]&0xFFFFFFFF
            elif w&0xFFFFFC00==0x52800000:self.x[rt]=w>>5&65535
            elif w&0xFF000010==0x54000000:
                n,v,z=bool(self.flags&0x80000000),bool(self.flags&0x10000000),bool(self.flags&0x40000000)
                take={0:z,1:not z,10:n==v}[w&15]
                if take:nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0x7E000000==0x36000000:
                bit=(w>>31)*32+(w>>19&31)
                if bool(self.x[rt]&(1<<bit))==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x3FFF,14)*4
            elif w&0xFC000000==0x14000000:nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            elif w!=0xD503201F:raise AssertionError(hex(w))
            pc=nxt
        raise AssertionError('counter operation did not exit')
class NativeCounterIncrementCaseTests(unittest.TestCase):
    def test_each_exact_operation_keeps_native_bytes_and_one_entry(self):
        for c in CASES:
            with self.subTest(case=c['name']):
                v,o,b,k,begin,entry,head,end,exits=fixture(c)
                self.assertEqual(ar.android_exclusive.native_conditional_refresh(b[head],b,k,ar),(set(range(begin,end,4)),entry,{head}))
                image=ar.rewrite(struct.pack('<512I',*v),entry_offsets=(0,entry,*exits))
                self.assertEqual(image.bytes,struct.pack('<512I',*v));self.assertFalse(image.sites)
    def test_all_control_width_alias_and_missing_source_facts_refuse(self):
        for c in CASES:
            v,o,b,k,begin,entry,head,end,exits=fixture(c)
            for i,w in enumerate(c['words']):
                mask=sum(31<<shift for shift in c['fields'][i]);bits=c['external_bits'].get(i)
                if bits is not None:mask|=0x3FFFFFF if bits==26 else ((1<<bits)-1)<<5
                for bit in range(32):
                    if mask>>bit&1:continue
                    changed=dict(b);pc=begin+i*4
                    try:changed[pc]=ar.decode(w^(1<<bit),pc);ck=dict(k);ck[pc]=ar.site_kind(changed[pc]);r=ar.android_exclusive.native_conditional_refresh(changed[head],changed,ck,ar)
                    except ar.RewriteError:r=None
                    self.assertIsNone(r,(c['name'],i,bit))
            for pc in range(begin,end,4):
                partial=dict(b);del partial[pc];self.assertIsNone(ar.android_exclusive.native_conditional_refresh(b[head],partial,k,ar))
                for kind in ('x18','gate','parameter','parameter_tail'):
                    ck=dict(k);ck[pc]=kind
                    with self.assertRaises(ar.RewriteError):ar.android_exclusive.native_conditional_refresh(b[head],b,ck,ar)
    def test_consistent_rename_aliases_reserved_registers_and_closed_join(self):
        c=CASES[0]
        v,o,b,k,begin,entry,head,end,exits=fixture(c)
        def match(words):
            bo={pc:ar.decode(w,pc) for pc,w in zip(range(begin,end,4),words)}
            bo.update({pc:ins for pc,ins in b.items() if pc<begin or pc>=end})
            return ar.android_exclusive.native_conditional_refresh(bo[head],bo,{pc:ar.site_kind(ins) for pc,ins in bo.items()},ar)
        renamed=[]
        for w,shifts in zip(c['words'],c['fields']):
            for shift in shifts:
                role=w>>shift&31
                if role!=31:w=(w&~(31<<shift))|((role+3)<<shift)
            renamed.append(w)
        self.assertIsNotNone(match(renamed))
        for register in (8,9,10,11):
            for bad in (18,29,30,31):
                words=[]
                for w,shifts in zip(c['words'],c['fields']):
                    for shift in shifts:
                        if w>>shift&31==register:w=(w&~(31<<shift))|(bad<<shift)
                    words.append(w)
                self.assertIsNone(match(words),(register,bad))
        for first,second in ((8,9),(9,10),(10,11),(11,9),(0,8)):
            words=[]
            for w,shifts in zip(c['words'],c['fields']):
                for shift in shifts:
                    if w>>shift&31==first:w=(w&~(31<<shift))|(second<<shift)
                words.append(w)
            self.assertIsNone(match(words),(first,second))
        for i,shifts in enumerate(c['fields']):
            for shift in shifts:
                words=c['words'].copy();role=words[i]>>shift&31
                words[i]=(words[i]&~(31<<shift))|((0 if role==31 else 31)<<shift)
                self.assertIsNone(match(words),(i,shift))
        for pc in range(begin,end,4):
            missing=dict(k);del missing[pc]
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.native_conditional_refresh(b[head],b,missing,ar)
        missing=dict(b);del missing[end]
        self.assertIsNone(ar.android_exclusive.native_conditional_refresh(b[head],missing,k,ar))
        fatal=dict(b);fatal[end]=ar.decode(0,end)
        self.assertIsNone(ar.android_exclusive.native_conditional_refresh(b[head],fatal,k,ar))
    def test_all_other_metadata_roots_and_outside_edges_are_rejected(self):
        for c in CASES:
            v,o,b,k,begin,entry,head,end,exits=fixture(c)
            for pc in set(range(begin,end,4))-{entry}:
                with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(0,entry,*exits,pc),ar)
                changed=list(v);changed[1]=ar.branch(4,pc);bo=[ar.decode(w,i*4) for i,w in enumerate(changed)];ko={x.address:ar.site_kind(x) for x in bo}
                with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(bo,ko,(0,entry,*exits),ar)
    def test_unicorn_increment_competition_status_and_results_match_raw_model(self):
        settings={'increment': ((2, 2, 0, None), (3, 2, 0, None), (0, 2, 0, None), (4294967295, 2, 0, None), (2, 2, 1, 0), (2, 2, 2, None))}
        for c in CASES:
            v,o,b,k,begin,entry,head,end,exits=fixture(c);image=ar.rewrite(struct.pack('<512I',*v),entry_offsets=(0,entry,*exits))
            store=next(pc for pc in range(begin,end,4) if b[pc].mnemonic in ar.EXCLUSIVE_STORES)
            for initial,expected,failures,competitor in settings[c['name']]:
                with self.subTest(case=c['name'],initial=initial,expected=expected,failures=failures,competitor=competitor):
                    model=CounterModel(c,v,entry,end,exits,initial,expected,failures,competitor);before=model.x.copy();target=model.run()
                    base,stub=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                    for address in (base,stub,0x400000):cpu.mem_map(address,4096)
                    cpu.mem_write(base,image.bytes);cpu.mem_write(stub,struct.pack('<2I',0xD5033F5F,ar.branch(stub+4,base+store)))
                    for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
                    for i,value in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
                    cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
                    cpu.mem_write(0x400000,struct.pack('<II',initial,0x11223344));seen=dict(target=None,attempts=0,detour=False,live=False)
                    def code(machine,pc,size,_):
                        at=pc-base
                        if at in exits:self.assertFalse(seen['live']);seen['target']=at;machine.emu_stop()
                        elif at==head:seen['live']=True
                        elif begin<=at<end and b[at].mnemonic=='clrex':seen['live']=False
                        elif at==store:
                            if seen['detour']:seen['detour']=False
                            else:
                                seen['attempts']+=1
                                if seen['attempts']<=failures:
                                    if competitor is not None:machine.mem_write(0x400000,struct.pack('<I',competitor))
                                    seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,stub)
                            seen['live']=False
                    cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=2000)
                    self.assertEqual(seen['target'],target);self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                    self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                    self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                    self.assertEqual(struct.unpack('<II',cpu.mem_read(0x400000,8)),(model.memory,0x11223344))
if __name__=='__main__':unittest.main()
