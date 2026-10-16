"""Independent full18-word pair snapshot/CAS source; not device evidence."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UcError
from unicorn import arm64_const as uc
BEGIN,END=0x100,0x148;ENTRY,HEAD=BEGIN+12,BEGIN+24;NODES=set(range(ENTRY,END-4,4))
WORDS=(0xC87F2009,0xC82A2009,0x35FFFFCA,0xF9000049,0x9100050A,0x5280002B,0xC87F340C,0xEB0801BF,0x540000A1,0xEB09019F,0x54000061,0xC82BA801,0x35FFFF4B,0xD5033F5F,0xAA0D03E8,0xAA0C03E9,0xB5FFFE6B,0xD65F03C0)
FIELDS=((0,5,10),(0,5,10,16),(0,),(0,5),(0,5),(0,),(0,5,10),(0,5,16),(),(0,5,16),(),(0,5,10,16),(0,),(),(0,5,16),(0,5,16),(0,),())
MASK=(1<<64)-1;CELL,OUTPUT,STACK=0x400000,0x500000,0x800000
def raw(v):return struct.pack('<'+'I'*len(v),*v)
def fixture(mapping=None):
 v=[0xD503201F]*(END//4);v[0]=ar.branch(0,BEGIN);v[BEGIN//4:END//4]=WORDS
 if mapping:
  for slot,fields in enumerate(FIELDS):
   for shift in fields:
    r=WORDS[slot]>>shift&31
    if r!=31:v[BEGIN//4+slot]=(v[BEGIN//4+slot]&~(31<<shift))|mapping.get(r,r)<<shift
 return v
def decoded(v):
 ops=[ar.decode(w,i*4) for i,w in enumerate(v)];return ops,{i.address:ar.site_kind(i) for i in ops}
def helper(v=None,kinds_override=None,remove=None):
 ops,k=decoded(fixture() if v is None else v);by={i.address:i for i in ops};start=by[HEAD];k.update(kinds_override or {})
 if remove is not None:del by[remove]
 return ar.android_exclusive.native_conditional_refresh(start,by,k,ar)
def rewrite(v):return ar.rewrite(raw(v),entry_offsets=(0,BEGIN),checked_stack=True,package_version=2)

class PairMachine:
 def __init__(self,case):
  self.case=case;self.x=[0xABCD000000001000+i*0x101 for i in range(31)];self.x[0]=CELL;self.x[1]=case.get('new',0x8877665544332211);self.x[2]=CELL+8 if case.get('alias_out') else OUTPUT+0x80;self.x[30]=0xFFFFFFFFFFFFFFFC
  self.sp=STACK+0x800;self.nzcv=0xB0000000;self.q=tuple(int.from_bytes(bytes([i])*16,'little') for i in range(32));self.pages={a:bytearray((i*17+13)%256 for i in range(4096)) for a in (CELL,OUTPUT,STACK)}
  self.write(CELL,8,case.get('low',0x123456789ABCDEF0));self.write(CELL+8,8,case.get('high',7));self.initial={a:bytes(v) for a,v in self.pages.items()};self.initial_x=self.x.copy();self.monitor=False;self.counts=dict(snapshot_loads=0,snapshot_stores=0,cas_loads=0,cas_stores=0,clears=0);self.writes=[]
 def read(self,p,n):b=p&~4095;return int.from_bytes(self.pages[b][p-b:p-b+n],'little')
 def write(self,p,n,v):b=p&~4095;self.pages[b][p-b:p-b+n]=(v&((1<<(n*8))-1)).to_bytes(n,'little')
 def pair(self,values):self.write(CELL,8,values[0]);self.write(CELL+8,8,values[1])
 def cmp(self,a,b):
  v=(a-b)&MASK;n=v>>63;z=v==0;c=a>=b;overflow=bool(((a^b)&(a^v))>>63);self.nzcv=(n<<31)|(z<<30)|(c<<29)|(overflow<<28)
 def run(self):
  pc=0
  for _ in range(3000):
   nxt=pc+1
   if pc==0:self.monitor=True;self.counts['snapshot_loads']+=1;self.x[9],self.x[8]=self.read(CELL,8),self.read(CELL+8,8)
   elif pc==1:
    assert self.monitor;self.monitor=False;self.counts['snapshot_stores']+=1;fail=self.counts['snapshot_stores']<=self.case.get('snapshot_failures',0);self.x[10]=int(fail)
    if not fail:self.pair((self.x[9],self.x[8]));self.writes.append(('pair',CELL,self.x[9],self.x[8]))
   elif pc==2:
    if self.x[10]!=0:nxt=0
   elif pc==3:assert not self.monitor;self.write(self.x[2],8,self.x[9]);self.writes.append(('out',self.x[2],self.x[9]))
   elif pc==4:self.x[10]=(self.x[8]+1)&MASK
   elif pc==5:self.x[11]=1
   elif pc==6:
    assert not self.monitor;self.counts['cas_loads']+=1
    event=self.case.get('races',{}).get(self.counts['cas_loads'])
    if event:self.pair(event)
    self.x[12],self.x[13]=self.read(CELL,8),self.read(CELL+8,8);self.monitor=True
   elif pc==7:self.cmp(self.x[13],self.x[8])
   elif pc==8:
    if not self.nzcv>>30&1:nxt=13
   elif pc==9:self.cmp(self.x[12],self.x[9])
   elif pc==10:
    if not self.nzcv>>30&1:nxt=13
   elif pc==11:
    assert self.monitor;self.monitor=False;self.counts['cas_stores']+=1;fail=self.counts['cas_stores']<=self.case.get('cas_failures',0);self.x[11]=int(fail)
    if fail:
     event=self.case.get('store_race')
     if event:self.pair(event)
    else:self.pair((self.x[1],self.x[10]));self.writes.append(('pair',CELL,self.x[1],self.x[10]))
   elif pc==12:
    if self.x[11]!=0:nxt=6
   elif pc==13:self.monitor=False;self.counts['clears']+=1
   elif pc==14:self.x[8]=self.x[13]
   elif pc==15:self.x[9]=self.x[12]
   elif pc==16:
    if self.x[11]!=0:nxt=3
   elif pc==17:assert not self.monitor;return
   pc=nxt
  raise AssertionError('unbounded independent model')

def cpu_run(test,body,model):
 base,detour=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
 for p in (base,detour,*model.initial):cpu.mem_map(p,4096)
 cpu.mem_write(base,body)
 for j,offset in enumerate((4,44)):cpu.mem_write(detour+j*8,struct.pack('<2I',0xD5033F5F,ar.branch(detour+j*8+4,base+BEGIN+offset)))
 for p,v in model.initial.items():cpu.mem_write(p,v)
 for j,v in enumerate(model.initial_x):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{j}'),v)
 for j,v in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{j}'),v)
 cpu.reg_write(uc.UC_ARM64_REG_SP,STACK+0x800);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
 counts={k:0 for k in model.counts};seen=dict(done=False,live=False,detour=False);writes=[]
 def hook(machine,pc,size,_):
  at=pc-base-BEGIN
  if at==68:test.assertFalse(seen['live']);seen['done']=True;machine.emu_stop();return
  if at in (0,24):
   test.assertFalse(seen['live']);seen['live']=True;key='snapshot_loads' if at==0 else 'cas_loads';counts[key]+=1
   event=model.case.get('races',{}).get(counts[key]) if at==24 else None
   if event:machine.mem_write(CELL,struct.pack('<2Q',*event))
  elif at in (4,44):
   if seen['detour']:seen['detour']=False;return
   test.assertTrue(seen['live']);seen['live']=False;key='snapshot_stores' if at==4 else 'cas_stores';counts[key]+=1
   fail=counts[key]<=model.case.get('snapshot_failures' if at==4 else 'cas_failures',0)
   if fail:
    if at==44 and model.case.get('store_race'):machine.mem_write(CELL,struct.pack('<2Q',*model.case['store_race']))
    seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,detour+(0 if at==4 else 8));return
   first,second=(9,8) if at==4 else (1,10);writes.append(('pair',CELL,machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{first}')),machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{second}'))))
  elif at==12:
   test.assertFalse(seen['live']);writes.append(('out',machine.reg_read(uc.UC_ARM64_REG_X2),machine.reg_read(uc.UC_ARM64_REG_X9)))
  elif at==52:seen['live']=False;counts['clears']+=1
 cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(base+BEGIN,base+END,count=5000);test.assertTrue(seen['done'])
 test.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{j}')) for j in range(31)],model.x)
 test.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.nzcv))
 test.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{j}')) for j in range(32)),model.q)
 for p,v in model.pages.items():test.assertEqual(bytes(cpu.mem_read(p,4096)),bytes(v))
 test.assertEqual((counts,writes),(model.counts,model.writes))

class NativePairCASRefreshTests(unittest.TestCase):
 def test_full18_native_original_bytes_and_injective_ordinary_renaming(self):
  for mapping in (None,{0:3,1:4,2:5,8:6,9:7,10:14,11:15,12:16,13:17}):
   v=fixture(mapping);self.assertEqual(helper(v),(NODES,ENTRY,{HEAD}));ops,k=decoded(v)
   self.assertEqual(ar.android_exclusive.plan_regions(ops,k,(0,BEGIN),ar),())
   image=rewrite(v);self.assertEqual(image.bytes[:len(raw(v))],raw(v));self.assertEqual((image.sites,image.gates),((),()))
 def test_fixed_pair_widths_Rt2_roles_order_flags_and_kinds_refuse(self):
  v=fixture();ops,k=decoded(v);by={i.address:i for i in ops};bits=0
  for slot in range(3,17):
   pc=BEGIN+slot*4;w=v[pc//4];mask=sum(31<<s for s in FIELDS[slot] if (w>>s&31)!=31)
   for bit in range(32):
    if mask>>bit&1:continue
    changed=dict(by)
    try:changed[pc]=ar.decode(w^(1<<bit),pc);ck=dict(k);ck[pc]=ar.site_kind(changed[pc]);r=ar.android_exclusive.native_conditional_refresh(changed[HEAD],changed,ck,ar)
    except ar.RewriteError:r=None
    self.assertIsNone(r,(slot,bit));bits+=1
  self.assertGreater(bits,200)
  roles={0,1,2,8,9,10,11,12,13}
  for role in roles:
   for bad in (18,29,30,31,*sorted(roles-{role})):
    try:r=helper(fixture({role:bad}))
    except ar.RewriteError:r=None
    self.assertIsNone(r,(role,bad))
  for pc in NODES:
   with self.assertRaises(ar.RewriteError):helper(kinds_override={pc:'x18'})
   self.assertIsNone(helper(remove=pc))
  self.assertIsNone(helper(remove=END-4))
 def test_every_interior_metadata_and_direct_entry_refuses(self):
  v=fixture();ops,k=decoded(v)
  for pc in NODES-{ENTRY}:
   with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,k,(0,BEGIN,pc),ar)
   bad=list(v);bad[0]=ar.branch(0,pc);o,ks=decoded(bad)
   with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,ks,(0,BEGIN),ar)
  for pc in (BEGIN+4,BEGIN+8):
   with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,k,(0,BEGIN,pc),ar)
 def test_complete_original_and_rewrite_match_independent_pair_model(self):
  cases=({},dict(high=MASK),dict(snapshot_failures=2),dict(cas_failures=3),dict(races={1:(0x123456789ABCDEF0,12)}),dict(races={1:(0xFEDCBA9876543210,7)}),dict(races={1:(9,12),2:(0x8000000000000000,0x7FFFFFFFFFFFFFFF)}),dict(cas_failures=1,store_race=(0x8123456789ABCDEF,0xFFFFFFFFFFFFFFF0)),dict(alias_out=True),dict(low=MASK,high=0x8000000000000000,new=0xFEDCBA9876543210))
  original=raw(fixture());complete=rewrite(fixture()).bytes[:len(original)]
  for case in cases:
   with self.subTest(case=case):
    model=PairMachine(case);model.run();cpu_run(self,original,model);cpu_run(self,complete,model)
 def test_misaligned_pair_access_keeps_original_emulator_fault(self):
  original=raw(fixture());complete=rewrite(fixture()).bytes[:len(original)]
  for delta in (1,8):
   outcomes=[]
   for body in (original,complete):
    cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);cpu.mem_map(0x100000,4096);cpu.mem_map(CELL,4096);cpu.mem_write(0x100000,body);cpu.mem_write(CELL,bytes([0xA5])*4096);cpu.reg_write(uc.UC_ARM64_REG_X0,CELL+delta)
    try:cpu.emu_start(0x100000+BEGIN,0x100000+END,count=1)
    except UcError as e:outcome=(e.errno,cpu.reg_read(uc.UC_ARM64_REG_PC),bytes(cpu.mem_read(CELL,4096)))
    else:outcome=(None,cpu.reg_read(uc.UC_ARM64_REG_PC),bytes(cpu.mem_read(CELL,4096)))
    outcomes.append(outcome)
   self.assertEqual(outcomes[0],outcomes[1]);self.assertIsNotNone(outcomes[0][0]);self.assertEqual(outcomes[0][2],bytes([0xA5])*4096)
if __name__=='__main__':unittest.main()
