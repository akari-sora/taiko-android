"""Finite four-head free-list pop: exact source proof and software CPU checks."""
from pathlib import Path
import struct,sys,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'dm/verify/android/tests')]
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN=0x100;OFFSETS=(*range(0,88,4),*range(180,204,4))
WORDS=(0xC85FFD13,0x37000293,0xF9400269,0xB40000A9,0xC80AFD09,0x35FFFF6A,
 0xB5000453,0x1400000F,0xB2400269,0xC85FFD0A,0xEB13015F,0x54000141,
 0xC80A7D09,0x35FFFF8A,0x91020009,0xC85FFD2A,0xEB13015F,0x54000381,
 0xC80A7D3F,0x35FFFF8A,0x17FFFFF2,0xD5033F5F,0xD5033F5F,0xC85F7D09,
 0x927FF929,0xC80AFD09,0x35FFFFAA,0x17FFFFE4)
FIELDS=((0,5),(0,),(0,5),(0,),(0,5,16),(0,),(0,),(),(0,5),(0,5),
 (5,16),(),(0,5,16),(0,),(0,5),(0,5),(5,16),(),(0,5,16),(0,),(),(),(),
 (0,5),(0,5),(0,5,16),(0,),())
NODES={BEGIN+x for x in OFFSETS};HEADS={BEGIN+x for x in (0,36,60,184)}
MAPS=({x:x for x in (0,8,9,10,19)},{0:1,8:2,9:3,10:4,19:5},{0:28,8:27,9:26,10:25,19:24})
MASK=(1<<64)-1;BASE=0x100000;CELL=0x400100;SECOND=0x400140;NODE=0x500100;NEXT=0x500200;STACK=0x800800

def raw(words):return struct.pack('<'+'I'*len(words),*words)
def fixture(mapping=MAPS[0]):
 words=[0xD503201F]*(0x300//4);words[0]=ar.branch(0,BEGIN)
 for offset,w,fields in zip(OFFSETS,WORDS,FIELDS):
  for shift in fields:
   role=w>>shift&31;w=(w&~(31<<shift))|((31 if role==31 else mapping[role])<<shift)
  words[(BEGIN+offset)//4]=w
 for pc in (BEGIN+88,BEGIN+160,BEGIN+176):words[pc//4]=0xD65F03C0
 return words
def decoded(words):
 ops=[ar.decode(w,pc*4) for pc,w in enumerate(words)]
 return ops,{i.address:i for i in ops},{i.address:ar.site_kind(i) for i in ops}
def match(words=None,missing=(),overrides=None):
 ops,by,k=decoded(fixture() if words is None else words);start=by[BEGIN]
 for pc in missing:by.pop(pc,None)
 k.update(overrides or {})
 return ar.android_exclusive.native_pointer_chain(start,by,k,ar)
def plan(words,roots=(0,),reverse=False):
 ops,_,k=decoded(words)
 if reverse:ops.reverse()
 return ar.android_exclusive.plan_regions(ops,k,roots,ar)
def cmp64(a,b):
 a&=MASK;b&=MASK;value=(a-b)&MASK
 return ((bool(value>>63)<<3)|((value==0)<<2)|((a>=b)<<1)|bool((a^b)&(a^value)&(1<<63)))<<28

class NativePointerChainPopTests(unittest.TestCase):
 def test_exact_four_heads_and_consistent_roles_preserved(self):
  for mapping in MAPS:
   words=fixture(mapping);self.assertEqual(match(words),(NODES,BEGIN,HEADS));self.assertEqual(plan(words),())
   image=ar.rewrite(raw(words),entry_offsets=(0,),package_version=2,checked_stack=True)
   self.assertEqual(image.bytes,raw(words));self.assertFalse(image.sites);self.assertFalse(image.fixups)
 def test_each_nonregister_source_bit_is_fixed(self):
  words=fixture();ops,by,k=decoded(words)
  for pc,w,fields in zip((BEGIN+x for x in OFFSETS),WORDS,FIELDS):
   mask=sum(31<<s for s in fields)
   for bit in range(32):
    if mask>>bit&1:continue
    changed=by.copy();kinds=k.copy()
    try:
     changed[pc]=ar.decode(w^(1<<bit),pc);kinds[pc]=ar.site_kind(changed[pc])
     value=ar.android_exclusive.native_pointer_chain(changed[BEGIN],changed,kinds,ar)
    except ar.RewriteError:continue
    self.assertIsNone(value,(hex(pc),bit))
 def test_missing_host_kinds_fatal_exits_reserved_and_colliding_roles_refuse(self):
  for pc in sorted(NODES):
   self.assertIsNone(match(missing=(pc,)))
   for kind in ('gate','x18','stack_check','tls','foreign'):
    with self.assertRaises(ar.RewriteError):match(overrides={pc:kind})
  for role in MAPS[0]:
   for target in (*[r for r in MAPS[0] if r!=role],18,29,30,31):
    mapping=dict(MAPS[0]);mapping[role]=target;self.assertIsNone(match(fixture(mapping)),(role,target))
  for pc in (BEGIN+88,BEGIN+160):
   self.assertIsNone(match(missing=(pc,)))
   words=fixture();words[pc//4]=0xD4200000;self.assertIsNone(match(words))
 def test_every_interior_entry_and_raw_transfer_refuses(self):
  for pc in sorted(NODES-{BEGIN}):
   for origin in ('metadata','materialized','table','call'):
    with self.subTest(pc=hex(pc),origin=origin),self.assertRaises(ar.RewriteError):plan(fixture(),(0,pc))
   for kind in ('b','bl','cbnz','tbnz'):
    words=fixture();at=4
    words[at//4]=(ar.branch(at,pc) if kind=='b' else
     0x94000000|(((pc-at)//4)&0x3FFFFFF) if kind=='bl' else
     0x35000007|(((pc-at)//4)&0x7FFFF)<<5 if kind=='cbnz' else
     0x37000007|(((pc-at)//4)&0x3FFF)<<5)
    with self.subTest(pc=hex(pc),kind=kind),self.assertRaises(ar.RewriteError):plan(words)
  # A newly selected fallthrough into the detached clear is also forbidden.
  words=fixture();words[(BEGIN+176)//4]=0xD503201F;self.assertIsNotNone(match(words))
  with self.assertRaises(ar.RewriteError):plan(words,reverse=True)
  with self.assertRaises(ar.RewriteError):plan(words)
 def test_sparse_union_gap_and_overlap_remain_checked(self):
  # The fixture's ordinary gap ends in a NOP before detached CLREX. Replace
  # that edge with the actual return; otherwise the source entry check refuses.
  words=fixture();words[(BEGIN+176)//4]=0xD65F03C0
  self.assertEqual(plan(words),())
  for pc in range(BEGIN+88,BEGIN+180,4):self.assertIsNotNone(match(words,overrides={pc:'gate'}))
  fn=ar.android_exclusive.native_pointer_chain;head=BEGIN+184
  def earlier(start,by,k,api):
   if start.address==head:return {head,head+4,head+8,head+12},head,{head}
   return fn(start,by,k,api)
  ops,_,k=decoded(words);ordered=[i for i in ops if i.address==head]+[i for i in ops if i.address!=head]
  with patch.object(ar.android_exclusive,'native_pointer_chain',earlier),self.assertRaisesRegex(ar.RewriteError,'overlapping exclusive windows'):
   ar.android_exclusive.plan_regions(ordered,k,(0,),ar)
 def test_all_monitor_paths_cpu_and_independent_reference(self):
  cases=({'tagged':True},{'link':NEXT},{'link':NEXT,'fail':(2,0,0,0)},
   {},{'fail':(0,2,0,0)},{'mismatch_primary':True},{'secondary':NEXT},
   {'fail':(0,0,2,0)},{'secondary':NEXT,'fail':(0,0,0,2)},
   {'link':NEXT,'fail':(1,0,0,0),'compete':(0,NODE|1)},
   {'fail':(0,1,0,0),'compete':(1,NODE|1)},
   {'fail':(0,0,1,0),'compete':(2,NEXT)},
   {'secondary':NEXT,'fail':(0,0,0,1),'compete':(3,NODE|3)})
  for mapping in MAPS:
   words=fixture(mapping);words[(BEGIN+176)//4]=0xD65F03C0
   rewritten=ar.rewrite(raw(words),entry_offsets=(0,),package_version=2,checked_stack=True)
   for case in cases:
    want=reference(mapping,case)
    for body in (raw(words),rewritten.bytes):
     with self.subTest(mapping=mapping,case=case):self.assertEqual(execute(body,mapping,case),want)
 def test_monitor_graph_closes_each_exit_and_freshens_every_store(self):
  words=fixture();_,by,_=decoded(words);self.assertIsNotNone(match(words))
  pending=[(BEGIN,None)];seen=set();exits=set();refreshes=set()
  while pending:
   pc,live=pending.pop()
   if (pc,live) in seen:continue
   seen.add((pc,live))
   if pc not in NODES:
    self.assertIn(pc,(BEGIN+88,BEGIN+160));self.assertIsNone(live);exits.add(pc);continue
   i=by[pc];word=struct.unpack('<I',i.bytes)[0];base=word>>5&31
   if i.mnemonic in ar.EXCLUSIVE_LOADS:
    if live is not None:
     self.assertEqual((pc,live,base),(BEGIN+36,8,8));refreshes.add(pc)
    live=base
   elif i.mnemonic in ar.EXCLUSIVE_STORES:
    self.assertEqual(live,base);live=None
   elif i.mnemonic=='clrex':live=None
   self.assertNotIn(i.mnemonic,('bl','blr','br','ret','svc','wfe'))
   pending.extend((target,live) for target in ar.android_exclusive.successors(i))
  self.assertEqual({pc for pc,_ in seen}&NODES,NODES)
  self.assertEqual(exits,{BEGIN+88,BEGIN+160});self.assertEqual(refreshes,{BEGIN+36})

def initial(mapping,case):
 x=[0xA500000000000000+i for i in range(31)];x[mapping[0]]=CELL-0x40;x[mapping[8]]=CELL;x[30]=BASE+0x2F0
 owner=NODE|int(case.get('tagged',False));memory={CELL:owner,SECOND:case.get('secondary',NODE),NODE:case.get('link',0)}
 return x,memory
def reference(mapping,case):
 x,memory=initial(mapping,case);owner,cell,link,status=(mapping[r] for r in (19,8,9,10))
 flags=0xB0000000;loads=[0]*4;stores=[0]*4;clears=0;refreshes=0;exit=None
 failures=case.get('fail',(0,0,0,0));mismatch=case.get('mismatch_primary',False)
 def store(phase,payload,dst):
  stores[phase]+=1;failed=stores[phase]<=failures[phase]
  if failed and case.get('compete',(None,None))[0]==phase:memory[dst]=case['compete'][1]
  if not failed:memory[dst]=payload&MASK
  x[status]=int(failed);return failed
 while True:
  loads[0]+=1;x[owner]=memory[CELL]
  if x[owner]&1:clears+=1;exit=88;break
  x[link]=memory[x[owner]]
  if x[link]:
   if store(0,x[link],CELL):continue
   exit=160 if x[owner] else 88;break
  x[link]=x[owner]|1;refreshes+=1
  while True:
   loads[1]+=1
   if mismatch:memory[CELL]=NODE|1;mismatch=False
   x[status]=memory[CELL];flags=cmp64(x[status],x[owner])
   if x[status]!=x[owner]:clears+=1;exit=88;break
   if not store(1,x[link],CELL):break
  if exit is not None:break
  x[link]=x[mapping[0]]+0x80
  while True:
   loads[2]+=1;x[status]=memory[SECOND];flags=cmp64(x[status],x[owner])
   if x[status]!=x[owner]:
    clears+=1
    while True:
     loads[3]+=1;x[link]=memory[CELL]&~1
     if not store(3,x[link],CELL):break
    exit=88;break
   if not store(2,0,SECOND):exit=160 if x[owner] else 88;break
  break
 return {'x':x,'q':[int.from_bytes(bytes([r+3])*16,'little') for r in range(32)],'sp':STACK,'flags':flags,
  'memory':memory,'loads':loads,'stores':stores,'clears':clears,'refreshes':refreshes,'exit':BEGIN+exit}

def execute(body,mapping,case):
 cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);detour=0x700000
 for addr in (BASE,0x400000,0x500000,0x800000,detour):cpu.mem_map(addr,4096)
 cpu.mem_write(BASE,body);before,memory=initial(mapping,case)
 for addr,value in memory.items():cpu.mem_write(addr,struct.pack('<Q',value))
 for r,v in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{r}'),v)
 qs=[int.from_bytes(bytes([r+3])*16,'little') for r in range(32)]
 for r,v in enumerate(qs):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{r}'),v)
 cpu.reg_write(uc.UC_ARM64_REG_SP,STACK);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
 loads=[0]*4;stores=[0]*4;state={'live':False,'clears':0,'refreshes':0,'skip':False,'done':None,'mismatch':case.get('mismatch_primary',False)}
 loadpcs={BEGIN:0,BEGIN+36:1,BEGIN+60:2,BEGIN+184:3};storepcs={BEGIN+16:0,BEGIN+48:1,BEGIN+72:2,BEGIN+192:3}
 failures=case.get('fail',(0,0,0,0))
 def hook(machine,address,size,_):
  pc=address-BASE
  if pc in (BEGIN+88,BEGIN+160):
   assert not state['live'];state['done']=pc;machine.emu_stop();return
  if pc in loadpcs:
   phase=loadpcs[pc];loads[phase]+=1
   if phase==1 and state['live']:state['refreshes']+=1
   else:assert not state['live']
   state['live']=True
   if phase==1 and state['mismatch']:
    machine.mem_write(CELL,struct.pack('<Q',NODE|1));state['mismatch']=False
  if pc in (BEGIN+84,BEGIN+180):state['live']=False;state['clears']+=1
  if pc in storepcs:
   if state['skip']:state['skip']=False;return
   assert state['live'];state['live']=False;phase=storepcs[pc];stores[phase]+=1
   if stores[phase]<=failures[phase]:
    compete=case.get('compete',(None,None))
    if compete[0]==phase:machine.mem_write(SECOND if phase==2 else CELL,struct.pack('<Q',compete[1]))
    machine.mem_write(detour,raw((0xD5033F5F,ar.branch(detour+4,address))))
    state['skip']=True;machine.reg_write(uc.UC_ARM64_REG_PC,detour)
 cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(BASE+BEGIN,BASE+0x2F0,count=1000)
 assert state['done'] is not None
 # Full data-page and stack guards detect writes beyond the three modeled cells.
 observed={a:struct.unpack('<Q',cpu.mem_read(a,8))[0] for a in memory}
 for page in (0x400000,0x500000):
  expected=bytearray(4096)
  for addr,value in observed.items():
   if page<=addr<page+4096:struct.pack_into('<Q',expected,addr-page,value)
  assert bytes(cpu.mem_read(page,4096))==bytes(expected)
 assert bytes(cpu.mem_read(0x800000,4096))==bytes(4096)
 return {'x':[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)],
  'q':[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')) for r in range(32)],'sp':cpu.reg_read(uc.UC_ARM64_REG_SP),
  'flags':cpu.reg_read(uc.UC_ARM64_REG_NZCV),'memory':{a:struct.unpack('<Q',cpu.mem_read(a,8))[0] for a in memory},
  'loads':loads,'stores':stores,'clears':state['clears'],'refreshes':state['refreshes'],'exit':state['done']}
if __name__=='__main__':unittest.main()
