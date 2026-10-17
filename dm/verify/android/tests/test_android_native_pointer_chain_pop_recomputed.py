"""Second tagged free-list pop: recomputed cells, exact source proof, CPU checks."""
from pathlib import Path
import struct,sys,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'dm/verify/android/tests')]
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN=0x100
OFFSETS=(*range(0,36,4),*range(52,120,4),*range(700,728,4))
WORDS=(0xC85FFD33,0x37000393,0xF940026A,0xB400014A,0x9101010B,0xC80CFD6A,
 0x35FFFF4C,0xB5000413,0x14000016,0xB2400269,0x9101010A,0xC85FFD4B,
 0xEB13017F,0x54000181,0x9101010B,0xC80C7D69,0x35FFFF6C,0x91020109,
 0xC85FFD2A,0xEB13015F,0x540012E1,0x9102010A,0xC80B7D5F,0x35FFFF6B,
 0x17FFFFEB,0xD5033F5F,0x91010108,0xD5033F5F,0xC85F7D09,0x927FF929,
 0xC80AFD09,0x35FFFFAA,0x17FFFF69)
FIELDS=((0,5),(0,),(0,5),(0,),(0,5),(0,5,16),(0,),(0,),(),(0,5),
 (0,5),(0,5),(5,16),(),(0,5),(0,5,16),(0,),(0,5),(0,5),(5,16),(),
 (0,5),(0,5,16),(0,),(),(),(0,5),(),(0,5),(0,5),(0,5,16),(0,),())
NODES={BEGIN+x for x in OFFSETS}
HEADS={BEGIN+x for x in (0,60,88,708)}
ISLAND={BEGIN+x for x in (36,40,44,48)}
EXITS={BEGIN+120,BEGIN+156}
CLEARS={BEGIN+116,BEGIN+704}
RETRIES={BEGIN+24:BEGIN,BEGIN+80:BEGIN+60,BEGIN+108:BEGIN+88,BEGIN+720:BEGIN+708}
MAPS=({8:8,9:9,10:10,11:11,12:12,19:19},{8:1,9:2,10:3,11:4,12:5,19:6},
 {8:28,9:27,10:26,11:25,12:24,19:23})
SEALED_WORDS=(0xC85FFD13,0x37000293,0xF9400269,0xB40000A9,0xC80AFD09,0x35FFFF6A,
 0xB5000453,0x1400000F,0xB2400269,0xC85FFD0A,0xEB13015F,0x54000141,0xC80A7D09,
 0x35FFFF8A,0x91020009,0xC85FFD2A,0xEB13015F,0x54000381,0xC80A7D3F,0x35FFFF8A,
 0x17FFFFF2,0xD5033F5F,0xD5033F5F,0xC85F7D09,0x927FF929,0xC80AFD09,0x35FFFFAA,
 0x17FFFFE4)
SEALED_FIELDS=((0,5),(0,),(0,5),(0,),(0,5,16),(0,),(0,),(),(0,5),(0,5),(5,16),(),
 (0,5,16),(0,),(0,5),(0,5),(5,16),(),(0,5,16),(0,),(),(),(),(0,5),(0,5),(0,5,16),
 (0,),())
MASK=(1<<64)-1
BASE=0x100000
OBJ=0x400000
CELL=0x400040
SECOND=0x400080
NODE=0x500100
NEXT=0x500200
STACK=0x800800

def raw(words):return struct.pack('<'+'I'*len(words),*words)
def fixture(mapping=MAPS[0]):
 words=[0xD503201F]*(0x400//4);words[0]=ar.branch(0,BEGIN)
 for offset,word,fields in zip(OFFSETS,WORDS,FIELDS):
  for shift in fields:
   role=word>>shift&31
   word=(word&~(31<<shift))|((31 if role==31 else mapping[role])<<shift)
  words[(BEGIN+offset)//4]=word
 for pc in (BEGIN+48,BEGIN+120,BEGIN+156,BEGIN+696):words[pc//4]=0xD65F03C0
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

class NativePointerChainPopRecomputedTests(unittest.TestCase):
 def test_exact_recomputed_heads_and_consistent_roles_preserved(self):
  self.assertEqual((len(OFFSETS),len(WORDS),len(FIELDS)),(33,33,33))
  mod=ar.android_exclusive
  self.assertEqual(mod.NATIVE_POINTER_CHAIN_POP_RECOMPUTED_OFFSETS,OFFSETS)
  self.assertEqual(mod.NATIVE_POINTER_CHAIN_POP_RECOMPUTED_WORDS,WORDS)
  self.assertEqual(mod.NATIVE_POINTER_CHAIN_POP_RECOMPUTED_FIELDS,FIELDS)
  self.assertEqual(mod.NATIVE_POINTER_CHAIN_POP_WORDS,SEALED_WORDS)
  self.assertEqual(mod.NATIVE_POINTER_CHAIN_POP_FIELDS,SEALED_FIELDS)
  source=Path(mod.__file__).read_text(encoding='utf-8').splitlines()
  self.assertEqual(source[1738],"                raise api.RewriteError(f'0x{pc:x}: nested/overlapping exclusive window')")
  for mapping in MAPS:
   words=fixture(mapping);ops,by,k=decoded(words)
   self.assertIsNone(mod.native_pointer_chain_pop(by[BEGIN],by,k,ar))
   self.assertEqual(match(words),(NODES,BEGIN,HEADS))
   self.assertTrue(CLEARS<=NODES)
   self.assertTrue(ISLAND.isdisjoint(NODES))
   self.assertTrue(EXITS.isdisjoint(NODES))
   self.assertNotIn(BEGIN+124,NODES)
   self.assertEqual(plan(words),())
   image=ar.rewrite(raw(words),entry_offsets=(0,),package_version=2,checked_stack=True)
   self.assertEqual(image.bytes,raw(words));self.assertFalse(image.sites);self.assertFalse(image.fixups)
  identity=fixture()
  for offset,word in ((708,0xC85F7D09),(712,0x927FF929),(716,0xC80AFD09),(720,0x35FFFFAA)):
   self.assertEqual(identity[(BEGIN+offset)//4],word)
 def test_each_nonregister_source_bit_is_fixed(self):
  words=fixture();ops,by,k=decoded(words)
  for pc,word,fields in zip((BEGIN+x for x in OFFSETS),WORDS,FIELDS):
   mask=sum(31<<s for s in fields)
   for bit in range(32):
    if mask>>bit&1:continue
    changed=by.copy();kinds=k.copy()
    try:
     changed[pc]=ar.decode(word^(1<<bit),pc);kinds[pc]=ar.site_kind(changed[pc])
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
    mapping=dict(MAPS[0]);mapping[role]=target
    self.assertIsNone(match(fixture(mapping)),(role,target))
  for offset,word,fields in zip(OFFSETS,WORDS,FIELDS):
   for shift in fields:
    if word>>shift&31!=31:continue
    changed=fixture();at=(BEGIN+offset)//4
    changed[at]=(changed[at]&~(31<<shift))
    self.assertIsNone(match(changed),(hex(BEGIN+offset),shift))
  for pc in EXITS:
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
  words=fixture();words[(BEGIN+696)//4]=0xD503201F;self.assertIsNotNone(match(words))
  with self.assertRaises(ar.RewriteError):plan(words,reverse=True)
  with self.assertRaises(ar.RewriteError):plan(words)
  words=fixture();words[(BEGIN+48)//4]=0xD503201F
  with self.assertRaises(ar.RewriteError):plan(words)
 def test_sparse_union_gap_and_overlap_remain_checked(self):
  words=fixture();self.assertEqual(plan(words),())
  for pc in (*ISLAND,*range(BEGIN+120,BEGIN+700,4)):
   self.assertIsNotNone(match(words,overrides={pc:'gate'}))
  fn=ar.android_exclusive.native_pointer_chain;head=BEGIN+708
  def earlier(start,by,k,api):
   if start.address==head:return {head,head+4,head+8,head+12},head,{head}
   return fn(start,by,k,api)
  ops,_,k=decoded(words);ordered=[i for i in ops if i.address==head]+[i for i in ops if i.address!=head]
  with patch.object(ar.android_exclusive,'native_pointer_chain',earlier),self.assertRaisesRegex(ar.RewriteError,'overlapping exclusive windows'):
   ar.android_exclusive.plan_regions(ordered,k,(0,),ar)
 def test_retries_close_reservation_before_both_exits(self):
  words=fixture();_,by,_=decoded(words);self.assertIsNotNone(match(words))
  for pc,target in RETRIES.items():
   self.assertEqual(ar.android_exclusive.successors(by[pc]),(pc+4,target))
  self.assertEqual(ar.android_exclusive.successors(by[BEGIN+116]),(BEGIN+120,))
  self.assertNotIn(BEGIN+124,NODES)
  add=struct.unpack('<I',by[BEGIN+16].bytes)[0]
  load=struct.unpack('<I',by[BEGIN].bytes)[0]
  seed=tuple(sorted({add>>5&31:('obj',0),load>>5&31:('obj',0x40)}.items()))
  pending=[(BEGIN,None,seed)];seen=set();exits=set();refreshes=set()
  while pending:
   pc,live,snap=pending.pop()
   if (pc,live,snap) in seen:continue
   seen.add((pc,live,snap));addr=dict(snap)
   if pc not in NODES:
    self.assertIn(pc,EXITS);self.assertIsNone(live);exits.add(pc);continue
   ins=by[pc];word=struct.unpack('<I',ins.bytes)[0];base=word>>5&31
   if ins.mnemonic in ar.EXCLUSIVE_LOADS:
    self.assertEqual(addr[base][0],'obj');self.assertIn(addr[base][1],(0x40,0x80))
    if live is not None:
     self.assertEqual((pc,live,addr[base]),(BEGIN+60,('obj',0x40),('obj',0x40)));refreshes.add(pc)
    live=addr[base]
   elif ins.mnemonic in ar.EXCLUSIVE_STORES:
    self.assertEqual(addr[base],live);live=None
   elif ins.mnemonic=='clrex':live=None
   if ins.mnemonic=='add':
    imm=word>>10&0xFFF;rd=word&31;rn=word>>5&31
    self.assertEqual(word>>22&3,0);self.assertIn(imm,(0x40,0x80));self.assertIn(rn,addr)
    addr[rd]=(addr[rn][0],addr[rn][1]+imm)
   else:
    written=()
    if ins.mnemonic in ('ldaxr','ldxr','ldr','orr','and'):written=(word&31,)
    elif ins.mnemonic in ('stxr','stlxr'):written=(word>>16&31,)
    for reg in written:addr.pop(reg,None)
   self.assertNotIn(ins.mnemonic,('bl','blr','br','ret','svc','wfe'))
   pending.extend((target,live,tuple(sorted(addr.items()))) for target in ar.android_exclusive.successors(ins))
  visited={pc for pc,_,_ in seen}
  self.assertEqual(visited&NODES,NODES)
  self.assertEqual(exits,EXITS);self.assertEqual(refreshes,{BEGIN+60});self.assertTrue(CLEARS<=visited)
 def test_all_monitor_paths_cpu_and_independent_reference(self):
  cases=({'tagged':True},{'link':NEXT},{'link':NEXT,'fail':(2,0,0,0)},
   {},{'fail':(0,2,0,0)},{'mismatch_primary':True},{'secondary':NEXT},
   {'fail':(0,0,2,0)},{'secondary':NEXT,'fail':(0,0,0,2)},
   {'link':NEXT,'fail':(1,0,0,0),'compete':(0,NODE|1)},
   {'fail':(0,1,0,0),'compete':(1,NODE|1)},
   {'fail':(0,0,1,0),'compete':(2,NEXT)},
   {'secondary':NEXT,'fail':(0,0,0,1),'compete':(3,NODE|3)})
  for mapping in MAPS:
   words=fixture(mapping)
   rewritten=ar.rewrite(raw(words),entry_offsets=(0,),package_version=2,checked_stack=True)
   for case in cases:
    want=reference(mapping,case)
    for body in (raw(words),rewritten.bytes):
     with self.subTest(mapping=mapping,case=case):self.assertEqual(execute(body,mapping,case),want)

def initial(mapping,case):
 x=[0xA500000000000000+i for i in range(31)]
 x[mapping[8]]=OBJ;x[mapping[9]]=CELL;x[30]=BASE+0x2F0
 owner=NODE|int(case.get('tagged',False))
 memory={CELL:owner,SECOND:case.get('secondary',NODE),NODE:case.get('link',0)}
 return x,memory
def reference(mapping,case):
 x,memory=initial(mapping,case)
 obj,reuse,tmp,alt,sts,own=(mapping[r] for r in (8,9,10,11,12,19))
 cell,second=x[obj]+0x40,x[obj]+0x80
 flags=0xB0000000;loads=[0]*4;stores=[0]*4;clears=0;refreshes=0;exit=None
 failures=case.get('fail',(0,0,0,0));mismatch=case.get('mismatch_primary',False)
 compete=case.get('compete',(None,None))
 def store(phase,payload,dst,status):
  stores[phase]+=1;failed=stores[phase]<=failures[phase]
  if failed and compete[0]==phase:memory[dst]=compete[1]
  if not failed:memory[dst]=payload&MASK
  x[status]=int(failed);return failed
 while True:
  loads[0]+=1;x[own]=memory[cell]
  if x[own]&1:clears+=1;exit=120;break
  x[tmp]=memory[x[own]]
  if x[tmp]:
   x[alt]=cell
   if store(0,x[tmp],cell,sts):continue
   exit=156 if x[own] else 120;break
  x[reuse]=x[own]|1;x[tmp]=cell;refreshes+=1
  while True:
   loads[1]+=1
   if mismatch:memory[cell]=NODE|1;mismatch=False
   x[alt]=memory[cell];flags=cmp64(x[alt],x[own])
   if x[alt]!=x[own]:clears+=1;exit=120;break
   x[alt]=cell
   if not store(1,x[reuse],cell,sts):break
  if exit is not None:break
  x[reuse]=second
  while True:
   loads[2]+=1;x[tmp]=memory[second];flags=cmp64(x[tmp],x[own])
   if x[tmp]!=x[own]:
    clears+=1;x[obj]=cell
    while True:
     loads[3]+=1;x[reuse]=memory[cell]&~1
     if not store(3,x[reuse],cell,tmp):break
    exit=120;break
   x[tmp]=second
   if not store(2,0,second,alt):exit=156 if x[own] else 120;break
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
 loadpcs={BEGIN:0,BEGIN+60:1,BEGIN+88:2,BEGIN+708:3}
 storepcs={BEGIN+20:0,BEGIN+76:1,BEGIN+104:2,BEGIN+716:3}
 failures=case.get('fail',(0,0,0,0))
 def hook(machine,address,size,_):
  pc=address-BASE
  if pc in EXITS:
   assert not state['live'];state['done']=pc;machine.emu_stop();return
  if pc in loadpcs:
   phase=loadpcs[pc];loads[phase]+=1
   if phase==1 and state['live']:state['refreshes']+=1
   else:assert not state['live']
   state['live']=True
   if phase==1 and state['mismatch']:
    machine.mem_write(CELL,struct.pack('<Q',NODE|1));state['mismatch']=False
  if pc in CLEARS:state['live']=False;state['clears']+=1
  if pc in storepcs:
   if state['skip']:state['skip']=False;return
   assert state['live'];state['live']=False;phase=storepcs[pc];stores[phase]+=1
   if stores[phase]<=failures[phase]:
    compete=case.get('compete',(None,None))
    if compete[0]==phase:machine.mem_write(SECOND if phase==2 else CELL,struct.pack('<Q',compete[1]))
    machine.mem_write(detour,raw((0xD5033F5F,ar.branch(detour+4,address))))
    state['skip']=True;machine.reg_write(uc.UC_ARM64_REG_PC,detour)
 cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(BASE+BEGIN,BASE+0x400,count=1000)
 assert state['done'] is not None
 observed={a:struct.unpack('<Q',cpu.mem_read(a,8))[0] for a in memory}
 for page in (0x400000,0x500000):
  expected=bytearray(4096)
  for addr,value in observed.items():
   if page<=addr<page+4096:struct.pack_into('<Q',expected,addr-page,value)
  assert bytes(cpu.mem_read(page,4096))==bytes(expected)
 assert bytes(cpu.mem_read(0x800000,4096))==bytes(4096)
 return {'x':[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)],
  'q':[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')) for r in range(32)],'sp':cpu.reg_read(uc.UC_ARM64_REG_SP),
  'flags':cpu.reg_read(uc.UC_ARM64_REG_NZCV),'memory':observed,'loads':loads,'stores':stores,
  'clears':state['clears'],'refreshes':state['refreshes'],'exit':state['done']}
if __name__=='__main__':unittest.main()
