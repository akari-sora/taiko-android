"""Finite observed ADD/LDXR/STLXR/CBNZ schedule; software-only evidence."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,HEAD,END=0x100,0x104,0x110
WORDS=(0x910202C9,0xC85F7D28,0xC80AFD20,0x35FFFFAA)
FIELDS=((0,5),(0,5),(0,5,16),(0,))
NODES=set(range(BEGIN,END,4));MASK=(1<<64)-1
MAPS=({r:r for r in (0,8,9,10,22)},{0:1,8:2,9:3,10:4,22:5},{0:28,8:27,9:26,10:25,22:24})
def raw(words):return struct.pack('<'+'I'*len(words),*words)
def fixture(mapping=MAPS[0]):
 words=[0xD503201F]*((END+4)//4);words[0]=ar.branch(0,BEGIN);words[END//4]=0xD65F03C0
 for ix,(w,fields) in enumerate(zip(WORDS,FIELDS)):
  for shift in fields:w=(w&~(31<<shift))|mapping[WORDS[ix]>>shift&31]<<shift
  words[BEGIN//4+ix]=w
 return words
def decoded(words):
 ops=[ar.decode(w,ix*4) for ix,w in enumerate(words)]
 return ops,{i.address:ar.site_kind(i) for i in ops}
def helper(words=None,kinds=None,remove=None):
 ops,k=decoded(fixture() if words is None else words);by={i.address:i for i in ops};k.update(kinds or {})
 start=by[HEAD]
 if remove is not None:by.pop(remove)
 return ar.android_exclusive.native_conditional_refresh(start,by,k,ar)
def rewrite(words,entries=(0,BEGIN)):
 return ar.rewrite(raw(words),entry_offsets=entries,independent_entry_offsets=entries,checked_stack=True,package_version=2)
class NativeExchangeAddRetryTests(unittest.TestCase):
 def test_observed_exact_row_and_renames(self):
  for mapping in MAPS:
   words=fixture(mapping)
   self.assertEqual(helper(words),(NODES,BEGIN,{HEAD}))
   image=rewrite(words);self.assertEqual(image.bytes[BEGIN:END],raw(words)[BEGIN:END]);self.assertFalse(image.sites);self.assertFalse(image.fixups)
 def test_each_nonregister_bit_and_unobserved_literal_rejected(self):
  for ix,fields in enumerate(FIELDS):
   mask=sum(31<<s for s in fields)
   for bit in range(32):
    if mask>>bit&1:continue
    words=fixture();words[BEGIN//4+ix]^=1<<bit
    try:r=helper(words)
    except ar.RewriteError:r=None
    self.assertIsNone(r,(ix,bit))
 def test_interior_entries_all_origin_classes_and_raw_edges(self):
  for pc in sorted(NODES-{BEGIN}):
   for origin in ('metadata','materialized','table','call'):
    with self.subTest(pc=pc,origin=origin),self.assertRaises(ar.RewriteError):rewrite(fixture(),(0,BEGIN,pc))
   words=fixture();words[0]=ar.branch(0,pc)
   with self.assertRaises(ar.RewriteError):rewrite(words)
 def test_missing_host_kind_bad_registers_and_fatal_exit_rejected(self):
  for pc in sorted(NODES):
   self.assertIsNone(helper(remove=pc))
   for kind in ('x18','svc','tls','stack_check','foreign'):
    with self.assertRaises(ar.RewriteError):helper(kinds={pc:kind})
  for role in MAPS[0]:
   for target in (18,29,30,31):
    m=dict(MAPS[0]);m[role]=target;self.assertIsNone(helper(fixture(m)))
  for a in MAPS[0]:
   for b in MAPS[0]:
    if a==b:continue
    m=dict(MAPS[0]);m[a]=b;self.assertIsNone(helper(fixture(m)))
  words=fixture();words[END//4]=0xD4200000;self.assertIsNone(helper(words))
 def test_unicorn_original_and_rewritten_exchange_full_state(self):
  for mapping in MAPS:
   words=fixture(mapping);image=rewrite(words)
   for failures in (0,1,3):
    for old,new in ((0,0),(MASK,0x1122334455667788),(0x8000000000000000,MASK)):
     for body in (raw(words),image.bytes):
      self.cpu(body,mapping,failures,old,new)
 def cpu(self,body,mapping,failures,old,new):
  base,mem,stack,detour=0x100000,0x400000,0x800000,0x700000
  cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
  for page in (base,mem,stack,detour):cpu.mem_map(page,4096)
  cpu.mem_write(base,body);cpu.mem_write(detour,raw((0xD5033F5F,ar.branch(detour+4,base+BEGIN+8))))
  page=bytearray((i*13+7)%256 for i in range(4096));page[0x80:0x88]=struct.pack('<Q',old);cpu.mem_write(mem,bytes(page));stackpage=bytes([0xAC])*4096;cpu.mem_write(stack,stackpage)
  regs=[0xA500000000000000+i for i in range(31)];regs[mapping[22]]=mem;regs[mapping[0]]=new;regs[30]=base+0x300
  for r,v in enumerate(regs):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{r}'),v)
  qs=[int.from_bytes(bytes([r+3])*16,'little') for r in range(32)]
  for r,v in enumerate(qs):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{r}'),v)
  cpu.reg_write(uc.UC_ARM64_REG_SP,stack+0x800);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
  state={'loads':0,'stores':0,'live':False,'detour':False,'done':False,'old':old}
  def hook(machine,pc,size,_):
   if pc==base+END:
    self.assertFalse(state['live']);state['done']=True;machine.emu_stop();return
   if pc==base+HEAD:
    self.assertFalse(state['live']);state['live']=True;state['loads']+=1
   if pc==base+BEGIN+8:
    if state['detour']:state['detour']=False;return
    self.assertTrue(state['live']);state['live']=False;state['stores']+=1
    if state['stores']<=failures:
     state['old']=(old+state['stores']*0x101)&MASK;machine.mem_write(mem+0x80,struct.pack('<Q',state['old']));state['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,detour)
  cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(base,base+0x300,count=200)
  self.assertTrue(state['done']);self.assertEqual(state['loads'],failures+1);self.assertEqual(state['stores'],failures+1)
  expected=regs.copy();expected[mapping[9]]=mem+0x80;expected[mapping[8]]=state['old'];expected[mapping[10]]=0
  self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)],expected)
  self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')) for r in range(32)],qs)
  self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_SP),stack+0x800);self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_NZCV),0xB0000000)
  page[0x80:0x88]=struct.pack('<Q',new);self.assertEqual(bytes(cpu.mem_read(mem,4096)),bytes(page));self.assertEqual(bytes(cpu.mem_read(stack,4096)),stackpage)
if __name__=='__main__':unittest.main()
