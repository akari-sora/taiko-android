"""Finite Taiko read-poll return path; WFE simulation is not physical progress."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
FUNCTION,BEGIN=0x100,0x110;GATE,RET=BEGIN+40,BEGIN+44
POLL=(0xD50320BF,0xD503205F,0x885FFE69,0x72003D3F,0x54FFFFA1,0x53107D29,0x6B29011F,0x54FFFF41)
TAIL=(0xA9424FF4,0xF9400BF5,0xA8C37BFD,0xD65F03C0)
OLD=(0xA9427BFD,0xA9414FF4,0xF84307F5,0xD65F03C0)
PREFIX=(0xA9BD7BFD,0xF9000BF5,0x910003FD,0xA9024FF4)
CELL,STACK=0x400000,0x800000
def raw(v):return struct.pack('<'+'I'*len(v),*v)
def fixture():
 v=[0xD503201F]*((RET+4)//4);v[0]=ar.branch(0,FUNCTION);v[FUNCTION//4:BEGIN//4]=PREFIX;v[BEGIN//4:RET//4+1]=POLL+TAIL;return v
def decoded(v,checked=True):
 ops=[ar.decode(w,i*4) for i,w in enumerate(v)];k={i.address:ar.site_kind(i) for i in ops}
 if checked:
  for i in ops:
   if any(i.reg_name(r) in ('sp','wsp') for r in i.regs_access()[1]):
    if ar.stack_check_operation(int.from_bytes(i.bytes,'little')) is not None:k[i.address]='stack_check'
 return ops,k
def rewrite(v=None,**extra):
 opts=dict(checked_stack=True,package_version=2,entry_offsets=(0,FUNCTION));opts.update(extra);return ar.rewrite(raw(fixture() if v is None else v),**opts)
def helper(v=None,checked=True,remove=None,override=None):
 ops,k=decoded(fixture() if v is None else v,checked);by={i.address:i for i in ops};start=by[BEGIN+8]
 if remove is not None:del by[remove]
 k.update(override or {});return ar.android_exclusive.native_read_wait_checked_return(start,by,k,ar)

class TaikoReadWaitReturnTests(unittest.TestCase):
 def test_exact_true_epilogue_keeps_native_poll_and_actual_checked_pair_gate(self):
  self.assertEqual(helper(),(set(range(BEGIN,BEGIN+32,4)),BEGIN))
  image=rewrite();source=raw(fixture());self.assertEqual([s.offset for s in image.sites],[FUNCTION,GATE]);self.assertTrue(all(g.kind==ar.STACK_CHECK for g in image.gates))
  self.assertEqual(image.bytes[BEGIN:GATE],source[BEGIN:GATE]);self.assertEqual(image.bytes[RET:RET+4],source[RET:RET+4])
  g=next(g for g,p in zip(image.gates,image.gate_provenance) if p.original_offset==GATE);self.assertEqual(g.argument,TAIL[2]);self.assertEqual(ar.stack_check_operation(g.argument),{'source':31,'delta':48,'access_bytes':16,'post_index':True})
  self.assertNotIn(0xD5033F5F,struct.unpack('<10I',image.bytes[BEGIN:GATE])) # no CLREX before retry or in source loads
 def test_all_fixed_source_bits_and_context_gate_kind_refuse(self):
  v=fixture();count=0
  for slot in range(12):
   pc=BEGIN+slot*4
   for bit in range(32):
    changed=list(v);changed[pc//4]^=1<<bit
    try:r=helper(changed)
    except ar.RewriteError:r=None
    self.assertIsNone(r,(slot,bit));count+=1
  self.assertEqual(count,384)
  for pc in range(BEGIN,RET+4,4):self.assertIsNone(helper(remove=pc))
  for pc in range(BEGIN,GATE,4):
   for kind in ('gate','x18','tls','stack_check'):
    with self.assertRaises(ar.RewriteError):helper(override={pc:kind})
  for kind in (None,'gate','tls','missing'):
   with self.assertRaises(ar.RewriteError):helper(override={GATE:kind})
  with self.assertRaises(ar.RewriteError):helper(checked=False)
  with self.assertRaises(ar.RewriteError):helper(override={RET:'gate'})
 def test_no_mid_poll_entry_or_edge_and_no_unchecked_return(self):
  for pc in range(BEGIN+4,BEGIN+32,4):
   with self.assertRaises(ar.RewriteError):rewrite(entry_offsets=(0,FUNCTION,pc))
   changed=fixture();changed[0]=ar.branch(0,pc)
   with self.assertRaises(ar.RewriteError):rewrite(changed)
  with self.assertRaises(ar.RewriteError):rewrite(checked_stack=False)
 def test_original_full_return_path_registers_flags_stack_and_native_monitor_retry(self):
  # These independently authored path fixtures omit the unrelated writer and
  # fatal branches. They do not execute the complete original62-word function.
  for expected,sequence in ((42,(42<<16,)),(42,((42<<16)|1,42<<16)),(42,(41<<16,42<<16)),(42,((40<<16)|7,43<<16,42<<16)),(0,(0xFFFF0000,0)),(255,(0xFFFFFFFF,0xFFFF0000)),(0,(0x01000000,))):
   with self.subTest(expected=expected,sequence=sequence):
    cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base=0x100000;cpu.mem_map(base,4096);cpu.mem_map(CELL,4096);cpu.mem_map(STACK,4096);cpu.mem_write(base,raw(fixture()));stack=bytearray((i*19+7)%256 for i in range(4096));cpu.mem_write(STACK,bytes(stack));cell=bytearray([0xA5]*4096);cpu.mem_write(CELL,bytes(cell))
    before=[0xABCD000000001000+i*0x101 for i in range(31)];before[8]=expected;before[19]=CELL;before[30]=0xFFFFFFFFFFFFFFFC # exact source CMP W8,W9,UXTB compares the low byte of the shifted high field
    for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
    qs=tuple(int.from_bytes(bytes([i])*16,'little') for i in range(32))
    for i,value in enumerate(qs):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
    cpu.reg_write(uc.UC_ARM64_REG_SP,STACK+0x800);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000);seen=dict(waits=0,loads=0,live=False,wait_live=[],done=False)
    def code(machine,pc,size,_):
     at=pc-base
     if at==BEGIN+4:
      seen['wait_live'].append(seen['live']);value=sequence[min(seen['waits'],len(sequence)-1)];seen['waits']+=1;machine.mem_write(CELL,struct.pack('<I',value)) # authored competing writes, not forced wake/physical timing
     elif at==BEGIN+8:seen['loads']+=1;seen['live']=True
     elif at==RET:seen['done']=True;machine.emu_stop()
    cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base+FUNCTION,base+RET+4,count=1000);self.assertTrue(seen['done']);self.assertEqual(seen['waits'],len(sequence));self.assertEqual(seen['loads'],len(sequence));self.assertEqual(seen['wait_live'],[False]+[True]*(len(sequence)-1));self.assertTrue(seen['live'])
    want=before.copy();want[9]=sequence[-1]>>16
    self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],want);self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_SP),STACK+0x800);self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_NZCV),0x60000000);self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),qs)
    for off,reg in ((0x7D0,29),(0x7D8,30),(0x7E0,21),(0x7F0,20),(0x7F8,19)):struct.pack_into('<Q',stack,off,before[reg])
    self.assertEqual(bytes(cpu.mem_read(STACK,4096)),bytes(stack));struct.pack_into('<I',cell,0,sequence[-1]);self.assertEqual(bytes(cpu.mem_read(CELL,4096)),bytes(cell))
if __name__=='__main__':unittest.main()
