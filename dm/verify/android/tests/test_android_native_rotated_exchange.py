"""Observed rotated conditional exchange. Software CPU evidence only."""
from pathlib import Path
import struct, sys, unittest
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as uc
B,H,E,S,X=0x100,0x108,0x114,0x140,0x180
WORDS=(0xC808FF53,0x340001E8,0xC85FFF48,0xB4FFFFA8,0xD5033F5F)
FIELDS=((0,5,16),(0,),(0,5),(0,),())
NODES=set(range(B,E,4));MASK=(1<<64)-1
MAPS=({8:8,19:19,26:26},{8:0,19:1,26:2},{8:28,19:27,26:25})
def raw(words):return struct.pack('<'+'I'*len(words),*words)
def fixture(mapping=MAPS[0]):
    words=[0xD503201F]*((X+4)//4)
    words[0]=ar.branch(0,H);words[(B-4)//4]=ar.branch(B-4,H)
    for ix,(w,fields) in enumerate(zip(WORDS,FIELDS)):
        for shift in fields:w=(w&~(31<<shift))|mapping[WORDS[ix]>>shift&31]<<shift
        words[B//4+ix]=w
    words[(B+4)//4]=(words[(B+4)//4]&~(0x7FFFF<<5))|(((S-B-4)//4)&0x7FFFF)<<5
    words[E//4]=0xD5033BBF;words[E//4+1]=ar.branch(E+4,X)
    words[S//4]=0xD5033BBF;words[S//4+1]=ar.branch(S+4,X)
    words[X//4]=0xD65F03C0
    return words
def helper(words=None,remove=None,kinds=None):
    ops=[ar.decode(w,ix*4) for ix,w in enumerate(fixture() if words is None else words)]
    by={i.address:i for i in ops};start=by[H];k={i.address:ar.site_kind(i) for i in ops};k.update(kinds or {})
    if remove is not None:by.pop(remove)
    return ar.android_exclusive.native_conditional_refresh(start,by,k,ar)
def rewrite(words,entries=(0,H)):
    return ar.rewrite(raw(words),entry_offsets=entries,independent_entry_offsets=entries,package_version=2,checked_stack=True)
class NativeRotatedExchangeTests(unittest.TestCase):
    def test_original_shape_and_consistent_roles(self):
        for m in MAPS:
            w=fixture(m);self.assertEqual(helper(w),(NODES,H,{H}))
            r=rewrite(w);self.assertEqual(r.bytes[B:E],raw(w)[B:E]);self.assertFalse(r.sites);self.assertFalse(r.fixups)
    def test_fixed_bits_missing_words_and_roles_refuse(self):
        for ix,fields in enumerate(FIELDS):
            mask=sum(31<<s for s in fields)
            if ix==1:mask|=0x7FFFF<<5
            for bit in range(32):
                if mask>>bit&1:continue
                w=fixture();w[B//4+ix]^=1<<bit
                try:r=helper(w)
                except ar.RewriteError:r=None
                self.assertIsNone(r,(ix,bit))
        for pc in NODES:
            self.assertIsNone(helper(remove=pc))
            for kind in ('x18','svc','tls','stack_check','foreign'):
                with self.assertRaises(ar.RewriteError):helper(kinds={pc:kind})
        for role in MAPS[0]:
            for dest in (18,29,30,31):
                m=dict(MAPS[0]);m[role]=dest;self.assertIsNone(helper(fixture(m)))
            for other in MAPS[0]:
                if role==other:continue
                m=dict(MAPS[0]);m[role]=other;self.assertIsNone(helper(fixture(m)))
    def test_wrong_entries_and_external_targets_refuse(self):
        for pc in NODES-{H}:
            with self.assertRaises(ar.RewriteError):rewrite(fixture(),(0,H,pc))
            w=fixture();w[0]=ar.branch(0,pc)
            with self.assertRaises(ar.RewriteError):rewrite(w)
        for target in sorted(NODES):
            w=fixture();w[(B+4)//4]=(w[(B+4)//4]&~(0x7FFFF<<5))|(((target-B-4)//4)&0x7FFFF)<<5
            self.assertIsNone(helper(w))
        w=fixture();w[S//4]=0xD4200000;self.assertIsNone(helper(w))
        w=fixture();w[E//4]=0xD4200000;self.assertIsNone(helper(w))
    def test_original_rewrite_cpu_success_busy_race_and_failure(self):
        for m in MAPS:
            words=fixture(m);image=rewrite(words)
            for initial,failures,race,owner in ((0,0,0,0),(0,0,0,MASK),(1,0,0,3),(1<<63,0,0,4),(0,1,0,5),(0,3,0,6),(0,1,MASK,7)):
                a=self.cpu(raw(words),m,initial,failures,race,owner)
                b=self.cpu(image.bytes,m,initial,failures,race,owner)
                self.assertEqual(a,b)
    def cpu(self,body,m,initial,failures,race,owner):
        base,mem,stack,detour=0x100000,0x400000,0x800000,0x700000
        cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for page in (base,mem,stack,detour):cpu.mem_map(page,4096)
        cpu.mem_write(base,body);cpu.mem_write(detour,raw((0xD5033F5F,ar.branch(detour+4,base+B))))
        page=bytearray((i*17+9)%256 for i in range(4096));page[0x80:0x88]=struct.pack('<Q',initial);cpu.mem_write(mem,bytes(page));stackpage=bytes([0xAE])*4096;cpu.mem_write(stack,stackpage)
        regs=[0xA100000000000000+i for i in range(31)];regs[m[26]]=mem+0x80;regs[m[19]]=owner;regs[30]=base+X
        for r,v in enumerate(regs):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{r}'),v)
        qs=[int.from_bytes(bytes([r+2])*16,'little') for r in range(32)]
        for r,v in enumerate(qs):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{r}'),v)
        cpu.reg_write(uc.UC_ARM64_REG_SP,stack+0x800);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
        state={'loads':0,'stores':0,'live':False,'detour':False,'done':False,'success':False,'last':initial}
        def hook(machine,pc,size,_):
            if pc in (base+E,base+S):
                self.assertFalse(state['live']);state['success']=pc==base+S
            if pc==base+X:state['done']=True;machine.emu_stop();return
            if pc==base+H:
                self.assertFalse(state['live']);state['live']=True;state['loads']+=1
                state['last']=struct.unpack('<Q',machine.mem_read(mem+0x80,8))[0]
            if pc==base+B:
                if state['detour']:state['detour']=False;return
                self.assertTrue(state['live']);state['live']=False;state['stores']+=1
                if state['stores']<=failures:
                    machine.mem_write(mem+0x80,struct.pack('<Q',race));state['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,detour)
            if pc==base+B+16:self.assertTrue(state['live']);state['live']=False
        cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(base,base+X,count=300)
        # Unicorn's end PC stops before the hook at X.
        self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_PC),base+X);self.assertFalse(state['live'])
        expected=regs.copy();expected[m[8]]=0 if state['success'] else state['last']
        actual=[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)]
        self.assertEqual(actual,expected)
        self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')) for r in range(32)],qs)
        self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_SP),stack+0x800);self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_NZCV),0xB0000000)
        page[0x80:0x88]=struct.pack('<Q',owner if state['success'] else state['last'])
        self.assertEqual(bytes(cpu.mem_read(mem,4096)),bytes(page));self.assertEqual(bytes(cpu.mem_read(stack,4096)),stackpage)
        return actual,bytes(page),state['loads'],state['stores'],state['success']
if __name__=='__main__':unittest.main()
