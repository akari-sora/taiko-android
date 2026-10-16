"""The boolean CAS layout uses the existing single-frame X18 region emitter."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,ENTRY,HEAD,PRELOAD,SUCCESS,INVALID=32,52,64,60,108,160
BLOCK=(0xD5033F5F,0x2A1F03F1,0x37000231,0xAA1003F1,0x37000390,
       0x8A0B022A,0xAA0E014A,0xF9400552,0xC85F7D90,0xEB11021F,0x54FFFEC1,
       0x8A0B0252,0xAA0F0252,0x8A0D0231,0x8B110251,0xC8127D91,0x35FFFE32,
       0x52800031,0x3607FE31)
def words():
    v=[0xD503201F]*42;v[0]=ar.branch(0,ENTRY);v[7]=ar.branch(28,ENTRY);v[8:27]=BLOCK
    v[SUCCESS//4]=v[INVALID//4]=0xD65F03C0;return v
def raw(v):return struct.pack('<'+'I'*len(v),*v)
def plan(v,roots=(0,ENTRY,SUCCESS,INVALID),overrides=None):
    ops=[ar.decode(w,i*4) for i,w in enumerate(v)];kinds={o.address:ar.site_kind(o) for o in ops};kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ops,kinds,roots,ar)
class VirtualBooleanPreloadTests(unittest.TestCase):
    def test_exact_region_keeps_real_entry_retries_and_exits(self):
        regions=plan(words());self.assertEqual(len(regions),1);r=regions[0]
        self.assertEqual((r.entry,{i.address for i in r.instructions}),(ENTRY,set(range(BEGIN,SUCCESS,4))))
        self.assertEqual(r.reservation_terminals,{BEGIN,BEGIN+60})
        self.assertEqual(r.retry_edges,{(BEGIN+40,BEGIN),(BEGIN+64,BEGIN+4),(BEGIN+72,BEGIN+12)})
        self.assertEqual(r.exit_edges,{(BEGIN+8,SUCCESS),(BEGIN+16,INVALID),(BEGIN+72,SUCCESS)})
        ar.rewrite(raw(words()),entry_offsets=(0,ENTRY,SUCCESS,INVALID))
    def test_every_nonentry_metadata_and_outside_edge_is_rejected(self):
        for pc in set(range(BEGIN,SUCCESS,4))-{ENTRY}:
            with self.assertRaises(ar.RewriteError):plan(words(),roots=(0,ENTRY,SUCCESS,INVALID,pc))
            v=words();v[1]=ar.branch(4,pc)
            with self.assertRaises(ar.RewriteError):plan(v)
    def test_fixed_boolean_width_geometry_payload_and_gate_requirements(self):
        for slot,word in ((0,0xD503201F),(1,0xAA1F03F1),(2,0x37080231),(3,0x2A1003F1),
                          (4,0x37080390),(7,0xF9400952),(8,0xC85FFD90),(10,0x54FFFEE1),
                          (15,0xC812FD91),(16,0x35FFFE52),(17,0x52800051),(18,0x360FFE31)):
            v=words();v[BEGIN//4+slot]=word
            with self.assertRaises(ar.RewriteError):plan(v)
        for pc in range(BEGIN,SUCCESS,4):
            for kind in ('gate','parameter','parameter_tail'):
                with self.assertRaises(ar.RewriteError):plan(words(),overrides={pc:kind})
    def execute(self,image,initial,observed,failures,competitor,rewritten):
        base,state,helper,stack=0x100000,0x600000,0x700000,0x800000
        cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        for address in (base,0x400000,0x500000,state,helper,stack-0x1000):cpu.mem_map(address,4096)
        data=bytearray(image.bytes if rewritten else raw(words()))
        if rewritten:
            for fix in image.fixups:
                self.assertEqual(fix.helper,ar.STATE_HELPER);struct.pack_into('<Q',data,fix.offset,helper)
        cpu.mem_write(base,bytes(data));cpu.mem_write(helper,raw([0x58000050,0xD65F03C0])+struct.pack('<Q',state))
        regs=[0xAABB000000000100+i for i in range(31)]
        regs[11:18]=[0xFF,0x400000,0xFFFFFFFFFFFFFF00,0x500000,0x100,0x1122334455667788,initial]
        guest18,hardware18=0x0123456789ABCDEF,0xFEED000000000018
        regs[18]=hardware18 if rewritten else guest18
        for i,v in enumerate(regs):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),v)
        vectors=[int.from_bytes(bytes([i])*16,'little') for i in range(32)]
        for i,v in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),v)
        cpu.reg_write(uc.UC_ARM64_REG_SP,stack);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
        cpu.mem_write(state,struct.pack('<Q',guest18));cpu.mem_write(0x400000,struct.pack('<QQ',initial,0x1122334455667788))
        cpu.mem_write(0x500028,struct.pack('<Q',0xABCDEF1200000040));cpu.mem_write(0x500048,struct.pack('<Q',0xFEDCBA9800000060))
        if initial==0x1041:cpu.mem_write(0x500049,struct.pack('<Q',0x8899AABB00000060))
        result=dict(loads=0,stores=0,clears=0,helpers=0,detour=False,exit=None,monitor=False)
        def code(machine,pc,size,_):
            if rewritten:self.assertEqual(machine.reg_read(uc.UC_ARM64_REG_X18),hardware18)
            if pc in (base+SUCCESS,base+INVALID):result['exit']=pc-base;machine.emu_stop();return
            if pc==helper:
                self.assertFalse(result['monitor']);result['helpers']+=1
            word=struct.unpack('<I',machine.mem_read(pc,4))[0]
            if word&0xFFFFFC00==0xC85F7C00:
                result['loads']+=1;result['monitor']=True
                if result['loads']==1 and observed is not None:machine.mem_write(0x400000,struct.pack('<Q',observed))
            elif word&0xFFE0FC00==0xC8007C00:
                if result['detour']:result['detour']=False
                else:
                    result['stores']+=1
                    if result['stores']<=failures:
                        if competitor is not None:machine.mem_write(0x400000,struct.pack('<Q',competitor))
                        machine.mem_write(helper+0x100,raw([0xD5033F5F,ar.branch(helper+0x104,pc)]))
                        result['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,helper+0x100)
                result['monitor']=False
            elif word==0xD5033F5F:
                result['monitor']=False
                if pc!=helper+0x100:result['clears']+=1
        cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(data),count=4000)
        self.assertIn(result['exit'],(SUCCESS,INVALID));self.assertFalse(result['monitor'])
        final=[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)]
        if rewritten:final[18]=struct.unpack('<Q',cpu.mem_read(state,8))[0]
        result.update(regs=final,flags=cpu.reg_read(uc.UC_ARM64_REG_NZCV),sp=cpu.reg_read(uc.UC_ARM64_REG_SP),
                      q=[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)],memory=bytes(cpu.mem_read(0x400000,16)))
        return result
    def test_emitted_cpu_matches_original_guest_for_success_mismatch_failure_and_invalid(self):
        image=ar.rewrite(raw(words()),entry_offsets=(0,ENTRY,SUCCESS,INVALID))
        for initial,observed,failures,competitor in ((0x1020,None,0,None),(0x1020,None,3,None),
                (0x1020,0x1040,0,None),(0x1020,0x1041,0,None),(0x1041,None,1,None),
                (0x1020,None,1,0x1040),(0x1020,None,1,0x1041)):
            with self.subTest(initial=initial,observed=observed,failures=failures,competitor=competitor):
                original=self.execute(None,initial,observed,failures,competitor,False)
                relocated=self.execute(image,initial,observed,failures,competitor,True)
                self.assertEqual((original.pop('helpers'),relocated.pop('helpers')),(0,1))
                self.assertEqual(original,relocated)
if __name__=='__main__':unittest.main()
