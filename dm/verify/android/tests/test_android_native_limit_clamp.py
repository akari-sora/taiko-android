"""Authored pre-load signed clamp/release CAS row; no title addresses."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'dm/verify/android/tests')]
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,HEAD,END,EXIT,SLOW=16,24,96,108,112
WORDS=(0x0B09010A,0x6B0B015F,0x885F7E6A,0x4B08016C,0x1A89C189,
       0x6B08015F,0x540000E1,0x0B08012B,0x880CFE6B,0x350000AC,
       0x5280002B,0x360000AB,0x1400000B,0xD5033F5F,0x2A1F03EB,
       0x3700010B,0xB940126B,0x6B0A017F,0x2A0A03E8,0x54FFFDA1)
FIELDS=((0,5,16),(5,16),(0,5),(0,5,16),(0,5,16),(5,16),(),(0,5,16),(0,5,16),
        (0,),(0,),(0,),(),(),(0,16),(0,),(0,5),(5,16),(0,16),())
MASK=(1<<32)-1

def raw(values):return struct.pack('<'+'I'*len(values),*values)
def fixture(rename=None):
    block=list(WORDS);rename=rename or {}
    for index,fields in enumerate(FIELDS):
        for shift in fields:
            role=WORDS[index]>>shift&31
            if role!=31:block[index]=block[index]&~(31<<shift)|(rename.get(role,role)<<shift)
    expected=rename.get(8,8)
    tail=0x36F80000|(((END-EXIT)//4)&0x3FFF)<<5|expected
    return [ar.branch(0,BEGIN),0xD503201F,0xD503201F,ar.branch(12,BEGIN)]+block+[
        0xD65F03C0,0xD503201F,0xD503201F,tail,0xD65F03C0,0xD503201F]
def decoded(values):
    ops=[ar.decode(word,index*4) for index,word in enumerate(values)]
    return ops,{op.address:op for op in ops},{op.address:ar.site_kind(op) for op in ops}
def match(values,missing=(),overrides=None):
    ops,by,kinds=decoded(values);kinds.update(overrides or {})
    for pc in missing:by.pop(pc,None)
    return ar.android_exclusive.native_conditional_refresh(ops[HEAD//4],by,kinds,ar)
def plan(values,entries=(0,BEGIN,END,EXIT,SLOW),overrides=None):
    ops,_,kinds=decoded(values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ops,kinds,entries,ar)
def cmp32(left,right):
    left&=MASK;right&=MASK;result=(left-right)&MASK
    return ((bool(result>>31)<<3)|((result==0)<<2)|((left>=right)<<1)|bool((left^right)&(left^result)&0x80000000))<<28

def reference(before,roles,initial,reload_limit,failures=0,competitor=None):
    x=before[:];expect,step,loaded,limit,status,cell=roles
    memory=initial&MASK;counts=dict(loads=0,stores=0,clears=0,reloads=0,writes=0);clamps=[]
    for _ in range(100):
        x[loaded]=(x[expect]+x[step])&MASK;flags=cmp32(x[loaded],x[limit])
        preflags=flags;gt=not(flags&0x40000000) and bool(flags&0x80000000)==bool(flags&0x10000000)
        x[loaded]=memory;counts['loads']+=1
        x[status]=(x[limit]-x[expect])&MASK
        x[step]=(x[status] if gt else x[step])&MASK
        clamps.append((preflags,x[step]));flags=cmp32(x[loaded],x[expect])
        if x[loaded]!=(x[expect]&MASK):counts['clears']+=1
        else:
            x[limit]=(x[step]+x[expect])&MASK;counts['stores']+=1
            x[status]=int(counts['stores']<=failures)
            if not x[status]:
                memory=x[limit];counts['writes']+=1;x[limit]=1
                return x,memory,flags,counts,clamps,'slow' if x[expect]&0x80000000 else 'complete'
            if competitor is not None:memory=competitor&MASK
        x[limit]=0;x[limit]=reload_limit&MASK;counts['reloads']+=1
        flags=cmp32(x[limit],x[loaded]);x[expect]=x[loaded]&MASK
        if x[limit]==x[loaded]:return x,memory,flags,counts,clamps,'complete'
    raise AssertionError('reference did not close')


class NativeLimitClampTests(unittest.TestCase):
    def test_exact_native_row_ordinary_entry_and_injective_role_renaming(self):
        for rename in (None,{8:0,9:1,10:2,11:3,12:4,19:5},{8:28,9:27,10:26,11:25,12:24,19:23}):
            values=fixture(rename)
            self.assertEqual((set(range(BEGIN,END,4)),BEGIN,{HEAD}),match(values))
            self.assertEqual((),plan(values))
            image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,END,EXIT,SLOW))
            self.assertEqual(raw(values),image.bytes);self.assertEqual(((),(),()),(image.sites,image.fixups,image.gates))

    def test_every_interior_root_direct_and_materialized_entry_refuses(self):
        for pc in range(BEGIN+4,END,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):plan(fixture(),(0,BEGIN,END,EXIT,SLOW,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(values)
            # Raw callers explicitly provide address-taken entries, as the NSO
            # importer does; an ADR does not itself grant callback authority.
            delta=pc-4;values=fixture();values[1]=0x10000000|(delta&3)<<29|((delta>>2)&0x7FFFF)<<5
            ops,_,_=decoded(values);address=ops[1].operands[1].imm
            with self.subTest(adr=pc),self.assertRaises(ar.RewriteError):plan(values,(0,BEGIN,END,EXIT,SLOW,address))

    def test_exact_width_release_conditions_bits_roles_missing_and_source_kinds(self):
        for index in range(20):
            self.assertIsNone(match(fixture(),missing=(BEGIN+index*4,)))
            for kind in ('x18','parameter','parameter_tail','gate','data'):
                with self.assertRaises(ar.RewriteError):match(fixture(),overrides={BEGIN+index*4:kind})
            for word in (0xD4000001,0x94000000,0xD4200000):
                values=fixture();values[BEGIN//4+index]=word
                self.assertIsNone(match(values))
        for index,bit in ((0,29),(0,31),(1,31),(2,15),(2,30),(3,29),(3,31),(4,12),(4,31),
                          (5,31),(6,5),(8,15),(8,30),(9,31),(9,5),(10,5),(11,19),(11,24),
                          (11,5),(13,8),(14,16),(15,19),(15,24),(16,10),(16,30),(17,31),(18,31),(19,5)):
            values=fixture();values[BEGIN//4+index]^=1<<bit
            self.assertIsNone(match(values),(index,bit))
        logical=(8,9,10,11,12,19)
        for role in logical:
            for other in (*[value for value in logical if value!=role],18,29,30,31):
                self.assertIsNone(match(fixture({role:other})),(role,other))

    def test_external_branches_require_same_selected_nonfatal_outside_target(self):
        for index in (12,15):
            values=fixture();pc=BEGIN+index*4
            values[BEGIN//4+index]=(ar.branch(pc,END) if index==12 else
                0x3700000B|(((END-pc)//4)&0x3FFF)<<5)
            self.assertIsNone(match(values))
        for target in (BEGIN,HEAD,END-4,0x1000):
            values=fixture();values[BEGIN//4+12]=ar.branch(BEGIN+48,target)
            values[BEGIN//4+15]=0x3700000B|(((target-BEGIN-60)//4)&0x3FFF)<<5
            self.assertIsNone(match(values))
        values=fixture();values[EXIT//4]=0xD4200000;self.assertIsNone(match(values))

    def test_actual_cpu_signed_clamp_refresh_release_and_full_state(self):
        cases=((5,5,2,10,10,0,None),(5,1,2,10,5,0,None),(5,1,2,10,10,0,None),
               (5,5,7,10,10,0,None),(5,5,5,10,10,0,None),(5,5,2,10,10,2,None),
               (5,5,2,10,7,1,7),(0xFFFFFFFF,0xFFFFFFFF,1,10,10,0,None),
               (0x7FFFFFFF,0x7FFFFFFF,1,0x7FFFFFFF,0x7FFFFFFF,0,None),
               (0x80000000,0x80000000,0xFFFFFFFF,0x80000000,0x80000000,0,None),
               (0xFFFFFFFF,0xFFFFFFFF,0x80000000,0x7FFFFFFF,0x7FFFFFFF,0,None))
        for rename in (None,{8:0,9:1,10:2,11:3,12:4,19:5}):
            rename=rename or {};roles=tuple(rename.get(role,role) for role in (8,9,10,11,12,19))
            values=fixture(rename);image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,END,EXIT,SLOW))
            for initial,expected,step,limit,reload_limit,failures,competitor in cases:
                with self.subTest(rename=rename,case=(initial,expected,step,limit,failures,competitor)):
                    cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base,cell=0x100000,0x400100
                    cpu.mem_map(base,4096);cpu.mem_map(0x400000,4096);cpu.mem_write(base,image.bytes)
                    cpu.mem_write(base+0x100,raw((0xD5033F5F,ar.branch(base+0x104,base+BEGIN+32))))
                    payload=bytearray([0xA5]*56);struct.pack_into('<I',payload,16,initial);struct.pack_into('<I',payload,32,reload_limit)
                    cpu.mem_write(cell-16,bytes(payload))
                    before=[0xFEDCBA9800000100+i*0x101 for i in range(31)]
                    for register,value in ((roles[0],expected),(roles[1],step),(roles[3],limit)):before[register]=0xFEED000000000000|value
                    before[roles[5]]=cell
                    want,memory,flags,counts,clamps,outcome=reference(before,roles,initial,reload_limit,failures,competitor)
                    vectors=[int.from_bytes(bytes((i+j)%256 for j in range(16)),'little') for i in range(32)]
                    for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
                    for i,value in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
                    cpu.reg_write(uc.UC_ARM64_REG_SP,0x200000);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xF0000000)
                    observed=dict(loads=0,stores=0,clears=0,reloads=0,writes=0);seen=[];state=dict(detour=False,outcome=None)
                    def code(machine,pc,size,_):
                        at=pc-base
                        if at in (END,SLOW):state['outcome']='complete' if at==END else 'slow';machine.emu_stop()
                        elif at==HEAD:observed['loads']+=1
                        elif at==BEGIN+16:seen.append((machine.reg_read(uc.UC_ARM64_REG_NZCV),None))
                        elif at==BEGIN+20:seen[-1]=(seen[-1][0],machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{roles[1]}')))
                        elif at==BEGIN+32:
                            if state['detour']:state['detour']=False
                            else:
                                observed['stores']+=1
                                if observed['stores']<=failures:
                                    if competitor is not None:machine.mem_write(cell,struct.pack('<I',competitor))
                                    state['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,base+0x100)
                        elif at==BEGIN+36:
                            if machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{roles[4]}'))==0:observed['writes']+=1
                        elif at==BEGIN+52:observed['clears']+=1
                        elif at==BEGIN+64:observed['reloads']+=1
                    cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=2000)
                    self.assertEqual(outcome,state['outcome']);self.assertEqual(counts,observed);self.assertEqual(clamps,seen)
                    self.assertEqual(want,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)])
                    self.assertEqual(vectors,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)])
                    self.assertEqual((0x200000,flags),(cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)))
                    struct.pack_into('<I',payload,16,memory);self.assertEqual(bytes(payload),bytes(cpu.mem_read(cell-16,56)))


if __name__=='__main__':unittest.main()
