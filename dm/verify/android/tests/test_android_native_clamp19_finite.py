"""Seven authored literal reloads in one fixed19-word native CAS schedule."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'dm/verify/android/tests')]
import android_rewrite as ar
import test_android_native_limit_clamp as old
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,HEAD,END,EXIT,SLOW=16,24,92,104,108
OFFSETS=(0x40,0xF8,0x1D8,0x1F0,0x240,0x548,0xC90)
WORDS=(0x0B09010A,0x6B0B015F,0x885F7E6A,0x4B08016C,0x1A89C189,
       0x6B08015F,0x540000C1,0x0B08012B,0x880CFE6B,0x3500008C,
       0x5280002B,0x14000003,0xD5033F5F,0x2A1F03EB,0x3700010B,
       0xB941D9AB,0x6B0A017F,0x2A0A03E8,0x54FFFDC1)
FIELDS=((0,5,16),(5,16),(0,5),(0,5,16),(0,5,16),(5,16),(),(0,5,16),(0,5,16),
        (0,),(0,),(),(),(0,16),(0,),(0,5),(5,16),(0,16),())
raw=old.raw
def fixture(offset=0x1D8,rename=None):
    rename=rename or {};block=list(WORDS)
    block[15]=0xB9400000|(offset//4<<10)|(13<<5)|11
    for index,fields in enumerate(FIELDS):
        original=block[index]
        for shift in fields:
            role=original>>shift&31
            if role!=31:block[index]=block[index]&~(31<<shift)|rename.get(role,role)<<shift
    expected=rename.get(8,8);tail=0x36F80000|(((END-EXIT)//4)&0x3FFF)<<5|expected
    return [ar.branch(0,BEGIN),0xD503201F,0xD503201F,ar.branch(12,BEGIN)]+block+[
        0xD65F03C0,0xD503201F,0xD503201F,tail,0xD65F03C0,0xD503201F,0xD503201F]
def match(values,missing=(),overrides=None):return old.match(values,missing,overrides)
def plan(values,entries=(0,BEGIN,END,EXIT,SLOW),overrides=None):return old.plan(values,entries,overrides)

class Native19FiniteClampTests(unittest.TestCase):
    def test_all_seven_exact_literals_role_renaming_and_native_bytes(self):
        for offset in OFFSETS:
            for rename in (None,{9:21,19:20,13:9},{8:0,9:1,10:2,11:3,12:4,19:5,13:6}):
                values=fixture(offset,rename)
                self.assertEqual((set(range(BEGIN,END,4)),BEGIN,{HEAD}),match(values))
                self.assertEqual((),plan(values))
                image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,END,EXIT,SLOW))
                self.assertEqual(raw(values),image.bytes);self.assertFalse(image.sites);self.assertFalse(image.fixups)

    def test_unobserved_literals_aliases_reserved_roles_and_old20_schedule_unchanged(self):
        self.assertIsNotNone(match(old.fixture()))
        for offset in (0,4,16,0x18,0x1C,0x3C,0x44,0x70,0x168,0x180,0x1D4,0x1DC,0xC8C,0xC94,0xFFC,0x3FFC):
            self.assertIsNone(match(fixture(offset)),hex(offset))
        for role in (8,9,10,11,12,19,13):
            for collision in (*[r for r in (8,9,10,11,12,19,13) if r!=role],18,29,30,31):
                self.assertIsNone(match(fixture(rename={role:collision})))
        # Original twenty-word malformed displacement/width tests retain their
        # exact shape and expectation. A new nineteen-word row cannot match it.
        values=old.fixture();values[BEGIN//4+16]^=1<<10;self.assertIsNone(match(values))
        values=old.fixture();values[BEGIN//4+2]^=1<<30;self.assertIsNone(match(values))

    def test_all_interiors_all_origin_types_raw_edges_missing_kinds_and_fatal_refuse(self):
        for offset in OFFSETS:
            for pc in range(BEGIN,END,4):
                self.assertIsNone(match(fixture(offset),missing=(pc,)))
                for kind in ('x18','parameter','parameter_tail','gate','profile','data','table','tls'):
                    with self.assertRaises(ar.RewriteError):match(fixture(offset),overrides={pc:kind})
                values=fixture(offset);values[pc//4]=0xD4200000;self.assertIsNone(match(values))
                if pc==BEGIN:continue
                for origin in ('metadata','materialized','table','checked-call'):
                    with self.subTest(offset=offset,pc=pc,origin=origin),self.assertRaises(ar.RewriteError):
                        plan(fixture(offset),(0,BEGIN,END,EXIT,SLOW,pc))
                values=fixture(offset);values[1]=ar.branch(4,pc)
                with self.assertRaises(ar.RewriteError):plan(values)

    def test_exact_join_retry_flags_width_release_and_selected_external_exit(self):
        for offset in OFFSETS:
            for index,bit in ((0,29),(0,31),(1,31),(2,15),(2,30),(3,29),(4,12),(4,31),(5,31),
                              (6,5),(7,31),(8,15),(8,30),(9,5),(9,31),(10,5),(11,0),(12,8),
                              (13,16),(14,24),(14,19),(15,30),(16,31),(17,31),(18,5)):
                values=fixture(offset);values[BEGIN//4+index]^=1<<bit;self.assertIsNone(match(values),(offset,index,bit))
            for target in (BEGIN,HEAD,END-4,0x1000):
                values=fixture(offset);at=BEGIN+56
                values[BEGIN//4+14]=0x3700000B|(((target-at)//4)&0x3FFF)<<5
                self.assertIsNone(match(values))
            for pc in (END,EXIT):
                self.assertIsNone(match(fixture(offset),missing=(pc,)))
                values=fixture(offset);values[pc//4]=0xD4200000;self.assertIsNone(match(values))
            for pc in range(BEGIN,END,4):
                for word in (0xD4000001,0xD61F0200,0xD63F0200,0xD65F03C0):
                    values=fixture(offset);values[pc//4]=word
                    try:value=match(values)
                    except ar.RewriteError:continue
                    self.assertIsNone(value)

    def test_cpu_all_literals_original_payload_read_and_full_state(self):
        cases=((5,5,2,10,10,0,None),(5,1,2,10,5,0,None),(5,1,2,10,10,0,None),
               (5,5,7,10,10,0,None),(5,5,2,10,10,2,None),(5,5,2,10,7,1,7),
               (0xFFFFFFFF,0xFFFFFFFF,1,10,10,0,None),
               (0x7FFFFFFF,0x7FFFFFFF,1,0x7FFFFFFF,0x7FFFFFFF,0,None),
               (0x80000000,0x80000000,0xFFFFFFFF,0x80000000,0x80000000,0,None))
        for offset in OFFSETS:
            for rename in (None,{9:21,19:20,13:9},{8:0,9:1,10:2,11:3,12:4,19:5,13:6}):
                rename=rename or {};roles=tuple(rename.get(role,role) for role in (8,9,10,11,12,19));payload_register=rename.get(13,13)
                image=ar.rewrite(raw(fixture(offset,rename)),entry_offsets=(0,BEGIN,END,EXIT,SLOW))
                for initial,expected,step,limit,reload_limit,failures,competitor in cases:
                    with self.subTest(offset=offset,rename=rename,case=(initial,expected,step,limit,failures,competitor)):
                        cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base,cell,payload=0x100000,0x400100,0x500000
                        for address in (base,0x400000,payload):cpu.mem_map(address,4096)
                        cpu.mem_write(base,image.bytes);cpu.mem_write(base+0x100,raw((0xD5033F5F,ar.branch(base+0x104,base+BEGIN+32))))
                        memory=bytearray([0xA5]*56);struct.pack_into('<I',memory,16,initial);struct.pack_into('<I',memory,32,0xBAD0BAD0)
                        cpu.mem_write(cell-16,bytes(memory));payload_bytes=bytearray([0x5A]*4096);struct.pack_into('<I',payload_bytes,offset,reload_limit)
                        cpu.mem_write(payload,bytes(payload_bytes))
                        before=[0xFEDCBA9800000100+i*0x101 for i in range(31)]
                        for reg,val in ((roles[0],expected),(roles[1],step),(roles[3],limit)):before[reg]=0xFEED000000000000|val
                        before[roles[5]]=cell;before[payload_register]=payload
                        want,value,flags,counts,clamps,outcome=old.reference(before,roles,initial,reload_limit,failures,competitor)
                        vectors=[int.from_bytes(bytes((i+j)%256 for j in range(16)),'little') for i in range(32)]
                        for i,val in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),val)
                        for i,val in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),val)
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
                            elif at==BEGIN+48:observed['clears']+=1
                            elif at==BEGIN+60:observed['reloads']+=1
                        cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=2000)
                        self.assertEqual((outcome,counts,clamps),(state['outcome'],observed,seen))
                        self.assertEqual(want,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)])
                        self.assertEqual(vectors,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)])
                        self.assertEqual((0x200000,flags),(cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)))
                        struct.pack_into('<I',memory,16,value);self.assertEqual(bytes(memory),bytes(cpu.mem_read(cell-16,56)))
                        self.assertEqual(bytes(payload_bytes),bytes(cpu.mem_read(payload,4096)))

if __name__=='__main__':unittest.main()
