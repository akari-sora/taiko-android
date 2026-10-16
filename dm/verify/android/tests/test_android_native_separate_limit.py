"""Authored exact separate-base +0x180 clamp payload, no title addresses."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'dm/verify/android/tests')]
import android_rewrite as ar
import test_android_native_limit_clamp as old
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
BEGIN,HEAD,END,EXIT,SLOW=old.BEGIN,old.HEAD,old.END,old.EXIT,old.SLOW
raw=old.raw

def fixture(rename=None):
    rename=rename or {};values=old.fixture(rename)
    values[BEGIN//4+16]=0xB9418000|(rename.get(13,13)<<5)|rename.get(11,11)
    return values
def match(values,missing=(),overrides=None):return old.match(values,missing,overrides)


class NativeSeparateLimitTests(unittest.TestCase):
    def test_only_exact_new_seven_role_row_and_ordinary_entry_is_native(self):
        for rename in (None,{9:20,13:9},{8:0,9:1,10:2,11:3,12:4,19:5,13:6}):
            values=fixture(rename)
            self.assertEqual((set(range(BEGIN,END,4)),BEGIN,{HEAD}),match(values))
            self.assertEqual((),old.plan(values))
            image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,END,EXIT,SLOW))
            self.assertEqual(raw(values),image.bytes);self.assertEqual(((),(),()),(image.sites,image.fixups,image.gates))

    def test_same_base_old_row_remains_exact_and_no_offset_or_role_widening(self):
        self.assertIsNotNone(match(old.fixture()))
        for offset in (0,4,16,0x17C,0x184,0xFFC):
            values=fixture();values[BEGIN//4+16]=0xB9400000|(offset//4<<10)|(13<<5)|11
            self.assertIsNone(match(values),offset)
        for role in (8,9,10,11,12,19,13):
            for collision in (*[r for r in (8,9,10,11,12,19,13) if r!=role],18,29,30,31):
                self.assertIsNone(match(fixture({role:collision})),(role,collision))

    def test_missing_source_rewrites_and_every_nonentry_origin_refuse(self):
        for pc in range(BEGIN,END,4):
            self.assertIsNone(match(fixture(),missing=(pc,)))
            for kind in ('x18','parameter','gate','data'):
                with self.assertRaises(ar.RewriteError):match(fixture(),overrides={pc:kind})
            if pc==BEGIN:continue
            with self.assertRaises(ar.RewriteError):old.plan(fixture(),(0,BEGIN,END,EXIT,SLOW,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.assertRaises(ar.RewriteError):old.plan(values)

    def test_fixed_flags_width_release_joins_and_equal_external_targets_refuse_mutations(self):
        for index,bit in ((0,29),(1,31),(2,15),(2,30),(3,29),(4,12),(4,31),(5,31),
                          (6,5),(8,15),(8,30),(9,31),(10,5),(11,19),(11,24),(13,8),
                          (14,16),(15,19),(15,24),(16,30),(17,31),(18,31),(19,5)):
            values=fixture();values[BEGIN//4+index]^=1<<bit;self.assertIsNone(match(values),(index,bit))
        for index in (12,15):
            values=fixture();at=BEGIN+index*4
            values[BEGIN//4+index]=ar.branch(at,END) if index==12 else 0x3700000B|(((END-at)//4)&0x3FFF)<<5
            self.assertIsNone(match(values))
        values=fixture();values[EXIT//4]=0xD4200000;self.assertIsNone(match(values))

    def test_actual_cpu_reads_separate_payload_and_preserves_state_flags_and_memory(self):
        cases=((5,5,2,10,10,0,None),(5,1,2,10,5,0,None),(5,1,2,10,10,0,None),
               (5,5,7,10,10,0,None),(5,5,2,10,10,2,None),(5,5,2,10,7,1,7),
               (0xFFFFFFFF,0xFFFFFFFF,1,10,10,0,None),
               (0x7FFFFFFF,0x7FFFFFFF,1,0x7FFFFFFF,0x7FFFFFFF,0,None),
               (0x80000000,0x80000000,0xFFFFFFFF,0x80000000,0x80000000,0,None))
        for rename in (None,{9:20,13:9},{8:0,9:1,10:2,11:3,12:4,19:5,13:6}):
            rename=rename or {};roles=tuple(rename.get(role,role) for role in (8,9,10,11,12,19));payload_register=rename.get(13,13)
            image=ar.rewrite(raw(fixture(rename)),entry_offsets=(0,BEGIN,END,EXIT,SLOW))
            for initial,expected,step,limit,reload_limit,failures,competitor in cases:
                with self.subTest(rename=rename,case=(initial,expected,step,limit,failures,competitor)):
                    cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base,cell,payload=0x100000,0x400100,0x500000
                    for address in (base,0x400000,payload):cpu.mem_map(address,4096)
                    cpu.mem_write(base,image.bytes);cpu.mem_write(base+0x100,raw((0xD5033F5F,ar.branch(base+0x104,base+BEGIN+32))))
                    memory=bytearray([0xA5]*56);struct.pack_into('<I',memory,16,initial);struct.pack_into('<I',memory,32,0xBAD0BAD0)
                    cpu.mem_write(cell-16,bytes(memory));payload_bytes=bytearray([0x5A]*512);struct.pack_into('<I',payload_bytes,0x180,reload_limit)
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
                        elif at==BEGIN+52:observed['clears']+=1
                        elif at==BEGIN+64:observed['reloads']+=1
                    cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=2000)
                    self.assertEqual((outcome,counts,clamps),(state['outcome'],observed,seen))
                    self.assertEqual(want,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)])
                    self.assertEqual(vectors,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)])
                    self.assertEqual((0x200000,flags),(cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)))
                    struct.pack_into('<I',memory,16,value);self.assertEqual(bytes(memory),bytes(cpu.mem_read(cell-16,56)))
                    self.assertEqual(bytes(payload_bytes),bytes(cpu.mem_read(payload,512)))


if __name__=='__main__':unittest.main()
