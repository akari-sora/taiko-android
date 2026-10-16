"""A native retry reloads both addresses from the actual fixed FP cell slot."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc

BEGIN,HEAD,JOIN,END,ACQUIRED=16,20,56,60,64
TEMPLATE=(0xF9400FA8,0x885FFD08,0x350000C8,0xF9400FAA,0x52800029,
          0x880B7D49,0x35FFFF4B,0x14000003,0x2A1F03E9,0xD5033F5F,0x37000049)
FIELDS=((0,),(0,5),(0,),(0,),(0,),(0,5,16),(0,),(),(0,),(),(0,))
COMPARE_TEMPLATE=(0xF9400FA8,0x885F7D08,0x7100051F,0x540000C1,0xF9400FA9,
                  0x5280004A,0x880B7D2A,0x35FFFF2B,0x14000002,0xD5033F5F,0x34000048)
COMPARE_FIELDS=((0,),(0,5),(5,),(),(0,),(0,),(0,5,16),(0,),(),(),(0,))
DIRECT_TEMPLATE=(0xF9400FA8,0x885F7D08,0x350000C8,0xF9400FA8,0x52800029,
                 0x880A7D09,0x35FFFF4A,0x14000005,0xD5033F5F)
DIRECT_FIELDS=((0,),(0,5),(0,),(0,),(0,),(0,5,16),(0,),(),())


def fixture(rename=None,acquire=True,compare=False,direct=False):
    template=DIRECT_TEMPLATE if direct else COMPARE_TEMPLATE if compare else TEMPLATE
    block=list(template)
    if not compare and not direct and not acquire:block[1]^=0x8000
    for index,fields in enumerate(DIRECT_FIELDS if direct else COMPARE_FIELDS if compare else FIELDS):
        for shift in fields:
            role=template[index]>>shift&31
            if rename:block[index]=block[index]&~(31<<shift)|rename.get(role,role)<<shift
    if direct:return [ar.branch(0,BEGIN),0xD503201F,0xD503201F,ar.branch(12,BEGIN)]+block+[
        0xD65F03C0,0xD503201F,0xD503201F,0xD65F03C0,0xD503201F]
    return [ar.branch(0,BEGIN),0xD503201F,0xD503201F,ar.branch(12,BEGIN)]+block+[
        0xD65F03C0,0xD65F03C0,0xD503201F]


def raw(values):return struct.pack('<'+'I'*len(values),*values)


def decoded(values):
    ops=[ar.decode(value,index*4) for index,value in enumerate(values)]
    return ops,{ins.address:ar.site_kind(ins) for ins in ops}


def match(values,overrides=None):
    ops,kinds=decoded(values);kinds.update(overrides or {})
    return ar.android_exclusive.native_conditional_refresh(ops[HEAD//4],{ins.address:ins for ins in ops},kinds,ar)


def plan(values,roots=(0,BEGIN,END,ACQUIRED),overrides=None):
    ops,kinds=decoded(values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ops,kinds,roots,ar)


class RawMachine:
    """Independent raw words and monitor address; no planner-derived edges."""
    def __init__(self,values,initial=0,other=0,slots=(),failures=0,competing_value=None,*,end=END,reload_offset=12):
        self.values=values;self.initial=initial;self.other=other;self.end=end;self.reload_offset=reload_offset
        self.slots=slots;self.failures=failures;self.competing_value=competing_value
        self.x=[0xFEDCBA9800000100+i for i in range(31)];self.x[29]=0x800000
        self.flags=0xB0000000;self.sp=0x900000;self.q=tuple(range(32))
        self.memory={0x800018:0x400000,0x400000:initial,0x401000:other}
        self.loads=self.slot_reads=self.stores=self.clears=self.writes=0
    @staticmethod
    def signed(value,bits):return value-(1<<bits) if value&(1<<(bits-1)) else value
    def run(self):
        pc,monitor=0,None
        for _ in range(200):
            if pc in (self.end,ACQUIRED):
                assert monitor is None
                return 'acquired' if pc==ACQUIRED else 'slow'
            word=self.values[pc//4];rt,rn=word&31,word>>5&31;next_pc=pc+4
            if word&0xFFC00000==0xF9400000:
                if pc==BEGIN+self.reload_offset and self.loads<=len(self.slots):
                    self.memory[0x800018]=self.slots[self.loads-1]
                self.slot_reads+=1;self.x[rt]=self.memory[self.x[rn]+(word>>10&4095)*8]
            elif word&0xFFFFFC00 in (0x885FFC00,0x885F7C00):
                self.loads+=1;monitor=self.x[rn];self.x[rt]=self.memory[monitor]&0xFFFFFFFF
            elif word&0xFFE0FC00==0x88007C00:
                self.stores+=1;address=self.x[rn]
                success=monitor==address and self.stores>self.failures
                if success:self.memory[address]=self.x[rt]&0xFFFFFFFF;self.writes+=1
                elif self.competing_value is not None:self.memory[address]=self.competing_value
                self.x[word>>16&31]=0 if success else 1;monitor=None
            elif word==0xD5033F5F:monitor=None;self.clears+=1
            elif word&0xFFFFFC00==0x52800000:self.x[rt]=(word>>5&65535)
            elif word&0xFFE0FFE0==0x2A0003E0:self.x[rt]=0 if word>>16&31==31 else self.x[word>>16&31]&0xFFFFFFFF
            elif word&0xFFC0001F==0x7100001F:
                left,right=self.x[rn]&0xFFFFFFFF,word>>10&4095
                value=(left-right)&0xFFFFFFFF
                overflow=bool((left^right)&(left^value)&0x80000000)
                self.flags=((bool(value&0x80000000)<<3)|((value==0)<<2)|((left>=right)<<1)|overflow)<<28
            elif word&0xFF000010==0x54000000:
                assert word&15==1
                if not self.flags&0x40000000:next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(word&0x1000000):next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0x7E000000==0x36000000:
                bit=(word>>31)*32+(word>>19&31)
                if bool(self.x[rt]&(1<<bit))==bool(word&0x1000000):next_pc=pc+self.signed(word>>5&0x3FFF,14)*4
            elif word&0xFC000000==0x14000000:next_pc=pc+self.signed(word&0x3FFFFFF,26)*4
            else:raise AssertionError(f'unmodeled {pc:x}: {word:08x}')
            pc=next_pc
        raise AssertionError('native FP fixture did not terminate')


class NativeFpPreloadRefreshTests(unittest.TestCase):
    def test_native_union_and_injective_ordinary_roles_keep_fixed_fp(self):
        for rename in (None,{8:0,9:1,10:2,11:3},{8:16,9:17,10:27,11:28}):
            with self.subTest(rename=rename):
                values=fixture(rename);source=raw(values)
                self.assertEqual(match(values),(set(range(BEGIN,JOIN,4)),BEGIN,{HEAD}))
                self.assertEqual(plan(values),())
                image=ar.rewrite(source,entry_offsets=(0,BEGIN,END,ACQUIRED))
                self.assertEqual(image.bytes,source)
                self.assertEqual((image.sites,image.fixups,image.gates),((),(),()))

    def test_plain_load_variant_and_closed_monitor_join_are_preserved(self):
        for acquire in (True,False):
            for join_word in (0x37000049,0x37080049,0xB7000049):
                values=fixture(acquire=acquire);values[JOIN//4]=join_word
                with self.subTest(acquire=acquire,join=hex(join_word)):
                    self.assertEqual(match(values),(set(range(BEGIN,JOIN,4)),BEGIN,{HEAD}))
                    image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,JOIN,END,ACQUIRED))
                    self.assertEqual(image.bytes,raw(values))
                    self.assertFalse(image.sites)

    def test_every_other_metadata_root_and_external_edge_is_rejected(self):
        for pc in range(BEGIN+4,JOIN,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):plan(fixture(),roots=(0,BEGIN,END,ACQUIRED,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(values)

    def test_exact_slot_width_order_retries_testbit_and_no_host_calls(self):
        changes=((0,0xF9400BA8),(0,0xF9400F88),(0,0xB9400FA8),(1,0x485FFD08),
                 (1,0xC85FFD08),(1,0x885FFD28),(2,0x340000C8),(2,0x350000E8),
                 (3,0xF94013AA),(3,0xF9400F8A),(3,0xB9400FAA),(4,0x52800049),
                 (4,0xD2800029),(5,0x880BFD49),(5,0xC80B7D49),(5,0x880B7D09),
                 (6,0x35FFFF6B),(6,0xB5FFFF4B),(6,0x34FFFF4B),(7,0x14000002),
                 (8,0x2A0803E9),(9,0xD503201F),(9,0xD5033B5F))
        for slot,value in changes:
            values=fixture();values[BEGIN//4+slot]=value
            with self.subTest(slot=slot,word=hex(value)):self.assertIsNone(match(values))
        for slot in range(len(TEMPLATE)-1):
            for word in (0xD4000001,0x94000000,0x7100051F):
                values=fixture();values[BEGIN//4+slot]=word
                with self.subTest(slot=slot,gate_or_flags=hex(word)):self.assertIsNone(match(values))
            for kind in ('x18','gate','parameter','parameter_tail'):
                with self.subTest(slot=slot,rewrite=kind),self.assertRaises(ar.RewriteError):match(fixture(),{BEGIN+slot*4:kind})
            ops,kinds=decoded(fixture());by_pc={ins.address:ins for ins in ops if ins.address!=BEGIN+slot*4}
            self.assertIsNone(ar.android_exclusive.native_conditional_refresh(ops[HEAD//4],by_pc,kinds,ar))
        for role in (8,9,10,11):
            for forbidden in (18,29,30,31,*({8,9,10,11}-{role})):
                with self.subTest(role=role,forbidden=forbidden):self.assertIsNone(match(fixture({role:forbidden})))

    def test_compare_preload_exact_shape_and_all_entry_boundaries(self):
        for rename in (None,{8:0,9:1,10:2,11:3}):
            values=fixture(rename=rename,compare=True)
            self.assertEqual(match(values),(set(range(BEGIN,JOIN,4)),BEGIN,{HEAD}))
            image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,JOIN,END,ACQUIRED))
            self.assertEqual(image.bytes,raw(values));self.assertFalse(image.sites)
        for pc in range(BEGIN+4,JOIN,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):plan(fixture(compare=True),roots=(0,BEGIN,JOIN,END,ACQUIRED,pc))
            values=fixture(compare=True);values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(values)
        for slot,word in ((0,0xF9400BA8),(1,0x885FFD08),(2,0x7100091F),(2,0xF100051F),
                          (3,0x540000C0),(3,0x540000A1),(4,0xF94013A9),(4,0xF9400F89),
                          (5,0x5280002A),(6,0x880BFD2A),(7,0x35FFFF0B),(8,0x14000003),
                          (9,0xD503201F)):
            values=fixture(compare=True);values[BEGIN//4+slot]=word
            with self.subTest(slot=slot,word=hex(word)):self.assertIsNone(match(values))

    def test_direct_success_preload_exact_row_and_closed_exits(self):
        for rename in (None,{8:16,9:17,10:27}):
            values=fixture(rename=rename,direct=True)
            self.assertEqual(match(values),(set(range(BEGIN,52,4)),BEGIN,{HEAD}))
            image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,52,ACQUIRED))
            self.assertEqual(image.bytes,raw(values));self.assertFalse(image.sites)
        for pc in range(BEGIN+4,52,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):plan(fixture(direct=True),roots=(0,BEGIN,52,ACQUIRED,pc))
        for slot,word in ((0,0xF9400BA8),(1,0x885FFD08),(2,0x340000C8),(3,0xF9400FA9),
                          (4,0x52800049),(5,0x880AFD09),(6,0x35FFFF2A),(8,0xD503201F)):
            values=fixture(direct=True);values[BEGIN//4+slot]=word
            with self.subTest(slot=slot):self.assertIsNone(match(values))
        for word in (ar.branch(BEGIN+28,BEGIN),ar.branch(BEGIN+28,0x1000),0x94000005):
            values=fixture(direct=True);values[(BEGIN+28)//4]=word
            self.assertIsNone(match(values))

    def test_unicorn_and_independent_model_preserve_state_with_changing_slot(self):
        zero_cases=((0,0,(),0,None),(5,0,(),0,None),(0,0,(),2,None),
                    (0,0,(0x401000,),0,None),(0,5,(0x401000,),0,None),
                    (0,0,(0x401000,0x400000),0,None),(0,0,(),1,7))
        compare_cases=((1,0,(),0,None),(0,0,(),0,None),(2,0,(),0,None),
                       (1,1,(0x401000,),0,None),(1,3,(0x401000,),0,None),
                       (1,0,(),2,None),(1,0,(),1,3))
        cases=[(mode,*case) for mode in ('acquire','plain','direct') for case in zero_cases]
        cases += [('compare',*case) for case in compare_cases]
        for mode,initial,other,slots,failures,competitor in cases:
            with self.subTest(mode=mode,initial=initial,other=other,slots=slots,failures=failures):
                compare,direct=mode=='compare',mode=='direct'
                values=fixture(acquire=mode!='plain',compare=compare,direct=direct)
                end=52 if direct else END;reload_offset=16 if compare else 12
                store_offset=24 if compare else 20;clear_offset=32 if direct else 36
                store_base=9 if compare else 8 if direct else 10
                image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN,end,ACQUIRED))
                model=RawMachine(values,initial,other,slots,failures,competitor,end=end,reload_offset=reload_offset)
                outcome=model.run()
                base=0x100000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                for address in (base,0x400000,0x401000,0x800000,0x900000):cpu.mem_map(address,4096)
                cpu.mem_write(base,image.bytes)
                cpu.mem_write(base+0x100,raw([0xD5033F5F,ar.branch(base+0x104,base+BEGIN+store_offset)]))
                cpu.mem_write(0x800018,struct.pack('<Q',0x400000))
                cpu.mem_write(0x400000,struct.pack('<II',initial,0xAABBCCDD));cpu.mem_write(0x401000,struct.pack('<II',other,0x11223344))
                before=[0xFEDCBA9800000100+i for i in range(31)];before[29]=0x800000
                for index,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{index}'),value)
                for index,value in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{index}'),value)
                cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,model.flags)
                observed=dict(loads=0,stores=0,slot_reads=0,clears=0,detour=False,outcome=None)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at in (end,ACQUIRED):observed['outcome']='acquired' if at==ACQUIRED else 'slow';machine.emu_stop()
                    elif at in (BEGIN,BEGIN+reload_offset):
                        if at==BEGIN+reload_offset and observed['loads']<=len(slots):machine.mem_write(0x800018,struct.pack('<Q',slots[observed['loads']-1]))
                        observed['slot_reads']+=1
                    elif at==HEAD:observed['loads']+=1
                    elif at==BEGIN+clear_offset:observed['clears']+=1
                    elif at==BEGIN+store_offset:
                        if observed['detour']:observed['detour']=False
                        else:
                            observed['stores']+=1
                            if observed['stores']<=failures:
                                address=machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{store_base}'))
                                if competitor is not None:machine.mem_write(address,struct.pack('<I',competitor))
                                observed['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,base+0x100)
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image.bytes),count=500)
                self.assertEqual(observed['outcome'],outcome)
                self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                for address,value in model.memory.items():
                    width=8 if address==0x800018 else 4
                    self.assertEqual(int.from_bytes(cpu.mem_read(address,width),'little'),value)
                self.assertEqual(bytes(cpu.mem_read(0x400004,4)),struct.pack('<I',0xAABBCCDD))
                self.assertEqual(bytes(cpu.mem_read(0x401004,4)),struct.pack('<I',0x11223344))
                self.assertEqual(tuple(observed[k] for k in ('loads','stores','slot_reads','clears')),
                                 (model.loads,model.stores,model.slot_reads,model.clears))


if __name__=='__main__':unittest.main()
