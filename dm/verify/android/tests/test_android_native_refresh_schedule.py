"""A distinct native register schedule keeps every original CAS/refresh effect."""
import struct,unittest
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
# Independent decoded model copied unchanged from verified parent037/040 tests.
FIELDS = (
    (), (0, 5, 16), (0, 5, 10), (0, 5, 16), (0, 5, 16),
    (0, 5), (0, 5, 16), (0, 5), (0, 5), (0, 5, 16),
    (), (0, 5), (0,), (0, 5, 16), (0, 5),
    (0, 5, 16), (0, 5, 16), (0, 5, 16), (0, 5), (0, 5, 16),
    (), (0, 5, 16), (0,), (0,), (),
    (0, 5, 16), (), (0, 5), (0, 5, 16), (),
    (0, 5, 16), (0, 5), (0, 5), (0, 5, 16), (0, 5, 16),
    (0, 5, 16), (0, 5), (0, 5, 16), (), (0, 5, 16), (0,),
)

def decode(values, base=0):
    instructions = [ar.decode(value, base + index * 4) for index, value in enumerate(values)]
    return instructions, {ins.address: ins for ins in instructions}, {ins.address: ar.site_kind(ins) for ins in instructions}

class RefreshMachine:
    """Execute public ARM operations with explicit monitor contention.

    The actor can publish a new descriptor after the first inner update or
    invalidate one reservation. Actor writes are counted separately from CAS.
    No recognizer result controls execution or forces a branch outcome.
    """
    def __init__(self, source, *, inner=False, fail_inner=0, fail_outer=0,
                 mismatch_inner=False, mismatch_outer=False):
        values = struct.unpack('<42I', source)
        _, self.code, _ = decode(values)
        self.x = [0x900000 + number * 256 for number in range(31)]
        self.x[0], self.x[8], self.x[9], self.x[10] = 0x3000, 0x1000, 0x5000, 0x2000
        self.memory = {0x3038: 0x4000, 0x3040: 0, 0x4008: 0 if inner else 1,
                       0x5000: 0x1000, 0x4000: 0xAABB, 0x4010: 0xCCDD,
                       0x4FF8: 0x1122, 0x5008: 0x3344}
        self.fail_inner, self.fail_outer = fail_inner, fail_outer
        self.mismatch_inner, self.mismatch_outer = mismatch_inner, mismatch_outer
        self.monitor, self.flags, self.sp = None, 0xA0000000, 0x800000
        self.trace, self.events = [], []

    def read(self, ins, operand):
        if operand.type == 2:
            return operand.imm
        name = ins.reg_name(operand.reg)
        if name in ('wzr', 'xzr'):
            return 0
        value = self.x[int(name[1:])]
        return value & ((1 << (32 if name.startswith('w') else 64)) - 1)

    def write(self, ins, operand, value):
        name = ins.reg_name(operand.reg)
        if name not in ('wzr', 'xzr'):
            self.x[int(name[1:])] = value & ((1 << (32 if name.startswith('w') else 64)) - 1)

    def address(self, ins, operand):
        name = ins.reg_name(operand.mem.base)
        return self.x[int(name[1:])] + operand.mem.disp

    def run(self):
        pc = 4
        for _ in range(300):
            if pc == 164:
                return
            ins, following = self.code[pc], pc + 4
            self.trace.append(pc)
            op = ins.operands
            name = ins.mnemonic
            if name == 'mov':
                self.write(ins, op[0], self.read(ins, op[1]))
            elif name in ('and', 'orr', 'bic', 'add'):
                left, right = self.read(ins, op[1]), self.read(ins, op[2])
                value = {'and': lambda: left & right, 'orr': lambda: left | right,
                         'bic': lambda: left & ~right, 'add': lambda: left + right}[name]()
                self.write(ins, op[0], value)
            elif name == 'cmp':
                left, right = self.read(ins, op[0]), self.read(ins, op[1])
                bits = 32 if ins.reg_name(op[0].reg).startswith('w') else 64
                mask, sign = (1 << bits) - 1, 1 << (bits - 1)
                value = (left - right) & mask
                overflow = bool((left ^ right) & (left ^ value) & sign)
                self.flags = ((bool(value & sign) << 31) | ((value == 0) << 30) |
                              ((left >= right) << 29) | (overflow << 28))
            elif name == 'csel':
                self.write(ins, op[0], self.read(ins, op[1] if not self.flags & (1 << 30) else op[2]))
            elif name == 'ldp':
                address = self.address(ins, op[2])
                self.write(ins, op[0], self.memory[address])
                self.write(ins, op[1], self.memory[address + 8])
            elif name in ('ldr', 'ldar', 'ldxr', 'ldaxr'):
                address = self.address(ins, op[1])
                if name in ('ldxr', 'ldaxr'):
                    if pc == 72 and self.mismatch_inner:
                        self.memory[address], self.memory[0x4008] = 0x1008, 1
                        self.mismatch_inner = False
                        self.events.append(('actor-inner', address))
                    if pc == 144 and self.mismatch_outer:
                        self.memory[address] = 3
                        self.mismatch_outer = False
                        self.events.append(('actor-outer', address))
                    self.monitor = address
                self.write(ins, op[0], self.memory[address])
            elif name == 'stxr':
                address = self.address(ins, op[2])
                attribute = 'fail_inner' if pc == 84 else 'fail_outer'
                failures = getattr(self, attribute)
                success = self.monitor == address and not failures
                if failures:
                    setattr(self, attribute, failures - 1)
                if success:
                    self.memory[address] = self.read(ins, op[1])
                    self.events.append(('own-store', address))
                    if pc == 84:
                        self.memory[0x4008] = 1
                        self.events.append(('actor-publish', 0x4008))
                self.write(ins, op[0], 0 if success else 1)
                self.monitor = None
            elif name == 'clrex':
                self.monitor = None
            elif name == 'b':
                following = op[0].imm
            elif name == 'b.ne':
                if not self.flags & (1 << 30):
                    following = op[0].imm
            elif name == 'cbnz':
                if self.read(ins, op[0]):
                    following = op[1].imm
            elif name == 'tbnz':
                if self.read(ins, op[0]) & (1 << op[1].imm):
                    following = op[2].imm
            else:
                raise AssertionError(f'unmodeled ARM instruction: {name}')
            pc = following
        raise AssertionError('refresh operation did not reach its selected success continuation')

from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
WORDS=(3573759839, 2852652013, 2839784460, 2316108139, 2852913516, 2432704907, 2852979688, 3370122603, 4181721389, 3943498015, 1426063105, 4181729293, 922747467, 2315977131, 2432697772, 2852913515, 2318205196, 2332819819, 3361701164, 3943170463, 1409286305, 3356327211, 905969549, 1384120360, 335544323, 706675688, 3573759839, 1895825695, 2592870765, 402653157, 2315911594, 2432697774, 2432704908, 2853044554, 2318205293, 2332885322, 3361734029, 3943367103, 1426062145, 3356196234, 905968427)
def words(mapping=None):
    values=[];mapping=mapping or {}
    for word,fields in zip(WORDS,FIELDS):
        v=word
        for shift in fields:
            role=word>>shift&31;v=v&~(31<<shift)|mapping.get(role,role)<<shift
        values.append(v)
    return values+[0xD65F03C0]
def raw(v):return struct.pack('<42I',*v)
def match(v):
    ops,by_pc,kinds=decode(v)
    return ar.android_exclusive.native_conditional_refresh(by_pc[72],by_pc,kinds,ar)
class NativeRefreshScheduleTests(unittest.TestCase):
    def test_source_schedule_and_role_bijection_remain_native(self):
        for mapping in ({},{0:1,8:2,9:3,10:4,11:5,12:6,13:7,14:15}):
            v=words(mapping);self.assertEqual(match(v),(set(range(0,164,4)),4,{72,144}))
            image=ar.rewrite(raw(v),entry_offset=4,entry_offsets=(4,164))
            self.assertEqual(image.bytes,raw(v));self.assertEqual((image.sites,image.fixups),((),()))
    def test_every_nonregister_bit_and_every_nonentry_are_guarded(self):
        for i,word in enumerate(WORDS):
            mask=sum(31<<shift for shift in FIELDS[i])
            for bit in range(32):
                if mask>>bit&1:continue
                v=words();v[i]^=1<<bit
                try:r=match(v)
                except ar.RewriteError:r=None
                self.assertIsNone(r,(i,bit))
        for pc in set(range(0,164,4))-{4}:
            ops,by_pc,kinds=decode(words())
            with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,kinds,(4,164,pc),ar)
        for register in (9,18,29,30,31):self.assertIsNone(match(words({8:register})))
    def test_original_cpu_matches_shared_independent_raw_instruction_model(self):
        for settings in ({},{'inner':True},{'inner':True,'fail_inner':2},{'fail_outer':2},
                         {'inner':True,'mismatch_inner':True},{'mismatch_outer':True}):
            with self.subTest(settings=settings):
                model=RefreshMachine(raw(words()),**settings)
                before=model.x.copy();memory=model.memory.copy();model.run()
                base,stub=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                for address in (base,stub,0x3000,0x4000,0x5000):cpu.mem_map(address,4096)
                cpu.mem_write(base,raw(words()))
                for i,v in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),v)
                cpu.reg_write(uc.UC_ARM64_REG_SP,0x800000);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xA0000000)
                for address,v in memory.items():cpu.mem_write(address,struct.pack('<Q',v))
                state=dict(detour=False,inner=settings.get('fail_inner',0),outer=settings.get('fail_outer',0),
                           mismatch_inner=settings.get('mismatch_inner',False),mismatch_outer=settings.get('mismatch_outer',False),done=False)
                def code(machine,pc,size,_):
                    at=pc-base
                    if at==164:state['done']=True;machine.emu_stop();return
                    if at==72 and state['mismatch_inner']:
                        machine.mem_write(0x5000,struct.pack('<Q',0x1008));machine.mem_write(0x4008,struct.pack('<Q',1));state['mismatch_inner']=False
                    elif at==144 and state['mismatch_outer']:
                        address=machine.reg_read(uc.UC_ARM64_REG_X12);machine.mem_write(address,struct.pack('<Q',3));state['mismatch_outer']=False
                    elif at in (84,156):
                        kind='inner' if at==84 else 'outer'
                        if state['detour']:state['detour']=False
                        elif state[kind]:
                            state[kind]-=1;state['detour']=True
                            machine.mem_write(stub,struct.pack('<2I',0xD5033F5F,ar.branch(stub+4,pc)));machine.reg_write(uc.UC_ARM64_REG_PC,stub)
                    elif at==88 and machine.reg_read(uc.UC_ARM64_REG_W13)==0:machine.mem_write(0x4008,struct.pack('<Q',1))
                cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base+4,base+168,count=3000)
                self.assertTrue(state['done']);self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags))
                for address,v in model.memory.items():self.assertEqual(struct.unpack('<Q',cpu.mem_read(address,8))[0],v)
if __name__=='__main__':unittest.main()
