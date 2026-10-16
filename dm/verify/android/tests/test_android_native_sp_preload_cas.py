"""A finite native release CAS refreshes its payload from the existing guest SP."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

BEGIN, END, BUSY, SUCCESS, CALLEE = 16, 56, 56, 60, 64
TEMPLATE = (0xC85F7D09,0xB40000C9,0xD5033F5F,0xF94007E0,0xB50000C9,
            0xC85F7D09,0xB5FFFF89,0xC80AFD00,0x35FFFF6A,0x14000002)
FIELDS = ((0,5),(0,),(),(0,),(0,),(0,5),(0,),(0,5,16),(0,),())


def fixture(rename=None):
    block = list(TEMPLATE)
    for index,shifts in enumerate(FIELDS):
        for shift in shifts:
            role = TEMPLATE[index]>>shift&31
            if rename:
                block[index] = block[index]&~(31<<shift)|rename.get(role,role)<<shift
    # The busy BL is outside the union and may return normally to SUCCESS.
    return [ar.branch(0,BEGIN),0xD503201F,0xD503201F,ar.branch(12,BEGIN)]+block+[
        0x94000000|((CALLEE-BUSY)//4),0xD65F03C0,0xD65F03C0,0xD503201F]


def raw(values):
    return struct.pack('<'+'I'*len(values),*values)


def decode(values):
    instructions = [ar.decode(word,index*4) for index,word in enumerate(values)]
    return instructions,{ins.address:ar.site_kind(ins) for ins in instructions}


def plan(values,roots=(0,BEGIN,BUSY,SUCCESS,CALLEE),overrides=None):
    instructions,kinds = decode(values)
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions,kinds,roots,ar)


class Machine:
    """Independent raw-word execution; reservation failures/competitors are explicit."""
    def __init__(self,values,initial,failures=0,competitor=None,stack_after_failures=()):
        self.values = values
        self.x = [0xAABB000000001000+index for index in range(31)]
        self.x[8],self.x[0] = 0x400000,0x1122334455667788
        self.sp,self.flags = 0x800000,0xB0000000
        self.q = tuple(bytes([index])*16 for index in range(32))
        self.memory = {0x3FFFF8:0xABABABABABABABAB,0x400000:initial,
                       0x400008:0xCDCDCDCDCDCDCDCD,0x800000:0x1111222233334444,
                       0x800008:0x8877665544332211,0x800010:0x5555666677778888}
        self.failures,self.competitor = failures,competitor
        self.stack_after_failures = stack_after_failures
        self.loads = self.stores = self.clears = self.stack_reads = self.writes = 0

    @staticmethod
    def signed(value,bits):
        return value-(1<<bits) if value&(1<<(bits-1)) else value

    def run(self):
        pc,monitor = 0,None
        for _ in range(200):
            if pc in (BUSY,SUCCESS):
                assert monitor is None
                return 'busy' if pc==BUSY else 'success'
            word = self.values[pc//4]
            rt,rn = word&31,word>>5&31
            next_pc = pc+4
            if word&0xFFFFFC00==0xC85F7C00:
                self.loads += 1
                self.x[rt] = self.memory[self.x[rn]]
                monitor = self.x[rn]
            elif word&0xFFE0FC00==0xC800FC00:
                self.stores += 1
                assert monitor==self.x[rn]
                success = self.stores>self.failures
                if success:
                    self.memory[self.x[rn]] = self.x[rt]&0xFFFFFFFFFFFFFFFF
                    self.writes += 1
                elif self.competitor is not None:
                    self.memory[self.x[rn]] = self.competitor
                if not success and self.stores<=len(self.stack_after_failures):
                    self.memory[self.sp+8] = self.stack_after_failures[self.stores-1]
                self.x[word>>16&31] = 0 if success else 1
                monitor = None
            elif word==0xD5033F5F:
                self.clears += 1
                monitor = None
            elif word&0xFFC00000==0xF9400000:
                assert monitor is None and rn==31
                self.stack_reads += 1
                self.x[rt] = self.memory[self.sp+(word>>10&0xFFF)*8]
            elif word&0x7E000000==0x34000000:
                bits = 64 if word>>31 else 32
                nonzero = bool(self.x[rt]&((1<<bits)-1))
                if nonzero==bool(word&0x01000000):
                    next_pc = pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0xFC000000==0x14000000:
                next_pc = pc+self.signed(word&0x3FFFFFF,26)*4
            else:
                raise AssertionError(f'unmodeled instruction {pc:x}: {word:08x}')
            pc = next_pc
        raise AssertionError('nonterminating authored model')


class NativeSpPreloadCasTests(unittest.TestCase):
    def test_exact_native_union_and_register_renaming_keep_all_bytes(self):
        for rename in (None,{8:24,9:3,0:16,10:27}):
            values = fixture(rename)
            with self.subTest(rename=rename):
                self.assertEqual(plan(values),())
                image = ar.rewrite(raw(values),entry_offsets=(0,BEGIN,BUSY,SUCCESS,CALLEE))
                self.assertEqual(image.bytes,raw(values))
                self.assertFalse(image.sites)
                self.assertFalse(image.fixups)

    def test_raw_native_paths_preserve_payload_source_full_state_flags_and_guards(self):
        values = fixture()
        image = ar.rewrite(raw(values),entry_offsets=(0,BEGIN,BUSY,SUCCESS,CALLEE))
        emitted = list(struct.unpack('<'+'I'*(len(image.bytes)//4),image.bytes))
        # initial, failures, competitor; result, loads, stores, clears, stack reads.
        cases = ((0,0,None,'success',1,1,0,0),
                 (7,0,None,'busy',1,0,1,1),
                 (0x100000000,0,None,'busy',1,0,1,1),
                 (0,1,None,'success',2,2,0,1),
                 (0,3,None,'success',4,4,0,3),
                 (0,1,11,'busy',2,1,1,2),
                 (0,2,0,'success',3,3,0,2))
        for initial,failures,competitor,result,loads,stores,clears,reads in cases:
            with self.subTest(initial=initial,failures=failures,competitor=competitor):
                machine = Machine(emitted,initial,failures,competitor)
                registers,memory = machine.x.copy(),machine.memory.copy()
                self.assertEqual(machine.run(),result)
                payload = memory[machine.sp+8] if reads else registers[0]
                registers[0] = payload
                registers[9] = (competitor if failures and competitor is not None else initial)
                if stores:
                    registers[10] = 0 if result=='success' else 1
                self.assertEqual(machine.x,registers)
                self.assertEqual((machine.sp,machine.flags,machine.q),
                                 (0x800000,0xB0000000,tuple(bytes([i])*16 for i in range(32))))
                self.assertEqual((machine.loads,machine.stores,machine.clears,machine.stack_reads),
                                 (loads,stores,clears,reads))
                memory[0x400000] = payload if result=='success' else registers[9]
                self.assertEqual(machine.memory,memory)
                self.assertEqual(machine.writes,int(result=='success'))

    def test_each_failed_store_reads_the_current_original_stack_slot(self):
        values = fixture()
        image = ar.rewrite(raw(values),entry_offsets=(0,BEGIN,BUSY,SUCCESS,CALLEE))
        emitted = list(struct.unpack('<'+'I'*(len(image.bytes)//4),image.bytes))
        changes = (0xAAAAAAAA00000001,0xBBBBBBBB00000002,0xCCCCCCCC00000003)
        machine = Machine(emitted,0,failures=3,stack_after_failures=changes)
        registers,memory = machine.x.copy(),machine.memory.copy()
        self.assertEqual(machine.run(),'success')
        registers[0],registers[9],registers[10] = changes[-1],0,0
        memory[0x400000] = memory[0x800008] = changes[-1]
        self.assertEqual(machine.x,registers)
        self.assertEqual(machine.memory,memory)
        self.assertEqual((machine.loads,machine.stores,machine.stack_reads,machine.clears),
                         (4,4,3,0))
        self.assertEqual((machine.sp,machine.flags,machine.q),
                         (0x800000,0xB0000000,tuple(bytes([i])*16 for i in range(32))))

    def test_whole_union_has_one_entry_and_neither_interior_metadata_nor_edges(self):
        for pc in range(BEGIN+4,END,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):
                plan(fixture(),roots=(0,BEGIN,BUSY,SUCCESS,CALLEE,pc))
            values = fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):
                plan(values)

    def test_exact_sp_width_order_alias_and_closed_exit_requirements(self):
        helper = ar.android_exclusive.native_conditional_refresh
        instructions,kinds = decode(fixture())
        by_pc = {ins.address:ins for ins in instructions}
        nodes,entry,heads = helper(by_pc[BEGIN],by_pc,kinds,ar)
        self.assertEqual((nodes,entry,heads),(set(range(BEGIN,END,4)),BEGIN,{BEGIN,BEGIN+20}))
        mutations = ((0,TEMPLATE[0]^0x8000),(0,TEMPLATE[0]^0x40000000),
                     (1,TEMPLATE[1]^0x80000000),(1,TEMPLATE[1]^0x01000000),
                     (3,TEMPLATE[3]+0x400),(3,TEMPLATE[3]^0x40000000),
                     (3,TEMPLATE[3]^(1<<5)),(3,0x910023E0),
                     (4,TEMPLATE[4]^0x80000000),(5,TEMPLATE[5]^0x8000),
                     (6,TEMPLATE[6]^0x01000000),(7,TEMPLATE[7]^0x8000),
                     (7,TEMPLATE[7]^0x40000000),(8,TEMPLATE[8]^0x80000000),
                     (8,TEMPLATE[8]+(1<<5)),(9,ar.branch(BEGIN+36,BEGIN)))
        for index,word in mutations:
            values = fixture();values[BEGIN//4+index]=word
            ins,ks = decode(values)
            with self.subTest(index=index,word=hex(word)):
                self.assertIsNone(helper(ins[BEGIN//4],{i.address:i for i in ins},ks,ar))
        for role in (8,9,0,10):
            collision = {8:9,9:0,0:10,10:8}[role]
            for forbidden in (18,29,30,31,collision):
                values = fixture({role:forbidden})
                ins,ks = decode(values)
                with self.subTest(role=role,forbidden=forbidden):
                    self.assertIsNone(helper(ins[BEGIN//4],{i.address:i for i in ins},ks,ar))
        for pc in range(BEGIN,END,4):
            self.assertIsNone(helper(by_pc[BEGIN],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))
            with self.assertRaises(ar.RewriteError):
                plan(fixture(),overrides={pc:'x18'})
        for target in (BUSY,SUCCESS):
            bad = by_pc.copy();bad.pop(target)
            self.assertIsNone(helper(by_pc[BEGIN],bad,kinds,ar))
            bad = by_pc.copy();bad[target]=ar.decode(0,target)
            self.assertIsNone(helper(by_pc[BEGIN],bad,kinds,ar))


if __name__=='__main__':
    unittest.main()
