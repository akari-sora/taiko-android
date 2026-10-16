"""Finite inline byte format switches retain virtual X18 and CMP provenance."""
from dataclasses import replace
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_virtual_ro_x18 import image_for
from nso_format import parse_metadata
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

CMP, BRIDGE = 0x3C0, 0x3C4
BRANCHES, LOADS, GUARDS = (0x3E0, 0x498), (0x3D8, 0x490), (0x3C8, 0x480)
TABLES, BASE = (0x4800, 0x4840), 0x3E4
TAGS = (tuple((0, 4, 8, 12)[i % 4] for i in range(50)) + (200,),
        tuple((0, 4, 8, 16)[i % 4] for i in range(50)) + (220,))


def tbnz(pc, target, *, register=9, bit=6):
    return 0x37000000 | (bit & 31) << 19 | (bit >> 5) << 31 | (((target-pc)//4) & 0x3FFF) << 5 | register


def fixture():
    source = source_base()
    write_image(source, CMP, '<2I', 0x7100C99F, tbnz(BRIDGE, GUARDS[1]))
    for guard, branch, load, table, tags in zip(GUARDS, BRANCHES, LOADS, TABLES, TAGS):
        write_image(source, guard, '<7I', 0x54000008 | (((0x900-guard)//4) << 5),
                    0x9000002E, 0x910001CE | ((table & 4095) << 10),
                    adr(load-4, BASE, 15), 0x386C69D2, 0x8B1209EF, 0xD61F01E0)
        write_image(source, table, '<51B', *tags)
    for tag in set(TAGS[0]) | set(TAGS[1]):
        write_image(source, BASE+tag*4, '<2I', 0x11000652, 0xD65F03C0)
    return source


def copy_fixture(bound=120):
    source = source_base()
    write_image(source, CMP, '<9I', 0x7100015F | (bound << 10),
                0x54000008 | (((0x900-CMP-4)//4) << 5), 0x2A0A03F0,
                0x9000002F, 0x912001EF, adr(0x3D4, BASE, 17),
                0x387069F2, 0x8B120A31, 0xD61F0220)
    tags = tuple((0, 4, 8)[index % 3] for index in range(bound)) + (220,)
    write_image(source, 0x4800, '<'+str(len(tags))+'B', *tags)
    for tag in set(tags):write_image(source, BASE+tag*4, '<2I', 0x11000652, 0xD65F03C0)
    return source, tags


def classify(source, branch, *, roots=(0x300,), known=(), missing=(), readonly=((0x4000, 0x8000),)):
    raw = parse_nso(source).image
    by_pc = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I',raw,pc)[0],pc))
             for pc in range(0x300,0x1000,4) if pc not in missing}
    entries = set(roots)
    for op in by_pc.values():
        if op.mnemonic in ('b','bl','cbz','cbnz','tbz','tbnz') or op.mnemonic.startswith('b.'):
            entries.add(op.operands[-1].imm)
    return ar.readonly_guest_table(by_pc[branch],by_pc,entries,raw,readonly,
                                   root_entries=set(roots),known_tables=known)


class VirtualLoadedFormatTests(unittest.TestCase):
    def execute(self, source, *, mode=0, index=0, copy=False, entry=CMP, bad=None, selected_branches=None):
        branches = selected_branches if selected_branches is not None else (BRANCHES[0],) if copy else BRANCHES
        image = image_for(source,entry=CMP,proven_guest_indirect_offsets=branches)
        base,state,helper,stack = 0x10000000,0x30000000,0x30001000,0x20008000
        cpu = Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        cpu.mem_map(base,max(0x10000,(len(image.bytes)+4095)&~4095))
        cpu.mem_map(0x20000000,0x10000);cpu.mem_map(state,0x10000)
        cpu.mem_write(base,image.bytes);cpu.mem_write(helper,struct.pack('<IIQ',0x58000050,0xD65F03C0,state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER,fixup.helper)
            cpu.mem_write(base+fixup.offset,struct.pack('<Q',helper))
        registers = [0x1234567800000000+r*0x10101 for r in range(31)]
        table_register,index_register,target_register = (15,16,17) if copy else (14,12,15)
        table = 0x4800 if copy else TABLES[mode]
        registers[table_register],registers[index_register],registers[target_register] = base+table,index,base+BASE
        registers[9],registers[10],registers[30] = mode<<6,index,base+0x80
        if bad=='table':registers[table_register]+=1
        elif bad=='base':registers[target_register]+=4
        for r,value in enumerate(registers):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{r}'),value)
        vectors = [int.from_bytes(bytes((r+i)%256 for i in range(16)),'little') for r in range(32)]
        for r,value in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{r}'),value)
        cpu.reg_write(uc.UC_ARM64_REG_SP,stack);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
        cpu.mem_write(state,struct.pack('<Q',0xAABBCCDD11223344))
        observed = dict(returned=False,trapped=False,reads=0)
        def snapshot():
            return ([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV),
                    [cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine,pc,size,_):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I',machine.mem_read(pc,4))[0],pc)))
            if pc==base+0x80:observed['returned']=True;machine.emu_stop()
        def trap(machine,number,_):observed['trapped']=True;machine.emu_stop()
        def read(machine,access,address,size,value,_):
            if base+table<=address<base+table+(121 if copy else 51):observed['reads']+=1
        cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_INTR,trap);cpu.hook_add(UC_HOOK_MEM_READ,read)
        initial = snapshot();cpu.emu_start(base+entry,base+len(image.bytes),count=10000)
        observed.update(initial=initial,final=snapshot(),registers=registers,vectors=vectors,base=base,stack=stack,
                        state_value=struct.unpack('<Q',cpu.mem_read(state,8))[0])
        return observed

    def test_actual_cpu_all_51_byte_indices_on_both_tbnz_paths(self):
        for mode in (0,1):
            for index,tag in enumerate(TAGS[mode]):
                with self.subTest(mode=mode,index=index):
                    result = self.execute(fixture(),mode=mode,index=index)
                    self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))
                    expected = result['registers'][:];expected[14]=result['base']+TABLES[mode];expected[15]=result['base']+BASE+tag*4
                    self.assertEqual((expected,result['stack'],0x60000000 if index==50 else 0x80000000,result['vectors']),result['final'])
                    self.assertEqual(tag+1,result['state_value'])

    def test_actual_cpu_copy_domain_and_high_source_bits_are_preserved(self):
        source,tags = copy_fixture()
        for index,tag in enumerate(tags):
            result = self.execute(source,index=index,copy=True)
            expected = result['registers'][:];expected[16]=index;expected[15]=result['base']+0x4800;expected[17]=result['base']+BASE+tag*4
            self.assertEqual((expected,result['stack'],0x60000000 if index==120 else 0x80000000,result['vectors']),result['final'])
            self.assertEqual((True,False,1,tag+1),(result['returned'],result['trapped'],result['reads'],result['state_value']))
        result = self.execute(source,index=(1<<32)|2,copy=True)
        self.assertEqual(2,result['final'][0][16]);self.assertEqual(tags[2]+1,result['state_value'])

    def test_direct_inline_x_compare_still_uses_full_actual_index_guard(self):
        source = fixture()
        # Replace the mode bridge with the local X compare. The second mode
        # has no control-flow entrance in this distinct authored fixture.
        write_image(source,BRIDGE,'<I',0xF100C99F)
        plan = classify(source,BRANCHES[0])
        self.assertIsNotNone(plan)
        self.assertEqual((BRIDGE,50),(plan['compare_offset'],plan['index_bound']))
        for index,tag in enumerate(TAGS[0]):
            result=self.execute(source,index=index,selected_branches=(BRANCHES[0],))
            expected=result['registers'][:];expected[14]=result['base']+TABLES[0];expected[15]=result['base']+BASE+tag*4
            self.assertEqual((expected,result['stack'],0x60000000 if index==50 else 0x80000000,result['vectors']),result['final'])
            self.assertEqual((True,False,1,tag+1),(result['returned'],result['trapped'],result['reads'],result['state_value']))

    def test_actual_cpu_zero_read_failures_restore_all_machine_state(self):
        for copy in (False,True):
            source = copy_fixture()[0] if copy else fixture()
            for index,bad in ((0,'table'),(0,'base'),(121 if copy else 51,None),(1<<32,None)):
                result = self.execute(source,copy=copy,index=index,entry=LOADS[0],bad=bad)
                self.assertEqual((False,True,0),(result['returned'],result['trapped'],result['reads']))
                self.assertEqual(result['initial'],result['final']);self.assertEqual(0xAABBCCDD11223344,result['state_value'])

    def test_same_guard_metadata_alias_and_late_callback_origin_reject(self):
        for root in (BRIDGE,GUARDS[1],LOADS[1],LOADS[1]+4):
            self.assertIsNone(classify(fixture(),BRANCHES[1],roots=(0x300,root)))
        nso = parse_nso(fixture());metadata = parse_metadata(nso)
        with self.assertRaises(ai.ImportError):
            ai.discover_code(nso,replace(metadata,eh_starts=metadata.eh_starts+(GUARDS[1],)),checked_stack=True,indirect_policy='guarded-host')
        source = fixture();case = BASE+TAGS[1][-1]*4
        write_image(source,case,'<2I',adr(case,GUARDS[1],5),0xD65F03C0)
        with self.assertRaisesRegex(ai.ImportError,'guest table proof invalidated'):
            ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')

    def test_external_known_table_clobber_backward_and_wrong_width_paths_reject(self):
        for word in (0x7100053F,0x1100058C,0x94000001,0xD61F00A0,
                     tbnz(BRIDGE,GUARDS[1],register=18),tbnz(BRIDGE,GUARDS[1],bit=63),tbnz(BRIDGE,CMP)):
            source=fixture();write_image(source,BRIDGE,'<I',word)
            self.assertIsNone(classify(source,BRANCHES[1]))
        source=fixture();write_image(source,0x900,'<I',ar.branch(0x900,GUARDS[1]))
        self.assertIsNone(classify(source,BRANCHES[1]))
        self.assertIsNone(classify(fixture(),BRANCHES[1],known=({0x904:dict(offset=0x904,base=GUARDS[1],target_values=[0])},)))
        source=fixture();write_image(source,TABLES[1],'<B',(LOADS[1]-BASE)//4)
        self.assertIsNone(classify(source,BRANCHES[1]))

    def test_copy_is_a_distinct_finite_source_shape_and_ro_bounds_remain_strict(self):
        for pc,word in ((CMP,0x7104015F),(CMP+4,0x540000A8),(CMP+8,0xAA0A03F0),
                        (CMP+8,0x2A1203F0),(CMP+8,0x2A1003F0),(LOADS[0],0x387279F2)):
            source=copy_fixture()[0];write_image(source,pc,'<I',word)
            self.assertIsNone(classify(source,BRANCHES[0]))
        self.assertIsNone(classify(copy_fixture()[0],BRANCHES[0],readonly=((0x4800,0x4878),)))
        self.assertIsNone(classify(fixture(),BRANCHES[1],readonly=((0x4840,0x4872),)))
        for entry in (LOADS[0]+4,BRANCHES[0]):
            self.assertIsNone(classify(copy_fixture()[0],BRANCHES[0],roots=(0x300,entry)))


if __name__=='__main__':unittest.main()
