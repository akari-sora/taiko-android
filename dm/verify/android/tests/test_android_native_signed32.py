"""Self-authored native signed32 RO dispatches on Unicorn AArch64."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[4]/'dm/tools'))
import android_rewrite as ar
import android_import as ai
from test_android_runtime_ro_sub_inline import source_base,write_image,parse_nso
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_READ,UC_PROT_READ
from unicorn import arm64_const as uc

CMP,LOAD,ADD,BRANCH,TABLE=0x3C0,0x3D0,0x3D4,0x3D8,0x4800
TARGETS=(0x600,0x640,0x680,0x6C0)


def fixture(roles=(8,8,8,9),suffix=()):
    target,loaded,index,table=roles
    source=source_base()
    words=[0x71000C1F|(index<<5),0x54000008|(((0x900-CMP-4)//4)<<5),
           0x90000020|table,0x91200000|(table<<5)|table,
           0xB8A07800|(index<<16)|(table<<5)|loaded,
           0x8B000000|(table<<16)|(loaded<<5)|target,*suffix,0xD61F0000|(target<<5)]
    write_image(source,CMP,'<'+str(len(words))+'I',*words)
    write_image(source,TABLE,'<4i',*(target-TABLE for target in TARGETS))
    return source,BRANCH+len(suffix)*4


def plan(source,branch,*,entries=(),readonly=((0x4000,0x8000),),protected=()):
    raw=parse_nso(source).image
    by_pc={pc:ar.Instruction(ar.decode(struct.unpack_from('<I',raw,pc)[0],pc)) for pc in range(0x300,0x1000,4)}
    return ar.readonly_guest_table(by_pc[branch],by_pc,set(entries),raw,readonly,
                                  text_size=0x4000,protected_ranges=protected,root_entries={0x300})


class NativeSigned32Tests(unittest.TestCase):
    def image(self,source,branch):
        nso=parse_nso(source)
        return ar.rewrite(nso.image,entry_offset=CMP,text_size=nso.sections[0].end,
            code_ranges=((0x300,0x1000),),package_version=2,checked_stack=True,
            readonly_ranges=((0x4000,0x8000),),proven_guest_indirect_offsets=(branch,))

    def execute(self,roles,index,*,bad=None,entry=CMP,suffix=(),custom=None,register_values=None,memory_values=()):
        source,branch=fixture(roles,suffix) if custom is None else custom
        image=self.image(source,branch)
        base,stack=0x10000000,0x20008000
        cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        cpu.mem_map(base,max(0x10000,(len(image.bytes)+4095)&~4095));cpu.mem_map(0x20000000,0x10000)
        cpu.mem_write(base,image.bytes);cpu.mem_protect(base+0x4000,0x4000,UC_PROT_READ)
        state,helper=0x30000000,0x30001000
        cpu.mem_map(state,0x10000);cpu.mem_write(state,struct.pack('<Q',0xAABBCCDD11223344))
        cpu.mem_write(helper,struct.pack('<IIQ',0x58000050,0xD65F03C0,state))
        for address,data in memory_values:cpu.mem_write(address,data)
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER,fixup.helper)
            cpu.mem_write(base+fixup.offset,struct.pack('<Q',helper))
        target,loaded,idx,table=roles
        registers=[0x1234567800000000+r*0x10101 for r in range(31)]
        registers[idx]=index;registers[table]=base+TABLE;registers[30]=base+0x80
        for register,value in (register_values or {}).items():registers[register]=value
        if bad=='table':registers[table]+=4
        for r,value in enumerate(registers):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{r}'),value)
        vectors=[int.from_bytes(bytes((r+i)%256 for i in range(16)),'little') for r in range(32)]
        for r,value in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{r}'),value)
        cpu.reg_write(uc.UC_ARM64_REG_SP,stack);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
        arguments=bytes(range(16));cpu.mem_write(stack,arguments)
        observed=dict(returned=False,trapped=False,reads=0)
        def snapshot():
            return ([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)],cpu.reg_read(uc.UC_ARM64_REG_SP),
                    cpu.reg_read(uc.UC_ARM64_REG_NZCV),[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def step(machine,pc,size,_):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I',machine.mem_read(pc,4))[0],pc)))
            if pc==base+0x80:observed['returned']=True;machine.emu_stop()
        def trap(machine,number,_):observed['trapped']=True;machine.emu_stop()
        def read(machine,access,address,size,value,_):
            if base+TABLE<=address<base+TABLE+16:observed['reads']+=1
        cpu.hook_add(UC_HOOK_CODE,step);cpu.hook_add(UC_HOOK_INTR,trap);cpu.hook_add(UC_HOOK_MEM_READ,read)
        initial=snapshot();cpu.emu_start(base+entry,base+len(image.bytes),count=10000)
        self.assertEqual(arguments,bytes(cpu.mem_read(stack,len(arguments))))
        observed.update(initial=initial,final=snapshot(),registers=registers,vectors=vectors,base=base,stack=stack,
                        virtual_x18=struct.unpack('<Q',cpu.mem_read(state,8))[0])
        return observed

    def test_canonical_aliases_have_native_marker_and_signed_graph_values(self):
        for roles in ((8,8,8,9),(5,5,17,13),(6,5,17,10)):
            source,branch=fixture(roles);p=plan(source,branch)
            self.assertIsNotNone(p)
            self.assertTrue(p['native_signed_relative']);self.assertFalse(p.get('signed_relative',False))
            self.assertEqual([offset//4 for offset in sorted({target-TABLE for target in TARGETS})],p['target_values'])
            self.assertEqual(list(TARGETS),p['target_offsets'])

    def test_actual_cpu_all_indices_preserve_all_gpr_q_flags_sp_lr(self):
        for roles in ((8,8,8,9),(5,5,17,13),(6,5,17,10)):
            for index,target in enumerate(TARGETS):
                with self.subTest(roles=roles,index=index):
                    result=self.execute(roles,index);expected=result['registers'][:]
                    expected[roles[3]]=result['base']+TABLE
                    expected[roles[1]]=(target-TABLE)&0xFFFFFFFFFFFFFFFF
                    expected[roles[0]]=result['base']+target
                    self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))
                    self.assertEqual((expected,result['stack'],0x60000000 if index==3 else 0x80000000,result['vectors']),result['final'])

    def test_uninitialized_distinct_target_is_not_a_pre_read_base_requirement(self):
        result=self.execute((6,5,17,10),2,entry=LOAD)
        self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))

    def test_pre_read_wrong_table_and_full64_index_fail_without_read_or_clobber(self):
        for roles in ((8,8,8,9),(6,5,17,10)):
            for index,bad in ((0,'table'),(4,None),(1<<32,None),(0xFFFFFFFFFFFFFFFF,None)):
                result=self.execute(roles,index,bad=bad,entry=LOAD)
                self.assertEqual((False,True,0),(result['returned'],result['trapped'],result['reads']))
                self.assertEqual(result['initial'],result['final'])

    def test_misaligned_outside_metadata_and_own_core_targets_refuse(self):
        for target in (0,0x4000,0x601,ADD,BRANCH):
            source,branch=fixture();write_image(source,TABLE,'<i',target-TABLE)
            self.assertIsNone(plan(source,branch))
        source,branch=fixture()
        self.assertIsNone(plan(source,branch,protected=((TARGETS[0],TARGETS[0]+4),)))
        self.assertIsNone(plan(source,branch,protected=((TABLE,TABLE+16),)))
        self.assertIsNone(plan(source,branch,readonly=((TABLE,TABLE+15),)))
        write_image(source,TABLE,'<i',4-TABLE)
        self.assertIsNone(plan(source,branch,protected=((0,48),)))
        source,branch=fixture()
        with self.assertRaises(ar.RewriteError):
            nso=parse_nso(source)
            ar.rewrite(nso.image,entry_offset=CMP,text_size=0x4000,code_ranges=((0x300,0x1000),),
                package_version=2,checked_stack=True,readonly_ranges=((0x4000,0x8000),),
                protected_ranges=((TABLE,TABLE+16),),proven_guest_indirect_offsets=(branch,))

    def test_import_report_signed_family_matches_native_readonly_plan(self):
        source,branch=fixture()
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        discovery=report['code_discovery']
        self.assertEqual(discovery['readonly_guest_jump_tables'],discovery['signed_relative_jump_tables'])
        self.assertFalse(discovery.get('halfword_jump_tables'))
        self.assertEqual([branch],discovery['proven_guest_indirect_sites'])

    def test_local_complete_constructor_wins_without_nearest_constant_policy(self):
        source,branch=fixture()
        write_image(source,0x320,'<2I',0x90000029,0x91300129) # unrelated RO4c00
        write_image(source,0x4C00,'<4i',*(target-0x4C00 for target in TARGETS))
        self.assertEqual(TABLE,plan(source,branch)['table_offset'])
        # With only hoisted ambiguous candidates the actual object is unknown.
        write_image(source,0x330,'<2I',0x90000029,0x91200129)
        write_image(source,CMP+8,'<2I',0xD503201F,0xD503201F)
        self.assertIsNone(plan(source,branch))

    def test_postload_alias_target_clobber_and_invalid_source_words_refuse(self):
        for entry in (ADD,BRANCH):
            source,branch=fixture();self.assertIsNone(plan(source,branch,entries=(entry,)))
        for pc,word in ((LOAD,0xB8687928),(ADD,0x8B092108),(ADD,0xAB090108),
                        (CMP,0x7101011F),(CMP+4,0x54000088)):
            source,branch=fixture();write_image(source,pc,'<I',word)
            self.assertIsNone(plan(source,branch))
        for suffix in ((0xB1000508,),(0x94000001,),(0xD4000001,),(0x910043FF,)):
            source,branch=fixture(suffix=suffix);self.assertIsNone(plan(source,branch))


if __name__=='__main__':unittest.main()
