"""A byte table with the original self-loaded, decremented virtual index."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, ai, source_base, write_image
import test_taiko_checked_call as fixed
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

PAGE, START, LOAD, BRANCH, CASE_BASE, TABLE = 0x100, 0x120, 0x134, 0x13C, 0x140, 0x4081
VALUES = (0, 4, 12, 23, 37, 54, 75, 100, 129)


def cond(pc, destination, condition=8):
    return 0x54000000 | (((destination-pc)//4 & 0x7FFFF) << 5) | condition


def fixture(roles=(2, 3, 17, 13)):
    target, loaded, table, source = roles
    data=bytearray(0x5000)
    page_delta=(TABLE>>12)-(PAGE>>12)
    prefix=[0x90000000 | (page_delta&3)<<29 | (page_delta>>2&0x7FFFF)<<5 | table,
            0x91000000 | (TABLE&4095)<<10 | table<<5 | table]
    data[PAGE:PAGE+8]=fixed.raw(*prefix)
    data[PAGE+8:START]=fixed.raw(*([0xD503201F]*6))
    delta=CASE_BASE-(START+16)
    words=[0xB8606800 | source<<16 | 18<<5 | 18, 0x51000652,
           0x7100225F, cond(START+12,0x1800),
           0x10000000 | (delta&3)<<29 | (delta>>2&0x7FFFF)<<5 | target,
           0x38726800 | table<<5 | loaded,
           0x8B000800 | loaded<<16 | target<<5 | target, 0xD61F0000 | target<<5]
    data[START:START+32]=fixed.raw(*words)
    data[TABLE:TABLE+9]=bytes(VALUES)
    ranges=[(PAGE,START+32)]
    targets=tuple(CASE_BASE+x*4 for x in VALUES)
    for target_pc in targets:
        data[target_pc:target_pc+4]=ar.word(ar.branch(target_pc,0x2000))
        ranges.append((target_pc,target_pc+4))
    data[0x1800:0x1804]=ar.word(0xD65F03C0)
    callback=fixed.fixture()[0][0x100:]
    data[0x2000:0x2000+len(callback)]=callback
    ranges.extend(((0x1800,0x1804),(0x2000,0x2000+len(callback))))
    return bytes(data),sorted(ranges),targets


def rewritten(roles=(2,3,17,13), **changes):
    raw,ranges,_=fixture(roles)
    return ar.rewrite(raw, **(dict(entry_offset=PAGE,text_size=0x3000,code_ranges=ranges,
        package_version=2,checked_stack=True,readonly_ranges=((0x4000,0x5000),),
        proven_guest_indirect_offsets=(BRANCH,)) | changes))


def plan(raw=None, entries=(), root_entries=(), readonly=((0x4000,0x5000),), roles=(2,3,17,13)):
    original,ranges,_=fixture(roles)
    raw=original if raw is None else raw
    by={pc:ar.Instruction(ar.decode(struct.unpack_from('<I',raw,pc)[0],pc))
        for a,b in ranges for pc in range(a,b,4)}
    return ar.readonly_guest_table(by[BRANCH],by,set(entries),raw,readonly,root_entries=set(root_entries))


class VirtualIndexByteTests(unittest.TestCase):
    def execute(self,index=0,*,roles=(2,3,17,13),entry=PAGE,virtual=None,table_base=None,case_base=None):
        image=rewritten(roles); target,loaded,table,source=roles
        base,state,helper,output,pointer,stack=0x10000000,0x30000000,0x30001000,0x30002000,0x30003000,0x20008000
        cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
        cpu.mem_map(base,0x10000);cpu.mem_map(state,0x10000);cpu.mem_map(0x20000000,0x10000)
        cpu.mem_write(base,image.bytes);cpu.mem_write(helper,fixed.raw(0x58000050,0xD65F03C0)+struct.pack('<Q',state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER,fixup.helper);cpu.mem_write(base+fixup.offset,struct.pack('<Q',helper))
        registers=[0x12340000+r*0x101 for r in range(31)]
        registers[18],registers[28],registers[30],registers[source]=0x77AA000000000018,output,base+0x80,12
        registers[table]=base+TABLE if table_base is None else table_base
        registers[target]=base+CASE_BASE if case_base is None else case_base
        for r,value in enumerate(registers):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{r}'),value)
        vectors=[int.from_bytes(bytes((r+i)%256 for i in range(16)),'little') for r in range(32)]
        for r,value in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{r}'),value)
        cpu.reg_write(uc.UC_ARM64_REG_SP,stack);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
        arguments=bytes(range(16));cpu.mem_write(stack,arguments);cpu.mem_write(pointer+12,struct.pack('<I',(index+1)&0xFFFFFFFF))
        initial_virtual=virtual if virtual is not None else index if entry==LOAD else pointer
        cpu.mem_write(state,struct.pack('<Q',initial_virtual))
        targets=set(fixture(roles)[2]);result=dict(trapped=False,returned=False,pointer_reads=0,table_reads=0,target=None)
        def snapshot():
            return ([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)],cpu.reg_read(uc.UC_ARM64_REG_SP),
                cpu.reg_read(uc.UC_ARM64_REG_NZCV),[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')) for r in range(32)])
        def code(machine,pc,size,_):
            ins=ar.decode(struct.unpack('<I',machine.mem_read(pc,4))[0],pc)
            self.assertFalse(ar.has18(ins),'Executed code must not touch platform X18')
            if pc-base in targets:result['target']=pc-base
            if pc==base+0x80:result['returned']=True;machine.emu_stop()
        def read(machine,access,address,size,value,_):
            if address==pointer+12:result['pointer_reads']+=1
            if base+TABLE<=address<base+TABLE+9:result['table_reads']+=1
        def trap(machine,number,_):result['trapped']=True;machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_MEM_READ,read);cpu.hook_add(UC_HOOK_INTR,trap)
        initial=snapshot();cpu.emu_start(base+entry,base+len(image.bytes),count=20000)
        result.update(cpu=cpu,base=base,state=state,output=output,registers=registers,vectors=vectors,stack=stack,
            arguments=arguments,initial=initial,final=snapshot(),initial_virtual=initial_virtual)
        self.assertEqual(registers[18],cpu.reg_read(uc.UC_ARM64_REG_X18))
        self.assertEqual(stack,cpu.reg_read(uc.UC_ARM64_REG_SP));self.assertEqual(arguments,bytes(cpu.mem_read(stack,16)))
        return result

    def test_exact_shape_uses_complete_odd_aligned_byte_table(self):
        proof=plan();self.assertIsNotNone(proof)
        self.assertEqual(('runtime-virtual-index-x18-native-target-u8-ro-self-load-sub-v1',18,8,9),
            (proof['rule'],proof['virtual_index_register'],proof['index_bound'],proof['table_bytes']))
        self.assertEqual(list(VALUES),proof['target_values'])
        image=rewritten();raw=fixture()[0]
        self.assertEqual(raw[LOAD+4:BRANCH+4],image.bytes[LOAD+4:BRANCH+4])

    def test_actual_cpu_all_rows_preserve_original_pointer_sub_flags_gpr_q_stack_and_lr(self):
        for roles in ((2,3,17,13),(0,16,7,20),(16,0,17,21)):
            for index,value in enumerate(VALUES):
                with self.subTest(roles=roles,index=index):
                    r=self.execute(index,roles=roles);cpu,output=r['cpu'],r['output']
                    self.assertEqual((False,True,1,1),(r['trapped'],r['returned'],r['pointer_reads'],r['table_reads']))
                    expected=r['registers'][:];target,loaded,table,source=roles
                    expected[target],expected[loaded],expected[table],expected[18]=r['base']+CASE_BASE+4*value,value,r['base']+TABLE,index
                    self.assertEqual(expected,list(struct.unpack('<31Q',cpu.mem_read(output,248))))
                    self.assertEqual(index,struct.unpack('<Q',cpu.mem_read(r['state'],8))[0])
                    self.assertEqual((0x60000000 if index==8 else 0x80000000,r['stack']),struct.unpack('<2Q',cpu.mem_read(output+0x300,16)))
                    for q,value_q in enumerate(r['vectors']):self.assertEqual(value_q,int.from_bytes(cpu.mem_read(output+0x100+q*16,16),'little'))

    def test_full64_live_index_and_actual_bases_trap_without_any_read_and_restore(self):
        for options in (dict(virtual=9),dict(virtual=1<<32),dict(virtual=0xFFFFFFFFFFFFFFFF),
                        dict(table_base=0),dict(table_base=0x10004082),dict(case_base=0),dict(case_base=0x10000144)):
            with self.subTest(options=options):
                r=self.execute(entry=LOAD,**options)
                self.assertEqual((True,False,0,0),(r['trapped'],r['returned'],r['pointer_reads'],r['table_reads']))
                self.assertEqual(r['initial'],r['final'])
                self.assertEqual(r['initial_virtual'],struct.unpack('<Q',r['cpu'].mem_read(r['state'],8))[0])

    def test_direct_load_entry_is_checked_and_wrapping_original_sub_follows_original_bhi(self):
        for index,value in enumerate(VALUES):
            r=self.execute(index,entry=LOAD)
            self.assertEqual((True,0,1,CASE_BASE+value*4),(r['returned'],r['pointer_reads'],r['table_reads'],r['target']))
        for index in (-1,9,0xFFFFFFFF):
            r=self.execute(index)
            self.assertEqual((False,True,1,0),(r['trapped'],r['returned'],r['pointer_reads'],r['table_reads']))

    def test_postload_constructor_entries_aliases_transforms_and_incomplete_ro_refuse(self):
        raw=fixture()[0]
        for entry in (LOAD+4,BRANCH,PAGE+4):
            with self.subTest(entry=entry):
                self.assertIsNone(plan(entries=(entry,)));self.assertIsNone(plan(root_entries=(entry,)))
                with self.assertRaises(ar.RewriteError):rewritten(entry_offsets=(entry,))
        changes=((START,0xF86D6A52),(START,0xB86D6852),(START+4,0xD1000652),
                 (START+4,0x51000A52),(START+8,0x7100265F),(START+12,cond(START+12,0x1800,0)),
                 (START+16,0x100000A2),(LOAD,0x38726A22),(LOAD,0x387269E3),
                 (LOAD+4,0x8B030843),(PAGE+4,0x91000000|(TABLE&4095)<<10|16<<5|17),
                 (PAGE+8,0xAA0003F1),(PAGE+8,0x94000000),(PAGE+8,0x31000411),
                 (PAGE+8,0x71000411),(PAGE+8,0x72001C11),(PAGE+8,0xD4200000))
        for pc,word in changes:
            damaged=bytearray(raw);struct.pack_into('<I',damaged,pc,word)
            with self.subTest(pc=pc,word=hex(word)):self.assertIsNone(plan(bytes(damaged)))
        for roles in ((2,2,17,13),(2,3,17,17),(18,3,17,13),(2,29,17,13)):
            self.assertIsNone(plan(roles=roles))
        for readonly in ((),((TABLE,TABLE+8),)):
            self.assertIsNone(plan(readonly=readonly))

    def test_import_discovers_only_original_ro_case_targets_and_rewrites_virtual_case(self):
        source=source_base();raw=fixture()[0];shift=0x2C0;table=0x4801
        words=list(struct.unpack('<16I',raw[PAGE:BRANCH+4]))
        words[1]=0x91000000|(table&4095)<<10|17<<5|17
        words[(START+12-PAGE)//4]=cond(START+12+shift,0xF00)
        write_image(source,PAGE+shift,'<16I',*words)
        write_image(source,table,'<9B',*VALUES)
        case=CASE_BASE+shift+VALUES[-1]*4
        write_image(source,case,'<2I',0x52800032,0xD65F03C0)
        _,report=ai.import_module(source,'main',checked_stack=True,package_version=2,indirect_policy='guarded-host')
        proofs=report['code_discovery']['readonly_guest_jump_tables']
        proof=next(p for p in proofs if p['offset']==BRANCH+shift)
        self.assertEqual('runtime-virtual-index-x18-native-target-u8-ro-self-load-sub-v1',proof['rule'])
        self.assertEqual([CASE_BASE+shift+value*4 for value in VALUES],
            [proof['base']+value*4 for value in proof['target_values']])
        self.assertIn(case,report['code_discovery']['roots'])
        self.assertIn(case,[site['offset'] for site in report['rewrite']['sites']])


if __name__=='__main__':unittest.main()
