"""Public authored native-u8 inline/copy shapes exercise real emitted A64."""
import os
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,os.environ.get('DM_NATIVE_BYTE_TOOLS',str(ROOT/'dm/tools')))
import android_rewrite as ar
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

START,TABLE,BASE,DEFAULT=0x100,0x20000,0x2000,0x600


def pack(*words):return struct.pack('<'+'I'*len(words),*words)
def adr(pc,target,r):
    delta=(target-pc)&0x1FFFFF
    return 0x10000000|(delta&3)<<29|(delta>>2)<<5|r


def fixture(copy=False,bound=120,roles=None):
    target,loaded,table,index,alias=roles or ((16,17,14,15,10) if copy else (16,17,15,10,9))
    words=[0x7100001F|(bound<<10)|((alias if copy else index)<<5),0]
    if copy:words.append(0x2A0003E0|(alias<<16)|index)
    pc=START+4*len(words);pages=(TABLE>>12)-(pc>>12)
    words += [0x90000000|(pages&3)<<29|(pages>>2&0x7FFFF)<<5|table,
              0x91000000|(TABLE&4095)<<10|(table<<5)|table]
    pc=START+4*len(words)
    words += [adr(pc,BASE,target),0x38606800|(index<<16)|(table<<5)|loaded,
              0x8B000800|(loaded<<16)|(target<<5)|target,0xD61F0000|(target<<5)]
    words[1]=0x54000008|(((DEFAULT-(START+4))//4&0x7FFFF)<<5)
    branch=START+4*(len(words)-1);load=branch-8
    raw=bytearray(0x21000);raw[START:START+4*len(words)]=pack(*words)
    raw[DEFAULT:DEFAULT+4]=pack(0xD4200000)
    values=tuple(((i*17+i//7)%4)*64 for i in range(bound+1))
    raw[TABLE:TABLE+len(values)]=bytes(values)
    callback=[ar.pair(False,r,r+1,r*8)&~(31<<5)|28<<5 for r in range(0,30,2)]
    callback += [ar.memory(False,30,28,240)]
    callback += [0x3D800000|((0x100+r*16)//16)<<10|28<<5|r for r in range(32)]
    callback += [0xD53B4200,ar.memory(False,0,28,0x300),0x910003E0,
                 ar.memory(False,0,28,0x308),0xD65F03C0]
    ranges=[(START,branch+4),(DEFAULT,DEFAULT+4)]
    for tag in sorted(set(values)):
        at=BASE+tag*4;raw[at:at+4*len(callback)]=pack(*callback);ranges.append((at,at+4*len(callback)))
    return bytes(raw),sorted(ranges),dict(branch=branch,load=load,roles=(target,loaded,table,index,alias),values=values)


def rewrite(copy=False,bound=120,roles=None,**changes):
    raw,ranges,facts=fixture(copy,bound,roles)
    options=dict(entry_offset=START,text_size=0x4000,code_ranges=ranges,package_version=2,
                 checked_stack=True,proven_guest_indirect_offsets=(facts['branch'],),readonly_ranges=((TABLE,TABLE+((bound+4)//4*4)),))
    return ar.rewrite(raw,**(options|changes)),facts


def classify(raw,ranges,facts,entries=(),readonly=None):
    ops={pc:ar.Instruction(ar.decode(struct.unpack_from('<I',raw,pc)[0],pc))
         for lo,hi in ranges for pc in range(lo,hi,4)}
    return ar._guarded_native_readonly_table(ops[facts['branch']],ops,set(entries),raw,
        readonly if readonly is not None else ((TABLE,TABLE+len(facts['values'])),))


class NativeByteLargeCopyTests(unittest.TestCase):
    def execute(self,image,facts,index,*,copy=False,entry=None,bad=None):
        cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);base=0x10000000;state=0x30000000;helper=state+0x1000;out=state+0x2000;stack=0x20008000
        cpu.mem_map(base,0x40000);cpu.mem_map(0x20000000,0x10000);cpu.mem_map(state,0x10000)
        cpu.mem_write(base,image.bytes);cpu.mem_write(helper,pack(0x58000050,0xD65F03C0)+struct.pack('<Q',state))
        for fixup in image.fixups:
            self.assertEqual(fixup.helper,ar.STATE_HELPER);cpu.mem_write(base+fixup.offset,struct.pack('<Q',helper))
        expected=[0x1234567800000000+r*0x101 for r in range(31)]
        target,loaded,table,idx,alias=facts['roles'];expected[28]=out;expected[30]=base+0x80
        expected[table]=base+TABLE;expected[target]=base+BASE;expected[idx]=index
        if copy:expected[alias]=(1<<40)|index
        if bad=='table':expected[table]+=4
        if bad=='base':expected[target]+=4
        for r,value in enumerate(expected):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{r}'),value)
        vectors=[int.from_bytes(bytes((r+j)%256 for j in range(16)),'little') for r in range(32)]
        for r,value in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{r}'),value)
        cpu.reg_write(uc.UC_ARM64_REG_SP,stack);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
        arguments=bytes(range(16));cpu.mem_write(stack,arguments)
        observed=dict(trapped=False,returned=False,reads=0)
        def code(machine,pc,size,_):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I',machine.mem_read(pc,4))[0],pc)))
            if pc==base+0x80:observed['returned']=True;machine.emu_stop()
        def read(machine,access,address,size,value,_):
            if base+TABLE<=address<base+TABLE+len(facts['values']):observed['reads']+=1
        def trap(machine,number,_):observed['trapped']=True;machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE,code);cpu.hook_add(UC_HOOK_MEM_READ,read);cpu.hook_add(UC_HOOK_INTR,trap)
        cpu.emu_start(base+(START if entry is None else entry),base+len(image.bytes),count=20000)
        self.assertEqual(expected[18],cpu.reg_read(uc.UC_ARM64_REG_X18));self.assertEqual(stack,cpu.reg_read(uc.UC_ARM64_REG_SP))
        self.assertEqual(arguments,bytes(cpu.mem_read(stack,16)))
        if observed['returned']:
            value=facts['values'][index];expected[target]=base+BASE+value*4;expected[loaded]=value
            if copy:expected[idx]=index
            # Original STP X18 observes virtual guest X18; platform X18 was
            # checked separately above and must never become guest state.
            expected[18]=0
            self.assertEqual(expected,list(struct.unpack('<31Q',cpu.mem_read(out,248))))
            flags=0x60000000 if index==len(facts['values'])-1 else 0x80000000
            self.assertEqual((flags,stack),struct.unpack('<2Q',cpu.mem_read(out+0x300,16)))
            for r,value in enumerate(vectors):self.assertEqual(value,int.from_bytes(cpu.mem_read(out+0x100+r*16,16),'little'))
        else:
            self.assertEqual(expected,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{r}')) for r in range(31)])
            self.assertEqual(0xB0000000,cpu.reg_read(uc.UC_ARM64_REG_NZCV))
            for r,value in enumerate(vectors):self.assertEqual(value,cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{r}')))
        return observed

    def test_real_cpu_all121_indices_plain_and_wcopy_keep_full_guest_state(self):
        for copy in (False,True):
            image,facts=rewrite(copy)
            for index in range(121):
                with self.subTest(copy=copy,index=index):
                    self.assertEqual(dict(trapped=False,returned=True,reads=1),self.execute(image,facts,index,copy=copy))

    def test_role16_aliases_are_legal_with_distinct_native_operands(self):
        for copy,roles in ((False,(16,17,15,10,9)),(False,(14,16,15,10,9)),
                           (False,(14,17,16,10,9)),(False,(14,17,15,16,9)),
                           (True,(14,17,15,16,10)),(True,(14,17,15,10,16))):
            image,facts=rewrite(copy,roles=roles)
            self.execute(image,facts,120,copy=copy)

    def test_bad_actual_base_table_full_index_and_bounds_trap_before_any_read(self):
        for copy in (False,True):
            image,facts=rewrite(copy)
            for index,bad in ((0,'table'),(0,'base'),(121,None),(1<<32,None),(0xFFFFFFFFFFFFFFFF,None)):
                with self.subTest(copy=copy,index=index,bad=bad):
                    result=self.execute(image,facts,index,copy=copy,entry=facts['load'],bad=bad)
                    self.assertEqual(dict(trapped=True,returned=False,reads=0),result)

    def test_only_exact_finite_native_inline_and_copy_shapes_expand(self):
        for copy in (False,True):
            raw,ranges,facts=fixture(copy);load=facts['load'];branch=facts['branch']
            self.assertIsNotNone(classify(raw,ranges,facts))
            for bound in (64,120,255):self.assertEqual(len(rewrite(copy,bound)[1]['values']),bound+1)
            with self.assertRaises(ar.RewriteError):rewrite(copy,256)
            for entry in (load+4,branch):
                self.assertIsNone(classify(raw,ranges,facts,entries=(entry,)))
                with self.assertRaises(ar.RewriteError):rewrite(copy,entry_offsets=(entry,))
            for readonly in ((),((TABLE,TABLE+120),)):
                self.assertIsNone(classify(raw,ranges,facts,readonly=readonly))
                with self.assertRaises(ar.RewriteError):rewrite(copy,readonly_ranges=readonly)
            mutations=[(START,0xF100001F|(120<<10)|((10 if copy else facts['roles'][3])<<5)),
                       (START+4,0x54000000), (load-12,0xD503201F),
                       (load,0x38606800|(facts['roles'][3]<<16)|(facts['roles'][2]<<5)|facts['roles'][2])]
            if copy:mutations += [(START+8,0xAA0A03EF),(START+8,0x2A0B03EF)]
            for pc,word in mutations:
                damaged=bytearray(raw);struct.pack_into('<I',damaged,pc,word)
                with self.subTest(copy=copy,pc=pc,word=word):self.assertIsNone(classify(damaged,ranges,facts))

    def test_metadata_and_relative_relocation_postload_origins_cannot_bypass_read_guard(self):
        from nso_format import Symbol,Relocation
        for copy in (False,True):
            raw,ranges,facts=fixture(copy)
            for at in (facts['load']+4,facts['branch']):
                origins={'eh':(at,),
                         'defined-STT_FUNC':(Symbol('authored_callback',at,4,1,2,1,0),),
                         'RELATIVE':(Relocation(TABLE+0x100,1027,0,at),)}
                for kind,records in origins.items():
                    roots=tuple(record if kind=='eh' else record.value if kind=='defined-STT_FUNC' else record.addend for record in records)
                    with self.subTest(copy=copy,origin=kind,at=at):
                        self.assertIsNone(classify(raw,ranges,facts,entries=roots))
                        with self.assertRaises(ar.RewriteError):
                            rewrite(copy,entry_offsets=roots,independent_entry_offsets=(START,*roots))

    def test_virtual_reserved_and_overlapping_roles_do_not_gain_large_domain(self):
        for copy in (False,True):
            for roles in ((18,17,15,10,9),(16,18,15,10,9),(16,17,18,10,9),
                          (16,17,15,18,9),(16,16,15,10,9),(16,17,17,10,9),
                          (29,17,15,10,9),(16,17,15,30,9)):
                raw,ranges,facts=fixture(copy,roles=roles)
                with self.subTest(copy=copy,roles=roles):self.assertIsNone(classify(raw,ranges,facts))
            raw,ranges,facts=fixture(copy)
            # Destroy this exact inline table producer while leaving a valid
            # earlier table candidate: wider-domain classification must refuse.
            damaged=bytearray(raw);table=facts['roles'][2]
            struct.pack_into('<2I',damaged,0x80,0x90000100|table,0x91000000|table<<5|table)
            struct.pack_into('<I',damaged,facts['load']-12,0xD503201F)
            ranges=[(0x80,0x88),*ranges]
            self.assertIsNone(classify(damaged,ranges,facts))

    def test_adjacent_index_transform_keeps_existing_sub_family_limit(self):
        for bound in (64,120,255):
            raw,ranges,facts=fixture(bound=bound);index=facts['roles'][3]
            # Source W/X aliases both define the same architectural index.
            writes=(0x51000400|(9<<5)|index,0xD1000400|(9<<5)|index,
                    0x11000400|(9<<5)|index,0x31000400|(9<<5)|index,
                    0x71000400|(9<<5)|index,0x6A080000|(9<<5)|index,
                    0x53017C00|(9<<5)|index,0x2A0003E0|(9<<16)|index,
                    0xB9400000|(9<<5)|index)
            for word in writes:
                damaged=bytearray(raw);struct.pack_into('<I',damaged,START-4,word)
                selected=[(START-4,ranges[0][1]),*ranges[1:]]
                with self.subTest(bound=bound,word=hex(word)):
                    self.assertIsNone(classify(damaged,selected,facts))
                    with self.assertRaises(ar.RewriteError):
                        ar.rewrite(bytes(damaged),entry_offset=START,text_size=0x4000,code_ranges=selected,
                            package_version=2,checked_stack=True,proven_guest_indirect_offsets=(facts['branch'],),
                            readonly_ranges=((TABLE,TABLE+((bound+4)//4*4)),))
        # Reading an incoming index for storage or modifying another register
        # preserves the newly supported plain form; it is not an index transform.
        for word in (0xF900000A,0x2A0903EB,0xD503201F):
            raw,ranges,facts=fixture();damaged=bytearray(raw);struct.pack_into('<I',damaged,START-4,word)
            selected=[(START-4,ranges[0][1]),*ranges[1:]]
            with self.subTest(nonwriter=hex(word)):self.assertIsNotNone(classify(damaged,selected,facts))

    def test_original_sub_u8_regression_is_preserved_without_changing_its_test(self):
        from test_android_runtime_ro_sub_u8 import fixture as original_fixture,rewrite as original_rewrite
        for bound in (64,120):
            with self.subTest(bound=bound),self.assertRaises(ar.RewriteError):
                original_rewrite(original_fixture(bound),0x3E0)
        original_rewrite(original_fixture(63),0x3E0)

    def test_selected_fatal_predecessor_does_not_require_decoder_flag_attributes(self):
        for trap in (0,0xE7FFDEFE):
            raw,ranges,facts=fixture();damaged=bytearray(raw)
            struct.pack_into('<I',damaged,START-4,trap)
            selected=[(START-4,ranges[0][1]),*ranges[1:]]
            with self.subTest(trap=hex(trap)):
                image=ar.rewrite(bytes(damaged),entry_offset=START,text_size=0x4000,code_ranges=selected,
                    package_version=2,checked_stack=True,proven_guest_indirect_offsets=(facts['branch'],),
                    readonly_ranges=((TABLE,TABLE+((len(facts['values'])+3)//4*4)),))
                self.assertEqual(pack(trap),image.bytes[START-4:START])


if __name__=='__main__':unittest.main()
