"""Authored two-caller ABI and independent byte audit; no original game bytes."""
import copy
from dataclasses import asdict
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'.local/test-env/Lib/site-packages')]
import android_rewrite as ar
import taiko_forest_audit as audit
import test_taiko_checked_call as fixed
import test_taiko_forest_audit as authored
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_INTR
from unicorn import arm64_const as uc


def multi_fixture():
    image,forest,targets,args=authored.authored_fixture()
    first=args['trampoline'];second=first+64;literal=(second+67)&~7
    image.extend(bytes(literal+8-len(image)))
    for source,stub in ((0,first),(64,second)):
        authored.put(image,source,authored.jump(source,stub))
        authored.put(image,stub,0xD10103FF,0xA9007BF0,0xA90107E0,
            0x58000010|((literal-stub-12)//4)<<5,0xD63F0200,0xAA1003E1,0xA9407BF0,
            0xF90013E2,0xD53B4202,0xF90017E2,0xF9400020,
            *authored.address(stub+44,source+4,30),0xF9001BFE,authored.jump(stub+56,forest['root']))
    image[literal:literal+8]=bytes(8)
    forest['site_offsets']=[0,64]
    return image,forest,targets,dict(callers=[dict(offset=0,trampoline=first),dict(offset=64,trampoline=second)],
        patch_start=0x4000,fixups=[dict(offset=literal,helper=1)])


class MultiCallerAuditTests(unittest.TestCase):
    def test_two_authored_callers_share_exactly_one_complete_forest(self):
        image,forest,targets,args=multi_fixture()
        self.assertEqual(forest,audit.verify_emitted_forest(image,forest,targets,**args))

    def test_each_stub_word_and_own_continuation_are_independently_checked(self):
        fixture=multi_fixture()
        for caller in fixture[3]['callers']:
            for word in range(15):
                image,forest,targets,args=copy.deepcopy(fixture);at=caller['trampoline']+4*word
                authored.put(image,at,struct.unpack_from('<I',image,at)[0]^1)
                with self.subTest(caller=caller['offset'],word=word),self.assertRaises(ValueError):
                    audit.verify_emitted_forest(image,forest,targets,**args)

    def test_missing_extra_reordered_duplicate_overlap_and_fixup_claims_refuse(self):
        for mutation in ('missing','extra','reorder','duplicate','overlap','literal-in-other-stub','fixup-in-other-stub','site-list'):
            image,forest,targets,args=multi_fixture()
            if mutation=='missing':args['callers'].pop()
            elif mutation=='extra':args['callers'].append(dict(offset=128,trampoline=args['callers'][-1]['trampoline']+64))
            elif mutation=='reorder':args['callers'].reverse()
            elif mutation=='duplicate':args['callers'].append(args['callers'][0])
            elif mutation=='overlap':args['callers'][1]['trampoline']=args['callers'][0]['trampoline']+4
            elif mutation=='literal-in-other-stub':
                first,second=args['callers'];at=first['trampoline']+12
                authored.put(image,at,0x58000010|((second['trampoline']-at)//4)<<5)
            elif mutation=='fixup-in-other-stub':args['fixups'].append(dict(offset=args['callers'][1]['trampoline'],helper=1))
            else:forest['site_offsets']=[0]
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                audit.verify_emitted_forest(image,forest,targets,**args)


class MultiCallerCpuTests(unittest.TestCase):
    def image(self):
        callback=fixed.fixture()[0][0x100:]
        # Capture ten full8-byte ABI slots after the all-register observation.
        extra=[]
        for slot in range(10):extra.extend((ar.memory(True,0,31,slot*8),ar.memory(False,0,28,0x400+slot*8)))
        callback=callback[:-4]+fixed.raw(*extra,0xD65F03C0)
        targets=(0x100,0x400,0x700);source=bytearray(0x700+len(callback))
        for caller in (0,64):source[caller:caller+8]=fixed.raw(0xD63F0240,0xD4200020)
        for target in targets:source[target:target+len(callback)]=callback
        ranges=[(0,8),(64,72),*((target,target+len(callback)) for target in targets)]
        image=ar.rewrite(bytes(source),code_ranges=ranges,entry_offsets=(0,64,*targets),package_version=2,
            checked_stack=True,checked_call_forest_offsets=(0,64),checked_call_forest_targets=targets)
        return image,targets,len(source)

    def execute(self,caller,value):
        image,targets,patch=self.image();base,state,helper,output,stack=0x10000000,0x30000000,0x30001000,0x30002000,0x20008000
        cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM);cpu.mem_map(base,0x10000);cpu.mem_map(0x20000000,0x10000);cpu.mem_map(state,0x10000)
        cpu.mem_write(base,image.bytes);cpu.mem_write(helper,fixed.raw(0x58000050,0xD65F03C0)+struct.pack('<Q',state))
        for item in image.fixups:cpu.mem_write(base+item.offset,struct.pack('<Q',helper))
        cpu.mem_write(state,struct.pack('<Q',value))
        registers=[0x1234567800000000+i*0x10101 for i in range(31)];registers[28]=output
        for i,v in enumerate(registers):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),v)
        vectors=[int.from_bytes(bytes((i+j)%256 for j in range(16)),'little') for i in range(32)]
        for i,v in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),v)
        cpu.reg_write(uc.UC_ARM64_REG_SP,stack);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
        # Match the new caller's ten stores: slot3 alone carries full X12;
        # every W store preserves the upper four padding bytes of its slot.
        arguments=b''.join(struct.pack('<Q',registers[register]) if register==12 else
            struct.pack('<II',registers[register]&0xFFFFFFFF,0xAABBCC00+slot)
            for slot,register in enumerate((9,10,11,12,13,14,15,16,17,8)))+bytes(range(80))
        cpu.mem_write(stack,arguments);observed=dict(returned=False,trapped=False,target=False)
        def step(machine,pc,size,_):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I',machine.mem_read(pc,4))[0],pc)))
            if pc in {base+t for t in targets}:observed['target']=True
            if pc==base+caller+4:observed['returned']=True;machine.emu_stop()
        def trap(machine,number,_):observed['trapped']=True;machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE,step);cpu.hook_add(UC_HOOK_INTR,trap);cpu.emu_start(base+caller,base+len(image.bytes),count=10000)
        self.assertEqual(arguments,bytes(cpu.mem_read(stack,160)))
        self.assertEqual((stack,registers[18]),(cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_X18)))
        return cpu,observed,registers,vectors,output,stack,arguments,image,targets,patch

    def test_each_callee_observes_own_lr_and_all_ten_stack_slots_padding_and_state(self):
        for caller in (0,64):
            for target in (0x100,0x400,0x700):
                cpu,seen,registers,vectors,out,stack,args,image,targets,patch=self.execute(caller,0x10000000+target)
                self.assertEqual(dict(returned=True,trapped=False,target=True),seen)
                expected=registers[:];expected[18]=0x10000000+target;expected[30]=0x10000000+caller+4
                self.assertEqual(expected,list(struct.unpack('<31Q',cpu.mem_read(out,248))))
                self.assertEqual((0xB0000000,stack),struct.unpack('<2Q',cpu.mem_read(out+0x300,16)))
                self.assertEqual(args[:80],bytes(cpu.mem_read(out+0x400,80)))
                self.assertEqual(registers[12],struct.unpack_from('<Q',args,24)[0])
                for i,v in enumerate(vectors):self.assertEqual(v,int.from_bytes(cpu.mem_read(out+0x100+i*16,16),'little'))
                self.assertEqual(1,len(image.metadata()['checked_call_forests']))
                audit.verify_emitted_forest(image.bytes,image.metadata()['checked_call_forests'][0],targets,
                    callers=[dict(offset=s.offset,trampoline=s.trampoline) for s in image.sites if s.offset in (0,64)],
                    patch_start=patch,fixups=[asdict(f) for f in image.fixups])

    def test_unknown_native_othermodule_null_and_interior_restore_everything(self):
        for caller in (0,64):
            for value in (0,0x30001000,0x20000100,0x10000104,0xFFFFFFFFFFFFFFFF):
                cpu,seen,registers,vectors,*_=self.execute(caller,value)
                self.assertEqual(dict(returned=False,trapped=True,target=False),seen)
                self.assertEqual(registers,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)])
                self.assertEqual(vectors,[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)])
                self.assertEqual(0xB0000000,cpu.reg_read(uc.UC_ARM64_REG_NZCV))


if __name__=='__main__':unittest.main()
