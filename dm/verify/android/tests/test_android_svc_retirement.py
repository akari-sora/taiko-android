"""Generic gate retirement assertions; no game input or platform state shortcut."""
import importlib.util
import os
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
path=Path(os.environ.get('RETIRE_REWRITER',str(ROOT/'dm/tools/android_rewrite.py')))
spec=importlib.util.spec_from_file_location('retire_test_ar',path)
ar=importlib.util.module_from_spec(spec);sys.modules[spec.name]=ar;spec.loader.exec_module(ar)

def image(svc):
    return ar.rewrite(struct.pack('<II',0xd4000001|(svc<<5),0xd65f03c0))

class RetirementTests(unittest.TestCase):
    def test_1a_prefix_retires_before_first_frame_or_helper(self):
        self.prefix(0x1a)

    def test_36_prefix_retires_before_first_frame_or_helper(self):
        self.prefix(0x36)

    def prefix(self,svc):
        im=image(svc);site=im.sites[0]
        words=struct.unpack_from('<IIIII',im.bytes,site.trampoline)
        self.assertEqual(words[:3],(0xd5033f5f,0xd10043ff,0xa9007bfd))
        self.assertEqual(ar.decode(words[3],site.trampoline+12).mnemonic,'ldr')
        self.assertEqual(words[4],0xd63f03c0)
        self.assertEqual((im.gates[0].argument,im.gates[0].return_offset),(svc,site.trampoline+20))
        self.assertEqual(im.gate_provenance[0].original_word,0xd4000001|svc<<5)
        self.assertEqual(im.gate_provenance[0].original_offset,0)
        self.assertEqual(struct.unpack_from('<I',im.bytes,site.trampoline+20)[0],0xa9407bfd)
        self.assertEqual(struct.unpack_from('<I',im.bytes,site.trampoline+24)[0],0x910043ff)

    def test_unlisted_service_has_no_retirement_prefix(self):
        im=image(0x21)
        self.assertEqual(struct.unpack_from('<II',im.bytes,im.sites[0].trampoline),(0xd10043ff,0xa9007bfd))
        self.assertEqual(im.gates[0].return_offset,im.sites[0].trampoline+16)

    def test_nonservice_gate_does_not_inherit_svc_number_policy(self):
        e=ar.Emitter(bytes(8));ins=ar.decode(0xd63f0120,0)
        e.gate(ins,indirect=True);e.finish()
        self.assertEqual(struct.unpack_from('<II',e.data,8),(0xd10043ff,0xa9007bfd))
        self.assertEqual(e.gates[0].kind,ar.INDIRECT_HOST)

    def test_retirement_changes_no_gpr_simd_flags_sp_or_guest_memory(self):
        # Execute the actual emitted prefix, not a hand-written state transition.
        # This proves CPU-model prefix effects, not backend/physical execution.
        from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM
        from unicorn import arm64_const as uc
        im=image(0x36);word=struct.unpack_from('<I',im.bytes,im.sites[0].trampoline)[0]
        self.assertEqual(word,0xd5033f5f)
        for prefix,expected in ((word,1),(0xd503201f,0)):
            cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
            base,cell,tlr,stack=0x100000,0x400000,0x500000,0x800000
            for page in (base,cell,tlr,stack):cpu.mem_map(page,4096)
            cpu.mem_write(base,struct.pack('<III',0x885ffc00|19<<5|9,prefix,0x88007c00|10<<16|19<<5|8))
            cpu.mem_write(cell,struct.pack('<I',0x12345678));cpu.mem_write(tlr,bytes(range(256))*2)
            for n in range(31):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{n}'),0x1010101010000000+n)
            for n in range(32):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{n}'),int.from_bytes(bytes([n])*16,'little'))
            for reg,value in ((uc.UC_ARM64_REG_SP,stack+0x800),(uc.UC_ARM64_REG_NZCV,0xb0000000),
                              (uc.UC_ARM64_REG_FPSR,0x9f),(uc.UC_ARM64_REG_FPCR,0x1000000),
                              (uc.UC_ARM64_REG_X19,cell),(uc.UC_ARM64_REG_X8,0x98765432)):
                cpu.reg_write(reg,value)
            regs=[getattr(uc,f'UC_ARM64_REG_X{n}') for n in range(31)]+[getattr(uc,f'UC_ARM64_REG_Q{n}') for n in range(32)]+[
                uc.UC_ARM64_REG_SP,uc.UC_ARM64_REG_NZCV,uc.UC_ARM64_REG_FPSR,uc.UC_ARM64_REG_FPCR]
            cpu.emu_start(base,base+4,count=1)
            before=[cpu.reg_read(reg) for reg in regs]
            mem_before=bytes(cpu.mem_read(cell,4096))+bytes(cpu.mem_read(tlr,4096))+bytes(cpu.mem_read(stack,4096))
            cpu.emu_start(base+4,base+8,count=1)
            self.assertEqual(before,[cpu.reg_read(reg) for reg in regs])
            self.assertEqual(mem_before,bytes(cpu.mem_read(cell,4096))+bytes(cpu.mem_read(tlr,4096))+bytes(cpu.mem_read(stack,4096)))
            cpu.emu_start(base+8,base+12,count=1)
            self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_W10),expected)
            self.assertEqual(bytes(cpu.mem_read(cell,4)),struct.pack('<I',0x12345678 if expected else 0x98765432))

    def test_arbitrary_live_exclusive_svc_stays_refused(self):
        for svc in (0x36,0x1a):
            raw=struct.pack('<IIII',0x885ffc09,0xd4000001|svc<<5,0x880a7c08,0xd65f03c0)
            with self.subTest(svc=svc),self.assertRaises(ar.RewriteError):ar.rewrite(raw)

if __name__=='__main__':unittest.main(verbosity=2)
