"""Checked SDK pair save/restore must use virtual x18 after real preflight."""
import struct
import unittest

from test_android_stack_checks import ar, ai, raw, mutable_source, write_image
from test_android_rewrite import Machine

SAVE,RESTORE=0xA9BF4FF2,0xA8C14FF2


class CheckedX18PairTests(unittest.TestCase):
    def test_preflight_preserves_exact_original_word_then_virtualizes_pair(self):
        image=ar.rewrite(raw(SAVE,0xD297DDF2,0xD2886433,RESTORE,0xD65F03C0),package_version=2,checked_stack=True)
        self.assertEqual([gate.argument for gate in image.gates],[SAVE,RESTORE])
        for gate,origin in zip(image.gates,image.gate_provenance):
            self.assertEqual((gate.kind,origin.original_word),(5,gate.argument))
            at=gate.return_offset-16
            self.assertEqual(image.bytes[at:at+8],raw(0xD10043FF,ar.pair(False,29,30,0)))
            self.assertEqual(image.bytes[at+16:at+24],raw(ar.pair(True,29,30,0),0x910043FF))
            frame,cleanup=(64,48) if gate.argument==SAVE else (48,64)
            self.assertEqual(struct.unpack_from('<I',image.bytes,at+24)[0],0xD10003FF|frame<<10)
            self.assertEqual(struct.unpack_from('<I',image.bytes,at+80)[0],0x910003FF|cleanup<<10)
            ops=list(ar.MD.disasm(image.bytes[at:at+88],at))
            self.assertFalse(any(ar.has18(op) for op in ops))
            self.assertEqual(ops[-1].operands[0].imm,origin.original_offset+4)

    def test_both_source_effects_memory_flags_gprs_and_stack_are_preserved(self):
        image=ar.rewrite(raw(SAVE,0xD297DDF2,0xD2886433,RESTORE,0xD65F03C0),package_version=2,checked_stack=True)
        model=Machine(image);before=list(model.x);value=0xFEDCBA9876543210
        model.store(model.state,value,8);model.flags=0xA0000000
        model.store(model.start_sp-1024,0xCAFEBABE12345678,8)
        model.run()
        self.assertEqual(model.x,before)
        self.assertEqual(model.load(model.state,8),value)
        self.assertEqual(model.sp,model.start_sp)
        self.assertEqual(model.flags,0xA0000000)
        self.assertEqual(model.load(model.start_sp-16,8),value)
        self.assertEqual(model.load(model.start_sp-8,8),before[19])
        self.assertEqual(model.load(model.start_sp-1024,8),0xCAFEBABE12345678)
        self.assertEqual(model.calls,[(5,SAVE),(5,RESTORE)])

    def test_original_import_retains_provenance_and_unobserved_writeback_refuses(self):
        source=mutable_source();write_image(source,0,'<I',0x140000C0)
        write_image(source,0x300,'<3I',SAVE,RESTORE,0xD65F03C0)
        _,report=ai.import_module(source,'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        self.assertEqual([gate['argument'] for gate in report['rewrite']['gates'] if gate['kind']==5 and gate['argument'] in (SAVE,RESTORE)],[SAVE,RESTORE])
        for word in (0xA9BE4FF2,0xA8C24FF2,0x29BE4FF2,0xF81F0FF2):
            with self.subTest(word=hex(word)),self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(word,0xD65F03C0),package_version=2,checked_stack=True)


if __name__=='__main__':unittest.main()
