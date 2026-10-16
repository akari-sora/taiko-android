"""Virtual ADR remains image-relative when its trampoline is over 1MiB away."""
import hashlib
import unittest
from test_android_rewrite import ar,raw,Machine
from test_android_runtime_ro_backward import adr


class FarAdrTests(unittest.TestCase):
    def test_far_trampoline_keeps_target_low_bits_flags_and_hardware_x18(self):
        for source_pc,target in ((0,0x678),(0,0x679),(0x20,0x10),(0,0x1008)):
            source=raw(*([0xD503201F]*(source_pc//4)),adr(source_pc,target,18),0xAA1203E0,0xD65F03C0)
            image=ar.rewrite(source,entry_offset=source_pc,patch_offset=0x120000)
            model=Machine(image);before=list(model.x);model.flags=0xA0000000;model.run()
            before[0]=target
            self.assertEqual((model.x,model.sp,model.flags,model.load(model.state,8)),
                             (before,model.start_sp,0xA0000000,target))

    def test_supported_near_adr_and_adrp_keep_their_previous_binary_identity(self):
        for opcode,digest in ((0x10000092,'1087bb8d5ca8019f904e18954ea121bbf185c5c924ae0b50eb0dfc8c3890799e'),
                              (0xB0000012,'043e21b638b08532c6f1f22668dd67d5ba672eacaa88279d3707ef4a116878e8')):
            source=raw(opcode,0xAA1203E0,0xD65F03C0,0xD503201F,0xD503201F)
            self.assertEqual(hashlib.sha256(ar.rewrite(source).bytes).hexdigest(),digest)

    def test_beyond_page_reach_and_unmodified_literal_range_still_refuse(self):
        with self.assertRaisesRegex(ar.RewriteError,'PC-relative target out of range'):
            ar.Emitter(bytes(4096)).x18(ar.decode(0x10000012,1<<33))
        with self.assertRaisesRegex(ar.RewriteError,'literal target out of range'):
            ar.rewrite(raw(0x58000092,0xAA1203E0,0xD65F03C0),patch_offset=0x120000)


if __name__=='__main__':unittest.main()
