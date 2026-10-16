"""Read the actual EL0 cache geometry; never fabricate it or permit writes."""
import unittest
from test_android_rewrite import ar,raw


class CacheGeometryTests(unittest.TestCase):
    def test_exact_readonly_ctr_is_native_and_virtual_x18_uses_existing_lowering(self):
        for register in (0,8,16,17,18,29,30,31):
            source=raw(0xD53B0020|register,0xD65F03C0)
            image=ar.rewrite(source)
            with self.subTest(register=register):
                self.assertEqual(ar.site_kind(ar.decode(0xD53B0020|register,0)),'x18' if register==18 else None)
                self.assertEqual(len(image.sites),1 if register==18 else 0)
                if register!=18:self.assertEqual(image.bytes[:8],source)
                else:self.assertEqual(image.sites[0].offset,0)

    def test_ctr_writes_and_other_unapproved_registers_still_refuse(self):
        for value in (0xD51B0020,0xD51B0032,0xD5380000):
            with self.subTest(value=hex(value)),self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(value,0xD65F03C0))

    def test_potential_kernel_ctr_emulation_cannot_enter_an_exclusive_window(self):
        with self.assertRaisesRegex(ar.RewriteError,'exclusive|trap'):
            ar.rewrite(raw(0x885FFC20,0xD53B0022,0x8803FC20,0x35FFFFA3,0xD65F03C0))


if __name__=='__main__':unittest.main()
