"""Independent ADD entry invalidates page consumption; keep original negatives."""
from dataclasses import replace
import struct
import unittest
import test_android_adrp_consumed_page as old

class AdrpConsumedEntryTests(unittest.TestCase):
    def test_independent_add_entry_keeps_page_and_rejects_atomic_interior(self):
        nso,metadata=old.fixture()
        metadata=replace(metadata,init_addresses=(*metadata.init_addresses,0x1024))
        ranges,report=old.discover(nso,metadata)
        self.assertIn(0x1000,report['address_taken_roots'])
        self.assertIn(0x1000,report['roots'])
        with self.assertRaisesRegex(old.ar.RewriteError,'entry.*exclusive'):
            old.rewrite(nso,ranges,report)

    def test_late_add_entry_reaches_fixed_point_and_keeps_page_and_prior_final(self):
        nso,metadata=old.fixture();image=bytearray(nso.image)
        struct.pack_into('<2I',image,0xF00,0x10000922,0xD65F03C0) # ADR X2,0x1024;RET.
        nso=replace(nso,image=bytes(image))
        metadata=replace(metadata,init_addresses=(*metadata.init_addresses,0xF00))
        ranges,report=old.discover(nso,metadata)
        self.assertIn(0x1024,report['address_taken_roots'])
        self.assertIn(0x1000,report['address_taken_roots'])
        self.assertIn(0x17E4,report['address_taken_roots'])
        with self.assertRaisesRegex(old.ar.RewriteError,'entry.*exclusive'):
            old.rewrite(nso,ranges,report)

    def test_final_eh_entry_remains_independent_when_add_is_an_entry(self):
        nso,metadata=old.fixture()
        metadata=replace(metadata,init_addresses=(*metadata.init_addresses,0x1024),eh_starts=(0x17E4,))
        ranges,report=old.discover(nso,metadata)
        self.assertIn(0x17E4,report['roots'])
        self.assertIn(0x17E4,report['independent_roots'])
        self.assertTrue(any(start<=0x17E4<end for start,end in ranges))
        self.assertIn(0x1000,report['address_taken_roots'])
        with self.assertRaisesRegex(old.ar.RewriteError,'entry.*exclusive'):
            old.rewrite(nso,ranges,report)

if __name__=='__main__':unittest.main(verbosity=2)
