"""The SDK's eight exact LD1 SP post-index words need complete load bounds."""
import struct
import unittest

from test_android_stack_checks import ar,raw

WORDS={word:amount for base,amount in ((0x4CDF27E0,64),(0x4CDFA7E0,32)) for word in (base,base+4,base+8,base+12)}


class CheckedLd1Tests(unittest.TestCase):
    def test_exact_original_vector_word_gets_full_access_and_sp_bounds(self):
        for word,amount in WORDS.items():
            with self.subTest(word=hex(word)):
                operation=ar.stack_check_operation(word)
                self.assertEqual(operation,{'source':31,'delta':amount,'access_bytes':amount,'post_index':True})
                image=ar.rewrite(raw(0xD10003FF|amount<<10,word,0xD65F03C0),package_version=2,checked_stack=True)
                gate=image.gates[1];origin=image.gate_provenance[1]
                self.assertEqual((gate.argument,origin.original_word),(word,word))
                self.assertEqual(image.bytes[gate.return_offset+8:gate.return_offset+12],raw(word))
                self.assertEqual(struct.unpack_from('<I',image.bytes,gate.return_offset+12)[0],ar.branch(gate.return_offset+12,8))

    def test_unknown_register_list_arrangement_and_register_postindex_refuse(self):
        for word in (0x4CDF27E1,0x4CDF27F0,0x4CDFA7E2,0x4CDEA7E0,0x4CDF07E0,0x4CDF67E0):
            with self.subTest(word=hex(word)):
                self.assertIsNone(ar.stack_check_operation(word))
                with self.assertRaises(ar.RewriteError):
                    ar.rewrite(raw(word,0xD65F03C0),package_version=2,checked_stack=True)


if __name__=='__main__':unittest.main()
