"""Literal/code intersection preserves semantics without scanning every word."""
from pathlib import Path
import random
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai


class LiteralOverlapTests(unittest.TestCase):
    def test_equivalence_for_scalar_vector_and_unaligned_literal_spans(self):
        rng=random.Random(74921)
        for _ in range(30):
            words={pc:None for pc in range(0,256,4) if rng.randrange(3)==0}
            for start in range(-3,260):
                for size in (4,8,16):
                    expected=any(start<=pc<start+size for pc in words)
                    self.assertEqual(ai._literal_overlaps_code(words,start,start+size),expected,
                                     (sorted(words),start,size))

    def test_probe_count_is_bounded_by_literal_width_not_module_size(self):
        class AlignedWords(dict):
            probes=0
            def __iter__(self):
                raise AssertionError('literal check scanned all module instructions')
            def __contains__(self,key):
                self.probes+=1
                return super().__contains__(key)
        words=AlignedWords({pc:None for pc in range(0,1000000,4)})
        for size in (4,8,16):
            for start in (1000001,1000002,1000003,1000004):
                words.probes=0
                self.assertFalse(ai._literal_overlaps_code(words,start,start+size))
                self.assertLessEqual(words.probes,size//4)
        self.assertFalse(ai._literal_overlaps_code(words,12,12))


if __name__=='__main__':
    unittest.main()
