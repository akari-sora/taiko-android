"""An exact six-word native suffix keeps its read-before-kill register effects."""
import struct
import unittest

from test_android_native_lr_table_base import ar, adr, adrp, CpuCase, classify, image_for
from test_android_guarded_native_table import fixture as old_fixture, classify as old_classify
from test_android_runtime_ro_sub_inline import write_image

START, SUB, COMPARE, LOAD, BRANCH, TABLE = 0x40, 0x100, 0x104, 0x124, 0x144, 0x6200
CASE_BASE = BRANCH + 4
TAGS = (0, 4, 12, 18, 33, 67, 93, 111)


def fixture(bound=84):
    raw = bytearray(0x7000)
    struct.pack_into('<3I', raw, START, adrp(START, TABLE, 25), 0x91000339 | (TABLE & 4095) << 10,
                     ar.branch(START + 8, SUB))
    words = [0x5100954E, 0x710001DF | bound << 10,
             0x54000008 | (((0x1800 - (COMPARE + 4)) // 4) << 5),
             0xF90013FB, 0xAA1003F5, 0xF81E03A3, 0x91000536, 0x2A0F03E9,
             adr(LOAD - 4, CASE_BASE, 15), 0x786E7B30, 0x8B1009EF,
             0x2A1F03EA, 0x2A1F03EB, 0xD10013AC, 0x528000FC, 0x52A0004D, 0xAA0103FB, 0xD61F01E0]
    struct.pack_into('<18I', raw, SUB, *words)
    tags = tuple(TAGS[i % len(TAGS)] for i in range(bound + 1))
    struct.pack_into('<' + str(len(tags)) + 'H', raw, TABLE, *tags)
    targets = tuple(sorted({CASE_BASE + tag * 4 for tag in tags}))
    ranges = [(START, START + 12), (SUB, BRANCH + 4), (0x1800, 0x1804)]
    for target in targets:
        struct.pack_into('<I', raw, target, 0xD65F03C0); ranges.append((target, target + 4))
    struct.pack_into('<I', raw, 0x1800, 0xD65F03C0)
    return bytes(raw), sorted(ranges), targets


class NativeU16SixSuffixTests(CpuCase):
    def run_case(self, index=0, **options):
        raw, ranges, targets = fixture(); entry = options.pop('entry', START)
        return self.execute(raw, ranges, targets, branch=BRANCH, load=LOAD, table=TABLE, count=85,
                            entry=entry, index_register=14, table_register=25,
                            target_register=15, case_base=CASE_BASE, index=index,
                            overrides={10: index + 0x25} if entry == START else {}, **options)

    def test_all_85_indices_match_native_original_including_six_suffix_and_frame_stores(self):
        for index in range(85):
            with self.subTest(index=index):
                self.assert_matches_source(self.run_case(index, original=True), self.run_case(index))
        raw, ranges, _ = fixture(); plan = classify(raw, ranges, BRANCH)
        self.assertEqual((84, 'u16-six-native-suffix'), (plan['index_bound'], plan['bound_candidate_kind']))
        image = image_for(raw, ranges, BRANCH, START)
        self.assertEqual(raw[LOAD + 4:BRANCH + 4], image.bytes[LOAD + 4:BRANCH + 4])

    def test_live_bases_full64_index_are_checked_before_read_and_preserve_all_state(self):
        for index, bad in ((0, 'table'), (0, 'wrong-table'), (0, 'base'), (85, None), (1 << 32, None), (2**64 - 1, None)):
            result = self.run_case(index, entry=LOAD, bad=bad)
            self.assertEqual((True, None, 0), (result['trapped'], result['reached'], result['reads']))
            self.assertEqual(result['initial'], result['final']); self.assertEqual(result['initial_memory'], result['memory'])

    def test_exact_prefix_suffix_roles_guard_and_ro_are_required(self):
        raw, ranges, _ = fixture()
        mutations = ((COMPARE + 4, 0x54000000), (LOAD - 24, 0xF80087FB),
                     (LOAD - 20, 0xAA1003EF), (LOAD - 16, 0xF81E0FA3),
                     (LOAD - 12, 0xB1000536), (LOAD - 8, 0x2A1003E9),
                     (LOAD + 8, 0x2A1F03EF), (LOAD + 12, 0x2A1F03EE),
                     (LOAD + 16, 0xD10013AF), (LOAD + 20, 0x728000FC),
                     (LOAD + 24, 0x5280004D), (LOAD + 28, 0xAA0103EF),
                     (LOAD + 28, 0x3100052F), (LOAD + 28, 0xD503201F))
        for pc, word in mutations:
            data = bytearray(raw); struct.pack_into('<I', data, pc, word)
            self.assertIsNone(classify(data, ranges, BRANCH), (hex(pc), hex(word)))
        for entry in range(LOAD + 4, BRANCH + 4, 4):
            self.assertIsNone(classify(raw, ranges, BRANCH, entries=(entry,)))
            with self.assertRaises(ar.RewriteError): image_for(raw, ranges, BRANCH, START, entry_offsets=(entry,))
        self.assertIsNone(classify(raw, ranges, BRANCH, readonly=((TABLE, TABLE + 168),)))
        for bound in (63, 64, 120, 255):
            data, domain, _ = fixture(bound); self.assertIsNotNone(classify(data, domain, BRANCH))
        data, domain, _ = fixture(256); self.assertIsNone(classify(data, domain, BRANCH))
        data, domain, _ = fixture(3); data = bytearray(data)
        struct.pack_into('<I', data, LOAD + 28, 0xD503201F)
        self.assertIsNone(classify(data, domain, BRANCH))

    def test_legacy_byte_bound_64_still_refuses(self):
        source, branch = old_fixture(); write_image(source, 0x3C0, '<I', 0x7101013F)
        self.assertIsNone(old_classify(source, branch))


if __name__ == '__main__': unittest.main()
