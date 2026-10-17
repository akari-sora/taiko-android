"""A live Enter reservation may leave only through SVC #0x1A; RET."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

LOAD, CALL, LATER, STUB, BAD = 0, 32, 36, 48, 56
SVC1A, RET = 0xD4000341, 0xD65F03C0
SVC36 = 0xD40006C1


def tbnz(pc, reg, bit, target):
    imm = (target - pc) // 4
    return 0x37000000 | ((bit & 32) << 26) | ((bit & 31) << 19) | ((imm & 0x3FFF) << 5) | reg


def bl(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)


def words(stub=(SVC1A, RET), call_target=STUB, call_word=None):
    # Bit 0 set skips both STLXR sites. Their fallthroughs stay outside.
    # The return at LATER is the indirect stub and must not stay live.
    source = {
        LOAD: 0x885FFC08,
        4: tbnz(4, 8, 0, CALL),
        8: tbnz(8, 8, 1, 24),
        12: ar.branch(12, 16),
        16: 0x8809FC08,
        20: ar.branch(20, 44),
        24: 0x880AFC08,
        28: ar.branch(28, 44),
        CALL: bl(CALL, call_target) if call_word is None else call_word,
        LATER: bl(LATER, BAD),
        40: RET,
        44: RET,
        STUB: stub[0],
        STUB + 4: stub[1],
        BAD: 0x90000010,
        60: 0xF9400211,
        64: 0x91000210,
        68: 0xD61F0220,
    }
    return [source[pc] for pc in range(0, 72, 4)]


def raw(source):
    return struct.pack('<' + 'I' * len(source), *source)


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source, roots=(0, LATER, STUB, BAD)):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class ExclusiveSvc1aCallTests(unittest.TestCase):
    def test_enter_shape_matches_the_skipped_store_call(self):
        source = words()
        instructions, _ = decoded(source)
        self.assertEqual(instructions[1].operands[-1].imm, CALL)
        self.assertEqual(instructions[CALL // 4].operands[-1].imm, STUB)
        self.assertEqual(instructions[LATER // 4].operands[-1].imm, BAD)
        self.assertEqual(
            [instructions[pc // 4].mnemonic for pc in (0, 16, 24, CALL, LATER, STUB, STUB + 4, BAD, 60, 64, 68)],
            ['ldaxr', 'stlxr', 'stlxr', 'bl', 'bl', 'svc', 'ret', 'adrp', 'ldr', 'add', 'br'])
        self.assertEqual(instructions[68 // 4].op_str, 'x17')
        self.assertTrue(ar.android_exclusive.direct_svc1a_ret_call(instructions[CALL // 4],
                                                                    {ins.address: ins for ins in instructions}, ar))

    def test_exact_svc1a_ret_ends_the_enter_reservation(self):
        source = words()
        self.assertEqual(plan(source), ())
        image = ar.rewrite(raw(source))
        original = raw(source)
        self.assertEqual(image.bytes[:STUB], original[:STUB])
        self.assertEqual(image.bytes[STUB + 4:len(original)], original[STUB + 4:])
        self.assertEqual(len(image.sites), 1)
        self.assertEqual(image.sites[0].offset, STUB)
        self.assertEqual(struct.unpack_from('<I', image.bytes, image.sites[0].trampoline)[0], 0xD5033F5F)
        self.assertEqual(image.gates[0].argument, 0x1A)
        self.assertEqual(struct.unpack_from('<I', image.bytes, LATER)[0], source[LATER // 4])

    def test_live_br_stub_and_other_svc_ret_stay_rejected(self):
        rejected = (
            words(call_target=BAD),
            words(stub=(SVC36, RET)),
            words(stub=(SVC1A, 0xD503201F)),
            words(call_word=0xD63F0220),
            words(call_word=0xD61F0220),
        )
        for source in rejected:
            with self.subTest(call=f'{source[CALL // 4]:08x}', stub=f'{source[STUB // 4]:08x}'), \
                    self.assertRaisesRegex(ar.RewriteError, 'unbounded exclusive call'):
                plan(source)
            with self.subTest(rewrite=f'{source[CALL // 4]:08x}'), \
                    self.assertRaisesRegex(ar.RewriteError, 'unbounded exclusive call'):
                ar.rewrite(raw(source))

    def test_x18_monitor_retiring_call_is_not_relocated(self):
        source = words()
        source[12 // 4] = 0x91000652
        with self.assertRaisesRegex(ar.RewriteError, 'not relocated'):
            plan(source)


if __name__ == '__main__':
    unittest.main()
