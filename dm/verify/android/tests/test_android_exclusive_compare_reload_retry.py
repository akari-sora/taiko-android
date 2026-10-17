"""Failed STLXR may reload the same cell and branch to its dominating compare."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

HEAD, MOV, COMPARE, SKIP, SETUP, STORE, STATUS = range(0, 28, 4)
CALL, AFTER, RELOAD, LINK, STUB, STUB_RET = range(28, 52, 4)
SVC1A, RET = 0xD4000341, 0xD65F03C0
BR_X17, BLR_X17 = 0xD61F0220, 0xD63F0220


def cbnz(pc, reg, target):
    return 0x35000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def bl(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)


def words(overrides=()):
    source = {
        HEAD: 0x885FFC08,  # ldaxr w8, [x0]
        MOV: 0xAA0003F3,  # mov x19, x0
        COMPARE: cbnz(COMPARE, 8, SETUP),
        SKIP: ar.branch(SKIP, CALL),
        SETUP: 0x2A0803E9,  # mov w9, w8
        STORE: 0x880AFE69,  # stlxr w10, w9, [x19]
        STATUS: cbnz(STATUS, 10, RELOAD),
        CALL: bl(CALL, STUB),
        AFTER: RET,
        RELOAD: 0x885FFE68,  # ldaxr w8, [x19]
        LINK: ar.branch(LINK, COMPARE),
        STUB: SVC1A,
        STUB_RET: RET,
    }
    source.update(overrides)
    return [source[pc] for pc in range(0, STUB_RET + 4, 4)]


def raw(source):
    return struct.pack('<' + 'I' * len(source), *source)


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source, roots=(0, STUB)):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class ExclusiveCompareReloadRetryTests(unittest.TestCase):
    def test_same_cell_reload_branches_to_the_dominating_compare(self):
        source = words()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        body = {HEAD, MOV, COMPARE, SKIP, SETUP, STORE, CALL}
        tail, edges = ar.android_exclusive.retry_tail(by_pc, by_pc[STORE], HEAD, body, ar)
        self.assertEqual(tail, {STATUS, RELOAD, LINK})
        self.assertEqual(edges, {(LINK, COMPARE)})
        self.assertEqual(plan(source), ())
        image = ar.rewrite(raw(source))
        original = raw(source)
        self.assertEqual(image.bytes[HEAD:CALL + 4], original[HEAD:CALL + 4])
        self.assertEqual(image.bytes[RELOAD:STUB], original[RELOAD:STUB])
        self.assertEqual(len(image.sites), 1)
        self.assertEqual(image.sites[0].offset, STUB)
        self.assertEqual(image.gates[0].argument, 0x1A)

    def test_unknown_target_other_register_and_indirect_success_stay_rejected(self):
        rejected = (
            words({RELOAD: 0x885FFC28}),  # ldaxr w8, [x1]
            words({RELOAD: 0x885FFE69}),  # ldaxr w9, [x19]; compare still tests w8
            words({COMPARE: cbnz(COMPARE, 9, SETUP), RELOAD: 0x885FFE69}),  # ldaxr w8; cbnz w9; ldaxr w9, [x19]
            words({LINK: ar.branch(LINK, 0x80)}),
            words({LINK: ar.branch(LINK, HEAD)}),
            words({SETUP: 0xAA0103F3}),  # mov x19, x1
            self.bridged(BR_X17),
            self.bridged(BLR_X17),
            self.undominated_compare(),
        )
        for source in rejected:
            with self.subTest(store=f'{source[STORE // 4]:08x}', link=f'{source[LINK // 4]:08x}',
                              success=f'{source[(STATUS // 4) + 1]:08x}'), \
                    self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven exclusive retry tail'):
                plan(source)

    def bridged(self, transfer):
        """Status falls through to BR/BLR; SKIP still reaches SVC #0x1A; RET."""
        call, after, reload, link, stub, stub_ret = range(32, 56, 4)
        source = {
            HEAD: 0x885FFC08,
            MOV: 0xAA0003F3,
            COMPARE: cbnz(COMPARE, 8, SETUP),
            SKIP: ar.branch(SKIP, call),
            SETUP: 0x2A0803E9,
            STORE: 0x880AFE69,
            STATUS: cbnz(STATUS, 10, reload),
            28: transfer,
            call: bl(call, stub),
            after: RET,
            reload: 0x885FFE68,
            link: ar.branch(link, COMPARE),
            stub: SVC1A,
            stub_ret: RET,
        }
        return [source[pc] for pc in range(0, stub_ret + 4, 4)]

    def undominated_compare(self):
        """The reload branches to a later cbnz w8 that does not dominate the store."""
        return words({SKIP: cbnz(SKIP, 8, CALL), LINK: ar.branch(LINK, SKIP)})


if __name__ == '__main__':
    unittest.main()
