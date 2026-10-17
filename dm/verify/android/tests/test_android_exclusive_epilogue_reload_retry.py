"""Failed STLXR may fall through to a reload when CBZ enters a plain epilogue."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

HEAD, MOV, COMPARE, STORE, STATUS, RELOAD, LINK, CLEAR = range(0, 32, 4)
EPILOGUE, EPILOGUE_LDP, EPILOGUE_ADD, EPILOGUE_RET = range(32, 48, 4)
BR_X17, BLR_X17 = 0xD61F0220, 0xD63F0220


def cbz(pc, reg, target):
    return 0x34000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def cbnz(pc, reg, target):
    return 0x35000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def bl(pc, target):
    return 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)


def words(overrides=()):
    # Decoded Enter success exit: ldp / ldp / add sp / ret. CBZ takes it.
    # Failure falls through to ldaxr w8, [x19]; b <compare>.
    source = {
        HEAD: 0x885FFC08,  # ldaxr w8, [x0]
        MOV: 0xAA0003F3,  # mov x19, x0
        COMPARE: cbnz(COMPARE, 8, CLEAR),
        STORE: 0x8808FE74,  # stlxr w8, w20, [x19]
        STATUS: cbz(STATUS, 8, EPILOGUE),
        RELOAD: 0x885FFE68,  # ldaxr w8, [x19]
        LINK: ar.branch(LINK, COMPARE),
        CLEAR: 0xD5033F5F,  # clrex
        EPILOGUE: 0xA9424FF4,  # ldp x20, x19, [sp, #0x20]
        EPILOGUE_LDP: 0xA9417BFD,  # ldp x29, x30, [sp, #0x10]
        EPILOGUE_ADD: 0x9100C3FF,  # add sp, sp, #0x30
        EPILOGUE_RET: 0xD65F03C0,
    }
    source.update(overrides)
    return [source[pc] for pc in range(0, EPILOGUE_RET + 4, 4)]


def raw(source):
    return struct.pack('<' + 'I' * len(source), *source)


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source, roots=(0,)):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class ExclusiveEpilogueReloadRetryTests(unittest.TestCase):
    def test_cbz_epilogue_falls_through_to_the_same_cell_reload(self):
        source = words()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        body = {HEAD, MOV, COMPARE, STORE, CLEAR}
        tail, edges = ar.android_exclusive.retry_tail(by_pc, by_pc[STORE], HEAD, body, ar)
        self.assertEqual(tail, {STATUS, RELOAD, LINK})
        self.assertEqual(edges, {(LINK, COMPARE)})
        self.assertEqual(
            [by_pc[pc].mnemonic for pc in (EPILOGUE, EPILOGUE_LDP, EPILOGUE_ADD, EPILOGUE_RET)],
            ['ldp', 'ldp', 'add', 'ret'])
        self.assertEqual(plan(source), ())

    def test_indirect_call_other_register_and_body_target_stay_rejected(self):
        rejected = (
            words({EPILOGUE_RET: BR_X17}),
            words({EPILOGUE_LDP: BLR_X17}),
            words({EPILOGUE_ADD: bl(EPILOGUE_ADD, EPILOGUE_RET)}),
            words({RELOAD: 0x885FFE69}),  # ldaxr w9, [x19]
            words({RELOAD: 0x885FFC28}),  # ldaxr w8, [x1]
            words({STATUS: cbz(STATUS, 8, MOV)}),
            words({STATUS: cbz(STATUS, 8, COMPARE)}),
            words({LINK: ar.branch(LINK, MOV)}),  # reaches the compare, but is not it
        )
        for source in rejected:
            with self.subTest(status=f'{source[STATUS // 4]:08x}', reload=f'{source[RELOAD // 4]:08x}',
                              link=f'{source[LINK // 4]:08x}',
                              success=f'{source[EPILOGUE // 4]:08x}'), \
                    self.assertRaises(ar.RewriteError):
                plan(source)


if __name__ == '__main__':
    unittest.main()
