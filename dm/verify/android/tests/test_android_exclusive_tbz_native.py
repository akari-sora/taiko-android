"""Native-only shared zero/MOV, CLREX, TBZ retirement; all bytes stay in place."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

LOAD1, CMP1, BNE1, STORE1, RETRY1, LEAVE1 = range(0, 24, 4)
LOAD2, CMP2, BNE2, STORE2, RETRY2, LEAVE2 = range(24, 48, 4)
MOV, CLREX, TBZ, SUCCESS, SUCCESS_RET, UNUSED, ZERO, STR, RET, ALIEN = range(48, 88, 4)


def bne(pc, target):
    return 0x54000001 | ((((target - pc) // 4) & 0x7ffff) << 5)


def cbnz(pc, target):
    return 0x3500000b | ((((target - pc) // 4) & 0x7ffff) << 5)


def tbz(target, reg=8):
    return 0x36000000 | ((((target - TBZ) // 4) & 0x3fff) << 5) | reg


def words(overrides=None):
    values = [
        0xC85FFE8A, 0xEB09015F, bne(BNE1, MOV), 0xC80B7E88,
        cbnz(RETRY1, LOAD1), ar.branch(LEAVE1, SUCCESS),
        0xC85F7E8A, 0xEB09015F, bne(BNE2, MOV), 0xC80BFE88,
        cbnz(RETRY2, LOAD2), ar.branch(LEAVE2, SUCCESS),
        0x2A1F03E8, 0xD5033F5F, tbz(ZERO), 0x52800020, 0xD65F03C0,
        0xD65F03C0, 0x2A1F03E0, 0xF900026A, 0xD65F03C0, 0xD65F03C0,
    ]
    for pc, value in (overrides or {}).items():
        values[pc // 4] = value
    return values


def plan(values, entries=(), kinds_override=None):
    instructions = [ar.decode(value, index * 4) for index, value in enumerate(values)]
    kinds = {i.address: ar.site_kind(i) for i in instructions}
    kinds.update(kinds_override or {})
    return ar.android_exclusive.plan_regions(instructions, kinds, entries, ar)


class NativeSharedTbzTests(unittest.TestCase):
    def assert_refused(self, values, **kwargs):
        with self.assertRaises(ar.RewriteError):
            plan(values, **kwargs)

    def test_mixed_acquire_plain_x_loads_leave_in_place(self):
        self.assertEqual(plan(words()), ())
        self.assertEqual(plan(words({LOAD2: 0xC85FFE8A})), ())

    def test_zero_tbz_uses_taken_target_and_ignores_dead_fallthrough(self):
        self.assertEqual(plan(words({SUCCESS: 0xD4200000})), ())
        self.assert_refused(words({TBZ: tbz(STORE1)}))
        self.assert_refused(words({SUCCESS: ar.branch(SUCCESS, STORE1)}))

    def test_explicit_roots_at_shared_trio_or_attempt_interiors_refused(self):
        for pc in (MOV, CLREX, TBZ, CMP1, BNE1, STORE1):
            with self.subTest(root=pc):
                self.assert_refused(words(), entries=(pc,))

    def test_alien_branch_call_or_fallthrough_into_shared_trio_refused(self):
        for pc in (MOV, CLREX, TBZ):
            for value in (ar.branch(ALIEN, pc), ar.branch(ALIEN, pc) | 0x80000000):
                with self.subTest(target=pc, instruction=value):
                    self.assert_refused(words({ALIEN: value}))
        self.assert_refused(words({LEAVE2: 0xD503201F}))

    def test_load_family_width_address_and_compare_mutations_refused(self):
        for override in (
            {LOAD2: 0x885F7E8A}, {LOAD2: 0xC85F7E6A},
            {LOAD2: 0x085FFE8A}, {CMP2: 0xEB0A013F}, {BNE2: ar.branch(BNE2, MOV)},
        ):
            with self.subTest(override=override):
                self.assert_refused(words(override))

    def test_mov_and_bit_test_mutations_refused(self):
        for override in ({MOV: 0x2A1F03E9}, {MOV: 0x52800028}, {TBZ: tbz(ZERO, 9)},
                         {TBZ: tbz(ZERO) | 0x01000000}):
            with self.subTest(override=override):
                self.assert_refused(words(override))

    def test_live_taken_exit_must_store_loaded_x_value_away_from_cell_then_return(self):
        for override in ({STR: 0xF900028A}, {STR: 0xB900026A}, {STR: 0xF9000269},
                         {ZERO: 0x52800020}, {RET: ar.branch(RET, LOAD1)},
                         {RET: ar.branch(RET, STORE1)}, {RET: 0xD61F0020},
                         {RET: 0xD63F0020}, {RET: 0xD4200000}, {STR: 0xC85FFE8A}):
            with self.subTest(override=override):
                self.assert_refused(words(override))

    def test_a_relocated_attempt_cannot_use_native_retirement_exit(self):
        self.assert_refused(words(), kinds_override={CMP1: 'x18'})
        self.assert_refused(words(), kinds_override={CMP2: 'x18'})


if __name__ == '__main__':
    unittest.main()
