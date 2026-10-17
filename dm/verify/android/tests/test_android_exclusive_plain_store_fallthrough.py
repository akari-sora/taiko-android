"""Failed STLXR may fall through a plain store into its owning load."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar


def cbnz(pc, reg, target):
    return 0x35000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def cbz(pc, reg, target):
    return 0x34000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | reg


def bne(pc, target):
    return 0x54000001 | ((((target - pc) // 4) & 0x7FFFF) << 5)


def b(pc, target):
    return 0x14000000 | (((target - pc) // 4) & 0x3FFFFFF)


def tbz(pc, reg, bit, target):
    imm = (target - pc) // 4
    return 0x36000000 | ((bit & 32) << 26) | ((bit & 31) << 19) | ((imm & 0x3FFF) << 5) | reg


def build(gap=False, overrides=None):
    pc = {
        'LEAVE': 0, 'LDP': 4, 'RET': 8, 'CLREX': 12,
        'ZERO': 16, 'COPY': 20, 'DEAD': 24, 'PLAIN': 28,
    }
    cursor = 32
    if gap:
        pc['GAP'] = cursor
        cursor += 4
    for name in ('HEAD', 'CMP', 'BNE', 'STORE', 'STATUS', 'SUCCESS', 'SCOPY', 'SDEAD', 'SBRANCH', 'ALIEN'):
        pc[name] = cursor
        cursor += 4
    words = {
        pc['LEAVE']: 0xF9400BF3,  # ldr x19, [sp, #0x10]
        pc['LDP']: 0xA8C27BFD,  # ldp x29, x30, [sp], #0x20
        pc['RET']: 0xD65F03C0,  # ret
        pc['CLREX']: 0xD5033F5F,
        pc['ZERO']: 0x2A1F03EA,  # mov w10, wzr
        pc['COPY']: 0xAA0903E8,  # mov x8, x9
        pc['DEAD']: cbnz(pc['DEAD'], 10, pc['LEAVE']),
        pc['PLAIN']: 0xF9000028,  # str x8, [x1]
        pc['HEAD']: 0xC85F7E69,  # ldxr x9, [x19]
        pc['CMP']: 0xEB08013F,  # cmp x9, x8
        pc['BNE']: bne(pc['BNE'], pc['CLREX']),
        pc['STORE']: 0xC808FE60,  # stlxr w8, x0, [x19]
        pc['STATUS']: cbnz(pc['STATUS'], 8, pc['ZERO']),
        pc['SUCCESS']: 0x5280002A,  # mov w10, #1
        pc['SCOPY']: 0xAA0903E8,  # mov x8, x9
        pc['SDEAD']: cbz(pc['SDEAD'], 10, pc['PLAIN']),
        pc['SBRANCH']: b(pc['SBRANCH'], pc['LEAVE']),
        pc['ALIEN']: tbz(pc['ALIEN'], 9, 0, pc['PLAIN']),
    }
    if gap:
        words[pc['GAP']] = 0xD503201F  # nop
    for name, word in (overrides or {}).items():
        words[pc[name]] = word
    source = [words[addr] for addr in range(0, cursor, 4)]
    return pc, source


def decoded(source):
    instructions = [ar.decode(word, index * 4) for index, word in enumerate(source)]
    kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
    return instructions, kinds


def plan(source):
    instructions, kinds = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, kinds, (), ar)


class ExclusivePlainStoreFallthroughTests(unittest.TestCase):
    def test_dead_flag_falls_through_plain_store_into_the_load(self):
        pc, source = build()
        instructions, _ = decoded(source)
        by_pc = {ins.address: ins for ins in instructions}
        body = {pc['HEAD'], pc['CMP'], pc['BNE'], pc['STORE'], pc['CLREX']}
        tail = {pc['STATUS'], pc['ZERO'], pc['COPY'], pc['DEAD'], pc['SUCCESS'], pc['SCOPY'],
                pc['SDEAD'], pc['SBRANCH']}
        self.assertEqual(
            [by_pc[pc[name]].mnemonic for name in (
                'HEAD', 'CMP', 'BNE', 'STORE', 'STATUS', 'ZERO', 'COPY', 'DEAD', 'PLAIN')],
            ['ldxr', 'cmp', 'b.ne', 'stlxr', 'cbnz', 'mov', 'mov', 'cbnz', 'str'])
        self.assertEqual(by_pc[pc['HEAD']].op_str, 'x9, [x19]')
        self.assertEqual(by_pc[pc['CMP']].op_str, 'x9, x8')
        self.assertEqual(by_pc[pc['BNE']].operands[0].imm, pc['CLREX'])
        self.assertEqual(by_pc[pc['STORE']].op_str, 'w8, x0, [x19]')
        self.assertEqual(by_pc[pc['STATUS']].operands[-1].imm, pc['ZERO'])
        self.assertEqual(by_pc[pc['ZERO']].op_str, 'w10, wzr')
        self.assertEqual(by_pc[pc['COPY']].op_str, 'x8, x9')
        self.assertEqual(by_pc[pc['DEAD']].operands[-1].imm, pc['LEAVE'])
        self.assertNotIn(by_pc[pc['DEAD']].operands[-1].imm, {pc['CMP'], pc['STORE']})
        self.assertEqual(by_pc[pc['PLAIN']].op_str, 'x8, [x1]')
        self.assertEqual(by_pc[pc['PLAIN']].address + 4, pc['HEAD'])
        self.assertEqual(
            [by_pc[pc[name]].mnemonic for name in ('LEAVE', 'LDP', 'RET')],
            ['ldr', 'ldp', 'ret'])
        self.assertEqual(by_pc[pc['SUCCESS']].op_str, 'w10, #1')
        self.assertEqual(by_pc[pc['SDEAD']].operands[-1].imm, pc['PLAIN'])
        self.assertEqual(by_pc[pc['SBRANCH']].operands[0].imm, pc['LEAVE'])
        self.assertEqual(by_pc[pc['ALIEN']].operands[-1].imm, pc['PLAIN'])
        for name in ('ZERO', 'COPY', 'DEAD', 'PLAIN', 'SUCCESS', 'SCOPY', 'SDEAD', 'SBRANCH'):
            self.assertFalse(ar.android_exclusive.writes_register(by_pc[pc[name]], 19))
        self.assertIsNone(ar.android_exclusive.compare_reload_retry(by_pc, by_pc[pc['STORE']], pc['HEAD'], body, ar))
        self.assertIsNone(ar.android_exclusive.epilogue_reload_retry(by_pc, by_pc[pc['STORE']], pc['HEAD'], body, ar))
        self.assertIsNone(ar.android_exclusive.compare_reload_clrex_end(by_pc, by_pc[pc['STORE']], pc['HEAD'], body, ar))
        self.assertIsNone(ar.android_exclusive.conditional_return_retry(by_pc, by_pc[pc['STORE']], pc['HEAD'], body, ar))
        self.assertTrue(ar.android_exclusive.reaches_head(by_pc, pc['STATUS'], pc['HEAD'], ar))
        recognized, edges = ar.android_exclusive.retry_tail(by_pc, by_pc[pc['STORE']], pc['HEAD'], body, ar)
        self.assertEqual(recognized, tail)
        self.assertNotIn(pc['PLAIN'], recognized)
        self.assertEqual(edges, {(pc['PLAIN'], pc['HEAD'])})
        self.assertEqual(plan(source), ())

    def test_exclusive_address_store_address_write_and_foreign_successor_stay_rejected(self):
        rejected = (
            ('store', False, {'PLAIN': 0xF9000268}, 'str', 'x8, [x19]'),
            ('address', False, {'COPY': 0xAA0903F3}, 'mov', 'x19, x9'),
            ('following', True, None, 'nop', ''),
        )
        for name, gap, overrides, mnemonic, op_str in rejected:
            pc, source = build(gap=gap, overrides=overrides)
            instructions, _ = decoded(source)
            by_pc = {ins.address: ins for ins in instructions}
            body = {pc['HEAD'], pc['CMP'], pc['BNE'], pc['STORE'], pc['CLREX']}
            with self.subTest(name=name):
                if name == 'following':
                    self.assertEqual(by_pc[pc['PLAIN'] + 4].mnemonic, mnemonic)
                    self.assertEqual(by_pc[pc['HEAD']].mnemonic, 'ldxr')
                    self.assertNotEqual(pc['PLAIN'] + 4, pc['HEAD'])
                else:
                    shown = by_pc[pc['PLAIN' if name == 'store' else 'COPY']]
                    self.assertEqual(shown.mnemonic, mnemonic)
                    self.assertEqual(shown.op_str, op_str)
                self.assertIsNone(ar.android_exclusive.plain_store_fallthrough_retry(
                    by_pc, by_pc[pc['STORE']], pc['HEAD'], body, ar))
                self.assertTrue(ar.android_exclusive.reaches_head(by_pc, pc['STATUS'], pc['HEAD'], ar))
                with self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven exclusive retry tail'):
                    plan(source)


if __name__ == '__main__':
    unittest.main()
