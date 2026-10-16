"""A native bounded capacity CAS keeps both fresh acquire reload retry routes."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
from test_android_bounded_compare_retry import BoundedCompareMachine
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as uc

BEGIN, ENTRY, HEAD, END, REJECT = 16, 20, 32, 56, 64


def fixture(base=25, expected=8, status=9):
    block = [0xD5033F5F, 0x88DFFC00 | base << 5 | expected,
             0x7100041F | expected << 5, 0x54000128,
             0x885FFC00 | base << 5 | status,
             0x6B00001F | expected << 16 | status << 5, 0x54FFFF41,
             0x91000400 | expected << 5 | expected,
             0x8800FC00 | status << 16 | base << 5 | expected,
             0x35FFFF00 | status]
    return [ar.branch(0, ENTRY), 0xD503201F, 0xD503201F, ar.branch(12, ENTRY)] + block + [
        0xD65F03C0, 0xD503201F, 0xD65F03C0, 0xD503201F]


def raw(values):
    return struct.pack('<' + 'I' * len(values), *values)


def decoded(values):
    instructions = [ar.decode(value, at * 4) for at, value in enumerate(values)]
    return instructions, {ins.address: ar.site_kind(ins) for ins in instructions}


def plan(values, roots=(0, ENTRY, END, REJECT), overrides=None):
    instructions, kinds = decoded(values)
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions, kinds, roots, ar)


class NativeCapacityRefreshTests(unittest.TestCase):
    def test_exact_union_retains_bytes_without_host_helpers(self):
        for roles in ((25, 8, 9), (0, 1, 2), (28, 16, 17)):
            with self.subTest(roles=roles):
                source = raw(fixture(*roles))
                image = ar.rewrite(source, entry_offsets=(0, ENTRY, END, REJECT))
                self.assertEqual(image.bytes, source)
                self.assertEqual(plan(fixture(*roles)), ())
                self.assertFalse(image.sites)
                self.assertFalse(image.fixups)
                self.assertFalse(image.gates)

    def test_mismatch_and_store_failure_refresh_acquire_value_and_capacity(self):
        source = ar.rewrite(raw(fixture()), entry_offsets=(0, ENTRY, END, REJECT)).bytes
        # Exact same independent raw-word monitor model as the older fourteen-word
        # shape. The shortened topology still reaches distinct success/reject PCs.
        cases = ((0, None, 0, None, 'success', 1, 0, 1, 1, 1, 0, 1),
                 (1, None, 0, None, 'success', 2, 0, 1, 1, 1, 0, 2),
                 (2, None, 0, None, 'reject', 2, None, 1, 0, 0, 0, 2),
                 (0, 1, 0, None, 'success', 2, 0, 2, 2, 1, 1, 2),
                 (0, 2, 0, None, 'reject', 2, 2, 2, 1, 0, 1, 2),
                 (0, None, 2, None, 'success', 1, 0, 3, 3, 3, 0, 1),
                 (0, None, 1, 1, 'success', 2, 0, 2, 2, 2, 0, 2),
                 (0, None, 1, 2, 'reject', 2, 1, 2, 1, 1, 0, 2))
        for case in cases:
            initial, mismatch, failures, failed_value, result, expected, status, reads, loads, stores, clears, final = case
            with self.subTest(case=case):
                machine = BoundedCompareMachine(source, initial, mismatch=mismatch,
                                                failures=failures, failed_value=failed_value)
                before = machine.x.copy()
                self.assertEqual(machine.run(), result)
                before[8] = expected
                if status is not None:
                    before[9] = status
                self.assertEqual(machine.x, before)
                self.assertEqual(machine.sp, 0x200000)
                self.assertEqual(machine.flags, 0x60000000 if result == 'success' else 0x20000000)
                self.assertEqual((machine.reads, machine.exclusive_reads, machine.stores, machine.clears),
                                 (reads, loads, stores, clears))
                self.assertEqual(machine.writes, int(result == 'success'))
                self.assertEqual(machine.memory, {0x3FFFFC: 0x11223344, 0x400000: final,
                                                 0x400004: 0x55667788})

    def test_unicorn_executes_native_ordering_and_both_retry_routes(self):
        source = ar.rewrite(raw(fixture()), entry_offsets=(0, ENTRY, END, REJECT)).bytes
        for initial, mismatch, failures, competitor in ((0, None, 0, None), (2, None, 0, None),
                (0, 1, 0, None), (0, 2, 0, None), (0, None, 2, None),
                (0, None, 1, 1), (0, None, 1, 2)):
            with self.subTest(initial=initial, mismatch=mismatch, failures=failures, competitor=competitor):
                model = BoundedCompareMachine(source, initial, mismatch=mismatch,
                                               failures=failures, failed_value=competitor)
                outcome = model.run()
                base, data = 0x100000, 0x400000
                cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
                cpu.mem_map(base, 4096); cpu.mem_map(data, 4096)
                cpu.mem_write(base, source)
                # Explicit deterministic monitor loss is injected with a separate
                # CLREX/B fixture. The original STLXR really executes and fails;
                # no status/result register is synthesized by the hook.
                cpu.mem_write(base + 0x100, raw([0xD5033F5F, ar.branch(base + 0x104, base + 48)]))
                cpu.mem_write(data, struct.pack('<II', initial, 0x55667788))
                before = [0xFEDCBA9800000100 + index for index in range(31)]
                before[25] = data
                vectors = [int.from_bytes(bytes([index]) * 16, 'little') for index in range(32)]
                for index, value in enumerate(before):
                    cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{index}'), value)
                for index, value in enumerate(vectors):
                    cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{index}'), value)
                cpu.reg_write(uc.UC_ARM64_REG_SP, 0x200000)
                cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0x90000000)
                observed = dict(reads=0, loads=0, stores=0, clears=0, detour=False, outcome=None)
                def code(machine, pc, size, _):
                    at = pc - base
                    if at in (END, REJECT):
                        observed['outcome'] = 'success' if at == END else 'reject'
                        machine.emu_stop()
                    elif at == ENTRY:
                        observed['reads'] += 1
                    elif at == HEAD:
                        observed['loads'] += 1
                        if observed['loads'] == 1 and mismatch is not None:
                            machine.mem_write(data, struct.pack('<I', mismatch))
                    elif at == BEGIN:
                        observed['clears'] += 1
                    elif at == 48:
                        if observed['detour']:
                            observed['detour'] = False
                        else:
                            observed['stores'] += 1
                            if observed['stores'] <= failures:
                                if competitor is not None:
                                    machine.mem_write(data, struct.pack('<I', competitor))
                                observed['detour'] = True
                                machine.reg_write(uc.UC_ARM64_REG_PC, base + 0x100)
                cpu.hook_add(UC_HOOK_CODE, code)
                cpu.emu_start(base, base + len(source), count=500)
                self.assertEqual(observed['outcome'], outcome)
                self.assertEqual([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{index}')) for index in range(31)], model.x)
                self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_SP), model.sp)
                self.assertEqual(cpu.reg_read(uc.UC_ARM64_REG_NZCV), model.flags)
                self.assertEqual([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{index}')) for index in range(32)], vectors)
                self.assertEqual(struct.unpack('<II', cpu.mem_read(data, 8)), (model.memory[data], 0x55667788))
                self.assertEqual((observed['reads'], observed['loads'], observed['stores'], observed['clears']),
                                 (model.reads, model.exclusive_reads, model.stores, model.clears))

    def test_only_ordinary_entry_can_receive_external_roots_or_edges(self):
        for pc in range(BEGIN, END, 4):
            if pc == ENTRY:
                continue
            with self.subTest(root=pc), self.assertRaises(ar.RewriteError):
                plan(fixture(), roots=(0, ENTRY, END, REJECT, pc))
            values = fixture()
            values[1] = ar.branch(4, pc)
            with self.subTest(edge=pc), self.assertRaises(ar.RewriteError):
                plan(values)

    def test_changed_ordering_width_bound_retries_and_roles_fail_closed(self):
        helper = ar.android_exclusive.native_conditional_refresh
        def match(values, overrides=None):
            instructions, kinds = decoded(values)
            kinds.update(overrides or {})
            return helper(instructions[HEAD // 4], {ins.address: ins for ins in instructions}, kinds, ar)
        self.assertEqual(match(fixture()), (set(range(BEGIN, END, 4)), ENTRY, {HEAD}))
        changes = ((0, 0xD503201F), (0, 0xD5033B5F), (1, 0xC8DFFF28),
                   (1, 0x88DFFF48), (2, 0x7100091F), (3, 0x54000129),
                   (3, 0x54000028), (4, 0x885F7F29), (4, 0xC85FFF29),
                   (5, 0x6B0A013F), (6, 0x54FFFF61), (6, 0x54FFFF40),
                   (7, 0x11000508), (7, 0x91000908), (8, 0x88097F28),
                   (8, 0xC809FF28), (8, 0x880AFF28), (8, 0x8809FF48),
                   (9, 0x35FFFF29), (9, 0x35FFFF08), (9, 0xB5FFFF09))
        for slot, value in changes:
            values = fixture(); values[BEGIN // 4 + slot] = value
            with self.subTest(slot=slot, value=hex(value)):
                self.assertIsNone(match(values))
        for index in range(3):
            for forbidden in (18, 29, 30, 31, *((8, 9) if index == 0 else (25, 9) if index == 1 else (25, 8))):
                roles = [25, 8, 9]; roles[index] = forbidden
                with self.subTest(roles=roles):
                    self.assertIsNone(match(fixture(*roles)))
        for pc in range(BEGIN, END, 4):
            for kind in ('x18', 'parameter', 'parameter_tail', 'gate'):
                with self.subTest(rewrite=pc, kind=kind), self.assertRaises(ar.RewriteError):
                    match(fixture(), {pc: kind})
            instructions, kinds = decoded(fixture())
            by_pc = {ins.address: ins for ins in instructions if ins.address != pc}
            self.assertIsNone(helper(instructions[HEAD // 4], by_pc, kinds, ar))


if __name__ == '__main__':
    unittest.main()
