"""Exclusive monitor regions must contain only relocated guest instructions."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import gen_android_fixtures as gen
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM
from test_android_rewrite import Machine


def raw(*values):
    return b''.join(struct.pack('<I', value) for value in values)


def assemble(body):
    with tempfile.TemporaryDirectory(prefix='dm-exclusive-test-') as directory:
        source = Path(directory) / 'fixture.S'
        source.write_text('.text\n.global fixture\nfixture:\n' + body, encoding='utf-8')
        return gen.assemble(source, gen.toolchain())


class ExclusiveMachine(Machine):
    """Independent decoded load-exclusive/store-exclusive monitor model."""
    def __init__(self, image, *, fail_first=0, fail_all=False, retry_counter=None):
        super().__init__(image)
        self.fail_first, self.fail_all = fail_first, fail_all
        self.retry_counter = retry_counter
        self.track_retries = bool(fail_first or fail_all)
        self.store_attempts = self.helper_calls = self.failed_retry_loads = 0

    def run(self):
        pc, monitor, failed_retry = self.image.entry_offset, None, False
        for _ in range(10000):
            ins = ar.decode(self.load(pc, 4), pc)
            ops, name, next_pc = ins.operands, ins.mnemonic, pc + 4
            reg = lambda operand: self.name(ins, operand)
            value = lambda operand: self.value(ins, operand)
            if name == 'b':
                next_pc = ops[0].imm
            elif name in {'cbz', 'cbnz'}:
                if (value(ops[0]) == 0) == (name == 'cbz'):
                    next_pc = ops[1].imm
                if failed_retry and reg(ops[0]) == self.retry_counter and value(ops[0]) == 0 and name == 'cbnz':
                    failed_retry = False  # Proven finite exhaustion branch falls through.
            elif name == 'b.ne':
                if not self.flags & 0x40000000:
                    next_pc = ops[0].imm
                elif failed_retry and self.retry_counter:
                    assert self.get_reg(self.retry_counter) == 0
                    failed_retry = False
            elif name == 'blr':
                assert monitor is None, 'host helper while exclusive monitor live'
                assert not failed_retry, 'host helper between failed store and retry load'
                assert value(ops[0]) == 0x100001
                self.helper_calls += 1
                self.x[30], self.x[16] = next_pc, self.state
            elif name == 'ret':
                target = value(ops[0]) if ops else self.x[30]
                if target == 0xFFFFFFFFFFFFFFFC:
                    assert self.sp == self.start_sp
                    return self.x[0]
                next_pc = target
            elif name in {'mov', 'adr', 'adrp'}:
                self.set_reg(reg(ops[0]), value(ops[1]))
            elif name in {'add', 'sub', 'subs'}:
                left, right = value(ops[1]), value(ops[2])
                result = left + right * (-1 if name in {'sub', 'subs'} else 1)
                self.set_reg(reg(ops[0]), result)
                if name == 'subs':
                    bits = 32 if reg(ops[0]).startswith('w') else 64
                    masked, sign = result & ((1 << bits) - 1), 1 << (bits - 1)
                    self.flags = ((bool(masked & sign) << 3) | ((masked == 0) << 2) |
                                  ((left >= right) << 1) | bool((left ^ right) & (left ^ masked) & sign)) << 28
            elif name == 'clrex':
                monitor = None
            elif name in ar.EXCLUSIVE_LOADS | ar.EXCLUSIVE_STORES | {'ldr', 'str', 'ldp', 'stp'}:
                mem = next((operand for operand in ops if operand.type == ARM64_OP_MEM), None)
                if mem is None:
                    address = ops[-1].imm
                else:
                    address = self.get_reg(ins.reg_name(mem.mem.base)) + mem.mem.disp
                exclusive_load = name in ar.EXCLUSIVE_LOADS
                exclusive_store = name in ar.EXCLUSIVE_STORES
                if failed_retry and not exclusive_load and not exclusive_store:
                    raise AssertionError('memory access between failed store and retry load')
                data = ops[1:-1] if exclusive_store else ops[:-1]
                size = 1 if name.endswith('b') else 2 if name.endswith('h') else 4 if reg(data[0]).startswith('w') else 8
                is_load = name.startswith('ld')
                if exclusive_load:
                    self.failed_retry_loads += bool(failed_retry)
                    failed_retry = False
                    monitor = (address, size * len(data))
                success = not exclusive_store or monitor == (address, size * len(data))
                if exclusive_store:
                    self.store_attempts += 1
                    success &= not self.fail_all and self.store_attempts > self.fail_first
                    self.set_reg(reg(ops[0]), 0 if success else 1)
                    failed_retry = self.track_retries and not success
                    monitor = None
                if success:
                    for index, operand in enumerate(data):
                        if is_load:
                            self.set_reg(reg(operand), self.load(address + index * size, size))
                        else:
                            self.store(address + index * size, value(operand), size)
            elif name != 'nop':
                raise AssertionError(f'unmodeled {name} {ins.op_str}')
            pc = next_pc
        raise AssertionError('exclusive fixture did not terminate')


class ExclusiveTests(unittest.TestCase):
    def test_unrewritten_region_has_same_entry_boundary_as_virtual_x18(self):
        for register in (0, 18):
            source = assemble(f'ldxr x{register},[x1]\nadd x{register},x{register},#1\nclrex\nret\n')
            for root in (4, 8):
                with self.subTest(register=register, root=root), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                    ar.rewrite(source, entry_offsets=(0, root))
            image = ar.rewrite(source, entry_offsets=(0, 12))
            if register == 0:
                self.assertEqual(image.bytes, source)
                self.assertFalse(image.sites)

    def test_unrewritten_retry_tail_rejects_roots_and_outside_edges(self):
        for register in (3, 18):
            source = assemble(f'head: ldxr x{register},[x0]\nadd x{register},x{register},#1\nstxr w1,x{register},[x0]\n'
                              'cbz w1,done\nsubs x2,x2,#1\nb.ne head\ndone: ret\n')
            for root in (12, 16, 20):
                with self.subTest(register=register, root=root), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                    ar.rewrite(source, entry_offsets=(0, root))
            ar.rewrite(source, entry_offsets=(0, 24))
            source = assemble(f'b tail\nhead: ldxr x{register},[x0]\nadd x{register},x{register},#1\nstxr w1,x{register},[x0]\n'
                              'cbz w1,done\ntail: subs x2,x2,#1\nb.ne head\ndone: ret\n')
            with self.subTest(register=register), self.assertRaisesRegex(ar.RewriteError, 'external entry.*interior'):
                ar.rewrite(source, entry_offset=4)

    def test_unrewritten_region_keeps_original_sp_operands_without_scratch_requirements(self):
        source = assemble('ldxr x0,[x1]\nldr x2,[sp]\nclrex\nret\n')
        self.assertEqual(ar.rewrite(source, entry_offsets=(0, 12)).bytes, source)

    def test_profiled_parameter_kinds_cannot_enter_exclusive_body_or_retry_tail(self):
        examples = ((raw(0xC85F7C20, 0xD2800028, 0xC8027C20, 0xD65F03C0), 4),
                    (raw(0xC85F7C20, 0xC8027C20, 0x34000082, 0xD2800028, 0xF2A00088,
                         ar.branch(20, 0), 0xD65F03C0), 12))
        for source, endpoint in examples:
            instructions = [ar.decode(value[0], pc) for pc, value in
                            zip(range(0, len(source), 4), struct.iter_unpack('<I', source))]
            for kind in ('parameter', 'parameter_tail'):
                kinds = {ins.address: ar.site_kind(ins) for ins in instructions}
                kinds[endpoint] = kind
                with self.subTest(endpoint=endpoint, kind=kind), self.assertRaisesRegex(ar.RewriteError, 'exclusive'):
                    ar.android_exclusive.plan_regions(instructions, kinds, {0}, ar)

    def test_retry_failure_intervals_use_one_accessor_for_all_supported_shapes(self):
        tails = ('cbnz w1,head\n', 'cbz w1,done\nb head\n',
                 'cbz w1,done\nsubs x2,x2,#1\nb.ne head\n',
                 'cbz w1,done\nsub x2,x2,#1\ncbnz x2,head\n')
        for tail in tails:
            image = ar.rewrite(assemble('head: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\n' + tail +
                                        'done: ldr x0,[x0]\nret\n'))
            for failures in (0, 1, 3):
                with self.subTest(tail=tail, failures=failures):
                    machine = ExclusiveMachine(image, fail_first=failures, retry_counter='x2')
                    machine.x[0], machine.x[2] = 0x400000, 10
                    machine.store(0x400000, 41, 8)
                    self.assertEqual(machine.run(), 42)
                    self.assertEqual(machine.store_attempts, failures + 1)
                    self.assertEqual(machine.failed_retry_loads, failures)
                    self.assertEqual(machine.helper_calls, 1)
                    self.assertEqual(machine.load(machine.state, 8), 42)
                    self.assertEqual(machine.x[2], 10 - failures if 'sub' in tail else 10)
                    self.assertEqual(machine.flags, 0x20000000 if failures and 'subs' in tail else 0x60000000)

    def test_finite_retry_exhaustion_exits_once_with_original_flags_and_counter(self):
        for decrement, branch in (('subs x2,x2,#1', 'b.ne head'), ('sub x2,x2,#1', 'cbnz x2,head')):
            source = assemble('head: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\n'
                              f'cbz w1,done\n{decrement}\n{branch}\ndone: ldr x0,[x0]\nret\n')
            machine = ExclusiveMachine(ar.rewrite(source), fail_all=True, retry_counter='x2')
            machine.x[0], machine.x[2] = 0x400000, 3
            machine.store(0x400000, 41, 8)
            self.assertEqual(machine.run(), 41)
            self.assertEqual((machine.x[2], machine.store_attempts, machine.failed_retry_loads, machine.helper_calls), (0, 3, 2, 1))
            self.assertEqual(machine.load(machine.state, 8), 42)
            self.assertEqual(machine.flags, 0x60000000)

    def test_retry_status_w18_and_live_x16_lr_are_published_only_at_exit(self):
        for data in ('x16', 'x30'):
            save = 'mov x9,x30\n' if data == 'x30' else ''
            restore = 'mov x30,x9\n' if data == 'x30' else ''
            source = assemble(save + f'head: ldxr {data},[x0]\nadd {data},{data},#1\nstxr w18,{data},[x0]\n'
                              'cbz w18,done\nsub x2,x2,#1\ncbnz x2,head\n' +
                              f'done: mov x0,{data}\n' + restore + 'ret\n')
            machine = ExclusiveMachine(ar.rewrite(source), fail_first=3, retry_counter='x2')
            machine.x[0], machine.x[2] = 0x400000, 10
            machine.store(0x400000, 41, 8)
            machine.store(machine.state, 0xFFFFFFFFABCD1234, 8)
            self.assertEqual(machine.run(), 42)
            self.assertEqual(machine.helper_calls, 1)
            self.assertEqual(machine.load(machine.state, 8), 0)
            self.assertEqual(machine.x[30], 0xFFFFFFFFFFFFFFFC)
            self.assertEqual(machine.x[2], 7)
            if data == 'x16':
                self.assertEqual(machine.x[16], 42)
        source = assemble('head: ldxr x16,[x0]\nadd x16,x16,#1\nstxr w18,x16,[x0]\n'
                          'cbz w18,done\nsubs x2,x2,#1\nb.ne head\ndone: mov x0,x16\nret\n')
        machine = ExclusiveMachine(ar.rewrite(source), fail_all=True, retry_counter='x2')
        machine.x[0], machine.x[2] = 0x400000, 3
        machine.store(0x400000, 41, 8)
        machine.store(machine.state, 0xFFFFFFFFABCDEF00, 8)
        self.assertEqual(machine.run(), 42)
        self.assertEqual(machine.load(0x400000, 8), 41)
        self.assertEqual(machine.load(machine.state, 8), 1)
        self.assertEqual((machine.helper_calls, machine.x[2], machine.flags), (1, 0, 0x60000000))

    def test_retry_virtual_x18_base_is_live_across_failed_attempts(self):
        source = assemble('head: ldaxr x16,[x18]\nadd x16,x16,#1\nstlxr w1,x16,[x18]\n'
                          'cbnz w1,head\nmov x0,x16\nret\n')
        machine = ExclusiveMachine(ar.rewrite(source), fail_first=3)
        hardware18 = machine.x[18]
        machine.store(machine.state, 0x400000, 8)
        machine.store(0x400000, 41, 8)
        self.assertEqual(machine.run(), 42)
        self.assertEqual((machine.helper_calls, machine.failed_retry_loads), (1, 3))
        self.assertEqual(machine.load(machine.state, 8), 0x400000)
        self.assertEqual(machine.x[18], hardware18)

    def test_retry_widths_and_pairs_with_forced_spurious_failures(self):
        for load, store, registers, width in (
                ('ldxr', 'stxr', 'x18', 8), ('ldaxr', 'stlxr', 'w18', 4),
                ('ldxrb', 'stxrb', 'w18', 1), ('ldaxrb', 'stlxrb', 'w18', 1),
                ('ldxrh', 'stxrh', 'w18', 2), ('ldaxrh', 'stlxrh', 'w18', 2),
                ('ldxp', 'stxp', 'x18, x16', 8), ('ldaxp', 'stlxp', 'w16, w18', 4)):
            with self.subTest(load=load):
                source = assemble(f'head: {load} {registers},[x0]\n{store} w1,{registers},[x0]\n'
                                  'cbnz w1,head\nldr x0,[x0]\nret\n')
                machine = ExclusiveMachine(ar.rewrite(source), fail_first=2)
                machine.x[0] = 0x400000
                machine.store(0x400000, 0x8877665544332211, 8)
                machine.store(0x400008, 0x12345678ABCDEF00, 8)
                machine.run()
                self.assertEqual((machine.helper_calls, machine.store_attempts, machine.failed_retry_loads), (1, 3, 2))
                expected = 0x88776655 if registers == 'w16, w18' else 0x8877665544332211 & ((1 << (8 * width)) - 1)
                self.assertEqual(machine.load(machine.state, 8), expected)

    def test_tail_only_registers_and_pc_relative_address_are_preserved(self):
        source = assemble('head: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\n'
                          'cbz w1,done\nadd x15,x15,#1\nsubs x2,x2,#1\n'
                          'adr x14,literal\nnop\nb.ne head\ndone: ldr x0,[x0]\nret\nliteral: .quad 7\n')
        machine = ExclusiveMachine(ar.rewrite(source, text_size=len(source) - 8), fail_first=3, retry_counter='x2')
        before15 = machine.x[15]
        machine.x[0], machine.x[2] = 0x400000, 10
        machine.store(0x400000, 41, 8)
        self.assertEqual(machine.run(), 42)
        self.assertEqual((machine.x[15], machine.x[14], machine.x[2]), (before15 + 3, len(source) - 8, 7))
        self.assertEqual(machine.helper_calls, 1)

    def test_retry_tail_roots_and_outside_incoming_edges_reject(self):
        source = assemble('head: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\n'
                          'cbz w1,done\nsubs x2,x2,#1\nb.ne head\ndone: ldr x0,[x0]\nret\n')
        for root in (12, 16, 20):
            with self.subTest(root=root), self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
                ar.rewrite(source, entry_offsets=(0, root))
        # The ordinary failure/exhaustion exit remains a legal callback entry.
        ar.rewrite(source, entry_offsets=(0, 24))
        source = assemble('b tail\nhead: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\n'
                          'cbz w1,done\ntail: subs x2,x2,#1\nb.ne head\ndone: ret\n')
        with self.assertRaisesRegex(ar.RewriteError, 'external entry.*interior'):
            ar.rewrite(source, entry_offset=4)

    def test_tail_registers_participate_in_scratch_exhaustion_proof(self):
        source = 'head: ldxr x18,[x0]\n' + '\n'.join(f'add x{i},x{i},#0' for i in range(14))
        source += '\nstxr w1,x18,[x0]\ncbz w1,done\nadd x15,x15,#1\nsubs x14,x14,#1\nb.ne head\ndone: ret\n'
        with self.assertRaisesRegex(ar.RewriteError, 'insufficient unused registers'):
            ar.rewrite(assemble(source))

    def test_false_status_counter_and_unsafe_retry_shapes_reject(self):
        tails = (
            'cbnz w3,head', 'cbnz x1,head', 'b head',
            'cbz w1,done\nsub x2,x2,#1\nb.ne head',
            'cbz w1,done\nsubs x2,x3,#1\nb.ne head',
            'cbz w1,done\nsubs x2,x2,#2\nb.ne head',
            'cbz w1,done\nsub x2,x2,#1\ncbnz x3,head',
            'cbz w1,done\nsub w2,w2,#1\ncbnz x2,head',
            'cbz w1,done\nsub w1,w1,#1\ncbnz w1,head',
            'cbz w1,done\nmov x2,#10\nsubs x2,x2,#1\nb.ne head',
            'cbz w1,done\nldr x3,[x4]\nb head',
            'cbz w1,done\nprfm pldl1keep,[x4]\nb head',
            'cbz w1,done\nmrs x3,tpidr_el0\nb head',
            'cbz w1,done\nspin: cbnz x3,spin\nb head',
            'cbz w1,done\nsubs x2,x2,#1\nb.ne head\nb head',
        )
        for tail in tails:
            with self.subTest(tail=tail), self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven.*retry'):
                ar.rewrite(assemble('head: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\n' +
                                    tail + '\ndone: ret\n'))
        with self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven.*retry'):
            ar.rewrite(assemble('head: ldxr x18,[x0]\nadd x2,x2,#1\nstxr w1,x18,[x0]\n'
                                'cbz w1,done\nsubs x2,x2,#1\nb.ne head\ndone: ret\n'))
        with self.assertRaisesRegex(ar.RewriteError, 'SP-sensitive'):
            ar.rewrite(assemble('head: ldxr x18,[x0]\nstxr w1,x18,[x0]\n'
                                'cbz w1,done\nadd x3,sp,#0\nb head\ndone: ret\n'))

    def test_retry_tail_limit_and_backwards_sparse_body(self):
        source = 'head: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\ncbz w1,done\n'
        ending = 'b head\ndone: ldr x0,[x0]\nret\n'
        machine = ExclusiveMachine(ar.rewrite(assemble(source + 'nop\n' * 62 + ending)), fail_first=1)
        machine.x[0] = 0x400000
        machine.store(0x400000, 41, 8)
        self.assertEqual(machine.run(), 42)
        self.assertEqual(machine.helper_calls, 1)
        with self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven.*retry'):
            ar.rewrite(assemble(source + 'nop\n' * 63 + ending))
        source = assemble('update: add x18,x18,#1\nb store\nhead: ldxr x18,[x0]\nb update\n'
                          'store: stxr w1,x18,[x0]\ncbnz w1,head\nldr x0,[x0]\nret\n')
        machine = ExclusiveMachine(ar.rewrite(source, entry_offset=8), fail_first=2)
        machine.x[0] = 0x400000
        machine.store(0x400000, 41, 8)
        self.assertEqual(machine.run(), 42)
        self.assertEqual((machine.helper_calls, machine.failed_retry_loads), (1, 2))

    def test_indirect_retry_and_unknown_exhaustion_paths_reject(self):
        for transfer in ('br x4', 'blr x4', 'ret x4'):
            for bounded in (False, True):
                with self.subTest(transfer=transfer, bounded=bounded):
                    counter = 'subs x2,x2,#1\nb.ne head\n' if bounded else ''
                    source = assemble('head: ldxr x18,[x0]\nadd x18,x18,#1\nstxr w1,x18,[x0]\n'
                                      'cbz w1,done\n' + counter + 'adr x4,head\n' + transfer +
                                      '\ndone: mov x0,x18\nret\n')
                    with self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven.*retry'):
                        ar.rewrite(source)
        source = assemble('head: ldxr x18,[x0]\nstxr w1,x18,[x0]\ncbz w1,done\n'
                          'subs x2,x2,#1\nb.ne head\nbl callback\n'
                          'done: ret\ncallback: ret\n')
        with self.assertRaisesRegex(ar.RewriteError, 'unsupported/unproven.*retry'):
            ar.rewrite(source)

    def test_whole_region_has_no_helper_inside_reservation(self):
        # ldaxr x18,[x0]; add x18,x18,#1; stlxr w1,x18,[x0]; ret
        image = ar.rewrite(raw(0xC85FFC12, 0x91000652, 0xC801FC12, 0xD65F03C0))
        relocated = {site.offset: site.trampoline for site in image.sites}
        self.assertIn(0, relocated)
        words = list(ar.MD.disasm(image.bytes[relocated[0]:], relocated[0]))
        start = next(i for i, ins in enumerate(words) if ins.mnemonic == 'ldaxr')
        end = next(i for i, ins in enumerate(words[start:], start) if ins.mnemonic == 'stlxr')
        self.assertEqual([x.mnemonic for x in words[start:end + 1]], ['ldaxr', 'b', 'add', 'b', 'stlxr'])
        self.assertFalse(any(ar.has18(x) for x in words[start:end + 1]))

    def test_known_callback_root_cannot_enter_region_interior(self):
        with self.assertRaisesRegex(ar.RewriteError, 'entry.*exclusive'):
            ar.rewrite(raw(0xC85FFC12, 0x91000652, 0xC801FC12, 0xD65F03C0), entry_offsets=(0, 4))

    def test_widths_pairs_and_acquire_release_preserve_registers(self):
        for load, store, registers, width in (
                ('ldxr', 'stxr', 'x18', 8), ('ldaxr', 'stlxr', 'w18', 4),
                ('ldxrb', 'stxrb', 'w18', 1), ('ldaxrb', 'stlxrb', 'w18', 1),
                ('ldxrh', 'stxrh', 'w18', 2), ('ldaxrh', 'stlxrh', 'w18', 2),
                ('ldxp', 'stxp', 'x18, x16', 8), ('ldaxp', 'stlxp', 'w16, w18', 4)):
            with self.subTest(load=load, registers=registers):
                source = assemble(f'{load} {registers}, [x0]\n{store} w1, {registers}, [x0]\nret\n')
                machine = ExclusiveMachine(ar.rewrite(source))
                machine.x[0] = 0x400000
                before = machine.x.copy()
                initial = (0x8877665544332211, 0x123456789ABCDEF0)
                for index, item in enumerate(initial):
                    machine.store(0x400000 + index * width, item, width)
                machine.run()
                pair = ',' in registers
                expected18 = initial[1 if registers.endswith('w18') and pair else 0] & ((1 << (8 * width)) - 1)
                self.assertEqual(machine.load(machine.state, 8), expected18)
                self.assertEqual(machine.x[1], 0)
                for reg_index in range(31):
                    if reg_index not in {1, 16}:
                        self.assertEqual(machine.x[reg_index], before[reg_index], reg_index)
                self.assertEqual(machine.flags, 0x60000000)

    def test_status_w18_zero_extension_and_live_x16_lr(self):
        for data in ('x16', 'x30'):
            save = 'mov x9,x30\n' if data == 'x30' else ''
            restore = 'mov x30,x9\n' if data == 'x30' else ''
            machine = ExclusiveMachine(ar.rewrite(assemble(
                save + f'ldxr {data}, [x0]\nadd {data}, {data}, #1\nstxr w18, {data}, [x0]\nmov x0, {data}\n' + restore + 'ret\n')))
            machine.x[0] = 0x400000
            machine.store(0x400000, 41, 8)
            machine.store(machine.state, 0xFFFFFFFF12345678, 8)
            self.assertEqual(machine.run(), 42)
            self.assertEqual(machine.load(machine.state, 8), 0)
            self.assertEqual(machine.x[16 if data == 'x16' else 30], 42 if data == 'x16' else 0xFFFFFFFFFFFFFFFC)

    def test_noncontiguous_multiple_terminals_and_pc_relative_literals(self):
        source = assemble('ldxr x18, [x0]\ncbz x1, abandon\nldr x2, literal\n'
                          'adr x3, literal\nadd x18, x18, x2\nstxr w4, x18, [x0]\nb done\n'
                          'abandon: clrex\ndone: mov x0, x18\nret\nliteral: .quad 7\n')
        image = ar.rewrite(source, text_size=len(source) - 8)
        for take in (0, 1):
            machine = ExclusiveMachine(image)
            machine.x[0], machine.x[1] = 0x400000, take
            machine.store(0x400000, 35, 8)
            self.assertEqual(machine.run(), 35 if take == 0 else 42)
            self.assertEqual(machine.load(0x400000, 8), 35 if take == 0 else 42)
            if take:
                self.assertEqual(machine.x[3], len(source) - 8)

    def test_clrex_clears_monitor_before_later_store(self):
        source = assemble('ldxr x18, [x0]\nclrex\nstxr w1, x2, [x0]\nmov x0, x1\nret\n')
        machine = ExclusiveMachine(ar.rewrite(source))
        machine.x[0] = 0x400000
        machine.store(0x400000, 35, 8)
        self.assertEqual(machine.run(), 1)
        self.assertEqual(machine.load(0x400000, 8), 35)

    def test_region_enters_load_even_when_terminal_address_is_lower(self):
        source = assemble('abandon: clrex\nret\nldxr x18,[x0]\nb abandon\n')
        machine = ExclusiveMachine(ar.rewrite(source, entry_offset=8))
        machine.x[0] = 0x400000
        machine.store(0x400000, 123, 8)
        machine.run()
        self.assertEqual(machine.load(machine.state, 8), 123)

    def test_terminal_cannot_continue_into_same_region_interior(self):
        source = assemble('ldxr x18,[x0]\ncbz x1,shared\nstxr w2,x18,[x0]\n'
                          'shared: add x18,x18,#1\nclrex\nmov x0,x18\nret\n')
        with self.assertRaisesRegex(ar.RewriteError, 'terminal continuation.*interior'):
            ar.rewrite(source)

    def test_terminal_cannot_continue_into_another_region_interior(self):
        source = assemble('ldxr x18,[x0]\nstxr w1,x18,[x0]\n'
                          'shared: add x18,x18,#1\nclrex\nret\n'
                          'ldxr x18,[x0]\nb shared\n')
        with self.assertRaisesRegex(ar.RewriteError, 'external entry.*interior'):
            ar.rewrite(source, entry_offsets=(0, 20))

    def test_rejections_are_fail_closed(self):
        cases = (
            ('ldxr x18, [x0]\nspin: cbnz x1, spin\nstxr w2, x18, [x0]\nret', 'unbounded'),
            ('ldxr x18, [sp]\nstxr w2, x18, [sp]\nret', 'SP-sensitive'),
            ('ldxr x18, [x0]\nldxr x1, [x0]\nstxr w2, x18, [x0]\nret', 'nested'),
            ('ldxr x18, [x0]\nblr x5\nstxr w2, x18, [x0]\nret', 'call/indirect'),
            ('ldxr x18, [x0]\nmrs x1, tpidr_el0\nstxr w2, x18, [x0]\nret', 'host gate'),
            ('ldxr x18, [x0]\nbrk #1\nstxr w2, x18, [x0]\nret', 'host gate'),
            ('b middle\nldxr x18, [x0]\nmiddle: add x18, x18, #1\nstxr w2, x18, [x0]\nret', 'external entry'),
        )
        for source, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ar.RewriteError, message):
                    ar.rewrite(assemble(source))
        # Assemblers reject these Arm constrained-unpredictable operands.
        for instruction in (0xC8007C00, 0xF8008E52):
            with self.assertRaisesRegex(ar.RewriteError, 'constrained-unpredictable'):
                ar.rewrite(raw(0xC85F7C12, instruction, 0xD65F03C0))
        # This Capstone release rejects the duplicate LDXP destination outright.
        with self.assertRaisesRegex(ar.RewriteError, 'invalid ARM64|constrained-unpredictable'):
            ar.rewrite(raw(0xC87F0040, 0xC8017C12, 0xD65F03C0))

    def test_insufficient_whole_region_scratch_registers(self):
        source = 'ldxr x18, [x0]\n' + '\n'.join(f'add x{i}, x{i}, #0' for i in range(15))
        with self.assertRaisesRegex(ar.RewriteError, 'insufficient'):
            ar.rewrite(assemble(source + '\nstxr w15, x18, [x0]\nret\n'))


if __name__ == '__main__':
    unittest.main()
