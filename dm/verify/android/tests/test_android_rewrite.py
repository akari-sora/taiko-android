"""ABI/semantic regressions against decoded bytes, not generator golden copies."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import gen_android_fixtures as gen
from capstone import arm64_const as a64
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG


def raw(*words):
    return b''.join(struct.pack('<I', value) for value in words)


class Machine:
    """Small independent decoded-instruction interpreter for the fixture subset.

    Helper calls deliberately overwrite LR; all other architectural values are
    preserved. Memory is byte-addressed and stack access below allocated SP fails.
    This catches original x16/LR restoration, stack leaks and both cleanup paths.
    It is host evidence only; native runtime execution remains a separate gate.
    """
    def __init__(self, image):
        self.image = image
        self.memory = dict(enumerate(image.bytes))
        self.x = [0x100 + i for i in range(31)]
        self.x[30] = 0xFFFFFFFFFFFFFFFC
        self.sp, self.start_sp = 0x200000, 0x200000
        self.state = 0x300000
        self.flags = 0x60000000
        self.calls = []
        self.host_target, self.transferred_target = None, None
        for fixup in image.fixups:
            self.store(fixup.offset, 0x100000 + fixup.helper, 8)
        for offset in (0, 8, 16):
            self.store(self.state + offset, 0, 8)

    def store(self, address, value, size):
        for offset in range(size):
            self.memory[address + offset] = value >> (8 * offset) & 255

    def load(self, address, size):
        return sum(self.memory.get(address + offset, 0) << (8 * offset) for offset in range(size))

    def name(self, ins, operand):
        return ins.reg_name(operand.reg)

    def get_reg(self, name):
        if name in ('sp', 'wsp'):
            return self.sp & (0xFFFFFFFF if name == 'wsp' else 0xFFFFFFFFFFFFFFFF)
        if name in ('xzr', 'wzr'):
            return 0
        index = {'lr': 30, 'fp': 29}.get(name)
        if index is None:
            index = int(name[1:])
        return self.x[index] & (0xFFFFFFFF if name.startswith('w') else 0xFFFFFFFFFFFFFFFF)

    def set_reg(self, name, value):
        if name in ('xzr', 'wzr'):
            return
        if name in ('sp', 'wsp'):
            self.sp = value & (0xFFFFFFFF if name == 'wsp' else 0xFFFFFFFFFFFFFFFF)
            return
        index = {'lr': 30, 'fp': 29}.get(name)
        if index is None:
            index = int(name[1:])
        self.x[index] = value & (0xFFFFFFFF if name.startswith('w') else 0xFFFFFFFFFFFFFFFF)

    def value(self, ins, operand):
        value = operand.imm if operand.type == ARM64_OP_IMM else self.get_reg(self.name(ins, operand))
        extensions = {
            a64.ARM64_EXT_UXTB: (8, False), a64.ARM64_EXT_UXTH: (16, False),
            a64.ARM64_EXT_UXTW: (32, False), a64.ARM64_EXT_UXTX: (64, False),
            a64.ARM64_EXT_SXTB: (8, True), a64.ARM64_EXT_SXTH: (16, True),
            a64.ARM64_EXT_SXTW: (32, True), a64.ARM64_EXT_SXTX: (64, True),
        }
        if operand.ext:
            bits, signed = extensions[operand.ext]
            value &= (1 << bits) - 1
            if signed and value & (1 << (bits - 1)):
                value -= 1 << bits
        if operand.shift.type:
            assert operand.shift.type == a64.ARM64_SFT_LSL
            value <<= operand.shift.value
        return value

    def run(self):
        pc = self.image.entry_offset
        for _ in range(10000):
            ins = ar.decode(self.load(pc, 4), pc)
            ops, mnemonic = ins.operands, ins.mnemonic
            next_pc = pc + 4
            if mnemonic == 'b':
                next_pc = ops[0].imm
            elif mnemonic == 'br' and self.host_target is not None:
                self.transferred_target = self.get_reg(self.name(ins, ops[0]))
                assert self.transferred_target == self.host_target, 'captured target changed'
                assert self.sp == self.start_sp, 'host transfer uses scratch stack'
                return self.x[0]  # Stop at the host ABI boundary, without simulating its implementation.
            elif mnemonic == 'br':
                next_pc = self.get_reg(self.name(ins, ops[0]))
            elif mnemonic == 'blr':
                helper = self.get_reg(self.name(ins, ops[0]))
                self.x[30] = next_pc
                if helper == 0x100001:
                    # The real accessor owns an 800-byte frame below current
                    # SP. Model that write so a too-shallow SP redirect cannot
                    # accidentally pass negative-offset load tests.
                    self.store(self.sp - 800, int.from_bytes(b'\xA5' * 800, 'little'), 800)
                    self.x[16] = self.state
                elif helper == 0x100002:
                    gate = next(g for g in self.image.gates if g.return_offset == next_pc)
                    self.calls.append((gate.kind, gate.argument))
                    if gate.kind == ar.SVC:
                        self.x[0] += gate.argument
                    elif gate.kind == ar.TIMER and gate.argument == 18:
                        self.store(self.state, 0x1000 + gate.argument, 8)
                    elif gate.kind == ar.TIMER and gate.argument != 31:
                        self.x[gate.argument] = 0x1000 + gate.argument
                else:
                    raise AssertionError('unexpected helper pointer')
            elif mnemonic == 'ret':
                target = self.get_reg(self.name(ins, ops[0])) if ops else self.x[30]
                if target == 0xFFFFFFFFFFFFFFFC:
                    assert self.sp == self.start_sp, 'leaked scratch stack'
                    return self.x[0]
                next_pc = target
            elif mnemonic == 'mrs' and ins.op_str.endswith(', nzcv'):
                self.set_reg(self.name(ins, ops[0]), self.flags & 0xF0000000)
            elif mnemonic == 'msr' and ins.op_str.startswith('nzcv,'):
                self.flags = self.value(ins, ops[1]) & 0xF0000000
            elif mnemonic in ('mov', 'adr', 'adrp'):
                self.set_reg(self.name(ins, ops[0]), self.value(ins, ops[1]))
            elif mnemonic == 'lsr':
                self.set_reg(self.name(ins, ops[0]), self.value(ins, ops[1]) >> ops[2].imm)
            elif mnemonic == 'lsl':
                self.set_reg(self.name(ins, ops[0]), self.value(ins, ops[1]) << ops[2].imm)
            elif mnemonic == 'ror':
                name=self.name(ins,ops[0]);bits=32 if name.startswith('w') else 64
                value=self.value(ins,ops[1]);shift=ops[2].imm%bits
                self.set_reg(name,(value>>shift)|(value<<((bits-shift)%bits)))
            elif mnemonic == 'bfi':
                name=self.name(ins, ops[0]);shift,width=ops[2].imm,ops[3].imm
                mask=((1<<width)-1)<<shift
                self.set_reg(name,(self.get_reg(name)&~mask)|((self.value(ins,ops[1])<<shift)&mask))
            elif mnemonic == 'ubfx':
                self.set_reg(self.name(ins,ops[0]),(self.value(ins,ops[1])>>ops[2].imm)&((1<<ops[3].imm)-1))
            elif mnemonic == 'sxth':
                value=self.value(ins,ops[1])&0xFFFF
                self.set_reg(self.name(ins,ops[0]),value-0x10000 if value&0x8000 else value)
            elif mnemonic in ('orr', 'and'):
                left,right=self.value(ins,ops[1]),self.value(ins,ops[2])
                self.set_reg(self.name(ins,ops[0]),left|right if mnemonic=='orr' else left&right)
            elif mnemonic in ('mul', 'madd'):
                value=self.value(ins,ops[1])*self.value(ins,ops[2])
                self.set_reg(self.name(ins,ops[0]),value+(self.value(ins,ops[3]) if mnemonic=='madd' else 0))
            elif mnemonic in ('add', 'sub', 'adds', 'subs', 'cmp', 'cmn'):
                compare = mnemonic in ('cmp', 'cmn')
                left, right = (self.value(ins, ops[0]), self.value(ins, ops[1])) if compare else (self.value(ins, ops[1]), self.value(ins, ops[2]))
                subtract = mnemonic in ('sub', 'subs', 'cmp')
                value = left - right if subtract else left + right
                name = self.name(ins, ops[0])
                if not compare:
                    self.set_reg(name, value)
                if mnemonic in ('adds', 'subs', 'cmp', 'cmn'):
                    bits = 32 if name.startswith('w') else 64
                    masked = value & ((1 << bits) - 1)
                    sign = 1 << (bits - 1)
                    left_u, right_u = left & ((1 << bits) - 1), right & ((1 << bits) - 1)
                    carry = left_u >= right_u if subtract else left_u + right_u >= 1 << bits
                    overflow = bool((left_u ^ right_u if subtract else ~(left_u ^ right_u)) & (left_u ^ masked) & sign)
                    self.flags = ((bool(masked & sign) << 3) | ((masked == 0) << 2) | (carry << 1) | overflow) << 28
            elif mnemonic == 'b.hi':
                if (self.flags & (1 << 29)) and not (self.flags & (1 << 30)):
                    next_pc = ops[0].imm
            elif mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                value = self.value(ins, ops[0])
                zero = (value == 0) if mnemonic.startswith('cb') else not (value >> ops[1].imm & 1)
                if zero == (mnemonic in ('cbz', 'tbz')):
                    next_pc = ops[-1].imm
            elif mnemonic.startswith(('ldr', 'str', 'ldur', 'stur')) or mnemonic in ('ldp', 'stp', 'ldpsw', 'ldnp', 'stnp'):
                load = mnemonic.startswith('ld')
                pair = mnemonic in ('ldp', 'stp', 'ldpsw', 'ldnp', 'stnp')
                mem = next((op for op in ops if op.type == ARM64_OP_MEM), ops[-1])
                post = mem.type == ARM64_OP_MEM and ins.writeback and ops[-1].type == ARM64_OP_IMM
                base = None
                if mem.type == ARM64_OP_IMM:
                    address = mem.imm
                else:
                    base = ins.reg_name(mem.mem.base)
                    old_base = self.get_reg(base)
                    address = old_base + mem.mem.disp
                    if mem.mem.index:
                        index = self.get_reg(ins.reg_name(mem.mem.index))
                        if mem.ext in (a64.ARM64_EXT_SXTW, a64.ARM64_EXT_SXTX):
                            bits = 32 if mem.ext == a64.ARM64_EXT_SXTW else 64
                            index &= (1 << bits) - 1
                            if index & (1 << (bits - 1)):
                                index -= 1 << bits
                        address += index << mem.shift.value
                    if base == 'sp':
                        lowest = min(self.sp, address) if ins.writeback else self.sp
                        assert lowest <= address and address + (16 if pair else 8) <= self.start_sp, 'unallocated stack access'
                suffix = mnemonic[4:] if mnemonic.startswith(('ldur', 'stur')) else mnemonic[3:]
                signed = load and (suffix in ('sb', 'sh', 'sw') or mnemonic == 'ldpsw')
                size = 1 if suffix in ('b', 'sb') else 2 if suffix in ('h', 'sh') else 4 if signed or self.name(ins, ops[0]).startswith('w') else 8
                # Pair reads happen before either destination or writeback,
                # including instructions whose first result is the old base.
                values = [self.load(address + i * size, size) if load else self.get_reg(self.name(ins, ops[i])) for i in range(2 if pair else 1)]
                for index, value in enumerate(values):
                    name = self.name(ins, ops[index])
                    if load:
                        if signed and value & (1 << (size * 8 - 1)):
                            value -= 1 << (size * 8)
                        self.set_reg(name, value)
                    else:
                        self.store(address + index * size, value, size)
                if base and ins.writeback:
                    self.set_reg(base, old_base + ops[-1].imm if post else address)
            elif mnemonic != 'nop':
                raise AssertionError(f'unsupported interpreter instruction {ins.mnemonic} {ins.op_str}')
            pc = next_pc
        raise AssertionError('instruction budget exhausted (LR/control-flow corruption)')


class AndroidRewriteTests(unittest.TestCase):
    def test_guarded_transfer_preserves_gprs_flags_and_stack_at_host_boundary(self):
        for link, registers in ((False, (0, 16, 17, 29, 30)), (True, (0, 8, 16, 17, 29))):
            for register in registers:
                original = (0xD63F0000 if link else 0xD61F0000) | register << 5
                image = ar.rewrite(raw(original, 0xD65F03C0), package_version=2,
                                   indirect_policy='guarded-host', guarded_indirect_offsets=(0,))
                machine = Machine(image)
                machine.host_target = machine.x[register] = 0x400000
                expected = list(machine.x)
                if link:
                    expected[30] = 4
                flags = machine.flags
                machine.run()
                self.assertEqual(machine.x, expected)
                self.assertEqual(machine.flags, flags)
                self.assertEqual(machine.sp, machine.start_sp)
                self.assertEqual(machine.calls, [(4, register)])

    def test_guarded_transfer_decodes_to_restored_tail_branch_and_original_lr(self):
        for link, registers in ((False, (0, 16, 17, 29, 30)), (True, (0, 8, 16, 17, 29))):
            for register in registers:
                original = (0xD63F0000 if link else 0xD61F0000) | register << 5
                image = ar.rewrite(raw(original, 0xD65F03C0), package_version=2,
                                   indirect_policy='guarded-host', guarded_indirect_offsets=(0,), patch_offset=0x5000)
                gate = image.gates[0]
                self.assertEqual((gate.kind, gate.argument), (4, register))
                self.assertEqual(image.gate_provenance[0], ar.GateProvenance(gate.return_offset, 0, original))
                tail = [ar.decode(struct.unpack_from('<I', image.bytes, pc)[0], pc)
                        for pc in range(gate.return_offset, gate.return_offset + (20 if link else 12), 4)]
                self.assertEqual([x.mnemonic for x in tail], ['ldp', 'add'] + (['adrp', 'add'] if link else []) + ['br'])
                self.assertEqual(tail[-1].op_str, 'x' + str(register))
                if link:
                    self.assertEqual(tail[2].operands[1].imm + tail[3].operands[2].imm, 4)
                self.assertEqual(image.metadata()['indirect_policy'], 'guarded-host')

    def test_guarded_transfer_rejects_raw_v1_unsafe_registers_and_bad_sites(self):
        for options in ({}, {'indirect_policy': 'guarded-host'}, {'package_version': 2}):
            with self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(0xD63F0000, 0xD65F03C0), guarded_indirect_offsets=(0,), **options)
        for original in (0xD63F0240, 0xD61F0240, 0xD63F03C0, 0xD61F03E0, 0xD503201F, 0xD73F0800):
            with self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(original, 0xD65F03C0), package_version=2,
                           indirect_policy='guarded-host', guarded_indirect_offsets=(0,))

    def test_guarded_blr_lr_continuation_crosses_original_page(self):
        data = bytes(0xFFC) + raw(0xD63F0100, 0xD65F03C0)
        image = ar.rewrite(data, entry_offset=0xFFC, code_ranges=((0xFFC, len(data)),),
                           patch_offset=0x9000, package_version=2, indirect_policy='guarded-host',
                           guarded_indirect_offsets=(0xFFC,))
        pc = image.gates[0].return_offset + 8
        adrp, add = (ar.decode(struct.unpack_from('<I', image.bytes, at)[0], at) for at in (pc, pc + 4))
        self.assertEqual(adrp.operands[1].imm, 0x1000)
        self.assertEqual(add.operands[2].imm, 0)
        for invalid in ((4,), (0xFFC, 3)):
            with self.assertRaises(ar.RewriteError):
                ar.rewrite(data, entry_offset=0xFFC, code_ranges=((0xFFC, len(data)),),
                           package_version=2, indirect_policy='guarded-host', guarded_indirect_offsets=invalid)

    @classmethod
    def setUpClass(cls):
        cls.tools = gen.toolchain()

    def fixture(self, name):
        return ar.rewrite(gen.assemble(gen.FIXTURES / (name + '.S'), self.tools))

    def assembled(self, source):
        with tempfile.TemporaryDirectory(prefix='dm-sp-semantics-') as temporary:
            path = Path(temporary) / 'case.S'
            path.write_text('.text\n.global fixture\nfixture:\n' + source + '\n', encoding='utf-8')
            return ar.rewrite(gen.assemble(path, self.tools))

    def test_arithmetic_memory_and_live_lr_semantics(self):
        for name, increment in (('x18_arithmetic', 7), ('live_lr', 9)):
            image = self.fixture(name)
            for value in (0, 34, 0xFFFFFFFFFFFFFFFE):
                machine = Machine(image)
                initial_host18 = machine.x[18]
                machine.x[0] = value
                self.assertEqual(machine.run(), (value + increment) & 0xFFFFFFFFFFFFFFFF)
                self.assertEqual(machine.load(machine.state, 8), (value + increment) & 0xFFFFFFFFFFFFFFFF)
                self.assertEqual(machine.x[18], initial_host18)
                self.assertEqual(machine.flags, 0x60000000)
        machine = Machine(self.fixture('x18_memory'))
        machine.x[0] = 0x400000
        machine.store(0x400000, 17, 8)
        self.assertEqual(machine.run(), 22)
        self.assertEqual(machine.load(0x400000, 8), 22)

    def test_conditional_both_cleanup_exits(self):
        for value, expected in ((0, 11), (1, 22), (0x100000000, 22)):
            machine = Machine(self.fixture('x18_conditional'))
            original = list(machine.x)
            machine.x[0] = value
            self.assertEqual(machine.run(), expected)
            self.assertEqual(machine.x[1:], original[1:])
            self.assertEqual(machine.load(machine.state, 8), value)

    def test_tls_x18_source_and_destination(self):
        machine = Machine(self.fixture('tls'))
        machine.x[0] = 27
        machine.store(machine.state + 16, 101, 8)
        self.assertEqual(machine.run(), 131)
        self.assertEqual(machine.load(machine.state + 8, 8), 30)
        self.assertEqual(machine.load(machine.state, 8), 101)
        self.assertEqual(machine.x[18], 0x112)

    def test_timer_callee_saved_and_svc_metadata(self):
        machine = Machine(self.fixture('timer'))
        original = list(machine.x)
        machine.x[0] = 0x400000
        machine.run()
        self.assertEqual(machine.x[19:31], original[19:31])
        self.assertEqual(machine.calls, [(ar.TIMER, n) for n in (19, 20, 21, 22, 23, 18)])
        self.assertEqual([machine.load(0x400000 + i * 8, 8) for i in range(6)], [0x1000 + n for n in (19, 20, 21, 22, 23, 18)])
        machine = Machine(self.fixture('svc'))
        machine.x[0] = 9
        self.assertEqual(machine.run(), 75)
        self.assertEqual(machine.calls, [(ar.SVC, 0x42)])

    def test_flag_setting_virtual_w18_zero_extends(self):
        # adds w18,w0,#1; mov x0,x18; ret
        machine = Machine(ar.rewrite(raw(0x31000412, 0xAA1203E0, 0xD65F03C0)))
        machine.x[0] = 0xFFFFFFFF
        machine.flags = 0xA0000000
        self.assertEqual(machine.run(), 0)
        self.assertEqual(machine.load(machine.state, 8), 0)
        self.assertEqual(machine.flags, 0x60000000)  # Z/C set by original adds

    def test_live_original_lr_operand_and_test_bit_exits(self):
        # add x18,x0,x30; mov x0,x18; ret
        machine = Machine(ar.rewrite(raw(0x8B1E0012, 0xAA1203E0, 0xD65F03C0)))
        machine.x[0] = 12
        self.assertEqual(machine.run(), 8)  # Original LR (-4), not helper return PC.
        # mov x18,x0; tbnz x18,#40,16; mov x0,#22; ret; mov x0,#11; ret
        image = ar.rewrite(raw(0xAA0003F2, 0xB7400072, 0xD28002C0,
                               0xD65F03C0, 0xD2800160, 0xD65F03C0))
        for value, expected in ((0, 22), (1 << 40, 11)):
            machine = Machine(image)
            machine.x[0] = value
            self.assertEqual(machine.run(), expected)
            self.assertEqual(machine.load(machine.state, 8), value)

    def test_pc_relative_targets_use_original_image(self):
        # adr x18,0; mov x0,x18; ret
        machine = Machine(ar.rewrite(raw(0x10000012, 0xAA1203E0, 0xD65F03C0)))
        self.assertEqual(machine.run(), 0)
        # Force ADRP relocation into a different page from its original site.
        machine = Machine(ar.rewrite(raw(0x90000012, 0xAA1203E0, 0xD65F03C0) + raw(0xD503201F) * 1024))
        self.assertEqual(machine.run(), 0)
        # ldr x18,literal at12; mov x0,x18; ret; .quad 0x1234
        machine = Machine(ar.rewrite(raw(0x58000072, 0xAA1203E0, 0xD65F03C0) + struct.pack('<Q', 0x1234), text_size=12))
        self.assertEqual(machine.run(), 0x1234)

    def test_fail_closed_has_exact_site(self):
        cases = ((0xD61F0240, 'indirect'), (0xF8408FF2, 'unaligned SP'),
                 (0xD5380012, 'system register'))
        for instruction, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ar.RewriteError, '0x4:.*' + reason):
                    ar.rewrite(raw(0xD503201F, instruction, 0xD65F03C0))
        with self.assertRaisesRegex(ar.RewriteError, '0x8:.*exclusive.*0x4'):
            ar.rewrite(raw(0xD503201F, 0xC85F7C12, 0xD65F03C0))
        # ldxr x0,[x1]; svc#0x42; stxr w2,x0,[x1]; ret
        with self.assertRaisesRegex(ar.RewriteError, '0x4:.*exclusive window'):
            ar.rewrite(raw(0xC85F7C20, 0xD4000841, 0xC8027C20, 0xD65F03C0))
        # The branch skips the adjacent store, so a linear window scan is unsafe.
        with self.assertRaisesRegex(ar.RewriteError, '0x10:.*exclusive window'):
            ar.rewrite(raw(0xC85F7C20, 0x14000003, 0xC8027C20,
                           0xD65F03C0, 0xD4000841, 0xD65F03C0))

    def test_input_and_metadata_bounds(self):
        for data in (b'', b'\0', raw(0)):
            with self.assertRaises(ar.RewriteError):
                ar.rewrite(data)
        with self.assertRaisesRegex(ar.RewriteError, 'entry'):
            ar.rewrite(raw(0xD65F03C0), entry_offset=4)
        image = self.fixture('svc')
        for damaged in (replace(image, abi=0), replace(image, target='apple'),
                        replace(image, entry_offset=len(image.bytes)),
                        replace(image, fixups=(ar.Fixup(len(image.bytes), 2),)),
                        replace(image, fixups=(ar.Fixup(1, 2),)),
                        replace(image, fixups=(image.fixups[0], image.fixups[0])),
                        replace(image, gates=(ar.Gate(4, ar.SVC, 1),)),
                        replace(image, gates=(replace(image.gates[0], argument=65536),))):
            with self.assertRaises(ar.RewriteError):
                damaged.validate()
        for fixup in image.fixups:
            self.assertEqual(image.bytes[fixup.offset:fixup.offset + 8], b'\0' * 8)

    def test_instruction_spans_cannot_overlap_helper_literals(self):
        # BLR at12 is valid code, but its return instruction at16 is a helper
        # pointer slot. Loader fixups would turn that return into arbitrary data.
        image = ar.Image(raw(0xD65F03C0, 0xD503201F, 0xD503201F,
                             0xD63F03C0, 0, 0), 0,
                         (ar.Fixup(16, ar.DISPATCH_HELPER),),
                         (ar.Gate(16, ar.SVC, 0),), ())
        with self.assertRaisesRegex(ar.RewriteError, 'gate call/return.*overlap'):
            image.validate()
        # A return at24 lies outside the slot, but the preceding instruction at20
        # lies inside its last four bytes. Check both instruction spans explicitly.
        call_overlap = replace(image, bytes=image.bytes + raw(0xD503201F),
                               gates=(ar.Gate(24, ar.SVC, 0),))
        with self.assertRaisesRegex(ar.RewriteError, 'gate call/return.*overlap'):
            call_overlap.validate()
        with self.assertRaisesRegex(ar.RewriteError, 'entry instruction.*overlap'):
            replace(image, entry_offset=16, gates=()).validate()
        with self.assertRaisesRegex(ar.RewriteError, 'entry instruction.*overlap'):
            replace(image, entry_offset=20, gates=()).validate()

    def test_sparse_module_code_preserves_embedded_data_and_patch_alignment(self):
        # b24; nop; embedded module marker/data; svc#0x42; ret; trailing data
        data = (raw(0x14000006, 0xD503201F) + b'NSOMOD0\0' + b'\0' * 8 +
                raw(0xD4000841, 0xD65F03C0) + b'\0' * 16)
        image = ar.rewrite(data, text_size=32, code_ranges=[(0, 8), (24, 32)],
                           patch_offset=16 * 1024)
        self.assertEqual(image.bytes[8:24], data[8:24])
        self.assertEqual(image.bytes[32:len(data)], data[32:])
        self.assertEqual(image.bytes[len(data):16 * 1024], b'\0' * (16 * 1024 - len(data)))
        self.assertEqual([site.offset for site in image.sites], [24])
        self.assertEqual(image.sites[0].trampoline, 16 * 1024)
        machine = Machine(image)
        machine.x[0] = 9
        self.assertEqual(machine.run(), 75)
        self.assertEqual(machine.calls, [(ar.SVC, 0x42)])

    def test_sp_relative_x18_preserves_original_address_and_scratch_registers(self):
        # Allocate guest stack, write/read x18 at the original SP + 16, return it.
        image = ar.rewrite(raw(0xD10083FF, 0xAA0003F2, 0xF9000BF2,
                               0xF9400BF2, 0x91000E40, 0x910083FF, 0xD65F03C0))
        for value in (0, 1234, 0xFFFFFFFFFFFFFFFE):
            machine = Machine(image)
            original = list(machine.x)
            machine.x[0] = value
            self.assertEqual(machine.run(), (value + 3) & 0xFFFFFFFFFFFFFFFF)
            self.assertEqual(machine.load(machine.start_sp - 16, 8), value)
            self.assertEqual(machine.x[1:], original[1:])
            self.assertEqual(machine.flags, 0x60000000)
        # Pair operands exercise both data fields while SP is redirected.
        image = ar.rewrite(raw(0xD10083FF, 0xAA0003F2, 0xA90007F2,
                               0xA94007F2, 0xAA1203E0, 0x910083FF, 0xD65F03C0))
        machine = Machine(image)
        machine.x[0] = 123
        self.assertEqual(machine.run(), 123)
        self.assertEqual(machine.load(machine.start_sp - 32, 8), 123)
        self.assertEqual(machine.load(machine.start_sp - 24, 8), 0x101)
        self.assertEqual(machine.x[1], 0x101)

    def test_sp_immediate_memory_and_writeback_use_original_stack(self):
        seed = 0xFFEEDDCCBBAA9988
        base = 0x200000 - 1024
        # mnemonic, effective offset, final SP delta, width, pair, load, result
        cases = (
            ('str x18, [sp, #-16]!', -16, -16, 8, False, False, seed),
            ('ldr x18, [sp], #16', 0, 16, 8, False, True, seed),
            ('str x18, [sp, #-256]!', -256, -256, 8, False, False, seed),
            ('ldr x18, [sp], #240', 0, 240, 8, False, True, seed),
            ('stp x18, x16, [sp, #-512]!', -512, -512, 8, True, False, seed),
            ('ldp x16, x18, [sp], #496', 0, 496, 8, True, True, seed),
            ('ldpsw x18, x16, [sp, #-256]!', -256, -256, 4, True, True, 0xFFFFFFFFBBAA9988),
            ('ldpsw x16, x18, [sp], #240', 0, 240, 4, True, True, 0xFFFFFFFFBBAA9988),
            ('stur x18, [sp, #-8]', -8, 0, 8, False, False, seed),
            ('ldur x18, [sp, #-256]', -256, 0, 8, False, True, seed),
            ('sturb w18, [sp, #-8]', -8, 0, 1, False, False, seed),
            ('sturh w18, [sp, #-8]', -8, 0, 2, False, False, seed),
            ('ldursb w18, [sp, #-8]', -8, 0, 1, False, True, 0xFFFFFF88),
            ('ldursb x18, [sp, #-8]', -8, 0, 1, False, True, 0xFFFFFFFFFFFFFF88),
            ('ldursh w18, [sp, #-8]', -8, 0, 2, False, True, 0xFFFF9988),
            ('ldursh x18, [sp, #-8]', -8, 0, 2, False, True, 0xFFFFFFFFFFFF9988),
            ('stnp x18, x16, [sp, #-16]', -16, 0, 8, True, False, seed),
            ('ldnp x16, x18, [sp, #-16]', -16, 0, 8, True, True, seed),
        )
        for instruction, offset, delta, width, pair, load, expected in cases:
            with self.subTest(instruction=instruction):
                first18 = not pair or instruction.split(',')[0].endswith('x18')
                # Observe a negative-offset store before a later helper reuses
                # inactive memory below SP, as required by AAPCS64.
                observe = ''
                if not load:
                    adjust = ('sub' if offset < 0 else 'add') + f' x12,x12,#{abs(offset)}'
                    read = {1: 'ldrb w11', 2: 'ldrh w11', 8: 'ldr x11'}[width]
                    observe = f'{adjust}\n{read},[x12,#{0 if first18 else width}]\n'
                image = self.assembled(f'sub sp,sp,#1024\nmov x12,sp\n{instruction}\n{observe}mov x10,sp\nmov x0,x18\nadd sp,sp,#{1024-delta}\nret')
                machine = Machine(image)
                machine.store(machine.state, seed, 8)
                address = base + offset
                machine.store(address, seed if first18 else 0x1234, width)
                if pair:
                    machine.store(address + width, 0x1234 if first18 else seed, width)
                self.assertEqual(machine.run(), expected)
                self.assertEqual(machine.x[10], base + delta)
                self.assertEqual(machine.x[18], 0x112)
                self.assertEqual(machine.flags, 0x60000000)
                if not load:
                    self.assertEqual(machine.x[11], seed & ((1 << (width * 8)) - 1))
                    self.assertEqual(machine.load(machine.state, 8), seed)
                if pair:
                    self.assertEqual(machine.x[16], 0x1234 if load else 0x110)

    def test_sp_source_arithmetic_and_flags_preserve_address_and_width(self):
        base = 0x200000 - 1024
        cases = (
            ('mov x18, sp', 0xABCD, base, 0x60000000),
            ('mov w18, wsp', 0xABCD, base, 0x60000000),
            ('add x18, sp, #48', 0xABCD, base + 48, 0x60000000),
            ('sub x18, sp, #32', 0xABCD, base - 32, 0x60000000),
            ('add x18, sp, x18', 17, base + 17, 0x60000000),
            ('add x18, sp, w18, sxtw #2', 0xFFFFFFFF, base - 4, 0x60000000),
            ('adds x18, sp, w18, sxtw #2', 0xFFFFFFFF, base - 4, 0x20000000),
            ('adds x18, sp, x18', -base & ((1 << 64) - 1), 0, 0x60000000),
            ('cmp sp, x18', base, base, 0x60000000),
        )
        for instruction, seed, expected, flags in cases:
            with self.subTest(instruction=instruction):
                machine = Machine(self.assembled('sub sp,sp,#1024\n' + instruction + '\nmov x0,x18\nadd sp,sp,#1024\nret'))
                machine.store(machine.state, seed, 8)
                original = list(machine.x)
                self.assertEqual(machine.run(), expected)
                self.assertEqual(machine.flags, flags)
                self.assertEqual(machine.x[1:], original[1:])
        machine = Machine(self.assembled('sub sp,sp,#1024\nadd x0,sp,x18\nadd sp,sp,#1024\nret'))
        machine.store(machine.state, 13, 8)
        self.assertEqual(machine.run(), base + 13)
        self.assertEqual(machine.load(machine.state, 8), 13)
        # A WSP source must truncate high address bits and zero-extend W18.
        machine = Machine(self.assembled('mov w18,wsp\nmov x0,x18\nret'))
        machine.sp = machine.start_sp = 0x100200000
        self.assertEqual(machine.run(), 0x200000)

    def test_sp_unbounded_addresses_pivots_and_unpredictable_overlap_rejected(self):
        for source in ('ldr x18,[sp,x0]', 'ldr x18,[sp,w0,sxtw]',
                       'mov sp,x18', 'sub sp,sp,x18', 'ldr x18,[sp],#8',
                       '.inst 0xf8008e52', '.inst 0xf8008652'):
            with self.subTest(source=source), self.assertRaises(ar.RewriteError):
                self.assembled(source + '\nret')
        # No writeback: reading or storing the original virtual base is valid.
        for source, seed in (('ldr x18,[x18]', 0x400000), ('str x18,[x18]', 0x400000)):
            machine = Machine(self.assembled(source + '\nmov x0,x18\nret'))
            machine.store(machine.state, seed, 8)
            machine.store(seed, 99, 8)
            result = machine.run()
            self.assertEqual(result, 99 if source.startswith('ldr') else seed)

    def test_sparse_code_domains_and_patch_offsets_fail_closed(self):
        data = raw(0xD65F03C0, 0, 0xD503201F, 0xD65F03C0)
        for ranges in ([], [(0, 2)], [(0, 8), (4, 12)], [(8, 16), (0, 4)],
                       [(-4, 4)], [(0, 20)], [(0, 0)], [(0, 4, 8)], [(0, '4')]):
            with self.subTest(ranges=ranges), self.assertRaises(ar.RewriteError):
                ar.rewrite(data, code_ranges=ranges)
        for offset in (0, 17, -4, '16'):
            with self.subTest(offset=offset), self.assertRaisesRegex(ar.RewriteError, 'patch offset'):
                ar.rewrite(data, code_ranges=[(0, 4)], patch_offset=offset)
        with self.assertRaisesRegex(ar.RewriteError, 'entry'):
            ar.rewrite(data, entry_offset=4, code_ranges=[(0, 4), (8, 16)])
        with self.assertRaisesRegex(ar.RewriteError, '0x4: invalid ARM64'):
            ar.rewrite(data, code_ranges=[(0, 8)])
        with self.assertRaisesRegex(ar.RewriteError, '0x0: direct branch outside selected code'):
            ar.rewrite(raw(0x14000001) + data[4:], code_ranges=[(0, 4), (8, 16)])

    def test_exclusive_cfg_across_sparse_code_domain(self):
        # ldxr; b16; invalid embedded data; svc; ret
        with self.assertRaisesRegex(ar.RewriteError, '0x10:.*exclusive window'):
            ar.rewrite(raw(0xC85F7C20, 0x14000003, 0, 0, 0xD4000841, 0xD65F03C0),
                       code_ranges=[(0, 8), (16, 24)])
        # A fallthrough into excluded data cannot prove exclusivity was cleared.
        with self.assertRaisesRegex(ar.RewriteError, '0x4:.*unbounded exclusive'):
            ar.rewrite(raw(0xC85F7C20, 0, 0xD4000841, 0xD65F03C0),
                       code_ranges=[(0, 4), (8, 16)])
        # Clear the monitor before the hole and the later helper is safe.
        image = ar.rewrite(raw(0xC85F7C20, 0xD5033F5F, 0, 0, 0xD4000841, 0xD65F03C0),
                           code_ranges=[(0, 8), (16, 24)])
        self.assertEqual([site.offset for site in image.sites], [16])

    def test_large_patch_region_uses_reachable_local_helper_pools(self):
        # More than 1 MiB of emitted trampolines reproduces the original global
        # end-pool reach failure; the raw input itself is only about 160 KiB.
        data = raw(0xD65F03C0) + raw(0xD4000841) * 40000 + raw(0xD65F03C0)
        patch_offset = (len(data) + 16383) & ~16383
        image = ar.rewrite(data, patch_offset=patch_offset)
        self.assertGreater(len(image.bytes) - patch_offset, 1 << 20)
        self.assertGreater(len(image.fixups), 4)
        slots = {fixup.offset for fixup in image.fixups}
        self.assertTrue(all(offset % 8 == 0 for offset in slots))
        self.assertEqual(image.bytes[len(data):patch_offset], b'\0' * (patch_offset - len(data)))
        for site in image.sites:
            load_pc = site.trampoline + 8
            load = ar.decode(struct.unpack_from('<I', image.bytes, load_pc)[0], load_pc)
            self.assertEqual(load.mnemonic, 'ldr')
            self.assertIn(load.operands[1].imm, slots)
            self.assertLess(abs(load.operands[1].imm - load_pc), 1 << 20)
        for offset in slots:
            # Optional alignment NOP follows the unconditional trampoline exit.
            previous = offset - 4
            if image.bytes[previous:offset] == raw(0xD503201F):
                previous -= 4
            self.assertEqual(ar.decode(struct.unpack_from('<I', image.bytes, previous)[0], previous).mnemonic, 'b')


if __name__ == '__main__':
    unittest.main()
