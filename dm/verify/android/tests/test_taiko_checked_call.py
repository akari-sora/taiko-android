"""Execute self-authored checked-call stencils on Unicorn's AArch64 CPU."""
from pathlib import Path
import struct
import sys
import unittest
from dataclasses import replace
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import taiko_call_contract as contract
from nso_format import Section, Relocation
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
from unicorn import arm64_const as uc


def raw(*words):
    return b''.join(ar.word(value) for value in words)


def fixture():
    # The callee reads every guest GPR/SIMD value before using X0/X1 as scratch.
    body = []
    for first in range(0, 30, 2):
        body.append(ar.pair(False, first, first + 1, first * 8) & ~(31 << 5) | 28 << 5)
    body.append(ar.memory(False, 30, 28, 30 * 8))
    for vector in range(32):
        body.append(0x3D800000 | ((0x100 + vector * 16) // 16) << 10 | 28 << 5 | vector)
    body.extend((0xD53B4200, ar.memory(False, 0, 28, 0x300),
                 0x910003E0, ar.memory(False, 0, 28, 0x308),
                 ar.pair(True, 0, 1, 0),
                 ar.memory(False, 0, 28, 0x310), ar.memory(False, 1, 28, 0x318),
                 0xD65F03C0))
    source = raw(0xD63F0240, 0xD4200020) + bytes(0x100 - 8) + raw(*body)
    return source, [(0, 8), (0x100, len(source))]


class CheckedCallTests(unittest.TestCase):
    def image(self):
        source, ranges = fixture()
        return ar.rewrite(source, code_ranges=ranges, entry_offsets=[0, 0x100],
                          package_version=2, checked_stack=True, checked_call_targets={0: 0x100})

    def execute(self, value, *, base=0x10000000, flags=0xB0000000):
        image = self.image()
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        cpu.mem_map(base, 0x10000)
        cpu.mem_map(0x20000000, 0x10000)
        cpu.mem_map(0x30000000, 0x10000)
        state, helper, output, stack = 0x30000000, 0x30001000, 0x30002000, 0x20008000
        cpu.mem_write(base, image.bytes)
        cpu.mem_write(helper, raw(0x58000050, 0xD65F03C0) + struct.pack('<Q', state))
        for fixup in image.fixups:
            self.assertEqual(ar.STATE_HELPER, fixup.helper)
            cpu.mem_write(base + fixup.offset, struct.pack('<Q', helper))
        virtual = value(base) if callable(value) else value
        cpu.mem_write(state, struct.pack('<Q', virtual))
        expected = [0x1234567800000000 + index * 0x10101 for index in range(31)]
        expected[18] = 0x7FFF00000000ABCD  # Android's platform register, never guest state.
        expected[28] = output
        for index, value in enumerate(expected):
            cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{index}'), value)
        vectors = [int.from_bytes(bytes((index + byte) % 256 for byte in range(16)), 'little')
                   for index in range(32)]
        for index, value in enumerate(vectors):
            cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{index}'), value)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack)
        cpu.reg_write(uc.UC_ARM64_REG_NZCV, flags)
        arguments = raw(0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00)
        cpu.mem_write(stack, arguments)
        observed = {'returned': False, 'trapped': False, 'target': False}

        def step(machine, pc, size, _):
            instruction = ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)
            self.assertFalse(ar.has18(instruction), 'No executed instruction may access hardware X18')
            if pc == base + 0x100:
                observed['target'] = True
            if pc == base + 4:
                observed['returned'] = True
                machine.emu_stop()

        def trap(machine, number, _):
            observed['trapped'] = True
            machine.emu_stop()

        cpu.hook_add(UC_HOOK_CODE, step)
        cpu.hook_add(UC_HOOK_INTR, trap)
        cpu.emu_start(base, base + len(image.bytes), count=10000)
        observed.update(cpu=cpu, expected=expected, vectors=vectors, output=output,
                        state=state, stack=stack, arguments=arguments, virtual=virtual)
        self.assertEqual(expected[18], cpu.reg_read(uc.UC_ARM64_REG_X18))
        self.assertEqual(virtual, struct.unpack('<Q', cpu.mem_read(state, 8))[0])
        self.assertEqual(arguments, bytes(cpu.mem_read(stack, len(arguments))))
        self.assertEqual(stack, cpu.reg_read(uc.UC_ARM64_REG_SP))
        return observed

    def test_exact_target_preserves_arguments_vectors_flags_stack_and_original_lr(self):
        for base in (0x10000000, 0x1200000000):
            for flags in (0, 0x60000000, 0xF0000000):
                with self.subTest(base=base, flags=flags):
                    result = self.execute(lambda address: address + 0x100, base=base, flags=flags)
                    self.assertTrue(result['target'])
                    self.assertTrue(result['returned'])
                    self.assertFalse(result['trapped'])
                    cpu, output = result['cpu'], result['output']
                    captured = list(struct.unpack('<31Q', cpu.mem_read(output, 31 * 8)))
                    expected = result['expected'][:]
                    expected[18], expected[30] = base + 0x100, base + 4
                    self.assertEqual(expected, captured)
                    for index, value in enumerate(result['vectors']):
                        self.assertEqual(value, int.from_bytes(cpu.mem_read(output + 0x100 + index * 16, 16), 'little'))
                    self.assertEqual((flags, result['stack']), struct.unpack('<2Q', cpu.mem_read(output + 0x300, 16)))
                    self.assertEqual(result['arguments'], bytes(cpu.mem_read(output + 0x310, 16)))

    def test_zero_unknown_and_target_interior_restore_before_trapping(self):
        for value in (0, 0x10000104, 0x10000004, 0x10000200, 0xFFFFFFFFFFFFFFFF):
            with self.subTest(value=value):
                result = self.execute(value)
                self.assertTrue(result['trapped'])
                self.assertFalse(result['target'])
                self.assertFalse(result['returned'])
                cpu = result['cpu']
                for index, expected in enumerate(result['expected']):
                    self.assertEqual(expected, cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{index}')))
                self.assertEqual(0xB0000000, cpu.reg_read(uc.UC_ARM64_REG_NZCV))
                for index, value in enumerate(result['vectors']):
                    self.assertEqual(value, cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{index}')))

    def test_checked_call_requires_checked_mode_exact_source_and_selected_target(self):
        source, ranges = fixture()
        for options in ({}, {'package_version': 2}, {'checked_stack': True}):
            with self.subTest(options=options), self.assertRaises(ar.RewriteError):
                ar.rewrite(source, code_ranges=ranges, checked_call_targets={0: 0x100}, **options)
        for mapping in ({0: 0x104}, {0: 0x80}, {4: 0x100}, {0: True}, {True: 0x100}):
            with self.subTest(mapping=mapping), self.assertRaises(ar.RewriteError):
                ar.rewrite(source, code_ranges=ranges, entry_offsets=[0, 0x100], package_version=2,
                           checked_stack=True, checked_call_targets=mapping)
        with self.assertRaisesRegex(ar.RewriteError, 'unsupported guarded blr x18'):
            ar.rewrite(source, code_ranges=ranges, package_version=2, checked_stack=True,
                       indirect_policy='guarded-host', guarded_indirect_offsets=[0])

    def test_unrelated_source_identity_has_no_versioned_call_authority(self):
        fake = SimpleNamespace(source_sha256=bytes(32), build_id=bytes(32))
        self.assertEqual((), contract.select_checked_calls(fake, None))


class CallContractTests(unittest.TestCase):
    def fixture(self):
        # Sparse self-authored evidence fixture; no original NSO is committed.
        words = {
            0xDBB6B8: (0xAA0003F3,),
            0xDBBDA4: (0xF9422A72, 0xBD01E661, 0xB4000232),
            0xDBC7A4: (0xD63F0240,),
            0xDB9A20: (0xF100003F, 0x1A9F07E8, 0xF9022801, 0xB9047408, 0xD65F03C0),
            0xED0560: (0xB0022381, 0xF942B021, 0x17FBA52E),
            0xED0570: (0xAA1F03E1, 0x17FBA52B),
            0xDB9050: (0xD10103FF, 0x6D0123E9, 0xA9027BFD, 0x910083FD),
        }
        class EvidenceImage(dict):
            def __getitem__(self, key):
                return bytes(self.get(pc, 0) for pc in range(key.start, key.stop))
        image = EvidenceImage()
        for offset, values in words.items():
            image.update({offset + index: byte for index, byte in enumerate(raw(*values))})
        nso = SimpleNamespace(image=image, source_sha256=bytes.fromhex(contract.MAIN_SHA256),
            build_id=bytes.fromhex(contract.MAIN_BUILD_ID),
            sections=(Section('text', 0, 0x3229144), Section('ro', 0x322A000, 0x1716CD4),
                      Section('data', 0x4941000, 0xA080A8)))
        metadata = SimpleNamespace(eh_starts=(0xDB9050, 0xDB9A20, 0xDBB640, 0xED0560, 0xED0570),
                                   relocations=(Relocation(0x5341560, 1027, 0, 0xDB9050),))
        return nso, metadata, words

    def test_exact_identity_and_chain_select_only_fixed_mutable_callback(self):
        nso, metadata, _ = self.fixture()
        selected = contract.select_checked_calls(nso, metadata)
        self.assertEqual(1, len(selected))
        self.assertEqual((0xDBC7A4, 0xDB9050, 0xD63F0240),
                         tuple(selected[0][key] for key in ('offset', 'target', 'source_word')))
        self.assertIn('runtime-exact', selected[0]['target_policy'])
        for field in ('source_sha256', 'build_id'):
            saved = getattr(nso, field)
            setattr(nso, field, bytes(32))
            self.assertEqual((), contract.select_checked_calls(nso, metadata))
            setattr(nso, field, saved)

    def test_changed_original_words_eh_entries_and_relocation_chain_fail_closed(self):
        nso, metadata, words = self.fixture()
        for offset, values in words.items():
            for index in range(len(values)):
                at = offset + index * 4
                before = nso.image.get(at, 0)
                nso.image[at] = before ^ 1
                with self.subTest(word=hex(at)), self.assertRaises(ValueError):
                    contract.select_checked_calls(nso, metadata)
                nso.image[at] = before
        for entry in metadata.eh_starts:
            damaged = SimpleNamespace(eh_starts=tuple(pc for pc in metadata.eh_starts if pc != entry),
                                      relocations=metadata.relocations)
            with self.subTest(entry=hex(entry)), self.assertRaises(ValueError):
                contract.select_checked_calls(nso, damaged)
        relocation = metadata.relocations[0]
        for field, value in (('kind', 257), ('symbol', 1), ('addend', 0xDB9054), ('offset', 0x5341568)):
            damaged = SimpleNamespace(eh_starts=metadata.eh_starts,
                                      relocations=(replace(relocation, **{field: value}),))
            with self.subTest(relocation=field), self.assertRaises(ValueError):
                contract.select_checked_calls(nso, damaged)
        metadata.relocations += metadata.relocations
        with self.assertRaises(ValueError):
            contract.select_checked_calls(nso, metadata)


if __name__ == '__main__':
    unittest.main()
