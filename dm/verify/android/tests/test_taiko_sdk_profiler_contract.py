"""Self-authored wrapper fixture; production source pins are never overridden.

Only structural-validator tests mock its selector with a private synthetic
layout. No CLI, package builder or provider uses that mock. The real selector
rejects this fixture; original SDK probes and mutations remain in ignored .local.
"""
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as ai
import android_rewrite as ar
import taiko_sdk_contract as contract
from nso_format import Nso, Section, Symbol, Relocation, Metadata


def fixture():
    """Assemble public AArch64 ISA operations independently of game input."""
    start, plt, got, hook = 0x400, 0x1200, 0x4000, 0x100
    image = bytearray(0x6000)
    names = ('SleepThread', 'SignalEvent', 'ClearEvent', 'CloseHandle', 'ResetSignal',
             'WaitSynchronization', 'ArbitrateLock', 'ArbitrateUnlock', 'WaitProcessWideKeyAtomic',
             'SignalProcessWideKey', 'SendSyncRequest', 'SendSyncRequestWithUserBuffer',
             'WaitForAddress', 'SignalToAddress', 'ReplyAndReceive', 'ReplyAndReceiveWithUserBuffer')
    ids = (11, 17, 18, 22, 23, 24, 26, 27, 28, 29, 33, 34, 52, 53, 67, 68)
    pairs = ((0, 1, 0), (2, 3, 16), (4, 5, 32), (6, 7, 48), (29, 30, 64))
    save = [0xD10143FF, *(ar.pair(False, a, b, offset) for a, b, offset in pairs), 0x910103FD]
    restore = [*(ar.pair(True, a, b, offset) for a, b, offset in pairs), 0x910143FF]
    symbols = [Symbol('', 0, 0, 0, 0, 0, 0)]
    relocations, hook_names = [], []
    cursor = start
    for index, (name, svc) in enumerate(zip(names, ids)):
        words = save + [None] + restore + [0xD4000001 | svc << 5] + save
        words += [0xB81F0FE1, 0x910003E1, None, 0x910043FF] if svc in (24, 67, 68) else [None]
        words += restore + [0xD503201F, 0xD65F03C0]
        phase = 0
        for relative, word in enumerate(words):
            pc = cursor + relative * 4
            if word is None:
                number = index * 2 + phase
                target, slot, implementation = plt + number * 16, got + number * 8, hook + number * 16
                word = 0x94000000 | (((target - pc) // 4) & 0x3FFFFFF)
                delta = ((slot & ~4095) - (target & ~4095)) // 4096
                page = 0x90000010 | (delta & 3) << 29 | ((delta >> 2) & 0x7FFFF) << 5
                struct.pack_into('<4I', image, target, page, ar.memory(True, 17, 16, slot & 4095),
                                 0x91000210 | (slot & 4095) << 10, 0xD61F0220)
                struct.pack_into('<I', image, implementation, 0xD65F03C0)
                hook_name = name + ('InterceptEnter' if phase == 0 else 'InterceptExit')
                # Authored signatures deliberately differ from the production hash.
                mangled = '_ZN2nn8profiler' + str(len(hook_name)) + hook_name + 'Ev'
                hook_names.append(mangled)
                symbols.append(Symbol(mangled, implementation, 4, 2, 2, 2, 0))
                relocations.append(Relocation(slot, 1026, len(symbols) - 1, 0))
                phase += 1
            struct.pack_into('<I', image, pc, word)
        cursor += len(words) * 4
    struct.pack_into('<I', image, start - 4, 0xD65F03C0)
    symbols.append(Symbol('_ZN2nn8profiler12svcIntercept6EnableEv', start - 4, 4, 1, 2, 2, 0))
    source_sha, build = hashlib.sha256(image).digest(), bytes.fromhex('11' * 32)
    nso = Nso(bytes(image), (Section('text', 0, 0x1800), Section('ro', 0x2000, 0x1000),
                            Section('data', 0x4000, 0x1000)), 0x1000, build, source_sha, 0, (0, 0), (0, 0))
    layout = contract.SdkProfilerLayout(source_sha.hex(), build.hex(), start, cursor,
                hashlib.sha256(image[start:cursor]).hexdigest(), plt, got, hook,
                hashlib.sha256('\n'.join(hook_names).encode()).hexdigest())
    metadata = Metadata(0, {}, tuple(symbols), tuple(relocations), 0, (), (), (), 'synthetic')
    return nso, metadata, layout


class SyntheticProfilerTests(unittest.TestCase):
    def setUp(self):
        self.nso, self.metadata, self.layout = fixture()

    def prove(self, nso=None, metadata=None, roots=(), layout=None):
        # Substitution exists only in this isolated structural proof call.
        # Compiled pins are unchanged; no import/provider publication is called.
        with patch.object(ai, 'select_sdk_profiler_layout', return_value=layout or self.layout):
            return ai._sdk_profiler_bank(nso or self.nso, metadata or self.metadata, set(roots))

    def changed(self, pc, word):
        image = bytearray(self.nso.image); struct.pack_into('<I', image, pc, word)
        return replace(self.nso, image=bytes(image))

    def test_real_selector_never_authorizes_the_synthetic_fixture(self):
        self.assertIsNone(contract.select_sdk_profiler_layout(self.nso))
        self.assertIsNone(ai._sdk_profiler_bank(self.nso, self.metadata, set()))
        forged = replace(self.nso, source_sha256=bytes.fromhex(contract.SDK_SHA256),
                         build_id=bytes.fromhex(contract.SDK_BUILD_ID))
        with self.assertRaisesRegex(ValueError, 'range'):
            contract.select_sdk_profiler_layout(forged)
        with self.assertRaisesRegex(ValueError, 'build identity'):
            contract.select_sdk_profiler_layout(replace(forged, build_id=bytes(32)))
        # A claimed container identity cannot authorize an independently
        # authored zero body, even with the compiled section geometry/RET.
        compiled = contract._TAIKO_PROFILER
        image = bytearray(compiled.got_start + 256)
        struct.pack_into('<I', image, compiled.start - 4, 0xD65F03C0)
        sections = (Section('text', 0, compiled.plt_start + 512),
                    Section('ro', compiled.plt_start + 512, 4),
                    Section('data', compiled.got_start, 256))
        forged = replace(forged, image=bytes(image), sections=sections, bss_size=0)
        with self.assertRaisesRegex(ValueError, 'body identity'):
            contract.select_sdk_profiler_layout(forged)

    def test_full_authored_bank_receives_all_independent_abi_rewrites_only(self):
        proof = self.prove()
        self.assertEqual((16, 16, 32, 70), tuple(len(proof[name]) for name in
                         ('analysis_entries', 'svc_offsets', 'call_offsets', 'checked_sp_offsets')))
        self.assertEqual((False, False, 'NOT_RUN'), (proof['runtime_entry_authority'],
                         proof['callback_authority'], proof['original_execution_status']))
        hooks = [self.layout.hook_start + 16 * index for index in range(32)]
        roots = sorted([self.layout.start - 4, *hooks])
        ranges = [(pc, pc + 4) for pc in hooks] + [(self.layout.start - 4, self.layout.end),
                  (self.layout.plt_start, self.layout.plt_start + 512)]
        image = ar.rewrite(self.nso.image, self.layout.start - 4, self.nso.sections[0].end,
                           code_ranges=ranges, entry_offsets=roots,
                           guarded_indirect_offsets=[self.layout.plt_start + 12 + 16 * index for index in range(32)],
                           indirect_policy='guarded-host', checked_stack=True, package_version=2)
        provenance = {p.return_offset: p.original_offset for p in image.gate_provenance}
        self.assertEqual(set(proof['svc_offsets']), {provenance[g.return_offset] for g in image.gates if g.kind == ar.SVC})
        self.assertEqual(set(proof['checked_sp_offsets']), {provenance[g.return_offset] for g in image.gates if g.kind == ar.STACK_CHECK})
        report = {'roots': roots, 'dormant_assembly_banks': [proof]}
        callbacks = ai.audited_callback_roots(self.nso, self.metadata, [(0, self.nso.sections[0].end)], report)
        self.assertFalse(set(callbacks) & set(proof['analysis_entries']))
        marker = self.metadata.symbols[-1]
        metadata = replace(self.metadata, symbols=(*self.metadata.symbols, replace(marker, value=self.layout.start)))
        report['roots'] = [*roots, self.layout.start]
        with self.assertRaisesRegex(ai.ImportError, 'cannot authorize a callback'):
            ai.audited_callback_roots(self.nso, metadata, [(0, self.nso.sections[0].end)], report)
        self.assertIsNone(contract.select_sdk_profiler_layout(self.nso))

    def test_every_authored_body_word_and_return_flow_remain_exact(self):
        image = bytearray(self.nso.image); changed = replace(self.nso, image=image)
        for pc in range(self.layout.start, self.layout.end, 4):
            image[pc] ^= 1
            with self.subTest(pc=hex(pc)), self.assertRaisesRegex(ai.ImportError, 'body identity'):
                self.prove(changed)
            image[pc] ^= 1
        for pc, word in ((self.layout.end - 4, ar.branch(self.layout.end - 4, self.layout.start)),
                         (self.layout.start, 0xD4000001)):
            with self.assertRaisesRegex(ai.ImportError, 'body identity'):
                self.prove(self.changed(pc, word))

    def test_build_marker_bounds_and_complete_hook_signatures_fail_closed(self):
        with self.assertRaisesRegex(ai.ImportError, 'build identity'):
            self.prove(replace(self.nso, build_id=bytes(32)))
        with self.assertRaisesRegex(ai.ImportError, 'Enable marker'):
            self.prove(self.changed(self.layout.start - 4, 0xD503201F))
        sections = (replace(self.nso.sections[0], size=self.layout.end - 4), *self.nso.sections[1:])
        with self.assertRaisesRegex(ai.ImportError, 'range'):
            self.prove(replace(self.nso, sections=sections))
        symbols = tuple(replace(symbol, name=symbol.name + 'v') if index == 1 else symbol
                        for index, symbol in enumerate(self.metadata.symbols))
        with self.assertRaisesRegex(ai.ImportError, 'complete typed hook signatures'):
            self.prove(metadata=replace(self.metadata, symbols=symbols))

    def test_all_typed_plt_relocations_and_hook_words_are_mandatory(self):
        for index, relocation in enumerate(self.metadata.relocations):
            changed = replace(relocation, addend=4)
            metadata = replace(self.metadata, relocations=(*self.metadata.relocations[:index], changed,
                                                          *self.metadata.relocations[index + 1:]))
            with self.subTest(index=index), self.assertRaisesRegex(ai.ImportError, 'PLT relocation'):
                self.prove(metadata=metadata)
        for pc in (self.layout.plt_start, self.layout.plt_start + 4, self.layout.plt_start + 8,
                   self.layout.plt_start + 12, self.layout.hook_start, self.layout.hook_start + 31 * 16):
            with self.subTest(pc=hex(pc)), self.assertRaises(ai.ImportError):
                self.prove(self.changed(pc, 0xD503201F))

    def test_root_metadata_symbol_and_relocation_entries_never_gain_authority(self):
        for pc in (self.layout.start, self.layout.start + 56, self.layout.end - 4):
            with self.assertRaisesRegex(ai.ImportError, 'metadata entry'):self.prove(roots=(pc,))
        for field in ('eh_starts', 'init_addresses'):
            with self.assertRaisesRegex(ai.ImportError, 'metadata entry'):
                self.prove(metadata=replace(self.metadata, **{field: (self.layout.start,)}))
        with self.assertRaisesRegex(ai.ImportError, 'overlaps metadata'):
            self.prove(metadata=replace(self.metadata, protected=((self.layout.start, self.layout.start + 4),)))
        marker = self.metadata.symbols[-1]
        with self.assertRaisesRegex(ai.ImportError, 'defined symbol'):
            self.prove(metadata=replace(self.metadata, symbols=(*self.metadata.symbols,
                       replace(marker, name='self_authored_bank_entry', value=self.layout.start))))
        for relocation in (replace(self.metadata.relocations[0], offset=self.layout.start),
                           Relocation(self.layout.got_start, 1027, 0, self.layout.start)):
            with self.assertRaisesRegex(ai.ImportError, 'relocation/pointer'):
                self.prove(metadata=replace(self.metadata, relocations=(*self.metadata.relocations, relocation)))

    def test_direct_adr_adrp_and_initialized_pointer_entries_are_not_hidden(self):
        pc = self.layout.end + 4
        with self.assertRaisesRegex(ai.ImportError, 'external direct'):
            self.prove(self.changed(pc, ar.branch(pc, self.layout.start)))
        delta = (self.layout.start - pc) & 0x1FFFFF
        adr = 0x10000000 | (delta & 3) << 29 | (delta >> 2) << 5
        with self.assertRaisesRegex(ai.ImportError, 'materialized bank'):
            self.prove(self.changed(pc, adr))
        image = bytearray(self.nso.image)
        struct.pack_into('<II', image, pc, 0x90000000, 0x91000000 | self.layout.start << 10)
        with self.assertRaisesRegex(ai.ImportError, 'materialized bank'):
            self.prove(replace(self.nso, image=bytes(image)))
        struct.pack_into('<Q', image, self.nso.sections[1].end - 8, self.layout.start)
        struct.pack_into('<II', image, pc, 0, 0)
        with self.assertRaisesRegex(ai.ImportError, 'initialized bank pointer'):
            self.prove(replace(self.nso, image=bytes(image)))


if __name__ == '__main__':
    unittest.main()
