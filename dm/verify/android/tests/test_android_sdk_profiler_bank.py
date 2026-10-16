"""Pinned local SDK regression; no original game bytes or callback fixtures."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso, parse_metadata

SDK = Path('C:/Users/aa223/dm-work/data/switch/3.3.94012/Update/ExeFS/sdk')


@unittest.skipUnless(SDK.is_file(), 'local verified SDK required for versioned profiler regression')
class SdkProfilerBankTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.nso = parse_nso(SDK.read_bytes())
        cls.metadata = parse_metadata(cls.nso)

    def changed(self, pc, word):
        image = bytearray(self.nso.image)
        struct.pack_into('<I', image, pc, word)
        return replace(self.nso, image=bytes(image))

    def test_actual_bank_is_analysis_only_and_all_gates_receive_independent_rewrite(self):
        proof = ai._sdk_profiler_bank(self.nso, self.metadata, set())
        self.assertEqual((proof['start'], proof['end']), (0x362698, 0x362E7C))
        self.assertEqual(len(proof['analysis_entries']), 16)
        self.assertEqual(len(proof['svc_offsets']), 16)
        self.assertEqual(len(proof['checked_sp_offsets']), 70)
        self.assertFalse(proof['runtime_entry_authority'])
        self.assertFalse(proof['callback_authority'])
        self.assertEqual(proof['original_execution_status'], 'NOT_RUN')
        # Select only the genuine typed marker and its verified adjacent bank.
        # This component rewrite grants no entry to any unnamed wrapper.
        hook_entries = [0x3624A0 + 16 * i for i in range(32)]
        ranges = [(pc, pc+4) for pc in hook_entries] + [(0x362694, proof['end']), (0x582E70, 0x583070)]
        image = ar.rewrite(self.nso.image, 0x362694, self.nso.sections[0].end,
                           code_ranges=ranges, entry_offsets=[0x362694, *hook_entries],
                           guarded_indirect_offsets=[0x582E7C + 16 * i for i in range(32)],
                           indirect_policy='guarded-host', checked_stack=True, package_version=2)
        provenance = {p.return_offset: p.original_offset for p in image.gate_provenance}
        svc = {provenance[g.return_offset] for g in image.gates if g.kind == ar.SVC}
        stack = {provenance[g.return_offset] for g in image.gates if g.kind == ar.STACK_CHECK}
        self.assertEqual(svc, set(proof['svc_offsets']))
        self.assertEqual(stack, set(proof['checked_sp_offsets']))
        for pc in svc | stack:
            self.assertNotEqual(image.bytes[pc:pc+4], self.nso.image[pc:pc+4])
        # Receipt selection still equals all and only the original typed funcs.
        roots = sorted({s.value for s in self.metadata.symbols if s.kind == 2 and s.section not in (0, 0xFFF1)})
        report = {'roots': roots, 'dormant_assembly_banks': [proof]}
        callbacks = ai.audited_callback_roots(self.nso, self.metadata, [(0, self.nso.sections[0].end)], report)
        self.assertEqual(callbacks, roots)
        self.assertFalse(set(callbacks) & set(proof['analysis_entries']))
        # Even a forged metadata/report entry cannot use this analysis authority.
        marker = next(s for s in self.metadata.symbols if s.value == 0x362694 and s.kind == 2)
        metadata = replace(self.metadata, symbols=(*self.metadata.symbols, replace(marker, value=proof['start'])))
        report['roots'] = sorted({*roots, proof['start']})
        with self.assertRaisesRegex(ai.ImportError, 'cannot authorize a callback'):
            ai.audited_callback_roots(self.nso, metadata, [(0, self.nso.sections[0].end)], report)

    def test_identity_build_marker_body_and_plt_changes_fail_closed(self):
        self.assertIsNone(ai._sdk_profiler_bank(replace(self.nso, source_sha256=bytes(32)), self.metadata, set()))
        with self.assertRaisesRegex(ai.ImportError, 'build identity'):
            ai._sdk_profiler_bank(replace(self.nso, build_id=bytes(32)), self.metadata, set())
        for pc, word, message in ((0x362694, 0xD503201F, 'marker'),
                                   (0x3626D0, 0xD503201F, 'body identity'),
                                   (0x582E7C, 0xD65F03C0, 'PLT structure'),
                                   (0x3624A0, 0xD503201F, 'hook')):
            with self.subTest(pc=hex(pc)), self.assertRaisesRegex(ai.ImportError, message):
                ai._sdk_profiler_bank(self.changed(pc, word), self.metadata, set())
        symbols = tuple(replace(s, size=8) if s.value == 0x362694 else s for s in self.metadata.symbols)
        with self.assertRaisesRegex(ai.ImportError, 'marker'):
            ai._sdk_profiler_bank(self.nso, replace(self.metadata, symbols=symbols), set())

    def test_relocation_hook_and_metadata_entries_fail_closed(self):
        relocations = tuple(replace(r, kind=1027) if r.offset == 0xC71248 else r for r in self.metadata.relocations)
        with self.assertRaisesRegex(ai.ImportError, 'PLT relocation'):
            ai._sdk_profiler_bank(self.nso, replace(self.metadata, relocations=relocations), set())
        symbols = tuple(replace(s, name=s.name.replace('SleepThread', 'OtherThread')) if s.value == 0x3624A0 else s
                        for s in self.metadata.symbols)
        with self.assertRaisesRegex(ai.ImportError, 'hook'):
            ai._sdk_profiler_bank(self.nso, replace(self.metadata, symbols=symbols), set())
        symbols = tuple(replace(s, name=s.name + 'v') if s.value == 0x3624A0 else s for s in self.metadata.symbols)
        with self.assertRaisesRegex(ai.ImportError, 'complete typed hook signatures'):
            ai._sdk_profiler_bank(self.nso, replace(self.metadata, symbols=symbols), set())
        for pc in (0x362698, 0x3626D0, 0x362E78):
            with self.subTest(entry=hex(pc)), self.assertRaisesRegex(ai.ImportError, 'metadata entry'):
                ai._sdk_profiler_bank(self.nso, self.metadata, {pc})
        for field in ('eh_starts', 'init_addresses'):
            with self.subTest(field=field), self.assertRaisesRegex(ai.ImportError, 'metadata entry'):
                ai._sdk_profiler_bank(self.nso, replace(self.metadata, **{field: (0x362698,)}), set())

    def test_new_direct_and_materialized_entries_fail_closed(self):
        image = bytearray(self.nso.image)
        struct.pack_into('<Q', image, self.nso.sections[1].end - 8, 0x362698)
        with self.assertRaisesRegex(ai.ImportError, 'initialized bank pointer'):
            ai._sdk_profiler_bank(replace(self.nso, image=bytes(image)), self.metadata, set())
        pc = 0x362E80
        with self.assertRaisesRegex(ai.ImportError, 'external direct entry'):
            ai._sdk_profiler_bank(self.changed(pc, ar.branch(pc, 0x362698)), self.metadata, set())
        delta = (0x362698 - pc) & 0x1FFFFF
        adr = 0x10000000 | (delta & 3) << 29 | (delta >> 2) << 5
        with self.assertRaisesRegex(ai.ImportError, 'materialized bank entry'):
            ai._sdk_profiler_bank(self.changed(pc, adr), self.metadata, set())


if __name__ == '__main__':
    unittest.main()
