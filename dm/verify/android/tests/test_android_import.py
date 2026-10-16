"""Production import/package/code-domain regressions; no native test bypass."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as importer
from nso_format import parse_nso, parse_metadata
from test_nso_format import FIXTURES, mutable_source, write_image


class AndroidImportTests(unittest.TestCase):
    def test_data_relocation_values_do_not_create_misaligned_code_roots(self):
        original = mutable_source()
        nso = parse_nso(original)
        metadata = parse_metadata(nso)
        index = next(i for i, relocation in enumerate(metadata.relocations) if relocation.kind == 1027)
        _, baseline = importer.import_module(original, 'main', package_version=2, callback_audit=True)
        for value in (1, 2, 3, nso.sections[0].end - 1):
            source = bytearray(original)
            write_image(source, metadata.dynamic[7] + index * 24 + 16, '<q', value)
            with self.subTest(value=value):
                _, report = importer.import_module(source, 'main', package_version=2, callback_audit=True)
                self.assertEqual(report['relocations'][index]['addend'], value)
                self.assertNotIn(value, report['code_discovery']['roots'])
                self.assertEqual(report['callback_audit']['callback_roots'], baseline['callback_audit']['callback_roots'])

    def test_misaligned_relocation_value_still_refuses_actual_indirect_execution(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        index = next(i for i, relocation in enumerate(metadata.relocations) if relocation.kind == 1027)
        self.assertEqual(metadata.relocations[index].offset, 0x8018)
        write_image(source, metadata.dynamic[7] + index * 24 + 16, '<q', 1)
        write_image(source, 0, '<I', 0x140000C0)  # b 0x300
        write_image(source, 0x300, '<3I', 0x90000048, 0xF9400D09, 0xD61F0120)
        with self.assertRaisesRegex(importer.ImportError, '0x1: misaligned relocated data value used as an instruction target'):
            importer.import_module(source, 'main')

    def test_padded_bss_and_end_markers_preserve_allocation_and_callback_authority(self):
        source = mutable_source()
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        _, baseline = importer.import_module(source, 'main', package_version=2, callback_audit=True)
        write_image(source, metadata.mod0 + 8, '<ii', nso.sections[2].end + 16 - metadata.mod0,
                    len(nso.image) - 32 - metadata.mod0)
        marker = next(i for i, symbol in enumerate(metadata.symbols) if symbol.name == 'main_bss')
        write_image(source, metadata.dynamic[6] + marker * 24 + 4, '<BBHQQ', 0x10, 0, 1, len(nso.image), 0)
        relative = next(i for i, relocation in enumerate(metadata.relocations) if relocation.kind == 1027)
        write_image(source, metadata.dynamic[7] + relative * 24 + 16, '<q', len(nso.image))
        package, report = importer.import_module(source, 'main', package_version=2, callback_audit=True)
        self.assertEqual(struct.unpack_from('<Q', package, 32)[0], len(nso.image))
        self.assertEqual(struct.unpack_from('<QQQ', package, 72),
                         (nso.sections[2].offset, nso.sections[2].size, nso.bss_size))
        payload = struct.unpack_from('<Q', package, 112)[0]
        self.assertEqual(package[payload + nso.sections[2].end:payload + len(nso.image)], bytes(nso.bss_size))
        self.assertEqual(package[payload + nso.sections[2].offset:payload + nso.sections[2].end],
                         nso.image[nso.sections[2].offset:nso.sections[2].end])
        self.assertEqual(package[320:356], bytes(36))
        self.assertEqual(report['callback_audit']['callback_roots'], baseline['callback_audit']['callback_roots'])
        self.assertNotIn(len(nso.image), report['callback_audit']['callback_roots'])
        self.assertEqual(report['game_boot_status'], 'NOT_RUN')

    def test_callback_audit_is_explicit_and_binds_the_final_v2_package(self):
        source = (FIXTURES / 'main.nso').read_bytes()
        ordinary, ordinary_report = importer.import_module(source, 'main', package_version=2)
        self.assertNotIn('callback_audit', ordinary_report)
        package, report = importer.import_module(source, 'main', package_version=2, callback_audit=True)
        self.assertEqual(package, ordinary, 'receipt must not change DMAMOD02 bytes')
        self.assertEqual(report['callback_audit'], {
            'callback_audit_version': 1,
            'package_sha256': hashlib.sha256(package).hexdigest(),
            'source_sha256': hashlib.sha256(source).hexdigest(),
            'indirect_policy': 'strict',
            'callback_root_kind': 'defined-stt-func',
            'callback_roots': [0, 0x100, 0x168, 0x184],
        })
        self.assertEqual(bytes.fromhex(report['callback_audit']['source_sha256']), package[216:248])
        for options, message in (({}, 'version 2'), ({'package_version': 2, 'indirect_policy': 'any'}, 'indirect policy')):
            with self.subTest(options=options), self.assertRaisesRegex(importer.ImportError, message):
                importer.import_module(source, 'main', callback_audit=True, **options)
        for selection in (1, 'true', None):
            with self.subTest(selection=selection), self.assertRaisesRegex(importer.ImportError, 'explicit boolean'):
                importer.import_module(source, 'main', package_version=2, callback_audit=selection)

    def test_callback_audit_roots_include_local_hidden_zero_size_but_no_other_kind(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        index = next(i for i, symbol in enumerate(metadata.symbols) if symbol.name == 'fixture_init')
        # Move a local function away from DT_INIT; hidden and zero-size are
        # eligible only because production discovery and rewrite audit its entry.
        write_image(source, metadata.dynamic[6] + index * 24 + 4, '<BBHQQ', 2, 2, 1, 0x500, 0)
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<2I', 0x10000809, 0xD65F03C0)  # adr x9,0x400; ret
        write_image(source, 0x400, '<I', 0xD65F03C0)  # Address-taken non-symbol root.
        write_image(source, 0x500, '<I', 0xD65F03C0)
        _, report = importer.import_module(source, 'main', package_version=2, callback_audit=True)
        self.assertEqual(report['callback_audit']['callback_roots'], [0, 0x100, 0x184, 0x500])
        self.assertTrue({0x168, 0x400}.issubset(report['code_discovery']['roots']))
        self.assertNotIn(0x168, report['callback_audit']['callback_roots'])  # DT_INIT alone.
        self.assertNotIn(0x400, report['callback_audit']['callback_roots'])
        # An object, undefined function and absolute function never gain entry
        # authority merely because their value resembles an executable address.
        for name, info, section, value in (('main_bss', 0x11, 1, 0x600),
                                           ('force_override', 0x12, 0, 0),
                                           ('duplicate_value', 0x12, 0xFFF1, 0x604)):
            candidate = next(i for i, symbol in enumerate(metadata.symbols) if symbol.name == name)
            write_image(source, metadata.dynamic[6] + candidate * 24 + 4, '<BBHQQ', info, 0, section, value, 0)
        _, report = importer.import_module(source, 'main', package_version=2, callback_audit=True)
        self.assertEqual(report['callback_audit']['callback_roots'], [0, 0x100, 0x184, 0x500])

    def test_callback_audit_aliases_are_sorted_unique_and_count_bounded(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        index = next(i for i, symbol in enumerate(metadata.symbols) if symbol.name == 'fixture_init')
        write_image(source, metadata.dynamic[6] + index * 24 + 8, '<QQ', 0x100, 0)
        with patch.object(importer, 'MAX_CALLBACK_ROOTS', 3):
            _, report = importer.import_module(source, 'main', package_version=2, callback_audit=True)
        self.assertEqual(report['callback_audit']['callback_roots'], [0, 0x100, 0x184])
        with patch.object(importer, 'MAX_CALLBACK_ROOTS', 2), self.assertRaisesRegex(importer.ImportError, 'callback root.*limit'):
            importer.import_module(source, 'main', package_version=2, callback_audit=True)

    def test_callback_audit_cannot_certify_an_unaudited_or_exclusive_interior_entry(self):
        for entry, word, message in ((0x500, 0xFFFFFFFF, 'cannot be decoded'),
                                      (0x304, 0xD65F03C0, 'entry.*exclusive')):
            source = mutable_source()
            metadata = parse_metadata(parse_nso(source))
            index = next(i for i, symbol in enumerate(metadata.symbols) if symbol.name == 'fixture_init')
            write_image(source, metadata.dynamic[6] + index * 24 + 8, '<QQ', entry, 0)
            write_image(source, entry, '<I', word)
            if entry == 0x304:
                write_image(source, 0, '<I', 0x140000C0)
                write_image(source, 0x300, '<4I', 0xC85F7C20, 0x91000400, 0xD5033F5F, 0xD65F03C0)
            with self.subTest(entry=entry), patch.object(importer, 'make_package') as serialize:
                with self.assertRaisesRegex((importer.ImportError, importer.RewriteError), message):
                    importer.import_module(source, 'main', package_version=2, callback_audit=True)
                serialize.assert_not_called()

    def test_callback_audit_directory_receipt_records_guarded_policy(self):
        source = mutable_source()
        entry = next(s.value for s in parse_metadata(parse_nso(source)).symbols if s.name == 'fixture_main')
        write_image(source, entry, '<I', 0xD63F0000)
        with tempfile.TemporaryDirectory() as temporary:
            inputs, output = Path(temporary) / 'inputs', Path(temporary) / 'output'
            inputs.mkdir()
            (inputs / 'main').write_bytes(source)
            with patch.object(sys, 'argv', ['android_import.py', str(inputs), str(output), '--modules', 'main',
                                           '--package-version', '2', '--indirect-policy', 'guarded-host', '--callback-audit']), \
                    patch('builtins.print'):
                importer.main()
            report = json.loads((output / 'import.json').read_text())['modules'][0]
            receipt = report['callback_audit']
            self.assertEqual(receipt['indirect_policy'], 'guarded-host')
            self.assertEqual(receipt['package_sha256'], hashlib.sha256((output / 'main.dmag').read_bytes()).hexdigest())

    def test_guarded_host_is_explicit_v2_and_keeps_class0_authority(self):
        source = mutable_source()
        entry = next(s.value for s in parse_metadata(parse_nso(source)).symbols if s.name == 'fixture_main')
        write_image(source, entry, '<I', 0xD63F0000)
        for options in ({}, {'package_version': 2}):
            with self.assertRaisesRegex(importer.ImportError, 'unproven indirect'):
                importer.import_module(source, 'main', **options)
        with self.assertRaisesRegex(importer.ImportError, 'version 2'):
            importer.import_module(source, 'main', indirect_policy='guarded-host')
        package, report = importer.import_module(source, 'main', package_version=2, indirect_policy='guarded-host')
        self.assertEqual(package[320:356], bytes(36))  # No OBS profile/class authority.
        discovery = report['code_discovery']
        self.assertEqual(discovery['guarded_indirect_sites'], [entry])
        self.assertNotIn(entry, discovery['proven_indirect_sites'])
        self.assertEqual(discovery['rejected_indirect_sites'], [])
        self.assertEqual([g['argument'] for g in report['rewrite']['gates'] if g['kind'] == 4], [0])
        self.assertIn('gate_provenance', report['rewrite'])

    def test_guarded_policy_retains_sp_and_hidden_sensitive_word_audits(self):
        for word, message in ((0x9100001F, 'SP write/pivot'), (0xD4000001, 'uncovered rewrite candidate')):
            source = mutable_source()
            write_image(source, 0x300, '<I', word)
            if 'SP' in message:
                write_image(source, 0, '<I', 0x140000C0)
                write_image(source, 0x304, '<2I', 0xD63F0000, 0xD65F03C0)
            with self.assertRaisesRegex(importer.ImportError, message):
                importer.import_module(source, 'main', package_version=2, indirect_policy='guarded-host')

    def test_rejected_indirect_directory_report_identifies_site_without_packages(self):
        source = mutable_source()
        entry = next(s.value for s in parse_metadata(parse_nso(source)).symbols if s.name == 'fixture_main')
        write_image(source, entry, '<I', 0xD63F0240)  # Android reserves x18.
        with tempfile.TemporaryDirectory() as temporary:
            inputs, output = Path(temporary) / 'inputs', Path(temporary) / 'output'
            inputs.mkdir()
            (inputs / 'main').write_bytes(source)
            with self.assertRaises(importer.ImportError):
                importer.import_directory(inputs, output, ('main',), package_version=2, indirect_policy='guarded-host')
            report = json.loads((output / 'import.json').read_text())
            self.assertEqual(report['modules'][0]['code_discovery']['rejected_indirect_sites'], [entry])
            self.assertEqual(report['status'], 'rejected')
            self.assertFalse(list(output.glob('*.dmag')))

    def test_invalid_indirect_policy_is_never_silently_accepted(self):
        for policy in ('all', None, ''):
            with self.assertRaisesRegex(importer.ImportError, 'indirect policy'):
                importer.import_module(mutable_source(), 'main', package_version=2, indirect_policy=policy)

    def test_packages_match_frozen_format_and_source_inventory(self):
        for name in ('main', 'sdk', 'extra'):
            source = (FIXTURES / (name + '.nso')).read_bytes()
            package, report = importer.import_module(source, name)
            self.assertEqual(package, (FIXTURES / (name + '.dmag')).read_bytes())
            self.assertEqual(package[:8], b'DMAMOD01')
            self.assertEqual(struct.unpack_from('<IIII', package, 8), (1, importer.ABI, 320, 0))
            payload_size, original_size = struct.unpack_from('<QQ', package, 24)
            patch_offset, patch_size, payload_offset = struct.unpack_from('<QQQ', package, 96)
            self.assertEqual(patch_offset % 16384, 0)
            self.assertGreaterEqual(patch_offset, original_size)
            self.assertEqual(patch_offset + patch_size, payload_size)
            self.assertEqual(payload_offset % 16, 0)
            self.assertEqual(payload_offset + payload_size, len(package))
            self.assertEqual(package[184:216], source[0x40:0x60])
            self.assertEqual(package[216:248], hashlib.sha256(source).digest())
            self.assertEqual(package[248:280], hashlib.sha256(package[payload_offset:]).digest())
            self.assertEqual(package[296:320], bytes(24))
            previous_end = 320
            for offset_field, items, encode in (
                    (120, report['rewrite']['fixups'], lambda x: struct.pack('<QII', x['offset'], x['helper'], 0)),
                    (136, report['rewrite']['gates'], lambda x: struct.pack('<QII', x['return_offset'], x['kind'], x['argument'])),
                    (152, report['rewrite']['sites'], lambda x: struct.pack('<QQ', x['offset'], x['trampoline']))):
                table_offset, count = struct.unpack_from('<QQ', package, offset_field)
                self.assertEqual(table_offset % 8, 0)
                self.assertGreaterEqual(table_offset, previous_end)
                self.assertEqual(count, len(items))
                self.assertEqual(package[table_offset:table_offset + count * 16], b''.join(encode(x) for x in items))
                previous_end = table_offset + count * 16
            self.assertLessEqual(previous_end, payload_offset)
            nso = parse_nso(source)
            # MOD0, RO metadata, initialized data, BSS and section holes retain
            # exact source semantics; only selected text instruction sites change.
            for start, end in ((4, 0x100), (0x4000, 0xA000)):
                self.assertEqual(package[payload_offset + start:payload_offset + end], nso.image[start:end])
            self.assertEqual(report['game_boot_status'], 'NOT_RUN')
            self.assertFalse(report['unsupported'])

    def test_explicit_module_order_and_cli_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'output'
            # Production CLI expects actual ExeFS filenames without .nso.
            source = Path(temporary) / 'exefs'
            source.mkdir()
            for name in ('main', 'sdk', 'extra'):
                (source / name).write_bytes((FIXTURES / (name + '.nso')).read_bytes())
            report = importer.import_directory(source, output, ['sdk', 'main', 'extra'])
            self.assertEqual(report['module_order'], ['sdk', 'main', 'extra'])
            self.assertEqual(json.loads((output / 'import.json').read_text())['status'], 'prepared')
            self.assertEqual(len(list(output.glob('*.dmag'))), 3)
            with self.assertRaisesRegex(importer.ImportError, 'already contains'):
                importer.import_directory(source, output)

    def test_rejected_import_does_not_publish_earlier_prepared_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'exefs', Path(temporary) / 'output'
            source.mkdir()
            (source / 'main').write_bytes((FIXTURES / 'main.nso').read_bytes())
            (source / 'sdk').write_bytes(b'invalid')
            with self.assertRaises(importer.ImportError):
                importer.import_directory(source, output)
            report = json.loads((output / 'import.json').read_text())
            self.assertEqual(report['status'], 'rejected')
            self.assertFalse(list(output.glob('*.dmag')))
            self.assertTrue(report['unsupported'])
            self.assertEqual(report['modules'][1]['source_sha256'], hashlib.sha256(b'invalid').hexdigest())

    def test_invalid_module_names_and_duplicates(self):
        for names in ([], ['main', 'main'], ['../main'], ['name-is-too-long-for-header'], ['中文']):
            with self.assertRaises(importer.ImportError):
                importer.import_directory(FIXTURES, FIXTURES / 'unused-output', names)

    def test_unproven_padding_sensitive_words_are_rejected(self):
        source = mutable_source()
        write_image(source, 0x300, '<II', 0xD4000001, 0xD53BD052)
        with self.assertRaisesRegex(importer.ImportError, '0x300: uncovered rewrite candidate'):
            importer.import_module(source, 'main')

    def test_proven_literal_sensitive_words_are_preserved(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<II', 0x58000800, 0xD65F03C0)  # ldr x0,0x400; ret
        write_image(source, 0x400, '<II', 0xD4000001, 0xD53BD052)
        package, report = importer.import_module(source, 'main')
        payload = struct.unpack_from('<Q', package, 112)[0]
        self.assertEqual(package[payload + 0x400:payload + 0x408], struct.pack('<II', 0xD4000001, 0xD53BD052))
        self.assertFalse(any(site['offset'] in (0x400, 0x404) for site in report['rewrite']['sites']))
        self.assertEqual(report['code_discovery']['rewrite_candidate_audit']['verified_data_candidates'], [0x400, 0x404])

    def test_unproven_indirect_rejected(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        entry = next(s.value for s in metadata.symbols if s.name == 'fixture_main')
        write_image(source, entry, '<I', 0xD61F0000)  # br x0 supplied by arbitrary caller
        with self.assertRaisesRegex(importer.ImportError, 'unproven indirect'):
            importer.import_module(source, 'main')

    def test_reachable_invalid_instruction_and_metadata_branch_rejected(self):
        for word, message in ((0xFFFFFFFF, 'cannot be decoded'), (0x14000010, 'metadata')):
            source = mutable_source()
            write_image(source, 0, '<I', word)
            with self.assertRaisesRegex(importer.ImportError, message):
                importer.import_module(source, 'main')

    def test_validated_function_roots_rewrite_sdk_gate(self):
        _, report = importer.import_module((FIXTURES / 'sdk.nso').read_bytes(), 'sdk')
        self.assertEqual(len(report['rewrite']['gates']), 1)
        self.assertEqual(report['rewrite']['gates'][0]['argument'], 0x77)
        self.assertGreater(len(report['code_discovery']['proven_indirect_sites']), 6)

    def test_w_register_alias_kills_indirect_pointer_proof(self):
        source = mutable_source()
        # Replace main's first ldr x9 GOT with mov w9,#1: any previous x9
        # pointer is killed by the architectural zero-extending register alias.
        write_image(source, 0x10C, '<I', 0x52800029)
        with self.assertRaisesRegex(importer.ImportError, 'unproven indirect'):
            importer.import_module(source, 'main')

    def test_static_indirect_target_discovers_nonexported_function(self):
        source = mutable_source()
        # Use the NSO entry (metadata-independent root) to reach a private
        # function through ADR+BR. Its SVC must be selected and rewritten.
        write_image(source, 0, '<I', 0x140000C0)  # b 0x300
        write_image(source, 0x300, '<III', 0x10000809, 0xD61F0120, 0xD65F03C0)  # adr x9,0x400; br x9
        write_image(source, 0x400, '<II', 0xD4000221, 0xD65F03C0)  # svc #0x11; ret
        _, report = importer.import_module(source, 'main')
        self.assertTrue(any(site['offset'] == 0x400 for site in report['rewrite']['sites']))
        self.assertTrue(any(gate['argument'] == 0x11 for gate in report['rewrite']['gates']))

    def test_indirect_proof_cannot_cross_second_block_entrance(self):
        source = mutable_source()
        # Entry can bypass ADRP and jump straight into LDR/BLR. The alternate
        # entry means x8 is unknown even though adjacent bytes contain ADRP.
        write_image(source, 0, '<I', 0x14000043)  # b 0x10c
        with self.assertRaisesRegex(importer.ImportError, 'unproven indirect'):
            importer.import_module(source, 'main')

    def test_private_callback_passed_to_host_is_discovered_and_rewritten(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)  # b 0x300
        write_image(source, 0x300, '<7I', 0xA9BF7BFD, 0x100007E0, 0x90000048,
                    0xF9402109, 0xD63F0120, 0xA8C17BFD, 0xD65F03C0)
        write_image(source, 0x400, '<III', 0xD4000221, 0xD53BD052, 0xD65F03C0)
        _, report = importer.import_module(source, 'main')
        rewritten = {site['offset'] for site in report['rewrite']['sites']}
        self.assertTrue({0x400, 0x404}.issubset(rewritten), 'escaped callback contains unrewritten SVC/TLS')

    def test_store_to_relocated_slot_kills_indirect_target_proof(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<7I', 0xA9BF7BFD, 0x90000048, 0xF9002100,
                    0xF9402109, 0xD63F0120, 0xA8C17BFD, 0xD65F03C0)
        with self.assertRaisesRegex(importer.ImportError, '0x[0-9a-f]+:.*(clobber|unproven)'):
            importer.import_module(source, 'main')

    def test_unknown_alias_store_invalidates_relocation_target(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<7I', 0xA9BF7BFD, 0x90000048, 0xF9000020,
                    0xF9402109, 0xD63F0120, 0xA8C17BFD, 0xD65F03C0)  # str x0,[x1]
        with self.assertRaisesRegex(importer.ImportError, 'unproven indirect'):
            importer.import_module(source, 'main')
        _, report = importer.import_module(source, 'main', package_version=2, indirect_policy='guarded-host')
        discovery = report['code_discovery']
        self.assertTrue(discovery['relocation_slots_clobbered_by_code'])
        self.assertIn(0x310, discovery['guarded_indirect_sites'])
        self.assertNotIn(0x310, discovery['proven_indirect_sites'])

    def test_writable_image_pointer_passed_to_import_invalidates_slot(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<7I', 0xA9BF7BFD, 0x90000040, 0x90000048,
                    0xF9402109, 0xD63F0120, 0xA8C17BFD, 0xD65F03C0)  # adrp x0,0x8000
        with self.assertRaisesRegex(importer.ImportError, 'unproven indirect'):
            importer.import_module(source, 'main')

    def test_uncovered_unsupported_system_word_rejected(self):
        source = mutable_source()
        write_image(source, 0x300, '<I', 0xD53BE000)  # mrs x0,cntfrq_el0
        with self.assertRaisesRegex(importer.ImportError, '0x300: unsupported potential executable system-register'):
            importer.import_module(source, 'main')

    def test_literal_read_cannot_hide_escaped_callback(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        # LDR reads the callback bytes, but ADR also exposes their address.
        # This cannot acquire a literal-data exemption from the code audit.
        write_image(source, 0x300, '<8I', 0xA9BF7BFD, 0x580007E1, 0x100007C0,
                    0x90000048, 0xF9402109, 0xD63F0120, 0xA8C17BFD, 0xD65F03C0)
        write_image(source, 0x400, '<III', 0xD4000221, 0xD53BD052, 0xD65F03C0)
        with self.assertRaisesRegex(importer.ImportError, '0x400: materialized text address aliases literal data'):
            importer.import_module(source, 'main')

    def test_sp_pivot_cannot_hide_write_to_relocation_slot(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<11I', 0xA9BF7BFD, 0x90000048, 0x910003EA,
                    0x9100011F, 0xF90023E0, 0x9100015F, 0xF9402109, 0xD63F0120,
                    0xA8C17BFD, 0xD65F03C0, 0xD503201F)
        with self.assertRaisesRegex(importer.ImportError, '0x30c:.*(SP|sp)'):
            importer.import_module(source, 'main')

    def test_sp_compare_alias_and_aligned_ldpsw_writeback_are_supported(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        # Capstone 5 lists SP as a destination for both compare aliases, but
        # Arm discards the result. LDPSW writes SP only by its aligned immediate.
        write_image(source, 0x300, '<5I', 0xEB3263FF, 0xAB3263FF,
                    0x69FE43F2, 0x68C243F2, 0xD65F03C0)
        _, report = importer.import_module(source, 'main')
        rewritten = {site['offset'] for site in report['rewrite']['sites']}
        self.assertTrue({0x300, 0x304, 0x308, 0x30C}.issubset(rewritten))

    def test_unaligned_ldpsw_writeback_still_rejects(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        write_image(source, 0x300, '<2I', 0x68C143F2, 0xD65F03C0)  # +8 bytes
        with self.assertRaisesRegex(importer.ImportError, '0x300:.*SP write/pivot'):
            importer.import_module(source, 'main')

    def test_materialized_callback_into_discovered_exclusive_interior_rejects(self):
        source = mutable_source()
        write_image(source, 0, '<I', 0x140000C0)
        # ADR x5,0x308 names an already linearly decoded ADD inside the
        # LDXR-to-CLREX window. An escaped callback must not bypass its prologue.
        write_image(source, 0x300, '<5I', 0x10000045, 0xC85F7C12,
                    0x91000652, 0xD5033F5F, 0xD65F03C0)
        with self.assertRaisesRegex(importer.RewriteError, 'entry.*exclusive'):
            importer.import_module(source, 'main')

    def test_ordinary_exclusive_address_taken_and_relocation_roots_obey_boundaries(self):
        for authority in ('address-taken', 'relocation'):
            for interior in (False, True):
                source = mutable_source()
                metadata = parse_metadata(parse_nso(source))
                write_image(source, 0, '<I', 0x140000C0)
                if authority == 'address-taken':
                    # ADR names either the exclusive load or its ADD body.
                    write_image(source, 0x300, '<5I', 0x10000045 if interior else 0x10000025,
                                0xC85F7C20, 0x91000400, 0xD5033F5F, 0xD65F03C0)
                else:
                    write_image(source, 0x300, '<4I', 0xC85F7C20, 0x91000400, 0xD5033F5F, 0xD65F03C0)
                    # Existing third RELA record is RELATIVE; change only its addend.
                    write_image(source, metadata.dynamic[7] + 2 * 24 + 16, '<q', 0x304 if interior else 0x300)
                if interior:
                    with self.subTest(authority=authority), self.assertRaisesRegex(importer.RewriteError, 'entry.*exclusive'):
                        importer.import_module(source, 'main')
                else:
                    importer.import_module(source, 'main')


if __name__ == '__main__':
    unittest.main()
