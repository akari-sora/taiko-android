"""Only a proved, consumed PLT/GOT abort boundary requires native ABI v1."""
from dataclasses import replace
import hashlib
import importlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as importer
import android_rewrite as ar
import gen_android_graphics as builder
from nso_format import parse_nso, parse_metadata
from test_nso_format import write_image, dynamic_slot

SYMBOL = '_ZN2nn4diag6detail9AbortImplEPKcS3_S3_i'
BEGIN, MISMATCH, CLOSED, SUCCESS, ABORT, PLT = 0x100, 0x80, 0x120, 0x140, 0x180, 0x200
REQUIRED = 2


def conditional(pc, target, condition):
    return 0x54000000 | (((target - pc) // 4) & 0x7FFFF) << 5 | condition


def public_nso(mode='used', symbol=SYMBOL, defined=False):
    text = bytearray(struct.pack('<I', 0xD65F03C0) * (0x1000 // 4))
    struct.pack_into('<I', text, 0, ar.branch(0, BEGIN))
    struct.pack_into('<I', text, 4, 0x40)
    struct.pack_into('<4s6i', text, 0x40, b'MOD0', builder.DATA + 0x400 - 0x40,
                     builder.BSS - 0x40, builder.BSS - 0x40, 0, 0, 0)
    struct.pack_into('<2I', text, MISMATCH, 0xD5033F5F, 0xD65F03C0)
    struct.pack_into('<10I', text, BEGIN, 0x885FFE68, 0x53105D09, 0x6B48613F,
                     conditional(BEGIN + 12, MISMATCH, 1), 0x11000508, 0x72003D1F,
                     conditional(BEGIN + 24, ABORT, 0), 0x88097E68,
                     0x34000109, ar.branch(CLOSED + 4, BEGIN))
    call = ABORT
    if mode == 'clrex':
        struct.pack_into('<I', text, ABORT, 0xD5033F5F)
        call += 4
    elif mode == 'fresh-load':
        struct.pack_into('<2I', text, ABORT, 0x885FFE8C, 0xD5033F5F)
        call += 8
    struct.pack_into('<I', text, call, 0x94000000 | ((PLT - call) // 4))
    struct.pack_into('<4I', text, PLT, 0x90000110, 0xF9400211, 0x91000210, 0xD61F0220)
    definitions = {'fixture_entry': (BEGIN, 40, 2), 'fixture_init': (MISMATCH, 8, 2),
                   'public_abort_path': (ABORT, 16, 2), 'public_data': (builder.DATA, 8, 1),
                   symbol: (0, 0, 2)}
    with patch.object(builder, 'IMPORTS', (symbol,)):
        source = bytearray(builder.make_nso({'.text': bytes(text), '.const': b'', '.data': b''}, definitions))
    nso = parse_nso(source)
    metadata = parse_metadata(nso)
    index = next(index for index, item in enumerate(metadata.symbols) if item.name == symbol)
    # Author a real STT_FUNC import or a selected, nonzero defined function.
    # The required runtime ABI forces the canonical implementation; these
    # public RET bytes are never treated as a source-level noreturn proof.
    # Only segment hashes are disabled; production still verifies metadata.
    struct.pack_into('<I', source, 12, 0)
    write_image(source, metadata.dynamic[6] + index * 24 + 6, '<H', 1 if defined else 0)
    if defined:
        write_image(source, metadata.dynamic[6] + index * 24 + 8, '<QQ', 0x300, 4)
    return bytes(source)


def imported(source):
    return importer.import_module(source, 'main', package_version=2, checked_stack=True, callback_audit=True,
                                  indirect_policy='guarded-host')


def selected_source(source):
    nso = parse_nso(source)
    metadata = parse_metadata(nso)
    ranges, report = importer.discover_code(nso, metadata, indirect_policy='guarded-host', checked_stack=True)
    selected = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', nso.image, pc)[0], pc))
                for start, end in ranges for pc in range(start, end, 4)}
    return nso, ranges, report, selected


def real_image(source, diag_source, guarded_sites=None):
    nso, ranges, report, _ = selected_source(source)
    return ar.rewrite(nso.image, report.get('analysis_entry', {}).get('offset', 0), nso.sections[0].end,
                      code_ranges=ranges, entry_offsets=report['roots'], package_version=2,
                      checked_stack=True, indirect_policy='guarded-host',
                      independent_entry_offsets=report['independent_roots'],
                      guarded_indirect_offsets=(report.get('guarded_indirect_sites', ())
                                                if guarded_sites is None else guarded_sites),
                      readonly_ranges=((nso.sections[1].offset, nso.sections[1].end),),
                      diag_abort_source=diag_source)


def abort_gates(package):
    offset, count = struct.unpack_from('<QQ', package, 136)
    return [struct.unpack_from('<QQIIII', package, offset + index * 32) for index in range(count)]


class DiagAbortContractTests(unittest.TestCase):
    def test_consumed_exact_boundary_sets_required_bit_in_real_v2_audited_package(self):
        package, report = imported(public_nso())
        self.assertEqual(struct.unpack_from('<I', package, 20)[0], 1 | REQUIRED)
        self.assertEqual(report['callback_audit']['package_sha256'], hashlib.sha256(package).hexdigest())
        self.assertEqual(report['game_boot_status'], 'NOT_RUN')
        self.assertIs(report['rewrite']['requires_diag_abort_v1'], True)
        self.assertEqual(report['rewrite']['required_diag_abort_abi'], '__dm_android_diag_abort_v1')
        self.assertEqual([(origin, kind, register, original) for _, origin, kind, register, original, _
                          in abort_gates(package) if origin == PLT + 12],
                         [(PLT + 12, ar.INDIRECT_HOST, 17, 0xD61F0220)])
        image = real_image(public_nso(), public_nso())
        self.assertIs(image.requires_diag_abort_v1, True)

    def test_valid_defined_original_symbol_still_requires_the_forced_private_abi(self):
        package, report = imported(public_nso(defined=True))
        self.assertEqual(struct.unpack_from('<I', package, 20)[0], 1 | REQUIRED)
        self.assertEqual(report['rewrite']['required_diag_abort_abi'], '__dm_android_diag_abort_v1')
        self.assertIn(0x300, report['callback_audit']['callback_roots'])
        self.assertTrue(any(origin == PLT + 12 and kind == ar.INDIRECT_HOST and register == 17 and
                            original == 0xD61F0220 for _, origin, kind, register, original, _ in abort_gates(package)))

    def test_consumed_plt_has_a_forced_x17_host_gate_without_caller_guard_authority(self):
        source = public_nso(defined=True)
        image = real_image(source, source, guarded_sites=())
        self.assertIs(image.requires_diag_abort_v1, True)
        matches = [(gate, origin) for gate, origin in zip(image.gates, image.gate_provenance)
                   if origin.original_offset == PLT + 12]
        self.assertEqual(len(matches), 1)
        gate, origin = matches[0]
        self.assertEqual((gate.kind, gate.argument, origin.original_word),
                         (ar.INDIRECT_HOST, 17, 0xD61F0220))
        self.assertIn(PLT + 12, {site.offset for site in image.sites})

    def test_explicit_clear_and_fresh_load_retirement_do_not_require_abort_contract(self):
        for mode in ('clrex', 'fresh-load'):
            with self.subTest(mode=mode):
                package, report = imported(public_nso(mode))
                self.assertEqual(struct.unpack_from('<I', package, 20)[0], 1)
                self.assertEqual(report['callback_audit']['package_sha256'], hashlib.sha256(package).hexdigest())
                self.assertFalse(report['rewrite'].get('requires_diag_abort_v1', False))

    def test_only_selected_bl_and_every_exact_plt_word_produce_a_source_proof(self):
        boundary = importlib.import_module('android_diag_abort')
        source = public_nso()
        nso, _, _, selected = selected_source(source)
        verified = boundary.verified_monitor_retiring_calls
        self.assertEqual(verified(source, nso.image, selected), frozenset((ABORT,)))
        for missing in (ABORT, PLT, PLT + 4, PLT + 8, PLT + 12):
            reduced = dict(selected)
            reduced.pop(missing)
            with self.subTest(missing=missing):
                self.assertEqual(verified(source, nso.image, reduced), frozenset())
        changed = dict(selected)
        changed[PLT + 8] = ar.Instruction(ar.decode(0xD503201F, PLT + 8))
        self.assertEqual(verified(source, nso.image, changed), frozenset())
        wrong_image = bytearray(nso.image)
        wrong_image[0x300] ^= 1
        with self.assertRaises(ValueError):
            verified(source, bytes(wrong_image), selected)

    def test_raw_call_offset_sets_and_authorization_json_cannot_replace_original_nso(self):
        source = public_nso()
        for forged in (None, frozenset((ABORT,)), {'calls': [ABORT]}, b'not an NSO'):
            with self.subTest(forged=forged), self.assertRaises((ValueError, TypeError)):
                real_image(source, forged)

    def test_publication_rejects_cleared_required_bit_or_missing_wrong_register_gate(self):
        source = public_nso()
        image = real_image(source, source)
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        index = next(index for index, origin in enumerate(image.gate_provenance)
                     if origin.original_offset == PLT + 12)
        wrong_gates = list(image.gates)
        wrong_gates[index] = replace(wrong_gates[index], argument=16)
        changes = (dict(requires_diag_abort_v1=False), dict(gates=tuple(wrong_gates)),
                   dict(gates=image.gates[:index] + image.gates[index + 1:],
                        gate_provenance=image.gate_provenance[:index] + image.gate_provenance[index + 1:]))
        for change in changes:
            broken = replace(image, **change)
            with self.subTest(change=change):
                with self.assertRaises(ar.RewriteError):
                    broken.validate()
                with self.assertRaises((importer.ImportError, ar.RewriteError)):
                    importer.make_package('main', nso, metadata, broken, len(nso.image), package_version=2)

    def test_plt_words_got_slot_exact_name_symbol_kind_and_relocation_are_required(self):
        for pc, word in ((PLT, 0x90000111), (PLT + 4, 0xF9400611),
                         (PLT + 4, 0xB9400211), (PLT + 8, 0x91002210),
                         (PLT + 12, 0xD61F0200)):
            source = bytearray(public_nso())
            write_image(source, pc, '<I', word)
            with self.subTest(pc=pc, word=f'{word:08x}'), self.assertRaises(ValueError):
                imported(bytes(source))
        with self.assertRaises(ValueError):
            imported(public_nso(symbol=SYMBOL + '_returning'))
        for mutation in ('object', 'defined-zero', 'kind', 'addend', 'duplicate'):
            source = bytearray(public_nso())
            nso = parse_nso(source)
            metadata = parse_metadata(nso)
            index = next(index for index, symbol in enumerate(metadata.symbols) if symbol.name == SYMBOL)
            symbol = metadata.dynamic[6] + index * 24
            relocation = metadata.dynamic[23]
            if mutation == 'object':
                write_image(source, symbol + 4, '<B', 0x11)
            elif mutation == 'defined-zero':
                write_image(source, symbol + 6, '<H', 1)
            elif mutation == 'kind':
                write_image(source, relocation + 8, '<Q', index << 32 | 1025)
            elif mutation == 'addend':
                write_image(source, relocation + 16, '<q', 4)
            else:
                values = struct.unpack_from('<QQq', nso.image, relocation)
                write_image(source, relocation + 24, '<QQq', *values)
                write_image(source, dynamic_slot(source, 2) + 8, '<Q', 48)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                imported(bytes(source))


if __name__ == '__main__':
    unittest.main()
