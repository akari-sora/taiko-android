"""Freely authored exception-frame records; no runtime call authority."""
from dataclasses import FrozenInstanceError, replace
import hashlib
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
from nso_format import Nso, Section, NsoError, Relocation, Symbol
from nso_eh import validated_eh_functions, eh_target_set_sha256


def uleb(value):
    result = bytearray()
    while True:
        byte = value & 127; value >>= 7
        result.append(byte | (128 if value else 0))
        if not value: return bytes(result)


def sleb(value):
    result = bytearray()
    while True:
        byte = value & 127; value >>= 7
        done = value == 0 and not byte & 64 or value == -1 and byte & 64
        result.append(byte | (0 if done else 128))
        if done: return bytes(result)


def fixture(*, version=1, augmentation='zR', extended=False, encoding=0x1b, lsda_encoding=0x1c,
            personality_encoding=0x9c, unindexed_zero=False):
    raw = bytearray(0x2000); mod0, header, cie = 0x40, 0x1000, 0x1100
    struct.pack_into('<I', raw, 4, mod0); raw[mod0:mod0+4] = b'MOD0'
    struct.pack_into('<ii', raw, mod0 + 16, header-mod0, header+20-mod0)
    prefix = 12 if extended else 4
    def pointer(value, how, at):
        formats = {0: '<Q', 2: '<H', 3: '<I', 4: '<Q', 10: '<h', 11: '<i', 12: '<q'}
        adjusted = value - (at if how & 0x70 == 0x10 else header if how & 0x70 == 0x30 else 0) if value else 0
        if how & 15 == 1: return uleb(adjusted)
        if how & 15 == 9: return sleb(adjusted)
        return struct.pack(formats[how & 15], adjusted)
    body = bytearray(struct.pack('<I', 0) + bytes([version]) + augmentation.encode() + b'\0')
    if version == 4: body += bytes([8, 0])
    body += uleb(1) + sleb(-8) + (bytes([30]) if version == 1 else uleb(30))
    augmentation_length_at = None
    if augmentation:
        extra = bytearray()
        for character in augmentation[1:]:
            if character == 'R': extra.append(encoding)
            elif character == 'L': extra.append(lsda_encoding)
            elif character == 'P':
                extra.append(personality_encoding)
                extra += pointer(0x1810, personality_encoding, cie + prefix + len(body) + 1 + len(extra))
        augmentation_length_at = cie + prefix + len(body)
        body += uleb(len(extra)) + extra
    body += b'\x0c\x1f\x00'
    while (prefix + len(body)) % 8: body.append(0)
    record = (struct.pack('<IQ', 0xffffffff, len(body)) if extended else struct.pack('<I', len(body))) + body
    raw[cie:cie+len(record)] = record; fde = cie + len(record)
    def fde_record(at, start, size):
        entry = bytearray(struct.pack('<I', at + prefix - cie))
        entry += pointer(start, encoding, at + prefix + len(entry))
        entry += pointer(size, encoding & 15, at + prefix + len(entry))
        if augmentation:
            extra = pointer(0x1600, lsda_encoding, at + prefix + len(entry) + 1) if 'L' in augmentation and lsda_encoding != 255 else b''
            entry += uleb(len(extra)) + extra
        while (prefix + len(entry)) % 8: entry.append(0)
        return (struct.pack('<IQ', 0xffffffff, len(entry)) if extended else struct.pack('<I', len(entry))) + entry
    record = fde_record(fde, 0x100, 0x40)
    raw[fde:fde+len(record)] = record
    end = fde + len(record)
    if unindexed_zero:
        extra = fde_record(end, 0x100, 0)
        raw[end:end+len(extra)] = extra; end += len(extra)
    struct.pack_into('<I', raw, end, 0)
    raw[header:header+4] = bytes([1, 0x1b, 3, 0x3b])
    struct.pack_into('<iIii', raw, header+4, cie-(header+4), 1, 0x100-header, fde-header)
    struct.pack_into('<Q', raw, 0x1810, 0x200)
    nso = Nso(bytes(raw), (Section('text', 0, 0x800), Section('ro', 0x1000, 0x800), Section('data', 0x1800, 0x400)),
        0, bytes(32), hashlib.sha256(raw).digest(), 0, (0, 0), (0, 0))
    metadata = SimpleNamespace(mod0=mod0, eh_starts=(0x100,), relocations=(), symbols=())
    return nso, metadata, dict(header=header, cie=cie, fde=fde, prefix=prefix, terminator=end,
        augmentation_length=augmentation_length_at)


class NsoEhTests(unittest.TestCase):
    def mutate(self, nso, at, spec, value):
        raw = bytearray(nso.image); struct.pack_into(spec, raw, at, value)
        return replace(nso, image=bytes(raw))

    def test_valid_indexed_fde_has_immutable_crosschecked_extent(self):
        nso, metadata, locations = fixture()
        result = validated_eh_functions(nso, metadata)
        self.assertIsInstance(result, tuple)
        self.assertEqual([(row.start, row.end, row.fde, row.cie) for row in result],
            [(0x100, 0x140, locations['fde'], locations['cie'])])
        with self.assertRaises((FrozenInstanceError, AttributeError)): result[0].start = 0x200
        self.assertEqual(eh_target_set_sha256(result), hashlib.sha256(struct.pack('<Q', 0x100)).hexdigest())

    def test_recognized_versions_augmentation_and_extended_lengths(self):
        for version in (1, 3, 4):
            for extended in (False, True):
                for augmentation in ('', 'z', 'zR', 'zRS', 'zPLR'):
                    with self.subTest(version=version, extended=extended, augmentation=augmentation):
                        nso, metadata, _ = fixture(version=version, extended=extended, augmentation=augmentation,
                            encoding=0x1b if 'R' in augmentation else 0)
                        self.assertEqual(validated_eh_functions(nso, metadata)[0].start, 0x100)

    def test_supported_absolute_and_pc_relative_pointer_formats(self):
        for encoding in (0, 1, 2, 3, 4, 9, 10, 11, 12, 0x19, 0x1a, 0x1b, 0x1c):
            with self.subTest(encoding=encoding):
                nso, metadata, _ = fixture(encoding=encoding)
                self.assertEqual(validated_eh_functions(nso, metadata)[0].end, 0x140)

    def test_unknown_data_relative_frame_base_is_not_guessed_from_header(self):
        nso, metadata, _ = fixture(encoding=0x3b)
        with self.assertRaisesRegex(NsoError, 'declared ABI base'):
            validated_eh_functions(nso, metadata)

    def test_unindexed_zero_range_is_structural_only_never_an_extra_target(self):
        nso, metadata, _ = fixture(unindexed_zero=True)
        self.assertEqual(len(validated_eh_functions(nso, metadata)), 1)

    def test_reserved_zero_header_slots_are_padding_and_never_extra_rows(self):
        nso, metadata, at = fixture()
        nso = self.mutate(nso, metadata.mod0+20, '<i', at['header']+20+104-metadata.mod0)
        self.assertEqual(len(validated_eh_functions(nso, metadata)), 1)
        nso = self.mutate(nso, at['header']+20, '<B', 1)
        with self.assertRaisesRegex(NsoError, r'EH.*0x'): validated_eh_functions(nso, metadata)

    def test_indexed_initial_location_and_positive_aligned_range_must_match(self):
        nso, metadata, at = fixture()
        for offset, value in ((at['fde']+8, 0x104-(at['fde']+8)),
                              (at['fde']+12, -4), (at['fde']+12, 3), (at['fde']+12, 0x1000)):
            with self.subTest(offset=offset, value=value), self.assertRaisesRegex(NsoError, r'EH.*0x'):
                validated_eh_functions(self.mutate(nso, offset, '<i', value), metadata)

    def test_indexed_zero_range_is_excluded_without_rebinding_unindexed_positive(self):
        nso, metadata, at = fixture(unindexed_zero=True)
        extra_fde = at['fde'] + struct.unpack_from('<I', nso.image, at['fde'])[0] + 4
        nso = self.mutate(nso, at['fde']+12, '<i', 0)
        nso = self.mutate(nso, extra_fde+12, '<i', 0x80)
        self.assertEqual(validated_eh_functions(nso, metadata), ())
        self.assertEqual(eh_target_set_sha256(()), hashlib.sha256(b'').hexdigest())

    def test_cie_backreference_must_name_a_preceding_record_boundary(self):
        nso, metadata, at = fixture()
        for value in (0, 4, at['fde']+4, 0xffffffff):
            with self.subTest(value=value), self.assertRaisesRegex(NsoError, r'EH.*0x'):
                validated_eh_functions(self.mutate(nso, at['fde']+4, '<I', value), metadata)

    def test_lengths_and_terminator_are_bounded(self):
        nso, metadata, at = fixture()
        for offset, value in ((at['cie'], 3), (at['cie'], 0xfffffff0), (at['fde'], 0xffffffff),
                              (at['fde'], 0x7fffffff), (at['terminator'], 0x7fffffff)):
            with self.subTest(offset=offset, value=value), self.assertRaisesRegex(NsoError, r'EH.*0x'):
                validated_eh_functions(self.mutate(nso, offset, '<I', value), metadata)

    def test_unsupported_augmentation_encoding_and_version_reject(self):
        nso, metadata, at = fixture()
        for offset, value in ((at['cie']+8, 2), (at['cie']+10, ord('Q')),
                              (at['augmentation_length'], 127), (at['augmentation_length']+1, 0x7b),
                              (at['header']+1, 0x9b), (at['header']+3, 0x7b)):
            with self.subTest(offset=offset, value=value), self.assertRaisesRegex(NsoError, r'EH.*0x'):
                validated_eh_functions(self.mutate(nso, offset, '<B', value), metadata)

    def test_table_fde_cannot_point_inside_an_existing_record(self):
        nso, metadata, at = fixture()
        mutated = self.mutate(nso, at['header']+16, '<i', at['fde']+4-at['header'])
        with self.assertRaisesRegex(NsoError, r'EH.*0x'): validated_eh_functions(mutated, metadata)

    def test_header_count_and_frame_pointer_bounds_reject(self):
        nso, metadata, at = fixture()
        for offset, value in ((at['header']+8, 1000000), (at['header']+4, -0x100000),
                              (at['header']+4, 0x1810-(at['header']+4))):
            with self.subTest(offset=offset), self.assertRaisesRegex(NsoError, r'EH.*0x'):
                validated_eh_functions(self.mutate(nso, offset, '<i', value), metadata)

    def test_metadata_header_starts_cannot_be_substituted(self):
        nso, metadata, _ = fixture()
        metadata.eh_starts = (0x104,)
        with self.assertRaisesRegex(NsoError, r'EH.*0x'): validated_eh_functions(nso, metadata)

    def test_personality_indirect_import_is_structural_never_resolved(self):
        nso, metadata, _ = fixture(augmentation='zPLR')
        nso = self.mutate(nso, 0x1810, '<Q', 0)
        metadata.symbols = (Symbol('', 0, 0, 0, 0, 0, 0), Symbol('fixture_personality', 0, 0, 1, 2, 0, 0))
        metadata.relocations = (Relocation(0x1810, 257, 1, 0),)
        self.assertEqual(len(validated_eh_functions(nso, metadata)), 1)
        metadata.relocations += (Relocation(0x1814, 257, 1, 0),)
        with self.assertRaisesRegex(NsoError, r'EH.*0x'): validated_eh_functions(nso, metadata)

    def test_uleb_sleb_overflow_reject_without_unbounded_scan(self):
        nso, metadata, at = fixture()
        for displacement in (12, 13):
            raw = bytearray(nso.image)
            raw[at['cie']+displacement:at['cie']+displacement+11] = b'\x80' * 10 + b'\x02'
            with self.subTest(displacement=displacement), self.assertRaisesRegex(NsoError, r'EH.*0x'):
                validated_eh_functions(replace(nso, image=bytes(raw)), metadata)


if __name__ == '__main__': unittest.main()
