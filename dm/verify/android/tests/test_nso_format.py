"""Raw NSO/MOD0 validation against independently assembled public inputs."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
from nso_format import NsoError, parse_nso, parse_metadata

FIXTURES = ROOT / 'dm/platform/android/module_fixtures'


def mutable_source(name='main'):
    value = bytearray((FIXTURES / (name + '.nso')).read_bytes())
    # Mutation tests deliberately disable source hashes; hash checks have their
    # own regressions and must not hide a downstream bounds failure.
    struct.pack_into('<I', value, 12, 0)
    return value


def file_offset(source, memory):
    for index in range(3):
        start, offset, size = struct.unpack_from('<III', source, 0x10 + index * 16)
        if offset <= memory < offset + size:
            return start + memory - offset
    raise AssertionError('test address not in source')


def write_image(source, offset, fmt, *values):
    struct.pack_into(fmt, source, file_offset(source, offset), *values)


def dynamic_slot(source, tag):
    nso = parse_nso(source)
    mod0 = struct.unpack_from('<I', nso.image, 4)[0]
    cursor = mod0 + struct.unpack_from('<i', nso.image, mod0 + 4)[0]
    while True:
        current, value = struct.unpack_from('<qQ', nso.image, cursor)
        if current == tag:
            return cursor
        if not current:
            raise AssertionError(f'no tag {tag}')
        cursor += 16


class NsoFormatTests(unittest.TestCase):
    def reject(self, source, message):
        with self.assertRaisesRegex(NsoError, message):
            parse_metadata(parse_nso(source))

    def test_public_raw_and_compressed_sources(self):
        for name in ('main', 'sdk', 'extra'):
            source = (FIXTURES / (name + '.nso')).read_bytes()
            nso = parse_nso(source)
            metadata = parse_metadata(nso)
            self.assertEqual(len(nso.build_id), 32)
            self.assertEqual(len(nso.source_sha256), 32)
            self.assertEqual(nso.image[0x9000:], bytes(4096))
            self.assertEqual(metadata.symbol_count_source, 'DT_HASH')
            self.assertEqual(nso.flags & 7, 7 if name == 'sdk' else 0)
            self.assertGreater(len(metadata.symbols), 3)

    def test_truncated_header_section_and_bad_magic(self):
        source = (FIXTURES / 'main.nso').read_bytes()
        for value in (source[:255], source[:-1], b'XXXX' + source[4:]):
            with self.assertRaises(NsoError):
                parse_nso(value)

    def test_hash_mismatch_in_each_segment(self):
        for index in range(3):
            source = bytearray((FIXTURES / 'main.nso').read_bytes())
            start = struct.unpack_from('<I', source, 0x10 + index * 16)[0]
            source[start + 100] ^= 1
            with self.assertRaisesRegex(NsoError, 'SHA256 mismatch'):
                parse_nso(source)

    def test_corrupt_compressed_block(self):
        source = bytearray((FIXTURES / 'sdk.nso').read_bytes())
        start = struct.unpack_from('<I', source, 0x10)[0]
        size = struct.unpack_from('<I', source, 0x60)[0]
        source[start:start + size] = bytes(size)
        with self.assertRaisesRegex(NsoError, 'LZ4'):
            parse_nso(source)

    def test_overlapping_memory_and_file_extents(self):
        source = mutable_source()
        struct.pack_into('<I', source, 0x24, 0)
        with self.assertRaisesRegex(NsoError, 'overlap'):
            parse_nso(source)
        source = mutable_source()
        struct.pack_into('<I', source, 0x20, 256)
        with self.assertRaisesRegex(NsoError, 'overlapping NSO file'):
            parse_nso(source)

    def test_bounded_allocation_and_flags(self):
        source = mutable_source()
        struct.pack_into('<I', source, 0x28, 0xFFFFFFFC)
        with self.assertRaisesRegex(NsoError, 'bounds'):
            parse_nso(source)
        source = mutable_source()
        struct.pack_into('<I', source, 12, 0x8000)
        with self.assertRaisesRegex(NsoError, 'reserved flags'):
            parse_nso(source)

    def test_mod0_relative_bounds_bss_geometry_and_alignment(self):
        for memory, value, message in ((4, 0xFFFFFFFF, 'unaligned MOD0'),
                                        (0x44, 0x7FFFFFFC, 'section'),
                                        (0x48, 0, 'BSS geometry')):
            source = mutable_source()
            write_image(source, memory, '<I', value)
            self.reject(source, message)

    def test_mod0_bss_can_occupy_a_subrange_of_the_zero_tail(self):
        source = mutable_source()
        nso = parse_nso(source)
        expected = parse_metadata(nso)
        mod0, data = expected.mod0, nso.sections[2]
        image_end = len(nso.image)
        ranges = ((data.end, image_end - 16),
                  (data.end + 16, image_end),
                  (data.end + 16, image_end - 32),
                  (data.end, data.end),
                  (data.end + 16, data.end + 16),
                  (image_end, image_end))
        for start, end in ranges:
            with self.subTest(start=start, end=end):
                candidate = bytearray(source)
                write_image(candidate, mod0 + 8, '<ii', start - mod0, end - mod0)
                parsed = parse_nso(candidate)
                self.assertEqual(parse_metadata(parsed), expected)
                self.assertEqual(parsed.bss_size, nso.bss_size)
                self.assertEqual(len(parsed.image), image_end)
                self.assertEqual(parsed.image[data.offset:data.end], nso.image[data.offset:data.end])
                self.assertEqual(parsed.image[data.end:], bytes(nso.bss_size))

    def test_mod0_bss_rejects_reversed_overlapping_and_outside_ranges(self):
        source = mutable_source()
        nso = parse_nso(source)
        mod0 = parse_metadata(nso).mod0
        data_end, image_end = nso.sections[2].end, len(nso.image)
        ranges = ((data_end + 16, data_end),
                  (data_end - 4, image_end),
                  (data_end - 4, data_end - 4),
                  (data_end, image_end + 4),
                  (image_end + 4, image_end + 4),
                  (mod0 - 0x80000000, image_end),
                  (data_end, mod0 + 0x7FFFFFFF))
        for start, end in ranges:
            with self.subTest(start=start, end=end):
                candidate = bytearray(source)
                write_image(candidate, mod0 + 8, '<ii', start - mod0, end - mod0)
                self.reject(candidate, 'BSS geometry')

    def test_nso_bss_allocation_must_remain_bounded(self):
        source = mutable_source()
        struct.pack_into('<I', source, 0x3C, 0xFFFFFFFF)
        with self.assertRaisesRegex(NsoError, 'BSS: range outside bounds'):
            parse_nso(source)

    def test_dynamic_terminator_and_duplicate_tags(self):
        source = mutable_source()
        for offset in range(0x8400, 0x9000, 16):
            write_image(source, offset, '<qQ', 1, 0)
        self.reject(source, 'missing DT_NULL')
        source = mutable_source()
        write_image(source, 0x8410, '<qQ', 5, 1)
        self.reject(source, 'duplicate dynamic')

    def test_count_sources_and_hashless_fallback(self):
        source = mutable_source()
        hash_slot = dynamic_slot(source, 4)
        write_image(source, hash_slot, '<q', 0x6FFFFEF6)
        metadata = parse_metadata(parse_nso(source))
        self.assertEqual(metadata.symbol_count_source, 'NSO dynsym extent')
        struct.pack_into('<II', source, 0x98, 0, 0)
        metadata = parse_metadata(parse_nso(source))
        self.assertEqual(metadata.symbol_count_source, 'adjacent dynsym/dynstr layout')
        write_image(source, dynamic_slot(source, 5) + 8, '<Q', metadata.dynamic[5] + 1)
        self.reject(source, 'alignment/termination|NSO dynstr extent')

    def test_hash_count_disagreement_and_bad_bucket(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        write_image(source, metadata.dynamic[4] + 8, '<I', len(metadata.symbols))
        self.reject(source, 'DT_HASH symbol index')
        source = mutable_source()
        struct.pack_into('<I', source, 0x9C, (len(metadata.symbols) - 1) * 24)
        self.reject(source, 'count sources disagree')
        source = mutable_source()
        # A self-cycle in an otherwise bounded chain must also reject.
        write_image(source, metadata.dynamic[4] + 16, '<I', 1)
        self.reject(source, 'cyclic DT_HASH chain')

    def test_gnu_hash_count_and_chain_bounds(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        slot = dynamic_slot(source, 4)
        write_image(source, slot, '<qQ', 0x6FFFFEF5, 0x4E00)
        write_image(source, 0x4E00, '<IIIIQ', 1, 1, 1, 5, 0)
        write_image(source, 0x4E18, '<I', 1)
        for index in range(1, len(metadata.symbols)):
            write_image(source, 0x4E1C + 4 * (index - 1), '<I', 1 if index == len(metadata.symbols) - 1 else 2)
        self.assertEqual(parse_metadata(parse_nso(source)).symbol_count_source, 'DT_GNU_HASH')
        write_image(source, 0x4E18, '<I', 0xFFFFFFFF)
        self.reject(source, 'chain missing terminator')

    def test_symbol_name_and_function_ranges(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        write_image(source, metadata.dynamic[6] + 24, '<I', metadata.string_size)
        self.reject(source, 'symbol name outside')
        source = mutable_source()
        function_index = next(i for i, s in enumerate(metadata.symbols) if s.kind == 2 and s.section)
        write_image(source, metadata.dynamic[6] + function_index * 24 + 16, '<Q', 0x100000)
        self.reject(source, 'function symbol outside')

    def test_defined_zero_size_data_markers_can_equal_image_end(self):
        source = mutable_source()
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        index = next(i for i, symbol in enumerate(metadata.symbols) if symbol.name == 'main_bss')
        offset = metadata.dynamic[6] + index * 24
        for binding in (0, 1, 2):
            for kind in (0, 1):
                with self.subTest(binding=binding, kind=kind):
                    candidate = bytearray(source)
                    write_image(candidate, offset + 4, '<BBHQQ', binding << 4 | kind, 0, 1, len(nso.image), 0)
                    marker = parse_metadata(parse_nso(candidate)).symbols[index]
                    self.assertEqual((marker.value, marker.size, marker.kind), (len(nso.image), 0, kind))
        for writable in (False, True):
            with self.assertRaises(NsoError):
                nso.section_for(len(nso.image), 1, writable=writable)

    def test_image_end_marker_does_not_relax_symbol_storage_or_function_bounds(self):
        source = mutable_source()
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        index = next(i for i, symbol in enumerate(metadata.symbols) if symbol.name == 'main_bss')
        offset = metadata.dynamic[6] + index * 24
        for kind, section, value, size in ((0, 1, len(nso.image), 1),
                                           (1, 1, len(nso.image) - 1, 2),
                                           (0, 1, len(nso.image) + 1, 0),
                                           (0, 1, 0xFFFFFFFFFFFFFFFF, 0),
                                           (2, 1, len(nso.image), 0),
                                           (2, 1, nso.sections[0].end, 0),
                                           (0, 0, len(nso.image), 0)):
            with self.subTest(kind=kind, section=section, value=value, size=size):
                candidate = bytearray(source)
                write_image(candidate, offset + 4, '<BBHQQ', 0x10 | kind, 0, section, value, size)
                self.reject(candidate, 'section|function|undefined')

    def test_relative_pointer_can_equal_image_end_but_destination_stays_writable(self):
        source = mutable_source()
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        index = next(i for i, relocation in enumerate(metadata.relocations) if relocation.kind == 1027)
        record = metadata.dynamic[7] + index * 24
        write_image(source, record + 16, '<q', len(nso.image))
        self.assertEqual(parse_metadata(parse_nso(source)).relocations[index].addend, len(nso.image))
        for value in (-1, len(nso.image) + 1, 0x7FFFFFFFFFFFFFFF):
            candidate = bytearray(source)
            write_image(candidate, record + 16, '<q', value)
            self.reject(candidate, 'RELATIVE addend')
        candidate = bytearray(source)
        write_image(candidate, record, '<Q', len(nso.image))
        self.reject(candidate, 'writable')
        candidate = bytearray(source)
        write_image(candidate, record + 8, '<Q', 1 << 32 | 1027)
        self.reject(candidate, 'invalid relocation')

    def test_nso_relative_accepts_four_aligned_packed_pointer_fields(self):
        source = mutable_source()
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        index = next(i for i, relocation in enumerate(metadata.relocations) if relocation.kind == 1027)
        record = metadata.dynamic[7] + index * 24
        for target in (0x8204, nso.sections[2].end + 4, len(nso.image) - 12):
            with self.subTest(target=target):
                candidate = bytearray(source)
                write_image(candidate, record, '<Q', target)
                parsed = parse_nso(candidate)
                before = parsed.image
                try:
                    result = parse_metadata(parsed)
                except NsoError as error:
                    self.fail(f'packed NSO RELATIVE destination must decode: {error}')
                self.assertEqual(result.relocations[index].offset, target)
                self.assertEqual(result.relocations[index].addend, metadata.relocations[index].addend)
                self.assertEqual(parsed.image, before)

    def test_packed_relative_keeps_alignment_bounds_symbol_and_overlap_guards(self):
        source = mutable_source()
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        index = next(i for i, relocation in enumerate(metadata.relocations) if relocation.kind == 1027)
        record = metadata.dynamic[7] + index * 24
        for target in (0x8201, 0x8202, 0x8203, 0x8205, 0x8206, 0x8207):
            candidate = bytearray(source)
            write_image(candidate, record, '<Q', target)
            self.reject(candidate, 'invalid relocation')
        for kind in (257, 1025, 1026):
            candidate = bytearray(source)
            write_image(candidate, record, '<QQ', 0x8204, 1 << 32 | kind)
            self.reject(candidate, 'invalid relocation')
        for target, message in ((0x104, 'writable'), (len(nso.image) - 4, 'writable'),
                                (0x8404, 'overlaps dynamic metadata'), (0x8004, 'invalid relocation')):
            candidate = bytearray(source)
            write_image(candidate, record, '<Q', target)
            self.reject(candidate, message)
        # A four-byte overlap must reject in either table order. Keeping only
        # exact duplicate starts was sufficient only while all starts were8-aligned.
        first, second = metadata.dynamic[7], record
        for a, b in ((0x8200, 0x8204), (0x8204, 0x8200), (0x8204, 0x8204)):
            candidate = bytearray(source)
            write_image(candidate, first, '<QQq', a, 1027, 0x8100)
            write_image(candidate, second, '<QQq', b, 1027, 0x8100)
            self.reject(candidate, 'invalid relocation')

    def test_image_end_relative_pointer_cannot_be_an_initializer(self):
        source = mutable_source()
        nso = parse_nso(source)
        metadata = parse_metadata(nso)
        write_image(source, dynamic_slot(source, 12) + 8, '<Q', len(nso.image))
        self.reject(source, 'initializer outside text')
        source = mutable_source()
        # Replace the terminating dynamic slot with a bounded initializer array.
        null_slot = dynamic_slot(source, 0)
        write_image(source, null_slot, '<qQqQqQ', 25, 0x8300, 27, 8, 0, 0)
        index = next(i for i, relocation in enumerate(metadata.relocations) if relocation.kind == 1027)
        write_image(source, metadata.dynamic[7] + index * 24, '<QQq', 0x8300, 1027, len(nso.image))
        self.reject(source, 'initializer outside text')

    def test_relocation_whitelist_target_symbol_and_addend(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        offset = metadata.dynamic[7]
        for displacement, fmt, value, message in ((0, '<Q', 0x8001, 'invalid relocation'),
                                                  (0, '<Q', 0x100, 'writable'),
                                                  (8, '<Q', 9999, 'unsupported relocation'),
                                                  (8, '<Q', (len(metadata.symbols) << 32) | 257, 'invalid relocation')):
            copy = bytearray(source)
            write_image(copy, offset + displacement, fmt, value)
            self.reject(copy, message)
        relative_index = next(i for i, r in enumerate(metadata.relocations) if r.kind == 1027)
        write_image(source, offset + relative_index * 24 + 16, '<q', -1)
        self.reject(source, 'RELATIVE addend')

    def test_metadata_alias_and_relocation_metadata_target(self):
        source = mutable_source()
        metadata = parse_metadata(parse_nso(source))
        write_image(source, metadata.dynamic[7], '<Q', 0x8400)
        self.reject(source, 'target overlaps dynamic metadata')

    def test_init_bounds(self):
        source = mutable_source()
        write_image(source, dynamic_slot(source, 12) + 8, '<Q', 0x8000)
        self.reject(source, 'initializer outside text')

    def test_bounded_eh_frame_header(self):
        source = mutable_source()
        write_image(source, 0x50, '<ii', 0x4D00 - 0x40, 0x4D14 - 0x40)
        write_image(source, 0x4D00, '<BBBBiIii', 1, 0x1B, 3, 0x3B,
                    0x4F00 - 0x4D04, 1, 0x100 - 0x4D00, 0x4F00 - 0x4D00)
        self.assertEqual(parse_metadata(parse_nso(source)).eh_starts, (0x100,))
        write_image(source, 0x4D08, '<I', 0xFFFFFFFF)
        self.reject(source, 'EH frame table count')

    def test_compressed_and_uncompressed_same_image(self):
        source = (FIXTURES / 'sdk.nso').read_bytes()
        nso = parse_nso(source)
        header = bytearray(source[:256])
        struct.pack_into('<I', header, 12, nso.flags & ~7)
        cursor, parts = 256, []
        for index, section in enumerate(nso.sections):
            raw = nso.image[section.offset:section.end]
            struct.pack_into('<I', header, 0x10 + index * 16, cursor)
            struct.pack_into('<I', header, 0x60 + index * 4, len(raw))
            parts.append(raw)
            cursor += len(raw)
        uncompressed = parse_nso(bytes(header) + b''.join(parts))
        self.assertEqual(uncompressed.image, nso.image)
        self.assertEqual(uncompressed.build_id, nso.build_id)
        self.assertEqual(parse_metadata(uncompressed), parse_metadata(nso))


if __name__ == '__main__':
    unittest.main()
