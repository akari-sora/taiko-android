"""Bounded NSO0/MOD0 reader shared by production import and public fixtures.

NSO layout follows SciresM/hactool nso.h; dynamic records use ELF64/AAELF64.
No instruction rewriting or game-specific offsets belong in this reader.
"""
from dataclasses import dataclass
import hashlib
import struct

MAX_IMAGE = 512 * 1024 * 1024
SUPPORTED_RELOCATIONS = {257, 1025, 1026, 1027}


class NsoError(ValueError):
    pass


def bounded(offset, size, limit, what):
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise NsoError(f'{what}: range outside bounds')


@dataclass(frozen=True)
class Section:
    name: str
    offset: int
    size: int

    @property
    def end(self):
        return self.offset + self.size


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    size: int
    binding: int
    kind: int
    section: int
    visibility: int


@dataclass(frozen=True)
class Relocation:
    offset: int
    kind: int
    symbol: int
    addend: int


@dataclass(frozen=True)
class Nso:
    image: bytes
    sections: tuple
    bss_size: int
    build_id: bytes
    source_sha256: bytes
    flags: int
    dynstr_extent: tuple
    dynsym_extent: tuple

    def section_for(self, offset, size=1, *, writable=False):
        candidates = self.sections[2:] if writable else self.sections
        for section in candidates:
            end = section.end + (self.bss_size if writable else 0)
            if section.offset <= offset and offset <= end and size <= end - offset:
                return section
        raise NsoError(f'0x{offset:x}: range not in {"writable" if writable else "initialized"} section')


@dataclass(frozen=True)
class Metadata:
    mod0: int
    dynamic: dict
    symbols: tuple
    relocations: tuple
    string_size: int
    init_addresses: tuple
    eh_starts: tuple
    protected: tuple
    symbol_count_source: str


def parse_nso(source):
    if len(source) < 256 or source[:4] != b'NSO0':
        raise NsoError('missing/truncated NSO0 header')
    version, reserved, flags = struct.unpack_from('<III', source, 4)
    if version or reserved or flags & ~63:
        raise NsoError('unsupported NSO version/reserved flags')
    sections, file_ranges, decoded = [], [], []
    sizes = struct.unpack_from('<III', source, 0x60)
    for index, name in enumerate(('text', 'ro', 'data')):
        file_offset, offset, size = struct.unpack_from('<III', source, 0x10 + 16 * index)
        if not size or offset % 4 or size % 4:
            raise NsoError(f'{name}: empty/unaligned section')
        bounded(offset, size, MAX_IMAGE, name)
        stored_size = sizes[index] if flags & (1 << index) else size
        if not stored_size or file_offset < 256:
            raise NsoError(f'{name}: invalid file extent')
        bounded(file_offset, stored_size, len(source), name)
        if any(file_offset < end and start < file_offset + stored_size for start, end in file_ranges):
            raise NsoError('overlapping NSO file sections')
        file_ranges.append((file_offset, file_offset + stored_size))
        raw = source[file_offset:file_offset + stored_size]
        if flags & (1 << index):
            import lz4.block
            try:
                raw = lz4.block.decompress(raw, uncompressed_size=size)
            except (ValueError, lz4.block.LZ4BlockError) as error:
                raise NsoError(f'{name}: invalid LZ4 block') from error
        if len(raw) != size:
            raise NsoError(f'{name}: decompressed size mismatch')
        if flags & (1 << (index + 3)) and hashlib.sha256(raw).digest() != source[0xA0 + index * 32:0xC0 + index * 32]:
            raise NsoError(f'{name}: SHA256 mismatch')
        sections.append(Section(name, offset, size))
        decoded.append(raw)
    if sections[0].offset != 0 or any(a.end > b.offset for a, b in zip(sections, sections[1:])):
        raise NsoError('NSO sections overlap, are unordered, or text does not start at zero')
    bss_size = struct.unpack_from('<I', source, 0x3C)[0]
    bounded(sections[2].end, bss_size, MAX_IMAGE, 'BSS')
    if (sections[2].end + bss_size) % 4:
        raise NsoError('unaligned image end')
    image = bytearray(sections[2].end + bss_size)
    for section, raw in zip(sections, decoded):
        image[section.offset:section.end] = raw
    extents = []
    for field, alignment in ((0x90, 1), (0x98, 24)):
        offset, size = struct.unpack_from('<II', source, field)
        if size:
            bounded(offset, size, sections[1].size, 'NSO dynamic extent')
            if size % alignment:
                raise NsoError('invalid NSO dynamic extent size')
        elif offset:
            raise NsoError('empty NSO dynamic extent has nonzero offset')
        extents.append((sections[1].offset + offset, size))
    return Nso(bytes(image), tuple(sections), bss_size, source[0x40:0x60],
               hashlib.sha256(source).digest(), flags, *extents)


def parse_metadata(nso):
    raw, text, data = nso.image, nso.sections[0], nso.sections[2]
    mod0 = struct.unpack_from('<I', raw, 4)[0]
    if mod0 % 4:
        raise NsoError('unaligned MOD0 pointer')
    nso.section_for(mod0, 28)
    if raw[mod0:mod0 + 4] != b'MOD0':
        raise NsoError('invalid MOD0 pointer/magic')
    relative = struct.unpack_from('<6i', raw, mod0 + 4)
    dynamic_offset, bss_start, bss_end, eh_start, eh_end, module_object = (mod0 + value for value in relative)
    # switch-tools/elf2nso.c stores p_memsz - p_filesz as the NSO zero tail;
    # libnx/switch_crt0.s records linker BSS symbols in MOD0. The logical BSS
    # may exclude padding at either end of that already-zeroed allocation.
    if not data.end <= bss_start <= bss_end <= data.end + nso.bss_size:
        raise NsoError('MOD0 BSS geometry disagrees with NSO')
    if module_object != mod0:
        nso.section_for(module_object, 1, writable=True)
    section = nso.section_for(dynamic_offset, 16)
    if dynamic_offset % 8:
        raise NsoError('unaligned dynamic table')
    dynamic, protected = {}, [(4, 8), (mod0, mod0 + 28)]
    cursor = dynamic_offset
    while cursor <= section.end - 16:
        if cursor - dynamic_offset >= 65536 * 16:
            raise NsoError('dynamic entry limit exceeded')
        tag, value = struct.unpack_from('<qQ', raw, cursor)
        cursor += 16
        if tag == 0:
            break
        if tag in dynamic:
            # Repeatable dependency tags do not affect symbol/relocation geometry.
            if tag != 1:
                raise NsoError(f'duplicate dynamic tag {tag}')
        else:
            dynamic[tag] = value
    else:
        raise NsoError('dynamic table missing DT_NULL')
    protected.append((dynamic_offset, cursor))
    for tag in (5, 6, 10, 11):
        if tag not in dynamic:
            raise NsoError(f'missing dynamic tag {tag}')
    if dynamic[11] != 24 or not dynamic[10]:
        raise NsoError('invalid DT_SYMENT/DT_STRSZ')
    strtab, strsz, symtab = dynamic[5], dynamic[10], dynamic[6]
    nso.section_for(strtab, strsz)
    symbol_section = nso.section_for(symtab, 24)
    if symtab % 8 or raw[strtab] != 0 or raw[strtab + strsz - 1] != 0:
        raise NsoError('invalid dynamic string/symbol table alignment/termination')
    if nso.dynstr_extent[1] and nso.dynstr_extent != (strtab, strsz):
        raise NsoError('NSO dynstr extent disagrees with dynamic table')
    counts = []
    if 4 in dynamic:
        offset = dynamic[4]
        nso.section_for(offset, 8)
        buckets, chains = struct.unpack_from('<II', raw, offset)
        if not buckets or not chains:
            raise NsoError('empty DT_HASH')
        size = 8 + 4 * (buckets + chains)
        nso.section_for(offset, size)
        values = struct.unpack_from(f'<{buckets + chains}I', raw, offset + 8)
        if any(value >= chains for value in values):
            raise NsoError('DT_HASH symbol index outside table')
        marks = bytearray(chains)
        links = values[buckets:]
        for start in range(1, chains):
            index = start
            while index and not marks[index]:
                marks[index] = 1
                index = links[index]
            if index and marks[index] == 1:
                raise NsoError('cyclic DT_HASH chain')
            index = start
            while index and marks[index] == 1:
                marks[index] = 2
                index = links[index]
        counts.append(('DT_HASH', chains))
        protected.append((offset, offset + size))
    if 0x6FFFFEF5 in dynamic:
        offset = dynamic[0x6FFFFEF5]
        hash_section = nso.section_for(offset, 16)
        buckets, first, bloom_size, shift = struct.unpack_from('<IIII', raw, offset)
        if not buckets or not first or not bloom_size or bloom_size & (bloom_size - 1) or shift >= 64:
            raise NsoError('invalid GNU hash header')
        bucket_start = offset + 16 + bloom_size * 8
        chain_start = bucket_start + buckets * 4
        nso.section_for(offset, chain_start - offset)
        count, chain_end, seen = first, chain_start, set()
        for value in struct.unpack_from(f'<{buckets}I', raw, bucket_start):
            if value == 0:
                continue
            if value < first:
                raise NsoError('GNU hash bucket below symbol offset')
            index = value
            while True:
                location = chain_start + 4 * (index - first)
                if location > hash_section.end - 4:
                    raise NsoError('GNU hash chain missing terminator')
                if index in seen:
                    raise NsoError('overlapping GNU hash chains')
                seen.add(index)
                chain = struct.unpack_from('<I', raw, location)[0]
                chain_end = max(chain_end, location + 4)
                count = max(count, index + 1)
                if chain & 1:
                    break
                index += 1
        if not count:
            raise NsoError('GNU hash missing null symbol')
        counts.append(('DT_GNU_HASH', count))
        protected.append((offset, chain_end))
    if nso.dynsym_extent[1]:
        if nso.dynsym_extent[0] != symtab:
            raise NsoError('NSO dynsym extent disagrees with dynamic table')
        counts.append(('NSO dynsym extent', nso.dynsym_extent[1] // 24))
    if not counts:
        # Some old NSOs omit header extents and hash tables. Only accept an
        # exact adjacent table layout, then validate every inferred symbol.
        if strtab <= symtab or strtab > symbol_section.end or (strtab - symtab) % 24:
            raise NsoError('no bounded dynamic symbol count')
        counts.append(('adjacent dynsym/dynstr layout', (strtab - symtab) // 24))
    count = counts[0][1]
    if not count or any(value != count for _, value in counts):
        raise NsoError('dynamic symbol count sources disagree')
    nso.section_for(symtab, count * 24)
    protected.extend(((symtab, symtab + count * 24), (strtab, strtab + strsz)))
    symbols = []
    for index in range(count):
        name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', raw, symtab + index * 24)
        if name >= strsz:
            raise NsoError('symbol name outside string table')
        name_end = raw.find(b'\0', strtab + name, strtab + strsz)
        if name_end < 0:
            raise NsoError('unterminated symbol name')
        try:
            symbol_name = raw[strtab + name:name_end].decode('utf-8')
        except UnicodeError as error:
            raise NsoError('invalid symbol name encoding') from error
        binding, kind = info >> 4, info & 15
        if binding not in (0, 1, 2) or kind not in (0, 1, 2) or other & ~3:
            raise NsoError(f'unsupported symbol attributes for {symbol_name!r}')
        if shndx and shndx != 0xFFF1:
            if shndx >= 0xFF00:
                raise NsoError('unsupported reserved symbol section')
            # Object values may include zeroed BSS; FUNC values must be text.
            if kind == 2:
                if value % 4 or size % 4 or value >= text.end or size > text.end - value:
                    raise NsoError('function symbol outside text/alignment')
            elif not (size == 0 and value == len(raw)):
                # GNU ld linker markers name addresses without storage. Only
                # a zero-size non-function may name the exact image end.
                try:
                    nso.section_for(value, max(size, 1))
                except NsoError:
                    nso.section_for(value, max(size, 1), writable=True)
        elif shndx == 0 and (value or size):
            raise NsoError('undefined symbol has a value/size')
        symbols.append(Symbol(symbol_name, value, size, binding, kind, shndx, other))
    if raw[symtab:symtab + 24] != bytes(24):
        raise NsoError('dynamic symbol zero is not null')
    relocations, occupied = [], set()
    for forbidden in (17, 18, 19, 35, 36, 37):
        if dynamic.get(forbidden):
            raise NsoError(f'unsupported REL/RELR relocation tag {forbidden}')
    for pointer_tag, size_tag in ((7, 8), (23, 2)):
        size = dynamic.get(size_tag, 0)
        if (pointer_tag in dynamic) != (size_tag in dynamic):
            raise NsoError('relocation pointer/size tags must occur together')
        if size and pointer_tag not in dynamic:
            raise NsoError('relocation size without table')
        if pointer_tag == 7 and size and dynamic.get(9) != 24:
            raise NsoError('unsupported DT_RELAENT')
        if pointer_tag == 23 and size and dynamic.get(20) != 7:
            raise NsoError('DT_JMPREL must use RELA')
        if size % 24:
            raise NsoError('unaligned RELA table size')
        if not size:
            continue
        offset = dynamic[pointer_tag]
        if offset % 8:
            raise NsoError('unaligned RELA table')
        nso.section_for(offset, size)
        protected.append((offset, offset + size))
        for cursor in range(offset, offset + size, 24):
            target, info, addend = struct.unpack_from('<QQq', raw, cursor)
            kind, symbol = info & 0xFFFFFFFF, info >> 32
            if kind not in SUPPORTED_RELOCATIONS:
                raise NsoError(f'unsupported relocation {kind} at 0x{target:x}')
            # NSOs can retain packed, four-aligned RELATIVE pointer fields.
            # Other dynamic places retain AAELF64's eight-byte alignment.
            # Every admitted place still owns eight writable bytes; checking
            # neighboring four-byte starts prevents partially overlapping writes
            # without expanding the relocation-count memory budget.
            alignment = 4 if kind == 1027 else 8
            if (target % alignment or any(start in occupied for start in (target - 4, target, target + 4)) or
                    symbol >= count or (kind == 1027 and symbol)):
                raise NsoError('invalid relocation target/symbol')
            nso.section_for(target, 8, writable=True)
            # AAELF64 RELATIVE produces a pointer (base + addend), including
            # the one-past address; the target still requires 8 writable bytes.
            if kind == 1027 and not 0 <= addend <= len(raw):
                raise NsoError('RELATIVE addend outside image')
            occupied.add(target)
            relocations.append(Relocation(target, kind, symbol, addend))
    init_addresses = []
    if dynamic.get(12):
        init_addresses.append(dynamic[12])
    array_size = dynamic.get(27, 0)
    if (25 in dynamic) != (27 in dynamic):
        raise NsoError('initializer array pointer/size tags must occur together')
    if array_size:
        if dynamic[25] % 8 or array_size % 8:
            raise NsoError('invalid DT_INIT_ARRAY')
        start = dynamic[25]
        nso.section_for(start, array_size)
        protected.append((start, start + array_size))
        relocated = {r.offset: r for r in relocations}
        for cursor in range(start, start + array_size, 8):
            r = relocated.get(cursor)
            value = struct.unpack_from('<Q', raw, cursor)[0]
            if r:
                if r.kind != 1027:
                    raise NsoError('unsupported symbolic DT_INIT_ARRAY pointer')
                value = r.addend
            if value not in (0, 0xFFFFFFFFFFFFFFFF):
                init_addresses.append(value)
    for address in init_addresses:
        if address % 4 or not text.offset <= address < text.end:
            raise NsoError('initializer outside text')
    starts = []
    if eh_start != eh_end:
        if eh_start > eh_end:
            raise NsoError('invalid MOD0 EH frame range')
        nso.section_for(eh_start, eh_end - eh_start)
        protected.append((eh_start, eh_end))
        if eh_end - eh_start < 4 or raw[eh_start] != 1:
            raise NsoError('unsupported EH frame header version')
        pointer_encoding, count_encoding, table_encoding = raw[eh_start + 1:eh_start + 4]
        def encoded(cursor, encoding):
            fmt, application = encoding & 15, encoding & 0x70
            formats = {3: ('<I', 4), 11: ('<i', 4), 4: ('<Q', 8), 12: ('<q', 8), 0: ('<Q', 8)}
            if encoding & 0x80 or fmt not in formats or application not in (0, 0x10, 0x30):
                raise NsoError('unsupported EH frame pointer encoding')
            spec, width = formats[fmt]
            bounded(cursor, width, eh_end, 'EH frame table')
            value = struct.unpack_from(spec, raw, cursor)[0]
            value += cursor if application == 0x10 else eh_start if application == 0x30 else 0
            return value, cursor + width
        _, cursor = encoded(eh_start + 4, pointer_encoding)
        fde_count, cursor = encoded(cursor, count_encoding)
        if count_encoding & 0x70 or fde_count > (eh_end - cursor) // 8:
            raise NsoError('invalid EH frame table count')
        for _ in range(fde_count):
            start, cursor = encoded(cursor, table_encoding)
            fde, cursor = encoded(cursor, table_encoding)
            if start % 4 or not text.offset <= start < text.end:
                raise NsoError('EH frame function outside text')
            nso.section_for(fde, 4)
            starts.append(start)
        if starts != sorted(set(starts)):
            raise NsoError('EH frame starts unordered/duplicate')
    for index, (start, end) in enumerate(protected):
        if any(start < other_end and other_start < end for other_start, other_end in protected[:index]):
            raise NsoError('overlapping MOD0/dynamic metadata records')
    for relocation in relocations:
        if any(start < relocation.offset + 8 and relocation.offset < end for start, end in protected
               if (start, end) != (dynamic.get(25), dynamic.get(25, 0) + array_size)):
            raise NsoError('relocation target overlaps dynamic metadata')
    # Metadata records are always data even when located in the text section.
    return Metadata(mod0, dynamic, tuple(symbols), tuple(relocations), strsz,
                    tuple(init_addresses), tuple(starts), tuple(protected), counts[0][0])
