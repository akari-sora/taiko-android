"""Opt-in bounded .eh_frame validation; not a CFI VM or call authority.

Every indexed header row must name a real, structurally parsed FDE/CIE and
exactly match its initial location. Only positive indexed extents are returned.
Zero-range indexed entries and all unindexed FDEs are checked structurally but
never contribute returned targets; no same-PC alternative FDE is substituted.
CFI instruction tails are bounded opaque bytes; no unwind rules are evaluated.

Primary format references (independent implementation, no copied source):
https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
https://github.com/gcc-mirror/gcc/blob/master/libgcc/unwind-pe.h
https://github.com/llvm/llvm-project/blob/main/llvm/lib/DebugInfo/DWARF/DWARFDebugFrame.cpp
"""
from dataclasses import dataclass
import hashlib
import struct

from nso_format import NsoError

MAX_RECORDS = 1_048_576
MAX_CIES = 4096
MAX_RECORD_BYTES = 1024 * 1024
MAX_FRAME_BYTES = 64 * 1024 * 1024
MAX_AUGMENTATION_BYTES = 65536
MAX_HEADER_PADDING = 65536
MAX_U64 = (1 << 64) - 1


@dataclass(frozen=True)
class EHFunction:
    start: int
    end: int
    fde: int
    cie: int


@dataclass(frozen=True)
class _CIE:
    offset: int
    version: int
    augmentation: str
    fde_encoding: int
    lsda_encoding: int
    personality_encoding: int
    code_alignment: int
    data_alignment: int
    return_register: int


def _require(condition, offset, reason):
    if not condition:
        raise NsoError(f'EH 0x{offset:x}: {reason}')


class _Parser:
    def __init__(self, nso, metadata):
        self.nso, self.metadata, self.raw = nso, metadata, nso.image
        self.cies = {}
        self.fdes = {}
        self.record_count = 0
        self.excluded_indexed = ()
        self.header_start = self.header_end = 0

    def _section(self, offset, size):
        _require(type(offset) is int and type(size) is int and offset >= 0 and size >= 0,
                 max(offset, 0), 'negative or invalid initialized extent')
        try:
            return self.nso.section_for(offset, size)
        except NsoError as error:
            raise NsoError(f'EH 0x{offset:x}: extent outside initialized section') from error

    def _read(self, cursor, end, spec):
        width = struct.calcsize(spec)
        _require(0 <= cursor <= end and width <= end - cursor and end <= len(self.raw),
                 cursor, 'truncated bounded field')
        return struct.unpack_from(spec, self.raw, cursor)[0], cursor + width

    def _leb(self, cursor, end, signed=False):
        start, value, shift = cursor, 0, 0
        for _ in range(10):
            byte, cursor = self._read(cursor, end, '<B')
            value |= (byte & 127) << shift
            shift += 7
            if not byte & 128:
                if signed and byte & 64:
                    value -= 1 << shift
                _require(-(1 << 63) <= value < (1 << 63) if signed else 0 <= value <= MAX_U64,
                         start, 'SLEB128 overflow' if signed else 'ULEB128 overflow')
                return value, cursor
        raise NsoError(f'EH 0x{start:x}: unterminated/overflowing LEB128')

    def _encoding(self, encoding, offset, *, data_base=None, indirect=False, omitted=False):
        if encoding == 255 and omitted:
            return
        _require(encoding != 255 and encoding & 15 in (0, 1, 2, 3, 4, 9, 10, 11, 12),
                 offset, f'unsupported DW_EH_PE format 0x{encoding:02x}')
        application = encoding & 0x70
        _require(application in (0, 0x10, 0x30), offset,
                 f'unsupported DW_EH_PE application 0x{encoding:02x}')
        _require(application != 0x30 or data_base is not None, offset,
                 'data-relative pointer needs a declared ABI base')
        _require(not encoding & 0x80 or indirect, offset, 'indirect encoding is unsupported for this field')

    def _encoded(self, cursor, end, encoding, *, data_base=None, indirect=False, scalar=False):
        self._encoding(encoding, cursor, data_base=data_base, indirect=indirect)
        at = cursor
        form = encoding & 15
        formats = {0: '<Q', 2: '<H', 3: '<I', 4: '<Q', 10: '<h', 11: '<i', 12: '<q'}
        if form in (1, 9):
            value, cursor = self._leb(cursor, end, signed=form == 9)
        else:
            value, cursor = self._read(cursor, end, formats[form])
        if not scalar and value:
            application = encoding & 0x70
            value += at if application == 0x10 else data_base if application == 0x30 else 0
        _require(0 <= value <= MAX_U64, at, 'encoded pointer/scalar overflow or negative range')
        # Personality indirection deliberately returns a bounded slot address,
        # not a resolved external personality or an executable target.
        return value, cursor

    def _personality(self, value, encoding, field):
        _require(value != 0, field, 'null personality pointer/slot')
        if not encoding & 0x80:
            self._section(value, 1)
            return
        _require(value % 8 == 0, field, 'unaligned personality indirection slot')
        self._section(value, 8)
        overlapping = [relocation for relocation in self.metadata.relocations
            if relocation.offset < value + 8 and value < relocation.offset + 8]
        _require(len(overlapping) <= 1 and all(relocation.offset == value for relocation in overlapping),
                 field, 'overlapping/nonexact personality slot relocation')
        if overlapping:
            relocation = overlapping[0]
            _require(relocation.kind in (257, 1025, 1026, 1027) and type(relocation.symbol) is int and
                0 <= relocation.symbol < len(self.metadata.symbols) and
                -(1 << 63) <= relocation.addend < (1 << 63), field, 'invalid personality slot relocation')
            if relocation.kind == 1027:
                _require(relocation.symbol == 0 and 0 <= relocation.addend <= len(self.raw),
                         field, 'invalid RELATIVE personality slot relocation')
            else:
                _require(relocation.symbol != 0, field, 'symbolic personality slot lacks symbol')
        else:
            pointer = struct.unpack_from('<Q', self.raw, value)[0]
            _require(pointer != 0, field, 'null unrelocated personality slot')
            self._section(pointer, 1)

    def _cie(self, offset, cursor, end):
        version, cursor = self._read(cursor, end, '<B')
        _require(version in (1, 3, 4), cursor - 1, f'unsupported CIE version {version}')
        stop = self.raw.find(b'\0', cursor, min(end, cursor + 33))
        _require(stop >= 0, cursor, 'unterminated/bounded CIE augmentation string')
        try:
            augmentation = self.raw[cursor:stop].decode('ascii')
        except UnicodeError as error:
            raise NsoError(f'EH 0x{cursor:x}: non-ASCII CIE augmentation') from error
        _require(not augmentation or augmentation[0] == 'z' and
            all(character in 'PLRS' for character in augmentation[1:]) and
            len(set(augmentation)) == len(augmentation), cursor, 'unsupported/duplicate CIE augmentation')
        cursor = stop + 1
        if version == 4:
            address_size, cursor = self._read(cursor, end, '<B')
            segment_size, cursor = self._read(cursor, end, '<B')
            _require(address_size == 8 and segment_size == 0, cursor - 2, 'unsupported CIE address/segment size')
        code_alignment, cursor = self._leb(cursor, end)
        data_alignment, cursor = self._leb(cursor, end, signed=True)
        return_register, cursor = self._read(cursor, end, '<B') if version == 1 else self._leb(cursor, end)
        _require(code_alignment > 0 and data_alignment != 0 and return_register <= 255,
                 offset, 'invalid CIE alignment factors/return register')
        fde_encoding, lsda_encoding, personality_encoding = 0, 255, 255
        if augmentation:
            length, cursor = self._leb(cursor, end)
            _require(length <= MAX_AUGMENTATION_BYTES and length <= end - cursor, cursor, 'CIE augmentation length outside record')
            augmentation_end = cursor + length
            for character in augmentation[1:]:
                if character == 'S':
                    continue
                encoding, cursor = self._read(cursor, augmentation_end, '<B')
                self._encoding(encoding, cursor - 1, indirect=character == 'P', omitted=character == 'L')
                if character == 'R':
                    fde_encoding = encoding
                elif character == 'L':
                    lsda_encoding = encoding
                else:
                    personality_encoding = encoding
                    field = cursor
                    value, cursor = self._encoded(cursor, augmentation_end, encoding, indirect=True)
                    self._personality(value, encoding, field)
            _require(cursor == augmentation_end, cursor, 'CIE augmentation length/fields mismatch')
        return _CIE(offset, version, augmentation, fde_encoding, lsda_encoding, personality_encoding,
                    code_alignment, data_alignment, return_register)

    def _fde(self, offset, id_field, back_reference, cursor, end):
        cie_offset = id_field - back_reference
        _require(back_reference != 0 and cie_offset in self.cies and cie_offset < offset,
                 id_field, 'FDE CIE backreference is not a preceding CIE record boundary')
        cie = self.cies[cie_offset]
        initial, cursor = self._encoded(cursor, end, cie.fde_encoding)
        extent, cursor = self._encoded(cursor, end, cie.fde_encoding & 15, scalar=True)
        text = self.nso.sections[0]
        _require(initial % 4 == extent % 4 == 0 and text.offset <= initial < text.end and
            extent <= text.end - initial, offset, 'FDE PC range outside aligned original text')
        if cie.augmentation:
            length, cursor = self._leb(cursor, end)
            _require(length <= MAX_AUGMENTATION_BYTES and length <= end - cursor,
                     cursor, 'FDE augmentation length outside record')
            augmentation_end = cursor + length
            if cie.lsda_encoding != 255:
                lsda, cursor = self._encoded(cursor, augmentation_end, cie.lsda_encoding)
                if lsda: self._section(lsda, 1)
            _require(cursor == augmentation_end, cursor, 'FDE augmentation length/fields mismatch')
        return EHFunction(initial, initial + extent, offset, cie_offset)

    def _frames(self, start):
        section = self._section(start, 4)
        limit = min(section.end, start + MAX_FRAME_BYTES)
        cursor = start
        while cursor <= limit - 4:
            offset = cursor
            _require(offset % 4 == 0, offset, 'unaligned exception-frame record')
            length, cursor = self._read(cursor, limit, '<I')
            if length == 0:
                self.frame_end = cursor
                return
            if length == 0xffffffff:
                length, cursor = self._read(cursor, limit, '<Q')
            else:
                _require(length < 0xfffffff0, offset, 'reserved initial record length')
            _require(4 <= length <= MAX_RECORD_BYTES and length <= limit - cursor,
                     offset, 'exception-frame record length outside bounded section')
            end = cursor + length
            _require(not (offset < self.header_end and self.header_start < end), offset, 'exception-frame record overlaps header')
            id_field = cursor
            identity, cursor = self._read(cursor, end, '<I')
            self.record_count += 1
            _require(self.record_count <= MAX_RECORDS + MAX_CIES, offset, 'exception-frame record count exceeds bound')
            if identity == 0:
                _require(len(self.cies) < MAX_CIES, offset, 'CIE count exceeds bound')
                self.cies[offset] = self._cie(offset, cursor, end)
            else:
                _require(len(self.fdes) < MAX_RECORDS, offset, 'FDE count exceeds bound')
                self.fdes[offset] = self._fde(offset, id_field, identity, cursor, end)
            cursor = end
        raise NsoError(f'EH 0x{cursor:x}: missing bounded exception-frame terminator')

    def parse(self):
        raw, mod0 = self.raw, self.metadata.mod0
        self._section(4, 4); self._section(mod0, 28)
        _require(struct.unpack_from('<I', raw, 4)[0] == mod0 and raw[mod0:mod0+4] == b'MOD0',
                 mod0, 'metadata MOD0 identity mismatch')
        relative_start, relative_end = struct.unpack_from('<ii', raw, mod0 + 16)
        start, end = mod0 + relative_start, mod0 + relative_end
        _require(start <= end, mod0 + 16, 'reversed MOD0 EH header extent')
        if start == end:
            _require(not self.metadata.eh_starts, start, 'missing header has substituted EH entries')
            return ()
        self._section(start, end - start)
        self.header_start, self.header_end = start, end
        _require(end - start >= 4 and raw[start] == 1, start, 'unsupported/truncated EH header version')
        pointer_encoding, count_encoding, table_encoding = raw[start+1:start+4]
        frame, cursor = self._encoded(start + 4, end, pointer_encoding, data_base=start)
        _require(count_encoding & 0xf0 == 0, start + 2, 'EH count must use an absolute scalar encoding')
        count, cursor = self._encoded(cursor, end, count_encoding, scalar=True)
        _require(count <= MAX_RECORDS and count <= (end - cursor) // 2, cursor, 'EH table count exceeds bounded header')
        self._encoding(table_encoding, start + 3, data_base=start)
        rows, previous = [], -1
        text = self.nso.sections[0]
        for _ in range(count):
            row_at = cursor
            initial, cursor = self._encoded(cursor, end, table_encoding, data_base=start)
            fde, cursor = self._encoded(cursor, end, table_encoding, data_base=start)
            _require(initial % 4 == 0 and text.offset <= initial < text.end and initial > previous,
                     row_at, 'EH header PC entries outside text, unordered or duplicated')
            _require(fde % 4 == 0, row_at, 'unaligned EH header FDE pointer')
            rows.append((initial, fde, row_at)); previous = initial
        # Linkers may reserve table slots before removing duplicate/empty FDEs.
        # Only bounded zero fill is padding; it cannot add indexed targets.
        _require(end - cursor <= MAX_HEADER_PADDING and not any(raw[cursor:end]),
                 cursor, 'unexpected EH header trailing bytes')
        _require(tuple(row[0] for row in rows) == tuple(self.metadata.eh_starts), start, 'EH header differs from parsed metadata entries')
        self._frames(frame)
        result, excluded, seen_fdes = [], [], set()
        for initial, offset, row_at in rows:
            record = self.fdes.get(offset)
            _require(record is not None and offset not in seen_fdes, row_at, 'EH index does not name a unique actual FDE record boundary')
            _require(record.start == initial, offset, 'indexed FDE initial_location mismatch')
            seen_fdes.add(offset)
            if record.end == record.start:
                excluded.append(record)
            else:
                result.append(record)
        self.excluded_indexed = tuple(excluded)
        return tuple(result)


def validated_eh_functions(nso, metadata):
    """Return sorted immutable positive indexed FDE extents; malformed data raises.

    Legitimate zero-range index entries and every unindexed FDE are excluded.
    Consumers must independently prove CFG/code coverage and rewrite safety.
    The resulting entries do not authorize arbitrary runtime indirect calls.
    """
    return _Parser(nso, metadata).parse()


def eh_target_set_sha256(records):
    """Canonical target-only digest agreed with the forest verifier."""
    digest = hashlib.sha256(); previous = -1
    for record in records:
        _require(type(record.start) is int and previous < record.start <= MAX_U64 and record.start % 4 == 0,
                 max(previous, 0), 'target digest requires sorted unique aligned entries')
        digest.update(struct.pack('<Q', record.start)); previous = record.start
    return digest.hexdigest()
