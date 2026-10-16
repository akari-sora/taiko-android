"""Select one source-pinned SDK inline-data layout, never execution authority.

The importer must still prove every original LR/SP/control-flow path and reject
all direct, address-materialized and independent interior entries. This selector
only identifies where that existing complete proof may inspect literal data.
"""
from dataclasses import dataclass
import hashlib
import struct

SDK_SHA256 = '2a89fa1c0e677710e89ed29b578162affef530a0c9b8c93cda15d50a57a20d28'
SDK_BUILD_ID = '357efc198e728cb5d55265aff304f03cfc9cc0e3000000000000000000000000'


@dataclass(frozen=True)
class SdkInlineLayout:
    source_sha256: str
    build_id: str
    function_start: int
    function_end: int
    body_sha256: str
    target_bss: int

    @property
    def call_offset(self):
        return self.function_start + 0x70

    @property
    def literal_start(self):
        return self.function_start + 0x74

    @property
    def reader_offset(self):
        return self.function_start + 0x78

    @property
    def restore_offsets(self):
        return tuple(self.function_start + offset for offset in (0xDC, 0xE0, 0xE4))

    @property
    def return_offsets(self):
        return (self.function_start + 0xE8,)


_TAIKO_LAYOUT = SdkInlineLayout(
    source_sha256=SDK_SHA256, build_id=SDK_BUILD_ID,
    function_start=0x380758, function_end=0x38084C,
    body_sha256='75a9b6b577e7b8e150ea8b2b0de5adc9355fbea9bec9ecf40cbd4757e7f32c4e',
    target_bss=0xD6E580)


def _verify_layout(nso, layout):
    """Check identity/bounds; accepting a layout here grants no import exemption."""
    start, end = layout.function_start, layout.function_end
    text, data = nso.sections[0], nso.sections[2]
    if (start % 4 or end - start != 244 or
            not text.offset <= start < end <= text.end or end > len(nso.image)):
        return None
    body = bytearray(nso.image[start:end])
    # Only these four bytes are data. Every other original byte is pinned,
    # including branch immediates, saved caller LR, reader and all exits.
    body[0x74:0x78] = bytes(4)
    if hashlib.sha256(body).hexdigest() != layout.body_sha256:
        return None
    if len(nso.image) != data.end + nso.bss_size:
        raise ValueError('SDK inline LR literal BSS extent does not match its image')
    target = layout.literal_start + struct.unpack_from('<i', nso.image, layout.literal_start)[0]
    if target != layout.target_bss or not data.end <= target <= len(nso.image) - 28:
        raise ValueError('SDK inline LR literal target is outside its verified BSS object')
    return layout


def select_sdk_inline_layout(nso):
    """Select only the compiled Taiko SDK identity; caller layouts are forbidden."""
    if nso.source_sha256.hex() != SDK_SHA256 or nso.build_id.hex() != SDK_BUILD_ID:
        return None
    return _verify_layout(nso, _TAIKO_LAYOUT)
