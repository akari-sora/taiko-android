"""Select source-pinned SDK layouts, never execution authority.

The importer must still prove every original LR/SP/control-flow path and reject
all direct, address-materialized and independent interior entries. This selector
only identifies bounded inline-data and dormant-assembly layouts for those
complete proofs; entry, ABI and callback authority remain separate.
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


@dataclass(frozen=True)
class SdkProfilerLayout:
    source_sha256: str
    build_id: str
    start: int
    end: int
    body_sha256: str
    plt_start: int
    got_start: int
    hook_start: int
    hook_names_sha256: str


_TAIKO_PROFILER = SdkProfilerLayout(
    source_sha256=SDK_SHA256, build_id=SDK_BUILD_ID,
    start=0x3905E8, end=0x390DCC,
    body_sha256='244b24f47e89fd0dc6f253406fbdfe3f2a2918cff4600a00c74e05b74c1faa6d',
    plt_start=0x5CA680, got_start=0xCE0610, hook_start=0x3903F0,
    hook_names_sha256='75f455c16b08f779ba8c3281bf5d00d23c853fc45f2dbea50142361bd3a0c6c8')


def select_sdk_profiler_layout(nso):
    """Identify one complete bank for analysis; all entry/ABI checks remain required."""
    if nso.source_sha256.hex() != SDK_SHA256:
        return None
    layout = _TAIKO_PROFILER
    def require(condition, reason):
        if not condition:
            raise ValueError('SDK dormant profiler bank: ' + reason)
    require(nso.build_id.hex() == layout.build_id, 'build identity changed')
    text, data = nso.sections[0], nso.sections[2]
    require(text.offset <= layout.hook_start and layout.hook_start + 31 * 16 + 4 <= layout.start - 4 and
            layout.start - 4 < layout.end <= text.end and layout.end <= len(nso.image) and
            text.offset <= layout.plt_start and layout.plt_start + 32 * 16 <= text.end and
            layout.plt_start + 32 * 16 <= len(nso.image) and
            data.offset <= layout.got_start and layout.got_start + 32 * 8 <= data.end and
            layout.got_start + 32 * 8 <= len(nso.image), 'compiled range outside original sections')
    require(nso.image[layout.start - 4:layout.start] == bytes.fromhex('c0035fd6'), 'typed Enable marker changed')
    require(hashlib.sha256(nso.image[layout.start:layout.end]).hexdigest() == layout.body_sha256,
            'body identity changed')
    return layout
