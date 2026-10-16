"""Compiled source identity for one Taiko virtual-register callback contract.

This module never accepts a caller-supplied target list or grants generic EH/RX
membership. An unmatched input retains the ordinary strict import policy.
"""
import struct

MAIN_SHA256 = 'f1313fe0d6cd4a024e53d8a283434448bacea453b02f37b75b18bfe281d0fcff'
MAIN_BUILD_ID = '4541b79257635ce79105b3ba59e4808500000000000000000000000000000000'
CALL_OFFSET, TARGET_OFFSET = 0xDBC7A4, 0xDB9050
SLOT_OFFSET = 0x5341560

# Original words corroborate the incoming object, virtual-register producer,
# non-null gate, mutable callback setter, slot reader/clearer and target entry.
# Full NSO source SHA/build identity is required before inspecting these words.
WORD_CHECKS = (
    (0xDBB6B8, (0xAA0003F3,)),  # MOV X19,X0: callback object's incoming base.
    (0xDBBDA4, (0xF9422A72, 0xBD01E661, 0xB4000232)),  # LDR X18,[X19,#450]; CBZ.
    (CALL_OFFSET, (0xD63F0240,)),
    (0xDB9A20, (0xF100003F, 0x1A9F07E8, 0xF9022801, 0xB9047408, 0xD65F03C0)),
    (0xED0560, (0xB0022381, 0xF942B021, 0x17FBA52E)),  # Slot -> setter tail call.
    (0xED0570, (0xAA1F03E1, 0x17FBA52B)),  # Same setter can clear the field.
    (TARGET_OFFSET, (0xD10103FF, 0x6D0123E9, 0xA9027BFD, 0x910083FD)),
)
EH_ENTRIES = (TARGET_OFFSET, 0xDB9A20, 0xDBB640, 0xED0560, 0xED0570)


def select_checked_calls(nso, metadata):
    if nso.source_sha256.hex() != MAIN_SHA256 or nso.build_id.hex() != MAIN_BUILD_ID:
        return ()
    def require(condition, reason):
        if not condition:
            raise ValueError(f'pinned Taiko checked call: {reason}')

    text, data = nso.sections[0], nso.sections[2]
    require(all(text.offset <= offset and offset + len(words) * 4 <= text.end
                for offset, words in WORD_CHECKS), 'evidence outside original text')
    for offset, words in WORD_CHECKS:
        expected = struct.pack('<' + 'I' * len(words), *words)
        require(nso.image[offset:offset + len(expected)] == expected, f'original words changed at 0x{offset:x}')
    require(set(EH_ENTRIES) <= set(metadata.eh_starts), 'required EH entry missing')
    require(data.offset <= SLOT_OFFSET and SLOT_OFFSET + 8 <= data.end,
            'callback relocation slot outside initialized writable data')
    require(nso.image[SLOT_OFFSET:SLOT_OFFSET + 8] == bytes(8), 'original callback slot bytes changed')
    overlapping = [relocation for relocation in metadata.relocations
                   if relocation.offset < SLOT_OFFSET + 8 and SLOT_OFFSET < relocation.offset + 8]
    require(len(overlapping) == 1, 'callback slot requires one exact relocation')
    relocation = overlapping[0]
    require((relocation.offset, relocation.kind, relocation.symbol, relocation.addend) ==
            (SLOT_OFFSET, 1027, 0, TARGET_OFFSET), 'callback RELATIVE target changed')
    return (dict(offset=CALL_OFFSET, target=TARGET_OFFSET, source_word=0xD63F0240,
                 rule='versioned-taiko-main-mutable-callback-v1',
                 source_sha256=MAIN_SHA256, build_id=MAIN_BUILD_ID,
                 target_policy='runtime-exact-equality; null/unknown/interior targets trap after restoration',
                 evidence=dict(producer_offset=0xDBBDA4, object_base_offset=0xDBB6B8,
                               nonnull_gate_offset=0xDBBDAC, caller_eh_entry=0xDBB640,
                               setter_offset=0xDB9A20, setter_wrapper_offset=0xED0560,
                               clear_wrapper_offset=0xED0570, slot_offset=SLOT_OFFSET,
                               relocation_kind=1027, target_eh_entry=TARGET_OFFSET)),)
