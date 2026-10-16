"""Compiled source identity for one Taiko virtual-register callback contract.

This module never accepts a caller-supplied target list or grants generic EH/RX
membership. An unmatched input retains the ordinary strict import policy.
"""
import hashlib
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
FOREST_CALL_OFFSET = 0x292702C
FOREST_WORD_CHECKS = (
    (0x2927004, (0xF9400F11, 0xF9406231, 0xF9401A32, 0xF9400252,
                 0xA90427E8, 0xB90053EA, 0xA90233EB, 0xA90337EE,
                 0xA9013FF0, 0xF9401A22, 0xD63F0240)),
)
FOREST_CALLER_PINS = (
    dict(offset=0x84D7C0, source_word=0xD63F0240,
         caller_eh_start=0x84A890, caller_eh_end=0x852A78, caller_fde=0x474B0B0, caller_cie=0x41D6360,
         caller_body_sha256='8effd40fb6cd794194374b5ffade796e12b2a0ecae234fbcbc37bb6066fc1885',
         evidence_start=0x84D764, evidence_end=0x84D7C8,
         evidence_sha256='10a460b5d1c6f6c28e650c3800fd4ed20086ec723b81b112151583eef33dfde8',
         source_role='mutable-ctx-150-receiver-vptr-slot-196; runtime-domain-only; initialization/type/cross-module-unproven',
         stack_argument_bytes=0x50, stack_argument_store_count=10,
         stack_store_start=0x84D798, stack_store_end=0x84D7C0),
    dict(offset=FOREST_CALL_OFFSET, source_word=0xD63F0240,
         caller_eh_start=0x2926E60, caller_eh_end=0x2927164, caller_fde=0x4572CC0, caller_cie=0x41D6360,
         caller_body_sha256='5eeec23468d866136914f6a940793ab6f6455408b8c75c8383bb8f17489ba5ce',
         evidence_start=0x2927004, evidence_end=0x2927030,
         evidence_sha256='6ce44c15553014a6affd4c9faf6f0a656ac60a5fada7d92f817acd51f4d4f678',
         source_role='mutable-generated-function-pointer; runtime-domain-only'),
)


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


def select_checked_call_forest(nso, metadata):
    """Only these pinned callers may use the same validated EH entry set.

    This source reads a mutable generated function pointer through X17/X18;
    it is not a constant or a read-only switch. Every admitted target is an
    indexed positive-range entry validated against its actual FDE/CIE before
    original CFG discovery and ABI rewriting. Indexed zero-range and unindexed
    records grant no target authority, including same-PC alternatives.
    No external mapping/JSON selector reaches this contract.
    """
    if nso.source_sha256.hex() != MAIN_SHA256 or nso.build_id.hex() != MAIN_BUILD_ID:
        return None
    for offset, words in FOREST_WORD_CHECKS:
        expected = struct.pack('<' + 'I' * len(words), *words)
        if not (nso.sections[0].offset <= offset and offset + len(expected) <= nso.sections[0].end and
                nso.image[offset:offset + len(expected)] == expected):
            raise ValueError(f'pinned Taiko call forest: original pointer chain changed at 0x{offset:x}')
    # Keep the parser import local: unrelated modules never acquire its authority.
    from nso_eh import validated_eh_functions, eh_target_set_sha256
    records = validated_eh_functions(nso, metadata)  # Unknown/malformed CIE/FDE propagates.
    targets = tuple(record.start for record in records)
    if (not targets or any(type(pc) is not int or pc <= 0 or pc % 4 or pc >= nso.sections[0].end for pc in targets)
            or any(a >= b for a, b in zip(targets, targets[1:]))):
        raise ValueError('pinned Taiko call forest: invalid sorted EH entry set')
    callers=[]
    for pin in FOREST_CALLER_PINS:
        start,end=pin['caller_eh_start'],pin['caller_eh_end']
        if not any((record.start,record.end,record.fde,record.cie)==
                   (start,end,pin['caller_fde'],pin['caller_cie']) for record in records):
            raise ValueError('pinned Taiko call forest: caller FDE range changed')
        if (not nso.sections[0].offset<=start<=pin['evidence_start']<=pin['offset']<pin['evidence_end']<=end<=nso.sections[0].end or
                hashlib.sha256(nso.image[start:end]).hexdigest()!=pin['caller_body_sha256'] or
                hashlib.sha256(nso.image[pin['evidence_start']:pin['evidence_end']]).hexdigest()!=pin['evidence_sha256'] or
                nso.image[pin['offset']:pin['offset']+4]!=struct.pack('<I',pin['source_word'])):
            raise ValueError('pinned Taiko call forest: caller body/evidence changed')
        descriptor=dict(pin)
        if 'stack_store_start' in pin:
            descriptor['stack_store_sha256']=hashlib.sha256(nso.image[pin['stack_store_start']:pin['stack_store_end']]).hexdigest()
        callers.append(descriptor)
    return dict(callers=callers,
                rule='versioned-taiko-main-eh-callback-forest-v2',
                source_sha256=MAIN_SHA256, build_id=MAIN_BUILD_ID,
                targets=targets, target_count=len(targets), target_sha256=eh_target_set_sha256(records),
                target_policy='runtime-exact-positive-indexed-EH-entry; zero-range/unindexed/unknown/interior/null/cross-module trap')
