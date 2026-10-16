"""Fail-closed profile site planning, separate from unprofiled ABI rewriting."""
import struct

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm64_const import ARM64_OP_IMM


def parameter_layout():
    # A single checked native declaration owns these constants; Python does not
    # infer C++ structure layout or use Bionic's private TLS.
    from pathlib import Path
    import re
    header = Path(__file__).resolve().parents[1] / 'platform/android/guest_parameter_layout.h'
    values = dict(re.findall(r'^#define (DM_GUEST_PARAMETER_\w+)\s+(\d+)\s*$', header.read_text(), re.M))
    return tuple(int(values['DM_GUEST_PARAMETER_' + name]) for name in ('BASE', 'STRIDE', 'COUNT'))


def plan(profile, by_pc, kinds, roots, api):
    observations, parameters, endpoints = {}, {}, set()
    if profile is None:
        return observations, parameters
    if profile.target != 'android-arm64':
        raise api.RewriteError('unsupported profile target')

    def integer(value, lower, upper, description):
        if type(value) is not int or not lower <= value <= upper:
            raise api.RewriteError('invalid ' + description)

    def endpoint(pc, expected):
        integer(pc, 0, len(by_pc) * 4 + max(by_pc), 'profile offset')
        integer(expected, 0, 0xFFFFFFFF, 'profile word')
        if pc not in by_pc or pc in endpoints:
            raise api.RewriteError('profile endpoint outside code or overlapping')
        ins = by_pc[pc]
        if struct.unpack('<I', ins.bytes)[0] != expected:
            raise api.RewriteError(f'0x{pc:x}: profile original word mismatch')
        if kinds[pc] is not None:
            raise api.RewriteError(f'0x{pc:x}: profile conflicts with ABI rewrite')
        endpoints.add(pc)
        return ins

    ids = set()
    for item in profile.observations:
        integer(item.id, 1, 0xFFFFFFFF, 'observation ID')
        if item.id in ids:
            raise api.RewriteError('duplicate observation ID')
        ids.add(item.id)
        ins = endpoint(item.offset, item.word)
        # OBS6 is the sole declared midfunction exception. The importer binds
        # its exact offset/word to an independently registered full identity.
        if item.offset not in roots and item.id != 6:
            raise api.RewriteError('observation requires function entry')
        if (api.is_fatal_instruction(ins) or any(ins.group(g) for g in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)) or
                ins.mnemonic in ('adr', 'adrp', 'prfm', 'svc', 'brk', 'hlt', 'eret', 'drps') or
                ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES or
                any(op.type == ARM64_OP_IMM for op in ins.operands) and ins.mnemonic.startswith('ldr')):
            raise api.RewriteError('unsupported observation displaced instruction')
        observations[item.offset] = item

    for item in profile.parameters:
        integer(item.destination, 0, 30, 'parameter destination')
        integer(item.slot, 0, 3, 'parameter slot')
        integer(item.flags, 0, 1, 'parameter flags')
        if item.destination == 18:
            raise api.RewriteError('virtual x18 parameter destination unsupported')
        if item.a >= item.b:
            raise api.RewriteError('parameter B must follow A')
        for pc, expected in ((item.a, item.word_a), (item.b, item.word_b)):
            ins = endpoint(pc, expected)
            value = struct.unpack('<I', ins.bytes)[0]
            # Exactly MOVZ + MOVK, matching the original constant declarations.
            opcode = value & 0x7F800000
            if (opcode != (0x52800000 if pc == item.a else 0x72800000) or
                    value & 31 != item.destination or (value >> 31) != (1 - item.flags)):
                raise api.RewriteError('parameter constant encoding/width mismatch')
        parameters[item.a] = item

    for item in profile.parameters:
        interior = set(range(item.a + 4, item.b + 4, 4))
        if interior & roots:
            raise api.RewriteError('parameter interior entry')
        for pc in range(item.a + 4, item.b, 4):
            if pc not in by_pc:
                raise api.RewriteError('parameter interval contains unproven code')
            ins = by_pc[pc]
            if (api.is_fatal_instruction(ins) or item.destination in api.registers(ins) or
                    any(ins.group(g) for g in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)) or
                    kinds[pc] is not None or pc in observations):
                raise api.RewriteError('parameter intermediate register/control hazard')
            # Keep native provenance validation independent and bounded: only
            # position-independent constant/ALU words are currently registered.
            if not (ins.mnemonic in ('mov', 'movk', 'movz', 'movn', 'add', 'sub', 'adds', 'subs', 'nop') and
                    not any(ins.reg_name(r) in ('sp', 'wsp') for r in ins.regs_access()[1])):
                raise api.RewriteError('unsupported parameter intermediate instruction')
        for ins in by_pc.values():
            if ins.mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or ins.mnemonic.startswith('b.'):
                target = ins.operands[-1].imm
                if target in interior:
                    raise api.RewriteError('parameter interior branch entry')
    return observations, parameters
