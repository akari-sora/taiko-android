#!/usr/bin/env python3
"""Prepare ordered, locally supplied ExeFS NSOs for Android guest ABI v1.

Usage: android_import.py INPUT_DIRECTORY OUTPUT_DIRECTORY --modules main sdk
Unsupported metadata/control flow fails closed and is recorded in import.json.
"""
import argparse
from bisect import bisect_left
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import re
import struct

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG, ARM64_REG_X0
from android_rewrite import (ABI, INDIRECT_HOST, FatalWord, RewriteError, rewrite, site_kind,
                             indirect_register, is_fatal_word, is_fatal_instruction, stack_check_operation, has18,
                             byte_jump_table,halfword_jump_table,readonly_guest_table,x18_jump_table)
from nso_format import NsoError, parse_nso, parse_metadata
from android_profiles import resolve_profile
from android_instruction import Instruction

MAGIC = b'DMAMOD01'
HEADER_SIZE = 320
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.detail = True
MODULE_NAME = re.compile(r'[A-Za-z0-9_-]{1,15}\Z')
MAX_CALLBACK_ROOTS = 1_048_576
MAX_SP_ADJUSTMENT_BYTES = 1_048_576


class ImportError(ValueError):
    def __init__(self, message, *, rejected_indirect_sites=(), uncovered_window=None):
        super().__init__(message)
        self.rejected_indirect_sites = tuple(rejected_indirect_sites)
        self.uncovered_window=uncovered_window


def align(value, alignment):
    return (value + alignment - 1) & -alignment


def _literal_overlaps_code(instructions,start,end):
    """Instruction offsets are four-aligned; literal bounds are half-open."""
    return any(pc in instructions for pc in range((start+3)&~3,end,4))


def _sdk_inline_lr_literal(nso, metadata, roots):
    """The versioned SDK assembly helper consumes BL's LR as four data bytes.

    Its complete nonliteral body identity bounds this proof. Independently
    walk every original return path with saved caller LR/SP, and exclude any
    external/direct/address root that could bypass that save. No generic
    undecodable word or nonreturn call receives this exemption.
    """
    if nso.source_sha256.hex()!='1c9f198a91c0bcfee5cf8f5b53fb941895e91334dfb766ce79fc68576797f017':
        return None
    start,end,call,literal,reader=0x352658,0x35274C,0x3526C8,0x3526CC,0x3526D0
    body=bytearray(nso.image[start:end])
    if len(body)!=244:
        return None
    body[literal-start:literal-start+4]=bytes(4)
    identity=hashlib.sha256(body).hexdigest()
    if identity!='023312f9ac1c83766f3ac96df86713179a5aaaf882ed5464d2716d4afcbc3624':
        return None
    target=literal+struct.unpack_from('<i',nso.image,literal)[0]
    if target!=0xCFF508 or not nso.sections[2].end<=target<=len(nso.image)-28:
        raise ImportError('SDK inline LR literal target is outside its verified BSS object')
    if any(start<pc<end for pc in roots) or any(a<literal+4 and literal<b for a,b in metadata.protected):
        raise ImportError('SDK inline LR helper has a metadata/interior entry')
    def signed(value,bits):
        return value-(1<<bits) if value&(1<<(bits-1)) else value
    for pc in range(0,nso.sections[0].end,4):
        w=struct.unpack_from('<I',nso.image,pc)[0];destination=None
        if w&0x7C000000==0x14000000:
            destination=pc+4*signed(w&0x3FFFFFF,26)
        elif w&0xFF000010==0x54000000 or w&0x7E000000==0x34000000:
            destination=pc+4*signed(w>>5&0x7FFFF,19)
        elif w&0x7E000000==0x36000000:
            destination=pc+4*signed(w>>5&0x3FFF,14)
        if destination==literal or destination is not None and start<destination<end and not start<=pc<end:
            raise ImportError('SDK inline LR helper has an unproved direct/interior entry')
        if w&0x1F000000==0x10000000:
            immediate=signed((w>>5&0x7FFFF)<<2|(w>>29&3),21)
            destination=(pc&~4095)+(immediate<<12) if w>>31 else pc+immediate
            if start<destination<end:
                raise ImportError('SDK inline LR helper has a materialized interior entry')
            if w>>31 and pc+4<nso.sections[0].end:
                following=struct.unpack_from('<I',nso.image,pc+4)[0];reg=w&31
                if following&0xFFC003FF==0x91000000|(reg<<5)|reg:
                    destination+=following>>10&4095
                    if start<destination<end:
                        raise ImportError('SDK inline LR helper has a materialized interior entry')
    ops={}
    for pc in range(start,end,4):
        if pc==literal:
            continue
        decoded=list(MD.disasm(nso.image[pc:pc+4],pc,count=1))
        if len(decoded)!=1:
            raise ImportError('SDK inline LR helper contains an unknown instruction')
        ops[pc]=decoded[0]
    pending=[(start,0,'caller',False)];seen=set();returns=set()
    adjustments={start:-16,start+4:-16,start+8:-16,0x352734:16,0x352738:16,0x35273C:16}
    while pending:
        pc,sp,lr,saved=pending.pop();state=(pc,sp,lr,saved)
        if state in seen:
            continue
        seen.add(state)
        if len(seen)>128 or pc not in ops:
            raise ImportError('SDK inline LR helper escapes its finite control-flow proof')
        ins=ops[pc]
        if pc==start:
            if lr!='caller' or sp!=0:
                raise ImportError('SDK inline LR caller save is bypassed')
            saved=True
        sp+=adjustments.get(pc,0)
        if pc==0x35273C:
            if not saved or sp!=0:
                raise ImportError('SDK inline LR caller restore is bypassed')
            lr='caller'
        if ins.mnemonic=='ret':
            if sp!=0 or lr!='caller' or not saved:
                raise ImportError('SDK inline LR helper does not return to its original caller')
            returns.add(pc);continue
        if pc==call:
            if not saved or ins.mnemonic!='bl' or ins.operands[0].imm!=reader:
                raise ImportError('SDK inline LR reader call changed')
            pending.append((reader,sp,'literal',saved));continue
        if pc==reader and (lr!='literal' or ins.mnemonic!='ldr' or ins.op_str!='w0, [x30]'):
            raise ImportError('SDK inline LR data read is unproved')
        if ins.mnemonic=='blr':
            lr='normal-call-return'
        successors=[pc+4]
        if ins.group(CS_GRP_JUMP) and ins.mnemonic!='blr':
            successors=[ins.operands[-1].imm]+([] if ins.mnemonic=='b' else [pc+4])
        pending.extend((next_pc,sp,lr,saved) for next_pc in successors)
    if returns!={0x352740}:
        raise ImportError('SDK inline LR helper return set changed')
    return dict(function_start=start,function_end=end,call_offset=call,literal_start=literal,
                literal_end=literal+4,reader_offset=reader,target_bss=target,body_sha256=identity,
                return_offsets=sorted(returns),proven_instruction_offsets=sorted({state[0] for state in seen}),
                proof='versioned-sdk-saved-caller-lr-inline-signed32-v1')


def _sdk_profiler_bank(nso, metadata, roots):
    """Select this version's dormant SDK assembly for ABI audit, never entry authority.

    These unnamed wrappers follow the typed Enable RET but have no EH, symbol,
    initialization or pointer entry. Their calls use ordinary typed PLT slots.
    The proof selects every original word; SVC and SP writes still pass through
    the normal independent rewrite and checked-stack validation.
    """
    if nso.source_sha256.hex() != '1c9f198a91c0bcfee5cf8f5b53fb941895e91334dfb766ce79fc68576797f017':
        return None
    start, end = 0x362698, 0x362E7C
    def require(condition, message):
        if not condition:
            raise ImportError('SDK dormant profiler bank: ' + message)
    require(nso.build_id.hex() == '2d369d9999e3e10e665106f840ffff9bdaa0bb8e000000000000000000000000', 'build identity changed')
    require(end <= nso.sections[0].end, 'range outside text')
    identity = hashlib.sha256(nso.image[start:end]).hexdigest()
    require(identity == 'c613bdd0ed8165e4b8a84e8471e39ad7ef07f0ce8993146fa512191b92e548d1', 'body identity changed')
    marker = [s for s in metadata.symbols if s.name == '_ZN2nn8profiler12svcIntercept6EnableEv']
    require(len(marker) == 1 and (marker[0].value, marker[0].size, marker[0].binding, marker[0].kind, marker[0].section) ==
            (start - 4, 4, 1, 2, 2) and nso.image[start-4:start] == bytes.fromhex('c0035fd6'), 'typed Enable marker changed')
    require(not any(start <= pc < end for pc in (*roots, *metadata.init_addresses, *metadata.eh_starts)), 'bank acquired an executable metadata entry')
    require(not any(start < b and a < end for a, b in metadata.protected), 'bank overlaps metadata')
    require(not any(s.section not in (0, 0xFFF1) and start <= s.value < end for s in metadata.symbols), 'bank acquired a defined symbol')
    require(not any(start <= r.offset < end or r.kind in (257, 1027) and start <= r.addend < end
                    for r in metadata.relocations), 'bank acquired a relocation/pointer entry')
    names = ('SleepThread', 'SignalEvent', 'ClearEvent', 'CloseHandle', 'ResetSignal', 'WaitSynchronization',
             'ArbitrateLock', 'ArbitrateUnlock', 'WaitProcessWideKeyAtomic', 'SignalProcessWideKey',
             'SendSyncRequest', 'SendSyncRequestWithUserBuffer', 'WaitForAddress', 'SignalToAddress',
             'ReplyAndReceive', 'ReplyAndReceiveWithUserBuffer')
    ids = (0x0B, 0x11, 0x12, 0x16, 0x17, 0x18, 0x1A, 0x1B, 0x1C, 0x1D, 0x21, 0x22, 0x34, 0x35, 0x43, 0x44)
    save = (0xD10143FF, 0xA90007E0, 0xA9010FE2, 0xA90217E4, 0xA9031FE6, 0xA9047BFD, 0x910103FD)
    restore = (0xA94007E0, 0xA9410FE2, 0xA94217E4, 0xA9431FE6, 0xA9447BFD, 0x910143FF)
    relocations = {r.offset: r for r in metadata.relocations}
    entries, svc_offsets, sp_offsets, calls, hook_names = [], [], [], [], []
    cursor = start
    for index, (name, svc) in enumerate(zip(names, ids)):
        entries.append(cursor)
        expected = list(save) + [None] + list(restore) + [0xD4000001 | svc << 5] + list(save)
        if svc in (0x18, 0x43, 0x44):
            expected += [0xB81F0FE1, 0x910003E1, None, 0x910043FF]
        else:
            expected += [None]
        expected += list(restore) + [0xD503201F, 0xD65F03C0]
        phase = 0
        for relative, word in enumerate(expected):
            pc = cursor + relative * 4
            actual = struct.unpack_from('<I', nso.image, pc)[0]
            if word is None:
                plt = 0x582E70 + (2 * index + phase) * 16
                require(actual == 0x94000000 | (((plt - pc) // 4) & 0x3FFFFFF), 'wrapper PLT call changed')
                got = 0xC71248 + (2 * index + phase) * 8
                plt_words = struct.unpack_from('<4I', nso.image, plt)
                page_delta = ((got & ~4095) - (plt & ~4095)) // 4096
                adrp = 0x90000010 | (page_delta & 3) << 29 | ((page_delta >> 2) & 0x7FFFF) << 5
                require(plt_words == (adrp, 0xF9400211 | ((got & 4095) // 8) << 10,
                                     0x91000210 | (got & 4095) << 10, 0xD61F0220), 'PLT structure changed')
                relocation = relocations.get(got)
                require(relocation is not None and relocation.kind == 1026 and relocation.addend == 0 and
                        0 <= relocation.symbol < len(metadata.symbols), 'typed PLT relocation changed')
                symbol = metadata.symbols[relocation.symbol]
                hook = name + ('InterceptEnter' if phase == 0 else 'InterceptExit')
                require(symbol.name.startswith('_ZN2nn8profiler' + str(len(hook)) + hook + 'E') and
                        (symbol.value, symbol.size, symbol.binding, symbol.kind, symbol.section) ==
                        (0x3624A0 + (2 * index + phase) * 16, 4, 2, 2, 2) and
                        nso.image[symbol.value:symbol.value+4] == bytes.fromhex('c0035fd6'), 'typed profiler hook changed')
                hook_names.append(symbol.name)
                calls.append(pc)
                phase += 1
            else:
                require(actual == word, 'wrapper instruction changed')
            decoded = list(MD.disasm(nso.image[pc:pc+4], pc, count=1))
            require(len(decoded) == 1, 'undecodable wrapper word')
            if decoded[0].mnemonic == 'svc':
                svc_offsets.append(pc)
            if 'sp' in {MD.reg_name(reg) for reg in decoded[0].regs_access()[1]}:
                require(stack_check_operation(actual) is not None, 'unadmitted SP writer')
                sp_offsets.append(pc)
        cursor += 4 * len(expected)
    require(cursor == end and len(svc_offsets) == 16 and len(calls) == 32, 'finite wrapper geometry changed')
    require(hashlib.sha256('\n'.join(hook_names).encode('utf-8')).hexdigest() ==
            '75f455c16b08f779ba8c3281bf5d00d23c853fc45f2dbea50142361bd3a0c6c8', 'complete typed hook signatures changed')
    # The full source pin bounds this scan. Refuse new direct or materialized
    # entries rather than silently promoting the selected assembly to callbacks.
    def signed(value, bits):
        return value - (1 << bits) if value & (1 << (bits - 1)) else value
    for pc in range(0, nso.sections[0].end, 4):
        if start <= pc < end:
            continue
        word = struct.unpack_from('<I', nso.image, pc)[0]
        target = None
        if word & 0x7C000000 == 0x14000000:
            target = pc + 4 * signed(word & 0x3FFFFFF, 26)
        elif word & 0xFF000010 == 0x54000000 or word & 0x7E000000 == 0x34000000:
            target = pc + 4 * signed(word >> 5 & 0x7FFFF, 19)
        elif word & 0x7E000000 == 0x36000000:
            target = pc + 4 * signed(word >> 5 & 0x3FFF, 14)
        require(target is None or not start <= target < end, 'external direct entry')
        if word & 0x1F000000 == 0x10000000:
            immediate = signed((word >> 5 & 0x7FFFF) << 2 | (word >> 29 & 3), 21)
            target = (pc & ~4095) + (immediate << 12) if word >> 31 else pc + immediate
            require(not start <= target < end, 'materialized bank entry')
            if word >> 31 and pc + 4 < nso.sections[0].end:
                following = struct.unpack_from('<I', nso.image, pc+4)[0]
                reg = word & 31
                if following & 0xFFC003FF == 0x91000000 | reg << 5 | reg:
                    require(not start <= target + (following >> 10 & 4095) < end, 'materialized bank entry')
    # Also check initialized four-aligned pointer values; the exact source pin
    # bounds this versioned proof, rather than generalizing pointer alignment.
    for section in nso.sections:
        for pc in range(section.offset, section.end - 7, 4):
            require(not start <= struct.unpack_from('<Q', nso.image, pc)[0] < end, 'initialized bank pointer')
    return dict(proof='versioned-sdk-dormant-profiler-assembly-v1', start=start, end=end,
                body_sha256=identity, analysis_entries=entries, svc_offsets=svc_offsets,
                checked_sp_offsets=sp_offsets, call_offsets=calls, runtime_entry_authority=False,
                callback_authority=False, original_execution_status='NOT_RUN')


def discover_code(nso, metadata, *, indirect_policy='strict', checked_stack=False):
    """Reachable CFG from validated metadata, with proven indirect transfers.

The strict default accepts only PC-relative constants and relocation-backed
function pointers for indirect control flow. Explicit guarded-host policy marks
unresolved plain BR/BLR sites for runtime exact-host validation; it never follows
their unknown targets as guest CFG. Each selected word is subsequently decoded
again by the independent rewrite stage.
"""
    if indirect_policy not in ('strict', 'guarded-host'):
        raise ImportError('unsupported indirect policy')
    text = nso.sections[0]
    entry, analysis_entry = 0, None
    header_end = 0
    if struct.unpack_from('<I', nso.image)[0] == 0:
        # NSOs have no general ELF entry field. This canonical module header
        # contains data, not a CRT0 function. DT_INIT supplies an analysis entry
        # only; bootstrap still resolves its independently validated symbols.
        if metadata.mod0 != 8 or nso.image[36:48] != bytes(12):
            raise ImportError('unsupported zero-entry NSO header')
        header_end = 48
        entry = metadata.dynamic.get(12)
        if (not isinstance(entry, int) or entry % 4 or not header_end <= entry <= text.end - 4 or
                any(start < entry + 4 and entry < end for start, end in metadata.protected)):
            raise ImportError('canonical NSO header requires DT_INIT outside protected header/metadata')
        if entry not in metadata.eh_starts:
            raise ImportError('canonical NSO DT_INIT requires EH entry corroboration')
        values = list(MD.disasm(nso.image[entry:entry + 4], entry, count=1))
        if len(values) != 1 or values[0].size != 4 or values[0].mnemonic == 'udf' or is_fatal_instruction(values[0]):
            raise ImportError('canonical NSO DT_INIT must name a decoded non-trap instruction')
        if not checked_stack:
            raise ImportError('canonical NSO module requires checked-stack mode before package publication')
        analysis_entry = {'offset': entry, 'basis': 'canonical-no-crt0-dt-init-eh',
                          'non_code_header': [0, header_end], 'bootstrap_authority': False}

    def protected_target(pc):
        return pc < header_end or any(start <= pc < end for start, end in metadata.protected)

    roots = {entry, *metadata.eh_starts, *metadata.init_addresses}
    extents = []
    for symbol in metadata.symbols:
        if symbol.kind == 2 and symbol.section not in (0, 0xFFF1):
            roots.add(symbol.value)
            if symbol.size:
                extents.append((symbol.value, symbol.value + symbol.size))
    for relocation in metadata.relocations:
        # RELATIVE relocates data values too. A value inside text is only a
        # possible AArch64 entry when it names a complete aligned instruction.
        # Keep every relocation; an actual indirect branch to a bad value is
        # still rejected by instruction() during target discovery.
        if (relocation.kind == 1027 and relocation.addend % 4 == 0 and
                0 <= relocation.addend <= text.end - 4 and not protected_target(relocation.addend)):
            roots.add(relocation.addend)
    relocations = {item.offset: item for item in metadata.relocations}
    inline_lr=_sdk_inline_lr_literal(nso,metadata,roots) if checked_stack else None
    literal_ranges={(inline_lr['literal_start'],inline_lr['literal_end'])} if inline_lr else set()
    profiler_bank = _sdk_profiler_bank(nso, metadata, roots) if checked_stack else None
    # Analysis-only entries select ABI-sensitive dormant code without adding
    # runtime/callback roots or claiming an original control-flow entrance.
    analysis_entries = profiler_bank['analysis_entries'] if profiler_bank else ()
    instructions, pending = {}, list(sorted(roots)) + list(analysis_entries)
    def instruction(pc):
        if pc % 4 or not 0 <= pc <= text.end - 4:
            raise ImportError(f'0x{pc:x}: control flow outside original text')
        if pc < header_end:
            raise ImportError(f'0x{pc:x}: control flow reaches non-code NSO header')
        if inline_lr and inline_lr['literal_start']<=pc<inline_lr['literal_end']:
            raise ImportError(f'0x{pc:x}: control flow reaches verified literal data')
        if any(start < pc + 4 and pc < end for start, end in metadata.protected):
            raise ImportError(f'0x{pc:x}: control flow reaches MOD0/dynamic metadata')
        if is_fatal_word(struct.unpack_from('<I', nso.image, pc)[0]):
            return FatalWord(pc,original_word=struct.unpack_from('<I',nso.image,pc)[0])
        values = list(MD.disasm(nso.image[pc:pc + 4], pc, count=1))
        if len(values) != 1 or values[0].size != 4:
            raise ImportError(f'0x{pc:x}: reachable instruction cannot be decoded')
        return Instruction(values[0])
    # Discover direct flow before proving indirect registers, so predecessor
    # instructions are available regardless of symbol-table/root ordering.
    indirect, direct_targets = [], set(roots)
    def expand():
        while pending:
            pc = pending.pop()
            if pc in instructions:
                continue
            ins = instruction(pc)
            instructions[pc] = ins
            mnemonic = ins.mnemonic
            if is_fatal_instruction(ins):
                continue  # Preserve the faulting word; it has no normal successor.
            if ins.group(CS_GRP_RET):
                if ins.op_str not in ('', 'x30'):
                    raise ImportError(f'0x{pc:x}: unsupported indirect return {ins.op_str}')
                continue
            if mnemonic in ('br', 'blr'):
                indirect.append(ins)
                if mnemonic == 'blr':
                    pending.append(pc + 4)
                continue
            if ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL):
                if not ins.operands or ins.operands[-1].type != ARM64_OP_IMM:
                    raise ImportError(f'0x{pc:x}: unsupported control flow {mnemonic}')
                target = ins.operands[-1].imm
                direct_targets.add(target)
                pending.append(target)
                if mnemonic != 'b' and not (inline_lr and pc==inline_lr['call_offset']):
                    pending.append(pc + 4)
                continue
            if mnemonic in ('hlt', 'eret', 'drps'):
                raise ImportError(f'0x{pc:x}: unsupported terminal instruction {mnemonic}')
            pending.append(pc + 4)
    expand()
    def register_key(register):
        name = MD.reg_name(register)
        return 'x' + name[1:] if name.startswith('w') else name
    clobbered_slots = set()
    def register_value(register, before, depth=0):
        if depth > 12 or before in direct_targets or MD.reg_name(register) in ('sp', 'wsp', 'xzr', 'wzr'):
            return None
        # Walk a straight-line predecessor block. Crossing a second entrance or
        # a call would make a backwards register proof path-dependent.
        for pc in range(before - 4, max(-1, before - 4 * 17), -4):
            ins = instructions.get(pc)
            if ins is None or is_fatal_instruction(ins) or ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET):
                return None
            reads, writes = ins.regs_access()
            if register_key(register) in {register_key(value) for value in writes}:
                operands = ins.operands
                if not operands or operands[0].type != ARM64_OP_REG or operands[0].reg != register:
                    return None
                if ins.mnemonic in ('adr', 'adrp') and operands[1].type == ARM64_OP_IMM:
                    return ('address', operands[1].imm)
                if ins.mnemonic in ('add', 'sub') and len(operands) == 3 and operands[1].type == ARM64_OP_REG and operands[2].type == ARM64_OP_IMM:
                    base = register_value(operands[1].reg, pc, depth + 1)
                    if base and base[0] == 'address':
                        immediate = operands[2].imm << operands[2].shift.value
                        return ('address', base[1] + immediate * (1 if ins.mnemonic == 'add' else -1))
                if ins.mnemonic == 'mov' and len(operands) == 2 and operands[1].type == ARM64_OP_REG:
                    return register_value(operands[1].reg, pc, depth + 1)
                if ins.mnemonic == 'ldr' and len(operands) == 2 and MD.reg_name(register).startswith('x'):
                    operand = operands[1]
                    if operand.type == ARM64_OP_IMM:
                        location = operand.imm
                    elif operand.type == ARM64_OP_MEM and not operand.mem.index and not ins.writeback:
                        base = register_value(operand.mem.base, pc, depth + 1)
                        if not base or base[0] != 'address':
                            return None
                        location = base[1] + operand.mem.disp
                    else:
                        return None
                    if location in clobbered_slots:
                        return None
                    r = relocations.get(location)
                    if r:
                        if r.kind == 1027 and 0 <= r.addend < text.end:
                            # A relocated byte/data address is not executable
                            # merely because its numeric value falls in text.
                            return ('code' if r.addend % 4 == 0 and r.addend <= text.end - 4
                                    else 'relocated-data', r.addend)
                        symbol = metadata.symbols[r.symbol]
                        if r.kind != 1027 and symbol.kind == 2:
                            if symbol.section == 0 and r.addend == 0:
                                return ('external', symbol.name)
                            if symbol.section != 0xFFF1 and 0 <= symbol.value + r.addend < text.end:
                                return ('code', symbol.value + r.addend)
                    return None
                return None
            if pc in direct_targets:
                return None
        return None
    address_taken_roots = set()
    memory_writes = {}
    shifted_sp_adjustments = {}
    def audit_memory_writes():
        for ins in instructions.values():
            _, written_registers = ins.regs_access()
            # Capstone 5 incorrectly reports CMP/CMN's SP source as written.
            # These aliases discard their arithmetic result into XZR/WZR.
            if ins.mnemonic not in ('cmp', 'cmn') and any(MD.reg_name(register) in ('sp', 'wsp') for register in written_registers):
                operands = ins.operands
                if checked_stack and stack_check_operation(struct.unpack('<I', ins.bytes)[0]) is None:
                    raise ImportError(f'0x{ins.address:x}: unsupported checked SP/x18 instruction')
                legacy_adjustment = (ins.mnemonic in ('add', 'sub') and len(operands) == 3
                                    and operands[0].type == ARM64_OP_REG and MD.reg_name(operands[0].reg) == 'sp'
                                    and operands[1].type == ARM64_OP_REG and MD.reg_name(operands[1].reg) == 'sp'
                                    and operands[2].type == ARM64_OP_IMM and operands[2].shift.value in (0, 12)
                                    and 0 <= operands[2].imm <= 4095)
                stack_adjustment = checked_stack or legacy_adjustment
                if legacy_adjustment:
                    adjustment = operands[2].imm << operands[2].shift.value
                    if adjustment > MAX_SP_ADJUSTMENT_BYTES:
                        raise ImportError(f'0x{ins.address:x}: unsupported SP write/pivot; immediate adjustment '
                                          f'{adjustment} exceeds {MAX_SP_ADJUSTMENT_BYTES} byte bound')
                    stack_adjustment = adjustment % 16 == 0
                    if stack_adjustment and operands[2].shift.value == 12:
                        shifted_sp_adjustments[ins.address] = adjustment
                stack_memory = next((operand.mem for operand in operands if operand.type == ARM64_OP_MEM), None)
                stack_writeback = (ins.mnemonic in ('stp', 'ldp', 'ldpsw', 'str', 'ldr') and ins.writeback
                                   and stack_memory and MD.reg_name(stack_memory.base) == 'sp'
                                   and not stack_memory.index)
                if stack_writeback:
                    adjustment = stack_memory.disp
                    if operands[-1].type == ARM64_OP_IMM:
                        adjustment = operands[-1].imm
                    stack_writeback = abs(adjustment) <= 4096 and adjustment % 16 == 0
                if not stack_adjustment and not stack_writeback:
                    raise ImportError(f'0x{ins.address:x}: unsupported SP write/pivot; stack-store provenance unproven')
            memory = next((operand.mem for operand in ins.operands if operand.type == ARM64_OP_MEM), None)
            if memory is None:
                continue
            # Capstone marks load memory operands READ|WRITE for writeback, so
            # its access bits alone do not describe memory side effects.
            name = ins.mnemonic
            pure_loads = ('ldr', 'ldur', 'ldp', 'ldnp', 'ldxr', 'ldaxr', 'ldar', 'ldapr',
                          'ldtr', 'ld1', 'ld2', 'ld3', 'ld4', 'prfm', 'prfum')
            if name.startswith(pure_loads):
                continue
            if MD.reg_name(memory.base) in ('sp', 'wsp'):
                if checked_stack:
                    if len(clobbered_slots) != len(relocations):
                        clobbered_slots.update(relocations)
                    memory_writes[ins.address] = None
                continue  # Guest stack is a separate production mapping.
            base = register_value(memory.base, ins.address)
            registers = [MD.reg_name(operand.reg) for operand in ins.operands if operand.type == ARM64_OP_REG]
            width = {'x': 8, 'w': 4, 'q': 16, 'd': 8, 's': 4, 'h': 2, 'b': 1}.get(registers[-1][:1]) if registers else None
            if name in ('strb', 'sturb', 'stlrb', 'stxrb', 'stlxrb'):
                width = 1
            elif name in ('strh', 'sturh', 'stlrh', 'stxrh', 'stlxrh'):
                width = 2
            elif name in ('stp', 'stnp', 'stxp', 'stlxp') and width:
                width *= 2
            if not name.startswith(('str', 'stur', 'stp', 'stnp', 'stlr', 'stxr', 'stlxr', 'stxp', 'stlxp')):
                width = None  # Unknown/atomic/vector effects cannot prove disjointness.
            if not base or base[0] != 'address' or memory.index or not width:
                # Only relocation keys enter this set. Once all are tainted,
                # repeated unknown stores cannot change it; still audit every
                # instruction and retain every individual write fact below.
                if len(clobbered_slots) != len(relocations):
                    clobbered_slots.update(relocations)
                memory_writes[ins.address] = None
                continue
            start, end = base[1] + memory.disp, base[1] + memory.disp + width
            memory_writes[ins.address] = (start, end)
            if len(clobbered_slots) != len(relocations):
                clobbered_slots.update(slot for slot in relocations if start < slot + 8 and slot < end)
        # An explicit pointer into writable image storage passed to an imported
        # function allows that call to mutate relocation slots. Host imports are
        # trusted to obey their ABI, but their writable pointer arguments are
        # never treated as read-only. Unknown guest stores already taint all slots.
        for ins in indirect:
            target = register_value(ins.operands[0].reg, ins.address)
            if not target or target[0] != 'external':
                continue
            for index in range(8):
                # Capstone register enums are not numerically contiguous x0..x7
                # on every supported version; locate the argument by name.
                argument = MD.reg_name(ARM64_REG_X0 + index)
                if argument != 'x' + str(index):
                    raise ImportError('unsupported Capstone argument-register numbering')
                value = register_value(ARM64_REG_X0 + index, ins.address)
                if value and value[0] == 'address' and nso.sections[2].offset <= value[1] < len(nso.image):
                    if len(clobbered_slots) != len(relocations):
                        clobbered_slots.update(relocations)
                    memory_writes[ins.address] = None
    def discover_literals():
        for ins in instructions.values():
            if ins.mnemonic not in ('ldr', 'ldrsw') or len(ins.operands) != 2 or ins.operands[1].type != ARM64_OP_IMM:
                continue
            target = ins.operands[1].imm
            register = MD.reg_name(ins.operands[0].reg)
            width = 4 if ins.mnemonic == 'ldrsw' else {'w': 4, 'x': 8, 's': 4, 'd': 8, 'q': 16}.get(register[:1])
            if width and 0 <= target < text.end:
                if target % 4 or target + width > text.end:
                    raise ImportError(f'0x{ins.address:x}: invalid text literal extent')
                literal_ranges.add((target, target + width))
        for start, end in literal_ranges:
            if _literal_overlaps_code(instructions,start,end):
                raise ImportError(f'0x{start:x}: literal data overlaps discovered code')

    def add_address_root(value):
        if not value or value[0] not in ('address', 'code') or not 0 <= value[1] < text.end:
            return
        target = value[1]
        if protected_target(target):
            # Validated structural metadata is never an executable entry.
            return
        if any(start <= target < end for start, end in literal_ranges):
            raise ImportError(f'0x{target:x}: materialized text address aliases literal data; executable/data role unproven')
        if target % 4:
            raise ImportError(f'0x{target:x}: unaligned materialized text address has unproven code/data role')
        if inline_lr and inline_lr['function_start']<target<inline_lr['function_end']:
            raise ImportError('SDK inline LR helper has an address-taken interior entry')
        # A callback can name code already reached by linear CFG discovery.
        # Record every proven entry; only decoding work is conditional.
        address_taken_roots.add(target)
        roots.add(target)
        direct_targets.add(target)
        if target not in instructions:
            pending.append(target)

    # Materialized text addresses may escape through call arguments, stores or
    # return values. Root them regardless of whether this function itself calls
    # the pointer; an external host may call it later. Ambiguous data rejects
    # rather than acquiring an executable-code exemption.
    # Proven local pointers can also discover additional non-exported functions.
    guarded_sites, proven_sites, byte_jumps, guest_tables = set(), set(), {}, {}
    def table_context():
        return tuple((pc,plan['base'],tuple(plan.get('target_values',range(plan.get('count',0)))))
                     for tables in (byte_jumps,guest_tables) for pc,plan in sorted(tables.items()))
    while True:
        # A newly expanded table can expose another ADR after this round's
        # address-root pass. Complete the existing monotonic CFG fixed point
        # before treating its not-yet-proved x18 transfer as a final failure.
        # New entrances into already decoded code also require re-proving.
        count_before = (len(instructions),len(roots),len(direct_targets),table_context())
        deferred_x18 = []
        discover_literals()
        for ins in tuple(instructions.values()):
            operands = ins.operands
            if ins.mnemonic in ('adr', 'adrp'):
                add_address_root(('address', operands[1].imm))
            elif ins.mnemonic in ('add', 'sub') and len(operands) == 3 and operands[1].type == ARM64_OP_REG and operands[2].type == ARM64_OP_IMM:
                base = register_value(operands[1].reg, ins.address)
                if base and base[0] == 'address':
                    immediate = operands[2].imm << operands[2].shift.value
                    add_address_root(('address', base[1] + immediate * (1 if ins.mnemonic == 'add' else -1)))
            elif ins.mnemonic == 'ldr' and operands[0].type == ARM64_OP_REG:
                add_address_root(register_value(operands[0].reg, ins.address + 4))
        expand()
        audit_memory_writes()
        guarded_sites.clear()
        proven_sites.clear()
        for ins in sorted(indirect,key=lambda op:op.address):
            if checked_stack and struct.unpack('<I', ins.bytes)[0] == 0xD61F0240:
                plan = x18_jump_table(ins,instructions,direct_targets,nso.image,
                                      ((nso.sections[1].offset,nso.sections[1].end),),root_entries=roots)
                if plan is None:
                    byte_jumps.pop(ins.address,None)
                    deferred_x18.append(ins.address)
                    continue  # No guessed roots and no guarded-host fallback.
                byte_jumps[ins.address] = plan
                for target_pc in (plan['base']+value*4 for value in plan.get('target_values',range(plan['count']))):
                    roots.add(target_pc)
                    direct_targets.add(target_pc)
                    if target_pc not in instructions:
                        pending.append(target_pc)
                expand()
                proven_sites.add(ins.address)
                continue
            if checked_stack:
                plan=readonly_guest_table(ins,instructions,direct_targets,nso.image,
                                               ((nso.sections[1].offset,nso.sections[1].end),),known_tables=(byte_jumps,guest_tables))
                if plan is not None:
                    guest_tables[ins.address]=plan
                    for target_pc in (plan['base']+value*4 for value in plan['target_values']):
                        roots.add(target_pc)
                        direct_targets.add(target_pc)
                        if target_pc not in instructions:
                            pending.append(target_pc)
                    expand()
                    proven_sites.add(ins.address)
                    continue
                if ins.address in guest_tables:
                    raise ImportError(f'0x{ins.address:x}: guest table proof invalidated by another entry')
            target = register_value(ins.operands[0].reg, ins.address)
            if target and target[0] == 'relocated-data':
                raise ImportError(f'0x{target[1]:x}: misaligned relocated data value used as an instruction target')
            if target and target[0] in ('address', 'code'):
                if target[1] not in instructions:
                    direct_targets.add(target[1])
                    pending.append(target[1])
                    expand()
                target = ('code', target[1])
            if target and target[0] == 'code':
                roots.add(target[1])
            if not target or (target[0] == 'code' and target[1] not in instructions):
                if indirect_policy == 'guarded-host':
                    try:
                        indirect_register(ins)
                    except RewriteError as error:
                        raise ImportError(str(error), rejected_indirect_sites=(ins.address,)) from error
                    guarded_sites.add(ins.address)
                else:
                    raise ImportError(f'0x{ins.address:x}: unsupported/unproven indirect control flow {ins.mnemonic} {ins.op_str}',
                                      rejected_indirect_sites=(ins.address,))
            else:
                proven_sites.add(ins.address)
        if (len(instructions),len(roots),len(direct_targets),table_context()) == count_before:
            if deferred_x18:
                pc=deferred_x18[0]
                raise ImportError(f'0x{pc:x}: unproven byte dispatch br x18',rejected_indirect_sites=(pc,))
            break
    discover_literals()
    # Independent whole-text audit: a missing root must never silently leave
    # native x18/TLS/SVC/timer accesses executable. Only validated metadata and
    # bounded literal data may contain these bit patterns without rewriting.
    candidates, data_candidates, fatal_offsets = [], [], []
    for pc in range(0, text.end, 4):
        is_data = pc < header_end or any(start <= pc and pc + 4 <= end for start, end in (*metadata.protected, *literal_ranges))
        # Exact known fatal words need no ABI rewrite. An unselected occurrence
        # does not acquire an entry/root or callback authority from this audit.
        if is_fatal_word(struct.unpack_from('<I', nso.image, pc)[0]):
            if nso.image[pc:pc+4]!=bytes(4):
                fatal_offsets.append(pc) # Do not enumerate unselected zero padding.
            continue
        decoded = list(MD.disasm(nso.image[pc:pc + 4], pc, count=1))
        if not decoded:
            if not is_data and nso.image[pc:pc + 4] != bytes(4):
                raise ImportError(f'0x{pc:x}: unclassified nonzero text word; executable/data role unproven')
            continue
        try:
            kind = site_kind(decoded[0])
        except RewriteError as error:
            if is_data:
                data_candidates.append(pc)
                continue
            raise ImportError(f'0x{pc:x}: unsupported potential executable system-register word: {error}') from error
        if not kind:
            continue
        if is_data:
            data_candidates.append(pc)
        elif pc not in instructions:
            # The first failure still rejects the entire import. A bounded
            # diagnostic tail lets the next iteration group actual missing
            # roles, without discovering roots or scanning the remaining text.
            end=min(text.end,pc+65536)
            window={'start':pc,'end':end,'sites':[], 'truncated':end<text.end,'stop_reason':'window-bound' if end<text.end else 'text-end'}
            for probe in range(pc,end,4):
                if (probe<header_end or probe in instructions or any(start<=probe and probe+4<=stop
                        for start,stop in (*metadata.protected,*literal_ranges))):
                    continue
                value=struct.unpack_from('<I',nso.image,probe)[0]
                if is_fatal_word(value):
                    continue
                decoded=list(MD.disasm(nso.image[probe:probe+4],probe,count=1))
                if not decoded:
                    if value:
                        window.update(truncated=True,stop_reason='unallocated-word',end=probe+4)
                        break
                    continue
                try:
                    probe_kind=site_kind(decoded[0])
                except RewriteError:
                    window.update(truncated=True,stop_reason='unsupported-system-register',end=probe+4)
                    break
                if probe_kind:
                    window['sites'].append({'offset':probe,'kind':probe_kind})
                    if len(window['sites'])==64:
                        window.update(truncated=True,stop_reason='candidate-limit',end=probe+4)
                        break
            raise ImportError(f'0x{pc:x}: uncovered rewrite candidate ({kind}); code/data role unproven',uncovered_window=window)
        else:
            candidates.append(pc)
    ranges = []
    for pc in sorted(instructions):
        if ranges and ranges[-1][1] == pc:
            ranges[-1] = (ranges[-1][0], pc + 4)
        else:
            ranges.append((pc, pc + 4))
    report = {'roots': sorted(roots), 'function_extents': sorted(extents),
                    'selected_words': len(instructions), 'proven_indirect_sites': [x.address for x in indirect if x.address in proven_sites],
                    'address_taken_roots': sorted(address_taken_roots), 'proven_literal_ranges': sorted(literal_ranges),
                    'indirect_memory_policy': 'relocation-backed targets; reject discovered overlapping/unknown-alias writes and writable-image pointers passed to imports; trusted host ABI',
                    'stack_pointer_policy': 'only bounded aligned immediate SP adjustments and SP-relative load/store writeback; arbitrary SP writes rejected',
                    'relocation_slots_clobbered_by_code': sorted(clobbered_slots),
                    'reachable_memory_writes': [{'instruction_offset': pc, 'range': memory_writes[pc]} for pc in sorted(memory_writes)],
                    'rewrite_candidate_audit': {'text_words': text.size // 4, 'selected_candidates': candidates,
                                                'verified_data_candidates': data_candidates, 'uncovered_candidates': []}}
    selected_traps = [{'offset': pc, 'word': struct.unpack('<I', ins.bytes)[0]}
                      for pc, ins in sorted(instructions.items()) if is_fatal_instruction(ins)]
    if fatal_offsets or selected_traps:
        report['preserved_fatal_words'] = selected_traps
    if analysis_entry is not None:
        report['analysis_entry'] = analysis_entry
    if inline_lr is not None:
        report['inline_lr_literals']=[inline_lr]
    if profiler_bank is not None:
        if any(profiler_bank['start'] <= pc < profiler_bank['end'] for pc in roots | direct_targets):
            raise ImportError('SDK dormant profiler bank acquired runtime entry authority')
        report['dormant_assembly_banks']=[profiler_bank]
    if shifted_sp_adjustments:
        report['stack_pointer_policy'] = (f'only 16-byte aligned SP,SP imm12 adjustments with LSL 0/12 <= {MAX_SP_ADJUSTMENT_BYTES} bytes per instruction '
                                          'and bounded SP-relative load/store writeback; arbitrary SP writes rejected; cumulative frame bounds unproven')
        report['shifted_sp_adjustments'] = [{'offset': pc, 'byte_amount': amount}
                                          for pc, amount in sorted(shifted_sp_adjustments.items())]
    if checked_stack:
        report['stack_pointer_policy'] = 'v2 immutable STACK_CHECK preflight for every admitted SP writer; active invocation bounds, alignment and headroom; SP stores conservatively taint relocation slots'
    if byte_jumps:
        report['byte_jump_tables'] = [byte_jumps[pc] for pc in sorted(byte_jumps) if 'target_values' not in byte_jumps[pc]]
        halfwords=[byte_jumps[pc] for pc in sorted(byte_jumps) if 'target_values' in byte_jumps[pc]]
        if halfwords:
            report['halfword_jump_tables']=halfwords
    if guest_tables:
        report['readonly_guest_jump_tables']=[guest_tables[pc] for pc in sorted(guest_tables)]
        report['proven_guest_indirect_sites']=sorted(guest_tables)
    if indirect_policy == 'guarded-host':
        report.update(guarded_indirect_sites=sorted(guarded_sites), rejected_indirect_sites=[], indirect_policy=indirect_policy)
        report['indirect_memory_policy'] = ('static relocation proofs invalidated by overlapping/unknown-alias writes and writable-image arguments; '
                                             'unresolved BR/BLR require exact runtime host membership')
    return ranges, report


def make_package(name, nso, metadata, image, patch_offset, package_version=1):
    if not MODULE_NAME.fullmatch(name):
        raise ImportError('module name must be 1..15 ASCII letters/digits/_/-')
    if package_version not in (1, 2) or (package_version == 1 and (image.profile is not None or any(g.kind == INDIRECT_HOST for g in image.gates))):
        raise ImportError('registered profiles and guarded transfers require explicit package version 2')
    header_size = HEADER_SIZE if package_version == 1 else 384
    header = bytearray(header_size)
    header[:8] = MAGIC if package_version == 1 else b'DMAMOD02'
    struct.pack_into('<IIII', header, 8, package_version, ABI, header_size, 1 if image.checked_stack else 0)
    section_values = tuple(value for section in nso.sections for value in (section.offset, section.size))
    struct.pack_into('<11Q', header, 24, len(image.bytes), len(nso.image), *section_values,
                     nso.bss_size, patch_offset, len(image.bytes) - patch_offset)
    if package_version == 2 and len(image.gates) != len(image.gate_provenance):
        raise ImportError('extended gates require original instruction provenance')
    gates = (b''.join(struct.pack('<QII', item.return_offset, item.kind, item.argument) for item in image.gates)
             if package_version == 1 else b''.join(struct.pack('<QQIIII', item.return_offset, origin.original_offset,
                 item.kind, item.argument, origin.original_word, origin.flags)
                 for item, origin in zip(image.gates, image.gate_provenance)))
    tables = [b''.join(struct.pack('<QII', item.offset, item.helper, 0) for item in image.fixups), gates,
              b''.join(struct.pack('<QQ', item.offset, item.trampoline) for item in image.sites)]
    offsets, cursor = [], header_size
    for index, table in enumerate(tables):
        offsets.extend((cursor, len(table) // (32 if index == 1 and package_version == 2 else 16)))
        cursor += len(table)
    if package_version == 2:
        if image.profile is not None:
            header[320:352] = image.profile.digest
            struct.pack_into('<I', header, 352, image.profile.identity_class)
        struct.pack_into('<IQQII', header, 356, 32, cursor, len(image.parameters), 40, 0)
        params = b''.join(struct.pack('<QQIIIIII', p.a, p.b, p.word_a, p.word_b,
                                     p.destination, p.slot, p.flags, 0) for p in image.parameters)
        tables.append(params)
        cursor += len(params)
    payload_offset = align(cursor, 16)
    struct.pack_into('<7Q', header, 112, payload_offset, *offsets)
    header[168:168 + len(name)] = name.encode('ascii')
    header[184:216] = nso.build_id
    header[216:248] = nso.source_sha256
    header[248:280] = hashlib.sha256(image.bytes).digest()
    struct.pack_into('<QQ', header, 280, len(metadata.symbols), metadata.string_size)
    return bytes(header) + b''.join(tables) + bytes(payload_offset - cursor) + image.bytes


def audited_callback_roots(nso, metadata, code_ranges, code_report):
    """Receipt v1 certifies exact defined STT_FUNC entries, including aliases.

    Discovery roots and selected words have already passed the independent
    rewrite decoder and all exclusive-region entry/edge checks. In particular,
    a zero-size function receives authority only for that audited entry word.
    Bound distinct entries before adding them to the receipt allocation.
    """
    text_end = nso.sections[0].end
    limit = min(MAX_CALLBACK_ROOTS, nso.sections[0].size // 4)
    roots, audited_entries = set(), code_report['roots']
    for symbol in metadata.symbols:
        if symbol.kind != 2 or symbol.section in (0, 0xFFF1):
            continue
        entry = symbol.value
        if any(bank['start'] <= entry < bank['end'] for bank in code_report.get('dormant_assembly_banks', ())):
            raise ImportError('dormant assembly analysis cannot authorize a callback')
        if entry % 4 or not 0 <= entry <= text_end - 4 or symbol.size > text_end - entry:
            raise ImportError('callback function entry/extent outside original text')
        position = bisect_left(audited_entries, entry)
        if (position == len(audited_entries) or audited_entries[position] != entry or
                not any(start <= entry and entry + 4 <= end for start, end in code_ranges)):
            raise ImportError('callback function entry lacks complete code audit')
        if entry not in roots:
            if len(roots) >= limit:
                raise ImportError('callback root count exceeds bounded limit')
            roots.add(entry)
    return sorted(roots)


def import_module(source, name, *, package_version=1, profile=None, indirect_policy='strict', callback_audit=False, checked_stack=False):
    if indirect_policy not in ('strict', 'guarded-host'):
        raise ImportError('unsupported indirect policy')
    if indirect_policy == 'guarded-host' and package_version != 2:
        raise ImportError('guarded host transfers require package version 2')
    if not isinstance(callback_audit, bool):
        raise ImportError('callback audit selection must be explicit boolean')
    if callback_audit and package_version != 2:
        raise ImportError('callback audit receipt requires package version 2')
    if not isinstance(checked_stack, bool) or (checked_stack and package_version != 2):
        raise ImportError('checked-stack mode requires explicit boolean and package version 2')
    nso = parse_nso(source)
    metadata = parse_metadata(nso)
    if package_version not in (1, 2) or (package_version == 1 and profile is not None):
        raise ImportError('profile selection requires package version 2')
    try:
        selected_profile = resolve_profile(name, nso.build_id, nso.source_sha256, profile) if profile is not None else None
    except ValueError as error:
        raise ImportError(str(error)) from error
    if 4 not in metadata.dynamic and 0x6FFFFEF5 not in metadata.dynamic:
        if metadata.dynamic[6] + len(metadata.symbols) * 24 != metadata.dynamic[5]:
            raise ImportError('hashless NSO symbol extent must be adjacent to strings for package v1 verification')
    code_ranges, code_report = discover_code(nso, metadata, indirect_policy=indirect_policy, checked_stack=checked_stack)
    patch_offset = align(len(nso.image), 16384)
    image = rewrite(nso.image, code_report.get('analysis_entry', {}).get('offset', 0), nso.sections[0].end,
                    code_ranges=code_ranges, patch_offset=patch_offset,
                    entry_offsets=code_report['roots'], profile=selected_profile,
                    indirect_policy=indirect_policy, package_version=package_version,
                    guarded_indirect_offsets=code_report.get('guarded_indirect_sites', ()), checked_stack=checked_stack,
                    readonly_ranges=((nso.sections[1].offset,nso.sections[1].end),),
                    proven_guest_indirect_offsets=code_report.get('proven_guest_indirect_sites',()))
    package = make_package(name, nso, metadata, image, patch_offset, package_version)
    report = {'name': name, 'source_sha256': nso.source_sha256.hex(), 'build_id': nso.build_id.hex(),
              'image_sha256': hashlib.sha256(image.bytes).hexdigest(), 'package_sha256': hashlib.sha256(package).hexdigest(),
              'source_size': len(source), 'original_image_size': len(nso.image), 'package_size': len(package),
              'compression_flags': nso.flags & 7, 'sections': [asdict(x) for x in nso.sections],
              'bss_size': nso.bss_size, 'symbol_count': len(metadata.symbols), 'string_size': metadata.string_size,
              'symbol_count_source': metadata.symbol_count_source, 'init_addresses': metadata.init_addresses,
              'imports': [asdict(x) for x in metadata.symbols if not x.section and x.name],
              'exports': [asdict(x) for x in metadata.symbols if x.section and x.binding and x.name],
              'relocations': [asdict(x) for x in metadata.relocations], 'code_ranges': code_ranges,
              'code_discovery': code_report, 'rewrite': image.metadata(), 'unsupported': [],
              'game_boot_status': 'NOT_RUN'}
    if callback_audit:
        report['callback_audit'] = {
            'callback_audit_version': 1,
            'package_sha256': report['package_sha256'],
            'source_sha256': report['source_sha256'],
            'indirect_policy': indirect_policy,
            'callback_root_kind': 'defined-stt-func',
            'callback_roots': audited_callback_roots(nso, metadata, code_ranges, code_report),
        }
    return package, report


def import_directory(input_directory, output_directory, modules=('main', 'sdk'), *, package_version=1, profiles=None,
                     indirect_policy='strict', callback_audit=False, checked_stack=False):
    names = list(modules)
    if not names or len(names) != len(set(names)) or any(not MODULE_NAME.fullmatch(name) for name in names):
        raise ImportError('explicit module list is empty, duplicated, or invalid')
    if package_version not in (1, 2) or (profiles and package_version != 2):
        raise ImportError('profile selection requires explicit package version 2')
    if indirect_policy not in ('strict', 'guarded-host'):
        raise ImportError('unsupported indirect policy')
    if indirect_policy == 'guarded-host' and package_version != 2:
        raise ImportError('guarded host transfers require package version 2')
    if not isinstance(callback_audit, bool):
        raise ImportError('callback audit selection must be explicit boolean')
    if callback_audit and package_version != 2:
        raise ImportError('callback audit receipt requires package version 2')
    if not isinstance(checked_stack, bool) or (checked_stack and package_version != 2):
        raise ImportError('checked-stack mode requires explicit boolean and package version 2')
    if profiles is not None and (not isinstance(profiles, dict) or
            any(name not in names or not isinstance(variant, str) or not variant
                for name, variant in profiles.items())):
        raise ImportError('profile selections must name imported modules and nonempty variants')
    output_directory = Path(output_directory)
    # Never reuse a directory containing previous playable packages: an error
    # report next to stale output could otherwise look like a successful import.
    if output_directory.exists() and any(output_directory.glob('*.dmag')):
        raise ImportError('output directory already contains packages; choose a fresh directory')
    output_directory.mkdir(parents=True, exist_ok=True)
    report = {'format': 'DMAMOD01' if package_version == 1 else 'DMAMOD02', 'abi': ABI, 'module_order': names, 'status': 'rejected', 'modules': [], 'unsupported': []}
    if indirect_policy == 'guarded-host':
        report['indirect_policy'] = indirect_policy
    if checked_stack:
        report['checked_stack'] = True
    prepared = []
    try:
        for name in names:
            source_path = Path(input_directory) / name
            source = source_path.read_bytes()
            try:
                package, module_report = import_module(source, name, package_version=package_version,
                                                      profile=(profiles or {}).get(name), indirect_policy=indirect_policy,
                                                      callback_audit=callback_audit, checked_stack=checked_stack)
            except (NsoError, RewriteError, ImportError) as error:
                report['modules'].append({'name': name, 'source_sha256': hashlib.sha256(source).hexdigest(),
                                          'build_id': source[0x40:0x60].hex() if len(source) >= 0x60 else None,
                                          'unsupported': [str(error)]})
                rejected = getattr(error, 'rejected_indirect_sites', ())
                if rejected:
                    report['modules'][-1]['code_discovery'] = {'indirect_policy': indirect_policy,
                        'rejected_indirect_sites': list(rejected)}
                window=getattr(error,'uncovered_window',None)
                if window is not None:
                    report['modules'][-1].setdefault('code_discovery',{})['uncovered_window']=window
                raise
            prepared.append((name, package))
            report['modules'].append(module_report)
        report['status'] = 'prepared'
    except (OSError, NsoError, RewriteError, ImportError) as error:
        report['unsupported'].append(str(error))
        (output_directory / 'import.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        raise ImportError(str(error)) from error
    # Parse/rewrite every module before publishing any package.
    written = []
    try:
        for name, package in prepared:
            target = output_directory / (name + '.dmag')
            written.append(target)
            target.write_bytes(package)
        (output_directory / 'import.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    except OSError:
        for target in written:
            target.unlink(missing_ok=True)
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input_directory', type=Path)
    parser.add_argument('output_directory', type=Path)
    parser.add_argument('--modules', nargs='+', default=['main', 'sdk'])
    parser.add_argument('--package-version', type=int, choices=(1, 2), default=1)
    parser.add_argument('--profile', action='append', default=[], metavar='MODULE=VARIANT')
    parser.add_argument('--indirect-policy', choices=('strict', 'guarded-host'), default='strict')
    parser.add_argument('--callback-audit', action='store_true', help='emit trusted callback audit receipt v1 for package v2')
    parser.add_argument('--checked-stack', action='store_true', help='v2 immutable runtime SP preflight (required for canonical original modules)')
    args = parser.parse_args()
    try:
        profiles = {}
        for value in args.profile:
            if '=' not in value:
                raise ImportError('profile selection must be MODULE=VARIANT')
            module, variant = value.split('=', 1)
            if module in profiles:
                raise ImportError('duplicate profile selection')
            profiles[module] = variant
        report = import_directory(args.input_directory, args.output_directory, args.modules,
                                  package_version=args.package_version, profiles=profiles, indirect_policy=args.indirect_policy,
                                  callback_audit=args.callback_audit, checked_stack=args.checked_stack)
    except (ImportError, OSError) as error:
        raise SystemExit(f'Android import rejected: {error}') from error
    print(f'Prepared {len(report["modules"])} modules in explicit order: {", ".join(report["module_order"])}; game boot NOT_RUN')


if __name__ == '__main__':
    main()
