#!/usr/bin/env python3
"""Android ABI v1 raw ARM64 emitter, deliberately separate from patch_nso.py.

Offsets are image-relative. The loader fills aligned, zeroed helper literals
while RW, then seals RX. This module never assumes a Bionic TLS layout.
Bounded exclusive windows are relocated as complete single-entry regions.
"""
import argparse
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from itertools import combinations
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import android_exclusive
import android_observation
from android_instruction import Instruction

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm64_const import ARM64_OP_MEM, ARM64_OP_REG, ARM64_OP_IMM

ABI = 0x444D4101
STATE_HELPER, DISPATCH_HELPER = 1, 2
SVC, TIMER, OBS, INDIRECT_HOST, STACK_CHECK = 1, 2, 3, 4, 5
EXCLUSIVE_LOADS = {'ldxr', 'ldaxr', 'ldxp', 'ldaxp', 'ldxrb', 'ldaxrb', 'ldxrh', 'ldaxrh'}
EXCLUSIVE_STORES = {'stxr', 'stlxr', 'stxp', 'stlxp', 'stxrb', 'stlxrb', 'stxrh', 'stlxrh'}
HELPER_POOL_CHUNK = 256 * 1024
MD = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
MD.detail = True


class RewriteError(ValueError):
    pass


@dataclass(frozen=True)
class FatalWord:
    """Exact retail trap, preserved in place rather than decoded as an ALU op.

    0xe7ffdefe is the historical ARM TRAP word used by this A64 input. It
    remains unallocated in A64; it is not the A64 UDF instruction encoding.
    Keeping its original bytes preserves the synchronous illegal-instruction
    fault. Exact A64 UDF #0 (0x00000000), present after a returning retail
    error call, is also preserved as a synchronous fatal terminator. Other
    undecodable words and other UDF immediates remain unsupported.
    """
    address: int
    original_word: int = 0xE7FFDEFE
    size: int = 4
    mnemonic: str = 'fatal'
    operands: tuple = ()

    def __post_init__(self):
        if self.original_word not in (0,0xE7FFDEFE):
            raise RewriteError('unsupported fatal word')

    @property
    def bytes(self):
        return struct.pack('<I',self.original_word)

    @property
    def op_str(self):
        return 'udf #0' if self.original_word==0 else '0xe7ffdefe'

    def group(self, _):
        return False

    def regs_access(self):
        return (), ()


def is_fatal_word(value):
    return value in (0,0xE7FFDEFE)


def is_fatal_instruction(ins):
    # A64 BRK imm16 always takes a breakpoint exception. The current guest
    # runtime has no continuation/recovery contract for either of these traps.
    return isinstance(ins, FatalWord) or struct.unpack('<I', ins.bytes)[0] & 0xFFE0001F == 0xD4200000


@dataclass(frozen=True)
class Fixup:
    offset: int
    helper: int


@dataclass(frozen=True)
class Gate:
    return_offset: int
    kind: int
    argument: int


@dataclass(frozen=True)
class GateProvenance:
    return_offset: int
    original_offset: int
    original_word: int
    flags: int = 0


@dataclass(frozen=True)
class Site:
    offset: int
    trampoline: int
    instruction: str


@dataclass(frozen=True)
class Image:
    bytes: bytes
    entry_offset: int
    fixups: tuple
    gates: tuple
    sites: tuple
    abi: int = ABI
    target: str = 'android-arm64'
    profile: object = None
    gate_provenance: tuple = ()
    parameters: tuple = ()
    indirect_policy: str = 'strict'
    package_version: int = 1
    checked_stack: bool = False
    checked_calls: tuple = ()
    checked_call_forests: tuple = ()

    def metadata(self):
        result = {'target': self.target, 'abi': self.abi, 'size': len(self.bytes),
                'entry_offset': self.entry_offset,
                'fixups': [asdict(x) for x in self.fixups],
                'gates': [asdict(x) for x in self.gates],
                'sites': [asdict(x) for x in self.sites]}
        if self.profile is not None:
            result.update(profile_digest=self.profile.digest.hex(), profile_class=self.profile.identity_class,
                          gate_provenance=[asdict(x) for x in self.gate_provenance],
                          parameters=[asdict(x) for x in self.parameters])
        if self.indirect_policy == 'guarded-host':
            result.update(indirect_policy=self.indirect_policy,
                          gate_provenance=[asdict(x) for x in self.gate_provenance])
        if self.checked_stack:
            result.update(checked_stack=True, gate_provenance=[asdict(x) for x in self.gate_provenance])
        if self.checked_calls:
            result['checked_calls'] = [dict(offset=pc, target=target, rule='virtual-x18-exact-target-direct-call-v1')
                                       for pc, target in self.checked_calls]
        if self.checked_call_forests:
            result['checked_call_forests'] = [dict(item) for item in self.checked_call_forests]
        return result

    def validate(self):
        size = len(self.bytes)
        if not isinstance(self.checked_stack, bool) or (self.checked_stack and self.package_version != 2):
            raise RewriteError('checked stack requires explicit boolean and package version 2')
        if self.target != 'android-arm64' or self.abi != ABI:
            raise RewriteError('unsupported target/ABI')
        if size == 0 or size % 4 or self.entry_offset % 4 or not 0 <= self.entry_offset <= size - 4:
            raise RewriteError('invalid image size/entry')
        occupied = set()
        for item in self.fixups:
            if item.helper not in (STATE_HELPER, DISPATCH_HELPER) or item.offset % 8 or not 0 <= item.offset <= size - 8:
                raise RewriteError('invalid helper fixup')
            if item.offset in occupied or self.bytes[item.offset:item.offset + 8] != b'\0' * 8:
                raise RewriteError('duplicate/nonzero helper fixup')
            occupied.add(item.offset)
        if any(self.entry_offset < offset + 8 and offset < self.entry_offset + 4 for offset in occupied):
            raise RewriteError('entry instruction overlaps helper fixup')
        returns = set()
        for gate in self.gates:
            if gate.return_offset % 4 or not 4 <= gate.return_offset <= size - 4:
                raise RewriteError('invalid gate return offset')
            allowed = (SVC, TIMER, OBS) if self.profile is not None else (SVC, TIMER)
            if self.indirect_policy == 'guarded-host' and self.package_version == 2:
                allowed += (INDIRECT_HOST,)
            if self.checked_stack and self.package_version == 2:
                allowed += (STACK_CHECK,)
            maximum = 65535 if gate.kind == SVC else 31 if gate.kind in (TIMER, INDIRECT_HOST) else 0xFFFFFFFF
            if gate.kind not in allowed or not 0 <= gate.argument <= maximum:
                raise RewriteError('invalid gate kind/argument')
            if gate.kind == STACK_CHECK and stack_check_operation(gate.argument) is None:
                raise RewriteError('invalid stack-check word')
            if any(gate.return_offset - 4 < offset + 8 and offset < gate.return_offset + 4 for offset in occupied):
                raise RewriteError('gate call/return instructions overlap helper fixup')
            if gate.return_offset in returns or self.bytes[gate.return_offset - 4:gate.return_offset] != word(0xD63F03C0):
                raise RewriteError('gate must follow blr x30')
            returns.add(gate.return_offset)
        if (self.profile is not None or any(g.kind in (INDIRECT_HOST, STACK_CHECK) for g in self.gates)) and len(self.gates) != len(self.gate_provenance):
            raise RewriteError('gate provenance count mismatch')
        return self


def word(value):
    return struct.pack('<I', value)


def decode(value, address):
    if is_fatal_word(value):
        return FatalWord(address,original_word=value)
    result = list(MD.disasm(word(value), address))
    if len(result) != 1 or result[0].mnemonic == 'udf':
        raise RewriteError(f'0x{address:x}: invalid ARM64 instruction 0x{value:08x}')
    return result[0]


def branch(pc, target):
    delta = target - pc
    if delta % 4 or not -(1 << 27) <= delta < (1 << 27):
        raise RewriteError(f'0x{pc:x}: branch out of range/alignment')
    return 0x14000000 | ((delta >> 2) & 0x3FFFFFF)


def indirect_register(ins):
    original = struct.unpack('<I', ins.bytes)[0]
    if original & 0xFFFFFC1F not in (0xD61F0000, 0xD63F0000):
        raise RewriteError(f'0x{ins.address:x}: guarded transfer requires plain BR/BLR')
    register = original >> 5 & 31
    if register in (18, 31) or (ins.mnemonic == 'blr' and register == 30):
        raise RewriteError(f'0x{ins.address:x}: unsupported guarded {ins.mnemonic} x{register}')
    return register


def byte_jump_table(ins, by_pc, entries):
    """Prove the observed forward ADR + unsigned-byte + LSL2 BR x18 form.

    The byte's contents need no immutability assumption: all 256 possible
    instruction targets are audited. No entrance may bypass a producer.
    """
    if struct.unpack('<I', ins.bytes)[0] != 0xD61F0240:
        return None

    def writer(register, before):
        if before in entries:
            return None
        for pc in range(before - 4, max(-1, before - 36), -4):
            previous = by_pc.get(pc)
            if previous is None or is_fatal_instruction(previous):
                return None
            if previous.mnemonic in ('svc','hvc','smc') or any(
                    previous.group(group) for group in (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET)):
                return None
            names = {previous.reg_name(r).replace('w', 'x', 1) for r in previous.regs_access()[1]}
            if 'x' + str(register) in names:
                return previous
            if pc in entries:
                return None
        return None

    addition = writer(18, ins.address)
    if addition is None:
        return None
    value = struct.unpack('<I', addition.bytes)[0]
    if value & ~(31 << 16) != 0x8B000A52:
        return None
    index = value >> 16 & 31
    if index in (18, 31):
        return None
    load, address = writer(index, addition.address), writer(18, addition.address)
    if (load is None or load.mnemonic != 'ldrb' or load.writeback or
            len(load.operands) != 2 or load.operands[1].type != ARM64_OP_MEM or
            address is None or address.mnemonic != 'adr' or
            address.operands[1].type != ARM64_OP_IMM or address.operands[1].imm != ins.address + 4):
        return None
    return {'offset': ins.address, 'base': ins.address + 4, 'count': 256,
            'producer_offsets': sorted((address.address, load.address, addition.address)),
            'rule': 'adr-br-next-u8-lsl2-all-targets-v1'}


def _readonly_jump_table(ins, by_pc, entries, raw, readonly_ranges, target_register, width):
    """Shared bounded RO proof; changing target register needs no new lowering.

    A W-index SUB clears its upper half, CMP/B.HI bounds it, and no other
    entrance can bypass either fact. The exact immutable RO table determines
    the target set. This does not admit a generic 65536-target dispatch.
    """
    if struct.unpack('<I', ins.bytes)[0] != 0xD61F0000|(target_register<<5):
        return None

    def writer(register, before):
        if before in entries:
            return None
        for pc in range(before - 4, max(-1, before - 132), -4):
            previous=by_pc.get(pc)
            if previous is None or is_fatal_instruction(previous):
                return None
            if previous.mnemonic in ('svc','hvc','smc') or any(
                    previous.group(group) for group in (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET)):
                return None
            names={previous.reg_name(r).replace('w','x',1) for r in previous.regs_access()[1]}
            if 'x'+str(register) in names:
                return previous
            if pc in entries:
                return None
        return None

    def value(previous):
        return struct.unpack('<I', previous.bytes)[0]

    addition=writer(target_register,ins.address)
    if addition is None or value(addition)&~(31<<16)!=0x8B000800|(target_register<<5)|target_register:
        return None
    loaded=value(addition)>>16&31
    if loaded==18 or loaded>=29:
        return None
    load,address=writer(loaded,addition.address),writer(target_register,addition.address)
    load_encoding=0x38606800 if width==1 else 0x78607800
    if (load is None or value(load)&~((31<<16)|(31<<5)|31)!=load_encoding or
            address is None or address.mnemonic!='adr' or address.operands[1].imm!=ins.address+4):
        return None
    table_register,index=value(load)>>5&31,value(load)>>16&31
    if table_register in (18,31) or index==18 or index>=29:
        return None
    base_add=writer(table_register,load.address)
    if (base_add is None or value(base_add)&0xFFC003FF !=
            0x91000000|(table_register<<5)|table_register):
        return None
    base_page=writer(table_register,base_add.address)
    if base_page is None or base_page.mnemonic!='adrp':
        return None
    table=base_page.operands[1].imm+(value(base_add)>>10&4095)
    guard=None
    for pc in range(load.address-4,max(-1,ins.address-132),-4):
        previous=by_pc.get(pc)
        if previous is None or is_fatal_instruction(previous):
            return None
        if any(previous.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)):
            guard=previous
            break
    if (guard is None or value(guard)&0xFF00001F!=0x54000008 or
            guard.address<guard.operands[0].imm<=ins.address):
        return None
    compare=by_pc.get(guard.address-4)
    if compare is None or value(compare)&0xFFC003FF != 0x7100001F|(index<<5):
        return None
    bound=value(compare)>>10&4095
    if bound>63:
        return None
    zero=writer(index,compare.address)
    # Any ordinary W-register source still zero-extends the W destination.
    # Keep the same dominating SUB/CMP/guard and every producer-entry check.
    if (zero is None or value(zero)&0xFFC0001F != 0x51000000|index or
            (value(zero)>>5&31) in (18,31) or
            width==1 and value(zero)>>5&31!=index):
        return None
    for pc in range(compare.address+4,load.address,4):
        previous=by_pc.get(pc)
        if previous is None or previous.mnemonic in ('svc','hvc','smc') or 'x'+str(index) in {
                previous.reg_name(r).replace('w','x',1) for r in previous.regs_access()[1]}:
            return None
    # Includes CMP, B.HI and every table/target producer. The SUB itself may
    # be a function entry because it establishes the zero-extension fact.
    if any(pc in entries for pc in range(zero.address+4,ins.address+4,4)):
        return None
    size=width*(bound+1)
    if table%width or not any(start<=table and table+size<=end for start,end in readonly_ranges):
        return None
    data=raw[table:table+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<'+('B' if width==1 else 'H')*(bound+1),data)))
    if values[-1]>4095:
        return None
    return {'offset':ins.address,'base':ins.address+4,'count':1<<values[-1].bit_length(),
            'target_values':values,'index_bound':bound,'table_offset':table,
            'table_bytes':size,'table_sha256':hashlib.sha256(data).hexdigest(),
            'zero_extend_offset':zero.address,'compare_offset':compare.address,'guard_offset':guard.address,
            'producer_offsets':sorted((base_page.address,base_add.address,address.address,load.address,addition.address)),
            'rule':f'adr-br-next-u{width*8}-ro-guarded-index-lsl2-v1'}


def _copied_dual_bound_halfword_table(ins, by_pc, entries, raw, readonly_ranges, root_entries):
    """The observed two CMP37 paths feed one zero-extending W17 copy."""
    if root_entries is None:
        return None
    branch=ins.address
    def value(offset):
        op=by_pc.get(branch+offset)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    required={0:0xD61F0240,-76:0x710095BF,-64:0xF9400C08,-60:0xF940090B,-56:0x2A1F03E8,
              -52:0x710095BF,-44:0xB940080A,-32:0x2A0D03F1,-24:0x78717A07,-20:0x8B070A52,
              -16:0xAA1F03EE,-12:0xAA1F03EC,-8:0x528008CF,-4:0x2A0D03F0}
    if any(value(offset)!=word_ for offset,word_ in required.items()):
        return None
    first,default,guard,address=(by_pc.get(branch+offset) for offset in (-72,-68,-48,-28))
    if (any(op is None for op in (first,default,guard,address)) or
            value(-72)&0xFF00001F!=0x54000009 or first.operands[0].imm!=branch-44 or
            default.mnemonic!='b' or value(-48)&0xFF00001F!=0x54000008 or
            default.operands[0].imm!=guard.operands[0].imm or branch-76<=guard.operands[0].imm<=branch or
            address.mnemonic!='adr' or value(-28)&31!=18 or address.operands[1].imm!=branch+4):
        return None
    safe={branch+offset for offset in (-64,-60,-56,-52)}
    join=branch-44
    if join in root_entries or any(pc in entries and pc not in safe|{join} for pc in range(branch-72,branch+4,4)):
        return None
    # The join skips its second CMP only through the first bounded B.LS.
    # Do not treat an unrelated direct edge to the same address as equivalent.
    text_limit=min((begin for begin,_ in readonly_ranges),default=0)
    for pc in range(0,text_limit,4):
        word_=struct.unpack_from('<I',raw,pc)[0];target=None
        def signed(v,bits):return v-(1<<bits) if v&(1<<(bits-1)) else v
        if word_&0x7C000000==0x14000000:target=pc+4*signed(word_&0x3FFFFFF,26)
        elif word_&0xFF000010==0x54000000 or word_&0x7E000000==0x34000000:target=pc+4*signed(word_>>5&0x7FFFF,19)
        elif word_&0x7E000000==0x36000000:target=pc+4*signed(word_>>5&0x3FFF,14)
        if target==join and pc!=branch-72:
            return None
        if word_&0x1F000000==0x10000000:
            immediate=signed((word_>>5&0x7FFFF)<<2|(word_>>29&3),21)
            target=(pc&~4095)+(immediate<<12) if word_>>31 else pc+immediate
            if target==join:
                return None
            if word_>>31 and pc+4<text_limit:
                following=struct.unpack_from('<I',raw,pc+4)[0];reg=word_&31
                if following&0xFFC003FF==0x91000000|(reg<<5)|reg and target+(following>>10&4095)==join:
                    return None
    page,add=by_pc.get(branch-40),value(-36)
    if (page is None or page.mnemonic!='adrp' or value(-40)&31!=16 or
            add is None or add&0xFFC003FF!=0x91000210):
        return None
    table=page.operands[1].imm+(add>>10&4095);size=76
    if table%2 or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
        return None
    data=raw[table:table+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<38H',data)))
    if values[-1]>4095:
        return None
    return dict(offset=branch,base=branch+4,count=1<<values[-1].bit_length(),target_values=values,
                index_bound=37,table_offset=table,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                zero_extend_offset=branch-32,compare_offset=branch-52,guard_offset=branch-48,
                bounded_join_offset=join,bound_source_offsets=[branch-76,branch-72,branch-52,branch-48],
                preserved_source_offsets=[branch+offset for offset in (-44,-16,-12,-8,-4)],
                producer_offsets=[branch+offset for offset in (-40,-36,-32,-28,-24,-20)],
                rule='adr-br-next-u16-ro-dual-cmp37-wcopy-lsl2-v1')


def halfword_jump_table(ins, by_pc, entries, raw, readonly_ranges, *, root_entries=None):
    return (_readonly_jump_table(ins,by_pc,entries,raw,readonly_ranges,18,2) or
            _copied_dual_bound_halfword_table(ins,by_pc,entries,raw,readonly_ranges,root_entries))


def _virtual_x18_readonly_table(ins, by_pc, entries, raw, readonly_ranges):
    """Finite RO targets; actual virtual base/table/full64 index precede read."""
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address
    if value(branch)!=0xD61F0240:
        return None
    addition=None
    for pc in range(branch-4,max(-1,branch-24),-4):
        op=by_pc.get(pc)
        if (op is None or is_fatal_instruction(op) or op.mnemonic in ('svc','hvc','smc') or
                any(op.group(group) for group in (CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET))):
            return None
        if value(pc)&~(31<<16)==0x8B000A52:
            addition=pc;break
        if has18(op) or any(op.reg_name(r) in ('sp','wsp') for r in op.regs_access()[1]):
            return None
    if addition is None:
        return None
    loaded=value(addition)>>16&31;load=addition-4;word_=value(load)
    if word_ is None:
        return None
    width=2 if word_&~((31<<16)|(31<<5)|31)==0x78607800 else 1
    table_register,index=word_>>5&31,word_>>16&31
    roles=(loaded,table_register,index)
    if (len(set(roles))!=3 or any(r==18 or r>=29 for r in roles) or
            word_!=(0x78607800 if width==2 else 0x38606800)|(index<<16)|(table_register<<5)|loaded):
        return None
    address=by_pc.get(load-4)
    if address is None or address.mnemonic!='adr' or value(load-4)&31!=18:
        return None
    base=address.operands[1].imm
    if base%4 or base not in by_pc or any(pc in entries for pc in range(load+4,branch+4,4)):
        return None
    bound=None;bound_offset=None;basis=None
    for pc in range(load-8,max(-1,load-100),-4):
        compare=value(pc)
        if compare is None or compare&0xFFC0001F!=0x7100001F:
            continue
        candidate=compare>>10&4095;source=compare>>5&31
        if candidate>63 or source==31:
            continue
        copy=any(value(at)==0x2A0003E0|(source<<16)|index for at in range(pc+4,load-4,4))
        alias=(width==1 and source==18 and value(pc-4)==0x12001C00|(index<<5)|18 and
               any(value(at)==0x92401C00|(index<<5)|index for at in range(pc+4,load-4,4)))
        guards=[at for at in range(pc+4,load-4,4) if value(at) is not None and
                value(at)&0xFF00001F in (0x54000008,0x54000009)]
        if (source==index or copy or alias) and guards:
            bound,bound_offset,basis=candidate,pc,'nearby CMP candidate; actual full64 index is checked'
            break
    if bound is None:
        # Observed SDK loop29e5c8: its actual index is masked to two bits.
        # This is only the finite table candidate, not a cross-loop proof.
        masks=[pc for pc in range(max(0,load-192),load-4,4) if value(pc) is not None and
               value(pc)&~(31<<5)==0x12000400|index]
        if len(masks)!=1:
            return None
        bound,bound_offset,basis=3,masks[0],'observed AND Windex,#3 candidate; actual full64 index is checked'
    candidates=[]
    inline=by_pc.get(load-12)
    positions=(load-12,) if (inline is not None and inline.mnemonic=='adrp' and value(load-12)&31==table_register) else range(max(0,load-512),load-4,4)
    for pc in positions:
        page=by_pc.get(pc);add=value(pc+4)
        if (page is not None and page.mnemonic=='adrp' and value(pc)&31==table_register and
                add is not None and add&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
            candidates.append((pc,pc+4,page.operands[1].imm+(add>>10&4095)))
    if not candidates or len({candidate[2] for candidate in candidates})!=1:
        return None
    page,add,table=candidates[-1];size=width*(bound+1)
    if table%width or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
        return None
    data=raw[table:table+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<'+str(bound+1)+('H' if width==2 else 'B'),data)))
    if values[-1]>4095:
        return None
    return dict(offset=branch,base=base,count=1<<values[-1].bit_length(),target_values=values,
                load_offset=load,target_register=18,virtual_target_register=18,
                table_register=table_register,index_register=index,loaded_register=loaded,
                index_bound=bound,table_offset=table,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                bound_candidate_offset=bound_offset,bound_basis=basis,proof_start_offset=load-4,
                producer_offsets=[page,add,load-4,load,addition],
                permitted_source_rewrite_offsets=[load-4,addition],
                preserved_source_offsets=list(range(addition+4,branch,4)),
                rule=f'runtime-virtual-x18-base-index-u{width*8}-ro-lsl2-v1')


def _nonself_sub_inline_halfword(ins, by_pc, entries, guarded):
    """One SDK schedule can enter at its inline, dynamically checked table.

    This distinct nonself W-SUB class does not reinterpret rejected static
    self-SUB or dual-bound entrances. The already approved load guard checks
    the actual full64 index and both bases even when the CMP was bypassed.
    """
    load=guarded['load_offset'];index=guarded['index_register']
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    subtraction,compare,guard,suffix=(value(load+delta) for delta in (-24,-20,-16,8))
    if (subtraction is None or subtraction&0xFFC0001F!=0x51000000|index or
            subtraction>>5&31 in (index,18,29,30,31) or
            compare is None or compare&0xFFC003FF!=0x7100001F|(index<<5) or
            guarded['bound_candidate_offset']!=load-20 or
            guard is None or guard&0xFF00001F!=0x54000008 or
            load-16<by_pc[load-16].operands[0].imm<=ins.address or
            guarded['producer_offsets'][:2]!=[load-12,load-8] or
            ins.address!=load+12 or suffix is None or suffix&0xFF800000!=0x52800000 or
            suffix&31 in (guarded['loaded_register'],guarded['table_register'],index,18,29,30,31)):
        return None
    allowed=set(range(load-12,load+4,4))
    if any(pc in entries and pc not in allowed for pc in range(load-20,ins.address+4,4)):
        return None
    return dict(guarded,rule='runtime-virtual-x18-u16-nonself-sub-inline-mov-lsl2-v1',
                index_subtract_offset=load-24,index_source_register=subtraction>>5&31,
                index_subtract_immediate=subtraction>>10&4095,
                guarded_preload_entry_offsets=sorted(allowed),
                entry_policy='nonself-sub-inline-mov-must-pass-runtime-load-guard-v1')


def signed_relative_x18_table(ins, by_pc, entries, raw, readonly_ranges, *,
                              text_size=None, protected_ranges=(), root_entries=None):
    """A bounded signed32 table aliases virtual X18's index/offset/target.

    Constructor candidates supply only the expected RO base. A loop may skip
    them: the emitted load guard checks the actual base and full64 virtual
    index, and the final jump separately checks exact derived case addresses.
    """
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address;load=branch-8
    if text_size is None or value(branch)!=0xD61F0240:
        return None
    loaded=value(load)
    if loaded is None:
        return None
    table_register=loaded>>5&31
    if (table_register in (18,29,30,31) or loaded!=0xB8B27812|(table_register<<5) or
            value(load+4)!=0x8B000252|(table_register<<16)):
        return None
    definition,side,masked,compare,guard=(by_pc.get(load-d) for d in (20,16,12,8,4))
    if any(op is None for op in (definition,side,masked,compare,guard)):
        return None
    producer=value(load-20);source=producer>>5&31;shift=producer>>16&31
    if (producer&~((31<<16)|(31<<5))!=0x53007C12 or not 0<shift<32 or
            source in (table_register,18,29,30,31) or side.mnemonic!='ubfx' or
            value(load-16)>>5&31!=source or value(load-16)&31 in (source,table_register,18,29,30,31) or
            value(load-12)!=0x12000000|(source<<5)|source or
            value(load-8)&0xFFC003FF!=0x7100025F or value(load-4)&0xFF00001F!=0x54000008 or
            load-4<guard.operands[-1].imm<=branch):
        return None
    bound=value(load-8)>>10&4095
    if bound>63 or ({load+4,branch} & (set(entries)|set(root_entries or ()))):
        return None
    size=4*(bound+1);candidates=[];constructor_block=[]
    # Only this contiguous pre-index block supplies constructor candidates.
    # An earlier table used on a different branch must not compete merely
    # because it lies within 512 bytes. A loop may enter this block later;
    # no dominance claim follows, and its actual Xtable is checked at read.
    for at in range(load-24,max(-1,load-516),-4):
        op=by_pc.get(at)
        if (op is None or is_fatal_instruction(op) or op.mnemonic in ('svc','hvc','smc') or
                any(op.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET))):
            break
        constructor_block.append(at)
    for at in reversed(constructor_block):
        addition=value(at)
        if addition is None or addition&0xFFC003FF!=0x91000000|(table_register<<5)|table_register:
            continue
        for pc in range(at-4,max(-1,at-36),-4):
            op=by_pc.get(pc)
            if (op is None or is_fatal_instruction(op) or op.mnemonic in ('svc','hvc','smc') or
                    any(op.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET))):
                break
            written={op.reg_name(r).replace('w','x',1) for r in op.regs_access()[1]}
            if 'x'+str(table_register) in written:
                if op.mnemonic=='adrp' and value(pc)&31==table_register:
                    table=op.operands[-1].imm+(addition>>10&4095)
                    if table%4==0 and any(a<=table and table+size<=b for a,b in readonly_ranges):
                        candidates.append((pc,at,table))
                break
            if has18(op) or written&{'sp','xsp'}:
                break
    if not candidates or len({row[2] for row in candidates})!=1:
        return None
    page,addition,table=candidates[-1];data=raw[table:table+size]
    if len(data)!=size:
        return None
    offsets=struct.unpack('<'+str(bound+1)+'i',data)
    targets=sorted({table+offset for offset in offsets})
    if any(offset%4 for offset in offsets) or any(target<=0 or target%4 or target+4>text_size or
            any(a<target+4 and target<b for a,b in protected_ranges) for target in targets):
        return None
    if any(target in (load+4,branch) for target in targets):
        return None
    return dict(offset=branch,base=table,count=bound+1,target_values=sorted({offset//4 for offset in offsets}),
                target_offsets=targets,signed_offsets=list(offsets),signed_relative=True,
                target_register=18,virtual_target_register=18,index_register=18,loaded_register=18,
                table_register=table_register,index_bound=bound,table_offset=table,table_bytes=size,
                table_sha256=hashlib.sha256(data).hexdigest(),load_offset=load,
                compare_offset=load-8,guard_offset=load-4,index_definition_offset=load-20,
                index_source_register=source,index_shift=shift,
                proof_start_offset=load-20,producer_offsets=[page,addition,load-20,load,load+4],
                permitted_source_rewrite_offsets=[load-20,load-8,load,load+4],
                preserved_source_offsets=[load-16,load-12],
                entry_policy='actual-table-full64-virtual-index-pre-read-and-exact-target-jump-v1',
                rule='runtime-virtual-x18-signed32-relative-ro-v1')


def x18_jump_table(ins, by_pc, entries, raw, readonly_ranges, *, root_entries=None,
                   text_size=None, protected_ranges=()):
    signed=signed_relative_x18_table(ins,by_pc,entries,raw,readonly_ranges,text_size=text_size,
                                     protected_ranges=protected_ranges,root_entries=root_entries)
    if signed is not None:
        return signed
    precise=halfword_jump_table(ins,by_pc,entries,raw,readonly_ranges,root_entries=root_entries)
    if precise is not None:
        return precise
    guarded=_virtual_x18_readonly_table(ins,by_pc,entries,raw,readonly_ranges)
    if guarded is not None:
        load=by_pc[guarded['load_offset']]
        # BR-next halfword dispatches retain the existing precise producer and
        # entry contract, including its refusal. A generic dynamic proof must
        # not silently replace a rejected zero-extension/dual-bound proof.
        if load.mnemonic=='ldrh' and guarded['base']==ins.address+4:
            return _nonself_sub_inline_halfword(ins,by_pc,entries,guarded)
        return guarded
    return byte_jump_table(ins,by_pc,entries)


def readonly_guest_byte_table(ins, by_pc, entries, raw, readonly_ranges):
    """Finite guest BR targets; the original native-GPR branch is preserved."""
    value=struct.unpack('<I',ins.bytes)[0]
    target=value>>5&31
    if value&0xFFFFFC1F!=0xD61F0000 or target==18 or target>=29:
        return None
    plan=_readonly_jump_table(ins,by_pc,entries,raw,readonly_ranges,target,1)
    if plan is not None:
        plan['target_register']=target
    return plan


def _runtime_readonly_guest_table(ins, by_pc, entries, raw, readonly_ranges, width):
    """Prove a finite switch conditional on an inline preflight at its load.

    The nearby ADRP/ADD is only a table candidate, never a dominance or callee
    preservation claim. Actual table base, target base and full 64-bit index
    are checked before the original load. Every accepted path to BR must pass
    that preflight and the remaining target ADD. The inline-base form may enter
    at ADRP/ADD/ADR/the patched LDR: no skipped CMP/MOV fact is assumed there.
    This rule requires checked-stack headroom.
    """
    def value(item):
        return struct.unpack('<I', item.bytes)[0]

    def writes(item):
        # Capstone names architectural registers29/30 "fp"/"lr" in this
        # binding. Within this call-free source pattern they are numeric GPRs.
        names=(item.reg_name(r) for r in item.regs_access()[1])
        return {{'fp':'x29','lr':'x30'}.get(name,name.replace('w','x',1)) for name in names}

    branch_word=value(ins)
    target=branch_word>>5&31
    if (branch_word&0xFFFFFC1F!=0xD61F0000 or target==18 or
            target>=29 and not (width==1 and target==29)):
        return None
    # A small, straight-line suffix may contain unrelated original operations.
    addition=None
    for pc in range(ins.address-4,max(-1,ins.address-28),-4):
        previous=by_pc.get(pc)
        if previous is None or is_fatal_instruction(previous) or previous.mnemonic in ('svc','hvc','smc') or any(
                previous.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)):
            return None
        if 'x'+str(target) in writes(previous):
            addition=previous
            break
    if addition is None or value(addition)&~(31<<16)!=0x8B000800|(target<<5)|target:
        return None
    loaded=value(addition)>>16&31
    load=by_pc.get(addition.address-4)
    load_encoding=0x38606800 if width==1 else 0x78607800
    if load is None or value(load)&~((31<<16)|(31<<5)|31)!=load_encoding or value(load)&31!=loaded:
        return None
    table_register,index=value(load)>>5&31,value(load)>>16&31
    registers_=(target,loaded,table_register,index)
    fp_lr_pair=width==1 and (target,loaded)==(29,30)
    if (len(set(registers_))!=4 or any(r==18 or r>=29 for r in (table_register,index)) or
            not fp_lr_pair and any(r==18 or r>=29 for r in (target,loaded))):
        return None
    direct_compare=by_pc.get(load.address-12)
    scheduled_compare=by_pc.get(load.address-32)
    scheduled_alu=(width==2 and registers_==(14,16,13,15) and scheduled_compare is not None and
                   value(scheduled_compare)&0xFFC003FF==0x7100001F|(index<<5) and
                   all(by_pc.get(load.address-distance) is not None and
                       value(by_pc[load.address-distance])==opcode for distance,opcode in
                       ((24,0x1B087DCE),(20,0x8B2EC529),(16,0x8B2DC529))))
    # Two observed switches use an earlier ADR base (including their return
    # block) and one exact original suffix effect. Other backward forms refuse.
    suffix=by_pc.get(ins.address-4)
    candidate_address=by_pc.get(load.address-4)
    backward_compare=by_pc.get(load.address-(12 if width==2 else 20))
    backward_zero_suffix=(width==1 and backward_compare is not None and
                          value(backward_compare)&0xFFC003FF==0x7100001F|(index<<5) and
                          candidate_address is not None and candidate_address.mnemonic=='adr' and
                          candidate_address.operands[1].imm<backward_compare.address and
                          addition.address==ins.address-8 and suffix is not None and
                          value(suffix)&~31==0x2A1F03E0 and value(suffix)&31 not in (target,loaded,table_register,18,29,30,31))
    backward_direct=(backward_compare is not None and
                     candidate_address is not None and candidate_address.mnemonic=='adr' and
                     candidate_address.operands[1].imm<backward_compare.address and
                     value(backward_compare)==0x7100341F|(index<<5) and
                     addition.address==ins.address-8 and suffix is not None and
                     ((width==2 and registers_==(10,11,23,9) and value(suffix)==0x91036908) or
                      (width==1 and registers_==(9,10,11,8) and value(suffix)==0x2A1803E8))) or backward_zero_suffix
    scheduled_backward=(width==1 and scheduled_compare is not None and
                         value(scheduled_compare)==0x7100501F|(index<<5) and
                         candidate_address is not None and candidate_address.mnemonic=='adr' and
                         candidate_address.operands[1].imm<scheduled_compare.address and
                         addition.address==ins.address-8 and suffix is not None and value(suffix)==0x910110E7 and
                         all(by_pc.get(load.address-distance) is not None and
                             value(by_pc[load.address-distance])==opcode for distance,opcode in
                             ((24,0xF9403660|target),(20,0x93407CE7),(16,0x8B070AF5),
                              (12,0x8B0A02B5),(8,0x9B0B00E7|(target<<10)))))
    backward_halfword=(width==2 and direct_compare is not None and
                       value(direct_compare)&0xFFC003FF==0x7100001F|(index<<5) and
                       candidate_address is not None and candidate_address.mnemonic=='adr' and
                       candidate_address.operands[1].imm<direct_compare.address and
                       addition.address==ins.address-4)
    forward_halfword=(width==2 and direct_compare is not None and
                      value(direct_compare)&0xFFC003FF==0x7100001F|(index<<5) and
                      candidate_address is not None and candidate_address.mnemonic=='adr' and
                      candidate_address.operands[1].imm==ins.address+4 and addition.address==ins.address-4)
    direct_halfword=backward_halfword or forward_halfword
    suffix_moves=[by_pc.get(addition.address+delta) for delta in (4,8)]
    two_mov_suffix=(width==1 and addition.address==ins.address-12 and direct_compare is not None and
                    value(direct_compare)&0xFFC003FF==0x7100001F|(index<<5) and
                    all(op is not None and value(op)&~((31<<16)|31)==0xAA0003E0 and
                        value(op)&31 not in (target,18,29,30,31) and value(op)>>16&31 not in (18,29,30,31)
                        for op in suffix_moves))
    direct=(scheduled_alu or backward_direct or scheduled_backward or direct_halfword or width==1 and direct_compare is not None and
            value(direct_compare)&0xFFC003FF==0x7100001F|(index<<5))
    copy=by_pc.get(load.address-16)
    copy_form=(copy is not None and value(copy)&~(31<<16)==0x2A0003E0|index and
               value(copy)>>16&31 not in (18,29,30,31))
    mov_inline=not direct and width==1 and copy_form
    scheduled_mov=width==2 and copy_form
    subtraction=by_pc.get(load.address-24)
    sub_compare,sub_guard=by_pc.get(load.address-20),by_pc.get(load.address-16)
    # The observed byte form subtracts into a distinct index. Self-SUB byte
    # tables retain their existing static proof and strict entry policy.
    sub_inline=(subtraction is not None and sub_compare is not None and sub_guard is not None and
                value(subtraction)&0xFFC0001F==0x51000000|index and
                value(subtraction)>>5&31 not in (18,29,30,31) and
                (width==2 or value(subtraction)>>5&31!=index) and
                value(sub_compare)&0xFFC003FF==0x7100001F|(index<<5) and
                value(sub_guard)&0xFF00001F==0x54000008)
    inline_compare,inline_guard=by_pc.get(load.address-20),by_pc.get(load.address-16)
    inline_direct=(width==2 and not sub_inline and inline_compare is not None and inline_guard is not None and
                   value(inline_compare)&0xFFC003FF==0x7100001F|(index<<5) and
                   value(inline_guard)&0xFF00001F==0x54000008 and addition.address==ins.address-4)
    store_sub,store_compare,store=(by_pc.get(load.address-distance) for distance in (28,24,20))
    store_virtual18=(width==1 and all(op is not None for op in (store_sub,store_compare,store)) and
                     value(store_sub)&~(31<<5)==0x51000400|index and
                     value(store_compare)==0x71027C1F|(index<<5) and value(store)==0xB9000012|(target<<5))
    store_target_sp=(width==1 and all(op is not None for op in (store_sub,store_compare,store)) and
                     value(store_sub)&~(31<<5)==0x51000800|index and
                     value(store_compare)&0xFFC003FF==0x7100001F|(index<<5) and value(store_compare)>>10&4095<=63 and
                     value(store)==0xF9001BE0|target)
    scheduled_store=((store_virtual18 or store_target_sp) and
                     value(store_sub)>>5&31 not in (18,29,30,31) and addition.address==ins.address-4)
    direct=direct or inline_direct
    inline_base=mov_inline or scheduled_mov or sub_inline or scheduled_alu or inline_direct or scheduled_store
    if scheduled_store:
        compare,guard,zero,address=store_compare,inline_guard,store_sub,candidate_address
    elif scheduled_backward:
        compare,guard,address=(by_pc.get(load.address-distance) for distance in (32,28,4))
        zero=None
        if any(writes(by_pc[load.address-distance]) & {'x'+str(r) for r in (index,table_register)}
               for distance in (24,20,16,12,8)):
            return None
    elif direct_halfword:
        compare,guard,address=direct_compare,by_pc.get(load.address-8),candidate_address
        zero=None
    elif inline_direct:
        compare,guard,address=inline_compare,inline_guard,candidate_address
        zero=None
    elif backward_direct:
        compare,guard,address=backward_compare,by_pc.get(backward_compare.address+4),candidate_address
        zero=None
    elif scheduled_alu:
        compare,guard,address=(by_pc.get(load.address-distance) for distance in (32,28,4))
        zero=None
    elif sub_inline:
        compare,guard,zero,address=sub_compare,sub_guard,subtraction,by_pc.get(load.address-4)
    elif scheduled_mov:
        compare,guard,zero,address=(by_pc.get(load.address-distance) for distance in (40,32,16,4))
    elif mov_inline:
        compare,guard,zero,address=(by_pc.get(load.address-distance) for distance in (24,20,16,4))
    elif direct:
        compare,guard,address=(by_pc.get(load.address-distance) for distance in (12,8,4))
        zero=None
    else:
        compare,guard,zero,address=(by_pc.get(load.address-distance) for distance in (16,12,8,4))
    compare_register=(value(copy)>>16&31) if mov_inline or scheduled_mov else index if direct or sub_inline or scheduled_store or width==2 else target
    if (any(x is None for x in (compare,guard,address)) or (not direct and zero is None) or
            value(compare)&0xFFC003FF!=0x7100001F|(compare_register<<5) or
            value(guard)&0xFF00001F!=0x54000008 or
            guard.address<guard.operands[0].imm<=ins.address or
            (not direct and not inline_base and value(zero)!=(0x92401C00|(index<<5)|index if width==1 else 0x2A0003E0|(index<<16)|index)) or
            address.mnemonic!='adr' or address.operands[0].reg!=ins.operands[0].reg):
        return None
    target_base=address.operands[1].imm
    if backward_direct or scheduled_backward or backward_halfword:
        if target_base%4 or target_base>=compare.address or target_base not in by_pc:
            return None
    elif target_base!=ins.address+4:
        return None
    proof_start=subtraction.address if sub_inline else compare.address if direct or mov_inline or scheduled_mov else zero.address
    if scheduled_mov:
        store,side_page,side_add,side_address=(by_pc.get(load.address-distance) for distance in (36,28,24,20))
        if any(x is None for x in (store,side_page,side_add,side_address)):
            return None
        scratch=value(side_address)&31
        # Exact observed schedule. Xindex is dead while ADRP/ADD build the
        # parallel address; only the subsequent W-copy establishes the index.
        # The original SP store remains an effect at its original position.
        if (value(store)!=0xB9001FE0|target or side_page.mnemonic!='adrp' or
                side_page.reg_name(side_page.operands[0].reg)!='x'+str(index) or
                value(side_add)&0xFFC003FF!=0x91000000|(index<<5)|index or
                scratch in (*registers_,compare_register,18,29,30,31) or
                value(side_address)!=0x8B20CC00|(compare_register<<16)|(index<<5)|scratch):
            return None
        live={'x'+str(r) for r in (compare_register,target,loaded,table_register)}|{'nzcv'}
        if any(writes(op)&live for op in (store,side_page,side_add,side_address)):
            return None
    if width==1 and not direct and not mov_inline and not sub_inline and not scheduled_store:
        # The observed CMP uses a distinct W alias. Require the complete low8
        # alias/mask relation, including its single unrelated ADD, rather than
        # inferring a bound for the original SUB/rotate input register.
        alias,between=by_pc.get(compare.address-8),by_pc.get(compare.address-4)
        if alias is None or between is None or value(alias)!=0x12001C00|(index<<5)|compare_register:
            return None
        moved=value(between)&31
        if (moved in (*registers_,18,31) or
                value(between)&0xFFC003FF!=0x91000000|(moved<<5)|moved):
            return None
        proof_start=alias.address
    bound=value(compare)>>10&4095
    prior_sub=by_pc.get(load.address-16)
    large_backward_sub=(backward_halfword and bound==253 and prior_sub is not None and
                        value(prior_sub)&~(31<<5)==0x51000400|index and
                        value(prior_sub)>>5&31 not in (18,29,30,31))
    # Only the observed direct-CMP, nine-byte leaf pair is approved. This does
    # not widen the separate guarded-host ABI or other FP/LR combinations.
    if fp_lr_pair and (not direct or bound!=8):
        return None
    guarded_preload_entries=({load.address-4,load.address} if direct_halfword else
                             set(range(load.address-12,load.address+4,4)) if inline_base else set())
    if bound>(255 if width==2 and (sub_inline or inline_direct) else 253 if large_backward_sub else 159 if scheduled_store and store_virtual18 else 63) or any(pc in entries and pc not in guarded_preload_entries
                       for pc in range(proof_start+4,ins.address+4,4)):
        return None
    protected={'x'+str(r) for r in registers_ if width!=1 or r!=index}
    for pc in range(addition.address+4,ins.address,4):
        previous=by_pc.get(pc)
        if two_mov_suffix:
            # The native ADD has already consumed the load result. This path
            # leaves ADD/MOV/MOV/BR unchanged; BR consumes only target. The
            # earlier actual-base/index guard does not read a register here.
            if previous not in suffix_moves or 'x'+str(target) in writes(previous):
                return None
            continue
        if (previous is None or is_fatal_instruction(previous) or previous.mnemonic in ('svc','hvc','smc') or
                any(previous.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)) or
                protected & writes(previous)):
            return None
        if width==1 and 'x'+str(index) in writes(previous):
            # The index has been consumed by LDRB. Only the observed plain W
            # register MOV is admitted here; target and loaded value stay live.
            if value(previous)&~(31<<16)!=0x2A0003E0|index or value(previous)>>16&31==18:
                return None
    candidates=[]
    # This form constructs the table after the W-copy. Require those exact
    # inline producers; no earlier constant or unknown alias can substitute.
    candidate_pcs=(load.address-12,) if inline_base or backward_direct and width==1 else range(max(0,compare.address-(512 if width==1 or large_backward_sub else 256)),compare.address,4)
    for pc in candidate_pcs:
        page,add=by_pc.get(pc),by_pc.get(pc+4)
        if (page is not None and add is not None and page.mnemonic=='adrp' and
                page.reg_name(page.operands[0].reg)=='x'+str(table_register) and
                value(add)&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
            candidates.append((pc,pc+4,page.operands[1].imm+(value(add)>>10&4095)))
    if not candidates or (len(candidates)!=1 and not ((backward_direct or direct_halfword) and width==2 and
                                                    len({candidate[2] for candidate in candidates})==1)):
        return None
    page_pc,add_pc,table=candidates[-1] if backward_direct or direct_halfword else candidates[0]
    size=width*(bound+1)
    if table%width or not any(start<=table and table+size<=end for start,end in readonly_ranges):
        return None
    data=raw[table:table+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<'+('B' if width==1 else 'H')*(bound+1),data)))
    if values[-1]>4095:
        return None
    plan={'offset':ins.address,'base':target_base,'target_register':target,
            'load_offset':load.address,'table_register':table_register,'index_register':index,
            'loaded_register':loaded,'target_values':values,'index_bound':bound,
            'table_offset':table,'table_bytes':size,'table_sha256':hashlib.sha256(data).hexdigest(),
            'compare_offset':compare.address,'guard_offset':guard.address,
            'producer_offsets':[page_pc,add_pc,address.address,load.address,addition.address],
            'rule':'runtime-base-index-u16-ro-lsl2-v1'}
    if not direct:
        plan['zero_extend_offset']=zero.address
    if inline_base:
        plan.update(proof_start_offset=proof_start,guarded_preload_entry_offsets=sorted(guarded_preload_entries),
                    entry_policy='inline-preload-must-pass-runtime-guard-v1')
    if scheduled_alu:
        # These exact original ALU operations consume old W14 and X13 and
        # produce a live parallel X9 address. Keep all three effects in place.
        # W15/NZCV are untouched; final ADRP/ADD/ADR then establish the values
        # checked by the existing load guard. No pre-gap dominance is assumed.
        plan.update(rule='runtime-base-index-u16-ro-scheduled-alu-inline-lsl2-v1',
                    preserved_scheduled_alu_offsets=[load.address-distance for distance in (24,20,16)],
                    scheduled_source_registers=[8,9,13,14],parallel_result_register=9)
    elif sub_inline:
        plan.update(rule=f'runtime-base-index-u{width*8}-ro-sub-inline-lsl2-v1',
                    index_subtract_offset=subtraction.address,index_source_register=value(subtraction)>>5&31,
                    index_subtract_immediate=value(subtraction)>>10&4095,
                    index_transform='uint32 subtraction modulo 2^32; full64 result checked by guard')
    elif scheduled_store:
        plan.update(rule=('runtime-base-index-u8-ro-sub-cmp159-store-x18-inline-lsl2-v1' if store_virtual18 else
                          'runtime-base-index-u8-ro-sub-cmp-store-target-sp30-inline-lsl2-v1'),
                    index_subtract_offset=store_sub.address,index_source_register=value(store_sub)>>5&31,
                    preserved_source_offsets=[store.address],permitted_source_rewrite_offsets=[store.address] if store_virtual18 else [],
                    original_store_word=value(store),original_store_bytes=4 if store_virtual18 else 8)
    elif scheduled_mov:
        plan.update(rule='runtime-base-index-u16-ro-scheduled-mov-inline-lsl2-v1',
                    alias_source_register=compare_register,dead_before_copy_register=index,
                    dead_before_copy_write_offsets=[side_page.address,side_add.address],
                    parallel_address_offset=side_address.address,preserved_store_offset=store.address,
                    preserved_store_word=value(store))
    elif mov_inline:
        plan.update(rule='runtime-base-index-u8-ro-mov-alias-inline-lsl2-v1',
                    alias_source_register=compare_register)
    elif direct_halfword:
        plan.update(rule=('runtime-base-index-u16-ro-backward-cmp-no-suffix-lsl2-v1' if backward_halfword else
                          'runtime-base-index-u16-ro-direct-cmp-prior-table-lsl2-v1'),
                    proof_start_offset=proof_start,
                    equivalent_table_producer_offsets=[candidate[0] for candidate in candidates],
                    guarded_preload_entry_offsets=sorted(guarded_preload_entries),
                    entry_policy='adr-or-load-must-pass-runtime-guard-v1')
        if large_backward_sub:
            plan.update(rule='runtime-base-index-u16-ro-backward-sub1-cmp253-lsl2-v1',
                        index_subtract_offset=prior_sub.address,index_subtract_immediate=1,
                        index_source_register=value(prior_sub)>>5&31)
    elif inline_direct:
        plan.update(rule='runtime-base-index-u16-ro-direct-cmp-inline-lsl2-v1')
    elif scheduled_backward:
        plan.update(rule='runtime-base-index-u8-ro-scheduled-backward-cmp20-lsl2-v1',
                    proof_start_offset=proof_start,
                    preserved_scheduled_alu_offsets=[load.address-distance for distance in (24,20,16,12,8)],
                    preserved_source_offsets=[suffix.address])
    elif backward_direct:
        plan.update(rule=f'runtime-base-index-u{width*8}-ro-backward-direct-cmp-lsl2-v1',
                    proof_start_offset=proof_start,preserved_source_offsets=[suffix.address],
                    equivalent_table_producer_offsets=[candidate[0] for candidate in candidates])
    elif two_mov_suffix:
        plan.update(rule='runtime-base-index-u8-ro-cmp-two-mov-suffix-lsl2-v1',
                    proof_start_offset=proof_start,preserved_source_offsets=[op.address for op in suffix_moves],
                    consumed_loaded_register=loaded,branch_consumes_target_register=target)
    elif direct:
        plan.update(rule='runtime-base-index-u8-ro-direct-cmp-lsl2-v1',proof_start_offset=proof_start)
        if fp_lr_pair:
            plan['rule']='runtime-base-index-u8-ro-fp-lr-pair-lsl2-v1'
    elif width==1:
        plan.update(rule='runtime-base-index-u8-ro-mask-alias-lsl2-v1',
                    mask_alias_offset=alias.address,proof_start_offset=proof_start)
    return plan


def runtime_readonly_guest_halfword_table(ins, by_pc, entries, raw, readonly_ranges):
    return _runtime_readonly_guest_table(ins,by_pc,entries,raw,readonly_ranges,2)


def runtime_readonly_guest_byte_table(ins, by_pc, entries, raw, readonly_ranges):
    return _runtime_readonly_guest_table(ins,by_pc,entries,raw,readonly_ranges,1)


def _observed_runtime_guest_table(ins, by_pc, entries, raw, readonly_ranges):
    """Three exact source prefixes establish facts at the existing load guard.

    A reloaded stack value is not inferred equal to the compared register.
    Original masks, reloads, parallel ALU and suffix stores stay in place.
    Their actual full64 index, table and target are checked before the load.
    """
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]

    branch=ins.address
    branch_word=value(branch)
    if branch_word is None or branch_word&0xFFFFFC1F!=0xD61F0000:
        return None
    target=branch_word>>5&31
    for distance in (8,12,16):
        load=branch-distance
        addition=value(load+4)
        load_word=value(load)
        if addition is None or load_word is None:
            continue
        loaded=addition>>16&31
        if addition!=0x8B000800|(loaded<<16)|(target<<5)|target:
            continue
        table_register,index=load_word>>5&31,load_word>>16&31
        registers_=(target,loaded,table_register,index)
        width=2 if load_word&~((31<<16)|(31<<5)|31)==0x78607800 else 1
        if load_word&~((31<<16)|(31<<5)|31)!=(0x78607800 if width==2 else 0x38606800) or load_word&31!=loaded:
            continue
        start,page,bound,guard,compare=load-28,load-12,4,None,None
        extra={}
        if (width==1 and registers_==(8,9,10,11) and distance==8 and
                (value(load-28),value(load-24),value(load-16))==(0x12001F68,0x7100111F,0xF94013EB)):
            rule='runtime-base-index-u8-ro-sp-reload-observed-lsl2-v1'
            compare,guard=load-24,load-20
            preserved=[load-16]
            extra['bound_basis']='runtime full64 reloaded index<=4; no spill equivalence or callee preservation claimed'
        elif (width==2 and registers_==(10,11,9,8) and distance==16 and
                (value(load-28),value(load-24),value(load-16),value(load+8),value(load+12))==
                (0x12001C48,0x7100111F,0x92401C48,0x2A0003FB,0xF90057E1)):
            rule='runtime-base-index-u16-ro-low8-observed-lsl2-v1'
            compare,guard=load-24,load-20
            preserved=[load-16,load+8,load+12]
            extra['bound_basis']='exact low8 source masks plus runtime full64 index<=4'
        elif (width==1 and registers_==(26,8,0,25) and distance==8 and
                tuple(value(load-d) for d in (20,16,12,8))==
                (0x8B0F0A23,0x0B1E00B9,0x51000739,0x12000739)):
            rule='runtime-base-index-u8-ro-mask3-observed-lsl2-v1'
            page,bound=load-28,3
            preserved=[load-d for d in (20,16,12,8)]
            extra.update(index_mask_offset=load-8,parallel_result_register=3)
            # Exact observed loop: increment W30, then CBNZ W16 returns to
            # the index ADD. This path intentionally skips the parallel X3
            # effect and table producers; the load guard proves actual facts.
            if value(load+0xBC)==0x110007DE and value(load+0xC0)==0x35FFF990:
                extra.update(guarded_index_entry_offsets=[load-16],
                             observed_loop_source_offsets=[load+0xBC,load+0xC0])
        elif (width==1 and registers_==(16,25,26,8) and
                (distance==12 and value(load-16)==0x120004A8 and value(load+8)==0xF9408BFE or
                 distance==8 and value(load-16)==0x12000508)):
            rule='runtime-base-index-u8-ro-mask3-observed-lsl2-v1'
            start,bound=load-16,3
            preserved=[load-16]+([load+8] if distance==12 else [])
            extra['index_mask_offset']=load-16
        else:
            continue
        if guard is not None:
            guard_op=by_pc.get(guard)
            if (guard_op is None or value(guard)&0xFF00001F!=0x54000008 or
                    guard<guard_op.operands[0].imm<=branch):
                continue
            extra.update(compare_offset=compare,guard_offset=guard)
        page_op,address=by_pc.get(page),by_pc.get(load-4)
        add=value(page+4)
        if (page_op is None or page_op.mnemonic!='adrp' or
                page_op.reg_name(page_op.operands[0].reg)!='x'+str(table_register) or add is None or
                add&0xFFC003FF!=0x91000000|(table_register<<5)|table_register or
                address is None or address.mnemonic!='adr' or
                address.reg_name(address.operands[0].reg)!='x'+str(target) or address.operands[1].imm!=branch+4):
            continue
        preload={page,page+4,load-4,load}
        allowed=preload|set(extra.get('guarded_index_entry_offsets',()))
        if any(pc in entries and pc not in allowed for pc in range(start+4,branch+4,4)):
            continue
        table=page_op.operands[1].imm+(add>>10&4095)
        size=width*(bound+1)
        if table%width or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
            continue
        data=raw[table:table+size]
        if len(data)!=size:
            continue
        values=sorted(set(struct.unpack('<'+('B' if width==1 else 'H')*(bound+1),data)))
        if values[-1]>4095:
            continue
        return dict(offset=branch,base=branch+4,target_register=target,
                    load_offset=load,table_register=table_register,index_register=index,loaded_register=loaded,
                    target_values=values,index_bound=bound,table_offset=table,table_bytes=size,
                    table_sha256=hashlib.sha256(data).hexdigest(),proof_start_offset=start,
                    producer_offsets=[page,page+4,load-4,load,load+4],
                    guarded_preload_entry_offsets=sorted(preload),
                    entry_policy='inline-preload-must-pass-runtime-guard-v1',
                    preserved_source_offsets=preserved,rule=rule,**extra)
    return None


def _scheduled_side_load_table(ins, by_pc, entries, raw, readonly_ranges):
    """Two observed CMP5 schedules retain a parallel unsigned W load."""
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address;word_=value(branch)
    if word_ is None or word_&0xFFFFFC1F!=0xD61F0000:
        return None
    target=word_>>5&31;load=branch-8;addition=value(branch-4);load_word=value(load)
    if addition is None or load_word is None:
        return None
    loaded=addition>>16&31;table_register,index=load_word>>5&31,load_word>>16&31
    registers_=(target,loaded,table_register,index)
    width=2 if load_word&~((31<<16)|(31<<5)|31)==0x78607800 else 1
    if (len(set(registers_))!=4 or any(r==18 or r>=29 for r in registers_) or
            addition!=0x8B000800|(loaded<<16)|(target<<5)|target or
            load_word!=(0x78607800 if width==2 else 0x38606800)|(index<<16)|(table_register<<5)|loaded):
        return None
    address=by_pc.get(load-4)
    if (address is None or address.mnemonic!='adr' or value(load-4)&31!=target or
            address.operands[1].imm!=branch+4):
        return None
    for distance in (16,24):
        compare,guard,side=load-distance,load-distance+4,load-distance+8
        guard_op=by_pc.get(guard);side_word=value(side)
        if (value(compare)!=0x7100141F|(index<<5) or guard_op is None or
                value(guard)&0xFF00001F!=0x54000008 or guard<guard_op.operands[0].imm<=branch or
                side_word is None or side_word&0xFFFFFC00 not in (0xB942A000,0xB9406800,0xB9401800) or
                side_word&31 in (*registers_,29,30,31) or side_word>>5&31==31 or
                side_word&0xFFFFFC00==0xB942A000 and 18 in (side_word&31,side_word>>5&31) or
                any(pc in entries for pc in range(compare+4,branch+4,4))):
            continue
        candidates=[]
        for pc in ((load-12,) if distance==24 else range(max(0,compare-512),compare,4)):
            page=by_pc.get(pc);add=value(pc+4)
            if (page is not None and page.mnemonic=='adrp' and value(pc)&31==table_register and
                    add is not None and add&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
                candidates.append((pc,pc+4,page.operands[1].imm+(add>>10&4095)))
        if len(candidates)!=1:
            continue
        page,add,table=candidates[0];size=6*width
        if table%width or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
            continue
        data=raw[table:table+size]
        if len(data)!=size:
            continue
        values=sorted(set(struct.unpack('<6'+('H' if width==2 else 'B'),data)))
        if values[-1]>4095:
            continue
        return dict(offset=branch,base=branch+4,target_register=target,load_offset=load,
                    table_register=table_register,index_register=index,loaded_register=loaded,
                    index_bound=5,table_offset=table,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                    target_values=values,compare_offset=compare,guard_offset=guard,proof_start_offset=compare,
                    preserved_source_offsets=[side],producer_offsets=[page,add,load-4,load,load+4],
                    permitted_source_rewrite_offsets=[side] if has18(by_pc[side]) else [],
                    rule=f'runtime-base-index-u{width*8}-ro-cmp5-side-load-lsl2-v1')
    return None


def _shared_table_compare(guard_pc, index, branch, by_pc, raw, root_entries, known_tables=()):
    """One W-CMP reaches HI through bounded flag-neutral mode branches."""
    if root_entries is None:
        return None
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    guard=by_pc.get(guard_pc);word_=value(guard_pc)
    if (guard is None or word_ is None or word_&0xFF00001F!=0x54000008 or
            guard_pc<guard.operands[-1].imm<=branch):
        return None
    begin=max(0,guard_pc-512)
    predecessors={pc:set() for pc in range(begin,guard_pc+4,4) if pc in by_pc}
    for pc in predecessors:
        if pc==guard_pc:continue
        op=by_pc[pc]
        if is_fatal_instruction(op) or op.group(CS_GRP_RET) or op.mnemonic=='br':
            successors=()
        elif op.mnemonic=='b':
            successors=(op.operands[-1].imm,)
        elif op.mnemonic in ('cbz','cbnz','tbz','tbnz') or op.mnemonic.startswith('b.'):
            successors=(op.operands[-1].imm,pc+4)
        else:
            successors=(pc+4,)
        for destination in successors:
            if destination in predecessors:predecessors[destination].add(pc)
    pending=[guard_pc];seen=set();compares=set();bit_bridge=False
    while pending:
        pc=pending.pop()
        if pc in seen:continue
        seen.add(pc);op=by_pc[pc];word_=value(pc)
        if len(seen)>16:return None
        if word_&0xFFC003FF==0x7100001F|(index<<5) and word_>>10&4095<=63:
            compares.add(pc);continue
        if pc in root_entries:return None
        if pc!=guard_pc:
            bit_test=op.mnemonic in ('tbz','tbnz') and not word_>>31
            if (op.mnemonic not in ('cbz','cbnz') and not bit_test or
                    word_&31 in (18,29,30,31) or op.operands[-1].imm<=pc):
                return None
            bit_bridge|=bit_test
        previous=predecessors[pc]
        if not previous:return None
        pending.extend(previous-seen)
    if len(compares)!=1:return None
    compare=next(iter(compares))
    protected=(seen-compares)|set(range(guard_pc,branch+4,4))
    if protected.intersection(root_entries):return None
    for op in by_pc.values():
        if op.mnemonic in ('b','bl','cbz','cbnz','tbz','tbnz') or op.mnemonic.startswith('b.'):
            if op.operands[-1].imm in protected and op.address not in seen:return None
        elif op.mnemonic in ('adr','adrp'):
            destination=op.operands[1].imm
            if destination in protected:return None
            following=value(op.address+4);register=value(op.address)&31
            if (op.mnemonic=='adrp' and following is not None and
                    following&0xFFC003FF==0x91000000|(register<<5)|register and
                    destination+(following>>10&4095) in protected):
                return None
    for collection in known_tables:
        for plan in collection.values():
            destinations={plan['base']+tag*4 for tag in plan.get('target_values',range(plan.get('count',0)))}
            if protected.intersection(destinations):return None
    return compare,value(compare)>>10&4095,dict(
        bound_candidate_kind='tb-shared-cmp' if bit_bridge else 'cbz-shared-cmp',
        shared_guard_offset=guard_pc,shared_compare_path_offsets=sorted(seen))


def _virtual_loaded_x18_native_target(ins, by_pc, entries, raw, readonly_ranges, *, root_entries=None, known_tables=()):
    """The observed RO switch loads guest X18, then consumes it in ADD."""
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=value(ins.address);target=branch>>5&31
    if branch&0xFFFFFC1F!=0xD61F0000 or target in (18,29,30,31):
        return None
    addition=ins.address-4;suffix=[];neutral_u16_mov=False
    expected_add=0x8B120800|(target<<5)|target
    if value(addition)!=expected_add:
        mask=value(addition);reg=0 if mask is None else mask&31
        neutral_u16_mov=(mask is not None and mask&~(0xFFFF<<5)==0x52800000|reg)
        if (not neutral_u16_mov and mask!=0x12001C00|(reg<<5)|reg or
                reg in (target,18,29,30,31)):
            return None
        suffix=[addition];addition-=4
    load=addition-4;word_=value(load)
    if value(addition)!=expected_add or word_ is None:
        return None
    width=2 if word_&~((31<<16)|(31<<5))==0x78607812 else 1
    table_register,index=word_>>5&31,word_>>16&31
    if (len({target,table_register,index})!=3 or any(r in (18,29,30,31) for r in (table_register,index)) or
            word_!=(0x78607812 if width==2 else 0x38606812)|(index<<16)|(table_register<<5) or
            suffix and (width!=(2 if neutral_u16_mov else 1) or reg in (table_register,index))):
        return None
    if neutral_u16_mov:
        suffix_page=by_pc.get(load-12);suffix_add=value(load-8)
        # This ordinary MOVZ suffix is approved only for the complete inline
        # u16 page/ADD/ADR/read core. It does not widen old byte/hoisted suffixes.
        if (suffix_page is None or suffix_page.mnemonic!='adrp' or value(load-12)&31!=table_register or
                suffix_add is None or suffix_add&0xFFC003FF!=0x91000000|(table_register<<5)|table_register):
            return None
    page_op=by_pc.get(load-12);inline_add=value(load-8)
    inline=(page_op is not None and page_op.mnemonic=='adrp' and
            value(load-12)&31==table_register and inline_add is not None and
            inline_add&0xFFC003FF==0x91000000|(table_register<<5)|table_register)
    copy_word=value(load-16);copy_source=0 if copy_word is None else copy_word>>16&31
    inline_copy=(inline and width==1 and copy_word is not None and
                 copy_word==0x2A0003E0|(copy_source<<16)|index and
                 copy_source not in (target,table_register,index,18,29,30,31))
    distances=(24,20,4) if inline_copy else (20,16,4) if inline else (12,8,4)
    compare,guard,address=(by_pc.get(load-distance) for distance in distances)
    compare_register=copy_source if inline_copy else index
    shared=None
    if (inline and not inline_copy and (compare is None or
            value(compare.address)&0x7FC003FF!=0x7100001F|(index<<5))):
        shared=_shared_table_compare(load-16,index,ins.address,by_pc,raw,root_entries,known_tables)
        if shared is not None:compare=by_pc[shared[0]]
    if (any(op is None for op in (compare,guard,address)) or
            # Only the W/X width bit may differ. The live load guard still
            # checks all 64 index bits, including entries after this compare.
            value(compare.address)&(0xFFC003FF if inline_copy else 0x7FC003FF)!=0x7100001F|(compare_register<<5) or
            value(guard.address)&0xFF00001F!=0x54000008 or guard.address<guard.operands[0].imm<=ins.address or
            address.mnemonic!='adr' or value(address.address)&31!=target):
        return None
    base=address.operands[1].imm;bound=value(compare.address)>>10&4095
    preload={address.address,load}
    if inline:
        if base!=ins.address+4 and not (shared is not None and compare.address<base<guard.address):
            return None
        preload.update((load-12,load-8))
    if inline_copy:preload.add(load-16)
    if shared is not None:preload.add(guard.address)
    if (base%4 or base not in by_pc or not (base<compare.address or base==ins.address+4 or
            shared is not None and compare.address<base<guard.address) or bound>(255 if inline_copy else 63) or
            any(pc in entries and pc not in preload for pc in range(guard.address if shared is not None else compare.address+4,ins.address+4,4))):
        return None
    candidates=[]
    # The complete inline page/ADD/ADR source owns this table candidate.
    # Actual table/base/full64 index are still checked before the virtual load.
    for pc in ((load-12,) if inline else range(max(0,compare.address-512),compare.address,4)):
        page=by_pc.get(pc);add=value(pc+4)
        if (page is not None and page.mnemonic=='adrp' and value(pc)&31==table_register and
                add is not None and add&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
            candidates.append((pc,pc+4,page.operands[1].imm+(add>>10&4095)))
    reaching=[]
    if candidates and len({row[2] for row in candidates})!=1:
        # A prior switch may have used the same table register for a different
        # RO table. Require a later explicit redefinition with a complete,
        # call-free source interval and no subsequent write to that register.
        # Incoming ADR/load entries still check the actual live table at LDR;
        # this does not infer constructor dominance or table-value equality.
        latest=candidates[-1]
        interval=[by_pc.get(pc) for pc in range(latest[1]+4,load,4)]
        if any(op is None or is_fatal_instruction(op) or op.mnemonic in ('svc','hvc','smc') or
               op.group(CS_GRP_CALL) or 'x'+str(table_register) in {
                   op.reg_name(r).replace('w','x',1) for r in op.regs_access()[1]}
               for op in interval):
            return None
        reaching=list(latest[:2]);candidates=[latest]
    if not candidates or len({row[2] for row in candidates})!=1:
        return None
    page,add,table=candidates[-1];size=width*(bound+1)
    if table%width or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
        return None
    data=raw[table:table+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<'+str(bound+1)+('H' if width==2 else 'B'),data)))
    if values[-1]>4095:
        return None
    if shared is not None:
        protected=(set(shared[2]['shared_compare_path_offsets'])-{compare.address})|set(range(guard.address,ins.address+4,4))
        if any(base+tag*4 in protected for tag in values):return None
    return dict(offset=ins.address,base=base,target_register=target,load_offset=load,
                table_register=table_register,index_register=index,loaded_register=18,virtual_loaded_register=18,
                index_bound=bound,table_offset=table,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                target_values=values,compare_offset=compare.address,guard_offset=guard.address,
                proof_start_offset=load-4 if shared is not None else compare.address,producer_offsets=[page,add,address.address,load,addition],
                permitted_source_rewrite_offsets=[load,addition],guarded_preload_entry_offsets=sorted(preload),
                **(shared[2] if shared is not None else {}),
                **(dict(bound_candidate_kind='virtual-loaded-inline-wcopy',index_copy_offset=load-16,
                        index_copy_source_register=copy_source) if inline_copy else {}),
                **({'preserved_source_offsets':suffix} if suffix else {}),
                **({'reaching_table_producer_offsets':reaching} if reaching else {}),
                equivalent_table_producer_offsets=[row[0] for row in candidates],
                entry_policy='adr-or-virtual-load-must-pass-runtime-guard-v1',
                rule=f'runtime-virtual-loaded-x18-native-target-u{width*8}-ro-lsl2-v1')


def virtual_index_x18_byte_native_target(ins, by_pc, entries, raw, readonly_ranges, *, root_entries=None):
    """Exact self-loaded W18/SUB/CMP8 index with a hoisted native byte table.

    This is separate from the pointer-read/W-copy halfword schedule. The same
    virtual-index emitter checks both live native bases and the full64 virtual
    index before the original byte read, without assuming guard dominance.
    """
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address;branch_word=value(branch)
    if branch_word is None or branch_word&0xFFFFFC1F!=0xD61F0000:
        return None
    target=branch_word>>5&31;load=branch-8;load_word=value(load)
    if load_word is None:
        return None
    table,loaded=load_word>>5&31,load_word&31
    read,subtract,compare,guard,address=(by_pc.get(load-d) for d in (20,16,12,8,4))
    if any(op is None for op in (read,subtract,compare,guard,address)):
        return None
    source=value(read.address)>>16&31
    if (len({target,table,loaded,source})!=4 or
            any(r in (18,29,30,31) for r in (target,table,loaded,source)) or
            value(read.address)!=0xB8606800|(source<<16)|(18<<5)|18 or
            value(subtract.address)!=0x51000652 or value(compare.address)!=0x7100225F or
            value(guard.address)&0xFF00001F!=0x54000008 or
            guard.address<guard.operands[-1].imm<=branch or
            address.mnemonic!='adr' or value(address.address)&31!=target or
            address.operands[-1].imm!=branch+4 or branch+4 not in by_pc or
            load_word!=0x38726800|(table<<5)|loaded or
            value(load+4)!=0x8B000800|(loaded<<16)|(target<<5)|target):
        return None
    all_entries=set(entries)|set(root_entries or ())
    if any(pc in all_entries for pc in (load+4,branch)):
        return None
    candidates=[]
    for pc in range(max(0,read.address-128),read.address-4,4):
        page=by_pc.get(pc);add=value(pc+4)
        if (page is None or page.mnemonic!='adrp' or value(pc)&31!=table or add is None or
                add&0xFFC003FF!=0x91000000|(table<<5)|table):
            continue
        # No guessed reaching definition or constructor entry. Calls and
        # register writes invalidate this candidate; the live base is still
        # checked even when execution enters later than the constructor.
        if pc+4 in all_entries:
            continue
        interval=[by_pc.get(at) for at in range(pc+8,load,4)]
        if any(op is None or is_fatal_instruction(op) or op.group(CS_GRP_CALL) or
               op.mnemonic in ('svc','hvc','smc') or 'x'+str(table) in {
                   op.reg_name(r).replace('w','x',1) for r in op.regs_access()[1]} or
               op.update_flags and op.operands and op.operands[0].type==ARM64_OP_REG and
                   op.reg_name(op.operands[0].reg).replace('w','x',1)=='x'+str(table)
               for op in interval):
            continue
        candidates.append((pc,pc+4,page.operands[-1].imm+(add>>10&4095)))
    if not candidates or len({row[2] for row in candidates})!=1:
        return None
    page,add,table_offset=candidates[-1];size=9
    if not any(a<=table_offset and table_offset+size<=b for a,b in readonly_ranges):
        return None
    data=raw[table_offset:table_offset+size]
    if len(data)!=size:
        return None
    values=sorted(set(data))
    return dict(offset=branch,base=branch+4,target_register=target,table_register=table,
                loaded_register=loaded,index_register=18,virtual_index_register=18,index_bound=8,
                table_offset=table_offset,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                target_values=values,load_offset=load,compare_offset=compare.address,guard_offset=guard.address,
                proof_start_offset=read.address,producer_offsets=[page,add,address.address,load,load+4],
                permitted_source_rewrite_offsets=[read.address,subtract.address,compare.address,load],
                preserved_source_offsets=[read.address,subtract.address,compare.address],
                guarded_preload_entry_offsets=list(range(read.address,load+4,4)),
                equivalent_table_producer_offsets=[row[0] for row in candidates],
                entry_policy='actual-table-target-base-full64-virtual-index-before-original-read-v1',
                rule='runtime-virtual-index-x18-native-target-u8-ro-self-load-sub-v1')


def virtual_index_x18_native_target(ins, by_pc, entries, raw, readonly_ranges, *, root_entries=None):
    """Original pointer read, W-copy, then a checked virtual-index u16 table.

    Earlier selected guards may branch straight to the pointer read. Their
    dominance is not assumed: the load checks live virtual X18 in full64,
    along with the actual native table and target bases, on every entrance.
    """
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address;word_=value(branch)
    if word_ is None or word_&0xFFFFFC1F!=0xD61F0000:
        return None
    target=word_>>5&31;load=branch-8;loaded_word=value(load)
    if loaded_word is None:
        return None
    table,loaded=loaded_word>>5&31,loaded_word&31
    if (len({target,table,loaded})!=3 or any(r in (18,29,30,31) for r in (target,table,loaded)) or
            loaded_word!=0x78727800|(table<<5)|loaded or
            value(load+4)!=0x8B000800|(loaded<<16)|(target<<5)|target):
        return None
    copied,pointer,compare,guard,page,add,address=(by_pc.get(load-d) for d in (16,20,28,24,12,8,4))
    if any(op is None for op in (copied,pointer,compare,guard,page,add,address)):
        return None
    alias=value(copied.address)>>16&31;side=value(pointer.address)&31
    if (len({target,table,loaded,alias,side})!=5 or
            any(r in (18,29,30,31) for r in (alias,side)) or
            value(copied.address)!=0x2A0003F2|(alias<<16) or
            value(pointer.address)!=0x39400240|side or
            value(compare.address)&0xFFC003FF!=0x7100001F|(alias<<5) or
            value(guard.address)&0xFF00001F!=0x54000008 or
            guard.address<guard.operands[-1].imm<=branch or
            page.mnemonic!='adrp' or value(page.address)&31!=table or
            value(add.address)&0xFFC003FF!=0x91000000|(table<<5)|table or
            address.mnemonic!='adr' or value(address.address)&31!=target or
            address.operands[-1].imm!=branch+4 or branch+4 not in by_pc):
        return None
    bound=value(compare.address)>>10&4095;preload=set(range(load-20,load+4,4))
    all_entries=set(entries)|set(root_entries or ())
    if bound>63 or any(pc in all_entries and pc not in preload for pc in range(compare.address+4,branch+4,4)):
        return None
    table_offset=page.operands[-1].imm+(value(add.address)>>10&4095);size=2*(bound+1)
    if table_offset%2 or not any(a<=table_offset and table_offset+size<=b for a,b in readonly_ranges):
        return None
    data=raw[table_offset:table_offset+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<'+str(bound+1)+'H',data)))
    if values[-1]>4095:
        return None
    return dict(offset=branch,base=branch+4,target_register=target,table_register=table,
                loaded_register=loaded,index_register=18,virtual_index_register=18,index_bound=bound,
                index_alias_source_register=alias,zero_extend_offset=copied.address,
                pointer_read_offset=pointer.address,pointer_read_result_register=side,
                table_offset=table_offset,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                target_values=values,load_offset=load,compare_offset=compare.address,guard_offset=guard.address,
                proof_start_offset=compare.address,producer_offsets=[copied.address,page.address,add.address,address.address,load,load+4],
                permitted_source_rewrite_offsets=[pointer.address,copied.address,load],
                preserved_source_offsets=[pointer.address,copied.address],guarded_preload_entry_offsets=sorted(preload),
                entry_policy='actual-table-target-base-full64-virtual-index-before-original-read-v1',
                rule='runtime-virtual-index-x18-native-target-u16-ro-wcopy-pointer-read-v1')


def _virtual_table_x18_native_target(ins, by_pc, entries, raw, readonly_ranges):
    """Inline or hoisted RO tables use virtual X18 and a native branch target.

    Actual virtual table, native target base and full64 index precede the
    original read. Normal-target scratch reservation is part of the lowering.
    """
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    word_=value(ins.address);target=word_>>5&31
    if word_&0xFFFFFC1F!=0xD61F0000 or target in (18,29,30,31):
        return None
    addition=None
    for pc in (ins.address-4,ins.address-8,ins.address-12):
        candidate=value(pc)
        if candidate is not None and candidate&~(31<<16)==0x8B000800|(target<<5)|target:
            addition=pc;break
    if addition is None:
        return None
    loaded=value(addition)>>16&31;load=addition-4;load_word=value(load)
    if load_word is None:
        return None
    width=2 if load_word&~((31<<16)|31)==0x78607A40 else 1
    index=load_word>>16&31
    if (len({target,loaded,index})!=3 or any(r in (18,29,30,31) for r in (loaded,index)) or
            load_word!=(0x78607A40 if width==2 else 0x38606A40)|(index<<16)|loaded):
        return None
    suffix=[];copied_suffix=addition==ins.address-12;alias=None
    if copied_suffix:
        copied,immediate,virtual_copy=value(load-8),value(load+8),value(load+12)
        if any(op is None for op in (copied,immediate,virtual_copy)):
            return None
        alias=copied>>16&31;ordinary=immediate&31
        if (width!=1 or alias in (target,loaded,index,18,29,30,31) or
                copied!=0x2A0003E0|(alias<<16)|index or
                immediate&~(0xFFFF<<5)!=0x52800000|ordinary or
                ordinary in (target,loaded,index,alias,18,29,30,31) or
                virtual_copy!=0x2A0003F2|(alias<<16)):
            return None
        suffix=[load+8,load+12]
    elif addition!=ins.address-4:
        op=by_pc.get(ins.address-4);candidate=value(ins.address-4)
        # SDK preserves one original ordinary-GPR SUB #2 after its target ADD.
        if (width!=2 or candidate is None or candidate&0xFFFFFC00!=0xD1000800 or
                candidate&31 in (target,loaded,index,18,29,30,31) or
                candidate>>5&31 in (18,29,30,31)):
            return None
        suffix=[op.address]
    address,page,add=(by_pc.get(load-distance) for distance in ((4,16,12) if copied_suffix else (4,12,8)))
    if (address is None or address.mnemonic!='adr' or value(load-4)&31!=target or
            address.operands[1].imm!=ins.address+4 or address.operands[1].imm not in by_pc):
        return None
    inline=(page is not None and add is not None and page.mnemonic=='adrp' and value(page.address)&31==18 and
            value(add.address)&0xFFC003FF==0x91000252)
    if copied_suffix and not inline:
        return None
    compare=guard=None;side=[]
    for distance in ((28,) if copied_suffix else (20,24) if inline else (12,)):
        candidate,conditional=by_pc.get(load-distance),by_pc.get(load-distance+4)
        if (candidate is None or conditional is None or
                value(candidate.address)&0xFFC003FF!=0x7100001F|((alias if copied_suffix else index)<<5) or
                value(conditional.address)&0xFF00001F!=0x54000008 or
                conditional.address<conditional.operands[0].imm<=ins.address):
            continue
        if copied_suffix:
            side_word=value(load-20)
            if (side_word is None or side_word&0xFFC00000!=0xB9400000 or
                    side_word&31 in (target,loaded,index,alias,ordinary,18,29,30,31) or
                    side_word>>5&31 in (18,29,30,31)):
                continue
            side=[load-20]
        elif distance==24:
            side_word=value(load-16)
            if (width!=1 or side_word is None or side_word&0xFFFFFC00!=0xB9405000 or
                    side_word&31 in (target,loaded,index,18,29,30,31) or
                    side_word>>5&31 in (18,29,30,31)):
                continue
            side=[load-16]
        compare,guard=candidate,conditional;break
    if compare is None:
        return None
    bound=value(compare.address)>>10&4095
    preload=set(range(load-(16 if copied_suffix else 12),load+4,4)) if inline else {load-4,load}
    if bound>63 or any(pc in entries and pc not in preload for pc in range(compare.address+4,ins.address+4,4)):
        return None
    size=width*(bound+1)
    if not inline:
        candidates=[]
        for pc in range(max(0,load-2048),compare.address,4):
            candidate=by_pc.get(pc);following=value(pc+4)
            if (candidate is not None and candidate.mnemonic=='adrp' and value(pc)&31==18 and
                    following is not None and following&0xFFC003FF==0x91000252):
                table=candidate.operands[1].imm+(following>>10&4095)
                if table%width==0 and any(begin<=table and table+size<=end for begin,end in readonly_ranges):
                    candidates.append((pc,pc+4,table))
        if not candidates or len({row[2] for row in candidates})!=1:
            return None
        # A hoisted constructor is a discovered candidate, not a preservation
        # or dominance claim. The existing 48B leaf checks actual virtual X18,
        # actual target base and the full64 index before the original read.
        page=by_pc[candidates[-1][0]];add=by_pc[candidates[-1][1]]
    table=page.operands[1].imm+(value(add.address)>>10&4095)
    if table%width or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
        return None
    data=raw[table:table+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<'+str(bound+1)+('H' if width==2 else 'B'),data)))
    if values[-1]>4095:
        return None
    return dict(offset=ins.address,base=address.operands[1].imm,target_register=target,
                load_offset=load,table_register=18,virtual_table_register=18,index_register=index,
                loaded_register=loaded,index_bound=bound,table_offset=table,table_bytes=size,
                table_sha256=hashlib.sha256(data).hexdigest(),target_values=values,
                compare_offset=compare.address,guard_offset=guard.address,proof_start_offset=compare.address,
                producer_offsets=[page.address,add.address,*([load-8] if copied_suffix else []),address.address,load,addition],
                permitted_source_rewrite_offsets=([page.address,add.address,load] if inline else [load])+([load+12] if copied_suffix else []),
                guarded_preload_entry_offsets=sorted(preload),preserved_source_offsets=side+suffix,
                entry_policy='inline-virtual-table-must-pass-runtime-guard-v1',
                **(dict(index_alias_source_register=alias,zero_extend_offset=load-8,
                        virtual_suffix_copy_offset=load+12) if copied_suffix else {}),
                rule=f'runtime-virtual-table-x18-native-target-u{width*8}-ro-'+
                     ('copied-index-suffix-' if copied_suffix else '' if inline else 'hoisted-')+'lsl2-v1')


def _scheduled_native_readonly_table(ins, by_pc, entries, raw, readonly_ranges):
    """Observed schedules use the existing actual-value load preflight."""
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address;branch_word=value(branch)
    if branch_word is None or branch_word&0xFFFFFC1F!=0xD61F0000:
        return None
    target=branch_word>>5&31
    for kind,width,distance in (('parallel-byte',1,8),('copy-halfword',2,24),
                                ('backward-store',2,12),('zero-halfword',2,12),('self-copy-halfword',2,8),
                                ('pair-byte',1,12),('save-target-halfword',2,8),('loop-byte',1,16),
                                ('side-copy-halfword',2,8),('mask-back-byte',1,8),
                                ('mask-alias-byte',1,8),('mask-alias-halfword',2,8),
                                ('backward-alu-byte',1,12)):
        load=branch-distance;word_=value(load);addition=load+4
        if word_ is None or value(addition) is None:
            continue
        loaded,table_register,index=word_&31,word_>>5&31,word_>>16&31
        roles=(target,loaded,table_register,index)
        if (len(set(roles))!=4 or any(r==18 or r>=29 for r in roles) or
                word_!=(0x38606800 if width==1 else 0x78607800)|(index<<16)|(table_register<<5)|loaded or
                value(addition)!=0x8B000800|(loaded<<16)|(target<<5)|target):
            continue
        address=by_pc.get(load-4)
        if address is None or address.mnemonic!='adr' or value(load-4)&31!=target:
            continue
        permitted=[];preserved=[];extra={};prior_table=False
        if kind=='parallel-byte':
            compare,guard,page,table_add=load-32,load-28,load-16,load-12
            first,constant,last=value(load-24),value(load-20),value(load-8)
            if any(op is None for op in (first,constant,last)):
                continue
            parallel=first&31
            if (first&~((31<<16)|(31<<5)|31)!=0x8B000800 or
                    parallel in (*roles,18,29,30,31) or
                    any(r in (18,29,30,31) for r in (first>>5&31,first>>16&31)) or
                    constant&~(0xFFFF<<5)!=0x52800000|target or
                    last!=0x8B000000|(target<<16)|(parallel<<5)|parallel):
                continue
            preserved=[load-24,load-20,load-8]
        elif kind=='copy-halfword':
            compare,guard,page,table_add=load-28,load-24,load-16,load-12
            copy,side=value(load-8),value(load-20)
            suffix=[value(load+delta) for delta in (8,12,16,20)]
            if copy is None or side is None or any(op is None for op in suffix):
                continue
            alias=copy>>16&31;side_register,side_base=side&31,side>>5&31
            zeroed,immediate=suffix[1]&31,suffix[2]&31
            if (copy!=0x2A0003E0|(alias<<16)|index or alias in (*roles,18,29,30,31) or
                    side!=0xB9400800|(side_base<<5)|side_register or
                    side_register in (*roles,alias,18,29,30,31) or side_base in (18,29,30,31) or
                    suffix[0]!=0xAA1F03F2 or suffix[1]&~31!=0xAA1F03E0 or
                    zeroed in (*roles,alias,18,29,30,31) or suffix[2]!=0x528008C0|immediate or
                    immediate in (*roles,alias,18,29,30,31) or
                    suffix[3]!=0x2A0003E0|(alias<<16)|table_register):
                continue
            preserved=[load-20,*range(load+8,branch,4)];permitted=[load+8]
            extra=dict(zero_extend_offset=load-8,index_alias_source_register=alias)
        elif kind=='zero-halfword':
            compare,guard,page,table_add=load-20,load-16,load-12,load-8
            suffix=value(load+8)
            if (suffix is None or suffix&~31!=0x2A1F03E0 or
                    suffix&31 in (*roles,18,29,30,31)):
                continue
            preserved=[load+8]
        elif kind=='self-copy-halfword':
            compare,guard,page,table_add=load-24,load-20,load-12,load-8
            if value(load-16)!=0x2A0003E0|(index<<16)|index:
                continue
            preserved=[load-16];extra=dict(zero_extend_offset=load-16)
        elif kind=='side-copy-halfword':
            compare,guard,page,table_add=load-28,load-24,load-12,load-8
            side,copy=value(load-20),value(load-16)
            if side is None or copy is None:
                continue
            alias,side_register=copy>>16&31,side&31
            if (copy!=0x2A0003E0|(alias<<16)|index or alias in (*roles,18,29,30,31) or
                    side!=0x39400000|(index<<5)|side_register or
                    side_register in (*roles,alias,18,29,30,31)):
                continue
            preserved=[load-20,load-16]
            extra=dict(zero_extend_offset=load-16,index_alias_source_register=alias)
        elif kind=='mask-back-byte':
            compare,guard=load-12,load-8
            mask,subtract=value(load-20),value(load-16)
            if (mask is None or mask&~(31<<5)!=0x12001C00|index or
                    mask>>5&31 in (18,29,30,31) or subtract!=0x51000800|(index<<5)|index):
                continue
            preserved=[load-20,load-16];prior_table=True
        elif kind.startswith('mask-alias-'):
            compare,guard,page,table_add=load-24,load-20,load-12,load-8
            word_mask,full_mask=value(load-28),value(load-16)
            if word_mask is None or full_mask is None:
                continue
            source,alias=word_mask>>5&31,word_mask&31
            if (source in (18,29,30,31) or alias not in (target,index) or
                    word_mask!=0x12001C00|(source<<5)|alias or
                    full_mask!=0x92401C00|(source<<5)|index):
                continue
            preserved=[load-28,load-16];extra=dict(bound_alias_register=alias,index_mask_offset=load-16)
        elif kind=='pair-byte':
            compare,guard=load-16,load-8
            pair,suffix=value(load-12),value(load+8)
            if pair is None or suffix is None:
                continue
            first,second,pair_base=pair&31,pair>>10&31,pair>>5&31
            if (len({first,second,pair_base})!=3 or
                    any(r in (*roles,18,29,30,31) for r in (first,second,pair_base)) or
                    pair!=0x29448000|(second<<10)|(pair_base<<5)|first or
                    suffix!=0x52800020|pair_base):
                continue
            preserved=[load-12,load+8];prior_table=True
        elif kind=='save-target-halfword':
            compare,guard=load-16,load-12
            move=value(load-8)
            if (move is None or move!=0x2A0003E0|(target<<16)|(move&31) or
                    move&31 in (*roles,18,29,30,31)):
                continue
            preserved=[load-8];prior_table=True
        elif kind=='backward-alu-byte':
            compare,guard=load-28,load-24
            first,second,third,fourth=(value(load-distance) for distance in (20,16,12,8))
            suffix=value(load+8)
            if any(op is None for op in (first,second,third,fourth,suffix)):
                continue
            parallel,parallel_base,side=second&31,second>>5&31,second>>16&31
            load_base,term,multiplier=first>>5&31,third>>16&31,fourth>>16&31
            register_mask=(31<<16)|(31<<5)|31
            if (parallel==side or any(r in (*roles,18,29,30,31) for r in (parallel,side)) or
                    any(r in (18,29,30,31) for r in (load_base,parallel_base,term,multiplier)) or
                    first&0xFFC0001F!=0xF9400000|target or
                    second&~register_mask!=0x8B000800 or
                    third!=0x8B000000|(term<<16)|(parallel<<5)|parallel or
                    fourth!=0x9B000000|(multiplier<<16)|(target<<10)|(side<<5)|side or
                    suffix&0xFFC003FF!=0x91000000|(side<<5)|side):
                continue
            # The temporary target is consumed by MADD before ADR replaces it.
            # Neither the hoisted table nor the index is modified by this exact
            # four-op prefix or the post-load side ADD. All effects stay in place;
            # the existing preflight checks actual table/base/full64 index at LDRB.
            preserved=[*range(load-20,load-4,4),load+8];prior_table=True
            extra=dict(table_producer_search_bytes=512)
        elif kind=='loop-byte':
            compare,guard=load-36,load-32
            prefix=[value(pc) for pc in range(load-28,load-4,4)]
            suffix=[value(load+8),value(load+12)]
            if any(op is None for op in (*prefix,*suffix)):
                continue
            register_mask=(31<<16)|(31<<5)|31
            shapes=[op&~register_mask for op in prefix]
            if (shapes[0]!=0x1B007C00 or prefix[1]&~((31<<16)|31)!=0x2A0003E0 or
                    not (shapes[2]==0x8B000000 or prefix[2]&~((31<<5)|31)==0xD37FF800) or
                    shapes[3]!=0x8B000000 or shapes[4:]!=[0x1B007C00,0x1B007C00]):
                continue
            source_registers=[]
            for ordinal,op in enumerate(prefix):
                source_registers.extend((op&31,op>>16&31) if ordinal==1 else
                                        (op&31,op>>5&31) if ordinal==2 and shapes[2]!=0x8B000000 else
                                        (op&31,op>>5&31,op>>16&31))
            if (any(r==18 or r>=29 for r in source_registers) or
                    any(op&31 in (table_register,index) for op in prefix) or
                    len({op&31 for op in suffix})!=2 or
                    any(op&31 in (*roles,18,29,30,31) or op>>5&31 in (18,29,30,31) or
                        op>>16&31!=op&31 or op&~register_mask not in (0x8B000000,0x8B204400)
                        for op in suffix)):
                continue
            preserved=[*range(load-28,load-4,4),load+8,load+12];prior_table=True
        else:
            compare,guard,page,table_add=load-20,load-16,load-12,load-8
            subtraction=value(load-24)
            if (subtraction is None or subtraction&0xFFC0001F!=0x51000000|index or
                    subtraction>>5&31 in (18,29,30,31) or value(load+8)!=0xA9015BFC):
                continue
            # This offset pair store does not update SP. Keep its original word;
            # the source function's checked frame allocation remains mandatory.
            preserved=[load+8]
            extra=dict(index_subtract_offset=load-24,index_subtract_immediate=subtraction>>10&4095,
                       preserved_stack_store_word=0xA9015BFC)
        compared=by_pc.get(compare);guarded=by_pc.get(guard)
        compare_register=extra.get('bound_alias_register',extra.get('index_alias_source_register',index))
        if (compared is None or guarded is None or
                value(compare)&0xFFC003FF!=0x7100001F|(compare_register<<5) or
                value(guard)&0xFF00001F!=0x54000008 or
                guard<guarded.operands[0].imm<=branch):
            continue
        bound=value(compare)>>10&4095
        if bound>(255 if kind=='backward-store' else 63):
            continue
        base=address.operands[1].imm
        if kind in ('copy-halfword','zero-halfword','save-target-halfword','side-copy-halfword','mask-alias-byte','mask-alias-halfword'):
            if base!=branch+4:
                continue
        elif base%4 or base>=compare or base not in by_pc:
            continue
        if prior_table:
            candidates=[]
            size=width*(bound+1)
            lookback=512 if kind=='backward-alu-byte' else 256
            for pc in range(max(0,compare-lookback),compare,4):
                page_op=by_pc.get(pc);add_word=value(pc+4)
                if (page_op is not None and page_op.mnemonic=='adrp' and value(pc)&31==table_register and
                        add_word is not None and add_word&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
                    candidate=page_op.operands[1].imm+(add_word>>10&4095)
                    # Prior register reuse may construct an unrelated BSS
                    # object. Only complete immutable tables are candidates;
                    # distinct RO candidates still reject, actual bases are
                    # still checked before the source load.
                    if candidate%width==0 and any(begin<=candidate and candidate+size<=end for begin,end in readonly_ranges):
                        candidates.append((pc,pc+4,candidate))
            if not candidates or len({row[2] for row in candidates})!=1:
                continue
            page,table_add,_=candidates[-1]
        page_op=by_pc.get(page);add_word=value(table_add)
        if (page_op is None or page_op.mnemonic!='adrp' or value(page)&31!=table_register or
                add_word is None or add_word&0xFFC003FF!=0x91000000|(table_register<<5)|table_register):
            continue
        preload={page,table_add,load-4,load}
        if kind in ('copy-halfword','save-target-halfword'):preload.add(load-8)
        if kind=='loop-byte':preload.add(load-28)
        if kind=='side-copy-halfword':preload.add(load-20)
        if any(pc in entries and pc not in preload for pc in range(compare+4,branch+4,4)):
            continue
        table=page_op.operands[1].imm+(add_word>>10&4095);size=width*(bound+1)
        if table%width or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
            continue
        data=raw[table:table+size]
        if len(data)!=size:
            continue
        values=sorted(set(struct.unpack('<'+str(bound+1)+('H' if width==2 else 'B'),data)))
        # Native BR keeps the exact immutable sparse offsets; it allocates no
        # dense virtual-X18 veneer. Every target still undergoes code discovery
        # and independent selected-code validation before publication.
        if kind!='backward-store' and values[-1]>4095:
            continue
        return dict(offset=branch,base=base,target_register=target,load_offset=load,
                    table_register=table_register,index_register=index,loaded_register=loaded,
                    index_bound=bound,table_offset=table,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                    target_values=values,compare_offset=compare,guard_offset=guard,proof_start_offset=compare,
                    producer_offsets=[page,table_add,load-4,load,addition],preserved_source_offsets=preserved,
                    permitted_source_rewrite_offsets=permitted,guarded_preload_entry_offsets=sorted(preload),
                    rule=f'runtime-native-{kind}-ro-lsl2-v1',**extra)
    return None


def _assembled_byte_readonly_table(ins, by_pc, entries, raw, readonly_ranges):
    """Two byte-composition schedules retain their existing X18 lowering."""
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address;branch_word=value(branch)
    if branch_word is None or branch_word&0xFFFFFC1F!=0xD61F0000:
        return None
    target=branch_word>>5&31
    for backward,distance,prefix_bytes in ((False,16,36),(True,8,48)):
        load=branch-distance;loaded_word=value(load);addition=value(load+4)
        if loaded_word is None or addition is None:
            continue
        loaded,table_register,index=loaded_word&31,loaded_word>>5&31,loaded_word>>16&31
        roles=(target,loaded,table_register,index)
        if (len(set(roles))!=4 or any(r==18 or r>=29 for r in roles) or
                loaded_word!=0x38606800|(index<<16)|(table_register<<5)|loaded or
                addition!=0x8B000800|(loaded<<16)|(target<<5)|target):
            continue
        compare=load-prefix_bytes;guard=by_pc.get(compare+4);address=by_pc.get(load-4)
        if (value(compare)!=0x7100101F|(index<<5) or guard is None or
                value(compare+4)&0xFF00001F!=0x54000008 or compare+4<guard.operands[0].imm<=branch or
                address is None or address.mnemonic!='adr' or value(load-4)&31!=target or
                any(pc in entries for pc in range(compare+4,branch+4,4))):
            continue
        base=address.operands[1].imm
        if (backward and (base%4 or base>=compare or base not in by_pc) or
                not backward and base!=branch+4):
            continue
        if not backward:
            ops=[value(load-d) for d in (28,24,20,16,12,8)]
            suffix=[value(load+d) for d in (8,12)]
            if any(op is None for op in (*ops,*suffix)):
                continue
            p,q,r,s=ops[0]&31,ops[1]&31,ops[3]&31,ops[4]&31
            other=suffix[0]>>5&31
            if (len({p,q,r,s})!=4 or any(reg==18 or reg>=29 for reg in (p,q,r,s,other)) or
                    any(reg in roles for reg in (p,q,s)) or r in (loaded,table_register,index) or
                    other in (*roles,p,q,r,s) or
                    ops!=[0x39402800|(18<<5)|p,0x39402C00|(18<<5)|q,0xB3781C00|(p<<5)|q,
                          0x39402000|(18<<5)|r,0x39402400|(18<<5)|s,0xB3781C00|(r<<5)|s] or
                    suffix!=[0x8B000000|(q<<16)|(other<<5)|q,0xD341FC00|(s<<5)|p]):
                continue
            permitted=[load-d for d in (28,24,16,12)]
            preserved=[*range(compare+8,load-4,4),load+8,load+12]
        else:
            ops=[value(load-d) for d in (40,36,32,28,24,20,16,12,8)]
            if any(op is None for op in ops):
                continue
            source_base,p,other=ops[0]>>5&31,ops[1]&31,ops[6]>>5&31
            if (len({source_base,p,other})!=3 or
                    any(reg in (*roles,18,29,30,31) for reg in (source_base,p,other)) or
                    ops!=[0x39402812|(source_base<<5),0x39402C00|(source_base<<5)|p,
                          0xB3781C00|(18<<5)|p,0x39402000|(source_base<<5)|target,
                          0x39402400|(source_base<<5)|loaded,0x53185C00|(target<<5)|target,
                          0x8B000012|(p<<16)|(other<<5),0x93403C00|(target<<5)|p,
                          0xAA000000|(loaded<<16)|(p<<5)|p]):
                continue
            permitted=[load-d for d in (40,32,16)]
            preserved=list(range(compare+8,load-4,4))
        candidates=[]
        for pc in range(max(0,compare-128),compare,4):
            page,add=by_pc.get(pc),value(pc+4)
            if (page is not None and page.mnemonic=='adrp' and value(pc)&31==table_register and
                    add is not None and add&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
                candidates.append((pc,pc+4,page.operands[1].imm+(add>>10&4095)))
        if not candidates or len({row[2] for row in candidates})!=1:
            continue
        page,add,table=candidates[-1]
        if not any(begin<=table and table+5<=end for begin,end in readonly_ranges):
            continue
        data=raw[table:table+5]
        if len(data)!=5:
            continue
        return dict(offset=branch,base=base,target_register=target,load_offset=load,
                    table_register=table_register,index_register=index,loaded_register=loaded,
                    index_bound=4,table_offset=table,table_bytes=5,table_sha256=hashlib.sha256(data).hexdigest(),
                    target_values=sorted(set(data)),compare_offset=compare,guard_offset=compare+4,
                    proof_start_offset=compare,producer_offsets=[page,add,load-4,load,load+4],
                    preserved_source_offsets=preserved,permitted_source_rewrite_offsets=permitted,
                    equivalent_table_producer_offsets=[row[0] for row in candidates],
                    rule='runtime-native-byte-composition-'+('backward' if backward else 'forward')+'-ro-lsl2-v1')
    return None


def _reaching_table_candidates(load, register, current_branch, by_pc, candidates, known_tables, *, exclude_closed=False):
    """Select one constant over bounded selected CFG; never authorize an entry.

    known_tables contains only the caller's independently validated plan maps.
    The current dispatch cannot supply an edge for its own candidate proof.
    Permitted ADR/LDR entries still rely on the actual emitted read guard.
    """
    start=max(0,load-4096);end=load+4096
    selected={pc:by_pc[pc] for pc in range(start,end,4) if pc in by_pc}
    predecessors={pc:set() for pc in selected};edges={};successor_edges={}
    for collection in known_tables:
        for pc,plan in collection.items():
            if pc==current_branch or pc not in selected:
                continue
            if selected[pc].mnemonic!='br' or plan.get('offset')!=pc:
                return None
            targets={plan['base']+value*4 for value in plan.get('target_values',range(plan.get('count',0)))}
            if not targets or not targets<=by_pc.keys():
                return None
            if pc in edges and edges[pc]!=targets:
                return None
            edges[pc]=targets
    for pc,op in selected.items():
        if is_fatal_instruction(op) or op.group(CS_GRP_RET):
            successors=()
        elif op.mnemonic=='br':
            successors=edges.get(pc,())
        elif op.mnemonic=='b':
            successors=(op.operands[-1].imm,)
        elif op.mnemonic.startswith('b.') or op.mnemonic in ('cbz','cbnz','tbz','tbnz'):
            successors=(op.operands[-1].imm,pc+4)
        elif op.group(CS_GRP_JUMP):
            successors=() # Unresolved transfers supply no candidate proof.
        else:
            successors=(pc+4,)
        successor_edges[pc]=successors
        for target in successors:
            if target in predecessors:predecessors[target].add(pc)
    if exclude_closed:
        # Candidate selection only, not dominance or entry authority. An
        # unrelated definition is removable only when every finite selected
        # route closes without this load. Unknown overrides any clean route.
        reaching=[]
        for row in candidates:
            pending=[row[1]+4];seen=set();read=False;unknown=False
            while pending:
                pc=pending.pop()
                if pc==load:
                    read=True;continue
                if pc in seen:continue
                seen.add(pc);op=selected.get(pc)
                if op is None:
                    unknown=True;continue
                if is_fatal_instruction(op) or op.group(CS_GRP_RET):continue
                if (op.group(CS_GRP_CALL) or op.mnemonic in ('svc','hvc','smc') or
                        'x'+str(register) in _native_table_writes(op)):
                    unknown=True;continue
                successors=successor_edges[pc]
                if not successors:
                    unknown=True;continue # An unresolved transfer is no exit.
                pending.extend(successors)
            if unknown:return None
            if read:reaching.append(row)
        if not reaching or len({row[2] for row in reaching})!=1:return None
        return sorted(set(reaching))
    definitions={}
    for row in candidates:definitions.setdefault(row[1],[]).append(row)
    pending=list(predecessors.get(load,()));seen=set();reaching=[]
    if not pending:return None
    while pending:
        pc=pending.pop()
        if pc in seen:continue
        seen.add(pc);op=selected[pc]
        if pc in definitions:
            reaching.extend(definitions[pc]);continue
        writes=_native_table_writes(op)
        if ('x'+str(register) in writes or register<19 and
                (op.group(CS_GRP_CALL) or op.mnemonic in ('svc','hvc','smc'))):
            return None
        previous=predecessors[pc]
        if not previous:return None
        pending.extend(previous-seen)
    if not reaching or len({row[2] for row in reaching})!=1:return None
    return sorted(set(reaching))


def _native_u16_boolean_index(load, target, loaded, table, index, by_pc):
    """Four disjoint one-bit W fields provide a finite 0..15 candidate.

    Exact W encodings establish zero-extension and keep the original CMP/
    CSET ordering, GPR and SP-read effects. This supplies no dominance or
    entry authority; the original load still checks its actual full64 index.
    """
    pcs=list(range(load-64,load-12,4));ops=[by_pc.get(pc) for pc in pcs]
    if any(op is None for op in ops):
        return None
    words=[struct.unpack('<I',op.bytes)[0] for op in ops]
    shifted,source,second,temporary=words[0]&31,words[0]>>5&31,words[2]>>10&31,words[4]&31
    registers_=(shifted,source,second,temporary)
    if len(set(registers_))!=4 or any(r in (target,loaded,table,index,18,29,30,31) for r in registers_):
        return None
    expected=[0x531E7400|(source<<5)|shifted,0x121D0000|(shifted<<5)|index,
              0x294703E0|(second<<10)|shifted,0x7100001F|(shifted<<5),0x1A9FD7E0|temporary,
              0x7100001F|(second<<5),0x331E0000|(temporary<<5)|index,0x1A9FD7E0|temporary,
              0x331F0000|(temporary<<5)|index,0xB94043E0|temporary,
              0x7100001F|(temporary<<5),0x1A9FD7E0|table,0x2A000000|(table<<16)|(index<<5)|index]
    if words!=expected:
        return None
    return dict(bound_candidate_kind='u16-boolean-composition',bound_transform_offset=load-16,
                boolean_source_offsets=pcs,boolean_native_sources=list(registers_),boolean_field_bits=[3,2,1,0])


def native_signed32_readonly_table(ins, by_pc, entries, raw, readonly_ranges, *, text_size=None, protected_ranges=(), known_tables=()):
    """Finite signed byte offsets retain their original native LDRSW/ADD/BR.

    Source constants and bounds are candidates only. The existing leaf load
    guard checks the actual immutable table and full64 index before reading.
    No prior value of the native target is an address-base requirement.
    """
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    def ordinary(register):return register not in (18,29,30,31)
    def terminal(op):
        return (op is None or is_fatal_instruction(op) or op.mnemonic in ('svc','hvc','smc') or
                any(op.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)))
    branch=ins.address;branch_word=value(branch)
    if text_size is None or branch_word is None or branch_word&0xFFFFFC1F!=0xD61F0000:
        return None
    target=branch_word>>5&31
    if not ordinary(target):return None
    addition=None
    for pc in range(branch-4,max(-1,branch-68),-4):
        op=by_pc.get(pc)
        if terminal(op):return None
        if 'x'+str(target) in _native_table_writes(op):
            addition=pc;break
    if addition is None:return None
    add_word=value(addition);loaded=add_word>>5&31;table_register=add_word>>16&31
    if (not all(ordinary(r) for r in (loaded,table_register)) or
            add_word!=0x8B000000|(table_register<<16)|(loaded<<5)|target or
            table_register in (loaded,target)):
        return None
    load=None
    for pc in range(addition-4,max(-1,addition-68),-4):
        op=by_pc.get(pc)
        if terminal(op):return None
        if 'x'+str(loaded) in _native_table_writes(op):load=pc;break
    if load is None:return None
    load_word=value(load);index=load_word>>16&31
    if (not ordinary(index) or table_register==index or
            load_word!=0xB8A07800|(index<<16)|(table_register<<5)|loaded or
            target!=loaded and index in (target,loaded)):
        return None
    if any(pc in entries for pc in range(load+4,branch+4,4)):
        return None
    permitted=[]
    for pc in range(load+4,branch,4):
        op=by_pc.get(pc)
        if pc==addition:continue
        if (terminal(op) or op.update_flags or op.mnemonic not in ('add','mov','lsl','ldr','ldp','nop') or
                _native_table_writes(op)&{'sp','x29','x30','nzcv'}):return None
        protected={loaded,table_register} if pc<addition else {target}
        if _native_table_writes(op)&{'x'+str(register) for register in protected}:return None
        kind=site_kind(op)
        if kind is not None and kind!='x18':return None
        if kind=='x18':permitted.append(pc)
    bounds=[]
    for compare in range(max(0,load-128),load,4):
        word_=value(compare)
        if word_ is None:continue
        compared=word_>>5&31
        if not ordinary(compared):continue
        if word_&0xFFC003FF==0x7100001F|(compared<<5):
            bound=word_>>10&4095;kind='cmp-w-hi'
        elif word_&~((31<<16)|(31<<5))==0x7A403802:
            # CCMP's false arm emits NZCV=2 => HI, so only the true comparison
            # arm can reach the read. No earlier condition is borrowed.
            bound=word_>>16&31;kind='ccmp-w-nzcv2-lo-hi'
        else:continue
        if bound>63:continue
        guard=None
        for pc in range(compare+4,load,4):
            op=by_pc.get(pc)
            if op is not None and value(pc)&0xFF00001F==0x54000008:
                if not pc<op.operands[-1].imm<=branch:guard=pc
                break
            if (terminal(op) or op.update_flags or
                    _native_table_writes(op)&{'x'+str(compared),'x'+str(index),'nzcv'}):break
        if guard is None:continue
        copied=compared==index;valid=True;copies=[]
        for pc in range(guard+4,load,4):
            op=by_pc.get(pc)
            if terminal(op) or op.update_flags or _native_table_writes(op)&{'sp','x29','x30','nzcv'}:
                valid=False;break
            written=_native_table_writes(op)
            if not copied and 'x'+str(compared) in written:
                valid=False;break
            if 'x'+str(index) in written:
                if value(pc)==0x2A0003E0|(compared<<16)|index:
                    copied=True;copies.append(pc)
                elif copied and value(pc) in (0x2A0003E0|(index<<16)|index,
                                                0x92407C00|(index<<5)|index):
                    copies.append(pc)
                else:valid=False;break
        if valid and copied:bounds.append((compare,guard,bound,kind,copies))
    if len(bounds)!=1:return None
    compare,guard,bound,bound_kind,copies=bounds[0];size=4*(bound+1)
    table_regs={table_register}
    for pc in range(max(0,load-64),load,4):
        word_=value(pc)
        if word_ is not None and word_&~(31<<16)==0xAA0003E0|table_register:
            source=word_>>16&31
            if ordinary(source):table_regs.add(source)
    candidates=[];local=[]
    for page_pc in range(max(0,load-512),load,4):
        page=by_pc.get(page_pc);word_=value(page_pc)
        if page is None or page.mnemonic!='adrp' or word_&31 not in table_regs:continue
        register=word_&31
        for add_pc in range(page_pc+4,min(page_pc+44,load),4):
            op=by_pc.get(add_pc);word_=value(add_pc)
            if word_ is not None and word_&0xFFC003FF==0x91000000|(register<<5)|register:
                table=page.operands[1].imm+(word_>>10&4095)
                if table%4 or not any(a<=table and table+size<=b for a,b in readonly_ranges):break
                last=add_pc;copy=None
                if register!=table_register:
                    for at in range(add_pc+4,load,4):
                        side=by_pc.get(at)
                        if terminal(side):break
                        if value(at)==0xAA0003E0|(register<<16)|table_register:
                            copy=at;last=at;break
                        if 'x'+str(register) in _native_table_writes(side):break
                    if copy is None:break
                row=(page_pc,add_pc,copy,table);candidates.append(row)
                interval=[by_pc.get(at) for at in range(last+4,load,4)]
                if (page_pc>guard and all(not terminal(side) and
                        'x'+str(table_register) not in _native_table_writes(side) for side in interval)):
                    local.append(row)
                break
            if (terminal(op) or op.update_flags or has18(op) or
                    _native_table_writes(op)&{'x'+str(register),'sp','x29','x30','nzcv'}):break
    if local:candidates=local
    elif candidates and len({row[3] for row in candidates})>1:
        # Project the actual ADD/copy definition into the existing bounded
        # selected-CFG proof. No nearest-address or current-table edge guess.
        definitions=[(row[0],row[2] if row[2] is not None else row[1],row[3]) for row in candidates]
        reaching=_reaching_table_candidates(load,table_register,branch,by_pc,definitions,known_tables,exclude_closed=True)
        if reaching:
            candidates=[row for row in candidates
                        if (row[0],row[2] if row[2] is not None else row[1],row[3]) in reaching]
    if not candidates or len({row[3] for row in candidates})!=1:return None
    page,table_add,table_copy,table=candidates[-1]
    if any(a<table+size and table<b for a,b in protected_ranges):return None
    data=raw[table:table+size]
    if len(data)!=size:return None
    offsets=struct.unpack('<'+str(bound+1)+'i',data)
    targets=sorted({table+offset for offset in offsets})
    if any(offset%4 for offset in offsets) or any(target<=0 or target%4 or target+4>text_size or
            load<=target<=branch or any(a<target+4 and target<b for a,b in protected_ranges) for target in targets):
        return None
    return dict(offset=branch,base=table,count=bound+1,target_values=sorted({offset//4 for offset in offsets}),
        target_offsets=targets,signed_offsets=list(offsets),native_signed_relative=True,
        target_register=target,index_register=index,loaded_register=loaded,table_register=table_register,
        load_offset=load,index_bound=bound,table_offset=table,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
        compare_offset=compare,guard_offset=guard,bound_candidate_kind=bound_kind,index_preserving_offsets=copies,
        proof_start_offset=load,producer_offsets=[page,table_add,*([table_copy] if table_copy is not None else []),load,addition],
        permitted_source_rewrite_offsets=permitted,preserved_source_offsets=[pc for pc in range(load+4,branch,4) if pc!=addition],
        constructor_dominance_proven=False,constructor_policy='exact-local-core-or-unique-RO-candidate-with-actual-base-guard',
        entry_policy='native-signed32-actual-table-full64-index-read-only-v1',rule='runtime-native-signed32-relative-ro-v1')


def _native_table_writes(ins):
    """Effective GPR writes, including Capstone's flag-setting alias omissions."""
    def canonical(name):
        return {'lr':'x30','fp':'x29','wsp':'sp'}.get(name,name.replace('w','x',1))
    writes={canonical(ins.reg_name(r)) for r in ins.regs_access()[1]}
    if ins.mnemonic in ('cmp','cmn','tst','ccmp','ccmn'):
        return writes-{'x'+str(r) for r in range(31)}
    if ins.update_flags and ins.operands and ins.operands[0].type==ARM64_OP_REG:
        writes.add(canonical(ins.reg_name(ins.operands[0].reg)))
    return writes


def _native_u16_wide_schedule(load, branch, compare, base, roles, by_pc, tables):
    """Three exact unsigned schedules, each using the actual leaf read guard."""
    target,loaded,table,index=roles
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    def external_hi(pc):
        op=by_pc.get(pc);word_=value(pc)
        return (op is not None and word_&0xFF00001F==0x54000008 and
                not pc<op.operands[-1].imm<=branch)
    def ordinary(registers_):
        return len(set(registers_))==len(registers_) and all(r<29 and r!=18 and r not in roles for r in registers_)
    if not any(row[:2]==(load-12,load-8) for row in tables):
        return None
    prior=value(compare-4);suffix=value(branch-4)
    if prior is None or value(compare)&0xFFC003FF!=0x7100001F|(index<<5):
        return None
    if compare==load-28 and branch==load+12 and base==branch+4 and external_hi(compare+12):
        pointer=prior>>5&31;offset=prior>>16&31;destination=suffix&31
        if (ordinary((pointer,offset,destination)) and
                prior==0xB8606800|(offset<<16)|(pointer<<5)|index and
                value(compare+4)==0xF900BFE0|index and value(compare+8)==0xB90177E0|loaded and
                suffix==0x91001000|(offset<<5)|destination):
            return dict(bound_candidate_kind='u16-sp-pair-add-suffix',scheduled_guard_offset=compare+12)
    if compare==load-20 and external_hi(compare+4):
        source=prior>>5&31;other=prior>>16&31
        if (branch==load+12 and base==branch+4 and ordinary((source,other)) and
                prior==0x0B000000|(other<<16)|(source<<5)|index and suffix==0x2A1F03E0|other):
            return dict(bound_candidate_kind='u16-add-index-zero-suffix')
        if (branch==load+8 and base<compare-4 and ordinary((source,)) and
                prior==0xB9400000|(source<<5)|index):
            return dict(bound_candidate_kind='u16-backward-index-read')
    return None


def _guarded_native_readonly_table(ins, by_pc, entries, raw, readonly_ranges, *, virtual_table=False, virtual_loaded=False, known_tables=(), root_entries=None):
    """Normalize native dispatch around the actual checked read, not its prefix.

    CMP and ADRP/ADD supply finite candidates only. They do not prove dominance:
    the existing inline guard checks the actual bases and full64 index at LDR.
    All source instructions stay in place; no path may enter after that LDR.
    """
    def value(pc):
        op=by_pc.get(pc)
        return None if op is None else struct.unpack('<I',op.bytes)[0]
    branch=ins.address;branch_word=value(branch)
    if virtual_table and virtual_loaded:
        return None
    if branch_word is None or branch_word&0xFFFFFC1F!=0xD61F0000:
        return None
    target=branch_word>>5&31
    if target==18 or target>=29:
        return None
    addition=None
    for pc in range(branch-4,max(-1,branch-32),-4):
        op=by_pc.get(pc)
        if (op is None or is_fatal_instruction(op) or op.mnemonic in ('svc','hvc','smc') or
                any(op.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET))):
            return None
        writes=_native_table_writes(op)
        if 'x'+str(target) in writes:
            addition=pc;break
    if addition is None or value(addition)&~(31<<16)!=0x8B000800|(target<<5)|target:
        return None
    load=addition-4;load_word=value(load);address=by_pc.get(load-4)
    if load_word is None or address is None or address.mnemonic!='adr' or value(load-4)&31!=target:
        return None
    loaded,table_register,index=load_word&31,load_word>>5&31,load_word>>16&31
    roles=(target,loaded,table_register,index)
    width=1 if load_word&~((31<<16)|(31<<5)|31)==0x38606800 else 2
    lr_table=(not (virtual_table or virtual_loaded) and width==2 and table_register==30)
    zero=value(branch-4)
    fp_loaded=(not (virtual_table or virtual_loaded) and width==1 and loaded==29 and addition==branch-8 and
               zero is not None and zero&~31==0x2A1F03E0 and zero&31<29 and zero&31!=18 and zero&31 not in roles and
               value(load-24)==0x7100001F|(index<<5) and value(load-16)==0x51000400|(index<<5)|index and
               value(load-12) is not None and value(load-12)&0xFFC003FF==0x7100001F|(index<<5) and
               value(load-20) is not None and value(load-20)&0xFF00001F==0x5400000D and
               value(load-8) is not None and value(load-8)&0xFF00001F==0x54000008 and
               all(not pc<by_pc[pc].operands[-1].imm<=branch for pc in (load-20,load-8)))
    ordinary_roles=(target,loaded,index) if virtual_table or lr_table else (target,table_register,index) if virtual_loaded or fp_loaded else roles
    if (virtual_table and table_register!=18 or
            virtual_loaded and loaded!=18 or
            len(set(roles))!=4 or any(r==18 or r>=29 for r in ordinary_roles) or
            load_word!=(0x38606800 if width==1 else 0x78607800)|(index<<16)|(table_register<<5)|loaded or
            loaded!=value(addition)>>16&31 or
            any(pc in entries for pc in range(load+4,branch+4,4))):
        return None
    base=address.operands[1].imm
    if fp_loaded and base!=branch+4:
        return None
    if base%4 or base not in by_pc:
        return None
    # One observed byte-conversion switch masks virtual W18 after the native
    # target ADD. It must use the existing x18 rewrite, never platform X18.
    virtual_mask=(not (virtual_table or virtual_loaded) and width==1 and addition==branch-8 and value(branch-4)==0x12001E52)
    virtual_suffix_kind=None;virtual_suffix_offset=branch-4
    if not (virtual_table or virtual_loaded) and addition==branch-8:
        suffix=value(branch-4)
        if width==1 and suffix is not None and suffix&~(0xFFFF<<5)==0x52800012:
            virtual_suffix_kind='movz-w18-immediate'
        elif (width==2 and suffix is not None and suffix&~((31<<5)|31)==0x8B120000 and
                suffix&31 not in (*roles,18,29,30,31) and suffix>>5&31 not in (18,29,30,31)):
            virtual_suffix_kind='add-native-from-x18'
    elif (not (virtual_table or virtual_loaded) and width==1 and addition==branch-12 and
            value(addition+4)==0x2A1F03F2 and value(branch-4) is not None and
            value(branch-4)&~31==0x2A1F03E0 and value(branch-4)&31 not in (*roles,18,29,30,31)):
        virtual_suffix_kind='wzero-virtual-and-native';virtual_suffix_offset=addition+4
    # These exact non-flag-setting effects do not change the dispatch roles.
    # Their original PCs retain the existing x18 lowering and overlap audit;
    # no original table read is repeated or moved past the suffix.
    # Prefix x18/SP/gates and the exact suffix above are handled independently
    # by their existing rewrite and overlap checks.
    for pc in range(load-4,branch,4):
        op=by_pc.get(pc)
        if (op is None or has18(op) and not (virtual_table and pc==load or virtual_loaded and pc in (load,addition) or
                virtual_mask and pc==branch-4 or virtual_suffix_kind is not None and pc==virtual_suffix_offset) or is_fatal_instruction(op) or
                op.mnemonic in ('svc','hvc','smc') or
                any(op.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)) or
                any(op.reg_name(r) in ('sp','wsp') for r in op.regs_access()[1])):
            return None
    bounds=[];tables=[];bound_details={}
    for pc in range(max(0,load-(2048 if virtual_table else 512)),load-4,4):
        op=by_pc.get(pc);word_=value(pc);following=value(pc+4)
        if op is not None and op.mnemonic=='adrp' and word_&31==table_register:
            # A virtual table page may have up to six selected ordinary setup
            # instructions before its ADD. This supplies a candidate only;
            # the actual virtual table still has to match at the guarded read.
            frame_pair_seen=False
            for add_pc in range(pc+4,min(pc+(32 if virtual_table else 8),load-4),4):
                add_word=value(add_pc)
                if add_word is not None and add_word&0xFFC003FF==0x91000000|(table_register<<5)|table_register:
                    if frame_pair_seen and any(at in entries or at in (root_entries or ()) for at in range(pc+4,add_pc+4,4)):
                        break  # A frame-store constructor cannot acquire an interior entry.
                    tables.append((pc,add_pc,op.operands[1].imm+(add_word>>10&4095)))
                    break
                side=by_pc.get(add_pc)
                frame_pair=(virtual_table and width==1 and side is not None and side.mnemonic=='stp' and
                            not side.writeback and not side.update_flags and not side.regs_access()[1] and
                            add_word&~((31<<10)|31)==0xA93F03A0 and
                            len({add_word&31,add_word>>10&31})==2 and
                            all(r<29 and r!=18 for r in (add_word&31,add_word>>10&31)))
                if frame_pair:
                    # One exact STP Xr,Xs,[FP,#-16], without writeback. It reads
                    # ordinary GPRs/FP, writes only the original frame payload,
                    # and cannot change the table/index/flags. Keep its word in place.
                    if frame_pair_seen:
                        break
                    frame_pair_seen=True
                    continue
                if (not virtual_table or side is None or side.mnemonic not in ('mov','movz','movn','add') or
                        side.update_flags or any(side.reg_name(r) in
                        ('x18','w18','sp','wsp','fp','lr','x29','w29','x30','w30','nzcv')
                        for registers in side.regs_access() for r in registers)):
                    break
        if (pc>=load-128 and word_ is not None and
                word_&0x7FC003FF==0x7100001F|(index<<5)):
            bounds.append((pc,word_>>10&4095))
            bound_details.setdefault(pc,{})
        if (not (virtual_table or virtual_loaded) and width==1 and pc==load-8 and addition==branch-8 and base<pc and
                word_==0x92400C00|(index<<5)|index):
            other=value(load-20)&31 if value(load-20) is not None else 31
            if (other<29 and other!=18 and other not in roles and
                    value(load-20)==0x12000C00|(index<<5)|other and value(load-16)==0x71003C1F|(other<<5) and
                    value(load-12) is not None and value(load-12)&0xFF00001F==0x54000008 and
                    not load-12<by_pc[load-12].operands[-1].imm<=branch and value(branch-4)==0x2A1F03E0|other):
                bounds.append((pc,15));bound_details[pc]=dict(bound_candidate_kind='native-full64-nibble-mask',bound_transform_offset=pc)
        if pc<load-128 or word_ is None:
            continue
        source=word_>>5&31;lsb=word_>>16&63;last=word_>>10&63
        if (virtual_table and width==1 and addition==branch-4 and pc==load-8 and base<pc and
                source not in (18,29,30,31) and word_==0x92400400|(source<<5)|index):
            # Exact AND Xindex,Xsource,#3 immediately before the backward ADR.
            # This supplies four immutable table rows, not a dominance claim:
            # ADR/LDR entrances still check actual virtual table/base/full64 index.
            bounds.append((pc,3))
            bound_details[pc]=dict(bound_candidate_kind='full64-low2-mask',bound_transform_offset=pc,
                                   bound_source_register=source,bound_mask=3)
        if (source not in (18,29,30,31) and 0<=lsb<=last<32 and last-lsb<6 and
                word_==0x53000000|(lsb<<16)|(last<<10)|(source<<5)|index):
            bounds.append((pc,(1<<(last-lsb+1))-1))
            bound_details[pc]=dict(bound_candidate_kind='unsigned-bitfield',bound_transform_offset=pc,
                                   bound_source_register=source,field_lsb=lsb,field_bits=last-lsb+1)
        if (source not in (18,29,30,31) and 0<=lsb<=last<64 and
                word_==0xD3400000|(lsb<<16)|(last<<10)|(source<<5)|index):
            for mask_pc in (pc-4,pc-12):
                masked=value(mask_pc);mask_op=by_pc.get(mask_pc)
                if (masked is None or masked&0xFFFF0000!=0x92400000 or masked&31!=source or
                        masked>>10&63==63 or mask_op is None):
                    continue
                interval=[by_pc.get(at) for at in range(mask_pc+4,pc,4)]
                if any(op is None or is_fatal_instruction(op) or op.mnemonic in ('svc','hvc','smc') or
                       any(op.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)) or
                       'x'+str(source) in {op.reg_name(r).replace('w','x',1) for r in op.regs_access()[1]}
                       for op in interval):
                    continue
                mask=(1<<((masked>>10&63)+1))-1
                bound=(mask>>lsb)&((1<<(last-lsb+1))-1)
                bounds.append((pc,bound))
                bound_details[pc]=dict(bound_candidate_kind='masked-extraction',bound_transform_offset=pc,
                    bound_source_register=source,bound_mask_offset=mask_pc,bound_mask=mask,
                    field_lsb=lsb,field_bits=last-lsb+1)
                break
        alias=word_>>16&31
        if (alias!=index and alias not in (18,29,30,31) and word_==0x2A0003E0|(alias<<16)|index):
            for compare_pc in range(max(0,load-128),pc,4):
                compared=value(compare_pc)
                if compared is not None and compared&0x7FC003FF==0x7100001F|(alias<<5):
                    bounds.append((compare_pc,compared>>10&4095))
                    bound_details.setdefault(compare_pc,dict(bound_candidate_kind='wcopy-cmp',
                        bound_transform_offset=pc,bound_source_register=alias))
    if (not (virtual_table or virtual_loaded) and width==2 and addition==branch-4 and base==branch+4 and
            any(row[:2]==(load-12,load-8) for row in tables)):
        boolean=_native_u16_boolean_index(load,target,loaded,table_register,index,by_pc)
        if boolean is not None:
            bounds.append((load-16,15));bound_details[load-16]=boolean
    if bounds:
        definitions=[]
        for pc in range(max(0,load-128),load,4):
            op=by_pc.get(pc)
            # Capstone5 reports the first CMP operand as written for some
            # aliases; these instructions only update NZCV, not that GPR.
            if op is not None and op.mnemonic not in ('cmp','cmn','tst','ccmp','ccmn') and 'x'+str(index) in {
                    op.reg_name(r).replace('w','x',1) for r in op.regs_access()[1]}:
                definitions.append(pc)
        def anchor(row):
            return bound_details[row[0]].get('bound_transform_offset',row[0])
        # Preserve existing guarded candidate schedules. A later candidate
        # retires an older version only across an actual index write. A wide
        # extraction also invalidates an earlier CMP when its masked source
        # cannot be proved; borrowing that old zero bound loses legal cases.
        wide_definitions=[pc for pc in definitions if value(pc)&0xFFC0001F==0xD3400000|index]
        bounds=[row for row in bounds if not any(anchor(row)<pc<load for pc in wide_definitions) and
                not any(anchor(row)<anchor(later) and any(anchor(row)<pc<=anchor(later) for pc in definitions)
                        for later in bounds)]
    if virtual_suffix_kind=='add-native-from-x18':
        compare=load-12;upper=value(compare);hi=value(compare+4)
        if (upper is None or upper&0xFFC003FF!=0x7100001F|(index<<5) or hi is None or
                hi&0xFF00001F!=0x54000008 or compare+4<by_pc[compare+4].operands[-1].imm<=branch):
            return None
        # Exact serial sentinel equality does not bound the table. Its X-CMP
        # tests the one value above the later W-CMP/HI domain, without an
        # intervening index/flag write; retain every other ambiguity.
        prior,eq=value(compare-8),value(compare-4)
        if (prior is not None and eq is not None and prior==0xF100001F|(((upper>>10&4095)+1)<<10)|(index<<5) and
                eq&0xFF00001F==0x54000000 and not compare-4<by_pc[compare-4].operands[-1].imm<=branch):
            bounds=[row for row in bounds if row[0]!=compare-8]
            bound_details[compare]=dict(bound_candidate_kind='serial-sentinel-eq-wcmp-hi',
                sentinel_compare_offset=compare-8,sentinel_guard_offset=compare-4)
    if (not bounds and not (virtual_table or virtual_loaded) and
            any(row[:2]==(load-12,load-8) for row in tables)):
        shared=_shared_table_compare(load-16,index,branch,by_pc,raw,root_entries,known_tables)
        if shared is not None:
            compare,bound,details=shared
            bounds.append((compare,bound));bound_details[compare]=details
    str_guard=False
    if (not (virtual_table or virtual_loaded or lr_table) and width==2 and addition==branch-4 and base==branch+4 and
            value(load-24) is not None and value(load-24)&0xFFC003FF==0x7100001F|(index<<5)):
        store=value(load-20);read=value(load-32);step=value(load-28);hi=value(load-16)
        if all(word_ is not None for word_ in (store,read,step,hi)):
            pointer=store>>5&31;source=read&31;offset=step>>16&31;destination=step&31
            extras=(pointer,source,offset,destination)
            str_guard=(len(set(extras))==4 and all(r<29 and r!=18 and r not in roles for r in extras) and
                       store==0xB900181F|(pointer<<5) and read==0xF9401800|(pointer<<5)|source and
                       step==0x8B000C00|(offset<<16)|(source<<5)|destination and hi&0xFF00001F==0x54000008 and
                       not load-16<by_pc[load-16].operands[-1].imm<=branch and any(row[0]==load-24 for row in bounds))
            if str_guard:
                # The exact CMP/STR-zero/HI core supplies this finite count.
                # Earlier same-index compares are not table-size authority;
                # the actual full64 index is checked anew at the unique read.
                bounds=[row for row in bounds if row[0]==load-24]
                bound_details[load-24]=dict(bound_candidate_kind='u16-str-zero-paired-guard',scheduled_guard_offset=load-16)
    if not bounds:
        return None
    compare,bound=bounds[-1]
    if virtual_loaded and bound_details[compare].get('bound_candidate_kind')!='masked-extraction':
        return None
    size=width*(bound+1)
    tables=[row for row in tables if row[2]%width==0 and any(begin<=row[2] and row[2]+size<=end for begin,end in readonly_ranges)]
    if lr_table:
        # LR is data only in this native-u16 table role. Selected source may
        # construct it far before the read, but never across a call/LR write.
        # No dominance or call-preservation inference: the leaf read guard
        # compares the actual LR, native base and full64 index before LDRH.
        tables=[]
        for page_pc in range(max(0,load-4096),load-4,4):
            page=by_pc.get(page_pc)
            if page is None or page.mnemonic!='adrp' or value(page_pc)&31!=30:
                continue
            for add_pc in range(page_pc+4,min(page_pc+60,load-4),4):
                side=by_pc.get(add_pc);side_word=value(add_pc)
                if side_word is not None and side_word&0xFFC003FF==0x910003DE:
                    table=page.operands[1].imm+(side_word>>10&4095)
                    if (not any(pc in entries or pc in (root_entries or ()) for pc in range(page_pc+4,add_pc+4,4)) and
                            table%2==0 and any(begin<=table and table+size<=end for begin,end in readonly_ranges)):
                        tables.append((page_pc,add_pc,table))
                    break
                if (side is None or is_fatal_instruction(side) or side.update_flags or
                        side.mnemonic in ('svc','hvc','smc') or site_kind(side) not in (None,'x18') or
                        any(side.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)) or
                        _native_table_writes(side)&{'x30','x29','sp','nzcv'}):
                    break
    guard=by_pc.get(compare+4);wide_setup=False
    wide_compare=(width==2 and 63<bound<=255 and not bound_details[compare] and guard is not None and
                  value(compare+4)&0xFF00001F==0x54000008 and not compare+4<guard.operands[0].imm<=branch)
    if not tables and not (virtual_table or virtual_loaded or lr_table) and (bound<=63 or wide_compare):
        # Native libc tables interleave independent setup: up to nine words
        # for u16 or ten for u8. Preserve existing near plans and never infer
        # page dominance. The wider u16 sibling also requires an exact CMP/HI.
        for page_pc in range(max(0,load-4096),load-4,4):
            page=by_pc.get(page_pc);page_word=value(page_pc)
            if page is None or page.mnemonic!='adrp' or page_word&31!=table_register:
                continue
            for add_pc in range(page_pc+4,min(page_pc+(44 if width==2 else 48),load-4),4):
                side=by_pc.get(add_pc);side_word=value(add_pc)
                if side_word is not None and side_word&0xFFC003FF==0x91000000|(table_register<<5)|table_register:
                    table=page.operands[1].imm+(side_word>>10&4095)
                    if add_pc>page_pc+4 and table%width==0 and any(begin<=table and table+size<=end for begin,end in readonly_ranges):
                        tables.append((page_pc,add_pc,table))
                    break
                if (side is None or is_fatal_instruction(side) or site_kind(side) is not None or side.update_flags or
                        any(side.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)) or
                        any(side.reg_name(r) in ('x'+str(table_register),'w'+str(table_register),
                            'x18','w18','sp','wsp','fp','lr','x29','w29','x30','w30','nzcv') for r in side.regs_access()[1])):
                    break
        wide_setup=bool(tables) and wide_compare
    # Only these exact native-u8 cores admit the full finite byte domain.
    # Other/virtual/hoisted/scheduled families retain their existing limits.
    # Adjacent index transforms belong to their existing bounded families.
    # The wider plain-byte form consumes an incoming index, not SUB/UBFX/etc.
    # Normalize W/X aliases; Capstone's CMP alias write reports are not writes.
    prior_index=by_pc.get(compare-4)
    prior_index_write=(prior_index is not None and not is_fatal_instruction(prior_index) and
                       prior_index.mnemonic not in ('cmp','cmn','tst','ccmp','ccmn') and
                       ('x'+str(index) in {prior_index.reg_name(r).replace('w','x',1)
                           for r in prior_index.regs_access()[1]} or
                        prior_index.update_flags and prior_index.operands and
                        prior_index.operands[0].type==ARM64_OP_REG and
                        prior_index.reg_name(prior_index.operands[0].reg).replace('w','x',1)=='x'+str(index)))
    native_byte_inline=(not (virtual_table or virtual_loaded) and width==1 and not prior_index_write and
                        addition==branch-4 and compare==load-20 and not bound_details[compare] and
                        value(compare)&0xFFC003FF==0x7100001F|(index<<5) and
                        guard is not None and value(compare+4)&0xFF00001F==0x54000008 and
                        not compare+4<guard.operands[0].imm<=branch and
                        any(row[:2]==(load-12,load-8) for row in tables))
    canonical_copy=(not (virtual_table or virtual_loaded) and width in (1,2) and addition==branch-4 and compare==load-24 and
                    (width==2 or value(compare)&0xFFC003FF==0x7100001F|(bound_details[compare].get('bound_source_register',31)<<5)) and
                    bound_details[compare].get('bound_candidate_kind')=='wcopy-cmp' and
                    bound_details[compare].get('bound_transform_offset')==load-16 and
                    guard is not None and value(compare+4)&0xFF00001F==0x54000008 and
                    not compare+4<guard.operands[0].imm<=branch and
                    any(row[:2]==(load-12,load-8) for row in tables))
    native_sp_store_u16=False
    if (not (virtual_table or virtual_loaded) and width==2 and not bound_details[compare] and
            compare==load-44 and addition==branch-20 and base==branch+4 and
            value(compare)&0xFFC003FF==0x7100001F|(index<<5) and
            any(row[:2]==(load-16,load-12) for row in tables)):
        offsets=(-52,-48,-40,-36,-32,-28,-24,-20,-8,8,12,16,20)
        schedule=[value(load+d) for d in offsets]
        if all(word_ is not None for word_ in schedule):
            read,sub,pair_store,word_store,byte_store,hi,first,second,pointer_store,zero0,zero1,mov_index,mov_loaded=schedule
            source=sub>>5&31;pointer=second>>5&31;offset=first>>5&31;temporary=first&31
            zero=zero0&31;last_source=mov_loaded>>16&31
            ordinary=(source,pointer,offset,temporary,zero,last_source,pair_store&31,pair_store>>10&31,word_store&31)
            native_sp_store_u16=(all(r not in (18,29,30,31) for r in ordinary) and
                all(r not in roles for r in (source,pointer,offset,temporary,zero,last_source)) and
                temporary not in (source,pointer,offset) and zero!=source and
                read==0x38606800|(offset<<16)|(pointer<<5)|source and
                sub&0xFFC003FF==0x51000000|(source<<5)|index and
                pair_store&~((31<<10)|31)==0x290303E0 and
                word_store&~31==0xB90023E0 and byte_store==0x390093E0|source and
                hi&0xFF00001F==0x54000008 and not load-28<by_pc[load-28].operands[-1].imm<=branch and
                first==0x91000400|(offset<<5)|temporary and
                second==0x8B000000|(temporary<<16)|(pointer<<5)|loaded and
                pointer_store==0xF9000BE0|loaded and
                zero0==0x2A1F03E0|zero and zero1==0x2A1F03E0|source and
                mov_index&~(0xFFFF<<5)==0x52800000|index and
                mov_loaded==0x2A0003E0|(last_source<<16)|loaded)
        # Every store is an exact non-writeback SP form. They leave CMP's
        # flags/index intact; setup ADDs touch only independent temporaries.
        # The four suffix MOVs retain all effects after the target ADD, and
        # every entrance still passes the existing actual full64 read guard.
    native_six_u16=False
    if (not (virtual_table or virtual_loaded or lr_table) and width==2 and not bound_details[compare] and
            compare==load-32 and addition==branch-28 and base==branch+4 and
            value(compare)&0xFFC003FF==0x7100001F|(index<<5) and guard is not None and
            value(compare+4)&0xFF00001F==0x54000008 and not compare+4<guard.operands[0].imm<=branch):
        schedule=[value(load+d) for d in (-36,-24,-20,-16,-12,-8,8,12,16,20,24,28)]
        if all(word_ is not None for word_ in schedule):
            sub,store,save,frame_store,step,old_target,zero0,zero1,frame,imm0,imm1,last=schedule
            source=sub>>5&31;saved=store&31;save_pointer=save&31;frame_source=frame_store&31
            step_source=step>>5&31;step_result=step&31;zero=zero1&31;frame_result=frame&31
            first_immediate=imm0&31;second_immediate=imm1&31;last_source=last>>16&31
            ordinary=(source,saved,save_pointer,frame_source,step_source,step_result,zero,frame_result,
                      first_immediate,second_immediate,last_source)
            native_six_u16=(all(r not in (18,29,30,31) and r not in roles for r in ordinary) and
                len(set(ordinary))==len(ordinary) and
                sub&0xFFC003FF==0x51000000|(source<<5)|index and
                store==0xF90013E0|saved and save==0xAA0003E0|(loaded<<16)|save_pointer and
                frame_store==0xF81E03A0|frame_source and step==0x91000400|(step_source<<5)|step_result and
                old_target==0x2A0003E0|(target<<16)|step_source and
                zero0==0x2A1F03E0|source and zero1==0x2A1F03E0|zero and
                frame==0xD10013A0|frame_result and imm0&~(0xFFFF<<5)==0x52800000|first_immediate and
                imm1&~(0xFFFF<<5)==0x52A00000|second_immediate and
                last==0xAA0003E0|(last_source<<16)|saved)
        # Exact effects matter: the prefix consumes the old loaded/target
        # values and stores the old saved argument before suffix overwrites.
        # Keep every word in place; only the actual read receives a veneer.
    unsigned_wide=(_native_u16_wide_schedule(load,branch,compare,base,roles,by_pc,tables)
                   if not (virtual_table or virtual_loaded or lr_table) and width==2 and not bound_details[compare] else None)
    if len({row[1] for row in bounds})!=1 or bound>(255 if canonical_copy or wide_setup or native_byte_inline or native_sp_store_u16 or native_six_u16 or unsigned_wide or str_guard else 63):
        return None
    if addition==branch-28 and bound_details[compare].get('bound_candidate_kind')!='masked-extraction' and not native_six_u16:
        return None
    # Exact inline ADRP/ADD/ADR/LDR defines this source table immediately.
    # Newly discovered earlier cases may reuse the register for other RO
    # objects; they do not change this core. Entrances at ADR/LDR still check
    # the live table, so this does not borrow constructor dominance.
    inline=[row for row in tables if row[:2]==(load-12,load-8)]
    local_store=False
    if (not (virtual_table or virtual_loaded or lr_table) and width==2 and addition==branch-8 and base==branch+4 and
            bound_details[compare].get('bound_candidate_kind')=='unsigned-bitfield' and compare==load-20 and
            bound_details[compare].get('field_lsb')==4 and bound_details[compare].get('field_bits')==2):
        store=value(load-8);zero=value(branch-4)
        if store is not None and zero is not None:
            stored=store&31;pointer=store>>5&31;cleared=zero&31;source=bound_details[compare]['bound_source_register']
            extras=(stored,pointer,cleared,source)
            local_store=(len(set(extras))==4 and all(r<29 and r!=18 and r not in roles for r in extras) and
                         store==0xF901A400|(pointer<<5)|stored and zero==0xAA1F03E0|cleared)
            if local_store:
                # Select only this self-contained local ADRP/ADD/STR/ADR core,
                # never the closest arbitrary earlier object in the same GPR.
                inline += [row for row in tables if row[:2]==(load-16,load-12)]
    if native_sp_store_u16:
        inline += [row for row in tables if row[:2]==(load-16,load-12)]
    local_add=value(load-8)
    if (not (virtual_table or virtual_loaded) and not bound_details[compare] and
            guard is not None and value(compare+4)&0xFF00001F==0x54000008 and
            not compare+4<guard.operands[0].imm<=branch and local_add is not None and
            local_add&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
        # The ADD/ADR/LDR core may have a bounded independent schedule
        # between its own post-guard page and ADD. Validate every word rather
        # than choosing the closest of unrelated far RO candidates. Entries
        # before LDR still need the actual live-base/full-index read guard.
        local_pages=[pc for pc in range(max(compare+8,load-(44 if width==2 else 48)),load-12,4)
                     if by_pc.get(pc) is not None and by_pc[pc].mnemonic=='adrp' and value(pc)&31==table_register]
        gapped=[]
        for page_pc in local_pages:
            gap=[by_pc.get(pc) for pc in range(page_pc+4,load-8,4)]
            if any(side is None or is_fatal_instruction(side) or site_kind(side) is not None or side.update_flags or
                   any(side.group(group) for group in (CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET)) or
                   any(side.reg_name(r) in ('x'+str(table_register),'w'+str(table_register),
                       'x18','w18','sp','wsp','fp','lr','x29','w29','x30','w30','nzcv')
                       for r in side.regs_access()[1]) for side in gap):
                continue
            table=by_pc[page_pc].operands[1].imm+(local_add>>10&4095)
            if table%width==0 and any(begin<=table and table+size<=end for begin,end in readonly_ranges):
                gapped.append((page_pc,load-8,table))
        if local_pages and not gapped:
            return None  # A broken local setup cannot borrow another RO object.
        inline+=gapped
    if (bound_details[compare].get('bound_candidate_kind')=='masked-extraction' and compare==load-8 and
            bound_details[compare]['bound_mask_offset']==load-20):
        inline += [row for row in tables if row[:2]==(load-16,load-12)]
    if inline:
        tables=inline
    reaching=[]
    if (not lr_table and bound_details[compare].get('bound_candidate_kind')=='masked-extraction' and
            (not tables or len({row[2] for row in tables})!=1)):
        candidates=[]
        for pc in range(max(0,load-4096),load-4,4):
            page=by_pc.get(pc);add=value(pc+4)
            if (page is not None and page.mnemonic=='adrp' and value(pc)&31==table_register and
                    add is not None and add&0xFFC003FF==0x91000000|(table_register<<5)|table_register):
                table=page.operands[1].imm+(add>>10&4095)
                if table%width==0 and any(begin<=table and table+size<=end for begin,end in readonly_ranges):
                    candidates.append((pc,pc+4,table))
        if candidates and len({row[2] for row in candidates})==1:
            # Like a near/hoisted candidate, one selected complete constant
            # needs no dominance claim. Later classified loop roots may lack
            # proven predecessors; their actual live values remain guarded.
            tables=sorted(set(candidates))
        else:
            tables=_reaching_table_candidates(load,table_register,branch,by_pc,candidates,known_tables)
            if tables:reaching=sorted({pc for row in tables for pc in row[:2]})
    if not tables or len({row[2] for row in tables})!=1:
        return None
    page,add,table=tables[-1]
    if table%width or not any(begin<=table and table+size<=end for begin,end in readonly_ranges):
        return None
    data=raw[table:table+size]
    if len(data)!=size:
        return None
    values=sorted(set(struct.unpack('<'+str(bound+1)+('B' if width==1 else 'H'),data)))
    # Native u16 BR keeps a sparse finite set; its veneer does not scale with
    # the largest tag. Every derived case still needs original code-domain
    # audit. Virtual-table/loaded families retain their existing ceilings.
    if values[-1]>4095 and (width!=2 or virtual_table or virtual_loaded):
        return None
    return dict(offset=branch,base=base,target_register=target,load_offset=load,
                table_register=table_register,index_register=index,loaded_register=loaded,
                index_bound=bound,table_offset=table,table_bytes=size,table_sha256=hashlib.sha256(data).hexdigest(),
                target_values=values,bound_candidate_offset=compare,proof_start_offset=load-4,
                producer_offsets=[page,add,load-4,load,addition],
                equivalent_table_producer_offsets=[row[0] for row in tables],
                **({'reaching_table_producer_offsets':reaching} if reaching else {}),
                preserved_source_offsets=list(range(addition+4,branch,4)),
                entry_policy='all-paths-must-pass-actual-native-read-guard-v1',
                **(dict(bound_candidate_kind='scheduled-u16-sp-stores',scheduled_guard_offset=load-28,
                        preserved_sp_store_offsets=[compare+4,compare+8,compare+12,load-8]) if native_sp_store_u16 else {}),
                **(dict(bound_candidate_kind='u16-six-native-suffix') if native_six_u16 else {}),
                **(unsigned_wide or {}),
                **(dict(loaded_candidate_kind='native-byte-fp-scratch') if fp_loaded else {}),
                **(dict(table_candidate_kind='u16-local-store-core') if local_store else {}),
                **(dict(table_constructor_gap=add-page,table_candidate_kind='native-u16-lr-data') if lr_table else {}),
                rule=('runtime-virtual-table-x18-guarded-readonly-lsl2-v1' if virtual_table else
                      'runtime-virtual-loaded-x18-guarded-readonly-lsl2-v1' if virtual_loaded else
                      'runtime-native-guarded-readonly-lsl2-v1'),**bound_details[compare],
                **(dict(virtual_suffix_kind=virtual_suffix_kind) if virtual_suffix_kind is not None else {}),
                **(dict(virtual_table_register=18,permitted_source_rewrite_offsets=[load]) if virtual_table else
                   dict(virtual_loaded_register=18,permitted_source_rewrite_offsets=[load,addition]) if virtual_loaded else
                   dict(permitted_source_rewrite_offsets=[virtual_suffix_offset]) if virtual_suffix_kind is not None else
                   dict(permitted_source_rewrite_offsets=[branch-4]) if virtual_mask else {}))


def readonly_guest_table(ins, by_pc, entries, raw, readonly_ranges, *, known_tables=(), root_entries=None, text_size=None, protected_ranges=()):
    return (native_signed32_readonly_table(ins,by_pc,entries,raw,readonly_ranges,text_size=text_size,protected_ranges=protected_ranges,known_tables=known_tables) or
            readonly_guest_byte_table(ins,by_pc,entries,raw,readonly_ranges) or
            runtime_readonly_guest_halfword_table(ins,by_pc,entries,raw,readonly_ranges) or
            runtime_readonly_guest_byte_table(ins,by_pc,entries,raw,readonly_ranges) or
            _observed_runtime_guest_table(ins,by_pc,entries,raw,readonly_ranges) or
            _scheduled_side_load_table(ins,by_pc,entries,raw,readonly_ranges) or
            virtual_index_x18_native_target(ins,by_pc,entries,raw,readonly_ranges,root_entries=root_entries) or
            virtual_index_x18_byte_native_target(ins,by_pc,entries,raw,readonly_ranges,root_entries=root_entries) or
            _virtual_table_x18_native_target(ins,by_pc,entries,raw,readonly_ranges) or
            _virtual_loaded_x18_native_target(ins,by_pc,entries,raw,readonly_ranges,root_entries=root_entries,known_tables=known_tables) or
            _scheduled_native_readonly_table(ins,by_pc,entries,raw,readonly_ranges) or
            _assembled_byte_readonly_table(ins,by_pc,entries,raw,readonly_ranges) or
            _guarded_native_readonly_table(ins,by_pc,entries,raw,readonly_ranges,known_tables=known_tables,root_entries=root_entries) or
            _guarded_native_readonly_table(ins,by_pc,entries,raw,readonly_ranges,virtual_table=True,known_tables=known_tables) or
            _guarded_native_readonly_table(ins,by_pc,entries,raw,readonly_ranges,virtual_loaded=True,known_tables=known_tables))


def stack_check_operation(value):
    """Finite, independently mirrored native decoder; no Capstone defaults."""
    if value in (0x4CDF27E0,0x4CDF27E4,0x4CDF27E8,0x4CDF27EC,
                 0x4CDFA7E0,0x4CDFA7E4,0x4CDFA7E8,0x4CDFA7EC):
        amount=64 if value&0x8000==0 else 32
        return {'source':31,'delta':amount,'access_bytes':amount,'post_index':True}
    # SDK's exact 64-bit virtual-x18 pair save/restore. Other x18 SP writers
    # remain unsupported; these execute only through the checked x18 stub.
    if value in (0xA9BF4FF2,0xA8C14FF2):
        return {'source':31,'delta':-16 if value==0xA9BF4FF2 else 16,
                'access_bytes':16,'post_index':value==0xA8C14FF2}
    source = value >> 5 & 31
    alignment = {0x9274CC1F: 4095, 0x927BE81F: 31, 0x927AE41F: 63,
                 0x9279E01F: 127}.get(value & 0xFFFFFC1F)
    if alignment is not None:
        if source in (18, 31):
            return None
        return {'source': source, 'delta': 0, 'access_bytes': 0,
                'post_index': False, 'alignment_mask': 0xFFFFFFFFFFFFFFFF - alignment}
    if value & 0xBF80001F == 0x9100001F:
        amount = (value >> 10 & 4095) << (12 if value >> 22 & 1 else 0)
        if source == 18 or amount > 1048576 or (source == 31 and amount % 16):
            return None
        return {'source': source, 'delta': -amount if value >> 30 & 1 else amount,
                'access_bytes': 0, 'post_index': False}
    if source != 31:
        return None
    vector = bool(value >> 26 & 1)
    first, second = value & 31, value >> 10 & 31
    if value & 0x3A000000 == 0x28000000 and (value >> 23 & 3) in (1, 3):
        opc, load = value >> 30 & 3, bool(value >> 22 & 1)
        if opc == 3 or (not vector and (first == 18 or second == 18 or (opc == 1 and not load))):
            return None
        if load and first == second:
            return None
        width = (4 << opc) if vector else (8 if opc == 2 else 4)
        immediate = value >> 15 & 127
        delta = (immediate - 128 if immediate & 64 else immediate) * width
        if delta % 16:
            return None
        return {'source': 31, 'delta': delta, 'access_bytes': width * 2,
                'post_index': (value >> 23 & 3) == 1}
    if value & 0x3B200000 == 0x38000000 and (value >> 10 & 3) in (1, 3):
        size, opc = value >> 30 & 3, value >> 22 & 3
        if not vector and (opc > 1 or first == 18):
            return None
        if vector and opc > 1 and size != 0:
            return None
        width = 16 if vector and opc > 1 else 1 << size
        immediate = value >> 12 & 511
        delta = immediate - 512 if immediate & 256 else immediate
        if delta % 16:
            return None
        return {'source': 31, 'delta': delta, 'access_bytes': width,
                'post_index': (value >> 10 & 3) == 1}
    return None


def pair(load, first, second, offset):
    return (0xA9400000 if load else 0xA9000000) | ((offset // 8 & 127) << 15) | (second << 10) | (31 << 5) | first


def memory(load, target, base, offset):
    return (0xF9400000 if load else 0xF9000000) | (offset // 8 << 10) | (base << 5) | target


def has18(ins):
    return re.search(r'\b[xw]18\b', ins.op_str) is not None


def registers(ins):
    result = {int(x) for x in re.findall(r'\b[xw](\d+)\b', ins.op_str)}
    for reg in sum((list(x) for x in ins.regs_access()), []):
        name = ins.reg_name(reg)
        if name in ('lr', 'fp'):
            result.add(30 if name == 'lr' else 29)
        match = re.fullmatch(r'[xw](\d+)', name)
        if match:
            result.add(int(match[1]))
    return result


def substitute(ins, scratch, *, sp_base=None):
    original = struct.unpack('<I', ins.bytes)[0]
    desired = re.sub(r'\b([xw])18\b', lambda m: f'{m[1]}{scratch}', ins.op_str)
    positions = [p for p in (0, 5, 10, 16) if original >> p & 31 == 18]
    for count in range(len(positions), 0, -1):
        for fields in combinations(positions, count):
            candidate = original
            for field in fields:
                candidate = candidate & ~(31 << field) | scratch << field
            if sp_base is not None:
                candidate = candidate & ~(31 << 5) | sp_base << 5
            try:
                decoded = decode(candidate, ins.address)
            except RewriteError:
                continue
            expected = desired
            expected_mnemonic = ins.mnemonic
            if sp_base is not None:
                expected = re.sub(r'\bwsp\b', f'w{sp_base}', expected)
                expected = re.sub(r'\bsp\b', f'x{sp_base}', expected)
                # ADD-immediate #0 has a MOV alias only when SP is an
                # operand. Replacing SP with a GPR removes that alias.
                if ins.mnemonic == 'mov':
                    expected_mnemonic, expected = 'add', expected + ', #0'
                # Extended ADD/SUB hides UXTX/UXTW #0 for an SP operand;
                # the decoded GPR form prints the extension explicitly.
                if (original & 0x1F200000 == 0x0B200000 and
                        ins.mnemonic in ('add', 'sub', 'adds', 'subs', 'cmp', 'cmn') and
                        original >> 13 & 7 in (2, 3) and not original >> 10 & 7 and
                        not re.search(r'\b(?:uxtw|uxtx)\b', expected)):
                    expected += ', ' + ('uxtx' if original >> 13 & 7 == 3 else 'uxtw')
            if (decoded.mnemonic, decoded.op_str) == (expected_mnemonic, expected):
                return candidate
    raise RewriteError(f'0x{ins.address:x}: unsupported x18 encoding: {ins.mnemonic} {ins.op_str}')


def site_kind(ins):
    if ins.mnemonic == 'svc':
        return 'gate'
    if ins.mnemonic in ('mrs', 'msr'):
        system = ins.op_str.split(',')[1 if ins.mnemonic == 'mrs' else 0].strip()
        # Linux exposes actual (or kernel-sanitized) EL0 cache geometry.
        # Preserve this exact read; writes and all other system registers keep
        # their existing admission rules. Virtual x18 still uses its lowering.
        if ins.mnemonic=='mrs' and struct.unpack('<I',ins.bytes)[0]&0xFFFFFFE0==0xD53B0020:
            return 'x18' if has18(ins) else None
        if system in ('tpidr_el0', 'tpidrro_el0'):
            return 'tls'
        if system in ('cntpct_el0', 'cntvct_el0') and ins.mnemonic == 'mrs':
            return 'gate'
        if system not in ('nzcv', 'fpsr', 'fpcr'):
            raise RewriteError(f'0x{ins.address:x}: unsupported system register {system}')
    return 'x18' if has18(ins) else None


class Emitter:
    def __init__(self, raw):
        self.data = bytearray(raw)
        self.fixups, self.gates, self.sites, self.literals = [], [], [], []
        self.gate_provenance = []
        self.pool_start = self.pc

    @property
    def pc(self):
        return len(self.data)

    def emit(self, value):
        self.data.extend(word(value))

    def helper(self, reg, kind):
        self.literals.append((self.pc, reg, kind))
        self.emit(0)  # LDR literal resolved once all trampoline offsets are known.

    def begin(self, ins, *, sp_base=None, frame=None, reserved=()):
        scratch, state = [r for r in range(16) if r not in registers(ins)|set(reserved)][:2]
        frame = (48 if sp_base is not None else 32) if frame is None else frame
        self.emit(0xD10003FF | frame << 10)  # sub sp,sp,#frame (preserves NZCV)
        self.emit(pair(False, 16, 30, 0))
        self.emit(pair(False, scratch, state, 16))
        if sp_base is not None:
            self.emit(pair(False, sp_base, 31, 32))
        self.helper(16, STATE_HELPER)
        self.emit(0xD63F0200)  # blr x16
        self.emit(0xAA1003E0 | state)  # mov state,x16
        self.emit(pair(True, 16, 30, 0))  # original operands and LR before native instruction
        if sp_base is not None:
            self.emit(0x910003E0 | frame << 10 | sp_base)  # add base,sp,#frame
        return scratch, state

    def cleanup(self, scratch, state, target, *, sp_base=None, adjustment=None):
        if sp_base is not None:
            self.emit(pair(True, sp_base, 31, 32))
        self.emit(pair(True, scratch, state, 16))
        adjustment = (48 if sp_base is not None else 32) if adjustment is None else adjustment
        self.emit(0x910003FF | adjustment << 10)
        self.emit(branch(self.pc, target))

    def checked_call(self, ins, target):
        """Compare a virtual X18 snapshot, then direct-call one audited entry.

        The mutable source field is not treated as a constant. Both exits restore
        all guest arguments, flags and SP before transferring or trapping. X16
        remains an argument; X30 alone receives the original BLR continuation.
        """
        scratch, state = self.begin(ins, frame=64)
        third = next(r for r in range(16) if r not in registers(ins) | {scratch, state})
        self.emit(memory(False, third, 31, 32))
        self.emit(0xD53B4200 | third)  # MRS third,NZCV
        self.emit(memory(False, third, 31, 40))
        self.emit(memory(True, scratch, state, 0))  # Snapshot virtual X18.

        def address(register, offset):
            pages = (offset >> 12) - (self.pc >> 12)
            if not -(1 << 20) <= pages < (1 << 20):
                raise RewriteError('checked call address exceeds ADRP reach')
            self.emit(0x90000000 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5 | register)
            self.emit(0x91000000 | (offset & 4095) << 10 | register << 5 | register)

        address(state, target)
        self.emit(0xEB00001F | state << 16 | scratch << 5)  # CMP scratch,state
        mismatch = self.pc
        self.emit(0)

        def restore():
            self.emit(memory(True, third, 31, 40))
            self.emit(0xD51B4200 | third)  # MSR NZCV,third
            self.emit(memory(True, third, 31, 32))
            self.emit(pair(True, scratch, state, 16))
            self.emit(pair(True, 16, 30, 0))
            self.emit(0x910103FF)  # ADD SP,SP,#64; preserves restored NZCV.

        restore()
        address(30, ins.address + 4)
        self.emit(branch(self.pc, target))
        failure = self.pc
        restore()
        self.emit(0xD4200000)  # Unknown, null and interior targets fail closed.
        self.data[mismatch:mismatch + 4] = word(0x54000001 | ((failure - mismatch) // 4 & 0x7FFFF) << 5)

    def checked_call_forest(self, targets, sites):
        """One balanced exact-entry decision forest, placed before all stubs.

        Conditional edges are local; every distant child and successful guest
        transfer uses B's signed 26-bit displacement. No node performs an
        indirect branch or touches platform X18. See the independent auditor
        for a second parser of this 60-byte node/28-byte failure wire format.
        """
        start = self.pc
        failure = start + len(targets) * 60

        def direct(target):
            try:
                self.emit(branch(self.pc, target))
            except RewriteError as error:
                raise RewriteError(f'checked call forest branch range at 0x{self.pc:x} to 0x{target:x}') from error

        def restore(success):
            self.emit(memory(True, 2, 31, 40))
            self.emit(0xD51B4202)  # MSR NZCV,X2
            self.emit(memory(True, 2, 31, 32))
            self.emit(pair(True, 0, 1, 16))
            if success:
                self.emit(memory(True, 16, 31, 0))
                self.emit(memory(True, 30, 31, 48))
            else:
                self.emit(pair(True, 16, 30, 0))
            self.emit(0x910103FF)  # ADD SP,SP,#64

        def emit_node(lo, hi, index):
            middle = (lo + hi) // 2
            target = targets[middle]
            pc = start + index * 60
            if self.pc != pc:
                raise RewriteError('checked call forest node geometry mismatch')
            pages = (target >> 12) - (pc >> 12)
            if not -(1 << 20) <= pages < (1 << 20):
                raise RewriteError('checked call forest address exceeds ADRP range')
            self.emit(0x90000001 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5)
            self.emit(0x91000021 | (target & 4095) << 10)
            self.emit(0xEB01001F)  # CMP X0,X1: full 64-bit relocated pointer.
            self.emit(0x54000080)  # B.EQ node+28, local success restore.
            self.emit(0x54000043)  # B.LO node+24, local left-child B.
            right = start + (index + 1 + middle - lo) * 60 if middle + 1 < hi else failure
            left = start + (index + 1) * 60 if lo < middle else failure
            direct(right)
            direct(left)
            restore(True)
            direct(target)
            if lo < middle:
                emit_node(lo, middle, index + 1)
            if middle + 1 < hi:
                emit_node(middle + 1, hi, index + 1 + middle - lo)

        emit_node(0, len(targets), 0)
        if self.pc != failure:
            raise RewriteError('checked call forest failure geometry mismatch')
        restore(False)
        self.emit(0xD4200000)
        digest = hashlib.sha256()
        for target in targets:
            digest.update(struct.pack('<Q', target))
        geometry = dict(version=1, start=start, root=start, end=self.pc,
                        failure_offset=failure, node_size=60, node_count=len(targets),
                        target_count=len(targets), target_sha256=digest.hexdigest(),
                        site_offsets=sorted(sites), max_depth=len(targets).bit_length(),
                        stub_size=60, frame_size=64)
        self.finish()  # Align/reset helper pools after the large literal-free forest.
        return geometry

    def checked_call_forest_stub(self, ins, root):
        scratch, state = self.begin(ins, frame=64)
        if (scratch, state) != (0, 1):
            raise RewriteError('checked call forest requires exact BLR X18 scratch layout')
        self.emit(memory(False, 2, 31, 32))
        self.emit(0xD53B4202)
        self.emit(memory(False, 2, 31, 40))
        self.emit(memory(True, 0, 1, 0))  # Virtual X18 snapshot in X0.
        continuation = ins.address + 4
        pages = (continuation >> 12) - (self.pc >> 12)
        if not -(1 << 20) <= pages < (1 << 20):
            raise RewriteError('checked call forest continuation exceeds ADRP range')
        self.emit(0x9000001E | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5)
        self.emit(0x910003DE | (continuation & 4095) << 10)
        self.emit(memory(False, 30, 31, 48))
        self.emit(branch(self.pc, root))

    def byte_jump(self, ins, plan):
        if plan.get('signed_relative'):
            return self.signed_relative_x18_jump(ins,plan)
        # Preserve every guest GPR, SP, LR and NZCV. The state accessor also
        # preserves SIMD/FP state and hardware x18. No guest register is dead
        # merely because the original instruction was an indirect branch.
        scratch, state = self.begin(ins)
        self.emit(memory(True, scratch, state, 0))  # virtual x18
        pages = (plan['base'] >> 12) - (self.pc >> 12)
        if not -(1 << 20) <= pages < (1 << 20):
            raise RewriteError('byte dispatch base exceeds ADRP reach')
        self.emit(0x90000000 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5 | state)
        self.emit(0x91000000 | (plan['base'] & 4095) << 10 | state << 5 | state)
        self.emit(0xCB000000 | state << 16 | scratch << 5 | scratch)  # SUB, not SUBS
        checks = []
        for bit in (0, 1):
            checks.append((self.pc, 0x37000000 | bit << 19 | scratch))
            self.emit(0)  # TBNZ low bits: alignment, without touching NZCV.
        shift=2+plan['count'].bit_length()-1
        self.emit(0xD340FC00 | shift << 16 | scratch << 5 | state)  # LSR: aligned target range
        high_check = self.pc
        self.emit(0)  # CBNZ rejects underflow and offsets >=1024.
        table_address = self.pc
        self.emit(0)  # ADR state,table
        self.emit(0x8B000000 | state << 16 | scratch << 5 | scratch)
        self.emit(0xD61F0000 | scratch << 5)
        failure = self.pc
        self.emit(0xD4200000)  # Impossible after source proof; corruption traps.
        table = self.pc
        for _ in range(plan['count']):
            self.emit(branch(self.pc,failure))
        for index in plan.get('target_values',range(plan['count'])):
            at = table + index * 4
            self.data[at:at + 4] = word(branch(at, self.pc))
            self.cleanup(scratch, state, plan['base'] + index * 4)
        for at, value in checks:
            self.data[at:at + 4] = word(value | ((failure - at) // 4 & 0x3FFF) << 5)
        self.data[high_check:high_check + 4] = word(0xB5000000 | ((failure - high_check) // 4 & 0x7FFFF) << 5 | state)
        delta = table - table_address
        self.data[table_address:table_address + 4] = word(0x10000000 | (delta & 3) << 29 | (delta >> 2 & 0x7FFFF) << 5 | state)

    def signed_relative_x18_jump(self, ins, plan):
        """Exact finite jump membership, retaining the original LR on both exits."""
        scratch,state=self.begin(ins,frame=64)
        third=next(r for r in range(16) if r not in registers(ins)|{scratch,state})
        self.emit(memory(False,third,31,32));self.emit(0xD53B4200|third)
        self.emit(memory(False,third,31,40));self.emit(memory(True,scratch,state,0))
        matches=[]
        for target in plan['target_offsets']:
            pages=(target>>12)-(self.pc>>12)
            if not -(1<<20)<=pages<(1<<20):
                raise RewriteError('signed relative jump target exceeds ADRP range')
            self.emit(0x90000000|(pages&3)<<29|(pages>>2&0x7FFFF)<<5|state)
            self.emit(0x91000000|(target&4095)<<10|state<<5|state)
            self.emit(0xEB00001F|state<<16|scratch<<5)
            matches.append((self.pc,target));self.emit(0)

        def restore():
            self.emit(memory(True,third,31,40));self.emit(0xD51B4200|third)
            self.emit(memory(True,third,31,32));self.emit(pair(True,scratch,state,16))
            self.emit(pair(True,16,30,0));self.emit(0x910103FF)

        restore();self.emit(0xD4200000)
        for at,target in matches:
            delta=self.pc-at
            if delta%4 or not -(1<<20)<=delta<(1<<20):
                raise RewriteError('signed relative membership branch exceeds range')
            self.data[at:at+4]=word(0x54000000|((delta//4)&0x7FFFF)<<5)
            restore();self.emit(branch(self.pc,target))

    def signed_relative_x18_load(self, ins, plan):
        """Read one signed32 offset using an actual checked virtual index."""
        scratch,state=self.begin(ins,frame=48)
        third=next(r for r in range(16) if r not in registers(ins)|{scratch,state})
        self.emit(memory(False,third,31,32));self.emit(0xD53B4200|third)
        self.emit(memory(False,third,31,40));self.emit(memory(True,scratch,state,0))
        table=plan['table_offset'];pages=(table>>12)-(self.pc>>12)
        if not -(1<<20)<=pages<(1<<20):
            raise RewriteError('signed relative table exceeds ADRP range')
        self.emit(0x90000000|(pages&3)<<29|(pages>>2&0x7FFFF)<<5|third)
        self.emit(0x91000000|(table&4095)<<10|third<<5|third)
        self.emit(0xCB000000|third<<16|plan['table_register']<<5|third)
        failures=[(self.pc,0xB5000000|third)];self.emit(0)
        self.emit(0xF100001F|plan['index_bound']<<10|scratch<<5)
        failures.append((self.pc,0x54000008));self.emit(0)
        # Rt and Rm both alias virtual X18. A64 computes the address before
        # replacing the same scratch register with its sign-extended result.
        self.emit(substitute(ins,scratch));self.emit(memory(False,scratch,state,0))

        def restore():
            self.emit(memory(True,third,31,40));self.emit(0xD51B4200|third)
            self.emit(memory(True,third,31,32));self.emit(pair(True,scratch,state,16))
            self.emit(0x9100C3FF)

        restore();self.emit(branch(self.pc,ins.address+4))
        failure=self.pc;restore();self.emit(0xD4200000)
        for at,encoding in failures:
            delta=failure-at
            if delta%4 or not -(1<<20)<=delta<(1<<20):
                raise RewriteError('signed relative load failure branch exceeds range')
            self.data[at:at+4]=word(encoding|((delta//4)&0x7FFFF)<<5)

    def readonly_table_load(self, ins, plan):
        if plan.get('virtual_index_register')==18:
            return self.virtual_index_x18_load(ins,plan)
        if plan.get('signed_relative'):
            return self.signed_relative_x18_load(ins,plan)
        if plan.get('virtual_target_register')==18:
            return self.virtual_x18_table_load(ins,plan)
        if plan.get('virtual_table_register')==18 or plan.get('virtual_loaded_register')==18:
            return self.virtual_table_x18_load(ins,plan)
        # No state accessor or host call: the checked invocation has >=16KiB
        # compiler headroom, of which this leaf preflight uses exactly 32B.
        # Both paths restore scratch registers, original SP and NZCV. SIMD/FP,
        # LR and hardware/virtual x18 are never touched.
        a,b,flags=[r for r in range(16) if r not in registers(ins)|{plan['target_register']}][:3]
        self.emit(0xD10083FF)
        self.emit(pair(False,a,b,0))
        self.emit(memory(False,flags,31,16))
        self.emit(0xD53B4200|flags)  # MRS flags,NZCV
        failures=[]
        checked_values=((plan['table_register'],plan['table_offset']),) if plan.get('native_signed_relative') else (
                        (plan['table_register'],plan['table_offset']),(plan['target_register'],plan['base']))
        for actual,expected in checked_values:
            pages=(expected>>12)-(self.pc>>12)
            if not -(1<<20)<=pages<(1<<20):
                raise RewriteError('runtime RO table address exceeds ADRP reach')
            self.emit(0x90000000|(pages&3)<<29|(pages>>2&0x7FFFF)<<5|a)
            self.emit(0x91000000|(expected&4095)<<10|a<<5|a)
            self.emit(0xCB000000|a<<16|actual<<5|b)  # SUB preserves NZCV
            failures.append((self.pc,0xB5000000|b));self.emit(0)
        self.emit(0xF100001F|plan['index_bound']<<10|plan['index_register']<<5)
        failures.append((self.pc,0x54000008));self.emit(0)  # B.HI, full64 index

        def restore():
            self.emit(0xD51B4200|flags)
            self.emit(memory(True,flags,31,16))
            self.emit(pair(True,a,b,0))
            self.emit(0x910083FF)

        restore()
        self.emit(struct.unpack('<I',ins.bytes)[0])
        self.emit(branch(self.pc,ins.address+4))
        failure=self.pc
        restore()
        self.emit(0xD4200000)
        for at,encoding in failures:
            delta=failure-at
            if delta%4 or not -(1<<20)<=delta<(1<<20):
                raise RewriteError('runtime RO table failure branch exceeds reach')
            self.data[at:at+4]=word(encoding|((delta//4)&0x7FFFF)<<5)

    def virtual_index_x18_load(self, ins, plan):
        # The native target is not an LDRH operand, but must survive the helper
        # and all guard scratch. Virtual X18 is read-only for this instruction.
        target=plan['target_register'];scratch,state=self.begin(ins,frame=48,reserved=(target,))
        third=next(r for r in range(16) if r not in registers(ins)|{scratch,state,target})
        self.emit(memory(False,third,31,32));self.emit(0xD53B4200|third)
        self.emit(memory(False,third,31,40));self.emit(memory(True,scratch,state,0))
        failures=[]
        for actual,expected in ((plan['table_register'],plan['table_offset']),(target,plan['base'])):
            pages=(expected>>12)-(self.pc>>12)
            if not -(1<<20)<=pages<(1<<20):
                raise RewriteError('virtual index table/base exceeds ADRP range')
            self.emit(0x90000000|(pages&3)<<29|(pages>>2&0x7FFFF)<<5|third)
            self.emit(0x91000000|(expected&4095)<<10|third<<5|third)
            self.emit(0xCB000000|third<<16|actual<<5|third)
            failures.append((self.pc,0xB5000000|third));self.emit(0)
        self.emit(0xF100001F|plan['index_bound']<<10|scratch<<5)
        failures.append((self.pc,0x54000008));self.emit(0)
        self.emit(substitute(ins,scratch))  # Exactly one original-width read.

        def restore():
            self.emit(memory(True,third,31,40));self.emit(0xD51B4200|third)
            self.emit(memory(True,third,31,32));self.emit(pair(True,scratch,state,16))
            self.emit(0x9100C3FF)

        restore();self.emit(branch(self.pc,ins.address+4))
        failure=self.pc;restore();self.emit(0xD4200000)
        for at,encoding in failures:
            delta=failure-at
            if delta%4 or not -(1<<20)<=delta<(1<<20):
                raise RewriteError('virtual index load failure branch exceeds range')
            self.data[at:at+4]=word(encoding|((delta//4)&0x7FFFF)<<5)

    def virtual_x18_table_load(self, ins, plan):
        # Existing accessor preserves flags/FP/all GPRs except its explicit X16
        # result. begin saves/restores original X16/LR and the two scratch GPRs.
        scratch,state=self.begin(ins,frame=48)
        third=next(r for r in range(16) if r not in registers(ins)|{scratch,state})
        self.emit(memory(False,third,31,32))
        self.emit(0xD53B4200|third)
        self.emit(memory(False,third,31,40))
        failures=[]
        # Virtual target is read from this invocation's state, never Bionic X18.
        self.emit(memory(True,scratch,state,0))
        for actual,expected in ((scratch,plan['base']),(plan['table_register'],plan['table_offset'])):
            pages=(expected>>12)-(self.pc>>12)
            if not -(1<<20)<=pages<(1<<20):
                raise RewriteError('virtual-x18 RO table address exceeds ADRP reach')
            self.emit(0x90000000|(pages&3)<<29|(pages>>2&0x7FFFF)<<5|third)
            self.emit(0x91000000|(expected&4095)<<10|third<<5|third)
            self.emit(0xCB000000|third<<16|actual<<5|scratch)
            failures.append((self.pc,0xB5000000|scratch));self.emit(0)
        self.emit(0xF100001F|plan['index_bound']<<10|plan['index_register']<<5)
        failures.append((self.pc,0x54000008));self.emit(0)

        def restore():
            self.emit(memory(True,third,31,40))
            self.emit(0xD51B4200|third)
            self.emit(memory(True,third,31,32))
            self.emit(pair(True,scratch,state,16))
            self.emit(0x9100C3FF)

        restore()
        self.emit(struct.unpack('<I',ins.bytes)[0])
        self.emit(branch(self.pc,ins.address+4))
        failure=self.pc
        restore();self.emit(0xD4200000)
        for at,encoding in failures:
            delta=failure-at
            if delta%4 or not -(1<<20)<=delta<(1<<20):
                raise RewriteError('virtual-x18 RO failure branch exceeds reach')
            self.data[at:at+4]=word(encoding|((delta//4)&0x7FFFF)<<5)

    def virtual_table_x18_load(self, ins, plan):
        # The normal target (not an operand of LDR) must survive the accessor
        # and every guard. Hardware X18 is never an address or scratch GPR.
        target=plan['target_register']
        scratch,state=self.begin(ins,frame=48,reserved=(target,))
        third=next(r for r in range(16) if r not in registers(ins)|{scratch,state,target})
        self.emit(memory(False,third,31,32))
        self.emit(0xD53B4200|third)
        self.emit(memory(False,third,31,40))
        virtual_table=plan.get('virtual_table_register')==18
        if virtual_table:
            self.emit(memory(True,scratch,state,0))
        failures=[]
        for actual,expected in ((scratch if virtual_table else plan['table_register'],plan['table_offset']),(target,plan['base'])):
            pages=(expected>>12)-(self.pc>>12)
            if not -(1<<20)<=pages<(1<<20):
                raise RewriteError('virtual table RO address exceeds ADRP reach')
            self.emit(0x90000000|(pages&3)<<29|(pages>>2&0x7FFFF)<<5|third)
            self.emit(0x91000000|(expected&4095)<<10|third<<5|third)
            self.emit(0xCB000000|third<<16|actual<<5|scratch)
            failures.append((self.pc,0xB5000000|scratch));self.emit(0)
        self.emit(0xF100001F|plan['index_bound']<<10|plan['index_register']<<5)
        failures.append((self.pc,0x54000008));self.emit(0)

        def restore():
            self.emit(memory(True,third,31,40))
            self.emit(0xD51B4200|third)
            self.emit(memory(True,third,31,32))
            self.emit(pair(True,scratch,state,16))
            self.emit(0x9100C3FF)

        # Reuse the strict x18 operand substitution while the frame still
        # owns scratch. This executes the original table read exactly once.
        if virtual_table:
            self.emit(memory(True,scratch,state,0))
        self.emit(substitute(ins,scratch))
        if plan.get('virtual_loaded_register')==18:
            self.emit(memory(False,scratch,state,0))
        restore();self.emit(branch(self.pc,ins.address+4))
        failure=self.pc
        restore();self.emit(0xD4200000)
        for at,encoding in failures:
            delta=failure-at
            if delta%4 or not -(1<<20)<=delta<(1<<20):
                raise RewriteError('virtual table RO failure branch exceeds reach')
            self.data[at:at+4]=word(encoding|((delta//4)&0x7FFFF)<<5)

    def gate(self, ins, observation=None, *, indirect=False, stack_check=False):
        self.emit(0xD10043FF)  # sub sp,sp,#16
        self.emit(pair(False, 29, 30, 0))
        self.helper(30, DISPATCH_HELPER)
        self.emit(0xD63F03C0)
        kind = STACK_CHECK if stack_check else INDIRECT_HOST if indirect else OBS if observation is not None else SVC if ins.mnemonic == 'svc' else TIMER
        argument = struct.unpack('<I', ins.bytes)[0] if stack_check else indirect_register(ins) if indirect else observation.id if observation is not None else ins.operands[0].imm if kind == SVC else struct.unpack('<I', ins.bytes)[0] & 31
        self.gates.append(Gate(self.pc, kind, argument))
        self.gate_provenance.append(GateProvenance(self.pc, ins.address, struct.unpack('<I', ins.bytes)[0]))
        self.emit(pair(True, 29, 30, 0))
        self.emit(0x910043FF)
        if indirect:
            if ins.mnemonic == 'blr':
                target = ins.address + 4
                pages = (target >> 12) - (self.pc >> 12)
                if not -(1 << 20) <= pages < (1 << 20):
                    raise RewriteError('guarded BLR continuation exceeds ADRP reach')
                self.emit(0x9000001E | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5)
                self.emit(0x910003DE | (target & 4095) << 10)
            self.emit(0xD61F0000 | argument << 5)
            return
        if stack_check:
            if argument in (0xA9BF4FF2,0xA8C14FF2):
                self.x18(ins)
                return
            self.emit(argument)
        elif observation is not None:
            self.emit(observation.word)
        self.emit(branch(self.pc, ins.address + 4))

    def parameter(self, ins, parameter):
        base, stride, count = android_observation.parameter_layout()
        if stride != 8 or count != 4 or base % 8 or not 0 <= base <= 32760 - 24:
            raise RewriteError('unsupported checked guest parameter layout')
        scratch, state = self.begin(ins)
        value = memory(True, parameter.destination, state, base + parameter.slot * stride)
        if parameter.flags & 1:
            value = 0xB9400000 | ((base + parameter.slot * stride) // 4 << 10) | (state << 5) | parameter.destination
        self.emit(value)
        self.cleanup(scratch, state, parameter.a + 4)

    def tls(self, ins):
        scratch, state = self.begin(ins)
        raw = struct.unpack('<I', ins.bytes)[0]
        dest = raw & 31
        system = ins.op_str.split(',')[1 if ins.mnemonic == 'mrs' else 0].strip()
        offset = 8 if system == 'tpidr_el0' else 16
        if ins.mnemonic == 'mrs':
            self.emit(memory(True, scratch if dest == 18 else dest, state, offset))
            if dest == 18:
                self.emit(memory(False, scratch, state, 0))
        else:
            if dest == 18:
                self.emit(memory(True, scratch, state, 0))
            self.emit(memory(False, scratch if dest == 18 else dest, state, offset))
        self.cleanup(scratch, state, ins.address + 4)

    def x18(self, ins):
        sp_base = None
        frame, sp_delta = 32, 0
        mem = next((op for op in ins.operands if op.type == ARM64_OP_MEM), None)
        if mem is not None and ins.writeback and ins.reg_name(mem.mem.base) != 'sp':
            base = ins.reg_name(mem.mem.base).replace('w', 'x', 1)
            if any(op.type == ARM64_OP_REG and ins.reg_name(op.reg).replace('w', 'x', 1) == base
                   for op in ins.operands):
                raise RewriteError(f'0x{ins.address:x}: constrained-unpredictable writeback overlap')
        if re.search(r'\b(?:sp|wsp)\b', ins.op_str):
            if mem is not None:
                if (ins.mnemonic not in ('ldr', 'str', 'ldur', 'stur', 'ldrb', 'strb',
                                         'ldrh', 'strh', 'ldrsb', 'ldrsh', 'ldrsw',
                                         'ldurb', 'sturb', 'ldurh', 'sturh', 'ldursb',
                                         'ldursh', 'ldursw', 'ldp', 'stp', 'ldpsw', 'ldnp', 'stnp') or
                        ins.reg_name(mem.mem.base) != 'sp' or mem.mem.index):
                    raise RewriteError(f'0x{ins.address:x}: SP-sensitive x18 address unsupported')
                post = ins.writeback and ins.operands[-1].type == ARM64_OP_IMM
                effective = 0 if post else mem.mem.disp
                sp_delta = (ins.operands[-1].imm if post else mem.mem.disp) if ins.writeback else 0
                if sp_delta % 16:
                    raise RewriteError(f'0x{ins.address:x}: unaligned SP writeback')
                # Both the accessed address and the resulting guest SP must
                # remain above our 48-byte saved payload. The accessor writes
                # another 800 bytes below this allocated frame. Merely saving
                # registers elsewhere cannot protect a negative guest address.
                frame = (48 + max(0, -effective, -sp_delta) + 15) & ~15
            else:
                # Only Rn reads SP here. Dynamic SP destinations/pivots cannot
                # be proven safe by a fixed-size stack allocation.
                source = 0 if ins.mnemonic in ('cmp', 'cmn') else 1
                operands = ins.operands
                if (ins.mnemonic not in ('mov', 'add', 'sub', 'adds', 'subs', 'cmp', 'cmn') or
                        len(operands) <= source or operands[source].type != ARM64_OP_REG or
                        ins.reg_name(operands[source].reg) not in ('sp', 'wsp') or
                        (ins.mnemonic not in ('cmp', 'cmn') and
                         any(ins.reg_name(reg) in ('sp', 'wsp') for reg in ins.regs_access()[1]))):
                    raise RewriteError(f'0x{ins.address:x}: SP-sensitive x18 arithmetic/pivot unsupported')
                frame = 48
            if not 0 < frame <= 4095 or not 0 <= frame + sp_delta <= 4095:
                raise RewriteError(f'0x{ins.address:x}: SP-sensitive x18 frame out of bounds')
            sp_base = [r for r in range(16) if r not in registers(ins)][2]
        if any(ins.group(group) for group in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)) and ins.mnemonic not in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            raise RewriteError(f'0x{ins.address:x}: indirect x18 control flow unsupported')
        if ins.mnemonic in EXCLUSIVE_LOADS | EXCLUSIVE_STORES:
            raise RewriteError(f'0x{ins.address:x}: exclusive x18 instruction unsupported')
        scratch, state = self.begin(ins, sp_base=sp_base, frame=frame)
        self.emit(memory(True, scratch, state, 0))
        raw = struct.unpack('<I', ins.bytes)[0]
        if ins.mnemonic in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            cond_pc = self.pc
            self.emit(0)
            self.cleanup(scratch, state, ins.address + 4)
            taken = self.pc
            mask = 0x3FFF if ins.mnemonic in ('tbz', 'tbnz') else 0x7FFFF
            rewritten = raw & ~(mask << 5 | 31) | (((taken - cond_pc) // 4 & mask) << 5) | scratch
            self.data[cond_pc:cond_pc + 4] = word(rewritten)
            self.cleanup(scratch, state, ins.operands[-1].imm)
            return
        if ins.mnemonic in ('adr', 'adrp'):
            target = ins.operands[-1].imm
            delta = target - self.pc if ins.mnemonic == 'adr' else (target // 4096 - self.pc // 4096)
            if ins.mnemonic=='adr' and not -(1<<20)<=delta<(1<<20):
                pages=target//4096-self.pc//4096
                if not -(1<<20)<=pages<(1<<20):
                    raise RewriteError(f'0x{ins.address:x}: PC-relative target out of range')
                self.emit(0x90000000|((pages&3)<<29)|((pages>>2&0x7FFFF)<<5)|scratch)
                self.emit(0x91000000|((target&4095)<<10)|(scratch<<5)|scratch)
            else:
                if not -(1 << 20) <= delta < (1 << 20):
                    raise RewriteError(f'0x{ins.address:x}: PC-relative target out of range')
                self.emit((0x10000000 if ins.mnemonic == 'adr' else 0x90000000) | ((delta & 3) << 29) | ((delta >> 2 & 0x7FFFF) << 5) | scratch)
        elif ins.mnemonic.startswith('ldr') and '[' not in ins.op_str:
            target = ins.operands[-1].imm
            delta = target - self.pc
            if delta % 4 or not -(1 << 20) <= delta < (1 << 20):
                raise RewriteError(f'0x{ins.address:x}: literal target out of range')
            self.emit(raw & ~((0x7FFFF << 5) | 31) | ((delta // 4 & 0x7FFFF) << 5) | scratch)
        else:
            self.emit(substitute(ins, scratch, sp_base=sp_base))
        self.emit(memory(False, scratch, state, 0))
        self.cleanup(scratch, state, ins.address + 4, sp_base=sp_base, adjustment=frame + sp_delta)

    def finish(self):
        # Flush only between complete trampolines. Every trampoline exit is an
        # unconditional branch, so execution cannot fall into a literal pool.
        # Bounding each chunk also avoids the ARM64 LDR-literal +/-1 MiB limit
        # when a production module needs many megabytes of patched code.
        if self.pc % 8:
            self.emit(0xD503201F)
        slots = {}
        for _, _, kind in self.literals:
            if kind not in slots:
                slots[kind] = self.pc
                self.fixups.append(Fixup(self.pc, kind))
                self.data.extend(b'\0' * 8)
        for pc, reg, kind in self.literals:
            delta = slots[kind] - pc
            if not -(1 << 20) <= delta < (1 << 20):
                raise RewriteError(f'0x{pc:x}: helper literal out of range')
            self.data[pc:pc + 4] = word(0x58000000 | ((delta // 4 & 0x7FFFF) << 5) | reg)
        self.literals.clear()
        self.pool_start = self.pc


def rewrite(raw, entry_offset=0, text_size=None, *, code_ranges=None, patch_offset=None, entry_offsets=None, profile=None,
            indirect_policy='strict', package_version=1, guarded_indirect_offsets=(), checked_stack=False,
            readonly_ranges=(), proven_guest_indirect_offsets=(), checked_call_targets=None, protected_ranges=(),
            checked_call_forest_offsets=(), checked_call_forest_targets=(), independent_entry_offsets=None):
    """Rewrite selected ARM64 code while preserving all other raw image bytes.

    Ranges are image-relative, half-open (start, end) pairs within text_size.
    Omission selects the whole text segment for the original raw-fixture API.
    patch_offset optionally reserves aligned padding before appended code; NSO
    callers can align it to their module mapping granularity (for example 16 KiB).
    entry_offsets must include every function/callback/indirect entry proven by
    the caller. The raw API declares only entry_offset when omitted. Exclusive
    regions allow only proven retry edges and reject other cycles, unknown exits and overlapping reservations, including
    regions without x18; relocated regions additionally reject SP use and any
    external entry into their interior.
    Guarded transfers require explicit package v2 and guarded-host policy plus
    caller-selected offsets. The standalone raw CLI never enables this policy.
    readonly_ranges declares immutable original storage beyond text_size; the
    NSO importer supplies its actual RO section. Halfword dispatch requires
    this fact as well as its independently checked source guard and table.
    proven_guest_indirect_offsets names native-GPR RO switches; they retain
    the original BR after the same proof and are never host dispatch gates.
    checked_call_targets is an internal raw-fixture API for exact virtual-X18
    calls to independently selected entry roots. NSO import chooses only its
    compiled versioned contract; the CLI exposes no caller-supplied mapping.
    """
    if indirect_policy not in ('strict', 'guarded-host'):
        raise RewriteError('unsupported indirect policy')
    if package_version not in (1, 2) or (indirect_policy == 'guarded-host' and package_version != 2):
        raise RewriteError('guarded host transfers require package version 2')
    if not isinstance(checked_stack, bool) or (checked_stack and package_version != 2):
        raise RewriteError('checked stack requires explicit boolean and package version 2')
    guarded = set(guarded_indirect_offsets)
    if checked_call_targets is not None and not isinstance(checked_call_targets, Mapping):
        raise RewriteError('checked call targets must be an explicit mapping')
    checked_calls = dict(checked_call_targets or {})
    forest_sites = set(checked_call_forest_offsets)
    forest_targets = tuple(checked_call_forest_targets)
    if bool(forest_sites) != bool(forest_targets):
        raise RewriteError('checked call forest requires both source sites and targets')
    if forest_sites and (not checked_stack or package_version != 2 or
                         forest_sites & (guarded | checked_calls.keys())):
        raise RewriteError('checked call forest requires checked v2 and disjoint source sites')
    if (any(type(pc) is not int for pc in forest_sites) or
            any(type(pc) is not int or pc <= 0 or pc % 4 for pc in forest_targets) or
            any(a >= b for a, b in zip(forest_targets, forest_targets[1:]))):
        raise RewriteError('checked call forest requires sorted unique aligned integer targets')
    if checked_calls and (not checked_stack or package_version != 2 or checked_calls.keys() & guarded):
        raise RewriteError('checked calls require checked v2 mode and cannot be host gates')
    if any(type(pc) is not int or type(target) is not int for pc, target in checked_calls.items()):
        raise RewriteError('checked call offsets and targets must be integers')
    guest_tables=set(proven_guest_indirect_offsets)
    if (checked_calls.keys() | forest_sites) & guest_tables:
        raise RewriteError('checked calls cannot overlap guest table transfers')
    if guest_tables and (not checked_stack or guest_tables&guarded):
        raise RewriteError('proven guest tables require checked mode and cannot be host gates')
    if guarded and indirect_policy != 'guarded-host':
        raise RewriteError('guarded transfer sites require explicit guarded-host policy')
    text_size = len(raw) if text_size is None else text_size
    if not raw or len(raw) % 4 or not 0 < text_size <= len(raw) or text_size % 4:
        raise RewriteError('invalid/unaligned raw image or text size')
    readonly_ranges=list(readonly_ranges)
    end_before=text_size
    for item in readonly_ranges:
        if (not isinstance(item,(tuple,list)) or len(item)!=2 or
                any(not isinstance(x,int) for x in item) or
                not end_before<=item[0]<item[1]<=len(raw) or item[0]%4 or item[1]%4):
            raise RewriteError('invalid immutable read-only range outside text')
        end_before=item[1]
    ranges = [(0, text_size)] if code_ranges is None else list(code_ranges)
    previous_end = 0
    for item in ranges:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise RewriteError('invalid code range')
        start, end = item
        if (not isinstance(start, int) or not isinstance(end, int) or
                start % 4 or end % 4 or not previous_end <= start < end <= text_size):
            raise RewriteError('invalid/unaligned/overlapping code range')
        previous_end = end
    if not ranges:
        raise RewriteError('empty code ranges')
    if entry_offset % 4 or not any(start <= entry_offset < end for start, end in ranges):
        raise RewriteError('entry offset outside selected code')
    patch_offset = len(raw) if patch_offset is None else patch_offset
    if not isinstance(patch_offset, int) or patch_offset % 4 or patch_offset < len(raw):
        raise RewriteError('invalid/unaligned patch offset')
    instructions = []
    for start,end in ranges:
        for pc in range(start,end,4):
            decoded=decode(struct.unpack_from('<I',raw,pc)[0],pc)
            instructions.append(decoded if isinstance(decoded,FatalWord) else Instruction(decoded))
    by_pc = {ins.address: ins for ins in instructions}
    kinds = {ins.address: site_kind(ins) for ins in instructions}
    if checked_stack:
        for ins in instructions:
            if ins.mnemonic in ('cmp', 'cmn'):
                continue
            if any(ins.reg_name(reg) in ('sp', 'wsp') for reg in ins.regs_access()[1]):
                if stack_check_operation(struct.unpack('<I', ins.bytes)[0]) is None:
                    raise RewriteError(f'0x{ins.address:x}: unsupported checked SP/x18 instruction')
                kinds[ins.address] = 'stack_check'
    for pc in guarded:
        if pc not in by_pc:
            raise RewriteError('guarded transfer outside selected code')
        indirect_register(by_pc[pc])
        kinds[pc] = 'gate'
    direct_entries = set()
    for ins in instructions:
        if ins.mnemonic in ('b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz') or ins.mnemonic.startswith('b.'):
            target = ins.operands[-1].imm
            if target not in by_pc:
                raise RewriteError(f'0x{ins.address:x}: direct branch outside selected code')
            direct_entries.add(target)
    roots = {entry_offset} if entry_offsets is None else {entry_offset, *entry_offsets}
    if any(not isinstance(root, int) or root not in by_pc for root in roots):
        raise RewriteError('entry root outside selected code')
    if independent_entry_offsets is None:
        independent_roots=set(roots)
    else:
        try:
            independent_roots={entry_offset,*independent_entry_offsets}
        except TypeError as error:
            raise RewriteError('invalid independent entry roots') from error
        if any(type(root) is not int for root in independent_roots) or not independent_roots<=roots:
            raise RewriteError('independent entry roots must be selected declared entries')
    for pc, target in checked_calls.items():
        if (pc not in by_pc or struct.unpack('<I', by_pc[pc].bytes)[0] != 0xD63F0240 or
                target not in by_pc or target not in independent_roots or target in (pc, pc + 4)):
            raise RewriteError('checked call requires exact BLR X18 and a distinct independent selected entry root')
        kinds[pc] = 'checked_call'
    if any(target not in by_pc or target not in independent_roots for target in forest_targets):
        raise RewriteError('checked call forest target is not an independent selected source entry root')
    for pc in forest_sites:
        if pc not in by_pc or struct.unpack('<I', by_pc[pc].bytes)[0] != 0xD63F0240:
            raise RewriteError('checked call forest requires exact original BLR X18')
        kinds[pc] = 'checked_call_forest_stub'
    byte_jumps = {}
    native_tables={}
    producer_entries = roots | direct_entries
    if checked_stack:
        for ins in instructions:
            if struct.unpack('<I', ins.bytes)[0] != 0xD61F0240:
                continue
            plan = x18_jump_table(ins,by_pc,producer_entries,raw,readonly_ranges,root_entries=roots,text_size=text_size)
            if plan is None:
                raise RewriteError(f'0x{ins.address:x}: unproven byte dispatch br x18')
            targets = {plan['base']+value*4 for value in plan.get('target_values',range(plan['count']))}
            if not targets <= by_pc.keys():
                raise RewriteError(f'0x{ins.address:x}: byte dispatch target outside selected code')
            roots.update(targets)
            producer_entries.update(targets)
            byte_jumps[ins.address] = plan
            kinds[ins.address] = 'byte_jump'
        pending_tables=set(guest_tables)
        while pending_tables:
            progressed=False
            for pc in sorted(pending_tables):
                if pc not in by_pc:
                    raise RewriteError('proven guest table outside selected code')
                plan=readonly_guest_table(by_pc[pc],by_pc,producer_entries,raw,readonly_ranges,
                                          known_tables=(byte_jumps,native_tables),root_entries=independent_roots,text_size=text_size,protected_ranges=protected_ranges)
                if plan is None:
                    continue
                targets={plan['base']+value*4 for value in plan['target_values']}
                if not targets<=by_pc.keys():
                    raise RewriteError(f'0x{pc:x}: guest table target outside selected code')
                roots.update(targets)
                producer_entries.update(targets)
                native_tables[pc]=plan;pending_tables.remove(pc);progressed=True
            if not progressed:
                raise RewriteError(f'0x{min(pending_tables):x}: unproven read-only guest table')
        # Added target entries must not invalidate another producer's proof.
        for pc, plan in byte_jumps.items():
            if x18_jump_table(by_pc[pc],by_pc,producer_entries,raw,readonly_ranges,root_entries=roots,text_size=text_size)!=plan:
                raise RewriteError(f'0x{pc:x}: byte dispatch target enters a producer')
        for pc,plan in native_tables.items():
            if readonly_guest_table(by_pc[pc],by_pc,producer_entries,raw,readonly_ranges,
                                    known_tables=(byte_jumps,native_tables),root_entries=independent_roots,text_size=text_size,protected_ranges=protected_ranges)!=plan:
                raise RewriteError(f'0x{pc:x}: guest table target enters a producer')
    all_tables=[*native_tables.values(),*byte_jumps.values()]
    table_loads={plan['load_offset']:plan for plan in all_tables if 'load_offset' in plan}
    if len(table_loads)!=sum('load_offset' in plan for plan in all_tables):
        raise RewriteError('runtime guest table loads overlap')
    for pc in table_loads:
        plan=table_loads[pc]
        permitted=set(plan.get('permitted_source_rewrite_offsets',()))
        if any(kinds[at] is not None and not (at in permitted and kinds[at]=='x18') and
               not (plan.get('virtual_target_register')==18 and at==plan['offset'] and kinds[at]=='byte_jump')
               for at in range(plan.get('proof_start_offset',plan.get('zero_extend_offset')),plan['offset']+4,4)):
            raise RewriteError('runtime guest table overlaps another source rewrite')
        kinds[pc]='readonly_table_load'
    observations, parameters = android_observation.plan(profile, by_pc, kinds, roots, sys.modules[__name__])
    if (checked_calls.keys() | forest_sites) & (observations.keys() | parameters.keys() | {p.b for p in parameters.values()}):
        raise RewriteError('checked calls cannot overlap profile/parameter rewrites')
    for plan in table_loads.values():
        window=set(range(plan.get('proof_start_offset',plan.get('zero_extend_offset')),plan['offset']+4,4))
        if window & (observations.keys()|parameters.keys()|{p.b for p in parameters.values()}):
            raise RewriteError('runtime guest table overlaps profile/parameter rewrite')
    for pc in observations:
        kinds[pc] = 'gate'
    for parameter in parameters.values():
        kinds[parameter.a] = 'parameter'
        kinds[parameter.b] = 'parameter_tail'
    # Native wait is an explicit opt-in. Unknown raw transfers cannot prove
    # that its ordinary TLS producer executes. Supply only already validated
    # lowering facts, including the entire finite guest case-entry set.
    native_wait_transfers={pc:('host',()) for pc in guarded}
    for pc,plan in {**byte_jumps,**native_tables}.items():
        values=plan['target_values'] if 'target_values' in plan else range(plan['count'])
        native_wait_transfers[pc]=('finite',tuple(sorted({plan['base']+value*4 for value in values})))
    native_wait_transfers.update((pc,('checked-call',(target,))) for pc,target in checked_calls.items())
    native_wait_transfers.update((pc,('checked-call-forest',forest_targets)) for pc in forest_sites)
    regions = android_exclusive.plan_regions(instructions, kinds, roots, sys.modules[__name__],
                                            native_wait_transfers=native_wait_transfers)
    region_entries = {region.entry: region for region in regions}
    region_words = {ins.address for region in regions for ins in region.instructions}
    if any(region_words & set(range(p.get('proof_start_offset',p.get('zero_extend_offset')),p['offset']+4,4)) for p in table_loads.values()):
        raise RewriteError('runtime guest table overlaps exclusive region')
    emitter = Emitter(raw + b'\0' * (patch_offset - len(raw)))
    forest = emitter.checked_call_forest(forest_targets, forest_sites) if forest_sites else None
    for ins in instructions:
        kind = kinds[ins.address]
        if kind == 'parameter_tail':
            emitter.data[ins.address:ins.address + 4] = word(0xD503201F)
            continue
        if ins.address in region_entries:
            if emitter.pc - emitter.pool_start >= HELPER_POOL_CHUNK:
                emitter.finish()
            android_exclusive.emit_region(emitter, region_entries[ins.address], sys.modules[__name__])
            continue
        if ins.address in region_words or not kind:
            continue
        if emitter.pc - emitter.pool_start >= HELPER_POOL_CHUNK:
            emitter.finish()
        start = emitter.pc
        if ins.address in forest_sites:
            emitter.checked_call_forest_stub(ins, forest['root'])
        elif ins.address in checked_calls:
            emitter.checked_call(ins, checked_calls[ins.address])
        elif kind == 'stack_check':
            emitter.gate(ins, stack_check=True)
        elif ins.address in table_loads:
            emitter.readonly_table_load(ins,table_loads[ins.address])
        elif ins.address in byte_jumps:
            emitter.byte_jump(ins, byte_jumps[ins.address])
        elif ins.address in guarded:
            emitter.gate(ins, indirect=True)
        elif ins.address in observations:
            emitter.gate(ins, observations[ins.address])
        elif ins.address in parameters:
            emitter.parameter(ins, parameters[ins.address])
        else:
            getattr(emitter, kind)(ins)
        emitter.sites.append(Site(ins.address, start, f'{ins.mnemonic} {ins.op_str}'))
        try:
            source_branch = branch(ins.address, start)
        except RewriteError as error:
            if forest is not None:
                raise RewriteError(f'post-forest source trampoline branch range at 0x{ins.address:x} to 0x{start:x}') from error
            raise
        emitter.data[ins.address:ins.address + 4] = word(source_branch)
    emitter.finish()
    return Image(bytes(emitter.data), entry_offset, tuple(emitter.fixups), tuple(emitter.gates), tuple(emitter.sites),
                 profile=profile, gate_provenance=tuple(emitter.gate_provenance),
                 parameters=tuple(profile.parameters) if profile is not None else (),
                 indirect_policy=indirect_policy, package_version=package_version, checked_stack=checked_stack,
                 checked_calls=tuple(sorted(checked_calls.items())),
                 checked_call_forests=(forest,) if forest is not None else ()).validate()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--entry-offset', type=lambda x: int(x, 0), default=0)
    parser.add_argument('--text-size', type=lambda x: int(x, 0))
    args = parser.parse_args()
    image = rewrite(args.input.read_bytes(), args.entry_offset, args.text_size)
    args.output.write_bytes(image.bytes)
    args.output.with_suffix(args.output.suffix + '.json').write_text(json.dumps(image.metadata(), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
