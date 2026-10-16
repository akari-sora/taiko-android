"""Validate native or relocate single-entry ARM64 exclusive regions as units.

The API object is android_rewrite, supplied by the caller to avoid an import
cycle. Only the external-entry prologue and real-exit epilogues access host
state or scratch memory. Recognized failed-store retries retain that frame
and branch straight back to the relocated exclusive load, without a host call.
"""
from dataclasses import dataclass
import re
import struct

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG

MAX_REGION_WORDS = 4096
MAX_TAIL_WORDS = 64
CONDITIONAL = {'cbz', 'cbnz', 'tbz', 'tbnz'}
TAIL_ARITHMETIC = {
    'nop', 'mov', 'movz', 'movn', 'movk', 'add', 'adds', 'sub', 'subs',
    'cmp', 'cmn', 'and', 'ands', 'orr', 'eor', 'bic', 'bics', 'orn', 'eon',
    'tst', 'lsl', 'lsr', 'asr', 'ror', 'ubfx', 'sbfx', 'bfi', 'bfxil',
    'ubfiz', 'sbfiz', 'extr', 'csel', 'csinc', 'csinv', 'csneg', 'cset',
    'csetm', 'cinc', 'cinv', 'cneg', 'neg', 'negs', 'mvn', 'adr', 'adrp',
}


@dataclass(frozen=True)
class Region:
    entry: int
    instructions: tuple
    reservation_terminals: frozenset
    retry_edges: frozenset
    exit_edges: frozenset
    scratch: int
    state: int


def successors(ins):
    if ins.mnemonic == 'b':
        return (ins.operands[-1].imm,)
    if ins.mnemonic in CONDITIONAL or ins.mnemonic.startswith('b.'):
        return (ins.address + 4, ins.operands[-1].imm)
    if ins.mnemonic == 'bl':
        return (ins.address + 4, ins.operands[-1].imm)
    if any(ins.group(group) for group in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)):
        return ()
    return (ins.address + 4,)


def validate_exclusive(ins, api):
    """Reject Arm constrained-unpredictable operands even if Capstone accepts."""
    value = struct.unpack('<I', ins.bytes)[0]
    rt, rn, rt2, status = value & 31, value >> 5 & 31, value >> 10 & 31, value >> 16 & 31
    pair = ins.mnemonic in {'ldxp', 'ldaxp', 'stxp', 'stlxp'}
    if ins.mnemonic in {'ldxp', 'ldaxp'} and rt == rt2:
        raise api.RewriteError(f'0x{ins.address:x}: constrained-unpredictable exclusive pair load')
    if ins.mnemonic in api.EXCLUSIVE_STORES and status != 31:
        operands = {rt, rn} | ({rt2} if pair else set())
        if status in operands:
            raise api.RewriteError(f'0x{ins.address:x}: constrained-unpredictable exclusive status overlap')


def validate_memory_operands(ins, api):
    memory = next((operand.mem for operand in ins.operands if operand.type == ARM64_OP_MEM), None)
    if memory is None:
        return
    data = [operand.reg for operand in ins.operands if operand.type == ARM64_OP_REG]
    base_name = ins.reg_name(memory.base)
    base = 30 if base_name == 'lr' else 29 if base_name == 'fp' else int(base_name[1:]) if re.fullmatch(r'[xw]\d+', base_name) else None
    data_names = {ins.reg_name(register) for register in data}
    if ins.writeback and base is not None and ({f'x{base}', f'w{base}', base_name} & data_names):
        raise api.RewriteError(f'0x{ins.address:x}: constrained-unpredictable writeback overlap in exclusive window')
    if ins.mnemonic in {'ldp', 'ldnp', 'ldpsw'} and len(data) >= 2 and data[0] == data[1]:
        raise api.RewriteError(f'0x{ins.address:x}: constrained-unpredictable pair load in exclusive window')


def register_number(ins, register):
    name = ins.reg_name(register)
    if name in {'lr', 'fp'}:
        return 30 if name == 'lr' else 29
    return int(name[1:]) if re.fullmatch(r'[xw]\d+', name) else None


def writes_register(ins, number):
    return any(register_number(ins, register) == number for register in ins.regs_access()[1])


def reaches_head(by_pc, first, head, api):
    """Bounded detection prevents an unsupported retry using per-attempt gates.

    A separate exclusive load starts a different operation. Unknown/oversized
    control flow is not evidence that returning through a host gate is safe.
    """
    pending, seen = [first], set()
    while pending:
        pc = pending.pop()
        if pc == head:
            return True
        if pc in seen:
            continue
        if pc not in by_pc or len(seen) >= MAX_TAIL_WORDS:
            return None
        seen.add(pc)
        ins = by_pc[pc]
        if api.is_fatal_instruction(ins):
            return None  # A retry proof must not cross a synchronous fault.
        if ins.mnemonic in api.EXCLUSIVE_LOADS:
            continue
        if ins.mnemonic == 'ret' and (not ins.operands or ins.reg_name(ins.operands[0].reg) in {'lr', 'x30'}):
            continue  # Ordinary ABI return leaves this operation.
        if (ins.group(CS_GRP_CALL) or ins.group(CS_GRP_RET) or
                (ins.group(CS_GRP_JUMP) and ins.mnemonic != 'b' and
                 ins.mnemonic not in CONDITIONAL and not ins.mnemonic.startswith('b.'))):
            return None  # No successor list is not a proof of an indirect exit.
        pending.extend(successors(ins))
    return False


def retry_tail(by_pc, store, head, body, api):
    """Recognize a Wstatus-tested retry, optionally with a finite counter tail."""
    first = store.address + 4
    test = by_pc.get(first)
    status = struct.unpack('<I', store.bytes)[0] >> 16 & 31
    result = None
    if (test is not None and test.mnemonic in {'cbz', 'cbnz'} and
            test.reg_name(test.operands[0].reg) == f'w{status}' and status != 31):
        target = test.operands[-1].imm
        if test.mnemonic == 'cbnz' and target == head and first + 4 not in body:
            result = ({first}, {(first, head)})
        elif test.mnemonic == 'cbz' and target != head:
            tail, prefix, pc = {first}, [], first + 4
            for _ in range(MAX_TAIL_WORDS - 1):
                ins = by_pc.get(pc)
                if ins is None or pc in body:
                    break
                tail.add(pc)
                if ins.mnemonic == 'b' and ins.operands[-1].imm == head:
                    result = (tail, {(pc, head)})
                    break
                if ((ins.mnemonic == 'b.ne' or ins.mnemonic == 'cbnz') and
                        ins.operands[-1].imm == head):
                    if pc + 4 in body | tail:
                        break
                    if ins.mnemonic == 'b.ne':
                        writers = [item for item in prefix if any(item.reg_name(register) == 'nzcv'
                                   for register in item.regs_access()[1])]
                    else:
                        tested = register_number(ins, ins.operands[0].reg)
                        writers = [item for item in prefix if tested is not None and writes_register(item, tested)]
                    decrement = writers[-1] if writers else None
                    if decrement is None or decrement.mnemonic not in {'sub', 'subs'}:
                        break
                    operands = decrement.operands
                    if (len(operands) != 3 or operands[0].type != ARM64_OP_REG or
                            operands[1].type != ARM64_OP_REG or operands[0].reg != operands[1].reg or
                            operands[2].type != ARM64_OP_IMM or operands[2].imm != 1 or operands[2].shift.value):
                        break
                    counter = register_number(decrement, operands[0].reg)
                    if (counter is None or counter == status or
                            any(writes_register(by_pc[at], counter) for at in body) or
                            any(item.address != decrement.address and writes_register(item, counter) for item in prefix)):
                        break
                    if ins.mnemonic == 'b.ne' and decrement.mnemonic != 'subs':
                        break
                    if ins.mnemonic == 'cbnz' and ins.operands[0].reg != operands[0].reg:
                        break
                    if reaches_head(by_pc, pc + 4, head, api) is not False:
                        break  # Counter exhaustion must really leave this loop.
                    result = (tail, {(pc, head)})
                    break
                if (ins.mnemonic not in TAIL_ARITHMETIC or
                        any(operand.type not in {ARM64_OP_REG, ARM64_OP_IMM} for operand in ins.operands)):
                    break
                prefix.append(ins)
                pc += 4
            if result is not None and target in result[0] | body:
                result = None  # A successful store must leave this retry attempt.
    if result is not None:
        return result
    reachable = reaches_head(by_pc, first, head, api)
    if reachable is not False:
        raise api.RewriteError(f'0x{store.address:x}: unsupported/unproven exclusive retry tail')
    return set(), set()


def require_acyclic(nodes, by_pc, retries, exits, api):
    colors = {}
    for first in nodes:
        pending = [(first, False)]
        while pending:
            pc, leaving = pending.pop()
            if leaving:
                colors[pc] = 2
                continue
            if colors.get(pc) == 1:
                raise api.RewriteError(f'0x{pc:x}: unsupported cycle in exclusive body/tail')
            if colors.get(pc) == 2:
                continue
            colors[pc] = 1
            pending.append((pc, True))
            pending.extend((target, False) for target in successors(by_pc[pc])
                           if target in nodes and (pc, target) not in retries | exits)


def require_single_entry(nodes, entry, instructions, entry_offsets, api):
    if (set(entry_offsets) & nodes) - {entry}:
        raise api.RewriteError(f'0x{entry:x}: external entry in exclusive region interior')
    for ins in instructions:
        if ins.address not in nodes and any(target in nodes - {entry} for target in successors(ins)):
            raise api.RewriteError(f'0x{ins.address:x}: external entry into exclusive region interior')


def native_dual_load_lock(start, by_pc, kinds, api):
    """Recognize only the native seven-word acquire-lock topology.

    The initial zero load can reach the shared store directly; a busy lock
    clears the reservation and reloads, and a failed store retries that second
    load. These are one operation, not two overlapping exclusive windows.
    Keep the bytes in place: this proof does not support any source rewrite.
    """
    nodes = tuple(by_pc.get(start.address + offset) for offset in range(0, 28, 4))
    if any(ins is None for ins in nodes):
        return False
    values = tuple(struct.unpack('<I', ins.bytes)[0] for ins in nodes)
    loaded, base, stored = values[0] & 31, values[0] >> 5 & 31, values[5] & 31
    expected = (0x885FFC00 | base << 5 | loaded, 0x34000080 | loaded,
                0xD5033F5F, 0x885FFC00 | base << 5 | loaded,
                0x35FFFFC0 | loaded,
                0x8800FC00 | loaded << 16 | base << 5 | stored,
                0x35FFFFA0 | loaded)
    if values != expected:
        return False
    if len({loaded, base, stored}) != 3 or any(reg in {18, 29, 30, 31} for reg in (loaded, base, stored)):
        raise api.RewriteError(f'0x{start.address:x}: unsupported registers in native dual-load exclusive lock')
    if any(kinds[ins.address] is not None for ins in nodes):
        raise api.RewriteError(f'0x{start.address:x}: source rewrite in native dual-load exclusive lock')
    for ins in nodes:
        validate_memory_operands(ins, api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES:
            validate_exclusive(ins, api)
    return True


def native_compare_retry(start, by_pc, kinds, api):
    """Native 32-bit capacity CAS refreshes its bound after either retry.

    Both a compare mismatch (via CLREX) and a failed store reload the expected
    value with LDAR. Include that refresh and the initial bound check in the
    single-entry union; nothing in this exact topology may require rewriting.
    """
    entry=start.address-32
    if entry<0:return None
    nodes=tuple(by_pc.get(entry+offset) for offset in range(0,56,4))
    if any(op is None for op in nodes) or nodes[3].mnemonic!='b':
        return None
    values=tuple(struct.unpack('<I',op.bytes)[0] for op in nodes)
    expected,base,status=values[0]&31,values[0]>>5&31,values[8]&31
    exit_target=nodes[3].operands[-1].imm
    if (entry<=exit_target<entry+56 or exit_target not in by_pc or entry+56 not in by_pc or
            nodes[7].mnemonic!='b.hi' or nodes[7].operands[-1].imm!=exit_target):
        return None
    words=(0x88DFFC00|base<<5|expected,0x7100041F|expected<<5,0x540000C9,
           api.branch(entry+12,exit_target),0xD5033F5F,0x88DFFC00|base<<5|expected,
           0x7100041F|expected<<5,0x54000008|(((exit_target-entry-28)//4)&0x7FFFF)<<5,
           0x885FFC00|base<<5|status,0x6B00001F|expected<<16|status<<5,
           0x54FFFF41,0x91000400|expected<<5|expected,
           0x8800FC00|status<<16|base<<5|expected,0x35FFFF00|status)
    if values!=words:return None
    if len({base,expected,status})!=3 or any(reg in {18,29,30,31} for reg in (base,expected,status)):
        raise api.RewriteError(f'0x{entry:x}: unsupported registers in native capacity compare retry')
    if any(kinds[op.address] is not None for op in nodes):
        raise api.RewriteError(f'0x{entry:x}: source rewrite in native capacity compare retry')
    for op in nodes:
        validate_memory_operands(op,api)
        if op.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:
            validate_exclusive(op,api)
    return entry


def native_rotated_lock(start, by_pc, kinds, api):
    """A native try-lock puts its store before the exclusive-load entry.

    Failed STXR falls through to a new reservation; a busy load clears that
    reservation before leaving. No code may enter the store/status test first.
    """
    entry=start.address-8
    if entry<0:return None
    nodes=tuple(by_pc.get(entry+offset) for offset in range(0,20,4))
    if any(op is None for op in nodes) or nodes[1].mnemonic!='cbz':return None
    values=tuple(struct.unpack('<I',op.bytes)[0] for op in nodes)
    data,base,status=values[0]&31,values[0]>>5&31,values[0]>>16&31
    load=values[2]&0xFFFFFC00;exit_target=nodes[1].operands[-1].imm
    if (load not in (0x885F7C00,0x885FFC00) or entry<=exit_target<entry+20 or
            exit_target not in by_pc or entry+20 not in by_pc):
        return None
    words=(0x88007C00|status<<16|base<<5|data,
           0x34000000|(((exit_target-entry-4)//4)&0x7FFFF)<<5|status,
           load|base<<5|status,0x34FFFFA0|status,0xD5033F5F)
    if values!=words:return None
    if len({base,status,data})!=3 or any(reg in {18,29,30,31} for reg in (base,status,data)):
        raise api.RewriteError(f'0x{entry:x}: unsupported registers in native rotated lock')
    if any(kinds[op.address] is not None for op in nodes):
        raise api.RewriteError(f'0x{entry:x}: source rewrite in native rotated lock')
    for op in nodes:
        validate_memory_operands(op,api)
        if op.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(op,api)
    return entry


NATIVE_CONDITIONAL_WORDS = (
    (0x885FFD0A, 0x6B09015F, 0x54000100, 0x7100055F,
     0xD5033F5F, 0x2A0A03E9, 0x540006EB, 0x885FFD0A,
     0x6B09015F, 0x54FFFF41, 0x11000529, 0x880B7D09,
     0x7100017F, 0x7A411948, 0x2A0A03E9, 0x54FFFF0A),
    (0x885FFD49, 0x6B0B013F, 0x54000100, 0xD5033F5F,
     0x7100053F, 0x5400044B, 0x2A0903EB, 0x885FFD49,
     0x6B0B013F, 0x54FFFF41, 0x880B7D5F, 0x35FFFF2B),
    (0xD5033F5F, 0x2A0B03EA, 0x3400014A, 0x7100095F,
     0x540000E0, 0x885FFD2B, 0x6B0A017F, 0x54FFFF21,
     0x880C7D28, 0x2A0B03EA, 0x35FFFF0C),
    (0xC85F7D09, 0xB40000C9, 0xD5033F5F, 0xF94007E0,
     0xB50000C9, 0xC85F7D09, 0xB5FFFF89, 0xC80AFD00,
     0x35FFFF6A, 0x14000002),
    (0xD5033F5F, 0xAA0A03E9, 0xB940026A, 0x3400020A,
     0xF9000309, 0xC85F7D0A, 0xEB09015F, 0x54FFFF21,
     0xC80BFD18, 0xAA0A03E9, 0x35FFFF0B),
    (0xD5033F5F, 0x88DFFF28, 0x7100051F, 0x54001388,
     0x885FFF29, 0x6B08013F, 0x54FFFF41, 0x91000508,
     0x8809FF28, 0x35FFFF09),
    (0xF9400FA8, 0x885FFD08, 0x350000C8, 0xF9400FAA,
     0x52800029, 0x880B7D49, 0x35FFFF4B, 0x14000003,
     0x2A1F03E9, 0xD5033F5F),
    (0xF9400FA8, 0x885F7D08, 0x350000C8, 0xF9400FAA,
     0x52800029, 0x880B7D49, 0x35FFFF4B, 0x14000003,
     0x2A1F03E9, 0xD5033F5F),
    (0xF9400FA8, 0x885F7D08, 0x7100051F, 0x540000C1,
     0xF9400FA9, 0x5280004A, 0x880B7D2A, 0x35FFFF2B,
     0x14000002, 0xD5033F5F),
    (0xF9400FA8, 0x885F7D08, 0x350000C8, 0xF9400FA8,
     0x52800029, 0x880A7D09, 0x35FFFF4A, 0x1400000B,
     0xD5033F5F),
    (0xD5033F5F, 0x9100054A, 0x91004129, 0xF104015F,
     0x540000C0, 0x885F7D2C, 0x35FFFF4C, 0x880C7D2B,
     0x35FFFF2C, 0x14000036),
    (0xD5033F5F, 0x9100054A, 0x91004129, 0xEB0A017F,
     0x540000C0, 0x885F7D2D, 0x35FFFF4D, 0x880D7D2C,
     0x35FFFF2D, 0x14000027),
    (0x885F7F09, 0x6B0A013F, 0x540000E1, 0x1100054A,
     0x880B7F0A, 0x350000AB, 0x5280002A, 0x360000AA,
     0x14000008, 0xD5033F5F, 0x2A1F03EA, 0x370000AA,
     0x7100053F, 0x2A0903EA, 0x54FFFE4A, 0x1400003F),
    (
        0xD5033F5F, 0xAA0803ED, 0xA943AC0C, 0x8A0D016B,
        0xAA0C016C, 0x9100218B, 0xAA0D03E8, 0xC8DFFD6B,
        0xF940012D, 0xEB0D011F, 0x54FFFF01, 0xF940200D,
        0x3700024B, 0x8A0B01AB, 0x910005AC, 0xAA0C016B,
        0x8A2D010C, 0x8B0C016B, 0xC85F7D2C, 0xEB08019F,
        0x540000A1, 0xC80D7D2B, 0x35FFFF8D, 0x52800028,
        0x14000003, 0x2A1F03E8, 0xD5033F5F, 0x7100011F,
        0x9A8C116D, 0x17FFFFE5, 0x8A0A01AA, 0x910005AE,
        0x9100218C, 0xAA0E014A, 0x8A2D016D, 0x8B0D014A,
        0xC85FFD8D, 0xEB0B01BF, 0x54FFFB41, 0xC80B7D8A,
        0x35FFFB2B,
    ),
    (
        0xD5033F5F, 0x2A1F03EC, 0x2A1F03E8, 0x350001AC,
        0x0A09016D, 0x2A0B03EC, 0x3500014D, 0x885F7D4B,
        0x6B0C017F, 0x54FFFEE1, 0x2A090188, 0x880C7D48,
        0x35FFFEAC, 0x5280002C, 0x2A1F03E8, 0x34FFFEAC,
    ),
)
NATIVE_CONDITIONAL_FIELDS = (
    ((0,5),(5,16),(),(5,),(),(0,16),(),(0,5),(5,16),(),
     (0,5),(0,5,16),(5,),(5,),(0,16),()),
    ((0,5),(5,16),(),(),(5,),(),(0,16),(0,5),(5,16),(),
     (0,5,16),(0,)),
    ((),(0,16),(0,),(5,),(),(0,5),(5,16),(),(0,5,16),
     (0,16),(0,)),
    ((0,5),(0,),(),(0,),(0,),(0,5),(0,),(0,5,16),(0,),()),
    ((),(0,16),(0,5),(0,),(0,5),(0,5),(5,16),(),(0,5,16),(0,16),(0,)),
    ((),(0,5),(5,),(),(0,5),(5,16),(),(0,5),(0,5,16),(0,)),
    ((0,),(0,5),(0,),(0,),(0,),(0,5,16),(0,),(),(0,),()),
    ((0,),(0,5),(0,),(0,),(0,),(0,5,16),(0,),(),(0,),()),
    ((0,),(0,5),(5,),(),(0,),(0,),(0,5,16),(0,),(),()),
    ((0,),(0,5),(0,),(0,),(0,),(0,5,16),(0,),(),()),
    ((),(0,5),(0,5),(5,),(),(0,5),(0,),(0,5,16),(0,),()),
    ((),(0,5),(0,5),(5,16),(),(0,5),(0,),(0,5,16),(0,),()),
    ((0,5),(5,16),(),(0,5),(0,5,16),(0,),(0,),(0,),(),(),
     (0,),(0,),(5,),(0,16),(),()),
    ((), (0, 5, 16), (0, 5, 10), (0, 5, 16), (0, 5, 16), (0, 5), (0, 5, 16), (0, 5), (0, 5), (0, 5, 16), (), (0, 5), (0,), (0, 5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (0, 5, 16), (0, 5), (0, 5, 16), (), (0, 5, 16), (0,), (0,), (), (0, 5, 16), (), (0, 5), (0, 5, 16), (), (0, 5, 16), (0, 5), (0, 5), (0, 5, 16), (0, 5, 16), (0, 5, 16), (0, 5), (0, 5, 16), (), (0, 5, 16), (0,)),
    ((), (0,), (0,), (0,), (0, 5, 16), (0, 16), (0,), (0, 5), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (0,), (0,)),
)


def native_conditional_refresh(start, by_pc, kinds, api):
    """Return (all nodes, ordinary entry, reservation heads), or None.

    These observed schedules share a native refresh body across reservations.
    Registers are consistently renamed injectively, including intentionally
    reused expected/status roles; WZR and every ordering/condition bit stay fixed.
    FP-cell rows leave fixed X29/#24 outside the rename fields and retain
    both actual slot reads. Their closed-monitor joins stay outside the union.
    No instruction is emitted, patched, or allowed across a host call.
    """
    for variant, (words, fields) in enumerate(zip(NATIVE_CONDITIONAL_WORDS,
                                                NATIVE_CONDITIONAL_FIELDS)):
        begin = start.address - (0,0,20,0,20,16,4,4,4,4,20,20,0,72,28)[variant]
        block = tuple(by_pc.get(begin + i*4) for i in range(len(words)))
        if begin < 0 or any(ins is None for ins in block):
            continue
        external = ((6,),(5,),(2,4),(4,9),(3,),(3,),(),(),(),(7,),(4,9),(4,9),(15,),(),())[variant]
        roles, reverse, matched = {}, {}, True
        for index, (ins, expected, shifts) in enumerate(zip(block, words, fields)):
            value = struct.unpack('<I', ins.bytes)[0]
            mask = sum(31 << shift for shift in shifts)
            if index in external:
                mask |= 0x3FFFFFF if (variant,index) in ((3,9),(9,7),(10,9),(11,9),(12,15)) else 0x7FFFF << 5
            if value & ~mask != expected & ~mask:
                matched = False
                break
            for shift in shifts:
                role, actual = expected >> shift & 31, value >> shift & 31
                if role == 31:
                    matched = actual == 31
                elif (actual in {18,29,30,31} or roles.get(role,actual) != actual or
                      reverse.get(actual,role) != role):
                    matched = False
                else:
                    roles[role], reverse[actual] = actual, role
                if not matched:
                    break
            if not matched:
                break
        if not matched:
            continue
        nodes = {ins.address for ins in block}
        exits = [block[index].operands[-1].imm for index in external]
        exits.append(begin + len(words)*4)
        if any(pc in nodes or pc not in by_pc or api.is_fatal_instruction(by_pc[pc])
               for pc in exits):
            continue
        if any(kinds.get(pc,'missing') is not None for pc in nodes):
            raise api.RewriteError(f'0x{begin:x}: source rewrite in native conditional refresh')
        for ins in block:
            validate_memory_operands(ins,api)
            if ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES:
                validate_exclusive(ins,api)
        entry = begin + (0,0,12,0,16,4,0,0,0,0,20,20,0,4,28)[variant]
        heads = {begin+offset for offset in ((0,28),(0,28),(20,),(0,20),(20,),(16,),(4,),(4,),(4,),(4,),(20,),(20,),(0,),(72,144),(28,))[variant]}
        return nodes,entry,heads
    return None



def virtual_preload_cas(start, by_pc, kinds, api):
    """Relocate one tagged-pointer CAS, including its closed retry preload.

    The approved entry precedes the exclusive load. CLREX and failed STXR stay
    inside the same frame; only success and the invalid-tag branch publish X18.
    """
    begin=start.address-24;entry=start.address-12
    if begin<0:return None
    block=tuple(by_pc.get(begin+offset) for offset in range(0,60,4))
    if any(op is None for op in block) or block[2].mnemonic!='tbnz':return None
    values=tuple(struct.unpack('<I',op.bytes)[0] for op in block)
    loaded=values[6]&31;cell=values[6]>>5&31;expected=values[1]&31
    pointer=values[3]&31;mask=values[3]>>16&31;tag=values[4]>>16&31
    other_mask=values[11]>>16&31;other_tag=values[10]>>16&31
    invalid=block[2].operands[-1].imm
    nodes={op.address for op in block}
    if invalid in nodes or invalid not in by_pc or begin+60 not in by_pc:return None
    words=(0xD5033F5F,0xAA0003E0|loaded<<16|expected,
           0x37000000|(((invalid-begin-8)//4)&0x3FFF)<<5|loaded,
           0x8A000000|mask<<16|expected<<5|pointer,
           0xAA000000|tag<<16|pointer<<5|pointer,0xF9400412|pointer<<5,
           0xC85F7C00|cell<<5|loaded,0xEB00001F|expected<<16|loaded<<5,
           0x54FFFF01,0x8A000252|mask<<16,0xAA000252|other_tag<<16,
           0x8A000000|other_mask<<16|expected<<5|expected,
           0x8B000240|expected<<16|expected,0xC8127C00|cell<<5|expected,0x35FFFE72)
    if values!=words:return None
    roles=(loaded,cell,expected,pointer,mask,tag,other_mask,other_tag)
    if len(set(roles))!=8 or any(reg in {18,29,30,31} for reg in roles):
        raise api.RewriteError(f'0x{begin:x}: unsupported registers in virtual preload CAS')
    if any(kinds[pc] not in {None,'x18'} for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: unsupported ABI rewrite in virtual preload CAS')
    for op in block:
        validate_memory_operands(op,api)
        if op.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(op,api)
    used=set().union(*(api.registers(op) for op in block))
    available=[reg for reg in range(16) if reg not in used]
    if len(available)<2:
        raise api.RewriteError(f'0x{begin:x}: insufficient unused registers for virtual preload CAS')
    return Region(entry,block,frozenset((begin,begin+52)),
                  frozenset(((begin+32,begin),(begin+56,begin+4))),
                  frozenset(((begin+8,invalid),(begin+56,begin+60))),*available[:2])



def virtual_boolean_preload_cas(start, by_pc, kinds, api):
    """Exact boolean-result sibling of the shared tagged-pointer CAS layout.

    Reuse Region and the unchanged single-frame emitter. The source W18 status,
    both boolean joins and all pointer payload reads stay inside that frame.
    """
    begin=start.address-32;entry=start.address-12
    if begin<0:return None
    block=tuple(by_pc.get(begin+offset) for offset in range(0,76,4))
    if any(op is None for op in block) or block[4].mnemonic!='tbnz':return None
    values=tuple(struct.unpack('<I',op.bytes)[0] for op in block)
    loaded=values[8]&31;cell=values[8]>>5&31;expected=values[3]&31
    pointer=values[5]&31;mask=values[5]>>16&31;tag=values[6]>>16&31
    other_mask=values[13]>>16&31;other_tag=values[12]>>16&31
    invalid=block[4].operands[-1].imm;nodes={op.address for op in block}
    if invalid in nodes or invalid not in by_pc or begin+76 not in by_pc:return None
    words=(0xD5033F5F,0x2A1F03E0|expected,0x37000220|expected,
           0xAA0003E0|loaded<<16|expected,
           0x37000000|(((invalid-begin-16)//4)&0x3FFF)<<5|loaded,
           0x8A000000|mask<<16|expected<<5|pointer,
           0xAA000000|tag<<16|pointer<<5|pointer,0xF9400412|pointer<<5,
           0xC85F7C00|cell<<5|loaded,0xEB00001F|expected<<16|loaded<<5,
           0x54FFFEC1,0x8A000252|mask<<16,0xAA000252|other_tag<<16,
           0x8A000000|other_mask<<16|expected<<5|expected,
           0x8B000240|expected<<16|expected,0xC8127C00|cell<<5|expected,
           0x35FFFE32,0x52800020|expected,0x3607FE20|expected)
    if values!=words:return None
    roles=(loaded,cell,expected,pointer,mask,tag,other_mask,other_tag)
    if len(set(roles))!=8 or any(reg in {18,29,30,31} for reg in roles):
        raise api.RewriteError(f'0x{begin:x}: unsupported registers in virtual boolean preload CAS')
    if any(kinds[pc] not in {None,'x18'} for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: unsupported ABI rewrite in virtual boolean preload CAS')
    for op in block:
        validate_memory_operands(op,api)
        if op.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(op,api)
    used=set().union(*(api.registers(op) for op in block))
    available=[reg for reg in range(16) if reg not in used]
    if len(available)<2:
        raise api.RewriteError(f'0x{begin:x}: insufficient unused registers for virtual boolean preload CAS')
    return Region(entry,block,frozenset((begin,begin+60)),
                  frozenset(((begin+40,begin),(begin+64,begin+4),(begin+72,begin+12))),
                  frozenset(((begin+8,begin+76),(begin+16,invalid),(begin+72,begin+76))),*available[:2])


def native_closed_call_tail(start, body, terminals, by_pc, kinds, api):
    """A native lock calls its slow path only after STORE or CLREX.

    Validate the common argument prefix and its busy-path branch as a union.
    The call itself stays outside: the reservation and any need for exclusive
    relocation have both ended. Relocated X18 retry handling is unchanged.
    """
    stores=[pc for pc in terminals if by_pc[pc].mnemonic in api.EXCLUSIVE_STORES]
    clears=[pc for pc in terminals if by_pc[pc].mnemonic=='clrex']
    if len(stores)!=1 or len(clears)!=1 or any(kinds[pc] is not None for pc in body):return None
    store=by_pc[stores[0]];test=by_pc.get(store.address+4);busy=by_pc.get(clears[0]+4)
    status=struct.unpack('<I',store.bytes)[0]>>16&31;prefix=store.address+8
    if (test is None or test.mnemonic!='cbz' or status==31 or test.reg_name(test.operands[0].reg)!=f'w{status}' or
            busy is None or busy.mnemonic!='b' or busy.operands[-1].imm!=prefix or
            test.address in body or busy.address in body):
        return None
    tail={test.address,busy.address}
    if any(kinds[pc] is not None for pc in tail):return None
    for pc in range(prefix,prefix+36,4):
        op=by_pc.get(pc)
        if op is None or pc in body or pc in tail:return None
        if op.mnemonic=='bl':
            target=op.operands[-1].imm
            if (pc==prefix or test.operands[-1].imm!=pc+4 or pc+4 not in by_pc or
                    target not in by_pc or target in body|tail|{pc}):
                return None
            return body|tail
        if (kinds[pc] is not None or op.mnemonic not in TAIL_ARITHMETIC or
                any(arg.type not in {ARM64_OP_REG,ARM64_OP_IMM} for arg in op.operands) or
                any(op.reg_name(r) in {'sp','wsp'} for r in op.regs_access()[1])):
            return None
        tail.add(pc)
    return None



def native_shared_clear(start, by_pc, kinds, api):
    """Two source-exact fresh heads share one CLREX and acquire reload.

    The first consumes state 2 with a zero store; the second publishes its
    independent payload only from state zero. Mismatch paths retire before
    LDAR and either leave for ordinary classification or retry the second
    fresh load. Return the existing shared-head contract, never callback
    authority or a relaxation for arbitrary exclusive-window entrances.
    """
    begin=start.address
    block=tuple(by_pc.get(begin+offset) for offset in range(0,60,4))
    if any(ins is None for ins in block):return None
    values=tuple(struct.unpack('<I',ins.bytes)[0] for ins in block)
    loaded,base,payload=values[0]&31,values[0]>>5&31,values[8]&31
    expected=(0x885FFC00|base<<5|loaded,0x7100081F|loaded<<5,0x54000121,
              0x8800FC1F|loaded<<16|base<<5,0x35FFFF80|loaded,values[5],
              0x885FFC00|base<<5|loaded,0x35000080|loaded,
              0x8800FC00|loaded<<16|base<<5|payload,0x35FFFFA0|loaded,
              values[10],0xD5033F5F,0x88DFFC00|base<<5|loaded,
              values[13],0x17FFFFF8)
    if (values!=expected or values[5]&0xFC000000!=0x14000000 or
            values[10]&0xFC000000!=0x14000000 or
            values[13]&0xFF00001F!=(0x35000000|loaded)):return None
    roles=(base,loaded,payload)
    if len(set(roles))!=3 or any(role in {18,29,30,31} for role in roles):return None
    nodes={ins.address for ins in block}
    success,wait,classify=(block[index].operands[-1].imm for index in (5,10,13))
    if not wait<classify<begin<begin+60<success:return None
    if any(target not in by_pc or api.is_fatal_instruction(by_pc[target])
           for target in (success,wait,classify)):return None
    if any(kinds.get(pc,'missing') is not None for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in native shared clear')
    for ins in block:
        validate_memory_operands(ins,api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
    return nodes,{begin,begin+24}


def plan_regions(instructions, kinds, entry_offsets, api):
    by_pc = {ins.address: ins for ins in instructions}
    regions, occupied, consumed = [], set(), set()
    for start in instructions:
        if start.mnemonic not in api.EXCLUSIVE_LOADS or start.address in consumed:
            continue
        native_entry=native_compare_retry(start,by_pc,kinds,api)
        if native_entry is not None:
            nodes=set(range(native_entry,native_entry+56,4))
            if occupied&nodes:
                raise api.RewriteError(f'0x{native_entry:x}: overlapping exclusive windows')
            require_single_entry(nodes,native_entry,instructions,entry_offsets,api)
            occupied.update(nodes)
            continue
        native_start=native_rotated_lock(start,by_pc,kinds,api)
        if native_start is not None:
            nodes=set(range(native_start,native_start+20,4))
            if occupied&nodes:
                raise api.RewriteError(f'0x{native_start:x}: overlapping exclusive windows')
            require_single_entry(nodes,start.address,instructions,entry_offsets,api)
            occupied.update(nodes)
            continue
        shared=native_shared_clear(start,by_pc,kinds,api)
        if shared is not None:
            nodes,heads=shared
            if occupied&nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            if (set(entry_offsets)&nodes)-{min(heads)}:
                raise api.RewriteError(f'0x{start.address:x}: external entry in exclusive region interior')
            for ins in instructions:
                if ins.address not in nodes and any(target in nodes-heads for target in successors(ins)):
                    raise api.RewriteError(f'0x{ins.address:x}: external entry into exclusive region interior')
            occupied.update(nodes);consumed.update(heads)
            continue
        conditional=native_conditional_refresh(start,by_pc,kinds,api)
        if conditional is not None:
            nodes,entry,heads=conditional
            if occupied&nodes:
                raise api.RewriteError(f'0x{entry:x}: overlapping exclusive windows')
            require_single_entry(nodes,entry,instructions,entry_offsets,api)
            occupied.update(nodes);consumed.update(heads)
            continue
        if native_dual_load_lock(start, by_pc, kinds, api):
            nodes = set(range(start.address, start.address + 28, 4))
            if occupied & nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            require_single_entry(nodes, start.address, instructions, entry_offsets, api)
            occupied.update(nodes)
            consumed.add(start.address + 12)
            continue
        preload=virtual_preload_cas(start,by_pc,kinds,api)
        if preload is None:
            preload=virtual_boolean_preload_cas(start,by_pc,kinds,api)
        if preload is not None:
            nodes={op.address for op in preload.instructions}
            if occupied&nodes:
                raise api.RewriteError(f'0x{preload.entry:x}: overlapping exclusive windows')
            require_acyclic(nodes,by_pc,preload.retry_edges,preload.exit_edges,api)
            require_single_entry(nodes,preload.entry,instructions,entry_offsets,api)
            occupied.update(nodes);consumed.add(start.address);regions.append(preload)
            continue
        colors, terminals = {}, set()
        pending = [(start.address, False)]
        while pending:
            pc, leaving = pending.pop()
            if leaving:
                colors[pc] = 2
                continue
            if colors.get(pc) == 1:
                raise api.RewriteError(f'0x{pc:x}: cyclic/unbounded exclusive control flow starting 0x{start.address:x}')
            if colors.get(pc) == 2:
                continue
            if pc not in by_pc:
                raise api.RewriteError(f'0x{pc:x}: unbounded exclusive control flow starting 0x{start.address:x}')
            if len(colors) >= MAX_REGION_WORDS:
                raise api.RewriteError(f'0x{pc:x}: exclusive region exceeds bounded instruction limit')
            ins = by_pc[pc]
            if api.is_fatal_word(struct.unpack('<I', ins.bytes)[0]):
                raise api.RewriteError(f'0x{pc:x}: fatal word inside exclusive window starting 0x{start.address:x}')
            # Linux may emulate this EL0 read in the kernel. Such an exception
            # can lose the reservation on every retry, even though the read
            # outside an exclusive window correctly returns cache geometry.
            if struct.unpack('<I',ins.bytes)[0]&0xFFFFFFE0==0xD53B0020:
                raise api.RewriteError(f'0x{pc:x}: potentially trapping CTR read inside exclusive window')
            validate_memory_operands(ins, api)
            if kinds[pc] not in {None, 'x18'} or ins.mnemonic in {
                    'brk', 'hlt', 'hvc', 'smc', 'eret', 'drps', 'sys', 'sysl',
                    'dc', 'ic', 'tlbi', 'at', 'wfe', 'wfi'}:
                raise api.RewriteError(f'0x{pc:x}: host gate in exclusive window starting 0x{start.address:x}')
            if ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES:
                validate_exclusive(ins, api)
            if ins.mnemonic in api.EXCLUSIVE_LOADS and pc != start.address:
                raise api.RewriteError(f'0x{pc:x}: nested/overlapping exclusive window')
            colors[pc] = 1
            pending.append((pc, True))
            if ins.mnemonic in api.EXCLUSIVE_STORES or ins.mnemonic == 'clrex':
                terminals.add(pc)
                continue
            if (ins.mnemonic == 'bl' or
                    (any(ins.group(group) for group in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)) and
                     ins.mnemonic != 'b' and ins.mnemonic not in CONDITIONAL and not ins.mnemonic.startswith('b.'))):
                raise api.RewriteError(f'0x{pc:x}: unbounded exclusive call/indirect control flow starting 0x{start.address:x}')
            pending.extend((target, False) for target in reversed(successors(ins)))
        body, retries, tails = set(colors), set(), set()
        native_nodes=native_closed_call_tail(start,body,terminals,by_pc,kinds,api)
        if native_nodes is not None:
            if occupied&native_nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            require_single_entry(native_nodes,start.address,instructions,entry_offsets,api)
            occupied.update(native_nodes)
            continue
        for pc in terminals:
            if by_pc[pc].mnemonic not in api.EXCLUSIVE_STORES:
                continue
            tail, edges = retry_tail(by_pc, by_pc[pc], start.address, body, api)
            tails.update(tail)
            retries.update(edges)
        nodes = body | tails
        # Only virtual-x18 substitution is supported by this indivisible
        # relocation path. Every host-backed rewrite (including both endpoints
        # of a profiled parameter pair) must be rejected in the body and the
        # failed-store retry tail, before either original bytes or site records
        # can be emitted. Otherwise relocation silently loses that rewrite.
        if any(kinds[pc] not in {None, 'x18'} for pc in nodes):
            raise api.RewriteError(f'0x{start.address:x}: unsupported ABI rewrite in exclusive body/tail')
        if len(nodes) > MAX_REGION_WORDS:
            raise api.RewriteError(f'0x{start.address:x}: exclusive body/tail exceeds bounded instruction limit')
        if occupied & nodes:
            raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
        occupied.update(nodes)
        if any(pc + 4 in body - {start.address} for pc in terminals):
            raise api.RewriteError(f'0x{start.address:x}: terminal continuation enters exclusive region interior')
        exits = {(pc, target) for pc in nodes for target in successors(by_pc[pc])
                 if target not in nodes or by_pc[pc].mnemonic == 'clrex'}
        require_acyclic(nodes, by_pc, retries, exits, api)
        require_single_entry(nodes, start.address, instructions, entry_offsets, api)
        # Entry/CFG boundaries apply even when the reservation stays in-place.
        # Only actual relocation needs an SP-independent body and spare GPRs.
        if not any(kinds[pc] for pc in nodes):
            continue
        for pc in nodes:
            ins = by_pc[pc]
            if re.search(r'\bw?sp\b', ins.op_str) or any(
                    operand.type == ARM64_OP_MEM and ins.reg_name(operand.mem.base) == 'sp'
                    for operand in ins.operands):
                raise api.RewriteError(f'0x{pc:x}: SP-sensitive exclusive window unsupported')
        used = set().union(*(api.registers(by_pc[pc]) for pc in nodes))
        available = [reg for reg in range(16) if reg not in used]
        if len(available) < 2:
            raise api.RewriteError(f'0x{start.address:x}: insufficient unused registers for exclusive region')
        regions.append(Region(start.address, tuple(by_pc[pc] for pc in sorted(nodes)),
                              frozenset(terminals), frozenset(retries),
                              frozenset(exits),
                              *available[:2]))
    return tuple(regions)


def relocate(ins, pc, mapped, scratch, api):
    value = api.substitute(ins, scratch) if api.has18(ins) else struct.unpack('<I', ins.bytes)[0]
    mnemonic = ins.mnemonic
    if mnemonic == 'b' or mnemonic in CONDITIONAL or mnemonic.startswith('b.'):
        target = mapped[ins.operands[-1].imm]
        if mnemonic == 'b':
            return api.branch(pc, target)
        bits = 14 if mnemonic in {'tbz', 'tbnz'} else 19
        delta = target - pc
        if delta % 4 or not -(1 << (bits + 1)) <= delta < (1 << (bits + 1)):
            raise api.RewriteError(f'0x{ins.address:x}: relocated exclusive branch out of range')
        mask = ((1 << bits) - 1) << 5
        return value & ~mask | ((delta // 4 & ((1 << bits) - 1)) << 5)
    if mnemonic in {'adr', 'adrp'}:
        target = ins.operands[-1].imm
        delta = target - pc if mnemonic == 'adr' else target // 4096 - pc // 4096
        if not -(1 << 20) <= delta < (1 << 20):
            raise api.RewriteError(f'0x{ins.address:x}: relocated exclusive PC-relative target out of range')
        mask = (3 << 29) | (0x7FFFF << 5)
        return value & ~mask | ((delta & 3) << 29) | ((delta >> 2 & 0x7FFFF) << 5)
    if mnemonic in {'ldr', 'ldrsw', 'prfm'} and '[' not in ins.op_str:
        delta = ins.operands[-1].imm - pc
        if delta % 4 or not -(1 << 20) <= delta < (1 << 20):
            raise api.RewriteError(f'0x{ins.address:x}: relocated exclusive literal out of range')
        return value & ~(0x7FFFF << 5) | ((delta // 4 & 0x7FFFF) << 5)
    return value


def emit_region(emitter, region, api):
    scratch, state, begin = region.scratch, region.state, emitter.pc
    emitter.emit(0xD10083FF)  # sub sp,sp,#32
    emitter.emit(api.pair(False, 16, 30, 0))
    emitter.emit(api.pair(False, scratch, state, 16))
    emitter.helper(16, api.STATE_HELPER)
    emitter.emit(0xD63F0200)
    emitter.emit(0xAA1003E0 | state)
    emitter.emit(api.pair(True, 16, 30, 0))
    emitter.emit(api.memory(True, scratch, state, 0))
    # Emit an explicit branch after each node. This preserves CFG fallthrough
    # even when sorted source addresses contain holes or terminal epilogues.
    mapped = {ins.address: emitter.pc + 4 + index * 8 for index, ins in enumerate(region.instructions)}
    # A backwards edge can make a terminal's original address lower than the
    # exclusive load. Sorted layout must still enter at that load, not CLREX.
    emitter.emit(api.branch(emitter.pc, mapped[region.entry]))
    exits = sorted({target for _, target in region.exit_edges})
    exit_start = emitter.pc + len(region.instructions) * 8
    exit_stubs = {target: exit_start + index * 16 for index, target in enumerate(exits)}
    for ins in region.instructions:
        destinations = {target: exit_stubs[target] if (ins.address, target) in region.exit_edges else mapped[target]
                        for target in successors(ins)}
        emitter.emit(relocate(ins, emitter.pc, destinations, scratch, api))
        if ins.mnemonic == 'b':
            emitter.emit(0xD503201F)  # unreachable padding keeps mapping fixed
        else:
            emitter.emit(api.branch(emitter.pc, destinations[ins.address + 4]))
    for target in exits:
        emitter.emit(api.memory(False, scratch, state, 0))
        emitter.emit(api.pair(True, scratch, state, 16))
        emitter.emit(0x910083FF)  # add sp,sp,#32; original x16/LR may have changed
        emitter.emit(api.branch(emitter.pc, target))
    emitter.data[region.entry:region.entry + 4] = api.word(api.branch(region.entry, begin))
    # Entry records point to the prologue; other candidate records point to the
    # relocated guest instruction, which is reachable only after that prologue.
    emitter.sites.append(api.Site(region.entry, begin, 'exclusive region'))
    for ins in region.instructions:
        if ins.address != region.entry and api.has18(ins):
            emitter.sites.append(api.Site(ins.address, mapped[ins.address], f'{ins.mnemonic} {ins.op_str}'))
