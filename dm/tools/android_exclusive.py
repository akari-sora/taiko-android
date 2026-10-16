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
        if native_dual_load_lock(start, by_pc, kinds, api):
            nodes = set(range(start.address, start.address + 28, 4))
            if occupied & nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            require_single_entry(nodes, start.address, instructions, entry_offsets, api)
            occupied.update(nodes)
            consumed.add(start.address + 12)
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
