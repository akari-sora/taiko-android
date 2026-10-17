"""Validate native or relocate single-entry ARM64 exclusive regions as units.

The API object is android_rewrite, supplied by the caller to avoid an import
cycle. Only the external-entry prologue and real-exit epilogues access host
state or scratch memory. Recognized failed-store retries retain that frame
and branch straight back to the relocated exclusive load, without a host call.
A failed status branch may instead reload that same cell and branch directly
to the compare that dominates the store when success leaves only through an
approved SVC #0x1A; RET. After that call returns, a mask of a fresh load may
be compared with the original stored register: a match clears the new
reservation with CLREX and leaves through a plain epilogue, and a mismatch
branches to the compare that tests the fresh load. The opposite polarity is a
successful CBZ into a plain function epilogue; the failed store falls through
to that same reload. A failed CBZ may instead fall through to a same-cell
reload of the owning destination, compare it with the same other register, and
branch equal only to the MOV immediately before the store. Not-equal falls
into CLREX, which ends the attempt; the instructions after CLREX are not an
epilogue and are not followed. Two LDAXRB compare-not-equal branches of one
address may share one CLREX exit. A path from that CLREX re-enters an attempt
only at its exclusive load, and only after a write of the address register.
A path into the compare or the store leaves the CLREX inside the attempt.
Those branches may instead share the MOV immediately before that CLREX when
the MOV writes zero to the register tested by the following TBNZ. That TBNZ
is then dead. LDAXRB failures leave through STRB, LDAXRH failures through
STRH, and LDAXR failures through STR. That plain store uses a different
address and does not re-enter the exclusive load or store.
A failed STLXR may zero a result flag and fall through that now-dead bit
test to CMN of the loaded value. B.NE retries the owning load. The not-taken
path leaves the attempt, as does the successful store's flag branch. The
prelude writes neither the address register nor an exclusive operation, and
it does not branch to the compare, the increment, or the store.
A failed STLXR may instead zero a different flag and fall through that dead
test to a plain store whose address register is not the exclusive address.
The next instruction is the owning exclusive load. The dead branch targets a
plain LDR, LDP, RET leave and not the compare or the store. The prelude
writes neither the address register nor an exclusive operation.
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
    # Source-exact attempts may leave without using their reservation again.
    # Retire these live exits before even the first host-state/frame access.
    retire_exit_targets: frozenset = frozenset()
    requires_diag_abort_v1: bool = False
    monitor_retiring_call_sites: frozenset = frozenset()

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


def memory_base(ins):
    found = [operand.mem for operand in ins.operands if operand.type == ARM64_OP_MEM]
    if len(found) != 1 or found[0].disp or found[0].index or ins.writeback:
        return None
    return register_number(ins, found[0].base)


def loaded_register(ins):
    regs = [operand for operand in ins.operands if operand.type == ARM64_OP_REG]
    if len(regs) != 1:
        return None
    return register_number(ins, regs[0].reg)


def tests_register(ins, number):
    if ins.mnemonic not in CONDITIONAL or not ins.operands or number is None:
        return False
    return register_number(ins, ins.operands[0].reg) == number


def pointer_move(ins, dest, source):
    if ins.mnemonic != 'mov' or len(ins.operands) != 2:
        return False
    if any(operand.type != ARM64_OP_REG for operand in ins.operands):
        return False
    names = [ins.reg_name(operand.reg) for operand in ins.operands]
    return (names[0].startswith('x') and names[1].startswith('x') and
            register_number(ins, ins.operands[0].reg) == dest and
            register_number(ins, ins.operands[1].reg) == source)


def bounded_control_graph(by_pc, start, api):
    """Forward edges from start. A direct call contributes only its return site."""
    graph, pending, seen = {}, [start], set()
    while pending:
        pc = pending.pop()
        if pc in seen:
            continue
        ins = by_pc.get(pc)
        if ins is None or len(seen) >= MAX_REGION_WORDS or api.is_fatal_instruction(ins):
            return None
        seen.add(pc)
        if ins.mnemonic in {'br', 'blr', 'ret'}:
            graph[pc] = ()
            continue
        if ins.mnemonic == 'bl':
            targets = (pc + 4,)
        else:
            targets = successors(ins)
        if any(type(target) is not int or target not in by_pc for target in targets):
            return None
        graph[pc] = targets
        pending.extend(targets)
    return graph


def graph_reaches(graph, src, dst):
    pending, seen = [src], set()
    while pending:
        pc = pending.pop()
        if pc == dst:
            return True
        if pc in seen or pc not in graph:
            continue
        seen.add(pc)
        pending.extend(graph[pc])
    return False


def graph_dominates(graph, entry, dom, target):
    if graph is None or not graph_reaches(graph, entry, target):
        return False
    if entry == dom:
        return True
    pending, seen = [entry], set()
    while pending:
        pc = pending.pop()
        if pc == dom:
            continue
        if pc == target:
            return False
        if pc in seen or pc not in graph:
            continue
        seen.add(pc)
        pending.extend(graph[pc])
    return True


def nodes_reaching(graph, start, sink):
    if graph is None or start not in graph or sink not in graph:
        return None
    preds = {pc: [] for pc in graph}
    for pc, targets in graph.items():
        for target in targets:
            if target in preds:
                preds[target].append(pc)
    back, pending = set(), [sink]
    while pending:
        pc = pending.pop()
        if pc in back or pc not in preds:
            continue
        back.add(pc)
        pending.extend(preds[pc])
    if start not in back:
        return None
    return back


def success_only_approved_svc(by_pc, start, body, api):
    """Every successor path ends at a body SVC #0x1A; RET call."""
    pending, blocks = [start], {}
    while pending:
        pc = pending.pop()
        if pc in blocks:
            continue
        ins = by_pc.get(pc)
        if ins is None or len(blocks) >= MAX_TAIL_WORDS or api.is_fatal_instruction(ins):
            return False
        if ins.mnemonic in {'br', 'blr', 'svc'}:
            return False
        if direct_svc1a_ret_call(ins, by_pc, api):
            if pc not in body:
                return False
            blocks[pc] = ()
            continue
        if (ins.mnemonic == 'bl' or ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES or
                any(ins.group(group) for group in (CS_GRP_CALL, CS_GRP_RET)) or
                (ins.group(CS_GRP_JUMP) and ins.mnemonic != 'b' and
                 ins.mnemonic not in CONDITIONAL and not ins.mnemonic.startswith('b.'))):
            return False
        targets = successors(ins)
        if not targets or any(type(target) is not int or target not in by_pc for target in targets):
            return False
        blocks[pc] = targets
        pending.extend(targets)
    reaching = {pc for pc, targets in blocks.items() if not targets}
    if not reaching:
        return False
    changed = True
    while changed:
        changed = False
        for pc, targets in blocks.items():
            if pc not in reaching and any(target in reaching for target in targets):
                reaching.add(pc)
                changed = True
    return start in reaching and reaching == set(blocks)


def same_cell_address(by_pc, graph, head, store, reload, cell, origin, body, api):
    """The store/reload register still holds the owning load's address."""
    path = nodes_reaching(graph, head, reload)
    if path is None or store not in path:
        return False
    writers = [pc for pc in path if writes_register(by_pc[pc], cell)]
    if cell == origin:
        if writers:
            return False
    else:
        if len(writers) != 1 or writers[0] not in body:
            return False
        anchor = writers[0]
        if (not pointer_move(by_pc[anchor], cell, origin) or
                not graph_dominates(graph, head, anchor, store) or
                not graph_dominates(graph, head, anchor, reload)):
            return False
        prefix = nodes_reaching(graph, head, anchor)
        if prefix is None or any(pc != anchor and writes_register(by_pc[pc], origin) for pc in prefix):
            return False
    for pc in path:
        ins = by_pc[pc]
        if ins.mnemonic != 'bl':
            continue
        if not direct_svc1a_ret_call(ins, by_pc, api):
            return False
        target = ins.operands[-1].imm
        for stub in (by_pc.get(target), by_pc.get(target + 4)):
            if stub is None or writes_register(stub, cell) or writes_register(stub, origin):
                return False
    return True


def compare_reload_retry(by_pc, store, head, body, api):
    """Failed Wstatus branch, same-cell exclusive reload, then B to the dominating compare.

    The compare is the instruction that dominates this store and tests the
    reloaded register. That register must be the owning load's loaded
    register. A branch is not admitted because its target can reach the
    owning load. Success must reach only an approved SVC #0x1A; RET call
    already in the body. Unknown targets, a reload of any other register, and
    a success path that reaches BR/BLR stay outside this shape.
    """
    first = store.address + 4
    test = by_pc.get(first)
    status = struct.unpack('<I', store.bytes)[0] >> 16 & 31
    head_ins = by_pc.get(head)
    if (test is None or head_ins is None or store.mnemonic not in api.EXCLUSIVE_STORES or
            head_ins.mnemonic not in api.EXCLUSIVE_LOADS or test.mnemonic != 'cbnz' or
            status == 31 or not test.operands or
            test.reg_name(test.operands[0].reg) != f'w{status}' or
            test.operands[-1].type != ARM64_OP_IMM):
        return None
    reload_pc = test.operands[-1].imm
    reload = by_pc.get(reload_pc)
    branch = by_pc.get(reload_pc + 4)
    if (type(reload_pc) is not int or reload_pc % 4 or reload_pc in {head} | body or
            reload is None or branch is None or branch.address != reload_pc + 4 or
            branch.mnemonic != 'b' or len(branch.operands) != 1 or
            branch.operands[0].type != ARM64_OP_IMM):
        return None
    compare_pc = branch.operands[0].imm
    compare = by_pc.get(compare_pc)
    origin, cell, again = memory_base(head_ins), memory_base(store), memory_base(reload)
    destination = loaded_register(reload)
    owned = loaded_register(head_ins)
    if (compare is None or type(compare_pc) is not int or compare_pc not in body or
            compare_pc == head or origin is None or cell is None or again != cell or
            origin in {18, 29, 30, 31} or cell in {18, 29, 30, 31} or
            reload.mnemonic != head_ins.mnemonic or destination is None or
            destination != owned or
            not tests_register(compare, destination)):
        return None
    validate_memory_operands(reload, api)
    validate_exclusive(reload, api)
    graph = bounded_control_graph(by_pc, head, api)
    if (not graph_dominates(graph, head, compare_pc, store.address) or
            not same_cell_address(by_pc, graph, head, store.address, reload_pc, cell, origin, body, api) or
            not success_only_approved_svc(by_pc, first + 4, body, api)):
        return None
    return {first, reload_pc, branch.address}, {(branch.address, compare_pc)}


def stack_epilogue_step(ins):
    """One plain epilogue step: a stack restore or an SP adjustment."""
    if ins.mnemonic in {'ldp', 'ldnp'}:
        found = [operand for operand in ins.operands if operand.type == ARM64_OP_MEM]
        if len(found) != 1 or found[0].mem.index:
            return False
        return ins.reg_name(found[0].mem.base) == 'sp'
    if ins.mnemonic in {'add', 'sub'}:
        operands = ins.operands
        if (len(operands) != 3 or operands[0].type != ARM64_OP_REG or
                operands[1].type != ARM64_OP_REG or operands[2].type != ARM64_OP_IMM or
                operands[2].shift.value):
            return False
        return ins.reg_name(operands[0].reg) == 'sp' and ins.reg_name(operands[1].reg) == 'sp'
    return False


def plain_function_epilogue(by_pc, start, blocked, api):
    """Straight-line stack epilogue that ends at RET.

    A branch, a call, an exclusive operation, or any edge back into the blocked
    region is not this exit. The walk accepts only stack restores, SP
    adjustments, and a final RET.
    """
    if type(start) is not int or start < 0 or start % 4 or start in blocked:
        return False
    pc = start
    for _ in range(MAX_TAIL_WORDS):
        ins = by_pc.get(pc)
        if ins is None or pc in blocked or api.is_fatal_instruction(ins):
            return False
        if ins.mnemonic == 'ret':
            if ins.operands and ins.reg_name(ins.operands[0].reg) not in {'lr', 'x30'}:
                return False
            return not successors(ins)
        if (ins.mnemonic in {'b', 'bl', 'br', 'blr'} or ins.mnemonic in CONDITIONAL or
                ins.mnemonic.startswith('b.') or ins.mnemonic == 'clrex' or
                ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES or
                any(ins.group(group) for group in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET))):
            return False
        if not stack_epilogue_step(ins):
            return False
        targets = successors(ins)
        if targets != (pc + 4,) or any(target in blocked for target in targets):
            return False
        pc += 4
    return False


def epilogue_reload_retry(by_pc, store, head, body, api):
    """Successful Wstatus CBZ enters a plain epilogue; failure falls through.

    Fallthrough is the same-cell exclusive reload of the owning load's
    destination, and the captured address register still holds that load's
    address. The next instruction must be a direct B to the compare that
    dominates this store and tests the reloaded register. Reaching that
    compare through another block is not enough. A success path that branches,
    calls, or performs another exclusive operation stays outside this shape.
    """
    first = store.address + 4
    test = by_pc.get(first)
    status = struct.unpack('<I', store.bytes)[0] >> 16 & 31
    head_ins = by_pc.get(head)
    if (test is None or head_ins is None or store.mnemonic not in api.EXCLUSIVE_STORES or
            head_ins.mnemonic not in api.EXCLUSIVE_LOADS or test.mnemonic != 'cbz' or
            status == 31 or not test.operands or
            test.reg_name(test.operands[0].reg) != f'w{status}' or
            test.operands[-1].type != ARM64_OP_IMM):
        return None
    success_pc = test.operands[-1].imm
    reload_pc = first + 4
    reload = by_pc.get(reload_pc)
    branch = by_pc.get(reload_pc + 4)
    if (type(success_pc) is not int or success_pc % 4 or success_pc in {head} | body or
            reload_pc in {head} | body or reload is None or branch is None or
            branch.address != reload_pc + 4 or branch.mnemonic != 'b' or
            len(branch.operands) != 1 or branch.operands[0].type != ARM64_OP_IMM):
        return None
    compare_pc = branch.operands[0].imm
    compare = by_pc.get(compare_pc)
    origin, cell, again = memory_base(head_ins), memory_base(store), memory_base(reload)
    destination = loaded_register(reload)
    owned = loaded_register(head_ins)
    if (compare is None or type(compare_pc) is not int or compare_pc not in body or
            compare_pc == head or compare.address != compare_pc or
            origin is None or cell is None or again != cell or
            origin in {18, 29, 30, 31} or cell in {18, 29, 30, 31} or
            reload.mnemonic != head_ins.mnemonic or destination is None or
            destination != owned or not tests_register(compare, destination)):
        return None
    validate_memory_operands(reload, api)
    validate_exclusive(reload, api)
    graph = bounded_control_graph(by_pc, head, api)
    blocked = set(body) | {head, first, reload_pc, branch.address}
    if (not graph_dominates(graph, head, compare_pc, store.address) or
            not same_cell_address(by_pc, graph, head, store.address, reload_pc, cell, origin, body, api) or
            not plain_function_epilogue(by_pc, success_pc, blocked, api)):
        return None
    return {first, reload_pc, branch.address}, {(branch.address, compare_pc)}


def nodes_between(graph, src, dst):
    """Instructions reachable from src that reach dst, excluding both ends."""
    if graph is None or src not in graph or dst not in graph:
        return None
    reaching = nodes_reaching(graph, src, dst)
    if reaching is None:
        return None
    forward, pending = set(), [src]
    while pending:
        pc = pending.pop()
        if pc in forward or pc not in graph:
            continue
        forward.add(pc)
        pending.extend(graph[pc])
    if dst not in forward:
        return None
    return (forward & reaching) - {src, dst}


def plain_prefix_step(ins):
    """One non-control prefix step: arithmetic, or a plain store through SP."""
    if ins.mnemonic in {'str', 'stur'}:
        found = [operand for operand in ins.operands if operand.type == ARM64_OP_MEM]
        return (len(found) == 1 and not found[0].mem.index and not ins.writeback and
                ins.reg_name(found[0].mem.base) == 'sp')
    if ins.mnemonic not in TAIL_ARITHMETIC:
        return False
    return all(operand.type in {ARM64_OP_REG, ARM64_OP_IMM} for operand in ins.operands)


def avoids_interior(by_pc, start, interior, api):
    """Static successors from start never enter interior."""
    pending, seen = [start], set()
    while pending:
        pc = pending.pop()
        if pc in seen:
            continue
        if type(pc) is not int or pc < 0 or pc % 4 or pc in interior:
            return False
        ins = by_pc.get(pc)
        if ins is None or len(seen) >= MAX_TAIL_WORDS or api.is_fatal_instruction(ins):
            return False
        seen.add(pc)
        if ins.mnemonic in {'br', 'blr'}:
            continue
        if ins.mnemonic == 'ret' and (not ins.operands or ins.reg_name(ins.operands[0].reg) in {'lr', 'x30'}):
            continue
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
            return False
        pending.extend(targets)
    return bool(seen)


def masked_compare_clrex_leave(by_pc, store, head, body, api, compared):
    """SVC return reloads the same cell, compares a mask, then CLREX-leaves.

    The compared register is the destination of an immediate AND of the fresh
    load, not that load register. Match is CLREX and then a plain epilogue.
    Mismatch is a direct B to the compare that already tests the fresh load.
    The expected register is the data register of the one earlier store of
    that value and is not written again before this compare. A nonzero status
    leaves without entering the attempt. The address register still names the
    owning load's cell.
    """
    failure_tail, failure_edges = compared
    head_ins = by_pc.get(head)
    if head_ins is None or len(failure_edges) != 1:
        return None
    link, compare_pc = next(iter(failure_edges))
    compare = by_pc.get(compare_pc)
    failure_reloads = [pc for pc in failure_tail if by_pc[pc].mnemonic in api.EXCLUSIVE_LOADS]
    if compare is None or len(failure_reloads) != 1 or link not in failure_tail:
        return None
    owned = loaded_register(by_pc[failure_reloads[0]])
    pc, call = store.address + 8, None
    for _ in range(MAX_TAIL_WORDS):
        ins = by_pc.get(pc)
        if ins is None or pc not in body:
            return None
        if direct_svc1a_ret_call(ins, by_pc, api):
            call = ins
            break
        if (successors(ins) != (pc + 4,) or ins.mnemonic == 'bl' or
                ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES | {'clrex'} or
                ins.mnemonic in {'b', 'br', 'blr'} | CONDITIONAL or ins.mnemonic.startswith('b.')):
            return None
        pc += 4
    else:
        return None
    prefix, cursor = [], call.address + 4
    status = None
    for _ in range(4):
        ins = by_pc.get(cursor)
        if ins is None or cursor in body or cursor in failure_tail:
            return None
        if (ins.mnemonic == 'cbnz' and len(ins.operands) >= 2 and
                ins.operands[0].type == ARM64_OP_REG and ins.operands[-1].type == ARM64_OP_IMM):
            status = ins
            break
        if (not plain_prefix_step(ins) or successors(ins) != (cursor + 4,) or
                ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES | {'clrex'}):
            return None
        prefix.append(cursor)
        cursor += 4
    else:
        return None
    fresh_pc = status.address + 4
    mask_pc, cmp_pc = fresh_pc + 4, fresh_pc + 8
    equal_pc, mismatch_pc = fresh_pc + 12, fresh_pc + 16
    fresh, mask, cmp_ins = by_pc.get(fresh_pc), by_pc.get(mask_pc), by_pc.get(cmp_pc)
    equal, mismatch = by_pc.get(equal_pc), by_pc.get(mismatch_pc)
    if (fresh is None or mask is None or cmp_ins is None or equal is None or mismatch is None or
            fresh.address != fresh_pc or mask.address != mask_pc or cmp_ins.address != cmp_pc or
            equal.address != equal_pc or mismatch.address != mismatch_pc):
        return None
    if (equal.mnemonic != 'b.eq' or mismatch.mnemonic != 'b' or len(equal.operands) != 1 or
            len(mismatch.operands) != 1 or equal.operands[0].type != ARM64_OP_IMM or
            mismatch.operands[0].type != ARM64_OP_IMM or status.operands[-1].type != ARM64_OP_IMM):
        return None
    clrex_pc, nonzero = equal.operands[0].imm, status.operands[-1].imm
    clrex = by_pc.get(clrex_pc)
    origin, cell, again = memory_base(head_ins), memory_base(store), memory_base(fresh)
    fresh_reg = loaded_register(fresh)
    if (clrex is None or clrex.mnemonic != 'clrex' or clrex.address != clrex_pc or
            type(clrex_pc) is not int or clrex_pc % 4 or type(nonzero) is not int or nonzero % 4 or
            origin is None or cell is None or again != cell or fresh_reg is None or owned is None or
            fresh_reg != owned or not tests_register(compare, fresh_reg) or
            origin in {18, 29, 30, 31} or cell in {18, 29, 30, 31} or
            fresh.mnemonic != head_ins.mnemonic or mismatch.operands[0].imm != compare_pc):
        return None
    if (mask.mnemonic != 'and' or len(mask.operands) != 3 or cmp_ins.mnemonic != 'cmp' or
            len(cmp_ins.operands) != 2):
        return None
    dest, source, immediate = mask.operands
    if (dest.type != ARM64_OP_REG or source.type != ARM64_OP_REG or immediate.type != ARM64_OP_IMM or
            any(operand.type != ARM64_OP_REG or operand.shift.value for operand in cmp_ins.operands)):
        return None
    mask_reg = register_number(mask, dest.reg)
    source_reg = register_number(mask, source.reg)
    compared_reg = register_number(cmp_ins, cmp_ins.operands[0].reg)
    expected = register_number(cmp_ins, cmp_ins.operands[1].reg)
    if (mask_reg is None or source_reg is None or compared_reg is None or expected is None or
            compared_reg != mask_reg or source_reg != fresh_reg or mask_reg == fresh_reg or
            expected in {fresh_reg, mask_reg, cell}):
        return None
    block = prefix + [status.address, fresh_pc, mask_pc, cmp_pc, equal_pc, mismatch_pc]
    if (len(set(block)) != len(block) or clrex_pc in set(block) | set(body) | set(failure_tail) or
            any(pc in set(body) | set(failure_tail) for pc in block)):
        return None
    if any(writes_register(by_pc[pc], cell) for pc in prefix):
        # Raise before retry_tail can accept the narrower compare-reload shape.
        raise api.RewriteError(f'0x{store.address:x}: unsupported/unproven exclusive retry tail')
    if any(writes_register(by_pc[pc], expected) for pc in prefix):
        return None
    originals = [pc for pc in body if by_pc[pc].mnemonic in {'stxr', 'stlxr'} and
                 struct.unpack('<I', by_pc[pc].bytes)[0] & 31 == expected and
                 memory_base(by_pc[pc]) == cell]
    if len(originals) != 1:
        return None
    graph = bounded_control_graph(by_pc, head, api)
    between = nodes_between(graph, originals[0], cmp_pc)
    if between is None:
        return None
    for pc in between:
        ins = by_pc[pc]
        if writes_register(ins, expected):
            return None
        if ins.mnemonic != 'bl':
            continue
        if not direct_svc1a_ret_call(ins, by_pc, api):
            return None
        target = ins.operands[-1].imm
        for stub in (by_pc.get(target), by_pc.get(target + 4)):
            if stub is None or writes_register(stub, expected):
                return None
    interior = set(body) | set(failure_tail) | set(block)
    blocked = interior | {clrex_pc}
    if (not same_cell_address(by_pc, graph, head, store.address, fresh_pc, cell, origin, body, api) or
            not plain_function_epilogue(by_pc, clrex_pc + 4, blocked, api) or
            not avoids_interior(by_pc, nonzero, interior, api)):
        return None
    validate_memory_operands(fresh, api)
    validate_exclusive(fresh, api)
    return set(failure_tail) | set(block) | {clrex_pc}, set(failure_edges) | {(mismatch_pc, compare_pc)}


def compare_reload_clrex_end(by_pc, store, head, body, api):
    """Failed STLXR reloads the same cell; CLREX ends the attempt.

    Fallthrough is a same-cell exclusive load of the owning destination, a
    compare with the same other register, and B.EQ only to the MOV immediately
    before this store. Not-equal falls into CLREX. CLREX ends the attempt:
    the instructions after it are not required to be an epilogue and are not
    followed, so a later direct call or indirect branch is not an exclusive
    call. The successful CBZ targets one instruction outside this attempt, and
    that instruction is not itself an exclusive load or store. A branch from
    the instruction after CLREX back into the attempt stays rejected.
    """
    if (type(head) is not int or head < 0 or head % 4 or store.mnemonic != 'stlxr' or
            head != store.address - 16):
        return None
    compare_pc, mismatch_pc, mov_pc = head + 4, head + 8, head + 12
    status_pc, reload_pc = store.address + 4, store.address + 8
    again_pc, equal_pc, clrex_pc = store.address + 12, store.address + 16, store.address + 20
    addresses = (head, compare_pc, mismatch_pc, mov_pc, store.address, status_pc, reload_pc,
                 again_pc, equal_pc, clrex_pc)
    nodes = [by_pc.get(pc) for pc in addresses]
    if any(ins is None or ins.address != pc for ins, pc in zip(nodes, addresses)):
        return None
    (head_ins, compare, mismatch, mov, store_ins, status, reload, again, equal, clrex) = nodes
    if set(body) != {head, compare_pc, mismatch_pc, mov_pc, store.address, clrex_pc}:
        return None
    status_reg = struct.unpack('<I', store_ins.bytes)[0] >> 16 & 31
    if (head_ins.mnemonic != 'ldaxr' or reload.mnemonic != 'ldaxr' or
            compare.mnemonic != 'cmp' or again.mnemonic != 'cmp' or
            mismatch.mnemonic != 'b.ne' or equal.mnemonic != 'b.eq' or
            mov.mnemonic != 'mov' or status.mnemonic != 'cbz' or clrex.mnemonic != 'clrex' or
            status_reg == 31 or not status.operands or not mismatch.operands or not equal.operands or
            status.operands[0].type != ARM64_OP_REG or status.operands[-1].type != ARM64_OP_IMM or
            mismatch.operands[0].type != ARM64_OP_IMM or equal.operands[0].type != ARM64_OP_IMM or
            status.reg_name(status.operands[0].reg) != f'w{status_reg}'):
        return None
    if (len(compare.operands) != 2 or len(again.operands) != 2 or
            any(operand.type != ARM64_OP_REG or operand.shift.value
                for operand in (*compare.operands, *again.operands))):
        return None
    owned, destination = loaded_register(head_ins), loaded_register(reload)
    origin, cell, again_cell = memory_base(head_ins), memory_base(store_ins), memory_base(reload)
    left = register_number(compare, compare.operands[0].reg)
    other = register_number(compare, compare.operands[1].reg)
    left_again = register_number(again, again.operands[0].reg)
    other_again = register_number(again, again.operands[1].reg)
    success_pc = status.operands[-1].imm
    if (owned is None or destination != owned or left != owned or left_again != owned or
            other is None or other != other_again or other in {owned, cell, status_reg, 18, 29, 30, 31} or
            origin is None or cell is None or again_cell != cell or origin != cell or
            origin in {18, 29, 30, 31} or cell in {18, 29, 30, 31} or
            mismatch.operands[0].imm != clrex_pc or equal.operands[0].imm != mov_pc or
            equal.address + 4 != clrex_pc or mov.address != store.address - 4):
        return None
    span = set(addresses)
    if any(writes_register(ins, other) or writes_register(ins, cell) for ins in nodes):
        return None
    success = by_pc.get(success_pc)
    if (type(success_pc) is not int or success_pc % 4 or success is None or
            success.address != success_pc or success_pc in span or
            success.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES):
        return None
    # CLREX ends the attempt. The next instruction is not part of it; a branch
    # from that instruction back into the attempt stays rejected, and nothing
    # beyond it is followed.
    after = by_pc.get(clrex_pc + 4)
    if after is not None and after.address == clrex_pc + 4:
        targets = successors(after)
        if not isinstance(targets, tuple) or any(target in span for target in targets):
            return None
    validate_memory_operands(reload, api)
    validate_exclusive(reload, api)
    return {status_pc, reload_pc, again_pc, equal_pc}, {(equal_pc, mov_pc)}


def conditional_return_retry(by_pc, store, head, body, api):
    """Failed STLXR zeroes a flag, then CMN retries the owning load.

    The status CBNZ enters a prelude that has no exclusive operation and does
    not write the address register. MOV Wflag, WZR makes the following TBNZ
    of bit 0 dead, so failure falls through to a copy of the loaded value,
    CMN against #1, and B.NE back to the owning LDAXR. That not-taken path
    leaves. Success sets the same flag bit and branches to the TBNZ, whose
    taken target leaves. A prelude write of the address register, a branch to
    the compare, the increment, or the store, and a not-taken path into those
    instructions stay rejected.
    """
    if (type(head) is not int or head < 0 or head % 4 or store.mnemonic != 'stlxr' or
            head != store.address - 16):
        return None
    compare_pc, mismatch_pc, add_pc = head + 4, head + 8, head + 12
    status_pc, success_pc, join_pc = store.address + 4, store.address + 8, store.address + 12
    clrex_pc, zero_pc = store.address + 16, store.address + 20
    flag_pc, copy_pc = store.address + 24, store.address + 28
    cmn_pc, retry_pc, leave_pc = store.address + 32, store.address + 36, store.address + 40
    addresses = (head, compare_pc, mismatch_pc, add_pc, store.address, status_pc, success_pc,
                 join_pc, clrex_pc, zero_pc, flag_pc, copy_pc, cmn_pc, retry_pc)
    nodes = [by_pc.get(pc) for pc in addresses]
    if any(ins is None or ins.address != pc for ins, pc in zip(nodes, addresses)):
        return None
    (head_ins, compare, mismatch, add, store_ins, status, success, join, clrex, zero, flag,
     copy, cmn, retry) = nodes
    if set(body) != {head, compare_pc, mismatch_pc, add_pc, store.address, clrex_pc}:
        return None
    status_reg = struct.unpack('<I', store_ins.bytes)[0] >> 16 & 31
    if (head_ins.mnemonic != 'ldaxr' or compare.mnemonic != 'cmp' or mismatch.mnemonic != 'b.ne' or
            add.mnemonic != 'add' or store_ins.mnemonic != 'stlxr' or status.mnemonic != 'cbnz' or
            success.mnemonic != 'mov' or join.mnemonic != 'b' or clrex.mnemonic != 'clrex' or
            zero.mnemonic != 'mov' or flag.mnemonic != 'tbnz' or copy.mnemonic != 'mov' or
            cmn.mnemonic != 'cmn' or retry.mnemonic != 'b.ne' or status_reg == 31):
        return None
    if (len(compare.operands) != 2 or len(add.operands) != 3 or len(success.operands) != 2 or
            len(zero.operands) != 2 or len(flag.operands) != 3 or len(cmn.operands) != 2 or
            not status.operands or not mismatch.operands or not join.operands or not retry.operands):
        return None
    owned, cell = loaded_register(head_ins), memory_base(head_ins)
    data = register_number(store_ins, store_ins.operands[1].reg) if len(store_ins.operands) >= 2 else None
    again = memory_base(store_ins)
    if (owned is None or cell is None or data is None or again != cell or owned == cell or
            data in {owned, cell, status_reg, 18, 29, 30, 31} or
            owned in {18, 29, 30, 31} or cell in {18, 29, 30, 31} or
            not tests_register(status, status_reg)):
        return None
    left = register_number(compare, compare.operands[0].reg)
    other = register_number(compare, compare.operands[1].reg)
    added, source, immediate = add.operands
    if (left != owned or other != data or register_number(add, added.reg) != data or
            register_number(add, source.reg) != data or immediate.type != ARM64_OP_IMM or
            immediate.imm != 1 or immediate.shift.value or
            any(operand.type != ARM64_OP_REG or operand.shift.value for operand in compare.operands)):
        return None
    flag_reg = register_number(zero, zero.operands[0].reg)
    zero_src = zero.operands[1]
    success_imm = success.operands[1]
    if (flag_reg is None or flag_reg in {cell, status_reg, 18, 29, 30, 31} or
            zero.reg_name(zero.operands[0].reg) != f'w{flag_reg}' or
            zero_src.type != ARM64_OP_REG or zero.reg_name(zero_src.reg) != 'wzr' or
            success.reg_name(success.operands[0].reg) != f'w{flag_reg}' or
            success_imm.type != ARM64_OP_IMM or success_imm.imm != 1 or success_imm.shift.value or
            not tests_register(flag, flag_reg) or flag.operands[1].type != ARM64_OP_IMM or
            flag.operands[1].imm != 0 or flag.operands[-1].type != ARM64_OP_IMM or
            status.operands[-1].type != ARM64_OP_IMM or mismatch.operands[0].type != ARM64_OP_IMM or
            join.operands[0].type != ARM64_OP_IMM or retry.operands[0].type != ARM64_OP_IMM):
        return None
    if (status.operands[-1].imm != zero_pc or mismatch.operands[0].imm != clrex_pc or
            join.operands[0].imm != flag_pc or retry.operands[0].imm != head):
        return None
    cmn_reg, cmn_imm = cmn.operands
    if (cmn_reg.type != ARM64_OP_REG or cmn_imm.type != ARM64_OP_IMM or cmn_imm.imm != 1 or
            cmn_imm.shift.value or register_number(cmn, cmn_reg.reg) != owned):
        return None
    prelude = (zero, flag, copy, cmn, retry)
    if any(ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES | {'clrex'} for ins in prelude):
        return None
    if any(writes_register(ins, cell) for ins in prelude):
        return None
    if not pointer_move(copy, data, owned):
        return None
    tail = {status_pc, success_pc, join_pc, zero_pc, flag_pc, copy_pc, cmn_pc, retry_pc}
    protected = {compare_pc, add_pc, store.address}
    for pc in tail:
        for target in successors(by_pc[pc]):
            if target in protected or (target in set(body) and (pc, target) != (retry_pc, head)):
                return None
    interior = set(body) | tail
    taken = flag.operands[-1].imm
    if (type(taken) is not int or taken % 4 or taken in interior or
            not avoids_interior(by_pc, taken, interior, api) or
            not avoids_interior(by_pc, leave_pc, interior, api)):
        return None
    return tail, {(retry_pc, head)}


def plain_ldr_ldp_leave(by_pc, start, blocked, api):
    """Straight-line LDR, LDP, RET. No instruction is inside the attempt."""
    if type(start) is not int or start < 0 or start % 4 or start in blocked:
        return False
    offsets = (0, 4, 8)
    nodes = [by_pc.get(start + offset) for offset in offsets]
    if any(ins is None or ins.address != start + offset for ins, offset in zip(nodes, offsets)):
        return False
    if {start, start + 4, start + 8} & set(blocked):
        return False
    ldr, pair, ret = nodes
    if ldr.mnemonic != 'ldr' or pair.mnemonic != 'ldp' or ret.mnemonic != 'ret':
        return False

    def based_sp(ins):
        found = [operand for operand in ins.operands if operand.type == ARM64_OP_MEM]
        return (len(found) == 1 and not found[0].mem.index and
                ins.reg_name(found[0].mem.base) == 'sp')

    if (not based_sp(ldr) or ldr.writeback or not based_sp(pair) or
            (ret.operands and ret.reg_name(ret.operands[0].reg) not in {'lr', 'x30'}) or
            successors(ldr) != (start + 4,) or successors(pair) != (start + 8,) or
            successors(ret) or any(api.is_fatal_instruction(ins) for ins in nodes)):
        return False
    return True


def plain_store_fallthrough_retry(by_pc, store, head, body, api):
    """Failed STLXR falls through a plain store into the owning load.

    The status CBNZ is not a direct retry. It enters a prelude that has no
    exclusive operation and does not write the address register. MOV Wflag,
    WZR makes the following CBNZ dead, so failure falls through a plain store
    whose address register is not that exclusive address. The next instruction
    is the owning exclusive load. The dead branch targets a plain LDR, LDP,
    RET leave and not the compare or the store. Success sets the same flag,
    so its CBZ back to that store is dead, and the following branch targets
    the same leave. A store through the exclusive address, a prelude write of
    that address, and a following instruction that is not the owning load
    stay rejected. The plain store stays outside the tail: the returned edge
    is its fallthrough into the load.
    """
    if (type(head) is not int or head < 0 or head % 4 or store.mnemonic != 'stlxr' or
            head != store.address - 12):
        return None
    compare_pc, mismatch_pc = head + 4, head + 8
    status_pc = store.address + 4
    success_pc, success_copy_pc = status_pc + 4, status_pc + 8
    success_dead_pc, success_leave_pc = status_pc + 12, status_pc + 16
    nodes = (
        (by_pc.get(head), head),
        (by_pc.get(compare_pc), compare_pc),
        (by_pc.get(mismatch_pc), mismatch_pc),
        (store, store.address),
        (by_pc.get(status_pc), status_pc),
        (by_pc.get(success_pc), success_pc),
        (by_pc.get(success_copy_pc), success_copy_pc),
        (by_pc.get(success_dead_pc), success_dead_pc),
        (by_pc.get(success_leave_pc), success_leave_pc),
    )
    if any(ins is None or ins.address != pc for ins, pc in nodes):
        return None
    (head_ins, compare, mismatch, store_ins, status, success, success_copy, success_dead,
     success_leave) = (item[0] for item in nodes)
    if (head_ins.mnemonic != 'ldxr' or compare.mnemonic != 'cmp' or mismatch.mnemonic != 'b.ne' or
            store_ins.mnemonic != 'stlxr' or status.mnemonic != 'cbnz' or success.mnemonic != 'mov' or
            success_copy.mnemonic != 'mov' or success_dead.mnemonic != 'cbz' or
            success_leave.mnemonic != 'b'):
        return None
    if (len(compare.operands) != 2 or len(success.operands) != 2 or len(success_copy.operands) != 2 or
            not mismatch.operands or not status.operands or not success_dead.operands or
            not success_leave.operands):
        return None
    status_reg = struct.unpack('<I', store_ins.bytes)[0] >> 16 & 31
    owned, cell = loaded_register(head_ins), memory_base(head_ins)
    if (status_reg == 31 or owned is None or cell is None or memory_base(store_ins) != cell or
            owned == cell or owned in {18, 29, 30, 31} or cell in {18, 29, 30, 31} or
            status_reg in {owned, cell} or
            status.operands[0].type != ARM64_OP_REG or status.operands[-1].type != ARM64_OP_IMM or
            mismatch.operands[0].type != ARM64_OP_IMM or
            status.reg_name(status.operands[0].reg) != f'w{status_reg}' or
            any(operand.type != ARM64_OP_REG or operand.shift.value for operand in compare.operands) or
            register_number(compare, compare.operands[0].reg) != owned):
        return None
    clrex_pc = mismatch.operands[0].imm
    clrex = by_pc.get(clrex_pc)
    if (clrex is None or type(clrex_pc) is not int or clrex_pc % 4 or clrex.address != clrex_pc or
            clrex.mnemonic != 'clrex' or
            set(body) != {head, compare_pc, mismatch_pc, store.address, clrex_pc}):
        return None
    zero_pc = status.operands[-1].imm
    if type(zero_pc) is not int or zero_pc < 0 or zero_pc % 4 or zero_pc in set(body) | {head}:
        return None
    copy_pc, dead_pc, plain_pc = zero_pc + 4, zero_pc + 8, zero_pc + 12
    if plain_pc + 4 != head or {zero_pc, copy_pc, dead_pc, plain_pc} & set(body):
        return None
    zero, copy, dead, plain = (by_pc.get(pc) for pc in (zero_pc, copy_pc, dead_pc, plain_pc))
    prelude_nodes = ((zero, zero_pc), (copy, copy_pc), (dead, dead_pc), (plain, plain_pc))
    if any(ins is None or ins.address != pc for ins, pc in prelude_nodes):
        return None
    if (zero.mnemonic != 'mov' or copy.mnemonic != 'mov' or dead.mnemonic != 'cbnz' or
            plain.mnemonic != 'str' or len(zero.operands) != 2 or len(copy.operands) != 2 or
            not dead.operands):
        return None
    flag = register_number(zero, zero.operands[0].reg)
    zero_src = zero.operands[1]
    if (flag is None or flag in {cell, 18, 29, 30, 31} or
            zero.reg_name(zero.operands[0].reg) != f'w{flag}' or
            zero_src.type != ARM64_OP_REG or zero.reg_name(zero_src.reg) != 'wzr' or
            dead.operands[0].type != ARM64_OP_REG or dead.operands[-1].type != ARM64_OP_IMM or
            register_number(dead, dead.operands[0].reg) != flag or
            dead.reg_name(dead.operands[0].reg) != f'w{flag}'):
        return None
    leave_pc = dead.operands[-1].imm
    if leave_pc in {compare_pc, store.address, head, plain_pc, zero_pc}:
        return None
    if any(operand.type != ARM64_OP_REG for operand in copy.operands):
        return None
    base = memory_base(plain)
    if (base is None or base == cell or base in {18, 29, 30, 31} or
            successors(zero) != (copy_pc,) or successors(copy) != (dead_pc,) or
            successors(dead) != (plain_pc, leave_pc) or successors(plain) != (head,)):
        return None
    success_imm = success.operands[1]
    if (success.reg_name(success.operands[0].reg) != f'w{flag}' or
            success_imm.type != ARM64_OP_IMM or success_imm.imm != 1 or success_imm.shift.value or
            any(operand.type != ARM64_OP_REG for operand in success_copy.operands) or
            success_dead.operands[0].type != ARM64_OP_REG or
            success_dead.operands[-1].type != ARM64_OP_IMM or
            register_number(success_dead, success_dead.operands[0].reg) != flag or
            success_dead.reg_name(success_dead.operands[0].reg) != f'w{flag}' or
            success_dead.operands[-1].imm != plain_pc or
            success_leave.operands[0].type != ARM64_OP_IMM or success_leave.operands[0].imm != leave_pc):
        return None
    if success_dead.operands[-1].imm in {compare_pc, store.address, head}:
        return None
    owned_ins = (zero, copy, dead, plain, status, success, success_copy, success_dead, success_leave)
    if any(ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES | {'clrex'} for ins in owned_ins):
        return None
    if any(writes_register(ins, cell) for ins in owned_ins):
        return None
    if writes_register(copy, flag) or writes_register(success_copy, flag):
        return None
    blocked = set(body) | {status_pc, zero_pc, copy_pc, dead_pc, plain_pc, success_pc,
                           success_copy_pc, success_dead_pc, success_leave_pc}
    if not plain_ldr_ldp_leave(by_pc, leave_pc, blocked, api):
        return None
    tail = {status_pc, zero_pc, copy_pc, dead_pc, success_pc, success_copy_pc, success_dead_pc,
            success_leave_pc}
    return tail, {(plain_pc, head)}


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
    compared = compare_reload_retry(by_pc, store, head, body, api)
    if compared is not None:
        extended = masked_compare_clrex_leave(by_pc, store, head, body, api, compared)
        if extended is not None:
            return extended
        return compared
    epilogue = epilogue_reload_retry(by_pc, store, head, body, api)
    if epilogue is not None:
        return epilogue
    ended = compare_reload_clrex_end(by_pc, store, head, body, api)
    if ended is not None:
        return ended
    conditional = conditional_return_retry(by_pc, store, head, body, api)
    if conditional is not None:
        return conditional
    plain = plain_store_fallthrough_retry(by_pc, store, head, body, api)
    if plain is not None:
        return plain
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
    interior = nodes - {entry}
    for ins in instructions:
        if ins.address not in nodes and any(target in interior for target in successors(ins)):
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
    (
        0xD5033F5F, 0x2A1F03E3, 0x37001863, 0x5AC0120F,
        0x4B0F0143, 0x2A1003EF, 0x6B0D007F, 0x54000321,
        0x885F7D10, 0x6B0F021F, 0x54FFFEC1, 0x88037D0F,
        0x35FFFEA3, 0x52800023, 0x3607FEA3, 0x140000B6,
    ),
    (
        0xD5033F5F, 0x2A1F03E3, 0x37001663, 0x5AC0020F,
        0x5AC011E3, 0x2A1003EF, 0x6B0D007F, 0x54000121,
        0x885F7D10, 0x6B0F021F, 0x54FFFEC1, 0x88037D0F,
        0x35FFFEA3, 0x52800023, 0x3607FEA3, 0x140000A6,
    ),
    (
        0x885FFD0E, 0x6B0F01DF, 0x540000C1, 0x0A0D01EF,
        0x88107D0F, 0x35000090, 0x5280002F, 0x14000003,
        0xD5033F5F, 0x2A1F03EF, 0x3700008F, 0x0A0B01D0,
        0x2A0E03EF, 0x35FFFE70,
    ),
    (
        0x885F7D0F, 0x6B0501FF, 0x540000C1, 0x0A0600A7,
        0x88137D07, 0x35000093, 0x52800027, 0x14000003,
        0xD5033F5F, 0x2A1F03E7, 0x37000A67, 0x5AC011E5,
        0x4B050147, 0x2A0F03E5, 0x6B0D00FF, 0x54FFFE20,
        0x14000011,
    ),
    (
        0x885F7D0F, 0x6B0501FF, 0x540000C1, 0x0A0600A7,
        0x88137D07, 0x35000093, 0x52800027, 0x14000003,
        0xD5033F5F, 0x2A1F03E7, 0x37000847, 0x5AC001E5,
        0x5AC010A7, 0x2A0F03E5, 0x6B0D00FF, 0x54FFFE20,
    ),
    (
        0x2A0C03ED, 0x2A0B018F, 0x885F7D0C, 0x6B0D019F,
        0x540000A1, 0x880D7D0F, 0x3500008D, 0x5280002D,
        0x14000003, 0xD5033F5F, 0x2A1F03ED, 0x3707FCAD,
        0x6A0B019F, 0x2A0C03EF, 0x54FFFE40, 0x17FFFFE1,
    ),
    (
        0x885F7D0E, 0x6B0501DF, 0x540000C1, 0x2A0B00AF,
        0x88107D0F, 0x35000090, 0x5280002F, 0x14000003,
        0xD5033F5F, 0x2A1F03EF, 0x3700008F, 0x6A0B01DF,
        0x2A0E03E5, 0x54FFFE60,
    ),
    (
        0xC85F7D4D, 0xEB0E01BF, 0x540000C1, 0xC80EFD4C,
        0x350000AE, 0x5280002E, 0x3600018E, 0x14000004,
        0xD5033F5F, 0x2A1F03EE, 0x3600010E,
    ),
    (
        0x0A0B012A, 0x2A0903E5, 0x35FFF8AA, 0x885F7D09,
        0x6B05013F, 0x540000C1, 0x2A0B00AA, 0x880C7D0A,
        0x3500008C, 0x5280002A, 0x14000003, 0xD5033F5F,
        0x2A1F03EA, 0x34FFFE6A, 0x17FFFFB9,
    ),
    (
        0xC85F7D09, 0xB40000A9, 0xD5033F5F, 0x2A1F03EA,
        0x360000CA, 0x1400000C, 0xC80AFD00, 0x340000CA,
        0x2A1F03EA, 0x3700010A, 0xF9400FA0, 0xB4FFFEA9,
        0x14000004, 0x5280002A, 0x3607FF8A, 0x14000002,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000E1, 0x0B08012B,
        0x880CFE6B, 0x350000AC, 0x5280002B, 0x360000AB,
        0x1400000B, 0xD5033F5F, 0x2A1F03EB, 0x3700010B,
        0xB940126B, 0x6B0A017F, 0x2A0A03E8, 0x54FFFDA1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000E1, 0x0B08012B,
        0x880CFE6B, 0x350000AC, 0x5280002B, 0x360000AB,
        0x1400000B, 0xD5033F5F, 0x2A1F03EB, 0x3700010B,
        0xB94181AB, 0x6B0A017F, 0x2A0A03E8, 0x54FFFDA1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000E1, 0x0B08012B,
        0x880CFE6B, 0x350000AC, 0x5280002B, 0x360000AB,
        0x1400000B, 0xD5033F5F, 0x2A1F03EB, 0x3700010B,
        0xB94169AB, 0x6B0A017F, 0x2A0A03E8, 0x54FFFDA1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000E1, 0x0B08012B,
        0x880CFE6B, 0x350000AC, 0x5280002B, 0x360000AB,
        0x1400000B, 0xD5033F5F, 0x2A1F03EB, 0x3700010B,
        0xB94019AB, 0x6B0A017F, 0x2A0A03E8, 0x54FFFDA1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000E1, 0x0B08012B,
        0x880CFE6B, 0x350000AC, 0x5280002B, 0x360000AB,
        0x1400000B, 0xD5033F5F, 0x2A1F03EB, 0x3700010B,
        0xB94071AB, 0x6B0A017F, 0x2A0A03E8, 0x54FFFDA1,
    ),
    ( # Increment compare/exchange: source315a48..315a84; closed retries.
        0x885FFD09, 0x6B0A013F, 0x540000C1, 0x1100054A,
        0x880B7D0A, 0x3500008B, 0x5280002A, 0x14000003,
        0xD5033F5F, 0x2A1F03EA, 0x2A1F03E0, 0x3700008A,
        0x7100053F, 0x2A0903EA, 0x54FFFE4A,
    ),
    ( # Guarded64 publication: original31b144..31b180; preload entry+16.
        0xD5033F5F, 0x2A1F03EB, 0xAA0903EA, 0x3500018B,
        0xB9400269, 0x34000249, 0xF900030A, 0xC85F7D09,
        0xEB0A013F, 0x54FFFEE1, 0xC80AFD18, 0x35FFFECA,
        0x5280002B, 0xAA0903EA, 0x34FFFECB,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000C1, 0x0B08012B,
        0x880CFE6B, 0x3500008C, 0x5280002B, 0x14000003,
        0xD5033F5F, 0x2A1F03EB, 0x3700010B, 0xB94041AB,
        0x6B0A017F, 0x2A0A03E8, 0x54FFFDC1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000C1, 0x0B08012B,
        0x880CFE6B, 0x3500008C, 0x5280002B, 0x14000003,
        0xD5033F5F, 0x2A1F03EB, 0x3700010B, 0xB940F9AB,
        0x6B0A017F, 0x2A0A03E8, 0x54FFFDC1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000C1, 0x0B08012B,
        0x880CFE6B, 0x3500008C, 0x5280002B, 0x14000003,
        0xD5033F5F, 0x2A1F03EB, 0x3700010B, 0xB941D9AB,
        0x6B0A017F, 0x2A0A03E8, 0x54FFFDC1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000C1, 0x0B08012B,
        0x880CFE6B, 0x3500008C, 0x5280002B, 0x14000003,
        0xD5033F5F, 0x2A1F03EB, 0x3700010B, 0xB941F1AB,
        0x6B0A017F, 0x2A0A03E8, 0x54FFFDC1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000C1, 0x0B08012B,
        0x880CFE6B, 0x3500008C, 0x5280002B, 0x14000003,
        0xD5033F5F, 0x2A1F03EB, 0x3700010B, 0xB94241AB,
        0x6B0A017F, 0x2A0A03E8, 0x54FFFDC1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000C1, 0x0B08012B,
        0x880CFE6B, 0x3500008C, 0x5280002B, 0x14000003,
        0xD5033F5F, 0x2A1F03EB, 0x3700010B, 0xB94549AB,
        0x6B0A017F, 0x2A0A03E8, 0x54FFFDC1,
    ),
    (
        0x0B09010A, 0x6B0B015F, 0x885F7E6A, 0x4B08016C,
        0x1A89C189, 0x6B08015F, 0x540000C1, 0x0B08012B,
        0x880CFE6B, 0x3500008C, 0x5280002B, 0x14000003,
        0xD5033F5F, 0x2A1F03EB, 0x3700010B, 0xB94C91AB,
        0x6B0A017F, 0x2A0A03E8, 0x54FFFDC1,
    ),
    (0xF9000049, 0x9100050A, 0x5280002B, 0xC87F340C, 0xEB0801BF, 0x540000A1, 0xEB09019F, 0x54000061, 0xC82BA801, 0x35FFFF4B, 0xD5033F5F, 0xAA0D03E8, 0xAA0C03E9, 0xB5FFFE6B),
    (0x910202C9, 0xC85F7D28, 0xC80AFD20, 0x35FFFFAA),
    (0xC808FF53, 0x340001E8, 0xC85FFF48, 0xB4FFFFA8, 0xD5033F5F),
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
    ((), (0, 16), (0,), (0, 5), (0, 5, 16), (0, 16), (5, 16), (), (0, 5), (5, 16), (), (0, 5, 16), (0,), (0,), (0,), ()),
    ((), (0, 16), (0,), (0, 5), (0, 5), (0, 16), (5, 16), (), (0, 5), (5, 16), (), (0, 5, 16), (0,), (0,), (0,), ()),
    ((0, 5), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5, 16), (0, 16), (0,)),
    ((0, 5), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (0, 5, 16), (0, 16), (5, 16), (), ()),
    ((0, 5), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (0, 5), (0, 16), (5, 16), ()),
    ((0, 16), (0, 5, 16), (0, 5), (5, 16), (), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (5, 16), (0, 16), (), ()),
    ((0, 5), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (5, 16), (0, 16), ()),
    ((0, 5), (5, 16), (), (0, 5, 16), (0,), (0,), (0,), (), (), (0, 16), (0,)),
    ((0, 5, 16), (0, 16), (0,), (0, 5), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), ()),
    ((0, 5), (0,), (), (0,), (0,), (), (0, 5, 16), (0,), (0,), (0,), (0,), (0,), (), (0,), (0,), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5), (5, 16), (), (0, 5), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0, 16), (0,), (5,), (0, 16), ()),
    ((), (0, 16), (0, 16), (0,), (0, 5), (0,), (0, 5), (0, 5), (5, 16), (), (0, 5, 16), (0,), (0,), (0, 16), (0,)),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5, 16), (5, 16), (0, 5), (0, 5, 16), (0, 5, 16), (5, 16), (), (0, 5, 16), (0, 5, 16), (0,), (0,), (), (), (0, 16), (0,), (0, 5), (5, 16), (0, 16), ()),
    ((0, 5), (0, 5), (0,), (0, 5, 10), (0, 5, 16), (), (0, 5, 16), (), (0, 5, 10, 16), (0,), (), (0, 5, 16), (0, 5, 16), (0,)),
    ((0, 5), (0, 5), (0, 5, 16), (0,)),
    ((0, 5, 16), (0,), (0, 5), (0,), ()),
)


NATIVE_WAIT_MUTEX_WORDS = (
    0x79420268,0x91004014,0xF9800290,0x11000515,0x34000228,
    0x52800029,0x79020275,0x885FFE8A,0x340000CA,0x79020268,
    0xD503205F,0x79020275,0x885FFE8A,0x35FFFF8A,0x880A7E89,
    0x340003CA,0x79020268,0x79020275,0x885FFE8A,0x35FFFECA,
    0x17FFFFFA,0x52800036,0x79020275,0x885FFE88,0x350000C8,
    0x1400000A,0xD503205F,0x79020275,0x885FFE88,0x340000C8,
    0x7902027F,0x79420668,0x34FFFF48,0x94016893,0x17FFFFF8,
    0x88087E96,0x34000128,0x7902027F,0x79420668,0x34FFFE88,
    0x9401688C,0x79020275,0x885FFE88,0x35FFFE68,0x17FFFFF7,
)
NATIVE_WAIT_MUTEX_FIELDS = (
    (0,5),(0,5),(5,),(0,5),(0,),(0,),(0,5),(0,5),(0,),(0,5),
    (),(0,5),(0,5),(0,),(0,5,16),(0,),(0,5),(0,5),(0,5),(0,),
    (),(0,),(0,5),(0,5),(0,),(),(),(0,5),(0,5),(0,),
    (0,5),(0,5),(0,),(),(),(0,5,16),(0,),(0,5),(0,5),(0,),
    (),(0,5),(0,5),(0,),(),
)


NATIVE_WAIT_MUTEX_COMPACT_WORDS = (
    0x79420268,0x91004014,0xF9800290,0x11000515,0x34000228,
    0x52800029,0x79020275,0x885FFE8A,0x340000CA,0x79020268,
    0xD503205F,0x79020275,0x885FFE8A,0x35FFFF8A,0x880A7E89,
    0x3400030A,0x79020268,0x79020275,0x885FFE8A,0x35FFFECA,
    0x17FFFFFA,0x52800036,0x14000002,0xD503205F,0x79020275,
    0x885FFE88,0x340000C8,0x7902027F,0x79420668,0x34FFFF48,
    0x9400000C,0x17FFFFF8,0x88087E96,0x340000C8,0x7902027F,
    0x79420668,0x34FFFE88,0x94000005,0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_COMPACT_FIELDS = ((0, 5), (0, 5), (5,), (0, 5), (0,), (0,), (0, 5), (0, 5), (0,), (0, 5), (), (0, 5), (0, 5), (0,), (0, 5, 16), (0,), (0, 5), (0, 5), (0, 5), (0,), (), (0,), (), (), (0, 5), (0, 5), (0,), (0, 5), (0, 5), (0,), (), (), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())

# Exact original and sparse layouts share source validation. No
# branch/order/width bits in the original 45/39-word rows are generalized.
NATIVE_WAIT_MUTEX_SPARSE_WORDS = (
    0x794202C8, 0xAA0103F4, 0xAA0003F3, 0x91006015,
    0xF98002B0, 0x11000517, 0x34000948, 0x52800029,
    0x790202D7, 0x885FFEAA, 0x350000CA, 0x1400000A,
    0x790202C8, 0x790202D7, 0x885FFEAA, 0x340000CA,
    0x790202C8, 0xD503205F, 0x790202D7, 0x885FFEAA,
    0x35FFFF8A, 0x880A7EA9, 0x35FFFECA, 0x52800038,
    0x14000002, 0xD503205F, 0x790202D7, 0x885FFEA8,
    0x340000C8, 0x790202DF, 0x794206C8, 0x34FFFF48,
    0x94016560, 0x17FFFFF8, 0x88087EB8, 0x34FFF768,
    0x790202DF, 0x794206C8, 0x34FFFE88, 0x94016559,
    0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_SPARSE_FIELDS = ((0, 5), (0, 16), (0, 16), (0, 5), (5,), (0, 5), (0,), (0,), (0, 5), (0, 5), (0,), (), (0, 5), (0, 5), (0, 5), (0,), (0, 5), (), (0, 5), (0, 5), (0,), (0, 5, 16), (0,), (0,), (), (), (0, 5), (0, 5), (0,), (0, 5), (0, 5), (0,), (), (), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())
NATIVE_WAIT_MUTEX_SPARSE_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 320, 324, 328, 332, 336, 340, 344, 348, 352, 356, 360, 364, 368, 372, 376, 380, 384, 388)

# Exact source offsets permit the closed ordinary payload gap in the sparse
# layout; its branches, TLR identity, cells, ordering and exits remain fixed.
NATIVE_WAIT_MUTEX_COHORT_A_WORDS = (
    0x794202C8, 0xAA0103F4, 0xAA0003F3, 0x91006015,
    0xF98002B0, 0x11000517, 0x34000228, 0x52800029,
    0x790202D7, 0x885FFEAA, 0x340000CA, 0x790202C8,
    0xD503205F, 0x790202D7, 0x885FFEAA, 0x35FFFF8A,
    0x880A7EA9, 0x3400030A, 0x790202C8, 0x790202D7,
    0x885FFEAA, 0x35FFFECA, 0x17FFFFFA, 0x52800038,
    0x14000002, 0xD503205F, 0x790202D7, 0x885FFEA8,
    0x340000C8, 0x790202DF, 0x794206C8, 0x34FFFF48,
    0x9401650D, 0x17FFFFF8, 0x88087EB8, 0x340000C8,
    0x790202DF, 0x794206C8, 0x34FFFE88, 0x94016506,
    0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_COHORT_A_FIELDS = ((0, 5), (0, 16), (0, 16), (0, 5), (5,), (0, 5), (0,), (0,), (0, 5), (0, 5), (0,), (0, 5), (), (0, 5), (0, 5), (0,), (0, 5, 16), (0,), (0, 5), (0, 5), (0, 5), (0,), (), (0,), (), (), (0, 5), (0, 5), (0,), (0, 5), (0, 5), (0,), (), (), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())
NATIVE_WAIT_MUTEX_COHORT_A_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156, 160)

NATIVE_WAIT_MUTEX_COHORT_B_WORDS = (
    0x794202C8, 0xAA0103F3, 0xAA0003F4, 0x91006035,
    0xF98002B0, 0x11000517, 0x34000868, 0x52800029,
    0x790202D7, 0x885FFEAA, 0x350000CA, 0x1400000A,
    0x790202C8, 0x790202D7, 0x885FFEAA, 0x340000CA,
    0x790202C8, 0xD503205F, 0x790202D7, 0x885FFEAA,
    0x35FFFF8A, 0x880A7EA9, 0x35FFFECA, 0x52800038,
    0x14000002, 0xD503205F, 0x790202D7, 0x885FFEA8,
    0x340000C8, 0x790202DF, 0x794206C8, 0x34FFFF48,
    0x94016253, 0x17FFFFF8, 0x88087EB8, 0x34FFF848,
    0x790202DF, 0x794206C8, 0x34FFFE88, 0x9401624C,
    0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_COHORT_B_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 292, 296, 300, 304, 308, 312, 316, 320, 324, 328, 332, 336, 340, 344, 348, 352, 356, 360)

NATIVE_WAIT_MUTEX_COHORT_C_WORDS = (
    0x794202C8, 0xAA0103F3, 0xAA0003F4, 0x91006035,
    0xF98002B0, 0x11000517, 0x34000228, 0x52800029,
    0x790202D7, 0x885FFEAA, 0x340000CA, 0x790202C8,
    0xD503205F, 0x790202D7, 0x885FFEAA, 0x35FFFF8A,
    0x880A7EA9, 0x3400030A, 0x790202C8, 0x790202D7,
    0x885FFEAA, 0x35FFFECA, 0x17FFFFFA, 0x52800038,
    0x14000002, 0xD503205F, 0x790202D7, 0x885FFEA8,
    0x340000C8, 0x790202DF, 0x794206C8, 0x34FFFF48,
    0x940161F5, 0x17FFFFF8, 0x88087EB8, 0x340000C8,
    0x790202DF, 0x794206C8, 0x34FFFE88, 0x940161EE,
    0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_COHORT_C_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156, 160)

NATIVE_WAIT_MUTEX_COHORT_D_WORDS = (
    0x79420328, 0xF98002D0, 0x1100051A, 0x35000088,
    0x1400000E, 0x79020328, 0xD503205F, 0x7902033A,
    0x885FFEC9, 0x35FFFF89, 0x88097ED7, 0x340002C9,
    0x79020328, 0x7902033A, 0x885FFEC9, 0x35FFFEC9,
    0x17FFFFFA, 0xD503205F, 0x7902033A, 0x885FFEC8,
    0x340000C8, 0x7902033F, 0x79420728, 0x34FFFF48,
    0x94015CCC, 0x17FFFFF8, 0x88087ED7, 0x340000C8,
    0x7902033F, 0x79420728, 0x34FFFE88, 0x94015CC5,
    0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_COHORT_D_FIELDS = ((0, 5), (5,), (0, 5), (0,), (), (0, 5), (), (0, 5), (0, 5), (0,), (0, 5, 16), (0,), (0, 5), (0, 5), (0, 5), (0,), (), (), (0, 5), (0, 5), (0,), (0, 5), (0, 5), (0,), (), (), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())
NATIVE_WAIT_MUTEX_COHORT_D_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128)

NATIVE_WAIT_MUTEX_COHORT_E_WORDS = (
    0x794202A8, 0xAA0003F3, 0x91004014, 0xF9800290,
    0x11000516, 0x34000228, 0x52800029, 0x790202B6,
    0x885FFE8A, 0x340000CA, 0x790202A8, 0xD503205F,
    0x790202B6, 0x885FFE8A, 0x35FFFF8A, 0x880A7E89,
    0x3400030A, 0x790202A8, 0x790202B6, 0x885FFE8A,
    0x35FFFECA, 0x17FFFFFA, 0x52800037, 0x14000002,
    0xD503205F, 0x790202B6, 0x885FFE88, 0x340000C8,
    0x790202BF, 0x794206A8, 0x34FFFF48, 0x94015C47,
    0x17FFFFF8, 0x88087E97, 0x340000C8, 0x790202BF,
    0x794206A8, 0x34FFFE88, 0x94015C40, 0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_COHORT_E_FIELDS = ((0, 5), (0, 16), (0, 5), (5,), (0, 5), (0,), (0,), (0, 5), (0, 5), (0,), (0, 5), (), (0, 5), (0, 5), (0,), (0, 5, 16), (0,), (0, 5), (0, 5), (0, 5), (0,), (), (0,), (), (), (0, 5), (0, 5), (0,), (0, 5), (0, 5), (0,), (), (), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())
NATIVE_WAIT_MUTEX_COHORT_E_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156)

NATIVE_WAIT_MUTEX_COHORT_F_WORDS = (
    0x794202C8, 0x2A0103F4, 0xAA0003F3, 0x91004015,
    0xF98002B0, 0x11000517, 0x34000228, 0x52800029,
    0x790202D7, 0x885FFEAA, 0x340000CA, 0x790202C8,
    0xD503205F, 0x790202D7, 0x885FFEAA, 0x35FFFF8A,
    0x880A7EA9, 0x3400030A, 0x790202C8, 0x790202D7,
    0x885FFEAA, 0x35FFFECA, 0x17FFFFFA, 0x52800038,
    0x14000002, 0xD503205F, 0x790202D7, 0x885FFEA8,
    0x340000C8, 0x790202DF, 0x794206C8, 0x34FFFF48,
    0x94015B25, 0x17FFFFF8, 0x88087EB8, 0x340000C8,
    0x790202DF, 0x794206C8, 0x34FFFE88, 0x94015B1E,
    0x17FFFFF2,
)
NATIVE_WAIT_MUTEX_COHORT_F_OFFSETS = (0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 148, 152, 156, 160)

NATIVE_WAIT_MUTEX_LAYOUTS = (
    (NATIVE_WAIT_MUTEX_WORDS,NATIVE_WAIT_MUTEX_FIELDS,(33,40),(28,48,72,92,112,168),28,19,tuple(range(0,180,4)),(180,)),
    (NATIVE_WAIT_MUTEX_COMPACT_WORDS,NATIVE_WAIT_MUTEX_COMPACT_FIELDS,(30,37),(28,48,72,100),28,19,tuple(range(0,156,4)),(156,)),
    (NATIVE_WAIT_MUTEX_SPARSE_WORDS,NATIVE_WAIT_MUTEX_SPARSE_FIELDS,(32,39),(36,56,76,336),36,22,NATIVE_WAIT_MUTEX_SPARSE_OFFSETS,(92,)),
    (NATIVE_WAIT_MUTEX_COHORT_A_WORDS,NATIVE_WAIT_MUTEX_COHORT_A_FIELDS,(32, 39),(36, 56, 80, 108),36,22,NATIVE_WAIT_MUTEX_COHORT_A_OFFSETS,(164,)),
    (NATIVE_WAIT_MUTEX_COHORT_B_WORDS,NATIVE_WAIT_MUTEX_SPARSE_FIELDS,(32, 39),(36, 56, 76, 308),36,22,NATIVE_WAIT_MUTEX_COHORT_B_OFFSETS,(92,)),
    (NATIVE_WAIT_MUTEX_COHORT_C_WORDS,NATIVE_WAIT_MUTEX_COHORT_A_FIELDS,(32, 39),(36, 56, 80, 108),36,22,NATIVE_WAIT_MUTEX_COHORT_C_OFFSETS,(164,)),
    (NATIVE_WAIT_MUTEX_COHORT_D_WORDS,NATIVE_WAIT_MUTEX_COHORT_D_FIELDS,(24, 31),(32, 56, 76),32,25,NATIVE_WAIT_MUTEX_COHORT_D_OFFSETS,(132,)),
    (NATIVE_WAIT_MUTEX_COHORT_E_WORDS,NATIVE_WAIT_MUTEX_COHORT_E_FIELDS,(31, 38),(32, 52, 76, 104),32,21,NATIVE_WAIT_MUTEX_COHORT_E_OFFSETS,(160,)),
    (NATIVE_WAIT_MUTEX_COHORT_F_WORDS,NATIVE_WAIT_MUTEX_COHORT_A_FIELDS,(32, 39),(36, 56, 80, 108),36,22,NATIVE_WAIT_MUTEX_COHORT_F_OFFSETS,(164,)),
)


def native_wait_mutex(start, by_pc, kinds, api):
    """Recognize exact native WFE schedules with exact void SVC36 source.

    Every call-return-to-store route executes a fresh LDAXR. TLS rewriting
    precedes the native union; the caller still enforces whole-union entry,
    overlap and head consumption. Actual WFE progress and dedicated void
    SVC36 require the separately verified owned-TLR/event-stream platform.
    """
    for words,fields,call_indices,head_offsets,first_head,tls_role,offsets,exit_offsets in NATIVE_WAIT_MUTEX_LAYOUTS:
        begin=start.address-first_head
        if begin<0:continue
        block=tuple(by_pc.get(begin+offset) for offset in offsets)
        if any(ins is None for ins in block):continue
        roles,reverse,matched={},{},True
        for index,(ins,expected,shifts) in enumerate(zip(block,words,fields)):
            value=struct.unpack('<I',ins.bytes)[0]
            mask=sum(31<<shift for shift in shifts)
            if index in call_indices:mask|=0x3FFFFFF
            if value&~mask!=expected&~mask:
                matched=False;break
            for shift in shifts:
                role,actual=expected>>shift&31,value>>shift&31
                if role==31:
                    matched=actual==31
                elif (actual in {18,29,30,31} or roles.get(role,actual)!=actual or
                      reverse.get(actual,role)!=role):
                    matched=False
                else:roles[role],reverse[actual]=actual,role
                if not matched:break
            if not matched:break
        if not matched:continue
        nodes={ins.address for ins in block};tls=by_pc.get(begin-4)
        if (tls is None or struct.unpack('<I',tls.bytes)[0]!=(0xD53BD060|roles[tls_role]) or
                kinds.get(begin-4,'missing')!=api.site_kind(tls)):continue
        first,second=call_indices;callee=block[first].operands[-1].imm
        if callee!=block[second].operands[-1].imm or begin<=callee<begin+offsets[-1]+4 or begin<=callee+4<begin+offsets[-1]+4:continue
        stub,ret=by_pc.get(callee),by_pc.get(callee+4)
        exits=[by_pc.get(begin+offset) for offset in exit_offsets]
        if (stub is None or ret is None or any(ins is None for ins in exits) or
                struct.unpack('<I',stub.bytes)[0]!=0xD40006C1 or
                struct.unpack('<I',ret.bytes)[0]!=0xD65F03C0 or
                any(api.is_fatal_instruction(ins) for ins in exits) or
                kinds.get(callee,'missing')!=api.site_kind(stub) or
                kinds.get(callee+4,'missing') is not None):continue
        retirement=getattr(api,'SVC_MONITOR_RETIRE',None)
        if (not isinstance(retirement,frozenset) or
                any(type(number) is not int for number in retirement) or 0x36 not in retirement):
            raise api.RewriteError(f'0x{callee:x}: native wait SVC36 lacks preframe retirement policy')
        if any(kinds.get(pc,'missing') is not None for pc in nodes):
            raise api.RewriteError(f'0x{begin:x}: source rewrite in native wait mutex')
        for ins in block:
            validate_memory_operands(ins,api)
            if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
        return nodes,begin,{begin+offset for offset in head_offsets}
    return None


NATIVE_TRY_MUTEX_WORDS = (
    0x79420274,0x11000696,0x91004015,0xF98002B0,0x79020276,0x885FFEA8,
    0x34000188,0xD5033F5F,0x79020274,0x35000094,0x79420668,0x34000048,
    0x94016870,0x2A1F03E0,0xA9427BFD,0xA9414FF4,0xA8C357F6,0xD65F03C0,
    0x34000194,0x52800020,0x88087EA0,0x34FFFF28,0x79020274,0x79020276,
    0x885FFEA8,0x34FFFF68,0x17FFFFED,0x79020276,0x885FFEA8,0x35FFFD48,
    0x52800020,0x88087EA0,0x34FFFDC8,0x7902027F,0x79420668,0x34FFFF08,
    0x94016858,0x17FFFFF6,
)

NATIVE_TRY_MUTEX_FIELDS = (
    (0,5),(0,5),(0,5),(5,),(0,5),(0,5),(0,),(),(0,5),(0,),
    (0,5),(0,),(),(0,),(),(0,10),(0,10),(),(0,),(0,),(0,5,16),(0,),
    (0,5),(0,5),(0,5),(0,),(),(0,5),(0,5),(0,),(0,),(0,5,16),(0,),
    (0,5),(0,5),(0,),(),(),
)


NATIVE_TRY_MUTEX_DIRECT_WORDS = (
    0x79420295, 0xF9800010, 0x110006B6, 0x79020296,
    0x885FFC08, 0x34000188, 0xD5033F5F, 0x79020295,
    0x35000095, 0x79420688, 0x34000048, 0x94016E4E,
    0x2A1F03E0, 0xA9424FF4, 0xA94157F6, 0xA8C37BFD,
    0xD65F03C0, 0xAA0003F3, 0x34000195, 0x52800020,
    0x88087E60, 0x34FFFF08, 0x79020295, 0x79020296,
    0x885FFE68, 0x34FFFF68, 0x17FFFFEC, 0x79020296,
    0x885FFE68, 0x35FFFD28, 0x52800020, 0x88087E60,
    0x34FFFDA8, 0x7902029F, 0x79420688, 0x34FFFF08,
    0x94016E35, 0x17FFFFF6,
)
NATIVE_TRY_MUTEX_DIRECT_FIELDS = ((0, 5), (5,), (0, 5), (0, 5), (0, 5), (0,), (), (0, 5), (0,), (0, 5), (0,), (), (0,), (0, 10), (0, 10), (), (), (0, 16), (0,), (0,), (0, 5, 16), (0,), (0, 5), (0, 5), (0, 5), (0,), (), (0, 5), (0, 5), (0,), (0,), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())

# Both exact source layouts use the shared native try-mutex validator. The
# direct-cell layout keeps ABI W0/X0 fixed through its live X19<-X0 bridge.
NATIVE_TRY_MUTEX_LAYOUTS = (
    (NATIVE_TRY_MUTEX_WORDS,NATIVE_TRY_MUTEX_FIELDS,20,19,(12,36),(14,15,16,17),(20,96,112),False),
    (NATIVE_TRY_MUTEX_DIRECT_WORDS,NATIVE_TRY_MUTEX_DIRECT_FIELDS,16,20,(11,36),(13,14,15,16),(16,96,112),True),
)


def native_try_mutex(start, by_pc, kinds, api):
    """Keep two exact nonblocking mutex retry schedules and closed SP holes.

    Shared parent040 validation retains its original row and ordinary role
    renames. Only the second observed layout fixes ABI role0: its initial X0
    cell and later X19 cell are connected by the original live-reservation MOV.
    The caller protects the preceding normal TLS producer, typed transfers,
    union occupancy and all fresh heads. Runtime pin-state support is separate.
    """
    for words,fields,head_offset,tls_role,call_indices,hole_indices,head_offsets,fixed_zero in NATIVE_TRY_MUTEX_LAYOUTS:
        begin=start.address-head_offset
        if begin<0:continue
        block=tuple(by_pc.get(begin+i*4) for i in range(len(words)))
        if any(ins is None for ins in block):continue
        roles,reverse=({0:0},{0:0}) if fixed_zero else ({},{})
        matched=True
        for index,(ins,expected,shifts) in enumerate(zip(block,words,fields)):
            value=struct.unpack('<I',ins.bytes)[0]
            mask=sum(31<<shift for shift in shifts)
            if index in call_indices:mask|=0x3FFFFFF
            if value&~mask!=expected&~mask:
                matched=False;break
            for shift in shifts:
                role,actual=expected>>shift&31,value>>shift&31
                if role==31:
                    matched=actual==31
                elif (actual in {18,29,30,31} or roles.get(role,actual)!=actual or
                      reverse.get(actual,role)!=role):
                    matched=False
                else:roles[role],reverse[actual]=actual,role
                if not matched:break
            if not matched:break
        if not matched:continue
        tls=by_pc.get(begin-4)
        if (tls is None or struct.unpack('<I',tls.bytes)[0]!=(0xD53BD060|roles[tls_role]) or
                kinds.get(begin-4,'missing')!=api.site_kind(tls)):continue
        full_nodes={ins.address for ins in block}
        first,second=call_indices;callee=block[first].operands[-1].imm
        if callee!=block[second].operands[-1].imm or callee in full_nodes or callee+4 in full_nodes:continue
        stub,ret=by_pc.get(callee),by_pc.get(callee+4)
        if (stub is None or ret is None or struct.unpack('<I',stub.bytes)[0]!=0xD40006C1 or
                struct.unpack('<I',ret.bytes)[0]!=0xD65F03C0 or
                kinds.get(callee,'missing')!=api.site_kind(stub) or
                kinds.get(callee+4,'missing') is not None):continue
        nodes={ins.address for index,ins in enumerate(block) if index not in hole_indices}
        if any(kinds.get(pc,'missing') is not None for pc in nodes):
            raise api.RewriteError(f'0x{begin:x}: source rewrite in native try mutex')
        for ins in block:
            validate_memory_operands(ins,api)
            if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
        return nodes,begin,{begin+offset for offset in head_offsets}
    return None


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
        begin = start.address - (0, 0, 20, 0, 20, 16, 4, 4, 4, 4, 20, 20, 0, 72, 28, 32, 32, 0, 0, 0, 8, 0, 0, 12, 0, 8, 8, 8, 8, 8, 0, 28, 8, 8, 8, 8, 8, 8, 8, 12, 4, 8)[variant]
        block = tuple(by_pc.get(begin + i*4) for i in range(len(words)))
        if begin < 0 or any(ins is None for ins in block):
            continue
        external = ((6,), (5,), (2, 4), (4, 9), (3,), (3,), (), (), (), (7,), (4, 9), (4, 9), (15,), (), (), (2, 7, 15), (2, 15), (), (10, 16), (10,), (11, 15), (), (6, 10), (2, 14), (5, 9, 15), (12, 15), (12, 15), (12, 15), (12, 15), (12, 15), (), (5,), (14,), (14,), (14,), (14,), (14,), (14,), (14,), (), (), (1,))[variant]
        roles, reverse, matched = {}, {}, True
        for index, (ins, expected, shifts) in enumerate(zip(block, words, fields)):
            value = struct.unpack('<I', ins.bytes)[0]
            mask = sum(31 << shift for shift in shifts)
            if index in external:
                bits = 14 if (variant,index) in ((15, 2), (16, 2), (18, 10), (19, 10), (20, 11), (22, 6), (22, 10), (24, 9), (25, 15), (26, 15), (27, 15), (28, 15), (29, 15), (32, 14), (33, 14), (34, 14), (35, 14), (36, 14), (37, 14), (38, 14)) else 19
                mask |= 0x3FFFFFF if (variant,index) in ((3, 9), (9, 7), (10, 9), (11, 9), (12, 15), (15, 15), (16, 15), (18, 16), (20, 15), (23, 14), (24, 5), (24, 15), (25, 12), (26, 12), (27, 12), (28, 12), (29, 12)) else ((1 << bits) - 1) << 5
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
        if variant in (25,26,27,28,29) and exits[0]!=exits[1]:
            continue # This clamp row has one shared completed-attempt exit.
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
        entry = begin + (0, 0, 12, 0, 16, 4, 0, 0, 0, 0, 20, 20, 0, 4, 28, 32, 32, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8)[variant]
        heads = {begin+offset for offset in ((0, 28), (0, 28), (20,), (0, 20), (20,), (16,), (4,), (4,), (4,), (4,), (20,), (20,), (0,), (72, 144), (28,), (32,), (32,), (0,), (0,), (0,), (8,), (0,), (0,), (12,), (0,), (8,), (8,), (8,), (8,), (8,), (0,), (28,), (8,), (8,), (8,), (8,), (8,), (8,), (8,), (12,), (4,), (8,))[variant]}
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


NATIVE_POINTER_REFRESH_WORDS = (
    0xD5033F5F, 0x2A1F03EF, 0xAA0E03ED, 0x35FFFE2F,
    0x8A0801AE, 0xAA0B01CE, 0xF900052E, 0xF940200E,
    0x8A0C01CC, 0x910005CF, 0x8A2E01AE, 0xAA0F018C,
    0x8B0E018C, 0xC85F7D4E, 0xEB0D01DF, 0x54FFFE21,
    0xC80DFD4C, 0x35FFFE0D, 0x5280002F, 0xAA0E03ED,
    0x34FFFE0F, 0x17FFFFDF,
)
NATIVE_POINTER_REFRESH_FIELDS = (
    (), (0,), (0, 5, 16), (0,), (0, 5, 16), (0, 5, 16),
    (0, 5), (0, 5), (0, 5, 16), (0, 5), (0, 5, 16),
    (0, 5, 16), (0, 5, 16), (0, 5), (0, 5, 16), (),
    (0, 5, 16), (0,), (0,), (0, 5, 16), (0,), (),
)


def native_pointer_refresh(start, by_pc, kinds, api):
    """Return (whole union, sole ordinary entry, sole exclusive head).

    Ordinary payload memory accesses run before a fresh LDXR, after CLREX or
    failed STLXR. The intentional expected/store-status alias is preserved.
    The caller must enforce whole-union single-entry and overlap exclusion.
    """
    begin = start.address - 52
    if begin < 0:
        return None
    block = tuple(by_pc.get(begin + offset) for offset in range(0, 88, 4))
    if any(ins is None for ins in block):
        return None
    roles, reverse = {}, {}
    for index, (ins, expected, fields) in enumerate(zip(
            block, NATIVE_POINTER_REFRESH_WORDS, NATIVE_POINTER_REFRESH_FIELDS)):
        value = struct.unpack('<I', ins.bytes)[0]
        mask = sum(31 << shift for shift in fields)
        if index == 3:
            mask |= 0x7FFFF << 5
        elif index == 21:
            mask |= 0x3FFFFFF
        if value & ~mask != expected & ~mask:
            return None
        for shift in fields:
            role, actual = expected >> shift & 31, value >> shift & 31
            if role == 31:
                if actual != 31:
                    return None
            elif (actual in {18, 29, 30, 31} or
                  roles.get(role, actual) != actual or
                  reverse.get(actual, role) != role):
                return None
            else:
                roles[role], reverse[actual] = actual, role
    nodes = {ins.address for ins in block}
    exit_pc = block[3].operands[-1].imm
    if (exit_pc != block[21].operands[-1].imm or exit_pc in nodes or
            exit_pc not in by_pc or api.is_fatal_instruction(by_pc[exit_pc])):
        return None
    if any(kinds.get(pc, 'missing') is not None for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in native pointer refresh')
    for ins in block:
        validate_memory_operands(ins, api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES:
            validate_exclusive(ins, api)
    return nodes, begin + 16, {begin + 52}



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



NATIVE_POINTER_CHAIN_POP_WORDS = (
    0xC85FFD13,0x37000293,0xF9400269,0xB40000A9,0xC80AFD09,
    0x35FFFF6A,0xB5000453,0x1400000F,0xB2400269,0xC85FFD0A,
    0xEB13015F,0x54000141,0xC80A7D09,0x35FFFF8A,0x91020009,
    0xC85FFD2A,0xEB13015F,0x54000381,0xC80A7D3F,0x35FFFF8A,
    0x17FFFFF2,0xD5033F5F,0xD5033F5F,0xC85F7D09,0x927FF929,
    0xC80AFD09,0x35FFFFAA,0x17FFFFE4,
)
NATIVE_POINTER_CHAIN_POP_FIELDS = (
    (0,5),(0,),(0,5),(0,),(0,5,16),(0,),(0,),(),(0,5),(0,5),
    (5,16),(),(0,5,16),(0,),(0,5),(0,5),(5,16),(),(0,5,16),
    (0,),(),(),(),(0,5),(0,5),(0,5,16),(0,),(),
)


def native_pointer_chain_pop(start, by_pc, kinds, api):
    """An exact tagged free-list pop keeps both clears and four heads native.

    The link/secondary-cell role is intentionally reused. All control offsets,
    tag bits, memory widths and ordering bits stay fixed. Failed stores refresh
    at the matching load; secondary mismatch clears before untagging the first
    cell. The two ordinary exits follow a store or CLREX, before any host gate.
    """
    begin=start.address
    offsets=(*range(0,88,4),*range(180,204,4))
    block=tuple(by_pc.get(begin+offset) for offset in offsets)
    if any(ins is None for ins in block):return None
    roles,reverse={},{}
    for ins,expected,fields in zip(block,NATIVE_POINTER_CHAIN_POP_WORDS,NATIVE_POINTER_CHAIN_POP_FIELDS):
        value=struct.unpack('<I',ins.bytes)[0]
        mask=sum(31<<shift for shift in fields)
        if value&~mask!=expected&~mask:return None
        for shift in fields:
            role,actual=expected>>shift&31,value>>shift&31
            if role==31:
                if actual!=31:return None
            elif (actual in {18,29,30,31} or roles.get(role,actual)!=actual or
                  reverse.get(actual,role)!=role):return None
            else:roles[role],reverse[actual]=actual,role
    if any(pc not in by_pc or api.is_fatal_instruction(by_pc[pc])
           for pc in (begin+88,begin+160)):return None
    nodes={ins.address for ins in block}
    if any(kinds.get(pc,'missing') is not None for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in native pointer chain pop')
    for ins in block:
        validate_memory_operands(ins,api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
    return nodes,begin,{begin,begin+36,begin+60,begin+184}


def native_pointer_chain(start, by_pc, kinds, api):
    """Four exact native heads retire before the tagged-chain call island.

    Only the null-link path replaces the initial reservation with a fresh
    same-cell acquire load. The original words remain native; secondary heads
    are consumed internal heads, never independent entrances.
    """
    pop=native_pointer_chain_pop(start,by_pc,kinds,api) or native_pointer_chain_pop_recomputed(start,by_pc,kinds,api)
    if pop is not None:return pop
    begin=start.address
    block=tuple(by_pc.get(begin+offset) for offset in range(0,72,4))
    if any(ins is None for ins in block):return None
    values=tuple(struct.unpack('<I',ins.bytes)[0] for ins in block)
    owner,cell,link,status,other=(values[0]&31,values[0]>>5&31,
                                  values[2]&31,values[8]&31,values[13]>>5&31)
    roles=(owner,cell,other,link,status)
    if len(set(roles))!=5 or any(role in {18,29,30,31} for role in roles):return None
    if block[1].mnemonic!='tbnz':return None
    clear=block[1].operands[-1].imm
    if clear-begin not in (0x60,0x68):return None
    second,epilogue,success=clear+8,clear+0x1C,begin+0x48
    tail=tuple(by_pc.get(clear+offset) for offset in range(0,28,4))
    if any(ins is None for ins in tail):return None
    if any(pc not in by_pc or api.is_fatal_instruction(by_pc[pc]) for pc in (epilogue,success)):return None
    expected=(0xC85FFC00|cell<<5|owner,
              0x37000000|(((clear-begin-4)//4)&0x3FFF)<<5|owner,
              0xF9400000|owner<<5|link,0xB4000080|link,
              0xC800FC00|status<<16|cell<<5|link,0x35FFFF60|status,
              0x1400000C,0xB2400000|owner<<5|link,
              0xC85FFC00|cell<<5|status,0xEB00001F|owner<<16|status<<5,
              0x54000001|(((clear-begin-40)//4)&0x7FFFF)<<5,
              0xC8007C00|status<<16|cell<<5|link,0x35FFFF80|status,
              0xC85FFC00|other<<5|link,0xEB00001F|owner<<16|link<<5,
              0x54000001|(((second-begin-60)//4)&0x7FFFF)<<5,
              0xC8007C1F|link<<16|other<<5,0x35FFFF80|link)
    ending=(0xD5033F5F,0x14000006,0xD5033F5F,0xC85F7C00|cell<<5|link,
            0x927FF800|link<<5|link,0xC800FC00|status<<16|cell<<5|link,
            0x35FFFFA0|status)
    if values!=expected or tuple(struct.unpack('<I',ins.bytes)[0] for ins in tail)!=ending:return None
    nodes={ins.address for ins in (*block,*tail)}
    if any(kinds.get(pc,'missing') is not None for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in native pointer chain')
    for ins in (*block,*tail):
        validate_memory_operands(ins,api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
    return nodes,begin,{begin,begin+32,begin+52,second+4}


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


def require_native_wait_transfers(instructions, by_pc, kinds, entries, protected, producer, facts, api):
    """Only wait opt-in requires complete facts for selected indirect transfers.

    The rewrite caller derives these from validated lowering plans, never from
    an offset-only whitelist. Host facts mean actual checked host gates, not
    native RX authority. Finite guest targets retain all source-entry checks.
    """
    facts={} if facts is None else facts
    if not isinstance(facts,dict):
        raise api.RewriteError('native wait transfer facts must be a mapping')
    entries=set(entries)
    for ins in instructions:
        if ins.group(CS_GRP_RET) and ins.op_str not in ('','x30'):
            raise api.RewriteError(f'0x{ins.address:x}: unsupported indirect return before native wait')
        if ins.mnemonic not in ('br','blr'):continue
        fact=facts.get(ins.address)
        if not isinstance(fact,tuple) or len(fact)!=2:
            raise api.RewriteError(f'0x{ins.address:x}: native wait lacks explicit processed transfer facts')
        kind,targets=fact
        if kind=='host':
            if targets!=() or kinds.get(ins.address)!='gate':
                raise api.RewriteError(f'0x{ins.address:x}: native wait host fact is not a lowered checked gate')
            continue
        expected={'finite':(None,'byte_jump'),'checked-call':('checked_call',),
                  'checked-call-forest':('checked_call_forest_stub',)}
        if (kind not in expected or kinds.get(ins.address) not in expected[kind] or
                ins.mnemonic!=('br' if kind=='finite' else 'blr') or
                not isinstance(targets,tuple) or not targets or
                any(type(target) is not int or target not in by_pc or target not in entries for target in targets)):
            raise api.RewriteError(f'0x{ins.address:x}: native wait finite transfer lacks complete selected entry facts')
        if (set(targets)&protected)-{producer}:
            raise api.RewriteError(f'0x{ins.address:x}: native wait transfer bypasses its TLR producer')


def native_read_wait_checked_return(start, by_pc, kinds, api):
    """Keep a read-only LDAXR/WFE poll native through its checked return.

    WFE must execute while the address monitor is live on retry. The sole
    host-backed SP check is after the successful poll, with no later WFE or
    store-exclusive before RET. Its normal checked-stack gate remains in
    place; the poll words remain native and no case is silently promoted to
    a new entry.
    """
    begin=start.address-8
    body=tuple(by_pc.get(begin+offset) for offset in range(0,32,4))
    tail=tuple(by_pc.get(begin+offset) for offset in range(32,48,4))
    if any(ins is None for ins in body+tail):
        return None
    values=tuple(struct.unpack('<I',ins.bytes)[0] for ins in body+tail)
    epilogues={
        (0xA9427BFD,0xA9414FF4,0xF84307F5,0xD65F03C0):8,
        (0xA9424FF4,0xF9400BF5,0xA8C37BFD,0xD65F03C0):16,
    }
    if (values[:8]!=(0xD50320BF,0xD503205F,0x885FFE69,0x72003D3F,
                     0x54FFFFA1,0x53107D29,0x6B29011F,0x54FFFF41) or
            values[8:] not in epilogues):
        return None
    if any(kinds.get(ins.address,'missing') is not None for ins in body+tail[:2]):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in native read wait')
    if kinds.get(tail[2].address)!='stack_check' or kinds.get(tail[3].address) is not None:
        raise api.RewriteError(f'0x{begin:x}: read wait return lacks checked SP gate')
    operation=api.stack_check_operation(values[-2])
    if operation!={'source':31,'delta':48,'access_bytes':epilogues[values[8:]],'post_index':True}:
        raise api.RewriteError(f'0x{begin:x}: read wait return has different SP access')
    validate_memory_operands(body[2],api)
    validate_exclusive(body[2],api)
    for ins in tail[:3]:
        validate_memory_operands(ins,api)
    # SEVL precedes the first wait; the two mismatch edges go to that WFE,
    # not to a host call or a second producer. The success edge reaches the
    # checked epilogue, where the reservation is no longer consumed.
    return {ins.address for ins in body},body[0].address



def ticket_continuation_retires(first, by_pc, kinds, api, *,
                               monitor_retiring_calls=frozenset(), used_contracts=None):
    """Bound every selected continuation until its old token is retired.

    A selected BL alone is not proof: the callee could consume the caller's
    token. The exact SVC36/RET boundary and importer-verified forced-binding
    callsites are the only call boundaries. Ordinary interposable PLTs, returns,
    unknown control flow and token-using stores remain refusals.
    """
    colors={}
    verified_used=set()
    pending=[(first,False)]
    while pending:
        pc,leaving=pending.pop()
        if leaving:
            colors[pc]=2;continue
        if colors.get(pc)==1:return False
        if colors.get(pc)==2:continue
        ins=by_pc.get(pc)
        if ins is None or len(colors)>=MAX_TAIL_WORDS:return False
        if ins.mnemonic in api.EXCLUSIVE_LOADS:
            if kinds.get(pc,'missing') is not None:return False
            validate_exclusive(ins,api);validate_memory_operands(ins,api)
            colors[pc]=2;continue
        if ins.mnemonic=='clrex':
            if kinds.get(pc,'missing') is not None:return False
            colors[pc]=2;continue
        if ins.mnemonic in api.EXCLUSIVE_STORES:return False
        if ins.mnemonic=='bl':
            if kinds.get(pc,'missing') is not None:return False
            if pc in monitor_retiring_calls:
                # The importer supplies immutable callsites bound to exact
                # PLT/GOT/ABI metadata. The native flagged-module binder must
                # enforce the same canonical CLREX-first abort contract.
                verified_used.add(pc);colors[pc]=2;continue
            target=ins.operands[-1].imm
            stub,ret=by_pc.get(target),by_pc.get(target+4)
            if (stub is None or ret is None or
                    struct.unpack('<I',stub.bytes)[0]!=0xD40006C1 or
                    struct.unpack('<I',ret.bytes)[0]!=0xD65F03C0 or
                    kinds.get(target,'missing')!=api.site_kind(stub) or
                    kinds.get(target+4,'missing') is not None):return False
            colors[pc]=2;continue
        if (kinds.get(pc,'missing') is not None or api.is_fatal_instruction(ins) or
                any(ins.group(group) for group in (CS_GRP_CALL,CS_GRP_RET)) or
                (ins.group(CS_GRP_JUMP) and ins.mnemonic!='b' and
                 ins.mnemonic not in CONDITIONAL and not ins.mnemonic.startswith('b.'))):return False
        targets=successors(ins)
        if not targets:return False
        colors[pc]=1;pending.append((pc,True))
        pending.extend((target,False) for target in reversed(targets))
    if used_contracts is not None:used_contracts.update(verified_used)
    return True



def retiring_ticket_attempt(start, by_pc, kinds, api, *, monitor_retiring_calls=frozenset()):
    """Relocate only the observed acquire/release ticket-count attempts.

    Live branches leave the attempt and cannot use its token before retirement.
    The six-word release keeps failed-store retries inside its one frame.
    Explicit CLREX makes later WFE/SVC/abort paths closed without
    guessing that an interposable abort cannot return. WFE wake timing may
    differ: execution retains the platform's mandatory EVTSTRM prerequisite.
    No source call, SP operation, or unrelated native topology is admitted.
    """
    begin=start.address
    release=start.mnemonic=='ldxr'
    size=24 if release else 32
    block=tuple(by_pc.get(begin+offset) for offset in range(0,size,4))
    if any(ins is None for ins in block):return None
    values=tuple(struct.unpack('<I',ins.bytes)[0] for ins in block)
    loaded,base=values[0]&31,values[0]>>5&31
    temp=(values[4]>>16&31) if release else (values[1]&31)
    if release:
        expected=(0x885F7C00|base<<5|loaded,0xF2403C1F|loaded<<5,values[2],
                  0x51000400|loaded<<5|loaded,
                  0x8800FC00|temp<<16|base<<5|loaded,0x35FFFF60|temp)
        if values!=expected or values[2]&0xFF00001F!=0x54000000:return None
    else:
        expected=(0x885FFC00|base<<5|loaded,0x53105C00|loaded<<5|temp,
                  0x6B40601F|loaded<<16|temp<<5,values[3],
                  0x11000400|loaded<<5|loaded,0x72003C1F|loaded<<5,
                  values[6],0x88007C00|temp<<16|base<<5|loaded)
        if (values!=expected or values[3]&0xFF00001F!=0x54000001 or
                values[6]&0xFF00001F!=0x54000000):return None
    roles=(base,loaded,temp)
    if len(set(roles))!=3 or any(role in {18,29,30,31} for role in roles):return None
    closed=begin+size
    if release:
        fatal=block[2].operands[-1].imm
        live_targets=(fatal,)
        exits=frozenset(((begin+8,fatal),(begin+20,closed)))
        retries=frozenset(((begin+20,begin),))
        terminal=begin+16
        if not closed<fatal:return None
    else:
        mismatch,fatal=(block[index].operands[-1].imm for index in (3,6))
        live_targets=(mismatch,fatal)
        exits=frozenset(((begin+12,mismatch),(begin+24,fatal),(begin+28,closed)))
        retries=frozenset();terminal=begin+28
        if not mismatch<begin<closed<fatal:return None
    if any(target not in by_pc or api.is_fatal_instruction(by_pc[target])
           for target in (*live_targets,closed)):return None
    used_contracts=set()
    if not all(ticket_continuation_retires(target,by_pc,kinds,api,
                                         monitor_retiring_calls=monitor_retiring_calls,
                                         used_contracts=used_contracts)
               for target in live_targets):return None
    nodes={ins.address for ins in block}
    if any(kinds.get(pc,'missing') is not None for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in retiring ticket attempt')
    for ins in block:
        validate_memory_operands(ins,api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
    used=set().union(*(api.registers(ins) for ins in block))
    available=[reg for reg in range(16) if reg not in used]
    if len(available)<2:return None
    return Region(begin,block,frozenset((terminal,)),retries,exits,
                  *available[:2],frozenset(live_targets),
                  requires_diag_abort_v1=bool(used_contracts),
                  monitor_retiring_call_sites=frozenset(used_contracts))



def writer_ticket_attempt(start, by_pc, kinds, api, *, monitor_retiring_calls=frozenset()):
    """One exact writer acquire: a failed STXR exits before any retry work.

    The fatal comparison alone leaves a live reservation. The successful and
    failed store paths already close it in hardware; their original downstream
    counter/SVC/WFE code remains native and outside this relocated attempt.
    """
    if start.mnemonic!='ldaxr':return None
    begin=start.address
    block=tuple(by_pc.get(begin+offset) for offset in range(0,36,4))
    if any(ins is None for ins in block):return None
    values=tuple(struct.unpack('<I',ins.bytes)[0] for ins in block)
    loaded,base=values[0]&31,values[0]>>5&31
    temp,status,increment=values[1]&31,values[7]>>16&31,values[6]>>16&31
    roles=(loaded,base,temp,status,increment)
    if len(set(roles))!=5 or any(role in {18,29,30,31} for role in roles):return None
    fatal=block[5].operands[-1].imm if block[5].mnemonic=='b.eq' else None
    success=block[8].operands[-1].imm if block[8].mnemonic=='cbz' else None
    closed=begin+36
    if (fatal is None or success is None or not closed<success<fatal or
            any(target not in by_pc or api.is_fatal_instruction(by_pc[target])
                for target in (closed,success,fatal))):return None
    expected=(0x885FFC00|base<<5|loaded,
              0xD3587C00|loaded<<5|temp,
              0x4B404000|loaded<<16|temp<<5|temp,
              0x2A2003E0|temp<<16|temp,
              0x72001C1F|temp<<5,
              0x54000000|(((fatal-(begin+20))//4)&0x7FFFF)<<5,
              0x0B000000|increment<<16|loaded<<5|temp,
              0x88007C00|status<<16|base<<5|temp,
              0x34000000|(((success-(begin+32))//4)&0x7FFFF)<<5|status)
    if values!=expected:return None
    used_contracts=set()
    if not ticket_continuation_retires(fatal,by_pc,kinds,api,
                                      monitor_retiring_calls=monitor_retiring_calls,
                                      used_contracts=used_contracts):return None
    if any(kinds.get(ins.address,'missing') is not None for ins in block):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in writer ticket attempt')
    for ins in block:
        validate_memory_operands(ins,api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
    used=set().union(*(api.registers(ins) for ins in block))
    available=[reg for reg in range(16) if reg not in used]
    if len(available)<2:return None
    return Region(begin,block,frozenset((begin+28,)),frozenset(),
                  frozenset(((begin+20,fatal),(begin+32,success),(begin+32,closed))),
                  *available[:2],frozenset((fatal,)),
                  requires_diag_abort_v1=bool(used_contracts),
                  monitor_retiring_call_sites=frozenset(used_contracts))



def direct_svc1a_ret_call(ins, by_pc, api):
    """Direct BL whose target is exactly SVC #0x1A; RET.

    That callee is the reservation-ending gate SVC_MONITOR_RETIRE already
    uses for a direct SVC #0x1A. Other immediates, indirect targets, and a
    leading SVC without this exact RET are not this exit.
    """
    if ins.mnemonic!='bl' or not ins.operands or ins.operands[-1].type!=ARM64_OP_IMM or len(ins.bytes)!=4:
        return False
    call=struct.unpack('<I',ins.bytes)[0]
    target=ins.operands[-1].imm
    retirement=getattr(api,'SVC_MONITOR_RETIRE',None)
    stub=by_pc.get(target) if type(target) is int and target>=0 and target%4==0 else None
    ret=by_pc.get(target+4) if stub is not None else None
    if ((call&0xFC000000)!=0x94000000 or stub is None or ret is None or
            len(stub.bytes)!=4 or len(ret.bytes)!=4 or
            not isinstance(retirement,frozenset) or 0x1A not in retirement or
            any(type(number) is not int for number in retirement)):
        return False
    return (struct.unpack('<I',stub.bytes)[0]==0xD4000341 and
            struct.unpack('<I',ret.bytes)[0]==0xD65F03C0)


def compare_tests_register(ins, number):
    """CMP tests this register, not an extension or shift of it."""
    if ins.mnemonic != 'cmp' or len(ins.operands) != 2 or number is None:
        return False
    tested = ins.operands[0]
    if (tested.type != ARM64_OP_REG or tested.ext or tested.shift.value or
            register_number(ins, tested.reg) != number):
        return False
    return True


def compare_fail_edge(by_pc, branch_pc, clrex_pc, api, loads=frozenset({'ldaxrb'})):
    """B.NE immediately after CMP of the preceding exclusive-load destination.

    The three instructions are adjacent. The compare tests that load's
    destination, and the branch target is this address. The load mnemonic is
    one of `loads`. The load's address register is the cell both failures share.
    """
    if (type(branch_pc) is not int or branch_pc < 8 or branch_pc % 4 or
            type(clrex_pc) is not int or clrex_pc % 4 or
            not isinstance(loads, frozenset)):
        return None
    branch, compare, load = (by_pc.get(branch_pc), by_pc.get(branch_pc - 4),
                             by_pc.get(branch_pc - 8))
    if (branch is None or compare is None or load is None or
            branch.address != branch_pc or compare.address != branch_pc - 4 or
            load.address != branch_pc - 8 or branch.mnemonic != 'b.ne' or
            compare.mnemonic != 'cmp' or load.mnemonic not in loads):
        return None
    if (not branch.operands or branch.operands[-1].type != ARM64_OP_IMM or
            branch.operands[-1].imm != clrex_pc):
        return None
    dest, base = loaded_register(load), memory_base(load)
    if (dest is None or base is None or dest == base or base in {18, 29, 30, 31} or
            not compare_tests_register(compare, dest)):
        return None
    return branch_pc, load.address, base, dest


def clrex_reentry_only_at_load(by_pc, clrex_pc, attempt, entry, base, api):
    """Paths after CLREX meet this attempt only at its exclusive load.

    Reaching that load is a new attempt only when this path has already
    written the address register. Reaching the compare, the failing branch,
    or the store is the same attempt. A call or indirect branch is not proof
    that those instructions stay unreachable.
    """
    interior = set(attempt) - {entry, clrex_pc}
    pending, seen = [(clrex_pc, False)], set()
    while pending:
        pc, written = pending.pop()
        if (pc, written) in seen:
            continue
        if len(seen) >= MAX_REGION_WORDS:
            return False
        seen.add((pc, written))
        ins = by_pc.get(pc)
        if ins is None or ins.address != pc or api.is_fatal_instruction(ins):
            return False
        if ins.mnemonic == 'ret':
            if ins.operands and register_number(ins, ins.operands[0].reg) not in {30}:
                return False
            continue
        if (ins.mnemonic in {'br', 'blr', 'bl'} or
                (ins.group(CS_GRP_JUMP) and ins.mnemonic != 'b' and
                 ins.mnemonic not in CONDITIONAL and not ins.mnemonic.startswith('b.'))):
            return False
        now = written or writes_register(ins, base)
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
            return False
        for target in targets:
            if target in interior:
                return False
            if target == entry:
                if not now:
                    return False
                continue
            pending.append((target, now))
    return bool(seen)


def shared_compare_fail_clrex_exit(by_pc, clrex_pc, attempt, entry, api):
    """Shared compare-fail CLREX is an exit of this LDAXRB attempt.

    Every static predecessor is a compare-not-equal after LDAXRB of the same
    address, and that compare tests the destination of its own load. At least
    two such loads share the CLREX. This attempt owns one of them. Paths from
    the CLREX re-enter this attempt only at that load, after an address write.
    """
    clrex = by_pc.get(clrex_pc)
    if (clrex is None or clrex.mnemonic != 'clrex' or clrex.address != clrex_pc or
            type(entry) is not int or entry not in attempt or clrex_pc not in attempt):
        return False
    predecessors = []
    for ins in by_pc.values():
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
            return False
        if clrex_pc in targets:
            predecessors.append(ins)
    if len(predecessors) < 2:
        return False
    edges = []
    for ins in predecessors:
        edge = compare_fail_edge(by_pc, ins.address, clrex_pc, api)
        if edge is None:
            return False
        edges.append(edge)
    if len({edge[1] for edge in edges}) < 2 or len({edge[2] for edge in edges}) != 1:
        return False
    owned = [edge for edge in edges if edge[1] == entry and edge[0] in attempt]
    if len(owned) != 1 or owned[0][0] - 4 not in attempt:
        return False
    return clrex_reentry_only_at_load(by_pc, clrex_pc, attempt, entry, owned[0][2], api)


def direct_predecessors(by_pc, target):
    """Static instructions whose successor list contains this exact address."""
    found = []
    for ins in by_pc.values():
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(item) is not int for item in targets):
            return None
        if target in targets:
            found.append(ins)
    return found


def mov_zeros_tested_register(mov, test):
    """MOV from WZR/XZR writes the register this TBNZ tests.

    A later bit test of that register is dead: every bit of the written
    value is clear. The source is the zero register, not a shifted copy.
    """
    if (mov.mnemonic != 'mov' or test.mnemonic != 'tbnz' or
            len(mov.operands) != 2 or len(test.operands) < 2):
        return False
    dest, source = mov.operands
    tested = test.operands[0]
    bit = test.operands[1]
    if (dest.type != ARM64_OP_REG or source.type != ARM64_OP_REG or tested.type != ARM64_OP_REG or
            dest.ext or source.ext or tested.ext or dest.shift.value or source.shift.value or
            tested.shift.value or bit.type != ARM64_OP_IMM or type(bit.imm) is not int or
            not 0 <= bit.imm < 64):
        return False
    if mov.reg_name(source.reg) not in {'wzr', 'xzr'}:
        return False
    written = register_number(mov, dest.reg)
    if (written is None or written in {18, 29, 30, 31} or
            written != register_number(test, tested.reg) or not writes_register(mov, written)):
        return False
    return True


def memory_uses_register(ins, number):
    """True when a memory operand cannot be shown to avoid this address register."""
    found = [operand for operand in ins.operands if operand.type == ARM64_OP_MEM]
    if not found:
        return False
    if len(found) != 1 or found[0].mem.index:
        return True
    base = register_number(ins, found[0].mem.base)
    if base is None:
        return ins.reg_name(found[0].mem.base) != 'sp'
    return base == number


def dead_tbnz_fallthrough_leaves(by_pc, tbnz_pc, body, base, api, release='strb'):
    """The dead TBNZ fallthrough store leaves without re-entering this attempt.

    Only the fallthrough is live. Each path to RET contains one plain store of
    the exclusive load's width whose address register is not the exclusive
    address. LDAXRB uses STRB, LDAXRH uses STRH, and LDAXR uses STR. A path
    into the exclusive load or store, or a store through that address, is not
    this exit.
    """
    if release not in {'strb', 'strh', 'str'}:
        return False
    pending, seen, left = [(tbnz_pc + 4, False)], set(), False
    while pending:
        pc, saw_strb = pending.pop()
        if (pc, saw_strb) in seen:
            continue
        if len(seen) >= MAX_REGION_WORDS or pc in body:
            return False
        seen.add((pc, saw_strb))
        ins = by_pc.get(pc)
        if ins is None or ins.address != pc or api.is_fatal_instruction(ins):
            return False
        if ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES or memory_uses_register(ins, base):
            return False
        if ins.mnemonic == release:
            if memory_base(ins) in {None, base}:
                return False
            saw_strb = True
        if ins.mnemonic == 'ret':
            if not saw_strb or (ins.operands and register_number(ins, ins.operands[0].reg) not in {30}):
                return False
            left = True
            continue
        if (ins.mnemonic in {'br', 'blr', 'bl'} or
                (ins.group(CS_GRP_JUMP) and ins.mnemonic != 'b' and
                 ins.mnemonic not in CONDITIONAL and not ins.mnemonic.startswith('b.'))):
            return False
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
            return False
        for target in targets:
            if target in body:
                return False
            pending.append((target, saw_strb))
    return left


def shared_compare_fail_mov_before_clrex(by_pc, clrex_pc, attempt, entry, api):
    """Shared compare failures may exit through the MOV before CLREX.

    Every predecessor of that MOV is a compare-not-equal after LDAXRB, LDAXRH,
    or LDAXR of the same address, and that compare tests the destination of its
    own load. Every one of those loads uses the same mnemonic. At least two such
    loads share the MOV. This attempt owns one of them. The MOV writes zero to
    the register tested by the TBNZ after this CLREX, so that branch is dead.
    CLREX is its only predecessor. The fallthrough does not re-enter this load
    or store. LDAXRB leaves through STRB, LDAXRH through STRH, and LDAXR through
    STR, using a different address. LDXR is not this exit.
    """
    clrex = by_pc.get(clrex_pc)
    mov_pc, tbnz_pc = clrex_pc - 4, clrex_pc + 4
    mov, tbnz = by_pc.get(mov_pc), by_pc.get(tbnz_pc)
    if (clrex is None or mov is None or tbnz is None or clrex.mnemonic != 'clrex' or
            clrex.address != clrex_pc or mov.address != mov_pc or tbnz.address != tbnz_pc or
            type(entry) is not int or entry not in attempt or mov_pc not in attempt or
            clrex_pc not in attempt or not mov_zeros_tested_register(mov, tbnz)):
        return False
    tested = register_number(tbnz, tbnz.operands[0].reg)
    if writes_register(clrex, tested):
        return False
    predecessors = direct_predecessors(by_pc, mov_pc)
    clrex_predecessors = direct_predecessors(by_pc, clrex_pc)
    tbnz_predecessors = direct_predecessors(by_pc, tbnz_pc)
    if (predecessors is None or clrex_predecessors is None or tbnz_predecessors is None or
            len(predecessors) < 2 or {ins.address for ins in clrex_predecessors} != {mov_pc} or
            {ins.address for ins in tbnz_predecessors} != {clrex_pc}):
        return False
    allowed = {'ldaxrb': 'strb', 'ldaxrh': 'strh', 'ldaxr': 'str'}
    edges = []
    for ins in predecessors:
        edge = compare_fail_edge(by_pc, ins.address, mov_pc, api, frozenset(allowed))
        if edge is None:
            return False
        edges.append(edge)
    if len({edge[1] for edge in edges}) < 2 or len({edge[2] for edge in edges}) != 1:
        return False
    kind = {by_pc[edge[1]].mnemonic for edge in edges}
    if len(kind) != 1:
        return False
    release = allowed.get(next(iter(kind)))
    if release is None:
        return False
    owned = [edge for edge in edges if edge[1] == entry and edge[0] in attempt]
    if len(owned) != 1 or owned[0][0] - 4 not in attempt or owned[0][2] != edges[0][2]:
        return False
    body = set(attempt) - {mov_pc, clrex_pc}
    if entry not in body:
        return False
    return dead_tbnz_fallthrough_leaves(by_pc, tbnz_pc, body, owned[0][2], api, release)


def shared_compare_fail_native_tbz_exit(by_pc, clrex_pc, attempt, entry, entries, api):
    """Closed native X-load failures share zero/MOV; CLREX; TBZ-to-return.

    This proof is only used for attempts that require no rewriting. All nine
    source predecessors (or their structurally equivalent peers) must be
    adjacent X-form LDXR/LDAXR, CMP, B.NE triples for the same address and
    loaded register. No root or other static predecessor may enter the
    shared trio. The taken zero-bit path stores that loaded X value away
    from the exclusive cell, then follows a straight stack epilogue to RET.
    No relocation frame can be inserted before the original CLREX.
    """
    mov_pc, test_pc = clrex_pc - 4, clrex_pc + 4
    trio = {mov_pc, clrex_pc, test_pc}
    mov, clrex, test = (by_pc.get(pc) for pc in (mov_pc, clrex_pc, test_pc))
    if (any(ins is None or ins.address != pc or len(ins.bytes) != 4
            for ins, pc in ((mov, mov_pc), (clrex, clrex_pc), (test, test_pc))) or
            clrex.mnemonic != 'clrex' or test.mnemonic != 'tbz' or
            entry not in attempt or not {mov_pc, clrex_pc} <= set(attempt) or
            set(entries) & trio):
        return False
    mov_word, test_word = (struct.unpack('<I', ins.bytes)[0] for ins in (mov, test))
    if (mov_word & 0xFFFFFFE0 != 0x2A1F03E0 or
            test_word & 0xFFF80000 != 0x36000000 or
            mov_word & 31 != test_word & 31 or mov_word & 31 in {18, 29, 30, 31}):
        return False
    predecessors = direct_predecessors(by_pc, mov_pc)
    clrex_predecessors = direct_predecessors(by_pc, clrex_pc)
    test_predecessors = direct_predecessors(by_pc, test_pc)
    if (predecessors is None or clrex_predecessors is None or test_predecessors is None or
            len(predecessors) < 2 or
            {ins.address for ins in clrex_predecessors} != {mov_pc} or
            {ins.address for ins in test_predecessors} != {clrex_pc}):
        return False
    edges = []
    for predecessor in predecessors:
        edge = compare_fail_edge(by_pc, predecessor.address, mov_pc, api,
                                 frozenset({'ldaxr', 'ldxr'}))
        if edge is None:
            return False
        load = by_pc[edge[1]]
        if not load.reg_name(load.operands[0].reg).startswith('x'):
            return False
        edges.append(edge)
    if (len({edge[1] for edge in edges}) < 2 or
            len({(edge[2], edge[3]) for edge in edges}) != 1):
        return False
    owned = [edge for edge in edges if edge[1] == entry and edge[0] in attempt]
    if len(owned) != 1 or owned[0][0] - 4 not in attempt:
        return False
    target = test.operands[-1].imm
    blocked = set(attempt) | trio
    zero, store = by_pc.get(target), by_pc.get(target + 4)
    if (zero is None or store is None or target in blocked or target + 4 in blocked or
            zero.address != target or store.address != target + 4 or
            struct.unpack('<I', zero.bytes)[0] != 0x2A1F03E0 or
            store.mnemonic != 'str' or len(store.operands) != 2 or store.writeback):
        return False
    value, memory = store.operands
    if (value.type != ARM64_OP_REG or memory.type != ARM64_OP_MEM or
            not store.reg_name(value.reg).startswith('x') or
            register_number(store, value.reg) != owned[0][3] or memory.mem.index or memory.mem.disp or
            memory_base(store) in {None, owned[0][2]}):
        return False
    return plain_function_epilogue(by_pc, target + 8, blocked, api)


def native_five_peer_byte_closure(start, by_pc, kinds, api):
    """One closed native byte-CAS family, with five fully owned attempts.

    Ownership includes all LOAD/CMP/B.NE/STORE/status words and the shared
    zeroing MOV plus CLREX. Continuations are only retirement witnesses, never
    a reason to remove shared nodes. The exact family has one plain/plain,
    one plain/release and three acquire/release peers. Peer order and scratch
    registers may change; no source address is an authority.
    """
    if start.mnemonic not in {'ldxrb', 'ldaxrb'}:
        return None
    branch = by_pc.get(start.address + 8)
    if (branch is None or branch.mnemonic != 'b.ne' or not branch.operands or
            branch.operands[-1].type != ARM64_OP_IMM):
        return None
    mov_pc = branch.operands[-1].imm
    mov, clear, test = (by_pc.get(mov_pc + offset) for offset in (0, 4, 8))
    if mov is None or clear is None or test is None:
        return None
    predecessors = direct_predecessors(by_pc, mov_pc)
    if predecessors is None:
        return None
    # Claim this family before exact validation. A damaged five-peer source
    # must not fall back to the older, smaller shared-exit recognizers.
    shared_anchor = clear.mnemonic == 'clrex' and test.mnemonic == 'tbnz'
    if len(predecessors) < 5 and (start.mnemonic != 'ldxrb' or not shared_anchor):
        return None

    def refuse(reason):
        raise api.RewriteError(f'0x{start.address:x}: invalid native five-peer byte closure: {reason}')

    if clear.mnemonic != 'clrex' or test.mnemonic != 'tbnz':
        refuse('shared CLREX and TBNZ must both match')

    def word(pc):
        ins = by_pc.get(pc)
        if ins is None or ins.address != pc or len(ins.bytes) != 4:
            refuse('missing source instruction')
        return struct.unpack('<I', ins.bytes)[0]

    if len(predecessors) != 5 or any(ins.mnemonic != 'b.ne' for ins in predecessors):
        refuse('exactly five compare-fail predecessors required')
    heads = {ins.address - 8 for ins in predecessors}
    if len(heads) != 5:
        refuse('peer heads must be distinct')
    if start.address != min(heads):
        return None
    nodes = {pc for head in heads for pc in range(head, head + 20, 4)} | {mov_pc, mov_pc + 4}
    if len(nodes) != 27:
        refuse('overlapping peer ownership')
    first = min(heads)
    loaded, cell = word(first) & 31, word(first) >> 5 & 31
    expected = word(first + 4) >> 16 & 31
    desired, status = word(first + 12) & 31, word(first + 12) >> 16 & 31
    roles = (loaded, expected, desired, status, cell)
    if (len(set(roles)) != 5 or
            any(reg not in range(1, 18) for reg in roles[:4]) or
            cell not in {19, 20, 24, 25, 26, 27, 28}):
        refuse('unsupported or overlapping register roles')
    families, leave_branches = [], set()
    success_pc = None
    for head in sorted(heads):
        load = by_pc.get(head)
        store = by_pc.get(head + 12)
        if load is None or store is None:
            refuse('missing peer')
        family = (load.mnemonic, store.mnemonic)
        families.append(family)
        load_base = {'ldxrb': 0x085F7C00, 'ldaxrb': 0x085FFC00}.get(load.mnemonic)
        store_base = {'stxrb': 0x08007C00, 'stlxrb': 0x0800FC00}.get(store.mnemonic)
        bne = 0x54000001 | (((mov_pc - head - 8) // 4) & 0x7FFFF) << 5
        retry = 0x35000000 | (((head - head - 16) // 4) & 0x7FFFF) << 5 | status
        if (load_base is None or store_base is None or
                tuple(word(head + offset) for offset in (0, 4, 8, 12, 16)) != (
                    load_base | cell << 5 | loaded,
                    0x6B00001F | expected << 16 | loaded << 5, bne,
                    store_base | status << 16 | cell << 5 | desired, retry)):
            refuse('peer width, operands, ordering or retry differs')
        end = by_pc.get(head + 20)
        if end is None:
            refuse('missing successful-store continuation')
        if end.mnemonic == 'b' and len(end.operands) == 1 and end.operands[0].type == ARM64_OP_IMM:
            target = end.operands[0].imm
            if word(head + 20) != api.branch(head + 20, target):
                refuse('noncanonical success branch')
            leave_branches.add(head + 20)
        else:
            target = head + 20
        if success_pc is None:
            success_pc = target
        if target != success_pc or head + 20 in nodes:
            refuse('successful status must leave the complete closure')
        validate_exclusive(load, api)
        validate_exclusive(store, api)
        validate_memory_operands(load, api)
        validate_memory_operands(store, api)
    if sorted(families) != sorted([('ldxrb', 'stxrb'), ('ldxrb', 'stlxrb')] + [('ldaxrb', 'stlxrb')] * 3):
        refuse('requires two plain and three acquire byte loads with exact store orderings')
    if len(leave_branches) != 4 or sum(head + 20 == success_pc for head in heads) != 1:
        refuse('requires four success branches and one adjacent status-zero fallthrough')
    if any(kinds.get(pc, 'missing') is not None for pc in nodes):
        refuse('all owned kinds must be explicitly native')
    if (word(mov_pc) != 0x2A1F03E0 | desired or word(mov_pc + 4) != 0xD5033F5F or
            word(success_pc) != 0x52800020 | desired):
        refuse('failure-zero or success-one carrier differs')
    success_test, failure_test = by_pc.get(success_pc + 4), by_pc.get(mov_pc + 8)
    if (success_test is None or failure_test is None or
            success_test.mnemonic != 'tbz' or failure_test.mnemonic != 'tbnz'):
        refuse('carrier bit tests differ')
    publish, leave = mov_pc + 12, failure_test.operands[-1].imm
    if (word(success_pc + 4) != 0x36000000 | (((publish - success_pc - 4) // 4) & 0x3FFF) << 5 | desired or
            word(mov_pc + 8) != 0x37000000 | (((leave - mov_pc - 8) // 4) & 0x3FFF) << 5 | desired or
            word(success_pc + 8) != api.branch(success_pc + 8, leave) or
            word(publish) != 0x2A1F03E0):
        refuse('dead carrier path or failure return value differs')
    output = by_pc.get(publish + 4)
    out = memory_base(output) if output is not None else None
    if (out not in {19, 20, 24, 25, 26, 27, 28} or out == cell or
            word(publish + 4) != 0x39000000 | out << 5 | loaded):
        refuse('failure must publish the loaded byte through a distinct address role')
    # Distinct register roles do not assert that their runtime pointer values
    # cannot alias. Every instruction below executes after hardware retirement.
    def epilogue(pc):
        # LDP cell,out,[SP,#32]; LDP X22,X21,[SP,#16];
        # LDP LR,X23,[SP],#48; RET. Pin every restore and SP update.
        return tuple(word(pc + offset) for offset in (0, 4, 8, 12)) == (
            0xA9400000 | 4 << 15 | out << 10 | 31 << 5 | cell,
            0xA9400000 | 2 << 15 | 21 << 10 | 31 << 5 | 22,
            0xA8C00000 | 6 << 15 | 23 << 10 | 31 << 5 | 30,
            0xD65F03C0)
    if (word(leave) != 0x52800020 or not epilogue(publish + 8) or not epilogue(leave + 4)):
        refuse('exact return epilogue required')
    witness = (leave_branches | set(range(success_pc, success_pc + 12, 4)) |
               set(range(mov_pc + 8, publish + 24, 4)) | set(range(leave, leave + 20, 4)))
    if nodes & witness or len(witness) != len(leave_branches) + 3 + 7 + 5:
        refuse('witness overlaps owned instructions or another witness')
    # The status-zero edge is only the CBNZ fallthrough after a completed store.
    # Success MOV-one/TBZ and failure MOV-zero/CLREX/TBNZ cannot be entered
    # midway. The common success epilogue can be a terminal entry for other
    # families; this proof claims retirement only for paths from C. Its
    # interior restores cannot have alien entries.
    allowed_predecessors = {
        mov_pc: {head + 8 for head in heads}, mov_pc + 4: {mov_pc}, mov_pc + 8: {mov_pc + 4},
        success_pc: leave_branches | {head + 16 for head in heads if head + 20 == success_pc},
        success_pc + 4: {success_pc}, success_pc + 8: {success_pc + 4},
        publish: {mov_pc + 8, success_pc + 4},
    }
    for target in leave_branches:
        allowed_predecessors[target] = {target - 4}
    for target in range(publish + 4, publish + 24, 4):
        allowed_predecessors[target] = {target - 4}
    for target in range(leave + 4, leave + 20, 4):
        allowed_predecessors[target] = {target - 4}
    incoming = {target: set() for target in allowed_predecessors}
    for ins in by_pc.values():
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
            refuse('unknown predecessor authority')
        for target in targets:
            if target in incoming:
                incoming[target].add(ins.address)
    for target, permitted in allowed_predecessors.items():
        if incoming[target] != permitted:
            refuse('alien direct entry or fallthrough into carrier/retirement witness')
    for pc in witness:
        ins = by_pc[pc]
        permitted_kind = {'stack_check', None} if ins.mnemonic == 'ldp' else {None}
        if kinds.get(pc, 'missing') not in permitted_kind or api.is_fatal_instruction(ins):
            refuse('unknown or host-backed witness instruction')
    return nodes, heads, witness


def native_five_peer_halfword_closure(start, by_pc, kinds, api):
    """One closed native halfword-CAS family, with five fully owned attempts.

    Ownership includes all LOAD/CMP/B.NE/STORE/status words and the shared
    zeroing MOV plus CLREX. Continuations are only retirement witnesses, never
    a reason to remove shared nodes. The exact family has one plain/plain,
    one plain/release and three acquire/release peers. Peer order and scratch
    registers may change; no source address is an authority.
    """
    if start.mnemonic not in {'ldxrh', 'ldaxrh'}:
        return None
    branch = by_pc.get(start.address + 8)
    if (branch is None or branch.mnemonic != 'b.ne' or not branch.operands or
            branch.operands[-1].type != ARM64_OP_IMM):
        return None
    mov_pc = branch.operands[-1].imm
    mov, clear, test = (by_pc.get(mov_pc + offset) for offset in (0, 4, 8))
    if mov is None or clear is None or test is None:
        return None
    predecessors = direct_predecessors(by_pc, mov_pc)
    if predecessors is None:
        return None
    # Claim this family before exact validation. A damaged five-peer source
    # must not fall back to the older, smaller shared-exit recognizers.
    shared_anchor = clear.mnemonic == 'clrex' and test.mnemonic == 'tbnz'
    if len(predecessors) < 5 and (start.mnemonic != 'ldxrh' or not shared_anchor):
        return None

    def refuse(reason):
        raise api.RewriteError(f'0x{start.address:x}: invalid native five-peer halfword closure: {reason}')

    if clear.mnemonic != 'clrex' or test.mnemonic != 'tbnz':
        refuse('shared CLREX and TBNZ must both match')

    def word(pc):
        ins = by_pc.get(pc)
        if ins is None or ins.address != pc or len(ins.bytes) != 4:
            refuse('missing source instruction')
        return struct.unpack('<I', ins.bytes)[0]

    if len(predecessors) != 5 or any(ins.mnemonic != 'b.ne' for ins in predecessors):
        refuse('exactly five compare-fail predecessors required')
    heads = {ins.address - 8 for ins in predecessors}
    if len(heads) != 5:
        refuse('peer heads must be distinct')
    if start.address != min(heads):
        return None
    nodes = {pc for head in heads for pc in range(head, head + 20, 4)} | {mov_pc, mov_pc + 4}
    if len(nodes) != 27:
        refuse('overlapping peer ownership')
    first = min(heads)
    loaded, cell = word(first) & 31, word(first) >> 5 & 31
    expected = word(first + 4) >> 16 & 31
    desired, status = word(first + 12) & 31, word(first + 12) >> 16 & 31
    roles = (loaded, expected, desired, status, cell)
    if (len(set(roles)) != 5 or
            any(reg not in range(1, 18) for reg in roles[:4]) or
            cell not in {19, 20, 24, 25, 26, 27, 28}):
        refuse('unsupported or overlapping register roles')
    families, leave_branches = [], set()
    success_pc = None
    for head in sorted(heads):
        load = by_pc.get(head)
        store = by_pc.get(head + 12)
        if load is None or store is None:
            refuse('missing peer')
        family = (load.mnemonic, store.mnemonic)
        families.append(family)
        load_base = {'ldxrh': 0x485F7C00, 'ldaxrh': 0x485FFC00}.get(load.mnemonic)
        store_base = {'stxrh': 0x48007C00, 'stlxrh': 0x4800FC00}.get(store.mnemonic)
        bne = 0x54000001 | (((mov_pc - head - 8) // 4) & 0x7FFFF) << 5
        retry = 0x35000000 | (((head - head - 16) // 4) & 0x7FFFF) << 5 | status
        if (load_base is None or store_base is None or
                tuple(word(head + offset) for offset in (0, 4, 8, 12, 16)) != (
                    load_base | cell << 5 | loaded,
                    0x6B00001F | expected << 16 | loaded << 5, bne,
                    store_base | status << 16 | cell << 5 | desired, retry)):
            refuse('peer width, operands, ordering or retry differs')
        end = by_pc.get(head + 20)
        if end is None:
            refuse('missing successful-store continuation')
        if end.mnemonic == 'b' and len(end.operands) == 1 and end.operands[0].type == ARM64_OP_IMM:
            target = end.operands[0].imm
            if word(head + 20) != api.branch(head + 20, target):
                refuse('noncanonical success branch')
            leave_branches.add(head + 20)
        else:
            target = head + 20
        if success_pc is None:
            success_pc = target
        if target != success_pc or head + 20 in nodes:
            refuse('successful status must leave the complete closure')
        validate_exclusive(load, api)
        validate_exclusive(store, api)
        validate_memory_operands(load, api)
        validate_memory_operands(store, api)
    if sorted(families) != sorted([('ldxrh', 'stxrh'), ('ldxrh', 'stlxrh')] + [('ldaxrh', 'stlxrh')] * 3):
        refuse('requires two plain and three acquire halfword loads with exact store orderings')
    if len(leave_branches) != 4 or sum(head + 20 == success_pc for head in heads) != 1:
        refuse('requires four success branches and one adjacent status-zero fallthrough')
    if any(kinds.get(pc, 'missing') is not None for pc in nodes):
        refuse('all owned kinds must be explicitly native')
    if (word(mov_pc) != 0x2A1F03E0 | desired or word(mov_pc + 4) != 0xD5033F5F or
            word(success_pc) != 0x52800020 | desired):
        refuse('failure-zero or success-one carrier differs')
    success_test, failure_test = by_pc.get(success_pc + 4), by_pc.get(mov_pc + 8)
    def carrier_test(ins):
        return (ins is not None and ins.mnemonic == 'tbnz' and len(ins.operands) == 3 and
                ins.operands[0].type == ARM64_OP_REG and ins.reg_name(ins.operands[0].reg) == f'w{desired}' and
                ins.operands[1].type == ARM64_OP_IMM and ins.operands[1].imm == 0 and
                ins.operands[2].type == ARM64_OP_IMM)
    if not carrier_test(success_test) or not carrier_test(failure_test):
        refuse('exact W-carrier bit-zero test operand shape required')
    publish, leave = mov_pc + 12, failure_test.operands[2].imm
    # An imm14 re-encoding alone aliases destinations separated by 64KiB.
    # Compare the independently decoded targets before matching encoded bits.
    if (success_test.operands[2].imm != leave or
            successors(success_test) != (success_pc + 8, leave) or
            successors(failure_test) != (mov_pc + 12, leave)):
        refuse('decoded carrier tests must share the exact common return target')
    if (word(success_pc + 4) != 0x37000000 | (((leave - success_pc - 4) // 4) & 0x3FFF) << 5 | desired or
            word(mov_pc + 8) != 0x37000000 | (((leave - mov_pc - 8) // 4) & 0x3FFF) << 5 | desired or
            word(success_pc + 8) != api.branch(success_pc + 8, publish) or
            word(publish) != 0x2A1F03E0):
        refuse('dead carrier path or failure return value differs')
    output = by_pc.get(publish + 4)
    out = memory_base(output) if output is not None else None
    if (out not in {19, 20, 24, 25, 26, 27, 28} or out in set(roles) or
            word(publish + 4) != 0x79000000 | out << 5 | loaded):
        refuse('failure must publish the loaded halfword through a distinct address role')
    # Distinct register roles do not assert that their runtime pointer values
    # cannot alias. Every instruction below executes after hardware retirement.
    def epilogue(pc):
        # LDP cell,out,[SP,#32]; LDP X22,X21,[SP,#16];
        # LDP LR,X23,[SP],#48; RET. Pin every restore and SP update.
        return tuple(word(pc + offset) for offset in (0, 4, 8, 12)) == (
            0xA9400000 | 4 << 15 | out << 10 | 31 << 5 | cell,
            0xA9400000 | 2 << 15 | 21 << 10 | 31 << 5 | 22,
            0xA8C00000 | 6 << 15 | 23 << 10 | 31 << 5 | 30,
            0xD65F03C0)
    if (word(leave) != 0x52800020 or not epilogue(publish + 8) or not epilogue(leave + 4)):
        refuse('exact return epilogue required')
    witness = (leave_branches | set(range(success_pc, success_pc + 12, 4)) |
               set(range(mov_pc + 8, publish + 24, 4)) | set(range(leave, leave + 20, 4)))
    if nodes & witness or len(witness) != len(leave_branches) + 3 + 7 + 5:
        refuse('witness overlaps owned instructions or another witness')
    # The success TBNZ is always taken after MOV-one; its B-to-publication
    # fallthrough remains an exact protected static witness. Failure TBNZ
    # is never taken after MOV-zero, but its common-return edge is checked.
    # The status-zero edge is only the CBNZ fallthrough after a completed store.
    # Success MOV-one/TBNZ and failure MOV-zero/CLREX/TBNZ cannot be entered
    # midway. The common success epilogue can be a terminal entry for other
    # families; this proof claims retirement only for paths from C. Its
    # interior restores cannot have alien entries.
    allowed_predecessors = {
        mov_pc: {head + 8 for head in heads}, mov_pc + 4: {mov_pc}, mov_pc + 8: {mov_pc + 4},
        success_pc: leave_branches | {head + 16 for head in heads if head + 20 == success_pc},
        success_pc + 4: {success_pc}, success_pc + 8: {success_pc + 4},
        publish: {mov_pc + 8, success_pc + 8},
    }
    for target in leave_branches:
        allowed_predecessors[target] = {target - 4}
    for target in range(publish + 4, publish + 24, 4):
        allowed_predecessors[target] = {target - 4}
    for target in range(leave + 4, leave + 20, 4):
        allowed_predecessors[target] = {target - 4}
    incoming = {target: set() for target in allowed_predecessors}
    for ins in by_pc.values():
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
            refuse('unknown predecessor authority')
        for target in targets:
            if target in incoming:
                incoming[target].add(ins.address)
    for target, permitted in allowed_predecessors.items():
        if incoming[target] != permitted:
            refuse('alien direct entry or fallthrough into carrier/retirement witness')
    for pc in witness:
        ins = by_pc[pc]
        permitted_kind = {'stack_check', None} if ins.mnemonic == 'ldp' else {None}
        if kinds.get(pc, 'missing') not in permitted_kind or api.is_fatal_instruction(ins):
            refuse('unknown or host-backed witness instruction')
    return nodes, heads, witness


def native_five_peer_word_closure(start, by_pc, kinds, api):
    """One closed native word-CAS family, with five fully owned attempts.

    Ownership includes all LOAD/CMP/B.NE/STORE/status words and the shared
    zeroing MOV plus CLREX. Continuations are only retirement witnesses, never
    a reason to remove shared nodes. The exact family has one plain/plain,
    one plain/release and three acquire/release peers. Peer order and scratch
    registers may change; no source address is an authority.
    """
    # LDXR/LDAXR share mnemonics with X-form; do not claim that family.
    if (start.mnemonic not in {'ldxr', 'ldaxr'} or not start.operands or
            start.operands[0].type != ARM64_OP_REG or
            not start.reg_name(start.operands[0].reg).startswith('w')):
        return None
    branch = by_pc.get(start.address + 8)
    if (branch is None or branch.mnemonic != 'b.ne' or not branch.operands or
            branch.operands[-1].type != ARM64_OP_IMM):
        return None
    mov_pc = branch.operands[-1].imm
    mov, clear, test = (by_pc.get(mov_pc + offset) for offset in (0, 4, 8))
    if mov is None or clear is None or test is None:
        return None
    predecessors = direct_predecessors(by_pc, mov_pc)
    if predecessors is None:
        return None
    # Claim this family before exact validation. A damaged five-peer source
    # must not fall back to the older, smaller shared-exit recognizers.
    shared_anchor = clear.mnemonic == 'clrex' and test.mnemonic == 'tbnz'
    # A damaged peer may remove one B.NE predecessor while the first peer
    # is acquire. Any remaining plain W peer still claims this mixed family;
    # the smaller all-acquire recognizers must not mask that damaged closure.
    plain_peer = any(
        (load := by_pc.get(pred.address - 8)) is not None and load.mnemonic == 'ldxr' and
        load.operands and load.operands[0].type == ARM64_OP_REG and
        load.reg_name(load.operands[0].reg).startswith('w')
        for pred in predecessors)
    if not shared_anchor or not plain_peer or len(predecessors) < 4:
        return None

    def refuse(reason):
        raise api.RewriteError(f'0x{start.address:x}: invalid native five-peer word closure: {reason}')

    if clear.mnemonic != 'clrex' or test.mnemonic != 'tbnz':
        refuse('shared CLREX and TBNZ must both match')

    def word(pc):
        ins = by_pc.get(pc)
        if ins is None or ins.address != pc or len(ins.bytes) != 4:
            refuse('missing source instruction')
        return struct.unpack('<I', ins.bytes)[0]

    def direct(ins, mnemonic, target, register=None):
        # Decoded target authority is independent of modulo immediate bits.
        count = 1 if register is None else 2
        if ins is None or ins.mnemonic != mnemonic or len(ins.operands) != count:
            return False
        if register is not None and (ins.operands[0].type != ARM64_OP_REG or
                ins.reg_name(ins.operands[0].reg) != f'w{register}'):
            return False
        if ins.operands[-1].type != ARM64_OP_IMM or ins.operands[-1].imm != target:
            return False
        expected = (target,) if mnemonic == 'b' else (ins.address + 4, target)
        return successors(ins) == expected

    def damaged_fifth_peer():
        # Four ordinary peers are not a five-peer family. Reject only when a
        # fifth complete same-role attempt is independently witnessed through
        # the common status-zero continuation, with its encoded B.NE still
        # targeting MOV but its decoded target contradicting those bytes.
        if any(pred.mnemonic != 'b.ne' for pred in predecessors):
            return False
        good_heads = {pred.address - 8 for pred in predecessors}
        if len(good_heads) != 4:
            return False

        def raw(pc):
            ins = by_pc.get(pc)
            if ins is None or ins.address != pc or len(ins.bytes) != 4:
                return None
            return struct.unpack('<I', ins.bytes)[0]

        first = min(good_heads)
        load_word, cmp_word, store_word = (raw(first + off) for off in (0, 4, 12))
        if None in (load_word, cmp_word, store_word):
            return False
        loaded, cell = load_word & 31, load_word >> 5 & 31
        expected = cmp_word >> 16 & 31
        desired, status = store_word & 31, store_word >> 16 & 31
        roles = loaded, expected, desired, status, cell
        if (len(set(roles)) != 5 or any(reg not in range(1, 18) for reg in roles[:4]) or
                cell not in {19, 20, 24, 25, 26, 27, 28}):
            return False

        def attempt(head, damaged=False):
            load, store, compare_branch, retry = (by_pc.get(head + off) for off in (0, 12, 8, 16))
            if any(ins is None for ins in (load, store, compare_branch, retry)):
                return None
            load_base = {'ldxr': 0x885F7C00, 'ldaxr': 0x885FFC00}.get(load.mnemonic)
            store_base = {'stxr': 0x88007C00, 'stlxr': 0x8800FC00}.get(store.mnemonic)
            delta = mov_pc - head - 8
            if load_base is None or store_base is None or delta % 4 or not -(1 << 20) <= delta < (1 << 20):
                return None
            bne = 0x54000001 | ((delta // 4) & 0x7FFFF) << 5
            cbnz = 0x35000000 | ((-4) & 0x7FFFF) << 5 | status
            if tuple(raw(head + off) for off in (0, 4, 8, 12, 16)) != (
                    load_base | cell << 5 | loaded,
                    0x6B00001F | expected << 16 | loaded << 5, bne,
                    store_base | status << 16 | cell << 5 | desired, cbnz):
                return None
            if not direct(retry, 'cbnz', head, status):
                return None
            if damaged:
                if (compare_branch.mnemonic != 'b.ne' or len(compare_branch.operands) != 1 or
                        compare_branch.operands[0].type != ARM64_OP_IMM or
                        compare_branch.operands[0].imm == mov_pc or
                        successors(compare_branch) != (head + 12, compare_branch.operands[0].imm)):
                    return None
            elif not direct(compare_branch, 'b.ne', mov_pc):
                return None
            end = by_pc.get(head + 20)
            if end is None:
                return None
            if end.mnemonic == 'b' and len(end.operands) == 1 and end.operands[0].type == ARM64_OP_IMM:
                target = end.operands[0].imm
                distance = target - head - 20
                if (distance % 4 or not -(1 << 27) <= distance < (1 << 27) or
                        not direct(end, 'b', target) or raw(head + 20) != api.branch(head + 20, target)):
                    return None
            else:
                target = head + 20
            if raw(target) != 0x52800020 | desired:
                return None
            return (load.mnemonic, store.mnemonic), target

        good = [attempt(head) for head in sorted(good_heads)]
        if any(row is None for row in good) or len({row[1] for row in good}) != 1:
            return False
        success_pc = good[0][1]
        incoming_success = direct_predecessors(by_pc, success_pc)
        if incoming_success is None:
            return False
        candidates = set()
        for pred in incoming_success:
            if pred.mnemonic == 'b':
                candidates.add(pred.address - 20)
            elif pred.mnemonic == 'cbnz' and pred.address + 4 == success_pc:
                candidates.add(pred.address - 16)
        found = []
        for head in candidates - good_heads:
            fifth = attempt(head, damaged=True)
            heads = good_heads | {head}
            owned = {pc for entry in heads for pc in range(entry, entry + 20, 4)}
            families = [row[0] for row in good] + ([fifth[0]] if fifth is not None else [])
            if (fifth is not None and fifth[1] == success_pc and len(owned) == 25 and
                    not owned & {mov_pc, mov_pc + 4, success_pc} and
                    sorted(families) == sorted([('ldxr', 'stxr'), ('ldxr', 'stlxr')] + [('ldaxr', 'stlxr')] * 3)):
                found.append(head)
        return len(found) == 1

    if len(predecessors) == 4:
        if damaged_fifth_peer():
            refuse('decoded fifth-peer compare-fail target contradicts its complete source witness')
        return None

    if len(predecessors) != 5 or any(ins.mnemonic != 'b.ne' for ins in predecessors):
        refuse('exactly five compare-fail predecessors required')
    heads = {ins.address - 8 for ins in predecessors}
    if len(heads) != 5:
        refuse('peer heads must be distinct')
    if start.address != min(heads):
        return None
    nodes = {pc for head in heads for pc in range(head, head + 20, 4)} | {mov_pc, mov_pc + 4}
    if len(nodes) != 27:
        refuse('overlapping peer ownership')
    first = min(heads)
    loaded, cell = word(first) & 31, word(first) >> 5 & 31
    expected = word(first + 4) >> 16 & 31
    desired, status = word(first + 12) & 31, word(first + 12) >> 16 & 31
    roles = (loaded, expected, desired, status, cell)
    if (len(set(roles)) != 5 or
            any(reg not in range(1, 18) for reg in roles[:4]) or
            cell not in {19, 20, 24, 25, 26, 27, 28}):
        refuse('unsupported or overlapping register roles')
    families, leave_branches = [], set()
    success_pc = None
    for head in sorted(heads):
        load = by_pc.get(head)
        store = by_pc.get(head + 12)
        if load is None or store is None:
            refuse('missing peer')
        if (not direct(by_pc.get(head + 8), 'b.ne', mov_pc) or
                not direct(by_pc.get(head + 16), 'cbnz', head, status)):
            refuse('decoded compare-fail/status branch target or operand shape differs')
        family = (load.mnemonic, store.mnemonic)
        families.append(family)
        load_base = {'ldxr': 0x885F7C00, 'ldaxr': 0x885FFC00}.get(load.mnemonic)
        store_base = {'stxr': 0x88007C00, 'stlxr': 0x8800FC00}.get(store.mnemonic)
        bne = 0x54000001 | (((mov_pc - head - 8) // 4) & 0x7FFFF) << 5
        retry = 0x35000000 | (((head - head - 16) // 4) & 0x7FFFF) << 5 | status
        if (load_base is None or store_base is None or
                tuple(word(head + offset) for offset in (0, 4, 8, 12, 16)) != (
                    load_base | cell << 5 | loaded,
                    0x6B00001F | expected << 16 | loaded << 5, bne,
                    store_base | status << 16 | cell << 5 | desired, retry)):
            refuse('peer width, operands, ordering or retry differs')
        end = by_pc.get(head + 20)
        if end is None:
            refuse('missing successful-store continuation')
        if end.mnemonic == 'b' and len(end.operands) == 1 and end.operands[0].type == ARM64_OP_IMM:
            target = end.operands[0].imm
            if not direct(end, 'b', target) or word(head + 20) != api.branch(head + 20, target):
                refuse('noncanonical success branch')
            leave_branches.add(head + 20)
        else:
            target = head + 20
        if success_pc is None:
            success_pc = target
        if target != success_pc or head + 20 in nodes:
            refuse('successful status must leave the complete closure')
        validate_exclusive(load, api)
        validate_exclusive(store, api)
        validate_memory_operands(load, api)
        validate_memory_operands(store, api)
    if sorted(families) != sorted([('ldxr', 'stxr'), ('ldxr', 'stlxr')] + [('ldaxr', 'stlxr')] * 3):
        refuse('requires two plain and three acquire word loads with exact store orderings')
    if len(leave_branches) != 4 or sum(head + 20 == success_pc for head in heads) != 1:
        refuse('requires four success branches and one adjacent status-zero fallthrough')
    if any(kinds.get(pc, 'missing') is not None for pc in nodes):
        refuse('all owned kinds must be explicitly native')
    if (word(mov_pc) != 0x2A1F03E0 | desired or word(mov_pc + 4) != 0xD5033F5F or
            word(success_pc) != 0x52800020 | desired):
        refuse('failure-zero or success-one carrier differs')
    success_test, failure_test = by_pc.get(success_pc + 4), by_pc.get(mov_pc + 8)
    def carrier_test(ins):
        return (ins is not None and ins.mnemonic == 'tbnz' and len(ins.operands) == 3 and
                ins.operands[0].type == ARM64_OP_REG and ins.reg_name(ins.operands[0].reg) == f'w{desired}' and
                ins.operands[1].type == ARM64_OP_IMM and ins.operands[1].imm == 0 and
                ins.operands[2].type == ARM64_OP_IMM)
    if not carrier_test(success_test) or not carrier_test(failure_test):
        refuse('exact W-carrier bit-zero test operand shape required')
    publish, leave = mov_pc + 12, failure_test.operands[2].imm
    # An imm14 re-encoding alone aliases destinations separated by 64KiB.
    # Compare the independently decoded targets before matching encoded bits.
    if (success_test.operands[2].imm != leave or
            successors(success_test) != (success_pc + 8, leave) or
            successors(failure_test) != (mov_pc + 12, leave)):
        refuse('decoded carrier tests must share the exact common return target')
    if not direct(by_pc.get(success_pc + 8), 'b', publish):
        refuse('decoded dead success branch must target exact publication')
    if (word(success_pc + 4) != 0x37000000 | (((leave - success_pc - 4) // 4) & 0x3FFF) << 5 | desired or
            word(mov_pc + 8) != 0x37000000 | (((leave - mov_pc - 8) // 4) & 0x3FFF) << 5 | desired or
            word(success_pc + 8) != api.branch(success_pc + 8, publish) or
            word(publish) != 0x2A1F03E0):
        refuse('dead carrier path or failure return value differs')
    output = by_pc.get(publish + 4)
    out = memory_base(output) if output is not None else None
    if (out not in {19, 20, 24, 25, 26, 27, 28} or out in set(roles) or
            word(publish + 4) != 0xB9000000 | out << 5 | loaded):
        refuse('failure must publish the loaded word through a distinct address role')
    # Distinct register roles do not assert that their runtime pointer values
    # cannot alias. Every instruction below executes after hardware retirement.
    def epilogue(pc):
        # LDP cell,out,[SP,#32]; LDP X22,X21,[SP,#16];
        # LDP LR,X23,[SP],#48; RET. Pin every restore and SP update.
        return tuple(word(pc + offset) for offset in (0, 4, 8, 12)) == (
            0xA9400000 | 4 << 15 | out << 10 | 31 << 5 | cell,
            0xA9400000 | 2 << 15 | 21 << 10 | 31 << 5 | 22,
            0xA8C00000 | 6 << 15 | 23 << 10 | 31 << 5 | 30,
            0xD65F03C0)
    if (word(leave) != 0x52800020 or not epilogue(publish + 8) or not epilogue(leave + 4)):
        refuse('exact return epilogue required')
    witness = (leave_branches | set(range(success_pc, success_pc + 12, 4)) |
               set(range(mov_pc + 8, publish + 24, 4)) | set(range(leave, leave + 20, 4)))
    if nodes & witness or len(witness) != len(leave_branches) + 3 + 7 + 5:
        refuse('witness overlaps owned instructions or another witness')
    # The success TBNZ is always taken after MOV-one; its B-to-publication
    # fallthrough remains an exact protected static witness. Failure TBNZ
    # is never taken after MOV-zero, but its common-return edge is checked.
    # The status-zero edge is only the CBNZ fallthrough after a completed store.
    # Success MOV-one/TBNZ and failure MOV-zero/CLREX/TBNZ cannot be entered
    # midway. The common success epilogue can be a terminal entry for other
    # families; this proof claims retirement only for paths from C. Its
    # interior restores cannot have alien entries.
    allowed_predecessors = {
        mov_pc: {head + 8 for head in heads}, mov_pc + 4: {mov_pc}, mov_pc + 8: {mov_pc + 4},
        success_pc: leave_branches | {head + 16 for head in heads if head + 20 == success_pc},
        success_pc + 4: {success_pc}, success_pc + 8: {success_pc + 4},
        publish: {mov_pc + 8, success_pc + 8},
    }
    for target in leave_branches:
        allowed_predecessors[target] = {target - 4}
    for target in range(publish + 4, publish + 24, 4):
        allowed_predecessors[target] = {target - 4}
    for target in range(leave + 4, leave + 20, 4):
        allowed_predecessors[target] = {target - 4}
    incoming = {target: set() for target in allowed_predecessors}
    for ins in by_pc.values():
        targets = successors(ins)
        if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
            refuse('unknown predecessor authority')
        for target in targets:
            if target in incoming:
                incoming[target].add(ins.address)
    for target, permitted in allowed_predecessors.items():
        if incoming[target] != permitted:
            refuse('alien direct entry or fallthrough into carrier/retirement witness')
    for pc in witness:
        ins = by_pc[pc]
        permitted_kind = {'stack_check', None} if ins.mnemonic == 'ldp' else {None}
        if kinds.get(pc, 'missing') not in permitted_kind or api.is_fatal_instruction(ins):
            refuse('unknown or host-backed witness instruction')
    return nodes, heads, witness



def native_returning_retire_function(start, by_pc, kinds, entry_offsets, returning_retire_calls, check_single_entry, api):
    import hashlib
    import android_guest_contract as contract

    try:
        contract.pack_returning_retire_table(returning_retire_calls)
    except contract.GuestContractError as error:
        raise api.RewriteError(f'invalid returning-retire records: {error}') from error
    if len(returning_retire_calls) != 2:
        raise api.RewriteError('returning-retire contract requires 2 callsites')
    r0, r1 = returning_retire_calls
    if (
        start.address != r0.exclusive_head
        or r1.exclusive_head != r0.exclusive_head
        or r1.matching_store != r0.matching_store
        or r1.function_start != r0.function_start
        or r1.function_end != r0.function_end
        or r1.fde_offset != r0.fde_offset
        or r1.cie_offset != r0.cie_offset
        or r1.function_sha256 != r0.function_sha256
        or r1.final_independent_roots_sha256 != r0.final_independent_roots_sha256
        or r1.whole_function_ownership_proof_sha256 != r0.whole_function_ownership_proof_sha256
    ):
        raise api.RewriteError(f'0x{start.address:x}: inconsistent returning-retire function records')
    fn_start, fn_end = r0.function_start, r0.function_end
    func_pcs = tuple(range(fn_start, fn_end, 4))
    func_nodes = set(func_pcs)
    if any(pc not in by_pc for pc in func_pcs):
        raise api.RewriteError(f'0x{fn_start:x}: returning-retire function has missing instructions')
    if fn_start not in entry_offsets:
        raise api.RewriteError(f'0x{fn_start:x}: returning-retire function start is not an entry root')
    check_single_entry(func_nodes, fn_start)
    fn_bytes = b''.join(by_pc[pc].bytes for pc in func_pcs)
    if hashlib.sha256(fn_bytes).digest() != r0.function_sha256:
        raise api.RewriteError(f'0x{fn_start:x}: returning-retire function SHA-256 mismatch')

    call_records = {r0.source_callsite: r0, r1.source_callsite: r1}
    for r in (r0, r1):
        ins = by_pc.get(r.source_callsite)
        if (
            ins is None
            or ins.mnemonic != 'bl'
            or struct.unpack('<I', ins.bytes)[0] != r.original_bl_word
            or not ins.operands
            or ins.operands[-1].type != ARM64_OP_IMM
            or ins.operands[-1].imm != r.original_target
            or r.normal_return != r.source_callsite + 4
            or r.normal_return not in func_nodes
        ):
            raise api.RewriteError(f'0x{r.source_callsite:x}: returning-retire callsite mismatch')

    for pc in func_pcs:
        ins = by_pc[pc]
        if api.is_fatal_word(struct.unpack('<I', ins.bytes)[0]):
            raise api.RewriteError(f'0x{pc:x}: fatal word in returning-retire function')
        validate_memory_operands(ins, api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES:
            validate_exclusive(ins, api)

    live_in = {pc: False for pc in func_pcs}
    dead_in = {pc: False for pc in func_pcs}
    seen = set()
    queue = [(fn_start, False)]
    ret_pcs = set()
    while queue:
        pc, live = queue.pop()
        if (pc, live) in seen:
            continue
        if pc not in func_nodes:
            raise api.RewriteError(f'0x{pc:x}: returning-retire control flow escapes function')
        seen.add((pc, live))
        if live:
            live_in[pc] = True
        else:
            dead_in[pc] = True
        ins = by_pc[pc]
        if live:
            if kinds.get(pc) is not None or api.has18(ins):
                raise api.RewriteError(f'0x{pc:x}: host rewrite or x18 access while monitor is LIVE')
            if re.search(r'\bw?sp\b', ins.op_str) or any(
                operand.type == ARM64_OP_MEM and ins.reg_name(operand.mem.base) == 'sp'
                for operand in ins.operands
            ):
                raise api.RewriteError(f'0x{pc:x}: SP access while monitor is LIVE')
            if ins.mnemonic in {
                'brk', 'hlt', 'hvc', 'smc', 'eret', 'drps', 'sys', 'sysl',
                'dc', 'ic', 'tlbi', 'at', 'wfe', 'wfi', 'svc', 'blr', 'br', 'ret'
            }:
                raise api.RewriteError(f'0x{pc:x}: forbidden {ins.mnemonic} while monitor is LIVE')
        if pc == r0.exclusive_head:
            if ins.mnemonic not in api.EXCLUSIVE_LOADS:
                raise api.RewriteError(f'0x{pc:x}: exclusive_head is not an exclusive load')
            queue.append((pc + 4, True))
            continue
        if pc == r0.matching_store:
            if ins.mnemonic not in api.EXCLUSIVE_STORES or not live:
                raise api.RewriteError(f'0x{pc:x}: matching_store reached without LIVE monitor')
            queue.append((pc + 4, False))
            continue
        if ins.mnemonic in api.EXCLUSIVE_LOADS | api.EXCLUSIVE_STORES | {'clrex'}:
            raise api.RewriteError(f'0x{pc:x}: uncontracted exclusive/clrex in returning-retire function')
        if pc in call_records:
            queue.append((call_records[pc].normal_return, False))
            continue
        if ins.mnemonic == 'bl':
            if live:
                raise api.RewriteError(f'0x{pc:x}: unproved BL while monitor is LIVE')
            queue.append((pc + 4, False))
            continue
        if ins.mnemonic == 'ret':
            if live:
                raise api.RewriteError(f'0x{pc:x}: RET while monitor is LIVE')
            ret_pcs.add(pc)
            continue
        if any(ins.group(group) for group in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)) and (
            ins.mnemonic != 'b' and ins.mnemonic not in CONDITIONAL and not ins.mnemonic.startswith('b.')
        ):
            raise api.RewriteError(f'0x{pc:x}: indirect control transfer in returning-retire function')
        for target in successors(ins):
            if target not in func_nodes:
                raise api.RewriteError(f'0x{pc:x}: branch target 0x{target:x} leaves returning-retire function')
            queue.append((target, live))

    if not live_in[r0.matching_store] or dead_in[r0.matching_store]:
        raise api.RewriteError(f'0x{r0.matching_store:x}: matching_store must be exclusively LIVE')
    for call_pc in call_records:
        if not live_in[call_pc]:
            raise api.RewriteError(f'0x{call_pc:x}: returning-retire callsite never reached in LIVE')
    if len(ret_pcs) != 1:
        raise api.RewriteError(f'0x{fn_start:x}: returning-retire function must have a unique RET epilogue')
    ret_pc = next(iter(ret_pcs))
    restore_window = tuple(range(ret_pc - 20, ret_pc, 4))
    if any(
        p not in func_nodes
        or by_pc[p].mnemonic not in {'ldp', 'ldr'}
        or live_in[p]
        or not dead_in[p]
        for p in restore_window
    ) or live_in[ret_pc] or not dead_in[ret_pc]:
        raise api.RewriteError(f'0x{ret_pc:x}: returning-retire epilogue restores not exclusively DEAD')

    live_nodes = {pc for pc in func_pcs if live_in[pc]}
    visiting = set()
    visited_live = set()

    def dfs_live(node):
        visiting.add(node)
        if node not in {r0.matching_store, *call_records}:
            for nxt in successors(by_pc[node]):
                if nxt in live_nodes and nxt != r0.exclusive_head:
                    if nxt in visiting:
                        raise api.RewriteError(f'0x{nxt:x}: cycle while monitor is LIVE')
                    if nxt not in visited_live:
                        dfs_live(nxt)
        visiting.remove(node)
        visited_live.add(node)

    for node in sorted(live_nodes):
        if node not in visited_live:
            dfs_live(node)

    return func_nodes


def plan_regions(instructions, kinds, entry_offsets, api, *, monitor_retiring_calls=frozenset(), native_wait_transfers=None, returning_retire_calls=()):
    if (not isinstance(monitor_retiring_calls,frozenset) or
            any(type(pc) is not int or pc<0 or pc%4 for pc in monitor_retiring_calls)):
        raise api.RewriteError('monitor-retiring call proof must be immutable aligned offsets')
    if returning_retire_calls:
        import android_guest_contract as contract
        try:
            contract.pack_returning_retire_table(returning_retire_calls)
        except contract.GuestContractError as error:
            raise api.RewriteError(f'invalid returning-retire records: {error}') from error
        if len(returning_retire_calls) != 2:
            raise api.RewriteError('returning-retire contract requires 2 callsites')
    by_pc = {ins.address: ins for ins in instructions}
    direct_incoming, entry_index_attempted = None, False

    def check_direct_entry(nodes, interior):
        # This index belongs only to this immutable planning invocation. Normal
        # fallthrough is queried at target - 4, never stored for every source.
        nonlocal direct_incoming, entry_index_attempted
        if not entry_index_attempted:
            entry_index_attempted = True
            try:
                incoming, previous = {}, None
                for ins in instructions:
                    pc = ins.address
                    if (type(pc) is not int or (previous is not None and pc <= previous) or
                            by_pc.get(pc) is not ins):
                        raise ValueError('entry index requires ordered unique source identities')
                    previous = pc
                    targets = successors(ins)
                    if not isinstance(targets, tuple) or any(type(target) is not int for target in targets):
                        raise ValueError('unexpected canonical successor shape')
                    for target in targets:
                        if target != pc + 4:
                            incoming.setdefault(target, []).append(pc)
                direct_incoming = incoming
            except Exception:
                direct_incoming = None
        if direct_incoming is not None:
            try:
                first = None
                for target in interior:
                    for pc in direct_incoming.get(target, ()):
                        if pc not in nodes:
                            first = pc if first is None else min(first, pc)
                            break
                    pc = target - 4
                    ins = by_pc.get(pc)
                    if ins is not None and pc not in nodes and target in successors(ins):
                        first = ins.address if first is None else min(first, ins.address)
            except Exception:
                direct_incoming = None
            else:
                if first is not None:
                    raise api.RewriteError(f'0x{first:x}: external entry into exclusive region interior')
                return
        # Preserve original source ordinal, short-circuiting, and raw failures
        # for an unexpected shape or any context that cannot support the index.
        for ins in instructions:
            if ins.address not in nodes and any(target in interior for target in successors(ins)):
                raise api.RewriteError(f'0x{ins.address:x}: external entry into exclusive region interior')

    def check_single_entry(nodes, entry):
        if (set(entry_offsets) & nodes) - {entry}:
            raise api.RewriteError(f'0x{entry:x}: external entry in exclusive region interior')
        check_direct_entry(nodes, nodes - {entry})

    regions, occupied, consumed = [], set(), set()
    matched_returning_retire = False
    for start in instructions:
        if start.mnemonic not in api.EXCLUSIVE_LOADS or start.address in consumed:
            continue
        if returning_retire_calls and start.address == returning_retire_calls[0].exclusive_head:
            func_nodes = native_returning_retire_function(
                start, by_pc, kinds, entry_offsets, returning_retire_calls, check_single_entry, api
            )
            if occupied & func_nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            occupied.update(func_nodes)
            consumed.add(start.address)
            matched_returning_retire = True
            continue
        closure = (native_five_peer_byte_closure(start, by_pc, kinds, api) or
                   native_five_peer_halfword_closure(start, by_pc, kinds, api) or
                   native_five_peer_word_closure(start, by_pc, kinds, api))
        if closure is not None:
            nodes, heads, witness = closure
            if occupied & nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            if ((set(entry_offsets) & nodes) - heads) or set(entry_offsets) & witness:
                raise api.RewriteError(f'0x{start.address:x}: external entry in native five-peer closure/witness')
            check_direct_entry(nodes, nodes - heads)
            retries = {(head + 16, head) for head in heads}
            exits = {(pc, target) for pc in nodes for target in successors(by_pc[pc]) if target not in nodes}
            terminals = {head + 12 for head in heads} | {pc for pc in nodes if by_pc[pc].mnemonic == 'clrex'}
            if (any(successors(by_pc[head + 12]) != (head + 16,) or
                    successors(by_pc[head + 16]) != (head + 20, head) or head + 20 in nodes
                    for head in heads) or
                    any(by_pc[pc].mnemonic == 'clrex' and pc + 4 in nodes for pc in terminals)):
                raise api.RewriteError(f'0x{start.address:x}: terminal continuation enters native five-peer closure interior')
            require_acyclic(nodes, by_pc, retries, exits, api)
            occupied.update(nodes)
            consumed.update(heads)
            continue
        ticket=(retiring_ticket_attempt(start,by_pc,kinds,api,
                                        monitor_retiring_calls=monitor_retiring_calls) or
                writer_ticket_attempt(start,by_pc,kinds,api,
                                      monitor_retiring_calls=monitor_retiring_calls))
        if ticket is not None:
            nodes={ins.address for ins in ticket.instructions}
            if occupied&nodes:
                raise api.RewriteError(f'0x{ticket.entry:x}: overlapping exclusive windows')
            require_acyclic(nodes,by_pc,ticket.retry_edges,ticket.exit_edges,api)
            require_single_entry(nodes,ticket.entry,instructions,entry_offsets,api)
            occupied.update(nodes);consumed.add(start.address);regions.append(ticket)
            continue
        native_wait=native_wait_mutex(start,by_pc,kinds,api)
        if native_wait is not None:
            nodes,entry,heads=native_wait
            # The producer remains an ordinary rewritten TLS instruction,
            # but it is the only external entry for this native wait proof.
            producer=entry-4;protected=nodes|{producer}
            if occupied&protected:
                raise api.RewriteError(f'0x{producer:x}: overlapping exclusive windows')
            check_single_entry(protected,producer)
            require_native_wait_transfers(instructions,by_pc,kinds,entry_offsets,protected,producer,native_wait_transfers,api)
            occupied.update(protected);consumed.update(heads)
            continue
        native_try=native_try_mutex(start,by_pc,kinds,api)
        if native_try is not None:
            nodes,entry,heads=native_try
            producer=entry-4;protected=nodes|{producer}
            if occupied&protected:
                raise api.RewriteError(f'0x{producer:x}: overlapping exclusive windows')
            check_single_entry(protected,producer)
            require_native_wait_transfers(instructions,by_pc,kinds,entry_offsets,protected,producer,native_wait_transfers,api)
            occupied.update(protected);consumed.update(heads)
            continue
        native_entry=native_compare_retry(start,by_pc,kinds,api)
        if native_entry is not None:
            nodes=set(range(native_entry,native_entry+56,4))
            if occupied&nodes:
                raise api.RewriteError(f'0x{native_entry:x}: overlapping exclusive windows')
            check_single_entry(nodes,native_entry)
            occupied.update(nodes)
            continue
        native_start=native_rotated_lock(start,by_pc,kinds,api)
        if native_start is not None:
            nodes=set(range(native_start,native_start+20,4))
            if occupied&nodes:
                raise api.RewriteError(f'0x{native_start:x}: overlapping exclusive windows')
            check_single_entry(nodes,start.address)
            occupied.update(nodes)
            continue
        shared=native_shared_clear(start,by_pc,kinds,api)
        if shared is not None:
            nodes,heads=shared
            if occupied&nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            if (set(entry_offsets)&nodes)-{min(heads)}:
                raise api.RewriteError(f'0x{start.address:x}: external entry in exclusive region interior')
            interior = nodes-heads
            check_direct_entry(nodes, interior)
            occupied.update(nodes);consumed.update(heads)
            continue
        chain=native_pointer_chain(start,by_pc,kinds,api)
        if chain is not None:
            nodes,entry,heads=chain
            if occupied&nodes:
                raise api.RewriteError(f'0x{entry:x}: overlapping exclusive windows')
            check_single_entry(nodes,entry)
            occupied.update(nodes);consumed.update(heads)
            continue
        conditional=native_conditional_refresh(start,by_pc,kinds,api)
        if conditional is not None:
            nodes,entry,heads=conditional
            if occupied&nodes:
                raise api.RewriteError(f'0x{entry:x}: overlapping exclusive windows')
            check_single_entry(nodes,entry)
            occupied.update(nodes);consumed.update(heads)
            continue
        read_wait=native_read_wait_checked_return(start,by_pc,kinds,api)
        if read_wait is not None:
            nodes,entry=read_wait
            if occupied&nodes:
                raise api.RewriteError(f'0x{entry:x}: overlapping exclusive windows')
            require_single_entry(nodes,entry,instructions,entry_offsets,api)
            occupied.update(nodes);consumed.add(start.address)
            continue
        if native_dual_load_lock(start, by_pc, kinds, api):
            nodes = set(range(start.address, start.address + 28, 4))
            if occupied & nodes:
                raise api.RewriteError(f'0x{start.address:x}: overlapping exclusive windows')
            check_single_entry(nodes,start.address)
            occupied.update(nodes)
            consumed.add(start.address + 12)
            continue
        pointer=native_pointer_refresh(start,by_pc,kinds,api)
        if pointer is not None:
            nodes,entry,heads=pointer
            if occupied&nodes:
                raise api.RewriteError(f'0x{entry:x}: overlapping exclusive windows')
            check_single_entry(nodes,entry)
            occupied.update(nodes);consumed.update(heads)
            continue
        preload=virtual_preload_cas(start,by_pc,kinds,api)
        if preload is None:
            preload=virtual_boolean_preload_cas(start,by_pc,kinds,api)
        if preload is not None:
            nodes={op.address for op in preload.instructions}
            if occupied&nodes:
                raise api.RewriteError(f'0x{preload.entry:x}: overlapping exclusive windows')
            require_acyclic(nodes,by_pc,preload.retry_edges,preload.exit_edges,api)
            check_single_entry(nodes,preload.entry)
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
            if direct_svc1a_ret_call(ins,by_pc,api):
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
            check_single_entry(native_nodes,start.address)
            occupied.update(native_nodes)
            continue
        for pc in terminals:
            if by_pc[pc].mnemonic not in api.EXCLUSIVE_STORES:
                continue
            tail, edges = retry_tail(by_pc, by_pc[pc], start.address, body, api)
            tails.update(tail)
            retries.update(edges)
        # The same-cell reload is this store's retry, so it must not start another window.
        consumed.update(pc for pc in tails if by_pc[pc].mnemonic in api.EXCLUSIVE_LOADS)
        nodes = body | tails
        # A shared compare-fail CLREX is an exit when re-entry is only this load.
        # The same failures may instead target the zeroing MOV immediately before it.
        shared_exits = set()
        for pc in terminals:
            if by_pc[pc].mnemonic != 'clrex':
                continue
            if shared_compare_fail_clrex_exit(by_pc, pc, nodes, start.address, api):
                shared_exits.add(pc)
            elif shared_compare_fail_mov_before_clrex(by_pc, pc, nodes, start.address, api):
                shared_exits.update((pc, pc - 4))
            elif (all(kinds[node] is None for node in nodes) and
                  shared_compare_fail_native_tbz_exit(by_pc, pc, nodes, start.address, entry_offsets, api)):
                shared_exits.update((pc, pc - 4))
        nodes -= shared_exits
        terminals -= shared_exits
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
        check_single_entry(nodes,start.address)
        # Entry/CFG boundaries apply even when the reservation stays in-place.
        # Only actual relocation needs an SP-independent body and spare GPRs.
        if not any(kinds[pc] for pc in nodes):
            continue
        if any(by_pc[pc].mnemonic=='bl' for pc in nodes):
            raise api.RewriteError(f'0x{start.address:x}: monitor-retiring exclusive call is not relocated')
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
    if returning_retire_calls and not matched_returning_retire:
        raise api.RewriteError('returning-retire exclusive head was not matched in plan_regions')
    return tuple(regions)


NATIVE_POINTER_CHAIN_POP_RECOMPUTED_OFFSETS = (
    *range(0,36,4),*range(52,120,4),*range(700,728,4),
)
NATIVE_POINTER_CHAIN_POP_RECOMPUTED_WORDS = (
    0xC85FFD33,0x37000393,0xF940026A,0xB400014A,0x9101010B,
    0xC80CFD6A,0x35FFFF4C,0xB5000413,0x14000016,0xB2400269,
    0x9101010A,0xC85FFD4B,0xEB13017F,0x54000181,0x9101010B,
    0xC80C7D69,0x35FFFF6C,0x91020109,0xC85FFD2A,0xEB13015F,
    0x540012E1,0x9102010A,0xC80B7D5F,0x35FFFF6B,0x17FFFFEB,
    0xD5033F5F,0x91010108,0xD5033F5F,0xC85F7D09,0x927FF929,
    0xC80AFD09,0x35FFFFAA,0x17FFFF69,
)
NATIVE_POINTER_CHAIN_POP_RECOMPUTED_FIELDS = (
    (0,5),(0,),(0,5),(0,),(0,5),(0,5,16),(0,),(0,),(),(0,5),
    (0,5),(0,5),(5,16),(),(0,5),(0,5,16),(0,),(0,5),(0,5),
    (5,16),(),(0,5),(0,5,16),(0,),(),(),(0,5),(),(0,5),(0,5),
    (0,5,16),(0,),(),
)


def native_pointer_chain_pop_recomputed(start, by_pc, kinds, api):
    """An exact tagged free-list pop recomputes each exclusive cell address.

    The incoming primary cell, tagged value, secondary address, and untag
    result share one role. Adds of #0x40 and #0x80 from the object pointer
    rebuild that address before every exclusive memory op; the far clear then
    reuses the object pointer as the primary cell. The 16-byte island and both
    post-close exits stay outside. Control offsets, tag bits, widths, and
    ordering stay fixed. Failed stores refresh the matching load. Both CLREX
    sites stay in the union, and both ordinary exits follow a store or CLREX.
    """
    begin=start.address
    offsets=NATIVE_POINTER_CHAIN_POP_RECOMPUTED_OFFSETS
    words=NATIVE_POINTER_CHAIN_POP_RECOMPUTED_WORDS
    fields_table=NATIVE_POINTER_CHAIN_POP_RECOMPUTED_FIELDS
    if len(offsets)!=len(words) or len(words)!=len(fields_table):return None
    block=tuple(by_pc.get(begin+offset) for offset in offsets)
    if any(ins is None for ins in block):return None
    roles,reverse={},{}
    for ins,expected,fields in zip(block,words,fields_table):
        value=struct.unpack('<I',ins.bytes)[0]
        mask=sum(31<<shift for shift in fields)
        if value&~mask!=expected&~mask:return None
        for shift in fields:
            role,actual=expected>>shift&31,value>>shift&31
            if role==31:
                if actual!=31:return None
            elif (actual in {18,29,30,31} or roles.get(role,actual)!=actual or
                  reverse.get(actual,role)!=role):return None
            else:roles[role],reverse[actual]=actual,role
    if any(pc not in by_pc or api.is_fatal_instruction(by_pc[pc])
           for pc in (begin+120,begin+156)):return None
    nodes={ins.address for ins in block}
    if any(kinds.get(pc,'missing') is not None for pc in nodes):
        raise api.RewriteError(f'0x{begin:x}: source rewrite in native pointer chain pop recomputed')
    for ins in block:
        validate_memory_operands(ins,api)
        if ins.mnemonic in api.EXCLUSIVE_LOADS|api.EXCLUSIVE_STORES:validate_exclusive(ins,api)
    return nodes,begin,{begin,begin+60,begin+88,begin+708}


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
    # exclusive load. Sorted layout must still enter at the approved entry.
    emitter.emit(api.branch(emitter.pc, mapped[region.entry]))
    exits = sorted({target for _, target in region.exit_edges})
    exit_start = emitter.pc + len(region.instructions) * 8
    if not region.retire_exit_targets<=set(exits):
        raise api.RewriteError('retirement target outside exclusive exits')
    exit_stubs,cursor={},exit_start
    for target in exits:
        exit_stubs[target]=cursor
        cursor+=16+(4 if target in region.retire_exit_targets else 0)
    for ins in region.instructions:
        destinations = {target: exit_stubs[target] if (ins.address, target) in region.exit_edges else mapped[target]
                        for target in successors(ins)}
        emitter.emit(relocate(ins, emitter.pc, destinations, scratch, api))
        if ins.mnemonic == 'b':
            emitter.emit(0xD503201F)  # unreachable padding keeps mapping fixed
        else:
            emitter.emit(api.branch(emitter.pc, destinations[ins.address + 4]))
    for target in exits:
        if target in region.retire_exit_targets:
            emitter.emit(0xD5033F5F)  # Retire before any scratch/state/frame access.
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
