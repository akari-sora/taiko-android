"""Independently inspect finite Taiko call forests in the emitted capsule.

No emitter or target-list receipt supplies authority here. The source-bound
entry set comes from fully cross-checked CIE/FDE records and a fresh source CFG
audit. Exact instruction stencils make every possible emitted edge explicit.
"""
from bisect import bisect_right
import hashlib
import struct

from taiko_call_contract import MAIN_SHA256, MAIN_BUILD_ID

CALL = 0x292702C
CALLER_START, CALLER_END = 0x2926E60, 0x2927164
NODE_SIZE, FAILURE_SIZE, STUB_SIZE = 60, 28, 60
MAX_TARGETS = 1_048_576
RULE = 'versioned-taiko-main-eh-callback-forest-v2'
POLICY = 'runtime-exact-positive-indexed-EH-entry; zero-range/unindexed/unknown/interior/null/cross-module trap'


# Independent pinned facts; never imported from the producer selector.
CALLER_PINS = (
    dict(offset=0x84D7C0, source_word=0xD63F0240,
         caller_eh_start=0x84A890, caller_eh_end=0x852A78, caller_fde=0x474B0B0, caller_cie=0x41D6360,
         caller_body_sha256='8effd40fb6cd794194374b5ffade796e12b2a0ecae234fbcbc37bb6066fc1885',
         evidence_start=0x84D764, evidence_end=0x84D7C8,
         evidence_sha256='10a460b5d1c6f6c28e650c3800fd4ed20086ec723b81b112151583eef33dfde8',
         source_role='mutable-ctx-150-receiver-vptr-slot-196; runtime-domain-only; initialization/type/cross-module-unproven',
         stack_argument_bytes=0x50, stack_argument_store_count=10,
         stack_store_start=0x84D798, stack_store_end=0x84D7C0),
    dict(offset=0x292702C, source_word=0xD63F0240,
         caller_eh_start=0x2926E60, caller_eh_end=0x2927164, caller_fde=0x4572CC0, caller_cie=0x41D6360,
         caller_body_sha256='5eeec23468d866136914f6a940793ab6f6455408b8c75c8383bb8f17489ba5ce',
         evidence_start=0x2927004, evidence_end=0x2927030,
         evidence_sha256='6ce44c15553014a6affd4c9faf6f0a656ac60a5fada7d92f817acd51f4d4f678',
         source_role='mutable-generated-function-pointer; runtime-domain-only'),
)


def require(condition, reason):
    if not condition:
        raise ValueError('Taiko forest audit: ' + reason)


def target_digest(targets):
    digest = hashlib.sha256()
    for target in targets:
        digest.update(struct.pack('<Q', target))
    return digest.hexdigest()


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def words(image, offset, count):
    require(type(offset) is int and offset % 4 == 0 and 0 <= offset <= len(image) - count * 4,
            'instruction extent outside emitted image')
    return struct.unpack_from('<' + 'I' * count, image, offset)


def direct_target(word, pc):
    require(word & 0xFC000000 == 0x14000000, 'edge is not an unconditional direct branch')
    return pc + 4 * signed(word & 0x3FFFFFF, 26)


def address_target(first, second, pc, register):
    require(first & 0x9F00001F == 0x90000000 | register and
            second & 0xFFC003FF == 0x91000000 | register << 5 | register,
            'address must be ADRP/ADD for the exact scratch register')
    immediate = (first >> 5 & 0x7FFFF) << 2 | (first >> 29 & 3)
    return (pc & ~4095) + (signed(immediate, 21) << 12) + (second >> 10 & 4095)


# Each scratch/argument save slot and each flags/SP restore is checked literally.
# These stencils cannot read/write hardware X18, alter SIMD state, or branch
# through mutable memory. X30 alone changes on the successful BLR replacement.
SUCCESS = (0xF94017E2, 0xD51B4202, 0xF94013E2, 0xA94107E0,
           0xF94003F0, 0xF9401BFE, 0x910103FF)
FAILURE = (0xF94017E2, 0xD51B4202, 0xF94013E2, 0xA94107E0,
           0xA9407BF0, 0x910103FF, 0xD4200000)


def verify_emitted_forest(image, forest, targets, *, patch_start, fixups, callers=None, source_offset=None, trampoline=None):
    """Check actual bytes; ``targets`` must be independently derived by caller.

    Kept separate from title selection to allow freely authored byte mutations.
    Synthetic callers cannot reach provider generation through this low-level API.
    """
    require(isinstance(forest, dict), 'missing forest geometry')
    targets = tuple(targets)
    require(0 < len(targets) <= MAX_TARGETS and all(type(x) is int and x >= 0 and x % 4 == 0 for x in targets)
            and targets == tuple(sorted(set(targets))), 'target set is empty, duplicate, unordered or unaligned')
    if callers is None:
        callers=[dict(offset=source_offset,trampoline=trampoline)]
    else:
        require(source_offset is None and trampoline is None, 'mixed caller APIs')
    require(isinstance(callers,(list,tuple)) and callers and all(isinstance(row,dict) and
            set(row)=={'offset','trampoline'} and all(type(row[key]) is int and row[key]>=0 and row[key]%4==0
            for key in row) for row in callers), 'invalid caller set')
    offsets=[row['offset'] for row in callers]
    require(offsets==sorted(set(offsets)) and all(pc+4<=patch_start for pc in offsets), 'caller set duplicate, unordered or outside source')
    require(len({item['offset'] for item in fixups})==len(fixups), 'duplicate helper fixup')
    start = patch_start
    failure = start + len(targets) * NODE_SIZE
    end = failure + FAILURE_SIZE
    depth = len(targets).bit_length()
    expected = dict(version=1, start=start, root=start, end=end, failure_offset=failure,
                    node_size=NODE_SIZE, node_count=len(targets), target_count=len(targets),
                    target_sha256=target_digest(targets), site_offsets=offsets, max_depth=depth,
                    stub_size=STUB_SIZE, frame_size=64)
    require(forest == expected, 'receipt geometry/target set differs from derived forest')
    extents=[(start,end),*((row['trampoline'],row['trampoline']+STUB_SIZE) for row in callers)]
    ordered=sorted(extents)
    require(start%4==0 and end<=len(image) and all(a>=end and b<=len(image) for a,b in extents[1:]) and
            all(b<=c for (a,b),(c,d) in zip(ordered,ordered[1:])), 'forest/stub extent overlaps or escapes patch')
    for row in callers:
        source_offset,trampoline=row['offset'],row['trampoline']
        require(direct_target(words(image, source_offset, 1)[0], source_offset) == trampoline,
                'source caller does not branch directly to its recorded stub')
        stub = words(image, trampoline, STUB_SIZE // 4)
        require(stub[:3] == (0xD10103FF, 0xA9007BF0, 0xA90107E0) and
                stub[4:11] == (0xD63F0200, 0xAA1003E1, 0xA9407BF0,
                               0xF90013E2, 0xD53B4202, 0xF90017E2, 0xF9400020),
                'caller save/helper/snapshot chain changed')
        literal_word = stub[3]
        require(literal_word & 0xFF00001F == 0x58000010, 'state helper must use LDR literal X16')
        literal = trampoline + 12 + 4 * signed(literal_word >> 5 & 0x7FFFF, 19)
        require(literal % 8 == 0 and end <= literal <= len(image) - 8 and image[literal:literal+8] == bytes(8)
                and dict((item['offset'], item['helper']) for item in fixups).get(literal) == 1,
                'state helper literal lacks exact immutable fixup')
        require(not any(a < literal+8 and literal < b for a,b in extents),
                'state helper literal overlaps forest/stub instructions')
        require(address_target(stub[11], stub[12], trampoline + 44, 30) == source_offset + 4 and
                stub[13] == 0xF9001BFE and direct_target(stub[14], trampoline + 56) == start,
                'caller continuation/root chain changed')
    require(words(image, failure, 7) == FAILURE, 'failure path does not restore then trap')
    # Preorder geometry is proved from the independently sorted target set.
    # Every node gets one disjoint ordinal, so no cycle/alias/extra leaf can hide.
    pending = [(0, len(targets), start)]
    visited = 0
    while pending:
        low, high, node = pending.pop()
        middle = (low + high) // 2
        left_count = middle - low
        left = node + NODE_SIZE if left_count else failure
        right = node + NODE_SIZE * (1 + left_count) if middle + 1 < high else failure
        actual = words(image, node, NODE_SIZE // 4)
        require(address_target(actual[0], actual[1], node, 1) == targets[middle],
                'node expected address differs from derived target')
        require(actual[2:5] == (0xEB01001F, 0x54000080, 0x54000043),
                'node compare/equality/unsigned ordering branch changed')
        require(direct_target(actual[5], node + 20) == right and
                direct_target(actual[6], node + 24) == left, 'node child edge/cycle/unknown path changed')
        require(actual[7:14] == SUCCESS, 'success leaf fails exact state/flags/SP/LR restoration')
        require(direct_target(actual[14], node + 56) == targets[middle],
                'success leaf does not directly reach its exact function entry')
        if left_count:
            pending.append((low, middle, left))
        if middle + 1 < high:
            pending.append((middle + 1, high, right))
        visited += 1
    require(visited == len(targets), 'incomplete forest traversal')
    # Reject even a claimed loader fixup over one checked instruction word.
    for item in fixups:
        at = item['offset']
        require(not any(a < at+8 and at < b for a,b in extents),
                'loader fixup overlaps audited forest/stub instructions')
    return expected


def _source_callers(nso, records):
    """Independently pinned source facts; no CFG or target authority by itself."""
    require(nso.source_sha256.hex()==MAIN_SHA256 and nso.build_id.hex()==MAIN_BUILD_ID,
            'source identity differs')
    callers=[]
    for pin in CALLER_PINS:
        start,end=pin['caller_eh_start'],pin['caller_eh_end']
        require(any((record.start,record.end,record.fde,record.cie)==
                    (start,end,pin['caller_fde'],pin['caller_cie']) for record in records),
                'exact caller CIE/FDE extent missing')
        require(words(nso.image,pin['offset'],1)==(0xD63F0240,), 'original caller is not pinned BLR X18')
        require(hashlib.sha256(nso.image[start:end]).hexdigest()==pin['caller_body_sha256'] and
                hashlib.sha256(nso.image[pin['evidence_start']:pin['evidence_end']]).hexdigest()==pin['evidence_sha256'],
                'caller source body/evidence changed')
        caller=dict(pin)
        if 'stack_store_start' in pin:
            caller['stack_store_sha256']=hashlib.sha256(nso.image[pin['stack_store_start']:pin['stack_store_end']]).hexdigest()
        callers.append(caller)
    return callers


def verify_checked_call_forests(nso, metadata, image, discovery, rewrite, sites, ranges, fixups, provenance):
    """Derive title authority and independently inspect every emitted node/leaf."""
    selected = discovery.get('versioned_checked_call_forests', [])
    forests = rewrite.get('checked_call_forests', [])
    matched = nso.source_sha256.hex() == MAIN_SHA256 and nso.build_id.hex() == MAIN_BUILD_ID
    if not matched:
        require(selected == [] and forests == [], 'unmatched source claimed a versioned forest')
        return []
    from nso_eh import validated_eh_functions
    from android_import import discover_code
    records = validated_eh_functions(nso, metadata)
    targets = tuple(record.start for record in records)
    callers=_source_callers(nso,records)
    descriptor=dict(callers=callers,rule=RULE,source_sha256=MAIN_SHA256,build_id=MAIN_BUILD_ID,
                    target_count=len(targets),target_sha256=target_digest(targets),target_policy=POLICY)
    require(selected==[descriptor] and len(forests)==1, 'source contract/forest count changed')
    # Receipt ranges are not evidence. Re-run the full source CFG, including its
    # whole-text sensitive-instruction coverage check, before reading coverage.
    fresh_ranges, fresh = discover_code(nso, metadata, indirect_policy='guarded-host', checked_stack=True)
    require(list(map(tuple, ranges)) == list(map(tuple, fresh_ranges)) and
            discovery.get('roots') == fresh.get('roots') and
            discovery.get('independent_roots') == fresh.get('independent_roots') and
            fresh.get('versioned_checked_call_forests') == [descriptor], 'source CFG receipt/contract differs')
    starts = [start for start, _ in fresh_ranges]
    root_set = set(fresh['roots'])
    for target in targets:
        index = bisect_right(starts, target) - 1
        require(index >= 0 and target + 4 <= fresh_ranges[index][1] and target in root_set,
                'validated function entry lacks complete source CFG audit')
    authorized={caller['offset'] for caller in callers}
    caller_sites=[site for site in sites if site['offset'] in authorized]
    require(len(caller_sites)==len(authorized) and {site['offset'] for site in caller_sites}==authorized and
            not any(item['original_offset'] in authorized for item in provenance),
            'forest sources must each have one stub and no host gate')
    for caller in callers:
        at=caller['offset'];index=bisect_right(starts,at)-1
        require(index>=0 and at+4<=fresh_ranges[index][1], 'caller lacks complete source CFG audit')
    patch_start=(len(nso.image)+16383)//16384*16384
    checked=verify_emitted_forest(image,forests[0],targets,
        callers=sorted((dict(offset=site['offset'],trampoline=site['trampoline']) for site in caller_sites),key=lambda row:row['offset']),
        patch_start=patch_start,fixups=fixups)
    owned=[(checked['start'],checked['end']),
           *((site['trampoline'],site['trampoline']+STUB_SIZE) for site in caller_sites)]
    for site in sites:
        if site['offset'] not in authorized:
            require(not any(start<=site['trampoline']<end for start,end in owned),
                    'nonauthorized site aliases an audited forest or caller stub')
    return [checked]
