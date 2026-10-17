"""Self-authored five-peer byte CAS closure; no commercial byte fixtures."""
from functools import lru_cache
import struct
import unittest
from test_android_exclusive import assemble
from test_android_rewrite import ar

BODY = '''peer0: ldxrb w9, [x20]
cmp w9, w10
b.ne failure
stxrb w11, w8, [x20]
cbnz w11, peer0
b success
peer1: ldxrb w9, [x20]
cmp w9, w10
b.ne failure
stlxrb w11, w8, [x20]
cbnz w11, peer1
b success
peer2: ldaxrb w9, [x20]
cmp w9, w10
b.ne failure
stlxrb w11, w8, [x20]
cbnz w11, peer2
b success
peer3: ldaxrb w9, [x20]
cmp w9, w10
b.ne failure
stlxrb w11, w8, [x20]
cbnz w11, peer3
b success
peer4: ldaxrb w9, [x20]
cmp w9, w10
b.ne failure
stlxrb w11, w8, [x20]
cbnz w11, peer4
success: mov w8, #1
tbz w8, #0, publish
b leave
failure: mov w8, wzr
clrex
tbnz w8, #0, leave
publish: mov w0, wzr
strb w9, [x19]
ldp x20, x19, [sp, #0x20]
ldp x22, x21, [sp, #0x10]
ldp x30, x23, [sp], #0x30
ret
leave: mov w0, #1
ldp x20, x19, [sp, #0x20]
ldp x22, x21, [sp, #0x10]
ldp x30, x23, [sp], #0x30
ret
alien: ret
padding: ret
'''
HEADS = {0, 24, 48, 72, 96}
MOV, CLREX, TBNZ, SUCCESS, PUBLISH, LEAVE, ALIEN = 128, 132, 136, 116, 140, 164, 184
CLOSURE = {pc for h in HEADS for pc in range(h, h+20, 4)} | {MOV, CLREX}

@lru_cache(maxsize=None)
def fixture(body=BODY):
    return assemble(body)

def decoded(source=None, base=0):
    source = fixture() if source is None else source
    instructions = tuple(ar.Instruction(ins) for ins in ar.MD.disasm(source, base))
    if len(instructions)*4 != len(source):
        raise ar.RewriteError('incomplete self-authored instruction stream')
    return instructions, {ins.address: None for ins in instructions}

def plan(source=None, entries=(), kinds=None):
    instructions, defaults = decoded(source)
    return ar.android_exclusive.plan_regions(instructions, defaults if kinds is None else kinds, entries, ar)

def changed(changes, source=None):
    value = bytearray(fixture() if source is None else source)
    for pc, word in changes.items():
        struct.pack_into('<I', value, pc, word)
    return bytes(value)

def word(pc, source=None):
    return struct.unpack_from('<I', fixture() if source is None else source, pc)[0]

def selected(source=None, base=0, kinds=None):
    instructions, defaults = decoded(source, base)
    by_pc = {ins.address:ins for ins in instructions}
    return ar.android_exclusive.native_five_peer_byte_closure(
        by_pc[min(by_pc)],by_pc,defaults if kinds is None else kinds,ar)

def branch(kind, pc, target):
    if kind in ('b','bl'):
        return ar.branch(pc,target) | (0x80000000 if kind=='bl' else 0)
    if kind == 'b.ne': return 0x54000001 | (((target-pc)//4)&0x7ffff)<<5
    if kind == 'cbnz': return 0x3500000c | (((target-pc)//4)&0x7ffff)<<5
    if kind == 'tbnz': return 0x3700000c | (((target-pc)//4)&0x3fff)<<5
    raise AssertionError(kind)

class FivePeerByteUnionTests(unittest.TestCase):
    def assert_refused(self, source=None, **kwargs):
        with self.assertRaises(ar.RewriteError):
            plan(source,**kwargs)

    def test_complete_native_closure_preserves_source_and_sites(self):
        self.assertEqual(plan(), ())
        result = ar.rewrite(fixture())
        self.assertEqual(result.bytes, fixture())
        self.assertEqual(result.sites, ())
        self.assertEqual(result.gates, ())
        self.assertEqual(result.fixups, ())

    def test_exact_C_H_and_one_complete_consumption(self):
        nodes,heads,witness=selected()
        self.assertEqual(nodes,CLOSURE)
        self.assertEqual(heads,HEADS)
        self.assertEqual(len(nodes),27)
        self.assertIn(MOV,nodes)
        self.assertIn(CLREX,nodes)
        self.assertNotIn(TBNZ,nodes)
        self.assertTrue(nodes.isdisjoint(witness))
        self.assertEqual(plan(entries=tuple(HEADS)),())
        instructions,kinds=decoded()
        by_pc={ins.address:ins for ins in instructions}
        for head in HEADS-{min(HEADS)}:
            self.assertIsNone(ar.android_exclusive.native_five_peer_byte_closure(by_pc[head],by_pc,kinds,ar))
        calls=[]
        original=ar.android_exclusive.native_five_peer_byte_closure
        def observed(start,*args):
            calls.append(start.address)
            return original(start,*args)
        ar.android_exclusive.native_five_peer_byte_closure=observed
        try: self.assertEqual(plan(),())
        finally: ar.android_exclusive.native_five_peer_byte_closure=original
        self.assertEqual(calls,[min(HEADS)])
        relocated=selected(base=0x1200)
        self.assertEqual(relocated[0],{pc+0x1200 for pc in CLOSURE})
        self.assertEqual(relocated[1],{pc+0x1200 for pc in HEADS})

    def test_legal_scratch_and_saved_address_role_rename(self):
        import re
        names={'w8':'w12','w9':'w13','w10':'w14','w11':'w15',
               'x20':'x24','x19':'x25'}
        renamed=re.sub(r'\b(?:w8|w9|w10|w11|x20|x19)\b',lambda m:names[m.group()],BODY)
        self.assertEqual(plan(fixture(renamed)),())
        self.assertEqual(ar.rewrite(fixture(renamed)).bytes,fixture(renamed))

    def test_family_preserving_peer_permutation(self):
        source=fixture()
        pairs=[(True,True),(False,True),(True,True),(False,False),(True,True)]
        changes={}
        for head,(acquire,release) in zip(sorted(HEADS),pairs):
            changes[head]=(word(head,source)&~0x8000)|(0x8000 if acquire else 0)
            changes[head+12]=(word(head+12,source)&~0x8000)|(0x8000 if release else 0)
        permuted=changed(changes)
        self.assertEqual(plan(permuted),())
        self.assertEqual(ar.rewrite(permuted).bytes,permuted)

    def test_checked_stack_preserves_all_owned_bytes_and_sites(self):
        source=fixture()
        image=ar.rewrite(source,package_version=2,checked_stack=True,indirect_policy='guarded-host')
        for pc in CLOSURE:
            self.assertEqual(image.bytes[pc:pc+4],source[pc:pc+4])
        self.assertFalse(CLOSURE & {site.offset for site in image.sites})
        self.assertEqual([site.offset for site in image.sites],[156,176])

    def test_every_owned_interior_and_witness_metadata_root_refused(self):
        _,_,witness=selected()
        for pc in (CLOSURE-HEADS)|witness:
            with self.subTest(root=pc): self.assert_refused(entries=(pc,))
        for pc in CLOSURE-HEADS:
            # entry_offsets is the single planner authority for relocations,
            # exported roots and resolved indirect/table destinations alike.
            with self.subTest(indirect_authority=pc):
                self.assert_refused(entries=tuple(HEADS|{pc}))

    def test_every_owned_interior_alien_direct_or_conditional_entry_refused(self):
        for pc in CLOSURE-HEADS:
            for kind in ('b','bl','b.ne','cbnz','tbnz'):
                with self.subTest(target=pc,kind=kind):
                    self.assert_refused(changed({ALIEN:branch(kind,ALIEN,pc)}))
        self.assert_refused(changed({124:0xD503201F}))  # alien fallthrough into shared MOV

    def test_carrier_and_retirement_witness_alien_entries_refused(self):
        _,_,witness=selected()
        for pc in witness-{LEAVE}:
            for kind in ('b','bl','b.ne'):
                with self.subTest(target=pc,kind=kind):
                    self.assert_refused(changed({ALIEN:branch(kind,ALIEN,pc)}))

    def test_every_owned_kind_missing_unknown_or_rewrite_refused(self):
        _,defaults=decoded()
        for pc in CLOSURE:
            for kind in ('missing','x18','gate','parameter','stack_check','unknown'):
                kinds=dict(defaults)
                if kind=='missing': kinds.pop(pc)
                else: kinds[pc]=kind
                with self.subTest(pc=pc,kind=kind): self.assert_refused(kinds=kinds)

    def test_each_peer_load_cmp_store_status_width_role_cell_retry_mutations_refused(self):
        for head in sorted(HEADS):
            changes=(
                (head,word(head)^0x40000000),  # byte -> halfword
                (head,word(head)^0x80000000),  # byte -> word
                (head,word(head)^1), (head,word(head)^(1<<5)),
                (head,word(head)^0x8000),  # acquire/plain count changes
                (head+4,word(head+4)^0x80000000), # W -> X compare
                (head+4,word(head+4)^1<<16), (head+4,word(head+4)^1<<5),
                (head+4,word(head+4)|1<<10),  # shifted compare
                (head+8,branch('b',head+8,MOV)),
                (head+8,branch('b.ne',head+8,CLREX)),
                (head+12,word(head+12)^0x40000000),
                (head+12,word(head+12)^0x80000000),
                (head+12,word(head+12)^1), (head+12,word(head+12)^1<<5),
                (head+12,word(head+12)^1<<16), (head+12,word(head+12)^0x8000),
                (head+16,word(head+16)^0x80000000),
                (head+16,word(head+16)^1), (head+16,word(head+16)^0x01000000),
                (head+16,0x3500000b|(((head+4-head-16)//4)&0x7ffff)<<5),
                (head+16,0x3500000b|((((head+24)%120-head-16)//4)&0x7ffff)<<5),
            )
            for pc,value in changes:
                with self.subTest(head=head,pc=pc,mutation=hex(value)):
                    self.assert_refused(changed({pc:value}))

    def test_missing_peer_extra_or_noncompare_predecessor_refused(self):
        for head in HEADS:
            self.assert_refused(changed({head:0xD503201F}))
            self.assert_refused(changed({head+8:0xD65F03C0}))
        self.assert_refused(changed({ALIEN:branch('b',ALIEN,MOV)}))
        self.assert_refused(changed({ALIEN:branch('b.ne',ALIEN,MOV)}))
        self.assert_refused(changed({96:word(96)&~0x8000,72:word(72)&~0x8000,48:word(48)&~0x8000}))
        self.assert_refused(changed({0:word(0)|0x8000,24:word(24)|0x8000}))
        self.assert_refused(fixture(BODY.replace('success: mov w8, #1','b success\nsuccess: mov w8, #1')))

    def test_zero_one_carrier_clrex_tbnz_and_publish_exactness_refused(self):
        changes=(
            (MOV,0x52800008),(MOV,word(MOV)^1),(CLREX,0xD503201F),
            (TBNZ,word(TBNZ)^0x01000000),(TBNZ,word(TBNZ)^1),
            (TBNZ,word(TBNZ)|(1<<19)),(TBNZ,branch('tbnz',TBNZ,0)),
            (SUCCESS,word(SUCCESS)^1),(SUCCESS,word(SUCCESS)^0x20),
            (SUCCESS+4,word(SUCCESS+4)^0x01000000),(SUCCESS+4,word(SUCCESS+4)|(1<<19)),
            (SUCCESS+8,branch('b',SUCCESS+8,0)),
            (PUBLISH,0x52800000),(PUBLISH,0x2A0803E0),
            (PUBLISH+4,word(PUBLISH+4)^1),(PUBLISH+4,word(PUBLISH+4)^1<<5),
            (PUBLISH+4,word(PUBLISH+4)|1<<10),
            (PUBLISH+4,word(PUBLISH+4)|0x40000000),
        )
        for pc,value in changes:
            with self.subTest(pc=pc,value=hex(value)): self.assert_refused(changed({pc:value}))
        for body in (
            BODY.replace('strb w9, [x19]','strb w9, [x20]'),
            BODY.replace('strb w9, [x19]','strb w9, [x19, #1]!'),
            BODY.replace('strb w9, [x19]','strb w9, [x19], #1'),
            BODY.replace('strb w9, [x19]','strb w9, [x19, x12]'),
            BODY.replace('publish: mov w0, wzr','publish: mov w9, wzr'),
        ): self.assert_refused(fixture(body))

    def test_exact_restores_sp_ret_and_no_body_indirect_or_fault_refused(self):
        for pc in (148,152,156,160,168,172,176,180):
            for value in (0xD503201F,branch('b',pc,0),branch('b',pc,12),0xD61F0020,0xD63F0020,0xD4200000):
                with self.subTest(pc=pc,value=hex(value)): self.assert_refused(changed({pc:value}))
        for pc in (148,152,156,168,172,176):
            for bit in (0,5,10,15,23):
                self.assert_refused(changed({pc:word(pc)^(1<<bit)}))
        self.assert_refused(fixture(BODY.replace('ret\n','ret x17\n')))

    def test_x18_cannot_enter_any_role(self):
        import re
        for name in ('w8','w9','w10','w11','x19','x20'):
            mutation=re.sub(r'\b'+name+r'\b',name[0]+'18',BODY)
            with self.subTest(role=name): self.assert_refused(fixture(mutation))

    def test_overlap_is_not_hidden_and_acyclic_guard_is_invoked(self):
        # A separate live attempt entering a peer's CMP remains rejected.
        extra=assemble('ldxrb w12,[x24]\nb #4\n')
        instructions,kinds=decoded()
        extra_ops,_=decoded(extra,0x200)
        extra_ops=(extra_ops[0],ar.decode(ar.branch(0x204,4),0x204))
        with self.assertRaises(ar.RewriteError):
            ar.android_exclusive.plan_regions((*instructions,*extra_ops),{**kinds,0x200:None,0x204:None},(),ar)
        original=ar.android_exclusive.require_acyclic
        observed=[]
        def checking(nodes,by_pc,retries,exits,api):
            observed.append((set(nodes),set(retries),set(exits)))
            return original(nodes,by_pc,retries,exits,api)
        ar.android_exclusive.require_acyclic=checking
        try: self.assertEqual(plan(),())
        finally: ar.android_exclusive.require_acyclic=original
        self.assertEqual(observed[0][0],CLOSURE)
        self.assertEqual(observed[0][1],{(h+16,h) for h in HEADS})

if __name__ == '__main__':
    unittest.main()
