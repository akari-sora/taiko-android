"""Finite 39-word wait layout; all source effects stay native, physical WFE NOT_RUN."""
import struct
import sys
import unittest
import test_android_native_wait_mutex as old
ar=old.ar
BEGIN,END,CALLEE=16,172,184
WORDS=(2034369128, 2432712724, 4185916048, 285213973, 872415784, 1384120361, 2030174837, 2287992458, 872415434, 2030174824, 3573751903, 2030174837, 2287992458, 905969546, 2282389129, 872416010, 2030174824, 2030174837, 2287992458, 905969354, 402653178, 1384120374, 335544322, 3573751903, 2030174837, 2287992456, 872415432, 2030174847, 2034370152, 889192264, 2483027980, 402653176, 2282258070, 872415432, 2030174847, 2034370152, 889192072, 2483027973, 402653170)
FIELDS=((0, 5), (0, 5), (5,), (0, 5), (0,), (0,), (0, 5), (0, 5), (0,), (0, 5), (), (0, 5), (0, 5), (0,), (0, 5, 16), (0,), (0, 5), (0, 5), (0, 5), (0,), (), (0,), (), (), (0, 5), (0, 5), (0,), (0, 5), (0, 5), (0,), (), (), (0, 5, 16), (0,), (0, 5), (0, 5), (0,), (), ())


def fixture(rename=None):
    block=list(WORDS)
    for index,fields in enumerate(FIELDS):
        for shift in fields:
            role=WORDS[index]>>shift&31
            if rename and role!=31:block[index]=block[index]&~(31<<shift)|rename.get(role,role)<<shift
    for index in (30,37):block[index]=0x94000000|((CALLEE-BEGIN-index*4)//4)&0x3FFFFFF
    tlr=rename.get(19,19) if rename else 19
    return [ar.branch(0,BEGIN-4),0xD503201F,0xD503201F,0xD53BD060|tlr]+block+[
        0xD65F03C0,0xD503201F,0xD503201F,0xD40006C1,0xD65F03C0]


def helper(values=None,overrides=None):
    instructions,kinds=old.decode(fixture() if values is None else values);kinds.update(overrides or {})
    by={ins.address:ins for ins in instructions}
    return ar.android_exclusive.native_wait_mutex(by[BEGIN+28],by,kinds,ar)


def plan(values=None,roots=(0,BEGIN-4,END,CALLEE),overrides=None):
    instructions,kinds=old.decode(fixture() if values is None else values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions,kinds,roots,ar)


class NativeWaitMutexCompactTests(unittest.TestCase):
    def test_unhandled_transfer_context_cannot_invent_tlr_dominance(self):
        old.assert_unknown_transfers_need_explicit_processed_facts(self,sys.modules[__name__])

    def test_verified_finite_tables_still_reject_native_body_case_entries(self):
        old.assert_finite_table_targets_keep_producer_entry_checks(self,sys.modules[__name__])

    def test_producer_cannot_be_bypassed_by_metadata_or_ordinary_alternate_entry(self):
        old.assert_producer_entry_required(self,sys.modules[__name__])

    def test_producer_ownership_cannot_overlap_another_native_window(self):
        old.assert_producer_ownership_exclusive(self,sys.modules[__name__])

    def test_compact_layout_is_native_in_checked_v2_and_all_four_heads_are_consumed(self):
        for rename in (None,{0:1,8:2,9:3,10:4,19:23,20:24,21:25,22:26}):
            values=fixture(rename);self.assertEqual((),plan(values))
            image=ar.rewrite(old.raw(values),checked_stack=True,package_version=2,entry_offsets=(0,BEGIN-4,END,CALLEE))
            self.assertEqual(old.raw(values)[BEGIN:END],image.bytes[BEGIN:END])
            self.assertEqual([BEGIN-4,CALLEE],[site.offset for site in image.sites])
        self.assertEqual((set(range(BEGIN,END,4)),BEGIN,{BEGIN+n for n in (28,48,72,100)}),helper())

    def test_zero_nested_wrap_busy_and_failed_store_source_effects_without_claiming_physical_wake(self):
        for count in (0,1,7,0xFFFF):
            for busy,release,failures in ((0,1,0),(1,1,0),(1,4,0),(0,1,3),(1,3,2)):
                machine=old.Machine(fixture(),count,busy,release,failures)
                before=machine.x.copy();memory=machine.memory.copy();machine.run(end=END)
                for register in (8,9,10,20,21,22):before[register]=machine.x[register]
                self.assertEqual(before,machine.x);memory[0x400010]=1;memory[0x500100]=(count+1)&0xFFFF
                self.assertEqual(memory,machine.memory)
                self.assertEqual((0x800000,0xB0000000,tuple(range(32))),(machine.sp,machine.nzcv,machine.q))
                self.assertEqual(0,machine.calls);self.assertEqual(failures+1,machine.stores)
        machine=old.Machine(fixture(),0,busy=1,interrupt=1)
        with self.assertRaisesRegex(ValueError,'unsupported pin model'):machine.run(end=END)
        self.assertEqual(1,machine.memory[0x500102])

    def test_all_38_interior_metadata_and_ordinary_entries_refuse(self):
        for pc in range(BEGIN,END,4):
            with self.assertRaises(ar.RewriteError):plan(roots=(0,BEGIN-4,END,CALLEE,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.assertRaises(ar.RewriteError):plan(values)

    def test_every_exact_word_and_role_ordering_width_call_or_wait_mutation_refuses(self):
        for slot in range(39):
            values=fixture();index=BEGIN//4+slot
            if slot in (30,37):values[index]=0x94000000|((END-BEGIN-slot*4)//4)&0x3FFFFFF
            else:values[index]^=0x8000 if slot in (7,12,18,25,14,32) else 1
            try:value=helper(values)
            except ar.RewriteError:continue
            with self.subTest(slot=slot):self.assertIsNone(value)
        for role in (0,8,9,10,19,20,21,22):
            for forbidden in (18,29,30,31,8 if role!=8 else 9):self.assertIsNone(helper(fixture({role:forbidden})))
        for pc in range(BEGIN,END,4):
            with self.assertRaises(ar.RewriteError):plan(overrides={pc:'x18'})
        instructions,kinds=old.decode(fixture());by={op.address:op for op in instructions}
        for pc in range(BEGIN,END,4):
            self.assertIsNone(ar.android_exclusive.native_wait_mutex(by[BEGIN+28],{p:i for p,i in by.items() if p!=pc},kinds,ar))
        for pc in (CALLEE,CALLEE+4,END,BEGIN-4):
            instructions,kinds=old.decode(fixture());by={op.address:op for op in instructions};del by[pc]
            self.assertIsNone(ar.android_exclusive.native_wait_mutex(by[BEGIN+28],by,kinds,ar))
        for word in (0xD40006E1,0xD503201F,0xD4000001):
            values=fixture();values[CALLEE//4]=word;self.assertIsNone(helper(values))
        values=fixture();values[(CALLEE+4)//4]=0xD61F03C0;self.assertIsNone(helper(values))
        for target in (BEGIN,BEGIN+120,END-4):
            values=fixture()
            for slot in (30,37):values[BEGIN//4+slot]=0x94000000|((target-BEGIN-slot*4)//4)&0x3FFFFFF
            self.assertIsNone(helper(values))
        self.assertIsNone(helper(overrides={CALLEE:None}))
        self.assertIsNone(helper(overrides={CALLEE+4:'x18'}))
        for slot,word in ((10,0xD503201F),(23,0xD503203F),(31,ar.branch(BEGIN+31*4,BEGIN+32*4)),
                          (38,ar.branch(BEGIN+38*4,BEGIN+32*4))):
            values=fixture();values[BEGIN//4+slot]=word;self.assertIsNone(helper(values))

    def test_tlr_width_offset_identity_and_normal_rewrite_remain_required(self):
        for word in (0xD503201F,0xD53BD053,0xD53BD074):
            values=fixture();values[(BEGIN-4)//4]=word;self.assertIsNone(helper(values))
        instructions,kinds=old.decode(fixture());by={op.address:op for op in instructions};kinds[BEGIN-4]=None
        self.assertIsNone(ar.android_exclusive.native_wait_mutex(by[BEGIN+28],by,kinds,ar))
        for slot in (0,6,9,11,16,17,24,27,28,34,35):
            values=fixture();values[BEGIN//4+slot]^=1<<10;self.assertIsNone(helper(values))


if __name__=='__main__':unittest.main()
