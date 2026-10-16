"""Long-lived masked table candidates follow control predecessors, not RVAs."""
import struct
import unittest

from test_android_runtime_ro_sub_inline import ar, parse_nso, source_base, write_image
from test_android_runtime_ro_backward import adr
from test_android_rewrite import Machine
from test_android_virtual_ro_x18 import image_for

LOAD=0xC18
BRANCH=0xC24
FIRST_BRANCH=0x61C
OTHER_BRANCH=0x81C


def fixture(virtual_loaded=False, alternative_reaches=False):
    source=source_base()
    # CBNZ chooses a mutually exclusive definition. The numerically nearest
    # constructor must not win when its path terminates away from this read.
    write_image(source,0x300,'<4I',0xB5000000|(((0x980-0x300)//4)<<5),
                0x9000002C,0x9120018C,ar.branch(0x30C,0x600))
    write_image(source,0x980,'<3I',0x9000002C,0x9124018C,
                ar.branch(0x988,0x700 if alternative_reaches else 0xE00))
    # A real, independently validated finite native switch is the only edge
    # connecting the old constructor to the eventual masked read.
    write_image(source,0x600,'<8I',0x7100001F,0x54000008|(((0xE00-0x604)//4)<<5),
                0x9000002D,0x912801AD,adr(0x610,0x700,6),0x386069A7,0x8B0708C6,0xD61F00C0)
    write_image(source,0x700,'<I',ar.branch(0x700,0xC00))
    # Another validated switch, disjoint from the reaching path, exercises
    # deterministic known-map order without inventing callback roots.
    write_image(source,0x800,'<8I',0x7100005F,0x54000008|(((0xE00-0x804)//4)<<5),
                0x9000002F,0x912C01EF,adr(0x810,0xE00,16),0x386269F1,0x8B110A10,0xD61F0200)
    write_image(source,0xC00,'<10I',0x7100013F,0xD503201F,0xD503201F,0x924039CE,
                0xD34D7DC9,adr(0xC14,0xD00,10),0x38696992 if virtual_loaded else 0x3869698B,
                0x8B12094A if virtual_loaded else 0x8B0B094A,0x91000694,0xD61F0140)
    for offset in (0x4800,0x4900):write_image(source,offset,'<4B',0,2,7,12)
    write_image(source,0x4A00,'<B',0);write_image(source,0x4B00,'<B',0)
    return source


def context(source):
    raw=parse_nso(source).image
    by_pc={pc:ar.Instruction(ar.decode(struct.unpack_from('<I',raw,pc)[0],pc))
           for pc in range(0x300,0x1000,4)}
    return raw,by_pc


def known_plans(raw, by_pc):
    plans={}
    for branch in (FIRST_BRANCH,OTHER_BRANCH):
        plan=ar.readonly_guest_table(by_pc[branch],by_pc,set(),raw,((0x4000,0x8000),))
        if plan is None:raise AssertionError(f'fixture switch {branch:x} was not independently validated')
        plans[branch]=plan
    return plans


def reaching_plan(source, *, known=None, entries=(), missing=()):
    raw,by_pc=context(source)
    plans=known_plans(raw,by_pc) if known is None else known
    for pc in missing:by_pc.pop(pc)
    return ar.readonly_guest_table(by_pc[BRANCH],by_pc,set(entries),raw,
                                  ((0x4000,0x8000),),known_tables=(plans,))


class NativeTableReachingTests(unittest.TestCase):
    def test_unique_selected_constant_survives_unproven_loop_classification_edges(self):
        for virtual_loaded in (False,True):
            source=fixture(virtual_loaded)
            write_image(source,0x980,'<I',0xD65F03C0) # Remove the distinct 4900 constructor.
            raw,by_pc=context(source);plans=known_plans(raw,by_pc)
            without_edges=ar.readonly_guest_table(by_pc[BRANCH],by_pc,set(),raw,((0x4000,0x8000),))
            with_edges=ar.readonly_guest_table(by_pc[BRANCH],by_pc,set(),raw,((0x4000,0x8000),),known_tables=(plans,))
            self.assertEqual(without_edges,with_edges)
            self.assertEqual(with_edges['table_offset'],0x4800)
            self.assertNotIn('reaching_table_producer_offsets',with_edges)
            # Materializing a later return-to-loop code address cannot add an
            # execution edge or turn this conditional identity into dominance.
            by_pc.pop(0x700)
            self.assertEqual(with_edges,ar.readonly_guest_table(by_pc[BRANCH],by_pc,set(),raw,((0x4000,0x8000),)))
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(FIRST_BRANCH,OTHER_BRANCH,BRANCH))
            from dataclasses import replace
            for bad in ('table','base','upper'):
                model=Machine(replace(image,entry_offset=LOAD));model.x[9]=2;model.x[10]=0xD00;model.x[12]=0x4800
                if bad=='table':model.x[12]=0x4900
                elif bad=='base':model.x[10]+=4
                else:model.x[9]|=1<<32
                before=list(model.x);model.flags=0xA0000000
                with self.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
                self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))

    def test_only_control_reaching_constructor_supplies_the_table_candidate(self):
        for virtual_loaded in (False,True):
            source=fixture(virtual_loaded)
            with self.subTest(virtual_loaded=virtual_loaded):
                plan=reaching_plan(source)
                self.assertIsNotNone(plan)
                self.assertEqual((plan['table_offset'],plan['index_bound'],plan['target_values']),
                                 (0x4800,3,[0,2,7,12]))
                self.assertGreater(LOAD-0x308,512)

    def test_all_four_indices_preserve_original_effects_on_the_reaching_path(self):
        for virtual_loaded in (False,True):
            source=fixture(virtual_loaded)
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(FIRST_BRANCH,OTHER_BRANCH,BRANCH))
            for index,tag in enumerate((0,2,7,12)):
                with self.subTest(virtual_loaded=virtual_loaded,index=index):
                    model=Machine(image);model.x[0]=0;model.x[9]=0
                    model.x[14]=0xF000000000000123|(index<<13)
                    model.store(model.state,0xAABBCCDD12345678,8)
                    before=list(model.x);model.run()
                    before[6]=0x700;before[7]=0;before[13]=0x4A00
                    before[9]=index;before[10]=0xD00+tag*4;before[12]=0x4800
                    before[14]=(index<<13)|0x123;before[20]+=1
                    if not virtual_loaded:before[11]=tag
                    self.assertEqual((model.x,model.sp,model.flags,model.load(model.state,8)),
                                     (before,model.start_sp,0x60000000,
                                      tag if virtual_loaded else 0xAABBCCDD12345678))

    def test_mutually_exclusive_path_returns_without_consuming_the_other_table(self):
        for virtual_loaded in (False,True):
            source=fixture(virtual_loaded)
            image=image_for(source,entry=0x300,proven_guest_indirect_offsets=(FIRST_BRANCH,OTHER_BRANCH,BRANCH))
            model=Machine(image);model.x[0]=1;before=list(model.x);model.run()
            before[12]=0x4900
            self.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0x60000000))

    def test_long_lived_table_still_checks_actual_values_before_the_original_read(self):
        from dataclasses import replace
        for virtual_loaded in (False,True):
            image=image_for(fixture(virtual_loaded),entry=0x300,
                            proven_guest_indirect_offsets=(FIRST_BRANCH,OTHER_BRANCH,BRANCH))
            for mode in ('upper','bound','table','base'):
                model=Machine(replace(image,entry_offset=LOAD))
                model.x[9]=2;model.x[10]=0xD00;model.x[12]=0x4800
                model.store(model.state,0x1122334455667788,8);model.flags=0xA0000000
                if mode=='upper':model.x[9]|=1<<32
                elif mode=='bound':model.x[9]=4
                elif mode=='table':model.x[12]=0x4900
                else:model.x[10]=0
                before=list(model.x)
                with self.subTest(virtual_loaded=virtual_loaded,mode=mode),self.assertRaisesRegex(AssertionError,'instruction brk'):
                    model.run()
                self.assertEqual((model.x,model.sp,model.flags,model.load(model.state,8)),
                                 (before,model.start_sp,0xA0000000,0x1122334455667788))

    def test_two_control_reaching_ro_constants_are_ambiguous(self):
        for virtual_loaded in (False,True):
            with self.subTest(virtual_loaded=virtual_loaded):
                self.assertIsNone(reaching_plan(fixture(virtual_loaded,alternative_reaches=True)))

    def test_missing_or_unknown_predecessor_does_not_certify_a_table(self):
        for virtual_loaded in (False,True):
            source=fixture(virtual_loaded)
            with self.subTest(virtual_loaded=virtual_loaded):
                self.assertIsNone(reaching_plan(source,missing=(0x700,)))
                changed=bytearray(source)
                write_image(changed,0x700,'<2I',0xD61F00A0,ar.branch(0x704,0xC00))
                self.assertIsNone(reaching_plan(changed))
                # Fatal words may be represented in selected code; do not use
                # them as fallthrough facts to reach the old constructor.
                raw,by_pc=context(source)
                by_pc[0x700]=ar.FatalWord(0x700,0xE7FFDEFE)
                self.assertIsNone(ar.readonly_guest_table(by_pc[BRANCH],by_pc,set(),raw,
                    ((0x4000,0x8000),),known_tables=(known_plans(raw,by_pc),)))

    def test_call_and_w_or_x_table_clobber_kill_old_definition(self):
        for word in (0x94000000|((0xE00-0x700)//4),0x2A1F03EC,0xAA1F03EC):
            for virtual_loaded in (False,True):
                source=fixture(virtual_loaded)
                write_image(source,0x700,'<2I',word,ar.branch(0x704,0xC00))
                with self.subTest(word=hex(word),virtual_loaded=virtual_loaded):
                    self.assertIsNone(reaching_plan(source))

    def test_known_plan_order_is_irrelevant_and_current_site_cannot_justify_itself(self):
        source=fixture();raw,by_pc=context(source);plans=known_plans(raw,by_pc)
        self.assertEqual(reaching_plan(source,known=plans),
                         reaching_plan(source,known=dict(reversed(tuple(plans.items())))))
        self.assertIsNone(reaching_plan(source,known={}))
        current=dict(plans[FIRST_BRANCH],offset=BRANCH,base=0x700,target_values=[0])
        self.assertIsNone(reaching_plan(source,known={BRANCH:current}))

    def test_constructor_outside_the_selected_window_cannot_supply_a_candidate(self):
        words={0x300:0x9000002C,0x304:0x9120018C,
               0x308:ar.branch(0x308,0x1000),0x1000:ar.branch(0x1000,0x2000),
               0x2000:0x3869698B}
        by_pc={pc:ar.Instruction(ar.decode(word,pc)) for pc,word in words.items()}
        self.assertIsNone(ar._reaching_table_candidates(0x2000,12,0x200C,by_pc,
                                                       [(0x300,0x304,0x4800)],()))

    def test_entries_after_the_read_cannot_bypass_guard(self):
        for virtual_loaded in (False,True):
            for entry in range(LOAD+4,BRANCH+4,4):
                with self.subTest(virtual_loaded=virtual_loaded,entry=hex(entry)):
                    self.assertIsNone(reaching_plan(fixture(virtual_loaded),entries=(entry,)))


if __name__=='__main__':unittest.main()
