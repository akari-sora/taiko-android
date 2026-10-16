"""Finite native busy-mutex proof; generic WFE and live calls remain refused."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar

BEGIN,END,CALLEE=16,196,208
WORDS=(0x79420268,0x91004014,0xF9800290,0x11000515,0x34000228,
       0x52800029,0x79020275,0x885FFE8A,0x340000CA,0x79020268,
       0xD503205F,0x79020275,0x885FFE8A,0x35FFFF8A,0x880A7E89,
       0x340003CA,0x79020268,0x79020275,0x885FFE8A,0x35FFFECA,
       0x17FFFFFA,0x52800036,0x79020275,0x885FFE88,0x350000C8,
       0x1400000A,0xD503205F,0x79020275,0x885FFE88,0x340000C8,
       0x7902027F,0x79420668,0x34FFFF48,0x94016893,0x17FFFFF8,
       0x88087E96,0x34000128,0x7902027F,0x79420668,0x34FFFE88,
       0x9401688C,0x79020275,0x885FFE88,0x35FFFE68,0x17FFFFF7)
FIELDS=((0,5),(0,5),(5,),(0,5),(0,),(0,),(0,5),(0,5),(0,),(0,5),
        (),(0,5),(0,5),(0,),(0,5,16),(0,),(0,5),(0,5),(0,5),(0,),
        (),(0,),(0,5),(0,5),(0,),(),(),(0,5),(0,5),(0,),
        (0,5),(0,5),(0,),(),(),(0,5,16),(0,),(0,5),(0,5),(0,),
        (),(0,5),(0,5),(0,),())


def raw(values):
    return struct.pack('<'+'I'*len(values),*values)


def fixture(rename=None):
    block=list(WORDS)
    for index,fields in enumerate(FIELDS):
        for shift in fields:
            role=WORDS[index]>>shift&31
            if rename and role!=31:
                block[index]=block[index]&~(31<<shift)|rename.get(role,role)<<shift
    for index in (33,40):
        block[index]=0x94000000|((CALLEE-(BEGIN+index*4))//4)&0x3FFFFFF
    tlr=rename.get(19,19) if rename else 19
    return [ar.branch(0,BEGIN-4),0xD503201F,0xD503201F,0xD53BD060|tlr]+block+[
        0xD65F03C0,0xD503201F,0xD503201F,0xD40006C1,0xD65F03C0]


def decode(values):
    instructions=[ar.decode(word,index*4) for index,word in enumerate(values)]
    return instructions,{ins.address:ar.site_kind(ins) for ins in instructions}


def plan(values,roots=(0,BEGIN-4,END,CALLEE),overrides=None):
    instructions,kinds=decode(values);kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(instructions,kinds,roots,ar)


def assert_producer_entry_required(test,module):
    producer=module.BEGIN-4
    valid_roots=(0,producer,module.END,module.CALLEE)
    test.assertEqual((),module.plan(module.fixture(),roots=valid_roots))
    for target in range(module.BEGIN,module.END,4):
        with test.subTest(metadata=target),test.assertRaises(ar.RewriteError):
            module.plan(module.fixture(),roots=valid_roots+(target,))
        for kind in ('b','bl','cbz'):
            values=module.fixture()
            values[0]=(ar.branch(0,target) if kind=='b' else
                       0x94000000|(target//4)&0x3FFFFFF if kind=='bl' else
                       0x34000000|((target//4)&0x7FFFF)<<5)
            if kind=='cbz':values[1]=ar.branch(4,producer)
            with test.subTest(kind=kind,target=target),test.assertRaises(ar.RewriteError):
                ar.rewrite(raw(values),checked_stack=True,package_version=2,
                           entry_offsets=(0,module.END,module.CALLEE))
    # Both known alternate paths reach the producer; the ordinary TLS gate
    # still executes before the native window and is not consumed as raw.
    values=module.fixture();values[0]=0x34000000|((producer//4)&0x7FFFF)<<5
    values[1]=ar.branch(4,producer)
    image=ar.rewrite(raw(values),checked_stack=True,package_version=2,entry_offsets=valid_roots)
    test.assertEqual(raw(values)[module.BEGIN:module.END],image.bytes[module.BEGIN:module.END])
    test.assertIn(producer,[site.offset for site in image.sites])


def assert_unknown_transfers_need_explicit_processed_facts(test,module):
    roots=(0,module.END,module.CALLEE)
    for word in (0xD61F0120,0xD63F0120,0xD65F0120):
        values=module.fixture();values[0]=word
        with test.subTest(unhandled=hex(word)),test.assertRaises(ar.RewriteError):
            ar.rewrite(raw(values),checked_stack=True,package_version=2,entry_offsets=roots)
    # Only actual guarded host lowering may account for an unknown host
    # target; its existing runtime membership checks are still mandatory.
    for word in (0xD61F0120,0xD63F0120):
        values=module.fixture();values[0]=word
        image=ar.rewrite(raw(values),checked_stack=True,package_version=2,entry_offsets=roots,
                         indirect_policy='guarded-host',guarded_indirect_offsets=(0,))
        test.assertEqual(raw(values)[module.BEGIN:module.END],image.bytes[module.BEGIN:module.END])
        test.assertIn(0,[site.offset for site in image.sites])
        test.assertTrue(any(gate.kind==ar.INDIRECT_HOST and gate.argument==9 for gate in image.gates))
    values=module.fixture();values[0]=0xD61F0120;instructions,kinds=decode(values)
    with test.assertRaises(ar.RewriteError):
        ar.android_exclusive.plan_regions(instructions,kinds,roots,ar,native_wait_transfers={0:('finite',())})


def assert_finite_table_targets_keep_producer_entry_checks(test,module):
    values=module.fixture();raw_image=bytearray(0x500);raw_image[:len(values)*4]=raw(values)
    dispatch=0xF0;branch=dispatch+28;table=0x400;producer=module.BEGIN-4
    delta=producer-(dispatch+16)
    address=0x10000000|((delta&3)<<29)|(((delta>>2)&0x7FFFF)<<5)|10
    sequence=(0x7100053F,0x54000008|(((module.END-dispatch-4)//4)&0x7FFFF)<<5,
              0x9000000C,0x9110018C,address,0x3869698B,0x8B0B094A,0xD61F0140)
    struct.pack_into('<8I',raw_image,dispatch,*sequence)
    struct.pack_into('<I',raw_image,0,ar.branch(0,dispatch))
    struct.pack_into('<2B',raw_image,table,0,(module.END-producer)//4)
    options=dict(checked_stack=True,package_version=2,text_size=0x200,
                 code_ranges=((0,len(values)*4),(dispatch,branch+4)),entry_offsets=(0,module.END,module.CALLEE),
                 readonly_ranges=((0x400,0x500),),proven_guest_indirect_offsets=(branch,))
    image=ar.rewrite(bytes(raw_image),**options)
    test.assertEqual(bytes(raw_image[module.BEGIN:module.END]),image.bytes[module.BEGIN:module.END])
    test.assertIn(producer,[site.offset for site in image.sites])
    # The same complete source-derived table now includes the native LDRH
    # after MRS. Its emitted read guard cannot excuse that illegal entry.
    raw_image[table]=1
    with test.assertRaises(ar.RewriteError):ar.rewrite(bytes(raw_image),**options)


def assert_producer_ownership_exclusive(test,module):
    # Synthetic previous/next recognizer contracts exercise only consumer
    # ownership. They do not claim another real family admits a raw MRS.
    from unittest.mock import patch
    engine=ar.android_exclusive;original=engine.native_conditional_refresh
    values=module.fixture();values[1]=0x885F7C2A
    instructions,kinds=decode(values);instructions=instructions[1:]
    def prior(start,by,ks,api):
        return ({4,8,module.BEGIN-4},4,{4}) if start.address==4 else original(start,by,ks,api)
    with patch.object(engine,'native_conditional_refresh',side_effect=prior):
        with test.assertRaisesRegex(ar.RewriteError,'overlapping exclusive'):
            engine.plan_regions(instructions,kinds,(4,module.END,module.CALLEE),ar)
    values=module.fixture();later=len(values)*4;values.append(0x885F7C2A)
    instructions,kinds=decode(values)
    def following(start,by,ks,api):
        return ({module.BEGIN-4,later},later,{later}) if start.address==later else original(start,by,ks,api)
    with patch.object(engine,'native_conditional_refresh',side_effect=following):
        with test.assertRaisesRegex(ar.RewriteError,'overlapping exclusive'):
            engine.plan_regions(instructions,kinds,(0,module.END,module.CALLEE,later),ar)


class Machine:
    """Authored deterministic event/reservation model, not physical wake evidence."""
    def __init__(self,values,old_count,busy=0,release_after=1,failures=0,interrupt=0):
        self.values=values;self.x=[0xAABB000000001000+i for i in range(31)]
        self.x[0],self.x[19]=0x400000,0x500000
        self.sp,self.nzcv,self.q=0x800000,0xB0000000,tuple(range(32))
        self.memory={0x40000C:0x11223344,0x400010:busy,0x400014:0x55667788,
                     0x5000FE:0xABCD,0x500100:old_count,0x500102:interrupt,0x500104:0xFEDC}
        self.release_after,self.failures=release_after,failures
        self.loads=self.stores=self.waits=self.calls=0

    @staticmethod
    def signed(value,bits):
        return value-(1<<bits) if value&(1<<(bits-1)) else value

    def run(self,end=END):
        pc,monitor=0,None
        for _ in range(500):
            if pc==end:
                assert monitor is None
                return
            word=self.values[pc//4];rt,rn=word&31,word>>5&31;next_pc=pc+4
            if word&0xFFC00000==0x79400000:
                self.x[rt]=self.memory[self.x[rn]+(word>>10&0xFFF)*2]&0xFFFF
            elif word&0xFFC00000==0x79000000:
                self.memory[self.x[rn]+(word>>10&0xFFF)*2]=0 if rt==31 else self.x[rt]&0xFFFF
            elif word&0xFFC00000 in (0x91000000,0x11000000):
                bits=64 if word>>31 else 32
                self.x[rt]=(self.x[rn]+(word>>10&0xFFF))&((1<<bits)-1)
            elif word&0xFFE00000==0x52800000:
                self.x[rt]=word>>5&0xFFFF
            elif word&0xFFFFFC00==0x885FFC00:
                self.loads+=1;self.x[rt]=self.memory[self.x[rn]];monitor=self.x[rn]
            elif word&0xFFE0FC00==0x88007C00:
                self.stores+=1;assert monitor==self.x[rn]
                success=self.stores>self.failures
                if success:self.memory[self.x[rn]]=self.x[rt]&0xFFFFFFFF
                self.x[word>>16&31]=0 if success else 1;monitor=None
            elif word==0xD503205F:
                self.waits+=1
                if self.waits>=self.release_after:self.memory[0x400010]=0
            elif word&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(word&0x01000000):
                    next_pc=pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0xFC000000==0x94000000:
                self.calls+=1
                # This adapter never pins threads. Nonzero interrupt flags need
                # a real pin model and cannot receive fabricated SVC success.
                raise ValueError('nonzero interrupt flag requires unsupported pin model')
            elif word&0xFC000000==0x14000000:
                next_pc=pc+self.signed(word&0x3FFFFFF,26)*4
            elif word&0xFFC00000==0xF9800000:
                pass
            elif word&0xFFFFFFE0==0xD53BD060:
                self.x[rt]=0x500000
            else:raise AssertionError(f'unmodeled {pc:x}: {word:08x}')
            pc=next_pc
        raise AssertionError('wait did not acquire: failure, never manufactured success')


class NativeWaitMutexTests(unittest.TestCase):
    def test_unhandled_transfer_context_cannot_invent_tlr_dominance(self):
        assert_unknown_transfers_need_explicit_processed_facts(self,sys.modules[__name__])

    def test_verified_finite_tables_still_reject_native_body_case_entries(self):
        assert_finite_table_targets_keep_producer_entry_checks(self,sys.modules[__name__])

    def test_producer_cannot_be_bypassed_by_metadata_or_ordinary_alternate_entry(self):
        assert_producer_entry_required(self,sys.modules[__name__])

    def test_producer_ownership_cannot_overlap_another_native_window(self):
        assert_producer_ownership_exclusive(self,sys.modules[__name__])

    def test_source_exact_union_stays_native_and_calls_only_real_lowered_svc36(self):
        for rename in (None,{0:1,8:2,9:3,10:4,19:23,20:24,21:25,22:26}):
            values=fixture(rename)
            self.assertEqual(plan(values),())
            image=ar.rewrite(raw(values),entry_offsets=(0,BEGIN-4,END,CALLEE))
            self.assertEqual(image.bytes[BEGIN:END],raw(values)[BEGIN:END])
            self.assertEqual([site.offset for site in image.sites],[BEGIN-4,CALLEE])

    def test_raw_wait_reloads_and_count_remains_old_plus_one_after_acquisition(self):
        for old in (0,1,7,0xFFFF):
            for busy,release,failures in ((0,1,0),(1,1,0),(1,4,0),(0,1,3),(1,3,2)):
                with self.subTest(old=old,busy=busy,release=release,failures=failures):
                    machine=Machine(fixture(),old,busy,release,failures)
                    before=machine.x.copy();memory=machine.memory.copy();machine.run()
                    for register in (8,9,10,20,21,22):before[register]=machine.x[register]
                    self.assertEqual(machine.x,before)
                    memory[0x400010],memory[0x500100]=1,(old+1)&0xFFFF
                    self.assertEqual(machine.memory,memory)
                    self.assertEqual((machine.sp,machine.nzcv,machine.q),(0x800000,0xB0000000,tuple(range(32))))
                    self.assertEqual(machine.calls,0)
                    self.assertGreaterEqual(machine.loads,machine.stores)
                    self.assertEqual(machine.stores,failures+1)
                    self.assertEqual(machine.waits,release if busy else 0)
        machine=Machine(fixture(),0,busy=1,interrupt=1)
        with self.assertRaisesRegex(ValueError,'unsupported pin model'):machine.run()
        self.assertEqual(machine.memory[0x500102],1)

    def test_every_union_interior_entry_and_incoming_edge_is_refused(self):
        for pc in range(BEGIN,END,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):
                plan(fixture(),roots=(0,BEGIN-4,END,CALLEE,pc))
            values=fixture();values[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(values)

    def test_exact_calls_fresh_loads_order_width_and_source_roles_are_required(self):
        helper=ar.android_exclusive.native_wait_mutex
        instructions,kinds=decode(fixture());by_pc={i.address:i for i in instructions}
        heads={BEGIN+offset for offset in (28,48,72,92,112,168)}
        self.assertEqual(helper(by_pc[BEGIN+28],by_pc,kinds,ar),(set(range(BEGIN,END,4)),BEGIN,heads))
        for slot in range(45):
            values=fixture();index=BEGIN//4+slot
            if slot in (33,40):values[index]=0x94000000|((END-(BEGIN+slot*4))//4)&0x3FFFFFF
            else:values[index]^=0x8000 if slot in (7,12,18,23,28,42,14,35) else 1
            try:ins,ks=decode(values)
            except ar.RewriteError:continue  # Earlier strict instruction decoding is also refusal.
            with self.subTest(slot=slot):
                self.assertIsNone(helper(ins[(BEGIN+28)//4],{i.address:i for i in ins},ks,ar))
        for role in (0,8,9,10,19,20,21,22):
            for forbidden in (18,29,30,31,8 if role!=8 else 9):
                ins,ks=decode(fixture({role:forbidden}))
                self.assertIsNone(helper(ins[(BEGIN+28)//4],{i.address:i for i in ins},ks,ar))
        for pc in range(BEGIN,END,4):
            self.assertIsNone(helper(by_pc[BEGIN+28],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))
            with self.assertRaises(ar.RewriteError):plan(fixture(),overrides={pc:'x18'})
        for pc in (CALLEE,CALLEE+4,END):
            self.assertIsNone(helper(by_pc[BEGIN+28],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))
        for word in (0xD40006E1,0xD503201F,0xD4000001):
            values=fixture();values[CALLEE//4]=word;ins,ks=decode(values)
            self.assertIsNone(helper(ins[(BEGIN+28)//4],{i.address:i for i in ins},ks,ar))

    def test_tlr_must_come_from_adjacent_matching_selected_tpidrro_read(self):
        helper=ar.android_exclusive.native_wait_mutex
        for prefix in (0xD503201F,0xD53BD053,0xD53BD074):
            values=fixture();values[(BEGIN-4)//4]=prefix
            instructions,kinds=decode(values);by_pc={i.address:i for i in instructions}
            with self.subTest(prefix=hex(prefix)):
                self.assertIsNone(helper(by_pc[BEGIN+28],by_pc,kinds,ar))
                with self.assertRaises(ar.RewriteError):plan(values)
        instructions,kinds=decode(fixture());by_pc={i.address:i for i in instructions}
        del by_pc[BEGIN-4]
        self.assertIsNone(helper(by_pc[BEGIN+28],by_pc,kinds,ar))
        by_pc={i.address:i for i in instructions};kinds[BEGIN-4]=None
        self.assertIsNone(helper(by_pc[BEGIN+28],by_pc,kinds,ar))

    def test_generic_wfe_or_untyped_call_is_not_enabled(self):
        for middle in (0xD503205F,0x94000004):
            source=[0x885F7D09,middle,0x880A7D09,0x35FFFFAA,0xD65F03C0,0xD65F03C0]
            with self.assertRaises(ar.RewriteError):plan(source,roots=(0,16,20))

    def test_default_kernel_regeneration_retains_the_native_wait_capsule(self):
        # Check composition without pretending the unrelated legacy GOT import
        # currently succeeds. The independent wait capsule has its real --check.
        from unittest.mock import patch
        import gen_android_kernel as generator
        suffix=generator.NATIVE_WAIT_MARKER+b'public capsule marker\n'
        def legacy_import(_source,output,_modules):
            output.mkdir()
            (output/'main.dmag').write_bytes(b'legacy-capsule')
            return {'public':'composition fixture'}
        with patch.object(generator,'assemble',return_value=(b'text',{})), \
             patch.object(generator,'make_kernel_nso',return_value=b'nso'), \
             patch.object(generator,'import_directory',side_effect=legacy_import), \
             patch.object(generator,'native_wait_header',return_value=suffix) as wait:
            outputs=generator.generate(('clang','objcopy'))
        self.assertTrue(outputs['generated_kernel.h'].endswith(suffix))
        self.assertEqual(outputs['generated_kernel.h'].count(generator.NATIVE_WAIT_MARKER),1)
        wait.assert_called_once_with(('clang','objcopy'))


if __name__=='__main__':unittest.main()
