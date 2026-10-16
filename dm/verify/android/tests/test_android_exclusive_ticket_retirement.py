"""A ticket-count attempt retires live exits before any ordinary host boundary."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from capstone.arm64_const import ARM64_OP_MEM
from test_android_rewrite import Machine

BEGIN,MISMATCH,STORE,FATAL,SUCCESS,CALLEE=64,16,96,160,112,176


def words(base=19,loaded=8,temp=9):
    values=[0xD503201F]*46
    values[0]=ar.branch(0,BEGIN)
    values[MISMATCH//4]=0xD5033F5F
    values[(MISMATCH+4)//4]=0xD65F03C0
    values[BEGIN//4:STORE//4]=[
        0x885FFC00|base<<5|loaded,
        0x53105C00|loaded<<5|temp,
        0x6B40601F|loaded<<16|temp<<5,
        0x54000001|(((MISMATCH-(BEGIN+12))//4)&0x7FFFF)<<5,
        0x11000400|loaded<<5|loaded,
        0x72003C1F|loaded<<5,
        0x54000000|(((FATAL-(BEGIN+24))//4)&0x7FFFF)<<5,
        0x88007C00|temp<<16|base<<5|loaded]
    values[STORE//4]=0x34000000|(((SUCCESS-STORE)//4)&0x7FFFF)<<5|temp
    values[STORE//4+1]=ar.branch(STORE+4,BEGIN)
    values[SUCCESS//4]=0xD65F03C0
    # A selected ordinary callable that can return: never infer noreturn from
    # its name or declare an unknown callee safe while a reservation is live.
    values[FATAL//4]=0xD5033F5F
    values[FATAL//4+1]=0x94000000|((CALLEE-(FATAL+4))//4)
    values[FATAL//4+2]=values[CALLEE//4]=0xD65F03C0
    return values


def raw(values):return struct.pack('<'+'I'*len(values),*values)


def plan(values,roots=(0,BEGIN,MISMATCH,STORE,FATAL,SUCCESS,CALLEE),overrides=None,
         monitor_retiring_calls=frozenset()):
    ins=[ar.decode(word,index*4) for index,word in enumerate(values)]
    kinds={i.address:ar.site_kind(i) for i in ins};kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ins,kinds,roots,ar,
                                            monitor_retiring_calls=monitor_retiring_calls)


class RetirementMachine(Machine):
    """Execute the actual emitted instructions; reject every live scratch access."""
    def __init__(self,image,initial,failures=0,competitor=None):
        super().__init__(image)
        self.x[19]=0x400000
        self.flags=0xB0000000
        self.q=tuple(bytes([i])*16 for i in range(32))
        self.store(0x3FFFFC,0x11223344,4);self.store(0x400000,initial,4);self.store(0x400004,0x55667788,4)
        self.store(self.state-8,0x1234567890ABCDEF,8)
        self.store(self.state,0x1818181818181818,8)
        self.store(self.state+8,0xFEDCBA0987654321,8)
        self.store(self.start_sp,0x13572468ABCDEF01,8)
        self.failures,self.competitor=failures,competitor
        self.loads=self.stores=self.clears=self.helpers=0

    def compare(self,left,right):
        left&=0xFFFFFFFF;right&=0xFFFFFFFF;result=(left-right)&0xFFFFFFFF
        overflow=bool((left^right)&(left^result)&0x80000000)
        self.flags=((int(bool(result&0x80000000))<<3)|((result==0)<<2)|((left>=right)<<1)|overflow)<<28

    def run(self):
        pc,monitor=self.image.entry_offset,None
        for _ in range(1000):
            if pc in (MISMATCH,FATAL,SUCCESS):
                assert monitor is None and self.sp==self.start_sp
                return pc
            if pc==STORE:
                assert monitor is None and self.sp==self.start_sp
                if self.x[9]:pc=BEGIN;continue
                return SUCCESS
            ins=ar.decode(self.load(pc,4),pc);ops,name=ins.operands,ins.mnemonic;next_pc=pc+4
            reg=lambda op:self.name(ins,op)
            value=lambda op:self.value(ins,op)
            if name=='b':next_pc=ops[0].imm
            elif name in ('b.eq','b.ne'):
                if bool(self.flags&0x40000000)==(name=='b.eq'):next_pc=ops[0].imm
            elif name=='blr':
                assert monitor is None,'state accessor called while monitor live'
                assert value(ops[0])==0x100000+ar.STATE_HELPER
                self.helpers+=1;self.x[30],self.x[16]=next_pc,self.state
            elif name=='mov':self.set_reg(reg(ops[0]),value(ops[1]))
            elif name in ('add','sub'):
                self.set_reg(reg(ops[0]),value(ops[1])+(1 if name=='add' else -1)*value(ops[2]))
            elif name=='ubfx':
                self.set_reg(reg(ops[0]),(value(ops[1])>>ops[2].imm)&((1<<ops[3].imm)-1))
            elif name=='cmp':
                right=self.get_reg(reg(ops[1]))>>ops[1].shift.value
                self.compare(value(ops[0]),right)
            elif name=='tst':
                result=value(ops[0])&value(ops[1]);self.flags=(int(bool(result&0x80000000))<<31)|((result==0)<<30)
            elif name=='clrex':monitor=None;self.clears+=1
            elif name in ('ldaxr','stxr','ldr','str','ldp','stp'):
                mem=next((op for op in ops if op.type==ARM64_OP_MEM),None)
                address=self.get_reg(ins.reg_name(mem.mem.base))+mem.mem.disp if mem is not None else ops[-1].imm
                exclusive_load,exclusive_store=name=='ldaxr',name=='stxr'
                data=ops[1:-1] if exclusive_store else ops[:-1]
                size=4 if reg(data[0]).startswith('w') else 8
                if exclusive_load:
                    assert address==0x400000 and size==4
                    self.loads+=1;monitor=(address,size)
                elif not exclusive_store:
                    assert monitor is None,'ordinary memory write/read before real CLREX'
                    if mem is not None and ins.reg_name(mem.mem.base)=='sp':
                        assert self.sp<=address and address+size*len(data)<=self.start_sp
                success=True
                if exclusive_store:
                    assert monitor==(address,size)
                    self.stores+=1;success=self.stores>self.failures
                    if not success and self.competitor is not None:self.store(address,self.competitor,4)
                    self.set_reg(reg(ops[0]),0 if success else 1);monitor=None
                if success:
                    for index,op in enumerate(data):
                        if name.startswith('ld'):self.set_reg(reg(op),self.load(address+index*size,size))
                        else:self.store(address+index*size,value(op),size)
            elif name!='nop':raise AssertionError(f'unmodeled {name} {ins.op_str}')
            pc=next_pc
        raise AssertionError('emitted attempt did not terminate')


class ExclusiveTicketRetirementTests(unittest.TestCase):
    def test_source_exact_attempt_has_two_explicit_live_retirement_exits(self):
        regions=plan(words())
        self.assertEqual(len(regions),1)
        region=regions[0]
        self.assertEqual(region.entry,BEGIN)
        self.assertEqual({i.address for i in region.instructions},set(range(BEGIN,STORE,4)))
        self.assertEqual(region.retire_exit_targets,frozenset((MISMATCH,FATAL)))
        self.assertFalse(region.requires_diag_abort_v1)
        self.assertEqual(region.monitor_retiring_call_sites,frozenset())
        self.assertEqual(region.reservation_terminals,frozenset((BEGIN+28,)))
        self.assertEqual(region.retry_edges,frozenset())
        self.assertEqual(region.exit_edges,frozenset(((BEGIN+12,MISMATCH),(BEGIN+24,FATAL),(BEGIN+28,STORE))))

    def test_outside_old_token_store_cannot_be_hidden_by_retirement(self):
        source=words()
        source[MISMATCH//4:MISMATCH//4+3]=[
            0x88097E68,
            0x35000009|(((BEGIN-(MISMATCH+4))//4)&0x7FFFF)<<5,
            0xD65F03C0]
        with self.assertRaises(ar.RewriteError):plan(source)

    def test_continuation_proof_refuses_opaque_calls_returns_cycles_and_missing_code(self):
        helper=ar.android_exclusive.ticket_continuation_retires
        def context(source):
            ins=[ar.decode(word,index*4) for index,word in enumerate(source)]
            return {i.address:i for i in ins},{i.address:ar.site_kind(i) for i in ins}
        for first in (0xD65F03C0,0xD63F0160,ar.branch(MISMATCH,MISMATCH),
                      0x94000000|((CALLEE-MISMATCH)//4)):
            source=words();source[MISMATCH//4]=first;by_pc,kinds=context(source)
            with self.subTest(first=hex(first)):
                self.assertFalse(helper(MISMATCH,by_pc,kinds,ar))
                with self.assertRaises(ar.RewriteError):plan(source)
        # A selected direct SVC36/RET is the existing typed retirement boundary,
        # unlike an arbitrary selected BL or interposable PLT.
        source=words();source[MISMATCH//4]=0x94000000|((CALLEE-MISMATCH)//4)
        source[CALLEE//4:CALLEE//4+2]=[0xD40006C1,0xD65F03C0]
        by_pc,kinds=context(source)
        self.assertTrue(helper(MISMATCH,by_pc,kinds,ar))
        for changed in (MISMATCH,CALLEE,CALLEE+4):
            missing=by_pc.copy();missing.pop(changed)
            self.assertFalse(helper(MISMATCH,missing,kinds,ar))
        kinds[MISMATCH]='x18';self.assertFalse(helper(MISMATCH,by_pc,kinds,ar))
        source[CALLEE//4]=0xD40006E1;by_pc,kinds=context(source)
        self.assertFalse(helper(MISMATCH,by_pc,kinds,ar))

    def test_verified_forced_boundary_is_required_only_when_reached_and_used(self):
        source=words()
        source[FATAL//4]=0x94000000|((CALLEE-FATAL)//4)
        with self.assertRaises(ar.RewriteError):plan(source)
        regions=plan(source,monitor_retiring_calls=frozenset((FATAL,)))
        self.assertEqual(len(regions),1)
        self.assertTrue(regions[0].requires_diag_abort_v1)
        self.assertEqual(regions[0].monitor_retiring_call_sites,frozenset((FATAL,)))
        # This component receives a verified immutable source-callsite proof;
        # the production NSO verifier separately checks exact ABI PLT/GOT/name.
        # A proof after an already closed source path is not a used requirement.
        unused=plan(words(),monitor_retiring_calls=frozenset((FATAL+4,)))
        self.assertFalse(unused[0].requires_diag_abort_v1)
        self.assertEqual(unused[0].monitor_retiring_call_sites,frozenset())
        for malformed in ({FATAL},(FATAL,),frozenset(('160',)),frozenset((FATAL+1,))):
            with self.subTest(proof=malformed),self.assertRaisesRegex(ar.RewriteError,'immutable aligned'):
                plan(source,monitor_retiring_calls=malformed)

    def test_verified_call_offsets_do_not_authorize_indirects_old_stores_or_partial_proofs(self):
        helper=ar.android_exclusive.retiring_ticket_attempt
        source=words();source[FATAL//4]=0xD63F0160
        with self.assertRaises(ar.RewriteError):
            plan(source,monitor_retiring_calls=frozenset((FATAL,)))
        source=words();source[MISMATCH//4]=0x88097E68
        source[FATAL//4]=0x94000000|((CALLEE-FATAL)//4)
        with self.assertRaises(ar.RewriteError):
            plan(source,monitor_retiring_calls=frozenset((MISMATCH,FATAL)))
        source=words();source[MISMATCH//4]=0x94000000|((CALLEE-MISMATCH)//4)
        source[FATAL//4]=0x88097E68
        ins=[ar.decode(word,index*4) for index,word in enumerate(source)]
        kinds={i.address:ar.site_kind(i) for i in ins};by_pc={i.address:i for i in ins}
        self.assertIsNone(helper(by_pc[BEGIN],by_pc,kinds,ar,
                                 monitor_retiring_calls=frozenset((MISMATCH,))))
        used=set()
        self.assertFalse(ar.android_exclusive.ticket_continuation_retires(
            FATAL,by_pc,kinds,ar,monitor_retiring_calls=frozenset((MISMATCH,)),used_contracts=used))
        self.assertEqual(used,set())

    def test_emitted_live_exits_clear_before_memory_flags_registers_or_host_boundary(self):
        image=ar.rewrite(raw(words()),entry_offsets=(0,BEGIN,MISMATCH,STORE,FATAL,SUCCESS,CALLEE))
        cases=((0x01010002,0,None,SUCCESS,0x01010003,0,1,1,0,0),
               (0,0,None,SUCCESS,1,0,1,1,0,0),
               (0x01020002,0,None,MISMATCH,0x01020002,2,1,0,1,0x20000000),
               (0x0101FFFF,0,None,FATAL,0x01020000,1,1,0,1,0x40000000),
               (0x01010002,3,None,SUCCESS,0x01010003,0,4,4,0,0),
               (0x01010002,1,0x01020002,MISMATCH,0x01020002,2,2,1,1,0x20000000),
               (0x01010002,1,0x0101FFFF,FATAL,0x01020000,1,2,1,1,0x40000000))
        for initial,failures,competitor,target,loaded,temp,loads,stores,clears,flags in cases:
            with self.subTest(initial=initial,failures=failures,competitor=competitor):
                machine=RetirementMachine(image,initial,failures,competitor)
                before=machine.x.copy()
                self.assertEqual(machine.run(),target)
                before[8],before[9]=loaded,temp
                self.assertEqual(machine.x,before)
                final=loaded if target==SUCCESS else competitor if competitor is not None else initial
                self.assertEqual((machine.load(0x3FFFFC,4),machine.load(0x400000,4),machine.load(0x400004,4)),
                                 (0x11223344,final,0x55667788))
                self.assertEqual((machine.loads,machine.stores,machine.clears,machine.helpers),(loads,stores,clears,loads))
                self.assertEqual((machine.sp,machine.flags,machine.q),
                                 (machine.start_sp,flags,tuple(bytes([i])*16 for i in range(32))))
                self.assertEqual((machine.load(machine.state-8,8),machine.load(machine.state,8),machine.load(machine.state+8,8)),
                                 (0x1234567890ABCDEF,0x1818181818181818,0xFEDCBA0987654321))
                self.assertEqual(machine.load(machine.start_sp,8),0x13572468ABCDEF01)

    def test_no_unknown_call_indirect_width_role_or_interior_entry_is_admitted(self):
        for pc in range(BEGIN+4,STORE,4):
            with self.subTest(root=pc),self.assertRaises(ar.RewriteError):
                plan(words(),roots=(0,BEGIN,MISMATCH,STORE,FATAL,SUCCESS,CALLEE,pc))
            source=words();source[1]=ar.branch(4,pc)
            with self.subTest(edge=pc),self.assertRaises(ar.RewriteError):plan(source)
        for index in range(1,8):
            source=words();source[BEGIN//4+index]=0xD63F0160
            with self.subTest(indirect=index),self.assertRaises(ar.RewriteError):plan(source)
        for pc in range(BEGIN,STORE,4):
            with self.assertRaises(ar.RewriteError):plan(words(),overrides={pc:'x18'})

    def test_mixed_twenty_and_sixteen_byte_exit_stubs_retire_before_cleanup(self):
        from dataclasses import replace
        region=plan(words())[0]
        image=ar.rewrite(raw(words()),entry_offsets=(0,BEGIN,MISMATCH,STORE,FATAL,SUCCESS,CALLEE))
        trampoline=next(site.trampoline for site in image.sites if site.offset==BEGIN)
        clears=[];closed=[]
        for pc in range(trampoline,len(image.bytes)-4,4):
            word=struct.unpack_from('<I',image.bytes,pc)[0]
            if word==0xD5033F5F:
                tail=[ar.decode(struct.unpack_from('<I',image.bytes,pc+4+i*4)[0],pc+4+i*4) for i in range(4)]
                self.assertEqual([i.mnemonic for i in tail],['str','ldp','add','b'])
                self.assertIn(tail[-1].operands[-1].imm,(MISMATCH,FATAL))
                self.assertEqual(tail[2].op_str,'sp, sp, #0x20')
                clears.append(tail[-1].operands[-1].imm)
            if word&0xFC000000==0x14000000:
                branch=ar.decode(word,pc)
                if branch.operands[-1].imm==STORE:
                    tail=[ar.decode(struct.unpack_from('<I',image.bytes,pc-12+i*4)[0],pc-12+i*4) for i in range(4)]
                    self.assertEqual([i.mnemonic for i in tail],['str','ldp','add','b'])
                    closed.append(pc-12)
        self.assertEqual(sorted(clears),[MISMATCH,FATAL]);self.assertEqual(len(closed),1)
        invalid=replace(region,retire_exit_targets=frozenset((BEGIN,)))
        with self.assertRaisesRegex(ar.RewriteError,'retirement target outside'):
            ar.android_exclusive.emit_region(ar.Emitter(raw(words())),invalid,ar)

    def test_only_exact_width_order_registers_and_selected_live_targets_qualify(self):
        helper=ar.android_exclusive.retiring_ticket_attempt
        def candidate(values):
            ins=[ar.decode(word,index*4) for index,word in enumerate(values)]
            kinds={i.address:ar.site_kind(i) for i in ins}
            return helper(ins[BEGIN//4],{i.address:i for i in ins},kinds,ar)
        for base,loaded,temp in ((19,8,9),(24,16,17),(0,1,2)):
            self.assertIsNotNone(candidate(words(base,loaded,temp)))
        for role in range(3):
            for forbidden in (18,29,30,31,(19,8,9)[(role+1)%3]):
                roles=[19,8,9];roles[role]=forbidden
                with self.subTest(role=role,forbidden=forbidden):
                    self.assertIsNone(candidate(words(*roles)))
        for slot in range(8):
            values=words();values[BEGIN//4+slot]^=0x8000 if slot in (0,7) else 1
            try:result=candidate(values)
            except ar.RewriteError:continue
            with self.subTest(slot=slot):self.assertIsNone(result)
        ins=[ar.decode(word,index*4) for index,word in enumerate(words())]
        kinds={i.address:ar.site_kind(i) for i in ins};by_pc={i.address:i for i in ins}
        for pc in tuple(range(BEGIN,STORE,4))+(MISMATCH,FATAL,STORE):
            self.assertIsNone(helper(by_pc[BEGIN],{p:i for p,i in by_pc.items() if p!=pc},kinds,ar))


if __name__=='__main__':unittest.main()
