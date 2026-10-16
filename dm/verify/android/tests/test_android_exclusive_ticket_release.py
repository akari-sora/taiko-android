"""Reader-ticket release retains its native retry and retires only invalid exit."""
from pathlib import Path
import struct
import sys
import unittest
from capstone.arm64_const import ARM64_OP_MEM

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from test_android_exclusive_ticket_retirement import RetirementMachine

BEGIN,DONE,FATAL,CALLEE=64,88,160,176


def words(base=0,loaded=8,status=9):
    source=[0xD503201F]*46;source[0]=ar.branch(0,BEGIN)
    source[BEGIN//4:DONE//4]=[
        0x885F7C00|base<<5|loaded,0xF2403C1F|loaded<<5,
        0x54000000|(((FATAL-(BEGIN+8))//4)&0x7FFFF)<<5,
        0x51000400|loaded<<5|loaded,
        0x8800FC00|status<<16|base<<5|loaded,0x35FFFF60|status]
    source[DONE//4]=0xD65F03C0
    source[FATAL//4:FATAL//4+3]=[0xD5033F5F,0x94000000|((CALLEE-(FATAL+4))//4),0xD65F03C0]
    source[CALLEE//4]=0xD65F03C0
    return source


def raw(source):return struct.pack('<'+'I'*len(source),*source)


def plan(source,roots=(0,BEGIN,DONE,FATAL,CALLEE),overrides=None,monitor_retiring_calls=frozenset()):
    ins=[ar.decode(word,index*4) for index,word in enumerate(source)]
    kinds={i.address:ar.site_kind(i) for i in ins};kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ins,kinds,roots,ar,monitor_retiring_calls=monitor_retiring_calls)


class ReleaseMachine(RetirementMachine):
    """Independently execute emitted six-word loop plus unchanged Region backend."""
    def __init__(self,image,initial,failures=0,competitor=None):
        super().__init__(image,initial,failures,competitor);self.x[0]=0x400000

    def run(self):
        pc,monitor=self.image.entry_offset,None
        for _ in range(1000):
            if pc in (DONE,FATAL):
                assert monitor is None and self.sp==self.start_sp
                return pc
            ins=ar.decode(self.load(pc,4),pc);ops,name=ins.operands,ins.mnemonic;next_pc=pc+4
            reg=lambda op:self.name(ins,op)
            value=lambda op:self.value(ins,op)
            if name=='b':next_pc=ops[0].imm
            elif name=='b.eq':
                if self.flags&0x40000000:next_pc=ops[0].imm
            elif name=='cbnz':
                if value(ops[0]):next_pc=ops[1].imm
            elif name=='blr':
                assert monitor is None and value(ops[0])==0x100000+ar.STATE_HELPER
                self.helpers+=1;self.x[30],self.x[16]=next_pc,self.state
            elif name=='mov':self.set_reg(reg(ops[0]),value(ops[1]))
            elif name in ('add','sub'):
                self.set_reg(reg(ops[0]),value(ops[1])+(1 if name=='add' else -1)*value(ops[2]))
            elif name=='tst':
                result=value(ops[0])&value(ops[1]);self.flags=(int(bool(result&0x8000000000000000))<<31)|((result==0)<<30)
            elif name=='clrex':monitor=None;self.clears+=1
            elif name in ('ldxr','stlxr','ldr','str','ldp','stp'):
                mem=next((op for op in ops if op.type==ARM64_OP_MEM),None)
                address=self.get_reg(ins.reg_name(mem.mem.base))+mem.mem.disp if mem is not None else ops[-1].imm
                exclusive_load,exclusive_store=name=='ldxr',name=='stlxr'
                data=ops[1:-1] if exclusive_store else ops[:-1]
                size=4 if reg(data[0]).startswith('w') else 8
                if exclusive_load:
                    assert address==0x400000 and size==4
                    self.loads+=1;monitor=(address,size)
                elif not exclusive_store:
                    assert monitor is None,'ordinary access before retirement'
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
        raise AssertionError('release loop did not finish')


class ExclusiveTicketReleaseTests(unittest.TestCase):
    def test_exact_loop_has_one_retired_exit_and_native_failed_store_retry(self):
        regions=plan(words());self.assertEqual(len(regions),1)
        region=regions[0]
        self.assertEqual({i.address for i in region.instructions},set(range(BEGIN,DONE,4)))
        self.assertEqual(region.retry_edges,frozenset(((BEGIN+20,BEGIN),)))
        self.assertEqual(region.retire_exit_targets,frozenset((FATAL,)))
        self.assertEqual(region.exit_edges,frozenset(((BEGIN+8,FATAL),(BEGIN+20,DONE))))
        self.assertFalse(region.requires_diag_abort_v1)
        self.assertFalse(region.monitor_retiring_call_sites)

    def test_emitted_release_retry_invalid_and_competition_preserve_full_state(self):
        image=ar.rewrite(raw(words()),entry_offsets=(0,BEGIN,DONE,FATAL,CALLEE))
        cases=((1,0,None,DONE,0,0,1,1,0,0),(9,3,None,DONE,8,0,4,4,0,0),
               (0,0,None,FATAL,0,0x109,1,0,1,0x40000000),
               (0x10000,0,None,FATAL,0x10000,0x109,1,0,1,0x40000000),
               (0xFFFFFFFF,0,None,DONE,0xFFFFFFFE,0,1,1,0,0),
               (9,1,0,FATAL,0,1,2,1,1,0x40000000))
        for initial,failures,competitor,target,loaded,status,loads,stores,clears,flags in cases:
            with self.subTest(initial=initial,failures=failures,competitor=competitor):
                machine=ReleaseMachine(image,initial,failures,competitor);before=machine.x.copy()
                self.assertEqual(machine.run(),target);before[8],before[9]=loaded,status
                self.assertEqual(machine.x,before)
                self.assertEqual((machine.sp,machine.flags,machine.q),
                                 (machine.start_sp,flags,tuple(bytes([i])*16 for i in range(32))))
                final=loaded if target==DONE else competitor if competitor is not None else initial
                self.assertEqual((machine.load(0x3FFFFC,4),machine.load(0x400000,4),machine.load(0x400004,4)),
                                 (0x11223344,final,0x55667788))
                self.assertEqual((machine.loads,machine.stores,machine.clears,machine.helpers),(loads,stores,clears,1))
                self.assertEqual((machine.load(machine.state-8,8),machine.load(machine.state,8),machine.load(machine.state+8,8)),
                                 (0x1234567890ABCDEF,0x1818181818181818,0xFEDCBA0987654321))

    def test_forced_contract_is_explicit_and_only_actual_used_call_is_reported(self):
        source=words();source[FATAL//4]=0x94000000|((CALLEE-FATAL)//4)
        with self.assertRaises(ar.RewriteError):plan(source)
        region=plan(source,monitor_retiring_calls=frozenset((FATAL,)))[0]
        self.assertTrue(region.requires_diag_abort_v1)
        self.assertEqual(region.monitor_retiring_call_sites,frozenset((FATAL,)))
        self.assertFalse(plan(words(),monitor_retiring_calls=frozenset((FATAL+4,)))[0].requires_diag_abort_v1)

    def test_shape_width_order_role_and_entry_guarantees_remain_strict(self):
        helper=ar.android_exclusive.retiring_ticket_attempt
        def candidate(source):
            ins=[ar.decode(word,index*4) for index,word in enumerate(source)]
            return helper(ins[BEGIN//4],{i.address:i for i in ins},{i.address:ar.site_kind(i) for i in ins},ar)
        for roles in ((0,8,9),(19,10,11),(24,16,17)):
            self.assertIsNotNone(candidate(words(*roles)))
        for role in range(3):
            for forbidden in (18,29,30,31,(0,8,9)[(role+1)%3]):
                roles=[0,8,9];roles[role]=forbidden
                self.assertIsNone(candidate(words(*roles)))
        for slot,mask in ((0,0x8000),(0,0x40000000),(1,0x80400000),(2,1),(3,1),(4,0x8000),(5,1)):
            source=words();source[BEGIN//4+slot]^=mask
            self.assertIsNone(candidate(source))
        for pc in range(BEGIN+4,DONE,4):
            with self.assertRaises(ar.RewriteError):plan(words(),roots=(0,BEGIN,DONE,FATAL,CALLEE,pc))
            source=words();source[1]=ar.branch(4,pc)
            with self.assertRaises(ar.RewriteError):plan(source)
        source=words();source[FATAL//4]=0x88097C08
        self.assertIsNone(candidate(source))
        for pc in range(BEGIN,DONE,4):
            with self.assertRaises(ar.RewriteError):plan(words(),overrides={pc:'x18'})


if __name__=='__main__':unittest.main()
