"""Writer-ticket acquire preserves native retry and retires its fatal exit."""
from pathlib import Path
import struct
import sys
import unittest
from capstone.arm64_const import ARM64_OP_MEM

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from test_android_exclusive_ticket_retirement import RetirementMachine

BEGIN,CLOSED,SUCCESS,FATAL,CALLEE=64,100,128,160,176


def words(base=19,loaded=8,temp=9,status=10,increment=21):
    result=[0xD503201F]*46
    result[0]=ar.branch(0,BEGIN)
    result[BEGIN//4:CLOSED//4]=[
        0x885FFC00|base<<5|loaded,
        0xD3587C00|loaded<<5|temp,
        0x4B404000|loaded<<16|temp<<5|temp,
        0x2A2003E0|temp<<16|temp,
        0x72001C1F|temp<<5,
        0x54000000|(((FATAL-(BEGIN+20))//4)&0x7FFFF)<<5,
        0x0B000000|increment<<16|loaded<<5|temp,
        0x88007C00|status<<16|base<<5|temp,
        0x34000000|(((SUCCESS-(BEGIN+32))//4)&0x7FFFF)<<5|status,
    ]
    result[CLOSED//4]=ar.branch(CLOSED,BEGIN)
    result[SUCCESS//4]=0xD65F03C0
    result[FATAL//4:FATAL//4+3]=[0xD5033F5F,
        0x94000000|((CALLEE-(FATAL+4))//4),0xD65F03C0]
    result[CALLEE//4]=0xD65F03C0
    return result


def plan(source,roots=(0,BEGIN,CLOSED,SUCCESS,FATAL,CALLEE),proof=frozenset()):
    instructions=[ar.decode(word,index*4) for index,word in enumerate(source)]
    kinds={ins.address:ar.site_kind(ins) for ins in instructions}
    return ar.android_exclusive.plan_regions(instructions,kinds,roots,ar,
                                              monitor_retiring_calls=proof)


class WriterMachine(RetirementMachine):
    """Independent status/monitor model for the emitted native writer path."""
    def __init__(self,image,initial,failures=0,competitor=None):
        super().__init__(image,initial,failures,competitor)
        self.x[21]=0x01000000

    def run(self):
        pc,monitor=self.image.entry_offset,None
        for _ in range(1200):
            if pc in (SUCCESS,FATAL):
                assert monitor is None and self.sp==self.start_sp
                return pc
            ins=ar.decode(self.load(pc,4),pc);ops,name=ins.operands,ins.mnemonic;next_pc=pc+4
            reg=lambda op:self.name(ins,op)
            value=lambda op:self.value(ins,op)
            if name=='b':next_pc=ops[0].imm
            elif name=='b.eq':
                if self.flags&0x40000000:next_pc=ops[0].imm
            elif name=='cbz':
                if value(ops[0])==0:next_pc=ops[1].imm
            elif name=='blr':
                assert monitor is None and value(ops[0])==0x100000+ar.STATE_HELPER
                self.helpers+=1;self.x[30],self.x[16]=next_pc,self.state
            elif name=='mov':self.set_reg(reg(ops[0]),value(ops[1]))
            elif name=='ubfx':
                self.set_reg(reg(ops[0]),(value(ops[1])>>ops[2].imm)&((1<<ops[3].imm)-1))
            elif name=='mvn':self.set_reg(reg(ops[0]),~value(ops[1]))
            elif name in ('add','sub'):
                operand=(self.get_reg(reg(ops[2]))>>ops[2].shift.value
                         if name=='sub' and ops[2].shift.value else value(ops[2]))
                self.set_reg(reg(ops[0]),value(ops[1])+(operand if name=='add' else -operand))
            elif name=='tst':
                result=value(ops[0])&value(ops[1]);self.flags=(int(bool(result&0x80000000))<<31)|((result==0)<<30)
            elif name=='clrex':monitor=None;self.clears+=1
            elif name in ('ldaxr','stxr','ldr','str','ldp','stp'):
                mem=next((operand for operand in ops if operand.type==ARM64_OP_MEM),None)
                address=self.get_reg(ins.reg_name(mem.mem.base))+mem.mem.disp if mem is not None else ops[-1].imm
                size=4 if (name in ('ldaxr','stxr') or reg(ops[0]).startswith('w')) else 8
                if name=='ldaxr':
                    assert address==0x400000 and monitor is None
                    self.loads+=1;monitor=(address,size)
                    self.set_reg(reg(ops[0]),self.load(address,size))
                elif name=='stxr':
                    assert monitor==(address,size)
                    self.stores+=1;success=self.stores>self.failures
                    if success:self.store(address,value(ops[1]),size)
                    elif self.competitor is not None:self.store(address,self.competitor,size)
                    self.set_reg(reg(ops[0]),0 if success else 1);monitor=None
                else:
                    assert monitor is None,'ordinary state/stack access before retirement'
                    if mem is not None and ins.reg_name(mem.mem.base)=='sp':
                        assert self.sp<=address and address+16<=self.start_sp
                    data=ops[:-1]
                    for index,op in enumerate(data):
                        if name.startswith('ld'):self.set_reg(reg(op),self.load(address+index*size,size))
                        else:self.store(address+index*size,value(op),size)
            elif name!='nop':raise AssertionError(f'unmodeled {name} {ins.op_str}')
            pc=next_pc
        raise AssertionError('writer attempt exhausted bounded execution')


class WriterTicketTests(unittest.TestCase):
    def test_exact_attempt_has_closed_store_exits_and_live_fatal_retirement(self):
        regions=plan(words());self.assertEqual(len(regions),1)
        region=regions[0]
        self.assertEqual((region.entry,len(region.instructions)),(BEGIN,9))
        self.assertEqual(region.reservation_terminals,frozenset((BEGIN+28,)))
        self.assertEqual(region.exit_edges,frozenset(((BEGIN+20,FATAL),
                                                      (BEGIN+32,SUCCESS),(BEGIN+32,CLOSED))))
        self.assertEqual(region.retire_exit_targets,frozenset((FATAL,)))
        self.assertFalse(region.requires_diag_abort_v1)
        image=ar.rewrite(struct.pack('<'+'I'*len(words()),*words()),
                         entry_offsets=(0,BEGIN,CLOSED,SUCCESS,FATAL,CALLEE))
        self.assertTrue(any(site.offset==BEGIN for site in image.sites))

    def test_real_fatal_contract_is_required_only_when_used(self):
        source=words();source[FATAL//4]=0x94000000|((CALLEE-FATAL)//4)
        with self.assertRaises(ar.RewriteError):plan(source)
        region=plan(source,proof=frozenset((FATAL,)))[0]
        self.assertTrue(region.requires_diag_abort_v1)
        self.assertEqual(region.monitor_retiring_call_sites,frozenset((FATAL,)))
        self.assertFalse(plan(words(),proof=frozenset((FATAL+4,)))[0].requires_diag_abort_v1)

    def test_unknown_shape_or_independent_interior_entry_never_qualifies(self):
        for pc in range(BEGIN+4,CLOSED,4):
            with self.assertRaises(ar.RewriteError):
                plan(words(),roots=(0,BEGIN,CLOSED,SUCCESS,FATAL,CALLEE,pc))
        for index in range(9):
            source=words();source[BEGIN//4+index]^=1
            with self.assertRaises(ar.RewriteError):plan(source)

    def test_hardware_status_retry_fatal_and_competing_writer_keep_full_state(self):
        source=words();image=ar.rewrite(struct.pack('<'+'I'*len(source),*source),
                                         entry_offsets=(0,BEGIN,CLOSED,SUCCESS,FATAL,CALLEE))
        cases=((0x01000000,0,None,SUCCESS,0x02000000,1,1,0,1,0),
               (0xFF000000,0,None,FATAL,0xFF000000,1,0,1,1,0x40000000),
               (0x01000000,3,None,SUCCESS,0x02000000,4,4,0,4,0),
               (0x01000000,1,0xFF000000,FATAL,0xFF000000,2,1,1,2,0x40000000))
        for initial,failures,competitor,target,final,loads,stores,clears,helpers,flags in cases:
            with self.subTest(initial=initial,failures=failures,competitor=competitor):
                machine=WriterMachine(image,initial,failures,competitor);before=machine.x.copy()
                self.assertEqual(machine.run(),target)
                before[8]=initial if not competitor or target==SUCCESS else competitor
                if target==SUCCESS:
                    before[9]=final
                else:
                    difference=(before[8]>>24)-(before[8]>>16)
                    before[9]=(~difference)&0xffffffff
                if stores:before[10]=0 if target==SUCCESS else 1
                self.assertEqual(machine.x,before)
                self.assertEqual((machine.sp,machine.q,machine.flags),(machine.start_sp,
                                  tuple(bytes([i])*16 for i in range(32)),flags))
                self.assertEqual((machine.loads,machine.stores,machine.clears,machine.helpers),
                                 (loads,stores,clears,helpers))
                self.assertEqual((machine.load(0x3FFFFC,4),machine.load(0x400000,4),machine.load(0x400004,4)),
                                 (0x11223344,final,0x55667788))


if __name__=='__main__':unittest.main()
