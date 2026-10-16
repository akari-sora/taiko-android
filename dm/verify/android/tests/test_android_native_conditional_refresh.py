"""Three finite native CAS schedules share refresh code across reservations."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar

BEGIN = 16
TEMPLATES = (
    (0x885FFD0A,0x6B09015F,0x54000100,0x7100055F,0xD5033F5F,0x2A0A03E9,
     0x540006EB,0x885FFD0A,0x6B09015F,0x54FFFF41,0x11000529,0x880B7D09,
     0x7100017F,0x7A411948,0x2A0A03E9,0x54FFFF0A),
    (0x885FFD49,0x6B0B013F,0x54000100,0xD5033F5F,0x7100053F,0x5400044B,
     0x2A0903EB,0x885FFD49,0x6B0B013F,0x54FFFF41,0x880B7D5F,0x35FFFF2B),
    (0xD5033F5F,0x2A0B03EA,0x3400014A,0x7100095F,0x540000E0,0x885FFD2B,
     0x6B0A017F,0x54FFFF21,0x880C7D28,0x2A0B03EA,0x35FFFF0C),
)
FIELDS = (
    ((0,5),(5,16),(),(5,),(),(0,16),(),(0,5),(5,16),(),(0,5),(0,5,16),
     (5,),(5,),(0,16),()),
    ((0,5),(5,16),(),(),(5,),(),(0,16),(0,5),(5,16),(),(0,5,16),(0,)),
    ((),(0,16),(0,),(5,),(),(0,5),(5,16),(),(0,5,16),(0,16),(0,)),
)


def fixture(variant, rename=None):
    block = list(TEMPLATES[variant])
    for i, shifts in enumerate(FIELDS[variant]):
        original = block[i]
        for shift in shifts:
            role = original >> shift & 31
            if rename and role != 31:
                block[i] = block[i] & ~(31 << shift) | rename.get(role,role) << shift
    end = BEGIN + len(block)*4
    reject = end + 12
    for index in ((6,) if variant == 0 else (5,) if variant == 1 else (2,4)):
        at = BEGIN + index*4
        target = end if variant == 2 and index == 4 else reject
        block[index] = block[index] & ~(0x7FFFF << 5) | (((target-at)//4)&0x7FFFF)<<5
    entry = BEGIN + (12 if variant == 2 else 0)
    values = [ar.branch(0,entry),0xD503201F,0xD503201F,ar.branch(12,entry)] + block + [0xD65F03C0]*4
    if len(values)%2:
        values.append(0xD503201F)
    return values,entry,end,reject


def raw(values):
    return struct.pack('<'+'I'*len(values),*values)


def decoded(values):
    ins = [ar.decode(word,i*4) for i,word in enumerate(values)]
    return ins,{item.address: ar.site_kind(item) for item in ins}


def plan(values,roots,overrides=None):
    ins,kinds = decoded(values)
    kinds.update(overrides or {})
    return ar.android_exclusive.plan_regions(ins,kinds,roots,ar)


class Machine:
    """Decode raw words independently; deterministic reservation loss is explicit."""
    def __init__(self,values,variant,initial,expected=1,failures=0,competitor=None,data=7):
        self.values,self.variant = values,variant
        self.x = [0xC0FFEE0000000100+i for i in range(31)]
        base,loaded,expect,status = ((8,10,9,11),(10,9,11,11),(9,11,10,12))[variant]
        self.roles = base,loaded,expect,status
        self.x[base],self.x[expect] = 0x400000,0xFEED000000000000|expected
        if variant == 2:
            self.x[8] = 0xABCD000000000000|data
        self.memory = {0x3FFFFC:0x12345678,0x400000:initial,0x400004:0xDEADBEEF}
        self.sp,self.flags,self.q = 0x800000,0x10000000,tuple(range(32))
        self.failures,self.competitor = failures,competitor
        self.loads = self.stores = self.clears = self.writes = 0
        self.ccmp = []

    @staticmethod
    def signed(value,bits):
        return value-(1<<bits) if value&(1<<(bits-1)) else value

    def cmp(self,left,right):
        left,right = left&0xFFFFFFFF,right&0xFFFFFFFF
        result = (left-right)&0xFFFFFFFF
        overflow = bool((left^right)&(left^result)&0x80000000)
        self.flags = ((int(bool(result&0x80000000))<<3)|((result==0)<<2)|
                      ((left>=right)<<1)|overflow)<<28

    def condition(self,code):
        n,z,v = (bool(self.flags & mask) for mask in (0x80000000,0x40000000,0x10000000))
        return {0:z,1:not z,10:n==v,11:n!=v}[code]

    def run(self):
        _,entry,end,reject = fixture(self.variant)
        pc,monitor = 0,None
        for _ in range(400):
            if pc in (end,reject):
                assert monitor is None
                return 'success' if pc == end else 'reject'
            word = self.values[pc//4]
            rt,rn = word&31,word>>5&31
            next_pc = pc+4
            if word&0xFFFFFC00 == 0x885FFC00:
                self.loads += 1
                self.x[rt] = self.memory[self.x[rn]]&0xFFFFFFFF
                monitor = self.x[rn]
            elif word&0xFFE0FC00 == 0x88007C00:
                self.stores += 1
                assert monitor == self.x[rn]
                success = self.stores > self.failures
                if success:
                    self.memory[self.x[rn]] = 0 if rt == 31 else self.x[rt]&0xFFFFFFFF
                    self.writes += 1
                elif self.competitor is not None:
                    self.memory[self.x[rn]] = self.competitor
                self.x[word>>16&31] = 0 if success else 1
                monitor = None
            elif word == 0xD5033F5F:
                self.clears += 1
                monitor = None
            elif word&0xFFE0FC1F == 0x6B00001F:
                self.cmp(self.x[rn],self.x[word>>16&31])
            elif word&0xFFC0001F == 0x7100001F:
                self.cmp(self.x[rn],word>>10&0xFFF)
            elif word&0xFFE00C10 == 0x7A400800:
                execute = self.condition(word>>12&15)
                if execute:
                    self.cmp(self.x[rn],word>>16&31)
                else:
                    self.flags = (word&15)<<28
                self.ccmp.append((execute,self.flags))
            elif word&0xFFE0FFE0 == 0x2A0003E0:
                self.x[rt] = self.x[word>>16&31]&0xFFFFFFFF
            elif word&0xFFC00000 == 0x11000000:
                self.x[rt] = (self.x[rn]+(word>>10&0xFFF))&0xFFFFFFFF
            elif word&0xFF000010 == 0x54000000:
                if self.condition(word&15):
                    next_pc = pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0x7E000000 == 0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF) == bool(word&0x01000000):
                    next_pc = pc+self.signed(word>>5&0x7FFFF,19)*4
            elif word&0xFC000000 == 0x14000000:
                next_pc = pc+self.signed(word&0x3FFFFFF,26)*4
            else:
                raise AssertionError(f'unmodeled {pc:x}: {word:08x}')
            pc = next_pc
        raise AssertionError('nonterminating public model')


class NativeConditionalRefreshTests(unittest.TestCase):
    def test_three_native_unions_keep_bytes_and_need_no_helper(self):
        for variant in range(3):
            for rename in (None,{8:24,9:3,10:16,11:17,12:27}):
                values,entry,end,reject = fixture(variant,rename)
                with self.subTest(variant=variant,rename=rename):
                    self.assertEqual(plan(values,(0,entry,end,reject)),())
                    image = ar.rewrite(raw(values),entry_offsets=(0,entry,end,reject))
                    self.assertEqual(image.bytes,raw(values))
                    self.assertFalse(image.sites)
                    self.assertFalse(image.fixups)

    def test_ccmp_native_paths_preserve_full_state_and_actual_flags(self):
        cases = ((1,1,0,None,'success',2,1,1,0,0x80000000),
                 (3,1,0,None,'success',4,2,1,1,0x80000000),
                 (0,1,0,None,'reject',0,1,0,1,0x80000000),
                 (1,1,2,None,'success',2,3,3,0,0x80000000),
                 (1,1,1,4,'success',5,3,2,1,0x80000000),
                 (1,1,1,0,'reject',0,2,1,1,0x80000000),
                 (0xFFFFFFFF,1,0,None,'reject',0xFFFFFFFF,1,0,1,0xA0000000))
        values,entry,end,reject = fixture(0)
        image = ar.rewrite(raw(values),entry_offsets=(0,entry,end,reject))
        emitted = list(struct.unpack('<'+'I'*(len(image.bytes)//4),image.bytes))
        for initial,expected,failures,competitor,result,final,loads,stores,clears,flags in cases:
            with self.subTest(initial=initial,failures=failures,competitor=competitor):
                machine = Machine(emitted,0,initial,expected,failures,competitor)
                before = machine.x.copy()
                self.assertEqual(machine.run(),result)
                before[9] = machine.x[10]
                before[10] = (final-1)&0xFFFFFFFF if result=='success' else final
                if stores:
                    before[11] = 0 if result=='success' else 1
                self.assertEqual(machine.x,before)
                self.assertEqual((machine.loads,machine.stores,machine.clears),(loads,stores,clears))
                self.assertEqual((machine.sp,machine.flags,machine.q),(0x800000,flags,tuple(range(32))))
                self.assertEqual(machine.memory,{0x3FFFFC:0x12345678,0x400000:final,0x400004:0xDEADBEEF})
                if result=='success':
                    self.assertEqual(machine.ccmp[-1],(False,0x80000000))
                if failures:
                    self.assertIn((True,0x60000000),machine.ccmp)

    def test_zero_store_and_tag_refresh_do_not_assume_payload_or_prepublish_expected(self):
        cases = ((1,3,1,0,None,'success',0),(1,1,7,0,None,'success',0),
                 (1,0,7,0,None,'reject',0),(1,1,1,2,None,'success',0),
                 (1,1,1,1,0,'reject',0),(2,4,4,0,None,'success',7),
                 (2,0,4,0,None,'reject',0),(2,2,2,0,None,'success',2),
                 (2,4,4,2,None,'success',7),(2,4,4,1,0,'reject',0),
                 (2,4,4,1,2,'success',2))
        for variant,initial,expected,failures,competitor,result,final in cases:
            values,entry,end,reject = fixture(variant)
            image = ar.rewrite(raw(values),entry_offsets=(0,entry,end,reject))
            emitted = list(struct.unpack('<'+'I'*(len(image.bytes)//4),image.bytes))
            with self.subTest(case=(variant,initial,expected,failures,competitor)):
                machine = Machine(emitted,variant,initial,expected,failures,competitor)
                before = machine.x.copy()
                self.assertEqual(machine.run(),result)
                base,loaded,expect,status = machine.roles
                for role in {loaded,expect,status}:
                    before[role] = machine.x[role]
                self.assertEqual(machine.x,before)
                self.assertEqual((machine.sp,machine.q),(0x800000,tuple(range(32))))
                self.assertEqual(machine.memory,{0x3FFFFC:0x12345678,0x400000:final,0x400004:0xDEADBEEF})
                if variant==1 and initial==0:
                    self.assertEqual(machine.x[expect],0xFEED000000000000|expected)

    def test_interior_roots_and_incoming_edges_stay_rejected(self):
        for variant in range(3):
            values,entry,end,reject = fixture(variant)
            for pc in range(BEGIN,end,4):
                if pc == entry:
                    continue
                with self.subTest(variant=variant,root=pc),self.assertRaises(ar.RewriteError):
                    plan(values,(0,entry,end,reject,pc))
                changed = values.copy()
                changed[1] = ar.branch(4,pc)
                with self.subTest(variant=variant,edge=pc),self.assertRaises(ar.RewriteError):
                    plan(changed,(0,entry,end,reject))

    def test_recognizer_rejects_decoupled_conditions_order_width_roles_and_partial_union(self):
        helper = ar.android_exclusive.native_conditional_refresh
        for variant in range(3):
            values,entry,end,reject = fixture(variant)
            ins,kinds = decoded(values)
            head = next(item for item in ins if item.mnemonic in ar.EXCLUSIVE_LOADS)
            nodes,actual_entry,heads = helper(head,{item.address:item for item in ins},kinds,ar)
            self.assertEqual((nodes,actual_entry),(set(range(BEGIN,end,4)),entry))
            self.assertEqual(len(heads),1 if variant==2 else 2)
            mutations = []
            for slot in ((0,7) if variant!=2 else (5,)):
                mutations.extend(((slot,values[BEGIN//4+slot]^0x8000),
                                  (slot,values[BEGIN//4+slot]^0x40000000)))
            for slot in ((2,6,9,13,15) if variant==0 else (2,5,9,11) if variant==1 else (2,4,7,10)):
                mutations.append((slot,values[BEGIN//4+slot]^1))
            store_slot = (11,10,8)[variant]
            mutations.append((store_slot,values[BEGIN//4+store_slot]^0x8000))
            for slot,word in mutations:
                changed = values.copy();changed[BEGIN//4+slot]=word
                ci,ck = decoded(changed)
                with self.subTest(variant=variant,slot=slot,word=hex(word)):
                    self.assertIsNone(helper(ci[head.address//4],{item.address:item for item in ci},ck,ar))
            role = (8,10,9)[variant]
            collision = (9,9,10)[variant]
            for forbidden in (18,29,30,31,collision):
                changed,_,_,_ = fixture(variant,{role:forbidden})
                ci,ck = decoded(changed)
                with self.subTest(variant=variant,role=forbidden):
                    self.assertIsNone(helper(ci[head.address//4],{item.address:item for item in ci},ck,ar))
            for pc in range(BEGIN,end,4):
                partial = {item.address:item for item in ins if item.address!=pc}
                self.assertIsNone(helper(head,partial,kinds,ar))
                with self.assertRaises(ar.RewriteError):
                    plan(values,(0,entry,end,reject),{pc:'x18'})


if __name__ == '__main__':
    unittest.main()
