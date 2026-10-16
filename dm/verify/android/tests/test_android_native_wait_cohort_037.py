"""Finite WFE rows from observed source; no matcher/ABI widening."""
from pathlib import Path
from types import SimpleNamespace
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
ENTRY,PRODUCER,CALLEE=0x20,0x1C,0x300
OBJECT,TLR=0x400000,0x500000
CASES=[{'name': 'A',
  'words': [2034369224,
            2852193268,
            2852127731,
            2432720917,
            4185916080,
            285213975,
            872415784,
            1384120361,
            2030174935,
            2287992490,
            872415434,
            2030174920,
            3573751903,
            2030174935,
            2287992490,
            905969546,
            2282389161,
            872416010,
            2030174920,
            2030174935,
            2287992490,
            905969354,
            402653178,
            1384120376,
            335544322,
            3573751903,
            2030174935,
            2287992488,
            872415432,
            2030174943,
            2034370248,
            889192264,
            2483119373,
            402653176,
            2282258104,
            872415432,
            2030174943,
            2034370248,
            889192072,
            2483119366,
            402653170],
  'fields': [[0, 5],
             [0, 16],
             [0, 16],
             [0, 5],
             [5],
             [0, 5],
             [0],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0, 5],
             [0],
             [],
             [0],
             [],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             [],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             []],
  'offsets': [0,
              4,
              8,
              12,
              16,
              20,
              24,
              28,
              32,
              36,
              40,
              44,
              48,
              52,
              56,
              60,
              64,
              68,
              72,
              76,
              80,
              84,
              88,
              92,
              96,
              100,
              104,
              108,
              112,
              116,
              120,
              124,
              128,
              132,
              136,
              140,
              144,
              148,
              152,
              156,
              160],
  'first_head': 36,
  'heads': [36, 56, 80, 108],
  'call_indices': [32, 39],
  'tls_role': 22,
  'success_offset': 164,
  'object_arg': 0,
  'cell_offset': 24},
 {'name': 'B',
  'words': [2034369224,
            2852193267,
            2852127732,
            2432720949,
            4185916080,
            285213975,
            872417384,
            1384120361,
            2030174935,
            2287992490,
            889192650,
            335544330,
            2030174920,
            2030174935,
            2287992490,
            872415434,
            2030174920,
            3573751903,
            2030174935,
            2287992490,
            905969546,
            2282389161,
            905969354,
            1384120376,
            335544322,
            3573751903,
            2030174935,
            2287992488,
            872415432,
            2030174943,
            2034370248,
            889192264,
            2483118675,
            402653176,
            2282258104,
            889190472,
            2030174943,
            2034370248,
            889192072,
            2483118668,
            402653170],
  'fields': [[0, 5],
             [0, 16],
             [0, 16],
             [0, 5],
             [5],
             [0, 5],
             [0],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             [0, 5],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5, 16],
             [0],
             [0],
             [],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             [],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             []],
  'offsets': [0,
              4,
              8,
              12,
              16,
              20,
              24,
              28,
              32,
              36,
              40,
              44,
              48,
              52,
              56,
              60,
              64,
              68,
              72,
              76,
              80,
              84,
              88,
              292,
              296,
              300,
              304,
              308,
              312,
              316,
              320,
              324,
              328,
              332,
              336,
              340,
              344,
              348,
              352,
              356,
              360],
  'first_head': 36,
  'heads': [36, 56, 76, 308],
  'call_indices': [32, 39],
  'tls_role': 22,
  'success_offset': 92,
  'object_arg': 1,
  'cell_offset': 24},
 {'name': 'C',
  'words': [2034369224,
            2852193267,
            2852127732,
            2432720949,
            4185916080,
            285213975,
            872415784,
            1384120361,
            2030174935,
            2287992490,
            872415434,
            2030174920,
            3573751903,
            2030174935,
            2287992490,
            905969546,
            2282389161,
            872416010,
            2030174920,
            2030174935,
            2287992490,
            905969354,
            402653178,
            1384120376,
            335544322,
            3573751903,
            2030174935,
            2287992488,
            872415432,
            2030174943,
            2034370248,
            889192264,
            2483118581,
            402653176,
            2282258104,
            872415432,
            2030174943,
            2034370248,
            889192072,
            2483118574,
            402653170],
  'fields': [[0, 5],
             [0, 16],
             [0, 16],
             [0, 5],
             [5],
             [0, 5],
             [0],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0, 5],
             [0],
             [],
             [0],
             [],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             [],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             []],
  'offsets': [0,
              4,
              8,
              12,
              16,
              20,
              24,
              28,
              32,
              36,
              40,
              44,
              48,
              52,
              56,
              60,
              64,
              68,
              72,
              76,
              80,
              84,
              88,
              92,
              96,
              100,
              104,
              108,
              112,
              116,
              120,
              124,
              128,
              132,
              136,
              140,
              144,
              148,
              152,
              156,
              160],
  'first_head': 36,
  'heads': [36, 56, 80, 108],
  'call_indices': [32, 39],
  'tls_role': 22,
  'success_offset': 164,
  'object_arg': 1,
  'cell_offset': 24},
 {'name': 'D',
  'words': [2034369320,
            4185916112,
            285213978,
            889192584,
            335544334,
            2030175016,
            3573751903,
            2030175034,
            2287992521,
            905969545,
            2282323671,
            872415945,
            2030175016,
            2030175034,
            2287992521,
            905969353,
            402653178,
            3573751903,
            2030175034,
            2287992520,
            872415432,
            2030175039,
            2034370344,
            889192264,
            2483117260,
            402653176,
            2282258135,
            872415432,
            2030175039,
            2034370344,
            889192072,
            2483117253,
            402653170],
  'fields': [[0, 5],
             [5],
             [0, 5],
             [0],
             [],
             [0, 5],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0, 5],
             [0],
             [],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             [],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             []],
  'offsets': [0,
              4,
              8,
              12,
              16,
              20,
              24,
              28,
              32,
              36,
              40,
              44,
              48,
              52,
              56,
              60,
              64,
              68,
              72,
              76,
              80,
              84,
              88,
              92,
              96,
              100,
              104,
              108,
              112,
              116,
              120,
              124,
              128],
  'first_head': 32,
  'heads': [32, 56, 76],
  'call_indices': [24, 31],
  'tls_role': 25,
  'success_offset': 132,
  'object_arg': 0,
  'cell_offset': 16,
  'initial_cell_register': 22,
  'initial_data_register': 23},
 {'name': 'E',
  'words': [2034369192,
            2852127731,
            2432712724,
            4185916048,
            285213974,
            872415784,
            1384120361,
            2030174902,
            2287992458,
            872415434,
            2030174888,
            3573751903,
            2030174902,
            2287992458,
            905969546,
            2282389129,
            872416010,
            2030174888,
            2030174902,
            2287992458,
            905969354,
            402653178,
            1384120375,
            335544322,
            3573751903,
            2030174902,
            2287992456,
            872415432,
            2030174911,
            2034370216,
            889192264,
            2483117127,
            402653176,
            2282258071,
            872415432,
            2030174911,
            2034370216,
            889192072,
            2483117120,
            402653170],
  'fields': [[0, 5],
             [0, 16],
             [0, 5],
             [5],
             [0, 5],
             [0],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0, 5],
             [0],
             [],
             [0],
             [],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             [],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             []],
  'offsets': [0,
              4,
              8,
              12,
              16,
              20,
              24,
              28,
              32,
              36,
              40,
              44,
              48,
              52,
              56,
              60,
              64,
              68,
              72,
              76,
              80,
              84,
              88,
              92,
              96,
              100,
              104,
              108,
              112,
              116,
              120,
              124,
              128,
              132,
              136,
              140,
              144,
              148,
              152,
              156],
  'first_head': 32,
  'heads': [32, 52, 76, 104],
  'call_indices': [31, 38],
  'tls_role': 21,
  'success_offset': 160,
  'object_arg': 0,
  'cell_offset': 16},
 {'name': 'F',
  'words': [2034369224,
            704709620,
            2852127731,
            2432712725,
            4185916080,
            285213975,
            872415784,
            1384120361,
            2030174935,
            2287992490,
            872415434,
            2030174920,
            3573751903,
            2030174935,
            2287992490,
            905969546,
            2282389161,
            872416010,
            2030174920,
            2030174935,
            2287992490,
            905969354,
            402653178,
            1384120376,
            335544322,
            3573751903,
            2030174935,
            2287992488,
            872415432,
            2030174943,
            2034370248,
            889192264,
            2483116837,
            402653176,
            2282258104,
            872415432,
            2030174943,
            2034370248,
            889192072,
            2483116830,
            402653170],
  'fields': [[0, 5],
             [0, 16],
             [0, 16],
             [0, 5],
             [5],
             [0, 5],
             [0],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0, 5],
             [0],
             [],
             [0],
             [],
             [],
             [0, 5],
             [0, 5],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             [],
             [0, 5, 16],
             [0],
             [0, 5],
             [0, 5],
             [0],
             [],
             []],
  'offsets': [0,
              4,
              8,
              12,
              16,
              20,
              24,
              28,
              32,
              36,
              40,
              44,
              48,
              52,
              56,
              60,
              64,
              68,
              72,
              76,
              80,
              84,
              88,
              92,
              96,
              100,
              104,
              108,
              112,
              116,
              120,
              124,
              128,
              132,
              136,
              140,
              144,
              148,
              152,
              156,
              160],
  'first_head': 36,
  'heads': [36, 56, 80, 108],
  'call_indices': [32, 39],
  'tls_role': 22,
  'success_offset': 164,
  'object_arg': 0,
  'cell_offset': 16}]

def raw(v):return struct.pack('<'+'I'*len(v),*v)
def fixture(case):
    v=[0xD503201F]*(0x340//4);v[0]=ar.branch(0,PRODUCER);v[PRODUCER//4]=0xD53BD060|case['tls_role']
    for offset,w in zip(case['offsets'],case['words']):v[(ENTRY+offset)//4]=w
    for index in case['call_indices']:
        at=ENTRY+case['offsets'][index];v[at//4]=0x94000000|((CALLEE-at)//4)&0x3FFFFFF
    v[(ENTRY+case['success_offset'])//4]=0xD65F03C0
    for previous,current in zip(case['offsets'],case['offsets'][1:]):
        if current!=previous+4:
            after=ENTRY+case['offsets'][-1]+8;v[(ENTRY+current-4)//4]=ar.branch(ENTRY+current-4,after);v[after//4]=0xD65F03C0
    v[CALLEE//4:CALLEE//4+2]=[0xD40006C1,0xD65F03C0]
    return v

def decoded(v):
    o=[ar.decode(w,i*4) for i,w in enumerate(v)];return o,{i.address:ar.site_kind(i) for i in o}
def context(case):
    v=fixture(case);o,k=decoded(v);return v,o,{i.address:i for i in o},k
class CohortWaitModel:
    def __init__(self,case,v,old,busy=0,release=1,failures=0,competitor=None,interrupt=0,data_live_in=1,cell_live_in_offset=None):
        self.v=v;self.x=[0xAABB000000001000+i*0x101 for i in range(31)];self.x[case['object_arg']]=OBJECT;self.cell=OBJECT+(case['cell_offset'] if cell_live_in_offset is None else cell_live_in_offset);self.success=ENTRY+case['success_offset']
        if 'initial_cell_register' in case:self.x[case['initial_cell_register']]=self.cell
        if 'initial_data_register' in case:self.x[case['initial_data_register']]=data_live_in
        self.sp,self.flags,self.q=0x800000,0xB0000000,tuple(int.from_bytes(bytes([i])*16,'little') for i in range(32))
        self.pages={a:bytearray((i*17+9)%256 for i in range(4096)) for a in (OBJECT,TLR)}
        self.write(self.cell,4,busy);self.write(TLR+0x100,2,old);self.write(TLR+0x102,2,interrupt)
        self.release,self.failures,self.competitor=release,failures,competitor
        self.loads=self.stores=self.waits=self.calls=self.flag_reads=0;self.counter_writes=[];self.wait_live=[]
    def read(self,address,size):base=address&~4095;return int.from_bytes(self.pages[base][address-base:address-base+size],'little')
    def write(self,address,size,value):
        base=address&~4095;self.pages[base][address-base:address-base+size]=(value&((1<<(size*8))-1)).to_bytes(size,'little')
    @staticmethod
    def signed(v,b):return v-(1<<b) if v&(1<<(b-1)) else v
    def run(self):
        pc,monitor=0,None
        for _ in range(1200):
            if pc==self.success:assert monitor is None;return
            w=self.v[pc//4];rt,rn=w&31,w>>5&31;nxt=pc+4
            if w&0xFFFFFFE0==0xD53BD060:self.x[rt]=TLR
            elif w&0xFFC00000==0x79400000:
                address=self.x[rn]+(w>>10&4095)*2;self.flag_reads+=address==TLR+0x102;self.x[rt]=self.read(address,2)
            elif w&0xFFC00000==0x79000000:
                address=self.x[rn]+(w>>10&4095)*2;value=0 if rt==31 else self.x[rt]&0xFFFF
                self.write(address,2,value);self.counter_writes.append((address,value))
            elif w&0xFFC00000 in (0x11000000,0x91000000):
                self.x[rt]=(self.x[rn]+(w>>10&4095))&((1<<(64 if w>>31 else 32))-1)
            elif w&0x7FE0FFE0==0x2A0003E0:
                value=0 if w>>16&31==31 else self.x[w>>16&31];self.x[rt]=value if w>>31 else value&0xFFFFFFFF
            elif w&0xFFE00000==0x52800000:self.x[rt]=w>>5&65535
            elif w&0xFFFFFC00==0x885FFC00:
                self.loads+=1;monitor=self.x[rn];self.x[rt]=self.read(self.x[rn],4)
            elif w&0xFFE0FC00==0x88007C00:
                assert monitor==self.x[rn];self.stores+=1;ok=self.stores>self.failures
                if ok:self.write(self.x[rn],4,self.x[rt])
                elif self.competitor is not None:self.write(self.cell,4,self.competitor)
                self.x[w>>16&31]=0 if ok else 1;monitor=None
            elif w==0xD503205F:
                self.waits+=1;self.wait_live.append(monitor is not None)
                if self.waits>=self.release:self.write(self.cell,4,0) # authored competing unlock event, not hardware wake timing
            elif w&0x7E000000==0x34000000:
                if bool(self.x[rt]&0xFFFFFFFF)==bool(w&0x1000000):nxt=pc+self.signed(w>>5&0x7FFFF,19)*4
            elif w&0xFC000000==0x94000000:
                self.calls+=1
                raise ValueError('nonzero pin-state remains unsupported; no SVC36 success model')
            elif w&0xFC000000==0x14000000:nxt=pc+self.signed(w&0x3FFFFFF,26)*4
            elif w&0xFFC00000==0xF9800000:pass
            elif w!=0xD503201F:raise AssertionError((hex(pc),hex(w)))
            pc=nxt
        raise AssertionError('sparse wait did not complete')


class NativeWaitCohortTests(unittest.TestCase):
    def test_exact_rows_keep_source_and_consume_all_fresh_heads(self):
        for c in CASES:
            with self.subTest(case=c['name']):
                v,o,b,k=context(c);nodes={ENTRY+x for x in c['offsets']};heads={ENTRY+x for x in c['heads']};head=ENTRY+c['first_head']
                self.assertEqual(ar.android_exclusive.native_wait_mutex(b[head],b,k,ar),(nodes,ENTRY,heads))
                self.assertEqual(ar.android_exclusive.plan_regions(o,k,(0,PRODUCER,CALLEE,ENTRY+c['success_offset']),ar),())
                image=ar.rewrite(raw(v),entry_offsets=(0,PRODUCER,CALLEE,ENTRY+c['success_offset']),package_version=2,checked_stack=True)
                for pc in nodes:self.assertEqual(image.bytes[pc:pc+4],raw(v)[pc:pc+4])
                self.assertFalse(any(site.offset in nodes for site in image.sites))
    def test_fixed_bits_missing_facts_wrong_source_and_aliases_refuse(self):
        for c in CASES:
            v,o,b,k=context(c);head=ENTRY+c['first_head'];nodes={ENTRY+x for x in c['offsets']};helper=ar.android_exclusive.native_wait_mutex
            for index,(offset,fields) in enumerate(zip(c['offsets'],c['fields'])):
                pc=ENTRY+offset;w=v[pc//4];mask=sum(31<<shift for shift in fields if (w>>shift&31)!=31)
                if index in c['call_indices']:mask|=0x3FFFFFF
                for bit in range(32):
                    if mask>>bit&1:continue
                    changed=dict(b)
                    try:
                        changed[pc]=ar.decode(w^(1<<bit),pc);ck=dict(k);ck[pc]=ar.site_kind(changed[pc]);result=helper(changed[head],changed,ck,ar)
                    except ar.RewriteError:result=None
                    self.assertIsNone(result,(c['name'],index,bit))
            for pc in nodes:
                partial=dict(b);del partial[pc];self.assertIsNone(helper(b[head],partial,k,ar))
                for kind in ('x18','gate','parameter','parameter_tail','missing'):
                    ck=dict(k)
                    if kind=='missing':del ck[pc]
                    else:ck[pc]=kind
                    with self.assertRaises(ar.RewriteError):helper(b[head],b,ck,ar)
            for pc in (PRODUCER,CALLEE,CALLEE+4,ENTRY+c['success_offset']):
                partial=dict(b);del partial[pc];self.assertIsNone(helper(b[head],partial,k,ar))
            for pc,w in ((PRODUCER,0xD53BD040|c['tls_role']),(CALLEE,0xD4000341),(CALLEE+4,0xD503201F)):
                changed=dict(b);changed[pc]=ar.decode(w,pc);self.assertIsNone(helper(b[head],changed,k,ar))
            roles={w>>shift&31 for w,fs in zip(c['words'],c['fields']) for shift in fs}-{31}
            for role in roles:
                for bad in (18,29,30,31,*sorted(roles-{role})):
                    changed=list(v)
                    for index,(offset,word,fields) in enumerate(zip(c['offsets'],c['words'],c['fields'])):
                        new=word
                        for shift in fields:
                            if word>>shift&31==role:new=(new&~(31<<shift))|(bad<<shift)
                        if index in c['call_indices']:new=v[(ENTRY+offset)//4]
                        changed[(ENTRY+offset)//4]=new
                    if role==c['tls_role']:changed[PRODUCER//4]=0xD53BD060|bad
                    try:
                        ops,ks=decoded(changed);by={x.address:x for x in ops};result=helper(by[head],by,ks,ar)
                    except ar.RewriteError:result=None
                    self.assertIsNone(result,(c['name'],role,bad))
    def test_all_metadata_and_exterior_direct_entries_bypass_refuse(self):
        for c in CASES:
            v,o,b,k=context(c);roots=(0,PRODUCER,CALLEE,ENTRY+c['success_offset'])
            for pc in {ENTRY+x for x in c['offsets']}:
                with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(*roots,pc),ar)
                values=list(v);values[1]=ar.branch(4,pc);ops,ks=decoded(values)
                with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(ops,ks,roots,ar)
    def test_missing_verified_retirement_policy_stays_refused(self):
        values=dict(vars(ar));values['SVC_MONITOR_RETIRE']=frozenset();api=SimpleNamespace(**values)
        for c in CASES:
            v,o,b,k=context(c)
            with self.assertRaisesRegex(ar.RewriteError,'SVC36.*preframe retirement'):
                ar.android_exclusive.native_wait_mutex(b[ENTRY+c['first_head']],b,k,api)
    def test_nonzero_pin_keeps_explicit_unsupported_state(self):
        for c in CASES:
            model=CohortWaitModel(c,fixture(c),0,busy=1,release=1000,interrupt=1)
            with self.assertRaisesRegex(ValueError,'nonzero pin-state'):model.run()
            self.assertEqual(model.read(TLR+0x102,2),1)
    def test_unicorn_counter_retries_and_live_wfe_match_independent_source(self):
        scenarios=((0,0,1,0,None),(7,0,1,0,None),(0xFFFF,0,1,2,None),(0,1,1,0,None),(0,1,4,2,None),(7,1,1,0,None),(7,1,4,2,None),(0,0,1,1,9),(7,0,1,1,9))
        for c in CASES:
            v=fixture(c);image=raw(v);nodes={ENTRY+x for x in c['offsets']};heads={ENTRY+x for x in c['heads']};stores=tuple(ENTRY+offset for offset,w in zip(c['offsets'],c['words']) if w&0xFFE0FC00==0x88007C00);success=ENTRY+c['success_offset'];cell=OBJECT+c['cell_offset']
            inputs=[(*item,1,c['cell_offset']) for item in scenarios]
            if 'initial_data_register' in c:
                inputs.extend(((0,0,1,0,None,0,128),(7,0,1,1,None,0xFFFFFFFF,256),(7,0,1,2,None,0xFFFFFFFFFFFFFFFF,384)))
            for old,busy,release,failures,competitor,data_live_in,cell_live_in_offset in inputs:
                cell=OBJECT+cell_live_in_offset
                with self.subTest(case=c['name'],old=old,busy=busy,release=release,failures=failures):
                    model=CohortWaitModel(c,v,old,busy,release,failures,competitor,data_live_in=data_live_in,cell_live_in_offset=cell_live_in_offset);before=model.x.copy();pages={a:bytes(b) for a,b in model.pages.items()};model.run()
                    self.assertEqual(model.read(cell,4),(data_live_in&0xFFFFFFFF) if 'initial_data_register' in c else 1);self.assertEqual(model.read(TLR+0x100,2),(old+1)&0xFFFF)
                    base,stub=0x100000,0x700000;cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
                    for address in (base,stub,*pages):cpu.mem_map(address,4096)
                    cpu.mem_write(base,image)
                    for i,store in enumerate(stores):cpu.mem_write(stub+i*8,struct.pack('<2I',0xD5033F5F,ar.branch(stub+i*8+4,base+store)))
                    for address,data in pages.items():cpu.mem_write(address,data)
                    for i,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{i}'),value)
                    for i,value in enumerate(model.q):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{i}'),value)
                    cpu.reg_write(uc.UC_ARM64_REG_SP,model.sp);cpu.reg_write(uc.UC_ARM64_REG_NZCV,model.flags);cpu.reg_write(uc.UC_ARM64_REG_TPIDRRO_EL0,TLR)
                    seen=dict(done=False,live=False,loads=0,stores=0,waits=0,flag_reads=0,counter_writes=[],wait_live=[],detour=False)
                    def code(machine,pc,size,_):
                        at=pc-base
                        if at==success:self.assertFalse(seen['live']);seen['done']=True;machine.emu_stop();return
                        if at in heads:seen['live']=True;seen['loads']+=1
                        elif at in stores:
                            if seen['detour']:seen['detour']=False
                            else:
                                seen['stores']+=1
                                if seen['stores']<=failures:
                                    if competitor is not None:machine.mem_write(cell,struct.pack('<I',competitor))
                                    seen['detour']=True;machine.reg_write(uc.UC_ARM64_REG_PC,stub+stores.index(at)*8)
                            seen['live']=False
                        if at in nodes:
                            w=v[at//4];rt,rn=w&31,w>>5&31
                            if w==0xD503205F:
                                seen['waits']+=1;seen['wait_live'].append(seen['live'])
                                if seen['waits']>=release:machine.mem_write(cell,struct.pack('<I',0))
                            elif w&0xFFC00000==0x79000000:
                                address=machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{rn}'))+(w>>10&4095)*2;value=0 if rt==31 else machine.reg_read(getattr(uc,f'UC_ARM64_REG_X{rt}'))&0xFFFF;seen['counter_writes'].append((address,value))
                            elif w&0xFFC00000==0x79400000:seen['flag_reads']+=(w>>10&4095)*2==0x102
                            elif w&0xFC000000==0x94000000:self.fail('rawflagzero CPU case entered unsupportedSvc36 pin path')
                    cpu.hook_add(UC_HOOK_CODE,code);cpu.emu_start(base,base+len(image),count=5000)
                    self.assertTrue(seen['done']);self.assertEqual([cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{i}')) for i in range(31)],model.x)
                    self.assertEqual((cpu.reg_read(uc.UC_ARM64_REG_SP),cpu.reg_read(uc.UC_ARM64_REG_NZCV)),(model.sp,model.flags));self.assertEqual(tuple(cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{i}')) for i in range(32)),model.q)
                    for address,data in model.pages.items():self.assertEqual(bytes(cpu.mem_read(address,4096)),bytes(data))
                    self.assertEqual(tuple(seen[k] for k in ('loads','stores','waits','flag_reads','counter_writes','wait_live')),(model.loads,model.stores,model.waits,model.flag_reads,model.counter_writes,model.wait_live))
