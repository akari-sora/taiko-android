"""Exact observed native boolean schedules preserve source bytes and monitor exits."""
from pathlib import Path
import sys,struct,unittest
ROOT=Path(__file__).resolve().parents[4];sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
CASES=[{'name': 'leading-boolean',
  'begin': 0,
  'end': 64,
  'entry': 32,
  'head': 32,
  'words': (3573759839,
            706675683,
            922753123,
            1522536975,
            1259274563,
            705692655,
            1796014207,
            1409286945,
            2287959312,
            1796145695,
            1426063041,
            2281929999,
            905969315,
            1384120355,
            906493603,
            335544502),
  'fields': ((),
             (0, 16),
             (0,),
             (0, 5),
             (0, 5, 16),
             (0, 16),
             (5, 16),
             (),
             (0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0,),
             (0,),
             (0,),
             ()),
  'external_bits': {2: 14, 7: 19, 15: 26}},
 {'name': 'trailing-boolean',
  'begin': 0,
  'end': 64,
  'entry': 32,
  'head': 32,
  'words': (3573759839,
            706675683,
            922752611,
            1522532879,
            1522536931,
            705692655,
            1796014207,
            1409286433,
            2287959312,
            1796145695,
            1426063041,
            2281929999,
            905969315,
            1384120355,
            906493603,
            335544486),
  'fields': ((),
             (0, 16),
             (0,),
             (0, 5),
             (0, 5),
             (0, 16),
             (5, 16),
             (),
             (0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0,),
             (0,),
             (0,),
             ()),
  'external_bits': {2: 14, 15: 26}},
 {'name': 'masked-refresh',
  'begin': 0,
  'end': 56,
  'entry': 0,
  'head': 0,
  'words': (2287992078,
            1796145631,
            1409286337,
            168624623,
            2282781967,
            889192592,
            1384120367,
            335544323,
            3573759839,
            706675695,
            922747023,
            168493520,
            705561583,
            905969264),
  'fields': ((0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0, 5, 16),
             (0,),
             (0,),
             (),
             (),
             (0, 16),
             (0,),
             (0, 5, 16),
             (0, 16),
             (0,)),
  'external_bits': {}},
 {'name': 'leading-masked',
  'begin': 0,
  'end': 68,
  'entry': 0,
  'head': 0,
  'words': (2287959311,
            1795490303,
            1409286337,
            168165543,
            2282978567,
            889192595,
            1384120359,
            335544323,
            3573759839,
            706675687,
            922749543,
            1522536933,
            1258619207,
            705627109,
            1796014335,
            1426062880,
            335544337),
  'fields': ((0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0, 5, 16),
             (0,),
             (0,),
             (),
             (),
             (0, 16),
             (0,),
             (0, 5),
             (0, 5, 16),
             (0, 16),
             (5, 16),
             (),
             ()),
  'external_bits': {10: 14, 16: 26}},
 {'name': 'trailing-masked',
  'begin': 0,
  'end': 64,
  'entry': 0,
  'head': 0,
  'words': (2287959311,
            1795490303,
            1409286337,
            168165543,
            2282978567,
            889192595,
            1384120359,
            335544323,
            3573759839,
            706675687,
            922748999,
            1522532837,
            1522536615,
            705627109,
            1796014335,
            1426062880),
  'fields': ((0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0, 5, 16),
             (0,),
             (0,),
             (),
             (),
             (0, 16),
             (0,),
             (0, 5),
             (0, 5),
             (0, 16),
             (5, 16),
             ()),
  'external_bits': {10: 14}},
 {'name': 'orr-prefix-refresh',
  'begin': 0,
  'end': 64,
  'entry': 0,
  'head': 8,
  'words': (705430509,
            705364367,
            2287959308,
            1796014495,
            1409286305,
            2282585359,
            889192589,
            1384120365,
            335544323,
            3573759839,
            706675693,
            923270317,
            1779106207,
            705430511,
            1426062912,
            402653153),
  'fields': ((0, 16),
             (0, 5, 16),
             (0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0,),
             (0,),
             (),
             (),
             (0, 16),
             (0,),
             (5, 16),
             (0, 16),
             (),
             ()),
  'external_bits': {11: 14, 15: 26}},
 {'name': 'orr-refresh',
  'begin': 0,
  'end': 56,
  'entry': 0,
  'head': 0,
  'words': (2287959310,
            1795490271,
            1409286337,
            705364143,
            2282781967,
            889192592,
            1384120367,
            335544323,
            3573759839,
            706675695,
            922747023,
            1779106271,
            705561573,
            1426062944),
  'fields': ((0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0, 5, 16),
             (0,),
             (0,),
             (),
             (),
             (0, 16),
             (0,),
             (5, 16),
             (0, 16),
             ()),
  'external_bits': {}},
 {'name': 'release-refresh',
  'begin': 0,
  'end': 44,
  'entry': 0,
  'head': 0,
  'words': (3361701197,
            3943563711,
            1409286337,
            3356425548,
            889192622,
            1384120366,
            905970062,
            335544324,
            3573759839,
            706675694,
            905969934),
  'fields': ((0, 5), (5, 16), (), (0, 5, 16), (0,), (0,), (0,), (), (), (0, 16), (0,)),
  'external_bits': {6: 14, 10: 14}},
 {'name': 'orr-exit-refresh',
  'begin': 0,
  'end': 60,
  'entry': 12,
  'head': 12,
  'words': (168493354,
            705233893,
            905967786,
            2287959305,
            1795490111,
            1409286337,
            705364138,
            2282519818,
            889192588,
            1384120362,
            335544323,
            3573759839,
            706675690,
            889192042,
            402653113),
  'fields': ((0, 5, 16),
             (0, 16),
             (0,),
             (0, 5),
             (5, 16),
             (),
             (0, 5, 16),
             (0, 5, 16),
             (0,),
             (0,),
             (),
             (),
             (0, 16),
             (0,),
             ()),
  'external_bits': {2: 19, 14: 26}}]
def fixture(case):
    begin=512;v=[0xD503201F]*512
    entry=begin+case['entry']-case['begin'];head=begin+case['head']-case['begin'];end=begin+case['end']-case['begin']
    v[0]=ar.branch(0,entry);v[begin//4-1]=ar.branch(begin-4,entry)
    v[begin//4:end//4]=case['words'];exits={end}
    for i,bits in case['external_bits'].items():
        op=ar.decode(v[begin//4+i],begin+i*4);target=op.operands[-1].imm
        assert target not in range(begin,end,4);exits.add(target)
    for target in exits:v[target//4]=0xD65F03C0
    o=[ar.decode(w,i*4) for i,w in enumerate(v)];b={x.address:x for x in o};k={x.address:ar.site_kind(x) for x in o}
    return v,o,b,k,begin,entry,head,end,exits
class NativeBooleanSchedulesTests(unittest.TestCase):
    def test_exact_rows_have_one_entry_native_bytes_and_closed_monitor_exits(self):
        for c in CASES:
            with self.subTest(shape=c['name']):
                v,o,b,k,begin,entry,head,end,exits=fixture(c)
                self.assertEqual(ar.android_exclusive.native_conditional_refresh(b[head],b,k,ar),(set(range(begin,end,4)),entry,{head}))
                image=ar.rewrite(struct.pack('<512I',*v),entry_offsets=(0,entry,*exits))
                self.assertEqual(image.bytes,struct.pack('<512I',*v));self.assertFalse(image.sites)
                pending=[(entry,False)];seen=set()
                while pending:
                    pc,live=pending.pop()
                    if (pc,live) in seen:continue
                    seen.add((pc,live))
                    if not begin<=pc<end:self.assertFalse(live);continue
                    ins=b[pc]
                    if ins.mnemonic in ar.EXCLUSIVE_LOADS:self.assertFalse(live);live=True
                    elif ins.mnemonic in ar.EXCLUSIVE_STORES:self.assertTrue(live);live=False
                    elif ins.mnemonic=='clrex':live=False
                    pending.extend((target,live) for target in ar.android_exclusive.successors(ins))
    def test_nonregister_control_bits_and_tb_width_or_testbit_cannot_be_erased(self):
        for c in CASES:
            v,o,b,k,begin,entry,head,end,exits=fixture(c)
            for i,w in enumerate(c['words']):
                mask=sum(31<<shift for shift in c['fields'][i]);bits=c['external_bits'].get(i)
                if bits is not None:mask|=0x3FFFFFF if bits==26 else ((1<<bits)-1)<<5
                for bit in range(32):
                    if mask>>bit&1:continue
                    changed=dict(b);ck=dict(k);pc=begin+i*4
                    try:changed[pc]=ar.decode(w^(1<<bit),pc);ck[pc]=ar.site_kind(changed[pc]);r=ar.android_exclusive.native_conditional_refresh(changed[head],changed,ck,ar)
                    except ar.RewriteError:r=None
                    self.assertIsNone(r,(c['name'],i,bit))
    def test_reserved_roles_aliases_and_missing_safety_words_refuse(self):
        for c in CASES:
            v,o,b,k,begin,entry,head,end,exits=fixture(c)
            roles={w>>shift&31 for w,fs in zip(c['words'],c['fields']) for shift in fs}-{31}
            for role in roles:
                for forbidden in (18,29,30,31,next(r for r in roles if r!=role)):
                    changed=list(v)
                    for i,(w,fs) in enumerate(zip(c['words'],c['fields'])):
                        value=w
                        for shift in fs:
                            if w>>shift&31==role:value=value&~(31<<shift)|forbidden<<shift
                        changed[begin//4+i]=value
                    bo={pc:ar.decode(w,pc) for pc,w in ((i*4,w) for i,w in enumerate(changed))};ko={pc:ar.site_kind(ins) for pc,ins in bo.items()}
                    try:r=ar.android_exclusive.native_conditional_refresh(bo[head],bo,ko,ar)
                    except ar.RewriteError:r=None
                    self.assertIsNone(r,(c['name'],role,forbidden))
            for pc in range(begin,end,4):
                partial=dict(b);del partial[pc]
                self.assertIsNone(ar.android_exclusive.native_conditional_refresh(b[head],partial,k,ar))

    def test_every_other_metadata_entry_and_all_source_rewrites_refuse(self):
        for c in CASES:
            v,o,b,k,begin,entry,head,end,exits=fixture(c)
            for pc in set(range(begin,end,4))-{entry}:
                with self.assertRaises(ar.RewriteError):ar.android_exclusive.plan_regions(o,k,(0,entry,*exits,pc),ar)
            for pc in range(begin,end,4):
                for kind in ('x18','gate','parameter','parameter_tail'):
                    changed=dict(k);changed[pc]=kind
                    with self.assertRaises(ar.RewriteError):ar.android_exclusive.native_conditional_refresh(b[head],b,changed,ar)
if __name__=='__main__':unittest.main()
