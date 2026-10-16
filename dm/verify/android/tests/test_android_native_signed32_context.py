"""Authored complete contexts; no original source bytes or root shortcuts."""
from pathlib import Path
import struct,sys,unittest
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'dm/verify/android/tests')]
import android_rewrite as ar
import android_import
import test_android_native_signed32 as base
from test_android_native_signed32 import fixture,plan,write_image,CMP,LOAD,ADD,TABLE,TARGETS

def classify(source,branch,known_tables=()):
    raw=base.parse_nso(source).image
    by_pc={pc:ar.Instruction(ar.decode(struct.unpack_from('<I',raw,pc)[0],pc)) for pc in range(0x300,0x1000,4)}
    return ar.readonly_guest_table(by_pc[branch],by_pc,set(),raw,((0x4000,0x8000),),
        text_size=0x4000,root_entries={0x300},known_tables=known_tables)


def context_fixture(copy=False):
    roles=(10,12,9,14) if copy else (8,8,8,9)
    source,branch=fixture(roles)
    table=roles[3]
    write_image(source,0x300,'<I',0x14000020) # root branches to real function380
    write_image(source,0x320,'<3I',0x90000020|table,0x91300000|(table<<5)|table,0xD65F03C0)
    write_image(source,0x4C00,'<4i',*(target-0x4C00 for target in TARGETS))
    write_image(source,CMP+8,'<2I',0xD503201F,0xD503201F) # constructor is hoisted
    if copy:
        write_image(source,0x380,'<I',0x14000004)
        write_image(source,0x390,'<4I',0x9000002C,0x9120018C,0xAA0C03EE,0x14000009)
    else:
        write_image(source,0x380,'<4I',0x90000020|table,0x91200000|(table<<5)|table,0xD503201F,0x1400000D)
    return source,branch,roles


class NativeSigned32ContextTests(unittest.TestCase):
    image=base.NativeSigned32Tests.image
    execute=base.NativeSigned32Tests.execute

    def test_prior_function_same_register_object_does_not_make_real_hoisted_table_ambiguous(self):
        for copied in (False,True):
            source,branch,roles=context_fixture(copied)
            selected=plan(source,branch)
            self.assertIsNotNone(selected)
            self.assertEqual(TABLE,selected['table_offset'])
            self.assertFalse(selected['constructor_dominance_proven'])
            self.assertEqual(list(TARGETS),selected['target_offsets'])

    def test_real_original_cpu_guard_preserves_state_and_full64_pre_read_refusals(self):
        for copied in (False,True):
            source,branch,roles=context_fixture(copied)
            for index,target in enumerate(TARGETS):
                result=self.execute(roles,index,entry=LOAD,custom=(source,branch))
                expected=result['registers'][:];expected[roles[1]]=(target-TABLE)&((1<<64)-1)
                expected[roles[0]]=result['base']+target
                self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))
                self.assertEqual((expected,result['stack'],0xB0000000,result['vectors']),result['final'])
            for index,bad in ((0,'table'),(4,None),(1<<32,None),(0xFFFFFFFFFFFFFFFF,None)):
                result=self.execute(roles,index,bad=bad,entry=LOAD,custom=(source,branch))
                self.assertEqual((False,True,0),(result['returned'],result['trapped'],result['reads']))
                self.assertEqual(result['initial'],result['final'])

    def test_two_reaching_objects_calls_and_effective_W_X_flag_writes_refuse(self):
        source,branch,_=context_fixture()
        write_image(source,0x300,'<I',0xB4000100) # CBZ X0 ->320, otherwise eventually380
        write_image(source,0x304,'<I',0x1400001F)
        write_image(source,0x328,'<I',0x14000026) # wrong object also reaches CMP
        self.assertIsNone(plan(source,branch))
        for word in (0xAA0003E9,0x2A0003E9,0xB1000409,0x31000409,0x9A810009,0x9400015E,0xD4000001):
            source,branch,_=context_fixture();write_image(source,0x388,'<I',word)
            self.assertIsNone(plan(source,branch))

    def test_postload_entries_and_table_target_metadata_bounds_stay_strict(self):
        source,branch,_=context_fixture()
        for entry in range(LOAD+4,branch+4,4):self.assertIsNone(plan(source,branch,entries=(entry,)))
        self.assertIsNone(plan(source,branch,protected=((TABLE,TABLE+16),)))
        self.assertIsNone(plan(source,branch,protected=((TARGETS[0],TARGETS[0]+4),)))
        self.assertIsNone(plan(source,branch,readonly=((TABLE,TABLE+15),)))
        write_image(source,TABLE,'<i',1)
        self.assertIsNone(plan(source,branch))

    def test_unknown_sibling_overrides_clean_path_and_unresolved_exit_never_closes(self):
        for op in (0xAA0003E9,0x2A0003E9,0xB1000409,0x31000409,0x9A810009,0xD63F0000,0xD61F0000):
            source,branch,_=context_fixture()
            write_image(source,0x388,'<2I',0xB40000C0,0x1400000D) # clean or unknown sibling
            write_image(source,0x3A0,'<2I',op,0x14000007)
            self.assertIsNone(plan(source,branch))
        for op in (0xD61F00E0,0xD63F00E0,0x14001336):
            source,branch,_=context_fixture();write_image(source,0x328,'<I',op)
            self.assertIsNone(plan(source,branch))
        source,branch,_=context_fixture()
        write_image(source,0x328,'<3I',0xB4000040,0xD65F03C0,0x14001334)
        self.assertIsNone(plan(source,branch)) # RET on one arm cannot hide outside on other.

    def test_only_independently_derived_other_dispatch_can_close_prior_function(self):
        source,branch,_=context_fixture()
        write_image(source,0x310,'<7I',0x71000D1F,0x540001E8,0x90000029,0x91300129,
            0xB8A87928,0x8B090108,0xD61F0100)
        write_image(source,0x4C00,'<4i',*(target-0x4C00 for target in (0x340,0x344,0x348,0x34C)))
        prior=classify(source,0x328);self.assertIsNotNone(prior)
        self.assertIsNone(classify(source,branch)) # Unknown prior BR is not a terminal.
        selected=classify(source,branch,({0x328:prior},))
        self.assertIsNotNone(selected);self.assertEqual(TABLE,selected['table_offset'])
        for invalid in (dict(prior,offset=0x324),dict(prior,target_values=[]),
                        dict(prior,base=0x5000,target_values=[0])):
            self.assertIsNone(classify(source,branch,({0x328:invalid},)))
        self.assertIsNone(classify(source,branch,({0x328:prior},{0x328:dict(prior,target_values=[0])})))
        # A current-dispatch mapping supplies no edge for its own proof.
        canonical,canonical_branch=fixture();own=plan(canonical,canonical_branch)
        self.assertIsNone(classify(source,branch,({branch:own},)))
        write_image(source,0x340,'<I',0x31000409) # conditional case kills table W9
        self.assertIsNone(classify(source,branch,({0x328:prior},)))


if __name__=='__main__':unittest.main()
