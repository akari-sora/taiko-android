"""Source-derived finite BR facts; never host or arbitrary RX permission."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_rewrite as ar
import test_android_native_wait_mutex as wait
sys.path.insert(0,str(ROOT/'dm/tools'))
FUNCTION,PRODUCER,ADD,POP,BR,TARGET=0x100,0x104,0x10c,0x110,0x114,0x140
def raw(words):return struct.pack('<'+'I'*len(words),*words)
def fixture(register=3):
    words=wait.fixture();words += [0xd503201f]*(0x180//4-len(words))
    body=[0xa9bf7bfd,0x90000000|register,0xaa1503e1 if register==0 else 0xaa1503e0,
          0x91000000|(TARGET<<10)|(register<<5)|register,0xa8c17bfd,0xd61f0000|(register<<5)]
    words[FUNCTION//4:BR//4+1]=body;words[TARGET//4]=0xd65f03c0
    return words
def options():return dict(checked_stack=True,package_version=2,entry_offsets=(0,wait.BEGIN-4,wait.END,wait.CALLEE,FUNCTION,TARGET))
def rewrite(words=None,**extra):
    opts=options();opts.update(extra)
    return ar.rewrite(raw(fixture() if words is None else words),**opts)
def plan(words=None,entries=None,kinds_override=None,protected=(),remove=None):
    words=fixture() if words is None else words
    ops={i*4:ar.Instruction(ar.decode(word,i*4)) for i,word in enumerate(words)}
    kinds={pc:ar.site_kind(op) for pc,op in ops.items()};kinds[FUNCTION]='stack_check';kinds[POP]='stack_check'
    kinds.update(kinds_override or {})
    if remove is not None:del ops[remove]
    return ar.native_transfer_plan(ops[BR],ops,set(options()['entry_offsets'] if entries is None else entries),raw(words),kinds,protected)

class NativeTransferTests(unittest.TestCase):
    def test_existing_global_failure_then_proof_recording_keeps_native_br(self):
        with self.assertRaisesRegex(ar.RewriteError,'native wait lacks explicit processed transfer facts'):rewrite()
        image=rewrite(native_transfer_candidates={BR:TARGET})
        self.assertEqual(raw(fixture())[BR:BR+4],image.bytes[BR:BR+4])
        self.assertNotIn(BR,[site.offset for site in image.sites])
        self.assertEqual(1,len(image.native_transfer_proofs))
        self.assertEqual((PRODUCER,TARGET),(image.native_transfer_proofs[0]['producer'],image.native_transfer_proofs[0]['target']))
        self.assertFalse(any(gate.kind==ar.INDIRECT_HOST for gate in image.gates))

    def test_valid_registers_adr_leaf_and_checked_sp_do_not_change_emission(self):
        for register in range(29):
            if register==18:continue
            image=rewrite(fixture(register),native_transfer_candidates={BR:TARGET})
            self.assertEqual(raw(fixture(register))[BR:BR+4],image.bytes[BR:BR+4])
        words=fixture();words[PRODUCER//4]=0x10000003|(((TARGET-PRODUCER)//4)<<5);words[ADD//4]=0xd503201f
        self.assertIsNotNone(plan(words))
        opts=dict(entry_offset=FUNCTION,code_ranges=((FUNCTION,TARGET+4),),entry_offsets=(FUNCTION,TARGET),checked_stack=True,package_version=2)
        old=ar.rewrite(raw(fixture()),**opts);new=ar.rewrite(raw(fixture()),native_transfer_candidates={BR:TARGET},**opts)
        self.assertEqual(old.bytes,new.bytes)
        self.assertEqual(old.metadata(),{key:value for key,value in new.metadata().items() if key!='native_transfer_proofs'})

    def test_candidate_is_not_permission_for_forged_unselected_or_unrooted_target(self):
        for candidates in ({BR:TARGET+4},{BR:0xdead},{BR:True},{True:TARGET},{BR:'320'},[BR]):
            with self.subTest(candidates=candidates),self.assertRaises(ar.RewriteError):rewrite(native_transfer_candidates=candidates)
        with self.assertRaises(ar.RewriteError):rewrite(native_transfer_candidates={BR:TARGET},independent_entry_offsets=(0,FUNCTION))
        roots=(*options()['entry_offsets'],TARGET+4)
        with self.assertRaisesRegex(ar.RewriteError,'source/target proof'):rewrite(native_transfer_candidates={BR:TARGET+4},entry_offsets=roots)
        with self.assertRaises(ar.RewriteError):rewrite(native_transfer_candidates={BR:TARGET},guarded_indirect_offsets=(BR,),indirect_policy='guarded-host')

    def test_source_alias_width_flags_call_opaque_gate_or_missing_word_refuses(self):
        for word in (0x11150063,0xb1050063,0x91450063,0xaa0403e3,0x2b040063,0xd40006c1,0x94000001,0xd61f0080,0xd65f03c0):
            words=fixture();words[ADD//4]=word
            self.assertIsNone(plan(words),hex(word))
        for word in (0x52800023,0x2b040063,0xb1000463):
            words=fixture();words[0x108//4]=word
            self.assertIsNone(plan(words),hex(word))
        for missing in (PRODUCER,0x108,ADD,POP):self.assertIsNone(plan(remove=missing))
        for kind in ('gate','x18','tls','readonly_table_load'):
            self.assertIsNone(plan(kinds_override={POP:kind}))
        words=fixture();words[POP//4]=0xd40006c1
        self.assertIsNone(plan(words,kinds_override={POP:'stack_check'}))
        self.assertIsNone(plan(protected=((PRODUCER,PRODUCER+4),)))
        self.assertIsNone(plan(protected=((TARGET,TARGET+4),)))

    def test_all_mid_entries_and_external_direct_successors_refuse(self):
        for pc in (0x108,ADD,POP,BR):
            with self.assertRaises(ar.RewriteError):rewrite(native_transfer_candidates={BR:TARGET},entry_offsets=(*options()['entry_offsets'],pc))
            words=fixture();words[0xf0//4]=ar.branch(0xf0,pc)
            with self.assertRaises(ar.RewriteError):rewrite(words,native_transfer_candidates={BR:TARGET})
        self.assertIsNotNone(plan(entries=(*options()['entry_offsets'],PRODUCER)))

    def test_finite_table_case_not_independent_root_still_invalidates_prefix(self):
        words=fixture();words += [0xd503201f]*(0x400//4-len(words));image=bytearray(0x800);image[:len(words)*4]=raw(words)
        dispatch,branch,table=0x200,0x21c,0x600;base=PRODUCER
        delta=base-(dispatch+16)
        address=0x10000000|((delta&3)<<29)|(((delta>>2)&0x7ffff)<<5)|10
        sequence=(0x7100053f,0x54000008|(((TARGET-dispatch-4)//4)&0x7ffff)<<5,
                  0x9000000c,0x9118018c,address,0x3869698b,0x8b0b094a,0xd61f0140)
        struct.pack_into('<8I',image,dispatch,*sequence)
        opts=options();opts.update(text_size=0x400,readonly_ranges=((0x600,0x800),),proven_guest_indirect_offsets=(branch,),native_transfer_candidates={BR:TARGET})
        struct.pack_into('<2B',image,table,0,(TARGET-base)//4)
        ar.rewrite(bytes(image),**opts)
        image[table]=(ADD-base)//4
        with self.assertRaisesRegex(ar.RewriteError,'source/target proof'):ar.rewrite(bytes(image),**opts)

    def test_authored_formal_import_records_candidate_only_after_source_proof(self):
        import android_import as importer
        import gen_android_kernel as generator
        text=bytearray(struct.pack('<I',0xd503201f)*0x400)
        struct.pack_into('<2I',text,0,ar.branch(0,0x200),0x40)
        struct.pack_into('<4s6I',text,0x40,b'MOD0',0x8400-0x40,0x9000-0x40,0xa000-0x40,0,0,0x8300-0x40)
        struct.pack_into('<I',text,0x100,0xd65f03c0)
        client=raw(wait.fixture());text[0x200:0x200+len(client)]=client
        functions={'fixture_entry':(0,4,2),'fixture_init':(0x100,4,2),
                   'authored_wait':(0x200,len(client),2),'authored_wait_svc':(0x200+wait.CALLEE,8,2),
                   'constant_tail':(0xc00,24,2),'constant_target':(0xc40,4,2)}
        body=(0xa9bf7bfd,0x90000003,0xaa1503e0,0x91310063,0xa8c17bfd,0xd61f0060)
        struct.pack_into('<6I',text,0xc00,*body);struct.pack_into('<I',text,0xc40,0xd65f03c0)
        source=generator.make_kernel_nso(bytes(text),functions,imports=())
        package,report=importer.import_module(source,'main',checked_stack=True,package_version=2,indirect_policy='guarded-host')
        self.assertTrue(package.startswith(b'DMAMOD02'))
        self.assertEqual([{'offset':0xc14,'target':0xc40}],report['code_discovery']['native_transfer_candidates'])
        self.assertEqual(0xc40,report['rewrite']['native_transfer_proofs'][0]['target'])
        struct.pack_into('<I',text,0xc08,0x2b040063) # effective W3 write, including Capstone alias gaps.
        source=generator.make_kernel_nso(bytes(text),functions,imports=())
        _,negative=importer.import_module(source,'main',checked_stack=True,package_version=2,indirect_policy='guarded-host')
        self.assertEqual([],negative['code_discovery']['native_transfer_candidates'])
        self.assertNotIn('native_transfer_proofs',negative['rewrite'])
        self.assertIn(0xc14,negative['code_discovery']['guarded_indirect_sites'])
        self.assertTrue(any(gate['kind']==ar.INDIRECT_HOST and gate['argument']==3 for gate in negative['rewrite']['gates']))
        with self.assertRaises(importer.ImportError):
            importer.import_module(source,'main',checked_stack=True,package_version=2,indirect_policy='strict')

if __name__=='__main__':unittest.main(verbosity=2)
