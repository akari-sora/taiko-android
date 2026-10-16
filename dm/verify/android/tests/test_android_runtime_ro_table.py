"""A finite RO switch with runtime facts instead of assumed callee saves."""
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(ROOT/'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso
from test_nso_format import mutable_source,write_image


def fixture(values=(0,2,7)):
    source=mutable_source()
    words=[0xD65F03C0]*48
    # X25 crosses a call. No static preservation claim is needed: the load's
    # inline preflight checks the actual value at runtime.
    words[:13]=[0x90000039,0x91200339,0x94000026,0xD503201F,
                0x7100091F,0x540002E8,0x2A0803E8,0x100000C9,
                0x78687B2A,0x8B0A0929,0x2A1F03FA,0x2A1F03FB,0xD61F0120]
    words[20]=0x52800552  # Case7 needs x18 rewriting and finite CFG expansion.
    write_image(source,0,'<I',0x140000C0)
    write_image(source,0x300,'<48I',*words)
    write_image(source,0x4800,'<3H',*values)
    return source


def rewrite(source,**changes):
    nso=parse_nso(source)
    options=dict(entry_offset=0x300,text_size=nso.sections[0].size,
                 code_ranges=((0x300,0x3C0),),package_version=2,checked_stack=True,
                 proven_guest_indirect_offsets=(0x330,),readonly_ranges=((0x4000,0x8000),))
    return ar.rewrite(nso.image,**(options|changes))


def assert_normalized_guard(test, source, image, branch, *, planner=ar._guarded_native_readonly_table):
    """Check the fallback's real emitted guard and unchanged source, not a mock.

    Prefix shape and CMP dominance are not prerequisites for this path. Actual
    table/base/full-width index failures must stop before the original read and
    restore every register, flags, SP and virtual x18.
    """
    from dataclasses import replace
    from test_android_rewrite import Machine
    nso=parse_nso(source);raw=nso.image
    by_pc={}
    for pc in range(0x300,min(0x1000,nso.sections[0].size),4):
        try:
            decoded=ar.decode(struct.unpack_from('<I',raw,pc)[0],pc)
            by_pc[pc]=decoded if isinstance(decoded,ar.FatalWord) else ar.Instruction(decoded)
        except ar.RewriteError:pass  # Unselected fixture padding is not code.
    # Wide canonical forms opt in explicitly; never silently fall back from
    # the bounded normalizer to a different proof when a fixture changes.
    test.assertIn(planner,(ar._guarded_native_readonly_table,ar.readonly_guest_table))
    plan=planner(by_pc[branch],by_pc,set(),raw,((0x4000,0x8000),))
    test.assertIsNotNone(plan)
    roles=[plan[key] for key in ('target_register','loaded_register','table_register','index_register')]
    test.assertEqual(len(set(roles)),4)
    test.assertTrue(all(0<=role<29 and role!=18 for role in roles))
    load=plan['load_offset'];site=next(s for s in image.sites if s.offset==load)
    test.assertEqual(image.bytes[branch:branch+4],raw[branch:branch+4])
    patched={s.offset for s in image.sites}
    for pc in range(0x300,min(0x1000,nso.sections[0].size),4):
        if pc not in patched:test.assertEqual(image.bytes[pc:pc+4],raw[pc:pc+4],hex(pc))
    test.assertEqual(image.bytes[0x4000:0x8000],raw[0x4000:0x8000])
    code=[]
    for ins in ar.MD.disasm(image.bytes[site.trampoline:],site.trampoline):
        code.append(ins)
        if ins.mnemonic=='brk':break
    test.assertFalse(any(i.mnemonic in ('bl','blr') for i in code))
    test.assertIn(('cmp',f"x{plan['index_register']}, #{hex(plan['index_bound']) if plan['index_bound']>=10 else plan['index_bound']}"),
                  [(i.mnemonic,i.op_str) for i in code])
    test.assertEqual(sum(bytes(i.bytes)==raw[load:load+4] for i in code),1)
    for mode in ('upper','bound','table','base'):
        model=Machine(replace(image,entry_offset=load))
        model.x[plan['index_register']]=0
        model.x[plan['table_register']]=plan['table_offset']
        model.x[plan['target_register']]=plan['base']
        if mode=='upper':model.x[plan['index_register']]=1<<32
        if mode=='bound':model.x[plan['index_register']]=plan['index_bound']+1
        if mode=='table':model.x[plan['table_register']]=0
        if mode=='base':model.x[plan['target_register']]=0
        model.flags=0xA0000000;model.store(model.state,0x1122334455667788,8)
        before=list(model.x)
        with test.subTest(guard_failure=mode),test.assertRaisesRegex(AssertionError,'instruction brk'):model.run()
        test.assertEqual((model.x,model.sp,model.flags),(before,model.start_sp,0xA0000000))
        test.assertEqual(model.load(model.state,8),0x1122334455667788)


class RuntimeRoTableTests(unittest.TestCase):
    def test_finite_cfg_and_guarded_original_load_keep_native_branch(self):
        package,report=ai.import_module(fixture(),'main',package_version=2,checked_stack=True,
                                        indirect_policy='guarded-host')
        discovery=report['code_discovery'];plan=discovery['readonly_guest_jump_tables'][0]
        self.assertEqual(plan['rule'],'runtime-base-index-u16-ro-lsl2-v1')
        self.assertEqual((plan['offset'],plan['load_offset'],plan['table_offset'],plan['base']),
                         (0x330,0x320,0x4800,0x334))
        self.assertEqual(plan['target_values'],[0,2,7])
        self.assertIn(0x350,discovery['roots'])
        self.assertNotIn(0x330,discovery['guarded_indirect_sites'])
        self.assertIn(0x320,[x['offset'] for x in report['rewrite']['sites']])
        self.assertNotIn(0x330,[x['offset'] for x in report['rewrite']['sites']])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(struct.unpack_from('<I',package,payload+0x330)[0],0xD61F0120)

    def test_inline_stub_has_no_call_and_restores_both_paths(self):
        image=rewrite(fixture());site=next(x for x in image.sites if x.offset==0x320)
        code=[]
        for ins in ar.MD.disasm(image.bytes[site.trampoline:],site.trampoline):
            code.append(ins)
            if ins.mnemonic=='brk':break
        self.assertFalse(any(x.mnemonic in ('bl','blr') for x in code))
        self.assertEqual((code[0].mnemonic,code[0].op_str),('sub','sp, sp, #0x20'))
        self.assertIn(('cmp','x8, #2'),[(x.mnemonic,x.op_str) for x in code])
        self.assertEqual(sum(x.mnemonic=='msr' and x.op_str.startswith('nzcv,') for x in code),2)
        self.assertEqual(sum(x.mnemonic=='add' and x.op_str=='sp, sp, #0x20' for x in code),2)
        original=next(x for x in code if x.bytes==ar.word(0x78687B2A))
        self.assertEqual(code[code.index(original)-1].op_str,'sp, sp, #0x20')
        self.assertEqual((code[-2].mnemonic,code[-2].op_str),('add','sp, sp, #0x20'))
        self.assertFalse(any('x18' in x.op_str for x in code))

    def test_missing_facts_entries_clobbers_and_exception_refuse(self):
        for changes in ({'readonly_ranges':()}, {'checked_stack':False},
                        {'guarded_indirect_offsets':(0x330,)},
                        {'code_ranges':((0x300,0x350),)}):
            with self.subTest(changes=changes),self.assertRaises(ar.RewriteError):rewrite(fixture(),**changes)
        for entry in (0x31C,0x320):
            assert_normalized_guard(self,fixture(),rewrite(fixture(),entry_offsets=(entry,)),0x330)
        for entry in range(0x324,0x334,4):
            with self.subTest(entry=hex(entry)),self.assertRaises(ar.RewriteError):
                rewrite(fixture(),entry_offsets=(entry,))
        # Direct branches are entries even when omitted from entry_offsets.
        candidate=fixture();write_image(candidate,0x30C,'<I',0x14000005)
        assert_normalized_guard(self,candidate,rewrite(candidate),0x330)
        for pc,value in ((0x314,0x540002E2),(0x318,0xAA0803E8),(0x320,0x78A87B2A),
                         (0x328,0xAA0003E9),(0x328,0xAA0003EA),(0x328,0xD4000001)):
            candidate=fixture();write_image(candidate,pc,'<I',value)
            if (pc,value) in ((0x314,0x540002E2),(0x318,0xAA0803E8),(0x328,0xAA0003EA)):
                assert_normalized_guard(self,candidate,rewrite(candidate),0x330)
            else:
                with self.subTest(pc=hex(pc),word=hex(value)),self.assertRaises(ar.RewriteError):rewrite(candidate)
        candidate=fixture();write_image(candidate,0x308,'<2I',0x90000039,0x91200339)
        assert_normalized_guard(self,candidate,rewrite(candidate),0x330)
        with self.assertRaises(ar.RewriteError):rewrite(fixture((0,2,65535)))


if __name__=='__main__':unittest.main()
