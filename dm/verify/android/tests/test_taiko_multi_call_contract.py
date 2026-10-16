"""Isolated authored pin/EH/CFG fixtures; no provider authority or game bytes.

Only internal compiled source pins and the EH/CFG parsers are substituted in
positive tests. Production pins separately refuse this synthetic NSO. The
independent auditor always inspects actual authored forest/stub machine words.
"""
from contextlib import ExitStack
import copy,hashlib,struct,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'.local/test-env/Lib/site-packages')]
import taiko_call_contract as contract
import taiko_forest_audit as audit
import android_import as importer
import test_taiko_multi_call_forest as multi
import test_taiko_forest_audit as authored


def source_fixture():
    original=bytearray(0x4000);pins=[];records=[]
    for index,start in enumerate((0x1000,0x2000,0x3000)):
        records.append(SimpleNamespace(start=start,end=start+64,fde=0x3500+index*32,cie=0x3400))
        if index==2:
            authored.put(original,start,0xD503201F,0xD65F03C0)
            continue
        authored.put(original,start,0xD503201F,0xD63F0240,0xD65F03C0)
        pins.append(dict(offset=start+4,source_word=0xD63F0240,caller_eh_start=start,caller_eh_end=start+64,
            caller_fde=records[-1].fde,caller_cie=0x3400,
            caller_body_sha256=hashlib.sha256(original[start:start+64]).hexdigest(),
            evidence_start=start,evidence_end=start+12,evidence_sha256=hashlib.sha256(original[start:start+12]).hexdigest(),
            source_role='self-authored-isolated-test-only'))
    nso=SimpleNamespace(source_sha256=bytes.fromhex(contract.MAIN_SHA256),build_id=bytes.fromhex(contract.MAIN_BUILD_ID),
                        image=bytes(original),sections=(SimpleNamespace(offset=0,end=0x4000),))
    return nso,object(),tuple(records),tuple(pins)


class MultiCallerContractTests(unittest.TestCase):
    def harness(self):
        nso,metadata,records,pins=source_fixture();stack=ExitStack();self.addCleanup(stack.close)
        parser=SimpleNamespace(validated_eh_functions=Mock(return_value=records),
            eh_target_set_sha256=lambda rows:audit.target_digest(tuple(row.start for row in rows)))
        stack.enter_context(patch.dict(sys.modules,{'nso_eh':parser}))
        # No caller-supplied mapping/CLI/provider entry reaches these patches.
        stack.enter_context(patch.object(contract,'FOREST_CALLER_PINS',pins))
        stack.enter_context(patch.object(contract,'FOREST_WORD_CHECKS',()))
        stack.enter_context(patch.object(audit,'CALLER_PINS',copy.deepcopy(pins)))
        return nso,metadata,records,pins,parser

    def test_production_source_pins_never_authorize_the_authored_nso(self):
        nso,metadata,_,_=source_fixture()
        with self.assertRaises(ValueError):contract.select_checked_call_forest(nso,metadata)
        nso.source_sha256=bytes(32);self.assertIsNone(contract.select_checked_call_forest(nso,metadata))

    def test_selector_has_sorted_two_canonical_callers_and_one_shared_domain(self):
        nso,metadata,records,pins,_=self.harness();selected=contract.select_checked_call_forest(nso,metadata)
        self.assertEqual(list(pins),selected['callers'])
        self.assertEqual((0x1000,0x2000,0x3000),selected['targets'])
        self.assertEqual(3,selected['target_count'])
        for field in ('source_sha256','build_id'):
            candidate=copy.deepcopy(nso);setattr(candidate,field,bytes(32))
            self.assertIsNone(contract.select_checked_call_forest(candidate,metadata))

    def test_each_source_word_body_and_fde_identity_mutation_refuses(self):
        nso,metadata,records,pins,parser=self.harness()
        for pin in pins:
            for at in range(pin['caller_eh_start'],pin['caller_eh_end'],4):
                candidate=copy.deepcopy(nso);image=bytearray(candidate.image);image[at]^=1;candidate.image=bytes(image)
                with self.subTest(at=at),self.assertRaises(ValueError):contract.select_checked_call_forest(candidate,metadata)
            for field in ('start','end','fde','cie'):
                changed=copy.deepcopy(records);setattr(changed[pins.index(pin)],field,getattr(changed[pins.index(pin)],field)+4)
                parser.validated_eh_functions.return_value=changed
                with self.subTest(field=field),self.assertRaises(ValueError):contract.select_checked_call_forest(nso,metadata)
                parser.validated_eh_functions.return_value=records

    def audit_fixture(self):
        nso,metadata,records,pins,parser=self.harness()
        image,forest,targets,args=multi.multi_fixture()
        for caller,pin in zip(args['callers'],pins):
            caller['offset']=pin['offset'];stub=caller['trampoline']
            authored.put(image,pin['offset'],authored.jump(pin['offset'],stub))
            authored.put(image,stub+44,*authored.address(stub+44,pin['offset']+4,30))
        forest['site_offsets']=[pin['offset'] for pin in pins]
        selected=contract.select_checked_call_forest(nso,metadata);selected.pop('targets')
        discovery=dict(roots=list(targets),independent_roots=list(targets),versioned_checked_call_forests=[selected])
        ranges=[(record.start,record.end) for record in records]
        cfg=Mock(return_value=(ranges,copy.deepcopy(discovery)))
        context=patch.object(importer,'discover_code',cfg);context.start();self.addCleanup(context.stop)
        return [nso,metadata,image,discovery,dict(checked_call_forests=[forest]),args['callers'],ranges,args['fixups'],[]],parser,cfg

    def test_independent_source_audit_rederives_both_callers_and_fresh_roots(self):
        args,parser,cfg=self.audit_fixture()
        parser.validated_eh_functions.reset_mock()
        self.assertEqual(args[4]['checked_call_forests'],audit.verify_checked_call_forests(*args))
        parser.validated_eh_functions.assert_called_once_with(args[0],args[1])
        cfg.assert_called_once_with(args[0],args[1],indirect_policy='guarded-host',checked_stack=True)

    def test_caller_set_descriptor_stub_source_and_receipt_mutations_refuse(self):
        args,parser,cfg=self.audit_fixture()
        for mutation in ('missing','extra','reorder','descriptor','missing-site','extra-site','source-word','fde','roots','origins','ranges'):
            candidate=copy.deepcopy(args);callers=candidate[3]['versioned_checked_call_forests'][0]['callers']
            if mutation=='missing':callers.pop()
            elif mutation=='extra':callers.append(copy.deepcopy(callers[-1]))
            elif mutation=='reorder':callers.reverse()
            elif mutation=='descriptor':callers[1]['source_role']='forged-cpp-type'
            elif mutation=='missing-site':candidate[5].pop()
            elif mutation=='extra-site':candidate[5].append(copy.deepcopy(candidate[5][0]))
            elif mutation=='source-word':
                original=bytearray(candidate[0].image);original[callers[0]['offset']]^=1;candidate[0].image=bytes(original)
            elif mutation=='fde':callers[0]['caller_fde']+=4
            elif mutation=='roots':candidate[3]['roots'].pop()
            elif mutation=='origins':candidate[3]['independent_roots'].pop()
            else:candidate[6].pop()
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):audit.verify_checked_call_forests(*candidate)

    def test_every_canonical_caller_descriptor_field_is_exact(self):
        args,_,_=self.audit_fixture()
        for index,caller in enumerate(args[3]['versioned_checked_call_forests'][0]['callers']):
            for field,value in caller.items():
                candidate=copy.deepcopy(args)
                candidate[3]['versioned_checked_call_forests'][0]['callers'][index][field]=value+4 if type(value) is int else value+'-forged'
                with self.subTest(caller=index,field=field),self.assertRaises(ValueError):audit.verify_checked_call_forests(*candidate)

    def test_nonauthorized_site_cannot_alias_forest_or_stub_with_resigned_actual_branch(self):
        args,_,_=self.audit_fixture();forest=args[4]['checked_call_forests'][0]
        owned=[forest['start'],forest['start']+4,forest['failure_offset'],forest['end']-4]
        owned.extend(site['trampoline']+offset for site in args[5] for offset in (0,4,32,56))
        def alias(trampoline):
            candidate=copy.deepcopy(args)
            candidate[5].append(dict(offset=0x3000,trampoline=trampoline))
            authored.put(candidate[2],0x3000,authored.jump(0x3000,trampoline))
            # Receipt hashes are recomputed; direct source B and Site agree.
            # This remains an isolated source/EH/CFG test, not a capsule bypass.
            candidate[4]['image_sha256']=hashlib.sha256(candidate[2]).hexdigest()
            return candidate
        for trampoline in owned:
            with self.subTest(trampoline=trampoline),self.assertRaisesRegex(ValueError,'nonauthorized site'):
                audit.verify_checked_call_forests(*alias(trampoline))
        outside=(len(args[2])+15)&~15
        args[2].extend(bytes(outside-len(args[2]))+struct.pack('<II',0xD503201F,0xD65F03C0))
        candidate=alias(outside)
        self.assertEqual(candidate[4]['checked_call_forests'],audit.verify_checked_call_forests(*candidate))


if __name__=='__main__':unittest.main()
