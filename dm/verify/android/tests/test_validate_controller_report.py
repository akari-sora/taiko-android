"""Native-shaped controller evidence and forged identity/capability regressions."""
import copy
import json
from pathlib import Path
import unittest
from test_validate_service_report import load_validator

ROOT=Path(__file__).resolve().parents[4]
def receipt():
    modules=[]
    for directory,cls in (('observation_fixtures',1),('controller_fixtures',0)):
        f=json.loads((ROOT/'dm/platform/android'/directory/'import.json').read_text())
        modules.append({'name':f['name'],'profileClass':cls,'buildId':f['build_id'],
                        'sourceSha256':f['source_sha256'],'packageSha256':f['package_sha256']})
    f=json.loads((ROOT/'dm/platform/android/controller_fixtures/import.json').read_text())
    return {'schemaVersion':1,'suite':'android-controller-sdk','kind':'suite','status':'PASS',
            'gamePlayable':False,'originalGameBoot':'NOT_RUN','physicalControllerVerified':False,
            'adapter':{'mode':'DIAGNOSTIC_RAW','identity':'android-controller-sdk-raw','productComplete':False},
            'operationMode':1,'fullStyle':1,'handheldStyle':0,
            'full':{'sampling':101,'buttons':1,'axes':[2000,-3000,0,0],'attributes':1,'padding':0},
            'handheld':{'sampling':102,'buttons':0,'axes':[0,0,0,0],'attributes':0,'padding':0},
            'vibration':{'permitted':0,'count':0,'handle':0},'sdkFallbackCalls':0,'setupCalls':1,
            'sdkInitializers':1,'moduleInitializers':1,'authorityChecks':3,'deniedRegistrations':0,'loadGeneration':42,
            'forceHits':[{'name':e['name'],'hits':1} for e in f['exports'] if e['name'].startswith('_ZN2nn3hid')],
            'modules':modules,'checks':[{'id':'actual-guest-npad','status':'PASS','detail':'Actual public guest return'}],
            'gates':{f'G{i}':'NOT_RUN' for i in range(1,7)}}

class ControllerReportTests(unittest.TestCase):
    def setUp(self): self.validator=load_validator('validate_controller_report');self.report=receipt()
    def rejects(self,report):
        with self.assertRaises(ValueError): self.validator.summarize(report)
    def test_accepts_exact_guest_receipt_without_promoting_game_or_physical_scope(self):
        r=self.validator.summarize(self.report)
        self.assertEqual(r['controllerSdk'],'PASS');self.assertFalse(r['gamePlayable']);self.assertFalse(r['physicalControllerVerified'])
        self.assertNotIn('G0',r['gates'])
        self.assertTrue(any('OS delivery' in limitation for limitation in r['limitations']))
    def test_persistent_poll_is_same_guest_proof_and_handheld_is_supported(self):
        r=copy.deepcopy(self.report);r['kind']='persistent-poll';r['operationMode']=0;r['fullStyle']=0;r['handheldStyle']=2
        r['full']['buttons']=0;r['full']['axes']=[0,0,0,0];r['full']['attributes']=0
        r['handheld']['attributes']=1;r['handheld']['buttons']=2
        self.assertEqual(self.validator.summarize(r)['controllerSdk'],'PASS')
    def test_every_module_identity_field_and_order_are_bound(self):
        for i in range(2):
            for field in self.report['modules'][i]:
                r=copy.deepcopy(self.report);r['modules'][i][field]=2 if field=='profileClass' else 'forged';self.rejects(r)
        for modules in ([],self.report['modules'][:1],list(reversed(self.report['modules'])),self.report['modules']*2):
            self.rejects({**self.report,'modules':modules})
    def test_capability_and_scope_claims_cannot_be_promoted(self):
        for key,value in (('gamePlayable',True),('physicalControllerVerified',True),('originalGameBoot','PASS')):
            self.rejects({**self.report,key:value})
        for key,value in (('mode','FULL_PRODUCT'),('productComplete',True),('identity','')):
            r=copy.deepcopy(self.report);r['adapter'][key]=value;self.rejects(r)
        r=copy.deepcopy(self.report);r['gates']['G1']='PASS';self.rejects(r)
    def test_integer_fields_reject_bool_float_and_out_of_range_aliases(self):
        for field in ('schemaVersion','operationMode','setupCalls','sdkInitializers','moduleInitializers','authorityChecks','loadGeneration'):
            for value in (True,False,1.0,-1,2**65):self.rejects({**self.report,field:value})
        for i in range(2):
            r=copy.deepcopy(self.report);r['modules'][i]['profileClass']=bool(i==0);self.rejects(r)
    def test_forced_exports_require_all_eleven_without_duplicates(self):
        for replacement in ([],self.report['forceHits'][:-1],self.report['forceHits']+[self.report['forceHits'][0]],self.report['forceHits'][:1]*11):
            self.rejects({**self.report,'forceHits':replacement})
        for value in (0,-1,True,1.0):
            r=copy.deepcopy(self.report);r['forceHits'][0]['hits']=value;self.rejects(r)
    def test_initializer_fallback_and_authority_sentinels_are_exact(self):
        for key in ('sdkFallbackCalls','setupCalls','sdkInitializers','moduleInitializers','authorityChecks','deniedRegistrations'):
            r=copy.deepcopy(self.report);r[key]+=1;self.rejects(r)
    def test_state_layout_validity_and_sample_order(self):
        for name,field,value in (('full','padding',1),('full','attributes',0),('handheld','buttons',1),('handheld','axes',[1,0,0,0]),('full','axes',[0,0,0]),('full','axes',[32768,0,0,0]),('full','sampling',True),('handheld','sampling',101)):
            r=copy.deepcopy(self.report);r[name][field]=value;self.rejects(r)
    def test_native_failure_remains_failure(self):
        r=copy.deepcopy(self.report);r['status']='FAIL';self.assertEqual(self.validator.summarize(r)['controllerSdk'],'FAIL')
        r=copy.deepcopy(self.report);r['checks'][0]['status']='FAIL';self.assertEqual(self.validator.summarize(r)['controllerSdk'],'FAIL')

if __name__=='__main__': unittest.main()
