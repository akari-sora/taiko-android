"""Authored source schedules; inputs contain no original game bytes."""
import struct
import unittest
import test_android_native_signed32 as base
from test_android_native_signed32 import fixture,plan,write_image,CMP,LOAD,TABLE,TARGETS


def variant(name):
    roles={'copy':(8,8,8,9),'and':(10,10,10,12),'ccmp':(6,5,17,10),
           'hoisted':(8,8,8,24),'sp':(11,11,11,12)}[name]
    source,_=fixture(roles)
    target,loaded,index,table=roles
    cmp=0x71000C1F|(index<<5)
    hi=0x54000008|(((0x900-CMP-4)//4)<<5)
    page=0x90000020|table;add=0x91200000|(table<<5)|table
    load=0xB8A07800|(index<<16)|(table<<5)|loaded
    target_add=0x8B000000|(table<<16)|(loaded<<5)|target
    suffix=[]
    if name=='copy':
        cmp=0x71000C3F
        prefix=[cmp,hi,page,0x2A0103E8,add]
        suffix=[0x2A1F03E0]
    elif name=='and':
        prefix=[cmp,hi,page,0x92407D4A,add]
        suffix=[0x2A1F03EB]
    elif name=='ccmp':
        write_image(source,CMP-4,'<I',0xEB01009F) # CMP X4,X1 determines LO
        prefix=[0x7A433A22,hi,page,add]
        suffix=[0x91000484,0x2A1203E5]
    elif name=='hoisted':
        write_image(source,0x300,'<4I',page,add,0xD63F0080,0x1400002D)
        prefix=[cmp,hi,0xD503201F,0xD503201F]
        suffix=[0x2A1703FB]
    else:
        prefix=[cmp,hi,page,add,0x910143EA] # ADD X10,SP,#80
        suffix=[0x91002003]
    words=[*prefix,load,target_add,*suffix,0xD61F0000|(target<<5)]
    write_image(source,CMP,'<'+str(len(words))+'I',*words)
    return source,CMP+(len(words)-1)*4,roles,CMP+len(prefix)*4


class NativeSigned32VariantTests(unittest.TestCase):
    image=base.NativeSigned32Tests.image
    execute=base.NativeSigned32Tests.execute
    def test_wcopy_and_masks_keep_original_zero_extension_and_suffix(self):
        for name in ('copy','and','sp'):
            source,branch,roles,load=variant(name)
            self.assertIsNotNone(plan(source,branch))
            for index,target in enumerate(TARGETS):
                values={1:(1<<40)|index} if name=='copy' else {}
                if name=='and':index|=1<<40
                result=self.execute(roles,index,custom=(source,branch),register_values=values)
                expected=result['registers'][:]
                expected[roles[1]]=result['base']+target;expected[roles[3]]=result['base']+TABLE
                if name=='copy':expected[0]=0
                if name=='and':expected[11]=0
                if name=='sp':expected[10]=result['stack']+80;expected[3]=expected[0]+8
                flags=0x60000000 if target==TARGETS[-1] else 0x80000000
                self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))
                self.assertEqual((expected,result['stack'],flags,result['vectors']),result['final'])

    def test_ccmp_true_and_false_paths_and_virtual_suffix(self):
        source,branch,roles,load=variant('ccmp')
        self.assertEqual('ccmp-w-nzcv2-lo-hi',plan(source,branch)['bound_candidate_kind'])
        for index,target in enumerate(TARGETS):
            result=self.execute(roles,index,entry=CMP-4,custom=(source,branch),register_values={4:1,1:2})
            expected=result['registers'][:];expected[4]=2;expected[5]=0x11223344
            expected[6]=result['base']+target;expected[10]=result['base']+TABLE
            flags=0x60000000 if index==3 else 0x80000000
            self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))
            self.assertEqual((expected,result['stack'],flags,result['vectors']),result['final'])
            self.assertEqual(0xAABBCCDD11223344,result['virtual_x18'])
        result=self.execute(roles,0xFFFFFFFFFFFFFFFF,entry=CMP-4,custom=(source,branch),register_values={4:2,1:1})
        self.assertEqual((True,False,0),(result['returned'],result['trapped'],result['reads']))
        self.assertEqual((result['registers'],result['stack'],0x20000000,result['vectors']),result['final'])

    def test_hoisted_across_call_requires_live_table_and_never_dominance(self):
        source,branch,roles,load=variant('hoisted')
        self.assertFalse(plan(source,branch)['constructor_dominance_proven'])
        for index in range(4):
            result=self.execute(roles,index,entry=load,custom=(source,branch))
            expected=result['registers'][:];expected[8]=result['base']+TARGETS[index]
            expected[27]=expected[23]&0xFFFFFFFF
            self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))
            self.assertEqual((expected,result['stack'],0xB0000000,result['vectors']),result['final'])
        for index,bad in ((0,'table'),(4,None),(1<<32,None)):
            result=self.execute(roles,index,entry=load,bad=bad,custom=(source,branch))
            self.assertEqual((False,True,0),(result['returned'],result['trapped'],result['reads']))
            self.assertEqual(result['initial'],result['final'])

    def test_variant_mutations_and_late_postload_entries_refuse(self):
        for name in ('copy','and','ccmp','hoisted','sp'):
            source,branch,roles,load=variant(name)
            for entry in range(load+4,branch+4,4):
                self.assertIsNone(plan(source,branch,entries=(entry,)))
        for name,pc,word in (('copy',CMP+12,0xAA0103E8),('and',CMP+12,0x9240794A),
                            ('ccmp',CMP,0x7A433A20),('ccmp',CMP,0x7A432A22),
                            ('sp',CMP+16,0x910143FF)):
            source,branch,_,_=variant(name);write_image(source,pc,'<I',word)
            self.assertIsNone(plan(source,branch))

    def test_split_table_copy_index_overwrite_and_virtual_ldp_before_add(self):
        roles=(10,12,9,14);source,_=fixture(roles)
        words=[0x71000D3F,0x540009E8,0x9000002C,0x9120018C,0xAA0C03EE,
               0xB8A979CC,0xB9400009,0x29404835,0x8B0E018A,0xD61F0140]
        write_image(source,CMP,'<10I',*words);branch=CMP+36;load=CMP+20
        self.assertIsNotNone(plan(source,branch))
        for index,target in enumerate(TARGETS):
            result=self.execute(roles,index,custom=(source,branch),register_values={0:0x30002000,1:0x30002010},
                memory_values=((0x30002000,struct.pack('<I',0x99)),(0x30002010,struct.pack('<II',0x1234,0x55667788))))
            expected=result['registers'][:];expected[9]=0x99;expected[12]=(target-TABLE)&((1<<64)-1)
            expected[14]=result['base']+TABLE;expected[10]=result['base']+target;expected[21]=0x1234
            self.assertEqual((True,False,1),(result['returned'],result['trapped'],result['reads']))
            self.assertEqual((expected,result['stack'],0x60000000 if index==3 else 0x80000000,result['vectors']),result['final'])
            self.assertEqual(0x55667788,result['virtual_x18'])
        for entry in range(load+4,branch+4,4):self.assertIsNone(plan(source,branch,entries=(entry,)))

    def test_each_variant_live_bad_values_fail_at_load_before_read_or_effects(self):
        for name in ('copy','and','ccmp','hoisted','sp'):
            source,branch,roles,load=variant(name)
            for index,bad in ((0,'table'),(4,None),(1<<32,None),(0xFFFFFFFFFFFFFFFF,None)):
                result=self.execute(roles,index,bad=bad,entry=load,custom=(source,branch))
                self.assertEqual((False,True,0),(result['returned'],result['trapped'],result['reads']))
                self.assertEqual(result['initial'],result['final'])
                self.assertEqual(0xAABBCCDD11223344,result['virtual_x18'])


if __name__=='__main__':unittest.main()
