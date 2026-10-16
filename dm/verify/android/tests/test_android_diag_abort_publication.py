"""Combined source-obligation stripping regression for both stock generators."""
import copy,hashlib,struct,unittest
from test_android_diag_abort_flags import public_nso,imported,pin
from test_taiko_diag_abort_reception import verify as taiko_verify
from nso_format import parse_nso
from test_nso_format import write_image
KEYS=('requires_diag_abort_v1','required_diag_abort_abi','diag_abort_call_sites','diag_abort_plt_branches')

def stripped(package,report,explicit_false=False):
    assert struct.unpack_from('<I',package,20)[0]==3
    assert report['rewrite']['diag_abort_call_sites']==[384]
    blob=bytearray(package);struct.pack_into('<I',blob,20,1)
    receipt=copy.deepcopy(report)
    for key in KEYS:receipt['rewrite'].pop(key,None)
    if explicit_false:receipt['rewrite']['requires_diag_abort_v1']=False
    digest=hashlib.sha256(blob).hexdigest()
    receipt['package_sha256']=digest;receipt['callback_audit']['package_sha256']=digest
    return bytes(blob),receipt

def resign(package,receipt):
    receipt=copy.deepcopy(receipt);receipt['package_size']=len(package)
    digest=hashlib.sha256(package).hexdigest()
    receipt['package_sha256']=digest;receipt['callback_audit']['package_sha256']=digest
    return bytes(package),receipt

class CombinedPublicationTests(unittest.TestCase):
    def test_combined_flag_and_four_keys_stripped_even_after_resigning_both_hashes_refuse(self):
        source=public_nso();package,report=imported(source)
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            for explicit in (False,True):
                bad,receipt=stripped(package,report,explicit)
                with self.subTest(generator=name,explicit_false=explicit),self.assertRaises(ValueError):verify(source,bad,receipt)
    def test_legitimate_required_and_explicit_source_retirement_keep_passing(self):
        for mode,flags in [('used',3),('clrex',1),('fresh-load',1)]:
            source=public_nso(mode);package,report=imported(source)
            self.assertEqual(struct.unpack_from('<I',package,20)[0],flags)
            for name,verify in [('generic',pin),('taiko',taiko_verify)]:
                with self.subTest(mode=mode,generator=name):self.assertTrue(verify(source,package,report))
                if flags==1:
                    receipt=copy.deepcopy(report);receipt['rewrite']['requires_diag_abort_v1']=False
                    self.assertTrue(verify(source,package,receipt))
    def test_receipt_code_ranges_or_site_labels_cannot_disable_the_obligation(self):
        source=public_nso();package,report=imported(source);bad,receipt=stripped(package,report)
        receipt['code_ranges']=[]
        for site in receipt['rewrite']['sites']:site['instruction']='omitted semantic label'
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            with self.subTest(generator=name),self.assertRaises(ValueError):verify(source,bad,receipt)
    def test_serialized_exclusive_entry_removal_or_mislabel_cannot_hide_the_source_patch(self):
        source=public_nso();package,report=imported(source)
        for lowered in (False,True):
            initial,receipt=(stripped(package,report) if lowered else (package,copy.deepcopy(report)))
            site_start,count=struct.unpack_from('<QQ',initial,152)
            index=next(i for i in range(count) if struct.unpack_from('<Q',initial,site_start+i*16)[0]==0x100)
            for mutation in ('remove','mislabel'):
                blob=bytearray(initial);r=copy.deepcopy(receipt)
                if mutation=='remove':
                    del blob[site_start+index*16:site_start+(index+1)*16]
                    struct.pack_into('<Q',blob,160,count-1)
                    for header in (112,360):struct.pack_into('<Q',blob,header,struct.unpack_from('<Q',initial,header)[0]-16)
                    del r['rewrite']['sites'][index]
                else:
                    struct.pack_into('<Q',blob,site_start+index*16,0x84)
                    r['rewrite']['sites'][index]['offset']=0x84
                bad,r=resign(blob,r)
                for name,verify in [('generic',pin),('taiko',taiko_verify)]:
                    with self.subTest(lowered=lowered,mutation=mutation,generator=name),self.assertRaises(ValueError):verify(source,bad,r)
    def test_partial_receipt_context_cannot_erase_original_ticket_words(self):
        source=public_nso();package,report=imported(source);bad,r=stripped(package,report)
        r['code_ranges']=[[0x100,0x104],[0x180,0x184],[0x200,0x210]]
        r['code_discovery']['roots']=[0x100,0x180,0x200]
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            with self.subTest(generator=name),self.assertRaises(ValueError):verify(source,bad,r)
    def test_exact_zero_serialized_site_count_downgrade_refuses(self):
        source=public_nso('used');package,report=imported(source)
        bad,r=stripped(package,report);blob=bytearray(bad)
        struct.pack_into('<Q',blob,160,0)
        bad,r=resign(blob,r)
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            with self.subTest(generator=name),self.assertRaises(ValueError):verify(source,bad,r)
    def test_unselected_rx_ticket_bytes_do_not_create_an_obligation_or_entry(self):
        source=bytearray(public_nso('clrex'));template=parse_nso(public_nso('used')).image
        block=list(struct.unpack_from('<8I',template,0x100));begin=0x380
        for index,target,condition in ((3,0x300,1),(6,0x400,0)):
            block[index]=0x54000000|(((target-(begin+index*4))//4)&0x7ffff)<<5|condition
        write_image(source,begin,'<8I',*block)
        write_image(source,0x300,'<2I',0xd5033f5f,0xd65f03c0)
        write_image(source,0x400,'<2I',0x94000000|(((0x200-0x400)//4)&0x3ffffff),0xd65f03c0)
        source=bytes(source);package,report=imported(source)
        self.assertEqual(struct.unpack_from('<I',package,20)[0],1)
        self.assertFalse(any(a<=begin<b for a,b in report['code_ranges']))
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            with self.subTest(generator=name):self.assertTrue(verify(source,package,report))

if __name__=='__main__':unittest.main(verbosity=2)
