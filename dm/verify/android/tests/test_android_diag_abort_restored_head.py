"""Structurally consistent restored-head plus dropped-site counterexample."""
import copy,hashlib,struct,unittest
from test_android_diag_abort_publication import public_nso,imported,pin,taiko_verify,KEYS
from nso_format import parse_nso

def restored(source,package,report,explicit_false=False):
    site_start,count=struct.unpack_from('<QQ',package,152)
    index=next(i for i in range(count) if struct.unpack_from('<Q',package,site_start+i*16)[0]==0x100)
    bad=bytearray(package);r=copy.deepcopy(report)
    del bad[site_start+index*16:site_start+(index+1)*16]
    struct.pack_into('<Q',bad,160,count-1)
    for header in (112,360):struct.pack_into('<Q',bad,header,struct.unpack_from('<Q',package,header)[0]-16)
    del r['rewrite']['sites'][index]
    struct.pack_into('<I',bad,20,1)
    payload=struct.unpack_from('<Q',bad,112)[0]
    bad[payload+0x100:payload+0x104]=parse_nso(source).image[0x100:0x104]
    for key in KEYS:r['rewrite'].pop(key,None)
    if explicit_false:r['rewrite']['requires_diag_abort_v1']=False
    image_digest=hashlib.sha256(bad[payload:]).digest();bad[248:280]=image_digest
    r['image_sha256']=image_digest.hex();r['package_size']=len(bad)
    digest=hashlib.sha256(bad).hexdigest();r['package_sha256']=digest;r['callback_audit']['package_sha256']=digest
    return bytes(bad),r

class RestoredHeadTests(unittest.TestCase):
    def test_restored_head_physically_removed_site_and_resigned_all_hashes_refuses(self):
        source=public_nso('used');package,report=imported(source)
        for explicit in (False,True):
            bad,r=restored(source,package,report,explicit)
            for name,verify in [('generic',pin),('taiko',taiko_verify)]:
                with self.subTest(generator=name,explicit_false=explicit),self.assertRaises(ValueError):verify(source,bad,r)

    def test_entire_ticket_attempt_restored_and_matching_sites_removed_refuses(self):
        source=public_nso('used');package,report=imported(source)
        raw=parse_nso(source).image
        site_start,count=struct.unpack_from('<QQ',package,152)
        indexes=[i for i in range(count) if 0x100<=struct.unpack_from('<Q',package,site_start+i*16)[0]<0x120]
        bad=bytearray(package);r=copy.deepcopy(report)
        for index in reversed(indexes):
            del bad[site_start+index*16:site_start+(index+1)*16]
            del r['rewrite']['sites'][index]
        struct.pack_into('<Q',bad,160,count-len(indexes))
        for header in (112,360):struct.pack_into('<Q',bad,header,struct.unpack_from('<Q',package,header)[0]-16*len(indexes))
        struct.pack_into('<I',bad,20,1)
        payload=struct.unpack_from('<Q',bad,112)[0]
        bad[payload+0x100:payload+0x120]=raw[0x100:0x120]
        for key in KEYS:r['rewrite'].pop(key,None)
        image_digest=hashlib.sha256(bad[payload:]).digest();bad[248:280]=image_digest
        r['image_sha256']=image_digest.hex();r['package_size']=len(bad)
        digest=hashlib.sha256(bad).hexdigest();r['package_sha256']=digest;r['callback_audit']['package_sha256']=digest
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            with self.subTest(generator=name),self.assertRaises(ValueError):verify(source,bytes(bad),r)

    def test_restored_head_with_stale_zero_header_count_refuses(self):
        source=public_nso('used');package,report=imported(source)
        bad,r=restored(source,package,report);blob=bytearray(bad)
        struct.pack_into('<Q',blob,160,0)
        digest=hashlib.sha256(blob).hexdigest();r['package_sha256']=digest;r['callback_audit']['package_sha256']=digest
        for name,verify in [('generic',pin),('taiko',taiko_verify)]:
            with self.subTest(generator=name),self.assertRaises(ValueError):verify(source,bytes(blob),r)

if __name__=='__main__':unittest.main(verbosity=2)
