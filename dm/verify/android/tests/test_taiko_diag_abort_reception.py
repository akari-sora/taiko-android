"""Authored required-ABI fixtures cannot grant stock title/provider authority."""
import copy,hashlib,struct,tempfile,unittest
from pathlib import Path
import gen_taiko_pins as pins
from nso_format import parse_nso,parse_metadata
from test_android_diag_abort_contract import public_nso,imported

def verify(source,package,report):
    nso=parse_nso(source);metadata=parse_metadata(nso)
    fact=dict(name='main',source_bytes=len(source),source_sha256=nso.source_sha256.hex(),
              decoded_sha256=hashlib.sha256(nso.image).hexdigest(),build_id=nso.build_id.hex())
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'main.dmag';path.write_bytes(package)
        return pins.verify_package(path,report,fact,nso,metadata)

class TaikoRequiredAbiTests(unittest.TestCase):
    def test_title_neutral_verifier_accepts_verified_required_and_unflagged_public_fixtures(self):
        for mode in ('used','clrex','fresh-load'):
            source=public_nso(mode=mode);package,report=imported(source)
            self.assertEqual(struct.unpack_from('<I',package,20)[0],3 if mode=='used' else 1)
            with self.subTest(mode=mode):self.assertEqual(verify(source,package,report)['package_sha256'],hashlib.sha256(package).hexdigest())
    def test_required_flag_receipt_and_checked_bit_are_indivisible(self):
        source=public_nso();package,report=imported(source)
        for flags in (0,1,2,7):
            blob=bytearray(package);struct.pack_into('<I',blob,20,flags)
            with self.subTest(flags=flags),self.assertRaises(ValueError):verify(source,blob,report)
        for changes in (dict(requires_diag_abort_v1=False),dict(required_diag_abort_abi='ordinary-returning-HLE'),
                        dict(diag_abort_call_sites=[0]),dict(diag_abort_plt_branches=[])):
            receipt=copy.deepcopy(report);receipt['rewrite'].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):verify(source,package,receipt)
    def test_unflagged_fixture_cannot_smuggle_required_abi_claim(self):
        source=public_nso(mode='clrex');package,report=imported(source)
        self.assertEqual(struct.unpack_from('<I',package,20)[0],1)
        for key,value in [('requires_diag_abort_v1',True),('required_diag_abort_abi','__dm_android_diag_abort_v1'),
                          ('diag_abort_call_sites',[0]),('diag_abort_plt_branches',[0x20c])]:
            receipt=copy.deepcopy(report);receipt['rewrite'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):verify(source,package,receipt)

if __name__=='__main__':unittest.main(verbosity=2)
