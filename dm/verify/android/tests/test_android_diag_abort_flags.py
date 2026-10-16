"""Required ABI publication rechecks actual source and every controlled PLT."""
import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from test_android_diag_abort_contract import public_nso, imported, PLT, ABORT
from test_nso_format import write_image
from nso_format import parse_nso, parse_metadata
import android_rewrite as ar
import gen_android_original_pins as pins


def pin(source,package,report):
    nso=parse_nso(source);metadata=parse_metadata(nso)
    fact=dict(name='main',source_sha256=nso.source_sha256.hex(),build_id=nso.build_id.hex(),source_bytes=len(source))
    with tempfile.TemporaryDirectory() as directory:
        path=Path(directory)/'main.dmag';path.write_bytes(package)
        return pins.package_pin(path,report,fact,nso,metadata)


def update_digest(report,package):
    report=copy.deepcopy(report);digest=hashlib.sha256(package).hexdigest()
    report['package_sha256']=digest;report['callback_audit']['package_sha256']=digest
    return report


class DiagAbortFlagTests(unittest.TestCase):
    def test_stock_pin_accepts_only_matching_required_or_legacy_receipts(self):
        for mode,flags in (('used',3),('clrex',1),('fresh-load',1)):
            with self.subTest(mode=mode):
                source=public_nso(mode);package,report=imported(source)
                self.assertEqual(struct.unpack_from('<I',package,20)[0],flags)
                self.assertEqual(pin(source,package,report)['package_sha256'],hashlib.sha256(package).hexdigest())

    def test_unknown_missing_checked_and_inconsistent_flags_are_rejected(self):
        source=public_nso();package,report=imported(source)
        for flags in (0,2,4,5,6,7,0x80000003):
            broken=bytearray(package);struct.pack_into('<I',broken,20,flags)
            with self.subTest(flags=flags),self.assertRaises(ValueError):
                pin(source,bytes(broken),update_digest(report,broken))
        for changes in (dict(requires_diag_abort_v1=False),dict(required_diag_abort_abi='any-returning-host'),
                        dict(diag_abort_call_sites=[0]),dict(diag_abort_plt_branches=[])):
            bad=copy.deepcopy(report);bad['rewrite'].update(changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):pin(source,package,bad)

    def test_wrong_serialized_gate_cannot_be_repaired_by_json_hashes(self):
        source=public_nso();package,report=imported(source);start,count=struct.unpack_from('<QQ',package,136)
        position=next(at for at in range(start,start+count*32,32) if struct.unpack_from('<Q',package,at+8)[0]==PLT+12)
        broken=bytearray(package);struct.pack_into('<I',broken,position+20,16)
        with self.assertRaises(ValueError):pin(source,bytes(broken),update_digest(report,broken))

    def test_all_selected_matching_plts_are_gated_even_when_only_one_call_is_consumed(self):
        source=bytearray(public_nso());nso=parse_nso(source)
        write_image(source,0x300,'<4I',*struct.unpack_from('<4I',nso.image,PLT))
        write_image(source,ABORT+4,'<I',ar.branch(ABORT+4,0x300))
        source=bytes(source);package,report=imported(source)
        self.assertEqual(report['rewrite']['diag_abort_call_sites'],[ABORT])
        self.assertEqual(report['rewrite']['diag_abort_plt_branches'],[PLT+12,0x30c])
        self.assertTrue(pin(source,package,report))

    def test_unselected_matching_plt_is_rejected_without_code_promotion(self):
        source=bytearray(public_nso());nso=parse_nso(source)
        write_image(source,0x300,'<4I',*struct.unpack_from('<4I',nso.image,PLT))
        with self.assertRaisesRegex(ar.RewriteError,'uncovered or unselected'):
            imported(bytes(source))


if __name__=='__main__':unittest.main()
