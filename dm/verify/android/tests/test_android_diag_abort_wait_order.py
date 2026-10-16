"""A consumed fatal ABI must be gated before native wait CFG admission."""
import hashlib
import struct
import unittest

from test_android_diag_abort_contract import public_nso, imported, abort_gates, real_image
from test_android_native_wait_mutex import fixture
from test_nso_format import write_image
import android_rewrite as ar


def source_with_wait():
    source=bytearray(public_nso(defined=True))
    # The source compiler still selects this separate wait function through a
    # normal direct branch; no metadata root or arbitrary callback is granted.
    write_image(source,0x184,'<I',ar.branch(0x184,0x400))
    for index,word in enumerate(fixture()):
        write_image(source,0x400+index*4,'<I',word)
    return bytes(source)


class DiagAbortWaitOrderTests(unittest.TestCase):
    def test_real_audited_package_gates_abort_plt_before_wait_scan(self):
        source=source_with_wait()
        # Model the stock SDK's real case: its defined AbortImpl PLT is not
        # independently supplied as a generic host gate by the caller.
        image=real_image(source,source,guarded_sites=())
        self.assertTrue(image.requires_diag_abort_v1)
        package,report=imported(source)
        self.assertEqual(struct.unpack_from('<I',package,20)[0],3)
        self.assertTrue(report['rewrite']['requires_diag_abort_v1'])
        self.assertEqual(report['callback_audit']['package_sha256'],hashlib.sha256(package).hexdigest())
        self.assertTrue(any(origin==0x20C and kind==ar.INDIRECT_HOST and reg==17
                            for _,origin,kind,reg,_,_ in abort_gates(package)))


if __name__=='__main__':unittest.main()
