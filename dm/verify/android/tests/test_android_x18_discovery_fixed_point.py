"""Newly discovered ADR producers must reach the existing CFG fixed point."""
import unittest

from test_android_runtime_ro_sub_inline import ar,ai,source_base,write_image
from test_android_runtime_ro_backward import adr


def fixture(invalid=False):
    source=source_base()
    write_image(source,0x300,'<I',ar.branch(0x300,0x3C0))
    write_image(source,0x3C0,'<8I',0x7100163F,0x54000808,
                0x9000002B,0x9120016B,adr(0x3D0,0x420,18),0x38716961,0x8B010A52,0xD61F0240)
    write_image(source,0x420,'<8I',0x7100161F,0x54000508,
                0x9000002A,0x9120414A,adr(0x430,0x340,18),0x38706941,0x8B010A52,0xD61F0240)
    write_image(source,0x4800,'<6B',*([0]*6));write_image(source,0x4810,'<6B',*([0]*6))
    if invalid:
        write_image(source,0x300,'<2I',0xB40009C0,ar.branch(0x304,0x3C0))  # CBZ X0,0x438: forbidden post-load entrance.
    return source


class X18DiscoveryFixedPointTests(unittest.TestCase):
    def test_new_dispatch_adr_base_is_discovered_before_final_proof(self):
        _,report=ai.import_module(fixture(),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')
        plans=report['code_discovery']['halfword_jump_tables']
        self.assertEqual({plan['offset'] for plan in plans},{0x3DC,0x43C})
        self.assertTrue({0x340,0x420}<=set(report['code_discovery']['address_taken_roots']))
        self.assertFalse({0x3DC,0x43C}&set(report['code_discovery'].get('guarded_indirect_sites',())))

    def test_stable_invalid_dispatch_still_refuses_without_host_fallback(self):
        with self.assertRaisesRegex(ai.ImportError,'0x43c: unproven byte dispatch br x18'):
            ai.import_module(fixture(True),'main',package_version=2,checked_stack=True,indirect_policy='guarded-host')


if __name__=='__main__':unittest.main()
