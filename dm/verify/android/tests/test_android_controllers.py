"""Independent contracts for actual forced HID calls against conflicting SDK code."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as importer
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from nso_format import parse_nso, parse_metadata

FIXTURES = ROOT / 'dm/platform/android/controller_fixtures'
HID_NAMES = {
    '_ZN2nn3hid14InitializeNpadEv',
    '_ZN2nn3hid22SetSupportedNpadIdTypeEPKjm',
    '_ZN2nn3hid24SetSupportedNpadStyleSetENS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE',
    '_ZN2nn3hid29SetNpadHandheldActivationModeENS0_26NpadHandheldActivationModeE',
    '_ZN2nn3hid15GetNpadStyleSetERKj',
    '_ZN2nn3hid12GetNpadStateEPNS0_16NpadFullKeyStateERKj',
    '_ZN2nn3hid12GetNpadStateEPNS0_17NpadHandheldStateERKj',
    '_ZN2nn3hid20IsVibrationPermittedEv',
    '_ZN2nn3hid25GetVibrationDeviceHandlesEPNS0_21VibrationDeviceHandleEiRKjNS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE',
    '_ZN2nn3hid25InitializeVibrationDeviceERKNS0_21VibrationDeviceHandleE',
    '_ZN2nn3hid18SendVibrationValueERKNS0_21VibrationDeviceHandleERKNS0_14VibrationValueE',
}

class ControllerFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (FIXTURES / 'controller.nso').read_bytes()
        cls.nso = parse_nso(cls.source)
        cls.metadata = parse_metadata(cls.nso)
        cls.symbols = {s.name: s for s in cls.metadata.symbols}
        cls.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    def instructions(self, name):
        s = self.symbols[name]
        return list(self.md.disasm(self.nso.image[s.value:s.value+s.size], s.value))

    def test_all_original_exports_have_competing_sdk_definitions_and_real_calls(self):
        core = '\n'.join(p.read_text(encoding='utf-8') for p in (ROOT/'dm/host').glob('hle_hid*.c'))
        self.assertEqual(set(re.findall(r'HLE_FORCE\("([^"]+)"', core)), HID_NAMES)
        targets = {r.offset: self.metadata.symbols[r.symbol].name for r in self.metadata.relocations}
        self.assertEqual(set(targets.values()), HID_NAMES)
        called = []
        for name in ('controller_setup', 'controller_sample'):
            ins = self.instructions(name)
            for i, op in enumerate(ins):
                if op.mnemonic != 'blr': continue
                self.assertEqual(op.op_str, 'x9')
                self.assertEqual((ins[i-2].mnemonic,ins[i-2].op_str), ('adrp','x8, #0x8000'))
                match = re.fullmatch(r'x9, \[x8(?:, #((?:0x)?[0-9a-f]+))?\]',ins[i-1].op_str)
                self.assertIsNotNone(match)
                called.append(targets[0x8000+int(match[1] or '0',0)])
        self.assertEqual(set(called), HID_NAMES)
        self.assertEqual(len(called), 12)
        for name in HID_NAMES:
            self.assertNotEqual(self.symbols[name].section,0)
            self.assertTrue(any(i.mnemonic=='mov' and i.op_str=='x0, #0xbad' for i in self.instructions(name)))

    def test_class_zero_sdk_has_no_self_asserted_observation_authority(self):
        package,report=importer.import_module(self.source,'sdk',package_version=2)
        self.assertEqual(package,(FIXTURES/'controller.dmag').read_bytes())
        self.assertEqual(package[:8],b'DMAMOD02')
        self.assertEqual(package[320:352],bytes(32))
        self.assertEqual(struct.unpack_from('<I',package,352)[0],0)
        self.assertEqual(struct.unpack_from('<Q',package,368)[0],0)
        self.assertEqual(report['game_boot_status'],'NOT_RUN')
        self.assertFalse(report['unsupported'])
        self.assertEqual(json.loads(json.dumps(report)),json.loads((FIXTURES/'import.json').read_text()))

    def test_owned_output_and_initialization_side_effect_sentinels(self):
        record=self.symbols['controller_result']
        self.assertEqual((record.value,record.size),(0x8500,136))
        self.assertEqual(self.nso.image[record.value:record.value+record.size],bytes(record.size))
        self.assertEqual(self.metadata.init_addresses,(self.symbols['fixture_init'].value,))
        for name,offset in (('_init_libc0','0x578'),('fixture_init','0x580')):
            self.assertTrue(any(i.mnemonic=='str' and i.op_str==f'x9, [x8, #{offset}]' for i in self.instructions(name)))

    def test_canonical_observation_main_and_catalog_are_unchanged(self):
        for path,digest in {
            'observation_fixtures/main.nso':'7c6d0e794b729082ec469823740d47c0a93469a3b68a32acb07b6401c3f23ff9',
            'observation_fixtures/main.dmag':'db5fc825c18a5abddcd0bb8ab3dbe5aa8e83af8087b78930591a7d1925e98e42',
            'observation_fixtures/generated_catalog.inc':'0681d18eba62fe0360e4325aaf9eb8b03aa2c4bb45b8e226d173b7dce8a7f2de',
        }.items():
            self.assertEqual(hashlib.sha256((ROOT/'dm/platform/android'/path).read_bytes()).hexdigest(),digest)

if __name__=='__main__': unittest.main()
