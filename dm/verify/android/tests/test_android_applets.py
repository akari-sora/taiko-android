"""Independent contracts for the public OE-to-PARAM cross-module guest."""
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

FIXTURES = ROOT / 'dm/platform/android/applet_fixtures'
# Written against the shared exported ABI, independently of the generator table.
OE_NAMES = {
    '_ZN2nn2oe15EnableRecordingEv', '_ZN2nn2oe16DisableRecordingEv',
    '_ZN2nn2oe16EnableScreenShotEv', '_ZN2nn2oe17DisableScreenShotEv',
    '_ZN2nn2oe16GetOperationModeEv', '_ZN2nn2oe18GetPerformanceModeEv',
    '_ZN2nn2oe27SetPerformanceConfigurationENS0_15PerformanceModeEi',
    '_ZN2nn2oe20GetCurrentFocusStateEv',
    '_ZN2nn2oe20SetFocusHandlingModeENS0_17FocusHandlingModeE',
    '_ZN2nn2oe25TryPopNotificationMessageEPj',
    '_ZN2nn2oe28SetResumeNotificationEnabledEb',
    '_ZN2nn2oe42SetOperationModeChangedNotificationEnabledEb',
    '_ZN2nn2oe44SetPerformanceModeChangedNotificationEnabledEb',
    '_ZN2nn2oe18GetDesiredLanguageEv', '_ZN2nn2oe17GetPseudoDeviceIdEPNS_4util4UuidE',
}
PARAM_NAMES = {'fixture_param_adjacent', 'fixture_param_interleaved',
               'fixture_param_wide', 'fixture_param_ui'}


class AppletFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (FIXTURES / 'applet.nso').read_bytes()
        cls.nso = parse_nso(cls.source)
        cls.metadata = parse_metadata(cls.nso)
        cls.symbols = {s.name: s for s in cls.metadata.symbols}
        cls.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    def instructions(self, name):
        symbol = self.symbols[name]
        return list(self.md.disasm(self.nso.image[symbol.value:symbol.value + symbol.size], symbol.value))

    def calls(self, name):
        instructions, names = self.instructions(name), []
        targets = {r.offset: self.metadata.symbols[r.symbol].name for r in self.metadata.relocations}
        for index, ins in enumerate(instructions):
            if ins.mnemonic != 'blr':
                continue
            self.assertEqual(ins.op_str, 'x9')
            self.assertEqual(instructions[index - 2].mnemonic, 'adrp')
            self.assertEqual(instructions[index - 2].op_str, 'x8, #0x8000')
            load = instructions[index - 1]
            self.assertEqual(load.mnemonic, 'ldr')
            match = re.fullmatch(r'x9, \[x8(?:, #((?:0x)?[0-9a-f]+))?\]', load.op_str)
            self.assertIsNotNone(match)
            names.append(targets[0x8000 + int(match[1] or '0', 0)])
        return names

    def test_all_fifteen_original_oe_import_names_and_signatures_are_real(self):
        imported = {s.name for s in self.metadata.symbols if s.section == 0 and s.name}
        self.assertEqual(imported, OE_NAMES | PARAM_NAMES | {'dm_applet_checked_copy'})
        shared = '\n'.join(p.read_text(encoding='utf-8') for p in (ROOT / 'dm/host').glob('hle_oe*.c'))
        self.assertEqual(set(re.findall(r'HLE_FORCE\("([^"]+)"', shared)), OE_NAMES)
        signatures = {name: (result, re.sub(r'\s+', ' ', arguments.strip()))
                      for name, result, arguments in re.findall(
                          r'HLE_FORCE\("([^"]+)",\s*"[^"]*",\s*(\w+),\s*\w+,\s*([^)]*)\)', shared)}
        for name in OE_NAMES:
            expected = ('void', 'void')
            if name in {'_ZN2nn2oe16GetOperationModeEv', '_ZN2nn2oe18GetPerformanceModeEv',
                        '_ZN2nn2oe20GetCurrentFocusStateEv'}:
                expected = ('int', 'void')
            elif name == '_ZN2nn2oe18GetDesiredLanguageEv':
                expected = ('uint64_t', 'void')
            elif name == '_ZN2nn2oe17GetPseudoDeviceIdEPNS_4util4UuidE':
                expected = ('void', 'uint8_t *uuid')
            elif name == '_ZN2nn2oe25TryPopNotificationMessageEPj':
                expected = ('unsigned', 'uint32_t *msg')
            elif name == '_ZN2nn2oe20SetFocusHandlingModeENS0_17FocusHandlingModeE':
                expected = ('void', 'int m')
            elif name == '_ZN2nn2oe27SetPerformanceConfigurationENS0_15PerformanceModeEi':
                expected = ('void', 'int mode, int cfg')
            elif name.endswith('NotificationEnabledEb'):
                expected = ('void', 'unsigned on')
            self.assertEqual(signatures[name], expected, name)
        # Actual indirect calls, rather than unused dynsym declarations, cover all15.
        calls = self.calls('applet_setup') + self.calls('applet_query') + self.calls('applet_pop')
        self.assertEqual(len(calls), 15)
        self.assertEqual(set(calls), OE_NAMES)

    def test_production_import_has_no_observation_or_parameter_authority(self):
        package, report = importer.import_module(self.source, 'applet', package_version=2)
        self.assertEqual(package, (FIXTURES / 'applet.dmag').read_bytes())
        self.assertEqual(package[:8], b'DMAMOD02')
        self.assertEqual(package[320:352], bytes(32))
        self.assertEqual(struct.unpack_from('<I', package, 352)[0], 0)
        self.assertEqual(struct.unpack_from('<Q', package, 368)[0], 0)
        self.assertFalse(any(g['kind'] == 3 for g in report['rewrite']['gates']))
        self.assertEqual(json.loads(json.dumps(report)), json.loads((FIXTURES / 'import.json').read_text()))
        self.assertEqual(report['game_boot_status'], 'NOT_RUN')
        self.assertFalse(report['unsupported'])

    def test_full_relocations_constructor_and_owned_result_extents_survive(self):
        self.assertEqual(len(self.metadata.relocations), 20)
        self.assertEqual({r.kind for r in self.metadata.relocations}, {1026})
        self.assertEqual({r.offset for r in self.metadata.relocations}, set(range(0x8000, 0x80a0, 8)))
        self.assertEqual(self.metadata.init_addresses, (self.symbols['fixture_init'].value,))
        expected = {'applet_query_result': (0x8500, 56), 'applet_pop_result': (0x8540, 40),
                    'applet_parameter_result': (0x8580, 32), 'applet_create_result': (0x85c0, 16),
                    'applet_sdk_context_a': (0x8600, 80), 'applet_sdk_context_b': (0x8680, 80)}
        for name, (offset, size) in expected.items():
            symbol = self.symbols[name]
            self.assertEqual((symbol.value, symbol.size, symbol.kind, symbol.binding), (offset, size, 1, 1))
            self.assertEqual(self.nso.image[offset:offset + size], bytes(size))

    def test_pop_reads_all_four_cross_module_slots_immediately_after_hle(self):
        instructions = self.instructions('applet_pop')
        pop = next(i for i, ins in enumerate(instructions) if ins.mnemonic == 'blr')
        self.assertEqual(instructions[pop + 1].mnemonic, 'str')
        self.assertEqual(instructions[pop + 1].op_str, 'w0, [sp, #0x10]')
        self.assertEqual(instructions[pop + 2].mnemonic, 'bl')
        self.assertEqual(int(instructions[pop + 2].op_str[1:], 16), self.symbols['applet_parameters'].value)
        self.assertEqual(set(self.calls('applet_parameters')), PARAM_NAMES)
        # No conditional bypass: the empty-pop case reads retained slots as well.
        self.assertFalse(any(i.mnemonic.startswith(('cb', 'tb', 'b.')) for i in instructions))
        self.assertTrue(any(i.mnemonic == 'str' and i.op_str == 'w0, [sp, #0x14]' for i in instructions[:pop]))

    def test_actual_kernel_calls_and_sdk_local_copy_are_reachable(self):
        expected = {'applet_sdk_create': ['#8'], 'applet_sdk_start': ['#9'],
                    'applet_sdk_wait': ['#0x18'], 'applet_sdk_close': ['#0x16'],
                    'applet_sdk_entry': ['#0x18', '#0xa']}
        for name, immediates in expected.items():
            self.assertEqual([i.op_str for i in self.instructions(name) if i.mnemonic == 'svc'], immediates)
        self.assertEqual(self.calls('applet_sdk_entry'),
                         ['fixture_param_adjacent', 'fixture_param_interleaved', 'fixture_param_wide',
                          'fixture_param_ui', 'dm_applet_checked_copy', 'dm_applet_checked_copy'])
        entry = self.instructions('applet_sdk_entry')
        self.assertTrue(any(i.mnemonic == 'add' and i.op_str == 'x0, sp, #0x20' for i in entry))
        self.assertTrue(any(i.mnemonic == 'ldr' and i.op_str == 'w0, [x19, #0x40]' for i in entry))
        self.assertFalse(any(i.mnemonic == 'b' for i in entry))  # no polling/exit-failure spin

    def test_existing_canonical_main_and_authority_are_byte_identical(self):
        expected = {
            'dm/platform/android/observation_fixtures/main.nso': '7c6d0e794b729082ec469823740d47c0a93469a3b68a32acb07b6401c3f23ff9',
            'dm/platform/android/observation_fixtures/main.dmag': 'db5fc825c18a5abddcd0bb8ab3dbe5aa8e83af8087b78930591a7d1925e98e42',
            'dm/platform/android/observation_fixtures/generated_catalog.inc': '0681d18eba62fe0360e4325aaf9eb8b03aa2c4bb45b8e226d173b7dce8a7f2de',
            'dm/tools/android_profiles.py': '3c71ed4636c44c93f410f26164aa9883bb5efc72e9804f02f2effb847f1426a9',
        }
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main()
