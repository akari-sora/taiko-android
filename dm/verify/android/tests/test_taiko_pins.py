"""Real freely authored NSO/capsule tests; fixtures cannot pass stock title pins."""
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from dataclasses import replace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import
import gen_taiko_pins as pins
import taiko_content
from nso_format import parse_nso, parse_metadata, Symbol, Relocation


class TaikoPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Public source is dm/platform/android/module_fixtures/main.S.
        cls.source = (ROOT / 'dm/platform/android/module_fixtures/main.nso').read_bytes()
        cls.nso = parse_nso(cls.source)
        cls.metadata = parse_metadata(cls.nso)
        cls.package, cls.report = android_import.import_module(cls.source, 'main', package_version=2,
            indirect_policy='guarded-host', callback_audit=True, checked_stack=True)
        cls.fact = dict(name='main', source_bytes=len(cls.source), source_sha256=hashlib.sha256(cls.source).hexdigest(),
            decoded_sha256=hashlib.sha256(cls.nso.image).hexdigest(), build_id=cls.nso.build_id.hex())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.path = self.directory / 'main.dmag'
        self.path.write_bytes(self.package)

    def verify(self, report=None):
        return pins.verify_package(self.path, report or self.report, self.fact, self.nso, self.metadata)

    def resign(self, package, report):
        payload = struct.unpack_from('<Q', package, 112)[0]
        digest = hashlib.sha256(package[payload:]).digest()
        package[248:280] = digest
        report['image_sha256'] = digest.hex()
        report['package_sha256'] = hashlib.sha256(package).hexdigest()
        report['callback_audit']['package_sha256'] = report['package_sha256']
        self.path.write_bytes(package)

    def test_original_fixture_package_passes_independent_stock_audit(self):
        result = self.verify()
        self.assertEqual(result['package_sha256'], self.report['package_sha256'])
        self.assertEqual(result['callback_audit']['callback_roots'], [0, 0x100, 0x168, 0x184])

    def test_fixture_can_never_authorize_production_provider(self):
        game = self.directory / 'game'
        (game / 'ExeFS').mkdir(parents=True)
        for name in taiko_content.SOURCE_PINS:
            (game / 'ExeFS' / name).write_bytes(self.source)
        output = ROOT / '.local' / ('rejected-' + self.directory.name + '.cpp')
        audit = output.with_suffix('.json')
        with self.assertRaises((ValueError, OSError)):
            pins.generate(game, self.directory, self.directory, output, audit)
        self.assertFalse(output.exists()); self.assertFalse(audit.exists())

    def test_resigned_rodata_code_and_bss_mutations_are_rejected(self):
        for offset in (0x500, self.nso.sections[1].offset, self.nso.sections[2].end):
            with self.subTest(offset=offset):
                package = bytearray(self.package); report = copy.deepcopy(self.report)
                payload = struct.unpack_from('<Q', package, 112)[0]
                package[payload + offset] ^= 1
                self.resign(package, report)
                with self.assertRaisesRegex(ValueError, 'original image'):
                    self.verify(report)

    def test_modified_source_site_word_cannot_hide_a_private_cut(self):
        package = bytearray(self.package); report = copy.deepcopy(self.report)
        payload = struct.unpack_from('<Q', package, 112)[0]
        site = report['rewrite']['sites'][0]
        struct.pack_into('<I', package, payload + site['offset'], 0xD503201F)
        self.resign(package, report)
        with self.assertRaisesRegex(ValueError, 'site branch'):
            self.verify(report)

    def test_observation_private_svc_profile_and_unknown_gate_rejected(self):
        gate_offset = struct.unpack_from('<Q', self.package, 136)[0]
        for kind, argument in ((3, 1), (1, 0x80), (99, 0)):
            with self.subTest(kind=kind, argument=argument):
                package = bytearray(self.package); report = copy.deepcopy(self.report)
                struct.pack_into('<II', package, gate_offset + 16, kind, argument)
                self.resign(package, report)
                with self.assertRaises(ValueError): self.verify(report)
        package = bytearray(self.package); package[320] = 1
        report = copy.deepcopy(self.report); self.resign(package, report)
        with self.assertRaises(ValueError): self.verify(report)

    def test_forged_callback_subset_and_extra_root_rejected(self):
        for roots in ([0], [0, 0x100, 0x168, 0x184, 0x500]):
            report = copy.deepcopy(self.report)
            report['callback_audit']['callback_roots'] = roots
            with self.subTest(roots=roots), self.assertRaisesRegex(ValueError, 'callback'):
                self.verify(report)

    def test_forged_site_table_count_rejected(self):
        package = bytearray(self.package); report = copy.deepcopy(self.report)
        struct.pack_into('<Q', package, 160, 0)
        self.resign(package, report)
        with self.assertRaises(ValueError): self.verify(report)

    def test_unmatched_stock_source_rejects_claimed_checked_call_descriptors(self):
        descriptor = dict(offset=0x110, target=0x100, source_word=0xD63F0240,
            rule='versioned-taiko-main-mutable-callback-v1', source_sha256=self.fact['source_sha256'],
            build_id=self.fact['build_id'], target_policy='forged', evidence={})
        report = copy.deepcopy(self.report)
        report['code_discovery']['versioned_checked_calls'] = [descriptor]
        report['rewrite']['checked_calls'] = [dict(offset=0x110, target=0x100,
            rule='virtual-x18-exact-target-direct-call-v1')]
        with self.assertRaisesRegex(ValueError, 'checked.call'):
            self.verify(report)

    def test_unmatched_source_rejects_rewrite_only_checked_call(self):
        report = copy.deepcopy(self.report)
        report['rewrite']['checked_calls'] = [dict(offset=0x110, target=0x100,
            rule='virtual-x18-exact-target-direct-call-v1')]
        with self.assertRaisesRegex(ValueError, 'checked.call'):
            self.verify(report)

    def test_unmatched_source_accepts_explicit_empty_checked_call_metadata(self):
        report = copy.deepcopy(self.report)
        report['code_discovery']['versioned_checked_calls'] = []
        report['rewrite']['checked_calls'] = []
        self.verify(report)

    def checked_call_fixture(self):
        # Selector output is stubbed only for isolated verifier coverage. It
        # never reaches generate(), emit_provider(), or production pin matching.
        image = bytearray(self.nso.image)
        struct.pack_into('<I', image, 0x110, 0xD63F0240)
        nso = replace(self.nso, image=bytes(image))
        descriptor = dict(offset=0x110, target=0x100, source_word=0xD63F0240,
            source_sha256=nso.source_sha256.hex(), build_id=nso.build_id.hex(),
            rule='versioned-taiko-main-mutable-callback-v1', evidence={'fixture': True})
        discovery = dict(versioned_checked_calls=[copy.deepcopy(descriptor)])
        rewrite = dict(checked_calls=[dict(offset=0x110, target=0x100,
            rule='virtual-x18-exact-target-direct-call-v1')])
        return nso, descriptor, discovery, rewrite

    def test_selected_checked_call_requires_canonical_source_discovery_and_rewrite(self):
        nso, descriptor, discovery, rewrite = self.checked_call_fixture()
        with patch.object(pins, 'select_checked_calls', return_value=(descriptor,)):
            result = pins.verify_checked_calls(nso, self.metadata, discovery, rewrite, {0x110}, {0x100}, [[0, 0x200]])
            self.assertEqual(result, [descriptor])
            for location, mutation in [('discovery', 'missing'), ('discovery', 'extra'), ('discovery', 'target'),
                                        ('discovery', 'evidence'), ('rewrite', 'missing'), ('rewrite', 'extra'),
                                        ('rewrite', 'target'), ('rewrite', 'rule')]:
                d, r = copy.deepcopy(discovery), copy.deepcopy(rewrite)
                items = d['versioned_checked_calls'] if location == 'discovery' else r['checked_calls']
                if mutation == 'missing': items.clear()
                elif mutation == 'extra': items.append(copy.deepcopy(items[0]))
                elif mutation == 'target': items[0]['target'] += 4
                elif mutation == 'evidence': items[0]['evidence']['fixture'] = False
                else: items[0]['rule'] = 'arbitrary-target'
                with self.subTest(location=location, mutation=mutation), self.assertRaisesRegex(ValueError, 'checked.call'):
                    pins.verify_checked_calls(nso, self.metadata, d, r, {0x110}, {0x100}, [[0, 0x200]])

    def test_selected_checked_call_requires_original_blr_and_one_site_and_root_coverage(self):
        nso, descriptor, discovery, rewrite = self.checked_call_fixture()
        with patch.object(pins, 'select_checked_calls', return_value=(descriptor,)):
            for candidate, sites, roots, ranges in [(self.nso, {0x110}, {0x100}, [[0, 0x200]]),
                    (nso, set(), {0x100}, [[0, 0x200]]), (nso, {0x110}, set(), [[0, 0x200]]),
                    (nso, {0x110}, {0x100}, [[0x104, 0x200]])]:
                with self.subTest(sites=sites, roots=roots, ranges=ranges), self.assertRaisesRegex(ValueError, 'checked.call'):
                    pins.verify_checked_calls(candidate, self.metadata, discovery, rewrite, sites, roots, ranges)

    def test_selected_checked_call_descriptor_must_bind_source_identity(self):
        nso, descriptor, discovery, rewrite = self.checked_call_fixture()
        for key in ('source_sha256', 'build_id'):
            altered = copy.deepcopy(descriptor); altered[key] = '0' * 64
            d = dict(versioned_checked_calls=[altered])
            with patch.object(pins, 'select_checked_calls', return_value=(altered,)):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'checked.call'):
                    pins.verify_checked_calls(nso, self.metadata, d, rewrite, {0x110}, {0x100}, [[0, 0x200]])

    def test_referenced_strong_import_closure_uses_cross_module_exports(self):
        class Metadata:
            def __init__(self, symbols, relocations):
                self.symbols, self.relocations = symbols, relocations
        null = Symbol('', 0, 0, 0, 0, 0, 0)
        strong = Symbol('cross', 0, 0, 1, 2, 0, 0)
        unused = Symbol('unused', 0, 0, 1, 2, 0, 0)
        weak = Symbol('weak', 0, 0, 2, 2, 0, 0)
        exported = Symbol('cross', 0x100, 4, 1, 2, 1, 0)
        objects = {'main': (None, Metadata([null, strong, unused, weak], [Relocation(0, 1026, 1, 0), Relocation(8, 1026, 3, 0)])),
            'subsdk0': (None, Metadata([null, exported], [])), 'sdk': (None, Metadata([null], []))}
        inventory = pins.verify_import_closure(objects)
        self.assertEqual(inventory['referenced_strong_imports']['main'], 1)
        objects['subsdk0'][1].symbols[1] = Symbol('cross', 0x100, 4, 1, 2, 1, 2)
        with self.assertRaisesRegex(ValueError, 'unresolved'): pins.verify_import_closure(objects)

    def content_fixture(self):
        root = self.directory / 'content'; (root / 'RomFS' / 'Data').mkdir(parents=True)
        (root / 'modules').mkdir()
        raw = b'fixture resource, never an original game'
        (root / 'RomFS' / 'Data' / 'fixture').write_bytes(raw)
        receipt = b'{"fixture":true}'
        (root / 'import.json').write_bytes(receipt)
        modules, packages = [], []
        for name in pins.MODULE_ORDER:
            (root / 'modules' / (name + '.dmag')).write_bytes(name.encode())
            digest = hashlib.sha256(name.encode()).hexdigest()
            modules.append(dict(name=name, package_bytes=len(name), package_sha256=digest,
                source_sha256=taiko_content.SOURCE_PINS[name]['sha256']))
            packages.append(dict(name=name, path='modules/' + name + '.dmag', bytes=len(name), sha256=digest,
                source_sha256=taiko_content.SOURCE_PINS[name]['sha256']))
        manifest = dict(schema=1, target='taiko-android', program_id=pins.PROGRAM_ID,
            selected_exefs_display_version=None, module_order=list(pins.MODULE_ORDER),
            sources=taiko_content.source_records(), packages=packages,
            import_receipt=dict(path='import.json', bytes=len(receipt), sha256=hashlib.sha256(receipt).hexdigest()),
            files=[dict(path='RomFS/Data/fixture', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())],
            total_bytes=sum(item['bytes'] for item in packages) + len(raw) + len(receipt))
        (root / 'taiko-content.json').write_text(json.dumps(manifest), encoding='utf-8')
        return root, modules, manifest, hashlib.sha256(receipt).hexdigest()

    def test_content_inventory_and_resources_are_independently_hashed(self):
        root, modules, manifest, receipt_sha = self.content_fixture()
        result = pins.verify_content(root, modules, receipt_sha)
        self.assertEqual(result['total_bytes'], manifest['files'][0]['bytes'])
        (root / 'RomFS' / 'extra').write_bytes(b'not listed')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            pins.verify_content(root, modules, receipt_sha)

    def test_content_resigned_manifest_cannot_hide_tampered_module(self):
        root, modules, manifest, receipt_sha = self.content_fixture()
        path = root / 'modules' / 'main.dmag'; path.write_bytes(b'fake')
        manifest['packages'][0]['sha256'] = hashlib.sha256(b'fake').hexdigest()
        manifest['packages'][0]['bytes'] = 4
        (root / 'taiko-content.json').write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaises(ValueError): pins.verify_content(root, modules, receipt_sha)

    def test_content_resource_tamper_is_rejected(self):
        root, modules, _, receipt_sha = self.content_fixture()
        (root / 'RomFS' / 'Data' / 'fixture').write_bytes(b'tampered')
        with self.assertRaises(ValueError): pins.verify_content(root, modules, receipt_sha)

    def test_content_traversal_path_is_rejected(self):
        root, modules, manifest, receipt_sha = self.content_fixture()
        manifest['files'][0]['path'] = '../escape'
        (root / 'taiko-content.json').write_text(json.dumps(manifest), encoding='utf-8')
        with self.assertRaises(ValueError): pins.verify_content(root, modules, receipt_sha)

    def test_emitter_produces_both_native_contracts_without_resource_bytes(self):
        root, _, _, receipt_sha = self.content_fixture()
        module = self.verify()
        content = pins.verify_content(root, self.content_fixture_modules(root), receipt_sha)
        model = dict(rtld=dict(self.fact, name='rtld'), sources=[dict(self.fact, name=name) for name in pins.MODULE_ORDER],
            modules=[dict(module, name=name) for name in pins.MODULE_ORDER],
            source_audit_sha256='1' * 64, import_manifest_sha256='2' * 64, content=content)
        emitted = pins.emit_provider(model)
        self.assertIn('#include "taiko_bringup.h"', emitted)
        self.assertIn('#include "taiko_resources.h"', emitted)
        self.assertIn('compiled_taiko_bringup_pins()', emitted)
        self.assertIn('compiled_taiko_content_pins()', emitted)
        self.assertIn('Taiko/01002460135A4000/Stock-v1', emitted)
        self.assertNotIn('fixture resource, never an original game', emitted)
        self.assertNotIn('D2R/', emitted)

    def content_fixture_modules(self, root):
        manifest = json.loads((root / 'taiko-content.json').read_text())
        return [dict(name=item['name'], package_bytes=item['bytes'], package_sha256=item['sha256'],
            source_sha256=item['source_sha256']) for item in manifest['packages']]

    def test_atomic_publication_never_overwrites_prior_file(self):
        output = self.directory / 'provider.cpp'
        pins.atomic_new(output, b'first complete payload')
        with self.assertRaises(FileExistsError): pins.atomic_new(output, b'replacement')
        self.assertEqual(output.read_bytes(), b'first complete payload')
        self.assertEqual(list(self.directory.glob('.provider.cpp-*')), [])


if __name__ == '__main__': unittest.main()
