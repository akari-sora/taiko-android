"""Synthetic packaging contracts; no fixture confers original execution authority."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import taiko_content as content


class TaikoContentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        (self.source / 'ExeFS').mkdir(parents=True)
        (self.source / 'RomFS' / 'Data').mkdir(parents=True)
        (self.source / 'RomFS' / 'Data' / 'song.bin').write_bytes(b'original fixture resource')
        self.capsules = self.root / 'capsules'
        self.capsules.mkdir()
        self.output = self.root / 'output'
        modules = []
        for name in content.MODULE_ORDER:
            pin = content.SOURCE_PINS[name]
            payload = b'fixture payload for ' + name.encode()
            header = bytearray(384)
            header[:8] = b'DMAMOD02'
            struct.pack_into('<IIII', header, 8, 2, content.ABI, 384, 1)
            struct.pack_into('<QQ', header, 24, len(payload), len(payload))
            struct.pack_into('<Q', header, 48, len(payload))
            struct.pack_into('<7Q', header, 112, 384, 384, 0, 384, 0, 384, 0)
            header[168:168+len(name)] = name.encode()
            header[184:216] = bytes.fromhex(pin['build_id'])
            header[216:248] = bytes.fromhex(pin['sha256'])
            header[248:280] = hashlib.sha256(payload).digest()
            struct.pack_into('<IQQII', header, 356, 32, 384, 0, 40, 0)
            package = bytes(header) + payload
            (self.capsules / (name + '.dmag')).write_bytes(package)
            digest = hashlib.sha256(package).hexdigest()
            modules.append(dict(name=name, source_sha256=pin['sha256'], build_id=pin['build_id'],
                source_size=pin['bytes'], package_size=len(package), package_sha256=digest,
                image_sha256=hashlib.sha256(payload).hexdigest(), original_image_size=len(payload),
                unsupported=[], rewrite={'checked_stack': True}, game_boot_status='NOT_RUN',
                callback_audit=dict(callback_audit_version=1, package_sha256=digest,
                    source_sha256=pin['sha256'], indirect_policy='guarded-host',
                    callback_root_kind='defined-stt-func', callback_roots=[0])))
        self.receipt = dict(format='DMAMOD02', abi=content.ABI, module_order=list(content.MODULE_ORDER),
            status='prepared', modules=modules, unsupported=[], checked_stack=True,
            indirect_policy='guarded-host')
        self.write_receipt()

    def write_receipt(self):
        (self.capsules / 'import.json').write_text(json.dumps(self.receipt), encoding='utf-8')

    def package(self):
        # Only source IO is substituted. Package/receipt verification uses real pins.
        with patch.object(content, 'validate_sources', return_value=content.source_records()):
            return content.package_content(self.source, self.capsules, self.output)

    def test_production_pins_match_checked_repository_identity(self):
        trusted = json.loads((ROOT / 'docs/TAIKO_CONTENT_IDENTITY.json').read_text(encoding='utf-8'))
        self.assertEqual(content.PROGRAM_ID, trusted['program_id'])
        for name, pin in trusted['sources'].items():
            self.assertEqual(content.SOURCE_PINS[name], dict(bytes=pin['file_bytes'], sha256=pin['sha256'], build_id=pin['build_id']))
        self.assertEqual(content.SOURCE_PINS['main.npdm']['sha256'], trusted['npdm_sha256'])

    def test_mutated_synthetic_original_is_rejected_without_output(self):
        (self.source / 'ExeFS' / 'rtld').write_bytes(b'NSO0' + bytes(92))
        with self.assertRaises(content.ContentError):
            content.package_content(self.source, self.capsules, self.output)
        self.assertFalse(self.output.exists())

    def test_complete_resource_tree_and_receipt_are_copied(self):
        (self.source / 'RomFS' / 'empty').mkdir()
        result = self.package()
        self.assertEqual(result['module_order'], ['main', 'subsdk0', 'sdk'])
        self.assertEqual([s['name'] for s in result['sources']], ['rtld', 'main', 'subsdk0', 'sdk', 'main.npdm'])
        self.assertNotIn('build_id', result['sources'][-1])
        self.assertEqual(result['files'][0]['path'], 'RomFS/Data/song.bin')
        self.assertEqual((self.output / result['files'][0]['path']).read_bytes(), b'original fixture resource')
        self.assertTrue((self.output / 'RomFS' / 'empty').is_dir())
        self.assertEqual(result['total_bytes'], result['import_receipt']['bytes'] + sum(p['bytes'] for p in result['packages'] + result['files']))
        self.assertEqual(json.loads((self.output / 'taiko-content.json').read_text()), result)
        self.assertEqual((self.output / 'import.json').read_bytes(), (self.capsules / 'import.json').read_bytes())

    def test_package_tamper_is_rejected_before_publish(self):
        with (self.capsules / 'main.dmag').open('ab') as target:
            target.write(b'tamper')
        with self.assertRaises(content.ContentError):
            self.package()
        self.assertFalse(self.output.exists())

    def test_self_asserted_receipt_cannot_change_header_source(self):
        path = self.capsules / 'main.dmag'
        package = bytearray(path.read_bytes()); package[216] ^= 1
        path.write_bytes(package)
        module = self.receipt['modules'][0]
        module['package_sha256'] = hashlib.sha256(package).hexdigest()
        module['callback_audit']['package_sha256'] = module['package_sha256']
        self.write_receipt()
        with self.assertRaises(content.ContentError):
            self.package()
        self.assertFalse(self.output.exists())

    def test_rejected_or_unchecked_receipt_never_publishes(self):
        for key, value in [('status', 'rejected'), ('checked_stack', False), ('module_order', ['sdk', 'main', 'subsdk0'])]:
            with self.subTest(key=key):
                original = self.receipt[key]; self.receipt[key] = value; self.write_receipt()
                with self.assertRaises(content.ContentError): self.package()
                self.assertFalse(self.output.exists())
                self.receipt[key] = original

    def test_receipt_missing_or_forged_callback_audit_rejected(self):
        self.receipt['modules'][0]['callback_audit']['source_sha256'] = '0' * 64
        self.write_receipt()
        with self.assertRaises(content.ContentError): self.package()
        self.assertFalse(self.output.exists())

    def test_casefold_collision_rejected(self):
        romfs = self.source / 'RomFS'
        # Windows cannot create both names, so expose the colliding directory
        # entries directly while retaining ordinary filesystem checks.
        original = Path.iterdir
        def entries(path):
            return iter([romfs / 'Data', romfs / 'data']) if path == romfs else original(path)
        with patch.object(Path, 'iterdir', entries):
            with self.assertRaises(content.ContentError): self.package()
        self.assertFalse(self.output.exists())

    def test_windows_ambiguous_resource_name_rejected(self):
        # POSIX traversal and Windows alternate stream syntax must both be denied.
        for name in ['../escape', 'a/b', 'a\\b', 'a:stream', '.', '..', 'trailing.', 'CON']:
            with self.subTest(name=name):
                with self.assertRaises(content.ContentError): content.validate_component(name)

    def test_symlink_rejected(self):
        link = self.source / 'RomFS' / 'linked'
        try: link.symlink_to(self.capsules / 'import.json')
        except OSError as error: self.skipTest(f'symlink privilege unavailable: {error}')
        with self.assertRaises(content.ContentError): self.package()
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_reused(self):
        self.output.mkdir()
        with self.assertRaises(content.ContentError): self.package()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_empty_romfs_cannot_produce_android_rejected_content(self):
        (self.source / 'RomFS' / 'Data' / 'song.bin').unlink()
        with self.assertRaises(content.ContentError): self.package()
        self.assertFalse(self.output.exists())

    def test_failed_copy_leaves_no_output_or_staging_tree(self):
        original = content.digest_file
        def fail_resource_copy(path, destination=None, **kwargs):
            if destination is not None and Path(path).name == 'song.bin':
                destination.write_bytes(b'partial')
                raise OSError('injected interrupted copy')
            return original(path, destination, **kwargs)
        with patch.object(content, 'digest_file', fail_resource_copy):
            with self.assertRaises(OSError): self.package()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.output-*')), [])

    def test_capsule_changed_between_validation_and_copy_is_rejected(self):
        original = content.digest_file
        def changed_package(path, destination=None, **kwargs):
            actual, payload = original(path, destination, **kwargs)
            if destination is not None and Path(path).name == 'main.dmag':
                actual['sha256'] = '0' * 64
            return actual, payload
        with patch.object(content, 'digest_file', changed_package):
            with self.assertRaises(content.ContentError): self.package()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.output-*')), [])


if __name__ == '__main__':
    unittest.main()
