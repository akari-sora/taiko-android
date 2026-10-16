"""Apple source receipts must bind both the emitter and shared profile tables.

Execute only the actual fingerprint producer AST and rulegate's Python checker;
the executable patcher is not imported and no game asset or Apple build is used.
"""
import ast
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
PATCHER = ROOT / 'dm/tools/patch_nso.py'
RULEGATE = ROOT / 'dm/verify/rulegate.sh'


class AppleSourceFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='dm-apple-source-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.tools = self.directory / 'tools'
        self.tools.mkdir()
        self.output = self.directory / 'output'
        self.output.mkdir()
        for name in ('patch_nso.py', 'android_profiles.py'):
            (self.tools / name).write_bytes((ROOT / 'dm/tools' / name).read_bytes())
        tree = ast.parse(PATCHER.read_text(encoding='utf-8'), filename=str(PATCHER))
        writers = [node for node in tree.body if isinstance(node, ast.With) and
                   any(isinstance(value, ast.Constant) and value.value == 'build_src.sha256'
                       for value in ast.walk(node.items[0].context_expr))]
        self.assertEqual(len(writers), 1, 'one actual source receipt producer is required')
        self.producer = compile(ast.Module(body=writers, type_ignores=[]), str(PATCHER), 'exec')
        rule = RULEGATE.read_text(encoding='utf-8')
        marker = 'if ! "$PY" - "$HERE/../tools" "$OUT/build_src.sha256" <<\'PY\'\n'
        self.assertEqual(rule.count(marker), 1)
        self.checker = rule.split(marker, 1)[1].split('\nPY\nthen', 1)[0]

    def produce(self):
        exec(self.producer, {'os': os, 'hashlib': hashlib,
                             '__file__': str(self.tools / 'patch_nso.py'),
                             'outdir': str(self.output)})
        return (self.output / 'build_src.sha256').read_text(encoding='ascii')

    def check_receipt(self):
        return subprocess.run([sys.executable, '-', str(self.tools),
                               str(self.output / 'build_src.sha256')],
                              input=self.checker, text=True, capture_output=True)

    def test_actual_producer_records_both_source_hashes(self):
        receipt = self.produce()
        self.assertEqual(receipt.splitlines(), [
            hashlib.sha256((self.tools / name).read_bytes()).hexdigest() + '  ' + name
            for name in ('patch_nso.py', 'android_profiles.py')])
        self.assertEqual(self.check_receipt().returncode, 0)

    def test_profile_only_change_invalidates_and_regeneration_refreshes(self):
        before = self.produce().splitlines()
        profile = self.tools / 'android_profiles.py'
        profile.write_bytes(profile.read_bytes() + b'\n# source freshness regression\n')
        self.assertEqual(self.check_receipt().returncode, 1)
        after = self.produce().splitlines()
        self.assertEqual(before[0], after[0])
        self.assertNotEqual(before[1], after[1])
        self.assertEqual(self.check_receipt().returncode, 0)

    def test_emitter_only_change_invalidates(self):
        self.produce()
        patcher = self.tools / 'patch_nso.py'
        patcher.write_bytes(patcher.read_bytes() + b'\n# source freshness regression\n')
        self.assertEqual(self.check_receipt().returncode, 1)

    def test_legacy_missing_duplicate_and_malformed_receipts_fail_closed(self):
        lines = self.produce().splitlines()
        for text in (lines[0] + '\n', lines[1] + '\n',
                     lines[1] + '\n' + lines[1] + '\n',
                     '\n'.join(lines) + '\nextra\n', 'malformed\n', ''):
            with self.subTest(receipt=text):
                (self.output / 'build_src.sha256').write_text(text, encoding='ascii')
                self.assertEqual(self.check_receipt().returncode, 1)
        (self.output / 'build_src.sha256').unlink()
        self.assertEqual(self.check_receipt().returncode, 1)


if __name__ == '__main__':
    unittest.main()
