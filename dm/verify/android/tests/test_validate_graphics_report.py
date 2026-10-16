"""Authored native-shaped unit receipts; these are not device or GPU evidence."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_validate_service_report import load_validator

ROOT = Path(__file__).resolve().parents[4]
DIRECTORY = ROOT / 'dm/verify/android'
CHECKS = (
    'exact-graph-bootstrap', 'forced-bootstrap-exports', 'guest-callback-growth',
    'full-byte-data-oracle', 'actual-vulkan-operations',
    'no-unavailable-host-or-validation-errors',
)
EXTENDED_CHECKS = (
    'cross-submit-buffer-copy', 'cross-submit-uniform-copy',
    'cross-submit-image-by-value-alias', 'cpu-edit-after-successful-wait',
    'same-pool-overlapping-copy', 'late-unsupported-whole-submit',
    'preaccept-allocation-refusal', 'preaccept-submit-refusal',
    'accepted-device-loss', 'accepted-publication-refusal',
    'held-gpu-retention-and-retirement', 'clean-reload-after-terminal-cases',
)


def receipt():
    """Mirror report() fields with authored values, never an executed GPU claim."""
    fixture = json.loads((ROOT / 'dm/platform/android/graphics_fixtures/import.json').read_text())
    return {
        'schemaVersion': 1, 'suite': 'android-graphics-sdk', 'status': 'PASS',
        'outcome': 'Completed', 'gamePlayable': False, 'syntheticOnly': True,
        'originalGame': 'NOT_RUN', 'capability': 'offscreen-diagnostic',
        'loadGeneration': 42, 'fence': 1, 'completedFence': 1, 'authorityChecks': 3,
        'dataOraclePassed': True, 'shapePassed': True, 'forceBootstrapMatched': True,
        'retentionReceipts': 'NOT_RUN', 'verifiedDataBytes': 70404,
        'publicationHeld': False, 'pendingDataUntouched': False,
        'checks': [{'id': name, 'passed': True} for name in CHECKS],
        'addresses': dict(zip(('pool', 'command', 'uniform', 'copy', 'clear',
                               'roundtrip', 'event', 'hostUpdate'),
                              (0x10000, 0x20000, 0x30000, 0x40000, 0x50000,
                               0x60000, 0x70000, 0x80000))),
        'guest': {
            'sdkInit': 1, 'moduleInit': 1, 'fallbackCalls': 0, 'lookupCount': 180,
            'callbackCalls': 5, 'callbackBytes': 1024, 'callbackSp': 0x100000,
            'callbackTls': 0x110000, 'callbackExpectedTls': 0x110000,
            'hostCallbackCalls': 2, 'waitUnfenced': 2, 'waitInitial': 2,
            'waitResult': 1, 'queueError': 0, 'phase': 2, 'failures': 0,
        },
        'gpu': {
            'device': 'authored validator unit fixture, not a real GPU receipt',
            'vendorId': 1, 'deviceId': 2, 'apiVersion': 4198400, 'driverVersion': 3,
            'submits': 1, 'completed': 1, 'failed': 0, 'uniformUpdates': 60,
            'bufferCopies': 1, 'imageUploads': 1, 'imageDownloads': 2,
            'renderPasses': 1, 'flushes': 0, 'invalidates': 0,
            'noncoherentAtomSize': 64, 'validationAvailable': False,
            'validationErrors': 0, 'validationStatus': 'UNAVAILABLE',
        },
        'sdkPackageSha256': fixture['package_sha256'],
        'unsupported': ['draw', 'compute', 'shaders', 'presentation', 'full-product'],
    }


def held_receipt():
    report = receipt()
    report.update(status='PENDING', outcome='Pending', completedFence=0,
                  dataOraclePassed=False, verifiedDataBytes=0,
                  publicationHeld=True, pendingDataUntouched=True)
    report['guest'].update(waitInitial=2, waitResult=2, phase=1)
    report['gpu']['completed'] = 0
    for check in report['checks']:
        check['passed'] = check['id'] not in ('full-byte-data-oracle', 'actual-vulkan-operations')
    report['addresses']['pool'] = 0x1000000
    return report


def retention_receipt(generation=42, waiter=False):
    """Authored 2 MiB retention schema, without claiming executed device data."""
    return {
        'schemaVersion': 1, 'suite': 'android-graphics-retention', 'status': 'PASS',
        'barrierId': 3, 'loadGeneration': generation, 'fence': 1, 'completedFence': 0,
        'heapAddress': 0x1000000, 'heapSize': 2097152, 'poolBytes': 262144,
        'verifiedUnchangedBytes': 2097152, 'poolFinalizeRetained': True,
        'textureFinalizeRetained': True, 'protectResult': 64001, 'shrinkResult': 64001,
        'mapResult': 64001, 'unmapPinnedSourceResult': 64001, 'nonquiescent': True,
        'resetRefused': True, 'shutdownRefused': True,
        'shutdownReason': ('guest invocations are still executing' if waiter else
                           'graphics work still retains guest memory'),
        'objectsAndHeapUnchanged': True, 'readLeaseHeldForShutdown': False,
        'gamePlayable': False,
    }


def extended_receipt():
    """Authored native-shaped rows; passing unit tests is not Vulkan evidence."""
    checks = []
    for index, name in enumerate(EXTENDED_CHECKS):
        row = {
            'id': name, 'passed': True, 'baselinePassed': True, 'closed': True,
            'loadGeneration': 100 + index, 'verifiedDataBytes': 0,
            'firstFence': 0, 'lastFence': 0, 'completedFence': 0,
            'submits': 0, 'completed': 0, 'failed': 0, 'guestWaits': 0,
            'waitResult': 1, 'queueError': 0, 'firstPending': False,
            'queueErrorCode': 0, 'queueErrorOperation': 0,
            'suffixRejected': False, 'suffixWaitResult': None,
            'suffixUnchanged': False, 'detail': '',
        }
        if index < 5:
            row.update(verifiedDataBytes=65536, firstFence=2, lastFence=3,
                       completedFence=3, submits=3, completed=3,
                       guestWaits=2 if index == 3 else 1, firstPending=True)
        elif index < 10:
            accepted = index >= 8
            row.update(verifiedDataBytes=262144, firstFence=1,
                       lastFence=2 if accepted else 1, completedFence=1,
                       submits=2 if accepted else 1, completed=1, failed=int(accepted),
                       guestWaits=3 if accepted else 0, waitResult=3 if accepted else None,
                       queueError=1, queueErrorCode=4 if accepted else 2,
                       queueErrorOperation=27 if index == 5 else 0,
                       suffixRejected=accepted, suffixUnchanged=accepted,
                       suffixWaitResult=3 if accepted else None,
                       detail='authored controlled failure unit fixture')
        elif index == 10:
            row.update(verifiedDataBytes=70404, lastFence=1, completedFence=1,
                       submits=1, completed=1, firstPending=True,
                       retention=retention_receipt(row['loadGeneration']))
        else:
            row['verifiedDataBytes'] = 70404
        checks.append(row)
    base = receipt()
    return {
        'schemaVersion': 1, 'suite': 'android-graphics-extended', 'status': 'PASS',
        'gamePlayable': False, 'syntheticOnly': True, 'originalGame': 'NOT_RUN',
        'capability': 'offscreen-diagnostic', 'verifiedDataBytes': 1779208,
        'checkCount': 12, 'checks': checks,
        'gpu': {key: base['gpu'][key] for key in ('device', 'vendorId', 'deviceId',
                                                'apiVersion', 'driverVersion',
                                                'validationAvailable', 'validationErrors')},
        'sdkPackageSha256': base['sdkPackageSha256'], 'unsupported': base['unsupported'],
    }


class GraphicsReportTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator('validate_graphics_report')
        self.report = receipt()

    def rejects(self, report):
        with self.assertRaises(ValueError):
            self.validator.summarize(report)

    def test_completed_native_shape_preserves_diagnostic_limits(self):
        result = self.validator.summarize(self.report)
        self.assertEqual(result['graphicsSdk'], 'PASS')
        self.assertEqual(result['gates'], {'G0': 'NOT_VERIFIED', **{f'G{i}': 'NOT_RUN' for i in range(1, 7)}})
        self.assertFalse(result['gamePlayable'])
        self.assertTrue(result['syntheticOnly'])
        self.assertEqual(result['originalGame'], 'NOT_RUN')
        self.assertEqual(result['capability'], 'offscreen-diagnostic')
        self.assertEqual(result['retentionReceipts'], 'NOT_RUN')
        self.assertEqual(result['validation'], 'NOT_RUN')
        self.assertTrue(any('retention' in item.lower() for item in result['limitations']))
        self.assertTrue(any('frontend' in item.lower() for item in result['limitations']))

    def test_identity_is_bound_to_current_compiled_sdk(self):
        for key, value in (('schemaVersion', 2), ('suite', 'android-controller-sdk'),
                           ('sdkPackageSha256', '0' * 64), ('sdkPackageSha256', None)):
            with self.subTest(key=key, value=value):
                self.rejects({**self.report, key: value})

    def test_checks_require_six_unique_exact_ids_and_real_booleans(self):
        for checks in ([], self.report['checks'][:-1], self.report['checks'] * 2,
                       self.report['checks'][:1] * 6,
                       [{'id': 'unknown', 'passed': True}] + self.report['checks'][1:]):
            self.rejects({**self.report, 'checks': checks})
        for value in (1, 0, 'true', None):
            report = copy.deepcopy(self.report)
            report['checks'][0]['passed'] = value
            self.rejects(report)
        report = copy.deepcopy(self.report)
        report['checks'][0]['passed'] = False
        self.assertEqual(self.validator.summarize(report)['graphicsSdk'], 'FAIL')

    def test_completion_requires_actual_data_shape_authority_and_fence(self):
        for key, value in (('outcome', 'Pending'), ('outcome', 'Failed'),
                           ('fence', 0), ('fence', 2), ('completedFence', 0),
                           ('completedFence', 2), ('authorityChecks', 2),
                           ('loadGeneration', 0), ('verifiedDataBytes', 70403),
                           ('dataOraclePassed', False), ('shapePassed', False),
                           ('forceBootstrapMatched', False), ('publicationHeld', True),
                           ('pendingDataUntouched', True)):
            with self.subTest(key=key, value=value):
                self.rejects({**self.report, key: value})

    def test_gpu_counters_cannot_be_replaced_by_true_checks(self):
        for key, value in (('submits', 0), ('submits', 2), ('completed', 0),
                           ('failed', 1), ('uniformUpdates', 59), ('bufferCopies', 0),
                           ('imageUploads', 0), ('imageDownloads', 1), ('renderPasses', 0),
                           ('validationErrors', 1), ('device', ''), ('apiVersion', 0),
                           ('noncoherentAtomSize', 3)):
            report = copy.deepcopy(self.report)
            report['gpu'][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(report)

    def test_guest_completion_requires_initialization_callbacks_and_clean_wait(self):
        for key, value in (('sdkInit', 0), ('moduleInit', 2), ('fallbackCalls', 1),
                           ('lookupCount', 0), ('callbackCalls', 2), ('callbackBytes', 256),
                           ('callbackSp', 17), ('callbackTls', 1), ('hostCallbackCalls', 1),
                           ('waitUnfenced', 0), ('waitInitial', 3), ('waitResult', 2),
                           ('queueError', 1), ('phase', 1), ('failures', 1)):
            report = copy.deepcopy(self.report)
            report['guest'][key] = value
            with self.subTest(key=key, value=value):
                self.rejects(report)
        report = copy.deepcopy(self.report)
        report['guest']['waitResult'] = 0
        self.assertEqual(self.validator.summarize(report)['graphicsSdk'], 'PASS')

    def test_all_integer_fields_reject_boolean_float_and_out_of_range_aliases(self):
        groups = (('', [key for key, value in self.report.items() if type(value) is int]),
                  ('guest', list(self.report['guest'])), ('addresses', list(self.report['addresses'])),
                  ('gpu', [key for key, value in self.report['gpu'].items() if type(value) is int]))
        for group, keys in groups:
            for key in keys:
                original = self.report[group][key] if group else self.report[key]
                for value in (bool(original), float(original), -1, 2**65):
                    report = copy.deepcopy(self.report)
                    (report[group] if group else report)[key] = value
                    with self.subTest(group=group, key=key, value=value):
                        self.rejects(report)

    def test_boolean_receipts_cannot_use_numeric_aliases(self):
        for key in ('gamePlayable', 'syntheticOnly', 'dataOraclePassed', 'shapePassed',
                    'forceBootstrapMatched', 'publicationHeld', 'pendingDataUntouched'):
            self.rejects({**self.report, key: int(self.report[key])})
        report = copy.deepcopy(self.report)
        report['gpu']['validationAvailable'] = 0
        self.rejects(report)

    def test_scope_and_retention_cannot_be_promoted(self):
        for key, value in (('gamePlayable', True), ('syntheticOnly', False),
                           ('originalGame', 'PASS'), ('capability', 'full-product'),
                           ('retentionReceipts', 'PASS'), ('unsupported', []),
                           ('gates', {'G0': 'PASS'}), ('frontend', 'PASS')):
            with self.subTest(key=key):
                self.rejects({**self.report, key: value})
        for gate in range(7):
            gates = {'G0': 'NOT_VERIFIED', **{f'G{i}': 'NOT_RUN' for i in range(1, 7)}}
            gates[f'G{gate}'] = 'PASS'
            self.rejects({**self.report, 'gates': gates})

    def test_validation_availability_and_capture_control_validation_claim(self):
        for available, native, expected in ((False, 'UNAVAILABLE', 'NOT_RUN'),
                                             (True, 'ENABLED', 'PASS'),
                                             (True, 'ENABLED_NO_MESSAGE_CAPTURE', 'NOT_RUN')):
            report = copy.deepcopy(self.report)
            report['gpu'].update(validationAvailable=available, validationStatus=native)
            self.assertEqual(self.validator.summarize(report)['validation'], expected)
        for available, native in ((False, 'PASS'), (False, 'ENABLED'),
                                  (True, 'UNAVAILABLE'), (True, 'PASS')):
            report = copy.deepcopy(self.report)
            report['gpu'].update(validationAvailable=available, validationStatus=native)
            self.rejects(report)

    def test_failed_or_pending_receipt_never_becomes_completed_evidence(self):
        for status, outcome in (('FAIL', 'Completed'), ('FAIL', 'Failed'), ('PENDING', 'Pending')):
            report = copy.deepcopy(self.report)
            report.update(status=status, outcome=outcome)
            self.assertEqual(self.validator.summarize(report)['graphicsSdk'], 'FAIL')
        failed = copy.deepcopy(self.report)
        failed.update(status='FAIL', outcome='Failed', completedFence=0,
                      dataOraclePassed=False, verifiedDataBytes=0)
        failed['guest'].update(waitResult=3, queueError=1, phase=1)
        failed['gpu'].update(completed=0, failed=1)
        for check in failed['checks']:
            if check['id'] in ('full-byte-data-oracle', 'actual-vulkan-operations'):
                check['passed'] = False
        self.assertEqual(self.validator.summarize(failed)['graphicsSdk'], 'FAIL')
        report = copy.deepcopy(self.report)
        report.update(status='PENDING', outcome='Pending', completedFence=0,
                      dataOraclePassed=False, verifiedDataBytes=0,
                      publicationHeld=True, pendingDataUntouched=True)
        report['guest'].update(waitResult=2, phase=1)
        report['gpu']['completed'] = 0
        for check in report['checks']:
            check['passed'] = False
        self.assertEqual(self.validator.summarize(report)['graphicsSdk'], 'FAIL')

    def test_missing_native_fields_are_rejected(self):
        for group in ('guest', 'gpu', 'addresses', ''):
            values = self.report[group] if group else self.report
            for key in values:
                report = copy.deepcopy(self.report)
                del (report[group] if group else report)[key]
                with self.subTest(group=group, key=key):
                    self.rejects(report)

    def test_cli_uses_strict_json_and_nonzero_failure_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'report.json', Path(directory) / 'summary.json'
            def run(text):
                source.write_text(text, encoding='utf-8')
                return subprocess.run([sys.executable, str(DIRECTORY / 'validate_graphics_report.py'),
                                       str(source), '--out', str(output)], capture_output=True, text=True)
            result = run(json.dumps(self.report))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())['validation'], 'NOT_RUN')
            report = {**self.report, 'status': 'FAIL', 'outcome': 'Failed'}
            result = run(json.dumps(report))
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(output.read_text())['graphicsSdk'], 'FAIL')
            for text in (json.dumps(self.report)[:-1] + ',"status":"PASS"}',
                         json.dumps(self.report).replace('"fence": 1', '"fence": NaN'),
                         json.dumps(self.report).replace('"fence": 1', '"fence": Infinity')):
                result = run(text)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ValueError', result.stderr)


class ExtendedGraphicsReportTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator('validate_graphics_report')
        self.report = extended_receipt()

    def rejects(self, report):
        with self.assertRaises(ValueError):
            self.validator.summarize_extended(report)

    def test_extended_rows_preserve_diagnostic_scope_and_validation_unknown(self):
        result = self.validator.summarize_extended(self.report)
        self.assertEqual(result['graphicsExtended'], 'PASS')
        self.assertEqual(result['verifiedDataBytes'], 1779208)
        self.assertEqual(result['retentionReceipts'], 'PASS')
        self.assertEqual(result['validation'], 'NOT_RUN')
        self.assertEqual(result['gates']['G0'], 'NOT_VERIFIED')
        self.assertTrue(all(result['gates'][f'G{i}'] == 'NOT_RUN' for i in range(1, 7)))
        self.assertFalse(result['gamePlayable'])
        self.assertEqual(result['checks'][10]['retention']['verifiedUnchangedBytes'], 2097152)
        report = copy.deepcopy(self.report)
        report['gpu']['validationAvailable'] = True
        self.assertEqual(self.validator.summarize_extended(report)['validation'], 'NOT_RUN')

    def test_extended_identity_scope_and_check_order_are_exact(self):
        for key, value in (('sdkPackageSha256', '0' * 64), ('suite', 'android-graphics-sdk'),
                           ('gamePlayable', True), ('originalGame', 'PASS'), ('syntheticOnly', False),
                           ('capability', 'full-product'), ('unsupported', []),
                           ('gates', {'G0': 'PASS'}), ('checkCount', 11),
                           ('verifiedDataBytes', 1779207), ('frontend', 'PASS')):
            self.rejects({**self.report, key: value})
        for checks in (self.report['checks'][:-1], self.report['checks'] * 2,
                       self.report['checks'][:1] * 12, list(reversed(self.report['checks']))):
            self.rejects({**self.report, 'checks': checks})

    def test_every_success_row_requires_full_bytes_ordered_fences_and_guest_waits(self):
        for index in range(5):
            for key, value in (('verifiedDataBytes', 64), ('firstFence', 1), ('lastFence', 2),
                               ('completedFence', 2), ('submits', 2), ('completed', 2),
                               ('failed', 1), ('firstPending', False), ('waitResult', 2),
                               ('guestWaits', 1 if index == 3 else 2), ('queueError', 1),
                               ('suffixRejected', True), ('suffixWaitResult', 3)):
                report = copy.deepcopy(self.report)
                report['checks'][index][key] = value
                with self.subTest(index=index, key=key):
                    self.rejects(report)

    def test_failure_rows_require_no_prefix_effects_and_terminal_suffix_rejection(self):
        for index in range(5, 10):
            accepted = index >= 8
            mutations = [('verifiedDataBytes', 4), ('firstFence', 2),
                         ('lastFence', 1 if accepted else 2), ('completedFence', 2),
                         ('submits', 1 if accepted else 2), ('completed', 0),
                         ('failed', 0 if accepted else 1), ('queueError', 0),
                         ('firstPending', True), ('guestWaits', 2 if accepted else 1),
                         ('waitResult', 1), ('queueErrorCode', 0), ('detail', '')]
            if accepted:
                mutations += [('suffixRejected', False), ('suffixUnchanged', False),
                              ('suffixWaitResult', 0)]
            else:
                mutations += [('suffixRejected', True), ('suffixWaitResult', 3)]
            for key, value in mutations:
                report = copy.deepcopy(self.report)
                report['checks'][index][key] = value
                with self.subTest(index=index, key=key):
                    self.rejects(report)
        report = copy.deepcopy(self.report)
        report['checks'][5]['queueErrorOperation'] = 26
        self.rejects(report)

    def test_generation_baselines_closure_and_nested_retention_bind_authority(self):
        for index in range(12):
            for key, value in (('baselinePassed', False), ('closed', False),
                               ('loadGeneration', 0 if index == 0 else 100 + index - 1)):
                report = copy.deepcopy(self.report)
                report['checks'][index][key] = value
                self.rejects(report)
        for key, value in (('loadGeneration', 999), ('completedFence', 1),
                           ('verifiedUnchangedBytes', 4096), ('poolFinalizeRetained', False),
                           ('readLeaseHeldForShutdown', True),
                           ('shutdownReason', 'guest invocations are still executing')):
            report = copy.deepcopy(self.report)
            report['checks'][10]['retention'][key] = value
            self.rejects(report)
        report = copy.deepcopy(self.report)
        report['checks'][11]['verifiedDataBytes'] = 0
        self.rejects(report)

    def test_extended_unsigned_fields_and_booleans_reject_aliases(self):
        for index, row in enumerate(self.report['checks']):
            for key, original in row.items():
                if type(original) not in (int, bool) and original is not None:
                    continue
                for value in ((1, 'true') if type(original) is bool else
                              (True, 1.0, -1, 2**64)):
                    report = copy.deepcopy(self.report)
                    report['checks'][index][key] = value
                    with self.subTest(index=index, key=key, value=value):
                        self.rejects(report)
        for group, keys in (('', ('schemaVersion', 'verifiedDataBytes', 'checkCount')),
                            ('gpu', ('vendorId', 'deviceId', 'apiVersion', 'driverVersion', 'validationErrors'))):
            for key in keys:
                for value in (True, 1.0, -1, 2**64):
                    report = copy.deepcopy(self.report)
                    (report[group] if group else report)[key] = value
                    self.rejects(report)

    def test_nested_schema_rejects_missing_fields_or_added_authority_even_on_failure(self):
        for index in range(12):
            for key in self.report['checks'][index]:
                report = copy.deepcopy(self.report)
                del report['checks'][index][key]
                self.rejects(report)
        for status in ('PASS', 'FAIL'):
            report = copy.deepcopy(self.report)
            report['status'] = status
            report['checks'][10]['retention']['originalGame'] = 'PASS'
            self.rejects(report)
        for group in ('gpu', ''):
            for key in (self.report[group] if group else self.report):
                report = copy.deepcopy(self.report)
                del (report[group] if group else report)[key]
                self.rejects(report)

    def test_extended_failed_status_or_false_check_cannot_pass(self):
        report = {**self.report, 'status': 'FAIL'}
        self.assertEqual(self.validator.summarize_extended(report)['graphicsExtended'], 'FAIL')
        report = copy.deepcopy(self.report)
        report['checks'][0]['passed'] = False
        self.assertEqual(self.validator.summarize_extended(report)['graphicsExtended'], 'FAIL')


class RetentionGraphicsReportTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator('validate_graphics_report')
        self.report, self.context = retention_receipt(), held_receipt()

    def rejects(self, report, context=None):
        with self.assertRaises(ValueError):
            self.validator.summarize_retention(report, self.context if context is None else context)

    def test_context_bound_gpu_and_waiter_receipts_do_not_claim_completion(self):
        for waiter in (False, True):
            result = self.validator.summarize_retention(retention_receipt(waiter=waiter), self.context)
            self.assertEqual(result['graphicsRetention'], 'PASS')
            self.assertEqual(result['graphicsCompletion'], 'NOT_RUN')
            self.assertEqual(result['validation'], 'NOT_RUN')
            self.assertFalse(result['gamePlayable'])
            self.assertEqual(result['gates']['G0'], 'NOT_VERIFIED')
            self.assertEqual(result['verifiedUnchangedBytes'], 2097152)

    def test_retention_needs_all_guard_bytes_and_no_added_read_lease(self):
        for key, original in self.report.items():
            if type(original) is bool:
                self.rejects({**self.report, key: not original})
                self.rejects({**self.report, key: int(original)})
            elif type(original) is int:
                for value in (True, float(original), -1, 2**64):
                    self.rejects({**self.report, key: value})
        for key, value in (('verifiedUnchangedBytes', 4096), ('heapSize', 262144),
                           ('poolBytes', 4096), ('fence', 2), ('completedFence', 1),
                           ('protectResult', 0), ('shrinkResult', 0), ('mapResult', 0),
                           ('unmapPinnedSourceResult', 0), ('shutdownReason', 'invalid argument'),
                           ('sdkPackageSha256', self.context['sdkPackageSha256']),
                           ('gates', {'G0': 'PASS'})):
            self.rejects({**self.report, key: value})
        for key in self.report:
            report = dict(self.report)
            del report[key]
            self.rejects(report)

    def test_retention_context_cannot_be_completed_mismatched_or_forged(self):
        with self.assertRaises(ValueError):
            self.validator.summarize_retention(self.report, None)
        self.rejects(self.report, receipt())
        for key, value in (('loadGeneration', 43), ('fence', 2), ('completedFence', 1),
                           ('sdkPackageSha256', '0' * 64), ('status', 'PASS'),
                           ('publicationHeld', False), ('pendingDataUntouched', False),
                           ('dataOraclePassed', True), ('verifiedDataBytes', 70404),
                           ('forceBootstrapMatched', False), ('authorityChecks', 2)):
            self.rejects(self.report, {**self.context, key: value})
        context = copy.deepcopy(self.context)
        context['addresses']['pool'] += 4096
        self.rejects(self.report, context)
        for key in ('waitResult', 'queueError', 'phase'):
            context = copy.deepcopy(self.context)
            context['guest'][key] = 0
            if key == 'queueError':
                context['guest'][key] = 1
            self.rejects(self.report, context)

    def test_retention_failure_remains_failure(self):
        self.assertEqual(self.validator.summarize_retention(
            {**self.report, 'status': 'FAIL'}, self.context)['graphicsRetention'], 'FAIL')

    def test_cli_dispatches_extended_and_requires_retention_context(self):
        with tempfile.TemporaryDirectory() as directory:
            source, context, output = [Path(directory) / name for name in ('report.json', 'context.json', 'out.json')]
            context.write_text(json.dumps(self.context), encoding='utf-8')
            command = [sys.executable, str(DIRECTORY / 'validate_graphics_report.py'), str(source), '--out', str(output)]
            source.write_text(json.dumps(extended_receipt()), encoding='utf-8')
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())['graphicsExtended'], 'PASS')
            source.write_text(json.dumps(self.report), encoding='utf-8')
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('context', result.stderr)
            result = subprocess.run(command + ['--context', str(context)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())['graphicsCompletion'], 'NOT_RUN')


if __name__ == '__main__':
    unittest.main()
