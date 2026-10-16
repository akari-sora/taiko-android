"""Contracts for profile authority and PRE observation/parameter rewriting."""
from dataclasses import replace
import hashlib
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_rewrite as ar
import android_import as ai
import android_profiles as profiles
from test_android_rewrite import Machine
from nso_format import parse_nso


def raw(*words):
    return struct.pack('<' + 'I' * len(words), *words)


def profile(*, observations=(), parameters=()):
    return profiles.Profile('android-arm64', 'main', 'test', 'test-v1',
                            bytes.fromhex('11' * 32), bytes.fromhex('22' * 32), 1,
                            tuple(observations), tuple(parameters))


class ObservationRewriteTests(unittest.TestCase):
    def test_profile_digest_binds_all_authority_fields(self):
        p = profile(observations=(profiles.Observation(0, 1, 0x91000400),))
        for changed in (replace(p, module='sdk'), replace(p, variant='other'),
                        replace(p, ruleset='test-v2'), replace(p, identity_class=2),
                        replace(p, source_sha256=bytes(32)),
                        replace(p, observations=(profiles.Observation(0, 2, 0x91000400),))):
            self.assertNotEqual(p.digest, changed.digest)
        self.assertEqual(len(p.digest), 32)
        self.assertEqual(p.digest, hashlib.sha256(p.canonical_bytes()).digest())
        a, b = profiles.Observation(0, 1, 0x91000400), profiles.Observation(4, 2, 0x91000800)
        self.assertNotEqual(profile(observations=(a, b)).digest, profile(observations=(b, a)).digest)

    def test_production_prefix_is_unresolved(self):
        self.assertEqual(len(profiles.APPLE_OBS[profiles.APPLE_BUILD_PREFIX]), 5)
        self.assertEqual(len(profiles.APPLE_PARAMS[profiles.APPLE_BUILD_PREFIX]), 7)
        self.assertFalse(any(p.identity_class == 2 for p in profiles.PROFILES))
        with self.assertRaisesRegex(ValueError, 'full|identity'):
            profile(observations=()).__class__('android-arm64', 'main', 'x', 'x', bytes(16), bytes(32), 2, (), ())

    def test_pre_gate_executes_displaced_word_after_frame_restore(self):
        p = profile(observations=(profiles.Observation(0, 1, 0x91000400),))
        image = ar.rewrite(raw(0x91000400, 0xD65F03C0), profile=p)
        gate, = image.gates
        self.assertEqual((gate.kind, gate.argument), (ar.OBS, 1))
        self.assertEqual(image.bytes[gate.return_offset:gate.return_offset + 12],
                         raw(ar.pair(True, 29, 30, 0), 0x910043FF, 0x91000400))
        self.assertEqual(image.gate_provenance[0].original_offset, 0)
        self.assertEqual(image.gate_provenance[0].original_word, 0x91000400)

    def test_obs_rejects_wrong_words_unknown_displacement_and_interior(self):
        for instruction in (0x10000000, 0x14000001, 0xD53BD040, 0xAA1203E0, 0xC85F7C20):
            with self.subTest(instruction=hex(instruction)), self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(instruction, 0xD65F03C0), profile=profile(observations=(profiles.Observation(0, 1, instruction),)))
        with self.assertRaisesRegex(ar.RewriteError, 'word'):
            ar.rewrite(raw(0x91000400, 0xD65F03C0), profile=profile(observations=(profiles.Observation(0, 1, 0x91000800),)))
        with self.assertRaisesRegex(ar.RewriteError, 'entry'):
            ar.rewrite(raw(0xD503201F, 0x91000400, 0xD65F03C0), profile=profile(observations=(profiles.Observation(4, 1, 0x91000400),)))

    def test_params_preserve_interleaved_instructions_and_return_a_plus_four(self):
        # mov x8,1; mov x9,2; add x0,x0,3; movk x8,4,lsl16; movk x9,5,lsl16
        words = (0xD2800028, 0xD2800049, 0x91000C00, 0xF2A00088, 0xF2A000A9, 0xD65F03C0)
        ps = (profiles.Parameter(0, 12, words[0], words[3], 8, 0, 0),
              profiles.Parameter(4, 16, words[1], words[4], 9, 1, 0))
        image = ar.rewrite(raw(*words), profile=profile(parameters=ps))
        self.assertEqual(image.bytes[8:12], raw(words[2]))
        self.assertEqual(image.bytes[12:20], raw(0xD503201F, 0xD503201F))
        self.assertEqual(image.parameters, ps)
        for site in image.sites:
            end = site.trampoline + 40
            self.assertEqual(struct.unpack_from('<I', image.bytes, end)[0], ar.branch(end, site.offset + 4))
        machine = Machine(image)
        before, flags = list(machine.x), machine.flags
        machine.store(machine.state + 136, 0x1122334455667788, 8)
        machine.store(machine.state + 144, 0x8877665544332211, 8)
        self.assertEqual(machine.run(), before[0] + 3)
        self.assertEqual(machine.x[8:10], [0x1122334455667788, 0x8877665544332211])
        self.assertEqual(machine.flags, flags)
        self.assertEqual([(i, v) for i, v in enumerate(machine.x) if i not in (0, 8, 9)],
                         [(i, v) for i, v in enumerate(before) if i not in (0, 8, 9)])

    def test_parameter_w_destination_zeroextends_and_every_legal_destination_encodes(self):
        for dest in range(31):
            if dest == 18:
                continue
            for narrow in (0, 1):
                a = (0xD2800020 if not narrow else 0x52800020) | dest
                b = (0xF2A00040 if not narrow else 0x72A00040) | dest
                p = profile(parameters=(profiles.Parameter(0, 4, a, b, dest, 3, narrow),))
                image = ar.rewrite(raw(a, b, 0xD65F03C0), profile=p)
                load = ar.decode(struct.unpack_from('<I', image.bytes, image.sites[0].trampoline + 28)[0], 0)
                self.assertEqual(load.op_str.split(',')[0], ('w' if narrow else 'x') + str(dest) if dest != 30 else ('w30' if narrow else 'x30'))
                if dest == 8:
                    machine = Machine(image)
                    machine.store(machine.state + 160, 0xFFEEDDCC12345678, 8)
                    machine.run()
                    self.assertEqual(machine.x[8], 0x12345678 if narrow else 0xFFEEDDCC12345678)

    def test_param_hazards_entry_overlap_width_and_virtual18_rejected(self):
        a, b = 0xD2800028, 0xF2A00088
        p = profile(parameters=(profiles.Parameter(0, 8, a, b, 8, 0, 0),))
        with self.assertRaisesRegex(ar.RewriteError, 'hazard'):
            ar.rewrite(raw(a, 0xAA0803E0, b, 0xD65F03C0), profile=p)
        with self.assertRaisesRegex(ar.RewriteError, 'entry'):
            ar.rewrite(raw(a, 0xD503201F, b, 0xD65F03C0), profile=p, entry_offsets=(4,))
        for parameter in (profiles.Parameter(0, 4, a, b, 8, 4, 0),
                          profiles.Parameter(0, 4, a, b, 8, 0, 2),
                          profiles.Parameter(0, 4, a, b, 18, 0, 0),
                          profiles.Parameter(0, 4, a, b, 8, 0, 1)):
            with self.subTest(parameter=parameter), self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(a, b, 0xD65F03C0), profile=profile(parameters=(parameter,)))

    def test_v1_byte_identical_when_profile_omitted(self):
        source = ROOT / 'dm/platform/android/module_fixtures/main.nso'
        package, _ = ai.import_module(source.read_bytes(), 'main')
        self.assertEqual(package, source.with_suffix('.dmag').read_bytes())

    def test_registered_production_import_wire_schema_and_independent_catalog(self):
        directory = ROOT / 'dm/platform/android/observation_fixtures'
        source = (directory / 'main.nso').read_bytes()
        package, report = ai.import_module(source, 'main', package_version=2, profile='synthetic-observation-v1')
        self.assertEqual(package, (directory / 'main.dmag').read_bytes())
        self.assertEqual(package[:8], b'DMAMOD02')
        self.assertEqual(struct.unpack_from('<IIII', package, 8), (2, ar.ABI, 384, 0))
        self.assertEqual(package[296:320], bytes(24))
        selected = profiles.SYNTHETIC_OBSERVATION
        self.assertEqual(package[184:216], selected.build_id)
        self.assertEqual(package[216:248], selected.source_sha256)
        self.assertEqual(package[320:352], selected.digest)
        klass, gate_stride, param_offset, count, param_stride, reserved = struct.unpack_from('<IIQQII', package, 352)
        self.assertEqual((klass, gate_stride, count, param_stride, reserved), (1, 32, 5, 40, 0))
        gate_offset, gate_count = struct.unpack_from('<QQ', package, 136)
        self.assertEqual(gate_count, len(selected.observations))
        for i, obs in enumerate(selected.observations):
            ret, pc, kind, arg, word, flags = struct.unpack_from('<QQIIII', package, gate_offset + i * gate_stride)
            self.assertEqual((pc, kind, arg, word, flags), (obs.offset, ar.OBS, obs.id, obs.word, 0))
            self.assertGreater(ret, 16384)
        for i, param in enumerate(selected.parameters):
            self.assertEqual(struct.unpack_from('<QQIIIIII', package, param_offset + i * param_stride),
                             (param.a, param.b, param.word_a, param.word_b, param.destination, param.slot, param.flags, 0))
        self.assertEqual(report['game_boot_status'], 'NOT_RUN')
        self.assertEqual(selected.source_sha256, hashlib.sha256(source).digest())
        # The generator must compare separately reviewed pins, never derive its
        # runtime authority from a just-imported package or its claimed digest.
        import gen_android_observations as generator
        self.assertEqual(generator.catalog(), (directory / 'generated_catalog.inc').read_bytes())

    def test_profile_selection_requires_exact_source_module_and_explicit_v2(self):
        source = (ROOT / 'dm/platform/android/observation_fixtures/main.nso').read_bytes()
        with self.assertRaisesRegex(ai.ImportError, 'version 2'):
            ai.import_module(source, 'main', profile='synthetic-observation-v1')
        with self.assertRaisesRegex(ai.ImportError, 'identity/source'):
            ai.import_module(source, 'sdk', package_version=2, profile='synthetic-observation-v1')
        modified = bytearray(source)
        modified[256 + 0x2f0] ^= 1
        # Repair NSO segment integrity, proving source identity rather than its
        # section hash is the reason a newly supplied variant cannot activate.
        size = struct.unpack_from('<I', modified, 0x18)[0]
        modified[0xA0:0xC0] = hashlib.sha256(modified[256:256 + size]).digest()
        with self.assertRaisesRegex(ai.ImportError, 'identity/source'):
            ai.import_module(bytes(modified), 'main', package_version=2, profile='synthetic-observation-v1')

    def test_unprofiled_v2_has_none_authority_and_no_observations_or_parameters(self):
        source = (ROOT / 'dm/platform/android/module_fixtures/main.nso').read_bytes()
        package, report = ai.import_module(source, 'main', package_version=2)
        self.assertEqual(package[320:356], bytes(36))
        self.assertEqual(struct.unpack_from('<Q', package, 368)[0], 0)
        self.assertTrue(all(g['kind'] != ar.OBS for g in report['rewrite']['gates']))

    def test_observation_id_and_parameter_endpoint_conflicts_reject(self):
        instruction = 0x91000400
        for observations in ((profiles.Observation(0, 1, instruction), profiles.Observation(4, 1, instruction)),
                             (profiles.Observation(0, 1, instruction), profiles.Observation(0, 2, instruction))):
            with self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(instruction, instruction, 0xD65F03C0), profile=profile(observations=observations), entry_offsets=(4,))
        a, b = 0xD2800028, 0xF2A00088
        item = profiles.Parameter(0, 4, a, b, 8, 0, 0)
        with self.assertRaisesRegex(ar.RewriteError, 'overlapping'):
            ar.rewrite(raw(a, b, 0xD65F03C0), profile=profile(parameters=(item, item)))

    def test_parameter_external_branch_and_exclusive_overlap_reject(self):
        a, b = 0xD2800028, 0xF2A00088
        p = profile(parameters=(profiles.Parameter(0, 8, a, b, 8, 0, 0),))
        with self.assertRaisesRegex(ar.RewriteError, 'entry'):
            ar.rewrite(raw(a, 0xD503201F, b, 0x17FFFFFE), profile=p)
        # A helper cannot run while the architectural reservation is live.
        p = profile(observations=(profiles.Observation(4, 6, 0x91000400),))
        with self.assertRaisesRegex(ar.RewriteError, 'exclusive'):
            ar.rewrite(raw(0xC85F7C20, 0x91000400, 0xC8027C20, 0xD65F03C0), profile=p)

    def test_parameter_endpoints_in_exclusive_body_reject_before_emission(self):
        a, b = 0xD2800028, 0xF2A00088
        parameter = profiles.Parameter(4, 8, a, b, 8, 0, 0)
        # No x18 operand is needed to expose the bug: the parameter rewrite
        # itself previously caused the whole exclusive body to relocate while
        # silently executing the original constant instead of the parameter.
        with self.assertRaisesRegex(ar.RewriteError, 'exclusive'):
            ar.rewrite(raw(0xC85F7C20, a, b, 0xC8027C20, 0xAA0803E0, 0xD65F03C0),
                       profile=profile(parameters=(parameter,)))

    def test_parameter_endpoints_in_exclusive_retry_tail_reject_before_emission(self):
        a, b = 0xD2800028, 0xF2A00088
        parameter = profiles.Parameter(12, 16, a, b, 8, 0, 0)
        # stxr w2; cbz w2,done; A; B; b head. A/B are outside the live
        # reservation but inside the preserved failed-store retry region.
        with self.assertRaisesRegex(ar.RewriteError, 'exclusive'):
            ar.rewrite(raw(0xC85F7C20, 0xC8027C20, 0x34000082, a, b,
                           ar.branch(20, 0), 0xAA0803E0, 0xD65F03C0),
                       profile=profile(parameters=(parameter,)))


if __name__ == '__main__':
    unittest.main()
