"""Self-authored forests and resigned byte/receipt mutations, no game bytes."""
import copy
from pathlib import Path
import struct
import sys
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import taiko_forest_audit as audit


def put(image, offset, *values):
    struct.pack_into('<' + 'I' * len(values), image, offset, *values)


def jump(pc, target):
    return 0x14000000 | ((target - pc) // 4 & 0x3FFFFFF)


def address(pc, target, register):
    pages = (target >> 12) - (pc >> 12)
    return (0x90000000 | (pages & 3) << 29 | (pages >> 2 & 0x7FFFF) << 5 | register,
            0x91000000 | (target & 4095) << 10 | register << 5 | register)


def authored_fixture(targets=(0x1000, 0x2000, 0x3000), patch=0x4000):
    """Write the agreed ISA contract directly, independently of the emitter."""
    targets = tuple(targets)
    failure = patch + 60 * len(targets)
    end = failure + 28
    stub = (end + 15) & ~15
    literal = (stub + 60 + 7) & ~7
    image = bytearray(literal + 8)
    put(image, 0, jump(0, stub))
    put(image, stub, 0xD10103FF, 0xA9007BF0, 0xA90107E0,
        0x58000010 | ((literal - stub - 12) // 4) << 5,
        0xD63F0200, 0xAA1003E1, 0xA9407BF0, 0xF90013E2,
        0xD53B4202, 0xF90017E2, 0xF9400020,
        *address(stub + 44, 4, 30), 0xF9001BFE, jump(stub + 56, patch))
    # Literals here are intentionally spelled out instead of copying audit's
    # SUCCESS/FAILURE constants, so a mistaken implementation constant fails.
    put(image, failure, 0xF94017E2, 0xD51B4202, 0xF94013E2,
        0xA94107E0, 0xA9407BF0, 0x910103FF, 0xD4200000)
    todo = [(0, len(targets), patch)]
    while todo:
        lo, hi, node = todo.pop()
        mid = (lo + hi) // 2
        left = node + 60 if lo < mid else failure
        right = node + 60 * (1 + mid - lo) if mid + 1 < hi else failure
        put(image, node, *address(node, targets[mid], 1), 0xEB01001F,
            0x54000080, 0x54000043, jump(node + 20, right), jump(node + 24, left),
            0xF94017E2, 0xD51B4202, 0xF94013E2, 0xA94107E0,
            0xF94003F0, 0xF9401BFE, 0x910103FF, jump(node + 56, targets[mid]))
        if lo < mid:
            todo.append((lo, mid, left))
        if mid + 1 < hi:
            todo.append((mid + 1, hi, right))
    descriptor = dict(version=1, start=patch, root=patch, end=end,
                      failure_offset=failure, node_size=60, node_count=len(targets),
                      target_count=len(targets), target_sha256=audit.target_digest(targets),
                      site_offsets=[0], max_depth=len(targets).bit_length(), stub_size=60, frame_size=64)
    arguments = dict(source_offset=0, trampoline=stub, patch_start=patch,
                     fixups=[dict(offset=literal, helper=1)])
    return image, descriptor, targets, arguments


class ForestAuditTests(unittest.TestCase):
    def verify(self, fixture):
        image, descriptor, targets, arguments = fixture
        return audit.verify_emitted_forest(image, descriptor, targets, **arguments)

    def test_actual_authored_forest_passes_single_even_odd_and_deep_geometry(self):
        for count in (1, 2, 3, 4, 7, 8, 31, 128, 4096):
            with self.subTest(count=count):
                targets = tuple(0x100 + 4 * index for index in range(count))
                result = self.verify(authored_fixture(targets, patch=0x10000))
                self.assertEqual(result['target_count'], count)

    def test_independent_byte_audit_accepts_production_emitter_and_rejects_resigned_leaf(self):
        # Production emitter is used only to construct input bytes. The audit
        # imports no emitter, regeneration, or emitter instruction constructors.
        from test_taiko_call_forest import rewritten, fixture
        from dataclasses import asdict
        for count in (1, 2, 7, 63, 1023):
            image, targets = rewritten(count)
            forest = image.metadata()['checked_call_forests'][0]
            source = fixture(count)[0]
            site = next(site for site in image.sites if site.offset == 0)
            arguments = dict(source_offset=0, trampoline=site.trampoline,
                             patch_start=len(source), fixups=[asdict(item) for item in image.fixups])
            with self.subTest(count=count):
                audit.verify_emitted_forest(image.bytes, forest, targets, **arguments)
                corrupted = bytearray(image.bytes)
                put(corrupted, forest['start'] + 56, jump(forest['start'] + 56, targets[len(targets)//2] + 4))
                with self.assertRaisesRegex(ValueError, 'exact function entry'):
                    audit.verify_emitted_forest(corrupted, forest, targets, **arguments)

    def test_every_node_word_mutation_is_rejected(self):
        fixture = authored_fixture()
        for node in range(3):
            for index in range(15):
                candidate = copy.deepcopy(fixture)
                at = 0x4000 + node * 60 + index * 4
                word = struct.unpack_from('<I', candidate[0], at)[0]
                put(candidate[0], at, word ^ (32 if index in (0, 1) else 1))
                with self.subTest(node=node, word=index), self.assertRaises(ValueError):
                    self.verify(candidate)

    def test_every_caller_and_failure_word_mutation_is_rejected(self):
        fixture = authored_fixture()
        for start, count in ((fixture[3]['trampoline'], 15), (fixture[1]['failure_offset'], 7)):
            for index in range(count):
                candidate = copy.deepcopy(fixture)
                at = start + 4 * index
                put(candidate[0], at, struct.unpack_from('<I', candidate[0], at)[0] ^ 1)
                with self.subTest(start=start, word=index), self.assertRaises(ValueError):
                    self.verify(candidate)

    def test_unknown_child_cycle_and_duplicate_leaf_rejected(self):
        fixture = authored_fixture()
        for at, target in ((0x4014, 0x4014), (0x4014, 0x4000), (0x4018, 0x4078),
                           (0x4038, 0x1000), (0x4074, 0x2000), (0x4014, 0)):
            candidate = copy.deepcopy(fixture)
            put(candidate[0], at, jump(at, target))
            with self.subTest(at=at, target=target), self.assertRaises(ValueError):
                self.verify(candidate)

    def test_node_key_and_target_leaf_must_both_match_derived_target(self):
        fixture = authored_fixture()
        candidate = copy.deepcopy(fixture)
        put(candidate[0], 0x4000, *address(0x4000, 0x2004, 1))
        put(candidate[0], 0x4038, jump(0x4038, 0x2004))
        with self.assertRaisesRegex(ValueError, 'derived target'):
            self.verify(candidate)

    def test_source_chain_and_helper_fixup_cannot_be_forged(self):
        fixture = authored_fixture()
        for mutation in ('source', 'helper-kind', 'helper-missing', 'helper-data', 'extra-instruction-fixup'):
            candidate = copy.deepcopy(fixture)
            if mutation == 'source': put(candidate[0], 0, jump(0, 0x4000))
            elif mutation == 'helper-kind': candidate[3]['fixups'][0]['helper'] = 2
            elif mutation == 'helper-missing': candidate[3]['fixups'] = []
            elif mutation == 'helper-data': candidate[0][candidate[3]['fixups'][0]['offset']] = 1
            else: candidate[3]['fixups'].append(dict(offset=0x4000, helper=1))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.verify(candidate)

    def test_all_geometry_and_receipt_fields_are_exact(self):
        fixture = authored_fixture()
        for key, value in fixture[1].items():
            candidate = copy.deepcopy(fixture)
            candidate[1][key] = value + 1 if type(value) is int else 'forged'
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify(candidate)
        candidate = copy.deepcopy(fixture); candidate[1]['targets'] = list(candidate[2])
        with self.assertRaises(ValueError): self.verify(candidate)

    def test_omitted_extra_duplicate_unaligned_and_reordered_targets_rejected(self):
        fixture = authored_fixture()
        for targets in ((), (0x1000, 0x2000), (0x1000, 0x2000, 0x3000, 0x4000),
                        (0x1000, 0x1000, 0x3000), (0x1000, 0x2001, 0x3000),
                        (0x3000, 0x2000, 0x1000)):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                audit.verify_emitted_forest(fixture[0], fixture[1], targets, **fixture[3])

    def test_truncated_forest_stub_and_literal_rejected(self):
        fixture = authored_fixture()
        for size in (0x4000, fixture[1]['end'] - 1, fixture[3]['trampoline'] + 56, len(fixture[0]) - 1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                audit.verify_emitted_forest(fixture[0][:size], fixture[1], fixture[2], **fixture[3])

    def test_unmatched_source_rejects_discovery_or_rewrite_claims(self):
        nso = SimpleNamespace(source_sha256=bytes(32), build_id=bytes(32))
        self.assertEqual([], audit.verify_checked_call_forests(nso, None, b'', {}, {}, [], [], [], []))
        for discovery, rewrite in (({'versioned_checked_call_forests': [{}]}, {}),
                                    ({}, {'checked_call_forests': [{}]})):
            with self.assertRaisesRegex(ValueError, 'unmatched source'):
                audit.verify_checked_call_forests(nso, None, b'', discovery, rewrite, [], [], [], [])

    def source_audit_fixture(self):
        """Mock source pins/EH/CFG only; byte inspector still reads real bytes.

        This isolated harness never invokes generate() or emits a provider.
        Real CIE/FDE semantics have their own parser tests, not a receipt mock.
        """
        import android_import
        image, forest, targets, arguments = authored_fixture()
        original = bytearray(0x4000); put(original, 0, 0xD63F0240)
        nso = SimpleNamespace(source_sha256=bytes.fromhex(audit.MAIN_SHA256),
                              build_id=bytes.fromhex(audit.MAIN_BUILD_ID), image=bytes(original))
        ranges = [(0, 4)] + [(target, target + 4) for target in targets]
        import hashlib
        pin=dict(offset=0,source_word=0xD63F0240,caller_eh_start=0x1000,caller_eh_end=0x1004,
                 caller_fde=0x1008,caller_cie=32,caller_body_sha256=hashlib.sha256(original[0x1000:0x1004]).hexdigest(),
                 evidence_start=0,evidence_end=4,evidence_sha256=hashlib.sha256(original[:4]).hexdigest(),source_role='authored-only')
        descriptor = dict(callers=[pin], rule=audit.RULE,
                          source_sha256=audit.MAIN_SHA256, build_id=audit.MAIN_BUILD_ID,
                          target_count=3, target_sha256=audit.target_digest(targets),
                          target_policy=audit.POLICY)
        discovery = dict(roots=[0, *targets], versioned_checked_call_forests=[descriptor])
        rewrite = dict(checked_call_forests=[forest])
        metadata = object()
        eh = Mock(return_value=tuple(SimpleNamespace(start=t, end=t+4, fde=t+8, cie=32) for t in targets))
        cfg = Mock(return_value=(ranges, copy.deepcopy(discovery)))
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.multiple(audit, CALL=0, CALLER_START=0x1000, CALLER_END=0x1004))
        stack.enter_context(patch.object(audit,'CALLER_PINS',(pin,)))
        stack.enter_context(patch.dict(sys.modules, {'nso_eh': SimpleNamespace(validated_eh_functions=eh)}))
        stack.enter_context(patch.object(android_import, 'discover_code', cfg))
        args = [nso, metadata, image, discovery, rewrite,
                [dict(offset=0, trampoline=arguments['trampoline'])], ranges, arguments['fixups'], []]
        return args, eh, cfg

    def test_source_contract_revalidates_all_eh_and_fresh_cfg_before_byte_authority(self):
        args, eh, cfg = self.source_audit_fixture()
        result = audit.verify_checked_call_forests(*args)
        self.assertEqual(result, args[4]['checked_call_forests'])
        eh.assert_called_once_with(args[0], args[1])
        cfg.assert_called_once_with(args[0], args[1], indirect_policy='guarded-host', checked_stack=True)

    def test_resigned_source_receipt_cannot_omit_ranges_roots_targets_or_caller_extent(self):
        args, eh, cfg = self.source_audit_fixture()
        for mutation in ('range-gap', 'forged-roots', 'target-hash', 'caller-extent', 'extra-forest',
                         'source-gate', 'no-site', 'duplicate-site', 'extra-claim', 'original-word'):
            candidate = copy.deepcopy(args)
            if mutation == 'range-gap': candidate[6] = [(0, 4), (0x1000, 0x1004)]
            elif mutation == 'forged-roots': candidate[3]['roots'].remove(0x2000)
            elif mutation == 'target-hash': candidate[3]['versioned_checked_call_forests'][0]['target_sha256'] = '0' * 64
            elif mutation == 'caller-extent': candidate[3]['versioned_checked_call_forests'][0]['callers'][0]['caller_eh_end'] += 4
            elif mutation == 'extra-forest': candidate[4]['checked_call_forests'].append(candidate[4]['checked_call_forests'][0])
            elif mutation == 'source-gate': candidate[8] = [dict(original_offset=0)]
            elif mutation == 'no-site': candidate[5] = []
            elif mutation == 'duplicate-site': candidate[5] *= 2
            elif mutation == 'extra-claim': candidate[3]['versioned_checked_call_forests'][0]['targets'] = [0x1000]
            else: candidate[0].image = bytes(len(candidate[0].image))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit.verify_checked_call_forests(*candidate)

    def test_even_matching_claimed_ranges_need_fresh_entry_coverage(self):
        args, eh, cfg = self.source_audit_fixture()
        args[6] = [(0, 4), (0x1000, 0x1004)]
        cfg.return_value = (args[6], copy.deepcopy(args[3]))
        with self.assertRaisesRegex(ValueError, 'entry lacks complete source CFG'):
            audit.verify_checked_call_forests(*args)

    def test_validated_eh_extent_must_match_exact_caller(self):
        args, eh, cfg = self.source_audit_fixture()
        eh.return_value[0].end += 4
        with self.assertRaisesRegex(ValueError, 'caller CIE/FDE extent'):
            audit.verify_checked_call_forests(*args)


if __name__ == '__main__': unittest.main()
