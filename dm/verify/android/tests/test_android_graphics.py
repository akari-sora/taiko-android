"""Compiled graphics guest contracts through the production guarded importer.

These establish package/code authority, not GPU or native callback execution.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as importer
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64_const import ARM64_OP_IMM, ARM64_OP_REG
from nso_format import parse_nso, parse_metadata

FIXTURES = ROOT / 'dm/platform/android/graphics_fixtures'

class GraphicsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (FIXTURES/'graphics.nso').read_bytes()
        cls.nso = parse_nso(cls.source)
        cls.metadata = parse_metadata(cls.nso)
        cls.symbols = {s.name: s for s in cls.metadata.symbols}
        cls.package, cls.report = importer.import_module(cls.source, 'sdk', package_version=2,
                                                        indirect_policy='guarded-host', callback_audit=True)

    def test_guarded_factory_calls_cannot_use_legacy_or_implicit_policy(self):
        for options in ({}, {'package_version': 2}):
            with self.assertRaisesRegex(importer.ImportError, 'unproven indirect'):
                importer.import_module(self.source, 'sdk', **options)
        self.assertEqual(self.package, (FIXTURES/'graphics.dmag').read_bytes())
        self.assertEqual(json.loads(json.dumps(self.report)), json.loads((FIXTURES/'import.json').read_text()))
        self.assertEqual(self.package[:8], b'DMAMOD02')
        self.assertEqual(self.package[320:356], bytes(36))
        self.assertEqual(self.report['game_boot_status'], 'NOT_RUN')
        self.assertFalse(self.report['unsupported'])

    def test_each_guarded_site_matches_actual_compiled_indirect_instruction(self):
        discovery = self.report['code_discovery']
        gates = {g['return_offset']: g for g in self.report['rewrite']['gates']}
        guards = {g['original_offset']: {**g, **gates[g['return_offset']]} for g in
                  self.report['rewrite']['gate_provenance'] if gates[g['return_offset']]['kind'] == 4}
        self.assertGreater(len(guards), 100)
        self.assertEqual(set(guards), set(discovery['guarded_indirect_sites']))
        self.assertEqual(discovery['rejected_indirect_sites'], [])
        self.assertFalse(discovery['rewrite_candidate_audit']['uncovered_candidates'])
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        for address, guard in guards.items():
            word = struct.unpack_from('<I', self.nso.image, address)[0]
            instruction = next(md.disasm(self.nso.image[address:address+4], address))
            self.assertIn(instruction.mnemonic, ('br', 'blr'))
            self.assertEqual(guard['original_word'], word)
            self.assertEqual(instruction.op_str, 'x' + str(guard['argument']))
            self.assertEqual(guard['flags'], 0)

    def test_callback_is_a_normal_discovered_function_and_results_start_empty(self):
        callback = self.symbols['command_memory']
        self.assertEqual(callback.kind, 2)
        self.assertIn(callback.value, self.report['code_discovery']['address_taken_roots'])
        self.assertIn(callback.value, self.report['code_discovery']['roots'])
        audit = self.report['callback_audit']
        self.assertEqual(audit['callback_audit_version'], 1)
        self.assertEqual(audit['callback_root_kind'], 'defined-stt-func')
        self.assertEqual(audit['package_sha256'], hashlib.sha256(self.package).hexdigest())
        self.assertEqual(audit['source_sha256'], hashlib.sha256(self.source).hexdigest())
        expected = sorted({s.value for s in self.metadata.symbols
                           if s.kind == 2 and s.section not in (0, 0xfff1)})
        self.assertEqual(audit['callback_roots'], expected)
        header = (FIXTURES/'generated_graphics.h').read_text()
        self.assertIn('dm_graphics_callback_roots[]={'+','.join(str(x) for x in expected)+'};', header)
        record = self.symbols['graphics_result']
        self.assertEqual(record.size, 36 * 8)
        self.assertEqual(self.nso.image[record.value:record.value+record.size], bytes(record.size))
        self.assertEqual(self.metadata.init_addresses, (self.symbols['fixture_init'].value,))
        competing = {'nvnBootstrapLoader', '_ZN2nn2oe16GetOperationModeEv'}
        self.assertEqual({self.metadata.symbols[r.symbol].name for r in self.metadata.relocations}, competing)
        for name in competing:
            self.assertNotEqual(self.symbols[name].section, 0)

    def test_canonical_observation_main_is_not_regenerated(self):
        for path, digest in {
            'main.nso': '7c6d0e794b729082ec469823740d47c0a93469a3b68a32acb07b6401c3f23ff9',
            'main.dmag': 'db5fc825c18a5abddcd0bb8ab3dbe5aa8e83af8087b78930591a7d1925e98e42',
            'generated_catalog.inc': '0681d18eba62fe0360e4325aaf9eb8b03aa2c4bb45b8e226d173b7dce8a7f2de',
        }.items():
            self.assertEqual(hashlib.sha256((FIXTURES.parent/'observation_fixtures'/path).read_bytes()).hexdigest(), digest)

    def instructions(self, name):
        symbol = self.symbols[name]
        disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        disassembler.detail = True
        return list(disassembler.disasm(self.nso.image[symbol.value:symbol.value+symbol.size], symbol.value))

    def literal_nvn_names(self, name):
        # Read compiled ADRP/ADD literal references, so a changed guest call is
        # checked independently from the C source text and generator metadata.
        registers, names = {}, set()
        for instruction in self.instructions(name):
            operands = instruction.operands
            if instruction.mnemonic == 'adrp' and len(operands) == 2:
                registers[instruction.reg_name(operands[0].reg)] = operands[1].imm
            elif instruction.mnemonic == 'add' and len(operands) == 3 and operands[2].type == ARM64_OP_IMM:
                source = registers.get(instruction.reg_name(operands[1].reg))
                destination = instruction.reg_name(operands[0].reg)
                if source is not None:
                    address = source + operands[2].imm
                    registers[destination] = address
                    if 0 <= address < len(self.nso.image):
                        raw = self.nso.image[address:address+128].split(b'\0', 1)[0]
                        if raw.startswith(b'nvn'):
                            names.add(raw.decode('ascii'))
                else:
                    registers.pop(destination, None)
            elif instruction.mnemonic == 'mov' and len(operands) == 2 and operands[1].type == ARM64_OP_REG:
                destination, source = (instruction.reg_name(operand.reg) for operand in operands)
                if source in registers:
                    registers[destination] = registers[source]
                else:
                    registers.pop(destination, None)
            if instruction.mnemonic in ('bl', 'blr'):
                for register in range(19):
                    registers.pop('x' + str(register), None)
        return names

    def test_actual_heap_svc_and_extended_wire_exports_are_compiled(self):
        self.assertEqual([(i.mnemonic, i.op_str) for i in self.instructions('graphics_heap_allocate')], [
            ('mov', 'x0, #0'), ('mov', 'x1, #0x200000'), ('svc', '#1'),
            ('cmp', 'x0, #0'), ('csel', 'x0, x1, xzr, eq'), ('ret', '')])
        self.assertTrue(any(gate['kind'] == 1 and gate['argument'] == 1 for gate in self.report['rewrite']['gates']))
        record = self.symbols['graphics_extended_result']
        self.assertEqual(record.size, 13 * 8)
        self.assertEqual(self.nso.image[record.value:record.value+record.size], bytes(record.size))
        for name in ('graphics_extended_first', 'graphics_extended_next', 'graphics_extended_wait'):
            self.assertEqual(self.symbols[name].kind, 2)
            self.assertIn(self.symbols[name].value, self.report['callback_audit']['callback_roots'])

    def test_dependent_submit_entries_have_no_intervening_guest_wait(self):
        first = self.literal_nvn_names('graphics_extended_first')
        following = self.literal_nvn_names('graphics_extended_next')
        for names in (first, following):
            self.assertNotIn('nvnSyncWait', names)
            self.assertIn('nvnCommandBufferBeginRecording', names)
        self.assertIn('nvnCommandBufferCopyBufferToBuffer', first)
        self.assertIn('nvnCommandBufferUpdateUniformBuffer', first)
        self.assertIn('nvnCommandBufferCopyBufferToTexture', first)
        self.assertIn('nvnCommandBufferDispatchCompute', first)
        self.assertIn('nvnCommandBufferCopyTextureToBuffer', following)
        self.assertIn('nvnSyncWait', self.literal_nvn_names('graphics_extended_wait'))

if __name__ == '__main__':
    unittest.main()
