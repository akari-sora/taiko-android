"""Exact retail fatal-word preservation; unknown words never gain admission."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / 'dm/tools'))
import android_import as ai
import android_rewrite as ar
from nso_format import parse_nso, parse_metadata
from test_nso_format import mutable_source, write_image
from test_android_observation import profile
import android_profiles as profiles

FATAL = 0xE7FFDEFE
RET = 0xD65F03C0


def raw(*words):
    return struct.pack('<' + 'I' * len(words), *words)


class FatalWordTests(unittest.TestCase):
    def source(self):
        source = mutable_source()
        symbol = next(s for s in parse_metadata(parse_nso(source)).symbols if s.name == 'fixture_main')
        entry = symbol.value
        words = [FATAL, RET] + [0xD503201F] * (symbol.size // 4 - 2)
        write_image(source, entry, '<' + 'I' * len(words), *words)
        return source, entry

    def test_raw_fatal_bytes_are_preserved_without_gates_or_rewrite_sites(self):
        source = raw(FATAL, RET)
        image = ar.rewrite(source)
        self.assertEqual(image.bytes, source)
        self.assertEqual((image.gates, image.sites, image.fixups), ((), (), ()))

    def test_import_records_selected_terminal_and_preserves_original_bytes(self):
        source, entry = self.source()
        package, report = ai.import_module(source, 'main', package_version=2)
        discovery = report['code_discovery']
        self.assertEqual(discovery['preserved_fatal_words'], [{'offset': entry, 'word': FATAL}])
        self.assertFalse(any(site['offset'] == entry for site in report['rewrite']['sites']))
        payload = struct.unpack_from('<Q', package, 112)[0]
        self.assertEqual(package[payload + entry:payload + entry + 4], raw(FATAL))

    def test_fatal_has_no_fallthrough_to_hidden_sensitive_word(self):
        source, entry = self.source()
        write_image(source, entry + 4, '<I', 0xD4000001)  # Unrooted SVC after fatal.
        with self.assertRaisesRegex(ai.ImportError, 'uncovered rewrite candidate'):
            ai.import_module(source, 'main')

    def test_unselected_exact_word_is_classified_without_granting_a_root(self):
        source = mutable_source()
        write_image(source, 0x300, '<I', FATAL)
        _, report = ai.import_module(source, 'main', package_version=2, callback_audit=True)
        self.assertNotIn(0x300, report['code_discovery']['roots'])
        self.assertNotIn(0x300, report['callback_audit']['callback_roots'])
        self.assertEqual(report['code_discovery']['preserved_fatal_words'], [])

    def test_arbitrary_unknowns_remain_rejected_selected_or_unselected(self):
        for value in (0xE7FFDEFF, 0xFFFFFFFF, 0x00000201):
            with self.subTest(value=hex(value)), self.assertRaises(ar.RewriteError):
                ar.rewrite(raw(value, RET))
        source = mutable_source()
        write_image(source, 0x300, '<I', 0xE7FFDEFF)
        with self.assertRaisesRegex(ai.ImportError, 'unclassified nonzero text word'):
            ai.import_module(source, 'main')

    def test_exact_udf_zero_is_preserved_after_a_returning_call_and_stops_flow(self):
        self.assertEqual(ar.rewrite(raw(0,RET)).bytes,raw(0,RET))
        source,entry=self.source()
        write_image(source,entry,'<4I',0x94000003,0,RET,RET)
        package,report=ai.import_module(source,'main',package_version=2,callback_audit=True)
        self.assertIn({'offset':entry+4,'word':0},report['code_discovery']['preserved_fatal_words'])
        payload=struct.unpack_from('<Q',package,112)[0]
        self.assertEqual(package[payload+entry+4:payload+entry+8],bytes(4))
        self.assertNotIn(entry+4,report['callback_audit']['callback_roots'])
        write_image(source,entry+8,'<I',0xD4000001)
        with self.assertRaisesRegex(ai.ImportError,'uncovered rewrite candidate'):
            ai.import_module(source,'main',package_version=2)

    def test_zero_padding_has_no_root_and_udf_cannot_move_into_rewrite_windows(self):
        source=mutable_source();write_image(source,0x300,'<I',0)
        _,report=ai.import_module(source,'main',package_version=2,callback_audit=True)
        self.assertNotIn(0x300,report['code_discovery']['roots'])
        self.assertNotIn(0x300,report['callback_audit']['callback_roots'])
        self.assertNotIn({'offset':0x300,'word':0},report['code_discovery'].get('preserved_fatal_words',[]))
        with self.assertRaisesRegex(ar.RewriteError,'fatal.*exclusive'):
            ar.rewrite(raw(0xC85F7C20,0,0xD5033F5F,RET))
        with self.assertRaisesRegex(ar.RewriteError,'fatal|unsupported observation'):
            ar.rewrite(raw(0,RET),profile=profile(observations=(profiles.Observation(0,1,0),)))

    def test_fatal_is_rejected_inside_exclusive_reservation(self):
        with self.assertRaisesRegex(ar.RewriteError, 'fatal.*exclusive'):
            ar.rewrite(raw(0xC85F7C20, FATAL, 0xD5033F5F, RET))

    def test_fatal_cannot_be_displaced_by_observation_or_parameter_window(self):
        with self.assertRaisesRegex(ar.RewriteError, 'fatal|unsupported observation'):
            ar.rewrite(raw(FATAL, RET), profile=profile(observations=(profiles.Observation(0, 1, FATAL),)))
        a, b = 0xD2800028, 0xF2A00088
        p = profile(parameters=(profiles.Parameter(0, 8, a, b, 8, 0, 0),))
        with self.assertRaisesRegex(ar.RewriteError, 'fatal|hazard'):
            ar.rewrite(raw(a, FATAL, b, RET), profile=p)

    def test_brk_immediates_preserve_bytes_and_terminal_import_semantics(self):
        for immediate in (0, 42, 65535):
            value = 0xD4200000 | immediate << 5
            with self.subTest(immediate=immediate):
                self.assertEqual(ar.rewrite(raw(value, RET)).bytes, raw(value, RET))
                source, entry = self.source()
                write_image(source, entry, '<I', value)
                package, report = ai.import_module(source, 'main', package_version=2)
                self.assertEqual(report['code_discovery']['preserved_fatal_words'], [{'offset': entry, 'word': value}])
                payload = struct.unpack_from('<Q', package, 112)[0]
                self.assertEqual(package[payload + entry:payload + entry + 4], raw(value))
                write_image(source, entry + 4, '<I', 0xD4000001)
                with self.assertRaisesRegex(ai.ImportError, 'uncovered rewrite candidate'):
                    ai.import_module(source, 'main')

    def test_brk_cannot_be_displaced_into_exclusive_or_observation_window(self):
        value = 0xD4200540
        with self.assertRaisesRegex(ar.RewriteError, 'exclusive'):
            ar.rewrite(raw(0xC85F7C20, value, 0xD5033F5F, RET))
        with self.assertRaisesRegex(ar.RewriteError, 'unsupported observation'):
            ar.rewrite(raw(value, RET), profile=profile(observations=(profiles.Observation(0, 1, value),)))

    def test_other_exception_terminal_instructions_remain_unsupported(self):
        for value in (0xD4400000, 0xD69F03E0, 0xD6BF03E0):  # HLT, ERET, DRPS.
            source, entry = self.source()
            write_image(source, entry, '<I', value)
            with self.subTest(value=hex(value)), self.assertRaisesRegex(ai.ImportError, 'unsupported terminal instruction'):
                ai.import_module(source, 'main')


if __name__ == '__main__':
    unittest.main()
