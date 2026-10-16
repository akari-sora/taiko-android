"""A read-only WFE poll keeps its monitor until the checked return path."""
import unittest

from test_android_runtime_ro_sub_inline import ar, parse_nso, source_base, write_image


BEGIN = 0x388
LOAD = BEGIN + 8
EXIT_GATE = BEGIN + 40
WORDS = (0xD50320BF, 0xD503205F, 0x885FFE69, 0x72003D3F,
         0x54FFFFA1, 0x53107D29, 0x6B29011F, 0x54FFFF41,
         0xA9427BFD, 0xA9414FF4, 0xF84307F5, 0xD65F03C0)


def fixture():
    source = source_base()
    write_image(source, 0x300, '<I', ar.branch(0x300, BEGIN))
    write_image(source, BEGIN, '<12I', *WORDS)
    return source


def rewrite(source, **changes):
    nso = parse_nso(source)
    options = dict(entry_offset=0x300, text_size=nso.sections[0].size,
                   code_ranges=((0x300, 0x304), (BEGIN, BEGIN + 48)),
                   package_version=2, checked_stack=True)
    return ar.rewrite(nso.image, **(options | changes)), nso


class NativeReadWaitCheckedReturnTests(unittest.TestCase):
    def test_poll_is_native_and_return_keeps_the_checked_sp_gate(self):
        image, nso = rewrite(fixture())
        self.assertEqual(image.bytes[BEGIN:EXIT_GATE], nso.image[BEGIN:EXIT_GATE])
        self.assertEqual([site.offset for site in image.sites], [EXIT_GATE])
        self.assertEqual([gate.kind for gate in image.gates], [ar.STACK_CHECK])
        self.assertEqual(image.bytes[LOAD:LOAD + 4], nso.image[LOAD:LOAD + 4])

    def test_changed_wait_retry_exit_and_skipped_producer_are_refused(self):
        for at, word in ((BEGIN, 0xD503201F), (BEGIN + 4, 0xD503201F),
                         (LOAD + 8, 0x54FFFF81), (LOAD + 20, 0x54FFFF21),
                         (EXIT_GATE - 4, 0xA9414FF3),
                         (EXIT_GATE, 0xD503201F)):
            source = fixture()
            write_image(source, at, '<I', word)
            with self.subTest(at=hex(at)), self.assertRaises(ar.RewriteError):
                rewrite(source)
        for entry in (BEGIN + 4, LOAD, LOAD + 4, LOAD + 20):
            with self.subTest(entry=hex(entry)), self.assertRaises(ar.RewriteError):
                rewrite(fixture(), entry_offsets=(entry,))
        with self.assertRaises(ar.RewriteError):
            rewrite(fixture(), checked_stack=False)


if __name__ == '__main__':
    unittest.main()
