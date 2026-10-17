"""Independently authored W32 five-peer program and fixed address oracles.

The two leading RETs, peer ordering, role tables and fixed coordinates were
chosen for this suite. No commercial image is an input. C and W below are
specified from the source listing, never inferred from a recognizer result.
"""
from functools import lru_cache
import struct

from test_android_exclusive import assemble
from test_android_rewrite import ar


BODY = """ret
ret
acquire0: ldaxr w9, [x20]
cmp w9, w10
b.ne mismatch
stlxr w11, w8, [x20]
cbnz w11, acquire0
b stored
plain: ldxr w9, [x20]
cmp w9, w10
b.ne mismatch
stxr w11, w8, [x20]
cbnz w11, plain
b stored
acquire1: ldaxr w9, [x20]
cmp w9, w10
b.ne mismatch
stlxr w11, w8, [x20]
cbnz w11, acquire1
b stored
release: ldxr w9, [x20]
cmp w9, w10
b.ne mismatch
stlxr w11, w8, [x20]
cbnz w11, release
b stored
acquire2: ldaxr w9, [x20]
cmp w9, w10
b.ne mismatch
stlxr w11, w8, [x20]
cbnz w11, acquire2
stored: mov w8, #1
tbnz w8, #0, yes
b publish
mismatch: mov w8, wzr
clrex
tbnz w8, #0, yes
publish: mov w0, wzr
str w9, [x19]
ldp x20, x19, [sp, #0x20]
ldp x22, x21, [sp, #0x10]
ldp x30, x23, [sp], #0x30
ret
yes: mov w0, #1
ldp x20, x19, [sp, #0x20]
ldp x22, x21, [sp, #0x10]
ldp x30, x23, [sp], #0x30
ret
alien: ret
ret
"""

HEADS = frozenset((8, 32, 56, 80, 104))
SUCCESS, SUCCESS_TEST, DEAD_B = 124, 128, 132
FAILURE, CLREX, FAILURE_TEST = 136, 140, 144
PUBLISH, STR, LEAVE, ALIEN = 148, 152, 172, 192
CLOSURE = frozenset((
    8, 12, 16, 20, 24,
    32, 36, 40, 44, 48,
    56, 60, 64, 68, 72,
    80, 84, 88, 92, 96,
    104, 108, 112, 116, 120,
    136, 140,
))
WITNESS_ROLES = {
    28: 'acquire0 success branch', 52: 'plain success branch',
    76: 'acquire1 success branch', 100: 'release success branch',
    124: 'stored carrier one', 128: 'stored carrier test',
    132: 'dead stored-to-publish branch', 144: 'mismatch carrier test',
    148: 'mismatch result zero', 152: 'loaded-word publication',
    156: 'mismatch cell/output restore', 160: 'mismatch x22/x21 restore',
    164: 'mismatch LR/x23 restore and SP increment', 168: 'mismatch RET',
    172: 'success result one', 176: 'success cell/output restore',
    180: 'success x22/x21 restore', 184: 'success LR/x23 restore and SP increment',
    188: 'success RET',
}
WITNESS = frozenset(WITNESS_ROLES)
RESTORES = frozenset((156, 160, 164, 176, 180, 184))
FAMILY = (('ldaxr', 'stlxr'), ('ldxr', 'stxr'), ('ldaxr', 'stlxr'),
          ('ldxr', 'stlxr'), ('ldaxr', 'stlxr'))


@lru_cache(maxsize=None)
def fixture(body=BODY):
    return assemble(body)


def decoded(source=None, base=0):
    source = fixture() if source is None else source
    instructions = tuple(ar.Instruction(ins) for ins in ar.MD.disasm(source, base))
    if len(instructions) * 4 != len(source):
        raise AssertionError('self-authored source did not completely decode')
    return instructions, {ins.address: None for ins in instructions}


def plan(source=None, *, entries=(), kinds=None):
    instructions, defaults = decoded(source)
    return ar.android_exclusive.plan_regions(
        instructions, defaults if kinds is None else kinds, entries, ar)


def word(pc, source=None):
    return struct.unpack_from('<I', fixture() if source is None else source, pc)[0]


def changed(changes, source=None):
    result = bytearray(fixture() if source is None else source)
    for pc, value in changes.items():
        struct.pack_into('<I', result, pc, value)
    return bytes(result)


def branch(name, pc, target, register=11):
    """Encode only architecturally representable signed, aligned targets."""
    delta = target - pc
    assert delta % 4 == 0
    bits = {'b': 26, 'bl': 26, 'b.ne': 19, 'cbnz': 19, 'tbnz': 14}[name]
    assert -(1 << (bits + 1)) <= delta <= (1 << (bits + 1)) - 4
    displacement = ((delta // 4) & ((1 << bits) - 1))
    if name in ('b', 'bl'):
        return (0x94000000 if name == 'bl' else 0x14000000) | displacement
    prefix = {'b.ne': 0x54000001, 'cbnz': 0x35000000, 'tbnz': 0x37000000}[name]
    return prefix | (displacement << 5) | (register if name != 'b.ne' else 0)


def helper(test):
    result = getattr(ar.android_exclusive, 'native_five_peer_word_closure', None)
    test.assertIsNotNone(result, 'native_five_peer_word_closure must be implemented')
    test.assertTrue(callable(result))
    return result


def selected(test, source=None, base=0):
    instructions, kinds = decoded(source, base)
    by_pc = {ins.address: ins for ins in instructions}
    return helper(test)(by_pc[8 + base], by_pc, kinds, ar)


def acceptance(source=None, **kwargs):
    """Public planner acceptance as data, so a missing feature is a test FAIL."""
    try:
        regions = plan(source, **kwargs)
    except ar.RewriteError as error:
        return False, str(error)
    return regions == (), repr(regions)
