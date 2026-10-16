"""Three finite native u16 schedules; source effects remain native and in place."""
import struct
import unittest
from test_android_native_lr_table_base import ar, adr, adrp
from test_android_guarded_native_table import fixture as legacy_fixture, classify as legacy_classify
from test_android_runtime_ro_sub_inline import write_image
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ
from unicorn import arm64_const as uc

TABLE = 0x6200


def fixture(kind, bound=None):
    raw = bytearray(0x7000); start = 0x100
    if kind == 'sp-store-add':
        bound = 68 if bound is None else bound
        target, loaded, table, index = 8, 9, 10, 1
        load, branch = 0x120, 0x12C; base = branch + 4
        words = [0xB8746AA1, 0x7100003F | bound << 10, 0xF900BFE1, 0xB90177E9,
                 0x54000008 | (((0x1800 - 0x110) // 4) << 5), adrp(0x114, TABLE, table),
                 0x9100014A | (TABLE & 4095) << 10, adr(0x11C, base, target), 0x78617949,
                 0x8B090908, 0x9100129B, 0xD61F0100]
    elif kind == 'add-zero':
        bound = 220 if bound is None else bound
        target, loaded, table, index = 11, 12, 10, 9
        load, branch = 0x118, 0x124; base = branch + 4
        words = [0x0B080349, 0x7100013F | bound << 10,
                 0x54000008 | (((0x1800 - 0x108) // 4) << 5), adrp(0x10C, TABLE, table),
                 0x9100014A | (TABLE & 4095) << 10, adr(0x114, base, target),
                 0x7869794C, 0x8B0C096B, 0x2A1F03E8, 0xD61F0160]
    elif kind == 'backward-read':
        bound = 131 if bound is None else bound
        target, loaded, table, index = 8, 10, 11, 9
        load, branch, base = 0x118, 0x120, 0x80
        words = [0xB9400369, 0x7100013F | bound << 10,
                 0x54000008 | (((0x1800 - 0x108) // 4) << 5), adrp(0x10C, TABLE, table),
                 0x9100016B | (TABLE & 4095) << 10, adr(0x114, base, target),
                 0x7869796A, 0x8B0A0908, 0xD61F0100]
    else: raise AssertionError(kind)
    struct.pack_into('<' + str(len(words)) + 'I', raw, start, *words)
    tags = tuple((0, 80, 100, 120, 140)[i % 5] for i in range(bound + 1))
    struct.pack_into('<' + str(len(tags)) + 'H', raw, TABLE, *tags)
    targets = {base + v * 4 for v in tags}
    ranges = [(start, branch + 4), (0x1800, 0x1804)]
    for pc in targets | {0x1800}: struct.pack_into('<I', raw, pc, 0xD65F03C0)
    ranges += [(pc, pc + 4) for pc in sorted(targets)]
    return bytes(raw), sorted(ranges), dict(kind=kind, start=start, load=load, branch=branch, base=base,
                                   target=target, loaded=loaded, table=table, index=index,
                                   bound=bound, targets=targets)


def classify(raw, ranges, info, entries=(), readonly=((0x6000, 0x7000),)):
    by = {pc: ar.Instruction(ar.decode(struct.unpack_from('<I', raw, pc)[0], pc))
          for a, b in ranges for pc in range(a, b, 4)}
    return ar._guarded_native_readonly_table(by[info['branch']], by, set(entries), raw, readonly)


def rewrite(raw, ranges, info, **options):
    return ar.rewrite(raw, entry_offset=info['start'], text_size=0x3000, code_ranges=ranges,
                      checked_stack=True, package_version=2, readonly_ranges=((0x6000, 0x7000),),
                      proven_guest_indirect_offsets=(info['branch'],), **options)


class NativeUnsignedWideSchedulesTests(unittest.TestCase):
    def execute(self, kind, index, *, original=False, bad=None, entry=None):
        return self.execute_fixture(*fixture(kind), index, original=original, bad=bad, entry=entry)

    def execute_fixture(self, raw, ranges, info, index, *, original=False, bad=None, entry=None):
        kind = info['kind']; image = None if original else rewrite(raw, ranges, info)
        base, stack, payload = 0x10000000, 0x20008000, 0x30000000
        cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM); cpu.mem_map(base, 0x20000)
        cpu.mem_map(0x20000000, 0x10000); cpu.mem_map(payload, 0x10000)
        cpu.mem_write(base, raw if original else image.bytes); cpu.mem_write(payload, struct.pack('<I', index & 0xFFFFFFFF)); cpu.mem_write(payload + 0x30, struct.pack('<Q', payload))
        if image: self.assertEqual((), image.fixups)
        regs = [0x1234000000000000 + i * 0x101 for i in range(31)]
        regs[8], regs[20], regs[21], regs[26], regs[27], regs[29] = 0, 0, payload, index, payload, stack + 0x80
        regs[info['index']], regs[info['table']], regs[info['target']] = index, base + TABLE, base + info['base']
        if kind == 'add-zero': regs[8] = 0
        if kind == 'fp-loaded': regs[info['index']] = index + (1 if entry is None else 0)
        if kind == 'str-guard': regs[20] = payload; regs[10] = payload
        if kind == 'local-store': regs[20] = payload; regs[10] = index << 4
        if bad == 'table': regs[info['table']] = 0
        elif bad == 'base': regs[info['target']] += 4
        for r, value in enumerate(regs): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_X{r}'), value)
        for r in range(32): cpu.reg_write(getattr(uc, f'UC_ARM64_REG_Q{r}'), (r + 1) * 0x102030405060708090A0B0C0D0E0F)
        cpu.reg_write(uc.UC_ARM64_REG_SP, stack); cpu.reg_write(uc.UC_ARM64_REG_NZCV, 0xB0000000)
        cpu.mem_write(stack, bytes(range(256)) * 3)
        result = dict(reached=None, trapped=False, reads=0)
        def snapshot():
            return ([cpu.reg_read(getattr(uc, f'UC_ARM64_REG_X{r}')) for r in range(31)],
                    [cpu.reg_read(getattr(uc, f'UC_ARM64_REG_Q{r}')) for r in range(32)],
                    cpu.reg_read(uc.UC_ARM64_REG_SP), cpu.reg_read(uc.UC_ARM64_REG_NZCV))
        def code(machine, pc, size, _):
            self.assertFalse(ar.has18(ar.decode(struct.unpack('<I', machine.mem_read(pc, 4))[0], pc)))
            if pc - base in info['targets']: result['reached'] = pc - base; machine.emu_stop()
        def read(machine, access, address, size, value, _):
            if base + TABLE <= address < base + TABLE + 2 * (info['bound'] + 1): result['reads'] += 1
        def trap(machine, number, _): result['trapped'] = True; machine.emu_stop()
        cpu.hook_add(UC_HOOK_CODE, code); cpu.hook_add(UC_HOOK_MEM_READ, read); cpu.hook_add(UC_HOOK_INTR, trap)
        result['initial'] = snapshot(); result['initial_memory'] = bytes(cpu.mem_read(stack, 768)); result['initial_payload'] = bytes(cpu.mem_read(payload, 0x400))
        cpu.emu_start(base + (info['start'] if entry is None else info['load']), base + 0x20000, count=1000)
        result.update(final=snapshot(), memory=bytes(cpu.mem_read(stack, 768)), payload=bytes(cpu.mem_read(payload, 0x400)))
        return result

    def test_all_422_indices_match_original_register_flags_vector_stack_and_lr_effects(self):
        for kind, bound in (('sp-store-add', 68), ('add-zero', 220), ('backward-read', 131)):
            for index in range(bound + 1):
                with self.subTest(kind=kind, index=index):
                    original = self.execute(kind, index, original=True); rewritten = self.execute(kind, index)
                    self.assertEqual((False, original['reached'], 1), (rewritten['trapped'], rewritten['reached'], rewritten['reads']))
                    self.assertEqual((original['final'], original['memory'], original['payload']), (rewritten['final'], rewritten['memory'], rewritten['payload']))

    def test_invalid_live_base_table_full64_index_traps_before_any_read_with_all_state_intact(self):
        for kind in ('sp-store-add', 'add-zero', 'backward-read'):
            _, _, info = fixture(kind)
            for index, bad in ((0, 'table'), (0, 'base'), (info['bound'] + 1, None), (1 << 32, None), (2**64 - 1, None)):
                result = self.execute(kind, index, entry='load', bad=bad)
                self.assertEqual((True, None, 0), (result['trapped'], result['reached'], result['reads']))
                self.assertEqual((result['initial'], result['initial_memory'], result['initial_payload']), (result['final'], result['memory'], result['payload']))

    def test_exact_schedules_complete_ro_postload_and_cap_requirements(self):
        for kind in ('sp-store-add', 'add-zero', 'backward-read'):
            raw, ranges, info = fixture(kind); self.assertIsNotNone(classify(raw, ranges, info))
            image = rewrite(raw, ranges, info)
            for pc in range(info['start'], info['branch'] + 4, 4):
                if pc != info['load']: self.assertEqual(raw[pc:pc + 4], image.bytes[pc:pc + 4])
            for pc in range(info['load'] + 4, info['branch'] + 4, 4):
                self.assertIsNone(classify(raw, ranges, info, entries=(pc,)))
            self.assertIsNone(classify(raw, ranges, info, readonly=((TABLE, TABLE + info['bound'] * 2),)))
            changed, domain, details = fixture(kind, 256); self.assertIsNone(classify(changed, domain, details))
            for at, word in ((info['start'], 0xB940001F), (info['load'] - 12, 0xD503201F),
                             (info['load'] + 4, 0x8B000800 | (info['index'] << 16) | (info['target'] << 5) | info['target'])):
                data = bytearray(raw); struct.pack_into('<I', data, at, word)
                self.assertIsNone(classify(data, ranges, info))
        raw, ranges, info = fixture('sp-store-add')
        for pc, word in ((0x108, 0xF80087E1), (0x10C, 0xB90177E1), (0x110, 0x54000000), (0x128, 0xB100129B)):
            changed = bytearray(raw); struct.pack_into('<I', changed, pc, word); self.assertIsNone(classify(changed, ranges, info))
        raw, ranges, info = fixture('add-zero')
        for word in (0x2A1F03E9, 0x2A1F03EB, 0x3100052B, 0xD503201F):
            changed = bytearray(raw); struct.pack_into('<I', changed, 0x120, word); self.assertIsNone(classify(changed, ranges, info))
        source, branch = legacy_fixture(); write_image(source, 0x3C0, '<I', 0x7101013F)
        self.assertIsNone(legacy_classify(source, branch))


if __name__ == '__main__': unittest.main()
