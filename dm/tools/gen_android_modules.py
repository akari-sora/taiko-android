#!/usr/bin/env python3
"""Build public NSOs from independent assembly and run the production importer.

The Python container writer writes real ELF64 dynamic records into NSO segments;
there is no alternate native or test-only module loading path.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from android_import import import_directory
from gen_android_fixtures import toolchain
import struct

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'dm/platform/android/module_fixtures'
NAMES = ('main', 'sdk', 'extra')


def assemble_module(name, tools):
    clang, objcopy = tools
    suffix = '.exe' if clang.suffix == '.exe' else ''
    nm = clang.parent / ('llvm-nm' + suffix)
    with tempfile.TemporaryDirectory(prefix='dm-module-asm-') as temporary:
        elf, binary = Path(temporary) / 'fixture.elf', Path(temporary) / 'fixture.bin'
        subprocess.run([str(clang), '--target=aarch64-linux-android29', '-nostdlib', '-static',
                        '-Wl,-T,' + str(FIXTURES / 'fixture.ld'), '-Wl,--build-id=none',
                        str(FIXTURES / (name + '.S')), '-o', str(elf)], check=True, capture_output=True)
        subprocess.run([str(objcopy), '-O', 'binary', '--only-section=.text', str(elf), str(binary)], check=True, capture_output=True)
        listing = subprocess.run([str(nm), '-S', '--defined-only', '--format=posix', str(elf)], check=True, capture_output=True, text=True).stdout
        symbols = {}
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[1] == 'T':
                symbols[fields[0]] = (int(fields[2], 16), int(fields[3], 16), 2)
        return binary.read_bytes(), symbols


def make_nso(name, text, functions, *, compressed=False):
    """Deterministic raw NSO with ELF64 symbols/hash/dynamic/RELA metadata."""
    ro, data = bytearray(4096), bytearray(4096)
    definitions = dict(functions)
    definitions['duplicate_value'] = (0x8180, 8, 1)
    struct.pack_into('<Q', data, 0x180, NAMES.index(name) + 1)
    imports = {'record_init': 2}
    relocs = [(0x8040, 1026, 'record_init', 0)]
    if name == 'main':
        imports.update(sdk_call=2, sdk_global=1, extra_global=1, force_override=2, record_boot=2)
        definitions['main_bss'] = (0x9000, 8, 1)
        relocs += [(0x8000, 1026, 'sdk_call', 0), (0x8008, 1025, 'sdk_global', 0),
                   (0x8010, 257, 'extra_global', 8), (0x8018, 1027, None, 0x8100),
                   (0x8020, 1026, 'force_override', 0), (0x8030, 257, 'extra_global', -8),
                   (0x8048, 1026, 'record_boot', 0)]
        struct.pack_into('<Q', data, 0x100, 13)
    elif name == 'sdk':
        imports.update(extra_call=2, record_boot=2)
        relocs += [(0x8000, 1026, 'extra_call', 0), (0x8048, 1026, 'record_boot', 0)]
        definitions.update(sdk_global=(0x8100, 8, 1), fixture_main_handle=(0x8110, 8, 1),
                           fixture_argument_area=(0x8118, 8, 1), fixture_argc=(0x8120, 8, 1), fixture_argv=(0x8128, 8, 1))
        struct.pack_into('<Q', data, 0x100, 7)
    else:
        definitions['extra_global'] = (0x8100, 16, 1)
        struct.pack_into('<QQ', data, 0x100, 3, 11)
    # Keep fixture-internal entry/init symbols local, so independently loaded
    # modules cannot interpose one another's synthetic constructor.
    records, strings, indices = [bytes(24)], bytearray(b'\0'), {}
    for symbol_name in sorted(set(definitions) | set(imports)):
        indices[symbol_name] = len(records)
        name_offset = len(strings)
        strings += symbol_name.encode() + b'\0'
        if symbol_name in definitions:
            value, size, kind = definitions[symbol_name]
            binding = 0 if symbol_name in ('fixture_entry', 'fixture_init') else 1
            record = struct.pack('<IBBHQQ', name_offset, binding * 16 + kind, 0, 1, value, size)
        else:
            record = struct.pack('<IBBHQQ', name_offset, 16 + imports[symbol_name], 0, 0, 0, 0)
        records.append(record)
    symtab = b''.join(records)
    sym_offset, str_offset = 0x4000, 0x4000 + len(symtab)
    ro[:len(symtab)] = symtab
    ro[len(symtab):len(symtab) + len(strings)] = strings
    hash_offset = (str_offset + len(strings) + 7) & -8
    # One SysV bucket containing a complete bounded chain.
    hash_words = [1, len(records), 1] + [0] + [i + 1 if i + 1 < len(records) else 0 for i in range(1, len(records))]
    hash_bytes = struct.pack(f'<{len(hash_words)}I', *hash_words)
    ro[hash_offset - 0x4000:hash_offset - 0x4000 + len(hash_bytes)] = hash_bytes
    rela_offset = (hash_offset + len(hash_bytes) + 7) & -8
    ordinary = [r for r in relocs if r[1] != 1026]
    jump = [r for r in relocs if r[1] == 1026]
    all_relas = b''.join(struct.pack('<QQq', target, ((indices[symbol] if symbol else 0) << 32) | kind, addend)
                         for target, kind, symbol, addend in ordinary + jump)
    ro[rela_offset - 0x4000:rela_offset - 0x4000 + len(all_relas)] = all_relas
    dynamic = [(5, str_offset), (10, len(strings)), (6, sym_offset), (11, 24), (4, hash_offset),
               (12, definitions['fixture_init'][0])]
    if ordinary:
        dynamic += [(7, rela_offset), (8, len(ordinary) * 24), (9, 24)]
    if jump:
        dynamic += [(23, rela_offset + len(ordinary) * 24), (2, len(jump) * 24), (20, 7)]
    dynamic += [(0, 0)]
    for index, (tag, value) in enumerate(dynamic):
        struct.pack_into('<qQ', data, 0x400 + index * 16, tag, value)
    header = bytearray(256)
    header[:4] = b'NSO0'
    struct.pack_into('<I', header, 12, 0x38 | (7 if compressed else 0))
    header[0x40:0x60] = hashlib.sha256(name.encode() + text + ro + data).digest()
    struct.pack_into('<IIII', header, 0x90, str_offset - 0x4000, len(strings), 0, len(symtab))
    parts, cursor = [], 256
    for index, (raw, memory) in enumerate(((text, 0), (bytes(ro), 0x4000), (bytes(data), 0x8000))):
        if compressed:
            import lz4.block
            stored = lz4.block.compress(raw, store_size=False)
        else:
            stored = raw
        struct.pack_into('<IIII', header, 0x10 + index * 16, cursor, memory, len(raw), 4096 if index == 2 else 0)
        struct.pack_into('<I', header, 0x60 + index * 4, len(stored))
        header[0xA0 + 32 * index:0xC0 + 32 * index] = hashlib.sha256(raw).digest()
        parts.append(stored)
        cursor += len(stored)
    return bytes(header) + b''.join(parts)


def generate(tools):
    sources = {name: make_nso(name, *assemble_module(name, tools), compressed=name == 'sdk') for name in NAMES}
    with tempfile.TemporaryDirectory(prefix='dm-module-import-') as temporary:
        source_dir, output = Path(temporary) / 'exefs', Path(temporary) / 'prepared'
        source_dir.mkdir()
        for name, source in sources.items():
            (source_dir / name).write_bytes(source)
        report = import_directory(source_dir, output, NAMES)
        lines = ['// Generated by dm/tools/gen_android_modules.py; do not hand edit.',
                 '// Self-authored NSO0 inputs use the production android_import.py path.',
                 '#pragma once', '#include <stddef.h>', '#include <stdint.h>', '']
        for name in NAMES:
            package = (output / (name + '.dmag')).read_bytes()
            prefix = 'dm_module_' + name
            lines.append(f'alignas(8) static const uint8_t {prefix}_bytes[] = {{')
            for offset in range(0, len(package), 24):
                lines.append('    ' + ','.join(f'0x{x:02x}' for x in package[offset:offset + 24]) + ',')
            lines += ['};', f'static constexpr size_t {prefix}_size = sizeof({prefix}_bytes);', '']
            digest = hashlib.sha256(package).digest()
            lines += [f'static const uint8_t {prefix}_package_sha256[32] = {{',
                      '    ' + ','.join(f'0x{x:02x}' for x in digest) + ',', '};', '']
        files = {'generated_modules.h': '\n'.join(lines).encode(),
                 'import.json': (json.dumps(report, indent=2) + '\n').encode()}
        files.update({name + '.nso': source for name, source in sources.items()})
        files.update({name + '.dmag': (output / (name + '.dmag')).read_bytes() for name in NAMES})
        return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    generated = generate(toolchain(args.ndk))
    for name, content in generated.items():
        target = FIXTURES / name
        if args.check:
            if not target.is_file() or target.read_bytes() != content:
                raise SystemExit(f'{target} differs; run gen_android_modules.py')
        else:
            target.write_bytes(content)
    print(f'{"Verified" if args.check else "Generated"} three independently assembled NSOs through production importer ({len(generated)} artifacts); game boot NOT_RUN')


if __name__ == '__main__':
    main()
