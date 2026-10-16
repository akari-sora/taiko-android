#!/usr/bin/env python3
"""Build an additional public class0 controller SDK NSO using the production importer.

The existing canonical observation main/catalog are inputs to the runtime test,
never outputs of this generator. No game identity or profile is introduced.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from android_import import import_module
from gen_android_fixtures import toolchain

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'dm/platform/android/controller_fixtures'
IMPORTS = (
    '_ZN2nn3hid14InitializeNpadEv',
    '_ZN2nn3hid22SetSupportedNpadIdTypeEPKjm',
    '_ZN2nn3hid24SetSupportedNpadStyleSetENS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE',
    '_ZN2nn3hid29SetNpadHandheldActivationModeENS0_26NpadHandheldActivationModeE',
    '_ZN2nn3hid15GetNpadStyleSetERKj',
    '_ZN2nn3hid12GetNpadStateEPNS0_16NpadFullKeyStateERKj',
    '_ZN2nn3hid12GetNpadStateEPNS0_17NpadHandheldStateERKj',
    '_ZN2nn3hid20IsVibrationPermittedEv',
    '_ZN2nn3hid25GetVibrationDeviceHandlesEPNS0_21VibrationDeviceHandleEiRKjNS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE',
    '_ZN2nn3hid25InitializeVibrationDeviceERKNS0_21VibrationDeviceHandleE',
    '_ZN2nn3hid18SendVibrationValueERKNS0_21VibrationDeviceHandleERKNS0_14VibrationValueE',
)
RESULTS = {'controller_result': (0x8500, 136)}


def assemble(tools):
    clang, objcopy = tools
    suffix = '.exe' if clang.suffix == '.exe' else ''
    nm = clang.parent / ('llvm-nm' + suffix)
    with tempfile.TemporaryDirectory(prefix='dm-controller-') as temporary:
        elf, binary = Path(temporary) / 'controller.elf', Path(temporary) / 'controller.bin'
        subprocess.run([str(clang), '--target=aarch64-linux-android29', '-nostdlib', '-static',
                        '-Wl,-T,' + str(FIXTURES / 'fixture.ld'), '-Wl,--build-id=none',
                        str(FIXTURES / 'controller.S'), '-o', str(elf)], check=True, capture_output=True)
        subprocess.run([str(objcopy), '-O', 'binary', '--only-section=.text', str(elf), str(binary)],
                       check=True, capture_output=True)
        listing = subprocess.run([str(nm), '-S', '--defined-only', '--format=posix', str(elf)],
                                 check=True, capture_output=True, text=True).stdout
        functions = {}
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[1] == 'T':
                functions[fields[0]] = (int(fields[2], 16), int(fields[3], 16), 2)
        return binary.read_bytes(), functions


def make_nso(text, functions):
    ro, data = bytearray(4096), bytearray(4096)
    definitions = dict(functions)
    definitions.update({name: (value, size, 1) for name, (value, size) in RESULTS.items()})
    records, strings, indices = [bytes(24)], bytearray(b'\0'), {}
    for name in sorted(set(definitions) | set(IMPORTS)):
        indices[name] = len(records)
        offset = len(strings)
        strings += name.encode('ascii') + b'\0'
        if name in definitions:
            value, size, kind = definitions[name]
            binding = 0 if name in ('fixture_entry', 'fixture_init') else 1
            record = struct.pack('<IBBHQQ', offset, binding * 16 + kind, 0, 1, value, size)
        else:
            record = struct.pack('<IBBHQQ', offset, 0x12, 0, 0, 0, 0)
        records.append(record)
    symbols = b''.join(records)
    ro[:len(symbols)] = symbols
    ro[len(symbols):len(symbols) + len(strings)] = strings
    hash_offset = (len(symbols) + len(strings) + 7) & -8
    words = [1, len(records), 1, 0] + [i + 1 if i + 1 < len(records) else 0 for i in range(1, len(records))]
    hashed = struct.pack('<' + 'I' * len(words), *words)
    ro[hash_offset:hash_offset + len(hashed)] = hashed
    rela_offset = (hash_offset + len(hashed) + 7) & -8
    relas = b''.join(struct.pack('<QQq', 0x8000 + index * 8, indices[name] << 32 | 1026, 0)
                     for index, name in enumerate(IMPORTS))
    if rela_offset + len(relas) > len(ro):
        raise ValueError('controller RO metadata exceeds its fixed section')
    ro[rela_offset:rela_offset + len(relas)] = relas
    dynamic = [(5, 0x4000 + len(symbols)), (10, len(strings)), (6, 0x4000), (11, 24),
               (4, 0x4000 + hash_offset), (12, functions['fixture_init'][0]),
               (23, 0x4000 + rela_offset), (2, len(relas)), (20, 7), (0, 0)]
    for index, (tag, value) in enumerate(dynamic):
        struct.pack_into('<qQ', data, 0x400 + index * 16, tag, value)
    header = bytearray(256)
    header[:4] = b'NSO0'
    struct.pack_into('<I', header, 12, 0x38)
    header[0x40:0x60] = hashlib.sha256(b'dm-public-controller-v1' + text + ro + data).digest()
    struct.pack_into('<IIII', header, 0x90, len(symbols), len(strings), 0, len(symbols))
    parts, cursor = [], 256
    for index, (raw, memory) in enumerate(((text, 0), (bytes(ro), 0x4000), (bytes(data), 0x8000))):
        struct.pack_into('<IIII', header, 0x10 + index * 16, cursor, memory, len(raw), 4096 if index == 2 else 0)
        struct.pack_into('<I', header, 0x60 + index * 4, len(raw))
        header[0xA0 + index * 32:0xC0 + index * 32] = hashlib.sha256(raw).digest()
        parts.append(raw)
        cursor += len(raw)
    return bytes(header) + b''.join(parts)


def generate(tools):
    source = make_nso(*assemble(tools))
    package, report = import_module(source, 'sdk', package_version=2)
    lines = ['// Generated by gen_android_controllers.py; public fixture, no game profile.',
             '#pragma once', '#include <stdint.h>', '#include <stddef.h>',
             'alignas(8) static const uint8_t dm_controller_bytes[] = {']
    for offset in range(0, len(package), 24):
        lines.append('    ' + ','.join(f'0x{x:02x}' for x in package[offset:offset + 24]) + ',')
    lines += ['};', 'static constexpr size_t dm_controller_size = sizeof(dm_controller_bytes);',
              'static const uint8_t dm_controller_package_sha256[32] = {' +
              ','.join(f'0x{x:02x}' for x in hashlib.sha256(package).digest()) + '};', '']
    return {'controller.nso': source, 'controller.dmag': package,
            'generated_controllers.h': '\n'.join(lines).encode(),
            'import.json': (json.dumps(report, indent=2) + '\n').encode()}


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
                raise SystemExit(f'{target} differs; run gen_android_controllers.py')
        else:
            target.write_bytes(content)
    print(('Verified' if args.check else 'Generated') +
          ' public controller NONE/class0 NSO via production wire-v2 importer; game boot NOT_RUN')


if __name__ == '__main__':
    main()
