#!/usr/bin/env python3
"""Generate freely authored service ABI clients through the production importer."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from android_import import import_directory
from gen_android_fixtures import toolchain

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'dm/platform/android/service_fixtures'
# Keep the enum and imported names together in generated_services.h.
IMPORTS = {
    'list_users': '_ZN2nn7account13ListOpenUsersEPiPNS0_3UidEi',
    'open_user': '_ZN2nn7account22TryOpenPreselectedUserEPNS0_10UserHandleE',
    'user_id': '_ZN2nn7account9GetUserIdEPNS0_3UidERKNS0_10UserHandleE',
    'nickname': '_ZN2nn7account11GetNicknameEPNS0_8NicknameERKNS0_3UidE',
    'ensure_network': '_ZN2nn7account36EnsureNetworkServiceAccountAvailableERKNS0_10UserHandleE',
    'token': '_ZN2nn7account37LoadNetworkServiceAccountIdTokenCacheEPmPcmRKNS0_10UserHandleE',
    'account_event': '_ZN2nn7account12AsyncContext14GetSystemEventEPNS_2os11SystemEventE',
    'account_result': '_ZN2nn7account12AsyncContext9GetResultEv',
    'auth_event': '_ZN2nn7account42NintendoAccountAuthorizationRequestContext14GetSystemEventEPNS_2os11SystemEventE',
    'auth_result': '_ZN2nn7account42NintendoAccountAuthorizationRequestContext34GetResultWithInteractionIfRequiredEv',
    'auth_token': '_ZN2nn7account42NintendoAccountAuthorizationRequestContext10GetIdTokenEPmPcm',
    'friends_event': '_ZN2nn7friends12AsyncContext14GetSystemEventEPNS_2os11SystemEventE',
    'friends_result': '_ZNK2nn7friends12AsyncContext9GetResultEv',
    'friends_notify': '_ZN2nn7friends17NotificationQueue14GetSystemEventEv',
    'friends_invite': '_ZN2nn7friends36GetFriendInvitationNotificationEventEv',
    'aoc_count': '_ZN2nn3aoc17CountAddOnContentEv',
    'aoc_list': '_ZN2nn3aoc16ListAddOnContentEPiii',
    'aoc_event': '_ZN2nn3aoc31GetAddOnContentListChangedEventEPNS_2os11SystemEventE',
    'profanity': '_ZN2nn3ngc15ProfanityFilter19CheckProfanityWordsEPjjPPKcm',
    'sdk_time': 'time',
    'user_time': '_ZN2nn4time23StandardUserSystemClock14GetCurrentTimeEPNS0_9PosixTimeE',
    'time_now': '_ZN2nn4time23StandardUserSystemClock3nowEv',
    'localtime': 'localtime',
    'calendar': '_ZN2nn4time14ToCalendarTimeEPNS0_12CalendarTimeEPNS0_22CalendarAdditionalInfoERKNS0_9PosixTimeE',
    'rom_cache_size': '_ZN2nn2fs22QueryMountRomCacheSizeEPm',
    'mount_rom': '_ZN2nn2fs8MountRomEPKcPvm',
    'mount_temp': '_ZN2nn2fs21MountTemporaryStorageEPKc',
    'ensure_save': '_ZN2nn2fs14EnsureSaveDataERKNS_7account3UidE',
    'mount_save': '_ZN2nn2fs13MountSaveDataEPKcRKNS_7account3UidE',
    'commit': '_ZN2nn2fs6CommitEPKc',
    'unmount': '_ZN2nn2fs7UnmountEPKc',
    'open_file': '_ZN2nn2fs8OpenFileEPNS0_10FileHandleEPKci',
    'read_file': '_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvm',
    'write_file': '_ZN2nn2fs9WriteFileENS0_10FileHandleElPKvmRKNS0_11WriteOptionE',
    'close_file': '_ZN2nn2fs9CloseFileENS0_10FileHandleE',
    'create_file': '_ZN2nn2fs10CreateFileEPKcl',
    'set_size': '_ZN2nn2fs11SetFileSizeENS0_10FileHandleEl',
    'get_size': '_ZN2nn2fs11GetFileSizeEPlNS0_10FileHandleE',
    'flush_file': '_ZN2nn2fs9FlushFileENS0_10FileHandleE',
    'file_mode': '_ZN2nn2fs15GetFileOpenModeENS0_10FileHandleE',
    'entry_type': '_ZN2nn2fs12GetEntryTypeEPNS0_18DirectoryEntryTypeEPKc',
    'create_dir': '_ZN2nn2fs15CreateDirectoryEPKc',
    'rename_file': '_ZN2nn2fs10RenameFileEPKcS2_',
    'delete_file': '_ZN2nn2fs10DeleteFileEPKc',
    'delete_dir': '_ZN2nn2fs26DeleteDirectoryRecursivelyEPKc',
    'open_dir': '_ZN2nn2fs13OpenDirectoryEPNS0_15DirectoryHandleEPKci',
    'read_dir': '_ZN2nn2fs13ReadDirectoryEPlPNS0_14DirectoryEntryENS0_15DirectoryHandleEl',
    'close_dir': '_ZN2nn2fs14CloseDirectoryENS0_15DirectoryHandleE',
    'audio_init': '_ZN2nn5audio27InitializeAudioOutParameterEPNS0_17AudioOutParameterE',
    'audio_open': '_ZN2nn5audio12OpenAudioOutEPNS0_8AudioOutEPNS_2os11SystemEventEPKcRKNS0_17AudioOutParameterE',
    'audio_start': '_ZN2nn5audio13StartAudioOutEPNS0_8AudioOutE',
    'audio_stop': '_ZN2nn5audio12StopAudioOutEPNS0_8AudioOutE',
    'audio_close': '_ZN2nn5audio13CloseAudioOutEPNS0_8AudioOutE',
    'audio_state': '_ZN2nn5audio16GetAudioOutStateEPKNS0_8AudioOutE',
    'audio_rate': '_ZN2nn5audio21GetAudioOutSampleRateEPKNS0_8AudioOutE',
    'audio_channels': '_ZN2nn5audio23GetAudioOutChannelCountEPKNS0_8AudioOutE',
    'audio_format': '_ZN2nn5audio23GetAudioOutSampleFormatEPKNS0_8AudioOutE',
    'audio_set_buffer': '_ZN2nn5audio21SetAudioOutBufferInfoEPNS0_14AudioOutBufferEPvmm',
    'audio_buffer_pointer': '_ZN2nn5audio28GetAudioOutBufferDataPointerEPKNS0_14AudioOutBufferE',
    'audio_buffer_size': '_ZN2nn5audio25GetAudioOutBufferDataSizeEPKNS0_14AudioOutBufferE',
    'audio_append': '_ZN2nn5audio20AppendAudioOutBufferEPNS0_8AudioOutEPNS0_14AudioOutBufferE',
    'audio_released': '_ZN2nn5audio25GetReleasedAudioOutBufferEPNS0_8AudioOutE',
}


def assembly(name):
    lines = ['.text', '.global fixture_entry', '.type fixture_entry,%function',
             'fixture_entry: ret', '.size fixture_entry,.-fixture_entry', '.word 0x40',
             '.org 0x40', '.ascii "MOD0"',
             '.word 0x10400-0x40,0x14000-0x40,0x15000-0x40,0,0,0x10300-0x40',
             '.org 0x100', '.global fixture_init', '.type fixture_init,%function',
             'fixture_init: ret', '.size fixture_init,.-fixture_init']
    if name == 'main':
        for i, key in enumerate(IMPORTS):
            symbol = 'service_' + key
            lines += ['.balign 4', '.global ' + symbol, '.type ' + symbol + ',%function', symbol + ':',
                      'stp x29,x30,[sp,#-16]!', 'mov x10,x0', 'adrp x9,0x10000',
                      f'ldr x9,[x9,#{i * 8}]',
                      'ldp x0,x1,[x10]', 'ldp x2,x3,[x10,#16]', 'ldp x4,x5,[x10,#32]',
                      'ldp x6,x7,[x10,#48]', 'blr x9', 'ldp x29,x30,[sp],#16', 'ret',
                      '.size ' + symbol + ',.-' + symbol]
        # A rewritten, immediate SVC invocation, separate from host direct tests.
        for key, number in (('wait', 0x18), ('close_handle', 0x16), ('signal', 0x11), ('query_memory', 6), ('clear_event', 0x12)):
            symbol = 'service_' + key
            lines += ['.global ' + symbol, '.type ' + symbol + ',%function', symbol + ':',
                      'mov x9,x0', 'ldp x0,x1,[x9]', 'ldp x2,x3,[x9,#16]',
                      f'svc #{number}', 'ret', '.size ' + symbol + ',.-' + symbol]
    else:
        create = '_ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb'
        writable = '_ZN2nn2os30GetWritableHandleOfSystemEventEPKNS0_15SystemEventTypeE'
        for symbol, instructions in (
            (create, ['stp x19,x30,[sp,#-16]!', 'mov x19,x0', 'svc #0x45',
                      'cbnz w0,1f', 'stp w1,w2,[x19]', '1: ldp x19,x30,[sp],#16', 'ret']),
            (writable, ['ldr w0,[x0]', 'ret']),
            ('time', ['mov x1,#0x3456', 'cbz x0,1f', 'str x1,[x0]', '1: mov x0,x1', 'ret'])):
            lines += ['.global ' + symbol, '.type ' + symbol + ',%function', symbol + ':']
            lines += instructions + ['.size ' + symbol + ',.-' + symbol]
    lines += ['.org 0x1000']
    return '\n'.join(lines) + '\n'


def assemble(name, tools):
    clang, objcopy = tools
    suffix = '.exe' if clang.suffix == '.exe' else ''
    with tempfile.TemporaryDirectory(prefix='dm-services-asm-') as temporary:
        source, elf, binary = (Path(temporary) / x for x in ('fixture.S', 'fixture.elf', 'fixture.bin'))
        source.write_text(assembly(name))
        subprocess.run([str(clang), '--target=aarch64-linux-android29', '-nostdlib', '-static',
                        '-Wl,-T,' + str(ROOT / 'dm/platform/android/module_fixtures/fixture.ld'),
                        '-Wl,--build-id=none', str(source), '-o', str(elf)], check=True, capture_output=True)
        subprocess.run([str(objcopy), '-O', 'binary', '--only-section=.text', str(elf), str(binary)],
                       check=True, capture_output=True)
        listing = subprocess.run([str(clang.parent / ('llvm-nm' + suffix)), '-S', '--defined-only',
                                  '--format=posix', str(elf)], check=True, capture_output=True, text=True).stdout
        functions = {}
        for line in listing.splitlines():
            fields = line.split()
            if len(fields) == 4 and fields[1] == 'T':
                functions[fields[0]] = (int(fields[2], 16), int(fields[3], 16), 2)
        return binary.read_bytes(), functions


def make_nso(name, text, definitions):
    ro, data = bytearray(0xc000), bytearray(0x4000)
    imports = list(IMPORTS.values()) if name == 'main' else []
    records, strings, indices = [bytes(24)], bytearray(b'\0'), {}
    for symbol in sorted(set(definitions) | set(imports)):
        indices[symbol] = len(records)
        offset = len(strings)
        strings += symbol.encode() + b'\0'
        if symbol in definitions:
            value, size, kind = definitions[symbol]
            binding = 0 if symbol in ('fixture_entry', 'fixture_init') else 1
            records.append(struct.pack('<IBBHQQ', offset, binding * 16 + kind, 0, 1, value, size))
        else:
            records.append(struct.pack('<IBBHQQ', offset, 18, 0, 0, 0, 0))
    symtab = b''.join(records)
    ro[:len(symtab)] = symtab
    ro[len(symtab):len(symtab) + len(strings)] = strings
    string_offset = 0x4000 + len(symtab)
    hash_offset = (string_offset + len(strings) + 7) & -8
    words = [1, len(records), 1, 0] + [i + 1 if i + 1 < len(records) else 0 for i in range(1, len(records))]
    table = struct.pack(f'<{len(words)}I', *words)
    ro[hash_offset - 0x4000:hash_offset - 0x4000 + len(table)] = table
    rela_offset = (hash_offset + len(table) + 7) & -8
    relas = b''.join(struct.pack('<QQq', 0x10000 + i * 8, (indices[symbol] << 32) | 1026, 0)
                     for i, symbol in enumerate(imports))
    ro[rela_offset - 0x4000:rela_offset - 0x4000 + len(relas)] = relas
    dynamic = [(5, string_offset), (10, len(strings)), (6, 0x4000), (11, 24), (4, hash_offset),
               (12, definitions['fixture_init'][0])]
    if imports:
        dynamic += [(23, rela_offset), (2, len(relas)), (20, 7)]
    dynamic += [(0, 0)]
    for i, (tag, value) in enumerate(dynamic):
        struct.pack_into('<qQ', data, 0x400 + i * 16, tag, value)
    header = bytearray(256)
    header[:4] = b'NSO0'
    struct.pack_into('<I', header, 12, 0x38)
    header[0x40:0x60] = hashlib.sha256(name.encode() + text + ro + data).digest()
    struct.pack_into('<IIII', header, 0x90, string_offset - 0x4000, len(strings), 0, len(symtab))
    cursor = 256
    for i, (segment, memory) in enumerate(((text, 0), (ro, 0x4000), (data, 0x10000))):
        struct.pack_into('<IIII', header, 0x10 + i * 16, cursor, memory, len(segment), 4096 if i == 2 else 0)
        struct.pack_into('<I', header, 0x60 + i * 4, len(segment))
        header[0xA0 + i * 32:0xC0 + i * 32] = hashlib.sha256(segment).digest()
        cursor += len(segment)
    return bytes(header) + text + ro + data


def generate(tools):
    sources = {name: make_nso(name, *assemble(name, tools)) for name in ('main', 'sdk')}
    with tempfile.TemporaryDirectory(prefix='dm-services-import-') as temporary:
        exefs, output = Path(temporary) / 'exefs', Path(temporary) / 'prepared'
        exefs.mkdir()
        for name, source in sources.items():
            (exefs / name).write_bytes(source)
        report = import_directory(exefs, output, ('main', 'sdk'))
        lines = ['// Generated by gen_android_services.py; public, freely authored ABI fixtures.',
                 '#pragma once', '#include <stddef.h>', '#include <stdint.h>']
        files = {}
        for name, source in sources.items():
            package = (output / (name + '.dmag')).read_bytes()
            prefix = 'dm_service_' + name
            lines += [f'alignas(8) static const uint8_t {prefix}_bytes[] = {{']
            for i in range(0, len(package), 24):
                lines.append('    ' + ','.join(f'0x{x:02x}' for x in package[i:i + 24]) + ',')
            lines += ['};', f'static constexpr size_t {prefix}_size = sizeof({prefix}_bytes);',
                      f'static const uint8_t {prefix}_package_sha256[32] = {{',
                      '    ' + ','.join(f'0x{x:02x}' for x in hashlib.sha256(package).digest()) + ',', '};']
            files[name + '.nso'], files[name + '.dmag'] = source, package
        lines += ['static const char* const dm_service_audio_imports[] = {']
        lines += ['    ' + json.dumps(symbol) + ',' for key, symbol in IMPORTS.items() if key.startswith('audio_')]
        lines += ['};']
        files['generated_services.h'] = ('\n'.join(lines) + '\n').encode()
        files['import.json'] = (json.dumps(report, indent=2) + '\n').encode()
        files['main.S'], files['sdk.S'] = (assembly(name).encode() for name in ('main', 'sdk'))
        return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ndk')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    FIXTURES.mkdir(exist_ok=True)
    for name, content in generate(toolchain(args.ndk)).items():
        target = FIXTURES / name
        if args.check:
            if not target.is_file() or target.read_bytes() != content:
                raise SystemExit(f'{target} differs; run gen_android_services.py')
        else:
            target.write_bytes(content)
    print('Verified service NSO production import' if args.check else 'Generated service NSO production import')


if __name__ == '__main__':
    main()
