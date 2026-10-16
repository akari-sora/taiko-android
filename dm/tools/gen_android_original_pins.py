#!/usr/bin/env python3
"""Verify owned retail NSOs and successful stock imports; emit hash-only C++ pins.

`inventory` performs no rewrite/import and reports actual strong-import closure
against the supplied compiled HostRegistry ELF. `generate` additionally requires
successful checked-stack/callback-audited DMAMOD02 files. Runtime JSON is never
authority: only the generated provider deliberately compiled into the app is.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import struct

from android_profiles import APPLE_BUILD_PREFIX, APPLE_OBS, APPLE_PARAMS
from nso_format import parse_nso, parse_metadata

ROOT = Path(__file__).resolve().parents[2]
PROVIDER_OUTPUT = ROOT/'dm/platform/android/original_build_pins.cpp'
BUILD = 'D2R/3.3.94012/OriginalBringup-stock-v1'
SOURCE_PINS = {
    'main': (18099792, '55fd909bb7230b002357e5b0d8499c11f06888f345c49e69eb4734df44a27d0e',
             'db0507f36b84200ac05f75d76ed5026f903e6c90000000000000000000000000'),
    'sdk': (5755393, '1c9f198a91c0bcfee5cf8f5b53fb941895e91334dfb766ce79fc68576797f017',
            '2d369d9999e3e10e665106f840ffff9bdaa0bb8e000000000000000000000000'),
    'subsdk0': (3409290, '67a38fcf89cd13e040a021eb3d157072f38ebf6680a907874c35c7b231b5d4e2',
               '507f19d1240d09d00992248e8a0fd77ebd784eb4000000000000000000000000'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii')


def word_checks(image):
    tree = ast.parse((ROOT/'dm/tools/patch_nso.py').read_text(encoding='utf-8'))
    cuts = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == 'CUTS' for target in node.targets))
    checks = [('CUTS', item[0], bytes.fromhex(item[1])) for item in cuts[APPLE_BUILD_PREFIX]]
    checks += [('OBS', item[0], bytes.fromhex(item[2])[::-1]) for item in APPLE_OBS[APPLE_BUILD_PREFIX]]
    for item in APPLE_PARAMS[APPLE_BUILD_PREFIX]:
        checks += [('PARAM', item[0], bytes.fromhex(item[1])[::-1]),
                   ('PARAM', item[2], bytes.fromhex(item[3])[::-1])]
    if len(checks) != 41:
        raise ValueError('expected all 41 independent CUTS/OBS/PARAM source checks')
    result = []
    for kind, offset, expected in checks:
        if image[offset:offset+len(expected)] != expected:
            raise ValueError(f'original {kind} source bytes mismatch at {offset:#x}')
        result.append(dict(kind=kind, offset=offset, original_hex=expected.hex()))
    return result


def verify_sources(directory):
    result, objects = [], {}
    for name, (size, digest, build_id) in SOURCE_PINS.items():
        path = Path(directory)/name
        if path.stat().st_size != size:
            raise ValueError(f'{name}: original source size differs from trusted retail pin')
        data = path.read_bytes()
        if sha(data) != digest:
            raise ValueError(f'{name}: original source SHA256 differs from trusted retail pin')
        nso = parse_nso(data)
        if nso.build_id.hex() != build_id:
            raise ValueError(f'{name}: full original build ID mismatch')
        metadata = parse_metadata(nso)
        objects[name] = (nso, metadata)
        result.append(dict(name=name, source_bytes=size, source_sha256=digest,
                           decoded_sha256=sha(nso.image), build_id=build_id))
    checks = word_checks(objects['main'][0].image)
    audit = dict(schema=1, build=BUILD, sources=result, original_word_checks=checks,
                 recipe_sha256={name: sha((ROOT/'dm/tools'/name).read_bytes())
                                for name in ('gen_android_original_pins.py', 'nso_format.py', 'android_profiles.py', 'patch_nso.py',
                                             'android_import.py', 'android_rewrite.py', 'android_exclusive.py', 'android_observation.py')})
    return audit, objects


def host_registry(path):
    """Read actual ELF swhle/swforce name/function relocations, no nm guesses."""
    data = Path(path).read_bytes()
    if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H', data, 18)[0] != 183:
        raise ValueError('HostRegistry input must be actual little-endian ELF64/AArch64')
    offset = struct.unpack_from('<Q', data, 40)[0]
    stride, count, string_index = struct.unpack_from('<HHH', data, 58)
    if stride != 64 or not 0 < count <= 65535 or string_index >= count or offset+count*stride > len(data):
        raise ValueError('invalid ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, offset+i*stride) for i in range(count)]
    strings = sections[string_index]
    names = data[strings[4]:strings[4]+strings[5]]

    def string(blob, at):
        end = blob.find(b'\0', at, min(len(blob), at+4096))
        if at < 0 or end < 0:
            raise ValueError('unterminated ELF registration string')
        return blob[at:end].decode('ascii')

    def view(address, length):
        for section in sections:
            if section[1] != 8 and section[3] <= address and address-section[3]+length <= section[5]:
                at = section[4]+address-section[3]
                if at+length <= len(data):
                    return data[at:at+length]
        raise ValueError('registration pointer outside file-backed ELF sections')

    relocations = {}
    for section in sections:
        if section[1] != 4:
            continue
        if section[9] != 24 or section[5] % 24 or section[4]+section[5] > len(data):
            raise ValueError('invalid ELF64 RELA table')
        for at in range(section[4], section[4]+section[5], 24):
            target, info, addend = struct.unpack_from('<QQq', data, at)
            relocations[target] = (info & 0xffffffff, info >> 32, addend)

    def pointer(address):
        relocation = relocations.get(address)
        if relocation is None or relocation[:2] != (1027, 0) or relocation[2] <= 0:
            raise ValueError('HostRegistry pointer lacks local R_AARCH64_RELATIVE ownership')
        return relocation[2]

    records = {}
    for section in sections:
        name = string(names, section[0])
        if name not in ('swhle', 'swforce'):
            continue
        size = 16 if name == 'swhle' else 24
        if section[5] % size:
            raise ValueError('invalid HostRegistry record extent')
        for at in range(section[3], section[3]+section[5], size):
            address = pointer(at)
            # Mangled names are bounded C strings in actual mapped ELF data.
            text = string(view(address, 1)+b'', 0) if view(address, 1) == b'\0' else None
            if text is None:
                for holder in sections:
                    if holder[1] != 8 and holder[3] <= address < holder[3]+holder[5]:
                        begin = holder[4]+address-holder[3]
                        text = string(data, begin)
                        break
            function = pointer(at+8)
            if not text or not any(s[2] & 4 and s[3] <= function < s[3]+s[5] for s in sections):
                raise ValueError('HostRegistry function/name is invalid')
            if name == 'swforce':
                pointer(at+16)  # Actual forced registration requires a reason.
            if text in records:
                raise ValueError('duplicate/conflicting actual HostRegistry registration')
            records[text] = name
    if not records:
        raise ValueError('HostRegistry ELF has no retained registration sections')
    return dict(elf_sha256=sha(data), registrations=records)


def import_inventory(objects, registry):
    def exports(order):
        return {s.name for name in order for s in objects[name][1].symbols
                if s.name and s.section and s.binding and s.visibility not in (1, 2)}

    def missing(order):
        available = exports(order) | registry['registrations'].keys()
        result = []
        for name in order:
            metadata = objects[name][1]
            used = {r.symbol for r in metadata.relocations if r.kind != 1027 and r.symbol}
            for index in sorted(used):
                symbol = metadata.symbols[index]
                if not symbol.section and symbol.binding != 2 and symbol.name not in available:
                    result.append(dict(module=name, symbol=symbol.name, binding=symbol.binding))
        return result

    two, three = ['main', 'sdk'], ['main', 'sdk', 'subsdk0']
    unresolved_two = missing(two)
    supplied_by_subsdk = sorted({item['symbol'] for item in unresolved_two} & exports(['subsdk0']))
    order = three if supplied_by_subsdk else two
    return dict(host_elf_sha256=registry['elf_sha256'], host_registration_count=len(registry['registrations']),
                recommended_module_order=order, subsdk0_supplies=supplied_by_subsdk,
                unresolved_main_sdk=unresolved_two, unresolved_main_sdk_subsdk0=missing(three),
                unresolved_selected=missing(order))


def package_pin(path, report, source, nso, metadata):
    if path.stat().st_size > 512*1024*1024:
        raise ValueError('original capsule exceeds hard package bound')
    data = path.read_bytes()
    if len(data) < 384 or data[:8] != b'DMAMOD02' or struct.unpack_from('<IIII', data, 8) != (2, 0x444d4101, 384, 1):
        raise ValueError('original capsule must be checked-stack DMAMOD02')
    digest = sha(data)
    payload = struct.unpack_from('<Q', data, 112)[0]
    image_size = struct.unpack_from('<Q', data, 24)[0]
    capsule_name = data[168:184].split(b'\0', 1)[0].decode('ascii')
    if capsule_name != source['name'] or payload+image_size != len(data) or data[184:216].hex() != source['build_id'] or data[216:248].hex() != source['source_sha256']:
        raise ValueError('capsule source/build/payload extent mismatch')
    image_digest = sha(data[payload:])
    if data[248:280].hex() != image_digest or data[320:352] != bytes(32) or struct.unpack_from('<I', data, 352)[0] or struct.unpack_from('<Q', data, 368)[0]:
        raise ValueError('stock capsule cannot carry product profile/parameters')
    gates, gate_count = struct.unpack_from('<QQ', data, 136)
    if gates+gate_count*32 > payload:
        raise ValueError('invalid capsule gate extent')
    for at in range(gates, gates+gate_count*32, 32):
        _, _, kind, argument, _, flags = struct.unpack_from('<QQIIII', data, at)
        if kind == 3 or (kind == 1 and argument >= 0x80) or flags:
            raise ValueError('stock capsule contains OBS/private product CUTS')
    if report.get('unsupported') or report.get('name') != source['name'] or report.get('source_sha256') != source['source_sha256'] or report.get('build_id') != source['build_id'] or report.get('package_sha256') != digest or report.get('image_sha256') != image_digest or report.get('package_size') != len(data) or report.get('source_size') != source['source_bytes'] or report.get('original_image_size') != len(nso.image):
        raise ValueError('successful import attestation does not match actual capsule bytes')
    audit = report.get('callback_audit', {})
    roots = sorted({s.value for s in metadata.symbols if s.kind == 2 and s.section not in (0, 0xfff1)})
    code_roots = set(report.get('code_discovery', {}).get('roots', []))
    if not roots or any(r % 4 or r < 0 or r+4 > nso.sections[0].end or r not in code_roots for r in roots):
        raise ValueError('actual defined callback entries lack complete code audit')
    if audit != dict(callback_audit_version=1, package_sha256=digest, source_sha256=source['source_sha256'],
                     indirect_policy='guarded-host', callback_root_kind='defined-stt-func', callback_roots=roots):
        raise ValueError('callback attestation differs from actual original function entries')
    return dict(name=source['name'], package_sha256=digest, image_sha256=image_digest,
                package_bytes=len(data), image_bytes=image_size, callback_audit=audit)


def emit_provider(model):
    """Emit constants only; CLI callers must first run all verification above."""
    def digest(value):
        if len(value) != 64 or not int(value, 16):
            raise ValueError('zero/malformed digest cannot enter compiled pins')
        return '{{'+','.join('0x'+value[i:i+2] for i in range(0,64,2))+'}}'
    lines = ['// Generated trusted PC pin facts; no original capsule/image bytes.', '#include "original_bringup.h"',
             'namespace dm_android { namespace {']
    for index, module in enumerate(model['modules']):
        roots = module['callback_audit']['callback_roots']
        lines += [f'static constexpr uint64_t roots_{index}[]={{'+','.join(f'{r}ull' for r in roots)+'};']
    lines += ['static const OriginalSourcePin sources[]={']
    for source in model['sources']:
        lines += ['{"'+source['name']+'",'+','.join(digest(source[key]) for key in ('source_sha256','decoded_sha256','build_id'))+f",{source['source_bytes']}ull"+'},']
    lines += ['};', 'static const OriginalModulePin modules[]={']
    for index, module in enumerate(model['modules']):
        audit = module['callback_audit']
        values = '"'+module['name']+'",'+digest(module['package_sha256'])+','+digest(module['image_sha256'])+f",{module['package_bytes']}ull,{module['image_bytes']}ull,"
        values += '{1,'+digest(module['package_sha256'])+','+digest(audit['source_sha256'])+',CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,'+f'roots_{index},sizeof(roots_{index})/sizeof(uint64_t)'+'}'
        lines += ['{'+values+'},']
    lines += ['};', 'static const OriginalBuildPins pins={1,"'+BUILD+'",sources,3,modules,sizeof(modules)/sizeof(modules[0]),41,'+
              digest(model['source_audit_sha256'])+','+digest(model['import_manifest_sha256'])+'};',
              '}', 'const OriginalBuildPins* compiled_original_bringup_pins(){return &pins;}', '}']
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('inventory', 'generate'))
    parser.add_argument('--nso-directory', required=True, type=Path)
    parser.add_argument('--host-library', required=True, type=Path)
    parser.add_argument('--packages', type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    audit, objects = verify_sources(args.nso_directory)
    inventory = import_inventory(objects, host_registry(args.host_library))
    model = dict(schema=1, build=BUILD, sources=audit['sources'], source_audit_sha256=sha(canonical(audit)),
                 source_audit=audit, import_inventory=inventory)
    if args.mode == 'generate':
        if not args.packages or inventory['unresolved_main_sdk_subsdk0']:
            raise ValueError('successful capsules and complete actual strong-import closure are required')
        manifest_bytes = (args.packages/'import.json').read_bytes()
        report = json.loads(manifest_bytes)
        # The verified stock game requires subsdk0's sixteen movie exports.
        # This original build purpose never silently falls back to the old
        # cut-enabled two-module host order.
        order = ['main', 'sdk', 'subsdk0']
        if report.get('status') != 'prepared' or report.get('unsupported') or report.get('module_order') != order or len(report.get('modules', [])) != len(order):
            raise ValueError('original import is incomplete/rejected or has a different runtime order')
        model['import_manifest_sha256'] = sha(manifest_bytes)
        model['modules'] = [package_pin(args.packages/(name+'.dmag'), report['modules'][i], audit['sources'][i], *objects[name]) for i,name in enumerate(order)]
        provider = emit_provider(model)
        # No partial or empty provider is written on any rejected input.
        if args.output.exists() or PROVIDER_OUTPUT.exists():
            raise ValueError('pin output directory must be new; prior authority is never overwritten')
        args.output.mkdir(parents=True)
        (args.output/'original_build_pins.cpp').write_text(provider, encoding='utf-8')
    else:
        args.output.mkdir(parents=True, exist_ok=False)
    (args.output/'original-build.json').write_text(json.dumps(model, indent=2)+'\n', encoding='utf-8')
    if args.mode == 'generate':
        # Publish only after all verification and complete audit output. x mode
        # refuses any prior provider; a failed/rejected import writes none.
        with PROVIDER_OUTPUT.open('x', encoding='utf-8', newline='\n') as destination:
            destination.write(provider)
            destination.flush()
            os.fsync(destination.fileno())
    print(json.dumps(dict(mode=args.mode, module_order=inventory['recommended_module_order'],
                         unresolved=len(inventory['unresolved_selected']), output=str(args.output))))


if __name__ == '__main__':
    main()
