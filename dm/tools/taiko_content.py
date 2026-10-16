#!/usr/bin/env python3
"""Package the pinned Taiko ExeFS and complete RomFS for Android content import.

Hashes establish byte integrity only. This tool neither executes guest code nor
grants native startup/shader authority. The native admission contract is separate.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import tempfile

PROGRAM_ID = '01002460135A4000'
MODULE_ORDER = ('main', 'subsdk0', 'sdk')
ABI = 0x444D4101
CHUNK_BYTES = 1024 * 1024
# Checked original identity; never accept caller-selected identity pins.
SOURCE_PINS = {
    'rtld': dict(bytes=7132, sha256='8e08c8cf2e4d6b39d69643af10ce765d39c06860878224c68f8cafc45a2636aa', build_id='567cdd4c5251494c5cd70822e3ccc740c190c2b2000000000000000000000000'),
    'main': dict(bytes=38127530, sha256='f1313fe0d6cd4a024e53d8a283434448bacea453b02f37b75b18bfe281d0fcff', build_id='4541b79257635ce79105b3ba59e4808500000000000000000000000000000000'),
    'subsdk0': dict(bytes=3385425, sha256='f38d30e8241ee208cbf3090f44613e328af517ad199eb5985619416bb2cbcb55', build_id='a8cb97803f7f442a3b6cce1c7cd4ee4a78b7def3000000000000000000000000'),
    'sdk': dict(bytes=5989236, sha256='2a89fa1c0e677710e89ed29b578162affef530a0c9b8c93cda15d50a57a20d28', build_id='357efc198e728cb5d55265aff304f03cfc9cc0e3000000000000000000000000'),
    'main.npdm': dict(bytes=1572, sha256='afd3aade95cbcc607759eb677b67082193719a701a5b0cc8ed78ac33b5c65150'),
}


class ContentError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ContentError(message)


def validate_component(name):
    reserved = {'CON', 'PRN', 'AUX', 'NUL', *(f'{p}{i}' for p in ('COM', 'LPT') for i in range(1, 10))}
    require(bool(name) and name not in ('.', '..') and not name.endswith((' ', '.'))
            and not any(ord(c) < 32 or c in '/\\:<>"|?*' for c in name)
            and name.split('.')[0].upper() not in reserved, 'unsafe path component: ' + repr(name))


def checked_stat(path, directory=False):
    """Do not traverse symbolic links, junctions or other Windows reparse points."""
    path = Path(os.path.abspath(path))
    for part in (*reversed(path.parents), path):
        value = part.lstat()
        require(not stat.S_ISLNK(value.st_mode) and not getattr(value, 'st_file_attributes', 0) & 0x400,
                'links/reparse points are not allowed: ' + str(part))
    require(stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode),
            'expected ordinary ' + ('directory: ' if directory else 'file: ') + str(path))
    return value


def digest_file(path, destination=None, *, payload_offset=None):
    before = checked_stat(path)
    digest, payload = hashlib.sha256(), hashlib.sha256()
    count = 0
    target = destination.open('xb') if destination is not None else None
    try:
        with Path(path).open('rb') as source:
            while chunk := source.read(CHUNK_BYTES):
                digest.update(chunk)
                if payload_offset is not None and count + len(chunk) > payload_offset:
                    payload.update(chunk[max(0, payload_offset-count):])
                if target is not None:
                    target.write(chunk)
                count += len(chunk)
    finally:
        if target is not None:
            target.close()
    after = checked_stat(path)
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) and count == before.st_size,
            'source changed while reading: ' + str(path))
    return dict(bytes=count, sha256=digest.hexdigest()), payload.hexdigest()


def source_records():
    return [dict(name=name, **pin) for name, pin in SOURCE_PINS.items()]


def validate_sources(source):
    exefs = Path(source) / 'ExeFS'
    checked_stat(exefs, directory=True)
    for name, pin in SOURCE_PINS.items():
        path = exefs / name
        actual, _ = digest_file(path)
        require(actual == {key: pin[key] for key in ('bytes', 'sha256')}, name + ' original source identity mismatch')
        if 'build_id' in pin:
            with path.open('rb') as stream:
                header = stream.read(96)
            require(header[:4] == b'NSO0' and header[64:96].hex() == pin['build_id'], name + ' NSO build identity mismatch')
    return source_records()


def load_receipt(capsules):
    path = capsules / 'import.json'
    checked_stat(path)
    require(path.stat().st_size <= 512 * 1024 * 1024, 'import receipt exceeds bounded size')
    raw = path.read_bytes()
    try:
        receipt = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise ContentError('invalid import receipt') from error
    require(isinstance(receipt, dict) and receipt.get('status') == 'prepared'
            and receipt.get('format') == 'DMAMOD02' and receipt.get('abi') == ABI
            and receipt.get('checked_stack') is True and receipt.get('indirect_policy') == 'guarded-host'
            and receipt.get('module_order') == list(MODULE_ORDER) and receipt.get('unsupported') == [],
            'receipt is not a complete checked-stack Taiko v2 import')
    modules = receipt.get('modules')
    require(isinstance(modules, list) and len(modules) == 3 and
            all(isinstance(item, dict) for item in modules) and
            [item.get('name') for item in modules] == list(MODULE_ORDER), 'receipt module list mismatch')
    return raw, modules


def validate_package(path, module):
    name = module['name']; pin = SOURCE_PINS[name]
    checked_stat(path)
    with path.open('rb') as stream:
        header = stream.read(384)
    require(len(header) == 384 and header[:8] == b'DMAMOD02' and
            struct.unpack_from('<IIII', header, 8) == (2, ABI, 384, 1), name + ' package v2/ABI/checked-stack header mismatch')
    require(header[168:184] == name.encode().ljust(16, b'\0') and
            header[184:216].hex() == pin['build_id'] and header[216:248].hex() == pin['sha256'],
            name + ' package original identity mismatch')
    require(header[320:356] == bytes(36), name + ' unexpected game profile authority')
    image_size, original_size = struct.unpack_from('<QQ', header, 24)
    payload_offset, fixup_offset, fixup_count, gate_offset, gate_count, site_offset, site_count = struct.unpack_from('<7Q', header, 112)
    gate_stride, param_offset, param_count, param_stride, reserved = struct.unpack_from('<IQQII', header, 356)
    require(gate_stride == 32 and param_stride == 40 and reserved == 0 and param_count == 0,
            name + ' unregistered parameter/profile format')
    cursor = 384
    for offset, count, stride in ((fixup_offset, fixup_count, 16), (gate_offset, gate_count, 32), (site_offset, site_count, 16)):
        require(offset == cursor and count <= (path.stat().st_size - cursor) // stride, name + ' package table layout mismatch')
        cursor += count * stride
    require(param_offset == cursor and payload_offset == (cursor + 15) // 16 * 16 and
            image_size > 0 and original_size > 0 and payload_offset + image_size == path.stat().st_size,
            name + ' package payload extent mismatch')
    actual, payload_hash = digest_file(path, payload_offset=payload_offset)
    rewrite = module.get('rewrite')
    require(actual == dict(bytes=module.get('package_size'), sha256=module.get('package_sha256')) and
            payload_hash == header[248:280].hex() == module.get('image_sha256') and
            original_size == module.get('original_image_size') and module.get('source_size') == pin['bytes'] and
            module.get('source_sha256') == pin['sha256'] and module.get('build_id') == pin['build_id'] and
            module.get('unsupported') == [] and isinstance(rewrite, dict) and rewrite.get('checked_stack') is True,
            name + ' package differs from checked import receipt')
    audit = module.get('callback_audit', {})
    require(isinstance(audit, dict) and audit.get('callback_audit_version') == 1 and
            audit.get('package_sha256') == actual['sha256'] and audit.get('source_sha256') == pin['sha256'] and
            audit.get('indirect_policy') == 'guarded-host' and audit.get('callback_root_kind') == 'defined-stt-func',
            name + ' callback receipt identity mismatch')
    roots = audit.get('callback_roots')
    text_start, text_size = struct.unpack_from('<QQ', header, 40)
    require(isinstance(roots, list) and len(roots) <= min(1_048_576, text_size // 4) and
            all(type(root) is int and root % 4 == 0 and text_start <= root <= text_start + text_size - 4 for root in roots) and
            roots == sorted(set(roots)), name + ' malformed callback roots')
    return dict(name=name, path='modules/' + name + '.dmag', **actual, source_sha256=pin['sha256'])


def resource_tree(root):
    checked_stat(root, directory=True)
    entries, seen = [], set()
    def visit(directory):
        for path in sorted(directory.iterdir(), key=lambda value: value.name):
            validate_component(path.name)
            relative = path.relative_to(root).as_posix()
            folded = relative.casefold()
            require(folded not in seen, 'casefold path collision: ' + relative)
            seen.add(folded)
            value = path.lstat()
            is_directory = stat.S_ISDIR(value.st_mode)
            checked_stat(path, directory=is_directory)
            entries.append((path, relative, is_directory))
            if is_directory: visit(path)
    visit(root)
    return entries


def package_content(source, capsules, output):
    source, capsules, output = (Path(os.path.abspath(value)) for value in (source, capsules, output))
    checked_stat(source, directory=True); checked_stat(capsules, directory=True)
    require(not output.exists() and not output.is_symlink(), 'choose a fresh output directory')
    checked_stat(output.parent, directory=True)
    require(not output.is_relative_to(source) and not output.is_relative_to(capsules), 'output must be outside input trees')
    sources = validate_sources(source)
    raw_receipt, modules = load_receipt(capsules)
    packages = [validate_package(capsules / (module['name'] + '.dmag'), module) for module in modules]
    entries = resource_tree(source / 'RomFS')
    require(any(not directory for _, _, directory in entries), 'RomFS must contain original resource files')
    # Validate everything before publication; interrupted copies never create output.
    staging = Path(tempfile.mkdtemp(prefix='.' + output.name + '-', dir=output.parent))
    try:
        (staging / 'modules').mkdir(); (staging / 'RomFS').mkdir()
        for package in packages:
            copied, _ = digest_file(capsules / (package['name'] + '.dmag'), staging / package['path'])
            require(copied == {key: package[key] for key in ('bytes', 'sha256')}, 'package changed after validation')
        files = []
        for path, relative, directory in entries:
            destination = staging / 'RomFS' / relative
            if directory:
                destination.mkdir()
            else:
                actual, _ = digest_file(path, destination)
                files.append(dict(path='RomFS/' + relative, **actual))
        (staging / 'import.json').write_bytes(raw_receipt)
        manifest = dict(schema=1, target='taiko-android', program_id=PROGRAM_ID,
            selected_exefs_display_version=None, module_order=list(MODULE_ORDER), sources=sources,
            packages=packages, files=files, total_bytes=len(raw_receipt) + sum(item['bytes'] for item in packages + files),
            import_receipt=dict(path='import.json', bytes=len(raw_receipt), sha256=hashlib.sha256(raw_receipt).hexdigest()))
        (staging / 'taiko-content.json').write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        # The source may be a running extraction; identity must still match at publication.
        require(validate_sources(source) == sources, 'original source changed during packaging')
        require(resource_tree(source / 'RomFS') == entries, 'resource tree changed during packaging')
        staging.rename(output)
        return manifest
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--capsules', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--identity-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.identity_only:
            require(args.capsules is None and args.output is None, 'identity-only does not accept capsules/output')
            result = dict(program_id=PROGRAM_ID, sources=validate_sources(args.source))
        else:
            require(args.capsules is not None and args.output is not None, 'capsules and output are required for packaging')
            result = package_content(args.source, args.capsules, args.output)
        print(json.dumps(result, indent=2))
    except (ContentError, OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, 'Taiko content rejected: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
