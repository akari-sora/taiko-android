#!/usr/bin/env python3
"""Compile hash-only Taiko module/content facts after strict local verification.

No rewrite is performed here. Exact stock sources, complete audited capsules,
and complete content are mandatory. Caller JSON alone never admits a title.
Only a deliberately compiled provider supplies the native authority contract.
"""
import argparse
from bisect import bisect_right
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile

from android_rewrite import decode, indirect_register, stack_check_operation
from android_diag_abort import MODULE_REQUIRE_DIAG_ABORT_V1, abi_header_sha256, validate_publication_contract
from nso_format import parse_nso, parse_metadata
from taiko_call_contract import select_checked_calls
from taiko_forest_audit import verify_checked_call_forests
from taiko_content import (ABI, PROGRAM_ID, MODULE_ORDER, SOURCE_PINS,
    checked_stat, digest_file, resource_tree, source_records, validate_component,
    validate_sources, require)

ROOT = Path(__file__).resolve().parents[2]
BUILD = 'Taiko/01002460135A4000/Stock-v1'
MAX_PACKAGE = 512 * 1024 * 1024
MAX_MANIFEST = 128 * 1024 * 1024
MAX_FILES = 100_000
MAX_FILE_BYTES = 16 * 1024**3
MAX_RESOURCE_BYTES = 64 * 1024**3


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def json_file(path, limit):
    checked_stat(path)
    require(path.stat().st_size <= limit, 'JSON exceeds bounded size: ' + str(path))
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    raw = path.read_bytes()
    return raw, json.loads(raw, object_pairs_hook=unique)


def verify_sources(source):
    validate_sources(source)
    facts, objects = {}, {}
    for name in ('rtld', *MODULE_ORDER):
        path = Path(source) / 'ExeFS' / name
        raw = path.read_bytes(); pin = SOURCE_PINS[name]
        require(len(raw) == pin['bytes'] and sha(raw) == pin['sha256'], 'original source changed: ' + name)
        nso = parse_nso(raw)
        require(nso.build_id.hex() == pin['build_id'], 'original build ID changed: ' + name)
        facts[name] = dict(name=name, source_bytes=len(raw), source_sha256=sha(raw),
            decoded_sha256=sha(nso.image), build_id=nso.build_id.hex())
        if name in MODULE_ORDER:
            objects[name] = (nso, parse_metadata(nso))
    return facts, objects


def verify_import_closure(objects):
    require(tuple(objects) == MODULE_ORDER, 'original modules must be main/subsdk0/sdk in loader order')
    exported = {symbol.name for _, metadata in objects.values() for symbol in metadata.symbols
        if symbol.name and symbol.section and symbol.binding and symbol.visibility not in (1, 2)}
    counts, missing = {}, []
    for name, (_, metadata) in objects.items():
        used = {relocation.symbol for relocation in metadata.relocations if relocation.kind != 1027 and relocation.symbol}
        count = 0
        for index in sorted(used):
            require(0 < index < len(metadata.symbols), name + ' invalid relocation symbol')
            symbol = metadata.symbols[index]
            if symbol.section or symbol.binding == 2:
                continue
            count += 1
            if not symbol.name or symbol.name not in exported:
                missing.append(name + ':' + symbol.name)
        counts[name] = count
    require(not missing, 'unresolved referenced strong imports: ' + ', '.join(missing[:8]))
    return dict(module_order=list(MODULE_ORDER), referenced_strong_imports=counts,
        visible_export_count=len(exported), unresolved=[])


def verify_checked_calls(nso, metadata, discovery, rewrite, site_offsets, code_roots, ranges):
    """Re-derive the source contract; import JSON cannot nominate a target."""
    selected = list(select_checked_calls(nso, metadata))
    require(discovery.get('versioned_checked_calls', []) == selected,
        'checked-call discovery differs from independently selected source contract')
    lowered = [dict(offset=item['offset'], target=item['target'], rule='virtual-x18-exact-target-direct-call-v1')
        for item in sorted(selected, key=lambda item: item['offset'])]
    require(rewrite.get('checked_calls', []) == lowered, 'checked-call rewrite differs from canonical source contract')
    offsets = set()
    starts = [start for start, _ in ranges]
    for item in selected:
        offset, target = item['offset'], item['target']
        require(type(offset) is int and type(target) is int and offset % 4 == target % 4 == 0 and
            0 <= offset <= nso.sections[0].end - 4 and 0 <= target <= nso.sections[0].end - 4 and
            target not in (offset, offset + 4) and offset not in offsets and offset in site_offsets and target in code_roots,
            'checked-call site/target must have one source site and selected target root')
        offsets.add(offset)
        require(item.get('source_sha256') == nso.source_sha256.hex() and item.get('build_id') == nso.build_id.hex() and
            item.get('source_word') == 0xD63F0240 and struct.unpack_from('<I', nso.image, offset)[0] == 0xD63F0240,
            'checked-call source identity or original BLR X18 differs')
        for entry in (offset, target):
            position = bisect_right(starts, entry) - 1
            require(position >= 0 and entry + 4 <= ranges[position][1], 'checked-call source/target lacks selected code coverage')
    return selected


def verify_package(path, report, source, nso, metadata):
    """Title-neutral byte audit; generate() supplies only hard-pinned sources."""
    checked_stat(path)
    require(path.stat().st_size <= MAX_PACKAGE, 'capsule exceeds bounded size')
    data = path.read_bytes(); name = source['name']
    require(len(data) >= 384 and data[:8] == b'DMAMOD02' and
        struct.unpack_from('<III', data, 8) == (2, ABI, 384), 'capsule must be checked-stack DMAMOD02')
    required_flags=struct.unpack_from('<I',data,20)[0]
    if required_flags not in (1,1|MODULE_REQUIRE_DIAG_ABORT_V1):
        raise ValueError('original capsule has unknown or inconsistent required ABI flags')
    receipt=report.get('rewrite',{})
    if not isinstance(receipt,dict):
        raise ValueError('original capsule rewrite attestation must be an object')
    declared=receipt.get('requires_diag_abort_v1',False)
    if type(declared) is not bool or declared!=bool(required_flags&MODULE_REQUIRE_DIAG_ABORT_V1):
        raise ValueError('original capsule required ABI flags disagree with rewrite attestation')
    if not declared and any(key in receipt for key in ('required_diag_abort_abi','diag_abort_call_sites','diag_abort_plt_branches')):
        raise ValueError('unflagged original capsule carries a required DiagAbort receipt')
    require(data[168:184] == name.encode('ascii').ljust(16, b'\0') and
        data[184:216].hex() == source['build_id'] and data[216:248].hex() == source['source_sha256'],
        'capsule original source/build mismatch')
    require(data[296:356] == bytes(60), 'stock capsule cannot contain profiles or reserved authority')
    image_size, original_size, *geometry = struct.unpack_from('<11Q', data, 24)
    expected_patch = (len(nso.image) + 16383) // 16384 * 16384
    expected_geometry = [value for section in nso.sections for value in (section.offset, section.size)]
    expected_geometry += [nso.bss_size, expected_patch, image_size - expected_patch]
    require(original_size == len(nso.image) and geometry == expected_geometry and
        image_size >= expected_patch and image_size % 4 == 0, 'capsule original section/patch geometry mismatch')
    payload, fixup_offset, fixup_count, gate_offset, gate_count, site_offset, site_count = struct.unpack_from('<7Q', data, 112)
    gate_stride, parameter_offset, parameter_count, parameter_stride, reserved = struct.unpack_from('<IQQII', data, 356)
    require((gate_stride, parameter_count, parameter_stride, reserved) == (32, 0, 40, 0),
        'noncanonical capsule parameters or gate stride')
    cursor = 384
    for offset, count, stride in ((fixup_offset, fixup_count, 16), (gate_offset, gate_count, 32), (site_offset, site_count, 16)):
        require(offset == cursor and count <= (len(data) - cursor) // stride, 'noncanonical capsule table count/extent')
        cursor += count * stride
    require(parameter_offset == cursor and payload == (cursor + 15) // 16 * 16 and
        payload + image_size == len(data) and not any(data[cursor:payload]), 'noncanonical capsule payload extent')
    image = memoryview(data)[payload:]
    digest, image_digest = sha(data), sha(image)
    require(data[248:280].hex() == image_digest and
        struct.unpack_from('<QQ', data, 280) == (len(metadata.symbols), metadata.string_size), 'capsule image/metadata digest mismatch')
    require(isinstance(report, dict) and report.get('name') == name and report.get('unsupported') == [] and
        report.get('source_sha256') == source['source_sha256'] and report.get('build_id') == source['build_id'] and
        report.get('source_size') == source['source_bytes'] and report.get('original_image_size') == original_size and
        report.get('package_size') == len(data) and report.get('package_sha256') == digest and
        report.get('image_sha256') == image_digest and report.get('sections') == [asdict(section) for section in nso.sections] and
        report.get('bss_size') == nso.bss_size, 'capsule differs from successful original import receipt')
    rewrite = report.get('rewrite')
    require(isinstance(rewrite, dict) and rewrite.get('target') == 'android-arm64' and rewrite.get('abi') == ABI and
        rewrite.get('size') == image_size and rewrite.get('checked_stack') is True and
        rewrite.get('indirect_policy') == 'guarded-host' and not any(key in rewrite for key in
        ('profile_digest', 'profile_class', 'parameters')), 'stock rewrite metadata mismatch')
    fixups = []
    seen_fixups = set()
    for offset in range(fixup_offset, fixup_offset + fixup_count * 16, 16):
        at, helper, zero = struct.unpack_from('<QII', data, offset)
        require(zero == 0 and helper in (1, 2) and at % 8 == 0 and expected_patch <= at <= image_size - 8 and
            at not in seen_fixups and image[at:at+8] == bytes(8), 'invalid stock helper fixup')
        seen_fixups.add(at); fixups.append(dict(offset=at, helper=helper))
    require(fixups == rewrite.get('fixups'), 'fixup receipt/table mismatch')
    sorted_fixups = sorted(seen_fixups)
    sites = rewrite.get('sites')
    require(isinstance(sites, list) and len(sites) == site_count, 'site receipt/table count mismatch')
    restored = bytearray(image[:original_size]); site_offsets = set()
    for index, site in enumerate(sites):
        at, trampoline = struct.unpack_from('<QQ', data, site_offset + index * 16)
        require(isinstance(site, dict) and site.get('offset') == at and site.get('trampoline') == trampoline and
            at % 4 == 0 and 0 <= at <= nso.sections[0].end - 4 and at not in site_offsets and
            trampoline % 4 == 0 and expected_patch <= trampoline <= image_size - 4,
            'site receipt/source/trampoline mismatch')
        site_offsets.add(at)
        original_word = struct.unpack_from('<I', nso.image, at)[0]
        actual_word = struct.unpack_from('<I', image, at)[0]
        # Relocated exclusive-region interior records can preserve the source
        # instruction in place; every changed source site is a plain B stub.
        if actual_word != original_word:
            delta = (actual_word & 0x3ffffff) * 4
            if delta & (1 << 27): delta -= 1 << 28
            require(actual_word & 0xfc000000 == 0x14000000 and at + delta == trampoline, 'invalid source site branch')
        restored[at:at+4] = nso.image[at:at+4]
    require(restored == nso.image and not any(image[original_size:expected_patch]),
        'stock capsule changed original image outside recorded instruction sites')
    gates, provenance, seen_returns = [], [], set()
    for offset in range(gate_offset, gate_offset + gate_count * 32, 32):
        return_offset, original_offset, kind, argument, original_word, flags = struct.unpack_from('<QQIIII', data, offset)
        require(flags == 0 and kind in (1, 2, 4, 5) and return_offset % 4 == 0 and
            expected_patch + 4 <= return_offset <= image_size - 4 and return_offset not in seen_returns and
            original_offset in site_offsets and struct.unpack_from('<I', nso.image, original_offset)[0] == original_word and
            struct.unpack_from('<I', image, return_offset - 4)[0] == 0xD63F03C0,
            'stock gate has invalid provenance or OBS/private authority')
        seen_returns.add(return_offset)
        preceding = bisect_right(sorted_fixups, return_offset + 3) - 1
        require(preceding < 0 or sorted_fixups[preceding] + 8 <= return_offset - 4,
                'gate call/return overlaps helper fixup')
        if kind == 1:
            require(original_word & 0xffe0001f == 0xd4000001 and argument == original_word >> 5 & 65535 and argument < 128,
                'stock gate contains a private CUTS SVC')
        elif kind == 2:
            require(original_word & 0xffffffe0 in (0xd53be020, 0xd53be040) and argument == original_word & 31,
                'stock timer gate mismatch')
        elif kind == 4:
            require(argument == indirect_register(decode(original_word, original_offset)), 'stock guarded transfer mismatch')
        else:
            require(argument == original_word and stack_check_operation(original_word) is not None, 'stock checked-stack gate mismatch')
        gates.append(dict(return_offset=return_offset, kind=kind, argument=argument))
        provenance.append(dict(return_offset=return_offset, original_offset=original_offset, original_word=original_word, flags=flags))
    require(gates == rewrite.get('gates') and provenance == rewrite.get('gate_provenance'), 'gate receipt/table mismatch')
    validate_publication_contract(nso,metadata,data,receipt)
    roots = sorted({symbol.value for symbol in metadata.symbols if symbol.kind == 2 and symbol.section not in (0, 0xfff1)})
    discovery = report.get('code_discovery', {})
    code_roots = discovery.get('roots') if isinstance(discovery, dict) else None
    ranges = report.get('code_ranges')
    require(isinstance(code_roots, list) and all(type(root) is int for root in code_roots) and
        code_roots == sorted(set(code_roots)) and isinstance(ranges, list), 'invalid original code root receipt')
    previous_end, starts = 0, []
    for selected in ranges:
        require(isinstance(selected, (list, tuple)) and len(selected) == 2 and all(type(value) is int for value in selected),
            'invalid original code interval')
        start, end = selected
        require(start % 4 == end % 4 == 0 and previous_end <= start < end <= nso.sections[0].end, 'invalid original code interval')
        starts.append(start); previous_end = end
    root_set = set(code_roots)
    require(0 < len(roots) <= min(1_048_576, nso.sections[0].size // 4), 'missing/bounded callback roots')
    for root in roots:
        position = bisect_right(starts, root) - 1
        require(root % 4 == 0 and root in root_set and position >= 0 and root + 4 <= ranges[position][1], 'callback root lacks audited original code')
    checked_calls = verify_checked_calls(nso, metadata, discovery, rewrite, site_offsets, root_set, ranges)
    for item in checked_calls:
        require(struct.unpack_from('<I', image, item['offset'])[0] & 0xfc000000 == 0x14000000 and
            not any(origin['original_offset'] == item['offset'] for origin in provenance),
            'checked-call source must use its recorded direct stub without a native gate')
    checked_forests = verify_checked_call_forests(nso, metadata, image, discovery, rewrite,
        sites, ranges, fixups, provenance)
    audit = dict(callback_audit_version=1, package_sha256=digest, source_sha256=source['source_sha256'],
        indirect_policy='guarded-host', callback_root_kind='defined-stt-func', callback_roots=roots)
    require(report.get('callback_audit') == audit, 'callback receipt differs from original defined STT_FUNC entries')
    return dict(name=name, source_sha256=source['source_sha256'], package_sha256=digest, image_sha256=image_digest,
        package_bytes=len(data), image_bytes=image_size, callback_audit=audit,
        original_image_restored_sha256=sha(restored), site_count=site_count, gate_count=gate_count, fixup_count=fixup_count,
        versioned_checked_calls=checked_calls, versioned_checked_call_forests=checked_forests)


def verify_content(directory, modules, import_sha):
    directory = Path(directory); checked_stat(directory, directory=True)
    raw, manifest = json_file(directory / 'taiko-content.json', MAX_MANIFEST)
    require(isinstance(manifest, dict) and manifest.get('schema') == 1 and manifest.get('target') == 'taiko-android' and
        manifest.get('program_id') == PROGRAM_ID and manifest.get('selected_exefs_display_version') is None and
        manifest.get('module_order') == list(MODULE_ORDER) and manifest.get('sources') == source_records(),
        'content manifest original identity mismatch')
    expected_packages = [dict(name=module['name'], path='modules/' + module['name'] + '.dmag',
        bytes=module['package_bytes'], sha256=module['package_sha256'], source_sha256=module['source_sha256']) for module in modules]
    require(manifest.get('packages') == expected_packages, 'content package pins differ from audited original capsules')
    for package in expected_packages:
        actual, _ = digest_file(directory / package['path'])
        require(actual == {key: package[key] for key in ('bytes', 'sha256')}, 'content module differs from audited capsule')
    receipt = manifest.get('import_receipt')
    actual_receipt, _ = digest_file(directory / 'import.json')
    require(receipt == dict(path='import.json', **actual_receipt) and actual_receipt['sha256'] == import_sha,
        'content import receipt differs from audited original import')
    listed = manifest.get('files')
    require(isinstance(listed, list) and 0 < len(listed) <= MAX_FILES, 'content resource inventory must be nonempty and bounded')
    declared = {}; folded = set(); total = 0
    for item in listed:
        require(isinstance(item, dict) and set(item) == {'path', 'bytes', 'sha256'} and isinstance(item['path'], str),
            'malformed content resource record')
        path = item['path']; encoded = path.encode('utf-8')
        parts = path.split('/')
        require(1 < len(parts) <= 65 and parts[0] == 'RomFS' and len(encoded) < 4096, 'unsafe content resource path')
        for component in parts: validate_component(component)
        require(path not in declared and path.casefold() not in folded and type(item['bytes']) is int and
            0 <= item['bytes'] <= MAX_FILE_BYTES, 'duplicate/oversized content resource')
        require(isinstance(item['sha256'], str) and len(item['sha256']) == 64 and
            all(c in '0123456789abcdef' for c in item['sha256']), 'invalid resource digest')
        total += item['bytes']; require(total <= MAX_RESOURCE_BYTES, 'resource byte total exceeds bound')
        declared[path] = item; folded.add(path.casefold())
    actual_paths = set()
    for path, relative, is_directory in resource_tree(directory / 'RomFS'):
        if is_directory: continue
        resource = 'RomFS/' + relative
        require(resource in declared, 'extra resource outside declared inventory: ' + resource)
        actual, _ = digest_file(path)
        require(actual == {key: declared[resource][key] for key in ('bytes', 'sha256')}, 'resource hash/size mismatch: ' + resource)
        actual_paths.add(resource)
    require(actual_paths == set(declared), 'missing declared resource inventory')
    require(type(manifest.get('total_bytes')) is int and manifest['total_bytes'] ==
        total + sum(module['package_bytes'] for module in modules) + actual_receipt['bytes'], 'content byte total mismatch')
    return dict(schema=1, program_id=PROGRAM_ID, manifest_sha256=sha(raw),
        files=[declared[path] for path in sorted(declared, key=lambda path: path.encode('utf-8'))], total_bytes=total)


def emit_provider(model):
    def digest(value):
        require(isinstance(value, str) and len(value) == 64 and any(c != '0' for c in value) and
            all(c in '0123456789abcdef' for c in value), 'zero/malformed digest cannot enter compiled pins')
        return '{{' + ','.join('0x' + value[index:index+2] for index in range(0, 64, 2)) + '}}'
    def source_value(source):
        return '{' + json.dumps(source['name']) + ',' + ','.join(digest(source[key]) for key in
            ('source_sha256', 'decoded_sha256', 'build_id')) + ',' + str(source['source_bytes']) + 'ull}'
    def cpp_string(value):
        # Numeric UTF-8 byte escapes avoid source/execution charset ambiguity.
        return '"' + ''.join('\\%03o' % byte for byte in value.encode('utf-8')) + '"'
    lines = ['// Generated verified Taiko hash/integer facts; no game or shader bytes.',
        '#include "taiko_bringup.h"', '#include "taiko_resources.h"', 'namespace dm_android { namespace {']
    for index, module in enumerate(model['modules']):
        roots = module['callback_audit']['callback_roots']
        lines.append(f'static constexpr uint64_t roots_{index}[]={{' + ','.join(str(root) + 'ull' for root in roots) + '};')
    lines += ['static const TaikoSourcePin sources[]={', *(source_value(source) + ',' for source in model['sources']),
        '};', 'static const TaikoModulePin modules[]={']
    for index, module in enumerate(model['modules']):
        audit = module['callback_audit']
        lines.append('{' + json.dumps(module['name']) + ',' + digest(module['package_sha256']) + ',' + digest(module['image_sha256']) +
            f",{module['package_bytes']}ull,{module['image_bytes']}ull," + '{1,' + digest(module['package_sha256']) + ',' +
            digest(audit['source_sha256']) + ',CallbackIndirectPolicy::GuardedHost,CallbackRootKind::DefinedSttFunc,' +
            f'roots_{index},sizeof(roots_{index})/sizeof(uint64_t)' + '}},')
    lines += ['};', 'static const TaikoBuildPins build_pins={1,' + json.dumps(BUILD) + ',' + json.dumps(PROGRAM_ID) + ',' +
        digest(SOURCE_PINS['main.npdm']['sha256']) + ',' + source_value(model['rtld']) + ',sources,3,modules,3,' +
        digest(model['source_audit_sha256']) + ',' + digest(model['import_manifest_sha256']) + '};',
        'static const TaikoResourcePin resources[]={']
    content = model['content']
    for item in content['files']:
        lines.append('{' + cpp_string(item['path']) + ',' + str(item['bytes']) + 'ull,' + digest(item['sha256']) + '},')
    lines += ['};', 'static const TaikoContentPins content_pins={1,' + json.dumps(PROGRAM_ID) + ',' + digest(content['manifest_sha256']) +
        ',resources,sizeof(resources)/sizeof(resources[0]),' + str(content['total_bytes']) + 'ull};', '}',
        'const TaikoBuildPins* compiled_taiko_bringup_pins(){return &build_pins;}',
        'const TaikoContentPins* compiled_taiko_content_pins(){return &content_pins;}', '}']
    return '\n'.join(lines) + '\n'


def atomic_new(path, data):
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    published = False
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        # Same-directory hard link publishes a complete file without replacing
        # an existing provider even if another process creates it after checks.
        os.link(temporary, path)
        published = True
        Path(temporary).unlink(missing_ok=True)
    except BaseException:
        if published: path.unlink(missing_ok=True)
        Path(temporary).unlink(missing_ok=True)
        raise


def generate(source, capsules, content, output, audit_output):
    output, audit_output = (Path(os.path.abspath(path)) for path in (output, audit_output))
    private = ROOT / '.local'
    for path in (output, audit_output):
        require(path.is_relative_to(private) and not path.exists() and not path.is_symlink(), 'outputs must be fresh private .local files')
        checked_stat(path.parent, directory=True)
    require(output != audit_output and output.suffix == '.cpp' and audit_output.suffix == '.json', 'distinct provider.cpp/audit.json required')
    capsules = Path(capsules); checked_stat(capsules, directory=True)
    facts, objects = verify_sources(source)
    inventory = verify_import_closure(objects)
    raw, receipt = json_file(capsules / 'import.json', 512 * 1024 * 1024)
    require(isinstance(receipt, dict) and receipt.get('status') == 'prepared' and receipt.get('unsupported') == [] and
        receipt.get('format') == 'DMAMOD02' and receipt.get('abi') == ABI and receipt.get('checked_stack') is True and
        receipt.get('indirect_policy') == 'guarded-host' and receipt.get('module_order') == list(MODULE_ORDER) and
        isinstance(receipt.get('modules'), list) and len(receipt['modules']) == 3, 'original import is incomplete/rejected/noncanonical')
    modules = [verify_package(capsules / (name + '.dmag'), receipt['modules'][index], facts[name], *objects[name])
        for index, name in enumerate(MODULE_ORDER)]
    audit = dict(schema=1, build=BUILD, program_id=PROGRAM_ID, npdm_sha256=SOURCE_PINS['main.npdm']['sha256'],
        rtld=facts['rtld'], sources=[facts[name] for name in MODULE_ORDER], import_inventory=inventory,
        recipe_sha256={name: sha((ROOT / 'dm/tools' / name).read_bytes()) for name in
            ('gen_taiko_pins.py', 'taiko_content.py', 'taiko_call_contract.py', 'taiko_sdk_contract.py', 'taiko_forest_audit.py',
             'nso_eh.py', 'nso_format.py', 'android_import.py', 'android_rewrite.py', 'android_exclusive.py', 'android_instruction.py', 'android_diag_abort.py')},
        diag_abort_abi_header_sha256=abi_header_sha256())
    model = dict(schema=1, build=BUILD, program_id=PROGRAM_ID, rtld=facts['rtld'], sources=audit['sources'],
        modules=modules, source_audit=audit, source_audit_sha256=sha(canonical(audit)), import_manifest_sha256=sha(raw))
    model['content'] = verify_content(content, modules, model['import_manifest_sha256'])
    provider = emit_provider(model).encode('utf-8')
    # Recheck bounded originals at publication; never publish after a failed audit.
    validate_sources(source)
    atomic_new(audit_output, json.dumps(model, indent=2, ensure_ascii=True).encode('utf-8') + b'\n')
    try:
        atomic_new(output, provider)
    except BaseException:
        audit_output.unlink(missing_ok=True)
        raise
    return model


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--capsules', required=True, type=Path)
    parser.add_argument('--content', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--audit', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = generate(args.source, args.capsules, args.content, args.output, args.audit)
        print(json.dumps(dict(build=BUILD, module_order=list(MODULE_ORDER), output=str(args.output),
            content_files=len(result['content']['files']), resource_bytes=result['content']['total_bytes'])))
    except (ValueError, OSError, TypeError, KeyError, struct.error) as error:
        parser.exit(1, 'Taiko pins rejected: ' + str(error) + '\n')


if __name__ == '__main__': main()
