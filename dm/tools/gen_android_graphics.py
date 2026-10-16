#!/usr/bin/env python3
"""Compile a public NONE/class0 transfer/compute/authored-draw SDK NSO.

The canonical observation main/catalog are read-only inputs, never generated here.
Freestanding C uses the actual reconstructed NVN declarations; assembly provides
two explicit GOT calls, both targeting competing SDK definitions overridden FORCE.
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

ROOT=Path(__file__).resolve().parents[2]
FIXTURES=ROOT/'dm/platform/android/graphics_fixtures'
IMPORTS=('nvnBootstrapLoader','_ZN2nn2oe16GetOperationModeEv')
RO=0x10000
DATA=0x20000
BSS=0x21000

def assemble(tools):
    clang,objcopy=tools
    suffix='.exe' if clang.suffix=='.exe' else ''
    nm=clang.parent/('llvm-nm'+suffix)
    with tempfile.TemporaryDirectory(prefix='dm-graphics-') as temporary:
        elf=Path(temporary)/'graphics.elf'
        result=subprocess.run([str(clang),'--target=aarch64-linux-android29','-O2','-fpie',
            '-ffixed-x18','-fno-stack-protector','-fno-builtin','-fno-unwind-tables',
            '-fno-asynchronous-unwind-tables','-nostdlib','-static','-Werror','-Wall','-Wextra',
            '-I'+str(ROOT/'dm/gfx/nvn/include'),
            '-Wl,-T,'+str(FIXTURES/'fixture.ld'),'-Wl,--build-id=none',
            str(FIXTURES/'bootstrap.S'),str(FIXTURES/'graphics.c'),'-o',str(elf)],
            capture_output=True,text=True)
        if result.returncode: raise RuntimeError(result.stderr)
        sections={}
        for section in ('.text','.const','.data'):
            binary=Path(temporary)/(section[1:]+'.bin')
            subprocess.run([str(objcopy),'-O','binary','--only-section='+section,str(elf),str(binary)],check=True,capture_output=True)
            sections[section]=binary.read_bytes()
        listing=subprocess.run([str(nm),'-S','--defined-only','--format=posix',str(elf)],check=True,capture_output=True,text=True).stdout
        symbols={}
        for line in listing.splitlines():
            fields=line.split()
            if len(fields)==4 and fields[1] in ('T','t','D','d','B','b','R','r'):
                symbols[fields[0]]=(int(fields[2],16),int(fields[3],16),2 if fields[1] in ('T','t') else 1)
        return sections,symbols

def make_nso(sections,definitions):
    text=bytearray(sections['.text'])
    if len(text)>RO: raise ValueError('graphics text exceeds reserved NSO range')
    data=bytearray(4096);data[:len(sections['.data'])]=sections['.data']
    ro=bytearray(0x10000)
    if len(sections['.const'])>0xc000:raise ValueError('graphics constants exceed reserved RO')
    ro[0x4000:0x4000+len(sections['.const'])]=sections['.const']
    records,strings,indices=[bytes(24)],bytearray(b'\0'),{}
    for name in sorted(definitions):
        indices[name]=len(records);offset=len(strings);strings+=name.encode('ascii')+b'\0'
        value,size,kind=definitions[name]
        binding=0 if name in ('fixture_entry','fixture_init') else 1
        records.append(struct.pack('<IBBHQQ',offset,binding*16+kind,0,1,value,size))
    symbols=b''.join(records);ro[:len(symbols)]=symbols;ro[len(symbols):len(symbols)+len(strings)]=strings
    hash_offset=(len(symbols)+len(strings)+7)&-8
    words=[1,len(records),1,0]+[i+1 if i+1<len(records) else 0 for i in range(1,len(records))]
    hashed=struct.pack('<'+'I'*len(words),*words);ro[hash_offset:hash_offset+len(hashed)]=hashed
    rela_offset=(hash_offset+len(hashed)+7)&-8
    relas=b''.join(struct.pack('<QQq',DATA+i*8,indices[name]<<32|1026,0) for i,name in enumerate(IMPORTS))
    if rela_offset+len(relas)>0x4000: raise ValueError('graphics metadata exceeds RO')
    ro[rela_offset:rela_offset+len(relas)]=relas
    dynamic=[(5,RO+len(symbols)),(10,len(strings)),(6,RO),(11,24),(4,RO+hash_offset),
             (12,definitions['fixture_init'][0]),(23,RO+rela_offset),(2,len(relas)),(20,7),(0,0)]
    for i,(tag,value) in enumerate(dynamic):struct.pack_into('<qQ',data,0x400+i*16,tag,value)
    end=max(value+size for value,size,kind in definitions.values() if kind==1)
    bss=(end-BSS+4095)&-4096
    struct.pack_into('<I',text,0x4c,BSS+bss-0x40)
    header=bytearray(256);header[:4]=b'NSO0';struct.pack_into('<I',header,12,0x38)
    header[0x40:0x60]=hashlib.sha256(b'dm-public-graphics-v5-authored-sampled-carrier'+text+ro+data).digest()
    struct.pack_into('<IIII',header,0x90,len(symbols),len(strings),0,len(symbols))
    parts=[];cursor=256
    for i,(raw,memory) in enumerate(((text,0),(bytes(ro),RO),(bytes(data),DATA))):
        struct.pack_into('<IIII',header,0x10+i*16,cursor,memory,len(raw),bss if i==2 else 0)
        struct.pack_into('<I',header,0x60+i*4,len(raw));header[0xa0+i*32:0xc0+i*32]=hashlib.sha256(raw).digest()
        parts.append(raw);cursor+=len(raw)
    return bytes(header)+b''.join(parts)

def generate(tools):
    source=make_nso(*assemble(tools));package,report=import_module(source,'sdk',package_version=2,indirect_policy='guarded-host',callback_audit=True)
    audit=report['callback_audit']
    if audit['callback_audit_version']!=1 or audit['callback_root_kind']!='defined-stt-func' or audit['indirect_policy']!='guarded-host':
        raise ValueError('unsupported production callback audit receipt')
    if audit['package_sha256']!=hashlib.sha256(package).hexdigest():
        raise ValueError('production callback audit digest mismatch')
    lines=['// Generated public graphics SDK; NONE/class0, no game authority.','#pragma once','#include <stdint.h>','#include <stddef.h>','#include "../module_runtime.h"',
           'alignas(8) static const uint8_t dm_graphics_bytes[] = {']
    for i in range(0,len(package),24):lines.append('    '+','.join(f'0x{x:02x}' for x in package[i:i+24])+',')
    lines+=['};','static constexpr size_t dm_graphics_size=sizeof(dm_graphics_bytes);',
            'static const uint8_t dm_graphics_package_sha256[32]={'+','.join(f'0x{x:02x}' for x in hashlib.sha256(package).digest())+'};',
            'static constexpr uint64_t dm_graphics_callback_roots[]={'+','.join(str(x) for x in audit['callback_roots'])+'};',
            'static const dm_android::TrustedCallbackAudit dm_graphics_callback_audit={1,',
            '{'+','.join(f'0x{x:02x}' for x in bytes.fromhex(audit['package_sha256']))+'},',
            '{'+','.join(f'0x{x:02x}' for x in bytes.fromhex(audit['source_sha256']))+'},',
            'dm_android::CallbackIndirectPolicy::GuardedHost,dm_android::CallbackRootKind::DefinedSttFunc,',
            'dm_graphics_callback_roots,sizeof(dm_graphics_callback_roots)/sizeof(dm_graphics_callback_roots[0])};','']
    return {'graphics.nso':source,'graphics.dmag':package,'generated_graphics.h':'\n'.join(lines).encode(),
            'import.json':(json.dumps(report,indent=2)+'\n').encode()}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--ndk');parser.add_argument('--check',action='store_true');args=parser.parse_args()
    generated=generate(toolchain(args.ndk))
    for name,content in generated.items():
        path=FIXTURES/name
        if args.check:
            if not path.is_file() or path.read_bytes()!=content:raise SystemExit(f'{path} differs; regenerate graphics fixture')
        else:path.write_bytes(content)
    print(('Verified' if args.check else 'Generated')+' public NONE/class0 graphics SDK through production importer; original game NOT_RUN')

if __name__=='__main__':main()
