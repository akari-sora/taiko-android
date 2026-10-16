"""Source proof for the single required Android DiagAbort ABI v1.

This proves a selected standard PLT/GOT binding, not original AbortImpl's
semantics. Only the required native ABI and its exact canonical gate make a
consumed call monitor-retiring and non-returning. No JSON selects this proof.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import struct
from types import SimpleNamespace

from nso_format import parse_nso, parse_metadata

MODULE_REQUIRE_DIAG_ABORT_V1 = 2
DIAG_ABORT_IMPL_SYMBOL = '_ZN2nn4diag6detail9AbortImplEPKcS3_S3_i'
DIAG_ABORT_RESOLVER_V1 = '__dm_android_diag_abort_v1'
ABI_HEADER = Path(__file__).resolve().parents[1]/'platform/android/diag_abort_abi.h'


def abi_header_sha256():
    data=ABI_HEADER.read_bytes();text=data.decode('utf-8').replace('\r\n','\n')
    required=(r'^#define DM_MODULE_REQUIRE_DIAG_ABORT_V1 \(1u << 1\)$',
              '^#define DM_DIAG_ABORT_IMPL_SYMBOL "'+re.escape(DIAG_ABORT_IMPL_SYMBOL)+'"$',
              '^#define DM_DIAG_ABORT_RESOLVER_V1 "'+re.escape(DIAG_ABORT_RESOLVER_V1)+'"$')
    if any(len(re.findall(pattern,text,re.M))!=1 for pattern in required):
        raise ValueError('fixed DiagAbort ABI differs from its native contract header')
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class DiagAbortProof:
    calls: tuple = ()  # (original BL offset, selected PLT BR offset)
    plt_branches: frozenset = frozenset()
    coverage_error: str = ''


def _plt_got(pc,first,load,add):
    if (first&0x9F00001F!=0x90000010 or load&0xFFC003FF!=0xF9400211 or
            add&0xFFC003FF!=0x91000210):return None
    immediate=(first>>5&0x7ffff)<<2|(first>>29&3)
    if immediate&0x100000:immediate-=0x200000
    displacement=(load>>10&4095)*8
    if add>>10&4095!=displacement:return None
    return (pc&~4095)+(immediate<<12)+displacement


def _check_complete_coverage(nso,metadata,branches):
    required=set()
    for relocation in metadata.relocations:
        if not 0<relocation.symbol<len(metadata.symbols):continue
        symbol=metadata.symbols[relocation.symbol]
        if symbol.name!=DIAG_ABORT_IMPL_SYMBOL:continue
        if relocation.kind!=1026 or relocation.addend:
            raise ValueError('required DiagAbort ABI has an unsupported original relocation')
        required.add(relocation.offset)
    found=set();raw=nso.image
    # Rejection-only coverage audit, matching the native binder. A syntactic
    # PLT in unselected code/data is never promoted to an executable entrance.
    for pc in range(0,nso.sections[0].end-12,4):
        first=struct.unpack_from('<I',raw,pc)[0]
        if first&0x9F00001F!=0x90000010:continue
        load,add,branch=struct.unpack_from('<3I',raw,pc+4)
        got=_plt_got(pc,first,load,add)
        if got not in required:continue
        if branch!=0xD61F0220 or pc+12 not in branches:
            raise ValueError('required DiagAbort ABI has an uncovered or unselected original PLT')
        found.add(got)
    if not required or found!=required:
        raise ValueError('required DiagAbort ABI lacks complete original PLT coverage')


def selected_diag_abort_proof(nso,metadata,by_pc):
    """Private pipeline input must already come from parse_nso/parse_metadata."""
    raw=nso.image;text_end=nso.sections[0].end
    relocations={}
    for row in metadata.relocations:relocations.setdefault(row.offset,[]).append(row)
    def word_at(pc):
        ins=by_pc.get(pc)
        if (ins is None or pc%4 or not 0<=pc<=text_end-4 or
                ins.bytes!=raw[pc:pc+4] or
                any(start<pc+4 and pc<end for start,end in metadata.protected)):
            return None
        return struct.unpack_from('<I',raw,pc)[0]
    plts={}
    for pc in by_pc:
        first=word_at(pc)
        if first is None or first&0x9F00001F!=0x90000010:continue
        load,add,branch=(word_at(pc+offset) for offset in (4,8,12))
        if (load is None or add is None or branch!=0xD61F0220 or
                load&0xFFC003FF!=0xF9400211 or add&0xFFC003FF!=0x91000210):
            continue
        got=_plt_got(pc,first,load,add)
        if got is None:continue
        if not any(section.offset<=got and got+8<=section.end for section in nso.sections[1:]):continue
        rows=relocations.get(got,())
        if len(rows)!=1:continue
        relocation=rows[0]
        if relocation.kind!=1026 or relocation.addend or not 0<relocation.symbol<len(metadata.symbols):continue
        symbol=metadata.symbols[relocation.symbol]
        if (symbol.name!=DIAG_ABORT_IMPL_SYMBOL or symbol.kind!=2 or symbol.binding!=1 or symbol.visibility!=0 or
                symbol.section==0xfff1 or symbol.section and
                (symbol.value%4 or not 0<symbol.value<=text_end-4 or
                 any(start<=symbol.value<end for start,end in metadata.protected))):
            continue
        plts[pc]=pc+12
    calls=[]
    for pc in by_pc:
        value=word_at(pc)
        if value is None or value&0xFC000000!=0x94000000:continue
        immediate=value&0x3ffffff
        if immediate&0x2000000:immediate-=0x4000000
        target=pc+immediate*4
        if target in plts:calls.append((pc,plts[target]))
    coverage_error=''
    if plts:
        abi_header_sha256()
        try:_check_complete_coverage(nso,metadata,frozenset(plts.values()))
        except ValueError as error:coverage_error=str(error)
    return DiagAbortProof(tuple(sorted(calls)),frozenset(plts.values()),coverage_error)


def verify_diag_abort_source(source,raw,by_pc):
    if type(source) is not bytes:
        raise ValueError('DiagAbort proof requires immutable original NSO bytes, never offsets or JSON')
    nso=parse_nso(source)
    if nso.image!=raw:
        raise ValueError('DiagAbort final source proof differs from the original decoded NSO image')
    return selected_diag_abort_proof(nso,parse_metadata(nso),by_pc)


def verified_monitor_retiring_calls(source,raw,by_pc):
    return frozenset(pc for pc,_ in verify_diag_abort_source(source,raw,by_pc).calls)


def validate_required_package(nso,metadata,data,receipt):
    """Check actual capsule gate bytes against original source, never JSON alone."""
    calls=receipt.get('diag_abort_call_sites');branches=receipt.get('diag_abort_plt_branches')
    for values in (calls,branches):
        if (type(values) is not list or not values or any(type(pc) is not int or pc%4 or
                not 0<=pc<=nso.sections[0].end-4 for pc in values) or values!=sorted(set(values))):
            raise ValueError('required DiagAbort source/gate receipt is missing or malformed')
    if receipt.get('required_diag_abort_abi')!=DIAG_ABORT_RESOLVER_V1:
        raise ValueError('required DiagAbort resolver ABI mismatch')
    selected=set(calls)
    for pc in branches:selected.update(range(pc-12,pc+4,4))
    source_words={pc:SimpleNamespace(bytes=nso.image[pc:pc+4]) for pc in selected if pc>=0}
    proof=selected_diag_abort_proof(nso,metadata,source_words)
    if (proof.coverage_error or frozenset(pc for pc,_ in proof.calls)!=frozenset(calls) or
            proof.plt_branches!=frozenset(branches)):
        raise ValueError('required DiagAbort receipt does not prove complete original ABI PLTs and calls')
    payload=struct.unpack_from('<Q',data,112)[0];image_size=struct.unpack_from('<Q',data,24)[0]
    image=data[payload:payload+image_size]
    gate_start,gate_count=struct.unpack_from('<QQ',data,136)
    site_start,site_count=struct.unpack_from('<QQ',data,152)
    if (gate_start+gate_count*32>payload or site_start+site_count*16>payload or payload+image_size!=len(data)):
        raise ValueError('required DiagAbort capsule record extent mismatch')
    gates=[struct.unpack_from('<QQIIII',data,at) for at in range(gate_start,gate_start+gate_count*32,32)]
    sites=[struct.unpack_from('<QQ',data,at) for at in range(site_start,site_start+site_count*16,16)]
    for pc in branches:
        matching=[gate for gate in gates if gate[1]==pc];rewrites=[site for site in sites if site[0]==pc]
        if len(matching)!=1 or len(rewrites)!=1:
            raise ValueError('required DiagAbort PLT is missing its unique gate or rewrite site')
        returned,_,kind,argument,word,flags=matching[0];trampoline=rewrites[0][1]
        if (kind!=4 or argument!=17 or word!=0xD61F0220 or flags or
                returned%4 or not 4<=returned<=len(image)-4 or
                image[returned-4:returned]!=struct.pack('<I',0xD63F03C0) or
                trampoline%4 or not 0<=trampoline<returned or
                image[pc-12:pc]!=nso.image[pc-12:pc]):
            raise ValueError('required DiagAbort PLT canonical gate/provenance differs from original source')
        branch=struct.unpack_from('<I',image,pc)[0];offset=branch&0x3ffffff
        if offset&0x2000000:offset-=0x4000000
        if branch&0xFC000000!=0x14000000 or pc+offset*4!=trampoline:
            raise ValueError('required DiagAbort PLT does not branch to its recorded controlled gate')
    if any(image[pc:pc+4]!=nso.image[pc:pc+4] for pc in calls):
        raise ValueError('required DiagAbort consumed source call has changed')


def publication_contract_obligation(nso,metadata):
    """Derive consumed ABI necessity from canonical original code roles only.

    Discovery supplies analysis coverage, never native/callback entry authority.
    Capsule sites, rewritten bytes and receipt claims cannot select or erase
    this source proof. The existing finite ticket and PLT validators own its
    semantics; unknown canonical control flow remains a publication refusal.
    """
    import android_rewrite as ar
    # Import locally: android_import also imports the rewrite/DiagAbort core.
    import android_import as importer
    from bisect import bisect_right

    if not any(0<row.symbol<len(metadata.symbols) and
               metadata.symbols[row.symbol].name==DIAG_ABORT_IMPL_SYMBOL
               for row in metadata.relocations):
        return DiagAbortProof(),frozenset()
    try:
        ranges,_=importer.discover_code(nso,metadata,indirect_policy='guarded-host',checked_stack=True)
    except importer.ImportError as error:
        raise ValueError('DiagAbort publication canonical source discovery failed: '+str(error)) from error
    starts=[start for start,_ in ranges]
    raw=nso.image

    class OriginalWords(dict):
        def __iter__(self):
            for start,end in ranges:
                yield from range(start,end,4)
        def __contains__(self,pc):return self.get(pc) is not None
        def __getitem__(self,pc):
            value=self.get(pc)
            if value is None:raise KeyError(pc)
            return value
        def get(self,pc,default=None):
            if type(pc) is not int or pc%4:return default
            index=bisect_right(starts,pc)-1
            if index<0 or pc+4>ranges[index][1]:return default
            if not dict.__contains__(self,pc):
                ins=ar.decode(struct.unpack_from('<I',raw,pc)[0],pc)
                self[pc]=ins if isinstance(ins,ar.FatalWord) else ar.Instruction(ins)
            return dict.__getitem__(self,pc)

    by_pc=OriginalWords()
    proof=selected_diag_abort_proof(nso,metadata,by_pc)
    calls=dict(proof.calls)
    if not calls:return DiagAbortProof(),frozenset()

    class OriginalKinds:
        def get(self,pc,default=None):
            ins=by_pc.get(pc)
            if ins is None:return default
            if ins.mnemonic not in ('cmp','cmn') and any(ins.reg_name(r) in ('sp','wsp') for r in ins.regs_access()[1]):
                return 'stack_check' if ar.stack_check_operation(struct.unpack('<I',ins.bytes)[0]) is not None else 'unsupported_sp'
            return ar.site_kind(ins)

    kinds=OriginalKinds();used=set();heads=set();verified=frozenset(calls)
    for pc in by_pc:
        ins=by_pc[pc]
        if ins.mnemonic not in ar.EXCLUSIVE_LOADS:continue
        region=(ar.android_exclusive.retiring_ticket_attempt(ins,by_pc,kinds,ar,monitor_retiring_calls=verified) or
                ar.android_exclusive.writer_ticket_attempt(ins,by_pc,kinds,ar,monitor_retiring_calls=verified))
        if region is not None and region.requires_diag_abort_v1:
            used.update(region.monitor_retiring_call_sites);heads.add(pc)
    return DiagAbortProof(tuple((pc,calls[pc]) for pc in sorted(used)),
                          proof.plt_branches if used else frozenset(),proof.coverage_error if used else ''),frozenset(heads)


def validate_publication_contract(nso,metadata,data,receipt):
    """Check source necessity even when capsule and receipt declarations vanish."""
    proof,heads=publication_contract_obligation(nso,metadata)
    needed=bool(proof.calls)
    flagged=bool(struct.unpack_from('<I',data,20)[0]&MODULE_REQUIRE_DIAG_ABORT_V1)
    declared=receipt.get('requires_diag_abort_v1',False)
    if type(declared) is not bool or needed!=flagged or needed!=declared:
        raise ValueError('source-derived required DiagAbort obligation differs from flags or receipt')
    if needed:
        if (proof.coverage_error or receipt.get('diag_abort_call_sites')!=[pc for pc,_ in proof.calls] or
                receipt.get('diag_abort_plt_branches')!=sorted(proof.plt_branches)):
            raise ValueError(proof.coverage_error or 'source-derived DiagAbort consumed calls or PLTs differ from receipt')
        validate_required_package(nso,metadata,data,receipt)
        # Necessity is already proved above. Preserve the exact lowering-site
        # requirement independently of generic generator receipt strictness.
        payload=struct.unpack_from('<Q',data,112)[0]
        image_size=struct.unpack_from('<Q',data,24)[0]
        site_start,site_count=struct.unpack_from('<QQ',data,152)
        if site_start<384 or site_start>payload or site_count>(payload-site_start)//16:
            raise ValueError('required DiagAbort ticket site extent is invalid')
        sites=[struct.unpack_from('<QQ',data,at) for at in range(site_start,site_start+site_count*16,16)]
        for pc in heads:
            matching=[target for original,target in sites if original==pc]
            if len(matching)!=1 or matching[0]%4 or not len(nso.image)<=matching[0]<=image_size-4:
                raise ValueError('required DiagAbort ticket head lacks its unique lowering site')
            word=struct.unpack_from('<I',data,payload+pc)[0]
            delta=word&0x3ffffff
            if delta&0x2000000:delta-=0x4000000
            if word&0xfc000000!=0x14000000 or pc+delta*4!=matching[0]:
                raise ValueError('required DiagAbort ticket head does not branch to its lowering site')
