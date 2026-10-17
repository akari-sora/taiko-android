"""TDD verification for DMAMOD03 source selector, lowering, loader and kind-6 dispatch."""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid


ROOT = Path(__file__).resolve().parents[4]
LIVE = Path(os.environ.get("TAIKO_LIVE_REPO", ROOT))
EVIDENCE = Path(os.environ.get("DM_TEST_OUTPUT_ROOT", "")) if os.environ.get("DM_TEST_OUTPUT_ROOT") else None
sys.path[:0] = [str(ROOT / "dm/tools"), str(LIVE / "dm/tools"), str(Path(__file__).parent)]

import android_exclusive as ae
import android_guest_contract as contract
import android_import as importer
import android_rewrite as ar
import gen_android_graphics as builder
from nso_eh import validated_eh_functions
from nso_format import parse_metadata, parse_nso
from test_android_guest_contract_v3_native import cpp_bytes
from test_android_guest_contract_v3_runtime import wsl_path
from test_nso_format import write_image


TAIKO_SDK_PATH = Path(
    os.environ.get(
        "TAIKO_SDK_NSO",
        r"C:\Users\aa223\Documents\Codex\2026-10-12\10m-10s-jhaizhou-ops-d2r-mobile\games\taiko-extract\ExeFS\sdk",
    )
)


def _plt_words(plt_pc: int, got_offset: int) -> tuple[int, int, int, int]:
    page_delta = ((got_offset & ~0xFFF) - (plt_pc & ~0xFFF)) >> 12
    immlo = (page_delta & 3) << 29
    immhi = ((page_delta >> 2) & 0x7FFFF) << 5
    adrp = 0x90000010 | immlo | immhi
    off = got_offset & 0xFFF
    ldr = 0xF9400211 | ((off // 8) << 10)
    add = 0x91000210 | (off << 10)
    br = 0xD61F0220
    return (adrp, ldr, add, br)


def _cond_branch(pc: int, target: int, cond: int) -> int:
    return 0x54000000 | ((((target - pc) // 4) & 0x7FFFF) << 5) | (cond & 0xF)


def _cbz_x(pc: int, target: int, reg: int, *, nonzero: bool = False) -> int:
    op = 0xB5000000 if nonzero else 0xB4000000
    return op | ((((target - pc) // 4) & 0x7FFFF) << 5) | (reg & 0x1F)


def _cbz_w(pc: int, target: int, reg: int, *, nonzero: bool = False) -> int:
    op = 0x35000000 if nonzero else 0x34000000
    return op | ((((target - pc) // 4) & 0x7FFFF) << 5) | (reg & 0x1F)


def _tbz_w(pc: int, target: int, reg: int, bit: int, *, nonzero: bool = False) -> int:
    op = 0x37000000 if nonzero else 0x36000000
    return op | ((bit & 0x1F) << 19) | ((((target - pc) // 4) & 0x3FFF) << 5) | (reg & 0x1F)


def build_synthetic_v3_sdk() -> tuple[bytes, contract.GuestContractSourceSpec]:
    """Build a compact self-contained NSO with 5 exact-guest PLTs, bindtextdomain, and Leave."""
    text = bytearray(struct.pack("<I", 0xD65F03C0) * (0x1000 // 4))
    # Header at 0: b 0x100 at 0 and MOD0 offset 0x40 at 4 (matching gen_android_graphics.py).
    struct.pack_into("<I", text, 0, ar.branch(0, 0x100))
    struct.pack_into("<I", text, 4, 0x40)
    # DT_INIT function at 0x100..0x120: includes an unknown pointer store (str x0, [x1])
    # so discover_code marks relocation_slots_clobbered_by_code = True, matching Taiko SDK.
    struct.pack_into(
        "<8I",
        text,
        0x100,
        0xA9BF7BFD,  # stp x29, x30, [sp, #-0x10]!
        0x910003FD,  # mov x29, sp
        0xF9000020,  # str x0, [x1] -> clobbers relocation slots in static analysis
        ar.branch(0x10C, 0x500) | 0x80000000,  # bl bindtextdomain (0x500)
        ar.branch(0x110, 0x700) | 0x80000000,  # bl PLT 0 (UnlockMutex)
        ar.branch(0x114, 0x760) | 0x80000000,  # bl PLT 3 (nnosUnlockMutex)
        0xA8C17BFD,  # ldp x29, x30, [sp], #0x10
        0xD65F03C0,  # ret
    )

    # Target 0: _ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE at [0x200, 0x220) (8 words, FDE-backed)
    struct.pack_into(
        "<8I",
        text,
        0x200,
        0xA9BF7BFD,
        0x910003FD,
        0x91000000,
        ar.branch(0x20C, 0x740) | 0x80000000,  # bl PLT 2 (Leave)
        0x52800000,
        0xD503201F,
        0xA8C17BFD,
        0xD65F03C0,
    )

    # Target 1: strcmp at [0x280, 0x298) (6 words, symbol_size=0, no FDE, closed local CFG + zero padding)
    struct.pack_into(
        "<6I",
        text,
        0x280,
        0x39400008,  # ldrb w8, [x0]
        0x39400029,  # ldrb w9, [x1]
        0x6B090108,  # subs w8, w8, w9
        _cond_branch(0x28C, 0x294, 1),  # b.ne 0x294
        0x2A0803E0,  # mov w0, w8
        0xD65F03C0,  # ret
    )
    for pad_pc in range(0x298, 0x300, 4):
        struct.pack_into("<I", text, pad_pc, 0)

    # Target 2: InternalCriticalSectionImplByHorizon::Leave at [0x300, 0x380) (32 words, FDE-backed)
    # Exact same instruction sequence as Taiko SDK Leave [0x37f7d4, 0x37f854).
    struct.pack_into(
        "<32I",
        text,
        0x300,
        0xD10083FF,  # 0x300: sub sp, sp, #0x20
        0xA9017BFD,  # 0x304: stp x29, x30, [sp, #0x10]
        0x910043FD,  # 0x308: add x29, sp, #0x10
        0xD53BD068,  # 0x30c: mrs x8, tpidrro_el0
        0xF940FD08,  # 0x310: ldr x8, [x8, #0x1f8]
        0xB941B108,  # 0x314: ldr w8, [x8, #0x1b0]
        0x885FFC09,  # 0x318: ldaxr w9, [x0] (head)
        0x6B08013F,  # 0x31c: cmp w9, w8
        _cond_branch(0x320, 0x33C, 1),  # 0x320: b.ne 0x33c (clrex)
        0x2A1F03E9,  # 0x324: mov w9, wzr
        0x880AFC09,  # 0x328: stlxr w10, w9, [x0] (store)
        _cbz_w(0x32C, 0x344, 10),  # 0x32c: cbz w10, 0x344
        0x885FFC09,  # 0x330: ldaxr w9, [x0] (retry_head)
        0x6B08013F,  # 0x334: cmp w9, w8
        _cond_branch(0x338, 0x324, 0),  # 0x338: b.eq 0x324
        0xD5033F5F,  # 0x33c: clrex
        0x2A0903E8,  # 0x340: mov w8, w9
        _tbz_w(0x344, 0x354, 8, 30),  # 0x344: tbz w8, #0x1e, 0x354
        ar.branch(0x348, 0x390) | 0x80000000,  # 0x348: bl 0x390 (svc #0x1b; ret)
        0xB9000BE0,  # 0x34c: str w0, [sp, #8]
        _cbz_w(0x350, 0x360, 0, nonzero=True),  # 0x350: cbnz w0, 0x360
        0xA9417BFD,  # 0x354: ldp x29, x30, [sp, #0x10]
        0x910083FF,  # 0x358: add sp, sp, #0x20
        0xD65F03C0,  # 0x35c: ret
        0x90000080,  # 0x360: adrp x0, #0x10000
        0x91000000,  # 0x364: add x0, x0, #0
        0x910023E4,  # 0x368: add x4, sp, #8
        0xAA0003E1,  # 0x36c: mov x1, x0
        0xAA0003E2,  # 0x370: mov x2, x0
        0x2A1F03E3,  # 0x374: mov w3, wzr
        0xAA0003E5,  # 0x378: mov x5, x0
        ar.branch(0x37C, 0x7A0) | 0x80000000,  # 0x37c: bl 0x7a0 (long AbortImpl PLT)
    )

    # Helper at 0x390: svc #0x1b; ret
    struct.pack_into("<2I", text, 0x390, 0xD4000361, 0xD65F03C0)
    # Helper at 0x3A0: unlock wrapper (b PLT 4 at 0x780), matching 0x56ce70 in Taiko SDK
    struct.pack_into("<I", text, 0x3A0, ar.branch(0x3A0, 0x780))

    # Target 3: nnosUnlockMutex at [0x400, 0x404) (1 word, FDE-backed)
    struct.pack_into("<I", text, 0x400, ar.branch(0x400, 0x700))

    # Target 4: __nnmusl_UnlockLock at [0x600, 0x604) (1 word, FDE-backed)
    struct.pack_into("<I", text, 0x600, ar.branch(0x600, 0x760))

    # Owned function bindtextdomain at [0x500, 0x5A0) (40 words, FDE-backed)
    # Mirrors the exact Taiko bindtextdomain exclusive head/store, shared DEAD/LIVE block,
    # two returning-retire BL callsites (0x548 -> 0x3A0 and 0x578 -> 0x720), post-return cycle,
    # and 5 native restores + RET at 0x550..0x564.
    struct.pack_into(
        "<40I",
        text,
        0x500,
        0xA9BB7BFD,  # 0x500: stp x29, x30, [sp, #-0x50]!
        0xF9000BF9,  # 0x504: str x25, [sp, #0x10]
        0x910003FD,  # 0x508: mov x29, sp
        0xA9025FF8,  # 0x50c: stp x24, x23, [sp, #0x20]
        0xA90357F6,  # 0x510: stp x22, x21, [sp, #0x30]
        0xA9044FF4,  # 0x514: stp x20, x19, [sp, #0x40]
        _cbz_x(0x518, 0x550, 0),  # 0x518: cbz x0, 0x550 (restores)
        0xC85FFD2A,  # 0x51c: ldaxr x10, [x9] (exclusive_head)
        0xEB08015F,  # 0x520: cmp x10, x8
        _cond_branch(0x524, 0x534, 1),  # 0x524: b.ne 0x534 (LIVE path into shared block)
        0xC80AFD34,  # 0x528: stlxr w10, x20, [x9] (matching_store -> LIVE_TO_DEAD)
        _cbz_w(0x52C, 0x51C, 10, nonzero=True),  # 0x52c: cbnz w10, 0x51c
        ar.branch(0x530, 0x538),  # 0x530: b 0x538 (DEAD path into shared block)
        0xD5033BBF,  # 0x534: dmb ish (LIVE)
        0x52800028,  # 0x538: mov w8, #1 (shared LIVE + DEAD)
        0xF9405735,  # 0x53c: ldr x21, [x25, #0xa8]
        _cbz_x(0x540, 0x570, 21, nonzero=True),  # 0x540: cbnz x21, 0x570
        0xAA1303E0,  # 0x544: mov x0, x19
        ar.branch(0x548, 0x3A0) | 0x80000000,  # 0x548: bl 0x3a0 (retire callsite 0)
        0xF9400E80,  # 0x54c: ldr x0, [x20, #0x18] (normal_return 0, DEAD)
        0xA9444FF4,  # 0x550: ldp x20, x19, [sp, #0x40] (restore 0)
        0xA94357F6,  # 0x554: ldp x22, x21, [sp, #0x30] (restore 1)
        0xA9425FF8,  # 0x558: ldp x24, x23, [sp, #0x20] (restore 2)
        0xF9400BF9,  # 0x55c: ldr x25, [sp, #0x10] (restore 3)
        0xA8C57BFD,  # 0x560: ldp x29, x30, [sp], #0x50 (restore 4)
        0xD65F03C0,  # 0x564: ret (restore 5)
        0xF94002B5,  # 0x568: ldr x21, [x21] (post-return loop head, DEAD)
        _cbz_x(0x56C, 0x544, 21),  # 0x56c: cbz x21, 0x544
        0xF9400A80,  # 0x570: ldr x0, [x20, #0x10] (LIVE + DEAD)
        0xAA1303E1,  # 0x574: mov x1, x19
        ar.branch(0x578, 0x720) | 0x80000000,  # 0x578: bl 0x720 (retire callsite 1 -> strcmp PLT)
        0xEB1402BF,  # 0x57c: cmp x21, x20 (normal_return 1, DEAD)
        _cond_branch(0x580, 0x568, 0),  # 0x580: b.eq 0x568
        _cbz_w(0x584, 0x568, 0, nonzero=True),  # 0x584: cbnz w0, 0x568
        0xD5033BBF,  # 0x588: dmb ish
        0xB9000EBF,  # 0x58c: str wzr, [x21, #0xc]
        0xD5033BBF,  # 0x590: dmb ish
        ar.branch(0x594, 0x568),  # 0x594: b 0x568
        0xD503201F,  # 0x598: nop (unreachable padding? No, keep all words reachable!)
        0xD503201F,  # 0x59c
    )
    # Make bindtextdomain end at 0x598 so every single word in [0x500, 0x598) is reachable!
    bind_end = 0x598

    # 6 PLTs at 0x700, 0x720, 0x740, 0x760, 0x780, 0x7A0
    plts = (
        (0x700, builder.DATA + 0x00, "_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE"),
        (0x720, builder.DATA + 0x08, "strcmp"),
        (0x740, builder.DATA + 0x10, "_ZN2nn2os6detail36InternalCriticalSectionImplByHorizon5LeaveEv"),
        (0x760, builder.DATA + 0x18, "nnosUnlockMutex"),
        (0x780, builder.DATA + 0x20, "__nnmusl_UnlockLock"),
        (0x7A0, builder.DATA + 0x28, "_ZN2nn4diag6detail9AbortImplEPKcS3_S3_iPKNS_6ResultES3_z"),
    )
    for plt_pc, got_off, _ in plts:
        struct.pack_into("<4I", text, plt_pc, *_plt_words(plt_pc, got_off))

    # Build .eh_frame_hdr and .eh_frame in .const (mapped at 0x14000)
    cie_off = 0x14100
    cie = struct.pack("<II", 16, 0) + b"\x01zR\x00\x01\x78\x1e\x01\x1b\x0c\x1f\x00"
    eh_ranges = (
        (0x100, 0x120),
        (0x200, 0x220),
        (0x300, 0x380),
        (0x400, 0x404),
        (0x500, bind_end),
        (0x600, 0x604),
    )
    fdes = bytearray()
    rows = bytearray()
    fde_map = {}
    for s, e in eh_ranges:
        fde_off = cie_off + len(cie) + len(fdes)
        fde_map[s] = fde_off
        rows += struct.pack("<ii", s - 0x14000, fde_off - 0x14000)
        fdes += struct.pack("<IIiiI", 16, (fde_off + 4) - cie_off, s - (fde_off + 8), e - s, 0)
    fdes += struct.pack("<I", 0)
    hdr = struct.pack("<BBBBiI", 1, 0x1B, 0x03, 0x3B, cie_off - 0x14004, len(eh_ranges)) + bytes(rows)
    const = bytearray(0x300)
    const[: len(hdr)] = hdr
    const[0x100 : 0x100 + len(cie) + len(fdes)] = cie + fdes

    # MOD0 header at 0x40 (since word 0 is 0 and word 4 is 0x40)
    struct.pack_into(
        "<4s6i",
        text,
        0x40,
        b"MOD0",
        builder.DATA + 0x400 - 0x40,
        builder.BSS - 0x40,
        builder.BSS + 0x1000 - 0x40,
        0x14000 - 0x40,
        0x14000 + len(hdr) - 0x40,
        builder.DATA + 0x300 - 0x40,
    )

    definitions = {
        "fixture_init": (0x100, 0x20, 2),
        "_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE": (0x200, 0x20, 2),
        "strcmp": (0x280, 0, 2),
        "_ZN2nn2os6detail36InternalCriticalSectionImplByHorizon5LeaveEv": (0x300, 0x80, 2),
        "svc_1b_helper": (0x390, 8, 2),
        "unlock_wrapper": (0x3A0, 4, 2),
        "nnosUnlockMutex": (0x400, 4, 2),
        "bindtextdomain": (0x500, bind_end - 0x500, 2),
        "__nnmusl_UnlockLock": (0x600, 4, 2),
        "_ZN2nn4diag6detail9AbortImplEPKcS3_S3_iPKNS_6ResultES3_z": (0, 0, 2),
        "public_bss": (builder.BSS, 0x100, 1),
    }
    imports = tuple(name for _, _, name in plts)
    with patch.object(builder, "IMPORTS", imports):
        raw_nso = bytearray(builder.make_nso({".text": bytes(text), ".const": bytes(const), ".data": b""}, definitions))
    nso_tmp = parse_nso(raw_nso)
    meta_tmp = parse_metadata(nso_tmp)
    # Mark long AbortImpl as SHN_UNDEF (section 0) and the 5 contracted symbols as section 1
    abort_idx = next(i for i, s in enumerate(meta_tmp.symbols) if s.name.startswith("_ZN2nn4diag6detail9AbortImpl"))
    struct.pack_into("<I", raw_nso, 12, 0)  # disable segment hashes so we can edit dynsym/dynamic cleanly
    write_image(raw_nso, meta_tmp.dynamic[6] + abort_idx * 24 + 6, "<H", 0)
    # Add a DT_RELA table (1 R_AARCH64_RELATIVE entry) so jmprel_offset_index == 1 > 0
    dt_rela_off = (meta_tmp.dynamic[23] + meta_tmp.dynamic[2] + 7) & -8
    write_image(raw_nso, dt_rela_off, "<QQq", builder.DATA + 0x80, 1027, 0x100)
    dyn_entries = [
        (5, meta_tmp.dynamic[5]),
        (10, meta_tmp.dynamic[10]),
        (6, meta_tmp.dynamic[6]),
        (11, 24),
        (4, meta_tmp.dynamic[4]),
        (12, meta_tmp.dynamic[12]),
        (7, dt_rela_off),
        (8, 24),
        (9, 24),
        (23, meta_tmp.dynamic[23]),
        (2, meta_tmp.dynamic[2]),
        (20, 7),
        (0, 0),
    ]
    for idx, (d_tag, d_val) in enumerate(dyn_entries):
        write_image(raw_nso, builder.DATA + 0x400 + idx * 16, "<qQ", d_tag, d_val)
    source = bytes(raw_nso)
    nso = parse_nso(source)
    metadata = parse_metadata(nso)

    # Build the matching GuestContractSourceSpec for this synthetic NSO
    sym_by_name = {s.name: (i, s) for i, s in enumerate(metadata.symbols)}
    exact_specs = []
    target_ranges = {
        "_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE": (0x200, 0x220, 1, fde_map[0x200], cie_off),
        "strcmp": (0x280, 0x298, 0, 0, 0),
        "_ZN2nn2os6detail36InternalCriticalSectionImplByHorizon5LeaveEv": (0x300, 0x380, 1, fde_map[0x300], cie_off),
        "nnosUnlockMutex": (0x400, 0x404, 1, fde_map[0x400], cie_off),
        "__nnmusl_UnlockLock": (0x600, 0x604, 1, fde_map[0x600], cie_off),
    }
    for rel_idx, (plt_pc, got_off, name) in enumerate(plts[:5], start=1):
        sym_idx, sym = sym_by_name[name]
        st_name = struct.unpack_from("<I", nso.image, metadata.dynamic[6] + sym_idx * 24)[0]
        f_start, f_end, eh_kind, fde_o, cie_o = target_ranges[name]
        f_sha = hashlib.sha256(nso.image[f_start:f_end]).hexdigest()
        exact_specs.append(
            contract.ExactGuestSiteSpec(
                original_br_offset=plt_pc + 12,
                original_br_word=0xD61F0220,
                target_register=17,
                got_offset=got_off,
                relocation_index=rel_idx,
                relocation_type=1026,
                symbol_index=sym_idx,
                symbol_name=name,
                symbol_type=2,
                symbol_binding=1,
                symbol_visibility=0,
                relocation_addend=0,
                symbol_name_offset=st_name,
                symbol_name_length=len(name),
                symbol_section_index=sym.section,
                eh_identity_kind=eh_kind,
                symbol_value=sym.value,
                symbol_size=sym.size,
                same_module_target_offset=f_start,
                function_start=f_start,
                function_end=f_end,
                fde_offset=fde_o,
                cie_offset=cie_o,
                independent_root_offset=f_start,
                function_sha256_hex=f_sha,
            )
        )
    retire_spec = contract.ReturningRetireFunctionSpec(
        function_start=0x500,
        function_end=bind_end,
        fde_offset=fde_map[0x500],
        cie_offset=cie_off,
        exclusive_head=0x51C,
        matching_store=0x528,
        function_sha256_hex=hashlib.sha256(nso.image[0x500:bind_end]).hexdigest(),
        calls=(
            contract.ReturningRetireCallSpec(
                source_callsite=0x548,
                original_bl_word=struct.unpack_from("<I", nso.image, 0x548)[0],
                stub_extent=8,
                original_target=0x3A0,
                normal_return=0x54C,
                reserved_stub_delta=0,
            ),
            contract.ReturningRetireCallSpec(
                source_callsite=0x578,
                original_bl_word=struct.unpack_from("<I", nso.image, 0x578)[0],
                stub_extent=8,
                original_target=0x720,
                normal_return=0x57C,
                reserved_stub_delta=8,
            ),
        ),
        restores=tuple(
            (pc, struct.unpack_from("<I", nso.image, pc)[0])
            for pc in (0x550, 0x554, 0x558, 0x55C, 0x560, 0x564)
        ),
    )
    leave_spec = contract.LeaveMonitorSpec(
        entry=0x300,
        end=0x380,
        head=0x318,
        retry_head=0x330,
        store=0x328,
        clrex_sites=(0x33C,),
        svc_1b_callsite=0x348,
        svc_1b_target=0x390,
        ret_site=0x35C,
        exceptional_callsite=0x37C,
        exceptional_plt_target=0x7A0,
    )
    spec = contract.GuestContractSourceSpec(
        source_sha256_hex=nso.source_sha256.hex(),
        build_id_hex=nso.build_id.hex(),
        exact_guest_sites=tuple(exact_specs),
        returning_retire=retire_spec,
        leave_monitor=leave_spec,
    )
    return source, spec


class GuestContractDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synth_source, cls.synth_spec = build_synthetic_v3_sdk()

    def test_taiko_source_selector_rederives_five_exact_and_two_retire_records_and_rejects_mutations(self):
        self.assertNotIn(0x1B, ar.SVC_MONITOR_RETIRE, "SVC 0x1B must never be a global monitor retirement primitive")
        if TAIKO_SDK_PATH.is_file():
            raw_sdk = TAIKO_SDK_PATH.read_bytes()
            nso = parse_nso(raw_sdk)
            metadata = parse_metadata(nso)
            spec = contract.TAIKO_SDK_GUEST_CONTRACT_SPEC
            self.assertEqual(nso.source_sha256.hex(), spec.source_sha256_hex)
            self.assertEqual(nso.build_id.hex(), spec.build_id_hex)
            # Disassemble only the needed functions/PLTs for fast direct selector verification on frozen SDK
            pcs = set()
            for site in spec.exact_guest_sites:
                pcs.update(range(site.original_br_offset - 12, site.original_br_offset + 4, 4))
                pcs.update(range(site.function_start, site.function_end, 4))
            ret = spec.returning_retire
            pcs.update(range(ret.function_start, ret.function_end, 4))
            for call in ret.calls:
                pcs.add(call.original_target)
            lv = spec.leave_monitor
            pcs.update(range(lv.entry, lv.end, 4))
            pcs.update((lv.svc_1b_target, lv.svc_1b_target + 4, lv.exceptional_plt_target))
            by_pc = {
                pc: ar.Instruction(ar.decode(struct.unpack_from("<I", nso.image, pc)[0], pc))
                for pc in sorted(pcs)
            }
            roots = {s.same_module_target_offset for s in spec.exact_guest_sites} | {ret.function_start, lv.svc_1b_target}
            selection = contract.select_taiko_guest_contract(
                raw_sdk,
                nso.image,
                by_pc,
                independent_roots=roots,
                final_roots=roots,
                patch_offset=0xDA8000,
            )
            self.assertEqual(len(selection.exact_guest_records), 5)
            self.assertEqual(len(selection.returning_retire_records), 2)
            self.assertEqual(
                [r.original_br_offset for r in selection.exact_guest_records],
                [0x5B27FC, 0x5BA08C, 0x5C91AC, 0x5CFB9C, 0x5D38CC],
            )
            self.assertEqual(
                [r.source_callsite for r in selection.returning_retire_records],
                [0x56975C, 0x56978C],
            )
            self.assertEqual(
                [r.reserved_stub_offset for r in selection.returning_retire_records],
                [0xDA8000, 0xDA8008],
            )
            strcmp_rec = selection.exact_guest_records[1]
            self.assertEqual((strcmp_rec.symbol_value, strcmp_rec.symbol_size, strcmp_rec.eh_identity_kind), (0x5AD3C0, 0, 0))
            self.assertEqual((strcmp_rec.function_start, strcmp_rec.function_end), (0x5AD3C0, 0x5AD48C))

            # Zero-sized strcmp cannot be accepted from symbol size/name alone without pinned closed CFG bounds
            bad_strcmp = replace(spec.exact_guest_sites[1], function_end=0x5AD488)
            bad_spec = replace(
                spec,
                exact_guest_sites=(
                    spec.exact_guest_sites[0],
                    bad_strcmp,
                    *spec.exact_guest_sites[2:],
                ),
            )
            with self.assertRaises(contract.GuestContractError):
                contract.select_taiko_guest_contract(
                    raw_sdk, nso.image, by_pc, independent_roots=roots, final_roots=roots, patch_offset=0xDA8000, spec=bad_spec
                )

            # Mutating Leave CLREX at 0x37f810 to NOP leaves reservation live at SVC 0x1B / RET / exceptional call
            bad_by_pc = dict(by_pc)
            bad_by_pc[0x37F810] = ar.Instruction(ar.decode(0xD503201F, 0x37F810))
            with self.assertRaisesRegex(contract.GuestContractError, "Leave|live|Instruction"):
                contract.select_taiko_guest_contract(
                    raw_sdk, nso.image, bad_by_pc, independent_roots=roots, final_roots=roots, patch_offset=0xDA8000
                )

    def test_exclusive_planner_and_emitter_lower_returning_retire_stubs_and_kind6_gates(self):
        with patch.object(contract, "TAIKO_SDK_GUEST_CONTRACT_SPEC", self.synth_spec):
            package, report = importer.import_module(
                self.synth_source,
                "sdk",
                package_version=3,
                indirect_policy="guarded-host",
                checked_stack=True,
            )
        self.assertEqual(package[:8], b"DMAMOD03")
        flags = struct.unpack_from("<I", package, 20)[0]
        self.assertEqual(
            flags,
            1 | contract.DM_MODULE_REQUIRE_EXACT_GUEST_V1 | contract.DM_MODULE_REQUIRE_RETURNING_RETIRE_V1,
        )
        # All 5 contracted PLTs + 1 long AbortImpl PLT remain guarded in discovery, not proven_guest
        discovery = report["code_discovery"]
        self.assertTrue(discovery["relocation_slots_clobbered_by_code"])
        for br_pc in (0x70C, 0x72C, 0x74C, 0x76C, 0x78C, 0x7AC):
            self.assertIn(br_pc, discovery["guarded_indirect_sites"])
            self.assertNotIn(br_pc, discovery["proven_indirect_sites"])

        # Long AbortImpl is NOT treated as short __dm_android_diag_abort_v1
        self.assertFalse(report["rewrite"].get("requires_diag_abort_v1", False))

        # Check DMAMOD03 header & tables
        patch_offset, patch_size, payload_offset = struct.unpack_from("<QQQ", package, 96)
        exact_offset, exact_count = struct.unpack_from("<QQ", package, 384)
        retire_offset, retire_count = struct.unpack_from("<QQ", package, 408)
        self.assertEqual(exact_count, 5)
        self.assertEqual(retire_count, 2)

        # Verify both returning-retire stubs are reserved FIRST at patch_offset + 0 and patch_offset + 8
        retire_records = [
            contract.ReturningRetireRecordV1.unpack(package[retire_offset + i * 192 : retire_offset + (i + 1) * 192])
            for i in range(2)
        ]
        self.assertEqual([r.reserved_stub_offset for r in retire_records], [patch_offset, patch_offset + 8])
        for rec in retire_records:
            # Source callsite is patched with BL (0x94000000), NOT B (0x14000000)
            bl_word = struct.unpack_from("<I", package, payload_offset + rec.source_callsite)[0]
            self.assertEqual(bl_word & 0xFC000000, 0x94000000)
            self.assertEqual(bl_word, ar.branch(rec.source_callsite, rec.reserved_stub_offset) | 0x80000000)
            # Stub word 0 is CLREX (0xD5033F5F), word 1 is direct B original_target
            stub_w0, stub_w1 = struct.unpack_from("<2I", package, payload_offset + rec.reserved_stub_offset)
            self.assertEqual(stub_w0, 0xD5033F5F)
            self.assertEqual(stub_w1, ar.branch(rec.reserved_stub_offset + 4, rec.original_target))

        # Verify all 5 exact gates use kind 6 (DM_GUEST_EXACT_GUEST = 6, argument = 17)
        # while the 6th PLT (long AbortImpl at 0x7AC) remains kind 4 (INDIRECT_HOST = 4)
        gate_offset, gate_count = struct.unpack_from("<QQ", package, 136)
        gates_by_origin = {}
        for i in range(gate_count):
            ret_off, orig_off, kind, arg, orig_word, gflags = struct.unpack_from("<QQIIII", package, gate_offset + i * 32)
            gates_by_origin[orig_off] = (ret_off, kind, arg, orig_word, gflags)
        for br_pc in (0x70C, 0x72C, 0x74C, 0x76C, 0x78C):
            self.assertEqual(gates_by_origin[br_pc][1:], (contract.DM_GUEST_EXACT_GUEST, 17, 0xD61F0220, 0))
            ret_off = gates_by_origin[br_pc][0]
            # Gate tail after return_offset is ldp x29, x30, [sp]; add sp, sp, #16; br x17
            tail_ldp, tail_add, tail_br = struct.unpack_from("<3I", package, payload_offset + ret_off)
            self.assertEqual((tail_ldp, tail_add, tail_br), (0xA9407BFD, 0x910043FF, 0xD61F0220))
        self.assertEqual(gates_by_origin[0x7AC][1:], (ar.INDIRECT_HOST, 17, 0xD61F0220, 0))

        # Verify guest_contract_audit in report
        audit = report["guest_contract_audit"]
        contract.validate_trusted_audit_v1(audit)
        self.assertEqual(audit["package_sha256"], hashlib.sha256(package).hexdigest())

        # Negative test: missing one of the two ReturningRetireCallSpecs leaves a LIVE path and rejects
        one_call_retire = replace(self.synth_spec.returning_retire, calls=(self.synth_spec.returning_retire.calls[0],))
        with patch.object(contract, "TAIKO_SDK_GUEST_CONTRACT_SPEC", replace(self.synth_spec, returning_retire=one_call_retire)):
            with self.assertRaises((importer.ImportError, ar.RewriteError, contract.GuestContractError)):
                importer.import_module(
                    self.synth_source, "sdk", package_version=3, indirect_policy="guarded-host", checked_stack=True
                )

        # Negative test: interior root inside bindtextdomain rejects
        nso = parse_nso(self.synth_source)
        ranges, disc = importer.discover_code(nso, parse_metadata(nso), indirect_policy="guarded-host", checked_stack=True)
        with patch.object(contract, "TAIKO_SDK_GUEST_CONTRACT_SPEC", self.synth_spec):
            with self.assertRaises((ar.RewriteError, contract.GuestContractError)):
                ar.rewrite(
                    nso.image,
                    0x100,
                    nso.sections[0].end,
                    code_ranges=ranges,
                    entry_offsets=sorted(set(disc["roots"]) | {0x538}),
                    package_version=3,
                    checked_stack=True,
                    indirect_policy="guarded-host",
                    independent_entry_offsets=disc["independent_roots"],
                    guarded_indirect_offsets=disc["guarded_indirect_sites"],
                    readonly_ranges=((nso.sections[1].offset, nso.sections[1].end),),
                    guest_contract_source=self.synth_source,
                )

    def test_native_loader_single_resolution_and_guarded_guest_dispatch_matrix(self):
        with patch.object(contract, "TAIKO_SDK_GUEST_CONTRACT_SPEC", self.synth_spec):
            package, report = importer.import_module(
                self.synth_source,
                "sdk",
                package_version=3,
                indirect_policy="guarded-host",
                checked_stack=True,
            )
        audit = report["guest_contract_audit"]
        package_sha = bytes.fromhex(audit["package_sha256"])

        # Build a canonical empty (0/0) checked-stack DMAMOD03 'main' module for multi-module graph verification
        main_raw = bytearray(self.synth_source)
        # Replace exclusive instructions in 0x300..0x350 and 0x51C..0x534 with NOPs so 'main' has 0 retire/exact records
        for nop_pc in (0x318, 0x328, 0x330, 0x33C, 0x51C, 0x528, 0x52C):
            write_image(main_raw, nop_pc, "<I", 0xD503201F)
        main_package, main_report = importer.import_module(
            bytes(main_raw),
            "main",
            package_version=3,
            indirect_policy="guarded-host",
            checked_stack=True,
        )
        self.assertEqual(main_package[:8], b"DMAMOD03")
        self.assertNotIn("guest_contract_audit", main_report)
        main_sha = hashlib.sha256(main_package).digest()

        if EVIDENCE is not None:
            run = EVIDENCE / "native-runs" / ("dmamod03-dispatch-" + uuid.uuid4().hex)
            run.mkdir(parents=True)
        else:
            tmp_dir = tempfile.TemporaryDirectory(prefix="dmamod03-dispatch-")
            self.addCleanup(tmp_dir.cleanup)
            run = Path(tmp_dir.name)
        stage = run / "src"
        stage.mkdir(parents=True)
        overlay_platform = ROOT / "dm/platform/android"
        live_platform = LIVE / "dm/platform/android"
        for name in (
            "module_runtime.cpp",
            "module_runtime.h",
            "guest_abi.h",
            "guest_parameter_layout.h",
            "guest_contract_abi.h",
            "guest_contract_wire.h",
            "guest_contract_wire.cpp",
            "guest_loader.cpp",
            "guest_loader_internal.h",
            "guest_stack_check.h",
            "observation_profile.h",
            "observation_profile.cpp",
            "module_sha256.h",
            "module_sha256.cpp",
            "diag_abort_abi.h",
        ):
            src_path = overlay_platform / name if (overlay_platform / name).is_file() else live_platform / name
            shutil.copy2(src_path, stage / name)

        arrays = "".join(
            (
                cpp_bytes("lowered_package", package),
                cpp_bytes("package_sha", package_sha),
                cpp_bytes("empty_main_package", main_package),
                cpp_bytes("empty_main_sha", main_sha),
                cpp_bytes("source_sha", bytes.fromhex(audit["source_sha256"])),
                cpp_bytes("build_id", bytes.fromhex(audit["build_id"])),
                cpp_bytes("recipe_sha", bytes.fromhex(audit["toolset_recipe_sha256"])),
                cpp_bytes("audit_sha", bytes.fromhex(audit["audit_identity_sha256"])),
                cpp_bytes("exact_table_sha", bytes.fromhex(audit["exact_guest"]["table_sha256"])),
                cpp_bytes("retire_table_sha", bytes.fromhex(audit["returning_retire"]["table_sha256"])),
                cpp_bytes("roots_sha", bytes.fromhex(audit["final_independent_roots_sha256"])),
                cpp_bytes("proof_sha", bytes.fromhex(audit["whole_function_ownership_proof_sha256"])),
            )
        )

        harness = (
            r"""
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#define private public
#include "module_runtime.h"
#undef private
#include "observation_profile.h"
using namespace dm_android;
"""
            + arrays
            + r"""
extern "C" void dm_android_state_accessor() {}
extern "C" void dm_android_dispatch_gate() {}
extern "C" __attribute__((noreturn)) void dm_android_diag_abort_entry(uint64_t,uint64_t,uint64_t,uint64_t){std::abort();}

template<size_t N> void load32(std::array<uint8_t,32>& out, const uint8_t(&in)[N]) {
    static_assert(N == 32);
    std::copy_n(in, 32, out.begin());
}

TrustedGuestContractAuditV1 make_audit() {
    TrustedGuestContractAuditV1 a{};
    load32(a.package_sha256, package_sha);
    load32(a.source_sha256, source_sha);
    load32(a.build_id, build_id);
    load32(a.toolset_recipe_sha256, recipe_sha);
    load32(a.audit_identity_sha256, audit_sha);
    a.exact_guest_count = 5;
    load32(a.exact_guest_table_sha256, exact_table_sha);
    a.returning_retire_count = 2;
    load32(a.returning_retire_table_sha256, retire_table_sha);
    load32(a.final_independent_roots_sha256, roots_sha);
    load32(a.whole_function_ownership_proof_sha256, proof_sha);
    return a;
}

std::unique_ptr<ModulePackage> decode_admitted() {
    std::unique_ptr<ModulePackage> out;
    std::string error;
    auto a = make_audit();
    if (!decode_package_with_guest_contract_audit(lowered_package, sizeof(lowered_package), package_sha, a, &out, &error)) {
        std::cerr << "decode_admitted failed: " << error << "\n";
        std::abort();
    }
    return out;
}

std::unique_ptr<ModulePackage> decode_empty_main() {
    std::unique_ptr<ModulePackage> out;
    std::string error;
    if (!decode_package(empty_main_package, sizeof(empty_main_package), empty_main_sha, &out, &error)) {
        std::cerr << "decode_empty_main failed: " << error << "\n";
        std::abort();
    }
    return out;
}

struct ResolverState {
    std::unordered_map<std::string, unsigned> forced_queries;
    std::unordered_map<std::string, unsigned> ordinary_queries;
    std::string force_hit_symbol;
    uintptr_t force_hit_value = 0xdeadbeef0000ULL;
};

bool tracking_resolver(const char* name, bool forced_only, uintptr_t* address, void* context) {
    auto* state = static_cast<ResolverState*>(context);
    std::string sym(name ? name : "");
    if (forced_only) {
        state->forced_queries[sym]++;
        if (!state->force_hit_symbol.empty() && sym == state->force_hit_symbol) {
            *address = state->force_hit_value;
            return true;
        }
        return false;
    }
    state->ordinary_queries[sym]++;
    if (sym == "_ZN2nn4diag6detail9AbortImplEPKcS3_S3_iPKNS_6ResultES3_z") {
        *address = 0x70001000ULL;
        return true;
    }
    return false;
}

int main() {
    // 1. Positive load: single forced query per exact record, zero ordinary queries for exact records,
    // own-module definition written to GOT and frozen in FrozenGate, with non-empty DT_RELA (jmprel_offset_index == 1).
    Process process;
    ResolverState rstate{};
    {
        auto pkg = decode_admitted();
        std::vector<std::unique_ptr<ModulePackage>> graph;
        graph.push_back(std::move(pkg));
        std::string error;
        if (!process.load(std::move(graph), tracking_resolver, &rstate, &error)) {
            std::cerr << "positive Process::load failed: " << error << "\n";
            std::abort();
        }
    }
    assert(process.modules_.size() == 1);
    const auto& mod = *process.modules_[0];
    const auto base = reinterpret_cast<uintptr_t>(mod.mapping.base);
    assert(mod.mapping.sealed);
    // Verify DT_RELA (index 0, R_AARCH64_RELATIVE at 0x20080 with addend 0x100) was bound before DT_JMPREL (indices 1..6)
    uint64_t rela0_val = 0;
    std::memcpy(&rela0_val, static_cast<const uint8_t*>(mod.mapping.base) + 0x20080, sizeof(rela0_val));
    assert(rela0_val == base + 0x100);
    const char* exact_names[5] = {
        "_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE",
        "strcmp",
        "_ZN2nn2os6detail36InternalCriticalSectionImplByHorizon5LeaveEv",
        "nnosUnlockMutex",
        "__nnmusl_UnlockLock"
    };
    const uint64_t expected_targets[5] = {0x200, 0x280, 0x300, 0x400, 0x600};
    const uint64_t expected_gots[5] = {0x20000, 0x20008, 0x20010, 0x20018, 0x20020};
    for (int i = 0; i < 5; ++i) {
        assert(mod.package->exact_guest_records[i].relocation_index == static_cast<uint32_t>(i + 1));
        assert(rstate.forced_queries[exact_names[i]] == 1);
        assert(rstate.ordinary_queries[exact_names[i]] == 0);
        uint64_t got_val = 0;
        std::memcpy(&got_val, static_cast<const uint8_t*>(mod.mapping.base) + expected_gots[i], sizeof(got_val));
        assert(got_val == base + expected_targets[i]);
    }

    // 2. Positive & negative exact_guest_site checks for all 5 kind-6 gates
    const auto gen = process.load_generation();
    for (int i = 0; i < 5; ++i) {
        const auto& rec = mod.package->exact_guest_records[i];
        const uint64_t return_pc = base + rec.gate_return_offset;
        const DmGuestGate* gate = Process::gate_resolver(&process, return_pc);
        assert(gate != nullptr);
        assert(gate->kind == DM_GUEST_EXACT_GUEST && gate->argument == 17);
        const uint64_t expected_x17 = base + rec.same_module_target_offset;
        assert(process.exact_guest_site(return_pc, gate, expected_x17, gen));

        // Reject null, misaligned, interior (+4), another valid root, appended RX, or host address
        assert(!process.exact_guest_site(return_pc, gate, 0, gen));
        assert(!process.exact_guest_site(return_pc, gate, expected_x17 + 2, gen));
        assert(!process.exact_guest_site(return_pc, gate, expected_x17 + 4, gen));
        const uint64_t other_root = base + expected_targets[(i + 1) % 5];
        assert(!process.exact_guest_site(return_pc, gate, other_root, gen));
        assert(!process.exact_guest_site(return_pc, gate, return_pc, gen));
        assert(!process.exact_guest_site(return_pc, gate, 0x70001000ULL, gen));

        // Reject wrong generation, wrong return_pc, or copied gate pointer
        assert(!process.exact_guest_site(return_pc, gate, expected_x17, 0));
        assert(!process.exact_guest_site(return_pc, gate, expected_x17, gen + 1));
        assert(!process.exact_guest_site(return_pc + 4, gate, expected_x17, gen));
        DmGuestGate fake_gate = *gate;
        assert(!process.exact_guest_site(return_pc, &fake_gate, expected_x17, gen));
    }

    // 3. Reject if mapping is unsealed or package admission is revoked
    process.modules_[0]->mapping.sealed = false;
    {
        const auto& rec = mod.package->exact_guest_records[0];
        const uint64_t return_pc = base + rec.gate_return_offset;
        const DmGuestGate* gate = Process::gate_resolver(&process, return_pc);
        assert(!process.exact_guest_site(return_pc, gate, base + rec.same_module_target_offset, gen));
    }
    process.modules_[0]->mapping.sealed = true;

    // 4. Multi-module v3 graph: canonical empty v3 module ('main' 0/0) + lowered v3 module ('sdk' 5/2)
    {
        auto main_pkg = decode_empty_main();
        auto sdk_pkg = decode_admitted();
        assert(main_pkg->exact_guest_records.empty() && main_pkg->returning_retire_records.empty());
        std::vector<std::unique_ptr<ModulePackage>> multi_graph;
        multi_graph.push_back(std::move(main_pkg));
        multi_graph.push_back(std::move(sdk_pkg));
        ResolverState multi_state{};
        std::string error;
        Process multi_proc;
        if (!multi_proc.load(std::move(multi_graph), tracking_resolver, &multi_state, &error)) {
            std::cerr << "multi-module v3 Process::load failed: " << error << "\n";
            std::abort();
        }
        assert(multi_proc.modules_.size() == 2);
        const auto& sdk_mod = *multi_proc.modules_[1];
        const auto sdk_base = reinterpret_cast<uintptr_t>(sdk_mod.mapping.base);
        const auto multi_gen = multi_proc.load_generation();
        for (int i = 0; i < 5; ++i) {
            const auto& rec = sdk_mod.package->exact_guest_records[i];
            const uint64_t return_pc = sdk_base + rec.gate_return_offset;
            const DmGuestGate* gate = Process::gate_resolver(&multi_proc, return_pc);
            assert(gate != nullptr);
            assert(multi_proc.exact_guest_site(return_pc, gate, sdk_base + rec.same_module_target_offset, multi_gen));
        }
    }

    // 5. Negative load: forced resolver hit must fail closed even if it returns the exact numeric address
    for (int i = 0; i < 5; ++i) {
        auto pkg = decode_admitted();
        std::vector<std::unique_ptr<ModulePackage>> graph;
        graph.push_back(std::move(pkg));
        ResolverState bad_state{};
        bad_state.force_hit_symbol = exact_names[i];
        bad_state.force_hit_value = base + expected_targets[i];
        std::string error;
        Process p2;
        assert(!p2.load(std::move(graph), tracking_resolver, &bad_state, &error));
    }

    // 6. Negative load: mutated post-decode retire stub (CLREX removed) or source BL changed to B must fail closed
    {
        auto pkg = decode_admitted();
        const uint64_t stub_off = pkg->returning_retire_records[0].reserved_stub_offset;
        pkg->bytes[stub_off] ^= 1;  // corrupt CLREX
        std::vector<std::unique_ptr<ModulePackage>> graph;
        graph.push_back(std::move(pkg));
        ResolverState s{};
        std::string error;
        Process p2;
        assert(!p2.load(std::move(graph), tracking_resolver, &s, &error));
    }
    {
        auto pkg = decode_admitted();
        const uint64_t call_off = pkg->returning_retire_records[0].source_callsite;
        pkg->bytes[call_off + 3] &= 0x7F;  // change BL (0x94) to B (0x14)
        std::vector<std::unique_ptr<ModulePackage>> graph;
        graph.push_back(std::move(pkg));
        ResolverState s{};
        std::string error;
        Process p2;
        assert(!p2.load(std::move(graph), tracking_resolver, &s, &error));
    }

    std::cout << "DMAMOD03 native loader & kind-6 dispatch matrix PASS\n";
    return 0;
}
"""
        )
        cpp = stage / "dispatch_test.cpp"
        cpp.write_text(harness, encoding="ascii")
        sources = [
            stage / "dispatch_test.cpp",
            stage / "module_runtime.cpp",
            stage / "guest_contract_wire.cpp",
            stage / "guest_loader.cpp",
            stage / "observation_profile.cpp",
            stage / "module_sha256.cpp",
        ]
        exe = run / "dispatch_test"
        arguments = [
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-error=misleading-indentation",
            "-pthread",
            f"-I{stage}",
            f"-I{live_platform}",
            *map(str, sources),
            "-o",
            str(exe),
        ]
        if os.name == "nt":
            self.assertTrue(Path(r"C:\Windows\System32\wsl.exe").is_file())
            compiler = "/usr/bin/c++"
            linux_args = [
                arg if not (len(arg) > 2 and arg[1] == ":") else wsl_path(Path(arg))
                for arg in arguments
            ]
            linux_args = [
                ("-I" + wsl_path(Path(arg[2:])))
                if arg.startswith("-I") and len(arg) > 3 and arg[3] == ":"
                else arg
                for arg in linux_args
            ]
            command = " ".join(map(shlex.quote, [compiler, *linux_args]))
            compiled = subprocess.run(["wsl.exe", "-e", "sh", "-lc", command], capture_output=True)
            run_command = ["wsl.exe", "-e", wsl_path(exe)]
        else:
            compiler = shutil.which("c++") or shutil.which("g++") or shutil.which("clang++")
            self.assertIsNotNone(compiler)
            compiled = subprocess.run([compiler, *arguments], capture_output=True)
            run_command = [str(exe)]
        compile_stdout = compiled.stdout.decode("utf-8", errors="replace")
        compile_stderr = compiled.stderr.decode("utf-8", errors="replace")
        self.assertEqual(compiled.returncode, 0, compile_stdout + compile_stderr)
        executed = subprocess.run(run_command, capture_output=True)
        run_stdout = executed.stdout.decode("utf-8", errors="replace")
        run_stderr = executed.stderr.decode("utf-8", errors="replace")
        self.assertEqual(executed.returncode, 0, run_stdout + run_stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
