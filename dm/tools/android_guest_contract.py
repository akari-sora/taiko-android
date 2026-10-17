"""Canonical host-only DMAMOD03 typed wire helpers.

This module freezes byte encoding and audit digest domains.  It contains no
game selector, production addresses, lowering, dispatch, or provider logic.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import struct
from typing import Mapping, Sequence


MAGIC_V3 = b"DMAMOD03"
HEADER_SIZE_V3 = 512
EXACT_GUEST_STRIDE_V1 = 288
RETURNING_RETIRE_STRIDE_V1 = 192
EXACT_GUEST_SCHEMA_V1 = 1
RETURNING_RETIRE_SCHEMA_V1 = 1
DM_MODULE_REQUIRE_EXACT_GUEST_V1 = 1 << 2
DM_MODULE_REQUIRE_RETURNING_RETIRE_V1 = 1 << 3
DM_GUEST_EXACT_GUEST = 6
EXACT_GUEST_ARGUMENT_REGISTER = 17

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_U64 = re.compile(r"0x[0-9a-f]{16}\Z")
_U32 = re.compile(r"0x[0-9a-f]{8}\Z")
_PATH = re.compile(r"[\x21-\x7e]+\Z")
ZERO_DIGEST = bytes(32)


class GuestContractError(ValueError):
    pass


def _integer(name: str, value: int, bits: int, *, signed: bool = False) -> int:
    if type(value) is not int:
        raise GuestContractError(f"{name} must be an integer")
    low = -(1 << (bits - 1)) if signed else 0
    high = (1 << (bits - (1 if signed else 0))) - 1
    if not low <= value <= high:
        raise GuestContractError(f"{name} is outside {'i' if signed else 'u'}{bits}")
    return value


def _digest(name: str, value: bytes, *, allow_zero: bool = False) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        raise GuestContractError(f"{name} must be exactly 32 bytes")
    if not allow_zero and value == ZERO_DIGEST:
        raise GuestContractError(f"{name} cannot use the distinguished zero digest")
    return value


def _aligned(name: str, value: int, alignment: int = 4) -> int:
    _integer(name, value, 64)
    if value % alignment:
        raise GuestContractError(f"{name} must be {alignment}-byte aligned")
    return value


@dataclass(frozen=True)
class ExactGuestRecordV1:
    gate_return_offset: int
    original_br_offset: int
    original_br_word: int
    target_register: int
    got_offset: int
    relocation_index: int
    relocation_type: int
    symbol_index: int
    symbol_type: int
    symbol_binding: int
    symbol_visibility: int
    relocation_addend: int
    symbol_name_offset: int
    symbol_name_length: int
    symbol_section_index: int
    eh_identity_kind: int
    symbol_value: int
    symbol_size: int
    same_module_target_offset: int
    function_start: int
    function_end: int
    fde_offset: int
    cie_offset: int
    independent_root_offset: int
    symbol_name_sha256: bytes
    function_sha256: bytes
    eh_identity_sha256: bytes
    final_independent_roots_sha256: bytes
    schema: int = EXACT_GUEST_SCHEMA_V1
    flags: int = 0

    def validate(self) -> "ExactGuestRecordV1":
        if self.schema != 1 or self.flags != 0:
            raise GuestContractError("exact record schema/flags must be 1/0")
        for name in ("gate_return_offset", "original_br_offset", "same_module_target_offset",
                     "function_start", "function_end", "fde_offset", "cie_offset",
                     "independent_root_offset"):
            _aligned(name, getattr(self, name))
        _aligned("got_offset", self.got_offset, 8)
        for name in ("original_br_word", "target_register", "relocation_index", "relocation_type",
                     "symbol_index", "symbol_name_offset", "symbol_name_length",
                     "symbol_section_index", "eh_identity_kind"):
            _integer(name, getattr(self, name), 32)
        for name in ("symbol_type", "symbol_binding", "symbol_visibility"):
            _integer(name, getattr(self, name), 8)
        _integer("relocation_addend", self.relocation_addend, 64, signed=True)
        for name in ("symbol_value", "symbol_size"):
            _integer(name, getattr(self, name), 64)
        if self.original_br_word != 0xD61F0220 or self.target_register != 17:
            raise GuestContractError("exact source must be the canonical BR x17")
        if not self.symbol_name_length or self.symbol_name_offset + self.symbol_name_length > 1 << 32:
            raise GuestContractError("exact symbol-name range is invalid")
        if not self.function_start < self.function_end:
            raise GuestContractError("exact function range is empty or reversed")
        if not self.function_start <= self.same_module_target_offset < self.function_end:
            raise GuestContractError("same-module target is outside its function")
        _digest("symbol_name_sha256", self.symbol_name_sha256)
        _digest("function_sha256", self.function_sha256)
        _digest("final_independent_roots_sha256", self.final_independent_roots_sha256)
        if self.eh_identity_kind == 0:
            if (self.function_start != self.symbol_value or
                    (self.symbol_size and self.function_end != self.symbol_value + self.symbol_size) or
                    self.fde_offset or self.cie_offset or self.eh_identity_sha256 != ZERO_DIGEST):
                raise GuestContractError("kind-0 EH identity is not an exact symbol range")
        elif self.eh_identity_kind == 1:
            if not self.fde_offset or not self.cie_offset:
                raise GuestContractError("kind-1 EH identity lacks indexed FDE/CIE")
            _digest("eh_identity_sha256", self.eh_identity_sha256)
        else:
            raise GuestContractError("unknown EH identity kind")
        return self

    def pack(self) -> bytes:
        self.validate()
        result = bytearray(EXACT_GUEST_STRIDE_V1)
        struct.pack_into("<IIQQIIQIIIBBBBqIIIIQQQQQQQQ", result, 0,
                         self.schema, self.flags, self.gate_return_offset,
                         self.original_br_offset, self.original_br_word,
                         self.target_register, self.got_offset, self.relocation_index,
                         self.relocation_type, self.symbol_index, self.symbol_type,
                         self.symbol_binding, self.symbol_visibility, 0,
                         self.relocation_addend, self.symbol_name_offset,
                         self.symbol_name_length, self.symbol_section_index,
                         self.eh_identity_kind, self.symbol_value, self.symbol_size,
                         self.same_module_target_offset, self.function_start,
                         self.function_end, self.fde_offset, self.cie_offset,
                         self.independent_root_offset)
        result[144:176] = self.symbol_name_sha256
        result[176:208] = self.function_sha256
        result[208:240] = self.eh_identity_sha256
        result[240:272] = self.final_independent_roots_sha256
        return bytes(result)

    @classmethod
    def unpack(cls, value: bytes) -> "ExactGuestRecordV1":
        if type(value) is not bytes or len(value) != EXACT_GUEST_STRIDE_V1:
            raise GuestContractError("exact record has wrong size")
        if value[55] or any(value[272:288]):
            raise GuestContractError("exact record has nonzero reserved bytes")
        v = struct.unpack_from("<IIQQIIQIIIBBBBqIIIIQQQQQQQQ", value)
        return cls(gate_return_offset=v[2], original_br_offset=v[3], original_br_word=v[4],
                   target_register=v[5], got_offset=v[6], relocation_index=v[7],
                   relocation_type=v[8], symbol_index=v[9], symbol_type=v[10],
                   symbol_binding=v[11], symbol_visibility=v[12], relocation_addend=v[14],
                   symbol_name_offset=v[15], symbol_name_length=v[16], symbol_section_index=v[17],
                   eh_identity_kind=v[18], symbol_value=v[19], symbol_size=v[20],
                   same_module_target_offset=v[21], function_start=v[22], function_end=v[23],
                   fde_offset=v[24], cie_offset=v[25], independent_root_offset=v[26],
                   symbol_name_sha256=value[144:176], function_sha256=value[176:208],
                   eh_identity_sha256=value[208:240], final_independent_roots_sha256=value[240:272],
                   schema=v[0], flags=v[1]).validate()


@dataclass(frozen=True)
class ReturningRetireRecordV1:
    source_callsite: int
    original_bl_word: int
    stub_extent: int
    original_target: int
    normal_return: int
    reserved_stub_offset: int
    exclusive_head: int
    matching_store: int
    function_start: int
    function_end: int
    fde_offset: int
    cie_offset: int
    function_sha256: bytes
    final_independent_roots_sha256: bytes
    whole_function_ownership_proof_sha256: bytes
    schema: int = RETURNING_RETIRE_SCHEMA_V1
    flags: int = 0

    def validate(self) -> "ReturningRetireRecordV1":
        if self.schema != 1 or self.flags != 0:
            raise GuestContractError("retire record schema/flags must be 1/0")
        for name in ("source_callsite", "original_target", "normal_return", "reserved_stub_offset",
                     "exclusive_head", "matching_store", "function_start", "function_end",
                     "fde_offset", "cie_offset"):
            _aligned(name, getattr(self, name))
        _integer("original_bl_word", self.original_bl_word, 32)
        _integer("stub_extent", self.stub_extent, 32)
        if self.original_bl_word & 0xFC000000 != 0x94000000:
            raise GuestContractError("retire source is not an A64 BL")
        if self.stub_extent != 8 or self.normal_return != self.source_callsite + 4:
            raise GuestContractError("retire stub extent or normal return is noncanonical")
        if not self.function_start < self.function_end:
            raise GuestContractError("retire function range is empty or reversed")
        for name in ("source_callsite", "exclusive_head", "matching_store"):
            if not self.function_start <= getattr(self, name) < self.function_end:
                raise GuestContractError(f"{name} is outside the owned function")
        if not self.fde_offset or not self.cie_offset:
            raise GuestContractError("retire ownership lacks indexed FDE/CIE")
        _digest("function_sha256", self.function_sha256)
        _digest("final_independent_roots_sha256", self.final_independent_roots_sha256)
        _digest("whole_function_ownership_proof_sha256", self.whole_function_ownership_proof_sha256)
        return self

    def pack(self) -> bytes:
        self.validate()
        result = bytearray(RETURNING_RETIRE_STRIDE_V1)
        struct.pack_into("<IIQIIQQQQQQQQQ", result, 0, self.schema, self.flags,
                         self.source_callsite, self.original_bl_word, self.stub_extent,
                         self.original_target, self.normal_return, self.reserved_stub_offset,
                         self.exclusive_head, self.matching_store, self.function_start,
                         self.function_end, self.fde_offset, self.cie_offset)
        result[96:128] = self.function_sha256
        result[128:160] = self.final_independent_roots_sha256
        result[160:192] = self.whole_function_ownership_proof_sha256
        return bytes(result)

    @classmethod
    def unpack(cls, value: bytes) -> "ReturningRetireRecordV1":
        if type(value) is not bytes or len(value) != RETURNING_RETIRE_STRIDE_V1:
            raise GuestContractError("retire record has wrong size")
        v = struct.unpack_from("<IIQIIQQQQQQQQQ", value)
        return cls(source_callsite=v[2], original_bl_word=v[3], stub_extent=v[4],
                   original_target=v[5], normal_return=v[6], reserved_stub_offset=v[7],
                   exclusive_head=v[8], matching_store=v[9], function_start=v[10],
                   function_end=v[11], fde_offset=v[12], cie_offset=v[13],
                   function_sha256=value[96:128], final_independent_roots_sha256=value[128:160],
                   whole_function_ownership_proof_sha256=value[160:192], schema=v[0], flags=v[1]).validate()


def _pack_table(records: Sequence[object], record_type: type, key: str) -> bytes:
    if not isinstance(records, (tuple, list)):
        raise GuestContractError("typed table must be a tuple or list")
    previous = None
    encoded = []
    for item in records:
        if type(item) is not record_type:
            raise GuestContractError("typed table contains a wrong record type")
        value = getattr(item, key)
        if previous is not None and value <= previous:
            raise GuestContractError("typed records must already be strictly sorted and unique")
        previous = value
        encoded.append(item.pack())
    return b"".join(encoded)


def pack_exact_guest_table(records: Sequence[ExactGuestRecordV1]) -> bytes:
    return _pack_table(records, ExactGuestRecordV1, "original_br_offset")


def pack_returning_retire_table(records: Sequence[ReturningRetireRecordV1]) -> bytes:
    return _pack_table(records, ReturningRetireRecordV1, "source_callsite")


def table_digest(value: bytes) -> bytes:
    if type(value) is not bytes:
        raise GuestContractError("table bytes must be immutable bytes")
    return hashlib.sha256(value).digest() if value else ZERO_DIGEST


def canonical_json(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise GuestContractError("value is outside the canonical JSON domain") from error


def _keys(value: object, expected: set[str], name: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != expected or any(type(k) is not str for k in value):
        raise GuestContractError(f"{name} has missing or extra keys")
    return value


def _hex64(value: object, name: str) -> str:
    if type(value) is not str or not _HEX64.fullmatch(value):
        raise GuestContractError(f"{name} must be lowercase hex64")
    return value


def _offset(value: object, name: str, *, word: bool = False) -> str:
    pattern = _U32 if word else _U64
    if type(value) is not str or not pattern.fullmatch(value):
        raise GuestContractError(f"{name} has noncanonical hexadecimal width")
    return value


def validate_toolset_recipe_v1(value: object) -> Mapping[str, object]:
    recipe = _keys(value, {"schema", "files"}, "ToolsetRecipeV1")
    if recipe["schema"] != 1 or type(recipe["schema"]) is not int or type(recipe["files"]) is not list:
        raise GuestContractError("invalid ToolsetRecipeV1 schema/files")
    paths = []
    for row in recipe["files"]:
        item = _keys(row, {"path", "sha256"}, "ToolsetRecipeV1 file")
        path = item["path"]
        if (type(path) is not str or not path or not _PATH.fullmatch(path) or "\\" in path or
                any(part in ("", ".", "..") for part in path.split("/"))):
            raise GuestContractError("toolset recipe path is not normalized repository-relative ASCII")
        _hex64(item["sha256"], "toolset file sha256")
        paths.append(path)
    if paths != sorted(set(paths), key=lambda x: x.encode("ascii")):
        raise GuestContractError("toolset recipe paths must be strictly ASCII sorted and unique")
    return recipe


def toolset_recipe_sha256(value: object) -> bytes:
    return hashlib.sha256(canonical_json(validate_toolset_recipe_v1(value))).digest()


def validate_ownership_proof_v1(value: object) -> Mapping[str, object]:
    proof = _keys(value, {"schema", "verdict", "source_sha256", "build_id", "tool_hashes",
                          "function", "exclusive", "final_roots", "independent_roots",
                          "direct_incoming", "calls", "state_facts", "restores", "leave_monitor"},
                  "OwnershipProofV1")
    if proof["schema"] != 1 or type(proof["schema"]) is not int or proof["verdict"] != "PASS":
        raise GuestContractError("ownership proof schema/verdict mismatch")
    _hex64(proof["source_sha256"], "proof source sha256")
    _hex64(proof["build_id"], "proof build id")
    validate_toolset_recipe_v1({"schema": 1, "files": proof["tool_hashes"]})
    function = _keys(proof["function"], {"start", "end", "fde", "cie", "function_sha256"}, "proof function")
    for name in ("start", "end", "fde", "cie"):
        _offset(function[name], f"function {name}")
    _hex64(function["function_sha256"], "proof function sha256")
    exclusive = _keys(proof["exclusive"], {"head", "store"}, "proof exclusive")
    for name in ("head", "store"):
        _offset(exclusive[name], f"exclusive {name}")
    for list_name in ("final_roots", "independent_roots"):
        rows = proof[list_name]
        if type(rows) is not list:
            raise GuestContractError(f"{list_name} must be a list")
        for row in rows:
            _offset(row, list_name)
        if rows != sorted(set(rows)):
            raise GuestContractError(f"{list_name} must be strictly sorted and unique")
    incoming_kinds = {"ROOT", "FALLTHROUGH", "DIRECT_BRANCH", "CONDITIONAL_TAKEN",
                      "CONDITIONAL_FALLTHROUGH", "CALL_RETURN"}
    incoming_keys = []
    if type(proof["direct_incoming"]) is not list:
        raise GuestContractError("direct_incoming must be a list")
    for row in proof["direct_incoming"]:
        item = _keys(row, {"from", "to", "kind"}, "direct incoming")
        _offset(item["from"], "incoming from"); _offset(item["to"], "incoming to")
        if item["kind"] not in incoming_kinds:
            raise GuestContractError("unknown direct incoming kind")
        incoming_keys.append((item["to"], item["from"], item["kind"]))
    if incoming_keys != sorted(set(incoming_keys)):
        raise GuestContractError("direct incoming facts must be strictly sorted and unique")
    if type(proof["calls"]) is not list or len(proof["calls"]) != 2:
        raise GuestContractError("ownership proof must contain exactly two returning calls")
    callsites = []
    for row in proof["calls"]:
        item = _keys(row, {"callsite", "original_bl_word", "target", "normal_return"}, "proof call")
        for name in ("callsite", "target", "normal_return"):
            _offset(item[name], f"call {name}")
        _offset(item["original_bl_word"], "call original word", word=True)
        callsites.append(item["callsite"])
    if callsites != sorted(set(callsites)):
        raise GuestContractError("calls must be strictly sorted and unique")
    transfer = {"LINEAR", "CONDITIONAL", "DIRECT_BRANCH", "DIRECT_CALL", "INDIRECT",
                "RETURN", "LOAD_EXCLUSIVE", "STORE_EXCLUSIVE", "CLREX", "SVC"}
    outcomes = {"LIVE_TO_LIVE", "LIVE_TO_DEAD", "DEAD_TO_DEAD", "REJECT"}
    state_pcs = []
    if type(proof["state_facts"]) is not list:
        raise GuestContractError("state facts must be a list")
    for row in proof["state_facts"]:
        item = _keys(row, {"pc", "live_in", "dead_in", "transfer", "successors", "outcomes"}, "state fact")
        _offset(item["pc"], "state pc")
        if type(item["live_in"]) is not bool or type(item["dead_in"]) is not bool or item["transfer"] not in transfer:
            raise GuestContractError("invalid state fact scalar")
        if type(item["successors"]) is not list or type(item["outcomes"]) is not list:
            raise GuestContractError("invalid state fact lists")
        for target in item["successors"]:
            _offset(target, "state successor")
        if item["successors"] != sorted(set(item["successors"])) or item["outcomes"] != sorted(set(item["outcomes"])) or not set(item["outcomes"]) <= outcomes:
            raise GuestContractError("state fact lists are not canonical")
        state_pcs.append(item["pc"])
    if state_pcs != sorted(set(state_pcs)):
        raise GuestContractError("state facts must be strictly sorted and unique")
    if type(proof["restores"]) is not list or len(proof["restores"]) != 6:
        raise GuestContractError("ownership proof must contain five restores and RET")
    for ordinal, row in enumerate(proof["restores"]):
        item = _keys(row, {"ordinal", "pc", "original_word"}, "restore")
        if type(item["ordinal"]) is not int or item["ordinal"] != ordinal:
            raise GuestContractError("restore ordinals must be 0..5")
        _offset(item["pc"], "restore pc"); _offset(item["original_word"], "restore word", word=True)
    leave = _keys(proof["leave_monitor"], {"entry", "head", "store", "clrex_sites", "terminal_facts"}, "leave monitor")
    for name in ("entry", "head", "store"):
        _offset(leave[name], f"leave {name}")
    if type(leave["clrex_sites"]) is not list:
        raise GuestContractError("CLREX sites must be a list")
    for pc in leave["clrex_sites"]:
        _offset(pc, "CLREX site")
    if leave["clrex_sites"] != sorted(set(leave["clrex_sites"])):
        raise GuestContractError("CLREX sites must be strictly sorted and unique")
    terminals = []
    if type(leave["terminal_facts"]) is not list:
        raise GuestContractError("terminal facts must be a list")
    for row in leave["terminal_facts"]:
        item = _keys(row, {"pc", "kind", "live"}, "terminal fact")
        _offset(item["pc"], "terminal pc")
        if item["kind"] not in {"SVC_1B", "RET", "EXCEPTIONAL_CALL"} or item["live"] is not False:
            raise GuestContractError("terminal fact is unknown or live")
        terminals.append((item["pc"], item["kind"]))
    if terminals != sorted(set(terminals)):
        raise GuestContractError("terminal facts must be strictly sorted and unique")
    return proof


def ownership_proof_sha256(value: object) -> bytes:
    return hashlib.sha256(canonical_json(validate_ownership_proof_v1(value))).digest()


_AUDIT_KEYS = {"schema", "flags", "package_sha256", "source_sha256", "build_id",
               "toolset_recipe_sha256", "exact_guest", "returning_retire",
               "final_independent_roots_sha256", "whole_function_ownership_proof_sha256"}


def validate_audit_object_v1(value: object) -> Mapping[str, object]:
    audit = _keys(value, _AUDIT_KEYS, "TrustedGuestContractAuditV1")
    if (audit["schema"] != 1 or type(audit["schema"]) is not int or
            audit["flags"] != 0 or type(audit["flags"]) is not int):
        raise GuestContractError("trusted audit schema/flags mismatch")
    for name in ("package_sha256", "source_sha256", "build_id", "toolset_recipe_sha256",
                 "final_independent_roots_sha256", "whole_function_ownership_proof_sha256"):
        _hex64(audit[name], name)
    for name in ("exact_guest", "returning_retire"):
        table = _keys(audit[name], {"count", "table_sha256"}, f"audit {name}")
        if type(table["count"]) is not int or not 0 <= table["count"] < 1 << 64:
            raise GuestContractError(f"audit {name} count is invalid")
        _hex64(table["table_sha256"], f"audit {name} digest")
        if (table["count"] == 0) != (table["table_sha256"] == "0" * 64):
            raise GuestContractError(f"audit {name} empty count/digest mismatch")
    return audit


def audit_identity_sha256(value: object) -> bytes:
    return hashlib.sha256(canonical_json(validate_audit_object_v1(value))).digest()


def validate_trusted_audit_v1(value: object) -> Mapping[str, object]:
    full = _keys(value, _AUDIT_KEYS | {"audit_identity_sha256"}, "trusted audit with identity")
    identity = _hex64(full["audit_identity_sha256"], "audit identity")
    body = {key: full[key] for key in full if key != "audit_identity_sha256"}
    validate_audit_object_v1(body)
    if audit_identity_sha256(body).hex() != identity:
        raise GuestContractError("trusted audit identity mismatch")
    return full


TAIKO_SDK_SHA256 = "2a89fa1c0e677710e89ed29b578162affef530a0c9b8c93cda15d50a57a20d28"
TAIKO_SDK_BUILD_ID = "357efc198e728cb5d55265aff304f03cfc9cc0e3000000000000000000000000"

TOOLSET_RECIPE_PATHS: tuple[str, ...] = (
    "dm/tools/android_exclusive.py",
    "dm/tools/android_guest_contract.py",
    "dm/tools/android_import.py",
    "dm/tools/android_rewrite.py",
    "dm/tools/nso_eh.py",
    "dm/tools/nso_format.py",
)


@dataclass(frozen=True)
class ExactGuestSiteSpec:
    original_br_offset: int
    original_br_word: int
    target_register: int
    got_offset: int
    relocation_index: int
    relocation_type: int
    symbol_index: int
    symbol_name: str
    symbol_type: int
    symbol_binding: int
    symbol_visibility: int
    relocation_addend: int
    symbol_name_offset: int
    symbol_name_length: int
    symbol_section_index: int
    eh_identity_kind: int
    symbol_value: int
    symbol_size: int
    same_module_target_offset: int
    function_start: int
    function_end: int
    fde_offset: int
    cie_offset: int
    independent_root_offset: int
    function_sha256_hex: str


@dataclass(frozen=True)
class ReturningRetireCallSpec:
    source_callsite: int
    original_bl_word: int
    stub_extent: int
    original_target: int
    normal_return: int
    reserved_stub_delta: int


@dataclass(frozen=True)
class ReturningRetireFunctionSpec:
    function_start: int
    function_end: int
    fde_offset: int
    cie_offset: int
    exclusive_head: int
    matching_store: int
    function_sha256_hex: str
    calls: tuple[ReturningRetireCallSpec, ...]
    restores: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class LeaveMonitorSpec:
    entry: int
    end: int
    head: int
    retry_head: int
    store: int
    clrex_sites: tuple[int, ...]
    svc_1b_callsite: int
    svc_1b_target: int
    ret_site: int
    exceptional_callsite: int
    exceptional_plt_target: int


@dataclass(frozen=True)
class GuestContractSourceSpec:
    source_sha256_hex: str
    build_id_hex: str
    exact_guest_sites: tuple[ExactGuestSiteSpec, ...]
    returning_retire: ReturningRetireFunctionSpec
    leave_monitor: LeaveMonitorSpec


@dataclass(frozen=True)
class SelectedGuestContract:
    exact_guest_records: tuple[ExactGuestRecordV1, ...]
    returning_retire_records: tuple[ReturningRetireRecordV1, ...]
    ownership_proof: Mapping[str, object]
    ownership_proof_sha256: bytes
    toolset_recipe: Mapping[str, object]
    toolset_recipe_sha256: bytes
    final_independent_roots_sha256: bytes


TAIKO_SDK_GUEST_CONTRACT_SPEC = GuestContractSourceSpec(
    source_sha256_hex=TAIKO_SDK_SHA256,
    build_id_hex=TAIKO_SDK_BUILD_ID,
    exact_guest_sites=(
        ExactGuestSiteSpec(
            original_br_offset=0x5B27FC,
            original_br_word=0xD61F0220,
            target_register=17,
            got_offset=0xCD46C8,
            relocation_index=25374,
            relocation_type=1026,
            symbol_index=7693,
            symbol_name="_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE",
            symbol_type=2,
            symbol_binding=1,
            symbol_visibility=0,
            relocation_addend=0,
            symbol_name_offset=14533,
            symbol_name_length=39,
            symbol_section_index=2,
            eh_identity_kind=1,
            symbol_value=0x375270,
            symbol_size=32,
            same_module_target_offset=0x375270,
            function_start=0x375270,
            function_end=0x375290,
            fde_offset=0xC1BDD0,
            cie_offset=0xB997B0,
            independent_root_offset=0x375270,
            function_sha256_hex="32e91acc49deccb3b86a5e02ccd48bcd6b71b9bd0dde609031e5cea10c692927",
        ),
        ExactGuestSiteSpec(
            original_br_offset=0x5BA08C,
            original_br_word=0xD61F0220,
            target_register=17,
            got_offset=0xCD8310,
            relocation_index=27303,
            relocation_type=1026,
            symbol_index=7689,
            symbol_name="strcmp",
            symbol_type=2,
            symbol_binding=1,
            symbol_visibility=0,
            relocation_addend=0,
            symbol_name_offset=942825,
            symbol_name_length=6,
            symbol_section_index=2,
            eh_identity_kind=0,
            symbol_value=0x5AD3C0,
            symbol_size=0,
            same_module_target_offset=0x5AD3C0,
            function_start=0x5AD3C0,
            function_end=0x5AD48C,
            fde_offset=0,
            cie_offset=0,
            independent_root_offset=0x5AD3C0,
            function_sha256_hex="cb05fa6a44e6adfd5c9288ed260f5aed841d51901474c3bf10d320864be3bbde",
        ),
        ExactGuestSiteSpec(
            original_br_offset=0x5C91AC,
            original_br_word=0xD61F0220,
            target_register=17,
            got_offset=0xCDFBA0,
            relocation_index=31161,
            relocation_type=1026,
            symbol_index=7312,
            symbol_name="_ZN2nn2os6detail36InternalCriticalSectionImplByHorizon5LeaveEv",
            symbol_type=2,
            symbol_binding=1,
            symbol_visibility=0,
            relocation_addend=0,
            symbol_name_offset=2119656,
            symbol_name_length=62,
            symbol_section_index=2,
            eh_identity_kind=1,
            symbol_value=0x37F7D4,
            symbol_size=128,
            same_module_target_offset=0x37F7D4,
            function_start=0x37F7D4,
            function_end=0x37F854,
            fde_offset=0xC1F278,
            cie_offset=0xB997B0,
            independent_root_offset=0x37F7D4,
            function_sha256_hex="3bd7369caa9b5beef2f48c57fe2799dd3a381dca8288e902b1159986f2123817",
        ),
        ExactGuestSiteSpec(
            original_br_offset=0x5CFB9C,
            original_br_word=0xD61F0220,
            target_register=17,
            got_offset=0xCE3098,
            relocation_index=32856,
            relocation_type=1026,
            symbol_index=25052,
            symbol_name="nnosUnlockMutex",
            symbol_type=2,
            symbol_binding=1,
            symbol_visibility=0,
            relocation_addend=0,
            symbol_name_offset=2132030,
            symbol_name_length=15,
            symbol_section_index=2,
            eh_identity_kind=1,
            symbol_value=0x376EC0,
            symbol_size=4,
            same_module_target_offset=0x376EC0,
            function_start=0x376EC0,
            function_end=0x376EC4,
            fde_offset=0xC1CAD8,
            cie_offset=0xB997B0,
            independent_root_offset=0x376EC0,
            function_sha256_hex="212e4e3fc9ac3229b08ffe784529f7e46287097d6d6c3a45da0f45f350c5d64e",
        ),
        ExactGuestSiteSpec(
            original_br_offset=0x5D38CC,
            original_br_word=0xD61F0220,
            target_register=17,
            got_offset=0xCE4F30,
            relocation_index=33835,
            relocation_type=1026,
            symbol_index=37,
            symbol_name="__nnmusl_UnlockLock",
            symbol_type=2,
            symbol_binding=1,
            symbol_visibility=0,
            relocation_addend=0,
            symbol_name_offset=2932998,
            symbol_name_length=19,
            symbol_section_index=2,
            eh_identity_kind=1,
            symbol_value=0x5B0778,
            symbol_size=4,
            same_module_target_offset=0x5B0778,
            function_start=0x5B0778,
            function_end=0x5B077C,
            fde_offset=0xC7C1D0,
            cie_offset=0xB997B0,
            independent_root_offset=0x5B0778,
            function_sha256_hex="50bb96a48d01d35c79441f17daaa5773258593ae908bc30276e573df8709ce46",
        ),
    ),
    returning_retire=ReturningRetireFunctionSpec(
        function_start=0x5695D0,
        function_end=0x5697AC,
        fde_offset=0xC74130,
        cie_offset=0xB997B0,
        exclusive_head=0x569690,
        matching_store=0x56969C,
        function_sha256_hex="7d1ac25050fe54353ff48a1c6d50bf50e50107bfee8c401e28d74319c819845b",
        calls=(
            ReturningRetireCallSpec(
                source_callsite=0x56975C,
                original_bl_word=0x94000DC5,
                stub_extent=8,
                original_target=0x56CE70,
                normal_return=0x569760,
                reserved_stub_delta=0,
            ),
            ReturningRetireCallSpec(
                source_callsite=0x56978C,
                original_bl_word=0x9401423D,
                stub_extent=8,
                original_target=0x5BA080,
                normal_return=0x569790,
                reserved_stub_delta=8,
            ),
        ),
        restores=(
            (0x569764, 0xA9444FF4),
            (0x569768, 0xA94357F6),
            (0x56976C, 0xA9425FF8),
            (0x569770, 0xF9400BF9),
            (0x569774, 0xA8C57BFD),
            (0x569778, 0xD65F03C0),
        ),
    ),
    leave_monitor=LeaveMonitorSpec(
        entry=0x37F7D4,
        end=0x37F854,
        head=0x37F7EC,
        retry_head=0x37F804,
        store=0x37F7FC,
        clrex_sites=(0x37F810,),
        svc_1b_callsite=0x37F81C,
        svc_1b_target=0x3CCED0,
        ret_site=0x37F830,
        exceptional_callsite=0x37F850,
        exceptional_plt_target=0x5B2290,
    ),
)


def roots_set_sha256(offsets: Sequence[int]) -> bytes:
    if not isinstance(offsets, (tuple, list)) or not offsets:
        raise GuestContractError("independent roots set must be non-empty")
    previous = -1
    digest = hashlib.sha256()
    for item in offsets:
        _aligned("independent root", item, 4)
        if item <= previous:
            raise GuestContractError("independent roots must be strictly sorted and unique")
        previous = item
        digest.update(struct.pack("<Q", item))
    return digest.digest()


def eh_identity_kind1_sha256(
    raw: bytes,
    function_start: int,
    function_end: int,
    cie_offset: int,
    fde_offset: int,
) -> bytes:
    for name, off in (("cie_offset", cie_offset), ("fde_offset", fde_offset)):
        _aligned(name, off, 4)
        if off <= 0 or off + 4 > len(raw):
            raise GuestContractError(f"{name} is outside image")
    cie_len = struct.unpack_from("<I", raw, cie_offset)[0]
    fde_len = struct.unpack_from("<I", raw, fde_offset)[0]
    if cie_len < 4 or cie_offset + 4 + cie_len > len(raw):
        raise GuestContractError("invalid CIE record length")
    if fde_len < 4 or fde_offset + 4 + fde_len > len(raw):
        raise GuestContractError("invalid FDE record length")
    cie_bytes = raw[cie_offset : cie_offset + 4 + cie_len]
    fde_bytes = raw[fde_offset : fde_offset + 4 + fde_len]
    preimage = (
        b"EXACT_GUEST_EH_V1\x00"
        + struct.pack(
            "<IIQQQQQ",
            1,
            0,
            function_start,
            function_end,
            cie_offset,
            fde_offset,
            len(cie_bytes),
        )
        + cie_bytes
        + struct.pack("<Q", len(fde_bytes))
        + fde_bytes
    )
    return hashlib.sha256(preimage).digest()


def current_toolset_recipe_v1() -> dict[str, object]:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    files = []
    for rel in sorted(TOOLSET_RECIPE_PATHS, key=lambda x: x.encode("ascii")):
        full = root / rel
        if not full.is_file():
            raise GuestContractError(f"missing toolset recipe file {rel}")
        files.append({"path": rel, "sha256": hashlib.sha256(full.read_bytes()).hexdigest()})
    recipe = {"schema": 1, "files": files}
    validate_toolset_recipe_v1(recipe)
    return recipe


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def _decode_plt_got(raw: bytes, plt_entry: int) -> tuple[int, int, int]:
    if plt_entry < 0 or plt_entry + 16 > len(raw) or plt_entry % 4:
        raise GuestContractError(f"0x{plt_entry:x}: PLT stub outside aligned text")
    w0, w1, w2, w3 = struct.unpack_from("<4I", raw, plt_entry)
    if (w0 & 0x9F00001F) != 0x90000010:
        raise GuestContractError(f"0x{plt_entry:x}: PLT word 0 is not ADRP x16")
    immlo = (w0 >> 29) & 3
    immhi = (w0 >> 5) & 0x7FFFF
    page_delta = _sign_extend((immhi << 2) | immlo, 21) << 12
    page = (plt_entry & ~0xFFF) + page_delta
    if (w1 & 0xFFC003FF) != 0xF9400211:
        raise GuestContractError(f"0x{plt_entry + 4:x}: PLT word 1 is not LDR x17, [x16, #imm]")
    ldr_off = ((w1 >> 10) & 0xFFF) * 8
    if (w2 & 0xFFC003FF) != 0x91000210:
        raise GuestContractError(f"0x{plt_entry + 8:x}: PLT word 2 is not ADD x16, x16, #imm")
    add_off = (w2 >> 10) & 0xFFF
    if ldr_off != add_off:
        raise GuestContractError(f"0x{plt_entry:x}: PLT LDR/ADD offset mismatch")
    if w3 != 0xD61F0220:
        raise GuestContractError(f"0x{plt_entry + 12:x}: PLT word 3 is not BR x17")
    return page + ldr_off, w3, 17


def _decode_local_word(pc: int, word: int) -> tuple[str, tuple[int, ...]]:
    if word == 0xD65F03C0:
        return "RETURN", ()
    if word == 0xD5033F5F:
        return "CLREX", (pc + 4,)
    if (word & 0xFFE0001F) == 0xD4000001:
        return "SVC", (pc + 4,)
    if (word & 0xFC000000) == 0x14000000:
        disp = _sign_extend(word & 0x3FFFFFF, 26) * 4
        return "DIRECT_BRANCH", (pc + disp,)
    if (word & 0xFC000000) == 0x94000000:
        disp = _sign_extend(word & 0x3FFFFFF, 26) * 4
        return "DIRECT_CALL", (pc + disp,)
    if (word & 0xFF000010) == 0x54000000:
        disp = _sign_extend((word >> 5) & 0x7FFFF, 19) * 4
        return "CONDITIONAL", (pc + 4, pc + disp)
    if (word & 0x7E000000) == 0x34000000:
        disp = _sign_extend((word >> 5) & 0x7FFFF, 19) * 4
        return "CONDITIONAL", (pc + 4, pc + disp)
    if (word & 0x7E000000) == 0x36000000:
        disp = _sign_extend((word >> 5) & 0x3FFF, 14) * 4
        return "CONDITIONAL", (pc + 4, pc + disp)
    if (word & 0xFE000000) == 0xD6000000:
        return "INDIRECT", ()
    if (word & 0x3F407C00) in (0x08407C00, 0x0840FC00):
        return "LOAD_EXCLUSIVE", (pc + 4,)
    if (word & 0x3F407C00) in (0x08007C00, 0x0800FC00):
        return "STORE_EXCLUSIVE", (pc + 4,)
    return "LINEAR", (pc + 4,)


def _verify_zero_size_closed_cfg(
    raw: bytes,
    by_pc: Mapping[int, object],
    start: int,
    end: int,
    text_end: int,
    symbols: Sequence[object],
) -> None:
    if start < 0 or end > text_end or start >= end or start % 4 or end % 4:
        raise GuestContractError(f"0x{start:x}: invalid zero-size function bounds")
    expected_pcs = set(range(start, end, 4))
    if not expected_pcs <= set(by_pc):
        raise GuestContractError(f"0x{start:x}: zero-size function has un-decoded instructions")
    visited = set()
    queue = [start]
    saw_return = False
    while queue:
        pc = queue.pop()
        if pc in visited:
            continue
        if pc not in expected_pcs:
            raise GuestContractError(f"0x{start:x}: zero-size function escapes [0x{start:x}, 0x{end:x}) to 0x{pc:x}")
        visited.add(pc)
        word = struct.unpack_from("<I", raw, pc)[0]
        kind, succs = _decode_local_word(pc, word)
        if kind in {"DIRECT_CALL", "INDIRECT", "SVC", "LOAD_EXCLUSIVE", "STORE_EXCLUSIVE", "CLREX"}:
            raise GuestContractError(f"0x{pc:x}: forbidden {kind} in zero-size leaf function")
        if kind == "RETURN":
            saw_return = True
            continue
        for target in succs:
            if target not in expected_pcs:
                raise GuestContractError(f"0x{pc:x}: branch target 0x{target:x} leaves zero-size function")
            queue.append(target)
    if visited != expected_pcs or not saw_return:
        raise GuestContractError(f"0x{start:x}: zero-size function CFG does not cover [0x{start:x}, 0x{end:x})")
    if struct.unpack_from("<I", raw, end - 4)[0] != 0xD65F03C0:
        raise GuestContractError(f"0x{start:x}: zero-size function does not end with RET")
    later_symbols = sorted(
        s.value for s in symbols if getattr(s, "section", 0) != 0 and getattr(s, "value", 0) > start
    )
    if later_symbols:
        next_sym = later_symbols[0]
        if next_sym < end:
            raise GuestContractError(f"0x{start:x}: next symbol 0x{next_sym:x} overlaps zero-size function")
        gap_end = min(next_sym, end + 64, text_end)
        if any(raw[end:gap_end]):
            raise GuestContractError(f"0x{end:x}: non-zero trailing gap before next symbol 0x{next_sym:x}")


def _verify_leave_monitor(
    raw: bytes,
    by_pc: Mapping[int, object],
    lv: LeaveMonitorSpec,
    metadata: object,
) -> dict[str, object]:
    expected_pcs = set(range(lv.entry, lv.end, 4))
    if not expected_pcs <= set(by_pc):
        raise GuestContractError("Leave monitor instructions missing from by_pc")
    for head_pc in (lv.head, lv.retry_head):
        if head_pc not in expected_pcs:
            raise GuestContractError("Leave monitor head outside function")
        kind, _ = _decode_local_word(head_pc, struct.unpack_from("<I", raw, head_pc)[0])
        if kind != "LOAD_EXCLUSIVE":
            raise GuestContractError(f"0x{head_pc:x}: Leave monitor head is not LDAXR")
    if lv.store not in expected_pcs:
        raise GuestContractError("Leave monitor store outside function")
    store_kind, _ = _decode_local_word(lv.store, struct.unpack_from("<I", raw, lv.store)[0])
    if store_kind != "STORE_EXCLUSIVE":
        raise GuestContractError(f"0x{lv.store:x}: Leave monitor store is not STLXR")
    if not lv.clrex_sites:
        raise GuestContractError("Leave monitor requires at least one CLREX site")
    for c_pc in lv.clrex_sites:
        if (
            c_pc not in expected_pcs
            or struct.unpack_from("<I", raw, c_pc)[0] != 0xD5033F5F
            or getattr(by_pc[c_pc], "mnemonic", None) != "clrex"
        ):
            raise GuestContractError(f"0x{c_pc:x}: Leave monitor CLREX site is not CLREX")
    # Verify svc #0x1b helper callsite and helper body (svc #0x1b; ret)
    svc_kind, svc_targets = _decode_local_word(lv.svc_1b_callsite, struct.unpack_from("<I", raw, lv.svc_1b_callsite)[0])
    if svc_kind != "DIRECT_CALL" or svc_targets != (lv.svc_1b_target,):
        raise GuestContractError("Leave monitor SVC 0x1b callsite target mismatch")
    if lv.svc_1b_target < 0 or lv.svc_1b_target + 8 > len(raw):
        raise GuestContractError("Leave monitor SVC 0x1b helper outside image")
    if struct.unpack_from("<2I", raw, lv.svc_1b_target) != (0xD4000361, 0xD65F03C0):
        raise GuestContractError("Leave monitor SVC 0x1b helper is not svc #0x1b; ret")
    # Verify exceptional AbortImpl PLT callsite
    exc_kind, exc_targets = _decode_local_word(
        lv.exceptional_callsite, struct.unpack_from("<I", raw, lv.exceptional_callsite)[0]
    )
    if exc_kind != "DIRECT_CALL" or exc_targets != (lv.exceptional_plt_target,):
        raise GuestContractError("Leave monitor exceptional callsite target mismatch")
    exc_got, _, _ = _decode_plt_got(raw, lv.exceptional_plt_target)
    exc_rels = [r for r in metadata.relocations if r.offset == exc_got]
    if len(exc_rels) != 1 or exc_rels[0].kind != 1026:
        raise GuestContractError("Leave monitor exceptional PLT lacks unique R_AARCH64_JUMP_SLOT")
    exc_sym = metadata.symbols[exc_rels[0].symbol]
    if exc_sym.name != "_ZN2nn4diag6detail9AbortImplEPKcS3_S3_iPKNS_6ResultES3_z":
        raise GuestContractError("Leave monitor exceptional PLT is not the long AbortImpl symbol")
    if struct.unpack_from("<I", raw, lv.ret_site)[0] != 0xD65F03C0:
        raise GuestContractError("Leave monitor ret_site is not RET")

    # State exploration from (lv.entry, False) where False=DEAD, True=LIVE
    seen: set[tuple[int, bool]] = set()
    queue: list[tuple[int, bool]] = [(lv.entry, False)]
    terminal_live: dict[int, bool] = {}
    while queue:
        pc, live = queue.pop()
        if (pc, live) in seen:
            continue
        if pc not in expected_pcs:
            raise GuestContractError(f"Leave monitor escapes function to 0x{pc:x}")
        seen.add((pc, live))
        word = struct.unpack_from("<I", raw, pc)[0]
        kind, succs = _decode_local_word(pc, word)
        if pc in (lv.head, lv.retry_head):
            queue.append((pc + 4, True))
            continue
        if pc == lv.store:
            if not live:
                raise GuestContractError("Leave monitor STLXR reached with DEAD monitor")
            queue.append((pc + 4, False))
            continue
        if pc in lv.clrex_sites:
            queue.append((pc + 4, False))
            continue
        if kind in {"LOAD_EXCLUSIVE", "STORE_EXCLUSIVE", "CLREX", "INDIRECT", "SVC"}:
            raise GuestContractError(f"0x{pc:x}: unexpected {kind} in Leave monitor")
        if pc == lv.svc_1b_callsite:
            terminal_live[pc] = terminal_live.get(pc, False) or live
            if live:
                raise GuestContractError("Leave monitor reaches SVC 0x1b helper with LIVE monitor")
            queue.append((pc + 4, False))
            continue
        if pc == lv.exceptional_callsite:
            terminal_live[pc] = terminal_live.get(pc, False) or live
            if live:
                raise GuestContractError("Leave monitor reaches exceptional AbortImpl with LIVE monitor")
            continue
        if pc == lv.ret_site:
            terminal_live[pc] = terminal_live.get(pc, False) or live
            if live:
                raise GuestContractError("Leave monitor reaches RET with LIVE monitor")
            continue
        if kind in {"DIRECT_CALL", "RETURN"}:
            raise GuestContractError(f"0x{pc:x}: uncontracted {kind} in Leave monitor")
        for target in succs:
            queue.append((target, live))

    for req_pc in (lv.svc_1b_callsite, lv.ret_site, lv.exceptional_callsite):
        if req_pc not in terminal_live or terminal_live[req_pc]:
            raise GuestContractError(f"0x{req_pc:x}: Leave monitor terminal site not proven DEAD")

    terminal_facts = sorted(
        [
            {"pc": f"0x{lv.svc_1b_callsite:016x}", "kind": "SVC_1B", "live": False},
            {"pc": f"0x{lv.ret_site:016x}", "kind": "RET", "live": False},
            {"pc": f"0x{lv.exceptional_callsite:016x}", "kind": "EXCEPTIONAL_CALL", "live": False},
        ],
        key=lambda x: (x["pc"], x["kind"]),
    )
    return {
        "entry": f"0x{lv.entry:016x}",
        "head": f"0x{lv.head:016x}",
        "store": f"0x{lv.store:016x}",
        "clrex_sites": [f"0x{c:016x}" for c in sorted(lv.clrex_sites)],
        "terminal_facts": terminal_facts,
    }


def _prove_returning_retire_function(
    raw: bytes,
    by_pc: Mapping[int, object],
    ret: ReturningRetireFunctionSpec,
    exact_sites: Sequence[ExactGuestSiteSpec],
    *,
    source_sha256_hex: str,
    build_id_hex: str,
    tool_hashes: list[dict[str, str]],
    final_roots: Sequence[int],
    independent_roots: Sequence[int],
    leave_obj: dict[str, object],
) -> dict[str, object]:
    start, end = ret.function_start, ret.function_end
    expected_pcs = set(range(start, end, 4))
    if not expected_pcs <= set(by_pc):
        raise GuestContractError("returning-retire function has un-decoded instructions")
    if start not in final_roots or start not in independent_roots:
        raise GuestContractError("returning-retire function entry is not a discovered root")
    for root in set(final_roots) | set(independent_roots):
        if start < root < end:
            raise GuestContractError(f"0x{root:x}: interior root inside returning-retire function")
    for pc, ins in by_pc.items():
        if start <= pc < end:
            continue
        word = struct.unpack_from("<I", raw, pc)[0]
        kind, succs = _decode_local_word(pc, word)
        if kind in {"DIRECT_BRANCH", "DIRECT_CALL", "CONDITIONAL"}:
            for target in succs:
                if start < target < end:
                    raise GuestContractError(f"0x{pc:x}: external edge into interior 0x{target:x}")
    if hashlib.sha256(raw[start:end]).hexdigest() != ret.function_sha256_hex:
        raise GuestContractError("returning-retire function body SHA-256 mismatch")

    if len(ret.calls) != 2:
        raise GuestContractError("returning-retire spec must contain 2 calls")
    call_by_site: dict[int, ReturningRetireCallSpec] = {}
    prev_site = -1
    for idx, call in enumerate(ret.calls):
        if call.source_callsite <= prev_site or call.source_callsite not in expected_pcs:
            raise GuestContractError("returning-retire callsites unsorted or outside function")
        prev_site = call.source_callsite
        word = struct.unpack_from("<I", raw, call.source_callsite)[0]
        if word != call.original_bl_word:
            raise GuestContractError(f"0x{call.source_callsite:x}: original BL word mismatch")
        kind, succs = _decode_local_word(call.source_callsite, word)
        if kind != "DIRECT_CALL" or succs != (call.original_target,):
            raise GuestContractError(f"0x{call.source_callsite:x}: decoded BL target mismatch")
        if call.normal_return != call.source_callsite + 4 or call.stub_extent != 8 or call.reserved_stub_delta != idx * 8:
            raise GuestContractError(f"0x{call.source_callsite:x}: noncanonical returning-retire call spec")
        call_by_site[call.source_callsite] = call

    # Verify call 0 targets a 1-word B wrapper to __nnmusl_UnlockLock PLT, and call 1 targets strcmp PLT
    unlock_plt = next(
        (s.original_br_offset - 12 for s in exact_sites if s.symbol_name == "__nnmusl_UnlockLock"), None
    )
    strcmp_plt = next((s.original_br_offset - 12 for s in exact_sites if s.symbol_name == "strcmp"), None)
    if unlock_plt is None or strcmp_plt is None:
        raise GuestContractError("missing __nnmusl_UnlockLock or strcmp in exact guest sites")
    c0_target = ret.calls[0].original_target
    if c0_target < 0 or c0_target + 4 > len(raw):
        raise GuestContractError("returning-retire call 0 target outside image")
    c0_kind, c0_succs = _decode_local_word(c0_target, struct.unpack_from("<I", raw, c0_target)[0])
    if c0_kind != "DIRECT_BRANCH" or c0_succs != (unlock_plt,):
        raise GuestContractError("returning-retire call 0 target is not a direct branch to __nnmusl_UnlockLock PLT")
    if ret.calls[1].original_target != strcmp_plt:
        raise GuestContractError("returning-retire call 1 target is not strcmp PLT")

    # Verify restores
    if len(ret.restores) != 6:
        raise GuestContractError("returning-retire spec must contain 5 restores + RET")
    restore_pcs = set()
    for ordinal, (r_pc, r_word) in enumerate(ret.restores):
        if r_pc not in expected_pcs or struct.unpack_from("<I", raw, r_pc)[0] != r_word:
            raise GuestContractError(f"0x{r_pc:x}: restore word mismatch")
        ins = by_pc[r_pc]
        if ordinal < 5:
            if ins.mnemonic not in {"ldp", "ldr"}:
                raise GuestContractError(f"0x{r_pc:x}: restore ordinal {ordinal} is not ldp/ldr")
        else:
            if r_word != 0xD65F03C0 or ins.mnemonic != "ret":
                raise GuestContractError(f"0x{r_pc:x}: restore ordinal 5 is not RET")
        restore_pcs.add(r_pc)

    # Whole-function (pc, state) exploration where state=False (DEAD) or True (LIVE)
    direct_incoming: set[tuple[str, str, str]] = {(f"0x{start:016x}", f"0x{start:016x}", "ROOT")}
    live_in_map: dict[int, bool] = {pc: False for pc in expected_pcs}
    dead_in_map: dict[int, bool] = {pc: False for pc in expected_pcs}
    outcomes_map: dict[int, set[str]] = {pc: set() for pc in expected_pcs}
    succs_map: dict[int, set[str]] = {pc: set() for pc in expected_pcs}
    transfer_map: dict[int, str] = {}

    seen: set[tuple[int, bool]] = set()
    queue: list[tuple[int, bool]] = [(start, False)]
    while queue:
        pc, live = queue.pop()
        if (pc, live) in seen:
            continue
        if pc not in expected_pcs:
            raise GuestContractError(f"returning-retire function escapes to 0x{pc:x}")
        seen.add((pc, live))
        if live:
            live_in_map[pc] = True
        else:
            dead_in_map[pc] = True
        word = struct.unpack_from("<I", raw, pc)[0]
        kind, succs = _decode_local_word(pc, word)
        transfer_map[pc] = kind
        ins = by_pc[pc]
        if live:
            if pc in restore_pcs:
                raise GuestContractError(f"0x{pc:x}: restore/epilogue reached with LIVE monitor")
            ops = getattr(ins, "op_str", "")
            if "x18" in ops or "w18" in ops or "sp" in ops:
                raise GuestContractError(f"0x{pc:x}: SP or x18 touched while monitor is LIVE")
        if pc == ret.exclusive_head:
            if kind != "LOAD_EXCLUSIVE":
                raise GuestContractError("exclusive_head is not LOAD_EXCLUSIVE")
            outcomes_map[pc].add("LIVE_TO_LIVE")
            succs_map[pc].add(f"0x{pc + 4:016x}")
            direct_incoming.add((f"0x{pc + 4:016x}", f"0x{pc:016x}", "FALLTHROUGH"))
            queue.append((pc + 4, True))
            continue
        if pc == ret.matching_store:
            if kind != "STORE_EXCLUSIVE":
                raise GuestContractError("matching_store is not STORE_EXCLUSIVE")
            if not live:
                raise GuestContractError("matching_store reached with DEAD monitor")
            outcomes_map[pc].add("LIVE_TO_DEAD")
            succs_map[pc].add(f"0x{pc + 4:016x}")
            direct_incoming.add((f"0x{pc + 4:016x}", f"0x{pc:016x}", "FALLTHROUGH"))
            queue.append((pc + 4, False))
            continue
        if kind in {"LOAD_EXCLUSIVE", "STORE_EXCLUSIVE", "CLREX", "SVC", "INDIRECT"}:
            raise GuestContractError(f"0x{pc:x}: uncontracted {kind} in returning-retire function")
        if pc in call_by_site:
            call = call_by_site[pc]
            outcomes_map[pc].add("LIVE_TO_DEAD" if live else "DEAD_TO_DEAD")
            succs_map[pc].add(f"0x{call.normal_return:016x}")
            direct_incoming.add((f"0x{call.normal_return:016x}", f"0x{pc:016x}", "CALL_RETURN"))
            queue.append((call.normal_return, False))
            continue
        if kind == "DIRECT_CALL":
            if live:
                raise GuestContractError(f"0x{pc:x}: unproved BL reached with LIVE monitor")
            outcomes_map[pc].add("DEAD_TO_DEAD")
            succs_map[pc].add(f"0x{pc + 4:016x}")
            direct_incoming.add((f"0x{pc + 4:016x}", f"0x{pc:016x}", "CALL_RETURN"))
            queue.append((pc + 4, False))
            continue
        if kind == "RETURN":
            if live:
                raise GuestContractError(f"0x{pc:x}: RET reached with LIVE monitor")
            outcomes_map[pc].add("DEAD_TO_DEAD")
            continue
        outcome = "LIVE_TO_LIVE" if live else "DEAD_TO_DEAD"
        outcomes_map[pc].add(outcome)
        for idx, target in enumerate(succs):
            if target not in expected_pcs:
                raise GuestContractError(f"0x{pc:x}: local edge to 0x{target:x} leaves function")
            succs_map[pc].add(f"0x{target:016x}")
            if kind == "LINEAR":
                edge_kind = "FALLTHROUGH"
            elif kind == "DIRECT_BRANCH":
                edge_kind = "DIRECT_BRANCH"
            else:
                edge_kind = "CONDITIONAL_FALLTHROUGH" if idx == 0 else "CONDITIONAL_TAKEN"
            direct_incoming.add((f"0x{target:016x}", f"0x{pc:016x}", edge_kind))
            queue.append((target, live))

    # Verify both callsites were reached in LIVE, matching_store was reached ONLY in LIVE,
    # all restores were reached ONLY in DEAD, and no LIVE cycle exists!
    if not live_in_map[ret.matching_store] or dead_in_map[ret.matching_store]:
        raise GuestContractError("matching_store must be reachable exclusively in LIVE state")
    for call in ret.calls:
        if not live_in_map[call.source_callsite]:
            raise GuestContractError(f"0x{call.source_callsite:x}: returning-retire callsite never reached in LIVE")
    for r_pc, _ in ret.restores:
        if live_in_map[r_pc] or not dead_in_map[r_pc]:
            raise GuestContractError(f"0x{r_pc:x}: restore must be reachable exclusively in DEAD state")

    # Check acyclicity of LIVE->LIVE subgraph
    live_nodes = {pc for pc, is_live in live_in_map.items() if is_live}
    visiting: set[int] = set()
    visited_live: set[int] = set()

    def _dfs_live(node: int) -> None:
        visiting.add(node)
        if node not in (ret.matching_store, *call_by_site):
            _, succs = _decode_local_word(node, struct.unpack_from("<I", raw, node)[0])
            for nxt in succs:
                if nxt in live_nodes and nxt != ret.exclusive_head:
                    if nxt in visiting:
                        raise GuestContractError(f"0x{nxt:x}: cycle detected while monitor is LIVE")
                    if nxt not in visited_live:
                        _dfs_live(nxt)
        visiting.remove(node)
        visited_live.add(node)

    for node in sorted(live_nodes):
        if node not in visited_live:
            _dfs_live(node)

    state_facts = []
    for pc in sorted(expected_pcs):
        if not live_in_map[pc] and not dead_in_map[pc]:
            raise GuestContractError(f"0x{pc:x}: unreachable instruction in returning-retire function")
        state_facts.append(
            {
                "pc": f"0x{pc:016x}",
                "live_in": live_in_map[pc],
                "dead_in": dead_in_map[pc],
                "transfer": transfer_map[pc],
                "successors": sorted(succs_map[pc]),
                "outcomes": sorted(outcomes_map[pc]),
            }
        )

    proof = {
        "schema": 1,
        "verdict": "PASS",
        "source_sha256": source_sha256_hex,
        "build_id": build_id_hex,
        "tool_hashes": tool_hashes,
        "function": {
            "start": f"0x{start:016x}",
            "end": f"0x{end:016x}",
            "fde": f"0x{ret.fde_offset:016x}",
            "cie": f"0x{ret.cie_offset:016x}",
            "function_sha256": ret.function_sha256_hex,
        },
        "exclusive": {
            "head": f"0x{ret.exclusive_head:016x}",
            "store": f"0x{ret.matching_store:016x}",
        },
        "final_roots": [f"0x{r:016x}" for r in sorted(set(final_roots))],
        "independent_roots": [f"0x{r:016x}" for r in sorted(set(independent_roots))],
        "direct_incoming": [
            {"from": frm, "to": to, "kind": knd} for to, frm, knd in sorted(direct_incoming)
        ],
        "calls": [
            {
                "callsite": f"0x{c.source_callsite:016x}",
                "original_bl_word": f"0x{c.original_bl_word:08x}",
                "target": f"0x{c.original_target:016x}",
                "normal_return": f"0x{c.normal_return:016x}",
            }
            for c in ret.calls
        ],
        "state_facts": state_facts,
        "restores": [
            {"ordinal": idx, "pc": f"0x{r_pc:016x}", "original_word": f"0x{r_word:08x}"}
            for idx, (r_pc, r_word) in enumerate(ret.restores)
        ],
        "leave_monitor": leave_obj,
    }
    validate_ownership_proof_v1(proof)
    return proof


def select_taiko_guest_contract(
    source: bytes,
    raw: bytes,
    by_pc: Mapping[int, object],
    *,
    independent_roots: Sequence[int],
    final_roots: Sequence[int],
    patch_offset: int,
    spec: GuestContractSourceSpec | None = None,
) -> SelectedGuestContract:
    from nso_eh import validated_eh_functions
    from nso_format import NsoError, parse_metadata, parse_nso

    spec = TAIKO_SDK_GUEST_CONTRACT_SPEC if spec is None else spec
    try:
        nso = parse_nso(bytes(source))
        metadata = parse_metadata(nso)
        eh_funcs = validated_eh_functions(nso, metadata)
    except NsoError as error:
        raise GuestContractError(f"invalid NSO/EH input for guest contract: {error}") from error

    if nso.source_sha256.hex() != spec.source_sha256_hex:
        raise GuestContractError("source SHA-256 does not match contracted v3 SDK")
    if nso.build_id.hex() != spec.build_id_hex:
        raise GuestContractError("build ID does not match contracted v3 SDK")
    if bytes(raw) != nso.image:
        raise GuestContractError("raw image does not match parsed NSO image")

    ind_roots_sorted = tuple(sorted(set(independent_roots)))
    final_roots_sorted = tuple(sorted(set(final_roots)))
    ind_roots_sha = roots_set_sha256(ind_roots_sorted)
    ind_roots_set = set(ind_roots_sorted)

    eh_by_start = {f.start: f for f in eh_funcs}
    if len(spec.exact_guest_sites) != 5:
        raise GuestContractError("contracted v3 SDK must specify 5 exact guest sites")

    dynsym_base = metadata.dynamic[6]
    dynstr_base = metadata.dynamic[5]
    exact_records: list[ExactGuestRecordV1] = []
    prev_br = -1
    for site in spec.exact_guest_sites:
        if site.original_br_offset <= prev_br:
            raise GuestContractError("exact guest sites must be strictly sorted by original_br_offset")
        prev_br = site.original_br_offset
        plt_entry = site.original_br_offset - 12
        got_off, br_word, reg = _decode_plt_got(nso.image, plt_entry)
        if got_off != site.got_offset or br_word != site.original_br_word or reg != site.target_register:
            raise GuestContractError(f"0x{site.original_br_offset:x}: PLT stub does not match exact guest spec")
        if site.original_br_offset in by_pc and getattr(by_pc[site.original_br_offset], "mnemonic", None) != "br":
            raise GuestContractError(f"0x{site.original_br_offset:x}: decoded instruction is not BR")

        if not (0 <= site.relocation_index < len(metadata.relocations)):
            raise GuestContractError(f"0x{site.original_br_offset:x}: relocation_index out of range")
        rel = metadata.relocations[site.relocation_index]
        if (
            rel.offset != site.got_offset
            or rel.kind != site.relocation_type
            or site.relocation_type != 1026
            or rel.symbol != site.symbol_index
            or rel.addend != site.relocation_addend
            or site.relocation_addend != 0
        ):
            raise GuestContractError(f"0x{site.original_br_offset:x}: relocation tuple mismatch")
        if sum(1 for r in metadata.relocations if r.offset == site.got_offset) != 1:
            raise GuestContractError(f"0x{site.got_offset:x}: duplicate relocation for GOT slot")

        if not (0 < site.symbol_index < len(metadata.symbols)):
            raise GuestContractError(f"0x{site.original_br_offset:x}: symbol_index out of range")
        sym = metadata.symbols[site.symbol_index]
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", nso.image, dynsym_base + site.symbol_index * 24
        )
        sym_type = st_info & 0xF
        sym_bind = st_info >> 4
        sym_vis = st_other & 3
        name_bytes = site.symbol_name.encode("ascii")
        if (
            sym.name != site.symbol_name
            or st_name != site.symbol_name_offset
            or len(name_bytes) != site.symbol_name_length
            or nso.image[dynstr_base + st_name : dynstr_base + st_name + len(name_bytes) + 1] != name_bytes + b"\x00"
            or sym_type != site.symbol_type
            or sym_type != 2
            or sym_bind != site.symbol_binding
            or sym_bind != 1
            or sym_vis != site.symbol_visibility
            or sym_vis != 0
            or st_shndx != site.symbol_section_index
            or st_shndx == 0
            or st_value != site.symbol_value
            or st_size != site.symbol_size
        ):
            raise GuestContractError(f"0x{site.original_br_offset:x}: symbol metadata mismatch for {site.symbol_name}")

        if (
            site.same_module_target_offset != site.function_start
            or site.function_start != site.symbol_value
            or site.independent_root_offset != site.function_start
            or site.independent_root_offset not in ind_roots_set
        ):
            raise GuestContractError(f"0x{site.original_br_offset:x}: target/root offset mismatch")

        if site.eh_identity_kind == 1:
            eh = eh_by_start.get(site.function_start)
            if (
                eh is None
                or eh.start != site.function_start
                or eh.end != site.function_end
                or eh.fde != site.fde_offset
                or eh.cie != site.cie_offset
            ):
                raise GuestContractError(f"0x{site.function_start:x}: FDE/CIE extent mismatch")
            if site.symbol_size and site.function_end != site.symbol_value + site.symbol_size:
                raise GuestContractError(f"0x{site.function_start:x}: symbol size disagrees with FDE")
            eh_sha = eh_identity_kind1_sha256(
                nso.image, site.function_start, site.function_end, site.cie_offset, site.fde_offset
            )
        elif site.eh_identity_kind == 0:
            if site.fde_offset or site.cie_offset:
                raise GuestContractError(f"0x{site.function_start:x}: kind-0 EH must have zero FDE/CIE")
            for f in eh_funcs:
                if f.start < site.function_end and site.function_start < f.end:
                    raise GuestContractError(f"0x{site.function_start:x}: kind-0 function overlaps FDE")
            if site.symbol_size and site.function_end != site.symbol_value + site.symbol_size:
                raise GuestContractError(f"0x{site.function_start:x}: kind-0 symbol size mismatch")
            _verify_zero_size_closed_cfg(
                nso.image,
                by_pc,
                site.function_start,
                site.function_end,
                nso.sections[0].end,
                metadata.symbols,
            )
            eh_sha = ZERO_DIGEST
        else:
            raise GuestContractError("unsupported eh_identity_kind")

        func_bytes = nso.image[site.function_start : site.function_end]
        func_sha = hashlib.sha256(func_bytes).digest()
        if func_sha.hex() != site.function_sha256_hex:
            raise GuestContractError(f"0x{site.function_start:x}: function SHA-256 mismatch")

        exact_records.append(
            ExactGuestRecordV1(
                gate_return_offset=patch_offset,
                original_br_offset=site.original_br_offset,
                original_br_word=site.original_br_word,
                target_register=site.target_register,
                got_offset=site.got_offset,
                relocation_index=site.relocation_index,
                relocation_type=site.relocation_type,
                symbol_index=site.symbol_index,
                symbol_type=site.symbol_type,
                symbol_binding=site.symbol_binding,
                symbol_visibility=site.symbol_visibility,
                relocation_addend=site.relocation_addend,
                symbol_name_offset=site.symbol_name_offset,
                symbol_name_length=site.symbol_name_length,
                symbol_section_index=site.symbol_section_index,
                eh_identity_kind=site.eh_identity_kind,
                symbol_value=site.symbol_value,
                symbol_size=site.symbol_size,
                same_module_target_offset=site.same_module_target_offset,
                function_start=site.function_start,
                function_end=site.function_end,
                fde_offset=site.fde_offset,
                cie_offset=site.cie_offset,
                independent_root_offset=site.independent_root_offset,
                symbol_name_sha256=hashlib.sha256(name_bytes).digest(),
                function_sha256=func_sha,
                eh_identity_sha256=eh_sha,
                final_independent_roots_sha256=ind_roots_sha,
            ).validate()
        )

    pack_exact_guest_table(exact_records)

    # Verify Leave monitor against the Leave exact-guest target
    leave_site = next(
        (s for s in spec.exact_guest_sites if s.symbol_name.endswith("InternalCriticalSectionImplByHorizon5LeaveEv")),
        None,
    )
    if (
        leave_site is None
        or spec.leave_monitor.entry != leave_site.function_start
        or spec.leave_monitor.end != leave_site.function_end
    ):
        raise GuestContractError("Leave monitor spec does not match Leave exact-guest target")
    leave_obj = _verify_leave_monitor(nso.image, by_pc, spec.leave_monitor, metadata)

    # Verify returning-retire function FDE/CIE and build whole-function ownership proof
    ret = spec.returning_retire
    ret_eh = eh_by_start.get(ret.function_start)
    if (
        ret_eh is None
        or ret_eh.start != ret.function_start
        or ret_eh.end != ret.function_end
        or ret_eh.fde != ret.fde_offset
        or ret_eh.cie != ret.cie_offset
    ):
        raise GuestContractError("returning-retire function FDE/CIE mismatch")

    recipe = current_toolset_recipe_v1()
    recipe_sha = toolset_recipe_sha256(recipe)
    proof = _prove_returning_retire_function(
        nso.image,
        by_pc,
        ret,
        spec.exact_guest_sites,
        source_sha256_hex=spec.source_sha256_hex,
        build_id_hex=spec.build_id_hex,
        tool_hashes=list(recipe["files"]),
        final_roots=final_roots_sorted,
        independent_roots=ind_roots_sorted,
        leave_obj=leave_obj,
    )
    proof_sha = ownership_proof_sha256(proof)
    ret_func_sha = bytes.fromhex(ret.function_sha256_hex)

    retire_records: list[ReturningRetireRecordV1] = []
    for call in ret.calls:
        retire_records.append(
            ReturningRetireRecordV1(
                source_callsite=call.source_callsite,
                original_bl_word=call.original_bl_word,
                stub_extent=call.stub_extent,
                original_target=call.original_target,
                normal_return=call.normal_return,
                reserved_stub_offset=patch_offset + call.reserved_stub_delta,
                exclusive_head=ret.exclusive_head,
                matching_store=ret.matching_store,
                function_start=ret.function_start,
                function_end=ret.function_end,
                fde_offset=ret.fde_offset,
                cie_offset=ret.cie_offset,
                function_sha256=ret_func_sha,
                final_independent_roots_sha256=ind_roots_sha,
                whole_function_ownership_proof_sha256=proof_sha,
            ).validate()
        )
    pack_returning_retire_table(retire_records)

    return SelectedGuestContract(
        exact_guest_records=tuple(exact_records),
        returning_retire_records=tuple(retire_records),
        ownership_proof=proof,
        ownership_proof_sha256=proof_sha,
        toolset_recipe=recipe,
        toolset_recipe_sha256=recipe_sha,
        final_independent_roots_sha256=ind_roots_sha,
    )


def build_trusted_audit_v1(
    package: bytes,
    *,
    source_sha256: bytes,
    build_id: bytes,
    exact_guest_records: Sequence[ExactGuestRecordV1],
    returning_retire_records: Sequence[ReturningRetireRecordV1],
    toolset_recipe_digest: bytes,
    final_independent_roots_digest: bytes,
    ownership_proof_digest: bytes,
) -> dict[str, object]:
    exact_bytes = pack_exact_guest_table(exact_guest_records)
    retire_bytes = pack_returning_retire_table(returning_retire_records)
    body: dict[str, object] = {
        "schema": 1,
        "flags": 0,
        "package_sha256": hashlib.sha256(package).hexdigest(),
        "source_sha256": _digest("source_sha256", source_sha256).hex(),
        "build_id": _digest("build_id", build_id, allow_zero=True).hex(),
        "toolset_recipe_sha256": _digest("toolset_recipe_sha256", toolset_recipe_digest).hex(),
        "exact_guest": {
            "count": len(exact_guest_records),
            "table_sha256": table_digest(exact_bytes).hex(),
        },
        "returning_retire": {
            "count": len(returning_retire_records),
            "table_sha256": table_digest(retire_bytes).hex(),
        },
        "final_independent_roots_sha256": _digest(
            "final_independent_roots_sha256", final_independent_roots_digest
        ).hex(),
        "whole_function_ownership_proof_sha256": _digest(
            "whole_function_ownership_proof_sha256", ownership_proof_digest
        ).hex(),
    }
    validate_audit_object_v1(body)
    full = dict(body)
    full["audit_identity_sha256"] = audit_identity_sha256(body).hex()
    validate_trusted_audit_v1(full)
    return full


