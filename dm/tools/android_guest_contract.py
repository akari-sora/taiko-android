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
            if (not self.symbol_size or self.function_start != self.symbol_value or
                    self.function_end != self.symbol_value + self.symbol_size or
                    self.fde_offset or self.cie_offset or self.eh_identity_sha256 != ZERO_DIGEST):
                raise GuestContractError("kind-0 EH identity is not an exact positive symbol range")
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

