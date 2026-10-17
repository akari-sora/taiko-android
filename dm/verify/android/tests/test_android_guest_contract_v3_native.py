"""Required MSVC cross-language parity for the portable DMAMOD03 decoder."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[4]
LIVE = Path(os.environ.get("TAIKO_LIVE_REPO", ROOT))
EVIDENCE = Path(os.environ.get("DM_TEST_OUTPUT_ROOT", ROOT))
sys.path[:0] = [str(ROOT / "dm/tools"), str(LIVE / "dm/tools"), str(Path(__file__).parent)]

import android_guest_contract as contract
import android_import as importer
from test_android_guest_contract_v3 import GuestContractImporterTests


def cpp_bytes(name: str, value: bytes) -> str:
    rows = []
    for start in range(0, len(value), 24):
        rows.append("  " + ",".join(f"0x{x:02x}" for x in value[start:start + 24]))
    return f"static const uint8_t {name}[]={{\n" + ",\n".join(rows) + "\n};\n"


class NativeGuestContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        GuestContractImporterTests.setUpClass()
        helper = GuestContractImporterTests(methodName="runTest")
        cls.empty = importer.make_package("main", helper.nso, helper.metadata,
                                          helper.image(typed=False), 0x4000, 3)
        cls.nonempty = importer.make_package("sdk", helper.nso, helper.metadata,
                                             helper.image(typed=True), 0x4000, 3)
        cls.golden = json.loads((ROOT / "dm/verify/android/fixtures/dmamod03_v1_golden.json").read_text(encoding="utf-8"))

    def test_msvc_decoder_audit_and_negative_matrix(self):
        vs = Path(r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat")
        self.assertTrue(vs.is_file(), "MSVC is mandatory; missing compiler is not a parity pass")
        run = EVIDENCE / "native-runs" / ("dmamod03-" + uuid.uuid4().hex)
        self.assertFalse(run.exists(), "native run directory must be unique")
        run.mkdir(parents=True)
        if not os.environ.get("DM_TEST_OUTPUT_ROOT"):
            self.addCleanup(shutil.rmtree, run, ignore_errors=True)
        package_sha = hashlib.sha256(self.nonempty).digest()
        body = copy.deepcopy(self.golden["audit"]["object_without_identity"])
        body["package_sha256"] = package_sha.hex()
        body["source_sha256"] = self.nonempty[216:248].hex()
        body["build_id"] = self.nonempty[184:216].hex()
        body["exact_guest"] = {"count": 1, "table_sha256": self.nonempty[432:464].hex()}
        body["returning_retire"] = {"count": 1, "table_sha256": self.nonempty[464:496].hex()}
        body["final_independent_roots_sha256"] = self.golden["roots"]["sha256"]
        body["whole_function_ownership_proof_sha256"] = self.golden["ownership"]["sha256"]
        audit_identity = contract.audit_identity_sha256(body)
        arrays = "".join((cpp_bytes("empty_package", self.empty),
                          cpp_bytes("full_package", self.nonempty),
                          cpp_bytes("package_sha", package_sha),
                          cpp_bytes("source_sha", self.nonempty[216:248]),
                          cpp_bytes("build_id", self.nonempty[184:216]),
                          cpp_bytes("recipe_sha", bytes.fromhex(body["toolset_recipe_sha256"])),
                          cpp_bytes("audit_sha", audit_identity),
                          cpp_bytes("roots_sha", bytes.fromhex(body["final_independent_roots_sha256"])),
                          cpp_bytes("proof_sha", bytes.fromhex(body["whole_function_ownership_proof_sha256"]))))
        source = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include "guest_contract_wire.h"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
#pragma comment(lib,"bcrypt.lib")
using namespace dm_android;
''' + arrays + r'''
bool sha256(const uint8_t* p,size_t n,uint8_t out[32],void*){
 BCRYPT_ALG_HANDLE alg=nullptr;BCRYPT_HASH_HANDLE hash=nullptr;DWORD object_bytes=0,result=0;std::vector<uint8_t> object;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0)return false;
 if(BCryptGetProperty(alg,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&object_bytes),sizeof(object_bytes),&result,0)<0){BCryptCloseAlgorithmProvider(alg,0);return false;}
 object.resize(object_bytes);
 bool ok=BCryptCreateHash(alg,&hash,object.data(),object_bytes,nullptr,0,0)>=0 &&
         BCryptHashData(hash,const_cast<PUCHAR>(p),static_cast<ULONG>(n),0)>=0 &&
         BCryptFinishHash(hash,out,32,0)>=0;
 if(hash)BCryptDestroyHash(hash);BCryptCloseAlgorithmProvider(alg,0);return ok;
}
void put32(std::vector<uint8_t>& v,size_t at,uint32_t n){for(unsigned i=0;i<4;++i)v[at+i]=uint8_t(n>>(i*8));}
void put64(std::vector<uint8_t>& v,size_t at,uint64_t n){for(unsigned i=0;i<8;++i)v[at+i]=uint8_t(n>>(i*8));}
template<size_t N>void load(std::array<uint8_t,32>& out,const uint8_t(&in)[N]){static_assert(N==32);std::copy_n(in,32,out.begin());}
int main(){
 GuestContractWireError error=GuestContractWireError::Ok;DecodedGuestContractV1 empty{},full{};
 assert(decode_guest_contract_v3(empty_package,sizeof(empty_package),sha256,nullptr,&empty,&error));
 assert(empty.exact_guest.empty()&&empty.returning_retire.empty()&&empty.exact_guest_offset==512&&empty.returning_retire_offset==512);
 assert(decode_guest_contract_v3(full_package,sizeof(full_package),sha256,nullptr,&full,&error));
 assert(full.exact_guest.size()==1&&full.returning_retire.size()==1&&full.exact_guest_offset==544&&full.returning_retire_offset==832&&full.payload_offset==1024);
 const auto& x=full.exact_guest[0];assert(x.gate_return_offset==0x4040&&x.original_br_offset==0x140&&x.target_register==17&&x.relocation_addend==-5&&x.same_module_target_offset==0x210);
 const auto& r=full.returning_retire[0];assert(r.source_callsite==0x300&&r.normal_return==0x304&&r.stub_extent==8&&r.reserved_stub_offset==0x4080);
 TrustedGuestContractAuditV1 audit{};load(audit.package_sha256,package_sha);load(audit.source_sha256,source_sha);load(audit.build_id,build_id);
 load(audit.toolset_recipe_sha256,recipe_sha);load(audit.audit_identity_sha256,audit_sha);audit.exact_guest_count=1;
 audit.exact_guest_table_sha256=full.exact_guest_table_sha256;audit.returning_retire_count=1;audit.returning_retire_table_sha256=full.returning_retire_table_sha256;
 load(audit.final_independent_roots_sha256,roots_sha);load(audit.whole_function_ownership_proof_sha256,proof_sha);
 assert(validate_guest_contract_audit_v1(full,audit,package_sha,source_sha,build_id,sha256,nullptr,&error));
 auto reject=[&](std::vector<uint8_t> bad){DecodedGuestContractV1 d{};return !decode_guest_contract_v3(bad.data(),bad.size(),sha256,nullptr,&d,&error);};
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b[0]^=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,8,2);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,12,0);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,16,384);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,20,0x1d);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,20,0x0c);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b[496]=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,400,280);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,404,2);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put64(b,384,552);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));std::swap_ranges(b.begin()+384,b.begin()+408,b.begin()+408);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b[432]^=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b[544]^=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b[544+4]=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,544+28,16);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b[544+55]=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b[544+272]=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put64(b,544+16,0x141);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,512+20,16);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));put32(b,512+28,1);assert(reject(b));}
 {auto b=std::vector<uint8_t>(empty_package,empty_package+sizeof(empty_package));put32(b,20,9);b[464]=1;assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));const uint64_t payload=1024;b.insert(b.begin()+payload,16,0);put64(b,112,payload+16);assert(reject(b));}
 {auto b=std::vector<uint8_t>(full_package,full_package+sizeof(full_package));b.push_back(0);assert(reject(b));}
 auto audit_reject=[&](const TrustedGuestContractAuditV1& changed){return !validate_guest_contract_audit_v1(full,changed,package_sha,source_sha,build_id,sha256,nullptr,&error);};
 {auto a=audit;a.schema=2;assert(audit_reject(a));}{auto a=audit;a.flags=1;assert(audit_reject(a));}
 {auto a=audit;a.package_sha256[0]^=1;assert(audit_reject(a));}{auto a=audit;a.source_sha256[0]^=1;assert(audit_reject(a));}
 {auto a=audit;a.build_id[0]^=1;assert(audit_reject(a));}{auto a=audit;a.toolset_recipe_sha256[0]^=1;assert(audit_reject(a));}
 {auto a=audit;a.exact_guest_count=2;assert(audit_reject(a));}{auto a=audit;a.exact_guest_table_sha256[0]^=1;assert(audit_reject(a));}
 {auto a=audit;a.returning_retire_count=2;assert(audit_reject(a));}{auto a=audit;a.returning_retire_table_sha256[0]^=1;assert(audit_reject(a));}
 {auto a=audit;a.final_independent_roots_sha256[0]^=1;assert(audit_reject(a));}{auto a=audit;a.whole_function_ownership_proof_sha256[0]^=1;assert(audit_reject(a));}
 {auto a=audit;a.audit_identity_sha256[0]^=1;assert(audit_reject(a));}
 return 0;
}
'''
        cpp = run / "dmamod03_native.cpp"
        cpp.write_text(source, encoding="ascii")
        platform = ROOT / "dm/platform/android"
        live_platform = LIVE / "dm/platform/android"
        exe = run / "dmamod03_native.exe"
        command = (f'call "{vs}" -arch=x64 -host_arch=x64 >nul && '
                   f'cl /nologo /std:c++17 /EHsc /W4 /WX /I"{platform}" /I"{live_platform}" '
                   f'"{cpp}" "{platform / "guest_contract_wire.cpp"}" bcrypt.lib /Fe:"{exe}"')
        batch = run / "build.cmd"
        batch.write_text("@echo off\r\n" + command + "\r\n", encoding="ascii")
        compiled = subprocess.run(["cmd.exe", "/d", "/c", str(batch)], capture_output=True, text=True, cwd=str(run))
        (run / "compile.stdout.log").write_text(compiled.stdout, encoding="utf-8")
        (run / "compile.stderr.log").write_text(compiled.stderr, encoding="utf-8")
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        executed = subprocess.run([str(exe)], capture_output=True, text=True)
        (run / "run.stdout.log").write_text(executed.stdout, encoding="utf-8")
        (run / "run.stderr.log").write_text(executed.stderr, encoding="utf-8")
        (run / "result.json").write_text(json.dumps({"compile_exit": compiled.returncode,
                                                       "run_exit": executed.returncode,
                                                       "full_package_sha256": package_sha.hex(),
                                                       "audit_identity_sha256": audit_identity.hex()}, indent=2) + "\n")
        self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
