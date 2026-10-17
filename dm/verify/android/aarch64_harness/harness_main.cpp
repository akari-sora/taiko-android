#include "guest_abi.h"
#include "guest_loader_internal.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sstream>
#include <string>
#include <vector>

#ifndef DM_GUEST_LOADER_SHA256
#define DM_GUEST_LOADER_SHA256 "unknown"
#endif

extern "C" {
uint32_t dm_synthetic_dso_version();
uint32_t dm_synthetic_const42();
uint64_t dm_synthetic_read_x18();
uint64_t dm_synthetic_read_tpidr_el0();
uint64_t dm_synthetic_read_sp();
uint32_t dm_synthetic_exclusive_retry_ok(uint64_t* word);
uint32_t dm_synthetic_exclusive_explicit_clrex(uint64_t* word);
uint32_t dm_synthetic_exclusive_bl_clrex_stub(uint64_t* word);
void dm_synthetic_long_diag_abort_entry(
    uint64_t x0, uint64_t x1, uint64_t x2,
    uint64_t x3, uint64_t x4, uint64_t x5, ...);

void* __real_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
int __real_mprotect(void* addr, size_t len, int prot);
int __real_munmap(void* addr, size_t length);

// Fail-fast test-only definitions for symbols referenced by guest_loader.cpp.
// Executable generic fixtures have empty fixups/gates; any unexpected helper call terminates.
void dm_android_state_accessor() { _exit(98); }
void dm_android_dispatch_gate() { _exit(99); }
}

namespace {

enum class FailMode {
    None,
    Mmap,
    MprotectRw,
    MprotectRx,
};

struct SyscallEvent {
    const char* op;
    uintptr_t addr;
    size_t len;
    int prot;
    int flags;
    int result;
};

struct ReservationSpan {
    uintptr_t addr;
    size_t len;
};

struct SyscallLedger {
    bool recording = false;
    bool rwx_violation = false;
    FailMode fail_mode = FailMode::None;
    std::vector<SyscallEvent> events;
    std::vector<ReservationSpan> active_reservations;

    void reset(FailMode mode = FailMode::None) {
        recording = true;
        rwx_violation = false;
        fail_mode = mode;
        events.clear();
        active_reservations.clear();
    }

    void stop() {
        recording = false;
        fail_mode = FailMode::None;
    }
};

SyscallLedger g_ledger;

struct LongAbortReceipt {
    uint64_t x[6];
    uint64_t captured_lr;
    uint64_t captured_sp;
    uint64_t magic;
};

int g_long_abort_pipe_fd = -1;

}  // namespace

extern "C" __attribute__((visibility("hidden"), noreturn))
void dm_synthetic_long_diag_abort_target(
    uint64_t x0, uint64_t x1, uint64_t x2,
    uint64_t x3, uint64_t x4, uint64_t x5,
    uint64_t captured_lr, uint64_t captured_sp) {
    if (g_long_abort_pipe_fd >= 0) {
        LongAbortReceipt receipt{
            {x0, x1, x2, x3, x4, x5},
            captured_lr,
            captured_sp,
            UINT64_C(0x444d4c4f4e473432),
        };
        const ssize_t written = write(g_long_abort_pipe_fd, &receipt, sizeof(receipt));
        (void)written;
        close(g_long_abort_pipe_fd);
    }
    _exit(42);
}

extern "C" void* __wrap_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
        g_ledger.rwx_violation = true;
        errno = EACCES;
        return MAP_FAILED;
    }
    if (g_ledger.recording && g_ledger.fail_mode == FailMode::Mmap) {
        g_ledger.fail_mode = FailMode::None;
        g_ledger.events.push_back({"mmap", 0, length, prot, flags, -1});
        errno = ENOMEM;
        return MAP_FAILED;
    }
    void* res = __real_mmap(addr, length, prot, flags, fd, offset);
    if (g_ledger.recording) {
        const uintptr_t mapped_addr = (res == MAP_FAILED) ? 0 : reinterpret_cast<uintptr_t>(res);
        g_ledger.events.push_back({"mmap", mapped_addr, length, prot, flags, (res == MAP_FAILED) ? -1 : 0});
        if (res != MAP_FAILED) {
            g_ledger.active_reservations.push_back({mapped_addr, length});
        }
    }
    return res;
}

extern "C" int __wrap_mprotect(void* addr, size_t len, int prot) {
    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
        g_ledger.rwx_violation = true;
        errno = EACCES;
        return -1;
    }
    if (g_ledger.recording) {
        if (g_ledger.fail_mode == FailMode::MprotectRw && (prot & PROT_WRITE) != 0) {
            g_ledger.fail_mode = FailMode::None;
            g_ledger.events.push_back({"mprotect", reinterpret_cast<uintptr_t>(addr), len, prot, 0, -1});
            errno = EACCES;
            return -1;
        }
        if (g_ledger.fail_mode == FailMode::MprotectRx && (prot & PROT_EXEC) != 0) {
            g_ledger.fail_mode = FailMode::None;
            g_ledger.events.push_back({"mprotect", reinterpret_cast<uintptr_t>(addr), len, prot, 0, -1});
            errno = EACCES;
            return -1;
        }
    }
    const int res = __real_mprotect(addr, len, prot);
    if (g_ledger.recording) {
        g_ledger.events.push_back({"mprotect", reinterpret_cast<uintptr_t>(addr), len, prot, 0, res});
    }
    return res;
}

extern "C" int __wrap_munmap(void* addr, size_t length) {
    const int res = __real_munmap(addr, length);
    if (g_ledger.recording) {
        const uintptr_t uaddr = reinterpret_cast<uintptr_t>(addr);
        g_ledger.events.push_back({"munmap", uaddr, length, 0, 0, res});
        if (res == 0) {
            for (auto it = g_ledger.active_reservations.begin(); it != g_ledger.active_reservations.end(); ++it) {
                if (it->addr == uaddr && it->len == length) {
                    g_ledger.active_reservations.erase(it);
                    break;
                }
            }
        }
    }
    return res;
}

namespace {

bool run_page_rounding_probe(size_t expected_page_size, std::string& detail) {
    const long actual_page_query = sysconf(_SC_PAGESIZE);
    if (actual_page_query <= 0) {
        detail = "sysconf(_SC_PAGESIZE) returned non-positive value";
        return false;
    }
    const size_t runtime_page = static_cast<size_t>(actual_page_query);
    if (expected_page_size != 0 && runtime_page != expected_page_size) {
        detail = "runtime page size mismatch: actual=" + std::to_string(runtime_page) +
                 " expected=" + std::to_string(expected_page_size);
        return false;
    }

    size_t out = 0;
    const bool round_4k_ok =
        dm_android_guest_round_size(1, 4096, &out) && out == 4096 &&
        dm_android_guest_round_size(4095, 4096, &out) && out == 4096 &&
        dm_android_guest_round_size(4096, 4096, &out) && out == 4096 &&
        dm_android_guest_round_size(4097, 4096, &out) && out == 8192;
    const bool round_16k_ok =
        dm_android_guest_round_size(1, 16384, &out) && out == 16384 &&
        dm_android_guest_round_size(16383, 16384, &out) && out == 16384 &&
        dm_android_guest_round_size(16384, 16384, &out) && out == 16384 &&
        dm_android_guest_round_size(16385, 16384, &out) && out == 32768;
    const bool negatives_ok =
        !dm_android_guest_round_size(0, 4096, &out) &&
        !dm_android_guest_round_size(1, 0, &out) &&
        !dm_android_guest_round_size(1, 123, &out) &&
        !dm_android_guest_round_size(SIZE_MAX, 4096, &out) &&
        !dm_android_guest_round_size(SIZE_MAX, 16384, &out);

    detail = "page_size=" + std::to_string(runtime_page) + " 4K/16K rounding and overflow negatives verified";
    return round_4k_ok && round_16k_ok && negatives_ok;
}

bool run_wx_loader_probe(std::string& detail) {
    const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    // mov w0, #42 ; ret
    static const uint32_t code42[] = {0x52800540u, 0xd65f03c0u};
    // mov w0, #43 ; ret
    static const uint32_t code43[] = {0x52800560u, 0xd65f03c0u};

    const DmGuestImage img42{
        DM_ANDROID_GUEST_ABI,
        reinterpret_cast<const uint8_t*>(code42),
        sizeof(code42),
        0,
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        0,
    };

    DmGuestLoadedImage loaded{};
    char error[160]{};
    g_ledger.reset(FailMode::None);
    if (!dm_android_guest_prepare(img42, &loaded, error, sizeof(error))) {
        g_ledger.stop();
        detail = std::string("prepare failed: ") + error;
        return false;
    }
    if (loaded.sealed || loaded.mapping_size != page || loaded.reservation_size != 3 * page) {
        dm_android_guest_unload(&loaded);
        g_ledger.stop();
        detail = "unexpected unsealed mapping geometry";
        return false;
    }
    if (!dm_android_guest_seal(&loaded, error, sizeof(error)) || !loaded.sealed) {
        dm_android_guest_unload(&loaded);
        g_ledger.stop();
        detail = std::string("seal failed: ") + error;
        return false;
    }

    const uint64_t x18_before = dm_synthetic_read_x18();
    const uint64_t tp_before = dm_synthetic_read_tpidr_el0();
    const uint64_t sp_before = dm_synthetic_read_sp();
    auto fn42 = reinterpret_cast<uint32_t (*)()>(loaded.base);
    const uint32_t val42 = fn42();
    const uint64_t x18_after = dm_synthetic_read_x18();
    const uint64_t tp_after = dm_synthetic_read_tpidr_el0();
    const uint64_t sp_after = dm_synthetic_read_sp();

    dm_android_guest_unload(&loaded);
    const bool ledger_clean_42 =
        !g_ledger.rwx_violation &&
        g_ledger.active_reservations.empty() &&
        g_ledger.events.size() == 4 &&
        g_ledger.events[0].prot == PROT_NONE &&
        g_ledger.events[1].prot == (PROT_READ | PROT_WRITE) &&
        g_ledger.events[2].prot == (PROT_READ | PROT_EXEC);
    g_ledger.stop();

    if (val42 != 42 || !ledger_clean_42 || x18_before != x18_after ||
        tp_before != tp_after || sp_before != sp_after || (sp_before & 15) != 0) {
        detail = "code42 execution or W^X ledger check failed";
        return false;
    }

    const DmGuestImage img43{
        DM_ANDROID_GUEST_ABI,
        reinterpret_cast<const uint8_t*>(code43),
        sizeof(code43),
        0,
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        0,
    };
    g_ledger.reset(FailMode::None);
    if (!dm_android_guest_load(img43, &loaded, error, sizeof(error))) {
        g_ledger.stop();
        detail = std::string("load code43 failed: ") + error;
        return false;
    }
    const uint32_t val43 = reinterpret_cast<uint32_t (*)()>(loaded.base)();
    dm_android_guest_unload(&loaded);
    const bool ledger_clean_43 = !g_ledger.rwx_violation && g_ledger.active_reservations.empty();
    g_ledger.stop();
    if (val43 != 43 || !ledger_clean_43) {
        detail = "code43 replacement mapping check failed";
        return false;
    }

    // Verify failure injection cleanup for mmap, RW mprotect, and RX mprotect.
    for (FailMode mode : {FailMode::Mmap, FailMode::MprotectRw, FailMode::MprotectRx}) {
        DmGuestLoadedImage failed_image{};
        char fail_err[160]{};
        g_ledger.reset(mode);
        const bool ok = dm_android_guest_load(img42, &failed_image, fail_err, sizeof(fail_err));
        const bool cleaned_up = !ok && failed_image.base == nullptr &&
                                !g_ledger.rwx_violation && g_ledger.active_reservations.empty();
        g_ledger.stop();
        if (!cleaned_up) {
            detail = "failure injection did not clean up reservation or unexpectedly succeeded";
            return false;
        }
    }

    detail = "guarded W^X prepare/seal/unload + code42/43 + failure injection cleanup verified";
    return true;
}

bool run_x18_and_dso_probe(const std::string& module_path, std::string& detail) {
    const uint64_t x18_0 = dm_synthetic_read_x18();
    const uint64_t tp_0 = dm_synthetic_read_tpidr_el0();
    const uint64_t sp_0 = dm_synthetic_read_sp();
    if ((sp_0 & 15) != 0 || dm_synthetic_const42() != 42 || dm_synthetic_dso_version() != 0x444d5331u) {
        detail = "direct synthetic probe ABI check failed";
        return false;
    }

    if (!module_path.empty()) {
        void* handle = dlopen(module_path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            detail = std::string("dlopen failed: ") + dlerror();
            return false;
        }
        auto ver_fn = reinterpret_cast<uint32_t (*)()>(dlsym(handle, "dm_synthetic_dso_version"));
        auto c42_fn = reinterpret_cast<uint32_t (*)()>(dlsym(handle, "dm_synthetic_const42"));
        const bool symbols_ok = ver_fn && c42_fn && ver_fn() == 0x444d5331u && c42_fn() == 42;
        dlclose(handle);
        if (!symbols_ok) {
            detail = "dlsym verification failed on libsynthetic_guest_dso.so";
            return false;
        }
    }

    const uint64_t x18_1 = dm_synthetic_read_x18();
    const uint64_t tp_1 = dm_synthetic_read_tpidr_el0();
    if (x18_0 != x18_1 || tp_0 != tp_1) {
        detail = "x18 or TPIDR_EL0 changed across probe execution";
        return false;
    }
    detail = "x18/TPIDR_EL0 unchanged, SP 16-byte aligned, DSO exports verified";
    return true;
}

bool run_exclusive_and_long_abort_probe(std::string& detail) {
    alignas(16) uint64_t word = 41;
    const uint32_t retry_status = dm_synthetic_exclusive_retry_ok(&word);
    if (retry_status != 0 || word != 42) {
        detail = "exclusive retry baseline did not succeed";
        return false;
    }
    const uint32_t explicit_clrex_status = dm_synthetic_exclusive_explicit_clrex(&word);
    if (explicit_clrex_status == 0 || word != 42) {
        detail = "explicit CLREX did not clear exclusive monitor";
        return false;
    }
    const uint32_t bl_clrex_status = dm_synthetic_exclusive_bl_clrex_stub(&word);
    if (bl_clrex_status == 0 || word != 42) {
        detail = "BL -> private CLREX-first stub -> B RET did not clear exclusive monitor";
        return false;
    }

    int pipefd[2]{-1, -1};
    if (pipe(pipefd) != 0) {
        detail = "pipe() failed for long-abort child supervisor";
        return false;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        detail = "fork() failed";
        return false;
    }
    if (pid == 0) {
        close(pipefd[0]);
        g_long_abort_pipe_fd = pipefd[1];
        dm_synthetic_long_diag_abort_entry(
            UINT64_C(0x101), UINT64_C(0x202), UINT64_C(0x303),
            UINT64_C(0x404), UINT64_C(0x505), UINT64_C(0x606),
            UINT64_C(0xdeadbeefcafebabe), UINT64_C(0xbadc0ffee0ddf00d));
        _exit(97);
    }

    close(pipefd[1]);
    LongAbortReceipt receipt{};
    const ssize_t nread = read(pipefd[0], &receipt, sizeof(receipt));
    close(pipefd[0]);

    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) != pid) {
        detail = "waitpid() failed";
        return false;
    }
    const bool exited_42 = WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 42;
    const bool receipt_ok =
        nread == static_cast<ssize_t>(sizeof(receipt)) &&
        receipt.magic == UINT64_C(0x444d4c4f4e473432) &&
        receipt.x[0] == UINT64_C(0x101) &&
        receipt.x[1] == UINT64_C(0x202) &&
        receipt.x[2] == UINT64_C(0x303) &&
        receipt.x[3] == UINT64_C(0x404) &&
        receipt.x[4] == UINT64_C(0x505) &&
        receipt.x[5] == UINT64_C(0x606) &&
        receipt.captured_lr != 0 &&
        receipt.captured_sp != 0 &&
        (receipt.captured_sp & 15) == 0;

    if (!exited_42 || !receipt_ok) {
        detail = "long-abort child receipt or exit42 verification failed";
        return false;
    }
    detail = "LDXR/CLREX/STXR controls and child exit42 long-abort capture verified";
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    size_t expected_page_size = 0;
    std::string module_path;
    std::string output_path;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--expected-page-size" && i + 1 < argc) {
            expected_page_size = static_cast<size_t>( strtoull(argv[++i], nullptr, 10));
        } else if (arg == "--module" && i + 1 < argc) {
            module_path = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_path = argv[++i];
        } else if (arg == "--suite" && i + 1 < argc) {
            ++i;
        }
    }

    std::string page_detail, wx_detail, x18_detail, excl_detail;
    // Run isolated fork child probe before any multi-threaded activity.
    const bool excl_ok = run_exclusive_and_long_abort_probe(excl_detail);
    const bool page_ok = run_page_rounding_probe(expected_page_size, page_detail);
    const bool wx_ok = run_wx_loader_probe(wx_detail);
    const bool x18_ok = run_x18_and_dso_probe(module_path, x18_detail);
    const bool all_ok = excl_ok && page_ok && wx_ok && x18_ok;

    std::ostringstream report;
    report << "{\n"
           << "  \"schema\": \"DM_AARCH64_SYNTHETIC_HARNESS_REPORT_V1\",\n"
           << "  \"loader_sha256\": \"" << DM_GUEST_LOADER_SHA256 << "\",\n"
           << "  \"runtime_page_size\": " << sysconf(_SC_PAGESIZE) << ",\n"
           << "  \"status\": \"" << (all_ok ? "PASS" : "FAIL") << "\",\n"
           << "  \"checks\": [\n"
           << "    {\"id\": \"exclusive_and_long_abort\", \"status\": \"" << (excl_ok ? "PASS" : "FAIL") << "\", \"detail\": \"" << excl_detail << "\"},\n"
           << "    {\"id\": \"page_rounding\", \"status\": \"" << (page_ok ? "PASS" : "FAIL") << "\", \"detail\": \"" << page_detail << "\"},\n"
           << "    {\"id\": \"wx_loader\", \"status\": \"" << (wx_ok ? "PASS" : "FAIL") << "\", \"detail\": \"" << wx_detail << "\"},\n"
           << "    {\"id\": \"x18_and_dso\", \"status\": \"" << (x18_ok ? "PASS" : "FAIL") << "\", \"detail\": \"" << x18_detail << "\"}\n"
           << "  ]\n"
           << "}\n";

    const std::string json_str = report.str();
    if (!output_path.empty()) {
        FILE* f = fopen(output_path.c_str(), "wb");
        if (!f || fwrite(json_str.data(), 1, json_str.size(), f) != json_str.size()) {
            if (f) fclose(f);
            return 2;
        }
        fclose(f);
    }
    fwrite(json_str.data(), 1, json_str.size(), stdout);
    return all_ok ? 0 : 1;
}
