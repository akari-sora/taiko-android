#include "diag_abort_runtime.h"
#include "kernel_runtime.h"
#include <cstdio>
#include <cstring>
#include <unistd.h>

namespace {
// An ordinary private registration makes the canonical entry visible to the
// existing callable registry. It never forces the public SDK AbortImpl symbol.
struct Registration {const char* name;void (*entry)(uint64_t,uint64_t,uint64_t,uint64_t);};
__attribute__((used,aligned(8),section("swhle")))
const Registration diag_abort_registration{DM_DIAG_ABORT_RESOLVER_V1,dm_android_diag_abort_entry};

[[noreturn]] void fatal(const char* text) noexcept {
    // The process cannot safely resume from original AbortImpl. Match the
    // platform fatal exit status without dereferencing a guest Break payload,
    // executing a notification branch, or pretending resources retired.
    const size_t size=std::strlen(text);
    (void)::write(STDERR_FILENO,text,size);
    _exit(42);
}
bool text(const dm_android::Process& process,uint64_t address,char (&out)[192]) {
    if(!address)return false;
    for(size_t i=0;i<sizeof(out);++i) {
        if(address>UINT64_MAX-i || !process.copy_readable(address+i,&out[i],1))return false;
        if(!out[i])return true;
        // Diagnostic input is data, never a format string or terminal command.
        const auto c=static_cast<unsigned char>(out[i]);
        if(c<32 || c>=127)out[i]='?';
    }
    return false; // A missing bounded terminator is invalid, not a safe prefix.
}
}

extern "C" [[noreturn]] void dm_android_diag_abort_from_guest(
    uint64_t arg0,uint64_t arg1,uint64_t arg2,uint64_t line,
    uint64_t guest_lr,uintptr_t guest_sp) noexcept {
    try {
        dm_android::RuntimeReadLease lease;
        auto* runtime=lease.runtime();dm_android::DiagAbortCaller caller;
        if(!runtime || !runtime->diag_abort_origin(guest_lr,guest_sp,&caller))
            fatal("Android original AbortImpl refused: missing current owned import origin\n");
        char text0[192]{},text1[192]{},text2[192]{};
        if(!text(runtime->process(),arg0,text0) ||
           !text(runtime->process(),arg1,text1) || !text(runtime->process(),arg2,text2))
            fatal("Android original AbortImpl refused: invalid bounded diagnostic text\n");
        char message[768]{};
        const int bytes=std::snprintf(message,sizeof(message),
            "Android original AbortImpl: module=%.48s callsite=0x%llx arg0=%s arg1=%s arg2=%s line=%d; fatal exit 42\n",
            caller.module?caller.module:"<missing>",static_cast<unsigned long long>(caller.callsite),
            text0,text1,text2,static_cast<int32_t>(line));
        if(bytes<0 || static_cast<size_t>(bytes)>=sizeof(message))
            fatal("Android original AbortImpl refused: bounded diagnostic formatting failed\n");
        fatal(message);
    } catch(...) {
        fatal("Android original AbortImpl refused: host diagnostic failure\n");
    }
}
