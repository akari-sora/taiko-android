#include "observation_probes.h"
#include "kernel_runtime.h"
#include "kernel_memory_android.h"
#include "guest_memory.h"
#include "guest_parameters.h"
#include "module_sha256.h"
#include "observation_fixtures/generated_observations.h"
#include "module_fixtures/generated_modules.h"
#include "fixtures/fixtures.h"
extern "C" {
#include "../../host/dm_uimsg.h"
uint64_t guest_ns();
void dm_guest_frame_tick();
void guest_clock_freeze_for(int,int);
int dm_detclock_enabled();
int gate_obs_present(int);
void gate_obs_set(int,void (*)(const uint64_t*));
void dm_android_test_guest_frame(void (*)(),DmGuestRegisterFrame*,DmGuestRegisterFrame*);
}
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <sys/mman.h>
#include <unistd.h>

namespace {
using namespace dm_android;
constexpr uint64_t virtual_sentinel=0x123456789abcdef0ull;
constexpr uint64_t mutable_x19=0xfedcba9876543210ull;
constexpr uint32_t mutable_s0=0x3fc00000;
constexpr uint64_t det_step=1234567,det_alignment=uint64_t{1}<<52;
struct Check {const char* id;bool passed=false;std::string detail;};
uintptr_t tp() {uintptr_t n;asm volatile("mrs %0,tpidr_el0":"=r"(n));return n;}
uintptr_t x18() {uintptr_t n;asm volatile("mov %0,x18":"=r"(n));return n;}
std::string hex(const uint8_t* p,size_t bytes) {
    const char* digits="0123456789abcdef";std::string out;
    for(size_t i=0;i<bytes;++i) {out+=digits[p[i]>>4];out+=digits[p[i]&15];}return out;
}
std::string escape(const std::string& text) {
    std::string out;for(unsigned char ch:text) {
        if(ch=='"'||ch=='\\') {out+='\\';out+=static_cast<char>(ch);}
        else if(ch<32) out+=' ';else out+=static_cast<char>(ch);
    }return out;
}
struct SavedEnvironment {
    explicit SavedEnvironment(const char* name):key(name) {
        const char* p=getenv(key);present=p!=nullptr;if(p) value=p;
    }
    ~SavedEnvironment() {if(present) setenv(key,value.c_str(),1);else unsetenv(key);}
    const char* key;bool present;std::string value;
};
bool load(HleRuntime& runtime,std::string* error) {
    std::unique_ptr<ModulePackage> package;
    if(!decode_package(dm_observation_main_bytes,dm_observation_main_size,
                       dm_observation_main_package_sha256,&package,error)) return false;
    std::vector<std::unique_ptr<ModulePackage>> packages;packages.push_back(std::move(package));
    return runtime.load(std::move(packages),false,nullptr,nullptr,error);
}
struct Probe {
    HleRuntime& runtime;
    GuestEnvironment environment;
    GuestStack stack{256*1024};
    uintptr_t plain=0,mid=0,ui=0,nested=0,adjacent=0,interleaved=0,wide=0,ui_parameter=0;
    uint8_t* base=nullptr;
    DmGuestRegisterFrame before{},after{};
    unsigned frame_callbacks=0,mid_callbacks=0,plain_callbacks=0;
    bool frame_valid=true,mid_valid=true,copy_valid=true;
    uint64_t seed[4]{};
    explicit Probe(HleRuntime& owner):runtime(owner) {}
    bool initialize() {
        runtime.configure(environment.state);environment.state.virtual_x18=virtual_sentinel;
        memcpy(seed,environment.state.parameters,sizeof(seed));
        base=static_cast<uint8_t*>(runtime.process().modules()[0]->mapping.base);
        return stack.valid() && environment.state.parameter_valid_mask==15 &&
          runtime.process().symbol("fixture_plain",&plain) && runtime.process().symbol("fixture_mid",&mid) &&
          runtime.process().symbol("fixture_ui",&ui) && runtime.process().symbol("fixture_nested",&nested) &&
          runtime.process().symbol("fixture_param_adjacent",&adjacent) &&
          runtime.process().symbol("fixture_param_interleaved",&interleaved) &&
          runtime.process().symbol("fixture_param_wide",&wide) && runtime.process().symbol("fixture_param_ui",&ui_parameter);
    }
    bool call(uintptr_t entry,uint64_t argument,uint64_t* value,std::string* error) {
        GuestCallResult result;const uintptr_t before_tp=tp(),before_x18=x18();
        const bool ok=stack.call(environment.state,entry,argument,&result,error);
        if(value) *value=result.value;
        return ok && !result.exited && tp()==before_tp && x18()==before_x18;
    }
};
thread_local Probe* current=nullptr;
void count_plain(const uint64_t*) {if(current) ++current->plain_callbacks;}
void frame_callback(DmGuestRegisterFrame* frame) {
    auto& p=*current;++p.frame_callbacks;
    for(unsigned i=0;i<31;++i) p.frame_valid&=frame->x[i]==(i==18?virtual_sentinel:p.before.x[i]);
    p.frame_valid&=frame->guest_sp==p.before.guest_sp && frame->nzcv==p.before.nzcv &&
        frame->fpsr==p.before.fpsr && frame->fpcr==p.before.fpcr && !memcmp(frame->q,p.before.q,sizeof(frame->q));
}
void mutable_callback(DmGuestRegisterFrame* frame) {
    auto& p=*current;++p.mid_callbacks;
    uint64_t chain[2]{};
    p.mid_valid&=frame->x[0]==41 && frame->x[29]==frame->guest_sp &&
        dm_android_guest_copy(frame->x[29],chain,sizeof(chain)) && chain[1]==frame->x[30] && chain[1]!=0;
    // Registration takes effect without a registry lock surviving the callback.
    gate_obs_set(2,count_plain);
    p.mid_valid&=reinterpret_cast<uint64_t (*)()>(p.adjacent)()==p.environment.state.parameters[0] &&
        reinterpret_cast<uint64_t (*)(uint64_t)>(p.nested)(5)==12;
    p.mid_valid&=!p.runtime.shutdown(nullptr);
    frame->x[0]=100;frame->x[19]=mutable_x19;
    memcpy(frame->q[0],&mutable_s0,sizeof(mutable_s0));
    frame->x[18]=virtual_sentinel+1;
    // These metadata fields may not redirect either physical SP or host return.
    frame->guest_sp=0;frame->return_pc=0;
}
uint64_t frame_entry(uint64_t argument) {
    auto& p=*reinterpret_cast<Probe*>(argument);current=&p;
    dm_android_test_guest_frame(reinterpret_cast<void (*)()>(p.plain),&p.before,&p.after);
    return 1;
}
uint64_t mid_entry(uint64_t argument) {
    auto& p=*reinterpret_cast<Probe*>(argument);current=&p;
    return reinterpret_cast<uint64_t (*)(uint64_t,void*)>(p.mid)(41,p.base+0x8100);
}
uint64_t refresh_entry(uint64_t argument) {
    auto& p=*reinterpret_cast<Probe*>(argument);current=&p;
    auto* state=dm_android_current_guest_state();
    state->parameters[0]^=0x1234;
    uint64_t expected[4]{};
    return dm_android_capture_guest_parameters(expected) && dm_android_refresh_guest_parameters() &&
        state->parameter_valid_mask==15 && !memcmp(expected,state->parameters,sizeof(expected));
}
uint64_t copy_entry(uint64_t argument) {
    auto& p=*reinterpret_cast<Probe*>(argument);current=&p;
    uint64_t local=0xaabbccdd88776655ull,out=0;
    bool ok=dm_android_guest_copy(reinterpret_cast<uintptr_t>(&local),&out,sizeof(out)) && out==local;
    auto* state=dm_android_current_guest_state();
    for(const auto& span:state->owned_memory) {
        uint8_t bytes[8]{};
        ok&=dm_android_guest_copy(span.base,bytes,sizeof(bytes)) && !memcmp(bytes,reinterpret_cast<void*>(span.base),sizeof(bytes));
    }
    p.copy_valid&=ok;return ok;
}
uint64_t borrowed_entry(uint64_t) {
    uint64_t local=5,out=0xfeed;
    return !dm_android_guest_copy(reinterpret_cast<uintptr_t>(&local),&out,sizeof(out)) && out==0xfeed;
}
struct Worker {
    explicit Worker(HleRuntime& r,uintptr_t target):runtime(r),entry(target) {}
    HleRuntime& runtime;uintptr_t entry;
    pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
    bool ready=false,release=false,passed=false;
    uint64_t initialized[4]{},marker=0;
    ~Worker() {pthread_cond_destroy(&condition);pthread_mutex_destroy(&mutex);}
};
void* parameter_worker(void* opaque) {
    auto& w=*static_cast<Worker*>(opaque);GuestEnvironment environment;GuestStack stack(128*1024);
    w.runtime.configure(environment.state);memcpy(w.initialized,environment.state.parameters,sizeof(w.initialized));
    GuestCallResult first;std::string error;
    bool ok=stack.call(environment.state,w.entry,uint64_t{0},&first,&error) &&
        first.value==w.initialized[0] && environment.state.parameter_valid_mask==15;
    w.marker=w.initialized[0]^0x3333;environment.state.parameters[0]=w.marker;
    pthread_mutex_lock(&w.mutex);w.ready=true;pthread_cond_broadcast(&w.condition);
    while(!w.release) pthread_cond_wait(&w.condition,&w.mutex);
    pthread_mutex_unlock(&w.mutex);
    GuestCallResult second;
    ok&=stack.call(environment.state,w.entry,uint64_t{0},&second,&error) && second.value==w.marker &&
        environment.state.parameters[0]==w.marker;
    w.passed=ok;return nullptr;
}
bool params(Probe& p,std::string* error) {
    uint64_t value=0;
    bool ok=p.call(p.adjacent,0,&value,error) && value==p.seed[0];
    ok&=p.call(p.interleaved,5,&value,error) && value==8+p.seed[0]+p.seed[1];
    ok&=p.call(p.wide,0,&value,error) && value==static_cast<uint32_t>(p.seed[2]);
    ok&=p.call(p.ui_parameter,0,&value,error) && value==static_cast<uint32_t>(p.seed[3]);
    // Poison high halves independently of real provider capture: the W loads
    // must zero-extend rather than accidentally return their 64-bit slot.
    p.environment.state.parameters[2]|=0xdeadbeef00000000ull;
    ok&=p.call(p.wide,0,&value,error) && value==static_cast<uint32_t>(p.seed[2]);
    memcpy(p.environment.state.parameters,p.seed,sizeof(p.seed));
    Worker worker(p.runtime,p.adjacent);pthread_t thread;
    if(pthread_create(&thread,nullptr,parameter_worker,&worker)) return false;
    pthread_mutex_lock(&worker.mutex);
    while(!worker.ready) pthread_cond_wait(&worker.condition,&worker.mutex);
    pthread_mutex_unlock(&worker.mutex);
    ok&=p.call(reinterpret_cast<uintptr_t>(&refresh_entry),reinterpret_cast<uintptr_t>(&p),&value,error) && value==1;
    pthread_mutex_lock(&worker.mutex);worker.release=true;pthread_cond_broadcast(&worker.condition);pthread_mutex_unlock(&worker.mutex);
    if(pthread_join(thread,nullptr)) std::abort();
    return ok && worker.passed && !memcmp(worker.initialized,p.seed,sizeof(p.seed));
}
bool poisoned_failure(uint64_t address,size_t bytes) {
    std::array<uint8_t,64> out{};out.fill(0xa5);const auto before=out;
    return !dm_android_guest_copy(address,out.data(),bytes) && out==before;
}
bool copy(Probe& p,std::string* error) {
    uint64_t value=0;uint8_t bytes[16]{};
    bool ok=dm_android_guest_copy(reinterpret_cast<uintptr_t>(p.base)+0x4601,bytes,16) &&
        !memcmp(bytes,"FrontEndNavigatio",16);
    ok&=dm_android_guest_copy(reinterpret_cast<uintptr_t>(p.base)+0x8000,bytes,16);
    ok&=poisoned_failure(reinterpret_cast<uintptr_t>(p.base)+0x5000,16) &&
        poisoned_failure(reinterpret_cast<uintptr_t>(p.base)+0x4ff8,16) && poisoned_failure(0,1) &&
        poisoned_failure(UINT64_MAX-3,8) && poisoned_failure(reinterpret_cast<uintptr_t>(p.base),0);
    void* foreign=malloc(64);
    ok&=foreign && poisoned_failure(reinterpret_cast<uintptr_t>(foreign),16);free(foreign);
    ok&=p.call(reinterpret_cast<uintptr_t>(&copy_entry),reinterpret_cast<uintptr_t>(&p),&value,error) && value==1 && p.copy_valid;
    void* borrowed=mmap(nullptr,128*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(borrowed==MAP_FAILED) return false;
    {
        GuestStack stack(borrowed,128*1024);GuestCallResult result;
        ok&=stack.call(p.environment.state,reinterpret_cast<uintptr_t>(&borrowed_entry),uint64_t{0},&result,error) && result.value==1;
    }
    ok&=munmap(borrowed,128*1024)==0;
    uint64_t registers[31]{};registers[1]=2*1024*1024;
    ok&=dm_android_memory_svc(1,registers) && registers[0]==0;
    if(registers[0]!=0) return false;
    const uint64_t heap=registers[1];*reinterpret_cast<uint64_t*>(heap)=0x1234;
    uint64_t actual=0;ok&=dm_android_guest_copy(heap,&actual,8) && actual==0x1234;
    registers[0]=heap;registers[1]=4096;registers[2]=0;
    ok&=dm_android_memory_svc(2,registers) && registers[0]==0;
    ok&=poisoned_failure(heap,8) && poisoned_failure(heap+4096-4,8);
    ok&=dm_android_guest_copy(heap+4096,&actual,8);
    registers[0]=heap;registers[1]=4096;registers[2]=3;
    ok&=dm_android_memory_svc(2,registers) && registers[0]==0;
    registers[1]=0;ok&=dm_android_memory_svc(1,registers) && registers[0]==0;
    return ok;
}
std::atomic<unsigned> message_count{0},retired_count{0};
std::atomic<bool> message_valid{true};
const char* expected_argument="FixturePanel";
void subscriber(const char* category,const char* action,const char* argument) {
    ++message_count;
    message_valid.store(message_valid.load() && !strcmp(category,"FrontEndNavigation") &&
        !strcmp(action,"ToGame") && !strcmp(argument,expected_argument));
}
void retired_subscriber(const char*,const char*,const char*) {++retired_count;}
void message(Probe& p,uint64_t action,uint64_t argument) {
    uint64_t object[3]={dm_uimsg_hash("FrontEndNavigation",18),action,argument};
    memcpy(p.base+0x8000,object,sizeof(object));
}
bool invoke_ui(Probe& p,std::string* error) {
    uint64_t args[2]={17,reinterpret_cast<uintptr_t>(p.base)+0x8000};GuestCallResult result;
    return p.stack.call(p.environment.state,p.ui,args,2,&result,error) && result.value==18;
}
bool ui_clock(Probe& p,std::string* error) {
    message_count.store(0);message_valid.store(true);
    dm_guest_frame_tick();const uint64_t initial=guest_ns();
    bool ok=dm_detclock_enabled();dm_guest_frame_tick();ok&=guest_ns()==initial+det_step;
    const uint64_t before_unknown=guest_ns();
    message(p,0x9999,0);ok&=invoke_ui(p,error) && guest_ns()==before_unknown && before_unknown<det_alignment;
    uimsg_subscribe(subscriber);
    expected_argument="FixturePanel";
    message(p,dm_uimsg_hash("ToGame",6),reinterpret_cast<uintptr_t>(p.base)+0x461b);
    ok&=invoke_ui(p,error) && guest_ns()==det_alignment && message_count.load()==1 && message_valid.load();
    dm_guest_frame_tick();ok&=guest_ns()==det_alignment+det_step;
    guest_clock_freeze_for(1,1);guest_clock_freeze_for(2,1);
    const uint64_t frozen=guest_ns();dm_guest_frame_tick();guest_clock_freeze_for(1,0);
    dm_guest_frame_tick();ok&=guest_ns()==frozen;guest_clock_freeze_for(2,0);
    dm_guest_frame_tick();ok&=guest_ns()==frozen+det_step;
    // A NUL at the last RO byte requires a checked partial ASCII prefix, and
    // malformed pointers retain the original empty-argument behavior.
    expected_argument="";
    message(p,dm_uimsg_hash("ToGame",6),reinterpret_cast<uintptr_t>(p.base)+0x4fff);
    ok&=invoke_ui(p,error) && message_count.load()==2 && message_valid.load();
    message(p,dm_uimsg_hash("ToGame",6),reinterpret_cast<uintptr_t>(p.base)+0x5000);
    ok&=invoke_ui(p,error) && message_count.load()==3 && message_valid.load();
    expected_argument="FixturePanel";
    const uint64_t before_repeat=guest_ns();
    message(p,dm_uimsg_hash("ToGame",6),reinterpret_cast<uintptr_t>(p.base)+0x461b);
    ok&=invoke_ui(p,error) && message_count.load()==4 && message_valid.load() &&
        guest_ns()==before_repeat; // never move backward
    // A message object straddling RO and its alignment hole must not dispatch.
    const unsigned before_malformed=message_count.load();
    uint64_t args[2]={17,reinterpret_cast<uintptr_t>(p.base)+0x4ff8};GuestCallResult result;
    ok&=p.stack.call(p.environment.state,p.ui,args,2,&result,error) && result.value==18 &&
        message_count.load()==before_malformed;
    return ok;
}
struct ReadHold {
    pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t condition=PTHREAD_COND_INITIALIZER;
    bool ready=false,release=false,valid=false;
    ~ReadHold() {pthread_cond_destroy(&condition);pthread_mutex_destroy(&mutex);}
};
void* read_holder(void* pointer) {
    auto& hold=*static_cast<ReadHold*>(pointer);RuntimeReadLease lease;
    pthread_mutex_lock(&hold.mutex);hold.valid=lease.runtime()!=nullptr;hold.ready=true;pthread_cond_broadcast(&hold.condition);
    while(!hold.release) pthread_cond_wait(&hold.condition,&hold.mutex);
    pthread_mutex_unlock(&hold.mutex);return nullptr;
}
bool retire(HleRuntime& runtime,std::string* error) {
    ReadHold hold;pthread_t thread;if(pthread_create(&thread,nullptr,read_holder,&hold)) return false;
    pthread_mutex_lock(&hold.mutex);while(!hold.ready) pthread_cond_wait(&hold.condition,&hold.mutex);pthread_mutex_unlock(&hold.mutex);
    bool ok=hold.valid && !runtime.shutdown(error);
    pthread_mutex_lock(&hold.mutex);hold.release=true;pthread_cond_broadcast(&hold.condition);pthread_mutex_unlock(&hold.mutex);
    if(pthread_join(thread,nullptr)) std::abort();
    return runtime.shutdown(error) && ok;
}
bool authority(std::string* error,unsigned* rejected) {
    std::unique_ptr<ModulePackage> package;
    if(!decode_package(dm_observation_main_bytes,dm_observation_main_size,dm_observation_main_package_sha256,&package,error)) return false;
    DmGuestLoadedImage mapping{};char detail[256];
    bool ok=package->profile && package->profile_class==1 &&
        !dm_android_guest_prepare(package->image,&mapping,detail,sizeof(detail));
    for(size_t offset:{size_t(184),size_t(216),size_t(320),size_t(352),size_t(356),size_t(376)}) {
        std::vector<uint8_t> blob(dm_observation_main_bytes,dm_observation_main_bytes+dm_observation_main_size);
        blob[offset]^=1;uint8_t digest[32];module_sha256(blob.data(),blob.size(),digest);
        std::unique_ptr<ModulePackage> invalid;
        const bool refused=!decode_package(blob.data(),blob.size(),digest,&invalid,error) && !invalid;
        ok&=refused;*rejected+=refused;
    }
    std::unique_ptr<ModulePackage> legacy;
    ok&=decode_package(dm_module_main_bytes,dm_module_main_size,dm_module_main_package_sha256,&legacy,error) &&
        legacy->wire_version==1 && !legacy->profile && legacy->parameters.empty();
    ok&=dm_android_guest_load(dm_fixture_x18_arithmetic,&mapping,detail,sizeof(detail));
    dm_android_guest_unload(&mapping);return ok;
}
}

std::string dm_android_run_observation_probes() {
    std::array<Check,6> checks{{{"observation-frame",false,{}},{"parameter-execution",false,{}},
        {"checked-copy",false,{}},{"ui-clock",false,{}},{"lifetime-reload",false,{}},{"profile-authority",false,{}}}};
    SavedEnvironment clock("DM_DETCLOCK");setenv("DM_DETCLOCK","1234567",1);
    HleRuntime runtime;std::string error;
    bool ready=load(runtime,&error);
    std::string build_id,source_digest,profile_digest;uint64_t provider_values[4]{};
    if(ready) {
        const auto& package=*runtime.process().modules()[0]->package;
        build_id=hex(package.build_id.data(),32);source_digest=hex(package.source_sha256.data(),32);
        profile_digest=hex(package.profile_digest.data(),32);
        Probe p(runtime);ready=p.initialize() && runtime.register_main()!=0;
        memcpy(provider_values,p.seed,sizeof(provider_values));current=&p;
        if(ready) {
            uint64_t value=0;
            bool frame=p.call(p.plain,41,&value,&error) && value==42;
            frame&=runtime.observation_set_frame(2,frame_callback) &&
                p.call(reinterpret_cast<uintptr_t>(&frame_entry),reinterpret_cast<uintptr_t>(&p),&value,&error) && value==1;
            frame&=p.frame_valid && p.frame_callbacks==1 && p.after.x[0]==p.before.x[0]+1;
            for(unsigned i=1;i<31;++i) frame&=p.after.x[i]==p.before.x[i];
            frame&=!memcmp(p.before.q,p.after.q,sizeof(p.before.q)) && p.before.guest_sp==p.after.guest_sp &&
                p.before.nzcv==p.after.nzcv && p.before.fpsr==p.after.fpsr && p.before.fpcr==p.after.fpcr;
            runtime.observation_set_frame(2,nullptr);
            frame&=runtime.observation_set_frame(6,mutable_callback) &&
                p.call(reinterpret_cast<uintptr_t>(&mid_entry),reinterpret_cast<uintptr_t>(&p),&value,&error) && value==101;
            uint64_t stored=0;uint32_t stored_s0=0;memcpy(&stored,p.base+0x8100,8);memcpy(&stored_s0,p.base+0x8108,4);
            frame&=p.mid_callbacks==1 && p.mid_valid && stored==mutable_x19 && stored_s0==mutable_s0 &&
                p.environment.state.virtual_x18==virtual_sentinel+1;
            frame&=p.call(p.plain,41,&value,&error) && value==42 && p.plain_callbacks==1;
            gate_obs_set(2,nullptr);runtime.observation_set_frame(6,nullptr);
            checks[0].passed=frame;
            checks[0].detail="No subscriber 41->42, mutable callback100->101; full 800-byte PRE snapshot and displaced ADD once; mutable x0/x19/s0/virtualx18; original FP chain/SP; nested guest PARAM/+7 calls; reentrant registration and active-callback unload refusal; frameCallbacks="+
                std::to_string(p.frame_callbacks)+", midCallbacks="+std::to_string(p.mid_callbacks)+", frameValid="+
                std::to_string(p.frame_valid)+", midValid="+std::to_string(p.mid_valid)+", storedX19="+std::to_string(stored)+", storedS0="+std::to_string(stored_s0);
            checks[1].passed=params(p,&error);
            checks[1].detail="All four native-provider slots execute through actual adjacent/interleaved/W parameter stubs; intermediate ADD+3 survives; W high-half poison zero-extends; second pthread retains private marker across current-thread provider refresh";
            checks[2].passed=copy(p,&error);
            checks[2].detail="Owned module RO/RW, active guarded stack and TLS/TLR/object copied; holes/boundaries/null/overflow/zero/unowned malloc/nonkernel borrowed stack refused without output changes; kernel READ denial enforced per logical 4 KiB with adjacent readable page";
            checks[3].passed=ui_clock(p,&error);
            checks[3].detail="Actual rewritten OBS1 decodes module message/hash RO names and invokes UI subscriber plus original detclock: first present, step1234567, ToGame forward2^52, overlapping freeze reasons, unknown before alignment/no backward alignment; final-byte NUL and invalid argument pointer; cross-hole24B message refused; subscriberCalls="+std::to_string(message_count.load());
            // A subscriber and observer deliberately left installed must retire
            // before mappings/cache publication for the replacement generation.
            uimsg_subscribe(retired_subscriber);gate_obs_set(2,count_plain);
            const uintptr_t old_base=reinterpret_cast<uintptr_t>(p.base);
            bool lifetime=retire(runtime,&error) && !dm_android_peek_guest_state() && !gate_obs_present(1);
            lifetime&=poisoned_failure(old_base+0x4601,8);
            const unsigned old_messages=message_count.load(),old_retired=retired_count.load(),old_observers=p.plain_callbacks;
            if(load(runtime,&error)) {
                Probe next(runtime);lifetime&=next.initialize();current=&next;
                if(next.plain) lifetime&=next.call(next.plain,41,&value,&error) && value==42 &&
                    next.plain_callbacks==0 && p.plain_callbacks==old_observers;
                dm_guest_frame_tick();const uint64_t before=guest_ns();
                message(next,dm_uimsg_hash("ToGame",6),reinterpret_cast<uintptr_t>(next.base)+0x461b);
                lifetime&=invoke_ui(next,&error) && before<det_alignment && guest_ns()==det_alignment &&
                    message_count.load()==old_messages && retired_count.load()==old_retired;
                lifetime&=runtime.shutdown(&error);
            } else lifetime=false;
            checks[4].passed=lifetime;
            checks[4].detail="Other pthread RuntimeReadLease rejects shutdown, release permits unload; stale old generation copy refused; reload retires observers/subscribers/RO cache; replacement actual OBS1 still reaches freshly subscribed original detclock";
        }
    }
    if(!ready) for(auto& check:checks) check.detail="Setup unavailable: "+error;
    current=nullptr;
    const bool shutdown=runtime.shutdown(&error);
    if(!shutdown) {checks[4].passed=false;checks[4].detail+="; shutdown: "+error;}
    unsigned rejected=0;checks[5].passed=authority(&error,&rejected);
    checks[5].detail="Independent compiled class1 identity; forged full build/source/profile/class/stride rejected="+
        std::to_string(rejected)+"/6; raw OBS mapper refusal, legacy v1 NSO decoder and raw x18 mapper preserved";
    std::ostringstream json;
    json<<"{\"schemaVersion\":6,\"phase\":\"4\",\"syntheticOnly\":true,\"gamePlayable\":false,\"environment\":{\"pageSize\":"
        <<sysconf(_SC_PAGESIZE)<<",\"abi\":\"arm64-v8a\",\"frameBytes\":"<<sizeof(DmGuestRegisterFrame)
        <<",\"copyBackend\":\"owned-mapping-locks\",\"parameterSeed\":[";
    for(unsigned i=0;i<4;++i) {if(i) json<<',';json<<provider_values[i];}
    json<<"]},\"module\":{\"name\":\"main\",\"target\":\"android-arm64\",\"profileClass\":1,\"packageSha256\":\""
        <<hex(dm_observation_main_package_sha256,32)<<"\",\"buildId\":\""<<build_id<<"\",\"sourceSha256\":\""<<source_digest
        <<"\",\"profileDigest\":\""<<profile_digest<<"\"},\"checks\":[";
    for(size_t i=0;i<checks.size();++i) {
        if(i) json<<',';json<<"{\"id\":\""<<checks[i].id<<"\",\"status\":\""<<(checks[i].passed?"PASS":"FAIL")
            <<"\",\"detail\":\""<<escape(checks[i].detail)<<"\"}";
    }
    json<<"],\"gates\":{\"G1\":\"NOT_RUN\",\"G2\":\"NOT_RUN\",\"G3\":\"NOT_RUN\",\"G4\":\"NOT_RUN\",\"G5\":\"NOT_RUN\",\"G6\":\"NOT_RUN\"}}";
    return json.str();
}
