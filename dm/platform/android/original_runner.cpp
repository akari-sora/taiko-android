#include "original_runner.h"
#include "original_bringup.h"
#include "taiko_bringup.h"
#include "taiko_resources.h"
#include "guest_bootstrap.h"
#include "kernel_runtime.h"
#include "kernel_thread_adapter.h"
#include "graphics_platform.h"
#include "graphics_surface.h"
#include "oe_platform.h"
#include "app_platform.h"
extern "C" {
#include "../../host/romfs_validate.h"
#include "../../host/hle_hid_core.h"
}
#include <array>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace dm_android {
namespace {
// The existing iOS host gives its main guest 8 MiB (host/main.c). Keep that
// capacity, with GuestStack's guard pages and all checked-stack entry checks.
constexpr size_t main_stack_bytes=8u*1024u*1024u;
#if defined(DM_TARGET_TAIKO) && DM_TARGET_TAIKO
using EntryModulePin=TaikoModulePin;
constexpr bool taiko_target=true;
constexpr const char* game_directory="taiko";
constexpr const char* argument_title="Taiko";
const TaikoBuildPins* entry_build(){return taiko_bringup_build();}
bool entry_graph(const Process& process,std::string* error){return taiko_bringup_graph(process,error);}
#else
using EntryModulePin=OriginalModulePin;
constexpr bool taiko_target=false;
constexpr const char* game_directory="game";
constexpr const char* argument_title="D2R";
const OriginalBuildPins* entry_build(){return original_bringup_build();}
bool entry_graph(const Process& process,std::string* error){return original_bringup_graph(process,error);}
#endif
constexpr const char* capsule_directory="original-first-entry-v1";
bool fail(std::string* error,const std::string& text){if(error)*error=text;return false;}
std::string quote(const std::string& text){
    std::string out="\"";static const char hex[]="0123456789abcdef";
    for(unsigned char c:text){if(c=='"'||c=='\\'){out+='\\';out+=char(c);}
        else if(c<32){out+="\\u00";out+=hex[c>>4];out+=hex[c&15];}else out+=char(c);}
    return out+'"';
}
std::string hex(const std::array<uint8_t,32>& value){
    static const char chars[]="0123456789abcdef";std::string out;
    for(auto b:value){out+=chars[b>>4];out+=chars[b&15];}return out;
}
struct Fd {
    int value=-1;
    Fd()=default;explicit Fd(int fd):value(fd){}
    ~Fd(){if(value>=0)close(value);}
    Fd(const Fd&)=delete;Fd& operator=(const Fd&)=delete;
    Fd(Fd&& other) noexcept:value(other.value){other.value=-1;}
};
Fd directory(int parent,const char* name,bool create,std::string* error){
    if(create && mkdirat(parent,name,0700) && errno!=EEXIST){fail(error,std::string("create private directory ")+name+": "+std::strerror(errno));return {};}
    Fd result(openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
    if(result.value<0)fail(error,std::string("open private directory ")+name+": "+std::strerror(errno));
    return result;
}
class Environment {
public:
    void set(const char* name,const std::string* value){
        const char* old=getenv(name);saved_.push_back({name,old?old:"",old!=nullptr});
        if(value?setenv(name,value->c_str(),1):unsetenv(name))throw std::runtime_error("original environment update failed");
    }
    ~Environment(){for(auto i=saved_.rbegin();i!=saved_.rend();++i)
        if(i->present?setenv(i->name.c_str(),i->value.c_str(),1):unsetenv(i->name.c_str()))std::abort();}
private:
    struct Saved{std::string name,value;bool present;};std::vector<Saved> saved_;
};
class Journal {
public:
    bool open(int parent,std::string* error){
        timespec now{};if(clock_gettime(CLOCK_MONOTONIC,&now))return fail(error,"original journal clock unavailable");
        name="attempt-"+std::to_string(getpid())+'-'+std::to_string(now.tv_sec)+'-'+std::to_string(now.tv_nsec)+".jsonl";
        fd_=std::make_unique<Fd>(openat(parent,name.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600));
        if(fd_->value<0)return fail(error,"cannot create original attempt journal");return true;
    }
    void write(const std::string& line){
        if(!fd_ || fd_->value<0)throw std::runtime_error("original attempt journal is not open");
        const std::string bytes=line+'\n';size_t offset=0;
        while(offset<bytes.size()){
            const ssize_t n=::write(fd_->value,bytes.data()+offset,bytes.size()-offset);
            if(n<0&&errno==EINTR)continue;
            if(n<=0)throw std::runtime_error("original attempt journal write failed");offset+=size_t(n);
        }
        // The next operation may crash in original code. Persist the distinction
        // between an attempted call and one which actually returned.
        if(fsync(fd_->value))throw std::runtime_error("original attempt journal sync failed");
    }
    std::string name;
private:std::unique_ptr<Fd> fd_;
};
bool read_capsule(int parent,const EntryModulePin& pin,std::unique_ptr<ModulePackage>* output,std::string* error){
    if(!pin.name || (std::strcmp(pin.name,"main")&&std::strcmp(pin.name,"sdk")&&std::strcmp(pin.name,"subsdk0")))
        return fail(error,"original module name is not in the fixed allowlist");
    const std::string name=std::string(pin.name)+".dmag";
    Fd fd(openat(parent,name.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW));
    struct stat before{};
    const ModuleLimits limits{};
    if(fd.value<0 || fstat(fd.value,&before) || !S_ISREG(before.st_mode) || before.st_size<0 ||
       uint64_t(before.st_size)!=pin.package_bytes || !pin.package_bytes || pin.package_bytes>limits.package_bytes)
        return fail(error,"original capsule is absent, nonregular, or has the wrong bounded size: "+name);
    std::vector<uint8_t> bytes(size_t(pin.package_bytes));size_t done=0;
    while(done<bytes.size()){
        const ssize_t n=pread(fd.value,bytes.data()+done,bytes.size()-done,off_t(done));
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return fail(error,"original capsule read failed: "+name);done+=size_t(n);
    }
    struct stat after{};
    if(fstat(fd.value,&after) || after.st_size!=before.st_size || after.st_dev!=before.st_dev || after.st_ino!=before.st_ino)
        return fail(error,"original capsule changed during read: "+name);
    // The compiled audit and whole-file digest are independent of these bytes.
    // The same decoder used by existing checked modules grants every admission.
    return decode_package_with_callback_audit(bytes.data(),bytes.size(),pin.package_sha256.data(),
                                              pin.callback_audit,output,error,limits);
}
struct Attempt {
    // Environment outlives every runtime/guest owner, including retained work.
    Environment environment;
    HleRuntime runtime;
    GuestEnvironment guest;
    GuestStack stack{main_stack_bytes};
    BootstrapArguments arguments{{argument_title}};
    BootstrapSession bootstrap;
    BootstrapResult result;
    Journal journal;
    uint64_t owner=0;
    bool resources_ready=false,services_prepared=false,loaded=false,nnmain_attempted=false,nnmain_returned=false;
    std::string last_step;
    static bool registration(DmGuestThreadState&,uint64_t* handle,uint64_t* area,void* opaque,std::string* error){
        auto& self=*static_cast<Attempt*>(opaque);*handle=self.runtime.register_main();*area=0;
        return *handle || fail(error,"original main-thread registration failed");
    }
    static bool attachment(Process& process,DmGuestThreadState& state,void* opaque,std::string* error){
        auto& self=*static_cast<Attempt*>(opaque);
        const auto surface=graphics_surface_snapshot();const auto oe=oe_platform_receipt();
        RuntimeGpuLease graphics;
        if(!entry_graph(process,error))return false;
        if(!self.resources_ready || state.runtime_generation!=process.load_generation() ||
           graphics.runtime()!=&self.runtime || graphics.generation()!=process.load_generation() ||
           dm_hid_configured_mode()!=DM_HID_DIAGNOSTIC_RAW || dm_hid_product_complete() ||
           !surface.available || surface.owner<self.owner || !oe.open || oe.epoch!=self.runtime.oe_epoch() ||
           oe.platform.generation!=surface.owner || !oe.platform.focused || !oe.platform.resumed ||
           !oe.platform.window_available)
            return fail(error,"original platform attachment lost its real resources, runtime, input, focus or surface");
        const auto current_ticket=graphics_surface_ticket();
        if(current_ticket.owner!=surface.owner || current_ticket.epoch!=surface.epoch)
            return fail(error,"original platform attachment changed during admission");
        // A recreated Activity may receive the same in-progress user request.
        // Follow only the real, forward-moving native/OE owner; this grants no
        // module, callback, or stale Surface-ticket authority.
        self.owner=surface.owner;
        // Actual HLE load already bound the graphics backend, raw Npad provider
        // and OE lifecycle channel. Do not install empty full-product consumers.
        return true;
    }
    static void observe(const char* step,bool completed,void* opaque){
        auto& self=*static_cast<Attempt*>(opaque);self.last_step=step;
        if(!std::strcmp(step,"nnMain")){self.nnmain_attempted=true;self.nnmain_returned=completed&&!self.result.main_result.exited;}
        self.journal.write("{\"event\":\"bootstrap\",\"step\":"+quote(step)+
                           ",\"state\":\""+(completed?"RETURNED":"ATTEMPT")+"\"}");
    }
};
// If the real game leaves live threads/FS/GPU resources, shutdown MUST refuse.
// Retain their complete owner rather than destroying memory they still use.
// The diagnostic ownership token also stays retained: a process restart is the
// only recovery until a real cooperative original-game stop is implemented.
Attempt* retained_attempt=nullptr;
}

std::string run_original_entry(const std::string& files,const std::string& locale,uint64_t owner){
    std::string error,status="BLOCKED",journal_path,last_step;bool loaded=false,returned=false,attempted=false,clean=true;
    std::unique_ptr<Attempt> attempt;
    Attempt* state=nullptr;
    try {
        if(retained_attempt){clean=false;status="RETAINED_REQUIRE_PROCESS_RESTART";throw std::runtime_error("original runtime is retained; process restart required");}
        if(files.empty() || files[0]!='/' || files.size()>768 || locale.size()>=64 || !owner)
            throw std::runtime_error("original entry requires an actual Android private directory, locale and Activity owner");
        Fd root(open(files.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
        if(root.value<0)throw std::runtime_error("cannot open Android files directory");
        auto game=directory(root.value,game_directory,true,&error);if(game.value<0)throw std::runtime_error(error);
        auto journals=directory(game.value,"original-attempts",true,&error);if(journals.value<0)throw std::runtime_error(error);
        attempt=std::make_unique<Attempt>();state=attempt.get();attempt->owner=owner;
        if(!attempt->journal.open(journals.value,&error))throw std::runtime_error(error);
        journal_path=std::string(game_directory)+"/original-attempts/"+attempt->journal.name;
        const auto* build=entry_build();
        attempt->journal.write("{\"event\":\"preparation\",\"originalFirstFrame\":\"NOT_OBSERVED\",\"gamePlayable\":false}");
        if(!build)throw std::runtime_error("no complete trusted compiled original capsules; original entry was not called");
        auto content=taiko_target?directory(game.value,"content",false,&error):directory(game.value,"modules",false,&error);
        if(content.value<0)throw std::runtime_error(error);
        auto capsules=directory(content.value,taiko_target?"modules":capsule_directory,false,&error);if(capsules.value<0)throw std::runtime_error(error);
        auto romfs=directory(taiko_target?content.value:game.value,taiko_target?"RomFS":"romfs",false,&error);if(romfs.value<0)throw std::runtime_error(error);
#if defined(DM_TARGET_TAIKO) && DM_TARGET_TAIKO
        if(!verify_taiko_content(content.value,&error))throw std::runtime_error(error);
#else
        auto data=directory(romfs.value,"data",false,&error);if(data.value<0)throw std::runtime_error(error);
#endif
        auto save=directory(game.value,"save",true,&error);if(save.value<0)throw std::runtime_error(error);
        auto temp=directory(game.value,"temp",true,&error);if(temp.value<0)throw std::runtime_error(error);
        const std::string game_path=files+"/"+game_directory,romfs_path=game_path+(taiko_target?"/content/RomFS":"/romfs"),save_path=game_path+"/save",temp_path=game_path+"/temp";
#if !defined(DM_TARGET_TAIKO) || !DM_TARGET_TAIKO
        char resource_error[2048]{};
        if(!dm_romfs_validate((romfs_path+"/data").c_str(),resource_error,sizeof(resource_error)))
            throw std::runtime_error(std::string("required original RomFS bytes unavailable: ")+resource_error);
#endif
        attempt->resources_ready=true;
        attempt->environment.set("DM_ROMFS",&romfs_path);attempt->environment.set("DM_ROMFS_OVERLAY",nullptr);
        attempt->environment.set("DM_SAVE",&save_path);attempt->environment.set("DM_TEMP",&temp_path);
        attempt->environment.set("DM_LANG",&locale);
#if defined(DM_TARGET_TAIKO) && DM_TARGET_TAIKO
        // The admitted input contains Application/Patch only. Do not inherit
        // the D2R host's default claim that its specific add-on is owned.
        const std::string no_addons="0";
        attempt->environment.set("DM_AOC_OWNED",&no_addons);
#endif
        if(!attempt->stack.valid())throw std::runtime_error(attempt->stack.error());
        std::vector<std::unique_ptr<ModulePackage>> packages;
        for(size_t i=0;i<build->module_count;++i){
            const auto& pin=build->modules[i];std::unique_ptr<ModulePackage> package;
            if(!read_capsule(capsules.value,pin,&package,&error))throw std::runtime_error(error);
            attempt->journal.write("{\"event\":\"capsule_verified\",\"name\":"+quote(pin.name)+
                ",\"packageSha256\":"+quote(hex(pin.package_sha256))+",\"sourceSha256\":"+
                quote(hex(build->sources[i].source_sha256))+",\"buildId\":"+quote(hex(build->sources[i].build_id))+"}");
            packages.push_back(std::move(package));
        }
        attempt->services_prepared=true;
        if(!dm_android_app_services_prepare(locale.c_str(),game_path.c_str()))throw std::runtime_error("original app services preparation failed");
        if(!attempt->runtime.load(std::move(packages),false,nullptr,nullptr,&error))throw std::runtime_error(error);
        attempt->loaded=loaded=true;
        // Publication into durable ownership is nonallocating and immediate.
        // Every subsequent throw (including reporting) leaves live state owned.
        retained_attempt=attempt.release();
        state->runtime.configure(state->guest.state);
        // An original fault can occur before a call returns. Persist actual
        // mapping bases so its native PC can be resolved to the pinned module
        // and rewrite site, without dumping executable or resource contents.
        for(const auto& module:state->runtime.process().modules()) {
            std::ostringstream mapping;
            mapping<<"{\"event\":\"module_loaded\",\"name\":"<<quote(module->package->name)
                   <<",\"generation\":"<<state->runtime.process().load_generation()
                   <<",\"base\":"<<reinterpret_cast<uintptr_t>(module->mapping.base)
                   <<",\"mappingBytes\":"<<module->mapping.mapping_size
                   <<",\"originalBytes\":"<<module->package->original_size<<'}';
            state->journal.write(mapping.str());
        }
        const bool authorized=taiko_target?state->bootstrap.authorize_taiko_bringup(state->runtime.process(),&error):
            state->bootstrap.authorize_original_bringup(state->runtime.process(),&error);
        if(!authorized)throw std::runtime_error(error);
        // Check foreground facts before any SDK initialization or main-thread
        // registration, then check again at the real before_main attachment.
        // A backgrounded import can therefore retire cleanly and be retried.
        state->last_step="pre_bootstrap_platform";
        if(!Attempt::attachment(state->runtime.process(),state->guest.state,state,&error))
            throw std::runtime_error(error);
        const BootstrapHooks hooks{Attempt::registration,Attempt::attachment,state,Attempt::observe,state};
        // This exact original SDK retains native WFE in LockBusyMutex. Require
        // the process's periodic event-stream capability before SDK execution;
        // occasional interrupts or a previous microbenchmark do not prove it.
        state->last_step="pre_bootstrap_native_wait";
        if(!native_wait_event_stream_available())
            throw std::runtime_error("original SDK native WFE requires Linux arm64 HWCAP_EVTSTRM");
        const bool ran=state->bootstrap.run(state->runtime.process(),state->guest,state->stack,state->arguments,hooks,&state->result,&error);
        status=ran?(state->result.main_result.exited?"NNMAIN_EXITED":"NNMAIN_RETURNED"):"STOPPED";
        if(!ran && error.empty())error="original bootstrap stopped without a returned success";
    }catch(const std::exception& exception){error=exception.what();}
    if(state){
        attempted=state->nnmain_attempted;returned=state->nnmain_returned;last_step=state->last_step;
        if(!state->loaded && state->services_prepared)dm_android_app_services_reset();
        if(state->loaded){
            // Runtime publication already transferred this owner to retention.
            std::string shutdown_error;
            clean=state->runtime.shutdown(&shutdown_error);
            if(clean){attempt.reset(retained_attempt);retained_attempt=nullptr;}
            else {status="RETAINED_REQUIRE_PROCESS_RESTART";if(!error.empty())error+="; ";error+="shutdown retained: "+shutdown_error;}
        }
        try{state->journal.write("{\"event\":\"result\",\"status\":"+quote(status)+",\"error\":"+quote(error)+
             ",\"cleanupComplete\":"+(clean?"true":"false")+",\"nnMainAttempted\":"+(attempted?"true":"false")+
             ",\"nnMainReturned\":"+(returned?"true":"false")+",\"originalFirstFrame\":\"NOT_OBSERVED\"}");}
        catch(const std::exception& exception){if(!error.empty())error+="; ";error+=exception.what();}
    }
    std::ostringstream report;
    report<<"{\"schemaVersion\":1,\"suite\":\"android-original-entry\",\"status\":"<<quote(status)
          <<",\"modulesLoaded\":"<<(loaded?"true":"false")<<",\"nnMainAttempted\":"<<(attempted?"true":"false")
          <<",\"nnMainReturned\":"<<(returned?"true":"false")<<",\"lastStep\":"<<quote(last_step)
          <<",\"cleanupComplete\":"<<(clean?"true":"false")<<",\"journal\":"<<quote(journal_path)
          <<",\"originalFirstFrame\":\"NOT_OBSERVED\",\"mainMenu\":\"NOT_OBSERVED\",\"gamePlayable\":false"
          <<",\"fullProductInput\":false,\"error\":"<<quote(error)<<'}';return report.str();
}
}
