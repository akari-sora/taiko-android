#include "guest_bootstrap.h"
#include <array>

namespace dm_android {
namespace {
bool fail(std::string* error, const std::string& message) {
    if (error) *error = message;
    return false;
}
bool executable(const Process& process, uintptr_t address) {
    for (const auto& module : process.modules()) {
        const uintptr_t base = reinterpret_cast<uintptr_t>(module->mapping.base);
        if (address < base) continue;
        const size_t offset = address - base;
        for (const auto& segment : module->package->segments) {
            if (!(segment.flags & DM_GUEST_EXEC) || segment.size < 4 || offset < segment.offset ||
                offset - segment.offset > segment.size - 4) continue;
            bool literal = false;
            for (const auto& fixup : module->package->fixups)
                literal |= offset >= fixup.offset && offset - fixup.offset < 8;
            if (!literal) return true;
        }
    }
    return false;
}
bool observe(const BootstrapHooks& hooks,const char* step,bool completed,std::string* error) {
    if(!hooks.observer)return true;
    try {hooks.observer(step,completed,hooks.observer_context);return true;}
    catch(...) {return fail(error,"bootstrap step observer must return normally");}
}
struct InitContext { DmGuestThreadState* state; GuestStack* stack; Process* process; const BootstrapHooks* hooks; };
struct ProductContext {
    Process& process;
    DmGuestThreadState& state;
    const BootstrapHooks& hooks;
    std::string* error;
    bool succeeded = false;
};
uint64_t run_product(uint64_t opaque) {
    auto& context = *reinterpret_cast<ProductContext*>(opaque);
    context.succeeded = context.hooks.before_main(context.process, context.state,
                                                 context.hooks.context, context.error);
    return context.succeeded;
}
bool run_init(uintptr_t address, void* opaque, std::string* error) {
    auto& context = *static_cast<InitContext*>(opaque);
    std::string step="DT_INIT";
    for(const auto& module:context.process->modules())
        if(module->mapping.base && address>=reinterpret_cast<uintptr_t>(module->mapping.base) &&
           address-reinterpret_cast<uintptr_t>(module->mapping.base)<module->mapping.mapping_size) {
            step+=":"+module->package->name;break;
        }
    if(!observe(*context.hooks,step.c_str(),false,error))return false;
    GuestCallResult result;
    if (!context.stack->call(*context.state, address, nullptr, 0, &result, error)) return false;
    if(result.exited)return fail(error,"guest ExitThread during module initialization");
    return observe(*context.hooks,step.c_str(),true,error);
}
}

bool BootstrapSession::authorize(Process& process,std::string* error) {
    if(purpose_!=Purpose::None)return fail(error,"bootstrap purpose is already authorized");
    if(!authority_.bind(process,this,error))return false;
    purpose_=Purpose::Diagnostic;return true;
}
bool BootstrapSession::authorize_original_bringup(Process& process,std::string* error) {
    if(purpose_!=Purpose::None)return fail(error,"bootstrap purpose is already authorized");
    if(!original_authority_.bind(process,this,error))return false;
    purpose_=Purpose::OriginalBringup;return true;
}
bool BootstrapSession::authorize_taiko_bringup(Process& process,std::string* error) {
    if(purpose_!=Purpose::None)return fail(error,"bootstrap purpose is already authorized");
    if(!taiko_authority_.bind(process,this,error))return false;
    purpose_=Purpose::TaikoStock;return true;
}
BootstrapArguments::BootstrapArguments(std::vector<std::string> values) : values_(std::move(values)) {
    if (values_.empty() || values_.size() > 63) {
        error_ = "guest requires one through 63 arguments";
        return;
    }
    for (auto& value : values_) {
        if (value.find('\0') != std::string::npos) {
            error_ = "guest argument contains an embedded NUL";
            pointers_.clear();
            return;
        }
        pointers_.push_back(value.data());
    }
    pointers_.push_back(nullptr);
}

bool BootstrapSession::run(Process& process, GuestEnvironment& environment, GuestStack& stack,
                            const BootstrapArguments& arguments, const BootstrapHooks& hooks,
                            BootstrapResult* result, std::string* error) {
    if (error) error->clear();
    if (!result) return fail(error, "missing bootstrap result");
    *result = {};
    if (started_) return fail(error, "bootstrap session has already started");
    // Capability validation precedes started_, registration and every SDK or
    // module initializer. A refused attempt cannot consume this session.
    const bool taiko=purpose_==Purpose::TaikoStock;
    if(taiko) {
        if(!taiko_authority_.validate(process,this,error))return false;
    } else if(purpose_==Purpose::OriginalBringup) {
        if(!original_authority_.validate(process,this,error))return false;
    } else if (!authority_.validate(process, this, error)) return false;
    if (!arguments.valid()) return fail(error, arguments.error());
    if (!stack.valid()) return fail(error, stack.error());
    if (!hooks.register_main_thread || !hooks.before_main || !environment.state.dispatch)
        return fail(error, "kernel dispatch, main-thread registration and product initialization are required");
    constexpr std::array<const char*, 9> names{
        "_init_libc0", "nnosInitialize", "_init_libc1", "nninitInitializeSdkModule",
        "nninitStartup", "_init_libc2", "_ZN2nn2os11SetHostArgcEi",
        "_ZN2nn2os11SetHostArgvEPPc", "nnMain"};
    std::array<uintptr_t, names.size()> functions{};
    // Validate every required startup entry before any initialization side effect.
    for (size_t i = 0; i < names.size(); ++i) {
        if(taiko) {
            // Host argc/argv setters are not part of this pinned SDK Start.
            // nnosInitialize receives the real registry's argument-area value.
            if(i==6 || i==7)continue;
            const TaikoStartupStep* pinned=nullptr;
            for(const auto& entry:taiko_startup_plan())
                if(entry.kind==TaikoStartupKind::Guest && std::string(entry.name)==names[i])pinned=&entry;
            if(!pinned || pinned->module_index>=process.modules().size() ||
               !process.module_symbol(pinned->module_index,names[i],&functions[i]) ||
               functions[i]!=reinterpret_cast<uintptr_t>(process.modules()[pinned->module_index]->mapping.base)+pinned->offset ||
               !executable(process,functions[i]) || !process.callback_root(functions[i]) ||
               !process.checked_stack_entry(functions[i]))
                return fail(error,std::string("Taiko pinned executable bootstrap entry mismatch: ")+names[i]);
            continue;
        }
        if (!process.symbol(names[i], &functions[i]) || !executable(process, functions[i]))
            return fail(error, std::string("missing executable bootstrap symbol: ") + names[i]);
    }
    started_ = true;
    auto& state = environment.state;
    state.gate_resolver = Process::gate_resolver;
    state.gate_context = &process;
    uint64_t handle = 0, argument_area = 0;
    if(!observe(hooks,"register_main_thread",false,error))return false;
    if (!hooks.register_main_thread(state, &handle, &argument_area, hooks.context, error)) return false;
    if (!handle) return fail(error, "kernel did not register a main thread handle");
    result->completed_steps.emplace_back("register_main_thread");
    if(!observe(hooks,"register_main_thread",true,error))return false;
    auto step = [&](size_t index, const uint64_t* args, size_t count, bool main) {
        if(!observe(hooks,names[index],false,error))return false;
        GuestCallResult called;
        if (!stack.call(state, functions[index], args, count, &called, error)) return false;
        if (called.exited && !main)
            return fail(error, std::string("guest ExitThread during startup: ") + names[index]);
        result->completed_steps.emplace_back(names[index]);
        if (main) result->main_result = called;
        return observe(hooks,names[index],true,error);
    };
    if (!step(0, nullptr, 0, false)) return false;
    const uint64_t os_args[]{handle, argument_area};
    if (!step(1, os_args, 2, false)) return false;
    if(taiko) {
        if(!taiko_authority_.validate(process,this,error))return false;
        if(!observe(hooks,"taiko_host_loader_ready",false,error))return false;
        taiko_host_loader_ready_=true;
        result->completed_steps.emplace_back("taiko_host_loader_ready");
        if(!observe(hooks,"taiko_host_loader_ready",true,error))return false;
    }
    for (size_t i = 2; i < 6; ++i) if (!step(i, nullptr, 0, false)) return false;
    InitContext init_context{&state, &stack, &process, &hooks};
    if(!observe(hooks,"module_initializers",false,error))return false;
    if(taiko && !taiko_host_loader_ready_)return fail(error,"Taiko host loader is not ready");
    if (!process.run_initializers(run_init, &init_context, error,
            taiko?InitializerOrder::Reverse:InitializerOrder::Forward)) return false;
    result->completed_steps.emplace_back("module_initializers");
    if(!observe(hooks,"module_initializers",true,error))return false;
    if(!taiko) {
        const uint64_t argc = arguments.argc();
        if (!step(6, &argc, 1, false)) return false;
        const uint64_t argv = reinterpret_cast<uintptr_t>(arguments.argv());
        if (!step(7, &argv, 1, false)) return false;
    }
    // Product helpers resolve and invoke guest functions directly. They need
    // the same attachment and guest SP as SDK initialization and nnMain.
    ProductContext product{process, state, hooks, error};
    GuestCallResult product_result;
    const char* attachment_step=taiko?"taiko_platform_attachment":
        purpose_==Purpose::OriginalBringup?"original_platform_attachment":"product_initialization";
    if(!observe(hooks,attachment_step,false,error))return false;
    if (!stack.call(state, reinterpret_cast<uintptr_t>(&run_product),
                    reinterpret_cast<uintptr_t>(&product), &product_result, error)) return false;
    if (product_result.exited) return fail(error, "guest ExitThread during product initialization");
    if (!product.succeeded) return false;
    result->completed_steps.emplace_back(attachment_step);
    if(!observe(hooks,attachment_step,true,error))return false;
    if(taiko && (!taiko_host_loader_ready_ || !taiko_authority_.validate(process,this,error)))return false;
    if(!step(8,nullptr,0,true))return false;
    // The verified Start suffix requires rtld C (forward DT_FINI), SDK finalizer
    // and quick exit. Until those exist, a normal nnMain return cannot be
    // misreported as successful complete SDK process teardown.
    if(taiko && !result->main_result.exited)
        return fail(error,"Taiko nnMain returned; pinned loader finalization and SDK teardown are unavailable");
    return true;
}
} // namespace dm_android
