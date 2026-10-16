#include "graphics_surface.h"
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <limits>
#include <mutex>
#include <thread>
#include <utility>

namespace dm_android {
namespace {
constexpr uint64_t max_frame_bytes=64ULL*1024*1024;
constexpr uint32_t max_extent=16384;
bool extent(uint32_t width,uint32_t height,uint32_t stride,uint64_t* bytes) {
    if(!width||!height||width>max_extent||height>max_extent||stride<uint64_t(width)*4)return false;
    *bytes=uint64_t(stride)*(height-1)+uint64_t(width)*4;
    return *bytes<=max_frame_bytes;
}
SurfaceResult refused(const char* error) {SurfaceResult result;result.error=error;return result;}
}
struct SurfacePresenter::State {
    struct Job {SurfaceTicket ticket;SurfaceFrame frame;std::promise<SurfaceResult> completion;};
    mutable std::mutex mutex;
    std::mutex lifecycle;
    std::condition_variable changed;
    std::shared_ptr<SurfaceWindow> window;
    std::unique_ptr<Job> pending;
    std::thread worker;
    uint64_t owner=0,epoch=0,posts=0,accepted=0,failures=0;
    uint64_t tick_serial=0,live_tick_serial=0;
    int64_t last_tick_ns=0;
    uint32_t width=0,height=0;
    bool resumed=false,valid=false,active=false,stopping=false;
    bool advance() {
        valid=false;live_tick_serial=0;changed.notify_all();
        if(epoch==std::numeric_limits<uint64_t>::max())return false;
        ++epoch;return true;
    }
    bool matches(SurfaceTicket ticket) const {
        return ticket.owner&&ticket.owner==owner&&ticket.epoch==epoch&&valid&&resumed&&window;
    }
    SurfaceResult render(Job& job,const std::shared_ptr<SurfaceWindow>& endpoint,uint32_t width_,uint32_t height_) {
        if(endpoint->geometry_rgba8_default_size()!=0)return refused("native window geometry refused");
        SurfaceBuffer buffer;
        if(endpoint->lock(&buffer)!=0)return refused("native window lock failed");
        SurfaceResult result;result.locked=true;
        // Every successful lock has exactly one cleanup post, even if metadata
        // or epoch validation subsequently fails. Public NDK has no cancel API.
        uint64_t target_bytes=0;
        bool copy=buffer.bits&&buffer.format==1&&buffer.width>0&&buffer.height>0&&
            buffer.stride>=buffer.width&&uint32_t(buffer.width)==width_&&uint32_t(buffer.height)==height_&&
            uint64_t(buffer.stride)*4<=UINT32_MAX&&
            extent(width_,height_,uint32_t(buffer.stride)*4,&target_bytes);
        {std::lock_guard<std::mutex> lock(mutex);copy=copy&&matches(job.ticket);}
        const char* reason=nullptr;
        if(copy) {
            const auto& source=job.frame;
            for(uint32_t y=0;y<height_;++y) {
                const uint32_t sy=uint32_t((uint64_t(2)*y+1)*source.height/(uint64_t(2)*height_));
                auto* row=static_cast<uint8_t*>(buffer.bits)+uint64_t(y)*uint32_t(buffer.stride)*4;
                const auto* src=source.rgba8.data()+uint64_t(sy)*source.row_stride_bytes;
                if(width_==source.width)std::memcpy(row,src,uint64_t(width_)*4);
                else for(uint32_t x=0;x<width_;++x) {
                    const uint32_t sx=uint32_t((uint64_t(2)*x+1)*source.width/(uint64_t(2)*width_));
                    std::memcpy(row+uint64_t(x)*4,src+uint64_t(sx)*4,4);
                }
            }
            result.width=width_;result.height=height_;
        } else reason="native window buffer metadata or surface epoch refused";
        result.posted=endpoint->unlock_and_post()==0;
        if(!result.posted)reason="native window post failed";
        {std::lock_guard<std::mutex> lock(mutex);
         result.accepted=copy&&result.posted&&matches(job.ticket);
         if(result.posted)++posts;
         if(!result.accepted&&!reason)reason="surface retired during presentation";}
        if(reason)result.error=reason;
        return result;
    }
    void run() {
        std::unique_lock<std::mutex> lock(mutex);
        for(;;) {
            changed.wait(lock,[&]{return stopping||pending!=nullptr;});
            if(stopping&&!pending)return;
            auto job=std::move(pending);
            if(!matches(job->ticket)||stopping) {
                lock.unlock();job->completion.set_value(refused("surface ticket is no longer live"));lock.lock();continue;
            }
            active=true;auto endpoint=window;const auto w=width,h=height;
            lock.unlock();SurfaceResult result;
            // Window implementations cannot throw across their native C API.
            // Fail closed if an injected/host adapter violates that contract.
            try {result=render(*job,endpoint,w,h);}
            catch(...) {std::terminate();}
            lock.lock();
            if(result.accepted)++accepted;
            else {++failures;if(job->ticket.epoch==epoch)valid=false;}
            active=false;changed.notify_all();
            lock.unlock();job->completion.set_value(std::move(result));lock.lock();
        }
    }
};
SurfacePresenter::SurfacePresenter():state_(new State) {state_->worker=std::thread([this]{state_->run();});}
SurfacePresenter::~SurfacePresenter() {
    auto& s=*state_;
    {std::lock_guard<std::mutex> lifecycle(s.lifecycle);std::unique_lock<std::mutex> lock(s.mutex);
     s.valid=false;s.stopping=true;s.changed.notify_all();s.changed.wait(lock,[&]{return !s.active;});}
    s.worker.join();
}
bool SurfacePresenter::bind(uint64_t owner,std::shared_ptr<SurfaceWindow> window,uint32_t width,uint32_t height,bool resumed) {
    auto& s=*state_;std::lock_guard<std::mutex> lifecycle(s.lifecycle);std::unique_lock<std::mutex> lock(s.mutex);
    if(!owner||owner<s.owner||s.stopping)return false;
    const bool epoch=s.advance();s.changed.wait(lock,[&]{return !s.active;});
    s.owner=owner;s.window=std::move(window);s.width=width;s.height=height;s.resumed=resumed;
    s.valid=epoch&&s.window&&width&&height&&width<=max_extent&&height<=max_extent;
    return true;
}
bool SurfacePresenter::activity(uint64_t owner,bool resumed) {
    auto& s=*state_;std::lock_guard<std::mutex> lifecycle(s.lifecycle);std::unique_lock<std::mutex> lock(s.mutex);
    if(!owner||owner!=s.owner||s.stopping)return false;
    if(s.resumed==resumed)return true;
    const bool was_valid=s.valid;const bool epoch=s.advance();s.changed.wait(lock,[&]{return !s.active;});
    s.resumed=resumed;s.valid=epoch&&was_valid;return true;
}
bool SurfacePresenter::detach(uint64_t owner) {return bind(owner,nullptr,0,0,false);}
SurfaceTicket SurfacePresenter::ticket() const {
    auto& s=*state_;std::lock_guard<std::mutex> lock(s.mutex);
    return s.valid&&s.resumed?SurfaceTicket{s.owner,s.epoch}:SurfaceTicket{};
}
SurfaceSnapshot SurfacePresenter::snapshot() const {
    auto& s=*state_;std::lock_guard<std::mutex> lock(s.mutex);
    return {s.owner,s.epoch,s.posts,s.accepted,s.failures,s.width,s.height,s.valid&&s.resumed,s.active};
}
bool SurfacePresenter::frame_tick(uint64_t owner,int64_t frame_time_ns) {
    auto& s=*state_;std::lock_guard<std::mutex> lock(s.mutex);
    if(!owner||owner!=s.owner||s.stopping||!s.matches({owner,s.epoch})||
       frame_time_ns<=0||frame_time_ns<=s.last_tick_ns||s.tick_serial==UINT64_MAX)return false;
    s.last_tick_ns=frame_time_ns;s.live_tick_serial=++s.tick_serial;s.changed.notify_all();return true;
}
SurfaceCadence SurfacePresenter::cadence() const {
    auto& s=*state_;std::lock_guard<std::mutex> lock(s.mutex);
    if(!s.matches({s.owner,s.epoch})||!s.live_tick_serial)return {};
    return {{s.owner,s.epoch},s.live_tick_serial,s.last_tick_ns};
}
bool SurfacePresenter::wait_cadence(SurfaceTicket ticket,uint64_t after,uint64_t timeout_ns,SurfaceCadence* out) {
    if(!out||timeout_ns>1000000000ULL)return false;
    auto& s=*state_;std::unique_lock<std::mutex> lock(s.mutex);
    s.changed.wait_for(lock,std::chrono::nanoseconds(timeout_ns),[&]{
        return s.stopping||!s.matches(ticket)||s.live_tick_serial>after;
    });
    if(s.stopping||!s.matches(ticket)||!s.live_tick_serial||s.live_tick_serial<=after)return false;
    *out={ticket,s.live_tick_serial,s.last_tick_ns};return true;
}
SurfaceResult SurfacePresenter::present(SurfaceTicket ticket,SurfaceFrame frame) {
    uint64_t bytes=0;
    if(!extent(frame.width,frame.height,frame.row_stride_bytes,&bytes)||frame.rgba8.size()<bytes||frame.rgba8.size()>max_frame_bytes)
        return refused("invalid or oversized linear RGBA8 source");
    auto job=std::make_unique<State::Job>();job->ticket=ticket;job->frame=std::move(frame);
    auto result=job->completion.get_future();auto& s=*state_;
    {std::lock_guard<std::mutex> lock(s.mutex);
     if(s.stopping||!s.matches(ticket))return refused("surface ticket is no longer live");
     if(s.pending||s.active)return refused("surface presenter already owns a frame");
     s.pending=std::move(job);s.changed.notify_all();}
    return result.get();
}
}

#ifdef __ANDROID__
#include "input_activity.h"
#include "kernel_runtime.h"
#include <android/native_window.h>
#include <game-activity/native_app_glue/android_native_app_glue.h>
namespace dm_android {
namespace {
class AndroidWindow final:public SurfaceWindow {
    ANativeWindow* window_;
public:
    explicit AndroidWindow(ANativeWindow* window):window_(window) {ANativeWindow_acquire(window_);}
    ~AndroidWindow() override {ANativeWindow_release(window_);}
    int geometry_rgba8_default_size() override {return ANativeWindow_setBuffersGeometry(window_,0,0,WINDOW_FORMAT_RGBA_8888);}
    int lock(SurfaceBuffer* out) override {
        ANativeWindow_Buffer buffer{};const int rc=ANativeWindow_lock(window_,&buffer,nullptr);
        if(!rc)*out={buffer.width,buffer.height,buffer.stride,buffer.format,buffer.bits};return rc;
    }
    int unlock_and_post() override {return ANativeWindow_unlockAndPost(window_);}
};
SurfacePresenter presenter;
std::mutex activity_mutex;
android_app* activity=nullptr;
uint64_t activity_generation=0;
bool activity_resumed=false,window_available=false;
ANativeWindow* bound_window=nullptr; // identity only; presenter owns its reference
int32_t bound_width=0,bound_height=0;
void bind_window(android_app* app,bool force) {
    ANativeWindow* current=window_available?app->window:nullptr;
    const int32_t w=current?ANativeWindow_getWidth(current):0,h=current?ANativeWindow_getHeight(current):0;
    // CONFIG/CONTENT_RECT can arrive after recreation without changing the
    // native endpoint. Retiring its live ticket then cancels an otherwise valid
    // in-flight frame. INIT/TERM and real endpoint/size changes always retire it.
    if(!force&&current==bound_window&&w==bound_width&&h==bound_height)return;
    if(current) {
        // Acquire only while the callback's Surface is valid. Default-size
        // buffers keep the input Activity's native pixel basis unchanged.
        auto window=std::make_shared<AndroidWindow>(current);
        presenter.bind(activity_generation,std::move(window),w>0?uint32_t(w):0,h>0?uint32_t(h):0,activity_resumed);
    } else presenter.bind(activity_generation,nullptr,0,0,activity_resumed);
    bound_window=current;bound_width=w;bound_height=h;
}
}
void graphics_surface_attach(android_app* app) {
    const auto generation=input_activity_generation(app);std::lock_guard<std::mutex> lock(activity_mutex);
    if(!generation||generation<=activity_generation)return;
    activity=app;activity_generation=generation;activity_resumed=false;window_available=app->window!=nullptr;bind_window(app,true);
}
void graphics_surface_command(android_app* app,int32_t command) {
    std::lock_guard<std::mutex> lock(activity_mutex);if(activity!=app)return;
    switch(command) {
    case APP_CMD_RESUME:activity_resumed=true;presenter.activity(activity_generation,true);break;
    case APP_CMD_PAUSE:case APP_CMD_STOP:activity_resumed=false;presenter.activity(activity_generation,false);break;
    case APP_CMD_INIT_WINDOW:window_available=true;bind_window(app,true);break;
    case APP_CMD_TERM_WINDOW:case APP_CMD_DESTROY:window_available=false;bind_window(app,true);break;
    case APP_CMD_WINDOW_RESIZED:case APP_CMD_CONTENT_RECT_CHANGED:case APP_CMD_CONFIG_CHANGED:
        if(window_available)bind_window(app,false);break;
    default:break;
    }
}
void graphics_surface_detach(android_app* app) {
    std::lock_guard<std::mutex> lock(activity_mutex);if(activity!=app)return;
    presenter.detach(activity_generation);activity=nullptr;activity_resumed=false;window_available=false;
    bound_window=nullptr;bound_width=0;bound_height=0;
}
SurfaceTicket graphics_surface_ticket(){return presenter.ticket();}
SurfaceSnapshot graphics_surface_snapshot(){return presenter.snapshot();}
bool graphics_surface_frame_tick(uint64_t owner,int64_t frame_time_ns){return presenter.frame_tick(owner,frame_time_ns);}
SurfaceCadence graphics_surface_cadence(){return presenter.cadence();}
bool graphics_surface_wait_cadence(SurfaceTicket ticket,uint64_t after,uint64_t timeout_ns,SurfaceCadence* out){
    return presenter.wait_cadence(ticket,after,timeout_ns,out);
}
SurfaceResult graphics_surface_present(SurfaceTicket ticket,uint64_t generation,SurfaceFrame frame) {
    RuntimeGpuLease lease;
    if(!lease.runtime()||lease.generation()!=generation)return refused("presentation runtime generation is no longer live");
    return presenter.present(ticket,std::move(frame));
}
}
#endif
