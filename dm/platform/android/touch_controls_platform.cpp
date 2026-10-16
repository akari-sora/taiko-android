#include "touch_controls_platform.h"
extern "C" {
#include "../../host/dm_input.h"
#include "../../host/hle_hid_core.h"
}
#include <algorithm>
#include <cmath>
#include <time.h>
#ifdef __ANDROID__
#include <game-activity/GameActivityEvents.h>
#include <android/input.h>
#endif

namespace dm_android {
namespace {
bool valid(const TouchViewport& v) {
    return std::isfinite(v.left_px) && std::isfinite(v.top_px) &&
        std::isfinite(v.width_px) && std::isfinite(v.height_px) &&
        std::isfinite(v.density) && v.width_px>0 && v.height_px>0 && v.density>0 &&
        std::isfinite(v.width_px/v.density) && std::isfinite(v.height_px/v.density);
}
bool same(const TouchViewport& a,const TouchViewport& b) {
    return a.left_px==b.left_px && a.top_px==b.top_px && a.width_px==b.width_px &&
        a.height_px==b.height_px && a.density==b.density;
}
const TouchSample* find(const TouchSnapshot& snapshot,int32_t id,uint32_t slot) {
    for(uint32_t i=0;i<snapshot.count && i<kTouchCapacity;++i)
        if(snapshot.points[i].pointer_id==id && snapshot.points[i].slot==slot) return &snapshot.points[i];
    return nullptr;
}
}
bool TouchControlsPlatform::set_viewport(const TouchViewport& viewport) {
    const bool usable=valid(viewport);
    if(!valid_ || !usable || !same(viewport_,viewport)) {
        cancel();
        // These process-global layout settings have the same single frontend
        // owner as the controls. Android coordinates here are density units.
        dm_tc_set_tall_scale(1); dm_tc_set_safe_insets(0,0); dm_tc_set_edge_bottom(0);
        const float width=usable?viewport.width_px/viewport.density:0;
        const float height=usable?viewport.height_px/viewport.density:0;
        if(initialized_) dm_tc_resize(&state_,width,height);
        else { dm_tc_init(&state_,width,height); initialized_=true; }
        dm_tc_enable_targets(&state_,((1u<<DM_TC_COUNT)-1)&~(1u<<DM_TC_PORTAL));
        // No original /players or native-binding consumer is attached yet.
        // Keep their invisible hit regions inactive rather than accepting them.
        state_.layout.diff.r=0;
        for(auto& pick:state_.layout.pick) pick.r=0;
    }
    viewport_=viewport; valid_=usable;
    return usable;
}
void TouchControlsPlatform::set_enabled(bool enabled) {
    enabled=enabled && valid_ && state_.layout.width>=state_.layout.height;
    if(enabled_==enabled) return;
    cancel(); enabled_=enabled;
    if(enabled_) dm_hid_cancel_touch(); // A visible owner starts with no old edges.
}
void TouchControlsPlatform::cancel() {
    dm_tc_cancel_all(&state_);
    pulse_epoch_=pulse_samples_=resume_samples_=0;
    pulse_started_s_=pulse_seen_s_=resume_started_s_=0;
    if(enabled_) dm_hid_cancel_touch();
}
void TouchControlsPlatform::publish() {
    if(enabled_) dm_input_set(state_.buttons,state_.lx,state_.ly,state_.rx,state_.ry);
}
void TouchControlsPlatform::consume(const TouchMotion& event,const TouchSnapshot& before,
                                    const TouchSnapshot& after,double now_s) {
    if(!enabled_ || !valid_ || !std::isfinite(now_s)) return;
    now_s=std::max(now_s,state_.last_time_s);
    if(event.action==TouchAction::Cancel) { cancel(); return; }
    // A new Down retires a lost previous stream without generating its release.
    if(event.action==TouchAction::Down && before.count) cancel();
    for(uint32_t i=0;i<after.count && i<kTouchCapacity;++i) {
        const auto& p=after.points[i];
        if(p.slot>=DM_TC_MAX_TOUCH) continue;
        const auto* previous=find(before,p.pointer_id,p.slot);
        if(!previous || !state_.finger[p.slot].active)
            dm_tc_begin_at(&state_,static_cast<int>(p.slot),p.logical_x,p.logical_y,now_s);
        // Android repeats every active pointer in one MotionEvent. A stationary
        // skill finger must not replace the most recently moved aiming finger.
        else if(previous->logical_x!=p.logical_x || previous->logical_y!=p.logical_y)
            dm_tc_move_at(&state_,static_cast<int>(p.slot),p.logical_x,p.logical_y,now_s);
    }
    for(uint32_t i=0;i<before.count && i<kTouchCapacity;++i) {
        const auto& p=before.points[i];
        if(p.slot>=DM_TC_MAX_TOUCH || find(after,p.pointer_id,p.slot)) continue;
        // The raw provider has already removed this pointer. Its final position
        // still belongs to this exact Up event, including movement after the
        // preceding Move; preserve that position for release-to-cast aiming.
        if(event.canceled) {
            dm_tc_cancel_finger(&state_,static_cast<int>(p.slot));
            // A neutral publication alone retains the HID sampler's short-tap
            // latch. Retire the cancelled edge, then republish all independent
            // held controls and their still-live release pulses below.
            dm_hid_cancel_touch();
        }
        else {
            for(uint32_t k=0;k<event.pointer_count && k<kTouchCapacity;++k) {
                const auto& last=event.pointers[k];
                if(last.pointer_id!=p.pointer_id) continue;
                const float x=std::clamp((last.x_px-viewport_.left_px)/viewport_.density,0.0f,state_.layout.width);
                const float y=std::clamp((last.y_px-viewport_.top_px)/viewport_.density,0.0f,state_.layout.height);
                dm_tc_move_at(&state_,static_cast<int>(p.slot),x,y,now_s);
                break;
            }
            dm_tc_end_at(&state_,static_cast<int>(p.slot),now_s);
        }
    }
    tick(now_s);
}
void TouchControlsPlatform::pulse_tick(double now_s) {
    const uint64_t samples=dm_input_samples();
    if(state_.pulse_button) {
        if(pulse_epoch_!=state_.pulse_epoch) {
            pulse_epoch_=state_.pulse_epoch; pulse_samples_=samples;
            pulse_started_s_=now_s; pulse_seen_s_=0;
        }
        if(samples>pulse_samples_ && !pulse_seen_s_) pulse_seen_s_=now_s;
        const bool taken=pulse_seen_s_ && samples-pulse_samples_>=3 &&
            now_s-pulse_seen_s_>=std::max(.12,state_.pulse_hold_s);
        if(taken || now_s-pulse_started_s_>=2) {
            dm_tc_pulse_end(&state_,pulse_epoch_);
            resume_samples_=samples; resume_started_s_=now_s;
        }
    } else if(dm_tc_pulse_pending(&state_) &&
              (samples-resume_samples_>=2 || now_s-resume_started_s_>=.5)) {
        dm_tc_pulse_resume(&state_);
    }
}
void TouchControlsPlatform::tick(double now_s) {
    if(!enabled_ || !valid_ || !std::isfinite(now_s)) return;
    now_s=std::max(now_s,state_.last_time_s);
    dm_tc_tick(&state_,now_s); pulse_tick(now_s); publish();
}
int TouchControlsPlatform::poll_timeout_ms() const {
    if(!enabled_) return -1;
    if(state_.pulse_button || state_.defer_button || dm_tc_pulse_pending(&state_) ||
       state_.belt_gap_cell || state_.belt_q) return 16;
    for(const auto& finger:state_.finger) if(finger.active) return 16;
    return -1;
}
TouchControlsSnapshot TouchControlsPlatform::snapshot() const { return {viewport_,state_,enabled_}; }

#ifdef __ANDROID__
void TouchControlsPlatform::consume_game_activity(const GameActivityMotionEvent& event,
                                                  const TouchSnapshot& before,const TouchSnapshot& after) {
    TouchMotion motion{};
    switch(event.action & AMOTION_EVENT_ACTION_MASK) {
    case AMOTION_EVENT_ACTION_DOWN: motion.action=TouchAction::Down; break;
    case AMOTION_EVENT_ACTION_POINTER_DOWN: motion.action=TouchAction::PointerDown; break;
    case AMOTION_EVENT_ACTION_MOVE: motion.action=TouchAction::Move; break;
    case AMOTION_EVENT_ACTION_POINTER_UP: motion.action=TouchAction::PointerUp; break;
    case AMOTION_EVENT_ACTION_UP: motion.action=TouchAction::Up; break;
    case AMOTION_EVENT_ACTION_CANCEL: motion.action=TouchAction::Cancel; break;
    default: return;
    }
    motion.pointer_count=event.pointerCount; motion.canceled=(event.flags & 0x20)!=0;
    for(uint32_t i=0;i<motion.pointer_count && i<kTouchCapacity && i<GAMEACTIVITY_MAX_NUM_POINTERS_IN_MOTION_EVENT;++i)
        motion.pointers[i]={event.pointers[i].id,GameActivityPointerAxes_getX(&event.pointers[i]),GameActivityPointerAxes_getY(&event.pointers[i])};
    timespec now{};
    if(clock_gettime(CLOCK_MONOTONIC,&now)==0) consume(motion,before,after,now.tv_sec+now.tv_nsec/1e9);
}
#endif
}

#ifdef __ANDROID__
extern "C" JNIEXPORT jboolean JNICALL
Java_org_d2rmobile_diagnostics_TouchControlOverlay_nativeSetVisible(JNIEnv* env,jclass,jobject activity,jboolean visible) {
    return dm_android::input_activity_touch_controls_visible(env,activity,visible==JNI_TRUE)?JNI_TRUE:JNI_FALSE;
}
extern "C" JNIEXPORT jfloatArray JNICALL
Java_org_d2rmobile_diagnostics_TouchControlOverlay_nativeSnapshot(JNIEnv* env,jclass,jobject activity) {
    dm_android::TouchControlsSnapshot value;
    if(!dm_android::input_activity_touch_controls_snapshot(env,activity,&value)) return nullptr;
    const auto& s=value.state;
    constexpr size_t header=17,record=6,count=DM_TC_COUNT+1;
    jfloat fields[header+record*count]={1,value.enabled?1.0f:0.0f,value.viewport.left_px,value.viewport.top_px,
        value.viewport.density,s.layout.width,s.layout.height,static_cast<float>(s.buttons),
        static_cast<float>(s.lx),static_cast<float>(s.ly),static_cast<float>(s.rx),static_cast<float>(s.ry),
        s.layout.joy_x,s.layout.joy_y,s.layout.joy_radius,s.joy_slot>=0?1.0f:0.0f,static_cast<float>(s.skill_set)};
    for(int i=0;i<static_cast<int>(count);++i) {
        const auto& t=i<DM_TC_COUNT?s.layout.target[i]:s.layout.swap;
        bool pressed=false;
        for(const auto& finger:s.finger)
            pressed|=finger.active && finger.target==(i<DM_TC_COUNT?i:DM_TC_SWAP);
        const size_t at=header+record*i;
        fields[at]=static_cast<float>(i); fields[at+1]=t.x; fields[at+2]=t.y; fields[at+3]=t.r;
        fields[at+4]=i==DM_TC_COUNT || (s.enabled_targets&(1u<<i))?1.0f:0.0f;
        fields[at+5]=pressed?1.0f:0.0f;
    }
    auto result=env->NewFloatArray(sizeof(fields)/sizeof(fields[0]));
    if(result) env->SetFloatArrayRegion(result,0,sizeof(fields)/sizeof(fields[0]),fields);
    return result;
}
#endif
