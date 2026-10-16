#pragma once
#include <stdint.h>
/* Plain guest/host wire ABI. Data-path bytes are checked independently by host. */
typedef struct {
    uint64_t sdk_init,module_init,fallback_calls,setup_calls;
    uint64_t lookup_count,unknown_lookup,callback_calls,callback_bytes;
    uint64_t callback_sp,callback_tls,callback_mode,callback_current;
    uint64_t wait_unfenced,wait_initial,wait_result,queue_error;
    uint64_t pool_address,command_address,recording_handle,repeat_handle;
    uint64_t uniform_address,copy_address,clear_address,roundtrip_address,event_address;
    uint64_t submit_calls,finish_calls,phase,guest_failures;
    uint64_t callback_expected_tls,callback_hle_calls,callback_control_calls,host_fallback_handle;
    uint64_t host_callback_calls,host_callback_bytes,host_update_address;
} DmGraphicsGuestRecord;

/* Separate wire record: the original 36-word baseline remains stable. */
typedef struct {
    uint64_t scenario,window_address,window_size,first_wait,wait_result;
    uint64_t queue_error_first,queue_error_second,submits,guest_waits;
    uint64_t pool_object,texture_object,heap_address,heap_size;
} DmGraphicsExtendedRecord;

typedef struct {
    uint64_t phase,initialized,shaders,submits,wait_result,queue_error;
    uint64_t source_address,source_echo,count_address,count_echo,event_address;
    uint64_t destination[4],echo[4],program[4],serial[4],generation[4];
    uint64_t retained_finalize,retained_replace,rollback,stale_replace,stale_finalize;
    uint64_t stale_submit_error,unknown_count_error,negative_unchanged,programs_finalized;
    uint64_t bad_object,stack_object;
    uint64_t pipeline_rollback;
} DmGraphicsComputeRecord;
