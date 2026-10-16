/* Public SDK-shaped ARM64 guest; every graphics operation uses bootstrap thunks. */
#include "../../../gfx/nvn/nvn_protos.h"
#include "record.h"
#include "shaders/original_records.h"
#include "draw_shaders/draw_records.h"
#include "draw_texture_shaders/draw_records.h"
#include "draw_probe_record.h"
extern PFNNVNGENERICFUNCPTRPROC graphics_bootstrap_import(const char*);
extern int graphics_operation_mode_import(void);
extern uint64_t graphics_heap_allocate(void);
/* Keep both complete sampled records as real observable carrier exports. The
 * host catalog still checks exact current module pointers and full record bytes. */
uint64_t graphics_sampled_record_byte(uint64_t stage,uint64_t offset) {
    if(stage>1||offset>=(stage?sizeof(sampled_draw_shader_fs_record):sizeof(sampled_draw_shader_vs_record)))return UINT64_MAX;
    const volatile uint8_t* record=stage?sampled_draw_shader_fs_record:sampled_draw_shader_vs_record;
    return record[offset];
}
DmGraphicsGuestRecord graphics_result __attribute__((section(".result"),aligned(16)));
DmGraphicsExtendedRecord graphics_extended_result;
DmGraphicsComputeRecord graphics_compute_result;
DmGraphicsDrawRecord graphics_draw_result;
static NVNdevice device;
static NVNqueue queue;
static NVNmemoryPool pool,command_pool;
static NVNcommandBuffer command,host_command;
static NVNtexture texture;
static NVNsync sync,unfenced;
static NVNevent event;
static uint8_t* memory;
static uint8_t commands[1<<17] __attribute__((aligned(4096)));
static uint8_t queue_memory[1<<19] __attribute__((aligned(4096)));
static uint32_t large_values[16384];
static size_t command_offset;
static PFNNVNDEVICEGETPROCADDRESSPROC get_proc;
static NVNprogram compute_program[4],compute_stale;
static NVNmemoryPool compute_echo_pool;
static NVNqueue compute_negative_queue;
/* No initialized native pointers: NSO relocations own all cross-module imports. */
static void* proc(const char* name) { ++graphics_result.lookup_count;void* p=(void*)get_proc(&device,name); if(!p)++graphics_result.guest_failures; return p; }
#define P(name) ((NVNT_##name)proc(#name))
void* memset(void* p,int value,size_t n) {uint8_t* b=p;for(size_t i=0;i<n;++i)b[i]=(uint8_t)value;return p;}
void* memcpy(void* to,const void* from,size_t n) {uint8_t* d=to;const uint8_t* s=from;for(size_t i=0;i<n;++i)d[i]=s[i];return to;}
static uint64_t guest_tls(void) {uint64_t v;__asm__ volatile("mrs %0,tpidrro_el0":"=r"(v));return v;}
static void command_memory(NVNcommandBuffer* c,NVNcommandBufferMemoryEvent kind,size_t minimum,void* data) {
    uint64_t sp;__asm__ volatile("mov %0,sp":"=r"(sp));
    ++graphics_result.callback_calls;graphics_result.callback_sp=sp;
    graphics_result.callback_tls=guest_tls();
    graphics_result.callback_current=(uint64_t)(uintptr_t)data;
    graphics_result.callback_mode=(uint64_t)graphics_operation_mode_import();
    ++graphics_result.callback_hle_calls;
    if(kind!=NVN_COMMAND_BUFFER_MEMORY_EVENT_OUT_OF_COMMAND_MEMORY)return;
    if(c==&host_command) {
        ++graphics_result.host_callback_calls;
        graphics_result.host_callback_bytes+=minimum;
        /* Exercise the original owner allocator through the real guest refill. */
        P(nvnCommandBufferAddCommandMemory)(c,0,0,0);return;
    }
    size_t n=minimum>256?minimum:256;
    if(command_offset+n>sizeof(commands)){++graphics_result.guest_failures;return;}
    P(nvnCommandBufferAddCommandMemory)(c,&command_pool,(ptrdiff_t)command_offset,n);
    command_offset+=n;graphics_result.callback_bytes=command_offset;
}
static void initialize_pool(NVNmemoryPool* p,void* bytes,size_t n) {
    NVNmemoryPoolBuilder b;P(nvnMemoryPoolBuilderSetDefaults)(&b);P(nvnMemoryPoolBuilderSetDevice)(&b,&device);
    P(nvnMemoryPoolBuilderSetStorage)(&b,bytes,n);P(nvnMemoryPoolBuilderSetFlags)(&b,0x24);
    if(!P(nvnMemoryPoolInitialize)(p,&b))++graphics_result.guest_failures;
}
static uint8_t pixel(unsigned x,unsigned y,unsigned channel) {return (uint8_t)(channel==0?x*16+y:channel==1?y*16+x:channel==2?0x55:0xaa);}
uint64_t graphics_begin(void) {
    ++graphics_result.setup_calls;
    get_proc=(PFNNVNDEVICEGETPROCADDRESSPROC)graphics_bootstrap_import("nvnDeviceGetProcAddress");
    if(!get_proc){++graphics_result.guest_failures;return 0xbad;}
    graphics_result.unknown_lookup=get_proc(0,"nvnNoSuchFunction")!=0;
    NVNdeviceBuilder db;P(nvnDeviceBuilderSetDefaults)(&db);P(nvnDeviceBuilderSetFlags)(&db,0);
    if(!P(nvnDeviceInitialize)(&device,&db))++graphics_result.guest_failures;
    memory=(uint8_t*)(uintptr_t)graphics_heap_allocate();
    if(!memory){++graphics_result.guest_failures;return 0xbad;}
    initialize_pool(&pool,memory,1<<18);initialize_pool(&command_pool,commands,sizeof(commands));
    graphics_extended_result.pool_object=(uint64_t)(uintptr_t)&pool;
    graphics_extended_result.texture_object=(uint64_t)(uintptr_t)&texture;
    graphics_extended_result.heap_address=(uint64_t)(uintptr_t)memory;
    graphics_extended_result.heap_size=0x200000;
    graphics_result.pool_address=P(nvnMemoryPoolGetBufferAddress)(&pool);
    graphics_result.command_address=(uint64_t)(uintptr_t)commands;
    graphics_result.uniform_address=(uint64_t)(uintptr_t)(memory+0x4000);
    graphics_result.copy_address=(uint64_t)(uintptr_t)(memory+0x6000);
    graphics_result.clear_address=(uint64_t)(uintptr_t)(memory+0x8000);
    graphics_result.roundtrip_address=(uint64_t)(uintptr_t)(memory+0xa000);
    graphics_result.event_address=(uint64_t)(uintptr_t)(memory+0x2000);
    graphics_result.host_update_address=(uint64_t)(uintptr_t)(memory+0x10000);
    memset(memory+0x4000,0xcc,0x1000);memset(memory+0x6000,0xcd,0x100);
    memset(memory+0x8000,0xce,0x100);memset(memory+0xa000,0xcf,0x100);
    for(unsigned i=0;i<64;++i)memory[0x7000+i]=(uint8_t)(i*3+1);
    for(unsigned y=0;y<3;++y)for(unsigned x=0;x<5;++x)for(unsigned c=0;c<4;++c)memory[0x9000+y*32+x*4+c]=pixel(x,y,c);
    NVNqueueBuilder qb;P(nvnQueueBuilderSetDefaults)(&qb);P(nvnQueueBuilderSetDevice)(&qb,&device);
    size_t qn=P(nvnQueueBuilderGetQueueMemorySize)(&qb);if(qn>sizeof(queue_memory))return 0xbad;
    P(nvnQueueBuilderSetQueueMemory)(&qb,queue_memory,qn);if(!P(nvnQueueInitialize)(&queue,&qb))++graphics_result.guest_failures;
    NVNtextureBuilder tb;P(nvnTextureBuilderSetDefaults)(&tb);P(nvnTextureBuilderSetDevice)(&tb,&device);
    P(nvnTextureBuilderSetTarget)(&tb,NVN_TEXTURE_TARGET_2D);P(nvnTextureBuilderSetWidth)(&tb,5);P(nvnTextureBuilderSetHeight)(&tb,3);
    P(nvnTextureBuilderSetFormat)(&tb,NVN_FORMAT_RGBA8);P(nvnTextureBuilderSetStorage)(&tb,&pool,0);
    if(!P(nvnTextureInitialize)(&texture,&tb))++graphics_result.guest_failures;
    NVNeventBuilder eb;P(nvnEventBuilderSetDefaults)(&eb);P(nvnEventBuilderSetStorage)(&eb,&pool,0x2000);
    if(!P(nvnEventInitialize)(&event,&eb))++graphics_result.guest_failures;
    P(nvnSyncInitialize)(&unfenced,&device);graphics_result.wait_unfenced=P(nvnSyncWait)(&unfenced,0);
    P(nvnSyncInitialize)(&sync,&device);P(nvnCommandBufferInitialize)(&command,&device);
    P(nvnCommandBufferSetMemoryCallback)(&command,command_memory);
    P(nvnCommandBufferSetMemoryCallbackData)(&command,(void*)&graphics_result);
    graphics_result.callback_expected_tls=guest_tls();
    P(nvnCommandBufferBeginRecording)(&command);
    uint32_t values[16];for(unsigned k=0;k<20;++k){for(unsigned i=0;i<16;++i)values[i]=k*100+i;
        P(nvnCommandBufferUpdateUniformBuffer)(&command,graphics_result.uniform_address,0x1000,k*64,64,values);memset(values,0xee,sizeof(values));}
    NVNcommandHandle child=P(nvnCommandBufferEndRecording)(&command);graphics_result.recording_handle=child;
    P(nvnCommandBufferBeginRecording)(&command);
    P(nvnCommandBufferCopyCommands)(&command,1,&child);P(nvnCommandBufferCopyCommands)(&command,1,&child);
    P(nvnCommandBufferCopyBufferToBuffer)(&command,(uint64_t)(uintptr_t)(memory+0x7000),graphics_result.copy_address,64,0);
    P(nvnCommandBufferSignalEvent)(&command,&event,NVN_EVENT_SIGNAL_MODE_WRITE,NVN_EVENT_SIGNAL_LOCATION_BOTTOM,0,7);
    P(nvnCommandBufferSignalEvent)(&command,&event,NVN_EVENT_SIGNAL_MODE_ADD,NVN_EVENT_SIGNAL_LOCATION_BOTTOM,0,5);
    const NVNtexture* colors[]={&texture};P(nvnCommandBufferSetRenderTargets)(&command,1,colors,0,0,0);
    float red[]={1,0,0,1},green[]={0,1,0,1};P(nvnCommandBufferClearColor)(&command,0,red,15);P(nvnCommandBufferClearColor)(&command,0,green,15);
    NVNcopyRegion all={0,0,0,5,3,1};P(nvnCommandBufferSetCopyRowStride)(&command,32);
    P(nvnCommandBufferCopyTextureToBuffer)(&command,&texture,0,&all,graphics_result.clear_address,0);
    P(nvnCommandBufferCopyBufferToTexture)(&command,(uint64_t)(uintptr_t)(memory+0x9000),&texture,0,&all,0);
    NVNcopyRegion sub={1,1,0,3,2,1};P(nvnCommandBufferSetCopyRowStride)(&command,24);
    P(nvnCommandBufferCopyTextureToBuffer)(&command,&texture,0,&sub,graphics_result.roundtrip_address,0);
    P(nvnCommandBufferBarrier)(&command,0);
    NVNcommandHandle main=P(nvnCommandBufferEndRecording)(&command);graphics_result.repeat_handle=main;
    /* Twenty 64 KiB owned inline records cross 1 MiB with only twenty ops.
       Callback grants NULL-pool memory for BEGIN and every later segment refill. */
    P(nvnCommandBufferInitialize)(&host_command,&device);
    P(nvnCommandBufferSetMemoryCallback)(&host_command,command_memory);
    P(nvnCommandBufferSetMemoryCallbackData)(&host_command,(void*)&graphics_result);
    P(nvnCommandBufferBeginRecording)(&host_command);
    for(unsigned i=0;i<16384;++i)large_values[i]=0x51000000u+i;
    for(unsigned i=0;i<20;++i)P(nvnCommandBufferUpdateUniformBuffer)(&host_command,
        graphics_result.host_update_address,sizeof(large_values),0,sizeof(large_values),large_values);
    memset(large_values,0xee,sizeof(large_values));
    graphics_result.host_fallback_handle=P(nvnCommandBufferEndRecording)(&host_command);
    NVNcommandHandle handles[]={main,graphics_result.host_fallback_handle};P(nvnQueueSubmitCommands)(&queue,2,handles);
    ++graphics_result.submit_calls;P(nvnQueueFenceSync)(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);
    graphics_result.wait_initial=P(nvnSyncWait)(&sync,0);graphics_result.wait_result=graphics_result.wait_initial;
    graphics_result.queue_error=P(nvnQueueGetError)(&queue,0);graphics_result.phase=1;return 0x612;
}
uint64_t graphics_wait(uint64_t timeout) {graphics_result.wait_result=P(nvnSyncWait)(&sync,timeout);graphics_result.queue_error=P(nvnQueueGetError)(&queue,0);if(graphics_result.wait_result<2)graphics_result.phase=2;return 0x612;}
uint64_t graphics_poll(void) {return graphics_wait(0);}

/* Each first/next pair crosses exported guest entries. There is deliberately no
 * guest wait between dependent submits except scenario 4's explicit CPU edit. */
static NVNtexture texture_alias;
static NVNevent extended_event;
static void extended_submit(void) {
    NVNcommandHandle handle=P(nvnCommandBufferEndRecording)(&command);
    P(nvnQueueSubmitCommands)(&queue,1,&handle);++graphics_extended_result.submits;
    P(nvnQueueFenceSync)(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);
}
uint64_t graphics_extended_first(uint64_t scenario) {
    DmGraphicsExtendedRecord* r=&graphics_extended_result;
    r->scenario=scenario;r->window_address=(uint64_t)(uintptr_t)(memory+0x20000);r->window_size=0x10000;
    r->submits=0;r->guest_waits=0;r->queue_error_first=0;r->queue_error_second=0;
    uint8_t* w=memory+0x20000;memset(w,0xa1,0x10000);
    for(unsigned i=0;i<64;++i)w[0x100+i]=(uint8_t)(17+i*7);
    if(scenario==3)for(unsigned y=0;y<3;++y)for(unsigned x=0;x<5;++x)
        for(unsigned c=0;c<4;++c)w[0x100+y*32+x*4+c]=(uint8_t)(31+y*47+x*5+c);
    memcpy(&texture_alias,&texture,sizeof(texture_alias));
    NVNeventBuilder eb;P(nvnEventBuilderSetDefaults)(&eb);P(nvnEventBuilderSetStorage)(&eb,&pool,0x20040);
    if(!P(nvnEventInitialize)(&extended_event,&eb))return 0xbad;
    P(nvnCommandBufferBeginRecording)(&command);
    if(scenario==2||scenario>=10) {
        uint32_t values[16];for(unsigned i=0;i<16;++i)values[i]=0x62510000u+i*13;
        P(nvnCommandBufferUpdateUniformBuffer)(&command,(uint64_t)(uintptr_t)(w+0x300),64,0,64,values);
        memset(values,0xee,sizeof(values));
    } else if(scenario==3) {
        NVNcopyRegion all={0,0,0,5,3,1};P(nvnCommandBufferSetCopyRowStride)(&command,32);
        P(nvnCommandBufferCopyBufferToTexture)(&command,(uint64_t)(uintptr_t)(w+0x100),&texture,0,&all,0);
    } else {
        P(nvnCommandBufferCopyBufferToBuffer)(&command,(uint64_t)(uintptr_t)(w+0x100),
            (uint64_t)(uintptr_t)(w+(scenario==5?0x110:0x300)),64,0);
    }
    if(scenario>=10) {
        const NVNtexture* colors[]={&texture};P(nvnCommandBufferSetRenderTargets)(&command,1,colors,0,0,0);
        float red[]={1,0,0,1};P(nvnCommandBufferClearColor)(&command,0,red,15);
        P(nvnCommandBufferSignalEvent)(&command,&extended_event,NVN_EVENT_SIGNAL_MODE_WRITE,NVN_EVENT_SIGNAL_LOCATION_BOTTOM,0,77);
        if(scenario==10)P(nvnCommandBufferDispatchCompute)(&command,1,1,1);
    }
    /* UINT64_MAX means no guest wait/poll has occurred. The host observes the
       first fence pending under the real publication barrier. */
    extended_submit();r->first_wait=UINT64_MAX;r->wait_result=UINT64_MAX;
    r->queue_error_first=P(nvnQueueGetError)(&queue,0);r->queue_error_second=P(nvnQueueGetError)(&queue,0);
    return 0x612;
}
uint64_t graphics_extended_next(uint64_t scenario) {
    DmGraphicsExtendedRecord* r=&graphics_extended_result;uint8_t* w=memory+0x20000;
    if(scenario!=r->scenario||scenario<1||scenario>5)return 0xbad;
    if(scenario==4) {
        for(unsigned i=0;i<64;++i)w[0x100+i]=(uint8_t)(203-i*3);
    }
    P(nvnCommandBufferBeginRecording)(&command);
    if(scenario==3) {
        NVNcopyRegion all={0,0,0,5,3,1};P(nvnCommandBufferSetCopyRowStride)(&command,32);
        P(nvnCommandBufferCopyTextureToBuffer)(&command,&texture_alias,0,&all,(uint64_t)(uintptr_t)(w+0x500),0);
    } else P(nvnCommandBufferCopyBufferToBuffer)(&command,
        (uint64_t)(uintptr_t)(w+(scenario==4?0x100:scenario==5?0x110:0x300)),(uint64_t)(uintptr_t)(w+0x500),64,0);
    extended_submit();return 0x612;
}
uint64_t graphics_extended_wait(uint64_t timeout) {
    DmGraphicsExtendedRecord* r=&graphics_extended_result;
    ++r->guest_waits;r->wait_result=P(nvnSyncWait)(&sync,timeout);
    r->queue_error_first=P(nvnQueueGetError)(&queue,0);r->queue_error_second=P(nvnQueueGetError)(&queue,0);
    graphics_result.wait_result=r->wait_result;
    return 0x612;
}
static uint64_t program_word(const NVNprogram* program,size_t offset){uint64_t value;memcpy(&value,program->reserved+offset,8);return value;}
static NVNshaderData original_shader(unsigned index){NVNshaderData source={(uint64_t)(uintptr_t)(graphics_original_records[index]+20),graphics_original_records[index]+276};return source;}
static void compute_bind(unsigned kernel,const NVNprogram* program) {
    const size_t tails[4]={8,16,24,32};const size_t source_bytes=36*(kernel<2?16:32)+tails[kernel];
    P(nvnCommandBufferBindProgram)(&command,program,NVN_SHADER_STAGE_COMPUTE_BIT);
    P(nvnCommandBufferBindUniformBuffer)(&command,NVN_SHADER_STAGE_COMPUTE,0,(uint64_t)(uintptr_t)(memory+0x30000),65536);
    P(nvnCommandBufferBindStorageBuffer)(&command,NVN_SHADER_STAGE_COMPUTE,0,(uint64_t)(uintptr_t)(memory+0x22100),source_bytes);
    P(nvnCommandBufferBindStorageBuffer)(&command,NVN_SHADER_STAGE_COMPUTE,1,(uint64_t)(uintptr_t)(memory+0x24100+kernel*0x1000),37*8);
}
uint64_t graphics_compute_begin(void) {
    DmGraphicsComputeRecord* r=&graphics_compute_result;
    memset(r,0,sizeof(*r));r->wait_result=UINT64_MAX;
    r->source_address=(uint64_t)(uintptr_t)(memory+0x22000);r->source_echo=(uint64_t)(uintptr_t)(memory+0x40000);
    r->count_address=(uint64_t)(uintptr_t)(memory+0x30000);r->count_echo=(uint64_t)(uintptr_t)(memory+0x41000);r->event_address=(uint64_t)(uintptr_t)(memory+0x21000);
    initialize_pool(&compute_echo_pool,memory+0x40000,0x20000);
    memset(memory+0x22000,0x72,0x1000);memset(memory+0x30000,0x66,65536);*(uint32_t*)(memory+0x30000)=UINT32_MAX;
    memset(memory+0x40000,0x84,0x20000);*(uint32_t*)(memory+0x21000)=0;
    for(unsigned i=0;i<256;++i){uint64_t value=(0xd831a97b1234abcdull+(uint64_t)i*0x789b1234feca0123ull)^((uint64_t)i<<41);memcpy(memory+0x22100+i*8,&value,8);}
    const uint64_t special[]={0,UINT64_MAX,0x100000000ull,0xffffffffull,0x7777777700000001ull,0x7777777700000000ull,UINT64_MAX,0,0x00000001ffffffffull,0x0000000100000000ull,0,UINT64_MAX};
    memcpy(memory+0x22100,special,sizeof(special));
    for(unsigned k=0;k<4;++k) {
        memset(memory+0x24000+k*0x1000,0x73,0x1000);memset(memory+0x24100+k*0x1000,0xaa,512);
        r->destination[k]=(uint64_t)(uintptr_t)(memory+0x24000+k*0x1000);r->echo[k]=(uint64_t)(uintptr_t)(memory+0x28000+k*0x1000);memset(memory+0x28000+k*0x1000,0x84,0x1000);
        r->program[k]=(uint64_t)(uintptr_t)&compute_program[k];
        r->initialized+=P(nvnProgramInitialize)(&compute_program[k],&device)!=0;
        NVNshaderData shader=original_shader(k);r->shaders+=P(nvnProgramSetShaders)(&compute_program[k],1,&shader)!=0;memset(&shader,0,sizeof(shader));
        r->serial[k]=program_word(&compute_program[k],104);r->generation[k]=program_word(&compute_program[k],112);
    }
    NVNeventBuilder eb;P(nvnEventBuilderSetDefaults)(&eb);P(nvnEventBuilderSetStorage)(&eb,&pool,0x21000);P(nvnEventInitialize)(&extended_event,&eb);
    P(nvnCommandBufferBeginRecording)(&command);uint32_t n=37;
    P(nvnCommandBufferUpdateUniformBuffer)(&command,r->count_address,65536,0,4,&n);
    for(unsigned k=0;k<4;++k){compute_bind(k,&compute_program[k]);P(nvnCommandBufferDispatchCompute)(&command,2,1,1);P(nvnCommandBufferCopyBufferToBuffer)(&command,r->destination[k],r->echo[k],0x1000,0);}
    P(nvnCommandBufferCopyBufferToBuffer)(&command,r->source_address,r->source_echo,0x1000,0);
    P(nvnCommandBufferCopyBufferToBuffer)(&command,r->count_address,r->count_echo,65536,0);
    P(nvnCommandBufferSignalEvent)(&command,&extended_event,NVN_EVENT_SIGNAL_MODE_WRITE,NVN_EVENT_SIGNAL_LOCATION_BOTTOM,0,0xc2b);
    NVNcommandHandle handle=P(nvnCommandBufferEndRecording)(&command);P(nvnQueueSubmitCommands)(&queue,1,&handle);++r->submits;
    P(nvnQueueFenceSync)(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);r->queue_error=P(nvnQueueGetError)(&queue,0);r->phase=1;return 0x612;
}
uint64_t graphics_compute_retained(uint64_t unused) {
    (void)unused;DmGraphicsComputeRecord* r=&graphics_compute_result;NVNprogram before=compute_program[0];
    P(nvnProgramFinalize)(&compute_program[0]);r->retained_finalize=1;for(unsigned i=0;i<sizeof(before);++i)r->retained_finalize&=before.reserved[i]==compute_program[0].reserved[i];
    before=compute_program[1];NVNshaderData shader=original_shader(1);r->retained_replace=P(nvnProgramSetShaders)(&compute_program[1],1,&shader)==0;
    for(unsigned i=0;i<sizeof(before);++i)r->retained_replace&=before.reserved[i]==compute_program[1].reserved[i];return 0x612;
}
uint64_t graphics_compute_wait(uint64_t timeout){graphics_compute_result.wait_result=P(nvnSyncWait)(&sync,timeout);graphics_compute_result.queue_error=P(nvnQueueGetError)(&queue,0);return 0x612;}
uint64_t graphics_compute_pipeline_rollback(uint64_t unused) {
    (void)unused;NVNprogram before=compute_program[1];NVNshaderData source=original_shader(1);
    graphics_compute_result.pipeline_rollback=P(nvnProgramSetShaders)(&compute_program[1],1,&source)==0;
    for(unsigned i=0;i<sizeof(before);++i)graphics_compute_result.pipeline_rollback&=before.reserved[i]==compute_program[1].reserved[i];
    P(nvnCommandBufferBeginRecording)(&command);compute_bind(1,&compute_program[1]);P(nvnCommandBufferDispatchCompute)(&command,2,1,1);
    P(nvnCommandBufferCopyBufferToBuffer)(&command,graphics_compute_result.destination[1],graphics_compute_result.echo[1],0x1000,0);
    NVNcommandHandle handle=P(nvnCommandBufferEndRecording)(&command);P(nvnQueueSubmitCommands)(&queue,1,&handle);++graphics_compute_result.submits;
    P(nvnQueueFenceSync)(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);return 0x612;
}
static void negative_submit(void) {
    NVNqueueBuilder qb;P(nvnQueueBuilderSetDefaults)(&qb);P(nvnQueueBuilderSetDevice)(&qb,&device);P(nvnQueueBuilderSetQueueMemory)(&qb,queue_memory,sizeof(queue_memory));P(nvnQueueInitialize)(&compute_negative_queue,&qb);
    NVNcommandHandle handle=P(nvnCommandBufferEndRecording)(&command);P(nvnQueueSubmitCommands)(&compute_negative_queue,1,&handle);
}
uint64_t graphics_compute_negatives(uint64_t unused) {
    (void)unused;DmGraphicsComputeRecord* r=&graphics_compute_result;NVNprogram before=compute_program[1];
    NVNprogram stack_program;uint32_t magic=1;
    r->stack_object=P(nvnProgramInitialize)(&stack_program,&device)!=0;P(nvnProgramFinalize)(&stack_program);memcpy(&magic,&stack_program,4);r->stack_object&=magic==0;
    r->bad_object=P(nvnProgramInitialize)((NVNprogram*)(uintptr_t)1,&device)==0;
    r->bad_object&=P(nvnProgramSetShaders)((NVNprogram*)(uintptr_t)1,0,0)==0;P(nvnProgramFinalize)((NVNprogram*)(uintptr_t)1);
    P(nvnCommandBufferBeginRecording)(&command);P(nvnCommandBufferBindProgram)(&command,(const NVNprogram*)(uintptr_t)1,NVN_SHADER_STAGE_COMPUTE_BIT);(void)P(nvnCommandBufferEndRecording)(&command);
    NVNshaderData bad=original_shader(1);bad.control=(const uint8_t*)bad.control+1;
    r->rollback=P(nvnProgramSetShaders)(&compute_program[1],1,&bad)==0;
    for(unsigned i=0;i<sizeof(before);++i)r->rollback&=before.reserved[i]==compute_program[1].reserved[i];
    r->rollback&=P(nvnProgramSetShaders)(&compute_program[1],1,(const NVNshaderData*)(uintptr_t)1)==0;
    compute_stale=compute_program[0];NVNshaderData next=original_shader(1);
    if(!P(nvnProgramSetShaders)(&compute_program[0],1,&next))r->rollback=0;
    const uint64_t serial=program_word(&compute_program[0],104);
    r->stale_replace=P(nvnProgramSetShaders)(&compute_stale,1,&next)==0;
    P(nvnProgramFinalize)(&compute_stale);r->stale_finalize=program_word(&compute_program[0],104)==serial;
    memset(memory+0x60000,0x91,64); /* outside any registered pool: no effects */
    P(nvnCommandBufferBeginRecording)(&command);P(nvnCommandBufferCopyBufferToBuffer)(&command,r->source_address,r->echo[0],64,0);compute_bind(0,&compute_stale);P(nvnCommandBufferDispatchCompute)(&command,2,1,1);negative_submit();
    r->stale_submit_error=P(nvnQueueGetError)(&compute_negative_queue,0)!=0;P(nvnQueueFinalize)(&compute_negative_queue);
    P(nvnCommandBufferBeginRecording)(&command);P(nvnCommandBufferCopyBufferToBuffer)(&command,r->source_address,r->count_address,4,0);compute_bind(1,&compute_program[1]);P(nvnCommandBufferDispatchCompute)(&command,2,1,1);negative_submit();
    r->unknown_count_error=P(nvnQueueGetError)(&compute_negative_queue,0)!=0;P(nvnQueueFinalize)(&compute_negative_queue);
    return 0x612;
}
uint64_t graphics_compute_end(uint64_t unused) {
    (void)unused;for(unsigned k=0;k<4;++k){uint32_t magic=1;P(nvnProgramFinalize)(&compute_program[k]);memcpy(&magic,&compute_program[k],4);graphics_compute_result.programs_finalized+=magic==0;}
    P(nvnEventFinalize)(&extended_event);P(nvnMemoryPoolFinalize)(&compute_echo_pool);graphics_compute_result.phase=3;return 0x612;
}

/* D1 uses the reviewed authored pair through ordinary guest NVN state. The
 * private arena does not overlap the earlier transfer or compute diagnostics. */
static NVNprogram draw_program;
static NVNtexture draw_texture;
static NVNmemoryPool draw_pool;
static NVNevent draw_event;
static NVNqueue draw_negative_queue;
static NVNshaderData draw_source(unsigned index) {
    NVNshaderData out;
    out.data=(uint64_t)(uintptr_t)(index?draw_shader_fs_record:draw_shader_vs_record);
    out.control=(const void*)(index?draw_shader_fs_record+112:draw_shader_vs_record+144);
    return out;
}
static int draw_same(const void* a,const void* b,size_t n) {
    const uint8_t* x=a;const uint8_t* y=b;for(size_t i=0;i<n;++i)if(x[i]!=y[i])return 0;return 1;
}
static void draw_state(void) {
    DmGraphicsDrawRecord* r=&graphics_draw_result;
    NVNvertexAttribState attr={0};NVNvertexStreamState stream={0};
    NVNcolorState color={0};NVNblendState blend={0};NVNchannelMaskState channels={0};
    NVNpolygonState polygon={0};NVNdepthStencilState depth={0};NVNmultisampleState samples={0};
    P(nvnVertexAttribStateSetDefaults)(&attr);P(nvnVertexAttribStateSetFormat)(&attr,NVN_FORMAT_RGBA32F,0);P(nvnVertexAttribStateSetStreamIndex)(&attr,0);
    P(nvnVertexStreamStateSetDefaults)(&stream);P(nvnVertexStreamStateSetStride)(&stream,16);P(nvnVertexStreamStateSetDivisor)(&stream,0);
    P(nvnColorStateSetDefaults)(&color);P(nvnColorStateSetBlendEnable)(&color,0,0);
    P(nvnBlendStateSetDefaults)(&blend);P(nvnChannelMaskStateSetDefaults)(&channels);
    P(nvnPolygonStateSetDefaults)(&polygon);P(nvnPolygonStateSetCullFace)(&polygon,NVN_FACE_NONE);P(nvnPolygonStateSetPolygonMode)(&polygon,NVN_POLYGON_MODE_FILL);
    P(nvnDepthStencilStateSetDefaults)(&depth);P(nvnDepthStencilStateSetDepthTestEnable)(&depth,0);P(nvnDepthStencilStateSetDepthWriteEnable)(&depth,0);P(nvnDepthStencilStateSetStencilTestEnable)(&depth,0);
    P(nvnMultisampleStateSetDefaults)(&samples);P(nvnMultisampleStateSetSamples)(&samples,1);P(nvnMultisampleStateSetAlphaToCoverageEnable)(&samples,0);P(nvnMultisampleStateSetSampleLocationsEnable)(&samples,0);
    const NVNtexture* targets[]={&draw_texture};float viewport[]={0,0,DM_DRAW_WIDTH,DM_DRAW_HEIGHT};
    NVNbufferRange vertex={r->vertex_address,48};
    P(nvnCommandBufferSetRenderTargets)(&command,1,targets,0,0,0);
    P(nvnCommandBufferBindProgram)(&command,&draw_program,NVN_SHADER_STAGE_VERTEX_BIT|NVN_SHADER_STAGE_FRAGMENT_BIT);
    P(nvnCommandBufferBindUniformBuffer)(&command,NVN_SHADER_STAGE_FRAGMENT,1,r->uniform_address,65536);
    P(nvnCommandBufferBindVertexAttribState)(&command,1,&attr);P(nvnCommandBufferBindVertexStreamState)(&command,1,&stream);
    P(nvnCommandBufferBindVertexBuffers)(&command,0,1,&vertex);
    P(nvnCommandBufferBindColorState)(&command,&color);P(nvnCommandBufferBindBlendState)(&command,&blend);P(nvnCommandBufferBindChannelMaskState)(&command,&channels);
    P(nvnCommandBufferBindPolygonState)(&command,&polygon);P(nvnCommandBufferBindDepthStencilState)(&command,&depth);P(nvnCommandBufferBindMultisampleState)(&command,&samples);
    P(nvnCommandBufferSetViewports)(&command,0,1,viewport);P(nvnCommandBufferSetScissor)(&command,0,0,DM_DRAW_WIDTH,DM_DRAW_HEIGHT);P(nvnCommandBufferSetDepthRange)(&command,0,1);
}
static void draw_readback(unsigned index) {
    NVNcopyRegion all={0,0,0,DM_DRAW_WIDTH,DM_DRAW_HEIGHT,1};
    P(nvnCommandBufferSetCopyRowStride)(&command,DM_DRAW_ROW_STRIDE);
    P(nvnCommandBufferCopyTextureToBuffer)(&command,&draw_texture,0,&all,graphics_draw_result.readback_window[index]+DM_DRAW_PIXEL_OFFSET,0);
    P(nvnCommandBufferCopyBufferToBuffer)(&command,graphics_draw_result.readback_window[index],graphics_draw_result.readback_echo[index],DM_DRAW_WINDOW_BYTES,0);
}
static void draw_submit(void) {
    NVNcommandHandle handle=P(nvnCommandBufferEndRecording)(&command);
    P(nvnQueueSubmitCommands)(&queue,1,&handle);++graphics_draw_result.submits;
    P(nvnQueueFenceSync)(&queue,&sync,NVN_SYNC_CONDITION_ALL_GPU_COMMANDS_COMPLETE,0);
    graphics_draw_result.queue_error=P(nvnQueueGetError)(&queue,0);
}
uint64_t graphics_draw_begin(void) {
    DmGraphicsDrawRecord* r=&graphics_draw_result;memset(r,0,sizeof(*r));r->wait_result=UINT64_MAX;
    uint8_t* base=memory+0x80000;memset(base,0x5e,DM_DRAW_POOL_BYTES);initialize_pool(&draw_pool,base,DM_DRAW_POOL_BYTES);
    r->pool_address=(uint64_t)(uintptr_t)base;r->pool_object=(uint64_t)(uintptr_t)&draw_pool;r->texture_object=(uint64_t)(uintptr_t)&draw_texture;
    r->program=(uint64_t)(uintptr_t)&draw_program;r->vertex_guard=r->pool_address+0x4000;r->vertex_address=r->vertex_guard+0x100;
    r->index_guard=r->pool_address+DM_DRAW_POOL_BYTES-0x100;r->index_address=r->pool_address+DM_DRAW_POOL_BYTES-6;
    r->uniform_address=r->pool_address+0x10000;r->event_address=r->pool_address+0x6000;r->negative_address=r->pool_address+0x50000;
    const uint32_t offsets[]={0x30000,0x38000,0x40000,0x48000};
    for(unsigned i=0;i<4;++i){r->readback_window[i]=r->pool_address+offsets[i];memset(base+offsets[i],0xa9+(int)i,DM_DRAW_WINDOW_BYTES);}
    for(unsigned i=0;i<4;++i){r->readback_echo[i]=r->pool_address+0x60000+i*0x8000;memset(base+0x60000+i*0x8000,0xb9+(int)i,DM_DRAW_WINDOW_BYTES);}
    memset(base+0x4000,0x72,0x1000);memset(base+DM_DRAW_POOL_BYTES-0x100,0x73,0x100);memset(base+0x10000,0x6d,65536);memset(base+0x50000,0xa7,0x1000);
    const float vertices[]={-.75f,-.75f,.5f,1,-.75f,.75f,.5f,1,.75f,.75f,.5f,1};memcpy(base+0x4100,vertices,sizeof(vertices));
    const uint16_t indices[]={2,0,1};memcpy(base+DM_DRAW_POOL_BYTES-6,indices,sizeof(indices));*(uint32_t*)(base+0x6000)=0;
    NVNtextureBuilder tb;P(nvnTextureBuilderSetDefaults)(&tb);P(nvnTextureBuilderSetDevice)(&tb,&device);
    P(nvnTextureBuilderSetFlags)(&tb,NVN_TEXTURE_FLAGS_LINEAR);P(nvnTextureBuilderSetTarget)(&tb,NVN_TEXTURE_TARGET_2D);
    P(nvnTextureBuilderSetWidth)(&tb,DM_DRAW_WIDTH);P(nvnTextureBuilderSetHeight)(&tb,DM_DRAW_HEIGHT);P(nvnTextureBuilderSetDepth)(&tb,1);
    P(nvnTextureBuilderSetLevels)(&tb,1);P(nvnTextureBuilderSetSamples)(&tb,1);P(nvnTextureBuilderSetFormat)(&tb,NVN_FORMAT_RGBA8);P(nvnTextureBuilderSetStride)(&tb,DM_DRAW_WIDTH*4);P(nvnTextureBuilderSetStorage)(&tb,&draw_pool,0);
    r->initialized=P(nvnTextureInitialize)(&draw_texture,&tb)!=0;r->initialized+=P(nvnProgramInitialize)(&draw_program,&device)!=0;
    NVNshaderData source[]={draw_source(0),draw_source(1)};r->shaders=P(nvnProgramSetShaders)(&draw_program,2,source)!=0;memset(source,0,sizeof(source));
    r->serial=program_word(&draw_program,104);r->generation=program_word(&draw_program,112);
    NVNeventBuilder eb;P(nvnEventBuilderSetDefaults)(&eb);P(nvnEventBuilderSetStorage)(&eb,&draw_pool,0x6000);r->initialized+=P(nvnEventInitialize)(&draw_event,&eb)!=0;
    P(nvnCommandBufferBeginRecording)(&command);draw_state();float red[]={1,0,0,1},green[]={0,1,0,1};
    P(nvnCommandBufferUpdateUniformBuffer)(&command,r->uniform_address,65536,0,sizeof(green),green);P(nvnCommandBufferClearColor)(&command,0,red,15);
    P(nvnCommandBufferDrawArrays)(&command,NVN_DRAW_PRIMITIVE_TRIANGLES,0,3);draw_readback(0);
    P(nvnCommandBufferSignalEvent)(&command,&draw_event,NVN_EVENT_SIGNAL_MODE_WRITE,NVN_EVENT_SIGNAL_LOCATION_BOTTOM,0,0xd11);draw_submit();r->phase=1;return 0x612;
}
uint64_t graphics_draw_wait(uint64_t timeout) {
    graphics_draw_result.wait_result=P(nvnSyncWait)(&sync,timeout);graphics_draw_result.queue_error=P(nvnQueueGetError)(&queue,0);
    graphics_result.wait_result=graphics_draw_result.wait_result;return 0x612;
}
uint64_t graphics_draw_retained(uint64_t unused) {
    (void)unused;DmGraphicsDrawRecord* r=&graphics_draw_result;NVNprogram before=draw_program;
    P(nvnProgramFinalize)(&draw_program);r->retained_finalize=draw_same(&before,&draw_program,sizeof(before));
    NVNshaderData source[]={draw_source(0),draw_source(1)};r->retained_replace=P(nvnProgramSetShaders)(&draw_program,2,source)==0&&draw_same(&before,&draw_program,sizeof(before));
    NVNtexture texture_before=draw_texture;P(nvnTextureFinalize)(&draw_texture);r->retained_texture=draw_same(&texture_before,&draw_texture,sizeof(texture_before));
    NVNmemoryPool pool_before=draw_pool;P(nvnMemoryPoolFinalize)(&draw_pool);r->retained_pool=draw_same(&pool_before,&draw_pool,sizeof(pool_before));return 0x612;
}
uint64_t graphics_draw_indexed(uint64_t unused) {
    (void)unused;DmGraphicsDrawRecord* r=&graphics_draw_result;float red[]={1,0,0,1},blue[]={0,0,1,1};
    P(nvnCommandBufferBeginRecording)(&command);draw_state();P(nvnCommandBufferUpdateUniformBuffer)(&command,r->uniform_address,65536,0,sizeof(blue),blue);P(nvnCommandBufferClearColor)(&command,0,red,15);
    P(nvnCommandBufferDrawElementsInstanced)(&command,NVN_DRAW_PRIMITIVE_TRIANGLES,NVN_INDEX_TYPE_UNSIGNED_SHORT,3,r->index_address,0,0,1);draw_readback(1);
    P(nvnCommandBufferSignalEvent)(&command,&draw_event,NVN_EVENT_SIGNAL_MODE_WRITE,NVN_EVENT_SIGNAL_LOCATION_BOTTOM,0,0xd12);draw_submit();return 0x612;
}
uint64_t graphics_draw_pipeline_rollback(uint64_t unused) {
    (void)unused;DmGraphicsDrawRecord* r=&graphics_draw_result;NVNprogram before=draw_program;NVNshaderData source[]={draw_source(0),draw_source(1)};
    r->pipeline_rollback=P(nvnProgramSetShaders)(&draw_program,2,source)==0&&draw_same(&before,&draw_program,sizeof(before));
    P(nvnCommandBufferBeginRecording)(&command);draw_state();float red[]={1,0,0,1};P(nvnCommandBufferClearColor)(&command,0,red,15);
    P(nvnCommandBufferDrawArrays)(&command,NVN_DRAW_PRIMITIVE_TRIANGLES,0,3);draw_readback(2);draw_submit();return 0x612;
}
uint64_t graphics_draw_late_invalid(uint64_t unused) {
    (void)unused;DmGraphicsDrawRecord* r=&graphics_draw_result;float black[]={0,0,0,1},yellow[]={1,1,0,1};uint32_t literal=0xfeedbeef;
    P(nvnCommandBufferBeginRecording)(&command);draw_state();P(nvnCommandBufferUpdateUniformBuffer)(&command,r->uniform_address,65536,0,sizeof(yellow),yellow);
    P(nvnCommandBufferUpdateUniformBuffer)(&command,r->negative_address,0x1000,0,4,&literal);P(nvnCommandBufferClearColor)(&command,0,black,15);
    P(nvnCommandBufferSignalEvent)(&command,&draw_event,NVN_EVENT_SIGNAL_MODE_WRITE,NVN_EVENT_SIGNAL_LOCATION_BOTTOM,0,0xbad);
    /* Index data ends exactly at the unique pool boundary: count4 needs8bytes,
       while only6bytes remain. Prefix literals/clear/event must have no effects. */
    P(nvnCommandBufferDrawElementsInstanced)(&command,NVN_DRAW_PRIMITIVE_TRIANGLES,NVN_INDEX_TYPE_UNSIGNED_SHORT,4,r->index_address,0,0,1);
    NVNqueueBuilder qb;P(nvnQueueBuilderSetDefaults)(&qb);P(nvnQueueBuilderSetDevice)(&qb,&device);P(nvnQueueBuilderSetQueueMemory)(&qb,queue_memory,sizeof(queue_memory));P(nvnQueueInitialize)(&draw_negative_queue,&qb);
    NVNcommandHandle handle=P(nvnCommandBufferEndRecording)(&command);P(nvnQueueSubmitCommands)(&draw_negative_queue,1,&handle);
    r->late_invalid_error=P(nvnQueueGetError)(&draw_negative_queue,0)!=0;P(nvnQueueFinalize)(&draw_negative_queue);
    return 0x612;
}
uint64_t graphics_draw_after_invalid(uint64_t unused) {
    (void)unused;P(nvnCommandBufferBeginRecording)(&command);draw_readback(3);draw_submit();return 0x612;
}
uint64_t graphics_draw_end(uint64_t unused) {
    (void)unused;uint32_t magic=1;P(nvnProgramFinalize)(&draw_program);memcpy(&magic,&draw_program,4);graphics_draw_result.programs_finalized=magic==0;
    P(nvnTextureFinalize)(&draw_texture);P(nvnEventFinalize)(&draw_event);P(nvnMemoryPoolFinalize)(&draw_pool);graphics_draw_result.phase=3;return 0x612;
}
uint64_t graphics_end(void) {
    if(graphics_result.phase!=2&&graphics_result.wait_result!=3)return 0xbad;
    P(nvnEventFinalize)(&event);P(nvnSyncFinalize)(&sync);P(nvnSyncFinalize)(&unfenced);
    if(graphics_extended_result.scenario)P(nvnEventFinalize)(&extended_event);
    P(nvnCommandBufferFinalize)(&command);P(nvnCommandBufferFinalize)(&host_command);
    P(nvnTextureFinalize)(&texture);P(nvnQueueFinalize)(&queue);
    P(nvnMemoryPoolFinalize)(&command_pool);P(nvnMemoryPoolFinalize)(&pool);P(nvnDeviceFinalize)(&device);
    graphics_result.phase=3;return 0x612;
}
void fixture_init(void){++graphics_result.module_init;}
void _init_libc0(void){++graphics_result.sdk_init;}
void nnosInitialize(void){}void _init_libc1(void){}void nninitInitializeSdkModule(void){}
void nninitStartup(void){}void _init_libc2(void){}
void _ZN2nn2os11SetHostArgcEi(int a){(void)a;}void _ZN2nn2os11SetHostArgvEPPc(char** a){(void)a;}
uint64_t nnMain(void){return graphics_begin();}
PFNNVNGENERICFUNCPTRPROC nvnBootstrapLoader(const char* n){(void)n;++graphics_result.fallback_calls;return 0;}
int _ZN2nn2oe16GetOperationModeEv(void){++graphics_result.fallback_calls;return -1;}
