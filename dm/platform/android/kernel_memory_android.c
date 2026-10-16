/* Horizon's 4 KiB logical pages are tracked separately from Android host pages.
 * Host permissions are the union of live logical pages sharing that host page;
 * QueryMemory and all HLE accesses enforce the narrower logical permissions. */
#include "kernel_memory_android.h"
#include "kernel_platform.h"
#include "../../host/dm.h"
#include <sys/mman.h>
#include <unistd.h>
#include <limits.h>

#define RESERVE (5ull << 30)
#define APP_POOL 0xcd500000ull
#define PAGE 0x1000ull
#define PAGE_COUNT (RESERVE / PAGE)
#define MAX_MAP 4096
#define INVALID_SIZE 0xca01u
#define INVALID_ADDRESS 0xcc01u
#define INVALID_STATE 0xd401u
#define INVALID_PERMISSION 0xd801u
#define OUT_OF_RESOURCE 0x10801u /* KernelError_OutOfResource = 132. */
#define OUT_OF_MEMORY 0xd001u
#define STATE_IN_USE 0xfa01u /* KernelError_InvalidState = 125. */
#define NOT_IMPLEMENTED 0x4201u /* KernelError_NotImplemented = 33. */

typedef struct { uint8_t state, perm, attr, owned; } Page;
typedef struct { uint64_t dst, src, size; unsigned pins; uint8_t physical; } Mapping;
static uint8_t* g_as;
static Page* g_pages;
static uint64_t g_heap_cur;
static size_t g_host_page;
static Mapping g_maps[MAX_MAP];
static unsigned g_nmap;
typedef struct { uint64_t token, address; size_t size; unsigned permissions; } GpuPin;
static GpuPin g_gpu[MAX_MAP];
static uint64_t g_gpu_next;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

static uint64_t as_base(void) { return (uint64_t)(uintptr_t)g_as; }
static uint64_t heap_base(void) { return as_base() + 0x40000000ull; }
static size_t page_index(uint64_t a);
static int span(uint64_t a, uint64_t n, uint64_t b, uint64_t length) {
    return a >= b && n <= length && a - b <= length - n;
}
static int valid_pages(uint64_t a, uint64_t n) {
    return n && !(a & (PAGE-1)) && !(n & (PAGE-1)) && n <= UINT64_MAX-a;
}
static int overlaps(uint64_t a,uint64_t n,uint64_t b,uint64_t m) {
    return a < b+m && b < a+n;
}
static int gpu_overlap(uint64_t a,uint64_t n) {
    for(unsigned i=0;i<MAX_MAP;i++)if(g_gpu[i].token && overlaps(a,n,g_gpu[i].address,g_gpu[i].size))return 1;
    return 0;
}
uint64_t dm_android_kernel_gpu_pin(uint64_t a,size_t n,unsigned permissions) {
    if(!a || !n || n>UINT64_MAX-a || !permissions || (permissions&~3u))return 0;
    pthread_mutex_lock(&g_mu);uint64_t token=0;
    if(g_as && span(a,n,as_base(),RESERVE)) {
        int ok=1;size_t end=page_index(a+n-1)+1;
        for(size_t i=page_index(a);i<end;i++)if(!g_pages[i].state || (g_pages[i].perm&permissions)!=permissions){ok=0;break;}
        if(ok)for(unsigned i=0;i<MAX_MAP;i++)if(!g_gpu[i].token){
            if(g_gpu_next!=UINT64_MAX){token=++g_gpu_next;g_gpu[i]=(GpuPin){token,a,n,permissions};}break;
        }
    }
    pthread_mutex_unlock(&g_mu);return token;
}
void dm_android_kernel_gpu_unpin(uint64_t token) {
    if(!token)return;pthread_mutex_lock(&g_mu);
    for(unsigned i=0;i<MAX_MAP;i++)if(g_gpu[i].token==token){g_gpu[i]=(GpuPin){0};break;}
    pthread_mutex_unlock(&g_mu);
}
int dm_android_kernel_gpu_copy(uint64_t token,uint64_t a,void* staging,size_t n) {
    if(!token || !staging || !n)return 0;pthread_mutex_lock(&g_mu);int ok=0;
    for(unsigned i=0;i<MAX_MAP;i++)if(g_gpu[i].token==token && (g_gpu[i].permissions&1) && span(a,n,g_gpu[i].address,g_gpu[i].size)){
        memcpy(staging,(const void*)(uintptr_t)a,n);ok=1;break;
    }
    pthread_mutex_unlock(&g_mu);return ok;
}
static int init_locked(void) {
    if (g_as) return 1;
    long p = sysconf(_SC_PAGESIZE);
    if (p != 4096 && p != 16384) return 0;
    Page* pages = calloc((size_t)PAGE_COUNT,sizeof(Page));
    if (!pages) return 0;
    void* reserve = mmap(NULL,(size_t)RESERVE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (reserve == MAP_FAILED) { free(pages); return 0; }
    g_pages=pages; g_as=reserve; g_host_page=(size_t)p;
    return 1;
}
static size_t page_index(uint64_t a) { return (size_t)((a-as_base())/PAGE); }
static int page_protection(size_t i) {
    unsigned perm=0;
    size_t count=g_host_page/(size_t)PAGE;
    for(size_t k=0;k<count;k++) perm |= g_pages[i+k].perm;
    return ((perm&1)?PROT_READ:0)|((perm&2)?PROT_WRITE:0);
}
/* Caller holds g_mu and has already changed metadata. Failure is reversible:
 * restore metadata, call protect again, and do not publish registry changes. */
static int protect(uint64_t a,uint64_t n) {
    uint64_t lo=a&~((uint64_t)g_host_page-1);
    uint64_t hi=(a+n+g_host_page-1)&~((uint64_t)g_host_page-1);
    for(uint64_t at=lo;at<hi;) {
        int perm=page_protection(page_index(at));
        uint64_t end=at+g_host_page;
        while(end<hi && page_protection(page_index(end))==perm) end+=g_host_page;
        if(mprotect((void*)(uintptr_t)at,(size_t)(end-at),perm)) return 0;
        at=end;
    }
    return 1;
}
static void fill(uint64_t a,uint64_t n,Page value) {
    size_t start=page_index(a), count=(size_t)(n/PAGE);
    for(size_t i=0;i<count;i++)g_pages[start+i]=value;
}
static int pages_match(uint64_t a,uint64_t n,unsigned state,unsigned perm,int require_unowned) {
    if(!span(a,n,as_base(),RESERVE))return 0;
    size_t i=page_index(a),end=page_index(a+n-1)+1;
    for(;i<end;i++) if(g_pages[i].state!=state || (g_pages[i].perm&perm)!=perm || (require_unowned&&g_pages[i].owned)) return 0;
    return 1;
}
static uint64_t image_bytes(void) {
    uint64_t total=0;
    for(int i=0;i<g_nmod;i++) {
        if(g_mod[i].size>UINT64_MAX-total)return UINT64_MAX;
        total+=g_mod[i].size;
    }
    if(total>UINT64_MAX-0x1fffff)return UINT64_MAX;
    return (total+0x1fffff)&~0x1fffffull;
}
static int accessible_locked(uint64_t a,size_t n,int write) {
    if(!n)return 1;
    if(n>UINT64_MAX-a)return 0;
    if(g_as && span(a,n,as_base(),RESERVE)) {
        size_t end=page_index(a+n-1)+1;
        for(size_t i=page_index(a);i<end;i++)if((g_pages[i].perm&(write?2:1))==0)return 0;
        return 1;
    }
    if(dm_android_current_guest_memory(a,n,write))return 1;
    uint64_t bottom=0,base=0;size_t size=0;unsigned flags=0;
    if(dm_android_host_query_memory(a,&base,&size,&flags) && span(a,n,base,size))return (flags&(write?2u:1u))!=0;
    return dm_android_current_stack_bounds(a,&bottom,&size) && span(a,n,bottom,size);
}
int dm_android_kernel_memory_accessible(uint64_t a,size_t n,int write) {
    pthread_mutex_lock(&g_mu);int ok=accessible_locked(a,n,write);pthread_mutex_unlock(&g_mu);return ok;
}
int dm_android_heap_readable(uint64_t a,size_t n) {
    pthread_mutex_lock(&g_mu);
    int ok=g_as && span(a,n,heap_base(),g_heap_cur) && accessible_locked(a,n,0);
    pthread_mutex_unlock(&g_mu);return ok;
}
int dm_android_kernel_memory_copy_readable(uint64_t a,void* staging,size_t n) {
    if(!staging || !a || !n || n>UINT64_MAX-a)return 0;
    pthread_mutex_lock(&g_mu);
    int ok=g_as && span(a,n,as_base(),RESERVE);
    if(ok) {
        const size_t end=page_index(a+n-1)+1;
        for(size_t i=page_index(a);i<end;i++) {
            if(!g_pages[i].state || !(g_pages[i].perm&1)) {ok=0;break;}
        }
    }
    // set_heap, permission, copy_map, physical and reset all use this same
    // mutex. No query/unlock/copy gap and no reliance on broader host-page R.
    if(ok)memcpy(staging,(const void*)(uintptr_t)a,n);
    pthread_mutex_unlock(&g_mu);
    return ok;
}
void dm_android_memory_range(uint8_t** base,size_t* size) {
    pthread_mutex_lock(&g_mu);*base=g_as;*size=(size_t)RESERVE;pthread_mutex_unlock(&g_mu);
}
int dm_android_kernel_stack_pin(uint64_t top,uint64_t* bottom,size_t* size) {
    pthread_mutex_lock(&g_mu);int ok=0;
    for(unsigned i=0;i<g_nmap;i++) {
        Mapping* m=&g_maps[i];
        if(!m->physical && top>m->dst && top<=m->dst+m->size && m->pins<UINT_MAX) {
            ++m->pins;*bottom=m->dst;*size=(size_t)m->size;ok=1;break;
        }
    }
    pthread_mutex_unlock(&g_mu);return ok;
}
void dm_android_kernel_stack_unpin(uint64_t bottom) {
    pthread_mutex_lock(&g_mu);
    for(unsigned i=0;i<g_nmap;i++)if(g_maps[i].dst==bottom && g_maps[i].pins){--g_maps[i].pins;break;}
    pthread_mutex_unlock(&g_mu);
}
int dm_android_kernel_memory_quiescent(void) {
    pthread_mutex_lock(&g_mu);
    int ready=1;
    for(unsigned i=0;i<g_nmap;i++) if(g_maps[i].pins) {ready=0;break;}
    for(unsigned i=0;i<MAX_MAP;i++)if(g_gpu[i].token){ready=0;break;}
    pthread_mutex_unlock(&g_mu);return ready;
}
int dm_android_kernel_memory_reset(void) {
    pthread_mutex_lock(&g_mu);
    for(unsigned i=0;i<MAX_MAP;i++)if(g_gpu[i].token){pthread_mutex_unlock(&g_mu);return 0;}
    for(unsigned i=0;i<g_nmap;i++)if(g_maps[i].pins){pthread_mutex_unlock(&g_mu);return 0;}
    if(g_as && munmap(g_as,(size_t)RESERVE)){pthread_mutex_unlock(&g_mu);return 0;}
    free(g_pages);g_pages=NULL;g_as=NULL;g_heap_cur=0;g_nmap=0;g_host_page=0;
    pthread_mutex_unlock(&g_mu);return 1;
}
static uint32_t set_heap(uint64_t size,uint64_t* out) {
    if(size&0x1fffffull)return INVALID_SIZE;
    if(size>RESERVE-0x40000000ull)return OUT_OF_MEMORY;
    uint64_t image=image_bytes();
    if(image>APP_POOL || size>APP_POOL-image)return OUT_OF_RESOURCE;
    uint64_t old=g_heap_cur,base=heap_base();
    if(size<old) {
        if(gpu_overlap(base+size,old-size))return STATE_IN_USE;
        for(unsigned i=0;i<g_nmap;i++)if(!g_maps[i].physical && overlaps(base+size,old-size,g_maps[i].src,g_maps[i].size))return STATE_IN_USE;
    }
    if(size!=old) {
        uint64_t lo=size<old?size:old,n=size<old?old-size:size-old;
        /* Heap pages can have user permissions; retain them on rollback. */
        /* Discard inaccessible growth before granting permissions. This keeps
         * multi-GiB heaps demand paged and guarantees zero on regrowth. */
        if(size>old && madvise((void*)(uintptr_t)(base+old),(size_t)(size-old),MADV_DONTNEED))return OUT_OF_MEMORY;
        Page* backup=malloc((size_t)(n/PAGE)*sizeof(Page));
        if(!backup)return OUT_OF_MEMORY;
        memcpy(backup,g_pages+page_index(base+lo),(size_t)(n/PAGE)*sizeof(Page));
        fill(base+lo,n,size<old?(Page){0}:(Page){5,3,0,0});
        if(!protect(base+lo,n)) {
            memcpy(g_pages+page_index(base+lo),backup,(size_t)(n/PAGE)*sizeof(Page));
            if(!protect(base+lo,n))die("memory permission rollback failed");
            free(backup);return OUT_OF_MEMORY;
        }
        free(backup);
        if(size<old)(void)madvise((void*)(uintptr_t)(base+size),(size_t)(old-size),MADV_DONTNEED);
        g_heap_cur=size;
    }
    *out=base;return 0;
}
static uint32_t copy_map(uint64_t dst,uint64_t src,uint64_t n,int unmap) {
    if(!valid_pages(dst,n)||!valid_pages(src,n))return INVALID_ADDRESS;
    if(!span(dst,n,as_base()+0x30000000ull,0x10000000ull) || !span(src,n,heap_base(),g_heap_cur))return INVALID_STATE;
    if(gpu_overlap(dst,n)||gpu_overlap(src,n))return STATE_IN_USE;
    if(!unmap) {
        if(g_nmap==MAX_MAP)return OUT_OF_MEMORY;
        if(!pages_match(dst,n,0,0,1)||!pages_match(src,n,5,3,1))return INVALID_STATE;
        Page* backup=malloc((size_t)(n/PAGE)*sizeof(Page));if(!backup)return OUT_OF_MEMORY;
        memcpy(backup,g_pages+page_index(src),(size_t)(n/PAGE)*sizeof(Page));
        fill(dst,n,(Page){0xb,3,0,1});
        if(!protect(dst,n)) { fill(dst,n,(Page){0});if(!protect(dst,n))die("stack permission rollback failed");free(backup);return OUT_OF_MEMORY; }
        /* Source has been validated before the first copy or protection change. */
        memcpy((void*)(uintptr_t)dst,(void*)(uintptr_t)src,(size_t)n);
        for(size_t i=page_index(src),end=page_index(src+n);i<end;i++){g_pages[i].perm=0;g_pages[i].owned=1;}
        if(!protect(src,n)) {
            memcpy(g_pages+page_index(src),backup,(size_t)(n/PAGE)*sizeof(Page));fill(dst,n,(Page){0});
            if(!protect(src,n)||!protect(dst,n))die("mapping rollback failed");free(backup);return OUT_OF_MEMORY;
        }
        free(backup);g_maps[g_nmap++]=(Mapping){dst,src,n,0,0};return 0;
    }
    unsigned k=0;for(;k<g_nmap;k++)if(g_maps[k].dst==dst&&g_maps[k].src==src&&g_maps[k].size==n&&!g_maps[k].physical)break;
    if(k==g_nmap)return INVALID_STATE;
    if(g_maps[k].pins)return STATE_IN_USE;
    for(size_t i=page_index(src),end=page_index(src+n);i<end;i++)g_pages[i].perm=3;
    if(!protect(src,n)) {for(size_t i=page_index(src),end=page_index(src+n);i<end;i++)g_pages[i].perm=0;if(!protect(src,n))die("unmap rollback failed");return OUT_OF_MEMORY;}
    memcpy((void*)(uintptr_t)src,(void*)(uintptr_t)dst,(size_t)n);
    fill(dst,n,(Page){0});
    if(!protect(dst,n)) {
        fill(dst,n,(Page){0xb,3,0,1});
        for(size_t i=page_index(src),end=page_index(src+n);i<end;i++)g_pages[i].perm=0;
        if(!protect(dst,n)||!protect(src,n))die("unmap rollback failed");return OUT_OF_MEMORY;
    }
    for(size_t i=page_index(src),end=page_index(src+n);i<end;i++)g_pages[i].owned=0;
    g_maps[k]=g_maps[--g_nmap];return 0;
}
static uint32_t physical(uint64_t a,uint64_t n,int unmap) {
    if(!valid_pages(a,n))return INVALID_ADDRESS;
    if(!span(a,n,as_base()+0x10000000ull,0x20000000ull))return INVALID_STATE;
    if(gpu_overlap(a,n))return STATE_IN_USE;
    size_t start=page_index(a),count=(size_t)(n/PAGE);
    for(size_t i=0;i<count;i++) {
        Page p=g_pages[start+i];
        if(unmap ? p.owned!=2 : p.state!=0)return INVALID_STATE;
    }
    Page old=unmap?(Page){5,3,0,2}:(Page){0},next=unmap?(Page){0}:(Page){5,3,0,2};
    fill(a,n,next);
    if(!protect(a,n)){fill(a,n,old);if(!protect(a,n))die("physical mapping rollback failed");return OUT_OF_MEMORY;}
    if(unmap) { /* Don't discard host pages containing adjacent 4KiB mappings. */
        uint64_t lo=(a+g_host_page-1)&~((uint64_t)g_host_page-1),hi=(a+n)&~((uint64_t)g_host_page-1);
        if(hi>lo)(void)madvise((void*)(uintptr_t)lo,(size_t)(hi-lo),MADV_DONTNEED);
    } else {
        uint64_t lo=(a+g_host_page-1)&~((uint64_t)g_host_page-1),hi=(a+n)&~((uint64_t)g_host_page-1);
        if(hi>lo && madvise((void*)(uintptr_t)lo,(size_t)(hi-lo),MADV_DONTNEED))memset((void*)(uintptr_t)lo,0,(size_t)(hi-lo));
        uint64_t edge_end=lo<a+n?lo:a+n;
        if(edge_end>a)memset((void*)(uintptr_t)a,0,(size_t)(edge_end-a));
        if(hi>=edge_end && hi<a+n)memset((void*)(uintptr_t)hi,0,(size_t)(a+n-hi));
    }
    return 0;
}
static uint32_t permission(uint64_t a,uint64_t n,uint64_t perm) {
    if(!valid_pages(a,n))return INVALID_ADDRESS;
    if(perm!=0&&perm!=1&&perm!=3)return INVALID_PERMISSION;
    if(!span(a,n,as_base(),RESERVE))return INVALID_STATE;
    if(gpu_overlap(a,n))return STATE_IN_USE;
    size_t start=page_index(a),count=(size_t)(n/PAGE);
    for(size_t i=0;i<count;i++)if(g_pages[start+i].state!=5||g_pages[start+i].owned)return INVALID_STATE;
    Page* backup=malloc(count*sizeof(Page));if(!backup)return OUT_OF_MEMORY;
    memcpy(backup,g_pages+start,count*sizeof(Page));
    for(size_t i=0;i<count;i++)g_pages[start+i].perm=(uint8_t)perm;
    int ok=protect(a,n);
    if(!ok){memcpy(g_pages+start,backup,count*sizeof(Page));if(!protect(a,n))die("permission rollback failed");}
    free(backup);return ok?0:OUT_OF_MEMORY;
}
typedef struct { uint64_t base,size;uint32_t state,attr,perm,ipc,device,pad; } MemoryInfo;
static uint32_t query(uint64_t out,uint64_t a) {
    if(out && !accessible_locked(out,sizeof(MemoryInfo),1))return INVALID_ADDRESS;
    MemoryInfo info={0};
    if(span(a,1,as_base(),RESERVE)) {
        size_t i=page_index(a),lo=i,hi=i+1;
        Page page=g_pages[i];
        while(lo && !memcmp(&g_pages[lo-1],&page,sizeof(Page)))--lo;
        while(hi<PAGE_COUNT && !memcmp(&g_pages[hi],&page,sizeof(Page)))++hi;
        info.base=as_base()+lo*PAGE;info.size=(hi-lo)*PAGE;info.state=page.state;info.perm=page.perm;info.attr=page.attr;
    } else {
        uint64_t base=0;size_t size=0;unsigned flags=0;
        if(dm_android_host_query_memory(a,&base,&size,&flags)) {
            info.base=base;info.size=size;info.perm=flags;info.state=flags?3:0;
        } else if(dm_android_current_guest_region(a,&base,&size,&flags)) {
            /* Exact owned environment/service spans retain their permissions,
             * including read-only timezone strings returned by the host. */
            info.base=base;info.size=size;info.perm=flags;info.state=5;
        } else if(dm_android_current_stack_bounds(a,&base,&size)) {
            info.base=base;info.size=size;info.perm=3;info.state=0xb;
        } else {info.base=a&~(PAGE-1);info.size=PAGE;}
    }
    if(out)memcpy((void*)(uintptr_t)out,&info,sizeof(info));return 0;
}
int dm_android_memory_svc(int number,uint64_t* r) {
    switch(number) {case 1:case 2:case 3:case 4:case 5:case 6:case 0x29:case 0x2c:case 0x2d:break;default:return 0;}
    pthread_mutex_lock(&g_mu);
    if(!init_locked()){r[0]=OUT_OF_MEMORY;pthread_mutex_unlock(&g_mu);return 1;}
    uint32_t result=0;
    switch(number) {
    case 1: result=set_heap(r[1],&r[1]);break;
    case 2: result=permission(r[0],r[1],r[2]);break;
    case 3: {
        uint64_t a=r[0],n=r[1],mask=r[2],value=r[3];
        if(!valid_pages(a,n))result=INVALID_ADDRESS;
        else if((mask&~8ull)||(value&~mask))result=INVALID_STATE;
        else if(!pages_match(a,n,5,0,1))result=INVALID_STATE;
        else for(size_t i=page_index(a),end=page_index(a+n);i<end;i++)g_pages[i].attr=(uint8_t)((g_pages[i].attr&~mask)|value);
        break;
    }
    case 4:case 5: result=copy_map(r[0],r[1],r[2],number==5);break;
    case 6:result=query(r[0],r[2]);r[1]=0;break;
    case 0x2c:case 0x2d:result=physical(r[0],r[1],number==0x2d);break;
    case 0x29: {
        uint64_t value=0;
        switch(r[1]) {
        case 0:value=7;break;case 1:value=0;break;
        case 2:value=as_base()+0x10000000ull;break;case 3:value=0x20000000;break;
        case 4:value=heap_base();break;case 5:value=RESERVE-0x40000000ull;break;
        case 6:case 21:value=APP_POOL;break;case 7:case 22:value=g_heap_cur+image_bytes();break;
        case 12:value=as_base();break;case 13:value=RESERVE;break;
        case 14:value=as_base()+0x30000000ull;break;case 15:value=0x10000000;break;
        case 16:value=0x2000000;break;case 17:value=0x400000;break;
        case 11: { uint64_t dm_entropy64(void);value=dm_entropy64();break;}
        case 8:case 20:value=0;break;case 18:value=0x0100726014352000ull;break;case 23:value=1;break;
        default:result=NOT_IMPLEMENTED;break;
        }
        r[1]=value;break;
    }
    default:break;
    }
    r[0]=result;pthread_mutex_unlock(&g_mu);return 1;
}
