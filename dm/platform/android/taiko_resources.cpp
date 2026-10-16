#include "taiko_resources.h"
#include "module_sha256.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <memory>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace dm_android {
const TaikoContentPins* compiled_taiko_content_pins() __attribute__((weak));
namespace {
constexpr size_t max_files=100000,max_path=4096,max_depth=64,max_entries=200000;
constexpr uint64_t max_file_bytes=16ull*1024*1024*1024,max_total_bytes=64ull*1024*1024*1024;
constexpr uint64_t max_manifest_bytes=128ull*1024*1024;
struct Fd {
    int value=-1;
    explicit Fd(int fd):value(fd){}
    ~Fd(){if(value>=0)close(value);}
    Fd(const Fd&)=delete;
    Fd& operator=(const Fd&)=delete;
};
bool fail(std::string* error,const std::string& text){if(error)*error=text;return false;}
bool nonzero(const std::array<uint8_t,32>& value){for(auto byte:value)if(byte)return true;return false;}
bool component(const std::string& name){
    if(name.empty() || name=="." || name==".." || name.size()>255 || name.back()==' ' || name.back()=='.')return false;
    for(unsigned char c:name)if(c<32 || c==127 || c=='/' || c=='\\' || c==':')return false;
    return true;
}
bool valid_path(const char* value){
    if(!value || std::strncmp(value,"RomFS/",6))return false;
    const size_t length=strnlen(value,max_path);
    if(length>=max_path)return false;
    std::string path(value,length);size_t begin=0,depth=0;
    while(begin<path.size()) {
        const size_t end=path.find('/',begin);
        if(!component(path.substr(begin,end==std::string::npos?end:end-begin)) || ++depth>max_depth)return false;
        if(end==std::string::npos)return true;
        begin=end+1;
    }
    return false;
}
bool same_stat(const struct stat& a,const struct stat& b){
    return a.st_dev==b.st_dev && a.st_ino==b.st_ino && a.st_size==b.st_size &&
        a.st_mtim.tv_sec==b.st_mtim.tv_sec && a.st_mtim.tv_nsec==b.st_mtim.tv_nsec &&
        a.st_ctim.tv_sec==b.st_ctim.tv_sec && a.st_ctim.tv_nsec==b.st_ctim.tv_nsec;
}
bool file_hash(int directory,const char* name,uint64_t bytes,uint64_t limit,
               const std::array<uint8_t,32>& expected,std::string* error){
    Fd file(openat(directory,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK));
    std::array<uint8_t,32> actual{};
    if(file.value<0 || !module_sha256_fd(file.value,bytes,limit,actual.data(),error))
        return fail(error,std::string("cannot verify content file: ")+name);
    if(actual!=expected)return fail(error,std::string("content file hash mismatch: ")+name);
    return true;
}
struct Inventory {
    const TaikoContentPins& pins;
    std::vector<bool> seen;
    size_t entries=0,files=0;
    uint64_t bytes=0;
    explicit Inventory(const TaikoContentPins& p):pins(p),seen(p.file_count,false){}
    bool walk(int directory,const std::string& prefix,size_t depth,std::string* error){
        if(depth>max_depth)return fail(error,"RomFS directory nesting exceeds bound");
        struct stat before{},after{};
        if(fstat(directory,&before) || !S_ISDIR(before.st_mode))return fail(error,"RomFS directory is invalid");
        const int duplicate=dup(directory);
        if(duplicate<0)return fail(error,"cannot duplicate RomFS directory descriptor");
        std::unique_ptr<DIR,int(*)(DIR*)> stream(fdopendir(duplicate),closedir);
        if(!stream){close(duplicate);return fail(error,"cannot enumerate RomFS directory");}
        for(;;){
            errno=0;dirent* entry=readdir(stream.get());
            if(!entry){if(errno)return fail(error,"cannot finish RomFS directory enumeration");break;}
            const std::string name(entry->d_name);
            if(name=="." || name=="..")continue;
            if(!component(name) || ++entries>max_entries)return fail(error,"unsafe or excessive RomFS directory entry");
            const std::string path=prefix+"/"+name;
            if(path.size()>=max_path)return fail(error,"RomFS path exceeds bound");
            struct stat value{};
            if(fstatat(directory,name.c_str(),&value,AT_SYMLINK_NOFOLLOW))return fail(error,"RomFS entry changed during enumeration");
            if(S_ISDIR(value.st_mode)){
                Fd child(openat(directory,name.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY));
                struct stat opened{};
                if(child.value<0 || fstat(child.value,&opened) || !same_stat(value,opened) ||
                   !walk(child.value,path,depth+1,error))return fail(error,"cannot verify RomFS directory: "+path);
            }else if(S_ISREG(value.st_mode)){
                const auto* pin=std::lower_bound(pins.files,pins.files+pins.file_count,path,
                    [](const TaikoResourcePin& p,const std::string& path){return std::strcmp(p.path,path.c_str())<0;});
                if(pin==pins.files+pins.file_count || path!=pin->path)return fail(error,"unexpected RomFS file: "+path);
                const size_t index=static_cast<size_t>(pin-pins.files);
                if(seen[index] || value.st_size<0 || uint64_t(value.st_size)!=pin->bytes ||
                   !file_hash(directory,name.c_str(),pin->bytes,max_file_bytes,pin->sha256,error))
                    return fail(error,"RomFS resource verification failed: "+path);
                seen[index]=true;++files;bytes+=pin->bytes;
            }else return fail(error,"RomFS symlink or special entry rejected: "+path);
        }
        if(fstat(directory,&after) || !same_stat(before,after))return fail(error,"RomFS directory changed during verification");
        return true;
    }
};
}
const TaikoContentPins* taiko_content_pins(){
    const auto* pins=compiled_taiko_content_pins?compiled_taiko_content_pins():nullptr;
    if(!pins || pins->schema!=1 || !pins->program_id || std::strcmp(pins->program_id,"01002460135A4000") ||
       !nonzero(pins->manifest_sha256) || !pins->files || !pins->file_count || pins->file_count>max_files ||
       pins->total_bytes>max_total_bytes)return nullptr;
    uint64_t total=0;
    for(size_t i=0;i<pins->file_count;++i){
        const auto& file=pins->files[i];
        if(!valid_path(file.path) || !nonzero(file.sha256) || file.bytes>max_file_bytes ||
           file.bytes>max_total_bytes-total || (i && std::strcmp(pins->files[i-1].path,file.path)>=0))return nullptr;
        total+=file.bytes;
    }
    return total==pins->total_bytes?pins:nullptr;
}
bool verify_taiko_content(int directory,std::string* error){
    if(error)error->clear();
    const auto* pins=taiko_content_pins();
    if(!pins)return fail(error,"Taiko content has no complete trusted compiled resource pins");
    struct stat root_before{},root_after{};
    if(fstat(directory,&root_before) || !S_ISDIR(root_before.st_mode))return fail(error,"Taiko content directory descriptor is invalid");
    struct stat manifest{};
    if(fstatat(directory,"taiko-content.json",&manifest,AT_SYMLINK_NOFOLLOW) || !S_ISREG(manifest.st_mode) ||
       manifest.st_size<0 || uint64_t(manifest.st_size)>max_manifest_bytes ||
       !file_hash(directory,"taiko-content.json",uint64_t(manifest.st_size),max_manifest_bytes,pins->manifest_sha256,error))
        return fail(error,"Taiko content manifest differs from compiled authority");
    Fd romfs(openat(directory,"RomFS",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY));
    if(romfs.value<0)return fail(error,"Taiko content RomFS directory is missing or unsafe");
    Inventory inventory(*pins);
    if(!inventory.walk(romfs.value,"RomFS",1,error))return false;
    if(inventory.files!=pins->file_count || inventory.bytes!=pins->total_bytes)
        return fail(error,"Taiko RomFS inventory omits pinned resources");
    if(fstat(directory,&root_after) || !same_stat(root_before,root_after))
        return fail(error,"Taiko content directory changed during verification");
    return true;
}
}
