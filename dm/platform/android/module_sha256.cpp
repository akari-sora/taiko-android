#include "module_sha256.h"
#include <string.h>
#include <algorithm>
#include <cerrno>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>
namespace dm_android {
namespace {
constexpr uint32_t k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
uint32_t rotr(uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }
void block(uint32_t h[8], const uint8_t p[64]) {
    uint32_t w[64];
    for (unsigned i=0;i<16;++i) w[i]=(uint32_t(p[i*4])<<24)|(uint32_t(p[i*4+1])<<16)|(uint32_t(p[i*4+2])<<8)|p[i*4+3];
    for (unsigned i=16;i<64;++i) {
        uint32_t a=w[i-15],b=w[i-2];
        w[i]=w[i-16]+(rotr(a,7)^rotr(a,18)^(a>>3))+w[i-7]+(rotr(b,17)^rotr(b,19)^(b>>10));
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],j=h[7];
    for (unsigned i=0;i<64;++i) {
        uint32_t t=j+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t u=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
        j=g;g=f;f=e;e=d+t;d=c;c=b;b=a;a=t+u;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=j;
}
}
ModuleSha256::ModuleSha256() : state_{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19} {}
void ModuleSha256::update(const uint8_t* bytes,size_t size) {
    if(!size)return;
    bytes_+=size;
    if(tail_bytes_) {
        const size_t take=std::min(size,64-tail_bytes_);
        if(take)memcpy(tail_+tail_bytes_,bytes,take);
        tail_bytes_+=take;bytes+=take;size-=take;
        if(tail_bytes_==64){block(state_,tail_);tail_bytes_=0;}
    }
    while(size>=64){block(state_,bytes);bytes+=64;size-=64;}
    if(size){memcpy(tail_,bytes,size);tail_bytes_=size;}
}
void ModuleSha256::finish(uint8_t digest[32]) const {
    uint32_t h[8];memcpy(h,state_,sizeof(h));
    uint8_t tail[128]={};const size_t remain=tail_bytes_;
    if(remain) memcpy(tail,tail_,remain);
    tail[remain]=0x80;
    size_t length=remain<56?64:128; uint64_t bits=bytes_*8;
    for(unsigned i=0;i<8;++i) tail[length-1-i]=uint8_t(bits>>(i*8));
    block(h,tail);if(length==128) block(h,tail+64);
    for(unsigned i=0;i<32;++i) digest[i]=uint8_t(h[i/4]>>(24-(i%4)*8));
}
void module_sha256(const uint8_t* bytes,size_t size,uint8_t digest[32]) {
    ModuleSha256 hash;hash.update(bytes,size);hash.finish(digest);
}
bool module_sha256_fd(int fd,uint64_t expected,uint64_t limit,uint8_t digest[32],std::string* error) {
    if(error)error->clear();
    const auto fail=[&](const char* text){if(error)*error=text;return false;};
    if(!digest || expected>limit || expected>uint64_t(std::numeric_limits<off_t>::max()))return fail("file hash exceeds trusted size bound");
    struct stat before{},after{};
    if(fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_size<0 || uint64_t(before.st_size)!=expected)
        return fail("file hash requires an ordinary file of the pinned size");
    ModuleSha256 hash;uint8_t buffer[64*1024];uint64_t position=0;
    while(position<expected) {
        const size_t count=static_cast<size_t>(std::min<uint64_t>(sizeof(buffer),expected-position));
        const ssize_t got=pread(fd,buffer,count,static_cast<off_t>(position));
        if(got<0 && errno==EINTR)continue;
        if(got<=0)return fail("file hash read failed or source became short");
        hash.update(buffer,static_cast<size_t>(got));position+=static_cast<size_t>(got);
    }
    if(fstat(fd,&after) || before.st_dev!=after.st_dev || before.st_ino!=after.st_ino ||
       before.st_size!=after.st_size || before.st_mtim.tv_sec!=after.st_mtim.tv_sec ||
       before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec || before.st_ctim.tv_sec!=after.st_ctim.tv_sec ||
       before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)return fail("file changed during streaming hash");
    hash.finish(digest);return true;
}
}
