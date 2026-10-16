"""Native streaming/inventory tests with temporary self-authored resources."""
import hashlib
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]


class TaikoResourcesTests(unittest.TestCase):
    def test_native_content_and_streaming(self):
        compiler = shutil.which("c++") or shutil.which("clang++")
        if not compiler:
            self.skipTest("host C++ compiler required; run under WSL on Windows")
        payload = bytes(range(256)) * 1025
        manifest = b"self-authored compiled manifest fixture\n"

        def digest(data):
            return "{" + ",".join(str(b) for b in hashlib.sha256(data).digest()) + "}"

        harness = r'''
#include "taiko_resources.h"
#include "module_sha256.h"
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <unistd.h>
namespace dm_android {
static TaikoResourcePin files[]{{"RomFS/Data/beat.bin",PAYLOAD_BYTES,PAYLOAD_SHA},{"RomFS/empty",0,EMPTY_SHA}};
static TaikoContentPins pins{1,"01002460135A4000",MANIFEST_SHA,files,2,PAYLOAD_BYTES};
#ifndef NO_PROVIDER
const TaikoContentPins* compiled_taiko_content_pins(){return &pins;}
#endif
}
int main(int argc,char** argv){using namespace dm_android;assert(argc==3);std::string error;
 int fd=open(argv[1],O_RDONLY|O_DIRECTORY);assert(fd>=0);
#ifdef NO_PROVIDER
 assert(!taiko_content_pins());assert(!verify_taiko_content(fd,&error));close(fd);return 0;
#else
 const std::string mode=argv[2];
 if(mode=="badpath")files[0].path="RomFS/../beat.bin";
 if(mode=="badtitle")pins.program_id="0100000000000000";
 if(mode=="badtotal")pins.total_bytes++;
 if(mode=="badorder")std::swap(files[0],files[1]);
 if(mode=="bound")files[0].bytes=17ull*1024*1024*1024;
 if(mode=="good"){
  assert(taiko_content_pins());int file=openat(fd,"RomFS/Data/beat.bin",O_RDONLY|O_NOFOLLOW);assert(file>=0);
  assert(lseek(file,7,SEEK_SET)==7);std::array<uint8_t,32> actual{};assert(module_sha256_fd(file,PAYLOAD_BYTES,PAYLOAD_BYTES,actual.data(),&error));assert(actual==files[0].sha256);assert(lseek(file,0,SEEK_CUR)==7);
  assert(!module_sha256_fd(file,PAYLOAD_BYTES-1,PAYLOAD_BYTES,actual.data(),&error));assert(!module_sha256_fd(file,PAYLOAD_BYTES,PAYLOAD_BYTES-1,actual.data(),&error));assert(!module_sha256_fd(fd,0,0,actual.data(),&error));close(file);
  ModuleSha256 incremental;const uint8_t abc[]{'a','b','c'};for(auto b:abc)incremental.update(&b,1);incremental.update(nullptr,0);incremental.finish(actual.data());const std::array<uint8_t,32> abcsha=ABC_SHA;assert(actual==abcsha);incremental.finish(actual.data());assert(actual==abcsha);
  for(size_t length:{size_t(0),size_t(1),size_t(55),size_t(56),size_t(63),size_t(64),size_t(65),size_t(127),size_t(128),size_t(1000)}){
   uint8_t data[1000];for(size_t i=0;i<1000;++i)data[i]=uint8_t(i);ModuleSha256 stream;for(size_t i=0;i<length;++i)stream.update(data+i,1);std::array<uint8_t,32> chunked{},whole{};stream.finish(chunked.data());module_sha256(data,length,whole.data());assert(chunked==whole);
  }
 }
 const bool ok=verify_taiko_content(fd,&error);close(fd);
 if(ok!=(mode=="good")){std::cerr<<mode<<": "<<error;return 1;}return 0;
#endif
}
'''
        for key, value in {"PAYLOAD_BYTES": str(len(payload)), "PAYLOAD_SHA": digest(payload),
                           "EMPTY_SHA": digest(b""), "MANIFEST_SHA": digest(manifest), "ABC_SHA": digest(b"abc")}.items():
            harness = harness.replace(key, value)
        with tempfile.TemporaryDirectory() as directory:
            d = pathlib.Path(directory)
            (d / "resources.cpp").write_text(harness)
            content = d / "content"
            (content / "RomFS/Data").mkdir(parents=True)
            (content / "RomFS/Data/beat.bin").write_bytes(payload)
            (content / "RomFS/empty").write_bytes(b"")
            (content / "taiko-content.json").write_bytes(manifest)
            for absent in (False, True):
                binary = d / ("absent" if absent else "resources")
                cmd = [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "dm/platform/android"),
                       str(d / "resources.cpp"), str(ROOT / "dm/platform/android/taiko_resources.cpp"),
                       str(ROOT / "dm/platform/android/module_sha256.cpp"), "-o", str(binary)]
                if absent:
                    cmd.insert(1, "-DNO_PROVIDER")
                    cmd.insert(2, "-Wno-unused-variable")
                built = subprocess.run(cmd, capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                modes = ("absent",) if absent else ("good", "badpath", "badtitle", "badtotal", "badorder", "bound")
                for mode in modes:
                    ran = subprocess.run([str(binary), str(content), mode], capture_output=True, text=True)
                    self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            def verify_bad():
                ran = subprocess.run([str(d / "resources"), str(content), "reject"], capture_output=True, text=True)
                self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)
            beat = content / "RomFS/Data/beat.bin"
            beat.write_bytes(b"!" + payload[1:]); verify_bad(); beat.write_bytes(payload)
            beat.rename(beat.with_name("Beat.bin")); verify_bad(); beat.with_name("Beat.bin").rename(beat)
            beat.unlink(); verify_bad(); beat.write_bytes(payload)
            extra = content / "RomFS/extra"; extra.write_bytes(b"extra"); verify_bad(); extra.unlink()
            beat.unlink(); beat.symlink_to(d / "outside"); verify_bad(); beat.unlink(); beat.write_bytes(payload)
            linkdir = content / "RomFS/linkdir"; linkdir.symlink_to(d, target_is_directory=True); verify_bad(); linkdir.unlink()
            manifest_path = content / "taiko-content.json"
            manifest_path.write_bytes(b"wrong manifest"); verify_bad(); manifest_path.write_bytes(manifest)
            manifest_path.unlink(); manifest_path.symlink_to(d / "outside"); verify_bad(); manifest_path.unlink(); manifest_path.write_bytes(manifest)
            import os
            fifo = content / "RomFS/fifo"; os.mkfifo(fifo); verify_bad(); fifo.unlink()


if __name__ == "__main__":
    unittest.main()
