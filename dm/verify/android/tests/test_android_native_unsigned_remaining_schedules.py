"""Narrow FP-byte, low-nibble, paired guard and local store table forms."""
import struct
import unittest
import test_android_native_unsigned_wide_schedules as wide
ar, adr, adrp, TABLE, classify, rewrite = wide.ar, wide.adr, wide.adrp, wide.TABLE, wide.classify, wide.rewrite


def fixture(kind):
    raw = bytearray(0x7000); start = 0x100
    if kind == 'fp-loaded':
        roles=(28,29,26,7); width=1;bound=9;load=0x118;branch=0x124;base=branch+4
        words=[0x710000FF,0x5400000D|(((0x1800-0x104)//4)<<5),0x510004E7,0x710024FF,
               0x54000008|(((0x1800-0x110)//4)<<5),adr(0x114,base,28),0x38676B5D,0x8B1D0B9C,0x2A1F03FB,0xD61F0380]
        struct.pack_into('<3I',raw,0x40,adrp(0x40,TABLE,26),0x9100035A|(TABLE&4095)<<10,ar.branch(0x48,start))
    elif kind == 'mask15':
        roles=(7,21,1,6);width=1;bound=15;load=0x118;branch=0x124;base=0x80
        words=[0x12000CC5,0x71003CBF,0x54000008|(((0x1800-0x108)//4)<<5),0x92400CC6,
               adr(0x110,base,7),0x38666835,0x8B1508E7,0x2A1F03E5,0xD61F00E0]
        load=0x114;branch=0x120
        struct.pack_into('<3I',raw,0x40,adrp(0x40,TABLE,1),0x91000021|(TABLE&4095)<<10,ar.branch(0x48,start))
    elif kind == 'str-guard':
        roles=(12,13,15,9);width=2;bound=146;load=0x120;branch=0x128;base=branch+4
        words=[0xF9401A8A,0x8B080D58,0x7102493F,0xB9001A9F,
               0x54000008|(((0x1800-0x110)//4)<<5),adrp(0x114,TABLE,15),0x910001EF|(TABLE&4095)<<10,
               adr(0x11C,base,12),0x786979ED,0x8B0D098C,0xD61F0180]
        struct.pack_into('<3I',raw,0xA0,0x7102453F,0x54000000|(((0x1800-0xA4)//4)<<5),ar.branch(0xA8,start))
    elif kind == 'local-store':
        roles=(13,14,12,11);width=2;bound=3;load=0x114;branch=0x120;base=branch+4
        words=[0x5304154B,adrp(0x104,TABLE,12),0x9100018C|(TABLE&4095)<<10,
               0xF901A689,adr(0x110,base,13),0x786B798E,0x8B0E09AD,0xAA1F03E8,0xD61F01A0]
        struct.pack_into('<3I',raw,0x40,adrp(0x40,TABLE+0x40,12),0x9100018C|((TABLE+0x40)&4095)<<10,ar.branch(0x48,start))
        struct.pack_into('<4H',raw,TABLE+0x40,0,40,60,80)
    else: raise AssertionError(kind)
    struct.pack_into('<'+str(len(words))+'I',raw,start,*words)
    tags=tuple((0,80,100,120)[i%4] for i in range(bound+1))
    struct.pack_into('<'+str(bound+1)+('B' if width==1 else 'H'),raw,TABLE,*tags)
    targets={base+v*4 for v in tags};ranges=[(start,branch+4),(0x1800,0x1804)]
    if kind in ('fp-loaded','mask15','local-store'):ranges.append((0x40,0x4C))
    if kind=='str-guard':ranges.append((0xA0,0xAC))
    for pc in targets|{0x1800}:struct.pack_into('<I',raw,pc,0xD65F03C0)
    ranges += [(pc,pc+4) for pc in targets]
    target,loaded,table,index=roles
    return bytes(raw),sorted(ranges),dict(kind=kind,start=start,load=load,branch=branch,base=base,target=target,
        loaded=loaded,table=table,index=index,bound=bound,targets=targets,width=width)


class NativeUnsignedRemainingTests(unittest.TestCase):
    execute_fixture = wide.NativeUnsignedWideSchedulesTests.execute_fixture
    def run_case(self,kind,index=0,**options):return self.execute_fixture(*fixture(kind),index,**options)

    def test_all_177_remaining_row_indices_match_original_effects(self):
        for kind,bound in (('fp-loaded',9),('mask15',15),('str-guard',146),('local-store',3)):
            for index in range(bound+1):
                with self.subTest(kind=kind,index=index):
                    original=self.run_case(kind,index,original=True);rewritten=self.run_case(kind,index)
                    self.assertEqual((False,original['reached'],1),(rewritten['trapped'],rewritten['reached'],rewritten['reads']))
                    self.assertEqual((original['final'],original['memory'],original['payload']),(rewritten['final'],rewritten['memory'],rewritten['payload']))
        for index in (1<<32,(1<<64)-1,0x123456780000000A):
            original=self.run_case('mask15',index,original=True);rewritten=self.run_case('mask15',index)
            self.assertEqual((original['reached'],original['final']),(rewritten['reached'],rewritten['final']))

    def test_actual_base_and_full_index_failure_never_reads_table(self):
        for kind in ('fp-loaded','mask15','str-guard','local-store'):
            _,_,info=fixture(kind)
            for index,bad in ((0,'table'),(0,'base'),(info['bound']+1,None),(1<<32,None),(2**64-1,None)):
                result=self.run_case(kind,index,entry='load',bad=bad)
                self.assertEqual((True,None,0),(result['trapped'],result['reached'],result['reads']))
                self.assertEqual((result['initial'],result['initial_memory'],result['initial_payload']),(result['final'],result['memory'],result['payload']))

    def test_shapes_roles_guards_ro_and_independent_postload_entries_fail_closed(self):
        for kind in ('fp-loaded','mask15','str-guard','local-store'):
            raw,ranges,info=fixture(kind);self.assertIsNotNone(classify(raw,ranges,info))
            image=rewrite(raw,ranges,info)
            for pc in range(info['start'],info['branch']+4,4):
                if pc!=info['load']:self.assertEqual(raw[pc:pc+4],image.bytes[pc:pc+4])
            for pc in range(info['load']+4,info['branch']+4,4):self.assertIsNone(classify(raw,ranges,info,entries=(pc,)))
            self.assertIsNone(classify(raw,ranges,info,readonly=((TABLE,TABLE+(info['bound']+1)*info['width']-1),)))
        mutations={'fp-loaded':[(0x100,0x710004FF),(0x104,0x54000000),(0x108,0x510008E7),(0x120,0x2A1F03FC),(0x118,0x38676B5E)],
                   'mask15':[(0x100,0x12000CC4),(0x104,0x710038BF),(0x10C,0x924010C6),(0x11C,0x2A1F03E7)],
                   'str-guard':[(0x100,0xF9401A8B),(0x104,0x8B080D49),(0x10C,0xB9001A89),(0x110,0x54000000)],
                   'local-store':[(0x100,0x5304194B),(0x10C,0xF8018689),(0x11C,0xAA1F03ED)]}
        for kind,cases in mutations.items():
            raw,ranges,info=fixture(kind)
            for pc,word in cases:
                changed=bytearray(raw);struct.pack_into('<I',changed,pc,word)
                self.assertIsNone(classify(changed,ranges,info),(kind,hex(pc),hex(word)))


if __name__=='__main__':unittest.main()
