"""Authored four-head tagged-chain fixtures; no title addresses or input bytes."""
from pathlib import Path
import struct,sys,unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[4]
sys.path[:0]=[str(ROOT/'dm/tools'),str(ROOT/'dm/verify/android/tests')]
import android_rewrite as ar
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn import arm64_const as uc
ENTRY=0x40;CALLEES=(0x200,0x220,0x240);STOP=0x2F0
MASK=(1<<64)-1

def raw(values):return struct.pack('<'+'I'*len(values),*values)
def branch19(pc,target,base,reg=0):return base|(((target-pc)//4)&0x7FFFF)<<5|reg
def branch14(pc,target,base,reg=0):return base|(((target-pc)//4)&0x3FFF)<<5|reg
def fixture(layout=0x60,roles=(19,20,21,8,9)):
    owner,cell,other,link,status=roles;clear=ENTRY+layout;second=clear+8;end=clear+0x1C
    values=[0xD503201F]*(0x300//4)
    values[:3]=(0xA9BF7BFD,0x910003FD,ar.branch(8,ENTRY))
    def put(pc,word):values[pc//4]=word
    words=(0xC85FFC00|cell<<5|owner,branch14(ENTRY+4,clear,0x37000000,owner),
        0xF9400000|owner<<5|link,branch19(ENTRY+12,ENTRY+28,0xB4000000,link),
        0xC800FC00|status<<16|cell<<5|link,branch19(ENTRY+20,ENTRY,0x35000000,status),
        ar.branch(ENTRY+24,ENTRY+72),0xB2400000|owner<<5|link,
        0xC85FFC00|cell<<5|status,0xEB00001F|owner<<16|status<<5,
        branch19(ENTRY+40,clear,0x54000001),0xC8007C00|status<<16|cell<<5|link,
        branch19(ENTRY+48,ENTRY+32,0x35000000,status),0xC85FFC00|other<<5|link,
        0xEB00001F|owner<<16|link<<5,branch19(ENTRY+60,second,0x54000001),
        0xC8007C1F|link<<16|other<<5,branch19(ENTRY+68,ENTRY+52,0x35000000,link))
    for index,word in enumerate(words):put(ENTRY+index*4,word)
    island=[branch19(ENTRY+72,end,0xB4000000,owner),0x91000000|((0x28 if layout==0x68 else 0x10)<<10)|owner<<5,
        0x94000000|(((CALLEES[0]-(ENTRY+80))//4)&0x3FFFFFF)]
    if layout==0x68:island.extend((0x91000000|0x18<<10|owner<<5,0x94000000|(((CALLEES[1]-(ENTRY+88))//4)&0x3FFFFFF)))
    island.extend((0xAA0003E0|owner<<16,0x94000000|(((CALLEES[2]-(clear-8))//4)&0x3FFFFFF),ar.branch(clear-4,ENTRY)))
    assert len(island)==(layout-0x48)//4
    for index,word in enumerate(island):put(ENTRY+72+index*4,word)
    tail=(0xD5033F5F,ar.branch(clear+4,end),0xD5033F5F,0xC85F7C00|cell<<5|link,
        0x927FF800|link<<5|link,0xC800FC00|status<<16|cell<<5|link,
        branch19(second+16,second+4,0x35000000,status))
    for index,word in enumerate(tail):put(clear+index*4,word)
    put(end,0xA8C17BFD);put(end+4,0xD65F03C0)
    for at in CALLEES:
        put(at,0x91000400|22<<5|22);put(at+4,0xD65F03C0)
    put(CALLEES[2],0xF9000000|cell<<5|23);put(CALLEES[2]+4,0x91000400|22<<5|22);put(CALLEES[2]+8,0xD65F03C0)
    return values
def geometry(layout):
    clear=ENTRY+layout;second=clear+8
    nodes=set(range(ENTRY,ENTRY+72,4))|{clear,clear+4}|set(range(second,second+20,4))
    return nodes,{ENTRY,ENTRY+32,ENTRY+52,second+4},clear+0x1C
def decoded(values):
    ops=[ar.decode(word,index*4) for index,word in enumerate(values)]
    return ops,{op.address:op for op in ops},{op.address:ar.site_kind(op) for op in ops}
def match(values,missing=(),overrides=None):
    ops,by,kinds=decoded(values);kinds.update(overrides or {})
    for pc in missing:by.pop(pc,None)
    fn=getattr(ar.android_exclusive,'native_pointer_chain',None)
    return None if fn is None else fn(ops[ENTRY//4],by,kinds,ar)
def plan(values,roots=(0,),overrides=None,reverse=False):
    ops,_,kinds=decoded(values);kinds.update(overrides or {})
    if reverse:ops=list(reversed(ops))
    return ar.android_exclusive.plan_regions(ops,kinds,roots,ar)

class NativePointerChainTests(unittest.TestCase):
    def test_exact_native_nodes_four_heads_and_role_renaming(self):
        for layout in (0x60,0x68):
            nodes,heads,_=geometry(layout)
            for roles in ((19,20,21,8,9),(25,26,27,16,17),(0,1,2,3,4)):
                values=fixture(layout,roles)
                self.assertEqual((nodes,ENTRY,heads),match(values))
                self.assertEqual((),plan(values))
                image=ar.rewrite(raw(values),entry_offsets=(0,))
                self.assertEqual(raw(values),image.bytes);self.assertFalse(image.sites);self.assertFalse(image.fixups)

    def test_every_interior_metadata_materialized_table_call_origin_and_raw_edge_refuses(self):
        for layout in (0x60,0x68):
            nodes,heads,_=geometry(layout)
            for pc in sorted(nodes-{ENTRY}):
                for origin in ('metadata','materialized','finite-table','checked-call'):
                    with self.subTest(layout=layout,pc=pc,origin=origin),self.assertRaises(ar.RewriteError):
                        plan(fixture(layout),roots=(0,pc))
                for mnemonic in ('b','cbnz','tbnz','bl'):
                    values=fixture(layout);at=12
                    values[at//4]=(ar.branch(at,pc) if mnemonic=='b' else
                        branch19(at,pc,0x35000000,7) if mnemonic=='cbnz' else
                        branch14(at,pc,0x37000000,7) if mnemonic=='tbnz' else
                        0x94000000|(((pc-at)//4)&0x3FFFFFF))
                    with self.subTest(layout=layout,pc=pc,mnemonic=mnemonic),self.assertRaises(ar.RewriteError):plan(values)

    def test_missing_kind_contamination_fatal_and_role_collisions_refuse(self):
        for layout in (0x60,0x68):
            nodes,_,_=geometry(layout)
            for pc in sorted(nodes):
                self.assertIsNone(match(fixture(layout),missing=(pc,)))
                ops,by,kinds=decoded(fixture(layout));kinds.pop(pc)
                fn=getattr(ar.android_exclusive,'native_pointer_chain',None)
                if fn is not None:
                    with self.assertRaises(ar.RewriteError):fn(by[ENTRY],by,kinds,ar)
                for kind in ('gate','profile','parameter','table','tls','x18','data'):
                    with self.assertRaises(ar.RewriteError):match(fixture(layout),overrides={pc:kind})
                values=fixture(layout);values[pc//4]=0xD4200000;self.assertIsNone(match(values))
            roles=(19,20,21,8,9)
            for index in range(5):
                for value in (*[role for role in roles if role!=roles[index]],18,29,30,31):
                    changed=list(roles);changed[index]=value;self.assertIsNone(match(fixture(layout,tuple(changed))))

    def test_geometry_flags_width_tag_mask_release_and_unknown_transfers_stay_exact(self):
        for layout in (0x60,0x68):
            nodes,_,end=geometry(layout)
            for pc in sorted(nodes):
                values=fixture(layout);values[pc//4]^=1<< (15 if pc in (ENTRY,ENTRY+16,ENTRY+32,ENTRY+44,ENTRY+52,ENTRY+64,end-16,end-8) else 0)
                try:value=match(values)
                except ar.RewriteError:continue
                self.assertIsNone(value,hex(pc))
            for pc,word in ((ENTRY+4,branch14(ENTRY+4,ENTRY+layout+4,0x37000000,19)),
                            (ENTRY+40,branch19(ENTRY+40,ENTRY+layout+8,0x54000001)),
                            (ENTRY+60,branch19(ENTRY+60,ENTRY+layout,0x54000001))):
                values=fixture(layout);values[pc//4]=word;self.assertIsNone(match(values))
            for pc in nodes:
                for word in (0xD61F0200,0xD63F0200,0xD65F03C0,0xD4000001):
                    values=fixture(layout);values[pc//4]=word
                    try:value=match(values)
                    except ar.RewriteError:continue
                    self.assertIsNone(value)
            for pc in (ENTRY+72,end):
                self.assertIsNone(match(fixture(layout),missing=(pc,)))
                values=fixture(layout);values[pc//4]=0xD4200000;self.assertIsNone(match(values))

    def test_every_single_source_word_bit_mutation_refuses(self):
        fn=getattr(ar.android_exclusive,'native_pointer_chain',None)
        if fn is None:self.fail('source matcher absent')
        for layout in (0x60,0x68):
            values=fixture(layout);_,base_by,base_kinds=decoded(values)
            for pc in sorted(geometry(layout)[0]):
                for bit in range(32):
                    by=base_by.copy();kinds=base_kinds.copy()
                    try:
                        by[pc]=ar.decode(values[pc//4]^(1<<bit),pc);kinds[pc]=ar.site_kind(by[pc])
                        value=fn(by[ENTRY],by,kinds,ar)
                    except ar.RewriteError:continue
                    self.assertIsNone(value,(hex(layout),hex(pc),bit))

    def test_call_island_remains_outside_and_overlap_uses_existing_consumer(self):
        for layout in (0x60,0x68):
            _,_,end=geometry(layout);values=fixture(layout)
            for pc in range(ENTRY+72,ENTRY+layout,4):
                self.assertIsNotNone(match(values,overrides={pc:'gate'}))
            gated=fixture(layout);gated[(ENTRY+76)//4]=0xD4000001
            self.assertIsNotNone(match(gated))
            lowered=ar.rewrite(raw(gated),entry_offsets=(0,))
            self.assertIn(ENTRY+76,{site.offset for site in lowered.sites})
            self.assertFalse({site.offset for site in lowered.sites}&geometry(layout)[0])
            for pc in geometry(layout)[0]:self.assertEqual(lowered.bytes[pc:pc+4],raw(gated)[pc:pc+4])
            # A selected fallthrough from outside into clearB's second word is
            # also an external entrance, despite not being an immediate branch.
            values=fixture(layout);values[(ENTRY+layout-4)//4]=0xD503201F
            self.assertIsNotNone(match(values))
            with self.assertRaisesRegex(ar.RewriteError,'external entry into'):plan(values)
            # Reverse processing also remains conservative.
            with self.assertRaises(ar.RewriteError):plan(fixture(layout),reverse=True)
            # Isolated consumer test: a prior recognized fallback-only region
            # claims its real four words. This mock does not grant source
            # acceptance; it exercises the unchanged occupied-set boundary.
            real=getattr(ar.android_exclusive,'native_pointer_chain',None)
            if real is not None:
                fallback=ENTRY+layout+12
                def earlier(start,by,kinds,api):
                    if start.address==fallback:return set(range(fallback,fallback+16,4)),fallback,{fallback}
                    return real(start,by,kinds,api)
                ops,_,kinds=decoded(fixture(layout));ordered=[op for op in ops if op.address==fallback]+[op for op in ops if op.address!=fallback]
                with patch.object(ar.android_exclusive,'native_pointer_chain',earlier):
                    with self.assertRaisesRegex(ar.RewriteError,'overlapping exclusive windows'):
                        ar.android_exclusive.plan_regions(ordered,kinds,(0,),ar)
            # An unrelated extra nested load is still rejected by the original walker.
            values=fixture(layout);values[0x180//4]=0xC85FFE68;values[0x184//4]=0xC85FFE69
            with self.assertRaises(ar.RewriteError):plan(values,roots=(0,0x180))

    def test_authored_cpu_four_store_paths_match_independent_reference(self):
        cases=(dict(tagged=True),dict(link=NODE_NEXT),dict(link=NODE_NEXT,fail=(1,0,0,0)),
            dict(),dict(fail=(0,1,0,0)),dict(mismatch_second=True),dict(secondary=NODE_NEXT),
            dict(fail=(0,0,1,0)),dict(secondary=NODE_NEXT,fail=(0,0,0,1)),
            dict(fail=(0,1,1,0)),dict(link=NODE_NEXT,fail=(1,0,0,0),compete=(0,NODE|1)),
            dict(fail=(0,1,0,0),compete=(1,NODE|1)),dict(fail=(0,0,1,0),compete=(2,NODE_NEXT)),
            dict(secondary=NODE_NEXT,fail=(0,0,0,1),compete=(3,NODE|3)),
            dict(secondary=NODE+(1<<32)),dict(tagged=True,owner_high=True),dict(link=0xABCDEF1200500200))
        for layout in (0x60,0x68):
            for roles in ((19,20,21,8,9),(25,26,27,16,17)):
                values=fixture(layout,roles);image=ar.rewrite(raw(values),entry_offsets=(0,))
                self.assertEqual(image.bytes,raw(values))
                for case in cases:
                    with self.subTest(layout=layout,roles=roles,case=case):
                        before=initial_registers(roles);want=reference(layout,roles,before,case)
                        observed=execute(image.bytes,layout,roles,before,case)
                        self.assertEqual(want,observed)


CODE=0x100000;PRIMARY=0x400100;SECONDARY=0x400180;NODE=0x500100;NODE_NEXT=0x500200;STACK=0x800800
def initial_registers(roles):
    x=[0xFEDCBA9800000100+index*0x101 for index in range(31)]
    x[roles[1]],x[roles[2]]=PRIMARY,SECONDARY;x[22]=0x12FEED0000000000;x[23]=NODE|1
    x[29]=0xCAFEBABE98760000;x[30]=CODE+STOP
    return x
def cmp64(left,right):
    left&=MASK;right&=MASK;value=(left-right)&MASK
    return ((bool(value>>63)<<3)|((value==0)<<2)|((left>=right)<<1)|bool((left^right)&(left^value)&(1<<63)))<<28
def initial_memory(case):
    owner=NODE|int(case.get('tagged',False))|(1<<63 if case.get('owner_high') else 0)
    return {PRIMARY:owner,SECONDARY:case.get('secondary',NODE),NODE:case.get('link',0)}
def reference(layout,roles,before,case):
    """Value-level tagged-chain algorithm, independent of opcode decoding."""
    owner,cell,other,link,status=roles;x=before[:];memory=initial_memory(case)
    flags=0xB0000000;loads=[0]*4;stores=[0]*4;clears=0;calls=[];replacement=0
    failures=case.get('fail',(0,0,0,0));mismatch=False
    def store(phase,payload,destination,statusreg):
        stores[phase]+=1;failed=stores[phase]<=failures[phase]
        if failed and case.get('compete',(None,None))[0]==phase:memory[destination]=case['compete'][1]
        if not failed:memory[destination]=payload&MASK
        x[statusreg]=int(failed)
        return failed
    def call(callee,site):
        x[30]=CODE+site+4;calls.append((callee,x[0],x[30]))
        if callee==CALLEES[2]:memory[PRIMARY]=x[23]
        x[22]=(x[22]+1)&MASK
    def finish():
        x[29],x[30]=before[29],before[30]
        return dict(x=x,flags=flags,SP=STACK,loads=loads,stores=stores,source_clears=clears,
            injected_losses=sum(min(stores[i],failures[i]) for i in range(4)),replacement=replacement,
            calls=calls,primary=memory[PRIMARY],secondary=memory[SECONDARY],node=memory[NODE])
    for _ in range(100):
        x[owner]=memory[PRIMARY];loads[0]+=1
        if x[owner]&1:clears+=1;return finish()
        x[link]=memory[x[owner]]
        if x[link]:
            if store(0,x[link],PRIMARY,status):continue
        else:
            x[link]=x[owner]|1;replacement+=1
            while True:
                if case.get('mismatch_second') and not mismatch:memory[PRIMARY]=NODE|1;mismatch=True
                x[status]=memory[PRIMARY];loads[1]+=1;flags=cmp64(x[status],x[owner])
                if x[status]!=x[owner]:clears+=1;return finish()
                if not store(1,x[link],PRIMARY,status):break
            while True:
                x[link]=memory[SECONDARY];loads[2]+=1;flags=cmp64(x[link],x[owner])
                if x[link]!=x[owner]:
                    clears+=1
                    while True:
                        x[link]=memory[PRIMARY]&~1;loads[3]+=1
                        if not store(3,x[link],PRIMARY,status):return finish()
                if not store(2,0,SECONDARY,link):break
        if x[owner]==0:return finish()
        x[0]=(x[owner]+(0x28 if layout==0x68 else 0x10))&MASK;call(CALLEES[0],ENTRY+80)
        if layout==0x68:x[0]=(x[owner]+0x18)&MASK;call(CALLEES[1],ENTRY+88)
        x[0]=x[owner];call(CALLEES[2],ENTRY+layout-8)
    raise AssertionError('unbounded authored reference')

def execute(image,layout,roles,before,case):
    cpu=Uc(UC_ARCH_ARM64,UC_MODE_ARM)
    for address in (CODE,0x400000,0x500000,0x800000):cpu.mem_map(address,4096)
    cpu.mem_write(CODE,image);cells=bytearray([0xA5]*4096);nodes=bytearray([0x5A]*4096);stack=bytearray([0xC7]*4096)
    memory=initial_memory(case)
    struct.pack_into('<Q',cells,PRIMARY-0x400000,memory[PRIMARY]);struct.pack_into('<Q',cells,SECONDARY-0x400000,memory[SECONDARY])
    struct.pack_into('<Q',nodes,NODE-0x500000,memory[NODE])
    cpu.mem_write(0x400000,bytes(cells));cpu.mem_write(0x500000,bytes(nodes));cpu.mem_write(0x800000,bytes(stack))
    vectors=[int.from_bytes(bytes((index+lane)%256 for lane in range(16)),'little') for index in range(32)]
    for index,value in enumerate(before):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_X{index}'),value)
    for index,value in enumerate(vectors):cpu.reg_write(getattr(uc,f'UC_ARM64_REG_Q{index}'),value)
    cpu.reg_write(uc.UC_ARM64_REG_SP,STACK);cpu.reg_write(uc.UC_ARM64_REG_NZCV,0xB0000000)
    clear=ENTRY+layout;heads=(ENTRY,ENTRY+32,ENTRY+52,clear+12);stores_pc=(ENTRY+16,ENTRY+44,ENTRY+64,clear+20)
    for phase,pc in enumerate(stores_pc):
        at=0x800+phase*8;cpu.mem_write(CODE+at,raw((0xD5033F5F,ar.branch(CODE+at+4,CODE+pc))))
    result=dict(loads=[0]*4,stores=[0]*4,source_clears=0,injected_losses=0,replacement=0,calls=[])
    state=dict(active=None,detour=None,pending=None,mismatch=False,stopped=False)
    failures=case.get('fail',(0,0,0,0))
    def hook(machine,pc,size,_):
        at=pc-CODE
        if at==STOP:assert state['active'] is None;state['stopped']=True;machine.emu_stop();return
        if at in heads:
            phase=heads.index(at);result['loads'][phase]+=1
            if phase==1:
                if state['active']==0:result['replacement']+=1
                if case.get('mismatch_second') and not state['mismatch']:
                    machine.mem_write(PRIMARY,struct.pack('<Q',NODE|1));state['mismatch']=True
            state['active']=phase
        if at in stores_pc:
            phase=stores_pc.index(at)
            if state['detour']==at:state['detour']=None
            else:
                result['stores'][phase]+=1
                if result['stores'][phase]<=failures[phase]:
                    if case.get('compete',(None,None))[0]==phase:
                        machine.mem_write(SECONDARY if phase==2 else PRIMARY,struct.pack('<Q',case['compete'][1]))
                    state['detour']=at;machine.reg_write(uc.UC_ARM64_REG_PC,CODE+0x800+phase*8);return
            state['pending']=phase
        if state['pending'] is not None and at==stores_pc[state['pending']]+4:
            state['active']=None;state['pending']=None
        if at in (clear,clear+8):result['source_clears']+=1;state['active']=None
        if at in tuple(0x800+phase*8 for phase in range(4)):
            result['injected_losses']+=1;state['active']=None
        if at in CALLEES:
            assert state['active'] is None
            result['calls'].append((at,machine.reg_read(uc.UC_ARM64_REG_X0),machine.reg_read(uc.UC_ARM64_REG_X30)))
    cpu.hook_add(UC_HOOK_CODE,hook);cpu.emu_start(CODE,CODE+len(image),count=10000)
    assert state['stopped']
    result.update(x=[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_X{index}')) for index in range(31)],
        flags=cpu.reg_read(uc.UC_ARM64_REG_NZCV),SP=cpu.reg_read(uc.UC_ARM64_REG_SP),
        primary=struct.unpack('<Q',cpu.mem_read(PRIMARY,8))[0],secondary=struct.unpack('<Q',cpu.mem_read(SECONDARY,8))[0],node=struct.unpack('<Q',cpu.mem_read(NODE,8))[0])
    assert vectors==[cpu.reg_read(getattr(uc,f'UC_ARM64_REG_Q{index}')) for index in range(32)]
    struct.pack_into('<Q',cells,PRIMARY-0x400000,result['primary']);struct.pack_into('<Q',cells,SECONDARY-0x400000,result['secondary'])
    struct.pack_into('<QQ',stack,STACK-0x800000-16,before[29],before[30])
    assert bytes(cells)==bytes(cpu.mem_read(0x400000,4096));assert bytes(nodes)==bytes(cpu.mem_read(0x500000,4096));assert bytes(stack)==bytes(cpu.mem_read(0x800000,4096))
    return result

if __name__=='__main__':unittest.main()
