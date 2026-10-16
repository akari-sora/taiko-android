.text
.global fixture_entry
.type fixture_entry,%function
fixture_entry: ret
.size fixture_entry,.-fixture_entry
.word 0x40
.org 0x40
.ascii "MOD0"
.word 0x10400-0x40,0x14000-0x40,0x15000-0x40,0,0,0x10300-0x40
.org 0x100
.global fixture_init
.type fixture_init,%function
fixture_init: ret
.size fixture_init,.-fixture_init
.global _ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb
.type _ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb,%function
_ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb:
stp x19,x30,[sp,#-16]!
mov x19,x0
svc #0x45
cbnz w0,1f
stp w1,w2,[x19]
1: ldp x19,x30,[sp],#16
ret
.size _ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb,.-_ZN2nn2os17CreateSystemEventEPNS0_15SystemEventTypeENS0_14EventClearModeEb
.global _ZN2nn2os30GetWritableHandleOfSystemEventEPKNS0_15SystemEventTypeE
.type _ZN2nn2os30GetWritableHandleOfSystemEventEPKNS0_15SystemEventTypeE,%function
_ZN2nn2os30GetWritableHandleOfSystemEventEPKNS0_15SystemEventTypeE:
ldr w0,[x0]
ret
.size _ZN2nn2os30GetWritableHandleOfSystemEventEPKNS0_15SystemEventTypeE,.-_ZN2nn2os30GetWritableHandleOfSystemEventEPKNS0_15SystemEventTypeE
.global time
.type time,%function
time:
mov x1,#0x3456
cbz x0,1f
str x1,[x0]
1: mov x0,x1
ret
.size time,.-time
.org 0x1000
