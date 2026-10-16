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
.balign 4
.global service_list_users
.type service_list_users,%function
service_list_users:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#0]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_list_users,.-service_list_users
.balign 4
.global service_open_user
.type service_open_user,%function
service_open_user:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#8]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_open_user,.-service_open_user
.balign 4
.global service_user_id
.type service_user_id,%function
service_user_id:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#16]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_user_id,.-service_user_id
.balign 4
.global service_nickname
.type service_nickname,%function
service_nickname:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#24]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_nickname,.-service_nickname
.balign 4
.global service_ensure_network
.type service_ensure_network,%function
service_ensure_network:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#32]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_ensure_network,.-service_ensure_network
.balign 4
.global service_token
.type service_token,%function
service_token:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#40]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_token,.-service_token
.balign 4
.global service_account_event
.type service_account_event,%function
service_account_event:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#48]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_account_event,.-service_account_event
.balign 4
.global service_account_result
.type service_account_result,%function
service_account_result:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#56]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_account_result,.-service_account_result
.balign 4
.global service_auth_event
.type service_auth_event,%function
service_auth_event:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#64]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_auth_event,.-service_auth_event
.balign 4
.global service_auth_result
.type service_auth_result,%function
service_auth_result:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#72]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_auth_result,.-service_auth_result
.balign 4
.global service_auth_token
.type service_auth_token,%function
service_auth_token:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#80]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_auth_token,.-service_auth_token
.balign 4
.global service_friends_event
.type service_friends_event,%function
service_friends_event:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#88]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_friends_event,.-service_friends_event
.balign 4
.global service_friends_result
.type service_friends_result,%function
service_friends_result:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#96]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_friends_result,.-service_friends_result
.balign 4
.global service_friends_notify
.type service_friends_notify,%function
service_friends_notify:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#104]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_friends_notify,.-service_friends_notify
.balign 4
.global service_friends_invite
.type service_friends_invite,%function
service_friends_invite:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#112]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_friends_invite,.-service_friends_invite
.balign 4
.global service_aoc_count
.type service_aoc_count,%function
service_aoc_count:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#120]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_aoc_count,.-service_aoc_count
.balign 4
.global service_aoc_list
.type service_aoc_list,%function
service_aoc_list:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#128]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_aoc_list,.-service_aoc_list
.balign 4
.global service_aoc_event
.type service_aoc_event,%function
service_aoc_event:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#136]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_aoc_event,.-service_aoc_event
.balign 4
.global service_profanity
.type service_profanity,%function
service_profanity:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#144]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_profanity,.-service_profanity
.balign 4
.global service_sdk_time
.type service_sdk_time,%function
service_sdk_time:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#152]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_sdk_time,.-service_sdk_time
.balign 4
.global service_user_time
.type service_user_time,%function
service_user_time:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#160]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_user_time,.-service_user_time
.balign 4
.global service_time_now
.type service_time_now,%function
service_time_now:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#168]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_time_now,.-service_time_now
.balign 4
.global service_localtime
.type service_localtime,%function
service_localtime:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#176]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_localtime,.-service_localtime
.balign 4
.global service_calendar
.type service_calendar,%function
service_calendar:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#184]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_calendar,.-service_calendar
.balign 4
.global service_rom_cache_size
.type service_rom_cache_size,%function
service_rom_cache_size:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#192]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_rom_cache_size,.-service_rom_cache_size
.balign 4
.global service_mount_rom
.type service_mount_rom,%function
service_mount_rom:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#200]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_mount_rom,.-service_mount_rom
.balign 4
.global service_mount_temp
.type service_mount_temp,%function
service_mount_temp:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#208]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_mount_temp,.-service_mount_temp
.balign 4
.global service_ensure_save
.type service_ensure_save,%function
service_ensure_save:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#216]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_ensure_save,.-service_ensure_save
.balign 4
.global service_mount_save
.type service_mount_save,%function
service_mount_save:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#224]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_mount_save,.-service_mount_save
.balign 4
.global service_commit
.type service_commit,%function
service_commit:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#232]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_commit,.-service_commit
.balign 4
.global service_unmount
.type service_unmount,%function
service_unmount:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#240]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_unmount,.-service_unmount
.balign 4
.global service_open_file
.type service_open_file,%function
service_open_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#248]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_open_file,.-service_open_file
.balign 4
.global service_read_file
.type service_read_file,%function
service_read_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#256]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_read_file,.-service_read_file
.balign 4
.global service_write_file
.type service_write_file,%function
service_write_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#264]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_write_file,.-service_write_file
.balign 4
.global service_close_file
.type service_close_file,%function
service_close_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#272]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_close_file,.-service_close_file
.balign 4
.global service_create_file
.type service_create_file,%function
service_create_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#280]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_create_file,.-service_create_file
.balign 4
.global service_set_size
.type service_set_size,%function
service_set_size:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#288]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_set_size,.-service_set_size
.balign 4
.global service_get_size
.type service_get_size,%function
service_get_size:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#296]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_get_size,.-service_get_size
.balign 4
.global service_flush_file
.type service_flush_file,%function
service_flush_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#304]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_flush_file,.-service_flush_file
.balign 4
.global service_file_mode
.type service_file_mode,%function
service_file_mode:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#312]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_file_mode,.-service_file_mode
.balign 4
.global service_entry_type
.type service_entry_type,%function
service_entry_type:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#320]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_entry_type,.-service_entry_type
.balign 4
.global service_create_dir
.type service_create_dir,%function
service_create_dir:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#328]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_create_dir,.-service_create_dir
.balign 4
.global service_rename_file
.type service_rename_file,%function
service_rename_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#336]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_rename_file,.-service_rename_file
.balign 4
.global service_delete_file
.type service_delete_file,%function
service_delete_file:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#344]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_delete_file,.-service_delete_file
.balign 4
.global service_delete_dir
.type service_delete_dir,%function
service_delete_dir:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#352]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_delete_dir,.-service_delete_dir
.balign 4
.global service_open_dir
.type service_open_dir,%function
service_open_dir:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#360]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_open_dir,.-service_open_dir
.balign 4
.global service_read_dir
.type service_read_dir,%function
service_read_dir:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#368]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_read_dir,.-service_read_dir
.balign 4
.global service_close_dir
.type service_close_dir,%function
service_close_dir:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#376]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_close_dir,.-service_close_dir
.balign 4
.global service_audio_init
.type service_audio_init,%function
service_audio_init:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#384]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_init,.-service_audio_init
.balign 4
.global service_audio_open
.type service_audio_open,%function
service_audio_open:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#392]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_open,.-service_audio_open
.balign 4
.global service_audio_start
.type service_audio_start,%function
service_audio_start:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#400]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_start,.-service_audio_start
.balign 4
.global service_audio_stop
.type service_audio_stop,%function
service_audio_stop:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#408]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_stop,.-service_audio_stop
.balign 4
.global service_audio_close
.type service_audio_close,%function
service_audio_close:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#416]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_close,.-service_audio_close
.balign 4
.global service_audio_state
.type service_audio_state,%function
service_audio_state:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#424]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_state,.-service_audio_state
.balign 4
.global service_audio_rate
.type service_audio_rate,%function
service_audio_rate:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#432]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_rate,.-service_audio_rate
.balign 4
.global service_audio_channels
.type service_audio_channels,%function
service_audio_channels:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#440]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_channels,.-service_audio_channels
.balign 4
.global service_audio_format
.type service_audio_format,%function
service_audio_format:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#448]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_format,.-service_audio_format
.balign 4
.global service_audio_set_buffer
.type service_audio_set_buffer,%function
service_audio_set_buffer:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#456]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_set_buffer,.-service_audio_set_buffer
.balign 4
.global service_audio_buffer_pointer
.type service_audio_buffer_pointer,%function
service_audio_buffer_pointer:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#464]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_buffer_pointer,.-service_audio_buffer_pointer
.balign 4
.global service_audio_buffer_size
.type service_audio_buffer_size,%function
service_audio_buffer_size:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#472]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_buffer_size,.-service_audio_buffer_size
.balign 4
.global service_audio_append
.type service_audio_append,%function
service_audio_append:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#480]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_append,.-service_audio_append
.balign 4
.global service_audio_released
.type service_audio_released,%function
service_audio_released:
stp x29,x30,[sp,#-16]!
mov x10,x0
adrp x9,0x10000
ldr x9,[x9,#488]
ldp x0,x1,[x10]
ldp x2,x3,[x10,#16]
ldp x4,x5,[x10,#32]
ldp x6,x7,[x10,#48]
blr x9
ldp x29,x30,[sp],#16
ret
.size service_audio_released,.-service_audio_released
.global service_wait
.type service_wait,%function
service_wait:
mov x9,x0
ldp x0,x1,[x9]
ldp x2,x3,[x9,#16]
svc #24
ret
.size service_wait,.-service_wait
.global service_close_handle
.type service_close_handle,%function
service_close_handle:
mov x9,x0
ldp x0,x1,[x9]
ldp x2,x3,[x9,#16]
svc #22
ret
.size service_close_handle,.-service_close_handle
.global service_signal
.type service_signal,%function
service_signal:
mov x9,x0
ldp x0,x1,[x9]
ldp x2,x3,[x9,#16]
svc #17
ret
.size service_signal,.-service_signal
.global service_query_memory
.type service_query_memory,%function
service_query_memory:
mov x9,x0
ldp x0,x1,[x9]
ldp x2,x3,[x9,#16]
svc #6
ret
.size service_query_memory,.-service_query_memory
.global service_clear_event
.type service_clear_event,%function
service_clear_event:
mov x9,x0
ldp x0,x1,[x9]
ldp x2,x3,[x9,#16]
svc #18
ret
.size service_clear_event,.-service_clear_event
.org 0x1000
