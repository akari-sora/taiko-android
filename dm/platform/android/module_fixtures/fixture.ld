ENTRY(fixture_entry)
SECTIONS {
    . = 0;
    .text : { *(.text) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
