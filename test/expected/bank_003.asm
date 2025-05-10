; Disassembly of "test.gb"
; This file was created with:
; mgbdis v3.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $003", ROMX[$4000], BANK[$3]

Init::
    ldh a, [rLY]
    cp $90
    jr nz, Init

    ld a, [$ff40]
    res 7, a
    ld [$ff40], a
    xor a
    ldh [rSCX], a
    ldh [rSCY], a
    ld hl, OldSkoolOutlineThick
    ld de, $8000
    ld bc, $0800
    call MemCopy
    ld hl, $9800
    ld bc, OldSkoolOutlineThick
    xor a
    call MemSet
    ld hl, Heading
    ld de, $9800
    ld bc, $000f
    call MemCopy
    ld hl, Separator
    ld de, $9820
    ld bc, $000f
    call MemCopy
    ld hl, HelloWorld
    ld de, $9860
    ld bc, $000c
    call MemCopy
    ld hl, Konami
    ld de, $9880
    ld bc, $000a
    call MemCopy
    ld hl, Smile
    ld de, $98a0
    ld bc, $0002
    call MemCopy
    ld hl, SaveStates
    ld de, $98c0
    ld bc, $000a
    call MemCopy
    ld hl, Abba
    ld de, $98e0
    ld bc, $0006
    call MemCopy
    ld hl, Escaped
    ld de, $9900
    ld bc, $0007
    call MemCopy
    ld hl, TheEnd
    ld de, $9920
    ld bc, $0007
    call MemCopy
    ld c, $47
    ldh a, [c]
    ld a, $e4
    ldh [c], a
    ld hl, $ff40
    set 7, [hl]
    ret

