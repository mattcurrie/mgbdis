INCLUDE "../hardware.inc"
INCLUDE "src/charmap.asm"
SETCHARMAP main

MACRO copy_to_map
    ld hl, \1
    ld de, _SCRN0 + \2 + SCRN_VX_B * \3 
    ld bc, \1.end - \1
    call MemCopy
ENDM


SECTION "boot", ROM0[$100]
    nop
    jp Main


SECTION "title", ROM0[$134]
    db "mgbdis test", $00


SECTION "cart compat", ROM0[$143]
    db CART_COMPATIBLE_DMG


SECTION "cart type", ROM0[$147]
    db CART_ROM_MBC1


SECTION "cart size", ROM0[$148]
    db CART_ROM_64KB


SECTION "main", ROM0[$150]
Main::
    di
    ld sp, $d000

    ld a, bank(Init)
    ld [rROMB0], a
    call Init

.forever
    halt
    nop
    jr .forever

    stop
    db $10, $69


SECTION "lib", ROM0[$200]
MemCopy::
.loop:
    ld a, [hl+]
    ld [de], a
    inc de

    dec bc
    ld a, b
    or c
    jr nz, .loop

    ret

MemSet::
    ld d, a

.loop:
    ld [hl+], a
    dec bc   
    ld a, b
    or c
    ld a, d
    jr nz, .loop

    ret
    

SECTION "text", ROM0[$300]

Header::
    db "mgbdis test rom"
.end::

Separator::
    db "---------------"
.end

HelloWorld::
    db "Hello World!"
.end::
   
PUSHC cmap
Konami::
    db "<up><up><down><down><left><right><left><right>ba"
.end

Smile::
    db "<smiley>"
.end

SaveStates::
    db "<supports save states>"
.end
POPC

Escaped::
    db "\\\{\}/\"_\""
.end

TheEnd::
    db "The End"
.end

ENDSECTION


SECTION "font", ROM0[$400]
INCLUDE "src/font.asm"
   

SECTION "init", ROMX, BANK[3]
Init::

.wait_vbl:
    ldh a, [rLY]
    cp $90
    jr nz, .wait_vbl

    ld a, [rLCDC]
    res LCDCB_ON, a
    ld [rLCDC],a 

    xor a
    ldh [rSCX], a 
    ldh [rSCY], a 

    ld hl, OldSkoolOutlineThick
    ld de, _VRAM
    ld bc, OldSkoolOutlineThick.end - OldSkoolOutlineThick
    call MemCopy

    ld hl, _SCRN0
    ld bc, SCRN_VX_B * SCRN_VY_B
    xor a
    call MemSet

    copy_to_map Header, 0, 0
    copy_to_map Separator, 0, 1
    copy_to_map HelloWorld, 0, 3
    copy_to_map Konami, 0, 4
    copy_to_map Smile, 0, 5
    copy_to_map SaveStates, 0, 6
    copy_to_map Escaped, 0, 7
    copy_to_map TheEnd, 0, 8

    ld c, low(rBGP)
    ldh a, [c]
    ld a, $e4
    ldh [c], a

    ld hl, rLCDC
    set LCDCB_ON, [hl]

    ret 
