; Disassembly of "test.gb"
; This file was created with:
; mgbdis v3.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $000", ROM0[$0]

RST_00::
; $08 times 0x00
    ds $0008 - @, 0x00

RST_08::
; $08 times 0x00
    ds $0010 - @, 0x00

RST_10::
; $08 times 0x00
    ds $0018 - @, 0x00

RST_18::
; $08 times 0x00
    ds $0020 - @, 0x00

RST_20::
; $08 times 0x00
    ds $0028 - @, 0x00

RST_28::
; $08 times 0x00
    ds $0030 - @, 0x00

RST_30::
; $08 times 0x00
    ds $0038 - @, 0x00

RST_38::
; $08 times 0x00
    ds $0040 - @, 0x00

VBlankInterrupt::
; $08 times 0x00
    ds $0048 - @, 0x00

LCDCInterrupt::
; $08 times 0x00
    ds $0050 - @, 0x00

TimerOverflowInterrupt::
; $08 times 0x00
    ds $0058 - @, 0x00

SerialTransferCompleteInterrupt::
; $08 times 0x00
    ds $0060 - @, 0x00

JoypadTransitionInterrupt::
; $08 times 0x00
    ds $0068 - @, 0x00

; $98 times 0x00
    ds $0100 - @, 0x00

Boot::
    nop
    jp Main


HeaderLogo::
    db $ce, $ed, $66, $66, $cc, $0d, $00, $0b, $03, $73, $00, $83, $00, $0c, $00, $0d
    db $00, $08, $11, $1f, $88, $89, $00, $0e, $dc, $cc, $6e, $e6, $dd, $dd, $d9, $99
    db $bb, $bb, $67, $63, $6e, $0e, $ec, $cc, $dd, $dc, $99, $9f, $bb, $b9, $33, $3e

HeaderTitle::
    db "mgbdis test", $00, $00, $00, $00, $00

HeaderNewLicenseeCode::
    db $00, $00

HeaderSGBFlag::
    db $00

HeaderCartridgeType::
    db $01

HeaderROMSize::
    db $01

HeaderRAMSize::
    db $00

HeaderDestinationCode::
    db $00

HeaderOldLicenseeCode::
    db $00

HeaderMaskROMVersion::
    db $00

HeaderComplementCheck::
    db $8f

HeaderGlobalChecksum::
    db $18, $46

Main::
    di
    ld sp, $d000
    ld a, $03
    ld [$2000], a
    call $4000

Main.forever::
    halt
    nop
    jr Main.forever

    stop
    db $10
    ld l, c
; $9c times 0x00
    ds $0200 - @, 0x00

MemCopy::
    ld a, [hl+]
    ld [de], a
    inc de
    dec bc
    ld a, b
    or c
    jr nz, MemCopy

    ret


MemSet::
    ld d, a

MemSet.loop::
    ld [hl+], a
    dec bc
    ld a, b
    or c
    ld a, d
    jr nz, MemSet.loop

    ret


; $ee times 0x00
    ds $0300 - @, 0x00

Heading::
    db "mgbdis test rom"

Separator::
    db "---------------"

HelloWorld::
    db "Hello World!"

SETCHARMAP cmap

Konami::
    db "<up><up><down><down><left><right><left><right>ba"

Smile::
    db "<smiley>"

SaveStates::
    db "<supports save states>"

Abba::
    db "abba abc"

SETCHARMAP main

Escaped::
    db "\\\{\}/\"_\""

TheEnd::
    db "The End"

; $ac times 0x00
    ds $0400 - @, 0x00

OldSkoolOutlineThick::
    INCBIN "gfx/OldSkoolOutlineThick.2bpp"
