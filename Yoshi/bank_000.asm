; Disassembly of "yoshi.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $000", ROM0[$0]

RST_00::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

RST_08::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

RST_10::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

RST_18::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

RST_20::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

RST_28::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

RST_30::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

RST_38::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

VBlankInterrupt::
    jp $4b59


    nop
    nop
    nop
    nop
    nop

LCDCInterrupt::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

TimerOverflowInterrupt::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

SerialTransferCompleteInterrupt::
    jp SerialHandler


    nop
    nop
    nop
    nop
    nop

JoypadTransitionInterrupt::
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop

PositionTable::
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $00, $00, $39, $00, $39, $00, $39, $00, $39
    db $00, $39, $00, $39, $00, $39, $00, $39

EntryPoint::
    nop
    jp Init


HeaderLogo::
    db $ce, $ed, $66, $66, $cc, $0d, $00, $0b, $03, $73, $00, $83, $00, $0c, $00, $0d
    db $00, $08, $11, $1f, $88, $89, $00, $0e, $dc, $cc, $6e, $e6, $dd, $dd, $d9, $99
    db $bb, $bb, $67, $63, $6e, $0e, $ec, $cc, $dd, $dc, $99, $9f, $bb, $b9, $33, $3e

HeaderTitle::
    db "YOSSY NO TAMAGO", $00

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
    db $01

HeaderMaskROMVersion::
    db $00

HeaderComplementCheck::
    db $a7

HeaderGlobalChecksum::
    db $97, $a1

ReadJoypad::
    ld a, $20
    ld c, $00
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]

ReadJoypadButtons::
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    cpl
    and $0f
    swap a
    ld b, a
    ld a, $10
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    cpl
    and $0f
    or b
    ld b, a
    ldh a, [JOYPAD_HELD]
    ld e, a
    xor b
    ld d, a
    and e
    ldh [JOYPAD_RAW], a
    ld a, d
    and b
    ldh [JOYPAD_PRESSED], a
    ld a, $30
    ldh [rP1], a
    ld a, b
    ldh [JOYPAD_HELD], a
    and $0f
    cp $0f
    ret nz

Jump_000_019d:
    xor a
    ldh [JOYPAD_HELD], a

jr_000_01a0:
    ld a, $30
    ldh [rP1], a
    ld b, a
    ld a, $10
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]

JoypadStuckCheck::
    and $0f
    jr z, jr_000_01a0

    jp Init


SetupOAMDMA::
    ld c, $80
    ld b, $0a
    ld hl, OAMDMARoutine

Jump_000_01c1:
jr_000_01c1:
    ld a, [hl+]
    ldh [c], a

OAMDMACopyLoop::
    inc c
    dec b
    jr nz, jr_000_01c1

    ret


OAMDMARoutine::
    db $3e, $c4, $e0, $46, $3e, $28, $3d, $20, $fd, $c9

LCDOff::
    ldh a, [rIE]
    ld b, a
    res 0, a
    ldh [rIE], a

jr_000_01d9:
    ldh a, [rLY]
    cp $91
    jr nz, jr_000_01d9

    ldh a, [rLCDC]
    and $7f

Jump_000_01e3:
    ldh [rLCDC], a
    ld a, b
    ldh [rIE], a
    ret


LCDOn::
    ldh a, [rLCDC]
    set 7, a
    ldh [rLCDC], a
    ret


ClearOAM::
    xor a
    ld hl, $c400
    ld b, $a0

jr_000_01f6:
    ld [hl+], a
    dec b
    jr nz, jr_000_01f6

    ret


HideAllSprites::
    ld a, $a0
    ld hl, $c400
    ld de, $0004
    ld b, $28

jr_000_0205:
    ld [hl], a
    add hl, de
    dec b
    jr nz, jr_000_0205

    ret


Memcopy::
    ld a, [hl+]
    ld [de], a
    inc de
    dec bc
    ld a, b
    or c
    jr nz, Memcopy

    ret


MemcopyCall::
    call Memcopy
    ret


jr_000_0218:
    ld a, [hl+]
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec bc
    ld a, c
    or b
    jr nz, jr_000_0218

    ret


VRAMCopySetup::
    ld a, e
    ldh [$ffaf], a
    ld a, d
    ldh [$ffb0], a
    ld a, l
    ldh [$ffb1], a
    ld a, h
    ldh [$ffb2], a

jr_000_022f:
    ld a, c

VRAMCopyExec::
    cp $08
    jr nc, jr_000_023a

    ldh [$ffae], a
    call $4bc5
    ret


jr_000_023a:
    ld a, $08
    ldh [$ffae], a
    call $4bc5
    ld a, c
    sub $08
    ld c, a
    jr jr_000_022f

    ld a, e
    ldh [$ffb4], a
    ld a, d
    ldh [$ffb5], a
    ld a, l
    ldh [$ffb6], a
    ld a, h
    ldh [$ffb7], a

jr_000_0253:
    ld a, c
    cp $08
    jr nc, jr_000_025e

    ldh [$ffb3], a
    call $4bc5
    ret


jr_000_025e:
    ld a, $08
    ldh [$ffb3], a
    call $4bc5
    ld a, c
    sub $08
    ld c, a
    jr jr_000_0253

StateInit::
    xor a
    ldh [GAME_STATE], a
    ld a, $af
    ldh [rLCDC], a
    ld a, $01
    ld [GAME_ACTIVE], a

MainLoop::
    call $4bc5
    call ReadJoypad
    ldh a, [GAME_STATE]
    and a
    jr nz, jr_000_02cb

    call LCDOff
    ld a, $02
    ld [$2100], a
    ld hl, $4000
    ld de, $8000
    ld bc, $0800
    call MemcopyCall
    ld hl, $6000
    ld de, $8800
    ld bc, $1000
    call MemcopyCall
    ld a, $01
    ld [$2100], a
    call LCDOn
    ld hl, $c7a9
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld a, $30
    call PlaySound
    call $4094
    call FillOAMTitleTile
    call $437d
    call InitTitleUI
    ld a, $01
    ld [LCD_REDRAW], a
    jp AdvanceState


jr_000_02cb:
    dec a
    jr nz, jr_000_02d3

    call InitGameVars
    jr MainLoop

jr_000_02d3:
    dec a
    jr nz, jr_000_0302

    call LCDOff
    ld a, $01
    ld [LCD_REDRAW], a
    call LoadGameTiles
    call LCDOn
    call FillOAMGameTile
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_02f2

    call ApplyGameSettings
    jr jr_000_02f8

jr_000_02f2:
    ld a, [BGM_INDEX]
    call PlaySound

jr_000_02f8:
    call $450b
    ld a, $01
    ld [LCD_REDRAW], a
    jr AdvanceState

jr_000_0302:
    dec a
    jr nz, jr_000_030e

    call HandlePause
    call $43ac
    jp MainLoop


jr_000_030e:
    dec a
    jr nz, jr_000_0317

    call HandleRoundEnd
    jp MainLoop


jr_000_0317:
    dec a
    jr nz, jr_000_0320

    call OptionsScreen
    jp MainLoop


jr_000_0320:
    dec a
    jr nz, jr_000_0352

    call LCDOff
    ld a, $02
    ld [$2100], a
    ld hl, $4800
    ld de, $8800
    ld bc, $1000
    call MemcopyCall
    ld hl, $5800
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ld a, $01
    ld [$2100], a
    call StartGameplay
    call LCDOn
    ld a, $05
    jr jr_000_0358

jr_000_0352:
    jp MainLoop


AdvanceState::
    ldh a, [GAME_STATE]
    inc a

jr_000_0358:
    ldh [GAME_STATE], a
    jp MainLoop


LoadGameTiles::
    ld a, $02
    ld [$2100], a
    ld hl, $4800
    ld de, $8800
    ld bc, $1000
    call MemcopyCall
    ld hl, $4000
    ld de, $8000
    ld bc, $0800
    call MemcopyCall
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_039f

    ld hl, $71d0
    ld de, $9500
    ld bc, $0200
    call MemcopyCall
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_039f

    ld hl, $6f70
    ld de, $81c0
    ld bc, $0260
    call MemcopyCall

jr_000_039f:
    ld a, $01
    ld [$2100], a
    ret


HandlePause::
    ld hl, TWO_PLAYER_FLAG
    xor a
    cp [hl]
    jr z, jr_000_03b5

    ld hl, LINK_ROLE
    ld a, $01

Jump_000_03b1:
    cp [hl]
    jr z, jr_000_03b5

    ret


jr_000_03b5:
    ldh a, [JOYPAD_PRESSED]
    and $08
    ret z

    call PauseGame

jr_000_03bd:
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and $08
    jr z, jr_000_03bd

    call UnpauseGame
    ret


PauseGame::
    ld a, $01
    ld [PAUSE_FLAG], a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_000_03da

    ld a, $01
    ld [$c002], a

jr_000_03da:
    ld a, $2e
    call PlaySound
    xor a
    ld [LCD_REDRAW], a
    db $76

DrawPauseOverlay::
    ld hl, PauseSpriteData
    ld de, $c400
    ld bc, $0020
    call MemcopyCall
    ret


UnpauseGame::
    ld a, $01
    ld [LCD_REDRAW], a
    xor a
    ld [$c002], a
    ld [PAUSE_FLAG], a
    ret


CheckPause2P::
    ld a, [PAUSE_FLAG]
    and a
    ret z

    ld a, [TWO_PLAYER_FLAG]
    and a
    ret z

    ld a, [LINK_ROLE]
    cp $01
    ret z

    call PauseGame

jr_000_0411:
    call $4bc5
    call DrawPauseOverlay
    ld a, [LINK_RECV]
    cp $f0
    jr z, jr_000_0411

    jp UnpauseGame


PauseSpriteData::
    db $50, $28, $44, $10, $50, $30, $46, $10, $50, $38, $48, $10, $50, $40, $4a, $10
    db $50, $48, $78, $10, $50, $50, $7a, $10, $50, $58, $7c, $10, $50, $60, $7e, $10

Init::
    di
    ld a, $01
    ld [$2100], a
    xor a
    ldh [rIF], a
    ldh [rIE], a
    xor a
    ldh [rSCX], a
    ldh [rSCY], a
    ldh [rSB], a
    ldh [rSC], a
    ldh [rWX], a
    ldh [rWY], a
    ldh [rTMA], a
    ldh [rTAC], a
    ld a, $80
    ldh [rLCDC], a
    call LCDOff
    ld a, $e4
    ldh [rBGP], a
    ld a, $e4
    ldh [rOBP0], a
    ld a, $d0
    ldh [rOBP1], a
    ld sp, $dfff
    ld hl, $c757
    ld a, [hl+]
    cp $c7
    jr nz, jr_000_048e

    ld a, [hl+]
    cp $8a

Jump_000_047e:
    jr nz, jr_000_048e

    ld a, [hl+]
    cp $29
    jr nz, jr_000_048e

    ld a, [hl+]
    cp $36
    jr nz, jr_000_048e

    ld d, $00
    jr jr_000_0490

jr_000_048e:
    ld d, $01

jr_000_0490:
    xor a
    ld hl, $c000
    ld bc, $2000

jr_000_0497:
    cp d
    jr nz, jr_000_04a7

    ld a, $c7
    cp h
    jr nz, jr_000_04a7

    ld a, $09
    cp l
    jr nz, jr_000_04a7

    ld hl, $c75b

jr_000_04a7:
    xor a
    ld [hl+], a
    dec c
    jr nz, jr_000_0497

    dec b
    jr nz, jr_000_0497

    ld hl, $c757
    ld a, $c7
    ld [hl+], a
    ld a, $8a
    ld [hl+], a
    ld a, $29
    ld [hl+], a
    ld a, $36
    ld [hl], a
    xor a
    ld hl, $8000

ClearVRAM::
    ld bc, $2000

jr_000_04c5:
    ld [hl+], a
    dec c
    jr nz, jr_000_04c5

    dec b
    jr nz, jr_000_04c5

    ld b, $7f
    ld hl, $ff80

jr_000_04d1:
    ld [hl+], a
    dec b
    jr nz, jr_000_04d1

    call ClearOAM
    call SetupOAMDMA
    xor a
    ldh [rSTAT], a
    ldh [rIF], a
    ldh [SCX_SHADOW], a
    ldh [$ff9d], a
    ld a, $0d
    ldh [rIE], a
    ld a, $90
    ldh [$ff9e], a
    ldh [rWY], a
    ld a, $07
    ldh [rWX], a
    ld h, $98
    call FillTilemap
    ld h, $9c
    call FillTilemap

StartGame::
    ld a, $e3
    ldh [rLCDC], a
    ld a, $ff
    call PlaySound
    xor a
    ld [WAVE_UPDATE], a
    ei
    jp StateInit


FillOAMGameTile::
    ld a, $4a
    jr jr_000_0513

FillOAMTitleTile::
    ld a, $e0

jr_000_0513:
    ld bc, $0168
    inc b
    ld hl, $c4a0

jr_000_051a:
    ld [hl+], a
    dec c
    jr nz, jr_000_051a

    dec b
    jr nz, jr_000_051a

    ret


    xor a
    srl h
    rr a
    srl h
    rr a
    srl h
    rr a
    or l
    ld l, a
    ld a, b
    or h
    ld h, a
    ret


CalcOAMAddress::
    ld a, h
    sla a
    sla a
    add h
    sla a
    sla a
    ld h, $c4
    jr nc, jr_000_0544

    inc h

jr_000_0544:
    add l
    jr nc, jr_000_0548

    inc h

jr_000_0548:
    add $a0
    jr nc, jr_000_054d

    inc h

jr_000_054d:
    ld l, a
    ret


FillTilemap::
    ld a, $4a
    jr jr_000_0554

    ld a, l

jr_000_0554:
    ld de, $0400
    ld l, e

jr_000_0558:
    ld [hl+], a
    dec e
    jr nz, jr_000_0558

    dec d
    jr nz, jr_000_0558

    ret


PlaySound::
    push hl
    push de
    push bc
    call $53c9
    pop bc
    pop de
    pop hl
    ret


Multiply::
    push bc
    push de
    push hl
    ld bc, $0343
    ld a, $fd
    ldh [$ffc3], a
    ld hl, $ffbf
    ld [hl], $00
    inc hl
    ld [hl], $26
    inc hl
    ld [hl], $9e
    inc hl
    ld [hl], $c3

jr_000_0582:
    ld hl, $ffc3
    srl b
    rr c
    rr [hl]
    jr c, jr_000_05a6

    jr nz, jr_000_05bb

    ld hl, $ffbf
    ld de, $ffbb
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld b, a
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    ld a, b
    pop hl
    pop de
    pop bc
    ret


jr_000_05a6:
    ld hl, $ffc2
    ld de, $ffbe
    ld a, [de]
    dec de
    add [hl]
    ld [hl-], a

MultiplyAddStep::
    ld a, [de]

Jump_000_05b1:
    dec de
    adc [hl]
    ld [hl-], a
    ld a, [de]
    dec de
    adc [hl]
    ld [hl-], a
    ld a, [de]
    adc [hl]
    ld [hl], a

jr_000_05bb:
    ld hl, $ffbe
    sla [hl]
    dec hl
    rl [hl]
    dec hl
    rl [hl]
    dec hl
    rl [hl]
    jr jr_000_0582

MultiplyAndCount::
    call Multiply
    and c
    ld c, $00

jr_000_05d1:
    sla a
    jr nc, jr_000_05d6

    inc c

jr_000_05d6:
    jr nz, jr_000_05d1

    ld a, c
    ret


UpdateSpriteObject::
    ld [$c68b], a
    inc a
    sla a
    sla a
    sla a
    sla a
    ld l, a
    ld h, $c2
    ld a, l
    ld [$ff96], a
    ld de, $c68c
    ld bc, $000a
    call MemcopyCall
    ld a, [$c694]
    and a
    ret z

    cp $01
    jr z, jr_000_0606

    call UpdateMatchState
    and a
    ret z

    jr jr_000_0617

jr_000_0606:
    ld hl, $c693
    dec [hl]
    jr nz, jr_000_0617

    ld a, [$c66e]
    ld [$c693], a
    ld a, $02
    ld [$c694], a

jr_000_0617:
    ld hl, $c68c
    ld d, $c2
    ld a, [$ff96]
    ld e, a
    ld bc, $000a
    call MemcopyCall
    ret


GetSpriteDataOffset1::
    sla a
    sla a
    ld e, a
    sla a
    add e
    ld de, SpritePatternTable2
    add e
    ld e, a
    ret nc

    inc d
    ret


GetSpriteDataOffset2::
    sla a
    sla a
    sla a
    ld de, SpritePatternTable1
    add e
    ld e, a
    ret nc

    inc d
    ret


CopySprite4Bytes::
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, [de]
    inc de
    ld [hl], a
    ret


CopySprite4BytesCond::
    ld a, [de]
    inc de
    inc a
    jr z, jr_000_0658

    ld [hl], a

jr_000_0658:
    inc hl
    ld a, [de]
    inc de
    inc a
    jr z, jr_000_065f

    ld [hl], a

jr_000_065f:
    inc hl
    ld a, [de]
    inc de
    inc a
    jr z, jr_000_0666

    ld [hl], a

jr_000_0666:
    inc hl
    ld a, [de]
    inc de
    inc a
    jr z, jr_000_066d

    ld [hl], a

jr_000_066d:
    ret


DrawColumnSprite::
    push af
    ld a, $04
    sub b
    ld c, a
    ld l, a
    sla l
    sla l
    ld de, $c66a
    add e
    ld e, a
    jr nc, jr_000_0680

    inc d

jr_000_0680:
    ld a, [de]
    ld h, a
    dec h
    dec h
    dec h
    ld a, c
    call GetSpriteDataOffset1
    call CalcOAMAddress
    pop af
    dec a
    jr nz, jr_000_06b9

    ld a, $30
    add e
    ld e, a
    jr nc, jr_000_06b9

    inc d
    jr jr_000_06b9

    push af
    ld a, h
    cp $ff
    jr z, jr_000_06a8

    call CalcOAMAddress
    pop af
    call GetSpriteDataOffset1
    jr jr_000_06b9

jr_000_06a8:
    inc h
    call CalcOAMAddress
    pop af
    call GetSpriteDataOffset1
    ld a, $04
    add e
    ld e, a
    jr nc, jr_000_06b7

    inc d

jr_000_06b7:
    jr jr_000_06c3

jr_000_06b9:
    call CopySprite4BytesCond
    ld a, $11
    add l
    ld l, a
    jr nc, jr_000_06c3

    inc h

jr_000_06c3:
    call CopySprite4BytesCond
    ld a, $11
    add l
    ld l, a
    jr nc, jr_000_06cd

    inc h

jr_000_06cd:
    call CopySprite4BytesCond
    ret


DrawGridPiece::
    push af
    ld a, h
    cp $20
    jr c, jr_000_06d9

    pop af
    ret


jr_000_06d9:
    pop af
    call GetSpriteDataOffset2
    call CalcOAMAddress
    call CopySprite4Bytes
    ld a, $11
    add l
    ld l, a
    jr nc, jr_000_06ea

    inc h

jr_000_06ea:
    call CopySprite4Bytes
    ret


ClearColumnLeft::
    push hl
    push bc
    ld b, a
    dec l
    call CalcOAMAddress

jr_000_06f5:
    ld [hl], $4a
    dec b
    jr z, jr_000_0703

    ld a, l
    add $14
    ld l, a
    jr nc, jr_000_06f5

Call_000_0700:
Jump_000_0700:
    inc h
    jr jr_000_06f5

jr_000_0703:
    pop bc
    pop hl
    ret


ClearColumnRight::
    push hl
    push bc
    ld b, a
    inc l
    inc l
    inc l
    inc l
    call CalcOAMAddress

jr_000_0710:
    ld [hl], $4a
    dec b
    jr z, jr_000_071e

    ld a, l
    add $14
    ld l, a
    jr nc, jr_000_0710

    inc h
    jr jr_000_0710

jr_000_071e:
    pop bc
    pop hl
    ret


DrawAllColumns::
    ld l, $00
    ld de, $c62b
    ld c, $04

jr_000_0728:
    ld b, $07
    ld h, $02

jr_000_072c:
    ld a, [de]
    inc de
    inc de
    push de
    push hl
    call DrawGridPiece
    pop hl
    pop de
    inc h
    inc h
    dec b
    jr nz, jr_000_072c

    ld a, e
    add $02
    ld e, a
    jr nc, jr_000_0742

    inc d

jr_000_0742:
    inc l
    inc l
    inc l
    inc l
    dec c
    jr nz, jr_000_0728

    ret


AnimateDropping::
    ld a, [$c75d]
    and a
    ret z

    ld hl, $c75e
    dec [hl]
    ret nz

    ld [hl], $02
    ld hl, $c764
    ld de, $c637
    ld a, [$c761]
    inc a
    swap a
    add e
    ld e, a
    jr nc, jr_000_0767

    inc d

jr_000_0767:
    ld b, $07

Jump_000_0769:
    ld a, [hl]
    and a
    jp z, Jump_000_0790

    push de
    push hl
    push bc
    call AnimateDropDown
    pop bc
    pop hl
    pop de
    inc [hl]
    ld a, [hl]
    cp $03
    jr nz, jr_000_078a

    ld a, b
    cp $02
    jr c, jr_000_0790

    inc hl
    inc hl
    ld [hl], $01
    dec hl
    dec hl
    jr jr_000_0790

jr_000_078a:
    cp $05
    jr nz, jr_000_0790

    ld [hl], $00

Jump_000_0790:
jr_000_0790:
    dec de
    dec de
    inc hl
    inc hl
    dec b
    jp nz, Jump_000_0769

    ld hl, $c774
    ld de, $c637
    ld a, [$c761]
    swap a
    add e
    ld e, a
    jr nc, jr_000_07a8

    inc d

jr_000_07a8:
    ld b, $07

Jump_000_07aa:
    ld a, [hl]
    and a
    jp z, Jump_000_07d5

    push de
    push hl
    push bc
    call AnimateDropUp
    pop bc
    pop hl
    pop de
    inc [hl]
    ld a, [hl]
    cp $03
    jr nz, jr_000_07cb

    ld a, b
    cp $02
    jr c, jr_000_07d5

    inc hl
    inc hl
    ld [hl], $01
    dec hl
    dec hl
    jr jr_000_07d5

jr_000_07cb:
    cp $05
    jr nz, jr_000_07d5

    ld [hl], $00
    ld a, b
    dec a
    jr z, jr_000_07de

Jump_000_07d5:
jr_000_07d5:
    dec de
    dec de
    inc hl
    inc hl
    dec b
    jp nz, Jump_000_07aa

    ret


jr_000_07de:
    call UpdateDropPositions
    ld h, d
    ld a, e
    add $10
    ld l, a
    jr nc, jr_000_07e9

    inc h

jr_000_07e9:
    ld b, $07

jr_000_07eb:
    ld c, [hl]
    ld a, [de]
    ld [hl], a
    ld a, c
    ld [de], a
    inc hl
    inc hl
    inc de
    inc de
    dec b
    jr nz, jr_000_07eb

    ld hl, $c66a
    ld a, [$c761]
    add l
    ld l, a
    jr nc, jr_000_0802

    inc h

jr_000_0802:
    ld a, [hl+]
    ld b, [hl]
    ld [hl-], a
    ld [hl], b
    xor a
    ld [$c75d], a
    ret


CheckCollisionDown::
    dec bc
    ld a, [$c761]
    inc a
    call CheckCollisionCore
    ret nc

    inc l
    ld a, [hl]
    sub $08
    ld [hl], a
    scf
    ret


CheckCollisionUp::
    inc bc
    ld a, [$c761]
    call CheckCollisionCore
    ret nc

    inc l
    ld a, [hl]
    add $08
    ld [hl], a
    scf
    ret


CheckCollisionCore::
    ld e, a
    ld a, [bc]
    dec a
    sla a
    sla a
    sla a
    ld c, a
    swap h
    srl h
    ld d, h
    ld hl, $c210
    ld b, $04

jr_000_083e:
    ld a, [hl]
    and a
    jr z, jr_000_084f

    inc l
    inc l
    inc l
    inc l
    ld a, c
    sub [hl]
    call c, CheckSpriteOverlap
    ld a, $0c
    jr jr_000_0851

jr_000_084f:
    ld a, $10

jr_000_0851:
    add l
    ld l, a
    dec b
    jr nz, jr_000_083e

    and a
    ret


CheckSpriteOverlap::
    ld a, d
    sub [hl]
    cp $09
    ret nc

    inc l
    ld a, e
    cp [hl]
    jr z, jr_000_0864

    dec l
    ret


jr_000_0864:
    pop bc
    scf
    ret


UpdateDropPositions::
    ld hl, $c215
    ld b, $04

jr_000_086c:
    ld a, [hl]
    inc a
    jr nz, jr_000_0877

    inc l
    ld a, [hl-]
    swap a
    srl a
    ld [hl], a

jr_000_0877:
    ld a, $10
    add l
    ld l, a
    dec b
    jr nz, jr_000_086c

    ret


CalcGridPosition::
    ld a, b
    sla a
    ld [$c762], a
    ld h, a
    ld a, [$c761]
    ld l, a
    sla l
    sla l
    ld bc, $c66a
    add c
    ld c, a
    ret nc

    inc b
    ret


AnimateDropDown::
    dec a
    jr nz, jr_000_08b5

    call CalcGridPosition
    inc l
    inc l
    inc l
    inc bc
    ld a, [bc]
    sub h
    jr c, jr_000_08ab

    jr z, jr_000_08ab

    call CheckCollisionDown
    jr jr_000_08b4

jr_000_08ab:
    ld a, $02
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece

jr_000_08b4:
    ret


jr_000_08b5:
    dec a
    jr nz, jr_000_08d3

    call CalcGridPosition
    inc l
    inc l
    inc bc
    ld a, [bc]
    sub h
    jr c, jr_000_08c9

    jr z, jr_000_08c9

    call CheckCollisionDown
    jr jr_000_08d2

jr_000_08c9:
    ld a, $02
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece

jr_000_08d2:
    ret


jr_000_08d3:
    dec a
    jr nz, jr_000_08f0

    call CalcGridPosition
    inc l
    inc bc
    ld a, [bc]
    sub h
    jr c, jr_000_08e6

    jr z, jr_000_08e6

    call CheckCollisionDown
    jr jr_000_08ef

jr_000_08e6:
    ld a, $02
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece

jr_000_08ef:
    ret


jr_000_08f0:
    call CalcGridPosition
    inc bc
    ld a, [bc]
    sub h
    jr c, jr_000_0902

    jr z, jr_000_0902

    call CheckCollisionDown
    ret nc

    dec l
    ld [hl], $ff
    ret


jr_000_0902:
    ld a, $02
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece
    ret


AnimateDropUp::
    dec a
    jr nz, jr_000_0927

    call CalcGridPosition
    inc l
    ld a, [bc]
    sub h
    jr c, jr_000_091d

    jr z, jr_000_091d

    call CheckCollisionUp
    ret


jr_000_091d:
    ld a, $02
    call ClearColumnLeft
    ld a, [de]
    call DrawGridPiece
    ret


jr_000_0927:
    dec a
    jr nz, jr_000_0943

    call CalcGridPosition
    inc l
    inc l
    ld a, [bc]
    sub h
    jr c, jr_000_0939

    jr z, jr_000_0939

    call CheckCollisionUp
    ret


jr_000_0939:
    ld a, $02
    call ClearColumnLeft
    ld a, [de]
    call DrawGridPiece
    ret


jr_000_0943:
    dec a
    jr nz, jr_000_096d

    call CalcGridPosition
    inc l
    inc l
    inc l
    inc bc
    ld a, [bc]
    dec bc
    sub h
    push af
    ld a, [bc]
    sub h
    jr c, jr_000_095c

    jr z, jr_000_095c

    call CheckCollisionUp
    pop af
    ret


jr_000_095c:
    pop af
    jr c, jr_000_0968

    cp $01
    jr c, jr_000_0968

    ld a, $02
    call ClearColumnLeft

jr_000_0968:
    ld a, [de]
    call DrawGridPiece
    ret


jr_000_096d:
    call CalcGridPosition
    inc l
    inc l
    inc l
    inc l
    inc bc
    ld a, [bc]
    dec bc
    sub h
    push af
    ld a, [bc]
    sub h
    jr c, jr_000_0988

    jr z, jr_000_0988

    pop af
    call CheckCollisionUp
    ret nc

    dec l
    ld [hl], $ff
    ret


jr_000_0988:
    pop af
    jr c, jr_000_0994

    cp $01
    jr c, jr_000_0994

    ld a, $02
    call ClearColumnLeft

jr_000_0994:
    ld a, [de]
    call DrawGridPiece
    ret


ClearAnimState::
    ld hl, $c75d
    ld b, $47
    xor a

jr_000_099f:
    ld [hl+], a
    dec b
    jr nz, jr_000_099f

    ret


StartDropAnim::
    push bc
    ld b, a
    ld a, [$c75d]
    and a
    jr nz, jr_000_09c6

    push hl
    ld a, b
    ld [$c761], a
    ld hl, $c764
    ld a, $01
    ld [hl], a
    ld hl, $c774
    ld [hl], a
    ld [$c75e], a
    ld a, $ff
    ld [$c75d], a
    ld a, $06
    pop hl

jr_000_09c6:
    pop bc
    ret


    ld d, $00
    ld hl, BOARD_DATA
    ld e, $00
    ld b, $04

jr_000_09d1:
    ld a, $07
    sub d
    ld c, a

jr_000_09d5:
    ld [hl], $00
    inc hl
    dec c
    jr nz, jr_000_09d5

    ld c, d
    inc c
    dec c
    jr z, jr_000_09e5

    ld a, e

jr_000_09e1:
    ld [hl+], a
    dec c
    jr nz, jr_000_09e1

jr_000_09e5:
    ld c, d
    sla c
    ld a, $10
    sub c
    ld [hl], a
    inc hl
    inc d
    inc e
    dec b
    jr nz, jr_000_09d1

    ret


    ret


    ld a, [$c7a4]
    inc a
    ld [$c7a4], a
    cp $30
    jr c, jr_000_0a03

    xor a
    ld [$c7a4], a

jr_000_0a03:
    ld hl, $c7a9
    ld de, $c7a5
    ld b, $04

jr_000_0a0b:
    ld a, [hl]
    and a
    jr z, jr_000_0a38

    ld a, [de]
    and a
    jr nz, jr_000_0a1b

    ld a, [$c7a4]
    and a
    jr z, jr_000_0a21

    jr jr_000_0a38

jr_000_0a1b:
    inc a
    ld [de], a
    cp $10
    jr c, jr_000_0a38

jr_000_0a21:
    xor a
    ld [de], a
    ld a, [hl]
    cp $01
    jr nz, jr_000_0a2c

    ld [hl], $02
    jr jr_000_0a2e

jr_000_0a2c:
    ld [hl], $01

jr_000_0a2e:
    push hl
    push bc
    push de
    ld a, [hl]
    call DrawColumnSprite
    pop de
    pop bc
    pop hl

jr_000_0a38:
    inc hl
    inc de
    dec b
    jr nz, jr_000_0a0b

    ret


InitBlinkState::
    ld hl, $c7a4
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    inc a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ret


SpritePatternTable1::
    db $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $00, $04, $05, $01, $10, $14, $15, $11
    db $00, $06, $07, $01, $10, $16, $17, $11, $00, $08, $09, $01, $10, $18, $19, $11
    db $00, $0a, $0b, $01, $10, $1a, $1b, $11, $00, $0c, $0d, $01, $10, $1c, $1d, $11
    db $00, $0e, $0f, $01, $10, $1e, $1f, $11, $4a, $0e, $0f, $4a, $4a, $1e, $1f, $4a
    db $4a, $20, $21, $4a, $4a, $22, $23, $4a

SpritePatternTable2::
    db $49, $49, $49, $49, $49, $49, $49, $49, $49, $49, $49, $49, $49, $49, $49, $49
    db $49, $87, $88, $49, $49, $89, $8a, $49, $49, $8f, $90, $49, $49, $91, $92, $49
    db $49, $93, $94, $49, $9b, $9c, $9d, $9e, $9f, $a0, $a1, $a2, $a3, $a4, $a5, $a6
    db $49, $49, $49, $49, $49, $83, $84, $49, $49, $85, $86, $49, $49, $49, $49, $49
    db $49, $8b, $8c, $49, $49, $8d, $8e, $49, $49, $95, $96, $49, $49, $97, $98, $49
    db $49, $99, $9a, $49, $a7, $a8, $a9, $aa, $ab, $ac, $ad, $ae, $af, $b0, $b1, $b2
    db $4a, $20, $21, $4a, $4a, $22, $23, $4a, $4a, $24, $25, $4a, $4a, $26, $27, $4a

InitGameState::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_000_0b33

    ld a, [$c6b2]
    ld [PLAYER_MODE], a
    ld a, [TWO_PLAYER_FLAG]
    jr z, jr_000_0b1b

    ld a, $01
    ld [PLAYER_MODE], a

jr_000_0b1b:
    ld a, [$c6b3]
    ld [$c6b7], a
    ld [$c6e2], a
    inc a
    ld [SPRITE_ANIM_FRAME], a
    xor a
    ld [SPRITE_ANIM_STATE], a
    ld a, [$c6b4]
    ld [$c6b8], a
    ret


jr_000_0b33:
    ld a, $01
    ld [PLAYER_MODE], a
    ld a, [$c6eb]
    ld [$c6b7], a
    ld [$c6e2], a
    inc a
    ld [SPRITE_ANIM_FRAME], a
    xor a
    ld [SPRITE_ANIM_STATE], a
    ld a, [$c6ec]
    ld [$c6b8], a
    ret


InitGameState2::
    ld a, [$c66f]
    and a
    ret z

    ld hl, $c670
    dec [hl]
    ret nz

    ld [hl], $02
    ld hl, $c202
    ld a, [hl]
    cp $04
    jr nc, jr_000_0b67

    inc a
    jr jr_000_0b6d

jr_000_0b67:
    inc a
    cp $08
    jr nz, jr_000_0b6d

    xor a

jr_000_0b6d:
    ld [hl], a
    jr z, jr_000_0b75

    cp $04
    jr z, jr_000_0b75

    ret


jr_000_0b75:
    xor a
    ld [$c66f], a
    ret


InitGameBoard::
    ld hl, $c66f
    ld [hl], $00
    inc hl
    ld [hl], $02
    ret


LevelCountTable::
    db $0d, $0b, $09, $07, $05

LevelThresholds::
    db $00, $0a, $14, $1e, $28

    inc b
    ld [bc], a
    jr z, jr_000_0b92

    inc b

jr_000_0b92:
    ld [bc], a
    inc h
    ld bc, $0204
    jr nz, jr_000_0b9a

    inc b

jr_000_0b9a:
    ld [bc], a
    inc e
    ld bc, $0204
    ld a, [de]
    ld bc, $0204
    jr jr_000_0ba6

    inc b

jr_000_0ba6:
    ld [bc], a
    ld d, $01
    inc b
    ld [bc], a
    inc d
    ld bc, $0204
    ld [de], a
    ld bc, $0204
    db $10
    ld bc, $0204
    ld e, $01
    inc b
    ld [bc], a
    inc e
    ld bc, $0204
    ld a, [de]
    ld bc, $0204
    jr jr_000_0bc6

    inc b

jr_000_0bc6:
    ld [bc], a
    ld d, $01
    inc b
    ld [bc], a
    inc d
    ld bc, $0204
    ld [de], a
    ld bc, $0204
    db $10
    ld bc, $0207
    ld c, $01
    ld bc, $0c03
    ld bc, $0204
    inc d
    ld bc, $0204
    inc de
    ld bc, $0204
    ld [de], a
    ld bc, $0204
    ld de, $0401
    ld [bc], a
    db $10
    ld bc, $0204
    rrca
    ld bc, $0204
    ld c, $01
    inc b
    ld [bc], a
    dec c
    ld bc, $0206
    inc c
    ld bc, $0302
    dec bc
    ld bc, $0204
    rrca
    ld bc, $0204
    ld c, $01
    inc b
    ld [bc], a
    dec c
    ld bc, $0204
    inc c
    ld bc, $0204
    dec bc
    ld bc, $0204
    ld a, [bc]
    ld bc, $0204
    add hl, bc
    ld bc, $0204
    ld [$0501], sp
    ld [bc], a
    rlca
    ld bc, $0303
    ld b, $01
    inc b
    ld [bc], a
    rrca
    ld bc, $0204
    ld c, $01
    inc b
    ld [bc], a
    dec c
    ld bc, $0204
    inc c
    ld bc, $0204
    dec bc

GameTurnTable::
    db $01, $04, $02, $0a, $01, $04, $02, $09, $01, $04, $02, $08, $01, $04, $02, $07
    db $01, $04, $03, $06, $01, $04, $02, $0f, $01, $04, $02, $0e, $01, $04, $02, $0d
    db $01, $04, $02, $0c, $01, $04, $02, $0b, $01, $04, $02, $0a, $01, $04, $02, $09
    db $01, $04, $02, $08, $01, $03, $02, $07, $01, $05, $03, $06, $01, $04, $02, $0f
    db $01, $04, $02, $0e, $01, $04, $02, $0d, $01, $04, $02, $0c, $01, $04, $02, $0b
    db $01, $04, $02, $0a, $01, $04, $02, $09, $01, $04, $02, $08, $01, $02, $02, $07
    db $01, $06, $03, $06, $01, $04, $02, $14, $01, $04, $02, $0d, $01, $04, $02, $0c
    db $01, $04, $02, $0b, $01, $04, $02, $0a, $01, $04, $02, $09, $01, $04, $02, $08
    db $01, $04, $02, $07, $01, $01, $02, $06, $01, $07, $03, $06, $01, $04, $02, $14
    db $01, $04, $02, $0a, $01, $04, $02, $09, $01, $04, $02, $08, $01, $04, $02, $07
    db $01, $04, $02, $06, $01, $04, $02, $05, $01, $04, $02, $04, $01, $04, $03, $06
    db $01, $04, $03, $05, $01, $04, $02, $14, $01, $04, $02, $0a, $01, $04, $02, $09
    db $01, $04, $02, $08, $01, $04, $02, $07, $01, $04, $02, $05, $01, $04, $02, $04
    db $01, $03, $02, $03, $01, $05, $03, $06, $01, $04, $03, $05, $01, $04, $02, $14
    db $01, $04, $02, $09, $01, $04, $02, $08, $01, $04, $02, $07, $01, $04, $02, $06
    db $01, $04, $02, $05, $01, $04, $02, $04, $01, $02, $02, $03, $01, $06, $03, $06
    db $01, $04, $03, $05, $01, $04, $02, $14, $01, $04, $02, $08, $01, $04, $02, $07
    db $01, $04, $02, $06, $01, $04, $02, $05, $01, $04, $02, $04, $01, $04, $02, $03
    db $01, $01, $02, $02, $01, $07, $03, $06, $01, $04, $03, $05, $01, $04, $02, $14
    db $01, $04, $02, $07, $01, $04, $02, $06, $01, $04, $02, $05, $01, $04, $02, $04
    db $01, $04, $02, $03, $01, $04, $02, $02, $01, $04, $03, $06, $01, $04, $03, $05
    db $01, $04, $03, $04, $01, $04, $02, $14, $01, $04, $02, $06, $01, $04, $02, $05
    db $01, $04, $02, $04, $01, $04, $02, $03, $01, $04, $02, $02, $01, $03, $02, $02
    db $01, $05, $03, $06, $01, $04, $03, $05, $01, $04, $03, $04, $01, $04, $02, $14
    db $01, $04, $02, $05, $01, $04, $02, $04, $01, $04, $02, $03, $01, $04, $02, $02
    db $01, $04, $02, $02, $01, $02, $02, $02, $01, $06, $03, $06, $01, $04, $03, $05
    db $01, $04, $03, $04, $01, $04, $02, $0f, $01, $04, $02, $04, $01, $04, $02, $03
    db $01, $04, $02, $02, $01, $04, $02, $02, $01, $04, $02, $02, $01, $01, $02, $02
    db $01, $07, $03, $06, $01, $04, $03, $05, $01, $04, $03, $04, $01, $04, $02, $0f
    db $01, $04, $02, $03, $01, $04, $02, $02, $01, $04, $02, $02, $01, $04, $02, $02
    db $01, $04, $02, $02, $01, $04, $03, $06, $01, $04, $03, $05, $01, $04, $03, $04
    db $01, $04, $03, $03, $01, $04, $02, $0f, $01, $04, $02, $02, $01, $04, $02, $02
    db $01, $04, $02, $02, $01, $04, $02, $02, $01, $03, $02, $02, $01, $05, $03, $06
    db $01, $04, $03, $05, $01, $04, $03, $04, $01, $04, $03, $03, $01, $04, $02, $0f
    db $01, $04, $02, $02, $01, $04, $02, $02, $01, $04, $02, $02, $01, $04, $02, $02
    db $01, $02, $02, $02, $01, $06, $03, $06, $01, $04, $03, $05, $01, $04, $03, $04
    db $01, $04, $03, $03, $01, $04, $02, $0f, $01, $04, $02, $02, $01, $04, $02, $02
    db $01, $04, $02, $02, $01, $04, $02, $02, $01, $01, $02, $02, $01, $07, $03, $06
    db $01, $04, $03, $05, $01, $04, $03, $04, $01, $04, $03, $03, $01, $04, $02, $06
    db $01, $04, $02, $06, $01, $04, $02, $05, $01, $04, $02, $05, $01, $04, $03, $04
    db $01, $04, $03, $04, $01, $04, $03, $03, $01, $04, $03, $03, $01, $04, $03, $02
    db $01, $04, $03, $02, $01

ProcessMatching::
    cp $1c
    jr c, jr_000_0edb

    ld a, $1b

jr_000_0edb:
    ldh [STATE_TRANSITION], a
    xor a
    ld [LCD_REDRAW], a
    call LCDOff
    call ClearOAM
    ld hl, $9c00
    ld bc, $0240
    ld d, $05
    call DrawCharacter
    ld a, $03
    ld [$2100], a
    ld hl, $4000
    ld de, $9000
    ld bc, $0800
    call MemcopyCall
    ld hl, $4800
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ld hl, $4e40
    ld de, $8000
    ld bc, $0800
    call MemcopyCall
    ld a, $01
    ld [$2100], a
    call LCDOn
    ld a, $8b
    ldh [rLCDC], a
    ld hl, $1184
    ld de, $c408
    ld bc, $0010
    call Memcopy
    ldh a, [STATE_TRANSITION]
    ld hl, $11d4
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl]
    sla a
    sla a
    add $02
    ld de, $0004
    ld hl, $c40a
    ld c, $04

jr_000_0f4b:
    ld [hl], a
    add hl, de
    inc a
    dec c
    jr nz, jr_000_0f4b

    ld hl, $c4a0
    ld bc, $0168
    ld d, $05
    call DrawCharacter
    ld a, $01
    ld [GAME_ACTIVE], a
    xor a
    ldh [ANIM_FRAME], a
    ld a, $18
    ldh [SCX_SHADOW], a
    ld a, $88

jr_000_0f6a:
    push af
    ldh a, [ANIM_FRAME]
    inc a
    cp $06
    jr c, jr_000_0f78

    ld a, $2b
    call PlaySound
    xor a

jr_000_0f78:
    ld b, $9f
    cp $03
    jr nc, jr_000_0f80

    ld b, $96

jr_000_0f80:
    ldh [ANIM_FRAME], a
    ld a, b
    ld hl, $c4ed
    ld bc, $0303
    call FillRect
    ldh a, [ANIM_FRAME]
    bit 0, a
    jr z, jr_000_0f95

    call $4bc5

jr_000_0f95:
    call $4bc5
    ldh a, [SCX_SHADOW]
    inc a
    ldh [SCX_SHADOW], a
    pop af
    dec a
    jr nz, jr_000_0f6a

    ld hl, $c4a0
    ld bc, $0168
    ld d, $05
    call DrawCharacter
    ld c, $3c
    call DrawString
    xor a
    ldh [ANIM_FRAME], a
    ld a, $60
    ldh [SCX_SHADOW], a

jr_000_0fb8:
    push af
    ldh a, [ANIM_FRAME]
    inc a
    cp $0a
    jr c, jr_000_0fc6

    ld a, $2c
    call PlaySound
    xor a

jr_000_0fc6:
    ld b, $00
    cp $05
    jr nc, jr_000_0fce

    ld b, $24

jr_000_0fce:
    ldh [ANIM_FRAME], a
    ld a, b
    ld hl, $c546
    ld bc, $0606
    call FillRect
    call $4bc5
    ldh a, [SCX_SHADOW]
    dec a
    ldh [SCX_SHADOW], a
    pop af
    dec a
    jr nz, jr_000_0fb8

    ld c, $1e
    call DrawString
    ld a, $48
    ld hl, $c546
    ld bc, $0606
    call FillRect
    ld c, $0a
    call DrawString
    ld a, $6c
    ld hl, $c546
    ld bc, $0607
    call FillRect
    ld c, $0a
    call DrawString
    ld hl, $117c
    ld de, $c400
    ld bc, $0008
    call Memcopy
    ld hl, $c59b
    ld a, $de
    ld [hl+], a
    inc a
    ld [hl+], a
    ld [hl], a
    ld a, $29
    call PlaySound
    ld b, $08
    ld de, $0004

jr_000_102a:
    ld c, $02
    call DrawNumber
    call $4bc5
    dec b
    jr nz, jr_000_102a

    ld b, $08
    ld de, $0004

jr_000_103a:
    push bc
    ld c, $04
    ld hl, $c409

jr_000_1040:
    ld a, [hl]
    sub $02
    ld [hl], a
    add hl, de
    dec c
    jr nz, jr_000_1040

    pop bc
    ld c, $fe
    call DrawNumber
    call $4bc5
    dec b
    jr nz, jr_000_103a

    ld hl, $c59b
    ld a, $8d
    ld [hl+], a
    inc a
    ld [hl+], a
    ld [hl], $05
    call ClearOAM
    ld c, $0a
    call DrawString
    ld hl, $c54c
    ld de, $0014
    ld c, $06

jr_000_106e:
    ld [hl], $05
    add hl, de
    dec c
    jr nz, jr_000_106e

    ld a, $48
    ld hl, $c546
    ld bc, $0606
    call FillRect
    ld c, $0a
    call DrawString
    ld a, $00
    ld hl, $c546
    ld bc, $0606
    call FillRect
    ld a, $a8
    ld hl, $c4ca
    ld bc, $0210
    call FillRect
    call UpdateLevel
    ld a, $54
    call PlaySound
    ld hl, $1194
    ld de, $c400
    ld bc, $0008
    call Memcopy
    ld de, $0004
    ld hl, $11d4
    ldh a, [STATE_TRANSITION]
    add l
    ld l, a
    jr nc, jr_000_10bb

    inc h

jr_000_10bb:
    ld a, [hl]
    sla a
    add $3e
    ld hl, $c402
    ld [hl], a
    inc a
    add hl, de
    ld [hl], a
    ld c, $14
    ld de, $0004

jr_000_10cc:
    call $4bc5
    ld hl, $c400
    ld a, [hl]
    dec a
    ld [hl], a
    add hl, de
    ld a, [hl]
    dec a
    ld [hl], a
    dec c
    jr nz, jr_000_10cc

    ld c, $3c

UpdateScore::
    call DrawString
    call ClearOAM
    ld hl, $119c
    ldh a, [STATE_TRANSITION]
    sla a
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld l, [hl]
    ld h, a
    call $432f
    call UpdateLevel

jr_000_10f8:
    ld a, [$c026]
    and a
    jr nz, jr_000_10f8

    call FillRectAlt
    ld a, $8f
    ldh [rLCDC], a
    jp DrawDigit


UpdateLevel::
    ld a, $c8
    ld hl, $c5d1
    ld bc, HeaderLogo
    call FillRect
    ld hl, $c5d6
    ld c, $05
    ld de, $c621

jr_000_111b:
    ld a, [de]
    inc de
    and $0f
    add $d4
    ld [hl+], a
    dec c
    jr nz, jr_000_111b

    ld a, $cc
    ld hl, $c509
    ld bc, HeaderLogo
    call FillRect
    ld hl, $c510
    ld a, [SPRITE_ANIM_FRAME]
    add $d4
    ld [hl-], a
    ld a, [SPRITE_ANIM_STATE]
    add $d4
    ld [hl], a
    ld hl, $c511
    ld a, [$c6b8]
    sla a
    add $d0
    ld [hl+], a
    inc a
    ld [hl], a
    ld a, $e0
    ld hl, $c5e5
    ld bc, $0103
    call FillRect
    ld hl, $c5ea
    ld de, $c6d6
    ld a, [de]
    inc de
    and $0f
    add $d4
    ld [hl+], a
    ld a, [de]
    inc de
    and $0f
    add $d4
    ld [hl+], a
    ld a, $e3
    ld [hl+], a
    ld a, [de]
    inc de
    and $0f
    add $d4
    ld [hl+], a
    ld a, [de]
    and $0f
    add $d4
    ld [hl+], a
    ret


    ld [hl], b
    ld l, b
    nop
    nop
    ld [hl], b
    ld [hl], b
    ld bc, $7000
    add b
    ld [bc], a
    nop
    ld [hl], b
    adc b
    inc bc
    nop
    ld a, b
    add b
    inc b
    nop
    ld a, b
    adc b
    dec b
    nop
    ld e, b
    ld e, b
    ccf
    nop
    ld e, b
    ld h, b
    ld b, b
    nop
    nop
    ld d, b
    ld bc, $0100
    ld d, b
    ld [bc], a
    nop
    ld [bc], a
    ld d, b
    inc bc
    nop
    inc bc
    nop
    inc b
    nop
    inc b
    nop
    dec b
    nop
    dec b
    nop
    ld b, $00
    ld b, $00
    rlca
    nop
    rlca
    nop
    ld [$0800], sp
    nop
    ld [$0900], sp
    nop
    add hl, bc
    nop
    add hl, bc
    nop
    stop
    stop
    stop
    ld [de], a
    nop
    ld [de], a
    nop
    ld [de], a
    nop
    dec d
    nop
    nop
    ld bc, $0302
    inc b
    dec b
    dec b
    ld b, $06
    rlca
    rlca
    ld [$0908], sp
    add hl, bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    dec bc
    dec bc
    dec bc
    inc c
    inc c
    inc c
    dec c
    dec c
    dec c
    ld c, $fe
    rst $38
    ret z

    push hl
    push de
    ld de, $0014
    sla a
    add $d2
    ld [hl], a
    add hl, de
    inc a
    ld [hl], a
    pop de
    pop hl
    ret


DrawNumber::
    ld hl, $c401
    ld a, [hl]
    add c
    ld [hl], a
    add hl, de
    ld a, [hl]
    add c
    ld [hl], a
    ret


DrawDigit::
    call LCDOff
    call ClearOAM
    call LoadGameTiles
    call LCDOn
    ld a, $01
    ld [LCD_REDRAW], a
    ret


DrawString::
    call $4bc5
    dec c
    jr nz, DrawString

    ret


DrawCharacter::
    ld a, d
    ld [hl+], a
    dec bc
    ld a, b
    or c
    jr nz, DrawCharacter

    ret


FillRect::
    ld de, $0014

jr_000_1232:
    push bc
    push hl

jr_000_1234:
    ld [hl+], a
    inc a
    dec c
    jr nz, jr_000_1234

    pop hl
    add hl, de
    pop bc
    dec b
    jr nz, jr_000_1232

    ret


FillRectAlt::
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and $0f
    jr z, FillRectAlt

    ret


DrawBox::
    ld b, $04
    xor a

jr_000_124d:
    push af
    push bc
    call UpdateSpriteObject
    pop bc
    pop af
    inc a
    dec b
    jr nz, jr_000_124d

    call DisplayLines
    and a
    jr nz, jr_000_1290

    call CalcDifficulty
    call DisplayLevel
    ld a, [PLAYER_MODE]
    and a
    ret z

    ld hl, $c66a
    ld b, $04

jr_000_126e:
    ld a, [hl+]
    cp $0f
    ret nz

    dec b
    jr nz, jr_000_126e

    ld a, $01
    ld [$c6e4], a
    ld [$c6e5], a
    ld [$c703], a
    push af
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_128b

    pop af
    call FormatRankEntry

jr_000_128b:
    pop af
    call ProcessNewHighScore
    ret


jr_000_1290:
    call DisplayScore
    ret


DisplayScore::
    ld hl, $c696
    ld a, [hl]
    and a
    jr z, jr_000_12ac

    dec [hl]
    ret nz

    ld a, [$c66f]
    ld b, a
    ld a, [$c75d]
    or b
    ret z

    ld a, $01
    ld [$c696], a
    ret


jr_000_12ac:
    ld a, [$c6a7]
    ld [$c696], a
    ret


DisplayLevel::
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_12bd

    call UpdateMenuCursor
    ret


jr_000_12bd:
    call ProcessMenuInput
    call DisplaySpeed
    call CalcResults
    ld a, [$c698]
    call DisplayResults
    ret


DisplayLines::
    ld hl, $c210
    ld b, $04

jr_000_12d2:
    ld a, [hl]
    and a
    jr nz, jr_000_12e0

    swap l
    inc l
    swap l
    dec b
    jr nz, jr_000_12d2

    xor a
    ret


jr_000_12e0:
    ld a, $01
    ret


DisplaySpeed::
    ld hl, $c6b0
    dec [hl]
    ret nz

    ld a, [$c6b7]
    cp $04
    jr c, jr_000_12f5

    cp $03
    jr z, jr_000_12f9

    jr jr_000_12fd

jr_000_12f5:
    ld a, $0a
    jr jr_000_1301

jr_000_12f9:
    ld a, $0a
    jr jr_000_1301

jr_000_12fd:
    ld a, $0a
    jr jr_000_1301

jr_000_1301:
    ld [hl], a
    ld hl, $c6a7
    ld a, [hl]
    cp $02
    ret c

    ret z

    dec [hl]
    ret


CheckMatch::
    ldh a, [JOYPAD_PRESSED]
    and $30
    jr z, jr_000_1317

    ld a, $28
    call PlaySound

jr_000_1317:
    ldh a, [JOYPAD_PRESSED]
    and $03
    jr z, jr_000_1341

    ld a, [$c75d]
    and a
    jr nz, jr_000_1341

    ld a, [$c6e7]
    and a
    jr nz, jr_000_1341

    ld a, $01
    ld [$c66f], a
    ld a, [$c206]
    swap a
    srl a
    push af
    ld a, $1b
    call PlaySound
    pop af
    call StartDropAnim
    jr jr_000_1341

jr_000_1341:
    ld hl, $c206
    ldh a, [JOYPAD_HELD]
    bit 7, a
    jr nz, jr_000_136d

    ldh a, [JOYPAD_PRESSED]
    bit 4, a
    jr nz, jr_000_1355

    bit 5, a
    jr nz, jr_000_1361

    ret


jr_000_1355:
    ld a, [hl]
    add $20
    cp $60
    ret z

    ld [hl], a
    ld hl, $c6e0
    inc [hl]
    ret


jr_000_1361:
    ld a, [hl]
    sub $20
    cp $e0
    ret z

    ld [hl], a
    ld hl, $c6e0
    dec [hl]
    ret


jr_000_136d:
    ld a, [$c218]
    cp $02
    jr z, jr_000_138a

    ld a, [$c228]
    cp $02
    jr z, jr_000_138a

    ld a, [$c238]
    cp $02
    jr z, jr_000_138a

    ld a, [$c248]
    cp $02
    jr z, jr_000_138a

    ret


jr_000_138a:
    ld hl, $c696
    ld a, [hl]
    cp $03
    jr c, jr_000_1394

    ld [hl], $03

jr_000_1394:
    ld b, $04
    ld hl, $c21f

jr_000_1399:
    ld a, [hl]
    cp $03
    jr c, jr_000_13a0

    ld [hl], $03

jr_000_13a0:
    ld a, l
    add $10
    ld l, a
    dec b
    jr nz, jr_000_1399

    ret


CheckVerticalMatch::
    call CheckHorizontalMatch
    ld a, [hl]
    ld d, h
    ld e, l
    push af
    call CheckHorizontalMatch
    pop af
    ld b, [hl]
    ld [hl], a
    ld a, b
    ld [de], a
    ret


CheckHorizontalMatch::
    ld c, $38
    call MultiplyAndCount
    ld b, $00
    ld c, a
    ld hl, $ff97
    add hl, bc
    ret


ProcessMatch::
    call ClearMatchedPieces
    ld a, [hl]
    ld d, h
    ld e, l
    push af
    call ClearMatchedPieces
    pop af
    ld b, [hl]
    ld [hl], a
    ld a, b
    ld [de], a
    ret


ClearMatchedPieces::
    ld c, $38
    call MultiplyAndCount
    ld b, $00
    ld c, a
    ld hl, $c673
    add hl, bc
    ret


UpdateMatchState::
    ld a, [$c696]
    and a
    ld a, $01
    ret nz

    ld a, [PIECE_FALL_POS]
    cp $02
    jr nz, jr_000_13f6

    ld a, [$c68b]
    call GameOverSequence

jr_000_13f6:
    call MovePieceUp
    ld b, a
    ld a, [PIECE_FALL_POS]
    inc a
    ld [PIECE_FALL_POS], a
    cp b
    jr nc, jr_000_140f

    ld a, [$c690]
    add $08
    ld [$c690], a
    ld a, $01
    ret


jr_000_140f:
    ld a, [$c695]
    cp $07
    call z, ScanBoard
    call MovePieceLeft
    cp b
    jr nz, jr_000_1429

    ld a, [PIECE_FALL_POS]
    cp $0f
    jr z, jr_000_1429

    call $1612
    jr jr_000_1463

jr_000_1429:
    ld a, $1c
    call PlaySound
    call MovePieceUp
    dec a
    ld h, a
    ld a, [PIECE_ROTATION]
    sla a
    sla a
    ld l, a
    ld a, [$c695]
    call DrawGridPiece
    call MovePieceUp
    dec a
    dec a
    ld [hl], a
    cp $ff
    jr nz, jr_000_1463

    ld a, $01
    ld [$c704], a
    xor a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_145d

    xor a
    call FormatRankEntry
    xor a
    ret


jr_000_145d:
    xor a
    call ProcessNewHighScore
    xor a
    ret


jr_000_1463:
    jr MovePieceDown

    pop hl

MovePieceDown::
    ld a, [$c68b]
    inc a
    swap a
    ld l, a
    ld h, $c2
    ld b, $0a
    xor a

jr_000_1472:
    ld [hl+], a
    dec b
    jr nz, jr_000_1472

    ret


MovePieceUp::
    ld a, [PIECE_ROTATION]
    ld hl, $c66a
    add l
    jr nc, jr_000_1481

    inc h

jr_000_1481:
    ld l, a
    ld a, [hl]
    ret


MovePieceLeft::
    ld hl, $c697
    dec [hl]
    call MovePieceUp
    ld hl, BOARD_DATA
    call GetArrayElement
    ld a, [PIECE_ROTATION]
    sla a
    sla a
    sla a
    sla a
    add l
    jr nc, jr_000_14a0

    inc h

jr_000_14a0:
    ld l, a
    ld b, [hl]
    ld a, [$c695]
    dec hl
    dec hl
    ld [hl], a
    ret


MovePieceRight::
    ld hl, $c210
    ld b, $80
    xor a

jr_000_14af:
    ld [hl+], a
    dec b
    jr nz, jr_000_14af

    ret


GetArrayElement::
    add l
    jr nc, jr_000_14b8

    inc h

jr_000_14b8:
    ld l, a
    ld a, [hl]
    ret


SetArrayElement::
    call DrawMenuCursor
    ret


ValidatePosition::
    ld hl, $c6a7
    ld a, [$c6b8]
    and a
    jr z, jr_000_14d2

    call ProcessFalling
    srl a
    ld [$c6a7], a
    jr jr_000_14d8

jr_000_14d2:
    call ProcessFalling
    ld [$c6a7], a

jr_000_14d8:
    ld a, $02
    ld [$c698], a
    ld a, [$c6b7]
    ld hl, LevelCountTable
    call GetArrayElement
    ld [$c699], a
    ld a, $30
    ld [$c672], a
    ld hl, $c6b0
    ld a, [$c6b7]
    cp $03
    jr z, jr_000_1500

    cp $04
    jr nc, jr_000_1504

    ld a, $0a
    jr jr_000_1506

jr_000_1500:
    ld a, $0a
    jr jr_000_1506

jr_000_1504:
    ld a, $0a

jr_000_1506:
    ld [hl], a
    ret


GenerateNextPiece::
    ld b, $40
    ld hl, BOARD_DATA

jr_000_150d:
    xor a
    ld [hl+], a
    dec b
    jr nz, jr_000_150d

    ret


GetRandomPiece::
    ld b, $04
    ld hl, $c66a
    ld a, [$c699]

jr_000_151b:
    ld [hl+], a
    dec b
    jr nz, jr_000_151b

    ret


ShuffleRandom::
    ld hl, $ff97
    ld [hl], $00
    inc hl
    ld [hl], $01
    inc hl
    ld [hl], $02
    inc hl
    ld [hl], $03
    ret


ProcessInput::
    ld hl, $c673
    ld b, $05
    ld a, $01

jr_000_1536:
    ld [hl+], a
    inc a
    dec b
    jr nz, jr_000_1536

    ret


ProcessInputGame::
    ld a, $0a
    ldh [VBLANK_BUSY], a
    call ProcessInputTitle

jr_000_1543:
    ldh a, [VBLANK_BUSY]
    and a
    jr nz, jr_000_1543

    ret


ProcessInputTitle::
    ld a, [$c699]
    cp $0f
    ret z

    sub $0f
    cpl
    inc a
    ld b, a
    srl b
    ld c, $04
    ld hl, $c637
    ld de, $0010

jr_000_155e:
    push bc
    push hl

jr_000_1560:
    push bc
    push de
    push hl
    call ProcessMatch
    call ProcessMatch
    call ProcessMatch
    ld a, [$c676]
    pop hl
    pop de
    pop bc
    call RotatePiece
    ld [hl-], a
    dec hl
    dec b
    jr nz, jr_000_1560

    pop hl
    pop bc
    add hl, de
    dec c
    jr nz, jr_000_155e

    ret


RotatePiece::
    push bc
    inc hl
    inc hl
    ld b, [hl]
    cp b
    jr nz, jr_000_158f

    inc a
    cp $05
    jr nz, jr_000_1593

    ld a, $01

jr_000_158f:
    dec hl
    dec hl
    pop bc
    ret


jr_000_1593:
    jr jr_000_158f

DropPiece::
    xor a
    ld [$c6ab], a
    ld [$c69d], a
    ld [$c6ae], a
    ld [$c6ad], a
    ld [$c6bf], a
    ld a, $14
    ld [$c6c0], a
    ret


HandleDrop::
    call MovePieceRight
    call GenerateNextPiece
    call GetRandomPiece
    call ShuffleRandom
    call ProcessInput
    call DropPiece
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_15d0

    call SetArrayElement
    ld a, $0f
    ld [$c699], a
    call GetRandomPiece
    jr jr_000_15e8

jr_000_15d0:
    call ValidatePosition
    call GetRandomPiece
    call ProcessInputGame
    ld a, [$c698]
    call DisplayResults
    call CalcResults
    ld a, [$c698]
    call DisplayResults

jr_000_15e8:
    ld hl, $c200
    ld [hl], $01
    ret


ProcessFalling::
    ld hl, $15fe
    ld a, [$c6e2]
    cp $14
    jr c, jr_000_15fa

    ld a, $13

jr_000_15fa:
    call GetArrayElement
    ret


    ld e, $1c
    ld a, [de]
    add hl, de
    jr @+$19

    ld d, $14
    inc de
    ld [de], a
    ld de, $0f10
    ld c, $0d
    inc c
    dec bc
    ld a, [bc]
    add hl, bc
    ld [$95fa], sp
    add $fe
    ld [$1120], sp
    ld a, [$c6bf]
    dec a
    dec a
    ld [$c6bf], a
    and a
    jr nz, jr_000_162a

    ld [$c69d], a
    ld [$c6ae], a

jr_000_162a:
    ld a, $26
    call PlaySound
    ld hl, $0005
    call $432f
    call MovePieceUp
    cp $10
    ret z

    inc a
    inc a
    ld [hl], a
    ld a, [PIECE_FALL_POS]
    ld h, a
    ld a, [PIECE_ROTATION]
    sla a
    sla a
    ld l, a
    xor a
    inc h
    call DrawGridPiece
    ld b, $00
    call UpdateBoard
    ret


UpdateBoard::
    ld a, [PIECE_ROTATION]
    add $0a
    swap a
    ld e, a
    ld d, $c2
    ld a, $06
    ld [de], a
    inc e
    inc e
    ld a, b
    ld [de], a
    inc de
    inc de
    ld a, [PIECE_FALL_POS]
    dec a
    sla a
    sla a
    sla a
    ld [de], a
    inc de
    inc de
    ld a, [PIECE_ROTATION]
    sla a
    sla a
    sla a
    sla a
    sla a
    ld [de], a
    ld a, [PIECE_ROTATION]
    ld hl, $c6cb
    call GetArrayElement
    ld [hl], $0a
    ret


ScanBoard::
    call UpdateFallTimer
    and a
    jp z, HandlePieceLanding

    push af
    call MovePieceUp
    pop af
    ld [hl], a
    push af
    call MovePieceDown
    pop af
    ld b, a
    ld a, [PIECE_FALL_POS]
    sub b
    cpl
    inc a
    ld b, a
    srl a
    ldh [SCREEN_STATE], a
    push bc
    push hl
    ld hl, $c6fc
    ld b, [hl]
    add b
    or $40
    ld [$c6e6], a
    pop hl
    pop bc
    inc b
    ld a, b
    cp $01
    jr nz, jr_000_16c7

    xor a
    ld [$c6a2], a
    jr jr_000_16cb

jr_000_16c7:
    ld hl, $c6a2
    ld [hl], b

jr_000_16cb:
    ld a, [PIECE_FALL_POS]
    ld h, a
    ld a, [PIECE_ROTATION]
    sla a
    sla a
    ld l, a
    ld c, $00

jr_000_16d9:
    push bc
    push hl
    xor a
    dec h
    dec h
    call DrawGridPiece
    pop hl
    pop bc
    ld a, h
    cp $03
    jr nz, jr_000_16f1

    push bc
    push de
    push hl
    call $43f2
    pop hl
    pop de
    pop bc

jr_000_16f1:
    push bc
    push hl
    ld a, $07
    dec h
    call DrawGridPiece
    pop hl
    pop bc
    ld a, $25
    sub c
    call PlaySound
    inc h
    ld a, c
    cp $07
    jr z, jr_000_1708

    inc c

jr_000_1708:
    push bc
    ld b, $07
    call Send2PData
    pop bc
    dec b
    jr nz, jr_000_16d9

    push hl
    dec h
    dec h
    xor a
    push hl
    call DrawGridPiece
    pop hl
    inc h
    inc h
    xor a
    push hl
    call DrawGridPiece
    pop hl
    call MovePieceUp
    inc a
    inc a
    ld [hl], a
    call ShowResults
    pop hl
    call UpdateTimer
    pop bc
    ld a, [$c6bf]
    dec a
    ld [$c6bf], a
    xor a
    ret


UpdateFallTimer::
    ld a, [PIECE_FALL_POS]
    cp $0f
    jr z, jr_000_1754

    ld h, a
    ld a, [PIECE_ROTATION]
    ld l, a

jr_000_1746:
    call GetFallSpeed
    cp $08
    jr z, jr_000_1756

    inc h
    inc h
    ld a, h
    cp $0f
    jr nz, jr_000_1746

jr_000_1754:
    xor a
    ret


jr_000_1756:
    ld a, h
    ret


GetFallSpeed::
    ld de, BOARD_DATA
    ld a, l
    sla a
    sla a
    sla a
    sla a
    add e
    jr nc, jr_000_1768

    inc d

jr_000_1768:
    ld e, a
    ld a, h
    add e
    jr nc, jr_000_176e

    inc d

jr_000_176e:
    ld e, a
    ld a, [de]
    ret


UpdateTimer::
    push af
    push bc
    push de
    push hl
    call $43f2
    pop hl
    pop de
    pop bc
    pop af
    ldh a, [SCREEN_STATE]
    ld [$c6a2], a
    inc h
    inc h
    ld b, h
    ldh a, [SCREEN_STATE]
    ld hl, $18cb
    call GetArrayElement
    ldh [SCREEN_STATE], a
    ld hl, $c290
    ld [hl], $03
    inc hl
    inc hl
    ldh a, [SCREEN_STATE]
    ld [hl+], a
    inc hl
    ld a, b
    sla a
    sla a
    sla a
    ld [hl+], a
    inc hl
    ld a, [PIECE_ROTATION]
    sla a
    sla a
    sla a
    sla a
    sla a
    add $10
    ld [hl], a
    ld hl, $c290
    ld [hl], $03
    inc l
    inc l
    ld [hl], $00
    ld b, $0f
    call Send2PData
    ld hl, $c290
    ld [hl], $03

Process2Player::
    inc l
    inc l
    ld [hl], $10
    ld b, $0f
    call Send2PData
    ld hl, $c2a0
    ld de, $0010
    xor a
    ld b, a

jr_000_17d6:
    ld [hl], $04
    push hl
    inc l
    inc l
    ld [hl], b
    inc l
    inc l
    ld a, [$c294]
    ld [hl], a
    inc l
    inc l
    ld a, [$c296]
    ld [hl], a
    pop hl
    add hl, de
    inc b
    ld a, $04
    cp b
    jr nz, jr_000_17d6

    ld a, $01
    ld [$c6c8], a
    ld [$c6c9], a
    ld [$c6ca], a
    ld [$c6c7], a
    ld a, $2d
    call PlaySound
    ld hl, $c290
    ld [hl], $03
    inc l
    inc l
    ld [hl], $01
    ld b, $14
    call Send2PData
    ld a, $01
    ld hl, $c290
    ld [hl], $03
    inc hl
    inc hl

jr_000_181a:
    ld [hl], a
    ld b, $05
    call Send2PData
    inc a
    push hl
    ld hl, SCREEN_STATE
    ld b, [hl]
    pop hl
    inc b
    cp b
    jr nz, jr_000_181a

    ld b, $19
    call Send2PData
    ld a, [$c292]
    xor $10
    ld [$c292], a
    ld a, [$c292]
    cp $14
    jr nz, jr_000_1846

    ld a, $16
    call PlaySound
    jr jr_000_184b

jr_000_1846:
    ld a, $12
    call PlaySound

jr_000_184b:
    ld b, $23
    call Send2PData
    ld a, [$c6e6]
    ld [$c6fc], a
    ld a, [$c6a2]
    sla a
    ld hl, $18d2
    call GetArrayElement
    ld d, a
    inc hl
    ld a, [hl]
    ld l, a
    ld h, d
    call $432f
    call $42f5
    call $4681
    ld hl, $c290
    ld [hl], $00
    ret


Send2PData::
    push af
    push bc
    push de
    push hl
    ld a, [$c705]
    and a
    jr nz, jr_000_18af

    call CheckPause2P
    call $4bc5
    ld a, [GAME_STATE]
    cp $03
    jr nz, jr_000_18af

    call ReadJoypad
    call HandlePause
    ld a, $01
    ld [$c6e7], a
    call CheckMatch
    call $4408
    xor a
    ld [$c6e7], a
    call SetupMultiplayer
    call $234c
    pop hl
    pop de
    pop bc
    pop af
    dec b
    jr nz, Send2PData

    ret


jr_000_18af:
    pop hl
    pop de
    pop bc
    pop af
    pop af
    pop af
    ret


ShowResults::
    ld hl, $c697
    dec [hl]
    ret


HandlePieceLanding::
    ld b, $01
    call UpdateBoard
    call MovePieceDown
    ld a, $27
    call PlaySound
    pop af
    xor a
    ret


    ld bc, $0202
    ld [bc], a
    inc bc
    inc bc
    inc b
    nop
    ld d, b
    ld bc, $0100
    nop
    ld bc, $0200
    nop
    ld [bc], a
    nop
    dec b
    nop
    dec b
    nop
    dec b
    nop

CalcResults::
    call HandleGameOver
    ret


DisplayResults::
    ldh [SCREEN_STATE], a
    call SelectMenuItem
    cp $03
    jr c, jr_000_18f6

    ld hl, $c6f8
    ld [hl], $01

jr_000_18f6:
    ld b, $04
    ld hl, $c6a3

jr_000_18fb:
    ld [hl], $00
    inc hl
    dec b
    jr nz, jr_000_18fb

    ld b, a

jr_000_1902:
    ld hl, $c673
    ld a, b
    dec a
    call GetArrayElement
    push af
    ld hl, $ff97
    ld a, b
    dec a
    call GetArrayElement
    ld hl, $c6a3
    call GetArrayElement
    pop af
    push bc
    push hl
    call ProcessMenuSelection
    pop hl
    pop bc
    ld [hl], a
    dec b
    jr nz, jr_000_1902

    push bc
    push hl
    call CheckGameOver
    pop hl
    pop bc
    call TitleScreenLoop
    ld hl, $c6ad
    ld [hl], $00
    ret


CheckGameOver::
    ld a, [$c6f7]
    and a
    ret z

    xor a
    ld [$c6f7], a
    ld hl, $c6a3
    ld b, $04

jr_000_1943:
    ld a, [hl]
    and a
    jr nz, jr_000_194c

    inc hl
    dec b
    jr nz, jr_000_1943

    nop

jr_000_194c:
    ld a, $07
    ld [hl], a
    ret


HandleGameOver::
    ld hl, $c6a3
    xor a
    ld d, a
    ld b, a
    ld c, $04

jr_000_1958:
    ld a, [hl]
    and a
    call nz, DrawGameOver
    inc d
    dec c
    inc hl
    jr nz, jr_000_1958

    ret


DrawGameOver::
    push bc
    push de
    push hl
    ld b, a
    ld a, d
    call AnimateGameOver
    pop hl
    pop de
    pop bc
    ret


AnimateGameOver::
    push af
    inc a
    swap a
    ld l, a
    ld h, $c2
    ld [hl], $02
    inc hl
    inc hl
    ld [hl], b
    inc hl
    xor a
    ld [hl+], a
    ld [hl+], a
    pop af
    ld [hl+], a
    sla a
    sla a
    sla a
    sla a
    sla a
    ld [hl+], a
    ld [hl], $28
    inc hl
    ld [hl], $01
    inc hl
    ld [hl], b
    ret


GameOverSequence::
    ld b, $04
    ld hl, $c6a6

jr_000_1999:
    ld a, [hl]
    and a
    jr z, jr_000_19be

    ld c, a
    push hl
    ld h, $c2
    ld a, b
    add $04
    swap a
    ld l, a
    ld [hl], $02
    inc hl
    inc hl
    ld [hl], c
    inc hl
    inc hl
    inc hl
    inc hl
    ld a, b
    dec a
    sla a
    sla a
    sla a
    sla a
    sla a
    ld [hl], a
    pop hl

jr_000_19be:
    dec hl
    dec b
    jr nz, jr_000_1999

    ret


ProcessMenuInput::
    ld b, $04
    ld hl, $c250
    ld de, $000e
    xor a

jr_000_19cc:
    ld [hl+], a
    inc hl
    ld [hl], a
    add hl, de
    dec b
    jr nz, jr_000_19cc

    ret


ProcessMenuLoop::
    call ProcessMenuInput
    call CalcResults
    ld hl, $c6a9
    ld a, [hl]
    ld l, a
    ld h, $00
    add hl, hl
    add hl, hl
    push bc
    ld bc, $0b8d
    add hl, bc
    pop bc
    ld a, [hl]
    ld [$c6aa], a
    inc hl
    inc hl
    ld a, [hl]
    ld b, a
    ld a, [$c6b8]
    and a
    jr z, jr_000_19fd

    srl b
    jr jr_000_19fd

    ld b, $02

jr_000_19fd:
    ld a, b
    ld [$c6ac], a
    dec hl
    ld a, [hl]
    push af
    call DisplayResults
    pop af
    ld [$c697], a
    ld [$c698], a
    ret


UpdateMenuCursor::
    ld hl, $c6aa
    dec [hl]
    jr z, jr_000_1a2b

    call ProcessMenuInput
    ld a, [$c6ac]
    ld [$c6a7], a
    ld [$c696], a
    call CalcResults
    ld a, [$c698]
    call DisplayResults
    ret


jr_000_1a2b:
    ld hl, $c6a9
    ld a, [hl]
    cp $ff
    jr z, jr_000_1a3d

    cp $d1
    jr nz, jr_000_1a3c

    ld a, $c8
    ld [hl], a
    jr jr_000_1a3d

jr_000_1a3c:
    inc [hl]

jr_000_1a3d:
    push af
    call TitleInputHandler
    pop af
    ld a, [hl]
    jr ProcessMenuLoop

DrawMenuCursor::
    xor a
    ld [$c6aa], a
    ld a, [$c6b7]
    ld hl, LevelThresholds
    call GetArrayElement
    ld [$c6a9], a
    ld hl, $0b8d
    sla a
    sla a
    call GetArrayElement
    inc hl
    ld a, [hl+]
    push hl
    call DisplayResults
    pop hl
    ld a, [hl]
    ld b, a
    ld a, [$c6b8]
    and a
    jr z, jr_000_1a74

    srl b
    jr jr_000_1a74

    ld b, $02

jr_000_1a74:
    ld a, b
    ld [$c6ac], a
    ld [$c696], a
    ld [$c6a7], a
    jp ProcessMenuLoop


ProcessMenuSelection::
    ld a, [$c6f8]
    and a
    jr z, jr_000_1a8d

    xor a
    ld [$c6f8], a
    jr jr_000_1ae2

jr_000_1a8d:
    ld a, [PLAYER_MODE]
    and a
    jr z, jr_000_1ae2

    ld a, [$c6d6]
    and a
    jr nz, jr_000_1aa0

    ld a, [$c6d7]
    cp $03
    jr c, jr_000_1ae2

jr_000_1aa0:
    call InitTitleGfx
    ldh a, [TEXT_FADE]
    cp $08
    jr nc, jr_000_1ae2

    call DrawTitleText
    ldh a, [TEXT_FADE]
    srl a
    jr c, jr_000_1acc

    call Multiply
    cp $46
    jr c, jr_000_1afb

    cp $82
    jr c, jr_000_1afe

    cp $b9
    jr c, jr_000_1b01

    cp $f1
    jr c, jr_000_1b04

    ld a, $01
    ld [$c6ad], a
    jr jr_000_1b07

jr_000_1acc:
    ld a, $01
    ld [$c6f7], a
    call Multiply
    cp $4b
    jr c, jr_000_1afb

    cp $8c
    jr c, jr_000_1afe

    cp $c3
    jr c, jr_000_1b01

    jr jr_000_1b04

jr_000_1ae2:
    call Multiply
    cp $41
    jr c, jr_000_1afb

    cp $78
    jr c, jr_000_1afe

    cp $a0
    jr c, jr_000_1b01

    cp $d2
    jr c, jr_000_1b04

    cp $eb
    jr c, jr_000_1b07

    jr jr_000_1b0a

jr_000_1afb:
    ld a, $01
    ret


jr_000_1afe:
    ld a, $04
    ret


jr_000_1b01:
    ld a, $02
    ret


jr_000_1b04:
    ld a, $03
    ret


jr_000_1b07:
    ld a, $07
    ret


jr_000_1b0a:
    ld a, $08
    ret


InitTitleGfx::
    push bc
    xor a
    ldh [TEXT_FADE], a
    ld hl, $c4c8
    ld de, $0018
    ld c, $07

jr_000_1b19:
    ld b, $04

jr_000_1b1b:
    ld a, [hl+]
    inc hl
    inc hl
    inc hl
    cp $4a
    jr z, jr_000_1b28

    ldh a, [TEXT_FADE]
    inc a
    ldh [TEXT_FADE], a

jr_000_1b28:
    dec b
    jr nz, jr_000_1b1b

    add hl, de
    dec c
    jr nz, jr_000_1b19

    pop bc
    ret


DrawTitleText::
    push bc
    push hl
    ld hl, $c210
    ld b, $04

jr_000_1b38:
    ld a, [hl]
    and a
    call nz, AnimateTitle
    ld de, $0010
    add hl, de
    dec b
    jr nz, jr_000_1b38

    pop hl
    pop bc
    ret


AnimateTitle::
    ld c, $00
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld a, [hl]
    cp $07
    jr z, jr_000_1b58

    inc c

jr_000_1b58:
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    ld a, [TEXT_FADE]
    add c
    ld [TEXT_FADE], a
    ret


TitleScreenLoop::
    ld a, [$c6ad]
    and a
    ret z

    ld hl, $c6a3
    ld b, $04

jr_000_1b73:
    ld a, [hl]
    and a
    jr z, jr_000_1b79

    ld [hl], $07

jr_000_1b79:
    inc hl
    dec b
    jr nz, jr_000_1b73

    ret


TitleInputHandler::
    ld hl, $c6d1
    inc [hl]
    ld a, [hl]
    cp $0a
    ret nz

    xor a
    ld [hl], a
    call $4570
    ld hl, $0812
    call $455f
    ret


SelectMenuItem::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_000_1b9c

    ld a, [SCREEN_STATE]
    ret


jr_000_1b9c:
    ld a, [$c6fa]
    and a
    jr nz, jr_000_1ba6

    ld a, [SCREEN_STATE]
    ret


jr_000_1ba6:
    ld c, a
    ld a, $04
    ld hl, SCREEN_STATE
    ld b, [hl]
    sub b
    ret z

    ld b, a
    ld a, [$c6fa]
    cp b
    jr c, jr_000_1bbe

    sub b
    ld [$c6fa], a
    ld a, $04
    jr jr_000_1bc8

jr_000_1bbe:
    ld hl, SCREEN_STATE
    ld b, [hl]
    add b
    ld hl, $c6fa
    ld [hl], $00

jr_000_1bc8:
    push af
    ld a, $11
    call PlaySound
    pop af
    ret


DrawTextBox::
    ld hl, $c6af
    dec [hl]
    ret nz

    ld [hl], $20
    ld hl, $c210
    ld de, $0010
    ld b, $08

jr_000_1bdf:
    ld a, [hl]
    cp $02
    jr nz, jr_000_1be7

    call DrawTextString

jr_000_1be7:
    add hl, de
    dec b
    jr nz, jr_000_1bdf

    ret


DrawTextString::
    inc hl
    inc hl
    ld a, [hl]
    cp $07
    jr z, jr_000_1bfa

    cp $08
    jr z, jr_000_1bfa

    xor $10
    ld [hl], a

jr_000_1bfa:
    dec hl
    dec hl
    ret


ClearTextArea::
    ld hl, $c6af
    ld [hl], $20
    ret


InitTextSystem::
    call FillOAMGameTile
    call DrawLabel
    call UpdatePaletteFade
    ret


DrawLabel::
    ld d, $00
    call TileDataLookup1
    ld d, $00
    call TileDataLookup2
    ld d, $00
    call TileDataLookup3
    ld d, $00
    call TileDataLookup4
    ld d, $00
    call TileDataLookupA
    ld d, $00
    call TileDataLookupB
    ld d, $00
    call TileDataLookupC
    ld d, $00
    call TileDataLookupD

SetPalette::
    ld d, $00
    call TileDataLookup5
    ld d, $00
    call TileDataLookup6
    ld d, $00
    call TileDataLookup7
    ld d, $00
    call TileDataLookup8
    ld d, $00
    call TileDataLookup9
    ret


UpdatePaletteFade::
    ld hl, $0102
    ld de, $1d84
    call DrawStringToGrid
    ld hl, $010c
    ld de, $1d8b
    call DrawStringToGrid
    ld hl, $0402
    ld de, $1d92
    call DrawStringToGrid
    ld hl, $0b02
    ld de, $1d98
    call DrawStringToGrid
    ld hl, $0f02
    ld de, $1d9e
    call DrawStringToGrid
    ld hl, $0c09
    ld de, $1da2
    call DrawStringToGrid
    ld hl, $0c0f
    ld de, $1da6
    call DrawStringToGrid
    ld hl, $1010
    ld de, $1dab
    call DrawStringToGrid
    ld hl, $0704
    ld a, $77
    ld b, $05

jr_000_1c9e:
    push hl
    push af
    call CalcOAMAddress
    pop af
    ld [hl], a
    pop hl
    inc l
    inc l
    inc l
    inc a
    dec b
    jr nz, jr_000_1c9e

    ret


UpdateBGMap::
    call CalcOAMAddress
    ld a, d
    ldh [STATE_TRANSITION], a
    push hl
    ld d, $24
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl+], a
    ld d, $25
    ldh a, [STATE_TRANSITION]
    add d
    call TileDataLookup0
    ld d, $26
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl], a
    pop hl
    ld de, $0014
    add hl, de

jr_000_1cce:
    push hl
    ld d, $27
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl+], a
    ld e, c
    ld d, $00
    add hl, de
    ld d, $27
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl], a
    pop hl
    ld de, $0014
    add hl, de
    dec b
    jr nz, jr_000_1cce

    ld d, $28
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl+], a
    ld d, $25
    ldh a, [STATE_TRANSITION]
    add d
    call TileDataLookup0
    ld d, $29
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl], a
    ret


TileDataLookup0::
    ld d, c

jr_000_1cfd:
    ld [hl+], a
    dec d
    jr nz, jr_000_1cfd

    ret


TileDataLookup1::
    ld hl, $0000
    ld bc, $0108
    call UpdateBGMap
    ret


TileDataLookup2::
    ld hl, $000a
    ld bc, $0108
    call UpdateBGMap
    ret


TileDataLookup3::
    ld hl, $0400
    ld bc, $0412
    call UpdateBGMap
    ret


TileDataLookup4::
    ld hl, $0301
    ld bc, $0105
    call UpdateBGMap
    ret


TileDataLookup5::
    ld hl, $0603
    ld bc, $0101
    call UpdateBGMap
    ret


TileDataLookup6::
    ld hl, $0606
    ld bc, $0101
    call UpdateBGMap
    ret


TileDataLookup7::
    ld hl, $0609
    ld bc, $0101
    call UpdateBGMap
    ret


TileDataLookup8::
    ld hl, $060c
    ld bc, $0101
    call UpdateBGMap
    ret


TileDataLookup9::
    ld hl, $060f
    ld bc, $0101
    call UpdateBGMap
    ret


TileDataLookupA::
    ld hl, $0b00
    ld bc, $0112
    call UpdateBGMap
    ret


TileDataLookupB::
    ld hl, $0a01
    ld bc, $0105
    call UpdateBGMap
    ret


TileDataLookupC::
    ld hl, $0f00
    ld bc, $0112
    call UpdateBGMap
    ret


TileDataLookupD::
    ld hl, $0e01
    ld bc, $0103
    call UpdateBGMap
    ret


    add b
    ld c, d
    add [hl]
    add b
    adc h
    add h
    rst $38
    add c
    ld c, d
    add [hl]
    add b
    adc h
    add h
    rst $38
    adc e
    add h
    sub l
    add h
    adc e
    rst $38
    sub d
    adc a
    add h
    add h
    add e
    rst $38
    add c
    add [hl]
    adc h
    rst $38
    adc e
    adc [hl]
    sub [hl]
    rst $38
    add a
    adc b
    add [hl]
    add a
    rst $38
    adc [hl]
    add l
    add l
    rst $38
    ld bc, $0101
    dec bc
    inc c
    ld [$0e0c], sp
    db $10
    ld b, $10
    add hl, bc
    db $10
    inc c
    db $10
    rrca

UpdateHighScore::
    ld b, $08
    ld hl, $1daf

jr_000_1dc4:
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    ld e, a
    push hl
    ld h, d
    ld l, e
    call CalcOAMAddress
    ld [hl], $4a
    pop hl
    dec b
    jr nz, jr_000_1dc4

    ld a, [$c6b2]
    and a
    jr nz, jr_000_1de2

    ld hl, $0101
    call LoadSettings
    jr jr_000_1de8

jr_000_1de2:
    ld hl, $010b
    call LoadSettings

jr_000_1de8:
    ld a, [$c6b4]
    and a
    jr nz, jr_000_1df6

    ld hl, $0c08
    call LoadSettings
    jr jr_000_1dfc

jr_000_1df6:
    ld hl, $0c0e
    call LoadSettings

jr_000_1dfc:
    ld a, [$c6b5]
    and a
    jr nz, jr_000_1e09

    ld hl, $1006
    call LoadSettings
    ret


jr_000_1e09:
    cp $01
    jr nz, jr_000_1e14

    ld hl, $1009
    call LoadSettings
    ret


jr_000_1e14:
    cp $02
    jr nz, jr_000_1e1f

    ld hl, $100c
    call LoadSettings
    ret


jr_000_1e1f:
    ld hl, $100f
    call LoadSettings
    ret


LoadSettings::
    call CalcOAMAddress
    ld [hl], $9a
    ret


SaveSettings::
    ld a, [de]
    cp $ff
    ret z

    ld h, a
    inc de
    ld a, [de]
    ld l, a
    inc de
    call CalcOAMAddress
    ld a, [de]
    inc de
    ld [hl], a
    jr SaveSettings

    inc b
    ld bc, $0471
    rlca
    ld [hl], b
    dec bc
    ld bc, $0b71
    rlca
    ld [hl], b
    rrca
    ld bc, $0f71
    dec b
    ld [hl], b
    rst $38

ApplySettings::
    ld hl, $1e75
    ld de, $c290
    ld bc, $0007
    call MemcopyCall
    ld hl, $1e7c
    ld de, $c2a0
    ld bc, $0007
    call MemcopyCall
    ld hl, $1e83
    ld de, $c2b0
    ld bc, $0007
    call MemcopyCall
    ret


    dec b
    nop
    nop
    nop
    ld [hl], e
    nop
    jr nc, jr_000_1e82

    nop
    ld bc, $7301
    nop

jr_000_1e82:
    ld c, b
    dec b
    nop
    ld [bc], a
    ld [bc], a
    ld [hl], e
    nop
    ld h, b

ResetSettings::
    ld a, $1b
    ld [$c6c1], a
    ld [$c6c2], a
    ret


OptionsScreen::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jp nz, UpdateGameLoop

    jp ProcessRoundEndLoop


    ret


    call Multiply
    call $7c02
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_1ec7

    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_1ebe

jr_000_1eb1:
    ldh a, [SERIAL_DONE]
    and a
    jr z, jr_000_1eb1

    xor a
    ldh [SERIAL_DONE], a
    ld a, [LINK_RECV]
    jr jr_000_1ec9

jr_000_1ebe:
    ldh a, [JOYPAD_PRESSED]
    ld [LINK_SEND], a
    ld a, $81
    ldh [rSC], a

jr_000_1ec7:
    ldh a, [JOYPAD_PRESSED]

jr_000_1ec9:
    and a
    ret z

    bit 3, a
    jr z, jr_000_1eef

    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_1ee7

    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_1ee7

    call $4bc5
    xor a
    ld [LINK_SEND], a
    ld a, $81
    ldh [rSC], a

jr_000_1ee7:
    call InitGameState
    ld a, $02
    ldh [GAME_STATE], a
    ret


jr_000_1eef:
    bit 7, a
    jr nz, jr_000_1f00

    bit 6, a
    jr nz, jr_000_1f10

    bit 4, a
    jr nz, jr_000_1f21

    bit 5, a
    jr nz, jr_000_1f50

    ret


jr_000_1f00:
    ld a, [MENU_CURSOR]
    inc a
    cp $04
    jr nz, jr_000_1f09

    xor a

jr_000_1f09:
    ld [MENU_CURSOR], a
    call UpdateCursorDisplay
    ret


jr_000_1f10:
    ld a, [MENU_CURSOR]
    dec a
    cp $ff
    jr nz, jr_000_1f1a

    ld a, $03

jr_000_1f1a:
    ld [MENU_CURSOR], a
    call UpdateCursorDisplay
    ret


jr_000_1f21:
    ld hl, $c6b2
    ld a, [MENU_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, $1f4c
    ld a, [MENU_CURSOR]
    call GetArrayElement
    cp b
    pop hl
    ret z

    inc [hl]
    ld a, $b5
    cp l
    jr nz, jr_000_1f42

    call ApplyGameSettings

jr_000_1f42:
    call DrawOptionValues
    call DrawOptionLabel
    call UpdateHighScore
    ret


    ld [bc], a
    dec b
    ld [bc], a
    inc b

jr_000_1f50:
    ld hl, $c6b2
    ld a, [MENU_CURSOR]
    call GetArrayElement
    and a
    ret z

    dec [hl]
    ld a, $b5
    cp l
    jr nz, jr_000_1f64

    call ApplyGameSettings

jr_000_1f64:
    call DrawOptionValues
    call DrawOptionLabel
    call UpdateHighScore
    ret


ApplyGameSettings::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_1f87

    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_1f81

    ld a, $50
    call PlaySound
    ret


jr_000_1f81:
    ld a, $4c
    call PlaySound
    ret


jr_000_1f87:
    call ApplySettings
    ld a, [$c6b5]
    and a
    jr nz, jr_000_1fa5

    ld a, $34
    ld [BGM_INDEX], a
    ld a, $38
    call PlaySound
    ld a, $1b
    ld [$c6c2], a
    ld a, $01
    ld [$c6c1], a
    ret


jr_000_1fa5:
    cp $01
    jr nz, jr_000_1fbe

    ld a, $3c
    ld [BGM_INDEX], a
    ld a, $40
    call PlaySound
    ld a, $2a
    ld [$c6c2], a
    ld a, $01
    ld [$c6c1], a
    ret


jr_000_1fbe:
    cp $02
    jr nz, jr_000_1fd7

    ld a, $44
    ld [BGM_INDEX], a
    ld a, $48
    call PlaySound
    ld a, $0c
    ld [$c6c2], a
    ld a, $01
    ld [$c6c1], a
    ret


jr_000_1fd7:
    ld a, $ff
    ld [BGM_INDEX], a
    ld a, $ff
    call PlaySound
    ret


UpdateCursorDisplay::
    push af
    call DrawLabel
    call UpdatePaletteFade
    call DrawOptionValues
    ld de, $1e3d
    call SaveSettings
    pop af
    and a
    ld d, $06
    jp z, DrawOptionLabel

    cp $01
    jp z, SaveConfig1

    cp $02
    jp z, SaveConfig2

    cp $03
    jp z, SaveConfig3

SaveConfig1::
    call TileDataLookup4
    ld de, $2026
    call SaveSettings
    ret


SaveConfig2::
    call TileDataLookupB
    ld de, $202d
    call SaveSettings
    ret


SaveConfig3::
    call TileDataLookupD
    ld de, $2034
    call SaveSettings
    ret


    inc b
    ld bc, $0476
    rlca
    ld [hl], l
    rst $38
    dec bc
    ld bc, $0b76
    rlca
    ld [hl], l
    rst $38
    rrca
    ld bc, $0f76
    dec b
    ld [hl], l
    rst $38
    ret


DrawOptionValues::
    call SetPalette
    ld a, [$c6b3]
    and a
    jr z, jr_000_2053

    cp $01
    jr z, jr_000_2059

    cp $02
    jr z, jr_000_205f

    cp $03
    jr z, jr_000_2065

    jr jr_000_206b

jr_000_2053:
    ld d, $06
    call TileDataLookup5
    ret


jr_000_2059:
    ld d, $06
    call TileDataLookup6
    ret


jr_000_205f:
    ld d, $06
    call TileDataLookup7
    ret


jr_000_2065:
    ld d, $06
    call TileDataLookup8
    ret


jr_000_206b:
    ld d, $06
    call TileDataLookup9
    ret


DrawOptionLabel::
    ld a, [MENU_CURSOR]
    and a
    ret nz

    ld d, $00
    call TileDataLookup1
    ld d, $00
    call TileDataLookup2
    ld a, [$c6b2]
    and a
    jr nz, jr_000_208c

    ld d, $06
    call TileDataLookup1

DrawOptionItem::
    ret


jr_000_208c:
    ld d, $06
    call TileDataLookup2
    ret


SerialHandler::
    push af
    push bc
    push de
    push hl
    ld a, [LINK_ROLE]
    and a
    jr z, jr_000_20b3

    ldh a, [rSB]
    ld [LINK_RECV], a
    ld a, [LINK_SEND]
    ldh [rSB], a
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_20d2

    ld a, $80
    ldh [rSC], a
    jr jr_000_20d2

jr_000_20b3:
    ldh a, [rSB]
    ld [LINK_RECV], a
    cp $02
    jr z, jr_000_20cf

    xor a
    ldh [rSB], a
    ld a, $03
    ldh [rDIV], a

WaitDIVTimer::
    ldh a, [rDIV]
    bit 7, a
    jr nz, WaitDIVTimer

    ld a, $80
    ldh [rSC], a
    jr jr_000_20d2

jr_000_20cf:
    xor a
    ldh [rSB], a

jr_000_20d2:
    ld a, $01
    ldh [SERIAL_DONE], a
    pop hl
    pop de
    pop bc
    pop af
    reti


InitTitleUI::
    ld hl, $c4b5
    ld bc, $0410
    ld a, $80
    call FillRect
    ld hl, $c4c5
    ld bc, $0402
    ld a, $c0
    call FillRect
    ld hl, $c4b1
    ld bc, $0102
    ld a, $50
    call FillRect
    ld hl, $c507
    ld bc, $0a0a
    ld a, $d0
    call FillRect
    ld hl, $c575
    ld bc, $0504
    ld a, $34
    call FillRect
    ld hl, $c510
    ld bc, $0107
    ld a, $70
    call FillRect
    xor a
    ld [$c6be], a

ResetTitleState::
    ld [$c6bc], a
    ld a, $05
    ld [$c6bd], a
    xor a
    ld [LINK_ROLE], a
    ld [PLAYER_MODE], a
    ld [MENU_CURSOR], a
    ld [LINK_RECV], a
    ld [LINK_SEND], a
    inc a
    ld [$c620], a
    ld [$ff94], a
    ld [$c66e], a
    call $46d7
    ret


DrawStringToGrid::
    push hl
    call CalcOAMAddress

jr_000_214b:
    ld a, [de]
    cp $ff
    jr z, jr_000_2154

    ld [hl+], a
    inc de
    jr jr_000_214b

jr_000_2154:
    inc de
    pop hl
    ld bc, $0014
    add hl, bc
    ret


InitGameVars::
    xor a
    ld [$c701], a
    ld [$c702], a
    ld [$c6d2], a
    ld [$c6d3], a
    ld [$c6d4], a
    ld [$c6d5], a
    ld [$c6fc], a
    ld [$c6fa], a
    ld [$c6f4], a
    ld [$c6f3], a
    ld [$c705], a
    ld [$c706], a
    call Multiply
    call $46ff
    call $4763
    ret


StartGameplay::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_000_21ae

    call InitP1Settings
    call InitP2Settings
    call ApplyGameSettings
    ret


    call ApplyGameSettings
    call InitTextSystem
    call ApplySettings
    call ResetSettings
    xor a
    call UpdateCursorDisplay
    call UpdateHighScore
    ret


jr_000_21ae:
    ld a, [LINK_ROLE]
    cp $02
    jr z, jr_000_21b9

    ld a, $6b
    jr jr_000_21bb

jr_000_21b9:
    ld a, $6d

jr_000_21bb:
    call PlaySound
    call DisplayP1Score
    call DisplayP2Score
    ret


SetupMultiplayer::
    call Setup2PField
    call DrawField1
    call DrawField3
    call DrawFieldBorder
    ret


Setup2PField::
    ld hl, $c6c8
    xor a
    cp [hl]
    ret z

    ld hl, $c2b6
    ld a, [hl]
    call SetupLinkCable
    cp $10
    ret z

    ld [hl], a
    dec l

Jump_000_21e4:
    dec l
    ld a, [hl]
    call SetupLinkCable
    ld [hl], a
    ret


SetupLinkCable::
    push hl
    ld b, a
    ld a, [$c6c3]
    ld hl, $22cc
    call GetArrayElement
    cp $10
    jr z, jr_000_2201

    add b
    ld hl, $c6c3
    inc [hl]
    pop hl
    ret


jr_000_2201:
    xor a
    ld [$c6c8], a
    ld [$c6c3], a
    ld [$c2b0], a
    ld a, $10
    pop hl
    ret


DrawField1::
    ld hl, $c6c9
    xor a
    cp [hl]
    ret z

    ld hl, $c2a6
    ld a, [hl]
    call DrawField2
    cp $10
    ret z

    cpl
    inc a
    add b
    ld [hl], a
    dec l
    dec l
    ld a, [hl]
    call DrawField2
    add b
    ld [hl], a
    ret


DrawField2::
    push hl
    ld b, a
    ld a, [$c6c4]
    ld hl, $22cc
    call GetArrayElement
    cp $10
    jr z, jr_000_2241

    ld hl, $c6c4
    inc [hl]
    pop hl
    ret


jr_000_2241:
    xor a
    ld [$c6c9], a
    ld [$c6c4], a
    ld [$c2a0], a
    ld a, $10
    pop hl
    ret


DrawField3::
    ld hl, $c6ca
    xor a
    cp [hl]
    ret z

    ld hl, $c2d6
    ld a, [hl]
    call DrawField4
    cp $10
    ret z

    ld [hl], a
    dec l
    dec l
    ld a, [hl]
    call DrawField4
    ld [hl], a
    ret


DrawField4::
    push hl
    ld b, a
    ld a, [$c6c5]
    ld hl, $230f
    call GetArrayElement
    cp $10
    jr z, jr_000_227e

    add b
    ld hl, $c6c5
    inc [hl]
    pop hl
    ret


jr_000_227e:
    xor a
    ld [$c6ca], a
    ld [$c6c5], a
    ld [$c2d0], a
    ld a, $10
    pop hl
    ret


DrawFieldBorder::
    ld hl, $c6c7
    xor a
    cp [hl]
    ret z

    ld hl, $c2c6
    ld a, [hl]
    call DrawFieldRow
    cp $10
    ret z

    cpl
    inc a
    add b
    ld [hl], a
    dec l
    dec l
    ld a, [hl]
    call DrawFieldRow

DrawFieldTile::
    add b
    ld [hl], a
    ret


DrawFieldRow::
    push hl
    ld b, a
    ld a, [$c6c6]
    ld hl, $230f
    call GetArrayElement
    cp $10
    jr z, jr_000_22be

    ld hl, $c6c6
    inc [hl]
    pop hl
    ret


jr_000_22be:
    xor a
    ld [$c6c7], a
    ld [$c6c6], a
    ld [$c2c0], a
    ld a, $10
    pop hl
    ret


    ld bc, $01ff
    rst $38
    ld bc, $01ff
    nop
    ld bc, $0100
    rst $38
    ld bc, $0100
    ld bc, $0001
    ld bc, $0100
    ld bc, $0101
    ld bc, $0101
    ld bc, $0100
    nop
    ld bc, $0101
    nop
    ld bc, $0100
    ld bc, $0001
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0110
    nop
    ld bc, $0100
    ld bc, $0001
    ld bc, $0100
    ld bc, $0001
    ld bc, $0101
    ld bc, $0101
    ld bc, $0001
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0101
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $2110
    set 0, [hl]
    ld b, $00

jr_000_2351:
    xor a
    cp [hl]
    jr z, jr_000_2359

    dec [hl]
    call z, ResetTimers

jr_000_2359:
    inc hl
    inc b
    ld a, $04
    cp b
    jr nz, jr_000_2351

    ret


ResetTimers::
    push bc
    push hl
    ld a, b
    add $0a
    swap a
    ld l, a
    ld h, $c2
    call UpdateTimerDisplay
    pop hl
    pop bc
    ret


UpdateTimerDisplay::
    ld b, $10
    xor a

jr_000_2374:
    ld [hl+], a
    dec b
    jr nz, jr_000_2374

    ret


TimerTick::
    ret


TimerTickCore::
    ld a, [GAME_STATE]
    cp $03
    ret nz

    ld a, [TWO_PLAYER_FLAG]
    and a
    ret z

    ld a, [PAUSE_FLAG]
    and a
    jr z, jr_000_239b

    ld a, [LINK_ROLE]
    cp $01
    ret nz

    ld a, $f0
    ld [LINK_SEND], a
    ld a, $81
    ldh [rSC], a
    ret


jr_000_239b:
    ld a, [$c6fe]
    ld hl, $c6fc
    add l
    ld l, a
    jr nc, jr_000_23a6

    inc h

jr_000_23a6:
    ld a, [$c6fe]
    inc a
    cp $02
    jr c, jr_000_23af

    xor a

jr_000_23af:
    ld [$c6fe], a
    ld a, [hl]
    ld [LINK_SEND], a
    xor a
    ld [hl], a
    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_23c3

    ld a, $81
    ldh [rSC], a

jr_000_23c3:
    ld a, [LINK_RECV]
    cp $f0
    jr z, jr_000_23de

    bit 7, a
    jr z, jr_000_23d1

    jp ProcessBit5


jr_000_23d1:
    bit 5, a
    jr z, jr_000_23d8

    jp ProcessBit7


jr_000_23d8:
    bit 6, a
    ret z

    jp ProcessBit6


jr_000_23de:
    ld a, $01
    ld [PAUSE_FLAG], a
    ret


ProcessBit6::
    res 6, a
    ld b, a
    ld a, [$c6fa]
    add b
    ld [$c6fa], a
    ret


ProcessBit5::
    ld b, $01
    bit 0, a
    jr z, jr_000_2404

    ld a, [$c704]
    and a
    jr nz, jr_000_2404

    ld hl, $c5dd
    ld a, $40
    ld [hl+], a
    ld [hl], a
    ld b, $00

jr_000_2404:
    ld a, b
    call FormatRankEntry
    ret


ProcessBit7::
    res 5, a
    ld hl, $c5de
    jp SpeedTable


SpeedTable::
    ld b, $00

jr_000_2413:
    cp $0a
    jr c, jr_000_241c

    inc b
    sub $0a
    jr jr_000_2413

jr_000_241c:
    add $40
    ld [hl-], a
    ld a, b
    add $40
    ld [hl], a
    ret


CalcDifficulty::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret z

    xor a
    ldh [ANIM_FRAME], a
    ld hl, $c4c8
    ld de, $0018
    ld c, $07

jr_000_2434:
    ld b, $04

jr_000_2436:
    ld a, [hl+]
    inc hl
    inc hl
    inc hl
    cp $4a
    jr z, jr_000_2443

    ldh a, [ANIM_FRAME]
    inc a
    ldh [ANIM_FRAME], a

jr_000_2443:
    dec b
    jr nz, jr_000_2436

    add hl, de
    dec c
    jr nz, jr_000_2434

    ldh a, [ANIM_FRAME]
    ld hl, $c566
    call SpeedTable
    ldh a, [ANIM_FRAME]
    or $20
    ld [$c6fd], a
    ret


UpdateDifficulty::
    push af
    push bc
    push de
    push hl
    ld b, a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_249d

    ld a, b
    or $80
    ldh [ANIM_FRAME], a

jr_000_246a:
    ldh a, [ANIM_FRAME]
    ld [LINK_SEND], a
    ld [$c6fc], a
    ld [$c6fd], a
    ld a, [LINK_RECV]
    bit 7, a
    jr z, jr_000_246a

    res 7, a
    ld [$c708], a
    ldh a, [ANIM_FRAME]
    ld [LINK_SEND], a
    ld [$c6fc], a
    ld [$c6fd], a
    call $4bc5
    ldh a, [ANIM_FRAME]
    ld [LINK_SEND], a
    ld [$c6fc], a
    ld [$c6fd], a
    call $4bc5

jr_000_249d:
    pop hl
    pop de
    pop bc
    pop af
    ret


UpdateGameLoop::
    call UpdateGameField
    call FormatNumber
    call ContinueCountdown
    call Multiply
    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_24d9

    ldh a, [JOYPAD_PRESSED]
    and a
    ret z

    push af
    xor a
    ld [GAME_MODE_FLAG], a
    ld a, $0f
    ld [$c6f2], a
    pop af
    bit 3, a
    jr z, jr_000_24ff

    call $4bc5
    xor a
    ld [LINK_SEND], a
    ld a, $55
    ldh [rSB], a
    ld a, $81
    ldh [rSC], a
    jr jr_000_24ed

jr_000_24d9:
    ld a, [LINK_RECV]
    cp $55
    jr nz, jr_000_24e5

    xor a
    ldh [rSB], a
    jr jr_000_24ed

jr_000_24e5:
    ldh a, [JOYPAD_PRESSED]
    res 3, a
    and a
    ret z

    jr jr_000_24ff

jr_000_24ed:
    xor a
    ld [LINK_SEND], a
    ld [LINK_RECV], a
    call $4bc5
    call InitGameState
    ld a, $02
    ldh [GAME_STATE], a
    ret


jr_000_24ff:
    bit 6, a
    jr nz, jr_000_2510

    bit 7, a
    jr nz, jr_000_251f

    bit 4, a
    jr nz, jr_000_252f

    bit 5, a
    jr nz, jr_000_2550

    ret


jr_000_2510:
    ld a, $28
    call PlaySound
    ld a, [MENU_SELECT]
    and a
    ret z

    ld hl, MENU_SELECT
    dec [hl]
    ret


jr_000_251f:
    ld a, $28
    call PlaySound
    ld a, [MENU_SELECT]
    cp $01
    ret z

    ld hl, MENU_SELECT
    inc [hl]
    ret


jr_000_252f:
    ld a, $28
    call PlaySound
    ld hl, $c6eb
    ld a, [MENU_SELECT]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, $254e
    ld a, [MENU_SELECT]
    call GetArrayElement
    cp b
    pop hl
    ret z

    inc [hl]
    ret


    dec b
    ld [bc], a

jr_000_2550:
    ld a, $28
    call PlaySound
    ld a, [MENU_SELECT]
    ld hl, $c6eb
    call GetArrayElement
    and a
    ret z

    dec [hl]
    ret


DisplayP1Score::
    ld a, $0f
    ld [$c6f2], a
    ret


DisplayP2Score::
    call DrawDigitSprite
    call DrawScoreDigits
    call DrawLevelDisplay
    call DrawLinesDisplay
    call DrawStatValue
    call DrawNextPiece
    call CalcBonus
    ret


FormatNumber::
    call DrawLinesDisplay
    call DrawStatValue
    call DrawNextPiece
    call CalcBonus
    ret


DrawDigitSprite::
    ld hl, $0000
    ld bc, $1412
    ld a, $d0
    call $44ea
    ld hl, $0301
    ld bc, $1206
    ld a, $4a
    call $44ea
    ld hl, $0b01
    ld bc, $1206
    ld a, $4a
    call $44ea
    ret


DrawScoreDigits::
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_25b9

    ld de, $25d2
    jr jr_000_25bc

jr_000_25b9:
    ld de, $25c3

jr_000_25bc:
    ld hl, $0103
    call DrawStringToGrid
    ret


    ld c, d
    ld [hl], b
    ld [hl], c
    ld [hl], d
    ld [hl], e
    ld c, d
    pop de
    jp nc, $744a

    ld [hl], l
    db $76
    ld [hl], a
    ld c, d
    rst $38
    ld c, d
    ld [hl], h
    ld [hl], l
    db $76
    ld [hl], a
    ld c, d
    pop de
    jp nc, $704a

    ld [hl], c
    ld [hl], d
    ld [hl], e
    ld c, d
    rst $38

CalcBonus::
    ld hl, $0708
    ld a, [MENU_SELECT]
    cp $01
    jr nz, jr_000_25f6

    ld a, [GAME_MODE_FLAG]
    and a
    jr z, jr_000_25f6

    ld de, $264e
    jr jr_000_2604

jr_000_25f6:
    ld a, [$c6ec]
    and a
    jr nz, jr_000_2601

    ld de, $2622
    jr jr_000_2604

jr_000_2601:
    ld de, $2638

jr_000_2604:
    call DrawStringToGrid
    call DrawStringToGrid
    ld hl, $0f08
    ld a, [$c700]
    and a
    jr nz, jr_000_2618

    ld de, $2622
    jr jr_000_261b

jr_000_2618:
    ld de, $2638

jr_000_261b:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


    cp h
    cp l
    cp [hl]
    cp a
    ld c, d
    ld c, d
    db $e4
    push hl
    and $e7
    rst $38
    ret nz

    pop bc
    jp nz, $4a9d

    ld c, d
    add sp, -$17
    ld [$ffeb], a
    call c, $dedd
    rst $18
    ld c, d
    ld c, d
    call nc, $d6d5
    rst $10
    rst $38
    ldh [$ffe1], a
    ldh [c], a
    db $e3
    ld c, d
    ld c, d
    ret c

    reti


    jp c, $ffdb

    call c, $dedd
    rst $18
    ld c, d
    ld c, d
    db $e4
    push hl
    and $e7
    rst $38
    ldh [$ffe1], a
    ldh [c], a
    db $e3
    ld c, d
    ld c, d
    add sp, -$17
    ld [$ffeb], a

DrawLevelDisplay::
    ld a, [LINK_ROLE]
    cp $02
    jr z, jr_000_267c

    ld a, $c3
    ld hl, $0402
    call DrawSpeedDisplay
    ld a, $c9
    ld hl, $0c02
    call DrawSpeedDisplay
    ret


jr_000_267c:
    ld a, $c9
    ld hl, $0402
    call DrawSpeedDisplay
    ld a, $c3
    ld hl, $0c02
    call DrawSpeedDisplay
    ret


DrawSpeedDisplay::
    push af
    call CalcOAMAddress
    pop af
    ld de, $0013
    ld [hl+], a
    inc a
    ld [hl], a
    add hl, de
    inc a
    ld [hl+], a
    inc a
    ld [hl], a
    add hl, de
    inc a
    ld [hl+], a
    inc a
    ld [hl], a
    ret


DrawLinesDisplay::
    ld hl, $0302
    call DrawStatLabel
    ret


DrawStatLabel::
    ld b, $04
    ld a, [MENU_SELECT]
    and a
    jr z, jr_000_26b7

    ld bc, $04aa
    jr jr_000_26ba

jr_000_26b7:
    ld bc, $04a6

jr_000_26ba:
    call $4501
    ret


DrawStatValue::
    ld hl, $0702
    call DrawStatRow
    ret


DrawStatRow::
    ld b, $04
    ld a, [MENU_SELECT]
    cp $01
    jr z, jr_000_26d3

    ld bc, $04b2
    jr jr_000_26d6

jr_000_26d3:
    ld bc, $04ae

jr_000_26d6:
    call $4501
    ret


DrawNextPiece::
    ld a, $04
    ld [ANIM_FRAME], a
    ld [STATE_TRANSITION], a
    ld a, [$c6eb]
    call DrawNextPieceSprite
    ld a, $0c
    ld [ANIM_FRAME], a
    ld a, $04
    ld [STATE_TRANSITION], a
    ld a, [$c6ff]
    call DrawPreview
    ret


DrawNextPieceSprite::
    ldh [TEXT_FADE], a
    ld a, [MENU_SELECT]
    and a
    jr nz, jr_000_270c

    ld a, [GAME_MODE_FLAG]
    and a
    jr z, jr_000_270c

    ld de, $2824
    jr jr_000_2722

jr_000_270c:
    ldh a, [TEXT_FADE]

DrawPreview::
    ld hl, $2734
    sla a
    sla a
    sla a
    sla a
    ld b, a
    sla a
    add b
    call GetArrayElement
    ld d, h
    ld e, l

jr_000_2722:
    ld a, [ANIM_FRAME]
    ld h, a
    ld a, [STATE_TRANSITION]
    ld l, a
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    ret


    ld a, [hl+]
    dec hl
    inc l
    inc h
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $ff
    dec l
    ld b, c
    ld a, c
    daa
    ld b, d
    ld a, b
    daa
    ld b, e
    ld a, b
    daa
    ld b, h
    ld a, b
    daa
    ld b, l
    ld a, b
    rst $38
    ld l, $7b
    cpl
    jr z, @+$7c

    add hl, hl
    jr z, jr_000_27d6

    add hl, hl
    jr z, jr_000_27d9

    add hl, hl
    jr z, jr_000_27dc

    add hl, hl
    rst $38
    inc h
    dec h
    ld h, $2a
    dec hl
    inc l
    inc h
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $ff
    daa
    ld b, c
    ld a, b
    dec l
    ld b, d
    ld a, c
    daa
    ld b, e
    ld a, b
    daa
    ld b, h
    ld a, b
    daa
    ld b, l
    ld a, b
    rst $38
    jr z, @+$7c

    add hl, hl
    ld l, $7b
    cpl
    jr z, jr_000_2806

    add hl, hl
    jr z, jr_000_2809

    add hl, hl
    jr z, jr_000_280c

    add hl, hl
    rst $38
    inc h
    dec h
    ld h, $24
    dec h
    ld h, $2a
    dec hl
    inc l
    inc h
    dec h
    ld h, $24
    dec h
    ld h, $ff
    daa
    ld b, c
    ld a, b
    daa
    ld b, d
    ld a, b
    dec l
    ld b, e
    ld a, c
    daa
    ld b, h
    ld a, b
    daa
    ld b, l
    ld a, b
    rst $38
    jr z, @+$7c

    add hl, hl
    jr z, @+$7c

    add hl, hl
    ld l, $7b
    cpl
    jr z, jr_000_2839

    add hl, hl
    jr z, jr_000_283c

    add hl, hl
    rst $38
    inc h
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $2a
    dec hl
    inc l
    inc h
    dec h
    ld h, $ff
    daa
    ld b, c

jr_000_27d6:
    ld a, b
    daa
    ld b, d

jr_000_27d9:
    ld a, b
    daa
    ld b, e

jr_000_27dc:
    ld a, b
    dec l
    ld b, h
    ld a, c
    daa
    ld b, l
    ld a, b
    rst $38
    jr z, @+$7c

    add hl, hl
    jr z, @+$7c

    add hl, hl
    jr z, jr_000_2866

    add hl, hl
    ld l, $7b
    cpl
    jr z, jr_000_286c

    add hl, hl
    rst $38
    inc h
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $2a
    dec hl
    inc l
    rst $38
    daa
    ld b, c

jr_000_2806:
    ld a, b
    daa
    ld b, d

jr_000_2809:
    ld a, b
    daa
    ld b, e

jr_000_280c:
    ld a, b
    daa
    ld b, h
    ld a, b
    dec l
    ld b, l
    ld a, c
    rst $38
    jr z, jr_000_2890

    add hl, hl
    jr z, jr_000_2893

    add hl, hl
    jr z, jr_000_2896

    add hl, hl
    jr z, jr_000_2899

    add hl, hl
    ld l, $7b
    cpl
    rst $38
    inc h
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $24
    dec h
    ld h, $ff
    daa
    ld b, c
    ld a, b
    daa
    ld b, d

jr_000_2839:
    ld a, b
    daa
    ld b, e

jr_000_283c:
    ld a, b
    daa
    ld b, h
    ld a, b
    daa
    ld b, l
    ld a, b
    rst $38
    jr z, @+$7c

    add hl, hl
    jr z, @+$7c

    add hl, hl
    jr z, @+$7c

    add hl, hl
    jr z, @+$7c

    add hl, hl
    jr z, jr_000_28cc

    add hl, hl
    rst $38

UpdateGameField::
    ld a, [$c6eb]
    swap a
    ld b, a
    ld a, [$c6ec]
    or b
    ld [LINK_SEND], a
    ld a, [LINK_ROLE]
    cp $01

jr_000_2866:
    jr nz, jr_000_286c

    ld a, $81
    ldh [rSC], a

jr_000_286c:
    ldh a, [SERIAL_DONE]
    and a
    jr z, jr_000_286c

    xor a
    ldh [SERIAL_DONE], a
    ld a, [LINK_RECV]
    ld b, a
    cp $55
    ret z

    swap a
    and $0f
    ld [$c6ff], a
    ld a, b
    and $0f
    ld [$c700], a
    ret


RefreshField::
    ld a, [$c756]
    and a
    ret nz

    ld a, $ff

jr_000_2890:
    ld [$c709], a

jr_000_2893:
    ld [$c714], a

jr_000_2896:
    ld [$c71f], a

jr_000_2899:
    ld [$c72a], a
    ld [$c735], a
    ld [$c740], a
    ld [$c756], a
    ret


ClearField::
    ld hl, $c621
    ld de, $c74b
    ld bc, $0005
    call Memcopy
    ld a, [SPRITE_ANIM_FRAME]
    ld [$c751], a
    ld a, [SPRITE_ANIM_STATE]
    ld [$c750], a
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_28d4

    ld hl, $c6d5
    ld de, $c752
    ld a, [hl-]
    ld [de], a

jr_000_28cc:
    inc de
    ld a, [hl-]
    ld [de], a
    inc de
    ld a, [hl-]
    ld [de], a
    jr jr_000_28e0

jr_000_28d4:
    ld hl, $c6db
    ld de, $c752
    ld bc, $0004
    call Memcopy

jr_000_28e0:
    ld hl, $c74b
    ld c, $0b

jr_000_28e5:
    ld a, [hl]
    and $0f
    ld [hl+], a
    dec c
    jr nz, jr_000_28e5

    xor a
    ldh [ANIM_FRAME], a
    ld hl, $c709
    ld a, [PLAYER_MODE]
    and a
    jr z, jr_000_28fb

    ld hl, $c72a

jr_000_28fb:
    ld c, $03
    ld b, $01

jr_000_28ff:
    push hl
    push bc
    ld a, [hl]
    inc a
    jr z, jr_000_294a

    ld de, $c74b
    ld c, $05
    call InitRound
    jr c, jr_000_294a

    jr nz, jr_000_293e

    ld de, $0005
    add hl, de
    ld de, $c750
    ld c, $02
    call InitRound
    jr c, jr_000_294a

    jr nz, jr_000_293e

    inc hl
    inc hl
    ld de, $c752
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_2937

    ld c, $03
    call InitRound
    jr c, jr_000_294a

    jr z, jr_000_294a

    jr jr_000_293e

jr_000_2937:
    ld c, $04
    call InitRound
    jr nc, jr_000_294a

jr_000_293e:
    pop bc
    pop hl
    ld de, $000b
    add hl, de
    inc b
    dec c
    jr nz, jr_000_28ff

    jr jr_000_29a0

jr_000_294a:
    pop bc
    ld a, b
    ldh [ANIM_FRAME], a
    cp $03
    jr z, jr_000_2996

    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_2978

    ld hl, $c714
    ld de, $c71f
    ld bc, $000b
    call Memcopy
    ldh a, [ANIM_FRAME]
    cp $01
    jr nz, jr_000_2996

    ld hl, $c709
    ld de, $c714
    ld bc, $000b
    call Memcopy
    jr jr_000_2996

jr_000_2978:
    ld hl, $c735
    ld de, $c740
    ld bc, $000b
    call Memcopy
    ldh a, [ANIM_FRAME]
    cp $01
    jr nz, jr_000_2996

    ld hl, $c72a
    ld de, $c735
    ld bc, $000b
    call Memcopy

jr_000_2996:
    pop de
    ld hl, $c74b
    ld bc, $000b
    call Memcopy

jr_000_29a0:
    call LCDOff
    call ClearOAM
    ld a, $03
    ld [$2100], a
    ld hl, $5400
    ld de, $9000
    ld bc, $0800
    call MemcopyCall
    ld hl, $5c00
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ld a, $01
    ld [$2100], a
    xor a
    ldh [rBGP], a
    call LCDOn
    ld hl, $c4a0
    ld bc, $0168
    ld d, $02
    call DrawCharacter
    ld a, $00
    ld hl, $c4b5
    ld bc, $0212
    call FillRect
    ld a, $24
    ld hl, $c4f7
    ld bc, $0106
    call FillRect
    ld hl, $c504
    ld a, $6f
    ld de, $7071
    call ApplyRoundSettings
    ld c, $06

jr_000_29fc:
    ld a, $72
    ld de, $2f73
    call ApplyRoundSettings
    dec c
    jr nz, jr_000_29fc

    ld a, $74
    ld de, $7576
    call ApplyRoundSettings
    ld a, $38
    ld hl, $c52d
    ld bc, $0103
    call FillRect
    ld a, $3b
    ld hl, $c555
    ld bc, $0103
    call FillRect
    ld a, $3e
    ld hl, $c57d
    ld bc, $0103
    call FillRect
    ld hl, $c534
    call NextRound
    ld hl, $c538
    call NextRound
    ld hl, $c53d
    call NextRound
    ld a, $2b
    ld hl, $c51d
    ld bc, $010d
    call FillRect
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_2a6b

    ld a, $4b
    ld hl, $c5a6
    ld bc, $0403
    call FillRect
    ld a, $57
    ld hl, $c5b0
    ld bc, $0406
    call FillRect
    jr jr_000_2a91

jr_000_2a6b:
    ld a, $77
    ld hl, $c527
    ld bc, $0103
    call FillRect
    ld a, $2a
    ld [$c4f8], a
    ld a, $7c
    ld hl, $c5a6
    ld bc, $0405
    call FillRect
    ld a, $90
    ld hl, $c5da
    ld bc, $0202
    call FillRect

jr_000_2a91:
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_2aa0

    ld de, $c709
    call SetupRound
    jp ApplyRoundSpeed


jr_000_2aa0:
    ld de, $c72a
    call SetupRound

ApplyRoundSpeed::
    call SetRoundSpeed
    xor a
    ldh [STATE_TRANSITION], a
    ldh a, [ANIM_FRAME]
    and a
    jp z, FillRectAlt

    ld b, $94
    ld c, $38
    ld hl, $c52d
    dec a
    jr z, jr_000_2acd

    ld b, $97
    ld c, $3b
    ld hl, $c555
    dec a
    jr z, jr_000_2acd

    ld b, $9a
    ld c, $3e
    ld hl, $c57d

jr_000_2acd:
    push bc
    push hl
    ld d, b
    ldh a, [STATE_TRANSITION]
    cp $1e
    jr c, jr_000_2ad7

    ld d, c

jr_000_2ad7:
    ld a, d
    ld bc, $0103
    call FillRect
    ldh a, [STATE_TRANSITION]
    inc a
    ldh [STATE_TRANSITION], a
    cp $3c
    jr c, jr_000_2aea

    xor a
    ldh [STATE_TRANSITION], a

jr_000_2aea:
    call $4bc5
    call ReadJoypad
    pop hl
    pop bc
    ldh a, [JOYPAD_PRESSED]
    and $0f
    jr z, jr_000_2acd

    ret


NextRound::
    ld de, $0028
    ld c, $03

jr_000_2afe:
    ld [hl], $7b
    add hl, de
    dec c
    jr nz, jr_000_2afe

    ret


InitRound::
    push hl

jr_000_2b06:
    ld a, [de]
    inc de
    ld b, a
    ld a, [hl+]
    cp b
    jr nz, jr_000_2b10

    dec c
    jr nz, jr_000_2b06

jr_000_2b10:
    pop hl
    ret


SetupRound::
    ld hl, $c530
    ld b, $03

jr_000_2b17:
    ld a, [de]
    inc a
    ret z

    ld c, $05
    ld a, $01
    call LoadRoundData
    inc hl
    inc hl
    ld c, $02
    ld a, $01
    call LoadRoundData
    inc hl
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_000_2b3d

    inc hl
    ld c, $03
    ld a, $01
    call LoadRoundData
    inc de
    inc hl
    jr jr_000_2b4e

jr_000_2b3d:
    ld c, $02
    ld a, $01
    call LoadRoundData
    ld a, $7a
    ld [hl+], a
    ld c, $02
    ld a, $00
    call LoadRoundData

jr_000_2b4e:
    push de
    ld de, $0019
    add hl, de
    pop de
    dec b
    jr nz, jr_000_2b17

    ret


LoadRoundData::
    push bc
    ldh [TEXT_FADE], a

jr_000_2b5b:
    ld a, [de]
    and $0f
    and a
    jr nz, jr_000_2b71

    ldh a, [TEXT_FADE]
    and a
    jr z, jr_000_2b71

    ld a, c
    cp $01
    jr nz, jr_000_2b6e

    ld a, $41
    ld [hl], a

jr_000_2b6e:
    inc hl
    jr jr_000_2b7b

jr_000_2b71:
    ld b, a
    xor a
    ldh [TEXT_FADE], a
    ld a, b
    and $0f
    add $41
    ld [hl+], a

jr_000_2b7b:
    inc de
    dec c
    jr nz, jr_000_2b5b

    pop bc
    ret


ApplyRoundSettings::
    ld [hl+], a
    ld b, $12
    ld a, d

jr_000_2b85:
    ld [hl+], a
    dec b
    jr nz, jr_000_2b85

    ld a, e
    ld [hl+], a
    ret


SetRoundSpeed::
    ld hl, $2b9d
    ld b, $04

jr_000_2b91:
    ld a, [hl+]
    ldh [rBGP], a
    ld c, $10
    call DrawString
    dec b
    jr nz, jr_000_2b91

    ret


    nop
    ld b, b
    sub b
    db $e4

InitP1Settings::
    ld a, $0f
    ld [$c6f2], a
    ret


InitP2Settings::
    call CheckWinCondition
    call ProcessWinLose
    call AnimateResult
    call DrawWinMessage1
    call DrawResultMessage1
    call DrawLoseMessage1
    call ShowFinalResult
    call ShowWinScreen
    call ProcessRestart
    call DrawContinue
    call UpdateContinue
    call ApplySettings
    call ResetSettings
    ld a, $34
    ld [BGM_INDEX], a
    ret


ProcessRoundEnd::
    call AnimateResult
    call DrawWinMessage1
    call DrawResultMessage1
    call DrawLoseMessage1
    call ProcessRestart
    call ShowFinalResult
    call ShowWinScreen
    call UpdateContinue
    ret


ProcessRoundEndLoop::
    call $7c02
    call ProcessRoundEnd
    call Multiply
    call ContinueCountdown
    ldh a, [JOYPAD_PRESSED]
    and a
    ret z

    push af
    xor a
    ld [GAME_MODE_FLAG], a
    ld a, $0f
    ld [$c6f2], a
    call DrawCountdownNum
    pop af
    bit 3, a
    jr z, jr_000_2c17

    call InitGameState
    ld a, $02
    ldh [GAME_STATE], a
    ret


jr_000_2c17:
    bit 6, a
    jr nz, jr_000_2c28

    bit 7, a
    jr nz, jr_000_2c32

    bit 4, a
    jr nz, jr_000_2c3d

    bit 5, a
    jr nz, jr_000_2c64

    ret


jr_000_2c28:
    ld a, [MENU_CURSOR]
    and a
    ret z

    ld hl, MENU_CURSOR
    dec [hl]
    ret


jr_000_2c32:
    ld a, [MENU_CURSOR]
    cp $03
    ret z

    ld hl, MENU_CURSOR
    inc [hl]
    ret


jr_000_2c3d:
    ld hl, $c6b2
    ld a, [MENU_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, $2c60
    ld a, [MENU_CURSOR]
    call GetArrayElement
    cp b
    pop hl
    ret z

    inc [hl]
    ld a, [MENU_CURSOR]
    cp $03
    ret nz

    call ApplyGameSettings
    ret


    ld [bc], a
    dec b
    ld [bc], a
    inc b

jr_000_2c64:
    ld a, [MENU_CURSOR]
    ld hl, $c6b2
    call GetArrayElement
    and a
    ret z

    dec [hl]
    ld a, [MENU_CURSOR]
    cp $03
    ret nz

    call ApplyGameSettings
    ret


CheckWinCondition::
    ld hl, $0000
    ld bc, $1412
    ld a, $cf
    call $44ea
    ld hl, $0301
    ld bc, $1202
    ld a, $4a
    call $44ea
    ld hl, $0601
    ld bc, $1204
    ld a, $4a
    call $44ea
    ld hl, $0b01
    ld bc, $1202
    ld a, $4a
    call $44ea
    ld hl, $0e01
    ld bc, DrawNumber
    ld a, $4a
    call $44ea
    ret


ProcessWinLose::
    ld hl, HeaderLogo
    ld de, $2cbc
    call DrawStringToGrid
    ret


    ld b, c
    ld c, d
    adc a
    adc e
    add b
    sbc b
    add h
    sub c
    ld c, d
    add [hl]
    add b
    adc h
    add h
    rst $38
    ld c, d
    sbc b
    adc [hl]
    sub d
    sub d
    sbc b
    ld c, d
    add h
    add [hl]
    add [hl]
    sub d
    ld c, d
    rst $38

ShowWinScreen::
    ld hl, $0b07
    ld a, [MENU_CURSOR]
    cp $02
    jr nz, jr_000_2cec

    ld a, [GAME_MODE_FLAG]
    and a
    jr z, jr_000_2cec

    ld de, $264e
    jr jr_000_2cfa

jr_000_2cec:
    ld a, [$c6b4]
    and a
    jr nz, jr_000_2cf7

    ld de, $2622
    jr jr_000_2cfa

jr_000_2cf7:
    ld de, $2638

jr_000_2cfa:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


DrawWinMessage1::
    ld hl, $0602
    call DrawWinMessage2
    ret


DrawWinMessage2::
    ld b, $04
    ld a, [MENU_CURSOR]
    cp $01
    jr z, jr_000_2d16

    ld bc, $04aa
    jr jr_000_2d19

jr_000_2d16:
    ld bc, $04a6

jr_000_2d19:
    call $4501
    ret


DrawLoseMessage1::
    ld hl, $0e02
    call DrawLoseMessage2
    ret


DrawLoseMessage2::
    ld a, [MENU_CURSOR]
    cp $03
    jr z, jr_000_2d30

    ld bc, $03b9
    jr jr_000_2d33

jr_000_2d30:
    ld bc, $03b6

jr_000_2d33:
    call $4501
    ret


DrawResultMessage1::
    ld hl, $0b02
    call DrawResultMessage2
    ret


DrawResultMessage2::
    ld b, $04
    ld a, [MENU_CURSOR]
    cp $02
    jr z, jr_000_2d4c

    ld bc, $04b2
    jr jr_000_2d4f

jr_000_2d4c:
    ld bc, $04ae

jr_000_2d4f:
    call $4501
    ret


AnimateResult::
    ld hl, $0302
    ld b, $04
    ld a, [MENU_CURSOR]
    and a
    jr z, jr_000_2d63

    ld bc, $04a2
    jr jr_000_2d66

jr_000_2d63:
    ld bc, $049e

jr_000_2d66:
    call $4501
    ret


ShowFinalResult::
    ld a, $07
    ld [ANIM_FRAME], a
    ld a, $04
    ld [STATE_TRANSITION], a
    ld a, [$c6b3]
    call WaitForRestart
    ret


WaitForRestart::
    ldh [TEXT_FADE], a
    ld a, [MENU_CURSOR]
    cp $01
    jr nz, jr_000_2d8f

    ld a, [GAME_MODE_FLAG]
    and a
    jr z, jr_000_2d8f

    ld de, $2824
    jr jr_000_2da5

jr_000_2d8f:
    ldh a, [TEXT_FADE]
    ld hl, $2734
    sla a
    sla a
    sla a
    sla a
    ld b, a
    sla a
    add b
    call GetArrayElement
    ld d, h
    ld e, l

jr_000_2da5:
    ld a, [ANIM_FRAME]
    ld h, a
    ld a, [STATE_TRANSITION]
    ld l, a
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    ret


ProcessRestart::
    ld hl, $0307
    ld a, [MENU_CURSOR]
    and a
    jr nz, jr_000_2dcb

    ld a, [GAME_MODE_FLAG]
    and a
    jr z, jr_000_2dcb

    ld de, $2e14
    jr jr_000_2dd9

jr_000_2dcb:
    ld a, [$c6b2]
    and a
    jr nz, jr_000_2dd6

    ld de, $2de0
    jr jr_000_2dd9

jr_000_2dd6:
    ld de, $2dfa

jr_000_2dd9:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


    db $f4
    db $ec
    db $ed
    xor $ef
    push af
    ld c, d
    ld a, [$fefd]
    db $d3
    ld c, d
    rst $38
    or $f0
    pop af
    ldh a, [c]
    di
    rst $30
    ld c, d
    ei
    dec c
    inc e
    dec e
    ld c, d
    rst $38
    ld c, d
    db $fc
    db $fd
    cp $d3
    ld c, d
    db $f4
    ld hl, sp-$13
    xor $ef
    push af
    rst $38
    ld c, d
    inc c
    dec c
    inc e
    dec e
    ld c, d
    or $f9
    pop af
    ldh a, [c]
    di
    rst $30
    rst $38
    ld c, d
    db $fc
    db $fd
    cp $d3
    ld c, d
    ld c, d
    ld a, [$fefd]
    db $d3
    ld c, d
    rst $38
    ld c, d
    inc c
    dec c
    inc e
    dec e
    ld c, d
    ld c, d
    ei
    dec c
    inc e
    dec e
    ld c, d
    rst $38

DrawContinue::
    ld hl, $0f10
    ld de, $2e38
    call DrawStringToGrid
    ret


    adc [hl]
    add l
    add l
    rst $38

UpdateContinue::
    ld hl, $0f06
    ld a, [MENU_CURSOR]
    cp $03
    jr nz, jr_000_2e58

    ld a, [$c6b5]
    cp $03
    jr nz, jr_000_2e58

    ld a, [GAME_MODE_FLAG]
    and a
    jr z, jr_000_2e58

    ld de, $2ea8
    jr jr_000_2e78

jr_000_2e58:
    ld a, [$c6b5]
    and a
    jr z, jr_000_2e70

    cp $01
    jr z, jr_000_2e75

    cp $02
    jr z, jr_000_2e6b

    ld de, $2e9d
    jr jr_000_2e78

jr_000_2e6b:
    ld de, $2e92
    jr jr_000_2e78

jr_000_2e70:
    ld de, $2e7c
    jr jr_000_2e78

jr_000_2e75:
    ld de, $2e87

jr_000_2e78:
    call DrawStringToGrid
    ret


    sbc d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    rst $38
    ld c, d
    ld c, d
    ld c, d
    sbc d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    rst $38
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    sbc d
    ld c, d
    ld c, d
    ld c, d
    rst $38
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    sbc d
    rst $38
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    rst $38
    ld b, $04
    ld a, [MENU_CURSOR]
    and a
    jr z, jr_000_2ec0

    ld bc, $04aa
    jr jr_000_2ec3

jr_000_2ec0:
    ld bc, $04a6

jr_000_2ec3:
    call $4501
    ret


ContinueCountdown::
    ld hl, $c6f2
    dec [hl]
    ret nz

    ld a, $0f
    ld [hl], a
    ld a, [GAME_MODE_FLAG]
    xor $01
    ld [GAME_MODE_FLAG], a
    ret


DrawCountdownNum::
    ld hl, $c292
    ld de, $0010
    ld b, $03

jr_000_2ee0:
    ld a, [hl]
    and $0f
    ld [hl], a
    add hl, de
    dec b
    jr nz, jr_000_2ee0

    ret


UpdateCountdownTimer::
    ld a, [$c7ce]
    and a
    ret z

    ld a, [$c7cf]
    xor $ff
    ld [$c7cf], a
    jr nz, jr_000_2f54

    ld a, [$c61e]
    swap a
    and $f0
    srl a
    ld de, $2ffb
    add e
    ld e, a
    jr nc, jr_000_2f09

    inc d

jr_000_2f09:
    ld hl, $c7be
    ld b, $07

jr_000_2f0e:
    ld a, [de]
    inc de
    swap a
    and $f0
    ld [hl+], a
    dec b
    jr nz, jr_000_2f0e

    ld a, [$c61d]
    and $f0
    srl a
    ld de, $2ffb
    add e
    ld e, a
    jr nc, jr_000_2f27

    inc d

jr_000_2f27:
    ld hl, $c7be
    ld b, $07

jr_000_2f2c:
    ld a, [de]
    inc de
    srl a
    srl a
    or [hl]
    ld [hl+], a
    dec b
    jr nz, jr_000_2f2c

    ld a, [$c61d]
    swap a
    and $f0
    srl a
    ld de, $2ffb
    add e
    ld e, a
    jr nc, jr_000_2f48

    inc d

jr_000_2f48:
    ld hl, $c7c6
    ld b, $07

jr_000_2f4d:
    ld a, [de]
    inc de
    ld [hl+], a
    dec b
    jr nz, jr_000_2f4d

    ret


jr_000_2f54:
    ld a, [$c61e]
    swap a
    and $f0
    srl a
    ld de, $2ffb
    add e
    ld e, a
    jr nc, jr_000_2f65

    inc d

jr_000_2f65:
    ld hl, $c7b6
    ld b, $07

jr_000_2f6a:
    ld a, [de]
    inc de
    swap a
    and $0f
    ld [hl+], a
    dec b
    jr nz, jr_000_2f6a

    ld a, [$c61e]
    and $f0
    srl a
    ld de, $2ffb
    add e
    ld e, a
    jr nc, jr_000_2f83

    inc d

jr_000_2f83:
    ld hl, $c7b6
    ld b, $07

jr_000_2f88:
    ld a, [de]
    inc de
    sla a
    sla a
    rl c
    or [hl]
    ld [hl+], a
    dec b
    jr nz, jr_000_2f88

    ld a, [$c61f]
    swap a
    and $f0
    srl a
    ld de, $2ffb
    add e
    ld e, a
    jr nc, jr_000_2fa6

    inc d

jr_000_2fa6:
    ld hl, $c7ae
    ld b, $07
    sla c

jr_000_2fad:
    ld a, [de]
    inc de
    sla c
    jr nc, jr_000_2fb5

    or $01

jr_000_2fb5:
    ld [hl+], a
    dec b
    jr nz, jr_000_2fad

    ret


RandomNext::
    ld a, [$c7ce]
    and a
    ret z

    dec a
    ld [$c7ce], a
    ld a, [$c7cf]
    and a
    jr nz, jr_000_2fe2

    ld de, $c7be
    ld hl, $9020
    ld b, $08

jr_000_2fd1:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2fd1

    ld b, $08

jr_000_2fda:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2fda

    ret


jr_000_2fe2:
    ld de, $c7ae
    ld hl, $9120
    ld b, $08

jr_000_2fea:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2fea

    ld b, $08

jr_000_2ff3:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2ff3

    ret


    jr c, @+$6e

    ld l, h
    ld l, h
    ld l, h
    ld l, h
    jr c, jr_000_3003

jr_000_3003:
    jr c, jr_000_301d

    jr jr_000_301f

    jr jr_000_3021

    jr jr_000_300b

jr_000_300b:
    ld a, b
    inc c
    inc c
    jr c, @+$62

    ld h, b
    ld a, h
    nop
    ld a, b
    inc c
    inc c
    jr c, jr_000_3024

    inc c
    ld a, b
    nop
    ld l, h
    ld l, h

jr_000_301d:
    ld l, h
    ld l, h

jr_000_301f:
    ld a, h
    inc c

jr_000_3021:
    inc c
    nop
    ld a, h

jr_000_3024:
    ld h, b
    ld h, b
    ld a, h
    inc c
    inc c
    ld a, b
    nop
    jr c, jr_000_308d

    ld h, b
    ld a, b
    ld l, h
    ld l, h
    jr c, jr_000_3033

jr_000_3033:
    ld a, h
    inc c
    ld [$1818], sp
    jr nc, jr_000_306a

    nop
    jr c, @+$6e

    ld l, h
    jr c, @+$6e

    ld l, h
    jr c, jr_000_3043

jr_000_3043:
    jr c, @+$6e

    ld l, h
    ld l, h
    inc a
    inc c
    jr c, ProcessRoundComplete

ProcessRoundComplete::
    ld hl, $c2a0
    ld de, $0010
    xor a
    ld b, a

jr_000_3053:
    ld [hl], $04
    push hl
    inc l
    inc l
    ld [hl], b
    inc l
    inc l
    ld a, [$c6f6]
    ld [hl], a
    inc l
    inc l
    ld a, [$c6f5]
    ld [hl], a
    pop hl
    add hl, de
    inc b
    ld a, $04

jr_000_306a:
    cp b
    jr nz, jr_000_3053

    ld a, $01
    ld [$c6c8], a
    ld [$c6c9], a
    ld [$c6ca], a
    ld [$c6c7], a
    ld a, $2d
    call PlaySound
    ret


jr_000_3081:
    call DrawScoreRanking
    jr jr_000_30a1

HandleRoundEnd::
    call $42f5
    ld a, [TWO_PLAYER_FLAG]
    and a

jr_000_308d:
    jr z, jr_000_3081

    call DrawScoreRanking
    ld hl, $c75b
    ld c, [hl]
    inc hl
    ld b, [hl]
    dec bc
    ld [hl], b
    dec hl
    ld [hl], c
    ld a, b
    or c
    ret nz

    jr jr_000_30a7

jr_000_30a1:
    ld a, [$c026]
    and a
    jr nz, jr_000_30a1

jr_000_30a7:
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_30be

    xor a
    ldh [SERIAL_DONE], a
    ld [LINK_SEND], a
    ld a, $78
    ldh [VBLANK_BUSY], a

jr_000_30b7:
    ldh a, [VBLANK_BUSY]
    and a
    jr nz, jr_000_30b7

    jr jr_000_30c7

jr_000_30be:
    ld a, $78
    ldh [VBLANK_BUSY], a

jr_000_30c2:
    ldh a, [VBLANK_BUSY]
    and a
    jr nz, jr_000_30c2

jr_000_30c7:
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_30e0

    ldh a, [TEXT_FADE]
    call CheckHighScoreTable
    jr c, jr_000_310f

    ld hl, $c6b7
    call $445c
    ld a, $03
    ld [GAME_STATE], a
    ret


jr_000_30e0:
    ld a, [PLAYER_MODE]
    and a

Jump_000_30e4:
    jr nz, jr_000_30eb

    call InitAnimFrame
    jr jr_000_3100

jr_000_30eb:
    ld a, [$c7ad]
    and a
    jr z, jr_000_3100

    ld a, [$c6e2]
    call ProcessMatching
    call $445c
    ld a, $03
    ld [GAME_STATE], a
    ret


jr_000_3100:
    push af
    xor a
    ld hl, $c200
    ld b, $ef

jr_000_3107:
    ld [hl+], a
    dec b
    jr nz, jr_000_3107

    call ClearField
    pop af

jr_000_310f:
    ld a, $00
    ld [GAME_STATE], a
    ld hl, $c6ab
    ld [hl], $00
    ret


DrawScoreRanking::
    ld hl, $0804
    ld b, $08
    ld a, [$c7ad]
    cp $43
    jr nz, jr_000_3128

    ld a, $01

jr_000_3128:
    swap a
    add $50
    call DrawRankEntry
    ld hl, $0904
    ld b, $08
    ld a, [$c7ad]
    cp $43
    jr nz, jr_000_313d

    ld a, $01

jr_000_313d:
    swap a
    add $58
    call DrawRankEntry
    ret


ProcessNewHighScore::
    ldh [TEXT_FADE], a
    call UpdateDifficulty
    ldh a, [TEXT_FADE]
    call CalcRankPosition
    ldh [TEXT_FADE], a
    push af
    push bc
    push hl
    ld hl, $c2a0
    xor a
    ld b, $40

jr_000_315a:
    ld [hl+], a
    dec b
    jr nz, jr_000_315a

    ld a, $01
    ld [$c6e4], a
    ld [$c6e5], a
    pop hl
    pop bc
    pop af
    ld hl, $c6ab
    ld [hl], $01
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_318a

    ldh a, [TEXT_FADE]
    ld [$c7ad], a
    and a
    jr z, jr_000_3183

    ld a, $6f
    call PlaySound
    jr jr_000_3188

jr_000_3183:
    ld a, $71
    call PlaySound

jr_000_3188:
    jr jr_000_31ab

jr_000_318a:
    ldh a, [TEXT_FADE]
    ld [$c7ad], a
    and a
    jr z, jr_000_31a1

    ld a, $ff
    call PlaySound
    ld a, $69
    call PlaySound
    call DrawScoreRanking
    jr jr_000_31ab

jr_000_31a1:
    ld a, $ff
    call PlaySound
    ld a, $66
    call PlaySound

jr_000_31ab:
    ld hl, $c75b
    ld a, $3c
    ld [hl+], a
    ld [hl], $00
    ld a, $04
    ld [GAME_STATE], a
    ret


DrawRankEntry::
    ld c, a
    call CalcOAMAddress
    ld a, c

jr_000_31be:
    ld [hl+], a
    inc a
    dec b
    jr nz, jr_000_31be

    ret


jr_000_31c4:
    call $4bc5
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and $08
    jr z, jr_000_31c4

    ret


FormatRankEntry::
    ld [$c706], a
    ld a, $01
    ld [$c705], a
    ld [$c6ab], a
    ret


CalcRankPosition::
    push af
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_000_31e6

    pop af
    ret


jr_000_31e6:
    pop af
    ld hl, $c708
    cp [hl]
    ret nz

    ld a, [LINK_ROLE]
    cp $02
    jr z, jr_000_31fd

    xor a
    ld [$c706], a
    ld [$c704], a
    ld a, $01
    ret


jr_000_31fd:
    xor a
    ret


CheckHighScoreTable::
    ldh [ANIM_FRAME], a
    and a
    ld a, $00
    ldh [STATE_TRANSITION], a
    jr z, jr_000_3211

    ld a, [$c701]
    inc a
    ld [$c701], a
    jr jr_000_3218

jr_000_3211:
    ld a, [$c702]
    inc a
    ld [$c702], a

jr_000_3218:
    cp $03
    jr nz, jr_000_3220

    ld a, $01
    ldh [STATE_TRANSITION], a

jr_000_3220:
    xor a
    ld [LCD_REDRAW], a
    call LCDOff
    call ClearOAM
    ld a, $03
    ld [$2100], a
    ld hl, $5dd0
    ld de, $9000
    ld bc, $0800
    call MemcopyCall
    ld hl, $65d0
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ldh a, [STATE_TRANSITION]
    and a
    jr z, jr_000_3264

    ld hl, $6ab0
    ld de, $9470
    ld bc, $0390
    call MemcopyCall
    ld hl, $6e40
    ld de, $8800
    ld bc, $0740
    call MemcopyCall

jr_000_3264:
    ld hl, $c4a0
    ld bc, $0168
    ld d, $18
    call DrawCharacter
    ld a, $01
    ld [$2100], a
    call LCDOn
    ld b, $00
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_3282

    ld b, $04

jr_000_3282:
    ld a, b
    ld hl, $c4cd
    ld bc, HeaderLogo
    call FillRect
    ld b, $04
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_3297

    ld b, $00

jr_000_3297:
    ld a, b
    ld hl, $c4d3
    ld bc, HeaderLogo
    call FillRect
    ld b, $08
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_32ac

    ld b, $0c

jr_000_32ac:
    ld a, b
    ld hl, $c4b7
    ld bc, $0202
    call FillRect
    ld b, $0c
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_32c1

    ld b, $08

jr_000_32c1:
    ld a, b
    ld hl, $c4c3
    ld bc, $0202
    call FillRect
    ld a, $14
    ld hl, $c4f3
    ld bc, $0202
    call FillRect
    ld a, $14
    ld hl, $c4f5
    ld bc, $0202
    call FillRect
    ld a, $14
    ld hl, $c4f7
    ld bc, $0202
    call FillRect
    ld a, $14
    ld hl, $c4fb
    ld bc, $0202
    call FillRect
    ld a, $14
    ld hl, $c4fd
    ld bc, $0202
    call FillRect
    ld a, $14
    ld hl, $c4ff
    ld bc, $0202
    call FillRect
    ld a, [$c701]
    and a
    jr z, jr_000_3328

    ld c, a
    ld hl, $c4f3

jr_000_3317:
    push hl
    push bc
    ld a, $10
    ld bc, $0202
    call FillRect
    pop bc
    pop hl
    inc hl
    inc hl
    dec c
    jr nz, jr_000_3317

jr_000_3328:
    ld a, [$c702]
    and a
    jr z, jr_000_3343

    ld c, a
    ld hl, $c4ff

jr_000_3332:
    push hl
    push bc
    ld a, $10
    ld bc, $0202
    call FillRect
    pop bc
    pop hl
    dec hl
    dec hl
    dec c
    jr nz, jr_000_3332

jr_000_3343:
    ldh a, [STATE_TRANSITION]
    and a
    jp z, PlayConfirmSound

    ldh a, [ANIM_FRAME]
    and a
    jr z, jr_000_3352

    ld a, $58
    jr jr_000_3354

jr_000_3352:
    ld a, $5b

jr_000_3354:
    call PlaySound
    xor a
    ldh [SERIAL_DONE], a
    ld [LINK_SEND], a
    ld a, $39
    ld hl, $c5d0
    ld bc, $0206
    call FillRect
    ld a, $45
    ld hl, $c5d6
    ld bc, $0201
    call FillRect
    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_33b8

    ldh a, [ANIM_FRAME]
    and a
    jr z, jr_000_339f

    ld a, $e3
    ld hl, $c574
    ld bc, $0403
    call FillRect
    ld a, $19
    ld hl, $c5d7
    ld bc, $0205
    call FillRect
    ld a, $47
    ldh [ANIM_SUBFRAME], a
    ld a, $6b
    ldh [TEXT_FADE], a
    jr @+$5a

jr_000_339f:
    ld a, $d7
    ld hl, $c572
    ld bc, $0403
    call FillRect
    ld a, $23
    ld hl, $c5d7
    ld bc, $0205
    call FillRect
    jp MenuInputHandler


jr_000_33b8:
    ldh a, [ANIM_FRAME]
    and a
    jr z, jr_000_33de

    ld a, $d7
    ld hl, $c574
    ld bc, $0403
    call FillRect
    ld a, $23
    ld hl, $c5d7
    ld bc, $0205
    call FillRect
    ld a, $8f
    ldh [ANIM_SUBFRAME], a
    ld a, $b3
    ldh [TEXT_FADE], a
    jp $33f7


jr_000_33de:
    ld a, $e3
    ld hl, $c572
    ld bc, $0403
    call FillRect
    ld a, $19
    ld hl, $c5d7
    ld bc, $0205
    call FillRect
    jp MenuInputHandler


    db $af, $e0, $8a, $cd, $c5, $4b, $fa, $26, $c0

    cp $5e
    jr z, jr_000_340d

    cp $58
    jr z, jr_000_340d

    ld a, $5e
    call PlaySound

jr_000_340d:
    ldh a, [ANIM_FRAME]
    cp $1e
    jr c, jr_000_3417

    ldh a, [ANIM_SUBFRAME]
    jr jr_000_3419

jr_000_3417:
    ldh a, [TEXT_FADE]

jr_000_3419:
    ld hl, $c543
    ld bc, $0606
    call FillRect
    ldh a, [ANIM_FRAME]
    inc a
    ldh [ANIM_FRAME], a
    cp $3c
    jr c, jr_000_342e

    xor a
    ldh [ANIM_FRAME], a

jr_000_342e:
    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_3448

    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and $08
    jr z, @-$42

    ld a, $55
    ldh [rSB], a
    ld a, $81
    ldh [rSC], a
    jr jr_000_344f

jr_000_3448:
    ld a, [LINK_RECV]
    cp $55
    jr nz, @-$53

jr_000_344f:
    scf
    ret


MenuInputHandler::
    call $4bc5
    ld a, [$c026]
    cp $62
    jr z, jr_000_3464

    cp $5b
    jr z, jr_000_3464

    ld a, $62
    call PlaySound

jr_000_3464:
    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_347e

    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and $08
    jr z, MenuInputHandler

    ld a, $55
    ldh [rSB], a
    ld a, $81
    ldh [rSC], a
    jr jr_000_344f

jr_000_347e:
    ld a, [LINK_RECV]
    cp $55
    jr nz, MenuInputHandler

    jr jr_000_344f

PlayConfirmSound::
    ld a, $54
    call PlaySound
    ld b, $55
    ldh a, [ANIM_FRAME]
    and a
    jr nz, jr_000_3495

    ld b, $85

jr_000_3495:
    ld a, b
    ld hl, $c546
    ld bc, $0608
    call FillRect
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_34b9

    ld b, $b5
    ldh a, [ANIM_FRAME]
    and a
    jr nz, jr_000_34af

    ld b, $c1

jr_000_34af:
    ld a, b
    ld hl, $c571
    ld bc, $0403
    call FillRect

jr_000_34b9:
    ld a, [$c703]
    and a
    jr z, jr_000_34c8

    call CheckLinkMode
    call FillScoreArea1
    jp ClearSerialState


jr_000_34c8:
    ld a, [$c704]
    and a
    jr z, jr_000_34d6

    call CheckLinkMode
    call FillScoreArea2
    jr ClearSerialState

jr_000_34d6:
    ld b, $23
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_34e1

    ld b, $19

jr_000_34e1:
    ld a, b
    ld hl, $c5d0
    ld bc, $0205
    call FillRect
    ldh a, [ANIM_FRAME]
    and a
    jr z, jr_000_34f5

    call FillScoreArea2
    jr ClearSerialState

jr_000_34f5:
    call FillScoreArea1

ClearSerialState::
    xor a
    ldh [SERIAL_DONE], a
    ld [LINK_SEND], a
    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_3518

jr_000_3505:
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and $08
    jr z, jr_000_3505

    ld a, $55
    ldh [rSB], a
    ld a, $81
    ldh [rSC], a
    jr jr_000_351f

jr_000_3518:
    ld a, [LINK_RECV]
    cp $55
    jr nz, jr_000_3518

jr_000_351f:
    call DrawDigit
    and a
    ret


CheckLinkMode::
    ld b, $19
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_352f

    ld b, $23

jr_000_352f:
    ld a, b
    ld hl, $c5d0
    ld bc, $0205
    jp FillRect


FillScoreArea1::
    ld a, $47
    ld hl, $c5d6
    ld bc, $0207
    jp FillRect


FillScoreArea2::
    ld a, $2d
    ld hl, $c5d6
    ld bc, $0206
    jp FillRect


InitAnimFrame::
    xor a
    ldh [ANIM_FRAME], a
    ld hl, $c6d3
    ld a, [hl]
    and $0f
    ld [hl+], a
    ld a, [hl]
    and $0f
    ld [hl+], a
    ld a, [hl]
    and $0f
    ld [hl], a
    and a
    jr nz, jr_000_3572

    ld a, [$c6d4]
    and a
    ret z

    cp $07
    jr nc, jr_000_3572

    dec a
    ldh [ANIM_FRAME], a
    jr jr_000_3576

jr_000_3572:
    ld a, $06
    ldh [ANIM_FRAME], a

jr_000_3576:
    ld hl, $c210
    ld bc, $00e0
    ld d, $00
    call DrawCharacter
    xor a
    ld [GAME_ACTIVE], a
    ld hl, $c4a0
    ld de, $0004
    ld a, $4a
    ld c, $10

jr_000_358f:
    ld b, $10

jr_000_3591:
    ld [hl+], a
    dec b
    jr nz, jr_000_3591

    add hl, de
    dec c
    jr nz, jr_000_358f

    ld hl, $c544
    ld a, $50
    ld bc, $0208
    call FillRect
    ld hl, $c4b4
    ld c, $10
    ld a, $4d

jr_000_35ab:
    ld [hl+], a
    dec c
    jr nz, jr_000_35ab

    ld a, $01
    ld [GAME_ACTIVE], a
    ld c, $03
    call DrawString
    xor a
    ld [GAME_ACTIVE], a
    ld [$c7ce], a
    ld de, $3839
    ld hl, $8820
    ld c, $50
    call VRAMCopySetup
    ld de, $3d39
    ld hl, $9140
    ld c, $11
    call VRAMCopySetup
    ld a, $01
    ld [GAME_ACTIVE], a
    ld a, [$c6d5]
    and a
    jr z, jr_000_35e6

    ld hl, $37b1
    jr jr_000_35f5

jr_000_35e6:
    ld a, [$c6d4]
    cp $04
    jr c, jr_000_35f2

    ld hl, $37a5
    jr jr_000_35f5

jr_000_35f2:
    ld hl, $3799

jr_000_35f5:
    ld de, $c56a
    ld bc, $000c
    call Memcopy
    ld a, $82
    ld hl, $c5b9
    ld bc, $0202
    call FillRect
    ld a, $82
    ld hl, $c5bd
    ld bc, $0202
    call FillRect
    ld a, $82
    ld hl, $c5c1
    ld bc, $0202
    call FillRect
    ld a, $82
    ld hl, $c5c5
    ld bc, $0202
    call FillRect
    ld hl, $c5b9
    ld a, $10
    call ShowRoundComplete
    ld hl, $c5bd
    ld a, $30
    call ShowRoundComplete
    ld hl, $c5c1
    ld a, $50
    call ShowRoundComplete
    ld hl, $c5c5
    ld a, $70
    call ShowRoundComplete

jr_000_364a:
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and a
    jr z, jr_000_364a

    ret


ShowRoundComplete::
    push hl
    ldh [ANIM_SUBFRAME], a
    xor a
    ldh [STATE_TRANSITION], a
    ld c, $14
    call WaitFrames
    ld a, $86
    ld bc, $0202
    call FillRect
    ld c, $0a
    call WaitFrames
    ldh a, [ANIM_SUBFRAME]
    ld [$c6f5], a
    ld a, $80
    ld [$c6f6], a
    call ProcessRoundComplete
    pop hl
    push hl
    ld de, $0013
    ld a, $4a
    ld [hl+], a
    ld [hl], a
    add hl, de
    ld [hl+], a
    ld [hl], a
    ld c, $14
    ld b, $00
    ld d, $00
    ld e, $00

jr_000_368c:
    push bc
    push de
    call $4bc5
    call SetupMultiplayer
    call ReadJoypad
    pop de
    pop bc
    ldh a, [JOYPAD_PRESSED]
    and a
    jr z, jr_000_36a1

    ld d, $01
    ld e, b

jr_000_36a1:
    inc b
    dec c
    jr nz, jr_000_368c

    ldh a, [STATE_TRANSITION]
    and a
    jr nz, jr_000_36b6

    dec d
    jr z, jr_000_36b3

    ld a, $ff
    ldh [STATE_TRANSITION], a
    jr jr_000_36b6

jr_000_36b3:
    ld a, e
    ldh [STATE_TRANSITION], a

jr_000_36b6:
    ld hl, $37c4
    ldh a, [ANIM_FRAME]
    sla a
    sla a
    ld b, $00
    ld c, a
    add hl, bc
    ldh a, [STATE_TRANSITION]
    cp [hl]
    jr nc, jr_000_36ef

    pop hl
    call FillRect2x2
    call FillRect3x2
    call FillRect3x4
    ld de, $ffd7
    add hl, de
    ld bc, $0404
    ld a, $b8
    call FillRect
    ld a, $16
    call PlaySound
    ld b, $ce
    ld c, $78
    ld hl, $0500
    call DrawSpriteAt
    jr jr_000_3754

jr_000_36ef:
    inc hl
    cp [hl]
    jr nc, jr_000_370e

    pop hl
    call FillRect2x2
    call FillRect3x2
    call FillRect3x4
    ld a, $12
    call PlaySound
    ld b, $cc
    ld c, $80
    ld hl, $0200
    call DrawSpriteAt
    jr jr_000_3754

jr_000_370e:
    inc hl
    cp [hl]
    jr nc, jr_000_372a

    pop hl
    call FillRect2x2
    call FillRect3x2
    ld a, $12
    call PlaySound
    ld b, $ca
    ld c, $80
    ld hl, $0100
    call DrawSpriteAt
    jr jr_000_3754

jr_000_372a:
    inc hl
    cp [hl]
    jr nc, jr_000_3743

    pop hl
    call FillRect2x2
    ld a, $12
    call PlaySound
    ld b, $c8
    ld c, $88
    ld hl, $0050
    call DrawSpriteAt
    jr jr_000_3754

jr_000_3743:
    ld hl, $37bd
    ld b, $00
    ldh a, [ANIM_FRAME]
    ld c, a
    add hl, bc
    ld a, [hl]
    pop hl
    ld bc, $0202
    call FillRect

jr_000_3754:
    ld a, $0f

jr_000_3756:
    push af
    push hl
    call $4bc5
    call SetupMultiplayer
    call $42f5
    pop hl
    pop af
    dec a
    jr nz, jr_000_3756

    ret


FillRect3x4::
    push hl
    ld de, $ffeb
    add hl, de
    ld bc, $0304
    ld a, $ac
    call FillRect
    pop hl
    ld a, $05
    jr jr_000_3756

FillRect3x2::
    push hl
    ld de, $ffec
    add hl, de
    ld bc, $0302
    ld a, $a6
    call FillRect
    pop hl
    ld a, $05
    jr jr_000_3756

FillRect2x2::
    push hl
    ld bc, $0202
    ld a, $a2
    call FillRect
    pop hl
    ld a, $05
    jr jr_000_3756

    ld c, d
    inc d
    dec d
    ld d, $17
    ld c, d
    jr jr_000_37ba

    add hl, de
    ld a, [de]
    dec de
    ld c, d
    ld c, d
    dec d
    inc e
    inc h
    dec d
    dec e
    dec e
    dec d
    ld e, $1f
    dec de
    ld c, d
    jr nz, jr_000_37d4

    ld [hl+], a
    dec d
    ld d, $4a
    ld [hl+], a
    dec e
    inc hl

jr_000_37ba:
    rla
    dec d
    ld d, $8a
    adc [hl]
    sub d
    sub [hl]
    sub [hl]
    sbc d
    sbc [hl]
    ld bc, $0302
    inc b
    ld bc, $0503
    ld [$0301], sp
    ld b, $0a
    ld bc, $0804
    inc c

jr_000_37d4:
    ld [bc], a
    dec b
    ld a, [bc]
    ld c, $03
    ld b, $0a
    rrca
    inc b
    ld [$120d], sp

DrawSpriteAt::
    push bc
    call $432f
    call SetupDrawCharacter
    pop bc
    ld hl, $c498
    ld a, c
    ld [hl+], a
    ldh a, [ANIM_SUBFRAME]
    ld e, a
    ld [hl+], a
    ld [hl], b
    inc hl
    inc hl
    ld a, c
    ld [hl+], a
    ld a, e
    add $08
    ld [hl+], a
    ld a, $d0
    ld [hl], a
    ld c, $10
    ld de, $0004

jr_000_3802:
    push bc
    push de
    call $4bc5
    call SetupMultiplayer
    pop de
    pop bc
    ld hl, $c498
    dec [hl]
    add hl, de
    dec [hl]
    dec c
    jr nz, jr_000_3802

    ld c, $1e
    call DrawString

SetupDrawCharacter::
    ld hl, $c498
    xor a
    ld bc, $0008
    jp DrawCharacter


WaitFrames::
    call $4bc5
    push bc
    call ReadJoypad
    pop bc
    ldh a, [JOYPAD_PRESSED]
    and a
    jr z, jr_000_3835

    ld a, $ff
    ldh [STATE_TRANSITION], a

jr_000_3835:
    dec c
    jr nz, WaitFrames

    ret


    nop
    nop
    inc bc
    inc bc
    inc c
    inc c
    db $10
    db $10
    db $10
    ld d, $20
    ld h, $20
    jr nz, @+$32

    jr nz, jr_000_384a

jr_000_384a:
    nop
    ret nz

    ret nz

    jr nc, @+$72

    ld [$0868], sp
    ld [$0404], sp
    inc b
    inc b
    inc b
    inc e
    ld [hl], b
    ld b, b
    ld [hl], b
    ld c, h
    ld h, b
    ld e, [hl]
    ld h, b
    ld e, [hl]
    inc sp
    inc l
    ccf
    jr nz, @+$21

    jr jr_000_386f

    rlca
    ld [bc], a
    ld a, $02
    ld a, $06
    ld a, [de]

jr_000_386f:
    ld a, $02
    call z, $cc34
    inc [hl]
    ld hl, sp+$18
    ldh [SERIAL_TEMP], a
    nop
    nop
    inc bc
    inc bc
    dec c
    dec c
    db $10
    db $10
    db $10
    ld d, $20
    ld h, $21
    ld hl, $2131
    nop
    nop
    ret nz

    ret nz

    or b
    ldh a, [$ff88]
    add sp, -$78
    adc b
    add h
    add h
    inc b
    inc b
    add h
    sbc h
    ld [hl], c
    ld b, c
    db $76
    ld c, [hl]
    ld h, d
    ld e, [hl]
    ld h, b
    ld e, [hl]
    inc sp
    inc l
    ccf
    jr nz, jr_000_38c5

    jr jr_000_38af

    rlca
    add d
    cp [hl]
    ld b, d
    ld a, [hl]
    ld h, $3a

jr_000_38af:
    ld a, $02
    call z, $cc34
    inc [hl]
    ld hl, sp+$18
    ldh [SERIAL_TEMP], a
    nop
    nop
    rlca
    rlca
    add hl, de
    ld e, $33
    inc l
    ld a, a
    ld b, b
    ld a, h
    ld b, e

jr_000_38c5:
    sbc b
    rst $20
    sbc b
    rst $20
    nop
    nop
    ldh [SERIAL_TEMP], a
    sbc b
    ld a, b
    call z, $fe34
    ld [bc], a
    ld a, $c2
    add hl, de
    rst $20
    add hl, de
    rst $20
    sbc b
    rst $20
    cp h
    jp $4f7f


    ld [hl-], a
    ld [hl-], a
    ld [hl+], a
    ld [hl+], a
    jr nz, jr_000_3905

    db $10
    db $10
    rrca
    rrca
    add hl, de
    rst $20
    dec a
    jp $f2fe


    ld c, h
    ld c, h
    ld b, h
    ld b, h
    inc b
    inc b
    ld [$f008], sp
    ldh a, [rP1]
    nop
    ld hl, $5221
    ld d, d
    ld c, h
    ld c, h
    add b
    add b
    adc h
    adc h

jr_000_3905:
    sub d
    sub d
    add b
    add b
    nop
    nop
    add h
    add h
    ld c, d
    ld c, d
    ld [hl-], a
    ld [hl-], a
    ld bc, $3101
    ld sp, $4949
    ld bc, $4001
    ld b, b
    jr c, jr_000_3955

    rlca
    rlca
    dec sp
    ld a, [hl-]
    ld a, a
    ld b, [hl]
    ld a, a
    ld b, d
    rst $38
    add c
    ld a, a
    ld a, a
    ld [bc], a
    ld [bc], a
    inc e
    inc e
    ldh [SERIAL_TEMP], a
    call c, $fe5c
    ld h, d
    cp $42
    rst $38
    add c
    cp $fe
    nop
    nop
    ld bc, $0301
    ld [bc], a
    inc bc
    ld [bc], a
    rlca
    inc b
    rst $38
    db $fc
    rst $38
    add b
    ld a, a
    ld b, d
    nop
    nop
    add b
    add b
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    and b
    jr nz, @-$3f

    ccf

jr_000_3955:
    pop bc
    ld bc, $42fa
    ccf
    ld [hl+], a
    rra
    db $10
    ccf
    jr nz, jr_000_399f

    jr nz, jr_000_39e1

    ld b, c
    ld a, [hl]
    ld b, [hl]
    ld hl, sp-$68
    ldh [SERIAL_TEMP], a
    db $f4
    ld b, h
    add sp, $08
    db $f4
    inc b
    db $f4
    inc b
    ld a, [$7a82]
    ld h, d
    dec e
    add hl, de
    rlca
    rlca
    nop
    nop
    rlca
    rlca
    jr jr_000_3997

    jr nz, jr_000_39a1

    ld b, b
    ld b, b
    ld d, h
    ld d, h
    sub h
    sub h
    add b
    add b
    nop
    nop
    ret nz

    ret nz

    jr nc, jr_000_39bf

    ld [$0408], sp
    inc b
    inc b
    inc b
    ld [hl-], a
    ld [hl-], a

jr_000_3997:
    ld c, d
    ld c, d
    add b
    xor d
    add b
    cp [hl]
    add b
    cp [hl]

jr_000_399f:
    ld b, b
    ld e, a

jr_000_39a1:
    ld b, b
    ld d, l
    jr nz, jr_000_39c5

    inc e
    inc e
    inc bc
    inc bc
    ld a, [bc]
    ld a, [bc]
    ld de, $0111
    ld bc, $0101
    ld [bc], a
    ld [bc], a
    inc c
    inc c
    jr nc, @+$32

    ret nz

    ret nz

    jr nc, jr_000_39eb

    rra
    rra
    dec e
    dec e

jr_000_39bf:
    dec [hl]
    dec [hl]
    ld [hl], $36
    ld a, d
    ld a, d

jr_000_39c5:
    ld a, e
    ld a, e
    ld a, a
    ld a, a
    nop
    nop
    add b
    add b
    ldh [SERIAL_TEMP], a
    ldh a, [$fff0]
    ldh a, [$fff0]
    ld hl, sp-$08
    ld hl, sp-$08
    cp $fe
    ld a, a
    ld a, a
    ccf
    ccf
    ccf
    ccf
    rra
    rra

jr_000_39e1:
    add hl, bc
    add hl, bc
    db $10
    db $10
    ld [$0708], sp
    rlca
    ldh a, [c]
    ldh a, [c]

jr_000_39eb:
    ldh [c], a
    ldh [c], a
    ldh [c], a
    ldh [c], a
    db $e4
    db $e4
    ret c

    ret c

    add b
    add b
    add b
    add b
    add b
    add b
    ld bc, $6d01
    ld bc, $01ff
    rst $38
    ld bc, $29fe
    cp $01
    ld l, h
    inc bc
    ld [hl], c
    ld [hl], b
    ret nz

    ret nz

    ldh a, [$ff30]
    ld hl, sp+$08
    ld hl, sp-$78
    ld a, h
    ld h, h
    ld a, h
    sub h
    ld a, [hl]
    adc [hl]
    rst $30
    ld [hl], l
    adc b
    adc b
    db $e4
    db $e4
    sub h
    sub h
    ld l, h
    ld l, h
    jr nc, jr_000_3a53

    inc c
    inc c
    inc bc
    inc bc
    nop
    nop
    adc a
    adc l
    rla
    dec e
    rst $20
    db $fd
    ld a, e
    dec bc
    jr nc, @+$12

    jr nc, jr_000_3a65

    ld hl, sp-$38
    ld a, b
    ld a, b
    nop
    nop
    ld b, $06
    dec c
    add hl, bc
    ld a, [bc]
    ld a, [bc]
    ccf
    jr nc, jr_000_3aa3

    ld b, b
    rst $38
    sub h
    rst $38
    add b
    nop
    nop
    ldh [SERIAL_TEMP], a
    ld [hl], b
    db $10
    sub b
    sub b
    sbc b
    adc b

jr_000_3a53:
    ret z

    ld [StartGame], sp
    db $fc
    inc b
    rst $38
    add b
    ld a, a
    ld b, b
    ccf
    ld sp, $0e0e
    db $10
    db $10
    db $10
    db $10

jr_000_3a65:
    ld [$1f08], sp
    rra
    db $fc
    ld b, h
    ld hl, sp+$68
    cp b
    adc b
    inc a
    inc b
    ld e, $02
    ld a, [hl]
    ld h, d
    cp h
    or h
    ld hl, sp-$08
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    ld b, $04
    ld c, $0e
    inc sp
    inc sp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    ldh [rNR41], a
    and b
    and b
    or b
    sub b
    ld e, h
    ld b, b
    ld a, a
    ld h, h
    cp a
    add b
    cp a
    add b
    ld a, a
    ld b, b

jr_000_3aa3:
    ld a, a
    ld b, b
    ccf
    ld sp, $0e0e
    sub b
    sub b
    ldh a, [rNR10]
    ld hl, sp+$08
    db $fc
    inc b
    db $fc
    ld b, h
    ld hl, sp+$48
    or b
    or b
    jr nz, jr_000_3ad9

    ld [bc], a
    ld [bc], a
    inc c
    inc c
    inc e
    inc d
    inc e
    inc d
    inc c
    inc c
    ld [bc], a
    ld [bc], a
    rlca
    rlca
    rlca
    rlca
    ld h, b
    jr nz, jr_000_3b3c

    ld d, b
    ld hl, sp-$78
    cp $96
    ld a, a
    ld h, c
    dec a
    dec a
    ld e, [hl]
    ld e, [hl]
    db $fc
    db $fc

jr_000_3ad9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0101
    ld bc, $0202
    nop
    nop
    dec c
    dec c
    rla
    ld [de], a
    dec a
    dec a
    jp $7cc3


    nop
    ld a, a
    nop
    rst $38
    adc b
    nop
    nop
    ret nz

    ret nz

    ldh [rNR41], a
    and b
    and b
    or b
    sub b
    sub b
    sub b
    ldh a, [rSVBK]
    ldh a, [rNR10]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld bc, $0101
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    pop bc
    ld a, $3e
    ld [bc], a
    ld [bc], a
    inc c
    inc c
    ei
    dec bc
    db $fc

jr_000_3b3c:
    inc b
    cp h
    add h
    cp b
    adc b
    ld sp, $fe31
    ldh [$ff78], a
    jr nz, jr_000_3bc1

    ld hl, $0000
    add b
    add b
    add b
    add b
    add b
    add b
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    add b
    add b
    ld b, b
    ld b, b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc a
    inc [hl]
    ld a, b
    ld c, b
    ld a, b
    ld c, b
    jr c, @+$3a

    inc b
    inc b
    inc b
    inc b
    dec bc
    dec bc
    rrca
    rrca
    ld a, [hl]
    ld d, b
    rst $38
    adc c
    cp $8e
    ld a, [hl]
    db $76
    rra
    ld bc, $3d3f
    ld e, [hl]
    ld e, [hl]
    db $fc
    db $fc
    ld b, b
    ld b, b
    add b
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0101
    ld bc, $0303
    inc c
    inc c
    inc de
    stop
    nop
    nop
    nop
    xor $ee
    rst $38
    ld de, $292b
    jp hl


jr_000_3bb4:
    add sp, $39
    jr c, jr_000_3bb4

    inc b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_000_3bc1:
    ld bc, $8101
    add c
    cp [hl]
    cp [hl]
    and b
    and b
    nop
    nop
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    jr nz, jr_000_3bf3

    jr nz, jr_000_3bf5

    rra
    rra
    ld bc, $2f01
    jr nz, jr_000_3c0b

    jr z, @+$61

    ld b, b
    ld e, a
    ld b, b
    ld e, a
    ld b, b
    ld e, a
    ld b, b
    ld e, a
    ld b, b
    ccf

jr_000_3be8:
    jr nz, jr_000_3be8

    ld [bc], a
    rst $38
    add c
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop

jr_000_3bf3:
    rst $38
    ld [bc], a

jr_000_3bf5:
    rst $38
    ld bc, $01ff
    sub b
    sub b
    adc b
    adc b
    call nz, $c444
    ld b, h
    add sp, $28
    add sp, $28
    di
    inc sp
    db $ec
    inc l
    ld [bc], a
    ld [bc], a

jr_000_3c0b:
    inc b
    inc b
    ld [$0808], sp
    ld [$0404], sp
    call nz, $32c4
    ld [hl-], a
    inc c
    inc c
    ccf
    jr nz, jr_000_3c3b

    jr jr_000_3c25

    rlca
    nop
    nop
    nop
    nop
    nop
    nop

jr_000_3c25:
    nop
    nop
    ld bc, $fe01
    ld b, $f8
    jr @-$1d

    ldh [$ff39], a
    jr c, jr_000_3c73

    ld b, b
    ld b, e
    ld b, b
    add e
    add b
    add e
    add c
    ldh [$ff60], a

jr_000_3c3b:
    sub b
    ldh a, [$ff90]
    ldh a, [JOYPAD_RAW]
    ldh [$ffd8], a
    ld e, b
    and $2e
    pop hl
    rst $28
    ldh [$ff2f], a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add b
    add b
    inc bc
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld [bc], a
    ld bc, $0001
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add e
    add d
    add e
    add d
    add c
    add c
    ret nz

    ret nz

    ld b, b
    ld b, b

jr_000_3c73:
    ld [hl], b
    ld [hl], b
    sbc h
    cp h
    rst $38
    rst $38
    ldh a, [rNR10]
    rst $38
    rra
    rst $38
    jr nz, @+$01

    ret nz

    ccf
    ld a, $4f
    ld e, a
    ld a, a
    ld a, a
    rst $38
    rst $38
    ret nz

    ret nz

    ld hl, sp+$38
    db $fc
    inc b
    db $f4
    inc b
    ret z

    ld [$3030], sp
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    rlca
    rlca
    inc b
    inc b
    inc b
    inc b
    rlca
    rlca
    ld bc, $0101
    ld bc, $0707
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rla
    rla
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    rla
    rla
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld [hl], a
    ld [hl], a
    dec d
    dec d
    dec d
    dec d
    ld [hl], l
    ld [hl], l
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld [hl], a
    ld [hl], a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld [hl], a
    ld [hl], a
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld [hl], l
    ld [hl], l
    dec d
    dec d
    dec d
    dec d
    ld [hl], a
    ld [hl], a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld [hl], b
    ld [hl], b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld d, b
    ld [hl], b
    ld [hl], b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add $c6
    add $c6
    xor $ee
    ld a, h
    ld a, h
    jr c, jr_000_3d81

    nop
    nop
    nop
    nop
    nop
    nop
    cp $fe
    ret nz

    ret nz

    db $fc
    db $fc
    ret nz

    ret nz

    cp $fe
    nop
    nop
    nop
    nop
    nop
    nop
    db $fc
    db $fc
    add $c6
    adc $ce
    ld hl, sp-$08
    adc $ce
    nop
    nop
    nop
    nop
    nop
    nop
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    inc a
    inc a
    jr jr_000_3d8f

    jr jr_000_3d91

    nop
    nop
    nop
    nop
    nop
    nop
    ld a, [hl]
    ld a, [hl]

jr_000_3d81:
    ldh [SERIAL_TEMP], a
    adc $ce
    and $e6
    ld a, [hl]
    ld a, [hl]
    nop
    nop
    nop
    nop
    nop
    nop

jr_000_3d8f:
    ld a, h
    ld a, h

jr_000_3d91:
    add $c6
    add $c6
    add $c6
    ld a, h
    ld a, h
    nop
    nop
    nop
    nop
    nop
    nop
    ld hl, sp-$08
    call z, $c6cc
    add $cc
    call z, $f8f8
    nop
    nop
    nop
    nop
    jr c, jr_000_3de7

    jr c, jr_000_3de9

    jr c, jr_000_3deb

    db $10
    stop
    nop
    db $10
    stop
    nop
    nop
    nop
    nop
    nop
    add $c6
    ld l, h
    ld l, h
    jr c, jr_000_3dfd

    ld l, h
    ld l, h
    add $c6
    nop
    nop
    nop
    nop
    nop
    nop
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld a, [hl]
    ld a, [hl]
    nop
    nop
    nop
    nop
    nop
    nop
    add $c6
    or $f6
    cp $fe
    sbc $de

jr_000_3de7:
    add $c6

jr_000_3de9:
    nop
    nop

jr_000_3deb:
    nop
    nop
    nop
    nop
    ld a, [hl]
    ld a, [hl]
    jr jr_000_3e0b

    jr jr_000_3e0d

    jr jr_000_3e0f

    jr jr_000_3e11

    nop
    nop
    nop
    nop

jr_000_3dfd:
    nop
    nop
    ld a, [hl]
    ld a, [hl]
    ldh [SERIAL_TEMP], a
    ld a, h
    ld a, h
    ld c, $0e
    db $fc
    db $fc
    nop
    nop

jr_000_3e0b:
    nop
    nop

jr_000_3e0d:
    nop
    nop

jr_000_3e0f:
    add $c6

jr_000_3e11:
    add $c6
    add $c6
    add $c6
    ld a, h
    ld a, h
    nop
    nop
    nop
    nop
    nop
    nop
    db $fc
    db $fc
    add $c6
    add $c6
    db $fc
    db $fc
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    ld a, h
    ld a, h
    add $c6
    add $c6
    cp $fe
    add $c6
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, h
    ld a, h
    add $c6
    ret nz

    ret nz

    add $c6
    ld a, h
    ld a, h
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    nop
    add hl, sp
    sbc h
    rst $18
    nop
    add hl, sp
    db $db
    ld b, l
    nop
    add hl, sp
    sub l
    cp $00
    add hl, sp
    db $fd
    rst $20
    nop
    add hl, sp
    xor l
    and a
    nop
    add hl, sp
    ld [bc], a
    db $fc
    nop
    add hl, sp
    inc l
    cp e
    nop
    add hl, sp
    sub e
    nop
