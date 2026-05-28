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
    jp VBlankHandler


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
    ld hl, SHADOW_OAM
    ld b, SHADOW_OAM_SIZE

jr_000_01f6:
    ld [hl+], a
    dec b
    jr nz, jr_000_01f6

    ret


HideAllSprites::
    ld a, OAM_HIDDEN_Y
    ld hl, SHADOW_OAM
    ld de, OAM_ENTRY_SIZE
    ld b, OAM_SPRITE_COUNT

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
    ldh [VRAM_SRC_LO], a
    ld a, d
    ldh [VRAM_SRC_HI], a
    ld a, l
    ldh [VRAM_DST_LO], a
    ld a, h
    ldh [VRAM_DST_HI], a

VRAMCopyNextChunk:
    ld a, c

VRAMCopyExec::
    cp $08
    jr nc, VRAMCopyFullChunk

    ldh [VRAM_COPY_BLOCKS], a
    call WaitVBlank
    ret


VRAMCopyFullChunk:
    ld a, $08
    ldh [VRAM_COPY_BLOCKS], a
    call WaitVBlank
    ld a, c
    sub $08
    ld c, a
    jr VRAMCopyNextChunk

UnusedVRAMCopy2Setup:
    ld a, e
    ldh [UNUSED_VRAM_COPY2_SRC_LO], a
    ld a, d
    ldh [UNUSED_VRAM_COPY2_SRC_HI], a
    ld a, l
    ldh [UNUSED_VRAM_COPY2_DST_LO], a
    ld a, h
    ldh [UNUSED_VRAM_COPY2_DST_HI], a

UnusedVRAMCopy2NextChunk:
    ld a, c
    cp $08
    jr nc, UnusedVRAMCopy2FullChunk

    ldh [UNUSED_VRAM_COPY2_BLOCKS], a
    call WaitVBlank
    ret


UnusedVRAMCopy2FullChunk:
    ld a, $08
    ldh [UNUSED_VRAM_COPY2_BLOCKS], a
    call WaitVBlank
    ld a, c
    sub $08
    ld c, a
    jr UnusedVRAMCopy2NextChunk

StateInit::
    xor a
    ldh [GAME_STATE], a
    ld a, $af
    ldh [rLCDC], a
    ld a, $01
    ld [GAME_ACTIVE], a

MainLoop::
    call WaitVBlank
    call ReadJoypad
    ldh a, [GAME_STATE]
    and a
    jr nz, jr_000_02cb

    ; GAME_STATE_TITLE_INIT: load title graphics, initialize title UI, then advance.
    call LCDOff
    ld a, ROM_BANK_GRAPHICS_0
    ld [MBC1_ROM_BANK_REG], a
    ld hl, GameTileSet
    ld de, $8000
    ld bc, $0800
    call MemcopyCall
    ld hl, TitleTileSet
    ld de, $8800
    ld bc, $1000
    call MemcopyCall
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call LCDOn
    ld hl, COLUMN_BLINK_SLOT_FLAGS
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld a, SND_TITLE_BGM
    call PlaySound
    call InitSpriteBuffer
    call FillOAMTitleTile
    call InitGameScreen
    call InitTitleUI
    ld a, $01
    ld [LCD_REDRAW], a
    jp AdvanceState


jr_000_02cb:
    dec a
    jr nz, jr_000_02d3

    ; GAME_STATE_TITLE_MENU: poll title/player-selection input.
    call RunTitleMenu
    jr MainLoop

jr_000_02d3:
    dec a
    jr nz, jr_000_0302

    ; GAME_STATE_PLAY_SETUP: load playfield graphics and initialize the game board.
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
    call InitPlayfield
    ld a, $01
    ld [LCD_REDRAW], a
    jr AdvanceState

jr_000_0302:
    dec a
    jr nz, jr_000_030e

    ; GAME_STATE_PLAYING: regular per-frame gameplay update.
    call HandlePause
    call GameMainUpdate
    jp MainLoop


jr_000_030e:
    dec a
    jr nz, jr_000_0317

    ; GAME_STATE_ROUND_END: result/high-score/continue processing.
    call HandleRoundEnd
    jp MainLoop


jr_000_0317:
    dec a
    jr nz, jr_000_0320

    ; GAME_STATE_PREPLAY_LOOP: settings/start-wait loop before the play setup state.
    call RunPreplayLoop
    jp MainLoop


jr_000_0320:
    dec a
    jr nz, jr_000_0352

    ; GAME_STATE_PREPLAY_INIT: load settings/start-wait graphics, then enter the loop.
    call LCDOff
    ld a, ROM_BANK_GRAPHICS_0
    ld [MBC1_ROM_BANK_REG], a
    ld hl, CommonTileSet
    ld de, $8800
    ld bc, $1000
    call MemcopyCall
    ld hl, ExtraTiles
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call StartGameplay
    call LCDOn
    ld a, GAME_STATE_PREPLAY_LOOP
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
    ld a, ROM_BANK_GRAPHICS_0
    ld [MBC1_ROM_BANK_REG], a
    ld hl, CommonTileSet
    ld de, $8800
    ld bc, $1000
    call MemcopyCall
    ld hl, GameTileSet
    ld de, $8000
    ld bc, $0800
    call MemcopyCall
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_039f

    ld hl, TwoPlayerTiles2
    ld de, $9500
    ld bc, $0200
    call MemcopyCall
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_039f

    ld hl, TwoPlayerTiles1
    ld de, $81c0
    ld bc, $0260
    call MemcopyCall

jr_000_039f:
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
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
    ld [SOUND_PAUSE_FLAG], a

jr_000_03da:
    ld a, SND_PAUSE
    call PlaySound
    xor a
    ld [LCD_REDRAW], a
    db $76

DrawPauseOverlay::
    ld hl, PauseSpriteData
    ld de, SHADOW_OAM
    ld bc, $0020
    call MemcopyCall
    ret


UnpauseGame::
    ld a, $01
    ld [LCD_REDRAW], a
    xor a
    ld [SOUND_PAUSE_FLAG], a
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
    call WaitVBlank
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
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
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
    ld hl, OAM_DMA_HRAM

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
    ld a, SND_STOP_ALL
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
    call SoundEngine
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
    ld [SPRITE_OBJECT_STAGING_INDEX], a
    inc a
    sla a
    sla a
    sla a
    sla a
    ld l, a
    ld h, SPRITE_OBJECTS_HI
    ld a, l
    ld [SPRITE_OBJECT_SLOT_OFFSET_TMP], a
    ld de, SPRITE_OBJECT_STAGING
    ld bc, SPRITE_OBJECT_STAGING_SIZE
    call MemcopyCall
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_PHASE]
    and a
    ret z

    cp SPRITE_OBJECT_PHASE_WAIT
    jr z, jr_000_0606

    call UpdateMatchState
    and a
    ret z

    jr jr_000_0617

jr_000_0606:
    ld hl, SPRITE_OBJECT_STAGING + SPRITE_OBJECT_DELAY_COUNTER
    dec [hl]
    jr nz, jr_000_0617

    ld a, [$c66e]
    ld [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_DELAY_COUNTER], a
    ld a, SPRITE_OBJECT_PHASE_UPDATE
    ld [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_PHASE], a

jr_000_0617:
    ld hl, SPRITE_OBJECT_STAGING
    ld d, SPRITE_OBJECTS_HI
    ld a, [SPRITE_OBJECT_SLOT_OFFSET_TMP]
    ld e, a
    ld bc, SPRITE_OBJECT_STAGING_SIZE
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
    ld de, COLUMN_TOP_ROWS
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
    ld a, [DROP_ANIM_ACTIVE]
    and a
    ret z

    ld hl, DROP_ANIM_FRAME_TIMER
    dec [hl]
    ret nz

    ld [hl], DROP_ANIM_FRAME_PERIOD
    ld hl, DROP_ANIM_DOWN_STATES
    ld de, $c637
    ld a, [DROP_ANIM_COLUMN]
    inc a
    swap a
    add e
    ld e, a
    jr nc, jr_000_0767

    inc d

jr_000_0767:
    ld b, DROP_ANIM_STATE_COUNT

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
    cp DROP_ANIM_STATE_TRIGGER_NEXT
    jr nz, jr_000_078a

    ld a, b
    cp DROP_ANIM_STATE_STRIDE
    jr c, jr_000_0790

    inc hl
    inc hl
    ld [hl], DROP_ANIM_STATE_START
    dec hl
    dec hl
    jr jr_000_0790

jr_000_078a:
    cp DROP_ANIM_STATE_END
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

    ld hl, DROP_ANIM_UP_STATES
    ld de, $c637
    ld a, [DROP_ANIM_COLUMN]
    swap a
    add e
    ld e, a
    jr nc, jr_000_07a8

    inc d

jr_000_07a8:
    ld b, DROP_ANIM_STATE_COUNT

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
    cp DROP_ANIM_STATE_TRIGGER_NEXT
    jr nz, jr_000_07cb

    ld a, b
    cp DROP_ANIM_STATE_STRIDE
    jr c, jr_000_07d5

    inc hl
    inc hl
    ld [hl], DROP_ANIM_STATE_START
    dec hl
    dec hl
    jr jr_000_07d5

jr_000_07cb:
    cp DROP_ANIM_STATE_END
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
    ld b, DROP_ANIM_STATE_COUNT

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

    ld hl, COLUMN_TOP_ROWS
    ld a, [DROP_ANIM_COLUMN]
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
    ld [DROP_ANIM_ACTIVE], a
    ret


CheckCollisionDown::
    dec bc
    ld a, [DROP_ANIM_COLUMN]
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
    ld a, [DROP_ANIM_COLUMN]
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
    ld hl, SPRITE_OBJECT_SLOT_1
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT

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
    ld a, SPRITE_OBJECT_SLOT_SIZE

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
    ld hl, SPRITE_OBJECT_SLOT_1 + $05
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT

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
    ld a, SPRITE_OBJECT_SLOT_SIZE
    add l
    ld l, a
    dec b
    jr nz, jr_000_086c

    ret


CalcGridPosition::
    ld a, b
    sla a
    ld [DROP_ANIM_GRID_ROW_TMP], a
    ld h, a
    ld a, [DROP_ANIM_COLUMN]
    ld l, a
    sla l
    sla l
    ld bc, COLUMN_TOP_ROWS
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
    ld hl, DROP_ANIM_ACTIVE
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
    ld a, [DROP_ANIM_ACTIVE]
    and a
    jr nz, jr_000_09c6

    push hl
    ld a, b
    ld [DROP_ANIM_COLUMN], a
    ld hl, DROP_ANIM_DOWN_STATES
    ld a, DROP_ANIM_STATE_START
    ld [hl], a
    ld hl, DROP_ANIM_UP_STATES
    ld [hl], a
    ld [DROP_ANIM_FRAME_TIMER], a
    ld a, DROP_ANIM_ACTIVE_VALUE
    ld [DROP_ANIM_ACTIVE], a
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


UpdateColumnBlinkState::
    ld a, [COLUMN_BLINK_GLOBAL_TIMER]
    inc a
    ld [COLUMN_BLINK_GLOBAL_TIMER], a
    cp COLUMN_BLINK_GLOBAL_PERIOD
    jr c, jr_000_0a03

    xor a
    ld [COLUMN_BLINK_GLOBAL_TIMER], a

jr_000_0a03:
    ld hl, COLUMN_BLINK_SLOT_FLAGS
    ld de, COLUMN_BLINK_SLOT_TIMERS
    ld b, COLUMN_BLINK_SLOT_COUNT

jr_000_0a0b:
    ld a, [hl]
    and a
    jr z, jr_000_0a38

    ld a, [de]
    and a
    jr nz, jr_000_0a1b

    ld a, [COLUMN_BLINK_GLOBAL_TIMER]
    and a
    jr z, jr_000_0a21

    jr jr_000_0a38

jr_000_0a1b:
    inc a
    ld [de], a
    cp COLUMN_BLINK_SLOT_PERIOD
    jr c, jr_000_0a38

jr_000_0a21:
    xor a
    ld [de], a
    ld a, [hl]
    cp COLUMN_BLINK_FRAME_1
    jr nz, jr_000_0a2c

    ld [hl], COLUMN_BLINK_FRAME_2
    jr jr_000_0a2e

jr_000_0a2c:
    ld [hl], COLUMN_BLINK_FRAME_1

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
    ld hl, COLUMN_BLINK_GLOBAL_TIMER
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

    ld a, [OPTION_GAME_TYPE]
    ld [GAME_TYPE], a
    ld a, [TWO_PLAYER_FLAG]
    jr z, jr_000_0b1b

    ld a, $01
    ld [GAME_TYPE], a

jr_000_0b1b:
    ld a, [OPTION_LEVEL]
    ld [ACTIVE_LEVEL], a
    ld [$c6e2], a
    inc a
    ld [SPRITE_ANIM_FRAME], a
    xor a
    ld [SPRITE_ANIM_STATE], a
    ld a, [OPTION_SPEED]
    ld [ACTIVE_SPEED], a
    ret


jr_000_0b33:
    ld a, $01
    ld [GAME_TYPE], a
    ld a, [LINK_2P_SELECTED_LEVEL]
    ld [ACTIVE_LEVEL], a
    ld [$c6e2], a
    inc a
    ld [SPRITE_ANIM_FRAME], a
    xor a
    ld [SPRITE_ANIM_STATE], a
    ld a, [LINK_2P_SELECTED_SPEED]
    ld [ACTIVE_SPEED], a
    ret


InitGameState2::
    ld a, [DROP_CURSOR_ANIM_ACTIVE]
    and a
    ret z

    ld hl, DROP_CURSOR_FRAME_TIMER
    dec [hl]
    ret nz

    ld [hl], DROP_CURSOR_FRAME_PERIOD
    ld hl, SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_FRAME
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
    ld [DROP_CURSOR_ANIM_ACTIVE], a
    ret


InitGameBoard::
    ld hl, DROP_CURSOR_ANIM_ACTIVE
    ld [hl], $00
    inc hl
    ld [hl], DROP_CURSOR_FRAME_PERIOD
    ret


LevelCountTable::
    db $0d, $0b, $09, $07, $05

LevelThresholds::
    db $00, $0a, $14, $1e, $28

GameTurnParamTable::
    db $04, $02, $28, $01, $04, $02, $24, $01, $04, $02, $20, $01, $04, $02, $1c, $01
    db $04, $02, $1a, $01, $04, $02, $18, $01, $04, $02, $16, $01, $04, $02, $14, $01
    db $04, $02, $12, $01, $04, $02, $10, $01, $04, $02, $1e, $01, $04, $02, $1c, $01
    db $04, $02, $1a, $01, $04, $02, $18, $01, $04, $02, $16, $01, $04, $02, $14, $01
    db $04, $02, $12, $01, $04, $02, $10, $01, $07, $02, $0e, $01, $01, $03, $0c, $01
    db $04, $02, $14, $01, $04, $02, $13, $01, $04, $02, $12, $01, $04, $02, $11, $01
    db $04, $02, $10, $01, $04, $02, $0f, $01, $04, $02, $0e, $01, $04, $02, $0d, $01
    db $06, $02, $0c, $01, $02, $03, $0b, $01, $04, $02, $0f, $01, $04, $02, $0e, $01
    db $04, $02, $0d, $01, $04, $02, $0c, $01, $04, $02, $0b, $01, $04, $02, $0a, $01
    db $04, $02, $09, $01, $04, $02, $08, $01, $05, $02, $07, $01, $03, $03, $06, $01
    db $04, $02, $0f, $01
    db $04, $02, $0e, $01, $04, $02, $0d, $01, $04, $02, $0c, $01, $04, $02, $0b

GameTurnParamTable_0c40::
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
    ld a, ROM_BANK_GRAPHICS_1
    ld [MBC1_ROM_BANK_REG], a
    ld hl, Bank3MatchingTilesTo9000
    ld de, $9000
    ld bc, $0800
    call MemcopyCall
    ld hl, Bank3MatchingTilesTo8800
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ld hl, Bank3MatchingTilesTo8000
    ld de, $8000
    ld bc, $0800
    call MemcopyCall
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call LCDOn
    ld a, $8b
    ldh [rLCDC], a
    ld hl, MatchingOamTemplateMiddle
    ld de, $c408
    ld bc, $0010
    call Memcopy
    ldh a, [STATE_TRANSITION]
    ld hl, MatchingTileBaseIndexTable
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

    call WaitVBlank

jr_000_0f95:
    call WaitVBlank
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
    call WaitVBlank
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
    ld hl, MatchingOamTemplateTop
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
    call WaitVBlank
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
    call WaitVBlank
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
    ld a, SND_CONFIRM
    call PlaySound
    ld hl, MatchingOamTemplateFinal
    ld de, $c400
    ld bc, $0008
    call Memcopy
    ld de, $0004
    ld hl, MatchingTileBaseIndexTable
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
    call WaitVBlank
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
    ld hl, MatchingScoreBonusTable
    ldh a, [STATE_TRANSITION]
    sla a
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld l, [hl]
    ld h, a
    call AddScore
    call UpdateLevel

jr_000_10f8:
    ld a, [SOUND_CH_ACTIVE_ID]
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
    ld de, SCORE_DIGITS

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
    ld a, [ACTIVE_SPEED]
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


MatchingOamTemplateTop::
    db $70, $68, $00, $00, $70, $70, $01, $00

MatchingOamTemplateMiddle::
    db $70, $80, $02, $00, $70, $88, $03, $00
    db $78, $80, $04, $00, $78, $88, $05, $00

MatchingOamTemplateFinal::
    db $58, $58, $3f, $00, $58, $60, $40, $00

MatchingScoreBonusTable::
    db $00, $50
    db $01, $00
    db $01, $50
    db $02, $00
    db $02, $50
    db $03, $00
    db $03, $00
    db $04, $00
    db $04, $00
    db $05, $00
    db $05, $00
    db $06, $00
    db $06, $00
    db $07, $00
    db $07, $00
    db $08, $00
    db $08, $00
    db $08, $00
    db $09, $00
    db $09, $00
    db $09, $00
    db $10, $00
    db $10, $00
    db $10, $00
    db $12, $00
    db $12, $00
    db $12, $00
    db $15, $00

MatchingTileBaseIndexTable::
    db $00, $01, $02, $03, $04, $05, $05, $06
    db $06, $07, $07, $08, $08, $09, $09, $0a
    db $0a, $0a, $0b, $0b, $0b, $0c, $0c, $0c
    db $0d, $0d, $0d, $0e

UnusedDrawNumberPairUnlessFF::
    cp $ff
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
    call WaitVBlank
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
    ld a, [GAME_TYPE]
    and a
    ret z

    ld hl, COLUMN_TOP_ROWS
    ld b, COLUMN_COUNT

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
    ld hl, PIECE_FALL_TIMER
    ld a, [hl]
    and a
    jr z, jr_000_12ac

    dec [hl]
    ret nz

    ld a, [DROP_CURSOR_ANIM_ACTIVE]
    ld b, a
    ld a, [DROP_ANIM_ACTIVE]
    or b
    ret z

    ld a, $01
    ld [PIECE_FALL_TIMER], a
    ret


jr_000_12ac:
    ld a, [PIECE_FALL_DELAY]
    ld [PIECE_FALL_TIMER], a
    ret


DisplayLevel::
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_000_12bd

    call UpdateMenuCursor
    ret


jr_000_12bd:
    call ProcessMenuInput
    call DisplaySpeed
    call CalcResults
    ld a, [PIECE_DISPLAY_COUNT]
    call DisplayResults
    ret


DisplayLines::
    ld hl, SPRITE_OBJECT_SLOT_1
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT

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

    ld a, [ACTIVE_LEVEL]
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
    ld hl, PIECE_FALL_DELAY
    ld a, [hl]
    cp PIECE_FALL_DELAY_MIN
    ret c

    ret z

    dec [hl]
    ret


CheckMatch::
    ldh a, [JOYPAD_PRESSED]
    and $30
    jr z, jr_000_1317

    ld a, SND_CURSOR_MOVE
    call PlaySound

jr_000_1317:
    ldh a, [JOYPAD_PRESSED]
    and $03
    jr z, jr_000_1341

    ld a, [DROP_ANIM_ACTIVE]
    and a
    jr nz, jr_000_1341

    ld a, [$c6e7]
    and a
    jr nz, jr_000_1341

    ld a, $01
    ld [DROP_CURSOR_ANIM_ACTIVE], a
    ld a, [SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_BASE_X]
    swap a
    srl a
    push af
    ld a, SND_DROP_START
    call PlaySound
    pop af
    call StartDropAnim
    jr jr_000_1341

jr_000_1341:
    ld hl, SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_BASE_X
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
    ld a, [SPRITE_OBJECT_SLOT_1 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, jr_000_138a

    ld a, [SPRITE_OBJECT_SLOT_2 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, jr_000_138a

    ld a, [SPRITE_OBJECT_SLOT_3 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, jr_000_138a

    ld a, [SPRITE_OBJECT_SLOT_4 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, jr_000_138a

    ret


jr_000_138a:
    ld hl, PIECE_FALL_TIMER
    ld a, [hl]
    cp $03
    jr c, jr_000_1394

    ld [hl], $03

jr_000_1394:
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT
    ld hl, SPRITE_OBJECT_SLOT_1 + $0f

jr_000_1399:
    ld a, [hl]
    cp $03
    jr c, jr_000_13a0

    ld [hl], $03

jr_000_13a0:
    ld a, l
    add SPRITE_OBJECT_SLOT_SIZE
    ld l, a
    dec b
    jr nz, jr_000_1399

    ret


ShufflePieceDisplaySlotOrder::
    call SelectPieceDisplaySlotOrderEntry
    ld a, [hl]
    ld d, h
    ld e, l
    push af
    call SelectPieceDisplaySlotOrderEntry
    pop af
    ld b, [hl]
    ld [hl], a
    ld a, b
    ld [de], a
    ret


SelectPieceDisplaySlotOrderEntry::
    ld c, $38
    call MultiplyAndCount
    ld b, $00
    ld c, a
    ld hl, PIECE_DISPLAY_SLOT_ORDER
    add hl, bc
    ret


ShufflePieceDisplayCodePool::
    call SelectPieceDisplayCodePoolEntry
    ld a, [hl]
    ld d, h
    ld e, l
    push af
    call SelectPieceDisplayCodePoolEntry
    pop af
    ld b, [hl]
    ld [hl], a
    ld a, b
    ld [de], a
    ret


SelectPieceDisplayCodePoolEntry::
    ld c, $38
    call MultiplyAndCount
    ld b, $00
    ld c, a
    ld hl, PIECE_DISPLAY_CODE_POOL
    add hl, bc
    ret


UpdateMatchState::
    ld a, [PIECE_FALL_TIMER]
    and a
    ld a, $01
    ret nz

    ld a, [PIECE_FALL_POS]
    cp $02
    jr nz, jr_000_13f6

    ld a, [SPRITE_OBJECT_STAGING_INDEX]
    call GameOverSequence

jr_000_13f6:
    call MovePieceUp
    ld b, a
    ld a, [PIECE_FALL_POS]
    inc a
    ld [PIECE_FALL_POS], a
    cp b
    jr nc, jr_000_140f

    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_BASE_Y]
    add $08
    ld [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_BASE_Y], a
    ld a, $01
    ret


jr_000_140f:
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
    cp $07
    call z, ScanBoard
    call MovePieceLeft
    cp b
    jr nz, jr_000_1429

    ld a, [PIECE_FALL_POS]
    cp $0f
    jr z, jr_000_1429

    call UpdateLandingProgress
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
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
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
    ld a, [SPRITE_OBJECT_STAGING_INDEX]
    inc a
    swap a
    ld l, a
    ld h, SPRITE_OBJECTS_HI
    ld b, SPRITE_OBJECT_STAGING_SIZE
    xor a

jr_000_1472:
    ld [hl+], a
    dec b
    jr nz, jr_000_1472

    ret


MovePieceUp::
    ld a, [PIECE_ROTATION]
    ld hl, COLUMN_TOP_ROWS
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
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
    dec hl
    dec hl
    ld [hl], a
    ret


MovePieceRight::
    ld hl, SPRITE_OBJECT_SLOT_1
    ld b, SPRITE_OBJECT_SLOT_SIZE * $08
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
    ld hl, PIECE_FALL_DELAY
    ld a, [ACTIVE_SPEED]
    and a
    jr z, jr_000_14d2

    call ProcessFalling
    srl a
    ld [PIECE_FALL_DELAY], a
    jr jr_000_14d8

jr_000_14d2:
    call ProcessFalling
    ld [PIECE_FALL_DELAY], a

jr_000_14d8:
    ld a, $02
    ld [PIECE_DISPLAY_COUNT], a
    ld a, [ACTIVE_LEVEL]
    ld hl, LevelCountTable
    call GetArrayElement
    ld [COLUMN_TOP_ROW_SEED], a
    ld a, $30
    ld [$c672], a
    ld hl, $c6b0
    ld a, [ACTIVE_LEVEL]
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


SeedColumnTopRows::
    ld b, COLUMN_COUNT
    ld hl, COLUMN_TOP_ROWS
    ld a, [COLUMN_TOP_ROW_SEED]

jr_000_151b:
    ld [hl+], a
    dec b
    jr nz, jr_000_151b

    ret


InitPieceDisplaySlotOrder::
    ld hl, PIECE_DISPLAY_SLOT_ORDER
    ld [hl], $00
    inc hl
    ld [hl], $01
    inc hl
    ld [hl], $02
    inc hl
    ld [hl], $03
    ret


InitPieceDisplayCodePool::
    ld hl, PIECE_DISPLAY_CODE_POOL
    ld b, PIECE_DISPLAY_CODE_POOL_SIZE
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
    ld a, [COLUMN_TOP_ROW_SEED]
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
    call ShufflePieceDisplayCodePool
    call ShufflePieceDisplayCodePool
    call ShufflePieceDisplayCodePool
    ld a, [PIECE_DISPLAY_CODE_POOL + $03]
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
    call SeedColumnTopRows
    call InitPieceDisplaySlotOrder
    call InitPieceDisplayCodePool
    call DropPiece
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_000_15d0

    call SetArrayElement
    ld a, $0f
    ld [COLUMN_TOP_ROW_SEED], a
    call SeedColumnTopRows
    jr jr_000_15e8

jr_000_15d0:
    call ValidatePosition
    call SeedColumnTopRows
    call ProcessInputGame
    ld a, [PIECE_DISPLAY_COUNT]
    call DisplayResults
    call CalcResults
    ld a, [PIECE_DISPLAY_COUNT]
    call DisplayResults

jr_000_15e8:
    ld hl, SPRITE_OBJECT_SLOT_0
    ld [hl], SPRITE_OBJECT_TYPE_PLAYER_CURSOR
    ret


ProcessFalling::
    ld hl, LevelFallDelayTable
    ld a, [$c6e2]
    cp $14
    jr c, jr_000_15fa

    ld a, $13

jr_000_15fa:
    call GetArrayElement
    ret


LevelFallDelayTable::
    db $1e, $1c, $1a, $19, $18, $17, $16, $14, $13, $12
    db $11, $10, $0f, $0e, $0d, $0c, $0b, $0a, $09, $08

UpdateLandingProgress::
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
    cp $08
    jr nz, CommitFallingPieceToBoard

    ld a, [$c6bf]
    dec a
    dec a
    ld [$c6bf], a
    and a
    jr nz, CommitFallingPieceToBoard

    ld [$c69d], a
    ld [$c6ae], a

CommitFallingPieceToBoard::
    ld a, SND_COMMIT_PIECE
    call PlaySound
    ld hl, $0005
    call AddScore
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
    ld hl, FIELD_COLUMN_TIMERS
    call GetArrayElement
    ld [hl], FIELD_COLUMN_TIMER_RELOAD
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
    ld hl, LINK_SEND_QUEUE_0
    ld b, [hl]
    add b
    or $40
    ld [LINK_FIELD_EVENT_PAYLOAD], a
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
    call SetupGameBG
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
    call SetupGameBG
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
    ld hl, RoundCompleteStateRemapTable
    call GetArrayElement
    ldh [SCREEN_STATE], a
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION
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
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION
    inc l
    inc l
    ld [hl], $00
    ld b, $0f
    call Send2PData
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION

Process2Player::
    inc l
    inc l
    ld [hl], $10
    ld b, $0f
    call Send2PData
    ld hl, SPRITE_OBJECT_SLOT_10
    ld de, SPRITE_OBJECT_SLOT_SIZE
    xor a
    ld b, a

jr_000_17d6:
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE
    push hl
    inc l
    inc l
    ld [hl], b
    inc l
    inc l
    ld a, [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_BASE_Y]
    ld [hl], a
    inc l
    inc l
    ld a, [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_BASE_X]
    ld [hl], a
    pop hl
    add hl, de
    inc b
    ld a, $04
    cp b
    jr nz, jr_000_17d6

    ld a, $01
    ld [FIELD_ANIM_SLOT_11_ACTIVE], a
    ld [FIELD_ANIM_SLOT_10_ACTIVE], a
    ld [FIELD_ANIM_SLOT_13_ACTIVE], a
    ld [FIELD_ANIM_SLOT_12_ACTIVE], a
    ld a, SND_ROUND_COMPLETE
    call PlaySound
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION
    inc l
    inc l
    ld [hl], $01
    ld b, $14
    call Send2PData
    ld a, $01
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION
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
    ld a, [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME]
    xor $10
    ld [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME], a
    ld a, [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME]
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
    ld a, [LINK_FIELD_EVENT_PAYLOAD]
    ld [LINK_SEND_QUEUE_0], a
    ld a, [$c6a2]
    sla a
    ld hl, RoundCompleteDelayParamTable
    call GetArrayElement
    ld d, a
    inc hl
    ld a, [hl]
    ld l, a
    ld h, d
    call AddScore
    call UpdateAnimFrame
    call IncrementEggCounter
    ld hl, SPRITE_OBJECT_SLOT_9
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
    call WaitVBlank
    ld a, [GAME_STATE]
    cp GAME_STATE_PLAYING
    jr nz, jr_000_18af

    call ReadJoypad
    call HandlePause
    ld a, $01
    ld [$c6e7], a
    call CheckMatch
    call LoadGameBGTiles
    xor a
    ld [$c6e7], a
    call SetupMultiplayer
    call UpdateFieldTimers
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
    ld a, SND_PIECE_LAND
    call PlaySound
    pop af
    xor a
    ret


RoundCompleteStateRemapTable::
    db $01, $02, $02, $02, $03, $03, $04

RoundCompleteDelayParamTable::
    db $00, $50
    db $01, $00
    db $01, $00
    db $01, $00
    db $02, $00
    db $02, $00
    db $05, $00
    db $05, $00
    db $05, $00

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
    ld b, PIECE_DISPLAY_STATE_COUNT
    ld hl, PIECE_DISPLAY_STATES

jr_000_18fb:
    ld [hl], $00
    inc hl
    dec b
    jr nz, jr_000_18fb

    ld b, a

jr_000_1902:
    ld hl, PIECE_DISPLAY_CODE_POOL
    ld a, b
    dec a
    call GetArrayElement
    push af
    ld hl, PIECE_DISPLAY_SLOT_ORDER
    ld a, b
    dec a
    call GetArrayElement
    ld hl, PIECE_DISPLAY_STATES
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
    ld hl, PIECE_DISPLAY_STATES
    ld b, PIECE_DISPLAY_STATE_COUNT

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
    ld hl, PIECE_DISPLAY_STATES
    xor a
    ld d, a
    ld b, a
    ld c, PIECE_DISPLAY_STATE_COUNT

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
    ld h, SPRITE_OBJECTS_HI
    ld [hl], SPRITE_OBJECT_TYPE_GAME_OVER_PIECE
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
    ld b, PIECE_DISPLAY_STATE_COUNT
    ld hl, PIECE_DISPLAY_STATES + PIECE_DISPLAY_STATE_COUNT - 1

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
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT
    ld hl, SPRITE_OBJECT_SLOT_5
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
    ld hl, GAME_TURN_TABLE_INDEX
    ld a, [hl]
    ld l, a
    ld h, $00
    add hl, hl
    add hl, hl
    push bc
    ld bc, GameTurnParamTable
    add hl, bc
    pop bc
    ld a, [hl]
    ld [GAME_TURN_STEP_TIMER], a
    inc hl
    inc hl
    ld a, [hl]
    ld b, a
    ld a, [ACTIVE_SPEED]
    and a
    jr z, jr_000_19fd

    srl b
    jr jr_000_19fd

    ld b, $02

jr_000_19fd:
    ld a, b
    ld [GAME_TURN_DELAY], a
    dec hl
    ld a, [hl]
    push af
    call DisplayResults
    pop af
    ld [$c697], a
    ld [PIECE_DISPLAY_COUNT], a
    ret


UpdateMenuCursor::
    ld hl, GAME_TURN_STEP_TIMER
    dec [hl]
    jr z, jr_000_1a2b

    call ProcessMenuInput
    ld a, [GAME_TURN_DELAY]
    ld [PIECE_FALL_DELAY], a
    ld [PIECE_FALL_TIMER], a
    call CalcResults
    ld a, [PIECE_DISPLAY_COUNT]
    call DisplayResults
    ret


jr_000_1a2b:
    ld hl, GAME_TURN_TABLE_INDEX
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
    ld [GAME_TURN_STEP_TIMER], a
    ld a, [ACTIVE_LEVEL]
    ld hl, LevelThresholds
    call GetArrayElement
    ld [GAME_TURN_TABLE_INDEX], a
    ld hl, GameTurnParamTable
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
    ld a, [ACTIVE_SPEED]
    and a
    jr z, jr_000_1a74

    srl b
    jr jr_000_1a74

    ld b, $02

jr_000_1a74:
    ld a, b
    ld [GAME_TURN_DELAY], a
    ld [PIECE_FALL_TIMER], a
    ld [PIECE_FALL_DELAY], a
    jp ProcessMenuLoop


ProcessMenuSelection::
    ld a, [$c6f8]
    and a
    jr z, jr_000_1a8d

    xor a
    ld [$c6f8], a
    jr jr_000_1ae2

jr_000_1a8d:
    ld a, [GAME_TYPE]
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
    ld hl, SPRITE_OBJECT_SLOT_1
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT

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

    ld hl, PIECE_DISPLAY_STATES
    ld b, PIECE_DISPLAY_STATE_COUNT

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
    ld hl, SPRITE_ANIM_TICK_COUNTER
    inc [hl]
    ld a, [hl]
    cp SPRITE_ANIM_TICK_PERIOD
    ret nz

    xor a
    ld [hl], a
    call AdvanceSpriteAnimFrame
    ld hl, $0812
    call SpriteAnimTable
    ret


SelectMenuItem::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_000_1b9c

    ld a, [SCREEN_STATE]
    ret


jr_000_1b9c:
    ld a, [LINK_PENDING_FIELD_RISE]
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
    ld a, [LINK_PENDING_FIELD_RISE]
    cp b
    jr c, jr_000_1bbe

    sub b
    ld [LINK_PENDING_FIELD_RISE], a
    ld a, $04
    jr jr_000_1bc8

jr_000_1bbe:
    ld hl, SCREEN_STATE
    ld b, [hl]
    add b
    ld hl, LINK_PENDING_FIELD_RISE
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
    ld hl, SPRITE_OBJECT_SLOT_1
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
    call DrawOptionTextLabels
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


DrawOptionTextLabels::
    ld hl, $0102
    ld de, OptionTextAGame
    call DrawStringToGrid
    ld hl, $010c
    ld de, OptionTextBGame
    call DrawStringToGrid
    ld hl, $0402
    ld de, OptionTextLevel
    call DrawStringToGrid
    ld hl, $0b02
    ld de, OptionTextSpeed
    call DrawStringToGrid
    ld hl, $0f02
    ld de, OptionTextBgm
    call DrawStringToGrid
    ld hl, $0c09
    ld de, OptionTextLow
    call DrawStringToGrid
    ld hl, $0c0f
    ld de, OptionTextHigh
    call DrawStringToGrid
    ld hl, $1010
    ld de, OptionTextOff
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


OptionTextAGame::
    db $80, $4a, $86, $80, $8c, $84, $ff ; "A GAME"
OptionTextBGame::
    db $81, $4a, $86, $80, $8c, $84, $ff ; "B GAME"
OptionTextLevel::
    db $8b, $84, $95, $84, $8b, $ff ; "LEVEL"
OptionTextSpeed::
    db $92, $8f, $84, $84, $83, $ff ; "SPEED"
OptionTextBgm::
    db $81, $86, $8c, $ff ; "BGM"
OptionTextLow::
    db $8b, $8e, $96, $ff ; "LOW"
OptionTextHigh::
    db $87, $88, $86, $87, $ff ; "HIGH"
OptionTextOff::
    db $8e, $85, $85, $ff ; "OFF"

OptionMarkerPositions::
    db $01, $01, $01, $0b, $0c, $08, $0c, $0e
    db $10, $06, $10, $09, $10, $0c, $10, $0f

DrawOptionMarkers::
    ld b, $08
    ld hl, OptionMarkerPositions

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

    ld a, [OPTION_GAME_TYPE]
    and a
    jr nz, jr_000_1de2

    ld hl, $0101
    call DrawOptionMarker
    jr jr_000_1de8

jr_000_1de2:
    ld hl, $010b
    call DrawOptionMarker

jr_000_1de8:
    ld a, [OPTION_SPEED]
    and a
    jr nz, jr_000_1df6

    ld hl, $0c08
    call DrawOptionMarker
    jr jr_000_1dfc

jr_000_1df6:
    ld hl, $0c0e
    call DrawOptionMarker

jr_000_1dfc:
    ld a, [OPTION_BGM]
    and a
    jr nz, jr_000_1e09

    ld hl, $1006
    call DrawOptionMarker
    ret


jr_000_1e09:
    cp $01
    jr nz, jr_000_1e14

    ld hl, $1009
    call DrawOptionMarker
    ret


jr_000_1e14:
    cp $02
    jr nz, jr_000_1e1f

    ld hl, $100c
    call DrawOptionMarker
    ret


jr_000_1e1f:
    ld hl, $100f
    call DrawOptionMarker
    ret


DrawOptionMarker::
    call CalcOAMAddress
    ld [hl], $9a
    ret


DrawTileTripletList::
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
    jr DrawTileTripletList

SettingsCursorTileData::
    db $04, $01, $71, $04, $07, $70
    db $0b, $01, $71, $0b, $07, $70
    db $0f, $01, $71, $0f, $05, $70
    db $ff

ApplySettings::
    ld hl, SettingsCursorSpriteInit0
    ld de, SPRITE_OBJECT_SLOT_9
    ld bc, $0007
    call MemcopyCall
    ld hl, SettingsCursorSpriteInit1
    ld de, SPRITE_OBJECT_SLOT_10
    ld bc, $0007
    call MemcopyCall
    ld hl, SettingsCursorSpriteInit2
    ld de, SPRITE_OBJECT_SLOT_11
    ld bc, $0007
    call MemcopyCall
    ret


SettingsCursorSpriteInit0::
    db SPRITE_OBJECT_TYPE_SETTINGS_CURSOR, $00, $00, $00, $73, $00, $30
SettingsCursorSpriteInit1::
    db SPRITE_OBJECT_TYPE_SETTINGS_CURSOR, $00, $01, $01, $73, $00, $48
SettingsCursorSpriteInit2::
    db SPRITE_OBJECT_TYPE_SETTINGS_CURSOR, $00, $02, $02, $73, $00, $60

ResetSettings::
    ld a, $1b
    ld [BGM_PREVIEW_TIMER], a
    ld [BGM_PREVIEW_PERIOD], a
    ret


RunPreplayLoop::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jp nz, Run2PPreplayLoop

    jp Run1PPreplayLoop


    ret


    call Multiply
    call TickBgmPreviewTimer
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

    call WaitVBlank
    xor a
    ld [LINK_SEND], a
    ld a, $81
    ldh [rSC], a

jr_000_1ee7:
    call InitGameState
    ld a, GAME_STATE_PLAY_SETUP
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
    ld hl, OPTION_GAME_TYPE
    ld a, [MENU_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, OptionMaxValueTable
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
    call DrawOptionMarkers
    ret


OptionMaxValueTable::
    db $02, $05, $02, $04

jr_000_1f50:
    ld hl, OPTION_GAME_TYPE
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
    call DrawOptionMarkers
    ret


ApplyGameSettings::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_000_1f87

    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_1f81

    ld a, SND_LINK_SLAVE
    call PlaySound
    ret


jr_000_1f81:
    ld a, SND_LINK_MASTER
    call PlaySound
    ret


jr_000_1f87:
    call ApplySettings
    ld a, [OPTION_BGM]
    and a
    jr nz, jr_000_1fa5

    ld a, SND_BGM_OPTION0
    ld [BGM_INDEX], a
    ld a, SND_BGM_PREVIEW0
    call PlaySound
    ld a, $1b
    ld [BGM_PREVIEW_PERIOD], a
    ld a, $01
    ld [BGM_PREVIEW_TIMER], a
    ret


jr_000_1fa5:
    cp $01
    jr nz, jr_000_1fbe

    ld a, SND_BGM_OPTION1
    ld [BGM_INDEX], a
    ld a, SND_BGM_PREVIEW1
    call PlaySound
    ld a, $2a
    ld [BGM_PREVIEW_PERIOD], a
    ld a, $01
    ld [BGM_PREVIEW_TIMER], a
    ret


jr_000_1fbe:
    cp $02
    jr nz, jr_000_1fd7

    ld a, SND_BGM_OPTION2
    ld [BGM_INDEX], a
    ld a, SND_BGM_PREVIEW2
    call PlaySound
    ld a, $0c
    ld [BGM_PREVIEW_PERIOD], a
    ld a, $01
    ld [BGM_PREVIEW_TIMER], a
    ret


jr_000_1fd7:
    ld a, SND_BGM_OFF
    ld [BGM_INDEX], a
    ld a, SND_BGM_OFF
    call PlaySound
    ret


UpdateCursorDisplay::
    push af
    call DrawLabel
    call DrawOptionTextLabels
    call DrawOptionValues
    ld de, SettingsCursorTileData
    call DrawTileTripletList
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
    ld de, SettingsCursorTileData0
    call DrawTileTripletList
    ret


SaveConfig2::
    call TileDataLookupB
    ld de, SettingsCursorTileData1
    call DrawTileTripletList
    ret


SaveConfig3::
    call TileDataLookupD
    ld de, SettingsCursorTileData2
    call DrawTileTripletList
    ret


SettingsCursorTileData0::
    db $04, $01, $76, $04, $07, $75, $ff
SettingsCursorTileData1::
    db $0b, $01, $76, $0b, $07, $75, $ff
SettingsCursorTileData2::
    db $0f, $01, $76, $0f, $05, $75, $ff
    ret


DrawOptionValues::
    call SetPalette
    ld a, [OPTION_LEVEL]
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
    ld a, [OPTION_GAME_TYPE]
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
    ld [TITLE_PLAYER_MARKER_PHASE], a

ResetTitleState::
    ld [TITLE_PLAYER_MARKER_TIMER], a
    ld a, $05
    ld [$c6bd], a
    xor a
    ld [LINK_ROLE], a
    ld [GAME_TYPE], a
    ld [MENU_CURSOR], a
    ld [LINK_RECV], a
    ld [LINK_SEND], a
    inc a
    ld [$c620], a
    ld [$ff94], a
    ld [$c66e], a
    call DrawTitleLabels
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


RunTitleMenu::
    xor a
    ld [$c701], a
    ld [$c702], a
    ld [EGG_COUNT_RESERVED], a
    ld [EGG_COUNT_ONES], a
    ld [EGG_COUNT_TENS], a
    ld [EGG_COUNT_HUNDREDS], a
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_PENDING_FIELD_RISE], a
    ld [$c6f4], a
    ld [$c6f3], a
    ld [$c705], a
    ld [$c706], a
    call Multiply
    call ProcessTitleInput
    call ProcessOptionInput
    ret


StartGameplay::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_000_21ae

    call InitPreplayBlinkTimer
    call Init1PPreplayScreen
    call ApplyGameSettings
    ret


    call ApplyGameSettings
    call InitTextSystem
    call ApplySettings
    call ResetSettings
    xor a
    call UpdateCursorDisplay
    call DrawOptionMarkers
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
    call UpdateFieldAnimSlot11
    call UpdateFieldAnimSlot10
    call UpdateFieldAnimSlot13
    call UpdateFieldAnimSlot12
    ret


UpdateFieldAnimSlot11::
    ld hl, FIELD_ANIM_SLOT_11_ACTIVE
    xor a
    cp [hl]
    ret z

    ld hl, SPRITE_OBJECT_SLOT_11 + SPRITE_OBJECT_BASE_X
    ld a, [hl]
    call StepFieldAnimSlot11SideDelta
    cp FIELD_ANIM_END_SENTINEL
    ret z

    ld [hl], a
    dec l

Jump_000_21e4:
    dec l
    ld a, [hl]
    call StepFieldAnimSlot11SideDelta
    ld [hl], a
    ret


StepFieldAnimSlot11SideDelta::
    push hl
    ld b, a
    ld a, [FIELD_ANIM_SLOT_11_CURSOR]
    ld hl, FieldSideDeltaTable
    call GetArrayElement
    cp FIELD_ANIM_END_SENTINEL
    jr z, jr_000_2201

    add b
    ld hl, FIELD_ANIM_SLOT_11_CURSOR
    inc [hl]
    pop hl
    ret


jr_000_2201:
    xor a
    ld [FIELD_ANIM_SLOT_11_ACTIVE], a
    ld [FIELD_ANIM_SLOT_11_CURSOR], a
    ld [SPRITE_OBJECT_SLOT_11], a
    ld a, FIELD_ANIM_END_SENTINEL
    pop hl
    ret


UpdateFieldAnimSlot10::
    ld hl, FIELD_ANIM_SLOT_10_ACTIVE
    xor a
    cp [hl]
    ret z

    ld hl, SPRITE_OBJECT_SLOT_10 + SPRITE_OBJECT_BASE_X
    ld a, [hl]
    call StepFieldAnimSlot10SideDelta
    cp FIELD_ANIM_END_SENTINEL
    ret z

    cpl
    inc a
    add b
    ld [hl], a
    dec l
    dec l
    ld a, [hl]
    call StepFieldAnimSlot10SideDelta
    add b
    ld [hl], a
    ret


StepFieldAnimSlot10SideDelta::
    push hl
    ld b, a
    ld a, [FIELD_ANIM_SLOT_10_CURSOR]
    ld hl, FieldSideDeltaTable
    call GetArrayElement
    cp FIELD_ANIM_END_SENTINEL
    jr z, jr_000_2241

    ld hl, FIELD_ANIM_SLOT_10_CURSOR
    inc [hl]
    pop hl
    ret


jr_000_2241:
    xor a
    ld [FIELD_ANIM_SLOT_10_ACTIVE], a
    ld [FIELD_ANIM_SLOT_10_CURSOR], a
    ld [SPRITE_OBJECT_SLOT_10], a
    ld a, FIELD_ANIM_END_SENTINEL
    pop hl
    ret


UpdateFieldAnimSlot13::
    ld hl, FIELD_ANIM_SLOT_13_ACTIVE
    xor a
    cp [hl]
    ret z

    ld hl, SPRITE_OBJECT_SLOT_13 + SPRITE_OBJECT_BASE_X
    ld a, [hl]
    call StepFieldAnimSlot13RowDelta
    cp FIELD_ANIM_END_SENTINEL
    ret z

    ld [hl], a
    dec l
    dec l
    ld a, [hl]
    call StepFieldAnimSlot13RowDelta
    ld [hl], a
    ret


StepFieldAnimSlot13RowDelta::
    push hl
    ld b, a
    ld a, [FIELD_ANIM_SLOT_13_CURSOR]
    ld hl, FieldRowDeltaTable
    call GetArrayElement
    cp FIELD_ANIM_END_SENTINEL
    jr z, jr_000_227e

    add b
    ld hl, FIELD_ANIM_SLOT_13_CURSOR
    inc [hl]
    pop hl
    ret


jr_000_227e:
    xor a
    ld [FIELD_ANIM_SLOT_13_ACTIVE], a
    ld [FIELD_ANIM_SLOT_13_CURSOR], a
    ld [SPRITE_OBJECT_SLOT_13], a
    ld a, FIELD_ANIM_END_SENTINEL
    pop hl
    ret


UpdateFieldAnimSlot12::
    ld hl, FIELD_ANIM_SLOT_12_ACTIVE
    xor a
    cp [hl]
    ret z

    ld hl, SPRITE_OBJECT_SLOT_12 + SPRITE_OBJECT_BASE_X
    ld a, [hl]
    call StepFieldAnimSlot12RowDelta
    cp FIELD_ANIM_END_SENTINEL
    ret z

    cpl
    inc a
    add b
    ld [hl], a
    dec l
    dec l
    ld a, [hl]
    call StepFieldAnimSlot12RowDelta

StoreFieldAnimCoordinate::
    add b
    ld [hl], a
    ret


StepFieldAnimSlot12RowDelta::
    push hl
    ld b, a
    ld a, [FIELD_ANIM_SLOT_12_CURSOR]
    ld hl, FieldRowDeltaTable
    call GetArrayElement
    cp FIELD_ANIM_END_SENTINEL
    jr z, jr_000_22be

    ld hl, FIELD_ANIM_SLOT_12_CURSOR
    inc [hl]
    pop hl
    ret


jr_000_22be:
    xor a
    ld [FIELD_ANIM_SLOT_12_ACTIVE], a
    ld [FIELD_ANIM_SLOT_12_CURSOR], a
    ld [SPRITE_OBJECT_SLOT_12], a
    ld a, FIELD_ANIM_END_SENTINEL
    pop hl
    ret


FieldSideDeltaTable::
    db $01, $ff, $01, $ff, $01, $ff, $01, $00
    db $01, $00, $01, $ff, $01, $00, $01, $01
    db $01, $00, $01, $00, $01, $01, $01, $01
    db $01, $01, $01, $01, $00, $01, $00, $01
    db $01, $01, $00, $01, $00, $01, $01, $01
    db $00, $01, $00, $01, $00, $01, $00, $01
    db $00, $01, $00, $01, $00, $01, $00, $01
    db $00, $01, $00, $01, $00, $01, $00, $01
    db $00, $01, $10
FieldRowDeltaTable::
    db $01, $00, $01, $00, $01, $01, $01, $00
    db $01, $00, $01, $01, $01, $00, $01, $01
    db $01, $01, $01, $01, $01, $01, $00, $01
    db $00, $01, $00, $01, $00, $01, $00, $01
    db $00, $01, $00, $01, $01, $01, $00, $01
    db $00, $01, $00, $01, $00, $01, $00, $01
    db $00, $01, $00, $01, $00, $01, $00, $01
    db $00, $01, $00, $01, $10

UpdateFieldTimers::
    ld hl, FIELD_COLUMN_TIMERS
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
    ld a, FIELD_COLUMN_TIMER_COUNT
    cp b
    jr nz, jr_000_2351

    ret


ResetTimers::
    push bc
    push hl
    ld a, b
    add FIELD_COLUMN_TIMER_RELOAD
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
    cp GAME_STATE_PLAYING
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
    ld a, [LINK_SEND_QUEUE_INDEX]
    ld hl, LINK_SEND_QUEUE_0
    add l
    ld l, a
    jr nc, jr_000_23a6

    inc h

jr_000_23a6:
    ld a, [LINK_SEND_QUEUE_INDEX]
    inc a
    cp $02
    jr c, jr_000_23af

    xor a

jr_000_23af:
    ld [LINK_SEND_QUEUE_INDEX], a
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
    ld a, [LINK_PENDING_FIELD_RISE]
    add b
    ld [LINK_PENDING_FIELD_RISE], a
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
    ld [LINK_SEND_QUEUE_1], a
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
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_SEND_QUEUE_1], a
    ld a, [LINK_RECV]
    bit 7, a
    jr z, jr_000_246a

    res 7, a
    ld [$c708], a
    ldh a, [ANIM_FRAME]
    ld [LINK_SEND], a
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_SEND_QUEUE_1], a
    call WaitVBlank
    ldh a, [ANIM_FRAME]
    ld [LINK_SEND], a
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_SEND_QUEUE_1], a
    call WaitVBlank

jr_000_249d:
    pop hl
    pop de
    pop bc
    pop af
    ret


Run2PPreplayLoop::
    call UpdateGameField
    call FormatNumber
    call TickSettingsBlink
    call Multiply
    ld a, [LINK_ROLE]
    cp $01
    jr nz, jr_000_24d9

    ldh a, [JOYPAD_PRESSED]
    and a
    ret z

    push af
    xor a
    ld [SETTINGS_BLINK_PHASE], a
    ld a, SETTINGS_BLINK_PERIOD
    ld [SETTINGS_BLINK_TIMER], a
    pop af
    bit 3, a
    jr z, jr_000_24ff

    call WaitVBlank
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
    call WaitVBlank
    call InitGameState
    ld a, GAME_STATE_PLAY_SETUP
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
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld a, [LINK_SETTINGS_CURSOR]
    and a
    ret z

    ld hl, LINK_SETTINGS_CURSOR
    dec [hl]
    ret


jr_000_251f:
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld a, [LINK_SETTINGS_CURSOR]
    cp LINK_SETTINGS_ROW_SPEED
    ret z

    ld hl, LINK_SETTINGS_CURSOR
    inc [hl]
    ret


jr_000_252f:
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld hl, LINK_2P_SELECTED_LEVEL
    ld a, [LINK_SETTINGS_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, LinkSettingsMaxValueTable
    ld a, [LINK_SETTINGS_CURSOR]
    call GetArrayElement
    cp b
    pop hl
    ret z

    inc [hl]
    ret


LinkSettingsMaxValueTable::
    db $05, $02

jr_000_2550:
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld a, [LINK_SETTINGS_CURSOR]
    ld hl, LINK_2P_SELECTED_LEVEL
    call GetArrayElement
    and a
    ret z

    dec [hl]
    ret


DisplayP1Score::
    ld a, SETTINGS_BLINK_PERIOD
    ld [SETTINGS_BLINK_TIMER], a
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
    call UpdateColumn
    ld hl, $0301
    ld bc, $1206
    ld a, $4a
    call UpdateColumn
    ld hl, $0b01
    ld bc, $1206
    ld a, $4a
    call UpdateColumn
    ret


DrawScoreDigits::
    ld a, [LINK_ROLE]
    cp $01
    jr z, jr_000_25b9

    ld de, ScoreHeaderTextRoleOther
    jr jr_000_25bc

jr_000_25b9:
    ld de, ScoreHeaderTextRole1

jr_000_25bc:
    ld hl, $0103
    call DrawStringToGrid
    ret


ScoreHeaderTextRole1::
    db $4a, $70, $71, $72, $73, $4a, $d1, $d2
    db $4a, $74, $75, $76, $77, $4a, $ff
ScoreHeaderTextRoleOther::
    db $4a, $74, $75, $76, $77, $4a, $d1, $d2
    db $4a, $70, $71, $72, $73, $4a, $ff

CalcBonus::
    ld hl, $0708
    ld a, [LINK_SETTINGS_CURSOR]
    cp LINK_SETTINGS_ROW_SPEED
    jr nz, jr_000_25f6

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, jr_000_25f6

    ld de, ResultTextBlock2
    jr jr_000_2604

jr_000_25f6:
    ld a, [LINK_2P_SELECTED_SPEED]
    and a
    jr nz, jr_000_2601

    ld de, ResultTextBlock0
    jr jr_000_2604

jr_000_2601:
    ld de, ResultTextBlock1

jr_000_2604:
    call DrawStringToGrid
    call DrawStringToGrid
    ld hl, $0f08
    ld a, [LINK_RECV_SPEED]
    and a
    jr nz, jr_000_2618

    ld de, ResultTextBlock0
    jr jr_000_261b

jr_000_2618:
    ld de, ResultTextBlock1

jr_000_261b:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


ResultTextBlock0::
    db $bc, $bd, $be, $bf, $4a, $4a, $e4, $e5, $e6, $e7, $ff
    db $c0, $c1, $c2, $9d, $4a, $4a, $e8, $e9, $ea, $eb, $ff
ResultTextBlock1::
    db $dc, $dd, $de, $df, $4a, $4a, $d4, $d5, $d6, $d7, $ff
    db $e0, $e1, $e2, $e3, $4a, $4a, $d8, $d9, $da, $db, $ff
ResultTextBlock2::
    db $dc, $dd, $de, $df, $4a, $4a, $e4, $e5, $e6, $e7, $ff
    db $e0, $e1, $e2, $e3, $4a, $4a, $e8, $e9, $ea, $eb, $ff

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
    ld a, [LINK_SETTINGS_CURSOR]
    and a
    jr z, jr_000_26b7

    ld bc, $04aa
    jr jr_000_26ba

jr_000_26b7:
    ld bc, $04a6

jr_000_26ba:
    call DrawColumnData
    ret


DrawStatValue::
    ld hl, $0702
    call DrawStatRow
    ret


DrawStatRow::
    ld b, $04
    ld a, [LINK_SETTINGS_CURSOR]
    cp LINK_SETTINGS_ROW_SPEED
    jr z, jr_000_26d3

    ld bc, $04b2
    jr jr_000_26d6

jr_000_26d3:
    ld bc, $04ae

jr_000_26d6:
    call DrawColumnData
    ret


DrawNextPiece::
    ld a, $04
    ld [ANIM_FRAME], a
    ld [STATE_TRANSITION], a
    ld a, [LINK_2P_SELECTED_LEVEL]
    call DrawNextPieceSprite
    ld a, $0c
    ld [ANIM_FRAME], a
    ld a, $04
    ld [STATE_TRANSITION], a
    ld a, [LINK_RECV_LEVEL]
    call DrawPreview
    ret


DrawNextPieceSprite::
    ldh [TEXT_FADE], a
    ld a, [LINK_SETTINGS_CURSOR]
    and a
    jr nz, jr_000_270c

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, jr_000_270c

    ld de, PiecePreviewBlankText
    jr jr_000_2722

jr_000_270c:
    ldh a, [TEXT_FADE]

DrawPreview::
    ld hl, PiecePreviewTextTable
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


PiecePreviewTextTable::
PiecePreviewText0::
    db $2a, $2b, $2c, $24, $25, $26, $24, $25, $26, $24, $25, $26, $24, $25, $26, $ff
    db $2d, $41, $79, $27, $42, $78, $27, $43, $78, $27, $44, $78, $27, $45, $78, $ff
    db $2e, $7b, $2f, $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $ff
PiecePreviewText1::
    db $24, $25, $26, $2a, $2b, $2c, $24, $25, $26, $24, $25, $26, $24, $25, $26, $ff
    db $27, $41, $78, $2d, $42, $79, $27, $43, $78, $27, $44, $78, $27, $45, $78, $ff
    db $28, $7a, $29, $2e, $7b, $2f, $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $ff
PiecePreviewText2::
    db $24, $25, $26, $24, $25, $26, $2a, $2b, $2c, $24, $25, $26, $24, $25, $26, $ff
    db $27, $41, $78, $27, $42, $78, $2d, $43, $79, $27, $44, $78, $27, $45, $78, $ff
    db $28, $7a, $29, $28, $7a, $29, $2e, $7b, $2f, $28, $7a, $29, $28, $7a, $29, $ff
PiecePreviewText3::
    db $24, $25, $26, $24, $25, $26, $24, $25, $26, $2a, $2b, $2c, $24, $25, $26, $ff
    db $27, $41, $78, $27, $42, $78, $27, $43, $78, $2d, $44, $79, $27, $45, $78, $ff
    db $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $2e, $7b, $2f, $28, $7a, $29, $ff
PiecePreviewText4::
    db $24, $25, $26, $24, $25, $26, $24, $25, $26, $24, $25, $26, $2a, $2b, $2c, $ff
    db $27, $41, $78, $27, $42, $78, $27, $43, $78, $27, $44, $78, $2d, $45, $79, $ff
    db $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $2e, $7b, $2f, $ff
PiecePreviewBlankText::
    db $24, $25, $26, $24, $25, $26, $24, $25, $26, $24, $25, $26, $24, $25, $26, $ff
    db $27, $41, $78, $27, $42, $78, $27, $43, $78, $27, $44, $78, $27, $45, $78, $ff
    db $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $28, $7a, $29, $ff

UpdateGameField::
    ld a, [LINK_2P_SELECTED_LEVEL]
    swap a
    ld b, a
    ld a, [LINK_2P_SELECTED_SPEED]
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
    ld [LINK_RECV_LEVEL], a
    ld a, b
    and $0f
    ld [LINK_RECV_SPEED], a
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
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_000_28d4

    ld hl, EGG_COUNT_HUNDREDS
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
    ld a, [GAME_TYPE]
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
    ld a, [GAME_TYPE]
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

    ld a, [GAME_TYPE]
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
    ld a, ROM_BANK_GRAPHICS_1
    ld [MBC1_ROM_BANK_REG], a
    ld hl, Bank3ResultTilesTo9000
    ld de, $9000
    ld bc, $0800
    call MemcopyCall
    ld hl, Bank3ResultTilesTo8800
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
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
    ld a, [GAME_TYPE]
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
    ld a, [GAME_TYPE]
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
    call WaitVBlank
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
    ld a, [GAME_TYPE]
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
    ld hl, RoundPaletteSequence
    ld b, $04

jr_000_2b91:
    ld a, [hl+]
    ldh [rBGP], a
    ld c, $10
    call DrawString
    dec b
    jr nz, jr_000_2b91

    ret


RoundPaletteSequence::
    db $00, $40, $90, $e4

InitPreplayBlinkTimer::
    ld a, SETTINGS_BLINK_PERIOD
    ld [SETTINGS_BLINK_TIMER], a
    ret


Init1PPreplayScreen::
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


Draw1PPreplayScreen::
    call AnimateResult
    call DrawWinMessage1
    call DrawResultMessage1
    call DrawLoseMessage1
    call ProcessRestart
    call ShowFinalResult
    call ShowWinScreen
    call UpdateContinue
    ret


Run1PPreplayLoop::
    call TickBgmPreviewTimer
    call Draw1PPreplayScreen
    call Multiply
    call TickSettingsBlink
    ldh a, [JOYPAD_PRESSED]
    and a
    ret z

    push af
    xor a
    ld [SETTINGS_BLINK_PHASE], a
    ld a, SETTINGS_BLINK_PERIOD
    ld [SETTINGS_BLINK_TIMER], a
    call DrawCountdownNum
    pop af
    bit 3, a
    jr z, jr_000_2c17

    call InitGameState
    ld a, GAME_STATE_PLAY_SETUP
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
    ld hl, OPTION_GAME_TYPE
    ld a, [MENU_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, RoundEndOptionMaxValueTable
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


RoundEndOptionMaxValueTable::
    db $02, $05, $02, $04

jr_000_2c64:
    ld a, [MENU_CURSOR]
    ld hl, OPTION_GAME_TYPE
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
    call UpdateColumn
    ld hl, $0301
    ld bc, $1202
    ld a, $4a
    call UpdateColumn
    ld hl, $0601
    ld bc, $1204
    ld a, $4a
    call UpdateColumn
    ld hl, $0b01
    ld bc, $1202
    ld a, $4a
    call UpdateColumn
    ld hl, $0e01
    ld bc, DrawNumber
    ld a, $4a
    call UpdateColumn
    ret


ProcessWinLose::
    ld hl, HeaderLogo
    ld de, ResultHeaderText
    call DrawStringToGrid
    ret


ResultHeaderText::
    db $41, $4a, $8f, $8b, $80, $98, $84, $91
    db $4a, $86, $80, $8c, $84, $ff ; "1 PLAYER GAME"
    db $4a, $98, $8e, $92, $92, $98, $4a, $84
    db $86, $86, $92, $4a, $ff ; " YOSSY EGGS "

ShowWinScreen::
    ld hl, $0b07
    ld a, [MENU_CURSOR]
    cp $02
    jr nz, jr_000_2cec

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, jr_000_2cec

    ld de, ResultTextBlock2
    jr jr_000_2cfa

jr_000_2cec:
    ld a, [OPTION_SPEED]
    and a
    jr nz, jr_000_2cf7

    ld de, ResultTextBlock0
    jr jr_000_2cfa

jr_000_2cf7:
    ld de, ResultTextBlock1

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
    call DrawColumnData
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
    call DrawColumnData
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
    call DrawColumnData
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
    call DrawColumnData
    ret


ShowFinalResult::
    ld a, $07
    ld [ANIM_FRAME], a
    ld a, $04
    ld [STATE_TRANSITION], a
    ld a, [OPTION_LEVEL]
    call WaitForRestart
    ret


WaitForRestart::
    ldh [TEXT_FADE], a
    ld a, [MENU_CURSOR]
    cp $01
    jr nz, jr_000_2d8f

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, jr_000_2d8f

    ld de, PiecePreviewBlankText
    jr jr_000_2da5

jr_000_2d8f:
    ldh a, [TEXT_FADE]
    ld hl, PiecePreviewTextTable
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

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, jr_000_2dcb

    ld de, RestartTextBlock2
    jr jr_000_2dd9

jr_000_2dcb:
    ld a, [OPTION_GAME_TYPE]
    and a
    jr nz, jr_000_2dd6

    ld de, RestartTextBlock0
    jr jr_000_2dd9

jr_000_2dd6:
    ld de, RestartTextBlock1

jr_000_2dd9:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


RestartTextBlock0::
    db $f4, $ec, $ed, $ee, $ef, $f5, $4a, $fa, $fd, $fe, $d3, $4a, $ff
    db $f6, $f0, $f1, $f2, $f3, $f7, $4a, $fb, $0d, $1c, $1d, $4a, $ff
RestartTextBlock1::
    db $4a, $fc, $fd, $fe, $d3, $4a, $f4, $f8, $ed, $ee, $ef, $f5, $ff
    db $4a, $0c, $0d, $1c, $1d, $4a, $f6, $f9, $f1, $f2, $f3, $f7, $ff
RestartTextBlock2::
    db $4a, $fc, $fd, $fe, $d3, $4a, $4a, $fa, $fd, $fe, $d3, $4a, $ff
    db $4a, $0c, $0d, $1c, $1d, $4a, $4a, $fb, $0d, $1c, $1d, $4a, $ff

DrawContinue::
    ld hl, $0f10
    ld de, ContinueOffText
    call DrawStringToGrid
    ret


ContinueOffText::
    db $8e, $85, $85, $ff ; "OFF"

UpdateContinue::
    ld hl, $0f06
    ld a, [MENU_CURSOR]
    cp $03
    jr nz, jr_000_2e58

    ld a, [OPTION_BGM]
    cp $03
    jr nz, jr_000_2e58

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, jr_000_2e58

    ld de, BgmMarkerNoneText
    jr jr_000_2e78

jr_000_2e58:
    ld a, [OPTION_BGM]
    and a
    jr z, jr_000_2e70

    cp $01
    jr z, jr_000_2e75

    cp $02
    jr z, jr_000_2e6b

    ld de, BgmMarker3Text
    jr jr_000_2e78

jr_000_2e6b:
    ld de, BgmMarker2Text
    jr jr_000_2e78

jr_000_2e70:
    ld de, BgmMarker0Text
    jr jr_000_2e78

jr_000_2e75:
    ld de, BgmMarker1Text

jr_000_2e78:
    call DrawStringToGrid
    ret


BgmMarker0Text::
    db $9a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $ff
BgmMarker1Text::
    db $4a, $4a, $4a, $9a, $4a, $4a, $4a, $4a, $4a, $4a, $ff
BgmMarker2Text::
    db $4a, $4a, $4a, $4a, $4a, $4a, $9a, $4a, $4a, $4a, $ff
BgmMarker3Text::
    db $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $9a, $ff
BgmMarkerNoneText::
    db $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a, $ff
    ld b, $04
    ld a, [MENU_CURSOR]
    and a
    jr z, jr_000_2ec0

    ld bc, $04aa
    jr jr_000_2ec3

jr_000_2ec0:
    ld bc, $04a6

jr_000_2ec3:
    call DrawColumnData
    ret


TickSettingsBlink::
    ld hl, SETTINGS_BLINK_TIMER
    dec [hl]
    ret nz

    ld a, SETTINGS_BLINK_PERIOD
    ld [hl], a
    ld a, [SETTINGS_BLINK_PHASE]
    xor $01
    ld [SETTINGS_BLINK_PHASE], a
    ret


DrawCountdownNum::
    ld hl, SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME
    ld de, SPRITE_OBJECT_SLOT_SIZE
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
    ld a, [COUNTDOWN_BLIT_TIMER]
    and a
    ret z

    ld a, [COUNTDOWN_BLIT_PHASE]
    xor $ff
    ld [COUNTDOWN_BLIT_PHASE], a
    jr nz, jr_000_2f54

    ld a, [$c61e]
    swap a
    and $f0
    srl a
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, jr_000_2f09

    inc d

jr_000_2f09:
    ld hl, COUNTDOWN_DIGIT_BUFFER_2
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

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
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, jr_000_2f27

    inc d

jr_000_2f27:
    ld hl, COUNTDOWN_DIGIT_BUFFER_2
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

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
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, jr_000_2f48

    inc d

jr_000_2f48:
    ld hl, COUNTDOWN_DIGIT_BUFFER_3
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

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
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, jr_000_2f65

    inc d

jr_000_2f65:
    ld hl, COUNTDOWN_DIGIT_BUFFER_1
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

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
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, jr_000_2f83

    inc d

jr_000_2f83:
    ld hl, COUNTDOWN_DIGIT_BUFFER_1
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

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
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, jr_000_2fa6

    inc d

jr_000_2fa6:
    ld hl, COUNTDOWN_DIGIT_BUFFER_0
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS
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
    ld a, [COUNTDOWN_BLIT_TIMER]
    and a
    ret z

    dec a
    ld [COUNTDOWN_BLIT_TIMER], a
    ld a, [COUNTDOWN_BLIT_PHASE]
    and a
    jr nz, jr_000_2fe2

    ld de, COUNTDOWN_DIGIT_BUFFER_2
    ld hl, $9020
    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

jr_000_2fd1:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2fd1

    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

jr_000_2fda:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2fda

    ret


jr_000_2fe2:
    ld de, COUNTDOWN_DIGIT_BUFFER_0
    ld hl, $9120
    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

jr_000_2fea:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2fea

    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

jr_000_2ff3:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, jr_000_2ff3

    ret


CountdownDigitPatternTable::
CountdownDigitPattern0::
    db $38, $6c, $6c, $6c, $6c, $6c, $38, $00
CountdownDigitPattern1::
    db $38, $18, $18, $18, $18, $18, $18, $00
CountdownDigitPattern2::
    db $78, $0c, $0c, $38, $60, $60, $7c, $00
CountdownDigitPattern3::
    db $78, $0c, $0c, $38, $0c, $0c, $78, $00
CountdownDigitPattern4::
    db $6c, $6c, $6c, $6c, $7c, $0c, $0c, $00
CountdownDigitPattern5::
    db $7c, $60, $60, $7c, $0c, $0c, $78, $00
CountdownDigitPattern6::
    db $38, $60, $60, $78, $6c, $6c, $38, $00
CountdownDigitPattern7::
    db $7c, $0c, $08, $18, $18, $30, $30, $00
CountdownDigitPattern8::
    db $38, $6c, $6c, $38, $6c, $6c, $38, $00
CountdownDigitPattern9::
    db $38, $6c, $6c, $6c, $3c, $0c, $38, $00

ProcessRoundComplete::
    ld hl, SPRITE_OBJECT_SLOT_10
    ld de, SPRITE_OBJECT_SLOT_SIZE
    xor a
    ld b, a

jr_000_3053:
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE
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
    ld [FIELD_ANIM_SLOT_11_ACTIVE], a
    ld [FIELD_ANIM_SLOT_10_ACTIVE], a
    ld [FIELD_ANIM_SLOT_13_ACTIVE], a
    ld [FIELD_ANIM_SLOT_12_ACTIVE], a
    ld a, SND_ROUND_COMPLETE
    call PlaySound
    ret


jr_000_3081:
    call DrawScoreRanking
    jr jr_000_30a1

HandleRoundEnd::
    call UpdateAnimFrame
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
    ld a, [SOUND_CH_ACTIVE_ID]
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

    ld hl, ACTIVE_LEVEL
    call StartNextRound
    ld a, GAME_STATE_PLAYING
    ld [GAME_STATE], a
    ret


jr_000_30e0:
    ld a, [GAME_TYPE]
    and a

Jump_000_30e4:
    jr nz, jr_000_30eb

    call InitAnimFrame
    jr jr_000_3100

jr_000_30eb:
    ld a, [RESULT_RANK_POSITION]
    and a
    jr z, jr_000_3100

    ld a, [$c6e2]
    call ProcessMatching
    call StartNextRound
    ld a, GAME_STATE_PLAYING
    ld [GAME_STATE], a
    ret


jr_000_3100:
    push af
    xor a
    ld hl, SPRITE_OBJECTS
    ld b, $ef

jr_000_3107:
    ld [hl+], a
    dec b
    jr nz, jr_000_3107

    call ClearField
    pop af

jr_000_310f:
    ld a, GAME_STATE_TITLE_INIT
    ld [GAME_STATE], a
    ld hl, $c6ab
    ld [hl], $00
    ret


DrawScoreRanking::
    ld hl, $0804
    ld b, $08
    ld a, [RESULT_RANK_POSITION]
    cp $43
    jr nz, jr_000_3128

    ld a, $01

jr_000_3128:
    swap a
    add $50
    call DrawRankEntry
    ld hl, $0904
    ld b, $08
    ld a, [RESULT_RANK_POSITION]
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
    ld hl, SPRITE_OBJECT_SLOT_10
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
    ld [RESULT_RANK_POSITION], a
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
    ld [RESULT_RANK_POSITION], a
    and a
    jr z, jr_000_31a1

    ld a, SND_STOP_ALL
    call PlaySound
    ld a, $69
    call PlaySound
    call DrawScoreRanking
    jr jr_000_31ab

jr_000_31a1:
    ld a, SND_STOP_ALL
    call PlaySound
    ld a, $66
    call PlaySound

jr_000_31ab:
    ld hl, $c75b
    ld a, $3c
    ld [hl+], a
    ld [hl], $00
    ld a, GAME_STATE_ROUND_END
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
    call WaitVBlank
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
    ld a, ROM_BANK_GRAPHICS_1
    ld [MBC1_ROM_BANK_REG], a
    ld hl, Bank3HighScoreTilesTo9000
    ld de, $9000
    ld bc, $0800
    call MemcopyCall
    ld hl, Bank3HighScoreTilesTo8800
    ld de, $8800
    ld bc, $0800
    call MemcopyCall
    ldh a, [STATE_TRANSITION]
    and a
    jr z, jr_000_3264

    ld hl, Bank3HighScoreOverlayTilesTo9470
    ld de, $9470
    ld bc, $0390
    call MemcopyCall
    ld hl, Bank3HighScoreOverlayTilesTo8800
    ld de, $8800
    ld bc, $0740
    call MemcopyCall

jr_000_3264:
    ld hl, $c4a0
    ld bc, $0168
    ld d, $18
    call DrawCharacter
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
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
    jp WaitLinkStartConfirm


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


WaitLinkStartConfirm::
    xor a
    ldh [ANIM_FRAME], a
    call WaitVBlank
    ld a, [SOUND_CH_ACTIVE_ID]
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
    call WaitVBlank
    ld a, [SOUND_CH_ACTIVE_ID]
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
    ld a, SND_CONFIRM
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
    ld hl, EGG_COUNT_ONES
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

    ld a, [EGG_COUNT_TENS]
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
    ld hl, SPRITE_OBJECT_SLOT_1
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
    ld [COUNTDOWN_BLIT_TIMER], a
    ld de, TitleResultTileData0
    ld hl, $8820
    ld c, $50
    call VRAMCopySetup
    ld de, TitleResultTileData1
    ld hl, $9140
    ld c, $11
    call VRAMCopySetup
    ld a, $01
    ld [GAME_ACTIVE], a
    ld a, [EGG_COUNT_HUNDREDS]
    and a
    jr z, jr_000_35e6

    ld hl, $37b1
    jr jr_000_35f5

jr_000_35e6:
    ld a, [EGG_COUNT_TENS]
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
    call WaitVBlank
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
    call WaitVBlank
    call SetupMultiplayer
    call UpdateAnimFrame
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
    call AddScore
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
    call WaitVBlank
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
    call WaitVBlank
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


TitleResultTileData0::
    db $00, $00, $03, $03, $0c, $0c, $10, $10, $10, $16, $20, $26, $20, $20, $30, $20
    db $00, $00, $c0, $c0, $30, $70, $08, $68, $08, $08, $04, $04, $04, $04, $04, $1c
    db $70, $40, $70, $4c, $60, $5e, $60, $5e, $33, $2c, $3f, $20, $1f, $18, $07, $07
    db $02, $3e, $02, $3e, $06, $1a, $3e, $02, $cc, $34, $cc, $34, $f8, $18, $e0, $e0
    db $00, $00, $03, $03, $0d, $0d, $10, $10, $10, $16, $20, $26, $21, $21, $31, $21
    db $00, $00, $c0, $c0, $b0, $f0, $88, $e8, $88, $88, $84, $84, $04, $04, $84, $9c
    db $71, $41, $76, $4e, $62, $5e, $60, $5e, $33, $2c, $3f, $20, $1f, $18, $07, $07
    db $82, $be, $42, $7e, $26, $3a, $3e, $02, $cc, $34, $cc, $34, $f8, $18, $e0, $e0
    db $00, $00, $07, $07, $19, $1e, $33, $2c, $7f, $40, $7c, $43, $98, $e7, $98, $e7
    db $00, $00, $e0, $e0, $98, $78, $cc, $34, $fe, $02, $3e, $c2, $19, $e7, $19, $e7
    db $98, $e7, $bc, $c3, $7f, $4f, $32, $32, $22, $22, $20, $20, $10, $10, $0f, $0f
    db $19, $e7, $3d, $c3, $fe, $f2, $4c, $4c, $44, $44, $04, $04, $08, $08, $f0, $f0
    db $00, $00, $21, $21, $52, $52, $4c, $4c, $80, $80, $8c, $8c, $92, $92, $80, $80
    db $00, $00, $84, $84, $4a, $4a, $32, $32, $01, $01, $31, $31, $49, $49, $01, $01
    db $40, $40, $38, $38, $07, $07, $3b, $3a, $7f, $46, $7f, $42, $ff, $81, $7f, $7f
    db $02, $02, $1c, $1c, $e0, $e0, $dc, $5c, $fe, $62, $fe, $42, $ff, $81, $fe, $fe
    db $00, $00, $01, $01, $03, $02, $03, $02, $07, $04, $ff, $fc, $ff, $80, $7f, $42
    db $00, $00, $80, $80, $40, $40, $40, $40, $a0, $20, $bf, $3f, $c1, $01, $fa, $42
    db $3f, $22, $1f, $10, $3f, $20, $3f, $20, $7f, $41, $7e, $46, $f8, $98, $e0, $e0
    db $f4, $44, $e8, $08, $f4, $04, $f4, $04, $fa, $82, $7a, $62, $1d, $19, $07, $07
    db $00, $00, $07, $07, $18, $18, $20, $20, $40, $40, $54, $54, $94, $94, $80, $80
    db $00, $00, $c0, $c0, $30, $30, $08, $08, $04, $04, $04, $04, $32, $32, $4a, $4a
    db $80, $aa, $80, $be, $80, $be, $40, $5f, $40, $55, $20, $20, $1c, $1c, $03, $03
    db $0a, $0a, $11, $11, $01, $01, $01, $01, $02, $02, $0c, $0c, $30, $30, $c0, $c0
    db $30, $30, $1f, $1f, $1d, $1d, $35, $35, $36, $36, $7a, $7a, $7b, $7b, $7f, $7f
    db $00, $00, $80, $80, $e0, $e0, $f0, $f0, $f0, $f0, $f8, $f8, $f8, $f8, $fe, $fe
    db $7f, $7f, $3f, $3f, $3f, $3f, $1f, $1f, $09, $09, $10, $10, $08, $08, $07, $07
    db $f2, $f2, $e2, $e2, $e2, $e2, $e4, $e4, $d8, $d8, $80, $80, $80, $80, $80, $80
    db $01, $01, $6d, $01, $ff, $01, $ff, $01, $fe, $29, $fe, $01, $6c, $03, $71, $70
    db $c0, $c0, $f0, $30, $f8, $08, $f8, $88, $7c, $64, $7c, $94, $7e, $8e, $f7, $75
    db $88, $88, $e4, $e4, $94, $94, $6c, $6c, $30, $30, $0c, $0c, $03, $03, $00, $00
    db $8f, $8d, $17, $1d, $e7, $fd, $7b, $0b, $30, $10, $30, $30, $f8, $c8, $78, $78
    db $00, $00, $06, $06, $0d, $09, $0a, $0a, $3f, $30, $5f, $40, $ff, $94, $ff, $80
    db $00, $00, $e0, $e0, $70, $10, $90, $90, $98, $88, $c8, $08, $fc, $04, $fc, $04
    db $ff, $80, $7f, $40, $3f, $31, $0e, $0e, $10, $10, $10, $10, $08, $08, $1f, $1f
    db $fc, $44, $f8, $68, $b8, $88, $3c, $04, $1e, $02, $7e, $62, $bc, $b4, $f8, $f8
    db $00, $00, $00, $00, $00, $00, $00, $00, $03, $03, $06, $04, $0e, $0e, $33, $33
    db $00, $00, $00, $00, $00, $00, $00, $00, $c0, $c0, $e0, $20, $a0, $a0, $b0, $90
    db $5c, $40, $7f, $64, $bf, $80, $bf, $80, $7f, $40, $7f, $40, $3f, $31, $0e, $0e
    db $90, $90, $f0, $10, $f8, $08, $fc, $04, $fc, $44, $f8, $48, $b0, $b0, $20, $20
    db $02, $02, $0c, $0c, $1c, $14, $1c, $14, $0c, $0c, $02, $02, $07, $07, $07, $07
    db $60, $20, $70, $50, $f8, $88, $fe, $96, $7f, $61, $3d, $3d, $5e, $5e, $fc, $fc
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $01, $01, $01, $01, $02, $02
    db $00, $00, $0d, $0d, $17, $12, $3d, $3d, $c3, $c3, $7c, $00, $7f, $00, $ff, $88
    db $00, $00, $c0, $c0, $e0, $20, $a0, $a0, $b0, $90, $90, $90, $f0, $70, $f0, $10
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $02, $02, $02, $02, $01, $01, $01, $01, $00, $00, $00, $00, $00, $00, $00, $00
    db $ff, $00, $ff, $00, $ff, $00, $ff, $00, $ff, $c1, $3e, $3e, $02, $02, $0c, $0c
    db $fb, $0b, $fc, $04, $bc, $84, $b8, $88, $31, $31, $fe, $e0, $78, $20, $79, $21
    db $00, $00, $80, $80, $80, $80, $80, $80, $40, $40, $40, $40, $80, $80, $40, $40
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $3c, $34, $78, $48, $78, $48, $38, $38, $04, $04, $04, $04, $0b, $0b, $0f, $0f
    db $7e, $50, $ff, $89, $fe, $8e, $7e, $76, $1f, $01, $3f, $3d, $5e, $5e, $fc, $fc
    db $40, $40, $80, $80, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $00, $00, $00, $00, $00, $00, $01, $01, $01, $01, $03, $03, $0c, $0c, $13, $10
    db $00, $00, $00, $00, $ee, $ee, $ff, $11, $2b, $29, $e9, $e8, $39, $38, $fc, $04
    db $00, $00, $00, $00, $00, $00, $00, $00, $01, $01, $81, $81, $be, $be, $a0, $a0
    db $00, $00, $00, $00, $00, $00, $c0, $c0, $20, $20, $20, $20, $1f, $1f, $01, $01
    db $2f, $20, $2f, $28, $5f, $40, $5f, $40, $5f, $40, $5f, $40, $5f, $40, $3f, $20
    db $fe, $02, $ff, $81, $ff, $00, $ff, $00, $ff, $00, $ff, $02, $ff, $01, $ff, $01
    db $90, $90, $88, $88, $c4, $44, $c4, $44, $e8, $28, $e8, $28, $f3, $33, $ec, $2c
    db $02, $02, $04, $04, $08, $08, $08, $08, $04, $04, $c4, $c4, $32, $32, $0c, $0c
    db $3f, $20, $1f, $18, $07, $07, $00, $00, $00, $00, $00, $00, $00, $00, $01, $01
    db $fe, $06, $f8, $18, $e1, $e0, $39, $38, $41, $40, $43, $40, $83, $80, $83, $81
    db $e0, $60, $90, $f0, $90, $f0, $a0, $e0, $d8, $58, $e6, $2e, $e1, $ef, $e0, $2f
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $80, $80
    db $03, $02, $03, $02, $03, $02, $01, $01, $00, $00, $00, $00, $00, $00, $00, $00
    db $83, $82, $83, $82, $81, $81, $c0, $c0, $40, $40, $70, $70, $9c, $bc, $ff, $ff
    db $f0, $10, $ff, $1f, $ff, $20, $ff, $c0, $3f, $3e, $4f, $5f, $7f, $7f, $ff, $ff
    db $c0, $c0, $f8, $38, $fc, $04, $f4, $04, $c8, $08, $30, $30, $c0, $c0, $00, $00
    db $00, $00, $07, $07, $04, $04, $04, $04, $07, $07, $01, $01, $01, $01, $07, $07
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $00, $00, $17, $17, $15, $15, $15, $15, $15, $15, $15, $15, $15, $15, $17, $17
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $00, $00, $77, $77, $15, $15, $15, $15, $75, $75, $45, $45, $45, $45, $77, $77
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $00, $00, $77, $77, $45, $45, $45, $45, $75, $75, $15, $15, $15, $15, $77, $77
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00
    db $00, $00, $70, $70, $50, $50, $50, $50, $50, $50, $50, $50, $50, $50, $70, $70
    db $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00, $00

TitleResultTileData1::
    db $00, $00, $00, $00, $00, $00, $c6, $c6, $c6, $c6, $ee, $ee, $7c, $7c, $38, $38
    db $00, $00, $00, $00, $00, $00, $fe, $fe, $c0, $c0, $fc, $fc, $c0, $c0, $fe, $fe
    db $00, $00, $00, $00, $00, $00, $fc, $fc, $c6, $c6, $ce, $ce, $f8, $f8, $ce, $ce
    db $00, $00, $00, $00, $00, $00, $66, $66, $66, $66, $3c, $3c, $18, $18, $18, $18
    db $00, $00, $00, $00, $00, $00, $7e, $7e, $e0, $e0, $ce, $ce, $e6, $e6, $7e, $7e
    db $00, $00, $00, $00, $00, $00, $7c, $7c, $c6, $c6, $c6, $c6, $c6, $c6, $7c, $7c
    db $00, $00, $00, $00, $00, $00, $f8, $f8, $cc, $cc, $c6, $c6, $cc, $cc, $f8, $f8
    db $00, $00, $00, $00, $38, $38, $38, $38, $38, $38, $10, $10, $00, $00, $10, $10
    db $00, $00, $00, $00, $00, $00, $c6, $c6, $6c, $6c, $38, $38, $6c, $6c, $c6, $c6
    db $00, $00, $00, $00, $00, $00, $60, $60, $60, $60, $60, $60, $60, $60, $7e, $7e
    db $00, $00, $00, $00, $00, $00, $c6, $c6, $f6, $f6, $fe, $fe, $de, $de, $c6, $c6
    db $00, $00, $00, $00, $00, $00, $7e, $7e, $18, $18, $18, $18, $18, $18, $18, $18
    db $00, $00, $00, $00, $00, $00, $7e, $7e, $e0, $e0, $7c, $7c, $0e, $0e, $fc, $fc
    db $00, $00, $00, $00, $00, $00, $c6, $c6, $c6, $c6, $c6, $c6, $c6, $c6, $7c, $7c
    db $00, $00, $00, $00, $00, $00, $fc, $fc, $c6, $c6, $c6, $c6, $fc, $fc, $c0, $c0
    db $00, $00, $00, $00, $00, $00, $7c, $7c, $c6, $c6, $c6, $c6, $fe, $fe, $c6, $c6
    db $00, $00, $00, $00, $00, $00, $7c, $7c, $c6, $c6, $c0, $c0, $c6, $c6, $7c, $7c

Bank0TailGraphicsData::
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39, $00
    db $39, $00, $39, $00, $39, $00, $39, $00, $39, $9c, $df, $00, $39, $db, $45, $00
    db $39, $95, $fe, $00, $39, $fd, $e7, $00, $39, $ad, $a7, $00, $39, $02, $fc, $00
    db $39, $2c, $bb, $00, $39, $93, $00
