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

UnusedInterruptVectorPadding::
    REPT UNUSED_INTERRUPT_VECTOR_PADDING_PREFIX_WORDS
        dw UNUSED_INTERRUPT_VECTOR_PADDING_WORD
    ENDR
    dw UNUSED_INTERRUPT_VECTOR_PADDING_ZERO_WORD
    REPT UNUSED_INTERRUPT_VECTOR_PADDING_SUFFIX_WORDS
        dw UNUSED_INTERRUPT_VECTOR_PADDING_WORD
    ENDR

EntryPoint::
    nop
    jp Init


HeaderLogo::
    NINTENDO_LOGO

HeaderTitle::
    db "YOSSY NO TAMAGO", $00

HeaderNewLicenseeCode::
    db HEADER_NEW_LICENSEE_CODE_UNUSED_HI, HEADER_NEW_LICENSEE_CODE_UNUSED_LO

HeaderSGBFlag::
    db HEADER_SGB_FLAG_NONE

HeaderCartridgeType::
    db HEADER_CARTRIDGE_TYPE_MBC1

HeaderROMSize::
    db HEADER_ROM_SIZE_64KB

HeaderRAMSize::
    db HEADER_RAM_SIZE_NONE

HeaderDestinationCode::
    db HEADER_DESTINATION_JAPAN

HeaderOldLicenseeCode::
    db HEADER_OLD_LICENSEE_NINTENDO

HeaderMaskROMVersion::
    db HEADER_MASK_ROM_VERSION_0

HeaderComplementCheck::
    db HEADER_COMPLEMENT_CHECK_VALUE

HeaderGlobalChecksum::
    db HEADER_GLOBAL_CHECKSUM_HI, HEADER_GLOBAL_CHECKSUM_LO

ReadJoypad::
    ld a, P1F_GET_DPAD
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
    and P1_INPUT_BITS_MASK
    swap a
    ld b, a
    ld a, P1F_GET_BTN
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
    and P1_INPUT_BITS_MASK
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
    ld a, P1F_GET_NONE
    ldh [rP1], a
    ld a, b
    ldh [JOYPAD_HELD], a
    and P1_INPUT_BITS_MASK
    cp P1_INPUT_BITS_RELEASED
    ret nz

ResetJoypadStateAndReinitOnRelease:
    xor a
    ldh [JOYPAD_HELD], a

WaitJoypadLinesReleasedLoop:
    ld a, P1F_GET_NONE
    ldh [rP1], a
    ld b, a
    ld a, P1F_GET_BTN
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]

JoypadStuckCheck::
    and P1_INPUT_BITS_MASK
    jr z, WaitJoypadLinesReleasedLoop

    jp Init


SetupOAMDMA::
    ld c, OAM_DMA_HRAM_LOW
    ld b, OAM_DMA_ROUTINE_SIZE
    ld hl, OAMDMARoutine

CopyOAMDMARoutineToHRAMLoop:
    ld a, [hl+]
    ldh [c], a

OAMDMACopyLoop::
    inc c
    dec b
    jr nz, CopyOAMDMARoutineToHRAMLoop

    ret


OAMDMARoutine::
    ld a, SHADOW_OAM_HI
    ldh [rDMA], a
    ld a, OAM_DMA_WAIT_LOOP_COUNT

WaitOAMDMATransfer:
    dec a
    jr nz, WaitOAMDMATransfer

    ret

LCDOff::
    ldh a, [rIE]
    ld b, a
    res IEB_VBLANK, a
    ldh [rIE], a

WaitForLCDOffSafeLine:
    ldh a, [rLY]
    cp LCD_OFF_SAFE_SCANLINE
    jr nz, WaitForLCDOffSafeLine

    ldh a, [rLCDC]
    and LCDC_DISABLE_MASK

StoreDisabledLCDCAndRestoreIE:
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

ClearShadowOamLoop:
    ld [hl+], a
    dec b
    jr nz, ClearShadowOamLoop

    ret


HideAllSprites::
    ld a, OAM_HIDDEN_Y
    ld hl, SHADOW_OAM
    ld de, OAM_ENTRY_SIZE
    ld b, OAM_SPRITE_COUNT

HideShadowOamSpritesLoop:
    ld [hl], a
    add hl, de
    dec b
    jr nz, HideShadowOamSpritesLoop

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


CopyBytesDuplicatedLoop:
    ld a, [hl+]
    ld [de], a
    inc de
    ld [de], a
    inc de
    dec bc
    ld a, c
    or b
    jr nz, CopyBytesDuplicatedLoop

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
    cp VRAM_COPY_MAX_BLOCKS_PER_VBLANK
    jr nc, VRAMCopyFullChunk

    ldh [VRAM_COPY_BLOCKS], a
    call WaitVBlank
    ret


VRAMCopyFullChunk:
    ld a, VRAM_COPY_MAX_BLOCKS_PER_VBLANK
    ldh [VRAM_COPY_BLOCKS], a
    call WaitVBlank
    ld a, c
    sub VRAM_COPY_MAX_BLOCKS_PER_VBLANK
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
    cp VRAM_COPY_MAX_BLOCKS_PER_VBLANK
    jr nc, UnusedVRAMCopy2FullChunk

    ldh [UNUSED_VRAM_COPY2_BLOCKS], a
    call WaitVBlank
    ret


UnusedVRAMCopy2FullChunk:
    ld a, VRAM_COPY_MAX_BLOCKS_PER_VBLANK
    ldh [UNUSED_VRAM_COPY2_BLOCKS], a
    call WaitVBlank
    ld a, c
    sub VRAM_COPY_MAX_BLOCKS_PER_VBLANK
    ld c, a
    jr UnusedVRAMCopy2NextChunk

StateInit::
    xor a
    ldh [GAME_STATE], a
    ld a, TITLE_INIT_LCDC_FLAGS
    ldh [rLCDC], a
    ld a, BG_MAP_SHADOW_COPY_ENABLED
    ld [BG_MAP_SHADOW_COPY_ENABLE_FLAG], a

MainLoop::
    call WaitVBlank
    call ReadJoypad
    ldh a, [GAME_STATE]
    and a
    jr nz, DispatchTitleMenuState

    ; GAME_STATE_TITLE_INIT: load title graphics, initialize title UI, then advance.
    call LCDOff
    ld a, ROM_BANK_GRAPHICS_0
    ld [MBC1_ROM_BANK_REG], a
    ld hl, GameTileSet
    ld de, VRAM_TILE_BLOCK_8000
    ld bc, BANK2_GAME_TILE_SET_COPY_SIZE
    call MemcopyCall
    ld hl, TitleTileSet
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK2_TITLE_TILE_SET_COPY_SIZE
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
    call FillTitleTilemap
    call ResetScoreAccumulatorAndDigits
    call InitTitleUI
    ld a, LCD_REDRAW_EXPAND_REQUEST
    ld [LCD_REDRAW], a
    jp AdvanceState


DispatchTitleMenuState:
    dec a
    jr nz, DispatchPlaySetupState

    ; GAME_STATE_TITLE_MENU: poll title/player-selection input.
    call RunTitleMenu
    jr MainLoop

DispatchPlaySetupState:
    dec a
    jr nz, DispatchPlayingState

    ; GAME_STATE_PLAY_SETUP: load playfield graphics and initialize the game board.
    call LCDOff
    ld a, LCD_REDRAW_EXPAND_REQUEST
    ld [LCD_REDRAW], a
    call LoadGameTiles
    call LCDOn
    call FillGameTilemap
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, PlaySinglePlayerSelectedBgm

    call ApplyGameSettings
    jr InitPlayfieldAfterBgmSetup

PlaySinglePlayerSelectedBgm:
    ld a, [BGM_INDEX]
    call PlaySound

InitPlayfieldAfterBgmSetup:
    call InitPlayfield
    ld a, LCD_REDRAW_EXPAND_REQUEST
    ld [LCD_REDRAW], a
    jr AdvanceState

DispatchPlayingState:
    dec a
    jr nz, DispatchRoundEndState

    ; GAME_STATE_PLAYING: regular per-frame gameplay update.
    call HandlePause
    call RunGameplayFrame
    jp MainLoop


DispatchRoundEndState:
    dec a
    jr nz, DispatchPreplayLoopState

    ; GAME_STATE_ROUND_END: result/high-score/continue processing.
    call HandleRoundEnd
    jp MainLoop


DispatchPreplayLoopState:
    dec a
    jr nz, DispatchPreplayInitState

    ; GAME_STATE_PREPLAY_LOOP: settings/start-wait loop before the play setup state.
    call RunPreplayLoop
    jp MainLoop


DispatchPreplayInitState:
    dec a
    jr nz, IgnoreInvalidGameStateAndLoop

    ; GAME_STATE_PREPLAY_INIT: load settings/start-wait graphics, then enter the loop.
    call LCDOff
    ld a, ROM_BANK_GRAPHICS_0
    ld [MBC1_ROM_BANK_REG], a
    ld hl, CommonTileSet
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK2_COMMON_TILE_SET_COPY_SIZE
    call MemcopyCall
    ld hl, PreplayMenuOverlayTiles
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK2_PREPLAY_MENU_OVERLAY_COPY_SIZE
    call MemcopyCall
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call StartGameplay
    call LCDOn
    ld a, GAME_STATE_PREPLAY_LOOP
    jr StoreGameStateAndLoop

IgnoreInvalidGameStateAndLoop:
    jp MainLoop


AdvanceState::
    ldh a, [GAME_STATE]
    inc a

StoreGameStateAndLoop:
    ldh [GAME_STATE], a
    jp MainLoop


LoadGameTiles::
    ld a, ROM_BANK_GRAPHICS_0
    ld [MBC1_ROM_BANK_REG], a
    ld hl, CommonTileSet
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK2_COMMON_TILE_SET_COPY_SIZE
    call MemcopyCall
    ld hl, GameTileSet
    ld de, VRAM_TILE_BLOCK_8000
    ld bc, BANK2_GAME_TILE_SET_COPY_SIZE
    call MemcopyCall
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, RestoreMainBankAfterGameTileLoad

    ld hl, TwoPlayerSharedTiles
    ld de, TWO_PLAYER_SHARED_TILES_VRAM_DEST
    ld bc, BANK2_TWO_PLAYER_SHARED_TILES_COPY_SIZE
    call MemcopyCall
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, RestoreMainBankAfterGameTileLoad

    ld hl, TwoPlayerNonMasterTiles
    ld de, TWO_PLAYER_NONMASTER_TILES_VRAM_DEST
    ld bc, BANK2_TWO_PLAYER_NONMASTER_TILES_COPY_SIZE
    call MemcopyCall

RestoreMainBankAfterGameTileLoad:
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    ret


HandlePause::
    ld hl, TWO_PLAYER_FLAG
    xor a
    cp [hl]
    jr z, CheckPauseButtonInput

    ld hl, LINK_ROLE
    ld a, LINK_ROLE_MASTER

CheckPauseAllowedForLinkMaster:
    cp [hl]
    jr z, CheckPauseButtonInput

    ret


CheckPauseButtonInput:
    ldh a, [JOYPAD_PRESSED]
    and PADF_START
    ret z

    call PauseGame

WaitPauseResumeInputLoop:
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and PADF_START
    jr z, WaitPauseResumeInputLoop

    call UnpauseGame
    ret


PauseGame::
    ld a, PAUSE_FLAG_ACTIVE
    ld [PAUSE_FLAG], a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, PlayPauseSoundAndHalt

    ld a, SOUND_PAUSE_FLAG_ACTIVE
    ld [SOUND_PAUSE_FLAG], a

PlayPauseSoundAndHalt:
    ld a, SND_PAUSE
    call PlaySound
    xor a
    ld [LCD_REDRAW], a
    halt

DrawPauseOverlay::
    ld hl, PauseOverlayOamTemplate
    ld de, SHADOW_OAM
    ld bc, PAUSE_OVERLAY_OAM_TEMPLATE_SIZE
    call MemcopyCall
    ret


UnpauseGame::
    ld a, LCD_REDRAW_EXPAND_REQUEST
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
    cp LINK_ROLE_MASTER
    ret z

    call PauseGame

WaitLinkPeerUnpauseLoop:
    call WaitVBlank
    call DrawPauseOverlay
    ld a, [LINK_RECV]
    cp LINK_PAUSE_PACKET
    jr z, WaitLinkPeerUnpauseLoop

    jp UnpauseGame


MACRO OAM_TEMPLATE_ENTRY
    db \1, \2, \3, \4
ENDM

PauseOverlayOamTemplate::
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_0, PAUSE_OVERLAY_OAM_TILE_0, PAUSE_OVERLAY_OAM_ATTR
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_1, PAUSE_OVERLAY_OAM_TILE_1, PAUSE_OVERLAY_OAM_ATTR
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_2, PAUSE_OVERLAY_OAM_TILE_2, PAUSE_OVERLAY_OAM_ATTR
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_3, PAUSE_OVERLAY_OAM_TILE_3, PAUSE_OVERLAY_OAM_ATTR
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_4, PAUSE_OVERLAY_OAM_TILE_4, PAUSE_OVERLAY_OAM_ATTR
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_5, PAUSE_OVERLAY_OAM_TILE_5, PAUSE_OVERLAY_OAM_ATTR
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_6, PAUSE_OVERLAY_OAM_TILE_6, PAUSE_OVERLAY_OAM_ATTR
    OAM_TEMPLATE_ENTRY PAUSE_OVERLAY_OAM_Y, PAUSE_OVERLAY_OAM_X_7, PAUSE_OVERLAY_OAM_TILE_7, PAUSE_OVERLAY_OAM_ATTR

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
    ld a, LCDCF_ON
    ldh [rLCDC], a
    call LCDOff
    ld a, DEFAULT_BGP_OBP0_PALETTE
    ldh [rBGP], a
    ld a, DEFAULT_BGP_OBP0_PALETTE
    ldh [rOBP0], a
    ld a, DEFAULT_OBP1_PALETTE
    ldh [rOBP1], a
    ld sp, STACK_TOP
    ld hl, WRAM_PERSIST_MAGIC
    ld a, [hl+]
    cp WRAM_PERSIST_MAGIC_BYTE_0
    jr nz, UseFullWRAMClear

    ld a, [hl+]
    cp WRAM_PERSIST_MAGIC_BYTE_1

CheckPersistMagicByte1:
    jr nz, UseFullWRAMClear

    ld a, [hl+]
    cp WRAM_PERSIST_MAGIC_BYTE_2
    jr nz, UseFullWRAMClear

    ld a, [hl+]
    cp WRAM_PERSIST_MAGIC_BYTE_3
    jr nz, UseFullWRAMClear

    ld d, WRAM_CLEAR_MODE_PRESERVE_RESULT_RECORDS
    jr BeginWRAMClear

UseFullWRAMClear:
    ld d, WRAM_CLEAR_MODE_FULL

BeginWRAMClear:
    xor a
    ld hl, WRAM_START
    ld bc, WRAM_SIZE

ClearWRAMLoop:
    cp d
    jr nz, ClearWRAMByte

    ld a, RESULT_RECORDS_PERSIST_START_HI
    cp h
    jr nz, ClearWRAMByte

    ld a, RESULT_RECORDS_PERSIST_START_LO
    cp l
    jr nz, ClearWRAMByte

    ld hl, ROUND_END_WAIT_TIMER

ClearWRAMByte:
    xor a
    ld [hl+], a
    dec c
    jr nz, ClearWRAMLoop

    dec b
    jr nz, ClearWRAMLoop

    ld hl, WRAM_PERSIST_MAGIC
    ld a, WRAM_PERSIST_MAGIC_BYTE_0
    ld [hl+], a
    ld a, WRAM_PERSIST_MAGIC_BYTE_1
    ld [hl+], a
    ld a, WRAM_PERSIST_MAGIC_BYTE_2
    ld [hl+], a
    ld a, WRAM_PERSIST_MAGIC_BYTE_3
    ld [hl], a
    xor a
    ld hl, VRAM_START

ClearVRAM::
    ld bc, VRAM_SIZE

ClearVRAMLoop:
    ld [hl+], a
    dec c
    jr nz, ClearVRAMLoop

    dec b
    jr nz, ClearVRAMLoop

    ld b, HRAM_WORK_CLEAR_SIZE
    ld hl, OAM_DMA_HRAM

ClearHRAMWorkAreaLoop:
    ld [hl+], a
    dec b
    jr nz, ClearHRAMWorkAreaLoop

    call ClearOAM
    call SetupOAMDMA
    xor a
    ldh [rSTAT], a
    ldh [rIF], a
    ldh [SCX_SHADOW], a
    ldh [SCY_SHADOW], a
    ld a, STARTUP_ENABLED_INTERRUPTS
    ldh [rIE], a
    ld a, WY_OFFSCREEN_Y
    ldh [WY_SHADOW], a
    ldh [rWY], a
    ld a, WX_LEFT_EDGE
    ldh [rWX], a
    ld h, SCRN0_HI
    call FillTilemap
    ld h, SCRN1_HI
    call FillTilemap

StartGame::
    ld a, GAME_LCDC_FLAGS
    ldh [rLCDC], a
    ld a, SND_STOP_ALL
    call PlaySound
    xor a
    ld [WAVE_UPDATE], a
    ei
    jp StateInit


FillGameTilemap::
    ld a, GAME_BG_SHADOW_CLEAR_TILE
    jr BeginBgMapShadowFill

FillTitleTilemap::
    ld a, TITLE_BG_SHADOW_CLEAR_TILE

BeginBgMapShadowFill:
    ld bc, BG_MAP_SHADOW_SIZE
    inc b
    ld hl, BG_MAP_SHADOW

FillBgMapShadowLoop:
    ld [hl+], a
    dec c
    jr nz, FillBgMapShadowLoop

    dec b
    jr nz, FillBgMapShadowLoop

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


CalcTilemapAddress::
    ld a, h
    sla a
    sla a
    add h
    sla a
    sla a
    ld h, BG_MAP_SHADOW_HI
    jr nc, AddTilemapColumnOffset

    inc h

AddTilemapColumnOffset:
    add l
    jr nc, AddBgMapShadowBaseLow

    inc h

AddBgMapShadowBaseLow:
    add BG_MAP_SHADOW_LO
    jr nc, StoreCalculatedTilemapAddressLow

    inc h

StoreCalculatedTilemapAddressLow:
    ld l, a
    ret


FillTilemap::
    ld a, HARDWARE_TILEMAP_CLEAR_TILE
    jr BeginHardwareTilemapFill

    ld a, l

BeginHardwareTilemapFill:
    ld de, HARDWARE_TILEMAP_SIZE
    ld l, e

FillHardwareTilemapLoop:
    ld [hl+], a
    dec e
    jr nz, FillHardwareTilemapLoop

    dec d
    jr nz, FillHardwareTilemapLoop

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
    ld bc, RNG_MULTIPLIER_HIGH_WORD
    ld a, RNG_MULTIPLIER_LOW_BYTE
    ldh [RNG_MULTIPLIER_LOW_WORK], a
    ld hl, RNG_WORK
    ld [hl], RNG_INCREMENT_BYTE_0
    inc hl
    ld [hl], RNG_INCREMENT_BYTE_1
    inc hl
    ld [hl], RNG_INCREMENT_BYTE_2
    inc hl
    ld [hl], RNG_INCREMENT_BYTE_3

MultiplyShiftMultiplierLoop:
    ld hl, RNG_MULTIPLIER_LOW_WORK
    srl b
    rr c
    rr [hl]
    jr c, AddShiftedMultiplicandToProduct

    jr nz, ShiftMultiplicandForNextBit

    ld hl, RNG_WORK
    ld de, RNG_STATE
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


AddShiftedMultiplicandToProduct:
    ld hl, RNG_WORK_LAST
    ld de, RNG_STATE_LAST
    ld a, [de]
    dec de
    add [hl]
    ld [hl-], a

MultiplyAddStep::
    ld a, [de]

MultiplyAddCarryChain:
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

ShiftMultiplicandForNextBit:
    ld hl, RNG_STATE_LAST
    sla [hl]
    dec hl
    rl [hl]
    dec hl
    rl [hl]
    dec hl
    rl [hl]
    jr MultiplyShiftMultiplierLoop

MultiplyAndCount::
    call Multiply
    and c
    ld c, $00

CountMaskedMultiplyBitsLoop:
    sla a
    jr nc, ContinueMaskedMultiplyBitCount

    inc c

ContinueMaskedMultiplyBitCount:
    jr nz, CountMaskedMultiplyBitsLoop

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
    jr z, TickSpriteObjectWaitPhase

    call UpdateFallingPieceMotionAndLanding
    and a
    ret z

    jr WriteBackSpriteObjectStaging

TickSpriteObjectWaitPhase:
    ld hl, SPRITE_OBJECT_STAGING + SPRITE_OBJECT_DELAY_COUNTER
    dec [hl]
    jr nz, WriteBackSpriteObjectStaging

    ld a, [SPRITE_OBJECT_DELAY_RELOAD]
    ld [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_DELAY_COUNTER], a
    ld a, SPRITE_OBJECT_PHASE_UPDATE
    ld [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_PHASE], a

WriteBackSpriteObjectStaging:
    ld hl, SPRITE_OBJECT_STAGING
    ld d, SPRITE_OBJECTS_HI
    ld a, [SPRITE_OBJECT_SLOT_OFFSET_TMP]
    ld e, a
    ld bc, SPRITE_OBJECT_STAGING_SIZE
    call MemcopyCall
    ret


GetColumnSpritePatternOffset::
    sla a
    sla a
    ld e, a
    sla a
    add e
    ld de, ColumnSpritePatternTable
    add e
    ld e, a
    ret nc

    inc d
    ret


GetGridPiecePatternOffset::
    sla a
    sla a
    sla a
    ld de, GridPiecePatternTable
    add e
    ld e, a
    ret nc

    inc d
    ret


CopyTilePatternRow4::
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


CopyEncodedTilePatternRow4SkipFF::
    ld a, [de]
    inc de
    inc a
    jr z, AdvanceAfterConditionalSpriteByte0

    ld [hl], a

AdvanceAfterConditionalSpriteByte0:
    inc hl
    ld a, [de]
    inc de
    inc a
    jr z, AdvanceAfterConditionalSpriteByte1

    ld [hl], a

AdvanceAfterConditionalSpriteByte1:
    inc hl
    ld a, [de]
    inc de
    inc a
    jr z, AdvanceAfterConditionalSpriteByte2

    ld [hl], a

AdvanceAfterConditionalSpriteByte2:
    inc hl
    ld a, [de]
    inc de
    inc a
    jr z, ReturnAfterConditionalSpriteBytes

    ld [hl], a

ReturnAfterConditionalSpriteBytes:
    ret


DrawColumnSprite::
    push af
    ld a, COLUMN_COUNT
    sub b
    ld c, a
    ld l, a
    sla l
    sla l
    ld de, COLUMN_TOP_ROWS
    add e
    ld e, a
    jr nc, ReadColumnTopRowForSprite

    inc d

ReadColumnTopRowForSprite:
    ld a, [de]
    ld h, a
    REPT COLUMN_SPRITE_TOP_ROW_OFFSET
        dec h
    ENDR
    ld a, c
    call GetColumnSpritePatternOffset
    call CalcTilemapAddress
    pop af
    dec a
    jr nz, DrawColumnSpriteRow0

    ld a, COLUMN_SPRITE_FRAME_BLOCK_SIZE
    add e
    ld e, a
    jr nc, DrawColumnSpriteRow0

    inc d
    jr DrawColumnSpriteRow0

UnreachedColumnSpriteAlternateRowFragment:
    push af
    ld a, h
    cp COLUMN_TOP_ROW_OVERFLOW_SENTINEL
    jr z, UnreachedColumnSpriteWrapRow

    call CalcTilemapAddress
    pop af
    call GetColumnSpritePatternOffset
    jr DrawColumnSpriteRow0

UnreachedColumnSpriteWrapRow:
    inc h
    call CalcTilemapAddress
    pop af
    call GetColumnSpritePatternOffset
    ld a, GRID_PIECE_TILE_WIDTH
    add e
    ld e, a
    jr nc, UnreachedColumnSpriteContinueAtRow1

    inc d

UnreachedColumnSpriteContinueAtRow1:
    jr DrawColumnSpriteRow1

DrawColumnSpriteRow0:
    call CopyEncodedTilePatternRow4SkipFF
    ld a, GRID_PIECE_NEXT_ROW_DELTA
    add l
    ld l, a
    jr nc, DrawColumnSpriteRow1

    inc h

DrawColumnSpriteRow1:
    call CopyEncodedTilePatternRow4SkipFF
    ld a, GRID_PIECE_NEXT_ROW_DELTA
    add l
    ld l, a
    jr nc, DrawColumnSpriteRow2

    inc h

DrawColumnSpriteRow2:
    call CopyEncodedTilePatternRow4SkipFF
    ret


DrawGridPiece::
    push af
    ld a, h
    cp GRID_DRAW_ROW_LIMIT
    jr c, DrawGridPieceWithinBounds

    pop af
    ret


DrawGridPieceWithinBounds:
    pop af
    call GetGridPiecePatternOffset
    call CalcTilemapAddress
    call CopyTilePatternRow4
    ld a, GRID_PIECE_NEXT_ROW_DELTA
    add l
    ld l, a
    jr nc, DrawGridPieceSecondRow

    inc h

DrawGridPieceSecondRow:
    call CopyTilePatternRow4
    ret


ClearColumnLeft::
    push hl
    push bc
    ld b, a
    dec l
    call CalcTilemapAddress

ClearColumnLeftLoop:
    ld [hl], GRID_COLUMN_CLEAR_TILE
    dec b
    jr z, ReturnFromClearColumnLeft

    ld a, l
    add BG_MAP_ROW_STRIDE
    ld l, a
    jr nc, ClearColumnLeftLoop

ClearColumnLeftNextTilemapPage:
    inc h
    jr ClearColumnLeftLoop

ReturnFromClearColumnLeft:
    pop bc
    pop hl
    ret


ClearColumnRight::
    push hl
    push bc
    ld b, a
    REPT GRID_PIECE_TILE_WIDTH
        inc l
    ENDR
    call CalcTilemapAddress

ClearColumnRightLoop:
    ld [hl], GRID_COLUMN_CLEAR_TILE
    dec b
    jr z, ReturnFromClearColumnRight

    ld a, l
    add BG_MAP_ROW_STRIDE
    ld l, a
    jr nc, ClearColumnRightLoop

    inc h
    jr ClearColumnRightLoop

ReturnFromClearColumnRight:
    pop bc
    pop hl
    ret


DrawAllColumns::
    ld l, BOARD_DRAW_FIRST_COLUMN
    ld de, BOARD_DATA + BOARD_CELL_VISIBLE_PAYLOAD_OFFSET
    ld c, COLUMN_COUNT

DrawAllColumnsColumnLoop:
    ld b, BOARD_VISIBLE_ROW_COUNT
    ld h, BOARD_DRAW_FIRST_ROW

DrawAllColumnsRowLoop:
    ld a, [de]
    REPT BOARD_CELL_STRIDE
        inc de
    ENDR
    push de
    push hl
    call DrawGridPiece
    pop hl
    pop de
    REPT BOARD_CELL_STRIDE
        inc h
    ENDR
    dec b
    jr nz, DrawAllColumnsRowLoop

    ld a, e
    add BOARD_CELL_STRIDE
    ld e, a
    jr nc, AdvanceDrawAllColumnsColumn

    inc d

AdvanceDrawAllColumnsColumn:
    REPT GRID_PIECE_TILE_WIDTH
        inc l
    ENDR
    dec c
    jr nz, DrawAllColumnsColumnLoop

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
    ld de, BOARD_COLUMN_BOTTOM_VISIBLE_CELL
    ld a, [DROP_ANIM_COLUMN]
    inc a
    swap a
    add e
    ld e, a
    jr nc, BeginDropDownCascade

    inc d

BeginDropDownCascade:
    ld b, DROP_ANIM_STATE_COUNT

AnimateDropDownCascadeLoop:
    ld a, [hl]
    and a
    jp z, AdvanceDropDownCascadeSlot

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
    jr nz, CheckDropDownCascadeEnd

    ld a, b
    cp DROP_ANIM_STATE_STRIDE
    jr c, AdvanceDropDownCascadeSlot

    REPT DROP_ANIM_STATE_STRIDE
        inc hl
    ENDR
    ld [hl], DROP_ANIM_STATE_START
    REPT DROP_ANIM_STATE_STRIDE
        dec hl
    ENDR
    jr AdvanceDropDownCascadeSlot

CheckDropDownCascadeEnd:
    cp DROP_ANIM_STATE_END
    jr nz, AdvanceDropDownCascadeSlot

    ld [hl], DROP_ANIM_STATE_INACTIVE

AdvanceDropDownCascadeSlot:
    REPT BOARD_CELL_STRIDE
        dec de
    ENDR
    REPT DROP_ANIM_STATE_STRIDE
        inc hl
    ENDR
    dec b
    jp nz, AnimateDropDownCascadeLoop

    ld hl, DROP_ANIM_UP_STATES
    ld de, BOARD_COLUMN_BOTTOM_VISIBLE_CELL
    ld a, [DROP_ANIM_COLUMN]
    swap a
    add e
    ld e, a
    jr nc, BeginDropUpCascade

    inc d

BeginDropUpCascade:
    ld b, DROP_ANIM_STATE_COUNT

AnimateDropUpCascadeLoop:
    ld a, [hl]
    and a
    jp z, AdvanceDropUpCascadeSlot

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
    jr nz, CheckDropUpCascadeEnd

    ld a, b
    cp DROP_ANIM_STATE_STRIDE
    jr c, AdvanceDropUpCascadeSlot

    REPT DROP_ANIM_STATE_STRIDE
        inc hl
    ENDR
    ld [hl], DROP_ANIM_STATE_START
    REPT DROP_ANIM_STATE_STRIDE
        dec hl
    ENDR
    jr AdvanceDropUpCascadeSlot

CheckDropUpCascadeEnd:
    cp DROP_ANIM_STATE_END
    jr nz, AdvanceDropUpCascadeSlot

    ld [hl], DROP_ANIM_STATE_INACTIVE
    ld a, b
    dec a
    jr z, FinishDropCascadeAndSwapColumns

AdvanceDropUpCascadeSlot:
    REPT BOARD_CELL_STRIDE
        dec de
    ENDR
    REPT DROP_ANIM_STATE_STRIDE
        inc hl
    ENDR
    dec b
    jp nz, AnimateDropUpCascadeLoop

    ret


FinishDropCascadeAndSwapColumns:
    call UpdateDropPositions
    ld h, d
    ld a, e
    add BOARD_COLUMN_STRIDE
    ld l, a
    jr nc, BeginDropAnimationColumnSwap

    inc h

BeginDropAnimationColumnSwap:
    ld b, DROP_ANIM_STATE_COUNT

SwapDropAnimationColumnCellsLoop:
    ld c, [hl]
    ld a, [de]
    ld [hl], a
    ld a, c
    ld [de], a
    REPT BOARD_CELL_STRIDE
        inc hl
    ENDR
    REPT BOARD_CELL_STRIDE
        inc de
    ENDR
    dec b
    jr nz, SwapDropAnimationColumnCellsLoop

    ld hl, COLUMN_TOP_ROWS
    ld a, [DROP_ANIM_COLUMN]
    add l
    ld l, a
    jr nc, SwapColumnTopRowsAfterDrop

    inc h

SwapColumnTopRowsAfterDrop:
    ld a, [hl+]
    ld b, [hl]
    ld [hl-], a
    ld [hl], b
    xor a
    ld [DROP_ANIM_ACTIVE], a
    ret


CheckDropDownCollisionAndNudge::
    dec bc
    ld a, [DROP_ANIM_COLUMN]
    inc a
    call CheckDropCollisionAgainstActiveObjects
    ret nc

    inc l
    ld a, [hl]
    sub DROP_COLLISION_SPRITE_X_STEP
    ld [hl], a
    scf
    ret


CheckDropUpCollisionAndNudge::
    inc bc
    ld a, [DROP_ANIM_COLUMN]
    call CheckDropCollisionAgainstActiveObjects
    ret nc

    inc l
    ld a, [hl]
    add DROP_COLLISION_SPRITE_X_STEP
    ld [hl], a
    scf
    ret


CheckDropCollisionAgainstActiveObjects::
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

ScanDropCollisionSpriteSlotsLoop:
    ld a, [hl]
    and a
    jr z, SkipInactiveDropCollisionSlot

    inc l
    inc l
    inc l
    inc l
    ld a, c
    sub [hl]
    call c, CheckDropSpriteOverlap
    ld a, DROP_COLLISION_ADVANCE_FROM_BASE_Y
    jr AdvanceDropCollisionSlot

SkipInactiveDropCollisionSlot:
    ld a, SPRITE_OBJECT_SLOT_SIZE

AdvanceDropCollisionSlot:
    add l
    ld l, a
    dec b
    jr nz, ScanDropCollisionSpriteSlotsLoop

    and a
    ret


CheckDropSpriteOverlap::
    ld a, d
    sub [hl]
    cp DROP_COLLISION_Y_OVERLAP_LIMIT
    ret nc

    inc l
    ld a, e
    cp [hl]
    jr z, ReturnDropCollisionDetected

    dec l
    ret


ReturnDropCollisionDetected:
    pop bc
    scf
    ret


UpdateDropPositions::
    ld hl, SPRITE_OBJECT_SLOT_1 + SPRITE_OBJECT_GRID_COLUMN
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT

UpdateDropPositionsLoop:
    ld a, [hl]
    inc a
    jr nz, AdvanceDropPositionSlot

    inc l
    ld a, [hl-]
    swap a
    srl a
    ld [hl], a

AdvanceDropPositionSlot:
    ld a, SPRITE_OBJECT_SLOT_SIZE
    add l
    ld l, a
    dec b
    jr nz, UpdateDropPositionsLoop

    ret


CalcGridPosition::
    ld a, b
    sla a
    ld [DROP_ANIM_UNUSED_GRID_ROW_TMP], a
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
    jr nz, CheckDropDownState2

    call CalcGridPosition
    inc l
    inc l
    inc l
    inc bc
    ld a, [bc]
    sub h
    jr c, RedrawDropDownState1

    jr z, RedrawDropDownState1

    call CheckDropDownCollisionAndNudge
    jr ReturnFromDropDownState1

RedrawDropDownState1:
    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece

ReturnFromDropDownState1:
    ret


CheckDropDownState2:
    dec a
    jr nz, CheckDropDownState3

    call CalcGridPosition
    inc l
    inc l
    inc bc
    ld a, [bc]
    sub h
    jr c, RedrawDropDownState2

    jr z, RedrawDropDownState2

    call CheckDropDownCollisionAndNudge
    jr ReturnFromDropDownState2

RedrawDropDownState2:
    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece

ReturnFromDropDownState2:
    ret


CheckDropDownState3:
    dec a
    jr nz, HandleDropDownFinalState

    call CalcGridPosition
    inc l
    inc bc
    ld a, [bc]
    sub h
    jr c, RedrawDropDownState3

    jr z, RedrawDropDownState3

    call CheckDropDownCollisionAndNudge
    jr ReturnFromDropDownState3

RedrawDropDownState3:
    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece

ReturnFromDropDownState3:
    ret


HandleDropDownFinalState:
    call CalcGridPosition
    inc bc
    ld a, [bc]
    sub h
    jr c, RedrawDropDownFinalState

    jr z, RedrawDropDownFinalState

    call CheckDropDownCollisionAndNudge
    ret nc

    dec l
    ld [hl], SPRITE_OBJECT_GRID_COLUMN_UNSET
    ret


RedrawDropDownFinalState:
    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnRight
    ld a, [de]
    call DrawGridPiece
    ret


AnimateDropUp::
    dec a
    jr nz, CheckDropUpState2

    call CalcGridPosition
    inc l
    ld a, [bc]
    sub h
    jr c, RedrawDropUpState1

    jr z, RedrawDropUpState1

    call CheckDropUpCollisionAndNudge
    ret


RedrawDropUpState1:
    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnLeft
    ld a, [de]
    call DrawGridPiece
    ret


CheckDropUpState2:
    dec a
    jr nz, CheckDropUpState3

    call CalcGridPosition
    inc l
    inc l
    ld a, [bc]
    sub h
    jr c, RedrawDropUpState2

    jr z, RedrawDropUpState2

    call CheckDropUpCollisionAndNudge
    ret


RedrawDropUpState2:
    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnLeft
    ld a, [de]
    call DrawGridPiece
    ret


CheckDropUpState3:
    dec a
    jr nz, HandleDropUpFinalState

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
    jr c, HandleDropUpState3Boundary

    jr z, HandleDropUpState3Boundary

    call CheckDropUpCollisionAndNudge
    pop af
    ret


HandleDropUpState3Boundary:
    pop af
    jr c, DrawDropUpState3Piece

    cp DROP_ANIM_UP_CLEAR_LEFT_MIN_DELTA
    jr c, DrawDropUpState3Piece

    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnLeft

DrawDropUpState3Piece:
    ld a, [de]
    call DrawGridPiece
    ret


HandleDropUpFinalState:
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
    jr c, HandleDropUpFinalBoundary

    jr z, HandleDropUpFinalBoundary

    pop af
    call CheckDropUpCollisionAndNudge
    ret nc

    dec l
    ld [hl], SPRITE_OBJECT_GRID_COLUMN_UNSET
    ret


HandleDropUpFinalBoundary:
    pop af
    jr c, DrawDropUpFinalPiece

    cp DROP_ANIM_UP_CLEAR_LEFT_MIN_DELTA
    jr c, DrawDropUpFinalPiece

    ld a, GRID_PIECE_TILE_ROWS
    call ClearColumnLeft

DrawDropUpFinalPiece:
    ld a, [de]
    call DrawGridPiece
    ret


ClearDropAnimationState::
    ld hl, DROP_ANIM_ACTIVE
    ld b, DROP_ANIM_CLEAR_SIZE
    xor a

ClearDropAnimationStateLoop:
    ld [hl+], a
    dec b
    jr nz, ClearDropAnimationStateLoop

    ret


StartDropColumnSwapAnimation::
    push bc
    ld b, a
    ld a, [DROP_ANIM_ACTIVE]
    and a
    jr nz, ReturnFromStartDropColumnSwapAnimation

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
    ld a, DROP_ANIM_ACCEPTED_RETURN_VALUE
    pop hl

ReturnFromStartDropColumnSwapAnimation:
    pop bc
    ret


UnusedFillBoardDataPattern::
    ld d, UNUSED_BOARD_PATTERN_FIRST_COLUMN_INDEX
    ld hl, BOARD_DATA
    ld e, UNUSED_BOARD_PATTERN_FIRST_COLUMN_INDEX
    ld b, UNUSED_BOARD_PATTERN_COLUMN_COUNT

UnusedBoardPatternColumnLoop:
    ld a, UNUSED_BOARD_PATTERN_LEADING_CLEAR_BASE
    sub d
    ld c, a

ClearUnusedBoardPatternLeadingBytes:
    ld [hl], BOARD_PAYLOAD_EMPTY
    inc hl
    dec c
    jr nz, ClearUnusedBoardPatternLeadingBytes

    ld c, d
    inc c
    dec c
    jr z, StoreUnusedBoardPatternTailByte

    ld a, e

FillUnusedBoardPatternIndexBytes:
    ld [hl+], a
    dec c
    jr nz, FillUnusedBoardPatternIndexBytes

StoreUnusedBoardPatternTailByte:
    ld c, d
    sla c
    ld a, UNUSED_BOARD_PATTERN_TAIL_BASE
    sub c
    ld [hl], a
    inc hl
    inc d
    inc e
    dec b
    jr nz, UnusedBoardPatternColumnLoop

    ret


    ret


UpdateColumnBlinkState::
    ld a, [COLUMN_BLINK_GLOBAL_TIMER]
    inc a
    ld [COLUMN_BLINK_GLOBAL_TIMER], a
    cp COLUMN_BLINK_GLOBAL_PERIOD
    jr c, BeginColumnBlinkSlotScan

    xor a
    ld [COLUMN_BLINK_GLOBAL_TIMER], a

BeginColumnBlinkSlotScan:
    ld hl, COLUMN_BLINK_SLOT_FLAGS
    ld de, COLUMN_BLINK_SLOT_TIMERS
    ld b, COLUMN_BLINK_SLOT_COUNT

ColumnBlinkSlotLoop:
    ld a, [hl]
    and a
    jr z, AdvanceColumnBlinkSlot

    ld a, [de]
    and a
    jr nz, TickColumnBlinkSlotTimer

    ld a, [COLUMN_BLINK_GLOBAL_TIMER]
    and a
    jr z, ToggleColumnBlinkSlotFrame

    jr AdvanceColumnBlinkSlot

TickColumnBlinkSlotTimer:
    inc a
    ld [de], a
    cp COLUMN_BLINK_SLOT_PERIOD
    jr c, AdvanceColumnBlinkSlot

ToggleColumnBlinkSlotFrame:
    xor a
    ld [de], a
    ld a, [hl]
    cp COLUMN_BLINK_FRAME_1
    jr nz, SetColumnBlinkFrame1

    ld [hl], COLUMN_BLINK_FRAME_2
    jr DrawColumnBlinkSlot

SetColumnBlinkFrame1:
    ld [hl], COLUMN_BLINK_FRAME_1

DrawColumnBlinkSlot:
    push hl
    push bc
    push de
    ld a, [hl]
    call DrawColumnSprite
    pop de
    pop bc
    pop hl

AdvanceColumnBlinkSlot:
    inc hl
    inc de
    dec b
    jr nz, ColumnBlinkSlotLoop

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


MACRO GRID_PIECE_PATTERN_ROW
    db \1, \2, \3, \4
ENDM

GridPiecePatternTable::
GridPiecePatternEmptyPayload:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_BLANK_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_BLANK_TILE

GridPiecePatternPiece1:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_TOP_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_1_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_1_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_TOP_RIGHT_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_BOTTOM_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_1_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_1_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_BOTTOM_RIGHT_TILE

GridPiecePatternPiece2:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_TOP_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_2_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_2_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_TOP_RIGHT_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_BOTTOM_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_2_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_2_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_BOTTOM_RIGHT_TILE

GridPiecePatternPiece3:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_TOP_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_3_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_3_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_TOP_RIGHT_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_BOTTOM_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_3_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_3_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_BOTTOM_RIGHT_TILE

GridPiecePatternPiece4:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_TOP_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_4_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_4_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_TOP_RIGHT_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_BOTTOM_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_4_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_4_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_BOTTOM_RIGHT_TILE

GridPiecePatternPiece5:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_TOP_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_5_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_5_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_TOP_RIGHT_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_BOTTOM_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_5_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_5_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_BOTTOM_RIGHT_TILE

GridPiecePatternPiece6:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_TOP_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_6_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_6_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_TOP_RIGHT_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_FRAME_BOTTOM_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_6_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_PIECE_6_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_FRAME_BOTTOM_RIGHT_TILE

GridPiecePatternScanTrigger:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_SCAN_TRIGGER_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_SCAN_TRIGGER_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_BLANK_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_SCAN_TRIGGER_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_SCAN_TRIGGER_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_BLANK_TILE

GridPiecePatternScanTarget:
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_SCAN_TARGET_TOP_INNER_LEFT_TILE, GRID_PIECE_PATTERN_SCAN_TARGET_TOP_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_BLANK_TILE
    GRID_PIECE_PATTERN_ROW GRID_PIECE_PATTERN_BLANK_TILE, GRID_PIECE_PATTERN_SCAN_TARGET_BOTTOM_INNER_LEFT_TILE, GRID_PIECE_PATTERN_SCAN_TARGET_BOTTOM_INNER_RIGHT_TILE, GRID_PIECE_PATTERN_BLANK_TILE

MACRO COLUMN_SPRITE_PATTERN_ROW
    db \1, \2, \3, \4
ENDM

ColumnSpritePatternTable::
ColumnSpritePatternFrame2Block:
ColumnSpritePatternFrame2Column0:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
ColumnSpritePatternFrame2Column1:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN1_ROW1_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN1_ROW1_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN1_ROW2_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN1_ROW2_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
ColumnSpritePatternFrame2Column2:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN2_ROW0_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN2_ROW0_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN2_ROW1_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN2_ROW1_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN2_ROW2_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN2_ROW2_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
ColumnSpritePatternFrame2Column3:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW0_TILE0_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW0_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW0_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW0_TILE3_ENCODED
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW1_TILE0_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW1_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW1_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW1_TILE3_ENCODED
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW2_TILE0_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW2_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW2_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_FRAME2_COLUMN3_ROW2_TILE3_ENCODED

ColumnSpritePatternFrame1Block:
ColumnSpritePatternFrame1Column0:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN0_ROW1_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN0_ROW1_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN0_ROW2_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN0_ROW2_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
ColumnSpritePatternFrame1Column1:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN1_ROW1_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN1_ROW1_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN1_ROW2_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN1_ROW2_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
ColumnSpritePatternFrame1Column2:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN2_ROW0_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN2_ROW0_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN2_ROW1_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN2_ROW1_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN2_ROW2_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN2_ROW2_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_BLANK_ENCODED_TILE
ColumnSpritePatternFrame1Column3:
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW0_TILE0_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW0_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW0_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW0_TILE3_ENCODED
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW1_TILE0_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW1_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW1_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW1_TILE3_ENCODED
    COLUMN_SPRITE_PATTERN_ROW COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW2_TILE0_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW2_TILE1_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW2_TILE2_ENCODED, COLUMN_SPRITE_PATTERN_FRAME1_COLUMN3_ROW2_TILE3_ENCODED

UnreachedColumnSpritePatternTailRows:
    COLUMN_SPRITE_PATTERN_ROW UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW0_INNER_LEFT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW0_INNER_RIGHT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE
    COLUMN_SPRITE_PATTERN_ROW UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW1_INNER_LEFT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW1_INNER_RIGHT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE
    COLUMN_SPRITE_PATTERN_ROW UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW2_INNER_LEFT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW2_INNER_RIGHT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE
    COLUMN_SPRITE_PATTERN_ROW UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW3_INNER_LEFT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_ROW3_INNER_RIGHT_TILE, UNREACHED_COLUMN_SPRITE_TAIL_BLANK_TILE

InitGameState::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, InitTwoPlayerLevelSpeedSettings

    ld a, [OPTION_GAME_TYPE]
    ld [GAME_TYPE], a
    ld a, [TWO_PLAYER_FLAG]
    jr z, InitSinglePlayerLevelSpeedSettings

    ld a, GAME_TYPE_B
    ld [GAME_TYPE], a

InitSinglePlayerLevelSpeedSettings:
    ld a, [OPTION_LEVEL]
    ld [ACTIVE_LEVEL], a
    ld [PROGRESSION_LEVEL], a
    inc a
    ld [LEVEL_DISPLAY_ONES], a
    xor a
    ld [LEVEL_DISPLAY_TENS], a
    ld a, [OPTION_SPEED]
    ld [ACTIVE_SPEED], a
    ret


InitTwoPlayerLevelSpeedSettings:
    ld a, GAME_TYPE_B
    ld [GAME_TYPE], a
    ld a, [LINK_2P_SELECTED_LEVEL]
    ld [ACTIVE_LEVEL], a
    ld [PROGRESSION_LEVEL], a
    inc a
    ld [LEVEL_DISPLAY_ONES], a
    xor a
    ld [LEVEL_DISPLAY_TENS], a
    ld a, [LINK_2P_SELECTED_SPEED]
    ld [ACTIVE_SPEED], a
    ret


UpdateDropCursorAnimation::
    ld a, [DROP_CURSOR_ANIM_ACTIVE]
    and a
    ret z

    ld hl, DROP_CURSOR_FRAME_TIMER
    dec [hl]
    ret nz

    ld [hl], DROP_CURSOR_FRAME_PERIOD
    ld hl, SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_FRAME
    ld a, [hl]
    cp DROP_CURSOR_FRAME_ALT_START
    jr nc, AdvanceDropCursorAltFrame

    inc a
    jr StoreAdvancedDropCursorFrame

AdvanceDropCursorAltFrame:
    inc a
    cp DROP_CURSOR_FRAME_WRAP
    jr nz, StoreAdvancedDropCursorFrame

    xor a

StoreAdvancedDropCursorFrame:
    ld [hl], a
    jr z, StopDropCursorFrameAnimation

    cp DROP_CURSOR_FRAME_ALT_START
    jr z, StopDropCursorFrameAnimation

    ret


StopDropCursorFrameAnimation:
    xor a
    ld [DROP_CURSOR_ANIM_ACTIVE], a
    ret


InitDropCursorAnimationState::
    ld hl, DROP_CURSOR_ANIM_ACTIVE
    ld [hl], DROP_CURSOR_ANIM_INACTIVE
    inc hl
    ld [hl], DROP_CURSOR_FRAME_PERIOD
    ret


MACRO B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY
    db \1
ENDM

BTypeColumnTopRowSeedTable::
    B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_0
    B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_1
    B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_2
    B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_3
    B_TYPE_COLUMN_TOP_ROW_SEED_ENTRY B_TYPE_COLUMN_TOP_ROW_SEED_LEVEL_4

MACRO GAME_TURN_LEVEL_START_INDEX_ENTRY
    db \1
ENDM

GameTurnLevelStartIndexTable::
    GAME_TURN_LEVEL_START_INDEX_ENTRY GAME_TURN_LEVEL_0_START_INDEX
    GAME_TURN_LEVEL_START_INDEX_ENTRY GAME_TURN_LEVEL_1_START_INDEX
    GAME_TURN_LEVEL_START_INDEX_ENTRY GAME_TURN_LEVEL_2_START_INDEX
    GAME_TURN_LEVEL_START_INDEX_ENTRY GAME_TURN_LEVEL_3_START_INDEX
    GAME_TURN_LEVEL_START_INDEX_ENTRY GAME_TURN_LEVEL_4_START_INDEX

MACRO GAME_TURN_PARAM
    db \1, \2, \3, GAME_TURN_PARAM_UNREAD_TAIL_VALUE
ENDM

MACRO GAME_TURN_PARAM_SPLIT_HEAD
    db \1, \2, \3
ENDM

MACRO GAME_TURN_PARAM_SPLIT_TAIL
    db GAME_TURN_PARAM_UNREAD_TAIL_VALUE
ENDM

GameTurnParamTable::
    GAME_TURN_PARAM $04, $02, $28
    GAME_TURN_PARAM $04, $02, $24
    GAME_TURN_PARAM $04, $02, $20
    GAME_TURN_PARAM $04, $02, $1c
    GAME_TURN_PARAM $04, $02, $1a
    GAME_TURN_PARAM $04, $02, $18
    GAME_TURN_PARAM $04, $02, $16
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $12
    GAME_TURN_PARAM $04, $02, $10
    GAME_TURN_PARAM $04, $02, $1e
    GAME_TURN_PARAM $04, $02, $1c
    GAME_TURN_PARAM $04, $02, $1a
    GAME_TURN_PARAM $04, $02, $18
    GAME_TURN_PARAM $04, $02, $16
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $12
    GAME_TURN_PARAM $04, $02, $10
    GAME_TURN_PARAM $07, $02, $0e
    GAME_TURN_PARAM $01, $03, $0c
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $13
    GAME_TURN_PARAM $04, $02, $12
    GAME_TURN_PARAM $04, $02, $11
    GAME_TURN_PARAM $04, $02, $10
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $0e
    GAME_TURN_PARAM $04, $02, $0d
    GAME_TURN_PARAM $06, $02, $0c
    GAME_TURN_PARAM $02, $03, $0b
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $0e
    GAME_TURN_PARAM $04, $02, $0d
    GAME_TURN_PARAM $04, $02, $0c
    GAME_TURN_PARAM $04, $02, $0b
    GAME_TURN_PARAM $04, $02, $0a
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $05, $02, $07
    GAME_TURN_PARAM $03, $03, $06
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $0e
    GAME_TURN_PARAM $04, $02, $0d
    GAME_TURN_PARAM $04, $02, $0c
    GAME_TURN_PARAM_SPLIT_HEAD $04, $02, $0b

GameTurnParamTableContinuation::
    GAME_TURN_PARAM_SPLIT_TAIL
    GAME_TURN_PARAM $04, $02, $0a
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $04, $02, $07
    GAME_TURN_PARAM $04, $03, $06
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $0e
    GAME_TURN_PARAM $04, $02, $0d
    GAME_TURN_PARAM $04, $02, $0c
    GAME_TURN_PARAM $04, $02, $0b
    GAME_TURN_PARAM $04, $02, $0a
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $03, $02, $07
    GAME_TURN_PARAM $05, $03, $06
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $0e
    GAME_TURN_PARAM $04, $02, $0d
    GAME_TURN_PARAM $04, $02, $0c
    GAME_TURN_PARAM $04, $02, $0b
    GAME_TURN_PARAM $04, $02, $0a
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $02, $02, $07
    GAME_TURN_PARAM $06, $03, $06
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $0d
    GAME_TURN_PARAM $04, $02, $0c
    GAME_TURN_PARAM $04, $02, $0b
    GAME_TURN_PARAM $04, $02, $0a
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $04, $02, $07
    GAME_TURN_PARAM $01, $02, $06
    GAME_TURN_PARAM $07, $03, $06
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $0a
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $04, $02, $07
    GAME_TURN_PARAM $04, $02, $06
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $04, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $0a
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $04, $02, $07
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $03, $02, $03
    GAME_TURN_PARAM $05, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $09
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $04, $02, $07
    GAME_TURN_PARAM $04, $02, $06
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $02, $02, $03
    GAME_TURN_PARAM $06, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $08
    GAME_TURN_PARAM $04, $02, $07
    GAME_TURN_PARAM $04, $02, $06
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $04, $02, $03
    GAME_TURN_PARAM $01, $02, $02
    GAME_TURN_PARAM $07, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $07
    GAME_TURN_PARAM $04, $02, $06
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $04, $02, $03
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $06
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $04, $02, $03
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $03, $02, $02
    GAME_TURN_PARAM $05, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $02, $14
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $04, $02, $03
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $02, $02, $02
    GAME_TURN_PARAM $06, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $04
    GAME_TURN_PARAM $04, $02, $03
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $01, $02, $02
    GAME_TURN_PARAM $07, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $03
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $03, $03
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $03, $02, $02
    GAME_TURN_PARAM $05, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $03, $03
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $02, $02, $02
    GAME_TURN_PARAM $06, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $03, $03
    GAME_TURN_PARAM $04, $02, $0f
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $04, $02, $02
    GAME_TURN_PARAM $01, $02, $02
    GAME_TURN_PARAM $07, $03, $06
    GAME_TURN_PARAM $04, $03, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $03, $03
    GAME_TURN_PARAM $04, $02, $06
    GAME_TURN_PARAM $04, $02, $06
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $02, $05
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $03, $04
    GAME_TURN_PARAM $04, $03, $03
    GAME_TURN_PARAM $04, $03, $03
    GAME_TURN_PARAM $04, $03, $02
    GAME_TURN_PARAM $04, $03, $02

ProcessMatching::
    cp MATCHING_STATE_COUNT
    jr c, StoreMatchingStateAndLoadGraphics

    ld a, MATCHING_LAST_STATE

StoreMatchingStateAndLoadGraphics:
    ldh [STATE_TRANSITION], a
    xor a
    ld [LCD_REDRAW], a
    call LCDOff
    call ClearOAM
    ld hl, BG_MAP_VRAM_BASE
    ld bc, MATCHING_BG_VRAM_CLEAR_SIZE
    ld d, MATCHING_BG_CLEAR_TILE
    call FillBytesWithD
    ld a, ROM_BANK_GRAPHICS_1
    ld [MBC1_ROM_BANK_REG], a
    ld hl, Bank3MatchingTilesTo9000
    ld de, VRAM_TILE_BLOCK_9000
    ld bc, BANK3_MATCHING_TILE_BLOCK_COPY_SIZE
    call MemcopyCall
    ld hl, Bank3MatchingTilesTo8800
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK3_MATCHING_TILE_BLOCK_COPY_SIZE
    call MemcopyCall
    ld hl, Bank3MatchingTilesTo8000
    ld de, VRAM_TILE_BLOCK_8000
    ld bc, BANK3_MATCHING_TILE_BLOCK_COPY_SIZE
    call MemcopyCall
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call LCDOn
    ld a, MATCHING_LCDC_FLAGS
    ldh [rLCDC], a
    ld hl, MatchingOamTemplateMiddle
    ld de, SHADOW_OAM_ENTRY_2
    ld bc, MATCHING_MIDDLE_OAM_TEMPLATE_SIZE
    call Memcopy
    ldh a, [STATE_TRANSITION]
    ld hl, MatchingTileBaseIndexTable
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl]
    REPT MATCHING_MIDDLE_OAM_TILE_INDEX_SHIFT
        sla a
    ENDR
    add MATCHING_MIDDLE_OAM_TILE_BASE
    ld de, OAM_ENTRY_SIZE
    ld hl, SHADOW_OAM_ENTRY_2 + OAM_TILE_ID_OFFSET
    ld c, MATCHING_MIDDLE_OAM_ENTRY_COUNT

FillMatchingMiddleOamTileIdsLoop:
    ld [hl], a
    add hl, de
    inc a
    dec c
    jr nz, FillMatchingMiddleOamTileIdsLoop

    ld hl, BG_MAP_SHADOW
    ld bc, BG_MAP_SHADOW_SIZE
    ld d, MATCHING_BG_CLEAR_TILE
    call FillBytesWithD
    ld a, BG_MAP_SHADOW_COPY_ENABLED
    ld [BG_MAP_SHADOW_COPY_ENABLE_FLAG], a
    xor a
    ldh [ANIM_FRAME], a
    ld a, MATCHING_INTRO_SCROLL_START_X
    ldh [SCX_SHADOW], a
    ld a, MATCHING_INTRO_SCROLL_FRAMES

MatchingIntroScrollBlinkLoop:
    push af
    ldh a, [ANIM_FRAME]
    inc a
    cp MATCHING_INTRO_BLINK_PERIOD
    jr c, SelectMatchingIntroBlinkTile

    ld a, SND_MATCHING_INTRO_BLINK
    call PlaySound
    xor a

SelectMatchingIntroBlinkTile:
    ld b, MATCHING_INTRO_BLINK_TILE_1
    cp MATCHING_INTRO_BLINK_ALT_START_FRAME
    jr nc, DrawMatchingIntroBlinkBlock

    ld b, MATCHING_INTRO_BLINK_TILE_0

DrawMatchingIntroBlinkBlock:
    ldh [ANIM_FRAME], a
    ld a, b
    ld hl, MATCHING_INTRO_BLINK_TOP_LEFT
    ld bc, MATCHING_INTRO_BLINK_RECT_SIZE
    call FillRect
    ldh a, [ANIM_FRAME]
    bit 0, a
    jr z, WaitMatchingIntroScrollFrame

    call WaitVBlank

WaitMatchingIntroScrollFrame:
    call WaitVBlank
    ldh a, [SCX_SHADOW]
    inc a
    ldh [SCX_SHADOW], a
    pop af
    dec a
    jr nz, MatchingIntroScrollBlinkLoop

    ld hl, BG_MAP_SHADOW
    ld bc, BG_MAP_SHADOW_SIZE
    ld d, MATCHING_BG_CLEAR_TILE
    call FillBytesWithD
    ld c, MATCHING_POST_INTRO_WAIT_FRAMES
    call WaitVBlankFrames
    xor a
    ldh [ANIM_FRAME], a
    ld a, MATCHING_RESULT_SCROLL_START_X
    ldh [SCX_SHADOW], a

ResultPanelScrollBlinkLoop:
    push af
    ldh a, [ANIM_FRAME]
    inc a
    cp MATCHING_RESULT_BLINK_PERIOD
    jr c, SelectResultPanelBlinkTile

    ld a, SND_MATCHING_RESULT_PANEL_BLINK
    call PlaySound
    xor a

SelectResultPanelBlinkTile:
    ld b, MATCHING_RESULT_PANEL_BLINK_TILE_1
    cp MATCHING_RESULT_BLINK_ALT_START_FRAME
    jr nc, DrawResultPanelBlinkBlock

    ld b, MATCHING_RESULT_PANEL_BLINK_TILE_0

DrawResultPanelBlinkBlock:
    ldh [ANIM_FRAME], a
    ld a, b
    ld hl, RESULT_MAIN_PANEL_TOP_LEFT
    ld bc, RESULT_MAIN_PANEL_RECT_SIZE
    call FillRect
    call WaitVBlank
    ldh a, [SCX_SHADOW]
    dec a
    ldh [SCX_SHADOW], a
    pop af
    dec a
    jr nz, ResultPanelScrollBlinkLoop

    ld c, MATCHING_RESULT_PANEL_PRE_FILL_WAIT_FRAMES
    call WaitVBlankFrames
    ld a, MATCHING_RESULT_PANEL_STAGE_TILE_0
    ld hl, RESULT_MAIN_PANEL_TOP_LEFT
    ld bc, RESULT_MAIN_PANEL_RECT_SIZE
    call FillRect
    ld c, MATCHING_RESULT_PANEL_STEP_WAIT_FRAMES
    call WaitVBlankFrames
    ld a, MATCHING_RESULT_PANEL_STAGE_TILE_1
    ld hl, RESULT_MAIN_PANEL_TOP_LEFT
    ld bc, RESULT_MAIN_PANEL_WITH_EDGE_RECT_SIZE
    call FillRect
    ld c, MATCHING_RESULT_PANEL_STEP_WAIT_FRAMES
    call WaitVBlankFrames
    ld hl, MatchingOamTemplateTop
    ld de, SHADOW_OAM
    ld bc, MATCHING_PAIR_OAM_TEMPLATE_SIZE
    call Memcopy
    ld hl, MATCHING_ANIM_STRIP_TOP_LEFT
    ld a, MATCHING_ANIM_STRIP_INITIAL_TILE
    ld [hl+], a
    inc a
    ld [hl+], a
    ld [hl], a
    ld a, SND_MATCHING_OAM_SLIDE
    call PlaySound
    ld b, MATCHING_OAM_SLIDE_FRAMES
    ld de, OAM_ENTRY_SIZE

SlideMatchingTopOamRightLoop:
    ld c, MATCHING_OAM_X_STEP_RIGHT
    call ShiftMatchingOamPairX
    call WaitVBlank
    dec b
    jr nz, SlideMatchingTopOamRightLoop

    ld b, MATCHING_OAM_SLIDE_FRAMES
    ld de, OAM_ENTRY_SIZE

SlideMatchingOamTogetherLeftLoop:
    push bc
    ld c, MATCHING_MIDDLE_OAM_ENTRY_COUNT
    ld hl, SHADOW_OAM_ENTRY_2 + OAM_X_OFFSET

ShiftMatchingMiddleOamLeftLoop:
    ld a, [hl]
    sub MATCHING_OAM_X_STEP_RIGHT
    ld [hl], a
    add hl, de
    dec c
    jr nz, ShiftMatchingMiddleOamLeftLoop

    pop bc
    ld c, MATCHING_OAM_X_STEP_LEFT
    call ShiftMatchingOamPairX
    call WaitVBlank
    dec b
    jr nz, SlideMatchingOamTogetherLeftLoop

    ld hl, MATCHING_ANIM_STRIP_TOP_LEFT
    ld a, MATCHING_ANIM_STRIP_FINAL_TILE
    ld [hl+], a
    inc a
    ld [hl+], a
    ld [hl], MATCHING_ANIM_STRIP_FINAL_TAIL_TILE
    call ClearOAM
    ld c, MATCHING_RESULT_PANEL_STEP_WAIT_FRAMES
    call WaitVBlankFrames
    ld hl, RESULT_MAIN_PANEL_RIGHT_EDGE
    ld de, BG_MAP_ROW_STRIDE
    ld c, RESULT_MAIN_PANEL_EDGE_ROWS

FillResultMainPanelRightEdgeLoop:
    ld [hl], MATCHING_BG_CLEAR_TILE
    add hl, de
    dec c
    jr nz, FillResultMainPanelRightEdgeLoop

    ld a, MATCHING_RESULT_PANEL_STAGE_TILE_0
    ld hl, RESULT_MAIN_PANEL_TOP_LEFT
    ld bc, RESULT_MAIN_PANEL_RECT_SIZE
    call FillRect
    ld c, MATCHING_RESULT_PANEL_STEP_WAIT_FRAMES
    call WaitVBlankFrames
    ld a, MATCHING_RESULT_PANEL_BLINK_TILE_1
    ld hl, RESULT_MAIN_PANEL_TOP_LEFT
    ld bc, RESULT_MAIN_PANEL_RECT_SIZE
    call FillRect
    ld a, MATCHING_RESULT_HEADER_TILE
    ld hl, MATCHING_RESULT_HEADER_TOP_LEFT
    ld bc, MATCHING_RESULT_HEADER_RECT_SIZE
    call FillRect
    call DrawMatchingResultStats
    ld a, SND_CONFIRM
    call PlaySound
    ld hl, MatchingOamTemplateFinal
    ld de, SHADOW_OAM
    ld bc, MATCHING_PAIR_OAM_TEMPLATE_SIZE
    call Memcopy
    ld de, OAM_ENTRY_SIZE
    ld hl, MatchingTileBaseIndexTable
    ldh a, [STATE_TRANSITION]
    add l
    ld l, a
    jr nc, LoadMatchingFinalOamTileBase

    inc h

LoadMatchingFinalOamTileBase:
    ld a, [hl]
    REPT MATCHING_FINAL_OAM_TILE_INDEX_SHIFT
        sla a
    ENDR
    add MATCHING_FINAL_OAM_TILE_BASE
    ld hl, SHADOW_OAM_ENTRY_0 + OAM_TILE_ID_OFFSET
    ld [hl], a
    inc a
    add hl, de
    ld [hl], a
    ld c, MATCHING_FINAL_OAM_UP_FRAMES
    ld de, OAM_ENTRY_SIZE

MoveMatchingFinalOamUpLoop:
    call WaitVBlank
    ld hl, SHADOW_OAM
    ld a, [hl]
    dec a
    ld [hl], a
    add hl, de
    ld a, [hl]
    dec a
    ld [hl], a
    dec c
    jr nz, MoveMatchingFinalOamUpLoop

    ld c, MATCHING_SCORE_WAIT_FRAMES

ApplyMatchingScoreBonusAndWait::
    call WaitVBlankFrames
    call ClearOAM
    ld hl, MatchingScoreBonusTable
    ldh a, [STATE_TRANSITION]
    REPT MATCHING_SCORE_BONUS_RECORD_SHIFT
        sla a
    ENDR
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld l, [hl]
    ld h, a
    call AddScore
    call DrawMatchingResultStats

WaitMatchingScoreSoundEndLoop:
    ld a, [SOUND_CH_ACTIVE_ID]
    and a
    jr nz, WaitMatchingScoreSoundEndLoop

    call WaitAnyButtonPress
    ld a, MATCHING_SCORE_LCDC_FLAGS
    ldh [rLCDC], a
    jp ReloadGameTilesAndRequestRedraw


DrawMatchingResultStats::
    ld a, RESULT_SCORE_LABEL_TILE
    ld hl, RESULT_SCORE_LABEL_TOP_LEFT
    ld bc, RESULT_LABEL_RECT_SIZE
    call FillRect
    ld hl, RESULT_SCORE_VALUE_TOP_LEFT
    ld c, RESULT_SCORE_DIGIT_COUNT
    ld de, SCORE_DIGITS

DrawResultScoreDigitsLoop:
    ld a, [de]
    inc de
    and RESULT_DIGIT_MASK
    add RESULT_DIGIT_TILE_BASE
    ld [hl+], a
    dec c
    jr nz, DrawResultScoreDigitsLoop

    ld a, RESULT_LEVEL_LABEL_TILE
    ld hl, RESULT_LEVEL_LABEL_TOP_LEFT
    ld bc, RESULT_LABEL_RECT_SIZE
    call FillRect
    ld hl, RESULT_LEVEL_VALUE_ONES
    ld a, [LEVEL_DISPLAY_ONES]
    add RESULT_DIGIT_TILE_BASE
    ld [hl-], a
    ld a, [LEVEL_DISPLAY_TENS]
    add RESULT_DIGIT_TILE_BASE
    ld [hl], a
    ld hl, RESULT_SPEED_VALUE_TOP_LEFT
    ld a, [ACTIVE_SPEED]
    sla a
    add RESULT_SPEED_TILE_BASE
    ld [hl+], a
    inc a
    ld [hl], a
    ld a, RESULT_TIME_LABEL_TILE
    ld hl, RESULT_TIME_LABEL_TOP_LEFT
    ld bc, RESULT_TIME_LABEL_RECT_SIZE
    call FillRect
    ld hl, RESULT_TIME_VALUE_TOP_LEFT
    ld de, ROUND_TIMER_DIGITS
    ld a, [de]
    inc de
    and RESULT_DIGIT_MASK
    add RESULT_DIGIT_TILE_BASE
    ld [hl+], a
    ld a, [de]
    inc de
    and RESULT_DIGIT_MASK
    add RESULT_DIGIT_TILE_BASE
    ld [hl+], a
    ld a, RESULT_TIME_SEPARATOR_TILE
    ld [hl+], a
    ld a, [de]
    inc de
    and RESULT_DIGIT_MASK
    add RESULT_DIGIT_TILE_BASE
    ld [hl+], a
    ld a, [de]
    and RESULT_DIGIT_MASK
    add RESULT_DIGIT_TILE_BASE
    ld [hl+], a
    ret


MatchingOamTemplateTop::
    OAM_TEMPLATE_ENTRY MATCHING_TOP_OAM_Y, MATCHING_TOP_OAM_LEFT_X, MATCHING_TOP_OAM_LEFT_TILE, OAM_ATTR_NONE
    OAM_TEMPLATE_ENTRY MATCHING_TOP_OAM_Y, MATCHING_TOP_OAM_RIGHT_X, MATCHING_TOP_OAM_RIGHT_TILE, OAM_ATTR_NONE

MatchingOamTemplateMiddle::
    OAM_TEMPLATE_ENTRY MATCHING_MIDDLE_OAM_TOP_Y, MATCHING_MIDDLE_OAM_LEFT_X, MATCHING_MIDDLE_OAM_INITIAL_TILE_0, OAM_ATTR_NONE
    OAM_TEMPLATE_ENTRY MATCHING_MIDDLE_OAM_TOP_Y, MATCHING_MIDDLE_OAM_RIGHT_X, MATCHING_MIDDLE_OAM_INITIAL_TILE_1, OAM_ATTR_NONE
    OAM_TEMPLATE_ENTRY MATCHING_MIDDLE_OAM_BOTTOM_Y, MATCHING_MIDDLE_OAM_LEFT_X, MATCHING_MIDDLE_OAM_INITIAL_TILE_2, OAM_ATTR_NONE
    OAM_TEMPLATE_ENTRY MATCHING_MIDDLE_OAM_BOTTOM_Y, MATCHING_MIDDLE_OAM_RIGHT_X, MATCHING_MIDDLE_OAM_INITIAL_TILE_3, OAM_ATTR_NONE

MatchingOamTemplateFinal::
    OAM_TEMPLATE_ENTRY MATCHING_FINAL_OAM_Y, MATCHING_FINAL_OAM_LEFT_X, MATCHING_FINAL_OAM_INITIAL_TILE_0, OAM_ATTR_NONE
    OAM_TEMPLATE_ENTRY MATCHING_FINAL_OAM_Y, MATCHING_FINAL_OAM_RIGHT_X, MATCHING_FINAL_OAM_INITIAL_TILE_1, OAM_ATTR_NONE

MACRO SCORE_DELTA_ENTRY
    db HIGH(\1), LOW(\1)
ENDM

MatchingScoreBonusTable::
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_50
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_100
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_150
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_200
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_250
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_300
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_300
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_400
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_400
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_500
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_500
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_600
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_600
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_700
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_700
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_800
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_800
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_800
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_900
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_900
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_900
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_1000
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_1000
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_1000
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_1200
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_1200
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_1200
    SCORE_DELTA_ENTRY MATCHING_SCORE_BONUS_DELTA_1500

MACRO MATCHING_TILE_BASE_INDEX_ENTRY
    db \1
ENDM

MatchingTileBaseIndexTable::
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_0
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_1
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_2
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_3
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_4
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_5
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_6
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_7
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_8
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_9
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_10
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_11
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_12
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_13
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_14
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_15
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_16
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_17
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_18
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_19
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_20
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_21
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_22
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_23
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_24
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_25
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_26
    MATCHING_TILE_BASE_INDEX_ENTRY MATCHING_TILE_BASE_INDEX_STATE_27

UnusedDrawVerticalTilePairUnlessFF::
    cp UNUSED_VERTICAL_TILE_PAIR_SKIP_VALUE
    ret z

    push hl
    push de
    ld de, BG_MAP_ROW_STRIDE
    sla a
    add UNUSED_VERTICAL_TILE_PAIR_TILE_BASE
    ld [hl], a
    add hl, de
    inc a
    ld [hl], a
    pop de
    pop hl
    ret


ShiftMatchingOamPairX::
    ld hl, SHADOW_OAM_ENTRY_0 + OAM_X_OFFSET
    ld a, [hl]
    add c
    ld [hl], a
    add hl, de
    ld a, [hl]
    add c
    ld [hl], a
    ret


ReloadGameTilesAndRequestRedraw::
    call LCDOff
    call ClearOAM
    call LoadGameTiles
    call LCDOn
    ld a, LCD_REDRAW_EXPAND_REQUEST
    ld [LCD_REDRAW], a
    ret


WaitVBlankFrames::
    call WaitVBlank
    dec c
    jr nz, WaitVBlankFrames

    ret


FillBytesWithD::
    ld a, d
    ld [hl+], a
    dec bc
    ld a, b
    or c
    jr nz, FillBytesWithD

    ret


FillRect::
    ld de, BG_MAP_ROW_STRIDE

FillRectRowLoop:
    push bc
    push hl

FillRectColumnLoop:
    ld [hl+], a
    inc a
    dec c
    jr nz, FillRectColumnLoop

    pop hl
    add hl, de
    pop bc
    dec b
    jr nz, FillRectRowLoop

    ret


WaitAnyButtonPress::
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and PADF_ANY_BUTTON
    jr z, WaitAnyButtonPress

    ret


UpdateGameplayObjectsAndCheckBTypeClear::
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT
    xor a

UpdateGameplayObjectSlotsLoop:
    push af
    push bc
    call UpdateSpriteObject
    pop bc
    pop af
    inc a
    dec b
    jr nz, UpdateGameplayObjectSlotsLoop

    call CheckGameplayObjectSlotsActive
    and a
    jr nz, TickFallTimerForActiveGameplayObjects

    call QueueLinkFieldOccupancyCount
    call UpdatePieceDisplayByGameType
    ld a, [GAME_TYPE]
    and a
    ret z

    ld hl, COLUMN_TOP_ROWS
    ld b, COLUMN_COUNT

CheckBTypeColumnClearLoop:
    ld a, [hl+]
    cp BOARD_FALL_END_ROW
    ret nz

    dec b
    jr nz, CheckBTypeColumnClearLoop

    ld a, ROUND_RESULT_CODE_NONZERO
    ld [ROUND_TIMER_STOPPED], a
    ld [TOTAL_TIMER_STOPPED], a
    ld [RESULT_CLEAR_FLAG], a
    push af
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, ProcessBTypeClearRoundResult

    pop af
    call QueueRoundResult

    ; In the 2P clear path the saved AF is already popped above, so this pop
    ; discards RunGameplayFrame's return address and exits the gameplay tail.
ProcessBTypeClearRoundResult:
    pop af
    call ProcessRoundResultAndEnterRoundEnd
    ret


TickFallTimerForActiveGameplayObjects:
    call UpdatePieceFallTimer
    ret


UpdatePieceFallTimer::
    ld hl, PIECE_FALL_TIMER
    ld a, [hl]
    and a
    jr z, ReloadPieceFallTimer

    dec [hl]
    ret nz

    ld a, [DROP_CURSOR_ANIM_ACTIVE]
    ld b, a
    ld a, [DROP_ANIM_ACTIVE]
    or b
    ret z

    ld a, PIECE_FALL_TIMER_ANIM_HOLD_RELOAD
    ld [PIECE_FALL_TIMER], a
    ret


ReloadPieceFallTimer:
    ld a, [PIECE_FALL_DELAY]
    ld [PIECE_FALL_TIMER], a
    ret


UpdatePieceDisplayByGameType::
    ld a, [GAME_TYPE]
    and a
    jr nz, RunBTypePieceDisplayUpdate

    call UpdateGameTurnPieceDisplay
    ret


RunBTypePieceDisplayUpdate:
    call ClearPieceDisplayObjectSlots
    call UpdateFallAcceleration
    call BuildPieceDisplayObjects
    ld a, [PIECE_DISPLAY_COUNT]
    call BuildPieceDisplayStatesForCount
    ret


CheckGameplayObjectSlotsActive::
    ld hl, SPRITE_OBJECT_SLOT_1
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT

ScanGameplayObjectSlotsLoop:
    ld a, [hl]
    and a
    jr nz, ReturnGameplayObjectsActive

    swap l
    inc l
    swap l
    dec b
    jr nz, ScanGameplayObjectSlotsLoop

    xor a
    ret


ReturnGameplayObjectsActive:
    ld a, GAMEPLAY_OBJECTS_ACTIVE
    ret


UpdateFallAcceleration::
    ld hl, PIECE_FALL_ACCEL_TIMER
    dec [hl]
    ret nz

    ld a, [ACTIVE_LEVEL]
    cp PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD
    jr c, ReloadFallAccelTimerForLowLevel

    cp PIECE_FALL_ACCEL_LEVEL3_VALUE
    jr z, UnreachableReloadFallAccelTimerForLevel3

    jr ReloadFallAccelTimerForHighLevel

ReloadFallAccelTimerForLowLevel:
    ld a, PIECE_FALL_ACCEL_PERIOD
    jr StoreFallAccelTimerReload

UnreachableReloadFallAccelTimerForLevel3:
    ld a, PIECE_FALL_ACCEL_PERIOD
    jr StoreFallAccelTimerReload

ReloadFallAccelTimerForHighLevel:
    ld a, PIECE_FALL_ACCEL_PERIOD
    jr StoreFallAccelTimerReload

StoreFallAccelTimerReload:
    ld [hl], a
    ld hl, PIECE_FALL_DELAY
    ld a, [hl]
    cp PIECE_FALL_DELAY_MIN
    ret c

    ret z

    dec [hl]
    ret


HandlePlayfieldInput::
    ldh a, [JOYPAD_PRESSED]
    and PADF_RIGHT | PADF_LEFT
    jr z, CheckDropStartInput

    ld a, SND_CURSOR_MOVE
    call PlaySound

CheckDropStartInput:
    ldh a, [JOYPAD_PRESSED]
    and PADF_A | PADF_B
    jr z, HandleCursorMoveOrFastFall

    ld a, [DROP_ANIM_ACTIVE]
    and a
    jr nz, HandleCursorMoveOrFastFall

    ld a, [LINK_SEND_DROP_INPUT_LOCK]
    and a
    jr nz, HandleCursorMoveOrFastFall

    ld a, DROP_CURSOR_ANIM_ACTIVE_VALUE
    ld [DROP_CURSOR_ANIM_ACTIVE], a
    ld a, [SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_BASE_X]
    swap a
    srl a
    push af
    ld a, SND_DROP_START
    call PlaySound
    pop af
    call StartDropColumnSwapAnimation
    jr HandleCursorMoveOrFastFall

HandleCursorMoveOrFastFall:
    ld hl, SPRITE_OBJECT_SLOT_0 + SPRITE_OBJECT_BASE_X
    ldh a, [JOYPAD_HELD]
    bit PADB_DOWN, a
    jr nz, CheckFastFallActiveSlots

    ldh a, [JOYPAD_PRESSED]
    bit PADB_RIGHT, a
    jr nz, MovePlayerCursorRight

    bit PADB_LEFT, a
    jr nz, MovePlayerCursorLeft

    ret


MovePlayerCursorRight:
    ld a, [hl]
    add PLAYER_CURSOR_X_STEP
    cp PLAYER_CURSOR_REJECT_RIGHT_X
    ret z

    ld [hl], a
    ld hl, FIELD_COLUMN_TILE_PATTERN_INDEX
    inc [hl]
    ret


MovePlayerCursorLeft:
    ld a, [hl]
    sub PLAYER_CURSOR_X_STEP
    cp PLAYER_CURSOR_REJECT_LEFT_X
    ret z

    ld [hl], a
    ld hl, FIELD_COLUMN_TILE_PATTERN_INDEX
    dec [hl]
    ret


CheckFastFallActiveSlots:
    ld a, [SPRITE_OBJECT_SLOT_1 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, ClampFastFallTimers

    ld a, [SPRITE_OBJECT_SLOT_2 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, ClampFastFallTimers

    ld a, [SPRITE_OBJECT_SLOT_3 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, ClampFastFallTimers

    ld a, [SPRITE_OBJECT_SLOT_4 + SPRITE_OBJECT_PHASE]
    cp SPRITE_OBJECT_PHASE_UPDATE
    jr z, ClampFastFallTimers

    ret


ClampFastFallTimers:
    ld hl, PIECE_FALL_TIMER
    ld a, [hl]
    cp PIECE_FAST_FALL_TIMER_CLAMP
    jr c, ClampGameplayObjectFastFallTimers

    ld [hl], PIECE_FAST_FALL_TIMER_CLAMP

ClampGameplayObjectFastFallTimers:
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT
    ld hl, SPRITE_OBJECT_SLOT_1 + SPRITE_OBJECT_FAST_FALL_CLAMP_BYTE

ClampGameplayObjectFastFallLoop:
    ld a, [hl]
    cp PIECE_FAST_FALL_TIMER_CLAMP
    jr c, AdvanceFastFallClampSlot

    ld [hl], PIECE_FAST_FALL_TIMER_CLAMP

AdvanceFastFallClampSlot:
    ld a, l
    add SPRITE_OBJECT_SLOT_SIZE
    ld l, a
    dec b
    jr nz, ClampGameplayObjectFastFallLoop

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
    ld c, PIECE_DISPLAY_SHUFFLE_INDEX_MASK
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
    ld c, PIECE_DISPLAY_SHUFFLE_INDEX_MASK
    call MultiplyAndCount
    ld b, $00
    ld c, a
    ld hl, PIECE_DISPLAY_CODE_POOL
    add hl, bc
    ret


UpdateFallingPieceMotionAndLanding::
    ld a, [PIECE_FALL_TIMER]
    and a
    ld a, SPRITE_OBJECT_UPDATE_CONTINUE
    ret nz

    ld a, [PIECE_FALL_POS]
    cp BOARD_DRAW_FIRST_ROW
    jr nz, AdvanceFallingPiecePosition

    ld a, [SPRITE_OBJECT_STAGING_INDEX]
    call BuildGameOverPieceDisplayObjects

AdvanceFallingPiecePosition:
    call GetSelectedColumnTopRow
    ld b, a
    ld a, [PIECE_FALL_POS]
    inc a
    ld [PIECE_FALL_POS], a
    cp b
    jr nc, HandleFallingPieceReachedColumn

    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_BASE_Y]
    add PIECE_FALL_SPRITE_Y_STEP
    ld [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_BASE_Y], a
    ld a, SPRITE_OBJECT_UPDATE_CONTINUE
    ret


HandleFallingPieceReachedColumn:
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
    cp BOARD_SCAN_TRIGGER_PAYLOAD
    call z, RunBoardScanTriggerSequence
    call StagePiecePayloadInSelectedColumn
    cp b
    jr nz, DrawLandedPieceAndUpdateColumnTop

    ld a, [PIECE_FALL_POS]
    cp BOARD_FALL_END_ROW
    jr z, DrawLandedPieceAndUpdateColumnTop

    call HandleMatchedLandingScanState
    jr ClearLandedGameplayObject

DrawLandedPieceAndUpdateColumnTop:
    ld a, SND_PLACE_PIECE
    call PlaySound
    call GetSelectedColumnTopRow
    dec a
    ld h, a
    ld a, [FALLING_PIECE_GRID_COLUMN]
    sla a
    sla a
    ld l, a
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
    call DrawGridPiece
    call GetSelectedColumnTopRow
    REPT BOARD_CELL_STRIDE
        dec a
    ENDR
    ld [hl], a
    cp COLUMN_TOP_ROW_OVERFLOW_SENTINEL
    jr nz, ClearLandedGameplayObject

    ld a, RESULT_FLAG_SET
    ld [RESULT_GAME_OVER_FLAG], a
    xor a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, ProcessSinglePlayerGameOverResult

    ; Preserve the one-byte zero load while documenting ROUND_RESULT_CODE_ZERO.
    xor a
    call QueueRoundResult
    xor a
    ret


ProcessSinglePlayerGameOverResult:
    ; RESULT_RANK_NONE makes ProcessRoundResultAndEnterRoundEnd take the no-rank path.
    xor a
    call ProcessRoundResultAndEnterRoundEnd
    xor a
    ret


ClearLandedGameplayObject:
    jr ClearCurrentGameplaySpriteObjectRecord

UnreachedClearLandedGameplayObjectPop:
    pop hl

ClearCurrentGameplaySpriteObjectRecord::
    ld a, [SPRITE_OBJECT_STAGING_INDEX]
    inc a
    swap a
    ld l, a
    ld h, SPRITE_OBJECTS_HI
    ld b, SPRITE_OBJECT_STAGING_SIZE
    xor a

ClearGameplayObjectRecordLoop:
    ld [hl+], a
    dec b
    jr nz, ClearGameplayObjectRecordLoop

    ret


GetSelectedColumnTopRow::
    ld a, [FALLING_PIECE_GRID_COLUMN]
    ld hl, COLUMN_TOP_ROWS
    add l
    jr nc, ReadSelectedColumnTopRowEntry

    inc h

ReadSelectedColumnTopRowEntry:
    ld l, a
    ld a, [hl]
    ret


StagePiecePayloadInSelectedColumn::
    ld hl, PIECE_DISPLAY_REMAINING
    dec [hl]
    call GetSelectedColumnTopRow
    ld hl, BOARD_DATA
    call GetArrayElement
    ld a, [FALLING_PIECE_GRID_COLUMN]
    sla a
    sla a
    sla a
    sla a
    add l
    jr nc, StoreStagedPayloadInBoardColumn

    inc h

StoreStagedPayloadInBoardColumn:
    ld l, a
    ld b, [hl]
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
    REPT BOARD_ADJACENT_VISIBLE_CELL_DELTA
        dec hl
    ENDR
    ld [hl], a
    ret


ClearPieceSpriteObjectSlots::
    ld hl, SPRITE_OBJECT_SLOT_1
    ld b, PIECE_SPRITE_OBJECT_CLEAR_BYTES
    xor a

ClearPieceSpriteObjectSlotsLoop:
    ld [hl+], a
    dec b
    jr nz, ClearPieceSpriteObjectSlotsLoop

    ret


GetArrayElement::
    add l
    jr nc, ReadArrayElementAtOffset

    inc h

ReadArrayElementAtOffset:
    ld l, a
    ld a, [hl]
    ret


InitATypeGameTurnPieceDisplay::
    call InitGameTurnPieceDisplay
    ret


InitBTypeFallTimingAndBoardSeed::
    ld hl, PIECE_FALL_DELAY
    ld a, [ACTIVE_SPEED]
    and a
    jr z, LoadUnhalvedBTypeFallDelay

    call GetLevelFallDelay
    srl a
    ld [PIECE_FALL_DELAY], a
    jr InitBTypeBoardSeed

LoadUnhalvedBTypeFallDelay:
    call GetLevelFallDelay
    ld [PIECE_FALL_DELAY], a

InitBTypeBoardSeed:
    ld a, B_TYPE_INITIAL_PIECE_DISPLAY_COUNT
    ld [PIECE_DISPLAY_COUNT], a
    ld a, [ACTIVE_LEVEL]
    ld hl, BTypeColumnTopRowSeedTable
    call GetArrayElement
    ld [COLUMN_TOP_ROW_SEED], a
    ld a, SCORE_UNUSED_TILE_BASE_INITIAL
    ld [SCORE_UNUSED_TILE_BASE_SOURCE], a
    ld hl, PIECE_FALL_ACCEL_TIMER
    ld a, [ACTIVE_LEVEL]
    cp PIECE_FALL_ACCEL_LEVEL3_VALUE
    jr z, InitFallAccelTimerForLevel3

    cp PIECE_FALL_ACCEL_HIGH_LEVEL_THRESHOLD
    jr nc, InitFallAccelTimerForHighLevel

    ld a, PIECE_FALL_ACCEL_PERIOD
    jr StoreInitialFallAccelTimer

InitFallAccelTimerForLevel3:
    ld a, PIECE_FALL_ACCEL_PERIOD
    jr StoreInitialFallAccelTimer

InitFallAccelTimerForHighLevel:
    ld a, PIECE_FALL_ACCEL_PERIOD

StoreInitialFallAccelTimer:
    ld [hl], a
    ret


ClearBoardData::
    ld b, BOARD_DATA_SIZE
    ld hl, BOARD_DATA

ClearBoardDataLoop:
    xor a
    ld [hl+], a
    dec b
    jr nz, ClearBoardDataLoop

    ret


SeedColumnTopRows::
    ld b, COLUMN_COUNT
    ld hl, COLUMN_TOP_ROWS
    ld a, [COLUMN_TOP_ROW_SEED]

SeedColumnTopRowsLoop:
    ld [hl+], a
    dec b
    jr nz, SeedColumnTopRowsLoop

    ret


InitPieceDisplaySlotOrder::
    ld hl, PIECE_DISPLAY_SLOT_ORDER
    ld [hl], PIECE_DISPLAY_SLOT_INDEX_0
    inc hl
    ld [hl], PIECE_DISPLAY_SLOT_INDEX_1
    inc hl
    ld [hl], PIECE_DISPLAY_SLOT_INDEX_2
    inc hl
    ld [hl], PIECE_DISPLAY_SLOT_INDEX_3
    ret


InitPieceDisplayCodePool::
    ld hl, PIECE_DISPLAY_CODE_POOL
    ld b, PIECE_DISPLAY_CODE_POOL_SIZE
    ld a, PIECE_DISPLAY_CODE_FIRST

InitPieceDisplayCodePoolLoop:
    ld [hl+], a
    inc a
    dec b
    jr nz, InitPieceDisplayCodePoolLoop

    ret


FillInitialBoardWithVBlankWait::
    ld a, INITIAL_BOARD_FILL_VBLANK_WAIT_FRAMES
    ldh [VBLANK_BUSY], a
    call FillInitialBoardColumns

WaitInitialBoardFillVBlankLoop:
    ldh a, [VBLANK_BUSY]
    and a
    jr nz, WaitInitialBoardFillVBlankLoop

    ret


FillInitialBoardColumns::
    ld a, [COLUMN_TOP_ROW_SEED]
    cp BOARD_FALL_END_ROW
    ret z

    sub BOARD_FALL_END_ROW
    cpl
    inc a
    ld b, a
    srl b
    ld c, COLUMN_COUNT
    ld hl, BOARD_COLUMN_BOTTOM_VISIBLE_CELL
    ld de, BOARD_COLUMN_STRIDE

FillInitialBoardColumnLoop:
    push bc
    push hl

FillInitialBoardCellLoop:
    push bc
    push de
    push hl
    call ShufflePieceDisplayCodePool
    call ShufflePieceDisplayCodePool
    call ShufflePieceDisplayCodePool
    ld a, [PIECE_DISPLAY_CODE_POOL + INITIAL_BOARD_PIECE_POOL_OFFSET]
    pop hl
    pop de
    pop bc
    call AvoidInitialBoardAdjacentDuplicate
    ld [hl-], a
    dec hl
    dec b
    jr nz, FillInitialBoardCellLoop

    pop hl
    pop bc
    add hl, de
    dec c
    jr nz, FillInitialBoardColumnLoop

    ret


AvoidInitialBoardAdjacentDuplicate::
    push bc
    REPT BOARD_ADJACENT_VISIBLE_CELL_DELTA
        inc hl
    ENDR
    ld b, [hl]
    cp b
    jr nz, ReturnInitialBoardPieceCandidate

    inc a
    cp INITIAL_BOARD_PIECE_WRAP_SENTINEL
    jr nz, ReturnIncrementedInitialBoardPiece

    ld a, INITIAL_BOARD_PIECE_WRAP_CODE

ReturnInitialBoardPieceCandidate:
    REPT BOARD_ADJACENT_VISIBLE_CELL_DELTA
        dec hl
    ENDR
    pop bc
    ret


ReturnIncrementedInitialBoardPiece:
    jr ReturnInitialBoardPieceCandidate

ClearRoundLandingAndResultState::
    xor a
    ld [RESULT_FLOW_ACTIVE], a
    ld [UNRESOLVED_LANDING_RESET_BYTE_0], a
    ld [UNRESOLVED_LANDING_RESET_BYTE_1], a
    ld [PIECE_DISPLAY_FORCE_ALL_STATES_FLAG], a
    ld [UNRESOLVED_LANDING_SCAN_COUNTER], a
    ld a, UNRESOLVED_LANDING_RESET_TIMER_INITIAL
    ld [UNRESOLVED_LANDING_RESET_TIMER], a
    ret


InitPlayfieldBoardAndPieceState::
    call ClearPieceSpriteObjectSlots
    call ClearBoardData
    call SeedColumnTopRows
    call InitPieceDisplaySlotOrder
    call InitPieceDisplayCodePool
    call ClearRoundLandingAndResultState
    ld a, [GAME_TYPE]
    and a
    jr nz, InitBTypePlayfieldBoardAndDisplay

    call InitATypeGameTurnPieceDisplay
    ld a, BOARD_FALL_END_ROW
    ld [COLUMN_TOP_ROW_SEED], a
    call SeedColumnTopRows
    jr SetPlayfieldCursorSlotType

InitBTypePlayfieldBoardAndDisplay:
    call InitBTypeFallTimingAndBoardSeed
    call SeedColumnTopRows
    call FillInitialBoardWithVBlankWait
    ld a, [PIECE_DISPLAY_COUNT]
    call BuildPieceDisplayStatesForCount
    call BuildPieceDisplayObjects
    ld a, [PIECE_DISPLAY_COUNT]
    call BuildPieceDisplayStatesForCount

SetPlayfieldCursorSlotType:
    ld hl, SPRITE_OBJECT_SLOT_0
    ld [hl], SPRITE_OBJECT_TYPE_PLAYER_CURSOR
    ret


GetLevelFallDelay::
    ld hl, LevelFallDelayTable
    ld a, [PROGRESSION_LEVEL]
    cp LEVEL_FALL_DELAY_TABLE_COUNT
    jr c, ReadLevelFallDelayTable

    ld a, LEVEL_FALL_DELAY_MAX_INDEX

ReadLevelFallDelayTable:
    call GetArrayElement
    ret


MACRO LEVEL_FALL_DELAY_ENTRY
    db \1
ENDM

LevelFallDelayTable::
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_0
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_1
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_2
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_3
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_4
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_5
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_6
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_7
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_8
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_9
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_10
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_11
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_12
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_13
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_14
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_15
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_16
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_17
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_18
    LEVEL_FALL_DELAY_ENTRY LEVEL_FALL_DELAY_INDEX_19

HandleMatchedLandingScanState::
    ld a, [SPRITE_OBJECT_STAGING + SPRITE_OBJECT_TILE_ID]
    cp BOARD_SCAN_TARGET_PAYLOAD
    jr nz, CommitFallingPieceToBoard

    ld a, [UNRESOLVED_LANDING_SCAN_COUNTER]
    REPT BOARD_CELL_STRIDE
        dec a
    ENDR
    ld [UNRESOLVED_LANDING_SCAN_COUNTER], a
    and a
    jr nz, CommitFallingPieceToBoard

    ld [UNRESOLVED_LANDING_RESET_BYTE_0], a
    ld [UNRESOLVED_LANDING_RESET_BYTE_1], a

CommitFallingPieceToBoard::
    ld a, SND_COMMIT_PIECE
    call PlaySound
    ld hl, SCORE_DELTA_COMMIT_PIECE
    call AddScore
    call GetSelectedColumnTopRow
    cp COLUMN_TOP_ROW_COMMIT_LIMIT
    ret z

    REPT BOARD_CELL_STRIDE
        inc a
    ENDR
    ld [hl], a
    ld a, [PIECE_FALL_POS]
    ld h, a
    ld a, [FALLING_PIECE_GRID_COLUMN]
    sla a
    sla a
    ld l, a
    xor a
    inc h
    call DrawGridPiece
    ld b, FIELD_COLUMN_EFFECT_FRAME_COMMIT
    call SpawnFieldColumnEffect
    ret


SpawnFieldColumnEffect::
    ld a, [FALLING_PIECE_GRID_COLUMN]
    add FIELD_COLUMN_EFFECT_SLOT_BASE
    swap a
    ld e, a
    ld d, SPRITE_OBJECTS_HI
    ld a, SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT
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
    ld a, [FALLING_PIECE_GRID_COLUMN]
    sla a
    sla a
    sla a
    sla a
    sla a
    ld [de], a
    ld a, [FALLING_PIECE_GRID_COLUMN]
    ld hl, FIELD_COLUMN_TIMERS
    call GetArrayElement
    ld [hl], FIELD_COLUMN_TIMER_RELOAD
    ret


RunBoardScanTriggerSequence::
    call FindBoardScanTargetRow
    and a
    jp z, FinishBoardScanNoTargetLanding

    push af
    call GetSelectedColumnTopRow
    pop af
    ld [hl], a
    push af
    call ClearCurrentGameplaySpriteObjectRecord
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
    or LINK_FIELD_EVENT_FLAG
    ld [LINK_FIELD_EVENT_PAYLOAD], a
    pop hl
    pop bc
    inc b
    ld a, b
    cp BOARD_SCAN_SINGLE_STEP_DISTANCE
    jr nz, StoreBoardScanDistanceRewardIndex

    xor a
    ld [BOARD_SCAN_REWARD_INDEX], a
    jr DrawBoardScanAnimation

StoreBoardScanDistanceRewardIndex:
    ld hl, BOARD_SCAN_REWARD_INDEX
    ld [hl], b

DrawBoardScanAnimation:
    ld a, [PIECE_FALL_POS]
    ld h, a
    ld a, [FALLING_PIECE_GRID_COLUMN]
    sla a
    sla a
    ld l, a
    ld c, BOARD_SCAN_STEP_INITIAL

BoardScanAnimationStepLoop:
    push bc
    push hl
    xor a
    REPT BOARD_CELL_STRIDE
        dec h
    ENDR
    call DrawGridPiece
    pop hl
    pop bc
    ld a, h
    cp BOARD_SCAN_BG_REFRESH_ROW
    jr nz, DrawBoardScanTriggerPayload

    push bc
    push de
    push hl
    call DrawGameplayBgTopRowIfNoResultFlow
    pop hl
    pop de
    pop bc

DrawBoardScanTriggerPayload:
    push bc
    push hl
    ld a, BOARD_SCAN_TRIGGER_PAYLOAD
    dec h
    call DrawGridPiece
    pop hl
    pop bc
    ld a, SND_BOARD_SCAN_STEP_BASE
    sub c
    call PlaySound
    inc h
    ld a, c
    cp BOARD_SCAN_STEP_MAX
    jr z, SendBoardScanStepFrames

    inc c

SendBoardScanStepFrames:
    push bc
    ld b, BOARD_SCAN_SEND_FRAMES
    call Send2PData
    pop bc
    dec b
    jr nz, BoardScanAnimationStepLoop

    push hl
    REPT BOARD_CELL_STRIDE
        dec h
    ENDR
    xor a
    push hl
    call DrawGridPiece
    pop hl
    REPT BOARD_CELL_STRIDE
        inc h
    ENDR
    xor a
    push hl
    call DrawGridPiece
    pop hl
    call GetSelectedColumnTopRow
    REPT BOARD_CELL_STRIDE
        inc a
    ENDR
    ld [hl], a
    call DecrementPieceDisplayRemaining
    pop hl
    call RunBoardScanRoundTransition
    pop bc
    ld a, [UNRESOLVED_LANDING_SCAN_COUNTER]
    dec a
    ld [UNRESOLVED_LANDING_SCAN_COUNTER], a
    xor a
    ret


FindBoardScanTargetRow::
    ld a, [PIECE_FALL_POS]
    cp BOARD_FALL_END_ROW
    jr z, ReturnNoBoardScanTarget

    ld h, a
    ld a, [FALLING_PIECE_GRID_COLUMN]
    ld l, a

FindBoardScanTargetRowLoop:
    call ReadBoardCellAtColumnRow
    cp BOARD_SCAN_TARGET_PAYLOAD
    jr z, ReturnBoardScanTargetRow

    REPT BOARD_ADJACENT_VISIBLE_CELL_DELTA
        inc h
    ENDR
    ld a, h
    cp BOARD_FALL_END_ROW
    jr nz, FindBoardScanTargetRowLoop

ReturnNoBoardScanTarget:
    xor a
    ret


ReturnBoardScanTargetRow:
    ld a, h
    ret


ReadBoardCellAtColumnRow::
    ld de, BOARD_DATA
    ld a, l
    sla a
    sla a
    sla a
    sla a
    add e
    jr nc, StoreBoardColumnBaseLow

    inc d

StoreBoardColumnBaseLow:
    ld e, a
    ld a, h
    add e
    jr nc, ReadBoardCellAtComputedAddress

    inc d

ReadBoardCellAtComputedAddress:
    ld e, a
    ld a, [de]
    ret


RunBoardScanRoundTransition::
    push af
    push bc
    push de
    push hl
    call DrawGameplayBgTopRowIfNoResultFlow
    pop hl
    pop de
    pop bc
    pop af
    ldh a, [SCREEN_STATE]
    ld [BOARD_SCAN_REWARD_INDEX], a
    inc h
    inc h
    ld b, h
    ldh a, [SCREEN_STATE]
    ld hl, BoardScanTransitionFrameLimitTable
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
    ld a, [FALLING_PIECE_GRID_COLUMN]
    sla a
    sla a
    sla a
    sla a
    sla a
    add ROUND_TRANSITION_BASE_X_OFFSET
    ld [hl], a
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION
    inc l
    inc l
    ld [hl], ROUND_TRANSITION_PRE_FRAME_0
    ld b, ROUND_TRANSITION_PRE_FRAME_SEND_FRAMES
    call Send2PData
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION

SendRoundTransitionPreFrame1:
    inc l
    inc l
    ld [hl], ROUND_TRANSITION_PRE_FRAME_1
    ld b, ROUND_TRANSITION_PRE_FRAME_SEND_FRAMES
    call Send2PData
    ld hl, SPRITE_OBJECT_SLOT_10
    ld de, SPRITE_OBJECT_SLOT_SIZE
    xor a
    ld b, a

InitRoundCompleteTileSlotsLoop:
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
    ld a, ROUND_COMPLETE_TILE_SLOT_COUNT
    cp b
    jr nz, InitRoundCompleteTileSlotsLoop

    ld a, FIELD_ANIM_ACTIVE_VALUE
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
    ld [hl], ROUND_TRANSITION_FRAME_START
    ld b, ROUND_TRANSITION_INITIAL_SEND_FRAMES
    call Send2PData
    ld a, ROUND_TRANSITION_FRAME_START
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_TRANSITION
    inc hl
    inc hl

SendRoundTransitionFrameLoop:
    ld [hl], a
    ld b, ROUND_TRANSITION_FRAME_SEND_FRAMES
    call Send2PData
    inc a
    push hl
    ld hl, SCREEN_STATE
    ld b, [hl]
    pop hl
    inc b
    cp b
    jr nz, SendRoundTransitionFrameLoop

    ld b, ROUND_TRANSITION_POST_FRAME_SEND_FRAMES
    call Send2PData
    ld a, [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME]
    xor ROUND_TRANSITION_FRAME_TOGGLE_MASK
    ld [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME], a
    ld a, [SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME]
    cp ROUND_TRANSITION_MAJOR_REVEAL_FRAME
    jr nz, PlayRoundTransitionDefaultSound

    ld a, SND_ROUND_COMPLETE_MAJOR_REVEAL
    call PlaySound
    jr ApplyBoardScanRewardScoreAndEggCount

PlayRoundTransitionDefaultSound:
    ld a, SND_ROUND_COMPLETE_REVEAL
    call PlaySound

ApplyBoardScanRewardScoreAndEggCount:
    ld b, ROUND_TRANSITION_REWARD_SEND_FRAMES
    call Send2PData
    ld a, [LINK_FIELD_EVENT_PAYLOAD]
    ld [LINK_SEND_QUEUE_0], a
    ld a, [BOARD_SCAN_REWARD_INDEX]
    sla a
    ld hl, BoardScanRewardScoreDeltaTable
    call GetArrayElement
    ld d, a
    inc hl
    ld a, [hl]
    ld l, a
    ld h, d
    call AddScore
    call Draw1PCountdownDigitTileSlots
    call IncrementEggCountAndRefreshDisplay
    ld hl, SPRITE_OBJECT_SLOT_9
    ld [hl], SPRITE_OBJECT_TYPE_NONE
    ret


Send2PData::
    push af
    push bc
    push de
    push hl
    ld a, [ROUND_RESULT_PENDING]
    and a
    jr nz, AbortSend2PDataFrames

    call CheckPause2P
    call WaitVBlank
    ld a, [GAME_STATE]
    cp GAME_STATE_PLAYING
    jr nz, AbortSend2PDataFrames

    call ReadJoypad
    call HandlePause
    ld a, LINK_SEND_DROP_INPUT_LOCK_ACTIVE
    ld [LINK_SEND_DROP_INPUT_LOCK], a
    call HandlePlayfieldInput
    call DrawFieldColumnTilePattern
    xor a
    ld [LINK_SEND_DROP_INPUT_LOCK], a
    call UpdateFieldAnimationSlots
    call UpdateFieldTimers
    pop hl
    pop de
    pop bc
    pop af
    dec b
    jr nz, Send2PData

    ret


AbortSend2PDataFrames:
    pop hl
    pop de
    pop bc
    pop af
    pop af
    pop af
    ret


DecrementPieceDisplayRemaining::
    ld hl, PIECE_DISPLAY_REMAINING
    dec [hl]
    ret


FinishBoardScanNoTargetLanding::
    ld b, FIELD_COLUMN_EFFECT_FRAME_LAND
    call SpawnFieldColumnEffect
    call ClearCurrentGameplaySpriteObjectRecord
    ld a, SND_PIECE_LAND
    call PlaySound
    pop af
    xor a
    ret


MACRO BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY
    db \1
ENDM

BoardScanTransitionFrameLimitTable::
    BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY BOARD_SCAN_TRANSITION_FRAME_LIMIT_1
    BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY BOARD_SCAN_TRANSITION_FRAME_LIMIT_2
    BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY BOARD_SCAN_TRANSITION_FRAME_LIMIT_2
    BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY BOARD_SCAN_TRANSITION_FRAME_LIMIT_2
    BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY BOARD_SCAN_TRANSITION_FRAME_LIMIT_3
    BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY BOARD_SCAN_TRANSITION_FRAME_LIMIT_3
    BOARD_SCAN_TRANSITION_FRAME_LIMIT_ENTRY BOARD_SCAN_TRANSITION_FRAME_LIMIT_4

BoardScanRewardScoreDeltaTable::
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_50
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_100
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_100
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_100
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_200
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_200
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_500
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_500
    SCORE_DELTA_ENTRY BOARD_SCAN_REWARD_SCORE_DELTA_500

BuildPieceDisplayObjects::
    call BuildPieceDisplayObjectsFromStates
    ret


BuildPieceDisplayStatesForCount::
    ldh [SCREEN_STATE], a
    call SelectEffectivePieceDisplayCount
    cp PIECE_DISPLAY_SKIP_SPECIAL_MIN_COUNT
    jr c, InitPieceDisplayStateBuild

    ld hl, PIECE_DISPLAY_SKIP_SPECIAL_SELECTION_FLAG
    ld [hl], PIECE_DISPLAY_SKIP_SPECIAL_ACTIVE

InitPieceDisplayStateBuild:
    ld b, PIECE_DISPLAY_STATE_COUNT
    ld hl, PIECE_DISPLAY_STATES

ClearPieceDisplayStatesLoop:
    ld [hl], PIECE_DISPLAY_STATE_EMPTY
    inc hl
    dec b
    jr nz, ClearPieceDisplayStatesLoop

    ld b, a

BuildPieceDisplayStatesLoop:
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
    call SelectPieceDisplayCode
    pop hl
    pop bc
    ld [hl], a
    dec b
    jr nz, BuildPieceDisplayStatesLoop

    push bc
    push hl
    call ApplyFirstForcedPieceDisplayState
    pop hl
    pop bc
    call ApplyAllForcedPieceDisplayStates
    ld hl, PIECE_DISPLAY_FORCE_ALL_STATES_FLAG
    ld [hl], PIECE_DISPLAY_FORCE_FLAG_INACTIVE
    ret


ApplyFirstForcedPieceDisplayState::
    ld a, [PIECE_DISPLAY_FORCE_FIRST_STATE_FLAG]
    and a
    ret z

    xor a
    ld [PIECE_DISPLAY_FORCE_FIRST_STATE_FLAG], a
    ld hl, PIECE_DISPLAY_STATES
    ld b, PIECE_DISPLAY_STATE_COUNT

FindFirstForcedPieceDisplayStateLoop:
    ld a, [hl]
    and a
    jr nz, StoreFirstForcedPieceDisplayState

    inc hl
    dec b
    jr nz, FindFirstForcedPieceDisplayStateLoop

    nop

StoreFirstForcedPieceDisplayState:
    ld a, PIECE_DISPLAY_FORCED_STATE
    ld [hl], a
    ret


BuildPieceDisplayObjectsFromStates::
    ld hl, PIECE_DISPLAY_STATES
    xor a
    ld d, a
    ld b, a
    ld c, PIECE_DISPLAY_STATE_COUNT

BuildPieceDisplayObjectSlotsLoop:
    ld a, [hl]
    and a
    call nz, InitPieceDisplayObjectFromState
    inc d
    dec c
    inc hl
    jr nz, BuildPieceDisplayObjectSlotsLoop

    ret


InitPieceDisplayObjectFromState::
    push bc
    push de
    push hl
    ld b, a
    ld a, d
    call InitActivePieceDisplayObject
    pop hl
    pop de
    pop bc
    ret


InitActivePieceDisplayObject::
    push af
    inc a
    swap a
    ld l, a
    ld h, SPRITE_OBJECTS_HI
    ld [hl], SPRITE_OBJECT_TYPE_PIECE_DISPLAY
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
    ld [hl], PIECE_DISPLAY_OBJECT_INITIAL_DELAY
    inc hl
    ld [hl], SPRITE_OBJECT_PHASE_WAIT
    inc hl
    ld [hl], b
    ret


BuildGameOverPieceDisplayObjects::
    ld b, PIECE_DISPLAY_STATE_COUNT
    ld hl, PIECE_DISPLAY_STATES + PIECE_DISPLAY_STATE_COUNT - 1

BuildGameOverPieceDisplayObjectSlotsLoop:
    ld a, [hl]
    and a
    jr z, AdvanceGameOverPieceDisplaySlot

    ld c, a
    push hl
    ld h, SPRITE_OBJECTS_HI
    ld a, b
    add GAME_OVER_PIECE_DISPLAY_SLOT_OFFSET
    swap a
    ld l, a
    ld [hl], SPRITE_OBJECT_TYPE_PIECE_DISPLAY
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

AdvanceGameOverPieceDisplaySlot:
    dec hl
    dec b
    jr nz, BuildGameOverPieceDisplayObjectSlotsLoop

    ret


ClearPieceDisplayObjectSlots::
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT
    ld hl, SPRITE_OBJECT_SLOT_5
    ld de, PIECE_DISPLAY_OBJECT_CLEAR_SLOT_ADVANCE
    xor a

ClearPieceDisplayObjectSlotsLoop:
    ld [hl+], a
    inc hl
    ld [hl], a
    add hl, de
    dec b
    jr nz, ClearPieceDisplayObjectSlotsLoop

    ret


LoadGameTurnPieceDisplayStep::
    call ClearPieceDisplayObjectSlots
    call BuildPieceDisplayObjects
    ld hl, GAME_TURN_TABLE_INDEX
    ld a, [hl]
    ld l, a
    ld h, $00
    REPT GAME_TURN_PARAM_RECORD_SHIFT
        add hl, hl
    ENDR
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
    jr z, StoreGameTurnPieceDelay

    srl b
    jr StoreGameTurnPieceDelay

UnreachedGameTurnDelayClamp:
    ld b, PIECE_FALL_DELAY_MIN

StoreGameTurnPieceDelay:
    ld a, b
    ld [GAME_TURN_DELAY], a
    dec hl
    ld a, [hl]
    push af
    call BuildPieceDisplayStatesForCount
    pop af
    ld [PIECE_DISPLAY_REMAINING], a
    ld [PIECE_DISPLAY_COUNT], a
    ret


UpdateGameTurnPieceDisplay::
    ld hl, GAME_TURN_STEP_TIMER
    dec [hl]
    jr z, AdvanceGameTurnTableIndex

    call ClearPieceDisplayObjectSlots
    ld a, [GAME_TURN_DELAY]
    ld [PIECE_FALL_DELAY], a
    ld [PIECE_FALL_TIMER], a
    call BuildPieceDisplayObjects
    ld a, [PIECE_DISPLAY_COUNT]
    call BuildPieceDisplayStatesForCount
    ret


AdvanceGameTurnTableIndex:
    ld hl, GAME_TURN_TABLE_INDEX
    ld a, [hl]
    cp GAME_TURN_TABLE_INDEX_SENTINEL
    jr z, ContinueAdvancedGameTurn

    cp GAME_TURN_TABLE_LOOP_END_INDEX
    jr nz, IncrementGameTurnTableIndex

    ld a, GAME_TURN_TABLE_LOOP_RESTART_INDEX
    ld [hl], a
    jr ContinueAdvancedGameTurn

IncrementGameTurnTableIndex:
    inc [hl]

ContinueAdvancedGameTurn:
    push af
    call TickTitleLevelDisplayDigits
    pop af
    ld a, [hl]
    jr LoadGameTurnPieceDisplayStep

InitGameTurnPieceDisplay::
    xor a
    ld [GAME_TURN_STEP_TIMER], a
    ld a, [ACTIVE_LEVEL]
    ld hl, GameTurnLevelStartIndexTable
    call GetArrayElement
    ld [GAME_TURN_TABLE_INDEX], a
    ld hl, GameTurnParamTable
    REPT GAME_TURN_PARAM_RECORD_SHIFT
        sla a
    ENDR
    call GetArrayElement
    inc hl
    ld a, [hl+]
    push hl
    call BuildPieceDisplayStatesForCount
    pop hl
    ld a, [hl]
    ld b, a
    ld a, [ACTIVE_SPEED]
    and a
    jr z, StoreInitialGameTurnPieceDelay

    srl b
    jr StoreInitialGameTurnPieceDelay

UnreachedInitialGameTurnDelayClamp:
    ld b, PIECE_FALL_DELAY_MIN

StoreInitialGameTurnPieceDelay:
    ld a, b
    ld [GAME_TURN_DELAY], a
    ld [PIECE_FALL_TIMER], a
    ld [PIECE_FALL_DELAY], a
    jp LoadGameTurnPieceDisplayStep


SelectPieceDisplayCode::
    ld a, [PIECE_DISPLAY_SKIP_SPECIAL_SELECTION_FLAG]
    and a
    jr z, CheckBTypeTimedSpecialPieceDisplayCode

    xor a
    ld [PIECE_DISPLAY_SKIP_SPECIAL_SELECTION_FLAG], a
    jr UseDefaultPieceDisplayCode

CheckBTypeTimedSpecialPieceDisplayCode:
    ld a, [GAME_TYPE]
    and a
    jr z, UseDefaultPieceDisplayCode

    ld a, [ROUND_TIMER_DIGITS]
    and a
    jr nz, UseBTypeTimedSpecialPieceDisplayCode

    ld a, [ROUND_TIMER_DIGITS + 1]
    cp PIECE_DISPLAY_TIMED_SPECIAL_SECOND_DIGIT_MIN
    jr c, UseDefaultPieceDisplayCode

UseBTypeTimedSpecialPieceDisplayCode:
    call CountFieldOccupancyIntoUiScratch
    ldh a, [UI_SCRATCH]
    cp PIECE_DISPLAY_TIMED_SPECIAL_OCCUPANCY_LIMIT
    jr nc, UseDefaultPieceDisplayCode

    call AddNonForcedPieceDisplayObjectsToUiScratch
    ldh a, [UI_SCRATCH]
    srl a
    jr c, UseFirstForcedPieceDisplayCode

    call Multiply
    cp PIECE_DISPLAY_TIMED_RANDOM_CODE1_THRESHOLD
    jr c, ReturnPieceDisplayCode1

    cp PIECE_DISPLAY_TIMED_RANDOM_CODE4_THRESHOLD
    jr c, ReturnPieceDisplayCode4

    cp PIECE_DISPLAY_TIMED_RANDOM_CODE2_THRESHOLD
    jr c, ReturnPieceDisplayCode2

    cp PIECE_DISPLAY_TIMED_RANDOM_CODE3_THRESHOLD
    jr c, ReturnPieceDisplayCode3

    ld a, PIECE_DISPLAY_FORCE_FLAG_ACTIVE
    ld [PIECE_DISPLAY_FORCE_ALL_STATES_FLAG], a
    jr ReturnPieceDisplayForcedState

UseFirstForcedPieceDisplayCode:
    ld a, PIECE_DISPLAY_FORCE_FLAG_ACTIVE
    ld [PIECE_DISPLAY_FORCE_FIRST_STATE_FLAG], a
    call Multiply
    cp PIECE_DISPLAY_FIRST_FORCED_RANDOM_CODE1_THRESHOLD
    jr c, ReturnPieceDisplayCode1

    cp PIECE_DISPLAY_FIRST_FORCED_RANDOM_CODE4_THRESHOLD
    jr c, ReturnPieceDisplayCode4

    cp PIECE_DISPLAY_FIRST_FORCED_RANDOM_CODE2_THRESHOLD
    jr c, ReturnPieceDisplayCode2

    jr ReturnPieceDisplayCode3

UseDefaultPieceDisplayCode:
    call Multiply
    cp PIECE_DISPLAY_DEFAULT_RANDOM_CODE1_THRESHOLD
    jr c, ReturnPieceDisplayCode1

    cp PIECE_DISPLAY_DEFAULT_RANDOM_CODE4_THRESHOLD
    jr c, ReturnPieceDisplayCode4

    cp PIECE_DISPLAY_DEFAULT_RANDOM_CODE2_THRESHOLD
    jr c, ReturnPieceDisplayCode2

    cp PIECE_DISPLAY_DEFAULT_RANDOM_CODE3_THRESHOLD
    jr c, ReturnPieceDisplayCode3

    cp PIECE_DISPLAY_DEFAULT_RANDOM_FORCED_STATE_THRESHOLD
    jr c, ReturnPieceDisplayForcedState

    jr ReturnPieceDisplayCode8

ReturnPieceDisplayCode1:
    ld a, PIECE_DISPLAY_CODE_1
    ret


ReturnPieceDisplayCode4:
    ld a, PIECE_DISPLAY_CODE_4
    ret


ReturnPieceDisplayCode2:
    ld a, PIECE_DISPLAY_CODE_2
    ret


ReturnPieceDisplayCode3:
    ld a, PIECE_DISPLAY_CODE_3
    ret


ReturnPieceDisplayForcedState:
    ld a, PIECE_DISPLAY_FORCED_STATE
    ret


ReturnPieceDisplayCode8:
    ld a, PIECE_DISPLAY_CODE_8
    ret


CountFieldOccupancyIntoUiScratch::
    push bc
    xor a
    ldh [UI_SCRATCH], a
    ld hl, FIELD_OCCUPANCY_SCAN_TOP_LEFT
    ld de, FIELD_OCCUPANCY_SCAN_NEXT_ROW_DELTA
    ld c, FIELD_OCCUPANCY_SCAN_ROWS

FieldOccupancyScanRowLoop:
    ld b, FIELD_OCCUPANCY_SCAN_COLUMNS

FieldOccupancyScanColumnLoop:
    ld a, [hl+]
    inc hl
    inc hl
    inc hl
    cp FIELD_OCCUPANCY_EMPTY_TILE
    jr z, AdvanceFieldOccupancyScanCell

    ldh a, [UI_SCRATCH]
    inc a
    ldh [UI_SCRATCH], a

AdvanceFieldOccupancyScanCell:
    dec b
    jr nz, FieldOccupancyScanColumnLoop

    add hl, de
    dec c
    jr nz, FieldOccupancyScanRowLoop

    pop bc
    ret


AddNonForcedPieceDisplayObjectsToUiScratch::
    push bc
    push hl
    ld hl, SPRITE_OBJECT_SLOT_1
    ld b, SPRITE_OBJECT_ACTIVE_SLOT_COUNT

ScanPieceDisplayObjectsForUiScratchLoop:
    ld a, [hl]
    and a
    call nz, AddPieceDisplayObjectToUiScratch
    ld de, SPRITE_OBJECT_SLOT_SIZE
    add hl, de
    dec b
    jr nz, ScanPieceDisplayObjectsForUiScratchLoop

    pop hl
    pop bc
    ret


AddPieceDisplayObjectToUiScratch::
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
    cp PIECE_DISPLAY_FORCED_STATE
    jr z, AccumulatePieceDisplayUiScratchCount

    inc c

AccumulatePieceDisplayUiScratchCount:
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    dec hl
    ld a, [UI_SCRATCH]
    add c
    ld [UI_SCRATCH], a
    ret


ApplyAllForcedPieceDisplayStates::
    ld a, [PIECE_DISPLAY_FORCE_ALL_STATES_FLAG]
    and a
    ret z

    ld hl, PIECE_DISPLAY_STATES
    ld b, PIECE_DISPLAY_STATE_COUNT

ApplyAllForcedPieceDisplayStatesLoop:
    ld a, [hl]
    and a
    jr z, AdvanceAllForcedPieceDisplayState

    ld [hl], PIECE_DISPLAY_FORCED_STATE

AdvanceAllForcedPieceDisplayState:
    inc hl
    dec b
    jr nz, ApplyAllForcedPieceDisplayStatesLoop

    ret


TickTitleLevelDisplayDigits::
    ld hl, LEVEL_DISPLAY_TICK_COUNTER
    inc [hl]
    ld a, [hl]
    cp LEVEL_DISPLAY_TICK_PERIOD
    ret nz

    xor a
    ld [hl], a
    call AdvanceATypeLevelDisplayDigits
    ld hl, TITLE_LEVEL_PREVIEW_DIGITS_COORD
    call DrawLevelDisplayDigits
    ret


SelectEffectivePieceDisplayCount::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, SelectTwoPlayerPieceDisplayCount

    ld a, [SCREEN_STATE]
    ret


SelectTwoPlayerPieceDisplayCount:
    ld a, [LINK_PENDING_FIELD_RISE]
    and a
    jr nz, ConsumePendingFieldRiseForDisplayCount

    ld a, [SCREEN_STATE]
    ret


ConsumePendingFieldRiseForDisplayCount:
    ld c, a
    ld a, LINK_FIELD_RISE_SCREEN_STATE_LIMIT
    ld hl, SCREEN_STATE
    ld b, [hl]
    sub b
    ret z

    ld b, a
    ld a, [LINK_PENDING_FIELD_RISE]
    cp b
    jr c, ApplyPartialPendingFieldRise

    sub b
    ld [LINK_PENDING_FIELD_RISE], a
    ld a, LINK_FIELD_RISE_SCREEN_STATE_LIMIT
    jr PlayPendingFieldRiseSound

ApplyPartialPendingFieldRise:
    ld hl, SCREEN_STATE
    ld b, [hl]
    add b
    ld hl, LINK_PENDING_FIELD_RISE
    ld [hl], LINK_PENDING_FIELD_RISE_NONE

PlayPendingFieldRiseSound:
    push af
    ld a, SND_LINK_FIELD_RISE
    call PlaySound
    pop af
    ret


UpdatePieceDisplayBlink::
    ld hl, PIECE_DISPLAY_BLINK_TIMER
    dec [hl]
    ret nz

    ld [hl], PIECE_DISPLAY_BLINK_PERIOD
    ld hl, SPRITE_OBJECT_SLOT_1
    ld de, SPRITE_OBJECT_SLOT_SIZE
    ld b, PIECE_DISPLAY_BLINK_SLOT_COUNT

ScanPieceDisplayBlinkSlotsLoop:
    ld a, [hl]
    cp SPRITE_OBJECT_TYPE_PIECE_DISPLAY
    jr nz, AdvancePieceDisplayBlinkSlot

    call TogglePieceDisplayFrame

AdvancePieceDisplayBlinkSlot:
    add hl, de
    dec b
    jr nz, ScanPieceDisplayBlinkSlotsLoop

    ret


TogglePieceDisplayFrame::
    inc hl
    inc hl
    ld a, [hl]
    cp PIECE_DISPLAY_FORCED_STATE
    jr z, ReturnFromTogglePieceDisplayFrame

    cp PIECE_DISPLAY_BLINK_EXEMPT_STATE
    jr z, ReturnFromTogglePieceDisplayFrame

    xor PIECE_DISPLAY_BLINK_FRAME_TOGGLE_MASK
    ld [hl], a

ReturnFromTogglePieceDisplayFrame:
    dec hl
    dec hl
    ret


ResetPieceDisplayBlinkTimer::
    ld hl, PIECE_DISPLAY_BLINK_TIMER
    ld [hl], PIECE_DISPLAY_BLINK_PERIOD
    ret


InitTextSystem::
    call FillGameTilemap
    call DrawOptionBoxLayout
    call DrawOptionTextLabels
    ret


DrawOptionBoxLayout::
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionAGameBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionBGameBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionLevelPanelBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionLevelLabelBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionSpeedPanelBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionSpeedLabelBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionBgmPanelBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionBgmLabelBox

DrawOptionLevelValueBoxes::
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionLevel0ValueBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionLevel1ValueBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionLevel2ValueBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionLevel3ValueBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionLevel4ValueBox
    ret


DrawOptionTextLabels::
    ld hl, OPTION_TEXT_A_GAME_COORD
    ld de, OptionTextAGame
    call DrawStringToGrid
    ld hl, OPTION_TEXT_B_GAME_COORD
    ld de, OptionTextBGame
    call DrawStringToGrid
    ld hl, OPTION_TEXT_LEVEL_COORD
    ld de, OptionTextLevel
    call DrawStringToGrid
    ld hl, OPTION_TEXT_SPEED_COORD
    ld de, OptionTextSpeed
    call DrawStringToGrid
    ld hl, OPTION_TEXT_BGM_COORD
    ld de, OptionTextBgm
    call DrawStringToGrid
    ld hl, OPTION_TEXT_LOW_COORD
    ld de, OptionTextLow
    call DrawStringToGrid
    ld hl, OPTION_TEXT_HIGH_COORD
    ld de, OptionTextHigh
    call DrawStringToGrid
    ld hl, OPTION_TEXT_OFF_COORD
    ld de, OptionTextOff
    call DrawStringToGrid
    ld hl, OPTION_DECORATION_START_COORD
    ld a, OPTION_DECORATION_FIRST_TILE
    ld b, OPTION_DECORATION_COUNT

DrawOptionDecorationTilesLoop:
    push hl
    push af
    call CalcTilemapAddress
    pop af
    ld [hl], a
    pop hl
    REPT OPTION_DECORATION_COLUMN_STEP
        inc l
    ENDR
    inc a
    dec b
    jr nz, DrawOptionDecorationTilesLoop

    ret


DrawOptionBoxAtCoord::
    call CalcTilemapAddress
    ld a, d
    ldh [STATE_TRANSITION], a
    push hl
    ld d, OPTION_BOX_TOP_LEFT_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl+], a
    ld d, OPTION_BOX_HORIZONTAL_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    call FillOptionBoxHorizontalRun
    ld d, OPTION_BOX_TOP_RIGHT_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl], a
    pop hl
    ld de, BG_MAP_ROW_STRIDE
    add hl, de

DrawBoxSideRowsLoop:
    push hl
    ld d, OPTION_BOX_SIDE_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl+], a
    ld e, c
    ld d, OPTION_BOX_INNER_WIDTH_HIGH
    add hl, de
    ld d, OPTION_BOX_SIDE_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl], a
    pop hl
    ld de, BG_MAP_ROW_STRIDE
    add hl, de
    dec b
    jr nz, DrawBoxSideRowsLoop

    ld d, OPTION_BOX_BOTTOM_LEFT_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl+], a
    ld d, OPTION_BOX_HORIZONTAL_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    call FillOptionBoxHorizontalRun
    ld d, OPTION_BOX_BOTTOM_RIGHT_TILE_BASE
    ldh a, [STATE_TRANSITION]
    add d
    ld [hl], a
    ret


FillOptionBoxHorizontalRun::
    ld d, c

FillTileRunLoop:
    ld [hl+], a
    dec d
    jr nz, FillTileRunLoop

    ret


DrawOptionAGameBox::
    ld hl, OPTION_BOX_A_GAME_COORD
    ld bc, OPTION_BOX_GAME_TYPE_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionBGameBox::
    ld hl, OPTION_BOX_B_GAME_COORD
    ld bc, OPTION_BOX_GAME_TYPE_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionLevelPanelBox::
    ld hl, OPTION_BOX_LEVEL_PANEL_COORD
    ld bc, OPTION_BOX_LEVEL_PANEL_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionLevelLabelBox::
    ld hl, OPTION_BOX_LEVEL_LABEL_COORD
    ld bc, OPTION_BOX_LABEL_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionLevel0ValueBox::
    ld hl, OPTION_BOX_LEVEL0_VALUE_COORD
    ld bc, OPTION_BOX_LEVEL_VALUE_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionLevel1ValueBox::
    ld hl, OPTION_BOX_LEVEL1_VALUE_COORD
    ld bc, OPTION_BOX_LEVEL_VALUE_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionLevel2ValueBox::
    ld hl, OPTION_BOX_LEVEL2_VALUE_COORD
    ld bc, OPTION_BOX_LEVEL_VALUE_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionLevel3ValueBox::
    ld hl, OPTION_BOX_LEVEL3_VALUE_COORD
    ld bc, OPTION_BOX_LEVEL_VALUE_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionLevel4ValueBox::
    ld hl, OPTION_BOX_LEVEL4_VALUE_COORD
    ld bc, OPTION_BOX_LEVEL_VALUE_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionSpeedPanelBox::
    ld hl, OPTION_BOX_SPEED_PANEL_COORD
    ld bc, OPTION_BOX_WIDE_PANEL_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionSpeedLabelBox::
    ld hl, OPTION_BOX_SPEED_LABEL_COORD
    ld bc, OPTION_BOX_LABEL_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionBgmPanelBox::
    ld hl, OPTION_BOX_BGM_PANEL_COORD
    ld bc, OPTION_BOX_WIDE_PANEL_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


DrawOptionBgmLabelBox::
    ld hl, OPTION_BOX_BGM_LABEL_COORD
    ld bc, OPTION_BOX_BGM_LABEL_INNER_SIZE
    call DrawOptionBoxAtCoord
    ret


MACRO OPTION_TEXT_ROW_3
    db \1, \2, \3, DRAW_STRING_ROW_END
ENDM

MACRO OPTION_TEXT_ROW_4
    db \1, \2, \3, \4, DRAW_STRING_ROW_END
ENDM

MACRO OPTION_TEXT_ROW_5
    db \1, \2, \3, \4, \5, DRAW_STRING_ROW_END
ENDM

MACRO OPTION_TEXT_ROW_6
    db \1, \2, \3, \4, \5, \6, DRAW_STRING_ROW_END
ENDM

OptionTextAGame::
    OPTION_TEXT_ROW_6 OPTION_TEXT_TILE_A, OPTION_TEXT_TILE_SPACE, OPTION_TEXT_TILE_G, OPTION_TEXT_TILE_A, OPTION_TEXT_TILE_M, OPTION_TEXT_TILE_E
OptionTextBGame::
    OPTION_TEXT_ROW_6 OPTION_TEXT_TILE_B, OPTION_TEXT_TILE_SPACE, OPTION_TEXT_TILE_G, OPTION_TEXT_TILE_A, OPTION_TEXT_TILE_M, OPTION_TEXT_TILE_E
OptionTextLevel::
    OPTION_TEXT_ROW_5 OPTION_TEXT_TILE_L, OPTION_TEXT_TILE_E, OPTION_TEXT_TILE_V, OPTION_TEXT_TILE_E, OPTION_TEXT_TILE_L
OptionTextSpeed::
    OPTION_TEXT_ROW_5 OPTION_TEXT_TILE_S, OPTION_TEXT_TILE_P, OPTION_TEXT_TILE_E, OPTION_TEXT_TILE_E, OPTION_TEXT_TILE_D
OptionTextBgm::
    OPTION_TEXT_ROW_3 OPTION_TEXT_TILE_B, OPTION_TEXT_TILE_G, OPTION_TEXT_TILE_M
OptionTextLow::
    OPTION_TEXT_ROW_3 OPTION_TEXT_TILE_L, OPTION_TEXT_TILE_O, OPTION_TEXT_TILE_W
OptionTextHigh::
    OPTION_TEXT_ROW_4 OPTION_TEXT_TILE_H, OPTION_TEXT_TILE_I, OPTION_TEXT_TILE_G, OPTION_TEXT_TILE_H
OptionTextOff::
    OPTION_TEXT_ROW_3 OPTION_TEXT_TILE_O, OPTION_TEXT_TILE_F, OPTION_TEXT_TILE_F

MACRO OPTION_MARKER_POSITION
    db HIGH(\1), LOW(\1)
ENDM

OptionMarkerPositions::
    OPTION_MARKER_POSITION OPTION_MARKER_A_GAME_COORD
    OPTION_MARKER_POSITION OPTION_MARKER_B_GAME_COORD
    OPTION_MARKER_POSITION OPTION_MARKER_SPEED_LOW_COORD
    OPTION_MARKER_POSITION OPTION_MARKER_SPEED_HIGH_COORD
    OPTION_MARKER_POSITION OPTION_MARKER_BGM_0_COORD
    OPTION_MARKER_POSITION OPTION_MARKER_BGM_1_COORD
    OPTION_MARKER_POSITION OPTION_MARKER_BGM_2_COORD
    OPTION_MARKER_POSITION OPTION_MARKER_BGM_OFF_COORD

DrawOptionMarkers::
    ld b, OPTION_MARKER_COUNT
    ld hl, OptionMarkerPositions

ClearOptionMarkerPositionsLoop:
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    ld e, a
    push hl
    ld h, d
    ld l, e
    call CalcTilemapAddress
    ld [hl], OPTION_MARKER_BLANK_TILE
    pop hl
    dec b
    jr nz, ClearOptionMarkerPositionsLoop

    ld a, [OPTION_GAME_TYPE]
    and a
    jr nz, DrawSelectedBGameMarker

    ld hl, OPTION_MARKER_A_GAME_COORD
    call DrawOptionMarker
    jr DrawSelectedSpeedMarker

DrawSelectedBGameMarker:
    ld hl, OPTION_MARKER_B_GAME_COORD
    call DrawOptionMarker

DrawSelectedSpeedMarker:
    ld a, [OPTION_SPEED]
    and a
    jr nz, DrawSelectedHighSpeedMarker

    ld hl, OPTION_MARKER_SPEED_LOW_COORD
    call DrawOptionMarker
    jr DrawSelectedBgmMarker

DrawSelectedHighSpeedMarker:
    ld hl, OPTION_MARKER_SPEED_HIGH_COORD
    call DrawOptionMarker

DrawSelectedBgmMarker:
    ld a, [OPTION_BGM]
    and a
    jr nz, CheckBgmOption1Marker

    ld hl, OPTION_MARKER_BGM_0_COORD
    call DrawOptionMarker
    ret


CheckBgmOption1Marker:
    cp OPTION_BGM_VALUE_1
    jr nz, CheckBgmOption2Marker

    ld hl, OPTION_MARKER_BGM_1_COORD
    call DrawOptionMarker
    ret


CheckBgmOption2Marker:
    cp OPTION_BGM_VALUE_2
    jr nz, DrawSelectedBgmOffMarker

    ld hl, OPTION_MARKER_BGM_2_COORD
    call DrawOptionMarker
    ret


DrawSelectedBgmOffMarker:
    ld hl, OPTION_MARKER_BGM_OFF_COORD
    call DrawOptionMarker
    ret


DrawOptionMarker::
    call CalcTilemapAddress
    ld [hl], OPTION_MARKER_SELECTED_TILE
    ret


DrawTileTripletList::
    ld a, [de]
    cp DRAW_TILE_TRIPLET_LIST_END
    ret z

    ld h, a
    inc de
    ld a, [de]
    ld l, a
    inc de
    call CalcTilemapAddress
    ld a, [de]
    inc de
    ld [hl], a
    jr DrawTileTripletList

MACRO DRAW_TILE_TRIPLET
    db \1, \2, \3
ENDM

OptionCursorInactiveTileTriplets::
    DRAW_TILE_TRIPLET OPTION_CURSOR_LEVEL_ROW, OPTION_CURSOR_LEFT_COL, OPTION_CURSOR_INACTIVE_LEFT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_LEVEL_ROW, OPTION_CURSOR_RIGHT_COL, OPTION_CURSOR_INACTIVE_RIGHT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_SPEED_ROW, OPTION_CURSOR_LEFT_COL, OPTION_CURSOR_INACTIVE_LEFT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_SPEED_ROW, OPTION_CURSOR_RIGHT_COL, OPTION_CURSOR_INACTIVE_RIGHT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_BGM_ROW, OPTION_CURSOR_LEFT_COL, OPTION_CURSOR_INACTIVE_LEFT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_BGM_ROW, OPTION_CURSOR_BGM_RIGHT_COL, OPTION_CURSOR_INACTIVE_RIGHT_TILE
    db DRAW_TILE_TRIPLET_LIST_END

ApplySettings::
    ld hl, SettingsCursorSpriteInit0
    ld de, SPRITE_OBJECT_SLOT_9
    ld bc, SETTINGS_CURSOR_INIT_COPY_SIZE
    call MemcopyCall
    ld hl, SettingsCursorSpriteInit1
    ld de, SPRITE_OBJECT_SLOT_10
    ld bc, SETTINGS_CURSOR_INIT_COPY_SIZE
    call MemcopyCall
    ld hl, SettingsCursorSpriteInit2
    ld de, SPRITE_OBJECT_SLOT_11
    ld bc, SETTINGS_CURSOR_INIT_COPY_SIZE
    call MemcopyCall
    ret


MACRO SETTINGS_CURSOR_INIT_RECORD
    db SPRITE_OBJECT_TYPE_SETTINGS_CURSOR, SETTINGS_CURSOR_INIT_UNUSED_BYTE
    db \1, \1
    db SETTINGS_CURSOR_BASE_Y, SETTINGS_CURSOR_INIT_GRID_COLUMN, \2
ENDM

SettingsCursorSpriteInit0::
    SETTINGS_CURSOR_INIT_RECORD SETTINGS_CURSOR_FRAME_0, SETTINGS_CURSOR_BASE_X_0
SettingsCursorSpriteInit1::
    SETTINGS_CURSOR_INIT_RECORD SETTINGS_CURSOR_FRAME_1, SETTINGS_CURSOR_BASE_X_1
SettingsCursorSpriteInit2::
    SETTINGS_CURSOR_INIT_RECORD SETTINGS_CURSOR_FRAME_2, SETTINGS_CURSOR_BASE_X_2

ResetSettings::
    ld a, BGM_PREVIEW_RESET_VALUE
    ld [BGM_PREVIEW_TIMER], a
    ld [BGM_PREVIEW_UNUSED_PERIOD], a
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
    jr z, ReadDetachedLocalPreplayJoypad

    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, SendDetachedMasterPreplayJoypad

WaitDetachedPreplaySerialDoneLoop:
    ldh a, [SERIAL_DONE]
    and a
    jr z, WaitDetachedPreplaySerialDoneLoop

    xor a
    ldh [SERIAL_DONE], a
    ld a, [LINK_RECV]
    jr HandleDetachedPreplayInputByte

SendDetachedMasterPreplayJoypad:
    ldh a, [JOYPAD_PRESSED]
    ld [LINK_SEND], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a

ReadDetachedLocalPreplayJoypad:
    ldh a, [JOYPAD_PRESSED]

HandleDetachedPreplayInputByte:
    and a
    ret z

    bit PADB_START, a
    jr z, HandleDetachedPreplayNonStartInput

    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, EnterDetachedPreplayPlaySetup

    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr nz, EnterDetachedPreplayPlaySetup

    call WaitVBlank
    xor a
    ld [LINK_SEND], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a

EnterDetachedPreplayPlaySetup:
    call InitGameState
    ld a, GAME_STATE_PLAY_SETUP
    ldh [GAME_STATE], a
    ret


HandleDetachedPreplayNonStartInput:
    bit PADB_DOWN, a
    jr nz, MoveDetachedPreplayCursorDown

    bit PADB_UP, a
    jr nz, MoveDetachedPreplayCursorUp

    bit PADB_RIGHT, a
    jr nz, IncrementDetachedPreplaySelectedOption

    bit PADB_LEFT, a
    jr nz, DecrementDetachedPreplaySelectedOption

    ret


MoveDetachedPreplayCursorDown:
    ld a, [MENU_CURSOR]
    inc a
    cp MENU_CURSOR_ROW_COUNT
    jr nz, StoreDetachedPreplayCursorDown

    xor a

StoreDetachedPreplayCursorDown:
    ld [MENU_CURSOR], a
    call UpdateCursorDisplay
    ret


MoveDetachedPreplayCursorUp:
    ld a, [MENU_CURSOR]
    dec a
    cp MENU_CURSOR_UNDERFLOW_SENTINEL
    jr nz, StoreDetachedPreplayCursorUp

    ld a, MENU_CURSOR_ROW_BGM

StoreDetachedPreplayCursorUp:
    ld [MENU_CURSOR], a
    call UpdateCursorDisplay
    ret


IncrementDetachedPreplaySelectedOption:
    ld hl, OPTION_GAME_TYPE
    ld a, [MENU_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, DetachedPreplayOptionCountTable
    ld a, [MENU_CURSOR]
    call GetArrayElement
    cp b
    pop hl
    ret z

    inc [hl]
    ld a, OPTION_BGM_ADDR_LO
    cp l
    jr nz, RedrawIncrementedDetachedPreplayOption

    call ApplyGameSettings

RedrawIncrementedDetachedPreplayOption:
    call DrawOptionValues
    call DrawOptionLabel
    call DrawOptionMarkers
    ret


MACRO PREPLAY_OPTION_COUNT_ENTRY
    db \1
ENDM

DetachedPreplayOptionCountTable::
    PREPLAY_OPTION_COUNT_ENTRY OPTION_GAME_TYPE_OPTION_COUNT
    PREPLAY_OPTION_COUNT_ENTRY OPTION_LEVEL_OPTION_COUNT
    PREPLAY_OPTION_COUNT_ENTRY OPTION_SPEED_OPTION_COUNT
    PREPLAY_OPTION_COUNT_ENTRY OPTION_BGM_OPTION_COUNT

DecrementDetachedPreplaySelectedOption:
    ld hl, OPTION_GAME_TYPE
    ld a, [MENU_CURSOR]
    call GetArrayElement
    and a
    ret z

    dec [hl]
    ld a, OPTION_BGM_ADDR_LO
    cp l
    jr nz, RedrawDecrementedDetachedPreplayOption

    call ApplyGameSettings

RedrawDecrementedDetachedPreplayOption:
    call DrawOptionValues
    call DrawOptionLabel
    call DrawOptionMarkers
    ret


ApplyGameSettings::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, ApplySinglePlayerSettings

    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, PlayLinkMasterSettingsSound

    ld a, SND_LINK_SLAVE
    call PlaySound
    ret


PlayLinkMasterSettingsSound:
    ld a, SND_LINK_MASTER
    call PlaySound
    ret


ApplySinglePlayerSettings:
    call ApplySettings
    ld a, [OPTION_BGM]
    and a
    jr nz, CheckBgmOption1Settings

    ld a, SND_BGM_OPTION0
    ld [BGM_INDEX], a
    ld a, SND_BGM_PREVIEW0
    call PlaySound
    ld a, BGM_PREVIEW_UNUSED_PERIOD_OPTION0
    ld [BGM_PREVIEW_UNUSED_PERIOD], a
    ld a, BGM_PREVIEW_TIMER_INITIAL
    ld [BGM_PREVIEW_TIMER], a
    ret


CheckBgmOption1Settings:
    cp OPTION_BGM_VALUE_1
    jr nz, CheckBgmOption2Settings

    ld a, SND_BGM_OPTION1
    ld [BGM_INDEX], a
    ld a, SND_BGM_PREVIEW1
    call PlaySound
    ld a, BGM_PREVIEW_UNUSED_PERIOD_OPTION1
    ld [BGM_PREVIEW_UNUSED_PERIOD], a
    ld a, BGM_PREVIEW_TIMER_INITIAL
    ld [BGM_PREVIEW_TIMER], a
    ret


CheckBgmOption2Settings:
    cp OPTION_BGM_VALUE_2
    jr nz, ApplyBgmOffSettings

    ld a, SND_BGM_OPTION2
    ld [BGM_INDEX], a
    ld a, SND_BGM_PREVIEW2
    call PlaySound
    ld a, BGM_PREVIEW_UNUSED_PERIOD_OPTION2
    ld [BGM_PREVIEW_UNUSED_PERIOD], a
    ld a, BGM_PREVIEW_TIMER_INITIAL
    ld [BGM_PREVIEW_TIMER], a
    ret


ApplyBgmOffSettings:
    ld a, SND_BGM_OFF
    ld [BGM_INDEX], a
    ld a, SND_BGM_OFF
    call PlaySound
    ret


UpdateCursorDisplay::
    push af
    call DrawOptionBoxLayout
    call DrawOptionTextLabels
    call DrawOptionValues
    ld de, OptionCursorInactiveTileTriplets
    call DrawTileTripletList
    pop af
    and a
    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    jp z, DrawOptionLabel

    cp MENU_CURSOR_ROW_LEVEL
    jp z, DrawLevelCursorHighlight

    cp MENU_CURSOR_ROW_SPEED
    jp z, DrawSpeedCursorHighlight

    cp MENU_CURSOR_ROW_BGM
    jp z, DrawBgmCursorHighlight

DrawLevelCursorHighlight::
    call DrawOptionLevelLabelBox
    ld de, OptionCursorLevelHighlightTileTriplets
    call DrawTileTripletList
    ret


DrawSpeedCursorHighlight::
    call DrawOptionSpeedLabelBox
    ld de, OptionCursorSpeedHighlightTileTriplets
    call DrawTileTripletList
    ret


DrawBgmCursorHighlight::
    call DrawOptionBgmLabelBox
    ld de, OptionCursorBgmHighlightTileTriplets
    call DrawTileTripletList
    ret


OptionCursorLevelHighlightTileTriplets::
    DRAW_TILE_TRIPLET OPTION_CURSOR_LEVEL_ROW, OPTION_CURSOR_LEFT_COL, OPTION_CURSOR_ACTIVE_LEFT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_LEVEL_ROW, OPTION_CURSOR_RIGHT_COL, OPTION_CURSOR_ACTIVE_RIGHT_TILE
    db DRAW_TILE_TRIPLET_LIST_END
OptionCursorSpeedHighlightTileTriplets::
    DRAW_TILE_TRIPLET OPTION_CURSOR_SPEED_ROW, OPTION_CURSOR_LEFT_COL, OPTION_CURSOR_ACTIVE_LEFT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_SPEED_ROW, OPTION_CURSOR_RIGHT_COL, OPTION_CURSOR_ACTIVE_RIGHT_TILE
    db DRAW_TILE_TRIPLET_LIST_END
OptionCursorBgmHighlightTileTriplets::
    DRAW_TILE_TRIPLET OPTION_CURSOR_BGM_ROW, OPTION_CURSOR_LEFT_COL, OPTION_CURSOR_ACTIVE_LEFT_TILE
    DRAW_TILE_TRIPLET OPTION_CURSOR_BGM_ROW, OPTION_CURSOR_BGM_RIGHT_COL, OPTION_CURSOR_ACTIVE_RIGHT_TILE
    db DRAW_TILE_TRIPLET_LIST_END
    ret


DrawOptionValues::
    call DrawOptionLevelValueBoxes
    ld a, [OPTION_LEVEL]
    and a
    jr z, DrawOptionLevel0Value

    cp OPTION_LEVEL_VALUE_1
    jr z, DrawOptionLevel1Value

    cp OPTION_LEVEL_VALUE_2
    jr z, DrawOptionLevel2Value

    cp OPTION_LEVEL_VALUE_3
    jr z, DrawOptionLevel3Value

    jr DrawOptionLevel4Value

DrawOptionLevel0Value:
    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    call DrawOptionLevel0ValueBox
    ret


DrawOptionLevel1Value:
    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    call DrawOptionLevel1ValueBox
    ret


DrawOptionLevel2Value:
    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    call DrawOptionLevel2ValueBox
    ret


DrawOptionLevel3Value:
    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    call DrawOptionLevel3ValueBox
    ret


DrawOptionLevel4Value:
    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    call DrawOptionLevel4ValueBox
    ret


DrawOptionLabel::
    ld a, [MENU_CURSOR]
    and a
    ret nz

    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionAGameBox
    ld d, OPTION_BOX_NEUTRAL_TILE_OFFSET
    call DrawOptionBGameBox
    ld a, [OPTION_GAME_TYPE]
    and a
    jr nz, DrawBGameOptionLabel

    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    call DrawOptionAGameBox

ReturnFromDrawOptionGameTypeLabel::
    ret


DrawBGameOptionLabel:
    ld d, OPTION_BOX_SELECTED_TILE_OFFSET
    call DrawOptionBGameBox
    ret


SerialHandler::
    push af
    push bc
    push de
    push hl
    ld a, [LINK_ROLE]
    and a
    jr z, HandleUnassignedSerialRole

    ldh a, [rSB]
    ld [LINK_RECV], a
    ld a, [LINK_SEND]
    ldh [rSB], a
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, FinishSerialInterrupt

    ld a, SERIAL_TRANSFER_EXTERNAL_CLOCK
    ldh [rSC], a
    jr FinishSerialInterrupt

HandleUnassignedSerialRole:
    ldh a, [rSB]
    ld [LINK_RECV], a
    cp TITLE_LINK_READY_BYTE
    jr z, ClearUnassignedSerialByte

    xor a
    ldh [rSB], a
    ld a, SERIAL_DIV_RESET_WRITE_VALUE
    ldh [rDIV], a

WaitDIVTimer::
    ldh a, [rDIV]
    bit 7, a
    jr nz, WaitDIVTimer

    ld a, SERIAL_TRANSFER_EXTERNAL_CLOCK
    ldh [rSC], a
    jr FinishSerialInterrupt

ClearUnassignedSerialByte:
    xor a
    ldh [rSB], a

FinishSerialInterrupt:
    ld a, SERIAL_DONE_ACTIVE
    ldh [SERIAL_DONE], a
    pop hl
    pop de
    pop bc
    pop af
    reti


InitTitleUI::
    ld hl, TITLE_FRAME_INNER_TOP_LEFT
    ld bc, TITLE_FRAME_INNER_RECT_SIZE
    ld a, TITLE_FRAME_INNER_TILE_BASE
    call FillRect
    ld hl, TITLE_FRAME_RIGHT_STRIP_TOP_LEFT
    ld bc, TITLE_FRAME_RIGHT_STRIP_RECT_SIZE
    ld a, TITLE_FRAME_RIGHT_STRIP_TILE_BASE
    call FillRect
    ld hl, TITLE_FRAME_TOP_RIGHT_CAP_TOP_LEFT
    ld bc, TITLE_FRAME_TOP_RIGHT_CAP_RECT_SIZE
    ld a, TITLE_FRAME_TOP_RIGHT_CAP_TILE_BASE
    call FillRect
    ld hl, TITLE_MENU_PANEL_TOP_LEFT
    ld bc, TITLE_MENU_PANEL_RECT_SIZE
    ld a, TITLE_MENU_PANEL_TILE_BASE
    call FillRect
    ld hl, TITLE_BOTTOM_RIGHT_PANEL_TOP_LEFT
    ld bc, TITLE_BOTTOM_RIGHT_PANEL_RECT_SIZE
    ld a, TITLE_BOTTOM_RIGHT_PANEL_TILE_BASE
    call FillRect
    ld hl, TITLE_LEVEL_STRIP_TOP_LEFT
    ld bc, TITLE_LEVEL_STRIP_RECT_SIZE
    ld a, TITLE_LEVEL_STRIP_TILE_BASE
    call FillRect
    xor a
    ld [TITLE_PLAYER_MARKER_PHASE], a

ResetTitleState::
    ld [TITLE_PLAYER_MARKER_TIMER], a
    ld a, TITLE_PLAYER_MARKER_UNUSED_DELAY_INITIAL
    ld [TITLE_PLAYER_MARKER_UNUSED_DELAY], a
    xor a
    ld [LINK_ROLE], a
    ld [GAME_TYPE], a
    ld [MENU_CURSOR], a
    ld [LINK_RECV], a
    ld [LINK_SEND], a
    inc a
    ld [SCORE_PRESERVED_UNUSED_BYTE], a
    ld [TITLE_RESET_UNUSED_HRAM_FLAG], a
    ld [SPRITE_OBJECT_DELAY_RELOAD], a
    call DrawTitleLabels
    ret


DrawStringToGrid::
    push hl
    call CalcTilemapAddress

CopyStringToGridLoop:
    ld a, [de]
    cp DRAW_STRING_ROW_END
    jr z, AdvanceStringGridRow

    ld [hl+], a
    inc de
    jr CopyStringToGridLoop

AdvanceStringGridRow:
    inc de
    pop hl
    ld bc, BG_MAP_ROW_STRIDE
    add hl, bc
    ret


RunTitleMenu::
    xor a
    ld [LINK_RESULT_NONZERO_MARKS], a
    ld [LINK_RESULT_ZERO_MARKS], a
    ld [EGG_COUNT_UNUSED_BYTE], a
    ld [EGG_COUNT_ONES], a
    ld [EGG_COUNT_TENS], a
    ld [EGG_COUNT_HUNDREDS], a
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_PENDING_FIELD_RISE], a
    ld [EGG_TEXT_ALT_ANIM_PHASE], a
    ld [EGG_TEXT_ALT_ANIM_ACTIVE], a
    ld [ROUND_RESULT_PENDING], a
    ld [ROUND_RESULT_CODE], a
    call Multiply
    call ProcessTitleInput
    call ProcessOptionInput
    ret


StartGameplay::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, InitTwoPlayerPreplayScreen

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


InitTwoPlayerPreplayScreen:
    ld a, [LINK_ROLE]
    cp LINK_ROLE_SLAVE
    jr z, UseSlavePreplayInitSound

    ld a, SND_2P_PREPLAY_MASTER_INIT
    jr PlayTwoPlayerPreplayInitSound

UseSlavePreplayInitSound:
    ld a, SND_2P_PREPLAY_SLAVE_INIT

PlayTwoPlayerPreplayInitSound:
    call PlaySound
    call Init2PPreplayBlinkTimer
    call Draw2PPreplayScreen
    ret


UpdateFieldAnimationSlots::
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

UpdateFieldAnimSlot11BaseY:
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
    jr z, EndFieldAnimSlot11

    add b
    ld hl, FIELD_ANIM_SLOT_11_CURSOR
    inc [hl]
    pop hl
    ret


EndFieldAnimSlot11:
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
    jr z, EndFieldAnimSlot10

    ld hl, FIELD_ANIM_SLOT_10_CURSOR
    inc [hl]
    pop hl
    ret


EndFieldAnimSlot10:
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
    jr z, EndFieldAnimSlot13

    add b
    ld hl, FIELD_ANIM_SLOT_13_CURSOR
    inc [hl]
    pop hl
    ret


EndFieldAnimSlot13:
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
    jr z, EndFieldAnimSlot12

    ld hl, FIELD_ANIM_SLOT_12_CURSOR
    inc [hl]
    pop hl
    ret


EndFieldAnimSlot12:
    xor a
    ld [FIELD_ANIM_SLOT_12_ACTIVE], a
    ld [FIELD_ANIM_SLOT_12_CURSOR], a
    ld [SPRITE_OBJECT_SLOT_12], a
    ld a, FIELD_ANIM_END_SENTINEL
    pop hl
    ret


MACRO FIELD_ANIM_DELTA_PAIR
    db \1, \2
ENDM

FieldSideDeltaTable::
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_NEGATIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_NEGATIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_NEGATIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_NEGATIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    db FIELD_ANIM_END_SENTINEL
FieldRowDeltaTable::
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_ZERO
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_POSITIVE, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    FIELD_ANIM_DELTA_PAIR FIELD_ANIM_DELTA_ZERO, FIELD_ANIM_DELTA_POSITIVE
    db FIELD_ANIM_END_SENTINEL

UpdateFieldTimers::
    ld hl, FIELD_COLUMN_TIMERS
    ld b, $00

UpdateFieldColumnTimerLoop:
    xor a
    cp [hl]
    jr z, AdvanceFieldColumnTimerSlot

    dec [hl]
    call z, ClearExpiredFieldColumnEffect

AdvanceFieldColumnTimerSlot:
    inc hl
    inc b
    ld a, FIELD_COLUMN_TIMER_COUNT
    cp b
    jr nz, UpdateFieldColumnTimerLoop

    ret


ClearExpiredFieldColumnEffect::
    push bc
    push hl
    ld a, b
    add FIELD_COLUMN_EFFECT_SLOT_BASE
    swap a
    ld l, a
    ld h, SPRITE_OBJECTS_HI
    call ClearSpriteObjectSlot
    pop hl
    pop bc
    ret


ClearSpriteObjectSlot::
    ld b, SPRITE_OBJECT_SLOT_SIZE
    xor a

ClearSpriteObjectSlotLoop:
    ld [hl+], a
    dec b
    jr nz, ClearSpriteObjectSlotLoop

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
    jr z, SendNextLinkQueueByte

    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    ret nz

    ld a, LINK_PAUSE_PACKET
    ld [LINK_SEND], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a
    ret


SendNextLinkQueueByte:
    ld a, [LINK_SEND_QUEUE_INDEX]
    ld hl, LINK_SEND_QUEUE_0
    add l
    ld l, a
    jr nc, AdvanceLinkSendQueueIndex

    inc h

AdvanceLinkSendQueueIndex:
    ld a, [LINK_SEND_QUEUE_INDEX]
    inc a
    cp LINK_SEND_QUEUE_SLOT_COUNT
    jr c, StoreNextLinkSendQueueIndex

    xor a

StoreNextLinkSendQueueIndex:
    ld [LINK_SEND_QUEUE_INDEX], a
    ld a, [hl]
    ld [LINK_SEND], a
    xor a
    ld [hl], a
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr nz, DispatchReceivedLinkPacket

    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a

DispatchReceivedLinkPacket:
    ld a, [LINK_RECV]
    cp LINK_PAUSE_PACKET
    jr z, HandleReceivedLinkPausePacket

    bit LINK_RESULT_PACKET_BIT, a
    jr z, DispatchReceivedLinkFieldCountPacket

    jp ProcessLinkResultPacket


DispatchReceivedLinkFieldCountPacket:
    bit LINK_FIELD_COUNT_PACKET_BIT, a
    jr z, DispatchReceivedLinkFieldRisePacket

    jp ProcessLinkFieldCountPacket


DispatchReceivedLinkFieldRisePacket:
    bit LINK_FIELD_EVENT_BIT, a
    ret z

    jp ProcessLinkFieldRisePacket


HandleReceivedLinkPausePacket:
    ld a, PAUSE_FLAG_ACTIVE
    ld [PAUSE_FLAG], a
    ret


ProcessLinkFieldRisePacket::
    res LINK_FIELD_EVENT_BIT, a
    ld b, a
    ld a, [LINK_PENDING_FIELD_RISE]
    add b
    ld [LINK_PENDING_FIELD_RISE], a
    ret


ProcessLinkResultPacket::
    ld b, ROUND_RESULT_CODE_NONZERO
    bit LINK_RESULT_CODE_BIT, a
    jr z, QueueLinkResultPacketOutcome

    ld a, [RESULT_GAME_OVER_FLAG]
    and a
    jr nz, QueueLinkResultPacketOutcome

    ld hl, LINK_PEER_FIELD_COUNT_TENS
    ld a, FIELD_OCCUPANCY_COUNT_DIGIT_BASE
    ld [hl+], a
    ld [hl], a
    ld b, ROUND_RESULT_CODE_ZERO

QueueLinkResultPacketOutcome:
    ld a, b
    call QueueRoundResult
    ret


ProcessLinkFieldCountPacket::
    res LINK_FIELD_COUNT_PACKET_BIT, a
    ld hl, LINK_PEER_FIELD_COUNT_ONES
    jp DrawTwoDigitLinkFieldCount


DrawTwoDigitLinkFieldCount::
    ld b, $00

CountLinkFieldTensDigitLoop:
    cp FIELD_OCCUPANCY_COUNT_DECIMAL_BASE
    jr c, StoreTwoDigitLinkFieldCount

    inc b
    sub FIELD_OCCUPANCY_COUNT_DECIMAL_BASE
    jr CountLinkFieldTensDigitLoop

StoreTwoDigitLinkFieldCount:
    add FIELD_OCCUPANCY_COUNT_DIGIT_BASE
    ld [hl-], a
    ld a, b
    add FIELD_OCCUPANCY_COUNT_DIGIT_BASE
    ld [hl], a
    ret


QueueLinkFieldOccupancyCount::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret z

    xor a
    ldh [ANIM_FRAME], a
    ld hl, FIELD_OCCUPANCY_SCAN_TOP_LEFT
    ld de, FIELD_OCCUPANCY_SCAN_NEXT_ROW_DELTA
    ld c, FIELD_OCCUPANCY_SCAN_ROWS

ScanLinkFieldOccupancyRow:
    ld b, FIELD_OCCUPANCY_SCAN_COLUMNS

ScanLinkFieldOccupancyColumn:
    ld a, [hl+]
    inc hl
    inc hl
    inc hl
    cp FIELD_OCCUPANCY_EMPTY_TILE
    jr z, AdvanceLinkFieldOccupancyColumn

    ldh a, [ANIM_FRAME]
    inc a
    ldh [ANIM_FRAME], a

AdvanceLinkFieldOccupancyColumn:
    dec b
    jr nz, ScanLinkFieldOccupancyColumn

    add hl, de
    dec c
    jr nz, ScanLinkFieldOccupancyRow

    ldh a, [ANIM_FRAME]
    ld hl, LINK_LOCAL_FIELD_COUNT_ONES
    call DrawTwoDigitLinkFieldCount
    ldh a, [ANIM_FRAME]
    or LINK_FIELD_COUNT_PACKET_FLAG
    ld [LINK_SEND_QUEUE_1], a
    ret


Exchange2PResultCode::
    push af
    push bc
    push de
    push hl
    ld b, a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, ReturnFrom2PResultCodeExchange

    ld a, b
    or LINK_RESULT_PACKET_FLAG
    ldh [ANIM_FRAME], a

WaitForPeerResultCodePacket:
    ldh a, [ANIM_FRAME]
    ld [LINK_SEND], a
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_SEND_QUEUE_1], a
    ld a, [LINK_RECV]
    bit LINK_RESULT_PACKET_BIT, a
    jr z, WaitForPeerResultCodePacket

    res LINK_RESULT_PACKET_BIT, a
    ld [LINK_PEER_RESULT_CODE], a
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

ReturnFrom2PResultCodeExchange:
    pop hl
    pop de
    pop bc
    pop af
    ret


Run2PPreplayLoop::
    call Exchange2PPreplaySettings
    call Draw2PPreplayDynamicSettings
    call TickSettingsBlink
    call Multiply
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr nz, Check2PPreplayReceivedStartHandshake

    ldh a, [JOYPAD_PRESSED]
    and a
    ret z

    push af
    xor a
    ld [SETTINGS_BLINK_PHASE], a
    ld a, SETTINGS_BLINK_PERIOD
    ld [SETTINGS_BLINK_TIMER], a
    pop af
    bit PADB_START, a
    jr z, Handle2PPreplayNonStartInput

    call WaitVBlank
    xor a
    ld [LINK_SEND], a
    ld a, LINK_CONFIRM_BYTE
    ldh [rSB], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a
    jr Enter2PPreplayPlaySetup

Check2PPreplayReceivedStartHandshake:
    ld a, [LINK_RECV]
    cp LINK_CONFIRM_BYTE
    jr nz, Poll2PPreplayNonMasterInput

    xor a
    ldh [rSB], a
    jr Enter2PPreplayPlaySetup

Poll2PPreplayNonMasterInput:
    ldh a, [JOYPAD_PRESSED]
    res PADB_START, a
    and a
    ret z

    jr Handle2PPreplayNonStartInput

Enter2PPreplayPlaySetup:
    xor a
    ld [LINK_SEND], a
    ld [LINK_RECV], a
    call WaitVBlank
    call InitGameState
    ld a, GAME_STATE_PLAY_SETUP
    ldh [GAME_STATE], a
    ret


Handle2PPreplayNonStartInput:
    bit PADB_UP, a
    jr nz, Move2PPreplayCursorUp

    bit PADB_DOWN, a
    jr nz, Move2PPreplayCursorDown

    bit PADB_RIGHT, a
    jr nz, Increment2PPreplaySelectedSetting

    bit PADB_LEFT, a
    jr nz, Decrement2PPreplaySelectedSetting

    ret


Move2PPreplayCursorUp:
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld a, [LINK_SETTINGS_CURSOR]
    and a
    ret z

    ld hl, LINK_SETTINGS_CURSOR
    dec [hl]
    ret


Move2PPreplayCursorDown:
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld a, [LINK_SETTINGS_CURSOR]
    cp LINK_SETTINGS_ROW_SPEED
    ret z

    ld hl, LINK_SETTINGS_CURSOR
    inc [hl]
    ret


Increment2PPreplaySelectedSetting:
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld hl, LINK_2P_SELECTED_LEVEL
    ld a, [LINK_SETTINGS_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, LinkSettingsOptionCountTable
    ld a, [LINK_SETTINGS_CURSOR]
    call GetArrayElement
    cp b
    pop hl
    ret z

    inc [hl]
    ret


MACRO LINK_SETTINGS_OPTION_COUNT_ENTRY
    db \1
ENDM

LinkSettingsOptionCountTable::
    LINK_SETTINGS_OPTION_COUNT_ENTRY LINK_SETTINGS_LEVEL_OPTION_COUNT
    LINK_SETTINGS_OPTION_COUNT_ENTRY LINK_SETTINGS_SPEED_OPTION_COUNT

Decrement2PPreplaySelectedSetting:
    ld a, SND_CURSOR_MOVE
    call PlaySound
    ld a, [LINK_SETTINGS_CURSOR]
    ld hl, LINK_2P_SELECTED_LEVEL
    call GetArrayElement
    and a
    ret z

    dec [hl]
    ret


Init2PPreplayBlinkTimer::
    ld a, SETTINGS_BLINK_PERIOD
    ld [SETTINGS_BLINK_TIMER], a
    ret


Draw2PPreplayScreen::
    call Draw2PPreplayBackground
    call Draw2PPreplayRoleHeader
    call Draw2PPreplayRolePanels
    call Draw2PPreplayLevelLabel
    call Draw2PPreplaySpeedLabel
    call Draw2PPreplayLevelText
    call Draw2PPreplaySpeedText
    ret


Draw2PPreplayDynamicSettings::
    call Draw2PPreplayLevelLabel
    call Draw2PPreplaySpeedLabel
    call Draw2PPreplayLevelText
    call Draw2PPreplaySpeedText
    ret


Draw2PPreplayBackground::
    ld hl, PREPLAY_2P_BACKGROUND_TOP_LEFT
    ld bc, PREPLAY_2P_BACKGROUND_RECT_SIZE
    ld a, PREPLAY_2P_BACKGROUND_TILE
    call FillTilemapRectByCoord
    ld hl, PREPLAY_2P_TOP_PANEL_TOP_LEFT
    ld bc, PREPLAY_2P_TOP_PANEL_RECT_SIZE
    ld a, PREPLAY_2P_PANEL_CLEAR_TILE
    call FillTilemapRectByCoord
    ld hl, PREPLAY_2P_BOTTOM_PANEL_TOP_LEFT
    ld bc, PREPLAY_2P_BOTTOM_PANEL_RECT_SIZE
    ld a, PREPLAY_2P_PANEL_CLEAR_TILE
    call FillTilemapRectByCoord
    ret


Draw2PPreplayRoleHeader::
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, Use2PPreplayRole1HeaderText

    ld de, ScoreHeaderTextRoleOther
    jr Draw2PPreplayRoleHeaderText

Use2PPreplayRole1HeaderText:
    ld de, ScoreHeaderTextRole1

Draw2PPreplayRoleHeaderText:
    ld hl, PREPLAY_2P_ROLE_HEADER_COORD
    call DrawStringToGrid
    ret


MACRO TWO_PLAYER_ROLE_HEADER_TEXT
    db PREPLAY_1P_PANEL_CLEAR_TILE
    db LOW(\1), LOW(\1) + $01, LOW(\1) + $02, LOW(\1) + $03
    db PREPLAY_1P_PANEL_CLEAR_TILE
    db TWO_PLAYER_ROLE_HEADER_SUFFIX_TILE_0, TWO_PLAYER_ROLE_HEADER_SUFFIX_TILE_1
    db PREPLAY_1P_PANEL_CLEAR_TILE
    db LOW(\2), LOW(\2) + $01, LOW(\2) + $02, LOW(\2) + $03
    db PREPLAY_1P_PANEL_CLEAR_TILE, DRAW_STRING_ROW_END
ENDM

ScoreHeaderTextRole1::
    TWO_PLAYER_ROLE_HEADER_TEXT TWO_PLAYER_ROLE_HEADER_TILE_ROW_0, TWO_PLAYER_ROLE_HEADER_TILE_ROW_1
ScoreHeaderTextRoleOther::
    TWO_PLAYER_ROLE_HEADER_TEXT TWO_PLAYER_ROLE_HEADER_TILE_ROW_1, TWO_PLAYER_ROLE_HEADER_TILE_ROW_0

Draw2PPreplaySpeedText::
    ld hl, PREPLAY_2P_LOCAL_SPEED_TEXT_COORD
    ld a, [LINK_SETTINGS_CURSOR]
    cp LINK_SETTINGS_ROW_SPEED
    jr nz, Select2PPreplayLocalSpeedTextBySetting

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, Select2PPreplayLocalSpeedTextBySetting

    ld de, ResultTextBlock2
    jr Draw2PPreplayLocalSpeedTextLines

Select2PPreplayLocalSpeedTextBySetting:
    ld a, [LINK_2P_SELECTED_SPEED]
    and a
    jr nz, Use2PPreplayLocalHighSpeedText

    ld de, ResultTextBlock0
    jr Draw2PPreplayLocalSpeedTextLines

Use2PPreplayLocalHighSpeedText:
    ld de, ResultTextBlock1

Draw2PPreplayLocalSpeedTextLines:
    call DrawStringToGrid
    call DrawStringToGrid
    ld hl, PREPLAY_2P_PEER_SPEED_TEXT_COORD
    ld a, [LINK_RECV_SPEED]
    and a
    jr nz, Use2PPreplayPeerHighSpeedText

    ld de, ResultTextBlock0
    jr Draw2PPreplayPeerSpeedTextLines

Use2PPreplayPeerHighSpeedText:
    ld de, ResultTextBlock1

Draw2PPreplayPeerSpeedTextLines:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


MACRO PREPLAY_SPEED_TEXT_ROW
    db \1, \2, \3, \4
    db PREPLAY_1P_PANEL_CLEAR_TILE, PREPLAY_1P_PANEL_CLEAR_TILE
    db \5, \5 + $01, \5 + $02, \5 + $03
    db DRAW_STRING_ROW_END
ENDM

ResultTextBlock0::
    PREPLAY_SPEED_TEXT_ROW $bc, $bd, $be, $bf, $e4
    PREPLAY_SPEED_TEXT_ROW $c0, $c1, $c2, $9d, $e8
ResultTextBlock1::
    PREPLAY_SPEED_TEXT_ROW $dc, $dd, $de, $df, $d4
    PREPLAY_SPEED_TEXT_ROW $e0, $e1, $e2, $e3, $d8
ResultTextBlock2::
    PREPLAY_SPEED_TEXT_ROW $dc, $dd, $de, $df, $e4
    PREPLAY_SPEED_TEXT_ROW $e0, $e1, $e2, $e3, $e8

Draw2PPreplayRolePanels::
    ld a, [LINK_ROLE]
    cp LINK_ROLE_SLAVE
    jr z, Draw2PPreplayRolePanelsForSlave

    ld a, PREPLAY_2P_MASTER_ROLE_PANEL_TILE
    ld hl, PREPLAY_2P_TOP_ROLE_PANEL_COORD
    call Draw2PPreplayRolePanelAtCoord
    ld a, PREPLAY_2P_SLAVE_ROLE_PANEL_TILE
    ld hl, PREPLAY_2P_BOTTOM_ROLE_PANEL_COORD
    call Draw2PPreplayRolePanelAtCoord
    ret


Draw2PPreplayRolePanelsForSlave:
    ld a, PREPLAY_2P_SLAVE_ROLE_PANEL_TILE
    ld hl, PREPLAY_2P_TOP_ROLE_PANEL_COORD
    call Draw2PPreplayRolePanelAtCoord
    ld a, PREPLAY_2P_MASTER_ROLE_PANEL_TILE
    ld hl, PREPLAY_2P_BOTTOM_ROLE_PANEL_COORD
    call Draw2PPreplayRolePanelAtCoord
    ret


Draw2PPreplayRolePanelAtCoord::
    push af
    call CalcTilemapAddress
    pop af
    ld de, PREPLAY_2P_ROLE_PANEL_NEXT_ROW_DELTA
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


Draw2PPreplayLevelLabel::
    ld hl, PREPLAY_2P_LEVEL_LABEL_COORD
    call Draw2PPreplayLevelLabelAtCoord
    ret


Draw2PPreplayLevelLabelAtCoord::
    ld b, PREPLAY_LABEL_TILE_ROW_WIDTH
    ld a, [LINK_SETTINGS_CURSOR]
    and a
    jr z, UseSelected2PPreplayLevelLabelTiles

    ld bc, PREPLAY_LEVEL_LABEL_TILE_ROW
    jr Draw2PPreplayLevelLabelTiles

UseSelected2PPreplayLevelLabelTiles:
    ld bc, PREPLAY_LEVEL_LABEL_SELECTED_TILE_ROW

Draw2PPreplayLevelLabelTiles:
    call DrawSequentialTileRowByCoord
    ret


Draw2PPreplaySpeedLabel::
    ld hl, PREPLAY_2P_SPEED_LABEL_COORD
    call Draw2PPreplaySpeedLabelAtCoord
    ret


Draw2PPreplaySpeedLabelAtCoord::
    ld b, PREPLAY_LABEL_TILE_ROW_WIDTH
    ld a, [LINK_SETTINGS_CURSOR]
    cp LINK_SETTINGS_ROW_SPEED
    jr z, UseSelected2PPreplaySpeedLabelTiles

    ld bc, PREPLAY_SPEED_LABEL_TILE_ROW
    jr Draw2PPreplaySpeedLabelTiles

UseSelected2PPreplaySpeedLabelTiles:
    ld bc, PREPLAY_SPEED_LABEL_SELECTED_TILE_ROW

Draw2PPreplaySpeedLabelTiles:
    call DrawSequentialTileRowByCoord
    ret


Draw2PPreplayLevelText::
    ld a, PREPLAY_2P_LOCAL_LEVEL_TEXT_ROW_AND_COL
    ld [ANIM_FRAME], a
    ld [STATE_TRANSITION], a
    ld a, [LINK_2P_SELECTED_LEVEL]
    call Draw2PPreplayLocalLevelText
    ld a, PREPLAY_2P_PEER_LEVEL_TEXT_ROW
    ld [ANIM_FRAME], a
    ld a, PREPLAY_2P_PEER_LEVEL_TEXT_COL
    ld [STATE_TRANSITION], a
    ld a, [LINK_RECV_LEVEL]
    call Draw2PPreplayLevelTextAtIndex
    ret


Draw2PPreplayLocalLevelText::
    ldh [UI_SCRATCH], a
    ld a, [LINK_SETTINGS_CURSOR]
    and a
    jr nz, Select2PPreplayLocalLevelTextBySetting

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, Select2PPreplayLocalLevelTextBySetting

    ld de, PiecePreviewBlankText
    jr Draw2PPreplayLevelTextLines

Select2PPreplayLocalLevelTextBySetting:
    ldh a, [UI_SCRATCH]

Draw2PPreplayLevelTextAtIndex::
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

Draw2PPreplayLevelTextLines:
    ld a, [ANIM_FRAME]
    ld h, a
    ld a, [STATE_TRANSITION]
    ld l, a
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    ret


MACRO PIECE_PREVIEW_TOP_UNSELECTED_CELL
    db PIECE_PREVIEW_UNSELECTED_TOP_LEFT_TILE
    db PIECE_PREVIEW_UNSELECTED_TOP_LEFT_TILE + $01
    db PIECE_PREVIEW_UNSELECTED_TOP_LEFT_TILE + $02
ENDM

MACRO PIECE_PREVIEW_TOP_SELECTED_CELL
    db PIECE_PREVIEW_SELECTED_TOP_LEFT_TILE
    db PIECE_PREVIEW_SELECTED_TOP_LEFT_TILE + $01
    db PIECE_PREVIEW_SELECTED_TOP_LEFT_TILE + $02
ENDM

MACRO PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL
    db PIECE_PREVIEW_UNSELECTED_MIDDLE_LEFT_TILE, \1, PIECE_PREVIEW_UNSELECTED_MIDDLE_RIGHT_TILE
ENDM

MACRO PIECE_PREVIEW_MIDDLE_SELECTED_CELL
    db PIECE_PREVIEW_SELECTED_MIDDLE_LEFT_TILE, \1, PIECE_PREVIEW_SELECTED_MIDDLE_RIGHT_TILE
ENDM

MACRO PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    db PIECE_PREVIEW_UNSELECTED_BOTTOM_LEFT_TILE
    db PIECE_PREVIEW_UNSELECTED_BOTTOM_MIDDLE_TILE
    db PIECE_PREVIEW_UNSELECTED_BOTTOM_LEFT_TILE + $01
ENDM

MACRO PIECE_PREVIEW_BOTTOM_SELECTED_CELL
    db PIECE_PREVIEW_SELECTED_BOTTOM_LEFT_TILE
    db PIECE_PREVIEW_SELECTED_BOTTOM_MIDDLE_TILE
    db PIECE_PREVIEW_SELECTED_BOTTOM_LEFT_TILE + $01
ENDM

PiecePreviewTextTable::
PiecePreviewText0::
    PIECE_PREVIEW_TOP_SELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_MIDDLE_SELECTED_CELL PIECE_PREVIEW_LEVEL0_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL1_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL2_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL3_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL4_TILE
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_BOTTOM_SELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
PiecePreviewText1::
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_SELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL0_TILE
    PIECE_PREVIEW_MIDDLE_SELECTED_CELL PIECE_PREVIEW_LEVEL1_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL2_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL3_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL4_TILE
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_SELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
PiecePreviewText2::
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_SELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL0_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL1_TILE
    PIECE_PREVIEW_MIDDLE_SELECTED_CELL PIECE_PREVIEW_LEVEL2_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL3_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL4_TILE
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_SELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
PiecePreviewText3::
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_SELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL0_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL1_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL2_TILE
    PIECE_PREVIEW_MIDDLE_SELECTED_CELL PIECE_PREVIEW_LEVEL3_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL4_TILE
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_SELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
PiecePreviewText4::
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_SELECTED_CELL
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL0_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL1_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL2_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL3_TILE
    PIECE_PREVIEW_MIDDLE_SELECTED_CELL PIECE_PREVIEW_LEVEL4_TILE
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_SELECTED_CELL
    db DRAW_STRING_ROW_END
PiecePreviewBlankText::
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    PIECE_PREVIEW_TOP_UNSELECTED_CELL
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL0_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL1_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL2_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL3_TILE
    PIECE_PREVIEW_MIDDLE_UNSELECTED_CELL PIECE_PREVIEW_LEVEL4_TILE
    db DRAW_STRING_ROW_END
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    PIECE_PREVIEW_BOTTOM_UNSELECTED_CELL
    db DRAW_STRING_ROW_END

Exchange2PPreplaySettings::
    ld a, [LINK_2P_SELECTED_LEVEL]
    swap a
    ld b, a
    ld a, [LINK_2P_SELECTED_SPEED]
    or b
    ld [LINK_SEND], a
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER

Start2PPreplaySettingsExchange:
    jr nz, Wait2PPreplaySettingsSerialDone

    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a

Wait2PPreplaySettingsSerialDone:
    ldh a, [SERIAL_DONE]
    and a
    jr z, Wait2PPreplaySettingsSerialDone

    xor a
    ldh [SERIAL_DONE], a
    ld a, [LINK_RECV]
    ld b, a
    cp LINK_CONFIRM_BYTE
    ret z

    swap a
    and LINK_SETTINGS_NIBBLE_MASK
    ld [LINK_RECV_LEVEL], a
    ld a, b
    and LINK_SETTINGS_NIBBLE_MASK
    ld [LINK_RECV_SPEED], a
    ret


InitResultRecordsIfNeeded::
    ld a, [RESULT_RECORDS_INIT_FLAG]
    and a
    ret nz

    ld a, RESULT_RECORD_EMPTY_HEAD

InitATypeResultRecord0:
    ld [A_TYPE_RESULT_RECORD_0], a

InitATypeResultRecord1:
    ld [A_TYPE_RESULT_RECORD_1], a

InitATypeResultRecord2:
    ld [A_TYPE_RESULT_RECORD_2], a

InitBTypeResultRecords:
    ld [B_TYPE_RESULT_RECORD_0], a
    ld [B_TYPE_RESULT_RECORD_1], a
    ld [B_TYPE_RESULT_RECORD_2], a
    ld [RESULT_RECORDS_INIT_FLAG], a
    ret


ProcessCurrentResultRecordAndSetupScreen::
    ld hl, SCORE_DIGITS
    ld de, CURRENT_RESULT_RECORD
    ld bc, RESULT_RECORD_SCORE_DIGIT_COUNT
    call Memcopy
    ld a, [LEVEL_DISPLAY_ONES]
    ld [CURRENT_RESULT_LEVEL_ONES], a
    ld a, [LEVEL_DISPLAY_TENS]
    ld [CURRENT_RESULT_LEVEL_TENS], a
    ld a, [GAME_TYPE]
    and a
    jr nz, CopyBTypeResultTimerDigits

    ld hl, EGG_COUNT_HUNDREDS
    ld de, CURRENT_RESULT_DETAIL_DIGITS
    ld a, [hl-]
    ld [de], a

CopyATypeEggCountRemainingDigits:
    inc de
    ld a, [hl-]
    ld [de], a
    inc de
    ld a, [hl-]
    ld [de], a
    jr MaskCurrentResultRecordDigits

CopyBTypeResultTimerDigits:
    ld hl, TOTAL_TIMER_DIGITS
    ld de, CURRENT_RESULT_DETAIL_DIGITS
    ld bc, RESULT_RECORD_B_TYPE_DETAIL_DIGIT_COUNT
    call Memcopy

MaskCurrentResultRecordDigits:
    ld hl, CURRENT_RESULT_RECORD
    ld c, RESULT_RECORD_SIZE

MaskCurrentResultRecordDigitsLoop:
    ld a, [hl]
    and RESULT_RECORD_DIGIT_MASK
    ld [hl+], a
    dec c
    jr nz, MaskCurrentResultRecordDigitsLoop

    xor a
    ldh [ANIM_FRAME], a
    ld hl, A_TYPE_RESULT_RECORDS
    ld a, [GAME_TYPE]
    and a
    jr z, BeginResultRecordInsertScan

    ld hl, B_TYPE_RESULT_RECORDS

BeginResultRecordInsertScan:
    ld c, RESULT_RECORD_ROW_COUNT
    ld b, RESULT_RECORD_FIRST_RANK

ScanResultRecordInsertPositionLoop:
    push hl
    push bc
    ld a, [hl]
    inc a
    jr z, InsertCurrentResultRecordAtRank

    ld de, CURRENT_RESULT_RECORD
    ld c, RESULT_RECORD_SCORE_DIGIT_COUNT
    call CompareResultRecordBytes
    jr c, InsertCurrentResultRecordAtRank

    jr nz, AdvanceResultRecordScanSlot

    ld de, RESULT_RECORD_LEVEL_OFFSET
    add hl, de
    ld de, CURRENT_RESULT_LEVEL_TENS
    ld c, RESULT_RECORD_LEVEL_DIGIT_COUNT
    call CompareResultRecordBytes
    jr c, InsertCurrentResultRecordAtRank

    jr nz, AdvanceResultRecordScanSlot

    inc hl
    inc hl
    ld de, CURRENT_RESULT_DETAIL_DIGITS
    ld a, [GAME_TYPE]
    and a
    jr nz, CompareBTypeResultTimerDigits

    ld c, RESULT_RECORD_A_TYPE_DETAIL_DIGIT_COUNT
    call CompareResultRecordBytes
    jr c, InsertCurrentResultRecordAtRank

    jr z, InsertCurrentResultRecordAtRank

    jr AdvanceResultRecordScanSlot

CompareBTypeResultTimerDigits:
    ld c, RESULT_RECORD_B_TYPE_DETAIL_DIGIT_COUNT
    call CompareResultRecordBytes
    jr nc, InsertCurrentResultRecordAtRank

AdvanceResultRecordScanSlot:
    pop bc
    pop hl
    ld de, RESULT_RECORD_SIZE
    add hl, de
    inc b
    dec c
    jr nz, ScanResultRecordInsertPositionLoop

    jr SetupResultRecordScreen

InsertCurrentResultRecordAtRank:
    pop bc
    ld a, b
    ldh [ANIM_FRAME], a
    cp RESULT_RECORD_ROW_COUNT
    jr z, CopyCurrentResultRecordToRankSlot

    ld a, [GAME_TYPE]
    and a
    jr nz, ShiftBTypeResultRecordsForInsert

    ld hl, A_TYPE_RESULT_RECORD_1
    ld de, A_TYPE_RESULT_RECORD_2
    ld bc, RESULT_RECORD_SIZE
    call Memcopy
    ldh a, [ANIM_FRAME]
    cp RESULT_RECORD_FIRST_RANK
    jr nz, CopyCurrentResultRecordToRankSlot

    ld hl, A_TYPE_RESULT_RECORD_0
    ld de, A_TYPE_RESULT_RECORD_1
    ld bc, RESULT_RECORD_SIZE
    call Memcopy
    jr CopyCurrentResultRecordToRankSlot

ShiftBTypeResultRecordsForInsert:
    ld hl, B_TYPE_RESULT_RECORD_1
    ld de, B_TYPE_RESULT_RECORD_2
    ld bc, RESULT_RECORD_SIZE
    call Memcopy
    ldh a, [ANIM_FRAME]
    cp RESULT_RECORD_FIRST_RANK
    jr nz, CopyCurrentResultRecordToRankSlot

    ld hl, B_TYPE_RESULT_RECORD_0
    ld de, B_TYPE_RESULT_RECORD_1
    ld bc, RESULT_RECORD_SIZE
    call Memcopy

CopyCurrentResultRecordToRankSlot:
    pop de
    ld hl, CURRENT_RESULT_RECORD
    ld bc, RESULT_RECORD_SIZE
    call Memcopy

SetupResultRecordScreen:
    call LCDOff
    call ClearOAM
    ld a, ROM_BANK_GRAPHICS_1
    ld [MBC1_ROM_BANK_REG], a
    ld hl, Bank3ResultRecordTilesTo9000
    ld de, VRAM_TILE_BLOCK_9000
    ld bc, BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE
    call MemcopyCall
    ld hl, Bank3ResultRecordTilesTo8800
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK3_RESULT_RECORD_TILE_BLOCK_COPY_SIZE
    call MemcopyCall
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    xor a
    ldh [rBGP], a
    call LCDOn
    ld hl, BG_MAP_SHADOW
    ld bc, BG_MAP_SHADOW_SIZE
    ld d, RESULT_RECORD_BG_SHADOW_CLEAR_TILE
    call FillBytesWithD
    ld a, RESULT_RECORD_SCREEN_HEADER_TILE
    ld hl, RESULT_RECORD_SCREEN_HEADER_TOP_LEFT
    ld bc, RESULT_RECORD_SCREEN_HEADER_RECT_SIZE
    call FillRect
    ld a, RESULT_RECORD_TYPE_LABEL_TILE
    ld hl, RESULT_RECORD_TYPE_LABEL_TOP_LEFT
    ld bc, RESULT_RECORD_TYPE_LABEL_RECT_SIZE
    call FillRect
    ld hl, RESULT_RECORD_BOX_TOP_LEFT
    ld a, RESULT_RECORD_BOX_TOP_LEFT_TILE
    ld de, RESULT_RECORD_BOX_TOP_MIDDLE_RIGHT_TILES
    call FillResultRecordBoxRow
    ld c, RESULT_RECORD_BOX_BODY_ROW_COUNT

FillResultRecordBoxBodyRows:
    ld a, RESULT_RECORD_BOX_BODY_LEFT_TILE
    ld de, RESULT_RECORD_BOX_BODY_MIDDLE_RIGHT_TILES
    call FillResultRecordBoxRow
    dec c
    jr nz, FillResultRecordBoxBodyRows

    ld a, RESULT_RECORD_BOX_BOTTOM_LEFT_TILE
    ld de, RESULT_RECORD_BOX_BOTTOM_MIDDLE_RIGHT_TILES
    call FillResultRecordBoxRow
    ld a, RESULT_RECORD_LABEL_TILE_0
    ld hl, RESULT_RECORD_LABEL_ORIGIN_0
    ld bc, RESULT_RECORD_LABEL_RECT_SIZE
    call FillRect
    ld a, RESULT_RECORD_LABEL_TILE_1
    ld hl, RESULT_RECORD_LABEL_ORIGIN_1
    ld bc, RESULT_RECORD_LABEL_RECT_SIZE
    call FillRect
    ld a, RESULT_RECORD_LABEL_TILE_2
    ld hl, RESULT_RECORD_LABEL_ORIGIN_2
    ld bc, RESULT_RECORD_LABEL_RECT_SIZE
    call FillRect
    ld hl, RESULT_RECORD_SCORE_PLACEHOLDER_ORIGIN
    call FillResultRecordPlaceholderColumn
    ld hl, RESULT_RECORD_LEVEL_PLACEHOLDER_ORIGIN
    call FillResultRecordPlaceholderColumn
    ld hl, RESULT_RECORD_DETAIL_PLACEHOLDER_ORIGIN
    call FillResultRecordPlaceholderColumn
    ld a, RESULT_RECORD_COLUMN_HEADER_TILE
    ld hl, RESULT_RECORD_COLUMN_HEADER_TOP_LEFT
    ld bc, RESULT_RECORD_COLUMN_HEADER_RECT_SIZE
    call FillRect
    ld a, [GAME_TYPE]
    and a
    jr nz, DrawBTypeResultRecordDetailLayout

    ld a, RESULT_RECORD_A_TYPE_DETAIL_LEFT_TILE
    ld hl, RESULT_RECORD_A_TYPE_DETAIL_LEFT_TOP_LEFT
    ld bc, RESULT_RECORD_A_TYPE_DETAIL_LEFT_RECT_SIZE
    call FillRect
    ld a, RESULT_RECORD_A_TYPE_DETAIL_RIGHT_TILE
    ld hl, RESULT_RECORD_A_TYPE_DETAIL_RIGHT_TOP_LEFT
    ld bc, RESULT_RECORD_A_TYPE_DETAIL_RIGHT_RECT_SIZE
    call FillRect
    jr RenderStoredResultRecords

DrawBTypeResultRecordDetailLayout:
    ld a, RESULT_RECORD_B_TYPE_HEADER_PATCH_TILE
    ld hl, RESULT_RECORD_B_TYPE_HEADER_PATCH_TOP_LEFT
    ld bc, RESULT_RECORD_B_TYPE_HEADER_PATCH_RECT_SIZE
    call FillRect
    ld a, RESULT_RECORD_B_TYPE_LABEL_PATCH_TILE
    ld [RESULT_RECORD_B_TYPE_LABEL_PATCH], a
    ld a, RESULT_RECORD_B_TYPE_DETAIL_TILE
    ld hl, RESULT_RECORD_B_TYPE_DETAIL_TOP_LEFT
    ld bc, RESULT_RECORD_B_TYPE_DETAIL_RECT_SIZE
    call FillRect
    ld a, RESULT_RECORD_B_TYPE_MARK_TILE
    ld hl, RESULT_RECORD_B_TYPE_MARK_TOP_LEFT
    ld bc, RESULT_RECORD_B_TYPE_MARK_RECT_SIZE
    call FillRect

RenderStoredResultRecords:
    ld a, [GAME_TYPE]
    and a
    jr nz, RenderBTypeResultRecords

    ld de, A_TYPE_RESULT_RECORDS
    call DrawStoredResultRecords
    jp WaitResultRecordScreenInput


RenderBTypeResultRecords:
    ld de, B_TYPE_RESULT_RECORDS
    call DrawStoredResultRecords

WaitResultRecordScreenInput::
    call FadeInResultRecordPalette
    xor a
    ldh [STATE_TRANSITION], a
    ldh a, [ANIM_FRAME]
    and a
    jp z, WaitAnyButtonPress

    ld b, RESULT_RECORD_LABEL_SELECTED_TILE_0
    ld c, RESULT_RECORD_LABEL_TILE_0
    ld hl, RESULT_RECORD_LABEL_ORIGIN_0
    dec a
    jr z, BlinkResultRecordLabelLoop

    ld b, RESULT_RECORD_LABEL_SELECTED_TILE_1
    ld c, RESULT_RECORD_LABEL_TILE_1
    ld hl, RESULT_RECORD_LABEL_ORIGIN_1
    dec a
    jr z, BlinkResultRecordLabelLoop

    ld b, RESULT_RECORD_LABEL_SELECTED_TILE_2
    ld c, RESULT_RECORD_LABEL_TILE_2
    ld hl, RESULT_RECORD_LABEL_ORIGIN_2

BlinkResultRecordLabelLoop:
    push bc
    push hl
    ld d, b
    ldh a, [STATE_TRANSITION]
    cp RESULT_RECORD_LABEL_BLINK_ALT_START_FRAME
    jr c, DrawResultRecordLabelBlinkState

    ld d, c

DrawResultRecordLabelBlinkState:
    ld a, d
    ld bc, RESULT_RECORD_LABEL_RECT_SIZE
    call FillRect
    ldh a, [STATE_TRANSITION]
    inc a
    ldh [STATE_TRANSITION], a
    cp RESULT_RECORD_LABEL_BLINK_PERIOD
    jr c, PollResultRecordBlinkInput

    xor a
    ldh [STATE_TRANSITION], a

PollResultRecordBlinkInput:
    call WaitVBlank
    call ReadJoypad
    pop hl
    pop bc
    ldh a, [JOYPAD_PRESSED]
    and PADF_ANY_BUTTON
    jr z, BlinkResultRecordLabelLoop

    ret


FillResultRecordPlaceholderColumn::
    ld de, RESULT_RECORD_ROW_STRIDE
    ld c, RESULT_RECORD_ROW_COUNT

FillResultRecordPlaceholderColumnLoop:
    ld [hl], RESULT_RECORD_PLACEHOLDER_TILE
    add hl, de
    dec c
    jr nz, FillResultRecordPlaceholderColumnLoop

    ret


CompareResultRecordBytes::
    push hl

CompareResultRecordBytesLoop:
    ld a, [de]
    inc de
    ld b, a
    ld a, [hl+]
    cp b
    jr nz, ReturnResultRecordByteCompare

    dec c
    jr nz, CompareResultRecordBytesLoop

ReturnResultRecordByteCompare:
    pop hl
    ret


DrawStoredResultRecords::
    ld hl, RESULT_RECORD_VALUE_TOP_LEFT
    ld b, RESULT_RECORD_ROW_COUNT

DrawStoredResultRecordLoop:
    ld a, [de]
    inc a
    ret z

    ld c, RESULT_RECORD_SCORE_DIGIT_COUNT
    ld a, RESULT_RECORD_SUPPRESS_LEADING_ZEROES
    call DrawResultRecordDigitRun
    inc hl
    inc hl
    ld c, RESULT_RECORD_LEVEL_DIGIT_COUNT
    ld a, RESULT_RECORD_SUPPRESS_LEADING_ZEROES
    call DrawResultRecordDigitRun
    inc hl
    ld a, [GAME_TYPE]
    and a
    jr nz, DrawStoredBTypeResultDetail

    inc hl
    ld c, RESULT_RECORD_A_TYPE_DETAIL_DIGIT_COUNT
    ld a, RESULT_RECORD_SUPPRESS_LEADING_ZEROES
    call DrawResultRecordDigitRun
    inc de
    inc hl
    jr AdvanceStoredResultRecordRow

DrawStoredBTypeResultDetail:
    ld c, RESULT_RECORD_B_TYPE_TIMER_PAIR_DIGIT_COUNT
    ld a, RESULT_RECORD_SUPPRESS_LEADING_ZEROES
    call DrawResultRecordDigitRun
    ld a, RESULT_RECORD_TIMER_SEPARATOR_TILE
    ld [hl+], a
    ld c, RESULT_RECORD_B_TYPE_TIMER_PAIR_DIGIT_COUNT
    ld a, RESULT_RECORD_SHOW_LEADING_ZEROES
    call DrawResultRecordDigitRun

AdvanceStoredResultRecordRow:
    push de
    ld de, RESULT_RECORD_NEXT_RENDER_ROW_DELTA
    add hl, de
    pop de
    dec b
    jr nz, DrawStoredResultRecordLoop

    ret


DrawResultRecordDigitRun::
    push bc
    ldh [UI_SCRATCH], a

DrawResultRecordDigitRunLoop:
    ld a, [de]
    and RESULT_RECORD_DIGIT_MASK
    and a
    jr nz, DrawResultRecordNonzeroDigit

    ldh a, [UI_SCRATCH]
    and a
    jr z, DrawResultRecordNonzeroDigit

    ld a, c
    cp RESULT_RECORD_FINAL_DIGIT_REMAINING
    jr nz, AdvanceSuppressedResultRecordDigit

    ld a, RESULT_RECORD_DIGIT_TILE_BASE
    ld [hl], a

AdvanceSuppressedResultRecordDigit:
    inc hl
    jr AdvanceResultRecordDigitRun

DrawResultRecordNonzeroDigit:
    ld b, a
    xor a
    ldh [UI_SCRATCH], a
    ld a, b
    and RESULT_RECORD_DIGIT_MASK
    add RESULT_RECORD_DIGIT_TILE_BASE
    ld [hl+], a

AdvanceResultRecordDigitRun:
    inc de
    dec c
    jr nz, DrawResultRecordDigitRunLoop

    pop bc
    ret


FillResultRecordBoxRow::
    ld [hl+], a
    ld b, RESULT_RECORD_BOX_ROW_INNER_WIDTH
    ld a, d

FillResultRecordBoxRowMiddleLoop:
    ld [hl+], a
    dec b
    jr nz, FillResultRecordBoxRowMiddleLoop

    ld a, e
    ld [hl+], a
    ret


FadeInResultRecordPalette::
    ld hl, ResultRecordPaletteSequence
    ld b, RESULT_RECORD_PALETTE_FADE_STEP_COUNT

FadeInResultRecordPaletteLoop:
    ld a, [hl+]
    ldh [rBGP], a
    ld c, RESULT_RECORD_PALETTE_FADE_WAIT_FRAMES
    call WaitVBlankFrames
    dec b
    jr nz, FadeInResultRecordPaletteLoop

    ret


MACRO RESULT_RECORD_PALETTE_FADE_STEP
    db \1
ENDM

ResultRecordPaletteSequence::
    RESULT_RECORD_PALETTE_FADE_STEP RESULT_RECORD_PALETTE_FADE_VALUE_0
    RESULT_RECORD_PALETTE_FADE_STEP RESULT_RECORD_PALETTE_FADE_VALUE_1
    RESULT_RECORD_PALETTE_FADE_STEP RESULT_RECORD_PALETTE_FADE_VALUE_2
    RESULT_RECORD_PALETTE_FADE_STEP RESULT_RECORD_PALETTE_FADE_VALUE_3

InitPreplayBlinkTimer::
    ld a, SETTINGS_BLINK_PERIOD
    ld [SETTINGS_BLINK_TIMER], a
    ret


Init1PPreplayScreen::
    call Draw1PPreplayBackground
    call Draw1PPreplayHeaderText
    call Draw1PPreplayGameTypeLabel
    call Draw1PPreplayLevelLabel
    call Draw1PPreplaySpeedLabel
    call Draw1PPreplayBgmLabel
    call Draw1PPreplayLevelText
    call Draw1PPreplaySpeedText
    call Draw1PPreplayGameTypeText
    call Draw1PPreplayBgmOffText
    call Draw1PPreplayBgmMarker
    call ApplySettings
    call ResetSettings
    ld a, SND_BGM_OPTION0
    ld [BGM_INDEX], a
    ret


Draw1PPreplayScreen::
    call Draw1PPreplayGameTypeLabel
    call Draw1PPreplayLevelLabel
    call Draw1PPreplaySpeedLabel
    call Draw1PPreplayBgmLabel
    call Draw1PPreplayGameTypeText
    call Draw1PPreplayLevelText
    call Draw1PPreplaySpeedText
    call Draw1PPreplayBgmMarker
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
    call ClearSettingsCursorFrameHighBits
    pop af
    bit PADB_START, a
    jr z, Handle1PPreplayNonStartInput

    call InitGameState
    ld a, GAME_STATE_PLAY_SETUP
    ldh [GAME_STATE], a
    ret


Handle1PPreplayNonStartInput:
    bit PADB_UP, a
    jr nz, Move1PPreplayCursorUp

    bit PADB_DOWN, a
    jr nz, Move1PPreplayCursorDown

    bit PADB_RIGHT, a
    jr nz, Increment1PPreplaySelectedOption

    bit PADB_LEFT, a
    jr nz, Decrement1PPreplaySelectedOption

    ret


Move1PPreplayCursorUp:
    ld a, [MENU_CURSOR]
    and a
    ret z

    ld hl, MENU_CURSOR
    dec [hl]
    ret


Move1PPreplayCursorDown:
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_BGM
    ret z

    ld hl, MENU_CURSOR
    inc [hl]
    ret


Increment1PPreplaySelectedOption:
    ld hl, OPTION_GAME_TYPE
    ld a, [MENU_CURSOR]
    call GetArrayElement
    inc a
    ld b, a
    push hl
    ld hl, PreplayLoopOptionCountTable
    ld a, [MENU_CURSOR]
    call GetArrayElement
    cp b
    pop hl
    ret z

    inc [hl]
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_BGM
    ret nz

    call ApplyGameSettings
    ret


PreplayLoopOptionCountTable::
    PREPLAY_OPTION_COUNT_ENTRY OPTION_GAME_TYPE_OPTION_COUNT
    PREPLAY_OPTION_COUNT_ENTRY OPTION_LEVEL_OPTION_COUNT
    PREPLAY_OPTION_COUNT_ENTRY OPTION_SPEED_OPTION_COUNT
    PREPLAY_OPTION_COUNT_ENTRY OPTION_BGM_OPTION_COUNT

Decrement1PPreplaySelectedOption:
    ld a, [MENU_CURSOR]
    ld hl, OPTION_GAME_TYPE
    call GetArrayElement
    and a
    ret z

    dec [hl]
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_BGM
    ret nz

    call ApplyGameSettings
    ret


Draw1PPreplayBackground::
    ld hl, PREPLAY_1P_BACKGROUND_TOP_LEFT
    ld bc, PREPLAY_1P_BACKGROUND_RECT_SIZE
    ld a, PREPLAY_1P_BACKGROUND_TILE
    call FillTilemapRectByCoord
    ld hl, PREPLAY_1P_GAME_TYPE_PANEL_TOP_LEFT
    ld bc, PREPLAY_1P_GAME_TYPE_PANEL_RECT_SIZE
    ld a, PREPLAY_1P_PANEL_CLEAR_TILE
    call FillTilemapRectByCoord
    ld hl, PREPLAY_1P_LEVEL_PANEL_TOP_LEFT
    ld bc, PREPLAY_1P_LEVEL_PANEL_RECT_SIZE
    ld a, PREPLAY_1P_PANEL_CLEAR_TILE
    call FillTilemapRectByCoord
    ld hl, PREPLAY_1P_SPEED_PANEL_TOP_LEFT
    ld bc, PREPLAY_1P_SPEED_PANEL_RECT_SIZE
    ld a, PREPLAY_1P_PANEL_CLEAR_TILE
    call FillTilemapRectByCoord
    ld hl, PREPLAY_1P_BGM_PANEL_TOP_LEFT
    ld bc, PREPLAY_1P_BGM_PANEL_RECT_SIZE
    ld a, PREPLAY_1P_PANEL_CLEAR_TILE
    call FillTilemapRectByCoord
    ret


Draw1PPreplayHeaderText::
    ld hl, HeaderLogo
    ld de, ResultHeaderText
    call DrawStringToGrid
    ret


MACRO PREPLAY_HEADER_TEXT_ROW_START_8
    db \1, \2, \3, \4, \5, \6, \7, \8
ENDM

MACRO PREPLAY_HEADER_TEXT_ROW_END_4
    db \1, \2, \3, \4, DRAW_STRING_ROW_END
ENDM

MACRO PREPLAY_HEADER_TEXT_ROW_END_5
    db \1, \2, \3, \4, \5, DRAW_STRING_ROW_END
ENDM

ResultHeaderText::
    PREPLAY_HEADER_TEXT_ROW_START_8 PREPLAY_HEADER_TEXT_TILE_1, OPTION_TEXT_TILE_SPACE, OPTION_TEXT_TILE_P, OPTION_TEXT_TILE_L, OPTION_TEXT_TILE_A, OPTION_TEXT_TILE_Y, OPTION_TEXT_TILE_E, OPTION_TEXT_TILE_R
    PREPLAY_HEADER_TEXT_ROW_END_5 OPTION_TEXT_TILE_SPACE, OPTION_TEXT_TILE_G, OPTION_TEXT_TILE_A, OPTION_TEXT_TILE_M, OPTION_TEXT_TILE_E
    PREPLAY_HEADER_TEXT_ROW_START_8 OPTION_TEXT_TILE_SPACE, OPTION_TEXT_TILE_Y, OPTION_TEXT_TILE_O, OPTION_TEXT_TILE_S, OPTION_TEXT_TILE_S, OPTION_TEXT_TILE_Y, OPTION_TEXT_TILE_SPACE, OPTION_TEXT_TILE_E
    PREPLAY_HEADER_TEXT_ROW_END_4 OPTION_TEXT_TILE_G, OPTION_TEXT_TILE_G, OPTION_TEXT_TILE_S, OPTION_TEXT_TILE_SPACE

Draw1PPreplaySpeedText::
    ld hl, PREPLAY_1P_SPEED_TEXT_COORD
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_SPEED
    jr nz, Select1PPreplaySpeedTextByOption

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, Select1PPreplaySpeedTextByOption

    ld de, ResultTextBlock2
    jr Draw1PPreplaySpeedTextLines

Select1PPreplaySpeedTextByOption:
    ld a, [OPTION_SPEED]
    and a
    jr nz, Use1PPreplayHighSpeedText

    ld de, ResultTextBlock0
    jr Draw1PPreplaySpeedTextLines

Use1PPreplayHighSpeedText:
    ld de, ResultTextBlock1

Draw1PPreplaySpeedTextLines:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


Draw1PPreplayLevelLabel::
    ld hl, PREPLAY_1P_LEVEL_LABEL_COORD
    call Draw1PPreplayLevelLabelAtCoord
    ret


Draw1PPreplayLevelLabelAtCoord::
    ld b, PREPLAY_LABEL_TILE_ROW_WIDTH
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_LEVEL
    jr z, UseSelected1PPreplayLevelLabelTiles

    ld bc, PREPLAY_LEVEL_LABEL_TILE_ROW
    jr Draw1PPreplayLevelLabelTiles

UseSelected1PPreplayLevelLabelTiles:
    ld bc, PREPLAY_LEVEL_LABEL_SELECTED_TILE_ROW

Draw1PPreplayLevelLabelTiles:
    call DrawSequentialTileRowByCoord
    ret


Draw1PPreplayBgmLabel::
    ld hl, PREPLAY_1P_BGM_LABEL_COORD
    call Draw1PPreplayBgmLabelAtCoord
    ret


Draw1PPreplayBgmLabelAtCoord::
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_BGM
    jr z, UseSelected1PPreplayBgmLabelTiles

    ld bc, PREPLAY_1P_BGM_LABEL_TILE_ROW
    jr Draw1PPreplayBgmLabelTiles

UseSelected1PPreplayBgmLabelTiles:
    ld bc, PREPLAY_1P_BGM_LABEL_SELECTED_TILE_ROW

Draw1PPreplayBgmLabelTiles:
    call DrawSequentialTileRowByCoord
    ret


Draw1PPreplaySpeedLabel::
    ld hl, PREPLAY_1P_SPEED_LABEL_COORD
    call Draw1PPreplaySpeedLabelAtCoord
    ret


Draw1PPreplaySpeedLabelAtCoord::
    ld b, PREPLAY_LABEL_TILE_ROW_WIDTH
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_SPEED
    jr z, UseSelected1PPreplaySpeedLabelTiles

    ld bc, PREPLAY_SPEED_LABEL_TILE_ROW
    jr Draw1PPreplaySpeedLabelTiles

UseSelected1PPreplaySpeedLabelTiles:
    ld bc, PREPLAY_SPEED_LABEL_SELECTED_TILE_ROW

Draw1PPreplaySpeedLabelTiles:
    call DrawSequentialTileRowByCoord
    ret


Draw1PPreplayGameTypeLabel::
    ld hl, PREPLAY_1P_GAME_TYPE_LABEL_COORD
    ld b, PREPLAY_LABEL_TILE_ROW_WIDTH
    ld a, [MENU_CURSOR]
    and a
    jr z, UseSelected1PPreplayGameTypeLabelTiles

    ld bc, PREPLAY_1P_GAME_TYPE_LABEL_TILE_ROW
    jr Draw1PPreplayGameTypeLabelTiles

UseSelected1PPreplayGameTypeLabelTiles:
    ld bc, PREPLAY_1P_GAME_TYPE_LABEL_SELECTED_TILE_ROW

Draw1PPreplayGameTypeLabelTiles:
    call DrawSequentialTileRowByCoord
    ret


Draw1PPreplayLevelText::
    ld a, PREPLAY_1P_LEVEL_TEXT_ROW
    ld [ANIM_FRAME], a
    ld a, PREPLAY_1P_LEVEL_TEXT_COL
    ld [STATE_TRANSITION], a
    ld a, [OPTION_LEVEL]
    call Draw1PPreplayLevelTextAtIndex
    ret


Draw1PPreplayLevelTextAtIndex::
    ldh [UI_SCRATCH], a
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_LEVEL
    jr nz, Select1PPreplayLevelTextByOption

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, Select1PPreplayLevelTextByOption

    ld de, PiecePreviewBlankText
    jr Draw1PPreplayLevelTextLines

Select1PPreplayLevelTextByOption:
    ldh a, [UI_SCRATCH]
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

Draw1PPreplayLevelTextLines:
    ld a, [ANIM_FRAME]
    ld h, a
    ld a, [STATE_TRANSITION]
    ld l, a
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    ret


Draw1PPreplayGameTypeText::
    ld hl, PREPLAY_1P_GAME_TYPE_TEXT_COORD
    ld a, [MENU_CURSOR]
    and a
    jr nz, Select1PPreplayGameTypeTextByOption

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, Select1PPreplayGameTypeTextByOption

    ld de, RestartTextBlock2
    jr Draw1PPreplayGameTypeTextLines

Select1PPreplayGameTypeTextByOption:
    ld a, [OPTION_GAME_TYPE]
    and a
    jr nz, Use1PPreplayBTypeGameText

    ld de, RestartTextBlock0
    jr Draw1PPreplayGameTypeTextLines

Use1PPreplayBTypeGameText:
    ld de, RestartTextBlock1

Draw1PPreplayGameTypeTextLines:
    call DrawStringToGrid
    call DrawStringToGrid
    ret


MACRO PREPLAY_GAME_TYPE_TEXT_ROW_START
    db \1, \2, \3, \4, \5, \6
ENDM

MACRO PREPLAY_GAME_TYPE_TEXT_ROW_END
    db \1, \2, \3, \4, \5, \6, DRAW_STRING_ROW_END
ENDM

RestartTextBlock0::
    PREPLAY_GAME_TYPE_TEXT_ROW_START $f4, $ec, $ed, $ee, $ef, $f5
    PREPLAY_GAME_TYPE_TEXT_ROW_END OPTION_TEXT_TILE_SPACE, $fa, $fd, $fe, $d3, OPTION_TEXT_TILE_SPACE
    PREPLAY_GAME_TYPE_TEXT_ROW_START $f6, $f0, $f1, $f2, $f3, $f7
    PREPLAY_GAME_TYPE_TEXT_ROW_END OPTION_TEXT_TILE_SPACE, $fb, $0d, $1c, $1d, OPTION_TEXT_TILE_SPACE
RestartTextBlock1::
    PREPLAY_GAME_TYPE_TEXT_ROW_START OPTION_TEXT_TILE_SPACE, $fc, $fd, $fe, $d3, OPTION_TEXT_TILE_SPACE
    PREPLAY_GAME_TYPE_TEXT_ROW_END $f4, $f8, $ed, $ee, $ef, $f5
    PREPLAY_GAME_TYPE_TEXT_ROW_START OPTION_TEXT_TILE_SPACE, $0c, $0d, $1c, $1d, OPTION_TEXT_TILE_SPACE
    PREPLAY_GAME_TYPE_TEXT_ROW_END $f6, $f9, $f1, $f2, $f3, $f7
RestartTextBlock2::
    PREPLAY_GAME_TYPE_TEXT_ROW_START OPTION_TEXT_TILE_SPACE, $fc, $fd, $fe, $d3, OPTION_TEXT_TILE_SPACE
    PREPLAY_GAME_TYPE_TEXT_ROW_END OPTION_TEXT_TILE_SPACE, $fa, $fd, $fe, $d3, OPTION_TEXT_TILE_SPACE
    PREPLAY_GAME_TYPE_TEXT_ROW_START OPTION_TEXT_TILE_SPACE, $0c, $0d, $1c, $1d, OPTION_TEXT_TILE_SPACE
    PREPLAY_GAME_TYPE_TEXT_ROW_END OPTION_TEXT_TILE_SPACE, $fb, $0d, $1c, $1d, OPTION_TEXT_TILE_SPACE

Draw1PPreplayBgmOffText::
    ld hl, PREPLAY_1P_BGM_OFF_TEXT_COORD
    ld de, ContinueOffText
    call DrawStringToGrid
    ret


ContinueOffText::
    OPTION_TEXT_ROW_3 OPTION_TEXT_TILE_O, OPTION_TEXT_TILE_F, OPTION_TEXT_TILE_F

Draw1PPreplayBgmMarker::
    ld hl, PREPLAY_1P_BGM_MARKER_COORD
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_BGM
    jr nz, Select1PPreplayBgmMarkerByOption

    ld a, [OPTION_BGM]
    cp OPTION_BGM_OFF_VALUE
    jr nz, Select1PPreplayBgmMarkerByOption

    ld a, [SETTINGS_BLINK_PHASE]
    and a
    jr z, Select1PPreplayBgmMarkerByOption

    ld de, BgmMarkerNoneText
    jr Draw1PPreplayBgmMarkerText

Select1PPreplayBgmMarkerByOption:
    ld a, [OPTION_BGM]
    and a
    jr z, Use1PPreplayBgmMarker0Text

    cp OPTION_BGM_VALUE_1
    jr z, Use1PPreplayBgmMarker1Text

    cp OPTION_BGM_VALUE_2
    jr z, Use1PPreplayBgmMarker2Text

    ld de, BgmMarker3Text
    jr Draw1PPreplayBgmMarkerText

Use1PPreplayBgmMarker2Text:
    ld de, BgmMarker2Text
    jr Draw1PPreplayBgmMarkerText

Use1PPreplayBgmMarker0Text:
    ld de, BgmMarker0Text
    jr Draw1PPreplayBgmMarkerText

Use1PPreplayBgmMarker1Text:
    ld de, BgmMarker1Text

Draw1PPreplayBgmMarkerText:
    call DrawStringToGrid
    ret


MACRO PREPLAY_BGM_MARKER_TEXT
    REPT \1
        db OPTION_MARKER_BLANK_TILE
    ENDR
    db OPTION_MARKER_SELECTED_TILE
    REPT PREPLAY_BGM_MARKER_TEXT_WIDTH - \1 - $01
        db OPTION_MARKER_BLANK_TILE
    ENDR
    db DRAW_STRING_ROW_END
ENDM

MACRO PREPLAY_BGM_MARKER_NONE_TEXT
    REPT PREPLAY_BGM_MARKER_TEXT_WIDTH
        db OPTION_MARKER_BLANK_TILE
    ENDR
    db DRAW_STRING_ROW_END
ENDM

BgmMarker0Text::
    PREPLAY_BGM_MARKER_TEXT PREPLAY_BGM_MARKER_OPTION0_OFFSET
BgmMarker1Text::
    PREPLAY_BGM_MARKER_TEXT PREPLAY_BGM_MARKER_OPTION1_OFFSET
BgmMarker2Text::
    PREPLAY_BGM_MARKER_TEXT PREPLAY_BGM_MARKER_OPTION2_OFFSET
BgmMarker3Text::
    PREPLAY_BGM_MARKER_TEXT PREPLAY_BGM_MARKER_OFF_OFFSET
BgmMarkerNoneText::
    PREPLAY_BGM_MARKER_NONE_TEXT
    ld b, PREPLAY_LABEL_TILE_ROW_WIDTH
    ld a, [MENU_CURSOR]
    and a
    jr z, UseSelectedDetachedPreplayLabelTiles

    ld bc, PREPLAY_LEVEL_LABEL_TILE_ROW
    jr DrawDetachedPreplayLabelTiles

UseSelectedDetachedPreplayLabelTiles:
    ld bc, PREPLAY_LEVEL_LABEL_SELECTED_TILE_ROW

DrawDetachedPreplayLabelTiles:
    call DrawSequentialTileRowByCoord
    ret


TickSettingsBlink::
    ld hl, SETTINGS_BLINK_TIMER
    dec [hl]
    ret nz

    ld a, SETTINGS_BLINK_PERIOD
    ld [hl], a
    ld a, [SETTINGS_BLINK_PHASE]
    xor SETTINGS_BLINK_PHASE_TOGGLE_MASK
    ld [SETTINGS_BLINK_PHASE], a
    ret


ClearSettingsCursorFrameHighBits::
    ld hl, SPRITE_OBJECT_SLOT_9 + SPRITE_OBJECT_FRAME
    ld de, SPRITE_OBJECT_SLOT_SIZE
    ld b, SETTINGS_CURSOR_OBJECT_COUNT

ClearSettingsCursorFrameHighBitsLoop:
    ld a, [hl]
    and SETTINGS_CURSOR_FRAME_LOW_MASK
    ld [hl], a
    add hl, de
    dec b
    jr nz, ClearSettingsCursorFrameHighBitsLoop

    ret


UpdateCountdownTimer::
    ld a, [COUNTDOWN_BLIT_TIMER]
    and a
    ret z

    ld a, [COUNTDOWN_BLIT_PHASE]
    xor COUNTDOWN_BLIT_PHASE_TOGGLE_MASK
    ld [COUNTDOWN_BLIT_PHASE], a
    jr nz, BuildCountdownPhase1DigitBuffers

    ld a, [SCORE_BCD_MID]
    swap a
    and COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK
    srl a
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, CopyCountdownPhase0Buffer2LeftPattern

    inc d

CopyCountdownPhase0Buffer2LeftPattern:
    ld hl, COUNTDOWN_DIGIT_BUFFER_2
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

CopyCountdownPhase0Buffer2LeftLoop:
    ld a, [de]
    inc de
    swap a
    and COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK
    ld [hl+], a
    dec b
    jr nz, CopyCountdownPhase0Buffer2LeftLoop

    ld a, [SCORE_BCD_LOW]
    and COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK
    srl a
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, MergeCountdownPhase0Buffer2RightPattern

    inc d

MergeCountdownPhase0Buffer2RightPattern:
    ld hl, COUNTDOWN_DIGIT_BUFFER_2
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

MergeCountdownPhase0Buffer2RightLoop:
    ld a, [de]
    inc de
    srl a
    srl a
    or [hl]
    ld [hl+], a
    dec b
    jr nz, MergeCountdownPhase0Buffer2RightLoop

    ld a, [SCORE_BCD_LOW]
    swap a
    and COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK
    srl a
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, CopyCountdownPhase0Buffer3Pattern

    inc d

CopyCountdownPhase0Buffer3Pattern:
    ld hl, COUNTDOWN_DIGIT_BUFFER_3
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

CopyCountdownPhase0Buffer3Loop:
    ld a, [de]
    inc de
    ld [hl+], a
    dec b
    jr nz, CopyCountdownPhase0Buffer3Loop

    ret


BuildCountdownPhase1DigitBuffers:
    ld a, [SCORE_BCD_MID]
    swap a
    and COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK
    srl a
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, CopyCountdownPhase1Buffer1LeftPattern

    inc d

CopyCountdownPhase1Buffer1LeftPattern:
    ld hl, COUNTDOWN_DIGIT_BUFFER_1
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

CopyCountdownPhase1Buffer1LeftLoop:
    ld a, [de]
    inc de
    swap a
    and COUNTDOWN_PATTERN_LOW_NIBBLE_MASK
    ld [hl+], a
    dec b
    jr nz, CopyCountdownPhase1Buffer1LeftLoop

    ld a, [SCORE_BCD_MID]
    and COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK
    srl a
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, MergeCountdownPhase1Buffer1RightPattern

    inc d

MergeCountdownPhase1Buffer1RightPattern:
    ld hl, COUNTDOWN_DIGIT_BUFFER_1
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS

MergeCountdownPhase1Buffer1RightLoop:
    ld a, [de]
    inc de
    sla a
    sla a
    rl c
    or [hl]
    ld [hl+], a
    dec b
    jr nz, MergeCountdownPhase1Buffer1RightLoop

    ld a, [SCORE_BCD_HIGH]
    swap a
    and COUNTDOWN_PATTERN_HIGH_NIBBLE_MASK
    srl a
    ld de, CountdownDigitPatternTable
    add e
    ld e, a
    jr nc, CopyCountdownPhase1Buffer0Pattern

    inc d

CopyCountdownPhase1Buffer0Pattern:
    ld hl, COUNTDOWN_DIGIT_BUFFER_0
    ld b, COUNTDOWN_DIGIT_BUFFER_ROWS
    sla c

CopyCountdownPhase1Buffer0Loop:
    ld a, [de]
    inc de
    sla c
    jr nc, StoreCountdownPhase1Buffer0Row

    or COUNTDOWN_PHASE1_SPILL_PIXEL_MASK

StoreCountdownPhase1Buffer0Row:
    ld [hl+], a
    dec b
    jr nz, CopyCountdownPhase1Buffer0Loop

    ret


RandomNext::
    ld a, [COUNTDOWN_BLIT_TIMER]
    and a
    ret z

    dec a
    ld [COUNTDOWN_BLIT_TIMER], a
    ld a, [COUNTDOWN_BLIT_PHASE]
    and a
    jr nz, BlitCountdownPhase1DigitBuffers

    ld de, COUNTDOWN_DIGIT_BUFFER_2
    ld hl, COUNTDOWN_BLIT_DEST_PHASE0
    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

BlitCountdownPhase0Buffer2Loop:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, BlitCountdownPhase0Buffer2Loop

    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

BlitCountdownPhase0Buffer3Loop:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, BlitCountdownPhase0Buffer3Loop

    ret


BlitCountdownPhase1DigitBuffers:
    ld de, COUNTDOWN_DIGIT_BUFFER_0
    ld hl, COUNTDOWN_BLIT_DEST_PHASE1
    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

BlitCountdownPhase1Buffer0Loop:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, BlitCountdownPhase1Buffer0Loop

    ld b, COUNTDOWN_DIGIT_BUFFER_BYTES

BlitCountdownPhase1Buffer1Loop:
    ld a, [de]
    inc de
    ld [hl+], a
    ld [hl+], a
    dec b
    jr nz, BlitCountdownPhase1Buffer1Loop

    ret


MACRO COUNTDOWN_DIGIT_PATTERN
    db \1, \2, \3, \4, \5, \6, \7, \8
ENDM

CountdownDigitPatternTable::
CountdownDigitPattern0::
    COUNTDOWN_DIGIT_PATTERN $38, $6c, $6c, $6c, $6c, $6c, $38, $00
CountdownDigitPattern1::
    COUNTDOWN_DIGIT_PATTERN $38, $18, $18, $18, $18, $18, $18, $00
CountdownDigitPattern2::
    COUNTDOWN_DIGIT_PATTERN $78, $0c, $0c, $38, $60, $60, $7c, $00
CountdownDigitPattern3::
    COUNTDOWN_DIGIT_PATTERN $78, $0c, $0c, $38, $0c, $0c, $78, $00
CountdownDigitPattern4::
    COUNTDOWN_DIGIT_PATTERN $6c, $6c, $6c, $6c, $7c, $0c, $0c, $00
CountdownDigitPattern5::
    COUNTDOWN_DIGIT_PATTERN $7c, $60, $60, $7c, $0c, $0c, $78, $00
CountdownDigitPattern6::
    COUNTDOWN_DIGIT_PATTERN $38, $60, $60, $78, $6c, $6c, $38, $00
CountdownDigitPattern7::
    COUNTDOWN_DIGIT_PATTERN $7c, $0c, $08, $18, $18, $30, $30, $00
CountdownDigitPattern8::
    COUNTDOWN_DIGIT_PATTERN $38, $6c, $6c, $38, $6c, $6c, $38, $00
CountdownDigitPattern9::
    COUNTDOWN_DIGIT_PATTERN $38, $6c, $6c, $6c, $3c, $0c, $38, $00

ProcessRoundComplete::
    ld hl, SPRITE_OBJECT_SLOT_10
    ld de, SPRITE_OBJECT_SLOT_SIZE
    xor a
    ld b, a

InitRoundCompleteTileSlotsFromBaseLoop:
    ld [hl], SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE
    push hl
    inc l
    inc l
    ld [hl], b
    inc l
    inc l
    ld a, [ROUND_COMPLETE_TILE_BASE_Y]
    ld [hl], a
    inc l
    inc l
    ld a, [ROUND_COMPLETE_TILE_BASE_X]
    ld [hl], a
    pop hl
    add hl, de
    inc b
    ld a, ROUND_COMPLETE_TILE_SLOT_COUNT

    cp b
    jr nz, InitRoundCompleteTileSlotsFromBaseLoop

    ld a, FIELD_ANIM_ACTIVE_VALUE
    ld [FIELD_ANIM_SLOT_11_ACTIVE], a
    ld [FIELD_ANIM_SLOT_10_ACTIVE], a
    ld [FIELD_ANIM_SLOT_13_ACTIVE], a
    ld [FIELD_ANIM_SLOT_12_ACTIVE], a
    ld a, SND_ROUND_COMPLETE
    call PlaySound
    ret


DrawSinglePlayerRoundEndRanking:
    call DrawScoreRanking
    jr WaitRoundEndSoundFinishedLoop

HandleRoundEnd::
    call Draw1PCountdownDigitTileSlots
    ld a, [TWO_PLAYER_FLAG]
    and a

    jr z, DrawSinglePlayerRoundEndRanking

    call DrawScoreRanking
    ld hl, ROUND_END_WAIT_TIMER
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

    jr ContinueRoundEndFlow

WaitRoundEndSoundFinishedLoop:
    ld a, [SOUND_CH_ACTIVE_ID]
    and a
    jr nz, WaitRoundEndSoundFinishedLoop

ContinueRoundEndFlow:
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, WaitSinglePlayerRoundEndDelay

    xor a
    ldh [SERIAL_DONE], a
    ld [LINK_SEND], a
    ld a, ROUND_END_RESULT_DELAY_FRAMES
    ldh [VBLANK_BUSY], a

WaitTwoPlayerRoundEndDelayLoop:
    ldh a, [VBLANK_BUSY]
    and a
    jr nz, WaitTwoPlayerRoundEndDelayLoop

    jr ContinueRoundEndAfterDelay

WaitSinglePlayerRoundEndDelay:
    ld a, ROUND_END_RESULT_DELAY_FRAMES
    ldh [VBLANK_BUSY], a

WaitSinglePlayerRoundEndDelayLoop:
    ldh a, [VBLANK_BUSY]
    and a
    jr nz, WaitSinglePlayerRoundEndDelayLoop

ContinueRoundEndAfterDelay:
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, HandleSinglePlayerRoundCompleteFlow

    ldh a, [UI_SCRATCH]
    call UpdateLinkResultMarksAndScreen
    jr c, ReturnRoundEndToTitle

    ld hl, ACTIVE_LEVEL
    call StartNextRound
    ld a, GAME_STATE_PLAYING
    ld [GAME_STATE], a
    ret

HandleSinglePlayerRoundCompleteFlow:
    ld a, [GAME_TYPE]
    and a

    jr nz, HandleBTypeRoundEndFlow

    call ShowATypeRoundCompleteSummary
    jr ClearRoundEndSpriteObjectsAndRecord

HandleBTypeRoundEndFlow:
    ld a, [RESULT_RANK_POSITION]
    and a
    jr z, ClearRoundEndSpriteObjectsAndRecord

    ld a, [PROGRESSION_LEVEL]
    call ProcessMatching
    call StartNextRound
    ld a, GAME_STATE_PLAYING
    ld [GAME_STATE], a
    ret


ClearRoundEndSpriteObjectsAndRecord:
    push af
    xor a
    ld hl, SPRITE_OBJECTS
    ld b, ROUND_END_SPRITE_OBJECT_CLEAR_BYTES

ClearRoundEndSpriteObjectsLoop:
    ld [hl+], a
    dec b
    jr nz, ClearRoundEndSpriteObjectsLoop

    call ProcessCurrentResultRecordAndSetupScreen
    pop af

ReturnRoundEndToTitle:
    ld a, GAME_STATE_TITLE_INIT
    ld [GAME_STATE], a
    ld hl, RESULT_FLOW_ACTIVE
    ld [hl], RESULT_FLOW_INACTIVE
    ret


DrawScoreRanking::
    ld hl, RESULT_RANK_TOP_COORD
    ld b, RESULT_RANK_TILE_RUN_LENGTH
    ld a, [RESULT_RANK_POSITION]
    cp RESULT_RANK_SPECIAL_POSITION_CODE
    jr nz, NormalizeRankTopTileIndex

    ld a, RESULT_RANK_FIRST_PLACE

NormalizeRankTopTileIndex:
    swap a
    add RESULT_RANK_TOP_TILE_BASE
    call DrawRankEntry
    ld hl, RESULT_RANK_BOTTOM_COORD
    ld b, RESULT_RANK_TILE_RUN_LENGTH
    ld a, [RESULT_RANK_POSITION]
    cp RESULT_RANK_SPECIAL_POSITION_CODE
    jr nz, NormalizeRankBottomTileIndex

    ld a, RESULT_RANK_FIRST_PLACE

NormalizeRankBottomTileIndex:
    swap a
    add RESULT_RANK_BOTTOM_TILE_BASE
    call DrawRankEntry
    ret


ProcessRoundResultAndEnterRoundEnd::
    ldh [UI_SCRATCH], a
    call Exchange2PResultCode
    ldh a, [UI_SCRATCH]
    call ResolveResultRankPosition
    ldh [UI_SCRATCH], a
    push af
    push bc
    push hl
    ld hl, SPRITE_OBJECT_SLOT_10
    xor a
    ld b, ROUND_COMPLETE_OBJECT_SLOT_CLEAR_BYTES

ClearRoundCompleteObjectSlotsLoop:
    ld [hl+], a
    dec b
    jr nz, ClearRoundCompleteObjectSlotsLoop

    ld a, RESULT_FLAG_SET
    ld [ROUND_TIMER_STOPPED], a
    ld [TOTAL_TIMER_STOPPED], a
    pop hl
    pop bc
    pop af
    ld hl, RESULT_FLOW_ACTIVE
    ld [hl], RESULT_FLAG_SET
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, HandleSinglePlayerRoundResult

    ldh a, [UI_SCRATCH]
    ld [RESULT_RANK_POSITION], a
    and a
    jr z, Play2PZeroResultSound

    ld a, SND_RESULT_2P_NONZERO_RANK
    call PlaySound
    jr Finish2PRoundResult

Play2PZeroResultSound:
    ld a, SND_RESULT_2P_ZERO_RANK
    call PlaySound

Finish2PRoundResult:
    jr EnterRoundEndState

HandleSinglePlayerRoundResult:
    ldh a, [UI_SCRATCH]
    ld [RESULT_RANK_POSITION], a
    and a
    jr z, PlaySinglePlayerNoRankResultSound

    ld a, SND_STOP_ALL
    call PlaySound
    ld a, SND_RESULT_1P_RANKED
    call PlaySound
    call DrawScoreRanking
    jr EnterRoundEndState

PlaySinglePlayerNoRankResultSound:
    ld a, SND_STOP_ALL
    call PlaySound
    ld a, SND_RESULT_1P_NO_RANK
    call PlaySound

EnterRoundEndState:
    ld hl, ROUND_END_WAIT_TIMER
    ld a, ROUND_END_WAIT_INITIAL_FRAMES
    ld [hl+], a
    ld [hl], ROUND_END_WAIT_INITIAL_FRAMES_HI
    ld a, GAME_STATE_ROUND_END
    ld [GAME_STATE], a
    ret


DrawRankEntry::
    ld c, a
    call CalcTilemapAddress
    ld a, c

DrawRankEntryTileRunLoop:
    ld [hl+], a
    inc a
    dec b
    jr nz, DrawRankEntryTileRunLoop

    ret


WaitStartPressedLoop:
    call WaitVBlank
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and PADF_START
    jr z, WaitStartPressedLoop

    ret


QueueRoundResult::
    ld [ROUND_RESULT_CODE], a
    ld a, RESULT_FLAG_SET
    ld [ROUND_RESULT_PENDING], a
    ld [RESULT_FLOW_ACTIVE], a
    ret


ResolveResultRankPosition::
    push af
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, ResolveTwoPlayerEqualResultRank

    pop af
    ret


ResolveTwoPlayerEqualResultRank:
    pop af
    ld hl, LINK_PEER_RESULT_CODE
    cp [hl]
    ret nz

    ld a, [LINK_ROLE]
    cp LINK_ROLE_SLAVE
    jr z, ReturnSlaveEqualResultRank

    ; The master owns tied-result resolution and converts it to first place.
    xor a
    ld [ROUND_RESULT_CODE], a
    ld [RESULT_GAME_OVER_FLAG], a
    ld a, RESULT_RANK_FIRST_PLACE
    ret


ReturnSlaveEqualResultRank:
    xor a
    ret


UpdateLinkResultMarksAndScreen::
    ldh [ANIM_FRAME], a
    and a
    ld a, LINK_RESULT_TERMINAL_FLAG_CLEAR
    ldh [STATE_TRANSITION], a
    jr z, IncrementLinkZeroResultMarks

    ld a, [LINK_RESULT_NONZERO_MARKS]
    inc a
    ld [LINK_RESULT_NONZERO_MARKS], a
    jr SetTerminalLinkResultFlagIfMarkLimitReached

IncrementLinkZeroResultMarks:
    ld a, [LINK_RESULT_ZERO_MARKS]
    inc a
    ld [LINK_RESULT_ZERO_MARKS], a

SetTerminalLinkResultFlagIfMarkLimitReached:
    cp LINK_RESULT_MARK_LIMIT
    jr nz, BuildLinkResultScreen

    ld a, RESULT_FLAG_SET
    ldh [STATE_TRANSITION], a

BuildLinkResultScreen:
    xor a
    ld [LCD_REDRAW], a
    call LCDOff
    call ClearOAM
    ld a, ROM_BANK_GRAPHICS_1
    ld [MBC1_ROM_BANK_REG], a
    ld hl, Bank3LinkResultTilesTo9000
    ld de, VRAM_TILE_BLOCK_9000
    ld bc, BANK3_LINK_RESULT_TILE_BLOCK_COPY_SIZE
    call MemcopyCall
    ld hl, Bank3LinkResultTilesTo8800
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK3_LINK_RESULT_TILE_BLOCK_COPY_SIZE
    call MemcopyCall
    ldh a, [STATE_TRANSITION]
    and a
    jr z, SkipTerminalLinkResultOverlayTiles

    ld hl, Bank3LinkResultOverlayTilesTo9470
    ld de, LINK_RESULT_OVERLAY_VRAM_DEST
    ld bc, BANK3_LINK_RESULT_OVERLAY_9470_COPY_SIZE
    call MemcopyCall
    ld hl, Bank3LinkResultOverlayTilesTo8800
    ld de, VRAM_TILE_BLOCK_8800
    ld bc, BANK3_LINK_RESULT_OVERLAY_8800_COPY_SIZE
    call MemcopyCall

SkipTerminalLinkResultOverlayTiles:
    ld hl, BG_MAP_SHADOW
    ld bc, BG_MAP_SHADOW_SIZE
    ld d, LINK_RESULT_BG_CLEAR_TILE
    call FillBytesWithD
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call LCDOn
    ld b, LINK_RESULT_HEADER_MASTER_TILE
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, FillLinkResultLeftHeader

    ld b, LINK_RESULT_HEADER_NONMASTER_TILE

FillLinkResultLeftHeader:
    ld a, b
    ld hl, LINK_RESULT_LEFT_HEADER_TOP_LEFT
    ld bc, LINK_RESULT_HEADER_RECT_SIZE
    call FillRect
    ld b, LINK_RESULT_HEADER_NONMASTER_TILE
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, FillLinkResultRightHeader

    ld b, LINK_RESULT_HEADER_MASTER_TILE

FillLinkResultRightHeader:
    ld a, b
    ld hl, LINK_RESULT_RIGHT_HEADER_TOP_LEFT
    ld bc, LINK_RESULT_HEADER_RECT_SIZE
    call FillRect
    ld b, LINK_RESULT_BADGE_MASTER_TILE
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, FillLinkResultLeftBadge

    ld b, LINK_RESULT_BADGE_NONMASTER_TILE

FillLinkResultLeftBadge:
    ld a, b
    ld hl, LINK_RESULT_LEFT_BADGE_TOP_LEFT
    ld bc, LINK_RESULT_BADGE_RECT_SIZE
    call FillRect
    ld b, LINK_RESULT_BADGE_NONMASTER_TILE
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, FillLinkResultRightBadge

    ld b, LINK_RESULT_BADGE_MASTER_TILE

FillLinkResultRightBadge:
    ld a, b
    ld hl, LINK_RESULT_RIGHT_BADGE_TOP_LEFT
    ld bc, LINK_RESULT_BADGE_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_MARK_EMPTY_TILE
    ld hl, LINK_RESULT_NONZERO_MARK_BASE
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_MARK_EMPTY_TILE
    ld hl, LINK_RESULT_NONZERO_MARK_1
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_MARK_EMPTY_TILE
    ld hl, LINK_RESULT_NONZERO_MARK_2
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_MARK_EMPTY_TILE
    ld hl, LINK_RESULT_ZERO_MARK_2
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_MARK_EMPTY_TILE
    ld hl, LINK_RESULT_ZERO_MARK_1
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_MARK_EMPTY_TILE
    ld hl, LINK_RESULT_ZERO_MARK_BASE
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    ld a, [LINK_RESULT_NONZERO_MARKS]
    and a
    jr z, DrawZeroResultMarksIfAny

    ld c, a
    ld hl, LINK_RESULT_NONZERO_MARK_BASE

DrawFilledNonzeroResultMarksLoop:
    push hl
    push bc
    ld a, LINK_RESULT_MARK_FILLED_TILE
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    pop bc
    pop hl
    inc hl
    inc hl
    dec c
    jr nz, DrawFilledNonzeroResultMarksLoop

DrawZeroResultMarksIfAny:
    ld a, [LINK_RESULT_ZERO_MARKS]
    and a
    jr z, DispatchLinkResultScreenMode

    ld c, a
    ld hl, LINK_RESULT_ZERO_MARK_BASE

DrawFilledZeroResultMarksLoop:
    push hl
    push bc
    ld a, LINK_RESULT_MARK_FILLED_TILE
    ld bc, LINK_RESULT_MARK_RECT_SIZE
    call FillRect
    pop bc
    pop hl
    dec hl
    dec hl
    dec c
    jr nz, DrawFilledZeroResultMarksLoop

DispatchLinkResultScreenMode:
    ldh a, [STATE_TRANSITION]
    and a
    jp z, DrawLinkResultConfirmPanelsAndWait

    ldh a, [ANIM_FRAME]
    and a
    jr z, LoadZeroTerminalLinkResultSound

    ld a, SND_LINK_RESULT_NONZERO
    jr PlayTerminalLinkResultSoundAndClearResultAreas

LoadZeroTerminalLinkResultSound:
    ld a, SND_LINK_RESULT_ZERO

PlayTerminalLinkResultSoundAndClearResultAreas:
    call PlaySound
    xor a
    ldh [SERIAL_DONE], a
    ld [LINK_SEND], a
    ld a, LINK_RESULT_STATUS_CLEAR_TILE
    ld hl, LINK_RESULT_STATUS_TOP_LEFT
    ld bc, LINK_RESULT_STATUS_CLEAR_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_SCORE_CLEAR_TILE
    ld hl, RESULT_SCORE_VALUE_TOP_LEFT
    ld bc, LINK_RESULT_SCORE_CLEAR_RECT_SIZE
    call FillRect
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr nz, DrawNonMasterTerminalLinkResult

    ldh a, [ANIM_FRAME]
    and a
    jr z, DrawMasterZeroTerminalLinkResult

    ld a, LINK_RESULT_OUTCOME_TILE_B
    ld hl, LINK_RESULT_OUTCOME_RIGHT_TOP_LEFT
    ld bc, LINK_RESULT_OUTCOME_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_STATUS_TEXT_TILE_A
    ld hl, LINK_RESULT_BOTTOM_TEXT_TOP_LEFT
    ld bc, LINK_RESULT_STATUS_TEXT_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_WAIT_PANEL_MASTER_ALT_TILE
    ldh [ANIM_SUBFRAME], a
    ld a, LINK_RESULT_WAIT_PANEL_MASTER_BASE_TILE
    ldh [UI_SCRATCH], a
    jr WaitLinkStartConfirm

DrawMasterZeroTerminalLinkResult:
    ld a, LINK_RESULT_OUTCOME_TILE_A
    ld hl, LINK_RESULT_OUTCOME_LEFT_TOP_LEFT
    ld bc, LINK_RESULT_OUTCOME_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_STATUS_TEXT_TILE_B
    ld hl, LINK_RESULT_BOTTOM_TEXT_TOP_LEFT
    ld bc, LINK_RESULT_STATUS_TEXT_RECT_SIZE
    call FillRect
    jp WaitTerminalLinkResultMenuConfirm


DrawNonMasterTerminalLinkResult:
    ldh a, [ANIM_FRAME]
    and a
    jr z, DrawNonMasterZeroTerminalLinkResult

    ld a, LINK_RESULT_OUTCOME_TILE_A
    ld hl, LINK_RESULT_OUTCOME_RIGHT_TOP_LEFT
    ld bc, LINK_RESULT_OUTCOME_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_STATUS_TEXT_TILE_B
    ld hl, LINK_RESULT_BOTTOM_TEXT_TOP_LEFT
    ld bc, LINK_RESULT_STATUS_TEXT_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_WAIT_PANEL_NONMASTER_ALT_TILE
    ldh [ANIM_SUBFRAME], a
    ld a, LINK_RESULT_WAIT_PANEL_NONMASTER_BASE_TILE
    ldh [UI_SCRATCH], a
    jp WaitLinkStartConfirm


DrawNonMasterZeroTerminalLinkResult:
    ld a, LINK_RESULT_OUTCOME_TILE_B
    ld hl, LINK_RESULT_OUTCOME_LEFT_TOP_LEFT
    ld bc, LINK_RESULT_OUTCOME_RECT_SIZE
    call FillRect
    ld a, LINK_RESULT_STATUS_TEXT_TILE_A
    ld hl, LINK_RESULT_BOTTOM_TEXT_TOP_LEFT
    ld bc, LINK_RESULT_STATUS_TEXT_RECT_SIZE
    call FillRect
    jp WaitTerminalLinkResultMenuConfirm


WaitLinkStartConfirm::
    xor a
    ldh [ANIM_FRAME], a

ContinueLinkConfirmWait:
    call WaitVBlank
    ld a, [SOUND_CH_ACTIVE_ID]
    cp SND_LINK_RESULT_CONFIRM_WAIT
    jr z, EnsureLinkConfirmSound

    cp SND_LINK_RESULT_NONZERO
    jr z, EnsureLinkConfirmSound

    ld a, SND_LINK_RESULT_CONFIRM_WAIT
    call PlaySound

EnsureLinkConfirmSound:
    ldh a, [ANIM_FRAME]
    cp LINK_RESULT_WAIT_PANEL_ALT_START_FRAME
    jr c, UseLinkConfirmBaseTile

    ldh a, [ANIM_SUBFRAME]
    jr DrawLinkConfirmWaitPanel

UseLinkConfirmBaseTile:
    ldh a, [UI_SCRATCH]

DrawLinkConfirmWaitPanel:
    ld hl, LINK_RESULT_WAIT_PANEL_TOP_LEFT
    ld bc, LINK_RESULT_WAIT_PANEL_RECT_SIZE
    call FillRect
    ldh a, [ANIM_FRAME]
    inc a
    ldh [ANIM_FRAME], a
    cp LINK_RESULT_WAIT_PANEL_ANIM_PERIOD
    jr c, CheckLinkConfirmRole

    xor a
    ldh [ANIM_FRAME], a

CheckLinkConfirmRole:
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr nz, WaitForPeerLinkConfirm

    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and PADF_START
    jr z, ContinueLinkConfirmWait

    ld a, LINK_CONFIRM_BYTE
    ldh [rSB], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a
    jr ReturnLinkConfirmWithCarry

WaitForPeerLinkConfirm:
    ld a, [LINK_RECV]
    cp LINK_CONFIRM_BYTE
    jr nz, ContinueLinkConfirmWait

ReturnLinkConfirmWithCarry:
    scf
    ret


WaitTerminalLinkResultMenuConfirm::
    call WaitVBlank
    ld a, [SOUND_CH_ACTIVE_ID]
    cp SND_LINK_RESULT_MENU_WAIT
    jr z, CheckTerminalLinkResultMenuConfirmRole

    cp SND_LINK_RESULT_ZERO
    jr z, CheckTerminalLinkResultMenuConfirmRole

    ld a, SND_LINK_RESULT_MENU_WAIT
    call PlaySound

CheckTerminalLinkResultMenuConfirmRole:
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr nz, WaitTerminalLinkResultPeerConfirm

    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and PADF_START
    jr z, WaitTerminalLinkResultMenuConfirm

    ld a, LINK_CONFIRM_BYTE
    ldh [rSB], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a
    jr ReturnLinkConfirmWithCarry

WaitTerminalLinkResultPeerConfirm:
    ld a, [LINK_RECV]
    cp LINK_CONFIRM_BYTE
    jr nz, WaitTerminalLinkResultMenuConfirm

    jr ReturnLinkConfirmWithCarry

DrawLinkResultConfirmPanelsAndWait::
    ld a, SND_CONFIRM
    call PlaySound
    ld b, LINK_RESULT_CONFIRM_MAIN_TILE_0
    ldh a, [ANIM_FRAME]
    and a
    jr nz, DrawLinkResultConfirmMainPanel

    ld b, LINK_RESULT_CONFIRM_MAIN_TILE_1

DrawLinkResultConfirmMainPanel:
    ld a, b
    ld hl, RESULT_MAIN_PANEL_TOP_LEFT
    ld bc, LINK_RESULT_CONFIRM_MAIN_RECT_SIZE
    call FillRect
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, HandleLinkResultClearConfirmOutcome

    ld b, LINK_RESULT_CONFIRM_DETAIL_TILE_0
    ldh a, [ANIM_FRAME]
    and a
    jr nz, DrawNonMasterConfirmDetailPanel

    ld b, LINK_RESULT_CONFIRM_DETAIL_TILE_1

DrawNonMasterConfirmDetailPanel:
    ld a, b
    ld hl, LINK_RESULT_CONFIRM_DETAIL_TOP_LEFT
    ld bc, LINK_RESULT_CONFIRM_DETAIL_RECT_SIZE
    call FillRect

HandleLinkResultClearConfirmOutcome:
    ld a, [RESULT_CLEAR_FLAG]
    and a
    jr z, HandleLinkResultGameOverConfirmOutcome

    call DrawLinkResultRoleStatusStrip
    call FillLinkResultWideScoreArea
    jp WaitLinkResultConfirmAndReloadTiles


HandleLinkResultGameOverConfirmOutcome:
    ld a, [RESULT_GAME_OVER_FLAG]
    and a
    jr z, DrawLinkResultConfirmStatusStrip

    call DrawLinkResultRoleStatusStrip
    call FillLinkResultNarrowScoreArea
    jr WaitLinkResultConfirmAndReloadTiles

DrawLinkResultConfirmStatusStrip:
    ld b, LINK_RESULT_STATUS_TEXT_TILE_B
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, FillLinkResultConfirmStatusStrip

    ld b, LINK_RESULT_STATUS_TEXT_TILE_A

FillLinkResultConfirmStatusStrip:
    ld a, b
    ld hl, LINK_RESULT_STATUS_TOP_LEFT
    ld bc, LINK_RESULT_STATUS_TEXT_RECT_SIZE
    call FillRect
    ldh a, [ANIM_FRAME]
    and a
    jr z, FillLinkResultConfirmWideScoreArea

    call FillLinkResultNarrowScoreArea
    jr WaitLinkResultConfirmAndReloadTiles

FillLinkResultConfirmWideScoreArea:
    call FillLinkResultWideScoreArea

WaitLinkResultConfirmAndReloadTiles::
    xor a
    ldh [SERIAL_DONE], a
    ld [LINK_SEND], a
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr nz, WaitLinkResultPeerConfirmBeforeReload

WaitLinkResultMasterConfirmBeforeReload:
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and PADF_START
    jr z, WaitLinkResultMasterConfirmBeforeReload

    ld a, LINK_CONFIRM_BYTE
    ldh [rSB], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a
    jr ReloadGameTilesAfterLinkResultConfirm

WaitLinkResultPeerConfirmBeforeReload:
    ld a, [LINK_RECV]
    cp LINK_CONFIRM_BYTE
    jr nz, WaitLinkResultPeerConfirmBeforeReload

ReloadGameTilesAfterLinkResultConfirm:
    call ReloadGameTilesAndRequestRedraw
    and a
    ret


DrawLinkResultRoleStatusStrip::
    ld b, LINK_RESULT_STATUS_TEXT_TILE_A
    ld a, [LINK_ROLE]
    cp LINK_ROLE_MASTER
    jr z, FillLinkModeStatusStrip

    ld b, LINK_RESULT_STATUS_TEXT_TILE_B

FillLinkModeStatusStrip:
    ld a, b
    ld hl, LINK_RESULT_STATUS_TOP_LEFT
    ld bc, LINK_RESULT_STATUS_TEXT_RECT_SIZE
    jp FillRect


FillLinkResultWideScoreArea::
    ld a, LINK_RESULT_SCORE_AREA_WIDE_TILE
    ld hl, RESULT_SCORE_VALUE_TOP_LEFT
    ld bc, LINK_RESULT_SCORE_AREA_WIDE_RECT_SIZE
    jp FillRect


FillLinkResultNarrowScoreArea::
    ld a, LINK_RESULT_SCORE_AREA_NARROW_TILE
    ld hl, RESULT_SCORE_VALUE_TOP_LEFT
    ld bc, LINK_RESULT_SCORE_AREA_NARROW_RECT_SIZE
    jp FillRect


ShowATypeRoundCompleteSummary::
    xor a
    ldh [ANIM_FRAME], a
    ld hl, EGG_COUNT_ONES
    ld a, [hl]
    and EGG_COUNT_DIGIT_MASK
    ld [hl+], a
    ld a, [hl]
    and EGG_COUNT_DIGIT_MASK
    ld [hl+], a
    ld a, [hl]
    and EGG_COUNT_DIGIT_MASK
    ld [hl], a
    and a
    jr nz, UseMaxRoundCompleteSummaryIndex

    ld a, [EGG_COUNT_TENS]
    and a
    ret z

    cp ROUND_COMPLETE_SUMMARY_MAX_INDEX_TENS_THRESHOLD
    jr nc, UseMaxRoundCompleteSummaryIndex

    dec a
    ldh [ANIM_FRAME], a
    jr BuildRoundCompleteSummaryScreen

UseMaxRoundCompleteSummaryIndex:
    ld a, ROUND_COMPLETE_SUMMARY_MAX_INDEX
    ldh [ANIM_FRAME], a

BuildRoundCompleteSummaryScreen:
    ld hl, SPRITE_OBJECT_SLOT_1
    ld bc, ROUND_COMPLETE_SUMMARY_OBJECT_CLEAR_BYTES
    ld d, $00
    call FillBytesWithD
    xor a
    ld [BG_MAP_SHADOW_COPY_ENABLE_FLAG], a
    ld hl, BG_MAP_SHADOW
    ld de, ROUND_COMPLETE_SUMMARY_BG_FILL_ROW_SKIP
    ld a, ROUND_COMPLETE_SUMMARY_BG_FILL_TILE
    ld c, ROUND_COMPLETE_SUMMARY_BG_FILL_HEIGHT

FillRoundCompleteSummaryRowsLoop:
    ld b, ROUND_COMPLETE_SUMMARY_BG_FILL_WIDTH

FillRoundCompleteSummaryColumnsLoop:
    ld [hl+], a
    dec b
    jr nz, FillRoundCompleteSummaryColumnsLoop

    add hl, de
    dec c
    jr nz, FillRoundCompleteSummaryRowsLoop

    ld hl, ROUND_COMPLETE_SUMMARY_PANEL_TOP_LEFT
    ld a, ROUND_COMPLETE_SUMMARY_PANEL_TILE
    ld bc, ROUND_COMPLETE_SUMMARY_PANEL_RECT_SIZE
    call FillRect
    ld hl, ROUND_COMPLETE_SUMMARY_HEADER_TOP_LEFT
    ld c, ROUND_COMPLETE_SUMMARY_HEADER_WIDTH
    ld a, ROUND_COMPLETE_SUMMARY_HEADER_TILE

FillRoundCompleteSummaryHeaderLoop:
    ld [hl+], a
    dec c
    jr nz, FillRoundCompleteSummaryHeaderLoop

    ld a, BG_MAP_SHADOW_COPY_ENABLED
    ld [BG_MAP_SHADOW_COPY_ENABLE_FLAG], a
    ld c, ROUND_COMPLETE_SUMMARY_BG_COPY_WAIT_FRAMES
    call WaitVBlankFrames
    xor a
    ld [BG_MAP_SHADOW_COPY_ENABLE_FLAG], a
    ld [COUNTDOWN_BLIT_TIMER], a
    ld de, RoundCompleteSummaryGraphicTileData
    ld hl, ROUND_COMPLETE_SUMMARY_GRAPHIC_TILES_VRAM_DEST
    ld c, ROUND_COMPLETE_SUMMARY_GRAPHIC_TILES_COPY_BLOCKS
    call VRAMCopySetup
    ld de, RoundCompleteSummaryTextTileData
    ld hl, ROUND_COMPLETE_SUMMARY_TEXT_TILES_VRAM_DEST
    ld c, ROUND_COMPLETE_SUMMARY_TEXT_TILES_COPY_BLOCKS
    call VRAMCopySetup
    ld a, BG_MAP_SHADOW_COPY_ENABLED
    ld [BG_MAP_SHADOW_COPY_ENABLE_FLAG], a
    ld a, [EGG_COUNT_HUNDREDS]
    and a
    jr z, CheckExcellentSummaryMessage

    ld hl, RoundCompleteSummaryMessageSuperPlayer
    jr CopyRoundCompleteSummaryMessage

CheckExcellentSummaryMessage:
    ld a, [EGG_COUNT_TENS]
    cp ROUND_COMPLETE_SUMMARY_MID_MESSAGE_TENS_THRESHOLD
    jr c, UseVeryGoodSummaryMessage

    ld hl, RoundCompleteSummaryMessageExcellent
    jr CopyRoundCompleteSummaryMessage

UseVeryGoodSummaryMessage:
    ld hl, RoundCompleteSummaryMessageVeryGood

CopyRoundCompleteSummaryMessage:
    ld de, ROUND_COMPLETE_SUMMARY_MESSAGE_TOP_LEFT
    ld bc, ROUND_COMPLETE_SUMMARY_MESSAGE_SIZE
    call Memcopy
    ld a, ROUND_COMPLETE_TILEMAP_PENDING_TILE
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_0
    ld bc, ROUND_COMPLETE_TILEMAP_RECT_SIZE
    call FillRect
    ld a, ROUND_COMPLETE_TILEMAP_PENDING_TILE
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_1
    ld bc, ROUND_COMPLETE_TILEMAP_RECT_SIZE
    call FillRect
    ld a, ROUND_COMPLETE_TILEMAP_PENDING_TILE
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_2
    ld bc, ROUND_COMPLETE_TILEMAP_RECT_SIZE
    call FillRect
    ld a, ROUND_COMPLETE_TILEMAP_PENDING_TILE
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_3
    ld bc, ROUND_COMPLETE_TILEMAP_RECT_SIZE
    call FillRect
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_0
    ld a, ROUND_COMPLETE_TILE_BASE_X_0
    call ShowRoundComplete
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_1
    ld a, ROUND_COMPLETE_TILE_BASE_X_1
    call ShowRoundComplete
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_2
    ld a, ROUND_COMPLETE_TILE_BASE_X_2
    call ShowRoundComplete
    ld hl, ROUND_COMPLETE_TILEMAP_ORIGIN_3
    ld a, ROUND_COMPLETE_TILE_BASE_X_3
    call ShowRoundComplete

WaitRoundCompleteSummaryInputLoop:
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and a
    jr z, WaitRoundCompleteSummaryInputLoop

    ret


ShowRoundComplete::
    push hl
    ldh [ANIM_SUBFRAME], a
    xor a
    ldh [STATE_TRANSITION], a
    ld c, ROUND_COMPLETE_PRE_REVEAL_WAIT_FRAMES
    call WaitFramesSetTransitionOnInput
    ld a, ROUND_COMPLETE_TILEMAP_REVEAL_TILE
    ld bc, ROUND_COMPLETE_TILEMAP_RECT_SIZE
    call FillRect
    ld c, ROUND_COMPLETE_REVEAL_TILE_WAIT_FRAMES
    call WaitFramesSetTransitionOnInput
    ldh a, [ANIM_SUBFRAME]
    ld [ROUND_COMPLETE_TILE_BASE_X], a
    ld a, ROUND_COMPLETE_TILE_GROUP_BASE_Y
    ld [ROUND_COMPLETE_TILE_BASE_Y], a
    call ProcessRoundComplete
    pop hl
    push hl
    ld de, ROUND_COMPLETE_TILEMAP_NEXT_ROW_DELTA
    ld a, ROUND_COMPLETE_TILEMAP_CLEAR_TILE
    ld [hl+], a
    ld [hl], a
    add hl, de
    ld [hl+], a
    ld [hl], a
    ld c, ROUND_COMPLETE_INPUT_POLL_FRAMES
    ld b, $00
    ld d, $00
    ld e, $00

PollRoundCompleteRevealInputLoop:
    push bc
    push de
    call WaitVBlank
    call UpdateFieldAnimationSlots
    call ReadJoypad
    pop de
    pop bc
    ldh a, [JOYPAD_PRESSED]
    and a
    jr z, AdvanceRoundCompleteRevealPoll

    ld d, ROUND_COMPLETE_INPUT_CAPTURED_FLAG
    ld e, b

AdvanceRoundCompleteRevealPoll:
    inc b
    dec c
    jr nz, PollRoundCompleteRevealInputLoop

    ldh a, [STATE_TRANSITION]
    and a
    jr nz, SelectRoundCompleteRevealStage

    dec d
    jr z, UseCapturedRoundCompleteInputFrame

    ld a, ROUND_COMPLETE_NO_INPUT_TRANSITION_SENTINEL
    ldh [STATE_TRANSITION], a
    jr SelectRoundCompleteRevealStage

UseCapturedRoundCompleteInputFrame:
    ld a, e
    ldh [STATE_TRANSITION], a

SelectRoundCompleteRevealStage:
    ld hl, RoundCompleteRevealThresholdTable
    ldh a, [ANIM_FRAME]
    REPT ROUND_COMPLETE_REVEAL_THRESHOLD_RECORD_SHIFT
        sla a
    ENDR
    ld b, $00
    ld c, a
    add hl, bc
    ldh a, [STATE_TRANSITION]
    cp [hl]
    jr nc, CheckRoundComplete200PointReveal

    pop hl
    call RevealRoundComplete2x2Block
    call RevealRoundComplete3x2Block
    call RevealRoundComplete3x4Block
    ld de, ROUND_COMPLETE_500_BONUS_BLOCK_OFFSET
    add hl, de
    ld bc, ROUND_COMPLETE_500_BONUS_BLOCK_RECT_SIZE
    ld a, ROUND_COMPLETE_500_BONUS_BLOCK_TILE
    call FillRect
    ld a, SND_ROUND_COMPLETE_MAJOR_REVEAL
    call PlaySound
    ld b, ROUND_COMPLETE_BONUS_500_LEFT_TILE
    ld c, ROUND_COMPLETE_BONUS_500_OAM_Y
    ld hl, ROUND_COMPLETE_BONUS_500_SCORE_DELTA
    call AddScoreAndAnimateManualOamPair
    jr WaitAfterRoundCompleteBonusReveal

CheckRoundComplete200PointReveal:
    inc hl
    cp [hl]
    jr nc, CheckRoundComplete100PointReveal

    pop hl
    call RevealRoundComplete2x2Block
    call RevealRoundComplete3x2Block
    call RevealRoundComplete3x4Block
    ld a, SND_ROUND_COMPLETE_REVEAL
    call PlaySound
    ld b, ROUND_COMPLETE_BONUS_200_LEFT_TILE
    ld c, ROUND_COMPLETE_BONUS_200_OAM_Y
    ld hl, ROUND_COMPLETE_BONUS_200_SCORE_DELTA
    call AddScoreAndAnimateManualOamPair
    jr WaitAfterRoundCompleteBonusReveal

CheckRoundComplete100PointReveal:
    inc hl
    cp [hl]
    jr nc, CheckRoundComplete50PointReveal

    pop hl
    call RevealRoundComplete2x2Block
    call RevealRoundComplete3x2Block
    ld a, SND_ROUND_COMPLETE_REVEAL
    call PlaySound
    ld b, ROUND_COMPLETE_BONUS_100_LEFT_TILE
    ld c, ROUND_COMPLETE_BONUS_100_OAM_Y
    ld hl, ROUND_COMPLETE_BONUS_100_SCORE_DELTA
    call AddScoreAndAnimateManualOamPair
    jr WaitAfterRoundCompleteBonusReveal

CheckRoundComplete50PointReveal:
    inc hl
    cp [hl]
    jr nc, DrawRoundCompleteFinalTile

    pop hl
    call RevealRoundComplete2x2Block
    ld a, SND_ROUND_COMPLETE_REVEAL
    call PlaySound
    ld b, ROUND_COMPLETE_BONUS_50_LEFT_TILE
    ld c, ROUND_COMPLETE_BONUS_50_OAM_Y
    ld hl, ROUND_COMPLETE_BONUS_50_SCORE_DELTA
    call AddScoreAndAnimateManualOamPair
    jr WaitAfterRoundCompleteBonusReveal

DrawRoundCompleteFinalTile:
    ld hl, RoundCompleteFinalTileTable
    ld b, $00
    ldh a, [ANIM_FRAME]
    ld c, a
    add hl, bc
    ld a, [hl]
    pop hl
    ld bc, ROUND_COMPLETE_TILEMAP_RECT_SIZE
    call FillRect

WaitAfterRoundCompleteBonusReveal:
    ld a, ROUND_COMPLETE_POST_REVEAL_WAIT_FRAMES

WaitRoundCompleteRevealFramesLoop:
    push af
    push hl
    call WaitVBlank
    call UpdateFieldAnimationSlots
    call Draw1PCountdownDigitTileSlots
    pop hl
    pop af
    dec a
    jr nz, WaitRoundCompleteRevealFramesLoop

    ret


RevealRoundComplete3x4Block::
    push hl
    ld de, ROUND_COMPLETE_REVEAL_3X4_BLOCK_OFFSET
    add hl, de
    ld bc, ROUND_COMPLETE_REVEAL_3X4_BLOCK_RECT_SIZE
    ld a, ROUND_COMPLETE_REVEAL_3X4_BLOCK_TILE
    call FillRect
    pop hl
    ld a, ROUND_COMPLETE_REVEAL_BLOCK_WAIT_FRAMES
    jr WaitRoundCompleteRevealFramesLoop

RevealRoundComplete3x2Block::
    push hl
    ld de, ROUND_COMPLETE_REVEAL_3X2_BLOCK_OFFSET
    add hl, de
    ld bc, ROUND_COMPLETE_REVEAL_3X2_BLOCK_RECT_SIZE
    ld a, ROUND_COMPLETE_REVEAL_3X2_BLOCK_TILE
    call FillRect
    pop hl
    ld a, ROUND_COMPLETE_REVEAL_BLOCK_WAIT_FRAMES
    jr WaitRoundCompleteRevealFramesLoop

RevealRoundComplete2x2Block::
    push hl
    ld bc, ROUND_COMPLETE_TILEMAP_RECT_SIZE
    ld a, ROUND_COMPLETE_REVEAL_2X2_BLOCK_TILE
    call FillRect
    pop hl
    ld a, ROUND_COMPLETE_REVEAL_BLOCK_WAIT_FRAMES
    jr WaitRoundCompleteRevealFramesLoop

MACRO ROUND_COMPLETE_SUMMARY_MESSAGE_HALF
    db \1, \2, \3, \4, \5, \6
ENDM

RoundCompleteSummaryMessageVeryGood::
    ROUND_COMPLETE_SUMMARY_MESSAGE_HALF ROUND_COMPLETE_SUMMARY_TEXT_TILE_BLANK, ROUND_COMPLETE_SUMMARY_TEXT_TILE_V, ROUND_COMPLETE_SUMMARY_TEXT_TILE_E, ROUND_COMPLETE_SUMMARY_TEXT_TILE_R, ROUND_COMPLETE_SUMMARY_TEXT_TILE_Y, ROUND_COMPLETE_SUMMARY_TEXT_TILE_BLANK
    ROUND_COMPLETE_SUMMARY_MESSAGE_HALF ROUND_COMPLETE_SUMMARY_TEXT_TILE_G, ROUND_COMPLETE_SUMMARY_TEXT_TILE_O, ROUND_COMPLETE_SUMMARY_TEXT_TILE_O, ROUND_COMPLETE_SUMMARY_TEXT_TILE_D, ROUND_COMPLETE_SUMMARY_TEXT_TILE_EXCLAMATION, ROUND_COMPLETE_SUMMARY_TEXT_TILE_BLANK

RoundCompleteSummaryMessageExcellent::
    ROUND_COMPLETE_SUMMARY_MESSAGE_HALF ROUND_COMPLETE_SUMMARY_TEXT_TILE_BLANK, ROUND_COMPLETE_SUMMARY_TEXT_TILE_E, ROUND_COMPLETE_SUMMARY_TEXT_TILE_X, ROUND_COMPLETE_SUMMARY_TEXT_TILE_C, ROUND_COMPLETE_SUMMARY_TEXT_TILE_E, ROUND_COMPLETE_SUMMARY_TEXT_TILE_L
    ROUND_COMPLETE_SUMMARY_MESSAGE_HALF ROUND_COMPLETE_SUMMARY_TEXT_TILE_L, ROUND_COMPLETE_SUMMARY_TEXT_TILE_E, ROUND_COMPLETE_SUMMARY_TEXT_TILE_N, ROUND_COMPLETE_SUMMARY_TEXT_TILE_T, ROUND_COMPLETE_SUMMARY_TEXT_TILE_EXCLAMATION, ROUND_COMPLETE_SUMMARY_TEXT_TILE_BLANK

RoundCompleteSummaryMessageSuperPlayer::
    ROUND_COMPLETE_SUMMARY_MESSAGE_HALF ROUND_COMPLETE_SUMMARY_TEXT_TILE_S, ROUND_COMPLETE_SUMMARY_TEXT_TILE_U, ROUND_COMPLETE_SUMMARY_TEXT_TILE_P, ROUND_COMPLETE_SUMMARY_TEXT_TILE_E, ROUND_COMPLETE_SUMMARY_TEXT_TILE_R, ROUND_COMPLETE_SUMMARY_TEXT_TILE_BLANK
    ROUND_COMPLETE_SUMMARY_MESSAGE_HALF ROUND_COMPLETE_SUMMARY_TEXT_TILE_P, ROUND_COMPLETE_SUMMARY_TEXT_TILE_L, ROUND_COMPLETE_SUMMARY_TEXT_TILE_A, ROUND_COMPLETE_SUMMARY_TEXT_TILE_Y, ROUND_COMPLETE_SUMMARY_TEXT_TILE_E, ROUND_COMPLETE_SUMMARY_TEXT_TILE_R

MACRO ROUND_COMPLETE_FINAL_TILE
    db \1
ENDM

RoundCompleteFinalTileTable::
    ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_0
    ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_1
    ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_2
    ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_3
    ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_4
    ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_5
    ROUND_COMPLETE_FINAL_TILE ROUND_COMPLETE_FINAL_TILE_INDEX_6

MACRO ROUND_COMPLETE_REVEAL_THRESHOLDS
    db \1, \2, \3, \4
ENDM

RoundCompleteRevealThresholdTable::
    ROUND_COMPLETE_REVEAL_THRESHOLDS ROUND_COMPLETE_REVEAL_INDEX_0_500_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_0_200_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_0_100_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_0_50_THRESHOLD
    ROUND_COMPLETE_REVEAL_THRESHOLDS ROUND_COMPLETE_REVEAL_INDEX_1_500_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_1_200_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_1_100_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_1_50_THRESHOLD
    ROUND_COMPLETE_REVEAL_THRESHOLDS ROUND_COMPLETE_REVEAL_INDEX_2_500_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_2_200_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_2_100_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_2_50_THRESHOLD
    ROUND_COMPLETE_REVEAL_THRESHOLDS ROUND_COMPLETE_REVEAL_INDEX_3_500_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_3_200_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_3_100_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_3_50_THRESHOLD
    ROUND_COMPLETE_REVEAL_THRESHOLDS ROUND_COMPLETE_REVEAL_INDEX_4_500_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_4_200_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_4_100_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_4_50_THRESHOLD
    ROUND_COMPLETE_REVEAL_THRESHOLDS ROUND_COMPLETE_REVEAL_INDEX_5_500_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_5_200_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_5_100_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_5_50_THRESHOLD
    ROUND_COMPLETE_REVEAL_THRESHOLDS ROUND_COMPLETE_REVEAL_INDEX_6_500_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_6_200_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_6_100_THRESHOLD, ROUND_COMPLETE_REVEAL_INDEX_6_50_THRESHOLD

AddScoreAndAnimateManualOamPair::
    push bc
    call AddScore
    call ClearManualOamPair
    pop bc
    ld hl, SHADOW_OAM_MANUAL_PAIR
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
    add ROUND_COMPLETE_BONUS_RIGHT_TILE_X_STEP
    ld [hl+], a
    ld a, ROUND_COMPLETE_BONUS_RIGHT_TILE
    ld [hl], a
    ld c, ROUND_COMPLETE_BONUS_ANIM_FRAMES
    ld de, OAM_ENTRY_SIZE

AnimateManualOamPairUpLoop:
    push bc
    push de
    call WaitVBlank
    call UpdateFieldAnimationSlots
    pop de
    pop bc
    ld hl, SHADOW_OAM_MANUAL_PAIR
    dec [hl]
    add hl, de
    dec [hl]
    dec c
    jr nz, AnimateManualOamPairUpLoop

    ld c, ROUND_COMPLETE_BONUS_HOLD_FRAMES
    call WaitVBlankFrames

ClearManualOamPair::
    ld hl, SHADOW_OAM_MANUAL_PAIR
    xor a
    ld bc, SHADOW_OAM_MANUAL_PAIR_SIZE
    jp FillBytesWithD


WaitFramesSetTransitionOnInput::
    call WaitVBlank
    push bc
    call ReadJoypad
    pop bc
    ldh a, [JOYPAD_PRESSED]
    and a
    jr z, ContinueWaitFramesAfterInputCheck

    ld a, ROUND_COMPLETE_NO_INPUT_TRANSITION_SENTINEL
    ldh [STATE_TRANSITION], a

ContinueWaitFramesAfterInputCheck:
    dec c
    jr nz, WaitFramesSetTransitionOnInput

    ret


MACRO ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS
    db \1, \2, \3, \4, \5, \6, \7, \8
ENDM

RoundCompleteSummaryGraphicTileData::
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $03, $03, $0c, $0c, $10, $10
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $10, $16, $20, $26, $20, $20, $30, $20
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $c0, $c0, $30, $70, $08, $68
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $08, $08, $04, $04, $04, $04, $04, $1c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $70, $40, $70, $4c, $60, $5e, $60, $5e
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $33, $2c, $3f, $20, $1f, $18, $07, $07
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $02, $3e, $02, $3e, $06, $1a, $3e, $02
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $cc, $34, $cc, $34, $f8, $18, $e0, $e0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $03, $03, $0d, $0d, $10, $10
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $10, $16, $20, $26, $21, $21, $31, $21
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $c0, $c0, $b0, $f0, $88, $e8
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $88, $88, $84, $84, $04, $04, $84, $9c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $71, $41, $76, $4e, $62, $5e, $60, $5e
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $33, $2c, $3f, $20, $1f, $18, $07, $07
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $82, $be, $42, $7e, $26, $3a, $3e, $02
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $cc, $34, $cc, $34, $f8, $18, $e0, $e0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $07, $07, $19, $1e, $33, $2c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7f, $40, $7c, $43, $98, $e7, $98, $e7
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $e0, $e0, $98, $78, $cc, $34
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fe, $02, $3e, $c2, $19, $e7, $19, $e7
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $98, $e7, $bc, $c3, $7f, $4f, $32, $32
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $22, $22, $20, $20, $10, $10, $0f, $0f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $19, $e7, $3d, $c3, $fe, $f2, $4c, $4c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $44, $44, $04, $04, $08, $08, $f0, $f0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $21, $21, $52, $52, $4c, $4c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $80, $80, $8c, $8c, $92, $92, $80, $80
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $84, $84, $4a, $4a, $32, $32
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $01, $01, $31, $31, $49, $49, $01, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $40, $40, $38, $38, $07, $07, $3b, $3a
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7f, $46, $7f, $42, $ff, $81, $7f, $7f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $02, $02, $1c, $1c, $e0, $e0, $dc, $5c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fe, $62, $fe, $42, $ff, $81, $fe, $fe
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $01, $01, $03, $02, $03, $02
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $07, $04, $ff, $fc, $ff, $80, $7f, $42
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $80, $80, $40, $40, $40, $40
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $a0, $20, $bf, $3f, $c1, $01, $fa, $42
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $3f, $22, $1f, $10, $3f, $20, $3f, $20
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7f, $41, $7e, $46, $f8, $98, $e0, $e0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $f4, $44, $e8, $08, $f4, $04, $f4, $04
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fa, $82, $7a, $62, $1d, $19, $07, $07
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $07, $07, $18, $18, $20, $20
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $40, $40, $54, $54, $94, $94, $80, $80
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $c0, $c0, $30, $30, $08, $08
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $04, $04, $04, $04, $32, $32, $4a, $4a
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $80, $aa, $80, $be, $80, $be, $40, $5f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $40, $55, $20, $20, $1c, $1c, $03, $03
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $0a, $0a, $11, $11, $01, $01, $01, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $02, $02, $0c, $0c, $30, $30, $c0, $c0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $30, $30, $1f, $1f, $1d, $1d, $35, $35
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $36, $36, $7a, $7a, $7b, $7b, $7f, $7f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $80, $80, $e0, $e0, $f0, $f0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $f0, $f0, $f8, $f8, $f8, $f8, $fe, $fe
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7f, $7f, $3f, $3f, $3f, $3f, $1f, $1f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $09, $09, $10, $10, $08, $08, $07, $07
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $f2, $f2, $e2, $e2, $e2, $e2, $e4, $e4
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $d8, $d8, $80, $80, $80, $80, $80, $80
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $01, $01, $6d, $01, $ff, $01, $ff, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fe, $29, $fe, $01, $6c, $03, $71, $70
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $c0, $c0, $f0, $30, $f8, $08, $f8, $88
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7c, $64, $7c, $94, $7e, $8e, $f7, $75
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $88, $88, $e4, $e4, $94, $94, $6c, $6c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $30, $30, $0c, $0c, $03, $03, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $8f, $8d, $17, $1d, $e7, $fd, $7b, $0b
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $30, $10, $30, $30, $f8, $c8, $78, $78
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $06, $06, $0d, $09, $0a, $0a
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $3f, $30, $5f, $40, $ff, $94, $ff, $80
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $e0, $e0, $70, $10, $90, $90
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $98, $88, $c8, $08, $fc, $04, $fc, $04
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $ff, $80, $7f, $40, $3f, $31, $0e, $0e
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $10, $10, $10, $10, $08, $08, $1f, $1f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fc, $44, $f8, $68, $b8, $88, $3c, $04
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $1e, $02, $7e, $62, $bc, $b4, $f8, $f8
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $03, $03, $06, $04, $0e, $0e, $33, $33
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $c0, $c0, $e0, $20, $a0, $a0, $b0, $90
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $5c, $40, $7f, $64, $bf, $80, $bf, $80
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7f, $40, $7f, $40, $3f, $31, $0e, $0e
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $90, $90, $f0, $10, $f8, $08, $fc, $04
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fc, $44, $f8, $48, $b0, $b0, $20, $20
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $02, $02, $0c, $0c, $1c, $14, $1c, $14
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $0c, $0c, $02, $02, $07, $07, $07, $07
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $60, $20, $70, $50, $f8, $88, $fe, $96
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7f, $61, $3d, $3d, $5e, $5e, $fc, $fc
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $01, $01, $01, $01, $02, $02
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $0d, $0d, $17, $12, $3d, $3d
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $c3, $c3, $7c, $00, $7f, $00, $ff, $88
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $c0, $c0, $e0, $20, $a0, $a0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $b0, $90, $90, $90, $f0, $70, $f0, $10
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $02, $02, $02, $02, $01, $01, $01, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $ff, $00, $ff, $00, $ff, $00, $ff, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $ff, $c1, $3e, $3e, $02, $02, $0c, $0c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fb, $0b, $fc, $04, $bc, $84, $b8, $88
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $31, $31, $fe, $e0, $78, $20, $79, $21
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $80, $80, $80, $80, $80, $80
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $40, $40, $40, $40, $80, $80, $40, $40
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $3c, $34, $78, $48, $78, $48, $38, $38
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $04, $04, $04, $04, $0b, $0b, $0f, $0f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $7e, $50, $ff, $89, $fe, $8e, $7e, $76
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $1f, $01, $3f, $3d, $5e, $5e, $fc, $fc
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $40, $40, $80, $80, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $01, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $01, $01, $03, $03, $0c, $0c, $13, $10
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $ee, $ee, $ff, $11
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $2b, $29, $e9, $e8, $39, $38, $fc, $04
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $01, $01, $81, $81, $be, $be, $a0, $a0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $c0, $c0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $20, $20, $20, $20, $1f, $1f, $01, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $2f, $20, $2f, $28, $5f, $40, $5f, $40
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $5f, $40, $5f, $40, $5f, $40, $3f, $20
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fe, $02, $ff, $81, $ff, $00, $ff, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $ff, $00, $ff, $02, $ff, $01, $ff, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $90, $90, $88, $88, $c4, $44, $c4, $44
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $e8, $28, $e8, $28, $f3, $33, $ec, $2c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $02, $02, $04, $04, $08, $08, $08, $08
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $04, $04, $c4, $c4, $32, $32, $0c, $0c
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $3f, $20, $1f, $18, $07, $07, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $01, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $fe, $06, $f8, $18, $e1, $e0, $39, $38
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $41, $40, $43, $40, $83, $80, $83, $81
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $e0, $60, $90, $f0, $90, $f0, $a0, $e0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $d8, $58, $e6, $2e, $e1, $ef, $e0, $2f
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $80, $80
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $03, $02, $03, $02, $03, $02, $01, $01
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $83, $82, $83, $82, $81, $81, $c0, $c0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $40, $40, $70, $70, $9c, $bc, $ff, $ff
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $f0, $10, $ff, $1f, $ff, $20, $ff, $c0
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $3f, $3e, $4f, $5f, $7f, $7f, $ff, $ff
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $c0, $c0, $f8, $38, $fc, $04, $f4, $04
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $c8, $08, $30, $30, $c0, $c0, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $07, $07, $04, $04, $04, $04
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $07, $07, $01, $01, $01, $01, $07, $07
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $17, $17, $15, $15, $15, $15
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $15, $15, $15, $15, $15, $15, $17, $17
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $77, $77, $15, $15, $15, $15
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $75, $75, $45, $45, $45, $45, $77, $77
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $77, $77, $45, $45, $45, $45
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $75, $75, $15, $15, $15, $15, $77, $77
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $70, $70, $50, $50, $50, $50
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $50, $50, $50, $50, $50, $50, $70, $70
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
    ROUND_COMPLETE_SUMMARY_GRAPHIC_TILE_4_ROWS $00, $00, $00, $00, $00, $00, $00, $00
MACRO ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE
    db HIGH(\2), LOW(\2), HIGH(\3), LOW(\3), HIGH(\4), LOW(\4), HIGH(\5), LOW(\5)
    db HIGH(\6), LOW(\6), HIGH(\7), LOW(\7), HIGH(\8), LOW(\8), HIGH(\9), LOW(\9)
ENDM

RoundCompleteSummaryTextTileData::
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_V, $0000, $0000, $0000, %1100011011000110, %1100011011000110, $eeee, $7c7c, $3838
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_E, $0000, $0000, $0000, $fefe, %1100000011000000, $fcfc, %1100000011000000, $fefe
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_R, $0000, $0000, $0000, $fcfc, %1100011011000110, %1100111011001110, $f8f8, %1100111011001110
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_Y, $0000, $0000, $0000, $6666, $6666, $3c3c, $1818, $1818
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_G, $0000, $0000, $0000, $7e7e, $e0e0, %1100111011001110, $e6e6, $7e7e
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_O, $0000, $0000, $0000, $7c7c, %1100011011000110, %1100011011000110, %1100011011000110, $7c7c
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_D, $0000, $0000, $0000, $f8f8, %1100110011001100, %1100011011000110, %1100110011001100, $f8f8
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_EXCLAMATION, $0000, $0000, $3838, $3838, $3838, $1010, $0000, $1010
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_X, $0000, $0000, $0000, %1100011011000110, $6c6c, $3838, $6c6c, %1100011011000110
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_L, $0000, $0000, $0000, $6060, $6060, $6060, $6060, $7e7e
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_N, $0000, $0000, $0000, %1100011011000110, $f6f6, $fefe, $dede, %1100011011000110
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_T, $0000, $0000, $0000, $7e7e, $1818, $1818, $1818, $1818
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_S, $0000, $0000, $0000, $7e7e, $e0e0, $7c7c, $0e0e, $fcfc
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_U, $0000, $0000, $0000, %1100011011000110, %1100011011000110, %1100011011000110, %1100011011000110, $7c7c
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_P, $0000, $0000, $0000, $fcfc, %1100011011000110, %1100011011000110, $fcfc, %1100000011000000
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_A, $0000, $0000, $0000, $7c7c, %1100011011000110, %1100011011000110, $fefe, %1100011011000110
    ROUND_COMPLETE_SUMMARY_TEXT_GLYPH_TILE ROUND_COMPLETE_SUMMARY_TEXT_TILE_C, $0000, $0000, $0000, $7c7c, %1100011011000110, %1100000011000000, %1100011011000110, $7c7c

Bank0TailPaddingData::
    REPT BANK0_TAIL_PADDING_PREFIX_WORDS
        dw BANK0_TAIL_PADDING_WORD
    ENDR
    db $39, $9c, $df, $00, $39, $db, $45, $00
    db $39, $95, $fe, $00, $39, $fd, $e7, $00, $39, $ad, $a7, $00, $39, $02, $fc, $00
    db $39, $2c, $bb, $00, $39, $93, $00
