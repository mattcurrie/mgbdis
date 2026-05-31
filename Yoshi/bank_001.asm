; Disassembly of "yoshi.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $001", ROMX[$4000], BANK[$1]

UpdateSprites::
    ld a, [LCD_REDRAW]
    dec a
    jr z, BeginSpriteOamExpansion

    cp LCD_REDRAW_HIDE_ALL_SENTINEL
    ret nz

    ld [LCD_REDRAW], a
    jp HideAllSprites


BeginSpriteOamExpansion:
    ldh [SHADOW_OAM_WRITE_OFFSET], a

ScanSpriteObjectSlotLoop:
    ldh [SPRITE_SCAN_SLOT_OFFSET], a
    ld d, SPRITE_OBJECTS_HI
    ld e, a
    ld a, [de]
    and a
    jr z, AdvanceSpriteObjectSlot

    and SPRITE_OBJECT_ATTR_MASK
    ldh [SPRITE_OBJECT_ATTR_TMP], a
    ld a, [de]
    dec a
    ld hl, SpriteUpdatePointerTable
    ; Types $81-$87 preserve bit 7 for inherited OAM attributes while sharing
    ; the same frame-table entries as $01-$07.
    sla a
    add l
    ld l, a
    jr nc, LoadSpriteFramePointer

    inc h

LoadSpriteFramePointer:
    ld c, [hl]
    inc hl
    ld b, [hl]
    inc e
    inc e
    ld a, [de]
    cp SPRITE_OBJECT_FRAME_DISABLED
    jr nz, DrawSpriteObjectFrame

    jr AdvanceSpriteObjectSlot

DrawSpriteObjectFrame:
    ld l, a
    ld h, $00
    add hl, hl
    add hl, hl
    add hl, bc
    ld a, [hl+]
    ld c, a
    ld a, [hl+]
    ld b, a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    inc e
    inc e
    ld a, [de]
    ldh [SPRITE_BASE_Y_TMP], a
    inc e
    inc e
    ld a, [de]
    ldh [SPRITE_BASE_X_TMP], a
    ldh a, [SHADOW_OAM_WRITE_OFFSET]
    ld e, a
    ld d, SHADOW_OAM_HI

DrawSpriteObjectOamEntryLoop:
    ldh a, [SPRITE_BASE_Y_TMP]
    add OAM_Y_BIAS
    add [hl]
    ld [de], a
    inc hl
    inc e
    ldh a, [SPRITE_BASE_X_TMP]
    add OAM_X_BIAS
    add [hl]
    ld [de], a
    inc hl
    inc e
    ld a, [bc]
    inc bc
    ld [de], a
    inc e
    ld a, [hl]
    bit SPRITE_ATTR_INHERIT_BIT, a
    jr z, StoreSpriteObjectOamAttributes

    ldh a, [SPRITE_OBJECT_ATTR_TMP]
    or [hl]

StoreSpriteObjectOamAttributes:
    inc hl
    ld [de], a
    inc e
    bit SPRITE_ATTR_END_BIT, a
    jr z, DrawSpriteObjectOamEntryLoop

    ld a, e
    ldh [SHADOW_OAM_WRITE_OFFSET], a
    cp SHADOW_OAM_SIZE
    ret z

AdvanceSpriteObjectSlot:
    ldh a, [SPRITE_SCAN_SLOT_OFFSET]
    add SPRITE_OBJECT_SLOT_SIZE
    cp SPRITE_OBJECT_SCAN_END_OFFSET
    jr nz, ScanSpriteObjectSlotLoop

    ldh a, [SHADOW_OAM_WRITE_OFFSET]
    ld l, a
    ld h, SHADOW_OAM_HI
    ld de, OAM_ENTRY_SIZE
    ld a, SHADOW_OAM_HIDE_LIMIT

HideUnusedShadowOamLoop:
    cp l
    ret z

    ld [hl], OAM_HIDDEN_Y
    add hl, de
    jr HideUnusedShadowOamLoop

InitSpriteBuffer::
    ld hl, SPRITE_OBJECTS

ClearSpriteObjectSlotTypesLoop:
    xor a
    ld [hl], a
    ld a, l
    add SPRITE_OBJECT_SLOT_SIZE
    ld l, a
    jr nc, ClearSpriteObjectSlotTypesLoop

    ret


MACRO SPRITE_OBJECT_FRAME_TABLE
    dw \2
ENDM

MACRO SPRITE_FRAME_RECORD
    dw \1, \2
ENDM

MACRO SPRITE_TILE_LIST_1
    db \1
ENDM

MACRO SPRITE_TILE_LIST_2
    db \1, \2
ENDM

MACRO SPRITE_TILE_LIST_4
    db \1, \2, \3, \4
ENDM

MACRO SPRITE_TILE_LIST_6
    db \1, \2, \3, \4, \5, \6
ENDM

MACRO SPRITE_TILE_LIST_8
    db \1, \2, \3, \4, \5, \6, \7, \8
ENDM

MACRO SPRITE_LAYOUT_ENTRY
    db \1, \2, \3
ENDM

SpriteUpdatePointerTable::
    SPRITE_OBJECT_FRAME_TABLE SPRITE_OBJECT_TYPE_PLAYER_CURSOR, SpriteFrameTable_PlayerCursor
    SPRITE_OBJECT_FRAME_TABLE SPRITE_OBJECT_TYPE_PIECE_DISPLAY, SpriteFrameTable_PieceDisplay
    SPRITE_OBJECT_FRAME_TABLE SPRITE_OBJECT_TYPE_ROUND_TRANSITION, SpriteFrameTable_RoundTransition
    SPRITE_OBJECT_FRAME_TABLE SPRITE_OBJECT_TYPE_ROUND_COMPLETE_TILE, SpriteFrameTable_RoundCompleteTile
    SPRITE_OBJECT_FRAME_TABLE SPRITE_OBJECT_TYPE_SETTINGS_CURSOR, SpriteFrameTable_SettingsCursor
    SPRITE_OBJECT_FRAME_TABLE SPRITE_OBJECT_TYPE_FIELD_COLUMN_EFFECT, SpriteFrameTable_FieldColumnEffect
    SPRITE_OBJECT_FRAME_TABLE SPRITE_OBJECT_TYPE_RESERVED_7, SpriteFrameTable_ReservedObject7

SpriteFrameTable_SettingsCursor::
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame1, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame2, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame1, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame2, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame1, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame2, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame1, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame2, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame0Alt, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame1Alt, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_SettingsCursorFrame2Alt, SpriteLayout_TwoTileRow

SpriteFrameTable_PlayerCursor::
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame0, SpriteLayout_PlayerCursorSixTile
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame1, SpriteLayout_PlayerCursorFourTileForward
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame2, SpriteLayout_PlayerCursorFourTileForward
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame3, SpriteLayout_PlayerCursorFourTileForward
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame4, SpriteLayout_PlayerCursorSixTile
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame3, SpriteLayout_PlayerCursorFourTileFlipped
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame2, SpriteLayout_PlayerCursorFourTileFlipped
    SPRITE_FRAME_RECORD SpriteTileList_PlayerCursorFrame1, SpriteLayout_PlayerCursorFourTileFlipped

SpriteFrameTable_PieceDisplay::
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame2, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame3, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame4, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame5, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame6, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame6, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame8, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame0, SpriteLayout_TwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame17, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame18, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame19, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame20, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame21, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame22, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame22, SpriteLayout_PieceDisplayTwoTileRow
    SPRITE_FRAME_RECORD SpriteTileList_PieceDisplayFrame22, SpriteLayout_PieceDisplayTwoTileRow

SpriteFrameTable_RoundTransition::
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame1, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame2, SpriteLayout_RoundTransitionFourTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame3, SpriteLayout_RoundTransitionSixTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame4, SpriteLayout_RoundTransitionEightTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame0Alt, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame1Alt, SpriteLayout_RoundTransitionTwoTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame2Alt, SpriteLayout_RoundTransitionFourTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame3Alt, SpriteLayout_RoundTransitionSixTile
    SPRITE_FRAME_RECORD SpriteTileList_RoundTransitionFrame4Alt, SpriteLayout_RoundTransitionEightTile

SpriteFrameTable_RoundCompleteTile::
    SPRITE_FRAME_RECORD SpriteTileList_RoundCompleteTile, SpriteLayout_RoundCompleteTileNormal
    SPRITE_FRAME_RECORD SpriteTileList_RoundCompleteTile, SpriteLayout_RoundCompleteTileXFlip
    SPRITE_FRAME_RECORD SpriteTileList_RoundCompleteTile, SpriteLayout_RoundCompleteTileYFlip
    SPRITE_FRAME_RECORD SpriteTileList_RoundCompleteTile, SpriteLayout_RoundCompleteTileXYFlip

SpriteFrameTable_FieldColumnEffect::
    SPRITE_FRAME_RECORD SpriteTileList_FieldColumnEffect, SpriteLayout_FieldColumnEffectLower
    SPRITE_FRAME_RECORD SpriteTileList_FieldColumnEffect, SpriteLayout_FieldColumnEffectUpper

SpriteFrameTable_ReservedObject7::
    SPRITE_FRAME_RECORD SpriteTileList_ReservedObject7, SpriteLayout_ReservedObject7

SpriteTileList_ReservedObject7::
    SPRITE_TILE_LIST_2 $e0, $e0

SpriteLayout_ReservedObject7::
    SPRITE_LAYOUT_ENTRY $00, $08, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $10, OAMF_XFLIP | SPRITE_LAYOUT_ATTR_END

SpriteTileList_FieldColumnEffect::
    SPRITE_TILE_LIST_6 $da, $dc, $de, $da, $dc, $de

SpriteLayout_FieldColumnEffectLower::
    SPRITE_LAYOUT_ENTRY $10, $04, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $10, $0c, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $10, $14, OAM_ATTR_NONE

; Also the tail of SpriteLayout_FieldColumnEffectLower; the terminator is in the final triple.
SpriteLayout_FieldColumnEffectUpper::
    SPRITE_LAYOUT_ENTRY $00, $04, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $0c, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $14, SPRITE_LAYOUT_ATTR_END

SpriteTileList_PlayerCursorFrame0::
    SPRITE_TILE_LIST_6 $1c, $1e, $20, $20, $1e, $1c

SpriteTileList_PlayerCursorFrame1::
    SPRITE_TILE_LIST_4 $24, $26, $28, $2a

SpriteTileList_PlayerCursorFrame2::
    SPRITE_TILE_LIST_4 $2c, $2e, $30, $32

SpriteTileList_PlayerCursorFrame3::
    SPRITE_TILE_LIST_4 $34, $36, $38, $3a

SpriteTileList_PlayerCursorFrame4::
    SPRITE_TILE_LIST_6 $3c, $3e, $40, $40, $3e, $3c

SpriteTileList_RoundCompleteTile::
    SPRITE_TILE_LIST_1 $80

SpriteLayout_RoundCompleteTileNormal::
    SPRITE_LAYOUT_ENTRY $f0, $f8, SPRITE_LAYOUT_ATTR_END

SpriteLayout_RoundCompleteTileXFlip::
    SPRITE_LAYOUT_ENTRY $f0, $00, OAMF_XFLIP | SPRITE_LAYOUT_ATTR_END

SpriteLayout_RoundCompleteTileYFlip::
    SPRITE_LAYOUT_ENTRY $f0, $f8, OAMF_YFLIP | SPRITE_LAYOUT_ATTR_END

SpriteLayout_RoundCompleteTileXYFlip::
    SPRITE_LAYOUT_ENTRY $f0, $00, OAMF_XFLIP | OAMF_YFLIP | SPRITE_LAYOUT_ATTR_END

SpriteTileList_SettingsCursorFrame0::
    SPRITE_TILE_LIST_2 $60, $62

SpriteTileList_SettingsCursorFrame0Alt::
    SPRITE_TILE_LIST_2 $64, $66

SpriteTileList_SettingsCursorFrame1::
    SPRITE_TILE_LIST_2 $68, $6a

SpriteTileList_SettingsCursorFrame1Alt::
    SPRITE_TILE_LIST_2 $6c, $6e

SpriteTileList_SettingsCursorFrame2::
    SPRITE_TILE_LIST_2 $70, $72

SpriteTileList_SettingsCursorFrame2Alt::
    SPRITE_TILE_LIST_2 $74, $76

SpriteTileList_RoundTransitionFrame0::
    SPRITE_TILE_LIST_2 $82, $84

SpriteTileList_RoundTransitionFrame0Alt::
    SPRITE_TILE_LIST_2 $86, $88

SpriteTileList_RoundTransitionFrame1Alt::
    SPRITE_TILE_LIST_2 $8a, $8c

SpriteTileList_RoundTransitionFrame1::
    SPRITE_TILE_LIST_2 $8e, $90

SpriteTileList_RoundTransitionFrame2Alt::
    SPRITE_TILE_LIST_4 $92, $94, $96, $98

SpriteTileList_RoundTransitionFrame2::
    SPRITE_TILE_LIST_4 $9a, $9c, $9e, $a0

SpriteTileList_RoundTransitionFrame3Alt::
    SPRITE_TILE_LIST_6 $a2, $a4, $a6, $a8, $aa, $ac

SpriteTileList_RoundTransitionFrame3::
    SPRITE_TILE_LIST_6 $ae, $b0, $b2, $b4, $b6, $b8

SpriteTileList_RoundTransitionFrame4Alt::
    SPRITE_TILE_LIST_8 $ba, $bc, $be, $c0, $c2, $c4, $c6, $c8

SpriteTileList_RoundTransitionFrame4::
    SPRITE_TILE_LIST_8 $ca, $cc, $ce, $d0, $d2, $d4, $d6, $d8

SpriteLayout_RoundTransitionTwoTile::
    SPRITE_LAYOUT_ENTRY $f0, $f8, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f0, $00, SPRITE_LAYOUT_ATTR_END

SpriteLayout_RoundTransitionFourTile::
    SPRITE_LAYOUT_ENTRY $e8, $f8, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f8, $f8, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $e8, $00, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f8, $00, SPRITE_LAYOUT_ATTR_END

SpriteLayout_RoundTransitionSixTile::
    SPRITE_LAYOUT_ENTRY $e8, $f4, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f8, $f4, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $e8, $fc, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f8, $fc, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $e8, $04, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f8, $04, SPRITE_LAYOUT_ATTR_END

SpriteLayout_RoundTransitionEightTile::
    SPRITE_LAYOUT_ENTRY $e0, $f0, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f0, $f0, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $e0, $f8, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f0, $f8, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $e0, $00, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f0, $00, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $e0, $08, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $f0, $08, SPRITE_LAYOUT_ATTR_END

SpriteTileList_PieceDisplayFrame0::
    SPRITE_TILE_LIST_2 $00, $02

SpriteTileList_PieceDisplayFrame2::
    SPRITE_TILE_LIST_2 $04, $06

SpriteTileList_PieceDisplayFrame3::
    SPRITE_TILE_LIST_2 $08, $0a

SpriteTileList_PieceDisplayFrame4::
    SPRITE_TILE_LIST_2 $0c, $0e

SpriteTileList_PieceDisplayFrame5::
    SPRITE_TILE_LIST_2 $10, $12

SpriteTileList_PieceDisplayFrame6::
    SPRITE_TILE_LIST_2 $18, $1a

SpriteTileList_PieceDisplayFrame8::
    SPRITE_TILE_LIST_2 $14, $16

SpriteTileList_PieceDisplayFrame17::
    SPRITE_TILE_LIST_2 $4c, $4e

SpriteTileList_PieceDisplayFrame18::
    SPRITE_TILE_LIST_2 $50, $52

SpriteTileList_PieceDisplayFrame19::
    SPRITE_TILE_LIST_2 $54, $56

SpriteTileList_PieceDisplayFrame20::
    SPRITE_TILE_LIST_2 $58, $5a

SpriteTileList_PieceDisplayFrame21::
    SPRITE_TILE_LIST_2 $5c, $5e

SpriteTileList_PieceDisplayFrame22::
SpriteLayout_TwoTileRow::
    SPRITE_LAYOUT_ENTRY $00, $08, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $10, SPRITE_LAYOUT_ATTR_END

SpriteLayout_PieceDisplayTwoTileRow::
    SPRITE_LAYOUT_ENTRY $00, $08, OAM_ATTR_DMG_PALETTE_1
    SPRITE_LAYOUT_ENTRY $00, $10, OAM_ATTR_DMG_PALETTE_1 | SPRITE_LAYOUT_ATTR_END

SpriteLayout_PlayerCursorSixTile::
    SPRITE_LAYOUT_ENTRY $00, $08, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $10, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $18, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $20, OAMF_XFLIP
    SPRITE_LAYOUT_ENTRY $00, $28, OAMF_XFLIP
    SPRITE_LAYOUT_ENTRY $00, $30, OAMF_XFLIP | SPRITE_LAYOUT_ATTR_END

SpriteLayout_PlayerCursorFourTileForward::
    SPRITE_LAYOUT_ENTRY $00, $10, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $18, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $20, OAM_ATTR_NONE
    SPRITE_LAYOUT_ENTRY $00, $28, SPRITE_LAYOUT_ATTR_END

SpriteLayout_PlayerCursorFourTileFlipped::
    SPRITE_LAYOUT_ENTRY $00, $28, OAMF_XFLIP | SPRITE_LAYOUT_ATTR_INHERIT
    SPRITE_LAYOUT_ENTRY $00, $20, OAMF_XFLIP | SPRITE_LAYOUT_ATTR_INHERIT
    SPRITE_LAYOUT_ENTRY $00, $18, OAMF_XFLIP | SPRITE_LAYOUT_ATTR_INHERIT
    SPRITE_LAYOUT_ENTRY $00, $10, OAMF_XFLIP | SPRITE_LAYOUT_ATTR_INHERIT | SPRITE_LAYOUT_ATTR_END

Draw1PCountdownDigitTileSlots::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld a, [GAME_TYPE]
    and a

    jr nz, UseBTypeCountdownDigitSlotOrigin

    ld hl, COUNTDOWN_TILE_SLOT_A_TYPE_COORD
    jr DrawCountdownDigitTileSlotHead

UseBTypeCountdownDigitSlotOrigin:
    ld hl, COUNTDOWN_TILE_SLOT_B_TYPE_COORD

DrawCountdownDigitTileSlotHead:
    call CalcTilemapAddress
    ld [hl], COUNTDOWN_TILE_SLOT_0
    inc hl

    ld [hl], COUNTDOWN_TILE_SLOT_1

DrawCountdownDigitTileSlotTail:
    inc hl

    ld [hl], COUNTDOWN_TILE_SLOT_2
    inc hl

    ld [hl], COUNTDOWN_TILE_SLOT_3
    ld a, [COUNTDOWN_BLIT_TIMER]
    and a
    ret nz

    ld a, COUNTDOWN_BLIT_TIMER_RELOAD
    ld [COUNTDOWN_BLIT_TIMER], a
    ret


UnusedDrawLowNibbleTileDigitsByCoord::
    call CalcTilemapAddress

UnusedDrawLowNibbleTileDigitsLoop:
    ld a, [de]
    and PLAYFIELD_DIGIT_MASK
    inc de
    add PLAYFIELD_DIGIT_TILE_BASE
    ld [hl+], a
    dec b
    jr nz, UnusedDrawLowNibbleTileDigitsLoop

    ret


AddScore::
    ld a, [SCORE_BCD_LOW]
    add l
    daa
    ld [SCORE_BCD_LOW], a
    ld a, [SCORE_BCD_MID]
    adc h
    daa
    ld [SCORE_BCD_MID], a
    ld a, [SCORE_BCD_HIGH]
    adc SCORE_BCD_HIGH_ADDEND
    daa
    cp SCORE_BCD_HIGH_OVERFLOW_LIMIT
    jr c, StoreScoreDigitsFromBCD

    ld a, SCORE_BCD_LOW_MID_MAX
    ld [SCORE_BCD_LOW], a
    ld [SCORE_BCD_MID], a
    ld a, SCORE_BCD_HIGH_MAX

StoreScoreDigitsFromBCD:
    ld [SCORE_BCD_HIGH], a
    ld hl, SCORE_DIGITS
    ld a, [SCORE_BCD_HIGH]
    ld [hl+], a
    ld a, [SCORE_BCD_MID]
    swap a
    ld [hl+], a
    ld a, [SCORE_BCD_MID]
    ld [hl+], a
    ld a, [SCORE_BCD_LOW]
    swap a
    ld [hl+], a
    ld a, [SCORE_BCD_LOW]
    ld [hl+], a
    ld a, [SCORE_UNUSED_TILE_BASE_SOURCE]
    ld [SCORE_UNUSED_TILE_BASE_COPY], a
    swap a
    ld [SCORE_UNUSED_TILE_BASE_SWAPPED], a
    ret


ResetScoreAccumulatorAndDigits::
    ld a, [SCORE_PRESERVED_UNUSED_BYTE]
    ld c, a
    xor a
    ld hl, SCORE_BCD_LOW
    ld b, SCORE_CLEAR_BYTE_COUNT

ClearScoreAccumulatorAndDigitsLoop:
    ld [hl+], a
    dec b
    jr nz, ClearScoreAccumulatorAndDigitsLoop

    ld a, c
    ld [SCORE_PRESERVED_UNUSED_BYTE], a
    ret


    ld b, a
    call CalcTilemapAddress

UnusedDrawTwoDigitBcdTilePair::
    xor a
    add b
    daa
    ld b, a
    swap a
    and PLAYFIELD_DIGIT_MASK
    jr z, UseBlankUnusedBcdTensTile

    add PLAYFIELD_DIGIT_TILE_BASE
    jr StoreUnusedBcdDigitTiles

UseBlankUnusedBcdTensTile:
    ld a, PLAYFIELD_BLANK_DIGIT_TILE

StoreUnusedBcdDigitTiles:
    ld [hl+], a
    ld a, b
    and PLAYFIELD_DIGIT_MASK
    add PLAYFIELD_DIGIT_TILE_BASE
    ld [hl], a
    ret


RunGameplayFrame::
    call HandlePlayfieldInput
    call UpdateGameplayObjectsAndCheckBTypeClear
    call UpdateDropCursorAnimation
    call Draw1PCountdownDigitTileSlots
    call ShufflePieceDisplaySlotOrder
    call ShufflePieceDisplayCodePool
    call DrawGameplayBgTopRowIfNoResultFlow
    call UpdatePieceDisplayBlink
    call UpdateFieldTimers
    call AnimateDropping
    call DrawFieldColumnTilePattern
    call UpdateEggTextAnimation
    call CheckPause2P
    ld a, [GAME_TYPE]
    and a
    jr z, ContinueGameMainAfterTimerDraw

    call DrawPlayfieldRoundTimerDigits

ContinueGameMainAfterTimerDraw:
    call TimerTick
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, ReturnFromGameplayFrame

ProcessPending2PRoundResult::
    ld a, [ROUND_RESULT_PENDING]
    and a
    jr z, ReturnFromGameplayFrame

    ld a, [ROUND_RESULT_CODE]
    jp ProcessRoundResultAndEnterRoundEnd


ReturnFromGameplayFrame:
    ret


DrawGameplayBgTopRowIfNoResultFlow::
    ld hl, RESULT_FLOW_ACTIVE
    ld a, [hl]
    and a
    ret nz

    ld b, GAMEPLAY_BG_TOP_ROW_WIDTH
    ld h, HIGH(GAMEPLAY_BG_TOP_ROW_COORD)
    ld l, LOW(GAMEPLAY_BG_TOP_ROW_COORD)
    call CalcTilemapAddress

FillGameplayBgTopRowLoop:
    ld [hl], GAMEPLAY_BG_TOP_ROW_TILE
    inc hl
    dec b
    jr nz, FillGameplayBgTopRowLoop

    ret


DrawFieldColumnTilePattern::
    ld a, [FIELD_COLUMN_TILE_PATTERN_INDEX]
    REPT FIELD_COLUMN_TILE_PATTERN_INDEX_SHIFT
        sla a
    ENDR
    ld hl, FieldColumnTilePatternTable
    call GetArrayElement
    ld d, h
    ld e, l
    ld hl, FIELD_COLUMN_TILE_PATTERN_DEST_COORD
    push de
    call CalcTilemapAddress
    pop de
    ld b, FIELD_COLUMN_TILE_PATTERN_RECORD_SIZE

CopyFieldColumnTilePatternLoop:
    ld a, [de]
    ld [hl+], a
    inc de
    dec b
    jr nz, CopyFieldColumnTilePatternLoop

    ret

MACRO FIELD_COLUMN_TILE_PATTERN_ROW
    db FIELD_COLUMN_TILE_PATTERN_TILE_\1, FIELD_COLUMN_TILE_PATTERN_TILE_\2
    db FIELD_COLUMN_TILE_PATTERN_TILE_\3, FIELD_COLUMN_TILE_PATTERN_TILE_\4
    db FIELD_COLUMN_TILE_PATTERN_TILE_\5, FIELD_COLUMN_TILE_PATTERN_TILE_\6
    db FIELD_COLUMN_TILE_PATTERN_TILE_\7, FIELD_COLUMN_TILE_PATTERN_TILE_\8
ENDM

FieldColumnTilePatternTable::
    FIELD_COLUMN_TILE_PATTERN_ROW BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK
    FIELD_COLUMN_TILE_PATTERN_ROW BLANK, LEFT_MARKER, RIGHT_MARKER, BLANK, BLANK, LEFT_MARKER, RIGHT_MARKER, BLANK
    FIELD_COLUMN_TILE_PATTERN_ROW BLANK, LEFT_MARKER, RIGHT_MARKER, BLANK, BLANK, BLANK, BLANK, BLANK
    FIELD_COLUMN_TILE_PATTERN_ROW BLANK, BLANK, BLANK, BLANK, BLANK, LEFT_MARKER, RIGHT_MARKER, BLANK
    FIELD_COLUMN_TILE_PATTERN_ROW BLANK, LEFT_MARKER, RIGHT_MARKER, BLANK, BLANK, LEFT_MARKER, RIGHT_MARKER, BLANK
    FIELD_COLUMN_TILE_PATTERN_ROW BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK

StartNextRound::
    xor a
    ld [ROUND_RESULT_PENDING], a
    ld [ROUND_RESULT_CODE], a
    ld [EGG_COUNT_ONES], a
    ld [EGG_COUNT_TENS], a
    ld [EGG_COUNT_HUNDREDS], a
    ld [EGG_COUNT_UNUSED_BYTE], a
    ld [RESULT_CLEAR_FLAG], a
    ld [RESULT_GAME_OVER_FLAG], a
    ld [LINK_PENDING_FIELD_RISE], a
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_FIELD_EVENT_PAYLOAD], a
    ld [EGG_TEXT_ALT_ANIM_PHASE], a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, SetupNextRoundSinglePlayerSettings

    call ApplyGameSettings
    jr ContinueNextRoundSetup

SetupNextRoundSinglePlayerSettings:
    ld hl, ACTIVE_LEVEL
    ld a, [hl]
    cp ACTIVE_LEVEL_MAX
    jr z, SkipNextRoundActiveLevelIncrement

    inc [hl]

SkipNextRoundActiveLevelIncrement:
    ld a, [BGM_INDEX]
    call PlaySound
    call AdvanceLevelDisplayDigits

ContinueNextRoundSetup:
    call UpdateNextDisplay
    call InitPlayfieldBoardAndPieceState
    call InitPlayerCursorObject
    call DrawAllColumns
    call DrawGameplayBgTopRowIfNoResultFlow
    call Draw1PCountdownDigitTileSlots
    call InitDropCursorAnimationState
    call InitBlinkState
    call ClearDropAnimationState
    call ResetPieceDisplayBlinkTimer
    call ClearLevelDisplayTickCounter
    call ClearLinkRoundState
    call QueueLinkFieldOccupancyCount
    call ClearRoundTimerDigitsAndResume
    xor a
    ld [ROUND_TIMER_STOPPED], a
    ld [TOTAL_TIMER_STOPPED], a
    ret


InitPlayerCursorObject::
    ld a, FIELD_COLUMN_TILE_PATTERN_INITIAL_INDEX
    ld [FIELD_COLUMN_TILE_PATTERN_INDEX], a
    ld hl, SPRITE_OBJECT_SLOT_0
    ld [hl], SPRITE_OBJECT_TYPE_PLAYER_CURSOR
    inc hl
    inc hl
    ld [hl], PLAYER_CURSOR_INITIAL_FRAME
    inc hl
    inc hl
    ld [hl], PLAYER_CURSOR_INITIAL_BASE_Y
    inc hl
    inc hl
    ld [hl], PLAYER_CURSOR_INITIAL_BASE_X
    ret


    call DrawGameplayBgTopRowIfNoResultFlow

FillTilemapRectByCoord::
    ld e, a
    call CalcTilemapAddress
    ld d, b

FillTilemapRectRowLoop:
    ld a, e

FillTilemapRectColumnLoop:
    ld [hl+], a
    dec b
    jr nz, FillTilemapRectColumnLoop

    ld b, d
    ld a, BG_MAP_ROW_STRIDE
    sub d
    add l
    ld l, a
    jr nc, AdvanceTilemapRectRow

    inc h

AdvanceTilemapRectRow:
    dec c
    jr nz, FillTilemapRectRowLoop

    ret


DrawSequentialTileRowByCoord::
    call CalcTilemapAddress
    ld a, c

DrawSequentialTileRowLoop:
    ld [hl+], a
    inc a
    dec b
    jr nz, DrawSequentialTileRowLoop

    ret


InitPlayfield::
    xor a
    ld [RESULT_CLEAR_FLAG], a
    ld [RESULT_GAME_OVER_FLAG], a
    ld [EGG_TEXT_ALT_ANIM_PHASE], a
    ld [EGG_COUNT_ONES], a
    ld [EGG_COUNT_TENS], a
    ld [EGG_COUNT_HUNDREDS], a
    ld [EGG_COUNT_UNUSED_BYTE], a
    call UpdateNextDisplay
    call InitPlayfieldBoardAndPieceState
    call InitPlayerCursorObject
    call DrawAllColumns
    call DrawGameplayBgTopRowIfNoResultFlow
    call ResetScoreAccumulatorAndDigits
    call Draw1PCountdownDigitTileSlots
    call InitDropCursorAnimationState
    call InitBlinkState
    call ClearDropAnimationState
    call ResetPieceDisplayBlinkTimer
    call ClearLevelDisplayTickCounter
    call ClearEggCountDigitsAndUnusedByte
    call QueueLinkFieldOccupancyCount
    call InitResultRecordsIfNeeded
    call ClearTotalTimerDigitsAndResume
    call ClearRoundTimerDigitsAndResume
    call ClearLinkRoundState
    xor a
    ld [ROUND_TIMER_STOPPED], a
    ld [TOTAL_TIMER_STOPPED], a
    ret


DrawLevelDisplayDigits::
    call CalcTilemapAddress
    ld a, [LEVEL_DISPLAY_ONES]
    add PLAYFIELD_DIGIT_TILE_BASE
    ld [hl], a
    dec hl
    ld a, [LEVEL_DISPLAY_TENS]
    add PLAYFIELD_DIGIT_TILE_BASE
    ld [hl], a
    ret


AdvanceATypeLevelDisplayDigits::
    ld a, [GAME_TYPE]
    and a
    ret nz

    ld hl, PROGRESSION_LEVEL
    inc [hl]
    ld a, [LEVEL_DISPLAY_TENS]
    cp LEVEL_DISPLAY_MAX_DIGIT
    jr nz, IncrementATypeLevelDisplayDigits

    ld a, [LEVEL_DISPLAY_ONES]
    cp LEVEL_DISPLAY_MAX_DIGIT
    jr nz, IncrementATypeLevelDisplayDigits

    ret


IncrementATypeLevelDisplayDigits:
    ld a, [LEVEL_DISPLAY_ONES]
    inc a
    cp LEVEL_DISPLAY_DIGIT_LIMIT
    jr c, StoreATypeLevelDisplayOnes

    ld hl, LEVEL_DISPLAY_TENS
    inc [hl]
    xor a

StoreATypeLevelDisplayOnes:
    ld [LEVEL_DISPLAY_ONES], a
    ret


AdvanceLevelDisplayDigits::
    ld hl, PROGRESSION_LEVEL
    inc [hl]
    ld a, [LEVEL_DISPLAY_TENS]
    cp LEVEL_DISPLAY_MAX_DIGIT
    jr nz, IncrementLevelDisplayDigits

    ld a, [LEVEL_DISPLAY_ONES]
    cp LEVEL_DISPLAY_MAX_DIGIT
    jr nz, IncrementLevelDisplayDigits

    ret


IncrementLevelDisplayDigits:
    ld a, [LEVEL_DISPLAY_ONES]
    inc a
    cp LEVEL_DISPLAY_DIGIT_LIMIT
    jr c, StoreLevelDisplayOnes

    ld hl, LEVEL_DISPLAY_TENS
    inc [hl]
    xor a

StoreLevelDisplayOnes:
    ld [LEVEL_DISPLAY_ONES], a
    ret


ClearLevelDisplayTickCounter::
    xor a
    ld [LEVEL_DISPLAY_TICK_COUNTER], a
    ret


DrawEggTextFrame0::
    xor a
    jr DrawEggTextFrameByIndex

    ret


UnusedInlineEggTextFrame0Drawer:
    call CalcTilemapAddress
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE
    inc hl
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $01
    ld de, EGG_TEXT_INLINE_TWO_TILE_ROW_DELTA
    add hl, de
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $02
    inc hl
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $03
    inc hl
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $04
    add hl, de
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $05
    inc hl
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $06
    inc hl
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $07
    ld de, EGG_TEXT_INLINE_THREE_TILE_ROW_DELTA
    add hl, de
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $08
    inc hl
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $09
    inc hl
    ld [hl], EGG_TEXT_FRAME0_TILE_BASE + $0a
    ret


DrawEggTextFrameByIndex::
    push af
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, ReturnFromEggTextFrameDrawIn2P

    ld a, [GAME_TYPE]
    and a
    jr nz, UseBTypeEggTextCoord

    ld hl, PLAYFIELD_EGG_DISPLAY_A_TYPE_COORD
    jr SelectEggTextFrame

UseBTypeEggTextCoord:
    ld hl, PLAYFIELD_EGG_DISPLAY_B_TYPE_COORD

SelectEggTextFrame:
    pop af
    and a
    jr z, UseEggTextFrame0

    cp EGG_TEXT_FRAME_1
    jr z, UseEggTextFrame1

    jr UseEggTextFrame2

UseEggTextFrame0:
    ld de, EggTextFrame0TileRows
    jr DrawEggTextFrameRows

UseEggTextFrame1:
    ld de, EggTextFrame1TileRows
    jr DrawEggTextFrameRows

UseEggTextFrame2:
    ld de, EggTextFrame2TileRows

DrawEggTextFrameRows:
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    ret


ReturnFromEggTextFrameDrawIn2P:
    pop af
    ret

MACRO EGG_TEXT_TILE_ROW_2
    db \1, \2, DRAW_STRING_ROW_END
ENDM

MACRO EGG_TEXT_TILE_ROW_3
    db \1, \2, \3, DRAW_STRING_ROW_END
ENDM

MACRO EGG_TEXT_TILE_ROW_4
    db \1, \2, \3, \4, DRAW_STRING_ROW_END
ENDM

EggTextFrame0TileRows::
    EGG_TEXT_TILE_ROW_2 EGG_TEXT_FRAME0_TILE_BASE, EGG_TEXT_FRAME0_TILE_BASE + $01
    EGG_TEXT_TILE_ROW_2 EGG_TEXT_FRAME0_TILE_BASE + $02, EGG_TEXT_FRAME0_TILE_BASE + $03
    EGG_TEXT_TILE_ROW_3 EGG_TEXT_FRAME0_TILE_BASE + $05, EGG_TEXT_FRAME0_TILE_BASE + $06, EGG_TEXT_FRAME0_TILE_BASE + $07
    EGG_TEXT_TILE_ROW_3 EGG_TEXT_FRAME0_TILE_BASE + $08, EGG_TEXT_FRAME0_TILE_BASE + $09, EGG_TEXT_FRAME0_TILE_BASE + $0a

EggTextFrame1TileRows::
    EGG_TEXT_TILE_ROW_2 EGG_TEXT_FRAME1_TILE_BASE, EGG_TEXT_FRAME1_TILE_BASE + $01
    EGG_TEXT_TILE_ROW_4 EGG_TEXT_FRAME1_TILE_BASE + $02, EGG_TEXT_FRAME1_TILE_BASE + $03, EGG_TEXT_FRAME1_TILE_BASE + $04, EGG_TEXT_ROW_FILL_TILE
    EGG_TEXT_TILE_ROW_4 EGG_TEXT_FRAME1_TILE_BASE + $05, EGG_TEXT_FRAME1_TILE_BASE + $06, EGG_TEXT_FRAME1_TILE_BASE + $07, EGG_TEXT_ROW_FILL_TILE
    EGG_TEXT_TILE_ROW_4 EGG_TEXT_FRAME1_TILE_BASE + $08, EGG_TEXT_FRAME1_TILE_BASE + $09, EGG_TEXT_FRAME1_TILE_BASE + $0a, EGG_TEXT_ROW_FILL_TILE

EggTextFrame2TileRows::
    EGG_TEXT_TILE_ROW_2 EGG_TEXT_FRAME0_TILE_BASE, EGG_TEXT_FRAME0_TILE_BASE + $01
    EGG_TEXT_TILE_ROW_4 EGG_TEXT_FRAME0_TILE_BASE + $02, EGG_TEXT_FRAME0_TILE_BASE + $03, EGG_TEXT_FRAME0_TILE_BASE + $04, EGG_TEXT_ROW_FILL_TILE
    EGG_TEXT_TILE_ROW_4 EGG_TEXT_FRAME2_ALT_TILE_BASE, EGG_TEXT_FRAME2_ALT_TILE_BASE + $01, EGG_TEXT_FRAME2_ALT_TILE_BASE + $02, EGG_TEXT_ROW_FILL_TILE
    EGG_TEXT_TILE_ROW_4 EGG_TEXT_FRAME2_ALT_TILE_BASE + $03, EGG_TEXT_FRAME2_ALT_TILE_BASE + $04, EGG_TEXT_FRAME2_ALT_LAST_TILE, EGG_TEXT_ROW_FILL_TILE

DrawPlayfieldEggCountDigits::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld a, [GAME_TYPE]
    and a
    jr z, UseATypeEggCountCoord

    ld hl, PLAYFIELD_EGG_COUNT_B_TYPE_COORD
    jr DrawPlayfieldEggCountDigitsAtCoord

UseATypeEggCountCoord:
    ld hl, PLAYFIELD_EGG_COUNT_A_TYPE_COORD

DrawPlayfieldEggCountDigitsAtCoord:
    call CalcTilemapAddress
    ld a, [EGG_COUNT_ONES]
    add EGG_COUNT_TILE_BASE
    ld [hl], a
    dec hl
    ld a, [EGG_COUNT_TENS]
    add EGG_COUNT_TILE_BASE
    ld [hl], a
    ret


IncrementEggCountAndRefreshDisplay::
    ld hl, EGG_COUNT_ONES
    inc [hl]
    ld a, [hl]
    cp EGG_COUNT_DIGIT_LIMIT
    jr c, RefreshEggCountDigitsAfterIncrement

    xor a
    ld [hl], a
    call StartEggTextPulse
    ld hl, EGG_COUNT_TENS
    inc [hl]
    ld a, [hl]
    cp EGG_COUNT_DIGIT_LIMIT
    jr c, RefreshEggCountDigitsAfterIncrement

    xor a
    ld [hl], a
    call EnableEggTextAltAnimation
    ld hl, EGG_COUNT_HUNDREDS
    inc [hl]
    ld a, [hl]
    cp EGG_COUNT_DIGIT_LIMIT
    jr c, RefreshEggCountDigitsAfterIncrement

    ld a, EGG_COUNT_MAX_DIGIT
    ld [hl-], a
    ld [hl-], a
    ld [hl], a

RefreshEggCountDigitsAfterIncrement:
    call DrawPlayfieldEggCountDigits
    ret


ClearEggCountDigitsAndUnusedByte::
    xor a
    ld [EGG_COUNT_ONES], a
    ld [EGG_COUNT_TENS], a
    ld [EGG_COUNT_HUNDREDS], a
    ld [EGG_COUNT_UNUSED_BYTE], a
    ret


ClearLinkRoundState::
    xor a
    ld [LINK_SEND_QUEUE_INDEX], a
    ld [LINK_PENDING_FIELD_RISE], a
    ld [LINK_SEND], a
    ld [LINK_RECV], a
    ld [LINK_UNUSED_STAGING_BYTE], a
    ld [LINK_SEND_QUEUE_0], a
    ld [LINK_SEND_QUEUE_1], a
    ld [LINK_FIELD_EVENT_PAYLOAD], a
    ret


DrawTitleLabels::
    ld hl, TITLE_LABEL_PLAYER_COORD
    ld de, TitleLabelTextPlayer
    call DrawStringToGrid
    ld hl, TITLE_LABEL_YOSHI_COORD
    ld de, TitleLabelTextYoshi
    call DrawStringToGrid
    call DrawTitlePlayerSelectionMarker
    ret

MACRO TITLE_LABEL_TEXT_ROW
    db \1, TITLE_LABEL_TEXT_SEPARATOR_TILE
    db TITLE_LABEL_TEXT_SHARED_TILE_BASE, TITLE_LABEL_TEXT_SHARED_TILE_BASE + $01
    db TITLE_LABEL_TEXT_SHARED_TILE_BASE + $02, TITLE_LABEL_TEXT_SHARED_TILE_BASE + $03
    db TITLE_LABEL_TEXT_SHARED_TILE_BASE + $04, TITLE_LABEL_TEXT_SHARED_TILE_BASE + $05
    db DRAW_STRING_ROW_END
ENDM

TitleLabelTextPlayer::
    TITLE_LABEL_TEXT_ROW TITLE_LABEL_PLAYER_PREFIX_TILE

TitleLabelTextYoshi::
    TITLE_LABEL_TEXT_ROW TITLE_LABEL_YOSHI_PREFIX_TILE

ProcessTitleInput::
    call TickTitlePlayerMarkerBlink
    ldh a, [JOYPAD_PRESSED]
    and a
    ret z

    bit PADB_DOWN, a
    jr nz, SelectTitleTwoPlayerMode

    bit PADB_UP, a
    jr nz, SelectTitleOnePlayerMode

    bit PADB_SELECT, a
    jr nz, ToggleTitlePlayerMode

    ret


SelectTitleTwoPlayerMode:
    ld a, [TWO_PLAYER_FLAG]
    inc a
    cp TITLE_PLAYER_MODE_COUNT
    ret nc

    ld [TWO_PLAYER_FLAG], a
    call DrawTitlePlayerSelectionMarker
    ret


SelectTitleOnePlayerMode:
    ld a, [TWO_PLAYER_FLAG]
    dec a
    cp TITLE_PLAYER_MODE_UNDERFLOW_SENTINEL
    ret z

    ld [TWO_PLAYER_FLAG], a
    call DrawTitlePlayerSelectionMarker
    ret


ToggleTitlePlayerMode:
    ld a, [TWO_PLAYER_FLAG]
    xor TITLE_PLAYER_MODE_TOGGLE_MASK
    ld [TWO_PLAYER_FLAG], a
    call DrawTitlePlayerSelectionMarker
    ret


DrawTitlePlayerSelectionMarker::
    ld hl, TITLE_LABEL_PLAYER_MARKER_COORD
    call CalcTilemapAddress
    ld [hl], TITLE_LABEL_MARKER_CLEAR_TILE
    ld hl, TITLE_LABEL_YOSHI_MARKER_COORD
    call CalcTilemapAddress
    ld [hl], TITLE_LABEL_MARKER_CLEAR_TILE
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, DrawTitleTwoPlayerSelectionMarker

    ld hl, TITLE_LABEL_PLAYER_MARKER_COORD
    call CalcTilemapAddress
    ld [hl], TITLE_LABEL_MARKER_SELECTED_TILE
    ret


DrawTitleTwoPlayerSelectionMarker:
    ld hl, TITLE_LABEL_YOSHI_MARKER_COORD
    call CalcTilemapAddress
    ld [hl], TITLE_LABEL_MARKER_SELECTED_TILE
    ret


ProcessOptionInput::
    ld a, TITLE_LINK_READY_BYTE
    ldh [rSB], a
    ld a, SERIAL_TRANSFER_EXTERNAL_CLOCK
    ldh [rSC], a
    ldh a, [JOYPAD_PRESSED]
    bit PADB_START, a
    jr z, PollTitleStartOrReceivedLink

    xor a
    ld [LINK_RECV], a
    ldh [SERIAL_DONE], a
    ld a, TITLE_LINK_START_BYTE
    ldh [rSB], a
    ld a, SERIAL_TRANSFER_INTERNAL_CLOCK
    ldh [rSC], a

PollTitleStartOrReceivedLink:
    ld a, [LINK_RECV]
    and a
    jr nz, HandleTitleLinkHandshakeByte

    ldh a, [JOYPAD_PRESSED]
    bit PADB_START, a
    ret z

    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, EnterPreplayInitFromTitle

    ret


HandleTitleLinkHandshakeByte:
    cp TITLE_LINK_START_BYTE
    jr nz, CheckTitleLinkMasterHandshake

    ld a, LINK_ROLE_SLAVE
    ld [LINK_ROLE], a
    ld a, TITLE_PLAYER_MODE_2P
    ld [TWO_PLAYER_FLAG], a
    jr AcceptTitleLinkHandshake

CheckTitleLinkMasterHandshake:
    cp TITLE_LINK_READY_BYTE
    ret nz

    ld a, LINK_ROLE_MASTER
    ld [LINK_ROLE], a

AcceptTitleLinkHandshake:
    xor a
    ld [LINK_RECV], a
    ld [LINK_SEND], a
    call WaitVBlank
    xor a
    ld [LINK_RECV], a
    ld [LINK_SEND], a

EnterPreplayInitFromTitle:
    xor a
    ldh [rSB], a
    ld a, GAME_STATE_PREPLAY_INIT
    ld [GAME_STATE], a
    ret


TickTitlePlayerMarkerBlink::
    ld hl, TITLE_PLAYER_MARKER_TIMER
    dec [hl]
    ret nz

    ld a, [TITLE_PLAYER_MARKER_PHASE]
    and a
    jr z, DrawTitlePlayerMarkerTopPhase

    ld a, TITLE_PLAYER_MARKER_BOTTOM_DURATION
    ld [TITLE_PLAYER_MARKER_TIMER], a
    xor a
    ld [TITLE_PLAYER_MARKER_PHASE], a
    call DrawTitlePlayerMarkerBottom
    ret


DrawTitlePlayerMarkerTopPhase:
    ld a, TITLE_PLAYER_MARKER_TOP_DURATION
    ld [TITLE_PLAYER_MARKER_TIMER], a
    ld a, TITLE_PLAYER_MARKER_TOP_PHASE
    ld [TITLE_PLAYER_MARKER_PHASE], a
    call DrawTitlePlayerMarkerTop
    ret


DrawTitlePlayerMarkerTop::
    ld hl, TITLE_PLAYER_MARKER_ROW0_COORD
    ld b, TITLE_PLAYER_MARKER_WIDTH
    ld c, TITLE_PLAYER_MARKER_TOP_ROW0_TILE
    call DrawSequentialTileRowByCoord
    ld hl, TITLE_PLAYER_MARKER_ROW1_COORD
    ld b, TITLE_PLAYER_MARKER_WIDTH
    ld c, TITLE_PLAYER_MARKER_TOP_ROW1_TILE
    call DrawSequentialTileRowByCoord
    ret


DrawTitlePlayerMarkerBottom::
    ld hl, TITLE_PLAYER_MARKER_ROW0_COORD
    ld b, TITLE_PLAYER_MARKER_WIDTH
    ld c, TITLE_PLAYER_MARKER_BOTTOM_ROW0_TILE
    call DrawSequentialTileRowByCoord
    ld hl, TITLE_PLAYER_MARKER_ROW1_COORD
    ld b, TITLE_PLAYER_MARKER_WIDTH
    ld c, TITLE_PLAYER_MARKER_BOTTOM_ROW1_TILE
    call DrawSequentialTileRowByCoord
    ret


UpdateNextDisplay::
    call FillGameTilemap
    call ClearSpriteObjectBuffer
    ld hl, PLAYFIELD_SIDE_PANEL_TOP_LEFT_COORD
    ld bc, PLAYFIELD_SIDE_PANEL_RECT_SIZE
    ld a, PLAYFIELD_SIDE_PANEL_FILL_TILE
    call FillTilemapRectByCoord
    call Draw1PPlayfieldSidePanelLabelRow0
    call DrawPlayfieldSidePanelLabelRow1
    call DrawPlayfieldLevelDigits
    call DrawPlayfieldSpeedValue
    call DrawPlayfieldEggDisplay
    call DrawPlayfieldBottomColumnMarkers
    call DrawBTypeTimerHeaderAndDigits
    call DrawTwoPlayerPlayfieldRoleHeaders
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, UseTwoPlayerPlayfieldBlankRows

    ld a, [GAME_TYPE]
    and a
    jr nz, UseBTypePlayfieldBlankRows

    call BlankATypePlayfieldSidePanelRows
    ret


UseBTypePlayfieldBlankRows:
    call BlankBTypePlayfieldSidePanelRows
    ret


UseTwoPlayerPlayfieldBlankRows:
    call BlankTwoPlayerPlayfieldSidePanelRows
    ret


ClearSpriteObjectBuffer::
    ld hl, SPRITE_OBJECTS
    ld b, SPRITE_OBJECT_BUFFER_CLEAR_BYTES
    xor a

ClearSpriteObjectBufferLoop:
    ld [hl+], a
    dec b
    jr nz, ClearSpriteObjectBufferLoop

    ret


Draw1PPlayfieldSidePanelLabelRow0::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld a, [GAME_TYPE]
    and a
    jr nz, SelectBTypePlayfieldLabelRow0

    ld hl, PLAYFIELD_LABEL_ROW0_A_TYPE_COORD
    jp DrawPlayfieldSidePanelLabelRow0AtCoord


SelectBTypePlayfieldLabelRow0:
    ld hl, PLAYFIELD_LABEL_ROW0_B_TYPE_COORD

DrawPlayfieldSidePanelLabelRow0AtCoord::
    ld bc, PLAYFIELD_LABEL_ROW0_TILE_ROW
    call DrawSequentialTileRowByCoord
    ret


DrawPlayfieldSidePanelLabelRow1::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, Select1PPlayfieldLabelRow1

    ld hl, PLAYFIELD_LABEL_ROW1_2P_COORD
    jr DrawPlayfieldSidePanelLabelRow1AtCoord

Select1PPlayfieldLabelRow1:
    ld a, [GAME_TYPE]
    and a
    jr nz, SelectBTypePlayfieldLabelRow1

    ld hl, PLAYFIELD_LABEL_ROW1_A_TYPE_COORD
    jr DrawPlayfieldSidePanelLabelRow1AtCoord

SelectBTypePlayfieldLabelRow1:
    ld hl, PLAYFIELD_LABEL_ROW1_B_TYPE_COORD

DrawPlayfieldSidePanelLabelRow1AtCoord:
    ld bc, PLAYFIELD_LABEL_ROW1_TILE_ROW
    call DrawSequentialTileRowByCoord
    ret


DrawPlayfieldLevelDigits::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, Select1PPlayfieldLevelDigitsCoord

    ld hl, PLAYFIELD_LEVEL_DIGITS_2P_COORD
    jr DrawLevelDisplayDigitsAtPlayfieldCoord

Select1PPlayfieldLevelDigitsCoord:
    ld a, [GAME_TYPE]
    and a
    jr nz, SelectBTypePlayfieldLevelDigitsCoord

    ld hl, PLAYFIELD_LEVEL_DIGITS_A_TYPE_COORD
    jr DrawLevelDisplayDigitsAtPlayfieldCoord

SelectBTypePlayfieldLevelDigitsCoord:
    ld hl, PLAYFIELD_LEVEL_DIGITS_B_TYPE_COORD

DrawLevelDisplayDigitsAtPlayfieldCoord:
    call DrawLevelDisplayDigits
    ret


DrawPlayfieldSpeedValue::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, Select1PPlayfieldSpeedValueCoord

    ld hl, PLAYFIELD_SPEED_VALUE_2P_COORD
    jr DrawSpeedValueAtPlayfieldCoord

Select1PPlayfieldSpeedValueCoord:
    ld a, [GAME_TYPE]
    and a
    jr nz, SelectBTypePlayfieldSpeedValueCoord

    ld hl, PLAYFIELD_SPEED_VALUE_A_TYPE_COORD
    jr DrawSpeedValueAtPlayfieldCoord

SelectBTypePlayfieldSpeedValueCoord:
    ld hl, PLAYFIELD_SPEED_VALUE_B_TYPE_COORD

DrawSpeedValueAtPlayfieldCoord:
    ld b, PLAYFIELD_SPEED_VALUE_WIDTH
    ld c, PLAYFIELD_SPEED_VALUE_TILE_BASE
    ld a, [ACTIVE_SPEED]
    sla a
    add c
    ld c, a
    call DrawSequentialTileRowByCoord
    ret


DrawPlayfieldEggDisplay::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, Select1PPlayfieldEggDisplayCoord

    ret


Select1PPlayfieldEggDisplayCoord:
    ld a, [GAME_TYPE]
    and a
    jr nz, SelectBTypePlayfieldEggDisplayCoord

    ld hl, PLAYFIELD_EGG_DISPLAY_A_TYPE_COORD
    jr DrawEggDisplayAtPlayfieldCoord

SelectBTypePlayfieldEggDisplayCoord:
    ld hl, PLAYFIELD_EGG_DISPLAY_B_TYPE_COORD

DrawEggDisplayAtPlayfieldCoord:
    call DrawEggTextFrame0
    call DrawPlayfieldEggCountDigits
    ret


DrawPlayfieldBottomColumnMarkers::
    ld hl, PLAYFIELD_BOTTOM_COLUMN_MARKERS_COORD
    call CalcTilemapAddress
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_LEFT_TILE
    inc l
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_RIGHT_TILE
    inc l
    inc l
    inc l
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_LEFT_TILE
    inc l
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_RIGHT_TILE
    inc l
    inc l
    inc l
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_LEFT_TILE
    inc l
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_RIGHT_TILE
    inc l
    inc l
    inc l
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_LEFT_TILE
    inc l
    ld [hl], PLAYFIELD_BOTTOM_COLUMN_MARKER_RIGHT_TILE
    ret


BlankATypePlayfieldSidePanelRows::
    ld hl, PLAYFIELD_A_TYPE_BLANK_ROW0_COORD
    call CalcTilemapAddress
    ld a, PLAYFIELD_SIDE_PANEL_BLANK_TILE
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, PLAYFIELD_A_TYPE_BLANK_ROW1_COORD
    call CalcTilemapAddress
    ld a, PLAYFIELD_SIDE_PANEL_BLANK_TILE
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ret


BlankBTypePlayfieldSidePanelRows::
    ld hl, PLAYFIELD_B_TYPE_BLANK_ROW0_COORD
    call CalcTilemapAddress
    ld a, PLAYFIELD_SIDE_PANEL_BLANK_TILE
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, PLAYFIELD_B_TYPE_BLANK_ROW1_COORD
    call CalcTilemapAddress
    ld a, PLAYFIELD_SIDE_PANEL_BLANK_TILE
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, PLAYFIELD_B_TYPE_BLANK_ROW2_COORD
    call CalcTilemapAddress
    ld a, PLAYFIELD_SIDE_PANEL_BLANK_TILE
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ret


BlankTwoPlayerPlayfieldSidePanelRows::
    ld hl, TWO_PLAYER_BLANK_ROW0_COORD
    call CalcTilemapAddress
    ld a, PLAYFIELD_SIDE_PANEL_BLANK_TILE
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, TWO_PLAYER_BLANK_ROW1_COORD
    call CalcTilemapAddress
    ld a, PLAYFIELD_SIDE_PANEL_BLANK_TILE
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ret


DrawBTypeTimerHeaderAndDigits::
    ld a, [GAME_TYPE]
    and a
    ret z

    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld hl, PLAYFIELD_B_TYPE_TIMER_HEADER_COORD
    ld bc, PLAYFIELD_B_TYPE_TIMER_HEADER_TILE_ROW
    call DrawSequentialTileRowByCoord
    call DrawPlayfieldRoundTimerDigits
    ret


DrawPlayfieldRoundTimerDigits::
    ld hl, PLAYFIELD_ROUND_TIMER_COORD
    call DrawRoundTimerDigits
    ret


UnusedDrawPlayfieldGameTypeHeader:
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld hl, PLAYFIELD_GAME_TYPE_HEADER_COORD
    call CalcTilemapAddress
    ld a, [GAME_TYPE]
    and a
    jr nz, UseBTypePlayfieldGameTypeHeaderTile

    ld a, PLAYFIELD_GAME_TYPE_A_TILE
    jr DrawPlayfieldGameTypeHeaderText

UseBTypePlayfieldGameTypeHeaderTile:
    ld a, PLAYFIELD_GAME_TYPE_B_TILE

DrawPlayfieldGameTypeHeaderText:
    ld [hl], a
    ld hl, PLAYFIELD_GAME_TYPE_HEADER_TEXT_COORD
    ld bc, PLAYFIELD_GAME_TYPE_HEADER_TILE_ROW
    call DrawSequentialTileRowByCoord
    ret


DrawTwoPlayerPlayfieldRoleHeaders::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret z

    ld a, [LINK_ROLE]
    cp LINK_ROLE_SLAVE
    jr z, DrawTwoPlayerRoleHeadersForSlave

    ld hl, TWO_PLAYER_ROLE_HEADER_TOP_COORD
    ld bc, TWO_PLAYER_ROLE_HEADER_TILE_ROW_0
    call DrawSequentialTileRowByCoord
    ld hl, TWO_PLAYER_ROLE_HEADER_BOTTOM_COORD
    ld bc, TWO_PLAYER_ROLE_HEADER_TILE_ROW_1
    call DrawSequentialTileRowByCoord
    ret


DrawTwoPlayerRoleHeadersForSlave:
    ld hl, TWO_PLAYER_ROLE_HEADER_BOTTOM_COORD
    ld bc, TWO_PLAYER_ROLE_HEADER_TILE_ROW_0
    call DrawSequentialTileRowByCoord
    ld hl, TWO_PLAYER_ROLE_HEADER_TOP_COORD
    ld bc, TWO_PLAYER_ROLE_HEADER_TILE_ROW_1
    call DrawSequentialTileRowByCoord
    ret


DrawRoundTimerDigits::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    call CalcTilemapAddress
    ld de, ROUND_TIMER_DIGITS
    ld a, [de]
    add PLAYFIELD_DIGIT_TILE_BASE
    inc de
    ld a, [de]
    add PLAYFIELD_DIGIT_TILE_BASE
    ld [hl+], a
    inc de
    ld a, PLAYFIELD_ROUND_TIMER_SEPARATOR_TILE
    ld [hl+], a
    ld a, [de]
    add PLAYFIELD_DIGIT_TILE_BASE
    ld [hl+], a
    inc de
    ld a, [de]
    add PLAYFIELD_DIGIT_TILE_BASE
    ld [hl], a
    ret


ClearRoundTimerDigitsAndResume::
    ld hl, ROUND_TIMER_DIGITS
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [ROUND_TIMER_STOPPED], a
    ret


ClearTotalTimerDigitsAndResume::
    ld hl, TOTAL_TIMER_DIGITS
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [TOTAL_TIMER_STOPPED], a
    ret


StartEggTextPulse::
    ld a, EGG_TEXT_PULSE_INITIAL_TIMER
    ld [EGG_TEXT_PULSE_TIMER], a
    ld a, EGG_TEXT_PULSE_INITIAL_STEPS
    ld [EGG_TEXT_PULSE_STEPS], a
    ld a, EGG_TEXT_PULSE_INITIAL_FRAME
    ld [EGG_TEXT_PULSE_FRAME], a
    ret


UpdateEggTextAnimation::
    ld a, [EGG_TEXT_ALT_ANIM_ACTIVE]
    and a
    ret nz

    ld hl, EGG_TEXT_PULSE_TIMER
    ld a, [hl]
    and a
    ret z

    dec [hl]
    ret nz

    ld hl, EGG_TEXT_PULSE_STEPS
    dec [hl]
    jr z, ReturnAfterEggTextPulseComplete

    ld a, EGG_TEXT_PULSE_RELOAD
    ld [EGG_TEXT_PULSE_TIMER], a
    ld a, [EGG_TEXT_PULSE_FRAME]
    cp EGG_TEXT_FRAME_1
    jr z, DrawEggTextPulseFrame2

    ld a, EGG_TEXT_FRAME_1
    call DrawEggTextFrameByIndex
    jr ToggleEggTextPulseFrame

DrawEggTextPulseFrame2:
    ld a, EGG_TEXT_FRAME_2
    call DrawEggTextFrameByIndex

ToggleEggTextPulseFrame:
    ld a, [EGG_TEXT_PULSE_FRAME]
    xor EGG_TEXT_FRAME_TOGGLE_MASK
    ld [EGG_TEXT_PULSE_FRAME], a
    ret


ReturnAfterEggTextPulseComplete:
    ret


ToggleEggTextAltAnimation::
    ld a, [EGG_TEXT_ALT_ANIM_PHASE]
    xor EGG_TEXT_ALT_PHASE_TOGGLE_MASK
    ld [EGG_TEXT_ALT_ANIM_PHASE], a
    ld a, [EGG_TEXT_ALT_ANIM_ACTIVE]
    and a
    ret z

    ld a, [EGG_TEXT_ALT_ANIM_PHASE]
    inc a
    call DrawEggTextFrameByIndex
    ret


EnableEggTextAltAnimation::
    ld a, EGG_TEXT_ALT_ANIM_ACTIVE_VALUE
    ld [EGG_TEXT_ALT_ANIM_ACTIVE], a
    ret


CopyNextBgMapShadowSlice::
    ldh a, [BG_MAP_SHADOW_COPY_ENABLE_FLAG]
    and a
    ret z

    ld hl, sp+$00
    ld a, h
    ldh [VBLANK_SAVED_SP_HI], a
    ld a, l
    ldh [VBLANK_SAVED_SP_LO], a
    ldh a, [BG_MAP_COPY_PHASE]
    and a
    jr z, SelectBgMapShadowCopySlice0

    dec a
    jr z, SelectBgMapShadowCopySlice1

    ld hl, BG_MAP_SHADOW_COPY_SLICE_2
    ld sp, hl
    ld hl, BG_MAP_VRAM_COPY_SLICE_2
    xor a
    jr StoreNextBgMapShadowCopyPhase

SelectBgMapShadowCopySlice0:
    ld hl, BG_MAP_SHADOW_COPY_SLICE_0
    ld sp, hl
    ld hl, BG_MAP_VRAM_COPY_SLICE_0
    inc a
    jr StoreNextBgMapShadowCopyPhase

SelectBgMapShadowCopySlice1:
    ld hl, BG_MAP_SHADOW_COPY_SLICE_1
    ld sp, hl
    ld hl, BG_MAP_VRAM_COPY_SLICE_1
    ld a, BG_MAP_COPY_PHASE_SLICE_2

StoreNextBgMapShadowCopyPhase:
    ldh [BG_MAP_COPY_PHASE], a
    ld b, BG_MAP_COPY_SLICE_ROWS

CopyBgMapShadowSliceRowLoop:
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    ld a, BG_MAP_COPY_NEXT_ROW_DELTA
    add l
    ld l, a
    jr nc, CountBgMapShadowCopySliceRow

    inc h

CountBgMapShadowCopySliceRow:
    dec b
    jr nz, CopyBgMapShadowSliceRowLoop

    ldh a, [VBLANK_SAVED_SP_HI]
    ld h, a
    ldh a, [VBLANK_SAVED_SP_LO]
    ld l, a
    ld sp, hl
    ret


VRAMCopyDMA::
    ldh a, [VRAM_COPY_BLOCKS]
    and a
    ret z

    ld hl, sp+$00
    ld a, h
    ldh [VBLANK_SAVED_SP_HI], a
    ld a, l
    ldh [VBLANK_SAVED_SP_LO], a
    ldh a, [VRAM_SRC_LO]
    ld l, a
    ldh a, [VRAM_SRC_HI]
    ld h, a
    ld sp, hl
    ldh a, [VRAM_DST_LO]
    ld l, a
    ldh a, [VRAM_DST_HI]
    ld h, a
    ldh a, [VRAM_COPY_BLOCKS]
    ld b, a
    xor a
    ldh [VRAM_COPY_BLOCKS], a

CopyQueuedVram16ByteBlockLoop:
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc l
    pop de
    ld [hl], e
    inc l
    ld [hl], d
    inc hl
    dec b
    jr nz, CopyQueuedVram16ByteBlockLoop

    ld a, l
    ldh [VRAM_DST_LO], a
    ld a, h
    ldh [VRAM_DST_HI], a
    ld hl, sp+$00
    ld a, l
    ldh [VRAM_SRC_LO], a
    ld a, h
    ldh [VRAM_SRC_HI], a
    ldh a, [VBLANK_SAVED_SP_HI]
    ld h, a
    ldh a, [VBLANK_SAVED_SP_LO]
    ld l, a
    ld sp, hl
    ret


VBlankHandler::
    push af
    push bc
    push de
    push hl
    call CopyNextBgMapShadowSlice
    call RandomNext
    call VRAMCopyDMA
    call OAM_DMA_HRAM
    call TimerTickCore
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call UpdateSprites
    ldh a, [SCX_SHADOW]
    ldh [rSCX], a
    ldh a, [SCY_SHADOW]
    ldh [rSCY], a
    ldh a, [WY_SHADOW]
    ldh [rWY], a
    ldh a, [VBLANK_SYNC]
    and a
    jr z, CheckVBlankBusyCounter

    xor a
    ldh [VBLANK_SYNC], a

CheckVBlankBusyCounter:
    ldh a, [VBLANK_BUSY]
    and a
    jr z, ContinueVBlankRuntimeUpdates

    dec a
    ldh [VBLANK_BUSY], a

ContinueVBlankRuntimeUpdates:
    call UpdateSoundChannels
    call UpdateCountdownTimer
    call UpdateElapsedTimers
    ld a, [WAVE_UPDATE]
    and a
    jr z, ContinueVBlankAfterWaveUpdate

    call HandleWaveUpdate

ContinueVBlankAfterWaveUpdate:
    call CheckJoypadRaw
    jr nz, ReturnFromVBlankHandler

    jp ResetJoypadStateAndReinitOnRelease


ReturnFromVBlankHandler:
    pop hl
    pop de
    pop bc
    pop af
    reti


CheckJoypadRaw::
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
    and P1_INPUT_BITS_MASK
    ret


WaitVBlank::
    ld a, VBLANK_SYNC_REQUESTED
    ldh [VBLANK_SYNC], a

WaitVBlankSyncLoop:
    halt
    ldh a, [VBLANK_SYNC]
    and a
    jr nz, WaitVBlankSyncLoop

    ret


UnusedWaitSelectThenStartOrSelectPress::
    ldh a, [JOYPAD_PRESSED]
    and PADF_SELECT
    ret z

    ldh a, [JOYPAD_HELD]
    push af
    ldh a, [JOYPAD_RAW]
    push af
    ldh a, [JOYPAD_PRESSED]
    push af

WaitJoypadStartOrSelectPressLoop:
    halt
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and PADF_START_OR_SELECT
    jr z, WaitJoypadStartOrSelectPressLoop

    pop af
    and PADF_SELECT_CLEAR_MASK
    ldh [JOYPAD_PRESSED], a
    pop af
    and PADF_SELECT_CLEAR_MASK
    ldh [JOYPAD_RAW], a
    pop af
    and PADF_SELECT_CLEAR_MASK
    ldh [JOYPAD_HELD], a
    ret


HandleWaveUpdate::
    xor a
    ldh [rNR30], a
    ld hl, _AUD3WAVERAM

FillWaveRamWithFFLoop:
    ld a, SOUND_WAVE_RAM_FILL_VALUE
    ld [hl+], a
    ld a, l
    cp SOUND_WAVE_RAM_END_LOW
    jr nz, FillWaveRamWithFFLoop

    ld a, AUD3ENA_ON
    ldh [rNR30], a
    ldh a, [rNR51]
    or SOUND_WAVE_OUTPUT_TERMINAL_BITS
    ldh [rNR51], a
    ld a, SOUND_WAVE_TRIGGER_VALUE
    ldh [rNR34], a
    ld hl, UpdateSoundChannels

ReadWaveUpdateSourceByte:
    ld b, WAVE_UPDATE_BITS_PER_SOURCE_BYTE
    ld a, [hl]
    cp SOUND_WAVE_UPDATE_END_MARKER
    jr z, FinishWavePatternUpdate

    ld d, a
    jr OutputWaveUpdateBit

WaveUpdateBitDelay:
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

OutputWaveUpdateBit:
    push hl
    pop hl
    xor a
    sla d
    rra
    rra
    rra
    ldh [rNR32], a
    dec b
    jr nz, WaveUpdateBitDelay

    inc hl
    jr ReadWaveUpdateSourceByte

FinishWavePatternUpdate:
    xor a
    ld [WAVE_UPDATE], a
    ldh a, [rNR51]
    and SOUND_WAVE_OUTPUT_TERMINAL_CLEAR_MASK
    ldh [rNR51], a
    ret


UpdateElapsedTimers::
    ld a, [SOUND_PAUSE_FLAG]
    and a
    ret nz

    ld a, [ROUND_TIMER_STOPPED]
    and a
    jr nz, CheckTotalElapsedTimer

    ld hl, ROUND_TIMER_FRAME_COUNTER
    call TickElapsedTimerDigits

CheckTotalElapsedTimer:
    ld a, [TOTAL_TIMER_STOPPED]
    and a
    ret nz

    ld hl, TOTAL_TIMER_FRAME_COUNTER

TickElapsedTimerDigits::
    inc [hl]
    ld a, [hl]
    cp ELAPSED_TIMER_FRAMES_PER_SECOND
    jr c, ReturnFromTickElapsedTimerDigits

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp ELAPSED_TIMER_DECIMAL_DIGIT_LIMIT
    jr c, ReturnFromTickElapsedTimerDigits

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp ELAPSED_TIMER_SECONDS_TENS_LIMIT
    jr c, ReturnFromTickElapsedTimerDigits

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp ELAPSED_TIMER_DECIMAL_DIGIT_LIMIT
    jr c, ReturnFromTickElapsedTimerDigits

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp ELAPSED_TIMER_DECIMAL_DIGIT_LIMIT
    jr nc, ClampElapsedTimerDigits

ReturnFromTickElapsedTimerDigits:
    ret


ClampElapsedTimerDigits:
    ld a, ELAPSED_TIMER_MAX_ONES
    ld [hl+], a
    ld [hl+], a
    ld [hl], ELAPSED_TIMER_MAX_SECONDS_TENS
    inc hl
    ld [hl], a
    ret


UpdateSoundChannels::
    ld c, $00

UpdateSoundChannelLoop:
    ld b, $00
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr z, AdvanceSoundChannelIndex

    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nc, TickActiveSoundChannel

    ld a, [SOUND_PAUSE_FLAG]
    and a
    jr z, TickActiveSoundChannel

    bit SOUND_PAUSE_MUTE_APPLIED_BIT, a
    jr nz, AdvanceSoundChannelIndex

    set SOUND_PAUSE_MUTE_APPLIED_BIT, a
    ld [SOUND_PAUSE_FLAG], a
    xor a
    ldh [rNR51], a
    ldh [rNR30], a
    ld a, AUD3ENA_ON
    ldh [rNR30], a
    jr AdvanceSoundChannelIndex

TickActiveSoundChannel:
    call TickSoundChannel

AdvanceSoundChannelIndex:
    ld a, c
    inc c
    cp SOUND_LAST_CHANNEL_INDEX
    jr nz, UpdateSoundChannelLoop

    ret


TickSoundChannel::
    ld b, $00
    ld hl, SOUND_CH_NOTE_LENGTH
    add hl, bc
    ld a, [hl]
    cp SOUND_NOTE_LENGTH_SEQUENCE_STEP_VALUE
    jp z, SoundSequenceStep

    dec a
    ld [hl], a
    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nc, UpdateSoundChannelModulation

    ld hl, SOUND_BGM_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr z, UpdateSoundChannelModulation

    ret


UpdateSoundChannelModulation:
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_DUTY_ROTATE_ACTIVE_BIT, [hl]
    jr z, CheckSoundPitchSlideFlag

    call SoundUpdate1

CheckSoundPitchSlideFlag:
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_PITCH_SLIDE_ACTIVE_BIT, [hl]
    jr z, CheckSoundChannelDelay

    jp UpdateSoundPitchSlide


CheckSoundChannelDelay:
    ld hl, SOUND_CH_DELAY
    add hl, bc
    ld a, [hl]
    and a
    jr z, CheckSoundVibratoDepth

    dec [hl]
    ret


CheckSoundVibratoDepth:
    ld hl, SOUND_CH_VIBRATO_DEPTH
    add hl, bc
    ld a, [hl]
    and a
    jr nz, CheckSoundVibratoPhase

    ret


CheckSoundVibratoPhase:
    ld d, a
    ld hl, SOUND_CH_VIBRATO_PHASE
    add hl, bc
    ld a, [hl]
    and SOUND_VIBRATO_PHASE_COUNTER_MASK
    and a
    jr z, ApplySoundVibratoStep

    dec [hl]
    ret


ApplySoundVibratoStep:
    ld a, [hl]
    swap [hl]
    or [hl]
    ld [hl], a
    ld hl, SOUND_CH_FREQ_LO_BASE
    add hl, bc
    ld e, [hl]
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_VIBRATO_SUBTRACT_BIT, [hl]
    jr z, ApplySoundVibratoPositiveStep

    res SOUND_CH_VIBRATO_SUBTRACT_BIT, [hl]
    ld a, d
    and SOUND_VIBRATO_DEPTH_SUBTRACT_MASK
    ld d, a
    ld a, e
    sub d
    jr nc, UseSoundVibratoSubtractedFrequency

    ld a, $00

UseSoundVibratoSubtractedFrequency:
    jr StoreSoundVibratoFrequency

ApplySoundVibratoPositiveStep:
    set SOUND_CH_VIBRATO_SUBTRACT_BIT, [hl]
    ld a, d
    and SOUND_VIBRATO_DEPTH_ADD_MASK
    swap a
    add e
    jr nc, StoreSoundVibratoFrequency

    ld a, SOUND_VIBRATO_FREQ_MAX

StoreSoundVibratoFrequency:
    ld d, a
    ld b, SOUND_REGISTER_FREQ_LO_OFFSET
    call SoundUpdate3
    ld [hl], d
    ret


SoundSequenceStep::
    ld hl, SOUND_CH_DELAY_RELOAD
    add hl, bc
    ld a, [hl]
    ld hl, SOUND_CH_DELAY
    add hl, bc
    ld [hl], a
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    res SOUND_CH_PITCH_SLIDE_ACTIVE_BIT, [hl]
    res SOUND_CH_PITCH_SLIDE_DESCENDING_BIT, [hl]
    call CountdownSequence
    ret


CountdownSequence::
    call SoundUpdate2
    ld d, a
    cp SOUND_SEQUENCE_END_COMMAND
    jp nz, DispatchSoundNonEndCommand

    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_RETURN_PENDING_BIT, [hl]
    jr nz, ReturnFromSoundSubsequence

    ld a, c
    cp SOUND_CHANNEL3_INDEX
    jr nc, EndSoundSequenceChannel3Plus

    jr DisableSoundChannelOutputOnEnd

EndSoundSequenceChannel3Plus:
    res SOUND_CH_NOTE_OUTPUT_GATE_BIT, [hl]
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    res SOUND_CH_GATE_SUPPRESS_BIT, [hl]
    cp SOUND_SECONDARY_WAVE_CHANNEL_INDEX
    jr nz, CheckChannel6DeferredSoundEnd

    ld a, AUD3ENA_OFF
    ldh [rNR30], a
    ld a, AUD3ENA_ON
    ldh [rNR30], a

CheckChannel6DeferredSoundEnd:
    jr nz, SkipSoundChannelMuteOnEnd

    ld a, [SOUND_DEFERRED_ID]
    and a
    jr z, SkipSoundChannelMuteOnEnd

    xor a
    ld [SOUND_DEFERRED_ID], a
    jr DisableSoundChannelOutputOnEnd

SkipSoundChannelMuteOnEnd:
    jr ClearSoundChannelAfterEnd

ReturnFromSoundSubsequence:
    res SOUND_CH_RETURN_PENDING_BIT, [hl]
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, SOUND_CH_SEQUENCE_PTRS
    add hl, de
    push hl
    ld hl, SOUND_CH_RETURN_PTRS
    add hl, de
    ld e, l
    ld d, h
    pop hl
    ld a, [de]
    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl], a
    jp CountdownSequence


DisableSoundChannelOutputOnEnd:
    ld b, $00
    ld hl, SoundChannelDisableMaskTable
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a

ClearSoundChannelAfterEnd:
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr nc, CheckSoundBgmActiveIdForNr50Restore

    jr ClearSoundChannelActiveId

CheckSoundBgmActiveIdForNr50Restore:
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr z, ClearSoundChannelActiveId

    jr c, RestoreSoundNr50AfterBgmEnd

    jr ClearSoundChannelActiveId

RestoreSoundNr50AfterBgmEnd:
    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr z, RestoreSoundNr50FromBackup

    call UpdateChannel
    ret c

RestoreSoundNr50FromBackup:
    ld a, [SOUND_NR50_BACKUP]
    ldh [rNR50], a
    xor a
    ld [SOUND_NR50_BACKUP], a

ClearSoundChannelActiveId:
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, bc
    ld [hl], b
    ret


DispatchSoundNonEndCommand:
    cp SOUND_SUBSEQUENCE_CALL_COMMAND
    jp nz, CheckSoundLoopJumpCommand

    call SoundUpdate2
    push af
    call SoundUpdate2
    ld d, a
    pop af
    ld e, a
    push de
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, SOUND_CH_SEQUENCE_PTRS
    add hl, de
    push hl
    ld hl, SOUND_CH_RETURN_PTRS
    add hl, de
    ld e, l
    ld d, h
    pop hl
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl-]
    ld [de], a
    pop de
    ld [hl], e
    inc hl
    ld [hl], d
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set SOUND_CH_RETURN_PENDING_BIT, [hl]
    jp CountdownSequence


CheckSoundLoopJumpCommand:
    cp SOUND_LOOP_JUMP_COMMAND
    jp nz, CheckSoundLengthEnvelopeCommand

    call SoundUpdate2
    ld e, a
    and a
    jr z, JumpSoundSequenceToLoopTarget

    ld b, $00
    ld hl, SOUND_CH_LOOP_COUNTER
    add hl, bc
    ld a, [hl]
    cp e
    jr nz, IncrementSoundLoopCounter

    ld a, SOUND_COUNTER_INIT_VALUE
    ld [hl], a
    call SoundUpdate2
    call SoundUpdate2
    jp CountdownSequence


IncrementSoundLoopCounter:
    inc a
    ld [hl], a

JumpSoundSequenceToLoopTarget:
    call SoundUpdate2
    push af
    call SoundUpdate2
    ld b, a
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, SOUND_CH_SEQUENCE_PTRS
    add hl, de
    pop af
    ld [hl+], a
    ld [hl], b
    jp CountdownSequence


CheckSoundLengthEnvelopeCommand:
    and SOUND_COMMAND_HIGH_NIBBLE_MASK
    cp SOUND_LENGTH_ENVELOPE_COMMAND_BASE
    jp nz, CheckSoundExtendedCommand

    ld a, d
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    ld b, $00
    ld hl, SOUND_CH_LENGTH_SCALE
    add hl, bc
    ld [hl], a
    ld a, c
    cp SOUND_CHANNEL3_INDEX
    jr z, ContinueSoundCommandParsing

    call SoundUpdate2
    ld d, a
    ld a, c
    cp SOUND_PRIMARY_WAVE_CHANNEL_INDEX
    jr z, UseMainWavePatternSelector

    cp SOUND_SECONDARY_WAVE_CHANNEL_INDEX
    jr nz, StoreSoundEnvelope

    ld hl, SOUND_WAVE_PATTERN_ALT
    jr StoreWavePatternSelectorAndEnvelope

UseMainWavePatternSelector:
    ld hl, SOUND_WAVE_PATTERN_MAIN

StoreWavePatternSelectorAndEnvelope:
    ld a, d
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    ld [hl], a
    ld a, d
    and SOUND_WAVE_LEVEL_PARAM_BITS
    sla a
    ld d, a

StoreSoundEnvelope:
    ld b, $00
    ld hl, SOUND_CH_ENVELOPE
    add hl, bc
    ld [hl], d

ContinueSoundCommandParsing:
    jp CountdownSequence


CheckSoundExtendedCommand:
    ld a, d
    cp SOUND_FREQ_CARRY_TOGGLE_COMMAND
    jr nz, CheckSoundVibratoCommand

    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    ld a, [hl]
    xor SOUND_CH_FREQ_CARRY_MASK
    ld [hl], a
    jp CountdownSequence


CheckSoundVibratoCommand:
    cp SOUND_VIBRATO_COMMAND
    jr nz, CheckSoundPitchSlideCommand

    call SoundUpdate2
    ld b, $00
    ld hl, SOUND_CH_DELAY
    add hl, bc
    ld [hl], a
    ld hl, SOUND_CH_DELAY_RELOAD
    add hl, bc
    ld [hl], a
    call SoundUpdate2
    ld d, a
    and SOUND_COMMAND_HIGH_NIBBLE_MASK
    swap a
    ld b, $00
    ld hl, SOUND_CH_VIBRATO_DEPTH
    add hl, bc
    srl a
    ld e, a
    adc b
    swap a
    or e
    ld [hl], a
    ld a, d
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    ld d, a
    ld hl, SOUND_CH_VIBRATO_PHASE
    add hl, bc
    swap a
    or d
    ld [hl], a
    jp CountdownSequence


CheckSoundPitchSlideCommand:
    cp SOUND_PITCH_SLIDE_COMMAND
    jr nz, CheckSoundDutyLengthCommand

    call SoundUpdate2
    ld b, $00
    ld hl, SOUND_CH_SLIDE_TICKS
    add hl, bc
    ld [hl], a
    call SoundUpdate2
    ld d, a
    and SOUND_COMMAND_HIGH_NIBBLE_MASK
    swap a
    ld b, a
    ld a, d
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    call SoundUpdate5
    ld b, $00
    ld hl, SOUND_CH_SLIDE_TARGET_HI
    add hl, bc
    ld [hl], d
    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, bc
    ld [hl], e
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set SOUND_CH_PITCH_SLIDE_ACTIVE_BIT, [hl]
    call SoundUpdate2
    ld d, a
    jp ProcessSoundNoteCommand


CheckSoundDutyLengthCommand:
    cp SOUND_DUTY_LENGTH_COMMAND
    jr nz, CheckSoundTempoCommand

    call SoundUpdate2
    rrca
    rrca
    and SOUND_DUTY_BITS_MASK
    ld b, $00
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld [hl], a
    jp CountdownSequence


CheckSoundTempoCommand:
    cp SOUND_TEMPO_COMMAND
    jr nz, CheckSoundOutputMaskCommand

    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nc, StoreSfxTempo

    call SoundUpdate2
    ld [SOUND_MAIN_TEMPO_HI], a
    call SoundUpdate2
    ld [SOUND_MAIN_TEMPO_LO], a
    xor a
    ld [SOUND_CH_TEMPO_ACCUM], a
    ld [SOUND_CH_TEMPO_ACCUM + 1], a
    ld [SOUND_CH_TEMPO_ACCUM + 2], a
    ld [SOUND_CH_TEMPO_ACCUM + 3], a
    jr ContinueAfterSoundTempoCommand

StoreSfxTempo:
    call SoundUpdate2
    ld [SOUND_SFX_TEMPO_HI], a
    call SoundUpdate2
    ld [SOUND_SFX_TEMPO_LO], a
    xor a
    ld [SOUND_CH_TEMPO_ACCUM + 4], a
    ld [SOUND_CH_TEMPO_ACCUM + 5], a
    ld [SOUND_CH_TEMPO_ACCUM + 6], a
    ld [SOUND_CH_TEMPO_ACCUM + 7], a

ContinueAfterSoundTempoCommand:
    jp CountdownSequence


CheckSoundOutputMaskCommand:
    cp SOUND_OUTPUT_MASK_COMMAND
    jr nz, CheckNestedSoundCommand

    call SoundUpdate2
    ld [SOUND_OUTPUT_MASK], a
    jp CountdownSequence


CheckNestedSoundCommand:
    cp SOUND_NESTED_SOUND_COMMAND
    jr nz, CheckSoundDutyRotateCommand

    call SoundUpdate2
    push bc
    call SoundEngine
    pop bc
    ld a, [SOUND_DEFERRED_ID]
    and a
    jr nz, ContinueAfterNestedSoundCommand

    ld a, [SOUND_BGM_ACTIVE_ID + 3]
    ld [SOUND_DEFERRED_ID], a
    xor a
    ld [SOUND_BGM_ACTIVE_ID + 3], a

ContinueAfterNestedSoundCommand:
    jp CountdownSequence


CheckSoundDutyRotateCommand:
    cp SOUND_DUTY_ROTATE_COMMAND
    jr nz, CheckSoundMasterVolumeCommand

    call SoundUpdate2
    ld b, $00
    ld hl, SOUND_CH_DUTY_ROTATE
    add hl, bc
    ld [hl], a
    and SOUND_DUTY_BITS_MASK
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld [hl], a
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set SOUND_CH_DUTY_ROTATE_ACTIVE_BIT, [hl]
    jp CountdownSequence


CheckSoundMasterVolumeCommand::
    cp SOUND_MASTER_VOLUME_COMMAND
    jr nz, CheckSoundVisualUpdateCommand

    call SoundUpdate2
    ldh [rNR50], a
    jp CountdownSequence


CheckSoundVisualUpdateCommand:
    cp SOUND_VISUAL_UPDATE_COMMAND
    jr nz, CheckSoundGateFlagCommand

    push af
    push bc
    push de
    push hl
    call ApplySoundVisualUpdateCommand
    pop hl
    pop de
    pop bc
    pop af
    jp CountdownSequence


CheckSoundGateFlagCommand:
    cp SOUND_GATE_FLAG_COMMAND
    jr nz, CheckSoundOctaveCommand

    ld b, $00
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    set SOUND_CH_GATE_SUPPRESS_BIT, [hl]
    jp CountdownSequence


CheckSoundOctaveCommand:
    and SOUND_COMMAND_HIGH_NIBBLE_MASK
    cp SOUND_OCTAVE_COMMAND_BASE
    jr nz, CheckSoundExtendedNoteCommand

    ld hl, SOUND_CH_OCTAVE
    ld b, $00
    add hl, bc
    ld a, d
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    ld [hl], a
    jp CountdownSequence


CheckSoundExtendedNoteCommand:
    cp SOUND_EXTENDED_NOTE_COMMAND_BASE
    jr nz, CheckSoundSweepCommand

    ld a, c
    cp SOUND_CHANNEL3_INDEX
    jr c, CheckSoundSweepCommand

    ld b, $00
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    bit SOUND_CH_GATE_SUPPRESS_BIT, [hl]
    jr nz, CheckSoundSweepCommand

    call ProcessSoundNoteCommand
    ld d, a
    ld b, $00
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld a, [hl]
    or d
    ld d, a
    ld b, SOUND_REGISTER_DUTY_LENGTH_OFFSET
    call SoundUpdate3
    ld [hl], d
    call SoundUpdate2
    ld d, a
    ld b, SOUND_REGISTER_ENVELOPE_OFFSET
    call SoundUpdate3
    ld [hl], d
    call SoundUpdate2
    ld e, a
    ld a, c
    cp SOUND_LAST_CHANNEL_INDEX
    ld a, $00
    jr z, ContinueExtendedSoundNoteCommand

    push de
    call SoundUpdate2
    pop de

ContinueExtendedSoundNoteCommand:
    ld d, a
    push de
    call WriteSoundChannelLengthRegister
    call UpdateSoundChannelOutputMask
    pop de
    call ProcessNote
    ret


CheckSoundSweepCommand:
    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr c, CheckChannel3NestedSoundCommand

    ld a, d
    cp SOUND_SWEEP_COMMAND
    jr nz, CheckChannel3NestedSoundCommand

    ld b, $00
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    bit SOUND_CH_GATE_SUPPRESS_BIT, [hl]
    jr nz, CheckChannel3NestedSoundCommand

    call SoundUpdate2
    ldh [rNR10], a
    jp CountdownSequence


CheckChannel3NestedSoundCommand:
    ld a, c
    cp SOUND_CHANNEL3_INDEX
    jr nz, ProcessSoundNoteCommand

    ld a, d
    and SOUND_COMMAND_HIGH_NIBBLE_MASK
    cp SOUND_CHANNEL3_NESTED_COMMAND_BASE
    jr z, ReadChannel3NestedSoundOperand

    jr nc, ProcessSoundNoteCommand

    swap a
    ld b, a
    ld a, d
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    ld d, a
    ld a, b
    push de
    push bc
    jr TriggerChannel3NestedSoundIfAllowed

ReadChannel3NestedSoundOperand:
    ld a, d
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    push af
    push bc
    call SoundUpdate2

TriggerChannel3NestedSoundIfAllowed:
    ld d, a
    ld a, [SOUND_DEFERRED_ID]
    and a
    jr nz, ContinueAfterChannel3NestedSound

    ld a, d
    call SoundEngine

ContinueAfterChannel3NestedSound:
    pop bc
    pop de

ProcessSoundNoteCommand::
    ld a, d
    push af
    and SOUND_COMMAND_LOW_NIBBLE_MASK
    inc a
    ld b, $00
    ld e, a
    ld d, b
    ld hl, SOUND_CH_LENGTH_SCALE
    add hl, bc
    ld a, [hl]
    ld l, b
    call SoundUpdate4
    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nc, UseSfxOrFixedSoundTempo

UseMainSoundTempo:
    ld a, [SOUND_MAIN_TEMPO_HI]
    ld d, a
    ld a, [SOUND_MAIN_TEMPO_LO]
    ld e, a
    jr StoreScaledSoundNoteLength

UseSfxOrFixedSoundTempo:
    ld d, SOUND_FIXED_TEMPO_HI
    ld e, SOUND_FIXED_TEMPO_LO
    cp SOUND_LAST_CHANNEL_INDEX
    jr z, StoreScaledSoundNoteLength

    ld a, [SOUND_SFX_TEMPO_HI]
    ld d, a
    ld a, [SOUND_SFX_TEMPO_LO]
    ld e, a

StoreScaledSoundNoteLength:
    ld a, l
    ld b, $00
    ld hl, SOUND_CH_TEMPO_ACCUM
    add hl, bc
    ld l, [hl]
    call SoundUpdate4
    ld e, l
    ld d, h
    ld hl, SOUND_CH_TEMPO_ACCUM
    add hl, bc
    ld [hl], e
    ld a, d
    ld hl, SOUND_CH_NOTE_LENGTH
    add hl, bc
    ld [hl], a
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    bit SOUND_CH_GATE_SUPPRESS_BIT, [hl]
    jr nz, ProcessSoundNoteHighNibble

    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_NOTE_OUTPUT_GATE_BIT, [hl]
    jr z, ProcessSoundNoteHighNibble

    pop hl
    ret


ProcessSoundNoteHighNibble:
    pop af
    and SOUND_COMMAND_HIGH_NIBBLE_MASK
    cp SOUND_REST_NOTE_COMMAND_BASE
    jr nz, ProcessPitchedSoundNote

    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nc, CheckSoundRestWaveChannel

    ld hl, SOUND_BGM_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr nz, ReturnFromSoundNoteCommand

CheckSoundRestWaveChannel:
    ld a, c
    cp SOUND_PRIMARY_WAVE_CHANNEL_INDEX
    jr z, MuteWaveChannelForRest

    cp SOUND_SECONDARY_WAVE_CHANNEL_INDEX
    jr nz, TriggerSoundRestHardwareWrite

MuteWaveChannelForRest:
    ld b, $00
    ld hl, SoundChannelDisableMaskTable
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a
    jr ReturnFromSoundNoteCommand

TriggerSoundRestHardwareWrite:
    ld b, SOUND_REGISTER_ENVELOPE_OFFSET
    call SoundUpdate3
    ld a, SOUND_REST_ENVELOPE_VALUE
    ld [hl+], a
    inc hl
    ld a, AUDHIGH_RESTART
    ld [hl], a

ReturnFromSoundNoteCommand:
    ret


ProcessPitchedSoundNote:
    swap a
    ld b, $00
    ld hl, SOUND_CH_OCTAVE
    add hl, bc
    ld b, [hl]
    call SoundUpdate5
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_PITCH_SLIDE_ACTIVE_BIT, [hl]
    jr z, ContinueAfterPitchSlideNoteInit

    call InitSoundPitchSlideForNote

ContinueAfterPitchSlideNoteInit:
    push de
    ld a, c
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nc, WriteSoundEnvelopeAndEnableOutput

    ld hl, SOUND_BGM_ACTIVE_ID
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    and a
    jr nz, ReturnIfPrimaryBgmAlreadyActive

    jr WriteSoundEnvelopeAndEnableOutput

ReturnIfPrimaryBgmAlreadyActive:
    pop de
    ret


WriteSoundEnvelopeAndEnableOutput:
    ld b, $00
    ld hl, SOUND_CH_ENVELOPE
    add hl, bc
    ld d, [hl]
    ld b, SOUND_REGISTER_ENVELOPE_OFFSET
    call SoundUpdate3
    ld [hl], d
    call WriteSoundChannelLengthRegister
    call UpdateSoundChannelOutputMask
    pop de
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_FREQ_CARRY_BIT, [hl]
    jr z, StoreSoundNoteBaseFrequency

    inc e
    jr nc, StoreSoundNoteBaseFrequency

    inc d

StoreSoundNoteBaseFrequency:
    ld hl, SOUND_CH_FREQ_LO_BASE
    add hl, bc
    ld [hl], e
    call ProcessNote
    ret


UpdateSoundChannelOutputMask::
    ld b, $00
    ld hl, SoundChannelEnableMaskTable
    add hl, bc
    ldh a, [rNR51]
    or [hl]
    ld d, a
    ld a, c
    cp SOUND_LAST_CHANNEL_INDEX
    jr z, ApplySoundOutputMask

    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nc, WriteSoundChannelOutputMask

    ld hl, SOUND_BGM_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr nz, WriteSoundChannelOutputMask

ApplySoundOutputMask:
    ld a, [SOUND_OUTPUT_MASK]
    ld hl, SoundChannelEnableMaskTable
    add hl, bc
    and [hl]
    ld d, a
    ldh a, [rNR51]
    ld hl, SoundChannelDisableMaskTable
    add hl, bc
    and [hl]

StoreSoundChannelOutputMask:
    or d
    ld d, a

WriteSoundChannelOutputMask:
    ld a, d
    ldh [rNR51], a
    ret


WriteSoundChannelLengthRegister::
    ld b, $00
    ld hl, SOUND_CH_NOTE_LENGTH
    add hl, bc
    ld d, [hl]
    ld a, c
    cp SOUND_PRIMARY_WAVE_CHANNEL_INDEX

CheckWaveChannelLengthRegisterWrite:
    jr z, WriteSoundLengthRegister

    cp SOUND_SECONDARY_WAVE_CHANNEL_INDEX
    jr z, WriteSoundLengthRegister

    ld a, d
    and SOUND_LENGTH_BITS_MASK
    ld d, a
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld a, [hl]
    or d
    ld d, a

WriteSoundLengthRegister:
    ld b, SOUND_REGISTER_DUTY_LENGTH_OFFSET
    call SoundUpdate3
    ld [hl], d
    ret


ProcessNote::
    ld a, c
    cp SOUND_PRIMARY_WAVE_CHANNEL_INDEX
    jr z, LoadWavePatternForSoundNote

    cp SOUND_SECONDARY_WAVE_CHANNEL_INDEX
    jr nz, WriteSoundFrequencyAndTrigger

LoadWavePatternForSoundNote:
    push de
    ld de, SOUND_WAVE_PATTERN_MAIN
    cp SOUND_PRIMARY_WAVE_CHANNEL_INDEX
    jr z, LookupSoundWavePatternPointer

    ld de, SOUND_WAVE_PATTERN_ALT

LookupSoundWavePatternPointer:
    ld a, [de]
    add a
    ld d, $00
    ld e, a
    ld hl, SoundWavePatternPointerTable
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld hl, _AUD3WAVERAM
    ld b, SOUND_WAVE_PATTERN_LAST_BYTE_INDEX
    ld a, AUD3ENA_OFF
    ldh [rNR30], a

CopySoundWavePatternToWaveRamLoop:
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, b
    dec b
    and a
    jr nz, CopySoundWavePatternToWaveRamLoop

    ld a, AUD3ENA_ON
    ldh [rNR30], a
    pop de

WriteSoundFrequencyAndTrigger:
    ld a, d
    or AUDHIGH_RESTART
    and SOUND_FREQ_HIGH_RESTART_KEEP_MASK
    ld d, a
    ld b, SOUND_REGISTER_FREQ_LO_OFFSET
    call SoundUpdate3
    ld [hl], e
    inc hl
    ld [hl], d
    ret


UpdateChannel::
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr nc, CheckBgmActiveIdForSequenceRewind

    jr ReturnNoSoundSequenceRewind

CheckBgmActiveIdForSequenceRewind:
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr z, ReturnNoSoundSequenceRewind

    jr c, RewindSoundSequencePointerAndReturnCarry

    jr ReturnNoSoundSequenceRewind

RewindSoundSequencePointerAndReturnCarry:
    ld hl, SOUND_CH_SEQUENCE_PTRS
    ld e, c
    ld d, $00
    sla e
    rl d
    add hl, de
    ld a, [hl]
    sub SOUND_SEQUENCE_REWIND_LOW_BYTE_DELTA
    ld [hl], a
    inc hl
    ld a, [hl]
    sbc SOUND_SEQUENCE_REWIND_HIGH_BYTE_DELTA
    ld [hl], a
    scf
    ret


ReturnNoSoundSequenceRewind:
    scf
    ccf
    ret


UpdateSoundPitchSlide:
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit SOUND_CH_PITCH_SLIDE_DESCENDING_BIT, [hl]
    jp nz, UpdateSoundPitchSlideDescending

    ld hl, SOUND_CH_FREQ_LO
    add hl, bc
    ld e, [hl]
    ld hl, SOUND_CH_FREQ_HI
    add hl, bc
    ld d, [hl]
    ld hl, SOUND_CH_SLIDE_STEP_INT
    add hl, bc
    ld l, [hl]
    ld h, b
    add hl, de
    ld d, h
    ld e, l
    ld hl, SOUND_CH_SLIDE_ACCUM
    add hl, bc
    push hl
    ld hl, SOUND_CH_SLIDE_STEP_FRAC
    add hl, bc
    ld a, [hl]
    pop hl
    add [hl]
    ld [hl], a
    ld a, $00
    adc e
    ld e, a
    ld a, $00
    adc d
    ld d, a
    ld hl, SOUND_CH_SLIDE_TARGET_HI
    add hl, bc
    ld a, [hl]
    cp d
    jp c, ClearSoundPitchSlideFlags

    jr nz, StoreSoundPitchSlideFrequency

    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, bc
    ld a, [hl]
    cp e
    jp c, ClearSoundPitchSlideFlags

    jr StoreSoundPitchSlideFrequency

UpdateSoundPitchSlideDescending:
    ld hl, SOUND_CH_FREQ_LO
    add hl, bc
    ld a, [hl]
    ld hl, SOUND_CH_FREQ_HI
    add hl, bc
    ld d, [hl]
    ld hl, SOUND_CH_SLIDE_STEP_INT
    add hl, bc
    ld e, [hl]
    sub e
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, SOUND_CH_SLIDE_STEP_FRAC
    add hl, bc
    ld a, [hl]
    add a
    ld [hl], a
    ld a, e
    sbc b
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, SOUND_CH_SLIDE_TARGET_HI
    add hl, bc
    ld a, d
    cp [hl]
    jr c, ClearSoundPitchSlideFlags

    jr nz, StoreSoundPitchSlideFrequency

    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, bc
    ld a, e
    cp [hl]
    jr c, ClearSoundPitchSlideFlags

StoreSoundPitchSlideFrequency:
    ld hl, SOUND_CH_FREQ_LO
    add hl, bc
    ld [hl], e
    ld hl, SOUND_CH_FREQ_HI
    add hl, bc
    ld [hl], d
    ld b, SOUND_REGISTER_FREQ_LO_OFFSET
    call SoundUpdate3
    ld a, e
    ld [hl+], a
    ld [hl], d
    ret


ClearSoundPitchSlideFlags::
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    res SOUND_CH_PITCH_SLIDE_ACTIVE_BIT, [hl]
    res SOUND_CH_PITCH_SLIDE_DESCENDING_BIT, [hl]
    ret


InitSoundPitchSlideForNote::
    ld hl, SOUND_CH_FREQ_HI
    add hl, bc
    ld [hl], d
    ld hl, SOUND_CH_FREQ_LO
    add hl, bc
    ld [hl], e
    ld hl, SOUND_CH_NOTE_LENGTH
    add hl, bc
    ld a, [hl]
    ld hl, SOUND_CH_SLIDE_TICKS
    add hl, bc
    sub [hl]
    jr nc, StoreSoundPitchSlideTickCount

    ld a, SOUND_PITCH_SLIDE_MIN_TICKS

StoreSoundPitchSlideTickCount:
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, bc
    ld a, e
    sub [hl]
    ld e, a
    ld a, d
    sbc b
    ld hl, SOUND_CH_SLIDE_TARGET_HI
    add hl, bc
    sub [hl]
    jr c, InitSoundPitchSlideAscending

    ld d, a
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set SOUND_CH_PITCH_SLIDE_DESCENDING_BIT, [hl]
    jr CalculateSoundPitchSlideStep

InitSoundPitchSlideAscending:
    ld hl, SOUND_CH_FREQ_HI
    add hl, bc
    ld d, [hl]
    ld hl, SOUND_CH_FREQ_LO
    add hl, bc
    ld e, [hl]
    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, bc
    ld a, [hl]
    sub e
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, SOUND_CH_SLIDE_TARGET_HI
    add hl, bc
    ld a, [hl]
    sub d
    ld d, a
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    res SOUND_CH_PITCH_SLIDE_DESCENDING_BIT, [hl]

CalculateSoundPitchSlideStep:
    ld hl, SOUND_CH_SLIDE_TICKS
    add hl, bc

DivideSoundPitchSlideDeltaLoop:
    inc b
    ld a, e
    sub [hl]
    ld e, a
    jr nc, DivideSoundPitchSlideDeltaLoop

    ld a, d
    and a
    jr z, StoreSoundPitchSlideStep

    dec a
    ld d, a
    jr DivideSoundPitchSlideDeltaLoop

StoreSoundPitchSlideStep:
    ld a, e
    add [hl]
    ld d, b
    ld b, $00
    ld hl, SOUND_CH_SLIDE_STEP_INT
    add hl, bc
    ld [hl], d
    ld hl, SOUND_CH_SLIDE_STEP_FRAC
    add hl, bc
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_ACCUM
    add hl, bc
    ld [hl], a
    ret


SoundUpdate1::
    ld b, $00
    ld hl, SOUND_CH_DUTY_ROTATE
    add hl, bc
    ld a, [hl]
    rlca
    rlca
    ld [hl], a
    and SOUND_DUTY_BITS_MASK
    ld d, a
    ld b, SOUND_REGISTER_DUTY_LENGTH_OFFSET
    call SoundUpdate3
    ld a, [hl]
    and SOUND_LENGTH_BITS_MASK
    or d
    ld [hl], a
    ret


SoundUpdate2::
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, SOUND_CH_SEQUENCE_PTRS
    add hl, de
    ld a, [hl+]
    ld e, a
    ld a, [hl-]
    ld d, a
    ld a, [de]
    inc de
    ld [hl], e
    inc hl
    ld [hl], d
    ret


SoundUpdate3::
    ld a, c
    ld hl, SoundRegisterOffsetTable
    add l
    jr nc, ReadSoundRegisterBaseOffset

    inc h

ReadSoundRegisterBaseOffset:
    ld l, a
    ld a, [hl]
    add b
    ld l, a
    ld h, SOUND_REGISTER_PAGE_HI
    ret


SoundUpdate4::
    ld h, $00

MultiplySoundValueLoop:
    srl a
    jr nc, DoubleSoundMultiplyAddend

    add hl, de

DoubleSoundMultiplyAddend:
    sla e
    rl d
    and a
    jr z, ReturnFromSoundMultiply

    jr MultiplySoundValueLoop

ReturnFromSoundMultiply:
    ret


SoundUpdate5::
    ld h, $00
    ld l, a
    add hl, hl
    ld d, h
    ld e, l
    ld hl, SoundPitchBaseTable
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld a, b

ShiftSoundPitchBaseLoop:
    cp SOUND_PITCH_SHIFT_TARGET_OCTAVE
    jr z, ReturnShiftedSoundPitchBase

    sra d
    rr e
    inc a
    jr ShiftSoundPitchBaseLoop

ReturnShiftedSoundPitchBase:
    ld a, SOUND_PITCH_FREQ_HIGH_BIAS
    add d
    ld d, a
    ret


SoundEngine::
    ld [SOUND_COMMAND_ID], a
    cp SND_STOP_ALL
    jp z, StopAllSoundHW

    cp SOUND_BGM_RESET_SKIP_MAX_COMMAND
    jp z, SoundLookupIndex

    jp c, SoundLookupIndex

    cp SOUND_BGM_RESET_MAX_COMMAND
    jr z, ResetSoundStateForBgmCommand

    jp nc, SoundLookupIndex

ResetSoundStateForBgmCommand:
    xor a
    ld [SOUND_STATUS], a
    ld [SOUND_DEFERRED_ID], a
    ld [SOUND_MAIN_TEMPO_LO], a
    ld [SOUND_WAVE_PATTERN_MAIN], a
    ld [SOUND_WAVE_PATTERN_ALT], a
    ld d, SOUND_PRIMARY_POINTER_CLEAR_BYTES
    ld hl, SOUND_CH_RETURN_PTRS
    call StopAllSound
    ld hl, SOUND_CH_SEQUENCE_PTRS
    call StopAllSound
    ld d, SOUND_PRIMARY_CHANNEL_COUNT
    ld hl, SOUND_CH_ACTIVE_ID
    call StopAllSound
    ld hl, SOUND_CH_FLAGS
    call StopAllSound
    ld hl, SOUND_CH_DUTY_LENGTH
    call StopAllSound
    ld hl, SOUND_CH_DUTY_ROTATE
    call StopAllSound
    ld hl, SOUND_CH_DELAY
    call StopAllSound
    ld hl, SOUND_CH_VIBRATO_DEPTH
    call StopAllSound
    ld hl, SOUND_CH_VIBRATO_PHASE
    call StopAllSound
    ld hl, SOUND_CH_FREQ_LO_BASE
    call StopAllSound
    ld hl, SOUND_CH_DELAY_RELOAD
    call StopAllSound
    ld hl, SOUND_CH_GATE_FLAGS
    call StopAllSound
    ld hl, SOUND_CH_SLIDE_TICKS
    call StopAllSound
    ld hl, SOUND_CH_SLIDE_STEP_INT
    call StopAllSound
    ld hl, SOUND_CH_SLIDE_STEP_FRAC
    call StopAllSound
    ld hl, SOUND_CH_SLIDE_ACCUM
    call StopAllSound
    ld hl, SOUND_CH_FREQ_HI
    call StopAllSound
    ld hl, SOUND_CH_FREQ_LO
    call StopAllSound
    ld hl, SOUND_CH_SLIDE_TARGET_HI
    call StopAllSound
    ld hl, SOUND_CH_SLIDE_TARGET_LO
    call StopAllSound
    ld a, SOUND_COUNTER_INIT_VALUE
    ld hl, SOUND_CH_LOOP_COUNTER
    call StopAllSound
    ld hl, SOUND_CH_NOTE_LENGTH
    call StopAllSound
    ld hl, SOUND_CH_LENGTH_SCALE
    call StopAllSound
    ld [SOUND_MAIN_TEMPO_HI], a
    ld a, SOUND_OUTPUT_MASK_ALL
    ld [SOUND_OUTPUT_MASK], a
    xor a
    ldh [rNR50], a
    ld a, SOUND_HW_RESET_SWEEP_ENV_VALUE
    ldh [rNR10], a
    ld a, $00
    ldh [rNR51], a
    xor a
    ldh [rNR30], a
    ld a, AUD3ENA_ON
    ldh [rNR30], a
    ld a, SOUND_NR50_RESET_VALUE
    ldh [rNR50], a
    jp StartSoundSequence


SoundLookupIndex::
    ld l, a
    ld e, a
    ld h, $00
    ld d, h
    add hl, hl
    add hl, de
    ld de, SoundIndexTable
    add hl, de
    ld a, h
    ld [SOUND_INDEX_PTR_HI], a
    ld a, l
    ld [SOUND_INDEX_PTR_LO], a
    ld a, [hl]
    and SOUND_INDEX_ENTRY_COUNT_BITS
    rlca
    rlca
    ld c, a

ExpandSoundIndexChannelEntryLoop:
    ld d, c
    ld a, c
    add a
    add c
    ld c, a
    ld b, $00
    ld a, [SOUND_INDEX_PTR_HI]
    ld h, a
    ld a, [SOUND_INDEX_PTR_LO]
    ld l, a
    add hl, bc
    ld c, d
    ld a, [hl]
    and SOUND_INDEX_ENTRY_CHANNEL_MASK
    ld e, a
    ld d, $00
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, de
    ld a, [hl]
    and a
    jr z, ClearSoundChannelStateForNewEntry

    ld a, e
    cp SOUND_LAST_CHANNEL_INDEX
    jr nz, CheckSoundCommandPriorityAgainstActiveId

    ld a, [SOUND_COMMAND_ID]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr nc, CheckSoundChannel7PriorityGate

    ret


CheckSoundChannel7PriorityGate:
    ld a, [hl]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr z, ClearSoundChannelStateForNewEntry

    jr c, ClearSoundChannelStateForNewEntry

CheckSoundCommandPriorityAgainstActiveId:
    ld a, [SOUND_COMMAND_ID]
    cp [hl]
    jr z, ClearSoundChannelStateForNewEntry

    jr c, ClearSoundChannelStateForNewEntry

    ret


ClearSoundChannelStateForNewEntry:
    xor a
    push de
    ld h, d
    ld l, e
    add hl, hl
    ld d, h
    ld e, l
    ld hl, SOUND_CH_RETURN_PTRS
    add hl, de
    ld [hl+], a
    ld [hl], a
    ld hl, SOUND_CH_SEQUENCE_PTRS
    add hl, de
    ld [hl+], a
    ld [hl], a
    pop de
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_FLAGS
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_DUTY_ROTATE
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_DELAY
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_VIBRATO_DEPTH
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_VIBRATO_PHASE
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_FREQ_LO_BASE
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_DELAY_RELOAD
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_TICKS
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_STEP_INT
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_STEP_FRAC
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_ACCUM
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_FREQ_HI
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_FREQ_LO
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_TARGET_HI
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, de
    ld [hl], a
    ld a, SOUND_COUNTER_INIT_VALUE
    ld hl, SOUND_CH_LOOP_COUNTER
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_NOTE_LENGTH
    add hl, de
    ld [hl], a
    ld hl, SOUND_CH_LENGTH_SCALE
    add hl, de
    ld [hl], a
    ld a, e
    cp SOUND_PRIMARY_CHANNEL_COUNT
    jr nz, ContinueSoundIndexChannelExpansion

    ld a, SOUND_HW_RESET_SWEEP_ENV_VALUE
    ldh [rNR10], a

ContinueSoundIndexChannelExpansion:
    ld a, c
    and a
    jp z, StartSoundSequence

    dec c
    jp ExpandSoundIndexChannelEntryLoop


StopAllSoundHW::
    ld a, SOUND_HW_RESET_ENABLE_VALUE
    ldh [rNR52], a
    ldh [rNR30], a
    xor a
    ldh [rNR51], a
    ldh [rNR32], a
    ld a, SOUND_HW_RESET_SWEEP_ENV_VALUE
    ldh [rNR10], a
    ldh [rNR12], a
    ldh [rNR22], a
    ldh [rNR42], a
    ld a, SOUND_HW_RESET_LENGTH_ON_VALUE
    ldh [rNR14], a
    ldh [rNR24], a
    ldh [rNR44], a
    ld a, SOUND_NR50_RESET_VALUE
    ldh [rNR50], a
    xor a
    ld [SOUND_STATUS], a
    ld [SOUND_DEFERRED_ID], a
    ld [SOUND_PAUSE_FLAG], a
    ld [SOUND_MAIN_TEMPO_LO], a
    ld [SOUND_SFX_TEMPO_LO], a
    ld [SOUND_WAVE_PATTERN_MAIN], a
    ld [SOUND_WAVE_PATTERN_ALT], a
    ld d, SOUND_HW_RESET_ZERO_CLEAR_BYTES
    ld hl, SOUND_CH_SEQUENCE_PTRS
    call StopAllSound
    ld a, SOUND_COUNTER_INIT_VALUE
    ld d, SOUND_HW_RESET_COUNTER_CLEAR_BYTES
    ld hl, SOUND_CH_NOTE_LENGTH
    call StopAllSound
    ld [SOUND_MAIN_TEMPO_HI], a
    ld [SOUND_SFX_TEMPO_HI], a
    ld a, SOUND_OUTPUT_MASK_ALL
    ld [SOUND_OUTPUT_MASK], a
    ret


StopAllSound::
    ld b, d

FillSoundStateRangeLoop:
    ld [hl+], a
    dec b
    jr nz, FillSoundStateRangeLoop

    ret


StartSoundSequence::
    ld a, [SOUND_COMMAND_ID]
    ld l, a
    ld e, a
    ld h, $00
    ld d, h
    add hl, hl
    add hl, de
    ld de, SoundIndexTable
    add hl, de
    ld e, l
    ld d, h
    ld hl, SOUND_CH_SEQUENCE_PTRS
    ld a, [de]
    ld b, a
    rlca
    rlca
    and SOUND_INDEX_ENTRY_COUNT_FIELD_MASK
    ld c, a
    ld a, b
    and SOUND_INDEX_ENTRY_CHANNEL_MASK
    ld b, c
    inc b
    inc de
    ld c, $00

FindSoundSequencePointerSlot:
    cp c
    jr z, InstallSoundSequenceChannelEntry

    inc c
    inc hl
    inc hl
    jr FindSoundSequencePointerSlot

InstallSoundSequenceChannelEntry:
    push hl
    push bc
    push af
    ld b, $00
    ld c, a
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, bc
    ld a, [SOUND_COMMAND_ID]
    ld [hl], a
    pop af
    cp SOUND_CHANNEL3_INDEX
    jr c, StoreSoundSequencePointerForChannel

    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set SOUND_CH_NOTE_OUTPUT_GATE_BIT, [hl]

StoreSoundSequencePointerForChannel:
    pop bc
    pop hl
    ld a, [de]
    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl+], a
    inc de
    inc c
    dec b
    ld a, b
    and a
    ld a, [de]
    inc de
    jr nz, FindSoundSequencePointerSlot

    ld a, [SOUND_COMMAND_ID]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr nc, CheckSoundCommandForBgmActiveState

    jr ReturnFromStartSoundSequence

CheckSoundCommandForBgmActiveState:
    ld a, [SOUND_COMMAND_ID]
    cp SOUND_BGM_ACTIVE_ID_GATE
    jr z, ReturnFromStartSoundSequence

    jr c, StoreSoundBgmActiveState

    jr ReturnFromStartSoundSequence

StoreSoundBgmActiveState:
    ld hl, SOUND_BGM_ACTIVE_ID
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld hl, SOUND_CH_SEQUENCE_PTRS + SOUND_SECONDARY_WAVE_SEQUENCE_PTR_OFFSET
    ld de, SoundWaveDutyData
    ld [hl], e
    inc hl
    ld [hl], d
    ld a, [SOUND_NR50_BACKUP]
    and a
    jr nz, ReturnFromStartSoundSequence

    ldh a, [rNR50]
    ld [SOUND_NR50_BACKUP], a
    ld a, SOUND_NR50_RESET_VALUE
    ldh [rNR50], a

ReturnFromStartSoundSequence:
    ret

MACRO SOUND_WAVE_DUTY_END
    db SOUND_SEQUENCE_END_COMMAND
ENDM

MACRO SOUND_REGISTER_OFFSET_ENTRY
    db \1
ENDM

MACRO SOUND_CHANNEL_MASK_ENTRY
    db \1
ENDM

MACRO SOUND_PITCH_BASE_ENTRY
    dw \1
ENDM

SoundWaveDutyData::
    SOUND_WAVE_DUTY_END

SoundRegisterOffsetTable::
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH1_BASE_LOW
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH2_BASE_LOW
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH3_BASE_LOW
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH4_BASE_LOW
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH1_BASE_LOW
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH2_BASE_LOW
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH3_BASE_LOW
    SOUND_REGISTER_OFFSET_ENTRY SOUND_REGISTER_CH4_BASE_LOW

SoundChannelDisableMaskTable::
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH1_CLEAR_MASK
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH2_CLEAR_MASK
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH3_CLEAR_MASK
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH4_CLEAR_MASK
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH1_CLEAR_MASK
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH2_CLEAR_MASK
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH3_CLEAR_MASK
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH4_CLEAR_MASK

SoundChannelEnableMaskTable::
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH1_TERMINAL_BITS
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH2_TERMINAL_BITS
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH3_TERMINAL_BITS
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH4_TERMINAL_BITS
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH1_TERMINAL_BITS
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH2_TERMINAL_BITS
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH3_TERMINAL_BITS
    SOUND_CHANNEL_MASK_ENTRY SOUND_OUTPUT_CH4_TERMINAL_BITS

SoundPitchBaseTable::
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_0
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_1
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_2
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_3
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_4
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_5
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_6
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_7
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_8
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_9
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_10
    SOUND_PITCH_BASE_ENTRY SOUND_PITCH_BASE_INDEX_11

MACRO SOUND_DUTY_LENGTH
    db SOUND_DUTY_LENGTH_COMMAND, \1
ENDM

MACRO SOUND_SWEEP
    db SOUND_SWEEP_COMMAND, \1
ENDM

MACRO SOUND_EXTENDED_NOTE
    db SOUND_EXTENDED_NOTE_COMMAND_BASE | \1
    db \2, \3, \4
ENDM

MACRO SOUND_SEQUENCE_END
    db SOUND_SEQUENCE_END_COMMAND
ENDM

MACRO SOUND_LENGTH_ENVELOPE
    db SOUND_LENGTH_ENVELOPE_COMMAND_BASE | \1, \2
ENDM

MACRO SOUND_CHANNEL3_LENGTH_SCALE
    db SOUND_LENGTH_ENVELOPE_COMMAND_BASE | \1
ENDM

MACRO SOUND_OCTAVE
    db SOUND_OCTAVE_COMMAND_BASE | \1
ENDM

MACRO SOUND_VIBRATO
    db SOUND_VIBRATO_COMMAND, \1, \2
ENDM

MACRO SOUND_TEMPO
    db SOUND_TEMPO_COMMAND, \1, \2
ENDM

MACRO SOUND_MASTER_VOLUME
    db SOUND_MASTER_VOLUME_COMMAND, \1
ENDM

MACRO SOUND_FREQ_CARRY_TOGGLE
    db SOUND_FREQ_CARRY_TOGGLE_COMMAND
ENDM

MACRO SOUND_VISUAL_UPDATE
    db SOUND_VISUAL_UPDATE_COMMAND
ENDM

MACRO SOUND_GATE_FLAG
    db SOUND_GATE_FLAG_COMMAND
ENDM

MACRO SOUND_PITCH_SLIDE
    db SOUND_PITCH_SLIDE_COMMAND, \1, \2, \3
ENDM

MACRO SOUND_REST_NOTE
    db SOUND_REST_NOTE_COMMAND_BASE | \1
ENDM

MACRO SOUND_CHANNEL3_NESTED_SOUND_NOTE
    db SOUND_CHANNEL3_NESTED_COMMAND_BASE | \1, \2
ENDM

MACRO SOUND_SUBSEQUENCE_CALL
    db SOUND_SUBSEQUENCE_CALL_COMMAND
    dw \1
ENDM

MACRO SOUND_LOOP_JUMP
    db SOUND_LOOP_JUMP_COMMAND, \1
    dw \2
ENDM

TitleBgmChannel0Sequence::
    db $ed, $00
SoundSequenceData_569c::
    db $b0, $f0, $77, $ec, $02, $e8, $dc, $b1, $e6, $a2, $e5, $22, $51, $e6, $a2, $e5
    db $22, $51, $32, $72, $a1, $32, $72, $a1, $91, $53, $91, $e4, $03, $e5, $93, $a0
    db $90, $a0, $50, $70, $50, $20, $50, $e6, $a3, $e5, $a3
SoundSequenceData_56c7::
    db $dc, $b3, $e6, $a2, $e5, $22, $51, $e6, $a2, $e5, $22, $51, $32, $72, $a1, $32
    db $20, $30, $20, $20, $30, $02, $22, $31, $02, $22, $31, $a1, $51, $e4, $01, $e5
    db $31, $e4, $11, $e5, $21, $e4, $21, $e5, $01, $e6, $a2, $e5, $22, $51, $e6, $a2
    db $e5, $22, $51, $32, $72, $a1, $32, $72, $a1, $52, $52, $a1, $52, $92, $e4, $01
    db $22, $e5, $a2, $51, $e4, $51, $31, $21, $01, $e5, $71, $e6, $a1, $e5, $31, $51
    db $71, $31, $a1, $71, $51, $e6, $a1, $e5, $21, $31, $51, $21, $71, $51, $51, $e6
    db $91, $e5, $01, $21, $31, $01, $71, $31, $51, $31, $21, $01, $21, $51, $e6, $a1
    db $e5, $51, $71, $e6, $a1, $e5, $31, $51, $71, $31, $a1, $71, $51, $e6, $a1, $e5
    db $21, $31, $51, $71, $91, $b1, $e4, $01, $e5, $51, $71, $91, $51, $71, $91, $e4
    db $01, $e5, $a1, $91, $71, $91, $dc, $b1, $a7, $fe, $00, $c7, $56
TitleBgmChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $08, $26
    SOUND_LENGTH_ENVELOPE $0c, $c1
    SOUND_OCTAVE $04
    db $21, $21, $01, $01
    SOUND_OCTAVE $05
    db $a1
    SOUND_OCTAVE $04
    db $01, $21
    SOUND_OCTAVE $05
    db $a0
    SOUND_LENGTH_ENVELOPE $06, $c1
    SOUND_OCTAVE $04
    db $20, $50
    SOUND_LENGTH_ENVELOPE $0c, $c1
    db $71, $71, $51, $51, $71, $51, $31, $21, $01, $01, $21, $21, $31, $31, $71, $31
    db $53, $33, $23, $a3
SoundSequenceData_5792::
    db $dc, $b3, $50, $71, $52, $21, $a1, $91, $a1, $91, $71, $3d, $00, $31, $02, $e5
    db $91, $e4, $71, $51, $71, $51, $23, $33, $43, $53, $50, $71, $52, $21, $a1, $91
    db $a1, $91, $72, $aa, $d6, $b1, $50, $70, $90, $a0, $dc, $b3, $e3, $01, $01, $e4
    db $a1, $a1, $91, $e3, $21, $01, $e4, $91, $dc, $a7, $a7, $dc, $30, $a7, $dc, $b7
    db $73, $35, $71, $51, $71, $53, $a5, $a1, $91, $a1, $93, $53, $e3, $03, $e4, $93
    db $a3, $e3, $03, $21, $01, $e4, $a1, $91, $73, $35, $a1, $91, $a1, $e3, $23, $03
    db $e4, $b3, $61, $71, $e3, $03, $e4, $a3, $91, $e3, $21, $01, $e4, $91, $dc, $b3
    db $a3, $a3, $dc, $b1, $a7, $fe, $00, $92, $57
TitleBgmChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $06, $12
    SOUND_SUBSEQUENCE_CALL SoundSequenceData_5a34
    SOUND_SUBSEQUENCE_CALL SoundSequenceData_5a34
    SOUND_SUBSEQUENCE_CALL SoundSequenceData_5a34
    SOUND_SUBSEQUENCE_CALL SoundSequenceData_5a34
SoundSequenceData_5819::
    db $e4, $eb, $00, $5a, $a0, $c0, $51, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00
    db $5a, $a0, $c0, $73, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4
    db $eb, $00, $5a, $a0, $c0, $51, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a
    db $a0, $c0, $73, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb
    db $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0
    db $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4
    db $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a
    db $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0
    db $e4, $eb, $00, $5a, $a0, $c0, $71, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00
    db $5a, $a0, $c0, $93, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4
    db $eb, $00, $5a, $a0, $c0, $71, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a
    db $a0, $c0, $93, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb
    db $00, $5a, $a0, $c0, $21, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0
    db $c0, $03, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00
    db $5a, $a0, $c0, $e5, $b1, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0
    db $c0, $e5, $a3, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4
    db $eb, $00, $5a, $a0, $c0, $51, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a
    db $a0, $c0, $73, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb
    db $00, $5a, $a0, $c0, $51, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0
    db $c0, $73, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00
    db $5a, $a0, $c0, $a1, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0
    db $e3, $03, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb
    db $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0
    db $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4
    db $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a
    db $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0
    db $e4, $eb, $00, $5a, $a0, $c0, $91, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00
    db $5a, $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50
    db $c0, $e4, $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45, $50, $c0, $e4, $eb
    db $00, $5a, $a0, $c0, $e3, $23, $e4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45
    db $50, $c0, $e4, $eb, $00, $5a, $a0, $c2, $e3, $eb, $00, $45, $50, $c0, $e4, $eb
    db $00, $5a, $a0, $c4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $fd
    db $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fd, $34
    db $5a, $fd, $34, $5a, $fd, $34, $5a, $fe, $00, $19, $58
SoundSequenceData_5a34::
    db $e4, $eb, $00, $5a, $a0, $c2, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a
    db $a0, $c4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00
    db $5a, $a0, $c2, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c4, $eb
    db $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $ff
TitleBgmChannel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $02, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $04, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $02, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $04, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $04
SoundSequenceData_5a89::
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $02, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $04, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $02, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $04, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $02, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $04, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $07, $04
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $04
    SOUND_LOOP_JUMP $00, SoundSequenceData_5a89
BgmOption0Channel0Sequence::
    SOUND_TEMPO $00, $92
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $08, $b2
    SOUND_OCTAVE $05
    db $73, $b1, $93, $b1
    SOUND_OCTAVE $04
    db $05, $21, $41, $21
    SOUND_OCTAVE $05
    db $71
    SOUND_OCTAVE $04
    db $21, $01
    SOUND_OCTAVE $05
    db $b1, $91, $b1, $75, $25
BgmPreview0Channel0Sequence::
    SOUND_TEMPO $00, $92
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $08, $b2
SoundSequenceData_5afd::
    db $e5, $75, $63, $21, $75, $91, $61, $91, $75, $b3, $71, $91, $71, $61, $41, $61
    db $91, $75, $63, $21, $75, $91, $61, $91, $75, $b3, $e4, $21, $01, $e5, $b1, $91
    db $71, $91, $b1, $73, $91, $b3, $91, $e4, $03, $e5, $91, $e4, $01, $e5, $b1, $91
    db $73, $91, $b3, $91, $e4, $05, $e5, $b5, $43, $b1, $93, $71, $b1, $91, $71, $b1
    db $91, $71, $43, $b1, $93, $71, $b5, $95, $d8, $83, $25, $b3, $71, $91, $71, $91
    db $73, $61, $25, $b3, $71, $91, $71, $91, $b1, $91, $61, $d8, $93, $25, $b3, $71
    db $91, $b1, $91, $73, $61, $25, $b3, $71, $91, $71, $61, $b1, $e4, $01, $e5, $b1
    db $d8, $b2, $95, $b5, $93, $e4, $21, $25, $e5, $95, $45, $93, $e4, $21, $25, $d8
    db $83, $e5, $23, $21, $b3, $71, $91, $71, $91, $73, $61, $21, $21, $21, $b3, $71
    db $91, $b1, $91, $61, $71, $91, $d8, $92, $b1, $b1, $b1, $b1, $91, $71, $41, $41
    db $41, $73, $61, $b1, $b1, $b1, $b1, $91, $71, $41, $41, $41, $b1, $91, $61, $d8
    db $75, $7b, $9b, $bf, $c5, $d8, $a2, $71, $95, $75, $65, $43, $61, $75, $95, $b5
    db $e6, $bb, $d8, $b3, $e3, $2b, $7b, $2b, $7b, $e4, $9b, $e3, $4b, $6b, $25, $ea
    db $00, $00, $d8, $b2, $e5, $73, $e4, $71, $25, $e5, $b3, $e4, $21, $75, $e5, $73
    db $e4, $41, $25, $e5, $73, $b1, $e4, $25, $e5, $63, $91, $e4, $25, $e5, $73, $b1
    db $e4, $45, $e5, $93, $e4, $61, $73, $21, $95, $e5, $69, $b1, $b9, $b1, $b9, $b1
    db $b5, $e4, $23, $e5, $91, $99, $e4, $41, $49, $41, $45, $21, $11, $21, $41, $21
    db $07, $2b, $d8, $a1, $e5, $21, $21, $21, $25, $41, $41, $41, $4b, $d8, $b2, $65
    db $0b, $d8, $a1, $21, $21, $21, $25, $41, $41, $41, $4b, $d8, $b2, $65, $05, $ec
    db $01, $d8, $92, $e6, $b1, $e5, $21, $71, $21, $e6, $b1, $e5, $21, $e6, $b1, $e5
    db $21, $71, $e6, $b1, $e5, $21, $71, $e6, $b1, $e5, $21, $71, $21, $e6, $b1, $e5
    db $21, $e6, $b1, $e5, $21, $71, $e6, $b1, $e5, $21, $41, $e6, $91, $e5, $21, $61
    db $21, $e6, $91, $e5, $21, $e6, $91, $e5, $21, $61, $e6, $91, $e5, $21, $61, $e6
    db $91, $e5, $21, $61, $21, $e6, $91, $e5, $21, $e6, $91, $e5, $21, $61, $21, $e6
    db $91, $e5, $21, $d8, $92, $e6, $b1, $e5, $21, $71, $21, $e6, $b1, $e5, $21, $23
    db $71, $23, $01, $e6, $b1, $e5, $21, $71, $e6, $b1, $e5, $21, $71, $23, $71, $23
    db $01, $d8, $a2, $25, $b3, $71, $91, $71, $91, $73, $61, $25, $b3, $71, $91, $71
    db $91, $b1, $91, $61, $d8, $b2, $21, $21, $21, $b3, $71, $91, $41, $61, $73, $61
    db $71, $71, $71, $b3, $71, $91, $71, $91, $71, $93, $ec, $02, $d8, $b2, $fe, $00
    db $fd, $5a
BgmOption0Channel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $08, $c2
    SOUND_OCTAVE $04
    db $21, $71, $61, $73, $21, $41, $61, $71, $b3, $91, $73, $61, $43, $61, $75
    SOUND_OCTAVE $05
    db $75
BgmPreview0Channel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $08, $c2
SoundSequenceData_5ce9::
    db $e4, $21, $21, $21, $21, $01, $e5, $b1, $e4, $45, $63, $41, $21, $71, $61, $71
    db $61, $71, $43, $01, $e5, $b1, $e4, $01, $11, $21, $21, $21, $21, $01, $e5, $b1
    db $e4, $45, $63, $41, $21, $71, $61, $71, $61, $71, $93, $71, $63, $21, $b1, $a1
    db $b1, $e3, $01, $e4, $b1, $91, $75, $43, $70, $90, $b1, $a1, $b1, $e3, $01, $e4
    db $b1, $91, $71, $91, $71, $41, $61, $71, $91, $81, $91, $b1, $91, $71, $65, $23
    db $40, $60, $91, $81, $91, $41, $61, $41, $21, $41, $61, $21, $41, $61, $ea, $02
    db $22, $d8, $b3, $73, $61, $73, $21, $41, $21, $01, $e5, $b1, $e4, $01, $21, $73
    db $61, $73, $21, $41, $61, $71, $61, $41, $21, $73, $61, $73, $21, $41, $21, $01
    db $e5, $b1, $e4, $01, $21, $73, $61, $73, $21, $01, $71, $61, $75, $ea, $00, $00
    db $d8, $c2, $91, $81, $91, $73, $41, $23, $e3, $21, $23, $e4, $60, $70, $91, $81
    db $91, $73, $41, $23, $e3, $21, $25, $ea, $02, $22, $d8, $b3, $e4, $73, $61, $73
    db $21, $41, $21, $01, $e5, $b1, $e4, $01, $21, $73, $61, $73, $21, $41, $61, $71
    db $61, $41, $21, $73, $61, $73, $21, $41, $21, $01, $e5, $b1, $e4, $01, $21, $73
    db $61, $73, $21, $45, $73, $61, $ea, $00, $00, $d8, $c2, $e5, $21, $21, $21, $91
    db $71, $61, $41, $41, $41, $e4, $01, $e5, $b1, $91, $61, $61, $61, $e4, $41, $21
    db $01, $e5, $b1, $e4, $01, $21, $43, $21, $61, $41, $61, $41, $61, $41, $63, $41
    db $23, $61, $71, $61, $71, $61, $71, $61, $75, $e5, $75, $ec, $03, $d8, $b2, $e4
    db $21, $11, $21, $41, $21, $01, $e5, $b5, $e4, $25, $21, $11, $21, $43, $01, $e5
    db $b5, $75, $91, $81, $91, $e4, $23, $01, $e5, $b1, $a1, $b1, $e4, $43, $21, $61
    db $51, $61, $71, $61, $41, $25, $63, $ec, $02, $d8, $c2, $b0, $e3, $00, $21, $11
    db $21, $41, $21, $01, $e4, $b5, $e3, $25, $21, $11, $21, $43, $01, $e4, $b5, $75
    db $91, $81, $91, $e3, $23, $01, $e4, $b1, $a1, $b1, $e3, $43, $21, $61, $51, $61
    db $71, $61, $41, $95, $ec, $03, $d8, $c3, $e4, $21, $41, $61, $73, $61, $73, $91
    db $b5, $93, $71, $b5, $93, $71, $93, $21, $23, $90, $b0, $e3, $05, $e4, $b3, $91
    db $e3, $05, $e4, $b3, $91, $d8, $c5, $7b, $6b, $ec, $02, $d8, $c2, $21, $21, $21
    db $25, $41, $41, $41, $45, $61, $61, $61, $61, $41, $21, $05, $45, $21, $21, $21
    db $25, $41, $41, $41, $45, $61, $61, $61, $61, $41, $21, $03, $e5, $b1, $93, $71
    db $ec, $01, $ea, $02, $24, $d8, $c4, $e4, $71, $61, $71, $91, $71, $61, $45, $23
    db $40, $60, $71, $61, $71, $91, $71, $61, $41, $61, $41, $21, $41, $51, $61, $51
    db $61, $71, $61, $41, $25, $65, $61, $51, $61, $71, $61, $41, $21, $41, $61, $21
    db $41, $61, $ea, $02, $22, $d8, $b3, $73, $61, $73, $21, $41, $21, $01, $e5, $b1
    db $e4, $01, $21, $73, $61, $73, $21, $41, $61, $71, $61, $41, $21, $73, $61, $73
    db $21, $41, $21, $01, $e5, $b1, $e4, $01, $21, $73, $61, $73, $21, $41, $61, $71
    db $61, $41, $21, $73, $61, $73, $21, $41, $21, $01, $e5, $b1, $e4, $01, $21, $73
    db $61, $73, $21, $01, $71, $61, $73, $ec, $02, $d8, $c2, $ea, $00, $00, $e5, $b0
    db $e4, $00, $fe, $00, $e9, $5c
BgmOption0Channel2Sequence::
    SOUND_LENGTH_ENVELOPE $08, $12
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $05
    SOUND_OCTAVE $04
    db $01, $21
    SOUND_REST_NOTE $03
    db $01
    SOUND_REST_NOTE $03
    SOUND_OCTAVE $05
    db $b1
    SOUND_REST_NOTE $03
    db $b1
    SOUND_REST_NOTE $03
BgmPreview0Channel2Sequence::
    SOUND_LENGTH_ENVELOPE $08, $12
SoundSequenceData_5f30::
    db $e4, $21, $c3, $e5, $b1, $c3, $e4, $41, $c3, $03, $41, $21, $c3, $e5, $b1, $c3
    db $e4, $01, $c3, $11, $c3, $21, $c3, $e5, $b1, $c3, $e4, $41, $c3, $03, $41, $21
    db $c3, $71, $61, $21, $41, $c3, $21, $c1, $01, $e5, $b1, $c3, $e4, $31, $c3, $41
    db $c3, $71, $c3, $e5, $b1, $c3, $e4, $31, $c3, $41, $c3, $71, $c1, $e5, $b1, $91
    db $c3, $e4, $11, $c3, $21, $c3, $61, $c3, $e5, $91, $c3, $e4, $11, $c3, $21, $c3
    db $01, $c1, $41, $e5, $71, $cf, $c5, $71, $cf, $c5, $71, $c3, $b1, $c3, $e4, $01
    db $c3, $e5, $b1, $c1, $91, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5, $b1, $c1, $e4
    db $11, $21, $c3, $e5, $91, $c3, $e4, $21, $c1, $e5, $21, $21, $c3, $e4, $21, $c3
    db $e5, $91, $c3, $e4, $21, $c1, $e5, $21, $21, $c3, $71, $c3, $b1, $c3, $e4, $01
    db $c3, $e5, $b1, $c1, $91, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5, $b1, $c1, $91
    db $71, $c3, $b1, $c3, $e4, $01, $c3, $e5, $b1, $c1, $91, $71, $c3, $b1, $c3, $e4
    db $01, $c3, $e5
MusicSequenceData_5fe3::
    db $b1, $c1, $91, $b1, $c9, $e4, $01, $c9, $21, $cf, $c3, $01, $21, $c3, $01, $c3
    db $e5, $b1, $c3, $91, $c3, $71, $c3, $e4, $21, $c3, $71, $c3, $e5, $71, $c7, $e4
    db $21, $e5, $b1, $c7, $e4, $71, $21, $c7, $21, $e5, $b1, $c7, $e4, $41, $21, $c7
    db $21, $e5, $91, $c7, $e4, $41, $21, $c7, $61, $71, $c3, $91, $c3, $61, $c3, $21
    db $c3, $e5, $b1, $c3, $e4, $71, $c3, $21, $c3, $21, $c3, $e5, $b1, $c3, $e4, $41
    db $c3, $21, $c3, $21, $c3, $e5, $91, $c3, $e4, $41, $c3, $21, $c3, $61, $c3, $71
    db $c3, $91, $c3, $21, $c3, $71, $c3, $21, $c3, $71, $c3, $21, $c3, $71, $c3, $21
    db $c3, $91, $c1, $21, $21, $c3, $e3, $01, $c3, $e4, $41, $c3, $e3, $01, $c3, $e4
    db $41, $c3, $91, $c3, $21, $c3, $91, $c3, $21, $c3, $e3, $61, $c9, $71, $c9, $91
    db $c9, $61, $c3, $91, $c3, $61, $c9, $71, $c9, $91, $c9, $61, $c3, $91, $cf, $cf
    db $cf, $cf, $cf, $cf, $c3, $e5, $71, $cf, $c5, $71, $cf, $c3, $91, $71, $c3, $b1
    db $c3, $e4, $01, $c3, $e5, $b1, $c1, $91, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5
    db $b1, $c1, $91, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5, $b1, $c1, $91, $71, $c3
    db $b1, $c3, $e4, $01, $21, $c1, $21, $c1, $41, $fe, $00, $30, $5f
BgmOption0Channel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $08
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $07
    SOUND_REST_NOTE $07
    SOUND_REST_NOTE $0f
BgmPreview0Channel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $08
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $04
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
MusicSequenceData_60ce::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $07, MusicSequenceData_60ce
MusicSequenceData_60da::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_LOOP_JUMP $02, MusicSequenceData_60da
MusicSequenceData_60e2::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $02, MusicSequenceData_60e2
MusicSequenceData_60ee::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $04
    SOUND_CHANNEL3_LENGTH_SCALE $08
    SOUND_LOOP_JUMP $02, MusicSequenceData_60ee
MusicSequenceData_6101::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $04, MusicSequenceData_6101
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_REST_NOTE $09
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
MusicSequenceData_6116::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $02, MusicSequenceData_6116
MusicSequenceData_6122::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_LOOP_JUMP $04, MusicSequenceData_6122
MusicSequenceData_612a::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $08, MusicSequenceData_612a
MusicSequenceData_6136::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $02, MusicSequenceData_6136
MusicSequenceData_6144::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $04, MusicSequenceData_6144
MusicSequenceData_6150::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0b
    SOUND_LOOP_JUMP $02, MusicSequenceData_6150
MusicSequenceData_6158::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $04, MusicSequenceData_6158
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $05
    SOUND_LOOP_JUMP $00, MusicSequenceData_60ce
BgmOption1Channel0Sequence::
    SOUND_TEMPO $00, $e0
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $b3
    SOUND_REST_NOTE $03
    SOUND_OCTAVE $04
    db $07
    SOUND_OCTAVE $05
    db $b7, $41, $71, $01, $79
BgmPreview1Channel0Sequence::
    SOUND_TEMPO $00, $e0
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $b3
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $09
    SOUND_OCTAVE $05
    db $70, $50, $40, $50, $40, $20, $01
    SOUND_OCTAVE $06
    db $71
    SOUND_OCTAVE $05
    db $01, $41, $21, $51, $01, $41, $21
    SOUND_OCTAVE $06
    db $b0
    SOUND_OCTAVE $05
    db $00, $21, $51, $73, $53
MusicSequenceData_61a9::
    db $41, $01, $41, $71, $51, $01, $41, $01, $21, $e6, $b0, $e5, $00, $21, $51, $41
    db $50, $40, $21, $71, $01, $21, $41, $21, $40, $20, $01, $41, $71, $23, $53, $71
    db $51, $51, $21, $41, $71, $01, $40, $70, $53, $71, $41, $51, $51, $41, $41, $21
    db $51, $e6, $b1, $e5, $51, $70, $50, $41, $41, $71, $51, $41, $21, $01, $20, $00
    db $e6, $b0, $e5, $00, $21, $41, $51, $41, $51, $91, $70, $50, $40, $20, $01, $e6
    db $b1, $91, $b1, $e5, $01, $01, $20, $00, $e6, $b0, $90, $e5, $01, $41, $50, $20
    db $40, $00, $2f, $c3, $c1, $73, $77, $51, $4f, $cb, $71, $51, $41, $51, $71, $51
    db $41, $21, $41, $71, $90, $50, $70, $40, $51, $40, $70, $90, $70, $91, $b1, $e4
    db $21, $dc, $a5, $47, $07, $57, $23, $43, $77, $43, $b3, $47, $47, $07, $e5, $b7
    db $97, $77, $97, $b7, $dc, $b3, $73, $53, $43, $23, $e4, $03, $e5, $b3, $93, $71
    db $b1, $e4, $03, $e5, $53, $73, $03, $23, $43, $53, $7f, $c3, $cf, $cf, $cf, $fe
    db $00, $a9, $61
BgmOption1Channel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $c3
    SOUND_OCTAVE $04
    db $01, $21, $43, $51, $41, $21, $01
    SOUND_OCTAVE $05
    db $b1
    SOUND_OCTAVE $04
    db $21, $03, $23, $01
    SOUND_OCTAVE $05
    db $71, $51, $71
BgmPreview1Channel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $c3
    SOUND_OCTAVE $04
    db $01
    SOUND_OCTAVE $05
    db $71
    SOUND_OCTAVE $04
    db $01, $41, $21
    SOUND_OCTAVE $05
    db $71
    SOUND_OCTAVE $04
    db $21, $51, $41, $00, $20, $41, $51, $43, $21, $00, $20, $41, $01, $41, $71, $51
    db $01, $41, $01, $21
    SOUND_OCTAVE $05
    db $71
    SOUND_OCTAVE $04
    db $21, $51, $41, $50, $40, $23
MusicSequenceData_629f::
    db $c1, $00, $20, $41, $50, $40, $21, $e5, $b0, $e4, $00, $21, $41, $51, $41, $21
    db $01, $e5, $b1, $91, $71, $b1, $e4, $70, $50, $40, $20, $01, $e5, $b1, $91, $e4
    db $41, $e5, $71, $e4, $41, $51, $20, $40, $51, $01, $e5, $b1, $e4, $51, $21, $51
    db $41, $00, $20, $41, $21, $01, $21, $41, $01, $20, $00, $e5, $b0, $e4, $00, $21
    db $41, $57, $41, $41, $40, $20, $00, $20, $01, $00, $e5, $b0, $90, $70, $50, $70
    db $91, $91, $e4, $01, $01, $e5, $b1, $e4, $01, $23, $41, $41, $40, $20, $00, $20
    db $01, $00, $e5, $b0, $90, $70, $50, $70, $91, $91, $e4, $01, $01, $e5, $b1, $e4
    db $01, $23, $00, $e5, $b0, $91, $71, $e4, $41, $e5, $71, $e4, $41, $01, $41, $51
    db $41, $21, $00, $20, $e5, $b1, $e4, $01, $23, $70, $40, $50, $20, $40, $00, $20
    db $e5, $b0, $e4, $03, $70, $40, $50, $20, $40, $00, $20, $e5, $b0, $e4, $01, $00
    db $20, $41, $01, $53, $70, $40, $50, $20, $40, $00, $20, $e5, $b0, $e4, $01, $00
    db $20, $40, $20, $00, $20, $51, $51, $41, $41, $21, $41, $53, $dc, $b6, $77, $47
    db $97, $57, $b7, $77, $dc, $c3, $e3, $01, $01, $e4, $b1, $b1, $90, $70, $91, $b1
    db $71, $e3, $01, $00, $20, $00, $e4, $b0, $90, $70, $40, $50, $71, $01, $71, $90
    db $70, $50, $70, $91, $b1, $91, $71, $51, $41, $20, $40, $51, $40, $50, $71, $50
    db $70, $91, $b1, $71, $70, $50, $40, $20, $01, $e5, $b1, $91, $e4, $21, $e5, $b1
    db $e4, $21, $47, $77, $41, $41, $40, $20, $00, $20, $01, $00, $e5, $b0, $90, $70
    db $50, $70, $91, $91, $e4, $01, $01, $e5, $b1, $e4, $01, $23, $01, $e5, $71, $e4
    db $01, $41, $21, $e5, $71, $e4, $21, $51, $41, $00, $20, $41, $51, $41, $01, $23
    db $41, $01, $41, $71, $51, $01, $41, $01, $21, $e5, $71, $e4, $21, $51, $43, $23
    db $fe, $00, $9f, $62
BgmOption1Channel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_VIBRATO $08, $26
    SOUND_REST_NOTE $03
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
BgmPreview1Channel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_VIBRATO $08, $26
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0b
    SOUND_OCTAVE $06
    db $b0
    SOUND_OCTAVE $05
    db $00, $20
    SOUND_OCTAVE $06
    db $b0
MusicSequenceData_63fb::
    db $e5, $01, $e6, $71, $e5, $01, $41, $21, $71, $01, $41, $20, $00, $e6, $b0, $e5
    db $00, $e6, $b1, $e5, $01, $23, $73, $cf, $cf, $41, $01, $41, $71, $53, $43, $22
    db $c0, $20, $00, $e6, $b0, $e5, $00, $23, $73, $cf, $cf, $cf, $51, $41, $20, $00
    db $e6, $b0, $e5, $00, $23, $50, $70, $90, $b0, $e4, $00, $c0, $00, $c0, $00, $e5
    db $b0, $90, $b0, $e4, $01, $21, $41, $01, $23, $03, $e5, $b1, $91, $71, $b1, $e4
    db $01, $c5, $70, $40, $50, $20, $40, $00, $20, $e5, $b0, $e4, $03, $cb, $cb, $01
    db $e5, $b1, $91, $71, $51, $71, $93, $b1, $71, $e4, $00, $20, $40, $50, $77, $ea
    db $08, $46, $73, $ea, $08, $26, $20, $40, $50, $70, $97, $ea, $08, $46, $93, $ea
    db $08, $26, $40, $50, $70, $90, $b3, $91, $b1, $71, $b1, $e3, $07, $e4, $b7, $97
    db $77, $57, $47, $27, $77, $00, $c0, $00, $c0, $e5, $b0, $c0, $b0, $c0, $90, $70
    db $91, $b1, $71, $e4, $00, $c0, $00, $20, $00, $e5, $b0, $90, $70, $40, $50, $71
    db $01, $71, $90, $70, $50, $70, $91, $b1, $91, $71, $51, $41, $20, $40, $51, $40
    db $50, $71, $50, $70, $91, $b1, $e4, $21, $07, $27, $47, $57, $77, $53, $43, $27
    db $43, $53, $fe, $00, $fb, $63
BgmOption1Channel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_REST_NOTE $03
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
BgmPreview1Channel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $06
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
MusicSequenceData_64f0::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_64f0
MusicSequenceData_64fc::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_LOOP_JUMP $02, MusicSequenceData_64fc
MusicSequenceData_6504::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_6504
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
MusicSequenceData_6536::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $04, MusicSequenceData_6536
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
MusicSequenceData_6552::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_LOOP_JUMP $04, MusicSequenceData_6552
MusicSequenceData_655a::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $04, MusicSequenceData_655a
MusicSequenceData_656e::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_LOOP_JUMP $02, MusicSequenceData_656e
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $00, MusicSequenceData_64f0
BgmOption2Channel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $07, $23
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $b2
    SOUND_OCTAVE $04
    db $40, $60, $40, $60, $40, $60, $40, $60, $41
    SOUND_OCTAVE $05
    db $b1
    SOUND_OCTAVE $04
    db $11, $31
    SOUND_OCTAVE $05
    db $b2
    SOUND_OCTAVE $04
    db $10, $31
    SOUND_OCTAVE $05
    db $b1
    SOUND_OCTAVE $04
    db $43, $43
BgmPreview2Channel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $07, $23
    SOUND_FREQ_CARRY_TOGGLE
MusicSequenceData_65b7::
    db $dc, $b2, $e5, $81, $83, $b1, $e4, $43, $32, $10, $e5, $b1, $63, $e4, $91, $61
    db $e3, $41, $33, $e5, $b1, $b3, $61, $93, $62, $90, $83, $93, $b1, $91, $81, $61
    db $81, $43, $b1, $e4, $43, $32, $10, $e5, $b1, $63, $e4, $91, $61, $e3, $41, $33
    db $e5, $b1, $b3, $61, $93, $62, $90, $b3, $93, $83, $83, $c1, $83, $83, $83, $81
    db $c1, $93, $93, $90, $92, $91, $c1, $93, $91, $b1, $91, $81, $63, $80, $82, $91
    db $b1, $e4, $11, $11, $e5, $b1, $43, $e4, $15, $13, $11, $e5, $33, $e4, $35, $33
    db $31, $c1, $43, $42, $30, $41, $61, $41, $6f, $dc, $92, $c1, $e5, $43, $43, $43
    db $41, $61, $63, $63, $63, $61, $81, $83, $83, $83, $81, $6f, $41, $43, $43, $43
    db $41, $61, $63, $63, $63, $61, $81, $83, $83, $83, $81, $b1, $b3, $e4, $35, $d6
    db $b3, $e5, $b0, $e4, $10, $20, $30, $40, $50, $60, $70, $dc, $b3, $87, $67, $47
    db $67, $83, $63, $83, $63, $43, $63, $83, $63, $83, $63, $83, $63, $43, $63, $83
    db $63, $41, $e5, $b3, $e4, $41, $83, $63, $41, $63, $41, $33, $43, $dc, $b5, $e5
    db $97, $47, $e4, $37, $e5, $67, $dc, $83, $cf, $cf, $cf, $cf, $c1, $b5, $83, $63
    db $c1, $95, $63, $93, $c1, $85, $43, $63, $c1, $65, $63, $83, $dc, $b3, $cf, $cf
    db $cf, $cf, $c1, $b5, $b3, $b3, $c1, $e4, $15, $13, $13, $c1, $45, $43, $43, $35
    db $31, $33, $33, $e5, $b1, $e4, $31, $11, $e5, $b1, $e4, $31, $11, $31, $41, $41
    db $31, $11, $31, $41, $31, $11, $31, $61, $41, $31, $41, $61, $41, $61, $81, $b1
    db $91, $81, $63, $81, $83, $c7, $e5, $43, $33, $13, $e6, $b3, $93, $83, $e5, $43
    db $33, $13, $e6, $b3, $93, $83, $63, $33, $fe, $00, $b7, $65
BgmOption2Channel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $06, $24
    SOUND_LENGTH_ENVELOPE $0c, $c2
    SOUND_OCTAVE $04
    db $b5
    SOUND_OCTAVE $03
    db $11
    SOUND_OCTAVE $04
    db $b1, $91, $81, $61, $41, $61, $81, $61, $b3, $b3
BgmPreview2Channel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $06, $24
    SOUND_LENGTH_ENVELOPE $0c, $c2
MusicSequenceData_6700::
    db $dc, $c2, $e4, $41, $e5, $b3, $e4, $41, $83, $62, $40, $31, $e5, $b3, $e3, $11
    db $e4, $b1, $e3, $81, $63, $e4, $31, $63, $e5, $b1, $e4, $13, $32, $60, $45, $61
    db $87, $41, $e5, $b3, $e4, $41, $83, $62, $40, $31, $e5, $b3, $e3, $11, $e4, $b1
    db $e3, $81, $63, $e4, $31, $63, $e5, $b1, $e4, $13, $32, $60, $45, $e5, $b1, $e4
    db $41, $ec, $01, $dc, $c3, $e6, $b1, $e5, $11, $31, $45, $31, $13, $43, $35, $41
    db $67, $33, $63, $31, $e6, $b1, $e5, $11, $31, $45, $61, $87, $93, $12, $40, $97
    db $83, $e6, $b2, $e5, $40, $87, $62, $50, $61, $81, $91, $81, $91, $e4, $11, $e5
    db $b3, $ec, $02, $d6, $b1, $b1, $90, $80, $60, $40, $30, $10, $e6, $b7, $dc, $a2
    db $e5, $b2, $90, $85, $83, $83, $81, $95, $93, $91, $b1, $91, $b1, $b3, $b3, $b3
    db $b1, $e4, $3f, $c1, $e5, $83, $83, $81, $91, $81, $c1, $93, $93, $91, $b1, $91
    db $c1, $b3, $b3, $b1, $e4, $11, $e5, $b1, $e4, $31, $31, $61, $69, $dc, $a3, $e3
    db $43, $41, $e4, $b1, $e3, $33, $31, $e4, $b1, $e3, $13, $11, $e4, $b1, $e3, $33
    db $31, $e4, $b1, $e3, $43, $41, $e4, $b1, $e3, $33, $31, $e4, $b1, $e3, $13, $11
    db $e4, $b1, $e3, $33, $31, $e4, $b1, $e3, $43, $41, $e4, $b1, $e3, $33, $31, $e4
    db $b1, $e3, $13, $11, $e4, $b1, $e3, $33, $31, $e4, $b1, $e3, $43, $41, $e4, $b1
    db $e3, $33, $31, $e4, $b1, $e3, $13, $11, $e4, $b1, $e3, $33, $31, $e4, $b1, $dc
    db $c5, $17, $17, $e5, $b7, $b7, $dc, $c3, $e4, $45, $31, $11, $e5, $b1, $e4, $11
    db $e5, $91, $e4, $35, $11, $e5, $b1, $e4, $11, $31, $61, $41, $31, $11, $e5, $b1
    db $91, $81, $91, $e4, $11, $e5, $b3, $e4, $13, $31, $11, $31, $e5, $b1, $e4, $45
    db $31, $11, $e5, $b1, $e4, $11, $e5, $91, $e4, $35, $11, $e5, $b1, $e4, $11, $31
    db $61, $41, $31, $11, $e5, $b1, $91, $81, $91, $e4, $11, $e5, $b3, $e4, $13, $31
    db $11, $31, $e5, $b1, $e4, $45, $31, $11, $e5, $b1, $e4, $11, $e5, $91, $e4, $35
    db $11, $e5, $b1, $e4, $11, $31, $61, $41, $31, $11, $e5, $b1, $91, $81, $91, $e4
    db $11, $83, $63, $81, $61, $41, $31, $c1, $85, $83, $83, $c1, $95, $93, $93, $c1
    db $b5, $b3, $b3, $65, $61, $93, $e3, $13, $e4, $85, $85, $83, $95, $95, $93, $b5
    db $b5, $b3, $e3, $31, $11, $31, $63, $e4, $b1, $e3, $41, $e4, $10, $30, $43, $33
    db $13, $e5, $b3, $93, $83, $63, $43, $e4, $43, $33, $13, $e5, $b3, $93, $83, $63
    db $b3, $fe, $00, $00, $67
BgmOption2Channel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $09
    SOUND_OCTAVE $05
    db $b0
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $04
    db $10
    SOUND_REST_NOTE $00
    db $30
    SOUND_REST_NOTE $00
BgmPreview2Channel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
MusicSequenceData_68c3::
    db $e4, $40, $c0, $40, $c0, $e5, $b0, $c0, $e4, $80, $c0, $40, $c0, $b0, $c0, $e5
    db $b0, $c0, $e4, $60, $c0, $30, $c0, $e5, $b0, $c4, $eb, $00, $6b, $b0, $c2, $eb
    db $00, $6b, $b0, $c2, $e4, $30, $c0, $60, $c0, $e5, $b0, $c0, $e4, $30, $c0, $10
    db $c0, $30, $c0, $30, $c0, $e5, $b0, $c0, $e4, $40, $c0, $40, $c0, $e5, $b0, $c0
    db $e4, $40, $30, $40, $c0, $60, $c0, $e5, $b0, $c0, $e4, $30, $c0, $40, $c0, $e5
    db $b0, $c0, $b0, $c0, $e4, $80, $c0, $40, $c0, $b0, $c0, $40, $50, $60, $40, $30
    db $c0, $30, $c4, $e5, $eb, $00, $6b, $b0, $c2, $eb, $00, $6b, $b0, $c2, $e4, $30
    db $c0, $60, $c0, $e5, $b0, $c0, $e4, $30, $c0, $10, $c0, $30, $c2, $30, $c0, $40
    db $c2, $e5, $b0, $c2, $e4, $40, $c2, $40, $c2, $e5, $80, $c0, $b0, $c0, $80, $c0
    db $b0, $c0, $80, $c0, $b0, $c0, $80, $c0, $b0, $c0, $90, $c0, $e4, $10, $c0, $e5
    db $90, $80, $60, $80, $90, $c0, $e4, $10, $c0, $e5, $90, $c0, $e4, $10, $c0, $e5
    db $90, $c0, $e4, $10, $c0, $e5, $90, $c0, $e4, $10, $c0, $e5, $90, $c0, $60, $c0
    db $60, $c0, $90, $c0, $80, $c0, $b0, $c0, $80, $c0, $b0, $c0, $80, $90, $b0, $90
    db $80, $c0, $b0, $c6, $90, $e4, $10, $e5, $90, $c0, $e4, $40, $c0, $e5, $90, $c0
    db $e4, $40, $c6, $e5, $80, $b0, $e4, $30, $c0, $b0, $c0, $30, $c0, $b0, $c0, $e5
    db $90, $c0, $e4, $10, $c0, $e5, $90, $c0, $e4, $10, $c0, $e5, $90, $c0, $e4, $10
    db $c0, $e5, $90, $c0, $e4, $10, $c0, $30, $ce, $dc, $11, $e3, $40, $c0, $e4, $b0
    db $c2, $e3, $40, $c0, $80, $c0, $90, $c2, $80, $c0, $60, $c0, $10, $c2, $60, $c0
    db $90, $c0, $b0, $c2, $90, $c0, $80, $c0, $90, $c2, $b0, $c0, $e2, $10, $c0, $e3
    db $b0, $c2, $e2, $10, $c0, $e3, $90, $c0, $80, $c0, $60, $c0, $40, $c0, $30, $c0
    db $40, $c0, $60, $c0, $30, $c0, $40, $c0, $e4, $b0, $c2, $e3, $40, $c0, $80, $c0
    db $90, $c2, $80, $c0, $60, $c0, $10, $c2, $60, $c0, $90, $c0, $b0, $c2, $90, $c0
    db $80, $c0, $90, $c2, $b0, $c0, $e2, $10, $c0, $e3, $b0, $c2, $e2, $10, $c0, $30
    db $c0, $10, $c0, $30, $c0, $e3, $b0, $c8, $dc, $10, $e4, $87, $b7, $97, $e3, $37
    db $e4, $87, $b7, $97, $e3, $37, $e4, $83, $b3, $43, $b3, $91, $81, $61, $41, $31
    db $41, $61, $31, $81, $61, $41, $81, $b1, $91, $81, $61, $41, $61, $81, $91, $b1
    db $91, $81, $61, $c3, $e5, $40, $60, $80, $90, $b0, $e4, $10, $20, $30, $40, $c6
    db $e5, $60, $80, $90, $b0, $e4, $10, $30, $40, $50, $60, $c4, $83, $c1, $83, $43
    db $c1, $63, $c1, $63, $33, $c1, $43, $c1, $43, $13, $c1, $33, $c1, $33, $63, $c1
    db $83, $c1, $43, $43, $c1, $63, $c1, $33, $63, $c1, $43, $c1, $13, $43, $c1, $33
    db $c1, $33, $33, $41, $83, $b1, $83, $43, $31, $63, $91, $63, $33, $11, $43, $81
    db $43, $13, $31, $93, $e3, $11, $e4, $b3, $93, $41, $e5, $b3, $e4, $41, $83, $62
    db $40, $61, $13, $61, $93, $82, $60, $81, $93, $b1, $e3, $11, $e4, $b3, $e3, $11
    db $e4, $11, $33, $41, $63, $33, $41, $e5, $b3, $e4, $41, $83, $62, $40, $61, $13
    db $61, $93, $82, $60, $81, $93, $b1, $e3, $11, $e4, $b3, $e3, $11, $31, $11, $31
    db $e4, $b1, $c1, $e3, $40, $c0, $40, $cf, $c2, $e5, $43, $33, $13, $e6, $b3, $e4
    db $83, $63, $43, $33, $13, $e5, $b3, $c1, $b0, $c0, $e4, $10, $c0, $30, $c0, $fe
    db $00, $c3, $68
BgmOption2Channel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
BgmPreview2Channel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
MusicSequenceData_6b2a::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_LENGTH_SCALE $06
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_REST_NOTE $01
MusicSequenceData_6b42::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $02, MusicSequenceData_6b42
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_LENGTH_SCALE $06
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $02
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
MusicSequenceData_6b98::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $04, MusicSequenceData_6b98
MusicSequenceData_6bac::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $07
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $02, MusicSequenceData_6bac
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0f
MusicSequenceData_6bcc::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $03, MusicSequenceData_6bcc
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $0f
MusicSequenceData_6bda::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $03, MusicSequenceData_6bda
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $07
MusicSequenceData_6bef::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_6bef
MusicSequenceData_6bfb::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $06, MusicSequenceData_6bfb
MusicSequenceData_6c0f::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_6c0f
MusicSequenceData_6c1b::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_6c1b
MusicSequenceData_6c27::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $02, MusicSequenceData_6c27
MusicSequenceData_6c3b::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_6c3b
MusicSequenceData_6c47::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $02, MusicSequenceData_6c47
MusicSequenceData_6c5b::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_6c5b
MusicSequenceData_6c67::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $02, MusicSequenceData_6c67
MusicSequenceData_6c7b::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $07, MusicSequenceData_6c7b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
MusicSequenceData_6c9b::
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $03, MusicSequenceData_6c9b
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $03
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $00
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_VISUAL_UPDATE
    SOUND_REST_NOTE $01
    SOUND_LOOP_JUMP $00, MusicSequenceData_6b2a
LinkRoleSharedChannel0Sequence::
    SOUND_TEMPO $00, $84
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $07, $23
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $b2
    SOUND_OCTAVE $05
    db $71, $70, $70, $73
    SOUND_LENGTH_ENVELOPE $08, $b2
    SOUND_REST_NOTE $01
    db $71, $91, $b1
    SOUND_OCTAVE $04
    db $01, $11, $25
    SOUND_LENGTH_ENVELOPE $0c, $b2
    SOUND_OCTAVE $05
    db $b3
    SOUND_OCTAVE $04
    db $03
    SOUND_OCTAVE $05
    db $05
MusicSequenceData_6cec::
    db $53, $53, $53, $53, $e4, $00, $e5, $b0, $e4, $00, $e5, $b0, $e4, $03, $e5, $90
    db $80, $90, $80, $93, $73, $73, $73, $73, $90, $80, $90, $80, $90, $a0, $e4, $01
    db $e5, $a1, $91, $73, $53, $53, $53, $53, $e4, $00, $e5, $b0, $e4, $00, $e5, $b0
    db $e4, $03, $50, $40, $50, $40, $53, $e5, $73, $73, $73, $71, $e4, $01, $21, $41
    db $21, $71, $91, $a1, $73, $e5, $73, $73, $e4, $00, $20, $41, $01, $29, $e5, $90
    db $a0, $e4, $01, $e5, $71, $9f, $c1, $e4, $50, $40, $55, $70, $60, $73, $e5, $91
    db $53, $53, $53, $53, $e4, $50, $40, $55, $70, $60, $75, $e5, $03, $01, $91, $01
    db $91, $03, $23, $21, $e4, $01, $e5, $41, $e4, $01, $e5, $41, $55, $e4, $51, $01
    db $e5, $a1, $91, $e4, $01, $e5, $a5, $e4, $71, $41, $21, $01, $e5, $a1, $91, $53
    db $53, $53, $53, $e4, $50, $40, $55, $70, $60, $73, $51, $e5, $93, $93, $93, $93
    db $93, $93, $93, $93, $93, $93, $93, $93, $93, $93, $93, $93, $a3, $a3, $a3, $a3
    db $e4, $03, $03, $03, $03, $03, $03, $03, $00, $c0, $e5, $9f, $c0, $cf, $cf, $cf
    db $cf, $ca, $c5, $fe, $00, $ec, $6c
LinkMasterChannel1Sequence::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6ddd
MusicSequenceData_6db6::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6e00
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6f22
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6f4e
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6f66
    SOUND_LOOP_JUMP $00, MusicSequenceData_6db6
LinkSlaveChannel1Sequence::
    SOUND_LENGTH_ENVELOPE $04, $c1
    SOUND_REST_NOTE $00
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6ddd
MusicSequenceData_6dcd::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6e00
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6f38
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6f59
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_6f66
    SOUND_LOOP_JUMP $00, MusicSequenceData_6dcd
MusicSequenceData_6ddd::
    db $ec, $02, $dc, $c1, $e4, $01, $00, $00, $dc, $c3, $03, $d8, $c3, $c1, $01, $21
    db $41, $51, $61, $75, $b2, $90, $b0, $70, $dc, $c3, $e3, $03, $e5, $71, $ec, $03
    db $e4, $01, $ff
MusicSequenceData_6e00::
    db $dc, $c3, $e4, $92, $70, $51, $91, $71, $91, $a1, $e3, $21, $dc, $c6, $07, $e4
    db $95, $dc, $c3, $01, $72, $50, $41, $51, $dc, $c2, $71, $71, $dc, $c3, $91, $a1
    db $dc, $c6, $97, $e3, $05, $dc, $c3, $e4, $01, $92, $70, $51, $91, $71, $91, $a1
    db $e3, $21, $dc, $c6, $07, $57, $dc, $c3, $42, $20, $01, $41, $21, $01, $e4, $b1
    db $71, $dc, $c5, $e3, $0d, $dc, $c3, $00, $10, $22, $00, $e4, $a1, $91, $dc, $c5
    db $e3, $05, $dc, $c3, $e4, $91, $a2, $90, $71, $51, $dc, $c5, $77, $dc, $c2, $91
    db $90, $dc, $c3, $a0, $e3, $01, $e4, $a1, $91, $51, $e3, $01, $e4, $93, $dc, $c1
    db $e3, $20, $20, $25, $00, $00, $03, $dc, $c2, $e4, $91, $90, $dc, $c3, $a0, $e3
    db $01, $e4, $a1, $91, $51, $e3, $01, $e4, $93, $dc, $c1, $e3, $20, $20, $25, $40
    db $40, $43, $dc, $c2, $51, $50, $40, $21, $01, $21, $01, $e4, $a1, $93, $dc, $c3
    db $20, $40, $51, $21, $41, $40, $50, $73, $dc, $c2, $e3, $01, $00, $dc, $c4, $e4
    db $a0, $91, $a1, $e3, $05, $e4, $91, $dc, $c2, $a1, $a0, $dc, $c4, $e3, $00, $21
    db $e4, $b1, $dc, $c6, $e3, $07, $dc, $c2, $e4, $91, $90, $dc, $c3, $a0, $e3, $01
    db $e4, $a1, $91, $51, $e3, $01, $e4, $93, $dc, $c1, $e3, $20, $20, $25, $40, $40
    db $43, $ec, $02, $dc, $b2, $51, $e4, $53, $53, $53, $53, $53, $53, $53, $ec, $03
    db $dc, $c2, $41, $92, $90, $91, $a1, $e3, $03, $d6, $c2, $e4, $40, $50, $70, $90
    db $a0, $e3, $00, $20, $40, $55, $41, $23, $43, $d6, $c6, $0f, $d6, $c3, $25, $01
    db $e4, $a3, $e3, $23, $d8, $c3, $01, $e4, $a1, $e3, $01, $e4, $a1, $e3, $01, $e4
    db $a1, $ff
MusicSequenceData_6f22::
    db $e3, $01, $21, $01, $21, $01, $21, $d8, $c6, $0b, $d8, $c3, $c1, $c1, $c1, $c1
    db $c1, $c1, $d8, $c6, $cb, $ff
MusicSequenceData_6f38::
    db $d8, $c3, $c1, $c1, $c1, $c1, $c1, $c1, $d8, $c6, $cb, $e3, $01, $21, $01, $21
    db $01, $21, $d8, $c6, $0b, $ff
MusicSequenceData_6f4e::
    db $d8, $c6, $eb, $00, $45, $5f, $c7, $cf, $cf, $cf, $ff
MusicSequenceData_6f59::
    db $d8, $c6, $cf, $e4, $eb, $00, $55, $5f, $e3, $c7, $cf, $cf, $ff
MusicSequenceData_6f66::
    db $d8, $d0, $ea, $00, $60, $e4, $ab, $ea, $00, $00, $dc, $d1, $e3, $0f, $dc, $c1
    db $c0, $cf, $c2, $01, $e4, $01, $ff
LinkMasterChannel2Sequence::
    SOUND_FREQ_CARRY_TOGGLE
LinkSlaveChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $06, $10
    SOUND_OCTAVE $04
    db $42
    SOUND_REST_NOTE $00
    db $40
    SOUND_REST_NOTE $00
    db $40
    SOUND_REST_NOTE $00
    SOUND_LENGTH_ENVELOPE $0c, $10
    db $43
    SOUND_REST_NOTE $0b
    db $20
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $05
    db $70
    SOUND_REST_NOTE $02
MusicSequenceData_6f92::
    db $00, $c0, $e4, $00, $c0, $e5, $50, $c0, $e4, $00, $c0, $e5, $40, $c0, $e4, $00
    db $c0, $e5, $20, $c0, $e4, $00, $c0, $e5, $00, $c0, $e4, $00, $c0, $e5, $50, $c0
    db $e4, $00, $c0, $e5, $40, $c0, $e4, $00, $c0, $e5, $20, $c0, $e4, $00, $c0, $e5
    db $40, $c0, $e4, $20, $c0, $e5, $a0, $c0, $e4, $20, $c0, $e5, $90, $c0, $e4, $20
    db $c0, $e5, $70, $c0, $e4, $20, $c0, $e5, $50, $c0, $e4, $40, $c0, $00, $c0, $40
    db $c0, $e5, $90, $c0, $e4, $40, $c0, $e5, $70, $c0, $e4, $00, $c0, $e5, $00, $c0
    db $e4, $00, $c0, $e5, $50, $c0, $e4, $00, $c0, $e5, $40, $c0, $e4, $00, $c0, $e5
    db $20, $c0, $e4, $00, $c0, $e5, $00, $c0, $e4, $00, $c0, $e5, $50, $c0, $e4, $00
    db $c0, $e5, $40, $c0, $e4, $00, $c0, $e5, $20, $c0, $e4, $00, $c0, $e5, $40, $c0
    db $e4, $20, $c0, $e5, $70, $c0, $e4, $20, $c0, $e5, $20, $c0, $e4, $20, $c0, $e5
    db $50, $c0, $e4, $20, $c0, $e5, $00, $c0, $e4, $40, $c0, $00, $c0, $40, $c0, $e5
    db $a0, $c0, $e4, $40, $c0, $e5, $70, $c0, $e4, $40, $c0, $e5, $20, $c0, $e4, $20
    db $c0, $e5, $70, $c0, $e4, $20, $c0, $e5, $00, $c0, $e4, $00, $c0, $e5, $40, $c0
    db $e4, $00, $c0, $e6, $a0, $c0, $e5, $a0, $c0, $20, $c0, $a0, $c0, $e6, $90, $c0
    db $e5, $90, $90, $90, $c0, $70, $c0, $e6, $90, $c0, $e5, $90, $c0, $00, $c0, $90
    db $c0, $e6, $50, $c0, $e5, $90, $c0, $00, $c0, $90, $c0, $e6, $a0, $c0, $e5, $a0
    db $c0, $20, $c0, $a0, $c0, $00, $c0, $e4, $00, $c0, $e5, $70, $c0, $e4, $00, $c0
    db $e6, $90, $c0, $e5, $90, $c0, $00, $c0, $90, $c0, $e6, $50, $c0, $e5, $90, $c0
    db $00, $c0, $90, $c0, $e6, $a0, $c0, $e5, $a0, $c0, $20, $c0, $a0, $c0, $00, $c0
    db $e4, $00, $c0, $e5, $70, $c0, $e4, $00, $c0, $e6, $90, $c0, $e5, $90, $c0, $00
    db $c0, $90, $c0, $e6, $50, $c0, $e5, $90, $c0, $00, $c0, $90, $c0, $e6, $a0, $c0
    db $e5, $a0, $c0, $20, $c0, $a0, $c0, $40, $c0, $e4, $00, $c0, $e5, $00, $c0, $e4
    db $00, $c0, $e5, $50, $cf, $c8, $40, $50, $70, $c0, $40, $c0, $e6, $90, $c0, $e5
    db $90, $c0, $00, $c0, $90, $c0, $e6, $50, $c0, $e5, $90, $c0, $00, $c0, $90, $c0
    db $e6, $a0, $c0, $e5, $a0, $c0, $20, $c0, $a0, $c0, $00, $c0, $e4, $00, $c0, $e5
    db $70, $c0, $e4, $00, $c0, $e5, $50, $c0, $e4, $50, $c0, $00, $c0, $50, $c0, $e5
    db $a0, $c0, $e4, $50, $c0, $e5, $90, $c0, $e4, $50, $c0, $e5, $50, $c0, $e4, $50
    db $c0, $00, $c0, $50, $c0, $e5, $a0, $c0, $e4, $50, $c0, $e5, $90, $c0, $e4, $50
    db $c0, $e5, $50, $c0, $e4, $50, $c0, $00, $c0, $50, $c0, $e5, $a0, $c0, $e4, $50
    db $c0, $e5, $90, $c0, $e4, $50, $c0, $e5, $50, $c0, $e4, $50, $c0, $00, $c0, $50
    db $c0, $e5, $a0, $c0, $e4, $50, $c0, $e5, $90, $c0, $e4, $50, $c0, $e5, $70, $c0
    db $e4, $70, $c0, $20, $c0, $70, $c0, $00, $c0, $70, $c0, $e5, $a0, $c0, $e4
MusicSequenceData_7191::
    db $70, $c0, $e5, $00, $c0, $e4, $70, $c0, $e5, $40, $c0, $e4, $70, $c0, $e5, $70
    db $c0, $e4, $70, $c0, $e5, $a0, $c0, $e4, $70, $c0, $e5, $00, $c0, $e4, $70, $c0
    db $e5, $40, $c0, $e4, $70, $c0, $e5, $70, $c0, $e4, $70, $c0, $e5, $a0, $c0, $e4
MusicSequenceData_71c1::
    db $70
MusicSequenceData_71c2::
    db $c0, $e5, $50, $cf, $cf, $cf, $cf, $cf, $c8, $01, $21, $41, $fe, $00, $92, $6f
LinkMasterChannel3Sequence::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_71f2
MusicSequenceData_71d5::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7217
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_74f0
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_753c
    SOUND_LOOP_JUMP $00, MusicSequenceData_71d5
LinkSlaveChannel3Sequence::
    db SOUND_SUBSEQUENCE_CALL_COMMAND, LOW(MusicSequenceData_71f2)
MusicSequenceData_71e4::
    db HIGH(MusicSequenceData_71f2)
MusicSequenceData_71e5::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7217
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7516
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_753c
    SOUND_LOOP_JUMP $00, MusicSequenceData_71e5
MusicSequenceData_71f2::
    db $dc, $c3, $d6, $b0, $0a, $b0, $06, $b0, $0a, $b0, $06, $b0, $0a, $b0, $06, $b0
    db $0a, $b0, $06, $b1, $05, $cd, $b1, $05, $c5, $b1, $05, $c3, $b1, $05, $b1, $05
    db $c5, $b1, $09, $c5, $ff
MusicSequenceData_7217::
    db $d6, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $07, $c1, $b1, $07
    db $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
    db $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $b1, $07
    db $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1
    db $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $07
    db $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1
    db $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
    db $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $b1
    db $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1
    db $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $05, $c1, $b1, $08, $cf, $cf, $cd, $b1, $08
    db $c9, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
MusicSequenceData_73b3::
    db $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1
MusicSequenceData_73c1::
    db $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
    db $c1, $b1, $07, $c1, $b1, $07, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $07, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $c1, $b1, $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
    db $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $b1
    db $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $05, $c1, $b1, $05, $b1
    db $05, $c1, $b1, $05, $b1, $05, $c1, $b1, $05, $b1, $05, $b1, $05, $c5, $b1, $05
    db $c1, $b1, $05, $b1, $05, $b1, $05, $c1, $b1, $05, $c1, $b1, $05, $c1, $b1, $05
    db $c1, $b1, $05, $c5, $d8, $b1, $05, $b1, $04, $b1, $05, $b1, $05, $c3, $b1, $05
    db $b1, $04, $b1, $05, $b1, $05, $c3, $d6, $b0, $0a, $b0, $06, $b0, $0a, $b0, $06
    db $b0, $0a, $b0, $06, $b0, $0a, $b0, $06, $b0, $0a, $b0, $06, $b0, $0a, $b0, $06
    db $b0, $0a, $b0, $06, $b0, $0a, $b0, $06, $b1, $05, $c1, $b1, $05, $c9, $ff
MusicSequenceData_74f0::
    db $b1, $05, $c5, $b1, $07, $c5, $b1, $05, $c1, $b1, $07, $c5, $b1, $05, $c1, $d8
    db $b1, $05, $b1, $07, $b1, $05, $b1, $07, $b1, $05, $b1, $07, $dc, $b0, $05, $c2
    db $b0, $09, $c0, $b0, $07, $ff
MusicSequenceData_7516::
    db $b1, $07, $c5, $b1, $05, $c5, $b1, $07, $c1, $b1, $05, $c5, $b1, $07, $c1, $d8
    db $b1, $07, $b1, $05, $b1, $07, $b1, $05, $b1, $07, $b1, $05, $dc, $b0, $05, $c2
    db $b0, $09, $c0, $b0, $07, $ff
MusicSequenceData_753c::
    db $c0, $ff
ConfirmChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_MASTER_VOLUME $77
    SOUND_VIBRATO $18, $26
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $b1
    SOUND_OCTAVE $04
    db $01, $00, $00
    SOUND_LENGTH_ENVELOPE $0c, $b3
    db $01, $51
    SOUND_LENGTH_ENVELOPE $0c, $b0
    db $97
    SOUND_LENGTH_ENVELOPE $0c, $b7
    db $9f
    SOUND_LENGTH_ENVELOPE $0c, $92
    SOUND_OCTAVE $03
    SOUND_PITCH_SLIDE $00, $19, $91
    SOUND_REST_NOTE $07
    SOUND_SEQUENCE_END
ConfirmChannel1Sequence::
    SOUND_VIBRATO $10, $27
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $c1
    SOUND_OCTAVE $04
    db $51, $50, $50
    SOUND_LENGTH_ENVELOPE $0c, $c3
    db $51, $91
    SOUND_LENGTH_ENVELOPE $0c, $c0
    SOUND_OCTAVE $03
    db $07
    SOUND_LENGTH_ENVELOPE $0c, $c7
    db $0f
    SOUND_LENGTH_ENVELOPE $0c, $b3
    SOUND_OCTAVE $02
    SOUND_PITCH_SLIDE $00, $00, $01
    SOUND_SEQUENCE_END
ConfirmChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_OCTAVE $04
    db $90
    SOUND_REST_NOTE $00
    SOUND_LENGTH_ENVELOPE $06, $10
    db $90
    SOUND_REST_NOTE $00
    db $90
    SOUND_REST_NOTE $00
    SOUND_LENGTH_ENVELOPE $0c, $10
    db $90
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $03
    db $00
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $04
    db $93
    SOUND_REST_NOTE $03
    SOUND_REST_NOTE $0f
    SOUND_OCTAVE $03
    SOUND_PITCH_SLIDE $00, $10, $01
    SOUND_SEQUENCE_END
ConfirmChannel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
    SOUND_REST_NOTE $0f
    SOUND_CHANNEL3_LENGTH_SCALE $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0d
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0d
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0c
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0c
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0b
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0b
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0b
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0b
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $06
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $00, $0a
    SOUND_CHANNEL3_LENGTH_SCALE $08
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $05
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $05
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $05
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $09
    SOUND_SEQUENCE_END
LinkResultNonzeroChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_VIBRATO $0a, $23
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $b3
    SOUND_OCTAVE $05
    db $91, $90, $a0
    SOUND_OCTAVE $04
    db $05, $01
    SOUND_OCTAVE $05
    db $91
    SOUND_OCTAVE $04
    db $01, $21, $41, $51, $71, $97
    SOUND_SEQUENCE_END
LinkResultNonzeroChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $08, $24
    SOUND_LENGTH_ENVELOPE $0c, $c3
    SOUND_OCTAVE $04
    db $51, $50, $50, $55, $51, $71, $91, $a2
    SOUND_OCTAVE $03
    db $00, $21, $41, $57
    SOUND_SEQUENCE_END
LinkResultNonzeroChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_OCTAVE $05
    db $51, $50, $40, $55, $01, $21, $41, $52, $70, $91, $71, $53
    SOUND_REST_NOTE $03
    SOUND_SEQUENCE_END
LinkResultZeroChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_VIBRATO $0c, $23
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $03, $93
    SOUND_REST_NOTE $00
    SOUND_LENGTH_ENVELOPE $0c, $93
    SOUND_OCTAVE $05
    db $91, $90, $a0
    SOUND_OCTAVE $04
    db $05, $01
    SOUND_OCTAVE $05
    db $91
    SOUND_OCTAVE $04
    db $01, $21, $41, $51, $71, $97
    SOUND_SEQUENCE_END
LinkResultZeroChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_VIBRATO $0a, $24
    SOUND_LENGTH_ENVELOPE $03, $a3
    SOUND_REST_NOTE $00
    SOUND_LENGTH_ENVELOPE $0c, $a3
    SOUND_OCTAVE $04
    db $51, $50, $50, $55, $51, $71, $91, $a2
    SOUND_OCTAVE $03
    db $00, $21, $41, $57
    SOUND_SEQUENCE_END
LinkResultZeroChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $03, $10
    SOUND_REST_NOTE $00
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_OCTAVE $05
    db $51, $50, $40, $55, $01, $21, $41, $52, $70, $91, $71, $53
    SOUND_REST_NOTE $03
    SOUND_SEQUENCE_END
LinkResultConfirmWaitChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_VIBRATO $09, $24
    SOUND_DUTY_LENGTH $02
MusicSequenceData_7671::
    SOUND_LENGTH_ENVELOPE $0c, $b3
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7690
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7690
    SOUND_LENGTH_ENVELOPE $0c, $93
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_76d5
    SOUND_LENGTH_ENVELOPE $0c, $b3
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7690
    SOUND_LENGTH_ENVELOPE $0c, $93
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_76f4
    SOUND_LOOP_JUMP $00, MusicSequenceData_7671
MusicSequenceData_7690::
    SOUND_OCTAVE $04
    db $02
    SOUND_OCTAVE $05
    db $90
    SOUND_OCTAVE $04
    db $01, $53, $43, $21, $43, $7b
    SOUND_OCTAVE $05
    db $a2, $70
    SOUND_OCTAVE $04
    db $01, $43, $23, $41, $53, $0b
    SOUND_SEQUENCE_END
LinkResultConfirmWaitChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $0b, $23
MusicSequenceData_76ab::
    SOUND_LENGTH_ENVELOPE $0c, $c2
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_76d5
    SOUND_LENGTH_ENVELOPE $0c, $c1
    db $e6, $53, $03, $23, $43, $73, $03, $23, $03, $43, $03, $23, $43, $53, $03, $23
    db $43
    SOUND_LENGTH_ENVELOPE $0c, $c2
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_76d5
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_76d5
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7702
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_76f4
    SOUND_LOOP_JUMP $00, MusicSequenceData_76ab
MusicSequenceData_76d5::
    SOUND_OCTAVE $04
    db $52, $90
    SOUND_OCTAVE $03
    db $01, $23, $03
    SOUND_OCTAVE $04
    db $91, $a3
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $00
    SOUND_OCTAVE $05
    db $b0
    SOUND_OCTAVE $04
    db $01
    SOUND_OCTAVE $05
    db $a1, $73
    SOUND_OCTAVE $04
    db $42, $70, $91, $a3, $93, $71, $93, $5b
    SOUND_SEQUENCE_END
MusicSequenceData_76f4::
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $05
    SOUND_OCTAVE $04
    db $00
    SOUND_OCTAVE $05
    db $b0
    SOUND_OCTAVE $04
    db $01
    SOUND_OCTAVE $05
    db $a1, $73
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SEQUENCE_END
MusicSequenceData_7702::
    SOUND_OCTAVE $04
    db $52, $90
    SOUND_OCTAVE $03
    db $01, $23, $03
    SOUND_OCTAVE $04
    db $91, $a3
    SOUND_OCTAVE $03
    db $01
    SOUND_REST_NOTE $09
    SOUND_OCTAVE $04
    db $42, $70, $91, $a3, $93, $71, $93, $5b
    SOUND_SEQUENCE_END
LinkResultConfirmWaitChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7760
    SOUND_OCTAVE $03
    db $50
    SOUND_REST_NOTE $01
    db $90
    SOUND_OCTAVE $02
    db $00
    SOUND_REST_NOTE $00
    db $20
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $03
    db $90
    SOUND_REST_NOTE $00
    db $a0
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $02
    db $00
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $03
    db $00
    SOUND_OCTAVE $04
    db $b0
    SOUND_OCTAVE $03
    db $00
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $04
    db $a0
    SOUND_REST_NOTE $00
    db $70
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $03
    db $40
    SOUND_REST_NOTE $01
    db $70, $90
    SOUND_REST_NOTE $00
    db $a0
    SOUND_REST_NOTE $02
    db $90
    SOUND_REST_NOTE $02
    db $70
    SOUND_REST_NOTE $00
    db $90
    SOUND_REST_NOTE $02
    db $50
    SOUND_REST_NOTE $0a
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7760
    SOUND_LOOP_JUMP $00, LinkResultConfirmWaitChannel2Sequence
MusicSequenceData_7760::
    SOUND_OCTAVE $04
    db $50
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    db $70
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    db $50
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    SOUND_SEQUENCE_END
LinkResultConfirmWaitChannel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
MusicSequenceData_7783::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_779b
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_779b
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_77ca
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_77b6
    SOUND_LOOP_JUMP $00, MusicSequenceData_7783
MusicSequenceData_779b::
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_779b
    SOUND_SEQUENCE_END
MusicSequenceData_77b6::
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $0e
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_REST_NOTE $03
MusicSequenceData_77c5::
    SOUND_LOOP_JUMP $02, MusicSequenceData_77b6
    SOUND_SEQUENCE_END
MusicSequenceData_77ca::
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_77ca
    SOUND_SEQUENCE_END
LinkResultMenuWaitChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_VIBRATO $0c, $24
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $b3
MusicSequenceData_77eb::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7806
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7806
    SOUND_LENGTH_ENVELOPE $0c, $93
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_784c
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_786b
    SOUND_LENGTH_ENVELOPE $0c, $b3
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7806
    SOUND_LOOP_JUMP $00, MusicSequenceData_77eb
MusicSequenceData_7806::
    SOUND_OCTAVE $04
    db $02
    SOUND_OCTAVE $05
    db $90
    SOUND_OCTAVE $04
    db $01, $53, $43, $21, $43, $7b
    SOUND_OCTAVE $05
    db $a2, $70
    SOUND_OCTAVE $04
    db $01, $43, $23, $41, $53, $0b
    SOUND_SEQUENCE_END
LinkResultMenuWaitChannel1Sequence::
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $0a, $23
MusicSequenceData_7822::
    SOUND_LENGTH_ENVELOPE $0c, $c2
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_784c
    SOUND_LENGTH_ENVELOPE $0c, $c1
    SOUND_OCTAVE $06
    db $53, $03, $23, $43, $73, $03, $23, $03, $43, $03, $23, $43, $53, $03, $23, $43
    SOUND_LENGTH_ENVELOPE $0c, $c2
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_784c
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_784c
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_786b
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7879
    SOUND_LOOP_JUMP $00, MusicSequenceData_7822
MusicSequenceData_784c::
    SOUND_OCTAVE $04
    db $52, $90
    SOUND_OCTAVE $03
    db $01, $23, $03
    SOUND_OCTAVE $04
    db $91, $a3
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $00
    SOUND_OCTAVE $05
    db $b0
    SOUND_OCTAVE $04
    db $01
    SOUND_OCTAVE $05
    db $a1, $73
    SOUND_OCTAVE $04
    db $42, $70, $91, $a3, $93, $71, $93, $5b
    SOUND_SEQUENCE_END
MusicSequenceData_786b::
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $05
    SOUND_OCTAVE $04
    db $00
    SOUND_OCTAVE $05
    db $b0
    SOUND_OCTAVE $04
    db $01
    SOUND_OCTAVE $05
    db $a1, $73
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SEQUENCE_END
MusicSequenceData_7879::
    SOUND_OCTAVE $04
    db $52, $90
    SOUND_OCTAVE $03
    db $01, $23, $03
    SOUND_OCTAVE $04
    db $91, $a3
    SOUND_OCTAVE $03
    db $01
    SOUND_REST_NOTE $09
    SOUND_OCTAVE $04
    db $42, $70, $91, $a3, $93, $71, $93, $5b
    SOUND_SEQUENCE_END
LinkResultMenuWaitChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_78d7
    SOUND_OCTAVE $03
    db $50
    SOUND_REST_NOTE $01
    db $90
    SOUND_OCTAVE $02
    db $00
    SOUND_REST_NOTE $00
    db $20
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $03
    db $90
    SOUND_REST_NOTE $00
    db $a0
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $02
    db $00
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $03
    db $00
    SOUND_OCTAVE $04
    db $b0
    SOUND_OCTAVE $03
    db $00
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $04
    db $a0
    SOUND_REST_NOTE $00
    db $70
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $03
    db $40
    SOUND_REST_NOTE $01
    db $70, $90
    SOUND_REST_NOTE $00
    db $a0
    SOUND_REST_NOTE $02
    db $90
    SOUND_REST_NOTE $02
    db $70
    SOUND_REST_NOTE $00
    db $90
    SOUND_REST_NOTE $02
    db $50
    SOUND_REST_NOTE $0a
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_78d7
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_LOOP_JUMP $00, LinkResultMenuWaitChannel2Sequence
MusicSequenceData_78d7::
    SOUND_OCTAVE $04
    db $50
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    db $70
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    db $50
    SOUND_REST_NOTE $02
    db $00
    SOUND_REST_NOTE $02
    db $20
    SOUND_REST_NOTE $02
    db $40
    SOUND_REST_NOTE $02
    SOUND_SEQUENCE_END
LinkResultMenuWaitChannel3Sequence::
    SOUND_CHANNEL3_LENGTH_SCALE $0c
MusicSequenceData_78fa::
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7912
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7912
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_REST_NOTE $0f
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_792d
    SOUND_SUBSEQUENCE_CALL MusicSequenceData_7941
    SOUND_LOOP_JUMP $00, MusicSequenceData_78fa
MusicSequenceData_7912::
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_7912
    SOUND_SEQUENCE_END
MusicSequenceData_792d::
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $0e
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $0e
    SOUND_REST_NOTE $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_792d
    SOUND_SEQUENCE_END
MusicSequenceData_7941::
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_REST_NOTE $01
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $01, $03
    SOUND_REST_NOTE $03
    SOUND_CHANNEL3_NESTED_SOUND_NOTE $03, $03
    SOUND_LOOP_JUMP $02, MusicSequenceData_7941
    SOUND_SEQUENCE_END
TwoPlayerPreplayMasterInitChannel0Sequence::
    SOUND_TEMPO $00, $90
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $04, $b1
    SOUND_REST_NOTE $00
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $08, $b1
MusicSequenceData_7965::
    SOUND_OCTAVE $04
    db $02, $00, $00, $00, $41, $01, $41, $71, $41, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $42, $40, $40, $40, $71, $41, $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01, $43, $41, $02, $00, $00, $00
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71, $41, $03, $01, $43, $41, $73, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $73, $71, $73, $71
    SOUND_OCTAVE $03
    db $03, $01, $43, $41, $03, $01, $01, $01, $01, $45, $01, $01, $01, $45
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_LOOP_JUMP $00, MusicSequenceData_7965
TwoPlayerPreplayMasterInitChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $08, $c1
MusicSequenceData_79c3::
    SOUND_OCTAVE $04
    db $02, $00, $00, $00, $41, $01, $41, $71, $41, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $42, $40, $40, $40, $71, $41, $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01, $43, $41, $02, $00, $00, $00
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71, $41, $03, $01, $43, $41, $73, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $73, $71, $73, $71
    SOUND_OCTAVE $03
    db $03, $01, $43, $41, $03, $01, $01, $01, $01, $45, $01, $01, $01, $45
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_LOOP_JUMP $00, MusicSequenceData_79c3
TwoPlayerPreplaySlaveInitChannel0Sequence::
    SOUND_TEMPO $00, $90
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $04, $b1
    SOUND_REST_NOTE $00
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $c1
    SOUND_REST_NOTE $0f
MusicSequenceData_7a2b::
    SOUND_LENGTH_ENVELOPE $08, $b1
    SOUND_OCTAVE $04
    db $02, $00, $00, $00, $41, $01, $41, $71, $41, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $42, $40, $40, $40, $71, $41, $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01, $43, $41, $02, $00, $00, $00
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71, $41, $03, $01, $43, $41, $73, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $73, $71, $73, $71
    SOUND_OCTAVE $03
    db $03, $01, $43, $41, $03, $01, $01, $01, $01, $45, $01, $01, $01, $45
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_LOOP_JUMP $00, MusicSequenceData_7a2b
TwoPlayerPreplaySlaveInitChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $c1
    SOUND_REST_NOTE $0f
MusicSequenceData_7a8c::
    SOUND_LENGTH_ENVELOPE $08, $c1
    SOUND_OCTAVE $04
    db $02, $00, $00, $00, $41, $01, $41, $71, $41, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $42, $40, $40, $40, $71, $41, $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01, $43, $41, $02, $00, $00, $00
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71
    SOUND_OCTAVE $03
    db $01
    SOUND_OCTAVE $04
    db $71, $41, $03, $01, $43, $41, $73, $71
    SOUND_OCTAVE $03
    db $03, $01
    SOUND_OCTAVE $04
    db $73, $71, $73, $71
    SOUND_OCTAVE $03
    db $03, $01, $43, $41, $03, $01, $01, $01, $01, $45, $01, $01, $01, $45
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_OCTAVE $04
    db $71, $71, $71
    SOUND_OCTAVE $03
    db $05
    SOUND_LOOP_JUMP $00, MusicSequenceData_7a8c
Result1PNoRankChannel0Sequence::
    SOUND_TEMPO $00, $90
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $03
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_VIBRATO $05, $25
    SOUND_LENGTH_ENVELOPE $0c, $b1
    SOUND_OCTAVE $05
    db $70, $50, $40, $20, $01
    SOUND_OCTAVE $06
    db $b1, $91
    SOUND_OCTAVE $05
    db $41
    SOUND_OCTAVE $06
    db $71
    SOUND_OCTAVE $05
    db $21, $01
    SOUND_OCTAVE $06
    db $b1, $91, $71, $43
    SOUND_OCTAVE $07
    db $73
    SOUND_SEQUENCE_END
Result1PNoRankChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $06, $26
    SOUND_LENGTH_ENVELOPE $0c, $c2
    SOUND_OCTAVE $04
    db $01
    SOUND_OCTAVE $05
    db $b1, $91, $71, $40, $50, $71, $20, $40, $51, $41, $21, $01
    SOUND_OCTAVE $06
    db $b1
    SOUND_OCTAVE $05
    db $03
    SOUND_LENGTH_ENVELOPE $0c, $b1
    SOUND_OCTAVE $06
    db $03
    SOUND_SEQUENCE_END
Result1PNoRankChannel2Sequence::
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_REST_NOTE $0f
    SOUND_OCTAVE $06
    db $90, $b0
    SOUND_OCTAVE $05
    db $01, $00, $20, $41, $01
    SOUND_REST_NOTE $01
    SOUND_OCTAVE $06
    db $01
    SOUND_REST_NOTE $01
    SOUND_SEQUENCE_END
Result1PRankedChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_VIBRATO $01, $23
    SOUND_LENGTH_ENVELOPE $0c, $b1
    SOUND_OCTAVE $05
    db $b0
    SOUND_OCTAVE $04
    db $84, $90, $81, $60, $41, $30
    SOUND_OCTAVE $05
    db $b1, $90, $81, $90, $b2
    SOUND_LENGTH_ENVELOPE $0c, $b2
    SOUND_OCTAVE $04
    db $89
    SOUND_SEQUENCE_END
Result1PRankedChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_VIBRATO $00, $24
    SOUND_LENGTH_ENVELOPE $0c, $c2
    SOUND_OCTAVE $04
    db $40, $b4
    SOUND_OCTAVE $03
    db $10
    SOUND_OCTAVE $04
    db $b1, $90, $81, $60, $41, $60, $81, $60, $42
    SOUND_LENGTH_ENVELOPE $0c, $c3
    SOUND_OCTAVE $03
    db $49
    SOUND_SEQUENCE_END
Result2PNonzeroRankChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $b1
    SOUND_REST_NOTE $00
    SOUND_REST_NOTE $00
    SOUND_REST_NOTE $00
    SOUND_OCTAVE $04
    db $70, $70, $70
    SOUND_LENGTH_ENVELOPE $0c, $b4
    SOUND_OCTAVE $03
    db $0f
    SOUND_SEQUENCE_END
Result2PNonzeroRankChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $c1
    SOUND_OCTAVE $04
    db $00, $40, $70
    SOUND_OCTAVE $03
    db $00, $00, $00
    SOUND_LENGTH_ENVELOPE $0c, $c4
    db $4f
    SOUND_SEQUENCE_END
Result2PZeroRankChannel0Sequence::
    SOUND_TEMPO $00, $80
    SOUND_MASTER_VOLUME $77
    SOUND_DUTY_LENGTH $02
    SOUND_FREQ_CARRY_TOGGLE
    SOUND_LENGTH_ENVELOPE $0c, $b1
    SOUND_OCTAVE $05
    SOUND_PITCH_SLIDE $00, $40, $00
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $05
    SOUND_PITCH_SLIDE $00, $47, $70
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $06
    SOUND_PITCH_SLIDE $00, $50, $00
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $06
    SOUND_PITCH_SLIDE $00, $57, $70
    SOUND_REST_NOTE $02
    SOUND_SEQUENCE_END
Result2PZeroRankChannel1Sequence::
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $0c, $c1
    SOUND_OCTAVE $04
    SOUND_PITCH_SLIDE $00, $50, $00
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $04
    SOUND_PITCH_SLIDE $00, $57, $70
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $05
    SOUND_PITCH_SLIDE $00, $60, $00
    SOUND_REST_NOTE $02
    SOUND_OCTAVE $05
    SOUND_PITCH_SLIDE $00, $67, $70
    SOUND_REST_NOTE $02
    SOUND_SEQUENCE_END
MusicSequenceData_7bdf::
    SOUND_GATE_FLAG
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $04, $e1
    SOUND_OCTAVE $02
    SOUND_EXTENDED_NOTE $00, $00, $e3, $b0
    db $90
    SOUND_SEQUENCE_END
    SOUND_GATE_FLAG
    SOUND_DUTY_LENGTH $02
    SOUND_LENGTH_ENVELOPE $04, $e1
    SOUND_OCTAVE $03
    db $50, $90
    SOUND_OCTAVE $02
    db $00
    SOUND_LENGTH_ENVELOPE $0c, $e3
    db $5f
    SOUND_SEQUENCE_END
    SOUND_GATE_FLAG
    SOUND_LENGTH_ENVELOPE $0c, $10
    SOUND_OCTAVE $03
    SOUND_PITCH_SLIDE $00, $65, $53
    SOUND_SEQUENCE_END
TickBgmPreviewTimer::
    ld hl, BGM_PREVIEW_TIMER
    dec [hl]
    ret nz

    ret


ApplySoundVisualUpdateCommand::
    ld hl, GAME_STATE
    ld a, [hl]
    cp GAME_STATE_PLAYING
    jp z, ToggleEggTextAltAnimation

    ld a, [OPTION_BGM]
    add BGM_CURSOR_OBJECT_SLOT_BASE
    swap a
    ld l, a
    ld h, SPRITE_OBJECTS_HI
    ; SPRITE_OBJECT_TOGGLED_FRAME is copied to SPRITE_OBJECT_FRAME when selected.
    inc l
    inc l
    inc l
    ld a, [hl]
    xor BGM_CURSOR_FRAME_TOGGLE_MASK
    ld [hl], a
    ld a, [MENU_CURSOR]
    cp MENU_CURSOR_ROW_BGM
    ret nz

    ld a, [hl]
    dec l
    ld [hl], a
    ret

MACRO SOUND_INDEX_ENTRY
    db \1
    dw \2
ENDM

SoundIndexTable::
SoundIndexEntry_00::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_SENTINEL_FLAGS, SOUND_INDEX_ENTRY_SENTINEL_POINTER
SoundIndexEntry_01::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7d85
SoundIndexEntry_02::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7d89
SoundIndexEntry_03::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7d8d
SoundIndexEntry_04::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7d91
SoundIndexEntry_05::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7d95
SoundIndexEntry_06::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7d99
SoundIndexEntry_07::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7d9d
SoundIndexEntry_08::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7da1
SoundIndexEntry_09::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7da5
SoundIndexEntry_0a::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7da9
SoundIndexEntry_0b::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7dad
SoundIndexEntry_0c::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7db1
SoundIndexEntry_0d::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7db5
SoundIndexEntry_0e::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7db9
SoundIndexEntry_0f::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7fd0
SoundIndexEntry_10::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_5, SoundSequenceData_7fe3
SoundIndexEntry_LinkFieldRise::
SoundIndexEntry_11::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, MusicSequenceData_7bdf
SoundIndexEntry_RoundCompleteReveal::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7ef6
SoundIndexEntry_13::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_5, SoundSequenceData_7f0d
SoundIndexEntry_14::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_6, SoundSequenceData_7f1b
SoundIndexEntry_15::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7f1c
SoundIndexEntry_RoundCompleteMajorReveal::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7f9d
SoundIndexEntry_17::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_5, SoundSequenceData_7fb4
SoundIndexEntry_18::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_6, SoundSequenceData_7fc2
SoundIndexEntry_19::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_7, SoundSequenceData_7fc3
SoundIndexEntry_1a::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7f29
SoundIndexEntry_DropStart::
SoundIndexEntry_1b::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e2c
SoundIndexEntry_PlacePiece::
SoundIndexEntry_1c::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e5c
SoundIndexEntry_1d::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7eb4
SoundIndexEntry_BoardScanStep7::
SoundIndexEntry_1e::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_5, SoundSequenceData_7ec7
SoundIndexEntry_BoardScanStep6::
SoundIndexEntry_1f::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7ea9
SoundIndexEntry_BoardScanStep5::
SoundIndexEntry_20::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e9e
SoundIndexEntry_BoardScanStep4::
SoundIndexEntry_21::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e93
SoundIndexEntry_BoardScanStep3::
SoundIndexEntry_22::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e88
SoundIndexEntry_BoardScanStep2::
SoundIndexEntry_23::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e7d
SoundIndexEntry_BoardScanStep1::
SoundIndexEntry_24::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e72
SoundIndexEntry_BoardScanStep0::
SoundIndexEntry_BoardScanStepBase::
SoundIndexEntry_25::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e67
SoundIndexEntry_CommitPiece::
SoundIndexEntry_26::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7e4b
SoundIndexEntry_PieceLand::
SoundIndexEntry_27::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7eda
SoundIndexEntry_CursorMove::
SoundIndexEntry_28::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7eeb
SoundIndexEntry_MatchingOamSlide::
SoundIndexEntry_29::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7f65
SoundIndexEntry_2a::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_5, SoundSequenceData_7f80
SoundIndexEntry_MatchingIntroBlink::
SoundIndexEntry_2b::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7f34
SoundIndexEntry_MatchingResultPanelBlink::
SoundIndexEntry_2c::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7f43
SoundIndexEntry_RoundComplete::
SoundIndexEntry_2d::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7f52
SoundIndexEntry_Pause::
SoundIndexEntry_2e::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_4, SoundSequenceData_7dff
SoundIndexEntry_2f::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_5, SoundSequenceData_7e15
SoundIndexEntry_TitleBgm::
SoundIndexEntry_30::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, TitleBgmChannel0Sequence
SoundIndexEntry_31::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, TitleBgmChannel1Sequence
SoundIndexEntry_32::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, TitleBgmChannel2Sequence
SoundIndexEntry_33::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, TitleBgmChannel3Sequence
SoundIndexEntry_BgmOption0::
SoundIndexEntry_34::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, BgmOption0Channel0Sequence
SoundIndexEntry_35::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, BgmOption0Channel1Sequence
SoundIndexEntry_36::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, BgmOption0Channel2Sequence
SoundIndexEntry_37::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, BgmOption0Channel3Sequence
SoundIndexEntry_BgmPreview0::
SoundIndexEntry_38::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, BgmPreview0Channel0Sequence
SoundIndexEntry_39::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, BgmPreview0Channel1Sequence
SoundIndexEntry_3a::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, BgmPreview0Channel2Sequence
SoundIndexEntry_3b::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, BgmPreview0Channel3Sequence
SoundIndexEntry_BgmOption1::
SoundIndexEntry_3c::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, BgmOption1Channel0Sequence
SoundIndexEntry_3d::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, BgmOption1Channel1Sequence
SoundIndexEntry_3e::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, BgmOption1Channel2Sequence
SoundIndexEntry_3f::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, BgmOption1Channel3Sequence
SoundIndexEntry_BgmPreview1::
SoundIndexEntry_40::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, BgmPreview1Channel0Sequence
SoundIndexEntry_41::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, BgmPreview1Channel1Sequence
SoundIndexEntry_42::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, BgmPreview1Channel2Sequence
SoundIndexEntry_43::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, BgmPreview1Channel3Sequence
SoundIndexEntry_BgmOption2::
SoundIndexEntry_44::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, BgmOption2Channel0Sequence
SoundIndexEntry_45::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, BgmOption2Channel1Sequence
SoundIndexEntry_46::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, BgmOption2Channel2Sequence
SoundIndexEntry_47::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, BgmOption2Channel3Sequence
SoundIndexEntry_BgmPreview2::
SoundIndexEntry_48::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, BgmPreview2Channel0Sequence
SoundIndexEntry_49::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, BgmPreview2Channel1Sequence
SoundIndexEntry_4a::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, BgmPreview2Channel2Sequence
SoundIndexEntry_4b::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, BgmPreview2Channel3Sequence
SoundIndexEntry_LinkMaster::
SoundIndexEntry_4c::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, LinkRoleSharedChannel0Sequence
SoundIndexEntry_4d::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, LinkMasterChannel1Sequence
SoundIndexEntry_4e::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, LinkMasterChannel2Sequence
SoundIndexEntry_4f::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, LinkMasterChannel3Sequence
SoundIndexEntry_LinkSlave::
SoundIndexEntry_50::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, LinkRoleSharedChannel0Sequence
SoundIndexEntry_51::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, LinkSlaveChannel1Sequence
SoundIndexEntry_52::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, LinkSlaveChannel2Sequence
SoundIndexEntry_53::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, LinkSlaveChannel3Sequence
SoundIndexEntry_Confirm::
SoundIndexEntry_54::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, ConfirmChannel0Sequence
SoundIndexEntry_55::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, ConfirmChannel1Sequence
SoundIndexEntry_56::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, ConfirmChannel2Sequence
SoundIndexEntry_57::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, ConfirmChannel3Sequence
SoundIndexEntry_LinkResultNonzero::
SoundIndexEntry_58::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_3 | SOUND_INDEX_ENTRY_CHANNEL_0, LinkResultNonzeroChannel0Sequence
SoundIndexEntry_59::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, LinkResultNonzeroChannel1Sequence
SoundIndexEntry_5a::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, LinkResultNonzeroChannel2Sequence
SoundIndexEntry_LinkResultZero::
SoundIndexEntry_5b::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_3 | SOUND_INDEX_ENTRY_CHANNEL_0, LinkResultZeroChannel0Sequence
SoundIndexEntry_5c::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, LinkResultZeroChannel1Sequence
SoundIndexEntry_5d::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, LinkResultZeroChannel2Sequence
SoundIndexEntry_LinkResultConfirmWait::
SoundIndexEntry_5e::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, LinkResultConfirmWaitChannel0Sequence
SoundIndexEntry_5f::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, LinkResultConfirmWaitChannel1Sequence
SoundIndexEntry_60::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, LinkResultConfirmWaitChannel2Sequence
SoundIndexEntry_61::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, LinkResultConfirmWaitChannel3Sequence
SoundIndexEntry_LinkResultMenuWait::
SoundIndexEntry_62::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_4 | SOUND_INDEX_ENTRY_CHANNEL_0, LinkResultMenuWaitChannel0Sequence
SoundIndexEntry_63::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, LinkResultMenuWaitChannel1Sequence
SoundIndexEntry_64::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, LinkResultMenuWaitChannel2Sequence
SoundIndexEntry_65::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_3, LinkResultMenuWaitChannel3Sequence
SoundIndexEntry_Result1PNoRank::
SoundIndexEntry_66::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_3 | SOUND_INDEX_ENTRY_CHANNEL_0, Result1PNoRankChannel0Sequence
SoundIndexEntry_67::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, Result1PNoRankChannel1Sequence
SoundIndexEntry_68::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_2, Result1PNoRankChannel2Sequence
SoundIndexEntry_Result1PRanked::
SoundIndexEntry_69::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_0, Result1PRankedChannel0Sequence
SoundIndexEntry_6a::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, Result1PRankedChannel1Sequence
SoundIndexEntry_TwoPlayerPreplayMasterInit::
SoundIndexEntry_6b::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_0, TwoPlayerPreplayMasterInitChannel0Sequence
SoundIndexEntry_6c::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, TwoPlayerPreplayMasterInitChannel1Sequence
SoundIndexEntry_TwoPlayerPreplaySlaveInit::
SoundIndexEntry_6d::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_0, TwoPlayerPreplaySlaveInitChannel0Sequence
SoundIndexEntry_6e::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, TwoPlayerPreplaySlaveInitChannel1Sequence
SoundIndexEntry_Result2PNonzeroRank::
SoundIndexEntry_6f::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_0, Result2PNonzeroRankChannel0Sequence
SoundIndexEntry_70::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, Result2PNonzeroRankChannel1Sequence
SoundIndexEntry_Result2PZeroRank::
SoundIndexEntry_71::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_COUNT_2 | SOUND_INDEX_ENTRY_CHANNEL_0, Result2PZeroRankChannel0Sequence
SoundIndexEntry_72::
    SOUND_INDEX_ENTRY SOUND_INDEX_ENTRY_CHANNEL_1, Result2PZeroRankChannel1Sequence

MACRO SOUND_CHANNEL7_EXTENDED_NOTE
    db SOUND_EXTENDED_NOTE_COMMAND_BASE | \1
    db \2, \3
ENDM

MACRO SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE
    SOUND_CHANNEL7_EXTENDED_NOTE $00, \1, \2
    db SOUND_SEQUENCE_END_COMMAND
ENDM

SoundSequenceData_7d85::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $a1, $98
SoundSequenceData_7d89::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $a1, $23
SoundSequenceData_7d8d::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $a1, $33
SoundSequenceData_7d91::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $a1, $13
SoundSequenceData_7d95::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $a1, $32
SoundSequenceData_7d99::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $81, $32
SoundSequenceData_7d9d::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $61, $22
SoundSequenceData_7da1::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $a3, $13
SoundSequenceData_7da5::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $a1, $43
SoundSequenceData_7da9::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $91, $32
SoundSequenceData_7dad::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $51, $32
SoundSequenceData_7db1::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $41, $32
SoundSequenceData_7db5::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $31, $32
SoundSequenceData_7db9::
    SOUND_CHANNEL7_EXTENDED_NOTE_SEQUENCE $71, $44

MACRO SOUND_WAVE_PATTERN_POINTER
    dw \1
ENDM

SoundWavePatternPointerTable::
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_0
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_1
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_2
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_SharedSequence
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_SharedSequence
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_SharedSequence
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_SharedSequence
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_SharedSequence
    SOUND_WAVE_PATTERN_POINTER SoundWavePatternData_SharedSequence

MACRO SOUND_WAVE_PATTERN_ROW
    db \1, \2, \3, \4, \5, \6, \7, \8
ENDM

SoundWavePatternData_0::
    SOUND_WAVE_PATTERN_ROW $02, $46, $8a, $ce, $ff, $fe, $ed, $dc
    SOUND_WAVE_PATTERN_ROW $cb, $a9, $87, $65, $44, $33, $22, $11
SoundWavePatternData_1::
    SOUND_WAVE_PATTERN_ROW $bb, $ff, $ff, $ff, $ff, $ff, $ff, $bb
    SOUND_WAVE_PATTERN_ROW $44, $00, $00, $00, $00, $00, $00, $44
SoundWavePatternData_2::
    SOUND_WAVE_PATTERN_ROW $01, $12, $34, $57, $9b, $df, $fe, $dc
    SOUND_WAVE_PATTERN_ROW $ba, $98, $76, $54, $43, $32, $21, $11

SoundWavePatternData_SharedSequence::
SoundSequenceData_7dff::
    db $ed, $01, $00, $ec, $02, $24, $f4, $00, $07, $21, $a1, $40, $07, $22, $c1, $80
    db $07, $28, $a2, $c0, $07, $ff
SoundSequenceData_7e15::
    SOUND_DUTY_LENGTH $01
    SOUND_EXTENDED_NOTE $01, $21, $c0, $06
    SOUND_EXTENDED_NOTE $04, $d4, $00, $07
    SOUND_EXTENDED_NOTE $01, $81, $40, $07
    SOUND_EXTENDED_NOTE $02, $a1, $80, $07
    SOUND_EXTENDED_NOTE $08, $82, $c0, $07
    SOUND_SEQUENCE_END
SoundSequenceData_7e2c::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $00, $42, $00, $05
    SOUND_EXTENDED_NOTE $00, $92, $80, $06
    SOUND_EXTENDED_NOTE $00, $d2, $00, $07
    SOUND_EXTENDED_NOTE $00, $f2, $80, $07
    SOUND_EXTENDED_NOTE $00, $d2, $00, $07
    SOUND_EXTENDED_NOTE $00, $92, $80, $06
    SOUND_EXTENDED_NOTE $0a, $41, $00, $05
    SOUND_SEQUENCE_END
SoundSequenceData_7e4b::
    SOUND_DUTY_LENGTH $02
    SOUND_SWEEP $3a
    SOUND_EXTENDED_NOTE $04, $f2, $00, $04
    SOUND_SWEEP $23
    SOUND_EXTENDED_NOTE $08, $f2, $00, $06
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7e5c::
    SOUND_DUTY_LENGTH $00
    SOUND_SWEEP $22
    SOUND_EXTENDED_NOTE $04, $f2, $00, $03
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END

MACRO SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE
    db SOUND_DUTY_LENGTH_COMMAND, \1
    db SOUND_SWEEP_COMMAND, \2
    db SOUND_EXTENDED_NOTE_COMMAND_BASE | \3
    db \4, \5, \6
    db SOUND_SWEEP_COMMAND, \7
    db SOUND_SEQUENCE_END_COMMAND
ENDM

SoundSequenceData_7e67::
    SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE $02, $2d, $06, $f1, $c0, $07, $08
SoundSequenceData_7e72::
    SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE $02, $2d, $06, $f1, $a0, $07, $08
SoundSequenceData_7e7d::
    SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE $02, $2d, $06, $f1, $80, $07, $08
SoundSequenceData_7e88::
    SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE $02, $2d, $06, $f1, $60, $07, $08
SoundSequenceData_7e93::
    SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE $02, $2d, $06, $f1, $40, $07, $08
SoundSequenceData_7e9e::
    SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE $02, $2d, $06, $f1, $20, $07, $08
SoundSequenceData_7ea9::
    SOUND_SWEEP_EXTENDED_NOTE_SEQUENCE $02, $2d, $06, $f1, $00, $07, $08
SoundSequenceData_7eb4::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $00, $c1, $80, $07
    SOUND_EXTENDED_NOTE $01, $f1, $a0, $07
    SOUND_EXTENDED_NOTE $01, $c1, $c0, $07
    SOUND_EXTENDED_NOTE $04, $f1, $e0, $07
    SOUND_SEQUENCE_END
SoundSequenceData_7ec7::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $00, $91, $81, $07
    SOUND_EXTENDED_NOTE $01, $d1, $a1, $07
    SOUND_EXTENDED_NOTE $01, $91, $c1, $07
    SOUND_EXTENDED_NOTE $04, $d1, $e1, $07
    SOUND_SEQUENCE_END
SoundSequenceData_7eda::
    SOUND_DUTY_LENGTH $01
    SOUND_SWEEP $26
    SOUND_EXTENDED_NOTE $08, $f1, $40, $07
    SOUND_SWEEP $36
    SOUND_EXTENDED_NOTE $04, $e1, $c0, $07
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7eeb::
    SOUND_DUTY_LENGTH $01
    SOUND_SWEEP $15
    SOUND_EXTENDED_NOTE $04, $a1, $40, $07
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7ef6::
    SOUND_DUTY_LENGTH $03
    SOUND_SWEEP $17
    SOUND_EXTENDED_NOTE $04, $f1, $c0, $06
    SOUND_SWEEP $16
    SOUND_EXTENDED_NOTE $0f, $f1, $c0, $07
    SOUND_SWEEP $1d
    SOUND_EXTENDED_NOTE $04, $f1, $00, $04
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7f0d::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $04, $d1, $80, $06
    SOUND_EXTENDED_NOTE $0f, $a1, $c0, $07
    SOUND_EXTENDED_NOTE $04, $c1, $80, $03
SoundSequenceData_7f1b::
    SOUND_SEQUENCE_END
SoundSequenceData_7f1c::
    SOUND_CHANNEL7_EXTENDED_NOTE $01, $d1, $38
    SOUND_CHANNEL7_EXTENDED_NOTE $0e, $d1, $28
    SOUND_CHANNEL7_EXTENDED_NOTE $01, $d1, $39
    SOUND_CHANNEL7_EXTENDED_NOTE $04, $d1, $49
    SOUND_SEQUENCE_END
SoundSequenceData_7f29::
    SOUND_DUTY_LENGTH $02
    SOUND_SWEEP $36
    SOUND_EXTENDED_NOTE $08, $f1, $00, $07
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7f34::
    SOUND_DUTY_LENGTH $02
    SOUND_SWEEP $14
    SOUND_EXTENDED_NOTE $08, $71, $80, $06
    SOUND_EXTENDED_NOTE $08, $41, $00, $07
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7f43::
    SOUND_DUTY_LENGTH $02
    SOUND_SWEEP $14
    SOUND_EXTENDED_NOTE $08, $d1, $80, $06
    SOUND_EXTENDED_NOTE $08, $a1, $00, $07
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7f52::
    SOUND_DUTY_LENGTH $02
    SOUND_SWEEP $36
    SOUND_EXTENDED_NOTE $04, $f4, $80, $07
    SOUND_EXTENDED_NOTE $03, $c1, $c0, $07
    SOUND_EXTENDED_NOTE $04, $d1, $a0, $07
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7f65::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $02, $c4, $30, $02
    SOUND_EXTENDED_NOTE $02, $c4, $40, $02
    SOUND_EXTENDED_NOTE $03, $c1, $60, $02
    SOUND_EXTENDED_NOTE $0f, $00, $00, $00
    SOUND_GATE_FLAG
    SOUND_LENGTH_ENVELOPE $0c, $f1
    SOUND_OCTAVE $05
    SOUND_PITCH_SLIDE $00, $60, $f0
    SOUND_SEQUENCE_END
SoundSequenceData_7f80::
    SOUND_DUTY_LENGTH $03
    SOUND_EXTENDED_NOTE $02, $83, $31, $03
    SOUND_EXTENDED_NOTE $02, $83, $41, $03
    SOUND_EXTENDED_NOTE $03, $81, $61, $03
    SOUND_EXTENDED_NOTE $0f, $00, $00, $00
    SOUND_DUTY_LENGTH $02
    SOUND_GATE_FLAG
    SOUND_LENGTH_ENVELOPE $0c, $d1
    SOUND_OCTAVE $05
    SOUND_PITCH_SLIDE $00, $60, $f0
    SOUND_SEQUENCE_END
SoundSequenceData_7f9d::
    SOUND_DUTY_LENGTH $03
    SOUND_SWEEP $15
    SOUND_EXTENDED_NOTE $07, $f4, $c0, $02
    SOUND_SWEEP $13
    SOUND_EXTENDED_NOTE $0a, $f2, $c0, $03
    SOUND_SWEEP $1b
    SOUND_EXTENDED_NOTE $0c, $f2, $00, $03
    SOUND_SWEEP $08
    SOUND_SEQUENCE_END
SoundSequenceData_7fb4::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $04, $d1, $80, $02
    SOUND_EXTENDED_NOTE $0f, $a1, $c0, $03
    SOUND_EXTENDED_NOTE $04, $c1, $80, $02
SoundSequenceData_7fc2::
    SOUND_SEQUENCE_END
SoundSequenceData_7fc3::
    SOUND_CHANNEL7_EXTENDED_NOTE $04, $b2, $48
    SOUND_CHANNEL7_EXTENDED_NOTE $0e, $c1, $38
    SOUND_CHANNEL7_EXTENDED_NOTE $01, $81, $49
    SOUND_CHANNEL7_EXTENDED_NOTE $08, $82, $59
    SOUND_SEQUENCE_END
SoundSequenceData_7fd0::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $03, $d1, $c0, $07
    SOUND_EXTENDED_NOTE $03, $d1, $80, $07
    SOUND_EXTENDED_NOTE $03, $d1, $c0, $07
    SOUND_EXTENDED_NOTE $03, $d1, $80, $07
    SOUND_SEQUENCE_END
SoundSequenceData_7fe3::
    SOUND_DUTY_LENGTH $02
    SOUND_EXTENDED_NOTE $03, $a1, $c1, $07
    SOUND_EXTENDED_NOTE $03, $a1, $81, $07
    SOUND_EXTENDED_NOTE $03, $a1, $c1, $07
    SOUND_EXTENDED_NOTE $03, $a1, $81, $07
    SOUND_SEQUENCE_END

Bank1TailPaddingData::
    REPT BANK1_TAIL_PADDING_WORDS
        dw BANK1_TAIL_PADDING_WORD
    ENDR
