; Disassembly of "yoshi.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $001", ROMX[$4000], BANK[$1]

UpdateSprites::
    ld a, [LCD_REDRAW]
    dec a
    jr z, jr_001_400f

    cp $ff
    ret nz

    ld [LCD_REDRAW], a
    jp HideAllSprites


jr_001_400f:
    ldh [SHADOW_OAM_WRITE_OFFSET], a

jr_001_4011:
    ldh [SPRITE_SCAN_SLOT_OFFSET], a
    ld d, SPRITE_OBJECTS_HI
    ld e, a
    ld a, [de]
    and a
    jr z, jr_001_407b

    and SPRITE_OBJECT_ATTR_MASK
    ldh [SPRITE_OBJECT_ATTR_TMP], a
    ld a, [de]
    dec a
    ld hl, SpriteUpdatePointerTable
    sla a
    add l
    ld l, a
    jr nc, jr_001_402a

    inc h

jr_001_402a:
    ld c, [hl]
    inc hl
    ld b, [hl]
    inc e
    inc e
    ld a, [de]
    cp $ff
    jr nz, jr_001_4036

    jr jr_001_407b

jr_001_4036:
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

jr_001_4052:
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
    jr z, jr_001_406e

    ldh a, [SPRITE_OBJECT_ATTR_TMP]
    or [hl]

jr_001_406e:
    inc hl
    ld [de], a
    inc e
    bit SPRITE_ATTR_END_BIT, a
    jr z, jr_001_4052

    ld a, e
    ldh [SHADOW_OAM_WRITE_OFFSET], a
    cp SHADOW_OAM_SIZE
    ret z

jr_001_407b:
    ldh a, [SPRITE_SCAN_SLOT_OFFSET]
    add SPRITE_OBJECT_SLOT_SIZE
    cp $00
    jr nz, jr_001_4011

    ldh a, [SHADOW_OAM_WRITE_OFFSET]
    ld l, a
    ld h, SHADOW_OAM_HI
    ld de, OAM_ENTRY_SIZE
    ld a, SHADOW_OAM_HIDE_LIMIT

jr_001_408d:
    cp l
    ret z

    ld [hl], OAM_HIDDEN_Y
    add hl, de
    jr jr_001_408d

InitSpriteBuffer::
    ld hl, SPRITE_OBJECTS

jr_001_4097:
    xor a
    ld [hl], a
    ld a, l
    add SPRITE_OBJECT_SLOT_SIZE
    ld l, a
    jr nc, jr_001_4097

    ret


SpriteUpdatePointerTable::
    dw SpriteUpdateData_40fa ; 00
    dw SpriteUpdateData_411a ; 01
    dw SpriteUpdateData_417e ; 02
    dw SpriteUpdateData_41d2 ; 03
    dw SpriteUpdateData_40ae ; 04
    dw SpriteUpdateData_41e2 ; 05
    dw SpriteUpdateData_41ea ; 06

SpriteUpdateData_40ae::
    dw SpriteUpdateData_4233 ; 07
    dw SpriteUpdateData_42bf ; 08
    dw SpriteUpdateData_4237 ; 09
    dw SpriteUpdateData_42bf ; 10
    dw SpriteUpdateData_423b ; 11
    dw SpriteUpdateData_42bf ; 12
    dw SpriteUpdateData_4233 ; 13
    dw SpriteUpdateData_42bf ; 14
    dw SpriteUpdateData_4237 ; 15
    dw SpriteUpdateData_42bf ; 16
    dw SpriteUpdateData_423b ; 17
    dw SpriteUpdateData_42bf ; 18
    dw SpriteUpdateData_4233 ; 19
    dw SpriteUpdateData_42bf ; 20
    dw SpriteUpdateData_4237 ; 21
    dw SpriteUpdateData_42bf ; 22
    dw SpriteUpdateData_423b ; 23
    dw SpriteUpdateData_42bf ; 24
    dw SpriteUpdateData_4233 ; 25
    dw SpriteUpdateData_42bf ; 26
    dw SpriteUpdateData_4237 ; 27
    dw SpriteUpdateData_42bf ; 28
    dw SpriteUpdateData_423b ; 29
    dw SpriteUpdateData_42bf ; 30
    dw SpriteUpdateData_4233 ; 31
    dw SpriteUpdateData_42bf ; 32
    dw SpriteUpdateData_4233 ; 33
    dw SpriteUpdateData_42bf ; 34
    dw SpriteUpdateData_4233 ; 35
    dw SpriteUpdateData_42bf ; 36
    dw SpriteUpdateData_4233 ; 37
    dw SpriteUpdateData_42bf ; 38
    dw SpriteUpdateData_4235 ; 39
    dw SpriteUpdateData_42bf ; 40
    dw SpriteUpdateData_4239 ; 41
    dw SpriteUpdateData_42bf ; 42
    dw SpriteUpdateData_423d ; 43
    dw SpriteUpdateData_42bf ; 44

SpriteUpdateData_40fa::
    db $0e, $42, $cb, $42, $14, $42, $dd, $42, $18, $42, $dd, $42, $1c, $42, $dd, $42
    db $20, $42, $cb, $42, $1c, $42, $e9, $42, $18, $42, $e9, $42, $14, $42, $e9, $42

SpriteUpdateData_411a::
    db $a7, $42, $bf, $42, $a7, $42, $c5, $42, $a9, $42, $c5, $42, $ab, $42, $c5, $42
    db $ad, $42, $c5, $42, $af, $42, $c5, $42, $b1, $42, $c5, $42, $b1, $42, $c5, $42
    db $b3, $42, $c5, $42, $a7, $42, $bf, $42, $a7, $42, $bf, $42, $a7, $42, $bf, $42
    db $a7, $42, $bf, $42, $a7, $42, $bf, $42, $a7, $42, $bf, $42, $a7, $42, $bf, $42
    db $a7, $42, $bf, $42, $b5, $42, $c5, $42, $b7, $42, $c5, $42, $b9, $42, $c5, $42
    db $bb, $42, $c5, $42, $bd, $42, $c5, $42, $bf, $42, $c5, $42, $bf, $42, $c5, $42
    db $bf, $42, $c5, $42

SpriteUpdateData_417e::
    db $3f, $42, $6b, $42, $45, $42, $6b, $42, $4b, $42, $71, $42, $55, $42, $7d, $42
    db $63, $42, $8f, $42, $3f, $42, $6b, $42, $3f, $42, $6b, $42, $3f, $42, $6b, $42
    db $3f, $42, $6b, $42, $3f, $42, $6b, $42, $3f, $42, $6b, $42, $3f, $42, $6b, $42
    db $3f, $42, $6b, $42, $3f, $42, $6b, $42, $3f, $42, $6b, $42, $3f, $42, $6b, $42
    db $41, $42, $6b, $42, $43, $42, $6b, $42, $47, $42, $71, $42, $4f, $42, $7d, $42
    db $5b, $42, $8f, $42

SpriteUpdateData_41d2::
    db $26, $42, $27, $42, $26, $42, $2a, $42, $26, $42, $2d, $42, $26, $42, $30, $42

SpriteUpdateData_41e2::
    db $f6, $41, $fc, $41, $f6, $41, $05, $42

SpriteUpdateData_41ea::
    db $ee, $41, $f0, $41, $e0, $e0, $00, $08, $00, $00, $10, $21, $da, $dc, $de, $da
    db $dc, $de, $10, $04, $00, $10, $0c, $00, $10, $14, $00, $00, $04, $00, $00, $0c
    db $00, $00, $14, $01, $1c, $1e, $20, $20, $1e, $1c, $24, $26, $28, $2a, $2c, $2e
    db $30, $32, $34, $36, $38, $3a, $3c, $3e, $40, $40, $3e, $3c, $80, $f0, $f8, $01
    db $f0, $00, $21, $f0, $f8, $41, $f0, $00, $61

SpriteUpdateData_4233::
    db $60, $62

SpriteUpdateData_4235::
    db $64, $66

SpriteUpdateData_4237::
    db $68, $6a

SpriteUpdateData_4239::
    db $6c, $6e

SpriteUpdateData_423b::
    db $70, $72

SpriteUpdateData_423d::
    db $74, $76, $82, $84, $86, $88, $8a, $8c, $8e, $90, $92, $94, $96, $98, $9a, $9c
    db $9e, $a0, $a2, $a4, $a6, $a8, $aa, $ac, $ae, $b0, $b2, $b4, $b6, $b8, $ba, $bc
    db $be, $c0, $c2, $c4, $c6, $c8, $ca, $cc, $ce, $d0, $d2, $d4, $d6, $d8, $f0, $f8
    db $00, $f0, $00, $01, $e8, $f8, $00, $f8, $f8, $00, $e8, $00, $00, $f8, $00, $01
    db $e8, $f4, $00, $f8, $f4, $00, $e8, $fc, $00, $f8, $fc, $00, $e8, $04, $00, $f8
    db $04, $01, $e0, $f0, $00, $f0, $f0, $00, $e0, $f8, $00, $f0, $f8, $00, $e0, $00
    db $00, $f0, $00, $00, $e0, $08, $00, $f0, $08, $01, $00, $02, $04, $06, $08, $0a
    db $0c, $0e, $10, $12, $18, $1a, $14, $16, $4c, $4e, $50, $52, $54, $56, $58, $5a
    db $5c, $5e

SpriteUpdateData_42bf::
    db $00, $08, $00, $00, $10, $01, $00, $08, $10, $00, $10, $11, $00, $08, $00, $00
    db $10, $00, $00, $18, $00, $00, $20, $20, $00, $28, $20, $00, $30, $21, $00, $10
    db $00, $00, $18, $00, $00, $20, $00, $00, $28, $01, $00, $28, $22, $00, $20, $22
    db $00, $18, $22, $00, $10, $23

UpdateAnimFrame::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

jr_001_42fa:
    ld a, [GAME_TYPE]
    and a

jr_001_42fe:
    jr nz, jr_001_4305

    ld hl, $0310
    jr jr_001_4308

jr_001_4305:
    ld hl, $0210

jr_001_4308:
    call CalcOAMAddress
    ld [hl], $12
    inc hl

jr_001_430e:
    ld [hl], $13

LoadAnimData::
    inc hl

jr_001_4311:
    ld [hl], $02
    inc hl

jr_001_4314:
    ld [hl], $03
    ld a, [$c7ce]
    and a
    ret nz

    ld a, $02
    ld [$c7ce], a
    ret


    call CalcOAMAddress

jr_001_4324:
    ld a, [de]
    and $0f
    inc de
    add $40
    ld [hl+], a
    dec b
    jr nz, jr_001_4324

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
    adc $00
    daa
    cp $10
    jr c, StoreScoreDigitsFromBCD

    ld a, $99
    ld [SCORE_BCD_LOW], a
    ld [SCORE_BCD_MID], a
    ld a, $09

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
    ld a, [$c672]
    ld [$c629], a
    swap a
    ld [$c628], a
    ret


InitGameScreen::
    ld a, [$c620]
    ld c, a
    xor a
    ld hl, $c61d
    ld b, $09

jr_001_4387:
    ld [hl+], a
    dec b
    jr nz, jr_001_4387

    ld a, c
    ld [$c620], a
    ret


    ld b, a
    call CalcOAMAddress

DrawBCDNumber::
    xor a
    add b
    daa
    ld b, a
    swap a
    and $0f
    jr z, jr_001_43a2

    add $40
    jr jr_001_43a4

jr_001_43a2:
    ld a, $4a

jr_001_43a4:
    ld [hl+], a
    ld a, b
    and $0f
    add $40
    ld [hl], a
    ret


GameMainUpdate::
    call CheckMatch
    call DrawBox
    call InitGameState2
    call UpdateAnimFrame
    call CheckVerticalMatch
    call ProcessMatch
    call SetupGameBG
    call DrawTextBox
    call UpdateFieldTimers
    call AnimateDropping
    call LoadGameBGTiles
    call FieldUpdate18
    call CheckPause2P
    ld a, [GAME_TYPE]
    and a
    jr z, jr_001_43dc

    call FieldUpdate12

jr_001_43dc:
    call TimerTick
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_001_43f1

Check2PGameState::
    ld a, [$c705]
    and a
    jr z, jr_001_43f1

    ld a, [$c706]
    jp ProcessNewHighScore


jr_001_43f1:
    ret


SetupGameBG::
    ld hl, $c6ab
    ld a, [hl]
    and a
    ret nz

    ld b, $10
    ld h, $01
    ld l, $00
    call CalcOAMAddress

jr_001_4401:
    ld [hl], $4d
    inc hl
    dec b
    jr nz, jr_001_4401

    ret


LoadGameBGTiles::
    ld a, [$c6e0]
    sla a
    sla a
    sla a
    sla a
    ld hl, FieldColumnTilePatternTable
    call GetArrayElement
    ld d, h
    ld e, l
    ld hl, $1000
    push de
    call CalcOAMAddress
    pop de
    ld b, $10

jr_001_4425:
    ld a, [de]
    ld [hl+], a
    inc de
    dec b
    jr nz, jr_001_4425

    ret


FieldColumnTilePatternTable::
    db $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a
    db $4a, $fb, $fc, $4a, $4a, $fb, $fc, $4a
    db $4a, $fb, $fc, $4a, $4a, $4a, $4a, $4a
    db $4a, $4a, $4a, $4a, $4a, $fb, $fc, $4a
    db $4a, $fb, $fc, $4a, $4a, $fb, $fc, $4a
    db $4a, $4a, $4a, $4a, $4a, $4a, $4a, $4a

StartNextRound::
    xor a
    ld [$c705], a
    ld [$c706], a
    ld [$c6d3], a
    ld [$c6d4], a
    ld [$c6d5], a
    ld [$c6d2], a
    ld [$c703], a
    ld [$c704], a
    ld [$c6fa], a
    ld [$c6fc], a
    ld [$c6e6], a
    ld [$c6f4], a
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_001_448c

    call ApplyGameSettings
    jr jr_001_449e

jr_001_448c:
    ld hl, ACTIVE_LEVEL
    ld a, [hl]
    cp $04
    jr z, jr_001_4495

    inc [hl]

jr_001_4495:
    ld a, [BGM_INDEX]
    call PlaySound
    call AnimFrameData

jr_001_449e:
    call UpdateNextDisplay
    call HandleDrop
    call ProcessColumn
    call DrawAllColumns
    call SetupGameBG
    call UpdateAnimFrame
    call InitGameBoard
    call InitBlinkState
    call ClearAnimState
    call ClearTextArea
    call UpdateSpriteFrame
    call InitEggSystem
    call CalcDifficulty
    call FieldUpdate15
    xor a
    ld [$c6e4], a
    ld [$c6e5], a
    ret


ProcessColumn::
    ld a, $01
    ld [$c6e0], a
    ld hl, $c200
    ld [hl], $01
    inc hl
    inc hl
    ld [hl], $00
    inc hl
    inc hl
    ld [hl], $80
    inc hl
    inc hl
    ld [hl], $20
    ret


    call SetupGameBG

UpdateColumn::
    ld e, a
    call CalcOAMAddress
    ld d, b

jr_001_44ef:
    ld a, e

jr_001_44f0:
    ld [hl+], a
    dec b
    jr nz, jr_001_44f0

    ld b, d
    ld a, $14
    sub d
    add l
    ld l, a
    jr nc, jr_001_44fd

    inc h

jr_001_44fd:
    dec c
    jr nz, jr_001_44ef

    ret


DrawColumnData::
    call CalcOAMAddress
    ld a, c

jr_001_4505:
    ld [hl+], a
    inc a
    dec b
    jr nz, jr_001_4505

    ret


InitPlayfield::
    xor a
    ld [$c703], a
    ld [$c704], a
    ld [$c6f4], a
    ld [$c6d3], a
    ld [$c6d4], a
    ld [$c6d5], a
    ld [$c6d2], a
    call UpdateNextDisplay
    call HandleDrop
    call ProcessColumn
    call DrawAllColumns
    call SetupGameBG
    call InitGameScreen
    call UpdateAnimFrame
    call InitGameBoard
    call InitBlinkState
    call ClearAnimState
    call ClearTextArea
    call UpdateSpriteFrame
    call UpdateEggState
    call CalcDifficulty
    call RefreshField
    call FieldUpdate16
    call FieldUpdate15
    call InitEggSystem
    xor a
    ld [$c6e4], a
    ld [$c6e5], a
    ret


SpriteAnimTable::
    call CalcOAMAddress
    ld a, [SPRITE_ANIM_FRAME]
    add $40
    ld [hl], a
    dec hl
    ld a, [SPRITE_ANIM_STATE]
    add $40
    ld [hl], a
    ret


AdvanceSpriteAnimFrame::
    ld a, [GAME_TYPE]
    and a
    ret nz

    ld hl, $c6e2
    inc [hl]
    ld a, [SPRITE_ANIM_STATE]
    cp $09
    jr nz, jr_001_4588

    ld a, [SPRITE_ANIM_FRAME]
    cp $09
    jr nz, jr_001_4588

    ret


jr_001_4588:
    ld a, [SPRITE_ANIM_FRAME]
    inc a
    cp $0a
    jr c, jr_001_4595

    ld hl, SPRITE_ANIM_STATE
    inc [hl]
    xor a

jr_001_4595:
    ld [SPRITE_ANIM_FRAME], a
    ret


AnimFrameData::
    ld hl, $c6e2
    inc [hl]
    ld a, [SPRITE_ANIM_STATE]
    cp $09
    jr nz, jr_001_45ac

    ld a, [SPRITE_ANIM_FRAME]
    cp $09
    jr nz, jr_001_45ac

    ret


jr_001_45ac:
    ld a, [SPRITE_ANIM_FRAME]
    inc a
    cp $0a
    jr c, jr_001_45b9

    ld hl, SPRITE_ANIM_STATE
    inc [hl]
    xor a

jr_001_45b9:
    ld [SPRITE_ANIM_FRAME], a
    ret


UpdateSpriteFrame::
    xor a
    ld [$c6d1], a
    ret


GetFramePointer::
    xor a
    jr AnimateSprite

    ret


    call CalcOAMAddress
    ld [hl], $f0
    inc hl
    ld [hl], $f1
    ld de, $0013
    add hl, de
    ld [hl], $f2
    inc hl
    ld [hl], $f3
    inc hl
    ld [hl], $f4
    add hl, de
    ld [hl], $f5
    inc hl
    ld [hl], $f6
    inc hl
    ld [hl], $f7
    ld de, $0012
    add hl, de
    ld [hl], $f8
    inc hl
    ld [hl], $f9
    inc hl
    ld [hl], $fa
    ret


AnimateSprite::
    push af
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_001_4629

    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_4602

    ld hl, $0d10
    jr jr_001_4605

jr_001_4602:
    ld hl, $0e10

jr_001_4605:
    pop af
    and a
    jr z, jr_001_460f

    cp $01
    jr z, jr_001_4614

    jr jr_001_4619

jr_001_460f:
    ld de, $462b
    jr jr_001_461c

jr_001_4614:
    ld de, $4639
    jr jr_001_461c

jr_001_4619:
    ld de, $464b

jr_001_461c:
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    call DrawStringToGrid
    ret


jr_001_4629:
    pop af
    ret


    ldh a, [$fff1]
    rst $38
    ldh a, [c]
    di
    rst $38
    push af
    or $f7
    rst $38
    ld hl, sp-$07
    ld a, [$e0ff]
    pop hl
    rst $38
    ldh [c], a
    db $e3
    db $e4
    ld c, h
    rst $38
    push hl
    and $e7
    ld c, h
    rst $38
    add sp, -$17
    ld [$ff4c], a
    ldh a, [$fff1]
    rst $38
    ldh a, [c]
    di
    db $f4
    ld c, h
    rst $38
    db $eb
    db $ec
    db $ed
    ld c, h
    rst $38
    xor $ef
    db $fd
    ld c, h
    rst $38

ProcessEgg::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld a, [GAME_TYPE]
    and a
    jr z, jr_001_466d

    ld hl, $0e13
    jr jr_001_4670

jr_001_466d:
    ld hl, $0c13

jr_001_4670:
    call CalcOAMAddress
    ld a, [$c6d3]
    add $40
    ld [hl], a
    dec hl
    ld a, [$c6d4]
    add $40
    ld [hl], a
    ret


AdvanceEggAnimation::
    ld hl, $c6d3
    inc [hl]
    ld a, [hl]
    cp $0a
    jr c, jr_001_46ab

    xor a
    ld [hl], a
    call FieldUpdate17
    ld hl, $c6d4
    inc [hl]
    ld a, [hl]
    cp $0a
    jr c, jr_001_46ab

    xor a
    ld [hl], a
    call ResetFieldState
    ld hl, $c6d5
    inc [hl]
    ld a, [hl]
    cp $0a
    jr c, jr_001_46ab

    ld a, $09
    ld [hl-], a
    ld [hl-], a
    ld [hl], a

jr_001_46ab:
    call ProcessEgg
    ret


UpdateEggState::
    xor a
    ld [$c6d3], a
    ld [$c6d4], a
    ld [$c6d5], a
    ld [$c6d2], a
    ret


InitEggSystem::
    xor a
    ld [$c6fe], a
    ld [$c6fa], a
    ld [LINK_SEND], a
    ld [LINK_RECV], a
    ld [$c6fb], a
    ld [$c6fc], a
    ld [$c6fd], a
    ld [$c6e6], a
    ret


DrawTitleLabels::
    ld hl, $0f06
    ld de, $46ed
    call DrawStringToGrid
    ld hl, $1006
    ld de, $46f6
    call DrawStringToGrid
    call GenerateNext
    ret


    ld h, d
    ldh [$ff64], a
    ld h, l
    ld h, [hl]
    ld h, a
    ld l, b
    ld l, c
    rst $38
    ld d, d
    ldh [$ff64], a
    ld h, l
    ld h, [hl]
    ld h, a
    ld l, b
    ld l, c
    rst $38

ProcessTitleInput::
    call DisplayNextPiece
    ldh a, [JOYPAD_PRESSED]
    and a
    ret z

    bit 7, a
    jr nz, jr_001_4713

    bit 6, a
    jr nz, jr_001_4721

    bit 2, a
    jr nz, jr_001_472f

    ret


jr_001_4713:
    ld a, [TWO_PLAYER_FLAG]
    inc a
    cp $02
    ret nc

    ld [TWO_PLAYER_FLAG], a
    call GenerateNext
    ret


jr_001_4721:
    ld a, [TWO_PLAYER_FLAG]
    dec a
    cp $ff
    ret z

    ld [TWO_PLAYER_FLAG], a
    call GenerateNext
    ret


jr_001_472f:
    ld a, [TWO_PLAYER_FLAG]
    xor $01
    ld [TWO_PLAYER_FLAG], a
    call GenerateNext
    ret


GenerateNext::
    ld hl, $0f05
    call CalcOAMAddress
    ld [hl], $e0
    ld hl, $1005
    call CalcOAMAddress
    ld [hl], $e0
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_001_475a

    ld hl, $0f05
    call CalcOAMAddress
    ld [hl], $60
    ret


jr_001_475a:
    ld hl, $1005
    call CalcOAMAddress
    ld [hl], $60
    ret


ProcessOptionInput::
    ld a, $02
    ldh [rSB], a
    ld a, $80
    ldh [rSC], a
    ldh a, [JOYPAD_PRESSED]
    bit 3, a
    jr z, jr_001_477f

    xor a
    ld [LINK_RECV], a
    ldh [SERIAL_DONE], a
    ld a, $01
    ldh [rSB], a
    ld a, $81
    ldh [rSC], a

jr_001_477f:
    ld a, [LINK_RECV]
    and a
    jr nz, jr_001_4791

    ldh a, [JOYPAD_PRESSED]
    bit 3, a
    ret z

    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_001_47ba

    ret


jr_001_4791:
    cp $01
    jr nz, jr_001_47a1

    ld a, $02
    ld [LINK_ROLE], a
    ld a, $01
    ld [TWO_PLAYER_FLAG], a
    jr jr_001_47a9

jr_001_47a1:
    cp $02
    ret nz

    ld a, $01
    ld [LINK_ROLE], a

jr_001_47a9:
    xor a
    ld [LINK_RECV], a
    ld [LINK_SEND], a
    call WaitVBlank
    xor a
    ld [LINK_RECV], a
    ld [LINK_SEND], a

jr_001_47ba:
    xor a
    ldh [rSB], a
    ld a, GAME_STATE_PREPLAY_INIT
    ld [GAME_STATE], a
    ret


DisplayNextPiece::
    ld hl, $c6bc
    dec [hl]
    ret nz

    ld a, [$c6be]
    and a
    jr z, jr_001_47db

    ld a, $0a
    ld [$c6bc], a
    xor a
    ld [$c6be], a
    call DrawNextBottom
    ret


jr_001_47db:
    ld a, $d0
    ld [$c6bc], a
    ld a, $01
    ld [$c6be], a
    call DrawNextTop
    ret


DrawNextTop::
    ld hl, $0505
    ld b, $02
    ld c, $d2
    call DrawColumnData
    ld hl, $0605
    ld b, $02
    ld c, $dc
    call DrawColumnData
    ret


DrawNextBottom::
    ld hl, $0505
    ld b, $02
    ld c, $48
    call DrawColumnData
    ld hl, $0605
    ld b, $02
    ld c, $4a
    call DrawColumnData
    ret


UpdateNextDisplay::
    call FillOAMGameTile
    call FieldUpdate1
    ld hl, $0010
    ld bc, $0412
    ld a, $4c
    call UpdateColumn
    call FieldUpdate2
    call FieldUpdate3
    call FieldUpdate4
    call FieldUpdate5
    call FieldUpdate6
    call FieldUpdate7
    call FieldUpdate11
    call FieldUpdate13
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr nz, jr_001_4850

    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_484c

    call FieldUpdate8
    ret


jr_001_484c:
    call FieldUpdate9
    ret


jr_001_4850:
    call FieldUpdate10
    ret


FieldUpdate1::
    ld hl, $c200
    ld b, $ff
    xor a

jr_001_485a:
    ld [hl+], a
    dec b
    jr nz, jr_001_485a

    ret


FieldUpdate2::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_4870

    ld hl, $0210
    jp DrawColumnBlock


jr_001_4870:
    ld hl, $0110

DrawColumnBlock::
    ld bc, $0430
    call DrawColumnData
    ret


FieldUpdate3::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_001_4885

    ld hl, $0210
    jr jr_001_4893

jr_001_4885:
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_4890

    ld hl, $0710
    jr jr_001_4893

jr_001_4890:
    ld hl, $0910

jr_001_4893:
    ld bc, $0438
    call DrawColumnData
    ret


FieldUpdate4::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_001_48a5

    ld hl, $0312
    jr jr_001_48b3

jr_001_48a5:
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_48b0

    ld hl, $0812
    jr jr_001_48b3

jr_001_48b0:
    ld hl, $0a12

jr_001_48b3:
    call SpriteAnimTable
    ret


FieldUpdate5::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_001_48c2

    ld hl, $0411
    jr jr_001_48d0

jr_001_48c2:
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_48cd

    ld hl, $0911
    jr jr_001_48d0

jr_001_48cd:
    ld hl, $0b11

jr_001_48d0:
    ld b, $02
    ld c, $3c
    ld a, [ACTIVE_SPEED]
    sla a
    add c
    ld c, a
    call DrawColumnData
    ret


FieldUpdate6::
    ld a, [TWO_PLAYER_FLAG]
    and a
    jr z, jr_001_48e6

    ret


jr_001_48e6:
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_48f1

    ld hl, $0d10
    jr jr_001_48f4

jr_001_48f1:
    ld hl, $0e10

jr_001_48f4:
    call GetFramePointer
    call ProcessEgg
    ret


FieldUpdate7::
    ld hl, $1001
    call CalcOAMAddress
    ld [hl], $fb
    inc l
    ld [hl], $fc
    inc l
    inc l
    inc l
    ld [hl], $fb
    inc l
    ld [hl], $fc
    inc l
    inc l
    inc l
    ld [hl], $fb
    inc l
    ld [hl], $fc
    inc l
    inc l
    inc l
    ld [hl], $fb
    inc l
    ld [hl], $fc
    ret


FieldUpdate8::
    ld hl, $0510
    call CalcOAMAddress
    ld a, $4b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, $0b10
    call CalcOAMAddress
    ld a, $4b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ret


FieldUpdate9::
    ld hl, $0410
    call CalcOAMAddress
    ld a, $4b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, $0810
    call CalcOAMAddress
    ld a, $4b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, $0d10
    call CalcOAMAddress
    ld a, $4b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ret


FieldUpdate10::
    ld hl, $0610
    call CalcOAMAddress
    ld a, $4b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld hl, $0c10
    call CalcOAMAddress
    ld a, $4b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ret


FieldUpdate11::
    ld a, [GAME_TYPE]
    and a
    ret z

    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld hl, $0510
    ld bc, $047c
    call DrawColumnData
    call FieldUpdate12
    ret


FieldUpdate12::
    ld hl, $0610
    call FieldUpdate14
    ret


    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    ld hl, $0110
    call CalcOAMAddress
    ld a, [GAME_TYPE]
    and a
    jr nz, jr_001_49a9

    ld a, $34
    jr jr_001_49ab

jr_001_49a9:
    ld a, $4e

jr_001_49ab:
    ld [hl], a
    ld hl, $0111
    ld bc, $0335
    call DrawColumnData
    ret


FieldUpdate13::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret z

    ld a, [LINK_ROLE]
    cp $02
    jr z, jr_001_49d5

    ld hl, $0810
    ld bc, $0470
    call DrawColumnData
    ld hl, $0e10
    ld bc, $0474
    call DrawColumnData
    ret


jr_001_49d5:
    ld hl, $0e10
    ld bc, $0470
    call DrawColumnData
    ld hl, $0810
    ld bc, $0474
    call DrawColumnData
    ret


FieldUpdate14::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

    call CalcOAMAddress
    ld de, $c6d6
    ld a, [de]
    add $40
    inc de
    ld a, [de]
    add $40
    ld [hl+], a
    inc de
    ld a, $4f
    ld [hl+], a
    ld a, [de]
    add $40
    ld [hl+], a
    inc de
    ld a, [de]
    add $40
    ld [hl], a
    ret


FieldUpdate15::
    ld hl, $c6d6
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [$c6e4], a
    ret


FieldUpdate16::
    ld hl, $c6db
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [$c6e5], a
    ret


FieldUpdate17::
    ld a, $01
    ld [$c6e9], a
    ld a, $03
    ld [$c6ea], a
    ld a, $02
    ld [$c6e8], a
    ret


FieldUpdate18::
    ld a, [$c6f3]
    and a
    ret nz

    ld hl, $c6e9
    ld a, [hl]
    and a
    ret z

    dec [hl]
    ret nz

    ld hl, $c6ea
    dec [hl]
    jr z, jr_001_4a65

    ld a, $28
    ld [$c6e9], a
    ld a, [$c6e8]
    cp $01
    jr z, jr_001_4a57

    ld a, $01
    call AnimateSprite
    jr jr_001_4a5c

jr_001_4a57:
    ld a, $02
    call AnimateSprite

jr_001_4a5c:
    ld a, [$c6e8]
    xor $03
    ld [$c6e8], a
    ret


jr_001_4a65:
    ret


ToggleFieldAnim::
    ld a, [$c6f4]
    xor $01
    ld [$c6f4], a
    ld a, [$c6f3]
    and a
    ret z

    ld a, [$c6f4]
    inc a
    call AnimateSprite
    ret


ResetFieldState::
    ld a, $01
    ld [$c6f3], a
    ret


ProcessFieldLogic::
    ldh a, [GAME_ACTIVE]
    and a
    ret z

    ld hl, sp+$00
    ld a, h
    ldh [$ffa7], a
    ld a, l
    ldh [$ffa8], a
    ldh a, [$ffa6]
    and a
    jr z, jr_001_4a9f

    dec a
    jr z, jr_001_4aa9

    ld hl, $c590
    ld sp, hl
    ld hl, $9d80
    xor a
    jr jr_001_4ab2

jr_001_4a9f:
    ld hl, $c4a0
    ld sp, hl
    ld hl, $9c00
    inc a
    jr jr_001_4ab2

jr_001_4aa9:
    ld hl, $c518
    ld sp, hl
    ld hl, $9cc0
    ld a, $02

jr_001_4ab2:
    ldh [$ffa6], a
    ld b, $06

jr_001_4ab6:
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
    ld a, $0d
    add l
    ld l, a
    jr nc, jr_001_4aee

    inc h

jr_001_4aee:
    dec b
    jr nz, jr_001_4ab6

    ldh a, [$ffa7]
    ld h, a
    ldh a, [$ffa8]
    ld l, a
    ld sp, hl
    ret


VRAMCopyDMA::
    ldh a, [VRAM_COPY_BLOCKS]
    and a
    ret z

    ld hl, sp+$00
    ld a, h
    ldh [$ffa7], a
    ld a, l
    ldh [$ffa8], a
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

jr_001_4b18:
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
    jr nz, jr_001_4b18

    ld a, l
    ldh [VRAM_DST_LO], a
    ld a, h
    ldh [VRAM_DST_HI], a
    ld hl, sp+$00
    ld a, l
    ldh [VRAM_SRC_LO], a
    ld a, h
    ldh [VRAM_SRC_HI], a
    ldh a, [$ffa7]
    ld h, a
    ldh a, [$ffa8]
    ld l, a
    ld sp, hl
    ret


VBlankHandler::
    push af
    push bc
    push de
    push hl
    call ProcessFieldLogic
    call RandomNext
    call VRAMCopyDMA
    call OAM_DMA_HRAM
    call TimerTickCore
    ld a, ROM_BANK_MAIN_CODE
    ld [MBC1_ROM_BANK_REG], a
    call UpdateSprites
    ldh a, [SCX_SHADOW]
    ldh [rSCX], a
    ldh a, [$ff9d]
    ldh [rSCY], a
    ldh a, [$ff9e]
    ldh [rWY], a
    ldh a, [VBLANK_SYNC]
    and a
    jr z, jr_001_4b88

    xor a
    ldh [VBLANK_SYNC], a

jr_001_4b88:
    ldh a, [VBLANK_BUSY]
    and a
    jr z, jr_001_4b90

    dec a
    ldh [VBLANK_BUSY], a

jr_001_4b90:
    call UpdateLinkState
    call UpdateCountdownTimer
    call ProcessLinkData
    ld a, [WAVE_UPDATE]
    and a
    jr z, jr_001_4ba2

    call LoadWavePattern

jr_001_4ba2:
    call CheckJoypadRaw
    jr nz, jr_001_4baa

    jp Jump_000_019d


jr_001_4baa:
    pop hl
    pop de
    pop bc
    pop af
    reti


CheckJoypadRaw::
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
    and $0f
    ret


WaitVBlank::
    ld a, $01
    ldh [VBLANK_SYNC], a

jr_001_4bc9:
    db $76
    ldh a, [VBLANK_SYNC]
    and a
    jr nz, jr_001_4bc9

    ret


    ldh a, [JOYPAD_PRESSED]
    and $04
    ret z

    ldh a, [JOYPAD_HELD]
    push af
    ldh a, [JOYPAD_RAW]
    push af
    ldh a, [JOYPAD_PRESSED]
    push af

jr_001_4bde:
    db $76
    call ReadJoypad
    ldh a, [JOYPAD_PRESSED]
    and $0c
    jr z, jr_001_4bde

    pop af
    and $fb
    ldh [JOYPAD_PRESSED], a
    pop af
    and $fb
    ldh [JOYPAD_RAW], a
    pop af
    and $fb
    ldh [JOYPAD_HELD], a
    ret


LoadWavePattern::
    xor a
    ldh [rNR30], a
    ld hl, $ff30

jr_001_4bfe:
    ld a, $ff
    ld [hl+], a
    ld a, l
    cp $40
    jr nz, jr_001_4bfe

    ld a, $80
    ldh [rNR30], a
    ldh a, [rNR51]
    or $44
    ldh [rNR51], a
    ld a, $c0
    ldh [rNR34], a
    ld hl, UpdateLinkState

jr_001_4c17:
    ld b, $08
    ld a, [hl]
    cp $aa
    jr z, jr_001_4c3d

    ld d, a
    jr jr_001_4c2d

jr_001_4c21:
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

jr_001_4c2d:
    push hl
    pop hl
    xor a
    sla d
    rra
    rra
    rra
    ldh [rNR32], a
    dec b
    jr nz, jr_001_4c21

    inc hl
    jr jr_001_4c17

jr_001_4c3d:
    xor a
    ld [WAVE_UPDATE], a
    ldh a, [rNR51]
    and $bb
    ldh [rNR51], a
    ret


ProcessLinkData::
    ld a, [SOUND_PAUSE_FLAG]
    and a
    ret nz

    ld a, [$c6e4]
    and a
    jr nz, jr_001_4c59

    ld hl, $c6da
    call SendLinkByte

jr_001_4c59:
    ld a, [$c6e5]
    and a
    ret nz

    ld hl, $c6df

SendLinkByte::
    inc [hl]
    ld a, [hl]
    cp $3c
    jr c, jr_001_4c87

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp $0a
    jr c, jr_001_4c87

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp $06
    jr c, jr_001_4c87

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp $0a
    jr c, jr_001_4c87

    xor a
    ld [hl-], a
    inc [hl]
    ld a, [hl]
    cp $0a
    jr nc, jr_001_4c88

jr_001_4c87:
    ret


jr_001_4c88:
    ld a, $09
    ld [hl+], a
    ld [hl+], a
    ld [hl], $05
    inc hl
    ld [hl], a
    ret


UpdateLinkState::
    ld c, $00

jr_001_4c93:
    ld b, $00
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_001_4cbf

    ld a, c
    cp $04
    jr nc, jr_001_4cbc

    ld a, [SOUND_PAUSE_FLAG]
    and a
    jr z, jr_001_4cbc

    bit 7, a
    jr nz, jr_001_4cbf

    set 7, a
    ld [SOUND_PAUSE_FLAG], a
    xor a
    ldh [rNR51], a
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a
    jr jr_001_4cbf

jr_001_4cbc:
    call SyncLinkPlayers

jr_001_4cbf:
    ld a, c
    inc c
    cp $07
    jr nz, jr_001_4c93

    ret


SyncLinkPlayers::
    ld b, $00
    ld hl, SOUND_CH_NOTE_LENGTH
    add hl, bc
    ld a, [hl]
    cp $01
    jp z, SoundSequenceStep

    dec a
    ld [hl], a
    ld a, c
    cp $04
    jr nc, jr_001_4ce2

    ld hl, SOUND_BGM_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_001_4ce2

    ret


jr_001_4ce2:
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 6, [hl]
    jr z, jr_001_4ced

    call SoundUpdate1

jr_001_4ced:
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 4, [hl]
    jr z, jr_001_4cfa

    jp Jump_001_524c


jr_001_4cfa:
    ld hl, SOUND_CH_DELAY
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_001_4d04

    dec [hl]
    ret


jr_001_4d04:
    ld hl, SOUND_CH_VIBRATO_DEPTH
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_001_4d0d

    ret


jr_001_4d0d:
    ld d, a
    ld hl, SOUND_CH_VIBRATO_PHASE
    add hl, bc
    ld a, [hl]
    and $0f
    and a
    jr z, jr_001_4d1a

    dec [hl]
    ret


jr_001_4d1a:
    ld a, [hl]
    swap [hl]
    or [hl]
    ld [hl], a
    ld hl, SOUND_CH_FREQ_LO_BASE
    add hl, bc
    ld e, [hl]
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 3, [hl]
    jr z, jr_001_4d3a

    res 3, [hl]
    ld a, d
    and $0f
    ld d, a
    ld a, e
    sub d
    jr nc, jr_001_4d38

    ld a, $00

jr_001_4d38:
    jr jr_001_4d46

jr_001_4d3a:
    set 3, [hl]
    ld a, d
    and $f0
    swap a
    add e
    jr nc, jr_001_4d46

    ld a, $ff

jr_001_4d46:
    ld d, a
    ld b, $03
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
    res 4, [hl]
    res 5, [hl]
    call CountdownSequence
    ret


CountdownSequence::
    call SoundUpdate2
    ld d, a
    cp $ff
    jp nz, Jump_001_4df4

    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 1, [hl]
    jr nz, jr_001_4da2

    ld a, c
    cp $03
    jr nc, jr_001_4d7e

    jr jr_001_4dbd

jr_001_4d7e:
    res 2, [hl]
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    res 0, [hl]
    cp $06
    jr nz, jr_001_4d92

    ld a, $00
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a

jr_001_4d92:
    jr nz, jr_001_4da0

    ld a, [SOUND_DEFERRED_ID]
    and a
    jr z, jr_001_4da0

    xor a
    ld [SOUND_DEFERRED_ID], a
    jr jr_001_4dbd

jr_001_4da0:
    jr jr_001_4dc8

jr_001_4da2:
    res 1, [hl]
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


jr_001_4dbd:
    ld b, $00
    ld hl, SoundChannelDisableMaskTable
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a

jr_001_4dc8:
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp $0f
    jr nc, jr_001_4dd1

    jr jr_001_4dee

jr_001_4dd1:
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp $0f
    jr z, jr_001_4dee

    jr c, jr_001_4ddc

    jr jr_001_4dee

jr_001_4ddc:
    ld a, c
    cp $04
    jr z, jr_001_4de5

    call UpdateChannel
    ret c

jr_001_4de5:
    ld a, [SOUND_NR50_BACKUP]
    ldh [rNR50], a
    xor a
    ld [SOUND_NR50_BACKUP], a

jr_001_4dee:
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, bc
    ld [hl], b
    ret


Jump_001_4df4:
    cp $fd
    jp nz, Jump_001_4e29

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
    set 1, [hl]
    jp CountdownSequence


Jump_001_4e29:
    cp $fe
    jp nz, Jump_001_4e64

    call SoundUpdate2
    ld e, a
    and a
    jr z, jr_001_4e4d

    ld b, $00
    ld hl, SOUND_CH_LOOP_COUNTER
    add hl, bc
    ld a, [hl]
    cp e
    jr nz, jr_001_4e4b

    ld a, $01
    ld [hl], a
    call SoundUpdate2
    call SoundUpdate2
    jp CountdownSequence


jr_001_4e4b:
    inc a
    ld [hl], a

jr_001_4e4d:
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


Jump_001_4e64:
    and $f0
    cp $d0
    jp nz, Jump_001_4ea3

    ld a, d
    and $0f
    ld b, $00
    ld hl, SOUND_CH_LENGTH_SCALE
    add hl, bc
    ld [hl], a
    ld a, c
    cp $03
    jr z, jr_001_4ea0

    call SoundUpdate2
    ld d, a
    ld a, c
    cp $02
    jr z, jr_001_4e8c

    cp $06
    jr nz, jr_001_4e99

    ld hl, SOUND_WAVE_PATTERN_ALT
    jr jr_001_4e8f

jr_001_4e8c:
    ld hl, SOUND_WAVE_PATTERN_MAIN

jr_001_4e8f:
    ld a, d
    and $0f
    ld [hl], a
    ld a, d
    and $30
    sla a
    ld d, a

jr_001_4e99:
    ld b, $00
    ld hl, SOUND_CH_ENVELOPE
    add hl, bc
    ld [hl], d

jr_001_4ea0:
    jp CountdownSequence


Jump_001_4ea3:
    ld a, d
    cp $e8
    jr nz, jr_001_4eb5

    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    ld a, [hl]
    xor $01
    ld [hl], a
    jp CountdownSequence


jr_001_4eb5:
    cp $ea
    jr nz, jr_001_4eed

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
    and $f0
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
    and $0f
    ld d, a
    ld hl, SOUND_CH_VIBRATO_PHASE
    add hl, bc
    swap a
    or d
    ld [hl], a
    jp CountdownSequence


jr_001_4eed:
    cp $eb
    jr nz, jr_001_4f25

    call SoundUpdate2
    ld b, $00
    ld hl, SOUND_CH_SLIDE_TICKS
    add hl, bc
    ld [hl], a
    call SoundUpdate2
    ld d, a
    and $f0
    swap a
    ld b, a
    ld a, d
    and $0f
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
    set 4, [hl]
    call SoundUpdate2
    ld d, a
    jp Display2PStatus


jr_001_4f25:
    cp $ec
    jr nz, jr_001_4f3a

    call SoundUpdate2
    rrca
    rrca
    and $c0
    ld b, $00
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld [hl], a
    jp CountdownSequence


jr_001_4f3a:
    cp $ed
    jr nz, jr_001_4f7a

    ld a, c
    cp $04
    jr nc, jr_001_4f5e

    call SoundUpdate2
    ld [SOUND_MAIN_TEMPO_HI], a
    call SoundUpdate2
    ld [SOUND_MAIN_TEMPO_LO], a
    xor a
    ld [SOUND_CH_TEMPO_ACCUM], a
    ld [SOUND_CH_TEMPO_ACCUM + 1], a
    ld [SOUND_CH_TEMPO_ACCUM + 2], a
    ld [SOUND_CH_TEMPO_ACCUM + 3], a
    jr jr_001_4f77

jr_001_4f5e:
    call SoundUpdate2
    ld [SOUND_SFX_TEMPO_HI], a
    call SoundUpdate2
    ld [SOUND_SFX_TEMPO_LO], a
    xor a
    ld [SOUND_CH_TEMPO_ACCUM + 4], a
    ld [SOUND_CH_TEMPO_ACCUM + 5], a
    ld [SOUND_CH_TEMPO_ACCUM + 6], a
    ld [SOUND_CH_TEMPO_ACCUM + 7], a

jr_001_4f77:
    jp CountdownSequence


jr_001_4f7a:
    cp $ee
    jr nz, jr_001_4f87

    call SoundUpdate2
    ld [SOUND_OUTPUT_MASK], a
    jp CountdownSequence


jr_001_4f87:
    cp $ef
    jr nz, jr_001_4fa6

    call SoundUpdate2
    push bc
    call SoundEngine
    pop bc
    ld a, [SOUND_DEFERRED_ID]
    and a
    jr nz, jr_001_4fa3

    ld a, [SOUND_BGM_ACTIVE_ID + 3]
    ld [SOUND_DEFERRED_ID], a
    xor a
    ld [SOUND_BGM_ACTIVE_ID + 3], a

jr_001_4fa3:
    jp CountdownSequence


jr_001_4fa6:
    cp $fc
    jr nz, StageIntroAnim

    call SoundUpdate2
    ld b, $00
    ld hl, SOUND_CH_DUTY_ROTATE
    add hl, bc
    ld [hl], a
    and $c0
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld [hl], a
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set 6, [hl]
    jp CountdownSequence


StageIntroAnim::
    cp $f0
    jr nz, jr_001_4fd0

    call SoundUpdate2
    ldh [rNR50], a
    jp CountdownSequence


jr_001_4fd0:
    cp $f1
    jr nz, jr_001_4fe2

    push af
    push bc
    push de
    push hl
    call CheckGameStateUpdate
    pop hl
    pop de
    pop bc
    pop af
    jp CountdownSequence


jr_001_4fe2:
    cp $f8
    jr nz, jr_001_4ff1

    ld b, $00
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    set 0, [hl]
    jp CountdownSequence


jr_001_4ff1:
    and $f0
    cp $e0
    jr nz, jr_001_5004

    ld hl, SOUND_CH_OCTAVE
    ld b, $00
    add hl, bc
    ld a, d
    and $0f
    ld [hl], a
    jp CountdownSequence


jr_001_5004:
    cp $20
    jr nz, jr_001_5051

    ld a, c
    cp $03
    jr c, jr_001_5051

    ld b, $00
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    bit 0, [hl]
    jr nz, jr_001_5051

    call Display2PStatus
    ld d, a
    ld b, $00
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld a, [hl]
    or d
    ld d, a
    ld b, $01
    call SoundUpdate3
    ld [hl], d
    call SoundUpdate2
    ld d, a
    ld b, $02
    call SoundUpdate3
    ld [hl], d
    call SoundUpdate2
    ld e, a
    ld a, c
    cp $07
    ld a, $00
    jr z, jr_001_5044

    push de
    call SoundUpdate2
    pop de

jr_001_5044:
    ld d, a
    push de
    call GetMusicPointer
    call MusicDataInit
    pop de
    call ProcessNote
    ret


jr_001_5051:
    ld a, c
    cp $04
    jr c, jr_001_506d

    ld a, d
    cp $10
    jr nz, jr_001_506d

    ld b, $00
    ld hl, SOUND_CH_GATE_FLAGS
    add hl, bc
    bit 0, [hl]
    jr nz, jr_001_506d

    call SoundUpdate2
    ldh [rNR10], a
    jp CountdownSequence


jr_001_506d:
    ld a, c
    cp $03
    jr nz, Display2PStatus

    ld a, d
    and $f0
    cp $b0
    jr z, jr_001_5087

    jr nc, Display2PStatus

    swap a
    ld b, a
    ld a, d
    and $0f
    ld d, a
    ld a, b
    push de
    push bc
    jr jr_001_508f

jr_001_5087:
    ld a, d
    and $0f
    push af
    push bc
    call SoundUpdate2

jr_001_508f:
    ld d, a
    ld a, [SOUND_DEFERRED_ID]
    and a
    jr nz, jr_001_509a

    ld a, d
    call SoundEngine

jr_001_509a:
    pop bc
    pop de

Display2PStatus::
    ld a, d
    push af
    and $0f
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
    cp $04
    jr nc, jr_001_50bd

Draw2PField::
    ld a, [SOUND_MAIN_TEMPO_HI]
    ld d, a
    ld a, [SOUND_MAIN_TEMPO_LO]
    ld e, a
    jr jr_001_50cd

jr_001_50bd:
    ld d, $01
    ld e, $00
    cp $07
    jr z, jr_001_50cd

    ld a, [SOUND_SFX_TEMPO_HI]
    ld d, a
    ld a, [SOUND_SFX_TEMPO_LO]
    ld e, a

jr_001_50cd:
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
    bit 0, [hl]
    jr nz, jr_001_50f7

    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 2, [hl]
    jr z, jr_001_50f7

    pop hl
    ret


jr_001_50f7:
    pop af
    and $f0
    cp $c0
    jr nz, jr_001_512e

    ld a, c
    cp $04
    jr nc, jr_001_510b

    ld hl, SOUND_BGM_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_001_512d

jr_001_510b:
    ld a, c
    cp $02
    jr z, jr_001_5114

    cp $06
    jr nz, jr_001_5121

jr_001_5114:
    ld b, $00
    ld hl, SoundChannelDisableMaskTable
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a
    jr jr_001_512d

jr_001_5121:
    ld b, $02
    call SoundUpdate3
    ld a, $08
    ld [hl+], a
    inc hl
    ld a, $80
    ld [hl], a

jr_001_512d:
    ret


jr_001_512e:
    swap a
    ld b, $00
    ld hl, SOUND_CH_OCTAVE
    add hl, bc
    ld b, [hl]
    call SoundUpdate5
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 4, [hl]
    jr z, jr_001_5147

    call UpdateObjectData

jr_001_5147:
    push de
    ld a, c
    cp $04
    jr nc, jr_001_515c

    ld hl, SOUND_BGM_ACTIVE_ID
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    and a
    jr nz, jr_001_515a

    jr jr_001_515c

jr_001_515a:
    pop de
    ret


jr_001_515c:
    ld b, $00
    ld hl, SOUND_CH_ENVELOPE
    add hl, bc
    ld d, [hl]
    ld b, $02
    call SoundUpdate3
    ld [hl], d
    call GetMusicPointer
    call MusicDataInit
    pop de
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 0, [hl]
    jr z, jr_001_517e

    inc e
    jr nc, jr_001_517e

    inc d

jr_001_517e:
    ld hl, SOUND_CH_FREQ_LO_BASE
    add hl, bc
    ld [hl], e
    call ProcessNote
    ret


MusicDataInit::
    ld b, $00
    ld hl, SoundChannelEnableMaskTable
    add hl, bc
    ldh a, [rNR51]
    or [hl]
    ld d, a
    ld a, c
    cp $07
    jr z, jr_001_51a2

    cp $04
    jr nc, jr_001_51b4

    ld hl, SOUND_BGM_ACTIVE_ID
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_001_51b4

jr_001_51a2:
    ld a, [SOUND_OUTPUT_MASK]
    ld hl, SoundChannelEnableMaskTable
    add hl, bc
    and [hl]
    ld d, a
    ldh a, [rNR51]
    ld hl, SoundChannelDisableMaskTable
    add hl, bc
    and [hl]

LoadMusicTrack::
    or d
    ld d, a

jr_001_51b4:
    ld a, d
    ldh [rNR51], a
    ret


GetMusicPointer::
    ld b, $00
    ld hl, SOUND_CH_NOTE_LENGTH
    add hl, bc
    ld d, [hl]
    ld a, c
    cp $02

ParseMusicCommand::
    jr z, jr_001_51d3

    cp $06
    jr z, jr_001_51d3

    ld a, d
    and $3f
    ld d, a
    ld hl, SOUND_CH_DUTY_LENGTH
    add hl, bc
    ld a, [hl]
    or d
    ld d, a

jr_001_51d3:
    ld b, $01
    call SoundUpdate3
    ld [hl], d
    ret


ProcessNote::
    ld a, c
    cp $02
    jr z, jr_001_51e3

    cp $06
    jr nz, jr_001_5210

jr_001_51e3:
    push de
    ld de, SOUND_WAVE_PATTERN_MAIN
    cp $02
    jr z, jr_001_51ee

    ld de, SOUND_WAVE_PATTERN_ALT

jr_001_51ee:
    ld a, [de]
    add a
    ld d, $00
    ld e, a
    ld hl, WavePatternPointerTable
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld hl, $ff30
    ld b, $0f
    ld a, $00
    ldh [rNR30], a

jr_001_5203:
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, b
    dec b
    and a
    jr nz, jr_001_5203

    ld a, $80
    ldh [rNR30], a
    pop de

jr_001_5210:
    ld a, d
    or $80
    and $c7
    ld d, a
    ld b, $03
    call SoundUpdate3
    ld [hl], e
    inc hl
    ld [hl], d
    ret


UpdateChannel::
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp $0f
    jr nc, jr_001_5228

    jr jr_001_5249

jr_001_5228:
    ld a, [SOUND_BGM_ACTIVE_ID]
    cp $0f
    jr z, jr_001_5249

    jr c, jr_001_5233

    jr jr_001_5249

jr_001_5233:
    ld hl, SOUND_CH_SEQUENCE_PTRS
    ld e, c
    ld d, $00
    sla e
    rl d
    add hl, de
    ld a, [hl]
    sub $01
    ld [hl], a
    inc hl
    ld a, [hl]
    sbc $00
    ld [hl], a
    scf
    ret


jr_001_5249:
    scf
    ccf
    ret


Jump_001_524c:
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    bit 5, [hl]
    jp nz, Jump_001_5293

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
    jp c, ClearObjectFlags

    jr nz, jr_001_52c6

    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, bc
    ld a, [hl]
    cp e
    jp c, ClearObjectFlags

    jr jr_001_52c6

Jump_001_5293:
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
    jr c, ClearObjectFlags

    jr nz, jr_001_52c6

    ld hl, SOUND_CH_SLIDE_TARGET_LO
    add hl, bc
    ld a, e
    cp [hl]
    jr c, ClearObjectFlags

jr_001_52c6:
    ld hl, SOUND_CH_FREQ_LO
    add hl, bc
    ld [hl], e
    ld hl, SOUND_CH_FREQ_HI
    add hl, bc
    ld [hl], d
    ld b, $03
    call SoundUpdate3
    ld a, e
    ld [hl+], a
    ld [hl], d
    ret


ClearObjectFlags::
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    res 4, [hl]
    res 5, [hl]
    ret


UpdateObjectData::
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
    jr nc, jr_001_52fa

    ld a, $01

jr_001_52fa:
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
    jr c, jr_001_5316

    ld d, a
    ld b, $00
    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set 5, [hl]
    jr jr_001_5339

jr_001_5316:
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
    res 5, [hl]

jr_001_5339:
    ld hl, SOUND_CH_SLIDE_TICKS
    add hl, bc

jr_001_533d:
    inc b
    ld a, e
    sub [hl]
    ld e, a
    jr nc, jr_001_533d

    ld a, d
    and a
    jr z, jr_001_534b

    dec a
    ld d, a
    jr jr_001_533d

jr_001_534b:
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
    and $c0
    ld d, a
    ld b, $01
    call SoundUpdate3
    ld a, [hl]
    and $3f
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
    jr nc, jr_001_5393

    inc h

jr_001_5393:
    ld l, a
    ld a, [hl]
    add b
    ld l, a
    ld h, $ff
    ret


SoundUpdate4::
    ld h, $00

jr_001_539c:
    srl a
    jr nc, jr_001_53a1

    add hl, de

jr_001_53a1:
    sla e
    rl d
    and a
    jr z, jr_001_53aa

    jr jr_001_539c

jr_001_53aa:
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

jr_001_53b9:
    cp $07
    jr z, jr_001_53c4

    sra d
    rr e
    inc a
    jr jr_001_53b9

jr_001_53c4:
    ld a, $08
    add d
    ld d, a
    ret


SoundEngine::
    ld [SOUND_COMMAND_ID], a
    cp $ff
    jp z, StopAllSoundHW

    cp $2f
    jp z, SoundLookupIndex

    jp c, SoundLookupIndex

    cp $72
    jr z, jr_001_53e0

    jp nc, SoundLookupIndex

jr_001_53e0:
    xor a
    ld [SOUND_STATUS], a
    ld [SOUND_DEFERRED_ID], a
    ld [SOUND_MAIN_TEMPO_LO], a
    ld [SOUND_WAVE_PATTERN_MAIN], a
    ld [SOUND_WAVE_PATTERN_ALT], a
    ld d, $08
    ld hl, SOUND_CH_RETURN_PTRS
    call StopAllSound
    ld hl, SOUND_CH_SEQUENCE_PTRS
    call StopAllSound
    ld d, $04
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
    ld a, $01
    ld hl, SOUND_CH_LOOP_COUNTER
    call StopAllSound
    ld hl, SOUND_CH_NOTE_LENGTH
    call StopAllSound
    ld hl, SOUND_CH_LENGTH_SCALE
    call StopAllSound
    ld [SOUND_MAIN_TEMPO_HI], a
    ld a, $ff
    ld [SOUND_OUTPUT_MASK], a
    xor a
    ldh [rNR50], a
    ld a, $08
    ldh [rNR10], a
    ld a, $00
    ldh [rNR51], a
    xor a
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a
    ld a, $77
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
    and $c0
    rlca
    rlca
    ld c, a

Jump_001_54ba:
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
    and $0f
    ld e, a
    ld d, $00
    ld hl, SOUND_CH_ACTIVE_ID
    add hl, de
    ld a, [hl]
    and a
    jr z, jr_001_54f6

    ld a, e
    cp $07
    jr nz, jr_001_54ed

    ld a, [SOUND_COMMAND_ID]
    cp $0f
    jr nc, jr_001_54e6

    ret


jr_001_54e6:
    ld a, [hl]
    cp $0f
    jr z, jr_001_54f6

    jr c, jr_001_54f6

jr_001_54ed:
    ld a, [SOUND_COMMAND_ID]
    cp [hl]
    jr z, jr_001_54f6

    jr c, jr_001_54f6

    ret


jr_001_54f6:
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
    ld a, $01
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
    cp $04
    jr nz, jr_001_557e

    ld a, $08
    ldh [rNR10], a

jr_001_557e:
    ld a, c
    and a
    jp z, StartSoundSequence

    dec c
    jp Jump_001_54ba


StopAllSoundHW::
    ld a, $80
    ldh [rNR52], a
    ldh [rNR30], a
    xor a
    ldh [rNR51], a
    ldh [rNR32], a
    ld a, $08
    ldh [rNR10], a
    ldh [rNR12], a
    ldh [rNR22], a
    ldh [rNR42], a
    ld a, $40
    ldh [rNR14], a
    ldh [rNR24], a
    ldh [rNR44], a
    ld a, $77
    ldh [rNR50], a
    xor a
    ld [SOUND_STATUS], a
    ld [SOUND_DEFERRED_ID], a
    ld [SOUND_PAUSE_FLAG], a
    ld [SOUND_MAIN_TEMPO_LO], a
    ld [SOUND_SFX_TEMPO_LO], a
    ld [SOUND_WAVE_PATTERN_MAIN], a
    ld [SOUND_WAVE_PATTERN_ALT], a
    ld d, $a0
    ld hl, SOUND_CH_SEQUENCE_PTRS
    call StopAllSound
    ld a, $01
    ld d, $18
    ld hl, SOUND_CH_NOTE_LENGTH
    call StopAllSound
    ld [SOUND_MAIN_TEMPO_HI], a
    ld [SOUND_SFX_TEMPO_HI], a
    ld a, $ff
    ld [SOUND_OUTPUT_MASK], a
    ret


StopAllSound::
    ld b, d

jr_001_55dd:
    ld [hl+], a
    dec b
    jr nz, jr_001_55dd

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
    and $03
    ld c, a
    ld a, b
    and $0f
    ld b, c
    inc b
    inc de
    ld c, $00

jr_001_5603:
    cp c
    jr z, jr_001_560c

    inc c
    inc hl
    inc hl
    jr jr_001_5603

jr_001_560c:
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
    cp $03
    jr c, jr_001_5625

    ld hl, SOUND_CH_FLAGS
    add hl, bc
    set 2, [hl]

jr_001_5625:
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
    jr nz, jr_001_5603

    ld a, [SOUND_COMMAND_ID]
    cp $0f
    jr nc, jr_001_563f

    jr jr_001_5668

jr_001_563f:
    ld a, [SOUND_COMMAND_ID]
    cp $0f
    jr z, jr_001_5668

    jr c, jr_001_5649

jr_001_5647:
    jr jr_001_5668

jr_001_5649:
    ld hl, SOUND_BGM_ACTIVE_ID
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld hl, SOUND_CH_SEQUENCE_PTRS + $0c
    ld de, SoundWaveDutyData
    ld [hl], e
    inc hl
    ld [hl], d
    ld a, [SOUND_NR50_BACKUP]
    and a
    jr nz, jr_001_5668

    ldh a, [rNR50]
    ld [SOUND_NR50_BACKUP], a
    ld a, $77
    ldh [rNR50], a

jr_001_5668:
    ret

SoundWaveDutyData::
    db $ff

SoundRegisterOffsetTable::
    db $10, $15, $1a, $1f, $10, $15, $1a, $1f

SoundChannelDisableMaskTable::
    db $ee, $dd, $bb, $77, $ee, $dd, $bb, $77

SoundChannelEnableMaskTable::
    db $11, $22, $44, $88, $11, $22, $44, $88

SoundPitchBaseTable::
    dw $f82c, $f89d, $f907, $f96b, $f9ca, $fa23, $fa77, $fac7
    dw $fb12, $fb58, $fb9b, $fbda

SoundSequenceData_569a::
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
SoundSequenceData_5764::
    db $ec, $02, $ea, $08, $26, $dc, $c1, $e4, $21, $21, $01, $01, $e5, $a1, $e4, $01
    db $21, $e5, $a0, $d6, $c1, $e4, $20, $50, $dc, $c1, $71, $71, $51, $51, $71, $51
    db $31, $21, $01, $01, $21, $21, $31, $31, $71, $31, $53, $33, $23, $a3
SoundSequenceData_5792::
    db $dc, $b3, $50, $71, $52, $21, $a1, $91, $a1, $91, $71, $3d, $00, $31, $02, $e5
    db $91, $e4, $71, $51, $71, $51, $23, $33, $43, $53, $50, $71, $52, $21, $a1, $91
    db $a1, $91, $72, $aa, $d6, $b1, $50, $70, $90, $a0, $dc, $b3, $e3, $01, $01, $e4
    db $a1, $a1, $91, $e3, $21, $01, $e4, $91, $dc, $a7, $a7, $dc, $30, $a7, $dc, $b7
    db $73, $35, $71, $51, $71, $53, $a5, $a1, $91, $a1, $93, $53, $e3, $03, $e4, $93
    db $a3, $e3, $03, $21, $01, $e4, $a1, $91, $73, $35, $a1, $91, $a1, $e3, $23, $03
    db $e4, $b3, $61, $71, $e3, $03, $e4, $a3, $91, $e3, $21, $01, $e4, $91, $dc, $b3
    db $a3, $a3, $dc, $b1, $a7, $fe, $00, $92, $57
SoundSequenceData_580b::
    db $d6, $12, $fd, $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fd, $34, $5a
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
SoundSequenceData_5a6f::
    db $dc, $c3, $b7, $04, $b2, $04, $b4, $04, $b7, $04, $b7, $04, $b7, $04, $b2, $04
    db $b4, $04, $b7, $04, $b1, $04, $b0, $04, $b0, $04
SoundSequenceData_5a89::
    db $c3, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b2
    db $04, $b4, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7
    db $04, $b2, $04, $b4, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7
    db $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b2
    db $04, $b4, $04, $b7, $04, $b3, $04, $fe, $00, $89, $5a
SoundSequenceData_5ad4::
    db $ed, $00, $92, $f0, $77, $ec, $02, $e8, $d8, $b2, $e5, $73, $b1, $93, $b1, $e4
    db $05, $21, $41, $21, $e5, $71, $e4, $21, $01, $e5, $b1, $91, $b1, $75, $25
SoundSequenceData_5af3::
    db $ed, $00, $92, $f0, $77, $ec, $02, $e8, $d8, $b2
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
SoundSequenceData_5ccf::
    db $ec, $02, $d8, $c2, $e4, $21, $71, $61, $73, $21, $41, $61, $71, $b3, $91, $73
    db $61, $43, $61, $75, $e5, $75
SoundSequenceData_5ce5::
    db $ec, $02, $d8, $c2
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
SoundSequenceData_5f1f::
    db $d8, $12, $cf, $c5, $e4, $01, $21, $c3, $01, $c3, $e5, $b1, $c3, $b1, $c3
SoundSequenceData_5f2e::
    db $d8, $12
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
MusicSequenceData_60c0::
    db $d8, $cf, $c7, $c7, $cf
MusicSequenceData_60c5::
    db $d8, $f1, $c4, $f1, $c5, $f1, $c5, $f1, $c5
MusicSequenceData_60ce::
    db $f1, $c5, $f1, $c5, $f1, $c5, $f1, $c5, $fe, $07, $ce, $60
MusicSequenceData_60da::
    db $f1, $cb, $f1, $cb, $fe, $02, $da, $60
MusicSequenceData_60e2::
    db $f1, $c5, $f1, $c5, $f1, $c5, $f1, $c5, $fe, $02, $e2, $60
MusicSequenceData_60ee::
    db $f1, $c5, $f1, $c5, $f1, $c3, $f1, $c0, $f1, $c0, $f1, $c0, $f1, $c4, $d8, $fe
    db $02, $ee, $60
MusicSequenceData_6101::
    db $f1, $c5, $f1, $c5, $f1, $c5, $f1, $c5, $fe, $04, $01, $61, $f1, $cb, $f1, $cb
    db $f1, $cb, $c9, $f1, $c1
MusicSequenceData_6116::
    db $f1, $c5, $f1, $c5, $f1, $c5, $f1, $c5, $fe, $02, $16, $61
MusicSequenceData_6122::
    db $f1, $cb, $f1, $cb, $fe, $04, $22, $61
MusicSequenceData_612a::
    db $f1, $c5, $f1, $c5, $f1, $c5, $f1, $c5, $fe, $08, $2a, $61
MusicSequenceData_6136::
    db $f1, $cb, $f1, $cb, $f1, $cb, $f1, $c5, $f1, $c5, $fe, $02, $36, $61
MusicSequenceData_6144::
    db $f1, $c5, $f1, $c5, $f1, $c5, $f1, $c5, $fe, $04, $44, $61
MusicSequenceData_6150::
    db $f1, $cb, $f1, $cb, $fe, $02, $50, $61
MusicSequenceData_6158::
    db $f1, $c5, $f1, $c5, $f1, $c5, $f1, $c5, $fe, $04, $58, $61, $f1, $c5, $f1, $c5
    db $f1, $c5, $f1, $c5, $fe, $00, $ce, $60
MusicSequenceData_6170::
    db $ed, $00, $e0, $f0, $77, $ec, $02, $e8, $dc, $b3, $c3, $e4, $07, $e5, $b7, $41
    db $71, $01, $79
MusicSequenceData_6183::
    db $ed, $00, $e0, $f0, $77, $ec, $02, $e8, $dc, $b3, $cf, $c9, $e5, $70, $50, $40
    db $50, $40, $20, $01, $e6, $71, $e5, $01, $41, $21, $51, $01, $41, $21, $e6, $b0
    db $e5, $00, $21, $51, $73, $53
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
MusicSequenceData_625c::
    db $ec, $02, $dc, $c3, $e4, $01, $21, $43, $51, $41, $21, $01, $e5, $b1, $e4, $21
    db $03, $23, $01, $e5, $71, $51, $71
MusicSequenceData_6273::
    db $ec, $02, $dc, $c3, $e4, $01, $e5, $71, $e4, $01, $41, $21, $e5, $71, $e4, $21
    db $51, $41, $00, $20, $41, $51, $43, $21, $00, $20, $41, $01, $41, $71, $51, $01
    db $41, $01, $21, $e5, $71, $e4, $21, $51, $41, $50, $40, $23
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
MusicSequenceData_63e3::
    db $dc, $10, $ea, $08, $26, $c3, $cf, $cf
MusicSequenceData_63eb::
    db $dc, $10, $ea, $08, $26, $cf, $cf, $cf, $cb, $e6, $b0, $e5, $00, $20, $e6, $b0
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
MusicSequenceData_64d1::
    db $dc, $c3, $cf, $cf
MusicSequenceData_64d5::
    db $dc, $f1, $c6, $f1, $c7, $f1, $c7, $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $f1
    db $c3, $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3
MusicSequenceData_64f0::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $02, $f0, $64
MusicSequenceData_64fc::
    db $f1, $c7, $f1, $c7, $fe, $02, $fc, $64
MusicSequenceData_6504::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $02, $04, $65, $f1, $c7, $f1, $c7
    db $f1, $c7, $f1, $c3, $f1, $c3, $f1, $c7, $f1, $c7, $f1, $c3, $f1, $c3, $f1, $c3
    db $f1, $c3, $f1, $c7, $f1, $c7, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c3
    db $f1, $c3
MusicSequenceData_6536::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $04, $36, $65, $f1, $c7, $f1, $c7
    db $f1, $c7, $f1, $c3, $f1, $c3, $f1, $c7, $f1, $c3, $f1, $c3
MusicSequenceData_6552::
    db $f1, $c7, $f1, $c7, $fe, $04, $52, $65
MusicSequenceData_655a::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $04, $5a, $65
MusicSequenceData_656e::
    db $f1, $c7, $f1, $c7, $fe, $02, $6e, $65, $f1, $c7, $f1, $c3, $f1, $c3, $f1, $c7
    db $f1, $c3, $f1, $c3, $fe, $00, $f0, $64
MusicSequenceData_6586::
    db $ed, $00, $80, $f0, $77, $ec, $02, $ea, $07, $23, $e8, $dc, $b2, $e4, $40, $60
    db $40, $60, $40, $60, $40, $60, $41, $e5, $b1, $e4, $11, $31, $e5, $b2, $e4, $10
    db $31, $e5, $b1, $e4, $43, $43
MusicSequenceData_65ac::
    db $ed, $00, $80, $f0, $77, $ec, $02, $ea, $07, $23, $e8
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
MusicSequenceData_66e3::
    db $ec, $02, $ea, $06, $24, $dc, $c2, $e4, $b5, $e3, $11, $e4, $b1, $91, $81, $61
    db $41, $61, $81, $61, $b3, $b3
MusicSequenceData_66f9::
    db $ec, $02, $ea, $06, $24, $dc, $c2
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
MusicSequenceData_68b5::
    db $dc, $10, $cf, $c9, $e5, $b0, $c0, $e4, $10, $c0, $30, $c0
MusicSequenceData_68c1::
    db $dc, $10
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
MusicSequenceData_6b16::
    db $dc, $cf, $cf
MusicSequenceData_6b19::
    db $dc, $f1, $c0, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1
    db $c1
MusicSequenceData_6b2a::
    db $f1, $c1, $f1, $c1, $c1, $d6, $f1, $c0, $f1, $c2, $f1, $c0, $f1, $c2, $f1, $c0
    db $f1, $c2, $f1, $c0, $f1, $c2, $dc, $c1
MusicSequenceData_6b42::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $02, $42, $6b, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $c1, $d6, $f1, $c0, $f1, $c2, $f1, $c0
    db $f1, $c2, $f1, $c0, $f1, $c2, $f1, $c0, $f1, $c2, $dc, $c1, $f1, $c1, $f1, $c1
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c3, $f1, $c3
    db $f1, $c3, $f1, $c1, $f1, $c1
MusicSequenceData_6b98::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $04, $98, $6b
MusicSequenceData_6bac::
    db $f1, $c7, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $fe, $02, $ac, $6b, $f1, $c1
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $cf
MusicSequenceData_6bcc::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $03, $cc, $6b, $f1, $cf
MusicSequenceData_6bda::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $03, $da, $6b, $f1, $c1, $f1, $c1
    db $f1, $c1, $f1, $c1, $c7
MusicSequenceData_6bef::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $02, $ef, $6b
MusicSequenceData_6bfb::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $06, $fb, $6b
MusicSequenceData_6c0f::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $02, $0f, $6c
MusicSequenceData_6c1b::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $02, $1b, $6c
MusicSequenceData_6c27::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $02, $27, $6c
MusicSequenceData_6c3b::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $02, $3b, $6c
MusicSequenceData_6c47::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $02, $47, $6c
MusicSequenceData_6c5b::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $02, $5b, $6c
MusicSequenceData_6c67::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $02, $67, $6c
MusicSequenceData_6c7b::
    db $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1
    db $fe, $07, $7b, $6c, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c3, $f1, $c1, $f1, $c3
MusicSequenceData_6c9b::
    db $f1, $c3, $f1, $c3, $f1, $c3, $f1, $c3, $fe, $03, $9b, $6c, $f1, $c3, $f1, $c3
    db $f1, $c3, $c0, $f1, $c0, $f1, $c0, $f1, $c0, $f1, $c1, $f1, $c1, $f1, $c1, $f1
    db $c1, $f1, $c1, $f1, $c1, $f1, $c1, $f1, $c1, $fe, $00, $2a, $6b
MusicSequenceData_6cc8::
    db $ed, $00, $84, $f0, $77, $ec, $02, $ea, $07, $23, $e8, $dc, $b2, $e5, $71, $70
    db $70, $73, $d8, $b2, $c1, $71, $91, $b1, $e4, $01, $11, $25, $dc, $b2, $e5, $b3
    db $e4, $03, $e5, $05
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
MusicSequenceData_6db3::
    db $fd, $dd, $6d
MusicSequenceData_6db6::
    db $fd, $00, $6e, $fd, $22, $6f, $fd, $4e, $6f, $fd, $66, $6f, $fe, $00, $b6, $6d
MusicSequenceData_6dc6::
    db $d4, $c1, $c0, $e8, $fd, $dd, $6d
MusicSequenceData_6dcd::
    db $fd, $00, $6e, $fd, $38, $6f, $fd, $59, $6f, $fd, $66, $6f, $fe, $00, $cd, $6d
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
MusicSequenceData_6f7d::
    db $e8
MusicSequenceData_6f7e::
    db $d6, $10, $e4, $42, $c0, $40, $c0, $40, $c0, $dc, $10, $43, $cb, $20, $c2, $00
    db $c2, $e5, $70, $c2
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
MusicSequenceData_71d2::
    db $fd, $f2, $71
MusicSequenceData_71d5::
    db $fd, $17, $72, $fd, $f0, $74, $fd, $3c, $75, $fe, $00, $d5, $71
MusicSequenceData_71e2::
    db $fd, $f2
MusicSequenceData_71e4::
    db $71
MusicSequenceData_71e5::
    db $fd, $17, $72, $fd, $16, $75, $fd, $3c, $75, $fe, $00, $e5, $71
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
MusicSequenceData_753e::
    db $ed, $00, $80, $f0, $77, $ea, $18, $26, $ec, $02, $e8, $dc, $b1, $e4, $01, $00
    db $00, $dc, $b3, $01, $51, $dc, $b0, $97, $dc, $b7, $9f, $dc, $92, $e3, $eb, $00
    db $19, $91, $c7, $ff
MusicSequenceData_7562::
    db $ea, $10, $27, $ec, $02, $dc, $c1, $e4, $51, $50, $50, $dc, $c3, $51, $91, $dc
    db $c0, $e3, $07, $dc, $c7, $0f, $dc, $b3, $e2, $eb, $00, $00, $01, $ff
MusicSequenceData_7580::
    db $dc, $10, $e4, $90, $c0, $d6, $10, $90, $c0, $90, $c0, $dc, $10, $90, $c0, $e3
    db $00, $c0, $e4, $93, $c3, $cf, $e3, $eb, $00, $10, $01, $ff
MusicSequenceData_759c::
    db $dc, $cf, $d6, $b0, $0d, $b0, $0d, $b0, $0c, $b0, $0c, $b0, $0b, $b0, $0b, $b0
    db $0b, $b0, $0b, $b0, $06, $b0, $06, $b0, $06, $b0, $06, $b0, $06, $b0, $06, $b0
    db $06, $b0, $06, $b0, $0a, $b0, $0a, $b0, $0a, $b0, $0a, $b0, $0a, $b0, $0a, $b0
    db $0a, $b0, $0a, $d8, $b1, $05, $b1, $05, $b1, $05, $b1, $09, $ff
MusicSequenceData_75d9::
    db $ed, $00, $80, $ea, $0a, $23, $e8, $ec, $02, $dc, $b3, $e5, $91, $90, $a0, $e4
    db $05, $01, $e5, $91, $e4, $01, $21, $41, $51, $71, $97, $ff
MusicSequenceData_75f5::
    db $ec, $02, $ea, $08, $24, $dc, $c3, $e4, $51, $50, $50, $55, $51, $71, $91, $a2
    db $e3, $00, $21, $41, $57, $ff
MusicSequenceData_760b::
    db $dc, $10, $e5, $51, $50, $40, $55, $01, $21, $41, $52, $70, $91, $71, $53, $c3
    db $ff
MusicSequenceData_761c::
    db $ed, $00, $80, $ea, $0c, $23, $ec, $02, $d3, $93, $c0, $dc, $93, $e5, $91, $90
    db $a0, $e4, $05, $01, $e5, $91, $e4, $01, $21, $41, $51, $71, $97, $ff
MusicSequenceData_763a::
    db $ec, $02, $e8, $ea, $0a, $24, $d3, $a3, $c0, $dc, $a3, $e4, $51, $50, $50, $55
    db $51, $71, $91, $a2, $e3, $00, $21, $41, $57, $ff
MusicSequenceData_7654::
    db $d3, $10, $c0, $dc, $10, $e5, $51, $50, $40, $55, $01, $21, $41, $52, $70, $91
    db $71, $53, $c3, $ff
MusicSequenceData_7668::
    db $ed, $00, $80, $e8, $ea, $09, $24, $ec, $02
MusicSequenceData_7671::
    db $dc, $b3, $fd, $90, $76, $cf, $cf, $cf, $cf, $fd, $90, $76, $dc, $93, $fd, $d5
    db $76, $dc, $b3, $fd, $90, $76, $dc, $93, $fd, $f4, $76, $fe, $00, $71, $76
MusicSequenceData_7690::
    db $e4, $02, $e5, $90, $e4, $01, $53, $43, $21, $43, $7b, $e5, $a2, $70, $e4, $01
    db $43, $23, $41, $53, $0b, $ff
MusicSequenceData_76a6::
    db $ec, $02, $ea, $0b, $23
MusicSequenceData_76ab::
    db $dc, $c2, $fd, $d5, $76, $dc, $c1, $e6, $53, $03, $23, $43, $73, $03, $23, $03
    db $43, $03, $23, $43, $53, $03, $23, $43, $dc, $c2, $fd, $d5, $76, $fd, $d5, $76
    db $fd, $02, $77, $fd, $f4, $76, $fe, $00, $ab, $76
MusicSequenceData_76d5::
    db $e4, $52, $90, $e3, $01, $23, $03, $e4, $91, $a3, $e3, $01, $e4, $00, $e5, $b0
    db $e4, $01, $e5, $a1, $73, $e4, $42, $70, $91, $a3, $93, $71, $93, $5b, $ff
MusicSequenceData_76f4::
    db $cf, $c5, $e4, $00, $e5, $b0, $e4, $01, $e5, $a1, $73, $cf, $cf, $ff
MusicSequenceData_7702::
    db $e4, $52, $90, $e3, $01, $23, $03, $e4, $91, $a3, $e3, $01, $c9, $e4, $42, $70
    db $91, $a3, $93, $71, $93, $5b, $ff
MusicSequenceData_7719::
    db $dc, $10, $fd, $60, $77, $e3, $50, $c1, $90, $e2, $00, $c0, $20, $c2, $00, $c2
    db $e3, $90, $c0, $a0, $c2, $e2, $00, $c0, $e3, $00, $e4, $b0, $e3, $00, $c0, $e4
    db $a0, $c0, $70, $c2, $e3, $40, $c1, $70, $90, $c0, $a0, $c2, $90, $c2, $70, $c0
    db $90, $c2, $50, $ca, $cf, $cf, $cf, $cf, $cf, $cf, $cf, $cf, $cf, $cf, $cf, $cf
    db $fd, $60, $77, $fe, $00, $19, $77
MusicSequenceData_7760::
    db $e4, $50, $c2, $00, $c2, $20, $c2, $40, $c2, $70, $c2, $00, $c2, $20, $c2, $00
    db $c2, $40, $c2, $00, $c2, $20, $c2, $40, $c2, $50, $c2, $00, $c2, $20, $c2, $40
    db $c2, $ff
MusicSequenceData_7782::
    db $dc
MusicSequenceData_7783::
    db $fd, $9b, $77, $cf, $cf, $cf, $cf, $fd, $9b, $77, $cf, $cf, $cf, $cf, $fd, $ca
    db $77, $fd, $b6, $77, $fe, $00, $83, $77
MusicSequenceData_779b::
    db $b3, $0e, $b1, $03, $b1, $03, $b3, $0e, $b3, $03, $b1, $0e, $b1, $03, $b1, $03
    db $b1, $03, $b3, $0e, $b3, $03, $fe, $02, $9b, $77, $ff
MusicSequenceData_77b6::
    db $b3, $0e, $c1, $c1, $b3, $0e, $c3, $b1, $0e, $c1, $c1, $c1, $b3, $0e, $c3
MusicSequenceData_77c5::
    db $fe, $02, $b6, $77, $ff
MusicSequenceData_77ca::
    db $c3, $b1, $03, $b1, $03, $c3, $b3, $03, $c1, $b1, $03, $b1, $03, $b1, $03, $c3
    db $b3, $03, $fe, $02, $ca, $77, $ff
MusicSequenceData_77e1::
    db $ed, $00, $80, $ea, $0c, $24, $ec, $02, $dc, $b3
MusicSequenceData_77eb::
    db $fd, $06, $78, $cf, $cf, $cf, $cf, $fd, $06, $78, $dc, $93, $fd, $4c, $78, $fd
    db $6b, $78, $dc, $b3, $fd, $06, $78, $fe, $00, $eb, $77
MusicSequenceData_7806::
    db $e4, $02, $e5, $90, $e4, $01, $53, $43, $21, $43, $7b, $e5, $a2, $70, $e4, $01
    db $43, $23, $41, $53, $0b, $ff
MusicSequenceData_781c::
    db $e8, $ec, $02, $ea, $0a, $23
MusicSequenceData_7822::
    db $dc, $c2, $fd, $4c, $78, $dc, $c1, $e6, $53, $03, $23, $43, $73, $03, $23, $03
    db $43, $03, $23, $43, $53, $03, $23, $43, $dc, $c2, $fd, $4c, $78, $fd, $4c, $78
    db $fd, $6b, $78, $fd, $79, $78, $fe, $00, $22, $78
MusicSequenceData_784c::
    db $e4, $52, $90, $e3, $01, $23, $03, $e4, $91, $a3, $e3, $01, $e4, $00, $e5, $b0
    db $e4, $01, $e5, $a1, $73, $e4, $42, $70, $91, $a3, $93, $71, $93, $5b, $ff
MusicSequenceData_786b::
    db $cf, $c5, $e4, $00, $e5, $b0, $e4, $01, $e5, $a1, $73, $cf, $cf, $ff
MusicSequenceData_7879::
    db $e4, $52, $90, $e3, $01, $23, $03, $e4, $91, $a3, $e3, $01, $c9, $e4, $42, $70
    db $91, $a3, $93, $71, $93, $5b, $ff
MusicSequenceData_7890::
    db $dc, $10, $fd, $d7, $78, $e3, $50, $c1, $90, $e2, $00, $c0, $20, $c2, $00, $c2
    db $e3, $90, $c0, $a0, $c2, $e2, $00, $c0, $e3, $00, $e4, $b0, $e3, $00, $c0, $e4
    db $a0, $c0, $70, $c2, $e3, $40, $c1, $70, $90, $c0, $a0, $c2, $90, $c2, $70, $c0
    db $90, $c2, $50, $ca, $cf, $cf, $cf, $cf, $cf, $cf, $cf, $cf, $fd, $d7, $78, $cf
    db $cf, $cf, $cf, $fe, $00, $90, $78
MusicSequenceData_78d7::
    db $e4, $50, $c2, $00, $c2, $20, $c2, $40, $c2, $70, $c2, $00, $c2, $20, $c2, $00
    db $c2, $40, $c2, $00, $c2, $20, $c2, $40, $c2, $50, $c2, $00, $c2, $20, $c2, $40
    db $c2, $ff
MusicSequenceData_78f9::
    db $dc
MusicSequenceData_78fa::
    db $fd, $12, $79, $cf, $cf, $cf, $cf, $fd, $12, $79, $cf, $cf, $cf, $cf, $fd, $2d
    db $79, $fd, $41, $79, $fe, $00, $fa, $78
MusicSequenceData_7912::
    db $b3, $0e, $b1, $03, $b1, $03, $b3, $0e, $b3, $03, $b1, $0e, $b1, $03, $b1, $03
    db $b1, $03, $b3, $0e, $b3, $03, $fe, $02, $12, $79, $ff
MusicSequenceData_792d::
    db $b3, $0e, $c1, $c1, $b3, $0e, $c3, $b1, $0e, $c1, $c1, $c1, $b3, $0e, $c3, $fe
    db $02, $2d, $79, $ff
MusicSequenceData_7941::
    db $c3, $b1, $03, $b1, $03, $c3, $b3, $03, $c1, $b1, $03, $b1, $03, $b1, $03, $c3
    db $b3, $03, $fe, $02, $41, $79, $ff
MusicSequenceData_7958::
    db $ed, $00, $90, $f0, $77, $ec, $02, $d4, $b1, $c0, $e8, $d8, $b1
MusicSequenceData_7965::
    db $e4, $02, $00, $00, $00, $41, $01, $41, $71, $41, $71, $e3, $03, $01, $e4, $42
    db $40, $40, $40, $71, $41, $71, $e3, $01, $e4, $71, $e3, $01, $43, $41, $02, $00
    db $00, $00, $e4, $71, $e3, $01, $e4, $71, $e3, $01, $e4, $71, $41, $03, $01, $43
    db $41, $73, $71, $e3, $03, $01, $e4, $73, $71, $73, $71, $e3, $03, $01, $43, $41
    db $03, $01, $01, $01, $01, $45, $01, $01, $01, $45, $e4, $71, $71, $71, $e3, $05
    db $e4, $71, $71, $71, $e3, $05, $fe, $00, $65, $79
MusicSequenceData_79bf::
    db $ec, $02, $d8, $c1
MusicSequenceData_79c3::
    db $e4, $02, $00, $00, $00, $41, $01, $41, $71, $41, $71, $e3, $03, $01, $e4, $42
    db $40, $40, $40, $71, $41, $71, $e3, $01, $e4, $71, $e3, $01, $43, $41, $02, $00
    db $00, $00, $e4, $71, $e3, $01, $e4, $71, $e3, $01, $e4, $71, $41, $03, $01, $43
    db $41, $73, $71, $e3, $03, $01, $e4, $73, $71, $73, $71, $e3, $03, $01, $43, $41
    db $03, $01, $01, $01, $01, $45, $01, $01, $01, $45, $e4, $71, $71, $71, $e3, $05
    db $e4, $71, $71, $71, $e3, $05, $fe, $00, $c3, $79
MusicSequenceData_7a1d::
    db $ed, $00, $90, $f0, $77, $ec, $02, $d4, $b1, $c0, $e8, $dc, $c1, $cf
MusicSequenceData_7a2b::
    db $d8, $b1, $e4, $02, $00, $00, $00, $41, $01, $41, $71, $41, $71, $e3, $03, $01
    db $e4, $42, $40, $40, $40, $71, $41, $71, $e3, $01, $e4, $71, $e3, $01, $43, $41
    db $02, $00, $00, $00, $e4, $71, $e3, $01, $e4, $71, $e3, $01, $e4, $71, $41, $03
    db $01, $43, $41, $73, $71, $e3, $03, $01, $e4, $73, $71, $73, $71, $e3, $03, $01
    db $43, $41, $03, $01, $01, $01, $01, $45, $01, $01, $01, $45, $e4, $71, $71, $71
    db $e3, $05, $e4, $71, $71, $71, $e3, $05, $fe, $00, $2b, $7a
MusicSequenceData_7a87::
    db $ec, $02, $dc, $c1, $cf
MusicSequenceData_7a8c::
    db $d8, $c1, $e4, $02, $00, $00, $00, $41, $01, $41, $71, $41, $71, $e3, $03, $01
    db $e4, $42, $40, $40, $40, $71, $41, $71, $e3, $01, $e4, $71, $e3, $01, $43, $41
    db $02, $00, $00, $00, $e4, $71, $e3, $01, $e4, $71, $e3, $01, $e4, $71, $41, $03
    db $01, $43, $41, $73, $71, $e3, $03, $01, $e4, $73, $71, $73, $71, $e3, $03, $01
    db $43, $41, $03, $01, $01, $01, $01, $45, $01, $01, $01, $45, $e4, $71, $71, $71
    db $e3, $05, $e4, $71, $71, $71, $e3, $05, $fe, $00, $8c, $7a
MusicSequenceData_7ae8::
    db $ed, $00, $90, $f0, $77, $ec, $03, $e8, $ea, $05, $25, $dc, $b1, $e5, $70, $50
    db $40, $20, $01, $e6, $b1, $91, $e5, $41, $e6, $71, $e5, $21, $01, $e6, $b1, $91
    db $71, $43, $e7, $73, $ff
MusicSequenceData_7b0d::
    db $ec, $02, $ea, $06, $26, $dc, $c2, $e4, $01, $e5, $b1, $91, $71, $40, $50, $71
    db $20, $40, $51, $41, $21, $01, $e6, $b1, $e5, $03, $dc, $b1, $e6, $03, $ff
MusicSequenceData_7b2c::
    db $dc, $10, $cf, $e6, $90, $b0, $e5, $01, $00, $20, $41, $01, $c1, $e6, $01, $c1
    db $ff
MusicSequenceData_7b3d::
    db $ed, $00, $80, $f0, $77, $ec, $02, $e8, $ea, $01, $23, $dc, $b1, $e5, $b0, $e4
    db $84, $90, $81, $60, $41, $30, $e5, $b1, $90, $81, $90, $b2, $dc, $b2, $e4, $89
    db $ff
MusicSequenceData_7b5e::
    db $ec, $02, $ea, $00, $24, $dc, $c2, $e4, $40, $b4, $e3, $10, $e4, $b1, $90, $81
    db $60, $41, $60, $81, $60, $42, $dc, $c3, $e3, $49, $ff
MusicSequenceData_7b79::
    db $ed, $00, $80, $f0, $77, $ec, $02, $e8, $dc, $b1, $c0, $c0, $c0, $e4, $70, $70
    db $70, $dc, $b4, $e3, $0f, $ff
MusicSequenceData_7b8f::
    db $ec, $02, $dc, $c1, $e4, $00, $40, $70, $e3, $00, $00, $00, $dc, $c4, $4f, $ff
MusicSequenceData_7b9f::
    db $ed, $00, $80, $f0, $77, $ec, $02, $e8, $dc, $b1, $e5, $eb, $00, $40, $00, $c2
    db $e5, $eb, $00, $47, $70, $c2, $e6, $eb, $00, $50, $00, $c2, $e6, $eb, $00, $57
    db $70, $c2, $ff
MusicSequenceData_7bc2::
    db $ec, $02, $dc, $c1, $e4, $eb, $00, $50, $00, $c2, $e4, $eb, $00, $57, $70, $c2
    db $e5, $eb, $00, $60, $00, $c2, $e5, $eb, $00, $67, $70, $c2, $ff
MusicSequenceData_7bdf::
    db $f8, $ec, $02, $d4, $e1, $e2, $20, $00, $e3, $b0, $90, $ff, $f8, $ec, $02, $d4
    db $e1, $e3, $50, $90, $e2, $00, $dc, $e3, $5f, $ff, $f8, $dc, $10, $e3, $eb, $00
    db $65, $53, $ff
TickBgmPreviewTimer::
    ld hl, BGM_PREVIEW_TIMER
    dec [hl]
    ret nz

    ret


CheckGameStateUpdate::
    ld hl, GAME_STATE
    ld a, [hl]
    cp GAME_STATE_PLAYING
    jp z, ToggleFieldAnim

    ld a, [OPTION_BGM]
    add $09
    swap a
    ld l, a
    ld h, $c2
    inc l
    inc l
    inc l
    ld a, [hl]
    xor $10
    ld [hl], a
    ld a, [MENU_CURSOR]
    cp $03
    ret nz

    ld a, [hl]
    dec l
    ld [hl], a
    ret

SoundIndexTable::
SoundIndexEntry_00::
    db $ff
    dw $ffff
SoundIndexEntry_01::
    db $07
    dw SoundSequenceData_7d85
SoundIndexEntry_02::
    db $07
    dw SoundSequenceData_7d89
SoundIndexEntry_03::
    db $07
    dw SoundSequenceData_7d8d
SoundIndexEntry_04::
    db $07
    dw SoundSequenceData_7d91
SoundIndexEntry_05::
    db $07
    dw SoundSequenceData_7d95
SoundIndexEntry_06::
    db $07
    dw SoundSequenceData_7d99
SoundIndexEntry_07::
    db $07
    dw SoundSequenceData_7d9d
SoundIndexEntry_08::
    db $07
    dw SoundSequenceData_7da1
SoundIndexEntry_09::
    db $07
    dw SoundSequenceData_7da5
SoundIndexEntry_0a::
    db $07
    dw SoundSequenceData_7da9
SoundIndexEntry_0b::
    db $07
    dw SoundSequenceData_7dad
SoundIndexEntry_0c::
    db $07
    dw SoundSequenceData_7db1
SoundIndexEntry_0d::
    db $07
    dw SoundSequenceData_7db5
SoundIndexEntry_0e::
    db $07
    dw SoundSequenceData_7db9
SoundIndexEntry_0f::
    db $44
    dw SoundSequenceData_7fd0
SoundIndexEntry_10::
    db $05
    dw SoundSequenceData_7fe3
SoundIndexEntry_11::
    db $04
    dw MusicSequenceData_7bdf
SoundIndexEntry_12::
    db $c4
    dw SoundSequenceData_7ef6
SoundIndexEntry_13::
    db $05
    dw SoundSequenceData_7f0d
SoundIndexEntry_14::
    db $06
    dw SoundSequenceData_7f1b
SoundIndexEntry_15::
    db $07
    dw SoundSequenceData_7f1c
SoundIndexEntry_16::
    db $c4
    dw SoundSequenceData_7f9d
SoundIndexEntry_17::
    db $05
    dw SoundSequenceData_7fb4
SoundIndexEntry_18::
    db $06
    dw SoundSequenceData_7fc2
SoundIndexEntry_19::
    db $07
    dw SoundSequenceData_7fc3
SoundIndexEntry_1a::
    db $04
    dw SoundSequenceData_7f29
SoundIndexEntry_DropStart::
SoundIndexEntry_1b::
    db $04
    dw SoundSequenceData_7e2c
SoundIndexEntry_1c::
    db $04
    dw SoundSequenceData_7e5c
SoundIndexEntry_1d::
    db $44
    dw SoundSequenceData_7eb4
SoundIndexEntry_1e::
    db $05
    dw SoundSequenceData_7ec7
SoundIndexEntry_1f::
    db $04
    dw SoundSequenceData_7ea9
SoundIndexEntry_20::
    db $04
    dw SoundSequenceData_7e9e
SoundIndexEntry_21::
    db $04
    dw SoundSequenceData_7e93
SoundIndexEntry_22::
    db $04
    dw SoundSequenceData_7e88
SoundIndexEntry_23::
    db $04
    dw SoundSequenceData_7e7d
SoundIndexEntry_24::
    db $04
    dw SoundSequenceData_7e72
SoundIndexEntry_25::
    db $04
    dw SoundSequenceData_7e67
SoundIndexEntry_CommitPiece::
SoundIndexEntry_26::
    db $04
    dw SoundSequenceData_7e4b
SoundIndexEntry_PieceLand::
SoundIndexEntry_27::
    db $04
    dw SoundSequenceData_7eda
SoundIndexEntry_CursorMove::
SoundIndexEntry_28::
    db $04
    dw SoundSequenceData_7eeb
SoundIndexEntry_29::
    db $44
    dw SoundSequenceData_7f65
SoundIndexEntry_2a::
    db $05
    dw SoundSequenceData_7f80
SoundIndexEntry_2b::
    db $04
    dw SoundSequenceData_7f34
SoundIndexEntry_2c::
    db $04
    dw SoundSequenceData_7f43
SoundIndexEntry_RoundComplete::
SoundIndexEntry_2d::
    db $04
    dw SoundSequenceData_7f52
SoundIndexEntry_Pause::
SoundIndexEntry_2e::
    db $44
    dw SoundSequenceData_7dff
SoundIndexEntry_2f::
    db $05
    dw SoundSequenceData_7e15
SoundIndexEntry_TitleBgm::
SoundIndexEntry_30::
    db $c0
    dw SoundSequenceData_569a
SoundIndexEntry_31::
    db $01
    dw SoundSequenceData_5764
SoundIndexEntry_32::
    db $02
    dw SoundSequenceData_580b
SoundIndexEntry_33::
    db $03
    dw SoundSequenceData_5a6f
SoundIndexEntry_BgmOption0::
SoundIndexEntry_34::
    db $c0
    dw SoundSequenceData_5ad4
SoundIndexEntry_35::
    db $01
    dw SoundSequenceData_5ccf
SoundIndexEntry_36::
    db $02
    dw SoundSequenceData_5f1f
SoundIndexEntry_37::
    db $03
    dw MusicSequenceData_60c0
SoundIndexEntry_BgmPreview0::
SoundIndexEntry_38::
    db $c0
    dw SoundSequenceData_5af3
SoundIndexEntry_39::
    db $01
    dw SoundSequenceData_5ce5
SoundIndexEntry_3a::
    db $02
    dw SoundSequenceData_5f2e
SoundIndexEntry_3b::
    db $03
    dw MusicSequenceData_60c5
SoundIndexEntry_BgmOption1::
SoundIndexEntry_3c::
    db $c0
    dw MusicSequenceData_6170
SoundIndexEntry_3d::
    db $01
    dw MusicSequenceData_625c
SoundIndexEntry_3e::
    db $02
    dw MusicSequenceData_63e3
SoundIndexEntry_3f::
    db $03
    dw MusicSequenceData_64d1
SoundIndexEntry_BgmPreview1::
SoundIndexEntry_40::
    db $c0
    dw MusicSequenceData_6183
SoundIndexEntry_41::
    db $01
    dw MusicSequenceData_6273
SoundIndexEntry_42::
    db $02
    dw MusicSequenceData_63eb
SoundIndexEntry_43::
    db $03
    dw MusicSequenceData_64d5
SoundIndexEntry_BgmOption2::
SoundIndexEntry_44::
    db $c0
    dw MusicSequenceData_6586
SoundIndexEntry_45::
    db $01
    dw MusicSequenceData_66e3
SoundIndexEntry_46::
    db $02
    dw MusicSequenceData_68b5
SoundIndexEntry_47::
    db $03
    dw MusicSequenceData_6b16
SoundIndexEntry_BgmPreview2::
SoundIndexEntry_48::
    db $c0
    dw MusicSequenceData_65ac
SoundIndexEntry_49::
    db $01
    dw MusicSequenceData_66f9
SoundIndexEntry_4a::
    db $02
    dw MusicSequenceData_68c1
SoundIndexEntry_4b::
    db $03
    dw MusicSequenceData_6b19
SoundIndexEntry_LinkMaster::
SoundIndexEntry_4c::
    db $c0
    dw MusicSequenceData_6cc8
SoundIndexEntry_4d::
    db $01
    dw MusicSequenceData_6db3
SoundIndexEntry_4e::
    db $02
    dw MusicSequenceData_6f7d
SoundIndexEntry_4f::
    db $03
    dw MusicSequenceData_71d2
SoundIndexEntry_LinkSlave::
SoundIndexEntry_50::
    db $c0
    dw MusicSequenceData_6cc8
SoundIndexEntry_51::
    db $01
    dw MusicSequenceData_6dc6
SoundIndexEntry_52::
    db $02
    dw MusicSequenceData_6f7e
SoundIndexEntry_53::
    db $03
    dw MusicSequenceData_71e2
SoundIndexEntry_Confirm::
SoundIndexEntry_54::
    db $c0
    dw MusicSequenceData_753e
SoundIndexEntry_55::
    db $01
    dw MusicSequenceData_7562
SoundIndexEntry_56::
    db $02
    dw MusicSequenceData_7580
SoundIndexEntry_57::
    db $03
    dw MusicSequenceData_759c
SoundIndexEntry_58::
    db $80
    dw MusicSequenceData_75d9
SoundIndexEntry_59::
    db $01
    dw MusicSequenceData_75f5
SoundIndexEntry_5a::
    db $02
    dw MusicSequenceData_760b
SoundIndexEntry_5b::
    db $80
    dw MusicSequenceData_761c
SoundIndexEntry_5c::
    db $01
    dw MusicSequenceData_763a
SoundIndexEntry_5d::
    db $02
    dw MusicSequenceData_7654
SoundIndexEntry_5e::
    db $c0
    dw MusicSequenceData_7668
SoundIndexEntry_5f::
    db $01
    dw MusicSequenceData_76a6
SoundIndexEntry_60::
    db $02
    dw MusicSequenceData_7719
SoundIndexEntry_61::
    db $03
    dw MusicSequenceData_7782
SoundIndexEntry_62::
    db $c0
    dw MusicSequenceData_77e1
SoundIndexEntry_63::
    db $01
    dw MusicSequenceData_781c
SoundIndexEntry_64::
    db $02
    dw MusicSequenceData_7890
SoundIndexEntry_65::
    db $03
    dw MusicSequenceData_78f9
SoundIndexEntry_66::
    db $80
    dw MusicSequenceData_7ae8
SoundIndexEntry_67::
    db $01
    dw MusicSequenceData_7b0d
SoundIndexEntry_68::
    db $02
    dw MusicSequenceData_7b2c
SoundIndexEntry_69::
    db $40
    dw MusicSequenceData_7b3d
SoundIndexEntry_6a::
    db $01
    dw MusicSequenceData_7b5e
SoundIndexEntry_6b::
    db $40
    dw MusicSequenceData_7958
SoundIndexEntry_6c::
    db $01
    dw MusicSequenceData_79bf
SoundIndexEntry_6d::
    db $40
    dw MusicSequenceData_7a1d
SoundIndexEntry_6e::
    db $01
    dw MusicSequenceData_7a87
SoundIndexEntry_6f::
    db $40
    dw MusicSequenceData_7b79
SoundIndexEntry_70::
    db $01
    dw MusicSequenceData_7b8f
SoundIndexEntry_71::
    db $40
    dw MusicSequenceData_7b9f
SoundIndexEntry_72::
    db $01
    dw MusicSequenceData_7bc2

SoundSequenceData_7d85::
    db $20, $a1, $98, $ff
SoundSequenceData_7d89::
    db $20, $a1, $23, $ff
SoundSequenceData_7d8d::
    db $20, $a1, $33, $ff
SoundSequenceData_7d91::
    db $20, $a1, $13, $ff
SoundSequenceData_7d95::
    db $20, $a1, $32, $ff
SoundSequenceData_7d99::
    db $20, $81, $32, $ff
SoundSequenceData_7d9d::
    db $20, $61, $22, $ff
SoundSequenceData_7da1::
    db $20, $a3, $13, $ff
SoundSequenceData_7da5::
    db $20, $a1, $43, $ff
SoundSequenceData_7da9::
    db $20, $91, $32, $ff
SoundSequenceData_7dad::
    db $20, $51, $32, $ff
SoundSequenceData_7db1::
    db $20, $41, $32, $ff
SoundSequenceData_7db5::
    db $20, $31, $32, $ff
SoundSequenceData_7db9::
    db $20, $71, $44, $ff

WavePatternPointerTable::
    dw WavePatternData_7dcf
    dw WavePatternData_7ddf
    dw WavePatternData_7def
    dw WavePatternData_7dff
    dw WavePatternData_7dff
    dw WavePatternData_7dff
    dw WavePatternData_7dff
    dw WavePatternData_7dff
    dw WavePatternData_7dff

WavePatternData_7dcf::
    db $02, $46, $8a, $ce, $ff, $fe, $ed, $dc, $cb, $a9, $87, $65, $44, $33, $22, $11
WavePatternData_7ddf::
    db $bb, $ff, $ff, $ff, $ff, $ff, $ff, $bb, $44, $00, $00, $00, $00, $00, $00, $44
WavePatternData_7def::
    db $01, $12, $34, $57, $9b, $df, $fe, $dc, $ba, $98, $76, $54, $43, $32, $21, $11
WavePatternData_7dff::
SoundSequenceData_7dff::
    db $ed, $01, $00, $ec, $02, $24, $f4, $00, $07, $21, $a1, $40, $07, $22, $c1, $80
    db $07, $28, $a2, $c0, $07, $ff
SoundSequenceData_7e15::
    db $ec, $01, $21, $21, $c0, $06, $24, $d4, $00, $07, $21, $81, $40, $07, $22, $a1
    db $80, $07, $28, $82, $c0, $07, $ff
SoundSequenceData_7e2c::
    db $ec, $02, $20, $42, $00, $05, $20, $92, $80, $06, $20, $d2, $00, $07, $20, $f2
    db $80, $07, $20, $d2, $00, $07, $20, $92, $80, $06, $2a, $41, $00, $05, $ff
SoundSequenceData_7e4b::
    db $ec, $02, $10, $3a, $24, $f2, $00, $04, $10, $23, $28, $f2, $00, $06, $10, $08
    db $ff
SoundSequenceData_7e5c::
    db $ec, $00, $10, $22, $24, $f2, $00, $03, $10, $08, $ff
SoundSequenceData_7e67::
    db $ec, $02, $10, $2d, $26, $f1, $c0, $07, $10, $08, $ff
SoundSequenceData_7e72::
    db $ec, $02, $10, $2d, $26, $f1, $a0, $07, $10, $08, $ff
SoundSequenceData_7e7d::
    db $ec, $02, $10, $2d, $26, $f1, $80, $07, $10, $08, $ff
SoundSequenceData_7e88::
    db $ec, $02, $10, $2d, $26, $f1, $60, $07, $10, $08, $ff
SoundSequenceData_7e93::
    db $ec, $02, $10, $2d, $26, $f1, $40, $07, $10, $08, $ff
SoundSequenceData_7e9e::
    db $ec, $02, $10, $2d, $26, $f1, $20, $07, $10, $08, $ff
SoundSequenceData_7ea9::
    db $ec, $02, $10, $2d, $26, $f1, $00, $07, $10, $08, $ff
SoundSequenceData_7eb4::
    db $ec, $02, $20, $c1, $80, $07, $21, $f1, $a0, $07, $21, $c1, $c0, $07, $24, $f1
    db $e0, $07, $ff
SoundSequenceData_7ec7::
    db $ec, $02, $20, $91, $81, $07, $21, $d1, $a1, $07, $21, $91, $c1, $07, $24, $d1
    db $e1, $07, $ff
SoundSequenceData_7eda::
    db $ec, $01, $10, $26, $28, $f1, $40, $07, $10, $36, $24, $e1, $c0, $07, $10, $08
    db $ff
SoundSequenceData_7eeb::
    db $ec, $01, $10, $15, $24, $a1, $40, $07, $10, $08, $ff
SoundSequenceData_7ef6::
    db $ec, $03, $10, $17, $24, $f1, $c0, $06, $10, $16, $2f, $f1, $c0, $07, $10, $1d
    db $24, $f1, $00, $04, $10, $08, $ff
SoundSequenceData_7f0d::
    db $ec, $02, $24, $d1, $80, $06, $2f, $a1, $c0, $07, $24, $c1, $80, $03
SoundSequenceData_7f1b::
    db $ff
SoundSequenceData_7f1c::
    db $21, $d1, $38, $2e, $d1, $28, $21, $d1, $39, $24, $d1, $49, $ff
SoundSequenceData_7f29::
    db $ec, $02, $10, $36, $28, $f1, $00, $07, $10, $08, $ff
SoundSequenceData_7f34::
    db $ec, $02, $10, $14, $28, $71, $80, $06, $28, $41, $00, $07, $10, $08, $ff
SoundSequenceData_7f43::
    db $ec, $02, $10, $14, $28, $d1, $80, $06, $28, $a1, $00, $07, $10, $08, $ff
SoundSequenceData_7f52::
    db $ec, $02, $10, $36, $24, $f4, $80, $07, $23, $c1, $c0, $07, $24, $d1, $a0, $07
    db $10, $08, $ff
SoundSequenceData_7f65::
    db $ec, $02, $22, $c4, $30, $02, $22, $c4, $40, $02, $23, $c1, $60, $02, $2f, $00
    db $00, $00, $f8, $dc, $f1, $e5, $eb, $00, $60, $f0, $ff
SoundSequenceData_7f80::
    db $ec, $03, $22, $83, $31, $03, $22, $83, $41, $03, $23, $81, $61, $03, $2f, $00
    db $00, $00, $ec, $02, $f8, $dc, $d1, $e5, $eb, $00, $60, $f0, $ff
SoundSequenceData_7f9d::
    db $ec, $03, $10, $15, $27, $f4, $c0, $02, $10, $13, $2a, $f2, $c0, $03, $10, $1b
    db $2c, $f2, $00, $03, $10, $08, $ff
SoundSequenceData_7fb4::
    db $ec, $02, $24, $d1, $80, $02, $2f, $a1, $c0, $03, $24, $c1, $80, $02
SoundSequenceData_7fc2::
    db $ff
SoundSequenceData_7fc3::
    db $24, $b2, $48, $2e, $c1, $38, $21, $81, $49, $28, $82, $59, $ff
SoundSequenceData_7fd0::
    db $ec, $02, $23, $d1, $c0, $07, $23, $d1, $80, $07, $23, $d1, $c0, $07, $23, $d1
    db $80, $07, $ff
SoundSequenceData_7fe3::
    db $ec, $02, $23, $a1, $c1, $07, $23, $a1, $81, $07, $23, $a1, $c1, $07, $23, $a1
    db $81, $07, $ff, $00, $39, $00, $39, $00, $39, $00, $39, $00, $39
