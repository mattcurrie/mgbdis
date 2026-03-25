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
    ldh [$ff8f], a

jr_001_4011:
    ldh [$ff8e], a
    ld d, $c2
    ld e, a
    ld a, [de]
    and a
    jr z, jr_001_407b

    and $80
    ldh [$ff92], a
    ld a, [de]
    dec a
    ld hl, $40a0
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
    ldh [$ff91], a
    inc e
    inc e
    ld a, [de]
    ldh [$ff90], a
    ldh a, [$ff8f]
    ld e, a
    ld d, $c4

jr_001_4052:
    ldh a, [$ff91]
    add $10
    add [hl]
    ld [de], a
    inc hl
    inc e
    ldh a, [$ff90]
    add $08
    add [hl]
    ld [de], a
    inc hl
    inc e
    ld a, [bc]
    inc bc
    ld [de], a
    inc e
    ld a, [hl]
    bit 1, a
    jr z, jr_001_406e

    ldh a, [$ff92]
    or [hl]

jr_001_406e:
    inc hl
    ld [de], a
    inc e
    bit 0, a
    jr z, jr_001_4052

    ld a, e
    ldh [$ff8f], a
    cp $a0
    ret z

jr_001_407b:
    ldh a, [$ff8e]
    add $10
    cp $00
    jr nz, jr_001_4011

    ldh a, [$ff8f]
    ld l, a
    ld h, $c4
    ld de, $0004
    ld a, $98

jr_001_408d:
    cp l
    ret z

    ld [hl], $a0
    add hl, de
    jr jr_001_408d

InitSpriteBuffer::
    ld hl, $c200

jr_001_4097:
    xor a
    ld [hl], a
    ld a, l
    add $10
    ld l, a
    jr nc, jr_001_4097

    ret


    ld a, [$1a40]
    ld b, c
    ld a, [hl]
    ld b, c
    jp nc, $ae41

    ld b, b
    ldh [c], a
    ld b, c
    ld [$3341], a
    ld b, d
    cp a
    ld b, d
    scf
    ld b, d
    cp a
    ld b, d
    dec sp
    ld b, d
    cp a
    ld b, d
    inc sp
    ld b, d
    cp a
    ld b, d
    scf
    ld b, d
    cp a
    ld b, d
    dec sp
    ld b, d
    cp a
    ld b, d
    inc sp
    ld b, d
    cp a
    ld b, d
    scf
    ld b, d
    cp a
    ld b, d
    dec sp
    ld b, d
    cp a
    ld b, d
    inc sp
    ld b, d
    cp a
    ld b, d
    scf
    ld b, d
    cp a
    ld b, d
    dec sp
    ld b, d
    cp a
    ld b, d
    inc sp
    ld b, d
    cp a
    ld b, d
    inc sp

Jump_001_40e3:
    ld b, d

Jump_001_40e4:
    cp a

Jump_001_40e5:
    ld b, d
    inc sp
    ld b, d
    cp a
    ld b, d
    inc sp
    ld b, d
    cp a
    ld b, d
    dec [hl]
    ld b, d
    cp a
    ld b, d
    add hl, sp
    ld b, d
    cp a
    ld b, d
    dec a
    ld b, d
    cp a
    ld b, d
    ld c, $42
    bit 0, d
    inc d
    ld b, d
    db $dd
    ld b, d
    jr jr_001_4146

    db $dd
    ld b, d
    inc e
    ld b, d
    db $dd
    ld b, d
    jr nz, jr_001_414e

    bit 0, d
    inc e
    ld b, d
    jp hl


    ld b, d
    jr jr_001_4156

    jp hl


    ld b, d
    inc d
    ld b, d
    jp hl


    ld b, d
    and a
    ld b, d
    cp a
    ld b, d
    and a
    ld b, d
    push bc
    ld b, d
    xor c
    ld b, d
    push bc
    ld b, d
    xor e
    ld b, d
    push bc
    ld b, d
    xor l
    ld b, d
    push bc
    ld b, d
    xor a
    ld b, d
    push bc
    ld b, d
    or c
    ld b, d
    push bc
    ld b, d
    or c
    ld b, d
    push bc
    ld b, d
    or e
    ld b, d
    push bc
    ld b, d
    and a
    ld b, d
    cp a
    ld b, d
    and a
    ld b, d
    cp a
    ld b, d

jr_001_4146:
    and a
    ld b, d
    cp a
    ld b, d
    and a
    ld b, d
    cp a
    ld b, d

jr_001_414e:
    and a
    ld b, d
    cp a
    ld b, d
    and a
    ld b, d
    cp a
    ld b, d

jr_001_4156:
    and a
    ld b, d
    cp a
    ld b, d
    and a
    ld b, d
    cp a
    ld b, d
    or l
    ld b, d
    push bc
    ld b, d
    or a
    ld b, d
    push bc
    ld b, d
    cp c
    ld b, d
    push bc
    ld b, d
    cp e
    ld b, d
    push bc
    ld b, d
    cp l
    ld b, d
    push bc
    ld b, d
    cp a
    ld b, d
    push bc
    ld b, d
    cp a
    ld b, d
    push bc
    ld b, d
    cp a
    ld b, d
    push bc
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ld b, l
    ld b, d
    ld l, e
    ld b, d
    ld c, e
    ld b, d
    ld [hl], c
    ld b, d
    ld d, l
    ld b, d
    ld a, l
    ld b, d
    ld h, e
    ld b, d
    adc a
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ccf
    ld b, d
    ld l, e
    ld b, d
    ld b, c
    ld b, d
    ld l, e
    ld b, d

SetupSpriteAnim::
    ld b, e
    ld b, d
    ld l, e
    ld b, d
    ld b, a
    ld b, d
    ld [hl], c
    ld b, d
    ld c, a
    ld b, d
    ld a, l
    ld b, d
    ld e, e
    ld b, d
    adc a
    ld b, d
    ld h, $42
    daa
    ld b, d
    ld h, $42
    ld a, [hl+]
    ld b, d
    ld h, $42
    dec l
    ld b, d
    ld h, $42
    jr nc, jr_001_4224

    or $41

Jump_001_41e4:
    db $fc
    ld b, c
    or $41
    dec b
    ld b, d
    xor $41
    ldh a, [rSTAT]
    ldh [SERIAL_TEMP], a
    nop
    ld [$0000], sp
    db $10
    ld hl, $dcda
    sbc $da
    call c, UpdateScore
    inc b
    nop
    db $10
    inc c
    nop
    db $10
    inc d
    nop
    nop
    inc b
    nop
    nop
    inc c
    nop
    nop
    inc d
    ld bc, $1e1c
    jr nz, jr_001_4232

    ld e, $1c
    inc h
    ld h, $28
    ld a, [hl+]
    inc l
    ld l, $30
    ld [hl-], a
    inc [hl]
    ld [hl], $38
    ld a, [hl-]
    inc a
    ld a, $40
    ld b, b

jr_001_4224:
    ld a, $3c
    add b
    ldh a, [$fff8]
    ld bc, $00f0
    ld hl, $f8f0
    ld b, c
    ldh a, [rP1]

jr_001_4232:
    ld h, c
    ld h, b
    ld h, d
    ld h, h
    ld h, [hl]
    ld l, b
    ld l, d
    ld l, h
    ld l, [hl]
    ld [hl], b
    ld [hl], d
    ld [hl], h
    db $76
    add d
    add h
    add [hl]
    adc b
    adc d
    adc h
    adc [hl]
    sub b
    sub d
    sub h
    sub [hl]
    sbc b
    sbc d
    sbc h
    sbc [hl]
    and b
    and d
    and h
    and [hl]
    xor b
    xor d
    xor h
    xor [hl]
    or b
    or d
    or h
    or [hl]
    cp b
    cp d
    cp h
    cp [hl]
    ret nz

    jp nz, $c6c4

    ret z

    jp z, $cecc

    ret nc

    jp nc, $d6d4

    ret c

    ldh a, [$fff8]
    nop
    ldh a, [rP1]
    ld bc, $f8e8
    nop
    ld hl, sp-$08
    nop
    add sp, $00
    nop
    ld hl, sp+$00
    ld bc, $f4e8
    nop
    ld hl, sp-$0c
    nop
    add sp, -$04
    nop
    ld hl, sp-$04
    nop
    add sp, $04
    nop
    ld hl, sp+$04
    ld bc, $f0e0
    nop
    ldh a, [$fff0]
    nop
    ldh [$fff8], a
    nop
    ldh a, [$fff8]
    nop
    ldh [rP1], a
    nop
    ldh a, [rP1]
    nop
    ldh [$ff08], a
    nop
    ldh a, [$ff08]
    ld bc, $0200
    inc b
    ld b, $08
    ld a, [bc]
    inc c
    ld c, $10
    ld [de], a
    jr jr_001_42cd

    inc d
    ld d, $4c
    ld c, [hl]
    ld d, b
    ld d, d
    ld d, h
    ld d, [hl]
    ld e, b
    ld e, d
    ld e, h
    ld e, [hl]
    nop
    ld [$0000], sp

ProcessSpriteFrame::
    db $10
    ld bc, $0800
    stop
    db $10
    ld de, $0800

jr_001_42cd:
    nop
    nop
    stop
    nop
    jr jr_001_42d4

jr_001_42d4:
    nop
    jr nz, @+$22

    nop
    jr z, jr_001_42fa

    nop
    jr nc, jr_001_42fe

    nop
    stop
    nop
    jr jr_001_42e3

jr_001_42e3:
    nop
    jr nz, jr_001_42e6

jr_001_42e6:
    nop
    jr z, jr_001_42ea

    nop

jr_001_42ea:
    jr z, jr_001_430e

    nop
    jr nz, jr_001_4311

    nop
    jr jr_001_4314

    nop
    db $10
    inc hl

UpdateAnimFrame::
    ld a, [TWO_PLAYER_FLAG]
    and a
    ret nz

jr_001_42fa:
    ld a, [PLAYER_MODE]
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


    ld a, [$c61d]
    add l
    daa
    ld [$c61d], a
    ld a, [$c61e]
    adc h
    daa
    ld [$c61e], a
    ld a, [$c61f]
    adc $00
    daa
    cp $10
    jr c, jr_001_4353

    ld a, $99
    ld [$c61d], a
    ld [$c61e], a
    ld a, $09

jr_001_4353:
    ld [$c61f], a
    ld hl, $c621
    ld a, [$c61f]
    ld [hl+], a
    ld a, [$c61e]
    swap a
    ld [hl+], a
    ld a, [$c61e]
    ld [hl+], a
    ld a, [$c61d]
    swap a
    ld [hl+], a
    ld a, [$c61d]
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
    call $234c
    call AnimateDropping
    call LoadGameBGTiles
    call FieldUpdate18
    call CheckPause2P
    ld a, [PLAYER_MODE]
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
    ld hl, $442c
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


    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ei
    db $fc
    ld c, d
    ld c, d
    ei
    db $fc
    ld c, d
    ld c, d
    ei
    db $fc
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
    ei
    db $fc
    ld c, d
    ld c, d
    ei
    db $fc
    ld c, d
    ld c, d
    ei
    db $fc
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
    ld c, d
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
    ld hl, $c6b7
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


    ld a, [PLAYER_MODE]
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

    ld a, [PLAYER_MODE]
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

    ld a, [PLAYER_MODE]
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
    ld a, $06
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

    ld a, [PLAYER_MODE]
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

    ld a, [PLAYER_MODE]
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
    ld a, [PLAYER_MODE]
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
    ld a, [PLAYER_MODE]
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
    ld a, [PLAYER_MODE]
    and a
    jr nz, jr_001_48cd

    ld hl, $0911
    jr jr_001_48d0

jr_001_48cd:
    ld hl, $0b11

jr_001_48d0:
    ld b, $02
    ld c, $3c
    ld a, [$c6b8]
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
    ld a, [PLAYER_MODE]
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
    ld a, [PLAYER_MODE]
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
    ld a, [PLAYER_MODE]
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
    ldh a, [VRAM_SRC_LO]
    and a
    ret z

    ld hl, sp+$00
    ld a, h
    ldh [$ffa7], a
    ld a, l
    ldh [$ffa8], a
    ldh a, [VRAM_SRC_HI]
    ld l, a
    ldh a, [VRAM_DST_LO]
    ld h, a
    ld sp, hl
    ldh a, [VRAM_DST_HI]
    ld l, a
    ldh a, [VRAM_LEN_LO]
    ld h, a
    ldh a, [VRAM_SRC_LO]
    ld b, a
    xor a
    ldh [VRAM_SRC_LO], a

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
    ldh [VRAM_DST_HI], a
    ld a, h
    ldh [VRAM_LEN_LO], a
    ld hl, sp+$00
    ld a, l
    ldh [VRAM_SRC_HI], a
    ld a, h
    ldh [VRAM_DST_LO], a
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
    call $ff80
    call TimerTickCore
    ld a, $01
    ld [$2100], a
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
    ld a, [$c002]
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
    ld hl, $c026
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_001_4cbf

    ld a, c
    cp $04
    jr nc, jr_001_4cbc

    ld a, [$c002]
    and a
    jr z, jr_001_4cbc

    bit 7, a
    jr nz, jr_001_4cbf

    set 7, a
    ld [$c002], a
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
    ld hl, $c0b6
    add hl, bc
    ld a, [hl]
    cp $01
    jp z, SoundSequenceStep

    dec a
    ld [hl], a
    ld a, c
    cp $04
    jr nc, jr_001_4ce2

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_001_4ce2

    ret


jr_001_4ce2:
    ld hl, $c02e
    add hl, bc
    bit 6, [hl]
    jr z, jr_001_4ced

    call SoundUpdate1

jr_001_4ced:
    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 4, [hl]
    jr z, jr_001_4cfa

    jp Jump_001_524c


jr_001_4cfa:
    ld hl, $c04e
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_001_4d04

    dec [hl]
    ret


jr_001_4d04:
    ld hl, $c056
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_001_4d0d

    ret


jr_001_4d0d:
    ld d, a
    ld hl, $c05e
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
    ld hl, $c066
    add hl, bc
    ld e, [hl]
    ld hl, $c02e
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
    ld hl, $c06e
    add hl, bc
    ld a, [hl]
    ld hl, $c04e
    add hl, bc
    ld [hl], a
    ld hl, $c02e
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
    ld hl, $c02e
    add hl, bc
    bit 1, [hl]
    jr nz, jr_001_4da2

    ld a, c
    cp $03
    jr nc, jr_001_4d7e

    jr jr_001_4dbd

jr_001_4d7e:
    res 2, [hl]
    ld hl, $c036
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

    ld a, [$c003]
    and a
    jr z, jr_001_4da0

    xor a
    ld [$c003], a
    jr jr_001_4dbd

jr_001_4da0:
    jr jr_001_4dc8

jr_001_4da2:
    res 1, [hl]
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, $c006
    add hl, de
    push hl
    ld hl, $c016
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
    ld hl, $5672
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a

jr_001_4dc8:
    ld a, [$c02a]
    cp $0f
    jr nc, jr_001_4dd1

    jr jr_001_4dee

jr_001_4dd1:
    ld a, [$c02a]
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
    ld a, [$c005]
    ldh [rNR50], a
    xor a
    ld [$c005], a

jr_001_4dee:
    ld hl, $c026
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
    ld hl, $c006
    add hl, de
    push hl
    ld hl, $c016
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
    ld hl, $c02e
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
    ld hl, $c0be
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
    ld hl, $c006
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
    ld hl, $c0c6
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

    ld hl, $c0e7
    jr jr_001_4e8f

jr_001_4e8c:
    ld hl, $c0e6

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
    ld hl, $c0de
    add hl, bc
    ld [hl], d

jr_001_4ea0:
    jp CountdownSequence


Jump_001_4ea3:
    ld a, d
    cp $e8
    jr nz, jr_001_4eb5

    ld b, $00
    ld hl, $c02e
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
    ld hl, $c04e
    add hl, bc
    ld [hl], a
    ld hl, $c06e
    add hl, bc
    ld [hl], a
    call SoundUpdate2
    ld d, a
    and $f0
    swap a
    ld b, $00
    ld hl, $c056
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
    ld hl, $c05e
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
    ld hl, $c076
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
    ld hl, $c0a6
    add hl, bc
    ld [hl], d
    ld hl, $c0ae
    add hl, bc
    ld [hl], e
    ld b, $00
    ld hl, $c02e
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
    ld hl, $c03e
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
    ld [$c0e8], a
    call SoundUpdate2
    ld [$c0e9], a
    xor a
    ld [$c0ce], a
    ld [$c0cf], a
    ld [$c0d0], a
    ld [$c0d1], a
    jr jr_001_4f77

jr_001_4f5e:
    call SoundUpdate2
    ld [$c0ea], a
    call SoundUpdate2
    ld [$c0eb], a
    xor a
    ld [$c0d2], a
    ld [$c0d3], a
    ld [$c0d4], a
    ld [$c0d5], a

jr_001_4f77:
    jp CountdownSequence


jr_001_4f7a:
    cp $ee
    jr nz, jr_001_4f87

    call SoundUpdate2
    ld [$c004], a
    jp CountdownSequence


jr_001_4f87:
    cp $ef
    jr nz, jr_001_4fa6

    call SoundUpdate2
    push bc
    call SoundEngine
    pop bc
    ld a, [$c003]
    and a
    jr nz, jr_001_4fa3

    ld a, [$c02d]
    ld [$c003], a
    xor a
    ld [$c02d], a

jr_001_4fa3:
    jp CountdownSequence


jr_001_4fa6:
    cp $fc
    jr nz, StageIntroAnim

    call SoundUpdate2
    ld b, $00
    ld hl, $c046
    add hl, bc
    ld [hl], a
    and $c0
    ld hl, $c03e
    add hl, bc
    ld [hl], a
    ld hl, $c02e
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
    ld hl, $c036
    add hl, bc
    set 0, [hl]
    jp CountdownSequence


jr_001_4ff1:
    and $f0
    cp $e0
    jr nz, jr_001_5004

    ld hl, $c0d6
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
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_001_5051

    call Display2PStatus
    ld d, a
    ld b, $00
    ld hl, $c03e
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
    ld hl, $c036
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
    ld a, [$c003]
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
    ld hl, $c0c6
    add hl, bc
    ld a, [hl]
    ld l, b
    call SoundUpdate4
    ld a, c
    cp $04
    jr nc, jr_001_50bd

Draw2PField::
    ld a, [$c0e8]
    ld d, a
    ld a, [$c0e9]
    ld e, a
    jr jr_001_50cd

jr_001_50bd:
    ld d, $01
    ld e, $00
    cp $07
    jr z, jr_001_50cd

    ld a, [$c0ea]
    ld d, a
    ld a, [$c0eb]
    ld e, a

jr_001_50cd:
    ld a, l
    ld b, $00
    ld hl, $c0ce
    add hl, bc
    ld l, [hl]
    call SoundUpdate4
    ld e, l
    ld d, h
    ld hl, $c0ce
    add hl, bc
    ld [hl], e
    ld a, d
    ld hl, $c0b6
    add hl, bc
    ld [hl], a
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_001_50f7

    ld hl, $c02e
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

    ld hl, $c02a
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
    ld hl, $5672
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
    ld hl, $c0d6
    add hl, bc
    ld b, [hl]
    call SoundUpdate5
    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 4, [hl]
    jr z, jr_001_5147

    call UpdateObjectData

jr_001_5147:
    push de
    ld a, c
    cp $04
    jr nc, jr_001_515c

    ld hl, $c02a
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
    ld hl, $c0de
    add hl, bc
    ld d, [hl]
    ld b, $02
    call SoundUpdate3
    ld [hl], d
    call GetMusicPointer
    call MusicDataInit
    pop de
    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 0, [hl]
    jr z, jr_001_517e

    inc e
    jr nc, jr_001_517e

    inc d

jr_001_517e:
    ld hl, $c066
    add hl, bc
    ld [hl], e
    call ProcessNote
    ret


MusicDataInit::
    ld b, $00
    ld hl, $567a
    add hl, bc
    ldh a, [rNR51]
    or [hl]
    ld d, a
    ld a, c
    cp $07
    jr z, jr_001_51a2

    cp $04
    jr nc, jr_001_51b4

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_001_51b4

jr_001_51a2:
    ld a, [$c004]
    ld hl, $567a
    add hl, bc
    and [hl]
    ld d, a
    ldh a, [rNR51]
    ld hl, $5672
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
    ld hl, $c0b6
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
    ld hl, $c03e
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
    ld de, $c0e6
    cp $02
    jr z, jr_001_51ee

    ld de, $c0e7

jr_001_51ee:
    ld a, [de]
    add a
    ld d, $00
    ld e, a
    ld hl, $7dbd
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
    ld a, [$c02a]
    cp $0f
    jr nc, jr_001_5228

    jr jr_001_5249

jr_001_5228:
    ld a, [$c02a]
    cp $0f
    jr z, jr_001_5249

    jr c, jr_001_5233

    jr jr_001_5249

jr_001_5233:
    ld hl, $c006
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
    ld hl, $c02e
    add hl, bc
    bit 5, [hl]
    jp nz, Jump_001_5293

    ld hl, $c09e
    add hl, bc
    ld e, [hl]
    ld hl, $c096
    add hl, bc
    ld d, [hl]
    ld hl, $c07e
    add hl, bc
    ld l, [hl]
    ld h, b
    add hl, de
    ld d, h
    ld e, l
    ld hl, $c08e
    add hl, bc
    push hl
    ld hl, $c086
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
    ld hl, $c0a6
    add hl, bc
    ld a, [hl]
    cp d
    jp c, ClearObjectFlags

    jr nz, jr_001_52c6

    ld hl, $c0ae
    add hl, bc
    ld a, [hl]
    cp e
    jp c, ClearObjectFlags

    jr jr_001_52c6

Jump_001_5293:
    ld hl, $c09e
    add hl, bc
    ld a, [hl]
    ld hl, $c096
    add hl, bc
    ld d, [hl]
    ld hl, $c07e
    add hl, bc
    ld e, [hl]
    sub e
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, $c086
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
    ld hl, $c0a6
    add hl, bc
    ld a, d
    cp [hl]
    jr c, ClearObjectFlags

    jr nz, jr_001_52c6

    ld hl, $c0ae
    add hl, bc
    ld a, e
    cp [hl]
    jr c, ClearObjectFlags

jr_001_52c6:
    ld hl, $c09e
    add hl, bc
    ld [hl], e
    ld hl, $c096
    add hl, bc
    ld [hl], d
    ld b, $03
    call SoundUpdate3
    ld a, e
    ld [hl+], a
    ld [hl], d
    ret


ClearObjectFlags::
    ld hl, $c02e
    add hl, bc
    res 4, [hl]
    res 5, [hl]
    ret


UpdateObjectData::
    ld hl, $c096
    add hl, bc
    ld [hl], d
    ld hl, $c09e
    add hl, bc
    ld [hl], e
    ld hl, $c0b6
    add hl, bc
    ld a, [hl]
    ld hl, $c076
    add hl, bc
    sub [hl]
    jr nc, jr_001_52fa

    ld a, $01

jr_001_52fa:
    ld [hl], a
    ld hl, $c0ae
    add hl, bc
    ld a, e
    sub [hl]
    ld e, a
    ld a, d
    sbc b
    ld hl, $c0a6
    add hl, bc
    sub [hl]
    jr c, jr_001_5316

    ld d, a
    ld b, $00
    ld hl, $c02e
    add hl, bc
    set 5, [hl]
    jr jr_001_5339

jr_001_5316:
    ld hl, $c096
    add hl, bc
    ld d, [hl]
    ld hl, $c09e
    add hl, bc
    ld e, [hl]
    ld hl, $c0ae
    add hl, bc
    ld a, [hl]
    sub e
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, $c0a6
    add hl, bc
    ld a, [hl]
    sub d
    ld d, a
    ld b, $00
    ld hl, $c02e
    add hl, bc
    res 5, [hl]

jr_001_5339:
    ld hl, $c076
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
    ld hl, $c07e
    add hl, bc
    ld [hl], d
    ld hl, $c086
    add hl, bc
    ld [hl], a
    ld hl, $c08e
    add hl, bc
    ld [hl], a
    ret


SoundUpdate1::
    ld b, $00
    ld hl, $c046
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
    ld hl, $c006
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
    ld hl, $566a
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
    ld hl, $5682
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
    ld [$c001], a
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
    ld [$c000], a
    ld [$c003], a
    ld [$c0e9], a
    ld [$c0e6], a
    ld [$c0e7], a
    ld d, $08
    ld hl, $c016
    call StopAllSound
    ld hl, $c006
    call StopAllSound
    ld d, $04
    ld hl, $c026
    call StopAllSound
    ld hl, $c02e
    call StopAllSound
    ld hl, $c03e
    call StopAllSound
    ld hl, $c046
    call StopAllSound
    ld hl, $c04e
    call StopAllSound
    ld hl, $c056
    call StopAllSound
    ld hl, $c05e
    call StopAllSound
    ld hl, $c066
    call StopAllSound
    ld hl, $c06e
    call StopAllSound
    ld hl, $c036
    call StopAllSound
    ld hl, $c076
    call StopAllSound
    ld hl, $c07e
    call StopAllSound
    ld hl, $c086
    call StopAllSound
    ld hl, $c08e
    call StopAllSound
    ld hl, $c096
    call StopAllSound
    ld hl, $c09e
    call StopAllSound
    ld hl, $c0a6
    call StopAllSound
    ld hl, $c0ae
    call StopAllSound
    ld a, $01
    ld hl, $c0be
    call StopAllSound
    ld hl, $c0b6
    call StopAllSound
    ld hl, $c0c6
    call StopAllSound
    ld [$c0e8], a
    ld a, $ff
    ld [$c004], a
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
    jp $55e2


SoundLookupIndex::
    ld l, a
    ld e, a
    ld h, $00
    ld d, h
    add hl, hl
    add hl, de
    ld de, $7c2c
    add hl, de
    ld a, h
    ld [$c0ec], a
    ld a, l
    ld [$c0ed], a
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
    ld a, [$c0ec]
    ld h, a
    ld a, [$c0ed]
    ld l, a
    add hl, bc
    ld c, d
    ld a, [hl]
    and $0f
    ld e, a
    ld d, $00
    ld hl, $c026
    add hl, de
    ld a, [hl]
    and a
    jr z, jr_001_54f6

    ld a, e
    cp $07
    jr nz, jr_001_54ed

    ld a, [$c001]
    cp $0f
    jr nc, jr_001_54e6

    ret


jr_001_54e6:
    ld a, [hl]
    cp $0f
    jr z, jr_001_54f6

    jr c, jr_001_54f6

jr_001_54ed:
    ld a, [$c001]
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
    ld hl, $c016
    add hl, de
    ld [hl+], a
    ld [hl], a
    ld hl, $c006
    add hl, de
    ld [hl+], a
    ld [hl], a
    pop de
    ld hl, $c026
    add hl, de
    ld [hl], a
    ld hl, $c02e
    add hl, de
    ld [hl], a
    ld hl, $c03e
    add hl, de
    ld [hl], a
    ld hl, $c046
    add hl, de
    ld [hl], a
    ld hl, $c04e
    add hl, de
    ld [hl], a
    ld hl, $c056
    add hl, de
    ld [hl], a
    ld hl, $c05e
    add hl, de
    ld [hl], a
    ld hl, $c066
    add hl, de
    ld [hl], a
    ld hl, $c06e
    add hl, de
    ld [hl], a
    ld hl, $c076
    add hl, de
    ld [hl], a
    ld hl, $c07e
    add hl, de
    ld [hl], a
    ld hl, $c086
    add hl, de
    ld [hl], a
    ld hl, $c08e
    add hl, de
    ld [hl], a
    ld hl, $c096
    add hl, de
    ld [hl], a
    ld hl, $c09e
    add hl, de
    ld [hl], a
    ld hl, $c0a6
    add hl, de
    ld [hl], a
    ld hl, $c0ae
    add hl, de
    ld [hl], a
    ld hl, $c036
    add hl, de
    ld [hl], a
    ld a, $01
    ld hl, $c0be
    add hl, de
    ld [hl], a
    ld hl, $c0b6
    add hl, de
    ld [hl], a
    ld hl, $c0c6
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
    jp z, $55e2

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
    ld [$c000], a
    ld [$c003], a
    ld [$c002], a
    ld [$c0e9], a
    ld [$c0eb], a
    ld [$c0e6], a
    ld [$c0e7], a
    ld d, $a0
    ld hl, $c006
    call StopAllSound
    ld a, $01
    ld d, $18
    ld hl, $c0b6
    call StopAllSound
    ld [$c0e8], a
    ld [$c0ea], a
    ld a, $ff
    ld [$c004], a
    ret


StopAllSound::
    ld b, d

jr_001_55dd:
    ld [hl+], a
    dec b
    jr nz, jr_001_55dd

    ret


    db $fa, $01, $c0, $6f, $5f, $26, $00, $54, $29, $19, $11, $2c, $7c, $19, $5d, $54
    db $21, $06, $c0, $1a, $47, $07, $07, $e6, $03, $4f, $78, $e6, $0f, $41, $04, $13
    db $0e, $00, $b9, $28, $05, $0c, $23, $23, $18, $f8, $e5, $c5, $f5, $06, $00, $4f
    db $21, $26, $c0, $09, $fa, $01, $c0, $77, $f1, $fe, $03, $38, $06, $21, $2e, $c0
    db $09, $cb, $d6, $c1, $e1, $1a, $22, $13, $1a, $22, $13, $0c, $05, $78, $a7, $1a
    db $13, $20, $cf, $fa, $01, $c0, $fe, $0f, $30, $02, $18, $2a, $fa, $01, $c0, $fe
    db $0f, $28, $23, $38, $02, $18, $1f, $21, $2a, $c0, $22, $22, $22, $77, $21, $12
    db $c0, $11, $69, $56, $73, $23, $72, $fa, $05, $c0, $a7, $20, $09, $f0, $24, $ea
    db $05, $c0, $3e, $77, $e0, $24, $c9, $ff, $10, $15, $1a, $1f, $10, $15, $1a, $1f
    db $ee, $dd, $bb, $77, $ee, $dd, $bb, $77, $11, $22, $44, $88, $11, $22, $44, $88
    db $2c, $f8, $9d, $f8, $07, $f9, $6b, $f9, $ca, $f9, $23, $fa, $77, $fa, $c7, $fa
    db $12, $fb, $58, $fb, $9b, $fb, $da, $fb, $ed, $00, $b0, $f0, $77, $ec, $02, $e8
    db $dc, $b1, $e6, $a2, $e5, $22, $51, $e6, $a2, $e5, $22, $51, $32, $72, $a1, $32
    db $72, $a1, $91, $53, $91, $e4, $03, $e5, $93, $a0, $90, $a0, $50, $70, $50, $20
    db $50, $e6, $a3, $e5, $a3, $dc, $b3, $e6, $a2, $e5, $22, $51, $e6, $a2, $e5, $22
    db $51, $32, $72, $a1, $32, $20, $30, $20, $20, $30, $02, $22, $31, $02, $22, $31
    db $a1, $51, $e4, $01, $e5, $31, $e4, $11, $e5, $21, $e4, $21, $e5, $01, $e6, $a2
    db $e5, $22, $51, $e6, $a2, $e5, $22, $51, $32, $72, $a1, $32, $72, $a1, $52, $52
    db $a1, $52, $92, $e4, $01, $22, $e5, $a2, $51, $e4, $51, $31, $21, $01, $e5, $71
    db $e6, $a1, $e5, $31, $51, $71, $31, $a1, $71, $51, $e6, $a1, $e5, $21, $31, $51
    db $21, $71, $51, $51, $e6, $91, $e5, $01, $21, $31, $01, $71, $31, $51, $31, $21
    db $01, $21, $51, $e6, $a1, $e5, $51, $71, $e6, $a1, $e5, $31, $51, $71, $31, $a1
    db $71, $51, $e6, $a1, $e5, $21, $31, $51, $71, $91, $b1, $e4, $01, $e5, $51, $71
    db $91, $51, $71, $91, $e4, $01, $e5, $a1, $91, $71, $91, $dc, $b1, $a7, $fe, $00
    db $c7, $56, $ec, $02, $ea, $08, $26, $dc, $c1, $e4, $21, $21, $01, $01, $e5, $a1
    db $e4, $01, $21, $e5, $a0, $d6, $c1, $e4, $20, $50, $dc, $c1, $71, $71, $51, $51
    db $71, $51, $31, $21, $01, $01, $21, $21, $31, $31, $71, $31, $53, $33, $23, $a3
    db $dc, $b3, $50, $71, $52, $21, $a1, $91, $a1, $91, $71, $3d, $00, $31, $02, $e5
    db $91, $e4, $71, $51, $71, $51, $23, $33, $43, $53, $50, $71, $52, $21, $a1, $91
    db $a1, $91, $72, $aa, $d6, $b1, $50, $70, $90, $a0, $dc, $b3, $e3, $01, $01, $e4
    db $a1, $a1, $91, $e3, $21, $01, $e4, $91, $dc, $a7, $a7, $dc, $30, $a7, $dc, $b7
    db $73, $35, $71, $51, $71, $53, $a5, $a1, $91, $a1, $93, $53, $e3, $03, $e4, $93
    db $a3, $e3, $03, $21, $01, $e4, $a1, $91, $73, $35, $a1, $91, $a1, $e3, $23, $03
    db $e4, $b3, $61, $71, $e3, $03, $e4, $a3, $91, $e3, $21, $01, $e4, $91, $dc, $b3
    db $a3, $a3, $dc, $b1, $a7, $fe, $00, $92, $57, $d6, $12, $fd, $34, $5a, $fd, $34
    db $5a, $fd, $34, $5a, $fd, $34, $5a, $e4, $eb, $00, $5a, $a0, $c0, $51, $e3, $eb
    db $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $73, $eb, $00, $5a, $a0, $c0
    db $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $51, $e3, $eb, $00
    db $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $73, $eb, $00, $5a, $a0, $c0, $e3
    db $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45
    db $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0
    db $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00
    db $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0
    db $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $71, $e3, $eb
    db $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $93, $eb, $00, $5a, $a0, $c0
    db $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $71, $e3, $eb, $00
    db $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $93, $eb, $00, $5a, $a0, $c0, $e3
    db $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $21, $e3, $eb, $00, $45
    db $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $03, $eb, $00, $5a, $a0, $c0, $e3, $eb
    db $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e5, $b1, $e3, $eb, $00, $45
    db $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e5, $a3, $e4, $eb, $00, $5a, $a0, $c0
    db $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $51, $e3, $eb, $00
    db $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $73, $eb, $00, $5a, $a0, $c0, $e3
    db $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $51, $e3, $eb, $00, $45
    db $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $73, $eb, $00, $5a, $a0, $c0, $e3, $eb
    db $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45, $50
    db $c0, $e4, $eb, $00, $5a, $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0, $e3
    db $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00, $45
    db $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0, $c0
    db $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $a1, $e3, $eb, $00
    db $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e3, $03, $e4, $eb, $00, $5a, $a0
    db $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $91, $e3, $eb
    db $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e3, $03, $e4, $eb, $00, $5a
    db $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $a1, $e3
    db $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c0, $e3, $23, $e4, $eb, $00
    db $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c2, $e3
    db $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0, $c4, $eb, $00, $5a, $a0, $c0
    db $e3, $eb, $00, $45, $50, $c0, $fd, $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fd
    db $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fd, $34, $5a, $fe, $00
    db $19, $58, $e4, $eb, $00, $5a, $a0, $c2, $e3, $eb, $00, $45, $50, $c0, $e4, $eb
    db $00, $5a, $a0, $c4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $e4
    db $eb, $00, $5a, $a0, $c2, $e3, $eb, $00, $45, $50, $c0, $e4, $eb, $00, $5a, $a0
    db $c4, $eb, $00, $5a, $a0, $c0, $e3, $eb, $00, $45, $50, $c0, $ff, $dc, $c3, $b7
    db $04, $b2, $04, $b4, $04, $b7, $04, $b7, $04, $b7, $04, $b2, $04, $b4, $04, $b7
    db $04, $b1, $04, $b0, $04, $b0, $04, $c3, $b7, $04, $b7, $04, $b7, $04, $b7, $04
    db $b7, $04, $b7, $04, $b7, $04, $b2, $04, $b4, $04, $b7, $04, $b7, $04, $b7, $04
    db $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b2, $04, $b4, $04, $b7, $04, $b7, $04
    db $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04, $b7, $04
    db $b7, $04, $b7, $04, $b7, $04, $b2, $04, $b4, $04, $b7, $04, $b3, $04, $fe, $00
    db $89, $5a, $ed, $00, $92, $f0, $77, $ec, $02, $e8, $d8, $b2, $e5, $73, $b1, $93
    db $b1, $e4, $05, $21, $41, $21, $e5, $71, $e4, $21, $01, $e5, $b1, $91, $b1, $75
    db $25, $ed, $00, $92, $f0, $77, $ec, $02, $e8, $d8, $b2, $e5, $75, $63, $21, $75
    db $91, $61, $91, $75, $b3, $71, $91, $71, $61, $41, $61, $91, $75, $63, $21, $75
    db $91, $61, $91, $75, $b3, $e4, $21, $01, $e5, $b1, $91, $71, $91, $b1, $73, $91
    db $b3, $91, $e4, $03, $e5, $91, $e4, $01, $e5, $b1, $91, $73, $91, $b3, $91, $e4
    db $05, $e5, $b5, $43, $b1, $93, $71, $b1, $91, $71, $b1, $91, $71, $43, $b1, $93
    db $71, $b5, $95, $d8, $83, $25, $b3, $71, $91, $71, $91, $73, $61, $25, $b3, $71
    db $91, $71, $91, $b1, $91, $61, $d8, $93, $25, $b3, $71, $91, $b1, $91, $73, $61
    db $25, $b3, $71, $91, $71, $61, $b1, $e4, $01, $e5, $b1, $d8, $b2, $95, $b5, $93
    db $e4, $21, $25, $e5, $95, $45, $93, $e4, $21, $25, $d8, $83, $e5, $23, $21, $b3
    db $71, $91, $71, $91, $73, $61, $21, $21, $21, $b3, $71, $91, $b1, $91, $61, $71
    db $91, $d8, $92, $b1, $b1, $b1, $b1, $91, $71, $41, $41, $41, $73, $61, $b1, $b1
    db $b1, $b1, $91, $71, $41, $41, $41, $b1, $91, $61, $d8, $75, $7b, $9b, $bf, $c5
    db $d8, $a2, $71, $95, $75, $65, $43, $61, $75, $95, $b5, $e6, $bb, $d8, $b3, $e3
    db $2b, $7b, $2b, $7b, $e4, $9b, $e3, $4b, $6b, $25, $ea, $00, $00, $d8, $b2, $e5
    db $73, $e4, $71, $25, $e5, $b3, $e4, $21, $75, $e5, $73, $e4, $41, $25, $e5, $73
    db $b1, $e4, $25, $e5, $63, $91, $e4, $25, $e5, $73, $b1, $e4, $45, $e5, $93, $e4
    db $61, $73, $21, $95, $e5, $69, $b1, $b9, $b1, $b9, $b1, $b5, $e4, $23, $e5, $91
    db $99, $e4, $41, $49, $41, $45, $21, $11, $21, $41, $21, $07, $2b, $d8, $a1, $e5
    db $21, $21, $21, $25, $41, $41, $41, $4b, $d8, $b2, $65, $0b, $d8, $a1, $21, $21
    db $21, $25, $41, $41, $41, $4b, $d8, $b2, $65, $05, $ec, $01, $d8, $92, $e6, $b1
    db $e5, $21, $71, $21, $e6, $b1, $e5, $21, $e6, $b1, $e5, $21, $71, $e6, $b1, $e5
    db $21, $71, $e6, $b1, $e5, $21, $71, $21, $e6, $b1, $e5, $21, $e6, $b1, $e5, $21
    db $71, $e6, $b1, $e5, $21, $41, $e6, $91, $e5, $21, $61, $21, $e6, $91, $e5, $21
    db $e6, $91, $e5, $21, $61, $e6, $91, $e5, $21, $61, $e6, $91, $e5, $21, $61, $21
    db $e6, $91, $e5, $21, $e6, $91, $e5, $21, $61, $21, $e6, $91, $e5, $21, $d8, $92
    db $e6, $b1, $e5, $21, $71, $21, $e6, $b1, $e5, $21, $23, $71, $23, $01, $e6, $b1
    db $e5, $21, $71, $e6, $b1, $e5, $21, $71, $23, $71, $23, $01, $d8, $a2, $25, $b3
    db $71, $91, $71, $91, $73, $61, $25, $b3, $71, $91, $71, $91, $b1, $91, $61, $d8
    db $b2, $21, $21, $21, $b3, $71, $91, $41, $61, $73, $61, $71, $71, $71, $b3, $71
    db $91, $71, $91, $71, $93, $ec, $02, $d8, $b2, $fe, $00, $fd, $5a, $ec, $02, $d8
    db $c2, $e4, $21, $71, $61, $73, $21, $41, $61, $71, $b3, $91, $73, $61, $43, $61
    db $75, $e5, $75, $ec, $02, $d8, $c2, $e4, $21, $21, $21, $21, $01, $e5, $b1, $e4
    db $45, $63, $41, $21, $71, $61, $71, $61, $71, $43, $01, $e5, $b1, $e4, $01, $11
    db $21, $21, $21, $21, $01, $e5, $b1, $e4, $45, $63, $41, $21, $71, $61, $71, $61
    db $71, $93, $71, $63, $21, $b1, $a1, $b1, $e3, $01, $e4, $b1, $91, $75, $43, $70
    db $90, $b1, $a1, $b1, $e3, $01, $e4, $b1, $91, $71, $91, $71, $41, $61, $71, $91
    db $81, $91, $b1, $91, $71, $65, $23, $40, $60, $91, $81, $91, $41, $61, $41, $21
    db $41, $61, $21, $41, $61, $ea, $02, $22, $d8, $b3, $73, $61, $73, $21, $41, $21
    db $01, $e5, $b1, $e4, $01, $21, $73, $61, $73, $21, $41, $61, $71, $61, $41, $21
    db $73, $61, $73, $21, $41, $21, $01, $e5, $b1, $e4, $01, $21, $73, $61, $73, $21
    db $01, $71, $61, $75, $ea, $00, $00, $d8, $c2, $91, $81, $91, $73, $41, $23, $e3
    db $21, $23, $e4, $60, $70, $91, $81, $91, $73, $41, $23, $e3, $21, $25, $ea, $02
    db $22, $d8, $b3, $e4, $73, $61, $73, $21, $41, $21, $01, $e5, $b1, $e4, $01, $21
    db $73, $61, $73, $21, $41, $61, $71, $61, $41, $21, $73, $61, $73, $21, $41, $21
    db $01, $e5, $b1, $e4, $01, $21, $73, $61, $73, $21, $45, $73, $61, $ea, $00, $00
    db $d8, $c2, $e5, $21, $21, $21, $91, $71, $61, $41, $41, $41, $e4, $01, $e5, $b1
    db $91, $61, $61, $61, $e4, $41, $21, $01, $e5, $b1, $e4, $01, $21, $43, $21, $61
    db $41, $61, $41, $61, $41, $63, $41, $23, $61, $71, $61, $71, $61, $71, $61, $75
    db $e5, $75, $ec, $03, $d8, $b2, $e4, $21, $11, $21, $41, $21, $01, $e5, $b5, $e4
    db $25, $21, $11, $21, $43, $01, $e5, $b5, $75, $91, $81, $91, $e4, $23, $01, $e5
    db $b1, $a1, $b1, $e4, $43, $21, $61, $51, $61, $71, $61, $41, $25, $63, $ec, $02
    db $d8, $c2, $b0, $e3, $00, $21, $11, $21, $41, $21, $01, $e4, $b5, $e3, $25, $21
    db $11, $21, $43, $01, $e4, $b5, $75, $91, $81, $91, $e3, $23, $01, $e4, $b1, $a1
    db $b1, $e3, $43, $21, $61, $51, $61, $71, $61, $41, $95, $ec, $03, $d8, $c3, $e4
    db $21, $41, $61, $73, $61, $73, $91, $b5, $93, $71, $b5, $93, $71, $93, $21, $23
    db $90, $b0, $e3, $05, $e4, $b3, $91, $e3, $05, $e4, $b3, $91, $d8, $c5, $7b, $6b
    db $ec, $02, $d8, $c2, $21, $21, $21, $25, $41, $41, $41, $45, $61, $61, $61, $61
    db $41, $21, $05, $45, $21, $21, $21, $25, $41, $41, $41, $45, $61, $61, $61, $61
    db $41, $21, $03, $e5, $b1, $93, $71, $ec, $01, $ea, $02, $24, $d8, $c4, $e4, $71
    db $61, $71, $91, $71, $61, $45, $23, $40, $60, $71, $61, $71, $91, $71, $61, $41
    db $61, $41, $21, $41, $51, $61, $51, $61, $71, $61, $41, $25, $65, $61, $51, $61
    db $71, $61, $41, $21, $41, $61, $21, $41, $61, $ea, $02, $22, $d8, $b3, $73, $61
    db $73, $21, $41, $21, $01, $e5, $b1, $e4, $01, $21, $73, $61, $73, $21, $41, $61
    db $71, $61, $41, $21, $73, $61, $73, $21, $41, $21, $01, $e5, $b1, $e4, $01, $21
    db $73, $61, $73, $21, $41, $61, $71, $61, $41, $21, $73, $61, $73, $21, $41, $21
    db $01, $e5, $b1, $e4, $01, $21, $73, $61, $73, $21, $01, $71, $61, $73, $ec, $02
    db $d8, $c2, $ea, $00, $00, $e5, $b0, $e4, $00, $fe, $00, $e9, $5c, $d8, $12, $cf
    db $c5, $e4, $01, $21, $c3, $01, $c3, $e5, $b1, $c3, $b1, $c3, $d8, $12, $e4, $21
    db $c3, $e5, $b1, $c3, $e4, $41, $c3, $03, $41, $21, $c3, $e5, $b1, $c3, $e4, $01
    db $c3, $11, $c3, $21, $c3, $e5, $b1, $c3, $e4, $41, $c3, $03, $41, $21, $c3, $71
    db $61, $21, $41, $c3, $21, $c1, $01, $e5, $b1, $c3, $e4, $31, $c3, $41, $c3, $71
    db $c3, $e5, $b1, $c3, $e4, $31, $c3, $41, $c3, $71, $c1, $e5, $b1, $91, $c3, $e4
    db $11, $c3, $21, $c3, $61, $c3, $e5, $91, $c3, $e4, $11, $c3, $21, $c3, $01, $c1
    db $41, $e5, $71, $cf, $c5, $71, $cf, $c5, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5
    db $b1, $c1, $91, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5, $b1, $c1, $e4, $11, $21
    db $c3, $e5, $91, $c3, $e4, $21, $c1, $e5, $21, $21, $c3, $e4, $21, $c3, $e5, $91
    db $c3, $e4, $21, $c1, $e5, $21, $21, $c3, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5
    db $b1, $c1, $91, $71, $c3, $b1, $c3, $e4, $01, $c3, $e5, $b1, $c1, $91, $71, $c3
    db $b1, $c3, $e4, $01, $c3, $e5, $b1, $c1, $91, $71, $c3, $b1, $c3, $e4, $01, $c3
    db $e5

Call_001_5fe3:
    or c
    pop bc
    sub c
    or c
    ret


    db $e4
    ld bc, $21c9
    rst $08
    jp $2101


    jp $c301


    push hl
    or c
    jp $c391


    ld [hl], c
    jp Jump_000_21e4


    jp $c371


    push hl
    ld [hl], c
    rst $00
    db $e4
    ld hl, $b1e5
    rst $00
    db $e4
    ld [hl], c
    ld hl, $21c7
    push hl
    or c
    rst $00
    db $e4
    ld b, c
    ld hl, $21c7
    push hl
    sub c
    rst $00
    db $e4
    ld b, c
    ld hl, $61c7
    ld [hl], c
    jp $c391


    ld h, c
    jp $c321


    push hl
    or c
    jp $71e4


    jp $c321


    ld hl, $e5c3
    or c
    jp Jump_001_41e4


    jp $c321


    ld hl, $e5c3
    sub c
    jp Jump_001_41e4


    jp $c321


    ld h, c
    jp $c371


    sub c
    jp $c321


    ld [hl], c
    jp $c321


    ld [hl], c
    jp $c321


    ld [hl], c
    jp $c321


    sub c
    pop bc
    ld hl, $c321
    db $e3
    ld bc, $e4c3
    ld b, c
    jp Jump_000_01e3


    jp Jump_001_41e4


    jp $c391


    ld hl, $91c3
    jp $c321


    db $e3
    ld h, c
    ret


    ld [hl], c
    ret


    sub c
    ret


    ld h, c
    jp $c391


    ld h, c
    ret


    ld [hl], c
    ret


    sub c
    ret


    ld h, c
    jp $cf91


    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    jp $71e5


    rst $08
    push bc
    ld [hl], c
    rst $08
    jp $7191


    jp $c3b1


    db $e4
    ld bc, $e5c3
    or c
    pop bc
    sub c
    ld [hl], c
    jp $c3b1


    db $e4
    ld bc, $e5c3
    or c
    pop bc
    sub c
    ld [hl], c
    jp $c3b1


    db $e4
    ld bc, $e5c3
    or c
    pop bc
    sub c
    ld [hl], c
    jp $c3b1


    db $e4
    ld bc, $c121
    ld hl, $41c1
    cp $00
    jr nc, @+$61

    ret c

    rst $08
    rst $00
    rst $00
    rst $08
    ret c

    pop af
    call nz, $c5f1
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $07
    adc $60
    pop af
    set 6, c
    set 7, [hl]
    ld [bc], a
    jp c, $f160

    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $02
    ldh [c], a
    ld h, b
    pop af
    push bc
    pop af
    push bc
    pop af
    jp $c0f1


    pop af
    ret nz

    pop af
    ret nz

    pop af
    call nz, $fed8
    ld [bc], a
    xor $60
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $04
    ld bc, $f161
    set 6, c
    set 6, c
    set 1, c
    pop af
    pop bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $02
    ld d, $61
    pop af
    set 6, c
    set 7, [hl]
    inc b
    ld [hl+], a
    ld h, c
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $08
    ld a, [hl+]
    ld h, c
    pop af
    set 6, c
    set 6, c
    set 6, c
    push bc
    pop af
    push bc
    cp $02
    ld [hl], $61
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $04
    ld b, h
    ld h, c
    pop af
    set 6, c
    set 7, [hl]
    ld [bc], a
    ld d, b
    ld h, c
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $04
    ld e, b
    ld h, c
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    pop af
    push bc
    cp $00
    adc $60
    db $ed
    nop
    ldh [$fff0], a
    ld [hl], a
    db $ec
    ld [bc], a
    add sp, -$24
    or e
    jp $07e4


    push hl
    or a
    ld b, c
    ld [hl], c
    ld bc, $ed79
    nop
    ldh [$fff0], a
    ld [hl], a
    db $ec
    ld [bc], a
    add sp, -$24
    or e
    rst $08
    ret


    push hl
    ld [hl], b
    ld d, b
    ld b, b
    ld d, b
    ld b, b
    jr nz, @+$03

    and $71
    push hl
    ld bc, $2141
    ld d, c
    ld bc, $2141
    and $b0
    push hl
    nop
    ld hl, $7351
    ld d, e
    ld b, c
    ld bc, $7141
    ld d, c
    ld bc, $0141
    ld hl, $b0e6
    push hl
    nop
    ld hl, $4151
    ld d, b
    ld b, b
    ld hl, $0171
    ld hl, $2141
    ld b, b
    jr nz, jr_001_61c5

    ld b, c

jr_001_61c5:
    ld [hl], c
    inc hl
    ld d, e
    ld [hl], c
    ld d, c
    ld d, c
    ld hl, $7141
    ld bc, $7040
    ld d, e
    ld [hl], c
    ld b, c
    ld d, c
    ld d, c
    ld b, c
    ld b, c
    ld hl, $e651
    or c
    push hl
    ld d, c
    ld [hl], b
    ld d, b
    ld b, c
    ld b, c
    ld [hl], c
    ld d, c
    ld b, c
    ld hl, $2001
    nop
    and $b0
    push hl
    nop
    ld hl, $5141
    ld b, c
    ld d, c
    sub c
    ld [hl], b
    ld d, b
    ld b, b
    jr nz, @+$03

    and $b1
    sub c
    or c
    push hl
    ld bc, $2001
    nop
    and $b0
    sub b
    push hl
    ld bc, $5041
    jr nz, jr_001_624a

    nop
    cpl
    jp Jump_001_73c1


    ld [hl], a
    ld d, c
    ld c, a
    bit 6, c
    ld d, c
    ld b, c
    ld d, c
    ld [hl], c
    ld d, c
    ld b, c
    ld hl, $7141
    sub b
    ld d, b
    ld [hl], b
    ld b, b
    ld d, c
    ld b, b
    ld [hl], b
    sub b
    ld [hl], b
    sub c
    or c
    db $e4
    ld hl, $a5dc
    ld b, a
    rlca
    ld d, a
    inc hl
    ld b, e
    ld [hl], a
    ld b, e
    or e
    ld b, a
    ld b, a
    rlca
    push hl
    or a
    sub a
    ld [hl], a
    sub a
    or a
    call c, Call_001_73b3
    ld d, e
    ld b, e
    inc hl
    db $e4
    inc bc
    push hl
    or e
    sub e
    ld [hl], c
    or c

jr_001_624a:
    db $e4
    inc bc
    push hl
    ld d, e
    ld [hl], e
    inc bc
    inc hl
    ld b, e
    ld d, e
    ld a, a
    jp $cfcf


    rst $08
    cp $00
    xor c
    ld h, c
    db $ec
    ld [bc], a
    call c, $e4c3
    ld bc, $4321
    ld d, c
    ld b, c
    ld hl, $e501
    or c
    db $e4
    ld hl, $2303
    ld bc, $71e5
    ld d, c
    ld [hl], c
    db $ec
    ld [bc], a
    call c, $e4c3
    ld bc, $71e5
    db $e4
    ld bc, $2141
    push hl
    ld [hl], c
    db $e4
    ld hl, $4151
    nop
    jr nz, @+$43

    ld d, c
    ld b, e
    ld hl, $2000
    ld b, c
    ld bc, $7141
    ld d, c
    ld bc, $0141
    ld hl, $71e5
    db $e4
    ld hl, $4151
    ld d, b
    ld b, b
    inc hl
    pop bc
    nop
    jr nz, jr_001_62e4

    ld d, b
    ld b, b
    ld hl, $b0e5
    db $e4
    nop
    ld hl, $5141
    ld b, c
    ld hl, $e501
    or c
    sub c
    ld [hl], c
    or c
    db $e4
    ld [hl], b
    ld d, b
    ld b, b
    jr nz, jr_001_62bc

    push hl

jr_001_62bc:
    or c
    sub c
    db $e4
    ld b, c
    push hl
    ld [hl], c
    db $e4
    ld b, c
    ld d, c
    jr nz, jr_001_6307

    ld d, c
    ld bc, $b1e5
    db $e4
    ld d, c
    ld hl, $4151
    nop
    jr nz, jr_001_6314

    ld hl, $2101
    ld b, c
    ld bc, $0020
    push hl
    or b
    db $e4
    nop
    ld hl, $5741
    ld b, c
    ld b, c
    ld b, b

jr_001_62e4:
    jr nz, jr_001_62e6

jr_001_62e6:
    jr nz, jr_001_62e9

    nop

jr_001_62e9:
    push hl
    or b
    sub b
    ld [hl], b
    ld d, b
    ld [hl], b
    sub c
    sub c
    db $e4
    ld bc, $e501
    or c
    db $e4
    ld bc, $4123
    ld b, c
    ld b, b
    jr nz, jr_001_62fe

jr_001_62fe:
    jr nz, jr_001_6301

    nop

jr_001_6301:
    push hl
    or b
    sub b
    ld [hl], b
    ld d, b
    ld [hl], b

jr_001_6307:
    sub c
    sub c
    db $e4
    ld bc, $e501
    or c
    db $e4
    ld bc, $0023
    push hl
    or b

jr_001_6314:
    sub c

jr_001_6315:
    ld [hl], c
    db $e4
    ld b, c
    push hl
    ld [hl], c
    db $e4
    ld b, c
    ld bc, $5141
    ld b, c

jr_001_6320:
    ld hl, $2000
    push hl
    or c
    db $e4
    ld bc, $7023
    ld b, b
    ld d, b
    jr nz, jr_001_636d

    nop
    jr nz, jr_001_6315

jr_001_6330:
    or b
    db $e4
    inc bc
    ld [hl], b
    ld b, b
    ld d, b
    jr nz, jr_001_6378

    nop
    jr nz, jr_001_6320

    or b
    db $e4
    ld bc, $2000
    ld b, c
    ld bc, $7053
    ld b, b
    ld d, b
    jr nz, jr_001_6388

    nop
    jr nz, jr_001_6330

    or b
    db $e4
    ld bc, $2000
    ld b, b
    jr nz, jr_001_6353

jr_001_6353:
    jr nz, jr_001_63a6

    ld d, c
    ld b, c
    ld b, c
    ld hl, $5341
    call c, Call_001_77b6
    ld b, a
    sub a
    ld d, a
    or a
    ld [hl], a
    call c, $e3c3
    ld bc, $e401
    or c
    or c
    sub b
    ld [hl], b

jr_001_636d:
    sub c
    or c
    ld [hl], c
    db $e3
    ld bc, $2000
    nop
    db $e4
    or b
    sub b

jr_001_6378:
    ld [hl], b
    ld b, b
    ld d, b
    ld [hl], c
    ld bc, $9071
    ld [hl], b
    ld d, b
    ld [hl], b
    sub c
    or c
    sub c
    ld [hl], c
    ld d, c
    ld b, c

jr_001_6388:
    jr nz, @+$42

    ld d, c
    ld b, b
    ld d, b
    ld [hl], c
    ld d, b
    ld [hl], b
    sub c
    or c
    ld [hl], c
    ld [hl], b
    ld d, b
    ld b, b
    jr nz, jr_001_6399

    push hl

jr_001_6399:
    or c
    sub c
    db $e4
    ld hl, $b1e5
    db $e4
    ld hl, $7747
    ld b, c
    ld b, c
    ld b, b

jr_001_63a6:
    jr nz, jr_001_63a8

jr_001_63a8:
    jr nz, jr_001_63ab

    nop

jr_001_63ab:
    push hl
    or b
    sub b
    ld [hl], b
    ld d, b
    ld [hl], b
    sub c
    sub c
    db $e4
    ld bc, $e501
    or c
    db $e4
    ld bc, $0123
    push hl
    ld [hl], c
    db $e4
    ld bc, $2141
    push hl
    ld [hl], c
    db $e4
    ld hl, $4151
    nop
    jr nz, jr_001_640c

    ld d, c
    ld b, c
    ld bc, $4123
    ld bc, $7141
    ld d, c
    ld bc, $0141
    ld hl, $71e5
    db $e4
    ld hl, $4351
    inc hl
    cp $00
    sbc a
    ld h, d
    call c, $ea10
    ld [$c326], sp
    rst $08
    rst $08
    call c, $ea10
    ld [$cf26], sp
    rst $08
    rst $08
    set 4, [hl]
    or b
    push hl
    nop
    jr nz, @-$18

    or b
    push hl
    ld bc, $71e6
    push hl
    ld bc, $2141
    ld [hl], c
    ld bc, $2041
    nop
    and $b0
    push hl
    nop

jr_001_640c:
    and $b1
    push hl
    ld bc, $7323
    rst $08
    rst $08
    ld b, c
    ld bc, $7141
    ld d, e
    ld b, e
    ld [hl+], a
    ret nz

    jr nz, jr_001_641e

jr_001_641e:
    and $b0
    push hl
    nop
    inc hl
    ld [hl], e
    rst $08
    rst $08
    rst $08
    ld d, c
    ld b, c
    jr nz, jr_001_642b

jr_001_642b:
    and $b0
    push hl
    nop
    inc hl
    ld d, b
    ld [hl], b
    sub b
    or b
    db $e4
    nop
    ret nz

    nop
    ret nz

    nop

jr_001_643a:
    push hl
    or b
    sub b
    or b
    db $e4
    ld bc, $4121
    ld bc, $0323
    push hl
    or c
    sub c
    ld [hl], c
    or c
    db $e4
    ld bc, $70c5
    ld b, b
    ld d, b
    jr nz, jr_001_6492

    nop
    jr nz, jr_001_643a

    or b
    db $e4
    inc bc
    set 1, e
    ld bc, $b1e5
    sub c
    ld [hl], c
    ld d, c
    ld [hl], c
    sub e
    or c
    ld [hl], c
    db $e4
    nop
    jr nz, jr_001_64a8

    ld d, b
    ld [hl], a
    ld [$4608], a
    ld [hl], e
    ld [$2608], a
    jr nz, jr_001_64b3

    ld d, b
    ld [hl], b
    sub a
    ld [$4608], a
    sub e
    ld [$2608], a
    ld b, b
    ld d, b
    ld [hl], b
    sub b
    or e
    sub c
    or c
    ld [hl], c
    or c
    db $e3
    rlca
    db $e4
    or a
    sub a
    ld [hl], a
    ld d, a
    ld b, a
    daa
    ld [hl], a
    nop
    ret nz

jr_001_6492:
    nop
    ret nz

    push hl
    or b
    ret nz

    or b
    ret nz

    sub b
    ld [hl], b
    sub c
    or c
    ld [hl], c
    db $e4
    nop
    ret nz

    nop
    jr nz, jr_001_64a4

jr_001_64a4:
    push hl
    or b
    sub b
    ld [hl], b

jr_001_64a8:
    ld b, b
    ld d, b
    ld [hl], c
    ld bc, $9071
    ld [hl], b
    ld d, b
    ld [hl], b
    sub c
    or c

jr_001_64b3:
    sub c
    ld [hl], c
    ld d, c
    ld b, c
    jr nz, @+$42

    ld d, c
    ld b, b
    ld d, b
    ld [hl], c
    ld d, b
    ld [hl], b
    sub c
    or c
    db $e4
    ld hl, $2707
    ld b, a
    ld d, a
    ld [hl], a
    ld d, e
    ld b, e
    daa
    ld b, e
    ld d, e
    cp $00
    ei
    ld h, e
    call c, $cfc3
    rst $08
    call c, GAME_MODE_FLAG
    pop af
    rst $00
    pop af
    rst $00
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $02
    ldh a, [$ff64]
    pop af
    rst $00
    pop af
    rst $00
    cp $02
    db $fc
    ld h, h
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $02
    inc b
    ld h, l
    pop af
    rst $00
    pop af
    rst $00
    pop af
    rst $00
    pop af
    jp $c3f1


    pop af
    rst $00
    pop af
    rst $00
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    rst $00
    pop af
    rst $00
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $04
    ld [hl], $65
    pop af
    rst $00
    pop af
    rst $00
    pop af
    rst $00
    pop af
    jp $c3f1


    pop af
    rst $00
    pop af
    jp $c3f1


    pop af
    rst $00
    pop af
    rst $00
    cp $04
    ld d, d
    ld h, l
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $04
    ld e, d
    ld h, l
    pop af
    rst $00
    pop af
    rst $00
    cp $02
    ld l, [hl]
    ld h, l
    pop af
    rst $00
    pop af
    jp $c3f1


    pop af
    rst $00
    pop af
    jp $c3f1


    cp $00
    ldh a, [$ff64]
    db $ed
    nop
    add b
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    ld [$2307], a
    add sp, -$24
    or d
    db $e4
    ld b, b
    ld h, b
    ld b, b
    ld h, b
    ld b, b
    ld h, b
    ld b, b
    ld h, b
    ld b, c
    push hl
    or c
    db $e4
    ld de, $e531
    or d
    db $e4
    db $10
    ld sp, $b1e5
    db $e4
    ld b, e
    ld b, e
    db $ed
    nop
    add b
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    ld [$2307], a
    add sp, -$24
    or d
    push hl
    add c
    add e
    or c
    db $e4
    ld b, e
    ld [hl-], a
    db $10
    push hl
    or c
    ld h, e
    db $e4
    sub c
    ld h, c
    db $e3
    ld b, c
    inc sp
    push hl
    or c
    or e
    ld h, c
    sub e
    ld h, d
    sub b
    add e
    sub e
    or c
    sub c
    add c
    ld h, c
    add c
    ld b, e
    or c
    db $e4
    ld b, e
    ld [hl-], a
    db $10
    push hl
    or c
    ld h, e
    db $e4
    sub c
    ld h, c
    db $e3
    ld b, c
    inc sp
    push hl
    or c
    or e
    ld h, c
    sub e
    ld h, d
    sub b
    or e
    sub e
    add e
    add e
    pop bc
    add e
    add e
    add e
    add c
    pop bc
    sub e
    sub e
    sub b
    sub d
    sub c
    pop bc
    sub e
    sub c
    or c
    sub c
    add c
    ld h, e
    add b
    add d
    sub c
    or c
    db $e4
    ld de, $e511
    or c
    ld b, e
    db $e4
    dec d
    inc de
    ld de, $33e5
    db $e4
    dec [hl]
    inc sp
    ld sp, $43c1
    ld b, d
    jr nc, jr_001_665e

    ld h, c
    ld b, c
    ld l, a
    call c, $c192
    push hl
    ld b, e
    ld b, e
    ld b, e
    ld b, c
    ld h, c
    ld h, e
    ld h, e
    ld h, e
    ld h, c
    add c
    add e
    add e
    add e
    add c
    ld l, a
    ld b, c
    ld b, e
    ld b, e
    ld b, e
    ld b, c
    ld h, c
    ld h, e
    ld h, e
    ld h, e
    ld h, c
    add c
    add e
    add e
    add e
    add c
    or c
    or e
    db $e4
    dec [hl]
    sub $b3
    push hl
    or b
    db $e4
    db $10
    jr nz, @+$32

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    call c, $87b3
    ld h, a
    ld b, a
    ld h, a
    add e
    ld h, e
    add e
    ld h, e
    ld b, e
    ld h, e

jr_001_665e:
    add e
    ld h, e
    add e
    ld h, e
    add e
    ld h, e
    ld b, e
    ld h, e
    add e
    ld h, e
    ld b, c
    push hl
    or e
    db $e4
    ld b, c
    add e
    ld h, e
    ld b, c
    ld h, e
    ld b, c
    inc sp
    ld b, e
    call c, $e5b5
    sub a
    ld b, a
    db $e4
    scf
    push hl
    ld h, a
    call c, $cf83
    rst $08
    rst $08
    rst $08
    pop bc
    or l
    add e
    ld h, e
    pop bc
    sub l
    ld h, e
    sub e
    pop bc
    add l
    ld b, e
    ld h, e
    pop bc
    ld h, l
    ld h, e
    add e
    call c, $cfb3
    rst $08
    rst $08
    rst $08
    pop bc
    or l
    or e
    or e
    pop bc
    db $e4
    dec d
    inc de
    inc de
    pop bc
    ld b, l
    ld b, e
    ld b, e
    dec [hl]
    ld sp, $3333
    push hl
    or c
    db $e4
    ld sp, $e511
    or c
    db $e4
    ld sp, $3111
    ld b, c
    ld b, c
    ld sp, $3111
    ld b, c
    ld sp, $3111
    ld h, c
    ld b, c
    ld sp, $6141
    ld b, c
    ld h, c
    add c
    or c
    sub c
    add c
    ld h, e
    add c
    add e
    rst $00
    push hl
    ld b, e
    inc sp
    inc de
    and $b3
    sub e
    add e
    push hl
    ld b, e
    inc sp
    inc de
    and $b3
    sub e
    add e
    ld h, e
    inc sp
    cp $00
    or a
    ld h, l
    db $ec
    ld [bc], a
    ld [$2406], a
    call c, $e4c2
    or l
    db $e3
    ld de, $b1e4
    sub c
    add c
    ld h, c
    ld b, c
    ld h, c
    add c
    ld h, c
    or e
    or e
    db $ec
    ld [bc], a
    ld [$2406], a
    call c, $dcc2
    jp nz, Jump_001_41e4

    push hl
    or e
    db $e4
    ld b, c
    add e
    ld h, d
    ld b, b
    ld sp, $b3e5
    db $e3
    ld de, $b1e4
    db $e3
    add c
    ld h, e
    db $e4
    ld sp, $e563
    or c
    db $e4
    inc de
    ld [hl-], a
    ld h, b
    ld b, l
    ld h, c
    add a
    ld b, c
    push hl
    or e
    db $e4
    ld b, c
    add e
    ld h, d
    ld b, b
    ld sp, $b3e5
    db $e3
    ld de, $b1e4
    db $e3
    add c
    ld h, e
    db $e4
    ld sp, $e563
    or c
    db $e4
    inc de
    ld [hl-], a
    ld h, b
    ld b, l
    push hl
    or c
    db $e4
    ld b, c
    db $ec
    ld bc, $c3dc
    and $b1
    push hl
    ld de, $4531
    ld sp, $4313
    dec [hl]
    ld b, c
    ld h, a
    inc sp
    ld h, e
    ld sp, $b1e6
    push hl
    ld de, $4531
    ld h, c
    add a
    sub e
    ld [de], a
    ld b, b
    sub a
    add e
    and $b2
    push hl
    ld b, b
    add a
    ld h, d
    ld d, b
    ld h, c
    add c
    sub c
    add c
    sub c
    db $e4
    ld de, $b3e5
    db $ec
    ld [bc], a
    sub $b1
    or c
    sub b
    add b
    ld h, b
    ld b, b
    jr nc, jr_001_678c

    and $b7
    call c, $e5a2
    or d
    sub b
    add l
    add e
    add e
    add c
    sub l
    sub e
    sub c
    or c
    sub c

jr_001_678c:
    or c
    or e
    or e
    or e
    or c
    db $e4
    ccf
    pop bc
    push hl
    add e
    add e
    add c
    sub c
    add c
    pop bc
    sub e
    sub e
    sub c
    or c
    sub c
    pop bc
    or e
    or e
    or c
    db $e4
    ld de, $b1e5
    db $e4
    ld sp, $6131
    ld l, c
    call c, $e3a3
    ld b, e
    ld b, c
    db $e4
    or c
    db $e3
    inc sp
    ld sp, $b1e4
    db $e3
    inc de
    ld de, $b1e4
    db $e3
    inc sp
    ld sp, $b1e4
    db $e3
    ld b, e
    ld b, c
    db $e4
    or c
    db $e3
    inc sp
    ld sp, $b1e4
    db $e3
    inc de
    ld de, $b1e4
    db $e3
    inc sp
    ld sp, $b1e4
    db $e3
    ld b, e
    ld b, c
    db $e4
    or c
    db $e3
    inc sp
    ld sp, $b1e4
    db $e3
    inc de
    ld de, $b1e4
    db $e3
    inc sp
    ld sp, $b1e4
    db $e3
    ld b, e
    ld b, c
    db $e4
    or c
    db $e3
    inc sp
    ld sp, $b1e4
    db $e3
    inc de
    ld de, $b1e4
    db $e3
    inc sp
    ld sp, $b1e4
    call c, Process2Player
    rla
    push hl
    or a
    or a
    call c, $e4c3
    ld b, l
    ld sp, $e511
    or c
    db $e4
    ld de, $91e5
    db $e4
    dec [hl]
    ld de, $b1e5
    db $e4
    ld de, $6131
    ld b, c
    ld sp, $e511
    or c
    sub c
    add c
    sub c
    db $e4
    ld de, $b3e5
    db $e4
    inc de
    ld sp, $3111
    push hl
    or c
    db $e4
    ld b, l
    ld sp, $e511
    or c
    db $e4
    ld de, $91e5
    db $e4
    dec [hl]
    ld de, $b1e5
    db $e4
    ld de, $6131
    ld b, c
    ld sp, $e511
    or c
    sub c
    add c
    sub c
    db $e4
    ld de, $b3e5
    db $e4
    inc de
    ld sp, $3111
    push hl
    or c
    db $e4
    ld b, l
    ld sp, $e511
    or c
    db $e4
    ld de, $91e5
    db $e4
    dec [hl]
    ld de, $b1e5
    db $e4
    ld de, $6131
    ld b, c
    ld sp, $e511
    or c
    sub c
    add c
    sub c
    db $e4
    ld de, $6383
    add c
    ld h, c
    ld b, c
    ld sp, $85c1
    add e
    add e
    pop bc
    sub l
    sub e
    sub e
    pop bc
    or l

jr_001_6881:
    or e
    or e
    ld h, l
    ld h, c
    sub e
    db $e3
    inc de
    db $e4
    add l
    add l
    add e
    sub l
    sub l
    sub e
    or l
    or l
    or e
    db $e3
    ld sp, $3111
    ld h, e
    db $e4
    or c
    db $e3

jr_001_689a:
    ld b, c
    db $e4
    db $10
    jr nc, @+$45

    inc sp
    inc de
    push hl
    or e
    sub e
    add e
    ld h, e
    ld b, e
    db $e4
    ld b, e
    inc sp
    inc de
    push hl
    or e
    sub e
    add e
    ld h, e
    or e
    cp $00
    nop
    ld h, a
    call c, $cf10

jr_001_68b8:
    ret


    push hl
    or b
    ret nz

    db $e4
    db $10
    ret nz

    jr nc, jr_001_6881

    call c, $e410
    ld b, b
    ret nz

    ld b, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    add b
    ret nz

    ld b, b
    ret nz

jr_001_68d0:
    or b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    jr nc, jr_001_689a

    push hl
    or b
    call nz, $00eb
    ld l, e
    or b
    jp nz, $00eb

jr_001_68e4:
    ld l, e
    or b
    jp nz, Jump_000_30e4

    ret nz

jr_001_68ea:
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    jr nc, @-$3e

    db $10
    ret nz

    jr nc, @-$3e

    jr nc, jr_001_68b8

    push hl
    or b
    ret nz

    db $e4

jr_001_68fc:
    ld b, b
    ret nz

    ld b, b
    ret nz

    push hl
    or b

jr_001_6902:
    ret nz

    db $e4
    ld b, b
    jr nc, @+$42

    ret nz

    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    jr nc, jr_001_68d0

    ld b, b
    ret nz

    push hl
    or b
    ret nz

    or b
    ret nz

    db $e4
    add b
    ret nz

    ld b, b
    ret nz

    or b
    ret nz

    ld b, b
    ld d, b
    ld h, b
    ld b, b
    jr nc, jr_001_68e4

    jr nc, jr_001_68ea

    push hl
    db $eb
    nop
    ld l, e
    or b
    jp nz, $00eb

    ld l, e
    or b
    jp nz, Jump_000_30e4

    ret nz

    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    jr nc, jr_001_68fc

    db $10
    ret nz

    jr nc, jr_001_6902

    jr nc, jr_001_6902

    ld b, b
    jp nz, $b0e5

    jp nz, Jump_001_40e4

    jp nz, $c240

    push hl
    add b
    ret nz

    or b
    ret nz

    add b
    ret nz

    or b
    ret nz

    add b
    ret nz

    or b
    ret nz

    add b
    ret nz

    or b
    ret nz

    sub b
    ret nz

    db $e4
    db $10
    ret nz

    push hl
    sub b
    add b
    ld h, b
    add b
    sub b
    ret nz

    db $e4
    db $10
    ret nz

jr_001_696c:
    push hl
    sub b
    ret nz

    db $e4

jr_001_6970:
    db $10
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    db $10
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    db $10
    ret nz

    push hl
    sub b
    ret nz

    ld h, b
    ret nz

    ld h, b
    ret nz

    sub b
    ret nz

    add b
    ret nz

    or b
    ret nz

    add b
    ret nz

    or b
    ret nz

    add b
    sub b
    or b
    sub b
    add b
    ret nz

    or b
    add $90
    db $e4
    db $10

jr_001_699a:
    push hl
    sub b
    ret nz

    db $e4
    ld b, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld b, b
    add $e5
    add b
    or b
    db $e4
    jr nc, jr_001_696c

    or b
    ret nz

    jr nc, jr_001_6970

    or b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    db $10
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    db $10
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    db $10

jr_001_69c3:
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    db $10

jr_001_69c9:
    ret nz

    jr nc, jr_001_699a

    call c, $e311
    ld b, b
    ret nz

    db $e4
    or b
    jp nz, Jump_001_40e3

    ret nz

    add b
    ret nz

    sub b
    jp nz, $c080

    ld h, b
    ret nz

    db $10
    jp nz, $c060

    sub b
    ret nz

    or b
    jp nz, $c090

    add b
    ret nz

    sub b
    jp nz, $c0b0

    ldh [c], a
    db $10
    ret nz

    db $e3
    or b

jr_001_69f4:
    jp nz, $10e2

    ret nz

jr_001_69f8:
    db $e3
    sub b
    ret nz

    add b
    ret nz

    ld h, b
    ret nz

    ld b, b
    ret nz

    jr nc, jr_001_69c3

    ld b, b
    ret nz

    ld h, b
    ret nz

    jr nc, jr_001_69c9

    ld b, b
    ret nz

    db $e4
    or b
    jp nz, Jump_001_40e3

    ret nz

    add b
    ret nz

    sub b
    jp nz, $c080

    ld h, b
    ret nz

    db $10
    jp nz, $c060

    sub b
    ret nz

    or b
    jp nz, $c090

    add b
    ret nz

    sub b
    jp nz, $c0b0

    ldh [c], a
    db $10
    ret nz

    db $e3
    or b
    jp nz, $10e2

    ret nz

    jr nc, jr_001_69f4

    db $10
    ret nz

    jr nc, jr_001_69f8

    db $e3
    or b
    ret z

    call c, $e410
    add a
    or a
    sub a
    db $e3
    scf
    db $e4
    add a
    or a
    sub a
    db $e3
    scf
    db $e4
    add e
    or e
    ld b, e
    or e
    sub c
    add c
    ld h, c
    ld b, c
    ld sp, $6141
    ld sp, $6181
    ld b, c
    add c
    or c
    sub c
    add c
    ld h, c
    ld b, c
    ld h, c
    add c
    sub c
    or c
    sub c
    add c
    ld h, c
    jp Jump_001_40e5


    ld h, b
    add b
    sub b
    or b
    db $e4
    db $10
    jr nz, jr_001_6aa1

    ld b, b
    add $e5
    ld h, b
    add b
    sub b
    or b
    db $e4
    db $10
    jr nc, jr_001_6abc

    ld d, b
    ld h, b
    call nz, $c183
    add e
    ld b, e
    pop bc
    ld h, e
    pop bc
    ld h, e
    inc sp
    pop bc
    ld b, e
    pop bc
    ld b, e
    inc de
    pop bc
    inc sp
    pop bc
    inc sp
    ld h, e
    pop bc
    add e
    pop bc
    ld b, e
    ld b, e
    pop bc
    ld h, e
    pop bc
    inc sp
    ld h, e
    pop bc
    ld b, e
    pop bc
    inc de
    ld b, e

jr_001_6aa1:
    pop bc
    inc sp
    pop bc
    inc sp
    inc sp
    ld b, c
    add e
    or c
    add e
    ld b, e
    ld sp, $9163
    ld h, e
    inc sp
    ld de, $8143
    ld b, e
    inc de
    ld sp, $e393
    ld de, $b3e4
    sub e

jr_001_6abc:
    ld b, c
    push hl
    or e
    db $e4
    ld b, c
    add e
    ld h, d
    ld b, b
    ld h, c
    inc de
    ld h, c
    sub e
    add d
    ld h, b
    add c
    sub e
    or c
    db $e3
    ld de, $b3e4
    db $e3

jr_001_6ad2:
    ld de, $11e4
    inc sp
    ld b, c
    ld h, e
    inc sp
    ld b, c
    push hl
    or e
    db $e4
    ld b, c
    add e
    ld h, d
    ld b, b
    ld h, c
    inc de
    ld h, c
    sub e
    add d
    ld h, b
    add c
    sub e
    or c
    db $e3
    ld de, $b3e4
    db $e3
    ld de, $1131
    ld sp, $b1e4
    pop bc
    db $e3
    ld b, b
    ret nz

    ld b, b
    rst $08
    jp nz, Check2PGameState

    inc sp
    inc de
    and $b3
    db $e4
    add e
    ld h, e
    ld b, e
    inc sp
    inc de
    push hl
    or e
    pop bc
    or b
    ret nz

    db $e4
    db $10
    ret nz

    jr nc, jr_001_6ad2

    cp $00
    jp $dc68


    rst $08
    rst $08
    call c, $c0f1
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop bc
    sub $f1
    ret nz

    pop af
    jp nz, $c0f1

    pop af
    jp nz, $c0f1

    pop af
    jp nz, $c0f1

    pop af
    jp nz, $c1dc

    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $02
    ld b, d
    ld l, e
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop bc
    sub $f1
    ret nz

    pop af
    jp nz, $c0f1

    pop af
    jp nz, $c0f1

    pop af
    jp nz, $c0f1

    pop af
    jp nz, $c1dc

    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    jp $c3f1


    pop af
    jp $c1f1


    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $04
    sbc b
    ld l, e
    pop af
    rst $00
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $02
    xor h
    ld l, e
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    rst $08
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $03
    call z, $f16b
    rst $08
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $03
    jp c, $f16b

    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    rst $00
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $02
    rst $28
    ld l, e
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $06
    ei
    ld l, e
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $02
    rrca
    ld l, h
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $02
    dec de
    ld l, h
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $02
    daa
    ld l, h
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $02
    dec sp
    ld l, h
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $02
    ld b, a
    ld l, h
    pop af
    jp $c3f1


    pop af
    jp $c3f1


    cp $02
    ld e, e
    ld l, h
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $02
    ld h, a
    ld l, h
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $07
    ld a, e
    ld l, h
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    jp $c1f1


    pop af
    jp $c3f1


    pop af
    jp $c3f1


    pop af
    jp CheckPause2P


    sbc e
    ld l, h
    pop af
    jp $c3f1


    pop af
    jp $f1c0


    ret nz

    pop af
    ret nz

    pop af
    ret nz

    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    pop af
    pop bc
    cp $00
    ld a, [hl+]
    ld l, e
    db $ed
    nop
    add h
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    ld [$2307], a
    add sp, -$24
    or d
    push hl
    ld [hl], c
    ld [hl], b
    ld [hl], b
    ld [hl], e
    ret c

    or d
    pop bc
    ld [hl], c
    sub c
    or c
    db $e4
    ld bc, $2511
    call c, $e5b2
    or e
    db $e4
    inc bc
    push hl
    dec b
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    db $e4
    nop
    push hl
    or b
    db $e4
    nop
    push hl
    or b
    db $e4
    inc bc
    push hl
    sub b
    add b
    sub b
    add b
    sub e
    ld [hl], e
    ld [hl], e
    ld [hl], e
    ld [hl], e
    sub b
    add b
    sub b
    add b
    sub b
    and b
    db $e4
    ld bc, $a1e5
    sub c
    ld [hl], e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    db $e4
    nop
    push hl
    or b
    db $e4
    nop
    push hl
    or b
    db $e4
    inc bc
    ld d, b
    ld b, b
    ld d, b
    ld b, b
    ld d, e
    push hl
    ld [hl], e
    ld [hl], e
    ld [hl], e
    ld [hl], c
    db $e4
    ld bc, $4121
    ld hl, $9171
    and c
    ld [hl], e
    push hl
    ld [hl], e
    ld [hl], e
    db $e4
    nop
    jr nz, jr_001_6d79

    ld bc, $e529
    sub b
    and b
    db $e4
    ld bc, $71e5
    sbc a
    pop bc
    db $e4
    ld d, b
    ld b, b
    ld d, l
    ld [hl], b
    ld h, b
    ld [hl], e
    push hl
    sub c
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    db $e4
    ld d, b
    ld b, b
    ld d, l
    ld [hl], b
    ld h, b
    ld [hl], l
    push hl
    inc bc
    ld bc, $0191
    sub c
    inc bc
    inc hl
    ld hl, $01e4
    push hl
    ld b, c
    db $e4
    ld bc, $41e5
    ld d, l
    db $e4
    ld d, c
    ld bc, $a1e5
    sub c
    db $e4
    ld bc, $a5e5
    db $e4
    ld [hl], c
    ld b, c
    ld hl, $e501

jr_001_6d79:
    and c
    sub c
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    db $e4
    ld d, b
    ld b, b
    ld d, l
    ld [hl], b
    ld h, b
    ld [hl], e
    ld d, c
    push hl
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    sub e
    and e
    and e
    and e
    and e
    db $e4
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    nop
    ret nz

    push hl
    sbc a
    ret nz

    rst $08
    rst $08
    rst $08
    rst $08
    jp z, $fec5

    nop
    db $ec
    ld l, h
    db $fd
    db $dd
    ld l, l
    db $fd
    nop
    ld l, [hl]
    db $fd
    ld [hl+], a
    ld l, a
    db $fd
    ld c, [hl]
    ld l, a
    db $fd
    ld h, [hl]
    ld l, a
    cp $00
    or [hl]
    ld l, l
    call nc, $c0c1
    add sp, -$03
    db $dd
    ld l, l
    db $fd
    nop
    ld l, [hl]
    db $fd
    jr c, @+$71

    db $fd
    ld e, c
    ld l, a
    db $fd
    ld h, [hl]
    ld l, a
    cp $00
    call $ec6d
    ld [bc], a
    call c, $e4c1
    ld bc, $0000
    call c, $03c3
    ret c

    jp Jump_000_01c1


    ld hl, $5141
    ld h, c
    ld [hl], l
    or d
    sub b
    or b
    ld [hl], b
    call c, $e3c3
    inc bc
    push hl
    ld [hl], c
    db $ec
    inc bc
    db $e4
    ld bc, $dcff
    jp $92e4


    ld [hl], b
    ld d, c
    sub c
    ld [hl], c
    sub c
    and c
    db $e3
    ld hl, $c6dc
    rlca
    db $e4
    sub l
    call c, OAMDMACopyLoop
    ld [hl], d
    ld d, b
    ld b, c
    ld d, c
    call c, Call_001_71c2
    ld [hl], c
    call c, $91c3
    and c
    call c, $97c6
    db $e3
    dec b
    call c, $e4c3
    ld bc, $7092
    ld d, c
    sub c
    ld [hl], c
    sub c
    and c
    db $e3
    ld hl, $c6dc
    rlca
    ld d, a
    call c, ProcessSpriteFrame
    jr nz, jr_001_6e3c

    ld b, c

jr_001_6e3c:
    ld hl, $e401
    or c
    ld [hl], c
    call c, $e3c5
    dec c
    call c, $00c3
    db $10
    ld [hl+], a
    nop
    db $e4
    and c
    sub c
    call c, $e3c5
    dec b
    call c, $e4c3
    sub c
    and d
    sub b
    ld [hl], c
    ld d, c
    call c, Call_001_77c5
    call c, $91c2
    sub b
    call c, $a0c3
    db $e3
    ld bc, $a1e4
    sub c
    ld d, c
    db $e3
    ld bc, $93e4
    call c, $e3c1
    jr nz, @+$22

    dec h
    nop
    nop
    inc bc
    call c, $e4c2
    sub c
    sub b
    call c, $a0c3
    db $e3
    ld bc, $a1e4
    sub c
    ld d, c
    db $e3
    ld bc, $93e4
    call c, $e3c1
    jr nz, jr_001_6eae

    dec h
    ld b, b
    ld b, b
    ld b, e
    call c, ParseMusicCommand
    ld d, b
    ld b, b
    ld hl, $2101
    ld bc, $a1e4
    sub e
    call c, WaitDIVTimer
    ld b, b
    ld d, c
    ld hl, $4041
    ld d, b
    ld [hl], e
    call c, $e3c2
    ld bc, $dc00

jr_001_6eae:
    call nz, $a0e4
    sub c
    and c
    db $e3
    dec b
    db $e4
    sub c
    call c, $a1c2
    and b
    call c, $e3c4
    nop
    ld hl, $b1e4
    call c, $e3c6
    rlca
    call c, $e4c2
    sub c
    sub b
    call c, $a0c3
    db $e3
    ld bc, $a1e4
    sub c
    ld d, c
    db $e3
    ld bc, $93e4
    call c, $e3c1
    jr nz, jr_001_6efd

    dec h
    ld b, b
    ld b, b
    ld b, e
    db $ec
    ld [bc], a
    call c, LoadMusicTrack
    db $e4
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    ld d, e
    db $ec
    inc bc
    call c, SetupSpriteAnim
    sub d
    sub b
    sub c
    and c
    db $e3
    inc bc
    sub $c2
    db $e4
    ld b, b

jr_001_6efd:
    ld d, b
    ld [hl], b
    sub b
    and b
    db $e3
    nop
    jr nz, @+$42

    ld d, l
    ld b, c
    inc hl
    ld b, e
    sub $c6
    rrca
    sub $c3
    dec h
    ld bc, $a3e4
    db $e3
    inc hl
    ret c

    jp $e401


    and c
    db $e3
    ld bc, $a1e4
    db $e3
    ld bc, $a1e4
    rst $38
    db $e3
    ld bc, $0121
    ld hl, $2101
    ret c

    add $0b
    ret c

    jp $c1c1


    pop bc
    pop bc
    pop bc
    pop bc
    ret c

    add $cb
    rst $38
    ret c

    jp $c1c1


    pop bc
    pop bc
    pop bc
    pop bc
    ret c

    add $cb
    db $e3
    ld bc, $0121
    ld hl, $2101
    ret c

    add $0b
    rst $38
    ret c

    add $eb
    nop
    ld b, l
    ld e, a
    rst $00
    rst $08
    rst $08
    rst $08
    rst $38
    ret c

    add $cf
    db $e4
    db $eb
    nop
    ld d, l
    ld e, a
    db $e3
    rst $00
    rst $08
    rst $08
    rst $38

jr_001_6f66:
    ret c

    ret nc

    ld [$6000], a
    db $e4
    xor e
    ld [$0000], a
    call c, $e3d1
    rrca
    call c, $c0c1
    rst $08
    jp nz, $e401

    ld bc, $e8ff

jr_001_6f7e:
    sub $10
    db $e4
    ld b, d
    ret nz

    ld b, b
    ret nz

    ld b, b
    ret nz

jr_001_6f87:
    call c, LoadAnimData
    sla b
    jp nz, $c200

    push hl
    ld [hl], b
    jp nz, $c000

    db $e4
    nop
    ret nz

    push hl
    ld d, b

jr_001_6f99:
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld b, b
    ret nz

    db $e4
    nop
    ret nz

    push hl
    jr nz, jr_001_6f66

    db $e4
    nop
    ret nz

    push hl
    nop
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld d, b
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld b, b
    ret nz

    db $e4
    nop
    ret nz

    push hl
    jr nz, jr_001_6f7e

    db $e4
    nop
    ret nz

    push hl
    ld b, b
    ret nz

jr_001_6fc4:
    db $e4
    jr nz, jr_001_6f87

    push hl
    and b
    ret nz

    db $e4
    jr nz, @-$3e

    push hl
    sub b
    ret nz

    db $e4
    jr nz, @-$3e

    push hl
    ld [hl], b
    ret nz

    db $e4
    jr nz, jr_001_6f99

    push hl
    ld d, b
    ret nz

jr_001_6fdc:
    db $e4
    ld b, b
    ret nz

    nop
    ret nz

    ld b, b
    ret nz

    push hl
    sub b

jr_001_6fe5:
    ret nz

    db $e4
    ld b, b
    ret nz

    push hl
    ld [hl], b

jr_001_6feb:
    ret nz

    db $e4
    nop

jr_001_6fee:
    ret nz

    push hl
    nop

jr_001_6ff1:
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld d, b

jr_001_6ff7:
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld b, b
    ret nz

    db $e4
    nop
    ret nz

    push hl
    jr nz, jr_001_6fc4

    db $e4
    nop
    ret nz

    push hl
    nop
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld d, b
    ret nz

jr_001_7010:
    db $e4
    nop
    ret nz

jr_001_7013:
    push hl
    ld b, b
    ret nz

    db $e4
    nop
    ret nz

jr_001_7019:
    push hl
    jr nz, jr_001_6fdc

    db $e4
    nop
    ret nz

    push hl
    ld b, b
    ret nz

    db $e4
    jr nz, jr_001_6fe5

    push hl
    ld [hl], b
    ret nz

    db $e4
    jr nz, jr_001_6feb

    push hl
    jr nz, jr_001_6fee

    db $e4
    jr nz, jr_001_6ff1

    push hl
    ld d, b
    ret nz

    db $e4
    jr nz, jr_001_6ff7

    push hl
    nop
    ret nz

    db $e4
    ld b, b
    ret nz

    nop
    ret nz

    ld b, b
    ret nz

    push hl
    and b
    ret nz

    db $e4
    ld b, b
    ret nz

    push hl
    ld [hl], b
    ret nz

    db $e4
    ld b, b
    ret nz

    push hl
    jr nz, jr_001_7010

    db $e4
    jr nz, jr_001_7013

    push hl
    ld [hl], b

jr_001_7055:
    ret nz

    db $e4
    jr nz, jr_001_7019

    push hl
    nop
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld b, b
    ret nz

    db $e4
    nop
    ret nz

    and $a0
    ret nz

    push hl
    and b
    ret nz

    jr nz, @-$3e

    and b
    ret nz

    and $90
    ret nz

    push hl
    sub b
    sub b
    sub b
    ret nz

    ld [hl], b
    ret nz

    and $90
    ret nz

    push hl
    sub b

jr_001_707e:
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $50
    ret nz

    push hl
    sub b
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $a0
    ret nz

    push hl
    and b
    ret nz

    jr nz, jr_001_7055

    and b
    ret nz

    nop
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld [hl], b
    ret nz

    db $e4
    nop
    ret nz

    and $90
    ret nz

    push hl
    sub b

jr_001_70a7:
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $50
    ret nz

    push hl
    sub b
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $a0
    ret nz

    push hl
    and b
    ret nz

    jr nz, jr_001_707e

    and b
    ret nz

    nop
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld [hl], b
    ret nz

    db $e4
    nop
    ret nz

    and $90
    ret nz

    push hl
    sub b
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $50
    ret nz

    push hl
    sub b

jr_001_70da:
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $a0
    ret nz

    push hl
    and b
    ret nz

    jr nz, jr_001_70a7

    and b
    ret nz

    ld b, b
    ret nz

    db $e4
    nop
    ret nz

    push hl
    nop
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld d, b
    rst $08
    ret z

    ld b, b
    ld d, b
    ld [hl], b
    ret nz

    ld b, b
    ret nz

    and $90
    ret nz

    push hl
    sub b
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $50
    ret nz

    push hl
    sub b
    ret nz

    nop
    ret nz

    sub b
    ret nz

    and $a0
    ret nz

    push hl
    and b
    ret nz

    jr nz, jr_001_70da

    and b
    ret nz

    nop
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld [hl], b
    ret nz

    db $e4
    nop
    ret nz

    push hl
    ld d, b
    ret nz

    db $e4
    ld d, b
    ret nz

    nop
    ret nz

    ld d, b
    ret nz

    push hl
    and b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    ld d, b
    ret nz

    db $e4
    ld d, b
    ret nz

    nop
    ret nz

    ld d, b
    ret nz

jr_001_7147:
    push hl
    and b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    ld d, b
    ret nz

    db $e4
    ld d, b
    ret nz

    nop
    ret nz

    ld d, b
    ret nz

    push hl
    and b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    ld d, b
    ret nz

    db $e4
    ld d, b
    ret nz

    nop
    ret nz

    ld d, b
    ret nz

    push hl
    and b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    sub b
    ret nz

    db $e4
    ld d, b
    ret nz

    push hl
    ld [hl], b
    ret nz

    db $e4
    ld [hl], b
    ret nz

    jr nz, jr_001_7147

    ld [hl], b
    ret nz

    nop
    ret nz

    ld [hl], b
    ret nz

    push hl
    and b
    ret nz

    db $e4

    db $70, $c0, $e5, $00, $c0, $e4, $70, $c0, $e5, $40, $c0, $e4, $70, $c0, $e5, $70
    db $c0, $e4, $70, $c0, $e5, $a0, $c0, $e4, $70, $c0, $e5, $00, $c0, $e4, $70, $c0
    db $e5, $40, $c0, $e4, $70, $c0, $e5, $70, $c0, $e4, $70, $c0, $e5, $a0, $c0, $e4

    ld [hl], b

Call_001_71c2:
    ret nz

    push hl
    ld d, b
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    ret z

    ld bc, $4121
    cp $00
    sub d
    ld l, a
    db $fd
    ldh a, [c]
    ld [hl], c
    db $fd
    rla
    ld [hl], d
    db $fd
    ldh a, [$ff74]
    db $fd
    inc a
    ld [hl], l
    cp $00
    push de
    ld [hl], c
    db $fd
    ldh a, [c]

    db $71, $fd, $17, $72, $fd, $16, $75, $fd, $3c, $75, $fe, $00, $e5, $71, $dc, $c3
    db $d6, $b0, $0a, $b0, $06, $b0, $0a, $b0, $06, $b0, $0a, $b0, $06, $b0, $0a, $b0
    db $06, $b1, $05, $cd, $b1, $05, $c5, $b1, $05, $c3, $b1, $05, $b1, $05, $c5, $b1
    db $09, $c5, $ff, $d6, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1
    db $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $07
    db $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1
    db $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
    db $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $b1, $07, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $c1, $b1, $07, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1
    db $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1
    db $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07
    db $c1, $b1, $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
    db $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1
    db $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1
    db $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $b1, $07, $b1
    db $05, $c1, $b1, $07, $b1, $07, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1
    db $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05
    db $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1
    db $b1, $05, $c1, $b1, $07, $c1, $b1, $05, $c1, $b1, $05, $c1, $b1, $08, $cf, $cf
    db $cd, $b1, $08, $c9, $b1, $07, $c1, $b1, $05, $c1, $b1, $07, $c1, $b1, $05

Call_001_73b3:
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c

Jump_001_73c1:
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    rlca
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    or c
    rlca
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc

    or c
    rlca
    or c
    rlca
    or c
    dec b
    pop bc
    or c
    rlca
    or c
    rlca
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    rlca
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    or c
    rlca
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    rlca
    or c
    rlca
    or c
    dec b
    pop bc
    or c
    rlca
    pop bc
    or c
    dec b
    pop bc
    or c
    dec b
    pop bc
    or c
    dec b
    or c
    dec b
    pop bc
    or c
    dec b
    or c
    dec b
    pop bc
    or c
    dec b
    or c
    dec b
    or c
    dec b
    push bc
    or c
    dec b
    pop bc
    or c
    dec b
    or c
    dec b
    or c
    dec b
    pop bc
    or c
    dec b
    pop bc
    or c
    dec b
    pop bc
    or c
    dec b
    pop bc
    or c
    dec b
    push bc
    ret c

    or c
    dec b
    or c
    inc b
    or c
    dec b
    or c
    dec b
    jp Jump_000_05b1


    or c
    inc b
    or c
    dec b
    or c
    dec b
    jp $b0d6


    ld a, [bc]
    or b
    ld b, $b0
    ld a, [bc]
    or b
    ld b, $b0
    ld a, [bc]
    or b
    ld b, $b0
    ld a, [bc]
    or b
    ld b, $b0
    ld a, [bc]
    or b
    ld b, $b0
    ld a, [bc]
    or b
    ld b, $b0
    ld a, [bc]
    or b
    ld b, $b0
    ld a, [bc]
    or b
    ld b, $b1
    dec b
    pop bc
    or c
    dec b
    ret


    rst $38
    or c
    dec b
    push bc
    or c
    rlca
    push bc
    or c
    dec b
    pop bc
    or c
    rlca
    push bc
    or c
    dec b
    pop bc
    ret c

    or c
    dec b
    or c
    rlca
    or c
    dec b
    or c
    rlca
    or c
    dec b
    or c
    rlca
    call c, MultiplyAddStep
    jp nz, $09b0

    ret nz

    or b
    rlca
    rst $38
    or c
    rlca
    push bc
    or c
    dec b
    push bc
    or c
    rlca
    pop bc
    or c
    dec b
    push bc
    or c
    rlca
    pop bc
    ret c

    or c
    rlca
    or c
    dec b
    or c
    rlca
    or c
    dec b
    or c
    rlca
    or c
    dec b
    call c, MultiplyAddStep
    jp nz, $09b0

    ret nz

    or b
    rlca
    rst $38
    ret nz

    rst $38
    db $ed
    nop
    add b
    ldh a, [rPCM34]
    ld [$2618], a
    db $ec
    ld [bc], a
    add sp, -$24
    or c
    db $e4
    ld bc, $0000
    call c, JoypadStuckCheck
    ld d, c
    call c, $97b0
    call c, $9fb7
    call c, $e392
    db $eb
    nop
    add hl, de
    sub c
    rst $00
    rst $38
    ld [$2710], a
    db $ec
    ld [bc], a
    call c, $e4c1
    ld d, c
    ld d, b
    ld d, b
    call c, $51c3
    sub c
    call c, $e3c0
    rlca
    call c, $0fc7
    call c, $e2b3
    db $eb
    nop
    nop
    ld bc, $dcff
    db $10
    db $e4
    sub b
    ret nz

    sub $10
    sub b
    ret nz

    sub b
    ret nz

    call c, $9010
    ret nz

    db $e3
    nop
    ret nz

    db $e4
    sub e
    jp $e3cf


    db $eb
    nop
    db $10
    ld bc, $dcff
    rst $08
    sub $b0
    dec c
    or b
    dec c
    or b
    inc c
    or b
    inc c
    or b
    dec bc
    or b
    dec bc
    or b
    dec bc
    or b
    dec bc
    or b
    ld b, $b0
    ld b, $b0
    ld b, $b0
    ld b, $b0
    ld b, $b0
    ld b, $b0
    ld b, $b0
    ld b, $b0
    ld a, [bc]
    or b
    ld a, [bc]
    or b
    ld a, [bc]
    or b
    ld a, [bc]
    or b
    ld a, [bc]
    or b
    ld a, [bc]
    or b
    ld a, [bc]
    or b
    ld a, [bc]
    ret c

    or c
    dec b
    or c
    dec b
    or c
    dec b
    or c
    add hl, bc
    rst $38
    db $ed
    nop
    add b
    ld [$230a], a
    add sp, -$14
    ld [bc], a
    call c, $e5b3
    sub c
    sub b
    and b
    db $e4
    dec b
    ld bc, $91e5
    db $e4
    ld bc, $4121
    ld d, c
    ld [hl], c
    sub a
    rst $38
    db $ec
    ld [bc], a
    ld [$2408], a
    call c, $e4c3
    ld d, c
    ld d, b
    ld d, b
    ld d, l
    ld d, c
    ld [hl], c
    sub c
    and d
    db $e3
    nop
    ld hl, $5741
    rst $38
    call c, $e510
    ld d, c
    ld d, b
    ld b, b
    ld d, l
    ld bc, $4121
    ld d, d
    ld [hl], b
    sub c
    ld [hl], c
    ld d, e
    jp $edff


    nop
    add b
    ld [$230c], a
    db $ec
    ld [bc], a
    db $d3
    sub e
    ret nz

    call c, $e593
    sub c
    sub b
    and b
    db $e4
    dec b
    ld bc, $91e5
    db $e4
    ld bc, $4121
    ld d, c
    ld [hl], c
    sub a
    rst $38
    db $ec
    ld [bc], a
    add sp, -$16
    ld a, [bc]
    inc h
    db $d3
    and e
    ret nz

    call c, $e4a3
    ld d, c
    ld d, b
    ld d, b
    ld d, l
    ld d, c
    ld [hl], c
    sub c
    and d
    db $e3
    nop
    ld hl, $5741
    rst $38
    db $d3
    db $10
    ret nz

    call c, $e510
    ld d, c
    ld d, b
    ld b, b
    ld d, l
    ld bc, $4121
    ld d, d
    ld [hl], b
    sub c
    ld [hl], c
    ld d, e
    jp $edff


    nop
    add b
    add sp, -$16
    add hl, bc
    inc h
    db $ec
    ld [bc], a
    call c, $fdb3
    sub b
    db $76
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    sub b
    db $76
    call c, $fd93
    push de
    db $76
    call c, $fdb3
    sub b
    db $76
    call c, $fd93
    db $f4
    db $76
    cp $00
    ld [hl], c
    db $76
    db $e4
    ld [bc], a
    push hl
    sub b
    db $e4
    ld bc, $4353
    ld hl, $7b43
    push hl
    and d
    ld [hl], b
    db $e4
    ld bc, $2343
    ld b, c
    ld d, e
    dec bc
    rst $38
    db $ec
    ld [bc], a
    ld [$230b], a
    call c, $fdc2
    push de
    db $76
    call c, $e6c1
    ld d, e
    inc bc
    inc hl
    ld b, e
    ld [hl], e
    inc bc
    inc hl
    inc bc
    ld b, e
    inc bc
    inc hl
    ld b, e
    ld d, e
    inc bc
    inc hl
    ld b, e
    call c, $fdc2
    push de
    db $76
    db $fd
    push de
    db $76
    db $fd
    ld [bc], a
    ld [hl], a
    db $fd
    db $f4
    db $76
    cp $00
    xor e
    db $76
    db $e4
    ld d, d
    sub b
    db $e3
    ld bc, $0323
    db $e4
    sub c
    and e
    db $e3
    ld bc, $00e4
    push hl
    or b
    db $e4
    ld bc, $a1e5

jr_001_76e9:
    ld [hl], e
    db $e4
    ld b, d
    ld [hl], b
    sub c
    and e
    sub e
    ld [hl], c
    sub e
    ld e, e
    rst $38
    rst $08
    push bc
    db $e4
    nop
    push hl
    or b
    db $e4
    ld bc, $a1e5
    ld [hl], e
    rst $08
    rst $08
    rst $38
    db $e4
    ld d, d
    sub b
    db $e3
    ld bc, $0323
    db $e4
    sub c
    and e
    db $e3
    ld bc, $e4c9
    ld b, d
    ld [hl], b
    sub c
    and e
    sub e
    ld [hl], c
    sub e
    ld e, e
    rst $38
    call c, $fd10
    ld h, b
    ld [hl], a
    db $e3
    ld d, b
    pop bc
    sub b
    ldh [c], a
    nop
    ret nz

    jr nz, jr_001_76e9

    nop
    jp nz, $90e3

    ret nz

    and b
    jp nz, $00e2

    ret nz

    db $e3
    nop
    db $e4
    or b
    db $e3
    nop
    ret nz

    db $e4
    and b
    ret nz

    ld [hl], b
    jp nz, Jump_001_40e3

    pop bc
    ld [hl], b
    sub b
    ret nz

    and b
    jp nz, $c290

    ld [hl], b
    ret nz

    sub b
    jp nz, $ca50

    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    ld h, b
    ld [hl], a
    cp $00
    add hl, de
    ld [hl], a
    db $e4
    ld d, b
    jp nz, $c200

    jr nz, @-$3c

    ld b, b
    jp nz, $c270

    nop
    jp nz, $c220

    nop
    jp nz, $c240

    nop
    jp nz, $c220

    ld b, b
    jp nz, $c250

    nop
    jp nz, $c220

    ld b, b
    jp nz, $dcff

    db $fd
    sbc e
    ld [hl], a
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    sbc e
    ld [hl], a
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    jp z, $fd77

    or [hl]
    ld [hl], a
    cp $00
    add e
    ld [hl], a
    or e
    ld c, $b1
    inc bc
    or c
    inc bc
    or e
    ld c, $b3
    inc bc
    or c
    ld c, $b1
    inc bc
    or c
    inc bc
    or c
    inc bc
    or e
    ld c, $b3
    inc bc
    cp $02
    sbc e
    ld [hl], a
    rst $38

Call_001_77b6:
    or e
    ld c, $c1
    pop bc
    or e
    ld c, $c3
    or c
    ld c, $c1
    pop bc
    pop bc
    or e
    ld c, $c3

Call_001_77c5:
    cp $02
    or [hl]
    ld [hl], a
    rst $38
    jp Jump_000_03b1


    or c
    inc bc
    jp $03b3


    pop bc
    or c
    inc bc
    or c
    inc bc
    or c
    inc bc
    jp $03b3


    cp $02
    jp z, $ff77

    db $ed
    nop
    add b
    ld [$240c], a
    db $ec
    ld [bc], a
    call c, $fdb3
    ld b, $78
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    ld b, $78
    call c, $fd93
    ld c, h
    ld a, b
    db $fd
    ld l, e
    ld a, b
    call c, $fdb3
    ld b, $78
    cp $00
    db $eb
    ld [hl], a

    db $e4
    ld [bc], a
    push hl
    sub b
    db $e4
    ld bc, $4353
    ld hl, $7b43
    push hl
    and d
    ld [hl], b
    db $e4
    ld bc, $2343
    ld b, c
    ld d, e
    dec bc
    rst $38
    add sp, -$14
    ld [bc], a
    ld [$230a], a
    call c, $fdc2
    ld c, h
    ld a, b
    call c, $e6c1
    ld d, e
    inc bc
    inc hl
    ld b, e
    ld [hl], e
    inc bc
    inc hl
    inc bc
    ld b, e
    inc bc
    inc hl
    ld b, e
    ld d, e
    inc bc
    inc hl
    ld b, e
    call c, $fdc2
    ld c, h
    ld a, b
    db $fd
    ld c, h
    ld a, b
    db $fd
    ld l, e
    ld a, b
    db $fd
    ld a, c
    ld a, b
    cp $00
    ld [hl+], a
    ld a, b
    db $e4
    ld d, d
    sub b
    db $e3
    ld bc, $0323
    db $e4
    sub c
    and e
    db $e3
    ld bc, $00e4
    push hl
    or b
    db $e4
    ld bc, $a1e5

jr_001_7860:
    ld [hl], e
    db $e4
    ld b, d
    ld [hl], b
    sub c
    and e
    sub e
    ld [hl], c
    sub e
    ld e, e
    rst $38
    rst $08
    push bc
    db $e4
    nop
    push hl
    or b
    db $e4
    ld bc, $a1e5
    ld [hl], e
    rst $08
    rst $08
    rst $38
    db $e4
    ld d, d
    sub b
    db $e3
    ld bc, $0323
    db $e4
    sub c
    and e
    db $e3
    ld bc, $e4c9
    ld b, d
    ld [hl], b
    sub c
    and e
    sub e
    ld [hl], c
    sub e
    ld e, e
    rst $38
    call c, $fd10
    rst $10
    ld a, b
    db $e3
    ld d, b
    pop bc
    sub b
    ldh [c], a
    nop
    ret nz

    jr nz, jr_001_7860

    nop
    jp nz, $90e3

    ret nz

    and b
    jp nz, $00e2

    ret nz

    db $e3
    nop
    db $e4
    or b
    db $e3
    nop
    ret nz

    db $e4
    and b
    ret nz

    ld [hl], b
    jp nz, Jump_001_40e3

    pop bc
    ld [hl], b
    sub b
    ret nz

    and b
    jp nz, $c290

    ld [hl], b
    ret nz

    sub b
    jp nz, $ca50

    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    rst $10
    ld a, b
    rst $08
    rst $08
    rst $08
    rst $08
    cp $00
    sub b
    ld a, b
    db $e4
    ld d, b
    jp nz, $c200

    jr nz, @-$3c

    ld b, b
    jp nz, $c270

    nop
    jp nz, $c220

    nop
    jp nz, $c240

    nop
    jp nz, $c220

    ld b, b
    jp nz, $c250

    nop
    jp nz, $c220

    ld b, b
    jp nz, $dcff

    db $fd
    ld [de], a
    ld a, c
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    ld [de], a
    ld a, c
    rst $08
    rst $08
    rst $08
    rst $08
    db $fd
    dec l
    ld a, c
    db $fd
    ld b, c
    ld a, c
    cp $00
    ld a, [$b378]
    ld c, $b1
    inc bc
    or c
    inc bc
    or e
    ld c, $b3
    inc bc
    or c
    ld c, $b1
    inc bc
    or c
    inc bc
    or c
    inc bc
    or e
    ld c, $b3
    inc bc
    cp $02
    ld [de], a
    ld a, c
    rst $38
    or e
    ld c, $c1
    pop bc
    or e
    ld c, $c3
    or c
    ld c, $c1
    pop bc
    pop bc
    or e
    ld c, $c3
    cp $02
    dec l
    ld a, c
    rst $38
    jp Jump_000_03b1


    or c
    inc bc
    jp $03b3


    pop bc
    or c
    inc bc
    or c
    inc bc
    or c
    inc bc
    jp $03b3


    cp $02
    ld b, c
    ld a, c
    rst $38
    db $ed
    nop
    sub b
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    call nc, $c0b1
    add sp, -$28
    or c
    db $e4
    ld [bc], a
    nop
    nop
    nop
    ld b, c
    ld bc, $7141
    ld b, c
    ld [hl], c
    db $e3
    inc bc
    ld bc, $42e4
    ld b, b
    ld b, b
    ld b, b
    ld [hl], c
    ld b, c
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $4143
    ld [bc], a
    nop
    nop
    nop
    db $e4
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $71e4
    ld b, c
    inc bc
    ld bc, $4143
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $73e4
    ld [hl], c
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $4143
    inc bc
    ld bc, $0101
    ld bc, $0145
    ld bc, DrawColumnData
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    cp $00
    ld h, l
    ld a, c
    db $ec
    ld [bc], a
    ret c

    pop bc
    db $e4
    ld [bc], a
    nop
    nop
    nop
    ld b, c
    ld bc, $7141
    ld b, c
    ld [hl], c
    db $e3
    inc bc
    ld bc, $42e4
    ld b, b
    ld b, b
    ld b, b
    ld [hl], c
    ld b, c
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $4143
    ld [bc], a
    nop
    nop
    nop
    db $e4
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $71e4
    ld b, c
    inc bc
    ld bc, $4143
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $73e4
    ld [hl], c
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $4143
    inc bc
    ld bc, $0101
    ld bc, $0145
    ld bc, DrawColumnData
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    cp $00
    jp $ed79


    nop
    sub b
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    call nc, $c0b1
    add sp, -$24
    pop bc
    rst $08
    ret c

    or c
    db $e4
    ld [bc], a
    nop
    nop
    nop
    ld b, c
    ld bc, $7141
    ld b, c
    ld [hl], c
    db $e3
    inc bc
    ld bc, $42e4
    ld b, b
    ld b, b
    ld b, b
    ld [hl], c
    ld b, c
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $4143
    ld [bc], a
    nop
    nop
    nop
    db $e4
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $71e4
    ld b, c
    inc bc
    ld bc, $4143
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $73e4
    ld [hl], c
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $4143
    inc bc
    ld bc, $0101
    ld bc, $0145
    ld bc, DrawColumnData
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    cp $00
    dec hl
    ld a, d
    db $ec
    ld [bc], a
    call c, $cfc1
    ret c

    pop bc
    db $e4
    ld [bc], a
    nop
    nop
    nop
    ld b, c
    ld bc, $7141
    ld b, c
    ld [hl], c
    db $e3
    inc bc
    ld bc, $42e4
    ld b, b
    ld b, b
    ld b, b
    ld [hl], c
    ld b, c
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $4143
    ld [bc], a
    nop
    nop
    nop
    db $e4
    ld [hl], c
    db $e3
    ld bc, $71e4
    db $e3
    ld bc, $71e4
    ld b, c
    inc bc
    ld bc, $4143
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $73e4
    ld [hl], c
    ld [hl], e
    ld [hl], c
    db $e3
    inc bc
    ld bc, $4143
    inc bc
    ld bc, $0101
    ld bc, $0145
    ld bc, DrawColumnData
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    db $e4
    ld [hl], c
    ld [hl], c
    ld [hl], c
    db $e3
    dec b
    cp $00
    adc h
    ld a, d
    db $ed
    nop
    sub b
    ldh a, [rPCM34]
    db $ec
    inc bc
    add sp, -$16
    dec b
    dec h
    call c, $e5b1
    ld [hl], b
    ld d, b
    ld b, b
    jr nz, @+$03

    and $b1
    sub c
    push hl
    ld b, c
    and $71
    push hl
    ld hl, $e601
    or c
    sub c
    ld [hl], c
    ld b, e
    rst $20
    ld [hl], e
    rst $38
    db $ec
    ld [bc], a
    ld [$2606], a
    call c, $e4c2
    ld bc, $b1e5
    sub c
    ld [hl], c
    ld b, b
    ld d, b
    ld [hl], c
    jr nz, jr_001_7b5f

    ld d, c
    ld b, c
    ld hl, $e601
    or c
    push hl
    inc bc
    call c, $e6b1
    inc bc
    rst $38
    call c, $cf10
    and $90
    or b
    push hl
    ld bc, $2000
    ld b, c
    ld bc, $e6c1
    ld bc, $ffc1
    db $ed
    nop
    add b
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    add sp, -$16
    ld bc, $dc23
    or c
    push hl
    or b
    db $e4
    add h
    sub b
    add c
    ld h, b
    ld b, c
    jr nc, @-$19

    or c
    sub b
    add c
    sub b
    or d
    call c, $e4b2
    adc c
    rst $38
    db $ec

jr_001_7b5f:
    ld [bc], a
    ld [$2400], a
    call c, $e4c2
    ld b, b
    or h
    db $e3
    db $10
    db $e4
    or c
    sub b
    add c
    ld h, b
    ld b, c
    ld h, b
    add c
    ld h, b
    ld b, d
    call c, $e3c3
    ld c, c
    rst $38
    db $ed
    nop
    add b
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    add sp, -$24
    or c
    ret nz

    ret nz

    ret nz

    db $e4
    ld [hl], b
    ld [hl], b
    ld [hl], b
    call c, $e3b4
    rrca
    rst $38
    db $ec
    ld [bc], a
    call c, $e4c1
    nop
    ld b, b
    ld [hl], b
    db $e3
    nop
    nop
    nop
    call c, StageIntroAnim
    rst $38
    db $ed
    nop
    add b
    ldh a, [rPCM34]
    db $ec
    ld [bc], a
    add sp, -$24
    or c
    push hl
    db $eb
    nop
    ld b, b
    nop
    jp nz, $ebe5

    nop
    ld b, a
    ld [hl], b
    jp nz, $ebe6

    nop
    ld d, b
    nop
    jp nz, $ebe6

    nop
    ld d, a
    ld [hl], b
    jp nz, $ecff

    ld [bc], a
    call c, $e4c1
    db $eb
    nop
    ld d, b
    nop
    jp nz, $ebe4

    nop
    ld d, a
    ld [hl], b
    jp nz, $ebe5

    nop
    ld h, b
    nop
    jp nz, $ebe5

    nop
    ld h, a
    ld [hl], b
    jp nz, $f8ff

    db $ec
    ld [bc], a
    call nc, $e2e1
    jr nz, jr_001_7be7

jr_001_7be7:
    db $e3
    or b
    sub b
    rst $38
    ld hl, sp-$14
    ld [bc], a
    call nc, $e3e1
    ld d, b
    sub b
    ldh [c], a
    nop
    call c, Call_001_5fe3
    rst $38
    ld hl, sp-$24
    db $10
    db $e3
    db $eb
    nop
    ld h, l
    ld d, e
    rst $38
    ld hl, $c6c1
    dec [hl]
    ret nz

    ret


CheckGameStateUpdate::
    ld hl, GAME_STATE
    ld a, [hl]
    cp $03
    jp z, ToggleFieldAnim

    ld a, [$c6b5]
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


    rst $38
    rst $38
    rst $38
    rlca
    add l
    ld a, l
    rlca
    adc c
    ld a, l
    rlca
    adc l
    ld a, l
    rlca
    sub c
    ld a, l
    rlca
    sub l
    ld a, l
    rlca
    sbc c
    ld a, l
    rlca
    sbc l
    ld a, l
    rlca
    and c
    ld a, l
    rlca
    and l
    ld a, l
    rlca
    xor c
    ld a, l
    rlca
    xor l
    ld a, l
    rlca
    or c
    ld a, l
    rlca
    or l
    ld a, l
    rlca
    cp c
    ld a, l
    ld b, h
    ret nc

    ld a, a
    dec b
    db $e3
    ld a, a
    inc b
    rst $18
    ld a, e
    call nz, $7ef6
    dec b
    dec c
    ld a, a
    ld b, $1b
    ld a, a
    rlca
    inc e
    ld a, a
    call nz, Call_001_7f9d
    dec b
    or h
    ld a, a
    ld b, $c2
    ld a, a
    rlca
    jp $047f


    add hl, hl
    ld a, a
    inc b
    inc l
    ld a, [hl]
    inc b
    ld e, h
    ld a, [hl]
    ld b, h
    or h
    ld a, [hl]
    dec b
    rst $00
    ld a, [hl]
    inc b
    xor c
    ld a, [hl]
    inc b
    sbc [hl]
    ld a, [hl]
    inc b
    sub e
    ld a, [hl]
    inc b
    adc b
    ld a, [hl]
    inc b
    ld a, l
    ld a, [hl]
    inc b
    ld [hl], d
    ld a, [hl]
    inc b
    ld h, a
    ld a, [hl]
    inc b
    ld c, e
    ld a, [hl]
    inc b
    jp c, Jump_000_047e

    db $eb
    ld a, [hl]
    ld b, h
    ld h, l
    ld a, a
    dec b
    add b
    ld a, a
    inc b
    inc [hl]
    ld a, a
    inc b
    ld b, e
    ld a, a
    inc b
    ld d, d
    ld a, a
    ld b, h
    rst $38
    ld a, l
    dec b
    dec d
    ld a, [hl]
    ret nz

    sbc d
    ld d, [hl]
    ld bc, $5764
    ld [bc], a
    dec bc
    ld e, b
    inc bc
    ld l, a
    ld e, d
    ret nz

    call nc, ReadJoypadButtons
    rst $08
    ld e, h
    ld [bc], a
    rra
    ld e, a
    inc bc
    ret nz

    ld h, b
    ret nz

    di
    ld e, d
    ld bc, $5ce5
    ld [bc], a
    ld l, $5f
    inc bc
    push bc
    ld h, b
    ret nz

    ld [hl], b
    ld h, c
    ld bc, $625c
    ld [bc], a
    db $e3
    ld h, e
    inc bc
    pop de
    ld h, h
    ret nz

    add e
    ld h, c
    ld bc, $6273
    ld [bc], a
    db $eb
    ld h, e
    inc bc
    push de
    ld h, h
    ret nz

    add [hl]
    ld h, l
    ld bc, $66e3
    ld [bc], a
    or l
    ld l, b
    inc bc
    ld d, $6b
    ret nz

    xor h
    ld h, l
    db $01

    ld sp, hl
    ld h, [hl]
    ld [bc], a
    pop bc
    ld l, b
    inc bc
    add hl, de
    ld l, e
    ret nz

    ret z

    ld l, h
    ld bc, $6db3
    ld [bc], a
    ld a, l
    ld l, a
    inc bc
    jp nc, $c071

    ret z

    ld l, h
    ld bc, $6dc6
    ld [bc], a
    ld a, [hl]
    ld l, a
    inc bc
    ldh [c], a
    ld [hl], c

jr_001_7d28:
    ret nz

    ld a, $75
    ld bc, $7562
    ld [bc], a
    add b

jr_001_7d30:
    ld [hl], l
    inc bc
    sbc h
    ld [hl], l

jr_001_7d34:
    add b
    reti


    ld [hl], l
    ld bc, $75f5
    ld [bc], a
    dec bc

jr_001_7d3c:
    db $76
    add b
    inc e
    db $76
    ld bc, $763a
    ld [bc], a
    ld d, h
    db $76

jr_001_7d46:
    ret nz

    ld l, b

jr_001_7d48:
    db $76
    ld bc, $76a6
    ld [bc], a
    add hl, de
    ld [hl], a
    inc bc
    add d
    ld [hl], a
    ret nz

    pop hl
    ld [hl], a
    ld bc, $781c
    ld [bc], a
    sub b
    ld a, b
    inc bc
    ld sp, hl
    ld a, b
    add b
    add sp, $7a
    ld bc, $7b0d
    ld [bc], a
    inc l
    ld a, e
    ld b, b
    dec a
    ld a, e
    ld bc, $7b5e
    ld b, b
    ld e, b
    ld a, c
    ld bc, $79bf
    ld b, b
    dec e
    ld a, d
    ld bc, $7a87
    ld b, b
    ld a, c
    ld a, e
    ld bc, $7b8f
    ld b, b
    sbc a
    ld a, e
    ld bc, $7bc2
    jr nz, jr_001_7d28

    sbc b
    rst $38
    jr nz, @-$5d

    inc hl
    rst $38
    jr nz, jr_001_7d30

    inc sp
    rst $38
    jr nz, jr_001_7d34

    inc de
    rst $38
    jr nz, @-$5d

    ld [hl-], a
    rst $38
    jr nz, @-$7d

    ld [hl-], a
    rst $38
    jr nz, jr_001_7e00

    ld [hl+], a
    rst $38
    jr nz, jr_001_7d46

    inc de
    rst $38
    jr nz, jr_001_7d48

    ld b, e
    rst $38
    jr nz, jr_001_7d3c

jr_001_7dab:
    ld [hl-], a
    rst $38
    jr nz, jr_001_7e00

    ld [hl-], a
    rst $38
    jr nz, jr_001_7df4

    ld [hl-], a

jr_001_7db4:
    rst $38
    jr nz, jr_001_7de8

    ld [hl-], a
    rst $38
    jr nz, jr_001_7e2c

    ld b, h
    rst $38
    rst $08
    ld a, l
    rst $18
    ld a, l
    rst $28
    ld a, l
    rst $38
    ld a, l
    rst $38

jr_001_7dc6:
    ld a, l
    rst $38
    ld a, l
    rst $38
    ld a, l
    rst $38
    ld a, l
    rst $38
    ld a, l
    ld [bc], a
    ld b, [hl]
    adc d
    adc $ff
    cp $ed

jr_001_7dd6:
    call c, $a9cb
    add a
    ld h, l
    ld b, h
    inc sp
    ld [hl+], a
    ld de, $ffbb
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    cp e
    ld b, h

jr_001_7de8:
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, h
    ld bc, $3412
    ld d, a
    sbc e

jr_001_7df4:
    rst $18
    cp $dc
    cp d
    sbc b
    db $76
    ld d, h
    ld b, e
    ld [hl-], a
    ld hl, $ed11

jr_001_7e00:
    ld bc, $ec00
    ld [bc], a
    inc h
    db $f4
    nop
    rlca
    ld hl, $40a1
    rlca
    ld [hl+], a
    pop bc
    add b
    rlca
    jr z, jr_001_7db4

jr_001_7e12:
    ret nz

    rlca
    rst $38
    db $ec
    ld bc, ResetTitleState
    ret nz

    ld b, $24
    call nc, Call_000_0700
    ld hl, $4081
    rlca
    ld [hl+], a
    and c
    add b
    rlca
    jr z, jr_001_7dab

    ret nz

    rlca
    rst $38

jr_001_7e2c:
    db $ec
    ld [bc], a

jr_001_7e2e:
    jr nz, @+$44

    nop
    dec b
    jr nz, jr_001_7dc6

    add b
    ld b, $20
    jp nc, Jump_000_0700

    jr nz, jr_001_7e2e

    add b
    rlca
    jr nz, jr_001_7e12

    nop
    rlca
    jr nz, jr_001_7dd6

    add b
    ld b, $2a
    ld b, c
    nop

jr_001_7e49:
    dec b
    rst $38
    db $ec
    ld [bc], a
    db $10
    ld a, [hl-]
    inc h
    ldh a, [c]
    nop
    inc b
    db $10
    inc hl
    jr z, jr_001_7e49

    nop
    ld b, $10
    ld [$ecff], sp
    nop
    db $10
    ld [hl+], a
    inc h
    ldh a, [c]
    nop
    inc bc
    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    dec l
    ld h, $f1
    ret nz

    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    dec l
    ld h, $f1
    and b

jr_001_7e79:
    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    dec l
    ld h, $f1
    add b
    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    dec l
    ld h, $f1
    ld h, b
    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    dec l
    ld h, $f1
    ld b, b
    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    dec l
    ld h, $f1
    jr nz, jr_001_7ead

    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    dec l

jr_001_7ead:
    ld h, $f1
    nop
    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    jr nz, jr_001_7e79

    add b
    rlca
    ld hl, $a0f1
    rlca
    ld hl, $c0c1
    rlca
    inc h
    pop af
    ldh [rTAC], a
    rst $38
    db $ec
    ld [bc], a
    jr nz, @-$6d

    add c
    rlca
    ld hl, $a1d1
    rlca

jr_001_7ed1:
    ld hl, $c191
    rlca
    inc h
    pop de
    pop hl
    rlca
    rst $38
    db $ec
    ld bc, $2610
    jr z, jr_001_7ed1

    ld b, b
    rlca
    db $10
    ld [hl], $24
    pop hl
    ret nz

    rlca
    db $10
    ld [$ecff], sp
    ld bc, $1510
    inc h
    and c
    ld b, b
    rlca
    db $10
    ld [$ecff], sp
    inc bc
    db $10
    rla
    inc h
    pop af
    ret nz

    ld b, $10
    ld d, $2f
    pop af
    ret nz

    rlca
    db $10
    dec e
    inc h
    pop af
    nop
    inc b
    db $10
    ld [$ecff], sp
    ld [bc], a
    inc h
    pop de
    add b
    ld b, $2f
    and c
    ret nz

    rlca
    inc h
    pop bc
    add b

jr_001_7f1a:
    inc bc
    rst $38
    ld hl, $38d1
    ld l, $d1
    jr z, jr_001_7f44

    pop de
    add hl, sp
    inc h
    pop de
    ld c, c
    rst $38
    db $ec
    ld [bc], a
    db $10
    ld [hl], $28
    pop af
    nop
    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    inc d
    jr z, jr_001_7fab

    add b
    ld b, $28
    ld b, c
    nop
    rlca
    db $10
    ld [$ecff], sp

jr_001_7f44:
    ld [bc], a
    db $10
    inc d
    jr z, jr_001_7f1a

    add b
    ld b, $28
    and c
    nop
    rlca
    db $10

jr_001_7f50:
    ld [$ecff], sp
    ld [bc], a
    db $10
    ld [hl], $24
    db $f4
    add b
    rlca
    inc hl
    pop bc
    ret nz

    rlca
    inc h
    pop de
    and b
    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    ld [hl+], a
    call nz, VRAMCopyExec
    ld [hl+], a
    call nz, $0240
    inc hl
    pop bc
    ld h, b
    ld [bc], a
    cpl
    nop
    nop
    nop
    ld hl, sp-$24
    pop af
    push hl
    db $eb
    nop
    ld h, b
    ldh a, [rIE]
    db $ec
    inc bc
    ld [hl+], a
    add e
    ld sp, $2203
    add e
    ld b, c
    inc bc
    inc hl
    add c
    ld h, c
    inc bc
    cpl
    nop
    nop
    nop
    db $ec
    ld [bc], a
    ld hl, sp-$24
    pop de
    push hl
    db $eb
    nop
    ld h, b
    ldh a, [rIE]

Call_001_7f9d:
    db $ec
    inc bc
    db $10
    dec d
    daa
    db $f4
    ret nz

    ld [bc], a
    db $10
    inc de
    ld a, [hl+]
    ldh a, [c]
    ret nz

    inc bc

jr_001_7fab:
    db $10
    dec de
    inc l
    ldh a, [c]
    nop
    inc bc
    db $10
    ld [$ecff], sp
    ld [bc], a
    inc h
    pop de
    add b
    ld [bc], a
    cpl
    and c
    ret nz

    inc bc
    inc h
    pop bc
    add b
    ld [bc], a
    rst $38
    inc h
    or d
    ld c, b
    ld l, $c1
    jr c, jr_001_7feb

    add c
    ld c, c
    jr z, jr_001_7f50

    ld e, c
    rst $38
    db $ec
    ld [bc], a
    inc hl
    pop de
    ret nz

    rlca
    inc hl
    pop de
    add b
    rlca
    inc hl
    pop de
    ret nz

    rlca
    inc hl
    pop de
    add b
    rlca
    rst $38
    db $ec
    ld [bc], a
    inc hl
    and c
    pop bc
    rlca
    inc hl
    and c

jr_001_7feb:
    add c
    rlca
    inc hl
    and c
    pop bc
    rlca
    inc hl
    and c
    add c
    rlca
    rst $38
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
