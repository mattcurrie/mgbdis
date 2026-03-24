; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $010", ROMX[$4000], BANK[$10]

    call Call_000_3e15
    call Call_000_03bf
    call Call_000_0ebd
    ld a, [$cc36]
    push af
    xor a
    ld [$cc26], a
    ld [$cc36], a
    ld [$cc2a], a
    inc a
    ld [$d0e3], a
    ld [$ffb7], a

Jump_010_401e:
    ld b, $08
    call Call_000_3e1f
    ld hl, $7c2c
    ld b, $05
    call Call_000_3620

jr_010_402b:
    ld hl, $cc24
    ld a, $03
    ld [hl+], a
    xor a
    ld [hl+], a
    inc a
    ld [$cc37], a
    inc hl
    inc hl
    ld a, $06
    ld [hl+], a
    ld [hl], $33
    call Call_010_4103
    jr c, jr_010_4063

jr_010_4043:
    xor a
    ld [$cc37], a
    ld [$cc26], a
    ld [$cc2a], a
    ld [$ffb7], a
    ld [$cd3a], a
    ld [$cd3b], a
    pop af
    ld [$cc36], a
    call Call_000_3e04
    call Call_000_3e1d
    jp Jump_000_1b86


jr_010_4063:
    call Call_010_406f
    dec b
    jr z, jr_010_4043

    dec b
    jr z, jr_010_402b

    jp Jump_010_401e


Call_010_406f:
    call Call_000_3c1c
    ld a, [$cc26]
    push af
    ld b, a
    ld a, [$cc2a]
    push af
    ld a, [$cc36]
    push af

Jump_010_407f:
    add b
    inc a
    ld [$d0e3], a
    ld a, [$d0e3]
    push af
    ld a, [$cd3d]
    push af
    ld hl, $d28e
    call Call_010_42ab
    ld b, $02
    jr z, jr_010_40c5

    call Call_010_676f
    ld hl, $cc24
    ld a, $0a
    ld [hl+], a
    ld a, $0c
    ld [hl+], a
    xor a
    ld [hl+], a
    inc hl
    ld a, $03
    ld [hl+], a
    ld [hl+], a
    xor a
    ld [hl+], a
    ld [$cc37], a

jr_010_40ae:
    call Call_000_3b08
    bit 1, a
    ld b, $02
    jr nz, jr_010_40c5

    ld a, [$cc26]
    and a
    jr z, jr_010_40e8

    dec a
    jr z, jr_010_40ef

    dec a
    jr z, jr_010_40fa

    ld b, $01

jr_010_40c5:
    pop af
    ld [$cd3d], a
    pop af
    ld [$d0e3], a
    pop af
    ld [$cc36], a
    pop af
    ld [$cc2a], a
    pop af
    ld [$cc26], a
    push bc
    ld hl, $c3dc
    ld de, $0014
    ld bc, $7f0d
    call Call_010_4454
    pop bc
    ret


jr_010_40e8:
    call Call_010_42cb
    ld b, $00
    jr jr_010_40c5

jr_010_40ef:
    ld a, [$d0e3]
    call Call_000_2dd0
    call Call_000_0e45
    jr jr_010_40ae

jr_010_40fa:
    ld a, $4a
    call Call_000_3e9d
    ld b, $00
    jr jr_010_40c5

Call_010_4103:
    xor a
    ldh [$ba], a
    ld hl, $c44b
    ld b, $08
    ld c, $07
    call Call_000_03d2
    ld hl, $c3aa
    ld [hl], $71
    ld hl, $c3be
    call Call_010_4272
    ld hl, $c45e
    call Call_010_4272
    ld hl, $d28e
    ld b, $13
    call Call_000_1690
    ld de, $d0e3
    ld hl, $c3ec
    ld bc, $0103
    call Call_000_3c8f
    ld hl, $d27b
    ld b, $13
    call Call_000_1690
    ld de, $d0e3
    ld hl, $c428
    ld bc, $0103
    call Call_000_3c8f
    ld hl, $c3d4
    ld de, $4281
    call Call_000_0405
    ld hl, $c410
    ld de, $4288
    call Call_000_0405
    ld hl, $c3b5
    ld de, $4290
    call Call_000_0405
    ld hl, $c475
    ld de, $4294
    call Call_000_0405
    ld hl, $d2a0
    ld b, $99

jr_010_4172:
    ld a, [hl-]
    ld c, $08

jr_010_4175:
    dec b
    sla a
    jr c, jr_010_417f

    dec c
    jr nz, jr_010_4175

    jr jr_010_4172

jr_010_417f:
    ld a, b
    ld [$cd3d], a

Jump_010_4183:
    xor a
    ldh [$ba], a
    ld hl, $c3cd
    ld bc, $0e05
    call Call_000_0374
    ld hl, $c3dd
    ld a, [$cc36]
    ld [$d0e3], a
    ld d, $07
    ld a, [$cd3d]
    cp $07
    jr nc, jr_010_41a6

    ld d, a
    dec a
    ld [$cc28], a

jr_010_41a6:
    ld a, [$d0e3]
    inc a
    ld [$d0e3], a
    push af
    push de
    push hl
    ld de, $d0e3
    ld bc, $8103
    call Call_000_3c8f
    push hl
    ld hl, $d27b
    call Call_010_42ab
    pop hl
    ld a, $7f
    jr z, jr_010_41c7

    ld a, $72

jr_010_41c7:
    ld [hl], a
    push hl
    ld hl, $d28e
    call Call_010_42ab
    jr nz, jr_010_41dc

    ld de, $41d6
    jr jr_010_41e2

    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    ld d, b

jr_010_41dc:
    call Call_010_676f
    call Call_000_1aab

jr_010_41e2:
    pop hl
    inc hl
    call Call_000_0405
    pop hl
    ld bc, $0028
    add hl, bc
    pop de
    pop af
    ld [$d0e3], a
    dec d
    jr nz, jr_010_41a6

    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    call Call_000_3e0c
    call Call_000_3b08
    bit 1, a
    jp nz, Jump_010_4270

    bit 6, a
    jr z, jr_010_4218

    ld a, [$cc36]
    and a
    jp z, Jump_010_4183

    dec a
    ld [$cc36], a
    jp Jump_010_4183


jr_010_4218:
    bit 7, a
    jr z, jr_010_4235

    ld a, [$cd3d]
    cp $07
    jp c, Jump_010_4183

    sub $07
    ld b, a
    ld a, [$cc36]
    cp b
    jp z, Jump_010_4183

    inc a
    ld [$cc36], a
    jp Jump_010_4183


jr_010_4235:
    bit 4, a
    jr z, jr_010_4258

    ld a, [$cd3d]
    cp $07
    jp c, Jump_010_4183

    sub $06
    ld b, a
    ld a, [$cc36]
    add $07
    ld [$cc36], a
    cp b
    jp c, Jump_010_4183

    dec b
    ld a, b
    ld [$cc36], a
    jp Jump_010_4183


jr_010_4258:
    bit 5, a
    jr z, jr_010_426e

    ld a, [$cc36]
    sub $07
    ld [$cc36], a
    jp nc, Jump_010_4183

    xor a
    ld [$cc36], a
    jp Jump_010_4183


jr_010_426e:
    scf
    ret


Jump_010_4270:
    and a
    ret


Call_010_4272:
    ld c, $09
    ld de, $0014
    ld a, $71

jr_010_4279:
    ld [hl], a
    add hl, de
    xor $01
    dec c
    jr nz, jr_010_4279

    ret


    db $ed
    inc l
    inc d
    ld b, e
    or [hl]
    dec l
    ld d, b
    db $ed
    inc l
    add hl, de
    ld b, e
    ret nz

    or [hl]
    dec l
    ld d, b
    db $ed
    inc l
    rra
    ld b, e
    db $ed
    inc l
    daa
    ld b, e
    ret nc

    reti


    ld c, [hl]
    push bc
    or a
    ld a, [hl+]
    or h
    ld c, [hl]
    inc a
    sbc $46
    db $dd
    ret nc

    reti


    ld c, [hl]
    call nc, $d9d2
    ld d, b

Call_010_42ab:
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $02
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    ret


Jump_010_42ba:
    call Call_000_3e04
    call Call_000_03bf
    call Call_000_0ebd
    ld hl, $7c2c
    ld b, $05
    call Call_000_3620

Call_010_42cb:
    ld hl, $d6ab
    set 1, [hl]
    ld a, $33
    ldh [rNR50], a
    call Call_000_3e15
    call Call_000_03bf
    ld a, [$d0e3]
    ld [$cf78], a
    push af
    ld b, $04
    call Call_000_3e1f
    pop af
    ld [$d0e3], a
    ldh a, [$d7]
    push af
    xor a
    ldh [$d7], a
    ld hl, $c3a0
    ld de, $0001
    ld bc, $6414
    call Call_010_4454
    ld hl, $c4f4
    ld b, $6f
    call Call_010_4454
    ld hl, $c3b4
    ld de, $0014
    ld bc, $6610
    call Call_010_4454
    ld hl, $c3c7
    ld b, $67
    call Call_010_4454
    ld a, $63
    ld [$c3a0], a
    ld a, $65
    ld [$c3b3], a
    ld a, $6c
    ld [$c4f4], a
    ld a, $6e
    ld [$c507], a
    ld hl, $c454
    ld de, $443f
    call Call_000_0405
    ld hl, $c421
    ld de, $4428
    call Call_000_0405
    call Call_000_1aab
    ld hl, $c3d1
    call Call_000_0405
    ld hl, $445e
    ld a, [$d0e3]
    dec a
    ld e, a
    ld d, $00
    add hl, de
    add hl, de
    ld a, [hl+]
    ld e, a
    ld d, [hl]
    ld hl, $c3f9
    call Call_000_0405
    ld h, b
    ld l, c
    push de
    ld de, $443d
    call Call_000_0405
    ld a, [$d0e3]
    push af
    call Call_010_6786
    ld hl, $c442
    ld a, $74
    ld [hl+], a
    ld a, $f2
    ld [hl+], a
    ld de, $d0e3
    ld bc, $8103
    call Call_000_3c8f
    ld hl, $d27b
    call Call_010_42ab
    pop af
    ld [$d0e3], a
    ld a, [$cf78]
    ld [$d092], a
    pop de
    ld a, c
    and a
    jp z, Jump_010_43ed

    inc de
    ld a, [de]
    push af
    ld hl, $c425
    ld bc, $0103
    call Call_000_3c8f
    ld hl, $c426
    pop af
    cp $0a
    jr nc, jr_010_43aa

    ld [hl], $f6

jr_010_43aa:
    inc hl
    ld a, [hl+]
    ld [hl-], a
    ld [hl], $f2
    inc de
    inc de
    inc de
    push de
    ld hl, $ff8b
    ld a, [hl]
    push af
    ld a, [de]
    ld [hl+], a
    ld a, [hl]
    push af
    dec de
    ld a, [de]
    ld [hl], a
    ld de, $ff8b
    ld hl, $c44c
    ld bc, $0204
    call Call_000_3c8f
    ld hl, $c44e
    ldh a, [$8c]
    sub $0a
    ldh a, [$8b]
    sbc $00
    jr nc, jr_010_43da

Call_010_43d8:
    ld [hl], $f6

jr_010_43da:
    inc hl
    ld a, [hl+]
    ld [hl-], a
    ld [hl], $f2
    pop af
    ldh [$8c], a
    pop af
    ldh [$8b], a
    pop de
    inc de
    ld hl, $c47d
    call Call_000_0405

Jump_010_43ed:
    call Call_000_3e07
    call Call_000_3e0c
    call Call_000_2f2e
    ld hl, $c3b5
    call Call_000_2d7a
    ld a, [$cf78]
    call Call_000_2dc7

jr_010_4402:
    call Call_000_3879
    ld a, [$ffb5]
    and $03
    jr z, jr_010_4402

    pop af
    ldh [$d7], a
    call Call_000_3e15
    call Call_000_03bf
    call Call_000_3e1d
    call Call_000_36ea
    call Call_000_3e0c
    ld hl, $d6ab
    res 1, [hl]
    ld a, $77
    ldh [rNR50], a
    ret


    db $ed
    inc l
    dec a
    ld b, e
    ld a, a
    and $e6
    and $60
    ld c, [hl]
    or l
    db $d3
    cp e
    ld a, a
    ld a, a
    and $e6
    and $61
    ld h, d
    ld d, b
    ld d, b
    ld d, b
    ld l, b
    ld l, c
    ld l, e
    ld l, c
    ld l, e
    ld l, c
    ld l, e
    ld l, c
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, c
    ld l, e
    ld l, c
    ld l, e
    ld l, c
    ld l, e
    ld l, c
    ld l, d
    ld d, b

Call_010_4454:
    push bc
    push de

jr_010_4456:
    ld [hl], b
    add hl, de
    dec c
    jr nz, jr_010_4456

    pop de
    pop bc
    ret


    jp c, $1645

    ld b, [hl]
    ld c, l
    ld b, [hl]
    adc b
    ld b, [hl]
    cp a
    ld b, [hl]
    ld sp, hl
    ld b, [hl]
    inc sp
    ld b, a
    ld l, a
    ld b, a
    and [hl]
    ld b, a
    sbc $47
    dec de
    ld c, b
    ld e, d
    ld c, b
    sub h
    ld c, b
    adc $48
    inc bc
    ld c, c
    ld b, d
    ld c, c
    ld a, c
    ld c, c
    or c
    ld c, c
    jp hl


    ld c, c
    inc hl
    ld c, d
    ld e, d
    ld c, d
    sub d
    ld c, d
    call $034a
    ld c, e
    add hl, sp
    ld c, e
    ld [hl], e
    ld c, e
    xor c
    ld c, e
    reti


    ld c, e
    ld de, $4a4c
    ld c, h
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    add [hl]
    ld c, h
    cp d
    ld c, h
    db $f4
    ld c, h
    ld l, $4d
    ld h, e
    ld c, l
    sbc [hl]
    ld c, l
    db $dd
    ld c, l
    db $10
    ld c, [hl]
    ld c, l
    ld c, [hl]
    adc e
    ld c, [hl]
    add $4e
    ld [bc], a
    ld c, a
    add hl, sp
    ld c, a
    ld [hl], e
    ld c, a
    or b
    ld c, a
    db $ed
    ld c, a
    inc h
    ld d, b
    ld l, d
    ld h, a
    ld e, h
    ld d, b
    ld l, d
    ld h, a
    sub h
    ld d, b
    jp z, $0450

    ld d, c
    ld l, d
    ld h, a
    dec a
    ld d, c
    ld [hl], h
    ld d, c
    or b
    ld d, c
    db $eb
    ld d, c
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    rra
    ld d, d
    ld d, [hl]
    ld d, d
    sub c
    ld d, d
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    rst $00
    ld d, d
    ld [bc], a
    ld d, e
    ccf
    ld d, e
    ld a, l
    ld d, e
    or a
    ld d, e
    di
    ld d, e
    ld l, $54
    ld h, l
    ld d, h
    sbc b
    ld d, h
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    rst $08
    ld d, h
    inc bc
    ld d, l
    ld b, b
    ld d, l
    ld [hl], l
    ld d, l
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    xor h
    ld d, l
    ldh [rHDMA5], a
    dec e
    ld d, [hl]
    ld d, e
    ld d, [hl]
    adc h
    ld d, [hl]
    call z, Call_010_6a56
    ld h, a
    ld l, d
    ld h, a
    inc b
    ld d, a
    ld a, [hl-]
    ld d, a
    ld l, l
    ld d, a
    and e
    ld d, a
    jp c, $1157

    ld e, b
    ld b, [hl]
    ld e, b
    ld [hl], a
    ld e, b
    xor [hl]
    ld e, b
    add sp, $58
    jr nz, jr_010_458b

    ld e, a
    ld e, c
    sbc b
    ld e, c
    rst $08
    ld e, c
    dec bc
    ld e, d
    ld b, [hl]
    ld e, d
    add e
    ld e, d
    jp nz, $fa5a

    ld e, d
    ld l, d
    ld h, a
    dec [hl]
    ld e, e
    ld [hl], l
    ld e, e
    and a
    ld e, e
    sbc $5b
    inc de
    ld e, h
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld c, h
    ld e, h
    add a
    ld e, h
    cp a
    ld e, h
    ld sp, hl
    ld e, h
    ld l, d
    ld h, a
    ld [hl-], a
    ld e, l
    ld l, a
    ld e, l
    xor [hl]
    ld e, l
    rst $18
    ld e, l
    inc e
    ld e, [hl]
    ld d, h
    ld e, [hl]
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    adc d
    ld e, [hl]
    ld l, d
    ld h, a
    cp a
    ld e, [hl]
    db $f4
    ld e, [hl]
    ld l, d
    ld h, a
    dec hl
    ld e, a
    ld h, l
    ld e, a
    sbc l
    ld e, a
    sub $5f
    dec d
    ld h, b
    ld l, d
    ld h, a
    ld d, c
    ld h, b
    adc c
    ld h, b
    jp $fa60


    ld h, b
    inc [hl]

jr_010_458b:
    ld h, c
    ld h, [hl]
    ld h, c
    sbc h
    ld h, c
    rst $08
    ld h, c
    ld bc, $6a62
    ld h, a
    dec a
    ld h, d
    ld a, b
    ld h, d
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    xor l
    ld h, d
    jp hl


    ld h, d
    ld h, $63

jr_010_45a8:
    ld e, l
    ld h, e
    sub h
    ld h, e
    call $0963
    ld h, h
    ld b, d
    ld h, h
    ld a, e
    ld h, h
    ld l, d
    ld h, a
    or [hl]
    ld h, h
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    db $ed
    ld h, h
    dec hl
    ld h, l
    ld h, d
    ld h, l
    sbc c
    ld h, l
    rst $08
    ld h, l
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    ld l, d
    ld h, a
    add hl, bc
    ld h, [hl]
    ld b, d
    ld h, [hl]
    ld a, d
    ld h, [hl]
    or d
    ld h, [hl]
    rst $28
    ld h, [hl]
    dec l
    ld h, a
    call nz, $c9d2
    call z, $cfcc
    jp nc, Jump_000_1350

    or b
    inc b
    db $ed
    ld hl, $4000
    db $db
    or c
    cp h
    ld a, a
    jr nc, jr_010_45a8

    inc sp
    ld c, [hl]
    ret nz

    jp nz, $b3d6

    add $c5
    rst $18
    ret nz

    add sp, -$6f
    sbc b
    inc sp
    ld a, a
    jp nz, $dab6

    reti


    call nz, Call_000_264e
    sbc $be
    or a
    add $d3
    ld a, a
    or c
    push bc
    ld h, $b1
    or d
    jp $cfbc


    or e
    add sp, $50
    add $c1
    call nc, $c5c8
    jp nc, $d37f

    rst $08
    adc $50
    ld d, $20
    inc bc
    db $ed
    ld hl, $4068
    db $db
    add $4e
    cp d
    inc [hl]
    db $d3
    db $dd
    ld a, a
    or d
    jp c, Jump_010_7fc3

    cp a
    jr nc, @-$3b

    reti


    add sp, $4e
    jp c, $2fde

    cp b
    ld b, b
    xor e
    sub b
    ld a, a
    cp d

jr_010_4643:
    or e
    add hl, hl
    or a
    ld h, $7f
    call nz, $b2b8
    add sp, $50
    adc $c5
    push bc
    call nz, $c5cc
    ld d, b
    dec b
    ld e, d
    nop
    db $ed
    ld hl, $40cd
    or a
    cp b
    ld a, a
    call nz, $b8b5
    ret


    ld a, a
    or l
    call nz, $4edd
    or a
    cp b
    call nz, Call_010_7fb7

jr_010_466c:
    jp z, $c03a

    cp b
    sub $b3
    add $7f
    or e
    ld a, [hl+]
    cp b
    add sp, $4e
    or l
    cp d
    reti


    call nz, $347f
    cp b
    ld a, [hl-]
    ret c

    db $dd
    ld a, a
    jr nc, jr_010_4643

    add sp, $50
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, b
    ld b, $4b
    nop
    db $ed
    ld hl, $414e
    ld h, $c0
    or [hl]
    rst $10
    ld c, [hl]
    ld b, a
    xor h
    sub e
    sub $b3
    add $7f
    add $de
    or a
    ld h, $7f
    or c
    reti


    add sp, $4e
    ret nz

    jr nc, jr_010_466c

    ld a, a
    push bc
    or [hl]
    push bc
    or [hl]
    ld a, a
    ret nc

    jp nz, $d7b9

    jp c, $b2c5

    add sp, $50
    jp nz, $d2c9

    call nz, Call_000_0350
    inc d
    nop
    db $ed
    ld hl, $419b
    ld a, a
    or c
    pop bc
    cp d
    pop bc
    db $dd
    ld a, a
    call nz, $cf3b
    call c, $e8d9
    ld c, [hl]
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    jp z, $bd7f

    cp b
    push bc
    or d
    ld h, $4e
    add h
    add d
    sbc a
    ld h, $b4
    cp h
    db $dd
    ld a, a
    jp nz, $b3b6

    call nz, $c37f
    ld a, [hl+]
    call c, $e8b2
    ld d, b
    jp nz, $ccc1

    call z, Call_000_0550
    ld l, b
    nop
    db $ed
    ld hl, $4208
    ld a, a
    call z, $b2d2
    ret


    ld a, a
    or d
    or a
    db $d3
    ret


    add sp, $4e
    or d
    call nc, $b5c5
    call nz, $7fdd
    jr nc, @-$42

    ret nz

    ret c

    ld a, a
    call nz, $2ec2
    sbc $4e
    inc l
    ld a, [hl-]
    cp b
    cp l
    reti


    ld a, a
    cp d
    call nz, $7fd3
    or c
    reti


    call nz, $b3b2
    add sp, $50
    call nz, $c9d2
    call z, $cfcc
    jp nc, Jump_000_0e50

    ld l, h
    ld [bc], a
    db $ed
    ld hl, $427d
    ret nz

    or d
    ld a, a
    set 1, h
    call nz, $c54e
    ld h, $b8
    ld a, a
    ret


    dec sp
    ret nz

    ld a, a
    sub c
    sbc b
    ld h, $7f
    call nz, $c1b8
    ld [c], a
    or e
    add sp, $4e
    sub c
    sbc b
    add $ca
    ld a, a
    inc [hl]
    cp b
    db $d3
    or c
    reti


    ret


    inc sp
    ld a, a
    pop bc
    pop hl
    or e
    or d
    add sp, $50
    reti


    pop bc
    call nz, $cecf
    ld d, b
    db $10
    ld de, $ed03
    ld hl, $42cb
    or e
    ret nc

    call $837f
    adc d
    db $dd
    ld c, [hl]
    call nz, $c6d8
    or d
    rst $18
    ret nz

    call nz, Call_010_7fb7
    adc e
    db $eb
    and [hl]
    rrca
    db $e3
    add $4e
    cp h
    rst $18
    ld c, b
    db $dd
    or [hl]
    rst $08
    jp c, $a27f

    inc de
    and l
    xor e
    add $c5
    rst $18
    ret nz

    add sp, $50
    db $d3
    push bc
    push bc
    call nz, Call_000_0a50
    add d
    nop
    db $ed
    ld hl, $4343
    push bc
    or [hl]
    add $7f
    jp nz, $c3b2

    or d
    jp $d64e


    or e
    inc a
    sbc $dd
    ld a, a
    or a
    pop hl
    or e
    cp h
    pop hl
    or e
    cp h
    jp $b8b2


    call nz, $b54e
    or l
    or a
    push bc
    ld a, a
    jp z, $26c5

    ld a, a
    cp e
    cp b
    call nz, $b3b2
    add sp, $50
    jp $c3cf


    rst $08
    adc $d5
    call nc, Call_000_1450
    or b
    inc b
    db $ed
    ld hl, $439e
    or d
    or e
    ret c

    sbc $7f
    call nz, $3ad6
    jp c, $e8d9

    ld c, [hl]
    ret nc

    ret


    ld a, a
    set 0, h
    jp nz, $c4cb

    jp nz, Jump_010_7fc6

    or [hl]
    or l
    ld h, $b1
    rst $18
    jp $bf4e


    jp c, $da2f

    ld a, a
    or d
    cp h
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $d9b2


    add sp, $50
    call nc, $cecf
    rst $00
    push de
    push bc
    ld d, b
    inc c
    adc a
    ld [bc], a
    db $ed
    ld hl, $4407
    sbc $c1
    ld [c], a
    or e
    ret


    ld a, a
    ld hl, sp+$3a
    or d
    db $d3
    or c
    reti


    add sp, $4e
    add e
    adc d
    db $dd
    call nz, $c0df
    ret c

    ld a, a
    cp d
    or e
    add hl, hl
    or a
    db $dd
    cp h
    ret nz

    ret c

    call nz, $cf4e
    reti


    inc sp
    ld a, a
    jp $d6c9


    or e
    add $7f
    or e
    ld a, [hl+]
    or [hl]
    cp [hl]
    reti


    add sp, $50
    push bc
    rst $00
    rst $00
    ld d, b
    inc b
    add hl, de
    nop
    db $ed
    ld hl, $4465
    ld a, a
    ret nz

    rst $08
    ld a, [hl+]
    ret


    ld a, a
    sub $b3
    jr nc, jr_010_4895

    ld c, [hl]
    inc l
    jp nz, $7fca

    cp h
    ld [c], a
    cp b
    inc a
    jp nz, Jump_010_7fc9

    adc a
    sub a
    add $c1
    or [hl]
    or d
    ld c, [hl]
    or d
    or a
    db $d3
    ret


    ld a, a
    inc sp
    or c
    reti


    cp d
    call nz, Call_010_7f26
    call c, $dfb6
    ret nz

    add sp, $50
    db $d3

jr_010_4895:
    call nc, $c3c9
    set 3, c
    ld a, a
    call $c4d5
    ld d, b
    add hl, bc
    inc l
    ld bc, $21ed
    add $44
    sbc $dd
    or c
    dec sp
    ret nz

    ld c, [hl]
    call $a813
    ld h, $7f
    dec a
    sub e
    dec a
    adc a
    db $e3
    add $cd
    sbc $b6
    cp h
    ret nz

    add sp, $4e
    or a
    ret nz

    push bc
    or d
    and c
    sbc b
    ld h, $7f
    jr nc, @-$4c

    cp d
    or e
    inc a
    jp nz, Jump_010_50e8

    db $d3
    ret z

    pop bc
    call nz, $d7cf
    ld d, b
    rrca
    sub l
    ld bc, $21ed
    rrca
    ld b, l
    push bc
    sbc $bc
    ret nz

    call nz, $4eb7
    or d
    ret


    pop bc
    db $dd
    or e
    ld a, [hl-]
    or d
    add $7f
    cp b
    rst $10
    call nc, $b6d0
    rst $10
    ld c, [hl]
    or c
    rst $10
    call c, $d9da
    cp d
    call nz, Call_010_7f26
    or c
    reti


    call nz, $b3b2
    add sp, $50
    adc $c5
    push bc
    call nz, $c5cc
    ld d, b
    inc b
    ld b, [hl]
    nop
    db $ed
    ld hl, $454b
    ld a, a
    inc [hl]
    cp b
    ld a, [hl-]
    ret c

    ret


    ld a, a
    or d
    ret c

    ld [c], a
    cp b
    jp z, $b74e

    ld [c], a
    or e
    jp c, Jump_000_33c2

    ld a, a
    pop bc
    pop hl
    or e
    or d
    ld h, $7f
    set 0, d
    sub $b3
    add sp, $4e
    and b
    adc h
    ret


    adc $b3
    ld h, $7f
    jp nz, Jump_000_26c9

jr_010_493b:
    ld a, a
    pop bc
    or d
    cp e
    or d
    add sp, $50
    call nz, $c9d2
    call z, $cfcc
    jp nc, Jump_000_0d50

    inc a
    nop
    db $ed
    ld hl, $45a9
    sub $b3
    push bc
    ld a, a
    add d
    xor b
    adc c
    ld h, $4e
    or [hl]
    rst $10
    jr nc, jr_010_493b

    ld a, a
    or l
    or l
    rst $18
    jp $d9b2


    add sp, $4e
    cp d
    or e
    call z, $bdde
    reti


    call nz, $ca7f
    ret c

    ld h, $7f
    cp e
    or [hl]
    jr nc, @-$3c

    add sp, $50
    call z, $cecf
    push bc
    call z, Call_010_50d9
    ld d, b
    inc b
    ld b, c
    nop
    db $ed
    ld hl, $4618
    jp z, $d4b5

    ret


    ld a, a
    adc $c8
    db $dd
    ld c, [hl]
    or c
    ret nz

    rst $08
    add $7f
    or [hl]
    inc a
    rst $18
    jp $d9b2


    add sp, -$45
    dec sp
    cp h
    or d
    call nz, $4eb7
    or l
    or l
    ld a, [hl+]
    or h
    inc sp
    ld a, a
    push bc
    cp b
    call nz, $b3b2
    add sp, $50
    db $d3
    ret nc

    call z, $cec9
    call nc, $d2c5
    ld d, b
    ld a, [bc]
    ld a, [hl]
    inc b
    db $ed
    ld hl, $4671
    ld h, $7f
    pop bc
    or [hl]
    rst $10
    ld h, $7f
    jp nz, $b8d6

    ld c, [hl]
    cp d
    or e
    cp a
    or e
    ld a, [de]
    and [hl]
    db $d3
    ld a, a
    ret nz

    or d
    or c
    ret nz

    ret c

    inc sp
    ld c, [hl]
    adc c
    sub h
    add hl, bc
    sub h
    add $7f
    call z, $bbde
    or d
    cp l
    reti


    add sp, $50
    call nc, $cfcf
    call z, $1950
    sbc b
    ld [$21ed], sp
    ldh [rDMA], a
    call nz, $dd3a
    ld a, a
    ret c

    or [hl]
    or d
    cp l
    reti


    ld a, a
    ret nz

    or [hl]
    or d
    ld c, [hl]
    pop bc
    ret


    or e
    db $dd
    db $d3
    jp nz, $b3e8

    ret nc

    ret


    ld a, a
    or e
    or h
    db $dd
    ld c, [hl]
    set 0, h
    db $dd
    ret


    cp [hl]
    jp $bd7f


    cp l
    pop de
    ret


    ld h, $7f
    cp l
    or a
    add sp, $50
    call z, $c7c5
    push bc
    adc $c4
    ld d, b
    inc de
    ld c, $06
    db $ed
    ld hl, $4743
    ld a, a
    or d
    or d
    jp nz, $b4c0

    add $b1
    reti


    ld c, [hl]
    inc sp
    sbc $be
    jp nz, Jump_010_7fc9

    ld b, e
    adc b
    and c
    xor e
    add sp, -$2d
    ret


    cp l
    ld a, [hl+]
    or d
    ld c, [hl]
    adc h
    ld b, c
    db $e3
    inc de
    inc sp
    ld a, a
    jp z, $d9bc

    call nz, $b3b2
    add sp, $50
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    ld d, b
    inc b
    jr z, jr_010_4a64

jr_010_4a64:
    db $ed
    ld hl, $4795
    add l
    add $7f
    cp [hl]
    or d
    cp a
    cp b
    cp l
    reti


jr_010_4a71:
    ld c, [hl]
    ld l, $c2
    jp nc, $bcc2

    ret nz

    jp z, $c92d

    ld a, a
    ld d, h
    add sp, $4e
    pop bc
    ret


    or e
    ld h, $c0
    or [hl]
    cp b
    ld a, a
    push bc
    sbc $33
    db $d3
    ld a, a
    or l
    ld a, $b4
    reti


    add sp, $50
    add $c5
    jp nc, $c3cf

    ret


    rst $08
    push de
    db $d3
    ld d, b
    ld b, c
    ld l, $09
    db $ed
    ld hl, $480f
    or e
    ld a, $b3
    push bc
    ld a, a
    cp [hl]
    or d
    or [hl]
    cp b
    add sp, $4e
    cp b
    pop bc
    or [hl]
    rst $10
    jr nc, jr_010_4a71

    ld a, a
    jp z, $b2b6

    cp d
    or e
    cp [hl]
    sbc $ca
    ld c, [hl]
    cp l
    dec a
    jp $d3c9


    ret


    db $dd
    ld a, a
    call nc, $c2b7
    cp b
    cp l
    add sp, $50
    jp nc, $c4c5

    ld a, a
    rst $00
    push bc
    call Call_000_0350
    jr z, jr_010_4ad8

jr_010_4ad8:
    db $ed
    ld hl, $4878
    sub $d8
    db $d3
    ld a, a
    or [hl]
    ret nz

    or d
    add l
    and l
    add $4e
    or l
    or l
    call c, $c3da
    or d
    reti


    add sp, -$44
    or [hl]
    cp h
    ld a, a
    push bc
    or [hl]
    jp z, $b24e

    ld h, $b2
    call nz, $d47f
    call c, $b6d7
    or d
    add sp, $50
    jp z, $ccc5

    call z, $c6d9
    ret


    db $d3
    ret z

    ld d, b
    add hl, bc
    rst $00
    ld bc, $21ed
    call Call_010_7f48
    cp l
    or a
    call nz, $dfb5
    ret nz

    ld c, [hl]
    jp nc, $cf30

    or [hl]
    rst $10
    ld a, a
    call z, $27bc
    push bc
    ld a, a
    res 6, [hl]
    ret c

    ret


    ld c, [hl]
    ld a, [de]
    db $e3
    sbc a
    db $dd
    ld a, a
    jp z, $bcdf

    ldh [$bd], a
    reti


    add sp, $50
    rst $00
    pop bc
    db $d3
    ld d, b
    dec c
    ld bc, $ed00
    ld hl, $4927
    or d
    ld a, a
    dec b
    adc h
    inc l
    ld [c], a
    or e
    ret


    ld a, a
    cp [hl]
    or d
    jp nc, $c0b2

    or d
    add sp, $4e
    dec b
    adc h
    add $7f
    jp nz, $cfc2

    jp c, $c4d9

    ld c, [hl]
    add c
    xor e
    inc de
    cpl
    or e
    db $d3
    ld a, a
    ld hl, sp+$3b
    ld [c], a
    or e
    inc sp
    ld a, a
    ret nz

    or l
    jp c, $e8d9

    ld d, b
    call $cec1
    call nc, $d3c9
    ld d, b
    rrca
    jr nc, @+$04

    db $ed
    ld hl, $49a3
    inc sp
    ld a, a
    or h
    db $d3
    ret


    db $dd
    ld a, a
    or a
    ret c

    cp e
    or a
    ld c, [hl]
    or d
    or a
    ret


    ret z

    db $dd
    ld a, a
    call nz, $d9d2
    add sp, $2a
    cp b
    rst $08
    jp c, Jump_010_4ec6

    sbc c
    sub a
    db $dd
    jp nz, $dfb6

    jp $c47f


    inc a
    add sp, $50
    add $c9
    jp nc, $c6c5

    call z, Call_010_50d9
    ld [$0159], sp
    db $ed
    ld hl, $4a13
    cp b
    ld a, a
    or c
    rst $10
    call c, $4eda
    sub $d9
    add $c5
    reti


    call nz, $c17f
    pop hl
    or e
    cp h
    sbc $26
    ld c, [hl]
    or c
    or [hl]
    cp b
    ld a, a
    jp $d2de


    jp nz, $d9bd

    add sp, $50
    jp $d5d2


    db $d3
    call nc, $1050
    ld d, a
    inc bc
    db $ed
    ld hl, $4a7f
    db $d3
    ret nz

    cp b
    ld a, a
    ret


    cp h
    or [hl]
    or [hl]
    rst $18
    jp $b14e


    or d
    jp $7fdd


    or a
    ld l, $c2
    cp e
    cp [hl]
    reti


    add sp, $4e
    ld b, c
    xor e
    sub b
    ret


    ld a, a
    call nz, $cab7
    ld a, a
    add l
    and l
    add $7f
    or [hl]
    cp b
    jp c, $e8d9

    ld d, b
    db $d3
    ret z

    push bc
    call z, $50cc
    rrca
    ld h, $02
    db $ed
    ld hl, $4b02
    push bc
    ld h, $b2
    ld a, a
    sub c
    sbc b
    jp z, Jump_010_407f

    xor c
    sbc e
    and [hl]
    add sp, $4e
    or d
    pop bc
    inc [hl]
    ld a, a
    jp z, $cfbb

    jp c, Jump_010_7fc3

    cp h
    rst $08
    rst $18
    ret nz

    rst $10
    ld c, [hl]
    pop bc
    daa
    jp c, $cfd9

    inc sp
    ld a, a
    jp z, $bbc5

    push bc
    or d
    add sp, $50
    jp nc, $d4c1

    call nc, $cec1
    ld d, b
    ld a, [bc]
    ld e, [hl]
    ld bc, $21ed
    ld a, d
    ld c, e
    jp nz, $bcd9

    ld [c], a
    cp b
    inc a
    jp nz, Jump_010_4e26

    or [hl]
    rst $10
    ret nc

    or c
    or d
    ld a, a
    cp h
    ld [c], a
    or e
    ret nz

    or d
    jp z, $d07f

    or h
    push bc
    or d
    add sp, $4e
    pop bc
    or [hl]
    dec l
    cp b
    db $d3
    ret


    add $7f
    or [hl]
    rst $10
    ret nc

    jp nz, $c3b2

    cp b
    reti


    add sp, $50
    call nz, $c7cf
    ld d, b
    rlca
    cp [hl]
    nop
    db $ed
    ld hl, $4be2
    cp d
    cp b
    ld a, a
    cp [hl]
    or d
    inc l
    jp nz, $7fc5

    cp [hl]
    or d
    or [hl]
    cp b
    add sp, $4e
    jp $c6b7


    jp z, $ce7f

    or h
    jp $b67f


    ret nc

    jp nz, $4eb7

    or l
    or d
    jp z, $b5d7

    or e
    ld a, a
    call nz, $d9bd
    add sp, $50
    ret nc

    pop bc
    adc $c7
    rst $08
    call z, $cec9
    ld d, b
    ld e, b
    inc [hl]
    ld [$21ed], sp
    ld e, [hl]
    ld c, h
    push bc
    or [hl]
    add $7f
    cp l
    sbc $33
    or d
    reti


    add sp, $4e
    pop bc
    pop bc
    pop hl
    or e
    db $dd

jr_010_4cda:
    ld a, a
    inc l
    cp a
    cp b
    ld a, a
    cp $f6
    add [hl]
    xor b
    inc sp
    ld c, [hl]
    adc $d8
    push bc
    ld h, $d7
    ld a, a
    add e
    adc d
    db $dd
    ld a, a
    cp e
    ld h, $bd
    add sp, $50
    jp nc, $c3cf

    ld d, b
    inc c
    ld a, h
    ld bc, $21ed
    add $4c
    push bc
    ld a, a
    jp nz, $bb3a

    inc sp
    ld a, a
    or l
    or l
    cpl
    rst $10
    db $dd
    ld c, [hl]
    call nz, $c23b
    ld [hl-], a
    cp c
    reti


    cp d
    call nz, Call_010_7f26
    inc sp
    or a
    reti


    add sp, $4e
    rst $30
    add $c1
    ld a, a
    or l
    ret c

    push bc
    cp b
    jp $7fd3


    jr nc, jr_010_4cda

    inc l
    ld [c], a
    or e
    inc a
    add sp, $50
    jp nz, $d2c9

    call nz, Call_000_0350
    ld [de], a
    nop
    db $ed
    ld hl, $4d22
    ld a, a
    cp l
    or a
    inc sp
    jp z, $b2c5

    add sp, $4e
    cp b
    cp e
    pop de
    rst $10
    ret


    ld a, a
    push bc
    or [hl]
    add $7f
    or [hl]
    cp b
    jp c, $4ec3

    pop bc
    or d
    cp e
    or d
    ld a, a
    pop de
    cp h
    push bc
    inc [hl]
    db $dd
    ld a, a
    call nz, $b4d7
    reti


    add sp, $50
    call z, $d2cf
    ret


    db $d3
    ld a, a
    ld d, b
    inc c
    ld l, b
    ld bc, $21ed
    ld l, d
    ld c, l
    call nz, $c3bc
    or d
    jp $c57f


    add $dd
    ld c, [hl]
    or [hl]
    sbc $26
    or h
    jp $d9b2


    or [hl]
    ld a, a
    call c, $d7b6
    push bc
    or d
    add sp, $4e
    cp h
    rst $18
    ld c, b
    inc sp
    ld a, a
    add e
    adc d
    db $dd
    ld a, a
    jp nz, $c9d9

    ld h, $7f
    call nz, $b2b8
    add sp, $50
    rst $10
    ret


    call z, $d0cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_000_0d50

    dec [hl]
    ld [bc], a
    db $ed
    ld hl, $4dc8
    pop bc
    ld [c], a
    or e
    ret


    or e
    ret c

    ld [c], a
    cp b
    ld c, [hl]
    cp h
    ld [c], a
    or e
    ret z

    sbc $26
    ld a, a
    dec a
    xor h
    sub e
    or [hl]
    rst $10
    ld a, a
    jp nc, $d22b

    reti


    call nz, $a34e
    xor e
    ld [$e3a5], sp
    add $7f
    call $bcde
    sbc $7f
    cp h
    jp $c0b2


    add sp, $50
    jp nc, $c3cf

    bit 2, b
    ld a, [bc]
    ld a, [de]
    inc b
    db $ed
    ld hl, $4e22
    or [hl]
    ret


    ld a, a
    cp e
    or [hl]
    ret nc

    pop bc
    db $dd
    ld c, [hl]
    or c
    reti


    or d
    jp $d9b2


    call nz, Call_000_097f
    xor b
    db $e3
    xor e
    ld h, $4e
    cp d
    db $db
    ld h, $df
    jp $b87f


    reti


    cp d
    call nz, Call_010_7f26
    or c
    reti


    add sp, $50
    push bc
    rst $00
    rst $00
    ld d, b
    dec bc
    ld e, d
    ld bc, $21ed
    ld e, a
    ld c, [hl]
    ld a, a
    or d
    cp b
    jp nz, $7fb6

    ret nz

    rst $08
    ld a, [hl+]
    db $dd
    ld a, a

Jump_010_4e26:
    or e
    pop de
    add sp, $4e
    cp a
    ret


    ld a, a
    ret nz

    rst $08
    ld a, [hl+]
    jp z, $b47f

Jump_010_4e33:
    or d
    sub $b3
    ld a, a
    rst $08
    sbc $c3
    sbc $33
    ld c, [hl]
    db $d3
    ret


    cp l
    ld a, [hl+]
    cp b
    ld a, a
    or l
    or d
    cp h
    or d
    ld a, a
    rst $10
    cp h
    or d
    add sp, $50
    add $cf
    jp nc, $c5c3

    ld a, a
    ld d, b
    rrca
    pop bc
    ld [bc], a
    db $ed
    ld hl, $4e93
    ret


    push bc
    or d
    ld a, a
    or a
    ld [c], a
    or e
    inc l
    sbc $c5
    ld c, [hl]
    add $b8
    ret nz

    or d
    db $dd
    ld a, a
    db $d3
    jp nz, $b5e8

    db $d3
    or d
    ld a, a
    add $d3
    jp nz, $4ec9

    or e
    sbc $44
    sbc $c5
    inc [hl]
    ret


    ld a, a
    cp h
    ld a, [hl+]
    call nz, $7fdd
    jp $30c2


    or e
    add sp, $50
    call $d2c9
    pop bc
    rst $00
    push bc
    ld d, b
    dec c
    ld hl, $ed02
    ld hl, $4ee6
    inc l
    cp d
    rst $08
    cp [hl]
    reti


    ret


    ld h, $7f
    or e
    rst $08
    or d
    add sp, $4e
    ld b, b
    xor e
    sub e
    sbc l
    add c
    sbc a
    inc sp
    ld a, a
    jp nz, $dfb8

    ret nz

    add l
    dec a
    ld h, $4e
    adc $de
    call nz, $c6b3
    ld a, a
    or c
    rst $10
    call c, $d9da
    call nz, $b3b2
    add sp, $50

Jump_010_4ec6:
    set 1, c
    jp Jump_010_50cb


    rrca
    ld a, [c]
    ld bc, $21ed
    ld a, [hl-]
    ld c, a
    push de

Jump_010_4ed3:
    or e
    add $7f
    ret


    dec sp

Call_010_4ed8:
    pop bc
    ld sp, $bcd0
    jp $c44e


    or l
    cp b
    ld a, a
    jp z, $dac5

    jp $d9b2


Jump_010_4ee8:
    ld a, a
    ld a, [hl-]
    or c
    or d
    inc sp
    db $d3
    ld c, [hl]
    or c
    or d
    jp $7fdd


    cp c
    ret c

    or c
    add hl, hl
    reti


    cp d
    call nz, Call_010_7f26
    inc sp
    or a
    reti


    add sp, $50
    jp nz, $d8cf

    ret


    adc $c7
    ld d, b
    ld c, $f6
    ld bc, $21ed
    sub d
    ld c, a
    ld a, a
    ret nz

    rst $08
    cp h
    or d
    ld h, $4e
    ret


    ret c

    or e
    jp nz, $c3df

    or d
    reti


    add sp, $40
    xor e
    sub b
    ret


    adc h
    ld b, c
    db $e3
    inc de
    jp z, $bc4e

    sbc $b6
    sbc $be
    sbc $d6
    ret c

    db $d3
    ld a, a
    jp z, $b2d4

    add sp, $50
    jp $c2cf


    jp nc, Jump_010_50c1

    inc hl
    adc d
    ld [bc], a
    db $ed
    ld hl, $4ff2
    sub $b3
    ld h, $7f
    cp d
    call c, $b6b2
    or l
    add $4e
    ret nc

    or h
    reti


    add sp, -$2a
    call c, $c3b2
    or a
    jp z, $bf7f

    ret


    db $d3
    sub $b3
    db $dd
    ld c, [hl]
    ret nc

    ret nz

    jr nc, @-$45

    inc sp
    ld a, a
    add $29
    jr nc, @-$42

    jp $cfbc


    or e
    add sp, $50
    call $d3d5
    ret z

    jp nc, $cfcf

    call Call_000_0a50
    daa
    ld bc, $21ed
    ld e, d
    ld d, b
    ld a, a
    inc [hl]
    cp b
    adc $b3
    cp h
    db $dd
    ld c, [hl]
    rst $08
    or a
    pop bc
    rst $10
    cp l
    add sp, -$44
    or [hl]
    cp h
    ld a, a
    pop bc
    pop hl
    or e
    ld a, [hl+]
    cp b
    inc sp
    jp z, $ba4e

    ret


    adc $b3
    cp h
    db $dd
    ld a, a
    or [hl]
    sbc $48
    or e
    call nc, $c6b8
    ld a, a
    cp l
    reti


    add sp, $50
    call nz, $c3d5
    bit 2, b
    ld [$00c4], sp
    db $ed
    ld hl, $50bd
    jp nz, $c6b3

    ld a, a
    push bc
    call nc, $bbcf
    jp c, $b2c3

    reti


    add sp, $4e
    cp d
    ret


    ld a, a
    dec l
    jp nz, Jump_000_26b3

    ld a, a
    jp z, $bc29

    cp b
    push bc
    reti


    call nz, $cc4e
    cp h
    daa
    push bc
    ld a, a
    pop bc
    or [hl]
    rst $10
    db $dd
    ld a, a
    jp nz, $b2b6

    jp z, $d22c

    reti


    add sp, $50
    ret z

    reti


    ret nc

    adc $cf
    db $d3
    ret


    db $d3
    ld d, b
    ld a, [bc]
    ld b, h
    ld bc, $21ed
    rra
    ld d, c
    or d
    or e
    ld a, a
    inc sp
    sbc $be
    jp nz, Jump_010_7fc9

    ld c, [hl]
    or d
    or a
    db $d3
    ret


jr_010_500b:
    ld a, a
    add hl, de
    add a
    ret


    ld a, a
    cp h
    cp a
    sbc $e8
    ld c, [hl]
    cp e
    or d
    ret nc

    sbc $2c
    pop hl
    jp nz, Jump_010_7f26

    call nz, $b2b8
    jr nc, jr_010_500b

    ld d, b
    jp $c2cf


    jp nc, Jump_010_50c1

    ld c, $b8
    dec bc
    db $ed
    ld hl, $5190
    sub $b3
    push bc
    ld a, a
    or [hl]
    ret nz

    or d
    ld a, a
    add l
    and l
    inc sp
    ld c, [hl]
    or l
    or l
    call c, $c3da
    or d
    reti


    add sp, -$09
    ret z

    sbc $c6
    ld a, a
    rst $30
    or [hl]
    or d
    ld c, [hl]
    jr nc, @-$1f

Call_010_5050:
    ld b, l
    cp h
    jp $b57f


    or l
    or a
    cp b
    push bc

jr_010_5059:
    reti


    add sp, $50
    ret nc

    push de
    add $c6
    adc l
    add $c9
    jp nc, Jump_010_50c5

    dec c
    cp l
    ld bc, $21ed
    ld c, $52
    cp b
    inc sp
    ld c, [hl]
    ret nc

    jp nz, $dfb6

    ret nz

    add sp, -$48
    pop bc
    or [hl]
    rst $10
    ld a, a
    adc $c9
    or l
    db $dd

Call_010_507f:
    jp z, $e8b8

    ld c, [hl]
    ret nz

    or d
    or l
    sbc $ca
    ld a, a
    rst $30
    ld hl, sp-$0a
    or $34
    ld a, a
    db $d3
    or c
    reti


    add sp, $50
    db $d3
    ret z

    rst $08
    jp $7fcb


    ld d, b
    dec bc
    inc l
    ld bc, $21ed
    add c
    ld d, d
    or a
    ld h, $7f
    jr nc, jr_010_5059

    cp d
    or e
    inc a
    jp nz, Jump_010_4e33

    or l
    or l
    or a
    push bc
    ld a, a
    jp z, Jump_000_33c2

    sbc $bc
    ld [c], a
    ld a, a
    push bc
    inc [hl]
    add $7f
    ld c, [hl]
    cp h
    ld a, [hl-]
    cp h

Jump_010_50c1:
    ld a, [hl-]
    ld a, a
    or c

Jump_010_50c4:
    rst $10

Call_010_50c5:
Jump_010_50c5:
    call c, $d9da
    add sp, $50
    push bc

Jump_010_50cb:
    call z, $c3c5
    call nc, $c9d2
    jp c, Jump_010_50c5

Jump_010_50d4:
    ld a, a
    ld a, [bc]
    ld e, b
    ld [bc], a
    db $ed

Call_010_50d9:
    ld hl, $52d4
    ld a, a
    jp c, $b9de

    jp nz, $c3bc

jr_010_50e3:
    ld c, [hl]

Call_010_50e4:
    or a
    ld [c], a
    or e
    ret c

Jump_010_50e8:
    ld [c], a
    cp b
    push bc
    ld a, a
    inc l
    ret c

    ld [c], a
    cp b
    cp [hl]
    sbc $c4
    ld c, [hl]
    cp d
    or e
    inc sp
    sbc $b1
    jp nz, $7fdd

    adc $b3
    cp h
    ldh [$bd], a
    reti


    add sp, $50
    rst $00
    pop bc
    db $d3
    ld d, b
    ld b, $0a
    nop
    db $ed
    ld hl, $532f
    ld a, a
    add hl, de
    and [hl]
    db $e3
    xor e
    inc l
    ld [c], a
    or e
    ret


    ld a, a
    or [hl]
    rst $10
    jr nc, jr_010_50e3

    ld c, [hl]
    db $d3
    or e
    inc [hl]
    cp b
    ret


    ld a, a
    dec b
    adc h
    ld h, $7f
    jp nz, $dfcf

    jp $d9b2


    add sp, $4e
    pop bc
    or [hl]
    cp b
    add $b8
    reti


    call nz, $b87f
    cp e
    or d
    add sp, $50
    ld d, b
    dec b
    jr jr_010_5142

    db $ed

jr_010_5142:
    ld hl, $539c
    ret nc

    ret


    cp d
    push bc
    cp h
    ld h, $7f
    or [hl]
    reti


    cp b
    ld a, a
    or a
    ld [c], a
    or e
    ld a, $b3
    push bc
    ld c, [hl]
    cp [hl]
    or d
    or [hl]
    cp b
    add sp, -$4b
    cp d
    rst $18
    jp $b17f


    ld a, [hl-]
    jp c, $c4d9

    ld c, [hl]
    jp Jump_010_7f26


    jp nz, $d7b9

    jp c, $b8c5

    push bc
    reti


    add sp, $50
    db $d3
    push bc
    pop bc
    ld a, a
    call z, $cfc9
    adc $50
    dec bc
    add h
    inc bc
    db $ed
    ld hl, $53f8
    or e
    add $7f
    or l
    or l
    call c, $c0da
    ld c, [hl]
    set 1, h
    jp z, Jump_000_3c7f

    or c
    jp nz, $c3b8

    ld a, a
    inc l
    ld [c], a
    or e
    inc a
    add sp, $4e
    jp c, $b6b2

    ld a, [$34f6]
    ld a, a
    inc sp
    db $d3
    ld a, a
    or [hl]
    jp nz, $b334

    inc sp
    or a
    reti


    add sp, $50
    call $cccf
    push bc
    ld d, b
    ld [bc], a
    ld [$ed00], sp
    ld hl, $5467
    ld a, a
    or c
    cp e
    or d
    call nz, $dbba

jr_010_51c3:
    db $dd
    ld a, a
    or d
    inc [hl]
    or e
    add sp, $4e
    adc $d8
    cp l
    cp l
    sbc $30
    or c
    call nz, $7fca
    inc l
    jp nc, $26de

    ld c, [hl]
    db $d3
    ret c

    or c
    ld h, $df
    jp $d9b2


    ret


    inc sp
    ld a, a
    cp l
    jr z, jr_010_51c3

    or [hl]
    reti


    add sp, $50
    jp nz, $ccd5

    call z, Call_010_507f
    ld c, $74
    inc bc
    db $ed
    ld hl, $54d3
    ret c

    cp h
    jp $d9b8


    call nz, $4eb7
    ld hl, sp-$32
    sbc $c9
    ld a, a
    cp h
    rst $18
    ld c, b
    inc sp
    ld a, a
    inc l
    inc a
    sbc $c9
    ld c, [hl]
    or [hl]
    rst $10
    jr nc, @-$21

    ld a, a
    ld b, c
    adc e
    ld b, c
    adc e
    call nz, $c07f
    ret nz

    cp b
    add sp, $50
    ret z

    push de
    adc $d4
    ld a, a
    jp nz, $d2c9

    call nz, Call_010_5050
    ld [$0096], sp
    db $ed
    ld hl, $5526
    reti


    ret nz

    jp nc, $4ec9

    cp h
    ld [c], a
    cp b
    inc a
    jp nz, Jump_010_7fc9

    add a
    add [hl]
    db $dd
    ld a, a
    or d
    rst $18
    ld c, b
    sbc $4e
    or d
    jp nz, $7fd3

    db $d3
    rst $18
    jp $b17f


    reti


    or d
    jp $d9b2


    add sp, $50
    ret


    adc $d3
    push bc
    jp Jump_010_50d4


    ld a, [bc]
    inc l
    ld bc, $21ed
    ld a, c
    ld d, l
    db $d3
    ld a, a
    jp nc, Jump_010_7f26

    and a
    db $e3
    rrca
    db $e3
    ret


    ld c, [hl]
    call nc, $dcb8
    ret c

    db $dd
    cp h
    jp $b67f


    jp nz, $b334

    inc sp
    or a
    reti


    add sp, $4e
    jp nc, $d7b6

    ld a, a
    ld a, [de]
    db $e3
    sbc a
    db $dd
    ld a, a
    jp z, $bcdf

    ldh [$bd], a
    reti


    add sp, $50
    call nz, $c1d2
    rst $00
    rst $08
    adc $50
    ld d, $34
    ld [$21ed], sp
    jp nz, $b255

    or [hl]
    cp b
    inc sp
    ld a, a
    cp a
    rst $10
    db $dd
    ld a, a
    call nz, $e83c
    ld c, [hl]
    pop bc
    or a
    pop hl
    or e
    db $dd
    ld a, a
    call nc, $f7b8
    db $fc
    inc l
    or [hl]
    sbc $33
    ld c, [hl]
    rst $30
    cp h
    pop hl
    or e
    ld a, a
    cp h
    jp $cfbc


    or e
    add sp, $50
    call nc, $c9d7
    adc $7f
    jp nz, $d2c9

    call nz, Call_000_0e50
    adc b
    ld bc, $21ed
    inc sp
    ld d, [hl]
    ld a, a
    ret nc

    jp nz, $dfb6

    ret nz

    ld c, [hl]
    call z, $c2c0
    ret


    ld a, a
    or c
    ret nz

    rst $08
    db $dd
    ld a, a
    db $d3
    jp nz, $437f

    adc b
    and c
    xor e
    add sp, $4e
    inc l
    cp a
    cp b
    ld a, a
    rst $30
    or $f6
    add [hl]
    xor b
    inc sp
    ld a, a
    jp z, $d9bc

    add sp, $50
    call nc, $c4c1
    ret nc

    rst $08
    call z, Call_010_50c5
    ld b, $7c
    nop
    db $ed
    ld hl, $569f
    db $db
    or d
    set 1, h
    jp z, $b37f

    cp l
    cp b
    ld c, [hl]
    cp h
    jp nc, $c3df

    or d
    reti


    add sp, -$3b
    or d
    cpl
    or e
    ret


    ld a, a
    or d
    pop bc
    inc a
    ld h, $4e
    cp l
    cp c
    jp $b37f


    dec l
    rst $08
    or a
    inc l
    ld [c], a
    or e
    add $7f
    ret nc

    or h
    reti


    add sp, $50
    call nc, $d9cf
    jp nz, $c2c1

    reti


    ld a, a
    ld d, b
    ld c, $96
    ld bc, $21ed
    dec d
    ld d, a
    ld a, a
    cp d
    call nz, $dd3a
    ld a, a
    jp z, $bdc5

    ld h, $4e
    rst $08
    jr nc, jr_010_53dc

    push bc
    add $dd
    or d
    rst $18
    jp $d9b2


    or [hl]
    ld a, a
    call z, $b2d2
    inc sp
    ld c, [hl]
    add hl, hl
    sbc $2b
    or d
    ld a, a
    cp c
    sbc $b7
    pop hl
    or e
    cp e
    jp c, $b2c3

    reti


    add sp, $50
    add $cc
    pop bc
    call Call_010_50c5
    inc d
    ld e, b
    ld [bc], a
    db $ed
    ld hl, $5782
    call nz, Call_010_43d8
    adc b
    and c
    xor e
    ret


    ld a, a
    set 0, h
    jp nz, Jump_010_4ee8

    add h
    and a
    xor e
    dec bc
    or d
    db $db
    ret


    ld a, a
    db $d3
    or h
    reti


    sub $b3
    push bc
    sbc c
    sub a
    ld h, $4e
    ret nc

    reti


    db $d3
    ret


    db $dd
    ld a, a
    or c
    rst $18
    call nz, $bdb3
    reti


    add sp, $50
    add $d2
    push bc
    push bc
    jp c, Jump_010_50c5

    ld de, $022a
    db $ed
    ld hl, $57ff
    call nz, Call_010_43d8
    adc b
    and c
    xor e
    ret


    ld a, a
    set 0, h
    jp nz, Jump_010_4ee8

    push bc
    ld h, $b2
    ld a, a
    cp h
    rst $18
    ld c, b
    ld h, $7f
    ret nz

jr_010_53dc:
    push bc
    dec sp
    or d
    jp $c44e


    sbc $33
    or d
    cp b
    ld a, a
    cp l
    ld h, $c0
    jp z, $bd7f

    ld a, [hl-]
    rst $10
    cp h
    or d
    add sp, $50
    db $d3
    ret z

    rst $08
    jp Jump_010_50cb


    db $10
    ld c, $02
    db $ed
    ld hl, $586b
    ld a, a
    call nz, Call_010_43d8
    adc b
    and c
    xor e
    ret


    ld a, a
    set 0, h
    jp nz, Jump_010_4ee8

    call nz, $c43c
    or a
    add $7f
    add hl, de
    sub b
    add hl, de
    sub b
    call nz, $c57f
    add $b6
    ret


    ld c, [hl]
    jp z, $b92c

    reti


    sub $b3
    push bc
    ld a, a
    or l
    call nz, $bd26
    reti


    add sp, $50
    jp $c1c8


    adc $c7
    push bc
    pop bc
    jp nz, $c5cc

    ld d, b
    inc bc
    jr z, jr_010_543c

jr_010_543c:
    db $ed
    ld hl, $58cd
    ld a, a
    jp nz, $d8b8

    db $dd
    ld c, [hl]
    inc l
    inc a
    sbc $33
    ld a, a
    cp b
    ret nc

    or [hl]
    or h
    jp $ce7f


    or [hl]
    ret


    ld c, [hl]
    cp [hl]
    or d
    jp nc, $c0b2

    or d
    add $7f
    call $bcde
    sbc $bd
    reti


    add sp, $50
    rst $08
    rst $10
    call z, $0450
    ld a, [hl+]
    nop
    db $ed
    ld hl, $591c
    jp z, $c87f

    jp $b63a


    ret c

    or d
    reti


    add sp, $4e
    sub $d9
    add $c5
    reti


    call nz, $d27f
    ld h, $7f
    or [hl]
    ld h, $d4
    or a
    ld c, [hl]
    push bc
    call c, $d83a
    db $dd
    ld a, a
    or c
    reti


    or a
    rst $08
    call c, $e8d9
    ld d, b
    jp nc, $d6c9

    push bc
    jp nc, $c37f

    jp nc, $c2c1

    ld d, b
    inc b
    ld b, c
    nop
    db $ed
    ld hl, $598c
    jp nz, $d9b6

    add sp, $4e
    or l
    or l
    or a
    push bc
    ld a, a
    sbc c
    adc d
    sbc [hl]
    jp z, $d37f

    daa
    call nz, $c3df
    db $d3
    ld c, [hl]
    or c
    call nz, $d7b6
    ld a, a
    rst $08
    ret nz

    ld a, a
    jp z, $c3b4

    cp b
    reti


    add sp, $50
    add $cf
    ret c

    ld d, b
    ld b, $63
    nop
    db $ed
    ld hl, $5a00
    ld h, $7f
    db $fc
    adc $de
    ret


    ld a, a
    cp h
    rst $18
    ld c, b
    ld h, $4e
    or e
    jp nz, $bcb8

    or d
    add sp, -$42
    or d
    pop bc
    ld [c], a
    or e
    cp l
    reti


    call nz, $bb4e
    rst $10
    add $7f
    cp h
    rst $18
    ld c, b
    ld h, $7f
    call z, $d9b4
    add sp, $50
    add $cf
    ret c

    ld d, b
    dec bc
    rst $00
    nop
    db $ed
    ld hl, $5a63
    add $7f
    or [hl]
    ld h, $d4
    cp b
    ld a, a
    ret nz

    or d
    db $d3
    or e
    call nz, $ff4e
    adc $de
    ret


    ld a, a
    push bc
    ld h, $b2
    ld a, a
    cp h
    rst $18
    ld c, b
    db $dd
    ld a, a
    db $d3
    jp nz, Jump_010_4ee8

    rst $30
    or $f6
    or $c8
    sbc $ca
    ld a, a
    or d
    or a
    reti


    call nz, $b27f
    call c, $d9da
    add sp, $50
    call $d5cf
    db $d3
    push bc
    ld d, b
    inc b
    inc a
    nop
    db $ed
    ld hl, $5ac4
    ret c

    ld [c], a
    or e
    ld h, $dc
    add $4e
    pop bc
    or d
    cp e
    or d
    ld a, a
    inc sp
    sbc $b7
    inc a
    cp b
    db $db
    db $dd
    ld a, a
    db $d3
    jp nz, Jump_010_4ee8

    ld b, c
    xor e
    sub b
    ret


    call nz, $c6b7
    ld a, a
    adc $b3
    inc sp
    sbc $bd
    reti


    add sp, $50
    call $d5cf
    db $d3
    push bc
    ld d, b
    ld [$012c], sp
    db $ed
    ld hl, $5b38
    rst $30
    or $cf
    sbc $1c
    and [hl]
    sub e
    add $4e
    ret nz

    rst $18
    cp l

jr_010_558e:
    reti


    cp d
    call nz, $b1d3
    ret c

    ld a, a
    call $c68f
    cp e
    call c, $c4d9
    ld c, [hl]
    add c
    xor e
    inc de
    cpl
    or e
    inc sp
    db $d3
    ld a, a
    or a
    ld l, $c2
    cp l
    reti


    add sp, $50
    call nz, $c1d2
    rst $00
    rst $08
    adc $50
    ld [de], a
    ld hl, $ed00
    ld hl, $5b9e
    cp h
    sbc $c1
    ld [c], a
    or e
    jp z, $f84e

    and b
    db $e3
    sub e
    and [hl]
    ld a, a
    or d
    inc l
    ld [c], a
    or e
    add sp, $30
    rst $18
    ld b, l
    db $dd
    ld c, [hl]
    cp b
    ret c

    or [hl]
    or h
    cp h
    jp $b57f


    or l
    or a
    cp b
    push bc
    reti


    add sp, $50
    call nz, $c1d2
    rst $00
    rst $08
    adc $50
    jr z, jr_010_558e

    nop
    db $ed
    ld hl, $5c09
    or e
    ret nc

    push bc
    inc [hl]
    add $7f
    cp l
    pop de
    call nz, $b3b2
    add sp, $4e
    jp z, $ddc8

    db $d3
    ret nz

    push bc
    or d
    ld h, $7f
    ret nz

    rst $08
    add $7f
    cp a
    rst $10
    db $dd
    ld c, [hl]
    call nz, Call_010_7f3c
    cp l
    ld h, $c0
    ld h, $7f
    db $d3
    cp b
    add hl, hl
    or a
    cp e
    jp c, $e8d9

    ld d, b
    jp $d5d2


    db $d3
    call nc, Call_000_0550
    ld [hl], e
    nop
    db $ed
    ld hl, $5c71
    inc a
    jp nz, Jump_010_7fc9

    or [hl]
    cp [hl]
    or a
    or [hl]
    rst $10
    ld c, [hl]
    cp e
    or d
    cp [hl]
    or d
    cp h
    ret nz

    ld b, e
    adc b
    and c
    xor e
    add sp, $4e
    or [hl]
    ret nz

    or d
    ld a, a
    add l
    and l
    inc sp
    ld a, a
    ret nc

    db $dd
    ld a, a
    rst $08
    db $d3
    rst $18
    jp $d9b2


    add sp, $50
    db $d3
    ret z

    push bc
    call z, $50cc
    dec c
    sub l
    ld bc, $21ed
    db $ec
    ld e, h
    ld a, a
    inc l
    push de
    or e
    add $7f
    or l
    sub $27
    ld c, [hl]
    cp l
    reti


    inc [hl]
    or d
    ld a, a
    add l
    sbc l
    inc sp
    ld a, a
    or h
    db $d3
    ret


    db $dd
    ld a, a

jr_010_5678:
    call nz, $b4d7
    ld c, [hl]
    ret nz

    or d
    or h
    or a
    db $dd
    ld a, a
    cp l
    or d
    call nz, $c3df
    cp h
    rst $08
    or e
    add sp, $50
    call nz, $c1d2
    rst $00
    rst $08
    adc $50
    inc b
    ld d, b
    nop
    db $ed
    ld hl, $5d4d
    or e
    add $7f
    add a
    and [hl]
    add a
    and [hl]
    rst $08
    or [hl]
    jp c, $4ec0

    cp h
    rst $18
    ld c, b
    inc sp
    ld a, a
    or [hl]
    rst $10
    jr nc, jr_010_5678

    ld a, a
    add hl, de
    and l
    xor e
    adc h
    db $dd
    call nz, $e8d9
    ld c, [hl]
    cp b
    pop bc
    or [hl]
    rst $10
    ld a, a
    adc h
    sbc [hl]
    db $dd
    ld a, a
    jp z, $bab8

    call nz, Call_010_7f26
    or c
    reti


    add sp, $50
    call nz, $c1d2
    rst $00
    rst $08
    adc $50
    inc c
    ld a, [$ed00]
    ld hl, $5dd0
    call c, $b3db
    call nz, $d9bd
    call nz, $b64e
    rst $10
    jr nc, jr_010_5712

    pop hl
    or e
    add $7f
    jp z, $d9b4

    ld a, a
    sub e
    ld [$4ec6], sp
    cp e
    cp e
    jp c, Jump_010_7fc3

    or a
    ld l, $c2
    cp l
    reti


    cp d
    call nz, $7fd3
    or c
    reti


    add sp, $50
    call $d5cf
    db $d3
    push bc
    ld d, b
    ld b, $78
    nop
    db $ed
    ld hl, $5e30
    push bc

jr_010_5712:
    db $dd
    ld a, a
    adc $df
    jp $bd7f


    pop de
    add sp, $4e
    inc l
    inc a
    sbc $c6
    ld a, a
    or a
    cp c
    sbc $26
    ld a, a
    cp [hl]
    rst $08
    reti


    call nz, $cf4e
    reti


    cp b
    push bc
    rst $18
    jp $d07f


    db $dd
    ld a, a
    rst $08
    db $d3
    reti


    add sp, $50

jr_010_573a:
    call $d5cf
    db $d3
    push bc
    ld d, b
    ld a, [bc]
    daa
    ld bc, $21ed
    sbc l
    ld e, [hl]
    ld a, a
    jp z, $d8bc

    ld a, a
    rst $08
    call c, Call_010_4ed8
    cp [hl]
    push bc
    or [hl]
    ret


    ld a, a
    sbc c
    ret c

    call nz, $bd7f
    reti


    inc [hl]
    or d
    ld a, a
    sub c
    and b
    ret


    ld c, [hl]
    cp d
    or e
    add hl, hl
    or a
    ld h, $7f
    call nz, $b2b8
    add sp, $50
    rst $10
    ret z

    ret


    jp nc, $d0cc

    rst $08
    rst $08
    call z, $0450
    ld c, e
    nop
    db $ed
    ld hl, $5f01
    ld a, a
    cp l
    sbc $33
    or d
    ret nz

    ld c, [hl]
    cp d
    jr nc, jr_010_573a

    ld a, a
    ld b, e
    adc b
    and c
    xor e
    add sp, -$09
    or $48
    sbc $c9
    ld a, a
    or c
    cp h
    db $dd
    ld c, [hl]
    cp b
    ret z

    rst $10
    cp [hl]
    jp $b57f


    sub $28
    add sp, $50
    rst $10
    ret z

    ret


    jp nc, $d0cc

    rst $08
    rst $08
    call z, Call_000_0a50
    ld e, [hl]
    ld bc, $21ed
    ld l, b
    ld e, a
    cp h
    ret


    ld a, a
    sub $b3
    add $4e
    jp z, $c0df

    jp nz, $bc7f

    jp $e8d9


    cp h
    ld h, $d0
    jp nz, $c4b8

    ld c, [hl]
    inc [hl]
    or e
    inc l
    add $7f
    or [hl]
    ret nc

    jp nz, $c3b2

    ld a, a
    cp b
    reti


    add sp, $50
    jp nz, $ccc1

    call z, $cfcf
    adc $50
    dec b
    scf
    nop
    db $ed
    ld hl, $5fc8
    or a
    or d
    ld a, a
    set 0, h
    ret nc

    inc sp
    ld c, [hl]
    cp e
    cp a
    or d
    cp d
    ret nc

    ld a, a
    cp d
    cp d
    pop bc
    sub $b2
    ld a, a
    or e
    ret nz

    db $dd
    ld c, [hl]
    or e
    ret nz

    or d
    ld a, a
    or c
    or d
    jp $7fdd


    ret z

    pop de
    rst $10
    cp [hl]
    reti


    add sp, $50
    jp nz, $ccc1

    call z, $cfcf
    adc $50
    ld a, [bc]
    ld a, b
    nop
    db $ed
    ld hl, $6038
    ld a, a
    cp h
    push bc
    call nc, $c5b6
    ld c, [hl]
    ret nz

    or d
    db $d3
    or e
    jp z, $b37f

    rst $18
    call nz, $bdd8
    reti


    adc $34
    add sp, $4e
    cp c
    ld h, $dc
    jp z, $ba7f

    or e
    or a
    pop hl
    or e
    set 3, [hl]
    jr nc, @-$16

    ld d, b
    push bc
    sub $cf
    call z, $d4d5
    ret


    rst $08
    adc $50
    inc bc
    ld b, c
    nop
    db $ed
    ld hl, $60ab
    xor e
    add $4e
    cp h
    sbc $b6
    cp l

jr_010_585e:
    reti


    ld a, a
    or [hl]
    ret


    or e
    cp [hl]
    or d
    db $dd
    ld a, a
    db $d3
    jp nz, $d24e

    dec l
    rst $10
    cp h
    or d
    ld a, a
    ld b, e
    adc b
    and c
    xor e
    jr nc, jr_010_585e

    ld d, b
    add $cc
    pop bc
    call Call_010_50c5
    add hl, bc
    ld a, [$ed00]
    ld hl, $6113
    adc $c9
    or l
    inc a
    cp b
    db $db
    ld h, $7f
    or c
    ret c

    ld c, [hl]
    call z, $b8b6
    ld a, a
    or d
    or a
    db $dd
    ld a, a
    cp l
    or d
    cp d
    sbc $30
    or c
    call nz, $f74e
    db $fd
    or $f6
    inc [hl]
    ld a, a
    ret


    ld a, a
    set 3, l
    ld a, a
    jp z, $e8b8

    ld d, b
    call nc, $d5c8
    adc $c4
    push bc
    jp nc, Jump_000_0850

    push af
    nop
    db $ed

jr_010_58ba:
    ld hl, $616d
    inc [hl]
    db $db
    or d
    ret nz

    ret c

    cp l
    reti


    call nz, Call_000_2e4e
    sbc $bc
    sbc $c9
    ld a, a
    cp c
    ld h, $7f
    jp z, $c9d8

    ld a, a
    sub $b3
    add $4e
    cp e
    or [hl]
    jr nc, jr_010_58ba

    jp $b17f


    or d
    jp $7fdd


    jp nz, $c7d7

    cp b
    add sp, $50
    add $cf
    pop bc
    call Call_000_0a50
    ld [hl+], a
    ld bc, $21ed
    ldh [$61], a
    ld a, a
    cp e
    or d
    ld a, $b3
    ret


    ld a, a
    jp nz, $d8b8

    ld h, $4e
    ret nc

    dec l
    ret


    ld a, a
    inc a
    sbc $bc
    call nz, $c67f
    jp $d9b2


    add sp, $4e
    ret nc

    dec l
    add $7f
    call nz, $d9b9
    call nz, $d07f
    or h
    push bc
    cp b
    push bc
    reti


    add sp, $50
    add $cf
    jp nc, $c5c3

    ld d, b
    ld [$00c3], sp
    db $ed
    ld hl, $6246
    ld a, a
    or a
    sbc $c6
    cp b
    add $7f
    push bc
    rst $18
    jp $d8b5


    ld c, [hl]
    cp d
    inc [hl]
    db $d3
    adc $34
    ret


    ld a, a
    or l
    or l
    or a
    cp e

jr_010_5945:
    cp h
    or [hl]
    push bc
    or d
    ret


    add $4e
    or l
    call nz, $7fc5
    rst $30
    or $f6
    add $de
    db $dd
    ld a, a
    push bc
    add hl, hl
    call nz, $be3a
    reti


    add sp, $50
    jp nz, $d4c1

    ld d, b
    ld [$004b], sp
    db $ed
    ld hl, $62a8
    adc $b3
    ret


    ld a, a
    jp nc, Jump_010_7f26

    cp a
    sbc $2b
    or d
    cp h
    push bc
    or d
    add sp, $4e
    cp b
    pop bc
    or [hl]
    rst $10
    ld a, a
    pop bc
    ld [c], a
    or e
    or l
    sbc $44
    db $dd
    ld a, a
    jr nc, jr_010_5945

    jp $b84e


    rst $10
    call nc, $ddd0
    ld a, a
    call nz, $cf3b
    call c, $e8d9
    ld d, b
    db $d3
    adc $c1
    set 0, l
    ld d, b
    inc d
    ld b, l
    nop
    db $ed
    ld hl, $6321
    or l
    or l
    cp b
    ld a, a
    cp [hl]
    or d
    cp a
    cp b
    cp l
    reti


    add sp, $4e
    cp h
    ret nz

    db $dd
    ld a, a
    sub b
    xor b
    sub b
    xor b
    ld a, a
    cp e
    cp [hl]
    jp $cf7f


    call c, $c9d8
    ld c, [hl]
    or a
    cp c
    sbc $dd
    ld a, a
    or [hl]
    sbc $2c
    call nz, $e8d9
    ld d, b
    call $d3d5
    ret z

    jp nc, $cfcf

    call Call_000_0350
    ld [hl], $00
    db $ed
    ld hl, $6379
    jp z, $c3b4

    or d
    reti


    ret


    jp z, $c44e

    or e
    pop bc
    pop hl
    or e
    or [hl]
    cp a
    or e
    ld a, a
    call nz, $b3b2
    ld a, a
    add [hl]
    sbc b
    adc c
    add sp, $4e
    cp a
    jr nc, @-$3c

    call nz, $867f
    sbc b
    adc c
    db $d3
    ld a, a
    or l
    or l
    or a
    cp b
    push bc
    reti


    add sp, $50
    call nc, $c4c1
    ret nc

    rst $08
    call z, Call_010_50c5
    ld a, [bc]
    ret z

    nop
    db $ed
    ld hl, $63f9
    ld a, a
    jp z, $c0df

    jp nz, $c3bc

    or l
    ret c

    ld a, a
    ld c, [hl]
    pop bc
    inc l
    ld [c], a
    or e
    inc sp
    ld a, a
    cp b
    rst $10
    cp [hl]
    reti


    ret


    add $7f
    push bc
    ld l, $b6
    ld c, [hl]
    cp l
    or d
    pop bc
    pop hl
    or e
    ld a, a
    cp [hl]
    or d
    or [hl]
    jp nz, Jump_010_7f26

    cp l
    or a
    add sp, $50
    call nc, $c4c1
    ret nc

    rst $08
    call z, Call_010_50c5
    dec c
    inc e
    ld [bc], a
    db $ed
    ld hl, $644e
    inc sp
    ld a, a
    add a
    xor b
    db $e3
    and [hl]
    call nc, $194e
    adc a
    sbc e
    and l
    add c
    ld h, $7f
    inc sp
    or a
    reti


    add sp, -$7c
    ret c

    xor e
    ld b, c
    xor h
    add a
    ret


    ld c, [hl]
    cp [hl]
    sbc $bc
    pop hl
    db $d3
    ld a, a
    or [hl]
    push bc
    call c, $b2c5
    adc $34
    ld a, a
    jp z, $b2d4

    add sp, $50

jr_010_5a83:
    ret


    adc $d3
    push bc
    jp Jump_010_50d4


    inc bc
    jr nz, jr_010_5a8d

jr_010_5a8d:
    db $ed
    ld hl, $64c8
    add $7f
    or l
    or l
    cp b
    ld a, a
    cp [hl]
    or d
    cp a
    cp b
    add sp, $4e
    or c
    ret nz

    rst $08
    ret


    ld a, a
    cp e
    or a
    add $7f
    ei
    adc l
    xor e
    sub b
    jr z, jr_010_5a83

    or d
    ret


    ld c, [hl]

jr_010_5aaf:
    pop bc
    or d
    cp e
    cp b
    ld a, a
    cp l
    reti


    inc [hl]
    or d
    ld a, a
    inc [hl]
    cp b
    ld a, [hl-]
    ret c

    db $dd
    db $d3
    jp nz, Jump_010_50e8

    jp $c3cf


    rst $08
    rst $08
    adc $50
    ld b, $64
    nop
    db $ed
    ld hl, $6530
    jr nc, jr_010_5aaf

    ld a, a
    jp nz, $d9b8

    ret nz

    jp nc, $4ec9

    or d
    pop bc
    inc l
    jp $c5b7


    ld a, a
    inc l
    ld [c], a
    or e
    ret nz

    or d
    add sp, $4e
    inc l
    inc a
    sbc $33
    jp z, $ce7f

    call nz, $34de
    ld a, a
    or e
    ld a, [hl+]
    cp c
    push bc
    or d
    add sp, $50
    rst $10
    pop bc
    db $d3
    ret nc

    ld d, b
    ld a, [bc]
    daa
    ld bc, $21ed
    ld h, a
    ld h, l
    sbc $33
    ld a, a
    or c
    rst $10
    call c, $d9da
    cp d
    call nz, $b1d3
    reti


    add sp, $4e
    db $d3
    or e
    adc h
    ld b, c
    db $e3
    inc de
    inc sp
    ld a, a
    call nz, $cf3b
    call c, Call_010_4ed8
    or l
    cp h
    ret c

    ret


    ld a, a
    inc [hl]
    cp b
    ld a, [hl-]
    ret c

    inc sp
    ld a, a
    cp e
    cp h
    rst $08
    cp b
    reti


    add sp, $50
    jp nz, $d2c9

    call nz, $1250
    ld d, h
    inc bc
    db $ed
    ld hl, $65f3
    add $7f
    ret nc

    jp nz, $d7b6

    push bc
    or d
    ld a, a
    pop bc
    sbc $bc
    pop hl
    add sp, $4e
    ld sp, hl
    jp nz, Jump_010_7fc9

    or c
    ret nz

    rst $08
    jp z, $d67f

    db $db
    cp d
    dec sp
    ld a, a
    or [hl]
    push bc
    cp h
    ret nc

    ld c, [hl]
    or d
    or [hl]
    ret c

    ret


    ld a, a
    or [hl]
    sbc $2c
    ld [c], a
    or e
    db $dd
    ld a, a
    or c
    rst $10
    call c, $e8bd
    ld d, b
    ld d, b
    ld a, [bc]
    ld b, b
    ld bc, $21ed
    ld h, c
    ld h, [hl]
    or d
    jp nz, $7fd3

    db $d3
    or e
    jp c, $c6c2

    ld a, a
    or l
    cp d
    rst $18
    jp $d8b5


    ld c, [hl]
    add $29
    jp $7fd3


    add $29
    jp Jump_010_4ed3


    inc [hl]
    cp d
    rst $08
    inc sp
    db $d3
    ld a, a
    or l
    or d
    or [hl]

jr_010_5ba1:
    cp c
    jp $d9b8


    add sp, $50
    call $cccf
    push bc
    ld d, b
    rlca
    ld c, l
    ld bc, $21ed
    and c
    ld h, [hl]
    ld a, a
    adc $d8
    cp l
    cp l
    sbc $33
    ld c, [hl]
    or c
    or d
    jp Jump_010_7f26


    push de
    jr nc, jr_010_5ba1

    cp h
    jp $d9b2


    call nz, $dbba
    db $dd
    ld c, [hl]
    dec a
    jp nz, Jump_010_7fc9

    ld a, [hl-]
    cp h
    ld [c], a
    or [hl]
    rst $10
    ld a, a
    cp d
    or e
    add hl, hl
    or a
    cp l
    reti


    add sp, $50
    call $d4cf
    ret z

    ld d, b
    rrca
    ld a, l
    nop
    db $ed
    ld hl, $66ea
    sbc $46
    sbc $26
    ld a, a
    jp nz, $c3b2

    or d
    jp $9a4e


    and l
    sbc d
    and l
    call nz, $ca7f
    ld a, [hl-]
    ret nz

    cp b
    ret nz

    dec sp
    add $4e
    db $d3
    or e
    inc [hl]
    cp b
    ret


    ld a, a
    cp d
    push bc
    db $dd
    ld a, a
    ld a, [hl-]
    rst $10
    rst $08
    cp b
    add sp, $50
    ret nc

    rst $08
    call z, $d2c1
    ld a, a
    jp nz, $c1c5

    jp nc, $1150

    or b
    inc b
    db $ed
    ld hl, $6744
    ld a, a
    cp c
    inc sp
    ld c, [hl]
    or l
    or l
    call c, $c3da
    or d
    reti


    add sp, -$45
    pop de
    cp e
    add $7f
    jp nz, $b8d6

    ld c, [hl]
    pop de
    cp h
    db $db
    ld a, a
    cp e
    pop de
    or d
    adc $34
    ld a, a
    add hl, hl
    sbc $b7

jr_010_5c47:
    add $c5
    reti


    add sp, $50
    rst $10
    rst $08
    jp nc, $50cd

    inc bc
    dec e
    nop
    db $ed
    ld hl, $67cb
    ld a, a
    set 1, h
    add $7f
    or l
    or l
    call c, $c3da
    or d
    reti


    add sp, $4e
    jr nc, jr_010_5c47

    ld b, l
    cp h
    jp $be7f


    or d
    pop bc
    ld [c], a
    or e
    cp l
    reti


    call nz, $b24e
    call nz, $7fdd
    or [hl]
    cp c
    jp $8a7f


    sub h
    ld b, $c6
    ld a, a
    or [hl]
    call c, $e8d9
    ld d, b
    jp $c3cf


    rst $08
    rst $08
    adc $50
    rlca
    ld h, e
    nop
    db $ed
    ld hl, $6846
    ld a, a
    jp nz, $cfc2

    jp c, $b2c3

    reti


    ld h, $4e
    push bc
    or [hl]
    ret nc

    jp z, $d47f

    call c, $b6d7
    or d
    ret


    inc sp
    ld c, [hl]
    jp nz, $b2d6

    ld a, a
    cp d
    or e
    add hl, hl
    or a
    add $ca
    ld a, a
    ret nz

    or h
    rst $10
    jp c, $b2c5

    add sp, $50
    jp nz, $d4d5

    call nc, $d2c5
    add $cc
    reti


    ld d, b
    dec bc
    ld b, b
    ld bc, $21ed
    and a
    ld l, b
    jp z, $b82c

    ld a, a
    ret c

    sbc $46
    sbc $c6
    ld c, [hl]
    rst $08
    db $d3
    rst $10
    jp c, $b2c3

    reti


    add sp, -$4f
    jp nc, Jump_010_7fc9

    swap e
    db $d3
    ld c, [hl]
    cp a
    rst $10
    db $dd
    ld a, a
    call nz, $ba3c
    call nz, Call_010_7f26
    inc sp
    or a
    reti


    add sp, $50
    add $cf
    jp nc, $c5c3

    ld d, b
    db $10
    inc d
    dec b
    db $ed
    ld hl, $690b
    ret nz

    ld a, a
    ld a, [$dece]
    ret


    ld a, a
    or e
    inc sp
    jp z, $f84e

    dec sp
    ld [c], a
    or e
    or [hl]
    sbc $c6
    ld a, a
    rst $30
    or $f6
    or $44
    jp nz, $4ec9

    ld b, b
    xor e
    sub b
    db $dd
    ld a, a
    cp b
    ret c

    jr nc, @-$41

    cp d
    call nz, $3326
    or a
    reti


    add sp, $50
    call nz, $c3d5
    bit 2, b
    ld de, $02fe
    db $ed
    ld hl, $694b
    ld a, a
    ret nc

    dec l
    or [hl]
    or a
    add $7f
    push bc
    rst $18
    jp $c3b2


    ld c, [hl]
    or l
    sub $28
    ret


    ld h, $7f
    call nz, $b2b8
    add sp, -$30
    dec l
    or e
    ret nc

    push bc
    inc [hl]
    inc sp
    ld c, [hl]
    push de
    or e
    ld h, $c5
    ld a, a
    cp l
    ld h, $c0
    ld h, $7f
    ret nc

    or [hl]
    cp c
    rst $10
    jp c, $e8d9

    ld d, b
    ret z

    reti


    ret nc

    adc $cf
    db $d3
    ret


    db $d3
    ld d, b
    db $10
    db $f4
    ld [bc], a
    db $ed
    ld hl, $6999
    ret


    db $dd
    ld a, a
    db $d3
    pop bc
    or c
    reti


    cp b
    add sp, $4e
    cp d
    inc [hl]
    db $d3
    add $7f
    cp e
    or d
    ret nc

    sbc $2c
    pop hl
    jp nz, $7fdd

    or [hl]
    cp c
    jp Jump_000_344e


    cp d
    or [hl]
    call $c27f
    jp c, $d9bb

    inc l
    cp c
    sbc $26
    ld a, a
    or c
    rst $18
    ret nz

    add sp, $50
    jp nz, $d4c1

    ld d, b
    db $10
    ld h, $02
    db $ed
    ld hl, $6a25
    or d
    add [hl]
    add hl, de
    inc sp
    ld a, a
    or [hl]
    ret nc

    jp nz, $c3b2

    ld c, [hl]
    or d
    pop bc
    inc [hl]
    add $7f
    ld sp, hl
    or $f6
    adc e
    db $e3
    adc e
    db $e3
    ret


    ld c, [hl]
    pop bc
    db $dd
    ld a, a
    cp l
    or d
    call nz, $c3df
    cp h
    rst $08
    or e
    add sp, $50
    rst $00
    push bc
    adc $c5
    ld d, b
    inc d
    call nz, $ed04
    ld hl, $6a78
    or e
    ret


    ld a, a
    ret nz

    jp nc, Jump_010_7fc6

    or d
    inc sp
    sbc $bc
    db $dd
    ld c, [hl]
    inc [hl]
    sbc $34
    sbc $7f
    cp b
    ret nc

    or [hl]
    or h
    jp $dfb2


    ret nz

    ld a, a
    cp c
    rst $18
    or [hl]
    ld c, [hl]
    or a
    ld [c], a
    or e
    ld a, $b3
    push bc
    ld a, a
    ld b, e
    adc b
    and c
    xor e
    add $7f
    push bc
    rst $18
    ret nz

    add sp, $50
    db $d3
    call z, $c5c5
    ret nc

    reti


    ld d, b
    dec d
    ld hl, sp+$11
    db $ed
    ld hl, $6aee
    dec a
    db $d3
    ret


    db $dd
    ld a, a
    ld a, [$f6f6]
    add [hl]
    xor b
    ld c, [hl]
    ret nz

    dec a
    push bc
    or d
    call nz, $b77f
    ld h, $7f
    cp l
    rst $08
    push bc
    or d
    add sp, $4e
    ret nz

    dec a
    or l
    call c, $c4d9
    ld a, a
    ret z

    pop de
    rst $18
    jp $cfbc


    or e
    add sp, $50
    add $c9
    db $d3
    ret z

    ld d, b
    add hl, bc
    ld h, h
    nop
    db $ed
    ld hl, $6b5f
    adc h
    ld b, c
    db $e3
    inc de
    db $d3
    ld a, a
    adc $c4
    sbc $34
    rrca
    and b
    add sp, $4e
    cp [hl]
    or [hl]
    or d

jr_010_5e71:
    inc sp

jr_010_5e72:
    ld a, a
    or d
    pop bc
    ld a, [hl-]
    sbc $7f
    sub $dc
    cp b
    jp $c54e


    cp e
    cp c
    push bc
    or d
    ld a, a
    ld b, e
    adc b
    and c
    xor e
    jr nc, jr_010_5e71

    ld d, b
    db $d3
    call nc, $c3c9
    set 3, c
    call nz, $d2c9
    call nc, Call_000_0c50
    inc l
    ld bc, $21ed
    add $6b
    dec hl
    rst $18
    jp $c3b2


    ld c, [hl]
    call c, $d7b6
    push bc
    or d
    add sp, -$4a
    rst $10
    jr nc, jr_010_5e72

    ld a, a
    cp e
    call c, $c4d9
    ld c, [hl]
    db $d3
    or e
    inc [hl]
    cp b
    add $7f
    or l
    or [hl]
    cp e
    jp c, $e8d9

    ld d, b
    jp $c9cc


    ret nc

    ret nc

    push bc
    jp nc, $50d3

    dec c
    ld e, b
    ld [bc], a
    db $ed
    ld hl, $6c1f
    rst $30
    rst $08
    sbc $3a
    ret c

    or a
    ret


    ld c, [hl]
    ld b, b
    xor c
    db $e3
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $d9b2


    ld h, $4e
    or l
    or l
    or a
    cp l
    daa
    jp $b37f


    ld a, [hl+]
    or a
    ld h, $7f

jr_010_5eef:
    add $3c
    or d
    add sp, $50
    ld d, b
    rrca
    dec l
    dec b
    db $ed
    ld hl, $6c96
    dec b
    add l
    and l
    ld h, $7f
    sra h
    ld [c], a
    or e
    add $7f
    or [hl]
    ret nz

    cp b
    ld c, [hl]
    sub h
    ld b, b
    db $e3
    sbc a
    jr nc, jr_010_5eef

    inc sp
    db $d3
    ld a, a
    cp d
    call c, $c5be
    or d
    add sp, $4e
    cp d
    or e

jr_010_5f1d:
    add hl, hl
    or a
    cp l
    reti


    call nz, $30b7
    cp c
    ld a, a
    set 2, a
    cp b
    add sp, $50
    jp nz, $ccc1

    call z, Call_000_0c50
    sbc d
    ld [bc], a
    db $ed
    ld hl, $6d04
    cp h
    add hl, hl
    or a
    add $7f
    jp z, $c9de

    or e
    cp h
    jp $3a4e


    cp b
    jp z, $bdc2

    reti


    add sp, $19
    add a
    rrca
    xor e
    inc e
    db $e3
    and [hl]
    call nz, $b3b2
    ld c, [hl]
    or c
    jr nc, jr_010_5f1d

    inc sp
    ld a, a
    cp d
    call c, $d726
    jp c, Jump_010_7fc3

    or d
    reti


    add sp, $50
    call nz, $cdc5
    rst $08
    adc $50
    dec c
    sub b
    ld bc, $21ed
    ld [hl], e
    ld l, l
    cp b
    jp $f77f


    add [hl]
    xor b
    ld a, a
    jp z, $dac5

    ret nz

    ld c, [hl]
    call nz, $dbba
    inc sp
    ld a, a
    or l
    call nz, $c0bc
    ld a, a
    jp z, $c9d8

    or l
    call nz, $4edd
    ret nc

    ld a, [hl+]
    call nz, Call_010_7fc6
    or a
    or a
    call c, $d7b9
    jp c, $e8d9

    ld d, b
    rst $00
    pop bc
    db $d3
    ld d, b
    inc c
    ld e, a
    nop
    db $ed
    ld hl, $6dd1
    jp c, Jump_010_7fc6

    call nz, $2ec2
    sbc $cd
    sbc $b2
    inc sp
    ld c, [hl]
    call z, Call_000_2ac0
    ret


    ld a, a
    pop bc
    or d
    cp e
    or d
    ld a, a
    inc de
    dec b
    db $e3
    adc h
    ld h, $4e
    jp c, $b9de

    jp nz, $c0bc

    rst $08
    rst $08
    ld a, a
    inc sp
    reti


    cp d
    call nz, $b126
    reti


    add sp, $50
    jp $d4c1


    ld d, b
    ld a, [bc]
    ld b, b
    ld bc, $21ed
    dec h
    ld l, [hl]
    ld [c], a
    or e
    ld h, $7f
    jp z, $bc29

    cp b
    ld a, a
    cp h
    rst $18
    ld c, b
    db $dd
    ld c, [hl]
    rst $08
    rst $18
    cp l
    jr z, jr_010_6073

    ret nz

    jp $d7c0


    ld a, a
    sub $b3
    ld a, a
    pop bc
    pop hl
    or e
    or d
    add sp, $4e
    call nz, $b63b
    or [hl]
    rst $18
    jp $b67f


    ret nc

    jp nz, $7fb8

    rst $08
    or h
    inc a
    jp c, $e830

    ld d, b
    jp nz, $cecf

    push bc
    call z, $cbc9
    ret


    adc $c7
    ld d, b
    ld a, [bc]
    jp nz, $ed01

    ld hl, $6e6e
    db $d3
    call nz, $c4d3
    ld a, a
    ld c, [hl]
    sub $dc
    or [hl]
    rst $18
    ret nz

    add sp, -$64
    sub a
    db $dd
    ld a, a
    jp nz, $b3b6

    sub $b3
    add $c5
    ret c

    ld c, [hl]
    cp [hl]
    or d
    or [hl]
    cp b
    ld h, $7f
    or a
    ld [c], a
    or e
    ld a, $b3
    or [hl]
    ld a, a
    cp h
    ret nz

    add sp, $50
    rst $00
    pop bc
    db $d3
    db $d3
    call nc, $d4c1
    ret


    rst $08
    adc $50
    db $10
    ld bc, $ed00
    ld hl, $6eb7
    or d
    push bc
    or d
    ret


    add $4e
    ret nc

    rst $10
    jp c, $b2c3

    reti


    sub $b3
    push bc
    ld a, a

jr_010_6073:
    or a
    ld h, $bc
    ret nz

    rst $10
    ld c, [hl]
    cp a
    cp d
    add $7f
    add hl, bc
    db $e3
    adc h
    sub e
    ld h, $7f
    or d
    reti


    ret


    jr nc, @-$16

    ld d, b
    rst $10
    ret


    call z, $d0cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_000_0950

    jp $ed00


    ld hl, $6f0b
    jp z, $c87f

    jp $d9b2


    add sp, $4e
    ret z

    pop de
    rst $18
    jp $7fd9


    or c
    or d
    jr nc, jr_010_60df

    db $d3
    ld a, a
    cp e
    rst $08
    dec hl
    rst $08
    push bc
    ld c, [hl]
    pop bc
    ld [c], a
    or e
    ret


    or e
    ret c

    ld [c], a
    cp b
    db $dd
    ld a, a
    jp nz, $b3b6

    add sp, $50
    rst $10
    ret


    call z, $d0cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_000_0f50

    ldh [rSB], a
    db $ed
    ld hl, $6f60
    ret c

    ld a, a
    cp d
    ret


    rst $08
    dec l
    ld c, [hl]
    pop bc
    ld [c], a
    or e
    ret


jr_010_60df:
    or e
    ret c

    ld [c], a
    cp b
    db $dd
    ld a, a
    inc l
    dec hl
    or d
    add $4e
    or c
    call nc, $dfc2
    jp $b17f


    or d
    jp $7fdd


    ret nz

    or l
    cp l
    add sp, $50
    jp nz, $d2c9

    call nz, Call_000_0b50
    inc l
    ld bc, $21ed
    or a
    ld l, a
    ld h, $7f
    jp z, $c0df

    jp nz, $c3bc

    or d
    reti


    add sp, $4e
    add e
    adc d
    ret


    ld a, a
    adc a
    sbc l
    adc a
    sbc l
    db $dd
    ld a, a
    jp nz, $deb6

    inc sp
    ld c, [hl]
    rst $30
    or $f6
    add [hl]
    xor b
    cp e
    or a
    ret


    ld a, a
    cp l
    ld a, a
    rst $08
    inc sp
    ld a, a
    jp z, $3cba

    add sp, $50
    jp nz, $d2c9

    call nz, Call_000_0f50
    adc e
    ld bc, $21ed
    dec c
    ld [hl], b
    sbc c
    sub a
    db $dd
    ld a, a
    set 3, e
    add hl, hl
    jp $b14e


    or d
    jp $7fdd


    or d
    or [hl]
    cp b
    cp l
    reti


    add sp, $4e
    sbc l
    xor h
    sbc c
    ld hl, sp+$33
    ld a, a
    cp a
    rst $10
    db $dd
    ld a, a
    call nz, $cf3b
    call c, $e8d9
    ld d, b
    jp nc, $c4c9

    call nz, $c5cc
    ld d, b
    dec bc
    jr nz, @+$05

    db $ed
    ld hl, $705f
    ld a, a
    inc e
    ld [de], a
    or b
    db $e3
    or [hl]
    rst $10
    ld c, [hl]
    or e
    pop bc
    pop hl
    or e
    cp [hl]
    or d
    inc a
    jp nz, $337f

    jp z, $b2c5

    or [hl]
    call nz, Call_000_2c4e
    db $d3
    call nz, $ca33
    ld a, a
    or e
    ret nz

    ld h, $dc
    jp c, $b2c3

    reti


    add sp, $50
    db $d3
    push bc
    push bc
    call nz, $0750
    ld b, l
    nop
    db $ed
    ld hl, $70c3
    or [hl]
    rst $10
    ld a, a
    cp [hl]
    push bc
    or [hl]
    add $4e
    cp h
    ld [c], a
    cp b
    inc a
    jp nz, Jump_010_7fc9

    adc a
    sub a
    ld h, $7f
    or c
    rst $18
    jp $bd4e


    cp d
    cp h
    ld [hl-], a
    jp nz, $b57f

    or l
    or a
    cp b
    ld a, a
    cp a
    jr nc, @-$3c

jr_010_61cd:
    add sp, $50
    jp nc, $ccc5

    pop bc
    ret c

    push bc
    call nz, Call_010_50e4
    jr @+$05

    db $ed
    ld hl, $713a
    cp l
    reti


    ld a, a
    or [hl]
    or l
    ret c

    ld h, $4e
    ret nz

    jr nc, @-$28

    or d
    ld a, a
    ret nz

    ret nz

    or [hl]
    or e
    db $d3
    ret


    ret


    ld c, [hl]
    or a
    db $d3
    pop bc
    db $dd
    ld a, a
    push bc
    jr nc, jr_010_61cd

    jp $cfbc


    or e
    add sp, $50
    jp z, $ccc5

    call z, $c6d9
    ret


    db $d3
    ret z

    ld d, b
    db $10
    ld h, $02
    db $ed
    ld hl, $718f
    cp h
    pop hl
    ld h, $7f
    inc l
    push de
    or e
    add $4e
    or e
    ld a, [hl+]
    cp b
    add sp, -$45
    cp e
    jp c, $c4d9

    ld a, a
    inc [hl]
    cp b
    add $7f
    or l
    or [hl]
    cp e
    jp c, $bd4e

    reti


    inc [hl]
    or d
    ld a, a
    or d
    ret nz

    ret nc

    ld h, $7f
    jp z, $d9bc

    add sp, $50
    rst $10
    ret z

    pop bc
    call z, Call_010_50c5
    ld b, $96
    nop
    db $ed
    ld hl, $71f5
    push bc
    ld a, [de]
    and a
    ld h, $7f
    or a
    sbc $c6
    cp b
    ret


    sub $b3
    add $4e
    jp z, $c0df

    jp nz, $c3bc

    or l
    ret c

    ld a, a
    cp l
    or d
    pop bc
    pop hl
    or e
    db $dd
    ld c, [hl]
    ei
    sbc b
    xor h
    sub e
    ret


    ld a, a
    jp z, $bbd4

    inc sp
    ld a, a
    or l
    sub $28
    add sp, $50
    rst $10
    ret z

    pop bc
    call z, Call_010_50c5
    dec c
    add [hl]
    ld bc, $21ed
    ld l, [hl]
    ld [hl], d
    or e
    add $7f
    call nz, $df26
    jp $d9b2


    sub c
    sbc b
    inc sp
    ld c, [hl]
    or d
    call c, $30ca
    db $dd
    ld a, a
    cp b
    ret c

    rst $00
    or a
    ld c, [hl]
    inc l
    inc a
    sbc $c9
    ld a, a
    cp l
    db $dd
    ld a, a
    jp nz, $dfb8

    jp $d9b2


    add sp, $50
    call $cdc1
    call $d4cf
    ret z

    ld d, b
    ld a, [bc]
    inc l
    ld bc, $21ed
    db $db
    ld [hl], d
    cp b
    ld a, a
    or c
    cp h
    ret


    ld a, a
    pop bc
    or [hl]
    rst $10
    ld h, $4e
    db $d3
    ret


    cp l
    ld a, [hl+]
    or d
    add sp, -$09
    or [hl]
    or d
    ret


    ld a, a
    dec bc
    xor l
    xor e
    ld b, d
    inc sp
    ld c, [hl]
    call nz, $b7b3
    ld [c], a
    or e
    adc a
    xor c
    db $e3
    db $d3
    ld a, a
    call nz, $ba3b
    or h
    reti


    add sp, $50
    call $cdc1
    call $d4cf
    ret z

    ld d, b
    ld de, $03b6
    db $ed
    ld hl, $734b
    cp d
    or e
    ld a, a
    ld hl, sp-$06
    or $86
    xor b
    add sp, $4e
    and b
    and l
    and b
    and l
    ld a, a
    db $d3
    or h
    push bc
    ld h, $d7
    ld a, a
    cp h
    sbc $b6
    sbc $be
    sbc $c4
    ld c, [hl]
    or l
    push bc
    inc l
    ld a, a
    adc h
    ld b, c
    db $e3
    inc de
    inc sp
    ld a, a
    or [hl]
    cp c
    rst $00
    cp c
    reti


    add sp, $50
    call $d5cf
    db $d3
    push bc
    ld d, b
    inc bc
    inc hl
    nop
    db $ed
    ld hl, $73b2
    cp b
    jp $bd7f


    reti


    inc [hl]
    or d
    add sp, $4e
    or d
    rst $18
    cp h
    ld [c], a
    or e
    ld a, a
    ret


    dec sp
    jp nz, $b932

    reti


    ret


    inc sp
    ld c, [hl]
    or [hl]
    ret nz

    or d
    ld a, a
    and c
    sbc b
    db $dd
    ld a, a
    or [hl]
    inc l
    rst $18
    jp $b97f


    dec l
    reti


    add sp, $50
    call $d5cf
    db $d3
    push bc
    ld d, b
    rlca
    cp c
    nop
    db $ed
    ld hl, $7414
    ld a, a
    push de
    dec sp
    jp z, $f97f

    ld a, $de
    inc sp
    ld c, [hl]
    pop bc
    or d
    cp e
    push bc
    ld a, a
    ret nc

    dec l
    or [hl]
    or a
    ld h, $7f
    jp nz, $c3b2

    or d
    reti


    add sp, $4e
    or [hl]
    call c, $7fdd
    or l
    sub $b2
    inc sp
    ld a, a
    call c, $d9c0
    add sp, $50
    adc $c5
    push bc
    call nz, $c5cc
    ld d, b
    add hl, bc
    jp $ed00


    ld hl, $743b
    ld a, a
    cp [hl]
    or d
    or [hl]
    cp b
    add sp, $4e
    jp z, $c0df

    jp nz, $c0bc

    ld a, a
    sub c
    sbc b
    db $dd
    ld a, a
    call z, $cfd8
    call c, $c3bc
    ld c, [hl]
    rrca
    add c
    and d
    and c
    xor e
    inc de
    db $d3
    ld a, a
    cp b
    cp h
    dec hl
    cp h
    add $7f
    cp l
    reti


    add sp, $50
    adc $c5
    push bc
    call nz, $c5cc
    ld d, b
    ld [$00c8], sp
    db $ed
    ld hl, $749c
    cp [hl]
    or d
    or [hl]
    cp b
    jp z, $b57f

    sbc $ba
    or e
    add sp, $4e
    cp b
    pop bc
    or [hl]
    rst $10
    ld a, a
    jr nc, @-$41

    ld a, a
    pop bc
    ld [c], a
    or e
    or l
    sbc $44
    jp z, $b14e

    or d
    jp $7fdd


    rst $08
    inc [hl]
    call c, Call_010_7fbd
    pop bc
    or [hl]
    rst $10
    ld h, $b1
    reti


    add sp, $50
    jp nc, $c3cf

    bit 2, b
    inc b
    ret z

    nop
    db $ed
    ld hl, $751b
    ld a, a
    db $d3
    pop bc
    call nc, $b2bd
    ret


    inc sp
    ld a, a
    jp nz, $deb6

    inc sp
    ld c, [hl]
    or c
    or d
    jp Jump_010_7fc6


    push bc
    add hl, hl
    jp Jump_000_3c7f


    jp nz, $d9b9

    ld c, [hl]
    add c
    adc e
    sub c
    dec de
    sub d
    ld a, a
    ld h, $df
    cp [hl]
    sbc $26
    ld a, a
    inc sp
    or a
    reti


    add sp, $50
    cp b
    ret


    jp c, $c5c5

    ld d, b
    ld [$016d], sp
    db $ed
    ld hl, $7575
    ld a, a
    or [hl]
    ld h, $b8
    ret c

    ld [c], a
    cp b
    db $dd
    ld a, a
    jp nz, $b2b6

    ld c, [hl]
    jp nz, $c6b2

    ld a, a
    inc l
    sbc $ba
    or e
    ret


    ld a, a
    ld b, e
    adc b
    and c
    xor e
    db $dd
    ld c, [hl]
    jp nz, $d9b8

    cp d
    call nz, Call_010_7fc6
    cp [hl]
    or d
    cp d
    or e
    cp h
    ret nz

    add sp, $50
    add $cf
    db $d3
    db $d3
    ret


    call z, $1250
    ld [bc], a
    db $ed
    ld hl, $75b6
    cp d
    cp e
    jp c, Jump_010_7fc0

    or a
    ld [c], a
    or e
    ret c

    pop hl
    or e
    ret


    ld c, [hl]
    or d
    inc sp
    sbc $bc
    or [hl]
    rst $10
    ld a, a
    call z, $b6df
    jp nz, $bebb

    ret nz

    add sp, $4e
    ret nz

    or [hl]
    or d
    cp d
    or h
    inc sp
    ld a, a
    push bc
    or a
    push bc
    ld h, $d7
    ld a, a
    call nz, $e83c
    ld d, b
    call $c7c1
    adc $c5
    call nc, Call_000_0350
    inc a
    nop
    db $ed
    ld hl, $761d
    ld a, a
    or e
    or d
    ret nz

    rst $08
    rst $08
    ld a, a
    or d
    inc [hl]
    or e
    cp h
    jp $bb4e


    push de
    or e
    ret


    ld a, a
    and e
    sub l
    xor h
    sub e
    or [hl]
    rst $10
    ld c, [hl]
    inc sp
    sbc $2c
    jp z, $34c5

    db $dd
    ld a, a
    adc $b3
    cp h
    ldh [$bd], a
    reti


    add sp, $50
    call z, $dac9
    pop bc
    jp nc, Jump_010_50c4

    ld b, $55
    nop
    db $ed
    ld hl, $7690
    rst $10
    ld a, a
    cp h
    rst $18
    ld c, b
    add $7f
    adc $c9
    or l
    ld h, $4e
    call nz, $dfd3
    jp $d9b2


    add sp, -$32
    ret


    or l
    ld h, $7f
    or a
    or h
    ret nz

    call nz, $4eb7
    cp a
    ret


    ld a, a
    or d
    ret


    pop bc
    jp z, $b57f

    call c, $c3df
    ld a, a
    cp h
    rst $08
    or e
    add sp, $50
    db $d3
    ret z

    push bc
    call z, $50cc
    dec b
    ld e, d
    nop
    db $ed
    ld hl, $76f6
    dec sp
    db $dd
    ld a, a
    cp d
    or e
    rst $10
    ret


    push bc
    or [hl]
    add $4e
    set 3, a
    cp d
    jp nc, $c4d9

    or a
    ld a, a
    or d
    or a
    or l
    or d
    sub $b8
    ld c, [hl]
    ret nc

    dec l
    inc sp
    rst $18
    ld c, b
    or e
    db $dd
    ld a, a
    jp z, $bcdf

    ldh [$bd], a
    reti


    add sp, $50
    db $d3
    call $cbcf
    push bc
    ld d, b
    dec bc
    cp [hl]
    nop
    db $ed
    ld hl, $7741
    ret c

    rst $08
    call c, $c3bc
    ld a, a
    or c
    or d
    jp $4edd


    push bc
    daa
    ret nz

    or l
    cp h
    ld a, a
    cp l
    reti


    inc [hl]
    or d
    ld a, a
    sub c
    and b
    inc sp
    ld c, [hl]
    inc c
    adc a
    inc c
    adc a
    add $7f
    res 6, a
    cp e
    or d
    jp $cfbc


    or e
    add sp, $50
    call nc, $d2cf
    call nc, $c9cf
    db $d3
    push bc
    ld d, b
    ld a, [bc]
    pop hl
    nop
    db $ed
    ld hl, $779f
    ld h, $7f
    ret nz

    or [hl]
    or d
    add sp, $4e
    rst $08
    ret nz

    ld a, a
    cp c
    inc sp
    ld a, a

jr_010_65b6:
    or l
    or l
    call c, $c0da
    ld a, a
    cp h
    rst $18
    ld c, b
    jp z, $c54e

    ld h, $b2
    or a
    cp l
    reti


    ld a, a
    adc e
    xor e
    inc e
    and [hl]
    jr nc, jr_010_65b6

    ld d, b
    db $d3
    call $cbcf
    push bc
    ld d, b
    ld de, $0389
    db $ed
    ld hl, $77f2
    ld a, [$f6f6]
    and b
    db $e3
    sub e
    and [hl]
    ld a, a
    rst $08
    inc sp
    ld c, [hl]
    sbc c
    sub a
    db $dd
    ld a, a
    jp nz, $dfb6

    jp $c47f


    inc a
    cp d
    call nz, $3326
    or a
    reti


    add sp, $4e
    cp d
    or e
    ret z

    jp nz, Jump_010_7fc9

    adc $c9
    or l
    db $dd
    ld a, a
    jp z, $e8b8

    ld d, b
    rst $00
    jp nc, $d3c1

    db $d3
    ld d, b
    dec b
    ld [hl], $00
    db $ed
    ld hl, $7845
    add b
    and [hl]
    add [hl]
    and b
    xor e
    ld [de], a
    adc h
    add sp, $4e
    sub $d9
    add $7f
    push bc
    reti


    call nz, $f87f
    adc $de
    ret


    ld a, a
    ret z

    rst $18
    cp d
    inc sp
    ld c, [hl]
    ld sp, hl
    or $f6
    and b
    db $e3
    sub e
    and [hl]
    db $d3
    ld a, a
    or c
    reti


    cp b
    call nz, $b3b2
    add sp, $50
    rst $00
    jp nc, $d3c1

    db $d3
    ld d, b
    ld [$0056], sp
    db $ed
    ld hl, $788d
    jp z, $c2c5

    ld a, a
    call nz, $c2c3
    db $d3
    push bc
    cp b
    ld c, [hl]
    cp b
    cp e
    or d
    ld a, a
    add $b5
    or d
    jp z, $f87f

    add [hl]
    xor b
    cp e
    or a
    rst $08
    inc sp
    ld c, [hl]
    call nz, $b734
    ld a, a
    or a
    db $dd
    ld a, a
    or e
    cp h
    push bc
    call c, $d9be
    add sp, $50
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_000_0c50

    cp d
    nop
    db $ed
    ld hl, $78d7
    or l
    or l
    or a
    or d
    ld a, a
    jp z, $3bc5

    rst $10
    or [hl]
    rst $10
    ld c, [hl]
    add b
    and a
    and [hl]
    ld b, $e3
    db $dd
    ld a, a
    or l
    cp d
    cp l
    ld a, a
    or [hl]
    call z, $ddde
    ld c, [hl]
    add h
    sub l
    ret


    ld a, a
    sub $b3
    add $7f
    ld a, [hl-]
    rst $10
    rst $08
    cp b
    add sp, $50
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, $0750

    jr z, jr_010_66bc

jr_010_66bc:
    db $ed
    ld hl, $794b
    ret


    sub $b3
    push bc
    ld a, a
    sub c
    inc e
    sbc [hl]
    or [hl]
    rst $10
    ld c, [hl]
    inc sp
    sbc $be
    jp nz, Jump_010_7fc9

    sbc l
    xor e
    inc de
    and l
    add hl, bc
    and l
    ret


    ld a, a
    or d
    rst $18
    cp h
    pop hl
    ld c, [hl]
    inc sp
    jp z, $b2c5

    or [hl]
    call nz, $bb7f
    cp e
    call nc, $dab6
    jp $d9b2


    add sp, $50
    ret


    adc $d3
    push bc
    jp Jump_010_50d4


    ld a, [bc]
    ld b, b
    nop
    db $ed
    ld hl, $7978
    inc a
    sbc $ca
    ld a, a
    add l
    xor h
    adc a
    db $e3
    add $c5
    rst $18
    jp $b14e


    or d
    jp $7fdd


    or a
    ret c

    cp e
    cp b
    add sp, -$48
    pop bc
    or [hl]
    rst $10
    jp z, $c54e

    sbc $33
    db $d3
    ld a, a
    call nz, $bdb6
    ld a, a
    or h
    or a
    ret nz

    or d
    db $dd
    ld a, a
    jp z, $e8b8

    ld d, b
    ret


    adc $d3
    push bc
    jp Jump_010_50d4


    ld de, $009b
    db $ed
    ld hl, $79ec
    push bc
    ld a, a
    or [hl]
    or l
    ret c

    inc sp
    ld a, a
    cp b
    pop bc
    ret


    ld c, [hl]
    push bc
    or [hl]
    add $7f
    cp e
    cp a
    or d
    cp d
    rst $08
    jp c, $d7c0

    ld a, a
    cp e
    or d
    ld a, [hl+]
    add sp, $4e
    sub $b3
    or [hl]
    or d
    or h
    or a
    inc sp
    ld a, a
    call nz, $bbb6
    jp c, $bcc3

    rst $08
    or e
    add sp, $50
    ld d, b
    ld a, [bc]
    ld h, h
    nop
    ld d, b

Call_010_676f:
    push bc
    push hl

jr_010_6771:
    ld a, [$d0e3]
    ld b, a
    ld c, $00
    ld hl, $679a

jr_010_677a:
    inc c
    ld a, [hl+]
    cp b
    jr nz, jr_010_677a

    ld a, c
    ld [$d0e3], a
    pop hl
    pop bc

jr_010_6785:
    ret


Call_010_6786:
    push bc
    push hl
    ld a, [$d0e3]
    dec a
    ld hl, $679a
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl]
    ld [$d0e3], a
    pop hl
    pop bc
    ret


    ld [hl], b
    ld [hl], e
    jr nz, jr_010_67c1

    dec d
    ld h, h
    ld [hl+], a
    ld d, b
    ld [bc], a
    ld h, a
    ld l, h
    ld h, [hl]
    ld e, b
    ld e, [hl]
    dec e
    rra
    ld l, b
    ld l, a
    add e
    dec sp
    sub a
    add d
    ld e, d
    ld c, b
    ld e, h
    ld a, e
    ld a, b
    add hl, bc
    ld a, a
    ld [hl], d
    nop
    nop
    ld a, [hl-]
    ld e, a
    ld d, $10
    ld c, a
    ld b, b
    ld c, e

jr_010_67c1:
    ld [hl], c
    ld b, e
    ld a, d
    ld l, d
    ld l, e
    jr jr_010_67f7

    ld [hl], $60
    ld c, h
    nop
    ld a, [hl]
    nop
    ld a, l
    ld d, d
    ld l, l
    nop
    jr c, jr_010_682a

    ld [hl-], a
    add b
    nop
    nop
    nop
    ld d, e
    jr nc, jr_010_6771

    nop
    nop
    nop
    ld d, h
    inc a
    ld a, h
    sub d
    sub b
    sub c
    add h
    inc [hl]
    ld h, d
    nop
    nop
    nop
    dec h
    ld h, $19
    ld a, [de]
    nop
    nop
    sub e
    sub h
    adc h
    adc l
    ld [hl], h
    ld [hl], l

jr_010_67f7:
    nop
    nop
    dec de
    inc e
    adc d
    adc e
    daa
    jr z, jr_010_6785

    adc b
    add a
    add [hl]
    ld b, d
    add hl, hl
    rla
    ld l, $3d
    ld a, $0d
    ld c, $0f
    nop
    ld d, l
    add hl, sp
    inc sp
    ld sp, $0057
    nop
    ld a, [bc]
    dec bc
    inc c
    ld b, h
    nop
    scf
    ld h, c
    ld a, [hl+]
    sub [hl]
    adc a
    add c
    nop
    nop
    ld e, c
    nop
    ld h, e
    ld e, e
    nop
    ld h, l
    inc h
    ld l, [hl]
    dec [hl]

jr_010_682a:
    ld l, c
    nop
    ld e, l
    ccf
    ld b, c
    ld de, $7912
    ld bc, $4903
    nop
    db $76
    ld [hl], a
    nop
    nop
    nop
    nop
    ld c, l
    ld c, [hl]
    inc de
    inc d
    ld hl, $4a1e
    adc c
    adc [hl]
    nop
    ld d, c
    nop
    nop
    inc b
    rlca
    dec b
    ld [$0006], sp
    nop
    nop
    nop
    dec hl
    inc l
    dec l
    ld b, l
    ld b, [hl]
    ld b, a
    ld a, [$cd3d]
    ld [$cd59], a
    ld a, [$cd3e]
    ld [$cd5a], a
    ld de, $68ae
    jr jr_010_6878

    ld a, [$cd3e]
    ld [$cd59], a
    ld a, [$cd3d]
    ld [$cd5a], a
    ld de, $68bf

jr_010_6878:
    ld a, [$d2d4]
    push af
    ldh a, [$af]
    push af
    ldh a, [$ae]
    push af
    xor a
    ld [$d2d4], a
    ldh [$af], a
    ldh [$ae], a
    push de
    pop de
    ld a, [de]
    cp $ff
    jr z, jr_010_68a3

    inc de
    push de
    ld hl, $68d5
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $688b
    push de
    jp hl


jr_010_68a3:
    pop af
    ldh [$ae], a
    pop af
    ldh [$af], a
    pop af
    ld [$d2d4], a
    ret


    nop
    ld bc, $0302
    dec b
    rlca
    ld [$0a09], sp
    dec bc
    ld b, $08
    ld [bc], a
    inc b
    rlca
    ld c, $ff
    nop
    ld [$0b0d], sp
    db $10
    dec b
    db $10
    ld [$0402], sp
    rrca
    ld bc, $0302
    db $10
    ld b, $10
    rlca
    ld [$0e09], sp
    rst $38
    rla
    ld l, c
    cp e
    ld l, c
    ld c, $6a
    ld c, b
    ld l, d
    xor h
    ld l, d
    db $ec
    ld l, d
    inc a
    ld l, e
    rst $30
    ld l, b
    ld a, $6d
    ld [hl], h
    ld l, l
    sbc e
    ld l, l
    db $d3
    ld l, l
    ld [$256e], sp
    ld l, [hl]
    or c
    ld l, c
    ld d, l
    ld l, l
    adc l
    ld l, c

Call_010_68f7:
    ld c, $64
    jp Jump_000_3781


Call_010_68fc:
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ret


Call_010_6907:
Jump_010_6907:
    ld c, $50
    jp Jump_000_3781


Call_010_690c:
    ld hl, $c3a0
    ld bc, $0168
    ld a, $7f
    jp Jump_000_372a


    call Call_010_690c
    call Call_000_0167
    ld hl, $6d51
    ld de, $9310
    ld bc, $0310
    ld a, $0e
    call Call_000_028c
    ld hl, $7061
    ld de, $87c0
    ld bc, $0040
    ld a, $0e
    call Call_000_028c
    ld hl, $9800
    ld bc, $0800
    ld a, $7f
    call Call_000_372a
    call Call_000_0188
    ld a, $ff
    ld [$cfb2], a
    ld hl, $d6af
    set 6, [hl]
    ld a, [$cf15]
    and a
    ld a, $e4
    jr z, jr_010_695b

    ld a, $f0

jr_010_695b:
    ldh [rOBP0], a
    call Call_000_0181
    xor a
    ldh [$ba], a
    ld a, [$cd3d]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $cd68
    ld de, $cf45
    ld bc, $0006
    call Call_000_01bb
    ld a, [$cd3e]
    ld [$d0e3], a
    jp Jump_000_1aab


Call_010_6981:
    ld a, $d0
    ldh [rOBP1], a
    ld b, $1c
    ld hl, $5c30
    jp Jump_000_3620


    ld hl, $d11d
    ld de, $cee4
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d806
    ld de, $d11d
    ld bc, $0006
    call Call_000_01bb
    ld hl, $cee4
    ld de, $d806
    ld bc, $0006
    jp Jump_000_01bb


    xor a
    call Call_000_0b3c
    ld hl, $d6af
    res 6, [hl]
    ret


    ld a, $ab
    ldh [rLCDC], a
    ld a, $50
    ldh [$b0], a
    ld a, $7e
    ldh [rWX], a
    ldh [$ae], a
    xor a
    ldh [$ba], a
    ld hl, $c3a5
    ld b, $06
    ld c, $09
    call Call_000_03d2
    call Call_010_7f68
    ld b, $98
    call Call_000_0386
    call Call_000_03bf
    ld a, [$cd3d]
    call Call_010_6d1a
    ld a, $7e

jr_010_69e9:
    push af
    call Call_000_0b31
    pop af
    ldh [rWX], a
    ldh [$ae], a
    dec a
    dec a
    and a
    jr nz, jr_010_69e9

    call Call_010_6907
    ld a, $ad
    call Call_010_6e5d
    ld a, $aa
    call Call_010_6e5d
    ld a, [$cd3d]
    call Call_000_2dc7
    xor a
    ldh [$ba], a
    ret


    call Call_010_690c
    ld b, $98
    call Call_000_0386
    ld b, $08
    call Call_000_3e1f
    ld hl, $9c8c
    call Call_010_6c24
    ld a, $a0
    ldh [$ae], a
    call Call_000_0b31
    ld a, $8b
    ldh [rLCDC], a
    ld hl, $c3ce
    ld b, $07
    call Call_010_702f
    call Call_010_68fc
    ld a, $8d
    call Call_000_0e45
    ld c, $14

jr_010_6a3e:
    ldh a, [$ae]
    add $04
    ldh [$ae], a
    dec c
    jr nz, jr_010_6a3e

    ret


    ld a, $ab
    call Call_010_6e5d
    ld c, $0a
    call Call_000_3781
    ld a, $e4
    ldh [rOBP0], a

Call_010_6a56:
    xor a
    ld [$d07c], a
    ld bc, $2060

jr_010_6a5d:
    push bc
    xor a
    ld de, $6aa4
    call Call_000_3ae1
    ld a, [$d07c]
    xor $01
    ld [$d07c], a
    add $7e
    ld hl, $c302
    ld de, $0004
    ld c, e

jr_010_6a76:
    ld [hl], a
    add hl, de
    dec c
    jr nz, jr_010_6a76

    call Call_000_3e07
    pop bc
    ld a, c
    add $04
    ld c, a
    cp $a0
    jr nc, jr_010_6a8e

    ld a, $8c
    call Call_000_0e45
    jr jr_010_6a5d

jr_010_6a8e:
    call Call_000_0188
    ld a, $01
    ldh [$ba], a
    call Call_000_03bf
    ld b, $98
    call Call_000_0386
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ret


    ld a, [hl]
    nop
    ld a, [hl]
    jr nz, @+$80

    ld b, b
    ld a, [hl]
    ld h, b
    ld a, $ac
    call Call_010_6e5d
    call Call_010_6d3e
    ld hl, $c46d
    ld b, $06
    ld c, $09
    call Call_000_03d2
    call Call_010_7fa6
    call Call_010_68fc
    ld a, $01
    ldh [$ba], a
    ld a, [$cd3e]
    call Call_010_6d1a
    ld a, $ad
    call Call_010_6e5d
    ld a, $01
    ldh [$ba], a
    ld a, [$cd3e]
    call Call_000_2dc7
    call Call_010_68f7
    ld hl, $c46d
    ld bc, $070b
    call Call_000_0374
    jp Jump_010_6e08


    call Call_010_6b87
    ld a, $01
    ld [$d067], a
    ld a, $e4
    ldh [rOBP0], a
    ld a, $54
    ld [$d05e], a
    ld a, $1c
    ld [$d05f], a
    ld a, [$cd59]
    ld [$cd58], a
    call Call_010_6c7b
    call Call_010_6ba3
    call Call_010_68fc
    call Call_010_6c15
    ld hl, $9c8c
    call Call_010_6c24
    ld b, $06
    call Call_010_6c3b
    ld a, $01
    ldh [$ba], a
    call Call_010_6c15
    ld b, $04
    call Call_010_6c3b
    call Call_010_6bd2
    ld b, $06
    call Call_010_6c3b
    xor a
    ldh [$ba], a
    call Call_010_6c9b
    jp Jump_000_0188


    call Call_010_6b87
    xor a
    ld [$d067], a
    ld a, $64
    ld [$d05e], a
    ld a, $44
    ld [$d05f], a
    ld a, [$cd5a]
    ld [$cd58], a
    call Call_010_6c7b
    call Call_010_6bd2
    call Call_010_68fc
    call Call_010_6c15
    ld hl, $9c94
    call Call_010_6c24
    call Call_010_6c9b
    ld b, $06
    call Call_010_6c3b
    ld a, $01
    ldh [$ba], a
    call Call_010_6c15
    ld b, $04
    call Call_010_6c3b
    call Call_010_6ba3
    ld b, $06
    call Call_010_6c3b
    xor a
    ldh [$ba], a
    jp Jump_000_0188


Call_010_6b87:
    ld a, $01
    ldh [$ba], a
    call Call_000_03bf
    xor a
    ldh [$ba], a
    call Call_010_6981
    call Call_000_0b31
    ld a, $ab
    ldh [rLCDC], a
    xor a
    ldh [$ae], a
    ld a, $90
    ldh [$b0], a
    ret


Call_010_6ba3:
    call Call_010_690c
    ld hl, $c3fb
    ld a, $5d
    ld [hl+], a
    ld a, $5e
    ld c, $08

jr_010_6bb0:
    ld [hl+], a
    dec c
    jr nz, jr_010_6bb0

    ld hl, $c3e1
    ld b, $06
    call Call_010_702f
    ld hl, $c438
    ld b, $02
    ld c, $05
    call Call_000_03d2
    ld hl, $c461
    ld de, $d11d
    call Call_000_0405
    jp Jump_000_0b31


Call_010_6bd2:
    call Call_010_690c
    ld hl, $c3f0
    ld a, $5e
    ld c, $0e

jr_010_6bdc:
    ld [hl+], a
    dec c
    jr nz, jr_010_6bdc

    ld a, $5f
    ld [hl], a
    ld de, $0014
    add hl, de
    ld a, $61
    ld [hl], a
    add hl, de
    ld [hl], a
    add hl, de
    ld [hl], a
    add hl, de
    ld [hl], a
    add hl, de
    ld a, $60
    ld [hl-], a
    ld a, $5d
    ld [hl], a
    ld hl, $c447
    ld b, $06
    call Call_010_702f
    ld hl, $c468
    ld b, $02
    ld c, $05
    call Call_000_03d2
    ld hl, $c491
    ld de, $d806
    call Call_000_0405
    jp Jump_000_0b31


Call_010_6c15:
    call Call_010_690c
    ld hl, $c3f0
    ld a, $5e
    ld c, $14

jr_010_6c1f:
    ld [hl+], a
    dec c
    jr nz, jr_010_6c1f

    ret


Call_010_6c24:
    push hl
    ld hl, $c3f0
    call Call_000_28b7
    pop hl
    ld a, h
    ldh [$d2], a
    ld a, l
    ldh [$d1], a
    ld a, $02
    ldh [$d0], a
    ld c, $0a
    jp Jump_000_3781


Call_010_6c3b:
jr_010_6c3b:
    ld a, [$d067]
    ld e, a
    ld d, $08

jr_010_6c41:
    ld a, e
    dec a
    jr z, jr_010_6c4b

    ldh a, [$ae]
    sub $02
    jr jr_010_6c4f

jr_010_6c4b:
    ldh a, [$ae]
    add $02

jr_010_6c4f:
    ldh [$ae], a
    call Call_000_0b31
    dec d
    jr nz, jr_010_6c41

    call Call_010_6c5e
    dec b
    jr nz, jr_010_6c3b

    ret


Call_010_6c5e:
    push de
    push bc
    push hl
    ldh a, [rBGP]
    xor $3c
    ldh [rBGP], a
    ld hl, $c302
    ld de, $0004
    ld c, $14

jr_010_6c6f:
    ld a, [hl]
    xor $40
    ld [hl], a
    add hl, de
    dec c
    jr nz, jr_010_6c6f

    pop hl
    pop bc
    pop de
    ret


Call_010_6c7b:
    ld b, $1c
    ld hl, $5d46
    call Call_000_3620
    call Call_010_6cce

Call_010_6c86:
    ld hl, $c300
    ld c, $14

jr_010_6c8b:
    ld a, [$d05f]
    add [hl]
    ld [hl+], a
    ld a, [$d05e]
    add [hl]
    ld [hl+], a
    inc hl
    inc hl
    dec c
    jr nz, jr_010_6c8b

    ret


Call_010_6c9b:
    ld a, [$d067]
    and a
    jr z, jr_010_6cac

    ld bc, $0400
    call Call_010_6cb5
    ld bc, $000a
    jr jr_010_6cb5

jr_010_6cac:
    ld bc, $00f6
    call Call_010_6cb5
    ld bc, $fc00

Call_010_6cb5:
jr_010_6cb5:
    ld a, b
    ld [$d05e], a
    ld a, c
    ld [$d05f], a
    ld d, $04

jr_010_6cbf:
    call Call_010_6c86
    call Call_010_6c5e
    ld c, $08
    call Call_000_3781
    dec d
    jr nz, jr_010_6cbf

    ret


Call_010_6cce:
    ld hl, $6cea
    ld c, $04
    xor a

jr_010_6cd4:
    push bc
    ld e, [hl]
    inc hl
    ld d, [hl]
    inc hl
    ld c, [hl]
    inc hl
    ld b, [hl]
    inc hl
    push hl
    inc a
    push af
    call Call_000_3ae1
    pop af
    pop hl
    pop bc
    dec c
    jr nz, jr_010_6cd4

    ret


    ld a, [$086c]
    ld [$6d02], sp
    jr jr_010_6cfa

    ld a, [bc]
    ld l, l
    ld [$1218], sp
    ld l, l
    jr jr_010_6d12

jr_010_6cfa:
    jr c, jr_010_6d0c

    add hl, sp
    db $10
    ld a, [hl-]
    db $10
    dec sp
    db $10
    add hl, sp
    jr nc, @+$3a

    jr nc, jr_010_6d42

    jr nc, @+$3c

    jr nc, jr_010_6d45

    ld d, b

jr_010_6d0c:
    dec sp
    ld d, b
    jr c, jr_010_6d60

    add hl, sp
    ld d, b

jr_010_6d12:
    dec sp
    ld [hl], b
    ld a, [hl-]
    ld [hl], b
    add hl, sp
    ld [hl], b
    jr c, jr_010_6d8a

Call_010_6d1a:
    ld [$cf78], a
    ld [$d092], a
    ld [$cf17], a
    ld b, $0b
    ld c, $00
    call Call_000_3e1f
    ldh a, [$ba]
    xor $01
    ldh [$ba], a
    call Call_000_2f2e
    ld hl, $c3cf
    call Call_000_2d7a
    ld c, $0a
    jp Jump_000_3781


Call_010_6d3e:
    ld a, $01
    ldh [$ba], a

jr_010_6d42:
    call Call_000_03bf

jr_010_6d45:
    ld a, $e3
    ldh [rLCDC], a
    ld a, $07
    ldh [rWX], a
    xor a
    ldh [$b0], a
    ld a, $90
    ldh [$ae], a
    ret


Jump_010_6d55:
    ld c, $32
    call Call_000_3781

jr_010_6d5a:
    call Call_000_0b31
    ldh a, [rWX]
    inc a

jr_010_6d60:
    inc a
    ldh [rWX], a
    cp $a1
    jr nz, jr_010_6d5a

    call Call_010_690c
    ld c, $0a
    call Call_000_3781
    ld a, $07
    ldh [rWX], a
    ret


    ld hl, $6d82
    call Call_000_3c79
    ld c, $c8
    call Call_000_3781
    jp Jump_010_6d55


    db $ed
    add hl, hl
    ld a, [de]
    ld [hl], l
    jp z, Jump_000_3c7f

    inc l

jr_010_6d8a:
    ld c, a
    ld d, b
    ld bc, $d806
    nop
    add $7f
    res 6, a
    call nz, $dad7
    rst $08
    cp h
    ret nz

    ld d, a
    ld hl, $6dad
    call Call_000_3c79
    call Call_010_6907
    ld hl, $6dc1
    call Call_000_3c79
    jp Jump_010_6907


    db $ed
    add hl, hl
    ccf
    ld [hl], l
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    or l
    cp b
    rst $18
    ret nz

    or [hl]
    call c, $c6d8
    ld d, a
    db $ed
    add hl, hl
    ld h, [hl]
    ld [hl], l
    jp z, $504f

    ld bc, $cd68
    nop
    db $dd
    ld a, a
    cp b
    jp c, $bdcf

    ld d, a
    ld hl, $6de8
    call Call_000_3c79
    call Call_010_6907
    ld hl, $6dfa
    call Call_000_3c79
    call Call_010_6907
    jp Jump_010_6d55


    db $ed
    add hl, hl
    ld a, l
    ld [hl], l
    ld h, $4f
    push bc
    ld a, [hl+]
    ret c

    db $dd
    ld a, a
    or l
    cp h
    ret nc

    push bc
    ld h, $d7
    ld d, a
    db $ed
    add hl, hl
    sbc d
    ld [hl], l
    db $dd
    ld c, a
    or l
    cp b
    rst $18
    jp $cfb7


    cp l
    ld d, a

Jump_010_6e08:
    ld hl, $6e11
    call Call_000_3c79
    jp Jump_010_6907


    db $ed
    add hl, hl
    xor a
    ld [hl], l
    db $dd
    ld c, a
    or [hl]
    call c, Call_000_26b2
    rst $18
    jp $dfd4


    jp Jump_000_30b8


    cp e
    or d
    ld d, a
    ld hl, $6e37
    call Call_000_3c79
    call Call_010_6907
    ld hl, $6e4a
    call Call_000_3c79
    jp Jump_010_6907


    db $ed
    add hl, hl
    ret nc

    ld [hl], l
    rst $10
    ld c, a
    ld d, b
    ld bc, $d806
    nop
    ret


    ld d, b
    ld bc, $cd68
    nop
    call nz, $ed57
    add hl, hl
    db $fd
    ld [hl], l
    ld bc, $cf45
    nop
    db $dd
    ld c, a
    cp d
    or e
    or [hl]
    sbc $bc
    rst $08
    cp l
    rst $20
    ld d, a

Call_010_6e5d:
    ld [$d059], a
    xor a
    ld [$cc5b], a
    ld a, $08
    jp Jump_000_3e9d


    ld a, $01
    ldh [$ba], a
    xor a
    ldh [$b4], a
    call Call_010_7077
    call Call_010_6e85
    call Call_000_0b5a
    xor a
    ldh [$ae], a
    ldh [$ba], a
    call Call_000_0188
    call Call_000_0b31
    ret


Call_010_6e85:
    ld b, $07
    call Call_000_3e1f
    ld a, $e4
    ldh [rBGP], a
    ldh [rOBP0], a
    ldh [rOBP1], a
    xor a
    ldh [$ae], a
    ld b, $03
    call Call_010_702c
    ld a, $08
    ld [$d05e], a
    ld a, $50
    ld [$d05f], a
    ld bc, $0606
    call Call_010_6fb4
    ld de, $28ff
    call Call_010_6ffb
    ret c

    ld a, $b9
    call Call_000_0e45
    xor a
    ld [$d07c], a
    ld de, $710f
    call Call_010_6f80
    ld a, $ba
    call Call_000_0e45
    ld de, $711a
    call Call_010_6f80
    ld c, $0a
    call Call_000_0359
    ret c

    ld a, $b9
    call Call_000_0e45
    ld de, $710f
    call Call_010_6f80
    ld a, $ba
    call Call_000_0e45
    ld de, $711a
    call Call_010_6f80
    ld c, $1e
    call Call_000_0359
    ret c

    ld b, $04
    call Call_010_702c
    ld a, $bb
    call Call_000_0e45
    ld de, $0401
    call Call_010_6ffb
    ld c, $1e
    call Call_000_0359
    ret c

    ld b, $05
    call Call_010_702c
    ld a, $bc
    call Call_000_0e45
    ld de, $0800
    call Call_010_6ffb
    ld a, $b9
    call Call_000_0e45
    ld a, $24
    ld [$d07c], a
    ld de, $7125
    call Call_010_6f80
    ld c, $1e
    call Call_000_0359
    ret c

    ld de, $0401
    call Call_010_6ffb
    ld b, $03
    call Call_010_702c
    ld c, $3c
    call Call_000_0359
    ret c

    ld a, $b9
    call Call_000_0e45
    xor a
    ld [$d07c], a
    ld de, $7130
    call Call_010_6f80
    ld a, $b9
    call Call_000_0e45
    ld de, $713b
    call Call_010_6f80
    ld c, $14
    call Call_000_0359
    ret c

    ld a, $24
    ld [$d07c], a
    ld de, $7146
    call Call_010_6f80
    ld c, $1e
    call Call_000_0359
    ret c

    ld a, $b8
    call Call_000_0e45
    ld a, $48
    ld [$d07c], a
    ld de, $714f
    call Call_010_6f80
    ld c, $50
    jp Jump_000_0359


Call_010_6f80:
jr_010_6f80:
    ld a, [de]
    cp $50
    ret z

    ld [$d05f], a
    inc de
    ld a, [de]
    ld [$d05e], a
    push de
    ld c, $24
    call Call_010_6f9b
    ld c, $05
    call Call_000_3781
    pop de
    inc de
    jr jr_010_6f80

Call_010_6f9b:
    ld hl, $c300
    ld a, [$d07c]
    ld d, a

jr_010_6fa2:
    ld a, [$d05f]
    add [hl]
    ld [hl+], a
    ld a, [$d05e]
    add [hl]
    ld [hl+], a
    ld a, d
    ld [hl+], a
    inc hl
    inc d
    dec c
    jr nz, jr_010_6fa2

    ret


Call_010_6fb4:
    ld hl, $c300
    ld d, $00

jr_010_6fb9:
    push bc
    ld a, [$d05f]
    ld e, a

jr_010_6fbe:
    ld a, e
    add $08
    ld e, a
    ld [hl+], a
    ld a, [$d05e]
    ld [hl+], a
    ld a, d
    ld [hl+], a
    ld a, $80
    ld [hl+], a
    inc d
    dec c
    jr nz, jr_010_6fbe

    ld a, [$d05e]
    add $08
    ld [$d05e], a
    pop bc
    dec b
    jr nz, jr_010_6fb9

    ret


Call_010_6fdd:
    ld hl, $9c00
    ld bc, $0240
    jr jr_010_6feb

Call_010_6fe5:
    ld hl, $c3f0
    ld bc, $00c8

jr_010_6feb:
    ld [hl], $00
    inc hl
    dec bc
    ld a, b
    or c
    jr nz, jr_010_6feb

    ret


Call_010_6ff4:
Jump_010_6ff4:
    ld a, $01

jr_010_6ff6:
    ld [hl+], a
    dec c
    jr nz, jr_010_6ff6

    ret


Call_010_6ffb:
jr_010_6ffb:
    ld a, e
    cp $ff
    jr z, jr_010_700a

    cp $01
    jr z, jr_010_701a

    ldh a, [$ae]
    dec a
    dec a
    jr jr_010_701e

jr_010_700a:
    push de
    ld a, $02
    ld [$d05e], a
    xor a
    ld [$d05f], a
    ld c, $24
    call Call_010_6f9b
    pop de

jr_010_701a:
    ldh a, [$ae]
    inc a
    inc a

jr_010_701e:
    ldh [$ae], a
    push de
    ld c, $02
    call Call_000_0359
    pop de
    ret c

    dec d
    jr nz, jr_010_6ffb

    ret


Call_010_702c:
    ld hl, $c439

Call_010_702f:
    ld c, $00
    ld a, $31
    jp Jump_000_3e9d


    ld a, $33
    call Call_000_3e9d
    ld a, b
    jp Jump_000_0e45


Call_010_703f:
    ld hl, $7298
    ld de, $9000
    ld bc, $0600
    ld a, $10
    call Call_000_028c
    ld hl, $7158
    ld de, $9600
    ld bc, $0140
    ld a, $10
    call Call_000_028c
    ld hl, $7158
    ld de, $8800
    ld bc, $0140
    ld a, $10
    call Call_000_028c
    ld hl, $7898
    ld de, $8000
    ld bc, $06c0
    ld a, $10
    jp Jump_000_028c


Call_010_7077:
    ld b, $0c
    call Call_000_3e1f
    ld b, $01
    ld hl, $497d
    call Call_000_3620
    ld a, $e4
    ldh [rBGP], a
    ld c, $b4
    call Call_000_3781
    call Call_000_03bf
    call Call_000_0167
    xor a
    ld [$d036], a
    call Call_010_70d9
    call Call_010_703f
    call Call_000_0181
    ld hl, $ff40
    res 5, [hl]
    set 3, [hl]
    ld c, $40
    call Call_000_3781
    ld b, $1c
    ld hl, $4569
    call Call_000_3620
    push af
    call Call_010_70fc
    pop af
    jr c, jr_010_70c0

    ld c, $28
    call Call_000_3781

jr_010_70c0:
    ld a, $1f
    ld [$c0ef], a
    ld [$c0f0], a
    ld a, $dc
    ld [$c0ee], a
    call Call_000_0e45
    call Call_010_6fe5
    call Call_000_0188
    jp Jump_000_3e07


Call_010_70d9:
    call Call_010_6fdd
    ld hl, $c3a0
    ld c, $50
    call Call_010_6ff4
    ld hl, $c4b8
    ld c, $50
    call Call_010_6ff4
    ld hl, $9c00
    ld c, $80
    call Call_010_6ff4
    ld hl, $9dc0
    ld c, $80
    jp Jump_010_6ff4


Call_010_70fc:
    ld hl, $c483
    ld de, $7105
    jp Jump_000_0405


    ld h, a
    ld l, b
    ld l, c
    ld l, d
    ld l, e
    ld l, h
    ld d, b
    nop
    nop
    ld d, b
    nop
    nop
    cp $02
    rst $38
    ld [bc], a
    ld bc, $0202
    ld [bc], a
    ld d, b
    nop
    nop
    cp $fe
    rst $38
    cp $01
    cp $02
    cp $50
    nop
    nop
    db $f4
    ld b, $f8
    ld b, $08
    ld b, $0c
    ld b, $50
    nop
    nop
    ld hl, sp-$04
    db $fc
    db $fc
    inc b
    db $fc
    ld [$50fc], sp
    nop
    nop
    ld hl, sp+$04
    db $fc
    inc b
    inc b
    inc b
    ld [$5004], sp
    nop
    nop
    ld [bc], a
    nop
    ld [bc], a
    nop
    nop
    nop
    ld d, b
    ld hl, sp-$10
    ld sp, hl
    ld a, [c]
    ld a, [$fcf4]
    or $50
    ld a, $3e
    ld h, d
    ld h, d
    ret nz

    ret nz

    adc $ce
    add $c6
    ld h, [hl]
    ld h, [hl]
    ccf
    ccf
    nop
    nop
    jr jr_010_7182

    jr jr_010_7184

    inc l
    inc l
    inc l
    inc l
    ld a, [hl]
    ld a, [hl]
    ld b, [hl]
    ld b, [hl]
    rst $28
    rst $28
    nop
    nop
    rst $20
    rst $20
    ld h, e
    ld h, e
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld e, e
    ld e, e

jr_010_7182:
    ld e, e
    ld e, e

jr_010_7184:
    set 1, e
    nop
    nop
    cp $fe
    ld h, d
    ld h, d
    ld a, h
    ld a, h
    ld h, h
    ld h, h
    ld h, b
    ld h, b
    ld h, d
    ld h, d
    cp $fe
    nop
    nop
    db $fc
    db $fc
    ld h, d
    ld h, d
    ld h, h
    ld h, h
    ld a, h
    ld a, h
    ld h, h
    ld h, h
    ld h, b
    ld h, b
    ldh a, [$f0]
    nop
    nop
    db $fc
    db $fc
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld a, h
    ld a, h
    ld l, [hl]
    ld l, [hl]
    ld h, [hl]
    ld h, [hl]
    or $f6
    inc bc
    inc bc
    rst $28
    rst $28
    ld h, [hl]
    ld h, [hl]
    ld a, b
    ld a, b
    ld l, h
    ld l, h
    ld l, [hl]
    ld l, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, e
    ld h, e
    nop
    nop
    nop
    nop
    nop
    nop
    rra
    rra
    dec de
    dec de
    ld e, $1e
    jr jr_010_71ec

    jr jr_010_71ee

    nop
    nop
    nop
    nop
    nop
    nop
    ld a, l
    ld a, l
    ld l, l
    ld l, l
    ld a, c
    ld a, c
    ld l, l
    ld l, l
    ld h, l
    ld h, l
    nop
    nop
    nop
    nop
    nop
    nop

jr_010_71ec:
    rst $20
    rst $20

jr_010_71ee:
    adc h
    adc h
    rst $28
    rst $28
    add e
    add e
    xor $ee
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, d
    ld a, d
    ld h, e
    ld h, e
    ld a, e
    ld a, e
    ld h, e
    ld h, e
    ld a, e
    ld a, e
    nop
    nop
    nop
    nop
    nop
    nop
    ld l, a
    ld l, a
    ld h, [hl]
    ld h, [hl]
    and $e6
    ld h, [hl]
    ld h, [hl]
    ld h, $26
    nop
    nop
    nop
    nop
    nop
    nop
    jr c, jr_010_7256

    ld h, b
    ld h, b
    ld a, b
    ld a, b
    jr jr_010_723c

    ld [hl], b
    ld [hl], b
    nop
    nop
    nop
    ld b, $00
    rrca
    nop
    dec c
    nop
    inc e
    nop
    inc e
    nop
    dec e
    nop
    add hl, de
    nop
    dec sp
    nop
    nop
    nop
    add b

jr_010_723c:
    nop
    ret nz

    nop
    ret nz

    nop
    ldh [rP1], a
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    dec sp
    nop
    ld a, [hl-]
    nop
    ld a, [hl-]
    nop
    dec sp
    nop
    dec de
    nop
    dec sp
    nop
    dec e

jr_010_7256:
    nop
    dec l
    nop
    ldh a, [rP1]
    ld a, b
    nop
    jr c, jr_010_725f

jr_010_725f:
    jr c, jr_010_7261

jr_010_7261:
    cp b
    nop
    ld a, b
    nop
    ld a, b
    nop
    ld [hl], b
    nop
    inc l
    nop
    ld e, $00
    rla
    nop
    rrca
    nop
    rla
    nop
    cpl
    nop
    ld a, $00
    nop
    nop
    ret nc

    nop
    ret nc

    nop
    ret nc

    nop
    and b
    nop
    ldh [rP1], a
    ldh a, [rP1]
    cp b
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
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $0302
    ld [bc], a
    nop
    inc bc
    ld bc, $0001
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0302
    dec b
    ld b, $0a
    dec c
    dec c
    ld a, [bc]
    ld [de], a
    dec e
    ld bc, $203f
    ccf
    ld [bc], a
    ld a, a
    ld c, d
    ld a, a
    ld d, h
    rst $38
    xor h
    rst $38
    call nc, $e8ff
    rst $38
    ld hl, sp-$01
    ld a, b
    ld a, a
    ld [hl], b
    ld a, a
    jr nc, jr_010_732d

    db $10
    rra
    dec d
    rra
    ld a, [bc]
    ccf
    dec [hl]
    ccf
    ld a, [hl+]
    ccf
    ret nz

    ld h, b
    ret c

    inc a
    di
    rrca
    xor b
    ld d, a
    ld d, c
    xor a
    and b
    rst $18
    pop bc
    cp a
    ld a, [bc]
    rst $38
    ld d, l
    ld a, a
    ld l, e
    ld a, a
    scf
    ld a, a
    ld a, $3f
    inc a
    ccf
    jr c, jr_010_7353

    jr nc, jr_010_7355

    jr nc, jr_010_7357

    ld h, l
    ld a, d
    xor d
    push af
    push de
    ld l, d
    ld a, [bc]
    push af
    sub h
    db $eb
    add b
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    inc d

jr_010_732d:
    rst $38
    ld [$15ff], sp
    rst $38
    ld a, [hl+]
    rst $38
    ld d, l
    rst $38
    ld a, [hl+]
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    nop
    nop
    nop
    nop

jr_010_734c:
    add b
    ret nz

    jr c, jr_010_734c

    ld b, e
    rst $38
    and a

jr_010_7353:
    rst $38
    ld e, h

jr_010_7355:
    rst $38
    cp e

jr_010_7357:
    db $f4
    ld b, l
    ld a, [$f58a]
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld [$05ff], sp
    rst $38
    ld a, [hl+]
    rst $38
    dec d
    rst $38
    adc d
    ld a, a
    ld de, $00ff
    rst $38
    ld bc, $00ff
    rst $38
    nop
    rst $38
    ld [bc], a
    rst $38
    ld bc, $02ff
    rst $38
    dec b
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor e
    rst $38
    ld d, a
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor a
    rst $38
    ld d, a
    rst $38
    cp a
    rst $38
    ld e, a
    rst $38
    cp a
    rst $38
    ld e, a
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $fc03
    rst $38
    add b
    rst $38
    db $fc
    inc bc
    add sp, $17
    ld d, l
    xor e
    and d
    ld e, a
    ld bc, $02ff
    rst $38
    dec d
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, a
    rst $38
    xor a
    rst $38
    ld a, l
    rst $38
    rst $38
    rst $38
    ld a, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $0d03
    ld e, $22
    ld a, l
    add c
    cp $00
    rst $38
    ld a, [bc]
    rst $38
    dec d
    rst $38
    dec hl
    rst $38
    ld d, l
    rst $38
    xor e
    rst $38
    ld d, a

jr_010_73ed:
    rst $38
    rst $28
    rst $38
    ld e, [hl]
    rst $38
    cp [hl]
    rst $38
    ld e, [hl]
    cp $aa
    cp $57
    rst $38
    cp d
    rst $38
    ld [hl], c
    cp $e2
    db $fd
    ld d, c
    cp $a2
    db $fd
    ld d, c
    cp $a8
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    push de
    rst $38
    xor $ff
    rst $18
    rst $38
    db $eb
    rst $38
    rst $30
    rst $38
    ei
    rst $38
    rst $38
    rst $38
    cp $ff
    rst $38
    rst $38
    cp $ff
    sub $ff
    xor [hl]
    cp $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_010_7430:
    nop
    nop
    nop
    nop
    jr jr_010_7472

    ld l, b
    call c, $9878
    ret nc

    jr c, jr_010_73ed

    ld d, b
    jr nz, jr_010_7430

    ld h, b
    ldh [$c0], a
    ldh [$c0], a
    ret nz

    add b
    ret nz

    add b
    add b
    nop
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
    add b
    add b
    ld b, b
    ret nz

    add b
    ld h, b
    ldh [rNR41], a
    and b
    ld d, b
    ld d, b
    or b
    db $10
    ldh a, [rNR10]
    ld hl, sp-$58
    ld hl, sp+$56
    cp $a9
    rst $38
    ld d, h
    rst $38

jr_010_7472:
    xor d
    rst $38
    ld d, l
    rst $38
    ld a, [$fdff]
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    cp h
    rst $38
    ld h, a
    ld a, a
    dec c
    add hl, bc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add b
    nop
    ret nz

    ld b, b
    ret nz

    nop
    ldh [$30], a
    ldh a, [$28]
    add sp, -$10
    add sp, -$50
    ldh a, [$a0]
    ldh [$50], a
    ret nc

    ret nc

    sub b
    ldh [$d0], a
    jr nz, jr_010_74c8

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rrca
    rra
    rrca
    jr nc, @+$1c

    dec d
    inc c
    dec bc
    dec b
    rlca
    ld [bc], a
    inc bc
    ld bc, $0001
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop

jr_010_74c8:
    nop
    nop
    nop
    nop
    nop
    ld bc, $0101
    ld [bc], a
    inc bc
    rlca
    inc b
    ld c, $09
    dec e
    ld [de], a
    ld a, [de]
    dec h
    inc [hl]
    dec hl
    ld b, c
    ld a, a
    ld l, d
    ld a, a
    ld d, l
    rst $38
    xor d
    rst $38
    rst $10
    rst $38
    rst $38
    rst $38
    ld a, a
    ld a, a
    ccf
    ld a, a
    rra
    ccf
    rrca
    rra
    inc bc
    rrca
    nop
    inc bc
    nop
    ld bc, $0100
    nop
    nop
    nop
    ld bc, $0f07
    ld [hl], e
    cp $af
    ld d, h
    ld e, [hl]
    xor l
    adc b
    ld a, a
    jr z, @+$01

    ld [hl], b
    rst $38
    or b
    rst $38
    ldh a, [rIE]
    ld a, [c]
    rst $38
    ld [hl], l
    rst $38
    ld h, d
    ld a, a
    inc h
    ccf
    nop
    ld a, a
    ld d, l
    ld l, d
    jp z, $94f5

    ei
    ld [$10f7], sp
    rst $38
    nop
    rst $38
    dec [hl]
    rst $38
    ld a, [hl+]
    rst $38
    ld [hl], l
    rst $38
    xor d
    rst $38
    ld [hl], l
    rst $38
    ld [$75ff], a
    rst $38
    ld [$e5ff], a
    rst $38
    ld [$d7ff], a
    rst $38
    set 7, a
    rst $10
    rst $38
    set 7, a
    push de
    rst $38
    adc a
    rst $38
    sub a
    rst $38
    adc a
    rst $38
    nop
    nop
    nop
    ld bc, $0101
    ld [bc], a
    inc bc
    inc bc
    rlca
    ld b, $07
    add hl, bc
    rra
    ld [hl+], a
    ld a, a
    dec d
    rst $28
    ld [c], a
    sbc a
    pop af
    rrca
    ld [c], a
    rra
    pop de
    cpl
    and d
    ld e, a
    dec b
    rst $38
    ld [bc], a
    rst $38
    dec d
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld b, c
    rst $38
    ld [bc], a
    rst $38
    dec b
    rst $38
    ld a, [bc]
    rst $38
    ld bc, $0aff
    rst $38
    dec d
    rst $38
    ld [bc], a
    rst $38
    ld d, l
    rst $38
    ld a, [hl+]
    rst $38
    ld d, a
    rst $38
    xor e
    rst $38
    ld e, a
    rst $38
    xor a
    rst $38
    ld d, a
    rst $38
    xor e
    rst $38
    ld d, a
    rst $38
    cp a
    rst $38
    rst $18
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    db $10
    jr @+$0a

    jr c, jr_010_75d5

    inc l
    inc [hl]
    ld c, h
    ld a, h
    ld b, h
    ld [$82f6], sp
    cp $02
    cp $00
    rst $38
    xor c
    rst $38
    ld d, l
    rst $38
    cp [hl]
    rst $38
    ld a, [hl]
    rst $38
    cp $ff
    ld a, a
    rst $38
    cp a
    rst $38
    ld a, [hl]
    rst $38
    cp a
    rst $38
    ld d, [hl]
    rst $38
    xor e
    rst $38
    ld d, l
    rst $38
    xor e
    rst $38
    ld e, a
    rst $38
    xor a
    rst $38
    ld a, a
    rst $38
    rst $38
    rst $38
    ld a, a
    rst $38
    rst $38
    rst $38
    ld e, a

jr_010_75d5:
    rst $38
    rst $38
    rst $38
    ld [bc], a
    ld [bc], a
    dec b
    dec b
    ld [bc], a
    inc b
    inc bc
    inc bc
    inc bc
    ld [bc], a
    add b
    add e
    add h
    add a
    add h
    add a
    ld c, b
    rst $08
    ld c, c
    rst $28
    ld a, [c]
    rst $38
    pop hl
    rst $38
    ld [$d5ff], a
    rst $38
    ld [$d5ff], a
    rst $38
    xor d
    rst $38
    rst $10
    rst $38
    xor a
    rst $38
    ld e, a
    rst $38
    cp a
    rst $38
    ld e, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
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
    db $10
    db $10
    jr nz, @+$2a

    ld l, b
    ld c, b
    ld l, c
    ld a, c
    sub $ae
    xor e
    ld d, h
    ld d, l
    xor e
    adc b
    ld [hl], a
    nop
    rst $38
    nop
    rst $38
    jr nz, @+$01

    ld d, b
    rst $38
    and b
    rst $38
    ld d, h
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor e
    rst $38
    ld e, l
    rst $38
    ld a, [$fefe]
    cp $ea
    cp $f6
    cp $e8
    cp $f4
    cp $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $f4
    db $fc
    add sp, -$02
    db $f4
    cp $ea
    cp $d6
    cp $ea
    cp $56
    cp $aa
    rst $38
    ld d, l
    rst $38
    xor e
    rst $38
    ld d, l
    rst $38
    xor e
    rst $38
    push de
    rst $38
    db $eb
    rst $38
    nop
    nop
    nop
    add b
    ld b, b
    ld b, b
    add b
    add b
    nop
    add b
    nop
    nop
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    nop
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    inc b
    inc b
    ld a, [bc]
    ld a, [bc]
    ld c, c
    ld l, a
    sbc l
    sub d
    ld a, [$40a5]
    rst $38
    ld b, b
    ld a, a
    ld l, b
    ld a, a
    push af
    cp a
    ld l, d
    ld a, a
    ld [hl], l
    ld a, a
    ccf
    ccf
    rra
    ccf
    rra
    rra
    rrca
    rrca
    rlca
    rrca
    ld [bc], a
    rlca
    inc b
    rlca
    ld [$100f], sp
    rra
    ld [$110f], sp
    rra
    ld [de], a
    rra
    ld bc, $223f
    ccf
    dec h
    ccf
    ld a, [bc]
    ld a, a
    ld b, l
    ld a, a
    ld c, d
    ld a, a
    dec d
    rst $38
    xor e
    rst $38
    rst $10

jr_010_76c7:
    rst $38
    nop
    nop
    nop
    nop
    add b
    add b
    nop
    ret nz

    ld b, c
    pop bc
    jr nz, jr_010_76c7

    inc e
    rst $38
    and b
    rst $38
    ld b, b
    rst $38
    ldh [rIE], a
    ld [$c5f5], a
    ld a, [$f5ca]
    add l
    ld a, [$fd02]
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    jr z, @+$01

    dec d
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, a
    rst $38
    xor e
    rst $38
    ld e, a
    rst $38
    xor a
    rst $38
    ld d, a
    rst $38
    cp a
    rst $38
    rst $18
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, $06
    ld b, $09
    rrca
    add hl, bc
    dec c
    ld a, [bc]
    ld a, [bc]
    dec c
    dec c
    ld a, [de]
    ld [$101f], sp
    rra
    ld a, [de]
    rra
    dec d
    rra
    dec de
    ccf
    scf
    ccf
    jr c, jr_010_7769

    ld h, c
    ld a, [hl]
    add b
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld [bc], a
    rst $38
    ld bc, $2aff
    rst $38
    dec d
    rst $38
    xor d
    ld a, a
    dec d
    rst $38
    adc b
    ld a, a
    dec d
    rst $38
    ld [bc], a
    rst $38
    dec d
    rst $38
    ld a, [bc]
    rst $38
    dec d
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    db $dd
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    nop

jr_010_7769:
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
    ld b, b
    ret nz

    ld b, b
    ldh [rNR41], a
    ldh [$50], a
    ldh a, [$b8]
    ld hl, sp+$7c
    cp $ff
    rst $38
    cp a
    ret nz

    rst $38
    nop
    ld d, l
    xor d
    ld a, [hl+]
    push de
    inc b
    ei
    nop
    rst $38
    nop
    rst $38
    add b
    rst $38
    ld d, b
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    ld a, [hl+]
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, l
    rst $38
    xor d
    rst $38
    ld d, a
    rst $38
    xor e
    rst $38
    ld d, a
    rst $38
    cp a
    rst $38
    ld e, a
    rst $38
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
    ldh [$b0], a
    ld a, b
    ld b, a
    cp a
    add d
    ld a, a
    nop
    rst $38
    ld [bc], a
    rst $38
    ld bc, $02ff
    rst $38
    ld d, l
    rst $38
    xor e
    rst $38
    ld e, a
    rst $38
    cp a
    rst $38
    ld a, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    db $fd
    rst $38
    db $eb
    rst $38
    sub $ff
    ld [$00fe], a
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
    inc bc
    rlca
    ld a, $79
    push af
    adc d
    xor b
    ld d, a
    dec b
    rst $38
    xor d
    rst $38
    ld d, a
    rst $38
    cp a
    rst $38
    rst $38
    rst $38
    cp $fe
    db $fc
    db $fc
    ld hl, sp-$08
    ldh a, [$f0]
    ldh [$e0], a
    ret nz

    ret nz

    ret nz

    ret nz

    ldh [$e0], a
    ld hl, sp-$04
    rst $20

Call_010_782b:
    rst $38
    ldh a, [rIE]
    ld hl, sp-$01
    ld a, [$fdff]
    rst $38
    cp $ff
    db $fd
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    inc bc
    rlca
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
    inc a
    ld a, h
    add $fe
    ld a, [hl+]
    cp $54
    db $fc
    cp b
    ld hl, sp+$70
    ldh a, [$e0]
    ldh [$c0], a
    ret nz

    add b
    add b
    nop
    nop
    nop
    nop
    nop
    add b
    ret nz

    add sp, $20
    db $f4
    inc e
    db $fc
    ld b, d
    cp $ac
    db $fd
    ld d, l
    db $fd
    xor [hl]
    cp $fc
    db $fc
    ld hl, sp-$0e
    ld a, [$c4fa]
    call nz, RST_00

Call_010_7884:
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
    inc bc
    rlca
    dec bc
    ld a, [bc]
    inc c
    dec c
    dec b
    dec b
    ld [bc], a
    ld b, $00
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
    ld bc, $0101
    nop
    ld [bc], a
    ld [bc], a
    ld [bc], a
    nop
    inc b
    ld b, $04
    dec e
    inc a
    ld e, a
    ld b, b
    ccf
    jr nc, jr_010_7942

    db $10
    rlca
    ld [$080f], sp
    inc bc

jr_010_7929:
    inc b
    rlca
    dec b
    ccf
    ccf
    nop
    ld b, b
    inc e
    jr nc, @+$09

    inc c
    rrca
    dec bc
    rra
    jr jr_010_7989

    ldh a, [$80]
    ld h, b
    push af
    jr nz, jr_010_7929

    db $10
    ccf
    sub b

jr_010_7942:
    rst $38
    ld hl, sp-$19
    and a
    ld b, b
    ld h, b
    nop
    nop
    ld bc, $0101
    ld bc, $0302
    inc bc
    inc b
    ld [$0708], sp
    rlca
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
    db $10
    jr nc, jr_010_79b3

    ld c, b
    nop
    add h
    add h
    add h
    nop
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    nop
    ld bc, $0151
    xor c
    ld bc, $0155
    db $eb
    ld bc, $01fd
    rst $38

jr_010_7983:
    ld [bc], a
    add sp, $18
    ret nz

    ld h, b
    nop

jr_010_7989:
    add b
    add b
    add b
    ld h, b
    ret nz

    ld a, b
    ld b, b
    ld a, b
    ld b, b
    xor c
    ld b, c
    ld d, a
    add e
    xor l
    dec b
    db $f4
    rrca
    db $10
    ld [$c1c1], sp
    add e
    add d
    dec de
    inc e
    ld e, [hl]
    ld h, b
    ei
    add e
    db $fd
    cp $82
    rst $38
    jr z, jr_010_7983

    call nc, Call_010_782b
    add a
    cp [hl]
    ld b, e
    ret c

jr_010_79b3:
    inc a
    ldh [$e0], a
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0001
    ld [bc], a
    ld [bc], a
    ld [bc], a
    inc h
    inc h
    inc c
    ld e, h
    ld e, b
    ld e, b
    db $10
    sub b
    or c
    or e
    ld [hl+], a
    daa
    ld b, h
    ld b, a
    ld b, b
    ld c, a
    ld [$080f], sp
    rrca
    ld c, b
    ld c, a
    add h
    rst $00
    add e
    inc hl
    add b
    jr nz, jr_010_7a17

    nop
    add b
    nop
    jr nz, jr_010_7a74

    sub b
    sub b
    ret nc

    ld d, b
    jr nz, @+$33

    ld e, h
    ld h, d
    ld a, c
    add h
    or $08
    rst $38
    nop
    adc e
    db $fc
    ld a, [hl]
    ld hl, sp-$7a
    adc b
    rlca
    inc b
    ld a, [bc]
    dec c
    ld [de], a
    ld d, $0d

jr_010_7a17:
    dec c
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
    nop
    ld bc, $0602
    ld [$2018], sp
    ld h, b
    add b
    add b
    rlca
    rlca
    db $10
    rra
    nop
    ccf
    ld b, b
    rst $38
    nop

jr_010_7a41:
    rst $38
    or b
    rst $38
    add hl, bc
    rst $38
    dec b
    rst $38
    ld b, $fe
    inc c
    db $fc
    ld e, $f8
    ccf
    ldh a, [$ef]
    ret c

    rst $10
    inc b
    pop hl
    ld [bc], a
    ld b, b
    add c
    nop
    add b
    ld [bc], a
    nop
    dec b
    nop
    ld b, d
    ret nz

    dec b
    jr nz, jr_010_7a85

    jr nz, jr_010_7a65

jr_010_7a65:
    db $10
    ld e, d
    db $10
    cp l
    ret nc

    inc a
    ld [hl+], a
    dec de
    inc h
    ld a, a
    ld c, h
    rst $30
    ld [hl], h
    inc hl
    and d

jr_010_7a74:
    sub c
    sub c
    ld h, b
    ld h, b
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

jr_010_7a85:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld h, b
    ld [hl], b
    add b
    adc b
    db $10
    stop
    db $10
    jr nz, jr_010_7ab6

    jr nc, jr_010_7ac8

    ld [$9008], sp
    sub b
    and b
    and b
    ld b, b
    ret nz

    ld b, b
    ret nz

    ret nz

    ret nz

    nop
    nop
    ld b, b
    ld b, b
    ld h, b
    ld [hl], b
    ld [$9008], sp
    db $10
    ld h, b
    jr nz, jr_010_7a41

    db $10
    ld b, b
    ld [$0898], sp

jr_010_7ab6:
    ldh a, [$30]
    jr nz, jr_010_7b1a

    jr nc, @+$1a

    ld a, h
    ld h, $88
    ld de, $315d
    add a
    add hl, bc
    ld c, $4a
    inc b
    add h

jr_010_7ac8:
    inc b
    add h
    ld [bc], a
    ld a, [hl-]
    add d
    ld a, [hl-]
    ld b, d
    ld [hl-], a
    add d
    ld [bc], a
    ld a, [$a43a]
    ld b, h
    ld hl, sp-$08
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
    nop
    nop
    nop
    ld bc, $0101
    nop
    ld [bc], a
    ld [bc], a
    ld [bc], a
    nop
    inc b
    inc b
    inc b
    nop
    ld [$080d], sp
    ld a, [hl-]
    ld a, b
    cp a
    add b
    ld a, a
    ld h, b
    ccf
    jr nz, jr_010_7b28

    db $10
    rra
    db $10
    rrca
    ld [$0407], sp
    ld b, $05
    inc bc
    inc bc
    ld b, $07
    rrca
    jr jr_010_7b51

    ld h, b

jr_010_7b1a:
    nop
    add b
    ld a, [hl]
    ld a, a
    rra
    db $10
    ld hl, $0020
    ld b, b
    ld l, e
    ld b, c
    ld d, l
    ld h, c

jr_010_7b28:
    ld a, $a0
    sbc [hl]
    sub b
    rst $38
    xor a
    ld h, h
    ld e, h
    jr c, jr_010_7b6a

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
    nop
    nop
    nop
    nop
    jr nz, jr_010_7bae

    sub b
    sub b
    nop

jr_010_7b51:
    ld [$0808], sp
    nop
    inc b
    inc b
    inc b
    inc b
    inc b
    nop
    ld [bc], a
    and e
    inc bc
    ld d, d
    ld [bc], a
    xor d
    ld [bc], a
    sub $06
    ei
    dec bc
    cp $0a
    ld [c], a
    db $10

jr_010_7b6a:
    push af
    db $10
    jp $8020


    ret nz

    nop
    nop
    nop
    nop
    ret nz

    nop
    ld [hl], b
    add b
    pop af
    add c
    db $d3
    add d
    xor a
    add [hl]
    ld e, b
    ld [$1ee9], sp
    jr nz, jr_010_7b94

    add e
    add e
    rlca
    inc b
    ld [hl], $38
    cp h
    ret nz

    rst $30
    rlca
    ld sp, hl
    rst $38
    ld c, h
    ld [hl], e
    ld d, [hl]
    ld c, l

jr_010_7b94:
    db $fd
    add e
    ld a, [hl]
    ld a, [hl]
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

jr_010_7bae:
    nop
    nop
    ld bc, $0201
    ld [bc], a
    inc b
    inc b
    ld d, b
    ld d, h
    adc b
    xor c
    and c
    and e
    ld [hl+], a
    inc hl
    ld h, h
    ld h, a
    ld b, h
    ld b, a
    ld c, e
    ld c, a
    inc c
    adc a
    adc b
    adc a
    add b
    sbc a
    sub b
    sbc a
    sub b
    sbc a
    sub b
    sbc a
    add hl, bc
    adc a
    ld b, $07
    nop
    nop
    add b
    add b
    nop
    add b
    nop
    ld b, b
    nop
    ld b, b
    ld b, b
    nop
    nop
    nop
    ld c, d
    ldh [$35], a
    ld hl, $a1be
    ld e, l
    ld h, d
    add b
    rst $38
    db $f4
    rst $38
    ld a, a
    rst $38
    or b
    ldh a, [rLCDC]
    ret nz

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
    ld b, $06
    add hl, de
    add hl, de
    ld [hl+], a
    ld h, d
    add d
    add d
    inc b
    inc b
    ld b, $06
    jr nc, @+$33

    ld c, d
    ld a, [$fa8a]
    inc b
    db $fc
    dec b
    db $fd
    ld b, $fe
    inc b
    db $fc
    ld c, b
    ld hl, sp+$28
    ld hl, sp+$1a
    ld hl, sp+$15
    cp $39
    pop af
    ld [hl], b
    ldh [rBCPS], a
    ret nz

    ret nc

    add b
    nop
    add b
    ld bc, $0080
    ld b, b
    ld bc, $0040
    nop
    dec b
    nop
    dec sp
    jr nc, @+$08

    ld c, l
    ld a, [bc]
    sbc [hl]
    pop hl
    ld hl, $2686
    xor c
    ld c, c
    ld a, [$324e]
    cp $89
    ld sp, hl
    ccf
    add hl, sp
    rlca
    ld b, $01
    ld bc, $0000
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
    add b
    add b
    sub b
    cp b
    adc b
    ret z

    ld b, b
    db $10
    or b
    db $10
    ld c, b
    ld [$04a0], sp
    call z, Call_010_7884
    inc e
    inc e
    ld [hl-], a
    sbc [hl]
    ld [bc], a
    ld e, [hl]
    ld [de], a
    and h
    inc c
    ld d, h
    inc c
    or b
    inc b
    or h
    ld a, h
    inc b
    adc h
    inc b
    inc b
    inc b
    inc b
    nop
    ld [bc], a
    add b
    add d
    jp nz, Jump_010_42ba

    ld a, d
    ld b, d
    ld [hl], d
    or $82
    jp z, $fc02

    ld a, d
    inc b
    add h
    ld hl, sp-$08
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
    ld [bc], a
    inc bc
    ld [bc], a
    ld bc, $0001
    nop
    nop
    nop
    ccf
    ccf
    nop
    ld b, b
    inc e
    jr nc, @+$09

    inc c
    rrca
    dec bc
    ld e, $10
    inc de
    jr nc, @+$45

    ld b, e
    ld [bc], a
    add d
    call nc, $6880
    add b
    ld a, a
    ld b, e
    dec a
    dec a
    ld b, $07
    ld e, $39
    ld e, a
    ld d, b
    ld [hl], a
    ld a, d
    dec l
    dec l
    dec d
    dec [hl]
    ld [bc], a
    ld [bc], a
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0200
    nop
    inc b
    nop
    ld [$0808], sp
    nop
    db $10
    ld de, $0a10
    jr nz, jr_010_7dcc

    jr nz, @-$04

    ret nz

    cp $01
    db $fd
    inc bc
    ld a, b
    adc h
    sub b
    ldh a, [rLCDC]
    ret nz

    ld h, e
    ld b, c
    ld h, d
    add d
    ld d, [hl]
    add h
    db $ec
    inc c
    or b
    ld de, $1ed8
    db $10
    db $10
    ld bc, $1f01
    rra
    ld l, d
    rst $38
    ld [hl], h
    ld a, a
    ld hl, sp-$61
    db $fd
    ld a, [de]
    ld a, [$7515]
    sbc d
    and b
    rst $38
    ld hl, $d6ff
    sub $08
    ld [$0706], sp

jr_010_7dcc:
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
    nop
    nop
    jr nz, @+$62

    add b
    sub b
    nop
    db $10
    db $10
    stop
    ld [$0909], sp
    ld a, [bc]
    ld a, [bc]
    ld c, d
    ld a, [bc]
    xor h
    inc c
    ld d, h
    inc d
    ret z

    ret


    ld d, c
    ld [hl], c
    jr nc, jr_010_7e31

    ld a, [de]
    dec de
    ld a, [bc]
    dec bc
    ld a, [bc]
    ld c, e
    add c
    add c
    nop
    add b
    nop
    ld b, b
    nop
    ld b, b
    nop
    add b
    nop
    nop
    nop
    nop
    ld h, b

jr_010_7e13:
    ldh [$30], a
    ld [hl-], a
    or c
    or c
    ld h, c
    pop hl
    inc hl
    ld [c], a
    daa
    db $e4
    ld b, e
    call nz, $c84f
    add a
    sbc c
    add d
    sbc [hl]
    ld [hl-], a
    ld a, $89
    rst $08
    inc b
    rlca
    inc bc
    inc bc
    ld bc, $0103

jr_010_7e31:
    ld bc, $0100
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
    ld bc, $0602
    ld c, b
    ld e, b
    jr nz, @-$5e

    add c
    add c
    inc b
    rlca
    nop
    rrca
    db $10
    ccf
    inc a
    ccf
    ld b, d
    rst $38
    ld bc, $01ff
    rst $38
    inc bc
    rst $38
    inc bc
    rst $38
    ld b, $fe
    dec c
    db $fd
    dec sp
    or $f5
    pop bc
    jr jr_010_7e8a

    db $10
    jr nz, jr_010_7e6d

jr_010_7e6d:
    stop
    stop
    nop
    nop
    nop
    nop
    rrca
    nop
    db $10
    ld d, b
    jr nz, jr_010_7e13

    ld h, $e0
    ld a, c
    sbc b
    sub b
    rst $28
    ei
    rst $20
    dec d
    xor $96
    db $db
    ld [$fc3f], a

jr_010_7e8a:
    dec b
    ld a, [$fd02]
    ret nz

    rst $38
    cp a
    ld a, a
    rst $30
    sbc a
    ld a, d
    xor $1c
    inc a
    nop
    nop

jr_010_7e9a:
    nop
    nop
    nop
    nop
    nop
    nop
    jr jr_010_7ebe

    jr nz, jr_010_7f06

    add h
    add h
    nop
    inc b
    ld [$0c08], sp
    inc c
    jp nz, Jump_000_24c2

    db $e4
    jr z, jr_010_7e9a

    db $10
    ldh a, [rNR10]
    ldh a, [$30]
    ldh a, [rLCDC]
    ret nz

    ld b, b
    ret nz

    add b
    add h

jr_010_7ebe:
    ld l, d
    ld l, d
    or d
    or d
    jp nz, $d003

    nop
    jp hl


    ld bc, $8276
    add hl, sp
    ld b, c
    inc d
    db $10
    add hl, sp
    nop
    rlca
    dec bc
    inc b
    inc b
    ld [bc], a
    ld [bc], a
    ld [bc], a
    add d
    ld bc, $5143
    ld b, b
    ld l, e
    ld b, c
    ld d, h
    ret nz

    xor d
    add c
    inc d
    nop
    nop
    ld [bc], a
    ret nc

    inc b
    add sp, $04
    ld h, b
    sub c
    sbc h
    ld h, e
    ld hl, sp-$1d
    inc a
    jr nz, jr_010_7f11

    jr jr_010_7efa

    rlca
    nop
    nop
    nop
    nop

jr_010_7efa:
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

jr_010_7f06:
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

jr_010_7f11:
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
    add b
    add b

Call_010_7f26:
Jump_010_7f26:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add b
    ret nz

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
    add b
    add b

Call_010_7f3c:
    add b
    ld h, b
    ld b, b
    sub b
    ret nc

    sub b
    jr nc, jr_010_7f94

    ld h, b
    ld h, b
    jr nz, jr_010_7f68

Call_010_7f48:
    jr nz, @+$22

    db $10
    db $10
    db $10
    sub b
    db $10
    sub b
    jr nc, jr_010_7f82

    ret nc

    ret nc

    db $10
    db $10
    ldh [$e0], a
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

Call_010_7f68:
jr_010_7f68:
    ld hl, $c3a6
    ld de, $7fe4
    call Call_000_0405
    ld a, [$cd3d]
    ld [$d0e3], a
    ld a, $3a
    call Call_000_3e9d
    ld hl, $c3aa
    ld de, $d0e3

jr_010_7f82:
    ld bc, $8103
    call Call_000_3c8f
    ld hl, $c3ce
    ld de, $cf45
    call Call_000_0405
    ld hl, $c3f9

jr_010_7f94:
    ld de, $cd41
    call Call_000_0405
    ld hl, $c421
    ld de, $cd47
    ld bc, $8205
    jp Jump_000_3c8f


Call_010_7fa6:
    ld hl, $c46e
    ld de, $7fe4
    call Call_000_0405
    ld a, [$cd3e]
    ld [$d0e3], a
    ld a, $3a

Call_010_7fb7:
    call Call_000_3e9d
    ld hl, $c472

Call_010_7fbd:
    ld de, $d0e3

Jump_010_7fc0:
    ld bc, $8103

Jump_010_7fc3:
    call Call_000_3c8f

Call_010_7fc6:
Jump_010_7fc6:
    ld hl, $c496

Jump_010_7fc9:
    ld de, $cd68
    call Call_000_0405
    ld hl, $c4c1
    ld de, $cd49
    call Call_000_0405
    ld hl, $c4e9
    ld de, $cd4f
    ld bc, $8205
    jp Jump_000_3c8f


    ld a, d
    ld a, d
    ld [hl], h
    ld a, [c]
    ld c, [hl]
    ld c, [hl]
    or l
    call nc, $4ef3
    ld [hl], e
    ld [hl], h
    ld a, [c]
    ld d, b
    ld hl, $ad91
    ld bc, $2545
    ld sp, $a565
    nop
    rla
    add hl, bc
    inc b
    db $cb
