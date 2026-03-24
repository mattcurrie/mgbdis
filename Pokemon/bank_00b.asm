; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $00b", ROMX[$4000], BANK[$b]

    ld [hl], a
    add a
    rst $10
    rst $38
    inc b
    ld d, l
    dec sp
    jp nc, Jump_000_2d94

    xor a
    call nc, $eb2f
    ld a, l
    dec b
    add hl, sp
    ld e, h
    add a
    add c
    ld [hl+], a
    jp nc, Jump_000_222b

    add $c2
    ei
    ld c, [hl]
    ld a, [hl+]
    rra
    and [hl]
    ld l, $d4
    add l
    ld d, e
    jr jr_00b_407a

    ld [hl], $79
    ldh [$64], a
    adc $bd
    ld a, [$69f4]
    add hl, bc
    ld a, [bc]
    sbc d
    db $fd
    ld c, b
    ld d, a
    add l
    dec c
    scf
    xor e
    ret nc

    cp a
    add d
    db $db
    ld [$afbe], a
    and l
    ld hl, $ce5b
    ld a, $fc
    inc e
    ld a, b
    pop bc
    ld [hl], b
    ld a, c
    ld c, b
    and c
    and e
    add c
    ld a, a
    add l
    ld b, l

jr_00b_4051:
    add l
    dec h
    sub c
    ld d, b
    ld d, d
    jr z, jr_00b_40c0

    reti


    ld a, d
    add hl, bc
    dec d
    ld b, c
    ld h, $ea
    ld h, c
    ld d, d
    add sp, $53
    ld h, a
    jp nc, $a620

    inc b
    ld de, $a861
    jp nz, Jump_00b_5f8e

    sub d
    inc d
    inc h
    add h
    rra
    pop de
    ld c, [hl]
    jr c, jr_00b_4051

    ld hl, $78e1

jr_00b_407a:
    ld d, $27
    ld a, b
    jp z, $a288

    ld h, e
    ld c, d
    ld [hl], d
    cpl
    ld a, [hl]
    dec hl
    db $e3
    sbc c
    dec [hl]
    ld a, b
    adc c
    ld e, b
    and l
    db $e3
    inc h
    ld hl, $28a2
    db $e4
    ld a, b
    sub l
    ld a, [hl]
    add c
    ret z

    sub b
    ld d, e
    ld [hl], l
    jr c, jr_00b_40b4

    rst $38
    cp l
    ld e, e
    res 0, l
    xor b
    ld l, b
    and $7b
    ld e, d
    pop hl
    rst $10
    and d
    dec d
    xor b
    add l
    ld a, [hl-]
    add hl, hl
    sub [hl]

Call_00b_40b0:
    sbc $06
    ld d, $38

jr_00b_40b4:
    sub c
    ld d, b
    and e
    ld e, d
    ld e, b
    ld l, b
    ld a, b
    ret


    ld c, h
    xor b
    ld [hl+], a
    ld l, b

jr_00b_40c0:
    sub $b8
    adc d
    dec h

Call_00b_40c4:
    ld hl, $e314
    xor d
    dec [hl]
    and d
    inc e
    jr nz, jr_00b_4116

    ld c, b
    ld c, b
    and e
    dec [hl]
    ld hl, $5aa3
    ld hl, $5345
    ld a, $8c
    call nc, $2828
    push de
    ld c, b
    sub d
    ld h, d
    db $10
    ld b, d
    rlca
    db $fd
    ld sp, $9e57
    dec [hl]
    ld d, d
    ld [hl+], a

jr_00b_40ea:
    ld h, e
    rrca
    and c
    ld a, d
    call nc, $9457
    jr z, @-$1b

    add c
    dec d
    ld h, $a3
    rlca
    jp c, Jump_00b_55fa

    db $e3
    ld a, d
    add hl, de
    ld hl, $5e41
    inc sp
    cp [hl]
    rst $28
    rst $38
    adc [hl]

jr_00b_4106:
    ld a, [bc]
    ld a, [de]

Call_00b_4108:
    dec b
    ld d, d
    jr z, jr_00b_40ea

    or a
    ld a, [$9538]
    ld [c], a
    jr z, jr_00b_4106

    db $e4
    ld [hl+], a
    sub d

jr_00b_4116:
    sbc [hl]
    sub h
    add hl, hl
    ld [hl], l
    ld [hl+], a
    sbc l
    ld c, c
    dec hl
    ld a, [de]
    ld b, [hl]
    jr nc, jr_00b_40ea

    ld c, c
    ret


    ldh [$bc], a
    ld [hl], b
    ld [hl+], a
    and c
    ld a, e
    xor d
    add hl, bc
    push bc
    ld c, l
    db $f4
    ld [hl], c
    pop bc
    rst $18
    rst $38
    db $eb
    sub d
    xor c
    adc e
    ld c, $9d
    inc de
    rst $38
    db $fc
    or l
    ld b, b
    sub $a4
    ld b, d
    ei
    rst $00
    inc l
    jr z, jr_00b_41c5

    inc a
    ld d, a
    ld l, e
    jr nc, jr_00b_418e

    xor a
    and a
    inc hl
    dec bc
    inc b
    or c
    ld a, [hl+]
    call z, $c11c
    ld c, $8e
    ld [hl], d
    and c
    ld c, h
    db $ec
    ld b, d
    ld a, [hl+]
    call nz, $a348
    jp $ece6


    ld b, d
    jr jr_00b_418a

    ei
    ld sp, hl
    sbc [hl]
    ld d, [hl]
    adc a
    sbc e
    ld d, d
    add e
    dec h
    inc a
    ld b, l
    ldh [$94], a
    add [hl]
    add hl, bc
    ld e, $36
    sbc e
    db $fc
    add hl, sp
    inc l
    ld e, a
    ld b, l
    pop hl
    sub a
    sub c
    and $dc
    ld l, $0b
    ld b, [hl]
    adc c
    ld a, $18
    and h
    ld a, b

jr_00b_418a:
    ld sp, hl
    push bc
    add $ee

jr_00b_418e:
    ld [de], a
    rst $38
    sbc b
    db $e4
    ld h, a
    ld a, e
    jr nc, jr_00b_41b7

    rst $38
    db $e4
    and h
    ld h, d
    pop de
    adc $91
    ld c, e
    ldh a, [$61]
    sub $67
    pop hl
    sbc h
    ld c, b
    jp z, $ffbf

    ldh a, [$34]
    ld l, b
    adc a
    add [hl]
    ld [hl], b
    rst $08
    rst $38
    rst $38
    rst $30
    db $e3
    sbc d
    ld l, h
    dec c
    inc b

jr_00b_41b7:
    ld [hl], b
    ld [hl], h
    rrca
    db $fc
    ld e, $1f
    ld de, $e01a
    add sp, $47
    inc b
    cpl
    db $fc

jr_00b_41c5:
    add hl, hl
    ld [$bea9], sp
    ld a, [de]
    sbc h
    sub d
    inc d
    sub e
    sub c
    adc [hl]
    ld l, a
    ld [hl], h
    ld [hl], c
    or e
    ld [bc], a
    call nz, $86e0
    rst $00
    ld [bc], a
    ld [hl], d
    and b
    call nz, $4c64
    add h
    ld [hl], $9e
    ld [de], a
    add hl, sp
    jr c, @-$5d

    jr jr_00b_4246

    sbc c
    ld b, a
    ld a, [hl+]
    inc a
    ld c, [hl]
    add hl, bc
    and l
    cp $a2
    add h
    ld [hl], d
    and h
    ld h, l
    ld b, a
    dec b
    ld a, a
    and a
    ld a, [hl-]
    ld a, d
    pop af
    db $eb
    nop
    ld b, h
    cp h
    sub l
    ld a, [hl-]
    call nc, Call_00b_548b
    push de
    inc sp
    or h
    sub l
    sub h
    or a
    db $e3
    ld a, [hl+]
    add hl, bc
    ld h, d
    add hl, hl
    sub c
    ld a, b
    inc d
    call $7246
    and [hl]
    ld b, c
    ld a, [$5234]
    ld d, h
    xor c
    and e
    add l
    ld b, [hl]
    dec bc
    ld b, l
    ld h, d
    rra
    ld [hl], $bd
    ld b, $06
    sub b
    sbc [hl]
    jr c, @-$15

    ld c, $a0
    add d

jr_00b_422f:
    ld a, [hl-]
    dec hl
    db $d3
    jp Jump_00b_54b5


    db $ec
    xor d
    adc a
    and l
    sbc a
    ld d, $9d
    ld [hl], d
    ld b, [hl]
    inc d
    sbc c
    cp c
    xor h
    reti


    ld e, d
    ld e, a
    ld b, [hl]

jr_00b_4246:
    di
    dec d
    ld l, c
    rst $08
    add [hl]
    ld c, e
    ld sp, hl
    set 7, c
    rla
    rst $18
    xor h
    ld [hl], c
    jp nz, Jump_00b_4584

    ld b, h
    ld h, a
    ld [hl+], a
    ld c, $61
    rst $20
    ld h, a
    cp $76
    push de
    rra
    add e
    nop
    ld [hl], a
    xor d
    db $d3
    sub d
    inc a
    dec h
    or h
    and h
    sbc b
    ld d, c
    xor b
    or h
    db $eb
    ld d, b
    or h
    sub h
    ld l, d
    inc d
    or [hl]
    ld a, [bc]
    adc [hl]
    or l
    dec de
    ld c, b
    ld c, c
    add l
    dec h
    ld b, [hl]
    xor b
    db $eb
    ld d, d
    inc l
    add h
    ld h, d
    ld h, l
    jp z, Jump_000_3aaa

    call nc, $2999
    ld h, $9b
    ld d, h
    ld a, [hl+]
    db $d3
    xor c
    ld c, d
    sub d
    jp nc, Jump_00b_7b2e

    cp h
    inc d
    ld [$2452], a
    ld [hl+], a
    dec h
    jr jr_00b_422f

    rst $38
    ldh a, [$bd]
    ld e, a
    ld c, h
    sbc a

jr_00b_42a6:
    ld d, d
    ccf
    ret nc

    or h
    add a
    add hl, de
    db $76
    sbc $ac
    add hl, hl
    rst $38
    sub e
    dec hl
    ld a, e
    push de
    ld b, d
    ld l, b
    daa
    xor a
    ld l, b
    ld e, $97
    sbc [hl]
    xor l
    xor b
    sub $b5
    xor l
    sub $7c
    ld a, $85
    or b
    ld l, b
    ld e, d
    rla
    sbc e
    rst $10
    db $d3
    ld a, [hl-]
    call nc, $e76b
    ld hl, $d3ea
    rla
    sbc b
    ld e, a
    cp $36
    xor l
    ldh a, [$6c]
    daa
    xor b
    sbc c
    ld c, b
    rst $28
    db $db
    db $eb
    db $d3
    add l
    pop hl
    ld b, l
    jp c, $a98c

    ld l, b
    ccf
    ld d, c
    db $fd
    ld [hl], $78
    and l
    ld h, h
    db $10
    adc h
    ld d, h
    rst $08
    rst $38
    rst $38
    ld sp, $5478
    jr z, jr_00b_42a6

    ld d, d
    sbc d
    ld a, [de]
    ld d, b
    cp $87
    ld hl, sp-$37
    ldh [$5c], a
    dec h
    jr jr_00b_436a

    or h
    adc l
    dec h
    ld b, a
    ld sp, hl
    push af
    ld hl, sp-$3b
    rst $30
    add sp, -$46
    ret nc

    ld d, e
    add hl, bc
    ld e, l
    rst $20
    ld [hl], b
    rst $38
    rst $38
    ld c, c
    ld a, a
    and d
    ld l, d
    add d
    add l
    ld c, h
    ld l, b
    add a
    ld a, a
    ld l, a
    rst $38
    cp [hl]
    dec h
    db $e3
    ld c, d
    ld h, $c5
    dec hl
    cp a
    db $fc
    rra
    xor e
    db $e3
    adc d
    add a
    adc b
    ld c, b
    adc c
    ld a, [hl]
    db $dd
    ldh a, [$a3]
    and l
    ld b, [hl]
    ld hl, $868a
    sbc e
    add l
    ld e, [hl]
    ld a, [hl-]
    ld d, h
    and [hl]
    dec l
    ld a, [de]
    ldh [$82], a
    sub l
    ld a, [hl-]
    sub h
    sub a
    ld hl, $9536
    ld c, [hl]
    and l
    ld hl, $52e4
    ld h, h
    adc b
    inc h
    dec h
    ld c, [hl]
    and l
    rla
    adc c
    ld c, c
    ld d, h
    ld h, d
    ld d, c
    adc [hl]
    and l
    rlca
    adc d
    ld c, h

jr_00b_436a:
    and e
    call nz, $b478
    sbc d
    add [hl]
    ld a, [de]
    adc [hl]
    xor c

jr_00b_4373:
    jr nc, jr_00b_439c

    xor a

jr_00b_4376:
    inc b
    sub [hl]
    sub e
    ld a, [bc]
    jr nc, jr_00b_43c3

    add l
    inc c
    sub h
    adc h
    ld c, d
    ld h, c
    sbc l
    pop af
    ld [de], a
    jr z, jr_00b_43ab

    ld sp, $5109
    inc c
    ld [hl], l
    call nz, Call_000_28cc
    add $31
    ld a, c
    reti


    dec d
    dec h
    ld h, d
    adc d
    ld b, d
    ld d, [hl]
    and a
    ld d, h
    ld e, h

jr_00b_439c:
    sub d
    or b
    pop hl
    dec [hl]
    or b
    ld a, [hl-]
    ld [hl], l
    add $11
    ld d, $86

jr_00b_43a7:
    ld d, d
    dec c
    cpl
    cp c

jr_00b_43ab:
    ld de, $09b4
    sub [hl]
    sub a
    ld b, $08
    ld b, b
    push bc
    ld b, b
    pop de
    jp nz, Jump_000_1291

    db $ed
    ld l, b
    inc a
    add h

jr_00b_43bd:
    inc l
    ld b, d
    ld a, [bc]
    ld h, d
    sbc h
    add hl, hl

jr_00b_43c3:
    db $10
    sub $93
    db $10
    ret nc

    or c
    ld de, $8c9c
    sbc e
    jr nz, jr_00b_4373

    dec sp
    jr nz, jr_00b_4376

    ret nz

    sub h
    sbc b
    ld hl, $1102
    push bc
    ld d, b
    ld [hl], c
    inc d
    ld a, $91
    dec hl
    ld a, [bc]
    ld sp, $7382
    ld h, h
    cp b
    ccf
    or c
    add [hl]
    adc h
    ld b, d
    sub d
    sbc h
    ld c, b
    ld h, c
    xor a
    ld l, a
    ei

jr_00b_43f1:
    db $10
    xor a
    push hl
    xor c
    jr z, jr_00b_43bd

    xor a
    or a

jr_00b_43f9:
    db $e4
    call $b1e8
    jr nc, jr_00b_4420

    jr jr_00b_43a7

    call $b991
    ld a, e
    di
    ld sp, $130b
    ld a, [bc]
    ld [hl], b
    and c
    ld [de], a
    add [hl]
    add hl, bc
    scf
    ld b, c
    inc de
    ld [de], a
    sub b
    sub l

jr_00b_4415:
    ld de, $a024
    sbc b
    ld b, e
    add d
    ld b, h
    ld c, d
    ld l, b
    xor d
    pop af

jr_00b_4420:
    add h
    ld e, h
    ld l, c
    and [hl]
    jr jr_00b_448c

    dec bc
    ld c, e
    jp $cb49


    dec bc
    db $10
    call nz, $c1a4
    pop de
    ld c, $61
    inc e
    ld l, c
    ld l, h
    ld e, h
    inc c
    ld h, d
    rst $00

Call_00b_443a:
    ld e, d
    ld d, e
    jr @+$65

    jr jr_00b_43f1

    sub $92
    call nz, $24c4
    and b
    sbc [hl]
    ld a, [bc]
    ld b, e
    ld a, [bc]
    ld sp, $3031
    ld b, h
    ld c, h
    ld [hl], l
    ld [hl+], a
    call nz, Call_000_13c1
    sbc [hl]
    ld a, [hl-]
    inc c
    ld h, c
    db $10
    sbc b
    jr nz, jr_00b_43f9

    ret z

    ld b, [hl]
    ld sp, $8649
    ld [hl], l
    add b
    ld b, h
    or h
    ld d, e
    ld a, b
    pop hl
    and d
    ret c

    sbc d
    jr c, jr_00b_4415

    add a
    ld a, [hl+]
    adc h
    ld a, c
    ld c, c

jr_00b_4472:
    and b
    and b
    ld d, c
    ld b, [hl]
    adc h
    rst $20
    push hl
    dec b
    ld a, [bc]
    add d
    ld d, $8d

jr_00b_447e:
    xor a
    sbc a

jr_00b_4480:
    inc b
    ld hl, $8e5e
    dec de
    ld b, [hl]
    adc h
    push de
    scf
    or h
    ret


    and l

jr_00b_448c:
    ld c, l
    sbc $14
    sbc a
    jr jr_00b_4472

    ld a, b
    ld e, d
    dec e
    ld b, c
    add hl, bc
    dec [hl]
    ld a, b
    rra
    adc c
    ld b, d
    call c, $c564
    cp a
    ld [$058a], sp
    ld h, b
    ld a, d
    and e
    ld a, [de]
    adc h
    sub h
    ld l, l
    ld d, e
    and c
    ld a, [hl+]
    db $d3
    sbc [hl]
    dec a
    add hl, de
    and d
    sbc e
    and a
    inc d
    ld h, c
    sub d
    sbc h

jr_00b_44b8:
    jr z, jr_00b_447e

    ld l, $4a
    ld h, a
    ld [bc], a
    ld d, h
    jr nc, jr_00b_4480

    ld a, [bc]
    ld l, l
    jr c, jr_00b_44e6

    ld [hl+], a
    cp $42
    ld a, [hl+]
    ld l, l
    ld b, c
    xor c
    dec d
    inc b
    rst $38
    sbc h
    ld a, [bc]
    ld h, d
    rst $38
    ld sp, hl
    pop bc
    ld a, c
    ld c, a
    db $fd
    inc b
    ld [hl], c
    cp b
    ccf
    or c
    call z, $fff7
    ld a, [hl]
    sbc h
    dec l
    dec bc
    cp $45

jr_00b_44e6:
    ret nc

    ld h, $6c
    ld h, c
    ld a, b
    rst $00
    ld h, [hl]
    ld c, h
    sbc l
    add hl, hl
    add h
    ld a, h
    ld c, b
    ld d, l
    cp h
    ld b, l
    inc a
    ld b, a
    xor $4e
    push hl
    ld hl, sp-$14
    ld d, l
    ld l, d
    jr nc, jr_00b_4546

    jr c, @-$5f

    db $e4
    ldh a, [$a8]
    pop de
    adc c
    adc [hl]
    ld d, l
    ld a, [hl+]
    ld d, [hl]
    adc h
    db $d3
    adc d
    push af

Jump_00b_4510:
    ld hl, $273c
    dec h
    ld c, h
    ld h, e
    sbc [hl]
    xor b
    reti


    add hl, sp
    xor $1c
    ld d, h
    pop de
    add hl, sp
    ld d, h
    push de
    ld a, [hl-]
    sub d
    ld sp, $be53
    and e
    adc d
    add hl, sp
    cpl
    db $e4
    adc b
    sbc b
    xor $94
    and l
    ld h, $3b

jr_00b_4532:
    jr z, jr_00b_44b8

Call_00b_4534:
    xor h
    db $ed
    and c

jr_00b_4537:
    ld b, l
    ld c, b
    adc [hl]
    bit 4, [hl]
    add [hl]
    sub l

jr_00b_453e:
    adc [hl]
    jp z, $df35

    inc d
    or h
    sbc [hl]
    ld a, [bc]

jr_00b_4546:
    jp hl


    sub $92
    xor l
    ld a, [bc]
    sub b
    sbc h
    adc d
    add l
    ret c

    jr nz, jr_00b_4537

    daa
    daa
    ld d, c
    rra
    rst $38
    dec d
    rst $20
    dec hl
    ld b, h
    ld e, l
    add $1e
    add hl, bc
    ret


    ld c, d
    ld b, d
    ld h, l
    ld sp, hl
    ret nc

    sub b
    sbc c
    ld sp, hl
    call z, Call_00b_46c5
    ld e, [hl]
    ld [hl], e
    ld c, b
    db $e3
    jr @-$06

    daa
    ld a, [hl-]
    ld d, h
    ld e, e
    rst $00
    ld c, d
    jr c, jr_00b_453e

    ld sp, hl
    jp nc, Jump_00b_4598

    ld a, b
    rst $00
    inc sp
    ld c, c
    jr nc, jr_00b_4532

    jp hl


Jump_00b_4584:
    reti


    dec h
    ld hl, $77fe
    ld b, h
    dec a
    call c, $f176
    dec de
    ld c, d
    ld [hl], a
    rl a
    ld d, c
    push hl
    add b
    ld b, h
    cp l

Jump_00b_4598:
    sub l
    and e
    sub c
    rst $38
    xor d
    dec d
    jr c, @-$16

    sbc d
    ld d, [hl]
    add hl, sp
    ld l, l
    ld d, e

jr_00b_45a5:
    cp d
    xor b
    db $ed
    ld a, [hl]
    dec sp
    ld l, a
    ld d, e
    cp c
    inc b
    db $ed
    db $fd
    ld c, [hl]
    jp c, $8554

    ld a, [hl-]
    db $fc
    inc hl
    or d
    sbc b
    jr jr_00b_45a5

    or l
    adc a
    add a
    sbc $da
    sbc h
    xor d
    xor b
    cp h
    ld [hl], d
    di
    ld l, b
    ld d, a
    inc e
    push af
    jr nc, jr_00b_4605

    push de
    ld b, c
    ld [bc], a
    db $76
    inc l
    ld [hl], a
    ld c, d
    ld a, b
    add hl, bc
    rst $18
    daa
    ld a, h
    inc d
    sbc [hl]
    ld c, $32
    ld [hl], l
    jp nz, $b59d

    rra
    db $10
    ld d, l
    cp [hl]
    sub c
    dec d
    ld d, e
    ld b, l
    jr c, jr_00b_4617

    ld a, [bc]
    cp e
    ld hl, sp-$3b
    cp $33
    ld d, l
    ld d, l
    ld d, d
    ccf
    dec c
    ld sp, $d8cc
    sbc h
    ld d, b
    ld l, l
    xor l
    dec b
    add hl, hl
    sub e
    db $76
    and l
    ld h, $e8
    ld d, b
    ld a, a

jr_00b_4605:
    pop de
    adc h
    or l
    rst $18
    ld [$420d], a
    add e
    xor b
    sbc c
    ld l, b
    add $dc
    ld e, e
    jp nc, Jump_000_133c

    ld c, b

jr_00b_4617:
    call $dbea
    add $a3

jr_00b_461c:
    ldh [$ad], a
    ld e, [hl]
    ld a, h
    ld d, l
    ld a, [hl-]
    sbc [hl]
    add $7e
    inc hl
    jp nz, Jump_00b_4c34

    ld a, [$d5ef]
    ld c, $81
    ld b, e
    ld d, h
    sub [hl]
    sub h
    sub $56
    adc c
    ld [hl], l
    jr @+$41

    cp b
    ld d, e
    add hl, hl
    daa
    jr jr_00b_4665

    sub a
    add d
    ld a, [de]
    add d
    ld h, e
    ld e, d
    xor d
    xor d
    inc hl
    ldh a, [$c1]
    ld hl, $38c7
    ld e, [hl]
    dec b
    ld [hl], a
    db $f4
    dec l
    ld l, b
    cpl

jr_00b_4653:
    db $d3
    sub d
    ld a, [de]
    and e
    ld c, d
    inc a
    xor c

Jump_00b_465a:
    db $f4
    add sp, -$59
    add e
    ld [de], a
    xor h
    ld h, h
    pop de
    and d
    ld b, h
    ld b, h

jr_00b_4665:
    ld c, d

jr_00b_4666:
    and b
    sbc b
    cp $67
    db $10
    add d
    db $10
    ld b, e
    ld a, l
    ld [bc], a
    ld h, c
    ld e, c
    sub d
    inc l
    jr jr_00b_461c

    ld e, $8b
    inc c
    ld b, d
    sbc d
    ld d, h
    ld c, [hl]
    ld h, e
    add $32
    ld l, b
    add d

Call_00b_4682:
    jr nc, jr_00b_4666

    sub c
    sbc d
    ld h, [hl]
    ld l, b
    ld h, c
    add d
    jr nc, jr_00b_4653

    ld c, $66
    add [hl]

Jump_00b_468f:
    jr jr_00b_46b8

    scf
    sbc d
    pop hl
    sub e
    ld hl, $6924
    adc e
    rst $20
    inc d
    add hl, sp
    db $76
    sub [hl]
    db $fc
    sbc c
    inc hl
    jp nc, Jump_00b_632c

    ld a, [bc]
    cp a
    inc b
    and [hl]
    or e
    ld h, $a8
    jp $9910


    ret


    ld [hl], b
    ld b, h
    dec hl
    ld hl, $47f2
    rst $20
    inc b
    ld b, h

jr_00b_46b8:
    jr z, jr_00b_46e4

    scf
    pop af
    dec e
    inc e
    sub c
    dec e
    ld [hl], c
    sbc l
    rra
    inc h
    ld b, h

Call_00b_46c5:
    cp [hl]
    ld c, c
    db $fd
    ld d, e
    sub c
    xor c
    rst $18
    sbc b
    inc hl
    sbc c
    adc c
    ld l, b
    ld l, c
    ld [hl], $fc
    inc hl
    add hl, bc
    ld b, a
    adc l
    call nc, $acd6
    sbc $8e
    ld [$f0db], sp
    ld c, h
    ld de, $e458

jr_00b_46e4:
    sub d
    ld d, h
    add l
    adc [hl]
    add hl, bc
    ld e, e
    cp [hl]
    rlca
    adc [hl]
    sub l
    ld e, [hl]
    dec sp
    ld a, [hl+]
    ld a, $b2
    ld a, h
    xor d
    ld [hl], e
    or b
    ld b, c
    inc de
    cp c
    ret z

    add e
    rla
    ld l, [hl]
    and a
    ld [hl], l
    ld e, c
    push bc
    sbc b
    and h
    and a
    rla
    sub [hl]
    ld a, [$c0f9]
    add a
    ld [$f7bd], a
    rst $00
    ld [bc], a
    dec [hl]
    rst $38
    cp [hl]
    ld [hl], d
    pop bc
    inc b
    rrca
    pop af
    reti


    ld d, c
    ld hl, sp+$60
    ld d, l
    or a
    ld d, l
    ld c, b
    ld a, a
    ld c, b
    ld d, b
    ld d, l
    db $e3
    dec [hl]
    xor b
    xor d
    add d
    ld b, [hl]
    cp [hl]
    cp a
    add hl, bc
    adc h
    rra
    ld c, l
    sub c
    ld b, e
    and b
    xor e
    dec b
    add hl, hl
    ldh [$f3], a
    ld e, a
    push hl
    dec bc
    rst $28
    add sp, -$5b
    dec de
    adc l
    ld h, d
    ld a, b
    add a
    ld l, l
    ld l, $65
    xor d
    adc h

jr_00b_4748:
    jp c, Jump_00b_5041

    ld e, l
    ld c, h
    ld h, d
    ld l, a
    and a
    ld b, c
    sbc $b0
    call nc, Call_00b_5428
    xor c
    adc d
    or l
    ld e, a
    jp nc, $a032

    and e
    sub d
    xor e
    push de
    add hl, bc
    ld d, h
    ld d, c
    ld d, e
    sbc [hl]
    cp $68
    add h
    ld d, c
    cp d
    add hl, sp
    ld d, l
    inc b
    and h
    ld d, d
    inc de
    sbc e
    rst $38
    dec bc
    ld d, h
    ld d, c
    ld a, d
    adc e
    ld c, h
    rra
    rst $38
    ld d, c
    sub e
    adc [hl]
    ld [$45ab], sp
    ld sp, hl
    ld d, [hl]
    inc b
    rla
    ld a, [bc]
    dec d
    jr nc, jr_00b_47ee

    ld a, [de]
    xor b
    ld [hl+], a
    jr nz, jr_00b_4748

    ld h, l
    ld l, l
    ld d, h
    and a
    ld [$a81a], sp
    jp nc, $5592

    sub h
    or l
    dec bc
    call Call_000_0775
    add c
    ld b, e
    ld a, b
    add $df
    dec [hl]
    cp d
    ld b, c
    xor d
    xor [hl]
    db $d3
    dec de
    ld c, l
    sub d
    ld a, [hl]
    rrca
    ldh [rKEY1], a
    ld l, d
    ld d, l
    ld l, d

Jump_00b_47b3:
    ld [hl], l
    ld l, d
    ei
    rst $30
    ld a, [bc]
    ld [hl], l
    ld h, $09
    call nz, $feaf
    xor c
    ld c, $ad
    dec b
    ld b, c
    add hl, de
    cp a
    rst $38
    rst $38
    cp $0f
    ld de, $b08a

jr_00b_47cc:
    ld h, $5f
    rst $38
    rst $38
    call nc, Call_000_2e11
    ld b, d
    sbc c
    xor a
    pop de
    add d
    ld sp, hl
    ld l, e
    ldh a, [$c9]
    adc a
    add $2f
    cp $4a
    ldh a, [$e3]
    ld sp, $6586
    ld a, a
    ret z

    and c
    ld l, b
    sub $2c
    sbc h
    dec [hl]

jr_00b_47ee:
    ld b, c
    ld e, c
    ld e, [hl]
    add hl, de
    ld l, $74
    cp d
    ccf
    or d
    dec d
    jp hl


    db $d3
    rst $18
    sbc $c8
    or c
    push de
    cp a
    cp a
    jr nc, jr_00b_47cc

    db $d3
    ld [hl], b
    rst $38
    jr nc, jr_00b_4837

    rst $00
    ld a, [bc]
    xor b

jr_00b_480b:
    ld l, $57
    add [hl]
    ld c, l
    sbc b
    ld h, [hl]
    ld c, a
    ei
    inc c
    rrca
    ld a, [bc]
    db $e3
    ld sp, $987e
    rst $18
    ld sp, hl
    dec [hl]
    and e
    adc e
    ld h, $15
    ld [$5e61], a
    ld e, l
    ld a, d
    inc l
    ld l, c
    rst $38
    rst $38
    ld a, [$93a0]
    ld h, h
    ld d, c
    or l
    rst $38
    rst $38
    rst $38
    pop hl
    ld l, c
    jr jr_00b_480b

jr_00b_4837:
    add h
    ld l, e
    ld d, a
    rst $38
    ld d, c
    rla
    ld d, d
    add d
    and b
    sbc l
    sub c
    add h
    ld e, b
    ld b, h
    or e
    ld d, l
    ld d, e
    and c
    and d
    jp hl


    ld c, c
    ld d, l
    inc sp
    xor b
    jp nc, $8468

    pop de
    adc l
    sub d
    inc hl
    ld b, h
    ld d, h
    and l
    sub b
    jp Jump_000_3419


    ld h, c
    xor d
    add a
    add $3b
    inc d
    pop bc
    inc [hl]
    ld c, h
    add sp, -$48
    pop de
    add hl, bc
    ld l, d
    and l
    ld [$34b9], sp
    sub e
    dec hl

Jump_00b_4871:
    db $f4
    pop hl
    ld h, e
    ld b, [hl]
    sub l
    ld c, l
    inc h
    call $ffbe
    ld c, l
    ld l, c
    ld d, l
    ld l, b
    ld a, [$e4f9]
    xor a
    rst $38
    xor c
    call $ff7f
    ld d, h
    sub d
    or d
    ld l, c
    db $f4
    ld b, e
    db $fd
    dec bc
    pop hl
    sbc d
    push bc
    ld d, h
    ld c, l
    cp a
    or c
    push de
    rst $38
    ld sp, hl
    push de
    rst $38
    ret


    push de
    cp $19
    xor d

jr_00b_48a1:
    ld d, d
    and h
    rst $10
    ei
    ld a, [de]
    ld e, d
    sub c
    ld a, [hl]
    and h
    ld d, a
    and $9f
    rst $38
    ld [$c0a0], a
    xor e
    ld a, [de]
    rst $10
    rst $38
    pop de
    ld hl, sp+$78
    ld h, [hl]
    cp [hl]
    jp z, Jump_00b_55fa

    inc a
    ld b, l
    ld b, d
    jp c, Jump_000_0b6a

    ld d, h
    db $eb
    ld a, [hl]
    xor a
    ld a, a
    ret z

    jp nz, Jump_00b_49ab

    ld l, c
    add hl, sp
    sub l
    and e
    ld e, b
    add [hl]
    add hl, sp
    ld d, h
    ld e, $a0
    ld d, d
    jp nc, $8a76

    ld c, [hl]
    ld h, $85
    ld h, c

jr_00b_48de:
    ld c, c
    ld l, b
    ld d, h
    inc h
    add [hl]
    xor d
    ld c, l
    call nc, Call_000_1972
    ld [hl+], a
    sub a
    adc c
    rst $00
    db $e4
    db $e3
    cp l
    ld b, $64
    ld d, a
    and d

jr_00b_48f3:
    ld a, [hl]
    and d
    db $10
    ld h, e
    adc c
    push de
    rst $38
    add d
    ld [hl], $66
    jr c, jr_00b_495e

    ld d, [hl]
    cp [hl]
    dec c
    inc sp
    ld e, d
    ld [$a2e2], sp
    ld a, [hl+]
    adc b
    ld [c], a
    sub d
    jr jr_00b_48a1

    db $e3
    ld d, l
    ld l, b
    sbc b
    jp nz, $aaea

    adc [hl]
    scf
    xor [hl]
    adc [hl]
    add hl, bc
    push de
    xor b
    pop hl
    and d
    dec l
    adc [hl]
    ld a, [hl+]
    adc [hl]
    call z, $3599
    ld h, c
    ld c, [hl]

Jump_00b_4926:
    dec de
    ld d, l
    ldh [$92], a
    ld l, c
    ld d, l
    ld d, a
    push de
    adc [hl]

jr_00b_492f:
    ld c, d
    adc b

Jump_00b_4931:
    ld a, l
    ld [hl-], a
    xor d
    inc a
    ld [$95b6], sp
    ld c, a
    ld [bc], a
    jp nc, Jump_000_3016

    and e
    pop bc
    cp a
    add l
    ld c, d
    and e
    ret


    or l
    ld a, b
    di
    ld a, [hl+]
    add hl, sp
    scf
    reti


    ld l, b
    ld [hl-], a
    add hl, hl
    ld [c], a
    jr nz, jr_00b_48de

    add [hl]
    inc d
    rra
    jr nz, jr_00b_48f3

    ld l, b
    ld [hl], b
    ld e, b
    cp c
    ld c, d
    scf
    and l
    jp hl


jr_00b_495e:
    jp $a00a


    or h
    and [hl]
    ld c, h
    ld b, e
    ld hl, $3b1c
    inc [hl]
    ld d, $85
    jr @-$42

    add h
    ld b, e
    sbc h
    ld d, d
    ld b, e
    add a
    sub l
    ld b, b
    swap [hl]
    xor l
    adc [hl]
    sbc e
    ldh [$c1], a
    ld a, h
    sub e
    ld a, e
    ld [bc], a
    jr nc, jr_00b_492f

    ld c, b
    ld h, a
    dec bc
    ld l, $f1
    inc a
    ld d, l
    ld b, c
    inc d
    add h
    ld [hl], d
    ld h, c
    and c
    ld c, h
    ld [hl], b

jr_00b_4991:
    ld sp, $86c7
    ld b, l
    ld de, $48c6
    dec l
    inc e
    ld a, c
    dec c
    ld l, b
    db $ec
    ld h, b

Call_00b_499f:
    push de
    and b
    rst $20
    ld e, $86
    ret z

    dec hl
    add hl, de
    inc hl
    ld d, b
    ld b, a
    inc l

Jump_00b_49ab:
    dec [hl]
    ld a, d
    ld l, e
    jr z, jr_00b_4991

    sbc h
    add hl, sp
    ld d, c
    ld a, [bc]
    sbc e
    call nc, $a571
    rst $38
    ld e, [hl]
    sbc e
    xor [hl]
    ld [hl], b
    ret nz

    adc d
    add hl, bc

jr_00b_49c0:
    db $76
    ld a, [hl+]
    xor d
    dec c
    ld e, h
    ld [hl], d
    ld b, e
    ld a, [bc]
    ret


    jr nc, jr_00b_4a1c

    ld sp, $97da
    ld hl, $a7c3
    add e
    rla
    add h
    dec l
    ld e, c
    pop hl
    pop hl
    sub c
    pop de
    add hl, sp
    and $20
    sbc [hl]
    ld [hl], h
    ld de, $44c8
    cp [hl]
    add hl, hl
    dec sp
    ld e, d
    jp c, Jump_00b_47b3

    ld [hl-], a
    ld d, h
    add h

jr_00b_49ec:
    ld d, l
    ld b, c
    ld d, h
    ld e, $36
    ld c, b
    add d
    rst $00
    xor d
    db $e3
    add l
    ld d, b
    add c
    ld h, e
    adc [hl]
    ld [$3a9b], sp
    ld de, $21bf
    sub e
    sub [hl]
    ld b, d
    ld d, [hl]
    sub [hl]
    inc d
    sub a
    di
    ld c, d
    ld d, l
    cp a
    call c, $aeef
    ld a, b
    db $ed
    and e
    ld [$d4b7], a
    jr z, jr_00b_49c0

    cp d
    ld h, [hl]
    sub c
    ld a, [bc]
    ld b, d

jr_00b_4a1c:
    ld [$b1a0], sp
    xor d
    ld c, d
    call nc, $41a1
    inc e
    scf
    add d
    ld [$9c7c], sp
    ld d, a
    ld hl, $a321
    ld sp, $6482
    add a
    sub c
    jp nz, $b198

    and h
    or l
    ld [bc], a
    add sp, $29
    rrca
    sbc h
    dec d
    ld b, e
    ld d, a
    sub e
    dec e
    sub h
    sbc a
    add l
    nop
    ld [hl], a
    xor l
    ld c, a
    ld e, a
    ld l, c
    dec a
    ld c, e
    sub $4d
    ld d, a
    xor a
    dec sp
    ld e, a
    dec c
    ld h, h
    ld d, e
    rlca
    xor b
    rra
    sub e
    xor [hl]
    add hl, hl
    db $f4

jr_00b_4a5d:
    dec de
    ld c, b
    and d
    jr z, jr_00b_49ec

    db $e4
    db $ec
    add c
    dec de
    add [hl]
    ld a, [$c235]
    ld d, l
    ld d, e
    dec [hl]
    jr nc, @+$5e

    ld [de], a
    jr z, @-$63

    ld c, h
    sbc c
    xor c
    inc e
    ld a, [hl+]
    xor d
    xor b
    pop bc
    xor e
    rlca
    ld [hl], h
    jp nz, $e831

    xor d
    xor d
    xor d
    call $a13b
    ld l, a
    inc a
    jr jr_00b_4a5d

    ld h, d
    rst $20
    ld c, d
    ld d, e
    add c
    ld d, l
    xor d
    ld a, [hl-]
    sub d
    ld a, [hl+]
    db $d3
    ld e, [hl]
    and h
    jp hl


    ld c, c
    jp nz, Jump_000_1f62

    db $d3
    ld l, a
    ld d, $a9
    ld sp, $3265
    and h
    ld d, h
    inc [hl]
    ld l, c

Call_00b_4aa7:
    inc [hl]
    ld e, b
    cp c
    jr nc, @-$7b

jr_00b_4aac:
    ret c

    db $10
    ld h, b
    ld l, c
    ld h, h
    db $10
    jp Jump_00b_4e42


    call nc, $3b22
    dec b
    add hl, de
    ld l, [hl]
    ld [$2562], sp
    ld a, [hl-]
    ld de, $614b
    and h
    db $10
    ld c, l
    ld h, l
    add hl, sp
    jr z, @+$54

    ld e, b
    jp nz, $e0b8

jr_00b_4acd:
    sub e
    ld b, h
    xor e
    push af
    ld b, d
    dec d
    ld a, a
    rst $20
    ld c, [hl]
    add hl, hl
    ld c, e
    ld h, [hl]
    inc [hl]
    or a
    xor b
    sbc [hl]
    db $e3
    sub [hl]
    sub l
    add e
    ld sp, $5e48
    dec l
    sbc e
    ld [hl], b
    pop bc
    inc a
    dec bc
    cp d
    dec l
    sbc b
    ld a, $6b
    adc [hl]
    dec h
    inc b
    inc hl
    dec sp
    push af
    ld d, [hl]
    ld h, d
    and b
    ld h, e
    inc b
    inc e
    or a

jr_00b_4afc:
    ld a, [$518d]
    db $fc
    jr jr_00b_4aac

    rla
    ld c, c
    ld a, a
    pop bc
    call c, $f010
    and e
    ld l, e
    cp $85
    ld e, [hl]
    adc b
    db $fc
    ld e, b
    jr nz, @-$5d

    cp b
    adc b
    dec a
    ld [hl+], a
    dec [hl]
    xor a
    ld a, [$aff8]
    ld [$22a8], sp
    or h
    adc d
    db $fc
    db $e3
    ld e, [hl]
    dec d
    ld a, [hl]
    inc b
    sub a
    xor l
    ld hl, $556f
    ld a, b
    rst $18
    rst $38
    ld e, a
    xor b
    ld e, h
    add a
    adc c
    ld d, d
    inc d
    ld l, d
    and e
    sub d
    xor b
    add l
    xor l
    ld a, [hl]
    jr nc, jr_00b_4afc

    ld a, a
    jr nc, jr_00b_4acd

    ld a, [hl]
    and l
    and a
    sub l
    inc sp
    rst $38
    add sp, -$17
    push hl
    ld hl, $ff05
    ld a, [$aa11]
    db $76
    ld c, l
    db $fc
    ld d, l
    sbc d
    or e
    adc d
    ld [hl], l
    ld b, h
    ret nz

    pop hl
    dec c
    and h
    jp $a918


    rst $18
    sub e
    scf
    cp h
    ld h, [hl]
    db $fc
    sub h
    sbc h
    adc b
    or d
    ld c, h
    ld c, h
    adc h
    and h
    inc a
    ld d, l
    ld b, [hl]
    sub c
    ld l, e
    rst $30
    inc b
    ld h, [hl]
    sub c
    ld a, l
    ld b, [hl]
    rst $18
    ei
    jr jr_00b_4bba

    ld d, e
    inc b
    ld h, e
    ld a, [hl+]
    jp hl


    or e
    rst $38
    call z, $9760
    pop hl
    and h
    cp d
    ld [hl], b
    xor b
    ld d, h
    ld [hl], e
    ld a, h
    ld e, $cb
    rst $00
    dec b
    rst $38
    add sp, -$56
    ld l, b
    adc e
    ld hl, sp-$02
    rla
    sub b
    adc d
    ld l, e
    ld a, a
    ld sp, $6132
    ld a, a
    add sp, -$42
    ld c, h
    ld d, l
    jp hl


    xor h
    and $39
    adc l
    cp $1f
    db $e3
    ccf
    rst $38
    xor l
    jp hl


    res 3, b
    rst $10
    add a
    ld hl, sp+$2a

jr_00b_4bba:
    or l
    ld d, a
    ei
    ld e, d
    ld a, [bc]
    ld [hl], b
    ld h, [hl]
    ld d, h
    rst $38
    dec a
    db $dd
    rst $38
    xor e
    ld d, h
    ld c, l
    ld a, d
    ld h, a
    push hl
    inc h
    cp a
    inc a
    adc $fd
    ld d, l
    ld d, l
    ld b, c
    rla
    xor c
    add a
    push hl
    push bc
    di
    sub $0a
    rst $38
    rst $38
    push de
    ld b, c
    dec d
    ld e, [hl]
    xor a
    pop af
    cp e
    inc [hl]
    dec c
    db $fd
    ld c, d
    xor a
    rst $38
    ld b, c
    dec h
    push de
    ld c, c
    sub d

jr_00b_4bf0:
    ld b, d
    inc c

jr_00b_4bf2:
    ld b, h
    di
    rst $38
    call nc, $bdaa
    ld b, b
    ret


    ld c, b
    ld c, c
    sbc l
    jr jr_00b_4bf2

    ld e, a
    rst $08
    rst $38
    ld a, [c]
    rst $38
    or d
    call z, Call_00b_6dbe
    ld a, [bc]
    ld l, $f0
    ld hl, sp+$7f
    rst $38
    ccf
    rst $38
    ccf
    rst $08
    ld sp, hl
    cp d
    jr z, jr_00b_4c45

    inc d
    add a
    rst $38

jr_00b_4c19:
    add a
    rst $38
    pop hl
    rst $38
    ccf
    add d
    ld [hl], b
    ld b, b
    sub h

Jump_00b_4c22:
    adc h
    adc a
    ld a, [hl]
    rra
    rst $38
    rst $08
    ld hl, sp+$77
    sbc h
    pop de
    add h

Jump_00b_4c2d:
    inc l
    jp $d0fc


    ld [hl], e
    ld h, e
    inc [hl]

Jump_00b_4c34:
    ld [hl], d
    ld h, $48
    call nz, $c570
    call z, $c275
    sub c
    ld e, $da
    ld de, $d231
    ld b, h
    rst $18

jr_00b_4c45:
    ld [$a193], a
    ld b, [hl]
    ld h, $4e
    ld a, b
    ld h, d
    db $e4
    rst $20
    add c
    inc hl
    ld [hl], e
    ld h, l
    adc e
    ld b, e
    db $e4
    jr nz, jr_00b_4bf0

    or l
    ld a, [hl]
    and d
    and b
    ld h, e
    add hl, hl
    ld e, a
    xor b
    jp nc, $262a

    ld d, $38
    ld d, e
    ld b, [hl]
    jr c, jr_00b_4c19

    sub e
    dec b
    add hl, sp
    ld [hl], l

Jump_00b_4c6d:
    sub d
    ld e, $8c
    ld d, h
    jp z, $0a57

    db $e3
    ld e, e
    db $fc
    jp nz, $bfaa

    ld a, [$14b2]
    add sp, -$59
    ld d, l
    dec sp
    ld h, l
    ld a, $32
    or c
    ld a, [bc]
    jp c, Jump_00b_7e76

Call_00b_4c89:
    ret


    db $d3
    ld l, l
    ei
    inc e
    rst $30
    db $ed
    ld a, [$2a9a]
    ld e, e
    rst $38
    add a
    ld a, h
    ld e, d
    dec bc
    ld b, [hl]

Jump_00b_4c9a:
    rla
    db $fc
    and c
    inc b
    sub b
    pop bc
    dec de
    ld a, h
    pop bc
    sub h
    db $fc
    ld [hl], b
    ccf
    inc h
    ld b, h
    ld d, a
    inc e
    dec hl
    ld l, [hl]
    sub h
    add $1a
    ld h, a
    call $af79
    sbc $a6
    jr @+$5c

    db $10
    xor d
    ld d, a
    adc h
    ld [hl], b
    ld d, c
    ld sp, $7574
    ld b, h
    rst $00
    push de
    add b
    ld d, l
    cp [hl]

jr_00b_4cc7:
    ld c, a
    and l
    ld sp, $b45e
    ld d, a
    db $e4
    jp c, $d547

    ld l, h
    jr nc, jr_00b_4d34

    cp [hl]

Call_00b_4cd5:
    add e
    ld d, l
    ld [hl], $94
    dec [hl]
    sbc b
    ld [de], a
    inc [hl]
    add $bf
    ld d, e
    ld a, [hl-]
    adc c
    and b
    ld b, l
    ld c, l
    and [hl]
    and e
    adc c
    dec d
    jr c, jr_00b_4cfe

    ret z

    sbc b
    reti


    db $e4
    adc [hl]
    ld a, [hl-]
    sub d
    sbc b
    inc de
    ld h, $49
    ld d, [hl]
    sub h
    or l
    ld d, d
    ld l, b
    add hl, de
    daa
    db $e4

jr_00b_4cfe:
    jr nz, jr_00b_4d7a

    xor b
    pop bc
    ld c, b
    ld c, d
    pop af
    set 3, b
    ld [hl+], a
    and d
    pop de
    db $76
    push af
    add hl, de
    adc b
    ld e, b
    pop de
    ld h, d
    ld de, $48e0
    xor a
    ld d, l
    and c
    ld b, l
    jr nc, jr_00b_4d6c

    ld d, b
    ld h, b
    ld a, d
    ld l, $94
    adc h
    jr jr_00b_4cc7

    ld [c], a
    sbc b
    ld e, $1a
    ld hl, $a72a
    inc hl
    cp $8c

jr_00b_4d2c:
    ld e, [hl]
    inc d
    ld l, l
    jp hl


    ld d, $aa
    ld e, b
    push de

jr_00b_4d34:
    pop hl
    ld a, e
    ld b, [hl]
    ld [hl], c
    and b
    ld d, l
    adc l
    rst $30
    cp $22
    sbc $09
    ld e, b
    ldh a, [rNR44]
    or d
    ld h, [hl]
    sbc e
    ld sp, $26d5
    ld l, h
    ld h, [hl]
    and $18
    dec h
    ld b, l
    ld a, [hl+]
    ld c, d
    ld c, $90
    db $f4
    ld h, e
    ld h, c
    jr jr_00b_4d2c

    ld b, h
    ld b, h
    ld a, [bc]
    ld [hl], b
    sbc $d2
    ld d, l
    db $10
    cp a
    rst $38
    add h
    sub [hl]
    and h
    or c
    add d
    ld b, h
    rra
    rst $38
    rst $38
    and c

jr_00b_4d6c:
    inc l
    ccf
    and a
    ld [bc], a
    rra
    rst $38
    rst $38
    ld hl, sp+$7a
    ld d, l
    inc e
    ccf
    rst $38
    rst $38

jr_00b_4d7a:
    rst $38
    ld b, [hl]
    call z, $0d55
    rst $38
    rst $38
    rst $38
    and [hl]
    ld c, c
    ld [hl-], a
    ld h, a
    ld [hl], e
    ld a, a
    rst $38
    ld a, [bc]
    ld e, d
    ld d, $5b
    ld a, [$1734]
    rst $10
    jp Jump_00b_68f9


jr_00b_4d94:
    db $ec
    sub e
    cp a
    sub d
    add h
    ld b, h
    ld d, a
    and h
    xor e
    inc b
    inc [hl]
    and c
    ld d, b
    xor a
    and $79
    ld c, e
    add hl, de
    jp nc, $ff1f

    ld a, [hl-]
    ld d, e
    inc d
    sbc b
    cpl
    dec d
    inc bc
    ld e, e
    cp $2b
    inc e
    add hl, hl
    xor h
    dec c
    ld de, $7a1c
    ld c, $92
    xor e
    jr @-$15

    pop bc
    db $fc
    ld d, $b1
    ld c, [hl]
    ld h, c
    add sp, -$3c
    push bc
    add $8f
    add hl, de
    ld [hl], c
    push hl
    add b
    ld b, h
    cp h
    sbc e
    db $f4
    add a
    ret nc

    ld l, c
    jr c, jr_00b_4e04

    dec bc
    ld a, b
    ld l, h
    ld d, b
    xor b
    sbc $d0
    add [hl]
    db $fd
    sbc a
    ld d, e
    ld h, l
    ld l, l
    ld l, b
    rla
    add $38
    inc h
    cpl
    rst $38
    and c
    ld b, c
    jr c, jr_00b_4d94

    ld b, $30
    ld c, [hl]
    ld e, b
    pop de
    dec a
    ld l, a
    add hl, hl
    add hl, sp
    sbc [hl]
    cpl
    ld c, [hl]

Jump_00b_4dfb:
    ld b, [hl]
    rlca
    sbc $45
    inc b
    pop hl
    push de
    add [hl]
    add hl, bc

jr_00b_4e04:
    ld e, a
    and l
    ld a, [hl-]
    ld l, d
    dec d
    adc a
    add l
    sbc e
    add hl, hl
    ldh [rOBP0], a
    add hl, hl
    ld a, [bc]
    ld [hl], h
    rst $38
    cp h
    ld de, $f1ce
    db $10
    inc hl
    and a
    ld [bc], a
    dec [hl]
    db $10
    res 3, h
    ld [hl], e
    and b
    or h
    ld b, a
    and $de
    sub c
    inc a
    ld h, c
    and $f5
    and [hl]
    reti


    add sp, $2c
    jr nc, jr_00b_4e74

    ld [hl], $9c
    ld sp, $7729
    rst $00
    inc hl
    pop bc
    ld b, c
    ld h, d
    add d
    ld [hl], b
    jp $8a12


    add hl, bc
    add hl, de
    ret z

Jump_00b_4e42:
    pop af
    adc h
    ld a, h
    jr c, jr_00b_4ebe

    sbc e
    push de
    dec [hl]
    cp c
    ld c, a
    ld a, [bc]
    jp c, Jump_00b_54bf

    add $9e
    ld d, e
    ret nz

    or h
    sbc d
    cp a
    ld d, h
    cp d
    ld a, c
    ld c, [hl]
    db $eb
    ld c, h
    ld l, d
    ld c, h
    xor c
    push hl
    dec sp
    dec l
    ld hl, $4d55
    jp hl


    call nc, $4ec5
    dec de
    ld h, d
    jp hl


    ld d, b
    cp a
    push de
    ld d, l
    ld a, [$6148]

jr_00b_4e74:
    adc [hl]
    add hl, hl
    dec h
    ld d, h
    adc b
    ld [de], a
    ld a, [hl+]
    xor d
    sub h
    ld l, e
    ld c, [hl]
    ld [hl], a
    inc e
    add a
    dec d
    ld a, a
    ld d, l
    ld l, $06
    jr @+$65

    add l
    jp $a122


    ld h, d
    ld [$87b4], a
    adc e
    adc [hl]
    jr jr_00b_4ec1

    ret


    dec [hl]
    cp l
    ld c, e
    add c
    scf
    ld h, e
    ld e, d
    adc l
    reti


    ld d, l
    pop hl
    sub e
    ld b, h
    db $dd
    db $e3
    add c
    ld hl, $4586
    ld [hl-], a
    ld c, a
    ld de, $458b
    jr c, jr_00b_4ec3

    ret nc

    add l
    ld b, [hl]
    or e
    push bc
    add l
    ld [hl], $b2
    ld a, [de]
    sub b
    adc c
    ld l, d
    sub e
    cp d

jr_00b_4ebe:
    jr @-$56

    xor b

jr_00b_4ec1:
    inc h
    inc de

jr_00b_4ec3:
    ld d, h
    jp nc, Jump_00b_4931

    adc d
    ld c, d
    ld c, b
    adc e
    ld c, d
    ld c, [hl]
    ld [$32b5], sp
    sub l
    adc h
    sbc b
    add l
    add [hl]
    add hl, sp
    and b
    adc h
    dec d
    ld c, h
    ld [$25a3], a
    ld d, [hl]
    and e
    add l
    ld c, e
    and l
    ld c, [hl]
    rrca
    ld a, [$36a9]
    add l
    add [hl]
    inc sp
    sub h
    call $938c
    ld d, h
    sub h
    adc d
    inc [hl]
    and h
    ld [c], a
    ld c, d
    adc h
    ld [c], a
    call nc, $25da
    ld h, l
    ld d, l
    ld e, b
    and h
    pop de
    call nc, $f4c1
    push bc
    ld [hl+], a
    ld l, d
    xor d
    ld a, [c]
    ld e, b
    jp z, $d12a

Jump_00b_4f0b:
    and b
    ld d, e
    ld b, h
    sbc c
    ld d, l
    adc c
    ld h, e
    ld e, c
    add hl, bc
    ld b, d
    sub $82
    ld d, e
    add hl, sp
    ld c, h
    ld d, [hl]
    adc [hl]
    ld a, [de]
    and d
    dec hl
    ld a, [hl]
    scf
    xor d
    xor d
    inc sp
    adc h
    ret z

    ld h, $b0
    ld b, b
    sbc [hl]
    inc h
    and c
    inc b
    add d
    ld l, e
    ld [bc], a
    ld a, b

Call_00b_4f31:
    ld d, a
    xor c
    db $10
    ld c, c
    xor h
    add hl, bc
    ldh [$5f], a
    ld [$fe55], a
    xor c
    ld [hl], b
    daa
    ld [hl], l
    rst $38
    ld d, l
    ld a, a
    rst $38
    rst $38
    xor d
    xor c
    sbc d
    sbc h
    ld [hl], h
    ld b, e
    db $eb
    ld d, a
    sub c
    ld [hl], l
    ld d, l
    ld b, c
    inc h
    jp $cc1c


    ld a, [bc]
    call nc, $286f
    ld b, e
    ld [hl+], a
    sbc h
    ld l, b
    cp a
    rst $38
    ld sp, hl
    ld [hl-], a
    add hl, hl
    ld [hl], c
    add d
    ld [hl], c
    and h
    cp $b7
    inc e
    ld a, [bc]
    ld d, e
    inc e
    ld a, a
    xor a
    rst $38
    sbc h
    ld [de], a
    cp [hl]
    xor a
    ld b, $6e
    add a
    rst $38
    ld hl, sp+$78
    ld a, c
    ret nz

    rst $38
    ldh a, [rOBP0]
    ld c, c
    and [hl]
    ccf
    rst $38
    rst $38
    or c
    call nz, Call_00b_56fc
    add hl, sp
    sub [hl]
    ld b, a
    rst $38
    rst $38
    ld sp, hl
    rst $00
    sbc c
    ld h, e
    sbc b
    inc h
    rst $38
    rst $10
    db $fd
    daa
    ld d, $66
    sbc c
    ld b, e
    add l
    db $e4
    rst $38
    cp $9c
    add hl, de
    sbc h
    add hl, sp
    adc d
    cpl

jr_00b_4fa4:
    db $eb
    push af
    rst $38
    and d
    jp $3925


    and d
    ld h, a
    ld a, [bc]
    rra
    cp $bf
    rst $38
    and $6f
    sbc d
    ld b, d
    sub l
    inc h
    ld b, e
    ld a, a
    rst $38
    cp $aa
    ld b, e
    dec bc
    cp $9b
    ld b, [hl]
    ld [$5725], sp
    rst $38
    rst $38
    ld hl, sp-$16
    rst $38
    rst $20
    ld d, h
    ld h, [hl]
    or l
    cp $bf
    rrca
    db $fc
    sub d
    sub b
    jp Jump_00b_4926


    rrca
    and l
    ret nc

    call c, $fd4b
    ld [$52b1], a
    ld b, [hl]
    ld h, e
    rrca
    db $f4
    sbc d
    jr z, @-$29

    inc bc
    rst $38
    jr jr_00b_501b

    jp hl


    add [hl]
    cpl
    sub c
    dec de
    ld d, d
    ld c, a
    cp $96
    add d
    db $10
    ld b, [hl]
    ld a, [hl]
    ld d, [hl]
    ld [hl], c
    add sp, $75
    ld b, h
    pop bc
    dec bc
    jr jr_00b_4fa4

    jr jr_00b_5027

    ret


    adc [hl]
    ld b, l
    and l
    dec l
    dec bc
    ld a, [de]
    jr nz, jr_00b_4fa4

    ld c, b
    ld c, c
    and h
    sub c
    ld b, h
    ld d, c
    inc c
    ld l, a
    ld [hl-], a
    sub b
    add [hl]
    sub c
    ld a, [de]
    ld c, d
    ld e, d

jr_00b_501b:
    pop de
    rst $10
    inc c
    ld a, b
    ld b, b
    ld b, h
    or d
    ld e, e
    db $d3
    ld b, l
    adc e
    ld a, a

jr_00b_5027:
    ld d, b
    ld h, b
    ld d, e
    dec b
    and d
    ret nc

    adc h
    ld hl, $5a89
    scf
    add [hl]
    ld [hl+], a
    ld b, c
    ld l, b
    ldh [$88], a
    adc h
    inc hl
    adc [hl]
    inc b
    adc c
    adc [hl]
    sub l
    ld c, c
    adc [hl]

Jump_00b_5041:
    and l
    ld c, [hl]
    push af
    adc [hl]
    ei
    call z, $93da
    add [hl]

jr_00b_504a:
    sub l
    inc a
    jr jr_00b_506b

    add hl, bc
    ld e, b
    ld d, e
    sub d
    ret c

    jp nz, $390a

    ld h, l
    ld hl, $d3bf
    sbc [hl]
    and e
    ld [$36f1], sp
    ld c, a
    ld a, [hl-]
    ld h, [hl]
    cp [hl]
    ld e, d
    ld e, $d4
    pop bc
    ld d, $bf
    ld b, c
    db $10

jr_00b_506b:
    add a
    ld de, $a5c0
    cpl
    ld a, d
    ld c, h
    ld b, h
    ld b, h
    add h
    ld b, e
    cpl
    ld h, c
    inc de
    dec h
    cp b
    jp z, Jump_000_1609

    ld de, $549a

Jump_00b_5081:
    ld de, $a30e
    dec de
    and l
    ld a, h
    ld d, d
    ld de, $72cf
    ld d, h
    sbc h
    ld de, $a576
    rst $00
    dec a
    sbc b
    ld b, h
    and [hl]
    ld c, c
    sub h
    jr jr_00b_504a

    ld d, c
    sub h
    ld l, [hl]
    and b
    ret


    sub d
    ld [hl], c
    and d
    adc a
    and b
    call Call_000_2327
    ld [bc], a
    add l
    adc l
    and a
    inc [hl]
    ld h, l
    ld e, $20
    ld d, l
    cp [hl]
    cp c
    ld d, l
    ld c, a
    ld bc, $bda2
    ld [hl], $5f
    pop de
    ld d, l
    ld d, $32
    cp l
    ld [hl-], a
    ld a, [hl]
    ret c

    add hl, hl
    and [hl]
    adc b
    ld c, h
    call nc, $83b7
    or d
    ld h, d

jr_00b_50c9:
    ld h, c
    ld h, b
    adc [hl]
    daa
    ldh a, [$83]
    ld [hl+], a
    dec l
    ld d, $30
    ld c, l
    add sp, -$57
    ld e, b
    ccf
    xor d
    xor c
    ld d, b
    and e
    push bc
    cp h
    jp nc, Jump_00b_4c22

    ld h, h
    push de
    ld c, h
    call c, Call_000_2569
    ld d, c
    and l
    jr c, jr_00b_50c9

    ret c

    cpl
    ld b, d
    ld b, $2e
    ld c, l
    sbc $0e
    ld a, [bc]
    jr jr_00b_510e

    jp nc, Jump_00b_5536

    db $fc
    add a
    ld hl, sp-$3b
    ld sp, $0aa3
    adc c
    ld a, b
    and h
    sub a
    or $26
    adc l
    add sp, -$3a
    ld b, a
    db $fc
    add l
    db $e3
    or d

jr_00b_510e:
    or a
    ld a, a
    and e
    push hl
    ld [hl], a
    reti


    and a
    add h
    rst $28
    ld b, b
    sbc [hl]
    rlca
    ld a, a
    sub c
    ld h, $aa
    sub d
    rst $18
    inc h
    ld a, [hl+]
    rla
    sub l
    ld h, $0b
    inc bc
    push de
    ld a, [bc]
    adc h
    inc de
    ld [hl], b
    ld b, [hl]
    ld de, $5585
    ld h, $4b
    inc sp
    inc b
    and l
    ld h, $aa
    ld h, d
    cp d
    adc e
    add e
    jp nc, Jump_00b_6e0c

    call nc, $1a91
    pop bc
    sbc e
    ld b, d
    ld [c], a

Jump_00b_5145:
    sbc b
    ld e, l
    dec b
    ld [bc], a

jr_00b_5149:
    adc [hl]
    sbc d
    cp $b8
    or l
    ld c, d
    dec [hl]
    cp h
    inc d
    ld de, $08a2
    ld hl, $0d71
    ld e, h
    sub b
    cp h
    add hl, bc
    sbc e
    dec c
    inc b
    add h
    ld h, e
    ld [hl-], a
    ld a, [hl-]
    ld a, [c]
    ld h, e
    add e
    ld d, c
    dec e
    ld a, [de]
    inc hl
    ret nc

    ld sp, $4294
    ld h, h
    sub a
    inc de
    ld c, h
    ld l, a
    add hl, de
    jp z, $8560

    dec e
    call $8454
    ld a, h
    xor b
    ld b, h
    cp l
    or l
    dec sp
    ld e, b
    db $ed
    and e
    sbc c
    ld c, e
    add l
    ld h, h
    sub $f5
    dec bc
    ld d, h
    sbc b
    pop hl
    cp b
    add hl, hl
    ld [hl], d
    ld h, l
    ld b, [hl]
    scf
    xor e
    ld a, [hl+]
    ld b, [hl]
    ret c

    db $dd
    ld a, [bc]
    ld sp, $e1a8
    xor h
    jr @-$29

    ld c, l
    ld d, h
    jr nz, @+$68

    jr nc, jr_00b_5149

    add d
    rst $18
    ld b, $69
    ld a, [bc]
    rst $38
    jr c, jr_00b_51d9

    call c, Call_000_3a85
    rst $28
    db $e3
    db $e3
    daa
    or [hl]
    sbc l
    xor l
    dec e
    adc h
    ld [hl], e
    and [hl]
    db $10
    dec l
    ld h, a
    ld [bc], a
    ld e, d
    ld b, e
    inc e
    sub [hl]
    adc l
    dec e
    adc a
    cp $96
    rst $20
    inc de
    rst $38
    ld a, [$e7bf]
    rrca
    ld e, l
    ld a, a
    rst $38
    ld sp, hl
    jp nz, $8791

    push af
    ld d, c

jr_00b_51d9:
    rst $00
    ld l, h
    rst $38
    sbc l
    rst $18
    rra
    ld e, b
    ld h, [hl]
    cp [hl]
    ld c, l
    rrca
    ld sp, hl
    inc a
    ld [hl], a
    sub l
    ld b, d
    ld h, e
    push bc
    ld a, [$4226]
    db $d3
    jp nz, $28a3

    db $e3
    ld d, l
    ld [hl], $85
    ld d, l
    ld d, h

Jump_00b_51f8:
    ld d, b
    ld d, e
    ld d, a
    xor d

jr_00b_51fc:
    db $d3
    dec [hl]
    and e
    ld a, [de]
    ld [hl], h
    pop de
    ld c, [hl]
    rla
    adc [hl]
    add hl, bc
    ld c, e
    ld l, l
    ld h, e
    ld h, $97
    adc [hl]
    ld l, [hl]
    db $fd
    call z, $2aa8
    inc b
    push bc
    ld d, l
    ld [hl-], a
    and b
    or h
    ld [de], a
    rra
    ret nc

    ld b, c
    ld b, d
    sub h
    add l
    ld l, b
    xor c
    dec [hl]
    or $60
    sbc b
    ld [hl], $b2
    ld hl, $8cb6
    and e
    inc [hl]
    ld [de], a
    add hl, hl
    dec l
    dec h

jr_00b_522f:
    ld l, b

Call_00b_5230:
    sub h
    inc sp
    add [hl]
    and b
    sbc [hl]
    ld d, b
    ld h, c
    ld b, c
    cp h
    inc de
    rla
    jr c, jr_00b_522f

    ld a, [de]
    cp d
    sbc b
    dec l
    and e
    rra
    ld c, b
    ld h, e
    ld b, l
    add d
    rlca
    ret c

    ld h, $81
    db $e3
    cpl
    rst $30
    call $2838
    jr z, jr_00b_5267

    ld l, d
    ld b, $35
    cp e
    adc h
    ld d, h
    ld hl, $b751
    ld a, c
    and l
    ld c, h
    call nc, Call_00b_4cd5
    db $10
    sub [hl]
    adc b
    add d
    adc l

jr_00b_5267:
    jr nz, jr_00b_51fc

    dec h
    ld [hl-], a
    xor b
    add $8c

jr_00b_526e:
    pop de
    ld l, l
    ld c, c
    ld a, b
    push bc
    ld h, e
    ld a, [hl+]
    or l
    add hl, hl
    add c
    adc b
    xor [hl]

jr_00b_527a:
    ld hl, sp-$36
    adc l
    ld l, l
    xor a
    db $fd
    and d
    sbc $3b
    ld l, l
    ld c, h
    sub a
    db $e3
    pop bc
    xor a
    push de
    ld a, [hl]
    adc l
    or a
    jp z, $b132

    db $e4
    or c
    ld [hl], d
    ld a, b
    xor h
    ld h, [hl]
    and a
    add h
    sbc e
    ld b, a
    ld [bc], a
    add hl, hl
    or d
    adc l
    ld d, l
    add hl, hl
    ld [de], a
    ld l, h
    pop bc
    add d
    sbc d
    ld a, l
    jr jr_00b_527a

    add $8f
    dec d
    ld a, [de]
    ld b, [hl]
    db $fc
    sbc b
    ld c, b
    ld sp, $a408
    jr z, jr_00b_52d5

    sbc b
    ld a, [hl+]
    sbc b
    ld e, c

jr_00b_52b9:
    ld [hl], e
    dec c
    jr z, jr_00b_526e

    dec de
    ld e, a

jr_00b_52bf:
    xor e
    ld e, d
    adc l
    add hl, hl
    ld l, $4c
    add hl, bc
    rrca
    db $10
    adc e
    add h
    or b
    ld c, d
    pop hl
    ld d, b
    ld l, c
    add hl, bc
    adc e
    or b
    jr nc, @-$0e

    dec l

jr_00b_52d5:
    dec b
    ei
    pop de
    sub l
    ld b, [hl]
    sub b
    ld d, l
    ld d, [hl]
    add h
    ld [$61b7], sp
    inc de
    sbc d
    push bc
    ld [hl], a
    ld de, $ac0b
    inc c
    ld sp, $5294
    add hl, bc
    sbc d
    inc c
    cp l
    ld e, d
    inc c
    ld b, e
    inc e
    add hl, sp
    xor e
    inc bc
    inc bc
    ld hl, $bd22

jr_00b_52fb:
    dec e
    adc b
    ld b, c
    add e
    ld de, $b113
    pop de

jr_00b_5303:
    dec bc
    add h
    inc l
    and h
    ldh a, [$fc]
    sbc d
    ld l, e
    and l
    jr c, jr_00b_52bf

    ld d, l
    ld d, [hl]
    ld h, c
    ld h, [hl]
    db $d3
    ld a, e
    cp a
    inc c
    ld h, a
    jr jr_00b_52b9

    sbc d
    inc hl
    scf
    cp $66
    add h
    ld h, a
    ld a, [hl+]
    sbc b
    ld sp, $0d2d
    sbc c
    rst $00
    inc b
    jp nc, $83ac

    cp a
    or c
    ldh [$5d], a
    ld d, l
    db $dd
    ld e, h
    ld a, b
    db $76
    ld a, [de]
    ld l, $11
    cp b
    ld b, h
    cp c
    rst $10
    db $fc
    rst $20
    ld d, a
    and e
    add d
    db $d3
    ld a, [bc]
    jp nz, $f35f

    ld h, l
    ld c, d
    ld h, c
    ld l, b
    ldh [$a1], a
    cp c
    ld d, b
    add l
    add hl, sp
    ld a, e
    ld l, c
    sbc c
    jr c, jr_00b_5303

jr_00b_5354:
    sbc b
    xor c
    ret c

    db $e4
    cp c

jr_00b_5359:
    ld c, e
    or h
    ldh [$62], a
    ld h, b
    sub h
    cp d
    sub h
    push de
    add c
    ld e, e
    or h
    jr jr_00b_52fb

    pop de
    ld d, l
    dec b
    ld a, [bc]
    jr jr_00b_5382

    dec c
    adc h
    ld e, e
    ld b, c
    or a
    ld l, [hl]
    ld a, [hl+]
    and b
    adc h
    ld l, d
    and a
    ld a, a
    call nc, $81ab
    jr c, jr_00b_53a8

    ld [hl], l
    ld b, $26
    adc [hl]

jr_00b_5382:
    ld e, d
    and e
    adc $9d
    ld l, d
    ld [hl], a
    ld a, $69
    ld a, [de]
    jr c, jr_00b_5354

    ld [bc], a
    ld h, a
    ld d, c
    ret


    jr nz, jr_00b_5359

    add hl, bc
    ret z

    adc d
    push de
    and a
    inc l
    ld b, l
    sub l
    ld l, c
    db $d3
    ld [bc], a
    cp a
    jp hl


    jp Jump_00b_465a


    dec d
    rst $38
    add sp, $40
    sbc e

jr_00b_53a8:
    ld b, c
    inc d
    rst $18
    rst $38
    jp hl


    and l
    ld d, [hl]
    sub b
    pop hl
    jp $9a57


    ld b, b
    xor a
    ld d, h
    ld sp, hl
    ld d, e
    dec de
    db $dd
    ld d, e
    ld a, [$474d]
    ld [hl+], a
    ld d, $7c
    ld [hl], b
    ld d, l
    cp l
    or l
    ld d, l
    dec sp
    sub $8b
    xor c
    ld c, [hl]
    add [hl]
    ld d, e
    ld l, c
    add hl, sp
    add hl, de
    add d
    ld l, $d2
    db $e3
    adc c
    inc b
    ld h, b
    ld d, d
    ld h, b
    ld d, c
    adc [hl]
    ld b, h
    sbc b
    ld hl, $988c
    inc hl
    adc [hl]
    ld h, $58
    cp b
    ld a, [c]
    ld [de], a
    inc hl
    sub l
    dec h
    and h
    jp nc, $9238

    ld d, b
    ld b, l
    inc sp
    ld h, e
    sub c
    ld hl, $3c0a
    dec b
    dec h
    ld sp, $4e51
    ld h, [hl]
    ld c, b

Call_00b_53fe:
    ld c, c
    jp hl


    inc d
    inc de
    sbc c
    add hl, bc
    add hl, de
    ld [hl+], a
    add [hl]
    ld h, [hl]
    add hl, sp
    and h
    dec h
    add hl, bc
    ld a, [hl+]
    inc b
    ld [$a7a5], a
    call nc, $3b89
    ld l, c
    ld e, d
    add hl, hl
    inc a

Jump_00b_5418:
    ld a, [de]
    xor d
    and e
    jp nc, $da9e

    ld c, d
    ld [hl], a
    and c
    cp l
    ld d, h
    cp b
    daa
    ld c, e
    pop af
    ld c, d

Call_00b_5428:
    ld b, l
    daa
    ld a, [hl+]
    ld sp, hl
    add a
    ld a, [$110a]
    add $be
    dec l
    inc hl
    adc l
    add a
    and a
    ld a, [de]
    ld hl, sp-$1c
    push hl
    ld b, e
    ld h, a
    daa
    db $e4
    ld c, e
    add hl, de
    rst $00
    daa
    db $e4
    xor c
    ldh [$7e], a
    inc l
    ld [hl-], a
    ld d, [hl]
    sbc h
    push de
    db $e3
    ld [hl+], a
    push bc
    ld e, c
    pop de
    sub l
    ld b, l
    and c
    adc [hl]
    ld [hl], d
    ld d, d
    add hl, de
    ld l, [hl]
    or e
    ld c, $72
    rst $10
    push hl
    ld e, d
    ldh a, [$b9]
    call $a55f
    ld d, b
    cp h
    ld [hl], l
    ld [hl], a
    and a
    adc l
    rlca
    ld l, d
    add hl, bc
    add hl, hl
    rst $18
    rrca
    ld d, l
    ld [bc], a
    ld a, h
    ret nc

    ld b, h
    cp [hl]
    ld d, l
    ld e, a
    db $d3
    sbc c
    ld a, [hl]
    or l
    ld c, [hl]
    ld d, [hl]
    ld h, c
    ld a, d
    jp nz, $e638

    dec d
    adc [hl]
    adc b
    rla
    ret c

    ld [$f868], a

Call_00b_548b:
    dec d
    ld d, h
    adc c
    ld c, [hl]
    ld a, [hl+]
    ld a, [$ffab]
    inc b
    ld [c], a
    ld h, l
    add hl, hl
    ld e, b
    push hl
    sub b
    xor d
    adc d
    ld c, [hl]
    ld e, d
    sub l
    ld d, [hl]
    adc a
    add [hl]
    rst $18
    ld l, $8a

jr_00b_54a5:
    db $76
    dec sp
    add hl, hl
    jp z, $c0e2

    ret nc

    ld b, a
    daa
    sub $0c
    and a
    inc [hl]
    add d
    ret nz

    rst $00

Jump_00b_54b5:
    ld b, e
    ld c, h
    db $76
    inc l
    db $76
    and l
    and h
    jp z, Jump_00b_4871

Jump_00b_54bf:
    ret c

    ld b, l
    ret


    push bc
    and c
    add hl, de
    ld d, c
    ret


    ld a, [hl+]
    ld e, d
    sbc l
    dec [hl]
    ld d, h
    ld a, h
    ld b, b
    ld h, [hl]
    or [hl]
    ld e, a
    ld sp, hl
    ld d, h
    pop af
    ld a, [de]
    adc c
    xor e
    ld a, [bc]
    ld d, e
    cp [hl]
    xor d
    ld l, a
    db $fd
    ld a, [hl+]
    ld c, [hl]
    rst $00
    or l
    ld [hl], h
    xor d
    and l
    ld [hl], e
    sbc l
    ld a, a
    jp nz, Jump_000_3aec

    ld c, [hl]
    rst $30
    cp d
    ld hl, $54dd
    inc h
    db $e4
    ld a, a
    ld b, l
    add d
    adc b
    ld l, b
    add $94
    call $1a69
    ld a, [de]
    ld [$0a55], sp
    add hl, sp
    rst $18
    and c
    or h
    adc d
    ld a, [de]
    adc b
    and e
    ld [hl], h
    jr z, jr_00b_54a5

    ld hl, $6206
    ld d, e
    ld a, [hl+]
    inc [hl]
    ld h, c
    add d
    sbc b
    dec h
    add c
    add hl, bc
    add d
    adc [hl]
    ld [hl], a
    ret z

    ld b, e
    sub e
    inc b
    adc d
    ld d, [hl]

Jump_00b_5520:
    jr c, jr_00b_557c

    jp nz, $8121

    sub e
    inc e
    and $5a
    ld d, h
    sbc b
    sbc l
    set 1, [hl]
    dec [hl]
    or $be
    add hl, hl
    add hl, bc
    ld d, d
    inc d
    sbc c

Jump_00b_5536:
    ld hl, $364e
    jr nc, @-$7c

    add d
    ld h, $91
    ld [$d40b], a
    push bc
    ld hl, $d88c
    ld [hl+], a
    ld [de], a
    inc de
    daa
    ld c, e
    ld b, [hl]
    and c
    ld c, h
    jr @+$64

    and [hl]
    ld a, [hl+]
    sbc c
    dec c
    dec [hl]
    ld h, l
    and h
    jr jr_00b_55b0

    jr @-$21

    ld hl, $212a
    ld h, b
    ld d, c
    ld a, b
    ld e, b
    dec d
    inc b
    jp $2242


    and d
    sub $8b
    ld h, b
    sub [hl]
    ld e, b
    ld l, b
    db $10
    ld a, l
    dec b
    ld c, [hl]
    ld l, e
    ld hl, $ba58
    ld [hl+], a
    or h
    inc d
    inc hl
    sbc d
    and e
    ld c, e

jr_00b_557c:
    adc h
    inc e

jr_00b_557e:
    inc de
    adc $70
    ld c, a
    add hl, sp
    ld l, $71
    cp c
    add hl, bc
    push hl
    ccf
    cp $e0
    sbc l
    add sp, -$58
    ld b, l
    push af
    ld l, c
    ldh [$2a], a
    sbc d
    ld b, e
    dec e
    dec hl
    db $fc
    ld b, l
    xor c
    ldh [$bf], a
    db $f4
    and l
    xor c
    jp nc, $ff92

    rst $08
    add hl, de
    ret


    or d
    ld h, b
    sub e
    ld h, h
    ld hl, $4f1d
    add d
    ld b, e
    sbc d
    dec h

jr_00b_55b0:
    jr nz, jr_00b_557e

    and c
    ld hl, $bf14
    adc l
    and c
    jp hl


    cp e
    dec sp
    db $fc
    ld [$c368], sp
    rst $38

jr_00b_55c0:
    call nz, $f9c1
    or [hl]

Jump_00b_55c4:
    rst $38
    ldh a, [$3c]
    inc sp
    and e

Call_00b_55c9:
    rst $38
    dec e
    rra
    db $f4

jr_00b_55cd:
    ld b, a
    add e
    ld de, $d061
    ld sp, $51cf
    ld c, [hl]
    rrca
    and c
    adc [hl]
    ld c, e
    inc e
    adc d
    cp a
    xor e
    pop hl
    cp $0c
    inc c
    ld [$7212], a
    ld a, a
    rst $38
    ldh a, [$7f]
    sub d
    pop hl
    db $e3
    ld l, c
    ld [$af39], sp
    rst $38
    ldh a, [$a1]
    ld b, h
    cp b
    ld a, [hl]
    xor a
    sub c
    dec b
    and [hl]

Jump_00b_55fa:
    ld c, e
    rst $38
    jp nz, $93ff

    db $e4
    ld e, a
    ldh a, [rLYC]
    ld e, d
    ld h, l
    rst $38
    ld a, [bc]
    rst $38
    db $10
    ld hl, sp-$20
    add d
    ld [$55f9], sp
    rla
    ld [hl], h
    ld c, d
    inc a
    xor e
    pop af
    ld d, $ee
    and e
    ld [hl], c
    db $d3
    rst $38
    inc b
    ld c, d
    jr jr_00b_55c0

    ld de, $341d
    ld l, b
    add d

jr_00b_5624:
    ld b, h
    jr nc, jr_00b_5698

    rst $20
    ld b, b
    and a
    sbc l
    ld [bc], a
    sbc [hl]
    ld [hl], l
    inc d
    ld b, h
    and [hl]
    ei
    call nc, Call_00b_4aa7
    ld e, h
    add $db
    cp a
    jp nc, Jump_00b_6b6d

    db $e3
    add [hl]
    cp l
    ld c, d
    rst $28
    add hl, sp
    ld h, d
    jr jr_00b_55cd

    push hl
    or c
    and e
    xor d
    ld c, l
    ld d, h
    pop hl
    adc l
    ld h, [hl]
    dec [hl]
    ld c, [hl]
    jr jr_00b_5624

    sub e
    or c
    add d
    dec sp
    inc hl
    sbc a
    sub d
    call nc, $93e7
    ld a, [de]
    ld d, l
    dec d
    ld l, d
    ld b, c
    xor e
    inc d
    sbc $bd
    ld d, l
    push de
    sub [hl]
    add hl, sp
    ld a, [hl+]
    xor d
    xor b
    ld a, [c]
    db $76
    ld a, [hl+]
    ld [hl], c
    ld h, $b3
    add hl, hl
    add d
    ld c, a
    sbc h
    inc d
    ld a, [c]
    dec bc

jr_00b_5679:
    inc b
    add e
    ld e, c
    rst $00
    ld h, $14
    ld [hl], b
    inc h
    cp e
    jr @+$54

    sbc d
    ld b, h
    add $e9
    jp nz, Jump_00b_4c9a

    ld [hl], c
    cp h
    ld h, b
    and [hl]
    ret nc

    ld b, l
    or c
    sbc d
    ld h, d
    pop bc
    ld a, [hl+]
    or h
    inc d

jr_00b_5698:
    ld c, l

jr_00b_5699:
    xor h
    ld h, e
    inc bc
    add $68
    xor l
    ld c, c
    adc l
    ld h, [hl]
    ld c, h
    ld b, d
    inc d
    and c
    add hl, de
    push de
    ld d, a
    jp nz, $55ab

    ld d, c
    jp $ae5f


    xor e
    ld b, a
    jp $5580


    cp a
    dec bc
    ld d, h
    pop af
    rra
    db $fd
    dec sp
    sub h
    ret


    ld l, [hl]
    and l
    jr c, jr_00b_56e1

    ld c, b
    pop de
    xor [hl]
    ld c, $0a
    jr jr_00b_5708

    sub e
    dec [hl]
    ld b, d
    sbc h
    db $10
    ld h, c
    adc h
    jr c, @-$75

    sub e
    jr z, jr_00b_5700

    ld hl, sp+$16
    jr c, jr_00b_5679

    adc h
    ld l, b
    add l
    ld b, d
    dec h
    ld [hl-], a
    db $f4
    pop hl

jr_00b_56e1:
    ld [hl], b
    jp Jump_000_2341


    add c
    ld b, d
    sub $8e
    dec [hl]
    ld b, [hl]
    inc d
    sbc b
    ld a, [hl-]
    call c, $1384
    dec de
    ld a, l
    ld e, [hl]
    ld a, [de]
    ld [$8120], sp
    ld h, $66
    inc sp
    ld e, c

Call_00b_56fc:
    add hl, de
    and l
    ld [hl], a

jr_00b_56ff:
    ld [hl], l

jr_00b_5700:
    add hl, bc
    sub $8d
    add hl, hl
    sbc b
    adc e
    ld d, b
    xor d

jr_00b_5708:
    and e
    sub [hl]
    ret c

    ld d, l
    jr jr_00b_56ff

    inc hl
    pop af
    add hl, de
    ld hl, sp+$5a
    add hl, bc
    ld [c], a
    jr nz, jr_00b_5699

    ld a, b
    ret z

    inc h
    ld [$3be7], a
    inc d
    di
    rst $18
    ld a, a
    dec bc
    sbc d
    call c, Call_00b_40b0
    di

jr_00b_5727:
    ret c

    ld a, b
    ld [hl], c
    inc de
    ld l, c
    and d
    dec sp
    cp [hl]
    pop hl
    cp e
    pop hl
    sub e
    inc a
    pop af
    adc h
    cpl
    rst $18
    cp $1f
    rst $38
    and e
    inc b
    sub $67
    db $fc
    ld b, l
    ld a, [hl]
    dec d
    rst $38
    add sp, -$45
    ld a, c
    sub e
    add sp, $41
    inc bc
    pop af
    ld [hl], h
    rst $38
    or [hl]
    pop de
    sbc l
    ld [bc], a
    dec bc
    or b
    ld e, b
    ld h, c
    sub c
    ld a, a
    reti


    cp e
    rst $30
    jp c, Jump_000_1016

    ld c, h
    jr nc, jr_00b_5727

    rst $28
    jr @+$49

    add a
    inc b
    ld a, [hl]
    ld [hl], b
    ld b, h
    cp [hl]
    ld b, l
    ld a, [hl-]
    db $dd
    ld l, [hl]
    ld [hl], h
    rst $20
    ld d, [hl]
    xor c
    ld d, e
    sbc [hl]
    adc e
    and d
    ld e, $ce
    inc d
    or h
    ld d, $39
    xor h
    ld e, $22
    ld a, [bc]
    ld h, e
    add e
    ld a, b
    ld l, h
    jp hl


    ld a, c
    ld d, b
    ld b, a
    sub h
    rst $20
    add l
    jp nz, $ec70

    and $aa
    ld [hl+], a
    xor b
    db $fc
    ld d, $7d
    ld [hl], d
    ld c, d
    ld [hl], l
    ld b, c
    cp $c7
    ld b, h
    add e
    rst $38
    call nz, Call_00b_7132
    ld a, a
    rst $38
    sub a
    sbc h
    cpl
    inc a
    ld d, $0d
    jp c, Jump_000_3f9d

    cp $e7
    inc h
    inc d
    rst $10
    rst $38
    sbc h

jr_00b_57b3:
    call z, Call_00b_4108
    call nc, $4a7e
    ld h, [hl]
    or a
    ld a, a
    ld d, e
    jp z, $9ea0

    db $f4
    di
    ld h, b
    ld c, a
    dec d
    ld b, d
    add d
    ld e, b
    ld d, e
    xor c
    ld d, l
    ld c, e
    adc e
    ld h, h
    db $eb
    ld b, e
    ld b, $eb
    add $45
    sbc b
    db $ed
    and a
    ld a, h
    dec [hl]
    and c
    ld b, [hl]
    ld hl, $d46f
    and $43
    and c
    ld d, e
    ld b, $e4
    sbc b
    add hl, hl
    jr c, jr_00b_5846

    add c
    ld a, h
    ld h, h
    jr jr_00b_57b3

    ld e, b
    add hl, hl
    adc l
    add sp, $59
    add c
    ld [hl+], a
    add [hl]
    inc hl
    ldh [$aa], a
    add hl, bc
    add d
    dec [hl]
    and a
    jp nz, Jump_00b_585e

    ret


    dec b
    ld a, [hl+]
    ld [hl+], a
    inc [hl]
    ld a, b
    ld d, [hl]
    push af
    ld e, [hl]
    ld b, $17
    ld h, b
    xor d
    ld h, h
    ld [de], a
    dec d

jr_00b_580f:
    ld d, e
    ld c, d
    ld b, d
    ld hl, sp+$71
    ld h, c
    sub l
    add hl, bc
    and [hl]
    ld b, c
    ld [$4caf], a
    ld l, c
    and h
    ld e, e
    jp nz, $0515

    ld c, c
    and [hl]
    ld [hl-], a
    and d
    sbc d
    add c
    adc c
    ld b, e
    ld h, b
    ld d, l
    and l
    sbc b
    ld [de], a
    ld e, d
    sub d
    jr z, @-$7a

    ld h, [hl]
    ld hl, $5050
    ld a, b
    and h
    ld [hl], $25
    sbc a
    sbc c
    ld [$2eb6], sp
    dec b
    dec b
    inc d
    ld h, b
    ld h, h
    db $10

jr_00b_5846:
    ld b, l
    inc b
    sub $8c
    sub h
    jr z, jr_00b_580f

    ld hl, $5090
    xor e
    ld h, b
    sub b
    ld c, l
    sub l
    ld a, [$7404]
    jr jr_00b_58b5

    ld b, d
    xor b
    ld d, $41

Jump_00b_585e:
    ld [hl], $51
    sbc b
    cp d
    ld b, $19
    cp a
    cp $a6
    ld [hl], $a0
    sbc b
    cp b
    ld l, l
    ld h, d
    add hl, hl
    ld d, l
    ld l, b
    reti


    rst $20
    adc h
    ld [de], a

jr_00b_5874:
    sub h
    db $eb
    ld d, a
    adc [hl]
    ld a, [de]
    ld a, [hl-]
    ld l, a
    adc h
    sub h
    db $eb
    sbc h
    ld d, c
    and $43
    inc de
    ld e, $42
    add hl, hl
    add hl, sp
    ld [c], a
    and l
    jp nz, $d8d1

    sbc b
    push bc
    cpl
    ld b, a
    ld h, h
    inc d
    add hl, bc
    adc e
    pop af
    pop hl
    call z, Call_000_2f8c
    ret


    ld l, c
    ret c

    adc d
    cp h
    db $fc
    jp hl


    ld [$8a5f], sp
    ld [hl], e
    cpl
    ret nc

    ld c, l
    rst $38
    add e
    db $e3
    ret nc

    ld a, a
    inc e
    ld c, a
    rst $38
    db $10
    adc a
    ld hl, sp+$64
    ld l, d
    pop bc

jr_00b_58b5:
    add e
    sbc h
    db $10
    reti


    ld d, b
    cp a
    add a
    ldh [$f7], a
    and c
    pop bc
    rst $20
    dec d
    ld [hl], d
    adc d
    db $fc
    ld a, [$8a17]
    ldh a, [$3a]
    ld [hl], d
    cp a
    rst $38
    rst $38
    ldh a, [$c2]
    ld [c], a
    rst $38
    inc e
    ld [hl], l
    ldh a, [$fc]
    inc d
    ld b, e
    add a
    ld hl, sp-$1f
    add hl, de
    jr nz, jr_00b_5874

    and c
    push bc
    ld b, d
    sub b
    sbc $08
    cp h
    ld d, e
    call nc, Call_000_12b3
    cp h
    ld d, h

jr_00b_58eb:
    db $10
    ld [hl+], a
    ld hl, sp+$7f
    dec b
    ld [bc], a
    ld c, a
    ld a, [bc]
    or a
    pop af
    ld sp, $2f9a
    adc $1a
    adc l
    and h
    ld c, h
    rrca
    add a
    rst $20
    ld [bc], a
    ccf
    pop hl
    db $e3
    sub c
    ld e, d
    ld e, l
    rlca
    db $f4
    ld l, h
    add e
    ldh a, [rVBK]
    ld de, $5fc3
    xor d
    rst $38
    db $f4
    ld [hl], b
    inc a
    ld c, a
    and h
    pop af
    dec a
    rst $38
    or $70
    ld b, c
    push bc
    and $1c
    ld d, h
    ld c, h
    ld [hl], b
    jr nz, jr_00b_58eb

    inc [hl]
    ld a, h
    adc h
    ld l, l

jr_00b_5929:
    dec e
    ld h, b
    ld b, h
    or h
    sub h
    and a
    ld c, l
    sub e
    ld [$2e3d], sp
    rla
    ld c, h
    ld [hl], h
    sub a
    db $db
    jp nc, Jump_00b_4c6d

    sub [hl]
    jp nc, $f1df

    ld d, l
    inc b
    jp z, $dcdf

    db $10
    ld d, l
    adc b
    ld b, c
    inc [hl]
    ld e, b
    sbc d
    ret nc

    ld l, b
    inc d
    ld de, $b489
    jr z, jr_00b_5929

    and h
    ld de, $6a62
    adc $06
    inc b
    add h
    cp e
    ld d, h
    ld [de], a
    jp nc, Jump_00b_5520

    db $e4
    add $83
    sbc b
    ld h, h
    add a
    ld [hl+], a
    ld b, d
    db $d3
    dec b
    sbc e
    jr nc, jr_00b_59b5

jr_00b_596f:
    sub l
    and e
    ld b, $de
    sub c
    add c
    sub h
    pop hl
    xor d
    dec h
    jp nz, $8e22

    xor e
    ld d, a
    adc [hl]
    jp z, Jump_00b_468f

    ld a, c
    xor [hl]
    sub a
    call nz, Call_000_0227
    ld [$4f5a], sp
    and h
    ld b, [hl]
    ld l, c
    add h
    ld d, $83
    ld [hl], b
    ret


    sbc l

jr_00b_5994:
    ld a, [hl+]
    sub c
    dec b
    ld hl, sp+$43
    add hl, hl
    and l
    rst $38
    add sp, $23
    db $e4
    ld c, h
    sbc e
    ld a, a
    cp $08
    db $e3
    inc b
    add hl, bc
    add d
    ld a, [de]
    rst $38
    rst $38
    or d
    ld b, h
    pop bc
    ld h, [hl]
    scf
    rst $18
    rst $38
    ld hl, sp+$28
    ld b, b

jr_00b_59b5:
    add a
    and [hl]
    ld d, e
    pop bc
    pop hl
    db $fc
    dec d
    ccf
    inc b
    ld l, c
    ld de, $f1e1
    rst $10
    add l
    jp hl


    db $db
    ld a, a
    rra
    ld h, b
    ld d, l
    cp [hl]
    ld h, l
    ld d, h
    ld d, l
    ld d, l
    ld c, [hl]
    xor d
    or b
    and [hl]
    inc c
    adc e
    ret nc

    ld a, a
    ld c, d
    ld d, e
    dec hl
    add c
    add c
    inc c
    ld e, h
    db $10
    cp l
    ld h, b
    ret nc

    ld a, b
    pop de
    add hl, bc
    db $eb
    ld l, d
    xor e
    jr jr_00b_596f

    ld hl, $9536
    rla
    ld d, h
    ld [hl+], a
    jr jr_00b_5a47

    or c
    adc l
    ld l, b
    db $76
    ld a, [de]
    adc b
    ld b, [hl]
    add d
    ld [hl+], a
    jr c, jr_00b_5a1b

    dec bc
    jr jr_00b_5994

    adc c
    db $e4
    and h
    adc $15
    ld c, b
    xor d
    ld h, d
    db $10
    ld hl, sp-$7c
    reti


    ld h, c
    pop bc
    ld b, $a1
    ld d, c
    jp nz, $8842

    ld c, l
    ld a, e
    ld [$791a], sp
    add d
    adc c

jr_00b_5a1b:
    ld d, d
    ld a, [de]
    ld [hl-], a
    cp [hl]
    push hl
    add hl, bc
    ld c, c
    xor h
    ld a, [de]
    ret c

    db $e3
    jp hl


    and l
    ld a, [bc]
    dec [hl]
    cp b
    jp c, $ed0a

    ld a, l

jr_00b_5a2f:
    ld b, $05
    ld b, $50
    ld b, d
    scf
    cp e
    xor e
    ld h, d
    db $10
    ld a, b
    jr c, jr_00b_5a52

    sub e
    add d
    ld l, l
    inc b
    db $10
    or h
    and [hl]
    ld a, [de]
    jr c, jr_00b_5a2f

    ld e, b

jr_00b_5a47:
    sbc b
    add [hl]
    dec sp
    xor d
    xor d
    and e
    db $d3
    sbc a
    ld a, $8a
    add hl, bc

jr_00b_5a52:
    call c, $cef2
    ld b, a
    ld b, $4a
    sbc h
    xor h
    rst $28
    xor $a8
    ld c, l
    db $fc
    ld [hl], c
    and b
    jp $ffc0


    ret nc

    ld h, e
    db $10
    adc [hl]
    ld l, l
    set 6, a
    db $f4
    ld b, a
    ld [bc], a
    ld d, l
    and [hl]
    cp b
    inc a
    db $fd

jr_00b_5a73:
    inc b
    adc [hl]
    rra
    and h
    pop hl
    ld a, [de]
    xor $2f

jr_00b_5a7b:
    ld [hl+], a
    adc $1f
    pop bc
    cpl
    and $fa
    pop af
    inc d
    db $d3
    jp z, $f94f

    xor e
    ld d, e
    ld h, b
    ld [$1fd2], a
    add sp, $3f
    and $a8
    db $f4
    cp $db
    ld a, b
    ld a, a
    jr z, jr_00b_5acd

    ld [hl], d
    sub $f8
    ld a, [hl]
    pop bc
    ld [hl], $18
    add hl, hl
    or e

jr_00b_5aa2:
    jp hl


    ld e, l
    ld [$e182], a
    adc d
    ld de, $0aba
    ret z

    and b
    sbc $14
    ld a, [c]
    sbc $70
    res 0, a
    ld a, $1e
    xor d
    inc d
    inc [hl]
    ld [hl], c
    pop hl
    db $ed
    ei
    ld a, a
    rst $00

jr_00b_5abf:
    ld e, h
    rla
    ld d, l
    ld d, d
    ld a, h
    ret c

    ld b, h

jr_00b_5ac6:
    cp l
    dec [hl]
    ld l, a
    cp l
    jr c, jr_00b_5aa2

    ret c

jr_00b_5acd:
    jr nz, jr_00b_5b20

    adc $2c
    jr nc, jr_00b_5a7b

    jr z, jr_00b_5aeb

    adc [hl]
    dec b
    ld l, e
    ld b, $b5
    jr c, jr_00b_5ac6

    xor $b6

jr_00b_5ade:
    ld b, [hl]
    jr jr_00b_5abf

    ldh [$85], a
    push hl
    rlca
    and h
    ld [c], a
    rst $18
    ld d, l
    dec c
    ret nc

jr_00b_5aeb:
    ld c, [hl]
    jr z, jr_00b_5a73

    and l
    ld a, [de]
    ld c, [hl]
    dec h
    ldh a, [rLYC]
    db $76
    adc [hl]
    inc h
    ld de, $856f
    adc $17
    jp nc, $a414

    jr c, jr_00b_5ade

    ld b, a
    ldh a, [$e5]
    ld h, d
    inc hl
    add d
    ld hl, sp+$6a
    xor d
    and e
    pop hl
    rst $20
    xor h
    adc d
    ld [hl], h
    ld hl, $7c38
    jp hl


    rst $00
    ld d, l
    ld d, l
    rst $28
    sbc h
    add sp, -$46
    or [hl]
    sbc h
    inc l
    adc e
    db $fc

jr_00b_5b20:
    rrca
    add [hl]
    ld [hl], c
    inc hl
    ldh a, [rVBK]
    ret nz

    and a
    ld [de], a
    sub $bf
    ld a, e
    rst $20
    ld e, $0f
    inc bc
    or a
    ld sp, hl
    push bc
    push af
    or a
    pop hl
    ld h, a
    inc h
    db $fd
    ld d, l
    ld l, b
    add hl, sp
    rst $00
    ret nz

    add d
    ld c, [hl]
    inc d
    ld [hl], b
    cp l

jr_00b_5b43:
    ld c, b
    inc [hl]
    db $10
    daa
    db $d3
    add b
    ld h, [hl]
    cp e
    rla
    rst $28
    rst $38
    ld d, e
    sub l
    ld d, l
    ld d, h
    and a
    and b
    add c
    db $fd
    ld a, e
    db $d3
    dec d
    ld a, [$befc]
    db $fd
    ld c, d
    ld b, d
    ld [hl+], a
    xor a
    ld l, l
    dec h
    jp hl


    add a
    add hl, de
    ld b, e
    inc b
    sbc d
    ld h, h
    ld d, b
    sub l
    db $fd
    ld l, l
    ld d, c
    and c
    ld b, c
    ld [$0a87], sp
    adc h
    ld h, b
    and d
    db $e4
    dec hl
    db $ed
    rla
    ldh [$6d], a
    ld l, e
    ld [hl], $4d
    ld [de], a
    ld e, a
    ld c, c
    ret nc

    ld d, d
    db $10
    or b
    ld d, l
    add hl, hl
    add hl, hl
    ld d, e
    rlca
    adc e
    ld b, l
    ld [hl], c
    add d
    sbc b
    push bc
    ld hl, $29a2
    ld b, c
    ld b, d
    jr jr_00b_5b43

    daa
    ld l, c
    inc b
    add h
    pop bc
    inc sp
    adc c
    ld d, d
    and $2d
    inc d
    ld d, d
    ld h, d
    inc de
    ld c, b
    cp b
    adc d
    ld a, [bc]
    dec bc
    add hl, hl
    ld h, d
    ld h, d
    sub e
    ld c, b
    jp nc, $1816

    jr z, jr_00b_5c0c

    and b
    ld c, d
    ld d, e
    inc h
    pop de
    ld [hl], d
    ld h, $8c
    ld a, l
    xor c
    ld b, d
    and l
    ld hl, $332b
    ld h, h
    ld d, c
    adc c
    ld d, h
    cp d
    sub h
    ld a, [hl+]
    dec h
    ld e, b

jr_00b_5bce:
    pop bc
    ld e, b
    inc d
    ld d, d
    sbc d
    push af
    ld d, l
    ld d, a
    ld a, [hl+]
    sbc a
    jr nc, jr_00b_5c2a

    xor b
    ld d, $15
    ld h, $42
    xor d
    xor a
    ld sp, $95cc
    ld e, d
    ld h, $14
    sub a
    sub l
    ld l, b
    rst $08
    di
    ld a, [de]
    and c
    ld l, b
    ld [de], a
    inc h
    ld h, b
    sub d
    sub d
    inc [hl]
    ld h, h
    jr jr_00b_5bce

    ld d, c
    add c
    dec h
    inc d
    ld h, h
    ld a, [hl]
    ld b, [hl]
    db $e4
    sub h
    reti


    ld b, l
    ld [$57c2], sp
    ld a, [hl+]
    ld b, [hl]
    ld [hl], h
    inc sp
    add d
    adc b

jr_00b_5c0c:
    and d
    db $10
    ld d, l
    ld h, $d5
    sub d
    dec [hl]
    jr c, jr_00b_5c82

    ld a, [de]
    daa
    ld d, b
    sub d
    ld a, [de]
    cp l
    jp nz, Jump_00b_6439

    ld l, l
    ld [hl+], a
    ld [hl], l
    sub c
    ld c, d
    xor b
    db $eb
    or d
    xor e
    di
    ld a, c
    ret c

jr_00b_5c2a:
    add [hl]
    add d
    ld c, h
    ld [hl], e
    and l
    and l
    inc h
    ld h, c
    ld h, h

jr_00b_5c33:
    inc h
    add $48
    ld c, e
    dec hl
    ld d, l
    ld e, h
    add hl, sp
    dec de
    db $ed
    and l
    ld b, d
    xor c
    add e
    call z, $a11f
    ld [bc], a
    ld e, l
    scf
    db $ed
    ld d, c
    dec d
    or d
    ld d, e
    pop hl
    pop bc
    db $fc
    rra
    rst $38
    dec d
    add l
    rst $38
    and [hl]
    ld [hl], b
    jp $3706


    adc a

jr_00b_5c5a:
    rst $38
    jr @+$66

    ld e, a
    add hl, de
    xor c
    add a
    rst $38
    ld e, d
    ld sp, hl
    adc [hl]
    add h
    ld [$0ca6], a
    add hl, bc
    jr z, jr_00b_5ca9

    ld [hl], b
    ld a, a
    sub e
    sub e
    add e
    db $fc
    ld c, l
    jr z, jr_00b_5c33

    db $e4
    rst $08
    inc c
    push af
    add l
    inc c
    ld b, [hl]
    inc de
    jp hl


    adc a
    adc a
    ld sp, hl
    inc [hl]

jr_00b_5c82:
    ld c, d
    cp [hl]
    jr nc, jr_00b_5cb7

    inc c
    inc de
    ret


    sub a
    adc a
    sbc c
    rst $38
    add h
    and c
    ld a, [bc]
    ldh a, [$cf]
    or d
    add hl, bc
    inc c
    ld hl, sp+$59
    add h
    add a
    ld b, h
    ld [hl+], a
    db $fd
    ld [bc], a
    sub c
    ld a, a
    xor $cf
    ld sp, hl
    and h
    jr c, jr_00b_5c5a

    add [hl]
    ld c, e
    inc a
    ld [hl-], a

jr_00b_5ca9:
    push de
    rst $38
    cp $71
    cp h
    ld d, e
    or c
    add l
    db $eb
    ld a, a
    rst $08
    and $28
    cpl

jr_00b_5cb7:
    di
    ld a, [hl-]
    jr nc, jr_00b_5d35

    sub a
    ld d, h
    dec e
    ld e, a
    ld b, [hl]
    ld [$213d], sp
    rlca
    cp $2d
    sub a
    db $fd
    inc b
    jp $d8a6


    xor e
    ld [hl], l
    pop hl
    db $eb
    ld de, $a844
    ld b, b
    rst $38
    sbc d
    cp a
    ld a, l
    add l
    pop hl
    pop hl
    ld l, b
    cp a
    or a
    xor l

Jump_00b_5cdf:
    cp $6f
    ld hl, $16f6
    add l
    and c
    ld l, b
    ld [hl], a
    db $ed
    ei
    ld d, c
    cp l
    ld hl, $168e
    ld b, e
    call nc, $d712
    or a
    jp hl


    call nz, Call_000_38a4

jr_00b_5cf8:
    ld e, b
    ld [hl], a
    ld l, d
    ld b, a
    inc bc
    jp hl


    rst $08
    ld [hl+], a
    pop hl
    adc h
    pop bc
    ld a, [$3c4c]
    ld [hl], e
    call nz, Call_000_10d9
    ld h, c
    ld a, [$d978]
    ld [hl], b
    ld [hl], c
    or b
    ld b, h
    add hl, sp
    inc d
    ld d, l
    ld d, e
    sbc c
    add [hl]
    add c
    ld c, [hl]
    ld h, [hl]
    ld [hl], b
    ld e, a
    and e
    sub c
    sbc [hl]
    dec d
    jr c, jr_00b_5cf8

    ld d, b
    cp e
    ld hl, $537c
    ld l, d
    rlca
    ld e, d
    ld l, [hl]
    push bc
    db $e3
    ld b, h
    rra
    db $f4
    ld h, h
    ld l, $18
    pop de

jr_00b_5d35:
    ld b, c
    inc b

jr_00b_5d37:
    ld sp, $6d70
    inc d
    db $db
    ld e, b
    adc b
    ld l, e
    xor $37
    sbc c
    cp h
    add $0f
    pop bc
    inc sp
    ld e, h
    ld d, b
    and l
    ld a, [de]
    ld a, d
    dec b
    adc h
    sbc l
    dec b
    sub c
    ld h, [hl]

jr_00b_5d52:
    xor d
    ld a, [bc]
    ld [$f7ce], sp
    ld h, c
    add l
    or b
    xor b
    jr jr_00b_5d37

    xor c
    ld d, l
    ld h, h
    dec de
    ld a, h
    add sp, -$58
    ld a, [c]
    rst $20
    and [hl]
    ldh [$bd], a
    ld h, a
    inc sp
    inc sp
    xor a
    add hl, sp
    add $cf
    dec b
    ld a, [hl+]
    and a
    ld a, [de]
    db $fc
    db $fd
    inc l
    add $ea
    dec d
    rlca
    xor a
    call z, $a8e6
    jp c, $f24d

    xor c
    cp h
    add d
    pop bc
    ld l, d
    rrca
    ld [bc], a
    ld c, $66
    add h
    jp hl


    db $76
    ld b, a
    add a
    sbc d
    ld e, e
    and [hl]
    ld a, h
    add a
    sbc d
    ld [c], a
    pop de
    ld l, [hl]
    ld b, e
    ld h, [hl]
    sub h
    call $9197
    add [hl]
    sbc h
    scf
    xor d
    adc [hl]
    ld d, $11
    db $d3
    inc b
    ld a, h
    ld e, b
    ld d, l
    ld a, $b5
    ld b, $94
    ldh a, [$79]
    ld a, d
    ld h, h
    add sp, $55
    ld e, l
    db $e4
    ld d, b
    ld b, e
    jr c, jr_00b_5d52

    ld c, $59
    ld a, [hl]
    db $eb
    jp $3742


    ld h, [hl]
    dec [hl]
    ld b, e
    ld b, $1b
    ld c, l
    dec e
    adc [hl]
    dec bc
    ld a, b
    ld [hl], b
    adc h
    db $d3
    sub l
    ld d, c
    db $fc
    pop de
    adc l
    call nc, $0d1b
    dec b
    inc b
    ret


    jr c, jr_00b_5e45

    ld b, d
    ld d, b
    rst $28
    adc [hl]
    ld b, h
    sub l
    rrca
    jp hl


    ld h, c
    ld b, c
    add hl, sp
    dec h
    and c
    sbc b
    ld a, e
    ld a, [hl+]
    ld [hl-], a
    sub d
    rst $10
    xor e
    ld [$7090], a
    ld e, [hl]
    adc l
    inc d
    xor h
    adc l
    xor b
    inc h
    inc l
    sbc h
    db $dd
    ld c, c
    xor [hl]
    ld [hl], a
    add a
    add e
    ld e, d
    jr c, @+$6e

    ld [de], a
    ld l, d
    add [hl]
    ld e, b
    ld [$0a83], a
    ld h, b
    ld a, [$0a3c]
    and e
    jp c, Jump_00b_5cdf

    rr [hl]
    ld a, [bc]
    ret z

    ld [hl], l
    and a
    ld b, d
    ld e, [hl]
    pop bc
    ld e, b
    or d
    ld [hl], c
    adc $1f
    ld a, [hl]
    add hl, de
    ld e, b
    ld a, h
    ld [hl], b
    or e
    ld d, c
    sbc [hl]
    dec de
    ld [hl], a
    dec de
    inc a
    ld [hl], b
    or e
    ld b, $b9
    sbc a
    inc e
    adc b
    inc hl
    sbc e
    ld [hl-], a
    add d
    add l
    ld a, [bc]
    sub b
    adc d
    ld a, [de]
    add d
    ld d, $65
    jp nz, $858a

    ld a, [bc]

jr_00b_5e45:
    add h
    ld [$2141], sp
    db $eb
    sbc d
    ld b, e
    and b
    xor l
    xor a
    jr c, jr_00b_5eb3

    or b
    ld e, l
    sbc c
    or [hl]
    or a
    db $e3
    rst $38
    db $fc
    dec a
    sub d
    and $5d
    rst $38
    ld d, e
    ld h, c
    rst $10
    jp nc, Jump_000_2d0d

    sbc h
    dec d
    ld [c], a
    xor d
    dec c
    ld l, b
    ld b, h
    or c
    pop bc
    db $fd
    ld a, a
    jp Jump_00b_4dfb


    ld c, c
    ret


    ld a, h
    or b
    ld b, c
    ld d, e
    dec e
    ld d, b
    ld h, e
    ei
    inc b
    sbc [hl]
    inc b
    ld c, h
    ld a, e
    jr nz, jr_00b_5ec7

    cp [hl]
    ld e, c
    ld d, e
    and l
    ld d, [hl]
    rst $38
    ld d, h
    ld [c], a
    ld l, h
    jr z, jr_00b_5eb8

    inc c
    inc sp
    add l
    and e
    pop bc
    ld e, e
    ld l, l
    ld a, [bc]
    add hl, sp
    rla
    push de
    ldh a, [$a3]
    sub c
    cp b
    add hl, de
    db $f4
    rst $20
    sub h
    rra
    ld l, b
    sub [hl]
    add hl, sp
    dec hl
    ld d, l
    dec b
    add c
    ld a, [hl-]
    cpl
    add l
    db $e3
    and d
    rst $10
    db $e3
    or d
    adc a
    adc d

jr_00b_5eb3:
    sbc a
    inc l
    add d
    ld a, b
    add hl, hl

jr_00b_5eb8:
    call z, Call_000_3986
    ld a, [de]
    pop de
    jp nz, $1886

    db $e4
    ld a, a
    sbc h
    ld e, b
    ld c, e
    rst $38
    rst $38

jr_00b_5ec7:
    rst $20
    inc d
    db $dd
    adc d
    xor e
    inc e
    ld [hl], e
    inc sp
    ld a, [bc]
    call c, $c909
    ld l, b
    ld [hl], c
    cpl
    sbc l
    ld l, b
    ld d, a
    dec e
    db $10
    ld b, a
    add l
    rra
    ld d, d
    ld h, [hl]
    cp b
    sbc a
    ld c, h
    rra
    ld d, e
    dec b
    ld a, [hl-]
    db $ed
    ld c, b
    db $f4
    dec hl
    ld c, c
    ei
    ld c, [hl]
    ld h, l
    ld [hl+], a
    ld a, c
    ld l, d
    dec h
    dec b
    ld h, e
    pop bc
    and [hl]

jr_00b_5ef7:
    add d
    and c
    adc b
    sbc [hl]
    ld d, h
    db $e4
    and e
    ld a, [de]
    ld d, d
    sub $d8
    adc b
    ld [c], a
    ld e, [hl]
    ld c, e
    ld d, h
    ld a, [hl+]
    ld d, a
    ld a, [$154e]
    rst $38
    ld l, b
    dec hl
    ld hl, sp-$77
    ld d, h
    pop de
    ld [hl-], a
    ld a, a
    ld [hl], l
    add $82
    ld d, a
    ld hl, $e448
    pop bc
    ld sp, $2878
    ld a, [hl+]
    ld l, b
    db $10
    cp a
    ld [hl+], a
    jr jr_00b_5f57

    sbc c
    ld b, $2e
    db $fd
    inc b
    xor d
    add hl, de
    ld h, $49
    ld c, h
    ld h, [hl]
    ld [hl+], a
    dec h

jr_00b_5f34:
    ld b, [hl]
    ld b, d
    or d
    ld h, d
    ld hl, $2a4c
    ld a, [de]
    sub h
    adc $d1
    sub d
    sub b
    cp $54
    ld [de], a
    ld e, d
    and b
    xor c
    ld c, l
    jr nz, @-$29

    ld l, b
    jp nz, $d4a0

    jp nz, $082a

    ld d, c
    cp [hl]
    ld [hl+], a
    or c
    ld d, c
    or h

jr_00b_5f57:
    ld h, b
    sub l
    push bc
    inc d
    ld de, $0866
    jp nz, Jump_00b_5418

    ld e, l
    dec de
    ld d, c
    xor d
    dec de
    ld b, l
    ld h, [hl]
    ld h, $a0
    or h

jr_00b_5f6b:
    adc e
    ld b, d
    call nc, Call_00b_653a
    ld h, l
    ld h, [hl]
    dec d
    ld e, d
    jr nc, jr_00b_5ef7

    ld a, [de]
    sbc c
    cp l
    jp nz, Jump_000_06de

    ld l, h
    jr jr_00b_5f34

    xor d
    sub l
    adc e
    and [hl]
    cp a
    ld e, h
    adc d
    rrca
    ld h, b
    adc c
    ld e, d
    jr c, jr_00b_5f34

    dec [hl]
    ld e, a

Jump_00b_5f8e:
    sub b
    or h
    ld e, c
    ld c, b
    ld h, e
    adc c
    ld a, [de]
    dec bc
    rst $38
    ldh a, [$60]
    rst $18
    ld d, d

jr_00b_5f9b:
    ld d, d
    sub h
    inc d

jr_00b_5f9e:
    adc d
    ld b, e
    adc b
    ld a, a
    rst $10
    rst $10
    sub h
    ld h, d
    jp nc, $9458

    ld d, h
    ld d, b
    ld c, h
    jp hl


    ld a, a
    ld l, l
    ld a, [hl+]
    dec b
    and c
    ld a, c
    inc e
    jr z, jr_00b_5f9b

    xor d
    xor e
    ld a, [$f821]
    jr nz, jr_00b_5fff

    ld hl, sp+$20
    adc a
    ld [bc], a
    rst $38
    and b
    or l
    ld h, [hl]
    dec e
    ldh [rNR52], a
    ld c, c
    call c, Call_00b_7298
    ld h, c
    dec e
    add hl, de
    ld c, e
    ld [bc], a
    ld e, d
    jr z, jr_00b_5f9e

    sbc h
    jp hl


    ld [$086c], sp

jr_00b_5fd9:
    xor c
    ld [$d252], sp
    add hl, bc
    ret


    cpl
    db $fc
    ld b, l
    dec l
    ld [bc], a
    ret nc

    jr nz, jr_00b_5f6b

    ld [hl], d
    ld hl, $195f
    ld d, h
    xor e
    inc b

jr_00b_5fee:
    ld [hl], c
    ld hl, $5528
    ld c, e
    ld c, c
    add $e6
    ld [hl], d
    dec e
    add hl, hl
    ld l, b
    or b
    ld hl, $09d6
    add e

jr_00b_5fff:
    sbc c
    ld [hl-], a
    ld de, $fb1d
    jr nc, jr_00b_5fd9

    ld [hl], $1d
    jp hl


    ld c, c
    jr nc, jr_00b_5fee

    jp hl


    ld [hl], d
    inc [hl]
    inc d
    sub b
    xor h
    ld [de], a
    or $8b
    inc de
    ld de, $82d7
    ld sp, $a612
    dec [hl]
    dec c
    ld a, [hl+]
    ld l, a
    inc hl
    db $10
    jp z, $29d1

    ld c, $29
    ld [hl-], a
    ld l, e
    db $10
    ld sp, hl
    sbc e
    ld d, b
    ld h, h
    dec h
    and c
    ld b, e
    inc h
    xor [hl]
    ld c, e
    ld [bc], a
    adc h
    sub [hl]
    adc d
    ret z

    ld d, l
    ld d, e
    call nz, $a1c4
    ld d, b
    xor b
    cp e
    ld b, h
    and c
    inc c
    ld [hl], $10
    ld hl, $d9c5
    ld [hl-], a
    jp c, $b016

    ld e, d
    ld e, $09
    inc c
    ld c, l
    ld b, [hl]
    ld l, d
    ld b, d
    or e
    ld a, d
    ld c, d
    db $10
    ld a, [hl+]
    dec de
    inc e
    or c

jr_00b_605d:
    ld d, $d7
    jp hl


jr_00b_6060:
    db $10
    cp l
    ld d, h
    ld h, [hl]
    or l
    ld c, d
    ld h, l

jr_00b_6067:
    ld d, d
    xor h
    ld b, d
    or a
    jp hl


    adc d
    ret nc

    jr z, jr_00b_605d

    add d
    db $e4
    or [hl]
    sbc b
    jp z, Jump_00b_7aa8

    ld b, e
    ld [bc], a
    jr c, @-$3d

    sub c
    sbc b
    ld d, h
    ld [de], a
    sbc b
    ld d, h
    ld b, l
    db $ec
    rrca
    rla
    ld [bc], a
    ld b, d
    ld l, h
    call nc, $a90a
    ld a, $18
    ld b, h
    jr nc, jr_00b_6060

    rst $00
    inc l
    ld e, [hl]
    ld b, h
    ld h, c
    ld hl, $0c13
    ld a, b
    ld e, b
    pop hl
    inc de
    xor h
    ld b, b
    ld b, h
    or e
    ld a, a
    ld d, d
    ld d, a
    db $f4
    inc de
    adc [hl]
    xor c
    cp l
    ld b, d
    di
    ld a, d
    ld d, [hl]
    rst $38
    add hl, hl
    ld [hl], $5b
    db $db
    ld l, l
    jp nc, Jump_00b_4c2d

    ld e, e
    add hl, bc
    ld e, [hl]
    daa
    inc b
    ld hl, $0b63
    ld e, h
    db $10
    ld d, a
    daa
    ld [$c694], sp
    sub b
    ld b, c
    ld b, [hl]
    adc b
    ld d, l
    ld d, d
    jr z, jr_00b_6067

    add a
    ld [hl], b
    ld e, d
    ld a, c
    ld b, c
    ld [$ab94], sp
    push bc
    dec bc
    ld e, e
    cp a
    ld sp, $baf8
    ld b, d
    ld h, b
    cp [hl]
    inc [hl]
    adc l
    dec h
    jr nc, jr_00b_612d

    ld b, l
    jr c, @+$2b

    ld d, b
    cp l
    ld h, $85
    adc $07
    add a
    sbc d
    push de
    add sp, -$20
    ld d, l
    ret c

    sbc d
    cp [hl]
    jr c, @+$6c

    dec a
    add hl, hl
    rst $20
    cp d
    sub h
    and a
    dec l
    ld d, l
    ld c, d
    add a
    and [hl]
    db $eb
    rst $10
    ld e, l
    xor b
    ld a, a
    ld h, $6f
    ld b, d
    or b
    ret nz

    add a
    ld sp, $a9a2
    ld d, d
    jr c, jr_00b_6134

    add [hl]
    ld d, $99
    ldh a, [rNR42]
    xor [hl]
    rst $38
    rst $38
    dec sp
    inc d
    and c
    adc e
    rst $38
    ld d, l
    ld d, a
    db $e3
    ld a, [hl]
    ld e, h
    ld e, $fc
    cp a
    rst $38
    and b
    ld hl, sp+$7e
    ld h, l

jr_00b_612d:
    ld a, b
    ld a, a
    pop de
    inc de
    cp $1f
    sbc d

jr_00b_6134:
    ret nz

    ret nc

    xor e
    db $e3
    ld c, l
    rst $20
    rra
    rst $38
    dec d
    ld b, a
    dec l
    rst $00
    rst $10
    add b
    ld d, l
    cp [hl]
    and c
    ld d, l
    ld d, h
    db $ec
    ld e, [hl]
    sbc $aa
    cp c
    jr c, @-$67

    rst $28
    cp a
    xor a
    ld c, d
    cp c
    rlca
    adc h
    ld [$f57f], a
    ld [hl], b
    ld d, h
    cp c
    ld [$d0da], sp
    ld [c], a
    ld l, a
    ld hl, sp-$43
    inc b
    ld d, e
    ld d, l
    add hl, hl
    ld d, l
    adc b
    and h
    adc e
    pop hl
    ld c, l
    and c
    ld h, b
    ld a, l
    dec h
    ld h, e
    and l
    ld b, c
    rst $38
    db $f4
    xor $aa
    and d
    ld a, [hl+]
    inc a
    dec b
    ld [hl], c
    ld d, h
    push bc
    di
    ld [hl], l
    ld a, [hl+]
    rst $38
    ld [c], a
    rst $38
    adc c
    ld c, l
    inc d
    inc d
    sbc d
    adc l
    ld e, b
    inc hl
    scf
    sbc b
    ld h, h
    ldh [$63], a
    ld [hl], l
    inc b
    sub h
    ldh [$c5], a
    call $ff6f
    push hl
    jr nc, @+$58

    add c
    add d
    db $e3
    ld l, d
    and b
    xor e
    rst $38
    push af
    ld e, d
    ld a, $5e
    ld a, l
    ld b, d
    ld e, d
    db $76
    or b
    call nz, $c930
    jp z, Jump_000_19a3

    ld h, l
    ld c, c
    ld de, $c3af
    inc e
    ld c, h
    sbc h
    ld de, $a54a
    add hl, hl
    db $10
    or b
    ld b, [hl]
    xor [hl]
    add d
    rst $38
    add $19
    inc sp
    pop hl
    dec de
    rst $38
    ret nz

    add d
    ld c, e
    push bc
    ld a, [hl]
    ld [hl], b
    or $42
    add hl, bc
    xor a
    and $f9
    jr nc, jr_00b_621c

    ld b, c
    jr @+$01

    sbc e
    jp hl


    db $10
    ld c, b
    jr nc, jr_00b_623a

    ld c, a
    ld b, c
    dec de
    ld e, [hl]
    ld e, d

jr_00b_61e6:
    add hl, bc
    ld [de], a
    ld b, h
    db $10
    ldh [$a6], a
    sub $9c
    ld l, h
    add [hl]
    ld l, h
    jp $0427


    ld a, [c]
    ld l, h
    add sp, -$46
    ld h, [hl]
    cp a
    pop af
    add hl, bc
    and h
    dec e
    ld h, c

jr_00b_61ff:
    ld c, d
    xor e
    rst $38
    db $f4
    db $76
    ld b, [hl]
    ld d, c
    di

jr_00b_6207:
    jr nz, jr_00b_624d

    cp [hl]
    ld d, c
    ld e, a
    db $fd
    jr c, jr_00b_61e6

    cp d
    adc d
    adc [hl]
    ld d, $aa
    ld a, [hl-]
    db $eb
    and e
    rst $20
    ld e, [hl]
    dec sp
    ld a, l
    ld d, e

jr_00b_621c:
    or [hl]
    ld d, b
    call nc, Call_000_39b6
    ld l, a
    ld a, [bc]
    xor d
    inc b
    rst $20
    xor d
    xor d
    adc a
    and [hl]
    sbc a
    inc [hl]
    and a
    ld [hl-], a
    ld h, l
    ld h, a
    rra
    and a
    rst $08
    and a
    sbc c
    sbc h
    xor c
    adc e
    rst $20
    ld c, d

jr_00b_623a:
    cp a
    ld sp, hl
    pop de
    dec c
    ld d, h
    ld a, [hl]

jr_00b_6240:
    inc c
    ld h, [hl]
    sub l
    ld d, e
    ld d, a
    ld sp, hl
    ld c, [hl]
    and a
    xor a
    ld d, e
    ld e, b
    ld h, h
    jp hl


jr_00b_624d:
    ld d, d
    db $10
    sub d
    ld [$6aa2], a
    xor c
    ld d, e
    dec h
    ld c, c
    ld d, d
    ret nc

    ld e, e
    jp c, $aaaa

    xor c
    ld e, [hl]
    ld d, d
    ld e, $8b
    ld d, c
    ret z

    db $db
    ld d, h
    ld [c], a
    sub [hl]
    ld b, l
    inc sp
    ld h, c

jr_00b_626b:
    and b
    ld h, a
    db $fd
    jr c, jr_00b_6240

    add [hl]
    dec l
    ld d, l
    jr jr_00b_61ff

    ld [hl+], a
    and e
    adc [hl]
    ld c, b
    adc b
    ld a, d
    ld [hl+], a
    add c
    dec b
    ld [hl], c
    ld d, h
    dec d
    jr c, jr_00b_62e5

    xor c
    jr nc, jr_00b_6207

    dec bc
    rst $38
    add l
    add hl, de
    jr c, jr_00b_62ae

    ld e, [hl]
    adc l
    ld l, d
    inc a
    or l
    rst $38
    ld d, e
    cp [hl]
    adc c
    ld h, b
    ld l, [hl]
    xor e
    and d
    ld e, b
    jp hl


    ld d, [hl]
    add d
    jr jr_00b_62f1

    ld a, [hl+]
    ld b, $3c
    inc c
    add h
    jr nc, jr_00b_626b

    inc a
    inc d
    sub [hl]
    add d
    ld [hl], l
    add d
    adc a
    dec b

jr_00b_62ae:
    xor b
    cpl
    ld d, l
    ld hl, sp-$1a
    adc h
    xor b
    ld a, [de]
    inc d
    ld a, [hl+]
    adc [hl]
    db $76
    ld hl, $822a
    dec h
    inc b
    jp hl


    ld h, l
    or b
    adc c
    and b
    adc b
    sub d
    dec h
    ld [$d584], sp
    ld a, [$5258]
    jr z, jr_00b_62f1

    dec d
    ld d, d
    ld h, h
    ld d, b
    ld c, h
    ld d, [hl]
    add c
    and d
    ld d, d
    inc d
    ld hl, $2265
    pop bc
    add l
    ld [hl+], a
    ld d, l
    xor b
    ld h, b
    adc e
    ld c, b
    ld d, b

jr_00b_62e5:
    jp c, $b978

    ld l, b
    db $dd
    dec l
    adc b
    ld d, d
    rla
    adc h
    dec l
    ld e, d

jr_00b_62f1:
    sub h
    jp nc, $a205

    rst $10
    add sp, -$1c
    xor c
    ld d, l
    ld e, d
    adc h
    or a
    ld [hl+], a
    xor c
    reti


    sub e
    ld [bc], a
    ld l, l
    ld c, c
    push de
    db $e3
    ldh [$a6], a
    ld [de], a
    xor b
    ld l, d
    xor e
    ld a, [bc]
    ld h, h
    sub a
    add a
    db $e3

Jump_00b_6311:
    adc d
    ld [de], a
    push de
    ld b, [hl]
    ld d, h
    inc c
    add hl, bc
    dec bc
    jr jr_00b_6393

    ld b, d
    xor b
    ld b, b
    and a
    inc h
    ld [$a6c0], sp
    ld l, a
    db $10
    jp $a249


    xor d
    adc h
    add d
    ld h, b

Jump_00b_632c:
    adc l
    add hl, hl
    ld [$09a9], sp
    add e
    ld b, l
    jp nc, Jump_00b_4510

    call nz, $82de
    ld [hl-], a
    ld b, d
    ld a, [bc]
    ld b, d
    ld l, e
    inc b
    db $10
    and $38
    jr z, jr_00b_638c

    xor h
    jr nc, jr_00b_6390

    pop bc
    inc b
    ld h, b
    sub b
    ld sp, hl
    ld d, h
    ld [hl], l
    ld b, c
    inc d
    ei
    or $28
    ld d, h
    xor c
    rst $18
    ld e, a
    dec bc
    ld hl, $24e5
    ld sp, $ead5
    ldh a, [rHDMA4]
    xor c
    jr z, jr_00b_63a7

    ld b, a
    ld d, l
    ld b, d
    add d
    add [hl]
    ld d, d
    ld e, d
    ld [hl], h
    ld l, b
    inc h
    ld hl, $4234
    ld h, d
    sbc l
    inc a
    ld c, e
    inc h
    ld sp, $999c
    add $5a
    inc l
    ld d, l
    ld b, [hl]
    ld a, [c]
    sub h
    jp z, Jump_00b_68e5

    jr nc, @+$29

    ld d, l
    ld e, a
    ld [hl], l
    dec d
    and b
    sub d
    push bc
    and a

jr_00b_638c:
    dec bc
    ld c, e
    db $10
    sub e

jr_00b_6390:
    and b
    adc e
    inc hl

jr_00b_6393:
    jr z, jr_00b_63d1

    ld [hl], b
    ld b, b
    push bc
    add hl, sp
    ld [$3048], sp
    add hl, sp
    ld e, h
    ld e, d
    ld h, l
    inc b
    ld e, e
    sub b
    jp $c6c0


    adc e

jr_00b_63a7:
    ld [hl], c
    sub d
    ld d, d
    ld de, $4f2c
    add hl, de
    ld d, l
    ld de, $a640
    dec e
    ret z

    ld b, l
    ld b, b
    add [hl]
    ld de, $0bc9
    ld d, l
    inc hl
    add hl, de
    nop
    ld b, h
    or c
    rst $28
    ld c, d
    or l
    dec d
    ld l, b
    push de
    add d
    push hl
    rla
    rrca
    xor d
    adc l
    xor d
    ld a, c
    add c
    and e
    sbc d

jr_00b_63d1:
    ld [hl+], a
    xor b
    ld [$8e88], a
    sub h
    adc h
    inc hl
    and l
    ld d, b
    xor e
    ld c, [hl]
    xor e
    adc [hl]
    push bc
    add hl, hl
    ld c, l
    inc de
    ld d, l
    ld hl, $4d35
    rst $28
    ld b, [hl]
    sub h
    and [hl]
    jr c, jr_00b_6445

    jp nz, $38aa

    ld e, b
    or a
    ld d, e
    adc l

jr_00b_63f4:
    adc d
    ld l, d
    ld a, [bc]
    ld e, d
    xor d
    inc sp
    xor d
    xor b
    adc d
    and e
    call z, $a9d9
    add d
    ld h, b
    and [hl]
    ret nc

    ld c, c
    ld a, b
    dec l
    ld b, a
    inc c
    add l
    jr z, jr_00b_6481

    ld [hl], h
    inc h
    jp hl


    db $dd
    inc c
    ld [hl], l
    ld b, d
    add e
    dec e
    ld [hl], d
    ld de, $e9eb
    ld c, $9d
    ld c, h
    ret


    db $db
    ld c, e
    dec e
    xor h
    ld b, d
    sbc l
    inc c
    dec hl
    rrca
    ld a, [$9aaa]
    ld [$ebc4], a
    ld b, a
    push bc
    nop
    ld d, l
    cp l
    ld a, [de]
    and l
    ld c, a
    ld a, [bc]
    ld [hl], l
    ld a, [de]
    ld c, a

Jump_00b_6439:
    ld b, $ed
    ld b, a
    sbc e
    ei
    db $d3
    and d
    ld l, [hl]
    add c
    ld b, $1b
    ld l, c

jr_00b_6445:
    db $fd
    ld hl, $944d
    xor b
    ld h, $23
    and c
    ld a, l
    db $e3
    and l
    ld b, d
    ld l, $81
    adc [hl]
    adc d
    ld [hl+], a
    jr nc, jr_00b_64b4

    inc d
    reti


    sub d
    dec de
    dec l
    ld a, [hl+]
    ld a, [$198e]
    add hl, hl
    ld b, $ad
    ld d, [hl]
    ld c, [hl]
    ld a, [hl+]
    ld [hl+], a
    ld a, [hl+]
    ld h, d
    jr z, jr_00b_63f4

    pop hl
    sbc b
    or l
    and c
    ld b, l
    ld b, l
    ld l, e
    dec [hl]
    xor b
    jp c, Jump_00b_51f8

    and e
    ld e, d
    adc e
    ld l, c
    inc hl
    ld d, [hl]
    and d
    sub e
    ld a, [hl-]

jr_00b_6481:
    adc d
    ld a, a
    xor c
    ld e, l
    xor l
    ld d, l
    add sp, -$3a
    add c
    ld d, $f8
    sbc d
    xor b
    add h
    ld [c], a
    ld e, l
    adc c
    ld d, l
    ld d, d
    sbc b
    sub [hl]
    inc [hl]
    xor b
    sbc e
    ld [$eaab], a
    dec d
    and e
    sub [hl]
    adc h
    xor d
    and e
    jp nc, $a49e

    add hl, hl
    ld [c], a
    ret nz

    adc h

jr_00b_64a9:
    sbc [hl]
    dec e
    add sp, $2f
    ld l, d
    pop bc
    dec e
    ld [hl], e
    ld [bc], a
    ld b, a
    ei

jr_00b_64b4:
    db $e3
    inc b
    ld d, d
    ld l, h
    jp nz, $e1ff

    ld a, c
    ld c, d
    sbc h
    xor e
    rst $38
    rst $28
    sbc c
    ld d, l
    sbc h
    rra
    db $fd
    ld e, a
    ld hl, sp+$6a
    ld a, [$46e1]
    push de
    ld sp, hl
    ld e, a
    rst $28
    rst $38
    ld a, [c]
    ld sp, $7abb
    adc e
    db $fc
    inc de
    sub $fb
    sbc e
    db $db
    ld a, a
    db $fd
    rla
    rlca
    ld a, a
    sbc e
    ld sp, hl
    jr c, jr_00b_6513

    adc [hl]
    ld a, [hl+]
    ld e, $c0
    add $97
    ld [de], a
    pop hl

jr_00b_64ed:
    rst $38
    cp a
    pop hl
    rst $38
    ld sp, hl
    xor a
    db $10
    pop af
    rla
    rst $38
    pop bc
    rst $38
    db $fc
    sbc d
    ld b, d
    pop de
    ld l, l
    ld e, e
    db $ed
    ld d, h
    ld [hl], b
    jr nc, jr_00b_64a9

    ld a, a
    rst $38
    rst $38
    ld a, [$d573]
    ld e, a
    rst $38
    db $fd
    inc e
    pop de
    sub a
    ld d, [hl]
    ld a, h
    ret nc

jr_00b_6513:
    ld b, h
    cp l
    add l
    ld c, [hl]
    ld [hl], l
    rst $38
    ld [$8df3], a
    add sp, -$37
    ld [hl], $bf
    push af
    ld d, l
    ld d, h
    adc h
    jp c, $f0d1

    rst $38
    dec b
    xor e
    jr c, jr_00b_655a

    ld d, $aa
    jp c, $e204

    add d
    inc sp
    and e
    sub c
    ld c, [hl]
    push de
    and h
    add [hl]
    dec b

Call_00b_653a:
    ld c, [hl]
    rla
    add c
    add d
    ld h, d
    add hl, hl
    scf
    ld a, b
    jr jr_00b_655e

    ld d, [hl]
    or l
    call $d69f
    ld [hl-], a
    xor b
    ld a, [$ec5d]
    jr nz, jr_00b_64ed

    add hl, sp
    db $10
    ld b, c
    daa
    ld d, h
    ld [hl], h
    dec h
    jp hl


    rst $08
    dec b

jr_00b_655a:
    dec h
    ld b, b
    and a
    inc e

jr_00b_655e:
    add e
    ld [hl], l
    ld c, h
    rra
    sbc h
    ld [hl], b

jr_00b_6564:
    and [hl]
    inc l
    ld [hl], d
    ld [hl], c
    call c, $38c6
    ld b, a
    inc e
    inc l
    sub b
    sub c
    ld h, a
    dec de
    ld de, $0f51
    inc e
    ld d, [hl]
    ld h, a
    inc b
    ld a, l
    jr z, jr_00b_65e2

    or e
    ld d, a
    rst $38
    rst $38
    ld d, h
    add l
    ld d, l
    ld d, e
    adc c
    ld a, a
    xor [hl]
    xor d
    xor d
    rst $38
    cp d
    xor d
    xor a
    ld d, d
    ld d, l
    ld l, $bf
    cp $aa
    sub l
    ld [hl+], a
    add hl, bc
    ld d, l
    ld d, d
    dec hl
    ld e, [hl]
    xor b
    call $55b5
    ld [hl+], a
    and l
    daa
    rst $38
    call nc, $8663
    xor d
    or [hl]
    dec b
    ld b, c
    ld h, c
    ld h, a
    jr jr_00b_65d2

    ld a, [de]
    ld c, l
    dec d
    dec hl
    cp $bd
    xor d
    ret nc

    sub l
    ld [hl+], a
    ret nc

    add d
    ld c, e
    ld a, [hl]
    db $fc
    ld e, [hl]
    ld [hl], $a3
    ld [$89a5], sp
    and b
    ld a, d
    dec d
    ld l, $8c
    inc d
    pop bc
    inc [hl]
    and b
    ld d, e
    add hl, sp
    ld d, c
    ld h, l
    ld [hl], h
    ld e, $48

jr_00b_65d2:
    ld h, h
    push bc
    ld c, b
    adc c
    and d
    ld h, a
    ld e, b
    xor b
    jr nz, jr_00b_6564

    ld h, b
    ld c, l
    db $ed
    inc sp
    xor a
    dec b

jr_00b_65e2:
    ld [hl+], a
    ld a, [hl+]
    dec l
    add hl, hl
    ld h, $82
    cp b
    or l
    db $db
    and e
    ld b, [hl]
    add hl, hl
    ld b, d
    sub h
    adc e
    dec bc
    push de
    cp $81
    adc l
    ld d, $25
    ld l, d
    adc l
    xor a
    ret z

    ld h, e
    ld a, [hl-]
    adc [hl]
    ld a, [de]
    daa
    xor a
    and c
    ld h, e
    ld b, $18
    jp z, $a18a

    adc d
    xor [hl]
    ld d, $2d
    ld h, [hl]
    ld h, e
    dec b
    ld [c], a
    ld d, e
    ld b, l
    and $29
    ld h, a
    add sp, $55
    ld e, a
    and d
    ld d, $a0
    and a
    xor a
    add sp, $35
    ld e, e
    jp c, $a8d5

    xor c
    dec b
    ld a, d
    and b
    ld [hl], l
    ld a, [bc]
    push af
    ld d, l
    ld a, a
    and h
    pop hl
    jp c, $d22e

    ld [$2eaa], a
    ld c, l
    and d
    sub a
    adc b
    cp l
    ld c, [hl]
    ld a, [hl+]
    ld d, l
    ld b, $91
    sub l
    ld a, [$af31]
    push de
    ld e, h
    push de
    ld [c], a
    ld l, d
    xor b
    ld [c], a
    push af
    adc h
    sub a
    db $e3
    cp d
    cp l
    ld d, l
    ld e, a
    add sp, -$19
    sbc c
    and e
    ld [bc], a
    xor d
    and l
    and l
    and a
    ld [de], a
    ld de, $8551
    ld e, d
    add hl, bc
    sub h
    add hl, bc
    pop bc
    dec de
    add hl, hl
    ld l, d
    ld b, d
    ld c, h
    sbc h
    ld c, d
    ld h, l
    ld a, a
    xor d
    or l
    ld l, [hl]
    ld [$83c0], sp
    sbc l
    rla
    push de
    ld sp, hl
    scf
    ldh [$84], a
    rra
    sbc d
    ld h, $99
    add l
    xor e
    rst $38
    or b
    ld [hl], a
    and l
    call nz, Call_000_2727
    ld a, a
    cp $19
    and h
    add hl, hl
    ld a, c
    ld [hl], c
    ld a, [hl+]
    rst $30
    rst $18
    ei
    sbc c
    add $49
    add hl, sp
    inc l
    dec d
    cp h
    ld b, l
    rst $38
    ld h, [hl]
    add hl, hl
    sbc [hl]
    ld h, e
    ld de, $53fe
    db $fc
    add $ae
    sub b
    ld a, [$f092]
    cpl
    ld a, [$fbbf]
    adc h
    ld l, b
    ld hl, sp+$3f
    rst $38
    ldh a, [$3f]
    dec b
    ld a, a
    rst $38
    adc $39
    ld d, a
    sub a
    ei
    call nc, $f143
    ld a, h
    ld d, $b4
    dec a
    sub l

jr_00b_66c4:
    jp hl


    ld [hl], a
    db $f4
    cpl
    push bc
    cp [hl]
    dec e
    inc d
    jp hl


    ld c, a
    jp hl


    ld [hl-], a
    ld e, e
    push bc
    cp l
    add a
    jp hl


    ld l, $11
    add a
    and $6c
    ld e, d
    ret nc

    ld c, a
    rst $38
    db $fd

jr_00b_66df:
    cp [hl]
    xor h
    add e
    cp $96
    push bc
    dec l
    ld [bc], a
    rst $38
    push af
    ld l, e
    rst $38
    pop de
    ld a, a
    and h
    ld l, $ab
    ld b, h
    dec l
    ld e, d
    or a
    rst $38
    push af
    or l
    sub b
    sbc h
    adc l
    rst $38
    rst $38
    ld [$95af], a
    and h
    ld c, d
    ld [hl], b
    ei
    ld e, a
    rst $38
    ld e, a
    cp $a3
    rla
    rlca
    ld a, [hl+]
    ld h, [hl]
    rst $38
    ld [$75a5], a
    ld e, c
    cp h
    dec a
    ld d, c
    cpl
    rst $38
    db $fc
    ld [hl], a
    jr nz, jr_00b_66c4

    rst $38
    rst $38
    ld h, c
    ld e, $0c
    dec e
    ld d, l
    adc h
    ld [hl], h
    add b
    ld b, h
    or e
    ld d, a
    rst $38
    db $fd
    ld d, h
    db $dd
    ld a, [$49d5]
    xor d
    db $d3
    scf
    rst $18
    ld [$4baf], a
    and e
    ld a, $8c
    db $ec
    cp b
    push bc
    ld c, [hl]
    rst $10
    adc d
    ld e, a
    db $fc
    add sp, $7a
    ld [hl-], a
    ld d, h
    ld d, $34
    and e
    rlca
    ld a, [$31ad]
    or h
    ld d, h
    and a
    adc h
    and e
    dec hl
    ld e, [hl]
    xor a
    jr nc, jr_00b_66df

    adc h
    ld l, [hl]
    ld c, b
    ld h, b
    ld h, l
    ld [$d664], sp
    ret nc

    and a
    cp b
    add h
    and l
    dec [hl]
    cp c
    ld b, c
    ld a, [c]
    ld a, [hl+]
    ld b, l
    cp h
    sub $5c
    ld hl, $6862
    push hl
    xor d
    dec a
    add hl, de
    db $e4
    and a
    inc b
    sbc d
    or h
    ld [hl], c
    ld c, c
    ldh [$67], a
    ld a, a
    sbc l
    xor a
    and $09
    ld c, c
    sbc d
    dec d
    cp $61
    and h
    ld l, h
    add d
    ld c, d
    sub a
    ld b, [hl]
    ld [hl], $0d
    xor $c2
    ld sp, hl
    rst $00
    ld a, [hl-]
    sub e
    rst $38
    push hl
    and [hl]
    ld c, [hl]
    call nc, Call_00b_7f3b
    ld hl, sp-$60
    and $76
    db $10
    xor e
    ldh a, [$de]
    dec d
    and $93
    ccf
    ldh a, [$27]
    ld b, h
    jr z, @-$4d

    ld a, [c]
    nop
    ld h, [hl]
    or l
    ld d, e
    ld d, a
    adc a
    ld bc, $4bfd
    ld a, c
    ld c, a
    dec b
    ld b, d
    cp l
    rlca
    adc d
    ld d, h
    pop de
    ld hl, sp-$2b
    ld b, d
    ld e, a
    db $fd
    dec d
    ei
    ld c, e
    ld d, a
    call z, $f8d5
    dec d
    ld [hl+], a
    dec bc
    rrca
    ret z

    ld b, c
    ld d, a
    ld a, [$2986]
    ld a, [hl]
    and b
    xor b
    add [hl]
    ld l, $bd
    adc e
    ld d, l
    dec b
    rst $38
    add e
    ld e, a
    ei
    adc b
    ld d, e
    ld a, d
    xor c
    ld d, l
    xor b
    pop de
    db $e4
    ld e, b
    xor b
    or h
    ret


    ld a, [hl]
    inc [hl]
    ld a, l
    ret


    call $8210
    ld e, a
    ld [$de36], a
    xor b
    ld d, l
    adc b
    ld b, l
    ld h, [hl]
    ld e, $88
    and e
    adc [hl]
    adc h
    sbc a
    jp c, Jump_000_3a16

    xor b
    ld e, d
    ld d, l
    adc c
    ld h, d
    push de
    ld e, d
    jr c, jr_00b_6877

    jr jr_00b_6873

    ld h, l
    and c
    add [hl]
    ld h, d

Jump_00b_6815:
    db $e4
    ld d, h
    adc $82
    ld d, $8c
    ld h, h
    ld h, e
    ld d, a
    xor b
    add $99
    ld [hl], b
    and e
    ld h, $18
    jp nc, $a034

    ld [hl], b
    ld d, l
    ld [hl+], a
    inc b
    ld d, h
    dec l
    add hl, bc
    dec h
    ld d, c
    ld l, e
    adc e
    and b
    ld [hl], b
    ld d, b
    add l
    ld hl, sp-$3a
    ret nc

    ld b, [hl]
    ld [hl+], a
    ld a, [bc]
    adc h
    add hl, hl
    pop hl
    ld c, c
    ld a, b
    sbc d
    ld l, $d1
    ld c, h
    ld e, a
    jp nc, $8838

    add a
    adc b
    ld d, l
    ld [hl+], a
    ld c, c
    ld c, b
    sub c
    cp a
    adc e
    adc h
    ld e, $21
    ldh [$88], a
    ld b, c
    ld c, c
    ld b, l
    ld d, h
    pop bc
    ld c, h
    ld e, [hl]
    dec b
    add sp, -$7c
    ld d, b
    add d
    jp nc, $9961

    ld d, a
    db $e3
    rlca
    sub a
    xor d
    rla
    ld h, $26
    ret nc

    and d
    ld l, d
    and e

jr_00b_6873:
    dec hl
    ld a, [$7e1a]

jr_00b_6877:
    ld [hl+], a
    adc h
    dec l
    and e
    adc d
    adc d
    cp [hl]
    ld h, $e3
    dec sp
    db $e3
    ld l, c
    ldh a, [rNR10]
    ld h, $4c
    ld a, b
    pop af
    reti


    ld a, [de]
    and l
    inc l
    sub b
    add $a8
    ret nz

    sbc c
    inc hl
    ld a, [bc]
    cp b
    db $e4
    ld d, d
    sub b
    push bc
    ld l, e
    and [hl]
    ld c, b
    ld b, h
    and c
    inc bc
    rst $28
    sub d
    xor h
    jp $ff57


    ldh [$91], a
    ld a, [de]
    ccf
    ld [hl], a
    add sp, $3f
    pop hl
    add a
    sbc b
    and a
    rra
    jr nc, @+$01

    add a
    db $fc
    rst $28
    ld [c], a
    or [hl]
    ld de, $92c7
    rst $38
    add a
    ld c, a
    cp a
    ld c, d
    rst $00
    inc b
    ld e, [hl]
    xor a
    rst $38
    ld [bc], a

jr_00b_68c6:
    cp $d3
    ld d, b
    rst $20
    inc h
    ld b, l
    rst $38
    rst $38
    db $fc
    ld [$933e], sp
    sbc h
    ld [hl], b
    xor b
    ccf
    rst $18
    db $d3
    add [hl]
    rst $38
    ld de, $1427
    rrca
    inc bc
    add a
    sub e
    ld [hl], l
    add a
    rst $28
    sub b

Jump_00b_68e5:
    sbc h
    jr nc, jr_00b_6918

    ld a, $3c
    ld d, d
    adc [hl]

jr_00b_68ec:
    dec d
    inc d
    add $f0
    ld c, a
    reti


    ld a, [de]
    ld d, h
    jp $fa87


    add e
    ld a, d

Jump_00b_68f9:
    ld h, a
    dec b
    call nc, Call_000_0819
    and e
    ld a, [hl]
    adc h
    rst $18
    ldh a, [$5f]
    ld b, [hl]
    jr nc, jr_00b_6938

    adc h
    rrca
    dec bc
    rst $38
    sub b
    rst $18
    xor [hl]
    ld l, c
    ld sp, $5f0c
    db $e3
    ld a, a
    push hl
    ccf
    cp $9d

jr_00b_6918:
    ld e, a
    add e
    cp $5d
    rst $38
    cp $9d
    ld a, a
    ld a, [$4361]
    ld a, a

jr_00b_6924:
    and b
    and a
    dec a
    ld a, [$9562]
    push de
    add h
    ld [hl], l
    ld h, $69
    ld [c], a
    ld h, $a9
    add sp, -$5a
    ret nz

    ld b, h
    jr c, jr_00b_68ec

jr_00b_6938:
    ld [hl], a
    push af
    jr nc, jr_00b_698f

    ld c, b
    ld [de], a
    dec d
    ld a, [bc]
    ld [hl-], a

jr_00b_6941:
    add l
    jr nc, jr_00b_68c6

    ld c, d
    sub h
    jp nz, $0919

    daa
    inc hl
    rlca
    or b
    ld [hl], e
    dec de
    ld b, e
    inc d
    add hl, de
    daa
    add d
    jr jr_00b_6924

    ld sp, hl
    ld e, [hl]
    push af
    push de
    adc [hl]
    ld d, $41
    and d
    and c
    adc $24
    ld e, d
    ld c, [hl]
    ld a, e
    ld d, b
    sub c
    ld c, h
    add hl, hl
    ld c, h
    dec d
    ld l, a
    ld c, b
    and e
    ld e, d
    ld a, [hl+]
    ld [hl], c
    add d
    inc c
    db $d3
    xor e
    adc h
    dec hl
    inc c

jr_00b_6977:
    cp l
    ld hl, $4216
    inc [hl]
    and l
    ld d, a
    ld [$fcc3], sp
    db $e3
    xor b
    add l
    ld h, c
    xor b
    push hl
    xor d
    inc a
    db $dd
    jp nz, $799c

    xor h
    add hl, bc

jr_00b_698f:
    ld c, c
    and h
    and c
    and l
    jr c, jr_00b_6977

    or $a6
    inc e
    jr @-$19

    ld h, h
    ld c, a
    ld [bc], a
    inc d
    ld h, e
    and c
    ld b, c

jr_00b_69a1:
    ld h, d
    db $e4
    jp $1955


    ld a, d
    ld b, d
    jp $b242


    sbc e
    ld c, h
    sbc d
    and a
    inc c
    ld b, e
    ld c, c
    add l
    ld a, d
    sbc e
    jr nz, jr_00b_6941

    ld h, c
    ld c, e
    ld b, [hl]
    cp [hl]
    dec c
    jr @+$26

    pop de
    add a
    jp z, $19e1

    ld h, b
    add d
    and [hl]
    ccf
    ld a, [hl+]
    xor h
    sub e
    jp $677a


    ld b, $38
    ld b, e
    inc d
    db $e3
    inc b
    ld [hl], b
    call nz, $844a
    ld a, h
    ld e, b
    ld h, [hl]
    and c
    ld d, l
    ld d, l
    ld c, a
    dec d
    cp a
    ld a, [$a4ab]
    add l
    ld d, c
    ld d, e
    ld h, a
    ld [c], a
    rra
    and l
    ld l, c
    ld e, b
    adc d
    xor e
    db $f4
    dec l
    inc sp
    ld d, d

jr_00b_69f2:
    db $e4
    inc h
    adc c
    ld [hl-], a
    adc h
    db $10
    ld hl, sp+$1a
    sub [hl]
    add hl, bc
    ld d, e
    ld a, [de]
    ld d, [hl]
    ld a, [hl+]
    sub d
    jr z, jr_00b_69a1

    inc d
    call Call_00b_5230
    and d
    jr @+$17

    ld c, b
    ld e, b
    push de
    ld l, b
    inc d
    jp nz, $9894

    ld h, h
    ld d, b
    db $76
    ld [c], a
    inc h
    add l
    adc b
    ld a, d
    adc b
    and d
    xor b
    ld d, d
    jr nz, jr_00b_6a66

    dec b
    dec l
    jp nz, Jump_00b_6815

    push bc
    ld d, b
    ld d, [hl]
    ld hl, $8806
    ld a, e
    ld d, b
    ld e, c
    xor a
    ld [$f08c], a
    sub l
    ld c, c
    xor c
    ld [hl], d
    xor e
    scf
    ld e, [hl]
    daa
    and l
    ld d, h
    and h
    and l
    ld a, [hl+]
    jp nc, $8b54

    and e
    inc h
    pop bc
    add d
    ld c, c
    ld c, c
    ld a, b
    ld d, [hl]
    ld h, e
    ld [hl], a
    ld c, d
    ld h, d
    ld d, d
    ld a, [de]
    cp l
    ld d, $43
    ld hl, $04e3
    ld h, b
    ld b, l
    ld h, e
    dec c
    add l
    adc d
    and c
    cp a
    adc h
    ld d, l
    ld b, $58
    add $25
    add hl, sp
    ld e, [hl]

jr_00b_6a66:
    jr nc, jr_00b_69f2

    ld d, l
    ld [hl], a
    ld a, [hl+]
    ld sp, $5542
    ld e, d
    ld sp, $fe7f
    xor d
    and l
    add c

jr_00b_6a75:
    sbc b
    sbc a
    call z, $abf4
    ld e, a
    db $eb
    ret z

    sub l
    sub l
    ld b, $2e
    ld c, h
    ld h, [hl]
    dec de
    ld b, d
    sbc a
    and e
    add hl, bc
    pop bc
    inc b
    inc d
    pop bc
    ld a, [hl+]
    and l
    ld h, $83
    ld h, l
    ld c, d
    ld e, d
    ld [$3195], sp
    ld d, c
    rst $10
    xor b
    sbc e
    ld e, c
    ld e, d
    xor b
    push bc
    inc c
    jp nc, Jump_000_33aa

    xor l
    ld a, [de]
    and l
    ld d, l
    xor b
    ld l, a
    push de
    ld d, l
    dec d
    ld d, l
    ld d, e
    dec hl
    push af
    ld c, h
    push de
    or $b6
    adc b
    xor d
    and e
    ld a, d
    cp a
    rst $38
    cp $a2
    sub l
    ld e, [hl]
    ld sp, $98ca
    xor c
    pop hl
    or d
    rst $38
    ld c, d
    ret nz

    call nz, $a228
    sbc h
    dec c
    sub c
    set 4, c
    ld c, d
    db $10
    jr c, jr_00b_6a75

    ld l, h
    ret nz

    sbc d
    push bc
    call nc, Call_00b_55c9
    pop bc

jr_00b_6ada:
    ld b, l
    ld hl, $6150
    adc d
    and d
    jp nz, $c3e4

    ld e, [hl]
    ld a, [bc]
    ld [de], a
    push hl
    push bc
    ld b, l
    ld e, a
    ld b, d
    add h
    ld h, c
    ld c, d
    inc [hl]
    inc de
    inc bc
    ret


    inc l
    ld d, d
    inc c
    ld b, e
    cp l
    ld [bc], a
    ld c, d
    xor b
    ld d, d
    and h
    ld d, h
    ld d, l
    xor h
    jr z, jr_00b_6b2b

    dec de
    push bc
    ld e, c
    ld c, $32
    ld b, d
    adc e
    inc bc
    ld de, $d172
    dec de
    ld b, b
    adc e
    jr jr_00b_6ada

    ld [de], a
    add e
    dec c
    jr @+$22

    adc e

jr_00b_6b17:
    add h
    inc de
    dec b
    ld a, [bc]
    ld a, [bc]
    ld c, h
    xor a
    pop de
    ld de, $a408
    call c, $8219
    or d
    ret nz

    sub e
    ld l, b
    inc l
    sub c

jr_00b_6b2b:
    ld de, $c944
    db $10
    ld h, h
    ld a, $83
    db $fd
    dec d
    ld [bc], a
    ld e, $4c
    and c
    inc de
    ld de, $c420
    ld e, l
    and d
    sbc c
    pop bc
    add h
    inc l
    add d
    adc d
    db $10

jr_00b_6b45:
    rst $38
    call nz, $f330
    pop de
    sub a
    ld h, c
    inc l
    add hl, bc
    inc l
    rrca
    jr jr_00b_6b17

    add $57
    inc b
    ldh a, [$b0]
    inc a
    dec bc
    ld b, [hl]
    ret


    sub h
    ld b, h
    db $10
    ld d, b
    or b
    inc a
    inc c
    add a
    add hl, de
    call z, $4c0a
    push bc
    and c
    call nc, Call_00b_443a
    push de

Jump_00b_6b6d:
    ld b, [hl]
    ld a, d
    ld b, l
    ld d, c
    ld a, [bc]
    jr z, @+$81

    ld h, d
    add e
    sub c
    pop hl
    or [hl]
    ld h, a
    ld l, c
    ld c, e
    ldh a, [$c1]
    ld l, d
    ld c, $84
    ld h, c
    ldh [$c6], a
    sub d
    pop hl
    ld h, c
    ld [bc], a
    ld d, a
    ld l, b
    ld b, b
    and h
    cpl
    rst $28
    and [hl]
    or e
    jp nz, $968d

    ret z

    ld b, d
    xor b
    rst $10
    add h
    ld [hl], b
    call nc, $9409
    inc [hl]
    and [hl]
    db $eb
    jr nz, jr_00b_6b45

    inc h
    ld a, [hl+]
    or $67
    add a
    jp c, $abaa

    ld h, b
    ret nz

    pop hl
    ld d, d
    ld sp, hl
    ld d, c
    cp h
    ld d, $63
    and c
    ld b, h
    rst $28
    ld d, h
    ld h, d
    ld b, h
    or c
    ld d, l
    ld d, e
    ld b, l
    adc h
    ld e, d
    adc e
    sub c
    ld d, l
    ld e, l
    ld h, e
    ld a, [de]
    ld c, d
    ld d, l
    ldh [$e9], a
    add hl, bc
    ld h, e
    ld c, h
    inc d
    inc h
    adc b
    ld h, l
    ld e, b
    pop de
    cp l
    ld a, h
    dec hl
    pop de
    and d
    inc sp
    dec h
    ld d, l
    ld d, h
    jr z, @-$75

    ld e, [hl]
    adc h
    ld e, [hl]
    add hl, hl
    ld a, b
    add $0a
    ld c, h
    ld d, l
    ld e, d
    ld [$a516], sp
    add c
    add hl, sp
    ld a, [de]
    add hl, sp
    and d
    ld e, e
    adc l
    ld [hl], h
    inc h
    jp nz, $6341

    ld b, [hl]
    rra
    ld c, h
    ld hl, sp-$2a
    dec de

jr_00b_6bfb:
    adc l
    ld h, l
    ld c, h
    and e
    sbc [hl]
    xor d
    xor d
    ld a, $3e
    ld h, b
    and h
    xor c
    and e
    jr jr_00b_6bfb

    adc l
    and b
    sub b
    ld a, [$9509]
    and h
    and h
    ld b, c
    ld [$1add], a
    ldh a, [$d6]
    cp $d5
    or b
    add hl, sp
    sbc d
    xor a
    add sp, $4f
    pop hl
    db $10
    and $71
    ld c, d
    rst $38
    cp $bb
    add hl, sp
    ld l, c
    ld a, [bc]
    rst $38
    rst $38
    rst $38
    add a
    ei
    jr jr_00b_6cb1

    db $f4
    rra
    push af
    ld a, [hl]
    and c

jr_00b_6c37:
    ld a, [hl]
    ld e, e
    pop de
    rrca
    ld b, l
    cp $4f
    sbc b
    inc h
    ld [hl], a
    add hl, de
    ld [hl], e
    and c
    add hl, de
    ld c, [hl]
    add $6c
    dec c
    ld d, c
    sbc e
    ld a, [de]
    jr nc, @-$38

    db $f4
    ld a, [bc]
    ld h, b
    rst $00
    rst $10
    nop
    ld d, l
    cp [hl]
    ld bc, $4e7e
    ld d, l
    ld e, d
    ld c, c
    ld a, [hl]
    ret c

    db $e3
    ld e, e
    or b
    ld l, b
    inc d
    jr z, jr_00b_6c7d

    and l
    dec l
    ld d, c
    ld e, e
    sub $2a
    jr jr_00b_6c7d

    adc e
    ld e, d
    ld d, b
    and c
    ld a, a
    ld d, a
    ld b, d
    adc h
    xor c
    inc b
    inc h
    ld h, h
    ld h, b
    ld c, b
    cp $fb

jr_00b_6c7d:
    adc l
    ret nc

    adc l
    ld e, c
    ld l, [hl]
    push hl
    ld d, d

jr_00b_6c84:
    ld [de], a
    ldh [$82], a
    inc b
    pop bc
    ld h, b
    and b
    adc b
    and d
    sub d
    db $d3
    ld h, $21
    ld [hl+], a
    pop de
    ld b, c
    ld a, h
    ld d, d
    db $ec
    jp nz, $a48b

    ld d, b
    ret z

    xor d
    ld c, h
    ldh [$82], a
    ld [hl-], a
    ld c, d
    ld b, d
    ld c, b
    ld d, e
    inc b
    cp [hl]
    ld d, b
    ld h, e
    ld c, c
    ld a, [bc]
    add c
    xor h
    jr nc, jr_00b_6c37

    adc e
    ld d, b

jr_00b_6cb1:
    ld b, [hl]
    or l
    ld l, $94
    sbc h
    adc c
    ld h, d
    sbc [hl]
    ld h, b
    ld h, e
    sub d
    rlca
    or h
    cp e
    jp c, $9538

    rra
    cp $2a
    ld a, [hl-]
    ld h, [hl]
    add d
    ld [$ecb8], sp
    and l
    ld c, d
    ld h, e
    jp nz, $8faa

    ld l, e
    ld a, h
    ld [de], a
    ret


    jp z, $a590

    call Call_000_1102
    rst $00
    add h
    jr nc, jr_00b_6c84

    ld b, d
    xor c
    add hl, bc
    ld l, c
    jr z, @-$35

    ld a, [de]
    call nz, Call_00b_7068
    ld hl, $03fd
    ld [bc], a
    inc a
    ld b, h
    dec e
    rrca
    add hl, de
    rst $18
    ld h, c
    dec d
    inc bc
    inc d
    add [hl]
    ld b, e
    inc c
    ld h, e
    ld [bc], a
    db $10
    ld b, [hl]
    ld l, b
    or b
    dec sp
    xor d
    ld sp, $11a4
    add l
    ld b, e
    pop bc
    ld d, h
    cpl
    ld de, $8204
    ld sp, $a0c8
    call z, $c008
    adc d
    ld b, d
    ld [$1446], sp
    and h
    push hl
    ld d, b
    ld [hl-], a
    adc [hl]
    sub h
    xor c
    sub d
    ld d, [hl]
    sbc b
    ld a, h
    or e
    sub h
    and b
    sub $1f
    ld d, c
    add h
    ld [$2ab0], sp
    jr c, @+$67

    ld b, h
    inc h
    ld h, d
    add $10
    ld sp, $988b
    or b
    ld hl, $1247
    dec hl
    ld d, [hl]
    ld d, d
    inc d
    add h
    ld [hl], c
    ld a, c
    ld de, $1d97
    ld d, b
    ld h, $5c
    db $76
    ld b, b
    ret nc

    ld a, [hl+]
    pop de
    pop hl
    ld b, a
    cp h
    ld b, h
    cp l
    dec h
    xor c
    ld a, [hl-]
    ld e, b
    cp c
    add hl, sp
    xor e
    add hl, de
    ret z

    ld c, [hl]
    dec h
    add d
    ld hl, $54f2
    push de
    ld h, [hl]
    and h
    sbc b
    add hl, de
    ld [hl], $64
    inc [hl]
    jp z, $d514

    ld a, l
    jp Jump_000_2a06


    ld d, e
    ld a, d
    inc b
    ld l, b
    add sp, -$6a
    dec sp
    db $e4
    push de
    sub e
    adc d
    ld e, h
    and [hl]
    ld d, [hl]
    add hl, sp
    ld l, d
    ld e, b
    adc c
    ld c, a
    ld b, $94
    ld hl, sp+$5d
    ld [$752a], a
    or h
    ld b, h
    sbc l
    ld [$4a6c], sp
    ld [hl], d
    xor a
    ld hl, $ed9c
    sub c
    ld c, b
    ld c, d
    add l
    ld b, [hl]
    rlc [hl]
    ld d, h
    ld [de], a
    sbc h
    ld d, e
    and [hl]
    ld de, $c6cd
    ld sp, $84c7
    ld e, d
    ld [hl], h
    and d
    and d
    call $fae8
    ld l, a
    ld e, b
    ld b, l
    or c
    ld sp, $45c9
    ld d, d
    sbc [hl]
    dec c
    rra
    ld a, [bc]
    ld d, l
    or a
    ld d, l
    rst $38

Call_00b_6dbe:
    push de
    add hl, sp
    push de
    rst $38
    rst $38
    rst $38
    cp $ce
    scf
    rst $38
    ld a, [$ada2]
    adc [hl]
    daa
    ld [c], a
    ccf
    rst $38
    ld d, d
    inc d
    db $e4
    ld e, a
    xor e
    ld c, d
    xor a
    adc $7f
    cp l
    ld a, [bc]
    ld sp, $99a3
    ld a, [bc]
    cp c
    ld a, [bc]
    ld d, h
    ld d, h
    add sp, -$70
    ret nc

    ld d, b
    ldh [$bc], a
    db $ec
    ret z

    pop af
    adc c
    and l
    ld d, l
    ld d, h
    db $dd
    add c
    ld a, [de]
    rrca
    ld c, b
    ld c, c
    rst $38
    ei
    rst $38
    jp nc, Jump_000_3aa4

    add hl, hl
    ld d, $17
    xor d
    xor d
    rst $38
    ld hl, sp-$59
    ld l, h
    rla
    ld e, a
    rst $10
    ld e, e
    ld c, [hl]
    ld b, l
    jp hl


Jump_00b_6e0c:
    and e
    dec hl
    ld l, l
    ld [hl], $bf
    and [hl]
    add c
    dec [hl]
    or [hl]
    db $d3
    ld c, d
    ld a, [bc]
    ld d, e
    ld d, l
    ld h, $db
    ld c, h
    push de
    dec de
    di
    adc d
    db $db
    ld c, h
    xor a
    ld b, [hl]
    cp a
    ld d, l
    ld d, h
    inc de
    dec bc
    ld l, b
    adc $ff
    pop de
    xor d
    xor d
    inc sp
    cp a
    ld c, h
    db $eb
    ld a, [$a594]
    inc sp
    cp a
    ld c, l
    ld l, d
    ld d, a
    ld [$5382], a
    dec hl
    or [hl]
    jp hl


    sbc d
    db $76
    ld [$4bd5], a
    add [hl]
    ld [hl], d
    xor e
    ld a, [$31a6]
    jp z, Jump_00b_55c4

    ld d, b
    ld a, d
    and c
    inc e
    push de
    ld c, c
    sub l
    ld e, c
    reti


    ld h, $4c
    ld [hl], e
    jp hl


    ld a, [hl+]
    and b
    sub e
    sbc l
    ld [hl], $8c
    adc a
    rst $08
    sbc l
    ld l, h
    adc [hl]
    ld sp, $6410
    and h
    ld h, $ef
    and b
    add h
    ld b, h
    or b
    rst $38
    and h
    ld d, c

jr_00b_6e75:
    ld e, c
    ld a, a
    dec l
    ld b, d
    jp nz, $98b4

    reti


    add hl, sp
    add l
    inc de
    ret nc

    ld a, b
    ld c, e
    ld e, d
    ld [hl], h
    inc l
    ld h, l
    ld de, $bb69
    add [hl]
    inc c
    ld [hl], c
    jp c, Jump_00b_7d6b

    ld l, c
    xor h
    sub a
    ld l, c
    and [hl]
    ld [$aadf], sp
    ld h, c
    jr jr_00b_6e75

    ld l, e
    inc h
    push de
    rst $38
    db $fc
    ld h, a
    ld l, c
    xor a
    add hl, hl
    pop de
    ld a, [de]
    pop bc
    add [hl]
    and [hl]
    add hl, hl
    db $db
    dec bc
    ld d, d
    ld a, [bc]
    rst $38
    ld a, [de]
    add b
    ld b, h
    cp [hl]
    ld d, l
    ld a, a
    db $fc
    push hl
    ld e, a
    and e
    sbc l
    ld e, e
    push bc
    ld e, a
    db $f4
    ldh [$fe], a
    xor e
    ld [$3826], a
    ld h, a
    sub h
    xor $b3
    or l
    ld h, [hl]
    jr nc, jr_00b_6f1a

    ld h, $6d
    xor [hl]
    rst $38
    adc [hl]
    add hl, hl
    push af
    cp $3a
    sbc $8e
    db $db
    rst $38
    rst $38
    db $fc
    ld a, [$f259]
    adc $ab
    sbc h
    ret z

    ld b, a
    ld c, d
    jr nc, jr_00b_6f08

    add e
    inc c
    sbc h
    ld [hl], $aa
    rst $00
    ld h, l
    ld [hl], c
    sbc $a6
    ld c, $72
    ccf
    xor d
    cp a
    rst $20
    dec bc
    db $fd
    ld [hl+], a
    cp l
    ld b, a
    inc d
    ld b, h
    dec l
    dec e
    ld c, c
    ldh [$c6], a
    ld [hl], c
    db $f4
    and b
    ld d, l
    cp [hl]
    pop bc

jr_00b_6f08:
    ld d, l
    inc a
    daa
    xor d
    or h
    ldh [$79], a
    inc sp
    ld d, b
    ld b, c
    rst $38
    inc b
    jp c, $91a1

    ld d, c
    ld a, d
    xor d

jr_00b_6f1a:
    ld h, $36
    ld c, h
    jr z, @+$76

    ld e, a
    ld hl, sp+$15
    ld l, b
    adc $8d
    add sp, -$76
    xor d
    or e
    ld a, [hl-]
    dec bc
    rst $08
    add hl, de
    ld a, [$3c52]
    inc hl
    and d
    add c
    jp nc, Jump_00b_6311

    add c
    dec [hl]
    push de
    ld e, [hl]
    add hl, bc
    ld a, b
    set 7, [hl]
    inc [hl]
    xor d

jr_00b_6f40:
    xor b
    adc [hl]
    and b
    xor l
    ld d, [hl]
    adc [hl]

jr_00b_6f46:
    dec hl
    ld d, l
    ld a, b
    adc e
    ld [hl+], a
    xor l
    ld c, c
    ld d, e
    ld l, d
    xor b
    dec d
    ld b, c
    ld h, h
    jr jr_00b_6fc4

    di
    ld c, c
    ld d, l
    cp $aa
    and b
    sbc l
    rrca
    push de
    and e
    add hl, sp
    ld a, [bc]
    dec b
    ld e, a
    ei
    ld d, l
    ld d, b
    xor l
    ld h, e
    ld l, e
    ld [$2a8c], a
    and b
    xor d
    ld a, $5a
    ld a, l
    add d
    ld b, d
    ld a, b
    ld c, b
    ld d, l
    jp hl


    push bc
    xor c
    xor d
    dec l
    ld d, d
    ld l, a
    inc b
    ld [hl-], a
    ld a, [hl+]
    jr z, jr_00b_6f40

    ld e, [hl]
    sbc h
    or h
    jr nc, jr_00b_6f46

    db $fc
    xor a
    pop af
    sbc d
    ld a, [bc]
    sbc c
    call c, $134d
    add hl, de
    call nz, $945a
    and e
    sbc h
    add sp, -$50
    jp c, $e6b2

    ld [$e622], sp
    pop de
    rrca
    add e
    cp $61
    add a
    cp $69
    ld [bc], a
    scf
    ld a, a
    ld e, [hl]
    db $e4
    ld a, $d5
    ld h, a
    ld a, [bc]
    db $fc
    ld b, e
    db $fd
    rst $38
    inc h
    add hl, sp
    cp a
    ld d, [hl]
    ld h, c
    ld a, d
    dec c
    ld a, a
    db $fc
    ld [hl], d
    ld [hl+], a
    add d
    rla
    di
    or l
    jp hl


    sbc h

jr_00b_6fc4:
    and d
    ret nz

    jp z, $32fa

    rst $38
    ld a, a
    ld a, [de]
    pop bc
    and c
    ret c

    ld b, e
    dec b
    push de
    add l
    ld e, b
    ld b, a
    inc c
    ld a, l
    ld e, b
    ld b, h
    cp [hl]
    push hl
    ld a, h
    pop hl
    ld a, a
    rst $18
    ld a, l
    xor d
    scf
    ld a, b
    sbc e
    xor d
    ld a, h
    inc de
    and d
    db $e3
    or a
    ld d, e
    sbc d
    jp nc, Jump_000_2958

    ld d, h
    db $e3
    cp [hl]
    add c
    add c
    ld l, e
    inc c
    db $e4
    xor b
    sbc e
    ld hl, sp-$11
    cp h
    db $fc
    ld d, $7d
    jp nz, Jump_00b_7442

    jr nz, @-$73

    add [hl]
    ld [hl], e
    ld c, c
    add hl, bc
    ld de, $f9ce
    ret nc

    sub d
    db $fd
    inc bc
    cp b
    daa
    dec c
    rst $38
    db $e4
    ld e, a
    add [hl]
    ld [hl], d
    ld d, h
    ld c, h
    and b
    rst $00
    ld [hl], l
    and a
    db $e4
    and b
    ld d, l
    cp [hl]
    adc l
    db $fd
    rla
    rst $38
    sub h
    add sp, -$5b
    xor e
    dec b
    ld [hl+], a
    sbc c
    ld [hl], $7e
    cp c
    ld d, d
    dec h
    add $54
    ld d, b
    ld c, l
    inc h
    ld a, h
    sbc l
    ld l, c
    ld h, h
    ld d, l
    sbc [hl]
    inc b
    jp nc, Jump_00b_5081

    rst $38
    ld c, b
    ld c, b
    ld h, c
    xor l
    ld [hl], $f6
    adc c
    ld hl, sp+$50
    and b
    ld b, d
    dec h
    inc b
    adc $48
    ld b, d
    ld e, c
    db $fd
    adc l
    ld de, $ea4c
    ld a, [hl+]
    sub [hl]
    and d
    db $e4
    add l
    adc [hl]
    dec b
    add hl, bc
    ld d, l
    ld c, c
    ld l, d
    xor d
    ld d, b
    ld c, l
    ret nc

    sub a
    xor b

Call_00b_7068:
    add [hl]
    add hl, hl
    dec de
    adc l
    sbc [hl]
    inc d
    add $95
    ld l, c
    and e
    ld h, a
    add [hl]
    add d
    dec hl
    push bc
    ld d, [hl]
    adc [hl]
    inc [hl]
    add [hl]
    adc c
    ld [$a5ba], a
    ld [hl], e
    ld h, [hl]
    inc c
    ld h, h
    adc b
    ld l, e
    push af
    ld d, [hl]
    adc [hl]
    add hl, bc
    ld l, c
    ld c, b
    or l
    add hl, bc
    ld c, [hl]
    sbc c
    ld d, [hl]
    xor d
    rst $30
    jp $12cf


    and e
    call nc, Call_00b_499f
    ld [bc], a
    ld c, d
    xor d
    sbc l
    ld d, [hl]
    pop bc
    adc h
    and h
    ld e, [hl]
    sbc e
    cp b
    dec hl
    or a
    ld d, e
    ldh a, [$5f]
    rst $38
    sbc e
    ld e, d
    rrca
    db $e4
    rst $38
    xor h
    ld c, l
    ld c, [hl]
    sbc d
    rst $38
    ld hl, sp+$2b
    ld a, [hl]
    rra
    add h
    ld e, l
    sbc d
    ccf
    ldh a, [rNR42]
    cp a
    db $fd
    inc a
    sub a
    dec de
    ld d, h
    dec [hl]
    ldh a, [$b6]
    inc de
    push bc
    rst $00
    ld [hl+], a
    db $db
    ld b, $5c
    ld h, b
    sbc h
    rla
    db $ed
    db $fc

jr_00b_70d3:
    adc e
    push de
    add d
    db $fc
    ld [hl], c
    ld d, a
    and b
    db $d3
    xor e
    cp $14
    ld [hl], c
    ld a, a
    and e
    inc sp
    ld a, a
    db $fd
    inc e
    ld a, [hl+]
    ld b, a
    ld a, [$1d55]
    ld a, $ff
    ld hl, sp+$36
    xor [hl]
    xor d
    ld b, e
    dec de
    ld d, a
    rst $38
    ldh a, [$a1]
    ld h, $11
    ret


    ld a, a
    call z, $a914
    db $e4
    pop de
    di
    add b
    ld b, h
    cp l
    daa
    db $ed
    dec d
    add hl, sp
    xor l
    ld [$f36b], sp
    sub l
    inc b
    jr @+$52

    ld d, e
    sub c
    add d
    sbc b
    ld a, [hl+]
    ld [$79e1], sp
    adc b
    ld h, b
    ld b, c
    inc b
    ldh [$aa], a
    dec h
    ld d, h
    adc b
    pop hl
    ld d, d
    ld h, $15
    add l
    adc $18
    jr @+$56

    inc d
    adc e
    jr c, jr_00b_7195

    add l
    ld b, c
    ld c, c
    ld c, [hl]
    dec d

Call_00b_7132:
    sub c
    sub h
    ld h, d
    inc sp
    adc d
    ld a, [$5481]
    add h
    add sp, -$43
    ld [hl], e
    cp d
    sub l
    ld c, a
    add l
    sbc [hl]
    xor d
    sbc l
    sbc d
    cp $0f
    daa
    dec [hl]
    db $fd
    jr z, jr_00b_7174

    ld [hl-], a
    or b
    jr nz, jr_00b_70d3

    rst $00
    ld [de], a
    rla
    pop hl
    pop hl
    or a
    sbc h
    inc a
    rrca
    jp z, $b1ad

    jp $c803


    rst $38
    rst $20
    scf
    add a
    rst $38
    ld hl, sp+$39
    push bc
    add h
    rra
    rst $38
    pop hl
    inc e
    ld [hl], d
    adc l
    rst $38
    dec e
    ld [$d777], a

jr_00b_7174:
    xor c
    db $f4
    and b
    ld h, [hl]
    cp [hl]
    pop hl
    ld d, l
    ld c, a
    ld hl, $aafa
    db $d3
    push bc
    and d
    db $f4
    inc d
    ret


    and h
    db $e3
    ld e, d
    add hl, hl
    ld [hl+], a
    sub e
    inc h
    sbc b
    ret


    ld d, l
    ld b, $06
    cp b
    adc d
    ld e, b
    dec sp

jr_00b_7195:
    ld c, d
    adc l
    rst $20
    or $06
    dec b
    ld e, c
    ld d, h
    ccf
    db $76
    pop de
    adc [hl]
    dec de
    ld hl, sp+$21
    add d
    ld h, b
    ld l, l
    db $e4
    jr nz, jr_00b_720a

    ld l, b
    pop bc
    ld sp, $61a2
    add d
    ld [hl+], a
    ld [$1889], sp
    jr @+$15

    inc b
    call $ce0c
    ld [hl+], a
    and c
    adc h
    ld d, l
    ld l, b
    reti


    inc sp
    ld b, [hl]
    ld b, $18
    db $ec
    adc h
    db $10
    ld b, d
    ld hl, sp+$2a
    add c
    ld [$86eb], sp
    ld a, [de]
    ld [$a588], sp
    ld a, [hl+]
    xor d
    ld c, l
    ld [hl+], a
    and c
    sub a
    inc b
    ld h, d
    ld a, d
    and c
    ld c, h
    inc hl
    ld h, $05
    ld [hl+], a
    ld c, b
    ld b, l
    inc sp
    ld d, h
    inc de
    ld [$ebc9], sp
    ld h, $50
    sub e
    dec a
    sbc b
    inc de
    add l
    ld c, h
    ld [$3709], a
    ld c, l
    and $f1
    ld c, l
    dec h
    ld hl, $a878
    sub h
    adc $aa
    ld a, [bc]
    ld d, e
    ld a, [hl-]
    add c
    ld sp, $39aa
    xor c
    ld c, h
    ld a, [de]
    inc a

jr_00b_720a:
    ld a, d
    xor d
    adc a
    or h
    sbc a
    ld [hl], b
    sub d
    sbc [hl]
    ld c, [hl]
    ld e, [hl]
    sbc [hl]
    dec [hl]
    rla
    jp c, $d266

    ld [hl], c
    and c
    ld a, [hl+]
    ld b, d
    cp $c6
    ld c, c
    ld sp, $8a92
    inc c
    ldh a, [$60]
    cp [hl]
    dec d
    ld h, $51
    cp h
    dec d
    inc sp
    rrc e
    ld d, d
    adc e
    inc hl
    ld de, $081c
    ld d, h
    ld c, $1c
    add e
    add hl, hl
    dec c
    add h
    di
    sbc c
    ld b, [hl]
    ld d, [hl]
    ld b, [hl]
    jr nc, jr_00b_7286

    pop bc
    jr z, jr_00b_7291

    db $10
    ld [hl], b
    ld h, l
    or c
    sbc [hl]
    db $10
    and $68
    ld e, b
    and [hl]
    sub c
    ret nz

    adc [hl]
    ld h, c
    and d
    ldh a, [rHDMA2]
    ld c, e
    sbc l
    ld e, $08
    ld l, l
    ld a, [hl+]
    inc c
    jr c, jr_00b_72dd

    ld e, $71
    and h
    rst $18
    and c
    inc de
    inc h
    jr c, jr_00b_72ba

    ld sp, hl
    ld d, h
    sbc c
    push hl
    ld e, a
    db $ec
    db $e3
    ld de, $7841
    ld a, c
    add h
    sbc b
    ldh a, [$29]
    rla
    cp $86
    ld h, d
    di
    add d
    ld h, c
    sbc e
    ld c, c
    rla
    ld a, [$14a6]

jr_00b_7286:
    call nz, $e665
    inc l
    adc e
    rla
    ld d, b
    ld e, d
    ld e, e
    and h
    ret


jr_00b_7291:
    add hl, sp
    sub h
    ret nc

    add hl, hl
    and l
    dec hl
    ei

Call_00b_7298:
    dec d
    ld [hl+], a
    rst $00
    dec d
    add hl, hl
    xor e
    sbc [hl]
    dec e
    add hl, hl
    ld c, l
    rra
    sub c
    nop
    ld b, h
    cp b
    sub l
    ld d, l
    add hl, sp
    sub [hl]
    adc h
    add hl, hl
    ld [hl], $55
    adc l
    db $e3
    ld [hl], $3b
    jp nc, Jump_000_3a19

    pop hl
    sbc b
    ld sp, hl
    and [hl]

jr_00b_72ba:
    inc b
    xor $42
    ret z

    ld l, b
    dec d
    ld c, [hl]
    dec de
    pop bc
    ld b, d
    dec b
    db $e4
    ld h, b
    sub e
    ld a, d
    dec de
    db $fd
    and d
    ld a, c
    adc [hl]
    ld c, b
    rst $00
    adc [hl]
    ld a, e
    ld d, l
    db $e3
    xor [hl]
    xor b
    ld a, [c]
    rst $20
    ld a, [bc]
    sub h
    and a
    ld [hl+], a
    pop de

jr_00b_72dd:
    sub l
    and [hl]
    adc e
    ld e, h
    ld l, a
    sbc c
    ldh a, [$32]
    ld [hl], l
    xor $f6
    sbc l

jr_00b_72e9:
    ld d, b
    call c, $8a7b
    ld l, d
    sbc h
    inc e
    ld sp, $7949
    cp e
    inc d
    push af

jr_00b_72f6:
    dec d
    ld h, $d6
    cp b
    ld [hl], c
    sbc l
    add d
    ld [hl], c
    ld b, b
    sub h
    db $e4
    ld b, a
    ld c, d
    ld sp, hl
    reti


    ld d, h
    ld a, h
    ld e, b
    ld [hl], a
    cp c
    sub l
    xor d
    and l
    inc a
    or [hl]
    adc l
    ld a, [hl+]
    ld d, l
    inc a
    jr c, @-$21

    ld l, d
    xor l
    inc a
    ld [$92d9], sp
    inc [hl]
    ld l, b
    push bc
    ld c, [hl]
    ld c, b
    jp c, $451b

    ld b, c

jr_00b_7324:
    ld c, e
    ld h, c
    adc [hl]
    inc h
    sbc $48
    ld d, l
    ld l, b
    or h
    reti


    cp a
    sub $2d
    xor d
    sub l
    ld b, d
    ld d, l
    and l
    add hl, sp
    ld h, b
    ret


jr_00b_7339:
    sub d
    db $e3
    dec b
    ld a, l
    ld b, d
    xor h
    pop bc
    jr c, jr_00b_73a7

    ld d, d
    ld [c], a
    sbc d
    ld d, l
    ld h, a
    sub c
    xor c
    ld l, b
    db $dd
    dec hl
    ld [c], a
    ld d, d
    ld e, b
    ld e, $aa
    or $64
    call $c558
    jr c, jr_00b_72f6

    rlca
    db $f4
    ld l, b
    jr nz, jr_00b_72e9

    jr jr_00b_7339

    xor b
    jp nc, Jump_00b_7990

    ld e, e
    ld b, d
    add d
    ld [$f1a8], sp
    ld [hl], c
    ld h, e
    ld d, [hl]
    inc a
    inc h
    ld h, a
    push hl
    ld b, c
    ld b, c
    inc a
    inc [hl]
    add [hl]
    ld a, [de]
    ld e, d
    push hl
    ld b, c
    inc d
    push hl
    ld e, d
    adc l
    ld e, e
    ld c, e
    jp hl


    call z, $8113
    add hl, hl
    ld c, l
    ld h, $f5
    ld d, l
    call nc, $a918
    jr c, jr_00b_7324

    ld [c], a
    and d
    jp hl


    rst $38
    rst $28
    ld h, e
    ld a, [hl+]
    ld d, e
    ld b, [hl]
    inc [hl]
    ld c, h
    rra
    ld a, [$8293]
    ld c, h
    inc de
    inc b
    pop bc
    add hl, hl
    ld c, d
    ret nc

    sub c
    ld d, h
    adc $30

jr_00b_73a7:
    or l
    ld e, b
    jp z, Jump_000_2595

    ldh [$b6], a
    inc b
    adc d
    ld d, e
    add [hl]
    xor d
    adc l
    pop de
    adc c
    ld b, c
    ld d, e

jr_00b_73b8:
    cp c
    scf
    sub d
    ld d, [hl]
    inc sp
    adc [hl]
    ld [hl], h
    ldh [$90], a
    db $e3
    ld l, c
    ld hl, $9338
    add [hl]
    ld d, l
    ld a, b
    adc $a3
    sub c
    jr c, jr_00b_73b8

    inc a
    ld b, h
    pop hl
    adc a
    ld [hl+], a
    sub l
    ld c, e
    ld e, d
    add hl, sp
    rst $20
    ld a, [hl+]
    add l
    inc de
    ld c, d
    ld a, c
    ld c, h
    ld l, a
    db $10
    sbc [hl]
    inc de
    dec de
    dec l
    ld e, $2b
    ld a, [de]
    or c
    ld l, b
    ld a, h
    ld h, d
    and a
    inc h
    ld l, l
    sub d
    xor e
    db $f4
    ld e, e
    inc c
    ld [hl], b
    cp c
    cp h
    add e
    cp l
    or c
    add [hl]
    ld l, h
    call nz, $1457
    pop af
    inc d
    dec hl
    ld d, [hl]
    db $fd
    inc e
    or b
    ld a, d
    ld h, h
    add $09
    inc e
    and h
    add hl, hl
    ld c, [hl]
    ld [hl], b
    call nc, $4c46
    ld d, e
    dec h
    ld h, b
    jp c, Jump_00b_5145

    add d
    ld h, c
    sub e
    ld b, c
    inc de
    sub d
    call z, Call_00b_40c4
    add h
    jp c, $a162

    add hl, de
    ld c, c
    inc c
    add hl, bc
    add d
    call z, $32c8
    db $10
    pop bc
    dec h
    ld sp, $1ac5
    ld b, c
    add h
    add hl, bc
    dec de

jr_00b_7436:
    inc b
    jr nc, jr_00b_747d

    or c
    pop hl
    ld h, b
    and a
    ld c, $74
    add $08
    ld h, h

Jump_00b_7442:
    ld b, h
    ret z

    ld c, b
    ld h, a
    ld e, d
    ld h, c
    sub e
    inc bc
    inc hl
    ld c, $10
    jr nc, jr_00b_7436

    dec hl
    ld b, e
    ld a, [de]
    ld c, b
    ld c, h
    ld b, h
    inc de
    db $10
    sub e
    sbc h
    add hl, de
    ld a, [hl+]
    ld h, b
    sub l
    jr nz, @-$3a

    db $ed
    inc bc
    dec d
    add hl, hl
    ret nz

    xor c
    add hl, bc
    ld sp, $1585
    adc e
    add hl, de
    jp nc, $f969

    add hl, sp
    ld e, c
    add e
    xor e
    ld a, [hl]
    sbc e
    jp c, Jump_000_1c5c

    ld c, e
    rla
    and h
    and e
    ld e, d
    rst $18

jr_00b_747d:
    adc e
    ld [bc], a
    ld h, l
    add hl, de
    inc h
    ld b, [hl]
    ld [hl], h
    ld h, e
    ld a, e
    ld b, c
    inc de
    ld b, a
    inc a
    ld l, [hl]
    sub a
    ld c, d
    and [hl]
    add hl, bc
    call $c99b
    ld d, a
    and $32
    ld [hl], e
    ld h, a
    inc b
    sub l
    ld c, c
    sub h
    xor h
    ld [hl], c
    ld h, a
    inc c
    ld c, d
    ld a, b
    ld [hl], c
    call nz, Call_000_3c9e
    sbc e
    and a
    sub l
    ld b, d
    and h
    xor l
    dec e
    nop
    ld b, h
    cp b
    push de
    ld d, l
    ld c, [hl]
    ld d, l
    and e
    ld a, [de]
    inc [hl]
    ld l, d
    sbc b
    or $a5
    inc a
    inc b
    xor $63
    pop bc
    db $f4
    db $ec
    sub b
    db $e3
    cp d
    and h
    add l
    ld c, [hl]
    or h
    ld [hl+], a
    inc h
    ld [$febf], a
    adc a
    ld b, $4f
    ld b, $53
    pop hl
    ld h, a
    ld [de], a
    sub [hl]
    and a
    inc hl
    ld b, [hl]
    ld [hl], c
    and e
    inc c
    ld de, $a9d4
    rst $18
    ld d, c
    sbc $a6
    ld a, [bc]
    sbc h
    ld l, h
    ld h, e
    ld de, $901c
    ld b, a
    sbc [hl]
    sbc h
    ld [hl], b
    inc a
    add hl, bc
    add h
    ld [hl], c
    ld c, h
    ld c, [hl]
    sbc l
    ld d, c
    dec [hl]
    daa
    add e
    daa
    add e
    daa
    jp nz, $5580

    cp a
    db $10
    ld a, d
    ld c, [hl]
    rst $30
    xor e
    inc c
    ld h, e
    or c
    db $ed
    add [hl]
    add hl, hl
    ld d, e
    sub c
    ld a, l
    ld c, c
    sub d
    ld a, [de]
    xor e
    ld c, [hl]
    rrca
    ld a, [c]
    ld e, [hl]
    ld b, [hl]
    and e
    rra
    ld c, l
    db $eb
    cp c
    add c
    inc sp
    ld c, c
    and e
    add [hl]
    add [hl]
    adc h
    inc l
    dec [hl]
    ld c, [hl]
    ld l, e
    ld c, h
    jr jr_00b_7590

    sub c
    ld d, h
    db $e3
    cp a
    rst $38
    and l
    inc hl
    ld e, [hl]
    inc a
    inc e
    ld a, [hl]
    inc a
    inc [hl]
    add [hl]
    dec sp
    sub l
    ld b, $1c
    rra
    and e
    sbc c
    ld a, [hl]
    xor b
    ld e, a
    ld b, l
    ld c, [hl]
    ld a, d
    push af
    ld d, a
    ld a, e
    ld hl, sp-$14
    xor b
    ld l, d
    adc a
    sub a
    sbc a
    adc b
    xor d
    ld a, b
    ld [$6f48], sp
    rst $20
    add c
    ld b, e
    rst $38
    adc d
    ld [hl], e
    ld hl, $9706
    ld d, e
    rst $00
    inc l
    ld [$f53e], sp
    sub c
    cp $54
    ld de, $06c5
    rlc e
    rst $38
    add d
    add hl, hl
    ld sp, $7fc5
    rst $38

jr_00b_7573:
    rst $38
    ld a, d
    jp c, $df73

    rst $38
    rst $08
    ld hl, sp+$57
    add h
    sbc h
    sub c
    ld d, c
    ld c, [hl]
    or d
    ld a, b
    ld l, d
    cp [hl]
    ld a, b
    ld [hl], a
    adc [hl]
    add hl, hl
    call nc, Call_00b_4682
    adc d
    add d
    ld [hl], a
    ei

jr_00b_7590:
    ld l, $77
    db $76

jr_00b_7593:
    dec a
    inc hl
    rra
    ld a, b
    ld b, h
    cp [hl]
    ld l, l
    ld c, [hl]
    rst $28
    adc $fa
    inc a
    inc b
    ldh [$7f], a
    db $fd
    dec l
    sub e
    ld h, a
    adc e
    or [hl]
    sbc c
    inc c
    pop de
    adc l
    db $76
    ld c, $33
    ld l, [hl]
    and e
    jr c, jr_00b_7593

    and a
    and b
    ld d, d
    sub d
    dec d
    ld [hl], e
    ld l, e
    sub b
    add l
    add e
    ld hl, sp+$28
    pop hl
    or l
    db $fc
    ld d, e

jr_00b_75c3:
    or [hl]
    and e
    db $e3
    ld [hl], a
    sbc $27
    add c
    ld e, $8e
    xor e
    add hl, de
    ld h, a
    inc d
    sub c
    jr nz, jr_00b_7573

    ld a, [$826a]
    ld h, a
    push af
    ld l, c
    and e
    jp nc, $6bb1

    inc b
    ld l, l
    ld d, h
    ld a, b
    db $10
    ld d, c
    rrca
    sbc l
    rla
    call nc, Call_00b_7d0a
    ld l, b
    ld d, l
    cp a
    ld c, a
    ld d, d
    ld e, a
    db $f4

jr_00b_75f0:
    dec d
    add hl, sp
    sbc [hl]
    ld a, [de]
    ld [hl], l
    ld d, a
    cp d

jr_00b_75f7:
    cp $f9
    ld d, l
    dec b
    ld c, b
    ld a, b
    inc h
    add [hl]
    sub a
    db $fc
    add hl, hl
    ld e, a
    db $ed
    xor a
    xor e
    ld d, h
    xor d
    add d
    dec b
    dec b
    ld d, l
    dec d
    ld c, e
    ld d, c
    ld h, e
    ld b, $a0
    ld b, l
    sub l
    ld e, [hl]
    sbc l
    sbc $41
    ld a, [bc]
    jr jr_00b_75c3

    sub h
    ld a, [hl+]
    adc d
    cp [hl]
    ld [hl+], a
    ld b, [hl]
    dec h
    add d
    sub c
    ld d, b
    ld [hl], b
    add c
    ld l, d
    dec b
    ld a, a
    sub c
    ld c, d
    ld h, d
    ld h, [hl]
    sub a
    add e
    sub h
    call $211a
    and e
    add hl, de
    ld b, l
    sub c
    sub c
    ld b, c
    ld e, d
    dec h
    ld e, b
    sbc $88
    sub c
    cp c
    ld d, l
    ld e, d
    adc [hl]
    xor d
    adc a
    adc $67
    ld [$c2d0], a
    add d
    ld [hl], e
    db $ed
    jr z, jr_00b_75f0

    call nc, $c31a
    jr z, jr_00b_75f7

    add d
    add hl, bc
    ld d, a
    add sp, -$14
    ld [hl-], a
    xor d
    rst $10
    ld de, $428a
    db $eb
    ld de, $f8ff
    add hl, sp
    ld a, [hl+]
    sub h
    add sp, $7e
    rra
    add sp, $22
    db $fc
    ld a, $43
    db $fd
    dec bc
    ld de, $ed77
    ldh a, [$3f]
    pop af
    ld c, $28
    ld d, b
    db $f4
    ld b, d
    ei
    scf
    push hl
    rst $38
    xor a
    add e
    call nz, Call_00b_4f31
    ld a, a
    or b
    ld b, [hl]
    scf
    db $fc
    rra
    dec hl
    db $e4
    cpl
    ei
    ld a, h
    ld l, e
    dec b
    inc de
    rst $38
    rst $18
    rst $38
    sub $31
    rst $08
    ret c

    push bc
    ld b, a
    db $eb
    nop
    ld b, h
    cp [hl]
    reti


    ld c, [hl]
    push bc
    sub $fd
    jr c, jr_00b_7706

    db $eb
    and c
    and c
    adc l
    jp c, $1622

    sub b
    ld d, e
    adc d
    ld [hl-], a
    add c
    ld b, d
    adc [hl]
    inc b
    add [hl]
    ld [hl+], a
    adc [hl]
    ld d, h
    ld a, [hl+]
    ld sp, $3855
    ld h, h
    or [hl]
    rra
    and h
    ld [c], a
    sub l
    ld l, a
    sbc a
    and e
    ldh a, [$6d]
    ld hl, sp-$55
    ldh [$a9], a
    rst $00
    ld a, [hl+]
    pop hl
    dec hl
    ld d, [hl]
    ld [hl], b
    dec a
    ld [hl+], a
    db $f4
    cpl
    ld h, $f9
    inc c
    ld d, l
    inc e
    call nc, $1355
    ld l, c
    cp [hl]
    sbc b
    inc hl
    rst $38
    rst $20
    inc c
    jp nc, Jump_00b_4f0b

    ld sp, $05cf
    dec b
    rra
    add h
    add b
    ld [hl], a
    cp a
    daa
    ld [hl], e
    ld b, a
    di

jr_00b_76f6:
    ld h, l
    ld d, l
    ld d, l
    ld d, l
    ld c, [hl]
    ld [hl], a
    adc l
    ld d, l
    ld [$afaa], a
    ld e, d
    inc sp
    ld c, h
    db $fc
    and l

jr_00b_7706:
    ld a, [$8498]
    sub l
    ldh a, [$a2]
    ld d, [hl]
    xor a
    xor b
    ld [hl+], a
    push de
    ld a, l
    rlca
    sbc c
    ret z

    ld d, b
    rst $28
    ld a, [$5a25]
    daa
    and c
    ld h, d

jr_00b_771d:
    ld e, a
    xor d
    add [hl]
    ld d, c
    xor d
    and c
    add d
    ld c, b
    ld d, [hl]
    and b
    ld h, l
    ld d, l
    ld d, l
    adc c
    ld a, b
    and l
    ld b, $08
    adc $25
    adc d
    ld h, e
    and c
    add sp, $25
    push bc
    ld l, d
    ld e, b
    adc b
    adc h
    ld e, l
    ld d, l
    jr c, jr_00b_771d

    dec b
    ret nc

    pop bc

jr_00b_7742:
    ld [$a231], a
    and d
    cp a
    ld c, c
    ld d, a
    ld a, [$bf90]
    and c
    ld b, d
    ld hl, $6988
    ld c, e
    and h
    ld d, l
    sbc e
    cp [hl]
    and b
    ld a, b
    ld h, $a9
    ld d, h
    ld h, l
    and d
    jr @-$52

    xor b
    ld h, l
    jr jr_00b_7773

    ld d, d
    ld e, $2a
    and l
    ld d, b
    xor d

jr_00b_7769:
    ld [hl], d
    ld [hl+], a
    ld d, [hl]
    jr nc, jr_00b_76f6

    ld l, d
    dec l
    db $e3
    ld a, d
    xor c

jr_00b_7773:
    ld c, b
    ld b, l
    sbc h
    jp z, $e334

    sub l
    and d
    ld l, b
    ld h, l
    or c
    add c
    jr jr_00b_7742

    adc [hl]
    ld h, [hl]
    dec l
    inc hl
    sub $22
    and d
    inc h
    add $a4
    db $dd
    add c
    ld c, d
    ld b, c
    inc b
    dec d
    ld d, [hl]
    add hl, hl
    ld e, h
    inc d
    sub h
    ld d, e
    ld b, [hl]
    ld b, $1a
    ld c, c

jr_00b_779b:
    xor [hl]
    adc b
    ld e, e
    ld l, d
    ld b, $61
    adc b
    adc b
    ld c, h
    ld e, b
    jr jr_00b_7769

    inc d
    inc h
    ld a, [hl+]
    sbc d
    dec h
    sbc b
    xor d
    sub h
    add h
    and [hl]
    ld b, $33
    add d
    add $86
    add hl, hl

jr_00b_77b7:
    sbc b
    sub $a2
    ld e, b
    jr jr_00b_779b

    ld d, l
    ld [hl+], a
    ld b, l
    sbc b
    push hl
    ld b, c
    adc [hl]
    ld l, d
    sub b
    or [hl]
    add hl, sp
    jr z, jr_00b_781d

    add l
    adc h
    db $e3
    and d
    dec b
    jr c, jr_00b_77f9

    ret


    adc [hl]
    push bc
    dec [hl]
    ld a, h
    jp z, $eb8e

    ld d, d
    rst $10
    add d
    push af

jr_00b_77dd:
    ld d, l
    db $e3
    pop bc
    xor a
    rst $38
    and d
    ld [$eea8], a
    sbc a
    ld h, b
    sbc [hl]
    cp e
    ld a, [de]
    pop bc
    ld d, c
    call nc, $329e
    ld h, b
    xor d
    ret c

    ld b, [hl]
    xor d
    ld [hl], b
    and d
    and c
    ld c, c

jr_00b_77f9:
    inc de
    db $fd
    add h
    ld h, b
    add l
    ld a, [bc]
    ld b, d
    ld h, b
    add d
    and l
    ret z

    ld d, b
    dec sp
    adc l
    inc b
    ld e, d
    ld sp, $0c51
    ld e, h
    sub b
    add l
    jr nz, jr_00b_77b7

    rra
    ld [$3042], a

jr_00b_7815:
    push af
    jr jr_00b_77dd

    inc h
    ld c, e
    ld [bc], a
    xor c
    adc e

jr_00b_781d:
    rst $38
    add sp, $30
    ld [hl+], a
    rst $00
    ld [hl+], a
    sub c
    ld [bc], a
    ld b, l
    ld d, d
    push de
    ld e, a
    ret


    ld l, [hl]
    sbc h
    adc b
    ret nz

    sub c
    dec c
    rst $38
    inc bc
    sub c
    inc de
    inc d
    add h
    ret


    sbc d
    inc l
    add hl, bc
    db $10
    jp z, $8b17

    jp nz, $28f5

    ld b, d
    and c
    ld a, a
    xor $30
    ld b, h
    ld sp, $3432
    rla
    jp $3ca4


    ld c, e
    sub l
    inc hl
    db $eb
    ld hl, sp-$55
    add $54
    ld a, [hl+]
    ld b, l
    ld d, [hl]
    add hl, de
    dec l
    ld de, $1191
    db $dd
    adc $1c
    ld [hl], d
    pop de
    jr c, jr_00b_7815

    ld b, d
    or d
    ld b, h
    cp h
    pop bc
    ld a, c
    db $d3
    cpl
    or h
    dec hl
    ld e, b
    db $e4
    sbc $57
    ld [bc], a
    sbc h
    xor a
    db $fc
    inc l
    ld a, [bc]
    call nz, Call_00b_4534

jr_00b_787c:
    ld a, [bc]
    sbc b
    daa
    dec bc
    cp $84
    add a
    jp hl


    ld d, b
    jp nz, $c68f

    ld [$cd26], sp
    xor l
    ld l, b
    rst $18
    pop af
    ld c, e
    ld b, d
    pop af
    ld c, c
    ld l, c
    sbc e
    ld d, b
    ld h, h
    ld [hl], d
    ld [$5048], sp

jr_00b_789b:
    inc a
    ld c, e
    add $70
    ld l, $62
    call nz, Call_000_2c3a
    add hl, hl
    ld d, b
    ld e, c
    rrca
    rst $00
    ld [hl-], a
    ld c, $a8
    jr nc, jr_00b_787c

    sub e
    xor b
    inc hl
    ld a, a
    rst $00
    ld h, $28
    ld [hl], c
    add hl, sp
    cpl
    jp nc, $9886

    ld b, a
    ld b, [hl]
    add hl, sp
    rrca
    xor b
    or h
    ld b, [hl]
    dec c
    xor d
    ld b, d
    ld [hl], h
    pop bc
    ld b, b
    push bc
    ld c, h
    ld b, d
    add e
    dec b
    push de
    ld h, a
    ld l, l
    jr jr_00b_789b

    ld c, h
    ld b, h
    adc d
    ld a, b
    add hl, hl
    add l
    sub e
    ld [bc], a
    ld b, h
    sbc [hl]
    inc l
    ld c, h
    ld a, c
    add b
    ld b, h
    cp d
    dec de
    dec sp
    jr @+$3a

    db $eb

jr_00b_78e7:
    ld c, b
    and e
    and l
    pop de
    adc [hl]
    and l
    ld [hl+], a
    dec sp
    reti


    ld d, e
    adc c
    rst $38
    call nc, Call_00b_4c89
    ld e, a
    call nc, Call_000_2e5e
    call nc, $c618
    ret nc

    xor [hl]
    adc h
    and $14
    jp z, $e0d4

    add l
    inc [hl]
    and d
    inc de
    ld b, h
    ldh [$57], a
    ret z

    ld d, l
    ld d, b
    ld b, l
    adc h
    sbc a
    and c
    or [hl]
    ld l, h
    adc b
    jr jr_00b_78e7

    push de
    ld [hl], d
    dec hl
    push de
    ld l, b
    jp c, Jump_000_3daa

    sbc c
    db $ec
    rst $00
    ld a, e
    rst $00
    ld l, [hl]
    ld a, [de]
    db $76
    cp [hl]
    sbc l
    or d
    rst $00
    ld d, d
    ld a, [$5da7]
    ld a, a
    sbc l
    sbc d
    add hl, bc
    or d
    sbc d
    rst $38
    and a
    ld c, d
    rst $38
    ld a, [$a172]
    ld d, a
    db $fc
    ld [hl], d
    or b
    inc a
    inc a
    ld [hl], c
    inc [hl]
    ld h, e
    rra
    inc e
    ld [hl], a
    cp d
    ld d, l
    dec a
    dec [hl]
    db $ec
    inc sp
    rst $00
    ld [hl], l
    cp $5e
    sbc [hl]
    adc a
    add hl, de
    sbc a
    ret z

    ret c

    ld e, $3c
    xor b
    scf
    jp nz, $8105

    inc a
    sbc d
    ld h, $14
    or h
    di
    sbc l
    ld a, [bc]
    adc [hl]
    rst $30
    or c
    jp hl


    ld d, h
    cp c
    ld h, c
    ld c, b
    adc [hl]
    and h
    inc d
    sbc d
    ld d, h
    ld [hl], h
    xor c
    inc b
    adc a
    ld e, e
    db $e4
    db $e4
    adc h
    ld d, [hl]
    inc b
    dec l
    ld e, a
    and c
    ld l, [hl]

jr_00b_7983:
    call c, $5366
    ld a, d
    sbc a
    sub l
    sub [hl]
    adc c
    and l
    dec b
    ld a, [de]
    ld l, e
    adc b

Jump_00b_7990:
    pop af
    and l
    dec [hl]
    db $eb
    ld l, d
    add l
    ld a, a
    and l
    ldh [$5c], a
    ld [hl+], a
    sub $30
    sub l
    ld d, a
    ld a, [$c104]
    ldh a, [$90]
    add c
    add c
    push hl
    adc h
    add hl, hl
    inc sp
    cp a
    cp a
    ld a, [bc]
    rrca
    ld b, [hl]
    add d
    ld [hl], c
    and b
    ld h, b
    add c
    sbc a
    sub d
    cp h
    push bc
    jp c, $0e85

    xor $0a
    ld h, $81
    and d
    ld l, a
    db $fd
    adc c
    ld a, h
    add $55
    ld a, l
    add e
    db $e3
    daa
    ld c, h
    jr c, @+$24

    rst $18
    or e
    ld h, $fe
    cp $14
    add [hl]

jr_00b_79d4:
    inc hl
    and [hl]
    dec l
    ld b, d
    ld d, a
    xor [hl]
    inc [hl]
    ld a, l
    xor b
    add l
    sbc c
    ld [$9824], sp
    cp b

jr_00b_79e3:
    ld h, h
    ld h, h
    ldh [$4c], a
    rst $28
    ld l, b
    sbc d
    adc h
    inc e
    add l
    sub l
    jr jr_00b_7a46

    jr nc, @-$6b

    add d
    ld e, $54
    inc a
    ld a, [hl-]
    sub l
    dec b
    jr jr_00b_7983

    ld h, e
    jr z, jr_00b_79d4

    jr @-$42

    xor c
    inc b
    ld [hl+], a
    ld d, h
    pop hl
    sub e
    add c
    ld d, $69
    ret nc

    and b
    add [hl]
    ld d, h
    jr z, @+$66

    push bc
    ld hl, $8533
    ld h, $26
    add hl, de
    adc c
    ld [hl], a
    add l
    ld b, c
    ld b, $25
    dec c
    ld [$4dcb], sp
    dec e
    dec bc
    ld h, $63
    add hl, bc
    ld [hl+], a

jr_00b_7a26:
    ld b, [hl]
    ld b, c
    inc [hl]
    ld l, c
    ld h, l
    inc hl
    and [hl]
    ld c, d
    adc d
    and b
    ld d, d
    inc hl
    sub [hl]
    ld d, h
    ld h, $49
    adc e
    adc e
    cp h
    rst $08
    ld d, l
    inc sp
    add l
    add c
    add hl, bc
    xor b
    or [hl]
    inc sp
    ld d, e
    inc b
    ld a, [hl+]
    inc [hl]

jr_00b_7a46:
    cp b
    jr jr_00b_79e3

    ld d, l
    ld l, b
    jp c, $78f5

    sbc $74
    and b
    sbc [hl]
    sbc d
    rrca
    rst $00
    sub e
    ld [bc], a
    cp d
    ld c, e
    ld e, $4a
    db $ed
    ld a, a
    jr nz, jr_00b_7a26

    sub h
    add [hl]
    jr z, jr_00b_7a9b

    ld a, h
    and a
    sub l
    dec b
    rst $28
    db $fd
    ld a, $79
    adc a
    db $fd
    rst $38
    pop af
    db $dd
    sub h
    call nz, $f0bf
    ld b, c
    ld a, a
    sbc l
    xor d
    ld h, e
    dec d
    ld a, d
    ld b, e
    ld hl, sp-$38
    db $eb
    sbc h
    or c
    and e
    ld de, $74df
    ld c, d
    scf
    ld a, [$d470]
    ld a, [hl+]
    ld b, d
    ld de, $138c
    ld a, [c]
    dec e
    rlca
    rst $38
    di
    ld [bc], a
    ld l, c
    and b
    sbc c
    dec hl
    ret


    inc l

jr_00b_7a9b:
    inc l
    ld c, e
    ld a, l
    ld a, [$4244]
    jr nc, jr_00b_7adf

    ld sp, $fc9d
    inc l
    ld b, e

Jump_00b_7aa8:
    and b
    or e
    cp $91
    dec d
    and c
    ld b, d
    add h
    ld a, [bc]
    sub e

jr_00b_7ab2:
    and h
    jr c, @+$3e

    call nz, $2d50
    rst $38
    cp $94
    sbc d
    ld [hl], h
    ld b, h
    ccf
    rst $38
    jp nc, $2bc5

    rst $38
    rst $38
    ld sp, hl
    ld d, c
    ld d, b
    jr z, jr_00b_7aef

    cp a
    db $fd
    ld a, a
    db $e4
    cp a
    rst $38
    rst $38
    rst $38
    inc d
    ld a, [$4412]
    and l
    ld e, a
    call nz, Call_00b_53fe
    db $fc
    ccf
    rst $38
    rst $00

jr_00b_7adf:
    dec e
    xor b
    ld b, c
    ld a, d
    ld b, e
    pop af
    add l
    inc b
    db $fd
    pop af
    ld c, h
    sbc h
    jr nc, jr_00b_7b10

    ld e, a
    ld [hl], b

jr_00b_7aef:
    and [hl]
    jr nc, jr_00b_7ab2

    sub h
    sub c
    ld [hl-], a
    ld l, [hl]
    adc d
    ld [$1041], sp
    add d
    ld [$19ad], sp
    ld e, d
    dec de
    ld [hl], $74
    or b
    rst $18
    inc bc
    rla
    and h
    ld a, $1e
    rst $18
    and [hl]
    xor c
    db $10
    xor [hl]
    sub b
    db $e3

jr_00b_7b10:
    jp z, $a444

    ld e, a

jr_00b_7b14:
    add a
    db $ed
    ld a, [$7f73]
    rst $38
    ld c, a
    add d
    call nz, $bfbd
    ld hl, sp+$7f
    pop af
    sub h
    ld h, b
    rst $38
    push af
    rst $38
    add $28
    pop bc
    rst $18
    ldh [$ec], a
    ld l, c

Jump_00b_7b2e:
    inc b
    dec c
    rst $38
    call nz, Call_000_1aff
    inc [hl]
    ld d, $1e
    ld b, [hl]
    add hl, bc
    xor h
    ld d, l
    jp hl


    rrca
    add $71
    ld a, b
    ld a, b
    ld b, c
    ld sp, $4b9c
    ld de, $fc5f
    ld l, l
    inc de
    adc l
    inc e
    ld l, h
    db $76
    ret nz

    ret


    jp nz, $a744

    db $e4
    pop bc
    ld d, l
    dec l
    ret


    ld d, h
    adc c
    and h
    ld a, [de]
    ld a, [hl+]
    ld d, l
    add d
    ld h, $ae
    ld b, l
    ld b, d
    ld d, d
    rst $18
    db $fc
    ret


    add hl, de
    db $76
    jr jr_00b_7b14

    rrca
    ld sp, $517a
    ld c, b
    ld h, d
    ldh [rIE], a
    ld l, $0f
    xor l
    dec c
    adc h
    or l
    ld d, h
    jp z, $e682

    xor c
    dec h
    rst $38
    and e
    dec b
    and d
    ld [hl+], a
    ld [c], a
    cpl
    ld b, d
    ld c, e
    sub [hl]
    sub c
    sub e
    ld h, $f8
    add $2f
    ld d, d
    sub d
    add sp, -$22
    ld h, l
    sub [hl]
    ld hl, $a439
    ld d, d
    ld e, l
    add hl, sp
    add sp, $2a
    ld [hl], a
    push af
    ld a, [hl-]
    db $eb
    add sp, -$08
    ld a, c
    jr nc, jr_00b_7c0f

    add d
    ld b, d
    ld l, d
    add d
    ld b, h
    or d
    inc c
    or d
    ld sp, $5c5e
    ret


    ld d, d
    and l
    ld hl, $1954
    ld l, a
    inc b
    xor h
    rla
    db $e4
    ld b, b
    sub e
    ld h, l
    ld [hl], b
    jp $ff7b


    ld de, $4a02
    ld c, h
    inc d
    or e
    dec a
    ld a, [hl+]
    sub l
    inc h
    ld b, [hl]
    ld [hl], b
    ld e, e
    rst $38
    ld a, [$4a3c]
    ld h, b
    pop de
    rrca
    dec b
    rst $38
    db $e3
    ld h, $78
    ld b, e
    inc bc
    ld l, a
    rst $38
    pop hl
    adc h
    sbc b
    push bc
    inc a
    rst $38
    rst $38
    sbc h
    rst $30
    rst $10
    db $fd
    dec e
    ld de, $7814
    jr nc, @+$22

    ldh [$9d], a
    or c
    pop af
    ld b, b
    nop
    nop
    nop

jr_00b_7bf9:
    nop
    nop
    nop
    nop
    rst $38
    nop
    nop
    ld b, c
    xor [hl]
    inc b
    ei
    jr nz, jr_00b_7c63

    inc b
    ld [de], a
    nop

jr_00b_7c09:
    rla
    ld [bc], a
    dec d
    nop
    rla
    nop

jr_00b_7c0f:
    dec d
    ld bc, $0416
    inc de
    nop
    dec d
    inc b
    cp d
    jr nz, jr_00b_7bf9

    add d
    ld [hl], l
    nop
    ldh [rP1], a
    rst $20
    ld b, b
    xor b

jr_00b_7c22:
    nop
    add sp, $20
    ld c, b
    inc b
    cp d
    jr nz, jr_00b_7c09

    add d
    ld [hl], l
    nop
    nop
    nop
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    inc b
    cp d
    jr nz, @-$1f

    add d
    ld [hl], l
    nop
    rlca
    nop
    push hl
    ld bc, $0416
    inc de
    nop
    dec d
    nop
    xor b
    jr nz, @-$36

    add b
    ld l, b
    nop
    add sp, $00
    add sp, $40
    xor b
    nop
    add sp, $20
    ld c, b
    nop
    xor b
    jr nz, jr_00b_7c22

    add b
    ld l, b
    nop
    rst $20
    nop
    ldh [rSTAT], a
    xor [hl]
    inc b

jr_00b_7c63:
    ei
    jr nz, jr_00b_7cc3

    inc b
    ld [de], a
    nop
    rla
    ld [bc], a
    dec d
    nop
    rst $20
    nop
    dec b
    ld b, c
    xor [hl]
    inc b
    ei
    jr nz, @+$5f

    inc b
    cp d
    jr nz, @-$1f

    add d
    ld [hl], l
    nop
    rst $28
    nop
    push af
    ld b, c
    xor [hl]
    inc b
    ei
    jr nz, jr_00b_7ce3

    nop
    nop
    ld a, d
    ld a, d
    ld c, e
    ld c, e
    ld a, d
    ld a, d
    ld c, b
    ld c, b
    ld [$1108], sp
    ld de, $0000
    nop
    nop
    inc c
    inc c
    pop hl
    pop hl
    ld c, l
    ld c, l
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    adc [hl]
    adc [hl]
    nop
    nop
    nop
    nop
    ld b, e
    ld b, e
    ld hl, sp-$08
    ld c, b
    ld c, b
    ld c, b
    ld c, b
    ld c, c
    ld c, c
    sbc d
    sbc d
    nop
    nop
    nop
    nop
    sbc $de
    ld b, b
    ld b, b
    ld c, h
    ld c, h
    add b
    add b
    sbc b
    sbc b
    ld b, [hl]

jr_00b_7cc3:
    ld b, [hl]
    nop
    nop
    nop
    nop
    ld hl, sp-$08
    dec bc
    dec bc
    ld [$5308], sp
    ld d, e
    jr nz, jr_00b_7cf2

    ld de, $0011
    nop
    nop
    nop
    ld c, a
    ld c, a
    add c
    add c
    add c
    add c
    ld [c], a
    ld [c], a
    add [hl]
    add [hl]
    add hl, bc

jr_00b_7ce3:
    add hl, bc
    nop
    nop
    nop
    nop
    ld [bc], a
    ld [bc], a
    ld a, [$22fa]
    ld [hl+], a
    jr nz, jr_00b_7d10

    jr nz, jr_00b_7d12

jr_00b_7cf2:
    ld sp, hl
    ld sp, hl
    nop
    nop
    nop
    nop
    ld c, b
    ld c, b
    ld e, a
    ld e, a
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    sub e
    sub e
    nop
    nop
    nop
    nop
    jr nz, jr_00b_7d2a

Call_00b_7d0a:
    ei
    ei
    jr nz, jr_00b_7d2e

    ei
    ei

jr_00b_7d10:
    jr nz, jr_00b_7d32

jr_00b_7d12:
    inc hl
    inc hl
    nop
    nop
    nop
    nop
    ld [$be08], sp
    cp [hl]
    and d
    and d
    add d
    add d
    add d
    add d
    adc h
    adc h
    nop
    nop
    nop
    nop
    jr nz, jr_00b_7d4a

jr_00b_7d2a:
    ld a, [$22fa]
    ld [hl+], a

jr_00b_7d2e:
    jr nz, jr_00b_7d50

    jr nz, jr_00b_7d52

jr_00b_7d32:
    pop bc
    pop bc
    nop
    nop
    nop
    nop
    ld [bc], a
    ld [bc], a
    xor d
    xor d
    and [hl]
    and [hl]
    ld [hl+], a
    ld [hl+], a
    ld b, l
    ld b, l
    adc b
    adc b
    nop
    nop
    nop
    nop
    ld b, b
    ld b, b

jr_00b_7d4a:
    ld a, [$4afa]
    ld c, d
    ld c, b
    ld c, b

jr_00b_7d50:
    ld c, b
    ld c, b

jr_00b_7d52:
    sbc c
    sbc c
    nop
    nop
    nop
    nop
    rrca
    rrca
    and b
    and b
    xor a
    xor a
    ld hl, $4121
    ld b, c
    adc [hl]
    adc [hl]
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Jump_00b_7d6b:
    nop
    ld a, e
    ld a, e
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sbc $de
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
    dec b
    dec b
    ld [de], a
    ld [de], a
    ld a, h
    ld a, h
    db $10
    db $10
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    nop
    nop
    nop
    nop
    nop
    nop
    add e
    add e
    ld sp, hl
    ld sp, hl
    sub e
    sub e
    ld de, $2011
    jr nz, jr_00b_7da5

jr_00b_7da5:
    nop
    nop
    nop
    nop
    nop
    ldh [$e0], a
    inc c
    inc c
    ldh [$e0], a
    ld bc, $ee01
    xor $00
    nop
    ld bc, $0101
    ld bc, $0000
    add l
    add l
    add l
    add l
    ld [$0808], sp
    ld [$0000], sp
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    nop
    nop
    nop
    nop
    ld a, [hl+]
    ld a, [hl+]
    xor d
    xor d
    add d
    add d
    inc c
    inc c
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ret nz

    ret nz

    ld [$c808], sp
    ret z

    db $10
    db $10
    ldh [$e0], a
    nop
    nop
    nop
    nop
    nop
    nop
    jr c, jr_00b_7dec

jr_00b_7dec:
    ld a, h
    nop
    ld a, h
    nop
    ld a, h
    nop
    jr c, jr_00b_7df4

jr_00b_7df4:
    nop
    nop
    nop

jr_00b_7df7:
    nop
    db $fc
    jr nc, jr_00b_7df7

    ld [de], a
    db $fc
    ld [de], a
    db $fc
    ld [de], a
    db $fc
    ld [de], a
    db $fc
    ld [bc], a
    nop
    ld a, [hl]
    nop
    nop
    db $fc
    ld [hl], b
    db $fc
    ld [de], a
    db $fc
    ld [hl], d
    db $fc
    ld b, d
    db $fc
    ld [hl], d
    db $fc
    ld [bc], a
    nop
    ld a, [hl]
    nop
    nop
    db $fc
    ld [hl], b
    db $fc
    ld [de], a
    db $fc
    ld [hl], d
    db $fc
    ld [de], a
    db $fc
    ld [hl], d
    db $fc
    ld [bc], a
    nop
    ld a, [hl]
    nop
    nop
    db $fc
    ld d, b
    db $fc
    ld d, d
    db $fc
    ld [hl], d
    db $fc
    ld [de], a
    db $fc
    ld [de], a
    db $fc
    ld [bc], a
    nop
    ld a, [hl]
    nop
    nop
    db $fc
    ld [hl], b
    db $fc
    ld b, d
    db $fc
    ld [hl], d
    db $fc
    ld [de], a
    db $fc
    ld [hl], d
    db $fc
    ld [bc], a
    nop
    ld a, [hl]
    nop
    nop
    db $fc
    ld [hl], b
    db $fc
    ld b, d
    db $fc
    ld [hl], d
    db $fc
    ld d, d
    db $fc
    ld [hl], d
    db $fc
    ld [bc], a
    nop
    ld a, [hl]
    nop
    nop
    db $fc
    ld [hl], b
    db $fc
    ld [de], a
    db $fc
    ld [de], a
    db $fc
    ld [de], a
    db $fc
    ld [de], a
    db $fc
    ld [bc], a
    nop
    ld a, [hl]
    nop
    nop
    db $fc
    ld [hl], b
    db $fc
    ld d, d
    db $fc
    ld [hl], d
    db $fc
    ld d, d
    db $fc
    ld [hl], d
    db $fc
    ld [bc], a
    nop
    ld a, [hl]

Jump_00b_7e76:
    ld a, [$cf79]
    ld hl, $d133
    ld bc, $002c
    call Call_000_3ad1
    ld a, [$d0bd]
    ld b, a
    ld c, $04

jr_00b_7e88:
    ld a, [hl+]
    cp b
    jr z, jr_00b_7e91

    dec c
    jr nz, jr_00b_7e88

    and a
    ret


jr_00b_7e91:
    ld hl, $7e99
    call Call_000_3c79
    scf
    ret


    db $ed
    add hl, hl
    db $e4
    ld h, a
    jp z, $bd7f

    inc sp
    add $4f
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    or l
    ld a, $b4
    jp $cfb2


    cp l
    ld e, b
    ld a, [$d038]
    and $7f
    cp $0a
    ret z

    ld hl, $7ec5
    jr nc, jr_00b_7ec2

    ld hl, $7ed2

jr_00b_7ec2:
    jp Jump_000_3c79


    db $ed
    add hl, hl
    ld bc, $ca68
    ld a, a
    ld a, [hl-]
    jp nz, $de28

    jr nc, @-$17

    ld e, b
    db $ed
    add hl, hl
    inc hl
    ld l, b
    jp z, $b27f

    rst $08
    set 0, h
    jp nz, Jump_00b_7fc9

    sub $b3
    jr nc, jr_00b_7f3b

    ld de, $a203
    ld hl, $a187
    call Call_00b_7f20
    call Call_00b_7ef8
    ld de, $a38b
    ld hl, $a30f
    call Call_00b_7f20

Call_00b_7ef8:
    ld b, $03

jr_00b_7efa:
    ld c, $1c

jr_00b_7efc:
    push bc
    ld a, [de]
    ld bc, $ffc9
    call Call_00b_7f3a
    ld a, [de]
    dec de
    swap a
    ld bc, $0037
    call Call_00b_7f3a
    pop bc
    dec c
    jr nz, jr_00b_7efc

    dec de
    dec de
    dec de
    dec de
    ld a, b
    ld bc, $ffc8
    add hl, bc
    ld b, a
    dec b
    jr nz, jr_00b_7efa

    ret


Call_00b_7f20:
    ld a, $1c
    ldh [$8b], a
    ld bc, $ffff

jr_00b_7f27:
    ld a, [de]
    dec de
    swap a
    call Call_00b_7f3a
    ldh a, [$8b]
    dec a
    ldh [$8b], a
    jr nz, jr_00b_7f27

    dec de
    dec de
    dec de
    dec de
    ret


Call_00b_7f3a:
    push hl

Call_00b_7f3b:
jr_00b_7f3b:
    and $0f
    ld hl, $7f4b
    add l
    ld l, a
    jr nc, jr_00b_7f45

    inc h

jr_00b_7f45:
    ld a, [hl]
    pop hl
    ld [hl-], a
    ld [hl], a
    add hl, bc
    ret


    nop
    inc bc
    inc c
    rrca
    jr nc, @+$35

    inc a
    ccf
    ret nz

    jp $cfcc


    ldh a, [$f3]
    db $fc
    rst $38
    xor a
    ld hl, $cd68
    ld [hl+], a
    ldh a, [$f3]
    and a
    ld a, [$d009]
    jr z, jr_00b_7f6b

    ld a, [$cfda]

jr_00b_7f6b:
    add a
    ldh [$98], a
    xor a
    ldh [$95], a
    ldh [$96], a
    ldh [$97], a
    ld a, $64
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$98]
    ld [hl+], a
    ldh a, [$99]
    ldh [$98], a
    ld a, $0a
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$98]
    swap a
    ld b, a
    ldh a, [$99]
    add b
    ld [hl], a
    ld de, $cce7
    ld c, $03
    ld a, $0b
    call Call_000_3e9d
    ld hl, $7fa7
    jp Jump_000_3c79


    db $ed
    add hl, hl
    ld b, h
    ld l, b
    ld h, $7f
    or c
    ret nz

    ret c

    add $7f
    pop bc
    rst $10
    ld a, [hl-]
    rst $18
    ret nz

    rst $20
    ld e, b
    ld a, [$c102]
    and $08
    jr z, jr_00b_7fde

    ld b, $45
    ld a, $1c
    call Call_000_3e9d
    ld a, b
    and a

Jump_00b_7fc9:
    ld b, $33
    jr z, jr_00b_7fd6

    ld hl, $d523
    ld a, [hl+]
    or [hl]
    jr nz, jr_00b_7fde

    ld b, $32

jr_00b_7fd6:
    call Call_000_3c6c
    ld a, b
    call Call_000_3f25
    xor a

jr_00b_7fde:
    ld [$cd3d], a
    ret


    db $ed
    inc l
    sub e
    ld l, [hl]
    adc b
    db $e3
    adc h
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $b2c5


    rst $20
    ld d, a
    db $ed
    dec l
    sbc $5b
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $b2c5


    rst $20
    ld d, a
    ld a, c
