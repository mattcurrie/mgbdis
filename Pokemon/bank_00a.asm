; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $00a", ROMX[$4000], BANK[$a]

    ld d, l
    cp [hl]
    ld [hl], c
    ld d, h
    push hl
    ld d, h
    sub $c1
    add hl, bc
    add hl, hl
    db $fd
    inc b
    sub a
    sub b
    sub e
    inc h
    inc d
    db $10
    or h
    ld e, $22
    db $ed
    ld b, [hl]
    or b
    ld c, h
    ld d, $06
    ld l, $f3
    ld a, [hl+]
    xor e
    add e
    add hl, hl
    db $e4
    dec hl
    ld b, [hl]
    adc b
    adc l
    ld a, [hl+]
    ld d, $32
    ld d, h
    ld d, c
    and e
    ld [hl], l
    xor [hl]
    dec [hl]
    adc b
    ld e, b
    inc h
    call $63a0
    dec d
    rlca
    ld c, h
    db $e3
    ld b, $1a
    ld l, c
    inc [hl]
    ld c, l
    inc h
    ld a, d
    ld [hl-], a
    ld c, h
    dec d
    adc b
    ld d, e
    add hl, hl
    ld [hl], c
    ld d, h
    ld l, d
    ld [hl-], a
    cp l
    ld h, c
    and l
    inc sp
    add l
    ld c, [hl]
    ld [$e4b7], sp
    push bc
    rrca
    adc [hl]
    ld d, a
    adc c
    and h
    cp d
    inc a
    inc d
    ldh [$4e], a
    add a
    dec [hl]
    ld h, e
    sbc l
    adc c
    ld e, d
    xor d
    and e
    add [hl]
    jp nc, $d8aa

    db $ed
    cp l
    ld e, a
    db $e3

jr_00a_406e:
    add d
    ld a, h
    ld a, [$8878]
    and $58
    ld b, [hl]
    ld e, a
    and [hl]
    adc e
    ld b, $6e
    add d
    inc [hl]
    add hl, bc
    and a
    call nz, $a624
    ld e, [hl]
    rra
    ld a, [$6061]
    adc h
    ld [hl-], a
    and c
    ld h, $0f
    pop hl
    ld d, b
    dec h
    xor a
    add sp, $30
    pop hl
    db $e3
    ld a, [hl+]
    cp a
    rst $30
    xor $97
    cp $1f
    rst $38
    cp $8d
    rst $38
    ldh a, [$7f]
    ld d, c
    add l
    pop bc
    or a
    rst $38
    ld hl, sp+$7f
    rst $38
    jr z, jr_00a_406e

    jp hl


    add [hl]
    rra
    pop hl
    ld a, l
    inc bc
    or a
    ldh [$87], a
    ld b, d
    rst $38
    jr jr_00a_4105

    pop af
    dec hl
    rst $38
    or l
    jr nc, jr_00a_413c

    rst $18
    and $51
    sub l
    ld d, b
    cp [hl]

Call_00a_40c4:
    cpl
    cp $14
    ld [hl], d
    jp hl


    rra
    pop bc
    rst $38
    db $ec
    ld [hl], h
    ld e, [hl]
    sub e
    db $fd
    ld a, a
    and a
    ld b, a
    ld a, [$e43f]
    ld d, l
    ld sp, $ffc9
    cp $a1
    ld b, h
    or c
    jp $ffab


    push de
    dec e
    or a
    rst $38
    db $fc
    ld a, b
    ld d, l
    inc e
    add b
    ld b, h
    cp l
    and l
    ld d, e
    add c
    db $d3
    rla
    xor d
    scf
    and b
    ld d, d
    add sp, -$1e
    ld a, b
    and l
    ld d, a
    sub e
    sub l
    ld b, d
    ld sp, $3495
    and c
    sbc b
    add [hl]
    sub e

jr_00a_4105:
    and c
    ld c, c
    ld l, b
    db $e3
    ld d, [hl]
    cpl
    ld b, l
    xor d
    sub e
    ld e, c
    ld d, c
    ld b, d
    ld e, $3a
    ld a, [hl+]
    add [hl]
    sbc l
    ld a, [hl-]
    dec d
    ld e, $0b
    ld c, [hl]
    ld [hl], l
    ld [c], a
    xor a
    rst $08
    and h
    rst $18
    dec sp
    inc e
    ld c, c
    and e

Jump_00a_4125:
    dec de
    xor e
    add hl, de
    pop af
    jp z, Jump_00a_5583

    inc hl
    xor d
    ld l, e
    dec bc
    inc [hl]
    ld c, $44
    jp nc, Jump_00a_4471

    call nz, $29a8
    or d
    ld d, a
    ld [de], a

jr_00a_413c:
    call nz, $b5e9
    inc b
    db $db
    ld c, c
    call c, $9283
    rst $00
    dec hl
    adc h
    ld c, [hl]
    ld [hl], h
    add $15

jr_00a_414c:
    rra
    ld c, b
    ld [hl], a
    cp c
    dec d
    dec l
    ld a, a
    sub l
    inc a
    ld l, a
    rst $28
    ld e, a
    and c
    cp a
    or h
    ldh a, [$97]
    ld e, c
    ld l, a
    push af
    ld l, e

jr_00a_4161:
    db $eb
    cp a
    call nc, $a8ea
    ld e, $a9
    xor e
    ld e, d
    ld l, $96
    or h
    ldh [rHDMA5], a
    ld d, b
    xor l
    ld [c], a
    db $10
    or l
    add [hl]
    ld c, h
    jp hl


    scf
    ld a, e
    ld e, e
    and b
    ld b, l
    rlca
    add $25
    jp nz, $81c3

    ld e, d
    or b
    ld c, l
    add hl, hl
    or c
    ld c, b
    ld b, l
    rst $38
    ld hl, $2156
    ld h, l
    adc d
    add d
    ld [hl], $48
    and d
    ld [hl+], a
    and b
    adc h
    sbc b
    ld a, [hl+]
    ld hl, $2468
    db $e3
    ld c, [hl]
    call $828a
    inc [hl]
    ld b, c
    ld l, b
    ldh [$64], a
    call Call_00a_5829
    push de
    ld h, l
    inc e
    and l
    ld d, l
    ld h, d
    dec h
    ld hl, $5a6b
    adc [hl]
    ld a, [bc]

jr_00a_41b4:
    ld d, l
    and d
    or e
    ld a, d
    adc [hl]
    cp [hl]
    ld [hl+], a
    jr nc, jr_00a_414c

    ld b, d
    dec a
    ld a, [hl+]
    dec d
    ld sp, $cad3
    cp b
    sub $4f
    dec h
    ld h, e
    ld d, l
    jr c, jr_00a_4161

    ld d, l
    db $fd
    ld c, l
    and h
    db $eb
    ld a, [hl]
    and h
    add l
    dec bc
    adc h

jr_00a_41d6:
    sub h
    add h
    ret


    ld [$4dd5], sp
    jr z, jr_00a_4206

    jp z, Jump_00a_5ad0

    xor b
    cp b
    push bc
    ld d, b
    sub [hl]
    and h
    add $08
    adc $d5
    ld h, $2e
    ld d, l
    ld l, [hl]
    and d
    ld a, c
    inc [hl]
    and e

jr_00a_41f3:
    ld e, l
    ld a, [$4a81]
    ld l, c
    ld h, b
    ld h, d
    jr nc, jr_00a_41b4

    add [hl]
    dec bc
    ld a, [de]
    jr c, jr_00a_426b

    sbc [hl]
    sub c
    ld c, c
    db $e3
    add hl, de

jr_00a_4206:
    ld l, b
    ld a, h
    adc b
    jp c, Jump_00a_5089

    sub l
    ld h, [hl]
    ld l, b
    ret


    inc b
    sbc d
    inc c
    jr z, jr_00a_41f3

jr_00a_4215:
    sub $30
    sub h
    pop bc
    ld c, b
    ld a, b
    add a
    add hl, bc
    ld a, [de]
    jr c, jr_00a_4289

    ld d, l
    push bc
    and c
    ld b, e
    ld [$881d], sp
    ld a, b
    ld a, [hl+]
    ld d, $3a
    ld l, d

Call_00a_422c:
    db $fc
    inc [hl]
    ld e, a
    and d

Call_00a_4230:
    sub a
    push de
    ld h, e
    pop bc
    xor d
    adc l
    ld a, [hl+]
    ld a, [bc]
    jr nc, jr_00a_41d6

    adc c
    or d
    add hl, hl
    db $e4
    and [hl]
    ld [$6978], a
    ld d, h
    sbc b
    dec a
    ld a, [hl+]
    ld c, h
    db $76
    ld b, h
    cp e
    add a
    xor b
    ld a, [hl-]
    rra
    rst $30
    xor c
    add hl, hl
    call nz, $bf98
    ld hl, sp+$3a
    rst $38
    pop hl
    ld b, c
    ld a, a
    db $f4
    sbc h
    ld l, e
    db $e4
    cp a
    cp $1f
    rst $38
    jr nc, jr_00a_4285

    ld a, [bc]
    rst $38
    add d
    sbc d
    ld b, d
    rst $18
    inc de

jr_00a_426b:
    or a
    rst $38
    add l
    ld d, d
    jr jr_00a_4215

    ld a, a
    pop af
    call nz, Call_00a_78fb
    ccf

Jump_00a_4277:
    db $ed
    ld d, d
    ccf
    cp $0a
    add a
    db $f4
    ld l, $6f
    db $fd
    ld a, $17
    cp $44

jr_00a_4285:
    ld de, $6f15
    rst $28

jr_00a_4289:
    ld [bc], a

Jump_00a_428a:
    cp a
    dec de
    set 7, b
    ld a, b
    rst $18
    add hl, de
    ld a, a
    cp $2f
    call nc, Call_00a_5f72
    bit 0, a
    dec b
    ld b, a
    ld d, h
    ld a, [hl+]
    sub b
    and a
    sbc a
    rst $38
    pop hl
    cp $79
    xor a
    cp $1b
    ld d, d
    ld a, c
    or a
    db $d3
    db $fc
    rst $20
    and c
    ld l, l
    add l
    ld de, $9427
    sub b
    sbc c
    and a
    ld h, h
    add hl, bc
    xor a
    or e
    ld [hl-], a
    ld b, e
    sbc h
    inc c
    ld b, h
    jp z, $192b

    pop bc
    ei
    ld d, h
    db $10
    ld a, [hl]
    ld l, [hl]
    sub h
    db $ed
    ld b, $46

jr_00a_42cc:
    ld l, e
    ld [hl], e
    rst $38

jr_00a_42cf:
    add a
    inc e
    ld d, h
    ld b, h
    cp $1e
    sbc e
    pop bc
    ld e, a
    db $fc
    ld d, d
    ld d, h
    ld d, d
    adc h
    adc a
    pop bc
    ld de, $f1e6

jr_00a_42e2:
    ld c, [hl]
    sub d
    and $0a
    or b
    cp b
    push bc
    ld sp, $0fba
    rst $38
    ld a, $85
    ld a, [$ff8f]
    adc a
    jr jr_00a_4346

    push bc
    rst $38
    ld b, e
    ld d, d
    ld b, h

jr_00a_42fa:
    rrca
    add a
    cp $1c
    ld h, e
    add hl, sp
    push bc
    ld c, a
    and e
    db $ed
    ld a, $16
    dec bc
    ld h, [hl]
    ld a, [hl+]
    db $10
    ld h, a
    ld d, l
    ld c, a
    add h
    cp b
    ld a, l
    inc d
    jp Jump_00a_787e


    ld [hl], l
    ld b, [hl]
    sub l
    dec b
    rra
    nop
    ld b, h
    cp l
    sub l
    ld d, e
    xor c
    ld a, [$81d3]
    ld d, l
    ld c, b
    and d
    jr z, jr_00a_42cc

    jr nc, jr_00a_439d

    xor c
    add d
    sbc d
    jr nc, jr_00a_42e2

    add a
    sbc [hl]
    sub e
    add hl, sp
    ld c, c
    or [hl]
    jp c, $8a7c

    xor b
    ldh [$b6], a
    ld l, c
    ld h, h
    cp c
    jr c, jr_00a_4367

    ld a, [hl]
    jr jr_00a_42fa

    pop hl
    and b
    adc e
    sub l

jr_00a_4346:
    adc e
    ld d, e
    jr c, jr_00a_42cf

    dec [hl]
    db $d3
    ld l, c
    add $7d
    ld [hl+], a
    ld b, [hl]
    jr c, jr_00a_43c2

    db $dd
    jp nc, $e718

    and d
    dec hl
    ld a, b
    ld hl, sp-$63
    db $ec
    and d
    sbc l
    or b
    rst $20
    ld [bc], a
    ld c, d
    ld h, l
    inc e
    jr nc, jr_00a_43db

jr_00a_4367:
    ld [$8c6a], sp
    ld h, c
    and [hl]
    ld c, a
    xor e
    sub e

Call_00a_436f:
    ld e, d
    sub a
    ld l, c
    jr z, jr_00a_43f1

    ld d, l
    ld d, $b1
    adc l
    and c
    inc b
    and l
    jp c, Jump_000_1a0f

    push bc
    ld e, c
    ld [hl], l
    jp hl


    cp l
    and h
    ld l, $ad
    and c
    ld d, l
    ld a, [de]
    ld b, c
    db $fd
    and c
    ld d, d
    ld [hl-], a
    sbc h
    ld d, $32
    inc d
    inc [hl]
    sbc h
    xor h
    ret c

    jp z, $9d0e

    sub h
    inc e
    ld a, h
    ld c, b

jr_00a_439d:
    ld [hl], a
    cp b
    ld d, d
    push de
    db $fd
    ld c, a

Call_00a_43a3:
    dec d
    rla
    push hl
    cp $f6
    sub a
    rst $38
    push de
    dec d
    add hl, sp
    push de
    push hl
    ld l, c
    ld a, l
    xor d
    dec d
    ld d, l
    rst $38
    db $f4
    db $e4
    ld b, c
    ld b, d
    jr jr_00a_4419

    adc b
    ld d, [hl]
    and d
    sub $6d
    jr c, @-$29

jr_00a_43c2:
    ld c, h
    ld h, b
    ld e, d
    add c
    ld e, d
    or b

Call_00a_43c8:
    ld e, b
    dec e
    rst $18
    adc $05
    add hl, bc
    dec l
    cp l
    xor d
    sub $ae
    add c
    cp b
    ld h, b
    adc [hl]
    inc d
    ld e, [hl]
    adc d
    and d

jr_00a_43db:
    cp h
    add l
    add l
    sbc b
    rst $20
    ld b, e
    ld d, b
    adc b
    ld a, l
    dec h
    ld l, c
    ld h, c
    ld e, l
    adc [hl]
    adc d
    jr jr_00a_43fd

    sbc [hl]
    cp l

jr_00a_43ee:
    ld d, l
    and c
    ld a, a

jr_00a_43f1:
    ld c, l
    inc de
    adc d
    ld [hl], l
    ld b, e
    db $fc
    ld hl, $17c3
    sbc c
    inc [hl]
    xor b

jr_00a_43fd:
    inc de
    daa
    jr jr_00a_442f

    xor a
    ld b, e
    dec h
    ld d, [hl]
    ld a, [bc]
    ld h, e
    ld c, d
    ld b, d
    and e
    inc [hl]
    ld d, l
    ld a, [c]
    ld [hl+], a
    ld h, a
    ld a, [bc]
    sub $35
    and h
    ld h, l
    ld sp, $bfef
    di
    dec c

jr_00a_4419:
    ld a, b
    push bc
    ld c, e
    ld a, c
    ld e, c
    ld c, h
    and [hl]
    push de
    ld [hl-], a
    ld e, d
    ld hl, $7d48
    add hl, hl
    ld b, [hl]
    ld b, $0d
    inc sp
    or [hl]
    adc c
    ld c, c
    ld c, c

jr_00a_442f:
    ld l, h
    add h
    inc d
    ld d, l
    ld [c], a
    ld h, c
    ld a, [$c533]
    ld h, a
    ld a, [c]
    ld l, d
    rst $28
    call nc, Call_00a_4230
    ret c

    add l
    add l
    add c
    ld c, l
    inc hl
    inc c
    pop bc
    rrca
    jr nc, jr_00a_44a2

    sub h
    ld e, d
    dec d
    dec h
    jp nc, $68ea

    inc h
    jp nz, $a618

    ld hl, $6260
    dec de
    push bc
    push af
    jr nc, jr_00a_43ee

    sub b
    adc l
    ld d, [hl]
    add l
    and l
    and c
    ld l, b
    adc e
    db $e4
    inc de
    add hl, sp
    rlca
    ld c, h
    ld d, l
    ld d, d
    xor d

jr_00a_446d:
    dec d
    and d
    ld d, [hl]
    ld e, a

Jump_00a_4471:
    ld c, [hl]
    dec h
    ld e, d
    and c
    ld a, b
    pop bc
    and c
    ld d, [hl]
    and b
    ei
    and e
    ld a, d
    dec l
    ld e, d
    and d
    dec d
    ld a, l
    ld l, d
    jr nc, jr_00a_44dd

    inc [hl]
    rst $20
    sub l
    ld e, l
    ld e, [hl]
    and e
    dec d

Jump_00a_448c:
    ld d, [hl]
    ld d, l
    db $d3
    ld a, d
    ld c, l
    ld l, e
    db $e4
    db $10
    ld b, c
    ld sp, hl
    ld b, $a0
    ld e, [hl]
    jr c, jr_00a_446d

    ld d, l
    ld e, d
    and d
    ld h, b
    cp e
    sbc [hl]
    ld a, [bc]

jr_00a_44a2:
    cp [hl]
    adc [hl]
    ld a, [de]
    and b
    ld [hl], h
    add hl, hl
    add hl, sp
    sub l
    db $d3
    adc [hl]
    push de
    ld e, d
    sub [hl]
    xor c
    ld c, l
    cp h

jr_00a_44b2:
    ccf
    adc [hl]
    ld l, b
    ld d, l
    xor e
    db $fd
    ld a, l
    sub l
    ld d, [hl]
    xor d
    scf
    sbc l
    ld [$27c4], sp
    adc d
    sub c
    call nz, Call_000_086a
    add $30
    and h
    daa
    ld a, [hl-]
    add e
    set 7, l
    xor e
    inc h
    add hl, hl
    ld c, b
    or c
    jp z, $ff8b

    cp $ff
    db $ec
    ld de, $1c9b
    ret z

jr_00a_44dd:
    cp a
    rst $38
    rst $38
    ret nc

    xor d
    ld d, h
    ld b, e
    dec e
    rrca

jr_00a_44e6:
    rst $18
    rst $38

jr_00a_44e8:
    ld c, e
    rst $38
    push de
    inc d
    pop af
    jp nc, $1ff1

    rst $38
    rst $38
    ld [$0b91], a
    rst $00
    ld e, a
    ld b, e
    db $fc
    or a
    rst $38
    ret nc

    ld b, b
    or h
    db $76
    db $e4
    db $fd
    ld b, c
    ld l, l
    ld b, h
    xor h
    ld a, b
    jr z, jr_00a_44b2

    rst $10
    bit 3, b
    cpl
    cpl
    dec e
    di
    xor l
    ld a, d
    cp $08
    ld d, h
    call c, $2070
    sbc d
    rst $08
    ld d, l
    ld de, $115e
    rra
    sbc h
    ld c, b
    inc hl
    add hl, de
    xor e
    rst $38
    ld c, e
    pop af
    dec bc
    ld e, c
    cp d
    jr z, jr_00a_456e

    ld a, [de]
    xor d
    rst $10
    db $f4
    xor a
    ei
    pop de
    add $c2
    sbc d
    set 2, h
    add a
    rst $38
    db $fc
    ld d, d
    ld de, $448a
    jr z, jr_00a_44e6

    sub h
    ld b, e
    ccf
    ld d, l
    xor a
    ld c, c
    jr jr_00a_44e8

    add d
    jr jr_00a_456f

    jr nc, @-$58

    db $eb
    pop hl
    pop hl
    rst $38
    rst $38
    ld e, b
    call z, $fe17
    ret nz

    or d
    ld [hl], d
    ld a, b
    ld a, a
    xor a
    db $fd
    ld a, b
    ld h, h
    inc sp
    rst $38
    inc bc
    call z, $9966
    db $db
    ld a, a
    ld hl, sp+$56
    xor h
    ld [de], a
    db $fd
    ld [bc], a
    rst $38

jr_00a_456e:
    add h

jr_00a_456f:
    ld d, e
    ld a, [bc]
    ld l, a
    inc bc
    rst $38
    ld b, d
    xor e
    ld a, a
    rst $38
    rst $38
    sub h
    add h
    add hl, bc
    call nz, Call_000_3c9a
    rst $38
    rst $38
    db $f4
    ld a, [bc]
    call c, $cbd1
    ld [de], a
    and c
    ld c, d
    rst $38
    push af
    dec hl
    rst $38
    di
    inc b
    ld d, d
    ld [hl], b
    dec h
    call nz, Call_00a_57bd
    rst $38
    rst $38
    db $fd
    ld d, c
    jr nc, jr_00a_45e1

    ldh a, [$66]

jr_00a_459d:
    cp a
    ld c, a
    rst $38
    ld a, [$12ab]
    sbc h
    adc b
    and [hl]
    ld [de], a
    cp a
    rst $38
    rst $38
    rst $38
    db $f4
    ld [hl], e
    ld [hl], b
    ld hl, $6921
    rla
    rst $38
    rst $38
    ld d, l
    ld b, d
    xor c
    call Call_00a_4c0c
    ld [$a156], sp
    ld d, a
    rst $38
    push af
    ld e, c
    db $db
    ld b, h
    call nz, $0c75
    ld d, h
    ld [hl], c
    add b
    ld b, h
    cp b
    ld d, l
    ld l, a
    ld [$158e], a
    or $a8
    jr jr_00a_459d

    ld d, d
    sbc $96
    xor d
    adc h
    ld a, [c]
    inc h
    ld e, [hl]
    ld b, $5a
    xor d
    xor d
    ld d, d

jr_00a_45e1:
    and l
    add hl, de
    ld c, b
    ld [hl], h
    ld [c], a
    ld l, d
    inc [hl]
    sub e
    add d
    ld d, d
    sub d
    ld [de], a
    ld h, e
    add a
    ld c, d
    ld e, b
    rst $20
    ld h, e
    ld e, $c1
    or h
    sbc $55
    ld l, $55
    dec bc
    ld d, e
    add [hl]
    or d
    ld de, $6b9e
    ld c, [hl]
    add hl, de
    ld h, d
    db $eb
    and b
    sub e
    or d
    sub h
    inc hl
    cp [hl]
    adc a
    add l
    sbc h
    xor d
    xor d
    and a
    ld a, [de]
    rst $38
    rst $38
    rst $38
    sbc h
    rrca
    db $fd
    dec l
    ld d, l
    ld a, c
    ld d, a
    and h
    cp a
    rst $00
    dec a
    and b
    cp $9c
    xor d
    xor h
    ld b, a
    cp $9c
    sub h
    pop hl
    rst $38
    rst $38
    sbc h
    ld [hl], l
    jr c, jr_00a_468f

Jump_00a_4630:
    rst $10
    sbc h
    ld l, e
    di
    xor h
    sub c
    daa
    dec l
    ld c, l
    ret nz

    sub c
    daa
    inc sp
    call nz, $85c0
    and a
    ld a, l
    ld l, c
    ldh [$c7], a
    db $d3

Jump_00a_4646:
    nop
    ld d, l
    cp a
    ld [$1479], sp
    reti


    ld c, [hl]
    inc h
    ld d, b
    cp d
    ld d, h
    add $8d
    jp c, $91d0

    ld a, d
    xor a
    ld d, d
    ld d, $0e
    inc [hl]
    ld b, d
    ld h, b
    ld b, d
    and e
    rrca
    sub d
    ld l, d
    inc [hl]
    cp b
    adc b
    db $10
    ld h, d
    jp hl


    db $fc
    ld a, [hl-]
    scf
    ld h, d
    and c
    ld c, d
    jp nc, Jump_000_1328

    ld l, l
    inc b
    jp z, $6f64

    jr @-$79

    inc sp
    ld d, c
    ld c, h
    rra
    reti


    jr nc, @+$7f

    inc [hl]
    ld h, h
    ld [de], a
    ld [c], a
    inc l
    dec d
    dec h
    ld e, b
    sub $22
    ld c, h
    xor c
    ld d, d
    ld l, c

jr_00a_468f:
    ld c, [hl]
    inc [hl]
    and l
    or h
    ld l, c
    sbc d
    adc [hl]
    sbc e
    ld b, [hl]
    add [hl]
    ld hl, $354e
    ld [hl], d
    xor b
    ld l, b
    ld h, b
    ld c, [hl]
    scf
    xor a
    ld d, [hl]
    ld b, d

Jump_00a_46a5:
    add [hl]
    adc b
    ld a, b
    pop hl
    ld a, a
    push af
    db $eb
    sub l
    ld e, a
    add d
    adc [hl]
    ld e, d
    and d
    ld h, b
    xor b
    db $f4
    and a
    pop hl
    ld d, c
    push hl
    xor c
    call c, $b582
    inc b
    ld l, h
    add d
    ld [hl], b

Call_00a_46c1:
    ld a, a
    dec de
    ld c, b
    cp d
    ld [hl], b
    ld a, h
    jr nc, jr_00a_4714

    ld h, h
    xor d
    inc de
    ld a, c
    pop bc
    ld b, $1a
    ld b, e
    ld a, [$58f8]
    call z, $f870
    ld a, a
    rst $38
    ret nc

    ld a, [hl]
    add h
    ld sp, $70c3
    ld e, a

Jump_00a_46e0:
    cp $fe
    sbc $73
    call nz, $ff5f
    rst $38
    rlca
    jr z, @+$22

    adc h
    ld [hl], c
    db $dd
    rst $38
    add a
    xor l
    ld sp, hl
    ld sp, $37c9
    ld l, [hl]
    rst $18
    add a
    inc a
    ld [hl], e
    add sp, $6d
    db $fd
    ld hl, sp+$7f
    inc e
    db $ec
    rra
    rst $18
    rst $18
    add [hl]
    sbc h
    adc d
    add hl, hl
    rla
    rst $18
    sbc $74
    ld e, b
    db $e4
    push de
    ld [hl], b
    ld b, a
    res 0, b
    ld b, h

jr_00a_4714:
    cp [hl]
    ld [hl], c
    add hl, sp
    ld d, h
    sub l

jr_00a_4719:
    ld l, b
    push hl
    and b
    sbc d
    ld a, [hl-]
    inc e
    inc d
    dec de
    ld a, [hl-]
    rla
    ld h, b
    and e
    xor l
    or e
    or [hl]
    di
    ret nz

    sub b
    ld b, c
    dec d
    ld a, [hl-]
    ld l, a
    cp l
    ld a, h
    add sp, -$0a
    ld l, d
    adc [hl]
    sbc b
    ld a, [$f7cd]
    ld c, e
    inc e
    or h
    dec hl
    ld d, c
    call z, $d9a8
    push de
    dec [hl]
    jr jr_00a_477e

    ret


    ld a, c
    adc h
    ld [hl], d
    ret z

    xor d
    db $76
    call nz, Call_00a_6a68
    ld [hl], l
    ld l, e
    ld b, b
    sbc l
    jr c, jr_00a_4719

    ld b, a
    ldh [$a0], a
    ld d, l
    cp d
    call nc, $54e2
    pop de
    ld d, c
    ld h, b
    xor [hl]
    ld c, h
    sub a
    ld [$07d3], a
    ld b, [hl]
    sbc d
    inc d
    ld h, h
    jp nz, $9bb4

    ld c, d
    ld d, h
    inc d
    jp z, Jump_00a_5221

    xor b

jr_00a_4774:
    and l
    dec l
    adc d
    ld c, e
    ld l, [hl]
    call z, $ce28
    adc c
    and b

jr_00a_477e:
    add l
    add hl, hl
    and e
    ld a, [de]
    ld h, $81
    bit 1, c
    ld d, e
    add hl, bc
    scf
    ld l, b
    and [hl]
    ld e, c
    inc d
    db $10
    adc b
    adc h
    db $f4
    add l
    ld a, [de]

Jump_00a_4793:
    ld [hl+], a
    jp nz, Jump_00a_6304

    adc d
    db $f4
    cp a
    dec bc
    ld e, b
    ld h, l
    ld h, e
    adc d
    ld a, [c]
    ld l, b
    ld e, $cc
    ld a, [hl+]
    ld b, c
    scf
    di
    dec b
    dec d
    ld d, l
    adc c
    or h
    ret


    ld h, $26
    add sp, $18
    pop de
    xor b
    ldh [rOBP1], a
    xor b
    pop de
    add l
    inc sp
    adc e
    ld c, l
    ld l, d
    and d
    sub e
    jr c, jr_00a_4774

    call $921d
    inc d
    jp nc, $924a

    ret c

    dec e
    ld l, b
    ld h, e
    add d
    ld c, d
    and [hl]
    and d
    jr nz, @-$74

    db $fc
    ldh [$a5], a
    ld c, [hl]
    dec h
    ld c, [hl]
    ld e, d
    xor d
    ld d, l
    ld d, l
    ld e, d
    add a
    ld a, h
    inc de
    rst $20
    ld l, $64
    sub $33
    adc [hl]
    add hl, hl
    call nc, Call_000_04bd
    ld h, b
    sbc h
    ld a, c
    ld l, a
    db $10
    sbc b
    ret nz

    reti


    adc [hl]
    add d
    add hl, hl
    inc a
    db $10
    ret z

    ld h, l
    ret nz

    add $6d
    db $ec
    ld e, h
    ld c, h
    adc l
    sub b
    sub c
    sbc d
    db $dd

jr_00a_4803:
    db $10
    call nz, $c134
    ld c, h
    add hl, bc
    res 2, b
    adc h
    ld c, l
    inc sp
    ld l, $9c
    ld d, b
    pop hl
    pop bc
    ld [hl+], a
    jp $7933


    ret z

    ret nc

    ld c, l
    pop af
    ld c, d
    ld b, h
    ld [hl], c
    push bc
    jr nc, @+$01

    ei
    ld d, d
    sbc d
    and [hl]
    ld [hl-], a
    xor a
    ld e, $25
    ld b, [hl]
    xor $69
    ld a, [bc]
    ret


    xor a
    ld a, [hl+]
    ld c, h
    ld l, e
    ld e, a
    xor c
    or [hl]
    db $dd
    ld d, c
    pop bc
    ld [hl], b
    add hl, hl
    sbc l
    ld de, $1c03
    jp nc, $d19b

    db $d3
    ld a, [hl+]
    ld h, b
    pop bc
    rst $20
    ld e, a
    push de
    ld d, h
    ld e, $48
    ld b, h
    cp l
    and l
    ld c, [hl]
    ld d, l
    ld d, l
    ld a, [hl]

jr_00a_4852:
    and e
    adc c
    ld a, [$a949]
    ld c, [hl]
    rlca
    adc c
    ld c, [hl]
    adc d
    dec h
    add c
    ld d, l
    ld c, [hl]
    ld a, [de]
    ld [hl+], a
    ret c

    jp nz, Jump_00a_4793

    add l
    db $e3
    and d
    sub l
    bit 2, e
    adc [hl]
    ld [$8c30], a
    jr jr_00a_4852

    ld d, d
    inc e
    ld h, l
    ld e, b
    pop hl
    and c
    ld a, [hl]
    ld hl, $6839
    jr nz, jr_00a_4803

    ld h, b
    add c
    jr c, @-$0f

    jp c, $e0f5

    xor b
    ld [c], a
    and d
    xor b
    ld a, [c]
    rst $30
    adc $27
    ld a, [de]
    push de
    ld d, h
    xor a
    inc e
    ld e, c
    sbc e
    jp hl


    call z, Call_00a_73b5
    inc b
    ld [hl], c
    ld c, l
    inc h
    ld a, h
    inc d
    sbc h
    inc a
    pop af
    inc c
    ld [hl], h
    ldh a, [$ce]
    ld [hl], h
    and l
    ld b, a
    ld c, d
    and h
    reti


    rst $08
    adc $4b
    jp hl


    call z, $bcd6
    db $dd
    ld a, [hl+]
    ld [hl], b
    db $db
    dec c
    rra
    ld a, [de]
    ld h, [hl]
    sub l
    db $fd
    ld b, l
    ld sp, hl
    ld a, [hl]
    ld c, [hl]
    rst $00
    and d
    dec hl
    and d
    ld [de], a
    ld e, a
    db $d3
    and c
    ld c, d
    ld e, l
    ld b, c
    ld [$2914], sp
    ld d, e
    and [hl]
    rst $38
    push hl
    ld e, h
    ld d, l
    ld d, b
    sbc a
    db $d3
    add l
    db $f4
    adc $87
    ld c, $46
    db $db
    ld a, [bc]
    scf
    ld b, [hl]
    adc l
    xor a
    push bc
    ld e, [hl]
    rst $10
    adc h
    sub h
    sbc d
    dec l
    ld d, d
    ld e, [hl]
    add d
    ld h, $06
    db $e3
    ld a, [hl-]
    and b
    xor b
    inc d
    sub a
    cp l
    ld b, d
    and c
    ld l, c
    cp d
    cp l
    dec d
    ld b, c
    ld a, [$190d]
    ld c, d
    or h
    ld a, [hl+]
    ld d, l
    dec b
    ld e, d
    ld b, c
    ld d, b
    ld a, [$f0b6]
    add l
    ld [$8cca], sp
    add hl, hl
    add sp, $62
    ld h, [hl]
    xor a
    ld b, l
    xor b
    add h
    jp z, $ad8c

    ld e, d
    and h
    ld a, [de]
    cp [hl]
    rla
    and b
    sub h
    adc $8c
    sub l
    ld a, a
    db $d3

Call_00a_4926:
    dec c
    rla
    rst $38
    adc h
    call nc, $90c6
    add c
    di
    rra
    add hl, de
    ld a, [bc]
    inc [hl]
    ld d, e
    rlca
    add c
    ld e, b
    daa
    ld h, h
    sbc [hl]
    ld h, $0a
    ld [hl-], a
    ld d, e
    ld [$962f], sp
    ld c, b
    rst $10
    ld l, b
    jp nz, Jump_00a_5133

    ld l, d
    ld h, c
    add l
    ld h, $42
    ld b, [hl]

jr_00a_494d:
    cp h
    jp nz, Jump_000_25fd

    ld b, c
    sub h
    ld [de], a
    ld h, l
    inc c
    sub h
    adc d
    xor d
    and b
    and b
    ld d, l
    and d
    dec l
    db $e3
    inc b
    cp d
    and e
    dec b
    inc d
    ld a, [de]
    ld sp, $1a7e
    dec bc
    ld d, $a3
    add hl, sp
    ld [$272b], sp
    inc d
    sbc d
    xor a
    ld hl, sp-$46
    adc b
    ld d, h
    ld a, [hl+]

Jump_00a_4977:
    ld b, c
    ld b, [hl]

Jump_00a_4979:
    cp $fa
    ld a, [bc]
    add d
    rst $38
    ld a, a
    ret nc

    adc c
    ld b, d
    ld [c], a
    db $e4
    cpl
    ld e, h
    jr nz, @+$4a

    ld hl, sp-$4b
    dec b
    ld b, [hl]
    dec b
    ei
    ld [$8b28], sp
    cp [hl]
    call z, $d552
    ld a, d
    ld d, a
    call nc, $b92a
    or l
    ld hl, sp+$15
    ld l, e
    inc sp
    rst $38
    ld a, a
    xor b
    ld a, [hl+]
    cp $85
    ld a, [de]
    rst $38
    and c
    db $fc
    ld d, [hl]
    jr jr_00a_494d

    inc b
    add hl, bc
    db $10
    inc hl
    ld [bc], a
    db $76
    and [hl]
    ld a, [de]
    cpl
    ld b, d
    add d
    ld sp, $d0de
    sbc $83
    ld a, b
    daa
    ld l, h
    ld b, h
    ld b, h
    inc [hl]
    ld d, l
    ld e, e
    sbc h
    ld c, h
    ld [hl], c
    ld b, b
    sbc b
    ld e, a
    dec de
    xor d
    ld [hl], b
    ld b, b
    cp d
    ld [$9acd], sp
    dec h
    add hl, sp
    ld l, c

Jump_00a_49d5:
    add d
    dec bc
    ldh a, [$63]
    ld [bc], a
    ld l, c
    ld b, $84
    pop af
    sbc h
    ld [$437f], sp
    and l
    add hl, sp
    ld c, c
    dec de
    ld h, e
    and a
    ld [de], a
    rst $10
    ld hl, sp+$2f
    ld c, d
    sub h
    ret c

    cpl
    ld sp, hl
    sbc d
    cpl
    cp $91
    ld l, h
    push af
    ld l, c
    dec bc
    pop bc
    ld d, a
    add $88
    ld a, h
    scf
    xor b
    ret nz

    xor e
    inc de
    inc bc
    inc d
    sbc h
    ld e, $2f
    push af
    ld e, [hl]
    xor h
    add d
    dec l
    add sp, $2a
    ld de, $ffaa
    cp $4f
    ld a, [c]
    pop hl
    ld [hl+], a
    rst $18
    pop hl
    ld sp, hl
    xor d
    dec e
    rst $38
    ld [de], a
    push af
    or l
    and c
    cpl
    ret nz

    rst $38
    and $68

jr_00a_4a26:
    or a
    ld hl, sp+$7f
    ld a, [c]
    scf
    xor d
    dec d
    ld de, $e6ff
    ld c, c
    ld a, [hl+]

Jump_00a_4a32:
    rst $08
    rst $38
    add [hl]
    adc d
    jp nc, Jump_000_1242

    add l
    rst $20
    dec e
    ld a, a
    pop hl
    ld a, a
    rst $38
    add d
    jr nc, jr_00a_4a26

    xor [hl]
    and l
    ld b, b
    adc d
    ld d, [hl]
    call nc, Call_00a_7fe3
    pop hl
    ld a, [c]
    rrca
    push af
    rst $38
    sub d
    sbc b
    ld a, e

jr_00a_4a53:
    rst $38
    db $fc
    ld c, l
    ld c, [hl]
    cp a
    ld l, a
    ld d, e
    db $fc
    ld h, d
    xor a
    ld hl, sp+$7f
    jp z, $f64b

    ld [de], a
    rrca
    rst $38
    dec b
    push hl
    ld b, h
    ld d, b
    or a

Jump_00a_4a6a:
    rst $18
    dec b
    ld l, b
    and h
    ld c, b
    db $dd
    ld l, e
    adc l
    ld a, [de]
    or e
    ld hl, sp+$25
    ld b, h
    inc h

Call_00a_4a78:
    set 7, a
    ld d, a
    jp hl


jr_00a_4a7c:
    sub d
    cp a
    ld e, b
    ld h, d
    cp a
    jp hl


    ld [$d87f], sp
    ld b, h
    cp [hl]
    ld e, h
    ld [hl], $31
    add h
    dec a
    ld d, c
    jr nc, jr_00a_4a53

    jp Jump_000_2051


    ld b, h
    or c
    ld d, h
    call $cd25
    ld d, b
    db $f4
    or a
    ld h, h
    jr z, jr_00a_4a7c

    ld l, a
    ld e, e
    pop hl
    sbc b
    inc e
    ldh [$96], a
    rst $18
    sub l
    add hl, bc
    ld [$68e2], sp
    adc h
    adc b
    ld d, e
    sbc l
    add c
    ld l, b
    ld d, e
    adc l
    ld a, [bc]
    ld e, b
    and h
    db $e3
    ld e, b
    ld h, h
    sub [hl]
    ld b, $37
    ld a, c
    add c
    ld b, d
    xor b
    ld h, e
    ld [hl], a
    sbc c
    and c
    and l
    add hl, de

jr_00a_4ac6:
    db $d3
    ld d, a
    ret c

    add l

jr_00a_4aca:
    ld h, $0b
    adc l
    rst $18
    or $0e
    cp $ce
    rra
    daa
    add $17
    and e
    add [hl]
    rst $38
    xor d
    jp hl


    ld e, b
    jr jr_00a_4ac6

    and c
    xor b
    pop af
    or $69
    jp $fe9a


    ld h, h
    ret z

    db $ec
    ld l, [hl]
    jp hl


    dec bc
    ld [hl], d
    ld [de], a
    ld [hl], d
    ld d, l
    scf
    ld a, c

Call_00a_4af2:
    ld [de], a
    ld [hl], c
    pop bc
    jr nc, jr_00a_4aca

    adc h

jr_00a_4af8:
    sbc h
    sub c
    rrca
    rst $00
    dec sp
    xor a
    push bc
    pop de
    jp nz, $18c1

    cp a
    sbc h
    inc [hl]
    pop bc
    add hl, hl
    dec bc
    rst $00
    ld [bc], a
    pop af
    ld [hl], h
    sbc h
    ld e, b
    ld sp, $2cdf
    ld [hl-], a
    ld a, [bc]
    and c
    daa
    dec c
    ld d, a

Jump_00a_4b18:
    ret nc

    ld b, b
    cp l
    ld [hl], c
    cp [hl]
    add hl, sp

jr_00a_4b1e:
    ld d, d
    ld a, [hl+]
    rst $00
    ld c, h
    ld b, h
    ld a, c
    jr nz, @+$68

    add a
    xor e
    push de
    inc a
    ld [hl], l
    ld [hl+], a
    cp e
    push af
    db $fd
    inc a
    dec bc

jr_00a_4b31:
    ld a, [c]
    ld l, $46
    ld d, b
    ld c, [hl]
    rst $10
    adc d

jr_00a_4b38:
    ld l, l
    jr nc, jr_00a_4b38

    ld a, [hl-]
    sub h
    dec d
    inc hl
    db $e3
    add hl, de
    dec b
    cp $41
    ld e, a
    ld c, l
    ld l, b
    adc b
    jr jr_00a_4b64

    sub b
    and d
    ld [$055d], a
    ld c, $94
    jp c, Jump_000_2185

    add d
    inc b
    or a
    ld b, c
    jp nz, Jump_00a_5a08

    adc l
    ld l, l
    adc b
    xor h
    ld l, b
    ld l, b
    ld d, a
    ld hl, sp-$46

jr_00a_4b64:
    ld b, c
    jr c, jr_00a_4bc4

    ld [hl], c
    ld h, h
    jr z, jr_00a_4af8

    call $d33b
    ld d, l
    dec de
    dec b
    dec b

Jump_00a_4b72:
    ld c, b
    ld d, b
    ld h, e
    ld a, [de]
    add hl, bc
    ld b, c
    ld [hl], $42
    ld a, [bc]
    ld a, [bc]
    jr jr_00a_4be9

    ret


    ld c, c
    and d
    db $e3
    dec [hl]
    ld b, d
    ld h, d
    db $10
    ld a, h
    ld l, b
    ld [hl+], a
    ld h, h
    rst $08
    jr c, jr_00a_4bc9

    adc a
    ld a, [c]
    inc d
    pop bc
    inc sp
    ld c, l
    reti


    inc d
    jr nz, jr_00a_4b1e

    ld a, [bc]
    add l
    inc b
    add h
    jr z, jr_00a_4b31

    call $1052
    add d
    ld a, [hl+]
    xor h
    sub h
    sbc d
    ld h, e
    sub d
    ld b, l
    ld h, b
    ld d, b
    xor b
    ld h, c
    adc d
    db $fc
    xor b
    sub $1f
    add hl, hl
    ld b, c
    ld b, $8c
    ld [c], a
    ld [c], a
    sbc a
    sbc d
    ld d, $c9
    call Call_000_3297
    ld c, h
    ld [hl+], a
    jr z, @-$47

    ld c, d
    ld [hl], d

jr_00a_4bc4:
    ld l, h
    dec e
    ld sp, $9e9f

jr_00a_4bc9:
    ld [hl+], a
    ld a, b
    ld d, $83
    add $ac
    inc d
    ld l, [hl]
    ld c, $30
    ld h, b
    ld h, e
    ld c, h
    db $10
    db $76
    ld a, [de]
    ld h, c
    add c
    call z, Call_000_1996
    ld d, l
    ld hl, $2e52
    ld a, [bc]
    ld sp, $2d86
    xor b
    ret


    ret nc

jr_00a_4be9:
    or a
    jr nc, jr_00a_4c45

    ld hl, $d652
    adc l
    sub [hl]
    ld a, [bc]
    ld [$a255], sp
    ld l, d
    ld [hl+], a
    xor d
    adc l
    and e
    ld [hl+], a
    ld [c], a
    sbc [hl]
    ld b, l
    inc b
    rst $38
    cp b
    and c
    daa
    adc b
    db $fd
    ld e, b
    ld a, l
    sbc [hl]
    dec bc
    scf
    rlca
    db $ed

Call_00a_4c0c:
    ei
    xor $9d
    ld [hl], h
    ld b, l
    rst $38
    pop bc
    ld a, b
    ld [hl], a
    inc hl
    xor d
    jr z, @-$37

    dec [hl]
    push bc
    cp $ef
    and c
    dec bc
    rst $08
    ld [$bb09], a
    sub [hl]
    and c
    rst $38
    ld e, [hl]
    adc a
    ei
    ld a, h
    cp h
    ld [hl], d
    ld e, [hl]
    ret z

    ld b, b
    db $ed
    rst $38
    rst $38
    cp $f0
    daa
    ld a, [bc]
    add l
    or b
    ld e, [hl]
    rst $18
    ld [hl], l
    xor l
    rst $38
    rst $38
    or d
    ld l, d
    add e
    ld a, h
    add e
    rst $38
    db $ec

jr_00a_4c45:
    adc a
    add l
    ld hl, sp+$68
    pop de
    ret nz

    ret c

    ld a, $18
    ccf
    ei
    ld a, $47
    db $eb
    and b
    ld sp, hl
    and h
    or a
    or a
    rst $38
    rst $38
    rst $38
    pop hl
    db $ed
    db $f4
    add a
    and [hl]
    rst $30
    rst $30
    rst $38
    db $fc
    dec c
    ld hl, sp+$7c
    rst $38
    ld c, a
    add $f3
    rlca
    ccf
    rst $38
    pop hl
    rlca
    dec b
    ccf
    adc [hl]
    ld a, [hl+]
    ld l, b
    pop bc
    ld h, c
    sub c

jr_00a_4c78:
    db $fd
    ld hl, sp+$43
    add a
    ld a, $0f
    pop bc
    ld a, c
    or e
    ld a, d
    rst $18
    ccf
    add h
    inc a
    rrca
    rst $38
    ld hl, sp-$57
    cp e
    ld a, [hl]
    ret z

    ld hl, $fff2
    rst $38
    push af
    rst $38
    ld a, [c]
    ld e, e
    add hl, hl
    dec c
    ld [hl], e
    scf
    xor [hl]
    cp a
    rst $38
    ld b, c
    rst $38

Jump_00a_4c9e:
    ret nz

    pop de
    add a
    db $e4
    db $ed
    or e
    rst $38
    ld e, a
    rst $38
    ld a, [$c2cf]
    reti


    ld a, [bc]
    ld a, [hl+]
    ret


    db $10
    or a
    ld hl, sp+$3f
    set 6, a
    or a
    jr nz, jr_00a_4c78

    ld de, $5ef8
    adc $d7
    or d
    call z, Call_000_0785
    rst $08
    db $f4
    ldh a, [rNR42]
    add hl, de
    ld e, h
    xor h
    call Call_000_0cfe
    call z, Call_000_0d82
    dec a
    dec de

jr_00a_4ccf:
    xor l
    rst $38
    add h
    pop hl
    inc de
    inc b
    ld b, h
    db $10
    ld d, c
    rst $00
    ld b, c
    ld d, l
    ld b, a
    add [hl]
    ld b, h
    xor l
    and l
    ld d, h
    add l
    xor d
    sub h
    call Call_00a_5d70
    ld a, [de]
    adc h
    and h
    jp nz, $c170

    inc c
    adc h
    ld [hl], l
    daa
    ld [hl-], a
    cp d
    inc c

Jump_00a_4cf4:
    jr nz, jr_00a_4ccf

    push bc
    ld h, h
    pop hl
    cp b
    dec d
    rrca
    ld b, a
    ld [hl], b
    ldh [$4e], a
    dec d
    ld d, $a4
    inc l
    db $10
    ld c, [hl]
    ld [$90be], sp
    ld b, l
    jr c, jr_00a_4d76

    rra
    sbc e
    or [hl]
    adc $1a
    add c
    jp nz, $ba19

    ld [hl], $7d
    cp a
    add d
    and c
    db $e3
    ld b, l
    dec d
    add c
    jr jr_00a_4d70

    sub d
    sub e
    rrca
    ld l, [hl]
    db $dd
    xor b
    ld h, b
    push hl
    ld e, b
    jp z, Jump_000_0cc2

    jr z, jr_00a_4d87

    sbc $38
    ld [hl-], a
    ccf
    xor e
    ld hl, sp-$1c
    xor d
    dec a
    ld a, c
    add d
    sub d
    sub b
    jp nc, Jump_00a_6a82

    adc e
    ld a, a
    jr nc, jr_00a_4d74

    inc c
    adc $98
    db $dd
    ld a, [hl]
    jr nc, jr_00a_4d7c

    ret c

    ld [hl], e
    or $68
    ret z

    xor l
    jp c, Jump_000_3b17

    ld h, a
    ld [bc], a
    dec c
    db $ed
    cp $ff
    sbc h
    ld a, [bc]
    ld [de], a
    dec [hl]
    or l
    adc $70
    and c
    inc a
    cp a
    ld a, [$04e7]
    dec bc
    dec a
    db $fd
    rst $38
    sbc h
    dec hl
    ld e, b
    ld hl, $f9f7
    cp d

jr_00a_4d70:
    adc h
    inc de
    ld l, $17

jr_00a_4d74:
    rst $00
    dec b

jr_00a_4d76:
    and l
    ld e, l
    ld [hl], h
    inc l
    ld h, e
    ld a, d

jr_00a_4d7c:
    rst $38
    xor e
    db $eb
    sub e
    dec de
    db $db
    push de
    or b
    rst $00
    dec d
    ld d, c

jr_00a_4d87:
    ld d, b
    ld b, a
    rst $00
    add b
    ld h, [hl]
    cp c
    dec d
    rst $38
    rst $38
    push af
    ld c, [hl]
    push de
    xor d
    adc h
    ld [$38f5], a
    sbc c
    rla
    xor d
    dec c
    jr c, jr_00a_4dc9

    ld c, l
    jp nc, $302e

    or h
    pop bc
    ld d, l

jr_00a_4da5:
    ld h, $d2
    inc de
    ld [$8816], sp
    db $d3
    dec h
    rst $38
    xor c
    db $e4
    adc d
    ld a, [bc]
    adc c
    ld a, d
    jr nc, @+$54

    sub l
    add sp, -$7b
    ld h, $08
    adc d
    adc c
    ld a, b
    ld d, h
    add h
    or l
    ld [$4635], a
    ld [hl+], a

jr_00a_4dc5:
    sub c
    ld d, d
    dec [hl]
    add hl, bc

jr_00a_4dc9:
    and b

Jump_00a_4dca:
    xor d
    and e
    add c
    inc [hl]
    ld d, e
    ld l, d
    xor a
    ld b, d
    adc e
    ld b, c
    and e
    ld b, h
    pop bc
    ld b, c
    sub h
    jp nz, Jump_00a_54db

    inc de
    jr z, @-$23

    ld d, d
    ld hl, $a564
    ld a, [bc]
    ld [hl], e
    ld d, $26
    add hl, sp
    inc de
    ld l, d
    ld d, l
    and e
    ld a, [hl-]
    ld [hl-], a
    ld d, d
    inc h
    and l
    jr c, jr_00a_4dc5

    sub h
    add $b4
    ld [hl+], a
    sub h
    and $68
    ld l, c
    ld b, e
    call nc, $298a
    ld c, [hl]
    ld [hl], $31
    sbc a
    ld b, d
    or h
    ld l, b
    ld a, [hl]
    jr c, @-$2c

    ld e, b
    cp e
    db $f4
    ld l, b
    adc c
    add hl, sp
    jr jr_00a_4da5

    call Call_000_0b6d
    adc b
    and l
    dec [hl]
    ld e, b
    jp nz, $1553

    db $ed
    ld [hl-], a
    xor d
    ld d, l
    ld e, d
    ld sp, $a28d
    dec d
    sub h
    rst $20
    ld h, e
    sub d
    ld h, $a5
    ld d, c
    ld d, l
    ld l, b
    sub [hl]
    dec sp
    rst $18
    and d
    ld d, l
    ld e, d
    inc a
    rrca
    ld d, l
    ld a, a
    xor b
    pop af
    ld l, d
    xor b
    db $e4
    call c, $c688
    ld a, [hl-]
    ld [hl], a
    and c

jr_00a_4e42:
    and c
    add h
    ld h, l
    ld c, $73
    dec h
    ld b, e
    ld b, a
    ld e, $9c
    jr z, jr_00a_4eb5

    ld [hl+], a
    ld c, d
    ld b, l
    and [hl]
    db $dd
    inc e
    jr z, jr_00a_4eb7

    ld [hl], a
    add e
    db $10
    ret


    or d
    ld e, d
    ld h, l
    ld d, $a4
    ld e, b

jr_00a_4e60:
    and b
    ret


    ld l, c
    ld [$c9a4], sp
    or h
    ld e, h
    ld d, h
    ld h, c
    ld d, $c3
    ld d, c
    add hl, hl
    ld c, e
    dec de
    and [hl]
    pop de
    dec d
    jr z, jr_00a_4e42

    ld d, b
    or c
    add d
    ld c, d
    ld h, b
    sbc b
    inc h
    dec l
    ld h, e
    ld b, b
    adc d
    sbc b
    ld d, c
    adc d
    ld b, h
    ld b, d
    jr nc, jr_00a_4e60

    sub h
    dec c
    and h
    and c
    db $10
    sub h
    add d
    ld l, c
    inc e
    ld c, l
    ld hl, $d019
    dec h
    ld b, h
    ld b, d
    sub [hl]
    rst $20
    ld a, [bc]
    ld h, c
    and c
    add hl, hl
    ld [hl], d
    ld h, b
    rst $00
    ld a, [bc]
    ld b, e
    dec d
    add d
    ld b, [hl]
    ld c, l
    ld b, l
    ld h, a
    inc bc
    inc d
    call nz, $97d7
    dec b
    ld c, h
    pop bc
    ld h, $4b
    ld b, a
    dec c
    and d

jr_00a_4eb5:
    pop de
    and l

jr_00a_4eb7:
    ld c, d
    call nc, Call_000_0365
    add hl, de
    ld [hl-], a
    add l
    reti


    jp nc, $ecc6

    ld [de], a
    ld b, h
    sbc h
    xor h
    ld [hl], d
    add sp, -$1f
    xor c
    and d
    cp l
    dec e
    or b
    or l
    ld e, l
    ld a, b
    ld d, h
    add hl, de
    ld [c], a
    ld h, c
    ld [bc], a
    ld b, d
    inc d
    ld a, b
    ld l, c
    inc sp
    ld d, b
    ld b, a
    adc e
    inc de
    inc e
    add b
    ld b, h
    cp b
    ld e, a
    ld c, d
    ld d, h
    db $e4
    and d
    rla
    ld a, [$278e]
    add c
    jp $678e


    add e
    ldh [$81], a
    add hl, sp
    ld l, b
    or a
    sbc b
    db $e3
    and d
    cp [hl]
    dec d
    dec sp
    ld e, [hl]
    ld a, [hl-]
    cp a
    db $e3
    ret nz

    ld c, [hl]
    ld l, d
    ld hl, $b448
    ld h, e
    adc d
    rst $20
    add c
    dec d
    inc b
    push hl
    sub a
    add d
    ld d, $16
    adc $5a
    or a
    daa
    ld a, [hl-]
    ld [$3ca6], a
    ld [$67f1], sp
    and h
    and $16
    ld [hl], c
    and b
    ret z

    daa
    ld [hl], e
    add d
    db $76
    ld [hl], b
    ld l, h
    db $76
    cp h
    ld [hl], l
    cp a
    ld e, $ba
    ld l, h
    sbc h
    ld l, c
    add [hl]
    adc d
    ld l, $70
    jp c, $cfb7

    add a
    rst $20
    inc l
    dec sp
    ld [hl], e
    rst $00
    ld e, h
    inc d
    ld a, [de]
    ld a, b
    ld de, $a0f0
    ld [hl], a
    or l
    ld e, d
    xor d
    xor d
    ld c, a
    ld hl, $aa6d
    xor d
    sub h
    inc h
    pop af
    add hl, de
    and l
    ld a, [c]
    or h
    ld h, c
    ld c, a
    dec b
    sbc l
    ld a, [$8350]
    ld b, d
    add [hl]
    inc d
    rst $28
    ld b, c
    ld a, [bc]
    ld e, a
    cp b
    db $10
    or [hl]
    add d
    inc a
    rlca
    ld h, c
    db $eb
    ld e, b
    adc b
    add h
    ld d, d
    ld h, e
    jp nz, $3082

    ld c, b
    sub e
    ld a, [bc]
    and l
    ld a, [hl-]
    ld hl, sp+$5a
    adc c
    sbc b
    pop bc
    xor d
    sub [hl]
    ld c, d
    ld d, l
    ld c, h
    xor l
    ld d, [hl]
    ld [$5494], sp
    adc d
    adc b
    adc h
    jr nz, @-$79

    ld [$419a], a
    add sp, -$77
    ld d, [hl]
    dec h
    db $dd
    or [hl]
    inc hl
    ld [$b828], sp
    inc de
    add hl, de
    ld [$6733], sp
    ld a, h
    rst $08
    ld [hl], $82
    ld c, d
    ld b, l
    ld [hl], $bf
    ld e, a
    pop bc
    inc sp
    adc c
    ld d, a
    db $fd
    sub l
    adc b
    and e
    ld d, a
    ei
    rst $38
    ld c, d
    ld c, d
    sub [hl]
    ld b, $aa
    db $f4
    push hl
    and [hl]
    sub a
    ld a, [c]
    sbc b
    and l
    ld d, b
    and e
    ld d, l
    ld e, b
    adc $9b
    cp l
    ld a, [bc]
    ld b, [hl]
    inc sp
    ld a, b
    sub h
    inc de
    sub [hl]
    sbc b
    ld a, [hl+]

jr_00a_4fcf:
    rlca
    inc b
    db $10
    ld d, d
    ld [hl+], a
    sbc a
    add sp, -$18
    or d
    sub c
    ret nc

    ld c, [hl]
    ld a, [bc]
    dec sp
    ld de, $f6b7
    rlca
    adc l
    sbc c
    dec l
    ld l, c
    ld c, l
    jp nc, Jump_000_0f2a

    ld [c], a
    ld [c], a
    sub c
    sbc b
    sub [hl]
    ld a, [de]
    ld b, d
    scf
    sub e
    add [hl]
    ld d, [hl]
    ld hl, $453d
    or [hl]
    and h
    ld h, h
    add [hl]
    jr c, jr_00a_4fcf

    db $10
    cp l
    db $dd
    dec h
    rst $18
    or h
    adc b
    adc d
    adc b
    ld c, [hl]
    ld d, [hl]
    ei
    sub $de
    xor l
    rst $38
    ld b, l
    ld b, $aa
    and e
    adc [hl]
    rra
    ld l, a

jr_00a_5014:
    rst $38
    ld a, [bc]
    rrca
    and a
    pop bc
    and [hl]
    dec sp
    inc h
    dec de
    sbc $de
    add hl, de
    ld a, l
    inc b
    jr z, jr_00a_5014

    ld h, $5a
    rst $38
    rst $18
    ld hl, sp+$53
    add $96
    xor d
    dec bc
    ld h, d
    jr @-$0c

    xor d
    ld d, h
    sub l
    adc [hl]
    dec a
    xor d
    ld [de], a
    xor d
    xor h
    ld a, c
    jr z, jr_00a_5088

    or a
    ld h, c
    db $eb
    add hl, hl
    ld [c], a
    xor a
    ld l, l
    ld b, c
    ld [hl], d
    inc de
    ld b, $9e
    ld a, [bc]
    ei
    ld l, l
    db $e4
    call z, Call_000_1a2c
    ld a, b
    jr jr_00a_50a0

    or h
    ld h, e
    ld b, e
    inc c
    db $76
    xor [hl]
    ld b, l
    ld d, $f9
    add hl, sp
    ld d, c
    db $db
    ld b, c
    ld a, [bc]
    jp z, $5cb2

    ld a, [bc]
    jp c, Jump_000_09ac

    call z, Call_000_1dac
    ld b, $68
    call nz, Call_000_2b44
    ld [bc], a
    ld e, d
    ld b, d
    ld h, l
    ld c, c
    ld sp, $f55a
    rst $10
    add e
    and e
    ld c, l
    ld [hl], $2a
    db $f4
    inc c
    ld b, h
    db $e4
    or h
    sub [hl]
    cp d
    dec a
    rrca
    inc bc

jr_00a_5088:
    inc h

Jump_00a_5089:
    ld d, c
    ld d, b
    ld hl, $0493
    ld [hl], b
    cp a
    db $fc
    db $10
    and [hl]
    sub c
    ld c, b
    ld b, l
    and a
    rla
    call nz, $be41
    ld l, d
    add d
    or [hl]
    sub a
    sbc h

jr_00a_50a0:
    ld d, [hl]
    and c
    rst $38
    ld sp, hl
    ld [hl], c
    jr z, jr_00a_5104

    ld hl, $a772
    dec e
    or l
    ret nc

    ld b, c
    sbc b
    db $e3
    add l
    ld b, h
    ld b, h
    ld b, e
    ld d, h
    sbc e
    ld c, l
    cp a
    ld a, e
    jr jr_00a_50fc

    bit 3, b
    or b
    daa
    inc a
    db $10
    ld d, d
    ld [de], a
    add d
    ld [$1141], sp
    ld [bc], a
    push de
    ld a, [bc]
    ld [hl], h
    dec hl
    add hl, hl
    ld [$9226], sp
    dec [hl]
    ld d, b
    inc a
    ld [hl], d
    ld sp, hl
    ld [de], a
    db $ec
    inc c
    adc $67
    add h
    ld a, [bc]
    call nc, $26b0
    ld a, [$5355]
    rrca
    sbc c
    ld a, [$a160]
    ld b, $70
    ld e, d
    xor d
    jp hl


    ld d, $97
    ld [bc], a
    xor e
    jp hl


    ld a, [bc]
    ld [hl], d
    jp nz, $35d4

    ld c, e
    dec hl
    rst $38
    ldh [$a1], a
    ld d, c

jr_00a_50fc:
    db $d3
    add h
    ld [$54fa], sp
    rrca
    or $fc

jr_00a_5104:
    db $e4
    ld a, [hl+]
    and c
    rst $20
    ld [de], a
    ld [hl], $8d
    add sp, -$09
    ccf
    ld a, [hl]
    sub b
    sub a
    ld b, a
    dec e
    add [hl]
    cp d
    adc l
    sub b
    ldh a, [$3c]
    ld [$762c], sp
    db $d3
    ld l, [hl]
    ld a, [c]
    sub c
    cp a
    dec bc
    sbc [hl]
    inc h
    rst $08
    ld a, [hl]
    ld b, l
    ld [de], a
    rst $20
    adc [hl]
    pop bc
    db $f4
    ld h, b
    rst $00
    sub a
    dec bc
    ld b, b
    and c
    daa

Jump_00a_5133:
    jr nz, jr_00a_5179

    cp b
    rla
    cp $53
    sbc c
    rst $38
    db $fd
    ld a, [de]
    ld d, e
    add [hl]
    ld a, [$4e2a]
    daa
    push bc
    rst $38
    ld c, [hl]
    ld b, [hl]
    rst $38
    rst $38
    db $fc
    db $e3
    rst $38
    rst $38
    rst $38
    di
    adc a
    rst $38
    rst $38
    rst $38
    adc b
    adc l
    rst $38
    db $fc
    ld [hl], d
    ret c

    reti


    ld e, l
    ld b, $22
    xor d
    adc l
    ld [$50aa], a
    ld l, b
    ld [hl+], a
    call nc, Call_00a_7dda
    ld b, c
    db $fd
    ld d, $86
    adc h
    ld a, [de]
    rlca
    rst $30
    cp $60
    adc [hl]
    add hl, bc
    xor a
    rst $38
    add sp, $18
    db $e3
    sbc a

jr_00a_5179:
    xor d
    ld d, $3a
    ld l, d
    xor b
    db $f4
    ld [hl], a
    ld [hl-], a
    ld [hl], h
    cp [hl]
    dec hl
    ld a, [$9c9c]
    inc l
    ld b, l
    ld l, a
    sbc e
    xor d
    ld c, l
    and a
    scf
    ld [hl], b
    ld h, h
    ld a, c
    call Call_000_3986
    ld e, $73

Call_00a_5197:
    ld h, c
    adc [hl]
    xor a
    inc e
    db $db
    and c
    inc e
    ret z

    and c
    adc e
    jp z, Jump_00a_46a5

    ld a, h
    pop bc
    add l
    db $10
    ret nz

    ret z

    and d
    sbc c
    ld b, c
    ld d, $af
    add h
    inc c
    ld b, h
    ld h, e
    and b
    cp a
    di
    db $fc
    ld de, $37c5
    ei
    ld [hl], b
    ld sp, $07cb
    ld a, [$7784]
    rst $00

jr_00a_51c3:
    and d
    ld h, [hl]
    cp d
    rst $18
    ld c, a
    ld sp, $4121
    db $f4
    pop bc
    db $e4
    jp hl


    ld a, e
    push af
    xor d
    and b
    ld a, l
    inc e
    ld d, e
    add l
    ld l, d
    cp b
    ld a, [hl+]
    xor d
    xor a
    sub d
    ld d, $4c
    ld d, $b2
    ld [$2346], a
    db $fc
    ld l, $07
    ld e, e
    ld c, [hl]
    dec b

jr_00a_51ea:
    ld h, $21
    add hl, de
    ld h, a

jr_00a_51ee:
    ld hl, sp-$3f
    ld c, b
    and e
    inc d
    xor c
    ld h, $85
    ld h, b
    xor d
    and d
    sub d
    ld a, [hl+]
    ld [$2ec9], sp
    ld [hl], l
    cp e
    db $db
    rst $38
    jp nc, $9a14

    and d
    ld [hl+], a
    ld d, [hl]
    ld hl, $466a
    add [hl]
    add d
    add l
    push af
    ld e, c
    dec h
    ld hl, $ff21
    dec b
    ld c, c
    adc b
    and c
    and d
    dec h
    ld d, l
    ld [$8610], sp
    and d
    sub l
    xor d

Jump_00a_5221:
    and e
    inc b
    inc d
    inc d
    jr nz, @+$44

    and d
    jr nz, jr_00a_527d

    rlca
    ld hl, sp+$2a
    xor b
    sub h
    dec sp
    db $fc
    add h
    ld l, b
    and h
    call $c255
    add hl, hl
    ld b, d
    jr jr_00a_51c3

    sub h
    pop bc
    dec [hl]
    or h
    cp e
    rst $38
    ld b, l
    ld hl, $29a2
    ld e, e
    ld d, b
    and e
    adc l
    ld d, l
    ld h, $a5
    jr nc, jr_00a_52bb

    jr jr_00a_5263

    dec sp
    ld c, b
    ld h, c
    and b
    ld c, b
    ld e, e
    ld c, e
    ld b, d
    jr jr_00a_51ee

    ld e, $4b
    xor a
    dec l
    db $eb
    ld c, c
    and l

Jump_00a_5261:
    ld [hl], c
    sub [hl]

jr_00a_5263:
    jr nc, jr_00a_51ea

    scf
    ld b, c
    ld [$0b63], sp
    jp z, Jump_000_3ea8

jr_00a_526d:
    ld [hl], $48
    ld c, c
    sub [hl]
    jr nc, jr_00a_526d

    ld d, c
    ld c, b
    ld b, c
    inc sp
    and d
    and h
    db $10
    ld d, e
    add d
    add l

jr_00a_527d:
    dec h
    ld [hl], $41
    ld b, d
    pop hl
    adc h
    inc hl
    ld a, [de]
    xor d
    sbc b
    reti


    ld a, d
    dec d
    adc c
    ld e, b
    call Call_000_1856
    jp z, Jump_00a_5f8a

    xor d
    xor b
    sbc $88
    sub [hl]
    ld sp, $7a55
    inc a
    add hl, de
    jp c, Jump_00a_729e

    add hl, hl
    ret nz

    sbc [hl]
    inc b
    ld b, a
    sub [hl]
    add d
    ld b, d
    ld [hl], b
    and c
    xor c
    ld a, [hl]
    ld l, h
    add d
    ld h, b
    add h
    ld h, e
    ld d, a
    add [hl]
    cp h
    ld c, d
    ld a, [$c790]
    ld a, [bc]
    ld c, l
    xor a
    db $ed

jr_00a_52bb:
    rla
    rst $38

Jump_00a_52bd:
    db $e3
    ld h, c
    rst $20
    cpl
    call nc, Call_00a_78a4
    rst $38
    db $fc
    ld sp, hl
    ld a, [de]
    ld b, d
    ld d, h
    ld h, h
    and h
    ld b, [hl]
    ld d, a
    ld d, e
    ld a, [hl]
    inc [hl]
    ld l, h
    add l
    sub e
    add h

jr_00a_52d5:
    ld c, d
    ld h, b
    and c
    ld l, l
    adc h
    ld b, h
    ld d, d
    sbc b
    ld d, l
    ld de, $e318
    ld b, b

Call_00a_52e2:
    add [hl]
    sbc e
    ld d, b
    ld sp, hl
    ld a, [hl+]
    and b
    adc d
    inc c
    ld a, $ab
    ld hl, sp+$6a
    ld h, h
    and [hl]
    ld [$c064], sp
    xor l
    sub c
    ld a, a
    rst $38
    ld a, $67
    ld b, b
    cp $86
    add l
    ld d, b
    ld a, a
    ld sp, hl
    dec [hl]
    db $fd
    ccf
    and [hl]
    ld [hl], a
    rst $38
    ld [c], a
    and h
    rst $18
    pop bc
    sub h
    add e
    push de
    sbc e
    ld a, a
    db $fc
    inc [hl]
    inc sp
    inc sp
    inc a
    ld b, h
    set 7, [hl]
    sbc e
    call nc, $ff60
    ld b, c
    ld e, h
    call z, $3f0e
    add sp, -$60
    and [hl]
    dec hl
    jr jr_00a_52d5

    cp $a1
    ld [bc], a
    rra
    db $fd
    ld e, c
    inc d
    add hl, bc

jr_00a_532e:
    adc [hl]
    ld h, b
    cp b
    rst $38
    ei
    ld a, h
    rra
    sub c
    adc e
    sbc c
    and e
    sbc b
    ld a, a
    rst $38

jr_00a_533c:
    cp $61
    ld de, $1b8f
    ld h, [hl]
    db $10
    scf
    rst $38
    jp hl


    sbc h
    ld c, $12
    ld l, e
    sbc b
    ld a, $1f
    ld a, [$9b6b]

jr_00a_5350:
    and e
    inc h
    cp l
    dec [hl]
    ld h, c
    ld a, [de]
    pop de
    ld [$9ea6], sp
    ret c

    ld b, a
    ld h, l
    add hl, de
    ld c, l
    inc b
    ld a, b
    ld h, b
    ld b, h
    or h
    ld a, l
    dec sp
    dec d
    dec bc
    ld b, c
    ld d, h
    ld [c], a
    ld l, b
    ld a, [hl-]
    ld b, e
    db $e4
    ld h, h
    db $e4
    cp d
    jp nz, Jump_000_1f62

    db $d3
    dec d
    ld d, d
    ld h, a
    push de
    ld d, $26
    jr nc, jr_00a_533c

jr_00a_537e:
    add hl, bc
    ld b, c
    adc d
    sub h
    jp c, Jump_000_0409

    jr z, jr_00a_5350

    ld c, l
    xor h
    add h
    db $ed

jr_00a_538b:
    ld a, d
    dec d
    jr nc, @+$55

    adc l
    ld [c], a
    ld e, [hl]
    and b
    ld c, c
    ld c, l
    jr jr_00a_532e

    or b
    ret


    cp a
    ld c, [hl]
    ld b, $26
    dec l
    ld d, h
    pop de
    inc e
    sub h
    pop bc
    xor d
    dec [hl]

jr_00a_53a5:
    sub a
    ld h, $55
    ld h, e
    ld [c], a
    and a
    sbc e
    add hl, hl
    ldh [$58], a
    scf
    jp hl


    rst $10
    rst $38
    rst $00
    ld [de], a
    ld h, a
    ld b, l
    add $be
    sbc c
    rst $00
    rla
    ld h, [hl]
    adc h
    ld [hl], b
    pop hl
    add hl, de
    cp c
    ld e, c
    adc $fc
    db $eb
    rst $20
    ld [hl-], a
    xor e
    ld a, a
    rst $00
    ld l, $ff
    rst $20
    ld d, a
    rst $38
    pop hl
    ld d, h
    ld l, c
    ld h, $17

jr_00a_53d5:
    rst $38
    inc e
    ld [hl], c
    ld a, [c]
    ldh [rPCM34], a
    cp b
    ld d, $a9
    ld c, a
    add hl, sp
    ld h, e
    jr jr_00a_53d5

    sbc $a1
    and d
    and d
    dec e
    dec h
    ld c, [hl]
    or l
    ld [c], a
    ld d, b
    and e
    dec h
    ld d, b
    ld l, a
    adc $65
    ld l, d
    jr nc, jr_00a_538b

    dec b
    jr jr_00a_537e

    ld d, c
    ld h, e
    sub c
    ld a, [$d2a8]
    add [hl]
    inc d
    add l
    add l
    ld d, e
    adc [hl]
    push af
    ld d, b
    ld c, h
    xor b
    add h

Call_00a_540a:
    add h
    sbc e
    cp a
    adc $5a
    jp c, Jump_00a_558c

    ld h, d
    ret c

    ld e, [hl]
    and e
    sbc [hl]
    add l
    push de
    dec h
    ld b, c
    jr nc, jr_00a_53a5

    ld c, [hl]
    cp e
    ld a, [hl]
    ld a, [bc]
    and l
    jp hl


    ld a, d
    ld sp, $ba4e
    add [hl]
    add l
    ld l, l
    ld hl, sp+$69
    ld c, h
    add hl, hl
    dec sp
    jr z, jr_00a_544f

Call_00a_5431:
    ld a, [bc]
    add c
    add hl, hl
    ld b, c
    ld c, h
    inc h
    ld [$1abe], a
    dec d
    ld l, d
    xor c
    ld a, [c]
    pop de
    adc l
    inc d
    and $d5
    ld c, h
    add hl, hl
    rlca
    pop af
    sub e
    add hl, de
    ld h, h
    sbc $8a
    ld d, l
    ld [hl-], a
    add d

jr_00a_544f:
    db $f4
    adc d
    ld c, b
    ld l, h
    ld h, b
    ld c, [hl]
    dec [hl]
    ld b, c
    ld [hl], $fc
    cp d
    adc b
    sub b
    call nc, $bae4
    dec [hl]
    ld hl, sp+$59
    ld [hl-], a
    or e
    ld a, d
    dec l
    sbc $32
    ld h, b
    ld l, e
    ld d, b
    and b
    add l
    add c
    ld c, l
    call nc, $36c2
    ld c, c
    and a
    push af
    add [hl]
    and e
    add c
    ld c, c
    and [hl]
    ld [hl-], a
    sbc b
    adc $8a
    cp b
    ldh [rHDMA2], a
    ld d, c
    ld c, e
    ld l, b
    rst $28
    ld d, d
    jp hl


    ld [hl+], a
    add l
    ld e, d
    inc a
    ld a, [de]
    or l
    ld [hl+], a
    xor e
    ld d, d
    add hl, hl
    ld [hl+], a
    dec sp
    db $ed
    ld l, d
    cp b
    jr z, jr_00a_54c3

    or c
    di
    call nz, Call_000_1aaf
    ld a, [bc]
    xor c
    push hl
    or e
    add $55
    ld h, b
    ld b, c
    inc sp
    ld d, e
    cp l
    cp $81
    ld d, l
    or a
    pop bc
    ld c, b
    adc a
    dec b
    ld d, a
    ld a, [$6aa2]
    rst $38
    sbc $3a
    scf
    ld [de], a
    xor c
    add sp, $20
    rst $18
    db $ed
    ld e, $7c
    dec d
    adc l
    inc b

jr_00a_54c3:
    ld a, c
    add hl, bc
    jr z, @-$55

    ld a, [bc]
    ld h, c
    and h
    ld sp, $8fd0
    add sp, -$08
    rst $18
    call nz, $2845
    inc l
    ld [hl], h
    ld c, a
    dec b
    sub c
    and l
    ld e, d
    ld [de], a

Jump_00a_54db:
    ld d, e
    ld [bc], a
    ld [hl], h
    xor $47
    ld hl, $c1e4
    ld l, h
    add hl, bc
    ld e, d
    add hl, de
    rst $10
    inc h
    pop bc
    inc de
    dec bc
    ld l, $42
    and c
    dec e
    ld e, b
    ld a, [hl+]
    sbc b
    cpl
    ld e, a
    ld b, c
    add l
    and a
    ld h, d
    dec e
    ld c, $8a
    jp $af28


    inc b
    sbc l
    or c
    jr c, jr_00a_5557

    ld de, $fdab
    ld [bc], a
    pop bc
    ld b, b

Call_00a_550a:
    sbc l
    cp d
    ldh a, [$e0]
    ld hl, sp-$0c

jr_00a_5510:
    cp h
    ld a, [bc]
    inc d
    add hl, hl
    reti


    ld b, h
    db $76
    rla
    db $ed
    ld d, a
    ei
    ret nz

    and c
    ld e, $0d
    ld [c], a
    and [hl]

jr_00a_5521:
    dec [hl]
    db $fc
    ld b, h
    sbc c
    jp nc, Jump_00a_6370

    db $f4
    ld [hl-], a
    ld [hl], c
    ld c, c
    add [hl]
    ld b, d
    ld [hl], c
    ld a, [$7144]
    xor h
    add e
    sub $9c
    add hl, hl
    ld e, $15
    inc e
    dec hl
    pop bc
    ld [bc], a
    pop de
    ld d, $6f
    rrca
    call nz, $9a34
    jr nc, jr_00a_5510

    sub e
    ld d, b
    xor c
    cp [hl]
    ld e, $71
    cp c
    ld [hl], l
    ld l, h
    ld d, h
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    or c
    ld [c], a
    jp hl


    ld [hl-], a

jr_00a_5557:
    push bc
    or c
    db $e4
    ret


    adc d
    db $fc
    ld a, b
    ld [$34a6], sp
    and h
    ret nc

    rst $00

Jump_00a_5564:
    add c
    ld b, $d2
    or h
    ld d, h
    sub l
    sbc [hl]
    dec l
    inc h
    ret nz

    cp b
    jp z, Jump_00a_4979

    jr z, jr_00a_5521

    dec b
    ld e, b
    daa
    adc c
    ld b, b
    xor c
    db $10
    dec l
    ld [bc], a
    sbc [hl]
    ld [hl+], a
    dec [hl]
    ld de, $5618

Jump_00a_5583:
    xor h
    ld [hl], h
    add b
    ld b, h
    or a
    ld e, e
    push de
    dec b
    ld d, e

Jump_00a_558c:
    adc c
    ld [$b71a], a
    db $ec
    ldh [$a3], a
    ld c, d
    di
    ld h, a
    adc a
    db $76
    adc a
    ld a, l
    ld c, a
    ld b, l
    adc l
    xor b
    rst $00
    xor d
    and e

Jump_00a_55a1:
    add [hl]
    push af
    ld d, d
    dec h
    dec b
    add hl, sp
    ld a, [hl+]
    cp a
    db $fd
    rst $30
    inc a
    ld [$5dfa], sp
    cp d
    inc de
    jr nz, @-$7c

    add hl, hl
    ret


    inc bc
    and c
    dec b
    ret c

    daa
    ld b, $55
    jp hl


    jr nc, jr_00a_5625

    ret


    adc a
    rst $20
    ld l, $60
    cp $72
    ld [hl], c
    ld c, a
    db $fc
    ld [hl], h
    cp a
    pop af
    call $f7bb
    dec e
    inc a
    ld de, $66db
    ld e, a
    add l
    add d
    ld l, a
    jr nc, jr_00a_5603

    add d
    add d
    sbc h
    ld d, b
    jp z, $15aa

    and a
    ldh [$a0], a
    ld h, [hl]
    xor l
    ld c, a
    ld a, [hl-]
    dec bc
    sub e
    rst $08
    sbc [hl]
    ld c, a
    ld [hl+], a
    inc b
    sbc c
    sub d
    sub l
    ld d, e
    push bc
    add d
    ld e, a
    xor c
    ld l, c
    ld hl, $935f
    add d
    ld [$88a4], sp

jr_00a_55ff:
    jp nz, $eb1a

    ld h, b

jr_00a_5603:
    ld c, l
    sub l
    dec d
    ld e, b
    adc b
    jp c, $a3a5

    ld l, a
    ld a, [$4d48]
    ld h, d
    ld e, d
    rlca
    call nc, $81a7
    ld a, [$9788]
    ld d, l
    dec l
    adc c
    ld c, h
    ld a, [hl+]

jr_00a_561d:
    sub b
    and c
    pop bc
    ld l, e
    call z, $a8e5
    or l

jr_00a_5625:
    ld c, d
    xor l
    ld h, b
    sub c
    or [hl]
    adc h
    call c, $abb5
    ld d, [hl]
    cp b
    add l
    sub d
    xor b
    or l
    ld d, $94
    add [hl]
    adc h
    and d
    ld [hl+], a
    dec hl
    ld d, l
    and d
    ld d, $98
    jr nz, jr_00a_55ff

    jr @-$38

    sub $37
    ld l, d
    sub [hl]
    adc d
    ld b, d
    jr jr_00a_561d

    and h
    sbc b
    jp z, $85b4

    xor d
    ld d, c
    adc a
    add hl, bc
    ld e, b
    ld d, $21
    jr c, @-$2b

    ld b, l
    ld [hl+], a
    ld d, h
    ld [de], a
    ld a, [de]
    ld hl, $5039
    ld e, d
    adc h
    sub l
    ld h, d
    dec d
    inc b
    push de
    adc e
    adc b
    ld l, b
    jp z, $8825

    add c
    ld [hl-], a
    ld d, d
    jp hl


    dec c
    ld c, l
    sbc d
    add hl, hl
    ld b, $52
    ld d, $30
    rst $10
    and b
    or h
    ld [c], a
    ld h, [hl]
    ld a, [bc]
    ld a, d
    add hl, hl
    ld d, l
    xor b
    cp d
    jr c, jr_00a_56a7

    adc h
    ld a, [hl+]
    xor d
    dec sp
    ld d, [hl]
    ld h, e
    ret


    ld e, c
    ld h, e
    jp nz, $bdde

    xor c
    rst $20
    ld d, e
    add hl, hl
    db $e4
    add sp, $20
    adc h
    sbc [hl]
    ld e, d
    ld d, h
    adc d
    push de
    ld c, d
    ld h, b
    xor c
    push bc
    inc c
    ld h, c
    ld [hl-], a

jr_00a_56a7:
    ld e, h
    dec bc
    ld d, b
    add hl, hl
    add $aa
    ld c, l

jr_00a_56ae:
    ld [bc], a
    add hl, bc
    add l
    ld [bc], a
    pop de
    push bc
    push de
    ld d, l
    ld d, c
    ld sp, $609c
    sub [hl]
    sub b
    add [hl]
    ld hl, sp-$52
    ld a, [hl+]
    sbc d
    ld h, $28
    jr nc, jr_00a_56ae

    dec e
    ld l, a
    ld sp, $2a0c
    ld e, d
    xor c
    ld l, l
    ld l, b
    ret


    add a
    add [hl]
    jp nc, Jump_00a_5ac5

    rst $18
    ld d, l
    add a
    dec l
    ld de, $1102
    ld e, h
    add $2b
    ld b, b
    or h
    ld h, b
    and h
    ld b, l
    ld b, b
    call nc, $1043
    or [hl]
    ld [hl], $e1
    ld h, $56
    xor d
    xor c
    and [hl]
    xor l
    inc bc
    ld de, $a030
    jp nc, Jump_00a_5261

    inc [hl]
    ld [hl], b
    ld sp, $1085
    adc d
    ld l, b
    and a
    inc bc
    inc bc
    ldh [$92], a
    sub e
    ld b, a
    ld [hl], l
    ld b, b
    add a
    ld [bc], a
    ret


    sub $ac
    ld l, d
    push af
    dec b
    inc e
    inc [hl]
    xor e
    ld b, d
    sbc d
    ld e, h
    add hl, bc
    inc [hl]
    ld [hl], b
    xor c
    dec bc
    ld d, c
    or e
    ld b, l
    ld [hl], d
    sbc c
    or [hl]
    xor b
    ld b, h
    ret


    or d

jr_00a_5724:
    ld c, e
    inc de
    ld c, d
    xor d
    call nz, Call_000_1c43

Call_00a_572b:
    adc c
    ld sp, $31e7
    push hl
    xor l
    ld e, $18
    ld b, h
    or a
    cp l
    ld d, e
    xor l
    ld b, d
    xor a
    ld d, l
    ld d, e
    ld a, e
    db $d3
    ld a, [de]
    ld a, a
    inc sp
    cp a
    ld d, b
    or b

jr_00a_5744:
    sub e
    ld [$48d5], sp
    adc b
    ld c, [hl]
    ld b, a
    db $f4
    push bc
    jr c, jr_00a_5724

    inc sp
    ld c, h
    ld d, e
    dec sp
    di
    inc b
    push bc
    inc [hl]
    or d

jr_00a_5758:
    sub $14
    ld d, [hl]
    adc l
    ld l, e
    cp $8a
    xor b
    rst $20
    and b
    call $85b3
    inc [hl]
    ld d, h
    db $e3
    sub d
    push de
    and a
    add hl, sp
    inc e
    ld d, $22
    xor b
    push hl
    and e
    rst $08
    sbc $7e
    ld a, b
    adc l
    ld d, h
    db $f4
    ld l, [hl]
    add d
    and e
    sbc b
    ld e, d
    ld l, d
    add sp, $7e
    ld [hl], l
    ld b, b
    call nz, $cd49
    ld b, b
    sbc l
    or h
    sbc l
    call z, $a662
    ld sp, $52a5
    xor e
    jr jr_00a_5744

    ret


    ld b, [hl]
    inc c
    and a
    ld [hl+], a
    ld sp, $1a0c
    inc d
    ld [hl], c
    call nz, Call_00a_5431
    sbc h
    or h
    ld a, h
    ld a, b
    ld [hl], a
    cp h
    ld d, l
    ld d, h
    di
    sub $b5
    ld [hl+], a
    sub h
    ld a, [c]
    ld e, l
    ld b, e
    jr jr_00a_57dc

    ld b, [hl]
    ld c, a
    dec d
    push de
    ld b, c
    pop af
    ld c, b
    ret z

    sub e
    pop bc
    ld a, h

Call_00a_57bd:
    add [hl]
    adc b
    and [hl]
    and l
    ld c, a
    ld de, $e342

jr_00a_57c5:
    inc h
    ld [hl+], a
    db $e3
    and l
    ld d, l
    ld d, a
    and e
    ld c, d
    dec b
    adc [hl]
    sub l
    ld a, [$abaa]
    push de
    jr nc, jr_00a_5758

    adc e
    adc h
    sub a
    db $e4
    add a
    and l

jr_00a_57dc:
    xor d
    and l
    dec b
    ei
    pop de
    ld [hl], l
    xor d
    dec [hl]
    ld h, [hl]
    jr @+$19

    sbc e
    ld d, l
    ld d, h
    adc e
    ld b, [hl]
    sbc e
    ld a, [c]
    jp nc, $0423

    ld [hl+], a
    and b
    add d
    add hl, de
    ld hl, $455e
    adc c
    and [hl]
    sub l
    ld h, d
    inc hl
    jr z, jr_00a_57c5

    ld l, c
    jr @+$64

    inc h
    sbc b
    or [hl]
    ld c, e
    adc l
    sbc d
    ld c, c
    and b
    ld b, [hl]
    ld b, d
    ld a, c
    dec [hl]
    sbc c
    ld c, b
    ld d, e
    ld c, c
    ld [hl-], a
    sbc l
    add hl, de
    ld b, c
    add l
    ld [$19c9], sp
    rla
    sub h
    ret


    ld a, [bc]
    cpl
    dec bc
    sub l
    ld d, [hl]
    sbc b
    pop hl
    add [hl]
    add hl, de
    ld hl, $e405

Call_00a_5829:
    pop bc
    inc d
    ld d, l
    ld d, h
    inc h
    push hl
    adc b
    add c
    ld [hl+], a
    inc b
    add $76

jr_00a_5835:
    add c
    dec b
    ld [$6853], sp
    adc $14
    pop de
    pop hl
    ld l, d
    add l
    ld [$18d2], sp
    ld h, h
    inc d
    ld d, e
    ld [$85b7], sp
    add c
    add c
    ld e, h
    ldh [$8a], a
    adc b
    ld c, c
    add c
    jr nc, jr_00a_5835

    ld de, $924a
    inc de
    jr jr_00a_587c

    inc h
    or h
    push hl
    ld h, d
    inc de
    inc h
    jr z, @-$69

    ld e, b
    ld d, d
    add sp, -$36
    rlca
    ld e, d
    ld b, $04
    inc hl
    dec b
    add d
    ld h, $49
    ld c, e
    add d
    jr nc, jr_00a_58d3

    adc b
    ld e, b
    ld d, b
    ld c, e
    ld h, h
    sub l
    ld h, $a8
    add h
    sub h

jr_00a_587c:
    ld [hl+], a
    ld [$89aa], a
    ld b, d
    dec h
    ld h, b
    ld c, b
    ld h, c
    ld c, h
    sub d
    sub $4d
    sub [hl]
    dec c
    ld e, e
    ld b, c

jr_00a_588d:
    adc h
    xor d
    xor h
    jp nc, $29d9

    ld d, [hl]
    adc b
    ld d, [hl]
    cp e
    sub d
    sub d
    jp c, Jump_000_3316

    or a
    and l
    ld [$81aa], a
    ld a, a
    add sp, $24
    sbc d
    xor d
    dec d
    adc l
    db $eb
    db $fd
    rst $38
    rst $38
    cp $8c
    add hl, hl
    ld d, l
    ld e, d
    adc h
    scf
    call Call_00a_572b
    xor c
    and $38
    ld hl, $78e1
    jp nc, $e878

    ld e, a
    call nc, $9584
    daa
    add [hl]
    db $fd
    sbc b
    call z, $a7ff
    add a
    ld [hl], h
    ld l, e
    call nz, $e851
    call z, Call_00a_4a78

jr_00a_58d3:
    xor d
    and [hl]
    sub d
    xor c
    ld de, $a6aa
    cpl
    adc l
    jr z, jr_00a_588d

    ld c, d
    ld c, d
    dec d
    ld d, a
    and [hl]
    ld l, h
    ld [de], a
    add hl, bc
    ld l, $11
    ld c, b
    call $8434
    cp b
    add hl, hl
    jp nz, $b184

    ld [$0831], sp
    xor [hl]
    ret z

    ld b, d
    adc l

jr_00a_58f8:
    ld hl, $1146
    xor h
    ld a, [bc]
    ld b, e
    dec b
    inc c
    add d
    ld h, c
    jr @+$43

    ld l, c

jr_00a_5905:
    inc c
    ld l, h

jr_00a_5907:
    ret nz

    and h
    ld l, d
    ld [de], a
    db $10
    and d
    sbc d
    ret z

    ld e, a
    add hl, hl
    xor h
    ld b, d
    ld d, d
    ld [de], a
    ret


    inc de
    ret nz

    ret nz

    sbc b
    pop bc
    sbc $d2
    sbc e
    ld c, b
    jr nz, jr_00a_5905

    ld c, l
    ld a, [hl+]
    ret nc

    ld sp, $129c
    ld b, l
    ld l, $95

jr_00a_592a:
    jr nz, @-$3a

    ld [$424a], a
    xor b
    ret


    push bc
    ld d, b
    ld d, h
    ld a, [hl-]
    jr nc, jr_00a_58f8

    dec bc
    dec bc
    dec l
    ld a, [hl+]
    ld [de], a
    ld sp, $4592
    jr jr_00a_5907

    db $10
    ld b, b
    jp nz, Jump_000_0ecc

    add e
    db $10
    sbc e
    pop de
    ld l, d
    ld c, d
    ld b, d
    db $10
    ld b, b
    or e
    inc bc
    ret nc

    xor l
    ld a, [de]
    and e
    ld b, l
    xor c
    ld d, h

jr_00a_5958:
    ld d, a
    ld b, b
    jp nz, $14c1

    add $f6
    and h
    ld a, [hl+]
    ld de, $295a
    add hl, hl
    jr nc, @+$27

    jr z, jr_00a_592a

    jr jr_00a_59ac

    dec bc
    ld a, a
    ld b, e
    ld d, $84
    sub c
    inc d
    ret nz

    xor l
    add h
    db $10
    dec h
    or e
    inc [hl]
    sbc h
    inc d
    ld c, h
    ld e, l
    ld b, b
    add a
    inc c

jr_00a_5980:
    ld h, b
    ret nz

    add h
    ld b, d
    sbc c
    dec h
    ld l, h
    add d
    ld h, a
    db $10
    ret nz

    jp nz, $a9b0

    ld [hl], a
    xor d
    xor d
    ld h, c
    or h
    jp z, $b162

    dec bc
    ld b, h
    ld [hl-], a
    ld a, [bc]
    dec l
    ld hl, $4655
    db $76
    and e
    ld d, d
    or h
    ld l, b
    pop bc
    sub b
    and b
    or h
    ld d, e
    ld a, [de]
    call nc, $a61a

jr_00a_59ac:
    adc e
    ld b, h
    jp z, $a216

    xor l
    inc e
    db $10
    jr nc, jr_00a_5980

    xor d
    xor l
    ld a, [de]
    ld d, h
    inc [hl]
    ld h, [hl]
    ld b, h
    ld sp, $f55b
    add hl, sp

jr_00a_59c1:
    sbc [hl]
    ld [hl+], a
    xor a
    push de
    cp $54
    ret


    add d
    ld sp, $5497
    ld a, [hl+]
    adc h
    jr jr_00a_5958

    push bc
    sub b
    ld d, b
    and h
    push bc
    dec h
    inc sp
    sub h
    add hl, hl
    ld sp, $4d8a
    jr nc, jr_00a_5a26

    sub e
    ld b, [hl]
    inc sp
    cp h
    ld [de], a
    inc de
    jr c, jr_00a_59c1

    rst $00
    cp b
    pop bc
    ld h, e
    ld b, [hl]
    jr c, jr_00a_5a01

    sub $21
    ld b, $34
    or h
    push bc
    add l
    or $55
    adc h
    cpl
    jp $a006


    ld e, [hl]
    dec bc
    ld d, b
    adc h
    ldh [$5a], a

jr_00a_5a01:
    rst $38
    add sp, -$3e
    xor b
    ld a, [$8259]

Jump_00a_5a08:
    ld a, [de]
    xor c
    push de
    rst $38
    ld a, a
    and h
    ld a, [hl+]
    ld l, l
    inc de
    ld a, d
    rla
    dec b
    cp $1f
    sbc b
    push bc
    ld hl, $2a79
    ld b, l
    ld a, c
    add d
    ld h, b
    pop af
    rrca
    jp hl


    ld d, [hl]
    ld l, a
    ld l, c
    rla

jr_00a_5a26:
    jp hl


    add $fa

jr_00a_5a29:
    ld d, $8d
    db $ec
    ld [hl], b
    rst $38
    db $e3
    ld sp, hl
    dec de
    ld a, [bc]
    ld c, $60
    cp a
    ldh a, [$3f]
    dec bc
    ld sp, hl
    jr jr_00a_5ab4

    ld l, l
    cp $0f
    jp nz, $c0ff

    ld hl, sp+$79
    sbc l
    cp $bf
    db $fc
    scf
    rst $08
    sbc b
    ld d, b
    dec l
    ld a, a
    db $f4
    ld h, c
    ld d, h
    ld h, l
    rra

Jump_00a_5a52:
    db $76
    ld [hl], a
    cp c
    ld d, a
    and l
    add hl, hl
    ld e, d
    xor a
    ld a, [$53a5]
    sbc l
    ld a, [$8a08]
    ld l, c
    ld e, d
    and d
    ld l, d
    xor h
    ld a, [hl-]
    ld d, e
    add l
    ldh [rBCPD], a
    add hl, bc
    ld [hl], b
    ld l, b
    ret


    ld d, b
    xor c
    ld d, l
    and e
    add c
    ld b, l
    daa
    ld l, b
    inc hl
    dec d
    add hl, bc
    ld e, [hl]
    and e
    sbc c
    ld c, h
    ld d, d
    ld [hl+], a
    push de
    rlca
    inc c
    db $eb
    ld b, d
    ld hl, $30a5
    ld e, d
    inc c
    ld a, [hl]
    ld a, [hl-]
    db $d3
    jr c, jr_00a_5a29

    adc h
    dec sp
    rst $38
    ld d, e
    sub l
    ld d, [hl]
    scf
    ld c, d
    ld d, l
    xor d
    cp a
    ld c, [hl]
    dec h
    inc d
    add [hl]
    sub e
    ld d, $25
    ld b, [hl]
    xor d
    ld e, h
    dec d
    ld l, d
    ld [hl-], a
    ld d, b
    and e
    jr jr_00a_5b05

    ld b, [hl]
    jp nc, Jump_00a_5564

    cp $ac
    adc b
    pop bc
    and b

jr_00a_5ab4:
    adc [hl]
    inc [hl]
    ld e, h
    xor a
    xor b
    sub [hl]
    ld [hl+], a
    dec l
    add c
    ld [hl-], a
    ld b, l
    add [hl]
    ld e, b
    adc b
    add [hl]
    and d
    sbc l

Jump_00a_5ac5:
    adc b
    ld h, d
    sbc l
    ld d, d
    ld de, $a189
    add c
    and h
    db $10
    ld b, c

Jump_00a_5ad0:
    adc e
    ld a, a
    adc c
    adc e
    ld c, h
    xor b

jr_00a_5ad6:
    pop hl
    pop bc
    adc e
    ld a, [hl]
    adc c
    ld h, e
    inc d
    inc hl
    add c
    and b
    sub [hl]
    inc d
    or a
    ld [c], a
    sbc b
    add $18
    sub [hl]
    ld c, [hl]
    sub a
    ld [c], a
    sbc b
    db $dd
    jr jr_00a_5ad6

    ld b, l
    cp b
    sub [hl]
    adc l
    and b
    adc b
    ld c, l
    ld h, l
    ld d, d
    ret c

    or [hl]
    jr c, @+$2a

    cp c
    adc b
    and h
    ld a, [c]
    ld l, b
    sbc $30
    adc l
    ld d, e

jr_00a_5b05:
    sub d
    jp c, $94a4

    pop bc
    ld d, [hl]
    ld sp, $154e
    ld l, $49
    ld c, c
    ld c, d
    ld c, c
    ld h, e
    inc c
    ld d, [hl]
    xor c
    ld d, l

jr_00a_5b18:
    ld l, [hl]
    ld [hl-], a
    and l
    call nc, Call_000_338a
    sub d
    sbc a
    xor d
    and l
    ld d, l
    sbc $35
    xor e
    call nc, Call_000_3095
    sub d
    dec e
    ld [$7f95], a
    and e
    sub d
    cp l
    ld [hl+], a
    xor b
    xor d
    add a
    ld h, h
    ld a, $a3
    or [hl]
    jp c, Jump_00a_5a52

    xor c
    dec bc
    ld [hl], l
    and l
    dec sp
    and h
    push de
    ld h, $bf
    add $ce
    ld [$7075], a
    ld e, b
    jp z, Jump_000_30aa

    call c, $99ea
    xor d
    xor d
    xor d
    sbc l

jr_00a_5b55:
    adc b
    ld d, c
    inc d
    and b
    cp a
    cp [hl]
    ld e, $5d
    ld d, d
    sbc h
    adc a
    add $0f
    jr nc, jr_00a_5b98

    ld h, h
    xor l
    ld d, h
    ld [hl], c
    xor d
    ld e, e
    ld d, e
    inc [hl]
    ld h, b
    push de
    dec e
    ld c, c
    adc d
    jr nc, jr_00a_5b18

    cp a
    sbc l
    ret z

    and [hl]
    sub c
    add h
    pop de
    jp c, $9591

    ld de, $2d25
    ret z

    ld a, [hl+]
    sbc l
    add hl, bc
    jp $91ff


    ld d, [hl]
    xor e
    ld c, c
    ret z

    sbc h
    ld d, c
    ld a, [bc]
    ld h, a
    ld d, c
    ld c, d
    ld l, b
    sbc h
    sub d
    ld [de], a
    add [hl]
    sub [hl]
    xor l

jr_00a_5b98:
    ld d, h
    ld de, $1c93
    xor e
    ld a, $85
    xor l
    ld b, e
    sub l
    jr jr_00a_5b55

    adc h
    ld l, e
    inc c
    add l
    call nc, Call_000_192a
    ld c, h
    ld h, b
    add $49
    add h
    ld d, d
    inc l
    call nz, $c52c
    add $2b
    add hl, de
    add $eb
    db $10
    call $c616
    ld c, b
    ld b, [hl]
    ld c, h
    ld h, b
    sub d
    xor b
    dec l
    ld sp, $1983
    pop bc
    ld a, [de]
    add $88
    jp nz, $acc5

    ld [hl], l
    cp c
    or l
    xor c
    ld l, h
    ld [hl], b
    and [hl]
    ret


    add d
    ld b, a
    ld a, [hl-]
    xor e
    pop de
    push bc
    ld b, $75
    ld l, l
    ld c, b
    ld a, c
    rr h
    pop af
    rla
    or d
    inc d
    ld [hl], e
    ld c, c
    call $1113
    dec e
    ld d, d
    sbc c
    and [hl]
    ld sp, $428a
    xor c
    ld l, d
    ld l, e
    ld c, d
    sub [hl]
    sbc b
    ret


    ld d, a
    jp nc, Jump_00a_55a1

    ld c, d
    ld [hl], c
    ld d, d
    add h
    add hl, bc
    sub h
    sub b
    add a
    db $e4
    ld d, l
    ld d, h
    ld [hl], h
    ld d, [hl]
    xor c
    sub l
    ld b, h
    ld c, h
    sbc [hl]
    dec e
    add $a9
    inc sp
    jp z, Jump_000_3278

    sbc c
    ld h, $34
    ld sp, hl
    pop hl
    ld d, d
    xor e
    ld b, a
    jr c, @+$46

    cp d
    rla
    db $e3
    adc l
    ld d, h
    ld e, [hl]
    ld h, l
    ld c, [hl]
    rlca
    ld [$60ae], a
    add [hl]
    scf
    and d
    sub b
    db $ec
    ld h, l
    adc l
    xor b
    add [hl]
    db $eb
    ld h, d
    sub e
    adc d
    jr nc, jr_00a_5c91

    push hl
    adc b
    ld c, b
    adc b
    add [hl]
    ld [hl], $52
    add hl, hl

jr_00a_5c45:
    sub b
    ld c, b
    ld c, [hl]
    dec hl
    pop bc
    ld hl, $a142
    ld h, e
    add [hl]
    cp [hl]
    ld b, $8e
    sbc d
    ld [$456a], sp
    sub e
    sbc d
    ld b, d
    ret nc

    add d
    jr c, jr_00a_5c45

    sbc d
    ld h, a
    ld c, $38
    rst $28
    ld d, l
    ld e, d
    ld d, h
    and $aa
    adc a
    cpl
    db $76
    daa
    ld a, [de]
    ld h, b
    ldh [$c7], a
    inc d
    rrca
    ret nz

    adc h
    ld de, $d2c5
    jp nc, $c7cc

    rla
    pop af
    jr jr_00a_5cd6

    reti


    ld b, a
    ld d, h
    ld b, d
    ld [de], a
    rst $00

jr_00a_5c83:
    ld a, [hl-]
    jr nc, @-$30

    ld [hl], h
    ret


    ld e, d
    db $76
    ld c, e
    ld h, a
    ld d, a
    sub c
    inc b
    ld [hl], l
    add hl, hl

jr_00a_5c91:
    inc de
    dec e
    dec sp
    ld a, [hl+]
    ld d, $a7
    dec [hl]
    dec b
    db $eb
    dec c
    ld b, a
    inc [hl]
    ld a, c
    ldh [rHDMA5], a
    cp h
    ld h, l
    scf
    ld d, h
    ld e, a
    push af

jr_00a_5ca6:
    dec b
    ld d, d
    sbc [hl]

jr_00a_5ca9:
    inc [hl]
    ld e, a
    xor d
    ld [c], a
    ld l, e
    inc b
    ld a, [de]
    sub h
    call $855e
    and h
    ret


    ld l, a
    ld [hl], h
    ld h, h
    cp d
    push af
    ld e, b
    ld d, e
    ld a, b
    inc l
    sub h
    sub h
    dec h

jr_00a_5cc2:
    ld a, [bc]
    pop bc
    sub e
    adc a
    ld c, e
    add d
    add [hl]

jr_00a_5cc9:
    ldh [rDMA], a
    jr c, jr_00a_5cc9

    ld h, c
    add d

jr_00a_5ccf:
    ld l, $25
    jr c, jr_00a_5ccf

    sbc b
    inc hl
    dec d

jr_00a_5cd6:
    jr jr_00a_5ca6

    adc e
    di
    ld [hl], l
    and e
    ld b, l
    jr nc, jr_00a_5cc2

    ld d, a
    cp a
    add l
    ld d, a
    cp $2d
    di
    ld [$1bc6], sp
    add sp, $67
    ld b, c
    rlca
    ld a, [hl]
    dec h
    and c
    sub d
    inc d
    ld d, d
    and d
    ld h, b
    cp e
    add d
    dec l
    jr jr_00a_5c83

    ld d, b
    and b
    push de
    adc [hl]
    ld c, d
    inc hl
    ld sp, $536a
    sbc c
    dec e
    or c
    ld b, l
    jp z, $8593

    jr jr_00a_5ca9

    add [hl]
    cp a
    db $d3
    dec de
    ld d, l
    ld c, e
    cp b
    jp nz, $b530

    adc b
    ld l, b
    sub h
    add [hl]
    ld [hl+], a
    adc [hl]
    ld a, [de]
    ld d, [hl]
    and d
    jr jr_00a_5d37

    dec sp
    sub l
    or [hl]
    adc h
    rst $30
    cp [hl]

jr_00a_5d27:
    sbc e
    and [hl]
    db $ed
    ld b, l
    pop bc
    cp l
    ld c, d
    sub b
    sbc e
    call nz, $8a29
    sub a
    ld c, d
    ld l, l
    and d

jr_00a_5d37:
    or c
    sbc h
    ld h, d
    and l
    xor l

jr_00a_5d3c:
    ld [de], a
    ld a, [$4076]
    xor h
    cp b
    ld b, a
    ld b, h
    ld c, h
    db $10
    ld sp, $82c4
    ld l, l
    inc b
    add hl, bc
    ld c, c
    ld [hl-], a
    ld e, d
    ld de, $c5c2
    inc l
    jr z, jr_00a_5d27

    or b
    ld sp, $c3cc
    ld l, b
    xor d
    rra
    add h
    ld [hl], a
    ld [hl], l
    ld d, c
    jp nz, Jump_000_16a3

    sub d
    add l
    ld a, [bc]
    sbc h
    ld e, c
    ld de, $eb72
    sub b
    sbc h
    jr nc, jr_00a_5d93

    jp hl


Call_00a_5d70:
    ld c, a
    ld d, l
    ld a, [$189c]
    ld b, h
    ld [hl], b
    ld [hl], h
    and c
    sbc b
    ld d, [hl]
    xor c
    add d
    ldh a, [$e5]
    ld [hl], c
    ld d, l
    ld h, $77
    rst $38
    call nc, Call_00a_7042
    jp z, Jump_00a_6642

    rst $00
    ld c, l
    ld b, h
    jr nc, jr_00a_5d3c

    ld e, $06
    or h
    ld l, d

jr_00a_5d93:
    ld b, h
    cp l
    dec [hl]
    ld d, e
    and c
    ld l, d
    ld [$54d0], a
    push de
    rlca
    ld a, [$d1ab]
    ld [$f035], a
    ld c, h
    sbc d
    jr c, jr_00a_5dbc

    daa
    ld c, h
    and h
    pop hl
    db $fc
    ld a, [c]
    and e
    adc c
    ld c, h
    ld e, a
    adc b
    add l
    dec [hl]
    ld d, h
    jp z, Jump_000_1441

    sbc $79
    ld d, h

jr_00a_5dbc:
    ld [hl+], a
    ld de, $3a4e
    adc c
    sub b

jr_00a_5dc2:
    ld e, b
    inc de
    sub d
    and c
    ld l, l
    ld e, b
    inc hl
    adc [hl]
    ld a, [$3b3e]
    ld a, h
    ld [hl], d
    ld c, d
    ld a, [hl+]
    add hl, hl
    ret


    ld [bc], a
    ret nz

    xor c
    db $10
    ld h, $fa
    ld sp, $8a74
    ld l, d
    sub c
    ld d, c
    adc l
    ld d, c
    or h
    ld a, [bc]
    sbc d
    daa
    inc c
    ld [hl], a
    jp hl


    adc e
    ld c, c
    jp z, $a898

    ld c, [hl]
    ld [hl], c
    ret nc

    jr z, jr_00a_5dc2

    ld c, d
    ld [hl], e
    ld b, e
    xor a
    inc h
    or d
    ld [hl], d
    ld b, e
    adc l
    ld d, c
    push af
    nop
    ld h, [hl]
    cp b
    ld e, a
    db $d3
    res 4, b
    ld a, b
    di
    db $dd
    inc a
    sub l
    inc e
    inc d
    add sp, $53
    add l
    and e
    adc c
    xor d
    ld b, l
    sub e
    ld b, l
    jp hl


    or [hl]
    sbc $4a
    ld d, l
    ld l, h
    xor e
    ld a, [bc]
    ld [hl-], a
    ld a, b
    inc de
    inc b
    sub l
    xor b
    xor a
    db $f4
    adc b
    inc hl
    rla
    add l
    dec b
    dec d
    add hl, bc
    ld b, l
    xor b
    adc $34
    ld e, d
    ld a, [hl+]
    dec l
    dec d
    adc c
    and h
    ld [c], a
    ld a, e
    ld c, e
    ld l, c
    inc e
    push de
    dec sp
    ld [de], a
    inc de
    ld h, [hl]
    jr c, jr_00a_5ea1

    cp d
    jr nc, jr_00a_5e8d

    ld c, c
    ld c, e
    ld c, [hl]
    inc h
    add sp, -$5c
    add h
    xor $50
    ld b, a
    ld b, l
    ld a, h
    ld a, [hl+]
    add hl, sp
    add sp, -$7c
    adc d

jr_00a_5e55:
    ld hl, $2098
    ld d, h
    db $eb
    ld a, a
    ld [hl], $a6
    sub e
    dec [hl]
    jr nc, jr_00a_5ea9

    ld e, c
    adc h
    ld e, [hl]
    pop de
    reti


    ld c, h
    ld e, [hl]
    add a
    ld [hl+], a
    and b
    ld d, [hl]
    ld [hl+], a
    inc sp
    or [hl]
    xor b
    push bc
    add d
    adc d
    and h
    pop bc
    inc d
    and l
    ld h, $cd
    ld hl, $aaa2
    dec de
    ld l, b
    inc h
    inc h
    sbc e
    ld a, [de]
    ld a, [hl-]
    inc hl
    ld c, c
    ld a, [bc]
    sub l
    ld e, h
    pop af
    jp hl


    ld c, a
    ld b, [hl]
    sub h

jr_00a_5e8d:
    db $e4
    pop de
    ld e, c
    ld h, e
    sub d
    and l
    ld d, e
    dec d
    ld l, b
    jr z, jr_00a_5e55

    ret z

    sbc [hl]
    ld [hl], e
    rst $00
    sbc [hl]
    add d
    ld a, c
    ld l, h
    ld [hl-], a

jr_00a_5ea1:
    ld a, c
    ld l, d
    xor c
    jp nz, $94a1

    sbc h
    dec c

jr_00a_5ea9:
    rst $10
    ld c, d
    ld e, d
    ld d, l
    call nz, Call_00a_46c1
    ld l, c
    ld d, b
    ret z

    ld e, c
    ld a, [hl-]
    rst $18
    ld d, b
    jp nc, $1182

    and e
    ld b, $ac
    db $10
    call nz, Call_000_1954
    dec d
    ld c, d
    ld a, $99
    db $e4
    ret nc

    ld b, h
    ld hl, $153f
    ld c, c
    ld [hl], d
    dec c
    and l
    add sp, -$4f
    adc a
    add $89
    adc h
    ret nz

    and h
    ld sp, $b610
    sbc h
    inc l

jr_00a_5edc:
    ld l, c
    ld h, c
    ld de, $4530
    ld b, h
    xor c
    and d
    ld a, b
    ld [hl], b
    inc a
    xor c
    ld [hl], d
    ld [hl], c
    and l
    and d
    sub b
    bit 3, a
    ld d, $9c
    ld [hl], h
    ld b, d
    inc [hl]
    ld c, e
    jp Jump_00a_6821


    inc [hl]
    ld [hl], e
    scf
    sbc e
    di
    ld a, [hl+]
    ld h, d
    xor d
    ld l, e
    pop af
    add e
    ld [bc], a
    jr nc, jr_00a_5f65

    ld hl, $bf24
    rst $10
    and c
    ld b, $38
    and b
    add $56
    adc $84
    ld h, c
    ld d, b
    call nz, $9654
    pop bc
    rla
    jr nz, jr_00a_5edc

    ld d, d
    adc d
    push bc
    ld c, e
    inc de
    ld d, c
    sub h
    sbc b
    ld b, d
    xor a
    inc bc
    rla
    add hl, de
    add $b0

jr_00a_5f2a:
    ld h, $15
    ld de, $8127
    dec b
    add hl, hl
    and h
    ld h, b
    sbc b
    ld [hl+], a
    sbc h
    ld d, h
    xor b
    xor d
    add $17
    xor d
    inc e
    inc e
    ld [hl], e
    pop de
    sub d
    add a
    add l
    ld b, l

jr_00a_5f44:
    add b
    ld b, h
    cp c
    dec d
    ld a, [hl]
    and e
    ld d, l
    dec h
    ld a, a
    xor d
    jr jr_00a_5f2a

    cp c
    ld a, [$6331]
    ld h, [hl]
    jr jr_00a_5f44

jr_00a_5f57:
    ld b, d
    ld [hl], $4e
    ld a, [bc]
    jr c, jr_00a_5f70

    cp l
    adc [hl]
    inc b
    db $ed
    ld a, d
    ld hl, $7331

jr_00a_5f65:
    adc l

Jump_00a_5f66:
    xor b
    and l
    ld hl, sp-$22
    db $fd
    ld d, l
    inc hl
    jr jr_00a_5f57

    sbc l

Jump_00a_5f70:
jr_00a_5f70:
    ld d, d
    ld d, e

Call_00a_5f72:
    and [hl]
    sub l
    ld [$ec2c], sp
    ld d, [hl]
    dec b
    ld a, [hl-]
    ld [$1f8f], a
    ld [hl], d
    ld [hl+], a
    ret


    adc $cc
    inc d
    ld b, h
    sbc e
    ld d, d
    inc a
    ld h, [hl]
    add $c8

Jump_00a_5f8a:
    ld h, h
    ld b, [hl]
    ld d, c
    jp $d2c6


    ld l, a
    add d
    inc l
    ld l, c
    daa
    dec b
    dec de
    add hl, hl
    or d
    ld l, a
    ld b, a
    ld [bc], a
    ld l, a
    ld h, $f0
    cp c
    or h
    ld l, l
    ld d, b
    add hl, hl
    ld e, [hl]
    and d
    and a
    dec h
    add hl, hl
    jr jr_00a_601c

    push de
    ld d, b
    ld b, c
    ld c, d
    ld [hl], l
    xor d
    pop de
    ldh a, [$a0]
    ld h, [hl]
    or b
    ld e, a
    rst $38
    ld d, e
    or l
    ld d, d
    ld [$1b45], a
    push af
    ld c, c
    ld d, l
    ld c, l
    xor c
    ld l, $82
    add d
    inc c
    db $10
    and h
    ld l, c

jr_00a_5fca:
    jp hl


jr_00a_5fcb:
    ld a, [de]
    ld c, h
    sub a
    bit 2, h
    dec a
    cp $a8
    ld [hl+], a
    ld d, d
    ld [hl-], a
    ld h, h
    ld d, a
    jp nc, $0a33

    ld d, [hl]
    ld b, c
    ld d, l
    ld h, e
    inc b
    jp nz, Jump_00a_71a8

    db $e3
    inc h
    adc a
    xor c
    ld sp, $52a2
    sub d
    db $76
    inc b
    or [hl]
    db $76
    ld l, $4b
    ld [hl], b
    ret z

    sub d
    ld l, c
    ld [hl+], a
    ld [$25a4], sp
    ld [hl], $68
    ld a, [hl+]
    and d
    ld h, d
    and $2d
    inc b
    ldh [$4e], a
    ld e, b
    ld a, [hl+]
    jr nc, @-$5b

    jr c, jr_00a_5fca

jr_00a_6009:
    xor e
    ld c, c
    adc e
    adc h
    inc de
    sbc d
    inc b
    ld h, e
    ld l, b
    or l
    call Call_000_2212
    ld h, b
    add l
    ld a, [bc]
    ld [$63e2], sp

jr_00a_601c:
    inc d
    and h
    ld l, a
    ret c

    inc d
    inc de
    sub c
    sub h
    add l
    jr nc, jr_00a_5fcb

    sbc a
    add c

jr_00a_6029:
    ld [hl-], a
    adc e
    ld h, h
    ld [de], a
    ld a, [hl+]
    dec l
    ld d, d
    add hl, hl
    ld d, l
    adc [hl]
    ld e, b
    add hl, de
    ld c, d
    ld l, b
    adc d
    ld c, [hl]
    cp c
    inc d
    adc c
    ld b, $32
    adc [hl]
    ret z

    ld h, l
    add hl, hl
    ld d, d
    db $e3
    add a
    ld hl, sp-$39
    ld d, l
    and b
    cp d
    and l
    ld e, b
    db $dd
    or b
    ld h, d
    call nc, Call_00a_6454
    ld [hl-], a
    ld h, e
    adc c
    adc b
    sub d
    and $81
    ld h, l
    add hl, bc
    add hl, sp
    ld d, l
    inc d
    ld h, e
    jr c, jr_00a_6071

    ld d, h
    ld h, b
    ld e, b
    call $1b56
    pop hl
    adc e
    and l
    ld [hl+], a
    ld [hl+], a
    add d
    ld d, $95
    ld d, [hl]
    adc l

jr_00a_6071:
    dec hl
    jr nc, jr_00a_6009

    ld [hl], l
    sub l
    ld e, d
    ld a, [hl-]
    inc d
    dec e
    add d
    jr jr_00a_6029

    ld a, b
    add hl, hl
    ld a, h
    adc e
    ld c, l
    or b
    and [hl]
    add hl, hl
    or [hl]
    inc d
    ld d, [hl]
    inc d
    dec c
    ld a, [hl+]
    rra
    ld b, b
    and b
    db $fc
    pop bc
    and [hl]
    cp [hl]
    ld h, b
    add e
    rst $30
    db $fd
    inc h
    xor d
    adc h

jr_00a_6099:
    ld [hl], $8a
    ld a, [de]
    ld [hl], b
    ld d, b
    ld l, $72
    push bc
    ld e, h
    rrca
    sbc c
    and c
    and c
    ld d, l
    ld [hl], d
    ld [$c04a], sp
    and h
    ld b, c
    jr z, jr_00a_6099

    ld h, b
    or l
    jp z, Jump_000_0497

    ld a, [bc]
    ld c, e
    ld e, b
    xor c
    inc d
    pop de
    ld l, [hl]
    jr c, jr_00a_6101

    ld c, c
    ld [hl], a
    ld b, h
    call nz, $4cc3

jr_00a_60c3:
    ld [de], a
    and h
    cp b
    pop bc
    add hl, de
    jp nc, Jump_000_036d

    and c
    sub c
    inc de
    dec bc
    daa
    inc de
    pop hl
    and l

jr_00a_60d3:
    sbc $39
    add [hl]
    sbc c
    add $5f
    and e
    ld [bc], a
    and h
    ld [hl], c
    add hl, de
    add e
    adc h
    ld d, h
    ld e, d
    sub c
    dec b
    cp e
    ld a, [hl+]
    ld [hl], b
    jp c, $d112

    sub d
    sub e
    di
    ld h, $49
    adc d
    xor c
    sbc d
    inc [hl]
    ret z

jr_00a_60f4:
    pop hl
    jp $2235


    push bc
    jp hl


    inc c
    sub [hl]
    call $df53
    xor d
    ld sp, hl

jr_00a_6101:
    ld d, b
    ld b, [hl]
    jr z, jr_00a_60c3

    dec d
    ld d, h
    inc [hl]
    sub e
    ld c, c
    ccf
    add sp, $21
    add hl, de
    jp nc, Jump_00a_4a32

    sub d
    sbc b
    ld b, h
    ld a, a
    rst $38
    ld a, [bc]
    ld l, b
    sub c
    ld d, c
    rra
    add $d0
    ld e, h
    dec bc
    ret nz

    and $35
    ld e, d
    push af
    or $98
    ld b, [hl]
    inc l
    jr nc, jr_00a_60d3

    sbc d
    rla
    ld b, $44
    inc d
    sub b
    push bc
    inc hl
    ld [bc], a
    ret nc

    ld [hl], h
    ld d, [hl]
    cpl
    ei
    ld h, b
    adc d
    ld c, l
    ld b, b
    adc [hl]
    ldh a, [$d1]
    dec hl
    db $e4
    xor b
    ret nz

    adc a
    or l
    ld b, d
    add e
    ld l, a
    ld [bc], a
    db $10
    ld h, l
    ld h, b
    ld sp, hl
    ld [hl], h
    jr jr_00a_60f4

    or h
    dec bc
    dec bc
    inc b
    jr jr_00a_619c

    sub l
    ld a, c
    add d
    jr nc, jr_00a_61d4

    ld [de], a
    ld [hl], l
    ld l, d
    nop
    ld b, h
    or [hl]
    ld d, l
    dec h
    ld a, a
    di
    add c
    ld [$8369], a
    ld hl, $288e
    scf
    ld e, l
    ld l, d
    ld h, e
    add d
    rst $30
    add hl, bc
    pop hl
    adc [hl]
    ld l, d
    xor d
    dec a
    add sp, -$4c
    ld e, b
    push hl
    ld l, l
    ld e, b
    ld d, h
    push hl
    ld d, c
    sub c
    ld h, c
    adc [hl]

Jump_00a_6184:
    ld e, e
    ld e, b
    inc hl
    and c
    or [hl]
    ld hl, $8e21
    ld a, [hl+]
    ld b, c
    ret c

    ld a, d
    add hl, sp
    inc d
    sub [hl]
    inc b
    ld a, [hl+]
    adc [hl]
    dec sp

jr_00a_6197:
    cp $a3
    ld [c], a
    rst $30
    ld b, d

jr_00a_619c:
    ld b, d
    ld [hl], c
    ld a, l
    jr z, jr_00a_6197

    jp nc, Jump_00a_4b72

    ld b, b
    db $fc
    ld sp, hl
    call z, $8cfe
    ld [de], a
    ld [hl], d
    ld h, b
    ret nc

    call nz, $3247
    jr z, jr_00a_61e4

    sub $8c
    db $76
    ld l, h
    sub b
    adc $9c

jr_00a_61ba:
    sbc h
    rst $10
    ld c, a
    inc b
    ld [hl], e
    ld c, c
    ld d, $c7
    ld d, h
    rst $20
    ld a, l
    ld d, b
    ld a, [hl+]
    ld [hl], e
    ld l, $a3
    dec e
    inc [hl]
    ld a, h
    ld [hl], b
    ld h, [hl]
    cp d
    ld d, h
    add l
    db $fd
    inc a

jr_00a_61d4:
    ld e, a
    cp d
    ld a, [$3cdd]
    ld c, e
    ld c, d
    xor [hl]
    adc h
    ld d, e
    daa
    db $f4
    sub a
    jp nc, $265d

Call_00a_61e4:
jr_00a_61e4:
    ld d, a
    call z, $302a
    and d
    add hl, hl
    ld c, b
    ld b, d
    ld l, d
    xor b
    rla
    add d
    adc h
    ld a, [hl+]
    add l
    rst $30
    adc d
    jp Jump_00a_46e0


    ld c, $82
    adc e
    ld d, h
    cp h
    dec [hl]
    ld b, [hl]
    ld hl, $3858
    xor c
    ld l, e
    dec c
    ld d, l
    ld a, [$0abd]
    ld c, d
    ld d, c
    ld a, d
    ld b, l
    and l
    ld [$0596], sp
    xor d
    push af
    dec h
    ld b, $a0
    ld d, [hl]
    call nc, $6499
    ld d, [hl]
    add sp, -$76
    and l
    ld b, d
    or l
    dec h
    add d
    ld h, $4c
    ld [hl], l
    inc sp
    ld d, b
    ld e, d
    ld h, $33
    adc l
    ld h, c
    ld c, h
    and [hl]
    inc d
    cp b
    ld h, l
    ld h, d
    ld l, b
    add $15
    inc [hl]
    xor c
    jr nc, jr_00a_61ba

    dec l
    db $e3
    add c
    ld l, d
    ld d, d
    jr nz, @-$7d

    ld d, l
    add hl, hl
    rlca
    ld d, h
    inc d
    or h
    ld [hl], d
    ld [hl+], a
    sub [hl]
    ld [$5a29], sp
    cp l
    dec d
    ld d, h
    ld l, d
    push de
    ld a, a
    adc b
    adc c
    ld a, a
    add d
    ld h, b
    ld [hl], l
    ld l, $54
    ld l, d
    ld [hl+], a
    xor c
    ld d, d
    inc d
    sub l
    ld [hl], l
    ld b, $eb
    db $f4
    sbc b
    ld h, b
    add d
    jr nc, jr_00a_62bd

    ld e, d
    ld d, d
    ld e, d
    inc b
    add hl, hl
    ld d, b
    rst $18
    ld c, c
    and e
    dec [hl]
    ld b, c
    add d
    and b
    push hl
    ld a, e
    pop de
    ld b, c
    rrca

Jump_00a_627b:
    ldh [rOBP1], a
    and e
    dec h
    ld h, c
    xor c
    sub a
    ld d, $4a
    ld e, c
    ld e, b
    ld l, b
    ld a, $33
    adc c
    cp b
    dec d
    jp $e8f0


    ld h, d
    xor b
    adc b
    ld [hl], $38
    push de
    ld hl, sp+$5c
    inc de
    ld a, [bc]
    ld h, $8e
    ld a, a
    ld h, d
    inc a
    add l
    ld e, a
    adc b
    ld a, b
    add sp, -$43
    ld d, b
    pop af
    sbc $85
    ld a, [hl]
    dec sp
    scf
    add sp, $15
    xor a
    ld a, [$9d32]
    add hl, hl
    ld c, b
    add hl, sp
    db $e3
    ld b, d
    add d
    ld [de], a
    add hl, bc
    push hl
    ld a, a
    ld sp, hl
    push de

jr_00a_62bd:
    rla
    dec h
    xor l
    cpl
    inc c
    ld h, e
    ld [bc], a
    ld h, c
    inc de
    sub d
    add h
    and b
    add [hl]
    ld c, $44
    ld l, c
    rla
    jr jr_00a_634c

    ld d, e
    ld de, $9906
    and l
    and $8f
    and c
    inc de
    adc e
    ld a, [hl-]
    add d
    ld b, e
    and h
    add sp, $5e
    and [hl]
    dec c
    ld c, c
    jr z, jr_00a_6343

    add h
    jp nc, Jump_000_11ff

    add e
    add sp, -$01
    sub l
    ld sp, $4632
    pop de
    rrca
    rst $38
    ld a, [$5ea4]
    ld b, a
    sub b
    adc l
    rla
    sub c
    cp $4f
    rst $38
    call nc, $0b5b
    and $f8
    dec a

Jump_00a_6304:
    ld sp, hl
    ccf
    cp $aa
    ld d, [hl]
    sbc c
    add $1f
    add a
    cp c
    scf
    rst $38
    ld a, a
    ld b, h
    ld a, [hl]
    ld h, d
    sbc b
    cp a
    cp a
    call nz, $d95a
    rra
    and e
    cp $09
    ld c, c
    add d
    rst $30
    pop hl
    jr jr_00a_637a

    ld b, [hl]
    ld [de], a
    sub e
    adc $96
    sub c
    sub $08
    and $2d
    ld [bc], a
    cp a
    inc [hl]
    xor [hl]
    call c, $26a4
    jr z, jr_00a_63b1

    ld h, e
    jr nc, jr_00a_6371

    rst $38
    pop bc
    ld a, [hl]
    db $10
    ld a, e
    add hl, de
    ld hl, $92f1

jr_00a_6343:
    inc l
    or b
    and h
    ld c, a
    inc de
    ld b, [hl]
    ld c, b
    ld [hl], c
    cpl

jr_00a_634c:
    ld de, $ca50
    adc l
    ld a, a
    ld b, b
    sub e
    sbc c
    push bc
    ld sp, $0a3f
    ld a, $c6
    ld e, e
    add hl, hl
    call $85c3
    add l
    sbc b
    ld b, d
    ld sp, hl
    pop de
    ld [de], a
    sbc $83
    dec d
    dec bc
    jp hl


    jp c, $fadf

    adc [hl]
    add d
    pop af

Jump_00a_6370:
    rst $10

jr_00a_6371:
    ld [bc], a
    scf
    rst $38
    ld e, a
    or $11
    db $db
    ld [bc], a
    dec d

jr_00a_637a:
    adc h
    jr nc, jr_00a_6343

    add b
    ld b, h
    or c
    or h
    add l
    ld c, h
    sub h
    push de
    ld l, l
    ld a, [de]
    pop de
    cp a
    adc h
    inc hl
    dec b
    dec bc
    pop hl
    and [hl]
    sub b
    adc e
    xor b
    ld e, a
    push de
    inc hl
    adc c
    sub b
    sub d
    ld [$88f8], a
    rla
    ld [hl+], a
    ld h, h
    ld [hl+], a
    jr jr_00a_634c

    ld c, h
    sbc b
    sbc c
    daa

Jump_00a_63a5:
    ld [hl-], a
    ld d, b
    ld e, a
    jp nz, $330b

    bit 0, a
    add sp, -$57
    ld [hl-], a
    ld [hl], d

jr_00a_63b1:
    push de
    dec [hl]
    add l
    xor d
    ld h, b
    sub d
    sbc $35
    adc e
    add e
    ret


    and e
    ld h, h
    or l
    add c
    ld c, d
    cp a
    ld c, e
    ld e, c
    add hl, bc
    rra
    ld [hl+], a
    ld c, h
    sub h
    add a
    and c
    add d
    cp $a4
    sub $fe
    ld [hl+], a
    ld hl, sp-$3a
    ld c, a
    add l
    sbc c
    and h
    daa
    ld d, h
    ld l, e
    ld a, [bc]
    inc e
    ld d, h
    ld h, c
    ld c, $93
    and l
    ld l, c
    ld [hl], h
    ld b, h
    db $10
    ld c, a
    and h
    ld a, [hl]
    or b
    ld a, $53
    pop de
    ld d, d
    rra
    and e
    ld a, a
    rst $38
    jr jr_00a_6438

    cp d
    rla
    ld [$fa0f], a
    ld h, e
    ld c, e
    push de
    ld l, b
    ld d, h
    rrca
    rst $38
    pop af
    ld c, b
    or c
    add l
    and l
    ld d, a
    jp hl


    sub h
    ld h, l
    db $eb
    dec c
    or a
    push hl
    ld sp, $c5a7
    ld hl, sp+$66
    ld a, [de]
    sbc b
    cp $1a
    ld b, e
    daa
    dec de
    ld c, b
    ld hl, $417b
    and [hl]
    ld [hl], h
    xor l
    inc de
    sbc c
    ld e, c
    or h
    ld d, h
    ld a, h
    adc b
    ld h, [hl]
    or l
    ld e, d
    and l
    ld a, [hl-]
    ld e, l
    inc sp
    ld a, [hl]
    xor h
    sbc a
    add hl, sp
    sub h
    call Call_00a_52e2
    inc a
    rst $20
    ld e, [hl]

jr_00a_6438:
    adc e
    ld a, b
    and h
    add h
    ld h, h
    ret


    ld d, h
    rst $08
    jp nc, $5269

    dec h
    dec b
    ld h, $45
    ld l, e
    xor d
    db $f4
    adc d
    ld a, [bc]
    ld d, c
    ld a, a
    xor d
    ld a, b
    ld l, c
    sub b
    add $88

Call_00a_6454:
    ld b, c
    adc c
    or l
    add hl, bc
    or d
    inc d
    pop de
    add c
    dec h
    ret c

    ld h, [hl]
    jr nc, jr_00a_64a9

    ld b, l
    ld b, c
    ld b, c
    or [hl]
    and b
    ld a, [hl]
    xor b
    ld d, b
    db $dd
    ld h, h
    pop bc
    adc c
    ld d, d
    sub b
    cp b
    add l
    add a
    ld a, a
    ld b, c
    ld l, [hl]
    inc b
    or [hl]
    ld d, $1a
    ret z

    ld a, l
    ld c, c
    ld b, e
    rst $20
    call nc, $9457
    cp b
    adc b
    ld h, b
    xor [hl]
    ld [hl+], a
    rst $38
    ld d, l
    ld b, [hl]
    ld b, d
    ret c

    ld hl, $128d
    db $d3
    ld a, [bc]
    cp l
    ld [c], a
    ld hl, $3354
    sbc [hl]
    ld c, b
    ld d, a
    cp $85
    sub [hl]
    sub d
    ld a, [hl+]
    inc sp
    adc c
    ld c, d
    ld b, e
    db $fd
    cp $43
    ld h, c
    and d
    dec d
    dec h
    adc c

jr_00a_64a9:
    ld c, b
    ld c, h
    db $ed
    ld a, d
    pop bc
    db $f4
    daa
    pop hl
    ret


    ld c, d
    ld c, b
    add d
    ld l, $1b
    ld b, [hl]
    ld hl, $6260
    rst $18
    inc d
    add $30
    ld [hl], c
    xor d
    add sp, -$7b
    ld d, b
    sub l
    ld h, e
    ld [$1888], sp

jr_00a_64c9:
    add $04
    adc l
    ld e, d
    add l
    ld a, [de]
    ld c, c
    ld d, d
    ldh [$d8], a
    push de
    ld l, l
    adc h
    inc d
    sbc b
    adc c
    ret z

    ld c, [hl]
    jr z, @-$63

    add hl, bc
    ld h, [hl]
    rrca
    ld d, a
    and l
    ld hl, $9582
    ld e, c
    ld hl, $9248
    and a
    and b
    ld h, c
    sub h
    add hl, hl
    add l
    ld sp, $1857
    ld h, b
    ld c, h
    xor l
    add a
    inc b
    pop bc
    adc c
    ld a, d
    pop de
    ld b, [hl]
    ld a, [de]
    jr jr_00a_64c9

    ld d, c
    add d
    dec de
    add hl, de
    dec l
    dec b
    ld hl, $856f
    ld d, e
    ld c, d
    ld d, [hl]
    and c
    ld e, b
    sbc e
    push de
    ld l, b
    jp z, $ba09

    xor c
    sub $9b
    ld l, a
    rst $38
    pop de
    sub $99
    rst $08
    rst $38
    and a
    ld e, a
    ld a, [de]
    ld d, b
    ccf
    inc bc
    add $88

jr_00a_6525:
    and [hl]
    dec bc
    push bc
    push bc
    call nc, Call_00a_422c
    sub b
    add h
    ld e, e
    sub e
    ld a, d
    ld d, d
    ld b, l
    db $ec
    ld h, c
    ld l, h
    ld b, h
    ld d, e
    dec hl
    ld l, b
    and c
    ld a, c
    add hl, bc
    dec bc
    pop af
    jr z, jr_00a_658c

    ldh [$ce], a
    ld b, e
    rrca
    rst $38
    or [hl]
    add a
    ld b, b
    sub b
    or b
    ld e, d
    db $10
    ccf
    cp $08
    adc $93
    rst $38
    ld b, $33
    sub h
    xor d
    dec de
    db $10
    or l
    ld e, a
    ret nz

    cp $57
    ret nz

    cp $44
    ld e, l
    ld b, $11
    dec c
    ld l, b
    call nc, $97cd
    ld de, $99ff
    inc hl
    ld [de], a
    ld a, [$8733]
    add [hl]
    ld de, $ff97
    and [hl]
    sub b
    ld [hl+], a
    db $fc
    rrca
    ld c, e
    cp c
    sbc e
    rst $38
    ld sp, hl
    ld l, b
    jp nz, $c0ff

    ld hl, sp-$42
    inc e
    ld c, [hl]
    ld d, a
    rst $38
    ld hl, sp-$5c
    inc h

jr_00a_658c:
    ld b, h
    ld e, e
    cp $47
    sbc $4f
    sub e
    rst $38
    ld a, a
    inc bc
    sbc b
    jr nz, jr_00a_6525

    or [hl]
    rra
    ret c

    inc h
    ccf
    sub c
    cp $3f
    add l
    inc de
    inc l
    pop hl
    add e
    rst $08
    cp $1b
    dec bc
    cp $2f
    db $e3
    ld hl, sp+$45
    ld b, d
    ret nc

    ld b, c
    call nz, $ff57
    dec b
    ld a, a
    ldh [$fe], a
    ld b, l
    sub b
    add sp, -$60
    ret nc

    ld e, [hl]
    add d
    ld d, l
    ld a, [c]
    sub e
    ld a, e
    ld sp, hl
    ld c, [hl]
    rrca
    db $e4
    ret c

    cpl
    ldh [$99], a
    jp c, $7e45

    ld c, e
    ei
    ld sp, hl
    sub l
    ld b, c
    ld a, [c]
    ld b, e
    ld [$6d1c], a
    rst $38
    add [hl]
    sbc c
    or c
    ld e, $f8
    rst $10
    add hl, de
    jr z, jr_00a_6607

    ld [hl], $36
    ld l, l
    rst $30
    pop af
    sbc [hl]
    ld l, $36
    inc l
    ld [hl], c
    ld [hl], c
    rra
    ld [$a197], a
    ld l, b
    ld hl, $5d1d
    ld d, c
    adc h
    ld c, h
    ld l, h
    ld b, h
    or [hl]
    ld e, [hl]
    ld c, [hl]
    and a
    ld c, $19
    ld a, a
    xor c
    ld c, l
    ld d, $08
    adc d

jr_00a_6607:
    dec b
    ld d, h
    ld l, b
    inc hl
    rla
    and h
    db $10
    ld h, c
    and b
    ld c, c
    sub e
    ld h, [hl]
    ld c, $2a
    add d
    ld b, d
    sub b
    adc h
    ld l, [hl]
    inc d
    pop bc
    ld h, c
    ld c, b
    and e
    dec sp
    ld d, b
    ld c, d
    ld [c], a
    ld e, l
    call z, $d09f
    cp l
    rst $18
    dec b
    xor a
    db $e3
    ld a, [hl+]
    ret nc

    ret nc

    cp e
    add [hl]
    ret z

    adc l
    jr z, jr_00a_668f

    sub e
    and c
    sub l
    add c
    ld [hl], h
    ld [hl], e
    sub d
    ld d, d
    ld h, b
    cp h
    add [hl]
    ld d, l
    ld h, e

Jump_00a_6642:
    ld e, d
    sbc c
    inc hl
    ld h, e
    and [hl]
    pop af
    ld c, [hl]
    jp c, $3b8f

    ld [hl], b
    add hl, hl
    ret c

    add [hl]
    ld d, $92
    adc [hl]
    add hl, bc
    or d
    ret c

    ld d, l
    jr z, jr_00a_66c2

    dec c
    sbc d
    ld e, h
    inc l
    inc [hl]
    ld [de], a
    ld b, d
    sbc d
    ld [hl-], a
    ld c, h
    ld c, l
    inc c
    db $10
    ld c, h
    ld h, l
    dec a
    ld a, [bc]
    ld d, l
    ld a, [bc]
    ld c, h
    ld l, [hl]
    rst $00
    ld [bc], a
    ld h, [hl]
    add [hl]
    sbc b
    xor b
    call nz, $71a6
    ld [de], a
    ld d, d
    adc h
    ld [hl], b
    ld c, d
    jp $ac24


    ld de, $9a11
    ld b, d
    sub c
    ld l, $96
    sbc d
    push de
    call z, $b83e
    call nc, $d471
    xor h

jr_00a_668f:
    db $76
    ld c, d
    sbc a
    inc e
    ld h, [hl]
    cp c
    rst $18
    db $d3
    res 6, h
    ld l, c
    dec b
    ld d, h
    sub a
    db $f4
    call $30fd
    ld a, l
    add hl, de
    add c
    ld [$55af], a
    ld b, d
    db $d3
    dec bc
    ld b, [hl]
    sub d
    ld l, b
    adc b
    ld e, d
    dec h
    rrca
    ld c, $ba
    jr nc, jr_00a_6732

    add hl, de
    add [hl]
    ld b, [hl]
    jp hl


    add d
    cpl
    adc c
    cp l
    xor a

jr_00a_66be:
    adc b
    and d
    inc hl
    dec h

jr_00a_66c2:
    ld [hl], c
    ld h, d
    ld [c], a
    ld [hl], d
    inc a
    dec hl
    pop hl
    cp d
    ld h, d
    ld [hl], d
    ld a, [hl-]
    xor c
    rst $10
    sub c
    sub d
    rst $18
    inc sp
    sub e
    sub d
    pop bc
    add [hl]
    pop bc
    ld e, [hl]
    ld a, [c]
    add hl, hl
    add hl, hl
    sub h
    ld d, l
    ld h, b
    ld b, e
    pop bc
    dec bc
    ld a, b
    ld [hl+], a
    ld a, [hl+]
    rst $20
    ret z

    push af
    ld [hl+], a
    and d
    ld [hl+], a
    cp b
    sbc e
    rla
    ld [hl+], a
    rra
    ld h, [hl]
    inc c
    sbc d
    ld [hl+], a
    add c
    and l
    ld h, $27
    ld [hl+], a
    rrca
    ld h, $ff
    sub l
    adc c
    ld d, d
    ld [hl], e
    add hl, sp
    dec l
    add e
    jp z, $237d

    sub l
    ld d, [hl]
    dec d
    add hl, bc
    ld l, b
    xor e
    dec b
    ld c, $1b
    inc d
    ccf
    db $76
    add l

jr_00a_6713:
    ld [hl-], a
    ld d, h
    db $10
    ld d, h
    cp d
    ld hl, $09ed
    xor d
    push hl
    ld a, [bc]
    sub l
    ld c, d
    sbc b
    xor d
    ld c, h
    sbc h
    jr nz, jr_00a_676e

    ld a, c
    ld b, $82
    dec d
    adc b
    ld h, h
    and h
    adc c
    ld d, l
    and c
    add c
    adc l

jr_00a_6732:
    or e
    ld a, [bc]
    add d
    ld h, $21
    add hl, hl
    dec b
    and d
    db $ec
    jr nz, jr_00a_66be

    inc b
    ld l, l
    dec d
    ld e, b
    ld d, d
    ld d, b
    xor e
    ret nc

    ld d, h
    push bc
    ld [$1541], a
    adc c
    and b
    ld e, b
    jr nz, jr_00a_67b1

    jr jr_00a_6713

    dec h
    jp nz, Jump_00a_7c83

    sub $d5
    ld [c], a
    add hl, de
    add hl, hl
    ld [hl+], a
    ld d, $2e
    pop af
    ld a, l
    ld sp, $9aa8
    add d
    ld h, $2d
    daa
    inc hl
    ret z

    ld d, e
    add l
    ld d, [hl]

jr_00a_676b:
    inc d
    and h
    adc l

jr_00a_676e:
    dec h
    db $fd
    xor d
    adc [hl]
    ld a, [de]
    dec b
    add d
    dec b
    inc b
    sbc b
    inc a
    scf
    cp $05
    jr c, jr_00a_676b

    ld e, [hl]
    ld a, [de]
    push af
    ld d, a
    add sp, $15
    ld a, b
    ld [hl], a
    ld b, d
    sbc [hl]
    db $76
    jp nz, Jump_00a_428a

    ld d, d
    and $aa
    ld h, [hl]
    and l
    ld l, d
    add l
    ld b, b
    and b
    add d
    ld [de], a
    add hl, bc
    adc [hl]
    jp nz, Jump_000_0497

    jr z, @+$40

    ld d, d
    xor h
    ld [$3148], sp
    ld c, d
    ld d, h
    ld [de], a
    sub c
    ld b, e
    ld d, b
    jr z, jr_00a_680b

    call nz, Call_00a_43c8
    ld b, l
    ld b, c
    ld a, [bc]

jr_00a_67b1:
    ld [hl-], a
    jr nc, jr_00a_67d9

    ld [hl], c
    push bc
    ld [bc], a
    add [hl]
    ld b, l
    inc c
    ld [de], a
    call nz, $f421
    db $eb
    ld c, c
    add hl, bc
    ld l, c
    inc d
    ld h, a
    inc h
    cpl
    ld a, [bc]
    add [hl]
    ld h, c
    ld de, $c522

jr_00a_67cc:
    xor $61
    add l
    ld [hl], h
    ld c, d
    xor b
    ret


    ld de, $b230
    ld b, d
    ret nc

    inc h

jr_00a_67d9:
    db $e4
    call nc, Call_000_1343
    inc hl
    ld d, h
    ld c, [hl]
    ld [$28e8], sp
    ld b, e
    ld c, $30
    inc hl
    ld b, a
    dec c
    inc bc
    inc a
    adc d
    add h
    and d
    sbc h
    add hl, bc
    ld l, c
    adc e
    call z, Call_000_061f
    ld c, a
    ld c, $28
    ld b, [hl]
    ld [hl-], a
    xor h
    ld b, d
    add d
    dec bc
    db $ed
    inc e

jr_00a_6800:
    add hl, de
    ld a, [hl+]
    ld l, d
    jp $5503


    add hl, hl
    add hl, sp
    add hl, hl
    adc e
    ld d, a

jr_00a_680b:
    and [hl]
    ld c, c
    add hl, hl
    dec l
    ret z

    ld sp, $5908
    ld [hl], b
    xor b
    pop de
    adc e
    xor h
    ld e, [hl]
    jr @+$68

    adc h
    inc sp
    ld c, $44
    ld a, [bc]
    add l

Jump_00a_6821:
    jr nc, jr_00a_67cc

Call_00a_6823:
    inc sp
    cp e
    and h
    ld c, b
    ld h, e
    add hl, sp
    ld d, b
    and e
    dec bc
    ld d, $a1
    sbc c
    ld a, [hl-]
    dec c
    sbc b
    jr z, jr_00a_6800

    ld e, a
    ld d, a
    and l
    or l
    ld c, c
    ld de, $e6ac
    ld d, b
    xor b
    pop de
    ld sp, $0871
    ld b, c
    sbc h
    inc c
    inc sp
    ld c, $71
    daa
    inc l
    push hl
    ld b, d
    and h
    ret


    inc l
    ld [$72b6], sp
    xor b
    call z, Call_00a_550a
    ld d, d
    ret nz

    ret nz

    add [hl]
    ld [hl], d
    ld c, [hl]
    ld h, c
    ld b, b
    xor b
    ld d, c
    dec hl
    sub d
    ld b, h
    cp c
    sbc [hl]
    ld e, a
    ld a, [hl-]
    jr jr_00a_687b

    inc hl
    add l
    db $e4
    adc a
    adc $56
    rlca
    add hl, bc
    ld e, h
    sub l
    adc l
    cp [hl]
    ld c, c
    ld l, d
    sub c

jr_00a_6878:
    ld c, [hl]
    ld b, $e1

jr_00a_687b:
    ld h, d
    pop hl
    sub e
    ld d, l
    call c, Call_00a_6823
    rst $10
    jr c, jr_00a_6878

    ld c, d
    db $ec
    inc d
    pop bc
    dec h
    dec [hl]
    sbc h
    sbc c
    dec d
    add a
    ld h, e
    ld l, a
    ld c, e
    and d
    db $d3
    add d
    ld b, d
    ld b, $90
    ld d, e
    sbc [hl]
    ld [c], a
    ld l, [hl]
    inc b
    ld d, e
    xor [hl]
    ld d, [hl]
    call nc, $88eb
    and e
    push bc
    call c, $ace8
    ld [hl], l
    db $d3
    ld sp, $97c2
    xor b
    ld h, d
    rst $00
    inc c
    and l
    ld c, [hl]
    inc e
    ld [hl], b
    ld h, h
    ld h, d
    push de
    ld d, [hl]
    sbc h
    ld a, [hl]

Call_00a_68bb:
    ld a, [c]
    ld h, c
    ld h, [hl]
    adc $91
    ld d, h
    ld h, l
    ld h, $99

jr_00a_68c4:
    jr @-$2d

    pop de
    ld [hl], c
    ld a, [bc]
    ld l, b
    rst $00
    dec b
    call z, $e062
    sbc e
    ld h, c
    ld b, $62
    ldh [$82], a
    ld [hl], b
    xor h
    inc de
    ld [hl], a
    add h
    ld [hl], d
    ld b, l
    pop bc
    ld b, $c7
    ld l, a
    inc b
    sbc [hl]
    inc c
    ld a, b
    and b
    ld h, [hl]
    or e
    ld c, a
    dec l
    ld h, $d0
    ld [hl], h
    ret


    jp nc, $875c

    ld c, c
    ld c, e
    db $fd
    ret nc

    rst $38
    ld [$af5c], sp
    add c
    ld e, e
    inc hl
    ld a, [c]
    ld h, e
    ld [$1f2e], sp
    sbc a
    ld h, d
    dec d
    rst $20
    or b
    sub d
    dec sp
    ld hl, $4635
    ld a, [bc]
    inc b
    ccf
    rst $28
    ldh a, [rHDMA2]
    ld sp, hl
    adc b
    db $f4
    set 1, c
    ldh a, [$a5]
    ld l, b
    jp nc, $9196

    db $fc
    res 0, a
    ld d, b
    ld l, b
    add sp, $42
    db $e3
    ld h, h
    ld a, [de]
    and e
    and c
    ld [hl], $6a
    dec h
    push bc
    add hl, sp
    ld [hl], d

jr_00a_692d:
    ld d, e
    dec d
    ld [hl], d
    db $e4
    dec h
    jr nc, jr_00a_6988

    ld d, h
    rst $00
    call z, $cc55
    and e
    jr jr_00a_68c4

    ld de, $8761
    adc h
    xor b
    sub $2a
    ld a, [bc]
    jr @-$66

    reti


    ld [hl-], a

jr_00a_6948:
    ld h, c
    adc h
    sub b
    ld b, e
    add $89
    sub d
    rst $18
    ret z

    ld [hl], c
    or d
    and d
    and d
    cp c
    ld [$e3da], sp
    inc d
    db $10
    ld e, b
    add $85
    ld e, d
    dec h
    ld h, e
    ld c, h
    db $10
    add $18
    add [hl]
    ld [hl], b
    sub l
    cp c
    ld [$5098], sp
    ld c, h
    ld d, b
    xor c
    inc b
    jp $2d43


    ld b, l
    add [hl]
    inc hl
    di
    jr jr_00a_698d

    jr nc, jr_00a_692d

    ldh [$8d], a
    call nc, $8c8b
    ld [hl-], a
    cpl
    xor c
    ld c, l

jr_00a_6984:
    sub d
    ld e, $94
    pop hl

jr_00a_6988:
    ld [hl], h
    cp d
    ld b, d
    ld c, e
    db $76

jr_00a_698d:
    sbc e
    db $e3
    ld c, l
    ret z

    db $fc
    call $a876
    sbc a
    ret z

    ld c, h
    db $fc
    sbc h
    jr nz, jr_00a_6a10

    and h
    dec [hl]
    ld sp, $8ffc
    inc sp

jr_00a_69a2:
    adc c
    pop af
    add d
    add hl, hl
    ld a, [hl]
    jr nc, jr_00a_69a2

    add $38
    dec de
    inc sp
    cp b
    push de
    inc [hl]
    ret c

    or h
    sub b
    xor c
    ldh [$b5], a
    jr nz, jr_00a_6948

    or b
    and l

jr_00a_69ba:
    or l
    inc h
    inc [hl]
    dec c
    ld c, c
    ld a, [bc]
    ld c, d
    ld c, l
    ld h, l
    ld d, b
    pop de
    add hl, bc
    add hl, bc
    ld [de], a
    sbc c
    add hl, hl
    ld d, l
    add hl, hl
    ld l, b
    jr z, jr_00a_6a1f

    and c
    ld l, $d4
    adc h
    adc [hl]
    ld a, [hl+]
    sbc c
    jr c, jr_00a_6984

    jr jr_00a_69ba

    xor b
    ld d, l
    ld b, b
    xor $0d
    inc l
    ld de, $8411
    ld b, h
    ld d, e
    or c
    sbc l
    pop bc
    ld a, [c]
    ld a, [bc]
    add hl, bc
    and h
    or b
    ld d, b
    cp c
    sbc d
    add hl, bc
    ccf
    cp b
    and c
    add hl, de
    and h

jr_00a_69f6:
    db $d3
    ld b, c
    ld hl, $6145
    ld h, h
    ld b, c
    cp $a2
    sbc c
    ld b, d
    add e
    ldh [$97], a
    ld de, $5ffa
    ld sp, hl
    ld e, c
    sbc d
    rla
    db $e3
    jr nc, @-$2a

    dec a
    ret nz

jr_00a_6a10:
    and d
    rst $38
    db $e4
    ld b, [hl]
    sbc d
    ld sp, $5674
    inc l
    jr z, jr_00a_6a3c

jr_00a_6a1b:
    adc $8c
    and [hl]
    dec bc

jr_00a_6a1f:
    inc b
    sub d
    sub h
    and h
    and c
    ld b, e
    rrca
    cp [hl]
    ld h, h
    xor d
    sub c
    dec bc
    dec c
    add hl, de
    ld b, h
    ld a, b
    xor a
    ldh [$97], a

Call_00a_6a32:
    ld de, $a111
    dec d
    add d
    sub d
    sub c

Call_00a_6a39:
    rlca
    jr nz, @+$01

jr_00a_6a3c:
    and $08
    or d
    sub d
    add e
    ld d, e
    push bc
    ld hl, $ab40
    cp a
    pop bc
    jr @+$52

    xor b
    or b
    ld b, d
    pop af
    add hl, bc
    inc sp
    ld c, h
    dec de
    ld sp, hl
    dec c
    ld b, l
    inc [hl]
    sub e
    add hl, hl
    adc e
    sbc b
    cp a
    inc a
    ld l, d
    sub b
    jp $19e1


    jr nz, jr_00a_69f6

    rst $38
    ld a, [c]
    ld b, h
    or c
    ld [hl], c

Call_00a_6a68:
    scf
    ld de, $08ea
    rst $38
    db $e4
    ld d, a
    ld l, b
    dec h
    add hl, hl
    ld a, [bc]
    push bc
    and e
    inc c
    ld de, $681f
    ld e, a
    ld c, e
    push bc
    xor b
    ld d, c
    add hl, hl
    ld l, e
    inc l
    dec c

Jump_00a_6a82:
    add hl, hl
    inc [hl]
    ld h, b
    jp nc, $915a

    inc b
    inc [hl]
    adc h
    ld b, h
    dec [hl]
    ld b, h
    and l
    jr nz, jr_00a_6a1b

    ld h, e
    ld d, b
    jp $c40c


    dec h
    ld b, b
    and e
    jr z, @-$2e

    ld d, c
    cp d
    add hl, hl
    ld e, c
    ld [de], a
    or b
    xor c
    ld d, d
    add $60
    ld b, h
    cp b
    ld [de], a
    rst $18
    db $d3
    ld b, h
    ld [de], a
    ld [c], a
    ld d, h
    adc b
    inc hl
    dec sp
    ld a, [c]
    dec d
    rlca
    ld [$4d16], a
    ld h, d
    dec hl
    ld c, $31
    ld [hl], e
    add [hl]
    pop bc
    dec l
    ld [hl+], a
    call z, $13f2
    ld h, $f1
    ld [hl], e
    ld a, b
    ld l, b
    and h
    ld [hl], d

jr_00a_6aca:
    ld [hl+], a
    db $f4
    pop bc
    add e
    ld l, $86
    ld [hl-], a
    adc e
    xor e
    add c
    db $e4
    sbc b
    ld [c], a
    cp e
    ld l, a
    ld h, b
    ld e, b
    ldh [$dc], a
    ld l, b
    db $10
    xor d
    add hl, sp
    inc hl
    ld [$cce2], sp
    or d
    dec d
    dec sp
    sub [hl]
    ld b, $a5
    ld a, [hl-]
    ld a, [hl+]
    ld l, $8f
    rla
    ld l, a
    ld b, l
    or b
    ld c, c
    sbc e
    ld c, c
    ld d, h
    ld e, a
    rst $08
    sbc e
    ld c, c
    jr z, jr_00a_6aca

    ld b, $10
    ld h, $52
    jp z, Jump_00a_4b18

    sbc l
    xor l
    inc b
    ld [hl], c
    call nc, Call_00a_540a
    jp nz, Jump_000_159c

    ld [bc], a
    adc a
    dec d
    ld sp, hl
    sbc l
    ld c, c
    ld l, [hl]
    push hl
    call nz, Call_00a_6a39
    push bc
    inc a
    ld d, [hl]
    sub l
    ld h, [hl]
    adc d
    inc [hl]
    add h
    adc a
    jr @+$28

    ld d, b
    pop de
    db $10
    ld l, c
    adc e
    and $52
    or c
    add a
    inc sp
    cp a
    sub a
    ld b, [hl]
    inc [hl]
    ld b, e
    ld c, b
    jr nc, @+$5e

    ld e, l
    jr @-$2d

    inc d
    adc h
    ld e, $31
    call $6104
    ld e, $28
    ld d, l
    and c
    ld sp, hl
    dec sp
    ld e, l
    rla
    sub a
    ld [$50eb], sp
    and l
    add hl, bc
    ld b, l
    ld a, [hl-]
    xor b
    ld e, $50
    cp l
    ld a, a
    push af
    ld d, e
    add [hl]
    adc e
    cp a
    rst $38
    ld d, h
    add hl, hl
    ld a, d
    ld d, b
    ld e, a
    ld e, a
    push af
    adc l
    xor d
    push hl
    add hl, de
    ld e, l
    add [hl]
    adc b
    ld h, l
    cp b
    sbc $42
    scf
    ld b, d

jr_00a_6b6f:
    add hl, de
    adc l
    ld e, [hl]
    add sp, $1f
    db $d3
    inc b
    push hl
    cp a
    push bc
    ld l, h
    ld e, [hl]
    ld a, [hl+]
    add hl, sp
    ld a, h
    sbc c
    jp hl


    add sp, -$1b
    ld d, l
    ld c, l
    inc d
    xor b
    call $ffff
    call z, $671a
    and d
    inc de
    ld a, [hl+]
    ld a, a
    ld [$a9a2], a
    ret z

    and e
    ld [hl], l
    cp d
    ld c, b
    ld a, a
    add $f6
    dec l
    dec [hl]
    cp l
    ld h, d
    dec l
    ld a, h
    push de
    inc c
    add [hl]
    adc d
    ld d, l
    ld d, h
    ld e, [hl]
    ld d, $95
    dec d
    ld c, c
    ld d, l
    adc c
    ld a, d
    and h
    ld l, d
    dec d
    dec b
    ld l, e
    push de

jr_00a_6bb5:
    add d
    ld d, c
    ld b, c
    ld c, c
    sbc d
    or l
    ld l, d
    ld b, $33
    or h
    add h
    db $10
    ld d, b
    ld e, c
    jr nc, jr_00a_6b6f

jr_00a_6bc5:
    scf
    cp [hl]
    ld [$1b19], sp
    ld [hl], c
    ld c, [hl]
    ret


    ld b, d
    ld c, [hl]
    rst $20
    adc d
    rst $30
    sbc l
    xor a
    ld hl, $d130
    sub $f2
    jr nc, jr_00a_6bb5

    xor d
    cp d
    add hl, hl
    jp Jump_00a_7179


    ld d, a
    ld a, a
    ld a, [$aae4]
    ld c, $af
    jp z, Jump_00a_5f70

    rst $38
    rst $28
    rst $18
    rst $38
    jp $c371


    ld a, a
    ld b, e
    inc sp
    ld a, a
    sbc h
    xor c
    inc e
    ld [$cfa4], sp
    rst $20
    dec [hl]
    and h
    ld d, b
    jr z, jr_00a_6bc5

    rst $20
    ld a, [hl-]
    db $e4
    ret nz

    call nz, $e741
    ld [de], a
    ld d, a
    sub a
    and h
    ld hl, $449b
    ld e, l
    ld d, b
    ld a, c
    jr nc, jr_00a_6c47

    ld [$9ce9], sp
    jr nc, @-$39

    ld e, [hl]
    adc [hl]
    jr z, jr_00a_6c6e

    scf
    sbc c
    pop bc
    xor $53
    ld b, c
    and [hl]

jr_00a_6c25:
    ld c, l
    and $b0
    add $2f
    jp hl


    ld c, h
    ld a, [$1453]
    sub h
    sub b
    rst $38
    xor a
    ld e, a
    rst $38
    jp hl


    add hl, bc
    ld c, c
    scf
    ld l, e
    rst $38
    call nc, $4d44
    ei
    ld a, [$c294]
    sub e
    ld d, h
    ld l, a
    jr c, jr_00a_6c25

jr_00a_6c47:
    ld b, h
    ld e, $b9
    db $dd
    push bc
    ld [hl], l
    rst $00
    add b
    ld b, h
    ld a, $39
    ld d, d
    sbc a
    rst $10
    jr c, jr_00a_6c75

    ld sp, hl
    ld [hl], l
    call c, $8163
    ld e, [hl]
    rst $38
    ld a, [$7773]
    sbc l
    ld a, d
    sbc $08
    ldh [$a0], a
    ld b, [hl]
    ld a, a
    ldh a, [$4e]
    dec hl
    ld e, a
    rst $38

jr_00a_6c6e:
    ld [$8e53], a
    push af
    ld d, h
    adc a
    ld d, e

jr_00a_6c75:
    add l
    rst $28
    db $f4
    inc h
    ld l, a
    ld hl, $6035
    ld d, l
    ld [$b81a], sp
    dec e
    ld [hl], $b4
    adc b
    cpl
    inc hl
    ld b, d
    adc [hl]
    add hl, bc
    ld e, b
    adc d
    xor b
    ld a, [$f299]
    ld [$718a], a
    ld hl, $c310
    ld e, a
    sbc h
    ld c, e
    call nc, $452a
    dec de
    and [hl]
    ld l, d
    push de
    dec de
    db $f4
    ld h, c
    dec bc
    cp $75
    cp a
    ld sp, hl
    jp nz, $c098

    rst $38
    sbc e
    ld sp, $9434
    rst $38
    sbc e
    ld c, c
    add [hl]
    xor a
    db $fd
    inc e
    rla
    db $e4
    push de
    ld b, a
    pop hl
    jr nz, jr_00a_6d24

    cp h
    dec b
    ld d, e
    jp z, $aa7e

    ld c, a
    ld hl, $5b52
    ld c, a
    ld e, $62
    and e
    jp z, Jump_00a_63a5

    rst $00
    ld b, c
    db $76
    xor e
    ld a, a
    inc b
    db $ed
    ld a, a
    ret c

    add l
    or l
    ld b, c
    dec sp
    ld e, $78
    inc e
    ld l, h
    ld l, d
    or a
    ld d, e
    daa
    db $f4
    push bc
    ldh [$a2], a
    inc l
    ld h, l
    ld [hl], l
    ld b, d
    dec b
    adc d
    ld a, d
    ld a, [de]
    db $f4
    sub l
    ld e, l
    sub e
    ld b, h
    ld a, a
    and d
    sub h
    ld [hl+], a
    inc hl
    ld [$183a], sp
    pop de
    add sp, -$6a
    scf
    and c
    xor e
    push af
    ld [c], a
    ld de, $897a
    ld b, c
    dec l
    ld c, h
    inc d
    ld l, b
    xor c
    ld c, b
    pop af
    ld h, d
    ld d, a
    or e
    dec de
    ld c, e
    ld b, d
    adc h
    ld d, h
    adc b
    adc b
    ld a, [hl]
    add d
    inc [hl]
    or h
    adc c
    db $e3
    dec [hl]
    ld c, e
    xor d
    cp a

jr_00a_6d24:
    adc l
    rra
    adc $19
    sub h
    add [hl]
    ld [hl+], a
    call $851e
    ld d, l
    ld c, l
    ld l, c
    xor b
    and [hl]
    ld c, h
    ld e, [hl]
    ld h, $6a
    and b
    push af
    inc sp
    adc d
    and b
    sbc b
    and a
    adc e
    ld d, e
    ld a, [de]
    call nc, Call_000_25b6
    ld c, a
    ld b, $bd
    ld l, b
    ld d, [hl]
    adc b
    ld d, e
    dec b
    ld sp, $7aa3
    xor d
    ld h, $82
    xor b
    or l
    adc b
    add c
    ld d, e
    xor a
    ld d, h
    add $b5
    ld a, [$af3a]

jr_00a_6d5e:
    ld h, e
    ld e, d
    adc a
    ld [hl+], a
    ld a, b
    ld [$94a7], sp
    push bc
    ld c, c
    push hl
    inc h
    jp c, Jump_00a_4c9e

    xor a
    rst $00
    sub a
    push de
    ld c, c
    ld [c], a
    xor b
    pop hl
    ld e, a
    ld de, $dd29
    or e
    ld b, l
    inc h
    ld a, $76
    cp h
    add $59
    inc de
    ld [bc], a
    ld h, h
    xor $64
    sub c
    ld b, [hl]
    ld [hl], a
    add d
    cp a
    ld b, l
    jr nc, jr_00a_6d5e

    ld l, [hl]
    sub [hl]
    add h
    ld a, [de]
    ld h, a
    ldh [rIE], a
    jp hl


    add hl, hl
    ld [hl], a
    jp hl


jr_00a_6d99:
    ld de, $664e
    db $fc
    db $10
    ld d, c
    pop bc
    call nz, $0f43
    ld a, [de]
    ld e, c
    inc a
    ld h, c
    jr jr_00a_6d99

    add $09
    and e
    ldh [$ba], a
    ld [hl], b
    and e
    add hl, de
    ld e, c
    add e
    ld c, l
    ld c, $9c
    inc [hl]
    ld l, l
    inc h
    ccf
    ld [$6fae], a
    inc e
    sub l
    rst $38
    cp $12
    ld [hl], b
    xor l
    ld d, d
    and [hl]
    ld e, a
    xor l
    ld d, d
    ld a, [$c570]
    jp nc, $2b82

    rst $38
    ld a, [$452e]
    inc d
    sbc b
    jp hl


    sbc l
    rst $18
    rst $38
    cp $0f
    sbc h
    sbc d
    ld l, e
    ld c, a
    ld d, l
    ld hl, $080c
    and l
    ld b, [hl]
    rra
    rst $00
    ld c, l
    db $eb
    jr jr_00a_6e33

    cp l
    call c, $bf74
    add $97
    ld h, a
    ld [hl], h
    ld de, $00ec
    ld b, h
    cp l
    ld d, l
    ld d, a
    di
    sub l
    ld a, [hl]
    xor d
    add hl, sp
    sbc [hl]
    adc [hl]
    adc e
    ei
    ld a, [hl-]
    db $ed
    ld [$55ee], sp
    dec sp
    db $e4
    xor $68
    rst $28
    ld e, [hl]
    ld b, c
    db $f4
    add sp, -$50
    ld b, c
    db $d3
    xor l
    sub d
    dec [hl]
    ld a, [hl-]
    ld h, a
    add a
    cp a
    ld a, [hl-]
    ld h, l
    adc a
    adc c
    sbc [hl]
    xor d
    ld b, e
    cp c
    jp z, Jump_00a_6184

    ld h, a
    sbc l
    ld [de], a
    sbc l
    xor b
    ld h, a
    ld a, a

jr_00a_6e2d:
    ld b, a
    cp l
    ld e, $0c
    ld d, e
    ld c, c

jr_00a_6e33:
    add hl, hl
    call $2904
    ld c, $72
    ret nz

    ld sp, hl
    rrca
    rst $20
    ld d, [hl]
    adc h
    ld a, l
    jr c, jr_00a_6e97

    ld a, $cd
    inc a
    dec [hl]
    add e
    inc a
    ld c, b
    ld h, [hl]
    rst $08
    dec b
    add e
    adc $d4
    ld a, [de]
    and b
    ld b, l
    ld d, h

jr_00a_6e53:
    and $66
    ld [$07b9], sp
    ld [hl], h
    db $e4
    push hl
    rst $00
    inc d
    db $10
    add [hl]
    xor b
    db $e3
    ld [hl], b
    ld l, a
    di
    inc l
    inc h
    db $e4
    ld h, b

jr_00a_6e68:
    ld [hl], c
    add $50
    or b
    add a
    jr c, jr_00a_6e53

    ld l, a
    ld a, [c]
    jr nz, jr_00a_6ebb

    ld b, c
    adc [hl]
    ld c, h
    call Call_000_0585
    add hl, sp
    and $41
    ld e, d
    ld [hl+], a
    xor [hl]
    ld [hl], e
    and [hl]
    rra
    cp $1a
    and e
    jp nz, Jump_000_0841

    inc de
    call nz, $cf96
    ld c, $c1
    di
    call nz, $8f86
    scf
    ld a, [hl]
    ld l, $91
    sbc [hl]

jr_00a_6e97:
    dec de
    ld e, $3f
    add h
    db $76
    jr nz, jr_00a_6e68

    xor [hl]
    ld d, $75
    jr nc, jr_00a_6ee9

    dec de
    ld a, [hl+]
    ld [hl], e
    jr nz, jr_00a_6e2d

    ld c, b
    ld [hl-], a
    ld d, e
    inc e
    cp d
    ld [$1855], sp
    add sp, $27
    dec hl
    dec c
    ld c, b
    ld a, [hl-]
    ld b, [hl]
    ld b, [hl]
    ld [hl], d
    ld h, h
    push de

jr_00a_6ebb:
    inc c
    ld d, [hl]
    add h
    ld [hl], d
    ret


    or d
    ld [de], a
    ld [hl], h
    ld c, b
    ld h, $37
    pop af
    push de
    inc b
    push de
    ld [hl], b
    ld hl, $1c1e
    add d
    ld a, b

jr_00a_6ed0:
    ret nc

    ld b, d
    sbc [hl]
    ld h, $42
    ld a, h
    or b
    ld b, h
    cp c
    ld d, b
    ld c, [hl]
    call $d306
    xor d
    ld d, b
    sbc b
    db $e3
    ld d, l
    ld d, a
    cp h
    jr nc, jr_00a_6f34

    rst $18
    xor d

jr_00a_6ee9:
    xor c
    inc b
    jr nc, jr_00a_6ed0

    ld l, d
    inc sp
    add a
    rlca
    dec [hl]
    and e
    ld l, [hl]
    inc b
    inc sp
    or d
    jr c, jr_00a_6f21

    jp nc, Jump_00a_7c0c

    jp c, $14d4

    ld d, [hl]
    inc hl
    rst $00
    scf
    sbc l
    ld a, [bc]
    ret z

    or b
    ld [hl], h
    db $e4
    xor d
    add [hl]
    rlca
    ld [$45e9], sp

jr_00a_6f0f:
    inc c
    db $eb
    db $eb
    ld a, $2f
    ld [hl], h
    daa
    ld h, [hl]
    ld b, h
    ld [hl], l
    add sp, $27
    ld [hl-], a
    ld e, a
    add hl, hl
    ret z

    pop bc
    ld d, l

jr_00a_6f21:
    ld d, b
    ld sp, $e9c4
    sub h
    ld d, $70
    ld [hl], b
    add $7a
    add hl, bc
    or e
    inc l
    ld h, l
    sub c
    sbc e
    ld c, c
    or [hl]
    add h

jr_00a_6f34:
    ld [hl], b
    ld c, b
    add hl, hl
    ld [$e7a0], sp
    ld [hl+], a
    dec sp
    inc b
    add l
    ld h, a
    inc a
    ld e, h
    ld [hl], a
    ld h, c
    sbc a
    ld e, b
    ld [hl], a
    cp d
    sbc a
    db $f4
    db $f4
    rst $28
    ld b, d
    adc a
    ld h, d
    adc a
    dec [hl]
    ld d, l
    ld [hl], a
    pop de
    ld d, l
    ld d, e
    adc c
    scf
    ld e, d
    adc c
    ld e, a
    call c, $ea20
    cp l
    ld c, l
    db $d3
    ld b, [hl]
    ld b, $a8
    jr z, jr_00a_6f0f

    sub c
    sub l
    ld h, c
    sub h
    sub $a9
    ld c, b
    ld h, b
    ld h, c
    ld e, b
    dec d
    rlca
    ld b, l
    ld h, l
    jp hl


    ld l, $4c
    ld h, e
    ld [$4911], sp
    ld b, [hl]
    xor b
    ld l, $0a
    and c
    cp c
    adc d
    ld c, h
    push hl
    add hl, hl
    inc e
    sbc d
    ld [$f8ca], sp
    cp b
    xor b
    push de
    db $fc
    ld hl, $73e2
    dec [hl]
    ld d, l
    ld d, $25
    dec h
    ld hl, $5854
    xor b
    adc d
    ld e, b
    add a
    cp $99
    rst $00
    and d
    rst $28
    and b
    ld l, b
    ld [hl-], a
    dec d
    add hl, hl
    ld hl, $5531
    and b
    and e
    ld a, l
    ld a, [$9531]
    jp nc, $c178

    xor d
    adc [hl]
    ld b, $a2
    ld [de], a
    xor c
    ld c, d
    and c
    ld b, c
    add hl, de
    ld h, c
    ld h, e
    adc d
    ld d, l
    and d
    sub e
    ld a, b
    db $10
    sub l
    and e
    sub c
    ld e, d
    xor d
    xor b
    pop de

jr_00a_6fcb:
    ld h, c
    sbc h
    ld a, d
    xor h
    reti


    ld l, b
    pop hl
    ld c, b
    and d
    ld h, h
    add l
    adc b
    db $d3
    ld d, h
    pop bc
    ld l, [hl]
    adc c
    xor b
    inc d
    ld h, h
    xor d
    ld a, a
    ld d, [hl]
    add c
    ld [hl-], a
    ld c, d
    ld e, h
    adc b
    jp nz, $fefd

    inc b

jr_00a_6feb:
    jp z, $e0aa

    ld l, c
    ld b, a
    ld d, l
    ld a, [$af37]
    db $f4
    ld h, e
    ld a, $87
    ld a, [hl+]
    xor d
    or l
    ld e, b
    ld [c], a
    ld a, a
    add hl, de
    add hl, hl
    ld l, c
    ld c, b
    ld d, d
    ld d, [hl]
    and b
    ld d, l
    ld d, l
    ld e, b
    ret


    rst $20
    ld l, d
    or h
    adc d
    or l
    ld a, [hl+]
    xor c
    ld l, d
    adc [hl]
    ld b, l
    ld a, [bc]
    jr nc, jr_00a_6fcb

    ld e, b
    ld d, $95
    ld l, d
    dec sp
    jr z, jr_00a_6feb

    xor d
    adc a
    dec a
    ld e, b
    ld a, [c]
    sub $90
    ld l, d
    dec a
    dec b
    db $fc
    jp nz, $da3c

    ld [hl], d
    sbc b
    ld a, [c]
    daa
    pop hl
    rst $08
    sbc [hl]
    call nz, Call_000_2775
    ld a, [bc]
    cp a
    ld b, h
    or l
    rlca
    add sp, -$57
    jp nz, $bf9a

    inc bc
    sub d
    rst $38

Call_00a_7042:
    add sp, $5f
    ld d, a
    ld a, [$c109]
    ld [bc], a
    ld c, e
    ldh a, [$2f]
    add e
    call c, $d217
    and h
    rst $18
    adc h
    sbc c
    dec h
    jp nz, Jump_000_37fe

    add h
    dec hl
    cp d
    jr z, jr_00a_70db

    and h
    ld b, h
    ld h, $90
    inc hl

jr_00a_7062:
    jr nz, jr_00a_7062

    ccf
    sub b
    rst $38
    rst $38
    xor a
    rst $38
    jp hl


    add $93
    add a
    ld [$3fbe], a
    rst $38
    sub a
    rst $38
    ld hl, sp-$5e
    call nz, $3125
    add l
    ld a, a
    cp $82
    ld b, l
    ld a, d
    ld a, [hl+]
    cp $b1
    adc h
    ld sp, $4a2a
    add a
    rst $38
    rst $38
    add a
    dec bc
    add a
    db $f4
    ld b, d
    xor h
    ld h, e

jr_00a_7090:
    sbc d
    ld b, b
    pop hl
    ld a, l
    push af
    pop af
    ld d, d
    xor d
    rst $38
    ld b, h
    cpl
    ld [$11e6], a
    ld e, c
    ld e, $1e
    ld e, e
    ccf
    rst $38
    call c, Call_000_2f10
    rst $38
    ld d, h
    ld c, e
    jr jr_00a_7090

    ei
    ld l, l
    ld c, e
    rst $38
    rst $38
    ld [hl], b
    cp a
    pop de
    cp d
    ld e, [hl]
    add e
    rlca
    rst $38
    db $fd
    ld a, a
    call c, $4f10
    rst $00
    ld e, $97
    sub b
    or l
    db $f4
    dec [hl]
    or $10
    ccf
    ld b, [hl]
    xor c
    adc [hl]
    sbc b
    rst $38
    ld [$42b5], a
    xor e
    dec de
    add hl, hl
    xor l

jr_00a_70d4:
    ld l, d
    xor b
    ld e, a
    ld d, [hl]
    rst $38
    rst $38
    rst $38

jr_00a_70db:
    ld a, [$8360]
    rst $20
    ld a, $83
    rst $38

jr_00a_70e2:
    rst $38
    rst $38
    rst $38
    rst $38
    ei
    rst $38
    call nz, $cfa6
    ld b, c
    ld a, a
    rst $38
    rst $38
    rst $38
    rst $38

Call_00a_70f1:
    db $fd
    ld d, c
    sub h
    ld l, d
    add $17
    rst $38
    rst $38
    ld e, a
    push af
    dec e
    adc c
    and l
    ld d, l
    rra
    ld c, [hl]
    adc h
    ld a, c
    cp c
    sbc d
    ld a, c
    or l
    xor c
    ld c, c
    db $eb
    daa
    sub h
    ld b, h
    or e
    ld a, a
    call nc, $ff15
    ld d, e
    ld h, a
    sbc $7b
    ld a, [bc]
    ld h, $8d
    ld d, l
    ld a, [hl]
    add d
    dec b
    scf
    ld b, l
    ld b, c
    ld d, h
    ld d, b
    ld h, b
    ld e, a
    ld c, h
    jp c, Jump_00a_4125

    add c
    ld a, l

jr_00a_712a:
    sub [hl]
    adc h
    push hl
    ld e, b
    ld h, c
    sbc $d7
    ld c, [hl]
    rla
    jr nc, jr_00a_70e2

    rst $30
    adc l
    xor a
    jr jr_00a_70d4

    xor d
    adc [hl]
    ld a, [bc]
    ld a, [bc]
    add hl, bc
    ld hl, $4eb9
    ld c, d
    rrca
    ld b, [hl]
    ld h, h
    db $10
    ld h, e
    adc e
    ld l, b
    sbc d
    jr jr_00a_712a

    ld b, [hl]
    sbc e
    ld l, $38
    ld e, a
    ld sp, hl
    add hl, de
    ld b, l
    sub $8d
    xor [hl]
    and b
    ld l, l
    ld e, b
    and $aa
    ld [hl+], a
    adc a
    ld a, [hl-]
    ld l, [hl]
    sbc l
    or c
    ld [hl-], a
    jr z, @+$22

    sbc h
    xor l
    adc e
    inc sp
    or d
    ld [hl], c
    cp h
    ld b, e
    inc bc
    ld a, [hl]
    ld [hl], b
    or l
    inc c
    ret c

    jr c, jr_00a_71ef

    rst $08
    inc bc
    ld b, c

Jump_00a_7179:
    add a
    sbc e
    dec h
    ld h, [hl]
    inc de
    ld sp, hl
    ret nz

    db $e3
    db $e4
    ld a, a
    rst $38
    sbc h
    ld l, $ba
    dec hl
    ld e, a
    rst $20
    inc de
    rst $38
    and c
    ld l, l
    ld sp, hl
    call nz, $85de
    ld hl, $9c3f
    or h
    sub d
    db $dd
    inc e
    ld c, a
    add [hl]
    xor c
    rst $08
    ld d, h
    ld b, l
    rra
    inc e
    ld h, [hl]
    cp l
    rst $20
    call nc, Call_00a_7fc1
    ld d, e

Jump_00a_71a8:
    pop bc
    ld a, l
    rla
    jp hl


    ld e, c
    sub e
    or d
    ret nc

    xor d
    ldh [rBCPS], a
    adc d
    inc d
    add a
    sub c
    ld d, h
    db $e4
    xor d
    ld h, b
    ld l, d
    sub h
    adc c
    ld d, b
    pop bc
    xor d
    adc [hl]
    ld a, [bc]
    jr nc, jr_00a_7211

    ld [de], a
    and a
    ld b, $d5
    jr nc, jr_00a_7222

    db $fd
    ld c, c
    ld d, e
    ld c, b
    or [hl]
    ld b, $60
    ld a, l
    rlca
    xor c
    ld hl, sp+$51
    adc l
    sub d
    ld e, b
    jr @-$4a

    ld l, $25
    ld d, e
    ld c, l
    inc sp
    ld h, b
    ld h, c
    adc c
    sbc c
    inc hl
    ld hl, sp-$26
    db $f4
    db $10
    ld h, b
    ld h, b
    ld h, d
    ld hl, sp+$17

jr_00a_71ef:
    ld h, d
    or b
    ld h, c
    ld c, h
    and b
    cp h
    jr @+$1a

    xor [hl]
    sub l
    ld a, [bc]
    call nc, $a959
    inc d
    sub $d6
    ld sp, $5b82
    sub [hl]
    dec c
    sbc [hl]
    ldh [$4c], a
    push de
    ld h, l
    db $e4
    xor b
    ld [hl], l
    rlca
    jp nz, Jump_00a_4630

jr_00a_7211:
    ld d, c
    adc b
    ld h, c
    ld e, c
    ld e, a
    ld c, c
    ld c, e
    ld a, a
    adc c
    ld d, c
    cp [hl]
    ld a, h
    ld d, $5a
    ld e, d
    adc c

jr_00a_7221:
    adc b

jr_00a_7222:
    ld b, l
    pop hl
    and a
    sub h
    ld l, d
    add [hl]
    inc b
    ld de, $8c96
    ld d, h
    adc c
    db $e3
    add hl, de
    ld l, d
    ld hl, $a854
    pop bc
    ld e, e
    and h
    ld a, [de]
    ld [hl], $aa
    and l
    ld [hl], b
    adc h
    ccf
    push de
    add c
    dec b
    add hl, sp
    ld e, [hl]
    add e
    inc b
    pop de
    ld e, b
    ld h, h
    db $e4

jr_00a_7249:
    ld a, b
    ld d, $66
    ld d, l
    ld d, [hl]
    and d
    ld e, $8e
    dec h
    ld a, [$8881]
    or l
    ld d, d
    call nc, Call_00a_61e4
    adc b
    ld h, d
    ld e, e
    ld l, d
    dec b
    ld l, b
    push hl
    adc h
    ld [de], a
    ld [$8eaa], a
    and h

jr_00a_7267:
    add a
    inc b
    pop af
    scf
    add $2a
    ld a, c
    ld c, e
    ld b, h
    ld d, d
    ld a, b
    ld l, b
    ld sp, $a40a
    dec h

jr_00a_7277:
    and a
    ld e, h
    adc $c3
    ld e, [hl]
    xor c
    ld a, $29
    reti


    ld c, e
    inc de
    jr nc, jr_00a_7277

    adc a
    and [hl]
    xor d
    and [hl]
    ld [$7446], sp
    or e
    ccf
    add $77
    ld d, h
    sub l
    inc e
    add hl, hl
    rra
    dec d
    jr nz, jr_00a_7221

    add hl, bc
    inc e
    ld [hl], d
    or b
    and c
    inc b
    ld d, h

Jump_00a_729e:
    db $dd
    ld a, a
    rst $38
    jr jr_00a_7249

    ld c, h
    cpl
    adc d
    ld h, e
    dec h
    ld h, b
    ret nz

    jp hl


    ld e, c
    add e
    add e
    ld a, a
    ld de, $0a39
    jr z, jr_00a_7267

    xor l
    ld [bc], a
    and h
    ld a, c
    dec bc
    ld l, [hl]
    call c, $ce4f
    inc sp
    ret nc

    ld l, a
    ld [de], a
    push hl
    di
    push af
    inc a
    add a
    dec h
    ld [hl], c
    ld [hl], d
    ld h, c
    or b
    and l
    ld sp, $5248
    ld e, $aa
    add e
    inc d
    add sp, -$5c
    jp nz, $befc

    dec hl
    push af
    dec hl
    db $10
    and b
    or c
    ld d, b
    ld h, h
    ld d, d
    or l
    ld b, b
    or d
    db $fd
    add hl, de
    ld e, a
    ld c, h
    ld h, a
    ld c, d
    xor e
    ld e, e
    jr nc, jr_00a_7347

    add d
    xor [hl]
    add d
    rst $00
    ld c, d
    ld de, $3f19
    call nc, Call_000_3910
    call nc, $838c
    sbc d
    xor c
    call z, $30db
    ld c, [hl]

jr_00a_7302:
    ld de, $ac4a
    ld [hl], e
    or b
    call z, $ff5d
    rst $30
    sbc h
    db $ed
    ld a, [bc]
    add $3a
    xor l
    ld b, a
    ld b, h
    ld b, e
    rst $20
    sub h
    xor l
    and a
    adc d
    ld b, h
    or d
    ld a, l
    dec sp
    jr z, jr_00a_7349

    ld b, l
    ld b, c
    ld a, d
    and h
    sub $da
    ld a, [de]
    cp $97
    ld c, l
    sbc a
    ld l, l
    ld d, $88
    cp a
    inc [hl]
    ld a, b
    adc c
    add e
    dec l
    db $fc
    pop bc
    ld e, l
    call z, Call_000_07bd
    cp $30
    ld a, a
    bit 1, b
    ld b, e
    add d
    db $e3
    dec hl
    xor c
    ld hl, $8e8a
    dec bc

jr_00a_7347:
    sbc h
    ld a, [hl+]

jr_00a_7349:
    ld sp, $1ea8
    ld c, h
    ld e, l
    ld d, e
    ld a, [hl-]
    ld sp, hl
    add hl, bc
    ld [hl-], a
    and c
    sub b
    ld c, c
    ld b, [hl]
    db $ed
    jr c, jr_00a_7302

    jr nc, jr_00a_73bc

    or h
    inc l
    inc de
    add [hl]
    ld a, [$f52a]
    add hl, bc
    dec sp
    dec hl
    push af
    ld a, $17
    ld a, c
    ld [hl], h
    add hl, bc
    adc h
    xor h
    ld [hl], b
    ld e, h
    ld [$293e], sp
    ld d, c
    xor [hl]
    ld a, [hl-]
    inc a
    cpl
    sbc h
    or b
    ld e, [hl]
    ld b, a
    ld sp, hl
    and d
    ld b, d
    xor h
    ld d, [hl]
    and c
    add $b0
    ld h, c
    sbc c
    inc hl
    ld a, c
    cp e
    and [hl]
    ld [hl], b
    ld a, [hl+]
    ld a, [hl+]
    ld h, a
    ld [hl-], a
    ld h, l
    ld d, a
    or $16
    sbc b
    or b
    ld h, $35
    ld a, h
    ret z

    add $b5
    ld a, [hl+]
    pop bc
    and c
    call nz, $4547
    ld [hl], $77
    jr nc, jr_00a_73cc

    ld a, h
    dec c
    ld d, c
    ldh a, [$a0]
    ld d, l
    cp [hl]
    add c
    add hl, hl
    ld d, l
    ld c, [hl]
    ld b, l
    add hl, hl
    push hl
    xor b
    sbc a

Call_00a_73b5:
    ld c, [hl]
    rla
    xor b
    adc b
    add hl, hl
    ld d, e
    ld a, [hl+]

jr_00a_73bc:
    ld d, l
    ld b, c
    db $f4
    and h
    ld a, [hl+]
    ld [$df1b], sp
    ld [hl], $e5
    jr nc, jr_00a_7349

    ld [hl+], a
    ld [$e33f], sp

jr_00a_73cc:
    ld d, $49
    add c
    ld sp, $c990
    ld a, a
    ret z

    ld d, d
    ld hl, $e4b2
    or h
    dec hl
    ld b, d
    cp $16
    add d
    ld b, c
    rrca
    ld c, l
    sbc $1b
    ret c

    jp nz, $a091

    adc h
    ld d, e
    inc c
    xor h
    push bc
    ld h, c
    ld l, l
    jr nc, @+$4d

    ld h, h
    add a
    sub l
    add hl, de
    ld b, c
    add d
    rrca
    adc e
    ld h, d
    ret c

    ld e, [hl]
    ld h, b
    ld a, l
    ld a, [de]
    ld hl, $3017
    and e
    dec bc
    adc b
    ld a, a
    db $fc
    jp nz, $86a3

    ld b, c
    ld d, $ff
    adc [hl]
    inc [hl]
    sub $1a
    ld [$51e2], sp
    adc e
    sub d
    ld d, e
    sbc e
    ld b, $58
    and l

jr_00a_741a:
    ld a, [bc]
    inc d
    inc [hl]
    push de
    ld h, l
    ld a, b
    adc $f8
    adc c
    cp l
    ld d, d
    cp a
    ld a, [hl-]
    ld [$a522], a
    ld h, e
    ld e, c
    db $f4
    add hl, bc
    ld a, [hl+]
    ld c, d
    sbc h
    adc c
    add d
    pop de
    ld d, h
    ld a, [bc]
    ld [hl], b
    ld [hl+], a
    sub b
    adc h
    ld [$7426], sp
    ld b, d
    sbc c
    ld h, c
    inc b
    ret nz

    call nz, Call_00a_6a32
    and h
    ld h, $19
    db $10
    ld h, l
    ld [hl], $53
    add h
    sub l
    ld sp, hl
    adc h
    sub b
    sub b
    call z, Call_000_3c0a
    add hl, hl
    ld [hl], a
    sub a
    ld a, [bc]
    ld c, h
    db $ec
    dec c
    or e
    ld l, b
    push bc
    ld a, $5c
    add hl, bc
    ld [hl-], a
    sub a
    sub l
    ld d, c
    add a
    jr jr_00a_741a

    ld a, [hl+]
    ld c, a
    ld [c], a
    add e
    sbc h
    ld c, h
    add hl, bc
    db $10
    jr nz, @-$71

    rst $28
    jr nc, @+$2e

    ld e, d
    ld h, b
    sub [hl]
    call nz, Call_00a_43a3
    ld a, [hl]
    push hl
    inc [hl]
    ld h, l
    sub b
    sub b
    call z, Call_00a_5197
    push bc
    add h
    add h
    or e
    ld [hl], $70
    ld a, [hl]
    ld l, c
    ld de, $c64e
    adc $3e
    ld h, c
    add d
    add hl, sp
    call $1883
    jp Jump_000_3411


    sbc c
    xor l
    ld b, a
    inc c
    ld d, h
    call c, $450a
    inc b
    ld a, b
    ld [hl], h
    inc d
    ld l, d
    ld b, h
    cp b
    sub h
    ld d, l
    ld d, h
    ldh [$74], a
    ld e, e
    add sp, -$61
    ld c, [hl]
    jr c, @-$11

    ld b, d
    dec sp
    ld h, e
    cp a
    or e
    cp [hl]
    ld c, [hl]
    or $3b
    call c, $93ef
    cp d
    and [hl]
    dec sp
    dec l
    add hl, de
    db $e4
    and l
    ld c, [hl]
    ld l, b
    ld l, c
    ld e, h
    ld h, e
    jp hl


    ld h, a
    ld a, [de]
    ld a, [bc]
    ld c, d
    ld [hl], b
    ld b, c
    dec bc
    ld [hl], h
    ld c, l
    ld [bc], a
    ld [hl], c
    rst $00
    ld h, l
    add h
    ld a, [hl+]
    ld [hl], l
    ld [hl+], a
    pop af
    push de
    inc hl
    ld e, $ea
    ld [hl], a
    jp z, Jump_00a_4277

    sbc l
    adc b
    ld a, [c]
    add hl, bc
    rst $10
    dec c
    ld a, [hl]
    sub b
    and c
    daa
    ld c, l
    dec c
    rra
    ld c, [hl]
    ld [hl], a
    cp h
    rst $10
    ld c, a
    dec c
    rst $38
    ld d, e
    xor c
    rst $38
    db $d3
    dec b
    ei
    ld l, h
    ld [hl+], a
    add hl, sp
    adc h
    call nc, $ffd6
    ld l, b
    sub a
    and c
    or l
    jr nc, jr_00a_7555

    inc [hl]
    ld c, [hl]
    dec d
    cp l
    or l
    dec l
    ld c, d
    add sp, -$33
    ld b, [hl]
    jr c, jr_00a_7588

    ld a, a
    set 0, [hl]
    inc d
    jr jr_00a_7574

    dec b
    inc b
    push hl
    and c
    ld hl, sp-$69
    ld [hl+], a
    ld l, h
    ld e, b
    pop bc
    ld b, c
    inc b
    ld [c], a
    ld e, a
    ld b, $95
    dec d
    sbc h
    ld e, b
    jr nz, jr_00a_758b

    ld b, l
    ld b, c
    add hl, sp
    and b
    and a
    db $ec
    sbc e
    ret


    ld b, e
    db $e4
    ld a, $50
    ld c, l
    db $e4
    xor e
    ld b, d
    add d
    add d
    add hl, hl
    ld [hl+], a
    and d
    ld de, $88f5
    adc l
    rra
    sub d
    and c
    adc b
    sub l
    ld h, c

jr_00a_7555:
    ld h, b
    ld d, b
    ld h, c
    or $90
    ld b, d
    ld d, l
    ld c, h
    dec d
    dec bc
    and b
    and h
    pop bc
    ld b, c
    ld a, a
    db $dd
    ld e, d
    add d
    ld a, [hl+]
    dec h
    sub d
    push de
    ld sp, $4e49
    ret z

    ld l, h
    dec h
    dec h
    ld e, c
    dec d

jr_00a_7574:
    jr jr_00a_75d6

    or h

jr_00a_7577:
    add h
    ld d, c
    ld d, l
    ld b, [hl]
    ld hl, $cb0c
    adc d
    ld e, l
    add hl, bc
    ld d, [hl]
    ld h, l
    ld a, [bc]
    ret nc

    ld d, b
    ld sp, hl
    rrca

jr_00a_7588:
    sub b
    ld h, b
    ld d, a

jr_00a_758b:
    adc e
    jp nc, $f6ab

    ld a, [de]
    reti


    add hl, bc
    ld b, d
    and b
    adc c
    jp Jump_000_15d2


    ld c, h
    dec [hl]
    ld c, [hl]
    dec de
    ld h, l
    ld a, [bc]
    ld d, b
    ld c, d
    or $22
    sbc b
    adc d
    ld b, [hl]
    ld c, d
    ld a, a
    push de
    ld d, l
    or $ae
    ld d, d
    dec h
    adc b
    adc c
    ld l, b
    sbc c
    ld c, l
    ld l, $ff
    cp $a2
    cpl
    ld a, c
    dec l
    xor d
    ld a, l
    ld c, l
    ld [$270a], a
    jp nc, $151a

    ld a, e
    ld c, b
    adc h
    ld hl, $25a5
    dec h
    ld d, d
    jr z, jr_00a_7577

    ld c, h
    ldh [$a3], a
    ld b, h
    xor h
    ld d, d
    ld d, l
    ld a, [hl+]
    adc b
    xor e

jr_00a_75d6:
    inc [hl]
    sbc b
    sub $96
    inc d
    sub l
    ld c, b
    ld d, l
    ld h, b
    adc c
    adc d
    ld d, d
    xor b
    inc hl
    inc b
    pop bc
    dec l
    ld e, d
    ld h, $ce
    ld l, b
    inc h
    pop de
    adc e
    ld h, e
    jr c, @-$29

    ld c, h
    ld hl, $8895
    ld l, b
    ldh a, [$d9]
    dec h
    adc h
    ld d, $3c
    ld a, c
    xor d
    jr nc, jr_00a_7663

    call z, $21a5
    ld l, b
    pop hl
    sbc $6a
    add hl, bc
    pop hl
    ld l, $30
    ld h, $b0
    ld b, [hl]
    sbc c
    add hl, de
    sbc d
    ld b, d
    ld b, h
    jr c, jr_00a_7656

    sbc c
    and [hl]
    ld hl, sp-$18
    ld h, [hl]
    inc [hl]
    db $dd
    inc b
    or b
    ld hl, $5066
    ld c, c
    pop bc
    ld c, $52
    ld de, $6cac
    pop de
    add $91
    db $fc
    ld b, d
    sbc c
    ld a, $60
    add d
    ld [hl], e
    ld b, e
    ld a, c
    jr nc, @+$7f

    inc h
    ld [hl], b
    ld b, [hl]
    inc c
    add e
    sbc h
    ld c, b

jr_00a_763d:
    ld h, e
    ld a, [hl+]
    sub c
    add l
    ld [bc], a
    ld l, $60
    xor h
    sbc h
    ret nc

    jr nz, jr_00a_763d

    ld hl, sp+$4b
    ld [hl], b
    jp c, Jump_000_3815

    ld c, h
    adc d
    sbc h
    or b
    ld b, b
    cp h
    ld b, e

jr_00a_7656:
    ld h, d
    and $58
    ld a, [hl-]
    and c
    dec e
    scf
    sub e
    ld b, b
    call c, $4744
    add e

jr_00a_7663:
    ld [hl], l
    add hl, hl
    add hl, hl
    add [hl]
    ld a, [hl-]
    add e
    ld a, [bc]
    ld h, e
    ld a, [c]
    adc e
    db $dd
    ld de, $cf45
    ld [bc], a
    ld h, c
    adc d
    sub l
    inc b
    ld c, d
    db $10
    ld d, c
    rst $08
    ld l, b
    ld c, b
    inc h
    db $e4
    inc l
    ldh [$84], a
    ld b, a
    ldh [$a5], a
    and d
    add d
    add h
    ld b, e
    dec h
    rst $38
    sub d
    adc [hl]
    add a
    add d
    inc c
    add l
    xor $0f
    ld hl, $84d3
    sub c
    ld b, c
    inc b
    or h
    call z, Call_000_3554
    call nz, $c8c0
    ld d, b
    jp nc, Jump_00a_4646

    ld a, [bc]
    dec bc
    cp [hl]
    ld b, h
    dec l
    rst $20
    dec d
    or d
    sub e
    inc bc
    rrca
    add e
    ccf
    ld [hl-], a
    scf
    call $9196
    sbc b
    ld c, e
    jr z, jr_00a_7709

    ld hl, $1369
    ld [$900f], a
    pop de
    sbc h
    add hl, hl
    add [hl]
    call c, Call_00a_40c4
    call z, $fd53
    add l
    inc hl
    inc l
    ld h, c
    and c
    inc b
    dec d
    ld d, e
    call z, $c04a
    add h
    cp b
    ld b, d
    cp c
    ld d, h
    and h
    ld h, h
    and b
    and h
    ld sp, $e50b
    call nz, $8ca0
    inc c
    ld l, e
    ld b, $4b
    ld h, l
    or e
    sub c
    add hl, de
    pop bc
    ld l, e
    ld b, [hl]
    jp hl


    ld c, l
    add [hl]
    dec d
    inc l
    ld de, $829e
    ld [de], a
    ld a, [bc]
    sbc e
    and l
    reti


    ld de, $c251
    adc h
    ld a, [de]
    sbc c
    xor h
    ld a, b
    ld a, [hl-]
    ld [hl-], a
    jp Jump_00a_4a6a


    rst $00

jr_00a_7709:
    adc e
    and [hl]
    ld d, l
    push af
    sbc [hl]
    ld c, h
    add hl, bc
    add d
    ld de, $c1e6
    ld b, b
    add h
    add h
    ld [hl], b
    add b
    ld b, h
    sbc e
    ld c, d
    ld h, e

jr_00a_771d:
    ld h, [hl]
    adc e
    cp a
    xor d
    ld b, c
    ld b, c
    jr nc, jr_00a_778c

    call z, Call_00a_436f
    add c
    ldh [$a5], a
    ld e, c
    ld a, [$5233]
    ld h, d
    dec d
    rla
    db $e3
    ld a, d
    xor d
    pop bc
    rst $38
    cp $8d
    dec d
    dec h
    sbc a
    ei
    pop hl
    ld c, l
    daa
    cp l
    ld c, $de
    dec h
    adc [hl]
    ld b, $ff
    cp $21
    adc c
    ld h, e
    ld l, c
    inc hl
    ld a, [hl+]
    xor [hl]
    adc l
    ld a, [hl+]
    dec de
    ld b, c
    xor c
    ld c, b
    or l
    ld c, h
    ld d, [hl]
    dec b
    jr jr_00a_771d

    ld c, b
    ld c, h
    sub a
    and a
    ld a, c
    ld sp, $8c88
    ld h, l
    ld a, a
    db $ed
    inc b
    add hl, hl
    inc d
    rst $10
    db $fd
    ld c, c
    or a
    and [hl]
    adc b
    ld h, e
    ld a, [hl+]
    and e
    ld e, d
    xor b
    ld a, [c]
    inc h
    daa
    ld a, [hl-]
    sbc c
    jr nz, @-$52

    sbc d
    or d
    sbc d
    db $d3
    ldh [$aa], a
    adc d
    inc de
    ld sp, hl
    and a
    ld [de], a
    add d
    ld c, d
    rrca
    cp $71
    and h

jr_00a_778c:
    xor a
    rst $18
    rst $20
    dec bc
    ccf
    push de
    inc bc
    cp $6a
    add sp, -$2a
    or d
    rrca
    rst $38
    sbc d
    jr nz, @-$71

    ld d, d
    rst $08
    rst $38
    ld sp, hl
    and [hl]
    pop hl
    ld a, e
    ld b, [hl]
    rla
    and $78
    ld a, [hl]
    or e

jr_00a_77aa:
    rst $38
    and h
    add $d1
    inc d
    rra
    rst $38
    ld [$b671], a
    rst $38
    rst $38
    rst $38
    add $48
    dec h
    rst $18
    ld d, a
    rst $38
    jp hl


    sub [hl]
    inc l
    ld d, h
    ld de, $711d
    pop af
    nop
    ld d, l
    or [hl]
    ld d, h
    sub h
    rst $28
    ld a, e
    ld c, b

jr_00a_77cd:
    db $fd
    add hl, sp
    ld e, d
    push af
    rst $20
    sub d
    ld l, a
    jp nc, $c5d4

    jp $a70a


    add d
    push af
    ld d, a
    rst $28
    ld d, a
    call z, Call_000_2554
    xor [hl]
    ld d, c
    sub h
    jr nc, jr_00a_77aa

    ld d, [hl]
    inc c
    ld d, $30
    ld d, d
    ld d, c
    adc e
    xor e
    db $f4
    sub [hl]
    and e
    dec [hl]
    ld a, [bc]
    ld [$9150], sp
    ld l, e
    ld c, $22
    jr c, jr_00a_782b

    dec e
    db $e4
    ld l, e

jr_00a_77ff:
    xor c
    ld d, d
    inc de
    adc d
    xor d
    ld [hl+], a
    inc sp
    adc b
    adc $99
    xor l
    ld c, c
    call z, Call_000_05de
    dec [hl]
    ld h, a
    or h
    add a
    add $94
    ld l, d
    xor b
    pop bc
    xor a
    ld d, [hl]
    ld a, l
    ld b, c
    ld a, [c]
    inc d
    ld h, h
    adc d
    and d
    ld e, h
    jr nc, jr_00a_77cd

    ld a, [hl]
    ld [hl+], a
    ld c, $14
    ld l, c
    dec d
    db $ec
    sub l

jr_00a_782b:
    add hl, bc
    ld l, e
    sbc b
    pop bc
    add d
    ld l, $15
    cp b
    add l
    dec h
    jr jr_00a_7891

    sbc d
    ld hl, sp-$3a
    ld d, $62
    ld d, h
    jr z, jr_00a_7860

    ld d, e
    sbc [hl]
    jr nc, jr_00a_77ff

    ld [hl], a
    adc [hl]
    ld e, b
    ld h, e
    ld a, [hl+]
    xor b
    add sp, -$6c
    ld sp, hl
    add hl, sp
    db $eb
    ld h, $09
    adc $aa
    ld b, e
    add hl, de
    ld c, c
    adc d
    ld h, h

jr_00a_7857:
    db $e3
    adc e
    db $10
    adc d
    ld c, d
    ld e, $90
    add d
    ld h, a

jr_00a_7860:
    rst $38
    or d
    ld d, a
    ld d, l
    ld d, a
    db $fd
    ld h, [hl]
    sbc a
    rst $18
    ld sp, hl
    sub d
    rrca
    ret


    pop bc
    ld a, b
    rst $38
    jr @+$25

    pop de
    bit 2, l
    rla
    ld l, b
    xor a

jr_00a_7878:
    xor c
    jp c, Jump_000_0383

    rst $38
    pop af

Jump_00a_787e:
    rst $10
    db $fc
    rla
    rst $38
    rst $20
    ld h, l
    ld [bc], a
    rrca
    rst $38
    db $e3
    ld [bc], a
    ld h, b
    sbc b
    xor d
    sub b
    rst $08
    ld a, a
    rst $38
    ld a, [bc]

jr_00a_7891:
    db $10
    ld [c], a
    sbc b
    jr c, jr_00a_7878

    pop bc
    jp nz, $f1ff

    adc a
    and $5f
    ei
    jr nc, jr_00a_7857

    ld e, h
    ld h, h
    add h
    ld sp, hl

Call_00a_78a4:
    ld a, a
    rst $18
    ld sp, hl
    call z, $85f1
    db $e3
    db $fc
    ld [hl], e
    ld h, [hl]
    sub l
    ld d, c
    db $d3
    sbc a
    ld a, b
    ld b, h
    ld a, [hl-]
    ld d, [hl]
    adc [hl]
    or [hl]
    ld c, [hl]
    ret c

    inc h
    pop hl
    ld d, l
    ld c, c
    ld d, a
    inc b
    add h
    pop de
    adc d
    sbc d
    ld sp, $234d
    ld [hl], $a9
    ld b, $34
    xor b
    ret


    ld c, b
    ld b, d
    ld c, l
    ld a, [hl+]
    dec b
    ld sp, $5998
    ld c, h
    rst $20
    db $e3
    ld b, [hl]
    ld a, [de]
    dec [hl]
    or b
    and e
    cp d
    and b
    ld d, d
    and e
    sbc d
    ld a, [hl]
    adc b
    ld h, h
    rst $20
    or a
    ld l, e
    reti


    dec sp
    ld l, a
    db $e3
    cp d
    and e
    rst $00
    db $dd
    ld l, d
    db $76
    inc a
    db $76
    jp nc, Jump_00a_4977

    jp nz, Jump_00a_49d5

    db $d3

Call_00a_78fb:
    jr jr_00a_7943

    add hl, bc
    pop bc
    ld d, $a6
    ld [hl-], a
    ld l, l
    db $10
    db $fd
    ld d, h
    sub l
    xor c
    and h
    jp nc, $9c62

    db $f4
    ld a, b
    ld de, $7484
    ld c, l
    ld a, [bc]
    add d
    ld [hl], l
    pop de

jr_00a_7916:
    ld d, $9e
    inc b
    ld a, h
    ld c, b
    ld d, l
    cp [hl]
    sbc l
    ld d, l
    ld d, e
    cp c
    ld l, b

jr_00a_7922:
    jp nz, Jump_000_1f92

    sub e
    add c
    and d
    ld d, [hl]
    xor c
    ld b, [hl]
    ld b, l
    adc [hl]
    rlca
    add hl, hl
    add c
    rst $38
    reti


    jr jr_00a_7916

    sbc d
    ld [hl+], a
    rlca
    add c
    ld d, b
    or [hl]
    add hl, hl
    adc l
    jr nz, jr_00a_7922

    sub l

jr_00a_793f:
    rlca
    xor e
    ld b, c
    ld h, c

jr_00a_7943:
    ld h, e
    add d
    add c
    reti


    ld a, [bc]
    ld a, l
    ld a, [bc]
    ld a, [hl-]
    sub b
    adc d
    ld d, e
    or e
    sub d
    jr jr_00a_797f

jr_00a_7952:
    call nc, $e398
    add e
    adc d
    or h
    ld a, [hl+]
    ld a, [de]
    inc d
    ld h, h
    sbc $78
    adc c
    dec bc
    ld d, l
    ldh [$62], a
    and h
    sbc $4a
    sub [hl]
    xor c
    ld h, e
    xor d
    sub h
    sbc d
    and d
    ret nc

    sub e
    adc l
    ld d, [hl]
    sub l
    ld d, h
    ld d, d
    ld l, a
    ld h, e
    ld h, a
    ld [$ffbf], a
    dec bc
    add l
    jr c, jr_00a_7952

    or l

jr_00a_797f:
    ld d, [hl]
    xor c
    ld [hl], h
    db $e4
    ld d, c

jr_00a_7984:
    rst $38
    ld d, l
    ld d, b
    rst $38
    adc [hl]
    ld l, e
    push de
    ld d, a
    cp $a3
    ld c, c
    db $f4
    jp z, $9d52

    adc e

jr_00a_7994:
    ld b, [hl]
    ld d, d
    ld b, e
    ld [hl-], a
    ld [hl], b
    ld sp, $432b
    ld c, d
    ld [de], a
    ld sp, $c9c2
    inc c
    ld b, h
    ld b, h
    ld [hl-], a
    ld de, $a329
    inc d
    push bc
    jr nz, jr_00a_793f

    inc h
    ld sp, $2cac
    jr nc, @-$38

    ld d, e
    inc c
    ld [hl], e
    ld hl, $0c04
    ld [$54c7], sp
    call nz, Call_00a_4926
    add $8c
    adc d
    ld de, $3008
    and a
    inc l
    sub l
    ld h, $51
    jr jr_00a_7994

    pop bc
    ld sp, $4212
    add hl, hl
    inc c
    ld d, h
    sbc h
    ld [de], a
    ld c, l
    jr z, jr_00a_7984

    dec e
    ld [hl], h
    and [hl]
    db $ec
    add d
    ld [hl], b
    and d
    add l
    jr @-$4d

    db $10
    ld b, [hl]
    db $ec
    ld d, h
    ld d, l
    inc l
    pop de
    add $96
    and h
    ld d, b
    xor h
    ld de, $8cca
    ld h, l
    ret z

    ld b, a
    ld b, h
    add hl, bc
    inc l
    ld sp, $44b8
    cp l
    ld d, l
    ld l, d
    and e
    sub c
    ld l, d
    ld a, [hl-]
    sbc b
    db $ed
    ld h, e
    cp c
    ld a, $81
    inc a
    inc d
    inc de
    ld d, l
    jr c, jr_00a_7a72

    jr nc, jr_00a_7a69

    ld d, e
    adc d
    dec b
    ld d, $df
    db $fc
    and $af
    db $76
    db $fc
    db $eb
    xor d
    and e
    pop hl
    ld h, a
    xor b
    and c
    ld d, l
    ld b, a
    ld a, [de]
    pop de
    sub $d1
    db $db
    sbc l
    ld sp, hl
    ldh [$67], a
    add c
    sbc [hl]
    ld b, $78
    ld [hl-], a
    sbc d
    ld a, [hl+]
    ld [hl], c
    push bc
    xor l
    daa
    dec l
    ld [bc], a
    inc d
    ld [$d549], sp
    ld a, [bc]
    ld de, $00f5

jr_00a_7a3f:
    ld h, [hl]
    cp c
    ld e, d
    jr c, @+$15

    and c
    ld c, b
    ld b, [hl]
    ld l, b
    jp nc, $9aa3

    add hl, de
    add a
    add c
    db $d3
    dec h
    ld a, [bc]
    add hl, sp
    ld h, l
    ld c, h
    dec h
    ld sp, $5151
    ld a, l
    jr c, jr_00a_7a3f

    ld de, $4af5
    ld a, b
    ld d, b
    ld a, a
    ld a, h
    ldh [$57], a
    db $dd
    xor d
    xor a
    rst $38
    ld d, a

Jump_00a_7a69:
jr_00a_7a69:
    ld l, a
    db $ed
    ld c, h
    rst $10
    ld a, [$1b8e]
    rst $28
    db $f4

jr_00a_7a72:
    ld [hl], $92
    sub a
    add sp, -$19
    ld a, h
    ld [hl], b
    cp l
    ld d, b
    ld c, b

jr_00a_7a7c:
    ld a, d
    ld a, [hl-]
    sbc a
    add a
    rra
    dec h

jr_00a_7a82:
    rlca
    adc h
    dec d
    ld l, d
    xor d
    xor [hl]
    xor d
    ld [c], a
    ld h, $56
    rst $30
    ld b, c
    ld c, d
    ld e, d
    ld l, c
    ld b, $90
    add d
    ld [$afc1], sp
    rst $30
    db $f4
    inc d
    add h
    ld h, b
    ld b, l
    dec c
    sbc c
    ld b, $b6
    ld d, $97
    ld a, [$7ea0]
    ld [hl+], a
    ret c

    sbc h
    adc d
    ld sp, $a09a
    adc l
    cpl
    or $78
    sub a
    ld d, $d6
    ld h, b
    add c
    ld [$d798], a
    rst $38
    dec h

jr_00a_7abb:
    ld [hl+], a
    ld b, l
    add hl, bc
    add hl, bc
    ld h, b
    ld h, d
    and $bf
    ld d, l
    rra
    cp d
    ld d, b
    add [hl]
    ld d, h
    ld l, b
    db $e4
    sub a
    cp $b6
    dec b
    dec b
    jr nc, jr_00a_7a7c

    ld d, l
    ld d, a
    jr nc, jr_00a_7abb

    ld d, l
    cp [hl]
    sbc l
    dec b
    dec de
    ld c, l
    sub l
    inc hl
    ld d, $a1
    db $fc
    ld a, h
    ld a, $47
    ld h, $f5
    ld [hl-], a
    ld d, b
    adc d
    and h
    adc a
    rst $00
    jp $94d0


    jp nz, Jump_00a_52bd

    db $e4
    add h
    dec h
    daa
    rst $00
    cp $21
    ld c, l
    ld a, [hl+]
    db $fd
    ld d, h
    jr nz, jr_00a_7a82

    push af
    ld e, e
    rst $30
    jp z, $8ea3

    xor e
    call nc, $7a15
    or h
    daa
    push af
    ld a, [bc]
    ld a, [hl-]
    sub h
    add hl, hl
    ld c, c
    ld d, d
    xor e
    ld d, e
    xor [hl]
    cp $2d
    ld a, b
    xor b
    ld h, a
    ld a, [hl+]
    ld a, c
    ld c, d
    ld b, d
    ld c, l
    ld a, [de]
    ld b, a
    ld b, [hl]
    ld c, h
    ld h, b
    sbc c
    inc hl
    rst $00
    inc [hl]
    ld h, h
    add h
    ld h, [hl]
    ld sp, hl
    ld e, c
    jp nc, $9892

    inc sp
    sub d
    ret


    jp nz, Jump_00a_448c

    ld e, h
    ld c, e
    dec b
    ld c, a
    push af
    ld a, [de]
    ld hl, $ca1c
    or b
    ret nz

    cp $96
    add h
    ld [hl], h
    xor d
    or l
    dec hl
    ld a, h
    ld a, b
    ld a, [bc]
    xor d
    call nc, Call_00a_68bb
    and h
    ld sp, $aac2
    and b
    sub b
    or l
    ld b, b
    ei
    ld h, b
    cp b
    ld h, b
    and [hl]
    reti


    rra
    pop hl
    add a
    db $fc
    ld [hl-], a
    or h
    db $10
    pop hl
    cp h
    and $28
    call nz, Call_000_3055
    ld b, b
    cp a
    rst $38
    rst $38
    sub e
    ld a, [hl]
    sbc $61
    adc d
    ld l, c
    ccf
    rst $38
    rst $38
    ld hl, sp-$43
    di
    sub a
    ld [hl+], a
    call nz, $c82a
    call $ffff
    cp $38
    ld h, c
    or [hl]
    ld h, e
    ld b, d
    add a
    rst $38
    add e
    dec hl
    push de
    rst $38
    ld e, b
    db $d3
    ld hl, $a640
    ld a, c
    rra
    pop hl
    add l
    ld a, h
    jr nc, jr_00a_7bca

    add d
    inc [hl]
    ld [de], a
    ld h, c
    ld b, l
    and d
    jp nz, Jump_00a_4dca

    xor a
    ld a, h
    add $11
    rl e
    ld d, l
    dec hl
    call c, Call_00a_70f1
    daa
    ld c, l
    ld d, h
    xor e
    pop bc
    ret


    sbc h
    add hl, bc
    or d
    ld h, c
    ld d, h
    adc d
    or e
    rst $00
    inc b
    add hl, hl
    add l
    add d
    ld b, e
    ld a, [bc]
    adc l
    ld a, d
    ld [hl], h
    call nz, $96ce
    ret z

jr_00a_7bca:
    ld b, b
    sub $75
    jp nz, Jump_00a_4cf4

    ld e, $9e
    inc e
    ld de, $1985
    add b
    ld b, h
    cp l
    ld d, l
    ld d, l
    ld d, e
    add l
    ld e, a
    ldh a, [$aa]
    xor d
    dec [hl]
    ld a, a
    xor b
    add sp, $78
    db $dd
    ld d, l
    ld sp, $e078
    adc a
    ld [bc], a
    ld d, e
    pop bc
    xor b
    ld a, [c]
    sub b
    adc [hl]
    reti


    cp c
    xor d
    xor c
    ld d, h
    ld [c], a
    xor c
    ld b, $90
    ld l, c
    dec bc
    push hl
    ld c, l
    db $ec
    ld [hl-], a
    add hl, hl
    ld h, c
    xor d
    add hl, sp
    dec l
    and e
    db $e3

jr_00a_7c09:
    ld h, a
    xor d
    sbc l

Jump_00a_7c0c:
    ld [$d138], sp
    add [hl]
    ld l, l
    add l
    dec de
    ld a, c
    ret c

    add l
    ld b, [hl]
    ld l, $70
    and $f9
    dec hl
    ld d, c
    adc h
    and [hl]
    sbc b
    or c
    jp Jump_00a_5f66


    adc d
    or l
    ld b, [hl]
    ld c, [hl]
    ld h, d
    rst $38
    ld [$f96c], a
    sbc l
    db $f4
    ld d, l
    ld a, [bc]
    xor a
    ld sp, hl
    or [hl]
    or c
    db $10
    jr c, jr_00a_7c5b

    ld d, [hl]
    ld l, a
    ld d, b
    ld c, a
    ld sp, $47dd
    rst $00
    nop
    ld [hl], a
    and a
    ld d, l
    ld d, d
    ld d, [hl]
    cp [hl]
    rst $08
    ld e, $21
    ld a, a
    sub $bd
    and l
    ld d, l
    dec sp
    ld d, [hl]
    sbc d
    dec d
    xor d
    sub h
    jr nc, @-$3b

    ld [hl], c
    xor c
    ld [hl], $5b

jr_00a_7c5b:
    jp nc, Jump_00a_627b

    ld [hl], l
    ld l, d
    ld b, $c2
    ld d, [hl]
    ld hl, $5357
    ld a, [hl+]
    jp $a4e2


    add h
    add l
    push af
    ld a, [bc]
    sub h
    jr c, jr_00a_7c09

    sbc d
    ld [hl-], a
    ld h, l
    rst $28
    ld b, [hl]
    ret z

    ld e, c
    ld l, b
    ld h, l
    jp hl


    ld [hl], b
    jp z, $d6a4

jr_00a_7c7f:
    sbc e
    ld a, [hl]
    jr jr_00a_7c94

Jump_00a_7c83:
    add d
    sbc l
    ld d, d
    ld l, $6f
    ld d, l
    dec d
    ld [hl], h
    pop bc
    db $fd
    ld c, h
    and a
    ld d, h
    sbc d
    cp a
    ld d, d
    add hl, hl

jr_00a_7c94:
    ld a, l
    ld a, l
    ld [hl], d
    ld e, a
    db $ec
    adc d
    db $f4
    sbc l
    rrca
    rrca
    db $fd
    ld d, b
    ld c, h
    jr @-$44

    ld l, c
    add c
    add d
    rlca
    or a
    ld [c], a
    ld de, $ffeb
    cp d
    call nc, $d2a8
    dec h
    and d
    jr z, jr_00a_7c7f

    add c
    push hl
    ld e, l
    push hl
    ld h, h
    ld h, e
    ld b, [hl]
    ld d, $30
    ld a, e
    jp nc, $2214

    ld l, b
    jr c, jr_00a_7ce8

    ld l, b
    inc hl
    ld e, c
    inc c
    add $90
    ld hl, sp+$76
    and b
    ld b, d
    ld [c], a
    ld e, b
    inc d
    ld d, e
    add [hl]
    ld e, [hl]
    ld d, h
    ld d, b
    ld d, l
    ld d, $f9
    sub a
    ld [$ff0a], a
    rst $28
    ld d, h
    pop bc
    cpl
    rst $38
    rra
    rrca
    add $be
    ld a, [c]
    dec l

jr_00a_7ce8:
    ld a, l
    ld a, l
    ld a, e
    rst $38
    ld hl, $6b88
    ld l, d
    jr jr_00a_7d1c

    adc h
    ld a, [hl+]
    xor d
    ld a, [hl+]
    or b
    and a
    sub $56
    ld h, $25
    ld b, l
    ld h, b
    db $f4
    set 5, [hl]
    sub l
    ld a, a
    ld c, e
    and d
    ld d, h
    and a
    ret nc

    add [hl]
    rst $18
    adc d
    ld e, [hl]
    sbc a
    xor c
    ld d, d
    dec d
    dec l
    ld l, b
    db $10
    add d
    sub d
    ld h, $a3
    rlca
    db $fc
    jr z, jr_00a_7d37

    sub l

jr_00a_7d1c:
    cp $61
    ld e, e
    ld e, b
    adc b
    ld a, [de]
    dec b
    ld b, [hl]
    ld b, d
    daa
    ld h, b
    ld b, d
    ld e, $07
    cp $81
    and c
    rst $38
    or b
    ld h, h
    jr z, jr_00a_7d8d

    and [hl]
    add hl, hl
    add l
    add hl, de
    adc b

jr_00a_7d37:
    ld e, [hl]
    add hl, hl
    sub [hl]
    xor e
    ld h, [hl]
    add [hl]
    xor $e8
    add l
    inc hl
    inc d
    inc l
    inc h
    xor d
    ld d, c
    db $fd
    add l
    ld l, c
    ld a, [$7f9c]
    dec [hl]
    ld h, h
    ld e, b
    ld [de], a
    ld e, e
    and d
    sub h
    ld [hl], $f0
    ldh a, [$58]
    jr jr_00a_7d71

    sub [hl]
    sbc b
    ld d, a
    jr jr_00a_7dc0

    sbc b
    ld de, $a0c8
    ld l, c
    ld d, c
    ld a, [hl]
    add l
    ld hl, $92fb
    ld h, h
    cp [hl]
    ld c, c
    push hl
    ld sp, hl
    ld e, b
    ld a, $d6

jr_00a_7d71:
    ld b, $16
    rra
    or h
    ld h, d
    ld e, b
    ld [hl+], a
    ld a, d
    ld h, h
    sbc d
    ld a, [de]
    sub l
    xor b
    dec d
    add l
    adc d
    ld a, a
    sub b
    ld b, c
    add [hl]
    dec l
    db $f4
    dec h
    ld c, b
    ld l, a
    jp c, Jump_00a_7a69

jr_00a_7d8d:
    adc c
    ld e, e
    cp d
    inc b
    add l
    adc h
    ld [hl+], a
    ld a, [hl+]
    ld e, a
    add [hl]
    ld e, d
    sub l
    ld hl, sp-$3e
    xor d
    ld d, [hl]
    dec b
    adc h
    and h
    push bc
    dec h
    ld [$9779], a
    ld b, h
    dec a
    ld e, a
    xor c
    ld c, c
    sbc $b0
    xor l
    ld c, d
    push af
    ld l, a
    ld e, a
    xor d
    sbc e
    and c
    inc b
    ld d, h
    inc l
    inc sp
    ld a, a
    call nc, $f7ea
    xor h
    ld d, h
    sbc c
    ld c, a

jr_00a_7dc0:
    jr @+$2e

    ld l, $85
    cp a
    ld a, [$eaf5]
    ldh a, [rNR52]
    ld sp, hl
    ld [$e4c4], sp
    scf
    ld [$fd85], a
    ld a, [hl]
    rst $38

jr_00a_7dd4:
    ei
    sbc h
    inc c
    ld h, c
    ld e, c
    inc d

Call_00a_7dda:
    ei
    ld a, [$d1bf]
    ld d, h
    ld c, h
    sbc b
    pop bc
    ld h, b
    sbc c
    ld d, d
    sub e
    ld e, a
    rst $38
    ld a, [$1d82]
    ld [bc], a
    sbc b
    call z, $c645
    ld de, $5f95
    ld a, [$0bdb]
    cp $de
    adc l
    ld c, c
    ld de, $2831
    ld [hl+], a
    ldh a, [$a8]
    jp $b0df


    inc sp
    ld a, a
    rst $28
    ldh [$c7], a
    dec de
    ret nz

    db $dd
    ld [$314b], a
    inc de
    ld a, l
    ld a, l
    add $70
    call nz, $e0c0
    add d
    sub c
    ld a, a
    db $eb
    pop af
    ld d, e
    add sp, $5a
    ld h, l
    rlca
    dec d
    dec c
    or d
    inc de
    inc bc
    pop af
    inc d
    dec de
    inc sp
    ccf
    rst $28
    db $e4
    inc l
    jr z, jr_00a_7dd4

    ret z

    ld e, [hl]
    call nc, Call_00a_4af2
    add h
    xor l
    ld e, a
    rst $38
    cp $32
    sub b
    add d
    add $10
    dec a
    ld d, h
    call nz, $d058
    dec [hl]
    set 7, a
    cp $54
    ld b, h
    sbc l
    ld c, l
    jr z, @-$3e

    rst $10
    rst $38
    add hl, de
    pop bc
    ld b, [hl]
    or b
    xor a
    adc l
    xor a
    di
    ld [$42a1], a
    adc d
    dec bc
    pop af
    db $10
    add $1a
    cp b
    dec [hl]
    ld a, l
    cpl
    add a
    db $fd
    inc d
    cp [hl]
    db $fc
    ld b, h
    cp d
    ld c, d
    ld [$3fdc], sp
    rst $30
    cp a
    rst $28
    pop de
    ld c, c
    jr c, jr_00a_7eea

    adc d
    add l
    push hl
    ret nz

    db $ec
    dec a
    cp a
    db $f4
    cp l
    ld a, [bc]
    rrca
    ld h, h
    pop bc
    or h
    db $10
    db $76
    ld e, $90
    jp nz, $aff0

    ret nc

    dec hl
    bit 1, e
    pop af
    ld l, b
    ld d, c
    ld l, d
    ccf
    ret nc

    db $e3
    sub c
    ld a, [c]
    cp a
    ld a, a
    inc bc
    cp $2a
    and h
    and d
    sub a
    and c
    add $39
    inc de
    ret nz

    or h
    dec bc
    call nc, $bc0a
    ld de, $c50c
    rst $38
    add sp, $25
    ret


    dec de
    di
    ret nc

    ld b, b
    db $f4
    add a
    ld a, [hl+]
    xor a
    dec d
    inc bc
    jp $a5ff


    jp c, $0b34

    push af
    ld a, e
    rlca
    ret nc

    ld a, a
    push bc
    pop bc
    ld [hl], h
    ccf
    push hl
    call nz, $3552
    dec d
    dec c
    ld [bc], a
    push af
    ld b, [hl]
    inc sp
    ret nc

    cp a
    and [hl]
    add hl, bc
    dec d
    ld [$45bc], a
    ld a, a
    ld a, [bc]
    ld l, c
    add h
    ld b, e
    ret


    set 2, b
    and e
    inc de
    dec de
    inc h
    ld b, [hl]
    and b

jr_00a_7eea:
    ld b, h
    cp d
    ld d, [hl]
    adc $06
    ld [hl-], a
    ld h, [hl]
    and e
    ld c, b
    ld d, b
    add c
    push bc
    ld b, $a7
    jp nc, $5962

    ld h, b
    ld [$995a], a
    db $e3
    ld a, [bc]
    ld b, c
    ld c, $75
    jp $0506


    ld d, d
    ld d, d
    call nc, $9920
    sbc $09
    ld d, [hl]
    ld hl, $9ab2
    ld b, $60
    ld b, c
    res 2, b
    ld [hl], h
    ld [de], a
    sbc e
    pop de
    ld b, d
    adc e
    ld d, h
    jr c, jr_00a_7f9c

    xor e
    add e
    ld d, b
    sbc d
    ld [hl], b
    ld h, c
    ld c, b
    ld a, b
    add $82
    db $db
    ld sp, hl
    ld h, c

jr_00a_7f2d:
    add d
    jr jr_00a_7f44

    ld [c], a
    or l
    adc h
    ld l, b
    db $e4
    cp [hl]
    xor l
    ld d, l
    ld c, [hl]
    ld l, c
    add [hl]
    xor d
    adc [hl]
    adc b
    ld hl, sp-$27
    or d
    ld l, d
    and [hl]
    xor b

jr_00a_7f44:
    or c
    add hl, bc
    ld l, a
    ld d, c
    ld c, h
    sub c
    inc d
    add h
    jr c, @+$63

    ld a, [bc]
    db $e4
    push bc
    jr z, jr_00a_7f7b

    add hl, hl
    ld [$374c], sp
    and $4c
    rlc e
    call nz, $2f7c
    push hl
    db $e4
    jr nz, jr_00a_7f2d

    ld [bc], a
    and h
    ccf
    di
    dec d
    ld d, d
    inc de
    inc b
    inc c
    cp $17
    di
    ld sp, $3532
    sub $13
    ld a, [hl]
    ld d, e
    ld b, $e6
    inc d
    ld d, $8b
    ld a, h

jr_00a_7f7b:
    ld c, h
    adc a
    add $b1
    add [hl]
    ld b, h
    pop hl
    ld c, e
    sbc h
    or b
    or [hl]
    add l
    ld d, c
    adc $91
    pop bc
    ld d, c
    pop de
    sbc [hl]
    inc c
    ld a, h
    ld h, b
    ld hl, $684d
    ld b, $0f
    call Call_000_3620
    ld a, [$d03c]

jr_00a_7f9c:
    and a
    jr nz, jr_00a_7fcf

    ld hl, $d045
    ld de, $cfd1
    ldh a, [$f3]
    and a
    jr z, jr_00a_7fb0

    ld hl, $d040
    ld de, $d000

jr_00a_7fb0:
    ld a, [de]
    cp $16
    jr z, jr_00a_7fcf

    inc de
    ld a, [de]
    cp $16
    jr z, jr_00a_7fcf

    bit 7, [hl]
    jr nz, jr_00a_7fcf

    set 7, [hl]

Call_00a_7fc1:
    ld hl, $7fdb
    ld b, $0f
    call Call_000_3620
    ld hl, $7fda
    jp Jump_000_3c79


jr_00a_7fcf:
    ld c, $32
    call Call_000_3781
    ld hl, $7fe9
    jp Jump_000_3c79


    db $ed
    add hl, hl
    xor a
    ld h, a
    ret nz

    ret z

    db $dd
    ld a, a
    or e

Call_00a_7fe3:
    or h
    jp nz, $c0b9

    rst $20
    ld e, b
    db $ed
    add hl, hl
    call z, $ba67
    or e
    add hl, hl
    or a
    db $dd
    ld a, a
    or [hl]
    call c, $c0bc
    rst $20
    ld e, b
    pop bc
    dec e
    adc l
    ld [hl], a
    ld a, e
    db $fd
    ld [hl], e
