; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $00d", ROMX[$4000], BANK[$d]

    ld [hl], a
    cp h
    ld [hl], l
    ld c, c
    ld a, l
    ld [hl-], a
    xor c
    dec sp
    rla
    cp c
    and c
    ld b, c
    ld b, c
    ld sp, $9391
    and c
    and c
    ld c, b
    pop bc
    xor b
    sub h
    reti


    dec d
    rlca
    ret nc

    ld e, d
    ld c, e

jr_00d_401c:
    and l
    and c
    xor b
    sub h
    xor b
    add $26
    db $eb
    add c
    ld [$1586], sp
    ld l, d
    inc b
    ld h, $27
    or $25
    ld [hl-], a
    ld c, h
    ld a, [c]
    ld h, l
    ld a, [c]
    sub b
    ld l, b
    ld d, b
    ld b, e
    jp nc, $9430

    call $9498
    db $10
    ld a, [hl]

jr_00d_403f:
    add c
    ld h, $04
    ld l, c
    ldh [$9f], a
    call c, $a260
    ret c

    sub h
    sub [hl]

jr_00d_404b:
    ld b, e
    adc c
    and h
    add h
    adc c
    ld l, $8c
    ld a, [hl+]
    dec h
    ld c, h
    ld l, b
    db $10
    ld c, h
    sub e
    ld b, h
    ld [c], a
    ld d, b
    ld c, c
    ld d, b
    and c
    ld c, [hl]

jr_00d_4060:
    db $38, $84
    and $60
    add [hl]
    dec d
    dec d
    db $30, $8e
    inc a
    jp z, Jump_00d_5989

    rrca
    ld b, c
    ld [$5862], sp
    and [hl]
    jr jr_00d_401c

    push bc
    ld c, l
    rst $10
    sbc e
    dec de
    ld e, b
    adc l
    ld b, c
    ld a, l
    ld b, l
    ld hl, $8adc
    ld [hl+], a
    add c
    ld c, d
    ld [hl], a
    ld e, [hl]
    ld c, b
    sub h
    ld d, [hl]
    db $db
    reti


    ld [$0a9b], sp
    jr c, jr_00d_403f

    ld b, d
    cp h
    cp d
    jp nz, Jump_000_250a

    inc b
    adc b
    adc b
    add $22
    dec h
    ei
    ld a, c
    adc h
    add sp, $28
    jr z, jr_00d_40c6

    ld h, d
    inc de
    ld c, b
    add hl, hl
    ld a, d
    pop bc
    ld c, b
    ld d, l
    jr c, @+$27

    add l
    ld h, e
    jr jr_00d_404b

    add hl, hl
    add sp, $5e

jr_00d_40b5:
    ld [hl+], a
    and l
    cp [hl]
    xor a
    ld l, $8e
    dec a
    ld b, l
    ld a, b
    jr nz, jr_00d_4060

    ld d, d
    db $eb
    and c
    adc [hl]
    jr z, @-$44

jr_00d_40c6:
    ld a, [hl+]
    ld [$61a8], sp
    push hl
    ld d, d
    inc d
    ret


    jr nc, jr_00d_414d

    ld a, [de]
    ld hl, $a561
    add hl, de
    ld h, d
    ld [hl+], a
    ld d, l
    inc b
    ret


    and d
    inc d
    inc d
    db $eb
    ld c, c
    xor b
    push de
    ld [hl+], a
    jr jr_00d_410e

    inc d
    adc d
    dec h
    and e
    ld b, $05
    ld h, b
    db $d3
    ld l, b
    cp c
    ld d, h
    xor d
    dec h
    ld c, h
    db $10
    and d
    ld e, h
    jr nz, jr_00d_4144

    and l
    ld h, d
    db $e4
    sub l
    ld b, c
    ld b, a
    ld l, b
    ld d, d
    push de
    ld b, c
    jr c, jr_00d_415a

    ld [$a88b], sp
    xor e
    xor h
    sub h
    pop de
    sub d
    ld d, h
    adc d
    dec d

jr_00d_410e:
    ld d, c
    ld b, c
    ld a, [de]
    ld e, b
    xor c
    ld c, c

jr_00d_4114:
    ld c, h
    inc l
    ld de, $70a4
    xor e
    ld [hl], h
    jr z, jr_00d_40b5

    pop hl
    sub h
    ld [hl], e
    ld a, [de]
    ld [hl], b
    ld a, d
    ld l, $8b
    sbc $e2
    sbc [hl]
    ld [de], a
    push bc
    ld [hl-], a
    ld h, a
    ld [hl-], a
    ld [hl], a
    jr nc, jr_00d_4114

    ret nc

    ld b, [hl]
    jp hl


    add hl, bc
    ld a, [bc]
    ld c, d
    sbc d
    inc h
    ld a, h
    ld a, [bc]
    ld d, $09
    xor h
    ld [hl-], a
    add h
    ret nz

    xor l
    ld sp, $8492

jr_00d_4144:
    rra
    adc e
    dec b

Jump_00d_4147:
    ld d, l
    sbc d
    inc h
    ld [hl], h
    adc h
    ld b, h

jr_00d_414d:
    ld b, d
    sub $0a
    dec sp
    ld a, d
    ld d, h
    jr jr_00d_419b

    xor e
    inc h
    call nz, Call_000_3e30

jr_00d_415a:
    inc l
    ld d, $44
    inc [hl]
    ld [hl-], a
    add hl, hl
    ld a, c
    add d
    add hl, bc
    add hl, bc
    ld l, b
    ld hl, $480d
    ld h, h
    ld [hl-], a
    ld c, d
    inc [hl]
    ld de, $3912
    ld e, c
    adc l
    ld [bc], a
    inc c
    ld e, h
    inc c
    dec l
    ld b, h
    ld c, c
    adc h
    ld h, d
    xor b
    and d
    xor c
    inc l
    ld l, c
    ld [hl], $33
    inc b
    ld d, h
    ld e, h
    ld c, h
    db $10
    dec l
    inc d
    and c
    ld c, c
    add h
    cpl
    sbc l
    jr @+$32

jr_00d_418f:
    ld a, [hl+]
    dec hl
    dec h
    call nz, Call_00d_5237
    call nz, $3544
    ld b, b
    add h
    sbc e

jr_00d_419b:
    inc l
    add hl, sp
    add h
    inc c
    ld b, e
    ld b, l
    add $29
    dec d
    ld [hl+], a
    and h
    xor h
    dec de
    ld d, d
    db $e4
    ld d, b
    dec l
    jr jr_00d_421f

    ld [hl-], a
    add e
    ld [bc], a
    ld a, [bc]
    ld c, h
    ld [de], a
    and c
    inc l
    inc d
    ld e, d
    sbc $0c
    inc c
    dec bc
    sub l
    sub c
    jr jr_00d_41e4

    dec h
    dec [hl]
    inc bc
    adc $ac
    ld b, a
    sbc b
    inc h
    and $6b
    dec d
    ld h, h
    ret z

    ld h, b
    jp z, $9132

    ld a, h
    push af
    add [hl]
    ld c, $c4
    add hl, hl
    ld a, [bc]
    add hl, hl
    ld d, h
    and c
    db $dd
    sub a
    ld c, l
    ld c, d
    sbc b
    ld d, b
    jr c, jr_00d_4205

    add h

jr_00d_41e4:
    jr nc, jr_00d_418f

    sub h
    ld [$7537], sp
    ld [bc], a

Call_00d_41eb:
    ret


    inc [hl]
    xor b
    rst $08
    jp nz, $a48d

    ld b, c
    rla
    db $e4
    add $30
    pop bc
    ld [hl], d
    xor l
    or b
    ld c, e
    and e
    jr nc, jr_00d_4243

    ld b, [hl]
    inc e
    ld b, d
    jp nz, $8c82

jr_00d_4205:
    or b
    or d
    ld b, e
    db $e3
    db $d3

jr_00d_420a:
    dec d
    sub e
    and a
    ld a, [hl-]
    ld h, e
    ld h, c
    ld e, b
    or a
    ld h, [hl]
    ld d, $15
    ld a, [bc]
    ld c, h
    inc [hl]
    jr z, @+$76

    dec l
    dec l
    or h
    ld b, a
    adc l

jr_00d_421f:
    cp d
    sub d
    or b
    ret nc

    ld b, b
    adc d
    dec hl
    ld b, b
    sbc b
    ld [hl-], a
    ld sp, $0886
    ei
    ld b, h
    ld h, b
    and l
    push bc
    ld c, b
    ld d, h
    add hl, bc
    ld a, [de]
    add a
    adc d
    ld h, d
    and e
    ld a, a
    ldh [$e3], a
    ld l, b
    xor h
    ld b, h
    ld b, h
    and [hl]
    ld [de], a
    inc de

jr_00d_4243:
    xor c
    sbc h
    dec [hl]
    ld hl, sp+$40
    xor b
    ld a, h
    ld h, b
    sub l
    ld b, [hl]
    inc d
    add h
    sbc c
    ld b, b
    ret nz

    rst $10
    sub l
    inc b
    ld [hl], l
    db $d3
    sbc d
    ret nz

    rst $00
    ld [$9644], sp
    ld d, d
    ld l, c
    db $fd
    ld b, c
    rst $38
    call nc, $0ac2
    and $a2
    ld de, $2781
    ld [$94a7], sp
    jr z, jr_00d_4298

    or l
    dec d
    xor d
    jr nc, jr_00d_42c5

    xor [hl]
    adc b
    and d
    jr nz, jr_00d_420a

    ld d, e
    dec b
    ld d, d
    ld [de], a
    and b
    ld e, b
    ld a, a
    and c

Jump_00d_4281:
    ld c, d
    add c
    dec d
    ld l, $23
    ld a, [c]
    and d
    sbc [hl]
    ld [hl+], a
    dec b
    ld c, c
    ld l, d
    jp z, $9598

    ld h, $81
    add c
    rra
    and d
    db $e3
    dec bc
    ld l, [hl]

jr_00d_4298:
    dec b
    and h
    ld a, b
    sub h
    jp c, Jump_000_2125

    ld a, b
    jr nc, jr_00d_42fd

    inc [hl]
    ld h, b
    ld c, h
    ld l, d
    rst $18
    ld c, l
    ld sp, $5f6f
    ld d, a

Call_00d_42ac:
    add d
    rlca
    ld d, e
    ld a, [hl-]
    ld h, $86
    and b
    sbc b
    add [hl]
    dec sp
    ld l, h
    add h
    inc sp
    xor [hl]
    and b
    and e
    push bc
    ret nc

    sub [hl]
    and b
    or c
    add d
    sbc c
    db $e4
    inc h

jr_00d_42c5:
    call nz, $0c59
    inc [hl]
    sub h
    add h
    ret nc

    ld d, e
    ld [hl], l
    ld e, [hl]
    ld [hl-], a
    sub b
    sub d
    ret nz

    db $e4
    res 1, e
    ld d, l
    ldh [$f2], a
    ld d, h
    ld de, $4a54
    ld b, e
    ld a, l
    add [hl]
    and l
    jp z, Jump_00d_5843

    ld e, d
    jp $b9c2


    sub h
    ld l, $aa
    and b
    push de
    ld b, $9a
    ld h, e
    inc de
    ld d, b
    ld a, $2c
    sub c
    ld h, $34
    ld de, $847f
    jr z, jr_00d_4327

    daa

jr_00d_42fd:
    ld d, $0e
    add [hl]
    ret nc

    ld a, $62
    jp $4117


    add h
    sub b
    and [hl]
    dec sp
    ld b, $1d

jr_00d_430c:
    ld c, d
    call z, $9c4d
    ld sp, $438c
    ld [de], a
    sbc l
    ld d, d
    or h
    ld a, h
    jr nc, jr_00d_4380

    cp b
    call nc, $29b5
    ld d, l
    dec sp
    ld a, [hl+]
    sub d
    ld a, [hl+]
    sub a
    ld [$3b9d], a

jr_00d_4327:
    ld h, b
    add l
    ld b, d
    ld [$fd55], sp
    ld a, [hl-]
    ld l, b
    xor b
    db $10
    ld b, d
    ld [$ada3], a
    db $e4
    adc b
    ld d, d
    dec h
    xor l
    add hl, sp
    sub [hl]
    xor b
    ld a, [hl+]
    adc c

jr_00d_433f:
    ret z

    ld l, d
    ldh [rHDMA5], a
    ld d, h
    push de
    or h
    or [hl]
    and c
    adc c
    sub a
    ld hl, sp+$11
    cp $ff
    ld d, d
    ld e, d
    add c
    dec h
    sbc [hl]
    ld [hl+], a
    add hl, bc
    pop hl
    ld e, d
    add a
    db $fd
    cp a
    ld hl, sp+$50
    add c
    adc b
    ld h, a
    adc e
    and b
    ld c, [hl]
    ld a, [de]
    ld l, d
    inc b
    dec h
    dec b
    sub [hl]
    add hl, bc
    ld hl, $34f4
    ld d, [hl]
    xor d
    xor d
    sub l
    ld b, c
    ld b, c
    ld e, [hl]
    and d
    ld [hl+], a
    jr nc, jr_00d_430c

    add hl, de
    adc b
    ld c, h
    ld d, l
    ld d, l
    rst $38
    inc sp
    ld b, d
    add l

jr_00d_4380:
    and e
    dec [hl]
    ld a, a
    ld a, [$aaaa]
    dec [hl]
    db $fd
    adc h
    db $10
    adc e
    xor d
    sub l
    ld d, l
    ld c, b
    ld e, d
    xor d
    sbc d
    db $f4
    pop bc
    ld h, h
    jp c, $f2ab

    ld h, h
    jp nz, Jump_00d_499b

    ld b, l
    scf
    rst $38
    and d
    ld l, b
    dec h
    jr nc, jr_00d_433f

    ld c, c
    adc h
    ld l, c
    rst $38
    ld b, l
    ld e, a
    add [hl]
    adc b
    and h
    and l
    ld sp, $a4d2
    ld [de], a
    ld a, a
    ei
    adc b
    or h
    add h
    sbc a
    ld e, d
    dec l
    and l
    inc d
    add h
    ld l, e
    call nc, $d8c2
    ld a, [hl+]
    rrca
    ld a, [hl+]
    add hl, hl
    ld h, $19
    sub $a8
    jp nc, $839e

    jp hl


    ld c, d
    ld b, [hl]
    ld l, b
    ld e, $3a
    add hl, hl
    ld l, c
    ld [hl+], a

Jump_00d_43d5:
    ld h, $46
    dec b
    dec sp
    xor b
    ld l, b
    adc b
    add h
    sbc a
    ld d, l
    ld a, [hl-]
    and d
    ld [c], a
    xor [hl]
    add [hl]
    xor d
    ld a, [hl-]
    sub d

Jump_00d_43e7:
    jr @-$38

    push af
    ld e, [hl]
    ld sp, $129e
    ld b, d
    ld [hl], a
    and [hl]
    ld a, d
    ld c, h
    db $76
    inc hl
    ld l, c
    add hl, bc
    rra
    jp nc, Jump_00d_7444

    and h
    ld a, [hl]
    ld b, d
    ld a, b
    xor d
    add e
    db $fc
    rra
    pop bc
    ld a, [$a173]
    rla
    rst $38
    adc e
    push bc
    ld e, d
    ld d, d
    ld l, l
    ld a, [bc]
    and h
    ccf
    ld sp, hl
    db $10
    and c
    xor a
    pop bc
    ld d, l
    xor e
    add d
    ld c, d
    ld c, e
    db $fc
    rst $38
    pop hl
    ld h, b
    adc e
    db $fc
    add d
    and [hl]
    jp hl


    rrca
    ret nz

    rst $38
    ld sp, hl
    ld a, $31
    db $10
    ld b, c
    ld d, l
    ld a, [hl]
    and l
    inc h
    res 4, d
    or a
    sub e
    ld [hl+], a
    and c
    add hl, de
    xor e
    adc d
    add hl, bc
    rra
    cp $36
    pop hl
    inc de
    inc hl
    ld [$fdab], a
    ld d, l
    ld d, l
    sub l
    rst $38
    jp hl


    ld c, [hl]
    ld c, l
    sub c
    ld d, l
    sub e
    dec de
    rst $38
    rst $38
    ret nz

    cp a
    sub e
    pop de
    inc l
    add d
    cp c
    add d
    ld l, e
    inc bc
    rst $38
    db $e4
    ld [hl], $28
    or e
    ccf
    rst $38
    add sp, $31
    ld [$8d49], sp
    rst $38
    add l
    ld a, [bc]
    sub $a8
    ld d, l
    ld e, c
    ld de, $3082
    dec h
    ld l, l
    ei
    sub e
    ld e, d
    rst $30

jr_00d_4476:
    and h
    and h
    xor d
    ld c, d
    ld d, h
    add a
    db $ed
    xor $8a
    sub c
    ld d, b
    ld e, e
    ld a, [hl+]
    or l
    add hl, hl
    sbc e
    rlca
    ei
    ld a, a
    and c
    xor c
    dec [hl]
    ld b, $82
    adc l
    add h
    ld h, h
    call nz, $87ff
    cp $86
    sub e
    inc bc
    and a
    ld d, l
    pop hl
    rst $38
    ld hl, sp-$26
    rrca
    rst $00
    ld a, a
    rst $38
    ld sp, hl
    jr nc, @+$5f

    dec e
    rst $28
    rst $38
    sbc b
    add hl, sp
    add hl, bc
    rst $18
    rst $38
    jr jr_00d_4476

    add a
    ld d, c
    xor h
    ld b, d
    ld h, [hl]
    ld b, h
    or l
    ld l, c
    dec l
    ld a, a
    ld c, l
    reti


    sub b
    ld c, b
    ld a, e
    ld d, l
    inc sp
    ld e, d
    ld a, [bc]
    inc e
    ld e, b
    rra
    add $30
    ld a, a
    ld d, $a2
    ld h, d
    ld h, c
    ld d, h
    cp c
    ld [$e21d], sp
    inc h
    add $52
    and a
    db $eb
    ld [hl], e
    ld d, l
    ld l, a
    scf
    call $e82a
    cp d
    sub a
    di
    add d
    ld [hl], d
    and b
    sub c
    sbc d
    add hl, hl
    daa
    rst $38
    jp nc, Jump_000_24e8

    ld l, a
    ld b, l
    ld [hl-], a
    add sp, -$3e
    ret nc

    pop de
    ld d, h
    add h
    add $8c
    xor l
    or e
    add hl, de
    push af
    ld c, $8d
    ld l, c
    ld d, b
    ld c, c
    ld a, a
    ld [$e13c], sp
    sub b
    ld h, b
    rst $38
    ld a, [hl]
    add hl, sp
    ld h, d
    ld l, d
    adc a
    ld a, [hl+]
    ld l, h
    and [hl]
    adc c
    jp nz, Jump_00d_69c1

    add l
    ld b, [hl]
    adc c
    ld a, $c5
    ld h, h
    xor d
    ld h, b
    ret nz

    adc e
    rst $38
    inc h
    ld b, h
    ld d, d
    ld h, e
    inc c
    rrca
    db $fc
    ld a, $8a
    rra
    call nc, Call_000_3f54
    cp l
    db $e3
    add hl, sp
    ld sp, $feb3
    adc $33
    sub d
    add d
    and [hl]
    ld [$3f35], sp
    add sp, $4e
    ld d, h
    dec d
    jr jr_00d_455f

    inc hl
    ld a, a
    and b
    ret nc

    daa
    ld [bc], a
    ld [hl-], a
    scf
    cp $4c
    rst $38
    jp hl


    and d
    ld [$925e], sp
    and d
    and [hl]
    ret nc

    ld [hl], $1e
    add hl, bc
    inc [hl]

jr_00d_4555:
    and b
    xor c
    cp h
    rla
    jp hl


    ld c, a
    sbc h
    pop de
    add h
    ld a, h

jr_00d_455f:
    ld d, b
    ld h, [hl]
    cp c
    call nc, $dff3
    db $d3
    call $f4b5
    dec d
    ld d, e
    jp $9056


    ld [hl], b
    rst $38
    db $d3
    cp l
    ld [$42f1], a
    sub c
    db $dd
    ld d, h
    db $ed
    ld a, e
    db $ed
    ld b, e
    sbc c
    ld a, [bc]
    dec bc
    ld c, [hl]
    adc a
    sbc $aa
    ld [hl], h
    ld d, b
    adc b
    ld d, h
    pop de
    ld d, l
    ld c, e
    and d
    ld e, d
    xor b
    ld l, c
    adc d
    sub e
    rla
    ld [$48ab], a
    and c
    ld e, b
    push bc
    sub l
    ld d, d
    jr z, jr_00d_4555

    add hl, hl
    ld d, b
    or h
    xor h
    cp l

jr_00d_45a0:
    rst $20
    xor h
    dec e
    ld d, e
    dec b
    ld d, d
    ld a, [hl+]
    db $f4
    dec d
    inc b
    ld e, l
    ld hl, $19a4
    add $33
    cp [hl]
    ld c, e
    ld b, [hl]
    inc b
    adc a
    ld a, [$6181]
    add e
    ld a, [bc]
    ld sp, $a266
    ld e, d
    add hl, hl
    ret nc

    cp b
    and h
    ld d, [hl]
    ld a, b
    pop bc
    add sp, -$4a
    ld hl, $7804
    or l
    ld d, a
    ld a, e
    adc h
    ld d, h
    or [hl]
    jp c, Jump_000_1b7e

    ld c, b
    ld a, h
    dec sp
    ei
    ld a, l
    ld c, l
    add sp, -$79
    adc e
    cp d
    add d
    and b
    db $fd
    push af
    db $ed
    jr c, jr_00d_45a0

    sbc d

jr_00d_45e5:
    ld [hl+], a
    ld [hl+], a
    ret nc

    xor e
    ld a, [$2d8c]
    ld sp, $c143
    ld sp, $2ca2
    sub l
    ld d, c
    ld d, d
    db $dd
    ld d, l
    ld h, b
    pop hl
    and c
    sub d
    ld l, l
    ld sp, $e3ab
    ld a, [hl+]
    xor d
    adc e
    adc h
    db $ed
    ld d, [hl]
    db $e3

jr_00d_4606:
    sbc d
    adc [hl]
    ld a, [hl-]
    xor b
    add sp, $53
    ld d, $3c
    ld l, e
    push de
    cp $3c
    xor d
    adc a
    ld [bc], a
    ld [hl], e
    and a
    and h
    rst $00
    and e
    inc b
    add hl, hl
    add hl, bc
    pop hl
    and b
    add d
    or b
    inc h
    daa
    add d
    sub [hl]
    db $eb
    db $10
    and c
    ld [bc], a
    add hl, bc
    call nc, $8394
    ld l, e
    dec c
    add sp, -$36
    ld [hl], h
    jr nc, jr_00d_4606

    ld c, l
    and b
    db $fc
    add h
    add hl, de
    and d
    ld c, d
    ld e, [hl]
    ld [hl-], a
    dec c
    ld c, e
    xor a
    call z, Call_00d_6352
    ld [de], a
    add d
    ld d, h
    ld a, [bc]
    or e
    rst $38
    rst $38
    ld [hl], b
    and h
    ld b, [hl]
    ld de, $ba5b
    ld h, c
    add a
    rst $38
    db $fc
    ld b, a
    ret nz

    add e
    jr jr_00d_46b1

    dec h
    ld e, a
    ld h, c
    jr nz, jr_00d_45e5

    rst $38
    rst $38
    dec hl
    inc b
    add a
    dec de
    inc h
    cp $c8
    cp a
    rst $38
    db $db
    ld d, c
    jr c, jr_00d_46b3

    ld l, a
    inc d
    push af

jr_00d_4670:
    ld b, d
    rst $38
    call c, Call_000_3211
    cp c
    sbc d
    ld h, b
    add a
    cp a
    rst $38
    ld a, [hl]
    call nz, $b024
    add $49
    ld l, e
    rst $38
    rst $38
    sub e
    inc h
    ld l, e
    db $fd
    ld l, d
    ldh [$99], a
    or h
    inc c
    ld b, a
    db $fc
    add hl, bc
    inc l
    jr c, jr_00d_4670

    rst $28
    sbc $a4
    and e
    add hl, de
    ld a, a
    sub c
    ld [de], a
    sbc c
    ld b, c
    ld d, l
    jr jr_00d_46e6

    ld a, a
    sbc $82
    ld d, [hl]
    ld c, h
    ld c, d
    add hl, hl
    ld de, $2570
    dec a
    ld de, $1984
    cp d
    ld c, h
    ld [hl], c

jr_00d_46b1:
    dec h
    ld b, [hl]

jr_00d_46b3:
    xor c
    inc c
    ld [hl], e
    reti


    sub d
    ld a, b
    or [hl]
    sbc b
    rst $00
    adc a
    ld [bc], a
    inc e
    ld de, $a0f1
    ld b, h
    cp c

Call_00d_46c4:
    sbc a
    ld c, [hl]

jr_00d_46c6:
    jp z, Jump_00d_4e15

    ld a, [$943a]
    ld e, h
    db $e3
    ld e, a
    ld a, [$4255]
    scf
    ld a, d
    ld b, c
    and l
    ld h, b
    ret c

    ld [c], a
    or [hl]
    inc e
    adc c
    jr c, jr_00d_46c6

    ld de, $aca8
    inc d
    ldh [$50], a
    db $ec
    xor a

jr_00d_46e6:
    ld d, h
    pop hl
    ld d, a
    add hl, hl
    push af
    ld a, [bc]
    ld [hl], $6a
    ld e, e
    jp nc, $e36f

    ld e, l
    ld a, d
    dec bc
    jp Jump_000_3b09


    dec l
    ld b, d
    ld c, [hl]
    ld [$2a3e], a
    ld a, h
    cp [hl]
    ld a, b
    ld a, [de]
    add hl, hl
    call nz, Call_000_0884
    jp $9b7f


    cp d
    ld [de], a
    ld a, [bc]
    ld a, [$1bd5]
    or e
    rst $08
    ei
    ld e, a
    ld a, c
    pop bc
    inc sp
    ei
    ld [hl+], a
    rst $00
    inc e
    rrca
    pop de
    add hl, bc
    db $d3
    dec h
    ret


    add hl, bc
    cp d
    ld de, $e113
    and b
    rst $00
    inc a
    jr nc, jr_00d_47a8

    db $76
    pop bc
    ld d, c
    push af
    jr nz, jr_00d_47a7

    or b
    ld d, h
    db $ed
    ld a, a
    db $d3
    sub d
    ld b, d
    push af
    ld c, [hl]
    ld [hl], l
    ld [hl+], a
    adc [hl]
    ld e, c
    sbc l
    cp l
    ld d, h
    or l
    ld d, h
    ret


    dec bc
    ld c, [hl]
    ld e, c
    inc b
    add [hl]
    xor e
    rst $10
    ld d, a
    rrca
    rst $10
    ld e, [hl]
    ld [hl+], a
    db $f4
    db $e4
    sbc d
    ld c, c
    add [hl]
    ld a, [hl+]
    add [hl]
    and [hl]
    ld l, a
    ret


    di
    sub [hl]
    ld b, c
    ld [hl], d
    ld e, $35
    or b
    ld a, l
    cp $39
    ret nc

    ld b, d
    ld e, [hl]
    scf
    ld [c], a
    inc hl
    xor c
    adc b
    xor d
    add hl, hl
    ld d, l
    dec de
    ld l, a

jr_00d_4770:
    ld h, l

jr_00d_4771:
    and e
    ld [hl], l
    rst $38
    ld d, h
    sbc b
    pop bc
    rst $28
    db $ed
    dec de
    rst $18
    adc [hl]
    rlca
    and b
    ld d, a
    res 1, d
    and l
    ld [hl+], a
    ld l, b
    adc $8c
    add sp, $1f
    xor e
    ld sp, $4a8b
    ld c, [hl]
    call nz, Call_00d_4c5f
    and h
    ld l, l
    sub l
    sbc [hl]
    rlca
    rla
    jr c, jr_00d_47c5

    ld a, [de]
    inc d
    push bc
    add hl, de
    ld b, d
    rst $38
    push hl
    sub b
    ld h, h
    sub h
    jp c, Jump_000_19d8

    ld c, h
    dec a

jr_00d_47a7:
    ld [hl+], a

jr_00d_47a8:
    ld c, b
    db $fd
    ld a, d
    ld h, d
    jr @-$21

    ld a, c
    and d
    ld e, b
    ld h, $9a
    or a
    push hl
    ld d, b
    cp l

jr_00d_47b7:
    cp d
    ld [hl+], a
    ld d, h
    pop bc

jr_00d_47bb:
    ld [$18b9], a
    jr nz, jr_00d_4770

    xor l
    db $fd
    ld a, [de]
    xor e
    reti


jr_00d_47c5:
    db $fd
    rla
    xor e
    ld c, b
    ld a, b
    ld d, a
    ld b, c
    db $f4
    ld d, d
    inc d
    ld h, b
    sbc l
    ld d, d
    sub c
    rst $28
    and h
    sub l
    cpl
    ld a, [bc]
    ld b, $bd
    ld d, b
    ld b, d
    sbc e
    ld a, [c]
    ld a, [hl+]
    inc d
    ld l, a
    ld e, b
    jr nc, jr_00d_4771

    call c, $d529
    sub $0b
    ld l, h
    dec e
    ret nc

    ld d, l
    rst $18
    di
    adc [hl]
    add a
    add d
    or l
    ld [hl+], a
    ld b, [hl]
    xor $fe
    jp $d206


    ccf
    ld a, [c]
    add hl, hl
    ld b, d
    ld d, d
    inc e
    ld d, h
    jr nz, jr_00d_47bb

    ld d, $95
    ld b, [hl]
    ld e, $09
    sbc a
    push de
    ld d, h
    ld d, h
    adc b
    ld a, [hl+]
    ld b, d
    ld hl, $9930
    ld b, l
    ld a, [bc]
    ld [$96d1], a
    cp a
    ldh a, [$a1]
    ld d, [hl]
    scf
    ld d, l
    ret nc

    or c
    ld d, c
    ld d, d
    dec l
    ld [hl+], a
    xor d
    xor d
    xor b
    pop hl
    ld a, d
    add [hl]
    reti


    jr jr_00d_47b7

    ret z

    or h
    pop af
    sub $2d
    db $f4
    sbc d
    add hl, sp
    inc d
    jp nz, $5d8c

    ld d, l
    ld d, c
    or h
    ld d, h
    push hl
    or h
    cp d
    ld [hl-], a
    xor d
    and d
    sbc a
    adc [hl]
    adc e
    push af
    ld a, b
    ld a, [c]
    and [hl]
    ld c, c
    db $dd
    inc c
    ld [hl], e
    db $db
    and b
    sbc h
    ld a, [c]
    ld c, h
    ld [hl], e
    db $db
    add h
    ld a, [bc]
    add hl, bc
    ld l, c
    add hl, bc
    sub d
    add hl, hl
    pop de
    ld a, d
    call nz, Call_000_0361
    xor d
    ld a, [bc]
    and b
    sub c
    xor a
    ld a, [$df73]
    db $eb
    db $10
    ldh a, [$b7]
    jp nz, Jump_00d_7fc1

    rst $38
    dec e
    rla
    cp $83
    adc d
    dec c
    db $e4
    db $eb
    inc bc
    ld b, c
    dec e

jr_00d_487b:
    ld [$ef37], sp
    xor $ff
    jp hl


    ld e, c
    add hl, bc

jr_00d_4883:
    jp nc, $ffc3

    rst $38
    ld e, l
    ld e, a
    jp hl


    db $10
    cp l
    inc e
    inc c
    ld [hl-], a
    ld e, l
    rst $38
    call nz, $8da0
    cp $0d
    jp nz, Jump_000_0ba7

    ld d, h
    ld e, l
    cp $10
    inc h
    ret z

    ld e, h
    call z, Call_00d_46c4
    ld [hl], c
    inc c
    rrca
    add $17
    ldh [$84], a
    sub b
    ret nz

    di
    inc b
    ld c, d
    ld l, b
    adc [hl]
    dec c
    ld [bc], a
    ld d, [hl]
    and e
    ld a, d
    adc h
    db $10
    or e
    ld b, l
    cp c
    xor h
    ld b, d
    ld a, $53
    ld a, [$fa37]
    cp h
    inc de
    dec bc
    dec bc
    rst $20
    inc c
    inc c
    jr jr_00d_4883

    ld e, e
    ld l, b
    rst $10
    ld a, [$cc84]
    cpl
    ld a, [$8a6a]
    db $10
    ld a, [hl-]
    inc c
    rst $38
    rst $08
    jp z, Jump_00d_6ad5

    add h
    cp a
    pop hl
    jr nz, jr_00d_487b

    or e

Call_00d_48e3:
    and c
    ld hl, sp+$4f
    db $db
    ld c, e
    ld a, [$f817]
    ccf
    rst $38
    dec l
    jr jr_00d_4915

    ld [hl], a
    db $ed
    ld h, c
    pop hl
    jp z, Jump_00d_5d17

    rst $18
    jp Jump_000_10fd


    call nz, Call_00d_7e71
    dec c
    ld a, [hl+]
    ld l, $d8
    ld [hl], l
    ld e, [hl]
    or l
    ld b, b
    add sp, $43
    inc bc
    ld b, [hl]
    cp a
    adc h
    rst $38
    xor a
    db $ed
    rst $38
    rst $38
    cp $a0
    rst $38
    db $fc

jr_00d_4915:
    ld h, b
    and h
    cp a

Jump_00d_4918:
    jp $f3f3


    or b
    ld a, e
    ld e, a
    rst $38
    db $fd
    add a
    ld a, [$ffff]
    ld a, [$5708]
    adc a
    dec bc
    add h
    ret z

    ld l, b
    ret nc

    xor d
    cp h
    ld c, l
    ld a, a
    rst $38
    rst $38
    ret nc

    db $e4
    jr c, jr_00d_499b

    ld h, l
    cp e
    pop hl
    call z, $8cc9
    dec c
    ld d, l
    ld b, h
    inc hl
    inc de
    ld l, h
    sub c
    adc d
    inc c
    rra
    add l
    ld c, h
    ld a, [hl-]
    ld b, d
    ld [hl], h
    ei
    inc h
    ld h, $17
    ret


    ld [hl], b
    ld a, a
    and a
    ccf
    add sp, $42
    sbc c
    ld e, a
    xor c
    db $10
    ld e, a
    db $fc
    ld [hl], d
    ld d, a
    jp hl


    add hl, hl

Jump_00d_4961:
    adc h
    dec e
    ld d, e
    inc de
    ld a, l
    inc e
    rst $30
    ld [$cb29], a
    inc b
    ld [hl], l
    ld b, c
    ld [hl], d
    ld a, c
    add b
    ld b, h
    or l
    ld d, l
    ld c, b
    ld a, l
    add hl, sp
    ld a, [hl+]
    xor e
    ld a, b
    db $e4
    ld d, h
    cp d
    dec h
    ld a, l
    ld [hl-], a
    ld a, [hl]
    xor d
    dec h
    rlca
    rlca
    add [hl]
    jr nc, @+$7b

    jr jr_00d_49b1

    db $f4
    jr z, jr_00d_49df

    inc de
    ld [hl], l
    sbc c
    add c
    inc b
    and l
    ld sp, $d4a6
    ld hl, $6952
    ld l, h
    inc de

Jump_00d_499b:
jr_00d_499b:
    add hl, de
    sub d
    ld hl, sp+$14
    jp nz, $d24c

    ld d, l
    sub $48
    ld e, a
    and e
    inc [hl]
    ld e, b
    cp d
    add l
    ei
    call z, $985e
    sub l
    ld d, b

jr_00d_49b1:
    ld a, [$32fc]
    rst $18
    dec e
    ld sp, hl
    rst $38
    ldh a, [$d6]
    ld e, [hl]
    dec h
    ldh [$df], a
    and b
    xor h
    ld sp, $86af
    ld l, $fe
    adc h
    ld l, d
    and l
    cp b
    ld hl, sp-$67
    xor d
    ld b, d
    ld d, h
    sbc h
    sub b
    and h
    inc h
    daa
    ld [de], a
    jr z, @-$1b

    sub c
    add h
    ld sp, $54a4
    add l
    db $e3
    db $ec
    ld l, b

jr_00d_49df:
    adc d
    jr nc, jr_00d_4a3c

    or $0e
    db $10
    and [hl]
    ld c, b
    dec hl
    ld [hl], a
    ret nc

    ld d, e
    add sp, $30
    and [hl]
    inc sp
    cp a
    ld a, [bc]
    or d
    or l
    and c
    ld sp, hl
    sbc a
    call nz, $ffac

jr_00d_49f9:
    xor b
    ld h, [hl]
    ldh a, [$a8]
    ld a, [hl+]
    push af
    jp nz, $aaa9

    inc e
    rst $08
    rst $38
    or e
    ld l, l
    sbc c
    jr z, jr_00d_4a54

    ld b, a
    ld e, [hl]
    jr nc, @+$23

    add hl, de
    jr z, jr_00d_49f9

    ld l, b
    and d
    add [hl]
    add a
    ld a, [de]
    pop hl
    dec d
    ld c, b
    or d
    dec c
    add hl, de
    ld b, c
    rra
    ld a, [hl-]
    ld h, [hl]
    cp h
    push hl
    ld c, h
    push de
    ld l, a
    adc [hl]
    dec h
    dec l
    cp a
    dec l

Jump_00d_4a2a:
    ldh a, [$aa]
    ld h, [hl]
    call nc, $86d5
    ld b, l
    adc h
    sbc a
    ld d, d
    and $c1
    and c
    ld d, d
    sub d
    add sp, -$32
    sub [hl]

jr_00d_4a3c:
    adc d
    ld d, a
    xor l
    ld [hl], b
    xor [hl]
    xor b
    and h
    inc de
    inc b
    adc e
    dec l
    cp a
    rst $38
    ld sp, $5a85
    add d
    push bc
    ld [hl+], a
    ld a, [hl+]
    sub b
    ld b, l
    sub [hl]

jr_00d_4a53:
    xor c

jr_00d_4a54:
    db $eb
    ld [hl+], a
    sbc b
    pop bc
    ld h, d
    ld d, d
    sub $fc
    sub l
    dec e
    reti


    ld e, c
    adc e
    ld c, c
    sub b
    and e
    dec d
    ld [$1e34], sp
    rst $38
    add sp, $58
    jp $0822


    jp c, Jump_000_28f4

    dec e
    ld c, d
    ld h, e
    jr jr_00d_4a9f

    sub e
    adc e
    jp nz, $0486

    ld e, h
    db $dd
    adc [hl]
    dec [hl]
    ld a, [bc]
    ld a, [de]
    and e
    add [hl]
    add hl, sp
    xor a
    ld e, d
    ld a, b
    jr z, jr_00d_4a53

jr_00d_4a89:
    inc b
    ld [$e0ab], a
    ld a, b
    push bc
    adc b
    ld c, h
    ld e, e
    adc $06
    ld c, l
    ld h, h
    sbc d
    sub l
    ld d, b
    add sp, -$33
    ld e, a
    db $dd
    ld [hl], $93

jr_00d_4a9f:
    sbc c
    ld a, [$a789]
    ld c, l
    ld d, e
    sub d
    ld c, e
    ld e, d
    db $76
    db $d3
    ld c, c
    rrca
    rst $38
    ld [hl-], a
    ld d, e
    ld a, [bc]
    sub b
    jp nz, $a582

    ld c, e
    adc l
    sbc $21
    jp nc, $45ee

    add l
    xor c
    ld e, b
    db $dd
    ld hl, $1478
    sub h
    sbc d
    add hl, bc
    add [hl]
    add hl, hl
    dec h
    sub l
    ld d, b
    ld b, c
    ld a, [$d726]
    and e
    ld d, h
    adc b
    ld h, $8c
    ld a, [hl-]
    inc [hl]
    and c
    or l
    ld a, [de]
    dec l
    ld h, e
    jp nz, $8eaf

    adc c
    rst $20
    ld h, $8a
    ld a, [hl+]
    add h
    ld [hl], l
    jp $c518


    jp c, $6c0a

    ld a, [$994b]
    jr z, jr_00d_4b15

    ld a, $8d
    jr nz, jr_00d_4a89

    rst $38
    ld b, b
    rst $38
    and l
    inc a
    ld h, d
    and e
    add $13
    ld [bc], a
    db $fc
    rst $38
    rst $38
    call z, $a44c
    cpl
    cp b
    ld b, c
    db $10
    and d
    ld hl, sp+$2f
    rst $38
    db $fc
    ld l, b
    rst $38
    db $fc
    cp l
    ld [bc], a
    ld c, h
    db $f4
    push af
    ld a, a

jr_00d_4b15:
    cp $43
    rla
    ld e, a
    ld a, [$3142]
    dec c
    ld c, a
    inc d
    cp $85
    ld a, [de]
    ld b, c
    rst $18
    or l
    ldh [$aa], a
    rst $38
    sub [hl]
    rst $10
    rst $20
    inc d
    rla
    or b
    ld c, b
    ld e, l
    db $fc
    ld h, c
    ld de, $2bc7
    ld a, [$df0c]
    dec de
    ld b, a
    inc h
    rra
    ld a, [$a735]
    adc l
    sub $3d
    or c
    sub h
    sbc l
    call z, Call_000_16df
    xor l
    jp hl


    sub e
    daa
    inc d
    and $93
    ld a, a
    cp c
    ld [hl], c
    rst $00
    inc b
    ld l, l
    cp a
    rst $38
    rst $38
    sbc c
    xor l
    ld [bc], a
    inc c
    xor [hl]
    sbc d
    ld a, e
    ld a, l
    ld d, l
    ld c, c
    adc h
    ld b, e
    ccf
    rst $38
    ld a, [$ff60]
    ld [$9953], a
    ld b, e
    inc b
    rst $08
    rst $38
    cp $bb
    ld a, a
    rst $38
    rst $38
    cp $60
    sub d
    add $15
    rst $38
    rst $38
    ld de, $dfff
    push af
    sbc b
    ld a, [hl-]
    add hl, de
    ld de, $5f8d
    sub l
    ld a, a
    rrca
    jp $7045


    ld b, [hl]
    add hl, hl
    db $10
    cpl
    jp hl


    ld a, h
    sbc e
    ld b, a
    dec d
    ld [hl], a
    and $31
    db $e3
    ld b, a
    ld c, b
    ld [hl], a
    or a
    ld d, a
    db $f4
    di
    dec de
    inc c
    ld a, [hl+]
    inc b
    pop af
    sub a
    rst $18
    ld d, l
    adc e
    sbc b
    pop af
    dec hl
    cp a
    cp c
    sub [hl]
    ld hl, $194f
    add sp, $1a
    ret z

    ld h, b
    ld l, l
    ld d, l
    rrca
    rst $38
    inc b
    add sp, $52
    jr nc, jr_00d_4c33

    ld h, c
    add l
    xor d
    adc h
    ld l, a
    ld d, h
    db $dd
    cp h
    cp d
    ld l, d
    dec b
    ret c

    ld [c], a
    xor e
    push af
    ld a, a
    ld d, l
    ld b, e
    and d
    dec e
    dec bc
    ret nc

    adc b
    xor c
    ld c, l
    ld d, h
    cp d
    adc b

Jump_00d_4bdb:
    xor d
    sub d
    dec l
    ld b, c
    ld b, [hl]
    rst $30

jr_00d_4be1:
    ld b, e
    call nc, $ce24
    ld l, d
    xor c
    ld c, c
    ld b, l
    ld d, d
    sub b
    ld a, b
    sbc e
    ldh [$6d], a
    add [hl]
    ld c, h
    db $d3
    inc b
    adc d
    ld [$2386], sp
    bit 4, [hl]
    adc d
    sub e
    ld h, a
    xor d
    ld b, c
    inc d
    dec [hl]
    ld [c], a
    rst $28
    ld c, b
    sbc c
    ld hl, $d848
    ld [c], a
    sbc c
    inc c
    inc l
    jp nc, $26d2

    ld d, d
    xor h
    inc hl
    adc [hl]
    sub d
    ld d, e
    ld b, l
    dec l
    rst $30
    ld c, b
    pop bc
    jr nc, @-$2b

    ld c, b
    reti


    db $e3
    ld c, $a2
    and c
    ld c, h
    dec hl
    ld c, [hl]
    ld b, a
    and e
    ld l, d
    ld [hl+], a
    inc d
    adc $d3
    ld b, l
    ld c, c
    db $e3
    ld b, $5b

Jump_00d_4c30:
    pop hl
    ld h, d
    inc h

jr_00d_4c33:
    jp nc, $52c1

    and a
    push bc
    ld b, l
    ld e, a
    or $07
    dec b
    ld d, b
    ld d, [hl]
    and b
    ld d, b
    ld l, d
    sub h
    adc d
    cp a
    ldh a, [$89]
    ld e, e
    xor b

jr_00d_4c49:
    push bc
    db $ed
    and d
    add hl, de
    sub b
    add c
    ld a, [hl+]
    sub h
    pop bc
    jr nc, jr_00d_4be1

    ld e, a
    adc c
    ld h, c
    ld a, b
    ld h, b
    sub e
    ld [$a18a], sp

jr_00d_4c5d:
    ld c, b
    adc l

Call_00d_4c5f:
    ld e, $2f
    rst $10
    db $f4
    ld [hl+], a
    dec a
    inc b
    sbc b
    jp hl


    ld d, e
    jr @+$71

    ld [c], a
    xor a
    ld a, [c]
    ld l, c
    ld d, l
    ld c, [hl]
    dec hl
    ld d, e
    ccf
    ld sp, $3ebc
    and e
    xor d
    cp l
    dec h
    ld b, d
    call z, $09f9
    ld c, [hl]
    push hl
    rlca
    cp h
    adc l
    ld d, d
    and c
    and h
    dec h
    dec sp
    ld l, $0f
    jp z, Jump_000_13ac

    dec e
    ld h, e
    ret nz

    ld a, [c]
    xor l
    dec de
    ld d, l
    ld l, [hl]
    inc a
    ld c, e
    ld d, a
    ld hl, sp-$66
    xor d
    ld [hl-], a
    sbc e
    and b
    pop hl
    and a
    sbc e
    cp l
    ld d, $9e
    ld [hl+], a
    db $10
    ld h, e
    adc a
    dec d
    inc c
    ld a, b
    db $d3
    inc c
    or b
    inc [hl]
    ld c, h
    ld a, b
    rlc e
    adc $60
    sub h
    or c
    inc [hl]
    ld [hl], h
    and h
    jr c, jr_00d_4d2e

    ld c, a
    db $fc
    ld l, a
    jr nz, jr_00d_4c5d

    or b
    jr nz, jr_00d_4c49

    ld a, [$f7af]
    xor c
    ret


    inc b
    add e
    inc b
    sub b
    sub d
    db $fc
    rra
    rst $38
    rst $38
    rst $28
    xor c
    and d
    ld [hl], b
    cp [hl]
    ld d, l
    ld de, $fe5f
    push de
    cp $99
    jp nc, Jump_000_24af

    dec hl
    call nc, $c628
    ccf
    pop de
    dec c
    cp $67
    dec b
    ld d, h
    and b
    db $fd
    ld [c], a
    add $bc
    ld h, c
    ld a, a
    and [hl]
    ld a, d
    ld e, a
    db $fc
    ld [de], a
    ld h, a
    dec d
    inc h
    cp h
    rst $38
    and [hl]
    ld e, c
    adc l
    daa
    ld [de], a
    ld c, h
    and b
    add h
    rst $18
    and $59
    and d
    ld b, [hl]
    ld l, d
    sub l
    cp h
    inc l
    rst $38
    sbc b
    ld a, c
    and h
    ld l, [hl]
    push bc
    pop af
    jr z, jr_00d_4d4f

    ld sp, hl
    sbc $ec
    ld h, b
    sub l
    ld b, b
    rst $38
    ld h, a
    ld c, d
    ld e, a
    sbc b
    inc [hl]
    dec de
    ld b, b
    rst $38
    ld c, [hl]
    sbc d
    xor b
    dec h
    ld b, e
    dec bc
    rst $38

jr_00d_4d2e:
    ld [hl], c
    db $10
    jp nc, $838d

    inc sp
    cp $a0
    and [hl]
    inc d
    ld a, [hl+]
    ld h, c
    push bc
    add hl, hl
    ld d, c
    ld c, h
    rst $38
    rst $38
    cp $b6
    and b
    and d
    rst $38
    and l
    dec h
    ld [hl], c
    adc h
    inc c
    rst $38
    rst $38
    rst $38
    rst $38
    xor l

jr_00d_4d4f:
    rst $30
    ld a, [c]
    ld h, a
    sbc e
    inc sp
    rst $38
    rst $38
    rst $38
    cp a
    rst $38
    xor e
    ld a, e
    sbc c
    ld sp, hl
    push bc
    ld d, e
    rst $38
    di
    ld a, a
    rst $38
    ld d, c
    ld d, c
    sub h
    ld l, d
    sbc b
    rst $18
    call z, $fecf
    sbc [hl]
    inc d

jr_00d_4d6e:
    sub a
    ld [hl], b
    pop bc
    inc c
    rst $38
    jp hl


    push hl
    ret


    add l
    ld e, a
    add sp, $27
    and a
    ld d, b
    ld b, a
    sbc [hl]
    sub d
    sbc [hl]
    ld b, d
    inc c
    ld de, $44ca
    cp l
    inc h
    ld [$b855], a
    db $e4
    pop af
    ld a, d
    and e
    ld b, l
    call $d128
    ld e, [hl]
    ld a, h
    call Call_00d_514a
    ld e, [hl]
    and l
    db $e3
    daa
    adc c
    ld a, c
    ld a, d
    ld [hl+], a
    adc l
    inc d
    or a
    add sp, -$5b
    dec [hl]
    ld d, b
    db $d3
    rla
    ldh a, [$8d]
    ld e, h
    ld a, a
    ld c, c
    ld a, b

jr_00d_4dae:
    jp nz, $b5fc

    or b
    db $fc
    rra
    adc [hl]
    ld e, e
    ld b, d
    ld hl, sp+$29
    ld c, $e2
    ld l, b
    jp nc, Jump_00d_52fd

    dec a
    rst $18
    ld d, l
    jr c, jr_00d_4dae

    jr nc, jr_00d_4d6e

    ld hl, sp+$79
    jp hl


    daa
    ld a, [hl+]
    sub b
    adc e
    rst $00
    inc hl
    add $31
    and d
    ld h, e
    ld h, l
    ld h, $48
    dec sp
    ld b, $66
    add e
    or c
    ld l, e
    cp $11
    sbc d
    rrca
    ldh [$a0], a
    and c
    inc sp
    ld d, c
    and d
    rst $38
    pop bc
    inc b
    ld c, e
    inc a
    ld c, [hl]
    ld h, c
    ccf
    add sp, $3f
    or h
    ld de, $f90b
    add h
    add a
    rst $38
    ld sp, hl
    sub l
    sbc c
    ret z

    ld a, a
    ld a, [c]
    sbc c
    and [hl]
    rst $18
    db $ed
    ld e, e
    ld hl, $c612
    pop de
    dec d
    ld d, b
    jp Jump_000_1f37


    ld c, h
    ld b, h
    dec l
    ld a, a
    ld sp, hl
    ld hl, $1605
    di
    rla

Jump_00d_4e15:
    xor [hl]
    ld b, [hl]
    ld [hl], h
    add hl, de
    cp [hl]
    db $ec
    jp $9289


    and c
    or h
    ld d, a
    dec [hl]
    ld b, e
    push bc
    call c, Call_00d_5e9e
    ld c, h
    db $fc
    add [hl]

jr_00d_4e2a:
    db $fd
    ld b, l
    cp b
    add hl, hl
    jr nc, jr_00d_4e91

    or $22
    ld b, $ab
    add c
    ld [$a0c2], sp
    cp b
    dec e
    xor b

jr_00d_4e3b:
    ld l, b
    adc a
    adc l
    ld e, h
    dec sp
    ld sp, $0842
    jp z, Jump_00d_4147

    dec c
    db $fd
    ld a, b
    jr nz, jr_00d_4e98

    add hl, hl
    rrca
    cp $22
    cp l
    ld d, a
    inc c
    jp z, Jump_00d_43e7

    inc d
    sbc e
    scf
    jp $f7ff


    ld h, h
    sbc l
    scf
    xor d
    sbc b
    ld hl, $4387
    add hl, sp
    xor b
    jr nz, jr_00d_4e2a

    ld hl, sp-$12
    adc a
    ld [hl-], a
    ld l, h
    sub e
    and l
    ld h, $8c
    ld [hl-], a
    ld b, h
    ld b, e
    ld h, d
    add e
    and $08
    and h
    dec h
    ld h, h
    jr z, jr_00d_4e3b

    sbc d
    and c
    dec bc
    push bc
    ld e, e
    db $fc
    ld h, d
    sub [hl]
    ld a, [$fe5c]
    ld de, $908a
    rst $38
    rst $38
    xor e
    rst $38
    ld b, [hl]
    sub e
    rst $38

jr_00d_4e91:
    rst $38
    rst $38

jr_00d_4e93:
    db $fc
    ld de, $f5ac
    ld a, a

jr_00d_4e98:
    rst $38
    rr c
    call nz, Call_00d_6858
    ld h, h
    ld d, [hl]
    cp $9a
    ld d, d
    ld d, $d9
    ld [hl], h
    ld d, l
    ld h, $2c
    adc e
    ld c, c
    adc d
    ld l, e
    ld [bc], a
    jr jr_00d_4e93

    xor c
    add d
    ld [hl], d
    or $f0
    jp Jump_00d_501d


    ld e, b
    ld [hl], c
    pop af
    ld b, b
    ld d, l
    cp [hl]
    add hl, hl
    dec sp
    dec a
    dec b
    dec d
    ld a, [bc]
    db $e3
    sbc l
    ld d, a
    cp $bf
    and b
    ld d, e
    sbc d
    xor h
    jr c, jr_00d_4eef

    ld e, e
    dec d
    add hl, sp
    xor $04
    jp nz, $1318

    xor d
    ld hl, $92d0
    ld d, h
    db $eb
    ld a, e
    ld h, $a9
    ld b, c
    db $e3
    sub e
    jp nz, $82fe

    ld [hl+], a
    cp [hl]
    add hl, sp
    ld l, b
    rra

jr_00d_4eeb:
    ret nc

    ld d, h
    adc b
    add a

jr_00d_4eef:
    ld c, [hl]
    ld e, d
    ld d, l
    adc h
    rra
    adc [hl]
    ld e, e
    ld a, l
    add d
    ld [c], a
    ld d, h
    db $dd
    rst $38
    ld d, d
    call nc, $f3a6
    adc l
    ld a, [$add2]
    ld [hl+], a
    add [hl]
    adc b
    ld c, h
    rst $28
    push af
    ld d, c
    ld d, a
    db $eb
    ld d, d
    ld l, b
    cpl
    inc [hl]
    cp a
    rst $28
    rst $28
    cp $0a
    db $f4
    ld l, [hl]
    ld d, e
    ld a, d
    rst $38
    add sp, -$36
    push af
    ld d, h
    pop af
    ld a, [hl+]
    adc a
    sub d
    sbc a
    ld d, b
    adc d
    jr z, jr_00d_4eeb

    inc e
    jp hl


    ld c, b
    ret nz

    adc a
    add h
    ld [hl], e
    rst $38
    ld a, $8a
    ld [$7474], sp
    ldh a, [$7f]
    adc d
    ld a, [bc]
    and a
    ld h, a
    ldh a, [rNR50]
    ld d, l
    dec e
    ld c, a
    db $e4
    ld h, [hl]
    or c
    jp z, $acfe

    db $10
    dec hl
    rst $28
    inc e
    sub a
    push af
    ld a, h
    rst $38
    rst $38
    pop bc
    inc e
    ld l, a
    jr jr_00d_4f93

    db $d3
    dec e
    sub $fe
    ld [hl], d
    ld b, h
    ld h, $7f
    db $fc
    xor c
    ret nz

    sub c
    ld [bc], a
    sbc c
    ld a, a
    rst $38
    and a
    dec e
    reti


    ld [$a13b], sp
    ld e, a
    ld a, [$4071]
    add h
    db $10
    ld e, b
    push bc
    rst $18
    sbc h
    or c
    ld de, $29ba
    rst $30
    ld b, b
    ld b, h
    cp [hl]
    cp l
    ld d, e
    or [hl]
    cp e
    ld e, a
    ld d, l
    ld [hl], e
    adc d
    db $fd
    add hl, bc
    sbc d
    db $fc
    db $e4
    cp l
    rst $10
    rst $38
    adc $6b
    ei
    ld a, [$973d]
    adc [hl]

jr_00d_4f93:
    rst $30
    call nc, $9feb
    xor c
    adc $ea
    ld a, $9a
    ld a, [hl]
    ld a, [hl+]
    and l
    daa
    dec sp
    rst $38
    call nc, $2978
    sub $af
    rst $20
    ld e, a
    rst $38
    sbc l
    cpl
    rst $38
    rst $00
    ld c, a
    ld d, l
    sbc a
    sub e
    add b
    ld h, [hl]
    cp b
    sbc l
    add hl, hl
    db $e3
    ld d, h
    ldh a, [rNR21]
    add l
    ld c, c
    ld b, c
    add sp, -$18
    xor d
    dec d
    and b
    ld a, l
    rla
    and a
    or h
    jp hl


    ld e, a
    ld a, l
    cp b
    sub l
    ld d, c
    ld [hl], h
    pop hl
    ld l, a
    jp c, Jump_00d_43d5

    rst $38
    cp l
    add hl, bc
    ld b, c
    and e
    add [hl]
    add l
    jp c, $efaf

    rst $38
    db $db
    ld d, [hl]
    xor l
    jr c, jr_00d_4ff9

    sub b
    ld c, c
    xor b
    ld a, [hl+]
    and d
    and l
    cp $88
    ld c, l
    ld d, l
    add hl, bc
    dec b
    dec b
    add d
    sub h
    ld d, h
    sbc d
    db $fc
    adc d
    adc h
    sbc a
    add [hl]

jr_00d_4ff9:
    ld b, [hl]
    push de
    dec hl
    db $e3
    ld a, [hl+]
    ld a, [bc]
    di

jr_00d_5000:
    dec hl
    ld c, b
    sub h
    cp d
    xor b
    jp c, $33a7

    ld a, b
    ld d, a
    ld d, c
    ld b, c
    inc d
    inc de
    ld a, d
    ld c, h
    db $fd
    ret z

    ld d, l
    dec d
    ld d, b
    cp a
    ld c, e
    ld a, l
    ld hl, $ca58
    or h
    ld a, [de]

Jump_00d_501d:
    jr jr_00d_5074

    ld b, [hl]
    ld hl, sp-$6b
    call nc, $e0a4
    ld a, h
    or l
    ld d, d
    jr z, jr_00d_5049

    add $89
    and e
    ld e, d
    ld h, b
    xor d
    ret z

    ld d, l
    add hl, hl
    ld l, b
    db $10
    and e
    adc c
    ld d, d
    call c, Call_00d_5285
    xor d
    ld [$92f3], a
    ld c, b
    and d
    sub l
    ld c, e
    cp [hl]
    ld [$8d86], sp
    rra
    add d

jr_00d_5049:
    xor e
    ld b, c
    ld b, [hl]
    ld [c], a
    push de
    ld [c], a
    db $10
    di
    ld b, a
    push de
    ld c, b
    cp d
    db $dd
    jr nc, jr_00d_5000

    or l
    ld c, l
    ld d, [hl]
    call nc, Call_000_0bc6
    call nc, $a8d2

jr_00d_5061:
    jp c, $bdd0

    ld d, e
    ld a, [de]
    ld sp, hl
    ld d, [hl]
    jp $e16c


    or l
    ld a, [bc]
    cp a
    ld d, l
    ld d, a
    and a
    or h
    adc e
    db $e3

jr_00d_5074:
    adc d
    cp l
    ld d, c
    and b
    and b
    add c
    ld e, a
    adc [hl]
    ld [$79bf], a
    rst $28
    ld l, b
    adc $72
    dec h
    daa
    sub b
    sub [hl]
    sbc [hl]
    ld h, h
    add hl, hl
    cp e
    sbc l
    ld [hl], b
    ld b, h
    ld c, c
    add hl, hl
    ld a, a
    rst $20
    ld h, $66
    add d
    ld e, h
    ld c, l
    rst $20
    dec e
    db $e4
    ld b, c
    ld h, b
    adc d
    ld c, e
    jr z, jr_00d_50e8

    ld sp, $72cb
    ld c, [hl]
    ld l, c
    sub b
    sub $a7
    inc h
    db $ec
    inc d
    sbc c
    inc [hl]
    inc l
    adc h
    ld [hl], c
    ld l, a
    ld sp, hl
    inc [hl]
    add hl, hl
    ld [$b244], sp
    ld c, h
    ld c, $9a
    rst $18
    jp nz, $519c

    add a
    ld a, [de]
    cp a
    db $e4
    ld a, b
    jr nz, jr_00d_5061

    or d
    sbc c
    rst $10
    db $e4
    ccf
    sub b
    sbc h
    cp h
    ld l, e
    ld e, a
    db $e4
    ld h, c
    ld a, [bc]
    ld h, d
    and b
    rst $20
    inc sp
    db $f4
    add e
    and c
    ld a, [bc]
    ld d, e
    rrca
    ld sp, hl
    ld [hl], c
    or a
    pop bc
    ld de, $8aff
    cp a
    sub c
    rst $38
    sbc h
    sub [hl]

jr_00d_50e8:
    sub a
    rst $38
    adc l
    cp $98
    and d
    sbc h
    inc e
    ld [$ff2f], sp
    and e
    ld a, a
    cp $b8
    ld a, a
    rst $00
    ld b, l
    rst $10
    rst $28
    rst $38
    db $fd
    ccf
    pop af
    rst $00
    ld sp, $178c
    rst $38
    rst $38
    rst $38
    ldh [$9c], a
    ld [hl], c
    xor h
    dec e
    rst $38
    rst $38
    cp $73
    jp nz, $c399

    ld d, h
    ld c, l
    and a
    ld a, [de]
    ld h, c
    jr jr_00d_5169

    db $fd
    dec e
    ld [hl], b
    dec h
    db $e3
    adc h
    reti


    pop hl
    jp nz, Jump_000_3884

    add $a0
    ld b, h
    cp c
    push de
    ld d, h
    ldh [rOBP0], a
    ld b, c
    sbc a
    xor d
    ld b, d
    dec [hl]
    ld e, a
    inc b
    dec [hl]
    ld a, e
    ld d, l
    adc l
    ld l, e
    rst $28
    rst $18
    ldh a, [rSVBK]
    add e
    dec [hl]
    ld h, c
    ld a, [$a989]
    call nc, Call_00d_6ad5
    scf
    and e

Jump_00d_5148:
    ccf
    dec sp

Call_00d_514a:
    sbc [hl]
    ld c, [hl]
    db $db
    add d
    dec sp
    ld d, [hl]
    sub e
    add [hl]
    inc [hl]
    ld l, b
    ld de, $0442
    or [hl]
    inc [hl]
    sub l
    ld h, a

jr_00d_515b:
    ret z

    or a
    add sp, $53
    add c
    ld b, d
    jp Jump_00d_67f8


    di
    add c
    ld h, $31
    and e

jr_00d_5169:
    pop hl
    ld [hl], a
    xor d
    or l
    ld d, h
    sbc h
    add hl, hl
    ld [$0a36], sp
    sbc h
    dec c
    inc b
    ld [hl], $e8
    dec a
    rlca
    sbc d
    ld l, e
    dec c
    rla
    ld b, c
    ldh [$9b], a
    ld b, a
    inc d
    ld l, d
    add h
    rst $00
    ld d, e
    dec e
    ld a, [c]
    and a
    ld [hl], d
    rst $00
    ld l, d
    ld c, d
    ld [$092a], sp
    rst $00
    inc [hl]
    add h
    ld de, $5410
    xor e
    sbc l
    db $fc
    ld a, l
    jr nz, jr_00d_5203

    cp h
    rla
    sbc a
    ld c, a
    cpl
    ld [$f214], sp
    rra
    dec bc
    sub h
    rst $20
    ld [hl], h
    dec e
    ld [hl+], a
    jp nc, $b420

    add a
    adc $85
    inc b
    ld [de], a
    ld d, l
    add l
    xor a
    ld a, [bc]
    dec l
    inc [hl]
    ld e, a
    ld b, [hl]
    and h
    inc h
    add a
    xor b
    xor d
    add hl, hl
    add sp, -$4b
    ld a, [$4c34]
    call nc, $ac85
    push bc
    add sp, -$2a
    inc b
    cpl
    ld [c], a
    sbc b
    jr z, jr_00d_515b

    dec l
    add hl, hl
    ld c, l
    sub b
    adc h
    call nc, $9968
    ld h, b
    adc d
    cp l
    ld d, d
    ret c

    inc hl
    dec d
    add d
    dec b
    dec b
    dec l

jr_00d_51e6:
    ld [hl-], a
    xor e
    rst $38
    cp l
    jr nc, @+$7b

    ld b, l

Jump_00d_51ed:
    ld c, c
    adc c
    ld c, [hl]
    rlca
    db $eb
    ld e, a
    rra
    ret z

    and l
    ld b, d
    add d
    add [hl]
    jr c, jr_00d_527a

    or $8b
    cp h
    jr nz, jr_00d_525e

    ld b, a
    and d
    ld d, h

jr_00d_5203:
    rst $10
    or d
    ld d, [hl]
    xor c
    jr nc, @-$5a

    ld e, $a7
    ld l, h
    call Call_000_16fa
    adc h
    inc hl
    rla
    add [hl]
    add [hl]
    call c, $bcca
    jr jr_00d_51e6

    pop de
    ld [hl], b
    ld d, d
    inc d
    sub l
    ld c, h
    xor b
    ld d, e
    ld b, h
    ld l, a
    add l
    ld d, c
    ld d, l
    and $8c
    ld l, b
    ld h, e
    ld b, [hl]
    ld [hl-], a
    xor a
    ld [$8c5b], a
    jr z, jr_00d_5295

    ld [hl], $0b
    ld c, l
    sbc l
    db $d3

Call_00d_5237:
    ld a, [de]
    ld hl, $5830
    xor e
    ld c, h
    ld d, a
    adc b
    or h
    xor d
    dec d
    dec bc
    ld e, c
    sbc $30
    xor c
    ld hl, $14e8
    ld e, h
    or l
    ld sp, hl
    ld a, b
    sbc d
    ld hl, $29d2
    or $88
    add [hl]
    inc sp
    adc c
    adc h
    xor [hl]
    dec bc
    ld hl, sp+$56
    cp l
    ld [hl], l

jr_00d_525e:
    add c
    ld d, e
    jp nz, $ea55

    rst $38
    ldh [$9e], a
    ld a, [bc]
    add hl, hl
    rst $20
    and b
    pop de
    db $e4
    xor b
    jr c, jr_00d_5296

    ld b, d
    ld b, d
    ld d, l
    inc h
    ld e, a
    sbc $12
    ld [hl], h
    ld l, b
    ld a, [hl+]
    ld d, d

jr_00d_527a:
    adc l
    sub c
    inc e
    add sp, $43
    rst $38
    ld a, [$df44]
    sbc e
    ld h, [hl]

Call_00d_5285:
    jr z, jr_00d_52cc

    rst $38
    rst $38
    jr z, jr_00d_527a

    jp hl


    add hl, hl
    ld a, [de]
    ld a, [$6752]
    rst $38
    ld hl, sp+$5a
    ret nc

jr_00d_5295:
    reti


jr_00d_5296:
    dec bc
    add a
    rst $38
    and $ef
    rst $38
    sbc d
    inc [hl]
    ld b, a
    add a
    rst $38
    sbc b
    ret nz

    adc a
    rst $38
    pop de
    and d
    sub c
    ld a, b
    scf
    db $fd
    ld a, [de]
    call nz, $8ca6
    jr c, jr_00d_530f

    ld a, $1f
    ld b, a
    inc c
    ld l, d
    sub c
    add [hl]
    db $10
    rst $38
    sbc h
    or c
    or l
    jr @+$41

    ld e, c
    call nc, $a986
    and a
    cp $b8
    add hl, hl
    and h
    ld e, h
    rst $38
    cp $0a

jr_00d_52cc:
    ld e, e
    dec b
    add a
    ld e, [hl]

jr_00d_52d0:
    ld [hl], b
    xor [hl]
    rra
    rst $38
    rst $08
    rst $38
    inc bc
    ld de, $1471
    ld h, a
    db $10
    cp b
    ld a, a
    rst $38
    ccf
    pop af
    add hl, hl
    inc e
    ld a, [bc]
    ld d, $65
    db $10
    cp $df
    db $fc
    rst $18
    add $12
    rst $38
    ld a, [de]
    ld b, h
    rst $38
    db $ed
    ld [hl], b
    ld a, [hl]
    ld a, [$ff60]
    ld [$1565], a
    ld e, a
    ld d, c
    ld d, a

Jump_00d_52fd:
    cp $94

Call_00d_52ff:
    rst $38
    rlca
    ld a, [$ff75]
    pop hl
    ld c, e
    pop af
    dec bc
    ld a, [hl]
    ld e, h
    add h
    ld l, d
    sub c
    ld a, [hl]
    adc h

jr_00d_530f:
    pop af
    ccf
    db $e3
    dec e
    sub c
    ld d, l
    ld a, d
    ld b, l
    ld e, $3c
    add h
    ld l, b
    ld b, h
    and l
    ret nc

    sub l
    ld d, e
    dec h
    ld a, h
    sub l
    ld d, h
    jr nz, jr_00d_52d0

    xor a
    ld c, c
    ld a, d
    adc h
    ld a, [hl+]
    inc [hl]
    ld b, d
    ld [hl+], a
    db $e4
    jp nz, $44d3

    adc c
    ld a, l
    ld b, d
    ld c, d
    ld l, l
    jr nc, @+$67

    xor a
    ld a, [hl+]
    and d
    ld e, d
    dec bc
    jp nc, $1716

    xor b
    rla
    adc e
    ld e, e
    db $dd
    ld a, a
    ld d, h
    ld hl, $8cc6
    ld a, b

jr_00d_534c:
    adc b
    ld h, c
    xor d
    db $d3
    add d
    jr c, jr_00d_537b

    db $dd
    ld c, [hl]
    ld [$b5e0], sp
    xor d
    and l
    ld c, h
    sub d
    inc de
    add hl, bc
    ld c, h
    ld a, h
    cp c
    cp [hl]
    inc sp
    and l
    ld b, d
    ld hl, sp+$5c
    jr nz, jr_00d_534c

    sub e
    add d
    db $dd
    add sp, -$1b
    adc d
    xor b
    di
    ld h, h
    and h
    inc h
    and [hl]
    ld c, b
    ld sp, $a648
    rla
    cp d

jr_00d_537b:
    ld d, d
    adc e
    ld [de], a
    sbc d
    ccf
    push hl
    sbc $e5
    ld b, [hl]
    ld c, a
    rst $38
    ld de, $d90e
    cp e
    db $fd
    ld c, $0b
    ccf
    dec de
    ld a, a
    ld b, h
    xor h
    cp a
    inc e
    db $10
    and d
    add a
    ld d, c
    pop de
    ld a, [hl]
    sbc h
    add hl, hl
    and a
    cp $75
    ccf
    cp $61
    ld a, [de]
    ld [$5f0d], a
    sbc b
    ld a, $a6
    xor l
    ld d, h
    push hl
    inc hl
    inc b
    ld [hl], d
    and h
    jr c, jr_00d_53f9

    ld e, a
    ld b, a
    add $80
    ld h, [hl]
    cp d
    dec d
    inc a
    dec d
    ld c, h
    xor d
    cp c
    dec sp
    ld a, [hl]
    cp l
    ld b, l
    ld l, b
    add [hl]
    ld l, l
    add hl, sp
    sub a
    rst $30
    ld [hl+], a
    cp d
    sub d
    ld d, d
    ld d, h
    sub l
    ei
    ld c, h
    ld a, a
    ld [hl-], a
    ld a, e
    ld sp, $16a2
    sbc b
    ld l, d
    ld [hl-], a
    adc h
    sub h
    and [hl]
    adc h
    ld [hl+], a
    ld [hl+], a
    ld l, a
    ld [hl-], a
    and e
    dec b
    add hl, hl
    inc b
    add l
    ld c, e
    sub l
    add sp, -$36
    sbc b
    push de
    ld e, b
    sub a
    add $51
    ld h, e
    ld e, e
    xor l
    inc [hl]
    ld d, b
    adc b
    and d
    rst $18
    ld c, b

jr_00d_53f9:
    ld d, e
    ld e, e
    cp $92
    ld a, [de]
    adc b
    adc l
    add hl, hl
    or l
    ld c, l
    ld d, a
    jp hl


    ld d, e
    ld [hl], l
    add e
    jp c, $f381

    rla
    add sp, $1a
    ld [hl+], a
    sub e
    daa
    and [hl]
    jr nc, jr_00d_5468

    rst $00
    push bc
    adc h
    and e
    ld b, $18
    pop bc
    ld b, d
    ld sp, $7453
    pop de
    ld c, b
    ld e, h
    sub h
    or l
    ld [hl+], a
    dec [hl]
    adc e
    or l
    ld a, e
    add sp, $21
    ld c, h
    sub c
    ld c, h
    sbc d
    adc h
    ld l, d
    xor l
    ld a, [hl+]
    ld sp, $42bb
    ld c, c
    ld e, b
    dec h
    dec [hl]
    ld d, b
    ld d, b
    ld d, b
    ld d, e
    dec [hl]
    rlca
    db $fd
    cp $34
    ld a, [hl]
    xor d
    sub $8d
    ld d, l
    xor b
    jr nz, jr_00d_54aa

    and e
    ld c, $32
    cp h
    jp c, $f926

    ld e, c
    adc c
    adc h
    sub h
    db $ec
    or h
    dec l
    ld a, [bc]
    dec h
    and h
    inc d
    ld d, h
    add sp, $52
    ld l, h
    ld [de], a
    ld d, c
    ld c, b
    ld e, c
    adc [hl]
    ld d, a
    adc h

jr_00d_5468:
    ccf
    push de
    rst $30
    ld a, [$758e]
    ld d, l
    ld e, a
    and c
    xor d

Jump_00d_5472:
    and e
    add hl, de
    ret nc

    sbc [hl]
    ld a, [hl+]
    ld h, l
    ld a, [hl]
    and a
    add d
    cp b
    ld [hl+], a
    add h
    rla
    sbc $09
    adc $84
    ld d, l
    ld a, [$3031]
    ld b, b

jr_00d_5488:
    jp hl


    add d
    and a
    scf
    sub [hl]
    and h
    ld b, e
    sub b
    cp a
    ld sp, hl
    call $d197
    db $76
    rra
    rst $38
    ld b, a
    ld l, $5c
    ld d, d
    ld c, h
    rra
    ld sp, hl
    or d
    ld h, l
    dec d
    db $10
    sub d
    sub c
    dec l
    dec e
    ld l, c
    ld l, h
    add hl, hl

jr_00d_54aa:
    add a
    jp hl


    ld c, c
    or h
    ld d, l
    adc h
    ld l, a
    rst $38
    sub b
    and [hl]
    add sp, $47
    dec hl
    ld [$f9bf], a

Call_00d_54ba:
    and h
    ld d, d
    rrca
    xor l
    jp hl


    ld l, a
    rst $38
    call c, $66ce
    sub d
    rst $30
    rst $38
    rst $30
    sub h
    rst $30
    pop af
    add d
    sbc b
    and h
    cpl
    add a
    rst $38
    rst $28
    dec d
    add h
    ret


Call_00d_54d5:
    ld a, [hl+]
    rra
    jr jr_00d_54fe

    ld a, a
    rst $18
    ld hl, sp+$66
    ld [hl-], a
    xor [hl]
    rst $38
    pop hl
    jr jr_00d_5488

    ld e, a
    db $eb
    ld b, [hl]
    jr z, jr_00d_550c

    or a
    rst $38
    sbc h
    ld [hl], l
    ld b, h
    and l
    ld c, [hl]
    call nz, $d73f
    dec de
    jp nz, $8c92

    ld h, b
    cp $b5
    rst $18
    xor b
    and [hl]
    or c
    ld c, c

jr_00d_54fe:
    ld sp, $f16f
    inc sp
    ld a, a
    ld sp, hl
    ret


    inc c
    add h
    ld d, l
    sub a
    dec b
    rst $38
    rst $00

jr_00d_550c:
    ld c, d
    ld e, [hl]
    ld d, e
    add sp, $7f
    rst $20
    ld [hl], e
    or c
    ld d, a
    rst $08
    jp nc, $bf76

    ret c

    and h
    and e
    dec e
    ld d, d
    ld b, l
    ld h, c
    inc e
    ld h, b
    ld b, h
    or d
    ld d, l
    ld c, h
    sub l
    di
    ld e, d
    xor d
    db $f4
    sub a
    xor b
    pop de
    ld hl, sp-$3e
    adc b

jr_00d_5531:
    cp c
    ld a, [hl-]
    ld e, $57
    xor [hl]
    ld c, h
    sub h
    or a
    ld [$99a4], a
    inc sp
    ld d, d
    ld e, $3a
    xor d
    or l
    ld c, [hl]
    add a
    ld l, d
    xor e
    ld c, [hl]
    ld d, a
    call z, $e468
    ld [hl], c
    ld d, l
    ld c, b
    adc [hl]
    ld c, d
    ld h, d
    xor b
    pop bc
    ld hl, $b432
    or l
    ld l, $6f
    adc l
    ld d, l
    xor b
    ld hl, $8370
    adc [hl]
    ld a, e
    ld [hl], a
    and e
    xor [hl]
    and e
    call $a299
    sbc c
    jr nz, jr_00d_5531

    pop de
    ld [hl], d
    ld d, d
    adc e
    add hl, de
    ld hl, $a916
    ld [hl], l
    cp c
    jp $c4ff


    cpl
    ld [hl], $65
    dec d
    db $fd
    inc de
    ccf
    ld sp, $d1c0
    sub a
    rst $00
    ld b, $09
    add hl, bc
    add a
    inc e
    ld de, $9256
    rst $00
    ld [bc], a
    ld h, e
    ld sp, hl
    call z, $fe97
    ld h, c
    ld a, [de]
    xor b
    ld [hl-], a
    db $eb
    jr jr_00d_55d8

    and [hl]
    ld [hl], b
    ld l, l
    db $d3
    sub h
    adc h
    ld de, $12c1
    sub b
    pop hl
    dec e
    ld a, l
    rra
    ld a, [de]
    ld d, l
    cp b
    sub h
    inc d
    ldh a, [$9e]
    ld [$3bd5], a
    sbc $a4
    ld l, e
    ld c, [hl]
    ret z

    ld e, h
    add hl, hl
    ret nc

    db $e3
    or d
    push af
    push af
    ld [$ad53], sp
    ld [hl], b
    and $a9
    ld c, [hl]
    and a
    and a
    and d
    ld de, $396d
    call nc, $b417
    ld l, l
    or [hl]
    db $d3
    sub c
    ld [$1fac], a
    rlca
    or h
    dec d

jr_00d_55d8:
    add hl, sp
    sub h
    and l
    rrca
    adc b
    ld c, [hl]
    db $76
    dec bc
    rlca
    and b
    cp a
    add l
    add hl, sp
    ld h, b
    ld l, d
    add hl, hl
    ldh [$50], a
    ld b, c
    jr c, @-$17

    ld [hl+], a
    dec b
    jr jr_00d_5669

    db $10
    ld c, [hl]
    ld h, l
    ld c, c
    or c
    ld d, [hl]
    add c
    ld a, [hl-]
    daa
    ld [$88a0], a
    ld h, e
    and l
    ld sp, hl
    add sp, $51
    adc [hl]
    xor c
    db $fc
    ld [hl], l
    ld b, l
    dec sp
    dec d
    ld a, h
    ld h, c
    ld c, [hl]
    rst $00
    adc b
    and c
    ld h, e
    cp d
    rst $18
    ld [$2738], a
    or h
    call nz, $8527
    ld a, [bc]
    ld d, $1e
    sbc l
    db $fc
    add d
    ld c, l
    sbc l
    db $f4
    ld e, l
    and a
    ld a, d
    dec c
    cp $a7
    ld d, d
    ld b, h
    sub e
    push de
    jp hl


    sub $de
    add l
    add sp, -$22
    sbc h
    xor h
    ld de, $bf0f
    ld [$73da], a
    ldh [rIE], a
    ld e, a
    rst $38
    or [hl]
    ld [hl], d
    cp a
    ld a, $4f
    jp nz, Jump_00d_72fe

    inc a
    ld c, [hl]
    ld b, e
    db $10
    rst $38
    dec e
    ccf
    and c
    ld a, d
    rst $38
    rst $00
    ld c, a
    rst $38
    cp a
    rst $38
    rst $00
    ld l, l
    ld d, h
    ld e, $11
    ret c

    sbc b
    ld a, [hl]
    db $76
    and e
    ld h, h
    ccf
    dec e
    or h
    ld b, h
    add a
    rst $00
    ld [hl], h
    add [hl]
    pop hl

jr_00d_5669:
    ld b, a
    or b
    ld b, h
    ld a, $49
    db $f4
    db $eb
    ld h, b
    xor $4e
    ld [hl], a
    and b
    pop hl
    db $f4
    push hl
    ld d, a
    db $fc
    adc e
    adc $3d
    ld b, d
    sub h
    add a
    ld [$a9e2], sp
    or b
    ld [hl], c
    di
    sub d
    and a
    add d
    rlca
    di
    sub [hl]
    or a
    inc hl
    ei
    adc [hl]
    ld c, b
    adc l
    cp l
    adc $a6
    ldh a, [$8e]
    add a
    dec c
    ld hl, sp-$16
    and e
    db $e3
    rst $30
    ret


    xor c
    rst $18
    reti


    db $db
    ld [hl], l
    ld c, c
    jp z, Jump_000_358b

    sub c
    add hl, hl
    push bc
    rrca
    ld [bc], a
    sub a
    inc e
    sub b
    ld c, d
    ld [hl], l
    ld a, b
    scf
    dec e
    ld a, h
    cp c
    add [hl]
    ld [hl], e
    ld c, d
    sub b
    or h
    ld [hl], e
    xor e
    ld hl, sp+$67
    ld c, h
    add l
    ld b, a

Jump_00d_56c3:
    ld l, h
    ld a, h
    ld [hl], b
    ld h, [hl]
    ld a, $45
    dec a
    inc b
    db $f4
    ld h, e
    rst $08
    ld h, e
    db $e4
    sbc l
    ld [hl-], a
    ld h, e
    dec a
    add hl, sp
    ld e, a
    di
    inc h
    and h
    ld [$ff7f], a
    ld c, e
    adc e
    or h
    and $7f
    add d
    dec bc
    ld a, [bc]
    ld d, c
    ld e, b
    cp d
    ld a, [de]
    scf
    ld a, a
    ret z

    ld d, c
    adc c
    and b
    ld b, d
    ld l, $8e
    daa
    db $fc
    add l
    ld sp, $0845
    cp d
    adc [hl]
    rra
    ld sp, hl
    dec h
    adc c
    ld c, b
    ld b, [hl]
    inc d
    ld d, h
    db $e3
    ld h, d
    ld a, [hl+]
    adc c
    ld h, c
    ld h, d
    ld e, a
    dec b
    ld d, h
    ld [c], a
    ld c, h
    pop hl
    ld h, d
    rst $38
    ld b, e
    xor e
    ld c, [hl]
    add hl, de
    ld c, b
    ld e, b
    ld a, [hl+]
    jr nc, jr_00d_5797

    ld h, e
    xor d
    and d
    inc de
    rla
    cp $3c
    sub a
    cp $3c
    ld d, h
    db $10
    ld a, a
    ld h, e
    rla
    and e
    or d
    rst $38
    di
    rla
    add sp, -$14
    ld d, a
    cp e
    dec l
    rst $38
    ld c, [hl]
    add l
    cp $aa
    xor c
    daa
    cp $4e
    ld d, l
    ld a, [$d135]
    rst $38
    ld c, [hl]
    ld c, a
    and e
    adc d
    jp nz, $bde4

    sbc $a7
    sub [hl]
    cp a
    ld b, $79
    rrca
    ld b, b
    ldh [$a7], a
    adc d
    ldh a, [$bf]
    pop hl
    ld e, $13
    ret nc

    cp a
    ldh a, [$39]
    ldh [$3c], a
    ld b, e
    rst $38
    sbc d
    ld a, [hl+]
    ld [hl], d
    cp h
    ld c, $17
    rst $38
    dec bc
    sub h
    ld a, [$c409]
    ldh a, [$3f]
    pop hl
    db $fc
    ld c, d
    cpl
    rst $38
    rst $20
    dec e
    inc bc
    rst $38

jr_00d_5775:
    db $e3
    dec d
    ld c, a
    ld de, $717c
    ld d, e
    rst $38
    cp d
    ld h, d
    add $14
    ld sp, $ffbd
    pop de
    ld sp, $1171
    ld [hl], h
    ld [hl], b
    rst $18

jr_00d_578b:
    ld sp, hl
    or d
    ld c, h
    ld e, l
    inc e
    inc sp
    jp $c42a


    cp c
    ld [hl], b
    and d

jr_00d_5797:
    sbc h
    db $76
    ld l, b
    pop af
    adc l
    ld a, [bc]
    ld [hl], d
    jp nc, $d160

    or d
    dec l
    daa

jr_00d_57a4:
    inc e
    ld a, [bc]
    add h
    ld [hl], b
    jr nz, jr_00d_57a4

    ld [hl], e
    ld b, h
    ld b, d
    sbc d
    inc sp
    rst $38
    sbc l
    ld l, [hl]
    ld h, [hl]
    rst $08
    rst $38
    rst $20
    ld c, e
    ret nz

    sbc b
    xor a
    rst $38
    rst $38
    rst $00
    dec hl
    jp nz, $77c6

    rst $38
    db $fc
    ld [hl], d
    inc a
    dec c
    ld a, [bc]
    xor d
    xor c
    scf
    rst $38
    sbc h
    ld l, a
    inc [hl]
    or l
    jr jr_00d_5775

    rst $38
    rst $00
    dec e
    db $db
    ld b, [hl]
    call nc, $f98f
    ret


    ld d, c
    rlc l
    add $00
    ld b, h
    dec sp
    inc d
    db $ed
    ld h, e
    and c
    ld d, c
    ld h, e
    and c
    pop af
    sub b
    sub e
    sbc e
    and d
    ret nc

    sub e
    adc c
    ld hl, $9030
    adc [hl]
    ld b, $26
    ld c, h
    inc hl
    add [hl]
    jr nc, jr_00d_578b

    ld e, a
    inc b
    ld [$eee8], a
    ld c, d
    ld c, [hl]
    adc d
    ld [$e958], sp
    and [hl]
    ld h, e
    xor a
    ret c

    ld a, [$d69d]
    ret


    ret c

    rst $00
    db $76
    ld [hl], l
    dec [hl]
    daa
    ld c, d
    push bc
    ld c, d
    ld [hl], d
    ldh [$c9], a
    db $76
    sbc h
    ld e, a
    ld de, $d125
    jp Jump_00d_4918


    ld c, d
    ld [hl], b
    add hl, hl
    add d
    ld [hl], h
    add hl, hl
    ld l, $96
    sbc h
    ld d, [hl]
    add l
    inc c
    ld c, e
    inc e
    ld [hl], l
    ld a, [c]
    jp nz, Jump_000_3ac7

    sub d
    rst $00
    dec a
    ldh a, [$b1]
    rst $10
    ld d, h
    ld a, c
    add b
    ld [hl], a
    xor $04
    push af

Jump_00d_5843:
    dec hl
    cp $04
    ldh a, [rHDMA4]
    db $dd
    rst $38
    rst $38
    or l
    ld d, l
    inc [hl]
    ld e, a
    call nc, $bb9f
    ld c, l
    ld l, [hl]
    ld l, a
    db $fd
    call c, Call_000_0723
    add sp, -$54
    ld e, e
    and b
    ld l, b
    set 4, l
    rlca
    rst $38
    rst $38
    add hl, de
    dec [hl]
    sbc b
    dec de
    ld l, $a3
    ld a, [hl+]
    ld c, b
    ld l, [hl]
    xor $2a
    ld d, c
    and b
    or b
    ld b, c
    ld l, l
    jp nc, $8b9a

    ld a, l
    ld b, c
    ld l, d
    rrca

jr_00d_587a:
    dec b
    jr nc, jr_00d_587a

    ld [$3fac], sp
    ldh a, [rSCX]
    push hl
    ld l, $ff
    ld [$aefa], a
    ld d, l
    ld b, d
    ld [hl], $f0
    rst $00
    and l
    ld c, [hl]
    adc e
    call nc, $e122
    adc c
    ld h, a
    or a
    add sp, -$14
    xor b
    and [hl]
    pop hl
    add l
    ldh [$7a], a
    inc a
    ld a, [hl+]
    ld d, $a8
    ld d, l
    adc b
    and e
    ret


    xor a
    ld [$9428], sp
    ld hl, $2453
    rst $20
    and d
    rra
    jp nc, $1b7a

    ei
    ld e, a

Jump_00d_58b5:
    ld b, c
    xor b
    push hl
    and c
    ld a, b
    jp z, $8558

    rlca
    add hl, bc
    db $f4
    and $51
    and c
    ld e, [hl]
    add c
    inc sp
    ld d, d
    dec a
    ld b, d
    adc [hl]
    ld b, l
    ld a, b
    ld a, [hl]
    ld a, [bc]
    add c
    inc [hl]
    cp [hl]
    sub c
    ld d, e
    sub [hl]
    adc d
    cp d
    adc b
    adc h
    ld l, d
    add c
    ld c, a
    dec b
    ld hl, sp-$6c
    add $d0
    ld d, c
    or l
    ld a, [hl-]
    rla
    ld hl, sp-$5c
    pop de
    ld d, c
    and b
    adc e
    ld a, l
    ld b, l
    ld c, d
    ld e, a
    ld a, [$5229]
    ld d, h
    jp $52f5


    rst $28
    xor $a9
    ld a, a
    add sp, -$3a
    add hl, bc
    ld b, e
    xor $95
    add d
    rla
    db $fc
    and l
    call c, Call_000_0f2f
    db $e4
    ret


    add d
    add c
    ld h, $52
    and c
    ld a, d
    dec hl
    cp $c1
    cp l
    rst $38
    jp nc, $2fd2

    db $fd
    ld c, b
    or $7d
    ld a, l
    add hl, hl
    ld e, d
    ld h, a
    rst $38
    rst $38
    jp z, $eb4c

    ld a, [$ad2a]
    ld hl, $67fe
    rst $38
    rst $38
    rst $38
    ld c, a
    ld a, [bc]
    xor a
    rst $38
    rst $38
    xor $ee
    pop af
    adc [hl]
    ld [$ef9e], a
    ld [hl], a
    xor d
    xor d
    or [hl]
    inc a
    rlca
    jp c, $d0a3

    db $ec
    and a
    xor e
    inc hl
    ld c, d
    ld a, d
    ld e, d
    ld d, l
    ld a, [hl+]
    ld c, d
    ld l, b
    add h
    and [hl]
    sub c
    or d
    inc c
    sub l
    ld d, h
    add hl, bc
    add e
    add l
    sub c
    ld h, [hl]
    ld c, l
    sbc d
    add hl, sp
    add hl, bc
    sbc d
    ld e, h
    ld h, c
    inc d
    or l
    ld d, l
    sbc c
    ret


    ld a, [bc]
    xor c
    add h
    and l
    add sp, -$3c
    or c
    ld c, b
    ld d, [hl]
    ld h, l
    ld d, a
    jp z, Jump_00d_601b

    xor c
    ld e, $0a
    jp $c410


    call nc, $980c
    pop hl
    ld d, c
    inc d
    ld c, l
    ld de, $1151
    ld c, b
    call nz, $0d52
    ld hl, $389d

Jump_00d_5989:
    dec h
    dec a
    ld b, h
    pop bc
    ld c, d
    ret c

    ld c, b
    ld b, a
    ld h, h
    ld [$4550], sp
    jp nc, $30b0

    ld b, a
    add l
    ld h, d
    push bc
    xor h
    ld b, h
    ld a, c
    ld d, h
    or c
    ld de, $422c
    ld a, b
    ld e, b
    ld b, d
    call nc, $8495
    inc de
    ld h, b
    and b
    and a
    ld e, [hl]
    inc sp
    inc e
    ld d, [hl]
    inc e
    ld d, $fc
    ld [hl], d
    and e
    ld b, h
    ld [hl+], a
    ret nz

    sbc b
    jp nz, $8284

    db $f4
    ld [hl], d
    pop bc
    call nz, Call_00d_54d5
    sub a
    sub e
    ld h, e
    ld [hl], b
    daa
    ld [hl], l
    ld d, h
    inc d
    ld d, e
    sbc b
    ld [hl], c
    ldh [$bf], a
    ld a, [bc]
    sub e
    add hl, de
    ld hl, $d649
    cp a
    db $10
    and l
    add hl, hl
    ld [de], a
    jr z, jr_00d_5a24

    sub b
    ld h, $8b
    rst $38
    db $10
    ret nz

    and h
    jr z, @+$56

    dec hl
    jp hl


    and l
    add d
    ld e, $42
    rst $38
    pop de
    ld d, b
    db $e3
    pop hl
    ld a, b
    jr z, jr_00d_5a59

    cp c
    sbc d
    xor [hl]
    and c
    rst $38
    ld b, [hl]
    inc c
    jr c, jr_00d_5a4f

    scf
    ld a, [$a690]
    ld a, l
    ld b, e
    push af
    add hl, de
    and l
    ld [hl], l
    ld b, b
    sub c
    db $e3
    ld d, a
    ld h, [hl]
    ld a, [hl+]
    inc e
    add $e9
    and h
    dec c
    inc e
    cpl
    di
    ld e, $8d
    ld b, [hl]
    ld c, d
    xor d
    and h
    ld b, a
    ld a, a
    ld d, b
    ld a, [hl+]
    dec d
    ld c, c
    adc l
    ld b, a

jr_00d_5a24:
    add d
    db $f4
    ld b, h
    ld a, d
    nop
    ld b, h
    cp c
    ld d, l
    cp e
    adc h
    sub e
    dec [hl]
    rst $38
    ld c, $ec
    add $b4
    or a
    xor a
    ld e, d
    rst $38
    ld sp, $bda0
    ld d, a
    xor a
    ei
    db $e3
    ld e, d
    rlca
    xor d
    xor e
    ld a, [hl]
    jr jr_00d_5a9a

    ld a, [hl-]
    adc h
    and d
    ld d, b
    ld h, h
    ld [$6476], a

jr_00d_5a4f:
    ret


    db $e3
    scf
    push hl
    sbc a
    dec l
    ld hl, sp+$13
    rla
    sbc e

jr_00d_5a59:
    rst $18
    ld a, [c]
    rst $18
    or $4a
    and b
    jp $fcff


    sub $bd
    ld a, [de]
    sbc a
    db $db
    cp h
    ldh [$a2], a
    xor $fe
    ld [hl], e
    add c
    ld c, b
    add $04
    dec hl
    db $d3
    add [hl]
    ld hl, sp+$5a
    ld l, $39
    ld a, [hl+]
    inc a
    db $fd
    ret nc

jr_00d_5a7c:
    xor d
    sbc h
    db $eb
    jp c, Jump_00d_62aa

    sbc e
    ld a, [hl-]
    dec d
    ld a, [hl]
    ld h, e
    ld hl, $4eca
    adc l
    ld e, b
    call nc, $2265
    pop bc
    call nc, Call_000_3408
    ld c, e
    sbc c
    call c, Call_000_1465
    ld a, [c]
    ld l, b

jr_00d_5a9a:
    jp z, Jump_000_2dc6

    rst $08
    ld a, [de]
    ld b, [hl]
    ld l, e
    inc sp
    add $59
    add hl, bc
    adc e
    dec sp
    add h
    ld h, a
    sub e
    dec h
    xor l
    ret


    bit 1, c
    ld d, $ae
    jr @+$2b

    rst $00
    ld b, e
    dec c
    ld d, e
    pop bc
    sbc h
    jr jr_00d_5a7c

    inc b
    and h
    jp nc, Jump_00d_6271

    pop af
    db $db
    ld e, $88
    ld d, l
    cp [hl]
    sbc l
    db $f4
    rra
    ld c, a
    adc d
    add c
    ld a, [bc]
    ld hl, $cb4e
    jr nc, @-$42

    inc h
    ld [$aa76], a
    ld d, [hl]
    ld [hl], h
    ldh [$4c], a
    ld a, [de]
    ld hl, $0afd
    db $d3
    add d
    and l
    db $dd
    ld d, h
    ld l, b
    db $10
    and c
    adc [hl]
    cpl
    inc [hl]
    ld d, b
    add c
    ld c, [hl]
    ld b, l
    ld l, e
    cp d
    and d
    cpl
    ldh [$8e], a
    ld c, b
    pop bc
    call z, $bd59
    ld a, [hl-]
    ld l, [hl]
    xor d
    and c
    ld [hl], b
    sub e
    xor d
    ld sp, $8ead
    jp z, $8f22

    ld d, $3c
    ld c, e
    ldh [$be], a
    ccf
    ld [bc], a
    sbc a
    ld d, b
    sbc [hl]
    ld b, [hl]
    ld a, c
    ld e, $83
    rst $20
    add a
    ld d, l
    ld b, a
    add h
    cp l
    ld a, [$ce9d]
    ccf
    ld d, a
    rst $20
    dec de
    ld h, $17
    ld sp, hl
    ld e, a
    sbc h
    ld c, b
    ld h, c
    inc sp
    rrca
    ld a, [$f943]
    rst $00
    jr @+$01

    rst $38
    rst $38
    rst $00
    ld h, l
    rst $38
    rst $38
    rst $00
    add c
    ld a, [hl+]
    or [hl]
    ld a, b
    ccf
    rst $18
    sbc a
    dec d
    db $e4
    ld a, c
    ld sp, hl
    ld e, b
    ld b, h
    cp l
    ld h, l
    ld hl, $9a4e
    and b
    xor b
    ld [$7cb7], a
    add sp, $58
    push hl
    ld c, h
    inc l
    and $a9
    ld [hl], a
    ld d, l
    add hl, sp
    cp h
    db $dd
    adc l
    sub l
    xor [hl]
    ld [$5881], a
    pop hl
    adc h
    db $10
    and e
    cp d
    dec b
    ld hl, $d84e
    db $ec
    cp [hl]
    dec bc
    rst $08
    and l
    rst $18
    dec l
    ld b, h
    ld d, c
    call nc, $f9ea
    jp nc, $dbe9

    ld [bc], a
    and a
    inc de
    and d
    add d

jr_00d_5b7c:
    add hl, hl
    ld de, $91c5
    db $dd
    sbc l
    rla
    jr jr_00d_5bc7

    xor d
    sbc l
    dec hl
    rst $10
    ld e, c
    sub $c1
    add hl, hl
    db $ed
    ld b, a
    push de
    add b
    ld d, l
    cp l
    ld h, l
    ld d, b
    ld c, a
    dec b
    xor d
    ld l, [hl]
    ld c, [hl]
    or [hl]
    and c
    ld c, b
    sub b
    or h
    add sp, -$16
    and e
    ld a, $21
    ld a, a
    pop de
    ld l, [hl]
    ld a, [hl+]
    ld l, $61
    ld h, b
    or l
    rst $38
    ret


    or l
    or e
    ld h, $ad
    sbc b
    adc b
    cp c
    sub e
    dec b
    ld [hl-], a
    and b

jr_00d_5bb9:
    sub b
    pop af
    adc h
    and b
    and l
    add c
    jr nc, jr_00d_5b7c

    or $61
    and d
    rst $10
    and l
    ld [hl+], a

jr_00d_5bc7:
    add c
    ld sp, $e2af
    ld h, h
    jp $afc2


    ld b, c
    ld c, l
    rst $20
    ld d, $d4
    ld d, b
    ld a, a
    push de
    jr jr_00d_5bb9

    ld d, [hl]
    add l
    ld a, [de]

jr_00d_5bdc:
    ld [$f66b], sp
    inc b
    db $dd
    ret


    ld h, b
    ld e, c
    inc b
    ld d, c
    and b
    ld h, e
    add d
    jp nz, $89f6

    sbc d
    dec h
    adc [hl]
    ld a, [hl-]
    adc h
    push de
    ld [hl+], a
    inc a
    dec d
    ld h, $39
    cp l
    jr nc, jr_00d_5c72

    add hl, de
    adc [hl]
    sub a
    xor d
    and b
    xor c
    adc [hl]
    jp c, $aaaa

    dec a
    ld a, c
    db $eb
    daa
    adc [hl]
    rst $30
    and a
    add b
    rst $08
    cp a
    ldh a, [$27]
    ld b, d
    cpl
    rst $38
    rst $38
    add a
    push hl
    jr nc, jr_00d_5bdc

    pop hl
    dec d
    dec a
    ld a, a
    rst $38
    pop bc
    db $f4
    ld [de], a
    ld e, d
    cp b
    push bc
    ldh [$c1], a
    dec b
    ldh a, [$b1]
    db $76
    add a
    ei
    db $ec
    ld d, e
    xor b
    ld c, b
    ld a, a
    ld c, [hl]
    ld h, b
    cp h
    rla
    cp $65
    ld a, d
    cp $ff
    jp hl


    inc c
    ld a, [hl+]
    or l
    db $f4
    ld l, c
    ld a, [bc]
    push de
    rst $38
    ld [$ff37], a
    and c
    inc e
    inc a
    rst $38
    rst $38
    res 6, a
    cp $64
    xor c
    add l
    rst $38
    push af
    ldh [$fe], a
    rst $38
    add hl, de
    call nc, $fd52
    inc de
    ld a, a
    cp $9c
    or d
    ld l, c
    ld [hl], l
    ld b, [hl]
    jp z, $a9aa

    and d
    cp $9a
    ccf
    rst $38
    rst $38
    rst $38
    and [hl]
    rrca
    sbc h
    sub a
    rst $38
    rst $38
    and h

jr_00d_5c72:
    cpl
    rst $00
    dec a
    rst $38
    rst $38
    and c
    ld d, [hl]
    ld [hl], b
    or b
    cp a
    dec c
    ld e, a
    db $fc
    ld a, e
    add b
    ld b, h
    cp l
    ld c, l
    ld d, h
    db $eb
    ld [$5c82], a
    rst $20
    push de
    add l
    adc [hl]
    dec [hl]
    rst $38
    pop de
    ld h, l
    adc $06
    ld h, d
    rst $20
    add sp, -$1e
    adc h
    db $e4
    xor $47
    ld [$53e0], sp
    ld b, $68
    inc de
    adc c
    and l
    inc d
    ld d, c
    ld c, [hl]
    ld c, c
    ld e, d
    sub c
    and [hl]
    adc [hl]
    ld l, c
    ld e, h
    jr @-$13

    xor d
    ld a, $ab
    ld a, h
    xor d
    jp nc, $d229

    xor d
    inc d
    ld [hl], d
    ld [hl-], a
    xor e

jr_00d_5cbc:
    ld d, b
    ld hl, $0b9c
    ld a, [hl+]
    ld d, a
    add h
    ld [hl], c
    ld b, c
    inc bc
    dec e
    or h
    ld h, d
    rst $20
    inc e
    ld h, d
    or b
    ld b, a
    dec e
    ld a, [hl+]
    ld c, h
    dec bc
    ld [bc], a
    sbc h
    xor h
    dec a
    ld [hl], h
    ld [hl], h
    jp c, $d9f1

    rra
    ld e, d
    ld d, l
    cp b
    sub l
    inc a
    ld e, d
    xor l
    inc a
    ld a, [hl-]
    ld [hl+], a
    db $d3
    xor l
    ld a, a
    db $fd
    add hl, hl
    ld d, l
    ld c, [hl]
    scf
    and a
    and b
    ld a, [hl]
    add d
    add d
    or a
    sub l
    cp l
    ld sp, $2062
    and d
    or c
    and d
    sub b
    add sp, -$18
    ld b, [hl]
    rst $38
    rst $38
    add $55
    ld [hl], $7a
    ld a, d
    sbc h
    inc d
    cp b
    ld d, [hl]
    ld [hl-], a

jr_00d_5d0c:
    ld d, d
    daa
    add c
    ld h, $89
    ld d, b
    ld h, [hl]
    db $fd
    ld [hl-], a
    or l
    inc c

Jump_00d_5d17:
    ld hl, $8245
    ld b, l
    ld [$8653], sp
    or l
    ld e, b
    jr z, jr_00d_5cbc

    adc e
    and l
    ld c, [hl]
    ld c, c
    inc b
    ccf
    rst $38
    inc c
    add [hl]
    adc [hl]
    ld a, e
    pop bc
    xor c

jr_00d_5d2f:
    pop af
    ld e, l
    ld a, [hl-]
    xor e
    rst $38
    or [hl]
    ld hl, $014f
    ld b, l
    ld d, e
    pop bc
    and b
    ld a, d
    or e
    add $d3
    pop bc
    or [hl]
    push de
    ld d, e
    pop bc
    cp a
    ld hl, sp-$0f
    ld l, b
    xor c
    call nz, Call_000_3c9e
    ld a, c
    ld sp, $da29
    ld [$beec], a
    and h
    and a
    cpl
    inc hl
    ld l, [hl]
    db $f4
    jr z, jr_00d_5d0c

    ld b, h
    ld c, d
    sbc b
    ldh [rIE], a
    pop hl
    pop hl
    sbc $ab
    xor a
    sbc $84
    ld h, a
    rst $38
    ei
    db $ec
    jr z, jr_00d_5d2f

    jr nc, jr_00d_5dc0

    ld a, [hl]
    ld de, $f297
    dec [hl]
    inc c
    adc h
    sub d
    ld hl, sp+$46
    or l
    rst $38
    ld e, b
    ld l, e
    ld hl, sp+$20
    cp l
    rst $30
    jp nz, Jump_00d_5f9a

    xor [hl]
    rra
    cp $0f
    db $ec

jr_00d_5d8a:
    rra
    ld [$116f], a
    ld [bc], a
    dec d
    dec c
    ld b, c
    ld c, a
    rst $38
    ld b, a
    inc a
    add a
    rst $38
    ld [hl-], a
    adc h
    ld [hl], l
    ld [hl], b
    cp b
    ldh [$fa], a
    db $76
    call nz, $cc43
    rst $00
    add l
    pop bc
    add [hl]
    ld de, $40df
    sub e
    daa
    ld a, d
    add hl, hl
    push hl
    or b
    ld b, a
    add a
    ld [bc], a
    ld a, c
    ret nz

    ld b, h
    cp c
    sub l
    ld d, h
    add sp, $7b
    rst $38
    ld [$70e5], sp
    sbc d

jr_00d_5dc0:
    adc [hl]
    dec h
    ld d, h
    ld a, [hl+]
    ld [$dd58], sp
    ld a, [$0eaa]
    xor d
    scf
    ld a, b
    ret


    ld [$931a], sp
    sub c
    ld [$232c], sp
    sbc l
    adc b
    xor h
    ld [de], a
    jr @-$1c

    xor c
    ld d, $19
    adc l
    xor l
    rlca
    and b
    and [hl]
    ld b, l
    ld c, b
    ld e, b
    adc $d7
    push de
    ld h, b
    sub h
    inc hl
    adc [hl]
    xor d
    ld l, $f6
    ccf
    ld [$c99c], sp
    add hl, hl
    db $d3
    dec [hl]
    ld d, [hl]
    ld [hl], h
    jr nz, jr_00d_5d8a

    db $ec
    ld l, h
    sub b
    add l
    pop bc
    xor a
    cp $6a
    rst $38
    db $fc
    ld [hl], $85
    ld d, h
    add hl, de
    adc d
    rst $18

jr_00d_5e0b:
    rst $38
    and c
    ld a, h
    rst $18
    ld a, [$ff6b]
    ld a, [$0fa1]
    rst $38
    sbc c
    ld l, a
    db $fc
    rst $38
    ld l, h
    rst $38
    db $fc
    ld h, d
    rst $38
    rst $18
    rst $18
    and h
    ld d, l
    ld b, [hl]
    or h
    adc l
    rst $30
    dec bc
    ld a, [$dd70]
    ld e, h
    ld h, c
    ld l, c
    db $db
    inc b
    ld a, [hl]
    ld [de], a
    ld h, [hl]
    cp [hl]
    ld bc, $f354
    ld a, [hl+]
    xor l
    inc a
    ld d, a
    xor d
    ld a, [hl+]
    adc [hl]
    add l
    ld sp, $4577
    rla
    dec l
    ld c, [hl]
    rla
    cp h
    cp d
    inc hl
    ld c, c
    add l
    rlca
    ei
    ld c, l
    rst $10
    and e
    ld b, [hl]
    inc c
    ld a, $81
    ld d, b
    and h
    or l
    ld d, d
    xor c
    ld a, [c]
    sub d
    ld h, [hl]
    ld hl, $5b88
    add e
    push de
    cp d
    xor l
    scf
    ld d, c
    ld a, l
    ld [c], a
    sub a
    jp c, $bdaa

    ld [hl+], a
    ret nc

    xor e
    ret


    and b
    and l
    ld b, e
    ld hl, $de68
    jp nc, $8c16

    rra
    ld [$18bc], a
    or h
    db $10
    ld d, e
    ld a, [de]
    ld c, c
    ld e, b
    ldh [$b4], a
    sub a
    xor e
    db $ed
    jr nc, jr_00d_5e0b

    adc [hl]
    ld a, [hl]
    sbc b
    db $e3
    adc h
    inc de
    add l
    ld a, [hl+]
    push de
    rlca
    adc e
    ld e, b
    or h
    jp hl


    and d
    ld d, e
    ld a, [bc]
    sbc [hl]
    ld b, c
    adc [hl]
    add hl, sp

Call_00d_5e9e:
    ld c, b
    db $fc
    ld de, $26b3
    cp $8e
    ld e, d
    ld e, d
    add d
    adc l
    ld h, l
    ld a, h
    rst $28
    or h
    db $d3
    adc a
    ld c, $ea
    ld d, l
    ld b, c
    rst $18
    inc a
    ld d, $aa
    xor b
    ld h, $8e
    ld c, $53
    ld h, [hl]
    ld a, h
    sub a
    sub c
    sub h
    sbc $9a
    ld d, d
    sub $1f
    dec d
    ld [c], a
    inc h
    ld [hl], e
    adc d
    ld b, [hl]
    xor d
    adc d
    add e
    add sp, -$3e
    adc [hl]
    ld e, c
    ld c, h
    dec d
    and e
    ld a, l

jr_00d_5ed7:
    ldh a, [$08]
    and a
    sbc c
    and e
    and a
    adc [hl]
    cp e
    inc [hl]
    ld sp, $37e2
    add $a9
    res 3, b
    ld [hl], c
    ld a, [bc]
    ld h, e
    ld hl, sp+$47
    inc l
    ld l, c
    inc a
    adc a
    sub $42
    ld a, [de]
    ld d, d

jr_00d_5ef4:
    add hl, hl

jr_00d_5ef5:
    adc [hl]
    ld e, d
    adc l
    jp c, $c843

    xor h
    jp hl


    dec c
    dec c
    sbc b
    dec h
    call nz, $f332
    rst $18
    cp l
    ld l, c
    ld c, d
    sbc c
    jp z, $a84f

    add hl, hl
    inc e
    ld b, e
    ld b, [hl]
    or [hl]
    add d
    jr nc, jr_00d_5ed7

    inc de
    adc a
    dec c
    add hl, hl
    add d
    ld l, l
    ld c, l
    inc c
    ld [hl], d
    ld c, b
    rst $08
    call c, Call_000_25d8
    sub $84
    ld [hl], e
    ld [c], a
    add l
    dec b
    ld b, e
    sbc c
    add hl, hl
    add hl, hl
    add $91
    xor [hl]
    jr nc, jr_00d_5ef5

    xor h
    and e
    inc c
    ld [hl], e
    xor l
    ld a, [hl]
    xor d
    cp a
    ld e, e
    ld h, e
    ld hl, $949c
    or h
    ld e, $1c
    jr nc, jr_00d_5ef4

    add hl, hl
    ld sp, $6d92
    ld b, h
    pop bc
    ld [bc], a
    add $2b
    and $57
    sbc h
    or d
    ld h, l
    ld d, c
    or d
    or l
    add hl, hl
    pop bc
    ld a, d
    xor d
    ld a, [hl+]
    add hl, de
    add d
    pop de
    adc h
    sbc e
    inc hl
    sub b
    jp $d116


    cp d
    ld h, [hl]
    jp nz, $c18b

    ld d, e
    inc de
    ld d, h
    xor c
    and h
    sub d
    add e
    ld de, $15bd
    add hl, sp
    inc e
    sub l
    ld c, d
    ld h, l
    sub c
    db $e4
    inc l
    add h
    ld l, l
    ld b, [hl]
    ld d, h
    xor d
    add [hl]
    ld b, a
    ld [hl], h
    sbc h
    jr nz, jr_00d_5fc9

    cp d
    call nc, Call_00d_5feb
    and e
    and c
    ld a, d
    ld a, [hl-]
    sbc [hl]
    adc [hl]
    or a
    adc [hl]
    ld c, e
    push de
    rst $38
    adc [hl]
    ld h, l
    ld a, [bc]
    ld d, e
    xor [hl]
    add l

Jump_00d_5f9a:
    ld c, d
    push de
    add hl, sp
    ld a, $33
    and h
    ld e, b
    and $d5
    add hl, bc
    and e
    ld h, l
    add hl, hl
    ld c, d
    and b
    db $d3
    ld a, e
    cp d
    ld [$a8c6], sp
    sbc $d5
    ld c, d
    ld d, c
    cp h
    db $e4
    ld e, c
    ld a, b
    db $eb
    xor d
    inc a

jr_00d_5fba:
    db $dd
    sub $9d
    xor e
    inc b
    ld [hl], h
    xor h
    db $76
    ld sp, $c7da
    ld h, $1a
    inc c
    or h

jr_00d_5fc9:
    ld [hl], e
    ld l, b
    ld b, b
    and a
    ld e, h
    dec c
    rst $00
    ld h, a
    add h
    ld h, e
    xor d
    db $76
    ld a, d
    add h
    sbc e
    add sp, $26
    sbc b
    jp z, Jump_00d_7e6d

    add d
    ld h, [hl]
    rst $00
    dec b
    ld [hl], b
    ld c, c
    ld c, $45
    inc e
    sbc l
    pop bc
    dec e
    sub b

Call_00d_5feb:
    rst $00
    sbc d
    ld h, [hl]
    cp [hl]
    add hl, hl
    ld d, e
    bit 7, [hl]
    xor l
    inc a
    dec h
    ld d, c
    and d
    sub e
    ld b, a
    db $f4
    call $7e7e
    ld e, d
    ld a, l
    dec b
    add c
    sub l
    ld c, b
    ld a, b
    pop de
    or $55
    ld a, d
    add hl, bc
    dec de
    ret z

    ld b, d
    or [hl]
    rst $38
    ld [hl], $7f
    db $f4
    ld h, b
    and c
    add c
    ld a, [bc]
    ld b, $21
    ld c, b
    ld l, e
    sub h

Jump_00d_601b:
    jp hl


    ld h, d
    jr nz, jr_00d_6064

    ld b, c
    ld e, c
    add [hl]
    add hl, de
    jr c, jr_00d_5fba

    ld e, $a0
    ld b, a
    add sp, $2a
    or h
    sbc d
    jr c, jr_00d_608c

    ld d, b
    ld h, b
    add c
    jr nc, jr_00d_6086

    and c
    ld b, $88
    ld b, l
    ret c

    sub h
    jp z, $2498

    call $f9ee

jr_00d_603f:
    add hl, de
    inc c
    ld d, l
    add hl, de
    ld a, [de]
    ld c, d
    ld e, d
    db $d3
    ld a, [bc]
    ld a, c
    ld b, e
    dec bc
    jr jr_00d_6065

    adc d
    ld b, d
    sub c
    sbc b
    inc sp
    ld e, d
    dec b
    ld e, a
    xor d
    xor b
    swap e
    sub e
    ld b, a
    ret c

    ret


    add hl, bc
    ld hl, $d562
    dec h
    ld d, h
    cp d

jr_00d_6064:
    inc sp

jr_00d_6065:
    ld a, [hl]
    ld h, [hl]
    cp d
    sub h
    adc h
    dec d

jr_00d_606b:
    ld d, d
    inc hl
    adc c
    ldh [rHDMA5], a
    ld h, a
    ld d, l
    ld c, b
    ld a, d
    ld [hl+], a
    ld c, [hl]
    ld h, a
    ld a, [$feb5]
    xor d
    ld sp, $9ba3
    xor l
    ld a, [de]
    xor l
    ld c, h
    add sp, -$1c
    ld d, l
    ld [hl], d

jr_00d_6086:
    sbc $bd
    ld b, e
    ld hl, $9ae3

jr_00d_608c:
    db $dd
    db $ed
    ld a, [hl+]
    add [hl]
    dec b
    ld hl, sp-$15
    and d
    jr nz, jr_00d_606b

    cp [hl]
    dec b
    adc a
    ld e, $7f
    ld hl, sp-$09
    and a
    push bc
    jr nz, jr_00d_603f

    ld l, l
    ld a, [$449e]
    cpl
    ld sp, hl
    cp d
    ld l, d
    pop bc
    dec [hl]

jr_00d_60ab:
    ld a, $91
    ld a, a
    ldh [$90], a
    sbc b
    and $50
    ld d, [hl]
    ld de, $2137
    inc hl
    ld e, h
    inc l
    ld b, e
    jp c, $8cf9

    ld b, h
    rst $28
    ldh a, [$62]
    or [hl]

jr_00d_60c3:
    rra
    dec bc
    ret nz

    ld a, [$e637]
    rst $38
    ld a, [$7018]
    ld a, $1a
    ldh a, [rHDMA5]
    sub e
    add l
    ld b, [hl]
    rst $18
    push de
    db $e3
    ccf
    sub c
    rla
    jr z, jr_00d_60c3

    rla
    ld [de], a
    ld hl, sp+$3f
    push hl
    ret


    ld a, [de]
    ld sp, hl
    jp $bd5a


    rst $28
    ld hl, sp-$37
    jr z, jr_00d_60ab

    ld a, e
    sbc e
    xor d
    sbc $85
    db $fc
    rst $38
    and b
    db $fd
    cp $ff
    ld [$8360], a
    call $540d
    rrca
    ld a, a
    db $fd
    pop hl
    ldh a, [$5c]
    ld [hl], $61
    inc c
    ld [$d546], sp
    ldh a, [rHDMA1]
    ld c, b
    ld c, b
    and $08
    ld b, c
    ld a, [de]
    ld c, c
    ld d, d
    and h
    cpl
    ld a, [c]
    rst $30
    inc e
    adc e
    dec b
    ld [bc], a
    rst $10
    ld a, [$3f43]
    rst $20
    dec hl
    ld [bc], a
    xor d
    ld [hl], $45
    ld c, b
    ld b, b
    rst $10
    rst $20
    ld l, $c5
    ld c, d
    xor d
    xor d

jr_00d_612e:
    ret nc

    dec [hl]
    inc e
    sbc $2a
    add hl, bc
    or e
    dec e
    ld d, [hl]
    cp [hl]
    inc [hl]
    sub d
    adc d
    rst $00
    sub l
    adc d
    ld a, c
    call nc, $887d
    ld b, h
    cp d
    sub a
    jr nc, @-$49

    ld c, l
    rst $18
    ld [$ddce], sp
    ld d, e
    ld a, [hl+]
    ld hl, $a031
    ld d, b
    ld l, l
    rst $38
    or $86
    jr @-$38

    db $db
    ld a, d
    ld l, $05
    add c
    ld d, e
    dec sp
    and e
    ld d, [hl]
    sub l
    ld a, [hl-]
    and [hl]
    ld [$3f3b], a
    ld c, h
    dec d
    ld [hl-], a
    ld l, d
    ret z

    ld [hl], b
    ld l, b
    cp b
    rra
    ld sp, hl
    ld [hl+], a
    ld e, d
    add c
    cp $53
    dec bc
    and $82
    ld b, c
    ld b, [hl]
    inc c
    cpl
    db $f4
    adc $bd
    sbc l
    db $76
    dec b
    rlca
    adc $8a
    add d
    adc [hl]
    ei
    ld e, c
    adc [hl]
    jp z, Jump_000_1f8f

    ld a, b
    sbc b
    jr nz, jr_00d_612e

    jr z, jr_00d_61da

    jr z, jr_00d_61e3

    add d
    ld [hl], b
    and [hl]
    ld d, $0c
    ei
    jp z, $acb0

    ld d, $9a
    ld c, h
    ld sp, $0b71
    pop af
    xor h
    jp nc, Jump_000_3f61

    cp $6b
    ld [hl+], a
    sbc b
    ld e, h
    push af
    dec de
    pop de
    sbc l
    ld a, [de]
    and h
    dec h
    or [hl]
    ld b, d
    and b
    add $3c
    ld a, $95
    ld b, c
    cp d
    db $db
    ld h, $38
    ld [hl], d
    rrca
    ld d, c
    jr z, jr_00d_61f3

    or d
    ld l, c
    ld h, c
    ret c

    jp z, $d7fb

    rst $00
    ld b, h
    ld [$1da3], sp
    ld d, b
    ld l, e
    rra
    inc c
    ld [hl], a
    cp h
    push de

jr_00d_61da:
    cp $4f
    add hl, de
    db $fd
    ld l, $67
    jp $943b


jr_00d_61e3:
    xor d
    ld a, h
    inc [hl]
    sub l
    ldh [rSCY], a
    ld a, [hl-]
    ld d, l
    ld b, d
    ld l, c
    ld b, d
    and b
    ld b, c
    and d
    ld d, l
    ld b, [hl]

jr_00d_61f3:
    ld c, [hl]
    ld a, d
    xor d
    and d
    ld h, b
    xor $aa
    adc c
    sbc [hl]
    sub b
    sub e
    db $76
    xor e
    adc c
    pop bc
    ld d, d
    dec l
    ld e, [hl]
    ld hl, $fcff
    ld d, c
    ld c, l

jr_00d_620a:
    add hl, de
    ld d, c
    pop bc
    ld [hl], h
    ld h, c
    and l
    add d
    ld e, h
    jr nz, @-$74

    add d
    jr c, jr_00d_6227

    add c
    add sp, $68
    add l
    adc h
    and d
    dec [hl]
    ld c, c
    add d
    adc l
    ld d, b
    add d
    add l
    ld c, b
    cp l
    ld [c], a

jr_00d_6227:
    rst $10
    ld [$f6aa], a
    add hl, hl
    adc h
    ld e, $c6
    ld b, $18
    jr c, jr_00d_624b

    add l
    ld a, [hl]
    adc l
    inc h
    sub h
    pop bc
    rst $20
    inc b
    ld l, c
    inc d
    jr jr_00d_626e

    ld a, [$288e]
    jr jr_00d_620a

    ld hl, sp+$20
    pop bc
    push af
    ld h, l
    and e
    push bc

jr_00d_624b:
    ld d, a
    cp c
    and l
    ld a, [de]
    dec sp
    rst $20
    jp nc, $be1e

    ld h, d
    xor d
    ld d, e
    add l
    ld c, h
    sub c
    add [hl]
    sbc [hl]
    call nc, $aa2b
    xor d
    and a
    sub h
    call Call_00d_41eb
    ld a, a
    ret nc

    rst $18
    rst $30
    rst $30
    cp $ff
    push de
    xor d

jr_00d_626e:
    ld [hl+], a
    sub h
    sub l

Jump_00d_6271:
    ld a, a
    jp $a0a2


    adc h
    xor d
    xor d
    xor b
    and [hl]
    xor e
    push de
    ld e, $25
    db $e3
    inc [hl]
    rra
    add hl, hl
    ld l, l
    or d
    ld d, $f7
    xor $d5
    ld c, b
    xor [hl]
    adc l
    xor b
    and a
    ld l, b
    add hl, de
    rrca
    cp $a1
    add sp, $18
    dec l
    ld b, c
    adc l
    ld h, d
    dec h
    inc d
    ld [de], a
    dec d
    ld [$7e25], a
    add d
    ld a, [hl+]
    cp l
    ld h, l
    dec l
    adc c
    and c
    ld e, d
    sbc $21
    ld d, a

Jump_00d_62aa:
    ld a, [$d426]
    sub l
    add [hl]
    ld b, d
    ld d, [hl]
    adc d
    adc d
    ld d, [hl]
    ld a, a
    ld a, [$4aa3]
    rst $38
    db $f4
    sbc b
    pop hl
    xor d
    cp a
    push de
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld e, a
    and d
    ld e, b
    dec d
    ld c, [hl]
    ld e, d
    xor d
    xor d
    xor d
    xor d
    xor b
    ld d, l
    ld e, l
    and d
    ld h, h
    adc b
    xor $55
    xor d
    dec b
    and e
    ld b, [hl]
    inc [hl]
    sub l
    ld d, l
    ld d, l
    ld l, d
    xor b
    ld d, l
    ld e, d
    inc [hl]
    ld e, [hl]
    ld [hl], $95
    ld d, h
    rst $10
    push de
    ld d, l
    ld d, l
    ld d, a
    cp $8e
    ld a, d
    xor d
    xor d
    xor d
    xor d
    xor d
    xor d
    and e
    add d
    ld a, c
    xor b
    ld b, b
    rst $20
    dec bc
    pop de
    ld a, [hl+]
    xor d
    xor d
    ld e, e
    sbc b
    ld b, h
    xor c
    pop bc
    ld b, [hl]
    ld a, [bc]
    or a
    rst $38
    ld [$172b], a
    inc de
    sbc h
    ld l, d
    rst $38
    db $fd
    rst $18
    rst $38
    ld a, [$2935]
    ld [hl-], a
    inc l
    sbc e
    cpl
    rst $38
    ei
    ld c, $1f
    rst $38
    db $fc
    ld [hl], $31

Jump_00d_6321:
    ld d, b
    call z, $3c99
    ld d, d
    inc a
    ld c, [hl]
    rst $38
    rst $38
    ldh a, [rNR42]
    jp hl


    ld l, $83
    ld a, [c]
    ld e, e
    ld b, h

Call_00d_6332:
    or b
    cpl
    rst $28
    db $e3
    ld a, a
    rst $38
    dec b
    adc $4b
    rst $38
    cp $9a
    and b
    db $fd
    ld a, a
    ldh [$f3], a

jr_00d_6343:
    db $fd
    ld b, h
    or c
    ccf
    rst $38
    rst $30
    sbc d
    inc hl
    call nz, Call_00d_52ff
    ld h, h
    or h
    ld c, l
    db $ed

Call_00d_6352:
    rst $38
    sbc d
    ld hl, sp-$3e
    ld hl, sp+$7f
    jr jr_00d_6387

    add hl, de
    ld e, a
    or a
    add $6c
    ld d, $0c
    jr z, jr_00d_63df

    xor d
    add l
    inc e
    rra
    ld sp, hl
    jp nz, $ea83

    ei
    rst $38

jr_00d_636d:
    sbc h
    sbc a
    ld sp, hl
    and d
    ld d, e
    dec [hl]
    rst $38
    rst $38
    jp hl


    call nz, $f1ff
    sub e
    ldh a, [$30]
    ld d, l
    ld b, e
    ld e, a
    cp $9a
    inc h
    ccf
    rst $38
    xor c
    add hl, bc
    dec l

jr_00d_6387:
    inc bc
    push af
    ld d, l
    ld e, d
    dec d
    cp $98
    jr nc, jr_00d_636d

    ld [$d0e1], a
    ld c, h
    ld c, a
    ld e, a
    ld de, $a810
    ld a, [hl+]

Call_00d_639a:
    rst $30
    ld [$4c16], a
    push af
    rst $38
    add [hl]
    adc d
    ld h, l
    ld c, d
    rst $38
    ld c, e
    db $f4
    ld c, l
    call nc, Call_000_0cfa
    ld b, e
    rst $38
    rst $30
    ld [bc], a
    ld h, b
    cp a
    or $fd
    ld b, h
    jr nz, jr_00d_6343

    inc hl
    inc bc
    ld h, h
    rst $38
    rst $38
    pop hl
    sub h
    add h
    rrca
    call Call_000_0f46
    ld hl, $2e13
    add [hl]
    add e
    rst $38
    rst $38
    ld hl, sp+$50
    and h
    inc a
    xor d
    xor d
    xor l
    cp h
    ld h, l
    ld de, $ff7f
    rst $38
    push hl
    ld [hl+], a
    or e
    rst $38
    rst $10
    cp a
    jr jr_00d_6407

    add hl, bc

jr_00d_63df:
    ld [hl], l
    rst $38
    rst $38
    ld d, $8d
    xor d
    cp a
    db $f4
    ld h, [hl]
    cp d
    db $fc
    ld e, h
    xor d
    xor e
    sbc d
    ld b, e
    ld [hl], l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld [hl], c
    adc e
    rst $38
    rst $38
    jp hl


    ld e, c
    ldh [rNR50], a
    cpl
    rst $38
    rst $38
    and $1e
    xor d
    xor d
    sbc e
    inc h
    ld l, d
    rst $38

jr_00d_6407:
    rst $38
    db $fd
    ld a, a
    add hl, de
    ld a, a
    rst $38
    rst $38
    sub l
    add d
    dec bc
    rst $38
    rst $38
    push af
    ld d, c
    dec hl
    add hl, de
    inc h
    ld e, a
    rst $38
    db $f4
    ld b, h
    db $10
    ld d, l
    ld d, c
    xor e
    inc c
    ld [hl], c
    push de
    ld d, c
    and $00
    ld b, h
    cp c
    sub l
    rst $38
    ld [hl-], a
    ld [hl], h
    ret


    ld a, [$f3a5]
    ld d, h
    add $f5
    ld a, d
    ld d, e
    ld a, [hl+]
    add c
    ld sp, $0f57
    add sp, -$32
    and l
    ld hl, $b67e
    inc [hl]
    or h
    ld l, b
    ld a, a
    and d
    daa
    add c
    ld a, h
    or l
    or h
    adc b
    jp nz, $bd87

    ld c, h
    dec l
    cp h
    push bc
    ld a, e
    ld l, d
    inc c
    jp z, Jump_00d_4bdb

    ld h, l
    add l
    db $ec
    jp nc, $3082

    ld b, e
    push af
    ld a, b
    push de
    ld b, c
    ld d, h
    sub [hl]
    pop af
    ld d, h
    jp c, $d9c3

    ld [hl+], a
    ld c, $22
    jr c, jr_00d_6499

    call c, $a235
    inc l
    push hl
    ld d, a
    ld hl, sp-$15
    xor d
    inc a
    ret


    ret nc

    add $a8
    ld h, $4c
    add h
    ld [$647a], sp
    adc d
    ld h, l
    inc b
    inc de
    db $fc
    ld h, a
    ld a, [bc]
    ld h, d
    adc d
    dec de
    ld d, c
    add $83
    db $fc
    ret nz

    cp [hl]
    ld e, l
    inc de
    rlca
    rlca
    rst $38
    ret nz

jr_00d_6499:
    db $dd
    jp hl


    ld [hl], c
    ld c, h
    rrca
    rst $38
    jp Jump_00d_51ed


    xor h
    rrca
    jp nz, Jump_000_35da

    ld c, h
    ld l, a
    ld a, d
    rra
    rst $10
    ld a, [bc]
    add hl, hl
    xor h
    rrca
    ei
    ld hl, sp-$40
    sbc h
    ld d, e
    rst $10
    rst $38
    and d
    adc d
    ld [hl], b
    and b
    or a
    sbc $e4
    and a
    inc e
    jr jr_00d_653d

    rst $00
    ld e, [hl]
    inc l
    ld a, h
    ld e, b
    ld h, [hl]
    or [hl]
    ld e, a
    ldh a, [rHDMA5]
    inc a
    ld b, [hl]
    and d
    xor d
    cp l
    ld c, [hl]
    ld a, [$7fbd]
    db $fd
    ld e, [hl]
    db $d3
    or c
    db $eb
    jp $aa4a


    rst $30
    add hl, sp
    rst $10
    rst $28
    xor b
    ld a, $d3
    cp l
    add sp, $60
    ld d, d
    rst $38
    ld c, [hl]
    ld d, a
    jp nc, Jump_000_0755

    ld d, b
    ld d, [hl]
    xor c
    or l
    inc sp
    ld a, l
    ld c, b
    and a
    adc d
    xor d
    inc sp
    add d
    dec [hl]
    and b
    ld e, e
    ld l, d
    ld c, h
    xor b
    call Call_000_1504
    jr nc, @-$5e

    ld e, a
    ld b, c
    rrca
    ld c, h
    xor b
    adc $71
    and h
    ld d, a
    sbc [hl]
    ld hl, $54d0
    ld [c], a
    ld e, d
    and h
    dec h
    xor h
    jr nz, jr_00d_656d

    xor d
    ld hl, sp-$1f
    and d
    ld d, d
    ld l, e
    ld hl, $3ab5
    inc d
    ld [de], a
    ld d, b
    adc h
    jr c, jr_00d_6551

    db $d3
    sub c
    ld d, c
    sbc c
    ld d, b
    adc b
    and l
    ld b, c
    dec b
    dec de
    ld c, c
    ld d, e
    adc [hl]
    ld d, $16
    add d
    adc b
    xor e
    db $f4
    dec de
    xor d

jr_00d_653d:
    call nc, $7dca
    sbc a
    ld e, l
    add c
    or b
    or h
    xor b
    add h
    db $10
    ld e, l
    dec l
    ld c, b
    and a
    xor c
    ld [$c219], sp
    ld [hl+], a

jr_00d_6551:
    sub l
    or b
    ld a, c
    ld [hl], a
    ld c, d
    ld d, d
    ld e, [hl]
    dec b
    ld d, a
    sbc [hl]
    ld [hl], h
    call Call_000_0505
    ld [hl], h
    and l
    ld e, a
    add a
    sub b

jr_00d_6564:
    rst $20
    sbc l
    rst $38
    push af
    ld e, b
    ld d, $22
    and e
    ld a, [bc]

jr_00d_656d:
    adc c
    add c
    dec bc
    rst $30
    adc c
    xor d
    rst $38
    add sp, $2a
    jr c, jr_00d_6564

    scf
    add sp, -$1e
    xor l
    ld c, [hl]
    ld c, d
    adc [hl]
    ld [hl], l
    ld c, a
    ld b, d
    inc a
    push af
    ld c, c
    sbc e
    ld hl, $900b
    sbc [hl]
    ld d, d
    xor e
    adc $09
    pop hl
    ld b, e
    rla
    push de
    and a
    ld l, d
    ld b, d
    sbc e
    pop de
    adc $86
    db $f4
    dec hl
    ld b, b
    sbc [hl]
    ld [bc], a
    cpl
    add h
    inc l
    ld c, e
    add hl, hl
    rst $18
    inc b
    sbc b
    call Call_00d_69aa
    dec h
    ld b, [hl]
    adc c
    sbc h
    db $10
    ld a, c
    sbc h
    jr c, jr_00d_661a

    and [hl]
    xor c
    sub h
    add e
    ret


    and h
    ld b, h
    add hl, sp
    or h
    ld c, h
    rst $08
    ld a, [c]
    inc e
    ld c, d
    ld l, e
    or c
    or e
    inc sp
    call nz, $2330
    ld [bc], a
    ld [$d229], sp
    add sp, $64
    cp b
    ld h, c
    dec c
    add l
    ld [hl], c
    adc $91
    inc b
    and b
    pop hl
    ld [$a108], a
    ld [$b072], a
    dec h
    cp c
    ld d, $1c
    inc c
    dec d
    add h
    sbc h
    jp c, $c443

    add hl, hl
    ld l, $1c
    db $10
    inc h
    ld c, b
    ld a, [hl-]
    ld [hl], b
    cp h
    jr z, @+$53

    ld a, $14
    and d
    db $e4
    ld b, c
    dec de
    cp a
    call nz, $905f
    ld hl, sp+$3e
    cp l
    inc b
    add hl, bc
    ld sp, $f1a7
    ld c, a
    dec bc
    ldh a, [$5f]
    rst $38
    pop hl
    ld a, [$466f]
    inc c
    cpl
    pop bc
    ld a, [bc]
    ld b, l
    ld d, b
    jp nc, $ff74

    ld b, [hl]
    ld [hl], c
    ld l, h

jr_00d_661a:
    ld de, $47cd
    ld b, d
    ld a, c
    pop af
    jp hl


    rst $20
    sbc l
    ld d, $77
    ldh [$8f], a
    ld e, d
    xor b
    pop af
    sub h
    db $dd

jr_00d_662c:
    ld d, h
    jp hl


    ld d, l
    jr nc, jr_00d_662c

    or h
    push de
    inc b
    and $7a
    xor b
    and [hl]
    add sp, $1a
    ld [hl-], a
    ld hl, sp+$1f
    ld c, [hl]
    add l
    ld hl, $69b5
    xor b
    jp z, Jump_000_15b2

    ld d, e
    add l
    ret z

    ld e, e
    ld h, d
    sub [hl]
    and d
    rst $18
    rlca
    ld e, d
    add e
    ld l, a
    call nc, Call_00d_54ba
    sbc l
    adc c
    cp e
    push hl
    ld l, $f7
    ld [$affa], a
    rst $38
    sub l
    ldh [rHDMA2], a
    jr nz, @+$4a

    or h
    ld a, [hl-]
    ld d, h
    ld [$d8aa], a
    add a
    xor b
    db $10
    or l
    db $ed
    ld a, [$6c3b]
    xor c
    ld l, d
    and l
    and b
    ld a, d
    inc a
    dec [hl]
    add hl, de
    ld a, [de]
    sub $05
    and e
    jp z, Jump_00d_58b5

    sub l
    ld [hl], h
    inc d
    sub l
    dec sp
    inc d
    ld d, l
    ld [hl], a
    cp e
    rst $38
    xor $81
    rst $28
    dec sp
    ld e, [hl]
    add l
    rrca
    rst $20
    jp c, $d697

    call nc, $b8ea
    and l
    rst $28
    cp b
    ld [de], a
    inc e
    ld e, a
    db $fc
    pop af
    dec hl
    cp d
    db $e4
    adc a
    ld [$0b8f], a
    jp nz, $ffaf

    ld a, [$4e30]
    push hl
    rst $20
    sub a
    rst $38
    ld sp, hl
    jp nc, $8e5e

    sub l
    ld a, d
    cp b
    cp e
    jp Jump_00d_56c3


    add c
    ld [c], a
    rst $18
    ld d, c
    ld d, d
    sub a
    add sp, $3f
    adc c
    ld d, h
    ld l, d
    xor e
    sub l
    ld b, e
    ld d, d
    rst $28
    cp $a9
    ld a, a
    rst $38
    db $e3
    rlca
    xor l
    ld b, e
    db $ed
    ld c, b
    rst $38
    ld a, [c]
    sub a
    ld b, [hl]
    ldh a, [rIE]
    and e
    ld c, d
    rrca
    db $fd
    sbc a
    inc b
    ld e, l
    add sp, -$51
    ld sp, hl
    ld e, a

jr_00d_66e8:
    xor b
    ldh [$bf], a
    xor a
    ld a, l
    xor e
    db $dd
    db $f4

jr_00d_66f0:
    and l
    ld l, c
    ld h, e
    or [hl]
    and e
    ld a, [de]
    jp nc, $fb1f

    adc a
    ld b, d
    xor b
    push af
    ld a, [hl+]
    adc a
    ld d, l
    ld d, e
    sub $8c
    ld a, d
    ldh a, [rBGP]
    xor a
    dec e
    ld l, c
    pop bc
    sbc e
    and a
    ld a, [hl-]
    scf
    and [hl]
    sub a
    ld a, [de]
    inc h
    ld l, c
    rst $08
    add $50
    pop bc
    add $90
    ld a, [hl-]
    ld [hl], d

jr_00d_671b:
    xor [hl]
    add hl, hl
    or a
    add hl, de
    ld e, e
    ld b, b
    and c
    ld b, b
    or c
    adc h
    and c
    ld h, a
    inc bc
    jr jr_00d_66f0

    pop de
    ld d, c
    ld e, b
    cp [hl]
    ld sp, $dc8a
    ld [hl], a
    jr nc, jr_00d_66e8

    ld a, $c5
    dec l
    add h
    ld a, b
    jr nc, jr_00d_671b

    db $d3
    ld hl, sp-$55
    rst $00
    adc l
    ld a, b
    call nz, $1ef9
    ld a, c
    ld d, [hl]
    add d
    ld a, $43

jr_00d_6749:
    ld l, $29
    pop hl
    and b
    pop af
    inc d
    ld c, d
    ld c, h
    add hl, bc
    pop hl
    xor h
    ld e, l
    xor a
    ld l, c
    ld d, h
    rst $00
    adc [hl]
    jp nz, $03fd

    xor e
    ld l, [hl]
    sbc [hl]
    ld [hl-], a
    db $e3
    dec d
    ld a, c
    and $64
    jp c, Jump_00d_79d2

    add hl, bc
    add d
    ld d, $b4
    ld h, h
    sbc l
    ld l, b
    cp a
    dec d
    add [hl]
    ld a, [bc]
    ld c, d
    adc d
    pop af
    adc d
    jr jr_00d_679c

    sub [hl]
    add h
    ld e, h
    ld e, h
    jp c, Jump_000_0a0a

    add hl, bc
    jp Jump_00d_5148


    dec de
    ld b, h
    ld b, [hl]
    or d
    sub c
    ld e, a
    and c
    ld [hl], c
    adc d
    dec bc
    ld a, d
    add l
    sbc h
    ld de, $a914
    ld d, a
    ld [hl-], a
    ld h, e
    inc b
    dec a
    inc e
    pop de

jr_00d_679c:
    jr nc, jr_00d_6812

    ld h, l
    jr jr_00d_6749

    ld b, a

jr_00d_67a2:
    and [hl]
    pop bc
    inc b
    ld a, d
    ld [hl], $7a
    sub $7b
    inc c
    ld a, d
    ret nz

    ld h, [hl]
    cp [hl]

jr_00d_67af:
    push de
    ld l, d
    xor d
    ld c, a
    ld de, $34a3
    db $ec
    ld b, c
    db $dd
    ld [hl], $53
    xor a
    rst $38
    or e
    ld l, [hl]
    ld a, [hl-]
    sub b
    add d
    jr c, @+$3a

    dec e
    inc b
    ld [c], a
    sbc b
    rst $20
    add d
    add sp, -$1f
    add l
    sub e
    xor c
    ret nc

    ld [hl], e
    dec d
    ld b, a
    dec sp
    xor a
    db $f4
    jp nz, Jump_00d_4a2a

    and h
    and $bf
    jr nc, jr_00d_682a

    inc hl
    ld [$fce6], sp
    pop bc
    inc a
    ld h, h
    inc hl
    inc c
    ldh [$4e], a
    ld l, e
    ld c, h
    ld [hl+], a
    ret c

    and [hl]
    ld a, [hl-]
    cpl
    ld c, d
    sub d
    jr jr_00d_67a2

    dec sp
    inc l
    cp a
    add hl, de

Jump_00d_67f8:
    inc a
    ld b, h
    jp nz, $a391

    jp nz, $bd4c

    inc a
    rst $28
    ret z

    ld c, [hl]
    inc [hl]
    inc de
    ld c, b
    jp z, $41e9

    inc d
    ret


    call c, $833f
    ld c, h
    inc hl
    ld c, e

jr_00d_6812:
    ld l, a
    cp l
    db $dd
    ld e, e
    add d
    ld [$af20], sp
    ld b, a
    ld h, h
    jp nc, Jump_000_1826

    jr nz, jr_00d_67af

    jr jr_00d_684d

    inc c
    db $f4
    and $89
    cp e
    ld [hl-], a
    ld e, d

jr_00d_682a:
    ld [hl], e
    ld [hl-], a
    add hl, de
    ld [$2f33], sp
    and b
    sub b
    call z, Call_000_31c8
    xor d
    inc c
    call z, $d5ef
    ld d, l
    add sp, $20
    rst $08
    db $ec
    ld l, b
    call $ffb3
    ld b, l
    ld d, l
    ld e, e
    ld de, $a63f
    sub e
    cpl
    rst $38
    ld sp, hl

jr_00d_684d:
    adc d
    xor a
    ret nz

    adc a
    db $fc
    sbc b
    inc h
    rst $08
    rst $38
    rst $18
    dec h

Call_00d_6858:
    ld c, b
    rst $38
    db $ec
    add a
    ld a, [c]
    ld h, b
    call $d4bf
    ld de, $9332
    rst $18
    rst $38
    rst $38
    ld [hl], d
    add hl, bc
    ld a, e
    rst $38
    dec de
    ld d, l
    ld de, $ff57
    xor a
    call z, Call_000_0743
    and b
    ld sp, hl
    call $ff5f
    cp $c8
    cp a
    adc [hl]
    ld e, a
    and a
    dec e
    rst $38
    cp $e4
    ld a, $4c

Jump_00d_6885:
    sub l
    ld a, [$5771]
    rst $38
    db $e4
    cp c
    xor h
    ld [hl], e
    rst $38
    db $fc
    adc e
    jp hl


    pop hl
    rst $18
    db $fc
    adc e
    jp hl


    ld l, c
    add d
    ld c, d
    ld [hl], b
    rst $38
    jp hl


    ld e, $92
    ld sp, hl
    ld [$3530], sp
    dec b
    ld c, d
    ld l, c
    ld a, a
    db $e4
    ld e, a
    adc a
    inc de
    ld d, b
    db $e4
    dec [hl]
    ld c, e
    sbc d
    rst $18
    sub b
    rst $18
    add h
    sbc b
    ld [hl], c
    ld l, d
    sub c
    sbc d
    rst $38
    ld a, [bc]
    dec c
    jp hl


    sub [hl]
    ld d, h
    ld b, l
    ld h, [hl]
    rst $08
    ret z

    pop bc
    ld a, a
    and c
    sub [hl]
    sub h
    xor e
    ld a, [bc]
    and [hl]
    ld c, l
    call nz, $ffb3
    ld a, [hl+]
    ld d, h
    add d
    ld de, $ff0b
    ld a, [$36a4]
    sub c
    scf
    ld a, a
    rst $38
    cp $aa
    cp e
    rst $38
    rst $38
    rst $38
    ld a, [$24b3]
    push de
    cp a
    ld a, a
    rst $38
    rst $38
    rst $38
    call c, $cdd4
    rst $38
    rst $38
    adc d
    ld [$117f], sp
    ld e, [hl]
    rst $18
    ld [hl], h
    dec c
    inc d
    add [hl]
    ld b, a
    ld b, c
    ld b, c
    sbc e
    or e
    ld de, $d01c
    ret nz

    ld d, l
    cp l
    ld b, l
    inc a
    dec b
    ld c, b
    cp b
    rst $28
    add d
    adc b
    sbc e
    push de
    dec [hl]
    ld d, h
    adc $6d
    ld h, $0f
    xor a
    ld d, h
    cp b
    adc c
    inc sp
    cp a
    rst $38
    ld e, [hl]
    and l
    jp nz, $e34c

    ld c, e
    ld d, h
    ld a, [hl+]
    xor d
    sub d
    dec h
    adc [hl]
    ld e, d
    ld [$f249], a
    or d
    add sp, -$37
    ld e, a
    ld [$f65f], a
    call z, $2332
    rlca
    rst $28
    ld d, l
    ld d, l
    ld d, h
    ld [hl], h
    db $e3
    cp a
    ld [$8da4], a
    ld e, a
    ld [hl], d
    ld [hl], d
    ret nc

    ld d, h
    ld e, b
    and l
    or $a2
    ld d, a
    inc [hl]
    and d
    ld [hl+], a
    ld d, a
    add sp, $15
    ld d, l
    ld a, d
    call z, Call_000_2bd3
    ld a, a
    ld a, [$62ab]
    dec a
    ld l, c
    dec d
    inc b
    add [hl]
    ld [hl+], a
    ld a, h
    pop bc
    ld [c], a
    scf
    adc d
    and d
    ld l, d
    jr c, jr_00d_6991

    add [hl]
    db $e3
    cp [hl]
    rst $38
    add sp, -$10
    ld e, l
    inc a
    ld a, d
    ld a, $0a
    ld a, d
    adc d
    sbc l
    add sp, $28
    ret


    ldh [rNR52], a
    db $10
    ld a, [hl-]
    add hl, bc
    xor d
    add hl, bc
    and h
    jp hl


    ld d, b
    ld c, h
    ld [de], a
    add hl, bc
    ld [hl], c
    ld [de], a
    ld l, e
    ld l, d
    ld hl, sp-$3f
    ld a, $94
    and l
    ld b, [hl]

jr_00d_6991:
    or a
    ld a, a
    call z, $a312
    ld l, h
    ld [de], a
    adc d
    ld [hl], b
    ld [hl], b
    ld e, d
    rrca
    cp $98
    ret


    sbc d
    ld c, $ff
    ldh [$90], a
    call nc, Call_000_3111
    add hl, de
    sub a

Call_00d_69aa:
    push af
    ld d, l
    ld d, b
    ld c, h
    rst $38
    ld h, $39
    ld [hl], e
    inc b
    ld e, l
    call z, $aa90
    sbc b
    ldh [$82], a
    add hl, sp
    add e
    cp a
    or d
    inc a
    and b
    sbc b

Jump_00d_69c1:
    call nz, Call_000_0ac3
    rst $38
    push af
    inc b
    rrca
    ld l, e
    ld a, [bc]
    ld d, d
    ld d, d
    ld b, e
    ld b, h
    push bc
    and e
    ld a, h
    inc d
    ld [de], a
    or b
    ld c, b
    ld sp, $5150
    add e
    or e
    rst $00
    add b
    rst $38
    rst $00
    add l
    ld b, a
    adc a
    ld a, [hl+]
    ld a, l
    ld c, b
    ld b, h
    or [hl]
    ld c, [hl]
    and h
    adc d
    db $d3
    sbc [hl]
    ld [$1788], sp
    ld c, [hl]
    ld l, c
    ld h, $d0
    cp l
    ld c, d
    ld d, e
    jr z, jr_00d_6a74

    ld d, a
    sub c
    ld a, d
    ld e, b
    pop bc
    ld h, $77
    ld [$8daf], a
    push hl
    ld h, $9f
    ld d, l
    or e
    ld l, c
    rrca
    rst $38
    rst $38
    xor d
    ld [hl], e
    add d
    cp l
    ld d, h
    dec d
    ld d, [hl]
    ld c, [hl]
    ld c, e
    jp $aeaa


    dec hl
    dec [hl]
    ld a, d
    add c
    ld d, l
    ld d, d
    ld a, [de]
    ld c, h
    ret c

    rra
    ei
    ld d, [hl]
    add c
    adc c
    and e
    ld h, $89
    and c
    ld a, d
    jr c, jr_00d_6a97

    cp e
    ld d, b
    di
    or d
    and e
    ret nc

    sbc d
    xor d
    sbc h
    ld [$828c], a
    ld [hl], e
    push bc
    cp e
    sbc h
    jp z, Jump_000_3061

    ld h, $09
    adc d
    ld l, $e9
    ld c, e
    ld hl, sp+$48
    ld b, [hl]
    ld c, $4c
    dec e
    or d
    ld [hl-], a
    add h
    ld l, b
    ld sp, hl
    add h

jr_00d_6a50:
    ld [de], a
    dec [hl]
    ld d, h
    ld l, e
    ld a, d
    xor d
    cp h
    rla
    ei
    inc e
    rla
    ld e, a
    add h
    dec d

jr_00d_6a5e:
    xor b
    daa
    ld [de], a
    rrca
    ret z

    rst $18
    ld a, [bc]
    sbc e
    rst $38
    db $fc
    db $10
    ld l, d
    inc [hl]
    ld [de], a
    ld h, h
    cp a
    inc c
    jr c, jr_00d_6abd

    sbc h
    inc l
    ld e, l

jr_00d_6a74:
    db $fc
    ld b, d
    ld [hl], c

jr_00d_6a77:
    ld b, [hl]
    dec d
    add l
    rra
    ld a, [de]
    ld h, [hl]
    cp [hl]
    pop bc
    db $fd
    inc a
    set 3, e

jr_00d_6a83:
    ld c, [hl]
    dec b
    dec sp
    inc d
    jr z, @+$59

    db $fd
    ld c, b
    ld c, [hl]
    ld h, l
    ld d, l
    add hl, hl
    rlca
    and c
    ld h, c
    sbc b
    or l
    ld c, l
    jr jr_00d_6a50

jr_00d_6a97:
    add d
    ld a, b
    ld e, e
    ld sp, $8de1
    ld e, b
    add h
    jp z, $30e6

    ld h, d
    inc hl
    ld [hl], h
    adc a
    ret


    ld c, h
    sbc [hl]
    ld hl, $8a68
    ld [hl+], a
    jr nc, @-$77

    ld [hl+], a
    rlca
    ld [$37ca], sp
    ld e, b
    jp nz, $c917

    sub b
    jp Jump_00d_4c30


    cp h

jr_00d_6abd:
    pop hl
    sbc h
    sub [hl]
    rst $00
    jr nc, jr_00d_6a77

    adc d
    sbc a
    push bc
    sub h
    or h
    adc h
    xor e
    inc c
    pop hl
    sub e
    jr c, jr_00d_6a83

    ld h, d
    ld [de], a
    or e
    add l
    ld a, [hl+]
    sub e

Call_00d_6ad5:
Jump_00d_6ad5:
    jr c, jr_00d_6a5e

    or e
    ld b, l
    ld b, d
    dec h
    ld c, b
    ld h, d
    dec h
    ld sp, $8390
    inc sp
    ld b, c
    ld a, [de]
    xor d
    ld c, b
    adc [hl]
    add hl, sp
    dec l
    add l
    ld a, [bc]
    cp a
    rst $38
    jp nc, $e424

    xor d
    and c
    ld [hl], b
    xor l
    dec l
    inc d
    sub h
    db $ec
    and d
    inc d
    add [hl]
    ld h, $4f
    ld [bc], a
    pop de
    or [hl]
    ld sp, $3b41
    rst $28
    ld e, h
    ld e, b
    cp b
    ldh a, [$ea]
    and e
    db $ec
    rst $20
    ret nz

    ld b, h
    and a
    sub [hl]
    xor $42
    ld e, d
    ld h, b
    sbc h
    ldh a, [rSTAT]
    rlca
    inc de
    inc c
    add d
    ld c, [hl]
    dec de
    inc e
    ld c, c
    ld [$b4a2], sp
    db $10
    ld a, [hl-]
    db $e3
    inc bc
    adc [hl]
    jr z, jr_00d_6b4f

    sbc d
    sub d
    add d
    ld l, $10
    rst $18
    push de
    ld e, b
    or d
    ld [$10a6], sp
    ld b, b
    rst $38
    db $ec
    inc a
    add sp, $3c
    sbc b
    ld e, b
    ld hl, $481a
    ld a, a
    db $fd
    ld a, [hl+]
    rst $18
    ret nc

    and h
    or d
    ld [hl-], a
    ld c, d
    ld e, d
    ld a, [hl+]
    dec a
    ccf
    rst $38
    or c

jr_00d_6b4f:
    add hl, bc
    ld d, a
    db $e4
    ld b, h
    ld sp, $fe6d
    dec l
    ld a, a
    rst $38
    and $96
    ld c, d
    ld de, $5f70
    cp b
    ld a, b
    ld a, a
    rst $38
    cp $29
    ld c, b
    and c
    ld c, $44
    ld c, d
    ccf
    add sp, $63
    ld l, a
    rst $38
    ld sp, hl
    add hl, hl
    ld [de], a
    ld [$54c1], sp
    and l
    ld [hl], a
    ld sp, hl
    ccf
    rst $38
    rst $38
    add hl, de
    add $71
    ld c, l
    ld a, h
    ld [$ff37], sp
    db $fc
    sub d
    sub h
    sub d
    pop bc
    ld h, $30
    jr nz, @+$01

    db $eb
    ld d, l
    rlca
    ldh [$96], a
    jp nz, Jump_000_0cf1

    ld e, d
    ld [de], a
    rla
    rst $38
    jp nz, $c1b8

    inc h
    cp h
    inc l
    and l
    ld b, [hl]
    ld d, d
    dec e
    ld d, e
    rrca
    jp hl


    ld l, b
    call nz, $9bcc
    ld b, l
    ld [hl+], a
    add l
    ld c, h
    sub b
    sub d
    pop bc
    inc h
    ld h, a
    inc e
    ld c, d
    jr z, @+$32

    push bc
    jr nc, jr_00d_6bec

    ld de, $ef9d
    and e
    db $ec
    ld b, e
    jr nc, jr_00d_6c08

    ld c, h
    inc c
    scf
    ld b, c
    or b
    call nz, $81c7
    inc c
    ld de, $f611
    nop
    ld b, h
    or e
    ld l, d
    and h
    push bc
    ld d, e
    ld d, [hl]
    inc b
    xor c
    ld hl, $8dba
    ld de, $b9e4
    add l
    ld e, b
    call $8927
    ld c, [hl]
    ld b, h
    push bc
    ld b, $3a
    ld [de], a
    add hl, sp
    add c
    add hl, hl
    ld d, e

jr_00d_6bec:
    ld l, a
    daa
    sub b
    jp z, $3246

    adc b
    adc b
    ret nc

    add d
    ld l, $4d
    ld [hl+], a
    inc e
    ld h, b
    call z, Call_00d_48e3
    ld l, h
    call $e004
    sub e
    ld c, a
    add d
    ld c, [hl]
    add hl, bc
    ld d, l

jr_00d_6c08:
    ld l, b
    ld h, $d1
    adc [hl]
    ld b, a
    ld hl, sp+$14
    cpl
    ld c, [hl]
    ld c, e
    rst $38
    adc d
    adc a
    add l
    ret c

    cp b
    ld a, [hl+]
    ld a, [c]
    jr jr_00d_6c3d

    add d
    ld h, a
    add d
    inc de
    ld [de], a
    call z, Call_000_0f84
    and $18
    or d
    add hl, bc
    ld a, [hl+]
    cp d
    jr nc, @+$58

    ld h, a
    inc a
    db $d3
    pop de
    ld [de], a
    inc de
    ld a, [de]
    reti


    reti


    adc h
    ld b, d
    ld b, [hl]
    add hl, bc
    ld l, l
    ld d, d
    ld e, d
    add hl, hl

jr_00d_6c3d:
    db $10
    ld b, h
    ld b, l
    ret z

    ld a, [hl-]
    ld e, h
    ld l, $4a
    and $77
    add $5d
    or b
    ld a, [hl-]
    ld e, d
    add hl, bc
    ld [de], a
    ld h, b
    adc e
    dec b
    dec c
    ld [$12cc], a
    sbc c
    ld b, e
    add e
    inc h
    and d
    jp c, $c90c

    sbc h
    rra
    push de
    rrca
    ld c, l
    inc hl
    sbc b
    ld h, l
    ld e, c

jr_00d_6c66:
    jr @+$35

    adc e
    ret z

    daa
    ld [de], a
    inc e
    jp Jump_000_1882


    rst $20
    inc c
    ld h, l
    inc b
    ld sp, $80e2
    ld [hl], a
    or l
    ld d, l
    dec a
    ld h, $8c
    ld d, l
    xor d
    sub e
    jp Jump_00d_4961


    xor d
    inc d
    cp b
    ldh a, [rNR23]
    sbc b
    or h
    adc b
    jp nz, $923b

    ld [hl], e
    jr jr_00d_6c3d

    ld d, d
    inc hl
    ret nz

    ld b, l
    ld sp, $2a43
    ld c, l
    jp c, $9aa4

    ld sp, $0c86
    cp b
    dec e
    inc b
    ld h, e
    ld d, [hl]
    dec b
    ld d, h
    adc b
    rl a
    db $76
    ld c, d
    rst $38
    res 2, h
    xor b
    ld h, e
    sub c
    rrca
    ld [c], a
    ld [hl-], a
    ld l, l
    cp b
    add $56
    ld [hl+], a
    xor d
    ld b, l
    inc [hl]
    add e
    ret z

    ld h, c
    ld d, h
    adc c
    add l
    add hl, sp
    inc h
    adc b
    xor b
    sbc e
    jp z, Jump_000_13d4

    ld [$0d13], sp
    inc [hl]
    ld h, d
    ld e, d
    ld l, $51
    ld l, h
    jr nz, jr_00d_6c66

    ld [hl], h
    ld h, e
    jr jr_00d_6d0d

jr_00d_6cd9:
    jp nz, $2d2a

    dec [hl]
    ld c, b
    add d
    ldh a, [$4c]
    call nc, Call_000_23d5
    rra
    reti


    jr c, jr_00d_6d25

    adc h
    inc [hl]
    inc hl
    ld a, [de]
    dec h
    inc hl
    ld a, [hl]
    ld hl, $3c38
    ld [hl], d
    db $e3
    inc h
    ld h, h
    ld h, d
    ccf
    call z, $4510
    add hl, hl
    ld hl, sp-$1b
    adc e
    ld b, l
    db $fd
    ld h, $1a
    ld h, b
    ld h, b
    xor [hl]
    inc b
    adc h
    push de
    ld h, d
    ldh [$86], a
    add d

jr_00d_6d0d:
    rst $30
    ld h, d
    ld l, d
    ld sp, $198c
    ld e, $a2
    sub d
    ld h, d
    db $10
    ld b, [hl]
    ld [$aa86], sp
    sub e
    inc c
    ld [hl-], a
    ld [hl+], a
    inc h
    dec h
    ld d, h
    add $42

jr_00d_6d25:
    ld [$4ac1], sp
    ld a, h
    call $928b
    ld d, d
    jr z, jr_00d_6cd9

    ld c, h
    ld a, a
    rla
    ldh a, [$cb]
    ld e, b
    adc $a8
    sbc $92
    cp a
    ld a, a
    ld a, [c]
    inc de
    rst $00
    ld c, c
    cp e
    cp a
    add e
    ld [$24f2], sp
    jp $a38c


    add $91
    call z, Call_00d_6332
    ret


    sub d
    or d
    db $d3
    call z, $b594
    adc a
    ld b, d
    xor d
    adc [hl]
    db $fd
    and d
    adc d
    ld a, d
    ld [hl], a
    dec c
    ld a, [bc]
    add a

jr_00d_6d60:
    jr z, @+$7c

    ld a, b
    ld l, h
    ld a, [bc]
    ld b, h
    ld c, $16
    ld e, d
    sbc l
    db $eb
    ld de, $2c02
    sub c
    ld de, $a710
    ld l, l
    sub c
    sbc b
    push bc
    ld h, e
    sub b
    sbc l
    or b
    and d
    sub c
    add hl, hl
    add hl, sp
    ld d, a
    ld h, $d8
    jp hl


    ld c, $65
    inc c
    ld [hl], c
    ld b, h
    ld h, $08
    xor c
    ld de, $9609
    ld h, l
    ld l, c
    sbc d
    add e
    xor c
    ld a, [bc]
    dec bc
    dec e
    ldh a, [rNR51]
    ld a, [hl-]
    xor b
    ld c, h
    jr z, jr_00d_6d60

    add sp, -$3e
    sbc h
    ld c, [hl]
    cp b
    ld d, d
    ldh a, [rNR50]
    ld b, [hl]
    rst $30
    ld b, b
    and l
    jp z, $ca5b

    ld [hl-], a
    ld sp, $2610
    inc c
    ld h, l
    inc b
    sub l
    ld [hl-], a
    jp z, $5da8

    ld l, h
    add $10
    and b
    adc l
    ld b, $65
    inc de
    push bc
    ld d, d
    sbc b
    and e
    dec de
    ld b, h
    cp c
    xor l
    ld c, $61
    daa
    ld d, e

jr_00d_6dcb:
    inc b
    ld h, l
    and e
    daa
    add c
    add h
    inc de
    ld b, [hl]
    ld d, d
    inc c
    ld sp, $09ac
    ld c, $09
    call nc, $c0c8
    xor c
    add hl, bc
    adc h
    rra
    call z, $e499
    ld d, c
    ld l, b
    ld [hl], c
    ld l, e
    ld de, $ae18
    xor e
    inc bc
    ld h, $30
    inc sp
    add [hl]
    adc h
    ld d, h
    ld c, e
    adc d
    add hl, bc
    dec bc
    ld [hl], b
    push de
    ld d, b
    inc l
    adc [hl]
    ret nc

    inc l
    ld c, l
    sbc b
    ld c, c
    inc [hl]
    xor $d0
    ld sp, $15b4
    ld de, $2826
    cp c
    ld de, $73b4
    ld a, h
    ld h, l
    inc c
    ld [hl], b
    rst $00
    ld [de], a
    ld a, b
    sub $9b
    ld h, c
    db $10
    sbc [hl]
    inc l
    sbc e
    ld [hl+], a
    and a
    adc a
    ld hl, $7198
    add hl, bc
    push hl
    ld c, c
    jr c, jr_00d_6dcb

    ld b, a
    sbc d
    ret nz

    xor h
    cp a
    ld e, $7c
    ld c, l
    dec e
    ret nz

    ld b, h
    or d
    ld l, c
    dec d
    xor d
    ld c, [hl]
    ld h, $26
    adc h
    inc h
    ldh a, [rHDMA3]
    add l
    ret nc

    sbc l
    ld sp, $d754
    pop hl
    db $ec
    add sp, -$3f
    ld l, [hl]
    jp c, $8e73

    dec c
    adc h
    ld [hl], e
    sub a
    call z, $97b3
    call nc, $681e
    db $e4
    ld b, [hl]
    ret nc

    ret c

    inc [hl]
    pop bc
    ld c, l

jr_00d_6e5c:
    inc h
    add l
    rst $18
    adc e
    ld c, [hl]
    ld [$8260], sp
    dec l
    adc [hl]
    add hl, hl
    ld [hl-], a
    ld h, e
    sbc d
    ld d, l
    ld e, d
    ld a, $33
    ld h, [hl]
    jp c, $6b08

    ret


    jp nz, $12b1

    inc d
    inc [hl]
    and a
    inc b
    ld d, h
    ld h, b
    add l
    dec e
    ld l, a
    and c
    ld a, [bc]
    ld l, b
    sub l
    add sp, $3c
    ld b, h
    ld b, h
    ld h, [hl]
    cp d
    sbc $b4
    ld d, h
    ld l, [hl]
    pop bc
    ld b, h
    rst $00
    add b
    sbc l
    adc a
    dec hl
    daa
    ld h, $94
    ldh a, [rWY]
    adc h
    ld a, $6b

jr_00d_6e9c:
    cpl
    rla
    ld [hl-], a
    add h
    ld [hl], b
    and [hl]
    inc l
    dec c
    rst $00
    dec c
    dec h
    jr nz, @-$32

    ld [hl], e
    dec [hl]
    ld e, a
    ld b, a
    push bc
    add b
    ld d, l
    cp a
    inc d
    ld a, c
    jr c, @+$17

    ld d, h
    reti


    pop hl
    adc d
    ld [hl], d
    sbc a
    xor e
    ld a, a
    rst $38
    ld a, l
    dec d
    ld [hl+], a
    adc d
    and d
    ld e, $29
    sub d
    xor b
    ld a, [hl+]
    inc d
    add $05
    dec [hl]
    adc e
    ld h, h
    inc h
    ld a, l
    add hl, bc
    rla
    db $ed
    inc sp
    ld [hl], h
    and h
    ld d, $1c
    jr nz, jr_00d_6e5c

    ld a, [$1522]
    dec l
    sub d
    dec d
    add c
    ld a, [hl]
    pop bc
    ld b, c
    ld e, l
    jr nc, jr_00d_6e9c

    ld h, $05
    add sp, $1e
    add c
    add sp, $6a
    or l
    ld [$ffba], sp
    xor a
    ld d, a
    adc b
    and d
    ld e, [hl]
    ld h, $f3
    ld e, d
    xor d
    adc a
    ld a, [hl-]
    sub b
    ld c, h
    ld e, [hl]
    ld a, [hl-]
    and [hl]
    ldh [$8a], a
    ld d, e
    or [hl]
    ld c, b
    ld c, d
    adc [hl]
    ld a, [$f0a3]
    add hl, hl
    ld hl, sp-$56
    sbc h
    add hl, hl
    add hl, hl
    pop bc
    ld c, c
    pop bc
    db $10
    pop bc
    sub e
    inc bc
    sub b
    call nz, $c4c5
    ld h, $2f
    inc de
    jr c, jr_00d_6f92

    db $ec
    db $e4
    jp $9812


    ld a, c
    ld e, l
    or h
    rrca
    db $fd
    db $10
    sub b
    sub c
    and l
    dec [hl]
    sub b
    ldh a, [rLY]
    ld hl, $3156
    adc l
    ld l, c
    ld c, l
    ld c, a
    ld [de], a
    or h
    rrca
    and d
    add d
    ld h, l
    ld a, d
    sub b
    add $8c
    jp z, Jump_000_1131

    adc h
    ld b, e
    ld [de], a
    sub l
    inc d
    sbc b
    and a
    ld c, d
    call z, $2799
    ld d, l
    cp $96
    sbc l
    rst $10
    rst $20
    adc a
    ld b, a
    push hl
    add b
    ld b, h
    cp c
    ld a, [de]
    ld hl, $9ea3
    ld d, c
    ld h, h
    db $ec
    and [hl]
    db $e3
    and c
    ld b, d
    adc [hl]
    rla
    or [hl]
    db $fd
    dec de
    dec l
    ld [hl-], a
    ld [hl], c
    ld b, [hl]
    rst $30
    pop de
    or h
    pop de
    ldh [$bf], a
    adc b
    sbc [hl]
    or l
    cp c
    ld c, [hl]
    adc e
    rst $28
    ld d, e
    xor a
    sub d
    inc hl
    dec b
    jr nc, jr_00d_6fd2

    ld h, l
    inc b
    jp nc, $88d4

    dec [hl]
    ld e, b
    jr nz, @-$5b

    ld a, d
    db $fd

jr_00d_6f92:
    ld a, d
    xor d
    ret nc

    db $e3
    or [hl]
    adc a
    xor d
    sbc h
    xor c
    ld c, d
    ld [hl], e
    call nc, $f98b
    pop de
    dec sp
    rst $38
    inc e
    push af
    db $d3
    ld sp, $12aa
    db $e3
    inc d
    sub l
    add hl, de
    set 5, l
    add hl, hl
    adc h
    ret


    add d
    ld c, h
    ld de, $0c34
    ld [de], a
    add l
    rst $20
    ld b, [hl]
    adc h
    ld b, h
    ld h, d
    sbc e
    cp $9a
    sub $a4
    ld a, [hl+]
    ld b, e
    ld a, [$b5a9]
    db $eb
    inc sp
    ld d, h
    ret c

    ld l, c
    pop bc
    inc de
    jr jr_00d_7018

    pop hl

jr_00d_6fd2:
    ld h, b
    ld h, [hl]
    cp [hl]
    add hl, bc
    rst $38
    ld c, a
    dec h
    pop hl
    ld a, b
    pop bc
    ld a, a
    push af
    ld a, [hl-]
    and d
    inc d
    or a
    or [hl]
    xor e
    db $ed
    add hl, sp
    ld d, d
    call nc, Call_00d_639a
    dec hl
    sub e
    sbc d
    ld h, $d0
    and h
    ldh [$4e], a
    ld l, c
    ld h, $a3
    ld b, $a4
    add sp, -$6e
    ld h, h
    or h
    add [hl]
    ld a, [hl+]
    ld a, [hl-]
    ld d, d
    xor d
    pop hl
    ld b, l
    add hl, hl
    adc [hl]
    xor b
    or l
    db $f4
    dec h
    and [hl]
    adc e
    add c
    add hl, sp
    sbc d
    cp l
    dec bc
    ld b, e
    db $d3
    ld b, $04
    db $e3
    ld l, d
    and d
    ld e, a
    ld l, [hl]

jr_00d_7018:
    ld [c], a
    sbc b
    dec d
    jr c, jr_00d_7075

    ld sp, $2aa2
    xor b
    daa
    ld d, $9f
    and e
    dec d
    ld d, b
    ld l, d
    rla
    dec d
    ld [hl+], a
    rst $38
    sub a
    ld d, a
    ld hl, sp-$6c
    sub a
    ld [$efa2], a
    ld d, h
    inc d
    ld l, a
    add sp, -$33
    add c
    ld a, [de]
    rla
    db $f4
    jp $41f0


    ld b, [hl]
    adc l
    sub e
    cpl
    ld h, $4b
    cp a
    db $dd
    call $8c16
    inc d
    ld l, a
    db $fd
    call nc, $2ea8
    ldh [rHDMA2], a
    ld d, $a3
    inc b
    sbc e
    ld d, l
    ld a, [hl]
    add [hl]
    ld d, h
    push bc
    ld b, d
    and e
    dec h
    adc h
    ld a, [hl+]
    and e
    ld a, [hl-]
    xor d
    and c
    and l
    add hl, hl
    ld l, b
    ld a, [c]
    ld a, [hl+]
    and e
    pop af
    cp c
    ldh a, [$7a]
    rst $20
    sub h
    and c
    pop af
    sub d
    db $10

jr_00d_7075:
    cp b
    daa
    ld d, [hl]
    rra
    sbc c
    or h
    dec [hl]
    add hl, sp
    call Call_00d_7efb
    ld d, h
    inc c
    ld h, l
    ld l, d
    ld [hl], d
    ld a, [hl]
    rst $18
    and e
    ld b, $6b
    ld l, d
    ld [hl], c
    ccf
    ei
    ld a, a
    jr jr_00d_70ce

    ld e, d
    ld a, $72
    rst $38
    ei
    ret z

    db $e4
    ld [hl], c
    ld e, h
    ld sp, hl
    call $f87f
    and e
    or [hl]
    sub b
    di
    ld a, [$5f73]
    ld h, h
    or e
    db $eb
    ld d, d
    rst $38
    and d
    sbc h
    cp e
    inc de
    inc b
    rst $18
    rst $38
    rst $38
    ld de, $8f9c
    ld sp, hl
    ld d, b
    rst $08
    ld d, l
    ld e, b
    xor h
    sbc h
    ld c, a
    db $ec
    sub b
    sub e
    ccf
    ldh a, [$a0]
    rst $38
    sbc d
    inc l
    ccf
    ei
    or e
    ld [hl+], a
    cp a
    ld l, d

jr_00d_70cc:
    xor a
    rst $38

jr_00d_70ce:
    and $37
    sub e
    ccf
    rst $38
    xor $ed
    cp a
    rst $38
    rst $38
    cp $11
    sbc h
    ld b, h
    rst $38
    rst $38
    rst $38
    rst $18
    rst $38
    rst $38
    di
    ld sp, hl
    rst $00
    rst $38
    rst $38
    cp $35
    ld d, l
    ld c, e
    rst $38
    and $52
    cp b
    ld [hl-], a
    dec d
    rst $38
    rst $38
    ld b, $aa
    rst $38
    rst $38
    db $fd
    ld d, $85
    ld h, c
    inc de
    ld b, b
    push af
    ld d, b
    dec hl
    rst $18
    rst $38
    db $fd
    or c
    pop hl
    db $d3
    push de
    or h
    ld a, [hl]
    sub b
    ld b, h
    cp c
    sbc a
    ei
    ld a, [hl-]
    ld h, b
    ld b, a
    adc $a4
    ld d, d
    inc de
    scf
    db $fd
    dec b
    cp a
    push af
    ld a, h
    jp nc, Jump_00d_6885

    jp c, $944c

    ld a, [hl+]
    adc c
    ld c, [hl]
    ld l, e
    ldh [$8a], a
    db $dd
    dec h
    inc b
    sub $b6
    ld c, b
    cp c
    cp $0b
    jr c, jr_00d_7153

    add l
    ld h, c
    ld h, d
    inc sp
    adc l
    ld [$2b5a], sp
    jr c, jr_00d_70cc

    add c
    adc [hl]
    ret


    add c
    ld d, l
    and b
    and e
    adc [hl]
    ld l, b
    jp nz, $89f3

    adc a
    sub d
    call c, $a7ea
    ld h, l
    and c
    sbc l
    adc b
    jr z, jr_00d_7179

jr_00d_7153:
    or b
    jp nz, $a086

    xor a
    cp d
    sbc c
    ld [hl], h
    add a
    jr nc, jr_00d_719f

    add [hl]
    sub l
    ld h, [hl]
    ld e, e
    ld hl, $6470
    ld e, h
    ld [hl], c
    sbc $08
    ld sp, hl
    ldh [rOBP0], a
    jr z, jr_00d_71e3

    jp hl


    res 7, l
    db $fd
    dec e
    ld [$553c], sp
    inc e
    adc e
    push bc

jr_00d_7179:
    ld [hl], $e7
    ld a, [de]
    xor l
    ld d, h
    jr z, jr_00d_71a7

    rra
    add hl, de
    ld e, c
    db $f4
    ret nz

    ld [hl], a
    cp a
    ld a, [de]
    ld e, d
    xor d
    db $fd
    ld c, a
    add hl, hl
    adc c
    ld [hl], c
    sub [hl]
    or h
    sub a
    or e
    dec [hl]
    ld l, d
    and l
    jr c, @+$20

    ld d, $ae
    ld c, b
    ld a, b
    call Call_00d_7fa2

jr_00d_719f:
    ld d, [hl]
    ld c, h
    ld h, e
    inc d
    xor b
    jr nz, @-$5e

    ld b, d

jr_00d_71a7:
    jp nc, $8658

    or d
    inc h
    ld h, $4c
    call nc, $2ace
    inc hl
    sub $2d
    adc h
    ldh [$c8], a
    adc [hl]
    ld b, l
    inc e
    ld h, b
    sub h
    xor b
    rst $10
    jp nz, $92d2

    ld d, l
    jr nc, jr_00d_7205

    ld c, h
    ld h, e
    ld h, h
    db $10
    ld e, [hl]
    ld [$aa9a], a
    xor e
    jp nc, Jump_00d_6321

    inc d
    db $dd
    ld a, [de]
    ld c, h
    or e
    rrca
    sub c
    ld h, c
    ld b, e
    ld hl, $938b
    inc c
    dec e
    adc c
    ret z

    ret z

    ret


    ld a, [c]

jr_00d_71e3:
    add hl, hl
    ld b, d
    dec d
    adc h
    ld d, b
    sub e
    dec b
    and d
    sub h
    ret


    adc h
    ld l, d
    adc l
    ld h, l
    add hl, hl
    xor c
    add hl, bc
    ld [hl+], a
    adc h
    inc e
    sub h
    ld d, e
    ld a, [bc]
    ld c, [hl]
    dec d
    ld h, d
    ld l, c
    ld c, b
    ldh a, [$50]
    pop de
    ld c, c
    sub e
    ld a, [de]

jr_00d_7205:
    ld d, e
    and [hl]
    rst $38
    ld [$a534], a
    add hl, bc
    ld d, l
    ld a, a
    ld a, [$5555]
    ld d, e
    inc b
    jp nc, $a534

    ld d, l
    ld d, l
    ld a, [bc]
    xor c
    ld d, l
    and d
    db $d3
    push bc
    xor d
    and l
    ld d, l
    ld c, [hl]
    ld a, [hl+]
    inc a
    ld l, b
    sbc b
    push af
    inc h
    ld [hl], e
    inc [hl]
    ld a, [c]
    db $eb
    sub d
    sub [hl]
    ld h, e
    call $e89f
    ld [hl], e
    call nc, $09a9
    dec a
    ld l, b
    di
    dec d
    ld e, a
    ld sp, hl
    ld h, b
    ld c, a
    inc de
    rst $38
    rst $38
    ld a, [c]
    sub l
    adc a
    ld l, $aa
    rst $38
    ld c, h
    rst $30
    db $e3
    ld c, b
    ld c, d
    adc d
    ret


    push hl
    xor b
    ld b, h
    sub $8c
    and a
    ld [de], a
    add a

jr_00d_7256:
    dec hl
    ld l, c
    and h
    ld h, b
    ret nc

    ld d, d
    add hl, de
    ld c, c
    sbc l
    add l
    dec d
    ld [bc], a
    ld h, l
    push bc
    cp c
    ld a, d
    ld c, h
    ld [de], a
    ld e, e
    ld [bc], a
    ld c, $0d
    ld hl, $a7b6
    ld [hl-], a
    ld c, d
    ld c, h
    adc e
    inc bc
    rlca
    ld sp, $c330
    ld l, b
    ldh [$9c], a
    ld [$6cb8], a
    ld b, e
    add hl, de
    ld hl, $24e8

jr_00d_7283:
    jp z, Jump_000_0aa9

    ld e, d
    dec c
    dec [hl]
    ld d, b
    ld c, d
    ld l, e
    ld de, $2b11
    ld c, d
    xor d
    add a
    ld c, b
    ldh a, [$b1]
    adc e
    db $10
    sbc h
    dec c
    ld d, l
    ld c, e
    ld c, e
    inc de
    ld [bc], a
    pop de
    adc e
    inc d
    ret


    jr nc, jr_00d_7256

    ld b, d
    ld a, $3e
    ld a, $09
    inc c
    inc d
    ld h, b
    cp h
    ld e, l
    or d
    call nz, Call_00d_42ac
    add d
    sub h
    xor c
    add hl, bc
    and d
    jr jr_00d_7283

    ld b, h
    reti


    cpl
    rlca
    dec d
    dec c
    ld d, h
    ld c, e
    inc c
    ld b, d
    ld h, e
    ld [bc], a
    dec [hl]
    ld d, c
    dec l
    and c
    inc e
    dec hl
    sub c
    ld b, h
    jp z, $0c5c

    ld a, [bc]
    xor d
    call nz, $2aa6
    rra
    db $e3
    ld [hl], h
    inc c
    ld h, e
    ld b, c
    push hl
    ld b, h
    cpl
    sub a
    ld d, l
    ld d, [hl]
    add $0b
    ld a, [bc]
    ld l, e
    and $2f
    ld de, $78e4
    or h
    ld h, d
    ret


    add hl, bc
    pop de
    ld b, h
    ld sp, hl
    ld l, c
    sub e
    ld sp, $780a
    jp nc, Jump_000_315b

    rst $20
    ret z

    ld [hl], $c6
    add hl, bc

Jump_00d_72fe:
    push hl
    pop bc
    sbc b
    or d
    ld a, c
    call $ba20
    ld a, d
    sub b
    cp [hl]
    sbc [hl]
    or l
    ld b, a
    sub h
    sub b
    jp z, $f991

    ld [c], a
    ld h, h
    ld sp, hl
    rra
    ld sp, hl
    inc e
    ld a, c
    ld [hl], c
    inc de
    ld d, c
    and b
    ld b, h
    cp d
    sub l
    inc [hl]

jr_00d_7320:
    ld d, l
    ld d, l
    xor d
    xor d
    and e
    ld [hl], $a5

jr_00d_7327:
    ld d, l
    ld e, a
    rst $38
    jp nz, Jump_000_29a9

    ret z

    ld [$9d5a], a
    xor d
    inc sp
    adc l
    cp [hl]
    jr c, jr_00d_7320

    jr nc, @+$7e

    cp [hl]
    ld c, h
    sub d
    ld [hl+], a
    rst $28
    daa
    ld a, [bc]
    ld sp, $928b
    jp nc, $a3f0

    inc b
    ld de, $c27c
    ldh a, [$57]
    ret c

    pop bc
    ld l, $49
    ld e, c
    or $22
    adc h
    jr @-$45

    jr jr_00d_737e

    jr nc, @-$72

    ld h, b
    ld d, d
    and l
    sub a
    ld c, [hl]
    jr c, jr_00d_7327

    xor b
    ld a, [$d2dd]
    and [hl]
    xor d
    ld e, a
    sbc b
    jp nc, $d896

    ld a, c
    ld a, h
    ld h, e
    ld b, l
    or e
    and c
    ld l, a
    ld a, [$5585]
    ld [bc], a
    sbc b
    add hl, sp
    ld de, $644e
    sbc h
    inc d

jr_00d_737e:
    db $10
    ld a, c
    sbc e
    ld b, l
    xor d
    sub c
    ld b, c
    ld a, c
    add d
    cp h
    push bc
    ld h, $14
    ld [hl], $90
    rst $08
    ldh [$b1], a
    ld d, d
    and d
    pop bc
    inc hl
    ld l, b
    ld a, [hl]
    cp $0a
    ld d, l
    inc hl
    dec d
    inc hl
    ld a, d
    ld de, $7749
    add $0c
    and c
    ld [hl], c
    jp $91f2


    ld h, b
    jp z, Jump_00d_5472

    ld e, h
    ld a, l
    add b

Call_00d_73ae:
    call Call_000_373e
    ld a, $01
    ld [$cf07], a
    ld b, a
    ld hl, $724c
    call Call_000_3620
    ld hl, $7430
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_00d_7420

    dec a
    ld [$cfb2], a
    ld hl, $cd4f
    xor a
    ld [hl+], a
    ld [hl], $02
    ld a, $4c
    call Call_000_3e9d
    call Call_000_3e04
    call Call_00d_79a2
    call Call_000_36ca
    ld b, $05
    call Call_000_3e1f
    call Call_000_3e0c
    ld a, $e4
    ldh [rOBP0], a
    ld hl, $d6af
    set 6, [hl]
    xor a
    ld [$d073], a
    ld hl, $cd3d
    ld bc, $0014
    call Call_000_372a
    call Call_00d_7447
    ld hl, $d6af
    res 6, [hl]
    xor a
    ld [$d073], a
    call Call_000_3e04
    ld a, $01
    ld [$cfb2], a
    call Call_000_3e1d
    call Call_000_3e38
    call Call_000_1ba5

jr_00d_7420:
    call Call_000_374a
    call Call_000_3e07
    call Call_000_3e0c
    ld a, [$cc5e]
    push af
    jp Jump_000_14ba


    db $ed
    add hl, hl
    adc a
    ld l, b
    sub e
    sbc l
    adc e
    db $e3
    xor e
    ld h, $7f
    or c
    reti


    rst $20
    ld c, a
    or c
    cp a
    dec sp
    rst $08
    cp l

Jump_00d_7444:
    or [hl]
    and $57

Call_00d_7447:
Jump_00d_7447:
    call Call_00d_784e
    xor a
    ld hl, $cd4a
    ld [hl+], a
    ld [hl], a
    call Call_00d_7859
    ld hl, $752c
    call Call_000_3c79
    call Call_000_3761

jr_00d_745c:
    ld a, $03
    ld [$cc29], a
    ld a, $02
    ld [$cc28], a
    ld a, $0c
    ld [$cc24], a
    ld a, $0f
    ld [$cc25], a
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    ld [$cc37], a
    ld hl, $c48a
    ld b, $05
    ld c, $04
    call Call_000_03d2
    ld hl, $c4a0
    ld de, $7510
    call Call_000_0405
    call Call_000_3b08
    and $02
    jp nz, Jump_000_376d

    ld a, [$cc26]
    ld b, a
    ld a, $03
    sub b
    ld [$cd50], a
    ld hl, $d523
    ld c, a
    ld a, [hl+]
    and a
    jr nz, jr_00d_74b3

    ld a, [hl]
    cp c
    jr nc, jr_00d_74b3

    ld hl, $7545
    call Call_000_3c79
    jr jr_00d_745c

jr_00d_74b3:
    call Call_000_376d
    call Call_00d_783b
    call Call_00d_78cf
    call Call_00d_7562
    ld a, $04
    ld hl, $cd4d
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    call Call_000_3790
    ld a, $c0
    call Call_000_0e45
    ld hl, $753e
    call Call_000_3c79
    call Call_00d_758f
    call Call_00d_766a
    ld hl, $d523
    ld a, [hl+]
    or [hl]
    jr nz, jr_00d_74ed

    ld hl, $751c
    call Call_000_3c79
    ld c, $3c
    jp Jump_000_3781


jr_00d_74ed:
    ld hl, $7552
    call Call_000_3c79
    ld hl, $c49e
    ld bc, $0d0f
    xor a
    ld [$d0f1], a
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$cc26]
    and a
    ret nz

    call Call_00d_78c8
    jp Jump_00d_7447


    db $ed
    inc l
    sbc $42
    ld hl, sp-$31
    or d
    ld c, [hl]
    rst $30
    rst $08
    or d
    ld d, b
    db $ed
    add hl, hl
    ld b, $69
    ld h, $4f
    push bc
    cp b
    push bc
    rst $18
    pop bc
    ldh [$df], a
    ret nz

    ld d, [hl]
    ld d, a
    db $ed
    add hl, hl
    jp z, $dd68

    ld c, a
    push bc
    sbc $cf
    or d
    ld a, a
    or [hl]
    cp c
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    add hl, hl
    db $fc
    ld l, b
    sub e
    rst $20
    ld d, a
    db $ed
    add hl, hl
    db $e3
    ld l, b
    ld h, $7f
    ret nz

    ret c

    rst $08
    cp [hl]
    sbc $e7
    ld e, b
    db $ed
    add hl, hl
    dec e
    ld l, c
    rst $30
    or [hl]
    or d
    ld c, a
    or c
    cp a
    dec sp
    rst $08
    cp l
    or [hl]
    and $57

Call_00d_7562:
    ld hl, $cd4c
    bit 7, [hl]
    ret nz

    ld a, [$d073]
    and a
    jr nz, jr_00d_7583

    call Call_000_3e8c
    and a
    jr z, jr_00d_7586

    ld b, a
    ld a, [$cc5b]
    cp b
    jr c, jr_00d_758c

    ld a, $d2
    cp b
    jr c, jr_00d_7583

    ld [hl], $00
    ret


jr_00d_7583:
    set 6, [hl]
    ret


jr_00d_7586:
    ld a, $3c
    ld [$d073], a
    ret


jr_00d_758c:
    set 7, [hl]
    ret


Call_00d_758f:
    ld c, $14

jr_00d_7591:
    push bc
    call Call_00d_790d
    call Call_00d_791d
    call Call_00d_792d
    ld c, $02
    call Call_000_3781
    pop bc
    dec c
    jr nz, jr_00d_7591

    xor a
    ld [$cd3d], a

jr_00d_75a8:
    call Call_00d_797c
    call Call_00d_75c1
    call Call_00d_75dd
    call Call_00d_75f9
    ret c

    ld a, [$cf15]
    xor $01
    inc a
    ld c, a
    call Call_000_3781
    jr jr_00d_75a8

Call_00d_75c1:
    ld a, [$cd3d]
    cp $01
    jr c, jr_00d_75da

    ld de, $cd3e
    ld a, [de]
    rra
    jr nc, jr_00d_75da

    ld hl, $cd4d
    ld a, [hl]
    and a
    ret z

    dec [hl]
    call Call_00d_760e
    ret nz

jr_00d_75da:
    jp Jump_00d_790d


Call_00d_75dd:
    ld a, [$cd3d]
    cp $02
    jr c, jr_00d_75f6

    ld de, $cd3f
    ld a, [de]
    rra
    jr nc, jr_00d_75f6

    ld hl, $cd4e
    ld a, [hl]
    and a
    ret z

    dec [hl]
    call Call_00d_7634
    ret z

jr_00d_75f6:
    jp Jump_00d_791d


Call_00d_75f9:
    ld a, [$cd3d]
    cp $03
    jr c, jr_00d_7609

    ld de, $cd40
    ld a, [de]
    rra
    jr nc, jr_00d_7609

    scf
    ret


jr_00d_7609:
    call Call_00d_792d
    and a
    ret


Call_00d_760e:
    call Call_00d_77b8
    ld hl, $cd41
    ld a, [$cd4c]
    and $80
    jr nz, jr_00d_7622

    inc hl
    ld a, [hl]
    cp $0a
    jr nz, jr_00d_762d

    ret


jr_00d_7622:
    ld c, $03

jr_00d_7624:
    ld a, [hl+]
    cp $02
    jr c, jr_00d_762d

    dec c
    jr nz, jr_00d_7624

    ret


jr_00d_762d:
    inc a
    ld hl, $cd4d
    ld [hl], $00
    ret


Call_00d_7634:
    call Call_00d_77ac
    ld a, [$cd4c]
    and $80
    jr nz, jr_00d_7644

    call Call_00d_7650
    ret nz

    jr jr_00d_764b

jr_00d_7644:
    call Call_00d_7650
    ld a, [de]
    cp $07
    ret nc

jr_00d_764b:
    xor a
    ld [$cd4e], a
    ret


Call_00d_7650:
    ld hl, $cd41
    ld de, $cd44
    ld a, [de]
    cp [hl]
    ret z

    inc de
    ld a, [de]
    cp [hl]
    ret z

    inc hl
    cp [hl]
    ret z

    inc hl
    cp [hl]
    ret z

    inc de
    ld a, [de]
    cp [hl]
    ret z

    dec de
    dec de
    ret


Call_00d_766a:
Jump_00d_766a:
    call Call_00d_77a0
    ld a, [$cd50]
    cp $02
    jr z, jr_00d_7695

    cp $01
    jr z, jr_00d_76b1

    ld hl, $cd41
    ld de, $cd45
    ld bc, $cd49
    call Call_00d_779a
    jp z, Jump_00d_76e6

    ld hl, $cd43
    ld de, $cd45
    ld bc, $cd47
    call Call_00d_779a
    jr z, jr_00d_76e6

jr_00d_7695:
    ld hl, $cd43
    ld de, $cd46
    ld bc, $cd49
    call Call_00d_779a
    jr z, jr_00d_76e6

    ld hl, $cd41
    ld de, $cd44
    ld bc, $cd47
    call Call_00d_779a
    jr z, jr_00d_76e6

jr_00d_76b1:
    ld hl, $cd42
    ld de, $cd45
    ld bc, $cd48
    call Call_00d_779a
    jr z, jr_00d_76e6

    ld a, [$cd4c]
    and $c0
    jr z, jr_00d_76cc

    ld hl, $cd4f
    dec [hl]
    jr nz, jr_00d_76d7

jr_00d_76cc:
    ld hl, $7794
    call Call_000_3c79

Jump_00d_76d2:
    xor a
    ld [$c002], a
    ret


jr_00d_76d7:
    call Call_00d_792d
    call Call_000_0b31
    call Call_00d_792d
    call Call_000_0b31
    jp Jump_00d_766a


Jump_00d_76e6:
jr_00d_76e6:
    ld a, [$cd4c]
    and $c0
    jr z, jr_00d_76d7

    and $80
    jr nz, jr_00d_76f6

    ld a, [hl]
    cp $07
    jr c, jr_00d_76d7

jr_00d_76f6:
    ld a, [hl]
    sub $02
    ld [$cd41], a
    ld hl, $776f
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    push de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $cf45
    ld bc, $0004
    call Call_000_01bb
    pop hl
    ld de, $771a
    push de
    jp hl


jr_00d_771a:
    ldh a, [rBGP]
    xor $40
    ldh [rBGP], a
    ld c, $05
    call Call_000_3781
    dec b
    jr nz, jr_00d_771a

    ld hl, $cd4a
    ld [hl], d
    inc hl
    ld [hl], e
    call Call_00d_7859
    ld hl, $7747
    call Call_000_3c79
    call Call_000_38ae
    call Call_00d_7865
    call Call_00d_7859
    ld a, $e4
    ldh [rOBP0], a
    jp Jump_00d_76d2


    ld [$cdc5], sp
    ld [hl+], a
    ld a, b
    ld hl, $7755
    pop bc
    inc bc
    inc bc
    inc bc
    inc bc
    ret


    db $ed
    dec l
    or a
    ld h, l
    db $db
    rst $18
    ret nz

    rst $20
    ld c, a
    adc c
    add c
    xor e
    ld d, b
    ld bc, $cf45
    nop
    rst $08
    or d
    ld a, a
    or d
    ret nz

    jr nc, @-$47

    rst $20
    ld d, a
    ld a, [$8777]
    ld [hl], a
    db $eb
    ld [hl], a
    adc e
    ld [hl], a
    rst $08
    ld [hl], a
    adc a
    ld [hl], a
    db $dd
    ld [hl], a
    sub c
    ld [hl], a
    db $dd
    ld [hl], a
    sub c
    ld [hl], a
    db $dd
    ld [hl], a
    sub c
    ld [hl], a
    ld sp, hl
    or $f6
    ld d, b
    rst $30
    or $f6
    ld d, b
    cp $50
    rst $30
    ei
    ld d, b
    db $ed
    add hl, hl
    dec hl
    ld l, c
    db $e3
    ld e, b

Call_00d_779a:
    ld a, [de]
    cp [hl]
    ret nz

    ld a, [bc]
    cp [hl]
    ret


Call_00d_77a0:
    ld de, $cd47
    ld hl, $7b27
    ld a, [$cd40]
    call Call_00d_77c1

Call_00d_77ac:
    ld de, $cd44
    ld hl, $7b03
    ld a, [$cd3f]
    call Call_00d_77c1

Call_00d_77b8:
    ld de, $cd41
    ld hl, $7adf
    ld a, [$cd3e]

Call_00d_77c1:
    ld c, a
    ld b, $00
    add hl, bc
    ld c, $03

jr_00d_77c7:
    ld a, [hl+]
    ld [de], a
    inc de
    inc hl
    dec c
    jr nz, jr_00d_77c7

    ret


    ld hl, $d073
    ld a, [hl]
    and a
    jr z, jr_00d_77d7

    dec [hl]

jr_00d_77d7:
    ld b, $02
    ld de, $0008
    ret


    ld hl, $d073
    ld a, [hl]
    and a
    jr z, jr_00d_77e5

    dec [hl]

jr_00d_77e5:
    ld b, $04
    ld de, $000f
    ret


    ld a, $94
    call Call_000_0e45
    xor a
    ld [$cd4c], a
    ld b, $08
    ld de, $0064
    ret


    ld hl, $781a
    call Call_000_3c79
    ld a, $89
    call Call_000_0e45
    call Call_000_3e8c
    cp $80
    ld a, $00
    jr c, jr_00d_7811

    ld [$cd4c], a

jr_00d_7811:
    ld [$d073], a
    ld b, $14
    ld de, $012c
    ret


    db $ed
    add hl, hl
    scf
    ld l, c
    rst $20
    ld d, b
    ld a, [bc]
    ld d, b
    ld hl, $c4ba
    ld a, [$cd41]
    add $25
    ld [hl+], a
    inc a
    ld [hl-], a
    inc a
    ld de, $ffec
    add hl, de
    ld [hl+], a
    inc a
    ld [hl], a
    ld hl, $c4f2
    ld [hl], $ee
    ret


Call_00d_783b:
    ld hl, $cd4b
    ld a, [$cd50]
    ld [hl-], a
    xor a
    ld [hl+], a
    ld de, $d524
    ld c, $02
    ld a, $0c
    call Call_000_3e9d

Call_00d_784e:
    ld hl, $c3b9
    ld de, $d523
    ld c, $02
    jp Jump_000_2fc4


Call_00d_7859:
    ld hl, $c3bf
    ld de, $cd4a
    ld bc, $8204
    jp Jump_000_3c8f


Call_00d_7865:
    ld a, $01
    ld [$c002], a
    call Call_000_3790
    ld hl, $cd46
    xor a
    ld [hl+], a
    inc a
    ld [hl], a
    ld a, $05
    ld [$d068], a

jr_00d_7879:
    ld a, [$cd4b]
    ld l, a
    ld a, [$cd4a]
    ld h, a
    or l
    ret z

    ld de, $ffff
    add hl, de
    ld a, l
    ld [$cd4b], a
    ld a, h
    ld [$cd4a], a
    ld hl, $cd47
    ld de, $d524
    ld c, $02
    ld a, $0b
    call Call_000_3e9d
    call Call_00d_784e
    call Call_00d_7859
    ld a, $bf
    call Call_000_0e45
    ld a, [$d068]
    dec a
    jr nz, jr_00d_78b5

    ldh a, [rOBP0]
    xor $40
    ldh [rOBP0], a
    ld a, $05

jr_00d_78b5:
    ld [$d068], a
    ld a, [$cd41]
    cp $07
    ld c, $08
    jr nc, jr_00d_78c3

    srl c

jr_00d_78c3:
    call Call_000_3781
    jr jr_00d_7879

Call_00d_78c8:
    ld a, $23
    ld [$d067], a
    jr jr_00d_78dd

Call_00d_78cf:
    ld a, $14
    ld [$d067], a
    ld a, [$cd50]
    dec a
    jr z, jr_00d_78f5

    dec a
    jr z, jr_00d_78e9

jr_00d_78dd:
    ld hl, $c3cb
    call Call_00d_78f8
    ld hl, $c46b
    call Call_00d_78f8

jr_00d_78e9:
    ld hl, $c3f3
    call Call_00d_78f8
    ld hl, $c443
    call Call_00d_78f8

jr_00d_78f5:
    ld hl, $c41b

Call_00d_78f8:
    ld a, [$d067]
    ld [hl], a
    ld bc, $000d
    add hl, bc
    ld [hl], a
    ld bc, $0007
    add hl, bc
    inc a
    ld [hl], a
    ld bc, $000d
    add hl, bc
    ld [hl], a
    ret


Call_00d_790d:
Jump_00d_790d:
    ld bc, $7adf
    ld de, $cd3e
    ld hl, $c300
    ld a, $30
    ld [$d05e], a
    jr jr_00d_793b

Call_00d_791d:
Jump_00d_791d:
    ld bc, $7b03
    ld de, $cd3f
    ld hl, $c330
    ld a, $50
    ld [$d05e], a
    jr jr_00d_793b

Call_00d_792d:
Jump_00d_792d:
    ld bc, $7b27
    ld de, $cd40
    ld hl, $c360
    ld a, $70
    ld [$d05e], a

jr_00d_793b:
    ld a, $58
    ld [$d05f], a
    push de
    ld a, [de]
    ld d, b
    add c
    ld e, a
    jr nc, jr_00d_7948

    inc d

jr_00d_7948:
    ld a, [$d05f]
    ld [hl+], a
    ld a, [$d05e]
    ld [hl+], a
    ld a, [de]
    ld [hl+], a
    ld a, $80
    ld [hl+], a
    ld a, [$d05f]
    ld [hl+], a
    ld a, [$d05e]
    add $08
    ld [hl+], a
    ld a, [de]
    inc a
    ld [hl+], a
    ld a, $80
    ld [hl+], a
    inc de
    ld a, [$d05f]
    sub $08
    ld [$d05f], a
    cp $28
    jr nz, jr_00d_7948

    pop de
    ld a, [de]
    inc a
    cp $1e
    jr nz, jr_00d_797a

    xor a

jr_00d_797a:
    ld [de], a
    ret


Call_00d_797c:
    call Call_000_0b31
    call Call_000_3879
    ldh a, [$b5]
    and $01
    ret z

    ld hl, $cd3d
    ld a, [hl]
    dec a
    ld de, $cd4d
    jr z, jr_00d_799d

    dec a
    ld de, $cd4e
    jr z, jr_00d_799d

jr_00d_7997:
    inc [hl]
    ld a, $be
    jp Jump_000_0e45


jr_00d_799d:
    ld a, [de]
    and a
    ret nz

    jr jr_00d_7997

Call_00d_79a2:
    call Call_000_0167
    ld hl, $4a47
    ld de, $8000
    ld bc, $01c0
    ld a, $1e
    call Call_000_028c
    ld hl, $7b4b
    ld de, $9000
    ld bc, $0250
    ld a, $0d
    call Call_000_028c
    ld hl, $4a47
    ld de, $9250
    ld bc, $01c0
    ld a, $1e
    call Call_000_028c
    ld hl, $79ef

Jump_00d_79d2:
    ld de, $c3a0
    ld bc, $00f0
    call Call_000_01bb
    call Call_000_0181
    ld hl, $cd3e
    ld a, $1c
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    call Call_00d_790d
    call Call_00d_791d
    jp Jump_00d_792d


    nop
    nop
    nop
    nop
    nop
    ld [bc], a
    inc bc
    inc b
    dec b
    nop
    nop
    ld b, $07
    ld [$0009], sp
    nop
    nop
    nop
    nop
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0a01
    ld c, $0b
    inc hl
    inc e
    ld e, $1f
    inc e
    inc e
    ld e, $1f
    inc e
    inc e
    ld e, $1f
    inc e
    inc hl
    ld a, [bc]
    ld c, $0b
    inc c
    rrca
    dec c
    inc h
    dec e
    jr nz, jr_00d_7a53

    dec e
    dec e
    jr nz, jr_00d_7a57

    dec e
    dec e
    jr nz, @+$23

    dec e
    inc h
    inc c
    rrca
    dec c
    ld a, [bc]
    db $10
    dec bc
    inc hl
    ld d, $22
    ld [hl+], a
    ld d, $16
    ld [hl+], a
    ld [hl+], a
    ld d, $16
    ld [hl+], a
    ld [hl+], a
    ld d, $23
    ld a, [bc]
    db $10
    dec bc

jr_00d_7a53:
    inc c
    ld de, $240d

jr_00d_7a57:
    ld d, $17
    rla
    ld d, $16
    rla
    rla
    ld d, $16
    rla
    rla
    ld d, $24
    inc c
    ld de, $0a0d
    ld [de], a
    dec bc
    inc hl
    ld d, $17
    rla
    ld d, $16
    rla
    rla
    ld d, $16
    rla
    rla
    ld d, $23
    ld a, [bc]
    ld [de], a
    dec bc
    inc c
    inc de
    dec c
    inc h
    ld d, $17
    rla
    ld d, $16
    rla
    rla
    ld d, $16
    rla
    rla
    ld d, $24
    inc c
    inc de
    dec c
    ld a, [bc]
    db $10
    dec bc
    inc hl
    ld d, $17
    rla
    ld d, $16
    rla
    rla
    ld d, $16
    rla
    rla
    ld d, $23
    ld a, [bc]
    db $10
    dec bc
    inc c
    ld de, $240d
    ld d, $22
    ld [hl+], a
    ld d, $16
    ld [hl+], a
    ld [hl+], a
    ld d, $16
    ld [hl+], a
    ld [hl+], a
    ld d, $24
    inc c
    ld de, $0a0d
    ld c, $0b
    inc hl
    nop
    jr @+$1b

    nop
    nop
    jr @+$1b

    nop
    nop
    jr jr_00d_7adf

    nop
    inc hl
    ld a, [bc]
    ld c, $0b
    inc c
    rrca
    dec c
    inc h
    ld bc, $1b1a
    ld bc, $1a01
    dec de
    ld bc, $1a01
    dec de
    ld bc, $0c24
    rrca
    dec c

jr_00d_7adf:
    nop
    ld [bc], a
    inc d
    ld d, $0c
    ld c, $04
    ld b, $08
    ld a, [bc]
    nop
    ld [bc], a
    inc c
    ld c, $10
    ld [de], a
    inc b
    ld b, $08
    ld a, [bc]
    nop
    ld [bc], a
    inc d
    ld d, $10
    ld [de], a
    inc b
    ld b, $08
    ld a, [bc]
    nop
    ld [bc], a
    inc d
    ld d, $0c
    ld c, $00
    ld [bc], a
    inc c
    ld c, $08
    ld a, [bc]
    db $10
    ld [de], a
    inc d
    ld d, $04
    ld b, $08
    ld a, [bc]
    inc c
    ld c, $10
    ld [de], a
    ld [$040a], sp
    ld b, $0c
    ld c, $10
    ld [de], a
    ld [$140a], sp
    ld d, $00
    ld [bc], a
    inc c
    ld c, $08
    ld a, [bc]
    nop
    ld [bc], a
    db $10
    ld [de], a
    inc c
    ld c, $08
    ld a, [bc]
    inc d
    ld d, $10
    ld [de], a
    inc c
    ld c, $08
    ld a, [bc]
    inc d
    ld d, $10
    ld [de], a
    inc c
    ld c, $08
    ld a, [bc]
    inc d
    ld d, $10
    ld [de], a
    inc b
    ld b, $00
    ld [bc], a
    db $10
    ld [de], a
    inc c
    ld c, $c3
    cp l
    jp Jump_000_003c


    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    xor d
    nop
    ld d, l
    nop
    xor d
    nop
    nop
    rst $38
    rst $38
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
    nop
    rst $38
    nop
    ld [c], a
    nop
    adc $00
    adc $00
    jp z, $e600

    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    jr nc, jr_00d_7b82

jr_00d_7b82:
    ld d, e
    nop
    ld d, b
    nop
    inc sp
    nop
    ld d, b
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    adc h
    nop
    sub h
    nop
    sub h
    nop
    sub h
    nop
    adc h
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    add a
    nop
    rst $08
    nop
    rst $08
    nop
    rst $08
    nop
    rst $08
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    inc e
    nop
    add hl, hl
    nop
    add hl, hl
    nop
    jr jr_00d_7bb8

jr_00d_7bb8:
    add hl, sp
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rlc b
    ld c, e
    nop
    ld c, e
    nop
    ld h, a
    nop
    ld h, a
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    add $00
    sub d
    nop
    sub d
    nop
    sub d
    nop
    rst $00
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    ld d, b
    nop
    ld e, c
    nop
    ld e, c
    nop
    ld e, c
    nop
    add hl, sp

jr_00d_7be9:
    nop
    rst $38
    nop
    rst $38
    rlca
    rst $38
    jr jr_00d_7be9

    daa
    ldh [$5f], a
    ret nz

    ld e, a
    ret nz

    cp a
    add b
    cp a
    add b
    nop
    rst $38
    ldh [rIE], a
    jr @+$21

    call nz, $fa07
    inc bc
    ld a, [$fd03]
    ld bc, $01fd
    cp a
    add b
    cp a
    add b
    ld e, a
    ret nz

    ld e, a
    ret nz

    daa
    ldh [rNR23], a
    ld hl, sp+$07
    rst $38
    nop
    rst $38
    db $fd
    ld bc, $01fd
    ld a, [$fa03]
    inc bc
    call nz, $1807
    rra
    ldh [rIE], a
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    ld a, [hl]
    jp $99c3


    sbc c
    di
    di
    ld sp, hl
    ld sp, hl
    sbc c
    sbc c
    jp $ffc3


    ld a, [hl]
    rst $38
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    ld a, [hl]
    jp $99c3


    sbc c
    pop af
    pop af
    rst $20
    ld h, a
    call $81cd
    add c
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    inc a
    rst $20
    db $e4
    add a
    add h
    rst $20
    db $e4
    rst $20
    inc h
    rst $20
    rst $20
    add c
    add c
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    rst $38
    rst $38
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
    nop
    rst $38
    inc a
    rst $38
    ld h, [hl]
    rst $20
    ld e, d
    jp $c35a


    ld h, [hl]
    rst $20
    inc a
    rst $38
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
    jp $c3a5


    and l
    jp $c3a5


    and l
    jp $c3a5


    and l
    jp $c3a5


    and l
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    nop
    nop
    rst $38
    ld a, a
    rst $38
    rst $38
    rst $38
    rst $38
    ret nz

    ldh [$df], a
    ldh [$df], a
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    cp $ff
    rst $38
    rst $38
    rst $38
    inc bc
    rlca
    ei
    rlca
    ei
    ldh [$df], a
    ldh [$df], a
    ldh [$df], a
    rst $38
    ret nz

    rst $38
    rst $38
    ld a, a
    rst $38
    nop
    rst $38
    nop
    rst $38
    rlca
    ei
    rlca
    ei
    rlca
    ei
    rst $38
    inc bc
    rst $38
    rst $38
    cp $ff
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    jr @+$01

    ld h, [hl]
    rst $20
    and l
    cp l
    cp l
    jp $81e7


    jp Jump_00d_4281


    jp $c366


    inc a
    rst $20
    jr @+$01

    nop
    rst $38
    nop
    rst $38
    jp $c33c


    cp l
    jr nc, @+$01

    dec sp
    rst $28
    scf
    db $ec
    ld h, $f8
    ld e, $f0
    ccf
    add sp, $77
    call nz, $c677
    inc c
    rst $38
    call c, $ecf7
    scf
    ld h, h
    rra
    ld a, b
    rrca
    db $fc
    rla
    xor $23

jr_00d_7d49:
    xor $63
    cpl
    ldh [rNR44], a
    ld [c], a
    jr jr_00d_7d49

    rla
    rst $30
    inc c
    db $fc
    inc bc
    rst $38
    rst $38
    nop
    rst $38
    rst $38
    db $f4
    rlca
    call nz, Call_000_1847
    rra
    add sp, -$11
    jr nc, @+$41

    ret nz

    rst $38
    rst $38
    nop
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
    inc a
    rst $38
    ld h, [hl]
    rst $38
    ld e, d
    rst $38
    ld e, d
    rst $38
    ld h, [hl]
    rst $38
    inc a
    rst $38
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
    call Call_000_36ea
    ld hl, $c3f3
    ld b, $07
    ld c, $0c
    call Call_000_03d2
    ld hl, $c41c
    ld de, $d11d
    call Call_000_0405
    ld hl, $c46c
    ld de, $d806
    call Call_000_0405
    ld hl, $c449
    ld a, $69
    ld [hl+], a
    ld [hl], $6a
    xor a
    ld [$cfb2], a
    ld hl, $6cdb
    ld b, $0e
    call Call_000_3620

jr_00d_7dce:
    ld c, $96
    jp Jump_000_3781


jr_00d_7dd3:
    ld hl, $ccd3
    ld a, [$cd38]
    dec a
    ld [$cd38], a
    ld d, $00
    ld e, a
    add hl, de
    ld d, h
    ld e, l
    ld hl, $7e18
    ld a, [$d0f4]

jr_00d_7de9:
    add a
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e1]
    ld c, a

jr_00d_7df9:
    ld a, [hl+]
    cp b
    jr nz, jr_00d_7e13

    ld a, [hl+]
    cp c
    jr nz, jr_00d_7e14

    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_00d_7e04:
    ld a, [hl+]
    cp $ff
    ret z

    ld [de], a
    inc de
    ld a, [$cd38]
    inc a
    ld [$cd38], a
    jr jr_00d_7e04

jr_00d_7e13:
    inc hl

jr_00d_7e14:
    inc hl
    inc hl
    jr jr_00d_7df9

    inc e
    ld a, [hl]
    jr c, @+$80

    ld [de], a
    dec de
    inc l
    ld a, [hl]
    db $10
    dec de
    cpl
    ld a, [hl]
    ld de, $321a
    ld a, [hl]
    ld de, $351c
    ld a, [hl]
    ld b, b
    ld b, b
    rst $38
    db $10
    jr nz, @+$01

    ld b, b
    db $10
    rst $38
    ld b, b
    jr nz, @+$01

    db $10
    ld [hl+], a
    ld c, h
    ld a, [hl]
    ld de, $5123
    ld a, [hl]
    ld [de], a
    dec h
    ld d, [hl]
    ld a, [hl]
    inc de
    dec h
    ld h, d
    ld a, [hl]
    ld de, $6724
    ld a, [hl]
    jr nz, jr_00d_7dce

    add b
    db $10
    rst $38
    jr nz, jr_00d_7dd3

    db $10
    jr nz, @+$01

    jr nz, @+$22

    jr nz, jr_00d_7e5a

jr_00d_7e5a:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    jr nz, @+$22

    ld b, b
    jr nz, @+$01

    jr nz, jr_00d_7de9

    jr nz, jr_00d_7e6b

jr_00d_7e6b:
    nop
    nop

Jump_00d_7e6d:
    nop
    nop
    nop
    nop

Call_00d_7e71:
    nop
    rst $38
    ld a, $08
    ld b, a
    xor a
    ldh [$95], a
    ldh [$9b], a
    ldh [$9c], a
    ldh [$9d], a
    ldh [$9e], a

jr_00d_7e81:
    ldh a, [$99]
    srl a
    ldh [$99], a
    jr nc, jr_00d_7ea9

    ldh a, [$9e]
    ld c, a
    ldh a, [$98]
    add c
    ldh [$9e], a
    ldh a, [$9d]
    ld c, a
    ldh a, [$97]
    adc c
    ldh [$9d], a
    ldh a, [$9c]
    ld c, a
    ldh a, [$96]
    adc c
    ldh [$9c], a
    ldh a, [$9b]
    ld c, a
    ldh a, [$95]
    adc c
    ldh [$9b], a

jr_00d_7ea9:
    dec b
    jr z, jr_00d_7ec6

    ldh a, [$98]
    sla a
    ldh [$98], a
    ldh a, [$97]
    rl a
    ldh [$97], a
    ldh a, [$96]
    rl a
    ldh [$96], a
    ldh a, [$95]
    rl a
    ldh [$95], a
    jr jr_00d_7e81

jr_00d_7ec6:
    ldh a, [$9e]
    ldh [$98], a
    ldh a, [$9d]
    ldh [$97], a
    ldh a, [$9c]
    ldh [$96], a
    ldh a, [$9b]
    ldh [$95], a
    ret


    xor a
    ldh [$9a], a
    ldh [$9b], a
    ldh [$9c], a
    ldh [$9d], a
    ldh [$9e], a
    ld a, $09
    ld e, a

jr_00d_7ee5:
    ldh a, [$9a]
    ld c, a
    ldh a, [$96]
    sub c
    ld d, a
    ldh a, [$99]
    ld c, a
    ldh a, [$95]
    sbc c
    jr c, jr_00d_7f00

    ldh [$95], a
    ld a, d
    ldh [$96], a
    ldh a, [$9e]

Call_00d_7efb:
    inc a
    ldh [$9e], a
    jr jr_00d_7ee5

jr_00d_7f00:
    ld a, b
    cp $01
    jr z, jr_00d_7f4a

    ldh a, [$9e]
    sla a
    ldh [$9e], a
    ldh a, [$9d]
    rl a
    ldh [$9d], a
    ldh a, [$9c]
    rl a
    ldh [$9c], a
    ldh a, [$9b]
    rl a
    ldh [$9b], a
    dec e
    jr nz, jr_00d_7f36

    ld a, $08
    ld e, a
    ldh a, [$9a]
    ldh [$99], a
    xor a
    ldh [$9a], a
    ldh a, [$96]
    ldh [$95], a
    ldh a, [$97]
    ldh [$96], a
    ldh a, [$98]
    ldh [$97], a

jr_00d_7f36:
    ld a, e
    cp $01
    jr nz, jr_00d_7f3c

    dec b

jr_00d_7f3c:
    ldh a, [$99]
    srl a
    ldh [$99], a
    ldh a, [$9a]
    rr a
    ldh [$9a], a
    jr jr_00d_7ee5

jr_00d_7f4a:
    ldh a, [$96]
    ldh [$99], a
    ldh a, [$9e]
    ldh [$98], a
    ldh a, [$9d]
    ldh [$97], a
    ldh a, [$9c]
    ldh [$96], a
    ldh a, [$9b]
    ldh [$95], a
    ret


    ld a, [$cd3d]
    cp $fd
    jr z, jr_00d_7f98

    cp $fe
    jr z, jr_00d_7f9c

    cp $ff
    jr z, jr_00d_7fa0

    ld b, $0b
    ld hl, $7fb9
    call Call_000_3620
    ld a, [$cd3d]
    and a
    ret z

    ld a, [$cd05]
    ld b, a
    ld a, [$cd3f]
    inc a
    cp b
    jr z, jr_00d_7f8a

    ld a, $fd
    jr jr_00d_7f8c

jr_00d_7f8a:
    ld a, $fa

jr_00d_7f8c:
    ld [$cc5b], a
    ldh a, [$b8]
    ld [$cc5e], a
    call Call_00d_73ae
    ret


jr_00d_7f98:
    ld a, $28
    jr jr_00d_7fa2

jr_00d_7f9c:
    ld a, $29
    jr jr_00d_7fa2

jr_00d_7fa0:
    ld a, $2a

Call_00d_7fa2:
jr_00d_7fa2:
    push af
    call Call_000_3c6c
    pop af
    call Call_000_3f25
    ret


    nop
    cp d
    cp h
    ld [c], a

jr_00d_7faf:
    or e
    ld a, a
    pop bc
    pop hl
    or e
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    dec hl
    sbc $c8
    sbc $7f
    jr nc, @-$45

    inc [hl]
    ld a, a

Jump_00d_7fc1:
    cp d
    call c, $c3da
    reti


    ld d, a
    db $ed
    inc l
    ret nz

Jump_00d_7fca:
    ld l, [hl]
    cp b
    inc l
    ld a, a
    pop bc
    pop hl
    or e
    rst $20

jr_00d_7fd2:
    ld c, a
    ld d, [hl]
    ld a, a
    ret


    ld a, a
    sbc e
    rrca
    ld h, $7f
    or [hl]
    cp c
    jp $d9b1


    rst $20
    ld d, a
    nop
    add l
    ld b, $26

jr_00d_7fe6:
    ld a, a
    or l
    or d
    jp $d9b1


    ld d, [hl]
    ld c, a
    or a
    rst $18
    call nz, $ba7f
    jp c, Jump_00d_7fca

    jr nc, jr_00d_7fd2

    or [hl]
    ret


    ld a, a
    jr nc, jr_00d_7faf

    jr nc, jr_00d_7fe6

    ld d, a
