; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $00e", ROMX[$4000], BANK[$e]

    ld bc, $312d
    ld sp, $412d
    ld d, $03
    dec l
    ld b, b
    ld d, l
    db $fd
    ld a, h
    db $d3
    ld a, l
    ld hl, $002d
    nop
    inc bc
    and h
    inc bc
    db $38, $c0
    inc bc
    ld [$0006], sp
    ld [bc], a
    inc a
    ld a, $3f
    inc a
    ld d, b
    ld d, $03
    dec l
    adc l
    ld h, [hl]
    inc bc
    ld d, b
    inc [hl]
    ld d, c
    ld hl, $492d
    nop
    inc bc
    and h
    inc bc
    db $38, $c0
    inc bc
    ld [$0006], sp
    inc bc
    ld d, b
    ld d, d
    ld d, e
    ld d, b
    ld h, h
    ld d, $03
    dec l
    ret nc

    ld [hl], a
    nop
    ld b, b
    ld e, e

Jump_00e_4046:
    ld b, d
    ld hl, $492d
    ld d, $03
    and h
    ld b, e
    jr c, @-$3e

    inc bc
    ld [$0006], sp
    inc b
    daa
    inc [hl]
    dec hl
    ld b, c
    ld [hl-], a
    inc d
    inc d
    dec l
    ld b, c
    ld d, l
    sub c
    ld e, e
    add c
    ld e, h
    ld a, [bc]
    dec l
    nop
    nop
    inc bc
    or l
    inc bc
    ld c, a
    ret z

    db $e3
    ld [$0026], sp
    dec b
    ld a, [hl-]
    ld b, b
    ld a, [hl-]
    ld d, b
    ld b, c
    inc d
    inc d
    dec l
    adc [hl]
    ld h, [hl]
    ld [hl-], a
    ld e, [hl]
    add h
    ld e, a
    ld a, [bc]
    dec l
    inc [hl]
    nop
    inc bc
    or l
    inc bc
    ld c, a
    ret z

    db $e3
    ld [$0026], sp
    ld b, $4e
    ld d, h
    ld c, [hl]
    ld h, h
    ld d, l
    inc d
    ld [bc], a
    dec l
    pop de
    ld [hl], a
    rst $10
    ld h, c
    ld h, $64
    ld a, [bc]
    dec l
    inc [hl]
    dec hl
    inc bc
    or l
    ld b, e
    ld c, a
    adc $e3
    ld [$0026], sp
    rlca
    inc l
    jr nc, jr_00e_40ed

    dec hl
    ld [hl-], a
    dec d
    dec d
    dec l
    ld b, d
    ld d, l
    db $dd
    ld e, h
    or l
    ld e, l
    ld hl, $0027
    nop
    inc bc
    or c
    ccf
    rrca
    ret z

    add e
    ld [$0032], sp
    ld [$3f3b], sp
    ld d, b
    ld a, [hl-]
    ld b, c
    dec d
    dec d
    dec l
    adc a
    ld h, [hl]
    db $ed
    ld e, a
    ld b, d
    ld h, c
    ld hl, $9127
    nop
    inc bc
    or c
    ccf
    rrca
    ret z

    add e
    ld [$0032], sp
    add hl, bc
    ld c, a
    ld d, e
    ld h, h
    ld c, [hl]
    ld d, l
    dec d
    dec d
    dec l
    jp nc, $8877

    db $76

jr_00e_40ed:
    sbc d
    ld a, b
    ld hl, $9127
    scf
    inc bc
    or c
    ld a, a
    rrca
    adc $83
    ld [$0032], sp
    ld a, [bc]
    dec l
    ld e, $23
    dec l
    inc d
    rlca
    rlca
    rst $38
    dec [hl]
    ld d, l
    ld a, c
    ld c, b
    dec c
    ld c, c
    ld hl, $0051
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    dec bc
    ld [hl-], a
    inc d
    scf
    ld e, $19
    rlca
    rlca
    ld a, b
    ld c, b
    ld d, l
    ld h, [hl]
    ld c, c
    inc b
    ld c, d
    ld l, d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc c
    inc a
    dec l
    ld [hl-], a
    ld b, [hl]
    ld d, b
    rlca
    ld [bc], a

jr_00e_413c:
    dec l
    and b
    ld [hl], a
    ld [hl], e
    ld c, d
    or a
    ld c, h
    ld e, l
    nop
    nop
    nop
    nop
    ld a, [hl+]
    ld b, e
    jr c, jr_00e_413c

    ld b, e
    jr z, jr_00e_4151

    nop
    dec c

jr_00e_4151:
    jr z, jr_00e_4176

    ld e, $32
    inc d
    rlca
    inc bc
    rst $38
    inc [hl]
    ld d, l
    cp $74
    sub a
    ld [hl], l
    jr z, jr_00e_41b2

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld c, $2d
    add hl, de
    ld [hl-], a
    inc hl
    add hl, de
    rlca
    inc bc
    ld a, b
    ld b, a

jr_00e_4176:
    ld d, l
    ld [$9e75], a
    db $76
    ld l, d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rrca
    ld b, c
    ld d, b
    jr z, @+$4d

    dec l
    rlca
    inc bc
    dec l
    sbc a
    ld [hl], a
    ldh a, [rPCM12]
    ldh [$78], a
    rra
    nop
    nop
    nop
    nop
    inc h
    ld b, e
    jr @-$3e

    jp Jump_000_0608


    nop
    db $10
    jr z, jr_00e_41d4

    jr z, jr_00e_41e1

    inc hl
    nop
    ld [bc], a
    rst $38
    scf
    ld d, l
    ld b, a
    ld b, [hl]
    inc de

jr_00e_41b2:
    ld b, a
    stop
    nop
    nop
    inc bc
    ld a, [hl+]
    inc bc
    ld [$43c0], sp
    inc c
    ld a, [bc]
    nop
    ld de, $3c3f
    scf
    ld b, a
    ld [hl-], a
    nop
    ld [bc], a
    ld a, b
    ld [hl], c
    ld h, [hl]
    ld e, $76
    ret z

    ld [hl], a
    db $10
    inc e
    nop
    nop
    inc bc

jr_00e_41d4:
    ld a, [hl+]
    inc bc
    ld [$43c0], sp
    inc c
    ld a, [bc]
    nop
    ld [de], a
    ld d, e
    ld d, b
    ld c, e
    ld e, e

jr_00e_41e1:
    ld b, [hl]
    nop
    ld [bc], a
    dec l
    xor h
    ld [hl], a
    cpl
    ld a, b
    ld d, [hl]
    ld a, d
    db $10
    inc e
    ld h, d
    nop
    inc bc
    ld a, [hl+]
    ld b, e
    ld [$43c0], sp
    inc c
    ld a, [bc]
    nop
    inc de
    ld e, $38
    inc hl
    ld c, b
    add hl, de
    nop
    nop
    rst $38
    add hl, sp
    ld d, l
    cp h
    ld c, [hl]
    ld a, d
    ld c, a
    ld hl, $0027
    nop
    nop
    and b
    cpl
    adc b
    ret


    jp nz, Jump_000_0208

    nop
    inc d
    scf
    ld d, c
    inc a

Jump_00e_4218:
    ld h, c
    ld [hl-], a
    nop
    nop
    ld e, d
    ld [hl], h
    ld h, [hl]
    or e
    ld c, a
    daa
    ld d, c
    ld hl, $6227
    nop
    nop
    and b
    ld a, a
    adc b
    ret


    jp nz, Jump_000_0208

    nop
    dec d
    jr z, jr_00e_426f

    ld e, $46
    rra
    nop
    ld [bc], a
    rst $38
    ld a, [hl-]
    ld d, l
    cp $47
    rst $18
    ld c, b
    ld b, b
    dec l
    nop
    nop
    nop
    ld a, [hl+]
    inc bc
    ld [$42c0], sp
    inc c
    ld a, [bc]
    nop
    ld d, $41

jr_00e_424e:
    ld e, d
    ld b, c
    ld h, h
    dec a
    nop
    ld [bc], a
    ld e, d
    and d
    ld [hl], a
    sbc l
    ld b, e
    ret


Call_00e_425a:
    ld b, l
    ld b, b
    dec l
    dec hl
    nop
    nop
    ld a, [hl+]
    ld b, e
    ld [$42c0], sp
    inc c
    ld a, [bc]
    nop
    rla
    inc hl

jr_00e_426a:
    inc a
    inc l
    scf
    jr z, @+$05

jr_00e_426f:
    inc bc
    rst $38
    ld a, $55
    dec b
    ld l, a
    ret c

    ld l, a
    inc hl
    dec hl
    nop
    nop
    nop
    and b
    inc bc
    jr jr_00e_424e

    add d
    adc b
    ld [hl+], a
    nop
    jr jr_00e_42c2

    ld d, l
    ld b, l
    ld d, b
    ld b, c
    inc bc
    inc bc
    ld e, d
    sub e
    ld [hl], a
    and h
    ld d, a
    cp h
    ld e, c
    inc hl
    dec hl
    jr z, jr_00e_4297

jr_00e_4297:
    nop
    and b
    ld b, e
    jr jr_00e_426a

    add d
    adc b
    ld [hl+], a
    nop
    add hl, de
    inc hl
    scf
    ld e, $5a
    ld [hl-], a
    rla
    rla
    cp [hl]
    ld d, d
    ld d, l
    push bc
    ld c, h
    adc $4d
    ld d, h
    dec l
    nop
    nop
    nop
    or c
    add e
    adc l
    pop bc
    jp Jump_00e_4218


    nop
    ld a, [de]
    inc a
    ld e, d
    scf
    ld h, h
    ld e, d

jr_00e_42c2:
    rla
    rla
    ld c, e
    ld a, d
    ld [hl], a
    ld b, [hl]
    ld c, [hl]
    jr nz, jr_00e_431b

    ld d, h
    dec l
    ld d, [hl]
    nop
    nop
    or c
    jp $c18d


    jp Jump_00e_4218


    nop
    dec de
    ld [hl-], a
    ld c, e
    ld d, l
    jr z, jr_00e_42fc

    inc b
    inc b
    rst $38
    ld e, l
    ld d, l
    ret


    ld e, c
    push bc
    ld e, d
    ld a, [bc]
    nop
    nop
    nop
    nop
    and h
    inc bc
    dec c
    adc $c2
    adc b
    ld h, $00
    inc e
    ld c, e
    ld h, h
    ld l, [hl]
    ld b, c
    scf
    inc b
    inc b

jr_00e_42fc:
    ld e, d
    and e
    ld h, [hl]
    ld c, c
    ld e, e
    ld de, $0a5d
    inc e
    nop
    nop
    nop
    and h
    ld b, e
    dec c
    adc $c2
    adc b
    ld h, $00
    dec e
    scf
    cpl
    inc [hl]
    add hl, hl
    jr z, jr_00e_431a

    inc bc
    db $eb
    dec sp

jr_00e_431a:
    ld d, l

jr_00e_431b:
    ld [hl], $5d
    dec c
    ld e, [hl]
    dec l
    ld hl, $0000
    inc bc
    and b
    inc hl
    adc b
    pop bc
    add e
    ld [$0002], sp
    ld e, $46
    ld a, $43
    jr c, jr_00e_4369

    inc bc
    inc bc
    ld a, b
    ld [hl], l
    ld h, [hl]
    or [hl]

Jump_00e_4338:
    ld d, e
    ld [hl+], a
    ld d, l
    dec l
    ld hl, $000a
    inc bc
    ldh [$3f], a
    adc b
    pop bc
    add e
    ld [$0002], sp
    rra
    ld e, d
    ld d, d
    ld d, a
    ld c, h
    ld c, e
    inc bc
    inc b
    dec l
    jp nz, Jump_00e_5477

    ld e, [hl]
    ld h, c
    ld h, b
    ld hl, $270a
    ld [hl+], a
    inc bc
    pop af
    rst $38
    adc a
    rst $00
    and e
    adc b
    ld [hl-], a
    nop
    jr nz, jr_00e_4394

    add hl, sp
    jr z, @+$34

jr_00e_4369:
    jr z, jr_00e_436e

    inc bc
    db $eb
    inc a

jr_00e_436e:
    ld d, l
    ld a, a
    ld b, l
    ld l, d
    ld b, [hl]
    dec hl
    ld hl, $0000
    inc bc
    ldh [rNR44], a
    adc b
    pop bc
    add e
    ld [$0002], sp
    ld hl, $483d
    add hl, sp
    ld b, c
    scf
    inc bc
    inc bc
    ld a, b
    db $76
    ld h, [hl]
    sbc h
    ld d, c
    dec de
    ld d, e
    dec hl
    ld hl, $001e
    inc bc

jr_00e_4394:
    ldh [$3f], a
    adc b
    pop bc
    add e
    ld [$0002], sp
    ld [hl+], a
    ld d, c
    ld e, h
    ld c, l
    ld d, l
    ld c, e
    inc bc
    inc b
    dec l
    jp Jump_000_1677


    ld c, d
    ld l, e
    ld c, h
    ld hl, $281e
    dec h
    inc bc
    pop af
    rst $38
    adc a
    rst $00
    and e
    adc b
    ld [hl-], a
    nop
    inc hl
    ld b, [hl]
    dec l
    jr nc, jr_00e_43e0

    inc a
    nop
    nop
    sub [hl]
    ld b, h
    ld d, l
    ret


    ld b, [hl]
    and h
    ld b, a
    ld bc, $002d
    nop
    inc b
    or c
    ccf
    xor a
    pop af
    and a
    jr c, @+$65

    nop
    inc h
    ld e, a
    ld b, [hl]
    ld c, c
    inc a
    ld d, l
    nop
    nop
    add hl, de
    add c
    ld h, [hl]
    ld [hl], a

jr_00e_43e0:
    ld h, [hl]
    and e
    ld h, a
    cpl
    inc bc
    ld l, e
    db $76
    inc b
    or c
    ld a, a
    xor a
    pop af
    and a
    jr c, jr_00e_4452

    nop
    dec h
    ld h, $29
    jr z, @+$43

    ld b, c
    inc d
    inc d
    cp [hl]
    ccf
    ld h, [hl]
    cp b
    ld c, b
    pop hl
    ld c, c
    inc [hl]
    daa
    nop
    nop
    nop
    and b
    inc bc
    ld [$e3c8], sp
    ld [$0002], sp
    ld h, $49
    ld c, h
    ld c, e
    ld h, h
    ld h, h
    inc d
    inc d
    ld c, e
    or d
    ld [hl], a
    ld b, [hl]
    ld c, d
    ld b, e
    ld c, h
    inc [hl]
    daa
    ld h, d
    ld l, $00
    and b
    ld b, e
    ld [$e3c8], sp
    ld [$0002], sp
    daa
    ld [hl], e
    dec l
    inc d
    inc d
    add hl, de
    nop
    nop
    xor d
    ld c, h
    ld d, l
    ld b, d
    ld h, c
    ld [$2f62], sp

jr_00e_4438:
    nop
    nop
    nop
    inc b
    or c
    ccf
    xor a
    pop af
    and e
    jr c, jr_00e_44a6

    nop
    jr z, @-$72

    ld b, [hl]
    dec l
    dec l
    ld [hl-], a
    nop
    nop
    ld [hl-], a
    ld l, l
    ld h, [hl]
    ld b, c
    ld h, d
    cp [hl]

jr_00e_4452:
    ld h, e
    cpl

jr_00e_4454:
    ld [hl-], a
    ld l, a
    inc bc
    inc b
    or c
    ld a, a
    xor a
    pop af
    and e
    jr c, @+$65

    nop
    add hl, hl
    jr z, jr_00e_4490

    inc hl
    scf
    jr z, @+$05

    ld [bc], a
    rst $38
    ld [hl], $55
    cp d
    ld l, l
    or c
    ld l, [hl]
    adc l

jr_00e_4470:
    nop
    nop
    nop
    nop
    ld a, [hl+]
    inc bc
    jr jr_00e_4438

    ld b, d
    ld [$0002], sp
    ld a, [hl+]
    ld c, e
    ld d, b
    ld b, [hl]
    ld e, d
    ld c, e
    inc bc
    ld [bc], a
    ld e, d
    xor e
    ld [hl], a
    db $10
    ld d, l
    call nc, $8d56

jr_00e_448c:
    ld h, a
    inc l
    nop
    nop

jr_00e_4490:
    ld a, [hl+]
    ld b, e
    jr jr_00e_4454

    ld b, d
    ld [$0002], sp
    dec hl
    dec l
    ld [hl-], a
    scf
    ld e, $4b
    ld d, $03
    rst $38
    ld c, [hl]
    ld d, l
    inc bc
    ld l, c
    db $e4

jr_00e_44a6:
    ld l, c
    ld b, a

jr_00e_44a8:
    nop
    nop
    nop
    inc bc
    inc h
    inc bc
    jr c, jr_00e_4470

    inc bc
    ld [$0006], sp
    inc l
    inc a
    ld b, c
    ld b, [hl]
    jr z, jr_00e_450f

    ld d, $03
    ld a, b
    add h
    ld h, [hl]
    ld a, h
    ld l, d
    adc $6b
    ld b, a
    ld c, l
    ld c, [hl]
    nop
    inc bc
    inc h
    inc bc
    jr c, jr_00e_448c

jr_00e_44cc:
    inc bc
    ld [$0006], sp
    dec l
    ld c, e
    ld d, b
    ld d, l
    ld [hl-], a
    ld h, h
    ld d, $03
    dec l
    cp b
    ld [hl], a
    ld [hl], a
    ld l, h
    ld sp, $4e6e
    ld c, a
    inc sp
    ld d, b
    inc bc
    and h
    ld b, e
    jr c, jr_00e_44a8

jr_00e_44e8:
    inc bc
    ld [$0006], sp
    ld l, $23
    ld b, [hl]
    scf
    add hl, de
    scf
    rlca
    ld d, $be
    ld b, [hl]
    ld d, l
    rra
    ld [hl], b
    ld bc, $0a71
    nop
    nop
    nop
    nop
    and h
    inc bc
    jr c, jr_00e_44cc

    add e
    ld [$0006], sp
    cpl
    inc a
    ld e, a
    ld d, b

jr_00e_450c:
    ld e, $50
    rlca

jr_00e_450f:
    ld d, $4b
    add b
    ld [hl], a
    ld d, e
    ld e, d
    ld hl, $0a5c
    ld c, [hl]
    adc l
    nop
    nop
    and h
    ld b, e
    jr c, jr_00e_44e8

    add e
    ld [$0006], sp
    jr nc, jr_00e_4562

    scf
    ld [hl-], a
    dec l
    jr z, jr_00e_4532

    inc bc
    cp [hl]
    ld c, e
    ld d, l
    xor d
    ld [hl], e
    xor b

jr_00e_4532:
    ld [hl], h
    ld hl, $0032
    nop
    nop
    jr nz, jr_00e_453d

    jr c, jr_00e_450c

    inc bc

jr_00e_453d:
    jr z, @+$04

    nop
    ld sp, $4146
    inc a
    ld e, d
    ld e, d
    rlca
    inc bc

jr_00e_4548:
    ld c, e
    adc d
    ld [hl], a
    ld a, l
    ld b, h
    ld l, l
    ld b, [hl]
    ld hl, $4d32
    adc l
    nop
    ld a, [hl+]
    ld b, e
    jr c, jr_00e_4548

    ld b, e
    jr z, jr_00e_455d

    nop
    ld [hl-], a

jr_00e_455d:
    ld a, [bc]
    scf
    add hl, de
    ld e, a
    dec l

jr_00e_4562:
    inc b
    inc b
    rst $38
    ld d, c
    ld d, l
    ld b, c
    ld l, [hl]
    rst $10
    ld l, [hl]
    ld a, [bc]
    nop
    nop
    nop
    nop
    and b
    inc bc
    ld [$02ce], sp
    adc b
    ld [bc], a
    nop
    inc sp
    inc hl
    ld d, b
    ld [hl-], a
    ld a, b
    ld b, [hl]
    inc b
    inc b
    ld [hl-], a
    sbc c
    ld h, [hl]
    ld e, a
    ld b, d
    cp $43
    ld a, [bc]
    dec l
    ld e, e
    nop
    nop
    and b
    ld b, e
    ld [$02ce], sp
    adc b
    ld [bc], a
    nop
    inc [hl]
    jr z, jr_00e_45c4

    inc hl
    ld e, d
    jr z, jr_00e_459b

jr_00e_459b:
    nop
    rst $38
    ld b, l
    ld d, l
    ld [c], a
    ld b, l
    call nz, Call_000_0a46
    dec l
    nop
    nop
    nop
    and b
    adc a
    adc b
    pop bc
    jp nz, Jump_000_0208

    nop
    dec [hl]
    ld b, c
    ld b, [hl]
    inc a
    ld [hl], e
    ld b, c
    nop
    nop
    ld e, d
    sub h
    ld [hl], a
    sbc $6a
    sbc c
    ld l, h
    ld a, [bc]
    dec l
    inc l
    ld h, a
    nop

jr_00e_45c4:
    and b
    rst $08
    adc b
    pop bc
    jp nz, Jump_000_0208

    nop
    ld [hl], $32
    inc [hl]
    jr nc, jr_00e_4608

    ld [hl-], a
    dec d
    dec d
    cp [hl]
    ld d, b
    ld d, l
    sbc a
    ld e, h
    sub e
    ld e, l
    ld a, [bc]
    nop
    nop
    nop
    nop
    or c
    cp a
    rrca
    ret z

    jp nz, Jump_000_3208

    nop
    scf
    ld d, b
    ld d, d
    ld c, [hl]
    ld d, l
    ld d, b
    dec d
    dec d
    ld c, e
    xor [hl]
    ld [hl], a
    inc de
    ld d, b
    db $e3
    ld d, c
    ld a, [bc]
    daa
    ld [hl-], a
    nop
    nop
    or c
    rst $38
    rrca
    ret z

    jp nz, Jump_000_3208

    nop
    jr c, jr_00e_462e

    ld d, b
    inc hl

jr_00e_4608:
    ld b, [hl]
    inc hl
    ld bc, $be01
    ld c, d
    ld d, l
    ld b, d
    ld l, e
    ld c, a
    ld l, h
    ld a, [bc]
    dec hl
    nop
    nop
    nop
    or c
    add e
    adc a
    ret


    add $88
    ld [hl+], a
    nop
    add hl, sp
    ld b, c
    ld l, c
    inc a
    ld e, a
    inc a
    ld bc, $4b01
    sub l
    ld [hl], a
    nop
    ld b, b
    rst $20

jr_00e_462e:
    ld b, c
    ld a, [bc]
    dec hl
    ld [bc], a
    sbc d
    nop
    or c
    jp $c98f


    add $88
    ld [hl+], a
    nop
    ld a, [hl-]
    scf
    ld b, [hl]
    dec l
    inc a
    ld [hl-], a
    inc d
    inc d
    cp [hl]
    ld e, e
    ld d, l
    nop
    ld b, b
    db $eb
    ld b, b
    inc l
    ld l, $00
    nop
    dec b
    and b
    inc bc
    ld c, b
    ret z

    db $e3
    ld [$0002], sp
    dec sp
    ld e, d
    ld l, [hl]
    ld d, b
    ld e, a
    ld d, b
    inc d
    inc d
    ld c, e
    push de
    ld [hl], a
    xor c
    ld h, a
    ret nc

    ld l, c
    ld l, $34
    dec hl
    inc h
    dec b
    and b
    ld b, e
    ld c, b
    add sp, -$1d
    ld [$0002], sp
    inc a
    jr z, jr_00e_46a9

    jr z, jr_00e_46d3

    jr z, jr_00e_4690

    dec d
    rst $38
    ld c, l
    ld d, l
    dec de
    ld a, c
    ld hl, sp+$79
    sub c
    nop
    nop
    nop
    inc bc
    and b
    ccf
    ld [$82d0], sp
    jr z, jr_00e_46a1

    nop

jr_00e_4690:
    dec a
    ld b, c
    ld b, c
    ld b, c
    ld e, d
    ld [hl-], a
    dec d
    dec d
    ld a, b
    add e
    ld h, [hl]
    ld [hl], a
    ld [hl], c
    and l
    ld [hl], d
    sub c
    ld e, a

jr_00e_46a1:
    scf
    nop
    inc bc
    or c
    ccf
    rrca
    sub $86

jr_00e_46a9:
    jr z, jr_00e_46dd

    nop
    ld a, $5a
    ld d, l
    ld e, a
    ld b, [hl]
    ld b, [hl]
    dec d
    ld bc, $b92d
    ld [hl], a
    ld [$ad73], sp
    ld [hl], h
    ld e, a
    scf
    inc bc
    ld [hl+], a
    inc bc
    or c
    ld a, a
    rrca
    sub $86
    jr z, jr_00e_46f9

    nop
    ccf
    add hl, de
    inc d
    rrca
    ld e, d
    ld l, c
    jr @+$1a

    ret z

    ld c, c
    ld d, l

jr_00e_46d3:
    add [hl]
    ld [hl], c
    call Call_00e_6472
    nop
    nop
    nop
    inc bc
    or c

jr_00e_46dd:
    inc bc
    rrca
    ldh a, [$87]
    jr c, jr_00e_4726

    nop
    ld b, b
    jr z, jr_00e_470a

    ld e, $69
    ld a, b
    jr jr_00e_4704

    ld h, h
    sub c
    ld h, [hl]
    cp c
    ld c, b
    sub d
    ld c, d
    ld h, h
    ld e, l
    ld [hl-], a
    nop
    inc bc
    or c

jr_00e_46f9:
    inc bc
    rrca
    ld hl, sp-$79
    jr c, jr_00e_4742

    nop
    ld b, c
    scf
    ld [hl-], a
    dec l

jr_00e_4704:
    ld a, b
    add a
    jr jr_00e_4720

    ld [hl-], a
    cp d

jr_00e_470a:
    ld [hl], a
    ld e, b
    ld [hl], e
    adc l
    ld [hl], l
    ld h, h
    ld e, l
    ld [hl-], a
    nop
    inc bc
    or c
    ld b, e
    rrca
    ld hl, sp-$79
    jr c, jr_00e_475e

    nop
    ld b, d
    ld b, [hl]
    ld d, b
    ld [hl-], a

jr_00e_4720:
    inc hl
    inc hl
    ld bc, $b401
    ld e, b

jr_00e_4726:
    ld d, l
    ld d, h
    ld l, h
    ld d, b
    ld l, l
    ld [bc], a
    nop
    nop
    nop
    inc bc
    or c
    inc bc
    rrca
    adc $a6
    adc b
    ld [hl+], a
    nop
    ld b, e
    ld d, b
    ld h, h
    ld b, [hl]
    dec l
    ld [hl-], a
    ld bc, $5a01
    sub d

jr_00e_4742:
    ld [hl], a
    ld b, l
    ld c, a
    inc [hl]
    ld d, c
    ld [bc], a

jr_00e_4748:
    ld b, e
    dec hl
    nop
    inc bc
    or c
    inc bc
    rrca
    adc $a6
    adc b
    ld [hl+], a
    nop
    ld b, h
    ld e, d
    add d
    ld d, b
    scf
    ld b, c
    ld bc, $2d01
    pop bc

jr_00e_475e:
    ld [hl], a
    inc a
    ld c, l
    sub a
    ld c, a
    ld [bc], a

jr_00e_4764:
    ld b, e
    dec hl
    nop
    inc bc
    or c
    ld b, e
    rrca
    adc $a6
    adc b
    ld [hl+], a
    nop
    ld b, l
    ld [hl-], a
    ld c, e
    inc hl
    jr z, jr_00e_47bc

    ld d, $03
    rst $38
    ld d, h
    ld d, l
    xor a
    ld l, [hl]
    ld e, l
    ld l, a
    ld d, $4a
    nop
    nop
    inc bc
    inc h
    inc bc
    jr c, jr_00e_4748

    inc bc
    ld [$0006], sp
    ld b, [hl]
    ld b, c
    ld e, d
    ld [hl-], a
    scf
    ld d, l
    ld d, $03
    ld a, b
    sub a
    ld h, [hl]
    db $d3
    ld l, a
    ld a, [bc]
    ld [hl], c
    ld d, $4a
    inc hl
    nop
    inc bc
    inc h
    inc bc
    jr c, jr_00e_4764

    inc bc
    ld [$0006], sp
    ld b, a
    ld d, b
    ld l, c
    ld b, c
    ld b, [hl]
    ld h, h
    ld d, $03
    dec l
    cp a
    ld [hl], a
    add l
    ld [hl], c
    inc e
    ld [hl], e
    ld c, a

jr_00e_47b8:
    ld c, [hl]
    inc sp
    ld c, e
    inc bc

jr_00e_47bc:
    and h
    ld b, e
    jr c, @-$3e

    inc bc
    ld [$0006], sp
    ld c, b
    jr z, jr_00e_47ef

    inc hl
    ld b, [hl]
    ld h, h
    dec d
    inc bc
    cp [hl]
    ld l, c
    ld d, l
    ld a, c
    ld l, [hl]
    ld l, [hl]
    ld l, a
    inc sp
    nop
    nop
    nop
    dec b
    inc h
    ccf
    jr @-$3e

    add e
    ld [$0016], sp
    ld c, c
    ld d, b
    ld b, [hl]
    ld b, c
    ld h, h
    ld a, b
    dec d
    inc bc
    inc a
    call Call_000_1966
    ld b, e
    or h
    ld b, h

jr_00e_47ef:
    inc sp
    jr nc, jr_00e_4815

    nop
    dec b
    inc h
    ld a, a
    jr jr_00e_47b8

    add e
    ld [$0016], sp
    ld c, d
    jr z, jr_00e_484f

    ld h, h
    inc d
    ld e, $05
    inc b
    rst $38
    ld d, [hl]
    ld d, l
    xor c
    ld d, l
    ld l, e
    ld d, [hl]
    ld hl, $0000
    nop
    inc bc
    and c
    inc bc
    rrca
    adc $2e

jr_00e_4815:
    ret z

    ld [hl+], a
    nop
    ld c, e
    scf
    ld e, a
    ld [hl], e
    inc hl
    dec l
    dec b
    inc b
    ld a, b
    add [hl]
    ld h, [hl]
    dec h
    ld c, e
    db $dd
    ld c, h
    ld hl, $006f
    nop
    inc bc
    and c
    inc bc
    rrca
    adc $2e
    ret z

    ld [hl+], a
    nop
    ld c, h
    ld d, b
    ld l, [hl]
    add d
    dec l
    scf
    dec b
    inc b
    dec l
    or c
    ld h, [hl]
    or h
    ld e, a
    ld e, a
    ld h, c
    ld hl, $006f
    nop
    inc bc
    or c
    ld b, e
    rrca
    adc $2e
    ret z

    ld [hl+], a

jr_00e_484f:
    nop
    ld c, l
    ld [hl-], a
    ld d, l
    scf
    ld e, d
    ld b, c
    inc d
    inc d
    cp [hl]
    sbc b
    ld h, [hl]
    rra
    ld c, d
    add h
    ld c, l
    inc [hl]
    nop
    nop
    nop
    nop
    ldh [$03], a
    ld [$e3c0], sp
    ld [$0002], sp
    ld c, [hl]
    ld b, c
    ld h, h
    ld b, [hl]
    ld l, c
    ld d, b
    inc d
    inc d
    inc a
    ret nz

    ld [hl], a
    sbc e
    ld c, e
    inc c
    ld c, [hl]
    inc [hl]
    daa
    rla
    dec l
    nop
    ldh [rSCX], a
    ld [$e3c0], sp
    ld [$0002], sp
    ld c, a
    ld e, d
    ld b, c
    ld b, c
    rrca
    jr z, jr_00e_48a4

    jr jr_00e_484f

    ld h, e
    ld d, l
    ld e, b
    ld b, a
    ld c, e
    ld c, b
    ld e, l
    nop
    nop
    nop
    nop
    and b
    cp a
    ld [$e3fe], sp
    jr c, jr_00e_4916

    nop

jr_00e_48a4:
    ld d, b
    ld e, a
    ld c, e
    ld l, [hl]
    ld e, $50
    dec d
    jr jr_00e_48f8

    and h
    ld [hl], a
    dec d
    ld c, l
    ld e, a
    ld c, a
    ld e, l
    ld [hl-], a
    dec e
    nop
    nop
    or c
    rst $38
    rrca
    cp $e3
    jr c, jr_00e_4932

    nop
    ld d, c
    add hl, de
    inc hl
    ld b, [hl]
    dec l
    ld e, a
    rla
    rla
    cp [hl]
    ld e, c
    ld d, l
    call nz, Call_00e_425a
    ld e, e
    ld hl, $0000
    nop
    nop
    jr nz, jr_00e_48d9

    adc b
    pop hl
    ld b, e

jr_00e_48d9:
    jr jr_00e_491d

    nop
    ld d, d
    ld [hl-], a
    inc a
    ld e, a
    ld b, [hl]
    ld a, b
    rla
    rla
    inc a
    and c
    ld h, [hl]
    sub e
    ld h, [hl]
    ld h, d
    ld l, b
    ld hl, $5431
    nop
    nop
    jr nz, jr_00e_4935

    adc b
    pop hl
    ld b, e
    jr jr_00e_4939

    nop

jr_00e_48f8:
    ld d, e
    inc [hl]
    ld b, c
    scf
    inc a
    ld a, [hl-]
    nop
    ld [bc], a
    dec l
    ld e, [hl]
    ld h, [hl]
    and c
    ld [hl], c
    add hl, de
    ld [hl], e
    ld b, b
    inc e
    nop
    nop
    nop
    xor [hl]
    inc bc
    ld [$c3c0], sp
    ld [$000e], sp
    ld d, h
    inc hl

jr_00e_4916:
    ld d, l
    dec l
    ld c, e
    inc hl
    nop
    ld [bc], a
    cp [hl]

jr_00e_491d:
    ld h, b
    ld d, l
    add $77
    or e
    ld a, b
    ld b, b
    nop
    nop
    nop
    nop
    xor b
    inc bc
    ld [$83c0], sp
    inc c
    dec bc
    nop
    ld d, l
    inc a

jr_00e_4932:
    ld l, [hl]
    ld b, [hl]
    ld h, h

jr_00e_4935:
    inc a
    nop
    ld [bc], a
    dec l

jr_00e_4939:
    sbc [hl]
    ld [hl], a
    ld c, b
    ld a, c
    ld d, c
    ld a, e
    ld b, b
    dec l
    rra
    nop
    nop
    xor b
    ld b, e
    ld [$83c0], sp
    inc c
    dec bc
    nop
    ld d, [hl]
    ld b, c
    dec l
    scf
    dec l
    ld b, [hl]
    dec d
    dec d
    cp [hl]
    ld h, h
    ld h, [hl]
    cp l
    ld l, h
    or $6d
    dec e
    nop
    nop
    nop
    nop
    ldh [$bf], a
    ld [$82c0], sp
    ld [$0032], sp
    ld d, a
    ld e, d

jr_00e_496a:
    ld b, [hl]
    ld d, b
    ld b, [hl]
    ld e, a
    dec d
    add hl, de
    ld c, e
    or b
    ld h, [hl]
    push bc
    ld b, [hl]
    ld [de], a
    ld c, b

Call_00e_4977:
    dec e
    dec l
    ld a, $00
    nop
    ldh [rIE], a
    ld [$82c0], sp
    ld [$0032], sp
    ld e, b
    ld d, b
    ld d, b
    ld [hl-], a
    add hl, de
    jr z, jr_00e_498e

    inc bc
    cp [hl]
    ld e, d

jr_00e_498e:
    ld d, l
    sbc [hl]
    ld e, c
    cp c
    ld e, d
    ld bc, $0032
    nop
    nop
    and b
    nop
    sbc b
    pop bc
    ld a, [hl+]
    ld c, b
    ld [bc], a
    nop
    ld e, c
    ld l, c
    ld l, c
    ld c, e
    ld [hl-], a
    ld b, c
    inc bc
    inc bc
    ld c, e
    sbc l
    ld [hl], a
    ccf
    ld e, l
    rra
    ld e, a
    ld bc, $8b32
    nop
    nop
    and b
    ld b, b
    sbc b
    pop bc
    ld a, [hl+]
    ld c, b
    ld [bc], a
    nop
    ld e, d
    ld e, $41
    ld h, h
    jr z, @+$2f

    dec d
    dec d
    cp [hl]
    ld h, c
    ld d, l
    ld b, l
    ld l, l
    ld [de], a
    ld l, [hl]
    ld hl, $006e
    nop
    dec b
    jr nz, jr_00e_4a11

    ld [$4be0], sp
    ld c, b
    inc de
    nop
    ld e, e
    ld [hl-], a
    ld e, a
    or h
    ld b, [hl]
    ld d, l
    dec d
    add hl, de
    inc a
    bit 6, a
    ld d, [hl]
    ld h, d
    adc b
    ld h, h
    ld l, [hl]
    jr nc, jr_00e_496a

    ld a, $05
    jr nz, jr_00e_4a6d

    ld [$4be0], sp
    ld c, b
    inc de
    nop
    ld e, h
    ld e, $23
    ld e, $50
    ld h, h
    ld [$be03], sp
    ld e, a
    ld [hl], a
    ret


    ld l, a
    cp l
    ld [hl], c
    ld a, d
    ld l, l
    ld h, l
    nop
    inc bc
    jr nz, jr_00e_4a0a

jr_00e_4a0a:
    sbc b
    pop de
    ld a, [bc]
    ld l, d
    ld [bc], a
    nop
    ld e, l

jr_00e_4a11:
    dec l
    ld [hl-], a
    dec l
    ld e, a
    ld [hl], e
    ld [$5a03], sp
    ld a, [hl]
    ld h, [hl]
    dec a
    ld l, a
    rst $38
    ld [hl], b
    ld a, d
    ld l, l
    ld h, l
    nop
    inc bc
    jr nz, jr_00e_4a26

jr_00e_4a26:
    sbc b
    pop de
    ld a, [bc]
    ld l, d
    ld [bc], a
    nop
    ld e, [hl]
    inc a
    ld b, c
    inc a
    ld l, [hl]
    add d
    ld [$2d03], sp
    cp [hl]
    ld h, [hl]
    ld a, a
    ld e, e
    call nc, $7a5c
    ld l, l
    ld h, l
    nop
    inc bc
    or c
    ld b, e
    sbc a
    pop de
    adc [hl]
    ld l, d
    ld [hl+], a
    nop
    ld e, a
    inc hl
    dec l
    and b
    ld b, [hl]
    ld e, $05
    inc b
    dec l
    ld l, h
    ld [hl], a
    ld c, [hl]
    ld b, c
    ld a, [de]
    ld b, e
    ld hl, $0067
    nop
    nop
    and b
    inc bc
    ld [$8ace], sp
    ret z

    ld [hl+], a
    nop
    ld h, b
    inc a
    jr nc, jr_00e_4a95

    ld a, [hl+]
    ld e, d
    jr jr_00e_4a84

    cp [hl]

jr_00e_4a6d:
    ld h, [hl]
    ld h, [hl]
    cp $5d
    ld b, l
    ld e, a
    ld bc, $005f
    nop
    nop
    or c
    inc bc
    rrca
    ldh a, [$87]
    ld a, [hl-]
    ld b, e
    nop
    ld h, c
    ld d, l
    ld c, c
    ld b, [hl]

jr_00e_4a84:
    ld b, e
    ld [hl], e
    jr jr_00e_4aa0

    ld c, e
    and l
    ld [hl], a
    ld a, [hl]
    ld d, d
    add d
    ld d, h
    ld bc, $325f
    ld e, l
    nop
    or c

jr_00e_4a95:
    ld b, e
    rrca
    ldh a, [$87]
    ld a, [hl-]
    ld b, e
    nop
    ld h, d
    ld e, $69
    ld e, d

jr_00e_4aa0:
    ld [hl-], a
    add hl, de
    dec d
    dec d
    pop hl
    ld [hl], e
    ld d, l
    inc e
    ld b, a
    ld b, h
    ld c, b
    sub c
    dec hl
    nop
    nop
    nop
    and h
    ccf
    ld [$02c0], sp
    ld [$0036], sp
    ld h, e
    scf
    add d
    ld [hl], e
    ld c, e
    ld [hl-], a
    dec d
    dec d
    inc a
    adc $77
    xor h
    ld e, a
    or l
    ld h, c
    sub c
    dec hl
    dec bc
    nop
    nop
    and h
    ld a, a
    ld [$02c0], sp
    ld [$0036], sp
    ld h, h
    jr z, jr_00e_4af5

    ld [hl-], a
    ld h, h
    scf
    rla
    rla
    cp [hl]
    ld h, a
    ld d, l
    ld l, $49
    cp b
    ld c, c
    ld hl, $0067
    nop
    nop
    jr nz, jr_00e_4aeb

    adc b

jr_00e_4aeb:
    pop hl
    ld c, e
    ld e, b
    ld b, d
    nop
    ld h, l
    inc a
    ld [hl-], a
    ld b, [hl]
    adc h

jr_00e_4af5:
    ld d, b
    rla
    rla
    inc a
    sub [hl]
    ld d, l
    dec a
    ld h, l
    ld [de], a
    ld h, [hl]
    ld hl, $3167
    nop
    nop
    jr nz, jr_00e_4b47

    adc b
    pop hl
    bit 3, b
    ld b, d
    nop
    ld h, [hl]
    inc a
    jr z, jr_00e_4b60

    jr z, jr_00e_4b4e

    ld d, $18
    ld e, d
    ld h, d
    ld [hl], a
    ld d, $57
    dec de
    ld e, c
    adc h
    ld e, a
    nop
    nop
    dec b
    jr nz, jr_00e_4b25

    ld [$1bf0], sp

jr_00e_4b25:
    ld l, b
    ld [bc], a
    nop
    ld h, a
    ld e, a
    ld e, a
    ld d, l
    scf
    ld a, l
    ld d, $18

jr_00e_4b30:
    dec l
    call nc, $b377
    ld d, c
    nop
    ld d, h
    adc h
    ld e, a
    nop
    nop
    dec b
    jr nz, jr_00e_4b81

    jr c, jr_00e_4b30

    dec de
    ld l, b
    ld [hl+], a
    nop
    ld l, b
    ld [hl-], a
    ld [hl-], a

jr_00e_4b47:
    ld e, a
    inc hl
    jr z, jr_00e_4b4f

    inc b
    cp [hl]
    ld d, a

jr_00e_4b4e:
    ld d, l

jr_00e_4b4f:
    ld a, [de]
    ld h, c
    dec e
    ld h, d
    ld a, l
    dec l
    nop
    nop
    nop
    or c
    ccf
    rrca
    adc $a2
    ld [$0022], sp

jr_00e_4b60:
    ld l, c
    inc a
    ld d, b
    ld l, [hl]
    dec l
    ld [hl-], a
    inc b
    inc b
    ld c, e
    ld a, h
    ld h, [hl]
    inc h
    ld l, l
    or h
    ld l, [hl]
    ld a, l
    dec l
    dec hl
    ld [hl], h
    nop
    or c
    ld a, a
    rrca
    adc $a2
    ld [$0022], sp
    ld l, d
    ld [hl-], a
    ld a, b
    dec [hl]
    ld d, a

jr_00e_4b81:
    inc hl
    ld bc, $2d01
    adc e
    ld [hl], a
    jp c, $8653

    ld d, l
    jr jr_00e_4bed

    nop
    nop
    nop
    or c
    inc bc
    rrca
    ret nz

    add $08
    ld [hl+], a
    nop
    ld l, e
    ld [hl-], a
    ld l, c
    ld c, a
    ld c, h
    inc hl
    ld bc, $2d01
    adc h
    ld h, [hl]
    db $e4
    ld d, l
    inc sp
    ld d, a
    inc b
    ld h, c
    nop
    nop
    nop
    or c
    inc bc
    rrca
    ret nz

    add $08
    ld [hl+], a
    nop
    ld l, h
    ld e, d
    scf
    ld c, e
    ld e, $3c
    nop
    nop
    dec l
    ld a, a
    ld [hl], a
    xor a
    ld d, h
    ld a, l
    ld d, [hl]
    inc hl
    jr nc, jr_00e_4bc6

jr_00e_4bc6:
    nop
    nop
    or l
    ld a, a
    adc a
    rst $00
    and d
    ld [$0036], sp
    ld l, l
    jr z, jr_00e_4c14

    ld e, a
    inc hl
    inc a
    inc bc
    inc bc
    cp [hl]
    ld [hl], d
    ld h, [hl]
    push hl
    ld l, b
    and l
    ld l, d
    ld hl, $007b
    nop
    nop
    jr nz, jr_00e_4be6

jr_00e_4be6:
    adc b
    pop bc
    ld a, [hl+]
    ld c, b
    ld [bc], a
    nop
    ld l, [hl]

jr_00e_4bed:
    ld b, c
    ld e, d
    ld a, b
    inc a
    ld d, l
    inc bc
    inc bc
    inc a
    xor l
    ld [hl], a
    cpl
    ld l, b
    ld [hl], $6a
    ld hl, $7c7b
    nop
    nop
    jr nz, @+$42

    adc b
    pop bc
    ld a, [hl+]
    ld c, b
    ld [bc], a
    nop
    ld l, a
    ld d, b
    ld d, l
    ld e, a
    add hl, de
    ld e, $04
    dec b
    ld a, b
    add a
    ld [hl], a
    adc a

jr_00e_4c14:
    ld h, d
    or d
    ld h, h
    ld e, $00
    nop
    nop
    dec b
    ldh [$03], a
    adc b
    rst $08
    and d
    adc b
    ld [hl+], a
    nop
    ld [hl], b
    ld l, c
    add d
    ld a, b
    jr z, jr_00e_4c57

    inc b
    dec b
    inc a
    call z, Call_000_0077
    ld b, b
    ld c, c
    ld b, d
    ld e, $17
    daa
    rra
    dec b
    pop af
    rst $38
    adc a
    rst $08
    and d
    adc b
    ld [hl-], a
    nop
    ld [hl], c
    ld a, [$0505]
    ld [hl-], a
    ld l, c
    nop
    nop
    ld e, $ff
    ld h, [hl]
    adc e
    ld c, l
    pop hl
    ld c, [hl]
    ld bc, $0003
    nop
    inc b
    or c
    ld a, a
    xor a

jr_00e_4c57:
    pop af
    or a
    add hl, sp
    ld h, e
    nop
    ld [hl], d
    ld b, c
    scf
    ld [hl], e
    inc a
    ld h, h
    ld d, $16
    dec l
    and [hl]
    ld h, [hl]
    adc l
    ld a, e
    ld c, d
    ld a, l
    add h
    inc d
    nop
    nop
    nop
    and h
    ld b, e
    jr c, @-$3e

    add d
    ld [$0006], sp
    ld [hl], e
    ld l, c
    ld e, a
    ld d, b
    ld e, d
    jr z, jr_00e_4c7f

jr_00e_4c7f:
    nop
    dec l
    xor a
    ld [hl], a
    pop hl
    ld b, d
    jp hl


    ld b, h
    inc b
    ld h, e
    nop
    nop
    nop
    or c
    ld a, a
    adc a
    rst $00
    and d
    adc b
    ld [hl-], a
    nop
    ld [hl], h
    ld e, $28
    ld b, [hl]
    inc a
    ld b, [hl]
    dec d
    dec d
    pop hl
    ld d, e
    ld d, l
    or h
    ld d, [hl]
    ld l, b
    ld d, a
    sub c
    nop
    nop
    nop
    nop
    jr nz, jr_00e_4ce9

    ld [$c2c0], sp
    ld [$0012], sp
    ld [hl], l
    scf
    ld b, c
    ld e, a
    ld d, l
    ld e, a
    dec d
    dec d
    ld c, e
    sbc e
    ld h, [hl]
    cp c
    ld d, a
    dec hl
    ld e, c
    sub c
    ld l, h
    nop
    nop
    nop
    jr nz, jr_00e_4d45

    ld [$c2c0], sp
    ld [$0012], sp
    db $76
    dec l
    ld b, e
    inc a
    ccf
    ld [hl-], a
    dec d
    dec d
    pop hl
    ld l, a
    ld h, [hl]
    ld h, b
    ld b, l
    jp nz, Jump_00e_4046

    daa
    nop
    nop
    nop
    ld h, b
    ccf
    ld [$c2c0], sp
    ld [$0012], sp
    ld [hl], a

jr_00e_4ce9:
    ld d, b
    ld e, h
    ld b, c
    ld b, h
    ld d, b
    dec d
    dec d
    inc a
    xor d
    ld [hl], a
    cpl
    ld b, a
    ld [hl], c
    ld c, c
    ld b, b
    daa
    jr nc, jr_00e_4cfb

jr_00e_4cfb:
    nop
    ld h, b
    ld a, a
    ld [$c2c0], sp
    ld [$0012], sp
    ld a, b
    ld e, $2d
    scf
    ld d, l
    ld b, [hl]
    dec d
    dec d
    pop hl
    ld l, d
    ld h, [hl]
    ld a, [de]
    ld [hl], l
    dec a
    db $76
    ld hl, $0000
    nop
    dec b
    jr nz, jr_00e_4d59

    adc b
    pop af
    jp Jump_00e_5338


    nop
    ld a, c
    inc a
    ld c, e
    ld d, l
    ld [hl], e
    ld h, h
    dec d
    jr jr_00e_4d65

    rst $08
    ld h, [hl]
    ld sp, hl
    ld a, d
    sbc a
    ld a, h
    ld hl, $6a37
    nop
    dec b
    jr nz, jr_00e_4db5

    adc b
    pop af
    jp Jump_00e_5338


    nop
    ld a, d
    jr z, jr_00e_4d6c

    ld b, c
    ld e, d
    ld h, h
    jr jr_00e_4d5c

    dec l

jr_00e_4d45:
    adc b
    ld h, [hl]
    call nz, Call_00e_6251
    ld d, e
    ld e, l
    ld [hl], b
    nop
    nop
    nop
    or c
    ld b, e
    xor a
    pop af
    add a
    jr c, jr_00e_4d99

    nop
    ld a, e

jr_00e_4d59:
    ld b, [hl]
    ld l, [hl]
    ld d, b

jr_00e_4d5c:
    ld l, c
    scf
    rlca
    ld [bc], a
    dec l
    cp e
    ld [hl], a
    ld c, c
    ld [hl], d

jr_00e_4d65:
    db $76
    ld [hl], h
    ld h, d
    nop
    nop
    nop
    nop

jr_00e_4d6c:
    inc h
    ld b, e
    ld [$c2c0], sp
    ld [$0006], sp
    ld a, h
    ld b, c
    ld [hl-], a
    inc hl
    ld e, a
    ld e, a
    add hl, de
    jr @+$2f

    adc c
    ld h, [hl]
    ccf
    ld a, d
    rst $10
    ld a, e
    ld bc, $008e
    nop
    nop
    or c
    ld a, a
    rrca
    ldh a, [$87]
    jr z, jr_00e_4d91

    nop
    ld a, l

jr_00e_4d91:
    ld b, c
    ld d, e
    add hl, sp
    ld l, c
    ld d, l
    rla
    rla
    dec l

jr_00e_4d99:
    sbc h
    ld h, [hl]
    ld h, $64
    ld a, [$6265]
    dec hl
    nop
    nop
    nop
    or c
    ld b, e
    adc a
    pop af
    rst $00
    jr c, jr_00e_4e0d

    nop
    ld a, [hl]
    ld b, c
    ld e, a
    add hl, sp
    ld e, l
    ld d, l
    inc d
    inc d
    dec l

jr_00e_4db5:
    and a
    ld h, [hl]
    adc $61
    ld a, [hl]
    ld h, e
    inc [hl]
    nop
    nop
    nop
    nop
    or c
    ld b, e
    rrca
    ldh a, [$a6]
    jr z, jr_00e_4de9

    nop
    ld a, a
    ld b, c
    ld a, l
    ld h, h
    ld d, l
    scf
    rlca
    rlca
    dec l
    ret z

    ld [hl], a
    inc hl
    ld a, c
    cp $7a
    dec bc
    nop
    nop
    nop
    dec b
    and h
    ld b, e
    dec c
    ret nz

    ld [bc], a
    ld [$0026], sp
    add b
    ld c, e
    ld h, h
    ld e, a
    ld l, [hl]

jr_00e_4de9:
    ld b, [hl]
    nop
    nop
    dec l
    db $d3
    ld [hl], a
    ld b, l
    ld l, a
    inc c
    ld [hl], c
    ld hl, $0000
    nop
    dec b
    ldh [$73], a
    adc b
    rst $00
    and d
    ld [$0022], sp
    add c
    inc d
    ld a, [bc]
    scf
    ld d, b
    inc d
    dec d
    dec d
    rst $38
    inc d
    ld h, [hl]
    ld c, d
    ld e, e

jr_00e_4e0d:
    xor h
    ld e, h
    sub [hl]
    nop
    nop
    nop
    dec b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add d
    ld e, a
    ld a, l
    ld c, a
    ld d, c
    ld h, h
    dec d
    ld [bc], a
    dec l
    sub $77
    ld h, a
    ld l, d
    or h
    ld l, h
    inc l
    ld d, d
    dec hl
    jr c, jr_00e_4e35

    and b
    ld a, a
    ret z

    pop bc
    and e

jr_00e_4e35:
    ld [$0032], sp
    add e
    add d
    ld d, l
    ld d, b
    inc a
    ld e, a
    dec d
    add hl, de
    dec l
    db $db
    ld [hl], a
    ld h, h
    ld h, l
    ld h, $67
    scf
    dec l
    nop
    nop
    dec b
    ldh [$7f], a
    add sp, -$2f
    add e
    jr z, jr_00e_4e85

    nop
    add h
    jr nc, @+$32

    jr nc, jr_00e_4e89

    jr nc, jr_00e_4e5b

jr_00e_4e5b:
    nop
    inc hl
    dec a
    ld d, l
    di
    ld b, h
    sub [hl]
    ld b, l
    sub b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add l
    scf
    scf
    ld [hl-], a
    scf
    ld b, c
    nop
    nop
    dec l
    ld e, h
    ld d, l
    jr nc, jr_00e_4ee1

    inc de
    ld h, l
    ld hl, $001c
    nop
    nop
    and b

jr_00e_4e85:
    inc bc
    ld [$c3c0], sp

jr_00e_4e89:
    ld [$0002], sp
    add [hl]
    add d
    ld b, c
    inc a
    ld b, c
    ld l, [hl]
    dec d
    dec d
    dec l
    call nz, $d966
    ld l, c
    or a
    ld l, e
    ld hl, $621c
    scf
    nop
    and b
    ld a, a
    ld [$c3c0], sp
    ld [$0012], sp
    add a
    ld b, c
    ld b, c
    inc a
    add d
    ld l, [hl]
    rla
    rla
    dec l
    push bc
    ld h, [hl]
    xor l
    ld h, a
    dec [hl]
    ld l, c
    ld hl, $621c
    ld d, h
    nop
    and b
    ld b, e
    adc b
    pop bc
    jp Jump_00e_4218


    nop
    adc b
    ld b, c
    add d
    inc a
    ld b, c
    ld l, [hl]
    inc d
    inc d
    dec l
    add $66
    ld a, e
    ld h, l
    inc h
    ld h, a
    ld hl, $621c
    inc [hl]
    nop
    and b
    ld b, e
    ld [$e3c0], sp
    ld [$0002], sp
    adc c

jr_00e_4ee1:
    ld b, c
    inc a
    ld b, [hl]
    jr z, jr_00e_4f31

    nop
    nop
    dec l
    add d
    ld h, [hl]
    add $56
    rst $18
    ld d, a
    ld hl, $a09f
    nop
    nop
    jr nz, jr_00e_4f69

    adc b
    pop af
    jp Jump_00e_4338


    nop
    adc d
    inc hl
    jr z, jr_00e_4f64

    inc hl
    ld e, d
    dec b
    dec d
    dec l
    ld a, b
    ld d, l
    xor d
    ld e, l
    add d
    ld e, [hl]
    scf
    ld l, [hl]
    nop
    nop
    nop
    and b
    ccf
    ld [$03c0], sp
    ld [$0012], sp
    adc e
    ld b, [hl]
    inc a
    ld a, l
    scf
    ld [hl], e
    dec b
    dec d
    dec l
    rst $00
    ld h, [hl]
    rst $18
    ld e, [hl]
    sbc [hl]
    ld h, b
    scf
    ld l, [hl]
    ld e, $00
    nop
    ldh [$7f], a
    dec c
    ret nz

    add e

jr_00e_4f31:
    ld [$0012], sp
    adc h
    ld e, $50
    ld e, d
    scf
    dec l
    dec b
    dec d
    dec l
    ld [hl], a
    ld d, l
    jp Jump_00e_7453


    ld d, h
    ld a, [bc]
    ld l, d
    nop
    nop
    nop
    and b
    ccf
    ld [$03c0], sp
    ld [$0012], sp
    adc l
    inc a
    ld [hl], e
    ld l, c
    ld d, b
    ld b, [hl]
    dec b
    dec d
    dec l
    ret


    ld h, [hl]
    adc $54
    cpl
    ld d, [hl]
    ld a, [bc]
    ld l, d
    ld b, a
    nop
    nop

jr_00e_4f64:
    or [hl]
    ld a, a
    dec c
    ret nz

    add e

jr_00e_4f69:
    ld [$0012], sp
    adc [hl]
    ld d, b
    ld l, c
    ld b, c
    add d
    inc a
    dec b
    ld [bc], a
    dec l
    jp z, Jump_000_3f77

    ld e, b
    add hl, hl
    ld e, d
    ld de, $0061
    nop
    dec b
    ld a, [hl+]
    ld b, e
    ld c, b
    ret nz

    ld h, e
    inc c
    ld a, [bc]
    nop
    adc a
    and b
    ld l, [hl]
    ld b, c
    ld e, $41
    nop
    nop
    add hl, de
    sbc d
    ld [hl], a
    and d
    ld e, c
    cp $5a
    dec e
    add l
    sbc h
    nop
    dec b
    or c
    rst $38
    xor a
    rst $10
    xor a
    xor b
    ld [hl-], a
    nop
    sub b
    ld e, d
    ld d, l
    ld h, h
    ld d, l
    ld a, l
    add hl, de
    ld [bc], a
    inc bc
    rst $10
    ld [hl], a
    nop
    ld b, b
    cp $41
    ld b, b
    ld a, [hl-]
    nop
    nop
    dec b
    ld a, [hl+]
    ld a, a
    ld [$43c0], sp
    inc c
    ld a, [bc]
    nop
    sub c
    ld e, d
    ld e, d
    ld d, l
    ld h, h
    ld a, l
    rla
    ld [bc], a
    inc bc
    ret c

    ld [hl], a
    ld h, e
    ld b, d
    ld h, e
    ld b, h
    ld d, h
    ld b, c
    nop
    nop
    dec b
    ld a, [hl+]
    ld b, e
    adc b
    pop bc
    ld b, e
    inc e
    ld c, d
    nop
    sub d
    ld e, d
    ld h, h
    ld e, d
    ld e, d
    ld a, l
    inc d
    ld [bc], a
    inc bc
    reti


    ld [hl], a
    ld b, c
    ld a, h
    ld [$407e], a
    ld d, e
    nop
    nop
    dec b
    ld a, [hl+]
    ld b, e
    ld [$63c0], sp
    inc c
    ld a, [bc]
    nop
    sub e
    add hl, hl
    ld b, b
    dec l
    ld [hl-], a
    ld [hl-], a
    ld a, [de]
    ld a, [de]
    dec l
    ld b, e
    ld d, l
    xor [hl]
    ld d, b
    ld a, l
    ld d, c
    inc hl
    dec hl
    nop
    nop
    dec b
    and b
    ccf
    ret z

    pop bc
    db $e3
    jr jr_00e_5025

    nop
    sub h
    dec a
    ld d, h
    ld b, c
    ld b, [hl]
    ld b, [hl]
    ld a, [de]
    ld a, [de]
    dec l
    sub b
    ld h, [hl]
    ldh [rHDMA1], a
    jr c, jr_00e_5076

    inc hl
    dec hl

jr_00e_5025:
    ld d, [hl]
    nop
    dec b
    ldh [$3f], a
    ret z

    pop bc
    db $e3
    jr jr_00e_5041

    nop
    sub l
    ld e, e
    add [hl]
    ld e, a
    ld d, b
    ld h, h
    ld a, [de]
    ld [bc], a
    dec l
    jp c, $f677

    ld [hl], h
    add hl, de
    ld [hl], a
    inc hl
    dec hl

jr_00e_5041:
    ld d, [hl]
    ld h, c
    dec b
    ld [c], a
    ld a, a
    ret z

    pop bc
    db $e3
    jr jr_00e_507d

    nop
    sub [hl]
    ld l, d
    ld l, [hl]

Jump_00e_504f:
    ld e, d
    add d
    sbc d
    jr jr_00e_506c

    inc bc
    call c, Call_00e_4977
    ld d, a
    ld c, $59
    ld e, l
    ld [hl-], a
    add c
    ld e, [hl]
    dec b
    or c
    rst $38
    xor a
    pop af
    xor a
    jr c, jr_00e_50ca

    nop
    or e
    and c
    and h
    and c

jr_00e_506c:
    xor [hl]
    xor h
    or l
    xor h
    and c
    or d
    xor [hl]
    xor c
    and h
    and l

jr_00e_5076:
    or d
    or b
    xor c
    or b
    xor c
    ld d, b
    xor l

jr_00e_507d:
    and c
    and e

Jump_00e_507f:
    xor b
    xor c
    xor l
    and c
    and d
    and l
    and l
    and h
    and l
    xor h
    and c
    xor [hl]
    cp c
    and c
    and h
    and l
    or d
    and [hl]
    or l
    or e
    xor b
    xor c
    xor [hl]
    and c
    cp b
    xor c
    ld d, b
    and d
    and l
    xor h
    xor a
    ld d, b
    xor a
    or [hl]
    and l
    or d
    ld d, b
    or e
    or h
    xor c
    and e
    xor e
    cp c
    or l
    xor b
    or l
    and c
    xor [hl]
    xor c
    and h
    and l
    or d
    or c
    or l
    and l
    and l
    xor [hl]
    xor b
    and c

Call_00e_50ba:
    xor b
    and c
    ld d, b
    or e
    xor c
    or b
    xor b
    xor a
    xor h
    and c
    and d
    xor h
    and c
    and d
    xor a
    and c

jr_00e_50ca:
    or e
    or h
    xor l
    xor c
    ld d, b
    ld d, b
    ld d, b
    and e
    and c
    or d
    xor h
    and c
    and d
    and c
    and a
    ld d, b
    ld d, b
    xor d
    and l
    xor h
    xor h
    cp c
    and a
    xor b
    xor a
    or e
    or h
    or e
    and e
    xor a
    or d
    and l
    and e
    xor h
    and l
    or d
    xor e
    and e
    and c
    or d
    xor l
    xor c
    and e
    and c
    or d
    xor h
    xor a
    and d
    and c
    xor [hl]
    and a
    xor h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and a
    or l
    and c
    or d
    and h
    cp c
    and l
    and l
    or a
    and c
    and h
    or d
    xor c
    xor h
    xor h
    and d
    xor a
    and d
    xor a
    ld d, b
    cp c
    and c
    and h
    xor a
    xor [hl]
    cp c
    or l
    and a
    and l
    xor h
    and a
    and l
    xor h
    and c
    xor [hl]
    and a
    xor a
    xor a
    and h
    ld d, b
    and a
    or l
    xor h
    xor c
    and e
    or h
    and c
    and d
    xor h
    and l
    or a
    and l
    or h
    xor h
    xor a
    or e
    xor b
    or d
    xor c
    xor l
    and c
    or d
    and d
    and l
    or d
    and l
    and c
    and e
    xor b
    ld d, b
    xor e
    and l
    and h
    and c
    or d
    or e
    xor c
    xor h
    xor c
    or b
    and e
    xor a
    xor h
    xor a
    xor l
    and d
    xor h
    xor a
    xor a
    and h
    and d
    or l
    and d
    and c
    ld d, b
    and d
    xor h
    xor a
    xor a
    and h
    and c
    xor h
    xor h
    or l
    and d
    and e
    xor c
    or d
    and e
    xor h
    and h
    and l
    xor d
    and c
    or e
    and d
    xor h
    xor a
    xor a
    and h
    xor l
    xor a
    xor [hl]
    xor e
    and l
    and d
    and c
    or d
    xor e
    ld d, b
    and h
    and l
    and a
    or l
    and h
    xor b
    and c
    xor h
    and [hl]
    ld d, b
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    xor a
    or b
    or b
    xor a
    xor [hl]
    or d
    and l
    and e
    and l
    xor [hl]
    xor a
    or h
    or h
    and l
    or d
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and e
    or l
    and e
    xor e
    xor a
    or e
    xor a
    and [hl]
    or h
    ld d, b
    or d
    and l
    and h
    ld d, b
    ld d, b
    and [hl]
    xor c
    or d
    and l
    ld d, b
    and [hl]
    or d
    and l
    and l
    cp d
    or h
    xor b
    or l
    xor [hl]
    and h
    or e
    xor b
    and c
    or b
    and l
    xor [hl]
    xor c
    or e
    or e
    ld d, b
    and e
    xor h
    or l
    and d
    ld d, b
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and c
    and h
    or [hl]
    and l
    or d
    and l
    cp b
    xor b
    and c
    or l
    and d
    xor c
    and e
    and c
    and e
    or a
    xor b
    xor c
    or h
    and l
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and h
    or d
    and c
    and a
    xor a
    or a
    xor b
    and h
    or d
    and c
    or e
    or l
    or d
    or d
    and l
    and e
    and c
    and d
    or l
    or h
    or h
    and c
    or d
    and e
    xor b
    or e
    and l
    and c
    and h
    or d
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and h
    and l
    or e
    and l
    or d
    or e
    and c
    xor [hl]
    and h
    or a
    and c
    xor a
    xor l
    xor [hl]
    xor c
    and c
    or l
    xor l
    or e
    or h
    or b
    or l
    and h
    and h
    xor c
    and d
    or l
    xor e
    xor h
    xor c
    cp c
    and l
    and l
    and d
    ld d, b
    and d
    xor a
    xor a
    or e
    or h
    or e
    or l
    xor [hl]
    or d
    and c
    or e
    xor b
    xor a
    or a
    and l
    or a
    and c
    xor [hl]
    xor h
    xor c
    or b
    and c
    or b
    and c
    xor [hl]
    or b
    and c
    or d
    or h
    xor [hl]
    or a
    xor c
    or e
    and h
    xor a
    or e
    xor a
    and [hl]
    or h
    and a
    or e
    xor a
    and [hl]
    or h
    xor l
    and d
    and l
    and l
    or h
    xor h
    or h
    and l
    and c
    and e
    xor b
    or [hl]
    and c
    xor [hl]
    and a
    or l
    and d
    xor h
    xor a
    xor a
    and h
    and h
    xor a
    and h
    xor a
    xor h
    and c
    xor [hl]
    and a
    or d
    cp c
    or b
    xor c
    or b
    and l
    xor h
    xor l
    xor a
    or d
    or b
    xor b
    and d
    and l
    and c
    or l
    or h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and e
    and c
    or h
    and c
    or b
    or h
    and l
    xor h
    and c
    xor [hl]
    xor [hl]
    and c
    or h
    or l
    or d
    or e
    or h
    or d
    and c
    xor [hl]
    and d
    xor h
    xor a
    xor a
    and h
    and a
    and c
    xor a
    xor h
    or l
    or e
    xor h
    xor c
    or b
    or b
    and a
    and c
    xor a
    xor h
    or l
    xor l
    xor c
    or e
    or l
    ld d, b
    and e
    and c
    or d
    and d
    xor c
    and e
    and c
    or d
    or b
    or e
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    or e
    or h
    xor c
    and e
    xor e
    and d
    xor h
    xor a
    xor a
    and h
    and e
    xor a
    and d
    or d
    and c
    or b
    and l
    and c
    or d
    xor h
    and d
    xor h
    xor a
    xor a
    and h
    xor l
    and c
    xor h
    or l
    xor l
    and d
    xor c
    cp b
    ld d, b
    ld d, b
    or b
    xor a
    xor c
    or e
    xor a
    or b
    and l
    or d
    or e
    xor c

Jump_00e_5338:
    xor b
    and c
    xor b
    and c
    ld d, b
    and d
    xor h
    xor a
    xor a
    and h
    and a
    xor b
    xor a
    or e
    or h
    xor e
    and l
    and e
    xor c
    ld d, b
    or e
    or h
    and c
    or h
    and l
    and d
    xor c
    and e
    xor b
    xor a
    and d
    xor c
    and e
    or h
    and l
    or e
    and c
    or d
    xor l
    cp c
    xor c
    xor [hl]
    and e
    xor a
    xor [hl]
    and [hl]
    xor h
    xor a
    or a
    and l
    and c
    xor [hl]
    and c
    and l
    or e
    and d
    xor h
    xor a
    xor a
    and h
    xor l
    xor a
    xor a
    xor [hl]
    ld d, b
    xor [hl]
    xor a
    or d
    or h
    xor b
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    or e
    or c
    or l
    xor c
    or d
    and a
    and c
    xor h
    and l
    or b
    xor e
    and l
    xor h
    and c
    or d
    xor h
    and c
    or d
    or h
    and l
    xor h
    xor c
    xor [hl]
    xor a
    xor [hl]
    xor h
    xor c
    xor [hl]
    xor c
    and c
    or e
    or h
    xor a
    xor [hl]
    and l
    or b
    xor a
    xor h
    xor c

jr_00e_53b9:
    and e
    and [hl]
    and c
    or a
    and [hl]
    xor c
    and d
    xor h
    xor a
    xor a
    and h
    and e
    xor a
    xor c
    xor h
    ld d, b
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    or e
    xor b
    and c
    and h
    xor a
    or h
    xor a
    or d
    or h
    xor a
    xor h
    xor c
    cp d
    and c
    or d
    and e
    and c
    or d
    xor l
    and l
    xor h
    xor c
    cp d
    and c
    or d
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and d
    xor h
    xor a
    xor a
    and h
    and a
    xor b
    xor a
    or e
    or h
    or l
    xor [hl]
    xor c
    and h
    and l
    or e
    or h
    xor c
    xor [hl]
    xor e
    and [hl]
    xor h
    xor a
    or a
    and l
    or e
    or h
    and c
    xor l
    and l
    and d
    and c
    xor h
    xor h
    ld d, b
    and d
    xor a
    or h
    or h
    xor h
    ld de, $8000
    inc bc
    nop
    add b
    nop
    nop
    add b
    add hl, de
    call z, Call_000_1001
    nop
    add b
    ld b, $ed
    add b
    add hl, bc
    nop
    add b
    rra
    nop
    add b
    rrca
    jr nz, jr_00e_53b9

    dec c
    nop
    add b
    inc c
    nop
    add b
    dec bc
    nop
    add b
    dec b
    nop
    add b
    rlca
    nop
    rst $38
    ld bc, $8000
    ld a, [bc]
    nop
    add b
    add hl, de
    nop
    add b
    inc b
    nop
    add b
    dec de
    nop
    add b
    dec d
    nop
    add b
    ld e, $ee
    rst $38
    rla
    nop
    add b
    jr jr_00e_5462

jr_00e_5462:
    add b
    ld a, [de]
    nop
    add b
    inc e
    nop
    add b
    ld d, $00
    add b
    ld e, $02
    jr nz, jr_00e_5483

    nop
    add b
    inc d
    nop
    add b
    ld [de], a
    nop

Jump_00e_5477:
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    rra
    jr nz, jr_00e_54c1

    rla
    rst $38

jr_00e_5483:
    ret nz

    jr jr_00e_54c6

    and b
    ld c, $df
    inc b
    ld [bc], a
    nop
    add b
    inc e
    xor b
    ret nz

    inc h
    nop
    add b
    inc d
    ld a, [bc]
    ret nz

    rra
    ld c, b
    ld h, b
    jr nz, jr_00e_54a3

    ld b, b
    ld [de], a
    add b
    ret nz

    inc c
    xor $c0
    rla

jr_00e_54a3:
    ldh [rNR10], a
    ld e, $42
    rst $38
    ld hl, $6020
    dec c
    adc b
    jr nz, jr_00e_54c1

    ldh [rLCDC], a
    nop
    nop
    nop
    inc b
    rst $38
    jr nc, jr_00e_54b8

jr_00e_54b8:
    nop
    nop
    ld b, $8f
    rst $38
    inc e
    jr nz, @-$3e

    ld [de], a

jr_00e_54c1:
    and $dd
    nop
    nop
    nop

jr_00e_54c6:
    ld a, [bc]
    db $dd
    ld h, b
    inc c
    adc b
    ret nz

    dec bc
    xor d
    ld bc, $111d
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
    db $10
    db $dd
    ld bc, $441a
    ld b, b
    rrca
    inc a
    ret nz

    nop
    add b
    stop
    nop
    nop
    dec e
    ldh [$80], a
    dec bc
    cp e
    ld bc, $ff0e
    rst $38
    dec c
    rst $38
    rst $38
    add hl, bc
    ld hl, sp+$40
    add hl, bc
    add b

jr_00e_54fb:
    ld b, b
    jr @+$01

    add b
    ld c, $ff
    rst $38
    add hl, de
    ld [hl], a
    db $10
    jr nz, jr_00e_5527

    ldh [rNR43], a
    rst $38
    ld b, b
    nop
    nop
    nop
    ld c, $e0
    ld h, b
    inc h
    ld c, a
    db $10
    inc h
    adc b
    ld h, b
    rrca
    xor $01
    add hl, bc
    xor $08
    nop
    nop
    nop
    nop
    nop
    nop
    rrca
    ld h, b
    ld b, b
    rrca

jr_00e_5527:
    ld b, b
    add b
    ld d, $bb
    ld b, b
    jr @-$10

    ld bc, $9919
    db $10
    add hl, de
    inc a
    ld bc, $400f
    ret nz

    rrca
    jr nz, jr_00e_54fb

    nop
    jr nz, jr_00e_557e

    nop
    rst $38
    rst $38
    rra
    ldh a, [rSB]
    rra
    rst $38
    ld b, b
    ld c, $ff
    dec [hl]
    ld c, $68
    ld h, b
    ld a, [de]
    adc b
    ld h, b
    ld a, [de]
    db $10
    jr nz, jr_00e_556e

    dec a
    add b
    ld a, [de]
    xor d
    rst $38
    rra
    xor $01
    dec e
    ldh [$80], a
    rla
    ld [de], a
    ld b, b
    ld e, $20
    ldh [$0e], a
    ld [hl], a
    ld h, b
    ld c, $00
    rst $38
    dec d
    xor $01

jr_00e_556e:
    inc de
    rst $38
    ld bc, $6013
    add b
    nop
    nop
    nop
    dec bc
    sbc c
    jr nz, jr_00e_5585

    xor a
    ld b, b
    dec bc

jr_00e_557e:
    ld a, [hl+]
    db $10
    ld a, [de]
    add hl, hl
    add b
    inc c
    inc hl

jr_00e_5585:
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, $80
    jr nz, jr_00e_55ac

    call z, $1601
    ld [hl], a
    ld b, b
    rra
    ld [$11c0], sp
    jr nz, @+$12

    ld hl, $40ff
    dec c
    xor $40
    dec e
    ld a, [$1e80]
    sbc c
    rst $38
    dec b
    ld d, l

jr_00e_55a9:
    ld bc, $8017

jr_00e_55ac:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rlca
    rst $28
    rst $38
    rrca
    ld b, b
    add b
    jr nz, jr_00e_55a9

    ldh [rNR23], a
    ld l, a
    ldh [rP1], a
    nop
    nop
    ld b, $a8
    sub b
    add hl, de
    xor d
    jr nz, @+$14

    rst $38

jr_00e_55ca:
    rst $38
    add hl, de
    sbc c
    rst $38
    ld [$604f], sp
    nop
    nop
    nop
    inc e
    jr nc, jr_00e_5617

    inc e
    ret nz

    ld bc, $981c
    rst $38
    inc d
    jr z, @-$3e

    inc d
    ld de, $1eff
    nop
    add b
    rrca
    add b
    ld bc, $000f
    ret nz

    ld a, [de]
    xor $ff
    nop
    nop
    nop
    ld d, $80
    ld b, b
    ld d, $10
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
    dec h
    nop
    add b
    dec h
    jr nz, jr_00e_55ca

    ld [hl+], a
    nop
    add b
    ld [hl+], a
    jr nz, @+$01

    nop
    inc l
    ret nz

    ld bc, $e02c
    inc h

jr_00e_5617:
    ldh a, [rNR10]
    dec h
    xor d
    rst $38
    inc hl
    jr nz, @-$0e

    nop
    nop
    nop
    inc e
    add b
    ld h, b
    nop
    nop
    nop
    nop
    nop
    nop
    inc b
    ld h, b
    ld b, b
    dec e
    ld h, b
    ld b, b
    inc b
    jr nz, jr_00e_5674

    dec e
    jr nz, @+$42

    inc b
    nop
    add b
    dec e
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
    ld [$01dd], sp
    ld [$40aa], sp
    inc hl
    ld [hl+], a
    rst $38
    ld hl, $0155
    dec h
    ld b, h
    jr nz, jr_00e_567b

    ld h, [hl]
    call z, Call_000_0001
    jr z, jr_00e_565c

jr_00e_565c:
    rst $38
    inc hl
    ld [bc], a
    nop
    ld [hl-], a
    nop
    rst $38
    add hl, de
    inc bc
    dec e
    rrca
    nop
    ret c

    ld a, [bc]
    inc b
    dec e
    ld [de], a
    nop
    ret c

    rrca
    dec b
    nop
    ld d, b
    nop

jr_00e_5674:
    ret c

    inc d
    ld b, $10
    jr z, jr_00e_567a

jr_00e_567a:
    rst $38

jr_00e_567b:
    inc d
    rlca
    inc b
    ld c, e
    inc d
    rst $38
    rrca
    ld [$4b05], sp
    add hl, de
    rst $38
    rrca
    add hl, bc
    ld b, $4b
    rla
    rst $38
    rrca
    ld a, [bc]
    nop
    jr z, jr_00e_5692

jr_00e_5692:
    rst $38
    inc hl
    dec bc
    nop
    scf
    nop
    rst $38
    ld e, $0c
    ld h, $01
    nop
    ld c, h
    dec b
    dec c
    daa
    ld d, b
    nop
    cp a
    ld a, [bc]
    ld c, $32
    nop
    nop
    rst $38
    ld e, $0f
    nop
    ld [hl-], a
    nop
    ld a, [c]
    ld e, $10
    nop
    jr z, jr_00e_56b6

jr_00e_56b6:
    rst $38
    inc hl
    ld de, $2300
    ld [bc], a
    rst $38
    inc hl
    ld [de], a
    inc e
    nop
    nop
    ret c

    inc d
    inc de
    dec hl
    ld b, [hl]
    ld [bc], a
    ld a, [c]
    rrca
    inc d
    ld a, [hl+]
    rrca
    nop
    cp a
    inc d
    dec d
    nop
    ld d, b
    nop
    cp a
    inc d
    ld d, $00
    inc hl
    ld d, $ff
    ld a, [bc]
    rla
    dec h
    ld b, c
    nop
    rst $38
    inc d
    jr jr_00e_5710

    ld e, $01
    rst $38
    ld e, $19
    nop
    ld a, b
    nop
    cp a
    dec b
    ld a, [de]
    dec l
    ld b, [hl]
    ld bc, $19f2
    dec de
    dec h
    inc a
    ld bc, $0fd8
    inc e
    ld d, $00
    nop
    rst $38
    rrca
    dec e
    dec h
    ld b, [hl]
    nop
    rst $38
    rrca
    ld e, $00
    ld b, c
    nop
    rst $38
    add hl, de
    rra
    dec e
    rrca
    nop

jr_00e_5710:
    ret c

    inc d
    jr nz, jr_00e_573a

    ld bc, $4c00
    dec b
    ld hl, $2300
    nop
    ld a, [c]
    inc hl
    ld [hl+], a
    inc h
    ld d, l
    nop
    rst $38
    rrca
    inc hl
    ld a, [hl+]
    rrca
    nop
    ret c

    inc d
    inc h
    jr nc, @+$5c

    nop
    ret c

    inc d
    dec h
    dec de
    ld e, d
    nop
    rst $38
    inc d
    ld h, $30
    ld h, h
    nop

jr_00e_573a:
    rst $38
    rrca
    daa
    inc de
    nop
    nop
    rst $38
    ld e, $28
    ld [bc], a
    rrca
    inc bc
    rst $38
    inc hl
    add hl, hl
    ld c, l
    add hl, de
    rlca
    rst $38
    inc d
    ld a, [hl+]
    dec e
    ld c, $07
    ret c

    inc d
    dec hl
    inc de
    nop
    nop
    rst $38
    ld e, $2c
    rra
    inc a
    nop
    rst $38
    add hl, de
    dec l
    ld [de], a
    nop
    nop
    rst $38
    jr z, jr_00e_5795

    inc e
    nop
    nop
    rst $38
    inc d
    cpl
    jr nz, jr_00e_576f

jr_00e_576f:
    nop
    adc h
    rrca
    jr nc, jr_00e_57a5

    nop
    nop
    adc h
    inc d
    ld sp, $0129
    nop
    push hl
    inc d
    ld [hl-], a
    ld d, [hl]
    nop
    nop
    adc h
    inc d
    inc sp
    ld b, l
    jr z, jr_00e_578b

    rst $38
    ld e, $34

jr_00e_578b:
    inc b
    jr z, jr_00e_57a2

    rst $38
    add hl, de
    dec [hl]
    inc b
    ld e, a
    inc d
    rst $38

jr_00e_5795:
    rrca
    ld [hl], $2e
    nop
    add hl, de
    rst $38
    ld e, $37
    nop
    jr z, jr_00e_57b5

    rst $38
    add hl, de

jr_00e_57a2:
    jr c, jr_00e_57a4

jr_00e_57a4:
    ld a, b

jr_00e_57a5:
    dec d
    call z, Call_000_3905
    nop
    ld e, a
    dec d
    rst $38
    rrca
    ld a, [hl-]
    dec b
    ld e, a
    add hl, de
    rst $38
    ld a, [bc]
    dec sp

jr_00e_57b5:
    inc hl
    ld a, b
    add hl, de
    push hl
    dec b
    inc a
    ld c, h
    ld b, c
    jr @+$01

    inc d
    dec a
    ld b, [hl]
    ld b, c
    dec d
    rst $38
    inc d
    ld a, $44
    ld b, c
    add hl, de
    rst $38
    inc d
    ccf
    ld d, b
    sub [hl]
    nop
    push hl
    dec b
    ld b, b
    nop
    inc hl
    ld [bc], a
    rst $38
    inc hl
    ld b, c
    nop
    ld d, b
    ld [bc], a
    rst $38
    inc d
    ld b, d
    jr nc, jr_00e_5831

    ld bc, $19cc
    ld b, e
    dec h
    ld [hl-], a
    ld bc, $14e5
    ld b, h
    nop
    ld bc, $ff01
    inc d
    ld b, l
    add hl, hl
    ld bc, $ff01
    inc d
    ld b, [hl]
    nop
    ld d, b
    nop
    rst $38
    rrca
    ld b, a
    inc bc
    inc d
    ld d, $ff
    inc d
    ld c, b
    inc bc
    jr z, jr_00e_581c

    rst $38
    ld a, [bc]
    ld c, c
    ld d, h
    nop
    ld d, $e5
    ld a, [bc]
    ld c, d
    dec c
    nop
    nop
    rst $38
    jr z, jr_00e_5860

    nop
    scf
    ld d, $f2
    add hl, de
    ld c, h
    daa

jr_00e_581c:
    ld a, b
    ld d, $ff
    ld a, [bc]
    ld c, l
    ld b, d
    nop
    inc bc
    cp a
    inc hl
    ld c, [hl]
    ld b, e
    nop
    ld d, $bf
    ld e, $4f
    jr nz, jr_00e_582f

jr_00e_582f:
    ld d, $bf

jr_00e_5831:
    rrca
    ld d, b
    dec de
    ld b, [hl]
    ld d, $ff
    inc d
    ld d, c
    inc d
    nop
    rlca
    ld a, [c]
    jr z, jr_00e_5891

    add hl, hl
    ld bc, $ff1a
    ld a, [bc]
    ld d, e
    ld a, [hl+]
    rrca
    inc d
    or d
    rrca
    ld d, h
    ld b, $28
    rla
    rst $38
    ld e, $55
    ld b, $5f
    rla
    rst $38
    rrca
    ld d, [hl]
    ld b, e
    nop
    rla
    rst $38
    inc d
    ld d, a
    ld b, $78
    rla

jr_00e_5860:
    or d
    ld a, [bc]
    ld e, b
    nop
    ld [hl-], a
    dec b
    and l
    rrca
    ld e, c
    nop
    ld h, h
    inc b
    rst $38
    ld a, [bc]
    ld e, d
    ld h, $01
    inc b
    ld c, h
    dec b
    ld e, e
    daa
    ld h, h
    inc b
    rst $38
    ld a, [bc]
    ld e, h
    ld b, d
    nop
    inc bc
    ret c

    ld a, [bc]
    ld e, l
    ld c, h
    ld [hl-], a
    jr @+$01

    add hl, de
    ld e, [hl]
    ld b, a
    ld e, d
    jr @+$01

    ld a, [bc]
    ld e, a
    jr nz, jr_00e_588f

jr_00e_588f:
    jr @-$65

jr_00e_5891:
    inc d
    ld h, b
    ld a, [bc]
    nop
    jr @+$01

    jr z, jr_00e_58fa

    inc [hl]
    nop
    jr @+$01

    ld e, $62
    nop
    jr z, jr_00e_58a2

jr_00e_58a2:
    rst $38
    ld e, $63
    ld d, c
    inc d
    nop
    rst $38
    inc d
    ld h, h
    inc e
    nop
    jr @+$01

    inc d
    ld h, l
    add hl, hl
    nop
    ld [$0fff], sp
    ld h, [hl]
    ld d, d
    nop
    nop
    rst $38
    ld a, [bc]
    ld h, a
    dec sp
    nop
    nop
    ret c

    jr z, jr_00e_592b

    rrca
    nop
    nop
    rst $38
    rrca
    ld l, c
    jr c, jr_00e_58cb

jr_00e_58cb:
    nop
    rst $38
    inc d
    ld l, d
    dec bc
    nop
    nop
    rst $38
    ld e, $6b
    rrca
    nop
    nop
    rst $38
    inc d
    ld l, h
    ld d, $00
    nop
    rst $38
    inc d
    ld l, l
    ld sp, $0800
    rst $38
    ld a, [bc]
    ld l, [hl]
    dec bc
    nop
    dec d
    rst $38
    jr z, jr_00e_595c

    dec bc
    nop
    nop
    rst $38
    jr z, jr_00e_5963

    inc sp
    nop
    jr @+$01

    ld e, $71
    ld b, b

jr_00e_58fa:
    nop
    jr @+$01

    ld e, $72
    add hl, de
    nop
    add hl, de
    rst $38
    ld e, $73
    ld b, c
    nop
    jr @+$01

    inc d
    ld [hl], h
    cpl
    nop
    nop
    rst $38
    ld e, $75
    ld a, [de]
    nop
    nop
    rst $38
    ld a, [bc]
    db $76
    ld d, e
    nop
    nop
    rst $38
    ld a, [bc]
    ld [hl], a
    add hl, bc
    nop
    ld [bc], a
    rst $38
    inc d
    ld a, b
    rlca
    add d
    nop
    rst $38

jr_00e_5927:
    dec b
    ld a, c
    nop
    ld h, h

jr_00e_592b:
    nop
    cp a
    ld a, [bc]
    ld a, d
    inc h
    inc d
    ld [$1eff], sp
    ld a, e
    ld hl, $0314
    or d
    inc d
    ld a, h
    ld hl, $0341
    rst $38
    inc d
    ld a, l
    rra
    ld b, c
    inc b
    ret c

    inc d
    ld a, [hl]

jr_00e_5947:
    ld [hl+], a
    ld a, b
    inc d
    ret c

    dec b
    ld a, a
    nop
    ld d, b
    dec d
    rst $38
    rrca
    add b
    ld a, [hl+]
    inc hl
    dec d
    cp a
    ld a, [bc]
    add c
    ld de, $003c

jr_00e_595c:
    rst $38
    inc d
    add d
    daa
    ld h, h
    nop
    rst $38

jr_00e_5963:
    rrca
    add e
    dec e
    inc d
    nop
    rst $38
    rrca
    add h
    ld b, [hl]
    ld a, [bc]
    nop
    rst $38
    inc hl
    add l
    dec [hl]
    nop
    jr @+$01

    inc d
    add [hl]
    ld d, $00
    jr jr_00e_5947

jr_00e_597b:
    rrca
    add a
    jr c, jr_00e_597f

jr_00e_597f:
    nop
    rst $38
    ld a, [bc]
    adc b
    dec l
    ld d, l
    ld bc, $14e5
    adc c
    ld b, e
    nop
    nop
    cp a
    ld e, $8a
    ld [$1864], sp
    rst $38
    rrca
    adc e
    ld b, d
    nop
    inc bc
    adc h
    jr z, jr_00e_5927

    dec e
    rrca
    nop
    ret c

    inc d
    adc l
    inc bc
    inc d
    rlca
    rst $38
    rrca
    adc [hl]
    jr nz, jr_00e_59a9

jr_00e_59a9:
    nop
    cp a
    ld a, [bc]
    adc a
    daa
    adc h
    ld [bc], a
    push hl
    dec b
    sub b
    add hl, sp
    nop
    nop
    rst $38
    ld a, [bc]
    sub c
    ld b, [hl]
    inc d
    dec d
    rst $38
    ld e, $92
    nop
    ld b, [hl]
    nop
    rst $38
    ld a, [bc]
    sub e
    jr nz, jr_00e_59c7

jr_00e_59c7:
    ld d, $ff
    rrca
    sub h
    ld d, $00
    nop
    or d
    inc d
    sub l
    add hl, hl
    ld bc, $cc18
    rrca
    sub [hl]
    ld d, l
    nop
    nop
    rst $38
    jr z, @-$67

    inc sp
    nop
    inc bc
    rst $38
    jr z, jr_00e_597b

    nop
    ld e, d
    dec d
    ret c

    ld a, [bc]
    sbc c
    rlca
    xor d
    nop
    rst $38
    dec b
    sbc d
    dec e
    ld [de], a
    nop
    call z, $9b0f
    inc l
    ld [hl-], a
    inc b
    push hl
    ld a, [bc]
    sbc h
    jr c, jr_00e_59fd

jr_00e_59fd:
    jr @+$01

    ld a, [bc]
    sbc l
    nop
    ld c, e
    dec b
    push hl
    ld a, [bc]
    sbc [hl]
    rra
    ld d, b
    nop
    push hl
    rrca
    sbc a
    ld a, [bc]
    nop
    nop
    rst $38
    ld e, $a0
    jr jr_00e_5a15

jr_00e_5a15:
    nop
    rst $38
    ld e, $a1
    nop
    ld d, b
    nop
    rst $38
    ld a, [bc]
    and d
    jr z, jr_00e_5a22

    nop

jr_00e_5a22:
    push hl
    ld a, [bc]
    and e
    nop
    ld b, [hl]
    nop
    rst $38
    inc d
    and h
    ld c, a
    nop
    nop
    rst $38
    ld a, [bc]
    and l
    jr nc, @+$34

    nop
    rst $38
    ld a, [bc]
    ld a, $0a
    ld hl, $cee4
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld a, [$d04f]
    swap a
    and $0f
    jr z, jr_00e_5a52

    ld hl, $cee4
    dec a
    ld c, a
    ld b, $00
    add hl, bc
    ld [hl], $50

jr_00e_5a52:
    ld hl, $5bb8
    ld a, [$d018]
    ld b, a

jr_00e_5a59:
    dec b
    jr z, jr_00e_5a62

jr_00e_5a5c:
    ld a, [hl+]
    and a
    jr nz, jr_00e_5a5c

    jr jr_00e_5a59

jr_00e_5a62:
    ld a, [hl]
    and a
    jp z, Jump_00e_5abc

    push hl
    pop hl
    ld a, [hl+]
    and a
    jr z, jr_00e_5a7f

    push hl
    ld hl, $5ac0
    dec a
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $5a68
    push de
    jp hl


jr_00e_5a7f:
    ld hl, $cee4
    ld de, $cfd4
    ld c, $04

jr_00e_5a87:
    ld a, [de]
    inc de
    and a
    jr z, jr_00e_5a7f

    dec [hl]
    jr z, jr_00e_5a95

    inc hl
    dec c
    jr z, jr_00e_5a7f

    jr jr_00e_5a87

jr_00e_5a95:
    ld a, c

jr_00e_5a96:
    inc [hl]
    dec hl
    inc a
    cp $05
    jr nz, jr_00e_5a96

    ld hl, $cee4
    ld de, $cfd4
    ld c, $04

jr_00e_5aa5:
    ld a, [de]
    and a
    jr nz, jr_00e_5aaa

    ld [hl], a

jr_00e_5aaa:
    ld a, [hl]
    dec a
    jr z, jr_00e_5ab2

    xor a
    ld [hl+], a
    jr jr_00e_5ab4

jr_00e_5ab2:
    ld a, [de]
    ld [hl+], a

jr_00e_5ab4:
    inc de
    dec c
    jr nz, jr_00e_5aa5

    ld hl, $cee4
    ret


Jump_00e_5abc:
    ld hl, $cfd4
    ret


    ret z

    ld e, d
    inc b
    ld e, e
    inc [hl]
    ld e, e
    and b
    ld e, e
    ld a, [$cfff]
    and a
    ret z

    ld hl, $cee3
    ld de, $cfd4
    ld b, $05

jr_00e_5ad5:
    dec b
    ret z

    inc hl
    ld a, [de]
    and a
    ret z

    inc de
    call Call_00e_5ba1
    ld a, [$cfb5]
    and a
    jr nz, jr_00e_5ad5

    ld a, [$cfb4]
    push hl
    push de
    push bc
    ld hl, $5aff
    ld de, $0001
    call Call_000_3ddb
    pop bc
    pop de
    pop hl
    jr nc, jr_00e_5ad5

    ld a, [hl]
    add $05
    ld [hl], a
    jr jr_00e_5ad5

    ld bc, $4220
    ld b, e
    rst $38
    ld a, [$ccd5]
    cp $01
    ret nz

    ld hl, $cee3
    ld de, $cfd4
    ld b, $05

jr_00e_5b12:
    dec b
    ret z

    inc hl
    ld a, [de]
    and a
    ret z

    inc de
    call Call_00e_5ba1
    ld a, [$cfb4]
    cp $0a
    jr c, jr_00e_5b12

    cp $1a
    jr c, jr_00e_5b31

    cp $32
    jr c, jr_00e_5b12

    cp $42
    jr c, jr_00e_5b31

    jr jr_00e_5b12

jr_00e_5b31:
    dec [hl]
    jr jr_00e_5b12

    ld hl, $cee3
    ld de, $cfd4
    ld b, $05

jr_00e_5b3c:
    dec b
    ret z

    inc hl
    ld a, [de]
    and a
    ret z

    inc de
    call Call_00e_5ba1
    push hl
    push bc
    push de
    ld hl, $672b
    ld b, $0f
    call Call_000_3620
    pop de
    pop bc
    pop hl
    ld a, [$d0e3]
    cp $10
    jr z, jr_00e_5b3c

    jr c, jr_00e_5b60

    dec [hl]
    jr jr_00e_5b3c

jr_00e_5b60:
    push hl
    push de
    push bc
    ld a, [$cfb6]
    ld d, a
    ld hl, $cfd4
    ld b, $05
    ld c, $00

jr_00e_5b6e:
    dec b
    jr z, jr_00e_5b96

    ld a, [hl+]
    and a
    jr z, jr_00e_5b96

    call Call_00e_5ba1
    ld a, [$cfb4]
    cp $28
    jr z, jr_00e_5b95

    cp $29
    jr z, jr_00e_5b95

    cp $2b
    jr z, jr_00e_5b95

    ld a, [$cfb6]
    cp d
    jr z, jr_00e_5b6e

    ld a, [$cfb5]
    and a
    jr nz, jr_00e_5b95

    jr jr_00e_5b6e

jr_00e_5b95:
    ld c, a

jr_00e_5b96:
    ld a, c
    pop bc
    pop de
    pop hl
    and a
    jr z, jr_00e_5b3c

    inc [hl]
    jr jr_00e_5b3c

    ret


Call_00e_5ba1:
    push hl
    push de
    push bc
    dec a
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld de, $cfb3
    call Call_000_01bb
    pop bc
    pop de
    pop hl
    ret


    nop
    ld bc, $0100
    nop
    ld bc, $0003
    ld bc, $0100
    nop
    ld bc, $0302
    nop
    ld bc, $0002
    ld bc, $0100
    nop
    ld bc, $0003
    ld bc, $0100
    ld [bc], a
    nop
    ld bc, $0003
    ld bc, $0003
    nop
    ld bc, $0100
    inc bc
    nop
    ld bc, $0002
    ld bc, $0003
    ld bc, $0100
    nop
    ld bc, $0100
    nop
    ld bc, $0100
    inc bc
    nop
    ld bc, $0002
    ld bc, $0002
    ld bc, $0003
    ld bc, $0100
    inc bc
    nop
    ld bc, $0003
    ld bc, $0100
    nop
    ld bc, $0003
    ld bc, $0003
    ld bc, $0003
    ld bc, $0003
    ld bc, $0003
    ld bc, $0003
    ld bc, $0002
    ld bc, $0003
    ld bc, $0003
    ld bc, $0302
    nop
    ld bc, $0100
    nop
    ld bc, $0003
    nop
    ld b, b
    nop
    dec d
    nop
    add $40
    nop
    stop
    nop
    ld b, d
    nop
    dec d
    nop
    db $db
    ld b, d
    nop
    jr nc, jr_00e_5c45

jr_00e_5c45:
    ld d, b
    ld b, h
    nop
    jr nz, jr_00e_5c4a

jr_00e_5c4a:
    adc b
    ld b, l
    nop
    jr nz, jr_00e_5c4f

jr_00e_5c4f:
    ret


    ld b, [hl]
    nop
    ld d, b
    nop
    pop af
    ld b, a
    nop
    dec h
    nop
    rst $20
    ld c, b
    nop
    dec [hl]
    nop
    cp [hl]
    ld c, d
    nop
    jr nz, jr_00e_5c63

jr_00e_5c63:
    sub c
    ld c, h
    nop
    sub b
    nop
    ld a, [bc]
    ld c, [hl]
    nop
    ld d, b
    nop
    ld a, l
    ld e, c
    nop
    dec [hl]
    nop
    add a
    ld c, a
    nop
    dec [hl]
    nop
    inc sp
    ld d, c
    nop
    dec b
    nop
    ld c, a
    ld d, d
    nop
    dec h
    nop
    ld hl, $0054
    ld [hl], b
    nop
    rst $18
    ld d, l
    nop
    ld [hl], b
    nop
    jr z, jr_00e_5ce4

    nop
    stop
    ld b, e
    ld e, b
    nop
    dec h
    nop
    ld a, l
    ld e, c
    nop
    dec [hl]
    nop
    ld c, [hl]
    ld e, e
    nop
    ld b, b
    nop
    db $db
    ld e, h
    nop
    dec h
    nop
    db $76
    ld e, [hl]
    nop
    dec h
    nop
    ld c, c
    ld h, b
    nop
    dec [hl]
    nop
    ld e, a
    ld h, c
    nop
    sbc c
    nop
    ld a, l
    ld h, d
    nop
    jr nc, jr_00e_5cb8

jr_00e_5cb8:
    ld a, l
    ld h, d
    nop
    ld d, b
    nop
    cp [hl]
    ld h, e
    nop
    sbc c
    nop
    sbc a
    ld h, h
    nop
    jr nc, jr_00e_5cc7

jr_00e_5cc7:
    dec [hl]
    ld h, [hl]
    nop
    dec [hl]
    nop
    cp [hl]
    ld h, a
    nop
    dec [hl]
    nop
    ld b, e
    ld l, c
    nop
    sbc c
    nop
    ld a, $6b
    nop
    sbc c
    nop
    ld b, b
    ld l, h
    nop
    sbc c
    nop
    jr nc, jr_00e_5d4f

    nop
    sbc c

jr_00e_5ce4:
    nop
    or l
    ld l, [hl]
    nop
    sbc c
    nop
    sub $6f
    nop
    sbc c
    nop
    ld d, b
    ld [hl], c
    nop
    sbc c
    nop
    ld d, d
    ld [hl], d
    nop
    sbc c
    nop
    ret nc

    ld [hl], e
    nop
    ld [hl], b
    nop
    rst $08
    ld [hl], h
    nop
    ld h, l
    nop
    inc hl
    halt
    sbc c
    nop
    ld a, c
    ld [hl], a
    nop
    sbc c
    nop
    and h
    ld a, b
    nop
    jr nc, jr_00e_5d12

jr_00e_5d12:
    ld [hl], c
    ld a, d
    nop
    sbc c
    nop
    and d
    ld a, e
    nop
    sbc c
    nop
    db $ed
    inc l
    cp a
    ld h, c
    cp d
    cpl
    or e
    ld d, b
    pop de
    cp h
    call nz, $c9d8
    cp h
    ld [c], a
    or e
    ret z

    sbc $50
    sbc [hl]
    sub l
    adc h
    add l
    db $e3
    sub e
    ld d, b
    call z, $c9c5
    ret c

    ld d, b
    inc e
    db $e3
    add c
    adc h
    add l
    add d
    sub e
    ld d, b
    dec b
    db $e3
    and [hl]
    adc h
    add l
    add d
    sub e
    ld d, b
    or [hl]
    or d
    inc l
    pop hl

jr_00e_5d4f:
    or e
    sbc l
    sub l
    add b
    ld d, b
    ret c

    or [hl]
    cp c
    or d
    ret


    or l
    call nz, Call_00e_50ba
    call nc, $b5cf
    call nz, Call_00e_50ba
    ld a, $b3
    cp a
    or e
    cpl
    cp b
    ld d, b
    or [hl]
    inc l
    ld a, [hl-]
    inc [hl]
    db $db
    ld a, $b3
    ld d, b
    inc sp
    sbc $b7
    call nc, $84c9
    and d
    dec bc
    ld d, b
    dec bc
    ld b, d
    adc e
    db $e3
    dec bc
    xor l
    rlca
    and l
    db $e3
    ld d, b
    jp nz, $3bd8

    call nz, $b650
    or d
    ld b, b
    xor e
    call nc, $b3db
    ld d, b
    adc h
    add [hl]
    xor e
    call $0cac
    ld d, b
    ld b, $ad
    xor e
    dec de
    and l
    db $e3
    ld d, b
    or l
    call nz, $c9c5
    or l
    ret z

    or h
    cp e
    sbc $50
    adc d
    add c
    add [hl]
    xor h
    add l
    db $e3
    ld d, b
    inc sp
    sbc $b7
    rlca
    and [hl]
    db $e3
    ld b, d
    ld d, b
    dec bc
    ld b, d
    adc e
    db $e3
    dec bc
    xor l
    rlca
    and l
    db $e3
    ld d, b
    db $d3
    or e
    inc l
    pop hl
    or e
    jp nz, $b2b6

    ld d, b
    call nz, $c2d8
    or [hl]
    or d
    ld d, b
    or [hl]
    rst $10
    jp $b3b5


    ld d, b
    and l
    add c
    add hl, de
    and [hl]
    rst $30
    ld d, b
    add h
    db $e3
    add [hl]
    inc de

jr_00e_5de2:
    cp [hl]
    sbc $be
    or d
    ld d, b
    adc e
    and [hl]
    sbc e
    ret


    sub b
    db $e3
    sbc e
    ld d, b
    jp z, $da28

    cp c
    sbc $b7
    pop hl
    or e
    or d
    sbc $50
    adc d
    add l
    add [hl]
    ld d, b
    xor b
    adc b
    xor h
    sub e
    jr nc, jr_00e_5de2

    or d
    sbc $50
    add e
    ret c

    db $e3
    sub e
    sub e
    and a
    db $e3
    sub h
    db $e3
    ld d, b
    add e
    ret c

    db $e3
    sub e
    sub e
    and a
    db $e3
    sub h
    db $e3
    ld d, b
    adc e
    add hl, de
    ld d, b
    adc a
    adc b
    adc e
    ld d, b
    add l
    adc h
    sbc [hl]
    ld d, b
    sbc l
    sub b
    adc h
    ld d, b
    add e
    ret c

    add l
    ld d, b
    add [hl]
    xor a
    add d
    ld d, b
    add l
    sub c
    and l
    ld d, b
    sub h
    sub c
    and b
    ld d, b
    dec bc
    db $eb
    xor e
    sub e
    and [hl]
    sbc l
    xor e
    ld d, b
    and l
    add c
    add hl, de
    and [hl]
    ld hl, sp+$50
    and l
    add c
    add hl, de
    and [hl]
    ld sp, hl
    ld d, b
    add l
    xor e
    sub h
    ld d, b
    or a
    call nz, $bcb3
    ld d, b
    add [hl]
    add a
    adc c
    ld d, b
    xor c
    adc a
    and [hl]
    ld d, b
    ld hl, $d0b9
    ld de, $df30
    ld b, $00

jr_00e_5e67:
    ld a, [hl+]
    and a
    jr z, jr_00e_5e99

    push hl
    ld [$d092], a
    ld a, $04
    ld [$d094], a
    ld a, $02
    ld [$d093], a
    call Call_000_37b3
    ld hl, $cd68

jr_00e_5e7f:
    ld a, [hl+]
    cp $50
    jr z, jr_00e_5e88

    ld [de], a
    inc de
    jr jr_00e_5e7f

jr_00e_5e88:
    ld a, b
    ld [$cd67], a
    inc b
    ld a, $4e
    ld [de], a
    inc de
    pop hl
    ld a, b
    cp $04
    jr z, jr_00e_5ea9

    jr jr_00e_5e67

jr_00e_5e99:
    ld a, $e3
    ld [de], a
    inc de
    inc b
    ld a, b
    cp $04
    jr z, jr_00e_5ea9

    ld a, $4e
    ld [de], a
    inc de
    jr jr_00e_5e99

jr_00e_5ea9:
    ld a, $50
    ld [de], a
    ret


    ld a, [$d0e0]
    cp $01
    jr nz, jr_00e_5ebe

    ld hl, $d81b
    ld de, $d92b
    ld a, $06
    jr jr_00e_5ef0

jr_00e_5ebe:
    cp $04
    jr nz, jr_00e_5ecc

    ld hl, $d123
    ld de, $d233
    ld a, $05
    jr jr_00e_5ef0

jr_00e_5ecc:
    cp $05
    jr nz, jr_00e_5eda

    ld hl, $cf62
    ld de, $5068
    ld a, $01
    jr jr_00e_5ef0

jr_00e_5eda:
    cp $02
    jr nz, jr_00e_5ee8

    ld hl, $d2a1
    ld de, $433f
    ld a, $04
    jr jr_00e_5ef0

jr_00e_5ee8:
    ld hl, $cf62
    ld de, $433f
    ld a, $04

jr_00e_5ef0:
    ld [$d093], a
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    ld a, e
    ld [$cf74], a
    ld a, d
    ld [$cf75], a
    ld bc, $421c
    ld a, c
    ld [$cf76], a
    ld a, b
    ld [$cf77], a
    ret


    ld hl, $d124
    ld a, [$cc49]
    and a
    jr z, jr_00e_5f23

    dec a
    jr z, jr_00e_5f20

    ld hl, $d9b3
    jr jr_00e_5f23

jr_00e_5f20:
    ld hl, $d81c

jr_00e_5f23:
    ld d, $00
    add hl, de
    ld a, [hl]
    ld [$cf78], a
    ret


    ldh a, [$f3]
    and a
    ld a, [$d03d]
    ld hl, $d00d
    jr z, jr_00e_5f3c

    ld a, [$d042]
    ld hl, $cfde

jr_00e_5f3c:
    ld c, $04
    ld b, a

jr_00e_5f3f:
    srl b
    call c, Call_00e_5f4a
    inc hl
    inc hl
    dec c
    ret z

    jr jr_00e_5f3f

Call_00e_5f4a:
    ld a, [hl]
    add a
    ld [hl-], a
    ld a, [hl]
    rl a
    ld [hl+], a
    ret


    ldh a, [$f3]
    and a
    ld a, [$d03e]
    ld hl, $d00c
    jr z, jr_00e_5f63

    ld a, [$d043]
    ld hl, $cfdd

jr_00e_5f63:
    ld c, $04
    ld b, a

jr_00e_5f66:
    srl b
    call c, Call_00e_5f71
    inc hl
    inc hl
    dec c
    ret z

    jr jr_00e_5f66

Call_00e_5f71:
    ld a, [hl]
    srl a
    ld [hl+], a
    rr [hl]
    or [hl]
    jr nz, jr_00e_5f7c

    ld [hl], $01

jr_00e_5f7c:
    dec hl
    ret


    xor a
    ld [$cfbf], a
    ld b, $01
    call Call_000_3e1f
    ld hl, $733e
    ld b, $0f
    call Call_000_3620
    ld hl, $c3b3
    ld c, $00

jr_00e_5f94:
    inc c
    ld a, c
    cp $07
    ret z

    ld d, $00
    push bc
    push hl

jr_00e_5f9d:
    call Call_00e_5fb2
    inc hl
    ld a, $07
    add d
    ld d, a
    dec c
    jr nz, jr_00e_5f9d

    ld c, $04
    call Call_000_3781
    pop hl
    pop bc
    dec hl
    jr jr_00e_5f94

Call_00e_5fb2:
    push hl
    push de
    push bc
    ld e, $07

jr_00e_5fb7:
    ld [hl], d
    ld bc, $0014
    add hl, bc
    inc d
    dec e
    jr nz, jr_00e_5fb7

    pop bc
    pop de
    pop hl
    ret


    ld a, [$d0f0]
    and a
    ret nz

    ld hl, $d81b
    xor a
    ld [hl+], a
    dec a
    ld [hl], a
    ld a, [$d036]
    sub $c9
    add a
    ld hl, $60ac
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$d03a]
    ld b, a

jr_00e_5fe4:
    dec b
    jr z, jr_00e_5fed

jr_00e_5fe7:
    ld a, [hl+]
    and a
    jr nz, jr_00e_5fe7

    jr jr_00e_5fe4

jr_00e_5fed:
    ld a, [hl+]
    cp $ff
    jr z, jr_00e_6008

    ld [$d0ec], a

jr_00e_5ff5:
    ld a, [hl+]
    and a
    jr z, jr_00e_6074

    ld [$cf78], a
    ld a, $01
    ld [$cc49], a
    push hl
    call Call_000_3971
    pop hl
    jr jr_00e_5ff5

jr_00e_6008:
    ld a, [hl+]
    and a
    jr z, jr_00e_601f

    ld [$d0ec], a
    ld a, [hl+]
    ld [$cf78], a
    ld a, $01
    ld [$cc49], a
    push hl
    call Call_000_3971
    pop hl
    jr jr_00e_6008

jr_00e_601f:
    ld a, [$d039]
    and a
    jr z, jr_00e_603c

    dec a
    add a
    ld c, a
    ld b, $00
    ld hl, $6093
    add hl, bc
    ld a, [hl+]
    ld d, [hl]
    ld hl, $d82d
    ld bc, $002c
    call Call_000_3ad1
    ld [hl], d
    jr jr_00e_6074

jr_00e_603c:
    ld a, [$d036]
    sub $c8
    ld b, a
    ld hl, $60a3

jr_00e_6045:
    ld a, [hl+]
    cp b
    jr z, jr_00e_6054

    inc hl
    inc a
    jr nz, jr_00e_6045

    ld a, b
    cp $2b
    jr z, jr_00e_605a

    jr jr_00e_6074

jr_00e_6054:
    ld a, [hl]
    ld [$d8dd], a
    jr jr_00e_6074

jr_00e_605a:
    ld a, $8f
    ld [$d82d], a
    ld a, [$d694]
    cp $99
    ld b, $48
    jr z, jr_00e_6070

    cp $b0
    ld b, $7e
    jr z, jr_00e_6070

    ld b, $3b

jr_00e_6070:
    ld a, b
    ld [$d909], a

jr_00e_6074:
    xor a
    ld de, $d056
    ld [de], a
    inc de
    ld [de], a
    inc de
    ld [de], a
    ld a, [$d0ec]
    ld b, a

jr_00e_6081:
    ld hl, $d026
    ld c, $02
    push bc
    ld a, $0b
    call Call_000_3e9d
    pop bc
    inc de
    inc de
    dec b
    jr nz, jr_00e_6081

    ret


    ld bc, $0175
    dec a
    ld [bc], a
    ld d, l
    ld [bc], a
    ld c, b
    inc bc
    ld e, h
    inc bc
    sub l
    inc bc
    ld a, [hl]
    inc b
    ld e, d
    inc l
    dec sp
    ld hl, $2e5a
    ld e, h
    cpl
    ld [hl], b
    rst $38
    ld a, [bc]
    ld h, c
    ccf
    ld h, c
    ld a, l
    ld h, c
    ret


    ld h, c
    jp hl


    ld h, c
    ld c, $62
    ld a, d
    ld h, d
    sub a
    ld h, d
    rst $08
    ld h, d
    dec c
    ld h, e
    ld d, l
    ld h, e
    ld a, b
    ld h, e
    add h
    ld h, e
    add h
    ld h, e
    cp d
    ld h, e
    cp $63
    inc h
    ld h, h
    ld b, d
    ld h, h
    add [hl]
    ld h, h
    sbc b
    ld h, h
    and c
    ld h, h
    jp nz, $dc64

    ld h, h
    cpl
    ld h, l
    ld d, l
    ld h, l
    adc [hl]
    ld h, l
    or d
    ld h, l
    or d
    ld h, l
    rst $28
    ld h, l
    dec c
    ld h, [hl]
    bit 4, [hl]
    or $66
    ld a, [de]
    ld h, a
    ld h, $67
    inc l
    ld h, a
    ld [hl-], a
    ld h, a
    ld a, [hl-]
    ld h, a
    ld b, d
    ld h, a
    ld c, h
    ld h, a
    ld d, [hl]
    ld h, a
    ld h, b
    ld h, a
    ld [hl], d
    ld h, a
    ld [bc], a
    ld l, b
    inc l
    ld l, b
    jr c, jr_00e_616e

    add a
    ld l, b
    sub e
    ld l, b
    dec bc
    and l
    ld l, h
    nop
    ld c, $05
    nop
    ld a, [bc]
    and l
    and l
    ld l, e
    nop
    ld c, $a5
    ld l, h
    ld l, e
    nop
    rrca
    and l
    dec b
    nop
    ld de, $0025
    ld c, $6c
    ld h, b
    nop
    dec d
    inc bc
    nop
    dec d
    ld l, h
    nop
    inc de
    ld h, b
    ld l, e
    nop
    ld de, $a5a5
    and [hl]
    nop
    ld [de], a
    inc bc
    and a
    nop
    ld de, $a505
    and l
    dec b
    nop
    ld b, $70
    ld a, e
    nop
    rlca
    ld [hl], b
    ld [hl], c
    ld [hl], b
    nop
    add hl, bc
    ld [hl], b
    nop
    ld a, [bc]
    ld a, e
    ld [hl], b
    ld a, e
    nop
    add hl, bc
    ld [hl], b
    ld [hl], c
    ld a, e
    ld a, h
    nop
    dec bc
    ld a, e
    ld a, h
    nop
    dec bc
    ld [hl], b
    ld [hl], c
    nop
    ld a, [bc]
    ld a, e
    ld a, h
    ld a, e
    nop
    ld c, $7b
    ld [hl], b
    nop
    db $10
    ld [hl], b
    ld a, e
    ld [hl], b
    nop
    inc d
    ld a, l

jr_00e_616e:
    nop
    ld [de], a
    ld a, h
    ld a, e
    ld b, c
    nop
    inc de
    ld [hl], d
    ld [hl], d
    nop
    inc d
    ld a, e
    ld [hl], b
    ld b, c
    nop
    add hl, bc
    inc h
    inc h
    nop
    ld a, [bc]
    and l
    inc bc
    nop
    ld c, $64
    nop
    rra
    ld l, l
    ld l, l
    ld l, $00
    dec bc
    cp c
    cp h
    nop
    ld c, $04
    nop
    db $10
    inc h
    rrca
    nop
    ld c, $24
    rrca
    nop
    rrca
    inc bc
    rrca
    nop
    dec c
    cp c
    inc h
    cp c
    nop
    ld [de], a
    inc h
    rrca
    nop
    ld [de], a
    and l
    ld d, h
    nop
    rla
    rrca
    xor b
    nop
    jr jr_00e_6200

    ld c, l
    ld c, l
    nop
    inc de
    inc h
    and l
    inc bc
    ld c, l
    ld d, h
    nop
    ld d, $04
    inc b
    nop
    rla
    cp h
    cp l
    nop
    rla
    cp c
    cp d
    nop
    ld [de], a
    ld l, d
    rla
    nop
    ld de, $186a
    nop
    dec d

jr_00e_61d2:
    rla
    nop
    ld de, $175c
    jr jr_00e_61d9

jr_00e_61d9:
    ld [de], a
    jr jr_00e_61f7

    nop
    ld de, $5c5c
    ld e, h
    nop
    inc d
    ld l, d
    nop
    dec d
    ld d, h
    ld d, h
    nop
    dec bc
    dec sp
    ld h, b
    nop
    ld c, $a5
    ld l, h
    nop
    ld [de], a
    add hl, sp
    nop
    inc d
    or c
    nop

jr_00e_61f7:
    db $10
    dec b
    and [hl]
    nop
    ld [de], a
    dec sp
    dec sp
    ld h, b
    nop

jr_00e_6200:
    dec d
    ld hl, $00b0
    inc de
    and l
    dec sp
    ld l, h
    ld h, b
    nop
    dec e
    inc bc
    and a
    nop
    inc de
    sbc l
    nop
    db $10
    and l
    ld d, h
    nop
    db $10
    inc h
    inc h
    inc h
    nop
    ld d, $99
    nop
    ld [de], a
    cp c
    cp h
    cp c
    cp h
    nop
    rla
    ld c, l
    nop
    inc d
    ld d, h
    inc b
    nop
    dec d
    inc h
    sub [hl]
    nop
    dec d
    ld h, h
    inc h
    ld c, l
    nop
    ld d, $b9
    sbc c
    nop
    jr jr_00e_61d2

    add hl, bc
    nop
    jr jr_00e_6261

    ld c, l
    and l
    ld d, h
    ld c, l
    nop

jr_00e_6242:
    ld e, $47
    ld b, a
    nop
    dec de
    inc h
    ld c, l
    inc h
    sub [hl]
    nop
    inc e
    sbc l
    ld b, a
    ld e, h
    nop

Call_00e_6251:
    rra
    sbc l
    sbc [hl]
    nop
    ld d, $bc
    inc b
    nop
    inc d
    ld c, l
    cp c
    inc h
    nop
    inc de
    inc h
    and l

jr_00e_6261:
    and l
    cp h
    nop
    inc e
    cp d
    cp c
    cp c

jr_00e_6268:
    nop
    dec e
    ld d, h
    ld d, l
    nop
    ld hl, $0004
    dec e
    cp h
    cp c
    ld e, $00
    ld e, $18
    ld e, h
    ld a, [hl-]
    nop
    ld e, $12
    dec bc
    nop
    inc d
    ld de, $0025
    inc d
    dec h
    dec h
    dec h
    nop
    ld d, $b0
    ld de, $1900
    dec h
    nop
    jr z, jr_00e_6242

    inc de
    dec bc
    nop
    rla
    ld de, $0025
    dec bc
    xor l
    ld b, $00
    inc c
    dec c
    ld b, $37
    nop
    inc d
    ld b, $37
    ld b, $ad
    nop
    ld d, $0d
    adc b
    dec c
    nop
    ld a, [de]
    scf
    nop
    ld d, $37
    xor l
    adc a
    nop
    inc d
    xor l
    xor l
    scf
    xor l
    nop
    jr jr_00e_6268

    ld b, $00
    inc h
    ld d, d
    ld d, d
    ld d, e
    nop
    ld [hl+], a
    and e
    or b
    ld d, d
    ld hl, $2900
    and h
    nop
    dec h
    ld hl, $0052
    ld a, [bc]
    xor c
    xor c
    ld [hl+], a
    nop
    rrca
    ld l, d
    xor c
    nop
    dec c
    xor c
    xor c
    ld l, d
    xor c
    nop
    ld de, $0022
    dec d
    xor c
    ld [hl+], a
    nop
    inc d
    xor c
    ld l, d
    xor c
    nop
    dec d
    xor c
    ld [hl+], a
    nop
    inc de
    ld [hl+], a
    daa
    nop
    dec d
    xor c
    xor c
    daa
    nop
    add hl, de
    xor c
    nop
    inc d
    ld l, d
    ld [hl+], a
    nop
    inc de
    xor c
    ld l, d
    xor c
    xor c
    nop
    inc d
    ld [hl+], a
    ld [hl+], a
    xor c
    nop
    dec d
    xor c
    daa
    nop
    inc e
    scf
    scf
    scf
    nop
    dec e
    scf
    dec c
    nop
    add hl, de
    scf
    scf
    adc a
    scf
    dec c
    nop
    inc e
    scf
    dec c
    adc a
    nop
    dec e
    dec c
    scf
    nop
    ld hl, $008f
    ld a, [de]
    dec c
    dec c
    dec c
    dec c
    nop
    inc e
    adc a
    scf
    adc a
    nop
    ld hl, $0088
    dec e
    ld b, $06
    nop
    dec e
    adc a

jr_00e_633d:
    adc b
    nop
    add hl, de
    scf
    adc a
    scf
    scf
    adc a
    nop
    ld a, [de]
    scf
    scf
    dec c
    scf
    nop
    inc e
    dec c
    dec c
    scf
    nop
    dec e
    scf
    adc b
    nop
    dec e
    ld hl, $0052
    ld hl, $0021
    inc e
    ld d, d
    or b
    and e
    nop
    inc h
    ld hl, $5352
    nop
    add hl, hl
    and e
    nop
    dec h
    ld d, d
    ld hl, $2200
    or b
    or d
    nop
    ld h, $53
    nop
    ld [hl+], a
    ld hl, $00a3
    dec d
    ld b, $ad
    nop
    dec d
    xor l
    nop
    ld [de], a
    xor l
    xor l
    ld [hl], $00
    ld de, $189d
    sbc l
    nop
    ld de, $1b18
    rla
    nop
    ld d, $9d
    ld b, a
    sbc l
    nop
    jr jr_00e_63ad

    sbc l
    nop
    dec de
    sbc l
    nop
    dec d
    ld b, a
    rla
    sbc l
    ld e, h
    nop
    inc e
    sbc [hl]
    sbc l
    sbc [hl]
    sbc [hl]
    nop
    rra
    rla
    adc e
    nop
    dec de
    add l
    add l

jr_00e_63ad:
    add l
    add l
    add l
    add l
    nop
    ld hl, $9d9e
    nop
    jr jr_00e_633d

    add l
    nop
    db $10
    ld e, h
    rla
    nop
    ld e, $18
    rla
    nop
    dec e

Jump_00e_63c3:
    sbc l
    ld e, h
    dec de
    nop
    ld e, $47
    ld l, [hl]
    nop
    dec de
    ld e, h
    jr jr_00e_63e7

    sbc l
    nop
    dec e
    sbc l
    rla
    sbc [hl]
    nop
    ld e, $5c
    ld e, h
    nop
    dec de
    jr jr_00e_63f5

    dec de
    ld e, h
    sbc e
    nop
    rra
    rla
    adc e
    nop
    inc hl
    dec de

jr_00e_63e7:
    nop
    inc e
    ld e, h
    ld e, h
    ld e, l
    ld e, h
    nop
    ld hl, $9b5d
    nop
    dec h
    sbc b
    nop

jr_00e_63f5:
    ld hl, $b31b
    nop
    jr nz, jr_00e_6469

    jr jr_00e_645a

    nop
    inc e
    ld l, d
    add hl, sp
    ld l, d
    nop
    dec e
    add hl, sp
    ld l, d

jr_00e_6406:
    nop
    ld hl, $006a
    dec e
    add hl, sp
    ld [hl], l
    nop
    dec e
    ld l, d
    add hl, hl
    nop
    ld hl, $0029
    ld a, [de]
    add hl, sp
    add hl, sp
    add hl, hl
    ld l, d
    nop
    dec e
    ld [hl], l
    add hl, hl
    nop
    rra
    jr @+$1a

    sbc e
    nop
    ld [de], a
    ld b, a
    ld e, h
    nop
    ld [de], a

jr_00e_6429:
    cp h
    cp c
    nop
    ld [de], a
    ld b, $ad
    nop
    ld [de], a
    ld hl, $0052
    ld d, $47
    ld b, a
    ld l, [hl]
    nop
    ld d, $22
    xor c
    daa
    nop
    jr jr_00e_6461

    ld d, d
    nop
    dec d
    cp c
    cp h
    cp c
    cp h
    nop
    jr jr_00e_6406

    cp h
    nop
    ld a, [de]
    inc c
    nop
    dec de
    and l
    ld d, h
    and l
    nop
    dec e
    inc b
    ld c, l
    nop
    inc hl
    sbc [hl]

jr_00e_645a:
    nop
    ld e, $17
    rla
    adc e
    nop
    rra

jr_00e_6461:
    ld b, a
    sbc [hl]
    nop
    dec e
    sub [hl]
    ld h, l
    nop
    dec e

jr_00e_6469:
    sbc c
    add hl, bc
    nop
    ld hl, $bcbd
    cp l
    nop
    dec de

Call_00e_6472:
    ld b, a
    sbc l
    sbc [hl]
    sbc l
    ld b, a
    nop
    ld e, $9d
    sbc [hl]
    nop
    dec e
    dec de
    dec de
    dec de
    nop
    ld e, $5d
    ld e, h
    ld e, l
    nop
    rra
    ld h, $25
    ld a, [hl+]
    ld h, $00
    ld [hl+], a
    ld a, [hl+]
    ld h, $00
    ld hl, $2525
    ld [$2600], sp
    ld [$1400], sp
    ld b, $ad
    ld b, $00
    dec e
    ld b, $8d
    nop
    dec e
    ld h, $2a
    nop
    add hl, hl
    jr nc, jr_00e_6429

    ld h, $26
    nop
    rra
    jr nc, jr_00e_64de

    ld h, $30
    nop
    ld [hl+], a
    jr nc, @-$7d

    nop
    jr nc, jr_00e_64e1

    nop
    ld hl, $0081
    ld h, $81
    nop
    ld [hl+], a
    jr nc, jr_00e_64e7

    nop
    ld [hl+], a
    ld h, c
    dec l
    nop
    ld hl, $612d
    dec l
    nop
    dec hl
    ld [de], a
    nop
    daa
    dec l
    inc a
    nop
    inc l
    sub b
    add b
    nop
    ld a, [hl+]
    ld [de], a
    ld [hl], l
    dec l
    inc a
    nop
    dec e
    inc h

jr_00e_64de:
    sub [hl]
    nop
    add hl, de

jr_00e_64e1:
    dec b
    inc h
    inc h
    dec b
    dec b
    nop

jr_00e_64e7:
    ld a, [de]
    inc h
    sub [hl]
    dec b
    inc hl
    nop
    ld hl, $0040
    dec e
    dec b
    inc hl
    nop
    ld a, [de]
    sub [hl]
    ld b, b
    ld b, [hl]
    inc h
    nop
    inc e
    ld [hl], h
    ld b, [hl]
    ld b, [hl]
    nop
    dec e
    dec b
    inc hl
    nop
    ld [hl+], a
    ld [hl], h
    nop
    ld a, [de]
    dec b
    dec b
    inc hl
    dec b
    nop
    ld e, $23
    inc hl
    sub [hl]
    nop
    daa
    sub [hl]
    sub [hl]
    inc h
    sub [hl]
    nop
    ld a, [hl+]
    ld b, b
    inc hl
    nop
    inc e
    inc h
    ld b, [hl]
    sub [hl]
    nop
    ld a, [de]
    inc h
    dec b
    inc h
    inc hl
    nop
    dec e
    sub [hl]
    inc hl
    nop
    inc e
    dec b
    ld b, [hl]
    inc hl
    nop
    dec h
    dec hl
    inc l
    nop
    rra
    add hl, sp
    add hl, sp
    ld [hl], l
    nop
    jr nz, jr_00e_65a4

    add hl, hl
    nop
    inc h
    ld [hl], l
    nop
    rra
    ld l, d
    add hl, sp
    ld [hl], l
    nop
    jr z, jr_00e_65b0

    add hl, hl
    nop
    dec hl
    add hl, hl
    nop
    ld h, $29
    ld l, d
    add hl, hl
    nop
    dec hl
    add hl, hl
    ld l, d
    add hl, hl
    nop
    dec b
    or c
    nop
    dec b
    sbc c
    nop
    dec b
    or b
    nop
    rst $38
    add hl, bc
    inc h
    ld [$00b1], sp
    rst $38
    add hl, bc
    inc h
    ld [$0099], sp
    rst $38
    add hl, bc
    inc h
    ld [$00b0], sp
    rst $38
    ld [de], a
    sub [hl]
    rrca
    sub h
    rrca
    and l
    ld de, $00b1
    rst $38
    ld [de], a
    sub [hl]
    rrca
    sub h
    rrca
    and l
    ld de, $0099
    rst $38
    ld [de], a
    sub [hl]
    rrca
    sub h
    rrca
    and l
    ld de, $00b0
    rst $38
    ld b, d
    inc a
    ld b, e
    ld a, [bc]
    ld b, h
    inc d
    ld b, l
    inc e
    ld b, [hl]
    ld d, $00
    rst $38
    ld b, d
    inc a
    ld b, e
    ld a, [bc]
    ld b, h
    inc d
    ld b, l
    sbc d
    ld b, [hl]

jr_00e_65a4:
    ld d, $00
    rst $38
    ld b, d
    inc a
    ld b, e
    ld a, [bc]
    ld b, h
    inc d
    ld b, l
    or h
    ld b, [hl]

jr_00e_65b0:
    ld d, $00
    ld [hl+], a
    scf
    ld b, $00
    ld a, [de]
    dec c
    adc a
    scf
    adc a
    nop
    inc e
    xor l
    ld b, $36
    nop
    dec e
    adc l
    adc a
    nop
    ld hl, $008d
    ld a, [de]
    ld [hl], $37
    adc a
    xor l
    nop
    add hl, de
    ld b, $37
    ld [hl], $ad
    scf
    nop
    dec e
    adc l
    adc b
    nop
    dec e
    dec c
    adc l
    nop
    inc e
    ld b, $37
    ld [hl], $00
    dec e
    xor l
    scf
    nop
    ld hl, $36ad
    ld b, $00
    ld [hl+], a
    xor l
    adc l
    nop
    rst $38
    add hl, de
    ld [hl+], a
    jr jr_00e_6606

    dec e
    ld [bc], a
    nop
    rst $38
    dec h
    and a
    inc hl
    ld [bc], a
    dec h
    ld [de], a
    add hl, hl
    stop
    rst $38
    dec l
    ld [de], a
    ld a, [hl+]
    db $76

jr_00e_6606:
    inc l
    db $10
    dec l
    rlca
    ld [hl-], a
    ld bc, $0d00
    and l
    ld l, e
    nop
    dec bc
    ld h, b
    and l
    ld l, e
    nop
    inc c
    ld l, e
    ld l, h
    nop
    db $10
    and [hl]
    nop
    ld de, $306a
    nop
    rrca
    ld l, h
    ld l, e
    nop
    inc d
    and [hl]
    ld l, e
    nop
    dec d
    jr nc, jr_00e_6696

    nop
    dec d
    and [hl]
    and [hl]
    nop
    inc d
    dec c
    scf
    scf
    nop
    inc de
    and l
    and [hl]
    and [hl]
    and l
    nop

jr_00e_663c:
    ld d, $0d
    scf
    nop
    ld de, $376b
    dec c
    ld l, e
    and [hl]
    nop
    inc d
    and l
    and [hl]
    jr nc, jr_00e_664c

jr_00e_664c:
    dec d
    ld l, d
    ld l, d
    nop
    rla
    ld h, b
    ld l, h
    ld h, c
    nop
    rla
    ld l, h
    ld h, b
    dec l
    nop
    dec d

jr_00e_665b:
    scf
    ld l, e
    nop
    add hl, de
    ld l, e
    ld l, e
    add d
    nop
    ld a, [de]
    scf
    jr nc, jr_00e_6667

jr_00e_6667:
    rla
    ld l, e
    and l
    and [hl]
    ld l, e
    nop
    ld a, [de]
    jr nc, jr_00e_66a7

    nop
    dec e
    ld de, $006b
    add hl, de
    add d
    ld l, e
    ld l, e
    and [hl]
    ld l, e
    nop
    inc e
    and [hl]
    add c
    and [hl]
    nop
    dec e
    ld l, d
    jr nc, jr_00e_6685

jr_00e_6685:
    inc e
    ld l, h
    ld l, e
    ld de, $2100
    dec l
    nop
    ld hl, $0081
    dec e
    ld l, d
    add hl, hl
    nop
    inc e
    ld l, e

jr_00e_6696:
    ld l, e
    add d
    nop
    ld a, [de]
    and [hl]
    dec l
    scf
    add d
    nop
    dec e
    ld de, $0011
    dec e
    ld h, b
    ld h, c
    nop

jr_00e_66a7:
    ld a, [de]
    and [hl]
    ld l, e
    add d
    and l
    nop
    inc e
    adc a
    add d
    scf
    nop
    inc e
    jr nc, jr_00e_66c2

jr_00e_66b5:
    ld l, d
    nop
    inc e
    add d
    jr nc, jr_00e_663c

    nop
    ld hl, $0029
    add hl, de
    and l
    and l

jr_00e_66c2:
    ld l, e
    and l
    ld l, h
    nop
    jr nz, jr_00e_66d9

    jr nc, jr_00e_665b

    nop
    daa
    and a
    rlca
    nop
    dec hl
    ld a, [bc]
    adc e
    inc d
    nop
    dec hl
    adc d
    sbc e
    inc e
    nop

jr_00e_66d9:
    dec l
    adc d
    sbc b
    nop
    ld a, [hl+]
    add hl, bc
    or e
    or d
    or h
    nop
    inc l
    add hl, bc
    or e
    or d
    nop
    ld sp, $0007
    inc l
    adc d
    adc e
    nop
    daa
    ld h, c
    halt
    dec hl
    ld [de], a
    nop
    jr jr_00e_66b5

    cp d
    add hl, bc
    nop
    dec hl
    cp h
    cp l
    cp [hl]
    nop
    dec hl
    ld l, $78
    jr z, jr_00e_6705

jr_00e_6705:
    ld l, $bb
    ld a, l
    nop
    inc l
    sub b
    ld d, e
    nop
    dec l
    add hl, bc
    sbc d
    nop
    dec l
    xor b
    stop
    dec hl
    sub b
    ld d, e
    ld d, l
    nop
    rst $38
    dec [hl]
    ld [hl+], a
    scf
    inc l
    scf
    dec hl
    jr c, jr_00e_6745

    ld a, [hl-]
    ld a, [hl]
    nop
    rst $38
    inc c
    xor c
    ld c, $22
    nop
    rst $38
    ld [de], a
    dec de
    dec d
    sbc b
    nop
    rst $38
    dec d
    ld b, $12
    ld d, h
    jr jr_00e_678e

    nop
    rst $38
    dec e
    cp [hl]
    jr jr_00e_675d

    dec e
    cp e
    nop
    rst $38
    dec h
    scf

jr_00e_6745:
    daa
    adc b
    dec h
    scf
    dec hl
    adc a
    nop
    rst $38
    ld a, [hl+]
    ld hl, $a328
    ld a, [hl+]
    and h
    cpl
    inc d
    nop
    rst $38
    ld h, $26
    dec h
    ld a, [hl+]
    ld h, $77

jr_00e_675d:
    dec hl
    sub l
    nop
    ld [de], a
    ld hl, $0021
    inc de

jr_00e_6765:
    inc bc
    rrca
    nop
    rla
    ld d, h
    nop
    jr nc, jr_00e_67e2

    nop
    ld de, $a321
    nop
    rst $38
    inc de
    sub [hl]
    db $10
    and [hl]
    ld [de], a
    ld h, $14
    or e
    nop
    rst $38
    inc de
    sub [hl]
    db $10
    and [hl]
    ld [de], a
    ld h, $14
    add hl, bc
    nop
    rst $38
    inc de
    sub [hl]
    db $10
    and [hl]

jr_00e_678b:
    ld [de], a
    ld h, $14

jr_00e_678e:
    or d
    nop
    rst $38
    add hl, de
    sub [hl]
    rla
    ld hl, $0c16
    inc d
    ld h, $19
    or e
    nop
    rst $38
    add hl, de
    sub [hl]
    rla
    ld d, $16
    ld hl, $2614
    add hl, de
    add hl, bc
    nop
    rst $38
    add hl, de
    sub [hl]
    rla
    inc c
    ld d, $16
    inc d
    ld h, $19
    or d
    nop
    rst $38
    dec h
    sub a
    ld h, $21
    inc hl
    inc c
    inc hl
    sub l
    jr z, jr_00e_67db

    nop
    rst $38
    dec h
    sub a
    ld h, $16
    inc hl
    ld hl, $9523
    jr z, jr_00e_6765

    nop
    rst $38
    dec h
    sub a
    ld h, $0c
    inc hl
    ld d, $23
    sub l
    jr z, jr_00e_678b

    nop
    rst $38
    cpl
    sub a

jr_00e_67db:
    dec l
    ld [de], a
    dec l
    ld hl, $0c2f
    ld [hl-], a

jr_00e_67e2:
    sub l
    dec [hl]
    inc e
    nop
    rst $38
    cpl
    sub a
    dec l
    ld [de], a
    dec l
    ld d, $2f
    ld hl, $9532
    dec [hl]
    sbc d
    nop
    rst $38
    cpl
    sub a
    dec l
    ld [de], a
    dec l
    inc c
    cpl
    ld d, $32
    sub l
    dec [hl]
    or h
    nop
    rst $38
    dec a
    sub a
    dec sp
    sub l
    dec a
    ld bc, $143d
    ccf
    ld a, [bc]
    ld b, c

jr_00e_680e:
    inc e
    nop
    rst $38
    dec a
    sub a
    dec sp
    sub l
    dec a
    ld bc, $163d
    ccf
    inc d
    ld b, c
    sbc d
    nop
    rst $38
    dec a
    sub a
    dec sp
    sub l
    dec a
    ld bc, $0a3d
    ccf
    ld d, $41
    or h
    nop
    rst $38
    ld [hl], $78
    dec [hl]
    adc e
    ld [hl], $08
    jr c, jr_00e_687d

    jr c, jr_00e_684a

    nop
    ld d, $19
    nop
    jr jr_00e_6856

    nop
    rla
    add hl, de
    add hl, de
    nop
    jr jr_00e_685d

    nop
    rla
    add hl, de
    nop
    jr jr_00e_6863

jr_00e_684a:
    nop
    jr @-$6b

    nop
    ld d, $19
    nop
    jr jr_00e_686c

    nop
    rla
    add hl, de

jr_00e_6856:
    add hl, de
    nop
    jr jr_00e_6873

    nop
    ld d, $19

jr_00e_685d:
    nop
    jr @+$1b

    nop
    rla
    sub e

jr_00e_6863:
    nop
    jr jr_00e_687f

    nop
    ld d, $19

Call_00e_6869:
    nop
    jr jr_00e_6885

jr_00e_686c:
    nop
    ld d, $93
    nop
    ld d, $19
    add hl, de

jr_00e_6873:
    add hl, de
    nop
    jr jr_00e_6890

    nop
    jr jr_00e_6893

    nop
    ld [hl+], a
    add hl, de

jr_00e_687d:
    sub e
    nop

jr_00e_687f:
    ld h, $93
    nop
    ld hl, $1919

jr_00e_6885:
    sub e
    nop
    rst $38
    jr c, jr_00e_6898

    jr c, jr_00e_680e

    scf
    sub e
    ld a, [hl-]
    dec l

jr_00e_6890:
    inc a
    ld c, $00

jr_00e_6893:
    rst $38
    ld a, [hl-]
    ld d, $38
    ld e, c

jr_00e_6898:
    jr c, jr_00e_68f3

    inc a
    xor e
    ld a, $42
    nop
    and a
    ld a, [$d034]
    dec a
    ret z

    ld a, [$d0f0]
    cp $04
    ret z

    ld a, [$d018]
    dec a
    ld c, a
    ld b, $00
    ld hl, $68cd
    add hl, bc
    add hl, bc
    add hl, bc
    ld a, [$ccdf]
    and a
    ret z

    inc hl
    inc a
    jr nz, jr_00e_68c6

    dec hl
    ld a, [hl+]
    ld [$ccdf], a

jr_00e_68c6:
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    call Call_000_3e8c
    jp hl


    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    ld e, d

jr_00e_68f3:
    ld l, c
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    inc bc
    ld e, d
    ld l, c
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    ld [bc], a
    ld h, b
    ld l, c
    inc bc
    inc b
    ld l, d
    inc bc
    inc b
    ld l, d
    ld bc, $6a04
    inc bc
    inc b
    ld l, d
    ld bc, $6966
    inc bc
    inc b
    ld l, d
    ld [bc], a
    ld l, h
    ld l, c
    ld bc, $6972
    ld [bc], a
    pop hl
    ld l, c
    dec b
    add l
    ld l, c
    ld bc, $698d
    ld bc, $6993
    ld bc, $6999
    ld [bc], a
    and l
    ld l, c
    ld [bc], a
    xor e
    ld l, c
    ld bc, $69b1
    inc bc
    inc b
    ld l, d
    ld bc, $69bd
    ld bc, $69c9
    ld [bc], a
    push de
    ld l, c
    inc bc
    inc b
    ld l, d
    ld [bc], a
    rst $20
    ld l, c
    ld bc, $69f8
    cp $40
    ret nc

    jp Jump_00e_6a9b


    cp $20
    ret nc

    jp Jump_00e_6b71


    cp $40
    ret nc

    jp Jump_00e_6b34


    cp $40
    ret nc

    jp Jump_00e_6b71


    cp $40
    ld a, $0a
    call Call_00e_6b4e
    jp c, Jump_00e_6a47

    ld a, $05
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a9b


    ld a, [$cfd0]
    and a
    ret z

    jp Jump_00e_6b05


    cp $40
    ret nc

    jp Jump_00e_6b77


    cp $40
    ret nc

    jp Jump_00e_6b7d


    cp $80
    ret nc

    ld a, $0a
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a41


    cp $40
    ret nc

    jp Jump_00e_6b71


    cp $40
    ret nc

    jp Jump_00e_6a41


    cp $40
    ret nc

    ld a, $0a
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a47


    cp $20
    ret nc

    ld a, $05
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a3b


    cp $20
    ret nc

    ld a, $05
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a11


    cp $80
    ret nc

    ld a, $05
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a41


    cp $40
    ret nc

    jp Jump_00e_6b77


    cp $14
    jp c, Jump_00e_6a9b

    cp $80
    ret nc

    ld a, $04
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a41


    cp $80
    ret nc

    ld a, $05
    call Call_00e_6b4e
    ret nc

    jp Jump_00e_6a47


    and a
    ret


Jump_00e_6a06:
    ld hl, $ccdf
    dec [hl]
    scf
    ret


Call_00e_6a0c:
    ld a, $8e
    jp Jump_000_3788


Jump_00e_6a11:
    call Call_00e_6b10
    ld a, $10
    ld [$cf00], a
    ld de, $cee6
    ld hl, $cfce
    ld a, [hl-]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    inc de
    ld hl, $cfdc
    ld a, [hl-]
    ld [de], a
    inc de
    ld [$cee4], a
    ld [$cfce], a
    ld a, [hl]
    ld [de], a
    ld [$cee5], a
    ld [$cfcd], a
    jr jr_00e_6a89

Jump_00e_6a3b:
    ld a, $14
    ld b, $14
    jr jr_00e_6a4b

Jump_00e_6a41:
    ld a, $13
    ld b, $32
    jr jr_00e_6a4b

Jump_00e_6a47:
    ld a, $12
    ld b, $c8

jr_00e_6a4b:
    ld [$cf00], a
    ld hl, $cfce
    ld a, [hl]
    ld [$cee6], a
    add b
    ld [hl-], a
    ld [$cee8], a
    ld a, [hl]
    ld [$cee7], a
    ld [$cee9], a
    jr nc, jr_00e_6a68

    inc a
    ld [hl], a
    ld [$cee9], a

jr_00e_6a68:
    inc hl
    ld a, [hl-]
    ld b, a
    ld de, $cfdc
    ld a, [de]
    dec de
    ld [$cee4], a
    sub b
    ld a, [hl+]
    ld b, a
    ld a, [de]
    ld [$cee5], a
    sbc b
    jr nc, jr_00e_6a89

    inc de
    ld a, [de]
    dec de
    ld [hl-], a
    ld [$cee8], a
    ld a, [de]
    ld [hl], a
    ld [$cee9], a

jr_00e_6a89:
    call Call_00e_6bb4
    ld hl, $c3ca
    xor a
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d
    jp Jump_00e_6a06


Jump_00e_6a9b:
    ld a, [$d81b]
    ld c, a
    ld hl, $d824
    ld d, $00

jr_00e_6aa4:
    ld a, [hl+]
    ld b, a
    ld a, [hl-]
    or b
    jr z, jr_00e_6aab

    inc d

jr_00e_6aab:
    push bc
    ld bc, $002c
    add hl, bc
    pop bc
    dec c
    jr nz, jr_00e_6aa4

    ld a, d
    cp $02
    jp nc, Jump_00e_6abc

    and a
    ret


Jump_00e_6abc:
    ld a, [$cfcf]
    ld hl, $d824
    ld bc, $002c
    call Call_000_3ad1
    ld d, h
    ld e, l
    ld hl, $cfcd
    ld bc, $0004
    call Call_000_01bb
    ld hl, $6af2
    call Call_000_3c79
    ld a, $01
    ld [$d0e2], a
    ld hl, $49f8
    ld b, $0f
    call Call_000_3620
    xor a
    ld [$d0e2], a
    ld a, [$d0f0]
    cp $04
    ret z

    scf
    ret


    db $ed
    add hl, hl
    ld c, [hl]
    ld l, c
    jp z, Jump_00e_504f

    ld bc, $cfc1
    nop
    db $dd
    set 3, a
    cp d
    jp nc, $e7c0

    ld e, b

Jump_00e_6b05:
    call Call_00e_6a0c
    call Call_00e_6b10
    ld a, $34
    jp Jump_00e_6bab


Call_00e_6b10:
    ld a, [$cfcf]
    ld hl, $d827
    ld bc, $002c
    call Call_000_3ad1
    xor a
    ld [hl], a
    ld [$cfd0], a
    ld hl, $d046
    res 0, [hl]
    ret


    call Call_00e_6a0c
    ld hl, $d045
    set 0, [hl]
    ld a, $2e
    jp Jump_00e_6bab


Jump_00e_6b34:
    call Call_00e_6a0c
    ld hl, $d045
    set 1, [hl]
    ld a, $37
    jp Jump_00e_6bab


    call Call_00e_6a0c
    ld hl, $d045
    set 2, [hl]
    ld a, $3a
    jp Jump_00e_6bab


Call_00e_6b4e:
    ldh [$99], a
    ld hl, $cfdb
    ld a, [hl+]
    ldh [$95], a
    ld a, [hl]
    ldh [$96], a
    ld b, $02
    call Call_000_3902
    ldh a, [$98]
    ld c, a
    ldh a, [$97]
    ld b, a
    ld hl, $cfce
    ld a, [hl-]
    ld e, a
    ld a, [hl]
    ld d, a
    ld a, d
    sub b
    ret nz

    ld a, e
    sub c
    ret


Jump_00e_6b71:
    ld b, $0a
    ld a, $41
    jr jr_00e_6b87

Jump_00e_6b77:
    ld b, $0b
    ld a, $42
    jr jr_00e_6b87

Jump_00e_6b7d:
    ld b, $0c
    ld a, $43
    jr jr_00e_6b87

    ld b, $0d
    ld a, $44

jr_00e_6b87:
    ld [$cf00], a
    push bc
    call Call_00e_6bb4
    pop bc
    ld hl, $cfb4
    ld a, [hl-]
    push af
    ld a, [hl]
    push af
    push hl
    ld a, $af
    ld [hl+], a
    ld [hl], b
    ld hl, $7762
    ld b, $0f
    call Call_000_3620
    pop hl
    pop af
    ld [hl+], a
    pop af
    ld [hl], a
    jp Jump_00e_6a06


Jump_00e_6bab:
    ld [$cf00], a
    call Call_00e_6bb4
    jp Jump_00e_6a06


Call_00e_6bb4:
    ld a, [$cf00]
    ld [$d0e3], a
    call Call_000_1add
    ld hl, $6bc3
    jp Jump_000_3c79


    db $ed
    add hl, hl
    ld l, e
    ld l, c
    jp z, Jump_00e_507f

    ld bc, $cfc1
    nop
    add $4f
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    jp nz, $dfb6

    ret nz

    ld e, b
    call Call_00e_6bf0
    call Call_00e_6bfc
    ld a, [$d034]
    dec a
    ret z

    jp Jump_00e_6c1a


    call Call_00e_6bf0
    jp Jump_00e_6c1a


Call_00e_6bf0:
    ld de, $6d11
    ld hl, $8310
    ld bc, $0e04
    jp Jump_000_02dd


Call_00e_6bfc:
    call Call_00e_6c95
    ld hl, $d12b
    ld de, $d123
    call Call_00e_6c39
    ld a, $60
    ld hl, $d05e
    ld [hl+], a
    ld [hl], a
    ld a, $08
    ld [$cd3e], a
    ld hl, $c300
    jp Jump_00e_6c74


Jump_00e_6c1a:
    call Call_00e_6cac
    ld hl, $d823
    ld de, $d81b
    call Call_00e_6c39
    ld hl, $d05e
    ld a, $48
    ld [hl+], a
    ld [hl], $20
    ld a, $f8
    ld [$cd3e], a
    ld hl, $c318
    jp Jump_00e_6c74


Call_00e_6c39:
    ld a, [de]
    push af
    ld de, $cee4
    ld c, $06
    ld a, $34

jr_00e_6c42:
    ld [de], a
    inc de
    dec c
    jr nz, jr_00e_6c42

    pop af
    ld de, $cee4

jr_00e_6c4b:
    push af
    call Call_00e_6c55
    inc de
    pop af
    dec a
    jr nz, jr_00e_6c4b

    ret


Call_00e_6c55:
    inc hl
    ld a, [hl+]
    and a
    jr nz, jr_00e_6c60

    ld a, [hl]
    and a
    ld b, $33
    jr z, jr_00e_6c6b

jr_00e_6c60:
    inc hl
    inc hl
    ld a, [hl]
    and a
    ld b, $32
    jr nz, jr_00e_6c6d

    dec b
    jr jr_00e_6c6d

jr_00e_6c6b:
    inc hl
    inc hl

jr_00e_6c6d:
    ld a, b
    ld [de], a
    ld bc, $0028
    add hl, bc
    ret


Call_00e_6c74:
Jump_00e_6c74:
    ld de, $cee4
    ld c, $06

jr_00e_6c79:
    ld a, [$d05f]
    ld [hl+], a
    ld a, [$d05e]
    ld [hl+], a
    ld a, [de]
    ld [hl+], a
    xor a
    ld [hl+], a
    ld a, [$d05e]
    ld b, a
    ld a, [$cd3e]
    add b
    ld [$d05e], a
    inc de
    dec c
    jr nz, jr_00e_6c79

    ret


Call_00e_6c95:
    ld hl, $6ca9
    ld de, $cd3f
    ld bc, $0003
    call Call_000_01bb
    ld hl, $c47a
    ld de, $ffff
    jr jr_00e_6cc3

    ld [hl], e
    ld [hl], a
    ld l, a

Call_00e_6cac:
    ld hl, $6cc0
    ld de, $cd3f
    ld bc, $0003
    call Call_000_01bb
    ld hl, $c3c9
    ld de, $0001
    jr jr_00e_6cc3

    ld [hl], e
    ld [hl], h
    ld a, b

jr_00e_6cc3:
    ld [hl], $73
    ld bc, $0014
    add hl, bc
    ld a, [$cd40]
    ld [hl], a
    ld a, $08

jr_00e_6ccf:
    add hl, de
    ld [hl], $76
    dec a
    jr nz, jr_00e_6ccf

    add hl, de
    ld a, [$cd41]
    ld [hl], a
    ret


    call Call_00e_6bf0
    ld hl, $d12b
    ld de, $d123
    call Call_00e_6c39
    ld hl, $d05e
    ld a, $50
    ld [hl+], a
    ld [hl], $40
    ld a, $08
    ld [$cd3e], a
    ld hl, $c300
    call Call_00e_6c74
    ld hl, $d823
    ld de, $d81b
    call Call_00e_6c39
    ld hl, $d05e
    ld a, $50
    ld [hl+], a
    ld [hl], $60
    ld hl, $c318
    jp Jump_00e_6c74


    nop
    nop
    inc e
    inc e
    ld [hl+], a
    ld a, $51
    ld l, a
    ld b, c
    ld a, a
    ld a, a
    ld b, c
    ld a, $22
    inc e
    inc e
    nop
    nop
    inc e
    inc e
    ld a, $3e
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, $3e
    inc e
    inc e
    nop
    nop
    ld b, c
    ld e, l
    ld a, $22
    ld a, $55
    ld a, $49
    ld a, $55
    ld a, $22
    ld b, c
    ld e, l
    nop
    nop
    inc e
    nop
    ld [hl+], a
    nop
    ld b, c
    nop
    ld b, c
    nop
    ld b, c
    nop
    ld [hl+], a
    nop
    inc e
    nop
    ccf
    ccf
    ld a, a
    ld a, a
    jp $c3c3


    jp $ffff


    ret nz

    ret nz

    ret nz

    ret nz

    jp $ffc3


    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    db $fc
    db $fc
    cp $fe
    jp $c3c3


    jp $fbfb


    rlca
    rlca
    inc bc
    inc bc
    jp $c7c3


    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    ccf
    db $fc
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
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
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    db $e3
    ccf
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
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
    nop
    rst $38
    nop
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    rst $00
    jp $c0c3


    ret nz

    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    db $fc
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
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
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    nop
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    ccf
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    db $fc
    db $fc
    nop
    nop
    db $e3
    db $e3
    db $e3
    db $e3
    jp $c3c3


    jp $8383


    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ldh a, [$f0]
    ldh a, [$f0]
    sub b
    sub b
    ldh a, [$f0]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    inc bc
    ld b, $06
    dec c
    dec c
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    jp Jump_00e_63c3


    ld h, e
    or e
    or e
    rst $08
    rst $08
    call $cdcd
    call $cfcf
    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    sbc a
    sbc a
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    sbc a
    sbc a
    ldh a, [$f0]
    sub b
    sub b
    ldh a, [$f0]
    ldh a, [$f0]
    rlca
    rlca
    inc c
    inc c
    dec de
    dec de
    rla
    rla
    rla
    rla
    dec de
    dec de
    inc c
    inc c
    rlca
    rlca
    adc e
    adc e
    set 1, e
    ld l, l
    ld l, l
    and [hl]
    and [hl]
    and e
    and e
    ld h, b
    ld h, b
    ret nz

    ret nz

    add b
    add b
    db $d3
    db $d3
    db $d3
    db $d3
    or e
    or e
    ld h, e
    ld h, e
    jp Jump_000_03c3


    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    nop
    nop
    nop
    nop
    nop
    nop
    inc c
    inc c
    inc a
    inc a
    pop af
    pop af
    pop bc
    pop bc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr jr_00e_6f21

    ld a, b
    ld a, b
    ldh [$e0], a
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
    ld [bc], a
    ld [bc], a
    ld a, [bc]
    ld a, [bc]
    add hl, hl
    add hl, hl
    and l
    and l

jr_00e_6f21:
    inc bc
    inc bc
    inc bc
    inc bc
    inc hl
    inc hl
    and e
    and e
    sub e
    sub e
    ld d, e
    ld d, e
    ld c, e
    ld c, e
    dec hl
    dec hl
    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ld a, a
    ld a, a
    ccf
    ccf
    nop
    nop
    nop
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
    sub h
    sub h
    ld d, d
    ld d, d
    ld c, d
    ld c, d
    jr z, jr_00e_6f81

    jr nz, jr_00e_6f7b

    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    and e
    and e
    add a
    add a
    ld b, $06
    ld c, $0e
    inc e
    inc e
    ld a, b
    ld a, b
    ldh a, [$f0]
    ret nz

    ret nz

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

jr_00e_6f7b:
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop

jr_00e_6f81:
    rst $38
    nop
    nop
    rst $38
    nop
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
    rra
    rra
    ld a, a
    ld a, a
    ldh [rIE], a
    ret nz

    rst $38
    pop bc
    cp $00
    nop
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    jp $c3fc


    db $fc
    jp $c3fc


    db $fc
    jp $c3fc


    db $fc
    jp $fffc


    rst $38
    rst $38
    nop
    ldh [$1f], a
    ret nz

    ccf
    pop bc
    ccf
    jp $c33f


    ccf
    jp $ff3f


    rst $38
    jp $c3fc


    db $fc
    db $e3
    db $fc
    rst $38
    rst $38
    ld a, a
    ld a, a
    nop
    nop
    nop
    nop
    nop
    nop
    jp $c33f


    ccf
    rst $00
    ccf
    rst $38
    rst $38
    cp $fe
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0301
    inc bc
    rlca
    rlca
    rlca
    ld b, $07
    ld b, $07
    ld b, $07
    rlca
    inc bc
    inc bc
    add b
    add b
    ret nz

    ret nz

    ldh [$e0], a
    ldh [$60], a
    ldh [$60], a
    ldh [$60], a
    ldh [$e0], a
    ret nz

    ret nz

    cp $fe
    ld h, a
    ld h, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld h, a
    ld h, a
    cp $fe
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    db $fc
    db $fc
    ld b, $fe
    inc bc
    rst $38
    pop hl
    rra
    pop af
    rrca
    add hl, sp
    rst $00
    add hl, de
    rst $20
    sbc c
    rst $20
    sbc c
    rst $20
    add hl, de
    rst $20
    add hl, de
    rst $20
    ld sp, hl
    rlca
    pop af
    rrca
    inc bc
    rst $38
    ld b, $fe
    db $fc
    db $fc
    sbc c
    rst $20
    sbc c
    rst $20
    sbc c
    rst $20
    sbc c
    rst $20
    sbc c
    rst $20
    sbc c
    rst $20
    sbc c
    rst $20
    sbc c
    rst $20
    rlca
    rlca
    jr jr_00e_7084

    jr c, jr_00e_708e

    ld a, b
    ld b, a
    ld a, b
    ld b, a
    ld hl, sp-$79
    ld hl, sp-$79
    ld hl, sp-$79
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    rrca
    inc c
    inc de
    inc e
    inc de
    inc e
    inc hl
    inc a
    inc hl
    inc a
    nop
    nop
    nop

jr_00e_7084:
    nop
    rra
    rra
    rst $38
    rst $38
    ldh [rIE], a
    nop
    rst $38
    inc bc

jr_00e_708e:
    db $fc
    rst $38
    nop
    rlca
    rlca
    rra
    rra
    ld a, b
    ld a, a
    ldh [rIE], a
    ret nz

    rst $38
    inc bc
    db $fc
    rra
    ldh [rIE], a
    nop
    ld hl, $ccd3
    xor a
    ld [hl], a
    ld a, [$cf79]
    ld c, a
    ld b, $01
    call Call_00e_7422
    ldh a, [$d7]
    push af
    xor a
    ld [$d0e6], a
    dec a
    ld [$cf79], a
    push hl
    push bc
    push de
    ld hl, $d123
    push hl

Jump_00e_70c1:
jr_00e_70c1:
    ld hl, $cf79
    inc [hl]
    pop hl
    inc hl
    ld a, [hl]
    cp $ff
    jp z, Jump_00e_7271

    ld [$cee4], a
    push hl
    ld a, [$cf79]
    ld c, a
    ld hl, $ccd3
    ld b, $02
    call Call_00e_7422
    ld a, c
    and a
    jp z, Jump_00e_70c1

    ld a, [$cee4]
    dec a
    ld b, $00
    ld hl, $7427
    add a
    rl b
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    push hl
    ld a, [$cf78]
    push af
    xor a
    ld [$cc49], a
    call Call_000_2d68
    pop af
    ld [$cf78], a
    pop hl

Jump_00e_7104:
    ld a, [hl+]
    and a
    jr z, jr_00e_70c1

    ld b, a
    cp $03
    jr z, jr_00e_7124

    ld a, [$d0f0]
    cp $32
    jr z, jr_00e_70c1

    ld a, b
    cp $02
    jr z, jr_00e_7137

    ld a, [$ccd4]
    and a
    jr nz, jr_00e_70c1

    ld a, b
    cp $01
    jr z, jr_00e_7140

jr_00e_7124:
    ld a, [$d0f0]
    cp $32
    jp nz, Jump_00e_726c

    ld a, [hl+]
    ld b, a
    ld a, [$cfa0]
    cp b
    jp c, Jump_00e_70c1

    jr jr_00e_7149

jr_00e_7137:
    ld a, [hl+]
    ld b, a
    ld a, [$cf78]
    cp b
    jp nz, Jump_00e_726c

jr_00e_7140:
    ld a, [hl+]
    ld b, a
    ld a, [$cfa0]
    cp b
    jp c, Jump_00e_726d

jr_00e_7149:
    ld [$d0ec], a
    ld a, $01
    ld [$d0e6], a
    push hl
    ld a, [hl]
    ld [$cee5], a
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    call Call_000_386e
    ld hl, $7307
    call Call_000_3c79
    ld c, $32
    call Call_000_3781
    xor a
    ldh [$ba], a
    ld hl, $c3a0
    ld bc, $0c14
    call Call_000_0374
    ld a, $01
    ldh [$ba], a
    ld a, $ff
    ld [$cfb2], a
    call Call_000_0188
    ld hl, $7e15
    ld b, $1e
    call Call_000_3620
    jp c, Jump_00e_72c1

    ld hl, $72d1
    call Call_000_3c79
    pop hl
    ld a, [hl]
    ld [$d092], a
    ld [$cf7f], a
    ld [$cee5], a
    ld a, $01
    ld [$d093], a
    ld a, $0e
    ld [$d094], a
    call Call_000_37b3
    push hl
    ld hl, $72e0
    call Call_000_3c89
    ld a, $89
    call Call_000_3788
    call Call_000_3790
    ld c, $28
    call Call_000_3781
    call Call_000_03bf
    call Call_00e_728a
    ld a, [$d0e3]
    push af
    ld a, [$d092]
    ld [$d0e3], a
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld hl, $4000
    ld bc, $001c
    call Call_000_3ad1
    ld de, $d095
    call Call_000_01bb
    ld a, [$d092]
    ld [$d095], a
    pop af
    ld [$d0e3], a
    ld hl, $cf8f
    ld de, $cfa1
    ld b, $01
    call Call_000_3980
    ld a, [$cf79]
    ld hl, $d12b
    ld bc, $002c
    call Call_000_3ad1
    ld e, l
    ld d, h
    push hl
    push bc
    ld bc, $0022
    add hl, bc
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld hl, $cfa2
    ld a, [hl-]
    sub c
    ld c, a
    ld a, [hl]
    sbc b
    ld b, a
    ld hl, $cf81
    ld a, [hl]
    add c
    ld [hl-], a
    ld a, [hl]
    adc b
    ld [hl], a
    dec hl
    pop bc
    call Call_000_01bb
    ld a, [$d092]
    ld [$d0e3], a
    xor a
    ld [$cc49], a
    call Call_00e_7326
    pop hl
    ld a, $42
    call Call_000_3e9d
    ld a, [$d034]
    and a
    call z, Call_00e_731d
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $01
    ld hl, $d27b
    push bc
    call Call_00e_7422
    pop bc
    ld hl, $d28e
    call Call_00e_7422
    pop de
    pop hl
    ld a, [$cf7f]
    ld [hl], a
    push hl
    ld l, e
    ld h, d
    jr jr_00e_726d

Jump_00e_726c:
    inc hl

Jump_00e_726d:
jr_00e_726d:
    inc hl
    jp Jump_00e_7104


Jump_00e_7271:
    pop de
    pop bc
    pop hl
    pop af
    ldh [$d7], a
    ld a, [$d0f0]
    cp $32
    ret z

    ld a, [$d034]
    and a
    ret nz

    ld a, [$d0e6]
    and a
    call nz, Call_000_0d9b
    ret


Call_00e_728a:
    ld a, [$d092]
    push af
    ld a, [$d095]
    ld [$d092], a
    call Call_000_37b3
    pop af
    ld [$d092], a
    ld hl, $cd68
    ld de, $cf45

jr_00e_72a1:
    ld a, [de]
    inc de
    cp [hl]
    inc hl
    ret nz

    cp $50
    jr nz, jr_00e_72a1

    ld a, [$cf79]
    ld bc, $0006
    ld hl, $d257
    call Call_000_3ad1
    push hl
    call Call_000_37b3
    ld hl, $cd68
    pop de
    jp Jump_000_01bb


Jump_00e_72c1:
    ld hl, $72ef
    call Call_000_3c79
    call Call_000_03bf
    pop hl
    call Call_00e_731d
    jp Jump_00e_70c1


    db $ed
    add hl, hl
    and a
    ld l, c
    call nz, $e7b3
    ld a, a
    ld d, b
    ld bc, $cf45
    nop
    jp z, $ed57

    add hl, hl
    call nz, Call_00e_6869
    call $c600
    ld a, a
    cp h
    sbc $b6
    cp h
    ret nz

    ld d, a
    db $ed
    add hl, hl
    db $e4
    ld l, c
    and $4f
    ld d, b
    ld bc, $cf45
    nop
    ret


    ld a, a
    call $b6de
    ld h, $7f
    call nz, $dfcf
    ret nz

    rst $20
    ld e, b
    db $ed
    dec l
    dec sp
    ld e, e
    call nc, $e6e7
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ret


    ld a, a
    sub $b3
    cp l
    ld h, $56
    rst $20
    ld d, a

Call_00e_731d:
    ld a, [$d0f0]
    cp $32
    ret z

    jp Jump_000_1ba5


Call_00e_7326:
    ld hl, $7427
    ld a, [$d0e3]
    ld [$cf78], a
    dec a
    ld bc, $0000
    ld hl, $7427
    add a
    rl b
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_00e_733e:
    ld a, [hl+]
    and a
    jr nz, jr_00e_733e

jr_00e_7342:
    ld a, [hl+]
    and a
    jr z, jr_00e_737c

    ld b, a
    ld a, [$d0ec]
    cp b
    ld a, [hl+]
    jr nz, jr_00e_7342

    ld d, a
    ld a, [$cc49]
    and a
    jr nz, jr_00e_7361

    ld hl, $d133
    ld a, [$cf79]
    ld bc, $002c
    call Call_000_3ad1

jr_00e_7361:
    ld b, $04

jr_00e_7363:
    ld a, [hl+]
    cp d
    jr z, jr_00e_737c

    dec b
    jr nz, jr_00e_7363

    ld a, d
    ld [$d0bd], a
    ld [$d0e3], a
    call Call_000_1b6d
    call Call_000_386e
    ld a, $1b
    call Call_000_3e9d

jr_00e_737c:
    ld a, [$cf78]
    ld [$d0e3], a
    ret


    call Call_000_3ec4
    push hl
    push de
    push bc
    ld hl, $7427
    ld b, $00
    ld a, [$cf78]
    dec a
    add a
    rl b
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_00e_739a:
    ld a, [hl+]
    and a
    jr nz, jr_00e_739a

    jr jr_00e_73a2

jr_00e_73a0:
    pop de

jr_00e_73a1:
    inc hl

jr_00e_73a2:
    ld a, [hl+]
    and a
    jp z, Jump_00e_7415

    ld b, a
    ld a, [$d0ec]
    cp b
    jp c, Jump_00e_7415

    ld a, [$cee4]
    and a
    jr z, jr_00e_73bb

    ld a, [$cd3d]
    cp b
    jr nc, jr_00e_73a1

jr_00e_73bb:
    push de
    ld c, $04

jr_00e_73be:
    ld a, [de]
    inc de
    cp [hl]
    jr z, jr_00e_73a0

    dec c
    jr nz, jr_00e_73be

    pop de
    push de
    ld c, $04

jr_00e_73ca:
    ld a, [de]
    and a
    jr z, jr_00e_73ec

    inc de
    dec c
    jr nz, jr_00e_73ca

    pop de
    push de
    push hl
    ld h, d
    ld l, e
    call Call_00e_7419
    ld a, [$cee4]
    and a
    jr z, jr_00e_73eb

    push de
    ld bc, $0012
    add hl, bc
    ld d, h
    ld e, l
    call Call_00e_7419
    pop de

jr_00e_73eb:
    pop hl

jr_00e_73ec:
    ld a, [hl]
    ld [de], a
    ld a, [$cee4]
    and a
    jr z, jr_00e_73a0

    push hl
    ld a, [hl]
    ld hl, $0015
    add hl, de
    push hl
    dec a
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld de, $cee4
    ld a, $0e
    call Call_000_01a3
    ld a, [$cee9]
    pop hl
    ld [hl], a
    pop hl
    jr jr_00e_73a0

Jump_00e_7415:
    pop bc
    pop de
    pop hl
    ret


Call_00e_7419:
    ld c, $03

jr_00e_741b:
    inc de
    ld a, [de]
    ld [hl+], a
    dec c
    jr nz, jr_00e_741b

    ret


Call_00e_7422:
    ld a, $10
    jp Jump_000_3e9d


    and e
    ld [hl], l
    or c
    ld [hl], l
    cp l
    ld [hl], l
    adc $75
    ldh [$75], a
    rst $28
    ld [hl], l
    cp $75
    ld b, $76
    ld d, $76
    add hl, hl
    db $76
    dec l
    db $76
    add hl, sp
    db $76
    ld c, e
    db $76
    ld e, h
    db $76
    ld h, d
    db $76
    ld [hl], e
    db $76
    ld a, e
    db $76
    adc d
    db $76
    sbc e
    db $76
    xor c
    db $76
    xor e
    db $76
    or l
    db $76

Jump_00e_7453:
    pop bc
    db $76
    pop de
    db $76
    and $76
    rst $28
    db $76
    db $fd
    db $76
    ld de, $1f77
    ld [hl], a
    dec l
    ld [hl], a
    dec sp
    ld [hl], a
    dec a
    ld [hl], a
    ccf
    ld [hl], a
    ld c, a
    ld [hl], a
    ld e, e
    ld [hl], a
    ld h, a
    ld [hl], a
    ld a, b
    ld [hl], a
    adc c
    ld [hl], a
    sbc d
    ld [hl], a
    xor e
    ld [hl], a
    cp c
    ld [hl], a
    ret z

    ld [hl], a
    call nc, $e077
    ld [hl], a
    db $ec
    ld [hl], a
    ld hl, sp+$77
    inc b
    ld a, b
    inc de
    ld a, b
    inc h
    ld a, b
    ld [hl-], a
    ld a, b
    inc [hl]
    ld a, b
    ld b, d
    ld a, b
    ld b, h
    ld a, b
    ld d, b
    ld a, b
    ld e, [hl]
    ld a, b
    ld l, l
    ld a, b
    ld l, a
    ld a, b
    ld a, [hl]
    ld a, b
    adc l
    ld a, b
    sbc h
    ld a, b
    xor b
    ld a, b
    xor d
    ld a, b
    xor h
    ld a, b
    xor [hl]
    ld a, b
    cp d
    ld a, b
    bit 7, b
    rst $10
    ld a, b
    reti


    ld a, b
    db $db
    ld a, b
    db $dd
    ld a, b
    xor $78
    rst $38
    ld a, b
    dec c
    ld a, c
    dec d
    ld a, c
    dec e
    ld a, c
    dec h
    ld a, c
    daa
    ld a, c
    ld [hl], $79
    ld b, l
    ld a, c
    ld b, a
    ld a, c
    ld c, c
    ld a, c
    ld c, e
    ld a, c
    ld e, e
    ld a, c
    ld e, l
    ld a, c
    ld l, l
    ld a, c
    ld l, a
    ld a, c
    ld [hl], c
    ld a, c
    ld [hl], e
    ld a, c
    add d
    ld a, c
    sub c
    ld a, c
    sbc [hl]
    ld a, c
    xor b
    ld a, c
    or a
    ld a, c
    jp $c579


    ld a, c
    rst $00
    ld a, c
    sub $79
    ld [c], a
    ld a, c
    rst $28
    ld a, c
    ld sp, hl
    ld a, c
    dec c
    ld a, d
    rrca
    ld a, d
    dec h
    ld a, d
    scf
    ld a, d
    ld c, c
    ld a, d
    ld e, e
    ld a, d
    ld l, d
    ld a, d
    ld a, c
    ld a, d
    adc b
    ld a, d
    sub a
    ld a, d
    xor c
    ld a, d
    xor a
    ld a, d
    or h
    ld a, d
    cp c
    ld a, d
    rst $00
    ld a, d
    ret


    ld a, d
    rst $10
    ld a, d
    db $e3
    ld a, d
    rst $28
    ld a, d
    db $fd
    ld a, d
    add hl, bc
    ld a, e
    dec bc
    ld a, e
    dec c
    ld a, e
    ld [de], a
    ld a, e
    rla
    ld a, e
    daa
    ld a, e
    inc sp
    ld a, e
    dec [hl]
    ld a, e
    ld b, c
    ld a, e
    ld c, a
    ld a, e
    ld e, e
    ld a, e
    ld h, a
    ld a, e
    ld [hl], c
    ld a, e
    ld a, b
    ld a, e
    ld a, d
    ld a, e
    ld a, h
    ld a, e
    adc d
    ld a, e
    adc h
    ld a, e
    sbc b
    ld a, e
    sbc h
    ld a, e
    sbc [hl]
    ld a, e
    xor d
    ld a, e
    xor h
    ld a, e
    cp b
    ld a, e
    call nz, $d07b
    ld a, e
    jp nc, $db7b

    ld a, e
    ldh [$7b], a
    xor $7b
    rst $38
    ld a, e
    dec c
    ld a, h
    rrca
    ld a, h
    ld [hl+], a
    ld a, h
    ld [hl-], a
    ld a, h
    ld b, h
    ld a, h
    ld b, [hl]
    ld a, h
    ld d, a
    ld a, h
    ld h, l
    ld a, h
    ld h, a
    ld a, h
    ld l, c
    ld a, h
    ld l, e
    ld a, h
    ld l, l
    ld a, h
    ld a, [hl]
    ld a, h
    adc h
    ld a, h
    sbc c
    ld a, h
    and e
    ld a, h
    or l
    ld a, h
    rst $00
    ld a, h
    ret c

    ld a, h
    ld [c], a
    ld a, h
    db $ec
    ld a, h
    xor $7c
    rst $38
    ld a, h
    ld bc, $037d
    ld a, l
    inc d
    ld a, l
    dec h
    ld a, l
    ld [hl], $7d
    ld b, a
    ld a, l
    ld d, l
    ld a, l
    ld d, a
    ld a, l
    ld e, c
    ld a, l
    ld e, e
    ld a, l
    ld e, l
    ld a, l
    ld l, [hl]
    ld a, l
    add b
    ld a, l
    adc b
    ld a, l
    sbc e
    ld a, l
    xor a
    ld a, l
    nop
    ld e, $17
    inc hl
    daa
    jr z, jr_00e_75c9

    jr nc, jr_00e_75cc

    scf
    dec hl
    ld b, b
    inc h
    nop
    nop
    ld a, [de]
    inc l
    rra
    daa
    inc h
    dec b
    add hl, hl
    dec hl
    ld l, $92
    nop
    ld bc, $a710
    nop
    ld [$0e1e], sp
    jr z, jr_00e_75db

    ld [hl], h
    dec e
    rra

jr_00e_75c9:
    inc h
    jr nz, jr_00e_75f7

jr_00e_75cc:
    jr jr_00e_75ce

jr_00e_75ce:
    ld [bc], a
    ld a, [bc]
    ld bc, $008e
    dec c
    cpl
    ld [de], a
    inc bc
    jr jr_00e_7644

    rra
    db $76

jr_00e_75db:
    daa
    ld l, a
    jr nc, @+$73

    nop
    ld bc, $2314
    nop
    add hl, bc
    dec hl
    rrca
    rra
    ld d, $77
    dec e
    ld b, c
    inc h
    ld h, c
    nop
    ld bc, $8d1e
    nop
    ld de, $1631
    ld a, b

jr_00e_75f7:
    dec e
    ld [hl], c
    inc h
    add c
    dec hl
    sbc c
    nop
    nop
    ld [$0e1e], sp
    jr z, jr_00e_761b

    dec h
    nop
    nop
    ld [de], a
    ld [hl-], a
    ld d, $1d
    dec de
    dec l
    ld hl, $2537
    ld l, [hl]
    inc l
    add l
    scf
    ld e, [hl]
    nop
    ld bc, $9a20
    nop
    rlca

jr_00e_761b:
    ld c, c
    dec c
    ld d, $16
    ld c, l
    ld e, $4b
    ld h, $4a
    ld l, $4f
    ld [hl], $4c
    nop
    nop
    inc e
    rla
    nop
    nop
    rlca
    rla
    rrca
    ld [hl-], a
    rla
    ld l, a
    rra
    dec d
    daa
    ld h, a
    nop
    ld [bc], a
    cpl
    ld bc, $000a
    add hl, de
    ld [hl], e
    inc e
    ld c, c
    jr nz, jr_00e_7692

jr_00e_7644:
    dec h
    ld c, l
    ld a, [hl+]
    ld c, h
    jr nc, jr_00e_7699

    nop
    ld bc, $8826
    nop
    ld e, $8b
    ld hl, $256b
    ld a, h
    ld a, [hl+]
    ld l, d
    jr nc, jr_00e_76c0

    scf
    sub a
    nop
    nop
    dec e
    ld e, a
    ld h, $8a
    nop
    ld bc, $a810
    nop
    ld [$0e0a], sp
    jr z, jr_00e_7680

    daa
    dec e
    inc l
    inc h
    sbc d
    dec hl
    jr jr_00e_7673

jr_00e_7673:
    nop
    ld [$0e0a], sp
    jr z, jr_00e_7690

    ld [hl+], a
    nop
    ld bc, $911c
    nop
    add hl, de

jr_00e_7680:
    dec hl
    rra
    ld [hl], h
    ld h, $25
    dec hl
    sbc e
    ld l, $63
    nop
    ld bc, $012a
    nop
    ld e, $17

jr_00e_7690:
    inc hl
    daa

jr_00e_7692:
    jr z, @+$21

    dec l
    jr nz, jr_00e_76c9

    dec hl
    scf

jr_00e_7699:
    inc h
    nop
    nop
    db $10
    cpl
    inc d
    ld [hl], $19
    ld [hl+], a
    rra
    ld l, l
    ld h, $3a
    ld l, $38
    nop
    nop
    nop
    nop
    ld a, [bc]
    sub b
    inc d
    dec b
    ld e, $76
    jr z, jr_00e_7712

    nop
    nop
    inc d
    inc l
    add hl, de
    ld d, d
    jr nz, @+$2d

    add hl, hl
    jr c, jr_00e_76f3

    ccf

jr_00e_76c0:
    nop
    ld [bc], a
    ld [hl+], a
    ld bc, $008b
    ld [de], a
    jr nc, @+$19

jr_00e_76c9:
    add b
    ld e, $3e
    daa
    dec hl
    ld [hl-], a
    ld a, [hl-]
    nop
    ld bc, $9b1e
    nop
    rlca
    jr nc, jr_00e_76e5

    inc hl
    ld [de], a
    jr z, @+$18

    scf
    dec de
    add h
    ld hl, $2870
    ld h, a
    jr nc, jr_00e_771d

jr_00e_76e5:
    nop
    ld bc, $9319
    nop
    dec de
    ld e, a
    inc hl
    adc d
    nop
    nop
    ld de, $142b

jr_00e_76f3:
    ld [hl], h
    jr jr_00e_775e

    dec e
    and e
    inc hl
    ld c, $2a
    ld h, c
    nop
    ld [bc], a
    ld [hl+], a
    ld bc, $0098
    ld de, $1637
    ld l, d
    dec de
    ld l, c
    jr nz, @-$7d

    dec h
    ld l, e
    ld a, [hl+]
    ld [hl], c
    cpl
    jr c, jr_00e_7711

jr_00e_7711:
    nop

jr_00e_7712:
    ld [$0f91], sp
    scf
    jr jr_00e_7744

    rra
    ld l, [hl]
    ld a, [hl+]
    add d
    inc [hl]

jr_00e_771d:
    jr c, jr_00e_771f

jr_00e_771f:
    nop
    add hl, de
    ld b, l
    ld e, $0c
    inc h
    ld [hl], h
    dec hl
    ld l, d
    ld sp, $36a3
    ld c, $00
    nop
    dec e
    ld b, a
    jr nz, @+$4f

    inc h
    ld c, [hl]
    daa
    ld c, a
    dec l
    dec d
    ld sp, $004a
    nop
    nop
    nop
    nop
    ld [bc], a
    jr nz, jr_00e_7743

    inc d

jr_00e_7743:
    nop

jr_00e_7744:
    ld [de], a
    inc [hl]
    rla
    dec hl
    ld e, $24
    daa
    ld h, c
    ld [hl-], a
    dec [hl]
    nop
    nop
    rrca
    inc d
    inc de
    ld e, b
    add hl, de
    ld h, e
    ld hl, $2b15
    ld l, d
    nop
    nop
    add hl, bc
    dec hl

jr_00e_775e:
    rrca
    rra
    add hl, de
    ld [hl], a
    ld [hl+], a
    ld b, c
    dec hl

jr_00e_7765:
    ld h, c
    nop
    ld bc, $9612
    nop
    dec b
    inc e
    inc c
    ld h, d
    inc de
    ld [de], a
    inc e
    ld de, $6124
    inc l
    ld [hl], a
    nop
    ld bc, $0825
    nop
    ld [de], a
    ld [hl-], a
    ld d, $1d
    dec de
    dec l
    ld hl, $2837
    add l
    jr nc, @+$60

    nop
    inc bc
    ld bc, $0095
    db $10
    ld e, l
    inc d
    ld [hl-], a
    dec de
    inc a
    rra
    ld l, c
    ld h, $5e
    ld a, [hl+]
    ld [hl], e
    nop
    inc bc
    ld bc, $0031
    dec bc
    ld l, a
    db $10
    ld e, b
    dec d
    ld a, b
    dec e
    ld l, d
    inc h
    ld e, c
    dec hl
    sbc c
    nop
    nop
    jr jr_00e_77dd

    ld e, $2d
    ld h, $6b
    inc l
    ld l, a
    jr nc, jr_00e_7827

    ld [hl], $26
    nop
    inc bc
    ld bc, $007e
    inc d
    ld b, e
    add hl, de
    dec hl
    inc h
    ld [hl], h
    inc l
    ld b, l
    inc [hl]
    ld b, d
    nop
    nop
    rrca
    ld e, l
    rla
    ld [hl], c
    rra
    inc bc
    daa
    ld h, b
    cpl
    and h
    nop
    nop
    ld hl, $261b
    ld a, [de]
    dec hl
    ld [hl], h
    jr nc, jr_00e_7765

jr_00e_77dd:
    dec [hl]
    add hl, de
    nop
    nop
    ld hl, $2607
    ld [$092b], sp
    jr nc, jr_00e_77ee

    dec [hl]
    ld b, h
    nop
    nop
    ld a, [bc]

jr_00e_77ee:
    jr z, jr_00e_7801

    inc l
    dec de
    adc c
    inc h
    ld h, a
    cpl
    inc sp
    nop
    nop
    dec c
    ld c, [hl]
    inc d
    adc l
    ld e, $93
    daa
    and e

jr_00e_7801:
    jr nc, @+$4c

    nop
    ld bc, $8021
    nop
    inc e
    daa
    rra
    ld [hl-], a
    inc h
    ld e, l
    dec hl
    sbc d
    inc [hl]
    jr c, jr_00e_7813

jr_00e_7813:
    ld bc, $811a
    nop
    inc c
    ld [hl-], a
    ld de, $185d
    dec e
    dec e
    adc e
    jr nz, @+$60

    dec h
    ld h, b
    nop
    nop
    dec bc
    ld l, a

jr_00e_7827:
    db $10
    ld e, b
    dec d
    ld a, b
    dec e
    ld l, d
    inc h
    ld e, c
    dec hl
    sbc c
    nop
    nop
    nop
    nop
    inc h
    dec hl
    daa
    ld l, l
    dec hl
    rlca
    jr nc, jr_00e_78a9

    inc [hl]
    ld a, e
    scf
    dec [hl]
    nop
    nop
    nop
    nop
    ld [hl+], a
    ld d, h
    dec h
    ld h, a
    ld a, [hl+]
    add hl, bc
    ld sp, $3671
    ld d, a
    nop
    nop
    dec d
    ld sp, $5419
    dec e
    jr nc, jr_00e_787e

    ld d, [hl]
    ld l, $81
    ld [hl], $67
    nop
    ld bc, $8f23
    nop
    jr nz, jr_00e_78e0

    dec h
    ld l, h
    jr z, jr_00e_78e0

    dec l
    ld [hl], d
    jr nc, @-$65

    nop
    nop
    nop
    ld bc, $751c
    nop
    rrca
    ld [bc], a
    dec d
    sbc d
    dec de
    ld [hl], h
    ld hl, $2745
    dec h
    nop

jr_00e_787e:
    ld bc, $7822
    nop
    ld e, $2d
    inc hl
    ld a, $28
    sbc h
    dec l
    inc h
    ld [hl-], a
    ld a, [hl-]

jr_00e_788c:
    nop
    ld bc, $761a
    nop
    rrca
    dec l
    inc de
    ld e, e
    jr jr_00e_78b3

    rra
    and e
    jr z, jr_00e_78f4

    nop
    nop
    dec d
    rla
    inc e
    daa
    inc hl
    dec hl
    inc l
    ld h, e
    inc sp
    inc h
    nop
    nop

jr_00e_78a9:
    nop
    nop
    nop
    nop
    nop
    nop
    rlca
    dec hl
    rrca
    rra

jr_00e_78b3:
    rla
    ld c, $1f
    ld h, c
    daa
    and e
    nop
    ld bc, $771f
    nop
    jr jr_00e_790d

    dec de
    adc l
    ld e, $4e
    inc hl
    inc a
    ld h, $4f
    dec hl
    ld e, [hl]
    nop
    nop
    ld a, [bc]
    ld d, [hl]
    inc d
    ld h, c
    inc hl
    dec d
    dec l
    ld d, d
    inc a
    ccf
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $741f

jr_00e_78e0:
    nop
    inc d
    dec l
    jr jr_00e_7904

    ld e, $41
    inc h
    ld h, e
    jr z, jr_00e_788c

    inc l
    ld h, c
    nop
    ld bc, $6e19
    nop
    db $10
    ld e, a

jr_00e_78f4:
    inc de
    scf
    add hl, de
    inc bc
    rra
    ld [hl+], a
    ld h, $85
    dec l
    jr c, jr_00e_78ff

jr_00e_78ff:
    nop
    ld [de], a
    ld a, d
    rla
    inc bc

jr_00e_7904:
    rra
    ld [$2227], sp
    cpl
    dec h
    ld a, [hl-]
    dec sp
    nop

jr_00e_790d:
    nop
    inc sp
    dec hl
    scf
    ld h, c
    inc a
    adc a
    nop
    nop
    inc sp
    dec sp
    scf
    ld h, c
    inc a
    ld [hl], $00
    nop
    inc sp
    ld d, a
    scf
    ld h, c
    inc a
    ld [hl], c
    nop
    nop
    nop
    ld bc, $901c
    nop
    inc c
    inc l
    ld de, $1806
    ld h, a
    ld hl, $2c9a
    and e
    nop
    ld bc, $8a1c
    nop
    inc d
    dec bc
    add hl, de
    inc c
    ld e, $17
    inc hl
    sbc b
    jr z, jr_00e_79ae

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld [bc], a
    jr nz, jr_00e_794f

    ld d, e

jr_00e_794f:
    nop
    db $10
    ld h, d
    dec d
    ld l, $1c
    ld l, l
    inc hl
    dec [hl]
    ld a, [hl+]
    ld d, e
    nop
    nop
    nop
    ld [bc], a
    ld hl, $5501
    nop
    add hl, bc
    ld d, [hl]
    db $10
    ld h, d
    ld a, [de]
    add c
    ld hl, $2b61
    ld d, a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $591e
    nop
    ld a, [bc]
    ld d, [hl]
    inc d
    ld h, c
    ld e, $15
    jr z, @+$54

    ld [hl-], a
    ccf
    nop
    ld bc, $4237
    nop
    ld a, [bc]
    ld d, [hl]
    inc d
    ld h, c
    inc hl
    dec d
    dec l
    ld d, d
    scf
    ccf
    nop
    ld bc, $5b28
    nop
    ld [hl+], a
    ld b, a
    daa
    and e
    inc l
    dec hl
    ld sp, $0038
    nop
    ld [hl+], a
    ld b, a
    daa
    and e
    ld l, $2b
    dec [hl]
    jr c, jr_00e_79a8

jr_00e_79a8:
    ld bc, $5d20
    nop
    inc de
    ld l, h

jr_00e_79ae:
    jr @+$2d

    ld e, $37
    dec h
    ld h, c
    dec l
    jr c, jr_00e_79b7

jr_00e_79b7:
    nop
    inc de
    ld l, h
    jr jr_00e_79e7

    ld e, $37
    add hl, hl
    ld h, c
    inc [hl]
    jr c, jr_00e_79c3

jr_00e_79c3:
    nop
    nop
    nop
    nop
    ld bc, $6116
    nop
    ld a, [bc]
    inc e
    ld de, $18a3
    jr z, jr_00e_79f1

    add c
    ld h, $9a
    nop
    nop
    ld a, [bc]
    inc e
    ld de, $1ba3
    jr z, jr_00e_7a02

    add c
    cpl
    sbc d
    nop
    ld bc, $6328
    nop
    ld [hl+], a

jr_00e_79e7:
    ld e, $27
    dec hl
    ld l, $83
    dec [hl]
    jr c, jr_00e_79ef

jr_00e_79ef:
    nop
    ld [hl+], a

jr_00e_79f1:
    ld e, $27
    dec hl
    inc l
    add e
    ld sp, $0038
    ld [bc], a
    ld a, [bc]
    ld bc, $0065
    add hl, bc
    ld bc, $320e

jr_00e_7a02:
    inc de
    ld l, a
    jr jr_00e_7a09

    dec e
    sbc h
    ld [hl+], a

jr_00e_7a09:
    ld [hl+], a
    daa
    ld h, $00
    nop
    nop
    ld [bc], a
    jr nz, jr_00e_7a13

    ld h, a

jr_00e_7a13:
    ld [bc], a
    ld hl, $6801
    ld [bc], a
    ld [hl+], a
    ld bc, $0069
    dec de
    ld h, d
    rra
    daa
    dec h
    inc l
    dec l
    inc h
    nop
    nop
    dec de
    ld h, d
    rra
    inc [hl]
    dec h
    daa
    jr z, jr_00e_7a5a

    ld a, [hl+]
    dec hl
    inc l
    ld d, e
    jr nc, jr_00e_7a97

    ld [hl], $35
    nop
    nop
    dec de
    ld h, d
    rra
    ld d, h
    dec h
    daa
    jr z, jr_00e_7a96

    ld a, [hl+]
    jr jr_00e_7a6f

    ld h, c
    jr nc, @+$2c

    ld [hl], $57
    nop
    nop
    dec de
    ld h, d
    rra
    scf
    dec h
    daa
    jr z, jr_00e_7a7e

    ld a, [hl+]
    sub a
    inc l
    ld [hl], d
    jr nc, jr_00e_7a8e

    ld [hl], $38

jr_00e_7a5a:
    nop
    ld bc, $291c
    nop
    inc d
    ld b, e
    add hl, de
    dec hl
    jr nz, jr_00e_7ad9

    daa
    ld b, l
    ld l, $42
    nop
    ld bc, $8216
    nop
    ld a, [bc]

jr_00e_7a6f:
    jr nc, jr_00e_7a80

    inc l
    dec d
    ld l, l
    inc e
    ld de, $7224
    nop
    ld bc, $2d16
    nop
    ld a, [bc]

jr_00e_7a7e:
    jr z, jr_00e_7a91

jr_00e_7a80:
    inc l
    jr @-$75

    rra
    ld h, a
    ld h, $33
    nop
    ld bc, $2e18
    nop
    dec c
    ld c, [hl]

jr_00e_7a8e:
    inc d
    adc l
    dec de

jr_00e_7a91:
    sub e
    ld [hl+], a
    and e
    add hl, hl
    ld c, d

jr_00e_7a96:
    nop

jr_00e_7a97:
    ld [bc], a
    ld [hl+], a
    ld bc, $006f
    db $10
    ld e, a
    inc de
    scf
    ld a, [de]
    inc bc
    ld hl, $2922
    add l
    ld sp, $0038
    nop
    db $10
    ld e, a
    inc de
    scf
    nop
    ld bc, $7107
    nop
    nop
    ld bc, $720a
    nop
    nop
    nop
    inc c
    rra
    db $10
    ld [hl], h
    inc d
    add hl, hl
    add hl, de
    ld h, e
    ld e, $2a
    inc hl
    ld h, c
    nop
    nop
    nop
    nop
    inc d
    dec l
    jr jr_00e_7aed

    ld e, $41
    daa
    ld h, e
    dec l
    and c
    inc sp
    ld h, c
    nop
    nop

jr_00e_7ad8:
    rrca

jr_00e_7ad9:
    ld [bc], a
    dec d
    sbc d
    dec de
    ld [hl], h
    dec h
    ld b, l
    ld l, $25
    nop
    nop
    rrca
    dec l
    inc de
    ld e, e
    jr jr_00e_7b06

    inc hl
    and e
    cpl

jr_00e_7aed:
    ld e, c
    nop
    nop
    jr jr_00e_7b3f

    dec de
    adc l
    ld e, $4e
    ld h, $3c
    dec hl
    ld c, a
    ld [hl-], a
    ld e, [hl]
    nop
    nop
    ld e, $2d
    inc hl
    ld a, $2c
    sbc h
    ld [hl-], a
    inc h

jr_00e_7b06:
    jr c, jr_00e_7b42

    nop
    nop
    nop
    nop
    nop
    ld bc, $7c07
    nop
    nop
    ld bc, $7d0a
    nop
    nop
    nop
    inc c
    ld e, l
    rrca
    ld c, l
    db $10
    ld c, [hl]
    ld de, $154f
    jr nc, @+$1c

    ld [de], a
    jr nz, jr_00e_7b62

    nop
    nop

jr_00e_7b28:
    inc d
    ld b, e
    add hl, de
    dec hl
    inc h
    ld [hl], h
    inc l
    ld b, l
    inc [hl]
    ld b, d
    nop
    nop
    nop
    nop
    inc e
    daa
    rra
    ld [hl-], a
    daa
    ld e, l
    jr nc, jr_00e_7ad8

    dec sp

jr_00e_7b3f:
    jr c, jr_00e_7b41

jr_00e_7b41:
    nop

jr_00e_7b42:
    inc c
    ld [hl-], a
    ld de, $185d
    dec e
    ld hl, $258b
    ld e, [hl]
    dec hl
    ld h, b
    nop
    nop
    ld a, [bc]
    jr nc, jr_00e_7b62

    inc l
    dec d
    ld l, l
    jr nz, jr_00e_7b69

    dec hl
    ld [hl], d
    nop
    nop
    ccf
    ld [hl], b
    ld b, d
    ld e, [hl]
    ld b, [hl]
    ld l, c

jr_00e_7b62:
    ld c, e
    ld [hl], $51
    add l
    nop
    nop

jr_00e_7b68:
    inc hl

jr_00e_7b69:
    ld [hl+], a
    add hl, hl
    ld l, d
    jr nc, jr_00e_7b94

    jr c, jr_00e_7baf

    nop
    ld bc, $1614
    nop
    rrca
    ld hl, $0000
    nop
    nop
    nop
    nop
    ld e, $8b
    ld hl, $256b
    ld a, h
    dec l
    ld l, d
    dec [hl]
    ld h, a
    inc a
    sub a
    nop
    nop
    nop
    nop
    inc d
    dec bc
    add hl, de
    inc c
    ld [hl+], a
    rla
    ld a, [hl+]

jr_00e_7b94:
    sbc b
    ld sp, $006a
    nop
    ld [hl-], a
    add e
    nop
    nop
    nop
    nop
    ld de, $1631
    ld a, b
    dec e
    ld [hl], c
    jr z, jr_00e_7b28

    ld [hl-], a
    sbc c
    nop
    nop
    nop
    nop
    jr nz, jr_00e_7c2b

jr_00e_7baf:
    daa
    ld l, h
    dec hl
    ld a, b
    ld sp, $3572
    sbc c
    nop
    nop
    inc c
    inc l
    ld de, $1806
    ld h, a
    dec h
    sbc d
    inc sp
    and e
    nop
    nop
    add hl, de
    dec hl
    ld hl, $2974
    dec h
    jr nc, jr_00e_7b68

    scf
    ld h, e
    nop
    nop
    nop
    inc bc
    ld bc, $000e
    dec e
    ld e, a
    ld h, $8a
    nop
    ld bc, $2610
    nop
    nop
    nop
    db $10
    ld e, l
    inc d
    ld [hl-], a
    dec de
    inc a
    rra
    ld l, c
    ld h, $5e
    ld a, [hl+]
    ld [hl], e
    nop
    ld bc, $9724
    nop
    dec b
    inc e
    inc c
    ld h, d
    dec d
    ld [de], a
    rra
    ld de, $6128
    ld sp, $0077
    nop
    dec b
    inc e
    inc c
    ld h, d
    dec d
    ld [de], a
    rra
    ld de, $612c
    ld [hl], $77
    nop
    nop
    nop
    ld bc, $0910
    nop
    rlca
    ld c, c
    dec c
    ld d, $14
    ld c, l
    dec de
    ld c, e
    ld [hl+], a
    ld c, d
    add hl, hl
    ld c, a
    jr nc, jr_00e_7c6d

    nop
    nop
    rlca
    ld c, c
    dec c
    ld d, $16
    ld c, l
    ld e, $4b

jr_00e_7c2b:
    dec hl
    ld c, d
    scf
    ld c, a
    ld b, c
    ld c, h
    nop
    nop
    rlca
    jr nc, @+$0f

    inc hl
    ld [de], a
    jr z, jr_00e_7c50

    scf
    dec de
    add h
    inc hl
    ld [hl], b
    dec hl
    ld h, a
    ld [hl-], a
    jr c, jr_00e_7c44

jr_00e_7c44:
    nop
    nop
    ld bc, $9e21
    nop
    inc de
    jr nc, jr_00e_7c65

    ld e, $1e
    rra

jr_00e_7c50:
    dec h
    ld a, a
    dec l
    jr nz, jr_00e_7c8b

    ld h, c
    nop
    nop
    inc de
    jr nc, jr_00e_7c73

    ld e, $1e
    rra
    daa
    ld a, a
    jr nc, @+$22

    ld [hl], $61
    nop

jr_00e_7c65:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_00e_7c6d:
    ld bc, $a428
    nop
    ld e, $27

jr_00e_7c73:
    jr nz, jr_00e_7c8c

    inc hl
    dec l
    daa
    ld d, e
    dec hl
    inc h
    jr nc, jr_00e_7cde

    nop
    nop
    ld e, $27
    jr nz, jr_00e_7c9a

    inc hl
    dec l
    daa
    ld d, e
    cpl
    inc h
    scf
    ld h, c

jr_00e_7c8b:
    nop

jr_00e_7c8c:
    ld bc, $a614
    nop
    rlca
    ld h, d
    ld c, $9e
    rla
    ld [hl], h
    ld [hl+], a
    and d
    nop
    nop

jr_00e_7c9a:
    rlca
    ld h, d
    ld c, $9e
    dec de
    ld [hl], h
    add hl, hl
    and d
    nop
    ld [bc], a
    ld a, [bc]
    ld bc, $0007
    ld [$0e1e], sp
    jr z, jr_00e_7cc4

    ld [hl], h
    jr nz, jr_00e_7ccf

    add hl, hl
    jr nz, @+$34

    jr jr_00e_7cb5

jr_00e_7cb5:
    ld [bc], a
    ld a, [bc]
    ld bc, $0010
    ld [$0e0a], sp
    jr z, jr_00e_7cd6

    daa
    jr nz, jr_00e_7cee

    add hl, hl
    sbc d

jr_00e_7cc4:
    ld [hl-], a
    jr jr_00e_7cc7

jr_00e_7cc7:
    ld bc, $2719
    nop
    dec bc
    ld l, a
    db $10
    ld e, b

jr_00e_7ccf:
    dec d
    ld a, b
    ld a, [de]
    ld l, d
    rra
    ld e, c
    inc h

jr_00e_7cd6:
    sbc c
    nop
    nop
    rla
    inc a
    inc e
    ld l, c
    inc hl

jr_00e_7cde:
    ld h, c
    ld a, [hl+]
    and c
    nop
    nop
    ld hl, $2630
    inc l
    dec l
    inc h
    ld [hl], $3f
    nop
    nop
    nop

jr_00e_7cee:
    ld bc, $361e
    nop
    dec d
    ld sp, $5419
    dec e
    jr nc, jr_00e_7d1c

    ld d, [hl]
    add hl, hl
    add c
    cpl
    ld h, a
    nop
    nop
    nop
    nop
    nop
    ld bc, $b210
    nop
    add hl, bc
    inc [hl]
    rrca
    dec hl
    ld d, $63
    ld e, $a3
    ld h, $35
    ld l, $53
    nop
    ld bc, $b310
    nop
    ld [$0f91], sp
    scf

jr_00e_7d1c:
    ld d, $2c
    inc e
    ld l, [hl]
    inc hl
    add d
    ld a, [hl+]
    jr c, jr_00e_7d25

jr_00e_7d25:
    ld bc, $b424
    nop
    add hl, bc
    inc [hl]
    rrca
    dec hl
    jr jr_00e_7d92

    ld hl, $2aa3
    dec [hl]
    jr c, jr_00e_7d88

    nop
    ld bc, $1c24
    nop
    ld [$0f91], sp
    scf
    jr jr_00e_7d6c

    rra
    ld l, [hl]
    daa
    add d
    cpl
    jr c, jr_00e_7d47

jr_00e_7d47:
    nop
    add hl, bc
    inc [hl]
    rrca
    dec hl
    jr jr_00e_7db1

    inc h
    and e
    ld l, $35
    scf
    ld d, e
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $ba15
    nop
    rrca
    ld c, l
    ld de, $134e
    ld c, a
    jr jr_00e_7d9c

    ld hl, $2e50

jr_00e_7d6c:
    ld c, h
    nop
    ld [bc], a
    cpl
    ld bc, $00bb
    rrca
    ld c, l
    ld de, $134e
    ld c, a
    inc e
    inc sp
    ld h, $50
    inc [hl]
    ld c, h
    nop
    nop
    rrca
    ld c, l
    ld de, $134e
    ld c, a
    nop

jr_00e_7d88:
    ld bc, $bd15
    nop
    dec c
    inc hl
    rrca
    ld c, l
    ld [de], a
    ld c, a

jr_00e_7d92:
    dec d
    ld c, [hl]
    ld a, [de]
    inc sp
    ld hl, $2a4b
    dec d
    nop
    ld [bc], a

jr_00e_7d9c:
    cpl
    ld bc, $00be
    dec c
    inc hl
    rrca
    ld c, l
    ld [de], a
    ld c, a
    rla
    ld c, [hl]
    dec e
    inc sp
    ld h, $4b
    ld sp, $0015
    nop
    dec c

jr_00e_7db1:
    inc hl
    rrca
    ld c, l
    ld [de], a
    ld c, a
    nop
    ldh a, [$f3]
    and a
    ld de, $cffc
    ld hl, $d00a
    ld a, [$cfb9]
    jr z, jr_00e_7dce

    ld de, $cfcd
    ld hl, $cfdb
    ld a, [$cfb3]

jr_00e_7dce:
    ld b, a
    ld a, [de]
    cp [hl]
    inc de
    inc hl
    ld a, [de]
    sbc [hl]
    jp z, Jump_00e_7e62

    ld a, b
    cp $9c
    jr nz, jr_00e_7e02

    push hl
    push de
    push af
    ld c, $32
    call Call_000_3781
    ld hl, $cfff
    ldh a, [$f3]
    and a
    jr z, jr_00e_7df0

    ld hl, $cfd0

jr_00e_7df0:
    ld a, [hl]
    and a
    ld [hl], $02
    ld hl, $7e6d
    jr z, jr_00e_7dfc

    ld hl, $7e7a

jr_00e_7dfc:
    call Call_000_3c79
    pop af
    pop de
    pop hl

jr_00e_7e02:
    ld a, [hl-]
    ld [$cee4], a
    ld c, a
    ld a, [hl]
    ld [$cee5], a
    ld b, a
    jr z, jr_00e_7e12

    srl b
    rr c

jr_00e_7e12:
    ld a, [de]
    ld [$cee6], a
    add c
    ld [de], a
    ld [$cee8], a
    dec de
    ld a, [de]
    ld [$cee7], a
    adc b
    ld [de], a
    ld [$cee9], a
    inc hl
    inc de
    ld a, [de]
    dec de
    sub [hl]
    dec hl
    ld a, [de]
    sbc [hl]
    jr c, jr_00e_7e3a

    ld a, [hl+]
    ld [de], a
    ld [$cee9], a
    inc de
    ld a, [hl]
    ld [de], a
    ld [$cee8], a

jr_00e_7e3a:
    ld hl, $7fdb
    call Call_00e_7ffa
    ldh a, [$f3]
    and a
    ld hl, $c45e
    ld a, $01
    jr z, jr_00e_7e4e

    ld hl, $c3ca
    xor a

jr_00e_7e4e:
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d
    ld hl, $4eb8
    call Call_00e_7ffa
    ld hl, $7e90
    jp Jump_000_3c79


Jump_00e_7e62:
    ld c, $32
    call Call_000_3781
    ld hl, $7f4e
    jp Jump_00e_7ffa


    db $ed
    dec l
    ld a, [de]
    ld l, c
    ret z

    pop de
    ret c

    jp z, $d22c

    ret nz

    rst $20
    ld d, a
    db $ed
    add hl, hl
    inc c
    ld l, d
    cp c
    sbc $ba
    or e
    add $c5
    rst $18
    jp $c84f


    pop de
    ret c

    jp z, $d22c

    ret nz

    rst $20
    ld d, a
    db $ed
    add hl, hl
    scf
    ld l, d
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    db $dd
    ld c, a
    or [hl]
    or d
    call z, $bcb8
    ret nz

    rst $20
    ld e, b
    ld hl, $cffb
    ld de, $cfcc
    ld bc, $d046
    ld a, [$d044]
    ldh a, [$f3]
    and a
    jr nz, jr_00e_7ec3

    ld hl, $cfcc
    ld de, $cffb
    ld bc, $d041
    ld [$cc2e], a
    ld a, [$d03f]

jr_00e_7ec3:
    bit 6, a
    jp nz, Jump_00e_7f76

    push hl
    push de
    push bc
    ld hl, $d040
    ldh a, [$f3]
    and a
    jr z, jr_00e_7ed6

    ld hl, $d045

jr_00e_7ed6:
    bit 4, [hl]
    push af
    ld hl, $577e
    ld b, $1e
    call nz, Call_000_3620
    ld a, [$d2d4]
    add a
    ld hl, $7fdb
    ld b, $0f
    jr nc, jr_00e_7ef1

    ld hl, $57be
    ld b, $1e

jr_00e_7ef1:
    call Call_000_3620
    ld hl, $57a8
    ld b, $1e
    pop af
    call nz, Call_000_3620
    pop bc
    ld a, [bc]
    set 3, a
    ld [bc], a
    pop de
    pop hl
    push hl
    ld a, [hl]
    ld [de], a
    ld bc, $0005
    add hl, bc
    inc de
    inc de
    inc de
    inc de
    inc de
    inc bc
    inc bc
    call Call_000_01bb
    ldh a, [$f3]
    and a
    jr z, jr_00e_7f24

    ld a, [de]
    ld [$cceb], a
    inc de
    ld a, [de]
    ld [$ccec], a
    dec de

jr_00e_7f24:
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    inc hl
    inc hl
    inc hl
    inc de
    inc de
    inc de
    ld bc, $0008
    call Call_000_01bb
    ld bc, $ffef
    add hl, bc
    ld b, $04

jr_00e_7f3c:
    ld a, [hl+]
    and a
    jr z, jr_00e_7f47

    ld a, $05
    ld [de], a
    inc de
    dec b
    jr nz, jr_00e_7f3c

jr_00e_7f47:
    pop hl
    ld a, [hl]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $cd26
    ld de, $cd12
    call Call_00e_7f67
    ld hl, $cd2e
    ld de, $cd1a
    call Call_00e_7f67
    ld hl, $7f7c
    jp Jump_000_3c79


Call_00e_7f67:
    ldh a, [$f3]
    and a
    jr z, jr_00e_7f70

    push hl
    ld h, d
    ld l, e
    pop de

jr_00e_7f70:
    ld bc, $0008
    jp Jump_000_01bb


Jump_00e_7f76:
    ld hl, $7f4e
    jp Jump_00e_7ffa


    db $ed
    add hl, hl
    ld e, e
    ld l, d
    ld d, b
    ld bc, $cd68
    nop
    add $7f
    call $bcde
    sbc $bc
    ret nz

    rst $20
    ld e, b
    ld hl, $d041
    ld de, $cfba
    ldh a, [$f3]
    and a
    jr z, jr_00e_7fa0

    ld hl, $d046
    ld de, $cfb4

jr_00e_7fa0:
    ld a, [de]
    cp $40
    jr nz, jr_00e_7fb0

    bit 1, [hl]
    jr nz, jr_00e_7fc4

    set 1, [hl]
    ld hl, $7fcf
    jr jr_00e_7fb9

jr_00e_7fb0:
    bit 2, [hl]
    jr nz, jr_00e_7fc4

    set 2, [hl]
    ld hl, $7fe5

jr_00e_7fb9:
    push hl
    ld hl, $7fdb
    call Call_00e_7ffa
    pop hl
    jp Jump_000_3c79


jr_00e_7fc4:
    ld c, $32
    call Call_000_3781
    ld hl, $7f4e
    jp Jump_00e_7ffa


    nop
    ld e, d
    jp z, $c44f

    cp b
    cp h
    pop hl
    cp d
    or e
    add hl, hl
    or a
    add $7f
    jp nz, $b8d6

    push bc
    rst $18
    ret nz

    rst $20
    ld e, b
    nop
    ld e, d
    jp z, Jump_000_304f

    add hl, hl
    or a
    cp d
    or e
    add hl, hl
    or a
    add $7f
    jp nz, $b8d6

    push bc
    rst $18
    ret nz

    rst $20
    ld e, b

Call_00e_7ffa:
Jump_00e_7ffa:
    ld b, $0f
    jp Jump_000_3620


    db $fd
