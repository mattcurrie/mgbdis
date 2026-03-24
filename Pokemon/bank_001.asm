; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $001", ROMX[$4000], BANK[$1]

    add b
    ld b, b
    sbc b
    ld b, b
    add h
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add h
    ld b, b
    and h
    ld b, b
    adc b
    ld b, b
    sbc b
    ld b, b
    adc h
    ld b, b
    sbc b
    ld b, b
    adc b
    ld b, b
    sbc b
    ld b, b
    adc h
    ld b, b
    and h
    ld b, b
    sub b
    ld b, b
    sbc b
    ld b, b
    sub h
    ld b, b
    sbc b
    ld b, b
    sub b
    ld b, b
    sbc b
    ld b, b
    sub h
    ld b, b
    sbc b
    ld b, b
    sub b
    ld b, b
    and h
    ld b, b
    sub h
    ld b, b
    and h
    ld b, b
    sub b
    ld b, b
    and h
    ld b, b
    sub h
    ld b, b
    and h
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    add b
    ld b, b
    sbc b
    ld b, b
    nop
    ld bc, $0302
    add b
    add c
    add d
    add e
    inc b
    dec b
    ld b, $07
    add h
    add l
    add [hl]

jr_001_408f:
    add a
    ld [$0a09], sp
    dec bc
    adc b
    adc c

jr_001_4096:
    adc d
    adc e
    nop
    nop
    nop
    nop
    ld [$0800], sp
    nop
    ld [bc], a
    ld [$0308], sp
    nop
    ld [$0020], sp
    nop
    jr nz, jr_001_40b3

    ld [$0822], sp
    nop
    inc hl
    ld d, l
    cp [hl]
    pop de

jr_001_40b3:
    sub e
    add l
    ld a, a
    call nc, Call_001_63d5
    add c
    add sp, -$66
    push af
    ld c, h
    ld hl, sp-$33
    ld hl, sp-$67
    cp d
    ld a, [bc]
    or h
    jp z, Jump_001_5033

    ld c, c
    sub a
    ld d, e
    ld a, [hl-]
    ld h, h
    or l
    db $fd
    ld a, b
    db $dd
    ld c, b
    and l
    adc e
    xor c
    ld d, h
    ret


    cp d
    dec d
    ret nc

    ld b, c
    ld sp, $a3a7
    add hl, sp
    ld [$2484], sp
    add hl, sp
    jr jr_001_408f

    ld d, e
    ld h, h
    ld a, [hl+]
    add [hl]
    ld b, $22
    ld b, d
    dec l
    ld c, b
    or h
    jp c, $7482

    adc b
    inc de
    dec b
    ld h, $8d
    inc d
    add h
    ld e, d
    adc e
    and c
    and e
    ld l, a
    ld [c], a
    ld d, $58
    ld d, l
    dec h
    ld b, [hl]
    adc b
    cp a
    push af
    ld d, l
    ld l, a
    ld [hl], h

jr_001_410a:
    ld d, d
    jr nz, jr_001_4096

    ld d, l
    ld c, h
    sbc [hl]
    ld a, d
    add l
    ld b, l
    ld l, l
    ld [$6a12], sp
    inc [hl]
    ld d, b
    ld d, d
    inc d
    ld e, $2e
    add hl, sp
    ld d, h
    dec d
    ldh [rHDMA2], a
    sub h
    jr z, jr_001_410a

    ld d, b
    and l
    db $e3
    ld b, $4e
    ld a, e
    ld a, [$8633]
    ld a, l
    and d
    sbc h

jr_001_4131:
    ld c, b
    ld b, e
    add d
    ld l, d
    add [hl]
    sbc h
    xor d
    ld b, h
    add hl, hl
    sbc [hl]
    ld l, e
    rla
    call nz, $4a44
    ld d, d
    add hl, de
    xor l
    and b
    sub e
    ld de, $9813
    ld [hl], h
    ld e, d
    ld de, $1b0d
    inc [hl]
    ld b, h
    add hl, de
    adc h
    ld [$6456], sp
    jp $2807


    and c
    add hl, de
    add $2c
    ld b, a
    and d
    add l
    add [hl]
    rrca
    db $fc
    ld d, h
    inc d
    ld b, d
    ld c, h
    ld c, a
    sub e
    cp [hl]
    rst $38
    rst $38
    ld d, $a5
    xor c
    ld [hl], h
    ld c, $18
    and c
    ld a, a
    pop de
    jr z, jr_001_41be

    ld [hl], h
    ld c, d
    ccf
    call c, Call_000_0d46
    ld b, [hl]
    ld d, a
    ld [de], a
    sub b
    pop af
    inc [hl]
    ld a, [bc]
    ret nc

jr_001_4183:
    ld b, h
    ld h, l
    jp Jump_001_4465


    and c
    ld d, l
    ld h, e
    jr nz, jr_001_4131

    call c, $dc4c
    ld l, c
    add hl, hl
    ld c, b
    inc a
    ld b, d
    ld a, [de]
    sbc h
    ld [hl], b
    ld c, d
    ld d, e
    jr jr_001_4183

    inc l
    ld [de], a
    ld [$54b4], sp
    inc e
    ld [hl], e
    ld b, d
    or [hl]
    ld h, l
    ld b, a
    ld c, h
    ld de, $44c0
    cp [hl]
    dec l
    ld e, a
    rst $38
    rst $10
    call nc, $eadd
    dec b
    ld d, l
    xor a
    rst $38
    jr c, jr_001_4227

    and b
    xor a
    ld e, d
    di
    add d

jr_001_41be:
    adc b
    ld d, d
    ld l, e
    call nc, $f8d6
    ld e, [hl]
    ld [hl-], a
    and e
    db $d3
    or h
    ldh a, [$28]
    ld a, [c]
    ld e, h
    and $bf
    push de
    db $e3
    or d
    and e
    ld [$c527], a
    and e
    ld a, [bc]
    cp b
    ld l, $09
    cp d
    ld b, d
    and h
    or h

jr_001_41df:
    or $a7
    rlca
    ld [de], a
    adc h
    ld [$9a53], sp
    xor a
    dec d
    ld b, h
    ld d, h
    add hl, bc
    pop bc
    db $10
    sbc [hl]
    ld [bc], a
    ld h, b
    and a
    ld d, d
    and c
    ld b, a
    ld e, l
    jr jr_001_41df

    ld [hl-], a
    ld b, d
    ld b, e
    sbc l
    ld [hl], b
    ld e, c
    ld hl, sp+$40
    sub a
    ld h, h
    ld h, h
    ld h, h
    ld h, h
    ld h, h
    jr jr_001_4220

    dec l
    ld b, b
    ld d, l
    or b
    ld b, b
    xor d
    ld b, c
    ld bc, $0000
    nop
    inc bc
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
    nop
    nop

jr_001_4220:
    ld [de], a
    nop
    nop
    ld b, $00
    nop
    ld [bc], a

jr_001_4227:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0000
    ld [bc], a
    ld d, b
    nop
    ld [bc], a
    ld d, b
    nop
    ld [bc], a
    nop
    nop
    ld [bc], a
    nop
    nop
    jr nc, jr_001_424c

jr_001_424c:
    nop
    dec h
    nop
    nop
    dec d
    nop
    nop
    rlca
    nop
    nop
    inc bc
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    dec b
    ld d, b
    nop
    inc bc
    ld d, b
    nop
    nop
    nop
    nop
    ld hl, $0000
    ld hl, $0000
    ld hl, $0000
    sbc b
    nop
    nop
    sbc b
    nop
    nop
    sbc b
    nop
    nop
    sbc b
    nop
    nop
    sbc b
    nop
    nop
    ld c, b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add hl, bc
    ld d, b
    nop
    ld hl, $0000
    nop
    nop
    ld bc, $0000
    nop
    sbc b
    nop
    nop
    stop
    nop
    ld b, $00
    nop
    dec d
    nop
    nop
    ld b, b
    nop
    nop
    rlca
    nop
    nop
    dec b
    nop
    nop
    rlca
    nop
    nop
    ld b, $50
    nop
    nop
    stop
    ld [bc], a
    nop
    nop
    inc bc
    nop
    nop
    inc bc
    ld d, b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    dec b
    nop
    nop
    dec b
    ld d, b
    nop
    inc bc
    ld d, b
    nop
    inc bc
    ld d, b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    db $ed
    inc l
    or c
    ld e, l
    inc e
    db $e3
    and [hl]
    ld d, b
    sbc c
    add c
    ld b, b
    db $e3
    inc e
    db $e3
    and [hl]
    ld d, b
    adc h
    db $e3
    ld b, b
    db $e3
    inc e
    db $e3
    and [hl]
    ld d, b
    and c
    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    ld d, b
    adc a
    add d
    xor e
    sbc l
    xor h
    ld b, d
    ld d, b
    inc l
    jp $bcde


    ldh [$50], a
    and $e6
    and $e6
    and $50
    adc d
    sbc e
    jp hl


    ret c

    inc e
    db $e3
    and [hl]
    ld d, b
    ld b, e
    adc b
    and c
    xor e

jr_001_437f:
    dec l
    or [hl]
    sbc $50
    jp nz, $c9b7

    or d

jr_001_4387:
    cp h
    ld d, b
    inc [hl]
    cp b
    cp c
    cp h

jr_001_438d:
    ld d, b
    call nc, Call_000_34b9
    push bc
    or l
    cp h
    ld d, b
    cp d
    or l
    ret c

    push bc
    or l
    cp h
    ld d, b
    ret z

    pop de
    cp c
    dec hl
    rst $08
    cp h
    ld d, b
    rst $08
    set 0, l
    or l
    cp h
    ld d, b
    or [hl]
    or d
    call z, $c9b8
    cp b
    cp l
    ret c

    ld d, b
    rst $08
    sbc $c0
    sbc $c9
    cp b
    cp l
    ret c

    ld d, b
    cp l
    ld a, [hl+]
    or d
    add [hl]
    inc c
    jr z, jr_001_437f

    ret c

    ld d, b
    or d
    or d
    add [hl]
    inc c
    jr z, jr_001_4387

    ret c

    ld d, b
    add [hl]
    inc c
    jr z, jr_001_438d

    ret c

    ld d, b
    rlca
    and a
    db $e3
    add hl, de
    xor h
    dec bc
    ld d, b
    dec de
    and [hl]
    db $e3
    add hl, de
    xor h
    dec bc
    ld d, b
    add h
    and a
    xor e
    dec bc
    add hl, de
    xor h
    dec bc
    ld d, b
    and a
    add c
    xor e
    inc e
    db $e3
    add hl, de
    xor h
    dec bc
    ld d, b
    ld b, c
    xor e
    add a
    add hl, de
    xor h
    dec bc
    ld d, b
    add hl, bc
    db $e3
    and [hl]
    inc de
    add hl, de
    xor h
    dec bc
    ld d, b
    add a
    ret c

    sbc a
    ld c, $ab
    add hl, de
    xor h
    dec bc
    ld d, b
    rlca
    ret c

    db $e3
    xor e
    add hl, de
    xor h
    dec bc
    ld d, b
    or c
    push bc
    rst $00
    cp c
    ret


    sbc d
    and c
    ld d, b
    pop de
    cp h
    sub $b9
    adc h
    ld b, d
    and a
    db $e3
    ld d, b
    set 2, b
    jp nz, $89c9

    sbc c
    add a
    ld d, b
    adc $c9
    or l
    ret


    or d
    cp h
    ld d, b
    or [hl]
    ret nc

    push bc
    ret c

    ret


    or d
    cp h
    ld d, b
    ret nc

    dec l
    ret


    or d
    cp h
    ld d, b
    sbc l
    xor h
    add a
    adc h
    add b
    xor h
    ld b, d
    ld d, b
    adc a
    add d
    ret c

    xor e
    ld d, b
    dec de
    xor b
    sbc a
    call $8b86
    xor e
    ld d, b
    add c
    xor e
    inc de
    and b
    adc a
    adc e
    xor e
    ld d, b
    ret c

    ld c, $90
    add d
    sbc a
    ld d, b
    call z, $27bc

Jump_001_4465:
    push bc
    add b
    and b
    ld d, b
    cp d
    or e
    rst $10
    ret


    add l
    adc l
    add [hl]
    ld d, b
    or [hl]
    or d
    ret


    add l
    adc l
    add [hl]
    ld d, b
    set 2, b
    jp nz, $85c9

    ld b, $50
    and $e6
    and $e6
    and $50
    res 6, a
    or [hl]
    or h
    cp c
    sbc $50
    and h
    add a
    add b
    adc a
    db $e3
    and [hl]
    ld d, b
    ret c

    db $e3
    sbc e
    ret


    or d
    cp h
    ld d, b
    add l
    db $e3
    inc de
    add [hl]
    db $e3
    ld d, b
    or a
    sbc $c9
    ret nz

    rst $08
    ld d, b
    ld b, e
    add c
    xor e
    sub e
    add b
    xor h
    ld b, d
    ld d, b
    ld b, c
    xor h
    ld b, c
    add $de
    daa
    ld [c], a
    or e
    ld d, b
    push bc
    sbc $33
    db $d3
    push bc
    or l
    cp h
    ld d, b
    add hl, hl
    sbc $b7
    ret


    or [hl]
    cp c
    rst $10
    ld d, b
    add hl, hl
    sbc $b7
    ret


    or [hl]
    ret nz

    rst $08
    ret c

    ld d, b
    add e
    sbc e
    db $eb
    add a
    sub e
    dec b
    db $e3
    inc de
    ld d, b
    adc e
    and [hl]
    add hl, de
    db $e3
    adc h
    ld b, d
    and a
    db $e3
    ld d, b
    add hl, bc
    db $e3
    and [hl]
    inc de
    adc h
    ld b, d
    and a
    db $e3
    ld d, b
    add a
    ret c

    sub d
    or b
    add l
    xor h
    adc a
    db $e3
    ld d, b
    adc c
    add c
    xor e
    ld d, b
    or l
    or d
    cp h
    or d
    ret nc

    dec l
    ld d, b
    adc d
    add c
    adc c
    adc [hl]
    db $e3
    rrca
    ld d, b
    sbc [hl]
    xor h
    add a
    adc h
    add h
    and a
    ld d, b
    call z, $c9c8
    sub b
    adc b
    xor h
    sub e
    ld d, b
    or a
    sbc $c9
    or d
    jp c, Jump_001_503a

    ld b, d
    and l
    adc h
    ld b, b
    xor c
    db $e3
    ld d, b
    ld [de], a
    or b
    sbc e
    db $eb
    xor e
    rrca
    db $e3
    ld d, b
    adc h
    ld b, c
    db $e3
    rrca
    db $e3
    ld d, b
    adc h
    ld b, a
    adc e
    xor l
    and [hl]
    add b
    xor h
    ld b, d
    ld d, b
    adc c
    add c
    xor e
    adc b
    db $e3
    adc h
    ld d, b
    or l
    call nz, $b934
    db $d3
    ret


    ld d, b
    rrca
    add d
    dec bc
    xor e
    rlca
    sbc l
    adc e
    xor e
    ld d, b
    adc e
    and [hl]
    sbc e
    adc h
    adc c
    db $e3
    ld b, d
    ld d, b
    ld b, e
    adc b
    and c
    xor e
    ret


    call z, $50b4
    add e
    and a
    dec a
    db $e3
    adc a
    ret


    add l
    ld b, $50
    ld h, $b8
    cp h
    pop hl
    or e
    cp a
    or e
    pop bc
    ld d, b
    inc e
    xor b
    ret


    jp nz, $2bd8

    or l
    ld d, b
    or d
    or d
    jp nz, $2bd8

    or l
    ld d, b
    cp l
    ld a, [hl+]
    or d
    jp nz, $2bd8

    or l
    ld d, b
    ld b, e
    add c
    xor e
    sub e
    add b
    xor h
    ld b, d
    ld d, b
    ld b, c
    db $e3
    ld b, c
    db $e3
    add e
    add c
    inc de
    ld d, b
    ld b, c
    db $e3
    ld b, c
    db $e3
    ret c

    add l
    add hl, de
    db $e3
    ld d, b
    ld b, c
    db $e3
    ld b, c
    db $e3
    add e
    add c
    rrca
    db $e3
    ld d, b
    ld b, c
    db $e3
    ld b, c
    db $e3
    sbc l
    xor h
    add a
    adc h
    ld d, b
    pop bc
    or [hl]
    ld hl, sp-$4a
    or d
    ld d, b
    pop bc
    or [hl]
    rst $30
    or [hl]
    or d
    ld d, b
    rst $30
    or [hl]
    or d
    ld d, b
    ld hl, sp-$4a
    or d
    ld d, b
    ld sp, hl
    or [hl]
    or d
    ld d, b
    ld a, [$b2b6]
    ld d, b
    ei
    or [hl]
    or d
    ld d, b
    db $fc
    or [hl]
    or d
    ld d, b
    db $fd
    or [hl]
    or d
    ld d, b
    cp $b6
    or d
    ld d, b
    rst $38
    or [hl]
    or d
    ld d, b
    rst $30
    or $b6
    or d
    ld d, b
    rst $30
    rst $30
    or [hl]
    or d
    ld d, b
    pop bc
    or [hl]
    ld a, [$b2b6]
    ld d, b
    db $ed
    inc l
    push hl
    ld e, h
    add hl, de
    xor h
    db $10
    ld d, b
    or [hl]
    or d
    ld h, $d7
    add hl, de
    xor h
    db $10
    ld d, b
    or l
    inc l
    cpl
    or e
    add hl, de
    xor h
    db $10
    ld d, b
    jp z, Jump_000_3cd4

    cp e
    add hl, de
    xor h
    db $10
    ld d, b
    set 3, [hl]
    call nc, Call_000_19d8
    xor h
    db $10
    ld d, b
    push bc
    or [hl]
    sub $bc
    add hl, de
    xor h
    db $10
    ld d, b
    add hl, de
    and l
    add hl, de
    xor h
    db $10
    ld d, b
    set 1, c
    ret nz

    rst $08
    add hl, de
    xor h
    db $10
    ld d, b
    add hl, bc
    db $e3
    and [hl]
    inc de
    add hl, de
    xor h
    db $10
    ld d, b
    ret nz

    rst $08
    ld a, [hl+]
    ld d, b
    set 2, [hl]
    cp d
    ld d, b
    dec de
    xor b
    xor e
    inc c
    ld d, b
    adc e
    and [hl]
    add hl, de
    db $e3
    ld d, b
    add hl, bc
    db $e3
    and [hl]
    inc de
    ld d, b
    ld b, d
    sub b
    add [hl]
    xor l
    ld b, d
    sub d
    xor e
    ld d, b
    add [hl]
    xor l
    ld b, d
    sub d
    xor e
    ld d, b
    ld b, d
    sub b
    sbc l
    adc h
    adc a
    db $e3
    ld d, b
    sbc l
    adc h
    adc a
    db $e3
    ld d, b
    add e
    add a
    adc l
    and a
    xor e
    sub e
    ld a, [$cfb2]
    dec a
    jr z, jr_001_4681

    cp $ff
    ret nz

    ld [$cfb2], a
    jp Jump_000_0193


jr_001_4681:
    xor a
    ldh [$90], a

Jump_001_4684:
    ldh [$8f], a
    ld d, $c1
    ldh a, [$8f]
    ld e, a
    ld a, [de]
    and a
    jp z, Jump_001_4710

    inc e
    inc e
    ld a, [de]
    ld [$d54c], a
    cp $ff
    jr nz, jr_001_469f

    call Call_001_4734
    jr jr_001_4710

jr_001_469f:
    cp $a0
    jr c, jr_001_46a9

    and $0f
    add $10
    jr jr_001_46ab

jr_001_46a9:
    and $0f

jr_001_46ab:
    ld l, a
    push de
    inc d
    ld a, e
    add $05
    ld e, a
    ld a, [de]
    and $80
    ldh [$94], a
    pop de
    ld h, $00
    ld bc, $4000
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
    call Call_001_4734
    ldh a, [$90]
    ld e, a
    ld d, $c3

jr_001_46cf:
    ldh a, [$92]
    add $10
    add [hl]
    ld [de], a
    inc hl
    ldh a, [$91]
    add $08
    add [hl]
    inc e
    ld [de], a
    inc e
    ld a, [bc]
    inc bc
    push bc
    ld b, a
    ld a, [$d54c]
    swap a
    and $0f
    cp $0b
    jr nz, jr_001_46f1

    ld a, $7c
    jr jr_001_46f9

jr_001_46f1:
    sla a
    sla a
    ld c, a
    sla a
    add c

jr_001_46f9:
    add b
    pop bc
    ld [de], a
    inc hl
    inc e
    ld a, [hl]
    bit 1, a
    jr z, jr_001_4706

    ldh a, [$94]
    or [hl]

jr_001_4706:
    inc hl
    ld [de], a
    inc e
    bit 0, a
    jr z, jr_001_46cf

    ld a, e
    ldh [$90], a

Jump_001_4710:
jr_001_4710:
    ldh a, [$8f]
    add $10
    cp $00
    jp nz, Jump_001_4684

    ldh a, [$90]
    ld l, a
    ld h, $c3
    ld de, $0004
    ld b, $a0
    ld a, [$d6b5]
    bit 6, a
    ld a, $a0
    jr z, jr_001_472e

    ld a, $90

jr_001_472e:
    cp l
    ret z

    ld [hl], b
    add hl, de
    jr jr_001_472e

Call_001_4734:
    inc e
    inc e
    ld a, [de]
    ldh [$92], a
    inc e
    inc e
    ld a, [de]
    ldh [$91], a
    ld a, $04
    add e
    ld e, a
    ldh a, [$92]
    add $04
    and $f0
    ld [de], a
    inc e
    ldh a, [$91]
    and $f0
    ld [de], a
    ret


    ld c, $80
    ld b, $0a
    ld hl, $475e

jr_001_4757:
    ld a, [hl+]
    ld [c], a
    inc c
    dec b
    jr nz, jr_001_4757

    ret


    ld a, $c3
    ldh [rDMA], a
    ld a, $28

jr_001_4764:
    dec a
    jr nz, jr_001_4764

    ret


Call_001_4768:
    ld bc, $0006
    jp Jump_000_01bb


    ld hl, $49e4
    ld de, $d11d
    call Call_001_4768
    ld hl, $49e9
    ld de, $d2ce
    call Call_001_4768
    xor a
    ldh [$b0], a
    ld [$d2d7], a
    ld hl, $d6b1
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld a, $1f
    ld [$c0ef], a
    ld [$c0f0], a

Jump_001_4794:
    call Call_000_3e15
    ld a, $01
    ldh [$ba], a
    xor a
    ldh [$d7], a
    ld a, $90
    ldh [$ae], a
    ld a, $90
    ldh [$b0], a
    call Call_000_03bf
    call Call_000_0167
    call Call_000_36ca
    ld hl, $5161
    ld de, $9410
    ld bc, $00d0
    ld a, $04
    call Call_000_028c
    ld hl, $4419
    ld de, $8800
    ld bc, $0600
    ld a, $04
    call Call_000_028c
    ld hl, $4a19
    ld de, $9310
    ld bc, $0100
    ld a, $04
    call Call_000_028c
    ld hl, $4000
    ld de, $9600
    ld bc, $0050
    ld a, $1a
    call Call_000_02c0
    call Call_001_495d
    ld hl, $c3b6
    ld a, $80
    ld de, $0014
    ld c, $06

jr_001_47f4:
    ld b, $10
    push hl

jr_001_47f7:
    ld [hl+], a
    inc a
    dec b
    jr nz, jr_001_47f7

    pop hl
    add hl, de
    dec c
    jr nz, jr_001_47f4

    ld hl, $c42e
    ld a, $31
    ld b, $10

jr_001_4808:
    ld [hl+], a
    inc a
    dec b
    jr nz, jr_001_4808

    call Call_001_4921
    ld hl, $c4f7
    ld a, $41
    ld b, $0d

jr_001_4817:
    ld [hl+], a
    inc a
    dec b
    jr nz, jr_001_4817

    call Call_000_373e
    call Call_001_49d1
    call Call_000_3761
    call Call_000_374a
    call Call_000_0181
    ld a, $99
    ld [$cd3d], a
    call Call_001_4968
    ld a, $9b
    call Call_001_4977
    ld a, $40
    ldh [$b0], a
    ld a, $98
    call Call_001_4977
    ld b, $06
    call Call_000_3e1f
    call Call_000_3e0c
    ld a, $e4
    ldh [rOBP0], a
    ld a, $bd
    call Call_000_0e45

jr_001_4852:
    call Call_000_0b31
    ldh a, [$ae]
    add $04
    ldh [$ae], a
    jr nz, jr_001_4852

    ld a, $90
    ldh [$b0], a
    ld c, $14
    call Call_000_3781
    call Call_001_49d1
    call Call_000_3e07
    ld a, $9c
    call Call_001_4977
    call Call_000_376d
    call Call_000_3e07
    ld a, $c3
    ld [$c0ee], a
    call Call_000_0e45

jr_001_487f:
    ld c, $ff
    call Call_000_0359
    jr c, jr_001_488e

    call Call_001_48f3
    call Call_001_48cc
    jr jr_001_487f

jr_001_488e:
    ld a, [$cd3d]
    call Call_000_2dc7
    call Call_000_3790
    call Call_000_3e04
    call Call_000_0188
    xor a
    ldh [$b0], a
    ld a, $01
    ldh [$ba], a
    call Call_000_03bf
    ld a, $98
    call Call_001_4977
    ld a, $9c
    call Call_001_4977
    call Call_000_3e07
    call Call_000_0b3c
    ldh a, [$b4]
    ld b, a
    and $46
    cp $46
    jp z, Jump_001_48c4

    jp Jump_001_591e


Jump_001_48c4:
    ld b, $07
    ld hl, $421e
    jp Jump_000_3620


Call_001_48cc:
    ld a, $98
    call Call_001_4977

jr_001_48d1:
    call Call_000_3e8c
    and $0f
    ld c, a
    ld b, $00
    ld hl, $49c1
    add hl, bc
    ld a, [hl]
    ld hl, $cd3d
    cp [hl]
    jr z, jr_001_48d1

    ld [hl], a
    call Call_001_4968
    ld a, $90
    ldh [$b0], a
    ld d, $a0
    ld c, $0c
    jp Jump_001_48fe


Call_001_48f3:
    ld d, $00
    ld c, $14
    call Call_001_48fe
    xor a
    ldh [$b0], a
    ret


Call_001_48fe:
Jump_001_48fe:
jr_001_48fe:
    ld h, d
    ld l, $48
    call Call_001_4913
    ld h, $00
    ld l, $88
    call Call_001_4913
    ld a, d
    add $08
    ld d, a
    dec c
    jr nz, jr_001_48fe

    ret


Call_001_4913:
jr_001_4913:
    ldh a, [rLY]
    cp l
    jr nz, jr_001_4913

    ld a, h
    ldh [rSCX], a

jr_001_491b:
    ldh a, [rLY]
    cp h
    jr z, jr_001_491b

    ret


Call_001_4921:
    ld hl, $5711
    ld de, $8000
    ld bc, $0230
    ld a, $04
    call Call_000_028c
    call Call_000_0188
    xor a
    ld [$cd3d], a
    ld hl, $c300
    ld de, $6030
    ld b, $07

jr_001_493e:
    push de
    ld c, $05

jr_001_4941:
    ld a, d
    ld [hl+], a
    ld a, e
    ld [hl+], a
    add $08
    ld e, a
    ld a, [$cd3d]
    ld [hl+], a
    inc a
    ld [$cd3d], a
    inc hl
    dec c
    jr nz, jr_001_4941

    pop de
    ld a, $08
    add d
    ld d, a
    dec b
    jr nz, jr_001_493e

    ret


Call_001_495d:
    ld hl, $9800
    ld bc, $0800
    ld a, $7f
    jp Jump_000_372a


Call_001_4968:
    ld [$cf78], a
    ld [$d092], a
    ld hl, $c471
    call Call_000_2f2e
    jp Jump_000_2d7f


Call_001_4977:
    ld [$ffbd], a
    jp Jump_000_3e07


    xor a
    ldh [$b0], a
    call Call_000_03bf
    call Call_000_36ea
    ld de, $5161
    ld hl, $9600
    ld bc, $0419
    call Call_000_02dd
    ld hl, $c431
    ld de, $499b
    jp Jump_000_0405


    ld h, b
    ld h, c
    ld h, d
    ld h, e
    ld l, l
    ld l, [hl]
    ld l, a
    ld [hl], b
    ld [hl], c
    ld [hl], d
    ld c, [hl]
    ld h, b
    ld h, c
    ld h, d
    ld h, e
    ld [hl], e
    ld [hl], h
    ld [hl], l
    db $76
    ld [hl], a
    ld a, b
    ld l, e
    ld l, h
    ld c, [hl]
    ld h, b
    ld h, c
    ld h, d
    ld h, e
    ld h, h
    ld h, l
    ld h, [hl]
    ld h, a
    ld l, b
    ld l, c
    ld l, d
    ld l, e
    ld l, h
    ld d, b
    sbc c
    or b
    or c
    ld a, e
    rrca
    dec e
    ld d, h
    inc b
    ld bc, $1994
    ld c, h
    sub [hl]
    ld [hl+], a
    and e
    add l

Call_001_49d1:
    ld hl, $c446
    ld de, $49da
    jp Jump_000_0405


    ld h, d
    ld h, e
    ld h, h
    ld a, a
    ld h, l
    ld h, [hl]
    ld h, a
    ld l, b
    ld l, c
    ld d, b
    call nc, $28cf
    pop bc
    ld d, b
    or d
    cp h
    jp z, Jump_001_50d7

    ld hl, $c46b
    ld b, $01
    ld c, $0b
    ld a, [$d034]
    and a
    jr z, jr_001_4a00

    call Call_000_03d2
    jr jr_001_4a03

jr_001_4a00:
    call Call_001_58df

jr_001_4a03:
    ld hl, $c480
    ld de, $4a11
    call Call_000_0405
    ld c, $32
    jp Jump_000_3781


    db $ed
    inc l
    nop
    ld b, b
    ret nz

    or d
    or a
    pop bc
    pop hl
    or e
    rst $20
    ld d, b
    ld h, $c1
    inc h
    ld a, $0e

jr_001_4a22:
    ld l, a
    sub $0e
    ld c, a
    ldh [$da], a
    ld a, [hl]
    and a
    jr z, jr_001_4a35

    push hl
    push de
    push bc
    call Call_001_4a3d
    pop bc
    pop de
    pop hl

jr_001_4a35:
    ld a, l
    add $10
    cp $0e
    jr nz, jr_001_4a22

    ret


Call_001_4a3d:
    cp $01
    jp nz, Jump_001_4a45

    jp Jump_001_4c2d


Jump_001_4a45:
    dec a
    swap a
    ldh [$93], a
    ld a, [$cf12]
    ld b, a
    ldh a, [$da]
    cp b
    jr nz, jr_001_4a56

    jp Jump_001_5034


jr_001_4a56:
    jp Jump_001_4ccd


Call_001_4a59:
    nop
    ld h, $c1
    ldh a, [$da]
    ld l, a
    ld a, [hl]
    and a
    ret z

    ld a, l
    add $03
    ld l, a
    ld a, [hl+]
    call Call_001_4b59
    ld a, [hl+]
    add $04
    add b
    and $f0
    or c
    ldh [$90], a
    ld a, [hl+]
    call Call_001_4b59
    ld a, [hl]
    add b
    and $f0
    or c
    ldh [$91], a
    ld a, l
    add $07
    ld l, a
    xor a
    ld [hl-], a
    ld [hl-], a
    ldh a, [$91]
    ld [hl-], a
    ldh a, [$90]
    ld [hl], a
    xor a

Jump_001_4a8c:
    ldh [$8f], a
    swap a
    ld e, a
    ldh a, [$da]
    cp e
    jp z, Jump_001_4b50

    ld d, h
    ld a, [de]
    and a
    jp z, Jump_001_4b50

    inc e
    inc e
    ld a, [de]
    inc a
    jp z, Jump_001_4b50

    ldh a, [$da]
    add $0a
    ld l, a
    inc e
    ld a, [de]
    call Call_001_4b59
    inc e
    ld a, [de]
    add $04
    add b
    and $f0
    or c
    sub [hl]
    jr nc, jr_001_4abb

    cpl
    inc a

jr_001_4abb:
    ldh [$90], a
    push af
    rl c
    pop af
    ccf
    rl c
    ld b, $07
    ld a, [hl]
    and $0f
    jr z, jr_001_4acd

    ld b, $09

jr_001_4acd:
    ldh a, [$90]
    sub b
    ldh [$92], a
    ld a, b
    ldh [$90], a
    jr c, jr_001_4ae8

    ld b, $07
    dec e
    ld a, [de]
    inc e
    and a
    jr z, jr_001_4ae1

    ld b, $09

jr_001_4ae1:
    ldh a, [$92]
    sub b
    jr z, jr_001_4ae8

    jr nc, jr_001_4b50

jr_001_4ae8:
    inc e
    inc l
    ld a, [de]
    push bc
    call Call_001_4b59
    inc e
    ld a, [de]
    add b
    and $f0
    or c
    pop bc
    sub [hl]
    jr nc, jr_001_4afb

    cpl
    inc a

jr_001_4afb:
    ldh [$91], a
    push af
    rl c
    pop af
    ccf
    rl c
    ld b, $07
    ld a, [hl]
    and $0f
    jr z, jr_001_4b0d

    ld b, $09

jr_001_4b0d:
    ldh a, [$91]
    sub b
    ldh [$92], a
    ld a, b
    ldh [$91], a
    jr c, jr_001_4b28

    ld b, $07
    dec e
    ld a, [de]
    inc e
    and a
    jr z, jr_001_4b21

    ld b, $09

jr_001_4b21:
    ldh a, [$92]
    sub b
    jr z, jr_001_4b28

    jr nc, jr_001_4b50

jr_001_4b28:
    ldh a, [$91]
    ld b, a
    ldh a, [$90]
    inc l
    cp b
    jr c, jr_001_4b35

    ld b, $0c
    jr jr_001_4b37

jr_001_4b35:
    ld b, $03

jr_001_4b37:
    ld a, c
    and b
    or [hl]
    ld [hl], a
    ld a, c
    inc l
    inc l
    ldh a, [$8f]
    ld de, $4b6c
    add a
    add e
    ld e, a
    jr nc, jr_001_4b49

    inc d

jr_001_4b49:
    ld a, [de]
    or [hl]
    ld [hl+], a
    inc de
    ld a, [de]
    or [hl]
    ld [hl], a

Jump_001_4b50:
jr_001_4b50:
    ldh a, [$8f]
    inc a
    cp $10
    jp nz, Jump_001_4a8c

    ret


Call_001_4b59:
    and a
    ld b, $00
    ld c, $00
    jr z, jr_001_4b6b

    ld c, $09
    cp $ff
    jr z, jr_001_4b6a

    ld c, $07
    ld a, $00

jr_001_4b6a:
    ld b, a

jr_001_4b6b:
    ret


    nop
    ld bc, $0200
    nop
    inc b
    nop
    ld [$1000], sp
    nop
    jr nz, jr_001_4b79

jr_001_4b79:
    ld b, b
    nop
    add b
    ld bc, $0200
    nop
    inc b
    nop
    ld [$1000], sp
    nop
    jr nz, jr_001_4b88

jr_001_4b88:
    ld b, b
    nop
    add b
    nop
    ret


jr_001_4b8d:
    call Call_000_3e0c
    ld a, $80
    ld [$d2d5], a
    ld hl, $d6b2
    set 0, [hl]
    ld hl, $d123
    xor a
    ld [hl+], a
    dec a
    ld [hl], a
    ld a, $01
    ld [$cf78], a
    ld a, $14
    ld [$d0ec], a
    xor a
    ld [$cc49], a
    ld [$d2dd], a
    call Call_000_3971
    ld a, $01
    ld [$d036], a
    ld a, $2c
    call Call_000_3e9d
    ld a, $01
    ld [$cfb2], a
    ldh [$ba], a
    jr jr_001_4b8d

    call Call_000_3c6c
    ldh a, [$8c]
    ld b, a
    ld hl, $d54d

jr_001_4bd1:
    ld a, [hl+]
    cp $ff
    ret z

    cp b
    jr z, jr_001_4bdb

    inc hl
    jr jr_001_4bd1

jr_001_4bdb:
    ld a, [hl]
    ldh [$db], a
    ld hl, $d483
    ldh a, [$8c]
    dec a
    add a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    ld b, a
    ld c, $01
    call Call_000_3e5e
    jr nc, jr_001_4c06

    ldh a, [$db]
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $01
    ld [$cc3c], a
    ld hl, $4c0d
    jr jr_001_4c09

jr_001_4c06:
    ld hl, $4c20

jr_001_4c09:
    call Call_000_3c79
    ret


    db $ed
    jr z, jr_001_4c31

    ld d, [hl]
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    ret nc

    jp nz, $c0b9

    rst $20
    ld d, b
    dec bc
    ld d, b
    db $ed
    jr z, jr_001_4c61

    ld d, [hl]
    ret


    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    rst $20
    ld d, a

Jump_001_4c2d:
    ld a, [$c200]
    and a

jr_001_4c31:
    jr z, jr_001_4c3d

    cp $ff
    jr z, jr_001_4c46

    dec a
    ld [$c200], a
    jr jr_001_4c46

jr_001_4c3d:
    ld a, [$c45c]
    ldh [$93], a
    cp $60
    jr c, jr_001_4c4c

jr_001_4c46:
    ld a, $ff
    ld [$c102], a
    ret


jr_001_4c4c:
    call Call_001_4a59
    ld h, $c1
    ld a, [$cfac]
    and a
    jr nz, jr_001_4c8c

    ld a, [$d4a7]
    bit 2, a
    jr z, jr_001_4c61

    xor a
    jr jr_001_4c82

jr_001_4c61:
    bit 3, a
    jr z, jr_001_4c69

    ld a, $04
    jr jr_001_4c82

jr_001_4c69:
    bit 1, a
    jr z, jr_001_4c71

    ld a, $08
    jr jr_001_4c82

jr_001_4c71:
    bit 0, a
    jr z, jr_001_4c79

    ld a, $0c
    jr jr_001_4c82

jr_001_4c79:
    xor a
    ld [$c107], a
    ld [$c108], a
    jr jr_001_4ca7

jr_001_4c82:
    ld [$c109], a
    ld a, [$cfab]
    bit 0, a
    jr nz, jr_001_4c79

jr_001_4c8c:
    ld a, [$d6b5]
    bit 7, a
    jr nz, jr_001_4cb2

    ldh a, [$da]
    add $07
    ld l, a
    ld a, [hl]
    inc a
    ld [hl], a
    cp $04
    jr nz, jr_001_4ca7

    xor a
    ld [hl], a
    inc hl
    ld a, [hl]
    inc a
    and $03
    ld [hl], a

jr_001_4ca7:
    ld a, [$c108]
    ld b, a
    ld a, [$c109]
    add b
    ld [$c102], a

jr_001_4cb2:
    ldh a, [$93]
    ld c, a
    ld a, [$d4b4]
    cp c
    ld a, $00
    jr nz, jr_001_4cbf

    ld a, $80

jr_001_4cbf:
    ld [$c207], a
    ret


    push bc
    push af
    ldh a, [$da]
    ld c, a
    pop af
    add c
    ld l, a
    pop bc
    ret


Jump_001_4ccd:
    ldh a, [$da]
    swap a
    dec a
    add a
    ld hl, $d463
    add l
    ld l, a
    ld a, [hl]
    ld [$cf0f], a
    ld h, $c1
    ldh a, [$da]
    ld l, a
    inc l
    ld a, [hl]
    and a
    jp z, Jump_001_4ea9

    call Call_001_4ed8
    ret c

    ld h, $c1
    ldh a, [$da]
    ld l, a
    inc l
    ld a, [hl]
    bit 7, a
    jp nz, Jump_001_4e7b

    ld b, a
    ld a, [$cfab]
    bit 0, a
    jp nz, Jump_001_4e6f

    ld a, b
    cp $02
    jp z, Jump_001_4e53

    cp $03
    jp z, Jump_001_4dfa

    ld a, [$cfac]
    and a
    ret nz

    call Call_001_4eb9
    ld h, $c2
    ldh a, [$da]
    add $06
    ld l, a
    ld a, [hl]
    inc a
    jr z, jr_001_4d55

    inc a
    jr z, jr_001_4d55

    dec a
    ld [hl], a
    dec a
    push hl
    ld hl, $cf0a
    dec [hl]
    pop hl
    ld de, $cc5b
    call Call_001_502d
    cp $e0
    jp z, Jump_001_4dc4

    cp $ff
    jr nz, jr_001_4d47

    ld [hl], a
    ld hl, $d6af
    res 0, [hl]
    xor a
    ld [$cd38], a
    ld [$cd3a], a
    ret


jr_001_4d47:
    cp $fe
    jr nz, jr_001_4d5b

    ld [hl], $01
    ld de, $cc5b
    call Call_001_502d
    jr jr_001_4d5b

jr_001_4d55:
    call Call_001_5005
    call Call_000_3e8c

jr_001_4d5b:
    ld b, a
    ld a, [$cf0f]
    cp $d0
    jr z, jr_001_4d7b

    cp $d1
    jr z, jr_001_4d92

    cp $d2
    jr z, jr_001_4da9

    cp $d3
    jr z, jr_001_4dba

    ld a, b
    cp $40
    jr nc, jr_001_4d87

    ld a, [$cf0f]
    cp $02
    jr z, jr_001_4da9

jr_001_4d7b:
    ld de, $0028
    add hl, de
    ld de, $0100
    ld bc, $0400
    jr jr_001_4dc7

jr_001_4d87:
    cp $80
    jr nc, jr_001_4d9e

    ld a, [$cf0f]
    cp $02
    jr z, jr_001_4dba

jr_001_4d92:
    ld de, $ffd8
    add hl, de
    ld de, $ff00
    ld bc, $0804
    jr jr_001_4dc7

jr_001_4d9e:
    cp $c0
    jr nc, jr_001_4db3

    ld a, [$cf0f]
    cp $01
    jr z, jr_001_4d92

jr_001_4da9:
    dec hl
    dec hl
    ld de, $00ff
    ld bc, $0208
    jr jr_001_4dc7

jr_001_4db3:
    ld a, [$cf0f]
    cp $01
    jr z, jr_001_4d7b

jr_001_4dba:
    inc hl
    inc hl
    ld de, $0001
    ld bc, $010c
    jr jr_001_4dc7

Jump_001_4dc4:
    ld de, $0000

jr_001_4dc7:
    push hl
    ld h, $c1
    ldh a, [$da]
    add $09
    ld l, a
    ld [hl], c
    ldh a, [$da]
    add $03
    ld l, a
    ld [hl], d
    inc l
    inc l
    ld [hl], e
    pop hl
    push de
    ld c, [hl]
    call Call_001_4f6a
    pop de
    ret c

    ld h, $c2
    ldh a, [$da]
    add $04
    ld l, a
    ld a, [hl]
    add d
    ld [hl+], a
    ld a, [hl]
    add e
    ld [hl], a
    ldh a, [$da]
    ld l, a
    ld [hl], $10
    dec h
    inc l
    ld [hl], $03
    jp Jump_001_4f53


Jump_001_4dfa:
    ldh a, [$da]
    add $07
    ld l, a
    ld a, [hl]
    inc a
    ld [hl], a
    cp $04
    jr nz, jr_001_4e0e

    xor a
    ld [hl], a
    inc l
    ld a, [hl]
    inc a
    and $03
    ld [hl], a

jr_001_4e0e:
    ldh a, [$da]
    add $03
    ld l, a
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    add b
    ld [hl+], a
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    add b
    ld [hl], a
    ldh a, [$da]
    ld l, a
    inc h
    ld a, [hl]
    dec a
    ld [hl], a
    ret nz

    ld a, $06
    add l
    ld l, a
    ld a, [hl]
    cp $fe
    jr nc, jr_001_4e36

    ldh a, [$da]
    inc a
    ld l, a
    dec h
    ld [hl], $01
    ret


jr_001_4e36:
    call Call_000_3e8c
    ldh a, [$da]
    add $08
    ld l, a
    ldh a, [$d3]
    and $7f
    ld [hl], a
    dec h
    ldh a, [$da]
    inc a
    ld l, a
    ld [hl], $02
    inc l
    inc l
    xor a
    ld b, [hl]
    ld [hl+], a
    inc l
    ld c, [hl]
    ld [hl], a
    ret


Jump_001_4e53:
    ld h, $c2
    ldh a, [$da]
    add $06
    ld l, a
    ld a, [hl]
    inc l
    inc l
    cp $fe
    jr nc, jr_001_4e65

    ld [hl], $00
    jr jr_001_4e68

jr_001_4e65:
    dec [hl]
    jr nz, jr_001_4e6f

jr_001_4e68:
    dec h
    ldh a, [$da]
    inc a
    ld l, a
    ld [hl], $01

Jump_001_4e6f:
jr_001_4e6f:
    ld h, $c1
    ldh a, [$da]
    add $08
    ld l, a
    ld [hl], $00
    jp Jump_001_4f53


Jump_001_4e7b:
    ld a, [$d6ac]
    bit 5, a
    jr nz, jr_001_4e6f

    res 7, [hl]
    ld a, [$d4a9]
    bit 3, a
    jr z, jr_001_4e8f

    ld c, $00
    jr jr_001_4ea1

jr_001_4e8f:
    bit 2, a
    jr z, jr_001_4e97

    ld c, $04
    jr jr_001_4ea1

jr_001_4e97:
    bit 1, a
    jr z, jr_001_4e9f

    ld c, $0c
    jr jr_001_4ea1

jr_001_4e9f:
    ld c, $08

jr_001_4ea1:
    ldh a, [$da]
    add $09
    ld l, a
    ld [hl], c
    jr jr_001_4e6f

Jump_001_4ea9:
    ld [hl], $01
    inc l
    ld [hl], $ff
    inc h
    ldh a, [$da]
    add $02
    ld l, a
    ld a, $08
    ld [hl+], a
    ld [hl], a
    ret


Call_001_4eb9:
    ld h, $c2
    ldh a, [$da]
    add $04
    ld l, a
    ld a, [$d2e0]
    ld b, a
    ld a, [hl]
    sub b
    swap a
    sub $04
    dec h
    ld [hl+], a
    inc h
    ld a, [$d2e1]
    ld b, a
    ld a, [hl+]
    sub b
    swap a
    dec h
    ld [hl], a
    ret


Call_001_4ed8:
    ld a, $12
    call Call_000_3e9d
    ldh a, [$e5]
    and a
    jp nz, Jump_001_4f2a

    ld h, $c2
    ldh a, [$da]
    add $06
    ld l, a
    ld a, [hl]
    cp $fe
    jr c, jr_001_4f11

    ldh a, [$da]
    add $04
    ld l, a
    ld b, [hl]
    ld a, [$d2e0]
    cp b
    jr z, jr_001_4f02

    jr nc, jr_001_4f2a

    add $08
    cp b
    jr c, jr_001_4f2a

jr_001_4f02:
    inc l
    ld b, [hl]
    ld a, [$d2e1]
    cp b
    jr z, jr_001_4f11

    jr nc, jr_001_4f2a

    add $09
    cp b
    jr c, jr_001_4f2a

jr_001_4f11:
    call Call_001_5005
    ld d, $60
    ld a, [hl+]
    cp d
    jr nc, jr_001_4f2a

    ld a, [hl-]
    cp d
    jr nc, jr_001_4f2a

    ld bc, $ffec
    add hl, bc
    ld a, [hl+]
    cp d
    jr nc, jr_001_4f2a

    ld a, [hl]
    cp d
    jr c, jr_001_4f36

Jump_001_4f2a:
jr_001_4f2a:
    ld h, $c1
    ldh a, [$da]
    add $02
    ld l, a
    ld [hl], $ff
    scf
    jr jr_001_4f52

jr_001_4f36:
    ld c, a
    ld a, [$cfac]
    and a
    jr nz, jr_001_4f52

    call Call_001_4f53
    inc h
    ldh a, [$da]
    add $07
    ld l, a
    ld a, [$d4b4]
    cp c
    ld a, $00
    jr nz, jr_001_4f50

    ld a, $80

jr_001_4f50:
    ld [hl], a
    and a

jr_001_4f52:
    ret


Call_001_4f53:
Jump_001_4f53:
    ld h, $c1
    ldh a, [$da]
    add $08
    ld l, a
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    add b
    ld b, a
    ldh a, [$93]
    add b
    ld b, a
    ldh a, [$da]
    add $02
    ld l, a
    ld [hl], b
    ret


Call_001_4f6a:
    ld h, $c2
    ldh a, [$da]
    add $06
    ld l, a
    ld a, [hl]
    cp $fe
    jr nc, jr_001_4f78

    and a
    ret


jr_001_4f78:
    ld a, [$d4af]
    ld l, a
    ld a, [$d4b0]
    ld h, a

jr_001_4f80:
    ld a, [hl+]
    cp $ff
    jr z, jr_001_4fe7

    cp c
    jr nz, jr_001_4f80

    ld h, $c2
    ldh a, [$da]
    add $06
    ld l, a
    ld a, [hl]
    inc a
    jr z, jr_001_4fe7

    ld h, $c1
    ldh a, [$da]
    add $04
    ld l, a
    ld a, [hl+]
    add $04
    add d
    cp $80
    jr nc, jr_001_4fe7

    inc l
    ld a, [hl]
    add e
    cp $90
    jr nc, jr_001_4fe7

    push de
    push bc
    call Call_001_4a59
    pop bc
    pop de
    ld h, $c1
    ldh a, [$da]
    add $0c
    ld l, a
    ld a, [hl]
    and b
    jr nz, jr_001_4fe7

    ld h, $c2
    ldh a, [$da]
    add $02
    ld l, a
    ld a, [hl+]
    bit 7, d
    jr nz, jr_001_4fce

    add d
    cp $05
    jr c, jr_001_4fe7

    jr jr_001_4fd2

jr_001_4fce:
    sub $01
    jr c, jr_001_4fe7

jr_001_4fd2:
    ld d, a
    ld a, [hl]
    bit 7, e
    jr nz, jr_001_4fdf

    add e
    cp $05
    jr c, jr_001_4fe7

    jr jr_001_4fe3

jr_001_4fdf:
    sub $01
    jr c, jr_001_4fe7

jr_001_4fe3:
    ld [hl-], a
    ld [hl], d
    and a

Call_001_4fe6:
    ret


Jump_001_4fe7:
jr_001_4fe7:
    ld h, $c1
    ldh a, [$da]
    inc a
    ld l, a
    ld [hl], $02
    inc l
    inc l
    xor a
    ld [hl+], a
    inc l
    ld [hl], a
    inc h
    ldh a, [$da]
    add $08
    ld l, a
    call Call_000_3e8c
    ldh a, [$d3]
    and $7f
    ld [hl], a
    scf
    ret


Call_001_5005:
    ld h, $c1
    ldh a, [$da]
    add $04
    ld l, a
    ld a, [hl+]
    add $04
    and $f0
    srl a
    ld c, a
    ld b, $00
    inc l
    ld a, [hl]
    srl a
    srl a
    srl a
    add $14
    ld d, $00
    ld e, a
    ld hl, $c3a0
    add hl, bc
    add hl, bc
    add hl, bc
    add hl, bc
    add hl, bc
    add hl, de
    ret


Call_001_502d:
    add e
    ld e, a
    jr nc, jr_001_5032

    inc d

jr_001_5032:
    ld a, [de]

Jump_001_5033:
    ret


Jump_001_5034:
    ld a, [$d6af]
    bit 7, a
    ret z

Jump_001_503a:
    ld hl, $d6ad
    bit 7, [hl]
    set 7, [hl]
    jp z, Jump_001_50a4

    ld hl, $cc97
    ld a, [$cd37]
    add l
    ld l, a
    jr nc, jr_001_504f

    inc h

jr_001_504f:
    ld a, [hl]
    cp $40
    jr nz, jr_001_505d

    call Call_001_50b0
    ld c, $04
    ld a, $fe
    jr jr_001_5087

jr_001_505d:
    cp $00
    jr nz, jr_001_506a

    call Call_001_50b0
    ld c, $00
    ld a, $02
    jr jr_001_5087

jr_001_506a:
    cp $80
    jr nz, jr_001_5077

    call Call_001_50b5
    ld c, $08
    ld a, $fe
    jr jr_001_5087

jr_001_5077:
    cp $c0
    jr nz, jr_001_5084

    call Call_001_50b5
    ld c, $0c
    ld a, $02
    jr jr_001_5087

jr_001_5084:
    cp $ff
    ret


jr_001_5087:
    ld b, a
    ld a, [hl]
    add b
    ld [hl], a
    ldh a, [$da]
    add $09
    ld l, a
    ld a, c
    ld [hl], a
    call Call_001_50c1
    ld hl, $cf13
    dec [hl]
    ret nz

    ld a, $08
    ld [$cf13], a
    ld hl, $cd37
    inc [hl]
    ret


Jump_001_50a4:
    xor a
    ld [$cd37], a
    ld a, $08
    ld [$cf13], a
    jp Jump_001_50c1


Call_001_50b0:
    ld a, $04

Jump_001_50b2:
    ld b, a
    jr jr_001_50b8

Call_001_50b5:
    ld a, $06
    ld b, a

jr_001_50b8:
    ld hl, $c100
    ldh a, [$da]
    add l
    add b
    ld l, a
    ret


Call_001_50c1:
Jump_001_50c1:
    ld hl, $c200
    ldh a, [$da]
    add $0e
    ld l, a
    ld a, [hl]
    dec a
    swap a
    ld b, a
    ld hl, $c100
    ldh a, [$da]
    add $09
    ld l, a
    ld a, [hl]

Jump_001_50d7:
    cp $00

Jump_001_50d9:
    jr z, jr_001_50e8

    cp $04
    jr z, jr_001_50e8

    cp $08
    jr z, jr_001_50e8

    cp $0c
    jr z, jr_001_50e8

    ret


jr_001_50e8:
    add b
    ld b, a
    ldh [$e9], a
    call Call_001_50ff
    ld hl, $c100
    ldh a, [$da]
    add $02
    ld l, a
    ldh a, [$e9]
    ld b, a
    ldh a, [$ea]
    add b
    ld [hl], a
    ret


Call_001_50ff:
    ldh a, [$da]
    add $07
    ld l, a
    ld a, [hl]
    inc a
    ld [hl], a
    cp $04
    ret nz

    xor a
    ld [hl], a
    inc l
    ld a, [hl]
    inc a
    and $03
    ld [hl], a
    ldh [$ea], a
    ret


Call_001_5115:
    ld c, $50
    call Call_000_3781
    call Call_000_03bf
    call Call_000_0ebd
    call Call_000_36ca
    call Call_000_370a
    call Call_001_5912
    ld hl, $c443
    ld b, $02
    ld c, $0c
    call Call_001_58df
    ld hl, $c46c
    ld de, $5368
    call Call_000_0405
    xor a
    ld hl, $d051
    ld [hl+], a
    ld [$cce0], a
    ld [hl], $50

Jump_001_5146:
    ld hl, $d117
    ld a, $fd
    ld b, $06

jr_001_514d:
    ld [hl+], a
    dec b
    jr nz, jr_001_514d

    ld hl, $d106
    ld a, $fd
    ld b, $07

jr_001_5158:
    ld [hl+], a
    dec b
    jr nz, jr_001_5158

    ld b, $0a

jr_001_515e:
    call Call_000_3e8c
    cp $fd
    jr nc, jr_001_515e

    ld [hl+], a
    dec b
    jr nz, jr_001_515e

    ld hl, $c508
    ld a, $fd
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld b, $c8
    xor a

jr_001_5174:
    ld [hl+], a
    dec b
    jr nz, jr_001_5174

    ld hl, $d806
    ld bc, $013b

jr_001_517e:
    xor a
    ld [hl+], a
    dec bc
    ld a, b
    or c
    jr nz, jr_001_517e

    ld hl, $d12a
    ld de, $c512
    ld bc, $0000

jr_001_518e:
    inc c
    ld a, c
    cp $fd
    jr z, jr_001_51aa

    ld a, b
    dec a
    jr nz, jr_001_519d

    ld a, c
    cp $0d
    jr z, jr_001_51b3

jr_001_519d:
    inc hl
    ld a, [hl]
    cp $fe
    jr nz, jr_001_518e

    ld a, c
    ld [de], a
    inc de
    ld [hl], $ff
    jr jr_001_518e

jr_001_51aa:
    ld a, $ff
    ld [de], a
    inc de
    ld bc, $0100
    jr jr_001_518e

; ── TradeExchangeData: ポケモン交換データ転送 ──
; 3段階でパーティ情報を双方向交換する:
;   1. $D106 → $CD7C (17バイト/$11): トレーナー名
;   2. $D117 → $D812 (359バイト/$167): パーティデータ (ポケモン6体分)
;   3. $C508 → $C5D0 (200バイト/$C8): 種族ID・ニックネーム等
; マスターは $CCE0 のコマンドバイトを先に送信してから転送開始。
; 割り込み: rIE=$08 (シリアルのみ) で転送 → 完了後 rIE=$0D に復帰。
jr_001_51b3:
    ld a, $ff
    ld [de], a          ; 終端マーカー
    xor a
    call Call_000_0c66  ; SerialSyncWait: 相手と同期
    ldh a, [$aa]
    cp $02              ; マスター?
    jr nz, jr_001_51d8  ; → スレーブは同期後すぐデータ転送へ

    ; マスター: コマンドバイトを2回送信 (確実な同期のため)
    call Call_000_3e07
    ld a, [$cce0]       ; コマンドバイト (通信種別)
    ldh [$ac], a
    ld a, $81
    ldh [rSC], a        ; 1回目送信
    call Call_000_0b31  ; VBlank待ち
    ld a, [$cce0]
    ldh [$ac], a
    ld a, $81
    ldh [rSC], a        ; 2回目送信

jr_001_51d8:
    call Call_000_3e07
    ld a, $08
    ldh [rIE], a        ; シリアル割り込みのみ有効

    ; 第1段階: トレーナー名 (17バイト)
    ld hl, $d106        ; 送信元: 自分のトレーナー名
    ld de, $cd7c        ; 受信先: 相手のトレーナー名
    ld bc, $0011        ; 17バイト
    call Call_000_0bf1  ; SerialExchangeBlock

    ld a, $fe
    ld [de], a          ; 終端マーカー

    ; 第2段階: パーティデータ (359バイト)
    ld hl, $d117        ; 送信元: 自分のパーティ
    ld de, $d812        ; 受信先: 相手のパーティ
    ld bc, $0167        ; 359バイト
    call Call_000_0bf1  ; SerialExchangeBlock

    ld a, $fe
    ld [de], a          ; 終端マーカー

    ; 第3段階: 種族ID・ニックネーム (200バイト)
    ld hl, $c508        ; 送信元
    ld de, $c5d0        ; 受信先
    ld bc, $00c8        ; 200バイト
    call Call_000_0bf1  ; SerialExchangeBlock

    ld a, $0d
    ldh [rIE], a        ; 割り込み復帰 (VBlank+Timer+Serial)
    ld a, $ff
    call Call_000_0e45
    ldh a, [$aa]
    cp $02              ; マスター?
    jr z, jr_001_5237   ; → マスターはスキップ

    ; スレーブ: 受信したトレーナー名からIDを抽出
    ld hl, $cd7c

jr_001_521b:
    ld a, [hl+]         ; 先頭のゼロ/$FD/$FE をスキップ
    and a
    jr z, jr_001_521b

    cp $fd
    jr z, jr_001_521b

    cp $fe
    jr z, jr_001_521b

    dec hl
    ld de, $d10d        ; 相手トレーナーID格納先
    ld c, $0a           ; 10バイト

jr_001_522d:
    ld a, [hl+]
    cp $fe              ; $FE (パディング) をスキップ
    jr z, jr_001_522d

    ld [de], a
    inc de
    dec c
    jr nz, jr_001_522d

jr_001_5237:
    ld hl, $d815

jr_001_523a:
    ld a, [hl+]
    and a
    jr z, jr_001_523a

    cp $fd
    jr z, jr_001_523a

    cp $fe
    jr z, jr_001_523a

    dec hl
    ld de, $d806
    ld c, $06

jr_001_524c:
    ld a, [hl+]
    cp $fe
    jr z, jr_001_524c

    ld [de], a
    inc de
    dec c
    jr nz, jr_001_524c

    ld de, $d81b
    ld bc, $0158

jr_001_525c:
    ld a, [hl+]
    cp $fe
    jr z, jr_001_525c

    ld [de], a
    inc de
    dec bc
    ld a, b
    or c
    jr nz, jr_001_525c

    ld de, $c508
    ld hl, $d12b
    ld c, $02

jr_001_5270:
    ld a, [de]
    inc de
    and a
    jr z, jr_001_5270

    cp $fd
    jr z, jr_001_5270

    cp $fe
    jr z, jr_001_5270

    cp $ff
    jr z, jr_001_528f

    push hl
    push bc
    ld b, $00
    dec a
    ld c, a
    add hl, bc
    ld a, $fe
    ld [hl], a
    pop bc
    pop hl
    jr jr_001_5270

jr_001_528f:
    ld hl, $d227
    dec c
    jr nz, jr_001_5270

    ld de, $c5d0
    ld hl, $d823
    ld c, $02

jr_001_529d:
    ld a, [de]
    inc de
    and a
    jr z, jr_001_529d

    cp $fd
    jr z, jr_001_529d

    cp $fe
    jr z, jr_001_529d

    cp $ff
    jr z, jr_001_52bc

    push hl
    push bc
    ld b, $00
    dec a
    ld c, a
    add hl, bc
    ld a, $fe
    ld [hl], a
    pop bc
    pop hl
    jr jr_001_529d

jr_001_52bc:
    ld hl, $d91f
    dec c
    jr nz, jr_001_529d

    ld a, [$d11d]
    cp $60
    jr nz, jr_001_52ce

    ld de, $5360
    jr jr_001_52d8

jr_001_52ce:
    ld a, [$d806]
    cp $60
    jr nz, jr_001_52e3

    ld de, $5364

jr_001_52d8:
    call Call_000_386e
    ld hl, $5336
    call Call_000_3c79

jr_001_52e1:
    jr jr_001_52e1

jr_001_52e3:
    ld a, $2b
    ld [$cf74], a
    ld a, $d9
    ld [$cf75], a
    xor a
    ld [$cc38], a
    ld a, $ff
    call Call_000_0e45
    ldh a, [$aa]
    cp $02
    ld c, $42
    call z, Call_000_3781
    ld a, [$d0f0]
    cp $03
    ld a, $32
    ld [$d0f0], a
    jr nz, jr_001_532d

    ld a, $04
    ld [$d0f0], a
    ld a, $e1
    ld [$d036], a
    call Call_000_03bf
    call Call_000_3e07
    ld hl, $d2d4
    res 7, [hl]
    ld a, $2c
    call Call_000_3e9d
    ld a, $07
    call Call_000_3e9d
    jp Jump_001_55a0


jr_001_532d:
    ld c, $1f
    ld a, $d9
    call Call_000_0e35
    jr jr_001_5375

    db $ed
    jr z, jr_001_5396

    ld d, [hl]
    ret


    ld a, a
    ld [de], a
    db $e3
    adc a
    ld h, $4f
    cp d
    call c, $c3da
    or d
    rst $08
    cp l
    rst $20
    ld c, e
    inc sp
    sbc $29
    sbc $dd
    ld a, a
    or a
    rst $18
    jp $d44c


    ret c

    push bc
    or l
    cp h
    jp Jump_000_30b8


    cp e
    or d
    add sp, $57
    inc l
    inc a
    sbc $50
    or c
    or d
    jp $ed50


    inc l
    dec e
    ld b, b
    inc l
    pop hl
    sbc $3b
    pop bc
    pop hl
    or e
    rst $20
    ld d, b

Jump_001_5375:
jr_001_5375:
    ld hl, $5886
    ld b, $00
    ld a, [$cc38]
    cp $ff
    jp z, Jump_001_4794

    add a
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp hl


    call Call_000_03bf
    call Call_001_5912
    call Call_001_5617
    call Call_001_55c5
    xor a

jr_001_5396:
    ld hl, $cc3d
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$cc37], a
    ld [$cc26], a
    ld [$cc2a], a
    ld [$cc34], a
    inc a
    ld [$cc42], a
    jp Jump_001_541a


Jump_001_53b0:
    xor a
    ld [$cc37], a
    inc a
    ld [$cc49], a
    ld a, $a1
    ld [$cc29], a
    ld a, [$d81b]
    ld [$cc28], a
    ld a, $03
    ld [$cc24], a
    ld a, $0c
    ld [$cc25], a

Jump_001_53cd:
    call Call_000_3b08
    and a
    jp z, Jump_001_5486

    bit 0, a
    jr z, jr_001_53ee

    ld a, $01
    ld [$d0e0], a
    ld hl, $5ead
    ld b, $0e
    call Call_000_3620
    ld hl, $d823
    call Call_001_55fb
    jp Jump_001_5486


jr_001_53ee:
    bit 5, a
    jr z, jr_001_5412

    xor a
    ld [$cc49], a
    ld a, [$cc30]
    ld l, a
    ld a, [$cc31]
    ld h, a
    ld a, [$cc27]
    ld [hl], a
    ld a, [$cc26]
    ld b, a
    ld a, [$d123]
    dec a
    cp b
    jr nc, jr_001_541a

    ld [$cc26], a
    jr jr_001_541a

jr_001_5412:
    bit 7, a
    jp z, Jump_001_5486

    jp Jump_001_5551


Jump_001_541a:
jr_001_541a:
    xor a
    ld [$cc49], a
    ld [$cc37], a
    ld a, $91
    ld [$cc29], a
    ld a, [$d123]
    ld [$cc28], a
    ld a, $03
    ld [$cc24], a
    ld a, $02
    ld [$cc25], a

Jump_001_5436:
    call Call_000_3b08
    and a
    jr nz, jr_001_543f

    jp Jump_001_5486


jr_001_543f:
    bit 0, a
    jr z, jr_001_5459

    jp Jump_001_5490


    ld a, $04
    ld [$d0e0], a
    ld hl, $5ead
    ld b, $0e
    call Call_000_3620
    call Call_001_55fb
    jp Jump_001_5486


jr_001_5459:
    bit 4, a
    jr z, jr_001_547f

    ld a, $01
    ld [$cc49], a
    ld a, [$cc30]
    ld l, a
    ld a, [$cc31]
    ld h, a
    ld a, [$cc27]
    ld [hl], a
    ld a, [$cc26]
    ld b, a
    ld a, [$d81b]
    dec a
    cp b
    jr nc, jr_001_547c

    ld [$cc26], a

jr_001_547c:
    jp Jump_001_53b0


Jump_001_547f:
jr_001_547f:
    bit 7, a
    jr z, jr_001_5486

    jp Jump_001_5551


Jump_001_5486:
jr_001_5486:
    ld a, [$cc49]
    and a
    jp z, Jump_001_5436

    jp Jump_001_53cd


Jump_001_5490:
    call Call_000_3761
    call Call_000_3c1c
    ld a, [$cc26]
    push af
    ld hl, $c4b8
    ld b, $02
    ld c, $12
    call Call_001_58df
    ld hl, $c4e2
    ld de, $553f
    call Call_000_0405
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    ld [$cc34], a
    ld [$cc28], a
    ld a, $10
    ld [$cc24], a

jr_001_54bf:
    ld a, $7f
    ld [$c4eb], a
    ld a, $13
    ld [$cc29], a
    ld a, $01
    ld [$cc25], a
    call Call_000_3b08
    bit 4, a
    jr nz, jr_001_54e3

    bit 1, a
    jr z, jr_001_54ff

jr_001_54d9:
    pop af
    ld [$cc26], a
    call Call_000_376d
    jp Jump_001_541a


jr_001_54e3:
    ld a, $7f
    ld [$c4e1], a
    ld a, $23
    ld [$cc29], a
    ld a, $0b
    ld [$cc25], a
    call Call_000_3b08
    bit 5, a
    jr nz, jr_001_54bf

    bit 1, a
    jr nz, jr_001_54d9

    jr jr_001_5519

jr_001_54ff:
    pop af
    ld [$cc26], a
    ld a, $04
    ld [$d0e0], a
    ld hl, $5ead
    ld b, $0e

jr_001_550d:
    call Call_000_3620
    call Call_001_55fb
    call Call_000_376d
    jp Jump_001_541a


jr_001_5519:
    call Call_000_3c1c
    pop af
    ld [$cc26], a
    ld [$cd3d], a
    ld [$cc42], a
    call Call_000_0c55
    ld a, [$cc3d]
    cp $0f
    jp z, Jump_001_5375

    ld [$cd3e], a
    call Call_001_55ec
    ld a, $01
    ld [$cc38], a
    jp Jump_001_5375


    db $ed
    inc l
    dec [hl]
    ld b, b
    adc h
    db $dd
    ret nc

    reti


    ld a, a
    ld a, a
    cp d
    or e
    or [hl]
    sbc $c6
    jr nc, jr_001_550d

    ld d, b

Jump_001_5551:
    ld a, [$cc26]
    ld b, a
    ld a, [$cc28]
    cp b
    jp nz, Jump_001_5486

    ld a, [$cc30]
    ld l, a
    ld a, [$cc31]
    ld h, a
    ld a, $7f
    ld [hl], a

jr_001_5567:
    ld a, $ed
    ld [$c4e1], a

jr_001_556c:
    call Call_000_3879
    ld a, [$ffb5]
    and a
    jr z, jr_001_556c

    bit 0, a
    jr nz, jr_001_558c

    bit 6, a
    jr z, jr_001_556c

    ld a, $7f
    ld [$c4e1], a
    ld a, [$d123]
    dec a
    ld [$cc26], a
    jp Jump_001_541a


jr_001_558c:
    ld a, $ec
    ld [$c4e1], a
    ld a, $0f
    ld [$cc42], a
    call Call_000_0c55
    ld a, [$cc3d]
    cp $0f
    jr nz, jr_001_5567

Jump_001_55a0:
    call Call_000_3e04
    ld hl, $cfab
    ld a, [hl]
    push af
    push hl
    res 0, [hl]
    xor a
    ld [$d6ac], a
    dec a
    ld [$d3ae], a
    call Call_000_2c52
    ld b, $03
    ld hl, $497b
    call Call_000_3620
    pop hl
    pop af
    ld [hl], a
    call Call_000_0b78
    ret


Call_001_55c5:
Jump_001_55c5:
    ld hl, $c4d7
    ld a, $7e
    ld bc, $0031
    call Call_000_372a
    ld hl, $c4cc
    ld b, $01
    ld c, $09
    call Call_001_58df
    ld hl, $c4e2
    ld de, $55e3
    jp Jump_000_0405


    db $ed
    inc l
    ld h, [hl]
    ld b, b

Call_001_55e7:
    pop bc
    pop hl
    or e
    cp h
    ld d, b

Call_001_55ec:
    ld a, [$cc3d]
    ld hl, $c3e8
    ld bc, $0028
    call Call_000_3ad1
    ld [hl], $ec
    ret


Call_001_55fb:
    ld a, [$cc26]
    ld [$cf79], a
    ld a, $36
    call Call_000_3e9d
    ld a, $37
    call Call_000_3e9d
    call Call_000_3e0c
    call Call_001_5912
    call Call_001_5617
    jp Jump_001_55c5


Call_001_5617:
    ld hl, $c3b4
    ld b, $0c
    ld c, $08
    call Call_001_58df
    ld hl, $c3be
    ld b, $0c
    ld c, $08
    call Call_001_58df
    ld hl, $c3b7
    ld de, $d11d
    call Call_000_0405
    ld hl, $c3c1
    ld de, $d806
    call Call_000_0405
    ld hl, $c3df
    ld de, $d124
    call Call_001_564c
    ld hl, $c3e9
    ld de, $d81c

Call_001_564c:
    ld c, $00

jr_001_564e:
    ld a, [de]
    cp $ff
    ret z

    ld [$d0e3], a
    push bc
    push hl
    push de
    push hl
    ld a, c
    ldh [$95], a
    call Call_000_1aab
    pop hl
    call Call_000_0405
    pop de
    inc de
    pop hl
    ld bc, $0028
    add hl, bc
    pop bc
    inc c
    jr jr_001_564e

    ld c, $64
    call Call_000_3781
    xor a
    ld [$cc43], a
    ld [$cc3e], a
    ld [$cc37], a
    ld [$cc34], a
    ld hl, $c490
    ld b, $04
    ld c, $12
    call Call_001_58df
    ld a, [$cd3d]
    ld hl, $d124
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $cd68
    ld de, $cd3f
    ld bc, $0006
    call Call_000_01bb
    ld a, [$cd3e]
    ld hl, $d81c
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $584a
    ld bc, $c4b9
    call Call_000_05f1
    call Call_000_3761
    ld hl, $c436
    ld bc, $080b
    ld a, $05
    ld [$d0f1], a
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    call Call_000_376d
    ld a, [$cc26]
    and a
    jr z, jr_001_56fe

    ld a, $01
    ld [$cc42], a
    ld hl, $c490
    ld b, $04
    ld c, $12
    call Call_001_58df
    ld hl, $c4b9
    ld de, $586d
    call Call_000_0405
    call Call_000_0c55
    jp Jump_001_583e


jr_001_56fe:
    ld a, $02
    ld [$cc42], a
    call Call_000_0c55
    ld a, [$cc3d]
    dec a
    jr nz, jr_001_5722

    ld hl, $c490
    ld b, $04
    ld c, $12
    call Call_001_58df
    ld hl, $c4b9
    ld de, $586d
    call Call_000_0405
    jp Jump_001_583e


jr_001_5722:
    ld a, [$cd3d]
    ld hl, $d233
    call Call_000_3ac7
    ld de, $cd41
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d12b
    ld a, [$cd3d]
    ld bc, $002c
    call Call_000_3ad1
    ld bc, $000c
    add hl, bc
    ld a, [hl+]
    ld [$cd47], a
    ld a, [hl]
    ld [$cd48], a
    ld a, [$cd3e]
    ld hl, $d92b
    call Call_000_3ac7
    ld de, $cd49
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d823
    ld a, [$cd3e]
    ld bc, $002c
    call Call_000_3ad1
    ld bc, $000c
    add hl, bc
    ld a, [hl+]
    ld [$cd4f], a
    ld a, [hl]
    ld [$cd50], a
    ld a, [$cd3d]
    ld [$cf79], a
    ld hl, $d124
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl]
    ld [$cd3d], a
    xor a
    ld [$cf7c], a
    call Call_000_3969
    ld a, [$cd3e]
    ld c, a
    ld [$cf79], a
    ld hl, $d81c
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    ld [$cf78], a
    ld hl, $d823
    ld a, c
    ld bc, $002c
    call Call_000_3ad1
    ld de, $cf7f
    ld bc, $002c
    call Call_000_01bb
    call Call_000_3a9d
    ld a, [$d123]
    dec a
    ld [$cf79], a
    ld a, $01
    ld [$ccd4], a
    ld a, [$cd3e]
    ld hl, $d81c
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl]
    ld [$cd3e], a
    ld a, $0a
    ld [$cfae], a
    ld a, $02
    ld [$c0f0], a
    ld a, $e5
    ld [$c0ee], a
    call Call_000_0e45
    ld c, $64
    call Call_000_3781
    call Call_000_03bf
    call Call_000_370a
    xor a
    ld [$cc5b], a
    ld a, [$ffaa]
    cp $01
    jr z, jr_001_57ff

    ld a, $38
    call Call_000_3e9d
    jr jr_001_5804

jr_001_57ff:
    ld a, $2f
    call Call_000_3e9d

jr_001_5804:
    ld hl, $70a1
    ld b, $0e
    call Call_000_3620
    call Call_000_03bf
    call Call_001_5912
    call Call_000_0c55
    ld c, $28
    call Call_000_3781
    ld hl, $c490
    ld b, $04
    ld c, $12
    call Call_001_58df
    ld hl, $c4b9
    ld de, $5861
    call Call_000_0405
    ld a, $50
    call Call_000_3e9d
    ld c, $32
    call Call_000_3781
    xor a
    ld [$cc38], a
    jp Jump_001_5146


Jump_001_583e:
    ld c, $64
    call Call_000_3781
    xor a
    ld [$cc38], a
    jp Jump_001_5375


    ld bc, $cd3f
    nop
    ld a, a
    call nz, $507f
    ld bc, $cd68
    nop
    ld a, a
    db $dd
    ld c, a
    cp d
    or e
    or [hl]
    sbc $bc
    rst $08
    cp l
    ld d, a
    db $ed
    inc l
    cp c
    ld b, b
    cp h
    pop hl
    or e
    ret c

    ld [c], a
    or e
    rst $20
    ld d, b
    db $ed
    inc l
    sbc b
    ld b, b
    push bc
    ld h, $d7
    ld c, [hl]
    cp d
    or e
    or [hl]
    sbc $ca
    ld a, a
    add [hl]
    xor l
    xor e
    adc l
    and [hl]
    cp e
    jp c, $bccf

    ret nz

    ld d, b
    adc c
    ld d, e
    ld l, [hl]
    ld d, [hl]
    ld a, [$d0f0]
    cp $02
    jr z, jr_001_58a0

    cp $03
    jr z, jr_001_58a0

    cp $05
    ret nz

    ld a, $4d
    call Call_000_3e9d
    jp Jump_000_09da


jr_001_58a0:
    call Call_001_5115
    ld hl, $7670
    ld a, h
    ld [$d4ae], a
    ld a, l
    ld [$d4ad], a
    ld a, $1b
    ld [$d4aa], a
    ld hl, $0266
    ld a, h
    ld [$d4b0], a
    ld a, l
    ld [$d4af], a
    xor a
    ld [$d806], a
    inc a
    ld [$d0f0], a
    ld [$ffb5], a
    ld a, $0a
    ld [$cfae], a
    ld a, $02
    ld [$c0f0], a
    ld a, $ca
    ld [$c0ee], a
    jp Jump_000_0e45


    ret


    call Call_000_3ec4

Call_001_58df:
    push hl
    ld a, $78
    ld [hl+], a
    inc a
    call Call_001_590c
    inc a
    ld [hl], a
    pop hl
    ld de, $0014
    add hl, de

jr_001_58ee:
    push hl
    ld a, $7b
    ld [hl+], a
    ld a, $7f
    call Call_001_590c
    ld [hl], $77
    pop hl
    ld de, $0014
    add hl, de
    dec b
    jr nz, jr_001_58ee

    ld a, $7c
    ld [hl+], a
    ld a, $76
    call Call_001_590c
    ld [hl], $7d
    ret


Call_001_590c:
    ld d, c

jr_001_590d:
    ld [hl+], a
    dec d
    jr nz, jr_001_590d

    ret


Call_001_5912:
    ld de, $7bf6
    ld hl, $9760
    ld bc, $0b09
    jp Jump_000_02dd


Jump_001_591e:
    call Call_001_5a2b
    xor a
    ld [$d067], a
    inc a
    ld [$d065], a
    call Call_001_5ee3
    jr nc, jr_001_5933

    ld a, $52
    call Call_000_3e9d

Jump_001_5933:
jr_001_5933:
    ld c, $14
    call Call_000_3781
    xor a
    ld [$d0f0], a
    ld hl, $cc2b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$d059], a
    ld hl, $d6ad
    res 6, [hl]
    call Call_000_03bf
    call Call_000_3e1d
    call Call_000_36ea
    call Call_000_36ca
    ld hl, $d6af
    set 6, [hl]
    ld a, [$d065]
    cp $01
    jr z, jr_001_5978

    ld hl, $c3a0
    ld b, $06
    ld c, $0d
    call Call_000_03d2
    ld hl, $c3ca
    ld de, $5bd6
    call Call_000_0405
    jr jr_001_598b

jr_001_5978:
    ld hl, $c3a0
    ld b, $04
    ld c, $0d
    call Call_000_03d2
    ld hl, $c3ca
    ld de, $5be0
    call Call_000_0405

jr_001_598b:
    ld hl, $d6af
    res 6, [hl]
    call Call_000_0ebd
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    ld [$cc34], a
    inc a
    ld [$cc25], a
    inc a
    ld [$cc24], a
    ld a, $0b
    ld [$cc29], a
    ld a, [$d065]
    ld [$cc28], a
    call Call_000_3b08
    bit 1, a
    jp nz, Jump_001_4794

    ld c, $14
    call Call_000_3781
    ld a, [$cc26]
    ld b, a
    ld a, [$d065]
    cp $02
    jp z, Jump_001_59ca

    inc b

Jump_001_59ca:
    ld a, b
    and a
    jr z, jr_001_59de

    cp $01
    jp z, Jump_001_5baa

    call Call_001_5ce4
    ld a, $01
    ld [$d067], a
    jp Jump_001_5933


jr_001_59de:
    call Call_001_5c08
    ld hl, $d0eb
    set 5, [hl]

jr_001_59e6:
    xor a
    ldh [$b3], a
    ldh [$b2], a
    ldh [$b4], a
    call Call_000_0153
    ldh a, [$b4]
    bit 0, a
    jr nz, jr_001_59fd

    bit 1, a
    jp nz, Jump_001_5933

    jr jr_001_59e6

jr_001_59fd:
    call Call_000_3e04
    call Call_000_03bf
    ld a, $04
    ld [$d4a9], a
    ld c, $0a
    call Call_000_3781
    ld a, [$d521]
    and a
    jp z, Jump_001_5bb7

    ld a, [$d2dd]
    cp $76
    jp nz, Jump_001_5bb7

    xor a
    ld [$d699], a
    ld hl, $d6b1
    set 2, [hl]
    call Call_001_6261
    jp Jump_001_5bb7


Call_001_5a2b:
    ld a, $01
    ld [$d2d7], a
    ld a, $03
    ld [$d2d4], a
    ret


    xor a
    ld [$d2d7], a
    ld hl, $d6ad
    set 6, [hl]
    ld hl, $6abc
    call Call_000_3c79
    call Call_000_3761
    ld hl, $5b6f
    call Call_000_3c79
    ld hl, $c470
    ld b, $06
    ld c, $0a
    call Call_000_03d2
    call Call_000_0ebd
    ld hl, $c49a
    ld de, $5bf5
    call Call_000_0405
    xor a
    ld [$cd37], a
    ld [$d6ac], a
    ld hl, $cc24
    ld a, $0c
    ld [hl+], a
    ld a, $09
    ld [hl+], a
    xor a
    ld [hl+], a
    inc hl
    ld a, $02
    ld [hl+], a
    inc a
    ld [hl+], a
    xor a
    ld [hl], a

jr_001_5a7e:
    call Call_000_3b08
    and $03
    add a
    add a
    ld b, a
    ld a, [$cc26]
    add b
    add $d0
    ld [$cc42], a
    ld [$cc43], a

jr_001_5a92:
    call Call_000_0c2e
    ld a, [$cc3d]
    ld b, a
    and $f0
    cp $d0
    jr z, jr_001_5aa9

    ld a, [$cc3e]
    ld b, a
    and $f0
    cp $d0
    jr nz, jr_001_5a92

jr_001_5aa9:
    ld a, b
    and $0c
    jr nz, jr_001_5ab7

    ld a, [$cc42]
    and $0c
    jr z, jr_001_5a7e

    jr jr_001_5acd

jr_001_5ab7:
    ld a, [$cc42]
    and $0c
    jr z, jr_001_5ac4

    ldh a, [$aa]
    cp $02
    jr z, jr_001_5acd

jr_001_5ac4:
    ld a, b
    ld [$cc42], a
    and $03
    ld [$cc26], a

jr_001_5acd:
    ldh a, [$aa]
    cp $02
    jr nz, jr_001_5add

    call Call_000_0b31
    call Call_000_0b31
    ld a, $81
    ldh [rSC], a

jr_001_5add:
    ld b, $7f
    ld c, $7f
    ld d, $ec
    ld a, [$cc42]
    and $08
    jr nz, jr_001_5af8

    ld a, [$cc26]
    cp $02
    jr z, jr_001_5af8

    ld c, d
    ld d, b
    dec a
    jr z, jr_001_5af8

    ld b, c
    ld c, d

jr_001_5af8:
    ld a, b
    ld [$c499], a
    ld a, c
    ld [$c4c1], a
    ld a, d
    ld [$c4e9], a
    ld c, $28
    call Call_000_3781
    call Call_000_376d
    ld a, [$cc42]
    and $08
    jr nz, jr_001_5b59

    ld a, [$cc26]
    cp $02
    jr z, jr_001_5b59

    xor a
    ld [$d67f], a
    ld a, [$cc26]
    and a
    ld a, $f0
    jr nz, jr_001_5b28

    ld a, $ef

jr_001_5b28:
    ld [$d6ac], a
    ld hl, $5b80
    call Call_000_3c79
    ld c, $32
    call Call_000_3781
    ld hl, $d6b1
    res 1, [hl]
    ld a, [$d059]
    ld [$d699], a
    call Call_001_6261
    ld c, $14
    call Call_000_3781
    xor a
    ld [$cc34], a

jr_001_5b4d:
    ld [$cc42], a
    inc a
    ld [$d0f0], a
    ld [$cc47], a
    jr jr_001_5bb7

jr_001_5b59:
    xor a
    ld [$cc34], a
    call Call_000_3e07
    call Call_001_754d
    ld hl, $5b97
    call Call_000_3c79
    ld hl, $d6ad
    res 6, [hl]
    ret


    db $ed
    jr z, @-$4d

    ld d, [hl]
    ret


    ld a, a
    call $c6d4
    ld c, a
    or d
    or a
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    jr z, jr_001_5b4d

    ld d, [hl]
    jp z, $ba7f

    jp c, $d8d6

    ld c, a
    ld a, [hl+]
    or c
    sbc $c5
    or d
    ld a, a
    or d
    ret nz

    cp h
    rst $08
    cp l
    ld d, a
    db $ed
    jr z, jr_001_5b9a

jr_001_5b9a:
    ld d, a
    sbc $ca
    ld a, a
    add [hl]
    xor l
    xor e
    adc l
    and [hl]
    ld a, a
    cp e
    jp c, $bccf

    ret nz

    ld d, a

Jump_001_5baa:
    ld hl, $d6b1
    res 1, [hl]
    call Call_001_5f5a
    ld c, $14
    call Call_000_3781

Jump_001_5bb7:
jr_001_5bb7:
    xor a
    ldh [$b3], a
    ldh [$b4], a
    ldh [$b5], a
    ld [$d6ac], a
    ld hl, $d6b1
    set 0, [hl]
    call Call_000_1377
    ld c, $14
    call Call_000_3781
    ld a, [$cc47]
    and a
    ret nz

    jp Jump_000_1dc3


    db $ed
    inc l
    ret


    ld b, b
    rst $10
    jp z, $d22c

    reti


    ld c, [hl]
    db $ed
    inc l
    sbc $40
    or [hl]
    rst $10
    jp z, $d22c

    reti


    ld c, [hl]
    cp [hl]
    rst $18
    jp $ddb2


    ld a, a
    or [hl]
    or h
    reti


    ld d, b
    db $ed
    inc l
    ld [$8d40], a
    xor e
    adc a
    db $e3
    ld c, [hl]
    adc c
    xor b
    adc e
    add b
    sbc a
    ld c, [hl]
    call nc, $d9d2
    ld d, b

Call_001_5c08:
    xor a
    ldh [$ba], a
    ld hl, $c430
    ld b, $08
    ld c, $0d
    call Call_000_03d2
    ld hl, $c459
    ld de, $5cbd
    call Call_000_0405
    ld hl, $c461
    ld de, $d11d
    call Call_000_0405
    ld hl, $c48a
    call Call_001_5c82
    ld hl, $c4b1
    call Call_001_5c95
    ld hl, $c4d8
    call Call_001_5ca8
    ld a, $01
    ldh [$ba], a
    ld c, $1e
    jp Jump_000_3781


    xor a
    ldh [$ba], a
    ld hl, $c3a5
    ld b, $08
    ld c, $0d
    call Call_000_03d2
    call Call_000_36ea
    call Call_000_0ebd
    ld hl, $c3ce
    ld de, $5cbd
    call Call_000_0405
    ld hl, $c3d5
    ld de, $d11d
    call Call_000_0405
    ld hl, $c3ff
    call Call_001_5c82
    ld hl, $c426
    call Call_001_5c95
    ld hl, $c44d
    call Call_001_5ca8
    ld a, $01
    ldh [$ba], a
    ld c, $1e
    jp Jump_000_3781


Call_001_5c82:
    push hl
    ld hl, $d2d5
    ld b, $01
    call Call_000_1690
    pop hl
    ld de, $d0e3
    ld bc, $0102
    jp Jump_000_3c8f


Call_001_5c95:
    push hl
    ld hl, $d27b
    ld b, $13
    call Call_000_1690
    pop hl
    ld de, $d0e3
    ld bc, $0103
    jp Jump_000_3c8f


Call_001_5ca8:
    ld de, $d97d
    ld bc, $0103
    call Call_000_3c8f
    ld [hl], $6d
    inc hl
    ld de, $d97f
    ld bc, $8102
    jp Jump_000_3c8f


    db $ed
    inc l
    db $fc
    ld b, b
    cp d
    or e
    ld c, [hl]
    db $d3
    rst $18
    jp $d9b2


    add hl, de
    xor h
    dec bc
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    cp d
    ld c, [hl]
    ld d, h
    dec l
    or [hl]
    sbc $7f
    ld a, a
    ld a, a
    ld a, a
    res 6, a
    ld c, [hl]
    ld b, d
    and a
    add c
    inc l
    or [hl]
    sbc $50

Call_001_5ce4:
    ld hl, $c3a0
    ld b, $03
    ld c, $12
    call Call_000_03d2
    ld hl, $c404
    ld b, $03
    ld c, $12
    call Call_000_03d2
    ld hl, $c468
    ld b, $03
    ld c, $12
    call Call_000_03d2
    ld hl, $c3b5
    ld de, $5e0a
    call Call_000_0405
    ld hl, $c419
    ld de, $5e26
    call Call_000_0405
    ld hl, $c47d
    ld de, $5e45
    call Call_000_0405
    ld hl, $c4e2
    ld de, $5e60
    call Call_000_0405
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    inc a
    ld [$d2d7], a
    ld [$cd40], a
    ld a, $03
    ld [$cc24], a
    call Call_001_5e91
    ld a, [$cd3d]
    ld [$cc25], a
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07

Jump_001_5d49:
jr_001_5d49:
    call Call_000_3bc6
    call Call_001_5e64

jr_001_5d4f:
    call Call_000_3879
    ldh a, [$b5]
    ld b, a
    and $fb
    jr z, jr_001_5d4f

    bit 1, b
    jr nz, jr_001_5d6c

    bit 3, b
    jr nz, jr_001_5d6c

    bit 0, b
    jr z, jr_001_5d7b

    ld a, [$cc24]
    cp $10
    jr nz, jr_001_5d49

jr_001_5d6c:
    ld a, $90
    call Call_000_0e45
    ret


Jump_001_5d72:
    ld [$cc25], a
    call Call_000_3c29
    jp Jump_001_5d49


jr_001_5d7b:
    ld a, [$cc24]
    bit 7, b
    jr nz, jr_001_5d9a

    bit 6, b
    jr nz, jr_001_5db4

    cp $08
    jr z, jr_001_5df4

    cp $0d
    jr z, jr_001_5dff

    cp $10
    jr z, jr_001_5d49

    bit 5, b
    jp nz, Jump_001_5dda

    jp Jump_001_5de5


jr_001_5d9a:
    cp $10
    ld b, $f3
    ld hl, $cd3d
    jr z, jr_001_5dcc

    ld b, $05
    cp $03
    inc hl
    jr z, jr_001_5dcc

    cp $08
    inc hl
    jr z, jr_001_5dcc

    ld b, $03
    inc hl
    jr jr_001_5dcc

jr_001_5db4:
    cp $08
    ld b, $fb
    ld hl, $cd3d
    jr z, jr_001_5dcc

    cp $0d
    inc hl
    jr z, jr_001_5dcc

    cp $10
    ld b, $fd
    inc hl
    jr z, jr_001_5dcc

    ld b, $0d
    inc hl

jr_001_5dcc:
    add b
    ld [$cc24], a
    ld a, [hl]
    ld [$cc25], a
    call Call_000_3c1c
    jp Jump_001_5d49


Jump_001_5dda:
    ld a, [$cd3d]
    cp $01
    jr z, jr_001_5dee

    sub $07
    jr jr_001_5dee

Jump_001_5de5:
    ld a, [$cd3d]
    cp $0f
    jr z, jr_001_5dee

    add $07

jr_001_5dee:
    ld [$cd3d], a
    jp Jump_001_5d72


jr_001_5df4:
    ld a, [$cd3e]
    xor $0b
    ld [$cd3e], a
    jp Jump_001_5d72


jr_001_5dff:
    ld a, [$cd3f]
    xor $0b
    ld [$cd3f], a
    jp Jump_001_5d72


    db $ed
    inc l
    ld d, $41
    ld a, a
    jp z, $bbd4

    ld c, [hl]
    ld a, a
    jp z, $b2d4

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call z, $b3c2
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or l
    cp a
    or d
    ld d, b
    db $ed
    inc l
    scf
    ld b, c
    ld a, a
    add b
    sub l
    and b
    db $e3
    adc e
    xor a
    xor e
    ld c, [hl]
    ld a, a
    inc l
    rst $18
    cp b
    ret c

    ld a, a
    ret nc

    reti


    ld a, a
    ld a, a
    call nz, $bc3a
    jp $d07f


    reti


    ld d, b
    db $ed
    inc l
    ld d, a
    ld b, c
    ld a, a
    and [hl]
    db $e3
    and [hl]
    ld c, [hl]
    ld a, a
    or d
    jp c, $b4b6

    adc a
    add c
    ld b, d
    ld a, a
    ld a, a
    or [hl]
    pop bc
    rst $00
    or a
    adc a
    add c
    ld b, d
    ld d, b
    db $ed
    inc l
    ld a, h
    ld b, c

Call_001_5e64:
    ld hl, $5edb
    ld a, [$cd3d]
    ld c, a

jr_001_5e6b:
    ld a, [hl+]
    cp c
    jr z, jr_001_5e72

    inc hl
    jr jr_001_5e6b

jr_001_5e72:
    ld a, [hl]
    ld d, a
    ld a, [$cd3e]
    dec a
    jr z, jr_001_5e7e

    set 7, d
    jr jr_001_5e80

jr_001_5e7e:
    res 7, d

jr_001_5e80:
    ld a, [$cd3f]
    dec a
    jr z, jr_001_5e8a

    set 6, d
    jr jr_001_5e8c

jr_001_5e8a:
    res 6, d

jr_001_5e8c:
    ld a, d
    ld [$d2d4], a
    ret


Call_001_5e91:
    ld hl, $5edc
    ld a, [$d2d4]
    ld c, a
    and $3f
    push bc
    ld de, $0002
    call Call_000_3ddb
    pop bc
    dec hl
    ld a, [hl]
    ld [$cd3d], a
    ld hl, $c3dc
    call Call_001_5ed4
    sla c
    ld a, $01
    jr nc, jr_001_5eb5

    ld a, $0a

jr_001_5eb5:
    ld [$cd3e], a
    ld hl, $c440
    call Call_001_5ed4
    sla c
    ld a, $01
    jr nc, jr_001_5ec6

    ld a, $0a

jr_001_5ec6:
    ld [$cd3f], a
    ld hl, $c4a4
    call Call_001_5ed4
    ld hl, $c4e0
    ld a, $01

Call_001_5ed4:
    ld e, a
    ld d, $00
    add hl, de
    ld [hl], $ec
    ret


    rrca
    dec b
    ld [$0103], sp
    ld bc, $ff08

Call_001_5ee3:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld b, $06
    ld hl, $a598

jr_001_5ef5:
    ld a, [hl+]
    cp $50
    jr z, jr_001_5f06

    dec b
    jr nz, jr_001_5ef5

    xor a
    ld [$0000], a
    ld [$6000], a
    and a
    ret


jr_001_5f06:
    xor a
    ld [$0000], a
    ld [$6000], a
    scf
    ret


Call_001_5f0f:
    ld a, [$d2d7]
    push af
    ld a, [$d2d4]
    push af
    ld a, [$d6b1]
    push af
    ld hl, $d11d
    ld bc, $0dfb
    xor a
    call Call_000_372a
    ld hl, $c100
    ld bc, $0200
    xor a
    call Call_000_372a
    pop af
    ld [$d6b1], a
    pop af
    ld [$d2d4], a
    pop af
    ld [$d2d7], a
    ld a, [$d067]
    and a
    call z, Call_001_5a2b
    ld hl, $49e4
    ld de, $d11d
    ld bc, $0006
    call Call_000_01bb
    ld hl, $49e9
    ld de, $d2ce
    ld bc, $0006
    jp Jump_000_01bb


Call_001_5f5a:
    ld a, $ff
    call Call_000_0e45
    ld a, $02
    ld c, a
    ld a, $ef
    call Call_000_0e35
    call Call_000_03bf
    call Call_000_36ea
    call Call_001_5f0f
    ld a, $18
    call Call_000_3e9d
    ld hl, $d4b9
    ld a, $14
    ld [$cf78], a
    ld a, $01
    ld [$cf7d], a
    call Call_000_16e0
    ld a, [$d059]
    ld [$d699], a
    call Call_001_6261
    xor a
    ldh [$d7], a
    ld a, [$d6b1]
    bit 1, a
    jp nz, Jump_001_6001

    ld de, $615f
    ld bc, $1300
    call Call_001_6237
    call Call_001_6204
    ld hl, $6098
    call Call_000_3c79
    call Call_000_0b5a
    call Call_000_03bf
    ld a, $a7
    ld [$d092], a
    ld [$cf78], a
    call Call_000_2f2e
    ld hl, $c3f6
    call Call_000_2d7a
    call Call_001_621b
    ld hl, $60df
    call Call_000_3c79
    call Call_000_0b5a
    call Call_000_03bf
    ld de, $5941
    ld bc, $0400
    call Call_001_6237
    call Call_001_621b
    ld hl, $6164
    call Call_000_3c79
    call Call_001_68da
    call Call_000_0b5a
    call Call_000_03bf
    ld de, $6049
    ld bc, $1300
    call Call_001_6237
    call Call_001_6204
    ld hl, $6181
    call Call_000_3c79
    call Call_001_692e

Jump_001_6001:
    call Call_000_0b5a
    call Call_000_03bf
    ld de, $5941
    ld bc, $0400
    call Call_001_6237
    call Call_000_0b78
    ld a, [$d6ac]
    and a
    jr nz, jr_001_601f

    ld hl, $61be
    call Call_000_3c79

jr_001_601f:
    ldh a, [$b8]
    push af
    ld a, $9c
    call Call_000_0e45
    pop af
    ldh [$b8], a
    ld [$2000], a
    ld c, $04
    call Call_000_3781
    ld de, $4180
    ld hl, $8000
    ld bc, $050c
    call Call_000_02dd
    ld de, $5a4b
    ld bc, $0400
    call Call_001_6237
    ld c, $04
    call Call_000_3781
    ld de, $5aa5
    ld bc, $0400
    call Call_001_6237
    call Call_000_1377
    ldh a, [$b8]
    push af
    ld a, $02
    ld [$c0ef], a
    ld [$c0f0], a
    ld a, $0a
    ld [$cfae], a
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    pop af
    ldh [$b8], a
    ld [$2000], a
    ld c, $14
    call Call_000_3781
    ld hl, $c40a
    ld b, $07
    ld c, $07
    call Call_000_0374
    call Call_000_36ea
    ld a, $01
    ld [$cfb2], a
    ld c, $32
    call Call_000_3781
    call Call_000_0b5a
    jp Jump_000_03bf


    db $ed
    jr z, @+$29

    ld d, a
    rst $08
    cp h
    jp Jump_001_4fe7


    ld b, e

jr_001_60a2:
    adc b
    xor h
    sub e
    ld a, a
    and c
    xor e
    adc h
    adc a
    db $e3
    ret


    ld a, a
    cp [hl]
    or [hl]
    or d
    call $d655
    or e
    cp d
    cp a
    rst $20
    ld d, c
    call c, $bcc0
    ret


    ld a, a
    push bc
    rst $08
    or h
    jp z, $847f

    db $e3
    add [hl]
    inc de
    ld c, a
    ret nc

    sbc $c5
    or [hl]
    rst $10
    jp z, Jump_001_547f

    ld a, a
    jp z, $beb6

    call nz, $bc55
    ret nz

    call c, $c3da
    ld a, a
    or l
    reti


    sub $58
    db $ed
    jr z, jr_001_60a2

    ld d, a
    cp [hl]
    or [hl]
    or d
    add $ca
    ld c, a
    ld b, e
    adc b
    xor h
    sub e
    ld a, a
    and c
    xor e
    adc h
    adc a
    db $e3
    call nz, $d67f
    ld a, [hl-]
    jp c, $51d9

    or d
    or a
    db $d3
    ret


    ld a, a
    ret nz

    pop bc
    ld h, $4f
    or d
    ret nz

    reti


    call nz, $dbba
    add $7f
    cp l
    sbc $33
    or d
    reti


    rst $20
    ld d, b
    inc d
    nop
    ld d, c
    cp a
    ret


    ld a, a
    ld d, h
    ld a, a
    call nz, $b3b2
    ld a, a
    or d
    or a
    db $d3
    ret


    db $dd
    ld c, a
    set 0, h
    jp z, $477f

    xor h
    sub e
    add $7f
    cp h
    ret nz

    ret c

    ld d, l
    cp h
    ld [c], a
    or e
    inc a
    add $7f
    jp nz, $dfb6

    ret nz

    ret c

    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld d, c
    cp a
    cp h
    jp Jump_001_7474


    ld [hl], h

jr_001_6146:
    ld d, c
    call c, $bcc0
    jp z, $ba7f

    ret


    ld a, a
    ld d, h
    ret


    ld c, a
    cp c
    sbc $b7
    pop hl
    or e
    db $dd
    ld a, a
    cp h
    jp Jump_001_7fd9


    call nz, $b3b2
    call c, Call_000_30b9
    ld e, b
    db $ed
    jr z, @-$5e

    ld e, b
    jp z, $d22c

    add $7f
    or a
    ret nc

    ret


    ld a, a
    push bc
    rst $08
    or h
    db $dd
    ld c, a
    or l
    cp h
    or h
    jp $d37f


    rst $10
    or l
    or e
    rst $20
    ld e, b
    db $ed
    jr z, jr_001_6146

    ld e, b
    jp z, $dc7f

    ret nz

    cp h
    ret


    ld a, a
    rst $08
    ld a, [hl+]
    ld c, a
    or a
    ret nc

    ret


    ld a, a
    or l
    cp e
    push bc
    push bc
    inc l
    ret nc

    inc sp
    or c
    ret c

    ld d, l
    and l
    add c
    add hl, de
    and [hl]
    ld a, a
    inc sp
    or c
    reti


    ld d, c
    ld [hl], h
    ld [hl], h
    ld [hl], h
    or h
    db $e3
    call nz, Call_001_4fe6
    push bc
    rst $08
    or h
    jp z, $c57f

    sbc $c3
    ld a, a
    or d
    rst $18
    ret nz

    or [hl]
    push bc
    and $58
    db $ed
    jr z, jr_001_61f1

    ld e, c
    or d
    sub $b2

jr_001_61c5:
    sub $7f
    cp d
    jp c, $d7b6

    ld a, a
    ld c, a
    or a
    ret nc

    ret


    ld a, a
    db $d3
    ret


    ld h, $c0
    ret c

    ret


    ld a, a
    jp z, $cf2c

    ret c

    jr nc, jr_001_61c5

    ld d, c
    push de
    jp nc, Jump_001_7fc4

    ld a, $b3
    cp c
    sbc $c4
    rst $20
    ld c, a
    ld b, e
    adc b
    xor h
    sub e
    ld a, a
    and c
    xor e

jr_001_61f1:
    adc h
    adc a
    db $e3
    ret


    ld a, a
    cp [hl]
    or [hl]
    or d
    call Call_001_55e7
    and a
    xor h
    sub c
    ld a, a
    add hl, bc
    db $e3
    rst $20
    ld d, a

Call_001_6204:
    ld hl, $6215
    ld b, $06

jr_001_6209:
    ld a, [hl+]
    ldh [rBGP], a
    ld c, $0a
    call Call_000_3781
    dec b
    jr nz, jr_001_6209

    ret


    ld d, h
    xor b
    db $fc
    ld hl, sp-$0c
    db $e4

Call_001_621b:
    ld a, $77
    ldh [rWX], a
    call Call_000_0b31
    ld a, $e4
    ldh [rBGP], a

jr_001_6226:
    call Call_000_0b31
    ldh a, [rWX]
    sub $08
    cp $ff
    ret z

    ldh [rWX], a
    jr jr_001_6226

    call Call_000_3ec4

Call_001_6237:
    push bc
    ld a, b
    call Call_000_3735
    ld hl, $a188
    ld de, $a000
    ld bc, $0310
    call Call_000_01bb
    ld de, $9000
    call Call_000_30b9
    pop bc
    ld a, c
    and a
    ld hl, $c3c3
    jr nz, jr_001_6259

    ld hl, $c3f6

jr_001_6259:
    xor a
    ldh [$e1], a
    ld a, $01
    jp Jump_000_3e9d


Call_001_6261:
    call Call_001_6292
    ld a, $19
    call Call_000_3e9d
    ld hl, $d6b1
    bit 2, [hl]
    res 2, [hl]
    jr z, jr_001_6277

    ld a, [$d699]
    jr jr_001_6280

jr_001_6277:
    bit 1, [hl]
    jr z, jr_001_627e

    call Call_001_6479

jr_001_627e:
    ld a, $00

jr_001_6280:
    ld b, a
    ld a, [$d6ac]
    and a
    jr nz, jr_001_6288

    ld a, b

jr_001_6288:
    ld hl, $d6b1
    bit 4, [hl]
    ret nz

    ld [$d2e4], a
    ret


Call_001_6292:
    ld a, [$d6ac]
    cp $ef
    jr nz, jr_001_62a7

    ld hl, $63bb
    ldh a, [$aa]
    cp $02
    jr z, jr_001_62c7

    ld hl, $63c3
    jr jr_001_62c7

jr_001_62a7:
    cp $f0
    jr nz, jr_001_62b9

    ld hl, $63cb
    ldh a, [$aa]
    cp $02
    jr z, jr_001_62c7

    ld hl, $63d3
    jr jr_001_62c7

jr_001_62b9:
    ld a, [$d6b1]
    bit 1, a
    jr nz, jr_001_62d9

    bit 2, a
    jr nz, jr_001_62d9

    ld hl, $63b3

jr_001_62c7:
    ld de, $d2dd
    ld c, $07

jr_001_62cc:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_001_62cc

    ld a, [hl+]
    ld [$d2e6], a
    xor a
    jr jr_001_6346

jr_001_62d9:
    ld a, [$d2e4]
    ld hl, $d6b1
    bit 4, [hl]
    jr nz, jr_001_62ee

    bit 6, [hl]
    res 6, [hl]
    jr z, jr_001_6321

    ld a, [$d698]
    jr jr_001_6324

jr_001_62ee:
    ld hl, $d6ac
    res 4, [hl]
    ld a, [$d69c]
    ld b, a
    ld [$d2dd], a
    ld a, [$d69d]
    ld c, a
    ld hl, $6352
    ld de, $0000
    ld a, $06
    ld [$d0f4], a

jr_001_6309:
    ld a, [hl+]
    cp b
    jr z, jr_001_6310

    inc hl
    jr jr_001_6314

jr_001_6310:
    ld a, [hl+]
    cp c
    jr z, jr_001_631b

jr_001_6314:
    ld a, [$d0f4]
    add e
    ld e, a
    jr jr_001_6309

jr_001_631b:
    ld hl, $636b
    add hl, de
    jr jr_001_6337

jr_001_6321:
    ld a, [$d699]

jr_001_6324:
    ld b, a
    ld [$d2dd], a
    ld hl, $63db

jr_001_632b:
    ld a, [hl+]
    inc hl
    cp b
    jr z, jr_001_6334

    inc hl
    inc hl
    jr jr_001_632b

jr_001_6334:
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_001_6337:
    ld de, $d2de
    ld c, $06

jr_001_633c:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_001_633c

    xor a
    ld [$d2e6], a

jr_001_6346:
    ld [$d461], a
    ld [$d462], a
    ld a, $ff
    ld [$d3ae], a
    ret


    sbc a
    ld bc, $029f
    and b
    ld bc, $02a0
    and c
    ld bc, $02a1
    and d
    ld bc, $02a2
    jp nz, $a502

    ld bc, $02a5
    sub $03
    rst $38
    ld b, [hl]
    rst $00
    rlca
    ld [de], a
    ld bc, $4800
    rst $00
    rlca
    rla
    ld bc, $4601
    rst $00
    rlca
    inc de
    ld bc, $4801
    rst $00
    rlca
    ld d, $01
    nop
    ld b, [hl]
    rst $00
    rlca
    ld [de], a
    ld bc, $4600
    rst $00
    rlca
    inc de
    ld bc, $9301
    rst $00
    ld c, $04
    nop
    nop
    sub e
    rst $00
    ld c, $05
    nop
    ld bc, $c7b1
    db $10
    ld d, $00
    nop
    sbc c
    rst $00
    ld c, $10
    nop
    nop
    sbc c
    rst $00
    ld c, $10
    nop
    nop
    sbc d
    rst $00
    ld c, $12
    nop
    nop
    ld h, $12
    rst $00
    ld b, $03
    nop
    ld bc, $ef04
    dec bc
    rst $00
    inc b
    inc bc
    nop
    ld bc, $ef15
    dec c
    rst $00
    inc b
    ld b, $00
    nop
    dec d
    ldh a, [$0b]
    rst $00
    inc b
    inc bc
    nop
    ld bc, $f015
    dec c

Call_001_63d5:
    rst $00
    inc b
    ld b, $00
    nop
    dec d
    nop
    nop
    rrca
    ld h, h
    ld bc, $1500
    ld h, h
    ld [bc], a
    nop
    dec de
    ld h, h
    inc bc
    nop
    ld hl, $0464
    nop
    daa
    ld h, h
    dec b
    nop
    dec l
    ld h, h
    ld b, $00
    inc sp
    ld h, h
    rlca
    nop
    add hl, sp
    ld h, h
    ld [$3f00], sp
    ld h, h
    add hl, bc
    nop
    ld b, l
    ld h, h
    ld a, [bc]
    nop
    ld c, e
    ld h, h
    rrca
    nop
    ld d, c
    ld h, h
    dec d
    nop
    ld d, a
    ld h, h
    dec hl
    rst $00
    ld b, $05
    nop
    ld bc, $c860
    ld a, [de]
    rla
    nop
    ld bc, $c85b
    ld a, [de]
    dec c
    nop
    ld bc, $c7f6
    ld [de], a
    inc de
    nop
    ld bc, $c72a
    ld b, $03
    nop
    ld bc, $c73c
    inc b
    dec bc
    nop
    ld bc, $c7b7
    ld a, [bc]
    add hl, hl
    nop
    ld bc, $c878
    inc e
    inc de
    nop
    ld bc, $c75e
    inc c
    dec bc
    nop
    ld bc, $c72d
    ld b, $09
    nop
    ld bc, $c88d
    ld e, $09
    nop
    ld bc, $c7ba
    ld b, $0b
    nop
    ld bc, $c79e
    inc d
    dec bc
    nop
    ld bc, $7211
    ld h, h

jr_001_6460:
    ld a, [de]
    cp $ff
    ret z

    ld [$cf78], a
    inc de
    ld a, [de]
    ld [$d0ec], a
    inc de
    call Call_000_3971
    jr jr_001_6460

    ld a, [bc]
    ld e, d
    ld l, h
    ld e, d
    ld bc, $ff05

Call_001_6479:
    ret


    call Call_000_3761
    call Call_000_3ec4
    push hl
    ld a, [$d034]
    dec a
    ld hl, $c3a1
    ld b, $04
    ld c, $0a
    call z, Call_000_0374
    ld a, [$cf78]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $64e6
    call Call_000_3c79
    ld hl, $c43a
    ld bc, $080f
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    pop hl
    ld a, [$cc26]
    and a
    jr nz, jr_001_64db

    ld a, [$cfb2]
    push af
    xor a
    ld [$cfb2], a
    push hl
    ld a, $02
    ld [$d05a], a
    call Call_001_6535
    ld a, [$d034]
    and a
    jr nz, jr_001_64cd

    call Call_000_3e38

jr_001_64cd:
    call Call_000_376d
    pop hl
    pop af
    ld [$cfb2], a
    ld a, [$cf45]
    cp $50
    ret nz

jr_001_64db:
    ld d, h
    ld e, l
    ld hl, $cd68
    ld bc, $0006
    jp Jump_000_01bb


    db $ed
    jr z, @-$70

    ld e, c
    add $4f
    sub l
    xor h
    add a
    sub a
    db $e3
    sbc a
    db $dd
    ld a, a
    jp nz, $cfb9

    cp l
    or [hl]
    and $57
    ld hl, $cee4
    xor a
    ld [$cfb2], a
    ld a, $02
    ld [$d05a], a
    call Call_001_6535
    call Call_000_3e04
    call Call_000_3dee
    call Call_000_0b3c
    ld a, [$cf45]
    cp $50
    jr z, jr_001_6533

    ld hl, $d257
    ld bc, $0006
    ld a, [$cf79]
    call Call_000_3ad1
    ld e, l
    ld d, h
    ld hl, $cee4
    ld bc, $0006
    call Call_000_01bb
    and a
    ret


jr_001_6533:
    scf
    ret


Call_001_6535:
    push hl
    ld hl, $d6af
    set 6, [hl]
    call Call_000_3e04
    call Call_000_03bf
    call Call_000_0ebd
    ld b, $08
    call Call_000_3e1f
    call Call_000_370a
    call Call_001_66ec
    ld b, $1c
    ld hl, $5c30
    call Call_000_3620
    ld hl, $c3f0
    ld b, $0b
    ld c, $12
    call Call_000_03d2
    call Call_001_687a
    ld a, $03
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    ld [$cc2a], a
    ld [$cc26], a
    ld a, $ff
    ld [$cc29], a
    ld a, $08
    ld [$cc28], a
    ld a, $50
    ld [$cf45], a
    xor a
    ld hl, $cee5
    ld [hl+], a
    ld [hl+], a
    ld [$d068], a
    call $6700
    call Call_000_3e0c
    ld a, [$cee5]
    and a
    jr nz, jr_001_65cc

    call Call_001_67b1
    call Call_000_3bc6

jr_001_659e:
    ld a, [$cc26]
    push af
    ld b, $1c
    ld hl, $5bbb
    call Call_000_3620
    pop af
    ld [$cc26], a
    call Call_000_3879
    ldh a, [$b3]
    and a
    jr z, jr_001_659e

    ld hl, $65fd

jr_001_65b9:
    sla a
    jr c, jr_001_65c3

    inc hl
    inc hl
    inc hl
    inc hl
    jr jr_001_65b9

jr_001_65c3:
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    push de
    jp hl


jr_001_65cc:
    pop de
    ld hl, $cf45
    ld bc, $0006
    call Call_000_01bb
    call Call_000_3e04
    call Call_000_03bf
    call Call_000_0188
    call Call_000_3e1d
    call Call_000_3e0c
    xor a
    ld [$d068], a
    ld hl, $d6af
    res 6, [hl]
    ld a, [$d034]
    and a
    jp z, Jump_000_36ea

    ld hl, $714c
    ld b, $0f
    jp Jump_000_3620


    sbc e
    ld h, l
    rst $08
    ld h, [hl]
    sbc e
    ld h, l
    cp l
    ld h, [hl]
    sbc e
    ld h, l
    xor c
    ld h, [hl]
    sbc e
    ld h, l
    sub e
    ld h, [hl]
    sub d
    ld h, l
    dec hl
    ld h, [hl]
    adc h
    ld h, l
    ld [hl+], a
    ld h, [hl]
    sub d
    ld h, l
    add a
    ld h, [hl]
    sub d
    ld h, l
    ld sp, $d166
    ld de, $658c
    push de
    ld a, [$cee6]
    xor $01
    ld [$cee6], a
    ret


jr_001_662b:
    ld a, $01
    ld [$cee5], a
    ret


    ld a, [$cc26]
    cp $06
    jr nz, jr_001_663f

    ld a, [$cc25]
    cp $11
    jr z, jr_001_662b

jr_001_663f:
    ld a, [$cc26]
    cp $07
    jr nz, jr_001_664d

    ld a, [$cc25]
    cp $01
    jr z, @-$2e

jr_001_664d:
    ld hl, $cc30
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    inc hl
    ld a, [hl]
    ld [$cee8], a
    call Call_001_686d
    ld a, [$cee8]
    cp $e5
    ld de, $6807
    jr z, jr_001_6674

    cp $e4
    ld de, $6858
    jr z, jr_001_6674

    ld a, [$cee4]
    cp $05
    jr c, jr_001_667b

    ret


jr_001_6674:
    push hl
    call Call_001_67f3
    pop hl
    ret nc

    dec hl

jr_001_667b:
    ld a, [$cee8]
    ld [hl+], a
    ld [hl], $50
    ld a, $90
    call Call_000_0e45
    ret


    ld a, [$cee4]
    and a
    ret z

    call Call_001_686d
    dec hl
    ld [hl], $50
    ret


    ld a, [$cc26]
    cp $07
    ret z

    ld a, [$cc25]
    cp $11
    jp z, Jump_001_66a5

    inc a
    inc a
    jr jr_001_66e6

Jump_001_66a5:
    ld a, $01
    jr jr_001_66e6

    ld a, [$cc26]
    cp $07
    ret z

    ld a, [$cc25]
    dec a
    jp z, Jump_001_66b9

    dec a
    jr jr_001_66e6

Jump_001_66b9:
    ld a, $11
    jr jr_001_66e6

    ld a, [$cc26]
    dec a
    ld [$cc26], a
    and a
    ret nz

    ld a, $07
    ld [$cc26], a
    ld a, $01
    jr jr_001_66e6

    ld a, [$cc26]
    inc a
    ld [$cc26], a
    cp $08
    jr nz, jr_001_66e1

    ld a, $01
    ld [$cc26], a
    jr jr_001_66e6

jr_001_66e1:
    cp $07
    ret nz

    ld a, $01

jr_001_66e6:
    ld [$cc25], a
    jp Jump_000_3c29


Call_001_66ec:
    ld de, $66f8
    ld hl, $8f00
    ld bc, $0001
    jp Jump_000_031b


    ldh a, [$c0]
    ldh a, [$ce]
    db $fd
    dec c
    dec c
    ld c, $af
    ldh [$ba], a
    ld a, [$cee6]
    and a
    ld de, $6738
    jr nz, jr_001_670f

    ld de, $6771

jr_001_670f:
    ld hl, $c406
    ld bc, $0609

jr_001_6715:
    push bc

jr_001_6716:
    ld a, [de]
    ld [hl+], a
    inc hl
    inc de
    dec c
    jr nz, jr_001_6716

    ld bc, $0016
    add hl, bc
    pop bc
    dec b
    jr nz, jr_001_6715

    call Call_000_0405
    ld hl, $c4f9
    ld de, $67aa
    call Call_000_0405
    ld a, $01
    ldh [$ba], a
    jp Jump_000_3e07


    and c
    and d
    and e
    and h
    and l
    and [hl]
    and a
    xor b
    xor c
    xor d
    xor e
    xor h
    xor l
    xor [hl]
    xor a
    or b
    or c
    or d
    or e
    or h
    or l
    or [hl]
    or a
    cp b
    cp c
    cp d
    ld a, a
    pop bc
    jp nz, $c4c3

    push bc
    add $c7
    ret z

    ret


    jp z, $cccb

    call $cfce
    ret nc

    pop de
    jp nc, $d4d3

    push de
    sub $d7
    ret c

    reti


    jp c, $b0f0

    sub c
    ld d, b
    and c
    and d
    and e
    and h
    and l
    and [hl]
    and a
    xor b
    xor c
    xor d
    xor e
    xor h
    xor l
    xor [hl]
    xor a
    or b
    or c
    or d
    or e
    or h
    or l
    or [hl]
    or a
    cp b
    cp c
    cp d
    ld a, a
    pop bc
    jp nz, $c4c3

    push bc
    add $c7
    ret z

    ret


    jp z, $cccb

    call $cfce
    ret nc

    pop de
    jp nc, $d4d3

    push de
    sub $d7
    ret c

    reti


    jp c, $b0f0

    sub d
    ld d, b
    db $ed
    inc l
    add b
    ld b, c
    ld [c], a
    cp b
    ld d, b

Call_001_67b1:
    call Call_001_686d
    ld a, c
    ld [$cee4], a
    ld hl, $c3c1
    ld bc, $0205
    call Call_000_0374
    ld hl, $c3d5
    ld de, $cf45

jr_001_67c7:
    call Call_000_0405
    ld hl, $c3e9
    ld a, $76
    ld b, $05

jr_001_67d1:
    ld [hl+], a
    dec b
    jr nz, jr_001_67d1

    ld a, [$cee4]
    cp $05
    jr nz, jr_001_67eb

    call Call_000_3c29

jr_001_67df:
    ld a, $11
    ld [$cc25], a
    ld a, $06
    ld [$cc26], a
    ld a, $04

jr_001_67eb:
    ld hl, $c3e9
    add l
    ld l, a
    ld [hl], $77
    ret


Call_001_67f3:
    push de
    call Call_001_686d
    dec hl
    ld a, [hl]
    pop hl
    ld de, $0002
    call Call_000_3ddb
    ret nc

    inc hl
    ld a, [hl]
    ld [$cee8], a
    ret


    or [hl]
    ld h, $b7
    daa
    cp b
    jr z, jr_001_67c7

    add hl, hl
    cp d
    ld a, [hl+]
    cp e
    dec hl
    cp h
    inc l
    cp l
    dec l
    cp [hl]
    ld l, $bf
    cpl
    ret nz

    jr nc, jr_001_67df

    ld sp, $32c2
    jp $c433


    inc [hl]
    jp z, $cb3a

    dec sp
    call z, $cd3c
    dec a
    adc $3e
    add l
    dec b
    add [hl]
    ld b, $87
    rlca
    adc b
    ld [$0989], sp
    adc d
    ld a, [bc]
    adc e
    dec bc
    adc h
    inc c
    adc l
    dec c
    adc [hl]
    ld c, $8f
    rrca
    sub b
    db $10
    sub c
    ld de, $1292
    sub e
    inc de
    sbc c
    add hl, de
    sbc d
    ld a, [de]
    sbc e
    dec de
    call $9c3d
    inc e
    rst $38
    jp z, $cb44

    ld b, l
    call z, $cd46
    ld b, a
    adc $48
    sbc c
    ld b, b
    sbc d
    ld b, c
    sbc e
    ld b, d
    call $9c47
    ld b, e
    rst $38

Call_001_686d:
    ld hl, $cf45
    ld c, $00

jr_001_6872:
    ld a, [hl]
    cp $50
    ret z

    inc hl
    inc c
    jr jr_001_6872

Call_001_687a:
    ld hl, $c3c9
    ld a, [$d05a]
    ld de, $68c1
    and a
    jr z, jr_001_68b6

    ld de, $68c5
    dec a
    jr z, jr_001_68b6

    ld a, [$cf78]
    ld [$cd58], a
    push af
    ld b, $1c
    ld hl, $5d46
    call Call_000_3620
    pop af
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $c3b8
    call Call_000_0405
    ld hl, $0001
    add hl, bc
    ld [hl], $c9
    ld hl, $c3e0
    ld de, $68d1
    jr jr_001_68be

jr_001_68b6:
    call Call_000_0405
    ld l, c
    ld h, b
    ld de, $68ca

jr_001_68be:
    jp Jump_000_0405


    db $ed
    inc l
    rst $08
    ld h, e
    db $ed
    inc l

jr_001_68c7:
    rst $10
    ld h, e
    ld d, b
    db $ed
    inc l
    sub b
    ld b, c
    jp z, $50e6

    db $ed
    inc l
    add [hl]
    ld b, c
    db $e3
    sbc a
    jp z, $50e6

Call_001_68da:
    call Call_001_69b4
    ld de, $6a4c
    call Call_001_6a0e
    ld a, [$cc26]
    and a
    jr z, jr_001_68f7

    ld hl, $6a92
    call Call_001_6a76
    ld de, $d11d
    call Call_001_698e
    jr jr_001_6916

jr_001_68f7:
    ld hl, $d11d
    xor a
    ld [$d05a], a
    call Call_001_6535
    ld a, [$cf45]
    cp $50
    jr z, jr_001_68f7

    call Call_000_03bf
    call Call_000_3e07
    ld de, $5941
    ld b, $04
    call Call_001_6237

jr_001_6916:
    ld hl, $691c
    jp Jump_000_3c79


    db $ed
    jr z, jr_001_68c7

    ld e, c
    ld [hl], h
    ld [hl], h
    ld c, a
    ld d, d
    ld a, a
    call nz, $b27f
    or e
    sbc $30
    push bc
    rst $20
    ld e, b

Call_001_692e:
    call Call_001_69b4
    ld de, $6a61
    call Call_001_6a0e
    ld a, [$cc26]
    and a
    jr z, jr_001_694b

    ld hl, $6aa7
    call Call_001_6a76
    ld de, $d2ce
    call Call_001_698e
    jr jr_001_696b

jr_001_694b:
    ld hl, $d2ce
    ld a, $01
    ld [$d05a], a
    call Call_001_6535
    ld a, [$cf45]
    cp $50
    jr z, jr_001_694b

    call Call_000_03bf
    call Call_000_3e07
    ld de, $6049
    ld b, $13
    call Call_001_6237

jr_001_696b:
    ld hl, $6971
    jp Jump_000_3c79


    db $ed
    jr z, @-$43

    ld e, c
    ld a, a
    cp a
    or e
    jr nc, @-$17

    ld a, a
    or l
    db $d3
    or d
    jr nc, @-$42

    ret nz

    cpl
    ld c, a
    ld d, e
    ld a, a
    call nz, $b3b2
    ld a, a
    push bc
    rst $08
    or h
    jr nc, jr_001_69e6

Call_001_698e:
    push de
    ld hl, $c3a0
    ld bc, $0c0b
    call Call_000_0374
    ld c, $0a
    call Call_000_3781
    pop de
    ld hl, $cd68
    ld bc, $0006
    call Call_000_01bb
    call Call_000_3e07
    ld hl, $c3fc
    ld de, $067d
    ld a, $ff
    jr jr_001_69bb

Call_001_69b4:
    ld hl, $c3f5
    ld de, $067d
    xor a

jr_001_69bb:
    push hl
    push de
    push bc
    ldh [$8d], a
    ld a, d
    ldh [$8b], a
    ld a, e
    ldh [$8c], a
    ld c, a
    ldh a, [$8d]
    and a
    jr nz, jr_001_69cf

    ld d, $00
    add hl, de

jr_001_69cf:
    ld d, h
    ld e, l

jr_001_69d1:
    xor a
    ldh [$ba], a
    ldh a, [$8d]
    and a
    jr nz, jr_001_69de

    ld a, [hl+]
    ld [hl-], a
    dec hl
    jr jr_001_69e1

jr_001_69de:
    ld a, [hl-]
    ld [hl+], a
    inc hl

jr_001_69e1:
    dec c
    jr nz, jr_001_69d1

    ldh a, [$8d]

jr_001_69e6:
    and a
    jr z, jr_001_69ec

    xor a
    dec hl
    ld [hl], a

jr_001_69ec:
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    ldh a, [$8c]
    ld c, a
    ld h, d
    ld l, e
    ldh a, [$8d]
    and a
    jr nz, jr_001_6a00

    inc hl
    jr jr_001_6a01

jr_001_6a00:
    dec hl

jr_001_6a01:
    ld d, h
    ld e, l
    ldh a, [$8b]
    dec a
    ldh [$8b], a
    jr nz, jr_001_69d1

    pop bc
    pop de
    pop hl
    ret


Call_001_6a0e:
    push de
    ld hl, $c3a0
    ld b, $0a
    ld c, $09
    call Call_000_03d2
    ld hl, $c3a3
    ld de, $6a45
    call Call_000_0405
    pop de
    ld hl, $c3ca
    call Call_000_0405
    call Call_000_0ebd
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    inc a
    ld [$cc25], a
    ld [$cc29], a
    inc a
    ld [$cc24], a
    inc a
    ld [$cc28], a
    jp Jump_000_3b08


    db $ed
    inc l
    sub [hl]
    ld b, c
    or e
    adc $50
    db $ed
    inc l
    and l
    ld h, e
    or a
    jp nc, $4ed9

    rlca
    ret c

    db $e3
    xor e
    ld c, [hl]
    adc e
    ld [$4ea6], sp
    dec bc
    xor a
    xor e
    ld d, b
    db $ed
    inc l
    cp d
    ld h, e
    or a
    jp nc, $4ed9

    and a
    xor h
    inc de
    ld c, [hl]
    adc d
    sub e
    adc e
    ld c, [hl]
    dec bc
    xor l
    xor h
    add a
    ld d, b

Call_001_6a76:
    ld b, a
    ld c, $00

jr_001_6a79:
    ld d, h
    ld e, l

jr_001_6a7b:
    ld a, [hl+]
    cp $50
    jr nz, jr_001_6a7b

    ld a, b
    cp c
    jr z, jr_001_6a87

    inc c
    jr jr_001_6a79

jr_001_6a87:
    ld h, d
    ld l, e
    ld de, $cd68
    ld bc, $0014
    jp Jump_000_01bb


    and h
    and l
    and [hl]
    xor c
    xor [hl]
    and l
    ld d, b
    and a
    or d
    and l
    and l
    xor [hl]
    ld d, b
    or h
    xor a
    xor l
    ld d, b
    xor e
    and l
    xor [hl]
    ld d, b
    and h
    and l
    and [hl]
    xor c
    xor [hl]
    and l
    ld d, b
    or d
    and l
    and h
    ld d, b
    or d
    xor a
    xor e
    cp c
    ld d, b
    xor d
    and c
    and e
    xor e
    ld d, b
    ld d, b
    ld de, $d2cb
    ld hl, $ff9f
    ld c, $03
    call Call_000_3ad8
    ret c

    ld de, $d2cd
    ld hl, $ffa1
    ld c, $03
    ld a, $0c
    call Call_000_3e9d
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    and a
    ret


    ld a, [$cf7b]
    cp $03
    jp c, Jump_000_1765

    push hl
    ld hl, $cf72
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    inc hl
    ld a, [$cc26]
    ld b, a
    ld a, [$cc36]
    add b
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    pop hl
    inc a
    jp z, Jump_000_1765

    ld a, [$cc35]
    and a
    jr nz, jr_001_6b1d

    ld a, [$cc26]
    inc a
    ld b, a
    ld a, [$cc36]
    add b
    ld [$cc35], a
    ld c, $14
    call Call_000_3781
    jp Jump_000_1765


jr_001_6b1d:
    ld a, [$cc26]
    inc a
    ld b, a
    ld a, [$cc36]
    add b
    ld b, a
    ld a, [$cc35]
    cp b
    jp z, Jump_000_1765

    dec a
    ld [$cc35], a
    ld c, $14
    call Call_000_3781
    push hl
    push de
    ld hl, $cf72
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    inc hl
    ld d, h
    ld e, l
    ld a, [$cc26]
    ld b, a
    ld a, [$cc36]
    add b
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [$cc35]
    add a
    add e
    ld e, a
    jr nc, jr_001_6b58

    inc d

jr_001_6b58:
    ld a, [de]
    ld b, a
    ld a, [hl+]
    cp b
    jr z, jr_001_6b78

    ldh [$95], a
    ld a, [hl-]
    ldh [$96], a
    ld a, [de]
    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl], a
    ldh a, [$96]
    ld [de], a
    dec de
    ldh a, [$95]
    ld [de], a
    xor a
    ld [$cc35], a
    pop de
    pop hl
    jp Jump_000_1765


jr_001_6b78:
    inc de
    ld a, [hl]
    ld b, a
    ld a, [de]
    add b
    cp $64
    jr c, jr_001_6b89

    sub $63
    ld [de], a
    ld a, $63
    ld [hl], a
    jr jr_001_6bb3

jr_001_6b89:
    ld [hl], a
    ld hl, $cf72
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    dec [hl]
    ld a, [hl]
    ld [$d0ef], a
    cp $01
    jr nz, jr_001_6b9c

    ld [$cc28], a

jr_001_6b9c:
    dec de
    ld h, d
    ld l, e
    inc hl
    inc hl

jr_001_6ba1:
    ld a, [hl+]
    ld [de], a
    inc de
    inc a
    jr z, jr_001_6bac

    ld a, [hl+]
    ld [de], a
    inc de
    jr jr_001_6ba1

jr_001_6bac:
    xor a
    ld [$cc36], a
    ld [$cc26], a

jr_001_6bb3:
    xor a
    ld [$cc35], a
    pop de
    pop hl
    jp Jump_000_1765


    ld a, [$cc36]
    push af
    call Call_000_0ebd
    xor a
    ld [$cf05], a

Jump_001_6bc7:
    xor a
    ld [$cc36], a
    ld [$cc26], a
    ld [$cc2f], a
    inc a
    ld [$cf7a], a
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    ld a, $15
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $d0ed
    ld a, [hl+]
    ld l, [hl]
    ld h, a
    ld a, [$d0f3]
    cp $02
    jp z, Jump_001_6d8e

    ld a, [$d0f2]
    and a
    jp z, Jump_001_6cb5

    dec a
    jp z, Jump_001_6c02

    dec a
    jp z, Jump_001_6d8e

Jump_001_6c02:
    xor a
    ld [$cf7a], a
    ld a, $02
    ld [$d0e0], a
    ld hl, $5ead
    ld b, $0e
    call Call_000_3620
    ld a, [$d2a1]
    and a
    jp z, Jump_001_6cac

    ld hl, $6e17
    call Call_000_3c79
    call Call_000_3761

Jump_001_6c23:
jr_001_6c23:
    call Call_000_376d
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $d2a1
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    xor a
    ld [$cf7a], a
    ld [$cc26], a
    ld a, $03
    ld [$cf7b], a
    call Call_000_16f7
    jp c, Jump_001_6d5f

    call Call_000_3121
    ld a, [$d0e9]
    and a
    jr nz, jr_001_6ca3

    ld a, [$cf78]
    call Call_000_1b55
    jr c, jr_001_6ca3

    ld a, $02
    ld [$cf7b], a
    ldh [$8e], a
    call Call_000_186a
    inc a
    jr z, jr_001_6c23

    ld hl, $6e28
    ld bc, $0e01
    call Call_000_3c79
    ld hl, $c43a
    ld bc, $080f
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$d0f3]
    cp $02
    jr z, jr_001_6c23

    ld a, [$d0f2]
    dec a
    jr z, jr_001_6c23

    ld a, [$cf05]
    and a
    jr nz, jr_001_6c97

    inc a
    ld [$cf05], a

jr_001_6c97:
    call Call_000_16af
    ld hl, $d2a1
    call Call_000_16cc
    jp Jump_001_6c23


jr_001_6ca3:
    ld hl, $6e60
    call Call_000_3c79
    jp Jump_001_6d5f


Jump_001_6cac:
    ld hl, $6e47
    call Call_000_3c79
    jp Jump_001_6d5f


Jump_001_6cb5:
    ld a, $01
    ld [$cf7a], a
    ld a, $03
    ld [$d0e0], a
    ld hl, $5ead
    ld b, $0e
    call Call_000_3620
    ld hl, $6da1
    call Call_000_3c79
    call Call_000_3761

Jump_001_6cd0:
jr_001_6cd0:
    call Call_000_376d
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $cf62
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    xor a
    ld [$cc26], a
    inc a
    ld [$cf7a], a
    inc a
    ld [$cf7b], a
    call Call_000_16f7
    jr c, jr_001_6d5f

    ld a, $63
    ld [$cf7e], a
    xor a
    ldh [$8e], a
    call Call_000_186a
    inc a
    jr z, jr_001_6cd0

    ld a, [$cf78]
    ld [$d0e3], a
    call Call_000_1add
    call Call_000_386e
    ld hl, $6db4
    call Call_000_3c79
    ld hl, $c43a
    ld bc, $080f
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$d0f3]
    cp $02
    jp z, Jump_001_6cd0

    ld a, [$d0f2]
    dec a
    jr z, jr_001_6cd0

    call Call_001_6d73
    jr c, jr_001_6d7e

    ld hl, $d2a1
    call Call_000_16e0
    jr nc, jr_001_6d86

    call Call_000_16a7
    ld a, [$cf05]
    and a
    jr nz, jr_001_6d4e

    ld a, $01
    ld [$cf05], a

jr_001_6d4e:
    ld a, $b2
    call Call_000_3788
    call Call_000_3790
    ld hl, $6dcc
    call Call_000_3c79
    jp Jump_001_6cd0


Jump_001_6d5f:
jr_001_6d5f:
    call Call_000_376d
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $6e8f

jr_001_6d6d:
    call Call_000_3c79
    jp Jump_001_6bc7


Call_001_6d73:
    ld de, $d2cb
    ld hl, $ff9f
    ld c, $03
    jp Jump_000_3ad8


jr_001_6d7e:
    ld hl, $6de4
    call Call_000_3c79
    jr jr_001_6d5f

jr_001_6d86:
    ld hl, $6df4
    call Call_000_3c79
    jr jr_001_6d5f

Jump_001_6d8e:
    ld hl, $6e81
    call Call_000_3c79
    ld a, $01
    ld [$cfb2], a
    call Call_000_0ebd
    pop af
    ld [$cc36], a
    ret


    db $ed
    jr z, jr_001_6df4

    ld e, d
    ret c

    ld a, a
    ld a, [hl+]
    rst $10
    sbc $c6
    push bc
    rst $18
    jp $b87f


    jr nc, jr_001_6d6d

    or d
    ld d, a
    db $ed
    jr z, jr_001_6e24

    ld e, d
    inc sp
    cp l
    ret z

    ld c, a
    ld d, b
    ld [bc], a
    sbc a
    rst $38
    jp $f000


    add $7f
    push bc
    ret c

    rst $08

jr_001_6dc8:
    cp l
    ld h, $e6
    ld d, a
    db $ed
    jr z, @-$70

    ld e, d
    inc [hl]
    or e
    cpl
    ld c, a
    rst $08
    or d
    inc [hl]
    ld a, a
    or c
    ret c

    ld h, $c4

jr_001_6ddc:
    or e
    ld a, a
    ld a, [hl+]
    dec hl
    or d
    rst $08
    cp l
    ld e, b
    db $ed
    jr z, jr_001_6dc8

    ld e, d
    ld h, $7f
    ret nz

    ret c

    push bc
    or d
    sub $b3
    inc sp
    cp l
    ret z

    ld e, b

jr_001_6df4:
    db $ed
    jr z, jr_001_6df7

jr_001_6df7:
    ld e, e
    inc l
    ld [c], a
    or e
    ld a, a
    db $d3
    pop bc

jr_001_6dfe:
    or a
    jp c, $becf

    sbc $c8
    ld c, a
    or d
    rst $10
    push bc
    or d
    and c
    sbc b
    db $dd
    ld a, a
    cp [hl]
    or d
    ret c

    cp h
    jp Jump_000_30b8


    cp e
    or d
    ld e, b
    db $ed
    jr z, jr_001_6dfe

    ld e, c
    ld a, a
    or e
    rst $18
    jp $c0b2


    jr nc, jr_001_6ddc

    rst $08

jr_001_6e24:
    cp l
    or [hl]
    and $57
    db $ed
    inc l
    add h
    ld h, l
    cp h
    ret nz

    rst $10
    ld a, a
    ld d, b
    ld [bc], a
    sbc a
    rst $38
    jp $f000


    inc sp
    ld a, a
    ld c, a
    or l
    res 6, a
    call nz, $b2d8
    ret nz

    cp h
    rst $08
    cp h
    ld [c], a
    or e
    ld d, a
    db $ed
    jr z, @+$2b

    ld e, d
    jp c, Jump_001_7fd9

    cp h
    push bc
    db $d3
    ret


    jp z, $b54f

    db $d3
    pop bc
    inc sp
    ld a, a
    push bc
    or d
    sub $b3
    inc sp

jr_001_6e5e:
    cp l
    ld e, b
    db $ed
    jr z, jr_001_6e5e

    ld e, c
    cp h
    push bc
    db $d3
    ret


    add $7f
    or l
    ret z

    jr nc, @-$20

    db $dd
    ld c, a
    or l
    jp nz, $bdb9

    reti


    call c, $c6b9
    jp z, $cf7f

    or d
    ret c

    rst $08
    cp [hl]
    sbc $58
    db $ed
    jr z, @+$3b

    ld e, e
    call nz, $7fb3
    ld a, [hl+]
    dec hl
    or d
    rst $08
    cp h
    ret nz

    ld d, a
    db $ed
    jr z, @-$47

    ld e, d
    or [hl]
    add $7f
    call c, $b8c0
    cp h
    inc [hl]
    db $d3
    inc sp
    ld c, a
    or l
    pop bc
    or [hl]
    rst $10
    add $7f
    push bc
    jp c, $bad9

    call nz, $e6ca
    ld d, a
    call Call_000_3761
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    ld hl, $cd68
    ld de, $d01d
    ld bc, $0006
    call Call_000_01bb

Jump_001_6ec4:
    ld hl, $d133
    ld bc, $002c
    ld a, [$cf79]
    call Call_000_3ad1
    ld d, h
    ld e, l
    ld b, $04

jr_001_6ed4:
    ld a, [hl]
    and a
    jr z, jr_001_6ef4

    inc hl
    dec b
    jr nz, jr_001_6ed4

    push de
    call Call_001_6f70
    pop de
    jp c, Jump_001_6f43

    push hl
    push de
    ld [$d0e3], a
    call Call_000_1b6d
    ld hl, $70bf
    call Call_000_3c79
    pop de
    pop hl

jr_001_6ef4:
    ld a, [$d0bd]
    ld [hl], a
    ld bc, $0015
    add hl, bc
    push hl
    push de
    dec a
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld de, $cee4
    ld a, $0e
    call Call_000_01a3
    ld a, [$cee9]
    pop de
    pop hl
    ld [hl], a
    ld a, [$d034]
    and a
    jp z, Jump_001_6f67

    ld a, [$cf79]
    ld b, a
    ld a, [$cc2f]
    cp b
    jp nz, Jump_001_6f67

    ld h, d
    ld l, e
    ld de, $d003
    ld bc, $0004
    call Call_000_01bb
    ld bc, $0011
    add hl, bc
    ld de, $d014
    ld bc, $0004
    call Call_000_01bb
    jp Jump_001_6f67


Jump_001_6f43:
    ld hl, $702d
    call Call_000_3c79
    ld hl, $c43a
    ld bc, $080f
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$cc26]
    and a
    jp nz, Jump_001_6ec4

    ld hl, $704b
    call Call_000_3c79
    ld b, $00
    ret


Jump_001_6f67:
    ld hl, $7000
    call Call_000_3c79
    ld b, $01
    ret


Call_001_6f70:
    push hl
    ld hl, $7064
    call Call_000_3c79
    ld hl, $c43a
    ld bc, $080f
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    pop hl
    ld a, [$cc26]
    rra
    ret c

    ld bc, $fffc
    add hl, bc
    push hl
    ld de, $d0b9
    ld bc, $0004
    call Call_000_01bb
    ld hl, $5e5f
    ld b, $0e
    call Call_000_3620
    pop hl

jr_001_6fa2:
    push hl
    ld hl, $701c
    call Call_000_3c79
    ld hl, $c440
    ld b, $08
    ld c, $12
    call Call_000_03d2
    ld hl, $c46a

jr_001_6fb6:
    ld de, $df30
    call Call_000_0405
    ld hl, $cc24
    ld a, $0a
    ld [hl+], a
    ld a, $01
    ld [hl+], a
    xor a
    ld [hl+], a
    inc hl
    ld a, [$cd67]
    ld [hl+], a
    ld a, $03
    ld [hl+], a
    ld [hl], $00
    call Call_000_3b08
    push af
    call Call_000_376d
    pop af
    pop hl
    bit 1, a
    jr nz, jr_001_6ffe

    push hl
    ld a, [$cc26]
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    push af
    push bc
    call Call_000_1b5e
    pop bc
    pop de
    ld a, d
    jr c, jr_001_6ff5

    pop hl
    add hl, bc
    and a
    ret


jr_001_6ff5:
    ld hl, $7102
    call Call_000_3c79
    pop hl
    jr jr_001_6fa2

jr_001_6ffe:
    scf
    ret


    db $ed
    jr z, jr_001_6fb6

    ld e, e
    jp z, $b17f

    ret nz

    rst $10
    cp h
    cp b
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    or l
    ld a, $b4
    ret nz

    rst $20
    ld d, b
    dec bc
    ld b, $50
    db $ed
    jr z, jr_001_708d

    ld e, h
    call c, $dd2b
    ld c, [hl]
    call c, $dabd
    cp e
    cp [hl]
    ret nz

    or d
    and $57
    db $ed
    jr z, jr_001_7074

    ld e, e
    jp z, $7f56

    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld c, a

jr_001_703b:
    or l
    ld a, $b4
    reti


    ret


    db $dd
    ld a, a
    or c
    or a
    rst $10
    jp nc, $bdcf

    or [hl]
    and $57
    db $ed
    jr z, jr_001_70c7

    ld e, e
    jp z, $507f

    ld bc, $cf45
    nop
    db $dd
    ld c, a
    or l
    ld a, $b4
    dec l
    add $7f
    or l
    call c, $c0df
    rst $20
    ld e, b
    db $ed
    jr z, jr_001_703b

    ld e, e
    jp z, $b17f

    ret nz

    rst $10
    cp h
    cp b
    ld c, a
    ld d, b
    ld bc, $cf45

jr_001_7074:
    nop
    db $dd
    ld a, a
    or l
    ld a, $b4
    ret nz

    or d
    ld d, [hl]
    rst $20
    ld d, c
    cp h
    or [hl]
    cp h
    ld a, a
    ld d, b
    ld bc, $d01d

jr_001_7087:
    nop
    jp z, $dc7f

    dec hl
    db $dd

jr_001_708d:
    ld a, a
    ld a, [$4fc2]
    or l
    ld a, $b4
    reti


    ret


    inc sp
    ld a, a
    cp [hl]
    or d
    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_001_7087

    ld d, c
    ld d, b
    ld bc, $cf45
    nop
    ret


    ld a, a
    or [hl]
    call c, $c6d8
    ld c, a
    adc $b6
    ret


    ld a, a
    call c, $dd2b
    ld a, a
    call c, $dabd
    cp e
    cp [hl]
    rst $08
    cp l
    or [hl]
    and $57
    nop
    sub c
    ld d, [hl]
    ld d, [hl]
    sub d
    ld d, [hl]
    ld d, [hl]
    ld d, b

jr_001_70c7:
    ld a, [bc]
    ld [$ae3e], sp
    call Call_000_3788
    ld hl, $70d2
    ret


    db $ed
    dec l
    and b
    ld h, l
    xor e
    rst $20
    ld d, b
    ld a, [bc]
    nop
    ld d, c
    ld d, b
    ld bc, $d01d
    nop
    jp z, $507f

    ld bc, $cd68
    nop
    ret


    ld c, a
    jp nz, $b2b6

    or [hl]
    ret nz

    db $dd
    ld a, a
    or a
    jp c, $c6b2

    ld a, a
    call c, $dabd
    ret nz

    rst $20
    ld d, c
    cp a
    cp h
    jp $e756


    ld e, b
    db $ed
    jr z, @-$64

    ld e, h
    ld a, a
    ret nz

    or d
    cp [hl]
    jp nz, $dcc5

    dec hl
    inc sp
    cp l
    ld c, a
    call c, $dabd
    cp e
    cp [hl]
    reti


    cp d
    call nz, Call_001_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $e7
    ld e, b
    call Call_000_3761
    ld hl, $7199
    call Call_000_3c79
    ld hl, $d6ad
    bit 2, [hl]
    set 1, [hl]
    set 2, [hl]
    jr nz, jr_001_713c

    ld hl, $71c1
    call Call_000_3c79

jr_001_713c:
    call Call_000_3654
    ld a, [$cc26]
    and a
    jr nz, jr_001_718d

    call Call_001_722e
    call Call_000_376d
    ld hl, $71db
    call Call_000_3c79
    ld a, $18
    ld [$c112], a
    call Call_000_3e07
    ld a, $07
    call Call_000_3e9d
    ld b, $1c
    ld hl, $4984
    call Call_000_3620
    xor a
    ld [$cfae], a
    ld a, [$c0f0]
    ld [$c0ef], a
    ld a, [$d2da]
    ld [$cfb1], a
    ld [$c0ee], a
    call Call_000_0e45

jr_001_717c:
    ld hl, $71f0
    call Call_000_3c79
    ld a, $14
    ld [$c112], a
    ld c, a
    call Call_000_3781
    jr jr_001_7190

jr_001_718d:
    call Call_000_376d

jr_001_7190:
    ld hl, $7219
    call Call_000_3c79
    jp Jump_000_0ebd


    db $ed
    jr z, jr_001_717c

    ld e, h
    cp a
    rst $20
    ld c, a
    ld d, h
    adc l
    xor e

jr_001_71a3:
    adc a
    db $e3
    call $ba51
    cp d
    inc sp
    jp z, Jump_001_547f

    ret


    ld c, a
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    ld a, a
    or [hl]
    or d
    call z, $ddb8
    ld a, a
    or d
    ret nz

    cp h
    rst $08
    cp l
    ld e, b
    db $ed
    jr z, jr_001_71e5

    ld e, l
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    db $dd
    ld a, a
    ld c, a
    or l
    or c
    dec l
    cp c
    add $7f
    push bc
    ret c

    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    jr z, jr_001_7226

jr_001_71de:
    ld e, l
    jp z, $b14f

    dec l
    or [hl]
    rst $10

jr_001_71e5:
    cp [hl]
    jp $b27f


    ret nz

    jr nc, jr_001_71a3

    rst $08
    cp l
    rst $20
    ld d, a
    db $ed
    jr z, jr_001_7259

    ld e, l
    inc [hl]
    or e
    cp e
    rst $08
    inc sp
    cp h
    ret nz

    rst $20
    ld c, a
    or l
    or c
    dec l
    or [hl]
    ret c

    cp h
    ret nz

    ld a, a
    ld d, h
    jp z, $d055

    sbc $c5
    ld a, a
    add hl, hl
    sbc $b7
    add $7f
    push bc
    ret c

    rst $08
    cp h
    ret nz

    sub $e7
    ld e, b
    db $ed
    jr z, jr_001_71de

    ld e, l
    ret


    ld c, a
    ld a, [hl+]
    ret c

    sub $b3
    db $dd
    ld a, a
    or l

jr_001_7226:
    rst $08
    pop bc
    cp h
    jp $bdcf


    rst $20
    ld d, a

Call_001_722e:
    push hl
    ld hl, $7248
    ld a, [$d2dd]
    ld b, a

jr_001_7236:
    ld a, [hl+]
    cp $ff
    jr z, jr_001_7240

    cp b
    jr nz, jr_001_7236

    jr jr_001_7246

jr_001_7240:
    ld a, [$d2e4]
    ld [$d698], a

jr_001_7246:
    pop hl
    ret


    rst $18
    ldh [$e1], a
    rst $38
    xor a
    ld [$cf7b], a
    ld a, [$cf07]
    bit 0, a
    jr nz, jr_001_727d

    ldh a, [$8c]

jr_001_7259:
    and a
    jr nz, jr_001_7273

    ld a, [$d6ca]
    bit 5, a
    ld hl, $c3ac
    ld b, $0e
    ld c, $06
    jr nz, jr_001_727a

    ld hl, $c3ac
    ld b, $0c
    ld c, $06
    jr jr_001_727a

jr_001_7273:
    ld hl, $c490
    ld b, $04
    ld c, $12

jr_001_727a:
    call Call_000_03d2

jr_001_727d:
    ld hl, $cfab
    set 0, [hl]
    ld hl, $cd5b
    bit 4, [hl]
    res 4, [hl]
    jr nz, jr_001_728e

    call Call_000_0ebd

jr_001_728e:
    ld hl, $c119
    ld c, $0f
    ld de, $0010

jr_001_7296:
    ld a, [hl]
    inc h
    ld [hl], a
    dec h
    add hl, de
    dec c
    jr nz, jr_001_7296

    ld hl, $c102
    ld de, $0010
    ld c, e

jr_001_72a5:
    ld a, [hl]
    cp $ff
    jr z, jr_001_72ad

    and $fc
    ld [hl], a

jr_001_72ad:
    add hl, de
    dec c
    jr nz, jr_001_72a5

    ld b, $9c
    call Call_000_0386
    xor a
    ldh [$b0], a
    call Call_000_36ca
    ld a, $01
    ldh [$ba], a
    ret


    ld a, [$d6ca]
    bit 5, a
    ld hl, $c3ac
    ld b, $0e
    ld c, $06
    jr nz, jr_001_72d6

    ld hl, $c3ac
    ld b, $0c
    ld c, $06

jr_001_72d6:
    call Call_000_03d2
    ld a, $cb
    ld [$cc29], a
    ld a, $02
    ld [$cc24], a
    ld a, $0d
    ld [$cc25], a
    ld a, [$cc2d]
    ld [$cc26], a
    ld [$cc2a], a
    xor a
    ld [$cc37], a
    ld hl, $d6af
    set 6, [hl]
    ld hl, $c3d6
    ld a, [$d6ca]
    bit 5, a
    ld a, $06
    jr z, jr_001_730e

    ld de, $7345
    call Call_001_7362
    ld a, $07

jr_001_730e:
    ld [$cc28], a
    ld de, $7349
    call Call_001_7362
    ld de, $734b
    call Call_001_7362
    ld de, $d11d
    call Call_001_7362
    ld a, [$d6ad]
    bit 6, a
    ld de, $734f
    jr z, jr_001_7330

    ld de, $7354

jr_001_7330:
    call Call_001_7362
    ld de, $735d
    call Call_001_7362
    ld de, $7359
    call Call_000_0405
    ld hl, $d6af
    res 6, [hl]
    ret


    db $ed
    inc l
    add h
    ld h, e
    ld d, h
    ld d, b
    db $ed
    inc l
    adc c
    ld h, e
    db $ed
    inc l
    adc a
    ld h, e
    ld d, b
    db $ed
    inc l
    sub h
    ld h, e
    ld d, b
    db $ed
    inc l
    sbc d
    ld h, e
    db $ed
    inc l
    sbc a
    ld h, e
    ld d, b

Call_001_7362:
    push hl
    call Call_000_0405
    pop hl
    ld de, $0028
    add hl, de
    ret


    ld hl, $7497
    call Call_000_3c79
    ld a, [$d6ca]
    bit 5, a
    jp nz, Jump_001_7388

    ld c, $3c
    call Call_000_3781
    ld hl, $7538
    call Call_000_3c79
    jp Jump_001_7444


; ── LinkHandshake: リンクケーブル接続ハンドシェイク ──
; ポケモン初代の標準リンクプロトコル:
;   1. 両方のGBが同時にマスターを試みる
;   2. 先にバイトを受信した側がスレーブ ($AA=$01) になる
;   3. もう一方がマスター ($AA=$02) に確定
; 手順:
;   a. rSB=$02, rSC=$80 → 外部クロック受信待ち (スレーブ候補)
;   b. rSB=$01, rSC=$81 → 内部クロック送信試行 (マスター候補)
;   c. ISRが受信 → $AA にロール確定
; リトライ: $CC47=$5A (90回) でタイムアウト → 切断処理
Jump_001_7388:
    ld a, $01
    ld [$cc34], a       ; リンクモードフラグ
    ld a, $10
    ld [$cce0], a       ; コマンドバイト=$10 (ハンドシェイク)
    ld a, $5a
    ld [$cc47], a       ; リトライカウンタ=90回

; ハンドシェイクループ
jr_001_7397:
    ldh a, [$aa]
    cp $02
    jr z, jr_001_73c6   ; → マスター確定: 接続成功

    cp $01
    jr z, jr_001_73c6   ; → スレーブ確定: 接続成功

    ; 未確定: 双方向試行
    ld a, $ff
    ldh [$aa], a        ; ロール=未確定
    ld a, $02
    ldh [rSB], a        ; テストバイト=$02
    xor a
    ldh [$ad], a        ; 受信バッファクリア
    ld a, $80
    ldh [rSC], a        ; 外部クロック受信待ち (スレーブ候補)
    ld a, [$cc47]
    dec a
    ld [$cc47], a       ; リトライカウンタ--
    jr z, jr_001_7433   ; → タイムアウト: 接続失敗

    ld a, $01
    ldh [rSB], a        ; テストバイト=$01
    ld a, $81
    ldh [rSC], a        ; 内部クロック送信 (マスター候補)
    call Call_000_0b31  ; VBlank待ち (ISR処理時間)
    jr jr_001_7397      ; → 再判定

; 接続成功: 安定化処理
jr_001_73c6:
    call Call_000_0d81  ; SerialSendZero (同期信号)
    call Call_000_0b31  ; VBlank待ち
    call Call_000_0d81  ; SerialSendZero (2回目)
    ld c, $32
    call Call_000_3781
    ld hl, $74ad
    call Call_000_3c79
    xor a
    ld [$cc34], a
    call Call_000_3636
    ld a, $01
    ld [$cc34], a
    ld a, [$cc26]
    and a
    jr nz, jr_001_743b

    ld hl, $7ce3
    ld b, $1c
    call Call_000_3620
    call Call_000_3790
    ld a, $b6
    call Call_000_3788
    ld hl, $74d3
    call Call_000_3c79
    ld hl, $cc47
    ld a, $03
    ld [hl+], a
    xor a
    ld [hl], a
    ldh [$a9], a
    ld [$cc42], a
    call Call_000_0c66
    ld hl, $cc47
    ld a, [hl+]
    inc a
    jr nz, jr_001_7454

    ld a, [hl]
    inc a
    jr nz, jr_001_7454

    ld b, $0a

jr_001_741f:
    call Call_000_0b31
    call Call_000_0d81
    dec b
    jr nz, jr_001_741f

    call Call_001_754d
    ld hl, $74e6
    call Call_000_3c79
    jr jr_001_7444

; ハンドシェイク失敗 (90回タイムアウト)
jr_001_7433:
    ld hl, $745f        ; "つうしん エラー" メッセージ
    call Call_000_3c79
    jr jr_001_7444

jr_001_743b:
    call Call_001_754d  ; LinkDisconnect
    ld hl, $7527
    call Call_000_3c79

; ── LinkCleanup: リンク状態クリーンアップ ──
; タイムアウトカウンタ、通信フラグをリセットして通常モードに復帰。
Jump_001_7444:
jr_001_7444:
    xor a
    ld hl, $cc47
    ld [hl+], a         ; タイムアウトカウンタ上位=0
    ld [hl], a          ; タイムアウトカウンタ下位=0
    ld hl, $d6ad
    res 6, [hl]         ; リンクフラグをクリア
    xor a
    ld [$cc34], a       ; リンクモード解除
    ret


jr_001_7454:
    xor a
    ld [hl-], a
    ld [hl], a
    ld hl, $5a36
    ld b, $01
    jp Jump_000_3620


    db $ed
    jr z, jr_001_747c

    ld e, a
    jp z, $c47f

    db $d3
    jr nc, @-$3d

    call nz, $c24f
    or e
    cp h
    sbc $88
    db $e3
    dec de
    and [hl]
    db $dd

Jump_001_7474:
    ld a, a
    jp nz, $b2c5

    jr nc, jr_001_74cb

jr_001_747a:
    or [hl]
    ret nz

jr_001_747c:
    ld h, $c0
    db $dd
    ld a, a
    call nz, Call_000_3db8
    jp nz, $e7c6

    ld c, a
    ld a, [hl+]
    or c
    sbc $c5
    or d
    ld a, a

jr_001_748d:
    or d
    ret nz

    cp h
    jp $b57f


    ret c

    rst $08
    cp l
    ld d, a
    db $ed
    jr z, jr_001_747a

    ld e, l
    sbc $7f

jr_001_749d:
    adc b
    db $e3
    dec de
    and [hl]
    ld a, a
    add a
    and l
    dec de
    add $4f
    sub $b3
    cp d
    cp a
    rst $20
    ld d, a
    db $ed
    jr z, jr_001_74e9

    ld e, [hl]
    cp c
    jp z, $ba7f

    pop bc
    rst $10
    inc sp
    cp l
    ld d, c
    jp nz, $bcb3

jr_001_74bd:
    sbc $dd
    ld a, a
    jp z, $d22c

    reti


    rst $08
    or h
    add $4f
    and a
    ld b, e
    db $e3

jr_001_74cb:
    sub e
    db $dd
    ld a, a
    or [hl]
    or a
    rst $08
    cp l
    ld d, a
    db $ed
    jr z, @-$73

    ld e, [hl]
    cp h
    ld [c], a
    or e
    ld a, a
    or l
    rst $08
    pop bc
    ld a, a

jr_001_74df:
    cp b
    jr nc, jr_001_749d

    or d
    ld d, b
    ld a, [bc]
    ld d, b
    db $ed
    jr z, jr_001_748d

jr_001_74e9:
    ld e, [hl]
    inc l
    or [hl]
    sbc $26
    ld a, a
    push bc
    ld h, $b2
    ret


jr_001_74f3:
    inc sp
    ld c, a
    or e
    cp c
    jp nz, $ddb9

    ld a, a
    pop bc
    pop hl
    or e
    cp h
    ld a, a
    or d
    ret nz

    cp h
    rst $08
    cp l
    rst $20
    ld d, c
    call nz, Call_000_30d3
    pop bc
    call nz, $da7f
    sbc $d7
    cp b
    db $dd
    ld a, a
    call nz, $c3df
    ld c, a
    db $d3
    or e
    or d
    pop bc
    inc [hl]
    ld a, a
    or l
    cp d
    cp h
    ld a, a
    cp b
    jr nc, jr_001_74df

    or d
    rst $20
    ld d, a
    db $ed
    jr z, jr_001_74bd

    ld e, a
    jp z, $cf7f

    ret nz

    ld a, a
    or l
    cp d
    cp h
    cp b
    jr nc, @-$43

    or d
    ld d, a
    db $ed
    jr z, jr_001_754c

    ld e, [hl]
    jp z, $c07f

    jr nc, jr_001_74f3

    rst $08
    ld c, a
    inc l
    pop hl
    sbc $3b
    pop bc
    pop hl
    or e
    inc sp
    cp l

jr_001_754c:
    ld d, a

; ── LinkDisconnect: リンク切断 ──
; ロールを未確定 ($FF) に戻し、スレーブモードで受信待ちに入る。
; 相手側もこの状態に入ることで、安全に通信を終了する。
Call_001_754d:
    call Call_000_3e07
    ld a, $ff
    ldh [$aa], a        ; ロール=未確定
    ld a, $02
    ldh [rSB], a        ; テストバイト
    xor a
    ldh [$ad], a        ; 受信バッファクリア
    ld a, $80
    ldh [rSC], a        ; 外部クロック受信待ち
    ret


    xor a
    ld [$cf06], a
    ld [$d67f], a
    ld [$d034], a
    ld [$d2dc], a
    ld [$cf0b], a
    ldh [$b4], a
    ld [$cc57], a
    ld [$cd5b], a
    ldh [$9f], a
    ldh [$a0], a
    ldh [$a1], a
    call Call_000_35f0
    jr c, jr_001_75af

    ld a, [$d2cb]
    ldh [$9f], a
    ld a, [$d2cc]
    ldh [$a0], a
    ld a, [$d2cd]
    ldh [$a1], a
    xor a
    ldh [$a2], a
    ldh [$a3], a
    ld a, $02
    ldh [$a4], a
    ld a, $0d
    call Call_000_3e9d
    ldh a, [$a2]
    ld [$d2cb], a
    ldh a, [$a3]
    ld [$d2cc], a
    ldh a, [$a4]
    ld [$d2cd], a

jr_001_75af:
    ld hl, $d6b1
    set 2, [hl]
    res 3, [hl]
    set 6, [hl]
    ld a, $ff
    ld [$cd66], a
    ld a, $07
    jp Jump_000_3e9d


    ld a, [$d991]
    ld [$cf78], a
    ld a, [$cc49]
    cp $03
    jr z, jr_001_75db

    ld a, [$cf79]
    ld e, a
    ld hl, $5f0f
    ld b, $0e
    call Call_000_3620

jr_001_75db:
    ld a, [$cf78]
    ld [$d092], a
    call Call_000_2f2e
    ld hl, $d12b
    ld bc, $002c
    ld a, [$cc49]
    cp $01
    jr c, jr_001_7605

    ld hl, $d823
    jr z, jr_001_7605

    cp $02
    ld hl, $d9d2
    ld bc, $0021
    jr z, jr_001_7605

    ld hl, $d991
    jr jr_001_760b

jr_001_7605:
    ld a, [$cf79]
    call Call_000_3ad1

jr_001_760b:
    ld de, $cf7f
    ld bc, $002c
    jp Jump_000_01bb


    ld hl, $cce9
    ld a, [hl]
    and a
    jr z, jr_001_7621

    dec [hl]
    ld hl, $7644
    jr jr_001_763c

jr_001_7621:
    dec hl
    ld a, [hl]
    and a
    ret z

    dec [hl]
    ld hl, $765a
    jr nz, jr_001_763c

    push hl
    ld a, [$cfcc]
    ld [$d092], a
    call Call_000_2f2e
    ld a, [$d09d]
    ld [$cfee], a
    pop hl

jr_001_763c:
    push hl
    call Call_000_376d
    pop hl
    jp Jump_000_3c79


    db $ed
    dec l
    jp c, $c967

    ld d, b
    ld bc, $cfc1
    nop
    jp z, $834f

    adc d
    db $dd
    ld a, a
    ret nz

    dec a
    jp $e7d9


    ld e, b
    db $ed
    dec l
    ei
    ld h, a
    ret


    ld d, b
    ld bc, $cfc1
    nop
    jp z, $b54f

    cp d
    rst $18
    jp $e7d9


    ld e, b
    ld a, [$d0ea]
    cp $14
    jp z, Jump_001_78e6

    ld c, a
    ld hl, $770a
    ld de, $0003
    call Call_001_76cf
    jr c, jr_001_7698

    ld hl, $7714
    ld de, $0005
    call Call_001_76cf
    jr c, jr_001_76a0

    ld hl, $7733
    ld de, $0009
    call Call_001_76cf
    jr c, jr_001_76aa

    ret


jr_001_7698:
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $7697
    push de
    jp hl


jr_001_76a0:
    call Call_001_76dd
    call Call_001_76f8
    call Call_000_03d2
    ret


jr_001_76aa:
    call Call_001_76dd
    push hl
    call Call_001_76f8
    call Call_000_03d2
    pop hl
    call Call_001_76ea
    ld a, [$d6af]
    push af
    ld a, [$d6af]
    set 6, a
    ld [$d6af], a
    call Call_000_0405
    pop af
    ld [$d6af], a
    call Call_000_0ebd
    ret


Call_001_76cf:
    dec de

jr_001_76d0:
    ld a, [hl+]
    cp $ff
    jr z, jr_001_76dc

    cp c
    jr z, jr_001_76db

    add hl, de
    jr jr_001_76d0

jr_001_76db:
    scf

jr_001_76dc:
    ret


Call_001_76dd:
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    sub e
    dec a
    ld c, a
    ld a, [hl+]
    sub d
    dec a
    ld b, a
    ret


Call_001_76ea:
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    push de
    ld a, [hl+]
    ld e, a
    ld a, [hl]
    ld d, a
    call Call_001_76f8
    pop de
    ret


Call_001_76f8:
    push bc
    ld hl, $c3a0
    ld bc, $0014

jr_001_76ff:
    ld a, d
    and a
    jr z, jr_001_7707

    add hl, bc
    dec d
    jr jr_001_76ff

jr_001_7707:
    pop bc
    add hl, de
    ret


    inc de
    ld a, $78
    dec d
    ld [hl], a
    ld a, b
    inc b
    jr nc, @+$7c

    rst $38
    ld bc, $0c00
    inc de
    ld de, $0003
    nop
    inc de
    ld c, $07
    nop
    nop
    dec bc
    ld b, $0d
    nop
    ld [bc], a
    inc de
    inc c
    db $10
    rlca
    nop
    inc de
    ld de, $0611
    inc b
    ld c, $0d
    rst $38
    dec b
    nop
    nop
    ld c, $11
    call z, $0377
    nop
    ld b, $0a
    ld a, [bc]
    inc de
    ld c, $ae
    ld [hl], a
    inc c
    dec bc
    ld [$0000], sp
    rlca
    dec b
    or [hl]
    ld [hl], a
    ld [bc], a
    ld [bc], a
    add hl, bc
    nop
    ld b, $05
    ld a, [bc]
    ret nz

    ld [hl], a
    ld [bc], a
    rlca
    dec bc
    nop
    inc c
    inc de
    ld de, $77de
    ld [bc], a
    ld c, $1b
    nop
    inc c
    inc de
    ld de, $77ed
    ld [bc], a
    ld c, $0c
    dec bc
    dec bc
    inc de
    ld de, $780e
    dec c
    inc c
    ld c, $00
    nop
    ld a, [bc]
    ld b, $96
    ld [hl], a
    ld [bc], a
    ld bc, $0b0f
    nop
    inc de
    ld [bc], a
    ret z

    ld [hl], a
    ld c, $00
    ld [de], a
    rlca
    ld b, $0b
    ld a, [bc]
    ld hl, $0878
    ld [$0b1a], sp
    ld [$1113], sp
    dec h
    ld a, b
    inc c
    ld a, [bc]
    db $ed
    inc l
    ld d, d
    ld h, h
    or a
    ret nz

    ld c, [hl]
    or e
    ret c

    add $7f
    or a
    ret nz

    ld c, [hl]
    dec a
    jp nz, $7fc6

    or d
    or d
    inc sp
    cp l
    ld d, b
    ld d, b
    db $ed
    inc l
    call c, $bd63
    jp Jump_001_50d9


    db $ed
    inc l
    add sp, $63
    and b
    xor h
    adc l
    db $e3
    dec bc
    ld d, b
    db $ed
    inc l
    db $f4
    ld h, e
    or l
    cp a
    or d
    ld d, b
    db $ed
    inc l
    ld h, l
    ld h, h
    db $d3
    pop bc
    db $d3
    ret


    ld d, b
    jp nz, $b732

    or [hl]
    rst $10
    ld c, [hl]
    cp e
    or d
    cp h
    ld [c], a
    or [hl]
    rst $10
    ld d, b
    db $ed
    inc l
    rst $38
    ld h, e
    ld a, a
    inc [hl]
    or e
    jr z, jr_001_7835

    ld d, h
    ld a, a
    add $29
    reti


    ld d, b
    db $ed
    inc l
    ld e, $64
    inc e
    db $e3
    and [hl]
    pop af
    ld a, a
    ld a, a
    ld a, a
    add e
    adc d
    db $dd
    push bc
    add hl, hl
    reti


    ld c, [hl]
    or d
    cp h
    db $dd
    push bc
    add hl, hl
    reti


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    add $29
    reti


    ld d, b
    db $ed
    inc l
    dec a
    ld h, h
    reti


    ld c, [hl]
    jp nz, $bbd6

    db $dd
    ret nc

    reti


    ld c, [hl]
    add [hl]
    xor l
    xor e
    adc l
    and [hl]
    ld d, b
    db $ed
    inc l
    ld l, d
    ld h, h
    db $ed
    inc l
    ld l, a
    ld h, h
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

jr_001_7835:
    ret nc

    reti


    ld c, [hl]
    add [hl]
    xor l
    xor e
    adc l
    and [hl]
    ld d, b
    ld hl, $d6af
    set 6, [hl]
    ld a, $0f
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $c3c1
    ld b, $01
    ld c, $06
    call Call_000_0374
    ld hl, $c3c0
    ld de, $786f
    call Call_000_0405
    ld hl, $c3c0
    ld de, $d2cb
    ld c, $83
    call Call_000_2fc4
    ld hl, $d6af
    res 6, [hl]
    ret


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ldh a, [$50]
    ld a, [$d6af]
    set 6, a
    ld [$d6af], a
    xor a
    ld [$d0f2], a
    ld a, $0e
    ld [$d0ea], a
    call Call_000_3130
    ld a, $03
    ld [$cc29], a
    ld a, $02
    ld [$cc28], a
    ld a, $01
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    ld [$cc37], a
    ld a, [$d6af]
    res 6, a
    ld [$d6af], a
    call Call_000_3b08
    call Call_000_3c1c
    bit 0, a
    jr nz, jr_001_78c6

    bit 1, a
    jr z, jr_001_78c6

    ld a, $02
    ld [$d0f3], a
    jr jr_001_78d9

jr_001_78c6:
    ld a, $01
    ld [$d0f3], a
    ld a, [$cc26]
    ld [$d0f2], a
    ld b, a
    ld a, [$cc28]
    cp b
    jr z, jr_001_78d9

    ret


jr_001_78d9:
    ld a, $02
    ld [$d0f3], a
    ld a, [$cc26]
    ld [$d0f2], a
    scf
    ret


Jump_001_78e6:
    push hl
    ld a, [$d6af]
    set 6, a
    ld [$d6af], a
    xor a
    ld [$d0f2], a
    ld [$d0f3], a
    ld a, $03
    ld [$cc29], a
    ld a, $01
    ld [$cc28], a
    ld a, b
    ld [$cc24], a
    ld a, c
    ld [$cc25], a
    xor a
    ld [$cc2a], a
    ld [$cc37], a
    push hl
    ld hl, $d0f1
    bit 7, [hl]
    res 7, [hl]
    jr z, jr_001_791a

    inc a

jr_001_791a:
    ld [$cc26], a
    pop hl
    push hl
    push hl
    call Call_001_79a0
    ld a, [$d0f1]
    ld hl, $79d3
    ld e, a
    ld d, $00
    ld a, $05

jr_001_792e:
    add hl, de
    dec a
    jr nz, jr_001_792e

    ld a, [hl+]
    ld c, a
    ld a, [hl+]
    ld b, a
    ld e, l
    ld d, h
    pop hl
    push de
    ld a, [$d0f1]
    cp $05
    jr nz, jr_001_7946

    call Call_001_58df
    jr jr_001_7949

jr_001_7946:
    call Call_000_03d2

jr_001_7949:
    call Call_000_0ebd
    pop hl
    ld a, [hl+]
    and a
    ld bc, $0016
    jr z, jr_001_7957

    ld bc, $002a

jr_001_7957:
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    pop hl
    add hl, bc
    call Call_000_0405
    xor a
    ld [$d0f1], a
    ld hl, $d6af
    res 6, [hl]
    call Call_000_3b08
    pop hl
    bit 1, a
    jr nz, jr_001_7989

    ld a, [$cc26]
    ld [$d0f2], a
    and a
    jr nz, jr_001_7989

    ld a, $01
    ld [$d0f3], a
    ld c, $0f
    call Call_000_3781
    call Call_001_79b8
    and a
    ret


jr_001_7989:
    ld a, $01
    ld [$cc26], a
    ld [$d0f2], a
    ld a, $02
    ld [$d0f3], a
    ld c, $0f
    call Call_000_3781
    call Call_001_79b8
    scf
    ret


Call_001_79a0:
    ld de, $cee4
    ld bc, $0506

jr_001_79a6:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_001_79a6

    push bc
    ld bc, $000e
    add hl, bc
    pop bc
    ld c, $06
    dec b
    jr nz, jr_001_79a6

    ret


Call_001_79b8:
    ld de, $cee4
    ld bc, $0506

jr_001_79be:
    ld a, [de]
    inc de
    ld [hl+], a
    dec c
    jr nz, jr_001_79be

    push bc
    ld bc, $000e
    add hl, bc
    pop bc
    ld c, $06
    dec b
    jr nz, jr_001_79be

    call Call_000_0ebd
    ret


    inc b
    inc bc
    nop
    ld [bc], a
    ld a, d
    inc b
    inc bc
    nop
    add hl, bc
    ld a, d
    inc b
    inc bc
    nop
    rrca
    ld a, d
    ld b, $03
    nop
    ld [bc], a
    ld a, d
    inc b
    inc bc
    nop
    rla
    ld a, d
    dec b
    inc bc
    nop
    ld e, $7a
    dec b
    inc b
    ld bc, $7a27
    inc b
    inc bc
    nop
    ei
    ld a, c
    db $ed
    inc l
    add l
    ld h, h
    jp z, Jump_001_50b2

    db $ed
    inc l
    adc h
    ld h, h
    or d
    or h
    ld d, b
    db $ed
    inc l
    sub e
    ld h, h
    cp h
    ld d, b
    db $ed
    inc l
    sbc [hl]
    ld h, h
    sla [hl]
    cp h
    ld d, b
    db $ed
    inc l
    xor c
    ld h, h
    ld h, $bc
    ld d, b
    db $ed
    inc l
    or h
    ld h, h
    ld c, [hl]
    call nc, $d9d2
    ld d, b
    db $ed
    inc l
    jp nz, $4e64

    call nc, $d9d2
    ld d, b
    xor a
    ld hl, $cd3d
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    call Call_001_7af0
    ld a, [$cd41]
    and a
    jr nz, jr_001_7a51

    ld hl, $c481
    ld b, $05
    ld c, $0d
    call Call_000_03d2
    call Call_000_0ebd
    jr jr_001_7aa5

jr_001_7a51:
    ld hl, $c481
    ld b, $05
    ld c, $0d
    ld de, $ffd8

jr_001_7a5b:
    add hl, de
    inc b
    inc b
    dec a
    jr nz, jr_001_7a5b

    ld de, $ffec
    add hl, de
    inc b
    call Call_000_03d2
    call Call_000_0ebd
    ld hl, $c497
    ld de, $ffd8
    ld a, [$cd41]

jr_001_7a75:
    add hl, de
    dec a
    jr nz, jr_001_7a75

    xor a
    ld [$cd41], a
    ld de, $cd3d

jr_001_7a80:
    push hl
    ld hl, $7aae
    ld a, [de]
    and a
    jr z, jr_001_7aa4

    inc de
    ld b, a

jr_001_7a8a:
    dec b
    jr z, jr_001_7a94

jr_001_7a8d:
    ld a, [hl+]
    cp $50
    jr nz, jr_001_7a8d

    jr jr_001_7a8a

jr_001_7a94:
    ld b, h
    ld c, l
    pop hl
    push de
    ld d, b
    ld e, c
    call Call_000_0405
    ld bc, $0028
    add hl, bc
    pop de
    jr jr_001_7a80

jr_001_7aa4:
    pop hl

jr_001_7aa5:
    ld hl, $c497
    ld de, $7aec
    jp Jump_000_0405


    or e
    or a
    xor a
    or d
    and h
    ld a, a
    or e
    xor e
    xor c
    xor h
    xor h
    ld d, b
    and [hl]
    xor h
    cp c
    xor c
    xor [hl]
    and a
    ld d, b
    ld d, b
    or e
    or l
    or d
    and [hl]
    ld d, b
    and [hl]
    xor a
    or d
    and e
    and l
    ld d, b
    xor h
    xor c
    and a
    xor b
    or h
    ld d, b
    and d
    or l
    or d
    or d
    xor a
    or a
    ld d, b
    or h
    or d
    and c
    xor [hl]
    or e
    xor l
    xor c
    or h
    ld d, b
    or e
    or b
    or a
    and c
    xor [hl]
    ld d, b
    ld c, [hl]
    add [hl]
    xor l
    db $ed
    inc l
    and b
    ld b, c

Call_001_7af0:
    ld a, [$cf79]
    ld hl, $d133
    ld bc, $002c
    call Call_000_3ad1
    ld d, h
    ld e, l
    ld c, $05
    ld hl, $cd3d

jr_001_7b03:
    push hl

jr_001_7b04:
    dec c
    jr z, jr_001_7b27

    ld a, [de]
    and a
    jr z, jr_001_7b27

    ld b, a
    inc de
    ld hl, $7b29

jr_001_7b10:
    ld a, [hl+]
    cp $ff
    jr z, jr_001_7b04

    cp b
    jr z, jr_001_7b1b

    inc hl
    jr jr_001_7b10

jr_001_7b1b:
    ld a, [hl]
    pop hl
    ld [hl+], a
    ld a, [$cd41]
    inc a
    ld [$cd41], a
    jr jr_001_7b03

jr_001_7b27:
    pop hl
    ret


    rrca
    ld bc, $0213
    or h
    inc bc
    add hl, sp
    inc b
    ld b, [hl]
    dec b
    sub h
    ld b, $5b
    rlca
    ld h, h
    ld [$0987], sp
    rst $38
    ld hl, $d0b4
    ld a, [hl]
    srl a
    ld [hl+], a
    ld a, [hl]
    rr a
    ld [hl-], a
    or [hl]
    jr nz, jr_001_7b4c

    inc hl
    inc [hl]

jr_001_7b4c:
    ld hl, $cffc
    ld de, $d00a
    ldh a, [$f3]
    and a
    jp z, Jump_001_7b5e

    ld hl, $cfcd
    ld de, $cfdb

Jump_001_7b5e:
    ld bc, $cee7
    ld a, [hl+]
    ld [bc], a
    ld a, [hl]
    dec bc
    ld [bc], a
    ld a, [de]
    dec bc
    ld [bc], a
    inc de
    ld a, [de]
    dec bc
    ld [bc], a
    ld a, [$d0b5]
    ld b, [hl]
    add b
    ld [hl-], a
    ld [$cee8], a
    ld a, [$d0b4]
    ld b, [hl]
    adc b
    ld [hl+], a
    ld [$cee9], a
    jr c, jr_001_7b8d

    ld a, [hl-]
    ld b, a
    ld a, [de]
    dec de
    sub b
    ld a, [hl+]
    ld b, a
    ld a, [de]
    inc de
    sbc b
    jr nc, jr_001_7b99

jr_001_7b8d:
    ld a, [de]
    ld [hl-], a
    ld [$cee8], a
    dec de
    ld a, [de]
    ld [hl+], a
    ld [$cee9], a
    inc de

jr_001_7b99:
    ldh a, [$f3]
    and a
    ld hl, $c45e
    ld a, $01
    jr z, jr_001_7ba7

jr_001_7ba3:
    ld hl, $c3ca
    xor a

jr_001_7ba7:
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d
    ld a, $00
    call Call_000_3e9d
    ld a, $49
    call Call_000_3e9d
    ld hl, $4ea1
    ld b, $0f
    call Call_000_3620
    ld hl, $7bd9
    ldh a, [$f3]
    and a
    ld a, [$cfba]
    jr z, jr_001_7bcf

    ld a, [$cfb4]

jr_001_7bcf:
    cp $08
    jr nz, jr_001_7bd6

    ld hl, $7bec

jr_001_7bd6:
    jp Jump_000_3c79


    db $ed
    inc l
    ld h, d
    ld h, l
    ld c, a
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    db $dd
    ld a, a
    cp l
    or d
    call nz, $c0df
    rst $20
    ld e, b
    db $ed
    jr z, jr_001_7ba3

    ld e, a
    push de
    jp nc, $7fdd

    cp b
    rst $18
    ret nz

    rst $20
    ld e, b
    ld hl, $d6af
    set 6, [hl]
    ld a, $04
    ld [$d093], a
    call Call_000_3761
    xor a
    ld [$cc2c], a
    ld [$ccd3], a
    ld a, [$cd5b]
    bit 3, a
    jr nz, jr_001_7c1f

    ld a, $99
    call Call_000_0e45
    ld hl, $7e2e
    call Call_000_3c79

Jump_001_7c1f:
jr_001_7c1f:
    ld a, [$ccd3]
    ld [$cc26], a
    ld hl, $cd5b
    set 5, [hl]
    call Call_000_374a
    ld hl, $c3a0
    ld b, $08
    ld c, $0a
    call Call_000_03d2
    call Call_000_0ebd
    ld hl, $c3ca
    ld de, $7e08
    call Call_000_0405
    ld hl, $cc24
    ld a, $02
    ld [hl+], a
    dec a
    ld [hl+], a
    inc hl
    inc hl
    ld a, $03
    ld [hl+], a
    ld a, $03
    ld [hl+], a
    xor a
    ld [hl], a
    ld hl, $cc36
    ld [hl+], a
    ld [hl], a
    ld [$cc2f], a
    ld hl, $7e40
    call Call_000_3c79
    call Call_000_3b08
    bit 1, a
    jp nz, Jump_001_7c80

    call Call_000_3c1c
    ld a, [$cc26]
    ld [$ccd3], a
    and a
    jp z, Jump_001_7d25

    dec a
    jp z, Jump_001_7ca8

    dec a
    jp z, Jump_001_7da2

Jump_001_7c80:
    ld a, [$cd5b]
    bit 3, a
    jr nz, jr_001_7c8f

    ld a, $9a
    call Call_000_0e45
    call Call_000_3790

jr_001_7c8f:
    ld hl, $cd5b
    res 5, [hl]
    call Call_000_374a
    xor a
    ld [$cc36], a
    ld [$cc2c], a
    ld hl, $d6af
    res 6, [hl]
    xor a
    ld [$cc3c], a
    ret


Jump_001_7ca8:
    xor a
    ld [$cc26], a
    ld [$cc36], a
    ld a, [$d2a1]
    and a
    jr nz, jr_001_7cbe

    ld hl, $7e7a
    call Call_000_3c79
    jp Jump_001_7c1f


Jump_001_7cbe:
jr_001_7cbe:
    ld hl, $7e4b
    call Call_000_3c79
    ld hl, $d2a1
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    xor a
    ld [$cf7a], a
    ld a, $03
    ld [$cf7b], a
    call Call_000_16f7
    jp c, Jump_001_7c1f

    call Call_000_3121
    ld a, $01
    ld [$cf7d], a
    ld a, [$d0e9]
    and a
    jr nz, jr_001_7cfa

    ld hl, $7e58
    call Call_000_3c79
    call Call_000_186a
    cp $ff
    jp z, Jump_001_7cbe

jr_001_7cfa:
    ld hl, $d4b9
    call Call_000_16e0
    jr c, jr_001_7d0b

    ld hl, $7e90
    call Call_000_3c79
    jp Jump_001_7cbe


jr_001_7d0b:
    ld hl, $d2a1
    call Call_000_16cc
    call Call_000_3790
    ld a, $ab
    call Call_000_0e45
    call Call_000_3790
    ld hl, $7e65
    call Call_000_3c79
    jp Jump_001_7cbe


Jump_001_7d25:
    xor a
    ld [$cc26], a
    ld [$cc36], a
    ld a, [$d4b9]
    and a
    jr nz, jr_001_7d3b

    ld hl, $7edc
    call Call_000_3c79
    jp Jump_001_7c1f


Jump_001_7d3b:
jr_001_7d3b:
    ld hl, $7eaa
    call Call_000_3c79
    ld hl, $d4b9
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    xor a
    ld [$cf7a], a
    ld a, $03
    ld [$cf7b], a
    call Call_000_16f7
    jp c, Jump_001_7c1f

    call Call_000_3121
    ld a, $01
    ld [$cf7d], a
    ld a, [$d0e9]
    and a
    jr nz, jr_001_7d77

    ld hl, $7eb8
    call Call_000_3c79
    call Call_000_186a
    cp $ff
    jp z, Jump_001_7d3b

jr_001_7d77:
    ld hl, $d2a1
    call Call_000_16e0
    jr c, jr_001_7d88

    ld hl, $7eeb
    call Call_000_3c79
    jp Jump_001_7d3b


jr_001_7d88:
    ld hl, $d4b9
    call Call_000_16cc
    call Call_000_3790
    ld a, $ab
    call Call_000_0e45
    call Call_000_3790
    ld hl, $7ec6
    call Call_000_3c79
    jp Jump_001_7d3b


Jump_001_7da2:
    xor a
    ld [$cc26], a
    ld [$cc36], a
    ld a, [$d4b9]
    and a
    jr nz, jr_001_7db8

    ld hl, $7edc
    call Call_000_3c79
    jp Jump_001_7c1f


Jump_001_7db8:
jr_001_7db8:
    ld hl, $7f02
    call Call_000_3c79
    ld hl, $d4b9
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    xor a
    ld [$cf7a], a
    ld a, $03
    ld [$cf7b], a
    push hl
    call Call_000_16f7
    pop hl
    jp c, Jump_001_7c1f

    push hl
    call Call_000_3121
    pop hl
    ld a, $01
    ld [$cf7d], a
    ld a, [$d0e9]
    and a
    jr nz, jr_001_7e02

    ld a, [$cf78]
    call Call_000_1b55
    jr c, jr_001_7e02

    push hl

jr_001_7df3:
    ld hl, $7f0e
    call Call_000_3c79
    call Call_000_186a
    pop hl

jr_001_7dfd:
    cp $ff
    jp z, Jump_001_7db8

jr_001_7e02:
    call Call_000_310c
    jp Jump_001_7db8


    db $ed
    inc l
    or e
    ld b, c
    ld a, a
    res 6, a
    jr nc, @-$41

    ld c, [hl]
    inc [hl]
    or e
    jr z, jr_001_7df3

    ld a, a
    or c
    dec l
    cp c
    reti


    ld c, [hl]
    inc [hl]
    or e
    jr z, jr_001_7dfd

    ld a, a
    cp l
    jp $4ed9


    adc h
    add c
    xor h
    sub b
    db $dd
    ld a, a
    or a
    reti


jr_001_7e2d:
    ld d, b
    db $ed
    jr z, jr_001_7e02

    ld e, a
    ld e, e
    ret


    ld a, a
    adc h
    add c
    xor h
    sub b
    db $dd
    ld a, a
    or d
    jp c, $e7c0

    ld e, b
    db $ed
    jr z, jr_001_7e2d

    ld e, a
    ld a, a
    cp h
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    jr z, jr_001_7e7d

    ld h, b
    ld a, a
    or c
    dec l
    cp c
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    jr z, jr_001_7ea3

    ld h, b
    ld a, a
    or c
    dec l
    cp c
    rst $08
    cp l
    or [hl]

jr_001_7e63:
    and $57
    db $ed
    jr z, @-$6c

    ld h, b
    cp h
    sbc $33
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    or c
    dec l
    cp c
    ret nz

    rst $20
    ld e, b
    db $ed

jr_001_7e7b:
    jr z, jr_001_7e7b

jr_001_7e7d:
    ld e, a
    rst $10
    jp c, Jump_001_7fd9

    inc [hl]
    or e
    jr z, jr_001_7e63

    ld c, a
    db $d3
    rst $18
    jp $cfb2


    cp [hl]

jr_001_7e8d:
    sbc $e7
    ld e, b
    db $ed
    jr z, jr_001_7ef8

    ld h, b
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d

jr_001_7e9a:
    inc sp
    cp l
    ld c, a
    db $d3
    or e
    ld a, a
    or c
    dec l
    cp c

jr_001_7ea3:
    rst $10
    jp c, $becf

    sbc $e7
    ld e, b
    db $ed
    jr z, jr_001_7e8d

    ld h, b
    ld a, a
    res 6, a
    jr nc, @-$42

    rst $08
    cp l
    or [hl]
    and $57
    db $ed

jr_001_7eb9:
    jr z, jr_001_7eb9

    ld h, b
    ld a, a
    res 6, a
    jr nc, jr_001_7e7d

    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    jr z, jr_001_7f12

    ld h, c
    cp h
    sbc $33
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    res 6, a
    jr nc, @-$42

    ret nz

    rst $20
    ld e, b
    db $ed
    jr z, jr_001_7f5a

    ld h, c
    ld a, a
    or c
    dec l
    cp c
    jp $cfb2


    cp [hl]
    sbc $e7
    ld e, b
    db $ed
    jr z, @+$1e

    ld h, c
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    inc sp
    cp l
    ld c, a

jr_001_7ef8:
    db $d3
    or e
    ld a, a
    db $d3
    jp $becf


    sbc $e7
    ld e, b
    db $ed
    jr z, jr_001_7e9a

    ld h, c
    ld a, a
    cp l
    jp $bdcf


    or [hl]
    and $57
    db $ed
    jr z, @-$4a

    ld h, c

jr_001_7f12:
    ld a, a
    cp l
    jp $bdcf


    or [hl]
    and $57
    ld hl, $d123
    ld a, [$cf7c]
    and a
    jr z, jr_001_7f26

    ld hl, $d9b2

jr_001_7f26:
    ld a, [hl]
    dec a
    ld [hl+], a
    ld a, [$cf79]
    ld c, a
    ld b, $00
    add hl, bc
    ld e, l
    ld d, h
    inc de

jr_001_7f33:
    ld a, [de]
    inc de
    ld [hl+], a
    inc a
    jr nz, jr_001_7f33

    ld hl, $d233
    ld d, $05
    ld a, [$cf7c]
    and a
    jr z, jr_001_7f49

    ld hl, $ddb0
    ld d, $1d

jr_001_7f49:
    ld a, [$cf79]
    call Call_000_3ac7
    ld a, [$cf79]
    cp d
    jr nz, jr_001_7f58

    ld [hl], $ff
    ret


jr_001_7f58:
    ld d, h
    ld e, l

jr_001_7f5a:
    ld bc, $0006
    add hl, bc
    ld bc, $d257
    ld a, [$cf7c]
    and a
    jr z, jr_001_7f6a

    ld bc, $de64

jr_001_7f6a:
    call Call_000_395d
    ld hl, $d12b
    ld bc, $002c
    ld a, [$cf7c]
    and a
    jr z, jr_001_7f7f

    ld hl, $d9d2
    ld bc, $0021

jr_001_7f7f:
    ld a, [$cf79]
    call Call_000_3ad1
    ld d, h
    ld e, l
    ld a, [$cf7c]
    and a
    jr z, jr_001_7f96

    ld bc, $0021
    add hl, bc
    ld bc, $ddb0
    jr jr_001_7f9d

jr_001_7f96:
    ld bc, $002c
    add hl, bc
    ld bc, $d233

jr_001_7f9d:
    call Call_000_395d
    ld hl, $d257
    ld a, [$cf7c]
    and a
    jr z, jr_001_7fac

    ld hl, $de64

jr_001_7fac:
    ld bc, $0006
    ld a, [$cf79]
    call Call_000_3ad1
    ld d, h
    ld e, l
    ld bc, $0006
    add hl, bc
    ld bc, $d27b
    ld a, [$cf7c]
    and a
    jr z, jr_001_7fc7

Jump_001_7fc4:
    ld bc, $df18

jr_001_7fc7:
    jp Jump_000_395d


Call_001_7fca:
    ld hl, $d6af
    set 6, [hl]
    ld a, $3d
    call Call_000_3e9d
    ld hl, $d6af
    res 6, [hl]

Jump_001_7fd9:
    call Call_000_1b86
    ld c, $0a
    call Call_000_3781
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $01
    ld hl, $d28e
    ld a, $10
    call Call_000_3e9d
    ld a, $01
    ld [$cc3c], a
    ret


    res 6, [hl]
    call Call_000_1b86
