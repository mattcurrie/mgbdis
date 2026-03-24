; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $004", ROMX[$4000], BANK[$4]

    db $ed
    inc l
    ld d, a
    ld d, [hl]
    or [hl]
    rst $10
    jp $af90


    xor h
    ld b, d
    ld d, b
    or l
    or e
    call z, $1ab8
    xor e
    adc a
    ld d, b
    jp c, $2fde

    cp b
    ld b, b
    xor e
    sub b
    ld d, b
    and b
    dec b
    sub e
    xor e
    ld b, b
    xor e
    sub b
    ld d, b
    sub a
    adc c
    add $ba
    ld a, [hl-]
    sbc $50
    adc $c9
    or l
    ret


    ld b, b
    xor e
    sub b
    ld d, b
    jp c, $c4b2

    or e
    ld b, b
    xor e
    sub b
    ld d, b
    or [hl]
    ret nc

    push bc
    ret c

    ld b, b
    xor e
    sub b
    ld d, b
    set 3, a
    or [hl]
    cp b
    ld d, b
    jp z, $d1bb

    ld d, b
    sbc c
    adc d
    sbc [hl]
    ld b, $a8
    sub b
    xor e
    ld d, b
    or [hl]
    rst $08
    or d
    ret nz

    pop bc
    ld d, b
    jp nz, $27d9

    ret


    rst $08
    or d
    ld d, b
    or d
    or c
    or d
    daa
    ret c

    ld d, b
    or [hl]
    ld l, $b5
    cp d
    cp h
    ld d, b
    jp nz, $bb3a

    inc sp
    or e
    jp nz, $cc50

    or a
    call nz, $bc3a
    ld d, b
    cp a
    rst $10
    db $dd
    call nz, Call_004_503c
    cp h
    jp nc, $b9c2

    reti


    ld d, b
    ret nz

    ret nz

    or a
    jp nz, $d9b9

    ld d, b
    jp nz, $c9d9

    sbc a
    sub b
    ld d, b
    call z, $c2d0
    cp c
    ld d, b
    add $34
    add hl, hl
    ret c

jr_004_409c:
    ld d, b
    and b
    dec b
    sub e
    xor e
    add [hl]
    xor h
    add a
    ld d, b
    call nz, Call_000_293b
    ret c

    ld d, b
    rst $08
    call c, $29bc
    ret c

    ld d, b
    cp l
    push bc
    or [hl]
    cp c
    ld d, b
    dec l
    jp nz, Jump_004_50b7

    jp nz, Jump_000_33c9

    jp nz, $50b8

    ret nc

    jr nc, jr_004_409c

    ld [hl-], a
    or a
    ld d, b
    jp nz, Jump_000_13c9

    ret c

    and [hl]
    ld d, b
    ret nz

    or d
    or c
    ret nz

    ret c

    ld d, b
    ret


    cp h
    or [hl]
    or [hl]
    ret c

    ld d, b
    rst $08
    or a
    jp nz, $50b8

    call nz, $bcdf
    sbc $50
    or c
    ld a, [hl-]
    jp c, Jump_004_50d9

    cp l
    jp $8fd0


    xor h
    add a
    and [hl]
    ld d, b
    cp h
    rst $18
    ld c, b
    db $dd
    call z, Call_004_50d9
    inc [hl]
    cp b
    ld a, [hl-]
    ret c

    ld d, b
    rrca
    dec de
    and [hl]
    sub l
    db $e3
    inc de
    and [hl]
    ld d, b
    sbc [hl]
    adc d
    add c
    and [hl]
    ld a, [hl-]
    ret c

    ld d, b
    add $d7
    ret nc

    jp nz, $d9b9

    ld d, b
    or [hl]
    ret nc

    jp nz, $50b8

    push bc
    or a
    ld a, [hl+]
    or h
    ld d, b
    adc $b4
    reti


    ld d, b
    or e
    ret nz

    or e
    ld d, b
    pop bc
    ld [c], a
    or e
    or l
    sbc $44
    ld d, b
    adc [hl]
    sub l
    xor h
    add a
    dec de
    db $e3
    sbc a
    ld d, b
    or [hl]
    push bc
    cp h
    ld a, [hl-]
    ret c

    ld d, b
    sub $b3
    or [hl]
    or d
    or h
    or a
    ld d, b
    set 1, c
    cp d
    ld d, b
    or [hl]
    or h
    sbc $ce
    or e
    cp h
    ldh [$50], a
    cp h
    db $db
    or d
    or a
    ret c

    ld d, b

Call_004_4150:
    ret nc

    dec l
    inc sp
    rst $18
    ld c, b
    or e
    ld d, b
    sbc c
    add c
    inc de
    xor b
    ld b, e
    xor e
    ld b, d
    ld d, b
    push bc
    ret nc

    ret


    ret c

    ld d, b
    jp c, $c4b2

    or e
    ld a, [de]
    db $e3
    sbc a
    ld d, b
    call z, $b73c
    ld d, b
    adc d
    add c
    adc b
    cp d
    or e
    cp [hl]
    sbc $50
    add hl, de
    dec de

jr_004_417a:
    and [hl]
    cp d
    or e
    cp [hl]
    sbc $50

jr_004_4180:
    add h
    db $e3
    xor b
    and l
    ld a, [de]
    db $e3
    sbc a
    ld d, b
    jp z, $b2b6

    cp d
    or e
    cp [hl]
    sbc $50
    jp nz, $b8c2

    ld d, b
    inc de
    ret c

    and [hl]
    cp b
    pop bc
    ld a, [hl-]
    cp h
    ld d, b
    inc l
    ld a, [hl+]
    cp b
    jr z, jr_004_417a

    rst $08
    ld a, a
    ld d, b
    cp c
    ret nz

    jr z, jr_004_4180

    ld d, b
    add l
    add d
    xor e
    adc a
    db $e3
    ld d, b
    pop bc
    or a
    pop hl
    or e
    push bc
    add hl, hl
    ld d, b
    or [hl]
    or d
    ret c

    or a
    ld d, b
    cp l
    or d
    call nz, Call_004_50d9
    and b
    dec b
    inc de
    and a
    add c
    xor e
    ld d, b
    call nc, $d834
    daa
    ret


    adc a
    sub a
    ld d, b
    cp [hl]
    or d
    pop bc
    ld [c], a
    or e
    ld d, b
    jp z, Jump_004_44df

    add l
    xor h
    adc a
    db $e3
    ld d, b
    adc [hl]
    db $e3
    and l
    db $e3
    ld a, [de]
    db $e3
    sbc a
    ld d, b
    inc [hl]
    cp b
    ret


    cp d
    push bc
    ld d, b
    cp h
    dec sp
    jp c, $c52a

    ld d, b
    ret z

    pop de
    ret c

    ld a, [hl+]
    push bc
    ld d, b
    jp z, $3bc5

    rst $10
    ret


    rst $08
    or d
    ld d, b

Jump_004_41ff:
    or d
    call nz, $cadd
    cp b
    ld d, b
    ret c

    pop hl
    or e
    ret


    or d
    or [hl]
    ret c

    ld d, b
    adc $c9
    or l
    ret


    or e
    dec l
    ld d, b
    inc sp
    sbc $b7
    adc e
    xor a
    xor h
    add a
    ld d, b
    rst $30
    or $cf
    sbc $1c
    and [hl]
    sub e
    ld d, b
    inc sp
    sbc $2c
    jp z, $b650

    ret nc

    push bc
    ret c

    ld d, b
    or d
    call c, $c4b5
    cp h
    ld d, b
    inc l
    cp h
    sbc $50
    inc l
    call c, $50da
    or c
    push bc
    db $dd
    adc $d9
    ld d, b
    inc [hl]
    cp b
    inc [hl]
    cp b
    ld d, b
    ret z

    sbc $d8
    or a
    ld d, b
    adc d
    add c
    adc c
    add [hl]
    sub a
    adc e
    adc h
    ld d, b
    cp e
    or d
    ret nc

    sbc $2c
    pop hl
    jp nz, $a450

    dec b
    ret


    ld b, e
    db $e3
    inc c
    ld d, b
    cp d
    or e
    cp a
    cp b
    or d
    inc [hl]
    or e
    ld d, b
    inc sp
    sbc $ba
    or e
    cp [hl]
    rst $18
    or [hl]
    ld d, b
    or d
    or [hl]
    ret c

    ld d, b
    sub d
    and a
    ld b, e
    db $e3
    sub e
    ld d, b
    sub h

Jump_004_427e:
    add c
    sub e
    call Call_000_13ac
    ld d, b
    db $d3
    ret


    rst $08
    ret z

    ld d, b
    or d
    call nc, $b5c5
    call nz, $b650
    add hl, hl
    inc a
    sbc $bc
    sbc $50
    inc l
    cp d
    cp e
    or d
    cp [hl]
    or d
    ld d, b
    or [hl]
    ret nz

    cp b
    push bc
    reti


    ld d, b
    pop bc
    or d
    cp e
    cp b
    push bc
    reti


    ld d, b
    or h
    sbc $cf
    cp b
    ld d, b
    or c
    call nc, $b2bc
    res 6, [hl]
    ret c

    ld d, b
    or [hl]
    rst $10
    add $ba
    db $d3
    reti


    ld d, b
    rst $08
    reti


    cp b
    push bc
    reti


    ld d, b
    add hl, de
    ret c

    add b
    db $e3
    ld d, b
    res 6, [hl]
    ret c

    ret


    or [hl]
    dec a

jr_004_42cf:
    ld d, b
    cp b
    db $db
    or d
    or a
    ret c

    ld d, b
    ret c

    sbc e
    and a
    add a
    adc a
    db $e3
    ld d, b

jr_004_42dd:
    or a
    or c
    or d
    jr nc, @-$2c

    ld d, b
    ld h, $cf
    sbc $50
    push de
    dec sp
    db $dd
    call z, Call_004_50d9
    add h
    add d
    sbc a
    ld h, $b4
    cp h
    ld d, b
    inc l
    ld a, [hl-]
    cp b
    ld d, b
    adc a
    sbc l
    add hl, bc
    ld a, [hl-]
    cp b
    jr nc, jr_004_42dd

    ld d, b
    cp h
    ret nz

    inc sp
    push bc
    jp nc, Jump_004_50d9

    adc h
    and c
    xor h
    rlca
    ld d, b
    call $a813
    cp d
    or e
    add hl, hl
    or a
    ld d, b
    sbc h
    sub a
    cp d
    sbc $3e
    or e
    ld d, b
    jr nc, jr_004_42cf

    db $d3
    sbc $2c
    ld d, b
    ret nz

    or a
    ret


    ld a, $d8
    ld d, b
    or [hl]
    rst $10
    inc sp
    jp z, $d1bb

    ld d, b
    adc h
    ld b, c
    db $e3
    inc de
    adc h
    adc a
    db $e3
    ld d, b
    xor b
    adc b
    xor h
    sub e
    dec l
    jp nz, Jump_004_50b7

    call nz, $8629
    xor l
    sbc b
    xor e
    ld d, b
    or [hl]
    rst $10
    ret nc

    jp nz, $50b8

    inc de
    call c, $dabd
    ld d, b
    adc h
    ld b, d
    db $e3
    xor e
    rst $08
    add hl, hl
    ld d, b
    adc a
    sbc l
    add hl, bc
    or e
    ret nc

    ld d, b
    call nz, $cb3b
    dec hl
    add hl, hl
    ret c

    ld d, b
    call $c63b
    rst $10
    ret nc

    ld d, b
    push de
    jp nc, $b2b8

    ld d, b
    inc [hl]
    cp b
    dec b
    adc h
    ld d, b
    ret nz

    rst $08
    push bc
    add hl, hl

jr_004_4378:
    ld d, b
    or a
    pop hl
    or e
    cp c
    jp nz, $b150

    cp b
    rst $08
    ret


    add [hl]
    xor h
    adc h
    ld d, b
    add hl, bc
    xor h
    inc de
    add hl, de
    db $e3
    inc de
    ld d, b
    call $bcde
    sbc $50
    or c
    call c, Call_004_4150
    and h
    ld b, c
    and h
    ld b, b
    xor e
    sub b
    ld d, b
    add [hl]
    sbc b
    adc c
    ret


    adc $b3
    cp h
    ld d, b
    sbc e
    and l

jr_004_43a8:
    xor h
    adc e
    xor [hl]
    ld d, b
    adc d
    add c
    adc c
    add d
    db $eb
    db $e3
    dec de
    ld d, b
    jp z, $d9c8

    ld d, b
    call nz, $d9b9
    ld d, b
    add a
    and l
    dec de
    sbc c
    xor e
    sbc l
    db $e3
    ld d, b
    jr nc, jr_004_4378

    ld a, [hl-]
    cp b
    jp z, Jump_004_50c2

    ret nc

    jr nc, jr_004_43a8

    set 3, a
    or [hl]
    or a
    ld d, b
    sbc h
    sub a
    dec de
    db $e3
    and b
    and l
    xor e
    ld d, b
    ret z

    pop de
    reti


    ld d, b
    or d
    call c, $30c5
    jp c, $cb50

    rst $18
    cp e
    jp nz, $b4cf

    ld a, [hl-]
    ld d, b
    or [hl]
    cp b
    ld a, [hl-]
    reti


    ld d, b
    sub d
    add a
    adc h
    sub b
    xor l
    db $e3
    ld d, b
    sub e
    and l
    add c
    add b
    adc a
    xor h
    add a
    ld d, b
    or d
    or [hl]
    ret c

    ret


    rst $08
    or h
    ld a, [hl-]
    ld d, b
    or a
    ret c

    cp e
    cp b
    ld d, b
    ret nc

    ld h, $dc
    ret c

    ld d, b
    call c, $b1d9
    ld h, $b7
    ld d, b
    nop
    nop
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $f3f3
    rst $30
    rst $30
    or $f6
    or $f6
    rst $30
    rst $30
    rst $30
    rst $30
    di
    di
    ret nz

    ret nz

    rst $20
    rst $20
    rst $30
    rst $30
    ld [hl], a
    ld [hl], a
    scf
    scf
    scf
    scf
    rst $30
    rst $30
    rst $20
    rst $20
    nop
    nop
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
    nop
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
    inc bc
    inc bc
    nop
    nop
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    nop
    nop
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    nop
    nop
    rst $38
    rst $38
    cp $fe
    rst $38
    rst $38
    cp $fe
    db $fc
    db $fc
    cp $fe
    cp $fe
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    nop
    nop
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    add b
    add b
    nop
    nop
    ret nz

    ret nz

    add b
    add b
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
    nop
    nop
    ldh a, [$f0]
    ld hl, sp-$08

Jump_004_44df:
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    nop
    nop
    ld a, h
    ld a, h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fe
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
    nop
    nop
    nop
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
    ld bc, $7f7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    pop af
    pop af
    ldh a, [$f0]
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
    rst $00
    rst $00
    rlca
    rlca
    rst $08
    rst $08
    adc a
    adc a
    rst $08
    rst $08
    rra
    rra
    sbc a
    sbc a
    ccf
    ccf
    ret nz

    ret nz

    ret nz

    ret nz

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
    nop
    nop
    nop
    ldh a, [$f0]
    ldh [$e0], a
    ldh a, [$f0]
    ret nz

    ret nz

    ldh [$e0], a
    add b
    add b
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
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    rra
    rra
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $fc01
    db $fc
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
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
    nop
    nop
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
    ld bc, $0101
    ld bc, $0101
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    ld hl, sp-$08
    ld sp, hl
    ld sp, hl
    ld sp, hl
    ld sp, hl
    ld sp, hl
    ld sp, hl
    di
    di
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    ld hl, sp-$08
    ld hl, sp-$08
    ld hl, sp-$08
    ld hl, sp-$08
    ld hl, sp-$08
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $1111
    rst $38
    rst $38
    rst $38
    rst $38
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    pop af
    pop af
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, [hl]
    ld a, [hl]
    cp $fe
    db $fc
    db $fc
    ld a, h
    ld a, h
    jr c, jr_004_467f

    db $10
    db $10
    rst $38
    rst $38
    rst $38
    rst $38
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ret nz

    ret nz

    add b
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    adc $ce
    rst $28
    rst $28
    rst $28
    rst $28
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
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38

jr_004_467f:
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
    rst $18
    rst $18
    sbc a
    sbc a
    sbc a
    sbc a
    rra
    rra
    sbc a
    sbc a
    rra
    rra
    add c
    add c
    add c
    add c
    rst $38
    rst $38
    cp $fe
    rst $38
    rst $38
    db $fc
    db $fc
    cp $fe
    rst $38
    rst $38
    ldh a, [$f0]
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
    ld [$1808], sp
    jr @+$1e

    inc e
    dec a
    dec a
    ld bc, $0101
    ld bc, $0303
    inc bc
    inc bc
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rrca
    rrca
    di
    di
    di
    di
    pop af
    pop af
    ldh a, [$f0]
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    or $f6
    rst $30
    rst $30
    rst $30
    rst $30
    rst $28
    rst $28
    ld l, a
    ld l, a
    rlca
    rlca
    inc bc
    inc bc
    ld bc, $7e01
    ld a, [hl]
    ld a, [hl]
    ld a, [hl]
    cp $fe
    cp $fe
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    ld hl, sp-$08
    nop
    nop
    rst $38
    rst $38
    cp $fe
    rst $38
    rst $38
    cp $fe
    cp $fe
    db $fc
    db $fc
    cp $fe
    add hl, de
    add hl, de
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, c
    ld a, c
    di
    di
    rst $30
    rst $30
    rst $30
    rst $30
    rst $30
    rst $30
    rst $30
    rst $30
    di
    di
    di
    di
    di
    di
    nop
    nop
    add b
    add b
    add b
    add b
    add b
    add b
    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    ldh [$e0], a
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, h
    ld a, h
    db $fc
    db $fc
    db $fc
    db $fc
    rst $28
    rst $28
    rst $28
    rst $28
    rst $28
    rst $28
    rst $28
    rst $28
    rst $28
    rst $28
    nop
    nop
    ld bc, $0301
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ld h, e
    ld h, e
    di
    di
    ei
    ei
    ei
    ei
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $f0f0
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    ld bc, $0301
    inc bc
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    cp a
    cp a
    ld a, a
    ld a, a
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    cp $fe
    cp $fe
    db $fc
    db $fc
    adc a
    adc a
    sbc a
    sbc a
    sbc a
    sbc a
    ccf
    ccf
    ccf
    ccf
    ld a, [hl]
    ld a, [hl]
    ld a, [hl]
    ld a, [hl]
    db $fc
    db $fc
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    db $fc
    db $fc
    ld a, [hl]
    ld a, [hl]
    ld a, [hl]
    ld a, [hl]
    ccf
    ccf
    ld bc, $0301
    inc bc
    inc bc
    inc bc
    rlca
    rlca
    rlca
    rlca
    rrca
    rrca
    rrca
    rrca
    rra
    rra
    ld hl, sp-$08
    ld hl, sp-$08
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ldh [$e0], a
    ldh [$e0], a
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, c
    ld a, c
    ld sp, hl
    ld sp, hl
    pop af
    pop af
    pop af
    pop af
    pop af
    pop af
    ld h, c
    ld h, c
    ld hl, $0121
    ld bc, $f1f1
    pop af
    pop af
    pop af
    pop af
    ldh a, [$f0]
    ldh a, [$f0]
    ldh a, [$f0]
    ret nc

    ret nc

    ld b, b
    ld b, b
    pop hl
    pop hl
    pop af
    pop af
    di
    di
    di
    di
    push hl
    push hl
    jp Jump_000_01c3


    ld bc, $0000
    db $fc
    db $fc
    ld hl, sp-$08
    ld hl, sp-$08
    ldh a, [$f0]
    ldh a, [$f0]
    ldh [$e0], a
    ld h, b
    ld h, b
    ret nz

    ret nz

    inc bc
    inc bc
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rla
    rla
    rrca
    rrca
    ld a, [bc]
    ld a, [bc]
    inc b
    inc b
    ei
    ei
    di
    di
    db $e3
    db $e3
    jp $83c3


    add e
    inc bc
    inc bc
    inc bc
    inc bc
    ld [bc], a
    ld [bc], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    and b
    and b
    add b
    add b
    ld bc, $0101
    ld bc, $0101
    nop
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
    cp $fe
    rst $38
    rst $38
    cp $fe
    ld a, a
    ld a, a
    ld a, $3e
    nop
    nop
    ccf
    ccf
    sbc a
    sbc a
    rra
    rra
    rrca
    rrca
    rrca
    rrca
    rlca
    rlca
    ld b, $06
    nop
    nop
    ld hl, sp-$08
    pop af
    pop af
    pop hl
    pop hl
    jp $83c3


    add e
    nop
    nop
    nop
    nop
    nop
    nop
    db $fc
    db $fc
    db $fc
    db $fc
    ld hl, sp-$08
    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    ld d, b
    ld d, b
    jr nz, jr_004_48f7

    nop
    nop
    ccf
    ccf
    rra
    rra
    ld e, $1e
    inc c
    inc c
    ld [$0008], sp
    nop
    nop
    nop
    nop
    nop
    rra
    rra
    ccf
    ccf
    ld a, a
    ld a, a
    ccf
    ccf
    ld a, a
    ld a, a
    ld e, $1e
    ld b, $06

jr_004_48f7:
    inc b

Call_004_48f8:
    inc b
    ret nz

    ret nz

    add b
    add b
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ldh a, [rP1]
    ret c

    nop
    ret c

    nop
    ret c

    nop
    ldh a, [rP1]
    ret nz

    nop
    ret nz

    nop
    nop
    nop
    ldh a, [rP1]
    ret c

    nop
    ret c

    nop
    ret c

    nop
    ret c

    nop
    ret c

    nop
    ld a, b
    nop
    nop
    nop
    ldh a, [rP1]
    ret c

    nop
    ret nz

    nop
    ret nz

    nop
    ret nz

    nop
    ret c

    nop
    ld a, b
    nop
    nop
    nop
    ret c

    nop
    ret c

    nop
    ldh a, [rP1]
    ldh [rP1], a
    ret c

    nop
    ret c

    nop
    ret c

    nop
    nop
    nop
    ld hl, sp+$00
    ret nz

    nop
    ret nz

    nop
    ld hl, sp+$00
    ret nz

    nop
    ret nz

    nop
    ld hl, sp+$00
    nop
    nop
    db $fc
    nop
    jr nc, jr_004_4a6e

jr_004_4a6e:
    jr nc, jr_004_4a70

jr_004_4a70:
    jr nc, jr_004_4a72

jr_004_4a72:
    jr nc, jr_004_4a74

jr_004_4a74:
    jr nc, jr_004_4a76

jr_004_4a76:
    jr nc, jr_004_4a78

jr_004_4a78:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add d
    nop
    add $00
    xor $00
    cp $00
    sub $00
    add $00
    add $00
    nop
    nop
    inc a
    nop
    ld [hl], $00
    ld [hl], $00
    ld [hl], $00
    ld [hl], $00
    ld [hl], $00
    ld e, $00
    nop
    nop
    inc hl
    nop
    inc sp
    nop
    dec sp
    nop
    ccf
    nop
    scf
    nop
    inc sp
    nop
    ld sp, $0000
    nop
    rrca
    nop
    jr jr_004_4ace

jr_004_4ace:
    jr jr_004_4ad0

jr_004_4ad0:
    rra
    nop
    inc bc
    nop
    inc bc
    nop
    ld e, $00
    nop
    nop
    rra
    nop
    ld b, $00
    ld b, $00
    ld b, $00
    ld b, $00
    ld b, $00
    ld b, $00
    nop
    nop
    sbc a
    nop
    jr jr_004_4aee

jr_004_4aee:
    jr jr_004_4af0

jr_004_4af0:
    rra
    nop
    jr jr_004_4af4

jr_004_4af4:
    jr jr_004_4af6

jr_004_4af6:
    rra
    nop
    nop
    nop
    ld e, $00
    dec de
    nop
    dec de
    nop
    dec de
    nop
    ld e, $00
    dec de
    nop
    add hl, de
    nop
    nop
    nop
    rrca
    nop
    jr jr_004_4b0e

jr_004_4b0e:
    jr jr_004_4b10

jr_004_4b10:
    rra
    nop
    inc bc
    nop
    inc bc
    nop
    ld e, $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr nc, @+$7a

    ld a, b
    ld a, b
    jr nc, jr_004_4b27

jr_004_4b27:
    jr nc, jr_004_4b29

jr_004_4b29:
    ld l, h
    ld l, h
    ld l, h
    nop
    nop
    nop
    nop
    nop
    ld l, h
    ld l, h
    cp $6c
    cp $6c
    ld l, h
    nop
    jr nc, @+$7e

    ret nz

    ld a, b
    inc c
    ld hl, sp+$30
    nop
    nop
    add $cc
    jr @+$32

    ld h, [hl]
    add $00
    jr c, @+$6e

    jr c, jr_004_4bc3

    call c, $76cc
    nop
    ld h, b
    ld h, b
    ret nz

    nop
    nop
    nop
    nop
    nop
    jr jr_004_4b8b

    ld h, b
    ld h, b
    ld h, b
    jr nc, jr_004_4b78

    nop
    ld h, b
    jr nc, jr_004_4b7c

    jr jr_004_4b7e

    jr nc, @+$62

    nop
    nop
    ld h, [hl]
    inc a
    rst $38
    inc a
    ld h, [hl]
    nop
    nop
    nop
    jr nc, @+$32

    db $fc
    jr nc, jr_004_4ba7

    nop

jr_004_4b78:
    nop
    nop
    nop
    nop

jr_004_4b7c:
    nop
    nop

jr_004_4b7e:
    jr nc, @+$32

    ld h, b
    nop
    nop
    nop
    db $fc
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_4b8b:
    nop
    nop
    nop
    jr nc, @+$32

    nop
    ld b, $0c
    jr jr_004_4bc5

    ld h, b
    ret nz

    add b
    nop
    ld a, h
    add $ce
    sbc $f6
    and $7c
    nop
    jr nc, @+$72

    jr nc, jr_004_4bd5

    jr nc, jr_004_4bd7

jr_004_4ba7:
    db $fc
    nop
    ld a, b
    call z, Call_000_380c
    ld h, b
    call z, $00fc
    ld a, b
    call z, Call_000_380c
    inc c
    call z, Call_000_0078
    inc e
    inc a
    ld l, h
    call z, Call_000_0cfe
    ld e, $00
    db $fc
    ret nz

jr_004_4bc3:
    ld hl, sp+$0c

jr_004_4bc5:
    inc c
    call z, Call_000_0078
    jr c, jr_004_4c2b

    ret nz

    ld hl, sp-$34
    call z, Call_000_0078
    db $fc
    call z, Call_000_180c

jr_004_4bd5:
    jr nc, jr_004_4c07

jr_004_4bd7:
    jr nc, jr_004_4bd9

jr_004_4bd9:
    ld a, b
    call z, Call_004_78cc
    call z, Call_004_78cc
    nop
    ld a, b
    call z, $7ccc
    inc c
    jr @+$72

    nop
    nop
    jr nc, jr_004_4c1c

    nop
    nop
    jr nc, jr_004_4c20

    nop
    nop
    jr nc, @+$32

    nop
    nop
    jr nc, @+$32

    ld h, b
    jr jr_004_4c2b

    ld h, b
    ret nz

    ld h, b
    jr nc, @+$1a

    nop
    nop
    nop
    db $fc
    nop
    nop
    db $fc

jr_004_4c07:
    nop
    nop
    ld h, b
    jr nc, @+$1a

    inc c
    jr jr_004_4c3f

    ld h, b
    nop
    ld a, b
    call z, Call_000_180c
    jr nc, jr_004_4c17

jr_004_4c17:
    jr nc, jr_004_4c19

jr_004_4c19:
    ld a, h
    add $de

jr_004_4c1c:
    sbc $de
    ret nz

    ld a, b

jr_004_4c20:
    nop
    jr nc, jr_004_4c9b

    call z, $fccc
    call z, Call_000_00cc
    db $fc
    ld h, [hl]

jr_004_4c2b:
    ld h, [hl]
    ld a, h
    ld h, [hl]
    ld h, [hl]
    db $fc
    nop
    inc a
    ld h, [hl]
    ret nz

    ret nz

    ret nz

    ld h, [hl]
    inc a
    nop
    ld hl, sp+$6c
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld l, h

jr_004_4c3f:
    ld hl, sp+$00
    ld a, [hl]
    ld h, b
    ld h, b
    ld a, b
    ld h, b
    ld h, b
    ld a, [hl]
    nop
    ld a, [hl]
    ld h, b
    ld h, b
    ld a, b
    ld h, b
    ld h, b
    ld h, b
    nop
    inc a
    ld h, [hl]
    ret nz

    ret nz

    adc $66
    ld a, $00
    call z, $cccc
    db $fc
    call z, $cccc
    nop
    ld a, b
    jr nc, @+$32

    jr nc, @+$32

    jr nc, @+$7a

    nop
    ld e, $0c
    inc c
    inc c
    call z, Call_004_78cc
    nop
    and $66
    ld l, h
    ld a, b
    ld l, h
    ld h, [hl]
    and $00
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld a, [hl]
    nop
    add $ee
    cp $fe
    sub $c6
    add $00
    add $e6
    or $de
    adc $c6
    add $00
    jr c, @+$6e

    add $c6
    add $6c
    jr c, jr_004_4c99

jr_004_4c99:
    db $fc
    ld h, [hl]

jr_004_4c9b:
    ld h, [hl]
    ld a, h
    ld h, b
    ld h, b
    ldh a, [rP1]
    ld a, b
    call z, $cccc
    call c, Call_000_1c78
    nop
    db $fc
    ld h, [hl]
    ld h, [hl]
    ld a, h
    ld l, h
    ld h, [hl]
    and $00
    ld a, b
    call z, $70e0
    inc e
    call z, Call_000_0078
    db $fc
    jr nc, jr_004_4cec

    jr nc, jr_004_4cee

    jr nc, @+$32

    nop
    call z, $cccc
    call z, $cccc
    db $fc
    nop
    call z, $cccc
    call z, Call_004_78cc
    jr nc, jr_004_4cd1

jr_004_4cd1:
    add $c6
    add $d6
    cp $ee
    add $00
    add $c6
    ld l, h
    jr c, jr_004_4d16

    ld l, h
    add $00
    call z, $cccc
    ld a, b
    jr nc, jr_004_4d17

    ld a, b
    nop
    cp $06
    inc c

jr_004_4cec:
    jr jr_004_4d1e

jr_004_4cee:
    ld h, b
    cp $00
    ld a, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld a, b
    nop
    ret nz

    ld h, b
    jr nc, jr_004_4d15

    inc c
    ld b, $02
    nop
    ld a, b
    jr @+$1a

    jr jr_004_4d1e

    jr jr_004_4d80

    nop
    db $10
    jr c, @+$6e

    add $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_4d15:
    nop

jr_004_4d16:
    nop

jr_004_4d17:
    nop
    rst $38
    jr nc, jr_004_4d4b

    jr jr_004_4d1d

jr_004_4d1d:
    nop

jr_004_4d1e:
    nop
    nop
    nop
    nop
    nop
    ld a, b
    inc c
    ld a, h
    call z, Call_000_0076
    ldh [$60], a
    ld h, b
    ld a, h
    ld h, [hl]
    ld h, [hl]
    call c, RST_00
    nop
    ld a, b
    call z, $ccc0
    ld a, b
    nop
    inc e
    inc c
    inc c
    ld a, h
    call z, $76cc
    nop
    nop
    nop
    ld a, b
    call z, $c0fc
    ld a, b
    nop
    jr c, jr_004_4db7

jr_004_4d4b:
    ld h, b
    ldh a, [$60]
    ld h, b
    ldh a, [rP1]
    nop
    nop
    db $76
    call z, $7ccc
    inc c
    ld hl, sp-$20
    ld h, b
    ld l, h
    db $76
    ld h, [hl]
    ld h, [hl]
    and $00
    jr nc, jr_004_4d63

jr_004_4d63:
    ld [hl], b
    jr nc, @+$32

    jr nc, @+$7a

    nop
    inc c
    nop
    inc c
    inc c
    inc c
    call z, Call_004_78cc
    ldh [$60], a
    ld h, [hl]
    ld l, h
    ld a, b
    ld l, h
    and $00
    ld [hl], b
    jr nc, @+$32

    jr nc, jr_004_4dae

    jr nc, jr_004_4df8

jr_004_4d80:
    nop
    nop
    nop
    call z, $fefe
    sub $c6
    nop
    nop
    nop
    ld hl, sp-$34
    call z, $cccc
    nop
    nop
    nop
    ld a, b
    call z, $cccc
    ld a, b
    nop
    nop
    nop
    call c, $6666
    ld a, h
    ld h, b
    ldh a, [rP1]
    nop
    db $76
    call z, $7ccc
    inc c
    ld e, $00
    nop
    call c, Call_004_6676

jr_004_4dae:
    ld h, b
    ldh a, [rP1]
    nop
    nop
    ld a, h
    ret nz

    ld a, b
    inc c

jr_004_4db7:
    ld hl, sp+$00
    db $10
    jr nc, jr_004_4e38

    jr nc, @+$32

    inc [hl]
    jr jr_004_4dc1

jr_004_4dc1:
    nop
    nop
    call z, $cccc
    call z, Call_000_0076
    nop
    nop
    call z, $cccc
    ld a, b
    jr nc, jr_004_4dd1

jr_004_4dd1:
    nop
    nop
    add $d6
    cp $fe
    ld l, h
    nop
    nop
    nop
    add $6c
    jr c, jr_004_4e4b

    add $00
    nop
    nop
    call z, $cccc
    ld a, h
    inc c
    ld hl, sp+$00
    nop
    db $fc
    sbc b
    jr nc, jr_004_4e53

    db $fc
    nop
    inc e
    jr nc, jr_004_4e24

    ldh [$30], a
    jr nc, @+$1e

jr_004_4df8:
    nop
    jr jr_004_4e13

    jr jr_004_4dfd

jr_004_4dfd:
    jr jr_004_4e17

    jr jr_004_4e01

jr_004_4e01:
    ldh [$30], a
    jr nc, @+$1e

    jr nc, jr_004_4e37

    ldh [rP1], a
    db $76
    call c, RST_00
    nop
    nop
    nop
    nop
    nop
    db $10

jr_004_4e13:
    jr c, jr_004_4e81

    add $c6

jr_004_4e17:
    cp $00
    nop
    nop
    ld d, b
    ld a, b
    call nc, Call_000_2844
    jr nz, jr_004_4e22

jr_004_4e22:
    nop
    db $10

jr_004_4e24:
    cp b
    call nc, Call_000_3894
    stop
    nop
    db $10
    jr jr_004_4e3e

    ld [hl], b
    sbc b
    ld [hl], b
    nop
    nop
    nop
    nop
    ld a, [hl]
    nop

jr_004_4e37:
    nop

jr_004_4e38:
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_4e3e:
    ld c, $0a
    ld c, $00
    nop
    nop
    nop
    nop
    inc b
    ld [de], a
    ld [$7e00], sp

jr_004_4e4b:
    rst $20
    adc $18
    nop
    jr jr_004_4e69

    jr jr_004_4e8f

jr_004_4e53:
    inc a
    inc a
    jr jr_004_4e57

jr_004_4e57:
    jr jr_004_4e71

    nop
    nop
    nop
    nop
    nop
    ld [hl], b
    ld d, b
    ld [hl], b
    nop
    nop
    nop
    ld hl, sp+$08

jr_004_4e66:
    jr z, jr_004_4e98

    ld b, b

jr_004_4e69:
    nop
    nop
    nop
    jr nz, jr_004_4e66

    adc b
    db $10
    ld h, b

jr_004_4e71:
    nop
    nop
    nop
    nop
    ld [hl], b
    jr nz, jr_004_4e98

    ld hl, sp+$00
    ld h, b
    ld d, b
    ld c, b
    ld b, h
    ld c, b
    ld d, b
    ld h, b

jr_004_4e81:
    nop
    ld h, b
    ld [hl], b
    ld a, b
    ld a, h
    ld a, b
    ld [hl], b
    ld h, b
    nop
    cp $fe
    ld a, h
    jr c, jr_004_4e9f

jr_004_4e8f:
    nop
    nop
    db $10
    jr c, @+$56

    sub d
    jr c, jr_004_4edb

    ld b, h

jr_004_4e98:
    jr c, jr_004_4e9a

jr_004_4e9a:
    cp $92
    sub d
    cp $82

jr_004_4e9f:
    add d
    add [hl]
    nop
    nop
    ld b, h
    jr z, @+$12

    jr z, jr_004_4eec

    nop
    nop
    nop
    nop
    nop
    nop
    jr nc, @+$32

    nop
    nop
    ld [bc], a
    inc b
    ld [$2010], sp
    ld b, b
    add b
    nop
    nop

Call_004_4ebb:
    nop
    db $10
    ld hl, sp+$30
    ld d, b
    sub b
    jr c, @+$46

    ld b, h
    jr c, @+$12

    ld a, h
    db $10
    stop
    nop
    jr c, jr_004_4f19

    add $c6
    ld h, h
    jr c, jr_004_4ed2

jr_004_4ed2:
    nop
    jr @+$3a

    jr @+$1a

    jr jr_004_4f57

    nop
    nop

jr_004_4edb:
    ld a, h
    add $0e
    ld a, b
    ldh [$fe], a
    nop
    nop
    ld a, [hl]
    inc c
    jr c, jr_004_4eed

    add $7c
    nop
    nop
    inc e

jr_004_4eec:
    inc a

jr_004_4eed:
    ld l, h
    call z, Call_000_0cfe
    nop
    nop
    db $fc
    ret nz

    db $fc
    ld b, $c6
    ld a, h
    nop
    nop
    ld a, h
    ret nz

    db $fc
    add $c6
    ld a, h
    nop
    nop
    cp $c6
    inc c
    jr jr_004_4f38

    jr nc, jr_004_4f0a

jr_004_4f0a:
    nop
    ld a, h
    add $7c
    add $c6
    ld a, h
    nop
    nop
    ld a, h
    add $c6
    ld a, [hl]
    ld b, $7c

jr_004_4f19:
    nop
    nop
    nop
    nop
    inc a
    inc a
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld a, [hl]
    ld a, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    nop
    nop
    nop
    nop
    ld a, h
    ld a, h
    ld h, [hl]
    ld h, [hl]
    ld a, h
    ld a, h
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, [hl]
    ld a, h

jr_004_4f38:
    ld a, h
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    ld d, c
    ld d, c
    pop bc
    pop bc
    db $10
    stop
    nop
    nop
    nop
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

jr_004_4f57:
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
    rst $38
    rst $38
    nop
    add b
    nop
    add b
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
    rst $38
    rst $38
    nop
    ret nz

    nop
    ret nz

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
    rst $38
    rst $38
    nop
    ldh [rP1], a
    ldh [rIE], a
    rst $38
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
    nop
    ldh a, [rP1]
    ldh a, [rIE]
    rst $38
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
    nop
    ld hl, sp+$00
    ld hl, sp-$01
    rst $38
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
    nop
    db $fc
    nop
    db $fc
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
    rst $38
    rst $38
    nop
    cp $00
    cp $ff
    rst $38
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
    nop
    rst $38
    nop
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
    add b
    add b
    add b
    add b
    nop
    nop
    jr z, jr_004_5013

    jr z, jr_004_5015

    jr z, jr_004_5017

    jr z, jr_004_5019

    jr z, jr_004_501b

    xor b
    xor b
    xor b
    xor b
    jr z, jr_004_5021

    nop
    nop
    nop
    nop
    nop
    nop
    jr jr_004_5019

    ld e, b
    ld e, b
    jr jr_004_501d

    ld e, b
    ld e, b
    ld e, $1e
    nop
    nop
    inc bc
    inc bc
    rrca
    rrca
    ccf
    ccf
    rst $38
    rst $38

jr_004_5013:
    nop
    nop

jr_004_5015:
    nop
    nop

jr_004_5017:
    nop
    nop

jr_004_5019:
    ld a, [hl+]
    ld a, [hl+]

jr_004_501b:
    ld a, [hl+]
    ld a, [hl+]

jr_004_501d:
    jr nz, jr_004_503f

    inc a
    inc a

jr_004_5021:
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    ld a, $3e
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld a, e
    ld a, e
    ld l, e
    ld l, e
    ld a, $3e
    ld [hl+], a

Call_004_503c:
    ld [hl+], a
    ld l, $2e

jr_004_503f:
    jr z, jr_004_5069

    jr z, jr_004_506b

    jr c, jr_004_507d

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld e, h
    ld e, h
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld e, h
    ld e, h
    nop
    nop
    nop
    nop
    nop
    nop
    sub b
    sub b
    rst $10
    rst $10
    push af
    push af
    or l
    or l
    sub a
    sub a
    nop
    nop

jr_004_5069:
    nop
    nop

jr_004_506b:
    nop
    nop
    nop
    nop
    nop
    nop
    sub d
    sub d
    nop
    nop
    nop
    nop
    nop
    nop

Jump_004_5079:
    nop
    nop
    nop
    nop

jr_004_507d:
    nop
    nop

Jump_004_507f:
    cp $fe
    cp $fe
    nop
    nop
    nop
    nop
    nop
    nop
    cp $fe
    cp $fe
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    ldh a, [$f0]
    db $fc
    db $fc
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
    rrca
    rrca
    db $10
    db $10
    daa
    daa
    cpl
    cpl
    inc l
    inc l

Jump_004_50b7:
jr_004_50b7:
    jr z, jr_004_50e1

Call_004_50b9:
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38

Jump_004_50c2:
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
    ldh [$e0], a
    db $10
    db $10
    ret z

    ret z

    add sp, -$18
    ld l, b
    ld l, b
    jr z, jr_004_5101

Call_004_50d9:
Jump_004_50d9:
    jr z, jr_004_5103

    jr z, jr_004_5105

    jr z, jr_004_5107

    jr z, jr_004_5109

jr_004_50e1:
    jr z, jr_004_510b

    jr z, jr_004_510d

    jr z, jr_004_510f

    jr z, jr_004_5111

    jr z, jr_004_5113

    jr z, jr_004_5115

    daa
    daa
    jr nc, @+$32

    rra
    rra
    rrca
    rrca
    nop
    nop
    nop
    nop
    jr z, jr_004_5123

    jr z, @+$2a

    ret z

    ret z

    jr jr_004_5119

jr_004_5101:
    ldh a, [$f0]

jr_004_5103:
    ldh [$e0], a

jr_004_5105:
    nop
    nop

jr_004_5107:
    nop
    nop

jr_004_5109:
    nop
    nop

jr_004_510b:
    nop
    nop

jr_004_510d:
    nop
    nop

jr_004_510f:
    nop
    nop

jr_004_5111:
    nop
    nop

jr_004_5113:
    nop
    nop

jr_004_5115:
    nop
    nop
    nop
    nop

jr_004_5119:
    jr jr_004_5133

    jr jr_004_5135

    jr jr_004_50b7

    sbc b
    jr jr_004_5122

jr_004_5122:
    nop

jr_004_5123:
    nop
    jr jr_004_517e

    jr jr_004_5180

    ld e, $00

jr_004_512a:
    inc bc
    rrca
    ccf
    rst $38
    nop
    nop
    nop
    jr jr_004_514b

jr_004_5133:
    jr jr_004_514d

jr_004_5135:
    jr jr_004_514f

    jr jr_004_5151

    jr jr_004_5153

    jr @+$21

    rrca
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sub d
    nop
    nop
    nop
    nop
    nop

jr_004_514b:
    nop
    rst $38

jr_004_514d:
    rst $38
    nop

jr_004_514f:
    nop
    nop

jr_004_5151:
    jr jr_004_516b

jr_004_5153:
    jr jr_004_514d

    ldh a, [rP1]
    nop
    nop
    nop
    ret nz

    ldh a, [$fc]
    rst $38
    nop
    nop
    nop
    ld a, h
    jr c, jr_004_512a

    ld b, h
    cp d
    sbc d
    and d
    and d
    cp d
    sbc d

jr_004_516b:
    add $44
    ld a, h
    jr c, jr_004_5170

jr_004_5170:
    nop
    nop
    nop
    rst $28
    rst $20
    ld l, l
    ld l, l
    ld l, a
    ld l, a
    ld h, c
    ld h, c
    ld l, a
    ld l, a
    nop

jr_004_517e:
    nop
    nop

jr_004_5180:
    nop
    nop
    nop
    cp [hl]
    inc e
    or [hl]
    or [hl]
    cp [hl]
    cp [hl]
    add [hl]
    add [hl]
    inc a
    inc a
    nop
    nop
    nop
    nop
    nop
    nop
    ld hl, sp-$08
    ret nz

    ret nz

    ld hl, sp-$08
    jr jr_004_51b3

    ld hl, sp-$10
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, e
    ld a, c
    jp $dbc3


    db $db
    db $db
    db $db
    ld a, e
    ld a, e
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_51b3:
    add sp, -$38
    ld l, h
    ld l, h
    rst $28
    xor $6d
    ld l, l
    ld l, h
    ld l, h
    nop
    nop
    nop
    nop
    nop
    nop
    cpl
    cpl
    ld l, h
    ld l, h
    rst $28
    rst $28
    ld l, h
    ld l, h
    ld l, a
    ld l, a
    nop
    nop
    nop
    nop
    nop
    nop
    ld e, $1e
    jr jr_004_51ef

    ld e, $1e
    jr jr_004_51f3

    jr @+$1a

    nop
    nop
    nop
    nop
    nop
    nop
    ei
    di
    db $db
    db $db
    ei
    di
    db $db
    db $db
    db $db
    db $db
    nop
    nop

jr_004_51ef:
    nop
    nop
    nop
    nop

jr_004_51f3:
    rst $18
    adc $1b
    dec de
    rst $18
    rst $18
    dec de
    dec de
    db $db
    db $db
    nop
    nop
    nop
    nop
    nop
    nop
    ld l, h
    ld l, h
    ld l, h
    ld l, h
    ld a, b
    ld [hl], b
    ld l, h
    ld l, h
    ld l, h
    ld l, h
    nop
    nop
    nop
    nop
    nop
    nop
    ld h, b
    ld h, b
    ld l, a
    ld l, [hl]
    ld l, l
    ld l, l
    ld l, l
    ld l, l
    ld l, l
    ld l, l
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, b
    jr c, jr_004_5288

    ld h, b
    ld h, e
    ld h, e
    ld a, e
    dec sp
    nop
    nop
    nop
    nop
    nop
    nop
    call $eccd
    db $ec
    db $dd
    db $dd
    db $dd
    db $dd
    call Call_000_00cd
    nop
    nop
    nop
    nop
    nop
    add b
    add b
    dec a
    dec a
    or [hl]
    or [hl]
    or [hl]
    or [hl]
    or [hl]
    or [hl]
    nop
    nop
    nop
    nop
    nop
    nop
    ret nz

    ret nz

    xor $ee
    jp c, $dcda

    call c, $cece
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    pop af
    pop af
    db $db
    db $db
    db $db
    db $db
    reti


    reti


    nop
    nop
    nop
    nop
    nop
    nop
    ld h, b
    ld h, b
    rst $20
    rst $20
    ld l, l
    ld l, l
    ld l, l
    ld l, l
    rst $20
    rst $20
    nop
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

jr_004_5288:
    add b
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
    ld a, b
    ld a, b
    db $e3
    jp $c3e3


    db $e3
    jp Jump_004_7b7b


    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    call c, $bddc
    dec [hl]
    add hl, sp
    add hl, sp
    inc e
    inc e
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    rst $30
    rst $30
    or e
    or e
    di
    or e
    ei
    ei
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    or [hl]
    or [hl]
    ld [hl], $36
    ld a, $36
    ld e, $1e
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rst $30
    rst $30
    rst $28
    call $cece
    rst $00
    rst $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc a
    inc a
    ld a, b
    ld [hl], b
    inc a
    inc e
    ld a, b
    ld a, b
    nop
    nop
    nop
    nop
    nop
    nop
    jr c, @+$3a

    ld l, h
    ld l, h
    add $c6
    add $c6
    cp $fe
    add $c6
    nop
    nop
    nop
    nop
    db $fc
    db $fc
    add $c6
    db $fc
    db $fc
    add $c6
    add $c6
    db $fc
    db $fc
    nop
    nop
    nop
    nop
    ld a, h
    ld a, h
    and $e6
    ret nz

    ret nz

    ret nz

    ret nz

    and $e6
    ld a, h
    ld a, h
    nop
    nop
    nop
    nop
    ld hl, sp-$08
    call z, $c6cc
    add $c6
    add $cc
    call z, $f8f8
    nop
    nop
    nop
    nop
    cp $fe
    ret nz

    ret nz

    db $fc
    db $fc
    ret nz

    ret nz

    ret nz

    ret nz

    cp $fe
    nop
    nop
    nop
    nop
    cp $fe
    ret nz

    ret nz

    ret nz

    ret nz

    db $fc
    db $fc
    ret nz

    ret nz

    ret nz

    ret nz

    nop
    nop
    nop
    nop
    ld a, [hl]
    ld a, [hl]
    ldh [$e0], a
    adc $ce
    add $c6
    and $e6
    ld a, [hl]
    ld a, [hl]
    nop
    nop
    nop
    nop
    add $c6
    add $c6
    cp $fe
    add $c6
    add $c6
    add $c6
    nop
    nop
    nop
    nop
    ld a, [hl]
    ld a, [hl]
    jr @+$1a

    jr jr_004_5391

    jr jr_004_5393

    jr jr_004_5395

    ld a, [hl]
    ld a, [hl]
    nop
    nop
    nop
    nop
    add $c6
    add $c6
    xor $ee
    ld a, h
    ld a, h
    jr c, jr_004_53c5

    db $10
    stop
    nop

jr_004_5391:
    nop
    nop

jr_004_5393:
    ld a, h
    ld a, h

jr_004_5395:
    ldh [$e0], a
    ld a, h
    ld a, h
    ld c, $0e
    adc $ce
    ld a, h
    ld a, h
    nop
    nop
    nop
    nop
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld a, [hl]
    ld a, [hl]
    nop
    nop
    nop
    nop
    add d
    add d
    add $c6
    xor $ee
    cp $fe
    sub $d6
    add $c6
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_53c5:
    db $10
    stop
    nop
    nop
    nop
    db $10
    stop
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
    add h
    add h
    add h
    add h
    add h
    add h
    ld h, b
    ld h, b
    nop
    nop
    nop
    nop
    ld h, b
    ld h, b
    nop
    nop
    ldh a, [$f0]
    ld [$0808], sp
    ld [$7070], sp
    ld c, $0e
    ld [$0808], sp
    ld [$0808], sp
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr nz, jr_004_542b

    jr nz, jr_004_542d

    jr nz, jr_004_542f

    ldh [$e0], a
    ld a, $3e
    ld [hl+], a
    ld [hl+], a
    ld l, $2e
    jr z, jr_004_5441

    jr z, jr_004_5443

    jr c, jr_004_5455

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr c, jr_004_545f

    jr z, jr_004_5451

    jr z, jr_004_5453

jr_004_542b:
    add sp, -$18

jr_004_542d:
    adc b
    adc b

jr_004_542f:
    ld hl, sp-$08
    nop
    nop
    nop
    nop
    nop
    nop
    jr jr_004_5451

    jr jr_004_5453

    nop
    nop
    nop
    nop
    nop
    nop

jr_004_5441:
    nop
    nop

jr_004_5443:
    nop
    nop
    nop
    nop
    nop
    nop
    sub d
    sub d
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_5451:
    nop
    nop

jr_004_5453:
    nop
    nop

jr_004_5455:
    jr nz, jr_004_5477

    ld hl, sp-$08
    inc h
    inc h
    ld a, b
    ld a, b
    xor h
    xor h

jr_004_545f:
    ld [hl], h
    ld [hl], h
    nop
    nop
    nop
    nop
    ld [hl], b
    ld [hl], b
    nop
    nop
    ld hl, sp-$08
    db $10
    db $10
    ld h, h
    ld h, h
    sbc b
    sbc b
    nop
    nop
    nop
    nop
    jr nz, jr_004_5497

jr_004_5477:
    db $f4
    db $f4
    inc h
    inc h
    ld [hl], b
    ld [hl], b
    xor b
    xor b
    ld c, b
    ld c, b
    nop
    nop
    nop
    nop
    rrca
    rrca
    db $10
    db $10
    daa
    daa
    cpl
    cpl
    inc l
    inc l
    jr z, jr_004_54b9

    nop
    nop
    nop
    nop
    rst $38
    rst $38

jr_004_5497:
    nop
    nop
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
    ldh [$e0], a
    db $10
    db $10
    ret z

    ret z

    add sp, -$18
    ld l, b
    ld l, b
    jr z, jr_004_54d9

    jr z, jr_004_54db

    jr z, jr_004_54dd

    jr z, jr_004_54df

    jr z, jr_004_54e1

jr_004_54b9:
    jr z, jr_004_54e3

    jr z, jr_004_54e5

    jr z, jr_004_54e7

    jr z, jr_004_54e9

    jr z, jr_004_54eb

    jr z, jr_004_54ed

    daa
    daa
    jr nc, jr_004_54f9

    rra
    rra
    rrca
    rrca
    nop
    nop
    nop
    nop
    jr z, jr_004_54fb

    jr z, jr_004_54fd

    ret z

    ret z

    jr jr_004_54f1

jr_004_54d9:
    ldh a, [$f0]

jr_004_54db:
    ldh [$e0], a

jr_004_54dd:
    nop
    nop

jr_004_54df:
    nop
    nop

jr_004_54e1:
    nop
    nop

jr_004_54e3:
    nop
    nop

jr_004_54e5:
    nop
    nop

jr_004_54e7:
    nop
    nop

jr_004_54e9:
    nop
    nop

jr_004_54eb:
    nop
    nop

jr_004_54ed:
    nop
    nop
    nop
    nop

jr_004_54f1:
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, [hl]
    ld a, [hl]

jr_004_54f9:
    ld e, e
    ld e, e

jr_004_54fb:
    ld e, e
    ld e, e

jr_004_54fd:
    ld e, e
    ld e, e
    nop
    nop
    nop
    nop
    ld h, b
    ld h, b
    ld h, [hl]
    ld h, [hl]
    ld l, h
    ld l, h
    ld a, b
    ld a, b
    ld l, h
    ld l, h
    ld h, [hl]
    ld h, [hl]
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, h
    ld a, h
    call z, $cccc
    call z, Call_004_7c7c
    inc c
    inc c
    ld hl, sp-$08
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    rra
    rst $38
    db $10
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rP1]
    rst $38
    nop
    rst $38
    nop
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
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld hl, sp-$01
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    db $10
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [$08]
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$080f], sp
    rrca
    ld [$100f], sp
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [$1f]
    rst $38
    rra
    rst $38
    db $10
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [rP1]
    nop
    ld a, [hl]
    ld a, [hl]
    ld a, [hl]
    ld b, d
    jp $c3c3


    jp Jump_004_427e


    ld a, [hl]
    ld a, [hl]
    nop
    nop
    ld [$080f], sp
    rrca
    ld [$f80f], sp
    rst $38
    ld hl, sp-$01
    ld [$080f], sp
    rrca
    ld [$000f], sp
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
    nop
    nop
    nop
    nop
    nop
    db $10
    ldh a, [rNR10]
    ldh a, [rNR10]
    ldh a, [$1f]
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
    nop
    inc a
    inc a
    inc a
    inc a
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
    ld [$080f], sp
    rrca
    ld [$f80f], sp
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
    nop
    nop
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
    jr jr_004_560b

    ld a, [hl]
    ld a, [hl]
    ld h, [hl]
    ld b, d
    ld h, [hl]
    ld b, d
    ld h, [hl]
    ld b, d
    ld h, [hl]
    ld b, d
    ld a, [hl]
    ld a, [hl]
    jr jr_004_5619

    jr jr_004_561b

    jr jr_004_561d

    jr jr_004_561f

    jr jr_004_5621

    jr jr_004_5623

jr_004_560b:
    jr jr_004_5625

    jr jr_004_5627

    jr jr_004_5629

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_5619:
    nop
    nop

jr_004_561b:
    nop
    nop

jr_004_561d:
    nop
    nop

jr_004_561f:
    nop
    nop

jr_004_5621:
    inc l
    rst $20

jr_004_5623:
    inc l
    rst $20

jr_004_5625:
    inc l
    rst $20

jr_004_5627:
    inc l
    rst $20

jr_004_5629:
    inc l
    rst $20
    inc l
    rst $20
    inc l
    rst $20
    inc l
    rst $20
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
    rst $38
    nop
    rst $38
    nop
    rst $38
    inc a
    rst $38
    ld a, [hl]
    jp $81c3


    jp $c381


    add c
    jp Jump_004_7e81


    jp $ff3c


    inc a
    nop
    adc c
    nop
    ld h, b
    nop
    rst $30
    nop
    rst $20
    nop
    rst $20
    nop
    sbc e
    nop
    call c, $ff00
    rst $38
    add c
    add c
    cp l
    add c
    and l
    add c
    and l
    add c
    cp l
    add c
    add c
    add c
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
    nop
    rst $38
    nop
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
    inc a
    add b
    add hl, bc
    ret nz

    nop
    ldh [rTAC], a
    ldh a, [rTAC]
    ld hl, sp+$03
    db $fc
    ld bc, $00fe
    rst $38
    inc a
    ld bc, $0388
    ld h, b
    rlca
    ldh a, [rIF]

jr_004_56a9:
    ldh [$1f], a
    ret nz

    ccf
    add b
    ld a, a
    nop
    rst $38
    nop
    rst $38
    add b
    ld a, a
    ld b, b
    ccf
    ldh [$1f], a
    ldh [rIF], a
    ldh [rTAC], a
    sbc b
    inc bc
    call c, Call_000_0001
    rst $38
    ld bc, $00fe
    db $fc
    rlca
    ld hl, sp+$07
    ldh a, [rTAC]
    ldh [rNR31], a
    ret nz

    ld e, h
    add b
    nop
    nop

jr_004_56d3:
    nop
    nop
    jr jr_004_56ef

    inc h
    inc h
    inc h
    inc h
    jr jr_004_56f5

    nop
    nop
    nop
    nop
    inc a
    nop
    adc c
    nop
    ld h, b
    nop
    rst $38
    jr @+$01

    jr jr_004_56d3

jr_004_56ec:
    nop
    sbc e
    nop

jr_004_56ef:
    call c, Call_000_3c00
    nop
    adc c
    nop

jr_004_56f5:
    ld h, b
    nop
    rst $30
    ld h, [hl]
    rst $20
    ld h, [hl]
    rst $20
    nop
    sbc e
    nop

jr_004_56ff:
    call c, Call_000_3c00
    nop
    sbc c
    jr jr_004_577e

    jr jr_004_56ff

    nop
    rst $20
    nop
    rst $38
    jr jr_004_56a9

    jr jr_004_56ec

    nop
    nop
    nop

jr_004_5713:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    ld bc, $0300
    nop
    nop
    nop
    nop
    inc bc
    rlca
    db $10
    ccf
    ld b, b
    rst $38
    jr @+$01

    inc h
    rst $20
    ld b, d
    db $db
    nop
    nop
    nop
    nop
    add b
    ret nz

    ldh a, [$30]
    jr c, jr_004_5713

    ld e, b
    and h
    inc l
    call nc, $a25c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jr jr_004_577f

    inc h
    inc h
    ld [hl+], a
    ld [hl+], a
    add hl, bc
    dec de
    jr jr_004_578e

    inc d
    rla
    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    nop
    ld bc, $0101
    ld bc, $6201
    ld h, d
    sub e

jr_004_577e:
    sub d

jr_004_577f:
    sub c
    ld de, $db42
    inc h
    rst $20
    inc e
    ld hl, sp+$23
    ret nz

    sbc b
    rlca
    ld b, [hl]
    add hl, sp
    sub a

jr_004_578e:
    ld [hl], b
    rst $30
    ret nc

    ld l, $d2
    ld d, $ea
    ld [bc], a
    ld a, [hl]
    jp nz, $3e3e

    sbc $a8
    sbc c
    and l
    add c
    pop hl
    dec b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld h, $33
    jr nz, @+$31

    inc a
    daa
    dec de
    dec de
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ldh [rNR41], a
    ld [hl], b
    ldh a, [$8c]
    xor $21
    jp hl


    ld hl, sp-$3c
    cp b
    call nz, Call_004_7c60
    jr nz, jr_004_57f5

    ld a, e
    ld b, h
    ld a, a
    ld b, b
    dec l
    inc sp
    db $db
    call c, Call_004_6767
    rla
    ld h, $31
    ld [hl+], a
    ld de, $ca33
    ld a, [bc]
    call z, $900c
    db $10
    ldh a, [rSVBK]
    ld c, b
    ret z

    call nz, $ef46
    dec l
    pop af
    cp $00
    nop
    nop
    nop

jr_004_57f5:
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rla
    db $10
    rrca
    jr @+$05

    ld b, $00
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    rrca
    ccf
    jp nz, $833f

    ld a, a
    jp nz, Jump_004_41ff

    ld a, a
    ld b, c
    ld a, a
    add c
    rst $38
    add c
    rst $38
    ld h, b
    rst $38
    and c
    rst $38
    ld [hl], c
    rst $38
    or c
    rst $38
    ld [hl], b
    rst $38
    ldh a, [rIE]
    ld hl, sp-$01
    ld hl, sp-$01
    ld b, b
    ld b, b
    add b
    jr nz, jr_004_5866

    jr nz, jr_004_5858

    db $10
    add b
    sub b
    and b
    ldh [$f0], a
    sub b
    ldh a, [$90]
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_5858:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_5866:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    add c
    rst $38
    add c
    ld sp, hl
    add c
    add c
    ld a, [hl]
    ld a, a
    db $10
    rra
    db $10
    rra
    nop
    rra
    jr nz, jr_004_58c0

    ld sp, hl
    ld sp, hl
    ret


    jp hl


    ccf
    ccf
    ld [hl+], a
    cp $22
    cp $02
    cp $c2
    rst $38
    ld b, b
    rst $38
    add sp, $08
    add sp, -$78
    db $f4
    add h
    ld a, h
    ld e, h
    db $e4
    db $fc
    ld a, [$feae]
    and [hl]
    ld a, [hl]
    ld [hl], d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_004_58c0:
    nop
    ld hl, $213f
    ccf
    dec d
    ld l, e
    ld c, d
    db $76
    ld d, [hl]
    ld l, d
    adc b
    db $f4
    xor h
    call nc, $fc84
    ld hl, $213f
    ccf
    dec hl
    dec [hl]
    dec h
    dec sp
    ld [bc], a
    dec a
    dec d
    ld a, [de]
    db $10
    rra
    db $10
    rra
    inc e
    inc e
    nop
    nop
    nop
    nop
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
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
    ld bc, $0101
    nop
    nop
    ld c, b
    ld a, b
    ld a, b
    ld a, b
    ret z

    ret z

    sub h
    db $fc
    ld h, h
    db $fc
    inc c
    sbc h
    ld hl, sp+$08
    ldh a, [$f0]
    db $10
    rra
    add hl, bc
    rrca
    rrca
    rrca
    ld de, $151c
    rra
    ld [de], a
    rra
    dec c
    ld c, $03
    inc bc
    add b
    add b
    nop
    nop
    nop
    nop
    add b
    add b
    ret nz

    ret nz

    jr nz, jr_004_595d

    ldh [rNR41], a
    ret nz

    ret nz

    ld [hl], a
    cp a
    adc h
    rst $10
    db $d3
    jp nc, Jump_004_777a

    ld c, [hl]
    and $94
    ld d, h
    pop bc
    db $e3
    inc d
    db $e3
    ld a, l
    dec h
    adc d
    cp d
    adc d
    and b
    ld d, a
    ld a, e
    ld a, [de]
    ld b, c
    ld d, l
    ld e, [hl]

jr_004_595d:
    and l
    pop bc
    add hl, hl
    ld hl, $2745

jr_004_5963:
    ret nc

    or a
    xor b
    adc d
    adc c
    adc c
    rst $18
    add hl, hl
    add hl, de
    ld l, $a8
    sub h
    add [hl]
    ld hl, $a855
    inc h
    rst $00
    add d
    ld hl, $4848
    adc b
    cp [hl]
    adc d
    pop bc
    ld b, l
    inc sp
    sub d
    sub l
    ld e, d
    and c
    xor b
    and l
    db $dd
    dec h
    ld [$8d51], sp
    ld d, d
    xor d
    push de
    ld c, b
    ld d, h
    sub l
    dec bc
    cp $04
    inc [hl]
    adc b
    inc d
    ld d, l
    ld l, d
    ld [$f7c7], sp
    ld a, [bc]
    ret z

    jp nc, Jump_004_6f14

    ld [$7769], sp
    ld d, b
    ld c, [hl]
    ld l, $ec
    add h
    ld h, d
    rst $28
    ld e, h
    adc b
    dec a
    dec de
    and l
    rst $38
    ei
    dec de
    rlca
    and l
    ld d, [hl]
    sub h
    dec h
    jr nc, jr_004_5963

    xor a
    ld [c], a
    xor a
    call z, Call_004_6e98
    inc sp
    xor b
    ld [$d5af], a
    ld l, l
    dec h
    adc a
    ld [hl-], a
    xor d
    xor d
    and e
    db $fc
    add hl, bc
    sbc a
    add $68
    ld l, c
    db $eb
    ld a, h
    add hl, bc
    ldh [$2a], a
    ld l, h
    sub b
    xor a
    rst $00
    ld [hl-], a
    ld d, d
    rst $38
    ld hl, sp-$1b
    rst $18
    adc h
    jr z, jr_004_5a3d

    adc d
    sub d
    xor d
    adc d
    ld c, $4a
    ldh a, [$dc]
    jr c, jr_004_5a15

    push de
    jr @+$65

    ld a, [hl+]
    rst $38
    rst $38
    cp $0c
    push bc
    ld h, e
    db $e4
    or e
    ld hl, sp+$7a
    ld a, [bc]
    ld sp, $ff7f
    rst $38
    ld d, h
    dec [hl]
    inc de
    ld a, [hl]
    adc d
    ld b, [hl]
    rra
    ld hl, sp+$49
    sbc h
    dec bc
    pop de
    ld sp, $ffbf
    ld [c], a

jr_004_5a10:
    sbc $ee
    ld sp, hl
    and e
    ei

jr_004_5a15:
    xor d
    sbc e
    rst $10
    rst $38
    db $ec
    adc l
    ld a, [bc]
    add hl, sp
    ld sp, $ff18
    rst $38
    rst $38
    add sp, -$26
    sub l
    ld a, a
    cp $11
    ld [hl], a
    add $38
    push de
    ld d, l
    ld a, a
    ldh a, [$e3]
    sub a
    rlca
    ld d, h
    inc [hl]
    ld d, h
    ld c, l
    ld a, [bc]
    db $ec
    ld b, d
    sub c
    jr jr_004_5a10

    ld l, a

jr_004_5a3d:
    add hl, de
    and l
    sbc $0c
    jp c, Jump_004_5079

    and e
    dec b

jr_004_5a46:
    inc b
    inc d
    ld a, a
    adc b
    nop
    ld [hl], a
    ccf
    sbc l
    inc d
    db $f4
    sub a
    ld a, [$df8c]
    ld c, a
    ld bc, $05fa
    inc b
    ld d, l
    ld a, a
    ld d, h
    and $5f
    db $fd
    ld b, l
    pop hl
    ld l, a
    push af
    ld [$a388], a
    sbc d
    and d
    xor d
    ld d, d
    ld l, e
    ld h, e
    dec [hl]
    push af
    ld c, [hl]
    ld a, [de]
    ld [hl-], a
    and e
    ld h, l
    ld e, a
    add sp, $68
    di
    dec d
    ld d, l
    ld a, [hl-]
    jr z, jr_004_5a46

    jp nc, $c6d4

    xor a
    ld e, a
    ld c, [hl]
    dec hl
    push de
    ld e, a
    add c
    ld c, b
    db $ed
    push de
    ld c, h
    ld l, b
    add sp, -$56
    adc d
    or l
    ld a, [bc]
    ld sp, hl
    dec bc
    db $fd
    ld e, a
    ld c, a
    ld [de], a
    cp l
    ld d, e
    ld a, [de]
    add l
    ld d, h
    pop af
    ld l, d
    ld hl, sp-$2e
    adc a
    ldh a, [$da]
    ld a, a
    pop de
    ld [$3f77], sp
    cp b
    sub h
    di
    rla
    push af
    rlca
    ld [$7d05], a
    inc a
    ld a, [hl-]
    adc b
    xor l
    inc hl
    ld a, d
    adc a
    ld d, $8e
    dec d
    ld hl, sp-$0b
    dec d
    ld c, a
    ld c, $8c
    inc d
    add l
    ld c, b
    xor b
    ldh a, [$ef]
    ld d, a
    push hl
    ld b, d
    dec bc
    push af
    ld c, a
    ld a, [de]
    and d
    ld l, e
    ld [c], a
    ld l, b
    rst $38
    dec hl
    rst $20
    db $fd
    db $10
    add b
    ld h, $c2
    ldh a, [$da]
    add $08
    ld l, a
    ld a, $7f
    ld [hl], a
    dec h
    ldh a, [$da]
    add $09
    ld l, a
    ld a, [hl-]
    ld b, a
    xor a
    ld [hl-], a
    ld [hl], a
    ldh a, [$da]
    add $02
    ld l, a
    ld a, [hl]
    or b
    ld [hl-], a
    ld a, $02
    ld [hl], a
    ret


    ld a, $29
    call Call_000_3e9d
    call Call_000_374a
    call Call_000_3e07
    call Call_000_0b3c
    call Call_000_0ebd
    jp Jump_000_15f0


Jump_004_5b0c:
    ld a, [$d123]
    and a
    jp z, Jump_000_15f0

    xor a
    ld [$cc35], a
    ld [$d05a], a
    ld [$cfb2], a
    call Call_000_2df3
    jr jr_004_5b2c

Jump_004_5b22:
    xor a
    ld [$cc35], a
    ld [$d05a], a
    call Call_000_2e08

Jump_004_5b2c:
jr_004_5b2c:
    jr nc, jr_004_5b3a

Jump_004_5b2e:
    call Call_000_3e04
    call Call_000_3dee
    call Call_000_0b3c
    jp Jump_000_15f0


jr_004_5b3a:
    call Call_000_3761
    ld a, $04
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $cd3d
    ld bc, $020c
    ld e, $05

jr_004_5b4d:
    dec e
    jr z, jr_004_5b59

    ld a, [hl+]
    and a
    jr z, jr_004_5b59

    inc b
    dec c
    dec c
    jr jr_004_5b4d

jr_004_5b59:
    ld hl, $cc24
    ld a, c
    ld [hl+], a
    ld a, $06
    ld [hl+], a
    xor a
    ld [hl+], a
    inc hl
    ld a, b
    ld [hl+], a
    ld a, $03
    ld [hl+], a
    xor a
    ld [hl], a
    call Call_000_3b08
    push af
    call Call_000_376d
    pop af
    bit 1, a
    jp nz, Jump_004_5b22

    ld a, [$cc28]
    ld b, a
    ld a, [$cc26]
    cp b
    jp z, Jump_004_5b2e

    dec b
    cp b
    jr z, jr_004_5b96

    dec b
    cp b
    jp z, Jump_004_5bac

    ld c, a
    ld b, $00
    ld hl, $cd3d
    add hl, bc
    jp Jump_004_5bc3


jr_004_5b96:
    ld a, [$d123]
    cp $02
    jp c, Jump_004_5b0c

    call Call_004_6156
    ld a, $04
    ld [$d05a], a
    call Call_000_2e08
    jp Jump_004_5b2c


Jump_004_5bac:
    call Call_000_0188
    xor a
    ld [$cc49], a
    ld a, $36
    call Call_000_3e9d
    ld a, $37
    call Call_000_3e9d
    call Call_000_1b86
    jp Jump_004_5b0c


Jump_004_5bc3:
    push hl
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    pop hl
    ld a, [hl]
    dec a
    add a
    ld b, $00
    ld c, a
    ld hl, $5bdf
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$d2d5]
    jp hl


    inc hl
    ld e, h
    pop af
    ld e, e
    scf
    ld e, h
    ld a, [hl-]
    ld e, h
    ld l, c
    ld e, h
    ld a, c
    ld e, h
    xor b
    ld e, h
    ret nz

    ld e, h
    ld c, e
    ld e, l
    bit 2, a
    jp z, Jump_004_5daa

    call Call_000_22f8
    jr z, jr_004_5c0d

    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    ld hl, $5d2d
    call Call_000_3c79
    jp Jump_004_5b22


jr_004_5c0d:
    call Call_000_1bbe
    ld a, [$d6b1]
    bit 3, a

jr_004_5c15:
    jp nz, Jump_004_5da4

    call Call_000_36ca
    ld hl, $d6ad
    set 1, [hl]
    jp Jump_004_5b0c


    bit 1, a
    jp z, Jump_004_5daa

    ld a, $3c
    call Call_000_3e9d
    ld a, [$cd65]
    and a
    jp z, Jump_004_5b22

    jp Jump_000_14ba


    jp Jump_004_5b22


    bit 4, a
    jp z, Jump_004_5daa

    ld b, $03
    ld hl, $457b
    call Call_000_3620
    ld hl, $d6a7
    bit 1, [hl]
    res 1, [hl]
    jp z, Jump_004_5b22

    ld a, $07
    ld [$cf78], a
    ld [$d117], a
    call Call_000_3104
    ld a, [$cd65]
    and a
    jp z, Jump_004_5b22

    call Call_000_3e04
    jp Jump_004_5da4


    bit 3, a
    jp z, Jump_004_5daa

    ld a, $5b
    call Call_000_3e9d
    call Call_000_3e04
    jp Jump_004_5da4


    bit 0, a
    jp z, Jump_004_5daa

    xor a
    ld [$d2dc], a
    ld hl, $5c8e
    call Call_000_3c79
    call Call_000_3e04
    jp Jump_004_5da4


    db $ed
    jr z, jr_004_5c15

    ld l, b
    or d
    ld a, a
    res 6, [hl]
    ret c

    ld h, $4f
    or c
    ret nz

    ret c

    db $dd
    ld a, a
    or c
    or [hl]
    reti


    cp b
    ld a, a
    jp $bdd7


    ld d, [hl]
    ld e, b
    ld a, $1d
    ld [$cf78], a
    ld [$d117], a
    call Call_000_3104
    ld a, [$cd65]
    and a
    jp z, Jump_004_5b22

    call Call_000_3e04
    jp Jump_004_5da4


    call Call_000_22f8
    jr z, jr_004_5cd7

    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    ld hl, $5d0e
    call Call_000_3c79
    jp Jump_004_5b22


jr_004_5cd7:
    ld hl, $5cf6
    call Call_000_3c79
    ld hl, $d6b1
    set 3, [hl]
    set 6, [hl]
    ld hl, $d6ad
    set 1, [hl]
    res 4, [hl]
    ld c, $3c
    call Call_000_3781
    call Call_000_3e04
    jp Jump_004_5da4


    db $ed
    jr z, @-$0f

    ld l, b
    add $7f
    call nc, $debd
    jr nc, @+$51

    ld d, h
    adc l
    xor e
    adc a
    db $e3
    call $c47f
    dec sp
    rst $08
    cp l
    rst $20
    ld d, a
    db $ed
    jr z, @-$4d

    ld l, b
    jp z, Jump_004_507f

    ld bc, $cd68
    nop
    inc sp
    ld c, a
    sub d
    and a
    ld b, e
    db $e3
    sub e
    cp l
    reti


    cp d
    call nz, Call_004_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $e7
    ld e, b
    db $ed
    jr z, @+$60

    ld l, b
    jp z, Jump_004_507f

    ld bc, $cd68
    nop
    inc sp
    ld c, a
    cp a
    rst $10
    db $dd
    ld a, a
    call nz, $ba3c
    call nz, Call_004_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $e7
    ld e, b
    ld hl, $d14d
    ld a, [$cf79]
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl+]
    ldh [$95], a
    ld a, [hl]
    ldh [$96], a
    ld a, $05
    ldh [$99], a
    ld b, $02
    call Call_000_3902
    ld bc, $ffdf
    add hl, bc
    ld a, [hl-]
    ld b, a
    ldh a, [$98]
    sub b
    ld b, [hl]
    ldh a, [$97]
    sbc b
    jp nc, Jump_004_5d8c

    ld a, [$cc2b]
    push af
    ld a, $14
    ld [$cf78], a
    ld [$d117], a
    call Call_000_3104
    pop af
    ld [$cc2b], a
    jp Jump_004_5b22


Jump_004_5d8c:
    ld hl, $5d95
    call Call_000_3c79
    jp Jump_004_5b22


    db $ed
    jr z, @+$2a

    ld l, c
    ld [c], a
    cp b
    ld h, $7f
    ret nz

    ret c

    rst $08
    cp [hl]
    sbc $e7
    ld e, b

Jump_004_5da4:
    call Call_000_3dee
    jp Jump_000_14ba


Jump_004_5daa:
    ld hl, $5db3
    call Call_000_3c79
    jp Jump_004_5b22


    db $ed
    jr z, @+$42

    ld l, c
    cp h
    or d
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld a, a
    jp $bdc6


    reti


    rst $08
    inc sp
    ld c, a
    rst $08
    jr nc, jr_004_5e48

    jp nz, $b4b6

    rst $08
    cp [hl]
    sbc $e7
    ld e, b

Call_004_5dd1:
    ld hl, $c3b4
    ld bc, $0028
    ld a, $06

jr_004_5dd9:
    ld [hl], $7f
    add hl, bc
    dec a
    jr nz, jr_004_5dd9

    ret


Jump_004_5de0:
    call Call_000_3752
    call Call_000_3e1d

Jump_004_5de6:
    ld a, [$d0f0]
    dec a
    jr nz, jr_004_5df4

    ld hl, $5f0e
    call Call_000_3c79
    jr jr_004_5e17

jr_004_5df4:
    ld bc, $d2a1
    ld hl, $cf72
    ld a, c
    ld [hl+], a
    ld [hl], b
    xor a
    ld [$cf7a], a
    ld a, $03
    ld [$cf7b], a
    ld a, [$cc2c]
    ld [$cc26], a
    call Call_000_16f7
    ld a, [$cc26]
    ld [$cc2c], a
    jr nc, jr_004_5e23

jr_004_5e17:
    call Call_000_374a
    call Call_000_36ea
    call Call_000_0ebd
    jp Jump_000_15f0


jr_004_5e23:
    ld a, $7f
    ld [$c3f1], a
    ld [$c419], a
    ld [$c441], a
    ld [$c469], a
    call Call_000_3c1c
    xor a
    ld [$cc35], a
    ld a, [$cf78]
    cp $06
    jp z, Jump_004_5e68

    ld a, $06
    ld [$d0ea], a
    call Call_000_3130

jr_004_5e48:
    ld hl, $cc24
    ld a, $0b
    ld [hl+], a
    ld a, $0b
    ld [hl+], a
    xor a
    ld [hl+], a
    inc hl
    inc a
    ld [hl+], a
    ld a, $03
    ld [hl+], a
    xor a
    ld [hl], a
    call Call_000_3b08
    call Call_000_3c1c
    bit 1, a
    jr z, jr_004_5e68

    jp Jump_004_5de0


Jump_004_5e68:
jr_004_5e68:
    ld a, [$cf78]
    ld [$d0e3], a
    call Call_000_1add
    call Call_000_386e
    ld a, [$cf78]
    cp $06
    jr nz, jr_004_5e8b

    ld a, [$d6b1]
    bit 5, a
    jr z, jr_004_5eba

    ld hl, $5f26
    call Call_000_3c79
    jp Jump_004_5de0


jr_004_5e8b:
    ld a, [$cc26]
    and a
    jr nz, jr_004_5eee

    ld [$d117], a
    ld a, [$cf78]
    cp $c4
    jr nc, jr_004_5ecb

    ld hl, $5f59
    ld de, $0001
    call Call_000_3ddb
    jr c, jr_004_5eba

    ld a, [$cf78]
    ld hl, $5f34
    ld de, $0001
    call Call_000_3ddb
    jr c, jr_004_5ecb

    call Call_000_3104
    jp Jump_004_5de0


jr_004_5eba:
    xor a
    ld [$d117], a
    call Call_000_3104
    ld a, [$cd65]
    and a
    jp z, Jump_004_5de0

    jp Jump_000_1681


jr_004_5ecb:
    ld a, [$cfb2]
    push af
    call Call_000_3104
    ld a, [$cd65]
    cp $02
    jp z, Jump_004_5ee7

    call Call_000_3e04
    call Call_000_3dee
    pop af
    ld [$cfb2], a
    jp Jump_004_5de6


Jump_004_5ee7:
    pop af
    ld [$cfb2], a
    jp Jump_004_5de0


jr_004_5eee:
    call Call_000_3121
    ld a, [$d0e9]
    and a

jr_004_5ef5:
    jr nz, jr_004_5f05

    ld a, [$cf78]
    call Call_000_1b55
    jr c, jr_004_5f05

    call Call_000_186a
    inc a
    jr z, jr_004_5f0b

jr_004_5f05:
    ld hl, $d2a1
    call Call_000_310c

jr_004_5f0b:
    jp Jump_004_5de0


    db $ed
    jr z, @+$6c

    ld l, c
    jp z, $347f

    or e
    jr z, jr_004_5ef5

    ld c, a
    jp nz, $b3b6

    cp d
    call nz, Call_004_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $58
    db $ed
    jr z, @-$72

    ld l, c
    cp d
    call nz, $7f26
    inc sp
    or a
    push bc
    or d
    rst $20
    ld e, b
    ld a, [bc]
    dec bc
    inc c
    dec c
    ld c, $0f
    db $10
    ld de, $1312
    inc d
    jr nz, @+$23

    ld [hl+], a
    inc hl
    inc h
    dec h
    ld h, $27
    jr z, @+$31

    inc [hl]
    dec [hl]
    ld [hl], $3c
    dec a
    ld a, $41
    ld b, d
    ld b, e
    ld b, h
    ld c, a
    ld d, b
    ld d, c
    ld d, d
    ld d, e
    rst $38
    dec e
    ld b, a
    ld c, c
    ld c, h
    ld c, l
    ld c, [hl]
    rst $38
    call Call_000_3e15
    call Call_000_03bf
    call Call_000_0ebd
    ldh a, [$d7]
    push af
    xor a
    ldh [$d7], a
    call Call_004_5f9a
    ld a, $2e
    call Call_000_3e9d
    ld b, $0d
    call Call_000_3e1f
    call Call_000_3e0c
    call Call_000_38ae
    call Call_000_3e15
    call Call_000_36ca
    call Call_000_374a
    call Call_000_3e1d
    call Call_000_1b86
    call Call_000_0b3c
    pop af
    ldh [$d7], a
    jp Jump_000_15f0


Call_004_5f9a:
    ld de, $5941
    ld bc, $0401
    ld a, $3b
    call Call_000_3e9d
    call Call_000_0167
    ld hl, $c3c8
    ld a, $7f
    call Call_004_60db
    ld hl, $c3c9
    call Call_004_60db
    ld hl, $9070
    ld de, $9000
    ld bc, $01c0
    call Call_000_01bb
    ld hl, $7bf6
    ld de, $9770
    ld bc, $0080
    push bc
    call Call_004_6081
    ld hl, $7c86
    ld de, $9600
    ld bc, $0170
    call Call_004_6081
    pop bc
    ld hl, $7df6
    ld de, $8e80
    call Call_004_6081
    ld hl, $6da9
    ld de, $9200
    ld bc, $0400
    ld a, $03
    call Call_000_028c
    ld hl, $52f1
    ld de, $00d0
    add hl, de
    ld de, $8f40
    ld bc, $0010
    ld a, $04
    push bc
    call Call_000_028c
    pop bc
    ld hl, $7c76
    ld de, $8f50
    call Call_004_6081
    call Call_000_0181
    ld hl, $cd3d
    ld a, $13
    ld [hl+], a
    dec a
    ld [hl+], a
    ld [hl], $01
    ld hl, $c3a0
    call Call_004_60a3
    ld hl, $cd3d
    ld a, $11
    ld [hl+], a
    dec a
    ld [hl+], a
    ld [hl], $03
    ld hl, $c469
    call Call_004_60a3
    ld hl, $c468
    ld a, $f5
    call Call_004_60db
    ld hl, $c47b
    call Call_004_60db
    ld hl, $c45a
    ld de, $609a
    call Call_000_0405
    ld hl, $c3ca
    ld de, $6086
    call Call_000_0405
    ld hl, $c3ce
    ld de, $d11d
    call Call_000_0405
    ld hl, $c3f8
    ld de, $d2cb
    ld c, $c3
    call Call_000_2fc4
    ld [hl], $f0
    ld hl, $c421
    ld de, $d97d
    ld bc, $4103
    call Call_000_3c8f
    ld [hl], $f4
    inc hl
    ld de, $d97f
    ld bc, $8102
    jp Jump_000_3c8f


Call_004_6081:
    ld a, $0b
    jp Jump_000_028c


    db $ed
    inc l
    ret c

    ld b, c
    ld c, [hl]
    or l
    cp d
    ld [hl-], a
    or [hl]
    or d
    di
    ld c, [hl]
    ld b, d
    and a
    add c
    inc l
    or [hl]
    sbc $f3
    ld d, b
    db $76
    ld [hl], b
    ld [hl], c
    ld [hl], d
    ld [hl], e
    ld [hl], h
    ld [hl], l
    db $76
    ld d, b

Call_004_60a3:
    ld a, $79
    ld de, $7a7b
    call Call_004_60c6
    call Call_004_60d3
    ld a, [$cd3d]
    ld e, a
    ld d, $00
    ld c, $06

jr_004_60b6:
    ld [hl], $7c
    add hl, de
    ld [hl], $78
    call Call_004_60d3
    dec c
    jr nz, jr_004_60b6

    ld a, $7d
    ld de, $777e

Call_004_60c6:
    ld [hl+], a
    ld a, [$cd3e]
    ld c, a
    ld a, d

jr_004_60cc:
    ld [hl+], a
    dec c
    jr nz, jr_004_60cc

    ld a, e
    ld [hl], a
    ret


Call_004_60d3:
    ld a, [$cd3f]

jr_004_60d6:
    inc hl
    dec a
    jr nz, jr_004_60d6

    ret


Call_004_60db:
    ld de, $0014
    ld c, $08

jr_004_60e0:
    ld [hl], a
    add hl, de
    dec c
    jr nz, jr_004_60e0

    ret


    ld a, [$d6ad]
    bit 6, a
    jp nz, Jump_000_09da

    ld a, $3f
    call Call_000_3e9d
    call Call_000_374a
    jp Jump_000_14b1


    xor a
    ldh [$ba], a
    call Call_000_03bf
    call Call_000_0ebd
    ld hl, $5ce4
    ld b, $01
    call Call_000_3620
    call Call_000_374a
    call Call_000_36ea
    call Call_000_0ebd
    jp Jump_000_15f0


    call Call_004_6156
    ld a, [$cd3d]
    call Call_004_6128
    ld a, [$cc26]
    call Call_004_6128
    jp Jump_004_7a1d


Call_004_6128:
    push af
    ld hl, $c3a0
    ld bc, $0028
    call Call_000_3ad1
    ld c, $28
    ld a, $7f

jr_004_6136:
    ld [hl+], a
    dec c
    jr nz, jr_004_6136

    pop af
    ld hl, $c300
    ld bc, $0010
    call Call_000_3ad1
    ld de, $0004
    ld c, e

jr_004_6148:
    ld [hl], $a0
    add hl, de
    dec c
    jr nz, jr_004_6148

    call Call_000_3790
    ld a, $ae
    jp Jump_000_0e45


Call_004_6156:
    ld a, [$cc35]
    and a
    jr nz, jr_004_6164

    ld a, [$cf79]
    inc a
    ld [$cc35], a
    ret


jr_004_6164:
    xor a
    ld [$d05a], a
    ld a, [$cc35]
    dec a
    ld b, a
    ld a, [$cc26]
    ld [$cd3d], a
    cp b
    jr nz, jr_004_617e

    xor a
    ld [$cc35], a
    ld [$d05a], a
    ret


jr_004_617e:
    ld a, b
    ld [$cc35], a
    push hl
    push de
    ld hl, $d124
    ld d, h
    ld e, l
    ld a, [$cc26]
    add l
    ld l, a
    jr nc, jr_004_6191

    inc h

jr_004_6191:
    ld a, [$cc35]
    add e
    ld e, a
    jr nc, jr_004_6199

    inc d

jr_004_6199:
    ld a, [hl]
    ldh [$95], a
    ld a, [de]
    ld [hl], a
    ldh a, [$95]
    ld [de], a
    ld hl, $d12b
    ld bc, $002c
    ld a, [$cc26]
    call Call_000_3ad1
    push hl
    ld de, $cc97
    ld bc, $002c
    call Call_000_01bb
    ld hl, $d12b
    ld bc, $002c
    ld a, [$cc35]
    call Call_000_3ad1
    pop de
    push hl
    ld bc, $002c
    call Call_000_01bb
    pop de
    ld hl, $cc97
    ld bc, $002c
    call Call_000_01bb
    ld hl, $d233
    ld a, [$cc26]
    call Call_000_3ac7
    push hl
    ld de, $cc97
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d233
    ld a, [$cc35]
    call Call_000_3ac7
    pop de
    push hl
    ld bc, $0006
    call Call_000_01bb
    pop de
    ld hl, $cc97
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d257
    ld a, [$cc26]
    call Call_000_3ac7
    push hl
    ld de, $cc97
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d257
    ld a, [$cc35]
    call Call_000_3ac7
    pop de
    push hl
    ld bc, $0006
    call Call_000_01bb
    pop de
    ld hl, $cc97
    ld bc, $0006
    call Call_000_01bb
    ld a, [$cc35]
    ld [$cd3d], a
    xor a
    ld [$cc35], a
    ld [$d05a], a
    pop de
    pop hl
    ret


    ld a, [$cf78]
    ld [$d092], a
    call Call_000_2f2e
    ld hl, $d0a9
    push hl
    ld a, [$d0bd]
    ld b, a
    ld c, $00
    ld hl, $6276

jr_004_6257:
    ld a, [hl+]
    cp b
    jr z, jr_004_625e

    inc c
    jr jr_004_6257

jr_004_625e:
    pop hl
    ld b, $02
    ld a, $10
    jp Jump_000_3e9d


    ld a, [$d0e3]
    dec a
    ld hl, $6276
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl]
    ld [$d0e3], a
    ret


    dec b
    dec c
    ld c, $12
    add hl, de
    ld e, h
    jr nz, jr_004_62a0

    inc h
    ld h, $3d
    scf
    ld a, [hl-]
    dec sp
    ccf
    ld b, $42
    ld b, h
    ld b, l
    ld h, e
    ld c, b
    ld c, h
    ld d, d
    ld d, l
    ld d, a
    ld e, c
    ld e, d
    ld e, e
    ld e, [hl]
    ld h, h
    ld h, [hl]
    ld l, b
    ld [hl], e
    ld [hl], l
    db $76
    ld a, b
    ld a, c
    ld a, [hl]
    add c
    add d
    add a
    adc d

jr_004_62a0:
    adc a
    sbc h
    ld d, [hl]
    sub l
    sbc c
    sbc l
    and c
    and h
    rrca
    inc de
    add hl, sp
    ld b, [hl]
    sub h
    inc bc
    inc bc
    rrca
    rrca
    rra
    ld e, $1f
    jr jr_004_62f5

    jr nc, @+$81

    ld d, [hl]
    ld a, a
    ld c, c
    ld l, a
    ld e, c
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp+$78
    ld hl, sp+$18
    db $fc
    inc c
    cp $6a
    cp $92
    or $9a
    ccf
    ld [hl], $3e
    add hl, sp
    ld a, e
    ld c, a
    ld a, a
    ld c, c
    ccf
    jr nc, jr_004_62f7

    db $10
    rra
    rra
    ld c, $0e
    db $fc
    ld l, h
    ld a, h
    sbc h
    sbc $f2
    cp $92
    db $fc
    inc c
    ld hl, sp+$08
    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    inc bc
    inc bc
    rrca
    rrca
    rra
    rra
    rra
    rra

jr_004_62f5:
    ccf
    ccf

jr_004_62f7:
    ld a, a
    ld e, a
    ld a, a
    ld e, a
    ld a, a
    ld e, a
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fa
    cp $fa
    cp $fa
    ccf
    scf
    ccf
    jr c, jr_004_638d

    ld e, a
    ld a, a
    ld d, b
    ccf
    jr nc, @+$21

    ld de, $1f1f
    ld c, $0e
    db $fc
    db $ec
    db $fc
    inc e
    sbc $fa
    cp $0a
    db $fc
    inc c
    ld hl, sp-$78
    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    inc de
    rra
    ld de, $181f
    rra
    rla
    rra
    inc d
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    ld hl, sp-$68
    rra
    jr jr_004_635b

    inc c
    rlca
    rlca
    rlca
    dec b
    rlca
    dec b
    rlca
    inc b
    rlca
    rlca

jr_004_635b:
    inc bc
    inc bc
    ldh a, [rNR10]
    ldh [$60], a
    ldh a, [$d0]
    ldh a, [$30]
    ldh a, [$30]
    ldh a, [$d0]
    ldh a, [$f0]
    ret nz

    ret nz

    nop
    nop
    inc bc
    inc bc
    rrca
    rrca
    rra
    ld e, $1f
    jr jr_004_63b7

    jr nc, @+$81

    ld d, [hl]
    ld a, a
    ld c, c
    nop
    nop
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp+$78
    ld hl, sp+$18
    db $fc
    inc c
    cp $6a
    cp $92

jr_004_638d:
    ld l, a
    ld e, c
    ld a, a
    db $76
    ld a, [hl]
    ld e, c
    ccf
    ccf
    rra
    dec de
    rrca
    inc c
    rrca
    rrca
    rlca
    rlca
    or $9a
    db $fc
    ld l, h
    ld a, h
    sbc h
    db $fc
    db $f4
    db $fc
    call z, Call_004_48f8
    or b
    or b
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    rrca
    rrca
    rra
    rra
    rra
    rra

jr_004_63b7:
    ccf
    ccf
    ld a, a
    ld e, a
    ld a, a
    ld e, a
    nop
    nop
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fa
    cp $fa
    ld a, a
    ld e, e
    ld a, a
    ld [hl], c
    ld a, a
    ld e, h
    ccf
    dec sp
    rra
    jr jr_004_63e7

    inc c
    rrca
    rrca
    rlca
    rlca
    cp $da
    db $fc
    adc h
    db $fc
    inc a
    cp $d2
    cp $12

jr_004_63e7:
    db $fc
    inc a
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    inc de
    rra
    ld de, $181f
    rra
    rla
    nop
    nop
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    rra
    inc d
    rra
    jr jr_004_641d

    inc c
    rlca
    rlca
    rra
    inc e
    ccf
    jr c, jr_004_6439

    rra
    ld c, $0e

jr_004_641d:
    ld hl, sp-$68
    ldh a, [rNR10]
    ld hl, sp+$68
    ld hl, sp-$18
    ld hl, sp-$68
    db $fc
    sbc h
    db $fc
    db $fc
    jr jr_004_6445

    nop
    inc bc
    nop
    rlca
    ld [$1c0f], sp
    inc de
    ld e, $11
    ccf
    inc [hl]

jr_004_6439:
    ld a, a
    ld d, d
    ld a, l
    ld b, d
    nop
    ret nz

    nop
    ldh [rNR10], a
    ldh a, [$38]
    ret z

jr_004_6445:
    ld a, b
    adc b
    db $fc
    inc l
    cp $4a
    cp [hl]
    ld b, d
    ccf
    jr nc, jr_004_648e

    add hl, sp
    ld a, a
    ld c, a
    ld a, a
    ld c, a
    add hl, sp
    ccf
    ld d, $1f
    ld de, $0e1f
    ld c, $fc
    inc c
    ld a, h
    sbc h
    cp $f2
    cp $f2
    sbc h
    db $fc
    ld l, b
    ld hl, sp-$78
    ld hl, sp+$70
    ld [hl], b
    nop
    inc bc
    nop
    rlca
    inc c
    dec bc
    rra
    db $10
    rra
    db $10
    ccf
    jr nc, jr_004_64f9

    ld d, b
    ld a, a
    ld b, b
    nop
    ret nz

    nop
    ldh [$30], a
    ret nc

    ld hl, sp+$08
    ld hl, sp+$08
    db $fc
    inc c
    cp $0a
    cp $02
    ccf

jr_004_648e:
    jr nc, jr_004_64cf

    jr c, jr_004_6511

    ld e, a
    ld a, a
    ld e, a
    ccf
    ccf
    rla
    rra
    ld de, $0e1f
    ld c, $fc
    inc c
    db $fc
    inc e
    cp $fa
    cp $fa
    db $fc
    db $fc
    add sp, -$08
    adc b
    ld hl, sp+$70
    ld [hl], b
    nop
    rlca
    nop
    rrca
    nop
    rra
    inc bc
    inc e
    rlca
    jr jr_004_64d7

    ld [de], a
    dec de
    inc d
    rra
    inc d
    nop
    ldh [rP1], a
    ldh a, [$60]
    sbc b
    ldh a, [$08]
    ld hl, sp+$08
    ld hl, sp+$08
    ld hl, sp+$68

jr_004_64cb:
    ld hl, sp-$68
    rra
    db $10

jr_004_64cf:
    dec bc
    inc c
    rlca
    rlca
    inc bc
    inc bc
    inc bc
    inc bc

jr_004_64d7:
    inc b
    rlca
    inc b
    rlca
    inc bc
    inc bc
    ld hl, sp+$18
    ld hl, sp+$78
    ldh a, [$f0]
    ldh a, [$30]
    ldh a, [$30]
    ldh [$e0], a
    jr nz, jr_004_64cb

    ret nz

    ret nz

    nop
    nop
    nop
    inc bc
    nop
    rlca
    ld [$1c0f], sp
    inc de
    ld e, $11

jr_004_64f9:
    ccf
    inc [hl]
    ld a, a
    ld d, d
    nop
    nop
    nop
    ret nz

    nop
    ldh [rNR10], a
    ldh a, [$38]
    ret z

    ld a, b
    adc b
    db $fc
    inc l
    cp $4a
    ld a, l
    ld b, d
    ld a, a
    ld [hl], b

jr_004_6511:
    ld a, [hl]
    ld e, c
    ccf
    ccf
    dec de
    rra
    ld c, $0f
    add hl, bc
    rrca
    rlca
    rlca
    cp [hl]
    ld b, d
    db $fc
    inc c
    ld [hl], h
    sbc h
    db $fc
    db $f4
    db $fc
    call z, $c878
    or b
    or b
    nop
    nop
    nop
    nop
    nop
    inc bc
    nop
    rlca
    inc c
    dec bc
    rra
    db $10
    rra
    db $10
    ccf
    jr nc, @+$81

    ld d, b
    nop
    nop
    nop
    ret nz

    nop
    ldh [$30], a
    ret nc

    ld hl, sp+$08
    ld hl, sp+$08
    db $fc
    inc c
    cp $0a
    ld a, a
    ld b, b
    ld a, a
    ld [hl], b
    ld a, a
    ld e, b
    ccf
    ccf
    rra
    rra
    inc c
    rrca
    dec bc
    rrca
    rlca
    rlca
    cp $02
    db $fc
    inc c
    db $fc
    inc e
    cp $f2
    cp $f2
    inc a
    db $fc
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop
    rlca
    nop
    rrca
    nop
    rra
    ld bc, $071e
    jr jr_004_6599

    ld [de], a
    dec de
    inc d
    nop
    nop
    nop
    ldh [rP1], a
    ldh a, [$60]
    sbc b
    ldh a, [$08]
    ld hl, sp+$08
    ld hl, sp+$08
    ld hl, sp+$68
    rra
    inc d
    rra
    db $10
    dec bc
    inc c
    rlca
    rlca
    rra
    rra
    inc h
    ccf

jr_004_6599:
    inc de
    rra
    ld c, $0e
    ld hl, sp-$68
    ld hl, sp+$18
    ldh a, [rSVBK]
    ldh a, [$f0]
    ld hl, sp-$68
    db $f4
    sbc h
    db $e4
    db $fc
    jr jr_004_65c5

    nop
    nop
    nop
    nop
    ld b, b
    nop
    nop
    nop
    nop
    nop
    rlca
    rlca
    ld [$100f], sp
    rra
    nop
    nop
    ld b, $00
    ld b, $00
    nop
    nop

jr_004_65c5:
    nop
    nop
    ldh [$e0], a
    ld [de], a
    ldh a, [$08]
    ld hl, sp+$12
    rra
    daa
    dec a
    cpl
    jr c, jr_004_6653

    ld d, d
    ld a, a
    ld [hl], d
    ld a, [hl]
    ld c, c
    ld a, a
    ld c, a
    jr nc, @+$32

    ld c, b
    ld hl, sp-$1c
    cp h
    db $f4
    inc e
    cp $4a
    cp $4e
    ld a, [hl]
    sub d
    cp $f2
    inc c
    inc c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    stop
    rlca
    rlca
    ld [$100f], sp
    rra
    nop
    nop
    nop
    nop
    jr jr_004_6603

jr_004_6603:
    jr jr_004_6605

jr_004_6605:
    nop
    nop
    ldh [$e0], a
    inc d
    ldh a, [$08]
    ld hl, sp+$20
    ccf
    jr nz, jr_004_6650

    ld [hl], b
    ld e, a
    ld a, b
    ld c, a
    ccf
    scf
    ld a, a
    ld e, b
    ld a, a
    ld c, a
    jr nc, jr_004_664d

    inc b
    db $fc
    inc b
    db $fc
    ld c, $fa
    ld e, $f2
    db $fc
    db $ec
    cp $1a
    cp $f2
    inc c
    inc c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    jp $c403


    rlca
    ld [$0c0f], sp
    rrca
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ldh a, [$f0]
    ld [$04f8], sp
    db $fc
    inc b
    db $fc

jr_004_664d:
    rra
    rla
    ld e, a

jr_004_6650:
    db $10
    rra
    inc d

jr_004_6653:
    rra
    inc d
    rra
    jr jr_004_6697

    inc h
    ccf
    daa
    jr jr_004_6675

    inc b
    db $fc
    add h
    db $fc
    db $e4
    db $fc
    ld hl, sp-$68
    ldh a, [rNR10]
    ldh [rNR41], a
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    ld b, b
    nop
    nop
    nop

jr_004_6675:
    rlca

Call_004_6676:
    rlca
    ld [$100f], sp
    rra
    ld [de], a
    rra
    nop
    nop
    ld b, $00
    ld b, $00
    nop
    nop
    ldh [$e0], a
    db $10
    ldh a, [$0a]
    ld hl, sp+$48
    ld hl, sp+$27
    dec a
    cpl
    jr c, jr_004_6711

    ld d, d
    ld a, a
    ld b, d
    ld a, $31

jr_004_6697:
    ld a, [hl]
    ld c, c
    ld a, a
    ld c, a
    jr nc, @+$32

    db $e4
    cp h
    db $f4
    inc e
    cp $4a
    cp $42
    ld a, h
    adc h
    ld [hl], b
    sub b
    ldh [$e0], a
    nop
    nop
    nop
    nop
    ld h, b
    nop
    ld h, b
    nop
    nop
    nop
    rlca
    rlca
    ld [$500f], sp
    rra
    db $10
    rra
    nop
    nop
    nop
    nop
    ld [bc], a
    nop
    nop
    nop
    ldh [$e0], a
    db $10
    ldh a, [$08]
    ld hl, sp+$08
    ld hl, sp+$20
    ccf
    jr nz, @+$41

    ld [hl], b
    ld e, a
    ld a, b
    ld c, a
    ccf
    scf
    rrca
    ld [$0707], sp
    nop
    nop
    inc b
    db $fc
    inc b
    db $fc
    ld c, $fa
    ld e, $f2
    db $fc
    db $ec
    cp $1a
    cp $f2
    inc c
    inc c
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    ld h, h
    rlca
    ld l, b
    rrca
    inc c
    rrca
    rrca
    dec bc
    nop
    nop
    nop
    nop
    nop
    nop
    ldh a, [$f0]
    ld [$04f8], sp
    db $fc
    inc b
    db $fc
    add d
    cp $0f
    ld [$0a2f], sp

jr_004_6711:
    rrca
    ld a, [bc]
    rrca
    ld [$0704], sp
    inc bc
    inc bc
    nop
    nop
    nop
    nop
    jp nz, $f27e

    ld a, [hl]
    db $fc
    ld c, h
    ld hl, sp+$08
    ldh a, [rSVBK]
    ldh a, [$90]
    ldh a, [$90]
    ld h, b
    ld h, b
    rlca
    rlca
    rrca
    ld [$101f], sp
    inc e
    inc de
    dec sp
    inc a
    ccf
    scf
    ld a, a
    ld d, b
    ld a, a
    ld b, d
    ldh [$e0], a
    ldh a, [rNR10]
    ld hl, sp+$08
    jr c, @-$36

    call c, $fc3c
    db $ec
    cp $0a
    cp $42
    ccf
    jr nc, jr_004_678e

    add hl, sp
    ld a, a
    ld c, a
    ld a, a
    ld c, c
    ccf
    jr c, jr_004_676f

    ld e, $11
    rra
    ld c, $0e
    db $fc
    inc c
    ld a, h
    sbc h
    cp $f2
    cp $92
    db $fc
    inc e

Call_004_6767:
    add sp, $78
    adc b
    ld hl, sp+$70
    ld [hl], b
    rlca
    rlca

jr_004_676f:
    rrca
    ld [$101f], sp
    rra
    db $10
    ccf
    jr nc, jr_004_67b7

    jr c, jr_004_67f9

    ld e, a
    ld a, a
    ld c, a
    ldh [$e0], a
    ldh a, [rNR10]
    ld hl, sp+$08
    ld hl, sp+$08
    db $fc
    inc c
    db $fc
    inc e
    cp $fa
    cp $f2
    ccf

jr_004_678e:
    scf
    ccf
    jr c, @+$81

    ld e, a
    ld a, a
    ld d, b
    ccf
    jr c, jr_004_67af

    ld e, $11
    rra
    ld c, $0e
    db $fc
    db $ec
    db $fc
    inc e
    cp $fa
    cp $0a
    db $fc
    inc e
    add sp, $78
    adc b
    ld hl, sp+$70
    ld [hl], b
    rlca
    rlca

jr_004_67af:
    rrca
    ld [$1817], sp
    dec sp
    inc [hl]
    ld a, l
    ld b, d

jr_004_67b7:
    ccf
    ccf
    rra
    db $10
    rra
    inc d
    ldh [$e0], a
    ldh a, [rNR10]
    ld hl, sp+$08
    ld hl, sp+$08
    db $fc
    inc e
    db $fc
    db $fc
    db $fc
    db $fc

jr_004_67cb:
    ld hl, sp-$68
    rra
    db $10
    dec bc
    inc c
    rlca
    rlca
    inc bc
    inc bc
    inc bc
    inc bc
    inc b
    rlca
    inc b
    rlca
    inc bc
    inc bc
    ldh a, [rNR10]
    ldh [$60], a
    ldh a, [$d0]
    ldh a, [$30]
    ldh a, [$30]
    ldh a, [$f0]
    jr nz, jr_004_67cb

    ret nz

    ret nz

    rlca
    rlca
    rrca
    rrca
    rra
    dec e
    rra
    jr jr_004_6835

    ld h, $3f
    add hl, sp

jr_004_67f9:
    ld a, a
    ld d, [hl]
    ld a, a
    ld b, b
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$48
    ld hl, sp+$18
    db $fc
    ld h, h
    db $fc
    sbc h
    cp $6a
    cp $02
    ld l, $31
    rra
    jr @+$3f

    ld h, $3f
    daa
    dec de
    ld e, $1f
    rra
    rrca
    rrca
    ld c, $0e
    ld [hl], h
    adc h
    ld hl, sp+$18
    cp h
    ld h, h
    db $fc
    db $e4
    ld e, b
    ld hl, sp-$08
    ld hl, sp-$10
    ldh a, [rSVBK]
    ld [hl], b
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    rra

jr_004_6835:
    ccf
    ccf
    ccf
    ccf
    ld l, a
    ld e, a
    ld [hl], l
    ld c, a
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    db $fc
    db $fc
    or $fa
    ld e, [hl]
    ld a, [c]
    ccf
    jr nc, jr_004_686b

    inc e
    ccf
    ccf
    ccf
    ccf
    inc d
    rra
    rra
    rra
    rra
    rra
    ld c, $0e
    db $fc

jr_004_685e:
    inc c

jr_004_685f:
    ret c

    jr c, jr_004_685e

    db $fc
    db $fc
    db $fc
    jr z, jr_004_685f

    ld hl, sp-$08
    ld hl, sp-$08

jr_004_686b:
    ld [hl], b
    ld [hl], b
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    rla
    ld e, $11
    rra
    inc e
    rra
    inc de
    rra
    inc e
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    cp h
    ld a, h
    db $fc
    db $fc

jr_004_688b:
    ld hl, sp+$58
    rra
    db $10
    dec bc
    inc c
    rlca
    rlca
    rlca
    rlca
    ld [bc], a
    rlca
    rlca
    rlca
    rlca
    rlca
    inc bc
    inc bc
    ldh a, [rNR10]
    ldh [$60], a
    ldh [$e0], a
    ldh [rNR41], a
    ldh [rNR41], a
    ldh [$e0], a
    ldh [$e0], a
    ret nz

    ret nz

    inc bc
    inc bc
    rrca
    inc c
    inc e
    inc de
    rra
    db $10
    jr z, jr_004_68ee

    ld l, a
    ld d, [hl]
    ld a, a
    ld c, c
    ld l, a
    ld e, c
    ret nz

    ret nz

    ldh a, [$30]
    jr c, jr_004_688b

    ld hl, sp+$08
    inc d
    db $ec
    or $6a
    cp $92

jr_004_68cb:
    or $9a
    ccf
    ld [hl], $3f
    add hl, sp
    ld e, a
    ld a, [hl]
    ld e, a
    ld a, a
    ccf
    ccf
    db $10
    rra
    add hl, sp
    ccf
    ld a, $3e
    db $fc
    ld l, h
    db $fc
    sbc h
    ld a, [$fa7e]
    cp $fc
    db $fc
    ld [$9cf8], sp
    db $fc
    ld a, h
    ld a, h
    inc bc

jr_004_68ee:
    inc bc
    rrca
    inc c
    inc e
    inc de
    rra
    db $10
    cpl
    jr nc, @+$81

    ld d, b
    ld a, a
    ld d, b
    ld a, a
    ld b, b
    ret nz

    ret nz

    ldh a, [$30]
    jr c, jr_004_68cb

    ld hl, sp+$08
    db $f4
    inc c
    cp $0a
    cp $0a
    cp $02
    ccf
    jr nc, jr_004_696f

    ld a, b
    ld d, a
    ld a, [hl]
    ld c, a
    ld [hl], e
    ccf
    inc sp
    inc e
    rra
    add hl, sp
    ccf
    ld a, $3e
    db $fc
    inc c
    ld a, [$ea1e]
    ld a, [hl]
    ld a, [c]
    adc $fc
    call z, $f838
    sbc h
    db $fc
    ld a, h
    ld a, h
    inc bc
    inc bc
    inc c
    rrca
    rra
    db $10
    ld de, $3e1e
    ld hl, $383f
    inc a
    daa
    ccf
    inc h
    ret nz

    ret nz

    ldh a, [$30]
    ld a, b
    adc b
    ld hl, sp+$08
    db $fc
    inc b
    db $fc
    inc b
    db $fc
    ld h, h
    ld a, h
    sub h
    ccf
    jr c, jr_004_696f

    db $10
    ld e, $19
    rrca
    rrca
    rlca
    rlca
    rrca
    rrca
    ld c, $0f
    rlca
    rlca
    db $fc
    inc d
    ld a, b
    add sp, -$48
    ld hl, sp+$1c
    db $e4
    sbc h
    db $e4
    db $fc
    db $fc
    ld [$f0f8], sp
    ldh a, [$03]
    inc bc

jr_004_696f:
    rrca
    rrca
    rra
    rra
    rra
    rra
    ccf
    jr nc, jr_004_69f7

    ld d, [hl]
    ld a, a
    ld c, c
    ld l, a
    ld e, c
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$28
    ld hl, sp-$68
    db $fc
    inc c
    cp $6a
    cp $92
    or $9a
    ccf
    ld [hl], $3e
    add hl, sp
    ld a, a
    ld c, a
    ld a, c
    ld c, a
    inc a
    ccf
    rla
    rra
    ld de, $0e1f
    ld c, $fc
    ld l, h
    ld a, h
    sbc h
    cp $f2
    sbc [hl]
    ld a, [c]
    inc a
    db $fc
    add sp, -$08
    adc b
    ld hl, sp+$70
    ld [hl], b
    inc bc
    inc bc
    rrca
    rrca
    rra
    rra
    rra
    rra
    ccf
    ccf
    ld a, a
    ld e, a
    ld a, a
    ld c, a
    ld l, a
    ld d, e
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fa
    cp $f2
    or $ca
    ccf
    jr nc, jr_004_6a0f

    jr c, jr_004_6a51

    ld e, a
    ld [hl], b
    ld e, a
    jr nc, jr_004_6a16

    inc de
    rra
    ld de, $0e1f
    ld c, $fc
    inc c
    db $fc
    inc e
    cp $fa
    ld c, $fa
    inc c
    db $fc
    ret z

    ld hl, sp-$78
    ld hl, sp+$70
    ld [hl], b
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    rra
    ccf
    inc sp

jr_004_69f7:
    ccf
    inc a
    rra
    ld [de], a
    rra
    ld [de], a
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    db $fc

jr_004_6a08:
    db $fc
    db $fc

jr_004_6a0a:
    inc a
    db $fc
    inc a
    rra
    inc e

jr_004_6a0f:
    dec bc
    inc c
    rlca
    rlca
    rlca
    rlca
    inc bc

jr_004_6a16:
    inc bc
    dec b
    rlca
    ld [$070f], sp
    rlca
    ld hl, sp+$38
    ldh a, [rSVBK]
    ret nc

    ldh a, [$50]
    ldh a, [$f0]
    jr nc, jr_004_6a08

    jr nz, jr_004_6a0a

    ldh [$c0], a
    ret nz

    inc bc
    inc bc
    rrca
    inc c
    rra
    db $10
    ld a, a
    ld [hl], b
    ldh a, [$8f]
    ld a, a
    ld [hl], b
    ld a, a
    ld c, a
    ld l, a
    ld d, d
    ret nz

    ret nz

    ldh a, [$30]
    ld hl, sp+$08
    cp $0e
    rrca
    pop af
    cp $0e
    cp $f2
    or $4a
    ccf
    jr nc, jr_004_6a8e

    add hl, sp

jr_004_6a51:
    ld [hl], a
    ld c, a
    ld a, [hl]
    ld c, c
    ld [hl], $3f
    jr jr_004_6a78

    rra
    rra
    ld c, $0e
    db $fc
    inc c
    ld a, h
    sbc h

jr_004_6a61:
    xor $f2
    ld a, [hl]
    sub d
    ld l, h
    db $fc
    jr jr_004_6a61

    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    inc bc
    inc bc
    rrca
    inc c
    rra
    db $10
    ld a, a
    ld [hl], b
    ldh a, [$8f]
    ld a, a

jr_004_6a78:
    ld [hl], b
    ld a, a
    ld c, a
    ld l, a
    ld d, a
    ret nz

    ret nz

    ldh a, [$30]
    ld hl, sp+$08
    cp $0e
    rrca
    pop af
    cp $0e
    cp $f2
    or $ea
    ccf

jr_004_6a8e:
    inc sp
    ccf
    jr c, jr_004_6b11

    ld d, a
    ld [hl], a
    ld e, b
    jr nc, jr_004_6ad6

    jr jr_004_6ab8

    rra
    rra
    ld c, $0e
    db $fc
    call z, Call_000_1cfc

jr_004_6aa1:
    cp $ea
    xor $1a
    inc c
    db $fc
    jr jr_004_6aa1

    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    rlca
    rlca
    rrca
    ld [$101f], sp
    ccf
    jr nc, jr_004_6b26

    ld c, a
    ccf

jr_004_6ab8:
    jr nc, jr_004_6ad9

    rra
    rra
    inc d
    ldh [$e0], a
    ldh a, [rNR10]
    ld hl, sp+$08
    db $fc
    inc c
    ld c, $f2
    db $fc

jr_004_6ac8:
    inc c
    db $fc

jr_004_6aca:
    db $fc

jr_004_6acb:
    call c, $1f2c
    db $10
    dec bc
    inc c
    rlca
    rlca
    rlca
    inc b
    inc bc

jr_004_6ad6:
    inc bc
    rlca
    rlca

jr_004_6ad9:
    rrca
    rrca
    rlca
    rlca
    ld hl, sp+$08
    ldh a, [rSVBK]
    ret nc

    ldh a, [$d0]
    ldh a, [$f0]
    jr nc, jr_004_6ac8

    jr nz, jr_004_6aca

    ldh [$c0], a
    ret nz

    inc bc
    inc bc
    rrca
    inc c
    inc e
    inc de
    ccf
    jr nz, @+$41

    ld hl, $263f
    ld e, a
    ld a, b
    ccf
    ld h, $c0

jr_004_6afe:
    ret nz

    ldh a, [$30]
    jr c, jr_004_6acb

    db $fc
    inc b
    db $fc
    add h
    db $fc
    ld h, h
    ld a, [$fc1e]
    ld h, h
    rra
    db $10
    ld c, $0d

jr_004_6b11:
    dec bc
    rrca
    add hl, bc
    rrca
    dec de
    ld e, $3c
    cpl
    ccf
    daa
    rra
    rra
    ld hl, sp+$08
    ld [hl], b
    or b
    ret nc

    ldh a, [$90]
    ldh a, [$d8]

jr_004_6b26:
    ld a, b
    inc a
    db $f4
    db $fc
    db $e4
    ld hl, sp-$08
    inc bc
    inc bc
    rrca
    inc c
    inc e
    inc de
    ccf
    jr nz, @+$41

    jr nz, jr_004_6b77

    jr nz, jr_004_6b99

    ld h, b
    ccf
    jr nz, jr_004_6afe

    ret nz

    ldh a, [$30]
    jr c, @-$36

    db $fc
    inc b
    db $fc
    inc b
    db $fc
    inc b
    ld a, [$fc06]
    inc b
    rra
    db $10
    rrca
    inc c
    dec bc
    rrca
    ld a, [bc]
    rrca
    ld a, [de]
    rra
    inc a
    cpl
    ccf
    daa
    rra
    rra
    ld hl, sp+$08
    ldh a, [$30]
    ret nc

    ldh a, [$50]
    ldh a, [$58]
    ld hl, sp+$3c
    db $f4
    db $fc
    db $e4
    ld hl, sp-$08
    inc bc
    inc bc
    rrca
    inc c
    inc e
    inc de
    ccf
    jr nz, jr_004_6bb5

    inc l

jr_004_6b77:
    ccf
    inc sp
    ccf
    jr nc, jr_004_6b9b

    inc e
    ret nz

    ret nz

    ldh a, [$30]
    jr c, @-$36

    db $fc
    inc b

jr_004_6b85:
    db $fc
    inc b
    db $fc
    inc b
    db $ec
    db $f4
    db $fc
    sub h
    rra
    db $10
    dec bc
    inc c
    rlca
    rlca
    dec b
    rlca
    ld b, $03
    inc e
    rra

jr_004_6b99:
    ccf
    inc hl

jr_004_6b9b:
    rra
    rra
    ld hl, sp+$18
    ldh a, [$30]

jr_004_6ba1:
    ldh [$e0], a
    jr nz, jr_004_6b85

    ldh [$e0], a
    jr c, jr_004_6ba1

    db $fc
    call nz, $f8f8
    rlca
    rlca
    ld [$190f], sp
    rla
    ld h, $3b

jr_004_6bb5:
    daa
    inc a
    cpl
    jr c, jr_004_6c09

    ld [hl], d
    ld e, a
    ld [hl], d
    ldh [$e0], a
    sub b
    ldh a, [$58]
    add sp, -$1c
    ld e, h
    db $e4
    inc a
    db $f4
    inc e
    ld a, [c]
    ld c, [hl]
    ld a, [$4e4e]
    ld a, c
    ld b, a
    ld a, a
    ld c, a
    ld a, e
    daa
    dec a
    rla
    ld e, $0f
    rrca
    rrca
    rrca
    inc bc
    inc bc
    ld [hl], d
    sbc [hl]
    ld [c], a
    cp $f2
    sbc $e4
    cp h
    add sp, $78
    ldh a, [$f0]
    ldh a, [$f0]
    ret nz

    ret nz

    nop
    nop
    rlca
    rlca
    ld [$100f], sp
    rra
    add hl, hl
    scf
    ld h, $3b
    daa
    inc a
    ld c, a
    ld a, b
    nop
    nop
    ldh [$e0], a
    sub b
    ldh a, [$88]
    ld hl, sp+$5c
    db $ec
    db $e4
    ld e, h

jr_004_6c09:
    db $e4
    inc a
    ld a, [c]
    ld e, $5f
    db $76
    ld c, [hl]
    ld a, c
    ld b, a
    ld a, a
    ld c, a
    ld a, a
    daa
    dec a
    rra
    ld e, $0f
    rrca
    inc bc
    inc bc
    ld a, [$726e]
    sbc [hl]

jr_004_6c21:
    ld [c], a
    cp $f2
    cp $e4
    cp h
    ld hl, sp+$78
    ldh a, [$f0]
    ret nz

    ret nz

    rlca
    rlca
    ld [$140f], sp
    dec de
    dec hl
    inc a
    inc a
    scf
    ld e, $13
    rra
    dec d
    rra
    inc d
    ret nz

    ret nz

    jr nz, jr_004_6c21

    db $10
    ldh a, [$08]
    ld hl, sp-$0c
    inc c
    inc b
    db $fc
    ld b, h
    db $fc
    jp nz, $1fbe

    db $10
    dec bc
    inc c
    rlca
    rlca
    ld e, $1d
    dec a
    inc hl
    rra
    rra
    rrca
    rrca
    inc bc
    inc bc
    ld [c], a
    ld a, $c2
    ld a, [hl]
    add d
    cp $c4
    db $fc
    ld hl, sp-$08
    ldh [$e0], a
    ldh a, [$f0]
    add b
    add b
    inc bc
    inc bc
    inc c
    rrca

jr_004_6c71:
    db $10
    rra
    jr nz, @+$41

    ld [hl+], a
    ccf
    daa
    dec a
    ld c, a
    ld a, b
    sbc a
    ld [c], a
    ret nz

    ret nz

    jr nc, jr_004_6c71

    ld [$04f8], sp
    db $fc
    ld b, h
    db $fc
    db $e4
    cp h
    ld a, [c]
    ld e, $f9
    ld b, a
    adc a
    ld a, [c]
    ld l, [hl]
    ld a, c
    rra
    rla
    rra
    inc d
    rra
    dec de
    rrca
    rrca
    add hl, bc
    rrca
    ld b, $06
    pop af
    ld c, a
    db $76
    sbc [hl]
    ld hl, sp-$18
    ld hl, sp-$18
    ld hl, sp-$28
    ldh a, [$f0]
    sub b
    ldh a, [$60]
    ld h, b
    inc bc
    inc bc
    inc c
    rrca

jr_004_6cb1:
    db $10
    rra
    jr nz, jr_004_6cf4

    jr nz, @+$41

    jr nz, @+$41

    ld b, b
    ld a, a
    add b
    rst $38
    ret nz

    ret nz

    jr nc, jr_004_6cb1

    ld [$04f8], sp
    db $fc
    inc b
    db $fc
    inc b
    db $fc
    ld [bc], a
    cp $01
    rst $38
    add b
    rst $38
    ld l, b
    ld a, a
    inc e
    rla
    rra
    rla
    rra
    rra
    rrca
    rrca
    add hl, bc
    rrca
    ld b, $06
    ld bc, $16ff
    cp $38
    add sp, -$08
    add sp, -$08
    ld hl, sp-$10
    ldh a, [$90]
    ldh a, [$60]
    ld h, b
    rlca
    rlca
    ld [$100f], sp
    rra
    db $10

jr_004_6cf4:
    rra
    jr z, jr_004_6d36

    ld a, $33
    rra
    dec d
    rra
    inc d
    ret nz

    ret nz

    jr nz, @-$1e

    db $10
    ldh a, [$08]
    ld hl, sp+$08
    ld hl, sp+$04
    db $fc
    ld [bc], a
    cp $c2
    ld a, $1f
    db $10
    dec bc
    inc c
    rlca
    rlca
    rlca
    rlca
    inc bc
    ld [bc], a
    rlca
    rlca
    ld [$070f], sp
    rlca
    jp nz, $c47e

    db $fc
    ld hl, sp-$08
    ldh [$60], a
    ldh [$e0], a
    ldh [$e0], a
    ret nz

    ret nz

    ret nz

    ret nz

    rlca
    rlca
    rrca
    ld [$1817], sp
    ccf
    ld [hl], $7f

jr_004_6d36:
    ld a, c
    ld l, a
    ld e, c
    ld a, a
    ld b, [hl]
    ld a, $31
    ldh [$e0], a
    ldh a, [rNR10]
    add sp, $18
    db $fc
    ld l, h
    cp $9e
    or $9a
    cp $62
    ld a, h
    adc h
    ld a, a
    ld a, b
    rst $38
    sbc a
    cp $9f
    ld a, a
    ld a, a
    ccf
    ccf
    ccf
    ccf
    ccf
    cpl
    ld e, $1e
    cp $1e
    rst $38
    ld sp, hl
    ld a, a
    ld sp, hl
    cp $fe
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $f4
    ld a, b
    ld a, b
    rlca
    rlca
    rrca
    ld [$101f], sp
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, a
    ld e, a
    ld a, a
    ld c, a
    ccf
    jr nc, @-$1e

    ldh [$f0], a
    db $10
    ld hl, sp+$08
    db $fc
    db $fc
    cp $fe
    cp $fa
    cp $f2
    db $fc
    inc c
    ld [hl], a
    ld a, b
    rst $38
    cp a
    rst $38
    cp a
    ld a, a
    ld a, a
    ccf
    ccf
    ccf
    ccf
    ccf
    cpl
    ld e, $1e
    xor $1e
    rst $38
    db $fd
    rst $38
    db $fd
    cp $fe
    db $fc
    db $fc
    db $fc
    db $fc
    db $fc
    db $f4
    ld a, b
    ld a, b
    inc bc
    inc bc
    rlca
    inc b
    rrca
    ld [$1c1f], sp
    rra
    ld [de], a
    rra
    inc de
    rra
    inc e
    rra
    db $10
    ldh [$e0], a
    ldh a, [rNR10]
    ld hl, sp+$08
    db $fc
    inc a
    db $fc
    ld a, h
    db $fc
    db $fc
    db $fc
    inc d
    db $fc
    inc d
    dec bc
    inc c
    rlca
    rlca
    dec bc
    rrca
    rra
    rra
    rra
    rra
    rrca
    rrca
    rrca
    dec bc
    rlca
    rlca
    ld hl, sp+$08
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp+$38
    ld hl, sp+$38
    ldh a, [$f0]
    ldh [$e0], a
    ldh [$e0], a
    inc bc
    inc bc
    ld a, a
    ld a, a
    ccf
    ccf
    rra
    rra
    ccf
    scf
    ld a, a
    ld d, b
    ld a, a
    ld b, b
    ld l, a
    ld d, [hl]
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    inc e
    cp $0a
    cp $02
    or $6a
    ccf
    jr nc, jr_004_6e4e

    add hl, sp
    ld a, a
    ld c, a
    ld a, c
    ld c, a
    inc a
    ccf
    rra
    rra
    rra
    rra
    ld c, $0e
    db $fc
    inc c
    ld a, h
    sbc h
    cp $f2
    sbc [hl]
    ld a, [c]
    inc a
    db $fc
    ld hl, sp-$08
    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    inc bc
    inc bc
    ld a, a
    ld a, a
    ccf
    ccf
    rra
    rra
    ccf
    ccf
    ld a, a
    ld e, a
    ld a, a
    ld c, a
    ld l, a
    ld e, a
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fa
    cp $f2
    or $fa
    ccf

jr_004_6e4e:
    scf
    ccf
    jr c, jr_004_6ed1

    ld e, a
    ld [hl], b
    ld e, a
    jr c, jr_004_6e96

    rra
    rra
    rra
    rra
    ld c, $0e
    db $fc
    db $ec
    db $fc
    inc e
    cp $fa
    ld c, $fa
    inc e
    db $fc
    ld hl, sp-$08
    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    inc bc
    inc bc
    ld a, a
    ld a, a
    ccf
    ccf
    rra
    rra
    dec e
    inc de
    rra
    db $10
    rra
    db $10
    rra
    ld d, $80
    add b
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    cp b
    ld a, b
    ld hl, sp+$18
    ldh a, [rNR10]
    rra
    db $10
    dec bc
    inc c
    rlca
    rlca
    inc b
    rlca
    dec b

jr_004_6e96:
    rlca
    rlca

Call_004_6e98:
    rlca
    rrca
    rrca
    rrca
    rrca
    ldh a, [$50]
    and b
    ld h, b
    ldh [$e0], a
    ldh a, [$f0]
    ldh a, [$30]
    ldh a, [$30]
    ldh a, [$f0]
    ldh [$e0], a
    rlca
    rlca
    rrca
    ld [$1817], sp
    ccf
    ld [hl], $7f
    ld [hl], b
    ld l, a
    ld d, d
    ld a, a
    ld b, b
    ld a, $31
    ldh [$e0], a
    ldh a, [rNR10]
    add sp, $18
    db $fc
    ld l, h
    cp $0e
    or $4a
    cp $02
    ld a, h
    adc h
    ld a, a
    ld a, b
    rst $38
    sub a

jr_004_6ed1:
    rst $38
    sub c
    ld a, a
    ld a, h
    inc sp
    ccf
    inc l
    ccf
    inc sp
    cpl
    ld e, $1e
    cp $1e
    rst $38
    jp hl


    rst $38
    adc c
    cp $3e
    call z, Call_000_34fc
    db $fc
    call z, Call_004_78f4
    ld a, b
    rlca
    rlca
    rrca
    ld [$101f], sp
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, a
    ld e, a
    ld a, a
    ld c, a
    ccf
    jr nc, @-$1e

    ldh [$f0], a
    db $10
    ld hl, sp+$08
    db $fc
    db $fc
    cp $fe
    cp $fa
    cp $f2
    db $fc
    inc c
    ld [hl], a
    ld a, b
    rst $38
    xor a
    rst $38
    and b
    ld a, a

Jump_004_6f14:
    ld a, h
    inc sp
    ccf
    ld a, $3f
    inc sp
    cpl
    ld e, $1e
    xor $1e
    rst $38
    push af
    rst $38
    dec b
    cp $3e
    call z, Call_004_7cfc
    db $fc
    sbc h
    db $f4
    ld a, b
    ld a, b
    inc bc
    inc bc
    rlca
    inc b
    rrca
    ld [$161f], sp
    rra
    db $10
    rra
    inc d
    rra
    db $10
    rra
    db $10
    ldh [$e0], a
    ldh a, [rNR10]
    ld hl, sp+$08
    db $fc
    inc a
    db $fc
    ld a, h
    db $fc
    ld a, h
    db $fc
    inc d
    db $fc
    inc d
    dec bc
    inc c
    rlca
    rlca
    rrca
    ld [$111f], sp
    rra
    ld de, $0f0e
    rrca
    dec bc
    inc b
    rlca
    ld hl, sp+$08
    ldh a, [$f0]
    ld hl, sp-$38
    ld hl, sp+$28
    ld hl, sp+$28
    ret nc

    ldh a, [$e0]
    ldh [rNR41], a
    ldh [rIF], a
    rrca
    rra
    ld e, $1e
    rra
    jr jr_004_6f94

    scf
    ccf
    ccf
    ccf
    ld [hl], a
    ld e, b
    ld a, a
    ld b, [hl]
    ldh a, [$f0]
    ld a, b
    ld hl, sp+$78
    ld hl, sp+$18
    ld hl, sp-$14
    db $fc
    db $fc
    db $fc
    xor $1a
    cp $62
    ld a, $31
    dec a
    ld a, [hl-]
    ld a, a
    ld c, h
    ld a, a

jr_004_6f94:
    ld c, h
    ccf
    ld a, [hl-]
    rra
    inc de
    rra
    rra
    ld c, $0e
    ld a, h
    adc h
    cp h
    ld e, h
    cp $32
    cp $32
    db $fc
    ld e, h
    ld hl, sp-$38
    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    rrca
    rrca
    rra
    rra
    rra
    rra
    rra
    rra
    jr nc, jr_004_6ff6

    ccf
    ccf
    ld [hl], b
    ld e, a
    ld [hl], b
    ld c, a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    ld hl, sp-$08
    inc c
    db $fc
    db $fc
    db $fc
    ld c, $fa
    ld c, $f2
    jr c, jr_004_7006

    ccf
    jr c, jr_004_7051

    ld e, a
    ld a, a
    ld e, a
    ccf
    ccf
    rra
    ld de, $1f1f
    ld c, $0e
    inc e
    db $ec
    db $fc
    inc e
    cp $fa
    cp $fa
    db $fc
    db $fc
    ld hl, sp-$78
    ld hl, sp-$08
    ld [hl], b
    ld [hl], b
    rlca
    rlca
    rrca
    rlca
    rlca
    rrca
    db $10
    rra
    ccf

jr_004_6ff6:
    ccf
    ccf
    ccf
    ld d, $19
    rra
    ld d, $f0
    ldh a, [$f8]
    ld hl, sp-$08
    ld hl, sp+$08
    ld hl, sp-$08

jr_004_7006:
    ld hl, sp-$08
    ld hl, sp+$08
    ld hl, sp+$08
    ld hl, sp+$1f
    db $10
    add hl, bc
    ld c, $06
    add hl, bc
    rlca
    add hl, bc
    inc bc
    rlca
    rlca
    dec b
    rrca
    rrca
    rrca
    rrca
    ld l, b
    sbc b
    ldh a, [rNR10]
    ldh [$60], a
    ldh a, [$f0]
    ldh a, [$30]
    ldh a, [$30]
    ldh a, [$f0]
    ldh [$e0], a
    inc bc
    inc bc
    rrca
    rrca
    ld e, $1f
    dec de
    inc e
    ccf
    jr nc, jr_004_70b7

    db $76
    ld l, a
    ld d, b
    ld a, [hl]

jr_004_703c:
    ld b, c
    ret nz

    ret nz

    ldh a, [$f0]
    ret c

    jr c, jr_004_703c

    ld [$0cfc], sp
    cp $6e
    or $0a
    ld a, [hl]
    add d
    cpl
    jr nc, @+$81

    ld e, b

jr_004_7051:
    rst $30
    sbc a
    add sp, -$49
    ld h, b
    ld a, a
    jr c, @+$41

    ccf
    ccf
    ld e, $1e
    db $f4
    inc c
    cp $1a
    rst $28
    ld sp, hl
    rla
    db $ed
    ld b, $fe
    inc e
    db $fc
    db $fc
    db $fc
    ld a, b
    ld a, b
    inc bc
    inc bc
    rrca
    rrca
    rra
    rra
    rra
    rra
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, a
    ld e, a
    ld a, a
    ld c, a
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fe
    cp $fa
    cp $f2
    ccf
    inc sp
    ld a, a
    ld e, b
    db $e3
    cp a
    db $ec
    or e
    ld h, b
    ld a, a
    jr nc, @+$41

    ccf
    ccf
    ld e, $1e
    db $fc
    call z, Call_000_1afe
    rst $00
    db $fd
    scf
    call $fe06
    inc c
    db $fc
    db $fc
    db $fc
    ld a, b
    ld a, b
    inc bc
    inc bc
    rlca
    inc b
    rrca
    ld [$0b0f], sp
    rra
    db $10

jr_004_70b7:
    rla
    jr @+$21

    db $10
    rra
    db $10
    ldh a, [$f0]
    ld a, b
    ld hl, sp-$04
    ld a, h
    cp $7e
    cp [hl]
    ld a, [hl]
    cp $1e
    cp $1e
    cp $1e
    rrca
    ld [$1f17], sp
    jr z, @+$39

    ld hl, $213f
    ccf
    ld de, $1f1f
    rra
    rrca
    rrca
    cp h
    ld a, h
    ld hl, sp-$08
    ldh a, [$90]
    ldh a, [rNR10]
    ldh a, [$30]
    ldh [$e0], a
    ret nz

    ret nz

    ret nz

    ret nz

    nop
    nop
    inc bc
    inc bc
    rrca
    rrca
    ld e, $1f
    dec de
    inc e
    ccf
    jr nc, jr_004_7179

    db $76
    ld l, a
    ld d, b
    nop
    nop
    ret nz

    ret nz

    ldh a, [$f0]
    ld a, b

jr_004_7104:
    ld hl, sp-$28
    jr c, jr_004_7104

    inc c
    cp $6e
    or $0a
    ld a, [hl]
    ld b, c
    ld l, a
    ld [hl], b
    rst $38
    sbc b
    rst $30
    cp a
    add sp, -$09
    inc a
    ccf
    ccf
    ccf
    ld e, $1e
    ld a, [hl]
    add d
    db $f4
    inc c
    cp $1a
    rst $28
    ld sp, hl
    rra
    pop af
    ld e, $f2
    db $ec
    db $ec
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    rrca
    rrca
    rra
    rra
    rra
    rra
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, a
    ld e, a
    nop
    nop
    ret nz

    ret nz

    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fe
    cp $fa
    ld a, a
    ld c, a
    ccf
    inc sp
    ld a, a
    ld e, b
    rst $20
    cp a
    ld hl, sp-$59
    ld h, b
    ld a, a
    ld a, $3f
    rra
    rra
    cp $f2
    db $fc
    call z, $12fe
    sbc a
    pop af
    ld a, a
    sub c
    ld c, $fe
    ld [$f0f8], sp
    ldh a, [rP1]
    nop
    inc bc
    inc bc
    rlca
    inc b
    rrca
    ld [$0b0f], sp
    rra
    db $10

jr_004_7179:
    rla
    jr jr_004_719b

    stop
    nop
    ldh a, [$f0]
    ld a, b
    ld hl, sp-$04
    ld a, h
    cp $7e
    cp [hl]
    ld a, [hl]
    cp $1e
    cp $1e
    rra
    db $10
    rrca
    ld [$1f17], sp
    jr z, @+$39

    ldh a, [rIE]
    ld hl, sp-$01
    ld a, a
    ld a, a

jr_004_719b:
    ld e, $1e
    cp $1e
    cp h
    ld a, h
    ld hl, sp-$08
    ld a, b
    ret z

    ld a, h
    call nz, $c47c
    ld hl, sp-$08
    ld a, b
    ld a, b
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    db $10
    ccf
    jr nz, @+$41

    ccf
    ld a, a
    ld d, [hl]
    ld a, a
    ld b, d
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp+$08
    db $fc
    inc b
    db $fc
    db $fc
    cp $6a
    cp $42
    ccf
    jr nc, jr_004_720e

    add hl, sp
    ld a, a
    ld c, a
    ld a, a
    ld c, b
    jr nc, @+$41

    rra
    rra
    ccf
    ccf
    inc a
    inc a
    db $fc
    inc c
    ld a, h
    sbc h
    cp $f2
    cp $12
    inc c
    db $fc
    ld hl, sp-$08
    db $fc
    db $fc
    inc a
    inc a
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    db $10
    ccf
    jr nc, @+$41

    ccf
    ld a, a
    ld e, a
    ld a, a
    ld c, a
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp+$08
    db $fc
    inc c
    db $fc
    db $fc
    cp $fa
    cp $f2
    ccf

jr_004_720e:
    inc sp
    ccf
    inc a
    ld a, a
    ld h, a
    ld a, a
    ld d, b
    jr nc, @+$41

    rra
    rra
    ccf
    ccf
    inc a
    inc a
    db $fc
    call z, $3cfc
    cp $e6
    cp $0a
    inc c
    db $fc
    ld hl, sp-$08
    db $fc
    db $fc
    inc a
    inc a
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    ccf
    jr nz, jr_004_7275

    jr nz, jr_004_7277

    ccf
    rra
    ld d, $1f
    inc d
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp+$08
    db $fc
    inc c
    db $fc
    db $fc
    db $fc
    db $fc
    ld hl, sp-$68
    rra
    db $10
    dec bc
    inc c
    rlca
    rlca
    inc bc
    inc bc
    ld bc, $0703
    rlca
    rlca
    rlca
    inc bc
    inc bc
    ldh a, [rNR10]
    ldh [$60], a
    ldh a, [$d0]
    ldh a, [$30]
    ldh a, [$30]
    ldh [$e0], a
    ldh [$e0], a
    ret nz

    ret nz

    nop
    nop
    rlca
    rlca
    rrca
    rrca
    rra
    rra

jr_004_7275:
    rra
    db $10

jr_004_7277:
    ccf
    jr nc, @+$41

    ccf
    ld a, a
    ld d, [hl]
    nop
    nop
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp+$08
    db $fc
    inc c
    db $fc
    db $fc
    cp $6a
    ld a, a
    ld b, d
    ld a, a
    ld [hl], b
    ld a, [hl]
    ld e, c
    ccf
    ccf
    add hl, bc
    ld c, $0e
    rrca
    rrca
    rrca
    ld b, $06
    cp $42
    db $fc
    inc c
    ld a, b
    sbc b
    ldh a, [$f8]
    ld hl, sp+$48
    ld a, b
    ret z

    or b
    or b
    nop
    nop
    nop
    nop
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    rra
    db $10
    ccf
    jr nc, @+$41

    ccf
    ld a, a
    ld e, a
    nop
    nop
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp+$08
    db $fc
    inc c
    db $fc
    db $fc
    cp $fa
    ld a, a
    ld c, a
    ld a, a
    ld [hl], e
    ld a, a
    ld e, h
    scf
    dec sp
    jr jr_004_72f6

    rra
    rra
    rra
    rra
    ld c, $0e
    cp $f2
    db $fc
    call z, $3cfc
    cp $d2
    ld e, $f2
    db $ec
    db $fc
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    rlca
    rlca
    rrca
    rrca
    rra
    rra
    ccf

jr_004_72f6:
    jr nz, jr_004_7337

    jr nz, jr_004_7339

    ccf
    rra
    ld d, $00
    nop
    ldh [$e0], a
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp+$08
    db $fc
    inc c
    db $fc
    db $fc
    db $fc
    db $fc
    rra
    inc d
    rra
    db $10
    dec bc
    inc c
    rlca
    rlca
    rra
    rra
    ccf
    dec a
    rra
    rra
    ld c, $0e
    ld hl, sp-$68
    ldh a, [rNR10]
    ldh [$60], a
    ldh a, [$d0]
    ldh a, [$30]
    db $fc
    inc a
    db $fc
    db $fc
    jr @+$1a

    rrca
    rrca
    rra
    ld e, $1f
    ld e, $10
    rra
    jr c, jr_004_7376

jr_004_7337:
    ccf
    scf

jr_004_7339:
    ld a, a
    ld d, d
    ld a, a
    ld b, d
    ldh a, [$f0]
    ld hl, sp+$78
    ld hl, sp+$78
    ld [$1cf8], sp
    db $fc
    db $fc
    db $ec
    cp $4a
    cp $42
    ccf
    jr nc, jr_004_736e

    add hl, de
    ccf
    ccf
    ld h, a
    ld a, a
    ld a, c
    ld c, [hl]
    ccf
    rrca
    rra
    rra
    ld e, $1e
    db $fc
    inc c
    ld a, b
    sbc b
    db $fc
    db $fc
    and $fe
    sbc [hl]
    ld [hl], d
    db $fc
    ldh a, [$f8]
    ld hl, sp+$78
    ld a, b
    rrca

jr_004_736e:
    rrca
    rra
    rra
    rra
    rra
    rra
    rra
    ccf

jr_004_7376:
    ccf
    ccf
    ccf
    ld a, b
    ld d, a
    ld a, a
    ld b, b
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    ld hl, sp-$08
    db $fc
    db $fc
    db $fc
    db $fc
    ld e, $ea
    cp $02
    ccf
    jr nc, jr_004_73af

    rra
    ccf
    ccf
    ld a, a
    ld a, a
    ld a, b
    ld a, a
    ccf
    rra
    rra
    rra
    ld e, $1e
    db $fc
    inc c
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fe
    ld e, $fe
    db $fc
    ld hl, sp-$08
    ld hl, sp+$78
    ld a, b
    rrca
    rrca

jr_004_73af:
    rra
    rla
    rra
    rla
    inc hl
    ccf
    ld b, a
    ld a, a
    ld a, $31
    rra
    inc d
    rra
    inc d
    ldh a, [$f0]
    ld hl, sp-$08
    ld hl, sp-$08
    ld hl, sp-$08
    ld hl, sp-$08
    ld [$c8f8], sp
    ld hl, sp-$18
    jr c, jr_004_73ed

    db $10
    dec bc
    inc c
    rrca
    rrca
    rrca
    ld c, $0d
    ld a, [bc]
    rlca
    ld b, $0f
    rrca
    rra
    rra
    ldh a, [$30]
    ret nz

    ld b, b
    ldh [$e0], a
    ldh [$60], a
    and b
    ld h, b
    ldh [$60], a
    ret nz

    ret nz

    add b
    add b

jr_004_73ed:
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    inc c
    rrca

jr_004_73f5:
    ld de, $111e
    ld e, $20
    ccf
    jr nz, jr_004_743c

    nop
    nop
    nop
    nop
    ret nz

    ret nz

    jr nc, jr_004_73f5

    adc b
    ld a, b
    adc b
    ld a, b
    inc b
    db $fc
    inc b
    db $fc
    jr c, @+$29

    ccf
    jr nz, jr_004_7431

    db $10
    rra
    db $10
    rrca
    inc c
    inc bc
    inc bc
    nop
    nop
    nop
    nop
    inc e
    db $e4
    db $fc
    inc b
    ld hl, sp+$08
    ld hl, sp+$08
    ldh a, [$30]
    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    rlca
    rlca

jr_004_7431:
    rra
    jr jr_004_7472

    ld hl, $370b
    ld [hl], l
    ld c, [hl]
    ld a, d
    ld c, l
    ld c, a

jr_004_743c:
    ld a, c
    nop
    nop
    ret nz

    ret nz

    ld [hl], b
    or b
    ld hl, sp+$08
    ld b, b
    cp h
    sbc h
    db $e4
    cp h
    ld b, h
    db $fc
    ld b, h
    ld h, a
    ld e, [hl]
    ld a, [hl]
    ld b, c
    rra
    inc hl
    ccf
    inc h
    ld e, $1d
    dec b
    ld c, $03
    rlca
    nop
    nop
    call z, $a474
    call c, $8870
    cp b
    ld c, b
    ld d, b
    or b
    ldh [$60], a
    add b
    add b
    nop
    nop
    rlca
    rlca
    rra
    jr jr_004_74b1

jr_004_7472:
    jr nz, jr_004_74f3

    ld b, b
    ld a, a
    ld b, b
    rst $38
    add b
    rst $38
    add b
    cp $81
    ldh [$e0], a
    ld hl, sp+$18
    db $fc
    inc b
    cp $02
    cp $02
    rst $28
    ld de, $01ff
    db $fd
    inc bc
    cp a
    ret nz

    rst $18
    and b
    xor d
    push de
    ld d, l
    ld l, d
    ld b, d
    ld a, l
    dec h
    ccf
    ld a, [de]
    rra
    rlca
    rlca
    ld sp, hl
    rlca
    push af
    dec bc
    pop hl
    rra
    ld d, [hl]
    xor [hl]
    ld a, [bc]
    cp $54
    db $fc
    cp b
    ld hl, sp-$20
    ldh [rP1], a
    nop
    ccf
    ccf

jr_004_74b1:
    ccf
    jr nz, @+$32

    cpl
    ccf
    jr nz, @+$34

    dec l
    ccf
    jr nz, jr_004_74ee

    dec l
    nop
    nop
    ld hl, sp-$08
    ld hl, sp+$08
    jr @-$16

    ld hl, sp+$08
    sbc b
    ld l, b
    ld hl, sp+$08
    sbc b
    ld l, b
    ccf
    jr nz, jr_004_7501

    ld l, $3f
    jr nz, jr_004_74f7

    inc a
    ld a, [hl-]
    dec h
    dec de
    inc d
    rrca
    rrca
    nop
    nop
    ld hl, sp+$08
    ld e, b
    xor b
    ld hl, sp+$08
    ld hl, sp+$08
    sbc b
    ld l, b
    ld hl, sp+$08
    ld hl, sp-$08
    nop
    nop
    nop

jr_004_74ee:
    nop
    nop
    nop
    nop
    nop

jr_004_74f3:
    ld a, $3e
    ld e, a
    ld h, c

jr_004_74f7:
    ld d, c
    ld l, [hl]
    ld e, [hl]
    ld h, c
    ld d, l
    ld l, d
    nop
    nop
    nop
    nop

jr_004_7501:
    nop
    nop
    ld a, $3e
    db $fd
    jp $bb45


    ld b, l
    cp e
    ld b, l
    cp e
    ld e, a
    ld h, b
    ld e, a
    ld h, b
    ld d, c
    ld l, [hl]
    ld e, a
    ld h, b
    ld b, b
    ld a, a
    ld a, a
    ld a, a
    nop
    nop
    nop
    nop
    ld a, l
    add e
    ld d, l
    xor e
    ld a, l
    add e
    ld a, l
    add e
    ld bc, $ffff
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, a
    ld a, a
    ld c, b
    ld a, a
    ld e, a
    ld h, a
    ld e, a
    ld h, b
    ld d, d
    ld l, l
    ld e, a
    ld h, b
    ld d, d
    ld l, l

jr_004_753d:
    nop
    nop
    ld hl, sp-$08
    ld c, b
    ld hl, sp-$18
    sbc b
    add sp, $18
    xor b
    ld e, b
    add sp, $18
    xor b
    ld e, b
    ld e, a
    ld h, b
    ld d, c

jr_004_7550:
    ld l, [hl]
    ld e, a
    ld h, b
    ld e, [hl]
    ld h, c
    ld e, a
    ld h, b
    ld b, b
    ld a, a
    ld a, a
    ld a, a
    nop
    nop
    add sp, $18
    ld l, b
    sbc b
    add sp, $18
    jr z, jr_004_753d

    add sp, $18
    ld [$f8f8], sp
    ld hl, sp+$00
    nop
    jr nz, @+$32

    scf
    ccf
    dec sp
    ccf
    rla
    jr c, jr_004_75a5

    inc a
    ld a, a
    ld h, c
    ret nc

    cp a
    xor a
    ldh a, [rDIV]
    inc c
    db $ec
    db $fc
    call c, $e8fc
    inc e
    db $f4
    inc a
    cp $86
    dec bc
    db $fd
    push af
    rrca
    ld e, a
    ld h, b
    ld e, a
    ld h, b
    ld l, a
    ld [hl], b
    ld a, b
    sbc a
    rst $28
    sbc a
    adc a
    rst $38
    ld [hl], b
    ld a, a
    nop
    nop
    ld a, [c]
    ld c, $e2
    ld e, $86
    ld a, [hl]
    ld e, $f9

jr_004_75a5:
    rst $30
    ld sp, hl
    pop af
    rst $38
    ld c, $fe
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    inc b
    rlca
    add hl, bc
    ld c, $13
    inc e
    rla
    jr jr_004_75d3

    jr jr_004_75be

jr_004_75be:
    nop
    nop
    nop
    ret nz

    ret nz

    jr nz, jr_004_75a5

    ret nc

    jr nc, jr_004_7550

    ld a, b
    adc b
    ld a, b
    jr z, jr_004_75a5

    inc d
    dec de
    inc d
    dec de
    jr jr_004_75f2

jr_004_75d3:
    inc c
    rrca
    rlca
    rlca
    inc bc
    inc bc
    nop
    nop
    nop
    nop
    jr z, @-$26

    ld l, b
    sbc b
    ret c

    jr c, @+$32

    ldh a, [$e0]
    ldh [$c0], a
    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    rlca
    rlca
    rrca

jr_004_75f2:
    ld [$1d1b], sp
    ld a, $21
    ld a, [hl]
    ld b, e
    rst $38
    add d
    rst $38
    add b
    ret nz

    ret nz

    db $e3
    inc hl
    rst $20
    push hl
    rst $38
    ld sp, hl
    ld a, a
    db $fd
    db $76
    cp [hl]
    or $3e
    or $5e
    rst $38
    add b
    rst $38
    add d
    ld a, [hl]
    ld b, e
    ld a, $21
    dec de
    inc e
    rrca
    add hl, bc
    rlca
    rlca
    nop
    nop
    or $5e
    or $3e
    db $76
    cp [hl]
    ld a, a
    db $fd
    rst $38
    ld sp, hl
    rst $20
    push hl
    db $e3
    inc hl
    ret nz

    ret nz

    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e7]
    call Call_004_763f
    ret z

    ld a, [$d2e1]
    ld b, a
    ld a, [$d2e8]

Call_004_763f:
    add a
    cp b
    ret z

    inc b
    ret


    call Call_000_3ec4
    ld a, $01
    jr jr_004_7650

    call Call_000_3ec4
    ld a, $02

jr_004_7650:
    ld [$cf7b], a
    push hl
    ld a, [$cf80]
    ld b, a
    ld a, [$cf81]
    ld c, a
    or b
    jr nz, jr_004_7668

    xor a
    ld c, a
    ld e, a
    ld a, $06
    ld d, a
    jp Jump_004_7679


jr_004_7668:
    ld a, [$cfa1]
    ld d, a
    ld a, [$cfa2]
    ld e, a
    ld a, $26
    call Call_000_3e9d
    ld a, $06
    ld d, a
    ld c, a

Jump_004_7679:
    pop hl
    push de
    push hl
    push hl
    call Call_000_2d2c
    pop hl
    ld bc, $0015
    add hl, bc
    ld de, $cf80
    ld bc, $0203
    call Call_000_3c8f
    ld a, $f3
    ld [hl+], a
    ld de, $cfa1
    ld bc, $0203
    call Call_000_3c8f
    pop hl
    pop de
    ret


    call Call_000_2d68
    ld a, [$cc49]
    cp $02
    jr c, jr_004_76bb

    ld a, [$cf82]
    ld [$cfa0], a
    ld [$d0ec], a
    ld hl, $cf8f
    ld de, $cfa1
    ld b, $01
    call Call_000_3980

jr_004_76bb:
    ld hl, $d6ab
    set 1, [hl]
    ld a, $33
    ldh [rNR50], a
    call Call_000_3e04
    call Call_000_03bf
    call Call_000_0ebd
    call Call_000_370a
    ld de, $5119
    ld hl, $96d0
    ld bc, $0403
    call Call_000_031b
    ld de, $5131
    ld hl, $9780
    ld bc, $0401
    call Call_000_031b
    ld de, $5149
    ld hl, $9760
    ld bc, $0402
    call Call_000_031b
    ld de, $7824
    ld hl, $9720
    ld bc, $0401
    call Call_000_031b
    ldh a, [$d7]
    push af
    xor a
    ldh [$d7], a
    ld hl, $c3c7
    ld bc, $060a
    call Call_004_780f
    ld de, $fffa
    add hl, de
    ld [hl], $f2
    dec hl
    ld [hl], $74
    ld hl, $c467
    ld bc, $0806
    call Call_004_780f
    ld hl, $c472
    ld de, $77ef
    call Call_000_0405
    ld hl, $c3e7
    ld a, $5f
    call Call_000_3e9d
    ld hl, $cf1f
    call Call_000_3e29
    ld b, $03
    call Call_000_3e1f
    ld hl, $c422
    ld de, $cf83
    call Call_000_2ed8
    jr nz, jr_004_7751

    ld hl, $c422
    ld de, $780b
    call Call_000_0405

jr_004_7751:
    jp Jump_004_775a


    ld de, $7804
    call Call_000_0405

Jump_004_775a:
    ld hl, $c3c4
    call Call_000_2f02
    ld a, [$d095]
    ld [$d0e3], a
    ld [$d092], a
    ld a, $3a
    call Call_000_3e9d
    ld hl, $c42f
    ld de, $d0e3
    ld bc, $8103
    call Call_000_3c8f

Jump_004_777a:
    ld hl, $c486
    ld a, $4b
    call Call_000_3e9d
    ld hl, $77e7
    call Call_004_77c8
    ld d, h
    ld e, l
    ld hl, $c3bf
    call Call_000_0405
    ld hl, $77df
    call Call_004_77c8
    ld d, h
    ld e, l
    ld hl, $c4ee
    call Call_000_0405
    ld hl, $c4c6
    ld de, $cf8b
    ld bc, $8205
    call Call_000_3c8f
    ld d, $00
    call Call_004_782c
    call Call_000_3e07
    call Call_000_3e0c
    ld hl, $c3a1
    call Call_000_2d7a
    ld a, [$cf78]
    call Call_000_2dc7
    call Call_000_38ae
    pop af
    ldh [$d7], a
    ret


Call_004_77c8:
    ld a, [$cc49]
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$cc49]
    cp $03
    ret z

    ld a, [$cf79]
    jp Jump_000_3ac7


    inc sp
    jp nc, $d92b

    or b
    db $dd
    adc e
    reti


    ld d, a
    jp nc, $d94f

    ld h, h
    sbc $85
    reti


    or h
    cp c
    or b
    and l
    sub c
    ld c, [hl]
    or h
    cp c
    or b
    and l
    sub d
    ld c, [hl]
    ld [hl], e
    ld [hl], h
    ld c, [hl]
    xor l
    and c
    or e
    or h
    ld c, [hl]
    ld d, b
    db $ed
    inc l
    ld a, [c]
    ld b, c
    or d
    di
    ld d, b
    db $ed
    inc l
    db $eb
    ld b, c

Call_004_780f:
    ld de, $0014

jr_004_7812:
    ld [hl], $78
    add hl, de
    dec b
    jr nz, jr_004_7812

    ld [hl], $77
    dec hl

jr_004_781b:
    ld [hl], $76
    dec hl
    dec c
    jr nz, jr_004_781b

    ld [hl], $6f
    ret


    nop
    db $fc
    add $c6
    add $fc
    ret nz

    ret nz

Call_004_782c:
    ld a, d
    and a
    jr nz, jr_004_7842

    ld hl, $c440
    ld b, $08
    ld c, $08
    call Call_000_03d2
    ld hl, $c469
    ld bc, $0005
    jr jr_004_7852

jr_004_7842:
    ld hl, $c3d1
    ld b, $08
    ld c, $09
    call Call_000_03d2
    ld hl, $c3fb
    ld bc, $0004

jr_004_7852:
    push bc
    push hl
    ld de, $7882
    call Call_000_0405
    pop hl
    pop bc
    add hl, bc
    ld de, $cfa3
    ld bc, $0203
    call Call_004_7878
    ld de, $cfa5
    call Call_004_7878
    ld de, $cfa7
    call Call_004_7878
    ld de, $cfa9
    jp Jump_000_3c8f


Call_004_7878:
    push hl
    call Call_000_3c8f
    pop hl
    ld de, $0028
    add hl, de
    ret


    db $ed
    inc l
    ld sp, hl
    ld b, c
    ld c, [hl]
    ld a, $b3
    daa
    ld [c], a
    ld c, [hl]
    cp l
    ld a, [hl-]
    call nc, Call_004_4ebb
    call nz, $bcb8
    pop hl
    ld d, b
    ldh a, [$d7]
    push af
    xor a
    ldh [$d7], a
    ldh [$ba], a
    ld bc, $0005
    ld hl, $d0b9
    call Call_000_372a
    ld hl, $cf87
    ld de, $d0b9
    ld bc, $0004
    call Call_000_01bb
    ld hl, $5e5f
    ld b, $0e
    call Call_000_3620
    ld hl, $c3d1
    ld bc, $050a
    call Call_000_0374
    ld hl, $c3ef
    ld [hl], $78
    ld hl, $c440

Call_004_78cc:
    ld b, $08
    ld c, $12
    call Call_000_03d2
    ld hl, $c455
    ld de, $df30
    call Call_000_0405
    ld a, [$cd67]
    inc a
    ld c, a
    ld a, $04
    sub c
    ld b, a
    ld hl, $c473
    ld de, $0028
    ld a, $72
    call Call_004_7a05
    ld a, b
    and a
    jr z, jr_004_78fa

Call_004_78f4:
    ld c, a
    ld a, $e3
    call Call_004_7a05

jr_004_78fa:
    ld hl, $cf87
    ld de, $c476
    ld b, $00

jr_004_7902:
    ld a, [hl+]
    and a
    jr z, jr_004_7950

    push bc
    push hl
    push de
    ld hl, $cc26
    ld a, [hl]
    push af
    ld a, b
    ld [hl], a
    push hl
    ld hl, $694a
    ld b, $03
    call Call_000_3620
    pop hl
    pop af
    ld [hl], a
    pop de
    pop hl
    push hl
    ld bc, $0014
    add hl, bc
    ld a, [hl]
    and $3f
    ld [$cd6c], a
    ld h, d
    ld l, e
    push hl
    ld de, $cd6c
    ld bc, $0102
    call Call_000_3c8f
    ld a, $f3
    ld [hl+], a
    ld de, $d0e3
    ld bc, $0102
    call Call_000_3c8f
    pop hl
    ld de, $0028
    add hl, de
    ld d, h
    ld e, l
    pop hl
    pop bc
    inc b
    ld a, b
    cp $04
    jr nz, jr_004_7902

jr_004_7950:
    ld hl, $c3e5
    ld de, $79f3
    call Call_000_0405
    ld a, [$cfa0]
    push af
    cp $64
    jr z, jr_004_7965

    inc a
    ld [$cfa0], a

jr_004_7965:
    ld hl, $c426
    ld [hl], $ed
    ld hl, $c426
    ld [hl], $ed
    inc hl
    inc hl
    call Call_000_2f02
    pop af
    ld [$cfa0], a
    ld de, $cf8d
    ld hl, $c3fc
    ld bc, $0307
    call Call_000_3c8f
    call Call_004_79ca
    ld de, $cf8d
    ld hl, $c41f
    ld bc, $0307
    call Call_000_3c8f
    ld hl, $c3ab
    call $79fd
    ld hl, $c3bf
    call $79fd
    ld a, [$d095]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $c3bf
    call Call_000_0405
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    call Call_000_38ae
    pop af
    ldh [$d7], a
    ld hl, $d6ab
    res 1, [hl]
    ld a, $77
    ldh [rNR50], a
    call Call_000_3e15
    jp Jump_000_03bf


Call_004_79ca:
    ld a, [$cfa0]
    cp $64
    jr z, jr_004_79eb

    inc a
    ld d, a
    ld hl, $4fb5
    ld b, $16
    call Call_000_3620
    ld hl, $cf8f
    ldh a, [$98]
    sub [hl]
    ld [hl-], a
    ldh a, [$97]
    sbc [hl]
    ld [hl-], a
    ldh a, [$96]
    sbc [hl]
    ld [hl-], a
    ret


jr_004_79eb:
    ld hl, $cf8d
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ret


    db $ed
    inc l
    ld d, $42
    pop bc
    di
    ld c, [hl]
    or c
    call nz, Call_000_0150
    dec b
    nop
    ld a, $7f
    jp Jump_000_372a


Call_004_7a05:
jr_004_7a05:
    ld [hl+], a
    ld [hl-], a
    add hl, de
    dec c
    jr nz, jr_004_7a05

    ret


    xor a
    ldh [$ba], a
    call Call_000_03bf
    call Call_000_0ebd
    ld b, $1c
    ld hl, $5c55
    call Call_000_3620

Jump_004_7a1d:
    ld a, [$d05a]
    cp $04
    jp z, Jump_004_7b46

    call Call_004_5dd1
    ld b, $1c
    ld hl, $6596
    call Call_000_3620
    ld hl, $c3b7
    ld de, $d124
    xor a
    ld c, a
    ldh [$8c], a
    ld [$cf27], a

Jump_004_7a3d:
    ld a, [de]
    cp $ff
    jp z, Jump_004_7b41

    push bc
    push de
    push hl
    ld a, c
    push hl
    ld hl, $d257
    call Call_000_2fb1
    pop hl
    call Call_000_0405
    ld b, $1c
    ld hl, $5d2c
    call Call_000_3620
    ldh a, [$8c]
    ld [$cf79], a
    inc a
    ldh [$8c], a
    call Call_000_2d68
    pop hl
    push hl
    ld a, [$cc35]
    and a
    jr z, jr_004_7a7d

    dec a
    ld b, a
    ld a, [$cf79]
    cp b
    jr nz, jr_004_7a7d

    dec hl
    dec hl
    dec hl
    ld a, $ec
    ld [hl+], a
    inc hl
    inc hl

jr_004_7a7d:
    ld a, [$d05a]
    cp $03
    jr z, jr_004_7aa4

    cp $05
    jr z, jr_004_7ae0

    push hl
    ld bc, $ffec
    add hl, bc
    ld de, $cf83
    call Call_000_2ed8
    pop hl
    push hl
    ld bc, $fff4
    add hl, bc
    ld a, $60
    call Call_000_3e9d
    call Call_004_7ca6
    pop hl
    jr jr_004_7abe

jr_004_7aa4:
    push hl
    ld a, $43
    call Call_000_3e9d
    pop hl
    ld de, $7ad1
    ld a, c
    and a
    jr nz, jr_004_7ab5

    ld de, $7ad8

jr_004_7ab5:
    push hl
    ld bc, $0009
    add hl, bc
    call Call_000_0405
    pop hl

jr_004_7abe:
    ld bc, $0005
    add hl, bc
    call Call_000_2f02
    pop hl
    pop de
    inc de
    ld bc, $0028
    add hl, bc
    pop bc
    inc c
    jp Jump_004_7a3d


    db $ed
    inc l
    ld d, e
    ld h, l
    jp c, Jump_004_50d9

    db $ed
    inc l
    ld e, c
    ld h, l
    jp c, $b2c5

    ld d, b

jr_004_7ae0:
    push hl
    ld hl, $7427
    ld b, $00
    ld a, [$cf7f]
    dec a
    add a
    rl b
    ld c, a
    add hl, bc
    ld de, $cd68
    ld a, $0e
    ld bc, $0002
    call Call_000_01a3
    ld hl, $cd68
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $cd68
    ld a, $0e
    ld bc, $000d
    call Call_000_01a3
    ld hl, $cd68
    ld de, $7b3b

jr_004_7b11:
    ld a, [hl+]
    and a
    jr z, jr_004_7b2a

    inc hl
    inc hl
    cp $02
    jr nz, jr_004_7b11

    dec hl
    dec hl
    ld b, [hl]
    ld a, [$d11b]
    inc hl
    inc hl
    inc hl
    cp b
    jr nz, jr_004_7b11

    ld de, $7b36

jr_004_7b2a:
    pop hl
    push hl
    ld bc, $0009
    add hl, bc
    call Call_000_0405
    pop hl
    jr jr_004_7abe

    jp nz, $b4b6

    reti


    ld d, b
    jp nz, $b4b6

    push bc
    or d
    ld d, b

Jump_004_7b41:
    ld b, $0a
    call Call_000_3e1f

Jump_004_7b46:
    ld hl, $d6af
    ld a, [hl]
    push af
    push hl
    set 6, [hl]
    ld a, [$d05a]
    cp $f0
    jr nc, jr_004_7b70

    add a
    ld hl, $7b9f
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    call Call_000_3c79

jr_004_7b63:
    pop hl
    pop af
    ld [hl], a
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    jp Jump_000_3e0c


jr_004_7b70:
    and $0f

jr_004_7b72:
    ld hl, $7b8d
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]

Jump_004_7b7b:
    ld h, [hl]
    ld l, a
    push hl
    ld a, [$cf01]
    ld hl, $d257
    call Call_000_2fb1
    pop hl
    call Call_000_3c79

jr_004_7b8b:
    jr jr_004_7b63

    dec bc
    ld a, h
    add hl, sp
    ld a, h
    ld c, c
    ld a, h
    ld e, l
    ld a, h
    dec h
    ld a, h
    ldh a, [$7b]
    ld l, e
    ld a, h
    ld a, e
    ld a, h
    adc [hl]
    ld a, h
    xor e
    ld a, e
    cp c
    ld a, e
    rst $00
    ld a, e
    call nc, $e27b
    ld a, e
    cp c
    ld a, e
    db $ed
    inc l
    ld e, l
    ld h, a
    or h
    rst $10
    sbc $33
    ld a, a
    cp b
    jr nc, jr_004_7b72

    or d
    ld d, a
    db $ed
    inc l
    sub d
    ld h, a
    add $7f
    jp nz, $b2b6

    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    inc l
    ld [hl], d
    ld h, a
    db $dd
    ld a, a
    jr nc, jr_004_7b8b

    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    dec l
    ld [hl-], a
    ld d, [hl]
    add $7f
    or l
    cp h
    or h
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    inc l
    xor l
    ld h, a
    ld a, a
    or d
    inc [hl]
    or e
    cp h
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    inc l
    ld hl, sp+$67
    ret


    ld a, a
    ret nz

    or d

jr_004_7bf8:
    ret c

    ld [c], a
    cp b
    ld h, $4f
    ld d, b
    add hl, bc
    ld hl, sp-$32
    inc hl
    nop
    ld a, a
    or [hl]
    or d
    call z, $bcb8
    ret nz

    ld d, a
    db $ed
    dec l
    ld l, a
    ld l, b
    ret


    ld a, a
    inc [hl]
    cp b
    jp z, $b74f

    jp c, Jump_004_7fb2

    cp e
    rst $18
    ld b, h

jr_004_7c1c:
    ret c

    ld a, a
    push bc
    cp b
    push bc
    rst $18
    ret nz

    rst $20
    ld d, a
    db $ed
    dec l
    pop de
    ld l, b
    ret


    ld a, a
    or [hl]
    rst $10
    jr nc, jr_004_7bf8

    ld c, a
    cp h
    dec sp
    jp c, $7f26

    call nz, $c0da
    ld d, a
    db $ed
    dec l
    add l
    ld l, b
    ret


    ld c, a
    call nc, Call_000_34b9
    ld h, $7f
    push bc
    or l
    rst $18
    ret nz

    ld d, a
    db $ed
    dec l
    and l
    ld l, b
    ret


    ld a, a
    or [hl]
    rst $10
    jr nc, jr_004_7c1c

    ld c, a
    cp d
    or l
    ret c

    ld h, $7f
    call nz, $c0b9
    ld d, a
    db $ed
    dec l
    cp l

Call_004_7c60:
    ld l, b
    jp z, $d24f

    db $dd
    ld a, a
    cp e
    rst $08
    cp h
    ret nz

    ld d, a
    db $ed
    dec l
    rst $28
    ld l, b
    jp z, $b94f

    sbc $ba
    or e
    add $c5
    rst $18
    ret nz

    rst $20
    ld d, a
    db $ed

Call_004_7c7c:
    dec l
    db $fd
    ld l, b
    jp z, Jump_000_294f

    sbc $b7
    db $dd
    ld a, a
    call nz, $d3d8
    inc [hl]
    cp h
    ret nz

    rst $20
    ld d, a
    db $ed
    inc l
    call $c967
    ld a, a
    and a
    dec a
    and [hl]
    ld h, $50
    add hl, bc
    db $ec
    ret nc

    inc de
    nop
    add $c5
    rst $18
    ret nz

    ld d, b
    dec bc
    ld b, $50

Call_004_7ca6:
    ld hl, $cf19
    ld a, [$cf27]
    ld c, a
    ld b, $00
    add hl, bc
    call Call_000_3e29
    ld b, $fc
    call Call_000_3e1f
    ld hl, $cf27
    inc [hl]
    ret


    ld a, [$d0f0]
    cp $04
    jr nz, jr_004_7cfe

    ld a, [$cfcf]
    ld hl, $d827
    ld bc, $002c
    call Call_000_3ad1
    ld a, [$cfd0]
    ld [hl], a
    call Call_000_03bf
    ld hl, $7d9b
    ld b, $0d
    call Call_000_3620
    ld a, [$cf06]
    cp $01
    ld de, $7d66
    jr c, jr_004_7cf1

    ld de, $7d6e
    jr z, jr_004_7cf1

    ld de, $7d76

jr_004_7cf1:
    ld hl, $c446
    call Call_000_0405
    ld c, $c8
    call Call_000_3781

Call_004_7cfc:
    jr jr_004_7d1d

jr_004_7cfe:
    ld a, [$cf06]
    and a
    jr nz, jr_004_7d26

    ld hl, $cce5
    ld a, [hl+]
    or [hl]
    inc hl
    or [hl]
    jr z, jr_004_7d1d

    ld de, $d2cd
    ld c, $03
    ld a, $0b
    call Call_000_3e9d
    ld hl, $7d7d
    call Call_000_3c79

jr_004_7d1d:
    xor a

jr_004_7d1e:
    ld [$ccd4], a
    ld a, $2a
    call Call_000_3e9d

jr_004_7d26:
    xor a
    ld [$d060], a
    ld [$c02a], a
    ld [$d034], a
    ld [$d037], a
    ld [$d03c], a
    ld [$d036], a
    ld [$d0e4], a
    ld [$d0e5], a
    ld [$d055], a
    ld hl, $cc2b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$cc36], a
    ld hl, $d03d
    ld b, $18

jr_004_7d51:
    ld [hl+], a
    dec b
    jr nz, jr_004_7d51

    ld hl, $d6ab
    set 0, [hl]
    call Call_000_3790
    call Call_000_3e15
    ld a, $ff
    ld [$d3ae], a
    ret


    or c
    push bc
    ret nz

    ret


    ld a, a
    or [hl]
    pop bc
    ld d, b
    or c
    push bc
    ret nz

    ret


    ld a, a
    rst $08
    cp c
    ld d, b
    ld a, a
    ld a, a
    res 6, a
    call c, Call_004_50b9
    db $ed
    jr z, jr_004_7d1e

    ld l, c
    ld d, b
    ld [bc], a
    push hl
    call z, Call_000_00c3
    ldh a, [rVBK]
    set 3, e
    rst $18
    ret nz

    rst $20
    ld e, b
    ld a, [$cc57]
    and a
    ret nz

    ld a, [$d6b5]
    and a
    ret nz

    ld hl, $4ae3
    ld b, $03
    call Call_000_3620
    jr nc, jr_004_7da7

jr_004_7da3:
    ld a, $01
    and a
    ret


jr_004_7da7:
    ld hl, $762d
    ld b, $04
    call Call_000_3620
    jr z, jr_004_7da3

    ld a, [$d0b8]
    and a
    jr z, jr_004_7dbd

    dec a
    jr z, jr_004_7e24

    ld [$d0b8], a

jr_004_7dbd:
    ld hl, $c45c
    ld c, [hl]
    ld a, [$d4b4]
    cp c
    ld a, [$d806]
    jr z, jr_004_7de3

    ld a, $14
    cp c
    ld a, [$d823]
    jr z, jr_004_7de3

    ld a, [$d2dd]
    cp $25
    jr c, jr_004_7e31

    ld a, [$d2e6]
    cp $03
    jr z, jr_004_7e31

    ld a, [$d806]

jr_004_7de3:
    ld b, a
    ldh a, [$d3]
    cp b
    jr nc, jr_004_7e31

    ldh a, [$d4]
    ld b, a
    ld hl, $7e37

jr_004_7def:
    ld a, [hl+]
    cp b
    jr nc, jr_004_7df6

    inc hl
    jr jr_004_7def

jr_004_7df6:
    ld c, [hl]
    ld hl, $d807
    ld a, [$c45c]
    cp $14
    jr nz, jr_004_7e04

    ld hl, $d824

jr_004_7e04:
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld [$d0ec], a
    ld a, [hl]
    ld [$cf78], a
    ld [$cfbf], a
    ld a, [$d0b8]
    and a
    jr z, jr_004_7e35

    ld a, [$d14c]
    ld b, a
    ld a, [$d0ec]
    cp b
    jr c, jr_004_7e31

    jr jr_004_7e35

jr_004_7e24:
    ld [$d0b8], a
    ld a, $d2
    ldh [$8c], a
    call Call_000_3c6c
    call Call_000_13f1

jr_004_7e31:
    ld a, $01
    and a
    ret


jr_004_7e35:
    xor a
    ret


    ld [hl-], a
    nop
    ld h, l
    ld [bc], a
    adc h
    inc b
    and l
    ld b, $be
    ld [$0ad7], sp
    db $e4
    inc c
    pop af
    ld c, $fc
    db $10
    rst $38
    ld [de], a
    ld a, [$fff3]
    and a
    ld a, [$cfb9]
    ld hl, $d00a
    jr z, jr_004_7e5d

    ld a, [$cfb3]
    ld hl, $cfdb

jr_004_7e5d:
    ld d, a
    ld a, [$d0b4]
    ld b, a
    ld a, [$d0b5]
    ld c, a
    srl b
    rr c
    ld a, d
    cp $a5
    jr z, jr_004_7e73

    srl b
    rr c

jr_004_7e73:
    ld a, b
    or c
    jr nz, jr_004_7e78

    inc c

jr_004_7e78:
    ld a, [hl+]
    ld [$cee5], a
    ld a, [hl]
    ld [$cee4], a
    push bc

Jump_004_7e81:
    ld bc, $fff2
    add hl, bc
    pop bc
    ld a, [hl]
    ld [$cee6], a
    sub c
    ld [hl-], a
    ld [$cee8], a
    ld a, [hl]
    ld [$cee7], a
    sbc b
    ld [hl], a
    ld [$cee9], a
    jr nc, jr_004_7ea2

    xor a
    ld [hl+], a
    ld [hl], a
    ld hl, $cee8
    ld [hl+], a
    ld [hl], a

jr_004_7ea2:
    ld hl, $c45e
    ldh a, [$f3]
    and a
    ld a, $01
    jr z, jr_004_7eb0

    ld hl, $c3ca
    xor a

jr_004_7eb0:
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d
    ld hl, $7ebe
    jp Jump_000_3c79


    db $ed
    jr z, @-$49

    ld l, c
    cp d
    or e
    add hl, hl
    or a
    ret


    ld c, a
    jp z, $34de

    or e
    db $dd
    ld a, a
    or e
    cp c
    ret nz

    rst $20
    ld e, b
    ld hl, $cfd1
    ld de, $d000
    ldh a, [$f3]
    and a
    ld a, [$d044]
    jr z, jr_004_7ee8

    push hl
    ld h, d
    ld l, e
    pop de
    ld a, [$d03f]

jr_004_7ee8:
    bit 6, a
    jr nz, jr_004_7f15

    ld a, [hl+]
    ld [de], a

jr_004_7eee:
    inc de
    ld a, [hl]
    ld [de], a
    ld hl, $7fdb
    ld b, $0f
    call Call_000_3620
    ld hl, $7eff
    jp Jump_000_3c79


    db $ed
    jr z, jr_004_7eee

    ld l, c
    cpl
    cp b
    cp [hl]
    or d
    db $dd
    ld c, a
    inc l
    inc a
    sbc $c6
    ld a, a
    jp z, $c2d8

    cp c
    ret nz

    rst $20
    ld e, b

jr_004_7f15:
    ld hl, $7f4e
    ld b, $0f
    jp Jump_000_3620


    ld a, $07
    ld hl, $cd1a
    call Call_004_7f8c
    ld hl, $cd2e
    call Call_004_7f8c
    ld hl, $cd12
    ld de, $d00c
    call Call_004_7f93
    ld hl, $cd26
    ld de, $cfdd
    call Call_004_7f93
    ld hl, $cfd0
    ld de, $ccdd
    ldh a, [$f3]
    and a
    jr z, jr_004_7f4c

    ld hl, $cfff
    dec de

jr_004_7f4c:
    ld a, [hl]
    ld [hl], $00
    and $07
    jr z, jr_004_7f56

    ld a, $ff
    ld [de], a

jr_004_7f56:
    xor a
    ld [$d04a], a
    ld [$d04f], a
    ld hl, $ccee
    ld [hl+], a
    ld [hl], a
    ld hl, $d03f
    res 7, [hl]
    inc hl
    ld a, [hl]
    and $78
    ld [hl+], a
    ld a, [hl]
    and $f8
    ld [hl], a
    ld hl, $d044
    res 7, [hl]
    inc hl
    ld a, [hl]
    and $78
    ld [hl+], a
    ld a, [hl]
    and $f8
    ld [hl], a
    ld hl, $7fdb
    ld b, $0f
    call Call_000_3620
    ld hl, $7f9c
    jp Jump_000_3c79


Call_004_7f8c:
    ld b, $08

jr_004_7f8e:
    ld [hl+], a
    dec b
    jr nz, jr_004_7f8e

    ret


Call_004_7f93:
    ld b, $08

jr_004_7f95:
    ld a, [hl+]
    ld [de], a
    inc de
    dec b
    jr nz, jr_004_7f95

    ret


    db $ed
    jr z, @+$2a

    ld l, d
    ret


    ld a, a
    adc h
    sub d
    db $e3
    adc a
    adc h
    ld h, $4f
    db $d3
    call nz, Call_004_7fc6
    db $d3
    inc [hl]
    rst $18
    ret nz

    rst $20

Jump_004_7fb2:
    ld e, b
    ld hl, $d806
    ld a, [$d0f0]
    and a
    jr nz, jr_004_7fe1

    ld hl, $d2ce
    ld a, [$d018]
    cp $19
    jr z, jr_004_7fe1

Call_004_7fc6:
    cp $2a
    jr z, jr_004_7fe1

Call_004_7fca:
    cp $2b
    jr z, jr_004_7fe1

    ld [$d092], a
    ld a, $07
    ld [$d093], a
    ld a, $0e
    ld [$d094], a
    call Call_000_37b3
    ld hl, $cd68

jr_004_7fe1:
    ld de, $df20
    ld bc, $0010
    jp Jump_000_01bb


    ldh a, [rDIV]
    ld b, a
    ldh a, [$d3]
    adc b
    ldh [$d3], a
    ldh a, [rDIV]
    ld b, a
    ldh a, [$d4]
    sbc b
    ldh [$d4], a
    ret


    nop
    dec c
    dec [hl]
    ld b, c
    nop
