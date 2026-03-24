; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $011", ROMX[$4000], BANK[$11]

    jr nz, jr_011_4012

    ld bc, $0c02
    dec c
    dec c
    ld hl, $0504
    rlca
    rlca
    ld [hl+], a
    inc hl
    ld [$0f0f], sp
    rrca

jr_011_4012:
    rrca
    rrca
    dec de
    ld c, $0a
    dec bc

jr_011_4018:
    ld c, $0f
    rrca
    ld c, $03
    rlca
    ld c, l
    ld c, l
    dec sp
    jr c, jr_011_4023

jr_011_4023:
    nop
    dec sp
    jr c, jr_011_4038

    ld hl, $0b00
    ld [$0001], sp
    add hl, bc
    ld a, [bc]
    or c
    ld b, b
    ld c, $41
    dec bc
    ld b, c
    ld c, $15
    cp h

jr_011_4038:
    ld b, h
    db $eb
    add $0a
    ld a, [bc]
    ld b, a
    nop
    add hl, hl
    ret


    rla
    inc l
    ld b, a
    xor e
    rst $00
    ld a, [bc]
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $13
    db $fd
    ld b, c
    jr jr_011_4018

    add hl, bc
    ld e, $00
    dec sp
    ld a, [hl+]
    rst $00
    ld e, c
    ld b, b
    inc l
    ld b, $05
    inc bc
    nop
    adc l
    dec b
    ld c, $00
    adc [hl]
    add hl, bc
    rlca
    nop

jr_011_4066:
    sub l
    dec c
    rrca
    nop
    sub [hl]
    dec c
    inc bc
    nop
    sub a
    dec c
    rlca
    nop
    push hl
    ld b, $09
    dec bc
    inc b
    inc bc
    add hl, bc
    dec b
    dec c
    db $10
    ld b, $05
    inc b
    rlca
    add hl, bc
    dec b
    ld [$1107], sp
    add hl, bc
    inc bc
    ld [$130d], sp
    cp $00
    ld bc, $0e07
    dec c
    rst $38
    rst $38
    ld [bc], a
    inc c
    dec bc
    inc c
    cp $02
    inc bc
    ld a, [de]
    rst $00
    dec b
    inc bc
    jr nz, jr_011_4066

    dec b
    ld c, $3c
    rst $00
    add hl, bc
    rlca
    ld h, b
    rst $00
    dec c
    rrca
    ld e, d
    rst $00
    dec c
    inc bc
    ld e, h
    rst $00
    dec c
    rlca
    ld d, a
    ld d, a
    dec h
    ld a, e
    ld a, e
    jr z, jr_011_4120

    ld a, a
    ld l, c
    inc l
    ld a, e
    jr nz, jr_011_40df

    ld a, e
    ld a, c
    jr z, jr_011_40f9

    ld a, l
    ld a, [hl]
    inc l
    ld a, e
    ld a, h
    ld [hl], d
    ld a, e
    ld a, e
    inc h
    ld d, a
    ld b, $57
    ld a, [hl+]
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, c
    jr z, @+$7d

    ld a, e
    ld a, c
    ld [bc], a
    inc bc
    ld a, c

jr_011_40df:
    ld a, e
    ld a, e
    ld a, e
    jr z, jr_011_415f

    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    jr nz, @+$23

    jr z, jr_011_4169

    ld [bc], a
    inc bc
    ld [bc], a
    inc bc
    ld a, e
    ld a, e
    ld a, h
    ld [hl], e
    jr z, jr_011_4173

    ld a, e

jr_011_40f9:
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    jr z, jr_011_4141

    ccf
    ccf
    dec sp
    ld a, e
    ld a, $3f
    ccf
    ccf
    inc l
    jp Jump_000_3c6c


    jr nz, jr_011_4151

    sbc e
    ld b, c
    sbc $41
    dec d
    ld b, d
    inc [hl]
    ld b, d
    sub [hl]
    rrca
    xor a
    rrca
    ld h, d
    ld b, d
    ld a, b
    ld b, d

jr_011_4120:
    ld [$3c21], sp
    ld b, c
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    ld hl, $4166
    jr nz, jr_011_4136

    ld hl, $4150

jr_011_4136:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    jr jr_011_41b6

    ld c, a

jr_011_4141:
    push de
    or e
    jp c, $cab2

    ld a, a
    or d
    reti


    call nz, $b57f
    db $d3
    or e
    and $57
    db $ed

jr_011_4151:
    add hl, hl
    or b
    db $76
    sbc $4f
    cp h
    sbc $2c
    jp Jump_011_7fd9


    set 0, h
    rst $18

jr_011_415f:
    jp $b27f


    reti


    sbc $30
    ld d, a
    db $ed
    add hl, hl
    ld b, d

jr_011_4169:
    db $76
    ld a, a
    cp a
    or e
    sub $c8
    rst $20
    ld d, c
    or c
    push bc

jr_011_4173:
    ret nz

    ret


    ld a, a
    ret nc

    daa
    or [hl]
    ret nz

    add $4f
    cp h
    db $db
    or d
    ld a, a
    jp Jump_011_7f26


    or l
    or [hl]
    jp c, $d9c3

    ld a, a
    push bc
    sbc $c3
    ld d, l
    ld d, [hl]
    or c
    ret nz

    cp h
    ret


    ld a, a
    ret nc

    rst $08
    pop bc
    ld h, $b2
    sub $c8
    ld d, a
    db $ed
    ld [hl+], a
    xor b
    ld c, h
    ld a, a
    ld d, h
    ret


    ld a, a
    or l
    jp z, $33b6

    ld c, a
    push de
    or e
    jp nc, $c5b2

    ld a, a
    adc a
    add d
    xor e
    jr nc, jr_011_4209

    ld d, c
    or [hl]
    rst $18

jr_011_41b6:
    jp $c0b2


    ld a, a
    ld d, h
    ld h, $7f
    cp h
    sbc $30
    call nz, $4fb7
    ld d, h
    ld a, a
    adc a
    xor c
    db $e3
    add $7f
    db $d3
    rst $18
    jp $dfb2


    jp $d255


    or d
    call z, $ddb8
    ld a, a
    or d
    ret


    reti


    ret


    cp e
    ld d, [hl]
    ld d, a
    db $ed
    ld [hl+], a
    ld b, d
    ld c, l
    sbc $7f
    ld d, h
    ld a, a
    adc a
    xor c
    db $e3
    add $4f
    push de
    or e
    jp c, Jump_000_26b2

    ld a, a
    inc sp
    reti


    ld a, a
    rst $10
    cp h
    or d
    sbc $30
    ld d, [hl]
    ld d, c
    inc [hl]
    or e
    db $d3
    ld a, a
    ld e, [hl]
    add $7f
    cp d
    db $db
    cp e
    jp c, $4fc0

    ld d, h

jr_011_4209:
    ret


    ld a, a
    push de
    or e
    jp c, Jump_011_7fb2

    rst $10
    cp h
    or d
    ld d, [hl]
    ld d, a
    db $ed
    ld [hl+], a
    adc $4d
    ld a, a
    adc e
    add h
    xor e
    ld a, a
    adc a
    add d
    xor e
    ld c, a
    adc e
    add h
    xor e
    jp z, $d17f

    rst $10
    cp e
    or a
    ld a, a
    call nz, $c4b3
    or d
    ld a, a
    or d
    db $db
    ld d, a
    db $ed
    ld [hl+], a
    dec c
    ld c, [hl]
    or d
    ld a, a
    ld d, h
    db $d3
    ld a, a
    sub $b8
    ret nc

    or h
    reti


    and $4f
    cp h
    sbc $7f
    cp [hl]
    or d
    set 3, [hl]
    rst $20
    ld a, a
    adc e
    and [hl]
    sbc e
    adc h
    adc c
    db $e3
    ld b, d
    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    adc e
    and [hl]
    sbc e
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    ld d, a
    db $ed
    ld [hl+], a
    ld [hl], h
    ld c, [hl]
    ld a, a
    or c
    or d
    ret


    ld a, a
    inc e
    and l
    xor e
    sub d
    or b
    add b
    ld c, a
    ld d, h
    ld a, a
    sbc c
    add d
    adc h
    ld d, a
    db $ed
    ld [hl+], a
    and a
    ld c, [hl]
    ld a, a
    ld d, h
    ret


    ld a, a
    jp c, $cab2

    or d
    ld a, a
    call nz, Call_011_4fb3
    ld d, h
    ld a, a
    adc a
    xor c
    db $e3
    ld d, a
    ld hl, $d28e
    ld b, $13
    call Call_000_1690
    ld a, [$d0e3]
    ldh [$db], a
    ld hl, $d27b
    ld b, $13
    call Call_000_1690
    ld a, [$d0e3]
    ldh [$dc], a
    ld hl, $4339

jr_011_42ab:
    ld a, [hl+]
    ld b, a
    ldh a, [$dc]
    cp b
    jr c, jr_011_42b6

    inc hl
    inc hl
    jr jr_011_42ab

jr_011_42b6:
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$d6c6]
    bit 3, a
    res 3, a
    ld [$d6c6], a
    jr nz, jr_011_42db

    push hl
    ld hl, $42f1
    call Call_000_3c79
    pop hl
    call Call_000_3c79
    ld b, $1f
    ld hl, $43db
    call Call_000_3620
    jp Jump_000_38ae


jr_011_42db:
    ld de, $cc5b
    ldh a, [$db]
    ld [de], a
    inc de
    ldh a, [$dc]
    ld [de], a
    inc de

jr_011_42e6:
    ld a, [hl+]
    cp $57
    jr z, jr_011_42ef

    ld [de], a
    inc de
    jr jr_011_42e6

jr_011_42ef:
    ld [de], a
    ret


    db $ed
    add hl, hl
    db $e4
    db $76
    ld a, a
    ld d, h
    dec l
    or [hl]
    sbc $c9
    ld c, a
    add hl, hl
    sbc $2b
    or d
    ret


    ld a, a
    or [hl]
    sbc $be
    or d
    inc [hl]
    ld a, a
    jp z, Jump_011_5156

    ret nc

    jp nz, $c0b9

    ld a, a
    ld d, h
    ld a, a
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    rst $20
    ld c, a
    jp nz, $cfb6

    or h
    ret nz

    ld a, a
    ld d, h
    ld a, a
    ld d, b
    add hl, bc
    call c, Call_000_13ff
    nop
    rst $20
    ld d, c
    add h
    db $e3
    add [hl]
    inc de
    jp z, $beb6

    ret


    ld a, a
    set 4, d
    or e
    or [hl]
    ld d, [hl]
    ld e, b

jr_011_4339:
    ld a, [bc]
    ld l, c
    ld b, e
    inc d
    sub h
    ld b, e
    ld e, $c5
    ld b, e
    jr z, jr_011_4339

    ld b, e
    ld [hl-], a
    inc h
    ld b, h
    inc a
    ld d, l
    ld b, h
    ld b, [hl]
    db $76
    ld b, h
    ld d, b
    sub l
    ld b, h
    ld e, d
    cp b
    ld b, h
    ld h, h
    call c, Call_011_6e44
    cp $44
    ld a, b
    inc h
    ld b, l
    add d
    ld b, e
    ld b, l
    adc h
    ld l, d
    ld b, l
    sub [hl]
    adc h
    ld b, l
    sbc b
    xor e
    ld b, l
    db $ed
    dec l
    ld l, d
    ld h, b
    jr nc, jr_011_43c5

    ld a, a
    cp d
    jp c, $d7b6

    jr nc, jr_011_43c5

    or c
    pop bc
    cp d
    pop bc
    ret


    ld a, a
    cp b
    cp e
    pop de
    rst $10
    add $7f
    jp z, $dfb2

    jp Jump_011_5455


    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    reti


    ret


    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec l
    ret c

    ld h, b
    or [hl]
    ld a, a
    pop bc
    ld [c], a
    or e
    cp h
    ld h, $7f
    inc sp
    jp $c0b7


    push bc
    rst $20
    ld c, a
    inc l
    ld [c], a
    cp h
    pop hl
    add $7f
    sbc e
    and l
    xor h
    adc e
    xor [hl]
    db $dd
    ld d, l
    db $d3
    ret nz

    cp [hl]
    ret nz

    cpl
    rst $20
    ld a, a
    db $d3
    rst $10
    rst $18
    jp $b87f


    jp c, $e7b2

    ld d, a

jr_011_43c5:
    db $ed
    dec l
    ld b, c
    ld h, c
    sbc $c6
    ld a, a
    cp h
    jp Jump_011_7fca


    rst $08
    jr nc, @+$51

    inc e
    ret c

    xor [hl]
    db $e3
    sbc a
    ld h, $7f
    ret nz

    ret c

    sbc $e7
    ld a, a
    or d
    db $db
    or d
    db $db
    push bc
    ld d, l
    cp h
    pop hl
    reti


    or d
    ret


    ld a, a
    ld d, h
    db $dd
    ld a, a
    call nz, $c9d9
    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec l
    or [hl]
    ld h, c
    ld a, a
    ld h, $de
    ld a, [hl-]
    rst $18
    jp $c5d9


    rst $20
    ld c, a
    inc l
    ld [c], a
    cp h
    pop hl
    add $7f
    rrca
    add d
    dec bc
    xor e
    rlca
    sbc l
    adc e
    xor e
    db $dd
    ld d, l
    db $d3
    ret nz

    cp [hl]
    ret nz

    cpl
    rst $20
    ld a, a
    db $d3
    rst $10
    rst $18
    jp $b87f


    jp c, $e7b2

    ld d, a
    db $ed
    dec l
    add hl, bc
    ld h, d
    inc sp
    or a
    ld a, [hl-]
    or h
    ld a, a
    inc l
    ldh [$c5], a
    or d
    or [hl]
    rst $20
    ld c, a
    inc l
    ld [c], a
    cp h
    pop hl
    add $7f
    ld h, $b8
    cp h
    pop hl
    or e
    cp a
    or e
    pop bc
    db $dd
    ld d, l
    db $d3
    ret nz

    cp [hl]
    ret nz

    cpl
    rst $20
    ld a, a
    db $d3
    rst $10
    rst $18
    jp $b87f


    jp c, $e7b2

    ld d, a
    db $ed
    dec l
    ld [hl], e
    ld h, d
    ld a, a
    ei
    or $bc
    pop hl
    reti


    or d
    db $dd
    ld a, a
    cp d
    or h
    ret nz

    or [hl]
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    cp d
    ret


    ld a, a
    pop bc
    ld [c], a
    or e
    cp h
    ld a, a
    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec l
    xor [hl]
    ld h, d
    or e
    rst $20
    ld a, a
    ld d, [hl]
    ld a, a
    cp d
    ret c

    ldh [$7f], a
    or d
    or d
    ld c, a
    ld d, h
    dec l
    or [hl]
    sbc $c6
    ld a, a
    push bc
    rst $18
    jp $b77f


    call nz, $e7d9
    ld d, a
    db $ed
    dec l
    ei
    ld h, d
    or e
    pop bc
    ld [c], a
    or e
    rst $20
    ld a, a
    or e
    ret nc

    inc sp
    ld a, a
    ld d, h
    ld c, a
    jp nz, Jump_000_3ada

    ld a, a
    db $d3
    rst $18
    call nz, $b17f
    jp nz, $d8cf

    ld a, a
    cp a
    or e
    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec l
    ld d, [hl]
    ld h, e
    sbc e
    and [hl]
    rst $20
    ld a, a
    db $d3
    cp h
    or [hl]
    cp h
    jp $b77f


    ret nc

    jp z, $d34f

    ret


    db $dd
    ld a, a
    or c
    jp nz, $d9d2

    ret


    ld a, a
    cp l
    or a
    push bc
    ret


    or [hl]

jr_011_44d9:
    ld d, [hl]
    and $57
    db $ed
    dec l
    ld a, h
    ld h, e
    call nc, Call_011_7f56
    cp d
    ret c

    ldh [$7f], a
    cp l
    ld a, [hl+]
    or d
    rst $20
    ld c, a
    or c
    jp nz, $d9d2

    ret


    jp z, $c07f

    or d
    call $7fde
    jr nc, jr_011_44d9

    ret nz

    db $db
    rst $20
    ld d, a
    db $ed
    dec l
    xor c
    ld h, e
    or e
    ld a, a
    rst $30
    or $f6
    cp h
    pop hl
    reti


    or d
    ld a, a
    cp d
    or h
    ret nz

    or [hl]
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    cp h
    sbc $2c
    rst $10
    jp c, $b2c5

    ld a, a
    or e
    inc sp
    rst $08
    or h
    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec l
    sbc $63
    cp h
    sbc $b6
    ld a, a
    cp c
    or d
    ret nz

    or d
    db $d3
    ld c, a
    jp z, $dfb2

    jp $b77f


    call nz, Call_011_56d9
    ld a, a
    cp l
    ld a, [hl-]
    rst $10
    cp h
    or d
    rst $20
    ld d, a
    db $ed
    dec l
    dec d
    ld h, h
    and a
    xor e
    sub e
    rst $20
    ld a, a
    call nz, Call_000_30d3
    pop bc
    call nz, $ba7f
    or e
    or [hl]
    sbc $4f
    cp l
    reti


    call nz, $d37f
    rst $18
    call nz, $b17f
    jp nz, $d9cf

    ld a, a
    or [hl]
    db $d3
    cp h
    jp c, $57de

    db $ed
    dec l
    ld d, d
    ld h, h
    inc sp
    ld a, a
    dec l
    or [hl]
    sbc $26
    ld a, a
    inc sp
    or a
    ret nz

    rst $10
    ld c, a
    db $d3
    jp z, Jump_011_7fd4

    ld b, d
    xor b
    sbc e
    db $eb
    xor h
    adc e
    xor a
    sub h
    and [hl]
    ld a, a
    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec l
    and a
    ld h, h
    ld a, a
    db $d3
    or e
    ld a, a
    or d
    or e
    cp d
    call nz, Call_011_7fca
    push bc
    or d
    rst $20
    ld c, a
    or a
    ret nc

    ld h, $7f
    ld d, h
    jp z, $beb6

    ld a, a
    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec l
    rst $08
    ld h, h
    ld a, a
    ld b, b
    db $e3
    sbc e
    db $eb
    add a
    sub e
    push bc
    ld a, a
    dec l
    or [hl]
    sbc $c9
    ld c, a
    or [hl]
    sbc $be

jr_011_45c0:
    or d
    inc l
    ldh [$e7], a
    ld a, a
    ld d, [hl]
    ld a, a
    or l
    jp nc, $c433

    or e
    rst $20
    ld d, a
    ld b, $04
    rlca
    nop
    ld b, b
    ldh [rLYC], a
    jp c, Jump_000_0045

    ld h, l
    ld b, [hl]
    call Call_000_0d8e
    jp Jump_000_3c6c


    add sp, $45
    jp hl


    ld b, l
    ld h, $46
    ld h, h
    ld b, [hl]
    rst $38
    db $ed
    inc h
    ld [hl-], a
    ld h, l
    ld a, a
    or c
    reti


    ld a, a
    ld e, e
    jp z, $347f

    or e
    cpl
    ld c, a
    ld a, [hl+]
    inc l
    push de
    or e
    add $7f
    or l
    jp nz, $b2b6

    cp b
    jr nc, jr_011_45c0

    or d
    rst $20
    ld d, c
    ld d, [hl]
    call nz, $b37f
    cp c
    jp nz, $c9b9

jr_011_4610:
    ld a, a
    ret z

    db $e3
    pop bc
    ldh [$de], a
    ld h, $4f
    or d
    rst $18
    call nz, $c0df
    ld a, a
    cp h
    sbc $be
    jp nz, $c9d4

    or e
    ld d, a
    db $ed
    inc h
    cp d
    ld h, l
    adc a
    db $e3
    jp z, $ba7f

    ret


    cp e
    or a
    ld c, a
    inc [hl]
    cp d
    ret


    ld a, a
    rst $08
    pop bc
    add $7f
    or d
    rst $18
    jp Jump_011_7fd3


    or c
    reti


    rst $20
    ld d, c
    push bc
    sbc $3b
    or a
    ld a, a
    or c
    dec l
    cp c
    jp Jump_011_7fd3


    ret nz

    jr nc, jr_011_46d1

    jr nc, jr_011_4610

    ld c, a
    cp d
    rst $08
    jp nc, Jump_011_7fc6

    jp nz, $b3b6

    call nz, $b27f
    or d
    sub $e7
    ld d, a
    or $00
    ld [bc], a
    rlca
    inc bc
    nop
    rst $38
    rlca
    inc b
    nop
    rst $38
    nop
    inc b
    add hl, hl
    dec b
    rlca
    rst $38
    ret nc

    ld bc, $0910
    ld c, $fe
    ld bc, $0702
    rlca
    ld [$ffff], sp
    inc bc
    ld a, [hl+]
    ld b, $0f
    rst $38
    ret nc

    inc b
    ld e, $c7
    rlca
    inc bc
    rra
    rst $00
    rlca
    inc b
    ld d, $0e
    rrca
    ld c, [hl]
    ld c, b
    ld a, [de]
    ld b, a
    sbc l
    ld b, [hl]
    nop
    db $f4
    ld b, a
    call Call_011_46b3
    call Call_000_3c6c
    ld hl, $4722
    ld de, $4714
    ld a, [$d5b9]
    call Call_000_31a8
    ld [$d5b9], a
    ret


Call_011_46b3:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld a, [$d715]
    bit 0, a
    jr nz, jr_011_46da

    ld bc, $060c
    call Call_011_46f9
    ld bc, $0308
    call Call_011_46f2
    ld bc, $080a

jr_011_46d1:
    call Call_011_46f2
    ld bc, $0d0d
    jp Jump_011_46f2


jr_011_46da:
    ld bc, $060c
    call Call_011_46f2
    ld bc, $0308
    call Call_011_46f9
    ld bc, $080a
    call Call_011_46f9
    ld bc, $0d0d
    jp Jump_011_46f9


Call_011_46f2:
Jump_011_46f2:
    ld a, $2d
    ld [$d07c], a
    jr jr_011_46fe

Call_011_46f9:
Jump_011_46f9:
    ld a, $0e
    ld [$d07c], a

jr_011_46fe:
    ld a, $17
    call Call_000_3e9d
    ret


    ld a, [$c109]
    cp $04
    ret nz

    xor a
    ldh [$b4], a
    ld a, $04
    ldh [$8c], a
    jp Jump_000_13f1


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    cpl
    ld b, a
    push bc
    rrca
    push bc
    rrca
    add e
    ld b, a
    ld bc, $1730
    rst $10
    add hl, sp
    ld b, a
    ld h, e
    ld b, a
    ld e, h
    ld b, a
    ld e, h
    ld b, a
    rst $38
    ld [$2221], sp
    ld b, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $e8
    ld [hl], a
    ld a, a
    or d
    push bc
    or d
    ld a, a
    jp z, $c92d

    ld c, a
    or d
    or h
    db $dd
    ld a, a
    or c
    reti


    or a
    ld a, a
    rst $08
    call c, Call_011_55d9
    or a
    ret nc

    jp z, $307f

    jp c, $c830

    and $57
    db $ed
    ld h, $68
    ld a, b
    ret nz

    push bc
    ld e, b
    db $ed
    ld h, $23
    ld a, b
    add $e6
    ld c, a
    add l
    ld b, $dd
    ld a, a
    cp e
    ld h, $bc
    jp $b27f


    reti


    ret


    or [hl]
    ld d, l
    cp e
    or c
    ld a, a
    cp h
    rst $10
    push bc
    or d
    ret z

    or h
    ld d, [hl]
    ld d, a
    ld [$be21], sp
    ld b, a
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_011_47b5

    ld a, $01
    ld [$cc3c], a
    ld hl, $d0eb
    set 5, [hl]
    ld hl, $47d8
    call Call_000_3c79
    ld a, $ad
    call Call_000_0e45
    ld hl, $d715
    bit 0, [hl]
    set 0, [hl]
    jr z, jr_011_47bb

    res 0, [hl]
    jr jr_011_47bb

jr_011_47b5:
    ld hl, $47e8
    call Call_000_3c79

jr_011_47bb:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld h, e
    ld [hl], a
    ret


    ld a, a
    adc h
    add c
    xor h
    sub b
    ld h, $7f
    or c
    reti


    rst $20
    ld d, c
    or l
    cp h
    jp $d07f


    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    add hl, hl
    sub a
    ld [hl], a
    ret nc

    sub $b3
    rst $20
    ld a, a
    ld d, [hl]
    ld b, e
    sub b
    xor h
    call nz, Call_011_58c5
    db $ed
    add hl, hl
    pop bc
    ld [hl], a
    jp z, $b17f

    or a
    rst $10
    jp nc, $57c0

    ld l, $08
    dec de
    inc b
    nop
    rst $38
    dec de
    dec b
    nop
    rst $38
    dec de
    ld b, $00
    rst $38
    dec de
    rlca
    nop
    rst $38
    ld a, [bc]
    dec b
    nop
    sub $17
    dec d
    nop
    ret c

    dec de
    ld a, [de]
    nop
    rst $38
    dec de
    dec de
    nop
    rst $38
    nop
    inc bc
    jr nz, jr_011_482f

    dec d
    rst $38
    jp nc, $e441

    inc b
    dec a
    rlca
    ld [de], a
    rst $38
    rst $38
    add d
    dec e
    dec a
    add hl, de
    ld d, $ff
    rst $38
    add e
    ld h, $11

jr_011_482f:
    ret z

    dec de
    inc b
    ld de, $1bc8
    dec b
    ld [de], a
    ret z

    dec de
    ld b, $12
    ret z

    dec de
    rlca
    ld l, c
    rst $00
    ld a, [bc]
    dec b
    rst $28
    rst $00
    rla
    dec d
    inc e
    ret z

    dec de
    ld a, [de]
    inc e
    ret z

    dec de
    dec de
    ld b, b
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld e, h
    ld b, $0e
    ld c, $53
    ld c, $11
    ld de, $1111
    ld de, $0e0e
    ld c, $5d
    ld e, h
    ld [hl], a
    ld c, $47
    ld b, [hl]
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld b, b
    ld h, e
    ld c, $5d
    ld b, h
    ld c, $43
    ld c, $46
    ld c, $53
    ld e, b
    ld c, $57
    ld e, b
    ld d, l
    ld c, $0e
    ld b, [hl]
    ld d, b
    ld c, c
    ld c, c
    ld e, b
    ld b, $07
    ld b, [hl]
    ld c, $0e
    ld c, $06
    jr c, jr_011_48de

    ld c, $5d
    ld b, h
    ld de, $3b3a
    ld a, [bc]
    ld c, $46
    ld c, $43
    ld b, e
    ld sp, $0e38
    ld sp, $445d
    ld de, $3b3f
    ld a, [bc]
    ld d, e
    ld c, d
    ld c, c
    ld c, c
    ld c, c
    ld e, b
    ld b, $0e
    ld d, a
    ld d, c
    ld b, h
    ld de, $3b3f
    ld a, [bc]
    ld b, [hl]
    ld c, $0e
    ld c, $06
    rlca
    ld c, $0e
    ld c, $5d
    ld b, h
    ld de, $3b3f
    ld a, [bc]
    ld b, [hl]
    ld c, $0e
    ld c, $48
    ld c, $58
    ld c, $57
    ld d, c
    ld b, h
    ld de, $3b3f
    ld a, [bc]
    ld b, [hl]
    ld c, $0b
    dec bc

jr_011_48de:
    dec bc
    ld c, $06
    ld d, d
    rlca
    ld e, l
    ld b, h
    ld de, $3b3f
    ld a, [bc]
    ld b, [hl]
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld b, h
    ld c, $46
    ld b, h
    ld de, $3b3f
    ld a, [bc]
    ld b, [hl]
    ld c, $0b
    dec bc
    dec bc
    ld c, [hl]
    ld c, $44
    ld c, $46
    ld b, h
    ld de, $3b3f
    ld a, [bc]
    ld b, [hl]
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld b, $0e
    ld b, [hl]
    ld c, b
    ld e, b
    ccf
    dec sp
    ld d, a
    ld c, d
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld b, $0e
    ld b, $11
    ld [de], a
    inc d
    ld d, l
    ld c, h
    ld b, l
    ld c, c
    inc l
    ld c, c
    nop
    sub $4b
    call Call_000_3c6c
    ld hl, $4955
    ld de, $493f
    ld a, [$d5a0]
    call Call_000_31a8
    ld [$d5a0], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    xor d
    ld c, c
    or b
    ld c, c
    or [hl]
    ld c, c
    cp h
    ld c, c
    jp nz, $c849

    ld c, c
    adc $49
    or l
    ld c, e
    ld bc, $5140
    rst $10
    ret c

    ld c, c
    ei
    ld c, c
    pop af
    ld c, c
    pop af
    ld c, c
    ld [bc], a
    ld b, b
    ld d, c
    rst $10
    inc hl
    ld c, d
    ld d, l
    ld c, d
    inc [hl]
    ld c, d
    inc [hl]
    ld c, d
    inc bc
    jr nc, @+$53

    rst $10
    ld a, c
    ld c, d
    and d
    ld c, d
    sbc h
    ld c, d
    sbc h
    ld c, d
    inc b
    jr nc, @+$53

    rst $10
    cp h
    ld c, d
    rst $10
    ld c, d
    rst $08
    ld c, d
    rst $08
    ld c, d
    dec b
    ld b, b
    ld d, c
    rst $10
    db $eb
    ld c, d
    ld hl, $0d4b
    ld c, e
    dec c
    ld c, e
    ld b, $40
    ld d, c
    rst $10
    ccf
    ld c, e
    ld h, h
    ld c, e
    ld e, d
    ld c, e
    ld e, d
    ld c, e
    rlca
    ld b, b
    ld d, c
    rst $10
    ld a, [hl]
    ld c, e
    and b
    ld c, e
    sub l
    ld c, e
    sub l
    ld c, e
    rst $38
    ld [$5521], sp
    ld c, c
    jr jr_011_49d2

    ld [$6121], sp
    ld c, c
    jr jr_011_49d2

    ld [$6d21], sp
    ld c, c
    jr jr_011_49d2

    ld [$7921], sp
    ld c, c
    jr jr_011_49d2

    ld [$8521], sp
    ld c, c
    jr jr_011_49d2

    ld [$9121], sp
    ld c, c
    jr jr_011_49d2

    ld [$9d21], sp
    ld c, c

jr_011_49d2:
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    pop bc
    ld d, [hl]
    push bc
    ld h, $e3
    or d
    ld c, a
    sub e
    xor e
    sub a
    and [hl]
    db $dd
    ld a, a
    rst $00
    cp c
    reti


    ld a, a
    jp nz, $d8d3

    or [hl]
    rst $20
    ld d, a
    db $ed
    dec h
    sub h
    ld d, a
    ret


    ld a, a
    rst $08
    cp c
    jr nc, jr_011_4a53

    db $ed
    dec h
    push af
    ld d, [hl]
    ld a, a
    inc sp
    reti


    ld a, a
    add c
    xor c
    db $e3
    add a
    jp z, $a74f

    dec a

jr_011_4a0b:
    and [hl]
    ld h, $7f
    ret nz

    or [hl]
    or d
    call nz, $bc7f
    jp nc, $b9c2

    jp $d9b8


    ld d, l
    or a
    db $dd
    ld a, a
    jp nz, $c5b9

    sub $57
    db $ed
    dec h
    xor e
    ld d, a
    ld c, a
    ret nc

    pop bc
    add $7f
    rst $08
    sub $df
    ret nz

    or [hl]

jr_011_4a31:
    push bc
    and $57
    db $ed
    dec h
    ld d, c
    ld e, b
    rst $18
    jp Jump_011_4fd9


    ld a, [hl-]
    or c
    or d
    inc l
    ldh [$7f], a
    push bc
    or [hl]
    rst $18
    ret nz

    ld d, l
    inc sp
    jr z, jr_011_4a0b

    jp z, $347f

    rst $18
    pop bc
    ld a, a
    jr nc, jr_011_4a31

    cp c

jr_011_4a53:
    and $58
    db $ed
    dec h
    push bc
    ld d, a
    sbc $7f
    inc [hl]
    or e
    db $db
    add $4f
    ld d, h
    ld h, $7f
    ret z

    jp $dbc0


    and $55
    or l
    jp c, Jump_011_7fd3

    cp d
    rst $08
    rst $18
    jp $cf7f


    call c, $d0d8
    pop bc
    jr nc, jr_011_4ad0

    db $ed
    dec h
    sub b
    ld e, b
    ld c, a
    call nc, $c6cf
    ld a, a
    cp l
    sbc $33
    ld a, a
    push bc
    ld h, $b2
    ld d, l
    sub $bf
    db $d3
    ret


    add $7f
    inc sp
    or [hl]
    or d
    ld a, a
    jp nz, $cad7

    ld a, a
    cp e
    cp [hl]
    sbc $57
    db $ed
    dec h
    ld e, h
    ld e, c
    or c
    ld e, b
    db $ed
    dec h
    pop af
    ld e, b
    ld a, a
    ret nc

    cp d
    ret nc

    ld h, $7f
    or c
    reti


    ld c, a
    call nc, $b5cf
    call nz, $c6ba
    ld a, a
    push bc
    rst $10
    sbc $b6
    and $57
    db $ed
    dec h
    ld l, [hl]
    ld e, c
    jp hl


    add c
    sub e
    db $e3
    rst $20
    ld c, a
    and a
    ld [de], a
    or b
    db $e3
    ld a, a
    add hl, bc
    db $e3
    rst $20
    ld d, a
    db $ed

jr_011_4ad0:
    dec h
    push de
    ld e, c
    ret nz

    ret


    or [hl]
    ld e, b
    db $ed
    dec h
    adc l
    ld e, c
    sub e
    inc sp
    db $d3
    ld c, a
    call nz, $c3df
    ld a, a
    or [hl]
    or h
    db $db
    or e
    or [hl]
    push bc
    ld d, [hl]
    ld d, a
    db $ed
    dec h
    jp hl


    ld e, c
    dec sp
    rst $18
    cp b
    ret c

    rst $20
    ld c, a
    or e
    cp l
    jr z, jr_011_4ad0

    or d
    ld a, a
    or [hl]
    rst $10
    rst $18
    jp $cd55


    sbc $c5
    ld a, a
    cp d
    call nz, $bc7f
    push bc
    or d
    inc sp
    rst $20
    ld d, a
    db $ed
    dec h
    xor a
    ld e, d
    rst $10
    cp b
    jp $d64f


    cp b
    ld a, a
    ret nc

    or h
    push bc
    or d
    sbc $30
    db $d3
    sbc $58
    db $ed
    dec h
    ld b, d
    ld e, d
    and [hl]
    add $d3
    ld a, a
    ld d, h
    ld a, a
    or d
    reti


    ret


    ret z

    ld c, a
    cp e
    rst $18
    or a
    ld a, a
    xor c
    xor e
    ret c

    add [hl]
    db $e3
    ld h, $7f
    or d
    ret nz

    call c, $ed57
    dec h
    pop hl
    ld e, d
    ld h, $bc
    add $7f
    or a
    jp $ba4f


    sbc $c5
    ld a, a
    call nz, $cfba
    inc sp
    ld a, a
    or a
    pop bc
    ldh [$df], a
    ret nz

    rst $20
    ld d, a
    db $ed
    dec h
    ld d, b
    ld e, e
    ld d, h
    ld a, a
    push bc
    or d
    call c, $ed58
    dec h
    rlca
    ld e, e
    or d
    ld a, a
    or [hl]
    or l
    ld a, a
    cp h
    jp $b94f


    rst $18
    cp d
    or e
    ld a, a
    jp nz, $b2d6

    ld a, a
    inc l
    ldh [$c5], a
    or d
    ld d, a
    db $ed
    dec h
    ld h, b
    ld e, e
    jp c, Jump_011_7fca

    ld d, h
    rst $20
    ld c, a
    cp e
    rst $18
    cp a
    cp b
    ld a, a
    jp z, $d22c

    rst $08
    cp h
    ld [c], a
    rst $20
    ld d, a
    db $ed
    dec h
    cp b
    ld e, e
    cp h
    jp $b87f


    reti


    call c, $ed58
    dec h
    add l
    ld e, e
    add c
    sub e
    ld a, a
    cp h
    jp $b14f


    cp [hl]
    ld a, a
    or [hl]
    or d
    pop bc
    ldh [$df], a
    ret nz

    call c, $ed57
    dec h
    add b
    ld d, [hl]
    ld a, a
    add c
    xor c
    and d
    sbc l
    ld a, a
    sub e
    xor e
    sub a
    and [hl]
    ld c, a
    sbc c
    sub h
    rrca
    ld a, a
    adc e
    sub d
    or b
    ld a, a
    ld d, [hl]
    ld a, a
    adc e
    add h
    xor e
    ld a, a
    adc a
    add d
    xor e
    ld d, a
    inc bc
    ld [$0f03], sp
    ld bc, $00ff
    rrca
    ld bc, $21ff
    rrca
    ld [bc], a
    rst $38
    inc hl
    rrca
    ld [bc], a
    rst $38
    inc bc
    dec h
    nop
    add sp, $03
    dec b
    ld bc, $0be8
    ld de, $e802
    ld de, $0325
    add sp, $01
    dec e
    dec bc
    ld [$0e07], sp
    add hl, bc
    dec bc
    rst $38
    ret nc

    ld b, c
    pop de
    inc c
    ld c, $14
    add hl, bc
    rst $38
    ret nc

    ld b, d
    pop de
    dec c
    ld c, $13
    dec d
    rst $38
    jp nc, $d143

    ld c, $0c
    inc c
    dec de
    rst $38
    jp nc, $cf44

    rlca
    ld b, $19
    add hl, hl
    rst $38
    jp nc, $ce45

    ld de, $1c06
    ld a, [de]
    rst $38
    ret nc

    ld b, [hl]
    adc $12
    ld b, $1c
    inc h
    rst $38
    db $d3
    ld b, a
    adc $13
    inc h
    rst $00
    inc bc
    rrca
    ld a, [bc]
    rst $00
    nop
    rrca
    xor d
    ret z

    ld hl, $c40f
    ret z

    inc hl
    rrca
    cpl
    rst $00
    inc bc
    dec h
    rra
    rst $00
    inc bc
    dec b
    adc l
    rst $00
    dec bc
    ld de, $c7e5
    ld de, $1425
    ld d, $20
    ld [hl+], a
    inc d
    add hl, de
    ld d, $20
    ld [hl+], a
    inc d
    add hl, de
    add hl, de
    add hl, de
    ld d, $14
    add hl, de
    ld d, $02
    ld [bc], a
    ld [bc], a
    jr jr_011_4c85

    jr z, @+$03

    jr jr_011_4c88

    ld a, [de]
    ld a, $01
    inc e
    dec e
    dec e
    dec e
    ld e, $1c
    dec e
    ld e, $01
    jr z, @+$04

    inc e
    ld e, $01
    ld bc, $1d1c
    ld e, $01

jr_011_4c85:
    ld bc, $0101

jr_011_4c88:
    ld bc, $0101
    ld bc, $0201
    ld bc, $1701
    rla
    ld bc, $0101
    ld bc, $1701
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld [bc], a
    ld bc, $1f01
    rra
    ld bc, $0101
    ld bc, $1f01
    jr nz, @+$24

    ld [bc], a
    ld bc, $0201
    jr nz, @+$24

    jr nz, @+$24

    ld bc, $1701
    rla
    ld bc, $1701
    ld bc, $1701
    ld bc, $1728
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rra
    rra
    ld bc, $1f01
    ld bc, $1f01
    ld bc, $1f01
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rla
    rla
    ld bc, $1701
    ld bc, $0101
    ld bc, $0201
    jr nz, @+$24

    jr nz, @+$24

    jr nz, jr_011_4d13

    jr nz, @+$24

    ld [bc], a
    rra
    rra
    ld bc, $1f01
    ld bc, $0101
    ld bc, $0101
    ld bc, $0117
    ld bc, $1701
    ld bc, $2801
    rla
    rla
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101

jr_011_4d13:
    ld bc, $011f
    ld bc, $1f01
    ld bc, $0101
    rra
    rra
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0117
    ld bc, $1701
    ld bc, $0101
    rla
    rla
    jr nz, @+$24

    jr nz, jr_011_4d58

    jr nz, jr_011_4d5a

    jr nz, @+$24

    jr nz, @+$24

    rra
    ld bc, $0101
    rra
    ld bc, $0101
    rra
    rra
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $1701
    ld bc, $0101

jr_011_4d58:
    rla
    ld [bc], a

jr_011_4d5a:
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $1f01
    ld bc, $0101
    rra
    inc d
    dec d
    dec d
    dec d
    ld d, $2a
    ld bc, $0101
    ld bc, $1514
    ld d, $01
    ld bc, $0101
    ld bc, $1701
    jr @+$1b

    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $1801
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    rra
    jr jr_011_4db0

    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $3e01
    ld bc, $1801
    add hl, de
    ld a, [de]
    inc d
    dec d
    dec d
    dec d
    dec d
    dec d
    ld d, $1c
    dec e
    dec e
    dec e
    ld e, $4e
    ld d, c

jr_011_4db0:
    ld d, d
    ld c, l
    ld c, [hl]
    inc e
    dec e
    ld e, $1c
    dec e
    dec e
    dec e
    dec e
    dec e
    ld e, $11
    add hl, bc
    rrca
    add l
    ld c, [hl]
    dec hl
    ld c, [hl]
    ret


    ld c, l
    nop
    cpl
    ld c, [hl]
    call Call_000_3c6c
    ld hl, $d766
    set 0, [hl]
    ld hl, $cd5b
    bit 7, [hl]
    res 7, [hl]
    jr z, jr_011_4e1b

    ld hl, $4e26
    call Call_000_352e
    ret nc

    ld hl, $d767
    ld a, [$cd3d]
    cp $01
    jr nz, jr_011_4df9

    set 6, [hl]
    ld a, $d7
    ld [$d056], a
    ld a, $d9
    ld [$d057], a
    jr jr_011_4e05

jr_011_4df9:
    set 7, [hl]
    ld a, $d8
    ld [$d056], a
    ld a, $da
    ld [$d057], a

jr_011_4e05:
    ld a, [$d056]
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, [$d057]
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


jr_011_4e1b:
    ld a, $9f
    ld [$d69c], a
    ld hl, $4e26
    jp $78a6


    ld b, $11
    ld b, $18
    rst $38
    add e
    rrca
    add e
    rrca
    ld a, l
    rlca
    ld de, $0004
    rst $38
    ld de, $0005
    rst $38
    ld de, $011a
    rst $38
    ld de, $011b
    rst $38
    dec b
    rlca
    ld bc, $039f
    add hl, de
    ld b, $9f
    rrca
    rla
    inc b
    sbc a
    ld [bc], a
    dec c
    dec b
    inc bc
    dec c
    add hl, de
    inc b
    ld [bc], a
    ccf
    ld c, $16
    rst $38
    db $10
    ld bc, $0b3f
    ld e, $ff
    db $10
    ld [bc], a
    xor b
    rst $00
    ld de, $a804
    rst $00
    ld de, $b305
    rst $00
    ld de, $b31a
    rst $00
    ld de, $2b1b
    rst $00
    dec b
    rlca
    rra
    rst $00
    inc bc
    add hl, de
    sbc h
    rst $00
    rrca
    rla
    ld b, l
    rst $00
    ld b, $11
    ld c, c
    rst $00
    ld b, $18
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    inc d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    ld d, $28
    ld bc, $2e2e
    jr jr_011_4ebf

    inc a
    add hl, de
    inc l
    dec e
    dec e
    dec e
    dec e
    dec l
    ld e, $01
    ld bc, $2e2e
    jr @+$1b

    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $7801
    ld bc, $016d
    ld [hl], a

jr_011_4ebf:
    ld bc, $2e2e
    jr jr_011_4edd

    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $016d
    ld bc, $2e01
    ld l, $1c
    dec e
    add hl, hl
    dec e
    ld e, $01
    ld bc, $0101
    ld c, h
    ld e, [hl]
    ld e, [hl]

jr_011_4edd:
    ld e, [hl]
    ld l, $2e
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld l, l
    ld bc, $0101
    ld l, $2e
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld l, l
    jr z, @+$03

    ld bc, $2e2e
    ld l, $24
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    inc h
    ld l, $0d
    inc bc
    ld a, [bc]
    ld l, e
    ld c, a
    dec de
    ld c, a
    jr @+$51

    nop
    ld d, c
    ld c, a
    jp Jump_000_3c6c


    dec e
    ld c, a
    db $ed
    dec h
    ld l, e
    ld l, d
    ld [c], a
    or e
    jp z, $b97f

    sbc $c9
    ld a, a
    ret nz

    jp nz, $de2c

    ld c, a
    or d
    or c
    or d
    daa
    ret c

Jump_011_4f33:
    ld h, $7f
    call nz, $b2b8
    rst $20
    ld d, c
    ld d, h
    add $d3
    ld a, a
    cp a
    ret


    ld a, a
    call c, $dd2b
    ld c, a
    or l
    cp h
    or h
    reti


    rst $18
    jp $b27f


    or e
    ld l, $e7
    ld d, a
    inc c
    ld [bc], a
    inc bc
    nop
    nop
    ld h, e
    inc bc
    inc de
    rlca
    ld h, b
    nop
    ld bc, $0713
    dec c
    cp $02
    ld bc, $c709
    inc bc
    nop
    ld [de], a
    rst $00
    inc bc
    inc de
    ld [de], a
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    ld de, $041d
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc e
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld de, $0f09
    scf
    ld d, d
    add hl, sp
    ld d, b
    sub l
    ld c, a
    nop
    call $cd51
    xor e
    ld c, a
    call Call_000_3c6c
    ld hl, $504d
    ld de, $4fc6
    ld a, [$d5bf]
    call Call_000_31a8
    ld [$d5bf], a
    ret


    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

Call_011_4fb3:
    ld hl, $d792
    bit 0, [hl]
    ret z

    ld a, $1d
    ld [$d07c], a
    ld bc, $0503
    ld a, $17
    jp Jump_000_3e9d


    call z, $944f
    ld [hl-], a
    cp l
    ld [hl-], a
    ld hl, $cd5b
    bit 7, [hl]
    res 7, [hl]
    jp z, Jump_011_5013

    ld hl, $500e

Jump_011_4fd9:
    call Call_000_352e
    jp nc, Jump_011_5013

    ld a, [$cd3d]
    cp $01
    jr nz, jr_011_4ff1

    ld hl, $d0eb
    set 5, [hl]
    ld hl, $d792
    set 0, [hl]
    ret


jr_011_4ff1:
    ld hl, $d792
    bit 6, [hl]
    set 6, [hl]
    jr nz, jr_011_5013

    ld a, $7a
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $60
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


    dec b
    inc bc
    rrca
    rla
    rst $38

Jump_011_5013:
jr_011_5013:
    ld a, $c2
    ld [$d69c], a
    ld hl, $500e
    call $78a6
    ld a, [$cd3d]
    cp $01
    jr nz, jr_011_5030

    ld hl, $d6ac
    res 4, [hl]
    ld hl, $d6b1
    res 4, [hl]
    ret


jr_011_5030:
    ld a, [$d6ac]
    bit 4, a
    jp z, Jump_000_3261

    ret


    ld a, [hl]
    ld d, b
    adc $50
    ld e, $51
    ld a, d
    ld d, c
    push bc
    rrca
    push bc
    rrca
    add e
    rrca
    add e
    rrca
    add e
    rrca
    add e
    rrca
    ld bc, $9210
    rst $10
    adc b
    ld d, b
    or d
    ld d, b
    xor b
    ld d, b
    xor b
    ld d, b
    ld [bc], a
    ld b, b
    sub d
    rst $10
    ret c

    ld d, b
    ei
    ld d, b
    ld a, [c]
    ld d, b
    ld a, [c]
    ld d, b
    inc bc
    ld b, b
    sub d
    rst $10
    jr z, jr_011_50bc

    ld c, a
    ld d, c
    ld b, e
    ld d, c
    ld b, e
    ld d, c
    inc b
    ld b, b
    sub d
    rst $10
    add h
    ld d, c
    xor d
    ld d, c
    and b
    ld d, c
    and b
    ld d, c
    rst $38
    ld [$4d21], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld c, [hl]
    ld e, c
    call nz, $c27f
    sub $b2
    ld a, a
    cp d
    inc [hl]
    db $d3
    ld h, $7f

jr_011_5097:
    or d
    reti


    call nz, $824f
    xor c
    adc d
    jp z, $b77f

    or d
    jp $b27f


    reti


    sub $57
    db $ed
    daa
    ld a, [$c059]
    ld a, a
    call nc, $30c2
    ld e, b
    db $ed
    daa
    sub h
    ld e, c
    sub e
    jr nc, jr_011_5097

    ret


    ld a, a
    adc d

jr_011_50bc:
    add l
    add [hl]
    db $dd
    ld c, a
    ret nz

    or l
    cp h
    ret nz

    ret


    jp z, $567f

    ld a, a
    or a
    ret nc

    or [hl]
    rst $20
    ld d, a
    ld [$5921], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    rla
    ld e, d
    jp z, $b37f

    or h
    ld h, $7f
    or d
    reti


    rst $18
    jp $b54f


    cp h
    or h
    jp $b17f


jr_011_50ed:
    add hl, hl
    rst $08
    cp l
    rst $20
    ld d, a
    db $ed
    daa
    reti


    ld e, d
    call nc, $b2bc
    rst $20
    ld e, b
    db $ed
    daa
    ld h, h
    ld e, d
    ld a, a
    call c, $bcc0
    sub $d8
    ld a, a
    jp nz, $b2d6

    call c, $4fe7
    or e
    or h
    add $ca
    ld a, a
    or e
    or h
    ld h, $7f
    or d
    reti


    rst $18
    jp $ba7f


    call nz, $57b6
    ld [$6521], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed

jr_011_5129:
    daa
    inc bc
    ld e, e
    jp c, Jump_011_7fc0

    db $d3
    ret


    ld a, a
    jr nc, jr_011_50ed

    ld h, $4f
    cp d
    cp d
    db $dd
    ld a, a
    rst $00
    cp c
    rst $10
    jp c, $c9d9

    jr nc, jr_011_5129

    ld d, a
    db $ed
    daa
    sub b
    ld e, e
    ret


    ld a, a
    jp z, $3eb2

    cp b
    jr nc, @+$5a

    db $ed
    daa
    dec l
    ld e, e
    ld a, a
    ld e, l
    db $d3

Jump_011_5156:
    ld a, a
    ret nc

    sbc $c5
    ld c, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    db $dd
    ld a, a
    jp nc, $bc2b

    jp $d9b2


    ld d, l
    push de
    jr nc, @-$20

    ld a, a
    cp h
    push bc
    or d
    ld a, a
    adc $b3
    ld h, $7f
    or d
    or d
    ld l, $e7
    ld d, a
    ld [$7121], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    xor d
    ld e, e
    ld a, a
    or c
    or d
    jp $7fdd


    db $d3
    call nz, $d9d2
    ret


    jp z, Jump_011_5d4f

    ret


    ld a, a
    cp h
    pop hl
    cp b
    jp nc, $d6b2

    rst $20
    ld d, a
    db $ed
    daa
    add hl, sp
    ld e, h
    ld a, a
    jp nz, $b2d6

    rst $20
    ld e, b
    db $ed
    daa
    rst $18
    ld e, e
    or d
    ld a, a
    ret nz

    ret nz

    or [hl]
    or d
    db $dd
    ld a, a
    jp nz, $b932

    jp $ce4f


    sbc $c4
    or e
    ret


    ld a, a
    jp nz, $bbd6

    ld h, $7f
    ret nc

    add $7f
    jp nz, $dcb8

    ld d, a
    ld a, l
    inc b
    rlca
    rla
    inc bc
    jp nz, Jump_000_1a08

    dec b
    jp nz, $1b0f

    inc b
    jp nz, Jump_000_0200

    ld b, $c2
    nop
    ld a, [bc]
    rlca
    add hl, bc
    jr nz, @+$01

    jp nc, $e741

    ld [bc], a
    ld b, $11
    dec bc
    rst $38
    db $d3
    ld b, d
    add sp, $02
    rlca
    ld [de], a
    ld a, [bc]
    rst $38
    jp nc, $e743

    inc bc
    ld b, $07
    ld de, $d3ff
    ld b, h
    add sp, $03
    dec a
    add hl, bc
    ld e, $ff
    rst $38
    add l
    ld [hl], $3d
    dec bc
    dec bc
    rst $38
    rst $38
    add [hl]
    rst $30
    ccf
    rlca
    ld a, [de]
    rst $38
    db $10
    rlca
    ccf
    db $10
    ld de, $10ff
    ld [$0e3f], sp
    inc e
    rst $38
    db $10
    add hl, bc
    ccf
    inc de
    ld a, [de]
    rst $38
    db $10
    ld a, [bc]
    ld c, b
    rst $00
    rlca
    rla
    ld e, a
    rst $00
    ld [$9e1a], sp
    rst $00
    rrca
    dec de
    rst $38
    add $00
    ld [bc], a
    ld c, l
    inc hl
    ld [hl], h
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
    ld h, b
    rlca
    ld [$0d0d], sp
    ld h, b
    inc d
    dec d
    dec d
    dec d
    dec d
    ld d, $60
    ld h, b
    ld h, b
    inc c
    rlca
    ld b, $6c
    dec bc
    ld h, b
    jr jr_011_5287

    dec e
    dec e
    dec l
    ld e, $60
    ld h, b
    ld [bc], a
    ld c, $07
    ld l, d
    ld l, e
    ld l, e
    ld l, a
    jr jr_011_5284

    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    jr z, jr_011_5279

    dec b
    add hl, bc
    ld h, [hl]
    dec e
    dec hl
    ld [hl], b
    jr jr_011_5293

jr_011_5279:
    ld h, b
    ld h, b
    rrca
    ld [$040d], sp
    ld b, $27
    rlca
    ld b, $60

jr_011_5284:
    inc e
    dec h
    dec e

jr_011_5287:
    ld e, $60
    ld h, b
    ld h, b
    ld h, b
    rlca
    ld h, b
    ld de, $070e
    ld b, $60

jr_011_5293:
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld b, $05
    dec b
    dec b
    dec b
    ld h, b
    ld b, $60
    rlca
    ld b, $60
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld [bc], a
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld l, c
    ld b, $28
    rlca
    ld [bc], a
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    ld a, [bc]
    inc b
    ld [bc], a
    ld d, $0e
    rrca
    ld [hl+], a
    ld d, l
    inc d
    ld d, e

jr_011_52c5:
    jp z, $0052

    ret nz

    ld d, h
    call Call_011_52e0
    call Call_000_3c6c
    ld hl, $5322
    ld de, $530e
    ld a, [$d5b0]
    call Call_000_31a8
    ld [$d5b0], a
    ret


Call_011_52e0:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld a, [$d794]
    bit 7, a
    jr nz, jr_011_5301

    bit 5, a
    jr nz, jr_011_52f7

    ld a, $54
    jr jr_011_5303

jr_011_52f7:
    ld a, $ad
    call Call_000_0e45
    ld hl, $d794
    bit 7, [hl]

jr_011_5301:
    ld a, $0e

jr_011_5303:
    ld [$d07c], a
    ld bc, $080c
    ld a, $17
    jp Jump_000_3e9d


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld e, a
    ld d, e
    and e
    ld d, e
    push hl
    ld d, e
    ld a, [hl+]
    ld d, h
    ld [hl], d
    ld d, h
    push bc
    rrca
    push bc
    rrca
    ld bc, $9430
    rst $10
    ld l, c
    ld d, e
    adc a
    ld d, e
    add l
    ld d, e
    add l
    ld d, e
    ld [bc], a
    jr nz, jr_011_52c5

    rst $10
    xor l
    ld d, e
    jp z, $c253

    ld d, e
    jp nz, Jump_000_0353

    jr nz, @-$6a

    rst $10
    rst $28
    ld d, e
    ld [$ff54], sp
    ld d, e
    rst $38
    ld d, e
    inc b
    jr nc, @-$6a

    rst $10
    inc [hl]
    ld d, h
    ld c, a
    ld d, h
    ld b, [hl]
    ld d, h
    ld b, [hl]
    ld d, h
    dec b
    jr nc, @-$6a

    rst $10
    ld a, h
    ld d, h
    and h
    ld d, h
    sub b
    ld d, h
    sub b
    ld d, h
    rst $38
    ld [$2221], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld c, l
    ld e, h
    rst $08
    or h
    jp z, $307f

    jp c, $e630

    ld c, a
    inc [hl]
    or e
    call nc, $c3df
    ld a, a
    cp d
    cp d
    add $7f
    jp z, $dfb2

    ret nz

    ld d, a
    db $ed
    daa
    cp d
    ld e, h
    ld a, a
    call nc, $dad7
    ret nz

    ld e, b
    db $ed
    daa
    ld [hl], e
    ld e, h
    ld d, [hl]
    ld a, a
    or l
    rst $08
    or h
    ld c, a
    ld e, [hl]
    db $dd
    ld a, a
    push bc
    jp nc, $d9c3

    push bc
    rst $20
    ld d, a
    ld [$2e21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    call z, $bc5c
    ret


    dec sp
    ld a, a
    cp d
    pop de
    ld a, a
    call nz, Call_011_7fca
    push bc
    sbc $c3
    ld a, a
    call nc, Call_011_57c2
    db $ed
    daa
    ld c, l
    ld e, l
    ret c

    ld d, [hl]
    rst $20
    ld e, b
    db $ed
    daa
    db $fc
    ld e, h
    rst $20
    ld a, a
    cp d
    ret


    rst $08
    rst $08
    ld a, a
    rst $10
    cp b
    add $4f
    cp l
    cp l
    jp nc, $c4d9

    ld a, a
    or l
    db $d3
    or e
    push bc
    rst $20
    ld d, a
    ld [$3a21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld l, d
    ld e, l
    pop hl
    or e
    cp h
    ldh [$dd], a
    ld a, a
    jp z, $b9df

    sbc $e7
    ld d, a
    db $ed
    daa
    rst $10
    ld e, l
    ld a, a
    jr nc, @-$2c

    or [hl]
    ld e, b
    db $ed
    daa
    add [hl]
    ld e, l
    rst $20
    ld c, a
    adc e
    and [hl]
    sbc e
    adc h
    adc c
    db $e3
    ld b, d
    db $dd
    ld a, a
    cp e
    ld h, $bc
    jp $e6d9


    ld d, l
    ld d, [hl]
    ld a, a
    or l
    jp c, Jump_011_7fca

    cp h
    rst $10
    ret z

    or h
    sub $57
    ld [$4621], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    db $ec
    ld e, l
    ld a, a
    or a
    ret nz

    ld a, a
    ret z

    rst $10
    or d
    jp z, $c57f

    sbc $30
    and $57
    db $ed
    daa
    ld h, l
    ld e, [hl]
    ld a, a
    add c
    add l
    xor e
    ld e, b
    db $ed
    daa
    inc de
    ld e, [hl]
    ret nz

    ld a, a

Jump_011_5455:
    or d
    or e
    ld d, [hl]
    ld c, a
    inc e
    adc h
    add $7f
    or c
    or d
    ret nz

    or d
    ld a, a
    push bc
    rst $10
    ld d, l
    add e
    and a
    dec a
    db $e3
    adc a
    add $7f
    ret


    reti


    sbc $30
    push bc
    ld d, a
    ld [$5221], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld [hl], e
    ld e, [hl]
    ret


    ld a, a
    rst $08
    or d
    ld a, [hl+]
    ret


    ld d, [hl]
    ld c, a
    ld a, $b3
    call nc, $b67f
    push bc
    and $57
    nop
    or a
    ret z

    reti


    sbc a
    ld a, a
    ld d, c
    ld d, b
    ld [$9421], sp
    rst $10
    set 5, [hl]
    ld hl, $54a2
    ret


    ld b, $50
    db $ed
    daa
    xor b
    ld e, [hl]
    ld a, a
    or d
    rst $08
    ret


    ld a, a
    cp e
    call c, $3327
    ld c, a
    call nz, $d73b
    ld h, $7f
    or c
    or d
    ret nz

    ld a, a
    cp h
    rst $08
    rst $18
    ret nz

    ld d, a
    ld l, $05
    ld [bc], a
    rla
    nop
    ret z

    ld [bc], a
    dec d
    ld [bc], a
    add a
    inc de
    jr jr_011_54cd

jr_011_54cd:
    rr b
    dec d
    inc bc
    ret z

    inc de
    add hl, de
    ld bc, $00cb
    rlca
    jr jr_011_54e6

    ld e, $ff
    jp nc, $e641

    ld [$0a18], sp
    db $10
    rst $38
    db $d3
    ld b, d

jr_011_54e6:
    and $09
    jr jr_011_54ff

    ld d, $ff
    ret nc

    ld b, e
    and $0a
    jr @+$1f

    inc de
    rst $38
    db $d3
    ld b, h
    and $0b
    jr jr_011_5510

    jr nz, @+$01

    jp nc, $e645

jr_011_54ff:
    inc c
    dec a
    ld [de], a
    rrca
    rst $38
    rst $38
    add [hl]
    dec e
    dec a
    dec d
    dec c
    rst $38
    rst $38
    add a
    ld [de], a
    ld e, $c7

jr_011_5510:
    ld [bc], a
    rla
    dec e
    rst $00
    ld [bc], a
    dec d
    rst $00
    rst $00
    inc de
    jr jr_011_551f

    ret z

    jr jr_011_5533

    rst $00

jr_011_551f:
    rst $00
    inc de
    add hl, de
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $40
    ld b, c
    ld b, c
    ld b, d
    ld l, $2e
    ld l, $2e

Call_011_5533:
jr_011_5533:
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $44
    ld l, [hl]
    ld l, a
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld b, b
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld h, e
    ld c, $0e
    ld h, a
    ld b, c
    ld b, d
    ld l, $2e
    ld l, $2e
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld b, b
    ld a, [hl+]
    dec hl
    ld b, d
    dec c
    ld c, $09
    ld b, b
    ld a, [hl+]
    dec hl
    ld b, d
    ld l, $2e
    ld l, $2e
    ld b, h
    ld c, $0e
    ld b, [hl]
    dec c
    ld c, $09
    ld b, h
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld b, h
    ld b, a
    ld b, a
    ld b, [hl]
    dec c
    ld c, $09
    ld b, h
    ld b, a
    ld b, a
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld [de], a
    ld c, $0e
    ld b, [hl]
    dec c
    ld c, $09
    ld [de], a
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld b, b
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld c, $67
    ld b, d
    ld l, $2e
    ld l, $2e
    ld [de], a
    ld c, $34
    inc [hl]
    inc [hl]
    ld c, $0e
    ld b, [hl]
    inc l
    ld d, a
    ld c, d
    ld l, $2e
    ld l, $2e
    ld [de], a
    ld c, $36
    ld [hl], $36
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $12
    ld c, $36
    ld [hl], $36
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld l, $2e

Call_011_55d9:
    ld l, $12
    ld c, $37
    scf
    scf
    ld c, $6f
    ld b, [hl]
    ld l, $2e
    ld l, $2e

Jump_011_55e6:
    ld l, $2e
    ld l, $48
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld l, $2e
    ld l, $16
    ld c, $0f
    ld l, b
    ld e, c
    and b
    ld e, b
    nop
    ld d, [hl]
    nop
    jr jr_011_5659

    call Call_000_3c6c
    ld hl, $58aa
    ld de, $5613
    ld a, [$d5b1]
    call Call_000_31a8
    ld [$d5b1], a
    ret


    dec de
    ld d, [hl]
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    sbc e
    ld d, a
    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e1]
    ld c, a
    ld hl, $5646
    call Call_000_348c
    cp $ff
    jp z, Jump_000_3261

    ld hl, $d6b5
    set 7, [hl]
    call Call_000_34d0
    ld a, $a7
    call Call_000_0e45
    ld a, $ff
    ld [$cd66], a
    ld a, $03
    ld [$d97c], a
    ret


    add hl, bc
    inc b
    di
    ld d, [hl]
    dec bc
    inc b
    or $56
    rrca
    inc b
    ld sp, hl
    ld d, [hl]
    db $10
    inc b
    cp $56
    inc de
    inc b
    di

jr_011_5659:
    ld d, [hl]
    ld d, $04
    dec b
    ld d, a
    ld c, $05
    ld a, [bc]
    ld d, a
    ld d, $06
    rrca
    ld d, a
    jr jr_011_566e

    ld [de], a
    ld d, a
    add hl, bc
    ld [$5715], sp

jr_011_566e:
    inc c
    ld [$5718], sp
    rrca
    ld [$5712], sp
    inc de
    ld [$5715], sp
    rla
    ld [$571b], sp
    ld c, $09
    jr nz, jr_011_56d9

    ld d, $09
    jr nz, @+$59

    add hl, bc
    ld a, [bc]
    inc hl
    ld d, a
    ld a, [bc]
    ld a, [bc]
    ld h, $57
    rrca
    ld a, [bc]
    dec hl
    ld d, a
    ld de, $300a
    ld d, a
    inc de
    ld a, [bc]
    dec [hl]
    ld d, a
    add hl, de
    ld a, [bc]
    or $56
    ld c, $0b
    inc a
    ld d, a
    db $10
    dec bc
    ld b, e
    ld d, a
    ld [de], a
    dec bc
    jr nz, jr_011_5701

    add hl, bc
    inc c
    ld c, b
    ld d, a
    dec bc
    inc c
    ld c, e
    ld d, a
    dec c
    inc c
    ld d, b
    ld d, a
    ld de, $550c
    ld d, a
    ld a, [bc]
    dec c
    ld e, d
    ld d, a
    inc c
    dec c
    ld e, a
    ld d, a
    db $10
    dec c
    ld h, d
    ld d, a
    ld [de], a
    dec c
    ld h, a
    ld d, a
    inc de
    dec c
    ld l, h
    ld d, a
    ld d, $0d
    ld [hl], l
    ld d, a
    rla
    dec c
    ld a, d
    ld d, a
    ld de, $810e

Call_011_56d9:
jr_011_56d9:
    ld d, a
    db $10
    rrca
    jr nz, jr_011_5735

    ld c, $10
    add h
    ld d, a
    db $10
    db $10
    add a
    ld d, a
    ld [de], a
    db $10
    adc d
    ld d, a
    ld a, [bc]
    ld de, $578d
    dec bc
    ld de, $5794
    rst $38
    jr nz, jr_011_56f7

    rst $38
    db $10

jr_011_56f7:
    inc b
    rst $38
    ld b, b
    inc b
    db $10
    inc b
    rst $38
    ld b, b
    inc b
    db $10

jr_011_5701:
    inc b
    ld b, b
    ld bc, $20ff
    ld [bc], a
    ld b, b
    inc bc
    rst $38
    add b
    ld [bc], a
    db $10
    inc b
    rst $38
    ld b, b
    ld [bc], a
    rst $38
    ld b, b
    inc b
    rst $38
    jr nz, @+$08

    rst $38
    ld b, b
    ld bc, $20ff
    ld b, $40
    inc b
    rst $38
    add b
    ld [bc], a
    rst $38
    jr nz, @+$0a

    rst $38
    jr nz, jr_011_5730

    ld b, b
    ld bc, $20ff
    ld [$0640], sp
    rst $38

jr_011_5730:
    ld b, b
    ld [bc], a
    db $10
    inc b
    rst $38

jr_011_5735:
    ld b, b
    ld [bc], a
    db $10
    inc b
    ld b, b
    ld [bc], a
    rst $38
    add b
    ld [bc], a
    db $10
    inc b
    add b
    ld [bc], a
    rst $38
    add b
    ld [bc], a
    db $10
    inc b
    rst $38
    jr nz, jr_011_5754

    rst $38
    jr nz, jr_011_5757

    ld b, b
    ld [bc], a
    rst $38
    jr nz, @+$0c

    ld b, b
    inc b

jr_011_5754:
    rst $38
    ld b, b
    ld [bc], a

jr_011_5757:
    db $10
    ld [bc], a
    rst $38
    db $10
    ld bc, $0280
    rst $38
    db $10
    ld bc, $80ff
    ld [bc], a
    db $10
    ld [bc], a
    rst $38
    add b
    ld [bc], a
    jr nz, jr_011_576d

    rst $38
    ld b, b

jr_011_576d:
    ld [bc], a
    db $10
    inc b
    ld b, b
    ld [bc], a
    jr nz, jr_011_5777

    rst $38
    add b
    ld [bc], a

jr_011_5777:
    jr nz, jr_011_577d

    rst $38
    jr nz, jr_011_5782

    ld b, b

jr_011_577d:
    inc b
    jr nz, jr_011_5785

    rst $38
    ld b, b

jr_011_5782:
    ld [bc], a
    rst $38
    ld b, b

jr_011_5785:
    ld bc, $40ff
    inc bc
    rst $38
    ld b, b
    dec b
    rst $38
    db $10
    ld bc, $0280
    jr nz, jr_011_5797

    rst $38
    jr nz, @+$0c

    ld b, b

jr_011_5797:
    ld [bc], a
    jr nz, jr_011_579f

    rst $38
    ld a, [$cd38]
    and a

jr_011_579f:
    jr nz, jr_011_57b0

    xor a
    ld [$cd66], a
    ld hl, $d6b5
    res 7, [hl]
    ld a, $00
    ld [$d97c], a
    ret


Jump_011_57b0:
jr_011_57b0:
    ld a, [$c102]
    srl a
    srl a
    ld hl, $585c
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$c102], a

Call_011_57c2:
    ld a, [$d2e6]
    cp $16
    ld hl, $57fc
    jr z, jr_011_57cf

    ld hl, $582c

jr_011_57cf:
    ld a, [$cd38]
    bit 0, a
    jr nz, jr_011_57da

    ld de, $0018

Jump_011_57d9:
    add hl, de

jr_011_57da:
    ld a, $04
    ld bc, $0000

jr_011_57df:
    push af
    push hl
    push bc
    add hl, bc
    ld a, [hl+]
    ld e, a

jr_011_57e5:
    ld a, [hl+]
    ld d, a

Call_011_57e7:
Jump_011_57e7:
    ld a, [hl+]
    ld c, a
    ld a, [hl+]
    ld b, a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    call Call_000_02dd
    pop bc
    ld a, $06
    add c
    ld c, a
    pop hl
    pop af
    dec a
    jr nz, jr_011_57df

    ret


    ld h, b
    ld e, b
    ld bc, $0011
    sub d
    ld [hl], b
    ld e, b
    ld bc, $1011
    sub d
    add b
    ld e, b
    ld bc, $0011
    sub e
    sub b
    ld e, b
    ld bc, $1011
    sub e
    ret nc

    ld [hl], e
    ld bc, $001a
    sub d
    ldh [$73], a
    ld bc, $101a
    sub d
    ret nc

    ld [hl], h
    ld bc, $001a
    sub e
    ldh [$74], a
    ld bc, $101a
    sub e
    ld [hl], b
    ld e, b
    ld bc, $c011
    sub e
    sub b
    ld e, b
    ld bc, $d011
    sub e
    ld h, b
    ld e, b
    ld bc, $c011
    sub h
    add b
    ld e, b
    ld bc, $d011
    sub h
    db $10
    ld b, h
    ld bc, $c01a
    sub e
    jr nz, jr_011_5890

    ld bc, $d01a
    sub e
    db $10
    ld b, l
    ld bc, $c01a
    sub h
    jr nz, jr_011_589d

    ld bc, $d01a
    sub h
    ld [$040c], sp
    nop
    add b
    ld [hl], b
    add b
    jr c, jr_011_57e5

    inc e
    add b
    ld c, $80
    rlca
    add b
    inc bc
    add b
    ld bc, $00ff
    rst $38
    nop
    add b
    ld bc, $0380
    add b
    rlca
    add b
    ld c, $80
    inc e
    add b
    jr c, @-$7e

    ld [hl], b
    ld bc, $010e
    inc e
    ld bc, $0138
    ld [hl], b
    ld bc, $01e0
    ret nz

    ld bc, $ff80
    nop

jr_011_5890:
    rst $38
    nop
    ld bc, $0180
    ret nz

    ld bc, $01e0
    ld [hl], b
    ld bc, $0138

jr_011_589d:
    inc e
    ld bc, $b70e
    ld e, b
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    ld bc, $9640
    rst $10
    pop bc
    ld e, b
    ld a, [c]
    ld e, b
    db $eb
    ld e, b
    db $eb
    ld e, b
    rst $38
    ld [$aa21], sp
    ld e, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    db $e4
    ld e, [hl]

Call_011_58c5:
    adc h
    adc c
    db $e3
    ld b, d
    db $dd
    ld a, a
    jp nz, $b3b6

    call nz, $d04f
    or h
    push bc
    or d
    ld a, a
    push de
    or e
    jp c, $d3b2

    ld a, a
    ret nc

    or h
    reti


    rst $18
    jp Jump_000_1c55


    adc h
    ld h, $7f
    or d
    rst $18
    jp Jump_000_2fc0


    ld d, a
    db $ed
    daa
    and e
    ld e, a
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    scf
    ld e, a
    adc $de
    inc a
    jp z, $c14f

    or [hl]
    ld a, a
    ld a, [$b2b6]
    ld a, a
    rst $08
    inc sp
    ld a, a
    or c
    reti


    ld d, l
    inc e
    adc h
    rst $08
    inc sp
    ld a, a
    ret nz

    inc [hl]
    ret c

    ld a, a
    jp nz, $d9b9

    or [hl]
    push bc
    and $57
    ld l, $05
    ld [$001b], sp
    rst $00
    ld [$0015], sp
    ret


    inc de
    jr jr_011_5925

jr_011_5925:
    rl [hl]
    dec d
    inc bc
    rst $00
    inc de
    add hl, de
    ld bc, $00cb
    dec b
    jr jr_011_5942

    jr @+$01

    ret nc

    ld b, c
    and $0d
    dec a
    rrca
    dec b
    rst $38
    rst $38
    add d
    ld a, [bc]
    dec a
    inc c
    inc d

jr_011_5942:
    rst $38
    rst $38
    add e
    ld sp, $103d
    ld a, [bc]
    rst $38
    rst $38
    add h
    rst $08
    dec a
    add hl, de
    rlca

jr_011_5950:
    rst $38
    rst $38
    add l
    inc de
    ld e, a
    rst $00
    ld [$5c1b], sp
    rst $00
    ld [$c715], sp
    rst $00
    inc de
    jr jr_011_5950

    rst $00
    ld d, $15
    rst $00
    rst $00
    inc de
    add hl, de
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $40
    ld b, c
    ld b, c
    ld a, d
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, b
    ld b, c
    ld b, d
    ld b, c
    ld b, c
    ld b, d
    ld b, h
    inc de
    dec de
    ld a, [bc]
    dec de
    dec de
    dec de
    inc e
    ld e, $55
    ld l, a
    ld b, [hl]
    dec c
    ld l, [hl]
    ld b, [hl]
    ld a, c
    add hl, sp
    ld h, $19
    inc de
    rla
    ld [bc], a
    ld c, $0f
    ld c, $0e
    ld b, [hl]
    dec c
    ld c, $46
    ld b, h
    ld a, [bc]
    ld a, [de]
    ld e, $17
    jr nz, jr_011_59f0

    dec d
    inc de
    ld c, $0e
    ld d, [hl]
    dec c
    ld c, $46
    ld a, c
    add hl, de
    inc bc
    ld c, $02
    ld [bc], a
    dec [hl]
    inc de
    rla
    ld e, c
    ld c, $0e
    ld c, $0e
    ld b, [hl]
    ld b, h
    add hl, de
    rla
    dec [hl]
    add hl, hl
    inc bc
    inc bc
    ld [bc], a
    rla
    ld b, b
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld b, h

jr_011_59f0:
    inc de
    dec de
    ld c, $1b
    ld [bc], a
    rrca
    add hl, hl
    rla
    ld d, l
    ld c, $53
    inc l
    ld d, a
    ld c, d
    ld b, h
    jr jr_011_5a12

    dec d
    jr nz, jr_011_5a2d

    dec e
    jr nz, @+$10

    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $44
    jr nz, @+$19

    rla
    ld [bc], a

jr_011_5a12:
    ld c, $0f
    jr nz, jr_011_5a24

    ld e, c
    ld l, [hl]
    ld b, [hl]
    ld l, $2e
    ld l, $44
    ld de, $1711
    add hl, hl
    ld h, $19
    inc de

jr_011_5a24:
    jr nz, @+$46

    ld c, $46
    ld l, $2e
    ld l, $48
    ld c, c

jr_011_5a2d:
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    inc sp
    ld c, b
    ld c, c
    ld c, d
    ld l, $2e
    ld l, $16
    ld c, $0f
    ld b, b
    ld e, h
    dec de
    ld e, e
    ld b, [hl]
    ld e, d
    nop
    ld c, $5c
    call Call_000_3c6c
    ld hl, $5b23
    ld de, $5a59
    ld a, [$d5b2]
    call Call_000_31a8
    ld [$d5b2], a
    ret


    ld h, c
    ld e, d
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    dec b
    ld e, e
    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e1]
    ld c, a
    ld hl, $5a8c
    call Call_000_348c
    cp $ff
    jp z, Jump_000_3261

    ld hl, $d6b5
    set 7, [hl]
    call Call_000_34d0
    ld a, $a7
    call Call_000_0e45
    ld a, $ff
    ld [$cd66], a
    ld a, $03
    ld [$d97c], a
    ret


    dec c
    ld a, [bc]
    db $ec
    ld e, d
    inc de
    ld a, [bc]
    call Call_000_125a
    dec bc
    call nc, Call_000_0b5a
    inc c
    reti


    ld e, d
    ld de, $dc0c
    ld e, d
    inc d
    inc c
    db $e3
    ld e, d
    db $10
    dec c
    db $ec
    ld e, d
    dec bc
    ld c, $ef
    ld e, d
    rrca
    ld c, $ec
    ld e, d
    ld de, $f20e
    ld e, d
    inc de
    ld c, $f7
    ld e, d
    db $10
    rrca
    rst $28
    ld e, d
    ld [de], a
    rrca
    db $fc
    ld e, d
    dec c
    db $10
    rst $38
    ld e, d
    inc c
    ld de, $5afc
    db $10
    ld [de], a
    ld [bc], a
    ld e, e
    rst $38
    db $10
    inc b
    ld b, b
    inc b
    db $10
    inc b
    rst $38
    add b

jr_011_5ad5:
    inc b
    db $10
    inc b
    rst $38
    jr nz, jr_011_5add

    rst $38
    db $10

jr_011_5add:
    inc b
    ld b, b
    ld [bc], a
    db $10
    ld [bc], a
    rst $38
    db $10
    inc b
    ld b, b
    ld [bc], a
    db $10
    ld [bc], a
    ld b, b
    inc bc
    rst $38
    db $10
    inc b
    rst $38
    db $10
    ld [bc], a
    rst $38
    db $10
    inc b
    ld b, b
    ld [bc], a
    rst $38
    db $10
    inc b
    ld b, b
    inc b
    rst $38
    add b
    inc b
    rst $38
    ld b, b
    ld [bc], a
    rst $38
    ld b, b
    ld bc, $faff
    jr c, jr_011_5ad5

    and a
    jp nz, Jump_011_57b0

    xor a
    ld [$cd66], a
    ld hl, $d6b5
    res 7, [hl]
    ld a, $00
    ld [$d97c], a
    ret


    inc a
    ld e, e
    or b
    ld e, e
    push bc
    rrca
    push bc
    rrca
    ld bc, $9820
    rst $10
    ld b, [hl]
    ld e, e
    ld l, a
    ld e, e
    ld h, l
    ld e, e
    ld h, l
    ld e, e
    ld [bc], a
    ld b, b
    sbc b
    rst $10
    cp d
    ld e, e
    db $e4
    ld e, e
    reti


    ld e, e
    reti


    ld e, e
    rst $38
    ld [$2321], sp
    ld e, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    or e
    ld e, a
    ld a, a
    ld e, [hl]
    ret


    ld c, a
    inc l
    ldh [$cf], a
    db $dd
    ld a, a
    cp h
    push bc
    or d
    ld a, a
    adc $b3
    ld h, $55
    ret nc

    ret


    ld a, a
    ret nz

    jp nc, $307f

    ld l, $e7
    ld d, a
    db $ed
    daa
    adc l
    ld h, b
    call nc, $dad7
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    pop hl
    ld e, a
    and [hl]
    sbc e
    adc h
    adc c
    db $e3
    ld b, d
    and $7f
    or c
    or c
    rst $20
    ld c, a
    inc e
    adc h
    ld h, $7f
    adc e
    and [hl]
    sbc e
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    inc sp
    ld d, l
    rst $00
    cp l
    sbc $33
    ld a, a
    or a
    ret nz

    ld a, a
    sbc l
    adc e
    xor e
    ret


    ld a, a
    cp d
    call nz, $e7b6
    ld d, l
    ld d, [hl]
    ld a, a
    inc [hl]
    cp d
    or [hl]
    add $7f
    or c
    reti


    ld a, a
    jp z, Jump_011_7f2d

    jr nc, jr_011_5bdd

    ld d, a
    ld [$2f21], sp
    ld e, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    or c
    ld h, b
    ret nz

    push bc
    and $4f
    or e
    or h
    ret


    ld a, a
    sbc e
    xor b
    add b
    ld a, a
    or [hl]
    rst $10
    ld d, l
    jp c, $d7de

    cp b
    ld h, $7f
    or a
    jp Jump_000_2ed9


    rst $20
    ld d, a
    db $ed
    daa
    ld c, h
    ld h, c

jr_011_5bdd:
    ld d, [hl]
    ld a, a
    ld a, [hl-]
    or [hl]
    push bc
    rst $20
    ld e, b
    db $ed
    daa
    ld [c], a
    ld h, b
    push bc
    rst $10
    ld a, a
    or d
    rst $18
    jp $d07f


    db $db
    rst $20
    ld c, a
    cp h
    or [hl]
    cp h
    ld a, a
    add e
    and a
    dec a
    db $e3
    adc a
    jp z, $8555

    ld b, $26
    ld a, a
    push bc
    or d
    call nz, $c27f
    or [hl]
    or h
    push bc
    or d
    ld l, $e7
    ld d, a
    ld l, $02
    ld b, $19
    ld bc, $12c8
    inc de
    nop
    jp z, Jump_000_0400

    jr jr_011_5c36

    ld c, $ff
    db $d3
    ld b, c
    and $0e
    jr @+$12

    ld e, $ff
    pop de
    ld b, d
    and $0f
    dec a
    dec d
    ld e, $ff
    rst $38
    add e
    jp nc, Jump_000_123d

    jr @+$01

    rst $38

jr_011_5c36:
    add h
    jr z, jr_011_5c82

    rst $00
    ld b, $19
    call nz, Call_000_12c7
    inc de
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld b, b
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld l, $2e
    ld l, $2e
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $6e
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld b, b
    ld b, c

jr_011_5c82:
    ld b, c
    ld b, c
    ld b, c
    ld h, e
    ld e, d
    ld c, c
    ld e, b
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld a, c
    inc de
    dec de
    ld h, $13
    add hl, de
    ld b, [hl]
    ld c, $0e
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld a, c
    ld h, $11
    inc de
    ld [bc], a
    dec [hl]
    ld d, $0e
    ld d, a
    ld c, c
    ld d, c
    ld l, $2e
    ld l, $2e
    ld b, h
    dec [hl]
    jr nz, @+$28

    ld c, $13
    ld b, [hl]
    ld c, $0e
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld b, h
    dec e
    inc bc
    daa
    add hl, hl
    rla
    ld d, $0e
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld b, h
    inc bc
    ld c, $02
    dec [hl]
    ld l, a
    ld b, [hl]
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld l, $2e
    ld l, $2e
    ld a, c
    add hl, de
    rla
    ld a, [bc]
    ld h, b
    ld a, [hl+]
    ld [hl], c
    ld h, d
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $44
    ld c, $0e
    add hl, hl
    ld h, h
    ld c, $0e
    ld h, [hl]
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $40
    ld b, c
    ld a, [hl+]
    ld h, a
    ld [hl], b
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $48
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld l, $2e
    ld l, $16
    inc c
    rrca
    sbc d
    ld h, b
    jp nz, $1e5d

    ld e, l
    nop
    dec sp
    ld h, b
    call Call_011_5d34
    call Call_000_3c6c
    ld hl, $5dd6
    ld de, $5d6f
    ld a, [$d5b3]
    call Call_000_31a8
    ld [$d5b3], a
    ret


Call_011_5d34:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld a, [$d79a]
    bit 5, a
    jr nz, jr_011_5d57

    and $0c
    cp $0c
    jr z, jr_011_5d4d

    ld a, $2d
    jr jr_011_5d59

jr_011_5d4d:
    ld a, $ad

Jump_011_5d4f:
    call Call_000_0e45
    ld hl, $d79a
    set 5, [hl]

jr_011_5d57:
    ld a, $0e

jr_011_5d59:
    ld [$d07c], a
    ld bc, $050c
    ld a, $17
    jp Jump_000_3e9d


Jump_011_5d64:
    xor a
    ld [$cd66], a
    ld [$d5b3], a
    ld [$d97c], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld [hl], a
    ld e, l
    ld a, [$d034]
    cp $ff
    jp z, Jump_011_5d64

    call Call_000_0ebd
    ld a, $f0
    ld [$cd66], a
    ld hl, $d79a
    set 7, [hl]
    ld a, $0a
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_0b71
    ld a, $83
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $87
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    call Call_000_0ebd
    call Call_000_0b53
    xor a
    ld [$cd66], a
    ld hl, $d0eb
    set 5, [hl]
    ld a, $00
    ld [$d5b3], a
    ld [$d97c], a
    ret


    ei
    ld e, l
    dec hl
    ld e, a
    ld a, l
    ld e, a
    ret nz

    ld e, a
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    cp l
    ld e, [hl]
    ld [bc], a
    nop
    sbc d
    rst $10
    dec [hl]
    ld e, a
    ld l, c
    ld e, a
    ld e, h
    ld e, a
    ld e, h
    ld e, a
    inc bc
    nop
    sbc d
    rst $10
    add a
    ld e, a
    xor d
    ld e, a
    and d
    ld e, a
    and d
    ld e, a
    inc b
    db $10
    sbc d
    rst $10
    jp z, $fb5f

    ld e, a
    db $f4
    ld e, a
    db $f4
    ld e, a
    rst $38
    ld [$9afa], sp
    rst $10
    bit 7, a
    jp nz, Jump_011_5e32

    ld hl, $5e3b
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $5eaa
    ld de, $5eaa
    call Call_000_339c
    ldh a, [$8c]
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    xor a
    ldh [$b4], a
    ld a, $03
    ld [$d5b3], a
    ld [$d97c], a
    jr jr_011_5e38

Jump_011_5e32:
    ld hl, $5ebd
    call Call_000_3c79

jr_011_5e38:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    rst $28
    ld [hl], a
    xor h
    rst $20
    ld c, a
    cp d
    sbc $c5
    ld a, a
    call nz, $dbba
    ld a, a
    rst $08
    inc sp
    ld a, a
    sub $b8
    or a
    ret nz

    ld d, c
    cp [hl]
    or [hl]
    or d
    ld a, a
    inc l
    pop hl
    or e
    ret


    ld a, a
    ld d, h
    db $dd
    ld c, a
    call c, Call_000_30d9
    cp b
    ret nc

    add $7f
    jp nz, $b2b6

    ld a, a
    rst $08
    cp b
    rst $18
    jp $b655


    ret z

    db $d3
    or e
    cp c

jr_011_5e73:
    ld a, a
    cp l
    reti


    ld a, a
    ld e, [hl]
    rst $20
    ld d, c
    call c, $bcc0
    ld h, $4f
    cp a
    ret


    ld a, a
    ret c

    db $e3
    rrca
    db $e3
    ld a, a
    adc d
    add l
    add [hl]
    jr nc, jr_011_5e73

    ld d, c
    call c, $bcc0
    add $7f
    jp z, $b6d1

    or e

jr_011_5e96:
    ld a, a
    push bc
    rst $10
    ld c, a
    or d
    ret nz

    or d
    ld a, a
    jp nc, Jump_011_7fc6

    or c
    rst $18
    jp $d37f


    rst $10
    or e
    rst $20
    ld d, a
    db $ed
    inc l
    push de
    ld b, l
    db $e3
    xor h
    rst $20
    ld c, a
    cp a
    sbc $c5
    ld a, a
    ld a, [hl-]
    or [hl]
    push bc
    db $e3
    xor h
    rst $20
    ld e, b
    db $ed
    add hl, hl
    or c
    ld a, b
    ret nc

    jp z, $c47f

    jp Jump_011_7fd3


    jr nc, @-$4c

    inc l
    add $4f
    ld d, h
    db $dd
    ld a, a
    cp a
    jr nc, jr_011_5e96

    jp $b27f


jr_011_5ed6:
    reti


    push bc
    ld d, c
    cp a
    sbc $c5
    ld a, a
    cp d
    inc [hl]
    db $d3
    add $4f
    call c, $bcc0
    ret


    ld a, a
    or [hl]
    sbc $26
    or h
    jp z, $c455

    jp Jump_011_7fd3


    ret c

    or [hl]
    or d
    ld a, a
    inc sp
    or a
    push bc
    or d
    jr nc, jr_011_5ed6

    or e
    ld d, c
    ld a, a
    ld d, [hl]
    rst $20
    ld c, a
    cp d
    cp d
    jp z, $b27f

    pop bc
    inc [hl]
    ld a, a
    ret nc

    db $dd
    ld a, a
    res 7, d
    or e
    rst $20
    ld d, c
    or a
    ret nc

    call nz, Call_011_7fca
    rst $08
    ret nz

    ld a, a
    inc [hl]
    cp d
    or [hl]
    inc sp
    ld c, a
    ret nz

    ret nz

    or [hl]
    or d
    ret nz

    or d
    ld a, a
    db $d3
    ret


    jr nc, @+$58

    rst $20
    ld d, a
    ld [$d621], sp
    ld e, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    jr @+$64

    ld a, a
    or l
    rst $08
    or h
    rst $20
    ld c, a
    add h
    sub c
    add [hl]
    sbc [hl]
    call nc, Call_000_33cf
    ld a, a
    add l
    adc l
    add [hl]
    ld a, a
    cp e
    ld h, $bc
    ret


    ld d, l
    inc l
    ldh [$cf], a
    ld a, a
    cp h
    ret nz

    ld a, a
    call nc, $30c2
    rst $20
    ld d, a
    db $ed
    daa
    call nz, $b262
    ld h, $7f
    call nc, $dad7
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    adc [hl]
    ld h, d
    inc l
    ldh [$cf], a
    ld a, a
    ld a, [hl-]
    or [hl]
    ret c

    ld a, a
    cp h
    call nc, $df26
    jp $e756


    ld d, a
    ld [$e221], sp
    ld e, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld [c], a
    ld h, d
    or c
    cp b
    inc l
    ret


    ld c, a
    cp l
    ld a, [hl-]
    rst $10
    cp h
    cp e
    ld h, $7f
    call c, $d7b6
    sbc $7f
    cp d
    inc [hl]
    db $d3
    jp nc, Jump_011_57e7

    db $ed
    daa
    db $76
    ld h, e
    daa
    ldh [$e7], a
    ld e, b
    db $ed
    daa
    ld l, $63
    rst $20
    ld c, a
    pop bc
    or [hl]
    rst $10
    ld a, a
    or l
    sub $3b
    ld a, a
    rst $08
    cp [hl]
    sbc $7f
    inc sp
    cp h
    ret nz

    ld d, a
    ld [$ee21], sp
    ld e, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    sub c
    ld h, e
    db $e3
    xor h
    rst $20
    ld c, a
    add e
    and a
    dec a
    db $e3
    adc a
    ld h, $7f
    jp nz, $b4b6

    push bc
    or d
    rst $18
    jp Jump_011_55e6


    add l
    ld b, $ca
    ld a, a
    jr nc, @-$24

    ld h, $7f
    db $d3
    rst $18
    jp $c9d9


    or [hl]
    push bc
    db $e3
    and $57
    db $ed
    daa
    db $ed
    ld h, e
    ld d, [hl]
    rst $20
    ld e, b
    ld [$1821], sp
    ld h, b
    call Call_000_3c79
    ld hl, $d79a
    bit 6, [hl]
    set 6, [hl]
    jr nz, jr_011_6015

    ld a, $88
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d

jr_011_6015:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld hl, $c079
    ld d, [hl]
    rst $20
    ld c, a
    cp [hl]
    rst $18
    or [hl]
    cp b
    ld a, a
    or [hl]
    cp b
    cp h
    jp $b57f


    or d
    ret nz

    ld d, l
    add e
    and a
    dec a
    db $e3
    adc a
    ret


jr_011_6034:
    ld a, a
    add l
    ld b, $26
    ld d, [hl]
    rst $20
    ld d, a
    ld l, $03
    ld a, [bc]
    inc de
    ld bc, $0fc9
    jr jr_011_6044

jr_011_6044:
    rrc a
    add hl, de
    ld bc, $00cb
    add hl, bc
    rla
    rlca
    dec e
    rst $38
    ret nc

    ld b, c
    push hl
    ld bc, $1018
    dec de
    rst $38
    ret nc

    ld b, d
    and $10
    jr jr_011_606d

    ld e, $ff
    ret nc

    ld b, e
    and $11
    jr jr_011_606b

    rrca
    rst $38
    ret nc

    ld b, h
    and $12

jr_011_606b:
    dec a
    db $10

jr_011_606d:
    ld c, $ff
    rst $38
    add l
    inc hl
    dec a
    ld [$ff0d], sp
    rst $38
    add [hl]
    jp z, Jump_000_183d

    db $10
    rst $38
    rst $38
    add a
    dec h
    dec a
    ld b, $1d
    rst $38
    rst $38
    adc b
    ld c, b
    dec a
    ld b, $0e
    rst $38
    rst $38
    adc c
    ld c, d
    ld [hl], b
    rst $00
    ld a, [bc]
    inc de
    sbc l
    rst $00
    rrca
    jr jr_011_6034

    rst $00
    rrca
    add hl, de
    ld l, $2e
    ld l, $2e
    ld h, b
    ld h, c
    ld h, c
    ld h, c
    ld b, b
    ld b, c
    ld b, d
    ld h, c
    ld h, c
    ld h, c
    ld b, d
    ld l, $2e
    ld l, $2e
    ld h, h
    ld c, $0e
    ld c, $70
    ld c, $46
    ld c, $0e
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld b, h
    ld b, a
    ld b, a
    ld c, $52
    ld c, $46
    ld c, $47
    ld b, a
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld d, b
    ld c, c
    ld c, c
    ld c, c
    ld b, h
    ld c, $46
    dec c
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld b, h
    ld c, $0e
    dec bc
    ld b, h
    ld c, $46
    dec c
    ld c, $0e
    ld h, [hl]
    ld l, $2e
    ld l, $2e
    ld b, h
    ld b, a
    ld c, $09
    ld b, h
    ld l, [hl]
    ld b, [hl]
    ld e, b
    ld c, $57
    ld d, c
    ld l, $2e
    ld l, $2e
    ld b, h
    ld b, a
    ld c, $67
    ld [hl], b
    ld d, e
    ld c, d
    ld c, $0e
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld b, h
    ld c, $0e
    ld c, $0e
    ld b, [hl]
    ld c, $53
    inc l
    ld d, a
    ld c, d
    ld l, $2e
    ld l, $2e
    ld h, b
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    ld h, e
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $64
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld b, [hl]
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $44
    ld c, $47
    ld b, a
    dec bc
    dec c
    ld c, $46
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $48
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld l, $2e
    ld l, $12
    inc b
    inc bc
    cp $61
    or l
    ld h, c
    ld e, d
    ld h, c
    nop
    rst $20
    ld h, c
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    push hl
    call nz, Call_011_6176
    pop hl
    bit 7, [hl]
    res 7, [hl]
    call nz, $61a9
    xor a
    ld [$cf07], a
    inc a
    ld [$cc3c], a
    ret


Call_011_6176:
    ld hl, $d32e
    ld a, [$d6ba]
    ld b, a
    ld a, [$d6bb]
    ld c, a
    call Call_011_6184

Call_011_6184:
    inc hl
    inc hl
    ld a, b
    ld [hl+], a
    ld a, c
    ld [hl+], a
    ret


Call_011_618b:
    ld hl, $619e
    call Call_000_1539
    ld hl, $61a3
    ld de, $cc5b
    ld bc, $0006
    call Call_000_01bb
    ret


    inc bc
    ld d, l
    ld d, h
    ld h, c
    rst $38
    inc b
    rst $00
    inc b
    ret z

    ld [bc], a
    jp z, Jump_000_07cd

    ld a, $06
    ld e, $21
    ld b, c
    ld a, a
    call Call_000_3620
    ret


    or a
    ld h, c
    ld [$4a06], sp
    call Call_000_34dd
    jr z, jr_011_61cc

    call Call_011_618b
    ld hl, $61a3
    ld a, $61
    call Call_000_3e9d
    jr jr_011_61d2

jr_011_61cc:
    ld hl, $61d5
    call Call_000_3c79

jr_011_61d2:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld e, l
    ld a, c
    ld a, a
    set 0, d
    sub $b3
    ld a, a
    ret nc

    ret nz

    or d
    jr nc, @-$39

    ld d, b
    dec c
    ld d, b
    rrca
    ld [bc], a
    ld bc, $0202
    rst $00
    ld bc, $0403
    rst $00
    ld bc, $0101
    ld bc, $f300
    add $01
    ld [bc], a
    di
    add $01
    inc bc
    ld b, h
    ld c, l
    ld b, a
    ld c, d
    ld c, h
    ld c, e
    ld c, d
    jr nz, @+$4d

    ld c, b
    ld b, [hl]
    ld c, c
    ld [de], a
    ld [bc], a
    ld [bc], a
    or c
    ld h, d
    adc c
    ld h, d
    ld d, $62
    nop
    sbc d
    ld h, d
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    push hl
    call nz, Call_011_6232
    pop hl
    bit 7, [hl]
    res 7, [hl]
    call nz, Call_011_627d
    xor a
    ld [$cf07], a
    inc a
    ld [$cc3c], a
    ret


Call_011_6232:
    ld hl, $d32e
    ld a, [$d6ba]
    ld b, a
    ld a, [$d6bb]
    ld c, a
    call Call_011_6240

Call_011_6240:
    inc hl
    inc hl
    ld a, b
    ld [hl+], a
    ld a, c
    ld [hl+], a
    ret


    ld hl, $625a
    call Call_000_1539
    ld hl, $6267
    ld de, $cc5b
    ld bc, $0016
    call Call_000_01bb
    ret


    dec bc
    ld d, [hl]
    ld d, a
    ld e, b
    ld e, c
    ld e, d
    ld e, e
    ld e, h
    ld e, l
    ld e, [hl]
    ld e, a
    ld h, b
    rst $38
    inc bc
    or l
    ld [bc], a
    rst $08
    ld [bc], a
    ret nc

    ld [bc], a
    pop de
    ld [bc], a
    jp nc, $d302

    ld [bc], a
    call nc, $d502
    ld [bc], a
    jp hl


    ld [bc], a
    ld [$eb01], a

Call_011_627d:
    call Call_000_3e07
    ld b, $1e
    ld hl, $7f41
    call Call_000_3620
    ret


    adc e
    ld h, d
    ld [$47cd], sp
    ld h, d
    ld hl, $6267
    ld a, $61
    call Call_000_3e9d
    jp Jump_000_0f6a


    rrca
    ld [bc], a
    inc bc
    ld bc, $ed00
    inc bc
    ld [bc], a
    nop
    db $ed
    ld bc, $0300
    ld bc, $f900
    add $03
    ld bc, $c6fa
    inc bc
    ld [bc], a
    ld a, [hl+]
    dec hl
    jr z, jr_011_62de

    inc bc
    dec c
    rrca
    ld a, b
    ld h, e
    call nz, $c162
    ld h, d
    nop
    daa
    ld h, e
    jp Jump_000_3c6c


    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    jp nc, $e362

    ld h, d
    dec bc
    ld h, e
    db $ed

jr_011_62d3:
    dec l
    ld l, d
    ld d, d
    cp c
    or d
    ld a, a
    sbc c
    add d
    adc h
    ld a, a
    ld d, [hl]

jr_011_62de:
    ld a, a
    or d
    cp d
    or d
    ld d, a
    db $ed
    dec l
    ld a, [hl]
    ld d, d
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    ret


    cp d
    ret c

    ld a, a
    inc l
    or [hl]
    sbc $ca
    ld c, a
    or c
    reti


    cp b
    ld a, a
    ld a, [hl+]
    call nz, Call_011_7fc6
    call $c3df
    ld a, a
    or d
    cp b
    rst $20
    ld d, a
    db $ed
    dec l
    ld [hl-], a
    ld d, d
    ld a, a
    pop bc
    pop hl
    or e
    or l
    or e
    ld a, a
    set 3, e
    ld a, [hl-]
    ld c, a
    or a
    ret nz

    ld a, a
    ld d, [hl]
    ld a, a
    jr nc, jr_011_62d3

    ld hl, sp+$7f
    add e
    ret c

    add b
    ld d, a
    nop
    dec b
    inc b
    nop
    ld b, $da

jr_011_632d:
    dec b
    nop
    rlca
    jp c, Jump_000_0016

    ld b, $dc
    rla
    nop
    ld b, $dc
    add hl, bc
    add hl, de
    nop
    ldh [$03], a
    ld a, [bc]
    ld a, [de]
    dec b
    inc b
    ld b, $06
    rla
    dec b
    rlca
    inc b
    dec a
    ld c, $19
    rst $38
    rst $38
    add c
    db $10
    dec a
    dec bc
    rlca
    rst $38
    rst $38
    add d
    ld de, $113d
    jr @+$01

    rst $38
    add e
    ld h, $3d
    db $10
    inc de
    rst $38
    rst $38
    add h
    db $ed
    jr z, jr_011_632d

    inc b
    nop
    jr z, @-$37

    dec b
    nop
    push hl
    rst $00
    ld d, $00
    push hl
    rst $00
    rla
    nop
    ld e, [hl]
    rst $00
    add hl, bc
    add hl, de
    ld c, b
    ld a, l
    ld a, l
    ld a, l
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    ld a, l
    dec b
    dec b
    dec b
    ld c, c
    ld c, h
    ld a, h
    ld a, h
    dec de
    dec h
    ld bc, $0101
    inc h
    dec de
    inc hl
    ld bc, $0101
    rlca
    ld d, [hl]
    dec de
    dec de
    ld hl, $3c1b
    dec a
    dec a
    dec a
    ld a, $25
    ld bc, $0101
    rlca
    ld c, b
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld b, h
    ld b, a
    ld b, l
    ld d, e
    ld b, [hl]
    dec h
    dec h
    inc h
    inc h
    ld a, [hl]
    ld a, a
    inc hl
    jr z, @+$2a

    ld [hl+], a
    dec de
    dec de
    ld [bc], a
    inc l
    add hl, hl
    inc l
    add hl, hl
    add hl, de
    inc e
    ld a, [hl]
    ld b, $28
    ld bc, $2001
    ld d, b
    ld d, c
    ld d, c
    ld d, c
    ld d, d
    dec de
    dec de
    dec de
    ld hl, $067e
    jr z, @+$03

    ld bc, $0128
    ld bc, $5501
    inc a
    dec a
    dec a
    dec a
    ld a, $02
    ld a, a
    dec h
    jr z, jr_011_640d

    inc h
    ld d, b
    ld d, c
    ld d, c
    ld c, a
    ld b, h
    ccf
    ld b, e
    ld b, a
    ld b, [hl]
    ld [bc], a
    ld c, h
    ld a, h
    ld a, h
    inc l
    dec de
    ld d, h
    dec l
    dec l
    dec l
    dec l
    ld b, b
    ld b, d
    inc l
    dec de
    ld a, [hl]
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld a, a
    inc l
    inc a
    dec a
    dec a
    dec a
    dec a
    ld c, d
    ld b, d
    dec de
    dec de

jr_011_640d:
    ld a, [hl]
    ld a, l
    ld a, l
    ld a, l
    ld a, a
    inc l
    ld b, h
    ld b, a
    ld b, l
    ld b, l
    ld b, l
    ld b, a
    ld b, [hl]
    ld bc, $7e22
    ld d, [hl]
    inc l
    inc sp
    ld c, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, a
    dec h
    ld bc, $0101
    inc h
    ld a, [hl]
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    ld a, h
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    ld a, h
    ld c, l
    inc bc
    ld [de], a
    inc d
    add b
    ld h, l
    ld c, d
    ld h, h
    ld b, a
    ld h, h
    nop
    rla
    ld h, l
    jp Jump_000_3c6c


    push bc

jr_011_644b:
    rrca
    push bc
    rrca
    ld e, b
    ld h, h
    ld l, c
    ld h, h
    sub d
    ld h, h
    sbc a
    ld h, h
    add sp, $64
    db $ed
    inc l
    and h
    ld l, l
    cp c
    or d
    ld a, a
    sbc c
    add d
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    or d
    cp d
    or d
    ld d, a
    db $ed
    dec l
    ld [c], a
    ld d, e
    call nz, $c5b8
    ld a, a

jr_011_6471:
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    sub e
    and a
    dec bc
    xor l
    db $e3
    ld a, a
    sbc c
    add d
    adc h
    jp z, $cf4f

    jr nc, @+$81

    cp e
    or a
    jr nc, jr_011_6471

    ld a, a
    ld h, $de
    ld a, [hl-]
    db $db
    or e
    rst $20
    ld d, a
    db $ed
    dec l
    call Call_011_7f53
    jr nc, jr_011_644b

    ld hl, sp+$7f
    add e
    ret c

    add b
    ld d, a
    db $ed
    dec l
    dec e
    ld d, e
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    ld d, h
    jp z, $b87f

    cp e
    pop de
    rst $10
    ret


    ld a, a
    push bc
    or [hl]
    add $4f
    cp d
    ret


    sbc $33
    ld a, a
    or [hl]
    cp b
    jp c, $e7d9

    ld d, c
    push bc
    or [hl]
    push bc
    or [hl]
    ld a, a
    ret nc

    jp nz, $d7b6

    push bc
    or d
    ld a, a
    call nz, $cab7
    ld c, a
    cp b
    cp e
    pop de
    rst $10
    db $dd
    ld a, a
    dec bc
    rlca
    ld a, [bc]
    rlca
    add $7f
    or c
    reti


    cp d
    or e
    rst $20
    ld d, a
    db $ed
    dec l
    pop bc
    ld d, d
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    sub e
    and a
    dec bc
    xor l
    db $e3
    ld a, a
    sbc c
    add d
    adc h
    db $dd
    ld a, a
    ret nc

    jp nz, $d9b9

    call nz, $cb4f
    inc sp
    sbc $9d
    adc e
    xor e
    ld h, $7f
    db $d3
    rst $10
    or h
    reti


    cpl
    rst $20
    ld d, a
    nop
    add hl, bc
    inc hl
    ld [bc], a
    nop
    db $db
    inc hl
    inc bc
    ld bc, $23db
    ld [$db02], sp
    inc hl
    add hl, bc
    inc bc
    db $db
    inc hl
    inc d
    inc b
    call c, $1523
    dec b
    call c, $271e
    nop
    reti


    rra
    daa
    ld bc, $03d9
    inc hl
    nop
    pop hl
    dec b
    inc b
    inc h
    inc bc
    add hl, de
    inc b
    inc b
    rra
    dec c
    dec b
    ld hl, $0613
    inc e
    ld a, [de]
    rlca
    ld [bc], a
    dec a
    dec b
    dec e
    rst $38
    rst $38
    add c
    inc h
    dec a
    dec bc
    rla
    rst $38
    rst $38
    add d
    ldh a, [$be]
    ret z

    inc hl
    ld [bc], a
    cp [hl]
    ret z

    inc hl
    inc bc
    pop bc
    ret z

    inc hl
    ld [$c8c1], sp
    inc hl
    add hl, bc
    rst $00
    ret z

    inc hl
    inc d
    rst $00
    ret z

    inc hl
    dec d
    sbc h
    ret z

    ld e, $27
    sbc h
    ret z

    rra
    daa
    ld l, $c7
    inc bc
    inc hl
    ld [bc], a
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
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    dec b
    dec b
    dec b
    dec b
    ld [bc], a
    ld a, a
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    inc hl
    ld bc, $1924
    inc e
    ld a, [hl]
    ld a, a
    dec h
    ld bc, $2401
    ld a, [hl]
    ld a, l
    ld a, l
    ld [bc], a
    ld a, l
    ld [bc], a
    ld a, l
    ld a, l
    ld a, l
    ld bc, $1b01
    dec de
    ld hl, $7f7e
    inc hl
    ld bc, $2201
    ld a, [hl]
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec h
    ld bc, $1b22
    dec de
    ld a, [hl]
    ld [bc], a
    dec h
    inc h
    dec h
    ld e, h
    ld d, d
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec h
    ld bc, $1b22
    ld a, [hl]
    ld a, a
    dec de
    add hl, hl
    inc l
    ld e, d
    ld e, e
    ld bc, $0222
    dec [hl]
    dec [hl]
    dec [hl]
    dec [hl]
    dec [hl]
    dec [hl]
    dec [hl]
    dec h
    ld bc, $7e1b
    ld a, a
    inc l
    dec de
    dec de
    ld e, d
    ld e, e
    ld bc, $7f22
    add hl, hl
    add hl, hl
    dec de
    dec de
    dec de
    dec de
    dec de
    inc a
    dec a
    dec a
    ld a, $7f
    add hl, hl
    ld e, h
    ld d, d
    jr z, @+$03

    ld bc, $7f24
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    ld b, h
    ld b, a
    ccf
    ld b, d
    ld a, a
    dec de
    ld e, d
    ld e, e
    dec h
    inc h
    dec h
    dec de
    ld a, a
    dec de
    dec de
    dec de
    dec de
    inc l
    add hl, hl
    dec de
    dec de
    dec de
    ld b, b
    ld b, d
    ld a, a
    inc l
    ld e, d
    ld e, e
    dec de
    dec de
    dec de
    dec de
    ld a, a
    inc l
    dec de
    dec de
    dec de
    dec de
    inc l
    dec de
    dec de
    dec de
    ld b, b
    ld b, d
    ld a, a
    add hl, hl
    ld a, [hl]
    add hl, hl
    dec de
    dec de
    dec de
    inc a
    dec a
    dec a
    dec a
    dec a
    ld a, $1b
    dec de
    dec de
    add hl, hl
    dec de
    ld b, b
    ld b, d
    ld a, a
    dec de
    ld a, [hl]
    inc hl
    inc hl
    ld bc, $4022
    ld b, c
    ld b, e
    ld b, l
    ld b, a
    ld b, [hl]
    dec de
    dec de
    dec de
    dec de
    dec de
    ld b, b
    ld b, d
    ld a, a
    dec de
    dec d
    ld bc, $525c
    ld bc, $4140
    ld b, d
    ld bc, $2201
    inc a
    dec a
    dec a
    dec a
    dec a
    ld c, d
    ld b, d
    ld a, a
    dec de
    ld a, [hl]
    ld bc, $5b5a
    inc h
    ld b, h
    ld b, a
    ld b, [hl]
    ld bc, $0101
    ld b, h
    ld b, a
    ld b, l
    ld b, l
    ld b, l
    ld b, l
    ld b, [hl]
    ld a, a
    dec de
    ld a, [hl]
    dec h
    ld e, d
    ld e, e
    dec de
    dec de
    ld a, [hl]
    dec h
    ld bc, $0101
    ld hl, $1b1b
    dec de
    dec de
    dec de
    dec e
    ld a, a
    add hl, hl
    ld a, [hl]
    dec de
    dec de
    dec de
    inc sp
    dec de
    ld a, [hl]
    inc l
    ld bc, $0101
    ld [hl+], a
    add hl, hl
    add hl, hl
    dec de
    add hl, hl
    dec de
    ld d, a
    ld a, a
    inc l
    ld a, [hl]
    dec de
    inc l
    dec de
    dec de
    dec de
    ld a, [hl]
    inc sp
    dec de
    inc h
    dec h
    inc h
    dec de
    dec de
    dec de
    dec de
    dec de
    dec e
    ld c, c
    ld e, c
    ld c, b
    ld c, c
    ld e, c
    ld c, b
    add hl, sp
    add hl, sp
    add hl, sp
    ld c, c
    ld e, c
    ld c, b
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    inc bc
    dec c
    rrca
    sub e
    ld h, a
    rst $30
    ld h, [hl]
    db $f4
    ld h, [hl]
    nop
    ld a, [hl-]
    ld h, a
    jp Jump_000_3c6c


    push bc
    rrca
    db $fd
    ld h, [hl]
    ld c, $67
    db $ed
    dec l
    ld e, $52
    cp c
    or d
    ld a, a
    sbc c
    add d
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    or d
    cp d
    or d
    ld d, a
    db $ed
    dec l
    db $d3
    ld d, c
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    adc h
    adc a
    db $e3
    sub e
    ld a, a
    inc e
    adc a
    xor e
    ld a, a
    or l
    cp h
    jp $4fe7


    ret


    cp d
    ret c

    ld a, a
    inc l
    or [hl]
    sbc $c9
    ld a, a
    or [hl]
    cp b
    add $de
    rst $20
    ld d, a
    nop
    add hl, bc
    add hl, de
    ld c, $02
    sbc h
    add hl, de
    rrca
    inc bc
    sbc h
    ld a, [bc]
    nop
    inc b
    db $db
    dec bc
    nop
    dec b
    db $db
    nop
    ld c, $04
    jp c, Jump_000_0f00

    dec b
    jp c, Jump_000_1d0a

    ld [bc], a
    reti


    dec bc
    dec e
    inc bc
    reti


    inc de
    ld de, $dd00
    ld [bc], a
    inc d
    ld [de], a
    ld [bc], a
    ld d, $0e
    inc bc
    ld bc, $0e3d
    ld [de], a
    rst $38
    rst $38
    add c
    ld sp, $c801
    add hl, de
    ld c, $01
    ret z

    add hl, de
    rrca
    ld h, a
    rst $00
    ld a, [bc]
    nop
    ld h, a
    rst $00
    dec bc
    nop
    dec b
    rst $00
    nop
    ld c, $05
    rst $00
    nop
    rrca
    ld [hl], l
    rst $00
    ld a, [bc]
    dec e
    ld [hl], l
    rst $00
    dec bc
    dec e
    jp Jump_000_13c7


    ld de, $7d7e
    ld a, l
    ld a, l
    ld a, l
    ld [bc], a
    ld a, l
    ld e, b
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, l
    ld a, a
    ld a, a
    dec de
    inc hl
    ld [hl+], a
    inc l
    ld a, [hl]
    dec de
    dec de
    inc hl
    ld [hl+], a
    inc hl
    ld [hl+], a
    add hl, hl
    dec de
    ld a, [hl]
    ld a, a
    inc hl
    ld bc, $2201
    ld a, [hl]
    add hl, hl
    inc hl
    ld bc, $0101
    ld bc, $1b22
    ld a, [hl]
    ld a, a
    dec h
    ld bc, $1b24
    ld a, [hl]
    dec de
    dec h
    ld bc, $2524
    ld bc, $2c24
    ld a, [hl]
    ld a, a
    dec de
    inc h
    inc hl
    ld e, h
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, d
    ld a, h
    ld a, h
    ld a, h
    ld [bc], a
    ld d, [hl]
    dec de
    dec de
    ld bc, $5d5a
    dec de
    ld l, $1b
    ld d, l
    ld e, e
    dec de
    ld l, $1b
    ld d, a
    ld a, a
    ld l, $1b
    dec h
    ld e, d
    ld e, [hl]
    ld d, c
    ld d, c
    ld d, c
    ld c, a
    ld e, e
    ld bc, $1b22
    ld a, [hl]
    ld a, a
    dec de
    inc l
    ld a, h
    ld a, h
    daa
    ld h, $17
    daa
    ld h, $1b
    dec h
    ld bc, $7e22
    ld [bc], a
    ld a, l
    ld a, l
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    dec de
    ld bc, $2201
    ld a, [hl]
    ld a, a
    dec de
    inc hl
    ld bc, $2201
    inc l
    dec de
    add hl, de
    inc e
    dec de
    inc hl
    ld bc, $7e24
    ld a, a
    inc l
    dec h
    ld bc, $2401
    dec de
    dec de
    dec de
    ld hl, $231b
    inc h
    inc l
    ld a, [hl]
    ld a, a
    dec de
    add hl, hl
    dec h
    ld bc, $2401
    ld hl, $2c2c
    inc hl
    inc h
    dec de
    dec de
    ld a, [hl]
    ld a, [hl]
    daa
    rla
    ld h, $17
    rla
    ld h, $58
    daa
    rla
    rla
    daa
    rla
    ld h, $7f
    inc c
    inc b
    inc b
    inc e
    ld b, b
    ld h, l
    ld l, b
    ld h, d
    ld l, b
    nop
    xor b
    ld l, b
    jp Jump_000_3c6c


    ld l, c
    ld l, b
    adc e
    ld l, b
    db $ed
    daa
    ret z

    ld a, d
    ld [hl], d
    ld d, h
    call nz, $c6d8
    ld a, a
    or d
    cp d
    or e
    rst $18
    jp $b24f


    rst $18
    ret nz

    ld a, a
    ret


    add $56
    adc c
    db $e3
    dec bc
    ld a, a
    inc [hl]
    cp d
    push bc
    ret


    sub $e7
    ld d, a
    db $ed
    daa
    inc b
    ld a, e
    rst $20
    ld a, a
    ld d, h
    ld a, a
    call nz, Call_011_7fd8
    rst $08
    cp b
    rst $18
    jp $b54f


    ret nc

    call nc, $c629
    ld a, a
    cp h
    sub $b3
    rst $18
    call nz, Call_011_57e7
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [$07dc], sp
    inc bc
    ld [$00dc], sp
    ld [bc], a
    dec c
    ld b, $07
    rst $38
    ret nc

    ld bc, $0820
    dec b
    cp $01
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    inc c
    inc b
    inc b
    inc e
    ld b, b
    ret c

    ld l, b
    call nc, Call_000_0068
    ld e, e
    ld l, c
    call Call_000_3c6c
    ret


    sbc $68
    dec b
    ld l, c
    ld [hl-], a
    ld l, c
    db $ed
    daa
    ld l, $7b
    db $db
    ld a, a
    or c
    jp $c4d9


    ld c, a
    add $29
    reti


    ld a, a
    or [hl]
    db $d3
    ld a, a
    cp h
    jp c, $b2c5

    ld h, $55
    jp nz, $cfb6

    or h
    ld a, a
    call nc, $b8bd
    jp z, $c57f

    reti


    sub $e7
    ld d, a
    db $ed
    daa
    ld l, a
    ld a, e
    rst $08
    db $dd
    ld a, a
    push bc
    add hl, hl
    reti


    call nz, $834f
    adc d
    add $7f
    pop de
    pop bc
    pop hl
    or e
    inc sp
    ld a, a
    or d
    reti


    ld a, a
    or c
    or d
    jr nc, jr_011_6977

    ld b, e
    adc b
    and c
    xor e
    jp z, $b17f

    rst $08
    ret c

    ld a, a
    add $29
    push bc
    or d
    rst $20
    ld d, a
    db $ed
    daa
    rst $18
    ld a, e
    sbc $7f
    or c
    reti


    or d
    ret nz

    ld a, a
    cp c
    inc [hl]
    ld c, a
    call nz, $c0d8
    or d
    ld a, a
    ld b, e
    adc b
    and c
    xor e
    ld h, $55
    push bc
    or [hl]
    push bc
    or [hl]
    ld a, a
    call nz, Call_000_303b
    cp h
    jp $ba7f


    push bc
    or d
    ret


    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    rlca
    db $db
    rlca
    inc bc
    rlca
    db $db
    nop
    inc bc
    jr nz, jr_011_6971

    ld [$00fe], sp

jr_011_696c:
    ld bc, $0607
    inc b
    rst $38

jr_011_6971:
    db $d3
    ld [bc], a
    dec de
    ld b, $0a
    rst $38

jr_011_6977:
    ret nc

    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    inc c
    inc b
    inc b
    inc e
    ld b, b
    sub c
    ld l, c
    adc l
    ld l, c
    nop
    db $fc
    ld l, c
    call Call_000_3c6c
    ret


    sub a
    ld l, c
    jp $e569


    ld l, c
    db $ed
    jr z, jr_011_699a

jr_011_699a:
    ld b, b
    ld a, a
    push bc
    sbc $3b
    or a
    ld a, a
    jp nz, $cfb6

    or h
    ret nz

    and $4f
    ld a, $b8
    jp z, $c27f

    or [hl]
    rst $08
    or h
    add $7f
    jp nz, $cfb6

    or h
    jp $c255


    or [hl]
    jp c, $7fc3

    cp h
    rst $08
    rst $18
    ret nz

    sub $57
    db $ed
    jr z, @+$45

    ld b, b
    db $e3
    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    ret nz

    ld l, $e7
    ld d, c
    cp d
    jp c, Jump_011_4f33

    inc l
    pop hl
    db $e3
    inc a
    sbc $7f
    db $d3
    call nz, Call_011_7fca
    call nz, $c0df
    rst $20
    ld d, a
    db $ed
    jr z, jr_011_696c

    ld b, b
    rst $20
    ld c, a
    jp z, $e0bc

    daa
    ld a, a
    cp l

jr_011_69f1:
    daa
    jp $c27f


    or [hl]
    jp c, $e0c1

    rst $18
    ret nz

    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    inc b
    reti


    rlca
    inc bc
    inc b
    reti


    nop
    inc bc
    jr nz, @+$09

    dec b
    cp $01
    ld bc, $0621
    ld [$ffff], sp
    ld [bc], a
    inc l
    ld b, $09
    rst $38
    rst $38
    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    inc c
    inc b
    inc b
    inc e
    ld b, b
    ld [hl-], a
    ld l, d
    ld l, $6a
    nop
    db $eb
    ld l, d
    call Call_000_3c6c
    ret


    jr c, @+$6c

    ld a, h
    ld l, d
    xor [hl]
    ld l, d
    db $ed
    jr z, jr_011_69f1

    ld b, b
    ret c

    ld a, a
    ld c, $e3
    xor e
    ld a, a
    push bc
    or d
    add $4f
    or l
    pop bc
    jp Jump_011_7fd9


    add b
    add c
    sub d
    sbc a
    jp z, $d355

    rst $18
    jp $b27f


    rst $18
    jp $b27f


    or d
    sbc $30
    sub $e7
    ld d, c
    inc sp
    db $d3
    ld a, a
    ld l, $de
    inc a

jr_011_6a66:
    ld a, a
    set 3, e
    rst $18
    jp $c07f


    rst $10
    ld c, a
    inc l
    or [hl]
    sbc $7f
    push bc
    cp b
    push bc
    rst $18
    pop bc
    ldh [$b3], a
    rst $20
    ld d, a
    db $ed
    jr z, jr_011_6ab6

    ld b, c
    add [hl]
    xor l
    xor e
    ld b, a
    db $e3
    xor e
    ld a, a
    pop bc
    pop hl
    or e
    ld a, a
    jr nc, @-$23

    ld c, a
    ld c, $e3
    xor e
    ld a, a
    or d
    pop bc
    ld a, [hl-]
    sbc $7f
    or l
    cp b
    ret


    ld a, a
    cp d
    call nc, Call_011_5533
    cp h
    ld [c], a
    or e
    set 3, [hl]
    db $dd
    ld a, a
    cp b
    jp c, $dfd9

    jp $e7bb


    ld d, a
    db $ed
    jr z, jr_011_6a66

    ld b, c
    ret


    ld a, a
    add c
    db $e3

jr_011_6ab6:
    dec de
    add c
    ld c, a
    dec de
    db $e3
    adc h
    adc a
    db $e3
    add $7f
    cp h
    sbc $b6

jr_011_6ac3:
    ld a, a
    cp h
    sub $df
    ret nz

    rst $20
    ld d, c
    inc sp
    db $d3
    ld a, a
    call nz, Call_000_30d3
    pop bc
    ld a, a
    ret


    jp z, $8b7f

    xor l
    xor c
    db $e3
    inc c
    add $4f
    push bc
    rst $18
    ret nz

    sbc $30
    rst $20
    ld a, a
    push bc
    sbc $33
    jr nc, jr_011_6ac3

    or e
    and $57
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [$07da], sp
    inc bc
    ld [$00da], sp
    inc bc
    jr nz, jr_011_6b00

    ld a, [bc]
    cp $02
    ld bc, $0823
    rlca

jr_011_6b00:
    rst $38
    rst $38
    ld [bc], a
    db $10
    add hl, bc
    dec b
    cp $01
    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld de, $0f09
    ld l, a
    ld l, e
    jr nz, jr_011_6b83

    dec e
    ld l, e
    nop
    ld h, $6b
    jp Jump_000_3c6c


    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    ld a, l
    ld b, $01
    dec e
    ld [bc], a
    db $e4
    ld b, $16
    inc bc
    db $e4
    rlca
    inc de
    inc b
    db $e4
    ld bc, $0509
    db $e4
    inc bc
    ld bc, $e406
    dec bc
    inc bc
    rlca
    db $e4
    nop
    inc bc
    dec a
    inc de
    add hl, bc
    rst $38
    rst $38
    add c
    ld c, a
    dec a
    ld de, $ff1d
    rst $38
    add d
    ld [bc], a
    dec a
    dec c
    ld hl, $ffff
    add e
    db $10
    inc c
    rst $00
    ld bc, $481d
    rst $00
    ld b, $16
    ld b, [hl]
    rst $00
    rlca
    inc de
    ld [bc], a
    rst $00
    ld bc, $1309
    rst $00
    inc bc
    ld bc, $c768
    dec bc
    inc bc
    inc b
    inc c
    dec b
    dec b
    jr z, jr_011_6b7d

    dec c
    inc b
    rlca
    dec c
    inc b
    inc b
    inc b
    inc b

jr_011_6b7d:
    jr z, jr_011_6ba7

    dec b
    add hl, bc
    rrca
    dec b

jr_011_6b83:
    ld c, $05
    rlca
    dec bc
    inc b
    inc b
    inc b
    inc b
    rrca
    dec b
    add hl, bc
    ld c, $05
    dec b
    dec b
    dec b
    dec b
    dec b
    dec c
    inc b
    inc b
    inc b
    rrca
    dec b
    ld b, $07
    dec b
    dec b
    ld [$0505], sp
    dec b
    dec b
    dec b
    jr z, jr_011_6bad

jr_011_6ba7:
    inc hl
    ld [$060f], sp
    rlca
    rrca

jr_011_6bad:
    ld b, $06
    dec b
    dec b
    ld b, $05
    dec b
    dec b
    ld b, $05
    dec b
    ld b, $06
    rlca
    jr z, jr_011_6bc3

    ld [$0e05], sp
    ld [$0505], sp

jr_011_6bc3:
    ld b, $05
    dec b
    ld b, $06
    ld [$0507], sp
    ld c, $06
    dec b
    dec b
    ld c, $05
    ld b, $06
    ld b, $06
    ld b, $06
    ld b, $07
    rrca
    dec b
    ld b, $05
    dec b
    ld [$0e05], sp
    ld b, $06
    ld b, $05
    ld c, $06
    rrca
    dec b
    dec b
    dec b
    dec b
    dec b
    ld c, $08
    dec b
    ld c, $06
    dec b
    dec b
    dec b
    ld c, $11
    add hl, bc
    rrca
    ld l, e
    ld l, h
    dec de
    ld l, h
    ld [bc], a
    ld l, h
    nop
    ld c, c
    ld l, h
    call Call_000_3c6c
    ld hl, $6c21
    ld de, $6c15
    ld a, [$d5cf]
    call Call_000_31a8
    ld [$d5cf], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld l, $6c
    push bc
    rrca
    push bc
    rrca
    ld bc, $de00
    rst $10
    jr c, jr_011_6c93

    jr c, @+$6e

    jr c, @+$6e

    jr c, jr_011_6c99

    rst $38
    ld [$2121], sp
    ld l, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_011_6c81

    ld b, d
    ld d, b
    ld [$833e], sp
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    ld a, l
    ld bc, $0306
    ld [$00e4], sp
    inc bc
    dec b
    ld c, $09
    rst $38
    ret nc

    ld b, c
    add e
    ld b, [hl]
    dec a
    dec bc
    inc e
    rst $38
    rst $38
    add d
    ld [bc], a
    dec a
    dec b
    inc e
    rst $38
    rst $38
    add e
    ld [hl], $3e
    rst $00
    ld b, $03
    inc d
    dec d
    dec d
    dec d
    dec d
    ld d, $0e
    ld bc, $206e
    ld hl, $6e22
    ld c, $01
    jr @+$1b

    inc l
    dec e
    dec l
    ld e, $01

jr_011_6c81:
    rla
    ld bc, $0501
    jr nz, jr_011_6ca9

    dec c
    ld bc, $1918
    ld a, [de]
    ld c, h
    ld bc, $0b01
    rra
    jr nz, @+$24

jr_011_6c93:
    ld bc, $0101
    ld bc, $1c01

jr_011_6c99:
    ld h, c
    ld e, $76
    db $76
    inc d
    dec d
    dec d
    dec d
    dec d
    dec d
    dec d
    ld d, $01
    ld [bc], a
    db $76
    ld [bc], a

jr_011_6ca9:
    jr nz, jr_011_6ccd

    ld d, c
    inc e
    dec l
    dec e
    dec e
    dec e
    dec hl
    ld [hl], h
    ld a, [de]
    ld bc, $7617
    inc d
    dec d
    ld d, $20
    ld [hl+], a
    ld b, $01
    ld bc, $1801
    add hl, de
    ld a, [de]
    ld bc, $761b
    ld h, [hl]
    dec e
    ld e, $76
    db $76
    inc d
    dec d

jr_011_6ccd:
    ld d, $01
    jr jr_011_6d1f

    ld a, [de]
    ld bc, $761b
    db $76
    db $76
    db $76
    db $76
    db $76
    ld h, [hl]
    dec l
    ld e, $01
    inc e
    dec l
    ld e, $01
    rra
    ld d, e
    ld d, c
    db $76
    db $76
    db $76
    db $76
    db $76
    ld c, h
    ld bc, $0201
    ld b, $01
    dec c
    ld [bc], a
    ld de, $1412
    and h
    ld [hl], b
    rla
    ld l, l
    cp $6c
    nop
    ld b, b
    ld [hl], b
    call Call_000_3c6c
    ld hl, $6d27
    ld de, $6d11
    ld a, [$d59f]
    call Call_000_31a8
    ld [$d59f], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    adc b
    ld l, l
    push hl
    ld l, l
    ld b, b
    ld l, [hl]
    sub l
    ld l, [hl]

jr_011_6d1f:
    jp hl


    ld l, [hl]
    ld b, d
    ld l, a
    sub a
    ld l, a
    and $6f
    ld bc, $fc40
    rst $10
    sub d
    ld l, l
    call $be6d
    ld l, l
    cp [hl]

jr_011_6d32:
    ld l, l
    ld [bc], a
    jr nc, jr_011_6d32

    rst $10
    rst $28
    ld l, l
    ld a, [de]
    ld l, [hl]
    ld b, $6e
    ld b, $6e
    inc bc
    jr nc, @-$02

    rst $10
    ld c, d
    ld l, [hl]
    ld [hl], h
    ld l, [hl]
    ld h, a
    ld l, [hl]
    ld h, a
    ld l, [hl]
    inc b
    ld b, b
    db $fc
    rst $10
    sbc a
    ld l, [hl]
    cp a
    ld l, [hl]
    or d
    ld l, [hl]
    or d

jr_011_6d56:
    ld l, [hl]
    dec b
    jr nc, jr_011_6d56

    rst $10
    di
    ld l, [hl]
    dec h
    ld l, a
    dec c
    ld l, a
    dec c
    ld l, a
    ld b, $40
    db $fc
    rst $10
    ld c, h
    ld l, a
    ld a, c
    ld l, a
    ld [hl], c
    ld l, a
    ld [hl], c

jr_011_6d6e:
    ld l, a
    rlca
    jr nc, jr_011_6d6e

    rst $10
    and c
    ld l, a
    jp z, $b86f

    ld l, a
    cp b
    ld l, a
    ld [$fc30], sp
    rst $10
    ldh a, [$6f]
    ld a, [de]
    ld [hl], b
    inc c
    ld [hl], b
    inc c
    ld [hl], b
    rst $38
    ld [$2721], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_011_6de4

    ld b, d
    adc h
    add l
    add d
    sub e
    jp z, $d47f

    rst $08
    inc sp
    ld c, a
    rst $08
    sub $dc

jr_011_6da3:
    push bc
    or d
    ld a, a
    sub $b3
    add $7f
    jp nc, $d92c

    cp h
    ret


    ld d, l
    cp d
    or h
    jr nc, @-$21

    ld a, a
    or l
    or d
    jp $b17f


    reti


    cp b
    ret


    ld d, a
    db $ed
    jr z, jr_011_6de3

    ld b, e
    ld d, [hl]
    rst $20
    ld c, a
    ld h, $de
    ld a, [hl-]
    rst $18
    ret nz

    ret


    add $58
    db $ed
    jr z, jr_011_6da3

    ld b, d
    ldh [$df], a
    ret nz

    cp h
    ld c, a
    or a
    ld [c], a
    or e
    jp z, $b57f

    or e
    pop bc
    add $7f
    or [hl]
    or h
    db $db

jr_011_6de3:
    or e

jr_011_6de4:
    ld d, a
    ld [$3321], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, @+$47

    ld b, e
    db $e3
    xor h
    rst $20
    ld c, a
    or l

jr_011_6df8:
    jp c, Jump_011_7fc9

    ld b, b
    xor c
    db $e3
    add $7f
    or [hl]
    jp $b6d9


    rst $20
    ld d, a
    db $ed
    jr z, jr_011_6df8

    ld b, e
    rst $18
    call nz, $4fe7
    ld b, b
    xor c
    db $e3
    ld a, a
    rst $08
    cp c
    ld a, a
    cp h
    ret nz

jr_011_6e17:
    or [hl]
    rst $20
    ld e, b
    db $ed
    jr z, jr_011_6e86

    ld b, e
    add $7f
    cp d
    jr nc, @-$22

    reti


    ret


    jp z, $b64f

    sbc $26
    or h
    push bc
    ld h, $d7
    ld a, a
    ret nz

    ret nz

    or [hl]
    or e
    ret


    ld h, $55
    add $26
    jp $307f


    or [hl]
    rst $10
    jr nc, @-$17

    ld d, a
    ld [$3f21], sp
    ld l, l

Call_011_6e44:
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, @+$08

    ld b, h
    or [hl]
    sbc $7f
    jp nz, $dfb8

    jp $e6d9


    ld c, a
    cp b
    cp a
    or e
    rst $20
    ld a, a
    ld a, $b8
    db $d3
    ld a, a
    call nc, $c0d8
    or d

jr_011_6e65:
    rst $20
    ld d, a
    db $ed
    jr z, jr_011_6e17

    ld b, h
    db $d3
    or e
    rst $20
    ld a, a
    cp b
    call nc, $b2bc
    ld e, b
    db $ed
    jr z, jr_011_6ecf

    ld b, h
    or [hl]
    rst $10
    cp e
    ld c, a
    ld d, h
    ld a, a
    dec l
    or [hl]
    sbc $7f
    or [hl]
    sbc $be
    or d

jr_011_6e86:
    ld a, a
    cp h
    ret nz

    rst $10
    ld d, l
    ld a, $b8
    add $7f
    cp b
    jp c, $b2c5

    and $57
    ld [$4b21], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_011_6e65

    ld b, h
    ld c, a
    ld d, h
    ld a, a
    adc c
    adc h
    ld b, d
    and a

jr_011_6eaa:
    ld a, a
    cp h
    rst $18

jr_011_6ead:
    jp $bdcf


    and $57
    db $ed
    jr z, jr_011_6f15

    ld b, l
    ld h, $7f
    push bc
    or d
    ld a, a
    inc sp
    cp l
    ret z

    ld e, b
    db $ed
    jr z, jr_011_6eaa

    ld b, h
    and a
    rst $18
    jp $b27f


    or e
    ret


    jp z, $414f

    xor h
    ld b, c

jr_011_6ecf:
    ret


    ld a, a
    or a
    jr z, jr_011_6ead

    ret nc

    ld a, a
    call nz, Call_011_7fb6
    jp nz, $dfb8

    jp Jump_011_5455


    add $7f
    push bc
    ret c

    or a
    reti


    sbc $33
    cp l
    ld d, a
    ld [$5721], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_011_6f6f

    ld b, l
    ld c, a
    ld d, h
    ld a, a
    sub d
    add a
    sub l
    xor h
    add a
    inc sp
    ld d, l
    set 4, e
    set 4, e
    ld a, a
    or d
    call c, $d9be
    ld l, $e7
    ld d, a
    db $ed
    jr z, jr_011_6f2c

    ld b, [hl]
    ret nz

    rst $20
    ld c, a
    or l

jr_011_6f15:
    rst $08
    or h
    ret


jr_011_6f18:
    ld a, a
    adc $b3
    ld h, $7f
    sub d
    add a
    sub l
    adc e
    xor l
    xor e
    jr nc, jr_011_6f7d

    db $ed
    jr z, @-$4c

    ld b, l
    push bc
    ld d, [hl]
    ld c, a

jr_011_6f2c:
    call nc, $c9cf
    ld a, a
    ld d, h
    ld a, a
    add $ca
    ld d, l
    or d
    call c, $8f7f
    add c
    ld b, d
    ld h, $7f
    or l
    or l
    or d
    cpl
    ld d, a

jr_011_6f42:
    ld [$6321], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, @+$49

    ld b, [hl]
    rst $18
    jp Jump_011_7fd3


    or d
    or d
    cp c
    inc [hl]
    ld d, [hl]
    ld c, a
    cp d
    ret


    ld a, a
    or c
    ret nz

    ret c

    add $ca
    ld d, l
    or c
    rst $08
    ret c

    ld a, a
    or a
    ret nz

    ld a, a
    cp d
    call nz, $c57f
    or d

jr_011_6f6f:
    ret


    ld d, a
    db $ed
    jr z, @+$01

    ld b, [hl]
    ldh [$df], a
    ret nz

    ld e, b
    db $ed
    jr z, jr_011_6f18

    ld b, [hl]

jr_011_6f7d:
    ldh [$b2], a
    ld a, a
    ld d, h
    ld h, $7f
    cp l
    or a
    ld c, a
    or l
    rst $18
    or a
    or d
    ret


    jp z, $ba7f

    call c, Call_011_7fb2
    or [hl]
    rst $10
    ld a, a
    or d
    call nc, Call_000_0857

jr_011_6f98:
    ld hl, $6d6f
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed

jr_011_6fa2:
    jr z, @+$0a

    ld b, a
    ld a, a
    push bc
    rst $10
    ld c, a
    inc [hl]
    db $e3
    sbc $c4
    ld a, a
    inc a
    jp nz, $dfb6

    jp $ba7f


    or d
    rst $20
    ld d, a
    db $ed
    jr z, jr_011_6f42

    ld b, a
    call nz, $4fe7
    cp d
    rst $18
    pop bc
    ld h, $7f
    call nc, $dad7
    ret nz

    rst $20
    ld e, b
    db $ed
    jr z, jr_011_6ff6

    ld b, a
    ld a, a
    ld a, $b3
    dec l
    add $7f
    rst $08
    cp c
    push bc
    or d
    ld c, a
    ld d, h
    db $dd
    ld a, a
    cp a
    jr nc, jr_011_6fa2

    jp $b57f


    cp b
    ld l, $e7
    ld d, a
    ld [$7b21], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_011_6f98

    ld b, a
    ld a, a
    or d

jr_011_6ff6:
    reti


    ld a, a
    call nz, $cab7
    ld c, a
    ld d, h
    ret


    ld a, a
    add c
    and l
    adc h
    sub e
    ld a, a
    call nz, Call_011_7fb6
    or [hl]
    or d
    jp Jump_011_57d9


    db $ed
    jr z, @+$4e

    ld c, b
    ld c, a
    ld a, $b8
    ld a, a
    cp b
    ret nz

    dec sp
    jp c, $58c0

    db $ed
    jr z, @-$0d

    ld b, a
    ld a, a
    ret nz

    ret nz

    or [hl]
    or e
    ret


    ld a, a
    pop de
    or d
    jp $c57f


    or d
    push bc
    ld c, a
    or [hl]
    or h
    rst $18
    jp $817f


    and l
    adc h
    sub e
    ld a, a
    inc sp
    db $d3
    ld a, a
    or [hl]
    or d
    jp $b3d6


    ld d, a
    inc bc
    inc b
    add hl, de
    ld hl, $5204
    inc bc
    dec de
    dec b
    ld d, d
    dec bc
    rla
    ld b, $52
    inc bc
    inc bc
    rlca
    ld d, d
    nop
    ld [$1106], sp
    rrca
    rst $38
    ret nc

    ld b, c
    adc $09
    ld c, $0e
    ld a, [bc]
    rst $38
    ret nc

    ld b, d
    pop de
    add hl, bc
    inc c
    add hl, bc
    rlca
    rst $38
    ret nc

    ld b, e
    rst $08
    inc bc
    inc c
    add hl, de
    jr @+$01

    db $d3
    ld b, h
    rst $08
    inc b
    ld c, $0e
    ld [hl+], a
    rst $38
    ret nc

    ld b, l
    pop de
    ld a, [bc]
    ld b, $20
    ld [de], a
    rst $38
    db $d3
    ld b, [hl]
    adc $0a
    ld c, $09
    dec h
    rst $38
    db $d3
    ld b, a
    pop de
    dec bc
    inc c
    ld [hl+], a
    ld e, $ff
    ret nc

    ld c, b
    rst $08
    dec b
    ld c, e
    ret z

    add hl, de
    ld hl, $c72a
    inc bc
    dec de
    sub b
    rst $00
    dec bc
    rla
    ld e, $c7
    inc bc
    inc bc
    rla
    ld [bc], a
    jr nz, jr_011_70ca

    jr nz, @+$24

    jr nz, @+$24

    jr nz, jr_011_70d0

    jr nz, @+$24

    jr nz, @+$24

    jr nz, jr_011_70d6

    jr nz, @+$24

    jr nz, @+$24

    rra
    ld a, $01
    rla
    ld bc, $1701
    ld bc, $0101
    ld bc, $1701
    ld a, $01
    ld bc, $0101

jr_011_70ca:
    ld bc, $1702
    ld bc, $1f01

jr_011_70d0:
    ld bc, $1f01
    ld bc, $0101

jr_011_70d6:
    ld bc, $1f01
    ld bc, $0101
    ld bc, $0101
    rla
    rra
    ld bc, $1701
    ld bc, $1701
    ld bc, $1701
    ld bc, $1701
    ld bc, $1701
    rla
    ld bc, $1f01
    rla
    ld bc, $1f01
    ld bc, $1f01
    ld bc, $1f01
    ld [bc], a
    ld [bc], a
    rra
    ld bc, $1f01
    rra
    ld bc, $1701
    rra
    ld bc, $0101
    ld bc, $1701
    ld bc, $0101
    ld bc, $173e
    ld bc, $0101
    ld bc, $0101
    rra
    rla
    ld bc, $0101
    ld bc, $1f01
    ld bc, $0101
    ld bc, $1f01
    ld bc, $0101
    ld bc, $0101
    rla
    rra
    ld bc, $1701
    ld bc, $0101
    ld bc, $1701
    jr nz, @+$24

    jr nz, @+$24

    jr nz, jr_011_7162

    ld bc, $0101
    rra
    rla
    ld bc, $1f01
    ld bc, $0101
    ld bc, $1f01
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rla
    rra
    ld bc, $1701
    ld bc, $0201
    ld bc, $1701

jr_011_7162:
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rra
    rla
    ld bc, $1f01
    ld bc, $0201
    ld bc, $1f01
    ld bc, $0101
    jr nz, @+$24

    jr nz, @+$24

    jr nz, jr_011_71a1

    rla
    rra
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld bc, $2001
    ld [hl+], a
    jr nz, jr_011_71ac

    ld bc, $0101
    rla
    ld bc, $0101
    ld bc, $1f01
    rla
    ld bc, $0101
    ld bc, $1701
    ld bc, $0101
    ld bc, $0101

jr_011_71a1:
    rra
    ld bc, $3e01
    ld bc, $1701
    rra
    ld bc, $0101

jr_011_71ac:
    ld bc, $1f01
    ld bc, $0101
    ld bc, $0101
    rla
    ld bc, $0101
    ld bc, $1f01
    rla
    jr nz, @+$24

    jr nz, jr_011_71e3

    jr nz, jr_011_71e5

    ld bc, $2001
    ld [hl+], a
    jr nz, jr_011_71eb

    rra
    ld bc, $0101
    ld bc, $1701
    rra
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101

jr_011_71e3:
    rra
    ld [bc], a

jr_011_71e5:
    ld bc, $0101
    ld bc, $0101

jr_011_71eb:
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rla
    jr nz, @+$24

    jr nz, jr_011_721e

    jr nz, jr_011_7220

    jr nz, jr_011_7222

    jr nz, jr_011_7224

    jr nz, @+$24

    jr nz, @+$24

    jr nz, jr_011_722a

    jr nz, @+$24

    ld [bc], a
    rra
    ld de, $0f09
    pop bc
    ld [hl], d
    ld [hl], l
    ld [hl], d
    jr jr_011_7287

    nop
    ld a, c
    ld [hl], d
    call Call_000_3c6c
    ld hl, $cd5b

jr_011_721e:
    bit 7, [hl]

jr_011_7220:
    res 7, [hl]

jr_011_7222:
    jr z, jr_011_7265

jr_011_7224:
    ld hl, $7270
    call Call_000_352e

jr_011_722a:
    ret nc

    ld hl, $d7fe
    ld a, [$cd3d]
    cp $01
    jr nz, jr_011_7243

    set 0, [hl]
    ld a, $d9
    ld [$d056], a
    ld a, $db
    ld [$d057], a
    jr jr_011_724f

jr_011_7243:
    set 1, [hl]
    ld a, $da
    ld [$d056], a
    ld a, $dc
    ld [$d057], a

jr_011_724f:
    ld a, [$d056]
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, [$d057]
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


jr_011_7265:
    ld a, $a0
    ld [$d69c], a
    ld hl, $7270
    jp $78a6


    ld b, $12
    ld b, $17
    rst $38
    add e
    rrca
    add e
    rrca
    ld a, l
    rlca
    ld [bc], a
    inc b
    nop
    and b
    dec b
    rlca
    inc b
    ret nz

    rlca
    dec c
    ld [bc], a
    and b

jr_011_7287:
    rrca
    inc de
    inc bc
    and b
    rrca
    rla
    ld b, $c0
    dec bc
    add hl, de
    dec b
    and b
    inc bc
    add hl, de
    dec b
    ret nz

    nop
    ld [bc], a
    ccf
    ld a, [bc]
    dec d
    rst $38
    db $10
    ld bc, $0a3f
    ld a, [de]
    rst $38
    db $10
    ld [bc], a
    dec d
    rst $00
    ld [bc], a
    inc b
    dec hl
    rst $00
    dec b
    rlca
    ld b, e
    rst $00
    rlca
    dec c
    sbc d
    rst $00
    rrca
    inc de
    sbc h
    rst $00
    rrca
    rla
    ld [hl], e
    rst $00
    dec bc
    add hl, de
    rra
    rst $00
    inc bc
    add hl, de
    ld l, $2e
    ld l, $2e
    ld l, $14
    dec d
    dec d
    dec d
    ld d, $2e
    ld l, $2e
    ld l, $2e
    ld l, $01
    daa
    ld bc, $1801
    add hl, de
    inc l
    dec l
    ld e, $01
    ld bc, $013e
    ld l, $2e
    ld bc, $7c14
    ld d, $18
    add hl, de
    ld a, [de]
    ld bc, $6d01
    ld bc, $0101
    ld l, $2e
    ld bc, $2c18
    ld e, $18
    inc a
    ld a, [de]
    ld bc, $6d77
    ld a, b
    ld bc, $2e01
    ld l, $01
    ld h, [hl]
    ld e, $14
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $4c01
    ld e, [hl]
    ld e, [hl]
    ld e, [hl]
    ld l, $2e
    ld bc, $0101
    jr jr_011_732b

    add hl, de
    add hl, de
    dec d
    ld d, $01
    ld bc, $0128
    ld l, $2e
    ld bc, $0101
    ld h, [hl]
    dec e
    dec e
    dec e
    dec l
    ld e, $01
    ld bc, $0101
    ld l, $2e

jr_011_732b:
    ld bc, $0101
    ld bc, $6d01
    ld bc, $2801
    ld l, l
    ld a, $01
    ld bc, $2e2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld de, $0f09
    db $fd
    ld [hl], e
    or c
    ld [hl], e
    ld d, h
    ld [hl], e
    nop
    or l
    ld [hl], e
    call Call_000_3c6c
    ld hl, $cd5b
    bit 7, [hl]
    res 7, [hl]
    jr z, jr_011_73a1

    ld hl, $73ac
    call Call_000_352e
    ret nc

    ld hl, $d7ff
    ld a, [$cd3d]
    cp $01
    jr nz, jr_011_737f

    set 0, [hl]
    ld a, $db
    ld [$d056], a
    ld a, $df
    ld [$d057], a
    jr jr_011_738b

jr_011_737f:
    set 1, [hl]
    ld a, $dc
    ld [$d056], a
    ld a, $e0
    ld [$d057], a

jr_011_738b:
    ld a, [$d056]
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, [$d057]
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


jr_011_73a1:
    ld a, $a1
    ld [$d69c], a
    ld hl, $73ac
    jp $78a6


    ld b, $13
    ld b, $16
    rst $38
    add e
    rrca
    add e
    rrca
    ld a, l
    rlca
    inc bc
    dec b
    nop
    sbc a
    dec c
    dec b
    nop
    and c
    rlca
    dec c
    ld [bc], a
    sbc a
    rrca
    inc de
    inc bc
    sbc a
    inc bc
    add hl, de
    inc bc
    and c
    dec bc
    add hl, de
    dec b
    sbc a
    ld c, $19
    inc b
    and c
    nop
    ld [bc], a
    ccf
    ld a, [bc]
    ld d, $ff
    db $10
    ld bc, $0a3f
    dec de
    rst $38
    db $10
    ld [bc], a
    dec d
    rst $00
    inc bc
    dec b
    ld a, [hl]
    rst $00
    dec c
    dec b
    ld b, e
    rst $00
    rlca
    dec c
    sbc d
    rst $00
    rrca
    inc de
    rra
    rst $00
    inc bc
    add hl, de
    ld [hl], e
    rst $00
    dec bc
    add hl, de
    sbc l
    rst $00
    ld c, $19
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld bc, $013e
    ld bc, $0101
    ld bc, $0101
    ld bc, $3c14
    ld d, $2e
    ld l, $01
    ld bc, $0101
    inc d
    dec d
    ld d, $01
    ld bc, $1c01
    dec l
    ld e, $2e
    ld l, $01
    ld bc, $0101
    jr jr_011_746e

    ld a, [de]
    ld bc, $5278
    ld [hl], a
    ld bc, $2e01
    ld l, $14
    dec d
    dec d
    dec d
    add hl, de
    add hl, de
    add hl, de
    dec d
    dec d
    ld d, $01
    ld bc, $2e01
    ld l, $1c
    dec e
    add hl, hl
    dec e
    dec e
    dec e
    dec hl
    add hl, de
    add hl, de
    ld a, [de]
    inc d
    ld a, h
    ld d, $2e
    ld l, $01
    jr z, @+$03

    ld bc, $0101
    inc e
    dec l
    dec e
    ld e, $18
    add hl, de
    ld a, [de]
    ld l, $2e
    ld bc, $0101
    ld bc, $0101
    db $10

jr_011_746e:
    ld bc, $013e
    inc e
    ld a, c
    ld e, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $2e
    ld l, $11
    add hl, bc
    rrca
    add hl, bc
    db $76
    sbc l
    ld [hl], l
    sub b
    ld [hl], h
    nop
    xor c
    ld [hl], l
    call Call_000_3c6c
    ld hl, $cd5b
    bit 7, [hl]
    res 7, [hl]
    jr z, jr_011_74df

    ld hl, $74f9
    call Call_000_352e
    ret nc

    ld hl, $d800
    ld a, [$cd3d]
    cp $01
    jr nz, jr_011_74bb

    set 0, [hl]
    ld a, $dd
    ld [$d056], a
    ld a, $e1
    ld [$d057], a
    jr jr_011_74c7

jr_011_74bb:
    set 1, [hl]
    ld a, $de
    ld [$d056], a
    ld a, $e2
    ld [$d057], a

jr_011_74c7:
    ld a, [$d056]
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, [$d057]
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    jr jr_011_74f0

jr_011_74df:
    ld a, $a2
    ld [$d69c], a
    ld hl, $74f9
    call $78a6
    ld a, [$d6b1]
    bit 4, a
    ret nz

jr_011_74f0:
    ld hl, $74fe
    ld a, [$d5e5]
    jp Jump_000_3dc7


    db $10
    inc bc
    db $10
    ld b, $ff
    ld b, $75
    inc a
    ld [hl], l
    ld b, a
    ld [hl], l
    sub d
    ld [hl], l
    ld a, [$d7ff]
    and $03
    cp $03
    ret z

    ld a, [$d2e0]
    cp $08
    ret nz

    ld a, [$d2e1]
    cp $0f
    ret nz

    ld hl, $ccd3
    ld de, $7535
    call Call_000_3556
    dec a
    ld [$cd38], a
    call Call_000_34d0
    ld hl, $d6b2
    set 2, [hl]
    ld a, $01
    ld [$d5e5], a
    ret


    add b
    ld b, $10
    dec b
    add b
    inc bc
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    ld a, $00
    ld [$d5e5], a
    ret


    ld a, [$d7ff]
    and $03
    cp $03
    ret z

    ld a, [$d2e1]
    cp $12
    jr z, jr_011_7561

    cp $13
    ld a, $00
    jr nz, jr_011_757e

    ld de, $7582
    jr jr_011_7564

jr_011_7561:
    ld de, $758b

jr_011_7564:
    ld hl, $ccd3
    call Call_000_3556
    dec a
    ld [$cd38], a
    xor a
    ld [$c206], a
    ld hl, $d6af
    set 7, [hl]
    ld hl, $d6b2
    set 2, [hl]
    ld a, $03

jr_011_757e:
    ld [$d5e5], a
    ret


    add b
    ld b, $10
    ld [bc], a
    add b
    inc b
    jr nz, jr_011_758b

    rst $38

jr_011_758b:
    add b
    ld b, $10
    ld [bc], a
    add b
    inc b
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    ld a, $00
    ld [$d5e5], a
    ret


    add e
    rrca
    add e
    rrca
    add e
    rrca
    add e
    rrca
    add e
    rrca
    add e
    rrca
    ld a, l
    rlca
    inc c
    dec b
    ld bc, $06a0
    ld [$a202], sp
    inc b
    add hl, de
    inc bc
    and d
    inc bc
    add hl, de
    inc b
    and b
    ld c, $19
    ld b, $a0
    ld de, $0014
    and d
    ld de, $0115
    and d
    nop
    ld b, $3f
    ld [de], a
    add hl, bc
    rst $38
    db $10
    ld bc, $133f
    rlca
    rst $38
    db $10
    ld [bc], a
    ccf
    ld [de], a
    inc c
    rst $38
    db $10
    inc bc
    ccf
    ld [de], a
    dec c
    rst $38
    db $10
    inc b
    ccf
    ld a, [bc]
    ld d, $ff
    rst $38
    dec b
    ccf
    ld a, [bc]
    rla
    rst $38
    rst $38
    ld b, $7e
    rst $00
    inc c
    dec b
    ld b, c
    rst $00
    ld b, $08
    inc [hl]
    rst $00
    inc b
    add hl, de
    rra
    rst $00
    inc bc
    add hl, de
    sbc l
    rst $00
    ld c, $19
    or b
    rst $00
    ld de, $b014
    rst $00
    ld de, $1415
    dec d
    dec d
    dec d
    ld d, $02
    ld [bc], a
    db $76
    ld [bc], a
    ld [bc], a
    inc d
    dec d
    dec d
    dec d
    ld d, $18
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    db $76
    db $76
    db $76
    db $76
    db $76
    jr jr_011_763d

    dec a
    add hl, de
    ld a, [de]
    jr jr_011_7642

    inc l
    add hl, hl
    ld e, $14
    dec d
    dec d
    ld d, $76
    inc e
    dec e
    ld a, c
    dec e
    ld e, $18
    add hl, de
    ld a, [de]
    ld bc, $1827
    inc l

jr_011_763d:
    dec l
    ld e, $76
    inc d
    dec d

jr_011_7642:
    dec d
    dec d
    ld d, $18
    add hl, de
    add hl, de
    dec d
    dec d
    add hl, de
    ld a, [de]
    db $76
    db $76
    db $76
    inc e
    dec l
    dec hl
    add hl, de
    ld a, [de]
    jr jr_011_766f

    add hl, de
    inc l
    dec e
    dec hl
    ld a, [de]
    db $76
    db $76
    db $76
    db $76
    db $76
    jr jr_011_767b

    ld a, [de]
    inc e
    dec e
    ld h, c
    ld e, $01
    jr jr_011_7683

    dec d
    dec d
    ld d, $76
    inc d

jr_011_766f:
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0c01
    rrca
    ld bc, $1d1c
    dec e
    add hl, hl

jr_011_767b:
    ld e, $76
    inc e
    ld h, c
    dec e
    ld e, $01
    ld a, b

jr_011_7683:
    ld b, $77
    rrca
    ld bc, $0101
    ld bc, $767a
    ld l, l
    ld bc, $0101
    ld de, $0f09
    rra
    ld a, b
    ld a, a
    ld [hl], a
    sbc h
    halt
    pop hl
    ld [hl], a
    call Call_000_3c6c
    ld a, [$d5e7]
    ld hl, $76b0
    jp Jump_000_3dc7


jr_011_76a8:
    xor a
    ld [$d5e7], a
    ld [$cd66], a
    ret


    jp z, Jump_000_0a76

    ld [hl], a
    add hl, de
    ld [hl], a
    ld h, e
    ld [hl], a
    cp d
    db $76
    ld a, [$d034]
    cp $ff
    jr z, jr_011_76a8

    call Call_000_32bd
    ld a, $00
    ld [$d5e7], a
    ret


    ld a, [$d7ff]
    and $03
    cp $03
    ret z

    ld hl, $7701
    call Call_000_3509
    ret nc

    ld a, [$cd3d]
    cp $03
    jr nc, jr_011_76e9

    ld a, $40
    ld [$ccd4], a
    ld a, $02
    jr jr_011_76eb

jr_011_76e9:
    ld a, $01

jr_011_76eb:
    ld [$cd38], a
    ld a, $40
    ld [$ccd3], a
    call Call_000_34d0
    ld hl, $d6b2
    res 2, [hl]
    ld a, $01
    ld [$d5e7], a
    ret


    ld de, $1114
    dec d
    db $10
    inc d
    db $10
    dec d
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    xor a
    ld [$cd66], a
    ld a, $00
    ld [$d5e7], a
    ret


    ld a, [$d800]
    and $03
    cp $03
    ld a, $00
    jr z, jr_011_774c

    ld hl, $7750
    call Call_000_3509
    ld a, $00
    jr nc, jr_011_774c

    ld a, [$cd3d]
    cp $01

jr_011_7733:
    jr nz, jr_011_773a

    ld de, $775c
    jr jr_011_773d

jr_011_773a:
    ld de, $7755

jr_011_773d:
    ld hl, $ccd3
    call Call_000_3556
    dec a
    ld [$cd38], a
    call Call_000_34d0
    ld a, $03

jr_011_774c:
    ld [$d5e7], a
    ret


    ld c, $04
    ld c, $05
    rst $38
    ld b, b
    inc bc
    db $10
    ld [bc], a
    ld b, b
    ld bc, $40ff
    inc bc
    db $10
    inc bc
    ld b, b
    ld bc, $faff
    jr c, jr_011_7733

    ld b, a
    cp $01
    call z, Call_011_7775
    ld a, b
    and a
    ret nz

    ld a, $00
    ld [$d5e7], a
    ret


Call_011_7775:
    xor a
    ld [$d67f], a
    ld [$d0df], a
    jp Jump_000_2cfe


    add e
    rrca
    add e
    rrca
    sub [hl]
    ld [hl], a
    cp b
    ld [hl], a
    pop de
    ld [hl], a
    ld [bc], a
    nop
    ld bc, $a5d8
    ld [hl], a
    and l
    ld [hl], a
    and l
    ld [hl], a
    and l
    ld [hl], a
    rst $38
    ld [$8921], sp
    ld [hl], a
    call Call_000_3214
    ld a, $04
    ld [$d5e7], a
    jp Jump_000_0f6a


    nop
    and c
    ret z

    add c
    ld a, a
    ld a, a
    ld d, b
    ld [$4a3e], sp
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    dec l
    jp Jump_011_7f4e


    or d
    call c, Call_011_7f33
    push bc
    ld h, $da
    db $dd
    ld c, a
    cp [hl]
    or a
    call nz, $d7d2
    jp c, $b6d9

    db $d3
    ld d, [hl]
    ld d, a
    db $ed
    dec l
    ld e, d
    ld c, c
    rst $20
    ld c, a
    push bc
    ld h, $da
    ld h, $7f
    jp z, $b2d4

    rst $20
    ld d, a
    ld a, l
    inc b
    ld de, $0514
    and c
    ld de, $0615
    and c
    rlca
    dec bc
    ld bc, $04a1
    add hl, de
    ld [bc], a
    and c
    ld [bc], a
    rrca
    add hl, bc
    inc b
    ld bc, $0517
    inc bc
    ccf
    inc de
    ld [$ffff], sp
    ld bc, $133f
    add hl, bc
    rst $38
    rst $38
    ld [bc], a
    add hl, bc
    dec b
    ld a, [bc]
    rst $38
    ret nc

    ld b, e
    ld c, d
    ld [hl-], a
    or b
    rst $00
    ld de, $b014
    rst $00
    ld de, $4215
    rst $00
    rlca
    dec bc
    inc [hl]
    rst $00
    inc b
    add hl, de
    ld l, $76
    inc d
    dec d
    dec d
    ld d, $76
    inc d
    dec d
    dec d
    dec d
    ld [hl], l
    dec d
    ld d, $2e
    ld l, $76
    inc e
    dec l
    dec e
    ld e, $76
    jr jr_011_7850

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld l, $2e
    db $76
    db $76
    db $76
    db $76
    db $76
    db $76
    jr jr_011_7872

    dec e
    dec e
    dec l
    ld h, c
    ld e, $2e
    ld l, $76
    db $76
    inc d

jr_011_7850:
    dec d
    ld a, h
    dec d
    add hl, de
    ld a, [de]
    db $76
    db $76
    db $76
    db $76
    db $76
    ld l, $2e
    db $76
    db $76
    jr @+$1b

    add hl, de
    add hl, de
    inc l
    ld e, $76
    db $76
    db $76
    db $76
    db $76
    ld l, $2e
    db $76
    db $76
    ld h, [hl]
    dec e
    dec e
    dec hl
    ld a, [de]

jr_011_7872:
    db $76
    db $76
    db $76
    db $76
    db $76
    db $76
    ld l, $2e
    db $76
    db $76
    db $76
    db $76
    db $76
    jr jr_011_789b

    db $76
    db $76
    db $76
    db $76
    db $76
    db $76
    ld l, $2e
    db $76
    db $76
    inc d
    ld [hl], l
    dec d
    add hl, de
    add hl, de
    dec d
    ld d, $76
    db $76
    db $76
    db $76
    ld l, $2e
    ld [bc], a
    db $76
    inc e

jr_011_789b:
    dec e
    dec e
    dec e
    dec e
    dec e
    ld e, $76
    ld [bc], a
    ld c, h
    ld [bc], a
    ld l, $af
    ld [$d69d], a
    ld a, [$d6ac]
    bit 4, a
    ret nz

    call Call_000_3509
    ret nc

    ld a, [$cd3d]
    ld [$d69d], a
    ld hl, $d6ac
    set 4, [hl]
    ld hl, $d6b1
    set 4, [hl]
    ret


    ld hl, $ffeb
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld de, $0000
    ld hl, $7965

jr_011_78d3:
    ld a, [hl+]
    ld b, a
    cp $ff
    jr z, jr_011_7921

    ld a, [$d2dd]
    cp b
    jr z, jr_011_78e3

    inc de
    inc de
    jr jr_011_78d3

jr_011_78e3:
    ld hl, $79bb
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    push hl
    ld hl, $cd3d
    xor a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    pop hl

jr_011_78f3:
    ld a, [hl+]
    cp $ff
    jr z, jr_011_7921

    ld [$cd40], a
    ld b, a
    ld a, [hl+]
    ld [$cd41], a
    ld c, a
    call Call_011_7926
    ldh a, [$ea]
    and a
    jr z, jr_011_7915

    inc hl
    inc hl
    inc hl
    inc hl
    push hl
    ld hl, $cd3f
    inc [hl]
    pop hl
    jr jr_011_78f3

jr_011_7915:
    ld a, [hl+]
    ld [$cd3d], a
    ld a, [hl+]
    ld [$cd3e], a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ret


jr_011_7921:
    ld a, $ff
    ldh [$ee], a
    ret


Call_011_7926:
    ld a, [$c109]
    cp $04
    jr z, jr_011_793b

    cp $08
    jr z, jr_011_794a

    cp $0c
    jr z, jr_011_7950

    ld a, [$d2e0]
    inc a
    jr jr_011_793f

jr_011_793b:
    ld a, [$d2e0]
    dec a

jr_011_793f:
    cp b
    jr nz, jr_011_7960

    ld a, [$d2e1]
    cp c
    jr nz, jr_011_7960

    jr jr_011_795d

jr_011_794a:
    ld a, [$d2e1]
    dec a
    jr jr_011_7954

jr_011_7950:
    ld a, [$d2e1]
    inc a

jr_011_7954:
    cp c
    jr nz, jr_011_7960

    ld a, [$d2e0]
    cp b
    jr nz, jr_011_7960

jr_011_795d:
    xor a
    jr jr_011_7962

jr_011_7960:
    ld a, $ff

jr_011_7962:
    ldh [$ea], a
    ret


    ld h, $27
    jr z, jr_011_7992

    ld a, [hl+]
    dec hl
    dec l
    inc [hl]
    ld [hl], $38
    ld a, [hl-]
    ld b, b
    ld b, c
    ld b, e
    adc l
    ld e, c
    ld e, h
    add c
    add l
    add [hl]
    add a
    adc h
    sbc d
    sbc l
    and [hl]
    xor e
    or d
    ld b, h
    ld d, c
    rst $28
    ldh a, [$33]
    dec a
    add hl, bc
    inc h
    inc d
    ld h, h
    ld l, b
    rst $00
    ret


    jp z, $92b6

    jr @-$62

jr_011_7992:
    db $db
    jp nc, $b0e9

    db $e4
    db $e3
    ld d, e
    and b
    and d
    and l
    rst $10
    ld [hl+], a
    jp nz, $586f

    ld bc, $e0df
    pop hl
    cp c
    sub l
    add h
    or c
    dec d
    xor [hl]
    xor d
    ld b, d
    ld d, $17
    sub $d8
    db $eb
    inc e
    ld [hl], a
    ld a, c
    ld b, $a1
    dec b
    inc bc
    rrca
    rst $38
    ld a, a
    ld a, d
    adc h
    ld a, d
    sbc a
    ld a, d
    cp b
    ld a, d
    push bc
    ld a, d
    add $7a
    db $d3
    ld a, d
    ldh [$7a], a
    db $ed
    ld a, d
    ld a, [$fb7a]
    ld a, d
    ld [$157b], sp
    ld a, e
    ld [hl+], a
    ld a, e
    inc hl
    ld a, e
    jr nc, jr_011_7a56

    dec a
    ld a, e
    xor d
    ld a, e
    or c
    ld a, e
    cp [hl]
    ld a, e
    bit 7, e
    db $ec
    ld a, h
    ld sp, hl
    ld a, h
    ld b, $7d
    inc de
    ld a, l
    ld a, $7d
    ld c, e
    ld a, l
    ld d, d
    ld a, l
    ld e, a
    ld a, l
    ld h, l
    ld a, d
    ld [hl], d
    ld a, d
    ld l, h
    ld a, l
    ld a, c
    ld a, l
    add [hl]
    ld a, l
    sub e
    ld a, l
    and b
    ld a, l
    and a
    ld a, l
    cp d
    ld a, l
    adc $7d
    push de
    ld a, l
    call c, $e37d
    ld a, l
    ldh a, [$7d]
    rst $30
    ld a, l
    inc b
    ld a, [hl]
    dec bc
    ld a, [hl]
    ld [de], a
    ld a, [hl]
    add hl, de
    ld a, [hl]
    jr nz, jr_011_7a9b

    daa
    ld a, [hl]
    ld l, $7e
    dec [hl]
    ld a, [hl]
    ld b, d
    ld a, [hl]
    ld c, c
    ld a, [hl]
    ld d, b
    ld a, [hl]
    ld h, h

jr_011_7a2a:
    ld a, [hl]
    add h
    ld a, [hl]
    sub a
    ld a, [hl]
    and h

jr_011_7a30:
    ld a, [hl]
    xor e
    ld a, [hl]
    or d
    ld a, [hl]
    cp c

jr_011_7a36:
    ld a, [hl]
    add $7e
    db $d3
    ld a, [hl]
    ldh [$7e], a
    rst $20
    ld a, [hl]
    ld a, [$0d7e]
    ld a, a
    pop bc
    ld a, l
    ld h, $7f
    dec l
    ld a, a
    ld a, [hl-]
    ld a, a
    ld e, a
    ld a, a
    ld h, [hl]
    ld a, a
    ld e, l
    ld a, [hl]
    ld [hl], c
    ld a, [hl]
    ld l, l
    ld a, a
    ld [hl], h

jr_011_7a56:
    ld a, a
    sub e
    ld a, a
    and b
    ld a, a
    xor l
    ld a, a
    or h
    ld a, a
    cp e
    ld a, a
    jp nz, $c97f

    ld a, a
    inc b
    dec b
    ret nc

    ld [$4525], sp
    inc b
    inc b
    ret nc

    ld [$4505], sp
    rst $38
    inc b
    dec b
    ret nc

    ld [$4525], sp
    inc b
    inc b
    ret nc

    ld [$4505], sp
    rst $38

jr_011_7a7f:
    ld bc, $0400
    rla
    inc bc
    ld a, c
    dec b
    inc bc
    ret nc

    rla
    rst $10
    ld a, b
    rst $38
    ld bc, $0400
    jr jr_011_7a2a

    ld a, a
    ld bc, $0401
    jr jr_011_7a30

    ld a, a
    ld bc, $0407

jr_011_7a9b:
    jr jr_011_7a36

    ld a, a
    rst $38
    nop
    inc b
    inc b
    rlca
    or b
    ld a, c
    nop
    dec b
    inc b
    rlca
    ret c

    ld a, c
    ld bc, $0400
    rlca
    add hl, de
    ld a, a
    ld bc, $0401
    rlca
    add hl, de
    ld a, a
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7a7f

    ld a, a
    rst $38
    rst $38
    inc b
    inc bc
    jr nz, jr_011_7ade

    db $76
    ld a, l

jr_011_7acc:
    nop
    inc bc
    ld hl, $ea17
    ld a, c
    rst $38
    rrca
    rrca
    inc b
    jr jr_011_7af9

    ld a, h
    rrca
    ld [de], a
    inc b
    jr @+$23

jr_011_7ade:
    ld a, h
    rst $38
    inc bc
    ld [bc], a
    inc b
    rla
    ld e, c
    ld a, c
    ld b, $02
    inc b
    rla

jr_011_7aea:
    add b
    ld a, c
    rst $38
    ld a, [bc]
    inc bc
    inc b
    jr jr_011_7b13

    ld a, h
    ld a, [bc]
    ld b, $04
    jr @+$23

    ld a, h

jr_011_7af9:
    rst $38
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr @-$42

    ld a, a
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr @-$42

jr_011_7b13:
    ld a, a
    rst $38
    dec bc
    inc bc
    inc b
    jr jr_011_7b3b

    ld a, h
    dec bc
    ld b, $04
    jr @+$23

    ld a, h
    rst $38
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7aea

    ld a, a
    rst $38
    inc bc
    dec c
    inc b
    jr @-$42

    ld a, a
    inc b
    nop
    inc b
    jr jr_011_7acc

jr_011_7b3b:
    ld a, h
    rst $38
    ld c, $03
    inc b
    jr jr_011_7b63

    ld a, h
    ld c, $06
    inc b
    jr jr_011_7b69

    ld a, h
    ld bc, $0006
    rla
    rst $00
    ld a, l
    rlca
    ld bc, $1700
    db $e4
    ld a, l
    add hl, bc
    ld bc, $1701
    db $e4
    ld a, l
    dec bc
    ld bc, $1702
    db $e4
    ld a, l
    rlca
    inc bc

jr_011_7b63:
    inc bc
    rla
    db $e4
    ld a, l
    add hl, bc
    inc bc

jr_011_7b69:
    inc b
    rla

jr_011_7b6b:
    db $e4
    ld a, l
    dec bc
    inc bc
    dec b
    rla
    db $e4
    ld a, l
    rlca
    dec b
    ld b, $17
    db $e4

jr_011_7b78:
    ld a, l
    add hl, bc
    dec b
    rlca
    rla
    db $e4
    ld a, l
    dec bc
    dec b
    ld [$e417], sp
    ld a, l
    rlca
    rlca
    add hl, bc
    rla
    db $e4
    ld a, l
    add hl, bc
    rlca
    ld a, [bc]
    rla
    db $e4
    ld a, l
    dec bc
    rlca
    dec bc
    rla
    db $e4
    ld a, l
    rlca
    add hl, bc
    inc c
    rla
    db $e4
    ld a, l
    add hl, bc
    add hl, bc
    dec c
    rla
    db $e4
    ld a, l
    dec bc
    add hl, bc
    ld c, $17
    db $e4
    ld a, l
    rst $38
    dec b
    nop
    inc b
    jr jr_011_7b6b

    ld a, a
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7b78

    ld a, a
    rst $38
    rrca
    inc bc
    inc b
    jr jr_011_7be4

    ld a, h
    rrca
    ld b, $04
    jr jr_011_7bea

    ld a, h
    rst $38
    rrca
    ld [de], a
    ret nc

    dec c
    ld e, a
    ld a, a
    ld c, $12
    ret nc

    dec c
    ld e, a
    ld a, a
    dec c
    ld [de], a
    ret nc

    dec c
    ld e, a
    ld a, a
    inc c
    ld [de], a
    ret nc

    dec c
    ld e, a
    ld a, a
    dec bc

jr_011_7be4:
    ld [de], a
    ret nc

    dec c
    ld e, a
    ld a, a
    ld a, [bc]

jr_011_7bea:
    ld [de], a
    rst $38
    dec c
    ld e, a
    ld a, a
    ld a, [bc]
    dec c
    ret nc

    dec c
    ld e, a
    ld a, a
    dec bc
    dec c
    ret nc

    dec c
    ld e, a
    ld a, a
    inc c
    dec c
    cp $0d
    ld e, a
    ld a, a
    dec c
    dec c
    ret nc

    dec c
    ld e, a
    ld a, a
    ld c, $0d
    ret nc

    dec c
    ld e, a
    ld a, a
    rrca
    dec c
    ret nc

    dec c
    ld e, a
    ld a, a
    rrca
    inc c
    ret nc

    dec c
    ld e, a
    ld a, a
    ld c, $0c
    ret nc

    dec c
    ld e, a
    ld a, a
    dec c
    inc c
    ret nc

    dec c
    ld e, a
    ld a, a
    inc c
    inc c
    ret nc

    dec c
    ld e, a
    ld a, a
    dec bc
    inc c
    ret nc

    dec c
    ld e, a
    ld a, a
    ld a, [bc]
    inc c
    ret nc

    dec c
    ld e, a
    ld a, a
    ld a, [bc]
    rlca
    ret nc

    dec c
    ld e, a
    ld a, a
    dec bc
    rlca
    ret nc

    dec c
    ld e, a
    ld a, a
    inc c
    rlca
    ret nc

    dec c
    ld e, a
    ld a, a
    dec c
    rlca
    ret nc

    dec c
    ld e, a
    ld a, a
    ld c, $07
    ret nc

    dec c
    ld e, a
    ld a, a
    rrca
    rlca
    ret nc

    dec c
    ld e, a
    ld a, a
    rrca
    ld b, $d0
    dec c
    ld e, a
    ld a, a
    ld c, $06
    ret nc

    dec c
    ld e, a
    ld a, a
    dec c
    ld b, $d0
    dec c
    ld e, a
    ld a, a
    inc c
    ld b, $fd
    dec c
    ld e, a
    ld a, a
    dec bc
    ld b, $d0
    dec c
    ld e, a
    ld a, a
    ld a, [bc]
    ld b, $d0
    dec c
    ld e, a
    ld a, a
    ld a, [bc]
    ld bc, $0dd0
    ld e, a
    ld a, a
    dec bc
    ld bc, $0dd0
    ld e, a
    ld a, a
    inc c
    ld bc, $0dd0
    ld e, a
    ld a, a
    dec c
    ld bc, $0dd0

jr_011_7c95:
    ld e, a
    ld a, a
    ld c, $01
    ret nc

    dec c
    ld e, a
    ld a, a
    rrca
    ld bc, $0dd0
    ld e, a
    ld a, a
    ld [$4500], sp
    dec e
    and h
    ld a, [hl]
    db $10
    ld bc, $1d45

jr_011_7cad:
    and h
    ld a, [hl]
    dec bc
    inc bc
    ld c, a
    dec e
    and h
    ld a, [hl]
    ld c, $03
    ld b, l
    dec e
    and h

jr_011_7cba:
    ld a, [hl]
    inc c
    inc b
    ld b, l
    dec e
    and h
    ld a, [hl]
    inc c
    add hl, bc
    ld c, a
    dec e
    and h
    ld a, [hl]
    rrca
    add hl, bc
    ld b, l
    dec e
    and h
    ld a, [hl]
    ld c, $10
    ld b, l
    dec e
    and h
    ld a, [hl]
    db $10

jr_011_7cd4:
    ld a, [bc]
    ld b, l
    dec e
    and h
    ld a, [hl]
    rlca
    dec bc
    ld h, e
    dec e
    and h
    ld a, [hl]
    ld [$9f0f], sp
    dec e
    and h
    ld a, [hl]
    rrca
    inc c
    ld b, l
    dec e
    and h
    ld a, [hl]
    rst $38
    inc bc
    dec c
    inc b
    jr jr_011_7cad

    ld a, a
    inc b
    nop
    ld [$9118], sp
    ld a, h
    rst $38
    inc bc
    dec c
    inc b
    jr jr_011_7cba

    ld a, a
    inc b
    nop
    inc b
    jr jr_011_7c95

    ld a, h

jr_011_7d05:
    rst $38
    rrca
    inc bc
    inc b
    jr jr_011_7d2c

    ld a, h
    rrca
    ld b, $04
    jr jr_011_7d32

    ld a, h
    rst $38
    dec c
    ld de, $1804
    ld hl, $077c
    rrca
    ld bc, $eb07
    ld a, d
    ld bc, $120a
    rlca
    db $eb
    ld a, d
    rlca

jr_011_7d26:
    add hl, bc
    inc de
    rlca
    db $eb
    ld a, d
    dec c

jr_011_7d2c:
    add hl, bc
    inc d
    rlca
    db $eb
    ld a, d
    dec c

jr_011_7d32:
    ld bc, $0705
    db $eb
    ld a, d
    rlca
    ld bc, $0716
    db $eb
    ld a, d
    rst $38
    inc b
    nop
    inc b
    jr jr_011_7cd4

    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7d05

    ld a, a
    rst $38
    rrca
    add hl, bc
    inc b
    jr jr_011_7d71

    ld a, h
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr @-$42

    ld a, a
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7d26

    ld a, a
    rst $38
    ld [de], a
    ld bc, $1d14
    ld a, b

jr_011_7d71:
    ld a, l
    ld a, [hl+]
    db $10
    dec bc
    dec e
    ld a, b
    ld a, l
    rst $38

jr_011_7d79:
    inc c
    ld [de], a
    ld a, [bc]
    dec e
    ld a, b
    ld a, l
    add hl, bc
    ld hl, $1d50
    ld a, b
    ld a, l
    rst $38
    dec c
    ld [$14ff], sp
    call z, $0d7f
    dec bc
    nop
    inc d
    call z, $ff7f
    inc bc
    ld h, $50
    dec e
    ld a, b
    ld a, l
    ld bc, $520a
    dec e
    ld a, b
    ld a, l
    rst $38
    rlca
    ld c, $50
    dec e
    ld a, b
    ld a, l
    rst $38
    dec b
    dec c
    nop

jr_011_7daa:
    rla
    rst $00
    ld a, l
    rlca
    dec c
    nop
    rla
    rst $00
    ld a, l
    add hl, bc
    dec c
    inc bc
    dec e
    ld a, b
    ld a, l
    rst $38
    ld b, $00
    ld [de], a
    dec e
    ld a, b
    ld a, l
    rst $38
    ld de, $1309
    dec e
    ld a, b
    ld a, l
    dec [hl]
    db $10
    ld d, c
    dec e
    ld a, b
    ld a, l
    rst $38
    rrca
    dec d
    ld c, a
    dec e
    ld a, b
    ld a, l
    rst $38
    ld de, $311b
    dec e
    ld a, b
    ld a, l
    rst $38
    ld bc, $1319
    dec e
    ld a, b
    ld a, l
    rst $38
    inc b
    nop
    inc b
    jr jr_011_7d79

    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7daa

    ld a, a
    rst $38
    inc c
    inc b
    ld d, d
    dec e
    ld a, b
    ld a, l
    rst $38
    ld c, $01
    ld c, a
    dec e
    ld a, b
    ld a, l
    dec c
    db $10
    daa
    dec e
    ld a, b
    ld a, l
    rst $38
    ld bc, $310a
    dec e
    ld a, b
    ld a, l
    rst $38
    dec b
    ld b, $35
    dec e
    ld a, b
    ld a, l
    rst $38
    inc bc
    dec bc
    ld d, d
    dec e
    ld a, b
    ld a, l
    rst $38
    rrca
    ld [bc], a
    ld de, $781d
    ld a, l
    rst $38
    ld b, $00
    ld sp, $781d
    ld a, l
    rst $38
    dec bc
    ld c, $28
    dec e
    ld a, b
    ld a, l
    rst $38
    inc bc
    dec de
    ld [bc], a
    dec e
    ld a, b
    ld a, l
    rst $38
    db $10
    ld de, $1d53
    ld a, b
    ld a, l
    ld bc, $4f0c
    dec e
    ld a, b
    ld a, l
    rst $38
    rrca
    rrca
    ld sp, $781d
    ld a, l
    rst $38
    ld de, $0219
    dec e
    ld a, b
    ld a, l
    rst $38
    db $10
    ld [$1d0a], sp
    ld a, b
    ld a, l
    dec b
    ld [bc], a
    inc b
    ld de, $4704
    rst $38
    dec bc
    ld [bc], a
    inc b
    inc d
    or a
    ld [hl], c
    rst $38
    add hl, bc
    ld bc, $1d36
    ld a, b
    ld a, l
    dec b
    ld a, [bc]
    inc b
    inc d
    ret nz

    ld [hl], h
    rst $38
    add hl, bc
    ld bc, $1d28
    ld a, b
    ld a, l
    inc bc
    inc d
    inc b
    inc d
    rlca
    ld [hl], a
    add hl, de
    ld [de], a
    inc b

jr_011_7e80:
    inc d
    rlca
    ld [hl], a
    rst $38
    inc l
    add hl, bc
    db $10
    dec e
    ld a, b
    ld a, l
    ld b, [hl]
    inc de
    ld [bc], a

jr_011_7e8d:
    dec e
    ld a, b
    ld a, l
    ld e, d
    ld [$1d51], sp
    ld a, b
    ld a, l
    rst $38
    ld [bc], a
    dec b
    ld [bc], a

jr_011_7e9a:
    dec e
    ld a, b
    ld a, l
    rlca
    ld a, [de]
    db $10
    dec e
    ld a, b
    ld a, l
    rst $38
    dec bc
    ld c, $53
    dec e
    ld a, b
    ld a, l
    rst $38
    inc b
    ld bc, $0704
    sub d
    ld a, l
    rst $38
    inc b
    ld c, $14
    dec e
    ld a, b
    ld a, l
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7e80

    ld a, a
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7e8d

    ld a, a
    rst $38
    inc b
    nop
    ld [$9118], sp
    ld a, h
    inc bc
    dec c
    inc b
    jr jr_011_7e9a

    ld a, a
    rst $38
    ld [bc], a
    ld bc, $1704
    inc c
    ld a, c
    rst $38

jr_011_7ee7:
    ld bc, $0000
    rlca
    ld l, e
    ld a, l
    ld bc, $0001
    rlca
    ld l, e
    ld a, l
    ld bc, $0007
    rlca
    ld l, e
    ld a, l
    rst $38
    nop
    inc bc
    inc [hl]
    rla
    ld [$0079], a
    inc b
    inc [hl]
    rla
    ld [$0479], a
    inc bc
    dec [hl]
    inc d
    db $76
    ld a, l
    rst $38
    add hl, bc
    inc bc
    inc b
    inc d
    or a
    ld a, a
    add hl, bc
    ld b, $04
    inc d
    or a
    ld a, a
    nop
    inc b
    inc b
    inc d
    sub l
    ld a, a
    nop
    dec b
    inc b
    inc d
    and l
    ld a, a
    rst $38

Jump_011_7f26:
    rlca
    rrca
    inc b
    jr jr_011_7ee7

    ld a, a
    rst $38

Jump_011_7f2d:
    inc b

jr_011_7f2e:
    nop
    inc b
    jr @-$42

    ld a, a

Call_011_7f33:
    inc b
    ld [bc], a
    inc b
    jr @-$42

    ld a, a
    rst $38
    nop
    ld bc, $07d0
    sbc b
    ld a, c
    ld bc, $d002
    rlca
    sbc b
    ld a, c
    ld [bc], a
    ld bc, $07d0
    sbc b
    ld a, c
    ld [bc], a
    inc bc

Jump_011_7f4e:
    ret nc

    rlca
    sbc b
    ld a, c
    inc b

Call_011_7f53:
    nop
    ret nc

    rlca

Call_011_7f56:
    sbc b
    ld a, c
    dec b
    ld bc, $07d0
    sbc b
    ld a, c
    rst $38
    dec b
    jr nc, jr_011_7f7f

    dec e
    ld a, b
    ld a, l
    rst $38
    ccf
    ld [bc], a
    ld [de], a
    dec e
    ld a, b
    ld a, l
    rst $38
    inc c
    ld a, [bc]
    inc b
    jr jr_011_7f2e

    ld a, a
    rst $38
    rrca
    rrca
    jr z, jr_011_7f95

    ld a, b
    ld a, l
    dec l
    ld [$1d10], sp
    ld a, b

jr_011_7f7f:
    ld a, l
    ld c, b
    ld de, $1d4f
    ld a, b
    ld a, l
    ld e, e
    inc b
    ld [hl], $1d
    ld a, b
    ld a, l
    ld a, c
    ld [$1d53], sp
    ld a, b
    ld a, l
    rst $38
    inc b
    inc bc

jr_011_7f95:
    db $10
    dec e
    ld a, b
    ld a, l
    ld [hl+], a
    inc b
    ld b, h
    dec e
    ld a, b
    ld a, l
    rst $38
    ld [bc], a
    inc c
    ld sp, $781d
    ld a, l
    dec b
    dec d
    ld d, d
    dec e
    ld a, b
    ld a, l
    rst $38
    rrca
    jr nc, jr_011_7fff

    dec e
    ld a, b

Call_011_7fb2:
Jump_011_7fb2:
    ld a, l
    rst $38
    db $10
    add hl, bc

Call_011_7fb6:
    ld d, e
    dec e
    ld a, b
    ld a, l
    rst $38
    dec bc
    ld c, $51
    dec e
    ld a, b

Jump_011_7fc0:
    ld a, l
    rst $38
    ld [$280f], sp
    dec e

Call_011_7fc6:
Jump_011_7fc6:
    ld a, b
    ld a, l
    rst $38

Jump_011_7fc9:
    inc bc

Call_011_7fca:
Jump_011_7fca:
    jr z, jr_011_7fcf

    dec e
    ld a, b
    ld a, l

jr_011_7fcf:
    rst $38
    ld bc, $3501

Jump_011_7fd3:
    inc bc

Jump_011_7fd4:
    ld [$1809], sp
    and c

Call_011_7fd8:
    ld c, c

Jump_011_7fd9:
    add d
    nop
    dec b
    ld bc, $3641
    jr nc, jr_011_7fe6

    inc bc
    ld [hl+], a
    pop bc
    add e
    add hl, bc

jr_011_7fe6:
    inc hl
    ld de, $0109
    add hl, bc
    inc c
    ld bc, $2143
    ld bc, $1381
    ld bc, $c181
    ld hl, $8d10
    sub e
    ld b, c
    ld h, b
    dec b
    inc c
    add hl, hl
    ld b, b

jr_011_7fff:
    ld [hl], c
