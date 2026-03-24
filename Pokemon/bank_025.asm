; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $025", ROMX[$4000], BANK[$25]

    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    call $cec1
    reti


    ld a, a
    call z, $c7d5
    rst $00
    pop bc
    rst $00
    push bc
    ld c, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    rst $10
    ret z

    ret


    call z, $81c5
    ld a, a
    xor c
    db $d3
    ld c, a
    ld a, a
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    pop bc
    adc $d9
    call nc, $c9c8
    adc $c7
    ld a, a
    call nc, $cf55
    ld a, a
    call nz, $8ccf
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    sbc a
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d97f
    rst $08
    push de
    add a
    call z, Call_025_7fcc
    ld d, l
    jp $c1c8


    call z, $c5cc
    adc $c7
    push bc
    ld a, a
    or h
    pop bc
    jp nc, $d5c2

    jp $55c8


    ret


    ld a, a
    adc [hl]
    ld a, a
    ret


    call nc, $d387
    ld a, a
    push bc
    pop bc
    jp nc, $c9cc

    push bc
    jp nc, $557f

    sub c
    sub b
    sub b
    sub b
    sub b
    ld a, a
    call z, $c7c9
    ret z

    call nc, $d97f
    push bc
    pop bc
    jp nc, Jump_025_55d3

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call nz, Call_025_7fcf
    rst $10
    push bc
    ld c, a
    call z, $81cc
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    rst $10
    rst $08
    jp nc, $c5d3

    ld a, a
    ld d, l
    call nc, $c1c8
    adc $7f
    xor l
    jp nc, $b47f

    pop bc
    jp nc, Jump_025_7fd8

    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    add c
    ld a, a
    sub c
    sub b
    sub b
    sub b
    sub b
    ld c, a
    ld a, a
    call z, $c7c9
    ret z

    call nc, $d97f
    push bc
    pop bc
    jp nc, Jump_025_7fd3

    ld d, [hl]
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $c97f
    adc $c4
    ret


    jp $c155


    call nc, Call_025_7fc5
    call nc, $cdc9
    push bc
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    ld d, l
    adc $c4
    ret


    jp $d4c1


    push bc
    db $d3
    ld a, a
    call nz, $d3c9
    call nc, $cec1
    jp Jump_025_55c5


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    add c
    ld a, a
    sub c
    sub b
    sub b
    sub b
    sub b
    ld c, a
    ld a, a
    call z, $c7c9
    ret z

    call nc, $d97f
    push bc
    pop bc
    jp nc, Jump_025_7fd3

    ld d, [hl]
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $c97f
    adc $c4
    ret


    jp $c155


    call nc, Call_025_7fc5
    call nc, $cdc9
    push bc
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    ld d, l
    adc $c4
    ret


    jp $d4c1


    push bc
    db $d3
    ld a, a
    call nz, $d3c9
    call nc, $cec1
    jp Jump_025_55c5


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    ret


    call nz, $d2c5
    call z, $cec1
    adc $8c
    ld a, a
    db $d3
    ret


    call nc, $c47f
    ld c, a
    rst $08
    rst $10
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    ret z

    rst $08
    call Call_025_7fc5
    ld d, h
    ld a, a
    call nz, $c5cf
    db $d3
    ld c, a
    adc $87
    call nc, $cd7f
    pop bc
    adc $c1
    rst $00
    push bc
    ld a, a
    rst $10
    push bc
    call z, Call_025_7fcc
    jp nz, $c555

    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    jp nz, $c9c5

    adc $c7
    ld a, a
    pop bc
    ld d, l
    ld a, a
    add $cf
    jp nc, $c9c5

    rst $00
    adc $7f
    adc [hl]
    ld a, a
    ld a, a
    db $d3
    rst $08
    adc l
    jp Jump_025_55c1


    call z, $c5cc
    call nz, $c67f
    rst $08
    jp nc, $c9c5

    rst $00
    adc $7f
    ret


    adc $c4
    ret


    ld d, l
    jp $d4c1


    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    push bc
    ret c

    ld d, l
    jp $c1c8


    adc $c7
    push bc
    call nz, $d77f
    ret


    call nc, Call_025_7fc8
    ld a, a
    rst $08
    add $7f
    ld d, l
    rst $08
    call nc, $c5c8
    jp nc, $8ed3

    ld a, a
    xor c
    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    add $cf
    ld d, l
    db $d3
    call nc, $d2c5
    push bc
    call nz, $d17f
    push de
    ret


    call nc, Call_025_7fc5
    pop de
    push de
    ret


    jp $cb55


    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $cc7f
    ret


    ld d, l
    db $d3
    call nc, $cec5
    ld a, a
    call nc, Call_025_7fcf
    rst $10
    ret z

    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld e, l
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    ld d, l
    pop bc
    ret


    call nz, $c27f
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ret z

    ret


    ld d, l
    db $d3
    ld a, a
    rst $10
    push bc
    pop bc
    res 0, c
    ld a, a
    xor c
    add $7f
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld d, l
    ld a, a
    pop bc
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $d47f

    ret z

    ld c, a
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_025_7fcc
    call nz, $d2d5
    ret


    adc $c7
    ld a, a
    add $cf
    ld d, l
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    ld d, h
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    pop bc
    jp nc, Jump_025_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    db $d3
    rst $08
    ld d, l
    call Call_025_7fc5
    db $d3
    set 1, c
    call z, $d3cc
    ld a, a
    push de
    adc $d4
    pop bc
    push de
    rst $00
    ret z

    ld d, l
    call nc, $8e7f
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    adc h
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $8c
    ld a, a
    jp nz, $d54f

    jp nc, Jump_025_7fce

    pop bc
    adc $c4
    ld a, a
    ret nc

    pop bc
    jp nc, $ccc1

    reti


    db $d3
    ret


    db $d3
    ld d, l
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cecf


    ld d, l
    db $d3
    call nc, $d4c9
    push de
    call nc, $cfc9
    adc $7f
    rst $08
    add $7f
    ld d, h
    ld a, a
    ld d, l
    ret


    db $d3
    adc $87
    call nc, $c77f
    rst $08
    rst $08
    call nz, $8c7f
    ld a, a
    ret


    call nc, $c37f
    ld d, l
    pop bc
    adc $7f
    push bc
    pop bc
    db $d3
    ret


    call z, Call_025_7fd9
    jp $d4c1


    jp Jump_025_7fc8


    adc [hl]
    ld d, l
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, [hl]
    ld a, a
    jp $d2c5


    call nc, $c9c1
    adc $cc
    reti


    ld d, l
    ld a, a
    jp $cec1


    ld a, a
    jp $d4c1


    jp Jump_025_7fc8


    adc h
    ld a, a
    jp $cec1


    add a
    ld d, l
    call nc, $c97f
    call nc, Call_025_7f9f
    ld d, a
    nop
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $819f
    ld a, a
    ld e, [hl]
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    call nz, $55cd
    ret


    jp nc, $cec9

    rst $00
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    ld d, l
    ld d, [hl]
    ld d, [hl]
    sbc a
    ld a, a
    ret z

    pop bc
    adc $c7
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld a, a
    and h
    ld d, l
    rst $08
    adc $87
    call nc, $c87f
    ret


    adc $c4
    push bc
    jp nc, $cd7f

    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push bc
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, Call_025_7f81
    ld a, a
    rst $08
    add $7f
    ld c, a
    jp $c9c8


    jp nz, $d4c1

    push bc
    jp nc, $d77f

    ret


    call z, Call_025_7fcc
    pop bc
    call nc, $55d4
    pop bc
    jp Jump_025_7fcb


    pop de
    push de
    ret


    jp $cccb


    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    pop bc
    ret z

    add c
    ld a, a
    ld a, a
    rst $00
    ret


    sub $c5
    db $d3
    ld a, a
    call Call_025_7fc5
    pop bc
    ld c, a
    ld a, a
    db $d3
    jp $d2c1


    push bc
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_025_7f9f
    ld d, l
    xor c
    db $d3
    adc $87
    call nc, $c87f
    push bc
    ld a, a
    pop bc
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld d, l
    ld a, a
    jp nz, $d9cf

    adc h
    ld a, a
    ret


    db $d3
    ld a, a
    ret z

    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    ld a, a
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld c, a
    ld a, a
    jp $cec1


    add a
    call nc, $cc7f
    rst $08
    pop bc
    add $7f
    pop bc
    jp nz, $d5cf

    call nc, Call_025_7f55
    ret


    adc $7f
    call nc, $c9c8
    db $d3
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $00
    jp nc, $c1c5

    call nc, $d9cc
    ld a, a
    db $d3
    push de
    jp nc, $d2d0

    ret


    db $d3
    push bc
    ld c, a
    call nz, Call_025_7f81
    ld e, b
    nop
    ld a, a
    rst $00
    jp nc, $c1c5

    call nc, $d9cc
    ld a, a
    db $d3
    push de
    jp nc, $d2d0

    ret


    db $d3
    push bc
    ld c, a
    call nz, Call_025_7f81
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    adc h
    ld a, a
    pop bc
    ld c, a
    jp nc, $cec5

    add a
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    call nc, Call_025_7fcf
    push bc
    ret c

    ret nc

    ld d, l
    call z, $d2cf
    push bc
    ld a, a
    jp $d6c1


    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_025_7fc5

    call nc, Call_025_7fcf
    db $d3
    ld c, a
    push bc
    call z, $c5cc
    jp Jump_025_7fd4


    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d07f
    call z, Call_025_55c1
    jp Jump_025_7fc5


    ld a, a
    add $cf
    jp nc, $c77f

    ret


    jp nc, $d3cc

    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and [hl]
    ret


    adc $c1
    call z, $d9cc
    ld a, a
    call z, $d3cf
    call nc, Call_025_4f7f
    adc h
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call z, $d3cf
    ret


    adc $c7
    ld a, a
    add $55
    pop bc
    jp $58c5


    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and [hl]
    ret


    adc $c1
    call z, $d9cc
    ld a, a
    call z, $d3cf
    call nc, Call_025_4f7f
    adc h
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call z, $d3cf
    ret


    adc $c7
    ld a, a
    add $55
    pop bc
    jp $58c5


    nop
    ld a, a
    or a
    pop bc
    ret z

    add c
    ld a, a
    xor c
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $d6c1


    push bc
    ld c, a
    ld a, a
    adc h
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    db $d3
    ret nc

    pop bc
    jp Jump_025_55c9


    rst $08
    push de
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nc, $cfcf
    ld a, a
    db $d3
    ret nc

    pop bc
    jp $cfc9


    push de
    ld c, a
    db $d3
    ld a, a
    call nc, Call_025_7fcf
    add $c9
    adc $c4
    ld a, a
    pop bc
    adc $7f
    push bc
    adc $d4
    jp nc, $c155

    adc $c3
    push bc
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld d, [hl]
    adc h
    ld a, a
    call z, $d3cf
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld d, [hl]
    adc h
    ld a, a
    call z, $d3cf
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    or a
    pop bc
    ret z

    rst $08
    rst $08
    add c
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_025_7f9f
    and h
    rst $08
    adc $4f
    add a
    call nc, $d37f
    ret z

    rst $08
    push de
    call nc, $d37f
    push de
    call nz, $c5c4
    adc $cc
    reti


    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_025_567f
    add c
    ld a, a
    and c
    adc $d9
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, $c54f

    ld a, a
    push bc
    call z, $c5d3
    ld a, a
    pop bc
    jp nc, $cec5

    add a
    call nc, $d47f
    ret z

    push bc
    ld d, l
    jp nc, Jump_025_7fc5

    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld d, h
    sbc a
    ld a, a
    ld d, a
    nop
    ld d, [hl]
    ld c, a
    ret


    db $d3
    adc $87
    call nc, $c97f
    call nc, $d37f
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $557f
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    push de
    jp Jump_025_7fc8


    ld d, h
    sbc a
    ld a, a
    ld e, b
    nop
    ld d, [hl]
    ld c, a
    ret


    db $d3
    adc $87
    call nc, $c97f
    call nc, $d37f
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $557f
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    push de
    jp Jump_025_7fc8


    ld d, h
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $819f
    ld a, a
    and [hl]
    jp nc, $c5c9

    adc $c4
    db $d3
    ld a, a
    ld a, a
    ld c, a
    call $d3c9
    db $d3
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    ld d, l
    reti


    ld a, a
    ret


    adc $7f
    jp $d6c1


    push bc
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    rst $10
    pop bc
    ret


    ld d, l
    call nc, $cec9
    rst $00
    ld a, a
    ret z

    push bc
    jp nc, $8cc5

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_025_7fc5

    pop bc
    jp nc, Jump_025_7fc5

    sub $c1
    call z, $c1d5
    jp nz, $cc4f

    push bc
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_025_7fd3
    ld a, a
    ret


    adc $7f
    call nc, $55c8
    ret


    db $d3
    ld a, a
    jp $d6c1


    push bc
    ld a, a
    adc [hl]
    ld a, a
    xor c
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ld d, l
    pop bc
    db $d3
    ld a, a
    db $d3
    rst $08
    rst $08
    adc $7f
    pop bc
    db $d3
    ld a, a
    xor c
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $c455

    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    call z, $d3cf
    call nc, Call_025_7f9f
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    call z, $d3cf
    call nc, Call_025_7f9f
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_025_7fc5

    pop bc
    jp nc, Jump_025_7fc5

    db $d3
    push de
    db $d3
    ret nc

    push bc
    jp $d44f


    ld a, a
    call $cec5
    ld a, a
    db $d3
    pop bc
    push de
    adc $d4
    push bc
    jp nc, $c4c5

    ld a, a
    call nc, $cf55
    ld a, a
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    jp $d6c1


    push bc
    adc [hl]
    ld a, a
    and c
    jp nc, Jump_025_7fc5

    reti


    rst $08
    push de
    ld a, a
    ld d, l
    ld d, [hl]
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    ld c, a
    call nc, $c1c8
    call nc, $a97f
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    push bc
    push bc
    adc $81
    ld d, l
    ld a, a
    or h
    ret z

    push bc
    jp nc, $87c5

    db $d3
    ld a, a
    adc $cf
    ld a, a
    call nz, $d5cf
    jp nz, $55d4

    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $c97f
    call nc, Call_025_7f81
    adc h
    ld a, a
    call nc, $c1c8
    call nc, Call_025_7f55
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    ld e, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    add $c1
    call z, $c5cc
    adc $7f
    pop bc
    ld a, a
    ld c, a
    ret nc

    jp nc, $d9c5

    ld a, a
    call nc, Call_025_7fcf
    pop bc
    ld a, a
    ret nc

    call z, $d4cf
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    add $c1
    call z, $c5cc
    adc $7f
    pop bc
    ld a, a
    ld c, a
    ret nc

    jp nc, $d9c5

    ld a, a
    call nc, Call_025_7fcf
    pop bc
    ld a, a
    ret nc

    call z, $d4cf
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $d07f
    pop bc
    db $d3
    db $d3
    ld a, a
    call nc, Call_025_4fc8
    jp nc, $d5cf

    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d6c1


    push bc
    ld a, a
    rst $10
    ret z

    ld d, l
    push bc
    adc $7f
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $d555
    push bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    ret z

    ret


    jp nz, $d4c1

    push bc
    jp nc, $c97f

    db $d3
    ld a, a
    pop bc
    rst $10
    add $d5
    ld c, a
    call z, $d9cc
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ret


    jp Jump_025_7f81


    jp nz, $d4d5

    ld d, l
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    call nz, $d0c5
    push bc
    adc $c4
    push bc
    adc $55
    call nc, Call_025_547f
    ld a, a
    ret


    add $7f
    jp nz, $c9c5

    adc $c7
    ld a, a
    jp Jump_025_55c1


    push de
    rst $00
    ret z

    call nc, Call_025_7f7f
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    xor c
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    call z, $d3cf
    call nc, Call_025_4f81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    xor c
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    call z, $d3cf
    call nc, Call_025_4f81
    ld a, a
    ld e, b
    nop
    ld a, a
    call nc, $c5c8
    adc $7f
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    call $cec9
    push bc
    ld c, a
    add c
    ld a, a
    ld d, b
    ld de, $0050
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_025_7fc5

    ret z

    pop bc
    sub $c5
    ld a, a
    add $cf
    push de
    adc $c4
    ld c, a
    ld a, a
    ld e, [hl]
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    add $55
    rst $08
    db $d3
    db $d3
    ret


    call z, $817f
    ld a, a
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld d, l
    ld a, a
    call $cbc1
    push bc
    ld a, a
    call $c3d5
    ret z

    ld a, a
    call $cecf
    push bc
    reti


    ld a, a
    ld d, l
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c5
    ld a, a
    ret z

    ret


    call $d27f
    push bc
    ld d, l
    sub $c9
    sub $c5
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $cd7f
    pop bc
    set 0, l
    db $d3
    ld a, a
    call Call_025_7fc5
    pop bc
    adc $4f
    rst $00
    jp nc, Jump_025_7fd9

    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c1c8
    call nc, $d97f
    rst $08
    push de
    add a
    ld d, l
    call z, Call_025_7fcc
    jp nz, Jump_025_7fc5

    jp nc, $c3c5

    rst $08
    jp nc, $c5c4

    call nz, $cf7f
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c1cc

    jp $cccb


    ret


    db $d3
    call nc, $cf7f
    add $55
    ld a, a
    ld e, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_025_7f8c
    xor c
    add a
    call $c17f
    adc $c7
    jp nc, $81d9

    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_025_7f8c
    xor c
    add a
    call $c17f
    adc $c7
    jp nc, $81d9

    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    xor l
    pop bc
    add $c9
    pop bc
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ld c, a
    ret


    jp $c17f


    adc $c4
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld d, l
    ld e, [hl]
    ld a, a
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    xor l
    reti


    ld a, a
    jp $cccf


    call z, $c1c5
    ld c, a
    rst $00
    push de
    push bc
    db $d3
    ld a, a
    rst $10
    ret


    call z, Call_025_7fcc
    adc $c5
    sub $c5
    jp nc, $c27f

    ld d, l
    push bc
    ld a, a
    db $d3
    ret


    call z, $cec5
    call nc, Call_025_7f8c
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    or a
    push bc
    ld a, a
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    call nz, $c9cf
    adc $c7
    ld a, a
    ret


    call $d04f
    rst $08
    jp nc, $c1d4

    adc $d4
    ld a, a
    rst $10
    rst $08
    jp nc, $81cb

    ld a, a
    xor h
    ret


    call nc, $d455
    call z, Call_025_7fc5
    jp nz, $d9cf

    push bc
    db $d3
    ld a, a
    rst $00
    rst $08
    ld a, a
    ret z

    rst $08
    call Call_025_55c5
    ld a, a
    pop de
    push de
    ret


    jp $cccb


    reti


    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    call nc, $ccc5
    call z, $cd7f
    push bc
    ld a, a
    call nc, $c5c8
    ld c, a
    ld a, a
    ret nc

    rst $08
    db $d3
    ret


    call nc, $cfc9
    adc $7f
    pop bc
    adc $c4
    ld a, a
    rst $00
    rst $08
    ld a, a
    ld d, l
    jp nz, $c3c1

    bit 7, a
    pop de
    push de
    ret


    jp $cccb


    reti


    ld a, a
    ret


    add $7f
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    add $c9
    adc $c4
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, $817f
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call nz, Call_025_7fcf
    rst $10
    push bc
    call z, $81cc
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call nz, Call_025_7fcf
    rst $10
    push bc
    call z, $81cc
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, Jump_025_4fcf

    push de
    db $d3
    ld a, a
    add $cf
    jp nc, $c37f

    ret z

    ret


    call z, $d2c4
    push bc
    adc $7f
    call nc, $cf55
    ld a, a
    jp nc, $ced5

    ld a, a
    ret


    adc $7f
    pop bc
    call z, Call_025_7fcc
    call nz, $d2c9
    push bc
    ld d, l
    jp $c9d4


    rst $08
    adc $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    call nz, $55d5
    call z, Call_025_7fd4
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_025_7fc5

    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_025_7fd3

    ld c, a
    ld d, h
    ld a, a
    call z, $d6c9
    ret


    adc $c7
    ld a, a
    ret z

    push bc
    jp nc, Jump_025_7fc5

    adc $55
    push bc
    pop bc
    jp nc, $d9c2

    ld a, a
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_025_7fc5

    ret z

    push de
    call $c155
    adc $7f
    push bc
    ret c

    ret


    db $d3
    call nc, $c4c5
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    adc $c7
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    adc $c7
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, [hl]
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor b
    push bc
    add a
    call z, $cc4f
    ld a, a
    jp $d2c5


    call nc, $c9c1
    adc $cc
    reti


    ld a, a
    ld a, a
    ld a, a
    call nc, $c9c8
    ld d, l
    adc $cb
    ld a, a
    rst $08
    push de
    call nc, $d37f
    rst $08
    call Call_025_7fc5
    push bc
    sub $c9
    call z, $557f
    ret


    call nz, $c1c5
    db $d3
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c5
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    call nz, $c7c9
    ld a, a
    ret z

    rst $08
    call z, Call_025_7fc5
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_025_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret z

    rst $08
    call z, Call_025_7fc5
    ld c, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call z, $81cc
    ld a, a
    or a
    push bc
    ld a, a
    jp $c155


    adc $7f
    rst $00
    rst $08
    ld a, a
    rst $08
    push de
    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    ret z

    push bc
    ld d, l
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    ld a, a
    ret


    adc $7f
    call $d94f
    ld a, a
    add $c1
    call $ccc9
    reti


    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    adc $c4
    ld a, a
    ld d, l
    rst $08
    add $7f
    push bc
    ret c

    jp $c1c8


    adc $c7
    ret


    adc $c7
    ld a, a
    ld d, l
    ld d, h
    adc [hl]
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    ld a, a
    adc h
    ld d, l
    ld a, a
    jp $cec1


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    call Call_025_7fc5
    ld d, l
    reti


    rst $08
    push de
    jp nc, Jump_025_7fd3

    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    ld d, l
    jp $cccf


    call z, $c3c5
    call nc, $cec9
    rst $00
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $d255
    pop bc
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    rst $08
    add $55
    ld a, a
    ld d, h
    adc h
    ld a, a
    xor c
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld a, a
    ld d, l
    ret


    call nc, $d77f
    ret


    call nc, Call_025_57c8
    nop
    ld a, a
    xor l
    pop bc
    jp nc, $c1d3

    jp $c9c8


    add c
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld c, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    pop bc
    call nc, $c87f
    push bc
    ld a, a
    adc $c5
    sub $c5
    ld d, l
    jp nc, $cd7f

    ret


    adc $c4
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, $c87f

    ld d, l
    push bc
    ld a, a
    call nz, $c5cf
    db $d3
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    add $cf
    jp nc, $d47f

    ld d, l
    ret z

    push bc
    ld a, a
    ret nc

    push de
    jp nc, $cfd0

    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    rst $00
    push bc
    call nc, $d455
    ret


    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret nc

    jp nc, $c3c5

    ld d, l
    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld d, h
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_025_7fc4

    db $d3
    ld c, a
    rst $08
    call Call_025_7fc5
    jp nc, $cdd5

    rst $08
    push de
    jp nc, $c17f

    jp nz, $d5cf

    call nc, $557f
    xor l
    pop bc
    jp nc, $c1d3

    jp $c9c8


    ld a, a
    sbc a
    ld a, a
    or a
    push bc
    ld a, a
    pop bc
    call z, Call_025_55cc
    ld a, a
    jp $ccc1


    call z, $c87f
    ret


    call $c67f
    pop bc
    adc $c1
    call nc, $c3c9
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    jp nz, $d4d5

    adc h
    ld a, a
    or a
    ret z

    rst $08
    ld d, l
    push bc
    sub $c5
    jp nc, $c87f

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    call $cfcf
    call nz, Call_025_7f7f
    ld d, l
    call nc, Call_025_7fcf
    call $cbc1
    push bc
    ld a, a
    pop bc
    ld a, a
    call nz, $d3c9
    ret nc

    call z, $d9c1
    ld d, l
    ld a, a
    rst $08
    add $7f
    jp $cccf


    call z, $c3c5
    call nc, $cfc9
    adc $d3
    ld a, a
    add c
    ld d, l
    ld a, a
    and l
    sub $c5
    jp nc, $cfd9

    adc $c5
    ld a, a
    push bc
    adc $d6
    ret


    push bc
    db $d3
    ld a, a
    ld d, l
    ret z

    ret


    call $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    call z, $c54f
    sub $c5
    call z, $cf7f
    adc $cc
    reti


    ld a, a
    jp nc, $c1c5

    jp $c5c8


    call nz, Call_025_7f55
    call nc, Call_025_7fcf
    sub e
    sub b
    ld a, a
    rst $10
    ret


    call z, Call_025_7fcc
    rst $00
    push bc
    call nc, $d77f
    ld d, l
    push bc
    call z, $8dcc
    jp nz, $c8c5

    pop bc
    sub $c5
    call nz, $c17f
    adc $c4
    ld a, a
    rst $08
    ld d, l
    jp nz, $c4c5

    ret


    push bc
    adc $d4
    ld a, a
    ret


    add $7f
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld d, l
    ld a, a
    pop bc
    ld a, a
    jp nz, $d5cc

    push bc
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    add c
    ld a, a
    and c
    ld d, l
    adc $c4
    ld a, a
    add $cf
    jp nc, $c57f

    ret c

    pop bc
    call $ccd0
    push bc
    ld a, a
    adc h
    ld a, a
    ld d, l
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    jp nz, $cfd2

    push de
    rst $00
    ret z

    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    rst $08
    call nc, $55c8
    push bc
    jp nc, Jump_025_7fd3

    pop bc
    adc $c4
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $c87f
    ld d, l
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, $d77f
    ret


    call nc, $c855
    ld a, a
    adc h
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    jp $cec1


    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld d, l
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    jp nz, Jump_025_7fd9

    jp $d4d5


    call nc, Call_025_55c9
    adc $c7
    ld a, a
    rst $08
    add $c6
    ld a, a
    db $d3
    call z, $cec5
    call nz, $d2c5
    ld a, a
    call nc, Call_025_55d2
    push bc
    push bc
    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $cdc5

    ld d, l
    pop bc
    ret


    adc $c4
    push bc
    jp nc, $c97f

    db $d3
    ld a, a
    call $cec9
    push bc
    adc [hl]
    ld a, a
    or h
    ld d, l
    pop bc
    set 0, l
    ld a, a
    ld d, l
    ld e, h
    ld a, a
    pop bc
    db $d3
    ld a, a
    ld d, l
    pop bc
    adc $7f
    ret z

    rst $08
    adc $cf
    push de
    jp nc, Jump_025_7f81

    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    ld c, a
    sub $c5
    call nz, $557f
    ld e, h
    sub c
    sub c
    add $d2
    ld d, l
    rst $08
    call $a37f
    pop bc
    jp nc, $cdd3

    reti


    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    call $c3d5
    ret z

    ld a, a
    call z, $c7d5
    rst $00
    pop bc
    rst $00
    push bc
    ld c, a
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d77f

    rst $08
    jp nc, $d3c4

    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    push bc
    ld c, a
    adc $cf
    push de
    rst $00
    ret z

    add c
    ld a, a
    and h
    rst $08
    push bc
    db $d3
    adc $87
    call nc, $ce7f
    push bc
    ld d, l
    push bc
    call nz, $a37f
    pop bc
    jp nc, $cdd3

    reti


    ld a, a
    call nc, Call_025_7fcf
    push bc
    adc $d4
    push bc
    ld d, l
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    pop bc
    jp nc, $cec5

Call_025_4f7f:
Jump_025_4f7f:
    pop bc
    adc [hl]

Call_025_4f81:
    ld a, a
    ld d, a
    nop
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $c87f
    pop bc
    sub $c5
    ld c, a
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    rst $10
    ret


    ld d, l
    call nc, Call_025_7fc8
    sub $c1
    jp nc, $cfc9

    push de
    db $d3
    ld a, a
    ld d, l
    ld e, [hl]
    ld a, a
    ld e, l
    ld a, a
    adc h
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


Jump_025_4fc2:
    add a
    call nc, $d57f
    adc $c4

Call_025_4fc8:
    push bc

Call_025_4fc9:
    jp nc, Jump_025_55d3

Call_025_4fcc:
    call nc, $cec1

Call_025_4fcf:
Jump_025_4fcf:
    call nz, $c87f
    rst $08
    rst $10

Call_025_4fd4:
    ld a, a
    rst $10
    push bc
    call z, Call_025_7fcc
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    pop bc
    jp nc, $8ec5

    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call $d3c5
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call $d3c5
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    ld c, a
    rst $08
    adc $7f
    ret


    adc $7f
    call nc, $d2d5
    adc $81
    ld a, a
    add $c9
    jp nc, $d4d3

    ld d, l
    adc h
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, $cdc9
    push bc
    add c
    ld a, a
    ld a, a
    jp $cf55


    call Call_025_7fc5
    rst $08
    adc $8c
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and [hl]
    jp nc, $cdcf

    ld a, a
    adc $cf
    rst $10
    ld a, a
    and e
    pop bc
    jp nc, $cdd3

    reti


    ld a, a
    ld c, a
    rst $10
    ret


    call z, Call_025_7fcc
    jp nz, $c3c5

    rst $08
    call Call_025_7fc5
    pop bc
    ld a, a
    db $d3
    call nc, Call_025_55d2
    rst $08
    adc $c7
    ld a, a
    ld e, l
    ld a, a
    ret


    adc $c3
    push bc
    db $d3
    ld d, l
    db $d3
    pop bc
    adc $d4
    call z, $81d9
    ld a, a
    and e
    pop bc
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    ld d, l
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    jp nz, Jump_025_7fd9

    db $d3
    push de
    jp Jump_025_7fc8


    ld d, l
    call $cec5
    ld a, a
    pop bc
    db $d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, $cec4
    add a
    call nc, $c27f
    push bc
    ld a, a
    ld c, a
    db $d3
    rst $08
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, $cec4
    add a
    call nc, $c27f
    push bc
    ld a, a
    ld c, a
    db $d3
    rst $08
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    adc $d3
    call nc, $ccc1
    call z, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $ccc1

    call z, Call_025_7f4f
    call nc, Call_025_7fcf
    call nc, $c5c8
    ld a, a
    jp $cecf


    sub $c5
    rst $00
    push bc
    jp nc, $557f

    jp nz, $ccc5

    call nc, $8e7f
    ld a, a
    sub c
    adc h
    sub d
    adc h
    sub e
    adc h
    sub h
    adc h
    sub l
    adc h
    ld d, l
    sub [hl]
    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor b
    add a
    call Call_025_7f8c
    ld d, h
    adc h
    ld a, a
    ld d, l
    rst $10
    ret z

    rst $08
    ld a, a
    jp $cec1


    ld a, a
    jp nz, $cfd2

    push de
    rst $00
    ret z

    call nc, $557f
    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    jp $cec1


    ld a, a
    jp nc, $c1c5

    jp Jump_025_7fc8


    call nc, Call_025_55cf
    ld a, a
    sub [hl]
    ret nc

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    ld a, a
    rst $08
    add $4f
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, l
    pop bc
    call nc, $c1d4
    jp $c5cb


    call nz, Call_025_7f9f
    xor c
    call nc, $d387
    ld a, a
    ret


    call $d055
    rst $08
    db $d3
    db $d3
    ret


    jp nz, $c5cc

    ld a, a
    adc $cf
    call nc, $d47f
    rst $08
    ld a, a
    jp $c155


    jp nc, $d9d2

    ld a, a
    pop bc
    ld a, a
    add $c5
    rst $10
    ld a, a
    pop bc
    jp nc, $c9d4

    jp Jump_025_55cc


    push bc
    db $d3
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $d47f
    ret z

    push bc
    ld a, a
    push bc
    sub $c5
    adc $55
    call nc, Call_025_7f7f
    rst $08
    add $7f
    ld e, [hl]
    ld a, a
    rst $08
    adc $7f
    ld d, l
    call nc, $c5c8
    ld a, a
    adc $c5
    rst $10
    db $d3
    ret nc

    pop bc
    ret nc

    push bc
    jp nc, Jump_025_7f8c

    ld d, a
    nop
    ld a, a
    ld e, [hl]
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor b
    push bc
    add a
    call z, $cc4f
    ld a, a
    jp $d2c5


    call nc, $c9c1
    adc $cc
    reti


    ld a, a
    ld a, a
    ld a, a
    call nc, $c9c8
    ld d, l
    adc $cb
    ld a, a
    rst $08
    push de
    call nc, $d37f
    rst $08
    call Call_025_7fc5
    push bc
    sub $c9
    call z, $557f
    ret


    call nz, $c1c5
    db $d3
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c5
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    call nz, $c7c9
    ld a, a
    ret z

    rst $08
    call z, Call_025_7fc5
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret z

    rst $08
    call z, Call_025_7fc5
    ld c, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call z, $81cc
    ld a, a
    add $d2
    rst $08
    call Call_025_7f55
    ret z

    push bc
    jp nc, Jump_025_7fc5

    rst $10
    push bc
    ld a, a
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, $c855
    jp nc, $d5cf

    rst $00
    ret z

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    ret z

    pop bc
    jp nc, Jump_025_7fc4

    rst $10
    rst $08
    jp nc, $c9cb

    ld c, a
    adc $c7
    ld a, a
    rst $00
    push de
    pop bc
    jp nc, Jump_025_7fc4

    adc [hl]
    ld a, a
    xor l
    reti


    ld a, a
    sub $cf
    ret


    ld d, l
    jp Jump_025_7fc5


    ret


    db $d3
    ld a, a
    call z, $d3cf
    call nc, Call_025_7f81
    xor b
    ret


    adc h
    ld a, a
    call nc, $c855
    push bc
    jp nc, $81c5

    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ret


    adc $c7
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    jp nc, $c9c2

    call nz, $c5c4
    adc $8e
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nc, $c1c8
    call nc, $8c7f
    ld a, a
    call z, $cfcf
    set 2, e
    ld c, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    pop de
    push de
    ret


    call nc, Call_025_7fc5
    rst $00
    rst $08
    rst $08
    ld d, l
    call nz, $c47f
    jp nc, $cec9

    bit 7, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    or a
    ret z

    reti


    sbc a
    ld d, l
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    call $9fc5
    ld a, a
    call nc, $c1c8
    adc $cb
    db $d3
    add c
    ld d, l
    ld a, a
    ld d, b
    ld de, $d5a2
    jp nz, $ccc2

    ret


    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    jp nz, $c2d5

    jp nz, $cc55

    ret


    adc $c7
    ld a, a
    ld d, [hl]
    or a
    push bc
    ld a, a
    jp $cec1


    ld a, a
    ret nc

    pop bc
    db $d3
    ld d, l
    db $d3
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    ld a, a
    ret


    add $7f
    rst $10
    push bc
    ld a, a
    ld d, l
    rst $00
    rst $08
    ld a, a
    call nc, Call_025_7fcf
    set 0, l
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $d4c9


    reti


    ld d, l
    ld a, a
    ld d, [hl]
    and a
    ret


    sub $c5
    ld a, a
    db $d3
    rst $08
    call Call_025_7fc5
    db $d3
    rst $08
    add $d4
    ld d, l
    ld a, a
    call nz, $c9d2
    adc $cb
    ld a, a
    ld a, a
    call nc, Call_025_7fcf
    call nc, $c5c8
    ld a, a
    rst $00
    push de
    ld d, l
    pop bc
    jp nc, Jump_025_7fc4

    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    db $d3
    ld d, l
    ret


    call nc, Call_025_7fc5
    rst $00
    pop bc
    call nc, Call_025_7fc5
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    pop bc
    call nc, Call_025_7f4f
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    pop bc
    jp nc, Jump_025_7fc5

    call $cec1
    reti


    ld a, a
    call nc, $c855
    ret


    adc $c7
    ld a, a
    call z, $d3cf
    call nc, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    call nz, $d2c1
    bit 7, a
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d2c7

    pop bc
    adc $c4
    ld a, a
    ld d, l
    call nc, $ced5
    adc $c5
    call z, Call_025_7f8e
    ld d, a
    nop
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    pop bc
    call nc, Call_025_7f4f
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    pop bc
    jp nc, Jump_025_7fc5

    call $cec1
    reti


    ld a, a
    call nc, $c855
    ret


    adc $c7
    ld a, a
    call z, $d3cf
    call nc, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    call nz, $d2c1
    bit 7, a
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d2c7

    pop bc
    adc $c4
    ld a, a
    ld d, l
    call nc, $ced5
    adc $c5
    call z, Call_025_7f8e
    ld d, a
    nop
    ld a, a
    or d
    push bc
    jp $cec5


    call nc, $d9cc
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    ld c, a
    pop bc
    ret


    call nz, $d47f
    ret z

    push bc
    jp nc, Jump_025_7fc5

    pop bc
    ret nc

    push bc
    pop bc
    jp nc, Jump_025_7fd3

    ld d, l
    db $d3
    rst $08
    call Call_025_7fc5
    call nz, $dac1
    jp c, Jump_025_7fd9

    ld d, h
    ld a, a
    ld a, a
    ret


    ld d, l
    adc $7f
    set 0, l
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    rst $10

Call_025_547f:
Jump_025_547f:
    pop bc
    adc $d4
    ld a, a
    call nc, Call_025_7fcf
    rst $00
    rst $08
    ld a, a
    db $d3
    ret z

    rst $08
    ld c, a
    ret nc

    ret nc

    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $55
    rst $00
    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ld d, l
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    pop bc
    jp nc, Jump_025_7fc5

    call $cec1
    reti


    ld a, a
    ret nc

    push bc
    ld d, l
    jp nc, $cfd3

    adc $7f
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    jp nz, $c4c1

    ld a, a
    jp $cf55


    adc $c4
    push de
    jp Jump_025_7fd4


    adc h
    ld a, a
    call $cbc1
    ret


    adc $c7
    ld a, a
    call $c555
    ld a, a
    add $c5
    push bc
    call z, $d47f
    push bc
    jp nc, $c9d2

    add $c9
    jp Jump_025_7f8e


    ld d, l
    ld d, a
    nop
    ld a, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    rst $08
    ld a, a
    db $d3
    ret z

    rst $08
    ld c, a
    ret nc

    ret nc

    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $55
    rst $00
    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc h
    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    ld d, l
    add $7f
    call nc, $c5c8
    ld a, a
    rst $00
    pop bc
    call nc, Call_025_7fc5
    adc h
    ld a, a
    ret


    call nc, $c97f
    ld d, l
    db $d3
    ld a, a
    adc $c5
    pop bc
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    rst $10
    push bc
    db $d3
    call nc, $d2c5
    ld d, l
    adc $7f
    call nc, $d7cf
    adc $8e
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $08
    add $d4
    push bc
    adc $7f
    rst $00
    rst $08
    ld a, a
    ld c, a
    call nc, $c5c8
    jp nc, $9fc5

    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $cecf


    sub $c5
    adc $55
    ret


    push bc
    adc $d4
    ld a, a
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    db $d3
    push bc
    call z, $c9cc
    adc $55
    rst $00
    ld a, a
    sub $c1
    jp nc, $cfc9

    push de
    db $d3
    ld a, a
    jp $cdcf


    call $c4cf
    ret


    ld d, l
    call nc, $c5c9
    db $d3
    ld a, a
    ret


    adc $7f
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld d, l
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    adc [hl]
    ld a, a
    ld d, a

Call_025_55c1:
Jump_025_55c1:
    nop

Jump_025_55c2:
    ld a, a
    ld d, h

Jump_025_55c4:
    ld a, a

Call_025_55c5:
Jump_025_55c5:
    and c
    jp $cfc3


Call_025_55c9:
Jump_025_55c9:
    jp nc, $c9c4

Call_025_55cc:
Jump_025_55cc:
    adc $c7
    ld a, a

Call_025_55cf:
Jump_025_55cf:
    call nc, Call_025_4fcf

Call_025_55d2:
Jump_025_55d2:
    ld a, a

Call_025_55d3:
Jump_025_55d3:
    call nz, $c6c9
    add $c5
    jp nc, $cec5

    call nc, $d47f
    reti


    ret nc

    push bc
    db $d3
    ld a, a
    ld d, l
    rst $08
    add $7f
    adc h
    ld a, a
    rst $10
    push bc
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    ld d, l
    adc $c5
    adc $d4
    db $d3
    ld a, a
    jp nz, $d4cf

    ret z

    ld a, a
    push bc
    pop bc
    db $d3
    reti


    ld a, a
    pop bc
    ld d, l
    adc $c4
    ld a, a
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, $d47f
    rst $08
    ld a, a
    call nz, $c555
    pop bc
    call z, $d77f
    ret


    call nc, Call_025_7fc8
    ret


    adc $7f
    jp $cecf


    call nc, Call_025_55c5
    db $d3
    call nc, Call_025_577f
    adc [hl]
    ld a, a
    nop
    ld a, a
    and d
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ret z

    pop bc
    sub $c9
    adc $4f
    rst $00
    ld a, a
    adc $cf
    ld a, a
    jp $c1c8


    adc $c3
    push bc
    ld a, a
    call nc, Call_025_7fcf
    push de
    db $d3
    ld d, l
    push bc
    ld a, a
    ret


    call nc, Call_025_7f8c
    rst $10
    push bc
    ld a, a
    db $d3
    push bc
    call z, Call_025_7fcc
    call nc, $c5c8
    ld d, l
    ld a, a
    rst $00
    rst $08
    call z, $c5c4
    adc $7f
    jp nz, $ccc1

    call z, Call_025_7f7f
    add h
    sub l
    sub b
    ld d, l
    sub b
    sub b
    add c
    ld a, a

Call_025_567f:
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_025_7fc5

    ret


    db $d3
    ld a, a
    jp nc, $c3cf

    bit 7, a
    call $d5cf
    ld c, a
    adc $d4
    pop bc
    ret


    adc $7f
    call nc, $ced5
    adc $c5
    call z, $cc7f
    ret


    rst $00
    ret z

    ld d, l
    call nc, $c27f
    call z, $c5d5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    pop bc
    ld d, l
    db $d3
    call nc, $d2c5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_025_7fcf
    ret nc

    ld c, a
    pop bc
    db $d3
    db $d3
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, l
    call z, $cecf
    rst $00
    ld a, a
    call nc, $ced5
    adc $c5
    call z, $9f7f
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    pop bc
    set 1, c
    adc $c7
    ld a, a
    ret nc

    pop bc
    jp nc, Jump_025_7fd4

    ret


    adc $7f
    call nc, $c84f
    push bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    jp nz, $55d9

    ld a, a
    jp $c1c8


    adc $c3
    push bc
    adc h
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    reti


    push bc
    pop bc
    ld d, l
    sub $c1
    jp nc, Jump_025_7fc3

    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    sub $c5
    jp nc, Jump_025_7fd9

    ld d, l
    ret z

    ret


    rst $00
    ret z

    ld a, a
    call z, $d6c5
    push bc
    call z, Call_025_7f8e
    and d
    push bc
    ld a, a
    jp Jump_025_55c1


    jp nc, $c6c5

    push de
    call z, $c17f
    adc $c4
    ld a, a
    set 0, l
    push bc
    ret nc

    ld a, a
    ret z

    ret


    ld d, l
    call $d57f
    adc $c4
    push bc
    jp nc, $d37f

    call nc, $c9d2
    jp Jump_025_7fd4


    jp Jump_025_55cf


    adc $d4
    jp nc, $cccf

    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a

Call_025_577f:
Jump_025_577f:
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    rst $10
    push bc
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    call z, $d3cf
    ld c, a
    call nc, Call_025_7f8e
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    rst $10
    push bc
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    call z, $d3cf
    ld c, a
    call nc, Call_025_7f8e
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_025_7f8c
    adc [hl]
    ld a, a
    call z, $d3cf
    call nc, $d97f
    rst $08
    push de
    jp nc, Jump_025_7f4f

    rst $10
    pop bc
    reti


    sbc a
    ld a, a
    ld d, a

Jump_025_57c5:
    nop
    ld a, a
    xor c

Call_025_57c8:
    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    pop bc
    adc $d9
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c855
    push bc
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub d
    ld a, a
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    sbc a
    ld d, l
    xor c
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $cd7f

    pop bc
    set 0, l
    ld a, a
    pop bc
    ld d, l
    call nz, $d4c5
    rst $08
    push de
    jp nc, Jump_025_7f8e

    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    ret


    call nc, $c97f
    db $d3
    adc $87
    call nc, $d47f
    ret z

    push bc
    ld c, a
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    call nc, Call_025_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, Call_025_7fc5
    ld d, l
    adc [hl]
    rst $10
    ret z

    ret


    jp Jump_025_7fc8


    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    adc $d4
    ld d, l
    jp nc, $cec1

    jp $9fc5


    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    ret


    call nc, $c97f
    db $d3
    adc $87
    call nc, $d47f
    ret z

    push bc
    ld c, a
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    call nc, Call_025_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, Call_025_7fc5
    ld d, l
    adc [hl]
    rst $10
    ret z

    ret


    jp Jump_025_7fc8


    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    adc $d4
    ld d, l
    jp nc, $cec1

    jp $9fc5


    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    adc h
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    call z, $d6c9
    push bc
    call nz, $c97f
    ld c, a
    adc $7f
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    add $cf
    jp nc, $c17f

    ld a, a
    ld d, l
    call z, $cecf
    rst $00
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    adc h
    ld a, a
    rst $10
    ret


    call z, Call_025_7fcc
    ld d, l
    adc $c5
    sub $c5
    jp nc, $cc7f

    push bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    add $cf
    jp nc, $c555

    ret


    rst $00
    adc $c5
    jp nc, $d47f

    reti


    jp nc, $cec1

    ret


    jp c, Jump_025_7fc5

    ret z

    ld d, l
    push bc
    jp nc, $8ec5

    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_025_4f7f
    add $d5
    call nc, $d2d5
    push bc
    ld a, a
    adc [hl]
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $55d0

    push de
    call nc, $d97f
    rst $08
    push de
    ld a, a
    sbc a
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d97f
    rst $08
    ld d, l
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_025_7fcf
    jp nz, Jump_025_7fc5

    pop bc
    ld a, a
    call Call_025_55cf
    push de
    adc $d4
    pop bc
    ret


    adc $cf
    push de
    db $d3
    ld a, a
    call $cec1
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, h
    adc h
    ld a, a
    add $c9
    rst $00
    ret z

    call nc, Call_025_7f81
    xor h
    pop bc
    call nz, Call_025_4fc9
    push bc
    db $d3
    adc h
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and l
    sub $c5
    adc $7f
    and e
    ret z

    ret


    jp nz, $d4c1

    push bc
    jp nc, $c17f

    call z, $d34f
    rst $08
    ld a, a
    rst $10
    pop bc
    adc $d4
    db $d3
    ld a, a
    call nc, Call_025_7fcf
    jp $d4c1


    jp $55c8


    ld a, a
    db $d3
    rst $08
    call Call_025_7fc5
    jp nz, $c3c1

    bit 7, a
    ld d, [hl]
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $c47f
    push bc
    add $c5
    pop bc
    call nc, $c4c5
    sbc a
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $c47f
    push bc
    add $c5
    pop bc
    call nc, $c4c5
    sbc a
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    reti


    pop bc
    rst $08
    rst $08
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    add $4f
    jp nc, $c7c9

    ret z

    call nc, $cec5
    push bc
    call nz, $cd7f
    push bc
    add c
    ld a, a
    and h
    rst $08
    adc $55
    add a
    call nc, $c47f
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    rst $00
    jp nc, $d4cf

    push bc
    db $d3
    pop de
    ld d, l
    push de
    push bc
    ld a, a
    call $d6cf
    push bc
    call $cec5
    call nc, $c97f
    adc $7f
    call nc, $55c8
    push bc
    ld a, a
    call nz, $cdc9
    ld a, a
    call nc, $ced5
    adc $c5
    call z, $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, Jump_025_7fc5

    ld d, h
    ld a, a
    ret


    adc $7f
    ld c, a
    call nc, $c5c8
    ld a, a
    call nc, $ced5
    adc $c5
    call z, Call_025_7f9f
    xor d
    push de
    db $d3
    call nc, $557f
    adc $cf
    rst $10
    ld a, a
    or a
    pop bc
    adc $cc
    ret


    jp $c9c8


    ld a, a
    ret


    db $d3
    ld a, a
    ret z

    ld d, l
    push bc
    jp nc, $8ec5

    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    push bc
    jp nc, Jump_025_7fc5

    ret


    call nc, $c97f
    db $d3
    ld a, a
    sub $c5
    ld c, a
    jp nc, Jump_025_7fd9

    call nz, $d2c1
    res 1, h
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $557f
    db $d3
    push bc
    push bc
    ld a, a
    jp $c5cc


    pop bc
    jp nc, $d9cc

    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    push bc
    jp nc, Jump_025_7fc5

    ret


    call nc, $c97f
    db $d3
    ld a, a
    sub $c5
    ld c, a
    jp nc, Jump_025_7fd9

    call nz, $d2c1
    res 1, h
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $557f
    db $d3
    push bc
    push bc
    ld a, a
    jp $c5cc


    pop bc
    jp nc, $d9cc

    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c57f
    sub $c5
    adc $7f
    ret z

    push bc
    jp nc, Jump_025_7fc5

    add $cf
    ld c, a
    jp nc, $cc7f

    rst $08
    rst $08
    set 1, c
    adc $c7
    ld a, a
    add $cf
    jp nc, $557f

    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c67f

    pop bc
    jp Jump_025_7fc5


    ret


    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld c, a
    call z, $d6cf
    push bc
    call z, $8cd9
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $557f
    jp nz, Jump_025_7fc5

    jp nc, $d4c1

    ret z

    push bc
    jp nc, $d37f

    call nc, $cfd2
    adc $c7
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_025_7fc5

    ret


    db $d3
    adc $87
    call nc, Call_025_547f
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_025_7fc5

    ret


    db $d3
    adc $87
    call nc, Call_025_547f
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nc, $c1c8
    call nc, $c97f
    db $d3
    ld a, a
    ld d, h
    add c
    ld c, a
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    jp nz, $c7c5

    ret


    adc $7f
    adc $cf
    rst $10
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    sub $c5
    jp nc, Jump_025_7fd9

    push bc
    ret c

    jp $d4c9


    push bc
    call nz, $a97f
    add a
    call Call_025_7f4f
    push bc
    sub $c5
    adc $7f
    db $d3
    rst $10
    push bc
    pop bc
    call nc, $cec9
    rst $00
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $08
    adc $c3
    push bc
    ld a, a
    call $d2cf
    push bc
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    rst $08
    adc $c3
    push bc
    ld a, a
    call $d2cf
    push bc
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ret


    adc $7f
    ret nc

    pop bc
    jp nc, $c14f

    call z, $d3d9
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_025_7fc4
    jp nz, Jump_025_7fc5

    sub $c5
    jp nc, $d94f

    ld a, a
    ret z

    pop bc
    jp nc, Jump_025_7fc4

    call nc, Call_025_7fcf
    adc $c1
    call Call_025_7fc5
    ld a, a
    db $d3
    ld d, l
    rst $08
    ld a, a
    call $cec1
    reti


    ld a, a
    jp $d0c1


    call nc, $d2d5
    push bc
    call nz, $557f
    ld d, h
    ld a, a
    add c
    ld a, a
    xor c
    adc $7f
    call nc, $c9c8
    db $d3
    ld a, a
    pop bc
    db $d3
    call nc, $c555
    jp nc, $d47f

    rst $08
    rst $10
    adc $7f
    pop bc
    ret z

    push bc
    pop bc
    call nz, $8c7f
    ld a, a
    call nc, $c855
    push bc
    jp nc, Jump_025_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ld a, a
    add $cf
    jp nc, $d5d4

    adc $55
    push bc
    adc l
    call nc, $ccc5
    call z, $cec9
    rst $00
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    jp $cec1


    ld d, l
    ld a, a
    call nz, $d6c9
    ret


    adc $c5
    ld a, a
    call nc, $c5c8
    ld a, a
    adc $c1
    call Call_025_7fc5
    ld d, l
    rst $08
    add $7f
    ld d, h
    ld a, a
    jp nz, Jump_025_7fd9

    call nc, $c5c8
    ld a, a
    and l
    ret


    rst $00
    ld d, l
    ret z

    call nc, $a47f
    ret


    pop bc
    rst $00
    jp nc, $cdc1

    db $d3
    adc h
    ld a, a
    xor b
    push bc
    ld a, a
    jp $c155


    adc $7f
    jp nc, $8dc5

    rst $00
    ret


    sub $c5
    ld a, a
    ld d, h
    ld a, a
    pop bc
    ld a, a
    ld d, l
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    adc $c1
    call Call_025_7fc5
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c67f
    jp nc, $c7c9

    ret z

    call nc, $cec5
    push bc
    call nz, Call_025_7f81
    ld c, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    jp $d6c1


    push bc
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    call nz, $c7d5
    ld a, a
    jp nz, Jump_025_7fd9

    and h
    ret


    rst $00
    push de
    call nz, $d2c5
    add c
    ld a, a
    ld d, l
    ld d, a
    xor c
    call nc, $cd7f
    pop bc
    reti


    ld a, a
    jp $cecf


    call nc, $c3c1
    call nc, Call_025_577f
    ld a, a
    rst $10
    ld d, l
    ret


    call nc, Call_025_7fc8
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    jp $d4c9


    ld d, l
    reti


    add c
    ld a, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c9c8
    jp nc, Jump_025_7fc4

    add $cc
    rst $08
    rst $08
    jp nc, Jump_025_4f7f

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret z

    ret


    rst $00
    ret z

    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    rst $10
    ld d, l
    ret z

    push bc
    jp nc, Jump_025_7fc5

    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    bit 7, a
    add $c1
    jp nc, Jump_025_7f55

    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $d3c9
    call nc, $cec1
    jp $c555


    adc [hl]
    ld d, a
    nop
    ld a, a
    and l
    sub $c5
    jp nc, Jump_025_7fd9

    ld d, h
    ld a, a
    ld a, a
    rst $10
    ret


    call nc, Call_025_7fc8
    ld c, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call Call_025_7fc5
    call z, $d6c5
    push bc
    call z, $cd7f
    pop bc
    ld d, l
    reti


    jp nz, Jump_025_7fc5

    ret z

    pop bc
    db $d3
    ld a, a
    call nz, $c6c9
    add $c5
    jp nc, $cec5

    call nc, Call_025_7f55
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, Call_025_7fc8
    call nz, $c7c5
    jp nc, $c5c5

    adc [hl]
    ld d, l
    ld a, a
    and c
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    add $cf
    ld d, l
    db $d3
    call nc, $d2c5
    push bc
    call nz, $c27f
    reti


    ld a, a
    call $cec1
    ld a, a
    call z, $cfcf
    ld d, l
    set 2, e
    ld a, a
    call $c3d5
    ret z

    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, $557f

    call nc, $c1c8
    adc $7f
    rst $10
    ret


    call z, Call_025_7fc4
    rst $08
    adc $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    ld d, h
    ld c, a
    call nc, $cbc1
    push bc
    db $d3
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $7f
    pop bc
    adc $c4
    ld a, a
    ld d, l
    rst $00
    rst $08
    push bc
    db $d3
    ld a, a
    push bc
    sub $c5
    adc $7f
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    ld d, l
    jp nc, Jump_025_7f81

    ld d, a
    nop
    ld a, a
    xor a
    push de
    jp nc, $d07f

    jp nc, $d3c5

    ret


    call nz, $cec5
    call nc, $cf7f
    add $4f
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    jp $c5c9


    call nc, Call_025_7fd9
    ret


    db $d3
    ld a, a
    call nc, $cf55
    rst $08
    ld a, a
    call z, $cecf
    rst $00
    adc l
    rst $10
    ret


    adc $c4
    push bc
    call nz, $d47f
    rst $08
    ld d, l
    ld a, a
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor h
    ret


    db $d3
    call nc, $cec5
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, $d9cc
    ld c, a
    ld a, a
    call nc, Call_025_7fcf
    call nc, $c5c8
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    jp Jump_025_7fc8


    ld a, a
    call $c155
    call nz, Call_025_7fc5
    jp nz, Jump_025_7fd9

    call nc, $c1c8
    call nc, $d37f
    push bc
    call z, $8dc6
    ld d, l
    db $d3
    pop bc
    call nc, $d3c9
    add $c9
    push bc
    call nz, $cb7f
    push bc
    push bc
    ret nc

    push bc
    jp nc, $5581

    ld a, a
    ld d, a
    nop
    ld a, a
    or b
    jp nc, $d3c5

    push bc
    adc $d4
    ld a, a
    pop bc
    ld a, a
    call nc, $cec5
    add $cf
    call z, $c44f
    ld a, a
    call nc, Call_025_7fcf
    db $d3
    rst $08
    call $cfc5
    adc $c5
    add a
    db $d3
    ld a, a
    db $d3
    push bc
    ld d, l
    call z, $8dc6
    db $d3
    pop bc
    call nc, $d3c9
    add $c9
    push bc
    call nz, $d47f
    rst $08
    ret nc

    ret


    ld d, l
    jp $c97f


    adc $7f
    jp nc, $d4c5

    push de
    jp nc, $81ce

    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d37f

    ret nc

    push bc
    push bc
    call nz, $cf7f
    add $7f
    ld c, a
    ld d, h
    ld a, a
    rst $10
    ret


    call z, Call_025_7fcc
    ret


    adc $c3
    jp nc, $c1c5

    db $d3
    push bc
    ld d, l
    pop bc
    db $d3
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    db $d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    ld d, l
    sub $c5
    ld a, a
    pop bc
    ld a, a
    rst $08
    jp nc, $cec1

    rst $00
    push bc
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld d, l
    ld a, a
    adc h
    and c
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, Call_025_7fcc
    add $55
    call z, $c9d9
    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    ld a, a
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    ld d, l
    push de
    db $d3
    push bc
    add $d5
    call z, $c8d7
    ret


    call z, Call_025_7fc5
    adc $cf
    ld a, a
    add $c9
    ld d, l
    rst $00
    ret z

    call nc, $cec9
    rst $00
    ld a, a
    add c
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    db $d3
    ld d, l
    push de
    ret nc

    push bc
    jp nc, Jump_025_7f81

    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ld d, l
    call nc, $cbcf
    push bc
    adc $7f
    rst $08
    add $7f
    call Call_025_7fd9
    jp nc, $c7c5

    pop bc
    jp nc, $c455

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    ret z

    pop bc
    call nz, $d27f
    push bc
    jp $c9c5


    sub $4f
    push bc
    call nz, Call_025_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $ad7f
    pop bc
    jp nc, $c8c3

    ret


    db $d3
    db $d3
    add c
    ld a, a
    ld d, b
    ld de, $b400
    ld d, l
    ret z

    push bc
    ld a, a
    sub $cf
    call z, $c1d4
    rst $00
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld e, h
    sub d
    sub h
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    sub c
    sub b
    sub b
    adc h
    sub b
    sub b
    sub b
    ld a, a
    sub $cf
    call z, $d3d4
    adc [hl]
    or h
    ld d, l
    push bc
    pop bc
    jp Jump_025_7fc8


    push de
    db $d3
    ld a, a
    db $d3
    rst $08
    call Call_025_7fc5
    push bc
    call z, $c3c5
    ld d, l
    call nc, $c9d2
    jp $d4c9


    reti


    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d27f

    push de
    jp $d3cb


    pop bc
    jp Jump_025_7fcb


    ret


    db $d3
    ld c, a
    ld a, a
    add $d5
    call z, Call_025_7fcc
    push bc
    adc $cf
    push de
    rst $00
    ret z

    add c
    ld a, a
    xor c
    call nc, $557f
    ret


    db $d3
    ld a, a
    call nc, $cfcf
    ld a, a
    ret z

    push bc
    pop bc
    sub $d9
    ld a, a
    add $cf
    jp nc, $557f

    reti


    rst $08
    push de
    ld a, a
    call nc, Call_025_7fcf
    jp nz, $c1c5

    jp nc, Jump_025_7f81

    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    call nc, $c1d2
    ret


    adc $c5
    call nz, $d37f
    call nc, $d24f
    ret


    jp $ccd4


    reti


    ld a, a
    jp nz, Jump_025_7fd9

    xor l
    pop bc
    jp z, $d2cf

    ld a, a
    xor l
    ld d, l
    pop bc
    jp nc, $c8c3

    ret


    db $d3
    db $d3
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_025_7fc5
    call Call_025_7fd9
    ld d, l
    push bc
    adc $cc
    ret


    db $d3
    call nc, $cec9
    rst $00
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    add a
    call nc, $cf7f
    ret nc

    push bc
    adc $7f
    call nc, $c84f
    push bc
    ld a, a
    call nz, $cfcf
    jp nc, Jump_025_7f8e

    jp $cec1


    ld a, a
    reti


    rst $08
    push de
    sbc a
    ld d, l
    ld a, a
    xor l
    pop bc
    jp nc, $c8c3

    ret


    db $d3
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    add $c1
    call Call_025_55cf
    push de
    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    jp nc, $d9cd

    ld a, a
    add $cf
    ld d, l
    jp nc, $c87f

    ret


    db $d3
    ld a, a
    ret z

    pop bc
    jp nc, $cfc2

    push de
    jp nc, $cec9

    rst $00
    ld a, a
    ld d, l
    db $d3
    push de
    db $d3
    ret nc

    ret


    jp $cfc9


    push de
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    pop bc
    jp $d455


    ret


    adc $c7
    ld a, a
    rst $10
    ret


    call nc, Call_025_7fc8
    jp $d5c1


    call nc, $cfc9
    adc $55
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call $817f
    ld a, a
    ret z

    ret


    rst $00
    ret z

    call z, Call_025_7fd9
    db $d3
    set 1, c
    ld c, a
    call z, $c5cc
    call nz, Call_025_7f8e
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call $817f
    ld a, a
    ret z

    ret


    rst $00
    ret z

    call z, Call_025_7fd9
    db $d3
    set 1, c
    ld c, a
    call z, $c5cc
    call nz, Call_025_7f8e
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_025_7fc5

    call nc, Call_025_7fcf
    call nz, $c54f
    pop bc
    call z, $d77f
    ret


    call nc, Call_025_7fc8
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $c955


    call nc, Call_025_7fd9
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    call Call_025_7fd9
    ret nc

    rst $08
    rst $08
    ld d, l
    jp nc, $d37f

    call nc, $c5d2
    adc $c7
    call nc, Call_025_7fc8
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    xor c
    ld a, a
    db $d3
    push bc
    push bc
    adc [hl]
    ld a, a
    xor l
    pop bc
    jp nc, $c8c3

    ld c, a
    ret


    db $d3
    db $d3
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    pop bc
    call nc, Call_025_7f55
    call nc, $c5c8
    ld a, a
    db $d3
    rst $10
    ret


    call nc, $c8c3
    ld a, a
    rst $08
    add $7f
    ret z

    ret


    ld d, l
    db $d3
    ld a, a
    call nz, $cfcf
    jp nc, $d77f

    pop bc
    db $d3
    ld a, a
    ret z

    ret


    call nz, $c4c5
    ld a, a
    ld d, l
    push de
    adc $c4
    push bc
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    jp nz, $d4cf

    call nc, $cdcf
    ld a, a
    ld d, l
    rst $08
    add $7f
    ld d, [hl]
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    rst $00
    rst $08
    call nc, $c17f
    adc $7f
    ld c, a
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $d37f


    ret z

    rst $08
    jp $81cb


    ld a, a
    ret z

    ld d, l
    pop bc
    sub $c9
    adc $c7
    ld a, a
    ret nc

    ret


    adc $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    adc $c5
    ld d, l
    push bc
    call nz, $c5cc
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    rst $00
    rst $08
    call nc, $c17f
    adc $7f
    ld c, a
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $d37f


    ret z

    rst $08
    jp $81cb


    ld a, a
    ret z

    ld d, l
    pop bc
    sub $c9
    adc $c7
    ld a, a
    ret nc

    ret


    adc $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    adc $c5
    ld d, l
    push bc
    call nz, $c5cc
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_025_7fc5

    jp $c9c8


    call z, $d2c4
    push bc
    adc $7f
    ld a, a
    pop bc
    ld c, a
    jp nc, Jump_025_7fc5

    add $cf
    jp nc, $c9c2

    call nz, $c5c4
    adc $7f
    rst $10
    ret z

    pop bc
    call nc, $c555
    sub $c5
    jp nc, $d97f

    rst $08
    push de
    jp nc, Jump_025_547f

    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    db $d3
    rst $08
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or b
    jp nc, $cdcf

    ret nc

    call nc, $d97f
    rst $08
    push de
    ld a, a
    call nc, $c1c8
    call nc, Call_025_4f7f
    xor l
    pop bc
    jp z, $d2cf

    ld a, a
    xor l
    pop bc
    jp nc, $c8c3

    ret


    db $d3
    db $d3
    ld a, a
    ret z

    pop bc
    ld d, l
    db $d3
    ld a, a
    call z, $c3cf
    set 0, l
    call nz, $c87f
    ret


    db $d3
    ld a, a
    call nz, $cfcf
    jp nc, Jump_025_7f55

    rst $10
    ret


    call nc, Call_025_7fc8
    call nc, $cfd7
    ld a, a
    ret nc

    pop bc
    call nz, $cfcc
    jp $55cb


    db $d3
    ld a, a
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld d, l
    ld a, a
    ret nc

    jp nc, Jump_025_7fd9

    rst $08
    ret nc

    push bc
    adc $7f
    call nc, $c5c8
    ld a, a
    add $c9
    jp nc, $d355

    call nc, $cc7f
    rst $08
    jp Jump_025_7fcb


    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    jp $cf55


    adc $c4
    ld a, a
    rst $08
    adc $c5
    ld a, a
    ret


    db $d3
    ld a, a
    adc $c5
    pop bc
    jp nc, $d9c2

    ld d, l
    ld a, a
    ret


    call nc, $8e7f
    ld a, a
    or h
    rst $10
    rst $08
    ld a, a
    jp nc, $ccc5

    ret


    push bc
    add $7f
    ld d, l
    db $d3
    ret nc

    jp nc, $cec9

    rst $00
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    adc $c5
    ret c

    call nc, $557f
    call nc, Call_025_7fcf
    push bc
    pop bc
    jp Jump_025_7fc8


    rst $08
    call nc, $c5c8
    jp nc, Jump_025_7f8e

    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor c
    add a
    call $d47f
    pop bc
    set 0, l
    adc $7f
    pop bc
    jp nz, $c14f

    jp $81cb


    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor c
    add a
    call $d47f
    pop bc
    set 0, l
    adc $7f
    pop bc
    jp nz, $c14f

    jp $81cb


    ld a, a
    ld e, b
    nop
    ld a, a
    xor h
    push bc
    call nc, $a27f
    rst $08
    jp nz, Jump_025_7fcf

    db $d3
    push bc
    adc $c4
    ld a, a
    call nc, Call_025_4fc8
    push bc
    ld a, a
    call z, $d4c5
    call nc, $d2c5
    ld a, a
    call nc, Call_025_7fcf
    call nc, $c5c8
    ld a, a
    adc $55
    rst $08
    jp nc, $c8d4

    ld a, a
    rst $08
    add $7f
    set 0, l
    jp nc, $c9d2

    pop bc
    ld a, a
    jp Jump_025_55c9


    call nc, Call_025_7fd9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or b
    ret


    ret nc

    ret


    adc [hl]
    ld a, a
    xor [hl]
    push bc
    ret c

    call nc, $d47f
    ret


    ld c, a
    call Call_025_7fc5
    xor c
    add a
    call nz, $cc7f
    ret


    set 0, l
    ld a, a
    call nc, Call_025_7fcf
    db $d3
    ret nc

    ld d, l
    push bc
    adc $c4
    ld a, a
    pop bc
    ld a, a
    add $c5
    rst $10
    ld a, a
    call nz, $d9c1
    db $d3
    ld a, a
    push bc
    adc $55
    jp z, $d9cf

    ret


    adc $c7
    ld a, a
    call $d3d9
    push bc
    call z, Call_025_7fc6
    ret


    adc $7f
    ld d, l
    reti


    rst $08
    push de
    jp nc, $c37f

    ret


    call nc, $8ed9
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld a, a
    rst $08
    ld d, l
    add $7f
    ld e, [hl]
    ld a, a
    ret


    adc $7f
    set 0, l
    jp nc, Jump_025_55d2

    ret


    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    ret z

    pop bc
    sub $55
    ret


    adc $c7
    ld a, a
    call $c3d5
    ret z

    ld a, a
    call nc, $cdc9
    push bc
    add c
    ld a, a
    jp nz, $55d5

    call nc, $c97f
    adc $7f
    call nz, $c9d2
    push bc
    call nz, $cc7f
    push bc
    pop bc
    sub $c9
    push bc
    ld d, l
    db $d3
    ld a, a
    jp $d4c9


    reti


    adc h
    ld a, a
    ret


    call nc, $c97f
    db $d3
    adc $87
    call nc, $557f
    db $d3
    rst $08
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    xor c
    add a
    call $c17f
    adc $7f
    pop bc
    call nc, $d44f
    push bc
    adc $c4
    pop bc
    adc $d4
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    ld d, l
    ret


    ret nc

    add c
    ld a, a
    and e
    pop bc
    call z, Call_025_7fcc
    call Call_025_7fc5
    ret


    add $7f
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    ld d, l
    call nz, $cecf
    push bc
    ld a, a
    add c
    ld a, a
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    push de
    adc $c3
    rst $08
    call $d5cd
    adc $55
    ret


    jp $d4c1


    ret


    sub $c5
    ld a, a
    call $cec1
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    pop bc
    rst $00
    push bc
    jp nc, Jump_025_7fd3

    rst $08
    adc $4f
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    add $c5
    push bc
    call z, $c27f
    ld d, l
    rst $08
    jp nc, $c4c5

    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    call z, $cf55
    adc $c7
    ld a, a
    sub $cf
    reti


    pop bc
    rst $00
    push bc
    add c
    ld a, a
    db $d3
    rst $08
    call $cfc5
    ld d, l
    adc $c5
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    jp $c1c8


    call z, $c5cc
    adc $c7
    push bc
    ld d, l
    ld a, a
    call nc, Call_025_7fcf
    set 1, c
    call z, Call_025_7fcc
    call nc, $cdc9
    push bc
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call nz, $d3c5
    ret


    jp nc, Jump_025_4fcf

    push de
    db $d3
    adc h
    ld a, a
    call z, $d8d5
    push de
    jp nc, Jump_025_7fd9

    ret nc

    pop bc
    db $d3
    db $d3
    pop bc
    rst $00
    ld d, l
    push bc
    jp nc, $d37f

    ret z

    ret


    ret nc

    adc h
    ld a, a
    ret


    call nc, $c37f
    pop bc
    jp nc, $c9d2

    ld d, l
    push bc
    db $d3
    ld a, a
    ld a, a
    ld d, h
    ld e, l
    ld a, a
    jp Jump_025_55cf


    call $cec9
    rst $00
    ld a, a
    add $d2
    rst $08
    call $c57f
    sub $c5
    jp nc, $d7d9

    ret z

    ld d, l
    push bc
    jp nc, Jump_025_7fc5

    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    add c
    ld d, l
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret


    adc $d6
    ret


    call nc, $c4c5
    ld a, a
    ld d, l
    ld e, l
    ld a, a
    ld a, a
    rst $10
    ret


    call z, Call_025_7fcc
    ret z

    rst $08
    call z, $c455
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    sub $c8
    pop bc
    adc $c7
    push bc
    ld a, a
    call nz, $cec1
    ld d, l
    jp Jump_025_7fc5


    ret nc

    pop bc
    jp nc, $d9d4

    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    pop bc
    jp nc, Jump_025_55d2

    ret


    sub $c9
    adc $c7
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    jp nc, Jump_025_55c2

    rst $08
    push de
    jp nc, $8e7f

    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $c1
    call $d5cf
    db $d3
    ld c, a
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    jp nc, Jump_025_7fd4

    rst $08
    add $7f
    db $d3
    rst $10
    rst $08
    jp nc, Jump_025_7fc4

    ld d, l
    db $d3
    set 1, c
    call z, Call_025_7fcc
    ret


    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    rst $08
    ld a, a
    ld d, l
    jp nz, Jump_025_7fc5

    rst $08
    adc $7f
    call nc, $c9c8
    db $d3
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    adc [hl]
    ld a, a
    ld d, l
    xor a
    ret z

    adc h
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    push bc
    push bc
    adc $7f
    ret z

    ret


    call $8c55
    ld a, a
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $c17f
    ld a, a
    db $d3
    push bc
    ld d, l
    pop bc
    db $d3
    ret


    jp Jump_025_7fcb


    rst $08
    call z, $cdc4
    pop bc
    adc $81
    ld a, a
    jp nz, $d4d5

    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, Call_025_7fcc
    ret


    db $d3
    ld a, a
    pop bc
    call z, Call_025_55d3
    rst $08
    ld a, a
    push de
    db $d3
    push bc
    add $d5
    call z, Call_025_7f81
    rst $00
    rst $08
    ld a, a
    call nc, Call_025_7fcf
    call $c555
    push bc
    call nc, $c87f
    ret


    call $817f
    ld a, a
    adc [hl]
    ld a, a
    call nc, $c5c8
    adc $8c
    ld d, l
    ld a, a
    jp nz, $c5d9

    adc l
    jp nz, $c5d9

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp $d0c1


    call nc, $c9c1
    adc $7f
    ret


    db $d3
    ld a, a
    pop bc
    ld c, a
    adc $7f
    push bc
    ret c

    ret nc

    push bc
    jp nc, Jump_025_7fd4

    rst $08
    add $7f
    db $d3
    rst $10
    rst $08
    jp nc, Jump_025_55c4

    ld a, a
    db $d3
    set 1, c
    call z, Call_025_7fcc
    adc [hl]
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    ld d, l
    rst $08
    call nz, $c17f
    call nc, $d37f
    rst $10
    rst $08
    jp nc, Jump_025_7fc4

    db $d3
    set 1, c
    call z, Call_025_55cc
    add c
    ld a, a
    xor b
    push bc
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    ld d, l
    call z, Call_025_7fcc
    rst $08
    add $7f
    ld d, h
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_025_7fc4
    ld d, l
    jp nz, Jump_025_7fc5

    call nc, $d5c1
    rst $00
    ret z

    call nc, Call_025_7f81
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $cec1
    jp Jump_025_7fc5


    ret nc

    pop bc
    jp nc, $d9d4

    ld a, a
    ld c, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_025_7fc4
    jp nz, Jump_025_7fc5

    push bc
    adc $c4
    ret


    adc $c7
    adc [hl]
    ld d, l
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    call nc, Call_025_55cf
    ld a, a
    db $d3
    push bc
    call nc, $d37f
    pop bc
    ret


    call z, Call_025_7f8e
    ld d, a
    nop
    ld a, a
    or d
    push bc
    pop bc
    call z, $d9cc
    add c
    ld a, a
    db $d3
    rst $10
    push bc
    push bc
    ret nc

    ret


    adc $c7
    ld c, a
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $c3c5
    bit 7, a
    ret


    db $d3
    adc $87
    call nc, $c17f
    ld d, l
    adc $7f
    push bc
    pop bc
    db $d3
    reti


    ld a, a
    jp z, $c2cf

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    or l
    jp $8cc8


    ld a, a
    rst $08
    push de
    jp $8cc8


    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    ld c, a
    xor c
    ld a, a
    add $c5
    push bc
    call z, $c97f
    call z, $8ecc
    ld a, a
    ld d, [hl]
    adc h
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    db $d3
    push bc
    pop bc
    db $d3
    ret


    jp Jump_025_7fcb


    adc [hl]
    ld a, a
    rst $00
    ld d, l
    push bc
    call nc, $c97f
    adc $7f
    pop bc
    ld a, a
    call nz, $c1d2
    push de
    rst $00
    ret z

    call nc, $557f
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    xor a
    rst $10
    adc h
    rst $08
    rst $10
    add c
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    add $c9
    rst $00
    ld c, a
    ret z

    call nc, $d47f
    rst $08
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_025_7f81

    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    ld c, a
    adc $cb
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    call $cec1
    reti


    ld a, a
    ld a, a
    call nc, $d0d9
    push bc
    ld d, l
    db $d3
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    ld d, l
    rst $08
    jp nc, $c4cc

    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    add c
    ld a, a
    reti


    rst $08
    push de
    ld c, a
    add a
    sub $c5
    ld a, a
    rst $00
    ret


    sub $c5
    adc $7f
    call Call_025_7fc5
    pop bc
    ld a, a
    db $d3
    call nc, $c155
    jp nc, $81d4

    ld a, a
    ld e, b
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    add c
    ld a, a
    reti


    rst $08
    push de
    ld c, a
    add a
    sub $c5
    ld a, a
    rst $00
    ret


    sub $c5
    adc $7f
    call Call_025_7fc5
    pop bc
    ld a, a
    db $d3
    call nc, $c155
    jp nc, $81d4

    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    ld c, a
    add c
    ld a, a
    and c
    jp nc, $cec5

    add a
    call nc, $d97f
    rst $08
    push de
    ld a, a
    db $d3
    push bc
    pop bc
    db $d3
    ld d, l
    ret


    jp $9fcb


    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    ret nc

    pop bc
    ret nc

    pop bc
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    push bc
    ld c, a
    jp nc, Jump_025_7fc5

    rst $10
    push bc
    jp nc, Jump_025_7fc5

    sub c
    sub b
    sub b
    ld a, a
    call nc, $d0d9
    push bc
    db $d3
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    jp nz, $d4d5

    ld a, a
    xor c
    ld a, a
    call nc, $c9c8
    ld d, l
    adc $cb
    ld a, a
    ret


    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_025_7fc4
    jp nz, Jump_025_7fc5

    call $cf55
    jp nc, $8ec5

    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    jp $d2c1


    push bc
    call z, $d3c5
    db $d3
    ld a, a
    ld e, b
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    jp $d2c1


    push bc
    call z, $d3c5
    db $d3
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    jp nz, $cfcc

    jp $cb4f


    push bc
    call nz, $d47f
    jp nc, $c6c1

    add $c9
    jp Jump_025_7f81


    db $d3
    call nc, $d0c5
    ld d, l
    ld a, a
    pop bc
    db $d3
    ret


    call nz, $8cc5
    db $d3
    call nc, $d0c5
    ld a, a
    db $d3
    ret


    call nz, $81c5
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c97f
    call nc, $d77f
    ret


    call z, Call_025_7fcc
    jp nz, Jump_025_7fc5

    ld c, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    pop bc
    jp nc, $c1c2

    rst $00
    push bc
    ld a, a
    jp Jump_025_55c1


    adc $9f
    ld a, a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $c1d2
    adc $c7
    push bc
    ld a, a
    jp nz, $c155

    call z, Call_025_7fcc
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    pop bc
    jp nz, $cec1

    call nz, $cecf
    push bc
    ld d, l
    call nz, $d47f
    ret z

    push bc
    jp nc, Jump_025_57c5

    nop
    ld a, a
    xor c
    add a
    call $d37f
    rst $08
    ld a, a
    jp nz, $d3d5

    reti


    ld a, a
    call nc, $c1c8
    call nc, Call_025_7f4f
    call Call_025_7fd9
    ret z

    push bc
    pop bc
    call nz, $c97f
    db $d3
    ld a, a
    db $d3
    rst $10
    ret


    call $55cd
    ret


    adc $c7
    ld a, a
    add c
    ld a, a
    or h
    ret z

    pop bc
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    ld d, l
    rst $00
    rst $08
    ld a, a
    call nc, $c5c8
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ret z

    push bc
    reti


    adc h
    ret z

    push bc
    reti


    adc h
    ret z

    push bc
    reti


    adc h
    ld c, a
    ld a, a
    ld d, [hl]
    and l
    sub $c5
    jp nc, $c4d9

    pop bc
    reti


    ld a, a
    ld a, a
    xor c
    ld a, a
    db $d3
    bit 2, l
    ret


    adc $7f
    call nc, $d2c1
    rst $08
    push bc
    db $d3
    add c
    ld a, a
    xor b
    push bc
    reti


    adc h
    ret z

    push bc
    ld d, l
    reti


    adc [hl]
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    jp nc, $c4cf

    push de
    ld d, l
    jp $c4c5


    ld a, a
    rst $10
    ret z

    ret


    call z, Call_025_7fc5
    rst $10
    rst $08
    jp nc, $c9cb

    adc $c7
    ld d, l
    adc [hl]
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    xor e
    pop bc
    jp nc, Jump_025_4fc2

    ret


    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    ld d, l
    jp nc, $c5c5

    call nz, Call_025_7fd9
    add $cf
    jp nc, $c67f

    rst $08
    rst $08
    call nz, $9f7f
    ld a, a
    ld d, l
    db $d3
    rst $08
    ld a, a
    rst $00
    call z, $d4d5
    call nc, $cecf
    rst $08
    push de
    db $d3
    adc h
    ld a, a
    db $d3
    rst $08
    ld d, l
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    reti


    adc [hl]
    ld a, a
    ld d, h
    xor [hl]
    rst $08
    jp nz, $c4cf

    ld d, l
    reti


    ld a, a
    push bc
    ret c

    jp $d0c5


    call nc, $c87f
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    ret z

    ret


    adc h
    ld a, a
    jp $c9c8


    adc [hl]
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    ld c, a
    adc $c4
    ld a, a
    rst $08
    add $7f
    ld a, a
    rst $08
    adc $c9
    rst $08
    adc $8d
    db $d3
    set 1, c
    adc $55
    adc $c9
    adc $c7
    ld a, a
    rst $08
    jp nc, $d47f

    push bc
    pop bc
    jp nc, $c48d

    jp nc, $d0cf

    ld d, l
    ret nc

    ret


    adc $c7
    ld a, a
    and l
    sub $c5
    jp nc, $c4d9

    pop bc
    reti


    ld a, a
    ld a, a
    xor c
    ld a, a
    ld d, l
    db $d3
    set 1, c
    adc $7f
    rst $08
    adc $c9
    rst $08
    adc $d3
    add c
    ld a, a
    and e
    ret z

    ret


    adc h
    ld d, l
    ld a, a
    jp $c9c8


    adc [hl]
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    add $55
    ld a, a
    ld a, a
    rst $08
    adc $c9
    rst $08
    adc $8d
    db $d3
    set 1, c
    adc $ce
    ret


    adc $c7
    ld a, a
    ld d, l
    rst $08
    jp nc, $d47f

    push bc
    pop bc
    jp nc, $c48d

    jp nc, $d0cf

    ret nc

    ret


    adc $c7
    ld a, a
    ld d, l
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d37f
    push bc
    push bc
    ret


    adc $c7
    ld a, a
    call $d9c1
    jp nz, $4fc5

    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $d4c5

    call nc, $d2c5
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $ce7f
    rst $08
    call nc, $d37f
    push bc
    pop bc
    db $d3
    ret


    jp Jump_025_7fcb


    ld c, a
    adc [hl]
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d0c1


    ld d, l
    call nc, $c9c1
    adc $7f
    adc [hl]
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c1c5

    call nz, $c955
    adc $c7
    ld a, a
    pop bc
    ld a, a
    jp nz, $cfcf

    bit 7, a
    adc $c1
    call $c4c5
    ld a, a
    ld d, l
    and c
    and d
    and e
    ld a, a
    rst $08
    add $7f
    or h
    jp nc, $d6c1

    push bc
    call z, $c27f
    reti


    ld a, a
    ld d, l
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    ld d, [hl]
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    pop bc
    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    add c
    ld a, a
    ld c, a
    xor c
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_025_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    rst $08
    ld d, l
    call Call_025_7fc5
    jp $cbc1


    push bc
    adc [hl]
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    call Call_025_7fc5
    ld d, l
    db $d3
    rst $08
    call Call_025_7fc5
    rst $10
    ret


    call nc, Call_025_7fc8
    and [hl]
    jp nc, $cec1

    jp Jump_025_7fc5


    ld d, l
    add $cc
    pop bc
    sub $cf
    push de
    jp nc, Jump_025_7f8c

    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or h
    jp nc, $d6c1

    push bc
    call z, $c9cc
    adc $c7
    ld a, a
    pop bc
    jp nz, $cfd2

    pop bc
    ld c, a
    call nz, $c27f
    reti


    ld a, a
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    ret nc

    ld d, l
    jp nc, $d0cf

    push bc
    jp nc, Jump_025_7f8c

    db $d3
    rst $08
    ld a, a
    pop de
    push de
    ret


    push bc
    call nc, $c17f
    ld d, l
    adc $c4
    ld a, a
    db $d3
    rst $08
    ld a, a
    jp $d2c1


    push bc
    add $d2
    push bc
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d37f
    call nc, $ccc9
    call z, $d77f
    ret


    call nc, Call_025_7fc8
    and d
    ld c, a
    push de
    set 1, h
    ret


    adc $7f
    ld a, a
    push de
    ret nc

    ld a, a
    call nc, Call_025_7fcf
    adc $cf
    rst $10
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    and d
    push de
    call z, $cec9
    add c
    and d
    push de
    call z, $cec9
    add c
    ld d, b
    nop
    ld a, a
    xor l
    reti


    ld a, a
    jp $c9c8


    call z, $d2c4
    push bc
    adc $7f
    pop bc
    adc $c4
    ld a, a
    ld c, a
    xor c
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    call nc, $c1d2
    sub $c5
    call z, $c9cc
    adc $c7
    ld a, a
    ld d, l
    pop bc
    jp nc, $d5cf

    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    adc [hl]
    ld d, l
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    adc h
    ret z

    pop bc
    ld a, a
    call z, $d5c1
    rst $00
    ret z

    call nc, Call_025_55c5
    jp nc, Jump_025_577f

    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    add a
    call $c17f
    adc $7f
    ret


    adc $d4
    push bc
    jp nc, $ce4f

    pop bc
    call nc, $cfc9
    adc $c1
    call z, $d07f
    rst $08
    call z, $c3c9
    push bc
    call Call_025_55c1
    adc $81
    ld a, a
    xor c
    add a
    call $d07f
    push de
    jp nc, $d5d3

    ret


    adc $c7
    ld a, a
    pop bc
    ld d, l
    adc $c4
    ld a, a
    jp $d0c1


    call nc, $d2d5
    ret


    adc $c7
    ld a, a
    ld d, l
    ld e, [hl]
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    ld d, l
    add $7f
    ret z

    ret


    db $d3
    ld a, a
    push bc
    sub $c9
    call z, $c47f
    push bc
    push bc
    call nz, $817f
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $cfcc
    jp nc, Jump_025_4f7f

    ld d, [hl]
    add c
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    ld d, h
    ld a, a
    ld a, a
    jp $d0c1


    ld d, l
    call nc, $d2d5
    push bc
    call nz, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $c1d2
    sub $55
    push bc
    call z, $c9cc
    adc $c7
    ld a, a
    rst $10
    pop bc
    reti


    ld a, a
    ret


    db $d3
    ld a, a
    call Call_025_7fd9
    ld d, l
    add $d2
    ret


    push bc
    adc $c4
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    add c
    ld a, a
    and e
    ret z

    push bc
    jp nc, $d3c9

    ret z

    ld a, a
    add $d2
    ret


    push bc
    ld c, a
    adc $c4
    db $d3
    ret z

    ret


    ret nc

    adc h
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    adc $c4
    ld a, a
    xor c
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    add $d2
    ret


    ld c, a
    push bc
    adc $c4
    db $d3
    adc h
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    adc $c4
    ld a, a
    xor c
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    add $d2
    ret


    ld c, a
    push bc
    adc $c4
    db $d3
    adc h
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld c, a
    and e
    rst $08
    call $cec9
    rst $00
    ld a, a
    ret


    adc $7f
    rst $10
    ret


    call nc, $cfc8
    push de
    call nc, Call_025_7f55
    ret nc

    push bc
    jp nc, $c9cd

    db $d3
    db $d3
    ret


    rst $08
    adc $7f
    adc h
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    jp nc, $d4c1

    ret z

    push bc
    jp nc, $c97f

    call $cfd0
    call z, $d4c9
    push bc
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and a
    rst $08
    ld a, a
    rst $08
    push de
    call nc, Call_025_7f8c
    call z, $d4c5
    ld a, a
    call Call_025_7fc5
    pop bc
    ld c, a
    call z, $cecf
    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push de
    call $c8d0
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nc, $c1c5

    call z, Call_025_4fcc
    reti


    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_025_7f55
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    call z, $d4c9
    push bc
    adc $c5
    db $d3
    db $d3
    ld a, a
    ret


    ld d, l
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push de
    call $c8d0
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nc, $c1c5

    call z, Call_025_4fcc
    reti


    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_025_7f55
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    call z, $d4c9
    push bc
    adc $c5
    db $d3
    db $d3
    ld a, a
    ret


    ld d, l
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld d, h
    ld a, a
    sub $c5
    jp nc, Jump_025_7fd9

    ld c, a
    call $c3d5
    ret z

    add c
    ld a, a
    or b
    call z, $c1c5
    db $d3
    push bc
    ld a, a
    add $cf
    db $d3
    call nc, $c555
    jp nc, Jump_025_7f7f

    ld d, h
    adc h
    ld a, a
    call nc, $cfcf
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    ret z

    ret


    add c
    ld a, a
    xor l
    pop bc
    set 0, l
    ld a, a
    add $d2
    ret


    ld c, a
    push bc
    adc $c4
    ld a, a
    rst $10
    ret


    call nc, Call_025_7fc8
    call $8cc5
    ld a, a
    ret nc

    call z, $c1c5
    ld d, l
    db $d3
    push bc
    add c
    ld a, a
    and c
    adc $c4
    ld a, a
    adc h
    ld a, a
    and l
    ret c

    jp $c1c8


    adc $c7
    ld d, l
    push bc
    ld a, a
    ld d, h
    adc h
    ld a, a
    db $d3
    ret z

    pop bc
    call z, Call_025_7fcc
    rst $10
    push bc
    sbc a
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    call nc, $cf4f
    rst $08
    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    call nc, $cf4f
    rst $08
    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    xor h
    rst $08
    rst $08
    res 0, c
    ld a, a
    or h
    ret z

    push bc
    db $d3
    push bc
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    ld c, a
    ld d, h
    db $d3
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    jp $cccf


    call z, $c3c5
    call nc, $c555
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    pop bc
    call z, Call_025_7fcc
    call nc, $c5c8
    ld a, a
    rst $10
    ld d, l
    rst $08
    jp nc, $c4cc

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $cec1


    ld a, a
    ret


    call nc, $c27f
    ld c, a
    push bc
    jp $cdcf


    push bc
    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    call Call_025_7fd9
    ld d, h
    ld a, a
    ld d, l
    sbc a
    ld a, a
    ld d, a
    xor c
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    ret


    call nc, $d47f
    rst $08
    ld a, a
    jp nc, Jump_025_55c5

    sub $c9
    sub $c5
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cec5


    call nc, Call_025_55d2
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    push de
    ret


    db $d3
    pop bc
    adc $c3
    push bc
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    ld d, h
    ld a, a
    ld d, [hl]
    ld a, a
    jp $cdcf


    ret


    adc $c7
    ld a, a
    add $55
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    push de
    ret


    db $d3
    pop bc
    adc $c3
    push bc
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    ld d, h
    ld a, a
    ld d, [hl]
    ld a, a
    jp $cdcf


    ret


    adc $c7
    ld a, a
    add $55
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    add $c9
    rst $00
    ret z

    call nc, $cec9
    rst $00
    ld a, a
    rst $10
    ret


    ld c, a
    call nc, Call_025_7fc8
    reti


    rst $08
    push de
    adc $c7
    ld a, a
    call $cec1
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $cf55

    reti


    db $d3
    ld a, a
    rst $08
    add $7f
    call z, $c6c9
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    call $d9c1
    jp nz, Jump_025_7fc5

    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, Call_025_7f4f
    ld d, h
    ld a, a
    ret


    add $7f
    ret


    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    dec d
    ld a, a
    reti


    ld d, l
    push bc
    pop bc
    jp nc, Jump_025_7fd3

    push bc
    pop bc
    jp nc, $c9cc

    push bc
    jp nc, $817f

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c37f
    rst $08
    call $d4c5
    ret


    call nc, $cfc9
    ld c, a
    adc $7f
    add c
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    jp nc, Jump_025_55c5

    jp $d6cf


    push bc
    jp nc, $cec9

    rst $00
    ld a, a
    rst $08
    adc $c5
    add a
    db $d3
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    call nc, $c6c8
    push de
    call z, $d67f
    ret


    rst $00
    rst $08
    push de
    jp nc, Jump_025_7f8e

    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c37f
    rst $08
    call $d4c5
    ret


    call nc, $cfc9
    ld c, a
    adc $7f
    add c
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    jp nc, Jump_025_55c5

    jp $d6cf


    push bc
    jp nc, $cec9

    rst $00
    ld a, a
    rst $08
    adc $c5
    add a
    db $d3
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    call nc, $c6c8
    push de
    call z, $d67f
    ret


    rst $00
    rst $08
    push de
    jp nc, Jump_025_7f8e

    ld e, b
    nop
    ld a, a
    xor h
    rst $08
    rst $08
    res 0, c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $c9
    db $d3
    ret z

    ld a, a
    xor c
    ld c, a
    ld a, a
    pop bc
    adc $c7
    call z, $c4c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and h
    pop bc
    adc $c3
    push bc
    ld a, a
    ret nc

    pop bc
    jp nc, $d9d4

    sbc a
    ld a, a
    ld c, a
    xor c
    call nc, $d387
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    call nc, Call_025_7fcf
    ld d, l
    push bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    pop bc
    jp nc, $d9d4

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, Call_025_7fcc
    ret


    db $d3
    ld a, a
    push bc
    call $d4d0
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    call z, Call_025_7fcc
    ret


    db $d3
    ld a, a
    push bc
    call $d4d0
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    adc $cb
    ld a, a
    rst $10
    ret z

    ret


    ld c, a
    jp Jump_025_7fc8


    rst $10
    ret


    call z, Call_025_7fcc
    rst $10
    ret


    adc $8c
    ld a, a
    db $d3
    call nc, $cfd2
    ld d, l
    adc $c7
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $08
    jp nc, $d07f

    jp nc, $c3c5

    ret


    rst $08
    ld d, l
    push de
    db $d3
    ld a, a
    ld d, h
    ld a, a
    sbc a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    ld d, [hl]
    ld a, a
    call nc, Call_025_7fcf
    jp nz, $c3c5

    ld c, a
    rst $08
    call Call_025_7fc5
    jp nz, $d4cf

    ret z

    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld d, l
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld d, h
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    jp nc, $d4c1

    ret z

    push bc
    jp nc, $c77f

    rst $08
    rst $08
    call nz, $c67f
    push bc
    ld c, a
    call z, $cfcc
    rst $10
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    jp nc, $d4c1

    ret z

    push bc
    jp nc, $c77f

    rst $08
    rst $08
    call nz, $c67f
    push bc
    ld c, a
    call z, $cfcc
    rst $10
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    and l
    sub $c5
    jp nc, $cfd9

    adc $c5
    ld a, a
    ret z

    pop bc
    ld c, a
    sub $c5
    ld a, a
    jp nz, $c5c5

    adc $7f
    db $d3
    push bc
    push bc
    adc $7f
    jp nz, $d4d5

    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret nc

    pop bc
    jp nc, $d9d4

    ld a, a
    adc [hl]
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    rst $10
    rst $08
    adc $c4
    push bc
    jp nc, $d5c6

    call z, Call_025_7f81
    ret z

    ld c, a
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld d, h
    ld a, a
    ret


    db $d3
    add c
    ld d, l
    ld a, a
    nop
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $557f
    ld d, [hl]
    adc h
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $557f
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    pop bc
    set 0, l
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    jp $d0c5


    call nc, $cfc9
    ld c, a
    adc $7f
    ret


    adc $7f
    call Call_025_7fd9
    add $c1
    sub $cf
    push de
    jp nc, Jump_025_7f8c

    ret nc

    ld d, l
    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor l
    pop bc
    set 0, l
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    jp $d0c5


    call nc, $cfc9
    ld c, a
    adc $7f
    ret


    adc $7f
    call Call_025_7fd9
    add $c1
    sub $cf
    push de
    jp nc, Jump_025_7f8c

    ret nc

    ld d, l
    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call Call_025_7fd9
    ret nc

    pop bc
    jp nc, $ced4

    ld c, a
    push bc
    jp nc, $a77f

    push de
    call z, $c3c9
    ret z

    ret


    ld a, a
    and c
    ld a, a
    call $cec1
    ld a, a
    ld d, l
    rst $08
    add $7f
    rst $00
    jp nc, $c1c5

    call nc, $d37f
    call nc, $c5d2
    adc $c7
    call nc, $55c8
    add c
    ld a, a
    xor b
    push bc
    ld a, a
    jp $cec1


    ld a, a
    push bc
    sub $c5
    adc $7f
    call $d6cf
    ld d, l
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $c3cf

    bit 7, a
    call nc, $c1c8
    call nc, $c37f
    ld d, l
    pop bc
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    sub $c9
    push bc
    jp nc, $c27f

    ld d, l
    reti


    ld a, a
    db $d3
    ret z

    push bc
    push bc
    jp nc, $c17f

    adc $c9
    call $ccc1
    ld a, a
    db $d3
    call nc, $d255
    push bc
    adc $c7
    call nc, $81c8
    ld a, a
    ld d, a
    nop
    and a
    push de
    call z, $c3c9
    ret z

    ret


    and a
    push de
    call z, $c3c9
    ret z

    ret


    ld d, b
    nop
    ld a, a
    and c
    db $d3
    ret


    call z, $d2cf
    ld a, a
    ret


    db $d3
    ld a, a
    ret


    adc $d3
    push bc
    ret nc

    push bc
    ld c, a
    jp nc, $d4c1

    push bc
    call z, Call_025_7fd9
    add $d2
    rst $08
    call $d37f
    jp $c6d5


    add $55
    call z, $8cc5
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $d97f
    rst $08
    push de
    ld d, l
    ld a, a
    sbc a
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    xor h
    ret


    call nc, Call_025_4fd4
    call z, Call_025_7fc5
    jp nz, $d9cf

    adc h
    ld a, a
    call nz, $cecf
    add a
    call nc, $d97f
    rst $08
    push de
    ld d, l
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_025_7fc5
    pop bc
    ld a, a
    db $d3
    pop bc
    ret


    call z, $d2cf
    sbc a
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push bc
    ld a, a
    jp nz, $cccf

    call nz, $817f
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld c, a
    pop bc
    ld a, a
    adc $cf
    call nc, $c27f
    pop bc
    call nz, $c37f
    rst $08
    call $c5d0
    call nc, Call_025_55c9
    call nc, $cfc9
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push bc
    ld a, a
    jp nz, $cccf

    call nz, $817f
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld c, a
    pop bc
    ld a, a
    adc $cf
    call nc, $c27f
    pop bc
    call nz, $c37f
    rst $08
    call $c5d0
    call nc, Call_025_55c9
    call nc, $cfc9
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    jp $cdcf


    push bc
    add c
    ld a, a
    rst $10
    ret


    call nc, Call_025_7fc8
    call nc, $c84f
    push bc
    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    ld a, a
    rst $08
    add $7f
    db $d3
    pop bc
    ret


    call z, $cf55
    jp nc, Jump_025_7f81

    and d
    push bc
    call nc, Call_025_7f8c
    reti


    rst $08
    push de
    add a
    call z, Call_025_7fcc
    db $d3
    ld d, l
    push de
    jp nc, $ccc5

    reti


    ld a, a
    rst $10
    ret


    adc $8e
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    jp nc, $cdc5

    ret


    adc $c4
    ret


    adc $c7
    ld a, a
    call nc, Call_025_4fc8
    push bc
    ld a, a
    ret z

    pop bc
    jp nc, $cfc2

    push de
    jp nc, $cf7f

    add $7f
    call nz, $c9d2
    push bc
    ld d, l
    call nz, $cc7f
    push bc
    pop bc
    sub $c9
    push bc
    db $d3
    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc h
    ld a, a
    ld d, l
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    call z, Call_025_7fc4
    add $c9
    db $d3
    ret z

    ret


    adc $55
    rst $00
    ld a, a
    call $cec1
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c77f
    rst $08
    ret


    adc $c7
    ld d, l
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    ld a, a
    rst $08
    add $7f
    db $d3
    pop bc
    ld c, a
    ret


    call z, $d2cf
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, $d3cf
    call nc, $8155
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    ld a, a
    rst $08
    add $7f
    db $d3
    pop bc
    ld c, a
    ret


    call z, $d2cf
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, $d3cf
    call nc, $8155
    ld a, a
    ld e, b
    nop
    ld a, a
    and l
    sub $c5
    adc $7f
    call nc, $c5c8
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    pop bc
    rst $00
    push bc
    ld c, a
    jp nc, Jump_025_7f7f

    pop bc
    call z, $cfd3
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ld d, h
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor a
    push de
    jp nc, Jump_025_547f

    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, Call_025_7f4f
    jp $d5c1


    rst $00
    ret z

    call nc, $c27f
    reti


    ld a, a
    rst $08
    push de
    jp nc, $c5d3

    call z, $d655
    ret


    push bc
    db $d3
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_025_7fc5
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    ld d, l
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    ld d, l
    pop bc
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    ld c, a
    rst $10
    push bc
    call z, Call_025_7fcc
    ld e, b
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    ld c, a
    rst $10
    push bc
    call z, Call_025_7fcc
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    call nz, Call_025_7fcf
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    ret z

    push bc
    pop bc
    call z, $d44f
    ret z

    reti


    ld a, a
    jp nz, $d9cf

    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call Call_025_55c5
    ld a, a
    pop bc
    db $d3
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    add c
    ld a, a
    ld d, b
    ld d, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, h
    ld a, a
    rst $08
    add $7f
    db $d3
    push bc
    pop bc
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $d0c5
    call nc, $d3c8
    ld a, a
    rst $08
    ld d, l
    add $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    adc [hl]
    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    adc h
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    add a
    call nz, $c17f
    adc $c7
    call z, Call_025_7fc5
    ret


    call nc, $d77f
    ret


    ld d, l
    call nc, Call_025_7fc8
    pop bc
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    jp nc, $c4cf

    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    ret nc

    ret


    call nc, Call_025_7fd9
    add c
    ld a, a
    call z, Call_025_4fcf
    db $d3
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    ret nc

    ret


    call nc, Call_025_7fd9
    add c
    ld a, a
    call z, Call_025_4fcf
    db $d3
    call nc, Call_025_7f81
    ld e, b
    nop
    ld a, a
    and h
    pop bc
    call $c9cd
    call nc, Call_025_7f81
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, $c44f
    ld a, a
    jp nz, Jump_025_7fc5

    call nc, $d2c8
    rst $08
    rst $10
    push bc
    call nz, $c97f
    adc $d4
    rst $08
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    ret


    add $7f
    call z, $d3cf
    call nc, $5581
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp z, $ccc5

    call z, $c6d9
    ret


    db $d3
    ret z

    ld a, a
    ld c, a
    ld d, h
    ld a, a
    ld a, a
    call $d9c1
    ld a, a
    add $cc
    rst $08
    pop bc
    call nc, $c27f
    reti


    ld d, l
    ld a, a
    jp $c1c8


    adc $c3
    push bc
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_025_7fc5
    rst $00
    rst $08
    ret


    ld d, l
    adc $c7
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push de
    add $c6
    push bc
    jp nc, $cec9

    rst $00
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d4cf
    ld c, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    push de
    add $c6
    push bc
    jp nc, $cec9

    rst $00
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d4cf
    ld c, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    ld c, a
    rst $08
    jp nc, Jump_025_7f7f

    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ld d, l
    ret


    adc $8c
    ld a, a
    rst $10
    ret z

    ret


    jp Jump_025_7fc8


    call nc, $c5c8
    ld a, a
    adc $c5
    rst $10
    ld d, l
    ld a, a
    jp $cdcf


    push bc
    jp nc, $c27f

    push bc
    call z, $cecf
    rst $00
    db $d3
    ld a, a
    call nc, Call_025_55cf
    sbc a
    ld a, a
    xor l
    reti


    ld a, a
    ld a, a
    pop bc
    jp nc, Jump_025_7fc5

    pop bc
    call z, Call_025_7fcc
    add $d2
    rst $08
    ld d, l
    call $d47f
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    pop bc
    add c
    ld a, a
    ld d, a
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_025_7f4f:
Jump_025_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_025_7f55:
Jump_025_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_025_7f7f:
Jump_025_7f7f:
    nop
    nop

Call_025_7f81:
Jump_025_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_025_7f8c:
Jump_025_7f8c:
    nop
    nop

Call_025_7f8e:
Jump_025_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_025_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Jump_025_7fc3:
    nop

Call_025_7fc4:
Jump_025_7fc4:
    nop

Call_025_7fc5:
Jump_025_7fc5:
    nop

Call_025_7fc6:
    nop
    nop

Call_025_7fc8:
Jump_025_7fc8:
    nop
    nop
    nop

Jump_025_7fcb:
    nop

Call_025_7fcc:
    nop
    nop

Jump_025_7fce:
    nop

Call_025_7fcf:
Jump_025_7fcf:
    nop
    nop
    nop
    nop

Call_025_7fd3:
Jump_025_7fd3:
    nop

Call_025_7fd4:
Jump_025_7fd4:
    nop
    nop
    nop
    nop

Jump_025_7fd8:
    nop

Call_025_7fd9:
Jump_025_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
