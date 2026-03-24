; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $028", ROMX[$4000], BANK[$28]

    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call $cec1
    reti


    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    ld c, a
    push de
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, Call_028_7f9f
    xor c
    add a
    sub $c5
    ld a, a
    jp nz, Jump_028_55c5

    push bc
    adc $7f
    jp $d4c1


    jp $c9c8


    adc $c7
    ld a, a
    adc h
    ld a, a
    xor c
    add a
    call Call_028_7f55
    db $d3
    rst $08
    ld a, a
    call nc, $d2c9
    push bc
    call nz, Call_028_7f81
    ld d, a
    nop
    ld a, a
    or h
    rst $08
    ld a, a
    jp $d4c1


    jp Jump_028_7fc8


    reti


    rst $08
    push de
    jp nc, $cc7f

    push de
    ld c, a
    jp $81cb


    ld a, a
    or h
    ret z

    push de
    db $d3
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    adc $cf
    push de
    ld d, l
    rst $00
    ret z

    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_028_7fcf
    call $cbc1
    ld d, l
    push bc
    ld a, a
    call $cecf
    push bc
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret nc

    call z, $d9c1
    push bc
    ld c, a
    call nz, $d47f
    rst $08
    rst $08
    ld a, a
    pop bc
    jp $c9d4


    sub $c5
    adc h
    ld a, a
    adc $cf
    rst $10
    ld d, l
    ld a, a
    ret


    call nc, $d387
    ld a, a
    call nc, $d2c9
    push bc
    call nz, Call_028_7f81
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    call nz, $d3c9
    ld c, a
    jp $d2c1


    call nz, $c4c5
    ld a, a
    ret nc

    jp nc, $d0cf

    db $d3
    ld a, a
    ld a, a
    ret z

    rst $08
    call $c555
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    push de
    adc $d4
    ld a, a
    add [hl]
    ld a, a
    call nc, $d255
    pop bc
    sub $c5
    call z, $c17f
    jp nc, $c1c5

    ld a, a
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    ret


    call nc, $cc87
    call z, $d77f
    pop bc
    db $d3
    call nc, Call_028_7fc5
    reti


    rst $08
    push de
    jp nc, $557f

    pop bc
    call z, Call_028_7fcc
    call nc, $cdc9
    push bc
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    ret nc

    ld d, l
    ret


    jp Jump_028_7fcb


    call nc, $cfcf
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ld a, a
    push de
    ret nc

    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    rst $10
    adc h
    ld a, a
    ret


    call nc, $d387
    ld a, a
    pop bc
    call nz, $c5d6
    jp nc, Jump_028_4fd4

    ret


    db $d3
    ret


    adc $c7
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ld d, l
    ret z

    pop bc
    call nc, $d47f
    ret z

    push bc
    jp nc, Jump_028_7fc5

    ret


    db $d3
    ld a, a
    call nz, $d3c9
    call nc, $d255
    ret


    jp nz, $d4d5

    ret


    adc $c7
    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    db $d3
    ld a, a
    ret


    ld d, l
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    call $ccc1
    call z, $c87f
    rst $08
    push de
    db $d3
    push bc
    ld d, l
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call $d3cf
    call nc, $c97f
    adc $ce
    push bc
    ld d, l
    jp nc, $cf7f

    add $7f
    call nc, $c5c8
    ld a, a
    pop bc
    jp nc, $c1c5

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    xor l
    reti


    ld a, a
    reti


    push bc
    push bc
    jp nz, $c87f

    pop bc
    db $d3
    ld a, a
    push bc
    sub $cf
    call z, $4fd5
    call nc, $c4c5
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    pop bc
    ld a, a
    jp nz, $cfcf

    db $d3
    call nc, Call_028_55c5
    jp nc, Jump_028_7f81

    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    ld a, a
    ld a, a
    rst $08
    add $7f
    add $d2
    ld d, l
    ret


    push bc
    adc $c4
    add a
    db $d3
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    push bc
    sub $cf
    call z, $d4d5
    ld d, l
    push bc
    call nz, $c97f
    adc $d4
    rst $08
    ld a, a
    pop bc
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ret


    adc $c7
    ld d, l
    ld a, a
    ret z

    push bc
    pop bc
    sub $d9
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    push bc
    jp nc, $c88c

    pop bc
    db $d3
    ld d, l
    adc $87
    call nc, $c97f
    call nc, Call_028_7f9f
    ld d, a
    nop
    ld a, a
    call $c1c9
    rst $08
    rst $10
    ld a, a
    ld d, b
    nop
    ld a, a
    call $c1c9
    rst $08
    rst $10
    ld a, a
    ld d, b
    nop
    ld a, a
    call $c1c9
    rst $08
    rst $10
    ld a, a
    ld d, b
    nop
    ld a, a
    call $c1c9
    rst $08
    rst $10
    ld a, a
    ld d, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    jp $d5cf


    call nc, $c77f
    ret


    jp nc, $d3cc

    ld a, a
    ld c, a
    pop bc
    jp nc, Jump_028_7fc5

    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ld d, l
    ret


    adc $7f
    adc [hl]
    ld a, a
    db $d3
    jp $d4c1


    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    db $d3
    call z, $cec5
    call nz, $d2c5
    ld a, a
    jp nz, $c1d2

    adc $c3
    ret z

    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c1cf

    call nz, $c17f
    db $d3
    ld a, a
    pop bc
    ld d, l
    ld a, a
    db $d3
    ret


    rst $00
    adc $7f
    ret


    adc $7f
    rst $08
    jp nc, $c5c4

    jp nc, $ce7f

    rst $08
    ld d, l
    call nc, $d47f
    rst $08
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    call nc, $c5c8
    ret


    jp nc, $d77f

    ld d, l
    pop bc
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, $c17f
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    or a
    push bc
    add a
    call nz, Call_028_7f4f
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    rst $00
    rst $08
    ld a, a
    ret z

    rst $08
    call Call_028_7fc5
    call nc, $cf55
    call nz, $d9c1
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    adc $d5
    ret


    db $d3
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    add a
    sub $4f
    push bc
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call Call_028_7fd9
    jp nz, $d3c5

    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    adc $d5
    ret


    db $d3
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    add a
    sub $4f
    push bc
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call Call_028_7fd9
    jp nz, $d3c5

    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    add c
    ld a, a
    and e
    pop bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, $c54f
    add $c5
    pop bc
    call nc, $cd7f
    reti


    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, Jump_028_7f9f

    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    jp nc, $c7c9

    ret


    call nz, $cc4f
    reti


    ld a, a
    pop bc
    call nz, $c5c8
    jp nc, Jump_028_7fc5

    call nc, Call_028_7fcf
    ret nc

    rst $08
    rst $10
    push bc
    ld d, l
    jp nc, $8e7f

    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $c27f
    push bc
    ld d, l
    jp $d5c1


    db $d3
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, $cec5

    add a
    call nc, $557f
    rst $00
    rst $08
    rst $08
    call nz, $c17f
    call nc, $d47f
    ret z

    ret


    adc $cb
    ret


    adc $c7
    ld a, a
    ld d, l
    rst $10
    ret z

    ret


    call z, Call_028_7fc5
    jp $cdcf


    ret nc

    push bc
    call nc, $cec9
    rst $00
    ld a, a
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, Jump_028_7f8c

    call z, $d3cf
    ld c, a
    call nc, Call_028_7f9f
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, Jump_028_7f8c

    call z, $d3cf
    ld c, a
    call nc, Call_028_7f9f
    ld e, b
    nop
    ld a, a
    and c
    jp nc, Jump_028_7fc5

    reti


    rst $08
    push de
    ld a, a
    jp $cdcf


    ret nc

    ret


    call z, $cec9
    ld c, a
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld d, l
    ld a, a
    ret z

    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    ld d, h
    sbc a
    ld a, a
    db $d3
    bit 2, l
    push de
    adc $cb
    add c
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    ld d, l
    call nc, Call_028_7fcf
    call nz, Call_028_7fcf
    ret


    call nc, Call_028_7f81
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    rst $08
    ld a, a
    adc h
    ld a, a
    and e
    pop bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    rst $00
    ret


    sub $c5
    ld a, a
    ret


    call nc, $d47f
    rst $08
    ld a, a
    call Call_028_7fc5
    ret


    add $7f
    ld d, l
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    add $c9
    adc $c9
    db $d3
    ret z

    push bc
    call nz, $c37f
    ld d, l
    rst $08
    call $c9cc
    ret nc

    push bc
    sbc a
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
    call $d37f
    rst $08
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_028_4fd9

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
    call $d37f
    rst $08
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_028_4fd9

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, Call_028_567f
    call nz, $c5cf
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    bit 1, a
    adc $cf
    rst $10
    ld a, a
    xor e
    push bc
    jp nc, $c5d3

    jp nz, $ccd5

    reti


    ld a, a
    ld d, l
    ld d, h
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
    rst $08
    adc l
    jp $ccc1


    call z, $c4c5
    ld a, a
    xor e
    push bc
    ld c, a
    jp nc, $c5d3

    jp nz, $ccd5

    reti


    ld a, a
    ret


    db $d3
    ld a, a
    call $c4c1
    push bc
    ld a, a
    ld a, a
    ld d, l
    jp nz, Jump_028_7fd9

    or b
    ret


    ret nc

    ret


    ld a, a
    ret nc

    call z, $d9c1
    call nc, $c9c8
    adc $c7
    ld d, l
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $cbc9
    push bc
    adc h
    ld a, a
    pop bc
    ld d, l
    db $d3
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    db $d3
    ld a, a
    call nc, $cfd7
    ld a, a
    ret nc

    push bc
    pop bc
    ld d, l
    db $d3
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $d47f
    pop bc
    jp $cccb


    push bc
    ld a, a
    call nc, $c84f
    ret


    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $d47f
    pop bc
    jp $cccb


    push bc
    ld a, a
    call nc, $c84f
    ret


    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call z, Call_028_7fcc
    call z, $d4c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nz, Jump_028_7fc5

    ld c, a
    pop bc
    ld a, a
    jp nc, $c1c5

    call z, $c57f
    reti


    push bc
    rst $08
    ret nc

    push bc
    adc $c5
    jp nc, $557f

    add $cf
    jp nc, $cd7f

    reti


    ld a, a
    ld a, a
    ld d, h
    ld a, a
    db $d3
    set 1, c
    call z, $55cc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $08
    add $7f
    jp $d5cf


    jp nc, $c5d3

    add c
    ld a, a
    ld d, [hl]
    call nc, $cfcf
    ld c, a
    ld a, a
    call $cec1
    reti


    ld a, a
    jp nc, $c3cf

    bit 7, a
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    ld d, l
    add $7f
    pop bc
    call $cecf
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $d4
    ld d, l
    pop bc
    ret


    adc $d9
    ld a, a
    ld d, h
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
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, $814f

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    push bc
    sub $c5
    adc $7f
    pop bc
    adc $7f
    push bc
    ret c

    ret nc

    ld d, l
    push bc
    jp nc, $8ed4

    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, $814f

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    push bc
    sub $c5
    adc $7f
    pop bc
    adc $7f
    push bc
    ret c

    ret nc

    ld d, l
    push bc
    jp nc, $8ed4

    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    ret nc

    jp nc, $c2cf

    call z, $cdc5
    ld a, a
    push bc
    sub $c5
    adc $7f
    ld c, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    pop bc
    ld a, a
    jp $cf55


    call $c5d0
    call nc, $d4c9
    ret


    rst $08
    adc $8c
    jp nz, $d4d5

    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $cf7f
    add $d4
    push bc
    adc $55
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    ret z

    push bc
    jp nc, $8ec5

    ld a, a
    ld d, a
    add c
    ld a, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call $ccc1
    call z, Call_028_547f
    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    call nz, $d3c5
    ret


    jp nc, $c2c1

    call z, Call_028_7fc5
    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    ld a, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    jp nz, $d2cf

    ret


    adc $c7
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $55
    ld a, a
    ret


    call nc, Call_028_7fd3
    call nc, $cfcf
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ret


    jp $8155


    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    or d
    push de
    db $d3
    ret z

    ld a, a
    rst $08
    push de
    call nc, $c97f
    add $7f
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    rst $10
    push bc
    jp nc, Jump_028_7fc5

    pop bc
    ld a, a
    call $cec1
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    ld a, a
    ld c, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    jp nz, Jump_028_7fd9

    call nc, $c5c8
    ld a, a
    call z, $c955
    call nc, $ccd4
    push bc
    ld a, a
    jp nz, $d9cf

    ld a, a
    call nc, Call_028_7fcf
    add $cf
    db $d3
    call nc, $c555
    jp nc, Jump_028_547f

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    rst $08
    adc $c7
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    rst $08
    adc $c5
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    rst $08
    adc $c7
    add c
    ld a, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    xor c
    ld a, a
    jp $cec1


    ld c, a
    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, Jump_028_7f81

    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call nz, $c5d2
    rst $10
    ld a, a
    db $d3
    rst $08
    call Call_028_4fc5
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $cfc9
    adc $7f
    ld d, l
    ld d, h
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $cbc9
    push bc
    ld d, l
    ld a, a
    rst $10
    ret z

    call z, $c5c9
    ld a, a
    xor c
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    pop bc
    call nc, $c87f
    ld d, l
    rst $08
    call Call_028_7fc5
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $ce7f
    rst $08
    call nc, $d37f
    push de
    ret


    call nc, $c4c5
    ld a, a
    call nc, $cf4f
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    xor c
    ld a, a
    jp nc, $c155

    call nc, $c5c8
    jp nc, $c47f

    jp nc, $d7c1

    ret


    adc $c7
    ld a, a
    call nc, $c1c8
    ld d, l
    adc $7f
    call nz, $c9cf
    adc $c7
    ld a, a
    db $d3
    rst $08
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    xor c
    add a
    call $d37f
    rst $08
    ld a, a
    call nc, $d2c9
    ld c, a
    push bc
    call nz, Call_028_7f8e
    ld e, b
    nop
    ld a, a
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    xor c
    add a
    call $d37f
    rst $08
    ld a, a
    call nc, $4fc9
    jp nc, $c4c5

    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    rst $08
    push de
    rst $00
    ret z

    ld a, a
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $cc
    ld c, a
    reti


    ld a, a
    pop bc
    ld a, a
    jp nz, $d9cf

    adc h
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_028_7f7f

    ld d, l
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $ccc5

    push de
    jp $c1d4


    adc $d4
    ld a, a
    ld d, l
    call nc, Call_028_7fcf
    call z, $c1c5
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    adc [hl]
    ld a, a
    ld d, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    add $cf
    db $d3
    call nc, Call_028_4fc5
    jp nc, Jump_028_547f

    ld a, a
    add $d2
    rst $08
    call $d97f
    rst $08
    push de
    jp nc, $cf7f

    ld d, l
    call z, Call_028_7fc4
    pop bc
    rst $00
    push bc
    db $d3
    ld a, a
    adc $cf
    rst $10
    ld a, a
    adc h
    ld a, a
    xor c
    ld a, a
    jp $c155


    adc $7f
    call nz, Call_028_7fcf
    ld a, a
    adc h
    ld a, a
    call nc, $cfcf
    add c
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_028_7f81
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_028_7f81
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_028_547f

    ld a, a
    ld a, a
    ld d, [hl]
    ld a, a
    ret z

    pop bc
    db $d3
    ld c, a
    ld a, a
    rst $10
    push bc
    pop bc
    set 1, [hl]
    push bc
    db $d3
    db $d3
    add c
    ld a, a
    xor c
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    ld d, l
    call z, Call_028_7fc4
    rst $10
    ret


    adc $7f
    ret


    add $7f
    pop bc
    call nc, $c1d4
    jp $c9cb


    ld d, l
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    or h
    ret z

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    add $c1
    jp Jump_028_7fd4


    pop bc
    db $d3
    ld a, a
    call z, $4fcf
    adc $c7
    ld a, a
    pop bc
    db $d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call nc, $c1d4
    jp Jump_028_7fcb


    ld d, l
    ret z

    ret


    db $d3
    ld a, a
    rst $10
    push bc
    pop bc
    set 1, [hl]
    push bc
    db $d3
    db $d3
    ld a, a
    xor c
    call nc, $d77f
    ld d, l
    rst $08
    adc $87
    call nc, $d77f
    ret


    adc $81
    ld a, a
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, Call_028_7f55
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    rst $10
    ret z

    push bc
    call nc, $c5c8
    jp nc, $d47f

    ret z

    push bc
    ld d, l
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call Call_028_55c5
    ld a, a
    pop bc
    db $d3
    ld a, a
    call nc, $c1c8
    call nc, Call_028_7f81
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call z, $d3cf
    call nc, $c27f
    push bc
    add $4f
    rst $08
    jp nc, Jump_028_7fc5

    xor c
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $c87f
    ret


    db $d3
    ld a, a
    ld d, l
    rst $10
    push bc
    pop bc
    set 1, [hl]
    push bc
    db $d3
    db $d3
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call z, $d3cf
    call nc, $c27f
    push bc
    add $4f
    rst $08
    jp nc, Jump_028_7fc5

    xor c
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $c87f
    ret


    db $d3
    ld a, a
    ld d, l
    rst $10
    push bc
    pop bc
    set 1, [hl]
    push bc
    db $d3
    db $d3
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    pop bc
    call $a97f
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    ld c, a
    adc $c5
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    add $cf
    push de
    jp nc, $cd7f

    ret


    ld d, l
    db $d3
    db $d3
    ret


    call z, Call_028_7fc5
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, $81d3

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    jp $d2c5


    call nc, $c9c1
    adc $cc
    reti


    add c
    ld a, a
    xor l
    ld c, a
    reti


    ld a, a
    reti


    rst $08
    push de
    adc $c7
    push bc
    jp nc, $c27f

    jp nc, $d4cf

    ret z

    push bc
    jp nc, Jump_028_7f55

    call $d9c1
    ld a, a
    jp nc, $d6c5

    push bc
    adc $c7
    push bc
    ld a, a
    add $cf
    jp nc, $557f

    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_028_7f81
    call z, $d3cf
    call nc, Call_028_7f8c
    call Call_028_7fd9
    jp nz, Jump_028_4fd2

    rst $08
    call nc, $c5c8
    jp nc, Jump_028_7f81

    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_028_7f81
    call z, $d3cf
    call nc, Call_028_7f8c
    call Call_028_7fd9
    jp nz, Jump_028_4fd2

    rst $08
    call nc, $c5c8
    jp nc, Jump_028_7f81

    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    call nc, $ce4f
    push bc
    call nc, Call_028_7fc8
    add $cc
    rst $08
    rst $08
    jp nc, Jump_028_7f81

    xor c
    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    adc $cf
    call nc, $c57f
    pop bc
    db $d3
    reti


    ld a, a
    call nc, Call_028_7fcf
    jp $cdcf


    push bc
    ld d, l
    ld a, a
    ret z

    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_028_7fc5

    ret nc

    jp nc, $c9c1

    db $d3
    push bc
    rst $10
    rst $08
    ld c, a
    jp nc, $c8d4

    reti


    ld a, a
    call nc, Call_028_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    jp $cdcf


    push bc
    ld d, l
    ld a, a
    ret z

    push bc
    jp nc, Jump_028_7fc5

    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $cfcf

    ld d, l
    call Call_028_7f7f
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $55
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    jp $c5c9


    call nc, Call_028_7fd9
    ret


    db $d3
    ld a, a
    rst $08
    ld d, l
    adc $7f
    call nc, $c5c8
    ld a, a
    push de
    ret nc

    ret nc

    push bc
    jp nc, $c67f

    call z, $cfcf
    jp nc, $5755

    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $cec1


    ld a, a
    ret


    call nc, $c27f
    push bc
    ld a, a
    db $d3
    rst $08
    ld c, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $cec1


    ld a, a
    ret


    call nc, $c27f
    push bc
    ld a, a
    db $d3
    rst $08
    ld c, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld e, b
    or h
    ret z

    push bc
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    db $d3
    ret z

    ld c, a
    rst $08
    push de
    call z, Call_028_7fc4
    jp nz, Jump_028_7fc5

    push bc
    adc $c4
    push bc
    call nz, Call_028_7f81
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_028_7fc4
    jp nz, Jump_028_7fc5

    db $d3
    pop bc
    ld c, a
    call nc, $d3c9
    add $c9
    push bc
    call nz, $c67f
    rst $08
    jp nc, $c87f

    pop bc
    sub $c9
    adc $55
    rst $00
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    call $81c5
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    adc $8c
    ld a, a
    call nz, $cecf
    add a
    call nc, $c77f
    rst $08
    ld a, a
    jp nz, $c3c1

    bit 2, l
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
    or a
    push bc
    call z, $81cc
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $d2c1
    reti


    ld a, a
    sbc d
    xor c
    add a
    call $d37f
    ld c, a
    rst $08
    ld a, a
    pop bc
    ret nc

    ret nc

    jp nc, $c3c5

    ret


    pop bc
    call nc, $c4c5
    ld a, a
    ld a, a
    add $cf
    ld d, l
    jp nc, $d97f

    rst $08
    push de
    jp nc, $c87f

    push bc
    call z, Call_028_7fd0
    adc [hl]
    ld a, a
    and c
    db $d3
    ld a, a
    ld d, l
    pop bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    jp $c955


    push bc
    call nc, Call_028_7fd9
    call Call_028_7fd9
    ret z

    push bc
    pop bc
    jp nc, Jump_028_7fd4

    ret


    db $d3
    ld a, a
    ld d, l
    add $d5
    call z, Call_028_7fcc
    rst $08
    add $7f
    ret


    adc $c4
    push bc
    jp nz, $c5d4

    call nz, Call_028_55ce
    push bc
    db $d3
    db $d3
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    and c
    jp nc, Jump_028_7fc5

    reti


    rst $08
    push de
    ld a, a
    ld c, a
    ld d, d
    sbc a
    ld a, a
    or a
    push bc
    ld a, a
    call $c5c5
    call nc, $c17f
    rst $00
    ld d, l
    pop bc
    ret


    adc $81
    ld a, a
    xor c
    add a
    call $c87f
    pop bc
    sub $c9
    adc $c7
    ld a, a
    pop bc
    ld d, l
    ld a, a
    call nc, $ccc1
    bit 7, a
    rst $10
    ret


    call nc, Call_028_7fc8
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    ld d, l
    pop bc
    call nz, $cf7f
    add $7f
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    db $d3
    rst $08
    jp $c955


    push bc
    call nc, Call_028_7fd9
    pop bc
    jp nz, $d5cf

    call nc, $d77f
    rst $08
    jp nc, $c9cb

    adc $55
    rst $00
    ld a, a
    call $d4c1
    call nc, $d2c5
    db $d3
    adc [hl]
    ld a, a
    xor c
    ld a, a
    rst $10
    ret


    db $d3
    ret z

    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    push de
    call nc, $d97f
    rst $08
    push de
    jp nc, $cd7f

    rst $08
    ld d, l
    push de
    call nc, Call_028_7fc8
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    call nz, $ccd5
    call nc, $557f
    rst $10
    rst $08
    jp nc, $c4cc

    add c
    ld a, a
    xor c
    add a
    call nz, $c77f
    ret


    sub $c5
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    rst $00
    pop bc
    jp nc, Jump_028_7fc4

    call nc, $cdc9
    push bc
    ld a, a
    ret


    add $55
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $c47f
    rst $08
    ld a, a
    pop bc
    db $d3
    ld a, a
    ld d, l
    xor c
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    ld d, [hl]
    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    ld c, a
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    call $d4c5
    ret z

    rst $08
    call nz, $b781
    push bc
    add a
    ld d, l
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $c17f

    jp nz, $cec1

    call nz, $cecf
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    xor b
    ret


    call z, $d5cc
    add $c6
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    xor a
    push de
    jp nc, Jump_028_5e7f

    ld a, a
    ret


    db $d3
    ld a, a
    ret


    call $cd55
    rst $08
    jp nc, $c1d4

    call z, $817f
    ld a, a
    ld d, d
    add c
    ld a, a
    and h
    ld d, l
    rst $08
    adc $87
    call nc, $c67f
    rst $08
    jp nc, $c5c7

    call nc, $c17f
    call z, Call_028_7fcc
    call nc, $c855
    push bc
    ld a, a
    ld d, h
    add $cf
    jp nc, Jump_028_7f7f

    push bc
    ret c

    ret


    db $d3
    call nc, Call_028_55d3
    ret


    adc $c7
    ld a, a
    add $cf
    jp nc, Jump_028_5e7f

    add c
    ld a, a
    ld d, l
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    add c
    ld a, a
    xor h
    push bc
    call nc, $cd7f
    push bc
    ld a, a
    rst $10
    ld d, l
    ret


    call nc, $c4c8
    jp nc, $d7c1

    add c
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
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    ld c, a
    call $d6cf
    push bc
    call $cec5
    call nc, Call_028_7f81
    and h
    rst $08
    adc $87
    call nc, $c77f
    ld d, l
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, $a97f
    add a
    sub $c5
    ld a, a
    db $d3
    pop bc
    ret


    call nz, Call_028_7f55
    call nc, Call_028_7fcf
    reti


    rst $08
    push de
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, a
    nop
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    sbc a
    ld a, a
    reti


    rst $08
    push de
    add a
    call z, Call_028_7fcc
    call $c54f
    push bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_028_7f8c
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld c, a
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_028_7f8c
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld c, a
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    or a
    ld c, a
    ret z

    pop bc
    call nc, $d387
    ld a, a
    call nc, $c5c8
    ld a, a
    call $d4c1
    call nc, $d2c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_028_7fcf
    call $c5c5
    call nc, $557f
    call nc, $c5c8
    ld a, a
    jp nz, $d3cf

    db $d3
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    push bc
    call z, Call_028_7fcc
    reti


    rst $08
    push de
    ld a, a
    add $c9
    jp nc, $d4d3

    call z, Call_028_4fd9
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    ret c

    pop bc
    jp $d455


    call z, Call_028_7fd9
    db $d3
    call nc, $cfd2
    adc $c7
    adc [hl]
    ld a, a
    and c
    adc $d9
    ret z

    rst $08
    ld d, l
    rst $10
    adc h
    ld a, a
    jp nz, Jump_028_7fc5

    jp $d2c1


    push bc
    add $d5
    call z, Call_028_7f81
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    jp $cec1


    ld a, a
    jp nz, Jump_028_7fc5

    ret z

    ld c, a
    push bc
    pop bc
    jp nc, $8ec4

    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c67f
    call z, $c5c5
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    call nc, Call_028_7fcf
    pop bc
    call z, $c9cc
    pop bc
    ld c, a
    adc $c3
    push bc
    ld a, a
    ld d, h
    add c
    ld a, a
    xor c
    add a
    call $ab7f
    pop bc
    adc $ce
    ld d, l
    pop bc
    adc h
    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    and d
    push de
    call nz, $c455
    ret z

    pop bc
    add a
    db $d3
    ld a, a
    sub h
    ld a, a
    rst $10
    pop bc
    jp nc, $c9d2

    rst $08
    jp nc, $c17f

    ld d, l
    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    db $d3
    add c

Call_028_4fc5:
Jump_028_4fc5:
    ld a, a
    xor [hl]
    rst $08

Call_028_4fc8:
    jp nz, $c4cf

    reti


Jump_028_4fcc:
    ld d, l
    ld a, a
    jp $cec1


    ld a, a

Jump_028_4fd2:
    rst $10
    ret


Call_028_4fd4:
Jump_028_4fd4:
    adc $7f
    call Call_028_7fc5

Call_028_4fd9:
Jump_028_4fd9:
    ret


    add $7f
    xor c
    ld a, a
    ld d, l
    push de
    db $d3
    push bc
    ld a, a
    add $d2
    rst $08
    jp c, $cec5

    ld a, a
    ld d, h
    add c
    xor c
    call nc, $8755
    db $d3
    ld a, a
    pop bc
    ld a, a
    sub $c5
    jp nc, Jump_028_7fd9

    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld d, l
    db $d3
    set 1, c
    call z, Call_028_7fcc
    call nc, Call_028_7fcf
    add $d2
    ret


    jp c, Jump_028_7fc5

    call nc, Call_028_55c8
    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    add c
    ld a, a
    xor a
    adc $c3
    push bc
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_028_547f

    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $d2
    ld d, l
    rst $08
    jp c, $cec5

    ld a, a
    adc h
    ld a, a
    ret z

    push bc
    ld a, a
    rst $10
    ret


    call z, Call_028_7fcc
    adc $cf
    ld d, l
    call nc, $cd7f
    rst $08
    sub $c5
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call $d2cf

Call_028_5055:
Jump_028_5055:
    push bc
    add c
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    adc $8c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret nc

    jp nc, $d0c5

    ld d, l
    pop bc
    jp nc, $c4c5

    ld a, a
    call $cec5
    call nc, $ccc1
    call z, $9fd9
    ld a, a
    ld d, a
    nop
    ld a, a
    xor h
    rst $08
    rst $08
    set 2, e
    ld a, a
    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    add c
    ld a, a
    ld c, a
    or l
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    and a
    rst $08
    ld d, l
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, $d47f
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    adc $c5
    ret c

    ld d, l
    call nc, $d27f
    rst $08
    rst $08
    call Call_028_7f81
    ld d, [hl]
    ld a, a
    ret


    db $d3
    adc $87
    call nc, $557f
    rst $08
    adc $cc
    reti


    ld a, a
    db $d3
    push de
    jp Jump_028_7fc8


    pop bc
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    ld d, l
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, $cf7f

    add $7f
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    reti


    push bc
    call nc, Call_028_7f81
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    or a
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c5
    ld c, a
    call z, $cfcc
    rst $10
    sbc a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    or a
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c5
    ld c, a
    call z, $cfcc
    rst $10
    sbc a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $c44f

    ld a, a
    ld d, [hl]
    and h
    rst $08
    adc $87
    call nc, $c67f
    call z, $c5c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d37f
    ret


    jp nz, $8cc1

    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $4f
    ld a, a
    call nc, $c5c8
    ld a, a
    and d
    push de
    call nz, $c8c4
    pop bc
    add a
    db $d3
    ld a, a
    sub h
    ld a, a
    rst $10
    ld d, l
    pop bc
    jp nc, $c9d2

    rst $08
    jp nc, $c17f

    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    db $d3
    ld d, l
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    pop bc
    jp nc, $c555

    adc h
    ld a, a
    call $cec1
    ld a, a
    rst $08
    jp nc, Jump_028_547f

    ld a, a
    adc h
    ld a, a
    call $c155
    reti


    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_028_7fc5
    ret z

    rst $08
    rst $10
    push bc
    sub $c5
    jp nc, Jump_028_7f55

    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld d, l
    rst $08
    adc $cc
    reti


    ld a, a
    call nc, $cdc5
    ret nc

    push bc
    jp nc, $cec9

    rst $00
    ld a, a
    ld a, a
    call nc, $c855
    jp nc, $d5cf

    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $c955
    call nc, $cfc9
    adc $81
    ld a, a
    or h
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    push bc
    db $d3
    jp $d0c1


    ret


    adc $c7
    ld a, a
    add $d2
    rst $08
    call Call_028_7f55
    call nc, $c5c8
    ld a, a
    call nc, $cdc5
    ret nc

    push bc
    jp nc, $cec9

    rst $00
    ld a, a
    pop bc
    adc $55
    call nz, $a97f
    ld a, a
    db $d3
    push de
    jp nc, $c9d6

    sub $c5
    call nz, Call_028_7f81
    and c
    adc $c4
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $ce7f
    rst $08
    rst $10
    ld a, a
    rst $08
    adc $8c
    ld a, a
    rst $10
    push bc
    adc h
    ld d, l
    call nc, $cfcf
    add c
    ld a, a
    xor l
    push bc
    adc $d4
    ret


    rst $08
    adc $7f
    ret


    call nc, $d47f
    ld d, l
    rst $08
    ld a, a
    ld d, d
    sbc a
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    call nc, Call_028_55d2
    reti


    ld a, a
    rst $08
    push de
    jp nc, $d37f

    push de
    ret nc

    push bc
    jp nc, $c17f

    jp nz, $ccc9

    ret


    ld d, l
    call nc, $81d9
    ld a, a
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call z, Call_028_7fcc
    jp nz, Jump_028_7fc5

    call nz, $cecf
    push bc
    ld a, a
    add $cf
    jp nc, Jump_028_7f4f

    ret


    add $7f
    xor c
    ld a, a
    call z, $d3cf
    call nc, $817f
    ld a, a
    db $d3
    set 2, l
    adc $55
    res 0, c
    ld a, a
    and [hl]
    rst $08
    call z, $cfcc
    rst $10
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    ret z

    ld d, l
    ret


    db $d3
    ld a, a
    ret z

    push bc
    push bc
    call z, $81d3
    ld a, a
    ld d, a
    or a
    ret z

    pop bc
    call nc, $d387
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, Call_028_7f9f
    ld d, [hl]
    ld a, a
    ld c, a
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    rst $10
    ret z

    reti


    ld a, a
    ld d, l
    xor c
    ld a, a
    call z, $d3cf
    call nc, Call_028_7f81
    ld e, b
    or a
    ret z

    pop bc
    call nc, $d387
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, Call_028_7f9f
    ld d, [hl]
    ld a, a
    ld c, a
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    rst $10
    ret z

    reti


    ld a, a
    ld d, l
    xor c
    ld a, a
    call z, $d3cf
    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $c44f

    ld a, a
    ld d, [hl]
    and h
    rst $08
    adc $87
    call nc, $c67f
    call z, $c5c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $a37f
    ret z

    ret


    jp $cbcf


    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ld c, a
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    and d
    push de
    call nz, $c8c4
    pop bc
    ld d, l
    add a
    db $d3
    ld a, a
    sub h
    ld a, a
    rst $10
    pop bc
    jp nc, $c9d2

    rst $08
    jp nc, $c17f

    call nc, $c5d4
    ld d, l
    adc $c4
    pop bc
    adc $d4
    db $d3
    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $c455

    ld a, a
    call nc, $c1c8
    call nc, $d97f
    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_028_7fc5

    ret


    adc $55
    ld a, a
    call nc, $c1c8
    call nc, $cf7f
    call z, Call_028_7fc4
    call $cec1
    ld a, a
    and c
    adc $c3
    ld d, l
    ret z

    ret


    call nz, $d2c5
    add a
    db $d3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c77f
    jp nc, $c3c1

    ld d, l
    push bc
    db $d3
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call z, $c4cf
    ld a, a
    call $cec1
    ld a, a
    rst $10
    ld d, l
    pop bc
    db $d3
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    ld d, l
    jp nc, Jump_028_7fd9

    pop bc
    adc $c4
    ld a, a
    sub $c5
    jp nc, Jump_028_7fd9

    db $d3
    call nc, $cfd2
    adc $55
    rst $00
    ld a, a
    call $cec1
    ld a, a
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    adc $cf
    rst $10
    ld a, a
    ret z

    ld d, l
    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_028_7fc5
    adc $cf
    jp nz, Jump_028_55cf

    call nz, $81d9
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    adc $cf
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    ld d, l
    adc $cc
    reti


    ld a, a
    jp $cdcf


    ret nc

    ret


    call z, $cec9
    rst $00
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    adc $c4
    ld d, l
    jp nz, $cfcf

    bit 7, a
    ld d, h
    ld a, a
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    ld d, l
    rst $08
    push de
    call z, Call_028_7fc4
    call z, $d4c5
    ld a, a
    ld d, h
    ld a, a
    jp $cdcf


    ret nc

    ld d, l
    push bc
    call nc, $8ec5

Call_028_547f:
Jump_028_547f:
    ld a, a
    ld d, d
    ld d, [hl]
    add c
    ld a, a
    xor c
    add a
    call z, $cc55
    ld a, a
    call nc, $c1c5
    jp Jump_028_7fc8


    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $557f
    call nc, $c5c8
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ld d, l
    ret


    rst $08
    adc $7f
    ld a, a
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    rst $10
    ret


    adc $4f
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    call z, Call_028_7fc4
    call $cec1
    ld d, l
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    adc $cf
    call nc, $c955
    jp $c1c5


    jp nz, $cccc

    reti


    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ret nc

    ld d, l
    rst $08
    ret


    adc $d4
    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ret z

    pop bc
    call nz, $ce7f
    rst $08
    ld d, l
    call nc, $c9c8
    adc $c7
    ld a, a
    call nc, Call_028_7fcf
    db $d3
    pop bc
    reti


    add c
    ld a, a
    rst $00
    rst $08
    ld a, a
    ld d, l
    call nc, Call_028_7fcf
    adc $c5
    ret c

    call nc, $d27f
    rst $08
    rst $08
    call Call_028_7f81
    ld d, a
    nop
    ld a, a
    and c
    ret z

    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c44f

    ret


    adc $c1
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c44f

    ret


    adc $c1
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld c, a
    jp nc, Jump_028_7fc5

    reti


Jump_028_5581:
    rst $08
    push de
    ld a, a
    call z, $cfcf
    set 1, c
    adc $c7
    ld a, a
    add $cf
    ld d, l
    jp nc, Jump_028_7f9f

    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, Call_028_7fc8
    pop bc
    rst $00
    pop bc
    ld d, l
    ret


    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push bc
    db $d3
    ret


    call nz, Call_028_7fc5
    call nc, $c5c8
    ld a, a
    ld d, h
    call nc, Call_028_4fc8
    push bc

Jump_028_55c1:
    jp nc, Jump_028_7fc5

Call_028_55c4:
    ret


Call_028_55c5:
Jump_028_55c5:
    db $d3
    adc $87

Call_028_55c8:
Jump_028_55c8:
    call nc, $c17f
    adc $d9
    ld a, a

Call_028_55ce:
    ld d, l

Call_028_55cf:
Jump_028_55cf:
    ld d, h
    ld a, a
    rst $10

Call_028_55d2:
    ret z

Call_028_55d3:
Jump_028_55d3:
    rst $08
    ld a, a
    jp $cec1


    ld a, a

Call_028_55d9:
Jump_028_55d9:
    jp $cdcf


    ret nc

    push bc
    ld d, l
    call nc, $81c5
    ld a, a
    and d
    push bc
    add $cf
    jp nc, Jump_028_7fc5

    call nc, $c5c8
    ld a, a
    ld d, l
    ld d, d
    xor c
    call nc, $d387
    ld a, a
    db $d3
    rst $08
    ld a, a
    call nz, $cdc9
    add c
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    add $c6
    push bc
    jp Jump_028_7fd4


    rst $08
    add $7f
    db $d3
    ret nc

    ld c, a
    jp nc, $d9c1

    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $00
    rst $08
    adc $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    add $cf
    push de
    adc $4f
    call nz, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
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
    ret nc

    rst $08
    jp nc, $c1d4

    jp nz, Jump_028_4fcc

    push bc
    ld a, a
    call z, $c7d5
    rst $00
    pop bc
    rst $00
    push bc
    add c
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    ld a, a
    call nz, $d4c1
    pop bc
    ld a, a
    rst $08
    add $7f
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    call nz, $d3c5
    call nc, $cfd2
    reti


    ret


    push bc

Call_028_567f:
    call nz, Call_028_7f81
    ld d, l
    ld c, e
    or h
    push de
    jp nc, Jump_028_7fce

    call nc, $c5c8
    ld a, a
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $c955


    call nc, Call_028_7fd9
    ld c, h
    ld a, a
    rst $08
    add $c6
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $d9d2
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    ld d, l
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    ret


    jp Jump_028_7fc8


    jp nc, $cfcf

    call $c47f
    rst $08
    ld a, a
    rst $10
    push bc
    ld c, a
    ld a, a
    rst $00
    rst $08
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    add $d2
    rst $08
    call $ce7f
    rst $08
    rst $10
    ld a, a
    rst $08
    ld c, a
    adc $7f
    xor c
    add a
    call z, Call_028_7fcc
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld d, l
    adc $7f
    ret


    adc $d4
    jp nc, $c4cf

    push de
    jp $c9d4


    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    rst $08
    call $d5cd
    adc $c9
    jp $d4c1


    ret


    rst $08
    adc $7f
    ret z

    pop bc
    ld c, a
    db $d3
    ld a, a
    jp nz, $c5c5

    adc $7f
    jp $cec1


    jp $ccc5


    call z, $c4c5
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    rst $08
    push de
    jp nc, $c67f

    ret


    jp nc, $d4d3

    ld a, a
    call $c54f
    push bc
    call nc, $cec9
    rst $00
    add c
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    call nc, $cf55
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    ld a, a
    rst $08
    add $7f
    ret nc

    ld d, l
    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    ld a, a
    add c
    ld a, a
    xor l
    ld d, l
    reti


    ld a, a
    adc $c1
    call Call_028_7fc5
    ret


    db $d3
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, Call_028_55c5
    jp nc, $a97f

    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    and h
    jp nc, Jump_028_7f8e

    ld d, h
    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    call z, $d6cf
    push bc
    ld d, l
    call nz, $c17f
    adc $c4
    ld a, a
    push bc
    db $d3
    call nc, $c5c5
    call $c4c5
    ld a, a
    jp nz, Jump_028_55d9

    ld a, a
    push de
    db $d3
    ld a, a
    pop bc
    call z, $81cc
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    adc $7f
    call nc, $c9c8
    db $d3
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    call nc, Call_028_4fc8
    push bc
    ld a, a
    pop bc
    call z, $d6c9
    push bc
    ld a, a
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    db $d3
    ld d, l
    ld a, a
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    pop bc
    db $d3
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    ld d, l
    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    db $d3
    ld a, a
    call z, $d6c9
    push bc
    ld a, a
    ret


    ld d, l
    adc $7f
    push bc
    sub $c5
    jp nc, Jump_028_7fd9

    jp $d2cf


    adc $c5
    jp nc, Jump_028_7f81

    ld d, b
    inc d
    nop
    ld a, a
    ld d, l
    or h
    ret z

    push bc
    ld a, a
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    ld a, a
    ld a, a
    adc $c1
    call $c555
    call nz, Call_028_547f
    rst $10
    pop bc
    db $d3
    ld a, a
    call nc, $c5d2
    pop bc
    call nc, $c4c5
    ld d, l
    ld a, a
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    push bc
    call nc, $d47f
    rst $08
    ld a, a
    call nc, $cbc1
    push bc
    ld d, l
    ld a, a

Call_028_5853:
    ret nc

    pop bc
    jp nc, Jump_028_7fd4

    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cdcf


    ret nc

    ld d, l
    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $81
    ld a, a
    and c
    adc $c4
    ld a, a
    xor c
    add a
    call $557f
    call nz, $c9cf
    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    rst $08
    ld d, l
    add $7f
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    or h
    ret z

    pop bc
    call nc, $557f
    ret


    db $d3
    ld a, a
    pop bc
    call z, $8ecc
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    adc $cf
    rst $10
    ld a, a
    call nc, $ccc5
    call z, $cd7f
    ld c, a
    push bc
    ld a, a
    reti


    rst $08
    push de
    jp nc, $ce7f

    pop bc
    call Call_028_7fc5
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
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    ld a, a
    ld c, a
    ret


    db $d3
    ld a, a
    call Call_028_7fd9
    rst $00
    jp nc, $cec1

    call nz, $cfd3
    adc $7f
    add c
    ld a, a
    ld d, l
    push bc
    ret


    call nc, $c5c8
    jp nc, $d97f

    rst $08
    push de
    jp nc, $d07f

    pop bc
    call z, Call_028_7fd9
    ld d, l
    ret nc

    pop bc
    jp nc, $ced4

    push bc
    jp nc, $cf7f

    jp nc, $d97f

    rst $08
    push de
    jp nc, $cf7f

    ld d, l
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    adc [hl]
    ld a, a
    or a
    push bc
    call z, $9fcc
    ld a, a
    or a
    ld d, l
    ret z

    pop bc
    call nc, $d387
    ld a, a
    reti


    rst $08
    push de
    jp nc, $ce7f

    pop bc
    call $9fc5
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    ld d, d
    add c
    ld a, a
    xor [hl]
    rst $08
    rst $10
    adc h
    ld a, a
    db $d3
    call nc, $d2c1
    ld c, a
    call nc, $d97f
    rst $08
    push de
    jp nc, $d37f

    call nc, $d2cf
    reti


    ld a, a
    add c
    call nz, $c5d2
    ld d, l
    pop bc
    call $c17f
    adc $c4
    ld a, a
    pop bc
    call nz, $c5d6
    adc $d4
    push de
    jp nc, $81c5

    ld d, l
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    ld d, l
    rst $08
    add $7f
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    ld d, l
    add c
    ld a, a
    rst $00
    rst $08
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    rst $10
    push bc
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call Call_028_4fc5
    ld d, b
    ld bc, $cd68
    nop
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    res 0, c
    ld a, a
    jp $ccc1


    call z, $c97f
    call nc, $4f7f
    ld d, d
    add c
    ld a, a
    ld e, b
    nop
    xor a
    ret z

    adc h
    jp nc, $c7c9

    ret z

    call nc, $ce81
    rst $08
    rst $10
    ld a, a
    ld a, a
    xor c
    ld a, a
    ld a, a
    ld c, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $d4c9

    add a
    db $d3
    ld a, a
    jp $ccc1


    call z, $c555
    call nz, Call_028_5853
    nop
    ld a, a
    or a
    ret z

    ret


    jp Jump_028_7fc8


    jp $cec1


    ld a, a
    jp nz, Jump_028_7fc5

    db $d3
    rst $08
    call z, $c44f
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    ld c, a
    ld a, a
    call nc, $d0cf
    jp nc, $c3c9

    push bc
    ld a, a
    ld a, a
    call nc, $c1c8
    call nc, $c37f
    rst $08
    ld d, l
    call $cfcd
    call nz, $d4c9
    reti


    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_028_7fc5

    ret


    db $d3
    adc $87
    call nc, $d77f
    ret z

    pop bc
    call nc, Call_028_7f4f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_028_7fcf
    jp nz, $d9d5

    adc [hl]
    ld d, l
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
    rst $00
    rst $08
    rst $08
    call nz, $cc7f
    rst $08
    rst $08
    bit 1, a
    adc [hl]
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    sbc a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $557f
    ld d, b
    ld [bc], a
    sbc a
    rst $38
    jp $8400


    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    adc h
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    or h
    ret z

    pop bc
    adc $cb
    ld c, a
    db $d3
    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    push de
    jp nc, $c37f

    rst $08
    call $cec9
    rst $00
    ld d, l
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and l
    ret c

    jp $d0c5


    call nc, $d47f
    ret z

    pop bc
    call nc, $b78c
    ret z

    pop bc
    call nc, Call_028_7f4f
    jp $cec1


    ld a, a
    rst $10
    push bc
    ld a, a
    ld a, a
    call nz, Call_028_7fcf
    add $cf
    jp nc, $d97f

    ld d, l
    rst $08
    push de
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    adc $cf
    ld a, a
    push bc
    adc $cf
    ld c, a
    push de
    rst $00
    ret z

    ld a, a
    call $cecf
    push bc
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    jp nc, $cec9

    rst $00
    ld a, a
    call $4fcf
    jp nc, $a3c5

    call z, $c1c5
    jp nc, $d57f

    ret nc

    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ld d, l
    ret


    adc $c7
    ld a, a
    push de
    adc $ce
    push bc
    jp $c5c3


    db $d3
    db $d3
    pop bc
    jp nc, $81d9

    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    pop bc
    adc $cb
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    adc $d3
    ret z

    pop bc
    call z, Call_028_7fcc
    rst $10
    push bc
    ld a, a
    pop bc
    jp nz, $cec1

    ld c, a
    call nz, $cecf
    ld a, a
    call z, $d4c5
    call nc, $cec9
    rst $00
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    call nc, Call_028_7fcf
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_028_7f9f

    ld d, a
    ld bc, $d01d
    nop
    ld c, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    push bc
    adc $c4
    push bc
    call nz, $c67f
    rst $08
    jp nc, $cd7f

    ld d, l
    push bc
    ld a, a
    adc $cf
    call nc, $d47f
    rst $08
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    jp nc, $cdc5

    ld d, l
    push bc
    call $c5c2
    jp nc, $c4c5

    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    add c
    ld e, b
    ld bc, $d01d
    nop
    ld c, a
    or d
    push bc
    call $cdc5
    jp nz, $d2c5

    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    ld d, b
    dec bc
    ld b, $50
    ld bc, $d01d
    nop
    ld c, a
    or d
    push bc
    call $cdc5
    jp nz, $d2c5

    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    adc $7f
    add c
    ld d, l
    ld d, b
    ld bc, $d01d
    nop
    ld d, l
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $c4c5

    ld a, a
    add $55
    rst $08
    push de
    jp nc, $d37f

    set 1, c
    call z, $d3cc
    db $d3
    rst $08
    adc h
    ld a, a
    xor b
    push bc
    ld a, a
    ld d, l
    ret z

    pop bc
    db $d3
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    jp nz, $d3c5

    call nc, $8155
    xor h
    push bc
    call nc, $c87f
    ret


    call $c67f
    rst $08
    jp nc, $c5c7

    call nc, $cf7f
    ld d, l
    call nc, $c5c8
    jp nc, $d37f

    set 1, c
    call z, $d3cc
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $cf55


    call $c5d0
    adc $d3
    pop bc
    call nc, $cfc9
    adc $7f
    rst $08
    add $7f
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    ret


    jp Jump_028_7fc8


    db $d3
    set 1, c
    call z, Call_028_7fcc
    ld a, a
    call nz, Call_028_7fcf
    ld c, a
    reti


    rst $08
    push de
    rst $10
    pop bc
    adc $d4
    ld a, a
    ret z

    ret


    call $d47f
    rst $08
    ld a, a
    add $cf
    ld d, l
    jp nc, $c5c7

    call nc, Call_028_7f9f
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    call nc, $c1c8
    call nc, $d387
    ld a, a
    pop bc
    adc $7f
    ret


    call $d04f
    rst $08
    jp nc, $c1d4

    adc $d4
    ld a, a
    db $d3
    set 1, c
    call z, $a9cc
    call nc, $d387
    ld d, l
    ld a, a
    ret


    call $cfd0
    db $d3
    db $d3
    ret


    jp nz, $c5cc

    ld a, a
    add $cf
    jp nc, $c87f

    ld d, l
    ret


    call $d47f
    rst $08
    ld a, a
    add $cf
    jp nc, $c5c7

    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call $81c5
    call nc, Call_028_7fcf
    rst $08
    push de
    jp nc, $c37f

    ld c, a
    push bc
    adc $d4
    jp nc, Jump_028_7fc5

    ld d, h
    ld a, a
    add c
    xor b
    push bc
    jp nc, Jump_028_7fc5

    ld a, a
    ld d, l
    rst $08
    add $7f
    ld d, h
    ld a, a
    jp nc, $c3c5

    rst $08
    sub $c5
    jp nc, $c4c5

    ld a, a
    ld d, l
    ret z

    ret


    db $d3
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, $8ec8
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
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $d47f
    ld c, a
    ret z

    push bc
    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $9f7f
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    xor h
    push bc
    call nc, $cd7f
    push bc
    ld a, a
    call nz, $d0c5
    rst $08
    ld c, a
    db $d3
    ret


    call nc, $c87f
    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    db $d3
    rst $08
    jp nc, $d9d2

    ld a, a
    call nc, Call_028_7fcf
    ret z

    pop bc
    sub $c5
    ld c, a
    ld a, a
    call z, $d4c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $cec9
    rst $00
    ld a, a
    ld d, l
    db $d3
    rst $08
    ld a, a
    call z, $cecf
    rst $00
    add c
    ld a, a
    call Call_028_7fd9
    call nz, $d0c5
    rst $08
    db $d3
    ld d, l
    ret


    call nc, $c4c5
    ld a, a
    ld d, h
    adc [hl]
    xor b
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    ld d, l
    adc $c7
    ld a, a
    pop bc
    call z, Call_028_7fcc
    rst $08
    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_028_55c5

    add c
    ld a, a
    ld e, b
    ld a, [bc]
    nop
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    jp $cdcf


    ret


    adc $c7
    ld a, a
    rst $08
    adc $4f
    jp Jump_028_7fc5


    call $d2cf
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    jp $cc4f


    push de
    jp nz, $cf7f

    add $7f
    jp $cdcf


    call $ced5
    ret


    jp $d4c1


    ld d, l
    ret


    rst $08
    adc $7f
    jp $c2c1


    call z, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, $8cc5

    ld a, a
    adc $cf
    rst $10
    ld a, a
    ret


    db $d3
    ld a, a
    call $cbc1
    ld c, a
    ret


    adc $c7
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $d0c5

    pop bc
    jp nc, $d4c1

    ret


    rst $08
    adc $55
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    ret


    db $d3
    ld a, a
    jp nc, $c3c5

    push bc
    ret nc

    call nc, $cfc9
    ld c, a
    adc $7f
    call nz, $d3c5
    res 1, [hl]
    ld a, a
    xor b
    pop bc
    adc $c4
    ld a, a
    pop bc
    ld a, a
    jp nc, Jump_028_55c5

    ret nc

    rst $08
    jp nc, Jump_028_7fd4

    ret


    adc $7f
    jp nz, $c6c5

    rst $08
    jp nc, Jump_028_7fc5

    db $d3
    call nc, $c155
    jp nc, $c9d4

    adc $c7
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    call $ced5

Jump_028_5e7f:
    ret


    jp $c155


    call nc, $cfc9
    adc $7f
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor d
    push de
    db $d3
    call nc, $d77f
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $cec9
    push de
    ld c, a
    call nc, $81c5
    ld a, a
    ld d, b
    ld a, [bc]
    nop
    ld a, a
    and [hl]
    jp nc, $cdcf

    ld a, a
    adc $cf
    rst $10
    ld a, a
    rst $08
    adc $8c
    ld a, a
    ret nc

    pop bc
    push de
    ld c, a
    db $d3
    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $c3c5

    push bc
    ret nc

    call nc, $cfc9
    adc $55
    add c
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    adc $cf
    ld a, a
    call nc, $c955
    call Call_028_7fc5
    call nc, Call_028_7fcf
    rst $10
    pop bc
    ret


    call nc, $a37f
    rst $08
    call Call_028_7fc5
    ld d, l
    pop bc
    rst $00
    pop bc
    ret


    adc $7f
    pop bc
    add $d4
    push bc
    jp nc, $c37f

    rst $08
    adc $d4
    pop bc
    ld d, l
    jp $c9d4


    adc $c7
    ld a, a
    rst $10
    ret


    call nc, Call_028_7fc8
    reti


    rst $08
    push de
    jp nc, $c67f

    ld d, l
    jp nc, $c5c9

    adc $c4
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    call nc, $c5c8
    ld a, a
    jp $cdcf


    call $ced5
    ret


    ld c, a
    jp $d4c1


    ret


    rst $08
    adc $7f
    jp $c2c1


    call z, Call_028_7fc5
    rst $10
    ret


    call nc, Call_028_55c8
    ld a, a
    add $d2
    ret


    push bc
    adc $c4
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $c5c5

    adc $7f
    ld d, l
    ret nc

    push de
    call nc, $d47f
    ret z

    jp nc, $d5cf

    rst $00
    ret z

    adc [hl]
    ld a, a
    xor h
    pop bc
    call nz, $55c9
    push bc
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $00
    push bc
    adc $d4
    call z, $cdc5
    pop bc
    adc $8c
    ld d, l
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    call z, $d4c5
    ld a, a
    call Call_028_7fc5
    call nc, Call_028_7fcf
    jp nz, $c555

    ld a, a
    pop bc
    ld a, a
    rst $00
    push de
    ret


    call nz, $8ec5
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    ret


    adc $d4
    jp nc, $c4cf

    push de
    jp Jump_028_7fc5


    ld c, a
    ret


    call nc, $cf7f
    adc $c3
    push bc
    ld a, a
    call $d2cf
    push bc
    adc [hl]
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $c5d2
    pop bc
    call $cf7f
    add $4f
    ld e, c
    ld d, l
    ret


    db $d3
    ld a, a
    jp nz, $cfd2

    set 0, l
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    or b
    jp nc, $d3c5

    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $cf4f

    call nc, $cfd4
    adc $7f
    ld e, e
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c47f
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $9fcf
    ld a, a
    ld c, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $c4c5
    ld a, a
    ret nc

    jp nc, $cf4f

    ret nc

    db $d3
    ld a, a
    ret z

    pop bc
    sub $c5
    adc $87
    call nc, $c27f
    push bc
    push bc
    adc $7f
    ld d, l
    ret nc

    ret


    jp $c5cb


    call nz, $d57f
    ret nc

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c47f
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $d0c5
    rst $08
    ld c, a
    db $d3
    ret


    call nc, Call_028_7f9f
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call $cec1
    reti


    ld a, a
    call nz, Call_028_7fcf
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, Call_028_7f9f
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $d0cf

    db $d3
    ld a, a
    ld a, a
    pop bc
    ld c, a
    jp nc, Jump_028_7fc5

    call nc, $cfcf
    ld a, a
    call $c3d5
    ret z

    ld a, a
    call nc, Call_028_7fcf
    call nz, Call_028_55c5
    ret nc

    rst $08
    db $d3
    ret


    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_028_7fc5

    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $c4c5
    ld a, a
    ld c, a
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    jp $cdcf


    call $ced5
    ret


    jp $d4c1


    ld d, l
    ret


    rst $08
    adc $7f
    ld e, e
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c9c8
    adc $c7
    ld a, a
    jp nz, Jump_028_7fc5

    call nz, $d0c5
    rst $08
    db $d3
    ld c, a
    ret


    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_028_7fc4
    jp nz, Jump_028_7fc5

    ret nc

    ld c, a
    ret


    jp $c5cb


    call nz, $d57f
    ret nc

    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_028_7fc4
    jp nz, Jump_028_7fc5

    ret nc

    ld c, a
    ret


    jp $c5cb


    call nz, $d57f
    ret nc

    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    rst $08
    rst $08
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
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, $c17f

    adc $d9
    ld d, l
    ld a, a
    call $d2cf
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_028_7fc5

    ret nc

    ret


    jp $c5cb


    call nz, $d57f
    ret nc

    ld a, a
    ld c, a
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    jp $cdcf


    call $ced5
    ret


    jp $d4c1


    ld d, l
    ret


    rst $08
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c9c8
    adc $c7
    ld a, a
    jp nz, Jump_028_7fc5

    call nz, $d0c5
    rst $08
    db $d3
    ld c, a
    ret


    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    ret


    jp Jump_028_7fc8


    db $d3
    ret z

    rst $08
    push de
    call z, Call_028_7fc4
    jp nz, Jump_028_7fc5

    ld c, a
    pop bc
    jp nz, $cec1

    call nz, $cecf
    push bc
    call nz, Call_028_7f9f
    ld d, a
    nop
    xor b
    rst $08
    rst $10
    ld a, a
    call $cec1
    reti


    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    pop bc
    adc $cb
    db $d3
    ld a, a
    add $cf
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    db $d3
    ld c, a
    call nc, $c1d2
    adc $c7
    push bc
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    call nc, $c5c8
    ld a, a
    jp nc, $c3cf

    bit 7, a
    jp $cec1


    ld a, a
    jp nz, Jump_028_7fc5

    call $cf55
    sub $c5
    call nz, $d37f
    call z, $c7c9
    ret z

    call nc, $d9cc
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
    ret nc

    push bc
    push bc
    call nz, $cf7f
    add $7f
    rst $10
    pop bc
    call nc, $c54f
    jp nc, $c97f

    db $d3
    ld a, a
    call nc, $cfcf
    ld a, a
    add $c1
    db $d3
    call nc, $d97f
    rst $08
    ld d, l
    push de
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld a, a
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
    pop bc
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    ld c, a
    call z, $d37f
    ret nc

    rst $08
    jp nc, Jump_028_7fd4

    jp nz, Jump_028_7fd9

    jp nz, $cbc9

    push bc
    add c
    ld a, a
    ld d, l
    or b
    pop bc
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $c4c9

    push bc
    adc l
    rst $08
    ld d, l
    adc $8d
    call nc, $c5c8
    adc l
    rst $10
    pop bc
    sub $c5
    add c
    ld a, a
    ld e, b
    nop
    ld d, d
    ld c, a
    ld d, b
    dec b
    nop
    ret z

    pop bc
    db $d3
    ld a, a
    push de
    db $d3
    push bc
    call nz, Call_028_5055
    ld bc, $cf45
    nop
    add c
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    jp $c5c3


    db $d3
    db $d3
    add $d5
    call z, Call_028_7f81
    xor c
    add a
    sub $c5
    ld c, a
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $557f
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    add c
    ld a, a
    ld d, b
    ld [de], a
    ld b, $50
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $d4c1
    pop bc
    ld a, a
    rst $08
    add $7f
    ld d, b
    ld bc, $cfc1
    nop
    ld c, a
    rst $10
    pop bc
    db $d3
    ld a, a
    jp nc, $c3c5

    rst $08
    jp nc, $c5c4

    call nz, $c97f
    adc $7f
    call nc, $c855
    push bc
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    ld d, l
    adc $c4
    jp nz, $cfcf

    bit 7, a
    ld d, h
    pop bc
    rst $00
    pop bc
    ret


    adc $7f
    add c
    ld d, l
    ld a, a
    ld d, b
    inc de
    ld b, $50
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ld d, b
    ld bc, $de64
    nop
    ld c, a
    ld a, a
    call nc, $c1d2
    adc $d3
    add $c5
    jp nc, $c5d2

    call nz, $d47f
    rst $08
    ld a, a
    rst $10
    ld d, l
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    ld e, e
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    rst $10
    rst $08
    adc $c4
    push bc
    jp nc, $d5c6

    call z, Call_028_7f81
    ld c, a
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    ld a, a
    rst $10
    push bc
    jp nc, Jump_028_7fc5

    add $c9
    adc $c1
    call z, $d9cc
    ld a, a
    jp $d5c1


    ld d, l
    rst $00
    ret z

    call nc, Call_028_7f81
    ld d, b
    ld [de], a
    ld b, $50
    nop
    ld a, a
    ld d, d
    ld d, b
    dec b
    ld a, a
    rst $00
    rst $08
    push bc
    db $d3
    call nz, $d7cf
    adc $7f
    add $4f
    jp nc, $cdcf

    ld a, a
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld d, d
    db $d3
    ret


    call nc, $cf7f
    adc $7f
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ret z

    push bc
    jp nc, Jump_028_7fc5

    jp $cec1


    ld a, a
    rst $10
    push bc
    ld a, a
    rst $00
    ld c, a
    rst $08
    ld a, a
    call nz, $d7cf
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    push bc
    add $c6
    push bc
    jp Jump_028_7fd4


    push bc
    sub $4f
    push bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    ret


    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    and c
    jp nz, $cec1

    call nz, $cecf
    ld a, a
    call nc, Call_028_4fc8
    push bc
    ld a, a
    jp nz, $c9c1

    call nc, Call_028_7f81
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    and c
    jp nz, $cec1

    call nz, $cecf
    ld a, a
    call nc, Call_028_4fc8
    push bc
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    push bc
    call nz, $d47f
    ret z

    push bc
    ld c, a
    ld a, a
    rst $10
    ret z

    ret


    db $d3
    call nc, $c5cc
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld d, l
    xor b
    add a
    call Call_028_7f81
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    jp nz, $c1c5

    push de
    call nc, $c955
    add $d5
    call z, $d47f
    rst $08
    adc $c5
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_028_5581

    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    push bc
    call nz, $d47f
    ret z

    push bc
    ld c, a
    ld a, a
    rst $10
    ret z

    ret


    db $d3
    call nc, $c5cc
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld d, l
    xor b
    add a
    call Call_028_7f81
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    jp nz, $c1c5

    push de
    call nc, $c955
    add $d5
    call z, $d47f
    rst $08
    adc $c5
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_028_5581

    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    call z, Call_028_7fcc
    call nc, $c5c8
    ld a, a
    ld d, h
    rst $08
    ret nc

    push bc
    adc $c5
    ld c, a
    call nz, $d47f
    ret z

    push bc
    ret


    jp nc, $c57f

    reti


    push bc
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c37f

    rst $08
    ret


    adc $7f
    ret


    db $d3
    ld a, a
    ld d, l
    ld d, b
    ld [bc], a
    inc hl
    push de
    jp nz, Jump_028_7f00

    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    add a
    call Call_028_7f81
    ld a, a
    ld d, [hl]
    adc $cf
    ld a, a
    pop bc
    adc $4f
    reti


    ld a, a
    jp nc, $d3c5

    ret nc

    rst $08
    adc $d3
    push bc
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    ld c, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, $d3c5

    ret nc

    rst $08
    adc $d3
    push bc
    add c
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    jp nc, Jump_028_7fc5

    jp nz, $d2d5

    ret


    push bc
    call nz, $d07f
    jp nc, $d0cf

    db $d3
    ld d, l
    ld a, a
    adc $c5
    pop bc
    jp nc, $d9c2

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    rst $08
    ld a, a
    jp nc, $c3c5

    rst $08
    sub $c5
    jp nc, Jump_028_7f9f

    or a
    ret z

    ret


    jp $c84f


    ld a, a
    db $d3
    set 1, c
    call z, $9fcc
    ld a, a
    ld d, a
    ld bc, $cf45
    nop
    ld c, a
    jp $cec1


    add a
    call nc, $c97f
    adc $c3
    jp nc, $c1c5

    db $d3
    push bc
    ld a, a
    call Call_028_55cf
    jp nc, Jump_028_7fc5

    add c
    ld a, a
    ld e, b
    ld bc, $cf45
    nop
    ld c, a
    call nc, $c5c8
    ld a, a
    call $c9c1
    adc $7f
    ret nc

    rst $08
    ret


    adc $d4
    db $d3
    ld a, a
    rst $08
    ld d, l
    add $7f
    db $d3
    set 1, c
    call z, Call_028_7fcc
    ret z

    pop bc
    sub $c5
    ld a, a
    ret


    adc $c3
    jp nc, $c555

    pop bc
    db $d3
    push bc
    call nz, Call_028_7f81
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $c9c1
    adc $7f
    ret nc

    rst $08
    ret


    adc $d4
    db $d3
    ld a, a
    ld c, a
    ret z

    pop bc
    sub $c5
    ld a, a
    jp nc, $c3c5

    rst $08
    sub $c5
    jp nc, $c4c5

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, h
    ld a, a
    ret z

    pop bc
    ld c, a
    db $d3
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, $c4c5
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
    push bc
    jp $c5d2


    call nc, $cd7f
    pop bc
    jp $c9c8


    ld c, a
    adc $c5
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    ld bc, $cf45
    nop
    ld c, a
    rst $10
    push bc
    jp nc, Jump_028_7fc5

    jp nc, $c3c5

    rst $08
    jp nc, $c5c4

    call nz, $c97f
    adc $81
    ld d, l
    xor h
    push bc
    call nc, Call_028_547f
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_028_5055

    ld bc, $cf45
    nop
    ld d, l
    sbc a
    ld a, a
    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    pop bc
    adc $c4
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    call $d4c1
    jp $c5c8


    db $d3
    ld a, a
    jp nz, $c4c1

    add c
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    xor [hl]
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_028_7f81

    ld d, l
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $ccc1

    call z, $c87f
    pop bc
    db $d3
    ld a, a
    jp nz, $c5c5

    ld c, a
    adc $7f
    db $d3
    ret nc

    jp nc, $ced5

    rst $00
    jp nz, Jump_028_7fd9

    ld d, l
    ld e, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    adc $c5
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    call nc, $cbc1
    push bc
    db $d3
    ld a, a
    db $d3
    rst $08
    ld c, a
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    jp nz, $ccc5

    rst $08
    adc $c7
    ret


    adc $c7
    ld d, l
    call nc, Call_028_7fcf
    rst $08
    call nc, $c5c8
    jp nc, Jump_028_7fd3

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call nc, Call_028_55c8
    ret


    push bc
    add $81
    ld a, a
    ld e, b
    ld bc, $cf45
    nop
    ld c, a
    ld a, a
    or h
    rst $08
    ld a, a
    pop bc
    jp nz, $cec1

    call nz, $cecf
    ret


    db $d3
    ld a, a
    add $c5
    pop bc
    ld d, l
    db $d3
    ret


    jp nz, $c5cc

    sbc a
    ld a, a
    ld e, b
    ld bc, $cd68
    nop
    ld c, a
    rst $10
    pop bc
    db $d3
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    pop bc
    jp nz, $cec1

    call nz, Call_028_55cf
    adc $c5
    call nz, Call_028_7f81
    ld e, b
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $4f
    rst $00
    ld a, a
    ret


    call $cfd0
    jp nc, $c1d4

    adc $d4
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, $c455
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    pop bc
    jp nz, $cec1

    call nz, $cecf
    push bc
    call nz, $8155
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_028_7fc5

    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_028_7fd3

    adc $cf
    ld c, a
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ret


    adc $d3
    ret


    rst $00
    adc $c9
    ld d, l
    add $c9
    jp $cec1


    call nc, $c97f
    adc $7f
    db $d3
    rst $10
    rst $08
    jp nc, Jump_028_7fc4

    db $d3
    ld d, l
    set 1, c
    call z, $81cc
    ld a, a
    ld e, b
    ld bc, $cd68
    nop
    ld c, a
    and [hl]
    ret


    rst $00
    ret z

    call nc, $c27f
    reti


    ld a, a
    db $d3
    rst $10
    rst $08
    jp nc, Jump_028_7fc4

    db $d3
    bit 2, l
    ret


    call z, Call_028_7fcc
    pop de
    push de
    ret


    call nc, Call_028_7fc5
    db $d3
    pop bc
    call nc, $d3c9
    add $c1
    ld d, l
    jp $cfd4


    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    ret


    db $d3
    ld a, a
    pop de
    push de
    pop bc
    jp nc, $dad4

    ld a, a
    ret nc

    ld c, a
    call z, $d4c1
    push bc
    pop bc
    push de
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    push de
    call $c9cd
    call nc, $cf7f
    add $7f
    ld c, a
    ld d, h
    ld a, a
    ld e, l
    add c
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ret z

    push bc
    pop bc
    call nz, $d5d1
    pop bc
    jp nc, $c5d4

    jp nc, Jump_028_7fd3

    rst $08
    add $7f
    pop bc
    ld d, l
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    ret


    rst $00
    ret z

    push bc
    db $d3
    call nc, $cf7f
    jp nc, $c1c7

    ld c, a
    adc $c9
    jp c, $d4c1

    ret


    rst $08
    adc $7f
    rst $08
    add $7f
    ld d, h
    call nc, Call_028_55c8
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $d5d1
    pop bc
    jp nc, $c5d4

    jp nc, Jump_028_7fd3

    rst $08
    add $55
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    adc $c9
    jp $c5c8


    ld a, a
    add $cf
    jp nc, Jump_028_7f4f

    pop bc
    ld a, a
    db $d3
    call nc, $d4c1
    push de
    push bc
    ld a, a
    rst $08
    add $7f
    and d
    push de
    call nz, Call_028_55c4
    ret z

    pop bc
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    jp $cec1


    add a
    call nc, $c67f
    call z, Call_028_7fd9
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    db $d3
    set 3, c
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    pop bc
    jp c, $ccda

    ret


    adc $c7
    ld a, a
    call z, $c7c9
    ret z

    call nc, $d37f
    ld c, a
    ret z

    ret


    adc $c5
    call nz, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    push de
    jp nc, $cfd2

    push de
    adc $55
    call nz, $cec9
    rst $00
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    ld a, a
    push de
    db $d3
    push bc
    call nz, $c67f
    rst $08
    ld d, l
    jp nc, $cec9

    add $cf
    jp nc, $c1cd

    call nc, $cfc9
    adc $7f
    jp $cdcf


    call $d555
    adc $c9
    jp $d4c1


    ret


    rst $08
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    call nc, $cc7f
    pop bc
    db $d3
    call nc, $c87f
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp nc, $c54f

    db $d3
    call nc, $c17f
    adc $c4
    ld a, a
    call nc, $c5c8
    adc $7f
    jp nc, $d3d5

    ret z

    ld d, l
    ld a, a
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    jp $cec5


    call nc, $c5d2
    ld a, a
    ld d, l
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    push bc
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    ld c, a
    call nc, $81c8
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d57f
    db $d3
    push bc
    ld a, a
    ret


    call nc, $c5c2
    add $cf
    jp nc, Jump_028_4fc5

    ld a, a
    rst $00
    pop bc
    ret


    adc $c9
    adc $c7
    ld a, a
    adc $c5
    rst $10
    ld a, a
    jp nz, $c4c1

    rst $00
    ld d, l
    push bc
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $d0cf

    db $d3
    ld a, a
    jp $c14f


    adc $87
    call nc, $c27f
    push bc
    ld a, a
    push de
    db $d3
    push bc
    call nz, Call_028_7f8e
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    call nz, $d7cf
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ret nc

    ret


    jp $c5cb


    call nz, $d57f
    ret nc

    ld d, l
    ld d, b
    ld [bc], a
    push hl
    call z, Call_000_00c3
    add h
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    or h
    ret z

    push bc
    ld a, a
    pop bc
    call nc, $c1d4
    jp $c5cb


    call nz, $ce7f
    rst $08
    rst $10
    ld a, a
    ld d, l
    db $d3
    call nc, $d2c1
    call nc, $d47f
    rst $08
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp $cf55


    push de
    adc $d4
    push bc
    jp nc, $d4c1

    call nc, $c3c1
    res 0, c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp $c1c8


    jp nc, $d4c1

    push bc
    jp nc, $d3c9

    call nc, $4fc9
    jp Jump_028_7fd3


    rst $08
    add $7f
    ld d, l
    ld e, c
    ld d, l
    ret


    db $d3
    ld a, a
    db $d3
    call nc, $c3c9
    set 0, l
    call nz, $cf7f
    adc $7f
    ret z

    ret


    call $d355
    push bc
    call z, $87c6
    db $d3
    ld a, a
    jp nz, $c4cf

    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    call z, Call_028_7fcc
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    jp $c1c9


    call z, $d37f
    ld c, a
    call nc, $d4c1
    push de
    db $d3
    ld a, a
    jp nc, $d4c5

    push de
    jp nc, Jump_028_7fce

    call nc, Call_028_7fcf
    call nc, $c855
    push bc
    ld a, a
    adc $cf
    jp nc, $c1cd

    call z, $c17f
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_028_7fc5

    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_028_7fd3

    pop bc
    rst $00
    ld c, a
    pop bc
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret


    call nz, $cec5
    call nc, $d4c9
    reti


    ld a, a
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld e, d
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    jp $d0c1


    push bc
    rst $00
    rst $08
    pop bc
    ld c, a
    call nc, Call_028_7f7f
    rst $08
    add $7f
    ld d, l
    ld e, d
    ld d, l
    ret z

    pop bc
    call nz, $c77f
    rst $08
    adc $c5
    ld a, a
    rst $08
    push de
    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    jp nz, $d4d5

    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nc, $cfcf
    ld a, a
    rst $10
    push bc
    pop bc
    ld c, a
    bit 7, a
    call nc, Call_028_7fcf
    call z, $d4c5
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    jp $d0c1


    ld d, l
    push bc
    rst $00
    rst $08
    pop bc
    call nc, Call_028_7f7f
    jp nz, $c3c1

    res 0, c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    ld a, a
    or b
    jp nc, $d3c5

    db $d3
    ld a, a
    call nc, $c5c8
    ld c, a
    ld a, a
    jp nz, $d4cf

    call nc, $cecf
    ld a, a
    rst $08
    add $7f
    ld e, e
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
    jp $cecf


    call nc, $c3c1
    call nc, $c4c5
    ld c, a
    ld a, a
    rst $10
    ret


    call nc, Call_028_7fc8
    rst $08
    adc $c5
    db $d3
    push bc
    call z, $87c6
    db $d3
    ld a, a
    ld d, l
    ld e, e
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $d37f
    ld d, l
    reti


    db $d3
    call nc, $cdc5
    ld a, a
    rst $08
    add $7f
    ret nc

    jp nc, $d0cf

    db $d3
    ld a, a
    jp Jump_028_55c1


    adc $7f
    jp nz, Jump_028_7fc5

    jp nc, $c1c5

    call nz, Call_028_7f81
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    jp $cecf


    call nc, $c3c1
    call nc, $c4c5
    ld c, a
    ld a, a
    rst $10
    ret


    call nc, Call_028_7fc8
    rst $08
    adc $c5
    db $d3
    push bc
    call z, $87c6
    db $d3
    ld a, a
    ld d, l
    ld e, e
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $d37f
    ld d, l
    reti


    db $d3
    call nc, $cdc5
    ld a, a
    rst $08
    add $7f
    ret nc

    jp nc, $d0cf

    db $d3
    ld a, a
    jp Jump_028_55c1


    adc $7f
    jp nz, Jump_028_7fc5

    jp nc, $c1c5

    call nz, Call_028_7f81
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    jp $cecf


    call nc, $c3c1
    call nc, $c4c5
    ld c, a
    ld a, a
    rst $10
    ret


    call nc, Call_028_7fc8
    ld e, e
    ld a, a
    rst $08
    add $7f
    xor l
    pop bc
    db $d3
    pop bc
    jp $c855


    reti


    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $d37f
    ld d, l
    reti


    db $d3
    call nc, $cdc5
    ld a, a
    rst $08
    add $7f
    ret nc

    jp nc, $d0cf

    db $d3
    ld a, a
    jp Jump_028_55c1


    adc $7f
    jp nz, Jump_028_7fc5

    jp nc, $c1c5

    call nz, Call_028_7f81
    ld e, b
    nop
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    xor c
    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    jp nz, $c54f

    jp nc, Jump_028_7fd9

    call nz, $cec1
    rst $00
    push bc
    jp nc, $d5cf

    db $d3
    ld a, a
    jp z, $d3d5

    ld d, l
    call nc, $ce7f
    rst $08
    rst $10
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $10
    ret


    call z, Call_028_7fc4
    ld d, l
    ld d, h
    ld a, a
    jp nc, $ced5

    ld a, a
    rst $08
    push de
    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $c155


    adc $7f
    call z, $d4c5
    ld a, a
    ld a, a
    ld d, h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ld d, l
    pop bc
    ld a, a
    call nc, $d9d2
    ld a, a
    ret


    add $7f
    ret z

    push bc
    jp nc, Jump_028_7fc5

    call nc, $c5c8
    ld d, l
    jp nc, Jump_028_7fc5

    ret


    db $d3
    ld a, a
    ld a, a
    ld d, h
    jp nz, $d4d5

    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    rst $10
    pop bc
    ret


    call nc, $c67f
    rst $08
    jp nc, $cf7f

    res 1, h
    add $cf
    call z, $cfcc
    ld d, l
    rst $10
    ld a, a
    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    push bc
    adc $c5
    sub $c5
    jp nc, $c97f

    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ld c, a
    ret z

    push bc
    jp nc, Jump_028_7fc5

    call nc, $c5c8
    ld a, a
    rst $00
    reti


    call $c17f
    call z, $c1d7
    ld d, l
    reti


    db $d3
    ld a, a
    jp $cfcc


    db $d3
    push bc
    db $d3
    ld a, a
    or a
    ret z

    ret


    jp Jump_028_7fc8


    add $55
    push bc
    call z, $cfcc
    rst $10
    ld a, a
    ld a, a
    rst $08
    adc $7f
    push bc
    pop bc
    jp nc, $c8d4

    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c87f
    push bc
    jp nc, $9fc5

    ld a, a
    ld d, l
    ld d, a
    nop
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
    call nc, $4f7f
    call nc, $c5c8
    jp nc, Jump_028_7fc5

    pop bc
    jp nc, Jump_028_7fc5

    sub d
    ld a, a
    set 1, c
    adc $c4
    db $d3
    ld d, l
    ld a, a
    rst $08
    add $7f
    ret nc

    push bc
    jp nc, $cfd3

    adc $d3
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    pop bc
    ld d, l
    jp nc, Jump_028_7fc5

    jp nz, $d2cf

    push bc
    call nz, $cf7f
    add $7f
    ld d, h
    and h
    rst $08
    ld d, l
    adc $87
    call nc, $d97f
    rst $08
    push de
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    ret


    call nc, $9f7f
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor e
    pop bc
    jp nc, $c1d4

    ret nc

    reti


    ld a, a
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $c17f
    ld c, a
    adc $d9
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $7f
    jp nz, $d4d5

    ld a, a
    ld a, a
    ret z

    pop bc
    ld d, l
    db $d3
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $7f
    call nc, $c1c8
    ld d, l
    adc $7f
    and d
    ret


    call nz, $ccc5
    push de
    ld a, a
    call nz, $c5cf
    db $d3
    add c
    ld a, a
    and d
    push bc
    ld d, l
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, $ce7f
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    jp nz, $c555

    ld a, a
    db $d3
    call nc, $ced5
    rst $00
    ld a, a
    jp nz, Jump_028_7fd9

    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d77f
    ret


    call z, Call_028_7fcc
    xor a
    bit 7, a
    ret


    add $7f
    ret


    call nc, $874f
    db $d3
    ld a, a
    db $d3
    rst $08
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    adc h
    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    add c
    ld a, a
    xor c
    ld a, a
    ld c, a
    jp $cec1


    ld a, a
    call nz, Call_028_7fcf
    adc $cf
    call nc, $c9c8
    adc $c7
    ld a, a
    pop bc
    jp nz, $cf55

    push de
    call nc, $c97f
    call nc, $d47f
    ret z

    pop bc
    call nc, $d97f
    rst $08
    push de
    ld a, a
    db $d3
    ld d, l
    call z, $c5c5
    ret nc

    ld a, a
    ret z

    push bc
    jp nc, Jump_028_7fc5

    add c
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    ld d, l
    rst $10
    pop bc
    ret


    call nc, $cec9
    rst $00
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, Call_028_7fcf
    call nz, $55c9
    db $d3
    ret nc

    push bc
    call z, $d47f
    ret z

    push bc
    ld a, a
    push bc
    add $c6
    push bc
    jp $d3d4


    ld a, a
    ld d, l
    rst $08
    add $7f
    pop bc
    call z, $cfc3
    ret z

    rst $08
    call z, Call_028_7f81
    ld d, a
    nop
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret


    call $d3c5
    ld a, a
    xor c
    ld a, a
    rst $00
    rst $08
    ld a, a
    db $d3
    ld c, a
    ret z

    rst $08
    ret nc

    ret nc

    ret


    adc $c7
    ld a, a
    call nc, Call_028_7fcf
    call nz, $d2c1
    bit 7, a
    rst $00
    ld d, l
    jp nc, $d9c5

    ld a, a
    jp $d4c9


    reti


    ld a, a
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    call nc, Call_028_55c8
    push bc
    ld a, a
    jp nc, $c1cf

    call nz, $c97f
    db $d3
    ld a, a
    jp c, $c7c9

    jp c, $c7c1

    ld a, a
    ld d, l
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    rst $08
    call nz, Call_028_7fd3
    call nc, Call_028_7fcf
    call nc, $c855
    push bc
    ld a, a
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    jp $d4c9


    reti


    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld c, a
    ld a, a
    call $cec9
    push de
    call nc, $81c5
    ld a, a
    xor h
    ret


    db $d3
    call nc, $cec5
    ld a, a
    call nc, $cf55
    ld a, a
    call $81c5
    ld a, a
    ld a, a
    ld d, [hl]
    xor b
    ret


    add c
    ld a, a
    ld a, a
    and h
    rst $08
    adc $55
    add a
    call nc, $c77f
    rst $08
    ld a, a
    call nc, $c5c8
    jp nc, $81c5

    ld a, a
    xor c
    add a
    sub $c5
    ld d, l
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $c97f
    call nc, $d47f
    rst $08
    ld a, a
    reti


    rst $08
    push de
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or a
    pop bc
    ret z

    rst $08
    rst $08
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    push bc
    sub $c5
    adc $7f
    ld c, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_028_7fcf
    db $d3
    call z, $c5c5
    ret nc

    ld a, a
    rst $10
    ret z

    ret


    call z, Call_028_55c5
    ld a, a
    rst $00
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    db $d3
    push de
    adc $7f
    add c
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $c1d2
    adc $c7
    push bc
    ld a, a
    ld d, l
    call nz, $c5d2
    pop bc
    call $d47f
    ret z

    pop bc
    call nc, $d37f
    ret


    call z, $c9cc
    ret nc

    ld d, l
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    push bc
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    call nz, $d255
    push bc
    pop bc
    call Call_028_7f81
    ld d, [hl]
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    xor c
    ld a, a
    call nz, $cf55
    adc $87
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    xor c
    ld a, a
    ld d, l
    jp nz, $c9d2

    adc $c7
    ld a, a
    ld d, l
    ld e, h
    jp nz, $d4d5

    sbc a
    ld d, l
    ld a, a
    xor b
    add a
    call Call_028_7f7f
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, $557f

    add $c1
    push de
    call z, $81d4
    ld a, a
    and a
    ret


    sub $c9
    adc $c7
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    ret


    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $4f
    push bc
    call nz, $5c7f
    sub h
    ld d, l
    sub d
    ld a, a
    add $d2
    rst $08
    call $c87f
    ret


    db $d3
    ld a, a
    push bc
    call z, $c5c4
    jp nc, $557f

    jp nz, $cfd2

    call nc, $c5c8
    jp nc, $817f

    ld a, a
    ld d, b
    stop
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
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    push bc
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    call nz, $c5d2
    pop bc
    call Call_028_7f55
    ld d, [hl]
    ld a, a
    ld a, a
    ret


    adc $7f
    ld d, l
    ld e, h
    add a
    db $d3
    ld a, a
    sub h
    ld d, l
    sub d
    call nz, $c5d2
    pop bc
    call Call_028_7f8e
    ld d, [hl]
    ld a, a
    db $d3
    adc $cf
    jp nc, $cec9

    ld d, l
    rst $00
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_028_567f
    call z, $cfcf
    set 2, e
    ld a, a
    pop bc
    db $d3
    ld a, a
    ret


    ld c, a
    add $7f
    call nz, $d5d2
    adc $cb
    push bc
    adc $81
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ret nc

    pop bc
    ld d, l
    ret


    adc $c6
    push de
    call z, $cd7f
    reti


    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c97f
    db $d3
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    add c
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret


    call $d3c5
    ld a, a
    pop bc
    jp nc, $c555

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    sub $c5
    jp nc, Jump_028_7fd9

    jp nz, $d3d5

    reti


    sbc a
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    pop bc
    ret z

    add c
    ld a, a
    and c
    jp nc, Jump_028_7fc5

    reti


    rst $08
    push de
    ld a, a
    jp $cf4f


    call $c9d0
    call z, $cec9
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    ret


    call z, $d5cc
    ld d, l
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    ld d, l
    ld d, h
    sbc a
    ld a, a
    xor c
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld d, l
    ld a, a
    db $d3
    push de
    rst $00
    rst $00
    push bc
    db $d3
    call nc, $cfc9
    adc $7f
    ret


    add $7f
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    call nz, Call_028_7fcf
    db $d3
    rst $08
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret nc

    pop bc
    rst $00
    push bc
    ld d, l
    ld a, a
    call $d9c1
    ld a, a
    call nc, $d2d5
    adc $7f
    pop bc
    push de
    call nc, $cdcf
    pop bc
    call nc, $c955
    jp $ccc1


    call z, Call_028_7fd9
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    jp $d5c1


    ld d, l
    rst $00
    ret z

    call nc, Call_028_547f
    ld a, a
    call nc, Call_028_7fcf
    ret


    adc $d6
    push bc
    db $d3
    call nc, $c955
    rst $00
    pop bc
    call nc, Call_028_7fc5
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_028_7f9f
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, $cf55
    ld a, a
    jp $d4c1


    jp Jump_028_7fc8


    sbc a
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    xor c
    ld a, a
    adc h
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    ret


    call nc, $d47f
    ld d, l
    rst $08
    ld a, a
    reti


    rst $08
    push de
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld c, a
    call $cecf
    push bc
    reti


    ld a, a
    ld d, [hl]
    ld d, [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $55c9
    call Call_028_7fc5
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cecf
    push bc
    reti


    ld a, a
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
    ld a, a
    sub $c9
    db $d3
    ret


    call nc, Call_028_4fc5
    call nz, $d47f
    ret z

    push bc
    ld a, a
    call $d3d5
    push bc
    push de
    call Call_028_7f9f
    ld d, a
    nop
    ld a, a
    xor a
    add $7f
    call nc, $c5c8
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_028_7f7f
    add $4f
    rst $08
    push de
    adc $c4
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    ld d, l
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $55
    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    ret c

    ret z

    ret


    jp nz, $d4c9

    ret


    rst $08
    adc $7f
    ld d, l
    ret


    db $d3
    ld a, a
    rst $10
    rst $08
    adc $c4
    push bc
    jp nc, $d5c6

    call z, Call_028_7f81
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    ld a, a
    ld d, [hl]
    add c
    ld a, a
    and e
    push bc
    jp nc, $c1d4

    ret


    adc $cc
    ld c, a
    reti


    ld a, a
    ret z

    pop bc
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $c77f

    rst $08
    ld a, a
    call nc, $c855
    push bc
    jp nc, Jump_028_7fc5

    ret


    add $7f
    db $d3
    rst $08
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    ld a, a
    ld d, [hl]
    add c
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    set 1, [hl]
    ld c, a
    rst $08
    rst $10
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $a97f
    add a
    call $c47f
    rst $08
    ret


    adc $c7
    ld d, l
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    add $7f
    jp $d5cf


    jp nc, $c5d3

    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    call nc, Call_028_4fc8
    pop bc
    call nc, Call_028_7f81
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call nz, $c6c9
    add $c9
    jp $d555


    call z, Call_028_7fd4
    call nc, Call_028_7fcf
    call nz, $c1c5
    call z, $d77f
    ret


    call nc, $81c8
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    ret z

    pop bc
    sub $c5
    ld a, a
    call nz, $d3d5
    call nc, $c4c5
    ld c, a
    ld a, a
    rst $10
    ret


    call nc, Call_028_7fc8
    pop bc
    adc $7f
    ret


    adc $d3
    push bc
    jp $c9d4


    jp $c955


    call nz, Call_028_7fc5
    ret


    adc $7f
    rst $08
    jp nc, $c5c4

    jp nc, $ce7f

    rst $08
    call nc, $557f
    call nc, Call_028_7fcf
    call z, $d4c5
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    ret


    call z, Call_028_7fc4
    ld d, l
    ld d, h
    push bc
    adc $d4
    push bc
    jp nc, $c97f

    adc $d4
    rst $08
    ld a, a
    ld a, a
    db $d3
    rst $08
    ld d, l
    ld a, a
    db $d3
    ret


    call $ccd0
    call z, Call_028_7fd9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    xor a
    push de
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, h
    ld c, a
    ld e, l
    sbc a
    ld a, a
    or h
    pop bc
    jp nc, $d3c3

    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    call z, $c9c9
    set 1, c
    adc $c7
    ld a, a
    add $cf
    jp nc, $c17f

    adc $7f
    rst $08
    ld d, l
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    jp $cdcf


    push bc
    ld d, l
    ld a, a
    ret z

    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    xor b
    ret


    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    rst $00
    ld c, a
    rst $08
    adc $c5
    ld a, a
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    xor l
    pop bc
    db $d3
    pop bc
    jp Jump_028_55c8


    push bc
    push bc
    add a
    db $d3
    ld a, a
    xor b
    push bc
    ld a, a
    call z, $d4c5
    ld a, a
    call Call_028_7fc5
    ret z

    pop bc
    ld d, l
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call z, $cfcf
    bit 7, a
    call nc, Call_028_7fcf
    ret z

    ret


    db $d3
    ld a, a
    ld d, l
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    or h
    ret z

    ld d, l
    pop bc
    adc $cb
    db $d3
    ld a, a
    ret z

    ret


    call $c67f
    rst $08
    jp nc, $c87f

    ret


    db $d3
    ld a, a
    ld d, l
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    adc $c4
    jp nz, $cf55

    rst $08
    bit 7, a
    ld d, h
    or h
    ret z

    push bc
    ld a, a
    ret nc

    pop bc
    rst $00
    push bc
    db $d3
    ld a, a
    ld d, l
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, $d2d5
    adc $c5
    call nz, $817f
    ld a, a
    and c
    adc $d9
    ld d, l
    ret z

    rst $08
    rst $10
    adc h
    ld a, a
    xor l
    pop bc
    db $d3
    pop bc
    jp $c5c8


    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    pop bc
    ld a, a
    add $c1
    call nc, $d3c1
    call nc, $c3c9
    ld a, a
    rst $08
    add $7f
    add $c1
    call $cf55
    push de
    db $d3
    ld a, a
    ld a, a
    ld d, h
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_028_7fc5

    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ld a, a
    ld d, h
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, Call_028_7f55
    db $d3
    reti


    db $d3
    call nc, $cdc5
    ld a, a
    rst $08
    add $7f
    jp $cdcf


    call $ced5
    ld d, l
    ret


    jp $d4c1


    ret


    rst $08
    adc $7f
    ld e, e
    add c
    ld a, a
    or h
    ret z

    pop bc
    call nc, $557f
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call $c4c1
    push bc
    ld a, a
    jp nz, Jump_028_7fd9

    xor l
    ld d, l
    pop bc
    db $d3
    pop bc
    jp $c5c8


    push bc
    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, $d5cf

    ld d, l
    call nc, $c77f
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_028_7fcf
    call nc, $c1c8
    adc $cb
    ld a, a
    ld d, l
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_028_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    push de
    ld d, l
    db $d3
    ret


    adc $c7
    ld a, a
    ret


    call nc, Call_028_7f9f
    xor c
    call nc, $d387
    ld a, a
    push bc
    adc $cf
    ld d, l
    push de
    rst $00
    ret z

    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $ce7f
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    push bc
    ld d, l
    pop bc
    call nc, $c77f
    jp nc, $d3c1

    db $d3
    ld a, a
    ret z

    push bc
    jp nc, Jump_028_7fc5

    rst $08
    adc $cc
    ld d, l
    reti


    add c
    ld a, a
    ld a, a
    ld d, [hl]
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    jp nz, $c5d9

    adc l
    jp nz, $d955

    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    xor b
    ret


    ld a, a
    ld d, d
    add c
    ld a, a
    ld c, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_028_7fc5

    call z, $c1cf
    add $c9
    adc $c7
    ld a, a
    call nc, $cf55
    ld a, a
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    ret


    adc $7f
    db $d3
    push de
    jp Jump_028_55c8


    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    add c
    ld a, a
    xor c
    ld a, a
    add $c9
    adc $c1
    ld d, l
    call z, $d9cc
    ld a, a
    jp $d4c1


    jp Jump_028_7fc8


    sub $c1
    jp nc, $c5c9

    call nc, Call_028_55d9
    ld a, a
    rst $08
    add $7f
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $10
    rst $08
    ld d, l
    adc $c4
    push bc
    jp nc, $d5c6

    call z, $8e7f
    ld a, a
    ld d, [hl]
    ld a, a
    or a
    ret z

    ret


    jp $c855


    adc h
    rst $10
    ret z

    ret


    jp $9fc8


    ld a, a
    ld d, d
    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    rst $10
    ret z

    pop bc
    call nc, $c87f
    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $d5c1


    ld d, l
    rst $00
    ret z

    call nc, Call_028_7f9f
    xor h
    push bc
    call nc, $cd7f
    push bc
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ld d, l
    pop bc
    ld a, a
    call z, $cfcf
    res 1, h
    ld a, a
    jp z, $d3d5

    call nc, $c17f
    ld a, a
    call z, Call_028_55cf
    rst $08
    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c57f
    adc $d4
    ld c, a
    push bc
    jp nc, $c97f

    adc $d4
    rst $08
    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, $cf7f

    adc $c5
    ld d, l
    add a
    db $d3
    ld a, a
    ret nc

    jp nc, $d6c9

    pop bc
    call nc, Call_028_7fc5
    reti


    pop bc
    jp nc, $81c4

    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    push bc
    call z, $8ccc
    ld a, a
    xor c
    sbc a
    ld a, a
    ld d, l
    ld d, [hl]
    adc [hl]
    ld a, a
    xor c
    add a
    call $ca7f
    push de
    db $d3
    call nc, $d07f
    pop bc
    db $d3
    db $d3
    ld d, l
    ret


    adc $c7
    ld a, a
    jp nz, Jump_028_7fd9

    ret z

    push bc
    jp nc, Jump_028_7fc5

    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $55
    reti


    ld a, a
    jp nz, $c9c5

    adc $c7
    ld a, a
    db $d3
    push de
    db $d3
    ret nc

    push bc
    jp $81d4


    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    push de
    db $d3
    ret nc

    push bc
    jp $9fd4


    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    add c
    ld c, a
    ld a, a
    or d
    push bc
    rst $00
    ret


    sub $c9
    adc $c7
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    call nc, $cccf
    push bc
    adc $7f
    ld d, l
    ld e, h
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    rst $08
    rst $08
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
    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    xor c
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c67f
    call z, Call_028_55c5
    push bc
    ld a, a
    rst $10
    ret


    call nc, $cfc8
    push de
    call nc, $c77f
    ret


    sub $c9
    adc $c7
    ld a, a
    ld d, l
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    jp nz, $c3c1

    bit 7, a
    call nc, Call_028_7fcf
    db $d3
    rst $08
    call $c555
    rst $08
    adc $c5
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $4f
    rst $00
    push bc
    call nz, $c27f
    pop bc
    jp Jump_028_7fcb


    ld d, l
    ld e, h
    ld a, a
    sub d
    sbc b
    add $55
    jp nc, $cdcf

    ld a, a
    ld e, [hl]
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    ld a, a
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    adc $8c
    ld a, a
    call nc, $c5c8
    adc $7f
    ld d, [hl]
    add c
    xor c
    add a
    call z, Call_028_7fcc
    ld d, l
    rst $10
    ret


    call nc, $c4c8
    jp nc, $d7c1

    add c
    ld a, a
    ld a, a
    ld d, [hl]
    db $d3
    push bc
    push bc
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c1
    push bc
    jp nc, Jump_028_7f81

    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    reti


    pop bc
    call nz, $d2c5
    call z, $cec1
    add c
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_028_7fc5

    ld c, a
    ret nc

    jp nc, $c4cf

    push de
    jp $cec9


    rst $00
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    ret nc

    call z, $cf55
    db $d3
    ret


    sub $c5
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    reti


    ld d, l
    pop bc
    call nz, $d2c5
    call z, $cec1
    ld a, a
    and c
    jp nc, Jump_028_7fc5

    reti


    rst $08
    push de
    ld a, a
    ret z

    ld d, l
    push bc
    pop bc
    jp nc, $cec9

    rst $00
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    pop bc
    call nz, $d2c5
    call z, $cec1
    add c
    ld a, a
    rst $08
    sub $c5
    jp nc, $d47f

    ld c, a
    ret z

    push bc
    jp nc, $8ec5

    ld a, a
    jp nz, $cfcf

    call Call_028_7f81
    ld d, [hl]
    ld a, a
    xor c
    call nc, Call_028_7f55
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    pop bc
    call nz, $d2c5
    call z, $cec1
    add c
    ld a, a
    call nz, $c6c5
    push bc
    adc $c4
    ld c, a
    ld a, a
    call nc, $cec5
    pop bc
    jp $cfc9


    push de
    db $d3
    call z, Call_028_7fd9
    ret


    adc $7f
    call nc, $c855
    push bc
    ld a, a
    db $d3
    ret z

    push bc
    call z, $81cc
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    adc [hl]
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_028_7fc5

    rst $10
    jp nc, $cecf

    rst $00
    add c
    ld a, a
    adc h
    ld d, l
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nc, $cfcf
    ld a, a
    call nc, Call_028_55d2
    rst $08
    push de
    jp nz, $c5cc

    db $d3
    rst $08
    call $81c5
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    or a
    ld d, l
    ret z

    push bc
    call nc, $c5c8
    jp nc, $cf7f

    jp nc, $ce7f

    rst $08
    call nc, $c97f
    call nc, $557f
    ret


    db $d3
    ld a, a
    rst $08
    jp nz, $c4c5

    ret


    push bc
    adc $d4
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, Call_028_55c5
    call nc, $d2c5
    call $cec9
    push bc
    call nz, $c27f
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $c555
    sub $c5
    call z, $cf7f
    add $7f
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    jp nc, Jump_028_55d3

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    pop bc
    call nz, $d2c5
    call z, $cec1
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $cbc1
    ret


    ld c, a
    adc $c7
    ld a, a
    pop bc
    ld a, a
    adc $c1
    ret nc

    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    pop bc
    call nz, $d2c5
    call z, $cec1
    ld a, a
    ret


    db $d3
    ld a, a
    call z, $c1cf
    add $4f
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp z, $c2cf

    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    pop bc
    call nz, $d2c5
    call z, $cec1
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $d2d5
    adc $4f
    ret


    adc $c7
    ld a, a
    pop bc
    ld a, a
    call nz, $c1c5
    add $7f
    push bc
    pop bc
    jp nc, $d47f

    rst $08
    ld d, l
    ld a, a
    pop bc
    adc $d9
    rst $08
    adc $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    pop bc
    call nz, $d2c5
    call z, $cec1
    ld a, a
    ret


    db $d3
    ld a, a
    ret nc

    jp nc, $d4c5

    ld c, a
    push bc
    adc $c4
    ret


    adc $c7
    ld a, a
    adc $cf
    call nc, $d47f
    rst $08
    ld a, a
    set 1, [hl]
    rst $08
    ld d, l
    rst $10
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    push bc
    adc h
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    db $d3
    push bc
    push bc
    adc $4f
    add c
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    pop bc
    jp nc, $55c2

    rst $08
    push de
    jp nc, $8c7f

    ld a, a
    jp $cdcf


    push bc
    db $d3
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    ld d, l
    adc $c4
    push de
    ld a, a
    and c
    adc $ce
    push de
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    and h
    ret


    call nz, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    adc $4f
    call nz, Call_028_7fd5
    and c
    adc $ce
    push de
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    db $d3
    push bc
    call nc, $557f
    db $d3
    pop bc
    ret


    call z, Call_028_7f9f
    xor c
    call nc, $d77f
    ret


    call z, Call_028_7fcc
    jp nz, Jump_028_7fc5

    ld d, l
    call nc, $c5c8
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    adc $55
    push bc
    ret c

    call nc, $d97f
    push bc
    pop bc
    jp nc, $d77f

    ret z

    push bc
    adc $7f
    ret


    call nc, $557f
    pop bc
    jp nc, $c9d2

    sub $c5
    db $d3
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call nz, Call_028_55d2
    ret


    push bc
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
    ld d, l
    add c
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    db $d3
    ld c, a
    pop bc
    adc $c4
    push de
    ld a, a
    and c
    adc $ce
    push de
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_7fc5
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    db $d3
    ld c, a
    pop bc
    adc $c4
    push de
    ld a, a
    and c
    adc $ce
    push de
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    add c
    ld a, a
    or b
    ld d, l
    pop bc
    jp nc, $cfc4

    adc $81
    ld a, a
    call nz, $c1c5
    jp nc, $c77f

    push de
    push bc
    db $d3
    call nc, $8c55
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    call Call_028_7fc5
    reti


    rst $08
    push de
    jp nc, $d47f

    ret


    ld d, l
    jp $c5cb


    call nc, Call_028_7f81
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, $cf4f
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    call nc, $c3c9
    set 0, l
    call nc, Call_028_7f55
    ld d, [hl]
    ld a, a
    call nc, Call_028_7fcf
    call nc, $c3c9
    set 0, l
    call nc, $c38d
    rst $08
    call z, $cc55
    push bc
    jp $cfd4


    jp nc, $c27f

    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call nc, $55c9
    jp $c5cb


    call nc, $c87f
    pop bc
    db $d3
    ld a, a
    jp nz, $c5c5

    adc $7f
    add $cf
    push de
    ld d, l
    adc $c4
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    rst $08
    jp nc, $d9d2

    add c
    ld a, a
    ld d, l
    xor a
    adc $cc
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    push bc
    adc $c7
    push bc
    ld d, l
    jp nc, Jump_028_7fd3

    rst $10
    ret z

    rst $08
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, $c3c9
    set 0, l
    ld d, l
    call nc, Call_028_7fd3
    jp $cec1


    ld a, a
    jp nz, $c1cf

    jp nc, Jump_028_7fc4

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    push bc
    db $d3
    ld a, a
    ret z

    ret


    db $d3
    ld c, a
    ld a, a
    call nc, $c3c9
    set 0, l
    call nc, $d47f
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $55c9
    jp $c5cb


    call nc, $c38d
    rst $08
    call z, $c5cc
    jp $cfd4


    jp nc, $817f

    ld a, a
    ld d, l
    xor a
    res 1, h
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    add c
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_028_55c5
    ld a, a
    call nc, Call_028_7fcf
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    adc $c4
    push de
    ld a, a
    and c
    adc $ce
    ld d, l
    push de
    ld a, a
    db $d3
    ret z

    ret


    ret nc

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
    ret z

    ret


    ret nc

    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    push bc
    call nc, Call_028_4fd4
    ret


    adc $c7
    ld a, a
    db $d3
    pop bc
    ret


    call z, Call_028_7f81
    ld d, a
    nop
    ld a, a
    pop bc
    ret z

    add c
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    db $d3
    push bc
    push bc
    ld c, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ret


    adc $c7
    ld a, a
    add $d2
    rst $08
    call Call_028_7f55
    call nc, $c5c8
    jp nc, Jump_028_7fc5

    xor [hl]
    rst $08
    rst $10
    ld a, a
    rst $10
    push bc
    ld a, a
    add $c9
    adc $55
    pop bc
    call z, $d9cc
    ld a, a
    call $c5c5
    call nc, $b481
    ret z

    push bc
    adc $7f
    xor c
    ld a, a
    ld d, l
    db $d3
    push bc
    adc $c4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    rst $08
    rst $08
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
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $4f
    push bc
    call nz, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $c8d4
    push bc
    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    ld a, a
    ld d, l
    add c
    ld a, a
    ld d, b
    dec bc
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Jump_028_7f00:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_028_7f4f:
Jump_028_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_028_7f55:
Jump_028_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_028_7f7f:
Jump_028_7f7f:
    nop
    nop

Call_028_7f81:
Jump_028_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_028_7f8c:
Jump_028_7f8c:
    nop
    nop

Call_028_7f8e:
Jump_028_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_028_7f9f:
Jump_028_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_028_7fc4:
Jump_028_7fc4:
    nop

Call_028_7fc5:
Jump_028_7fc5:
    nop
    nop
    nop

Call_028_7fc8:
Jump_028_7fc8:
    nop
    nop
    nop

Jump_028_7fcb:
    nop

Call_028_7fcc:
    nop
    nop

Jump_028_7fce:
    nop

Call_028_7fcf:
    nop

Call_028_7fd0:
    nop
    nop
    nop

Call_028_7fd3:
Jump_028_7fd3:
    nop

Call_028_7fd4:
Jump_028_7fd4:
    nop

Call_028_7fd5:
    nop
    nop
    nop
    nop

Call_028_7fd9:
Jump_028_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
