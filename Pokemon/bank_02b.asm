; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $02b", ROMX[$4000], BANK[$2b]

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
    rst $00
    rst $08
    call z, $c5c4
    adc $4f
    adc h
    ld a, a
    call nc, $c1d2
    adc $d3
    ret nc

    pop bc
    jp nc, $cec5

    call nc, $c17f
    adc $c4
    ld d, l
    ld a, a
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    call z, $c17f
    call $c5c2
    jp nc, Jump_02b_5581

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    pop bc
    jp nc, Jump_02b_7fc5

    sub $c1
    jp nc, $cfc9

    push de
    ld c, a
    db $d3
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    db $d3
    ld a, a
    call nc, Call_02b_7fcf
    push de
    db $d3
    push bc
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ld a, a
    call nc, Call_02b_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, Call_02b_7fc5
    ret


    ld d, l
    adc $7f
    call nc, $c9c8
    db $d3
    ld a, a
    jp nz, $cfd2

    pop bc
    call nz, $d77f
    rst $08
    jp nc, $55cc

    call nz, $817f
    ld a, a
    reti


    rst $08
    push de
    adc h
    db $d3
    push bc
    push bc
    call Call_02b_7fd3
    rst $08
    rst $10
    adc $55
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, Call_02b_7fcc
    rst $08
    add $7f
    ld d, l
    ld d, h
    ld a, a
    ld e, l
    add c
    ld a, a
    and a
    rst $08
    ld a, a
    call nc, $cf55
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    reti


    call $cf7f
    add $7f
    call nz, $c9d2
    push bc
    ld d, l
    call nz, $cc7f
    push bc
    pop bc
    sub $c5
    db $d3
    ld a, a
    jp $d4c9


    reti


    ld a, a
    pop bc
    adc $c4
    ld d, l
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d37f

    call nc, $c5d2
    adc $c7
    ld d, l
    call nc, Call_02b_7fc8
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    jp $cdcf


    push bc
    add c
    ld a, a
    xor c
    add a
    call $d47f
    ret z

    push bc
    ld a, a
    ret z

    push bc
    ld c, a
    pop bc
    call nz, $b47f
    pop bc
    jp nc, $c9d8

    ld a, a
    rst $08
    add $7f
    jp nc, $c9c1

    adc $c2
    ld d, l
    rst $08
    rst $10
    ld a, a
    ld d, h
    ld a, a
    rst $00
    reti


    call $817f
    ld a, a
    call Call_02b_7fd9
    ret


    ld d, l
    adc $d3
    ret


    db $d3
    call nc, $cec1
    call nc, $d77f
    ret


    call z, Call_02b_7fcc
    ld a, a
    jp nc, Jump_02b_55c5

    add $cc
    push bc
    jp $d3d4


    ld a, a
    ret


    adc $7f
    call Call_02b_7fd9
    ld d, h
    add c
    ld d, l
    ld a, a
    ret


    adc $d3
    ret


    db $d3
    call nc, $cec1
    jp Jump_02b_7fc5


    pop bc
    adc $c4
    ld a, a
    call nc, $cf55
    call z, $d2c5
    pop bc
    adc $c3
    push bc
    add c
    ld a, a
    or d
    ret


    rst $00
    ret z

    call nc, Call_02b_7f81
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    push de
    db $d3
    push bc
    call nz, Call_02b_7f8e
    and c
    call z, Call_02b_7fcc
    pop bc
    jp nc, Jump_02b_55c5

    ld a, a
    jp nc, $c3cf

    bit 7, a
    call nc, $d0d9
    push bc
    db $d3
    add c
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    ld d, l
    pop bc
    add c
    ld a, a
    and l
    sub $c5
    jp nc, $cfd9

    adc $c5
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    db $d3
    ld d, l
    ld a, a
    ret


    call nc, $d77f
    ret


    call z, Call_02b_7fcc
    call z, $d3cf
    push bc
    adc h
    ld a, a
    db $d3
    call nc, $c955
    call z, Call_02b_7fcc
    jp $cdcf


    ret nc

    push bc
    call nc, $9fc5
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    jp $c1c8


    jp nc, $c3c1

    call nc, $d2c5
    ret


    db $d3
    call nc, $c3c9
    ld d, l
    db $d3
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld e, l
    rst $00
    rst $08
    ld d, l
    rst $08
    call nz, $c57f
    adc $cf
    push de
    rst $00
    ret z

    sbc a
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    ld d, l
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    ld d, h
    ld a, a
    jp $c1c8


    ld c, a
    call Call_02b_7fd0
    adc h
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d47f
    pop bc
    set 0, l
    ld a, a
    ret


    ld d, l
    call nc, $c17f
    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    pop bc
    call z, Call_02b_7f9f
    xor c
    add a
    call Call_02b_557f
    adc $cf
    call nc, Call_02b_5d7f
    ld a, a
    adc [hl]
    ld a, a
    jp nz, $d4d5

    ld d, l
    ld a, a
    ret


    adc $7f
    rst $08
    jp nc, $c5c4

    jp nc, $d47f

    rst $08
    ld a, a
    rst $10
    ret


    adc $7f
    ld d, l
    adc h
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
    ld a, a
    db $d3
    push de
    ld d, l
    rst $00
    rst $00
    push bc
    db $d3
    call nc, $cfc9
    adc $81
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $af7f
    ld d, l
    res 3, a
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    rst $10
    rst $08
    jp nc, $55cb

    ld a, a
    ret z

    pop bc
    jp nc, Jump_02b_7fc4

    add $cf
    jp nc, $d77f

    ret


    adc $ce
    ret


    adc $c7
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    jp $c1c8


    call $81d0
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    res 0, c
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, Call_02b_4f7f
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or b
    call z, $c1c5
    db $d3
    push bc
    ld a, a
    call nz, $cecf
    add a
    call nc, $d37f
    call nc, Call_02b_4fc1
    adc $c4
    ld a, a
    rst $08
    adc $7f
    jp $d2c5


    push bc
    call $cecf
    reti


    add c
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    adc $8c
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, $c17f
    call nc, $cf7f
    adc $c3
    ld d, l
    push bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $cec1
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    add $c9
    jp nc, Jump_02b_4fd3

    call nc, $c37f
    rst $08
    call $c5d0
    call nc, $d3c5
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $d0cf
    ret nc

    push bc
    ld d, l
    db $d3
    call nc, $cf7f
    add $7f
    call z, $d3c9
    call nc, Call_02b_547f
    add c
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    call $d9c1
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    ld d, l
    call nz, $c1d6
    adc $d4
    pop bc
    rst $00
    push bc
    ld a, a
    ret


    add $7f
    push bc
    ret c

    jp $c1c8


    ld d, l
    adc $c7
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    jp nc, $c5c4

    jp nc, Jump_02b_7f81

    ld d, l
    or h
    jp nc, Jump_02b_7fd9

    pop bc
    adc $c4
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call z, Call_02b_55cf
    rst $08
    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    and l
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $4fc4

    ret


    adc $c1
    jp nc, $81d9

    ld a, a
    xor e
    push bc
    push bc
    ret nc

    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, l
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $10
    rst $08
    jp nc, Jump_02b_7fcb

    ret z

    pop bc
    ld d, l
    jp nc, $c5c4

    jp nc, Jump_02b_7f81

    ld d, h
    ld a, a
    jp $c1c8


    call $81d0
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and d
    push de
    call z, $c9cc
    adc $9a
    and d
    push de
    adc h
    jp nz, $8ed5

    ld a, a
    ld d, a
    nop
    ld a, a
    ld e, h
    ld de, $c77f
    pop bc
    ld c, a
    sub $c5
    ld a, a
    ld d, h
    ld a, a
    call nc, $c5c8
    ld a, a
    add $cf
    pop bc
    call $d47f
    ld d, l
    pop bc
    jp $c9d4


    jp Jump_02b_7fd3


    adc [hl]
    ld a, a
    xor h
    push bc
    call nc, Call_02b_547f
    ld a, a
    ld d, l
    ld a, a
    call z, $d6c9
    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    ld d, l
    call nc, $d2c5
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    ret


    call nc, Call_02b_7f81
    ld d, a
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    reti


    rst $08
    push de
    add c
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    pop bc
    ld a, a
    ld c, a
    db $d3
    set 1, c
    call z, $c5cc
    call nz, $d07f
    push bc
    jp nc, $cfd3

    adc $7f
    jp $55c1


    adc $7f
    ret z

    push bc
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_02b_7fc5
    pop bc
    adc $7f
    push bc
    ret c

    ld d, l
    ret nc

    push bc
    jp nc, Jump_02b_7fd4

    rst $10
    ret z

    ret


    call z, Call_02b_7fc5
    add $cf
    db $d3
    call nc, $d2c5
    ld d, l
    ret


    adc $c7
    ld a, a
    ld d, h
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c47f
    rst $08
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    jp $cecf


    db $d3
    ret


    call nz, $d2c5
    ld a, a
    rst $10
    ret z

    push bc
    adc $55
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, Call_02b_547f
    ld a, a
    ld a, a
    ld d, l
    sbc a
    ld a, a
    xor l
    reti


    ld a, a
    db $d3
    set 1, c
    call z, Call_02b_7fcc
    ret


    db $d3
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    call nc, Call_02b_7fcf
    pop bc
    call nc, $c1d4
    jp Jump_02b_7fcb


    push de
    db $d3
    ret


    adc $c7
    ld a, a
    rst $10
    ld d, l
    pop bc
    call nc, $d2c5
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, h
    adc [hl]
    ld d, l
    ld a, a
    pop bc
    call nc, $c1d4
    jp $8ccb


    ld a, a
    pop bc
    call nc, $c1d4
    jp Jump_02b_7fcb


    rst $10
    ld d, l
    ret


    call nc, Call_02b_7fc8
    call nc, $c5c8
    ld a, a
    call nz, $c1c5
    call nc, $8dc8
    call nz, $c6c5
    ld d, l
    reti


    ret


    adc $c7
    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    and c
    ld a, a
    add $d5
    call nc, $d2d5
    ld c, a
    push bc
    ld a, a
    jp $c1c8


    call $81d0
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    pop bc
    ld a, a
    db $d3
    push de
    rst $00
    rst $00
    push bc
    db $d3
    call nc, $cfc9
    adc $81
    ld a, a
    xor b
    push bc
    ld d, l
    jp nc, Jump_02b_7fc5

    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $a37f
    pop bc
    db $d3
    ret


    call $d955
    ld a, a
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    call z, Call_02b_55c9
    sub $c9
    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    ld d, l
    adc [hl]
    ld a, a
    and c
    call nc, $d47f
    ret z

    ret


    db $d3
    ld a, a
    call nc, $cdc9
    push bc
    adc h
    ld a, a
    push de
    ld d, l
    db $d3
    push bc
    ld a, a
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, l
    call nc, Call_02b_7fcf
    pop bc
    jp nz, $cfd3

    jp nc, Jump_02b_7fc2

    rst $10
    pop bc
    call nc, $d2c5
    ld a, a
    rst $08
    ld d, l
    jp nc, $d57f

    db $d3
    push bc
    ld a, a
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $d4c9


    reti


    ld d, l
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    add $7f
    ld a, a
    call nc, Call_02b_7fcf
    ret nc

    pop bc
    jp nc, $55c1

    call z, $dad9
    push bc
    ld a, a
    ret z

    ret


    call Call_02b_7f8c
    jp nz, $d4cf

    ret z

    ld a, a
    db $d3
    call nc, $d255
    pop bc
    call nc, $c7c5
    ret


    push bc
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    pop bc
    call z, Call_02b_7fcc
    ld d, l
    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    ld c, a
    and e
    pop bc
    db $d3
    ret


    call $81d9
    ld a, a
    xor h
    ret


    set 0, l
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_02b_7f55
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    push bc
    ret c

    jp $ccc5


    call z, $c555
    adc $d4
    adc h
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call Call_02b_7fc5
    call nc, $cfcf
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and h
    ret


    call nz, $d97f
    rst $08
    push de
    ld a, a
    jp nz, $d9d5

    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $c94f

    call nc, $c67f
    jp nc, $c7c1

    call $cec5
    call nc, Call_02b_7f9f
    and c
    ld a, a
    call nz, Call_02b_55d9
    ret


    adc $c7
    adc l
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    and c
    ld a, a
    ld d, l
    jp $cecf


    sub $c5
    adc $c9
    push bc
    adc $d4
    ld a, a
    ret nc

    jp nc, $d0cf

    ld a, a
    call nc, $cf55
    ld a, a
    call z, $d4c5
    ld a, a
    ret z

    ret


    call $d27f
    push bc
    sub $c9
    sub $c5
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    add $cf
    jp nc, $c5c3

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    push bc
    jp $cec5


    call nc, $d9cc
    adc h
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    call z, $4fc4
    ld a, a
    jp nz, $ccc1

    call z, $d77f
    pop bc
    db $d3
    ld a, a
    ret nc

    ret


    jp $c5cb


    call nz, Call_02b_557f
    push de
    ret nc

    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $cdc5

    rst $08
    call nc, Call_02b_7fc5
    ld d, l
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $d3
    ld a, a
    xor c
    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    ld d, l
    db $d3
    rst $08
    call z, Call_02b_7fc4
    sub l
    sub b
    sub b
    sub b
    add h
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    ld d, l
    push bc
    ld a, a
    rst $08
    add $7f
    adc $cf
    call nc, $c27f
    push bc
    ret


    adc $c7
    ld a, a
    push de
    db $d3
    ld d, l
    push bc
    call nz, Call_02b_7f8e
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    call z, $d4c5
    ld a, a
    call $c54f
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
    ld a, a
    db $d3
    push de
    rst $00
    rst $00
    ld d, l
    push bc
    db $d3
    call nc, $cfc9
    adc $81
    ld a, a
    and l
    call z, $c3c5
    call nc, $c9d2
    jp Jump_02b_557f


    ret nc

    rst $08
    rst $10
    push bc
    jp nc, $c97f

    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_02b_7fd9

    db $d3
    call nc, $55d2
    rst $08
    adc $c7
    add c
    ld a, a
    jp nz, $d4d5

    adc h
    ld a, a
    xor c
    call nc, $d77f
    ret


    call z, $55cc
    ld a, a
    jp nz, Jump_02b_7fc5

    pop bc
    jp nz, $cfd3

    jp nc, $c5c2

    call nz, $c67f
    rst $08
    jp nc, Jump_02b_557f

    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d5cf

    adc $c4
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    ld d, l
    add $7f
    adc [hl]
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
    jp Jump_02b_55d4


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, Call_02b_7fcc
    add c
    ld a, a
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $cf4f

    reti


    add c
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d57f

    adc $c3
    rst $08
    call $ccd0
    push bc
    ld d, l
    call nc, Call_02b_7fc5
    db $d3
    set 1, c
    call z, Call_02b_7fcc
    jp $cec1


    add a
    call nc, $c87f
    push bc
    ld d, l
    call z, Call_02b_7fd0
    reti


    rst $08
    push de
    ld a, a
    call nc, Call_02b_7fcf
    db $d3
    push de
    jp nc, $c9d6

    sub $c5
    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $d4c1

    call nc, $c5cc
    add $c9
    push bc
    ld d, l
    call z, $81c4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $c87f
    pop bc
    sub $c5
    ld d, l
    ld a, a
    push de
    db $d3
    push bc
    call nz, Call_02b_547f
    pop bc
    adc $7f
    push bc
    call z, $c3c5
    call nc, $d255
    ret


    jp $d37f


    ret z

    rst $08
    jp Jump_02b_7fcb


    ld a, a
    call nc, Call_02b_7fcf
    db $d3
    push de
    jp nc, $d655

    ret


    sub $c5
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    jp nc, $817f

    ld d, l
    ld a, a
    and c
    call z, Call_02b_7fcc
    pop bc
    jp nc, Jump_02b_7fc5

    ret nc

    pop bc
    jp nc, $ccc1

    reti


    jp c, Jump_02b_55c5

    call nz, $c17f
    adc $c4
    ld a, a
    jp $cec1


    add a
    call nc, $cd7f
    rst $08
    sub $c5
    ld a, a
    ld d, l
    pop bc
    adc $d9
    ld a, a
    call $d2cf
    push bc
    add c
    ld a, a
    reti


    rst $08
    push de
    add a
    call z, Call_02b_7fcc
    ld d, l
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, Call_02b_7fcf
    rst $00
    rst $08
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    pop bc
    call Call_02b_7fc5
    rst $10
    pop bc
    reti


    ld a, a
    adc [hl]
    ld a, a
    or b
    call z, $c4c5
    rst $00
    ld d, l
    push bc
    ld a, a
    call nc, Call_02b_7fcf
    jp nz, Jump_02b_7fc5

    call nc, $d5d2
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    and c
    ld a, a
    add $d5
    call nc, $d2d5
    ld c, a
    push bc
    ld a, a
    jp $c1c8


    call $81d0
    ld a, a
    xor l
    pop bc
    jp z, $d2cf

    ld a, a
    xor l
    pop bc
    ld d, l
    jp nc, $c8c3

    ret


    db $d3
    add a
    ld a, a
    db $d3
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call Call_02b_55c5
    ld a, a
    ret


    db $d3
    ld a, a
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    and c
    call $c555
    jp nc, $c3c9

    pop bc
    add c
    ld a, a
    xor c
    add $7f
    call z, $d4c5
    ld a, a
    ret z

    ret


    call Call_02b_7f55
    push de
    db $d3
    push bc
    ld a, a
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp Jump_02b_557f


    ld d, h
    ld a, a
    adc h
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call $c555
    ld a, a
    db $d3
    push bc
    push bc
    call Call_02b_7fd3
    call nc, Call_02b_7fcf
    jp nz, Jump_02b_7fc5

    xor d
    pop bc
    ret nc

    ld d, l
    pop bc
    adc $c5
    db $d3
    push bc
    ld a, a
    rst $08
    adc $c5
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp Jump_02b_55c8


    pop bc
    jp nc, $c3c1

    call nc, $d2c5
    ret


    db $d3
    call nc, $c3c9
    db $d3
    ld a, a
    rst $08
    add $7f
    ld d, l
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $10
    ld d, l
    pop bc
    call nc, $d2c5
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, Call_02b_7f55
    call $d4c1
    jp Jump_02b_7fc8


    rst $10
    push bc
    call z, $81cc
    ld a, a
    and h
    rst $08
    adc $87
    ld d, l
    call nc, $cc7f
    push bc
    call nc, $c87f
    ret


    call $d47f
    rst $08
    ld a, a
    ret nc

    jp nc, $c4cf

    ld d, l
    push de
    jp Jump_02b_7fc5


    ret nc

    pop bc
    jp nc, $ccc1

    reti


    db $d3
    ret


    db $d3
    adc [hl]
    ld a, a
    and d
    push bc
    ld d, l
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, Call_02b_7f81
    ld a, a
    xor l
    pop bc
    jp nc, $c8c3

    ret


    ld d, l
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    jp $d5c1


    call nc, $cfc9
    push de
    db $d3
    add c
    ld a, a
    and c
    adc $55
    call nz, Call_02b_7f8c
    xor b
    ret


    db $d3
    ld a, a
    jp nc, $cfcf

    call $d77f
    pop bc
    db $d3
    ld a, a
    rst $08
    ld d, l
    add $d4
    push bc
    adc $7f
    call z, $c3cf
    set 0, l
    call nz, Call_02b_7f8e
    and l
    sub $c5
    jp nc, $d955

    rst $08
    adc $c5
    ld a, a
    jp $cec1


    add a
    call nc, $c57f
    pop bc
    db $d3
    ret


    call z, Call_02b_55d9
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $c97f

    adc $d4
    rst $08
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_02b_7f8c
    xor b
    rst $08
    rst $10
    ld a, a
    ret


    adc $d4
    push bc
    adc $d3
    push bc
    ld c, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret


    adc $d4
    push bc
    jp nc, $c1ce

    call nc, Call_02b_55c9
    rst $08
    adc $c1
    call z, $c37f
    rst $08
    call $c5d0
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    sbc d
    and c
    ret z

    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call nz, Call_02b_4fcf
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $81cf
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $c955
    set 0, l
    ld a, a
    ld d, h
    sbc a
    ld a, a
    ld d, d
    sbc d
    xor [hl]
    rst $08
    ld d, l
    call nc, $c17f
    db $d3
    bit 7, a
    call $8cc5
    ld a, a
    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    pop bc
    ld d, l
    db $d3
    bit 7, a
    reti


    rst $08
    push de
    add c
    ld d, d
    sbc d
    ld d, [hl]
    adc h
    ld a, a
    ld d, l
    and c
    ret z

    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_02b_7f81
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $c1d2
    ld d, l
    adc $c7
    push bc
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    add c
    ld a, a
    xor c
    call $d4c9
    pop bc
    ld d, l
    call nc, $cec9
    rst $00
    ld a, a
    rst $00
    ret


    jp nc, $9acc

    ld d, [hl]
    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    ld d, l
    call nc, Call_02b_7f9f
    ret


    call $d4c9
    pop bc
    call nc, Call_02b_7fc5
    rst $08
    call nc, $c5c8
    jp nc, Jump_02b_55d3

    sbc a
    ld a, a
    and e
    push bc
    jp nc, $c1d4

    ret


    adc $cc
    reti


    adc h
    ld a, a
    ld a, a
    ld a, a
    xor c
    adc h
    ld d, l
    ld a, a
    adc h
    ld a, a
    xor l
    reti


    ld a, a
    ret


    adc $d4
    push bc
    jp nc, $d3c5

    call nc, $cec9
    rst $00
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, Call_02b_7fcf
    ret


    call $d4c9
    pop bc
    call nc, $81c5
    ld a, a
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
    and a
    ret


    sub $c5
    ld a, a
    call Call_02b_7fc5
    or b
    ld c, a
    ret


    ret nc

    ret


    ld a, a
    ret nc

    call z, $d9c1
    call nc, $c9c8
    adc $c7
    add c
    ld a, a
    xor b
    rst $08
    ld d, l
    rst $10
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    reti


    add c
    ld a, a
    ld d, [hl]
    ld a, a
    or h
    ret z

    push bc
    adc $81
    ld d, l
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
    call nc, $c9c8
    db $d3
    add c
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02b_4f7f
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
    ret


    jp nc, $87cc

    db $d3
    ld a, a
    ret z

    ld d, l
    pop bc
    adc $c4
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    xor c
    adc $7f
    ld d, l
    ld e, h
    sub e
    sub c
    ld a, a
    ld a, a
    ld d, l
    ret


    db $d3
    ld a, a
    ret


    call $d4c9
    pop bc
    call nc, $cfc9
    adc $7f
    xor c
    ld a, a
    call z, Call_02b_55cf
    sub $c5
    call nz, Call_02b_7f81
    xor h
    push bc
    call nc, $c87f
    ret


    call $d57f
    db $d3
    push bc
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    jp nc, Jump_02b_547f

    ld a, a
    add c
    ld a, a
    ld d, b
    dec c
    ld d, b
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
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    ld d, d
    sbc d
    and c
    ret z

    add c
    ld a, a
    jp z, $d3d5

    call nc, $ce7f
    ld c, a
    rst $08
    rst $10
    ld a, a
    ld a, a
    ld d, l
    ld e, h
    call nc, $c1c8
    adc $55
    set 2, e
    add c
    ld a, a
    ld d, d
    sbc d
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    ret z

    ld d, l
    pop bc
    call nc, Call_02b_7f9f
    ld d, d
    sbc d
    ld a, a
    or h
    rst $08
    ld a, a
    ret


    call Call_02b_55c9
    call nc, $d4c1
    push bc
    ld a, a
    call Call_02b_7fc5
    adc h
    ld a, a
    call nc, $c5c8
    adc $7f
    pop bc
    jp nc, $c555

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp z, $d9cf

    sbc a
    ld a, a
    xor c
    call $d4c9
    pop bc
    call nc, $c955
    adc $c7
    ld a, a
    rst $00
    ret


    jp nc, $9acc

    xor b
    add a
    call $567f
    add c
    ld a, a
    ld d, l
    sub $c5
    jp nc, Jump_02b_7fd9

    ret z

    pop bc
    ret nc

    ret nc

    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    sbc a
    ld a, a
    and e
    pop bc
    adc $87
    call nc, $d37f
    push bc
    push bc
    ld a, a
    pop bc
    adc $d9
    call nc, $c84f
    ret


    adc $c7
    add c
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    xor l
    reti


    ld a, a
    db $d3
    push bc
    ld c, a
    jp $c5d2


    call nc, $567f
    add c
    ld a, a
    and d
    push bc
    ld a, a
    add $cf
    adc $c4
    sbc d
    ld d, l
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    call $d4c9
    pop bc
    call nc, $cec9
    rst $00
    add c
    ld a, a
    xor c
    adc $55
    call nc, $d2c5
    push bc
    db $d3
    call nc, Call_02b_7f9a
    ld d, [hl]
    ld a, a
    ret nc

    call z, $d9c1
    call nc, Call_02b_55c8
    ret


    adc $c7
    add c
    ld a, a
    xor h
    ret


    set 0, l
    sbc d
    ld a, a
    ld d, [hl]
    ld a, a
    or b
    ret


    ret nc

    ld d, l
    ret


    add c
    ld a, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    rst $10
    ld c, a
    jp nc, $d3c5

    call nc, $c5cc
    jp nc, $a17f

    adc $7f
    push bc
    ret c

    push bc
    call $ccd0
    ld d, l
    pop bc
    jp nc, Jump_02b_7fd9

    call $d3c1
    call nc, $d2c5
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    push bc
    call $d4d0
    reti


    adc l
    ret z

    pop bc
    adc $c4
    push bc
    call nz, $ca7f
    push de
    call nz, $cf55
    ld a, a
    ret


    adc $7f
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    reti


    pop bc
    jp nc, $c455

    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    ld d, l
    pop bc
    call z, Call_02b_7fcc
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    db $d3
    ld d, l
    add c
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    ld a, a
    call nz, Call_02b_55cf
    adc $87
    call nc, $d37f
    call nc, $cec1
    call nz, $cf7f
    adc $7f
    jp $d2c5


    push bc
    ld d, l
    call $cecf
    reti


    add c
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, $8155
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, Jump_02b_4fcf

    push de
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    and e
    pop bc
    adc $7f
    rst $10
    push bc
    ld a, a
    push bc
    ret c

    ld d, l
    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    call $d4d0
    reti


    adc l
    ld d, l
    ret z

    pop bc
    adc $c4
    push bc
    call nz, $ca7f
    push de
    call nz, Call_02b_7fcf
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    ld d, l
    ld a, a
    jp nz, Jump_02b_7fd9

    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    reti


    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d27f
    push bc
    pop bc
    call z, $d9cc
    ld a, a
    call z, $d3cf
    call nc, Call_02b_4f81
    ld a, a
    jp nz, $d4d5

    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    ret


    rst $00
    adc $7f
    rst $08
    add $7f
    ld d, l
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    reti


    pop bc
    jp nc, Jump_02b_7fc4

    ld a, a
    ld d, l
    ld d, [hl]
    rst $08
    adc $cc
    reti


    ld a, a
    call nc, $c9c8
    db $d3
    add c
    ld a, a
    and h
    rst $08
    adc $87
    ld d, l
    call nc, $d47f
    pop bc
    set 0, l
    ld a, a
    ret


    call nc, $c17f
    rst $10
    pop bc
    reti


    add c
    ld a, a
    and a
    ld d, l
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call Call_02b_7fd9
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    ld d, l
    push de
    db $d3
    ld a, a
    rst $10
    jp nc, $d3c5

    call nc, $c5cc
    ld a, a
    ld d, h
    pop bc
    db $d3
    ld a, a
    ld d, l
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    adc $d3
    pop bc
    call nc, $cfc9
    adc $81
    ld a, a
    xor b
    ld d, l
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
    and e
    ret z

    rst $08
    ld d, l
    rst $08
    db $d3
    push bc
    ld a, a
    rst $08
    adc $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld d, l
    jp nz, $d3c5

    call nc, Call_02b_7f81
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld a, a
    rst $00
    jp nc, $c5c5

    call nz, Call_02b_7fd9
    ld c, a
    call nz, $c5c5
    call nz, Call_02b_7f81
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    set 1, c
    jp $8dcb


    db $d3
    bit 1, a
    ret


    call z, Call_02b_7fcc
    call $cecf
    db $d3
    call nc, $d2c5
    add c
    ld a, a
    or h
    rst $08
    ld a, a
    rst $08
    ld d, l
    jp $d5c3


    ret nc

    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $cdc1
    ret nc

    ld a, a
    call z, Call_02b_55cf
    rst $10
    adc l
    call z, $c9d9
    adc $c7
    ld a, a
    call z, $cec1
    call nz, Call_02b_7f9f
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    call nc, $cfcf
    ld a, a
    rst $00
    jp nc, $4fc5

    push bc
    call nz, $81d9
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    db $d3
    ret


    adc $c7
    ld a, a
    jp Jump_02b_4fcf


    call z, $d2cf
    pop bc
    call nc, $d2d5
    pop bc
    add c
    ld a, a
    or h
    rst $08
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    ld d, l
    db $d3
    ret z

    jp nc, $cdc9

    ret nc

    ld a, a
    db $d3
    ret z

    push bc
    call z, $9fcc
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $c18d

    jp nz, $ccc9

    ret


    call nc, Call_02b_7fd9
    ret


    db $d3
    ld c, a
    adc $87
    call nc, $c37f
    rst $08
    adc $c6
    ret


    adc $c5
    call nz, $d47f

Call_02b_4f7f:
    rst $08
    ld a, a

Call_02b_4f81:
    add c
    ld d, l
    ld a, a
    or a
    ret z

    rst $08
    push bc
    sub $c5
    jp nc, $c87f

    pop bc
    db $d3
    ld a, a
    ret


    call nc, Call_02b_7f81
    ld d, l
    rst $08
    adc $cc
    reti


    ld a, a
    jp z, $d3d5

    call nc, $ce7f
    rst $08
    call nc, $d07f
    pop bc
    reti


    ld d, l
    ld a, a
    pop bc
    call nc, $c5d4
    adc $d4
    ret


    rst $08
    adc $7f
    call nc, Call_02b_7fcf
    ret


    call nc, Call_02b_5581
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    add $c9

Call_02b_4fc1:
Jump_02b_4fc1:
    adc $c1
    call z, $d9cc

Call_02b_4fc6:
    ld a, a
    jp $cdcf


    push bc
    db $d3

Call_02b_4fcc:
    ld c, a
    add c
    ld a, a

Call_02b_4fcf:
Jump_02b_4fcf:
    and l
    ret c

    ret nc

    push bc

Jump_02b_4fd3:
    jp $c5d4


    call nz, Call_02b_7f81
    and c
    add $d4
    push bc
    jp nc, Jump_02b_7f55

    call Call_02b_7fd9
    call nc, $d2c8
    rst $08
    rst $10
    ret


    adc $c7
    ld a, a
    db $d3
    ret nc

    rst $08
    rst $08
    ld d, l
    adc $7f
    pop bc
    adc $c4
    ld a, a
    jp $d2d5


    sub $c9
    adc $c7
    ld a, a
    ret


    call nc, Call_02b_557f
    ret


    adc $c1
    call nz, $c5d6
    jp nc, $c5d4

    adc $d4
    call z, $8cd9
    ld a, a
    xor c
    adc h
    ld d, l
    ld a, a
    adc h
    ld a, a
    jp nz, $c3c5

    rst $08
    call $d3c5
    ld a, a
    pop bc
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    ld d, l
    jp nc, $c9c7

    jp nc, $8ecc

    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    ld d, l
    call nc, $cc7f
    ret


    set 0, l
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    ld d, l
    adc $8e
    ld a, a
    and d
    push de
    call nc, $8c7f
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ld d, l
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02b_7fcf
    call nz, Call_02b_7fcf
    db $d3
    rst $08
    adc h
    xor c
    add a
    call z, $55cc
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call Call_02b_7fd9
    add $cf
    jp nc, Jump_02b_55c3

    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    add $d5
    call nc, $d2d5
    push bc
    ld a, a
    ld c, a
    jp $c1c8


    call $81d0
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $08
    add $7f
    xor [hl]
    pop bc
    ld d, l
    jp $c9c8


    call Call_02b_7fd9
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $55c1

    jp nz, $ccc9

    ret


    call nc, Call_02b_7fd9
    adc [hl]
    ld a, a
    and l
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $cc55
    reti


    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    jp nc, $d3c5

    call nc, $c5cc
    jp nc, Jump_02b_557f

    ld d, h
    or h
    rst $10
    rst $08
    ld a, a
    call nz, $cecf
    add a
    call nc, $cd7f
    pop bc
    call nc, Call_02b_55c3
    ret z

    ld a, a
    rst $10
    push bc
    call z, $81cc
    ld a, a
    and d
    push bc
    add $cf
    jp nc, Jump_02b_7fc5

    ret nc

    jp nc, $cf55

    call nz, $c3d5
    ret


    adc $c7
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $c2c1

    ret


    call z, $d4c9
    reti


    ld a, a
    ld d, [hl]
    sbc a
    ld c, a
    ld a, a
    xor c
    add $7f
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, $c1c8
    call nc, Call_02b_7f7f
    ld d, l
    adc h
    ld a, a
    xor c
    add a
    call z, Call_02b_7fcc
    call $cbc1
    push bc
    ld a, a
    call $c3d5
    ret z

    ld a, a
    ld d, l
    call $cecf
    push bc
    reti


    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $cfd2
    ret nc

    ld d, l
    adc l
    jp $c9cf


    adc $7f
    rst $00
    pop bc
    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $cc7f
    ret


    rst $00
    ret z

    call nc, $c9ce
    adc $c7
    ld c, a
    ld a, a
    call z, $cdc1
    ret nc

    ld a, a
    adc h
    ld a, a
    rst $10
    ret z

    ret


    jp Jump_02b_7fc8


    ret


    db $d3
    ld a, a
    ld d, l
    ret z

    pop bc
    adc $c4
    push bc
    call nz, $c47f
    rst $08
    rst $10
    adc $7f
    add $d2
    rst $08
    call Call_02b_557f
    pop bc
    adc $c3
    ret


    push bc
    adc $d4
    ld a, a
    call nc, $cdc9
    push bc
    db $d3
    adc h
    ld a, a
    jp $55c1


    adc $7f
    call $cbc1
    push bc
    ld a, a
    pop bc
    adc $d9
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    ld a, a
    call nz, $c155
    jp nc, Jump_02b_7fcb

    ret nc

    call z, $c3c1
    push bc
    ld a, a
    call nc, Call_02b_7fcf
    jp nz, $c3c5

    rst $08
    ld d, l
    call Call_02b_7fc5
    sub $c5
    jp nc, Jump_02b_7fd9

    jp nz, $c9d2

    rst $00
    ret z

    call nc, $817f
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    push bc
    call Call_02b_7fd3
    call nc, Call_02b_7fcf
    jp nz, Jump_02b_7fc5

    call nc, $d2c9
    push bc
    ld c, a
    call nz, Call_02b_7f81
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp nc, $d3c5

    call nc, $c97f
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $d3c5

    call nc, $d27f
    rst $08
    rst $08
    call Call_02b_7f81
    ld e, b
    nop
    ld a, a
    and e
    rst $08
    call Call_02b_7fc5
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    push de
    jp Jump_02b_7fc8


    ret z

    push bc
    call z, $8cd0
    ld a, a
    call nc, $c1c8
    adc $cb
    ld c, a
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    jp $81c8


    ld a, a
    xor a
    ld c, a
    adc $7f
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, Call_02b_7fcf
    push de
    db $d3
    push bc
    ld a, a
    jp $cdcf


    call $d555
    adc $c9
    jp $d4c1


    ret


    rst $08
    adc $7f
    jp $c2c1


    call z, Call_02b_7fc5
    adc [hl]
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    rst $08
    ld a, a
    jp nc, $c1c5

    call nz, $d77f
    ret z

    ret


    jp Jump_02b_7fc8


    db $d3
    push de
    ld c, a
    jp nz, $c5ca

    jp $9fd4


    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c1cc

    jp $c2cb


    rst $08
    pop bc
    jp nc, $c44f

    ld a, a
    adc h
    ld a, a
    rst $10
    jp nc, $d4c9

    push bc
    db $d3
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ld d, l
    ret


    adc $c7
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    push bc
    adc $c5
    call nz, $c97f
    adc $7f
    call nc, $c855
    push bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    ld a, a
    pop bc
    ld d, l
    jp nz, $d5cf

    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp $c1c8


    adc $c7
    push bc
    ld a, a
    rst $08
    ld d, l
    add $7f
    ld d, h
    add a
    db $d3
    ld a, a
    ret nc

    ret z

    ret


    db $d3
    ret


    jp $ccc1


    ld a, a
    ld d, l
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    rst $08
    ld a, a
    jp nc, $c1c5

    call nz, $d77f
    ret z

    ret


    jp Jump_02b_7fc8


    db $d3
    push de
    ld c, a
    jp nz, $c5ca

    jp $9fd4


    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ld c, a
    pop bc
    jp nz, $d5cf

    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $55d2
    pop bc
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    ld d, l
    ld d, h
    ld a, a
    ret


    db $d3
    sbc a
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    add $cf
    push de
    adc $55
    call nz, $a87f
    pop bc
    ret z

    pop bc
    ld a, a
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $c7c9

    push bc
    ld d, l
    jp nc, $a87f

    pop bc
    ret z

    pop bc
    ld a, a
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    ld a, a
    ld d, l
    add $cf
    push de
    adc $c4
    add c
    ld a, a
    or a
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    ret


    db $d3
    ld a, a
    ret


    ld d, l
    call nc, Call_02b_7f9f
    and c
    ret z

    add c
    ld a, a
    jp $d2c5


    call nc, $c9c1
    adc $cc
    reti


    ld a, a
    ld d, l
    ld a, a
    ret


    db $d3
    adc $87
    call nc, $c87f
    push bc
    jp nc, $81c5

    ld a, a
    or h
    ret z

    push bc
    adc $55
    adc h
    ld a, a
    xor c
    ld a, a
    call $d3d5
    call nc, $c77f
    rst $08
    add c
    ld a, a
    xor c
    add a
    call Call_02b_557f
    call nz, $c6c9
    add $c5
    jp nc, $cec5

    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    reti


    rst $08
    ld d, l
    push de
    adc [hl]
    ld a, a
    xor c
    add a
    call $d37f
    rst $08
    ld a, a
    jp nz, $d3d5

    reti


    add c
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    adc $8c
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c1
    push bc
    ld d, l
    jp nc, Jump_02b_7f81

    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    xor a
    ret z

    add c
    ld a, a
    ld d, d
    add c
    ld c, a
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
    call nz, Call_02b_7fcf
    call nc, $cf55
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    ret z

    push bc
    jp nc, $9fc5

    ld a, a
    xor c
    db $d3
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    jp nc, Jump_02b_547f

    ld a, a
    call nz, $c5c9
    call nz, Call_02b_7f9f
    ld d, [hl]
    ld a, a
    ld d, l
    xor [hl]
    push de
    ret


    db $d3
    pop bc
    adc $c3
    push bc
    add c
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld d, l
    call z, $d6c9
    push bc
    add c
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    pop bc
    call nc, $cc7f
    push bc
    ld d, l
    pop bc
    db $d3
    call nc, $8c7f
    ld a, a
    xor a
    push de
    call nc, $cdd3
    pop bc
    jp nc, Jump_02b_7fd4

    ret z

    ret


    ld d, l
    call Call_02b_7f81

Call_02b_547f:
Jump_02b_547f:
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    add $c1
    jp Jump_02b_7fc5


    rst $08
    add $4f
    ld a, a
    db $d3
    rst $08
    push de
    call z, $c97f
    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    call z, Call_02b_7f7f
    rst $08
    add $7f
    xor b
    pop bc
    ret z

    pop bc
    ld d, l
    add a
    db $d3
    ld a, a
    call $d4cf
    ret z

    push bc
    jp nc, $d57f

    adc $c1
    jp nz, $c5cc

    ld a, a
    ld d, l
    call nc, Call_02b_7fcf
    jp nz, $c3c5

    rst $08
    call Call_02b_7fc5
    and d
    push de
    call nz, $c8c4
    pop bc
    ld a, a
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nc, $d4c5

    push de
    jp nc, $c9ce

    adc $c7
    ld a, a
    db $d3
    rst $08
    ld c, a
    push de
    call z, $cf7f
    add $7f
    db $d3
    rst $08
    ld a, a
    set 1, c
    adc $c4
    ld a, a
    xor b
    pop bc
    ret z

    ld d, l
    pop bc
    add a
    db $d3
    ld a, a
    call $d4cf
    ret z

    push bc
    jp nc, $d387

    ld a, a
    adc $cf
    rst $10
    ld a, a
    ld d, l
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_02b_7fd3

    pop bc
    adc $c4
    ld a, a
    call Call_02b_55d5
    db $d3
    call nc, $c87f
    pop bc
    sub $c5
    ld a, a
    ret nc

    push bc
    pop bc
    jp $ccc5


    reti


    ld a, a
    rst $00
    ld d, l
    rst $08
    adc $c5
    ld a, a
    call nc, Call_02b_7fcf
    xor b
    push bc
    pop bc
    sub $c5
    adc $7f
    ld d, [hl]
    adc [hl]
    ld d, l
    ld d, a
    nop
    ld a, a
    and [hl]
    push de
    jp z, $9ac9

    and c
    ret z

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    jp $cdcf


    push bc
    ld c, a
    ld a, a
    call nc, Call_02b_7fcf
    ret z

    push bc
    call z, Call_02b_7fd0
    call $9fc5
    ld a, a
    ld d, [hl]
    ld a, a
    or h
    ld d, l
    ret z

    pop bc
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    ld a, a

Call_02b_557f:
Jump_02b_557f:
    sub $c5

Call_02b_5581:
Jump_02b_5581:
    jp nc, Jump_02b_7fd9

    call $c3d5
    ld d, l
    ret z

    add c
    ld a, a
    jp nz, $d4d5

    adc h
    ld a, a
    xor c
    adc h
    ld a, a
    ld d, [hl]
    adc h
    jp $cdc1


    ld d, l
    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    call nc, Call_02b_7fcf
    jp $cecf


    db $d3
    rst $08
    call z, Call_02b_55c5
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    call z, Call_02b_7fd3
    rst $08
    add $7f
    xor b
    pop bc
    ret z

    ld d, l
    pop bc
    ld a, a
    pop bc
    adc $c4
    ld a, a

Call_02b_55c3:
Jump_02b_55c3:
    xor b

Call_02b_55c4:
    pop bc

Call_02b_55c5:
Jump_02b_55c5:
    ret z

    pop bc
    add a

Call_02b_55c8:
Jump_02b_55c8:
    db $d3

Call_02b_55c9:
Jump_02b_55c9:
    ld a, a
    call $d4cf
    ret z

    ld d, l

Call_02b_55cf:
Jump_02b_55cf:
    push bc
    jp nc, $817f

Jump_02b_55d3:
    ld a, a

Jump_02b_55d4:
    ld d, [hl]

Call_02b_55d5:
Jump_02b_55d5:
    ld a, a
    and c

Call_02b_55d7:
    ret z

    adc h

Call_02b_55d9:
    ld a, a
    pop bc
    call z, $c1d7
    reti


    ld d, l
    db $d3
    ld a, a
    add $c5
    push bc
    call z, Call_02b_7fd3
    xor b
    pop bc
    ret z

    pop bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ld d, l
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    rst $08
    adc $c5
    ld a, a
    call nc, Call_02b_7fcf
    call nc, $c5c8
    ld a, a
    ld d, l
    xor b
    push bc
    pop bc
    sub $c5
    adc $81
    ld a, a
    xor c
    ld a, a
    push bc
    db $d3
    ret nc

    push bc
    jp $c1c9


    ld d, l
    call z, $d9cc
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    ld a, a
    call nc, Call_02b_55cf
    ld a, a
    db $d3
    pop bc
    reti


    ld a, a
    call nc, $c1c8
    adc $cb
    db $d3
    ld a, a
    call nc, Call_02b_7fcf
    reti


    rst $08
    ld d, l
    push de
    add c
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
    ld d, l
    ld a, a
    rst $08
    adc $7f
    adc h
    ld a, a
    rst $00
    rst $08
    ld a, a
    ret z

    rst $08
    call Call_02b_7fc5
    rst $10
    ret


    call nc, $c855
    ld a, a
    call $81c5
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    rst $08
    call Call_02b_7fc5
    rst $08
    add $55
    ld a, a
    ld d, h
    ld a, a
    adc [hl]
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret z

    ret


    call z, $cc55
    add $cf
    rst $08
    call nc, $cf7f
    add $7f
    call nc, $c9c8
    db $d3
    ld a, a
    call nc, $d7cf
    ld d, l
    push bc
    jp nc, Jump_02b_7f81

    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    add c
    ld d, h
    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    ld d, l
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, $c27f
    push bc
    add $cf
    jp nc, $81c5

    or h
    ret z

    ld d, l
    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, $d28d
    ld d, l
    push bc
    sub $c9
    sub $c9
    adc $c7
    ld a, a
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    xor c
    ld d, l
    add a
    sub $c5
    ld a, a
    call $c4c1
    push bc
    add c
    ld a, a
    xor c
    call nc, $c37f
    pop bc
    adc $7f
    ld d, l
    call $cbc1
    push bc
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, $d47f
    rst $08
    ld a, a
    jp nc, Jump_02b_55c5

    sub $c9
    sub $c5
    xor h
    push bc
    call nc, $cd7f
    push bc
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_02b_7f81
    call nc, $c5c8
    adc $8c
    ld a, a
    or h
    ret z

    pop bc
    call nc, Call_02b_4f7f
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02b_7fc4
    jp nz, Jump_02b_7fc5

    ret z

    pop bc
    adc $c4
    push bc
    call nz, Call_02b_557f
    ret


    adc $7f
    pop de
    push de
    ret


    jp $cccb


    reti


    add c
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $c4c5
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $c1d2
    adc $c7
    push bc
    ld a, a
    and h
    jp nc, $8e55

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    ret nc

    push bc
    adc $c4
    ld a, a
    db $d3
    rst $08
    call Call_02b_7fc5
    call nc, $cdc9
    push bc
    ld a, a
    ld c, a
    db $d3
    call z, $c7c9
    ret z

    call nc, $d9cc
    add c
    ld a, a
    and a
    rst $08
    ld a, a
    call nc, Call_02b_7fcf
    call nc, $c855
    pop bc
    call nc, $c17f
    jp nc, $c1c5

    ld a, a
    ld a, a
    add $cf
    jp nc, $c17f

    ld a, a
    rst $10
    ld d, l
    pop bc
    call z, $81cb
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    adc $4f
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    ld c, a
    ld d, d
    add c
    and c
    ret z

    add c
    xor l
    push bc
    push bc
    call nc, $d97f
    rst $08
    push de
    ld d, l
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    ret


    db $d3
    ld a, a
    set 1, c
    adc $c4
    ld a, a
    rst $08
    add $7f
    ld d, l
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    and c
    jp nc, Jump_02b_7fc5

    reti


    rst $08
    push de
    ld d, l
    ld a, a
    ret


    adc $d6
    ret


    call nc, $c4c5
    sbc a
    ld a, a
    and c
    call nz, $c9c4
    call nc, $cfc9
    ld d, l
    adc $c1
    call z, $d9cc
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ld a, a
    rst $08
    add $7f
    call nc, Call_02b_55c8
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
    adc $55
    call nz, $cfc2
    set 1, e
    ld a, a
    ld d, h
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $55c1
    call nc, Call_02b_7fc1
    ret z

    pop bc
    sub $c5
    ld a, a
    jp nz, $c5c5

    adc $7f
    jp $cccf


    call z, $c555
    jp $c5d4


    call nz, $c37f
    rst $08
    call $ccd0
    push bc
    call nc, $ccc5
    reti


    add c
    ld d, l
    ld a, a
    xor c
    ld a, a
    adc h
    ld a, a
    push bc
    sub $c5
    adc $7f
    ret z

    pop bc
    sub $c5
    ld a, a
    jp $55c1


    push de
    rst $00
    ret z

    call nc, $947f
    sub b
    ld a, a
    set 1, c
    adc $c4
    db $d3
    ld a, a
    rst $08
    add $7f
    ld d, l
    ret


    call nc, $a181
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
    ld d, l
    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    ld a, a
    rst $08
    adc $c5
    ld a, a
    jp nc, $c1cf

    ld d, l
    call nz, $8c7f
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $55
    push bc
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $d77f
    ret


    call z, Call_02b_7fcc
    jp nz, Jump_02b_7fc5

    ld d, l
    call nz, $c6c9
    add $c5
    jp nc, $cec5

    call nc, Call_02b_7f81
    call z, $cfcf
    bit 7, a
    add $55
    rst $08
    jp nc, $c97f

    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    jp $cfcf


    bit 7, a
    ret z

    ld c, a
    push bc
    jp nc, $81c5

    ld a, a
    or h
    rst $08
    call nz, $d9c1
    add a
    db $d3
    ld a, a
    call $cec5
    push de
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    ld e, b
    adc [hl]
    ld a, a
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
    add $d2
    ret


    push bc
    call nz, Call_02b_4f7f
    jp $cfc8


    ret nc

    db $d3
    call nc, $c3c9
    set 2, e
    adc l
    jp nz, $c5d2

    pop bc
    call Call_02b_557f
    rst $08
    adc $7f
    rst $10
    ret z

    ret


    jp Jump_02b_7fc8


    ret nc

    rst $08
    push de
    jp nc, $c4c5

    ld a, a
    jp $d255


    push bc
    pop bc
    call $d77f
    ret


    call nc, Call_02b_7fc8
    and [hl]
    jp nc, $cec1

    jp Jump_02b_7fc5


    ld d, l
    add $cc
    pop bc
    sub $cf
    push de
    jp nc, $817f

    ld a, a
    jp nz, $d4d5

    ld a, a
    db $d3
    rst $08
    call $c555
    call nc, $c9c8
    adc $c7
    ld a, a
    call $d9c1
    ld a, a
    jp nz, Jump_02b_7fc5

    jp $cdcf


    ld d, l
    ret nc

    call z, $c9c1
    adc $c5
    call nz, Call_02b_7f8c
    jp nz, Jump_02b_7fd9

    add $c9
    db $d3
    ret z

    ld a, a
    ld d, l
    rst $08
    jp nc, $c27f

    reti


    ld a, a
    rst $00
    push de
    push bc
    db $d3
    call nc, $9f7f
    ld d, a
    nop
    ld a, a
    db $d3
    pop bc
    call z, Call_02b_7fd4
    jp nc, $c1cf

    db $d3
    call nc, $c17f
    push de
    call nc, $cdd5
    ld c, a
    adc $7f
    ret z

    pop bc
    ret


    jp nc, $c1d4

    ret


    call z, Call_02b_7f81
    ld d, [hl]
    ld a, a
    call $55c1
    reti


    ld a, a
    ret


    call nc, $c27f
    push bc
    ld a, a
    jp $cdcf


    ret nc

    call z, $c9c1
    adc $c5
    ld d, l
    call nz, $c27f
    reti


    ld a, a
    rst $00
    push de
    push bc
    db $d3
    call nc, $9f7f
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    push bc
    adc $c4
    push bc
    jp nc, $cfcc

    ret


    adc $7f
    jp nz, $c5c5

    add $d3
    ld c, a
    call nc, $c1c5
    res 0, c
    ld a, a
    jp nz, $d4d5

    adc h
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    call nc, Call_02b_55c8
    push bc
    ld a, a
    jp nc, $d7c1

    ld a, a
    call $d4c1
    push bc
    jp nc, $c1c9

    call z, Call_02b_7fd3
    push bc
    ld d, l
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    call nc, Call_02b_7fcf
    jp nz, Jump_02b_7fc5

    db $d3
    ret z

    pop bc
    jp nc, Jump_02b_55c5

    call nz, $cf7f
    push de
    call nc, $c57f
    pop de
    push de
    pop bc
    call z, $d9cc
    ld a, a
    jp nz, Jump_02b_7fd9

    ld d, l
    ret nc

    push bc
    jp nc, $c37f

    pop bc
    ret nc

    ret


    call nc, $9fc1
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    pop bc
    ret nc

    call nc, $c9c1
    adc $9a
    xor b
    add a
    call $567f
    adc h
    ld a, a
    ld c, a
    call nc, $c1c8
    adc $cb
    db $d3
    ld a, a
    add c
    ld a, a
    db $d3
    push bc
    push bc
    call Call_02b_7fd3
    call Call_02b_55cf
    jp nc, Jump_02b_7fc5

    jp $cdcf


    add $cf
    jp nc, $c1d4

    jp nz, $c5cc

    add c
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_02b_7f8c
    rst $10
    ret z

    pop bc
    call nc, Call_02b_7f8c
    rst $10
    ld d, l
    ret z

    pop bc
    call nc, Call_02b_7f81
    and e
    rst $08
    call Call_02b_7fc5
    call nc, Call_02b_7fcf
    db $d3
    push bc
    push bc
    ld a, a
    ld d, l
    db $d3
    push bc
    jp $c5d2


    call nc, $d37f
    set 1, c
    call z, $81cc
    ld a, a
    xor a
    ret z

    adc h
    ld d, l
    ld a, a
    reti


    push bc
    db $d3
    add c
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    ld d, l
    ret


    adc $7f
    rst $00
    rst $08
    rst $08
    call nz, $cd7f
    rst $08
    rst $08
    call nz, Call_02b_7f8c
    xor c
    add a
    call z, $cc55
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    rst $10
    rst $08
    jp nc, Jump_02b_7fc4

    ld d, l
    db $d3
    set 1, c
    call z, Call_02b_7fcc
    ld d, [hl]
    rst $10
    ret z

    ret


    jp Jump_02b_7fc8


    ld a, a
    xor c
    ld a, a
    ld d, l
    call nc, $cbc1
    push bc
    ld a, a
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $c4c9

    push bc
    add c
    ld a, a
    ld d, l
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    pop bc
    db $d3
    ld a, a
    ld d, l
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    adc $d3
    pop bc
    call nc, $cfc9
    adc $81
    ld a, a
    xor c
    ld d, l
    add $7f
    call nc, $c1c5
    jp $c9c8


    adc $c7
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, Call_02b_55c8
    ret


    db $d3
    ld a, a
    ld a, a
    ld d, h
    adc h
    rst $10
    ret z

    push bc
    adc $c5
    sub $c5
    jp nc, Jump_02b_557f

    reti


    rst $08
    push de
    ld a, a
    jp $d5cf


    call z, Call_02b_7fc4
    db $d3
    push bc
    push bc
    ld a, a
    db $d3
    rst $10
    rst $08
    ld d, l
    jp nc, Jump_02b_7fc4

    db $d3
    set 1, c
    call z, $87cc
    db $d3
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    add c
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02b_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    and e
    pop bc
    ret nc

    call nc, $c9c1
    adc $55
    ld a, a
    add c
    ld a, a
    ld d, b
    ld de, $0050
    ld a, a
    and l
    sub $c5
    adc $7f
    call nc, Call_02b_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, $cfcf
    ld c, a
    ld a, a
    call $c3d5
    ret z

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
    ld a, a
    and e
    pop bc
    ret nc

    call nc, $c9c1
    adc $9a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    add a
    call Call_02b_4f81
    ld a, a
    call $d2cf
    push bc
    ld a, a
    jp $cdcf


    add $cf
    jp nc, $c1d4

    jp nz, $c5cc

    ld d, l
    add c
    ld a, a
    ld d, [hl]
    or h
    ret


    call Call_02b_7fc5
    ret


    db $d3
    ld a, a
    jp $cfcc


    db $d3
    push bc
    ld d, l
    jp nc, Jump_02b_7f81

    and c
    call nc, $cf7f
    adc $c3
    push bc
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ld d, l
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

    ld a, a
    db $d3
    push bc
    ld d, l
    call nc, Call_02b_7fd3
    db $d3
    pop bc
    ret


    call z, Call_02b_7f81
    xor h
    rst $08
    rst $08
    bit 7, a
    pop bc
    add $d4
    ld d, l
    push bc
    jp nc, $d97f

    rst $08
    push de
    jp nc, $c5d3

    call z, Call_02b_7fc6
    push de
    adc $d4
    ret


    call z, Call_02b_7f55
    adc $c5
    ret c

    call nc, $d47f
    ret


    call Call_02b_7fc5
    rst $10
    push bc
    ld a, a
    call $c5c5
    ld d, l
    call nc, $c97f
    adc $7f
    call nz, $c9d2
    push bc
    call nz, $cc7f
    push bc
    pop bc
    sub $c5
    db $d3
    ld d, l
    ld a, a
    jp $d4c9


    reti


    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c9cc
    adc $c7
    ld a, a
    pop bc
    ld c, a
    jp nc, $d5cf

    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    adc [hl]
    ld a, a
    ld d, l
    jp nz, $d4d5

    ld a, a
    call nc, $c1c8
    call nc, $c67f
    push bc
    call z, $cfcc
    rst $10
    ld a, a
    pop bc
    ld d, l
    call z, $c1d7
    reti


    db $d3
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    db $d3
    ld a, a
    xor c
    add a
    call Call_02b_557f
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    db $d3
    push de
    jp nc, $d2d0

    ret


    db $d3
    push bc
    call nz, Call_02b_557f
    rst $10
    ret z

    push bc
    adc $7f
    xor c
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    ret z

    ret


    call Call_02b_5581
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ret


    call nc, $c97f
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    push bc
    push bc
    adc $7f
    ld d, h
    ld a, a
    rst $10
    ret z

    ld c, a
    rst $08
    ld a, a
    call z, $d4c5
    ld a, a
    rst $08
    adc $c5
    ld a, a
    jp nc, $c4c9

    push bc
    ld a, a
    rst $08
    adc $55
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $ced5

    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    rst $10
    pop bc
    call nc, $d2c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    pop bc
    adc $7f
    ld a, a
    db $d3
    rst $10
    rst $08
    jp nc, Jump_02b_7fc4

    db $d3
    set 1, c
    call z, Call_02b_4fcc
    ld a, a
    rst $08
    add $7f

Call_02b_5d7f:
Jump_02b_5d7f:
    ld d, h
    jp $d4d5


    ld a, a
    rst $08
    add $c6
    ld a, a
    db $d3
    call z, $c555
    adc $c4
    push bc
    jp nc, $d47f

    jp nc, $c5c5

    sbc a
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
    jp nz, $c5c5

    adc $7f
    ld a, a
    ret z

    ld c, a
    push de
    adc $d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c17f
    jp nc, $c555

    pop bc
    ld a, a
    rst $08
    add $7f
    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    reti


    sbc a
    ld a, a
    ld d, l
    or h
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    pop bc
    jp nc, Jump_02b_7fc5

    call $cec1
    reti


    ld a, a
    ret nc

    jp nc, $c555

    jp $cfc9


    push de
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    jp $d2c1


    jp Jump_02b_55c5


    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    pop bc
    call nc, $c5c8
    jp nc, $c17f

    adc $c4
    ld a, a
    xor c
    ld a, a
    call z, $cbc9
    ld c, a
    push bc
    ld a, a
    ret z

    push de
    adc $d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, Call_02b_7f55
    pop bc
    jp nc, $c1c5

    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_02b_7fcf
    db $d3
    call nc, Call_02b_55c9
    call z, Call_02b_7fcc
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02b_7fcf
    ret nc

    call z, $d9c1
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    xor l
    jp nc, Jump_02b_7f8e

    jp $d0c1


    call nc, $c9c1
    ld c, a
    adc $7f
    adc $cf
    call nc, $c67f
    push bc
    push bc
    call z, $d77f
    push bc
    call z, $8ecc
    ld a, a
    ld d, l
    xor b
    ret


    db $d3
    ld a, a
    add $c1
    jp Jump_02b_7fc5


    ret


    db $d3
    ld a, a
    ret nc

    pop bc
    call z, $81c5
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    pop bc
    ret nc

    ret nc

    ld c, a
    push bc
    pop bc
    jp nc, $cd7f

    pop bc
    adc $d9
    ld a, a
    db $d3
    push bc
    pop bc
    db $d3
    ret


    jp Jump_02b_7fcb


    ld d, l
    call $cec5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    pop bc
    call nz, $cf7f
    add $7f
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    jp $4fc9


    push bc
    call nc, $9ad9
    and c
    ret z

    adc h
    ld a, a
    jp z, $d6d5

    push bc
    adc $c9
    call z, $81c5
    ld d, l
    ld a, a
    xor b
    push bc
    call z, Call_02b_7fd0
    call Call_02b_7fc5
    call $c3d5
    ret z

    adc h
    ld a, a
    call nc, Call_02b_55c8
    pop bc
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    add c
    ld a, a
    and [hl]
    rst $08
    jp nc, $d97f

    rst $08
    push de
    jp nc, Jump_02b_7f55

    db $d3
    pop bc
    sub $c9
    adc $c7
    ld a, a
    call Call_02b_7fc5
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld d, l
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, $d5cf

    db $d3
    ld a, a
    call nc, $cdc9
    push bc
    add c
    ld a, a
    ld d, l
    xor c
    add a
    call z, Call_02b_7fcc
    adc $c5
    sub $c5
    jp nc, $c67f

    rst $08
    jp nc, $c5c7

    call nc, Call_02b_7f55
    reti


    rst $08
    push de
    jp nc, $d37f

    pop bc
    sub $c9
    adc $c7
    ld a, a
    add c
    ld a, a
    xor a
    ret z

    ld d, l
    add c
    ld a, a
    xor c
    ld a, a
    adc $c5
    pop bc
    call z, $d9cc
    ld a, a
    add $cf
    jp nc, $c5c7

    call nc, $8155
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    rst $00
    ret


    add $d4
    ld d, l
    ld a, a
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    call nc, $cbcf
    push bc
    adc $7f
    rst $08
    add $7f
    call Call_02b_55d9
    ld a, a
    jp nc, $c7c5

    pop bc
    jp nc, $81c4

    ld a, a
    xor h
    rst $08
    rst $08
    res 0, c
    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, $c9c8
    db $d3
    sbc a
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02b_4f7f
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
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    ld d, l
    db $d3
    rst $08
    jp $c5c9


    call nc, Call_02b_7fd9
    add c
    ld a, a
    ld d, b
    ld de, $0050
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
    ld d, a
    nop
    ld a, a
    and e
    pop bc
    ret nc

    call nc, $c9c1
    adc $9a
    or h
    ret z

    pop bc
    call nc, $567f
    ld a, a
    ld c, a
    adc h
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $c37f
    pop bc
    adc $87
    call nc, $c27f
    push bc
    ld d, l
    ld a, a
    jp nz, $d5cf

    rst $00
    ret z

    call nc, $c17f
    adc $d9
    rst $10
    ret z

    push bc
    jp nc, $81c5

    ld d, l
    ld a, a
    call nc, $c9d2
    pop bc
    call z, $d08d
    jp nc, $c4cf

    push de
    jp $d3d4


    ld a, a
    rst $08
    ld d, l
    call $c9ce
    ret nc

    rst $08
    call nc, $cec5
    call nc, $c27f
    pop bc
    call z, $81cc
    ld a, a
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    rst $10
    ret


    call z, Call_02b_7fcc
    jp $d2c5


    call nc, $c9c1
    adc $cc
    ld d, l
    reti


    ld a, a
    jp nz, Jump_02b_7fc5

    jp $d5c1


    rst $00
    ret z

    call nc, $c17f
    add $d4
    push bc
    jp nc, Jump_02b_7f55

    jp nz, $c9c5

    adc $c7
    ld a, a
    call nc, $d2c8
    rst $08
    rst $10
    adc $7f
    rst $08
    push de
    call nc, $8155
    ld a, a
    pop de
    push de
    ret


    push bc
    call nc, $d9cc
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    call nc, Call_02b_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld d, l
    ld a, a
    call z, $cfcf
    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    ret nc

    ret


    jp $d5d4


    jp nc, Jump_02b_7fc5

    ld a, a
    ld c, a
    rst $08
    add $7f
    call $cecf
    ret


    call nc, $d2cf
    ld a, a
    jp nc, $c6c5

    call z, $c3c5
    ld d, l
    call nc, Call_02b_7fd3
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld e, [hl]
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    add $cc
    push bc
    call nz, $814f
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
    adc $cf
    ld d, l
    call nc, $c67f
    jp nc, $c7c9

    ret z

    call nc, $cec5
    push bc
    call nz, $c17f
    call nc, $c17f
    ld d, l
    call z, Call_02b_7fcc
    push bc
    sub $c5
    adc $7f
    reti


    rst $08
    push de
    jp nc, $d77f

    pop bc
    call z, $55cb
    ret


    adc $c7
    ld a, a
    rst $08
    push de
    call nc, $c9d3
    call nz, $81c5
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    ld d, l
    rst $08
    rst $08
    call nz, Call_02b_7f81
    ld d, a
    nop
    ld a, a
    and c
    ret z

    ld a, a
    ld d, [hl]
    xor c
    call nc, $d387
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    ld c, a
    call nz, $d47f
    rst $08
    ld a, a
    push bc
    ret c

    ret


    call z, Call_02b_7fc5
    ld d, l
    ld e, [hl]
    ret


    add $7f
    ld d, h
    ld a, a
    call nc, $c5c8
    ld d, l
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
    pop bc
    jp nc, $c9d2

    ld d, l
    rst $08
    jp nc, $c17f

    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    db $d3
    ld a, a
    jp $cdcf


    ld d, l
    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    rst $10
    ret


    call nc, $c4c8
    jp nc, $d7c1

    ret


    adc $c7
    adc h
    ld c, a
    rst $10
    ret


    call nc, $c4c8
    jp nc, $d7c1

    ret


    adc $c7
    add c
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd13
    nop
    ld d, l
    ld a, a
    ld a, a
    ret z

    pop bc
    sub $c5
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    call nz, Call_02b_557f
    ld d, b
    ld bc, $cd19
    nop
    ld d, l
    add c
    ld a, a
    ld d, b
    ld bc, $7f00
    or h
    ret z

    push bc
    adc $7f
    jp $cecf


    call nc, $c3c1
    call nc, $c37f
    pop bc
    jp nz, $cc4f

    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld e, b
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
    ret


    adc $c6
    rst $08
    ld c, a
    jp nc, $c1cd

    call nc, $cfc9
    adc $7f
    rst $10
    push bc
    jp nc, Jump_02b_7fc5

    call nz, $d3c5
    call nc, $d255
    rst $08
    reti


    push bc
    call nz, Call_02b_7f81
    ld e, b
    nop
    ld a, a
    ld d, d
    jp nc, $c3c5

    rst $08
    jp nc, Jump_02b_7fc4

    db $d3
    push bc
    jp nc, $4fc9

    rst $08
    push de
    db $d3
    call z, Call_02b_7fd9
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $d0c5

    rst $08
    ld d, l
    jp nc, $81d4

    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    jp nc, $d4c9

    push bc
    ld a, a
    call nz, $d7cf
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c54f

    ret nc

    rst $08
    jp nc, Jump_02b_7fd4

    ld d, [hl]
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    ld d, l
    call Call_02b_7fc5
    call nc, $cdc9
    push bc
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    jp $d3c1


    push bc
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    db $d3
    ld a, a
    rst $10
    ret


    ld d, l
    call nc, Call_02b_7fc8
    or a
    rst $08
    adc $87
    call nc, $c97f
    call nc, $c47f
    rst $08
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    rst $08
    call z, $c5cc
    jp Jump_02b_7fd4


    jp $d3c1


    push bc
    ld a, a
    ld c, a
    ld d, h
    adc h
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, b
    ld d, b
    nop
    ld a, a
    or h
    rst $08
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, $c9c8
    ld c, a
    db $d3
    ld a, a
    rst $10
    ret


    call z, Call_02b_7fcc
    adc $cf
    call nc, $c57f
    ret c

    pop bc
    call $ccd0
    ld d, l
    push bc
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_02b_7fc5

    call nc, $c5c8
    ld a, a
    db $d3
    push de
    jp nz, Jump_02b_55cf

    jp nc, $c9c4

    adc $c1
    call nc, $d3c5
    add c
    ld a, a
    ld d, l
    ld e, [hl]
    adc [hl]
    ld d, [hl]
    adc [hl]
    ld a, a
    and h
    ret


    db $d3
    call Call_02b_55c9
    db $d3
    db $d3
    ld a, a
    add $d2
    rst $08
    call $ce7f
    rst $08
    rst $10
    add c
    ld a, a
    xor c
    adc h
    adc h
    ld a, a
    ld d, l
    add $d2
    rst $08
    call $d47f
    rst $08
    call nz, $d9c1
    adc h
    ld a, a
    jp nz, $c7c5

    ret


    adc $55
    ld a, a
    call nc, Call_02b_7fcf
    ret nc

    jp nc, $c3c1

    call nc, $d3c9
    push bc
    ld a, a
    ld d, h
    add a
    ld d, l
    db $d3
    ld a, a
    db $d3
    set 1, c
    call z, $8ecc
    ld a, a
    xor c
    ld a, a
    ret nc

    jp nc, $d0c5

    pop bc
    jp nc, $c555

    ld a, a
    call nc, Call_02b_7fcf
    db $d3
    call nc, $d2c1
    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c855
    push bc
    ld a, a
    sub $c5
    jp nc, Jump_02b_7fd9

    jp nz, $c7c5

    ret


    adc $ce
    ret


    adc $c7
    ld d, l
    add c
    ld a, a
    or l
    adc $d4
    ret


    call z, $d47f
    ret z

    push bc
    ld a, a
    adc $c5
    ret c

    call nc, Call_02b_557f
    call nc, $cdc9
    push bc
    ld a, a
    ld d, [hl]
    db $d3
    push bc
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $55c1
    call nc, $d2c5
    add c
    ld a, a
    ld a, a
    ld d, [hl]
    and d
    reti


    push bc
    adc l
    jp nz, $c5d9

    add c
    ld a, a
    ld d, l
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    xor b
    pop bc
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call $d94f
    ld a, a
    ld e, [hl]
    xor b
    push bc
    add a
    call z, Call_02b_7fcc
    jp nc, Jump_02b_55c5

    rst $00
    push de
    call z, $d4c1
    push bc
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    ld d, l
    pop bc
    rst $00
    pop bc
    ret


    adc $7f
    rst $08
    adc $7f
    ret z

    ret


    db $d3
    ld a, a
    jp nc, $d6c5

    ret


    ld d, l
    sub $c9
    adc $c7
    ld a, a
    call nz, $d9c1
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    rst $00
    reti


    call $817f
    ld a, a
    jp nz, $d4d5

    ld a, a
    xor b
    push bc
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    ld d, l
    add $cf
    push de
    adc $c4
    ld a, a
    jp nz, Jump_02b_7fd9

    reti


    rst $08
    push de
    ld a, a
    add c
    ld a, a
    xor c
    ld a, a
    ld d, l
    jp $cec1


    ld a, a
    call nz, Call_02b_7fcf
    adc $cf
    call nc, $c9c8
    adc $c7
    ld a, a
    pop bc
    jp nz, $cf55

    push de
    call nc, $c97f
    call nc, Call_02b_7f81
    and c
    call nc, $d47f
    ret z

    ret


    db $d3
    ld a, a
    call nc, $c955
    call Call_02b_7fc5
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, $cec4
    add a
    call nc, Call_02b_7f55
    rst $00
    push bc
    call nc, $c17f
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c37f
    pop bc
    ld d, l
    jp nc, $81c5

    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    rst $08
    adc $c3
    push bc
    ld a, a
    pop bc
    ld d, l
    rst $00
    pop bc
    ret


    adc $7f
    xor h
    push bc
    call nc, $d387
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    ld d, l
    call nc, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_02b_7fcc
    rst $08
    add $7f
    call nc, Call_02b_55c8
    push bc
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    db $d3
    call nc, $d37f
    pop bc
    jp $c9c8


    ld d, l
    jp Jump_02b_5d7f


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    add $d5
    call nc, $d2d5
    push bc
    ld a, a
    ld c, a
    jp $c1c8


    call $81d0
    ld a, a
    xor c
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c47f
    rst $08
    ld d, l
    adc $87
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d47f
    ret z

    push bc
    ld d, l
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    add $c1
    jp Jump_02b_7fc5


    rst $08
    add $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    ld d, l
    adc $7f
    jp $d4c9


    reti


    ld a, a
    ret


    db $d3
    add c
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    pop bc
    jp $d5d4


    pop bc
    call z, $d9cc
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cfd2
    ld d, l
    adc $c7
    push bc
    db $d3
    call nc, $cf7f
    adc $c5
    ld a, a
    pop bc
    call $cecf
    rst $00
    ld a, a
    pop bc
    ld d, l
    call z, Call_02b_7fcc
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_02b_7fd3
    ld a, a
    push de
    adc $d4
    ld d, l
    ret


    call z, $ce7f
    rst $08
    rst $10
    ld a, a
    add c
    ld a, a
    and c
    adc $c4
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    ld d, l
    push bc
    push bc
    call Call_02b_7fd3
    call nc, Call_02b_7fcf
    jp nz, Jump_02b_7fc5

    ret


    adc $7f
    call nc, $c9c8
    ld d, l
    db $d3
    ld a, a
    rst $00
    reti


    call $a17f
    call z, Call_02b_7fcc
    call nc, $c5c8
    ld a, a
    ld a, a
    push de
    db $d3
    ld d, l
    push bc
    jp nc, Jump_02b_7fd3

    rst $08
    add $7f
    rst $00
    jp nc, $d5cf

    adc $c4
    ld a, a
    call nc, $d0d9
    ld d, l
    push bc
    ld a, a
    ld d, h
    jp $cdcf


    push bc
    ld a, a
    call nc, $c7cf
    push bc
    call nc, $c5c8
    ld d, l
    jp nc, $c87f

    push bc
    jp nc, $81c5

    ld a, a
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
    call nz, Call_02b_7f81
    ld c, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_02b_7f7f
    rst $08
    add $7f
    push bc
    sub $c5
    jp nc, $c755

    jp nc, $c5c5

    adc $7f
    jp $d4c9


    reti


    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    jp Jump_02b_55d4


    push de
    pop bc
    call z, $d9cc
    ld a, a
    db $d3
    pop bc
    jp $c3c1


    ret z

    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    add $c5
    push bc
    call z, $a97f
    add a
    ld c, a
    sub $c5
    ld a, a
    jp nz, $d5cf

    rst $00
    ret z

    call nc, $d37f
    call nc, $c1d2
    adc $c7
    push bc
    ld d, l
    ld a, a
    ld d, h
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    rst $08
    call z, Call_02b_7fc4
    ld d, l
    jp nz, $cfcc

    rst $08
    call nz, $d5c3
    jp nc, $ccc4

    ret


    adc $c7
    ld a, a
    call $cec1
    ld d, l
    ld a, a
    add c
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $cfcf
    ld a, a
    rst $10
    push bc
    pop bc
    bit 2, l
    add c
    ld a, a
    jp nz, $d4d5

    ld a, a
    xor b
    push bc
    ld a, a
    ret nc

    jp nc, $c3c9

    push bc
    db $d3
    ld a, a
    ret


    ld d, l
    call nc, $957f
    sub b
    sub b
    add h
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    or h
    ret z

    rst $08
    push de
    rst $00
    ret z

    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    rst $10
    push bc
    pop bc
    ld c, a
    bit 7, a
    ld d, h
    adc h
    ld a, a
    pop bc
    db $d3
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    db $d3
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ret


    call nc, $d37f
    push bc
    ld d, l
    jp nc, $cfc9

    push de
    db $d3
    call z, Call_02b_7fd9
    reti


    rst $08
    push de
    ld a, a
    call $d9c1
    ld a, a
    rst $00
    ld d, l
    push bc
    call nc, $c77f
    rst $08
    rst $08
    call nz, $d27f
    push bc
    call nc, $d2d5
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call z, $d6c5
    push bc
    call z, $c97f
    db $d3
    ld a, a
    push bc
    adc $c8
    ld c, a
    pop bc
    adc $c3
    push bc
    call nz, $af7f
    adc $cc
    reti


    ld a, a
    ld d, h
    ld d, l
    ld e, l
    ld a, a
    jp $cec1


    ld a, a
    ret


    call nc, $d27f
    push bc
    ld d, l
    jp $c9c5


    sub $c5
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    ld a, a
    ld d, h
    add c
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    push bc
    ld d, l
    sub $c5
    jp nc, $ccc1

    ld a, a
    ld a, a
    ret


    call $cfd0
    jp nc, $c1d4

    adc $d4
    ld a, a
    ld d, l
    db $d3
    push bc
    jp $c5d2


    call nc, Call_02b_7fd3
    ret


    adc $7f
    call nc, $c1c8
    call nc, $c27f
    ld d, l
    pop bc
    call nz, $c5c7
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    or h
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    pop bc
    jp nc, $4fc5

    ld a, a
    sbc b
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, Call_02b_7fd3
    ret


    adc $7f
    jp nz, $c4c1

    ld d, l
    rst $00
    push bc
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    or a
    ret z

    ret


    jp Jump_02b_7fc8


    rst $10
    push bc
    add a
    ld d, l
    call nz, $d47f
    pop bc
    call z, Call_02b_7fcb
    pop bc
    jp nz, $d5cf

    call nc, Call_02b_7f9f
    ld d, a
    nop
    ld a, a
    and e
    rst $08
    call Call_02b_7fc5
    pop bc
    rst $00
    pop bc
    ret


    adc $7f
    ret


    add $7f
    reti


    rst $08
    ld c, a
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02b_7fcf
    call z, $d3c9
    call nc, $cec5
    ld a, a
    ld d, l
    call nc, $81cf
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    adc $7f
    pop bc
    push de
    call nc, $cdcf
    pop bc
    call nc, $814f
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    call nz, $c9d2
    adc $cb
    ld d, l
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $cecf
    push bc
    reti


    ld a, a
    ret


    db $d3
    ld a, a
    adc $cf
    call nc, Call_02b_7f4f
    push bc
    adc $cf
    push de
    rst $00
    ret z

    add c
    ld a, a
    ld d, a
    ld bc, $cf45
    nop
    ld c, a
    ld a, a
    jp $cdcf


    push bc
    db $d3
    ld a, a
    rst $08
    push de
    call nc, Call_02b_7f81
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    jp nz, $c1c5

    jp nc, $cec9

    rst $00
    ld a, a
    call $d2cf
    push bc
    add c
    ld c, a
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $d37f

    call nc, $d0cf
    ld c, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    reti


    pop bc
    jp nc, $4fc4

    sbc d
    or a
    pop bc
    ret z

    rst $08
    rst $08
    add c
    ld a, a
    pop bc
    call z, Call_02b_7fcc
    pop bc
    jp nc, Jump_02b_7fc5

    db $d3
    ld d, l
    rst $08
    push de
    adc $c4
    db $d3
    ld a, a
    ld a, a
    rst $10
    ret


    call nc, Call_02b_7fc8
    db $d3
    push de
    jp nc, $d2d0

    ld d, l
    ret


    db $d3
    ret


    adc $c7
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    sbc a
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    adc [hl]
    ld a, a
    and c
    ret z

    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    xor h
    pop bc
    push de
    rst $00
    ret z

    ret


    adc $c7
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp z, $cf55

    set 1, c
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, Call_02b_7fcc
    pop bc
    jp nc, Jump_02b_7fc5

    call nc, $c5c8
    ld a, a
    db $d3
    ret


    rst $00
    ret z

    ld c, a
    ld a, a
    rst $10
    ret


    call nc, Call_02b_7fc8
    add $c5
    push bc
    call z, $cec9
    rst $00
    db $d3
    ld a, a
    pop bc
    jp nz, $cf55

    push de
    call nc, $a87f
    pop bc
    adc h
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    xor a
    ret z

    ld a, a
    pop bc
    adc $55
    call nz, $d37f
    rst $08
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    reti


    pop bc
    jp nc, $4fc4

    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    add $c5
    call nc, $c8c3
    push bc
    call nz, $c77f
    rst $08
    call z, Call_02b_55c4
    ld a, a
    call nc, $c5c5
    call nc, Call_02b_7fc8
    add $d2
    rst $08
    call Call_02b_557f
    ld d, d
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    or b
    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call nc, $c555
    push bc
    call nc, Call_02b_7fc8
    ld a, a
    jp nz, $c3c1

    bit 7, a
    call nc, $c5c8
    ld a, a
    call Call_02b_55cf
    push de
    call nc, Call_02b_7fc8
    ret z

    push de
    jp nc, $c9d2

    call z, $81d9
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    reti


    pop bc
    jp nc, $4fc4

    sbc d
    xor c
    add a
    call $d37f
    rst $08
    jp nc, $d9d2

    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nc, $c555

    pop bc
    call z, $d9cc
    ld a, a
    ret z

    push bc
    call z, Call_02b_7fd0
    call $c3d5
    ret z

    add c
    ld a, a
    ld d, l
    or a
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, Jump_02b_7f7f

    xor c
    ld a, a
    db $d3
    pop bc
    reti


    ld a, a
    pop bc
    ld d, l
    adc $c4
    ld a, a
    rst $10
    ret z

    rst $08
    push bc
    sub $c5
    jp nc, $a97f

    ld a, a
    call nc, $ccc1
    bit 2, l
    ld a, a
    call nc, Call_02b_7fcf
    jp $cec1


    add a
    call nc, $c57f
    ret c

    ret nc

    jp nc, $d3c5

    db $d3
    ld d, l
    ld a, a
    call Call_02b_7fd9
    add $c5
    push bc
    call z, $cec9
    rst $00
    db $d3
    ld a, a
    adc $cf
    rst $10
    add c
    ld d, l
    ld a, a
    xor c
    add a
    call $d47f
    rst $08
    rst $08
    ld a, a
    push bc
    call $c1c2
    jp nc, $c1d2

    db $d3
    ld d, l
    db $d3
    push bc
    call nz, $d47f
    rst $08
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_02b_7fcf
    rst $08
    add $c6
    ret


    ld d, l
    jp Jump_02b_7fc5


    add c
    ld a, a
    xor a
    ret z

    adc h
    reti


    push bc
    db $d3
    add c
    ld a, a
    call nz, $c1c5
    jp nc, Jump_02b_7f55

    jp nz, $d9cf

    add c
    ld a, a
    call nc, $c1c8
    set 2, e
    add c
    ld a, a
    and a
    ret


    sub $c5
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    call nc, Call_02b_7fcf
    db $d3
    ret z

    rst $08
    rst $10
    ld d, l
    ld a, a
    call Call_02b_7fd9
    call nc, $c1c8
    adc $cb
    db $d3
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02b_4f7f
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
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    ld d, l
    reti


    pop bc
    jp nc, Jump_02b_7fc4

    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $7f
    reti


    pop bc
    jp nc, $4fc4

    sbc d
    db $d3
    push bc
    jp $c5d2


    call nc, $cd7f
    pop bc
    jp $c9c8


    adc $c5
    ld a, a
    inc b
    xor c
    ld d, l
    adc $7f
    ret


    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    call nc, $c1d2
    adc $c7
    push bc
    ld a, a
    add $55
    rst $08
    jp nc, $c5c3

    add c
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_02b_55c5
    db $d3
    ld a, a
    pop bc
    ld a, a
    call $cec1
    ld a, a
    rst $10
    ret


    call nc, Call_02b_7fc8
    rst $00
    jp nc, $c1c5

    ld d, l
    call nc, $d37f
    call nc, $c5d2
    adc $c7
    call nc, Call_02b_7fc8
    xor b
    push bc
    ld a, a
    pop bc
    call z, Call_02b_55d7
    pop bc
    reti


    db $d3
    ld a, a
    ret nc

    push de
    db $d3
    ret z

    push bc
    db $d3
    ld a, a
    jp nc, $c3cf

    bit 7, a
    rst $10
    ld d, l
    ret z

    push bc
    adc $7f
    adc $cf
    ld a, a
    add $c9
    rst $00
    ret z

    call nc, $cec9
    rst $00
    ld a, a
    add c
    ld d, l
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
    add c
    ld a, a
    ld d, [hl]
    and c
    call nz, Call_02b_55c4
    ret


    call nc, $cfc9
    adc $c1
    call z, $d9cc
    add c
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    ld d, l
    ret z

    pop bc
    sub $c5
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    pop bc
    ld a, a
    db $d3
    push bc
    jp $55d2


    push bc
    call nc, $cd7f
    pop bc
    jp $c9c8


    adc $c5
    ld a, a
    ret


    adc $7f
    ret z

    push de
    adc $55
    call nc, $c17f
    adc $c4
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c17f
    jp nc, $c1c5

    ld d, l
    ld a, a
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nc, $c4c9

    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    ld d, l
    rst $10
    pop bc
    sub $c5
    ld a, a
    ld a, a
    rst $10
    ret z

    ret


    jp Jump_02b_7fc8


    ret


    db $d3
    ld a, a
    call nz, Call_02b_55c9
    add $c6
    ret


    jp $ccd5


    call nc, $d47f
    rst $08
    ld a, a
    rst $00
    push bc
    call nc, Call_02b_7f81
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_02b_7f81
    call nc, $cfcf
    ld a, a
    call $c3d5
    ret z

    ld a, a
    call z, $d54f
    rst $00
    rst $00
    pop bc
    rst $00
    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    call nz, $c3c5
    rst $08
    jp nc, $d4c1

    push bc
    db $d3
    ld a, a
    ld c, a
    pop bc
    adc $c3
    ret


    push bc
    adc $d4
    ld a, a
    ld d, h
    ld a, a
    jp $cdcf


    call Call_02b_55cf
    call nz, $d4c9
    reti


    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02b_7fc5

    ret nc

    push de
    call nc, Call_02b_7fd3
    rst $08
    adc $7f
    add $cf
    ld c, a
    db $d3
    db $d3
    ret


    call z, Call_02b_547f
    adc h
    ld a, a
    ret nc

    ret z

    rst $08
    call nc, Call_02b_7fcf
    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $cbc9
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cecf
    push bc
    reti


    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    adc $cf
    call nc, $c57f
    adc $cf
    push de
    rst $00
    ret z

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    add c
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    ld c, a
    call nz, $957f
    sub b
    sub b
    add h
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_02b_7fc5

    push de
    db $d3
    push bc
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld a, a
    add $cf
    jp nc, Jump_02b_557f

    ret z

    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    or h
    ret z

    ret


    db $d3
    add c
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    add $c5
    call nc, $c8c3
    push bc
    db $d3
    ld a, a
    sub e
    sub b
    ld a, a
    ld d, l
    ret z

    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    jp nz, $ccc1

    call z, $d2c6
    rst $08
    call Call_02b_557f
    call nc, $c5c8
    ld a, a
    call nz, $d3c5
    bit 7, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    xor b
    pop bc
    db $d3
    adc $87
    call nc, Call_02b_7f55
    push bc
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    call nc, $cdc9
    push bc
    sbc a
    ld a, a
    xor [hl]
    rst $08
    call nc, $c955
    add $d9
    ld a, a
    push de
    db $d3
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    call Call_02b_55c5
    rst $00
    pop bc
    ret nc

    ret z

    rst $08
    adc $c5
    ret


    add $7f
    reti


    rst $08
    push de
    jp nc, $ce7f

    rst $08
    ld d, l
    ld a, a
    ret z

    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    jp nz, $ccc1

    call z, $817f
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    adc $7f
    ld d, [hl]
    add c
    ld a, a
    call $d9c1
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nz, $c555

    ld a, a
    ret


    adc $7f
    call z, $c3d5
    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    reti


    push bc
    db $d3
    add c
    ld a, a
    ld d, [hl]
    rst $08
    adc $c3
    push bc
    ld a, a
    ld c, a
    call $d2cf
    push bc
    adc h
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    jp nz, $ccc1

    call z, $b47f
    pop bc
    bit 1, a
    push bc
    ld a, a
    jp nz, $c3c1

    bit 7, a
    jp nc, $cdc5

    pop bc
    ret


    adc $c4
    push bc
    jp nc, Jump_02b_5581

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $8c
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
    push bc
    call z, $cfcc
    add c
    ld a, a
    and c
    jp nc, Jump_02b_7fc5

    reti


    rst $08
    push de
    ld a, a
    call nc, $c84f
    push bc
    ld a, a
    add $c9
    jp nc, $d4d3

    ld a, a
    call nc, Call_02b_7fcf
    ret nc

    call z, $d9c1
    ld a, a
    ld d, l
    ret z

    push de
    adc $d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c77f
    ld d, l
    pop bc
    call $9fc5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    db $d3
    rst $08
    jp nc, $d9d2

    ld a, a
    add $cf
    jp nc, $cd7f

    reti


    ld c, a
    ld a, a
    ret


    call $cfd0
    call z, $d4c9
    push bc
    adc $c5
    db $d3
    db $d3
    add c
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    db $d3
    rst $08
    ld a, a
    pop bc
    ld a, a
    add $c1
    call $ccc9
    ret


    ld d, l
    pop bc
    jp nc, $c37f

    call z, $c5c9
    adc $d4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push de
    adc $d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c1d2
    ld c, a
    sub $c5
    call z, $c77f
    pop bc
    call Call_02b_7fc5
    ret


    db $d3
    ld a, a
    call nz, $d6c9
    ret


    call nz, $c555
    call nz, $c97f
    adc $d4
    rst $08
    ld a, a
    sub h
    ld a, a
    pop bc
    jp nc, $c1c5

    db $d3
    add c
    ld a, a
    ld d, l
    xor c
    adc $7f
    push bc
    pop bc
    jp Jump_02b_7fc8


    pop bc
    jp nc, $c1c5

    ld a, a
    call z, $d6c9
    push bc
    ld d, l
    db $d3
    ld a, a
    sub $c1
    jp nc, $cfc9

    push de
    db $d3
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    ld d, l
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    jp $d2c1


    jp Jump_02b_7fc5


    ld d, h
    add c
    ld d, l
    ld a, a
    db $d3
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02b_7fc4
    push de
    db $d3
    ld d, l
    push bc
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c87f
    push de
    adc $d4
    ret


    adc $c7
    ld d, l
    ld a, a
    jp nz, $ccc1

    call z, $d47f
    rst $08
    ld a, a
    jp $d4c1


    jp Jump_02b_7fc8


    call nc, Call_02b_55c8
    push bc
    call Call_02b_7f81
    jp nz, $d4d5

    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    adc $cf
    ld a, a
    push bc
    ld d, l
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    rst $08
    jp nc, $ce7f

    rst $08
    ld a, a
    ld d, l
    pop bc
    adc $d9
    ld a, a
    jp nz, $ccc1

    call z, $b47f
    ret z

    push bc
    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    rst $00
    pop bc
    call Call_02b_7fc5
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02b_7fc4
    jp nz, Jump_02b_7fc5

    push bc
    ld d, l
    adc $c4
    push bc
    call nz, Call_02b_7f81
    ld d, a
    nop
    ld a, a
    or h
    pop bc
    set 0, l
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $7f
    ld a, a
    push bc
    pop bc
    jp $c84f


    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    pop bc
    jp $d5c3


    call Call_02b_55d5
    call z, $d4c1
    push bc
    ld a, a
    rst $00
    jp nc, $c4c1

    push de
    pop bc
    call z, $d9cc
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    ret z

    pop bc
    jp nc, Jump_02b_7fcd

    rst $10
    ret


    call z, Call_02b_7fcc
    jp nz, Jump_02b_7fc5

    jp nz, Jump_02b_55c9

    rst $00
    rst $00
    push bc
    jp nc, $c17f

    adc $c4
    ld a, a
    jp nz, $c7c9

    rst $00
    push bc
    jp nc, Jump_02b_7f81

    ld d, l
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
    set 1, c
    call z, Call_02b_7fcc
    call nc, $cf55
    ld a, a
    call $cbc1
    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    add $55
    jp nc, $c7c9

    ret z

    call nc, $cec5
    push bc
    call nz, Call_02b_7f81
    ld d, a
    nop
    ld a, a
    and e
    ret z

    ret


    reti


    pop bc
    rst $08
    sbc d
    ld d, [hl]
    ld a, a
    and d
    rst $08
    rst $08
    adc h
    ld a, a
    jp nz, $cf4f

    rst $08
    adc h
    ld a, a
    jp nz, $cfcf

    add c
    ld a, a
    or a
    ret z

    push bc
    call z, Call_02b_7fd0
    ld a, a
    jp $c855


    pop bc
    call z, $c5cc
    adc $c7
    push bc
    db $d3
    ld a, a
    call Call_02b_7fc5
    xor b
    rst $08
    rst $10
    ld a, a
    ld d, l
    jp nc, $c4c9

    ret


    jp $ccd5


    rst $08
    push de
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    push bc
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    call nc, Call_02b_7fcf
    call $cbc1
    push bc
    ld a, a
    ret nc

    push bc
    ld d, l
    rst $08
    ret nc

    call z, Call_02b_7fc5
    call z, $d5c1
    rst $00
    ret z

    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_02b_7fd3
    ld d, l
    rst $08
    add $c6
    add c
    ld a, a
    or h
    rst $08
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    ld d, l
    rst $08
    adc $7f
    ret


    db $d3
    ld a, a
    call nc, Call_02b_7fcf
    call nz, $d3c5
    call nc, $cfd2
    reti


    ld a, a
    ld d, l
    rst $08
    adc $c5
    db $d3
    push bc
    call z, $81c6
    ld a, a
    or h
    rst $08
    ld a, a
    jp nc, $d3c5

    ret


    db $d3
    ld d, l
    call nc, $d77f
    ret


    call nc, Call_02b_7fc8
    jp nz, $d2c1

    push bc
    adc l
    ret z

    pop bc
    adc $c4
    ld a, a
    ld d, l
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    ret


    adc $7f
    db $d3
    call z, Call_02b_55c5
    push bc
    ret nc

    add c
    ld a, a
    or d
    push bc
    jp $c9c5


    sub $c5
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ld d, l
    push bc
    jp $c5d2


    call nc, Call_02b_7f7f
    rst $08
    add $7f
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    push bc
    ld d, l
    pop bc
    jp nc, $cec1

    jp Jump_02b_7fc5


    db $d3
    set 1, c
    call z, Call_02b_7fcc
    rst $08
    add $7f
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
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
    adc $7f
    call nc, $c5c8
    ld a, a
    ld c, a
    add $c5
    pop bc
    jp nc, $d5c6

    call z, $d07f
    rst $08
    ret


    adc $d4
    ld a, a
    rst $08
    add $7f
    ld d, l
    pop bc
    ld a, a
    jp $cecf


    call nc, $cdc5
    ret nc

    rst $08
    jp nc, $d2c1

    reti


    ld a, a
    db $d3
    push bc
    ld d, l
    jp $c5d2


    call nc, $d37f
    ret nc

    reti


    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    call $d2cf
    adc $c9
    adc $c7
    add c
    ld a, a
    ld a, a
    add $d5
    call nc, $d2d5
    push bc
    ld c, a
    ld a, a
    jp $c1c8


    call $81d0
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c9d2
    jp $55cb


    ld a, a
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    ld a, a
    rst $08
    add $7f
    ret nc

    ret


    adc $cb
    ld a, a
    rst $00
    ld d, l
    reti


    call $c97f
    db $d3
    ld a, a
    db $d3
    push bc
    ret nc

    pop bc
    jp nc, $d4c1

    push bc
    call nz, $c27f
    ld d, l
    reti


    ld a, a
    pop bc
    adc $7f
    push de
    adc $d3
    push bc
    push bc
    adc $7f
    rst $10
    pop bc
    call z, $81cc
    ld d, l
    ld a, a
    and e
    ret z

    ret


    reti


    pop bc
    rst $08
    adc h
    ld a, a
    call nc, $c1c8
    call nc, $c67f
    push bc
    call z, $cc55
    rst $08
    rst $10
    ld a, a
    ret


    db $d3
    ld a, a
    adc $c5
    pop bc
    jp nc, $d9c2

    ld a, a
    db $d3
    push bc
    push bc
    ld d, l
    call Call_02b_7fd3
    call nc, Call_02b_7fcf
    db $d3
    push bc
    push bc
    ld a, a
    jp $c5cc


    pop bc
    jp nc, $d9cc

    ld d, l
    ld a, a
    ld d, [hl]
    reti


    rst $08
    push de
    add a
    call z, Call_02b_7fcc
    adc $cf
    call nc, $d37f
    push bc
    push bc
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    call nz, $cecf
    add a
    call nc, $cc7f
    rst $08
    rst $08
    bit 7, a
    add $cf
    jp nc, $d47f

    ld d, l
    ret z

    push bc
    ld a, a
    push de
    adc $d3
    push bc
    push bc
    adc $7f
    rst $10
    pop bc
    call z, $81cc
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    db $d3
    set 1, c
    call z, Call_02b_7fcc
    ret


    db $d3
    ld a, a
    jp Jump_02b_4fc1


    call z, $c5cc
    call nz, $c37f
    ret z

    pop bc
    jp nc, $c3c1

    call nc, $d2c5
    ld a, a
    jp $55c1


    call $c6d0
    ret


    jp nc, Jump_02b_7fc5

    add c
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    adc $55
    add a
    call nc, $d27f
    ret


    rst $00
    ret z

    call nc, Call_02b_7f81
    and d
    push bc
    add $cf
    jp nc, Jump_02b_7fc5

    ld d, l
    ret


    call nc, Call_02b_7fd3
    push bc
    ret c

    ret


    db $d3
    call nc, $cec9
    rst $00
    adc h
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    jp $d0c1


    ret


    call nc, $ccc1
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    jp $cf55


    push de
    adc $d4
    jp nc, Jump_02b_7fd9

    rst $10
    pop bc
    db $d3
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld d, l
    ld a, a
    jp $d0c1


    ret


    call nc, $ccc1
    ld a, a
    jp $c1c8


    jp nc, $c3c1

    call nc, Call_02b_55c5
    jp nc, $c17f

    adc $c4
    ld a, a
    add $c9
    jp nc, $8dc5

    db $d3
    push bc
    adc $c4
    ret


    adc $55
    rst $00
    ld a, a
    pop bc
    call z, $cbc9
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    call $d2cf
    adc $c9
    adc $c7
    add c
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    call $c14f
    adc $7f
    rst $10
    ret z

    rst $08
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    jp nz, $c5cc

    ld a, a
    call nc, Call_02b_55cf
    ld a, a
    jp nz, $d2d5

    adc $81
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    and e
    pop bc
    ld d, l
    jp $c9c8


    call z, Call_02b_7fc1
    rst $08
    add $7f
    jp nc, $c4c5

    ld a, a
    call z, $d4cf
    push de
    ld d, l
    db $d3
    ld a, a
    ret


    db $d3
    call z, $cec1
    call nz, Call_02b_547f
    ld a, a
    rst $00
    reti


    call Call_02b_5581
    ld a, a
    xor l
    reti


    ld a, a
    pop bc
    call z, Call_02b_7fcc
    ld d, h
    ld a, a
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    ld d, l
    jp nz, $d2d5

    adc $c9
    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    add $c9
    ld d, l
    jp nc, Jump_02b_7fc5

    xor h
    push bc
    call nc, $c87f
    ret


    call $c37f
    ret z

    pop bc
    jp nc, $c5d2

    ld d, l
    call nz, Call_02b_7f81
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld d, l
    ret nc

    jp nc, $d0c5

    pop bc
    jp nc, $d4c1

    ret


    rst $08
    adc $7f
    rst $08
    add $7f
    jp nz, Jump_02b_55d5

    jp nc, Jump_02b_7fce

    jp $d2d5


    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, h
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
    ld c, a
    ret z

    rst $08
    rst $10
    ld a, a
    call $cec1
    reti


    ld a, a
    call nz, $c7c5
    jp nc, $c5c5

    db $d3
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    call nc, $cdc5
    ret nc

    push bc
    jp nc, $d4c1

    push de
    jp nc, Jump_02b_7fc5

    rst $08
    ld d, l
    add $7f
    call nc, $c5c8
    ld a, a
    db $d3
    ret nc

    jp nc, $d9c1

    push bc
    call nz, $c67f
    ret


    jp nc, $c555

    ld a, a
    pop bc
    ret nc

    ret nc

    jp nc, $d8cf

    ret


    call $d4c1
    push bc
    call z, Call_02b_7fd9
    ret


    ld d, l
    db $d3
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
    jp Jump_02b_4fcf


    call $d5c2
    db $d3
    call nc, $c2c9
    call z, $d3c5
    ld a, a
    call $c1c5
    adc $d3
    ld a, a
    ld d, l
    ret


    call nc, Call_02b_7fd3
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    rst $08
    push de
    ld d, l
    adc $c4
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_02b_7fc5
    jp nz, $d2d5

    adc $c9
    adc $c7
    ld a, a
    ld d, l
    rst $10
    ret


    call nc, Call_02b_7fc8
    rst $08
    ret c

    reti


    rst $00
    push bc
    adc $7f
    ld d, [hl]
    ld a, a
    ret


    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    ret


    jp nc, Jump_02b_7f8e

    ld d, a
    nop
    ld a, a
    xor b
    push bc
    ld a, a
    jp $ccc1


    call z, Call_02b_7fd3
    ret z

    ret


    call $c5d3
    call z, Call_02b_4fc6
    ld a, a
    pop bc
    ld a, a
    call nc, $c9c8
    push bc
    add $7f
    pop bc
    adc $c4
    ld a, a
    db $d3
    call nc, $d0cf
    ld d, l
    db $d3
    ld a, a
    call nz, $c9cf
    adc $c7
    ld a, a
    push bc
    sub $c9
    call z, $c17f
    adc $c4
    ld a, a
    ld d, l
    jp nc, $c6c5

    rst $08
    jp nc, $d3cd

    ld a, a
    ret z

    ret


    call $c5d3
    call z, Call_02b_7fc6
    adc $55
    rst $08
    rst $10
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    ret nc

    jp nc, $c3c1

    call nc, $d3c9
    ret


    ld d, l
    adc $c7
    ld a, a
    db $d3
    set 1, c
    call z, Call_02b_7fcc
    ld d, h
    add c
    ld a, a
    ld d, a
    xor a
    adc $c3
    push bc
    ld a, a
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    rst $10
    ld a, a
    ld d, h
    ld a, a
    rst $08
    ld c, a
    add $7f
    rst $08
    call nc, $c5c8
    jp nc, $8cd3

    ld a, a
    ret z

    push bc
    ld a, a
    rst $10
    rst $08
    push de
    call z, $c455
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02b_7fcf
    db $d3
    call nc, $c1c5
    call z, Call_02b_7f81
    ld d, l
    ld d, a
    nop
    ld a, a
    and e
    pop bc
    adc $7f
    ret


    call nc, $cf7f
    sub $c5
    jp nc, $cfc3

    call Call_02b_7fc5
    ld c, a
    call Call_02b_7fc5
    call nz, $c9cf
    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $c4d5
    ld d, l
    reti


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
    or h
    ret z

    rst $08
    push de
    rst $00
    ret z

    ld a, a
    xor c
    ld a, a
    call nc, $ccc5
    call z, $d97f
    rst $08
    ld c, a
    push de
    ld a, a
    pop bc
    adc $c4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c47f
    ld d, l
    rst $08
    adc $87
    call nc, $d57f
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld a, a
    call nc, $c855
    push bc
    db $d3
    push bc
    ld a, a
    rst $10
    rst $08
    jp nc, $d3c4

    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push de
    call nc, $cf7f
    adc $cc
    reti


    ld a, a
    add $c5
    push bc
    call z, Call_02b_7fd3
    call nc, $cf4f
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    sub $c5
    jp nc, Jump_02b_7fd9

    call $c3d5
    ret z

    ld a, a
    ld d, l
    adc [hl]
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    push de
    db $d3
    ret


    adc $55
    rst $00
    ld a, a
    add $cc
    pop bc
    call Call_02b_7fc5
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    push de
    jp nc, $c47f

    jp nc, $c1c5

    call $567f
    sbc a
    ld a, a
    reti


    rst $08
    ld c, a
    push de
    ld a, a
    call $d3d5
    call nc, $d57f
    db $d3
    push bc
    ld a, a
    ret z

    ret


    call $c97f
    add $55
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    call nc, $d47f
    ret z

    ret


    push bc
    add $7f
    ld d, l
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    rst $10
    ret z

    reti


    ld a, a
    and e
    pop bc
    jp $c9c8


    ld c, a
    call z, Call_02b_7fc1
    db $d3
    call nc, $d2c1
    call nc, Call_02b_7fd3
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    push bc
    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $a37f
    pop bc
    ld c, a
    jp $c9c8


    call z, Call_02b_7fc1
    adc $c5
    pop bc
    jp nc, $d9cc

    ld a, a
    call nz, $c5c9
    call nz, Call_02b_7f55
    ld a, a
    call nz, $d2d5
    ret


    adc $c7
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $55
    adc l
    jp $c9cc


    call $c9c2
    adc $c7
    ld a, a
    and [hl]
    call z, $c5c9
    call nz, $d47f
    ld d, l
    ret z

    push bc
    ld a, a
    add $cc
    pop bc
    call $cec9
    rst $00
    rst $08
    ld a, a
    ld d, h
    call nc, Call_02b_55c8
    pop bc
    call nc, $cc7f
    ret


    call nc, Call_02b_7f7f
    call nc, $c5c8
    ld a, a
    call nz, $d2c1
    bit 7, a
    ld d, l
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    jp nc, $c1cf

    call nz, Call_02b_7f81
    and d
    reti


    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    call z, Call_02b_7fd0
    rst $08
    add $7f
    add $cc
    pop bc
    call $c955
    adc $c7
    rst $08
    adc h
    ld a, a
    and e
    pop bc
    jp $c9c8


    call z, Call_02b_7fc1
    db $d3
    pop bc
    add $55
    push bc
    call z, Call_02b_7fd9
    rst $10
    push bc
    adc $d4
    ld a, a
    call nz, $d7cf
    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    jp nz, $c5c5

    adc $7f
    sub $c1
    jp nc, $cfc9

    push de
    ld c, a
    db $d3
    ld a, a
    rst $00
    reti


    call Call_02b_7fd3
    xor b
    push bc
    jp nc, Jump_02b_7fc5

    ret


    db $d3
    ld a, a
    db $d3
    push de
    ld d, l
    ret


    call nc, $c4c5
    ld a, a
    call nc, Call_02b_7fcf
    push de
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    jp nc, $c1c5

    ld a, a
    rst $08
    add $7f
    and e
    ld c, a
    pop bc
    call z, $d0cf
    push de
    ld a, a
    add $c9
    jp nc, Jump_02b_7fc5

    call nc, $d0d9
    push bc
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    rst $10
    push bc
    call z, $cfc3
    call Call_02b_7fc5
    rst $10
    pop bc
    jp nc, $cccd

    reti


    add c
    ld d, l
    ld a, a
    ld d, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    adc $c5
    call Call_02b_7fd9
    ld a, a
    rst $08
    add $7f
    add $c9
    jp nc, $c54f

    ld a, a
    ret


    db $d3
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    jp $d5d4


    pop bc
    call z, $d9cc
    adc h
    ld a, a
    add $c9
    jp nc, Jump_02b_7fc5

    ret


    ld c, a
    db $d3
    ld a, a
    rst $10
    push bc
    pop bc
    bit 7, a
    call nc, Call_02b_7fcf
    rst $10
    pop bc
    call nc, $d2c5
    add c
    ld a, a
    ld d, l
    jp nz, $d4d5

    ld a, a
    add $c9
    jp nc, Jump_02b_7fc5

    ret


    db $d3
    ld a, a
    db $d3
    call nc, $cfd2
    adc $55
    rst $00
    ld a, a
    call nc, Call_02b_7fcf
    ret


    jp $8cc5


    ld a, a
    ret


    call nc, $c37f
    pop bc
    adc $7f
    ld d, l
    call nc, $c1c8
    rst $10
    ld a, a
    ret


    jp Jump_02b_7fc5


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    add $d5
    call nc, $d2d5
    push bc
    ld a, a
    ld c, a
    jp $c1c8


    call $81d0
    ld a, a
    and e
    pop bc
    jp $c9c8


    call z, Call_02b_7fc1
    ret


    db $d3
    ld d, l
    ld a, a
    ld a, a
    add $cc
    pop bc
    call Call_02b_7fc5
    call nc, $d0d9
    push bc
    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    ld d, l
    adc $8c
    ld a, a
    call Call_02b_7fd9
    ld a, a
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    ld d, l
    add c
    ld a, a
    or a
    pop bc
    ret


    call nc, $c17f
    ld a, a
    rst $10
    ret z

    ret


    call z, $8cc5
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $c37f

    push de
    jp nc, Jump_02b_7fc5

    ld d, l
    reti


    rst $08
    push de
    jp nc, $c27f

    push de
    jp nc, $c9ce

    adc $c7
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    or a
    ret


    adc $7f
    rst $08
    jp nc, $ce7f

    rst $08
    call nc, $9f4f
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    pop bc
    adc $7f
    rst $08
    call z, Call_02b_7fc4
    call $cec1
    ld a, a
    ld d, l
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, $d47f
    rst $08
    ld a, a
    call nz, $c1c5
    call z, Call_02b_7f55
    rst $10
    ret


    call nc, $81c8
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    ret z

    push bc
    reti


    add c
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    call nz, $cf4f
    adc $c5
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_02b_557f
    ld e, h
    add c
    ld a, a
    xor c
    call nc, $8755
    call z, Call_02b_7fcc
    jp nz, Jump_02b_7fc5

    ret


    adc $d4
    push bc
    jp nc, $d3c5

    call nc, $cec9
    ld d, l
    rst $00
    ld a, a
    call nc, Call_02b_7fcf
    call nc, $c1c5
    jp Jump_02b_7fc8


    ld d, h
    ld a, a
    call nc, Call_02b_55c8
    ret


    db $d3
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02b_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $c5d2
    db $d3
    push bc
    pop bc
    jp nc, $c8c3

    push bc
    jp nc, $817f

    ld d, l
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
    adc h
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, $cd7f

    rst $08
    ld d, l
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


    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    add $7f
    rst $10
    ret z

    ret


    ld d, l
    db $d3
    call nc, $c5cc
    ld a, a
    add $c9
    adc $c7
    push bc
    jp nc, Jump_02b_7f81

    or h
    rst $08
    ld a, a
    rst $10
    ld d, l
    ret z

    ret


    db $d3
    call nc, $c5cc
    ld a, a
    add $c9
    adc $c7
    push bc
    jp nc, Jump_02b_557f

    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, Call_02b_7fcf
    call $cbc1
    push bc
    ld a, a
    call nc, Call_02b_55c8
    push bc
    ld a, a
    jp nz, $c1d2

    ret


    adc $d3
    ld a, a
    rst $08
    add $7f
    ld a, a
    db $d3
    call nc, $cdc9
    ld d, l
    push de
    call z, $d4c1
    push bc
    call nz, $b47f
    ret z

    push de
    db $d3
    adc h
    ld a, a
    xor c
    call nc, $c37f
    ld d, l
    pop bc
    adc $7f
    call nz, Call_02b_7fcf
    sub $c1
    jp nc, $cfc9

    push de
    db $d3
    ld a, a
    db $d3
    set 1, c
    ld d, l
    call z, $d3cc
    ld a, a
    ld a, a
    call nc, $c1c8
    call nc, $c17f
    jp nc, Jump_02b_7fc5

    adc $c5
    sub $55
    push bc
    jp nc, $c47f

    rst $08
    adc $c5
    ld a, a
    ret


    adc $7f
    adc $cf
    jp nc, $c1cd

    call z, Call_02b_7f55
    call nc, $cdc9
    push bc
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    ret


    add a
    call $c77f
    jp nc, $c1c5

    call nc, Call_02b_4f7f
    call nz, $c3cf
    call nc, $d2cf
    ld a, a
    xor c
    add a
    call $c17f
    call z, $c1d7
    reti


    db $d3
    ld d, l
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, Jump_02b_55c5

    jp $cfc9


    push de
    db $d3
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_02b_7f81
    reti


    rst $08
    push de
    ld d, l
    add c
    ld a, a
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    rst $00
    rst $08
    ld d, l
    rst $08
    call nz, $c67f
    rst $08
    db $d3
    db $d3
    ret


    call z, Call_02b_7f9f
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    adc h
    ld a, a
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, Call_02b_7f81
    ld d, [hl]
    ld a, a
    ld c, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_02b_7fc4
    call nc, $cbc1
    push bc
    ld a, a
    db $d3
    ld c, a
    rst $08
    call Call_02b_7fc5
    call nc, $cdc9
    push bc
    add c
    ld a, a
    and a
    rst $08
    ld a, a
    call nc, $c5c8
    jp nc, $c555

    ld a, a
    call nc, Call_02b_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    rst $10
    pop bc
    call z, $81cb
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    db $d3
    call z, $d7cf
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $cf
    ld c, a
    db $d3
    db $d3
    ret


    call z, $c87f
    pop bc
    db $d3
    ld a, a
    jp nc, $d6c5

    ret


    sub $c5
    call nz, Call_02b_5581
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, $c97f
    db $d3
    ld a, a
    db $d3
    rst $08
    ld d, l
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    reti


    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    or a
    ret z

    reti


    ld a, a
    call nz, $c6c5
    ld c, a
    push bc
    pop bc
    call nc, $c4c5
    sbc a
    ld a, a
    ld d, [hl]
    xor l
    reti


    ld a, a
    jp nz, $c5d2

    push bc
    call nz, $c955
    adc $c7
    ld a, a
    call $d4c5
    ret z

    rst $08
    call nz, $567f
    call $d9c1
    ld a, a
    ld d, l
    adc $cf
    call nc, $c27f
    push bc
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    adc [hl]
    ld a, a
    jp nz, $d4d5

    ld d, l
    ld a, a
    adc $cf
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call $d4c5
    ret z

    rst $08
    call nz, Call_02b_7f81
    ld d, l
    ld d, [hl]
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_02b_7fc5

    pop bc
    ld a, a
    adc $c5
    rst $10
    ld a, a
    jp $c855


    pop bc
    call Call_02b_7fd0
    ld d, [hl]
    rst $08
    add $7f
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    ld d, l
    push bc
    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ld d, l
    ld d, [hl]
    xor c
    call nc, $d387
    ld a, a
    call nc, $cfcf
    ld a, a
    call z, $d3cf
    push bc
    adc l
    add $55
    pop bc
    jp $8cc5


    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    and [hl]
    ret


    adc $c1
    call z, $d9cc
    ld c, a
    ld a, a
    rst $10
    push bc
    ld a, a
    rst $10
    ret


    adc $81
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    rst $00
    push bc
    ld d, l
    adc $cf
    call Call_02b_7fd9
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, l
    ld d, h
    add c
    ld a, a
    and e
    rst $08
    adc $c7
    jp nc, $d4c1

    push de
    call z, $d4c1
    push bc
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret


    adc $7f
    call Call_02b_7fd9
    ret z

    push bc
    pop bc
    jp nc, Jump_02b_7fd4

    ld d, l
    rst $08
    add $7f
    ret z

    push bc
    pop bc
    jp nc, $d3d4

    add c
    ld a, a
    xor a
    adc $7f
    reti


    rst $08
    push de
    ld d, l
    jp nc, $c67f

    ret


    jp nc, $d4d3

    ld a, a
    rst $00
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_02b_7fc5
    db $d3
    call nc, $55d2
    rst $08
    adc $c7
    push bc
    jp nc, $c17f

    adc $c4
    call $d2cf
    push bc
    ld a, a
    call $d4c1
    ld d, l
    push de
    jp nc, Jump_02b_7fc5

    call nc, $c1c8
    adc $7f
    call nc, $c1c8
    call nc, $d97f
    rst $08
    push de
    ld d, l
    ld a, a
    rst $10
    push bc
    adc $d4
    ld a, a
    call nc, Call_02b_7fcf
    jp $cccf


    call z, $c3c5
    call nc, Call_02b_557f
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

    set 1, e
    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    call nc, $c97f
    ld d, l
    db $d3
    ld a, a
    call nc, $cfcf
    ld a, a
    push bc
    call $c1c2
    jp nc, $c1d2

    db $d3
    db $d3
    push bc
    call nz, $8155
    ld a, a
    reti


    pop bc
    ret z

    adc h
    reti


    pop bc
    ret z

    add c
    ld a, a
    ld d, d
    ld a, a
    ld d, l
    ret z

    pop bc
    db $d3
    ld a, a
    rst $00
    jp nc, $d7cf

    adc $7f
    push de
    ret nc

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    jp $cecf


    call nc, $c3c1
    call nc, $d77f
    ret


    call nc, $c84f
    ld a, a
    call nc, $c5c8
    ld a, a
    call $d3c1
    call nc, $d2c5
    ld a, a
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
    add c
    ld a, a
    xor b
    pop bc
    sub $c5
    ld d, l
    ld a, a
    jp nc, $c1c5

    call nz, $d47f
    ret z

    push bc
    ld a, a
    call nc, $c1d2
    adc $d3
    call Call_02b_55c9
    db $d3
    db $d3
    ret


    rst $08
    adc $7f
    call z, $d3c9
    call nc, Call_02b_7f7f
    rst $08
    add $7f
    call $55c1
    adc $c1
    rst $00
    push bc
    call $cec5
    call nc, $d07f
    jp nc, $c7cf

    jp nc, $cdc1

    call $c555
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, d
    jp $cec1


    add a
    call nc, $c27f
    ld c, a
    jp nc, $c1c5

    ld a, a
    call $d2cf
    push bc
    ld a, a
    ret nc

    jp nc, $d0cf

    db $d3
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02b_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_02b_7f55:
Jump_02b_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02b_7f7f:
Jump_02b_7f7f:
    nop
    nop

Call_02b_7f81:
Jump_02b_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02b_7f8c:
    nop
    nop

Call_02b_7f8e:
Jump_02b_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02b_7f9a:
    nop
    nop
    nop
    nop
    nop

Call_02b_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02b_7fc1:
    nop

Jump_02b_7fc2:
    nop
    nop

Call_02b_7fc4:
Jump_02b_7fc4:
    nop

Call_02b_7fc5:
Jump_02b_7fc5:
    nop

Call_02b_7fc6:
    nop
    nop

Call_02b_7fc8:
Jump_02b_7fc8:
    nop
    nop
    nop

Call_02b_7fcb:
Jump_02b_7fcb:
    nop

Call_02b_7fcc:
    nop

Jump_02b_7fcd:
    nop

Jump_02b_7fce:
    nop

Call_02b_7fcf:
    nop

Call_02b_7fd0:
    nop
    nop
    nop

Call_02b_7fd3:
Jump_02b_7fd3:
    nop

Call_02b_7fd4:
Jump_02b_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_02b_7fd9:
Jump_02b_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
