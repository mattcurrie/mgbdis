; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $026", ROMX[$4000], BANK[$26]

    nop
    ld a, a
    reti


    rst $08
    push de
    add a
    call nz, $c27f
    push bc
    ld a, a
    pop bc
    adc $7f
    pop bc
    call nc, $c5d4
    ld c, a
    adc $c4
    pop bc
    adc $d4
    ld a, a
    rst $08
    add $7f
    add $c9
    db $d3
    ret z

    push bc
    jp nc, $c97f

    ld d, l
    add $7f
    reti


    rst $08
    push de
    jp nc, $cc7f

    rst $08
    db $d3
    ret


    adc $c7
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    rst $00
    push bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    pop bc
    adc $c7
    ld c, a
    call z, $c4c5
    ld a, a
    add $c9
    db $d3
    ret z

    ld a, a
    add $d2
    push bc
    push bc
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
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    nop
    ld a, a
    xor c
    add a
    call $d37f
    push de
    jp nc, $ccc5

    reti


    ld a, a
    jp $cecf


    add $c9
    ld c, a
    call nz, $cec5
    call nc, Call_026_7f8e
    and h
    rst $08
    adc $87
    call nc, $cd7f
    pop bc
    set 0, l
    ld a, a
    ld d, l
    push bc
    sub $c5
    jp nc, $d4d9

    ret z

    ret


    adc $c7
    ld a, a
    jp nz, Jump_026_7fc5

    reti


    rst $08
    push de
    ld d, l
    jp nc, $cf7f

    rst $10
    adc $7f
    jp nz, $d3d5

    db $d3
    ret


    adc $c5
    db $d3
    db $d3
    adc h
    ld a, a
    ld d, l
    call nz, Call_026_7fcf
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    db $d3
    ld a, a
    pop bc
    call $cec1
    adc h
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    ret z

    pop bc
    ld c, a
    sub $c9
    adc $c7
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $8c7f
    ld a, a
    ret


    call nc, $557f
    ret


    db $d3
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, $817f
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_026_567f
    ld a, a
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_026_567f
    ld a, a
    ld e, b
    nop
    ld a, a
    xor h
    rst $08
    rst $08
    set 2, e
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $cec5
    call nc, Call_026_4f7f
    adc h
    ld a, a
    adc $cf
    call nc, $c17f
    ld a, a
    db $d3
    ret


    call $ccd0
    ret


    jp $d4c9


    ld d, l
    reti


    add c
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    ret nc

    jp nc, $d9c1

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    call nc, Call_026_7fcf
    pop bc
    call nc, $c1d4
    ret


    adc $7f
    ld c, a
    pop bc
    ld a, a
    reti


    push bc
    call nc, $c87f
    ret


    rst $00
    ret z

    push bc
    jp nc, $c77f

    rst $08
    pop bc
    call z, Call_026_7f55
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    jp $cecf


    add $c9
    ld c, a
    call nz, $cec5
    call nc, Call_026_7f81
    ld e, b
    nop
    ld a, a
    db $d3
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    jp $cecf


    add $c9
    ld c, a
    call nz, $cec5
    call nc, Call_026_7f81
    ld e, b
    nop
    ld a, a
    and c
    jp nc, Jump_026_7fc5

    reti


    rst $08
    push de
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, $4fc5

    ld a, a
    ld d, d
    add c
    xor c
    add a
    call $d47f
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    ld d, l
    adc $c9
    rst $08
    jp nc, $c77f

    push bc
    adc $c5
    jp nc, $ccc1

    ld a, a
    rst $08
    add $7f
    and d
    ld d, l
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

    rst $08
    jp nc, Jump_026_7f55

    pop bc
    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    db $d3
    add c
    push de
    db $d3
    push bc
    ld a, a
    or a
    ld d, l
    pop bc
    call nc, $d2c5
    call z, $cecf
    ld a, a
    rst $08
    add $7f
    add $cc
    reti


    ret


    adc $c7
    ld d, l
    ld a, a
    call nz, $c1d2
    rst $00
    rst $08
    adc $81
    reti


    rst $08
    push de
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    ld d, l
    pop bc
    jp nz, $d5cf

    call nc, $c67f
    call z, $c9d9
    adc $c7
    ld a, a
    call nz, $c1d2
    rst $00
    ld d, l
    rst $08
    adc $c1
    ld a, a
    db $d3
    pop bc
    jp $c5d2


    call nz, $c17f
    adc $c4
    ld a, a
    pop bc
    call z, $c955
    sub $c5
    ld a, a
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    ld a, a
    ret


    adc $7f
    call z, $c555
    rst $00
    push bc
    adc $c4
    add c
    and e
    pop bc
    ret nc

    call nc, $d2d5
    ret


    adc $c7
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, $c27f
    push de
    call nc, $cfc6
    ld d, l
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    rst $10
    push bc
    call z, Call_026_7fcc
    adc h
    ld a, a
    ret


    call nc, Call_026_7f55
    call $d9c1
    ld a, a
    jp nz, Jump_026_7fc5

    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cfd2
    adc $55
    rst $00
    push bc
    db $d3
    call nc, $c17f
    jp nc, $d5cf

    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    ld d, l
    rst $08
    jp nc, $c4cc

    adc [hl]
    or b
    ret z

    ret


    db $d3
    ret


    jp $ccc1


    call z, Call_026_7fd9
    db $d3
    ld d, l
    call nc, $cfd2
    adc $c7
    add c
    xor c
    call nc, $d387
    ld a, a
    adc $cf
    ld a, a
    push de
    db $d3
    push bc
    ld d, l
    ld a, a
    ret nc

    call z, $d9c1
    ret


    adc $c7
    ld a, a
    ret nc

    push bc
    call nc, $d9d4
    ld a, a
    call nc, Call_026_55d2
    ret


    jp $d3cb


    ld a, a
    call nc, Call_026_7fcf
    pop bc
    call nc, $c1d4
    jp $81cb


    ld a, a
    ld a, a
    ld d, l
    ld d, [hl]
    adc [hl]
    or h
    ret z

    push bc
    adc $81
    ld a, a
    ld a, a
    call z, $d4c5
    add a
    db $d3
    ld a, a
    jp nz, $c555

    rst $00
    ret


    adc $81
    rst $08
    jp nc, $cc7f

    push bc
    call nc, $d387
    ld a, a
    rst $00
    rst $08
    ld a, a
    ld d, l
    jp nz, $c3c1

    bit 7, a
    call nc, $c3d5
    set 1, c
    adc $c7
    ld a, a
    rst $08
    push de
    jp nc, $557f

    call nc, $c9c1
    call z, Call_026_7fd3
    jp nz, $d4c5

    rst $10
    push bc
    push bc
    adc $7f
    rst $08
    push de
    jp nc, Jump_026_7f55

    call z, $c7c5
    db $d3
    add c
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_026_7f8c
    ret z

    add a
    call $b481
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    ld c, a
    call z, Call_026_7fcc
    rst $08
    add $7f
    reti


    rst $08
    push de
    jp nc, Jump_026_7f7f

    ld d, h
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_026_7fcc
    call nc, $cfc8
    push de
    ld d, l
    rst $00
    ret z

    ld a, a
    xor c
    add a
    call $c17f
    adc $c7
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_026_7f8c
    ret z

    add a
    call $b481
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    ld c, a
    call z, Call_026_7fcc
    rst $08
    add $7f
    reti


    rst $08
    push de
    jp nc, Jump_026_7f7f

    ld d, h
    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_026_7fcc
    call nc, $cfc8
    push de
    rst $00
    ld d, l
    ret z

    ld a, a
    xor c
    add a
    call $c17f
    adc $c7
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    xor b
    push bc
    reti


    ld c, a
    add c
    ld a, a
    and e
    rst $08
    adc $c7
    jp nc, $d4c1

    push de
    call z, $d4c1
    ret


    rst $08
    adc $d3
    ld d, l
    adc h
    ld a, a
    jp $cecf


    rst $00
    jp nc, $d4c1

    push de
    call z, $d4c1
    ret


    rst $08
    adc $d3
    ld d, l
    add c
    ld a, a
    ld d, d
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_026_7fc5

    ld d, [hl]
    ld a, a
    ld d, l
    adc h
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    db $d3
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    rst $08
    add $7f
    ret nc

    pop bc
    db $d3
    call nc, $c17f
    rst $00
    push bc
    db $d3
    adc [hl]
    ld d, l
    ld a, a
    rst $10
    rst $08
    jp nc, $d3cb

    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $557f

    ld e, l
    ld a, a
    ld d, [hl]
    or d
    push bc
    jp $d2cf


    call nz, $557f
    call nc, $c5c8
    call Call_026_7f8c
    pop bc
    jp $c9d4


    sub $c5
    ld a, a
    ld d, h
    db $d3
    ld d, l
    adc h
    ld a, a
    ret z

    push bc
    jp nc, $8dc5

    pop bc
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    call nc, Call_026_55cf
    ld a, a
    push bc
    ret c

    call nc, $cccf
    ld a, a
    call nc, $c5c8
    call Call_026_7f81
    ld d, l
    ld e, l
    ld a, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, Call_026_7fcf
    ld d, l
    jp $ccc1


    call z, $d47f
    ret z

    push bc
    db $d3
    push bc
    ld a, a
    ld a, a
    jp nc, $c3c5

    rst $08
    jp nc, $c455

    push bc
    call nz, $d47f
    rst $08
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $d37f

    pop bc
    jp Jump_026_55d2


    push bc
    call nz, $a87f
    pop bc
    call z, $81cc
    ld a, a
    ld a, a
    ld d, d
    add c
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_026_7fc5
    ld d, l
    pop bc
    ld a, a
    jp $c1c8


    call Call_026_7fd0
    rst $08
    add $7f
    pop bc
    call z, $c9cc
    pop bc
    adc $55
    jp Jump_026_7fc5


    pop bc
    add $d4
    push bc
    jp nc, $c17f

    ld a, a
    jp $cfcc


    db $d3
    push bc
    ld a, a
    ld d, l
    jp $cecf


    call nc, $d3c5
    call nc, Call_026_7f7f
    add c
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    ret z

    push bc
    ld d, l
    jp nc, $8ec5

    ld a, a
    or a
    jp nc, $d4c9

    push bc
    ld a, a
    call nz, $d7cf
    adc $7f
    call nc, Call_026_55c8
    push bc
    ld a, a
    adc $c1
    call $d3c5
    ld a, a
    rst $08
    add $7f
    ld d, d
    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    ld d, h
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ld d, d
    add c
    ld a, a
    ld c, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ld d, e
    ld c, a
    ld d, [hl]
    add c
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    ret nc

    ret


    ld d, l
    call nc, $81d9
    ld a, a
    xor c
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_026_7fc5

    call z, $c955
    set 0, l
    ld a, a
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $557f

    ret z

    push bc
    pop bc
    jp nc, $cec9

    rst $00
    ld a, a
    call nc, $c1c8
    call nc, $d97f
    rst $08
    push de
    add a
    ld d, l
    sub $c5
    ld a, a
    rst $10
    ret


    adc $7f
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
    ld a, a
    adc [hl]
    ld a, a
    jp nz, $d4d5

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    add $c9
    adc $c1
    call z, $d9cc
    ld a, a
    call z, $d3cf
    call nc, $d77f
    ret z

    push bc
    adc $55
    ld a, a
    xor c
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    call nc, Call_026_7fcf
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $cc55
    ret


    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    add c
    ld a, a
    ld a, a
    ld d, l
    ld d, e
    ld a, a
    and c
    ret z

    adc h
    ld d, [hl]
    add c
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    rst $10
    ret z

    reti


    ld a, a
    reti


    rst $08
    push de
    add a
    sub $55
    push bc
    ld a, a
    call z, $d3cf
    call nc, Call_026_7f9f
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    ld d, [hl]
    adc [hl]
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    rst $10
    ret z

    reti


    ld a, a
    reti


    ld d, l
    rst $08
    push de
    add a
    sub $c5
    ld a, a
    add $cf
    jp nc, $cfc7

    call nc, $d97f
    rst $08
    push de
    jp nc, Jump_026_7f55

    call nc, $d5d2
    db $d3
    call nc, $c17f
    adc $c4
    ld a, a
    call z, $d6cf
    push bc
    ld a, a
    ld a, a
    ld d, l
    call nc, Call_026_7fcf
    ld d, h
    db $d3
    add c
    ld a, a
    db $d3
    rst $08
    ld a, a
    ret z

    rst $08
    rst $10
    push bc
    sub $55
    push bc
    jp nc, $c87f

    pop bc
    jp nc, Jump_026_7fc4

    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    adc h
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    add a
    call nc, $d37f
    call nc, $cec1
    call nz, $557f
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push de
    call $c9cd
    call nc, Call_026_7f81
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ld d, d
    add c
    ld a, a
    ld c, a
    xor c
    call nc, $c97f
    db $d3
    adc $87
    call nc, $d97f
    rst $08
    push de
    jp nc, $cf7f

    rst $10
    adc $55
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    call nc, Call_026_7fcf
    jp nc, $ccd5

    push bc
    ld a, a
    call nc, Call_026_55c8
    push bc
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, h
    adc [hl]
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    call nc, $c9c8
    ld d, l
    db $d3
    ld a, a
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    push bc
    call z, $81cc
    ld a, a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, l
    ret nc

    push bc
    jp nc, $c5c6

    jp Jump_026_7fd4


    call $d4c1
    jp Jump_026_7fc8


    jp nz, $d4c5

    ld d, l
    rst $10
    push bc
    push bc
    adc $7f
    ld d, d
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $08
    add $55
    ld a, a
    ld d, h
    ret


    db $d3
    ld a, a
    jp nz, $c9d2

    call z, $c9cc
    pop bc
    adc $d4
    add c
    ld d, l
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, d
    add c
    ld a, a
    ld d, l
    add $cf
    call z, $cfcc
    rst $10
    ld a, a
    call Call_026_7fc5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call $81c5
    ld a, a
    or a
    push bc
    call z, $cfc3
    call $4fc5
    ld a, a
    call nc, Call_026_7fcf
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    ret


    adc $7f
    call z, $c955
    rst $00
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    jp $d4c9


    reti


    add c
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    ret


    adc $d4
    jp nc, $c4cf

    push de
    jp $c9d4


    rst $08
    adc $7f
    ld a, a
    add $55
    rst $08
    jp nc, $c57f

    pop bc
    jp Jump_026_7fc8


    db $d3
    call nc, $d2cf
    push bc
    reti


    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c7c9

    ret z

    call nc, Call_026_7f8e
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    jp nc, $d5cf

    adc $c4
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    push bc
    ld c, a
    jp nc, $c9d6

    jp Jump_026_7fc5


    call nz, $d3c5
    bit 7, a
    ld d, [hl]
    adc [hl]
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    add $c9
    jp nc, $d4d3

    ld a, a
    add $cc
    rst $08
    rst $08
    jp nc, $c97f

    db $d3
    ld a, a
    ld d, l
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    ld d, [hl]
    ld e, l
    adc h
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    jp $cecf


    call nz, $c67f
    call z, $cfcf
    jp nc, $c97f

    ld d, l
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    ld d, [hl]
    ld a, a
    call nc, Call_026_7fcf
    ld d, l
    call $cecf
    rst $08
    ret nc

    rst $08
    call z, $dac9
    push bc
    ld a, a
    or h
    or [hl]
    ld a, a
    pop bc
    adc $c4
    ld d, l
    ld a, a
    ret nc

    call z, $d9c1
    push bc
    jp nc, Jump_026_7f8c

    or h
    ret z

    push bc
    ld a, a
    call nc, $c9c8
    jp nc, $c455

    ld a, a
    add $cc
    rst $08
    rst $08
    jp nc, $c97f

    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $c5cc


    sub $55
    push bc
    jp nc, $c1cd

    adc $7f
    ld d, [hl]
    ld a, a
    call nc, Call_026_7fcf
    rst $00
    ret


    sub $c5
    ld a, a
    ld d, l
    pop bc
    rst $10
    pop bc
    reti


    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $cf
    push de
    jp nc, $c8d4

    ld a, a
    ld d, l
    add $cc
    rst $08
    rst $08
    jp nc, $c97f

    db $d3
    ld a, a
    pop bc
    adc $7f
    pop bc
    adc $c1
    push bc
    db $d3
    ld d, l
    call nc, $c5c8
    call nc, $c3c9
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    ld a, a
    call nc, $d0cf
    ld a, a
    add $cc
    rst $08
    rst $08
    jp nc, $c97f

    db $d3
    ld a, a
    pop bc
    ld d, l
    push de
    call nc, $cdcf
    pop bc
    call nc, Call_026_567f
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    jp nc, $d5cf

    adc $c4
    adc h
    ld a, a
    db $d3
    push bc
    jp nc, Jump_026_4fd6

    ret


    jp Jump_026_7fc5


    call nz, $d3c5
    bit 7, a
    ld d, [hl]
    adc h
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
    adc $4f
    pop bc
    call $d3c5
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    call nc, Call_026_55cf
    call z, $cec5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $c3c5

    rst $08
    jp nc, Jump_026_7fc4

    ld a, a
    pop bc
    ld d, l
    adc $c4
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    ld d, h
    ld a, a
    adc h
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    rst $08
    adc $c4
    push bc
    jp nc, $d5c6

    call z, Call_026_7f81
    or h
    ret z

    push bc
    ld a, a
    jp nz, $cf4f

    reti


    ld a, a
    adc $c5
    ret c

    call nc, $c47f
    rst $08
    rst $08
    jp nc, $c57f

    ret c

    jp Jump_026_55c8


    pop bc
    adc $c7
    push bc
    db $d3
    ld a, a
    and a
    ret z

    rst $08
    db $d3
    call nc, $c17f
    adc $c4
    ld a, a
    and e
    ld d, l
    pop bc
    jp nc, $d5cc

    call z, Call_026_7fc1
    rst $10
    ret


    call nc, Call_026_7fc8
    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    or c
    push de
    ret


    jp Jump_026_7fcb


    call nc, Call_026_7fcf
    jp $cdcf


    push bc
    add c
    ld a, a
    and a
    ld c, a
    ret z

    rst $08
    db $d3
    call nc, $c27f
    pop bc
    jp nz, $81d9

    ld a, a
    xor c
    adc h
    ret


    db $d3
    ld a, a
    pop bc
    ld d, l
    ld a, a
    and a
    ret z

    rst $08
    db $d3
    call nc, $c67f
    pop bc
    adc $c1
    call nc, $c3c9
    add c
    ld a, a
    and c
    ld d, l
    ret z

    adc h
    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    and a
    ret z

    rst $08
    db $d3
    call nc, $557f
    ld a, a
    call nc, $c1d2
    adc $d3
    add $c5
    jp nc, $c5d2

    call nz, $c87f
    pop bc
    db $d3
    ld a, a
    ld d, l
    jp nz, $c3c5

    rst $08
    call Call_026_7fc5
    pop bc
    adc $cf
    call nc, $c5c8
    jp nc, $557f

    ld d, h
    add c
    sbc a
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
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    ld c, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    rst $08
    call nc, Call_026_55c8
    push bc
    jp nc, $8ed3

    ld a, a
    xor c
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld d, l
    ld a, a
    call nz, $c6c9
    add $c5
    jp nc, $cec5

    call nc, $cf7f
    ret nc

    ret nc

    rst $08
    adc $c5
    ld d, l
    adc $d4
    db $d3
    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d9c3

    jp nz, $d2c5

    add c
    ld a, a
    ld d, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    jp nc, $cccf

    call z, $ca8d
    push de
    call Call_026_7fd0
    ld c, a
    rst $00
    pop bc
    call Call_026_7fc5
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $557f
    call nc, $cdc9
    push bc
    ld a, a
    call nc, Call_026_7fcf
    ret nc

    call z, $d9c1
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d9c3

    jp nz, $d2c5

    add c
    ld a, a
    ld d, a
    nop
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

    rst $08
    jp nc, Jump_026_7fd4

    rst $00
    ld c, a
    pop bc
    call Call_026_7fc5
    add c
    or b
    pop bc
    ret nc

    pop bc
    ld a, a
    ld d, [hl]
    ld a, a
    call $d9c1
    ld a, a
    ld d, l
    call z, $cbc9
    push bc
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    call nc, $d0d9
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d9c3

    jp nz, $d2c5

    add c
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
    rst $00
    push de
    push bc
    db $d3
    db $d3
    adc l
    ld c, a
    pop bc
    adc l
    jp nc, $c4c9

    call nz, $c5cc
    ld a, a
    rst $00
    pop bc
    call Call_026_7fc5
    ld d, [hl]
    ld a, a
    ld d, l
    add c
    ld a, a
    xor a
    adc $c3
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    jp nz, $c7c5

    ret


    adc $d3
    adc h
    ld d, l
    ld a, a
    ret


    call nc, $d37f
    ret z

    rst $08
    push de
    call z, $cec4
    add a
    call nc, $d37f
    call nc, Call_026_55cf
    ret nc

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d9c3

    jp nz, $d2c5

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    ret z

    pop bc
    call nz, $d7cf
    jp nz, $d8cf

    ld c, a
    ld a, a
    rst $00
    pop bc
    call Call_026_7fc5
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    ld d, l
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    rst $08
    call $cfc5
    adc $c5
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
    push bc
    jp $cecf


    call nz, $c67f
    call z, $cfcf
    jp nc, Jump_026_7f4f

    ld d, [hl]
    ld a, a
    db $d3
    push bc
    call z, $d3cc
    ld a, a
    or h
    or [hl]
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld d, l
    ld a, a
    ret nc

    call z, $d9c1
    push bc
    jp nc, $8ed3

    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    push bc
    call nz, $c17f
    adc $c4
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    add c
    ld a, a
    ld c, a
    and c
    call z, $c5d4
    jp nc, $c1ce

    call nc, $d6c9
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ld d, l
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    push bc
    call nz, $c17f
    adc $c4
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    add c
    ld a, a
    ld c, a
    and c
    call z, $c5d4
    jp nc, $c1ce

    call nc, $d6c9
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ld d, l
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    push bc
    call nz, $c17f
    adc $c4
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    add c
    ld a, a
    ld c, a
    and c
    call z, $c5d4
    jp nc, $c1ce

    call nc, $d6c9
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ld d, l
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    reti


    rst $08
    push de
    adc $c7
    push bc
    jp nc, $d37f

    ret


    db $d3
    call nc, $4fc5
    jp nc, Jump_026_7f7f

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    adc $cf
    jp nz, $c4cf

    reti


    ld a, a
    rst $08
    add $55
    ld a, a
    ld d, h
    ld e, l
    add c
    ld a, a
    ld d, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    rst $10
    ret


    call z, $d5c6
    call z, Call_026_7f8c
    xor c
    add a
    ld d, l
    call $c27f
    rst $08
    jp nc, $c4c5

    ld a, a
    rst $08
    add $7f
    ret z

    push bc
    jp nc, Jump_026_7f8e

    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $d0cf
    ld a, a
    add $cc
    rst $08
    rst $08
    jp nc, Jump_026_7f8c

    ld c, a
    ld d, [hl]
    adc h
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, $d4d3

    ld a, a
    db $d3
    pop de
    push de
    pop bc
    ld d, l
    jp nc, Jump_026_7fc5

    ld d, [hl]
    ld a, a
    pop bc
    adc $7f
    pop bc
    push de
    call nc, $cdcf
    pop bc
    call nc, $558e
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $c3c1

    ret z

    push bc
    call z, $d2cf
    ld a, a
    call z, $c6c9
    ld c, a
    push bc
    ld a, a
    rst $08
    add $7f
    ld a, a
    ret


    db $d3
    adc $87
    call nc, $cc7f
    rst $08
    adc $c5
    call z, $d955
    ld a, a
    pop bc
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    adc $c3
    ret


    jp nc, $55c3

    call z, $c4c5
    ld a, a
    jp nz, Jump_026_7fd9

    ld d, h
    db $d3
    add c
    ld a, a
    xor [hl]
    ret


    db $d3
    db $d3
    ld d, l
    ld a, a
    ret


    adc $7f
    call Call_026_7fd9
    add $c1
    call $ccc9
    reti


    ld a, a
    db $d3
    rst $08
    call $c555
    call nc, $cdc9
    push bc
    db $d3
    ld a, a
    ret nc

    ret


    jp $c5cb


    db $d3
    ld a, a
    push de
    ret nc

    ld a, a
    ld d, l
    db $d3
    rst $08
    call Call_026_7fc5
    call $cecf
    push bc
    reti


    ld a, a
    rst $08
    jp nc, $d37f

    rst $08
    call $c555
    call nc, $c9c8
    adc $c7
    ld a, a
    push bc
    call z, $c5d3
    adc [hl]
    ld a, a
    ld d, a
    nop
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    call $cec1
    db $d3
    ret


    rst $08
    adc $4f
    ld a, a
    adc h
    ld a, a
    call $cec1
    pop bc
    rst $00
    push bc
    jp nc, $d27f

    rst $08
    rst $08
    call Call_026_577f
    nop
    ld a, a
    or d
    push bc
    jp $d0c5


    call nc, $cfc9
    adc $7f
    or d
    rst $08
    rst $08
    call $c67f
    ld c, a
    rst $08
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    or h
    ret z

    rst $08
    push de
    rst $00
    ret z

    call nc, $cf7f
    add $55
    ld a, a
    or b
    call z, $d9c1
    ld a, a
    xor l
    rst $08
    adc $d3
    call nc, $d2c5
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    sbc a
    ld a, a
    or h
    ret z

    pop bc
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cf4f

    rst $00
    jp nc, $cdc1

    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    and a
    push de
    call z, $d0c1
    ret z

    ret


    jp Jump_026_7f81


    xor c
    ld c, a
    call nc, $d387
    ld a, a
    xor c
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    ld d, l
    call nz, $d97f
    rst $08
    push de
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    rst $10
    jp nc, $d4cf

    push bc
    ld a, a
    pop bc
    ld a, a
    add $c9
    call z, Call_026_7fcd
    db $d3
    ld c, a
    jp $c9d2


    ret nc

    call nc, $817f
    ld a, a
    or h
    ret z

    pop bc
    call nc, $a17f
    call z, $c9cc
    ld d, l
    jp $c97f


    db $d3
    ld a, a
    call z, $d6cf
    push bc
    call z, $8cd9
    ld a, a
    ret


    db $d3
    adc $87
    ld d, l
    call nc, $d37f
    ret z

    push bc
    sbc a
    ld a, a
    and e
    pop bc
    jp nc, $cdd3

    reti


    ld a, a
    call nc, $cfcf
    ld d, l
    add c
    ld a, a
    xor [hl]
    pop bc
    jp $c9c8


    call Call_026_7fd9
    call nc, $cfcf
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $c7cf

    jp nc, $cdc1

    ld c, a
    call Call_026_7fc5
    pop bc
    jp nz, $d5cf

    call nc, $d07f
    call z, $d9c1
    add c
    ld a, a
    and c
    adc $55
    ld a, a
    push de
    adc $c5
    ret c

    ret nc

    push bc
    jp $c5d4


    call nz, $c37f
    ret z

    pop bc
    adc $c7
    ld d, l
    push bc
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_026_7fc4
    call nc, $cbc1
    push bc
    ld a, a
    ret nc

    call z, Call_026_55c1
    jp Jump_026_7fc5


    ret


    add $7f
    push bc
    ret c

    jp $c1c8


    adc $c7
    ret


    adc $c7
    ld a, a
    ld d, l
    call nc, $c9c8
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    call nc, $c9c8
    adc $cb
    ld a, a
    ld e, e
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $4fc8
    push bc
    ld a, a
    rst $10
    rst $08
    jp nc, $c9cb

    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    jp nz, Jump_026_55d5

    call nc, $c97f
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    jp nz, $55c5

    reti


    rst $08
    adc $c4
    ld a, a
    call Call_026_7fd9
    push bc
    ret c

    ret nc

    push bc
    jp $c9d4


    rst $08
    adc $55
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    add $c9
    call z, Call_026_7fcd
    db $d3
    jp Jump_026_4fd2


    ret


    ret nc

    call nc, $c17f
    jp nz, $d5cf

    call nc, $d07f
    rst $08
    jp $c5cb


    call nc, $557f
    call $cecf
    db $d3
    call nc, $d2c5
    db $d3
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    adc $c4
    ret


    adc $c7
    ld a, a
    ret nc

    rst $08
    jp nc, $c9d4

    ld d, l
    rst $08
    adc $81
    ld a, a
    call z, $d4c5
    add a
    db $d3
    ld a, a
    adc $cf
    call nc, $d27f
    push bc
    pop bc
    ld d, l
    call nz, $ce7f
    rst $08
    rst $10
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    push bc
    db $d3
    push bc
    pop bc
    jp nc, $c8c3

    ld a, a
    pop bc
    adc $c4
    ld a, a
    and h
    push bc
    sub $4f
    push bc
    call z, $d0cf
    call $cec5
    call nc, $ccc1
    ld a, a
    or d
    rst $08
    rst $08
    call $c67f
    ld d, l
    rst $08
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    or h
    ret z

    rst $08
    push de
    rst $00
    ret z

    call nc, $cf7f
    add $55
    ld a, a
    or b
    call z, $d9c1
    ld a, a
    xor l
    rst $08
    adc $d3
    call nc, $d2c5
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ld c, a
    ret z

Call_026_4f7f:
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, Jump_026_7f81

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
    ret


    call nc, $d77f
    jp nc, $d4c9

    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    xor [hl]
    ld d, l
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    ret nc

    jp nc, $c2cf

    call z, $cdc5
    ld a, a
    xor c
    ld a, a
    call nz, $cf55
    adc $87

Call_026_4fc4:
    call nc, $cb7f
    adc $cf

Call_026_4fc9:
Jump_026_4fc9:
    rst $10
    ld a, a

Jump_026_4fcb:
    adc h

Call_026_4fcc:
Jump_026_4fcc:
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a

Jump_026_4fd2:
    ld d, l
    ret z

    pop bc

Call_026_4fd5:
    db $d3

Jump_026_4fd6:
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    rst $08
    rst $10
    adc $7f
    rst $10
    rst $08
    jp nc, $c4cc

    ld d, l
    ld a, a
    pop bc
    call $cecf
    rst $00
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    pop bc
    call nc, $c5d4
    adc $55
    call nz, $cec1
    call nc, $81d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $c97f
    ld d, l
    adc $d6
    ret


    call nc, Call_026_7fc5
    reti


    rst $08
    push de
    jp nc, $c67f

    jp nc, $c5c9

    adc $c4
    ld d, l
    db $d3
    ld a, a
    ld a, a
    call nc, Call_026_7fcf
    jp $cdcf


    push bc
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $55
    rst $00
    ret


    adc $c7
    ld a, a
    ld d, h
    ld a, a
    adc [hl]
    ld a, a
    pop bc
    adc $c4
    ld a, a
    push bc
    adc $55
    jp z, $d9cf

    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    call $c5d3
    call z, $c5d6
    db $d3
    ld d, l
    ld a, a
    call nc, Call_026_7fcf
    call nc, $c5c8
    ld a, a
    add $d5
    call z, $81cc
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
    db $d3
    call z, $c5c5
    ret nc

    push bc
    call nz, Call_026_7f4f
    rst $10
    ret


    call nc, Call_026_7fc8
    call nc, $c5c8
    ld a, a
    rst $10
    ret z

    ret


    db $d3
    call nc, $c5cc
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, h
    adc h
    ld a, a
    rst $00
    push bc
    call nc, $d57f
    ret nc

    ld a, a
    db $d3
    ld d, l
    push de
    call nz, $c5c4
    adc $cc
    reti


    ld a, a
    adc h
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld d, l
    ld a, a
    rst $08
    add $7f
    pop bc
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c27f
    push de
    call nc, Call_026_7f55
    adc $cf
    call nc, $c88d
    push bc
    pop bc
    jp nc, $8dc4

    jp nz, $8dd9

    call $cec1
    ld d, l
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    jp nc, $c4cf

    push de
    jp $c4c5


    ld a, a
    jp nz, $d955

    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    ld a, a
    add $d2
    rst $08
    call $d07f
    ret


    adc $cb
    ld a, a
    ld c, a
    jp $d4c9


    reti


    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nc, $d5cf

    call nc, Call_026_7fc5
    ld a, a
    ld d, l
    add $cf
    jp nc, $c27f

    ret


    set 0, l
    ld a, a
    add $c1
    jp nc, $ca7f

    rst $08
    push de
    jp nc, $ce55

    push bc
    reti


    ld a, a
    ret


    db $d3
    ld a, a
    ret nc

    push de
    rst $10
    pop bc
    jp nc, Jump_026_7fc4

    db $d3
    call z, Call_026_55cf
    ret nc

    push bc
    adc [hl]
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    call nc, $d2c9
    push bc
    call nz, $8155
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    call nc, $c9c1
    adc $c2
    rst $08
    rst $10
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    ld c, a
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
    call z, $55c5
    sub $c5
    call z, $c97f
    db $d3
    ld a, a
    adc $cf
    ld a, a
    call $d2cf
    push bc
    ld a, a
    call nc, Call_026_55c8
    pop bc
    adc $7f
    sub l
    sub b
    ld a, a
    call $d9c1
    ld a, a
    jp nz, Jump_026_7fc5

    rst $08
    jp nz, $c4c5

    ld d, l
    ret


    push bc
    adc $d4
    ld a, a
    pop de
    push de
    ret


    push bc
    call nc, $d9cc
    add c
    ld a, a
    and c
    adc $c4
    ld d, l
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $c9d2
    jp $c5cb


    db $d3
    ld a, a
    ld a, a
    ld a, a
    rst $08
    ld d, l
    add $7f
    db $d3
    call nc, $c1d2
    adc $c7
    push bc
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    jp $cec1


    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    jp nz, Jump_026_7fc5

    push de
    db $d3
    ld d, l
    push bc
    call nz, $d77f
    ret z

    push bc
    adc $7f
    adc $cf
    ld a, a
    jp $cecf


    call nc, $d3c5
    ld d, l
    call nc, $cec9
    rst $00
    adc [hl]
    ld a, a
    and c
    call nz, $c9c4
    call nc, $cfc9
    adc $c1
    call z, Call_026_55cc
    reti


    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    call nc, Call_026_55c8
    ret


    db $d3
    ld a, a
    ret


    add $7f
    db $d3
    pop bc
    call nc, $d3c9
    add $c9
    push bc
    call nz, $817f
    ld d, l
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
    call nz, Call_026_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    xor c
    adc $7f
    ld d, l
    ld e, h
    sub d
    sub c
    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    adc $d5
    call nc, $c9d2
    call nc, $cfc9
    adc $7f
    rst $08
    add $55
    ld a, a
    ld d, h
    ld a, a
    jp nz, $c3c5

    rst $08
    call $cec9
    rst $00
    ld a, a
    add $d2
    rst $08
    ld d, l
    call $d47f
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    call z, Call_026_7fc6
    rst $08
    add $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    call z, $d3cf
    db $d3
    ld a, a
    adc [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    call nc, $d255
    pop bc
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, Jump_026_7fd9

    db $d3
    set 1, c
    call z, Call_026_7fcc
    ld d, l
    ld d, a
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
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    call $cec1
    add c
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    or h
    ret z

    ld c, a
    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    call nc, $c855
    pop bc
    call nc, $cf7f
    adc $cc
    reti


    ld a, a
    rst $00
    ret


    jp nc, $d3cc

    ld a, a
    jp Jump_026_55c1


    adc $7f
    push bc
    adc $d4
    push bc
    jp nc, Jump_026_7f81

    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c97f
    ld c, a
    add $7f
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    jp nz, Jump_026_7fd9

    and c
    call z, Call_026_55cc
    ret


    jp Jump_026_7f7f


    ld d, a
    nop
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    jp nc, $c4d5

    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    jp nc, $c4d5

    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    ret


    add c
    ld a, a
    and c
    call z, Call_026_7fcc
    pop bc
    jp nc, Jump_026_7fc5

    rst $00
    ret


    jp nc, Jump_026_4fcc

    db $d3
    ld a, a
    adc [hl]
    ld a, a
    add $c5
    push bc
    call z, $cec9
    rst $00
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, $9f55
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    push de
    jp nc, $c67f

    push bc
    push bc
    call nz, $c27f
    pop bc
    ret


    call nc, $c97f
    db $d3
    ld c, a
    ld a, a
    rst $10
    push bc
    pop bc
    bit 7, a
    call nc, Call_026_7fcf
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    and c
    adc $c4
    ld a, a
    adc $cf
    call nc, $cf7f
    adc $cc
    reti


    ld a, a
    rst $10
    pop bc
    call nc, $55c5
    jp nc, $d47f

    reti


    ret nc

    push bc
    ld a, a
    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    pop bc
    call z, $cfd3
    ld d, l
    ld a, a
    rst $00
    jp nc, $d5cf

    adc $c4
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, l
    jp nc, $c3cf

    bit 7, a
    call nc, $d0d9
    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_026_7f81
    ld e, b
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_026_7f81
    ld e, b
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    and c
    jp nc, $cec5

    add a
    call nc, $d97f
    rst $08
    push de
    ld a, a
    ld c, a
    call nc, $c5c8
    ld a, a
    call $cec1
    ld a, a
    ret nc

    push bc
    push bc
    ret nc

    ret


    adc $c7
    ld a, a
    pop bc
    ld d, l
    call nc, $c87f
    push bc
    jp nc, Jump_026_7fc5

    jp z, $d3d5

    call nc, $c27f
    push bc
    add $cf
    jp nc, $c555

    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    adc h
    call nc, $d5d2
    db $d3
    call nc, $d9cc
    ld a, a
    call nz, $cecf
    add a
    ld c, a
    call nc, $d07f
    push bc
    push bc
    ret nc

    ld a, a
    pop bc
    call nc, Call_026_7f9f
    call nc, $c5c8
    jp nc, Jump_026_7fc5

    ld d, l
    pop bc
    jp nc, Jump_026_7fc5

    call $cec1
    reti


    ld a, a
    ret


    adc $7f
    jp nc, $c3c5

    push bc
    adc $55
    call nc, Call_026_7f8e
    ld d, a
    nop
    ld a, a
    and d
    call z, $cec9
    set 1, c
    adc $c7
    ld a, a
    rst $08
    adc $c5
    add a
    db $d3
    ld a, a
    push bc
    ld c, a
    reti


    push bc
    db $d3
    ld a, a
    rst $10
    ret


    call nc, Call_026_7fc8
    pop bc
    db $d3
    call nc, $cecf
    ret


    db $d3
    ret z

    ld d, l
    call $cec5

Call_026_547f:
    call nc, Call_026_7f8e
    ld e, b
    nop
    ld a, a
    and d
    call z, $cec9
    set 1, c
    adc $c7
    ld a, a
    rst $08
    adc $c5
    add a
    db $d3
    ld a, a
    push bc
    ld c, a
    reti


    push bc
    db $d3
    ld a, a
    rst $10
    ret


    call nc, Call_026_7fc8
    pop bc
    db $d3
    call nc, $cecf
    ret


    db $d3
    ret z

    ld d, l
    call $cec5
    call nc, Call_026_7f8e
    ld e, b
    nop
    ld a, a
    xor b
    ret


    adc h
    ld d, [hl]
    adc h
    ld a, a
    call z, $cfcf
    res 0, c
    ld a, a
    or h
    ret z

    ret


    ld c, a
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call Call_026_7fd9
    ld d, h
    add c
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    add $7f
    jp $ccd5


    call nc, $d6c9
    pop bc
    call nc, $55c5
    call nz, $c77f
    jp nc, $d3c1

    db $d3
    adc [hl]
    ld a, a
    sub $c5
    jp nc, Jump_026_7fd9

    push bc
    pop bc
    db $d3
    ld d, l
    reti


    adc h
    ld a, a
    sub $c5
    jp nc, Jump_026_7fd9

    rst $00
    rst $08
    rst $08
    call nz, Call_026_7f8e
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
    push de
    db $d3
    push bc
    call nz, $c27f
    reti


    ld c, a
    ld a, a
    rst $08
    push de
    jp nc, $c77f

    reti


    call $c17f
    jp nc, Jump_026_7fc5

    pop bc
    call z, Call_026_7fcc
    ld d, l
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    call nc, $d0d9
    push bc
    add c
    ld a, a
    db $d3
    ret


    adc $c3
    push bc
    ld d, l
    ld a, a
    push bc
    ret c

    jp $d0c5


    call nc, Call_026_547f
    adc h
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ld d, l
    jp nc, $ced5

    ld a, a
    pop bc
    adc $cf
    call nc, $c5c8
    jp nc, $c37f

    call z, $d3c1
    db $d3
    ld d, l
    jp nc, $cfcf

    call $d47f
    push bc
    pop bc
    jp $c9c8


    adc $c7
    ld a, a
    ret z

    push de
    pop bc
    ld d, l
    call nz, Call_026_7fcf
    ld d, a
    nop
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_026_7f81
    ld e, b
    nop
    ld a, a
    jp nz, $d2cf

    push bc

Call_026_5581:
    call nz, Call_026_7f81
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a

Jump_026_558c:
    ret


    adc $d3
    push bc
    jp Jump_026_7fd4


    ld d, h
    ld a, a
    ld c, a
    adc h
    ld a, a
    add $c9
    jp nc, Jump_026_7fc5

    ld d, h
    adc h
    xor c
    add a
    call $d67f
    push bc
    ld d, l
    jp nc, Jump_026_7fd9

    jp nz, $d2cf

    push bc
    call nz, $cf7f
    add $7f
    adc [hl]
    ld a, a
    and h
    rst $08
    adc $55
    add a
    call nc, $c27f
    jp nc, $cec9

    rst $00
    ld a, a

Call_026_55c1:
Jump_026_55c1:
    call nc, $c5c8
    call $c87f
    push bc

Call_026_55c8:
Jump_026_55c8:
    jp nc, $c555

    add c

Call_026_55cc:
    ld a, a

Call_026_55cd:
    ld d, a
    nop

Call_026_55cf:
Jump_026_55cf:
    ld a, a
    reti


    rst $08

Call_026_55d2:
Jump_026_55d2:
    push de

Call_026_55d3:
    add c

Jump_026_55d4:
    ld a, a

Jump_026_55d5:
    or h
    ret z

    push bc
    ld a, a

Call_026_55d9:
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $4f
    ld a, a
    and c
    call z, $c9cc
    jp $c97f


    db $d3
    ld a, a
    pop bc
    ld a, a
    add $c1
    call $d5cf
    ld d, l
    db $d3
    ld a, a
    ld e, l
    ld a, a
    pop bc
    call $cecf
    rst $00
    ld a, a
    call nc, $c855
    ret


    db $d3
    ld a, a
    pop bc
    jp nc, $c1c5

    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    reti


    ld d, l
    rst $08
    push de
    jp nc, $c77f

    rst $08
    ret


    adc $c7
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $d47f
    ld d, l
    ret z

    ret


    adc $c7
    db $d3
    ld a, a
    db $d3
    call nc, $c1c5
    call nz, $ccc9
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    add c
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    add c
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c97f

    adc $d4
    push bc
    jp nc, $d3c5

    call nc, $c97f
    db $d3
    ld c, a
    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    reti


    push bc
    db $d3
    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    ld a, a

Call_026_567f:
    db $d3
    ld d, l
    call z, $c7c9
    ret z

    call nc, $d9cc
    ld a, a
    ret


    adc $d4
    push bc
    jp nc, $d3c5

    call nc, $557f
    ret


    adc $7f
    ld d, h
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    push bc
    ret c

    call nc, $d77f
    push bc
    push bc
    res 1, h
    ld a, a
    xor c
    add a
    call z, Call_026_7fcc
    ld c, a
    call nc, $cbc1
    push bc
    ld a, a
    pop bc
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    call nc, $cd7f
    reti


    ld d, l
    ld a, a
    ret nc

    jp nc, $d3cf

    ret nc

    push bc
    jp $c9d4


    sub $c5
    ld a, a
    ret nc

    pop bc
    jp nc, $55c5

    adc $d4
    db $d3
    adc l
    ret


    adc $8d
    call z, $d7c1
    adc [hl]
    ld a, a
    xor c
    ld a, a
    jp $cec1


    ld d, l
    add a
    call nc, $c77f
    ret


    sub $c5
    ld a, a
    ret


    call nc, $d57f
    ret nc

    ld a, a
    ret z

    pop bc
    call z, $c655
    ld a, a
    rst $10
    pop bc
    reti


    ld a, a
    ld a, a
    push bc
    sub $c5
    adc $7f
    ret


    adc $d6
    ret


    call nc, $c555
    call nz, $c27f
    reti


    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    xor c
    ld a, a
    call $d3d5
    call nc, Call_026_7f55
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, Call_026_7fcf
    jp nc, $c6c5

    push de
    db $d3
    push bc
    ld a, a
    call nc, $cf55
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $8ec5
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_026_7fcc
    ret


    db $d3
    ld a, a
    push bc
    ret c

    pop bc
    ld c, a
    jp $ccd4


    reti


    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $817f
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_026_7fcc
    ret


    db $d3
    ld a, a
    push bc
    ret c

    pop bc
    ld c, a
    jp $ccd4


    reti


    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $817f
    ld a, a
    ld e, b
    nop
    ld a, a
    rst $10
    push bc
    call z, $cfc3
    call Call_026_7fc5

Call_026_577f:
    call nc, Call_026_7fcf
    call z, $c7c9
    ret z

    call nc, $ce4f
    ret


    adc $c7
    ld a, a
    jp $d4c9


    reti


    ld a, a
    rst $00
    reti


    call Call_026_7f81
    reti


    rst $08
    ld d, l
    push de
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $ce7f

    rst $08
    call nc, $c27f
    push bc
    ld d, l
    ld a, a
    adc $c5
    rst $00
    call z, $c7c9
    push bc
    adc $d4
    ld a, a
    call nz, $cecf
    add a
    call nc, $557f
    call nc, $c9c8
    adc $cb
    ld a, a
    call nc, $c5c8
    reti


    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    rst $00
    ret


    ld d, l
    jp nc, $d3cc

    adc h
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    rst $08
    call nz, $d9c1
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld c, a
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    adc $87
    call nc, $c27f
    jp nc, $d5cf

    ld d, l
    rst $00
    ret z

    call nc, Call_026_7f8c
    db $d3
    rst $08
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    db $d3
    push de
    jp nc, $ccc5

    ld d, l
    reti


    ld a, a
    jp $cec1


    add a
    call nc, $c47f
    push bc
    add $c5
    pop bc
    call nc, $ce7f
    push bc
    ld d, l
    ret c

    call nc, $c37f
    rst $08
    adc $d4
    push bc
    db $d3
    call nc, $cec9
    rst $00
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    rst $10
    push bc
    call z, Call_026_4fcc
    ld a, a
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
    call nz, $cecf
    push bc
    ld a, a
    rst $10
    push bc
    call z, Call_026_4fcc
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_026_7fc5
    add c
    ld a, a
    or l
    db $d3
    push bc
    ld a, a
    call nc, $4fc8
    push bc
    ld a, a
    jp $c9cf


    adc $d3
    ld a, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret


    adc $7f
    ld d, l
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    call nc, Call_026_7fcf
    push bc
    ret c

    ld d, l
    jp $c1c8


    adc $c7
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    ret


    add $d4
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    push bc
    ret c

    ld d, l
    jp $c1c8


    adc $c7
    ret


    adc $c7
    ld a, a
    call nz, $d3c5
    bit 7, a
    rst $08
    push de
    call nc, $d355
    ret


    call nz, Call_026_7fc5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, Call_026_7f4f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $d3c4

    ld a, a
    rst $10
    push bc
    ld a, a
    db $d3
    pop bc
    reti


    ld d, l
    ld a, a
    ret z

    push bc
    jp nc, Jump_026_7fc5

    ld d, [hl]
    and c
    call z, Call_026_7fcc
    call nc, $c5c8
    ld a, a
    ret nc

    ld d, l
    push bc
    rst $08
    ret nc

    call z, Call_026_7fc5
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    db $d3
    ret nc

    jp nc, $c555

    pop bc
    call nz, $cec9
    rst $00
    ld a, a
    ld d, [hl]
    call nc, $c1c8
    call nc, $d47f
    ret z

    ret


    ld d, l
    db $d3
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    reti


    pop bc
    jp nc, Jump_026_7fc4

    ld a, a
    jp nz, $ccc5

    rst $08
    ld d, l
    adc $c7
    db $d3
    ld a, a
    call nc, Call_026_7fcf
    ld d, [hl]
    ld a, a
    ld a, a
    rst $08
    add $7f
    adc [hl]
    ld a, a
    ld d, a
    ld d, l
    ld e, [hl]
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, $c17f

    jp nc, Jump_026_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    jp $4fcf


    ret


    adc $7f
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    call nc, $d2c8
    rst $08
    rst $10
    ret


    ld d, l
    adc $c7
    ld a, a
    ld a, a
    push de
    ret nc

    ld a, a
    pop bc
    call nc, $c47f
    ret


    add $c6
    push bc
    jp nc, $55c5

    adc $d4
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    ret


    adc $d4
    push bc
    jp nc, $d3c5

    call nc, $cec9
    rst $00
    ld c, a
    ld a, a
    call nc, Call_026_7fcf
    ret nc

    call z, $d9c1
    ld a, a
    jp $c9cf


    adc $7f
    rst $00
    pop bc
    call $c555
    add c
    ld a, a
    xor c
    ld a, a
    push bc
    sub $c5
    adc $7f
    add $cf
    jp nc, $c5c7

    call nc, $557f
    call nc, $c5c8
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or b
    call z, $d9c1
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $d2c5
    jp nc, Jump_026_4fc9

    add $c9
    jp $a981


    add a
    call $ca7f
    push de
    db $d3
    call nc, $c37f
    rst $08
    call $55c9
    adc $c7
    ld a, a
    add $cf
    jp nc, $c17f

    ld a, a
    jp nc, $d3c5

    call nc, $8c7f
    ld a, a
    xor c
    ld d, l
    call nc, $c57f
    ret c

    jp $c5c5


    call nz, Call_026_7fd3
    call Call_026_7fd9
    push bc
    ret c

    ret nc

    push bc
    ld d, l
    jp $c1d4


    call nc, $cfc9
    adc $d3
    ld a, a
    call nc, $c1c8
    call nc, $a97f
    add a
    call Call_026_7f55
    db $d3
    rst $08
    ld a, a
    jp $d0c1


    call nc, $d6c9
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and a
    rst $08
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    pop bc
    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld c, a
    ld e, [hl]
    ld a, a
    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    jp $d255


    push bc
    call nc, $d47f
    jp nc, $c3c9

    bit 7, a
    ld a, a
    rst $10
    ret


    call z, Call_026_7fcc
    jp nz, $c555

    ld a, a
    push bc
    ret c

    ret nc

    rst $08
    db $d3
    push bc
    call nz, $cf7f
    push de
    call nc, $c97f
    add $7f
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $d17f
    push de
    ret


    jp $cccb


    reti


    ld d, l
    ld a, a
    jp $cecf


    call nc, $c3c1
    call nc, $d77f
    ret


    call nc, Call_026_7fc8
    call nc, $c5c8
    ld d, l
    ld a, a
    jp nz, $d3cf

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
    ret nc

    jp nc, $d0cf

    ld a, a
    ld a, a
    call nc, Call_026_7fcf
    db $d3
    ret z

    pop bc
    ld c, a
    jp nc, $c5d0

    adc $7f
    ld d, h
    add a
    db $d3
    ld a, a
    pop bc
    jp nz, $ccc9

    ret


    call nc, $d955
    ld a, a
    jp $cec1


    ld a, a
    jp nz, $d9d5

    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    adc [hl]
    ret z

    ld d, l
    push bc
    jp nc, Jump_026_7fc5

    xor c
    call nc, $c37f
    pop bc
    adc $7f
    push bc
    adc $c8
    pop bc
    adc $c3
    ld d, l
    push bc
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c17f
    jp nz, $ccc9

    ret


    call nc, Call_026_55d9
    adc h
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    ret z

    pop bc
    jp nc, $c5d0

    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    pop bc
    rst $00
    ret


    call z, $d3c5
    ld a, a
    adc [hl]
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
    jp nz, $d9d5

    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    ld c, a
    jp nc, $d0cf

    ld a, a
    call nc, Call_026_7fcf
    db $d3
    ret z

    pop bc
    jp nc, $c5d0

    adc $7f
    ld d, l
    ld d, h
    add a
    db $d3
    ld a, a
    pop bc
    jp nz, $ccc9

    ret


    call nc, Call_026_7fd9
    sbc a
    ld a, a
    call nc, $cf55
    ld a, a
    push bc
    adc $c8
    pop bc
    adc $c3
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    add $cf
    jp nc, $c355

    push bc
    ld a, a
    rst $08
    add $7f
    pop bc
    call nc, $c1d4
    jp $81cb


    ld a, a
    and d
    jp nc, Jump_026_55cf

    call $cec9
    push bc
    ld a, a
    ld a, a
    and d
    jp nc, Jump_026_7f7f

    jp $cec1


    ld a, a
    ret


    adc $c3
    ld d, l
    jp nc, $c1c5

    db $d3
    push bc
    ld a, a
    call nz, $c6c5
    push bc
    adc $d3
    ret


    sub $c5
    ld a, a
    pop bc
    ld d, l
    jp nz, $ccc9

    ret


    call nc, $81d9
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $cf
    push de
    jp nc, $c8d4

    ld a, a
    add $cc
    rst $08
    rst $08
    jp nc, Jump_026_7f4f

    ld d, [hl]
    adc h
    ld a, a
    pop bc
    adc $c1
    push bc
    db $d3
    call nc, $c5c8
    call nc, $c3c9
    ld a, a
    ld d, l
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    ld d, a
    nop
    xor b
    add a
    call Call_026_7f8c
    ld d, [hl]
    add c
    ld a, a
    and [hl]
    ret


    adc $c4
    ld a, a
    pop bc
    ld a, a
    call $c54f
    call nc, $cfc8
    call nz, $8e7f
    ld a, a
    call z, $cecf
    rst $00
    db $d3
    ld a, a
    call nc, Call_026_7fcf
    ld d, l
    rst $08
    rst $10
    adc $7f
    call nc, $c1c8
    call nc, $a77f
    ret z

    rst $08
    db $d3
    call nc, $a27f
    rst $08
    ld d, l
    call z, $81d9
    ld a, a
    jp nz, $d4d5

    ld a, a
    ret


    call nc, $d387
    ld a, a
    call nz, $c6c9
    add $55
    ret


    jp $ccd5


    call nc, $d47f
    rst $08
    ld a, a
    rst $10
    ret


    adc $7f
    ret


    adc $7f
    call nc, $c855
    push bc
    ld a, a
    jp $c9cf


    adc $8d
    call nz, $cfd2
    ret nc

    ld a, a
    rst $00
    pop bc
    call $55c5
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    adc h
    ret z

    pop bc
    add c
    ld a, a
    or b
    jp nc, $c6cf

    ret


    call nc, $8c4f
    ld a, a
    ret nc

    jp nc, $c6cf

    ret


    call nc, Call_026_7f8c
    ld d, [hl]
    add c
    ld a, a
    xor c
    call nc, $557f
    db $d3
    ret z

    rst $08
    push de
    call z, Call_026_7fc4
    jp nz, Jump_026_7fc5

    push bc
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    ld d, l
    rst $00
    rst $08
    rst $08
    call nz, $c97f
    add $7f
    push bc
    pop bc
    jp Jump_026_7fc8


    call nz, $d9c1
    ld a, a
    ld d, l
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    rst $08
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call $8cc5
    ld a, a
    rst $10
    push bc
    call z, $cfc3
    call $4fc5
    add c
    ld a, a
    and c
    call z, Call_026_7fcc
    pop bc
    jp nc, Jump_026_7fc5

    call nc, $c5c8
    ld a, a
    rst $00
    push de
    push bc
    ld d, l
    db $d3
    call nc, Call_026_7fd3
    rst $10
    ret z

    rst $08
    ld a, a
    sub $c9
    db $d3
    ret


    call nc, $d17f
    push de
    ret


    ld d, l
    call nc, Call_026_7fc5
    rst $08
    add $d4
    push bc
    adc $8c
    ld a, a
    xor c
    add a
    call $c17f
    jp Jump_026_55d4


    push de
    pop bc
    call z, $d9cc
    ld a, a
    push bc
    call $c1c2
    jp nc, $c1d2

    db $d3
    db $d3
    push bc
    call nz, $8155
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
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_026_7fcf
    ld c, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    jp nz, $d9d5

    ret


    adc $c7
    ld a, a
    db $d3
    ld d, l
    rst $08
    call Call_026_7fc5
    call $c4c5
    ret


    jp $cec9


    push bc
    ld a, a
    add $cf
    jp nc, $557f

    call Call_026_7fd9
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, Call_026_547f
    ld d, l
    ld d, [hl]
    call nc, Call_026_7fcf
    push bc
    adc $c8
    pop bc
    adc $c3
    push bc
    ld a, a
    ret


    call nc, Call_026_7fd3
    ld d, l
    add $cf
    jp nc, $c5c3

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    ret nc

    push bc
    pop bc
    bit 7, a
    pop de
    push de
    ret


    push bc
    call nc, $d9cc
    ld a, a
    ld c, a
    ld d, [hl]
    adc h
    ld a, a
    push bc
    adc $c7
    push de
    call z, Call_026_7fc6
    ld d, [hl]
    xor c
    call nc, $cc7f
    ld d, l
    rst $08
    rst $08
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, $c5c8
    jp nc, Jump_026_7fc5

    ret


    ld d, l
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nz, $d3c1

    push bc
    call $cec5
    call nc, Call_026_567f
    push de
    adc $55
    call nz, $d2c5
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    jp $d2cf


    adc $55
    push bc
    jp nc, $8e7f

    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    and e
    ret z

    push bc
    rst $10
    ret


    adc $c7
    ld a, a
    ret nc

    jp nc, $d5cf

    call nz, $d9cc
    ld a, a
    ld c, a
    ld d, [hl]
    add c
    ld a, a
    or h
    ret z

    pop bc
    call nc, $cf7f
    call z, $cdc4
    pop bc
    adc $7f
    db $d3
    ld d, l
    ret


    call nc, $c27f
    reti


    ld a, a
    call nc, $c1c8
    call nc, $d47f
    pop bc
    jp nz, $c5cc

    ld a, a
    ld d, l
    push de
    db $d3
    push bc
    call nz, $d57f
    ret nc

    ld a, a
    pop bc
    call z, Call_026_7fcc
    ret z

    ret


    db $d3
    ld a, a
    call $cf55
    adc $c5
    reti


    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp $c9cf


    adc $55
    adc l
    call nz, $cfd2
    ret nc

    ld a, a
    rst $00
    pop bc
    call $81c5
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
    ld d, [hl]
    add c
    ld a, a
    or h
    ret z

    push bc
    ld c, a
    ld a, a
    jp $c9cf


    adc $8d
    call nz, $cfd2
    ret nc

    ld a, a
    rst $00
    pop bc
    call Call_026_7fc5
    ret


    ld d, l
    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    ret nc

    jp nc, $d3cf

    ret nc

    push bc
    jp nc, $d5cf

    db $d3
    add c
    ld a, a
    ld d, l
    xor l
    pop bc
    set 1, c
    adc $c7
    ld a, a
    call $cecf
    push bc
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    rst $08
    ld a, a
    ret


    adc $7f
    jp $c1c8


    jp nc, $c5c7

    add c
    ld a, a
    or h
    ld c, a
    rst $08
    call nz, $d9c1
    add a
    db $d3
    ld a, a
    call nc, $d2d5
    adc $cf
    sub $c5
    jp nc, $cf7f

    ld d, l
    add $7f
    jp $c9cf


    adc $8d
    call nz, $cfd2
    ret nc

    ld a, a
    jp nz, $d9d5

    ld a, a
    sub d
    ld d, l
    sub b
    sub b
    sub b
    ret nc

    ld a, a
    ld d, h
    ld a, a
    ret


    adc $8c
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld d, l
    ld a, a
    push bc
    pop bc
    jp nc, $c5ce

    call nz, Call_026_7f81
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d47f
    rst $08
    push de
    jp Jump_026_7fc8


    call nc, $c5c8
    ld a, a
    ld c, a
    ret nc

    jp nc, $d0cf

    pop bc
    rst $00
    pop bc
    adc $c4
    pop bc
    ld a, a
    ret nc

    push de
    call nc, $d57f
    ret nc

    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    jp $d2cf


    adc $55
    push bc
    jp nc, Jump_026_7f81

    xor [hl]
    rst $08
    call nc, $c17f
    call nc, $c17f
    call z, Call_026_7fcc
    ret z

    pop bc
    ld d, l
    sub $c9
    adc $c7
    ld a, a
    ret z

    ret


    call nz, $c4c5
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $10
    ld d, l
    ret


    call nc, $c8c3
    ld a, a
    ld a, a
    jp nz, $c8c5

    ret


    adc $c4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld d, h
    ld d, [hl]
    sbc a
    ld a, a
    and c
    ret z

    adc h
    ld d, [hl]
    add c
    ld c, a
    ld a, a
    xor b
    push bc
    jp nc, Jump_026_7fc5

    ld a, a
    ret


    db $d3
    ld a, a
    ret z

    rst $08
    call nc, $ccc5
    ld a, a
    add $55
    rst $08
    jp nc, $d07f

    push bc
    rst $08
    ret nc

    call z, Call_026_7fc5
    call nc, Call_026_7fcf
    ret z

    rst $08
    push de
    db $d3
    ld d, l
    push bc
    ld a, a
    adc [hl]
    ld a, a
    and c
    call nc, $c17f
    ld a, a
    call z, $d3c5
    call nc, $cf7f
    ret nc

    ret nc

    ld d, l
    rst $08
    jp nc, $d5d4

    adc $c5
    ld a, a
    call $cdcf
    push bc
    adc $d4
    adc h
    ld a, a
    add $d5
    ld d, l
    call z, Call_026_7fcc
    ret z

    rst $08
    push de
    db $d3
    push bc
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_026_7f8c

    call Call_026_7fd9
    jp nz, $cf4f

    reti


    add $d2
    ret


    push bc
    adc $c4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    xor c
    add c
    ld a, a
    or a
    ld d, l
    push bc
    ld a, a
    call nc, $d2c8
    push bc
    push bc
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    call nc, Call_026_7fcf
    call nc, $d255
    pop bc
    sub $c5
    call z, Call_026_7f81
    xor h
    ret


    rst $00
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    ld d, l
    jp $d4c9


    reti


    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    sub $c5
    jp nc, Jump_026_7fd9

    jp nz, $c555

    pop bc
    push de
    call nc, $c6c9
    push de
    call z, $d47f
    rst $08
    rst $10
    adc $8e
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    ld a, a
    ld d, [hl]
    sbc a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_026_4fc4
    ld a, a
    jp nz, Jump_026_7fc5

    pop bc
    ld a, a
    jp z, $d5cf

    jp nc, $c5ce

    reti


    ld a, a
    rst $10
    ret


    call nc, $c855
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    ret


    jp nc, $c6cc

    jp nc, $c5c9

    adc $c4
    ld a, a
    ld d, l
    pop bc
    call z, $cecf
    push bc
    adc [hl]
    ld a, a
    jp nz, $d4d5

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp $cccf


    call z, $c7c5
    push de
    push bc
    db $d3
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    rst $08
    add $7f
    ld e, [hl]
    ld a, a
    jp $cec1


    ld d, l
    ld a, a
    call nz, Call_026_7fcf
    pop bc
    adc $d9
    ld a, a
    push bc
    sub $c9
    call z, $c47f
    push bc
    push bc
    call nz, Call_026_7f55
    add $cf
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    call $cecf
    push bc
    reti


    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    call nc, $c5c8
    jp nc, $d77f

    pop bc
    db $d3
    ld a, a
    jp $d5c8


    jp Jump_026_4fcb


    call z, $cec9
    rst $00
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_026_7fc5
    add $cc
    push bc
    call nz, $c67f
    ld d, l
    jp nc, $cdcf

    ld a, a
    ld e, [hl]
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, Call_026_55d3
    rst $08
    ld a, a
    db $d3
    pop bc
    rst $10
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    set 1, c
    call z, $cc55
    push bc
    call nz, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    add $cc
    push bc
    push bc
    ret


    adc $55
    rst $00
    ld a, a
    jp nc, $c1cf

    call nz, Call_026_577f
    adc [hl]
    ld a, a
    nop
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    call nc, $d7cf
    push bc
    jp nc, Jump_026_7f7f

    rst $10
    pop bc
    db $d3
    ld a, a
    ld c, a
    jp nz, $c9d5

    call z, Call_026_7fd4
    call nc, Call_026_7fcf
    jp $cecf


    db $d3
    rst $08
    call z, Call_026_7fc5
    ld d, l
    call nc, $c5c8
    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    db $d3
    ld a, a
    rst $08
    add $7f
    call nc, Call_026_55c8
    push bc
    ld a, a
    call nz, $c1c5
    call nz, Call_026_547f
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ret nc

    pop bc
    reti


    ld c, a
    ld a, a
    jp nc, $d3c5

    ret nc

    push bc
    jp $d3d4


    ld a, a
    call nc, Call_026_7fcf
    pop bc
    ld a, a
    call nz, $55c5
    pop bc
    call nz, $d07f
    push bc
    jp nc, $cfd3

    adc $7f
    pop bc
    call nc, $c87f
    ret


    db $d3
    ld a, a
    ld d, l
    call nc, $cdcf
    jp nz, Jump_026_7f9f

    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    adc $c5
    sub $c5
    jp nc, $c67f

    rst $08
    jp nc, $c5c7

    call nc, Call_026_4f7f
    ld d, [hl]
    ld a, a
    call nz, $c1c5
    call nz, $b07f
    ret


    ret nc

    ret


    ld a, a
    add c
    ld a, a
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld a, a
    call nc, $c1c5
    ld d, l
    jp nc, Jump_026_7fd3

    call nz, $cfd2
    ret nc

    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    or a
    ret z

    reti


    ld a, a
    call Call_026_7fd9
    reti


    pop bc
    call nz, Call_026_7fd9
    ld c, a
    ld d, [hl]
    ld a, a
    ld a, a
    call nz, $c5c9
    call nz, Call_026_7f9f
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    ret nc

    jp nc, $c5c9

    db $d3
    call nc, Call_026_7f81
    xor c
    ld a, a
    ld c, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    add $c5
    push bc
    call z, $d47f
    ret z

    pop bc
    call nc, $557f
    pop bc
    ld a, a
    rst $10
    pop bc
    reti


    adc l
    call z, $d3cf
    ret


    adc $c7
    ld a, a
    db $d3
    rst $08
    push de
    call z, Call_026_7f55
    ret


    db $d3
    ld a, a
    ret z

    rst $08
    sub $c5
    jp nc, $cec9

    rst $00
    ld a, a
    pop bc
    jp nz, $d6cf

    ld d, l
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $d0cf
    ld a, a
    adc [hl]
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
    call nc, Call_026_4f7f
    call nc, $c5c8
    jp nc, Jump_026_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    ret


    adc $d4
    push bc
    call z, $cc55
    ret


    rst $00
    push bc
    adc $d4
    ld a, a
    pop bc
    adc $c9
    call $ccc1
    ld a, a
    call z, $d6c9
    ld d, l
    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ld d, l
    ret


    adc $7f
    rst $08
    jp nc, $c97f

    adc $7f
    call nc, $c5c8
    ld a, a
    call z, $cbc1
    push bc
    ld d, l
    add c
    ld a, a
    and l
    sub $c5
    adc $7f
    rst $10
    push bc
    ld a, a
    jp $cec1


    add a
    call nc, $d37f
    ld d, l
    push bc
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    add $c1
    jp Jump_026_7fc5


    ld d, l
    ld d, [hl]
    ld a, a
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, $557f
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c1cf

    call $cec9
    rst $00
    ld a, a
    ld a, a
    add c
    ld d, l
    xor c
    call nc, $d77f
    rst $08
    push de
    call z, Call_026_7fc4
    jp nz, Jump_026_7fc5

    db $d3
    push bc
    push bc
    adc $7f
    ld d, l
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    jp nz, Jump_026_7fd9

    db $d3
    ld d, l
    ret


    call z, $d5cc
    add $c6
    ld a, a
    xor a
    jp nz, $c5d3

    jp nc, $c1d6

    call nc, $d2cf
    ld d, l
    ld a, a
    ret


    add $7f
    call nc, $c5c8
    jp nc, Jump_026_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    ret nc

    ld d, l
    push bc
    jp $c1c9


    call z, $d07f
    jp nc, $d0cf

    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    jp $c9c8


    jp nc, Jump_026_7fd0

    ld a, a
    ld d, [hl]
    ld c, a
    ld d, [hl]
    ld a, a
    and e
    rst $08
    rst $08
    adc h
    jp $cfcf


    adc h
    jp $cfcf


    adc h
    ld d, l
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    ret


    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    db $d3
    ret


    call z, $d5cc
    add $4f
    add $7f
    xor a
    jp nz, $c5d3

    jp nc, $c1d6

    call nc, $d2cf
    ld a, a
    adc h
    ld a, a
    ret


    call nc, Call_026_7f55
    jp $d5cf


    call z, Call_026_7fc4
    db $d3
    push bc
    push bc
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ld d, l
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    add $c1
    jp Jump_026_7fc5


    ld d, l
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, Call_026_547f
    adc [hl]
    ld d, l
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
    call nc, $d4c1
    push bc
    call $c555
    adc $d4
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    call $c3d5
    ret z

    ld a, a
    ret z

    push bc
    call z, $d04f
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    call $c3d5
    ret z

    ld a, a
    ret z

    push bc
    call z, $d04f
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, [hl]
    ld a, a
    call z, $d5c1
    rst $00
    ret z

    ld c, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    rst $08
    jp nc, $d9d2

    add c
    ld a, a
    xor c
    call nc, $c37f
    jp nc, $c1c5

    call nc, $4fc5
    db $d3
    ld a, a
    jp $cecf


    add $d5
    db $d3
    ret


    rst $08
    adc $7f
    jp nz, $c9c5

    adc $c7
    ld d, l
    ld a, a
    ret nc

    push bc
    db $d3
    call nc, $d2c5
    push bc
    call nz, $c27f
    reti


    ld a, a
    call nz, $cdc5
    rst $08
    ld d, l
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor a
    ret z

    sbc a
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    call $a97f
    ld c, a
    ld a, a
    call nz, $c9cf
    adc $c7
    ld a, a
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor a
    ret z

    sbc a
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    call $a97f
    ld c, a
    ld a, a
    call nz, $c9cf
    adc $c7
    ld a, a
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nz, $cdc5
    rst $08
    adc $81
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    pop bc
    ld c, a
    ret z

    add c
    ld a, a
    ret z

    push bc
    reti


    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    and c
    ret z

    ld a, a
    pop bc
    ret z

    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp $cccf


    call z, $c7c5
    push de
    push bc
    db $d3
    ld a, a
    pop bc
    jp nz, $cf4f

    sub $c5
    ld a, a
    db $d3
    push bc
    push bc
    call $c27f
    push bc
    ret


    adc $c7
    ld a, a
    pop bc
    call nc, $d455
    pop bc
    jp $c5cb


    call nz, $c27f
    reti


    ld a, a
    call nz, $cdc5
    rst $08
    adc $8c
    ld a, a
    ld d, l
    call nc, $cfcf
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_026_7f81
    ld d, [hl]
    and h
    rst $08
    push bc
    db $d3
    ld a, a
    ld d, [hl]
    ld a, a
    call nz, $c54f
    call $cecf
    ld a, a
    add $cc
    push bc
    push bc
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_026_7f81
    ld d, [hl]
    and h
    rst $08
    push bc
    db $d3
    ld a, a
    ld d, [hl]
    ld a, a
    call nz, $c54f
    call $cecf
    ld a, a
    add $cc
    push bc
    push bc
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    and a
    ret z

    rst $08
    db $d3
    call nc, $c27f
    call z, $cbcf
    push bc
    ld a, a
    ld d, [hl]
    ld c, a
    ld d, [hl]
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_026_567f
    db $d3
    push bc
    push bc
    call Call_026_7fd3
    call z, $cbc9
    push bc
    ld c, a
    ld a, a
    pop bc
    ld a, a
    call nz, $c5d2
    pop bc
    call Call_026_7f8e
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    or a
    ret z

    push bc
    jp nc, $8cc5

    ld a, a
    rst $10
    ret z

    push bc
    jp nc, $4fc5

    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, Call_026_7f9f
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    or a
    ret z

    push bc
    jp nc, $8cc5

    ld a, a
    rst $10
    ret z

    push bc
    jp nc, $4fc5

    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, Call_026_7f9f
    ld e, b
    nop
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    jp $d2d5


    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, $d77f

    push bc
    ld a, a
    call nz, $8ccf
    ld a, a
    ld c, a
    rst $10
    push bc
    ld a, a
    jp $cec1


    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    rst $10
    ret z

    pop bc
    ld d, l
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_026_7f55

    rst $08
    add $7f
    rst $00
    ret z

    rst $08
    pop bc
    call nc, Call_026_7f7f
    ret


    db $d3
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_026_7f8c
    ret z

    add a
    call Call_026_7f8c
    ret z

    add a
    call Call_026_7f8c
    ld c, a
    ld d, [hl]
    add c
    ld a, a
    and e
    pop bc
    adc $7f
    ld d, [hl]
    ld a, a
    rst $10
    ret


    adc $9f
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_026_7f81
    rst $08
    add $7f
    ld d, h
    pop bc
    ld a, a
    jp nc, $c1cf

    ld c, a
    call $cec9
    rst $00
    ld a, a
    db $d3
    rst $08
    push de
    call z, Call_026_7f8c
    jp nc, $d3c5

    call nc, $c97f
    ld d, l
    adc $7f
    ret nc

    push bc
    pop bc
    jp $81c5


    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    add a
    call $a97f
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    add a
    call $a97f
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    ret z

    push bc
    jp nc, $81c5

    ld a, a
    xor b
    push bc
    jp nc, Jump_026_7fc5

    ld c, a
    ret nc

    push de
    call nc, $cf7f
    adc $7f
    db $d3
    rst $08
    call Call_026_7fc5
    jp nz, $cec1

    db $d3
    ld a, a
    ld d, l
    ld d, a
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp nc, $d3c5

    call nc, $c67f
    ret


    jp nc, $d4d3

    ld d, l
    adc h
    ld a, a
    call nc, $c5c8
    adc $7f
    rst $00
    rst $08
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    add $cf
    jp nc, $c24f

    ret


    call nz, $c5c4
    adc $7f
    pop bc
    jp nc, $c1c5

    ld a, a
    ret nc

    jp nc, $d3c5

    push bc
    ld d, l
    jp nc, $c5d6

    call nz, $c27f
    reti


    ld a, a
    db $d3
    pop bc
    jp $c5d2


    call nz, $d07f
    jp nc, $c155

    reti


    ret


    adc $c7
    ld a, a
    add c
    ld a, a
    ld d, d
    ld a, a
    pop bc
    adc $c4
    ld d, l
    ld a, a
    ld d, h
    adc h
    ld a, a
    jp nc, $d6c5

    ret


    sub $c5
    call nz, $c17f
    add $d4
    ld d, l
    push bc
    jp nc, $c17f

    ld a, a
    db $d3
    ret z

    rst $08
    jp nc, Jump_026_7fd4

    jp nc, $d3c5

    call nc, Call_026_7f81
    ld d, l
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    rst $08
    push de
    call z, Call_026_567f
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    ld c, a
    call Call_026_7fc5
    ret


    call nc, $c27f
    pop bc
    jp $81cb


    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ld d, [hl]
    pop bc
    call $c17f
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    ld c, a
    call nc, $d2c9
    push bc
    call nz, Call_026_7f8e
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_026_7fcf
    jp z, $cfc9

    adc $7f
    push de
    db $d3
    adc h
    ld a, a
    ld c, a
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
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    call nc, $d2c9
    push bc
    call nz, Call_026_7f8c
    jp nz, $d54f

    call nc, $a97f
    add a
    call $ce7f
    rst $08
    call nc, $568e
    ld d, a
    nop
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    call nc, Call_026_7f9f
    ld e, b
    nop
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    call nc, Call_026_7f9f
    ld e, b
    nop
    ld a, a
    xor l
    pop bc
    reti


    ld a, a
    jp nz, Jump_026_7fc5

    db $d3
    rst $08
    call Call_026_7fc5
    jp $d2c5


    call nc, $c14f
    ret


    adc $7f
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    jp nc, $d37f

    call nc, $d4c1
    ld d, l
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call $8c7f
    ld a, a
    jp nc, $d6c5

    ret


    sub $c5
    ld a, a
    call nc, Call_026_7fcf
    ld c, a
    call nc, $c5c8
    ld a, a
    adc $cf
    jp nc, $c1cd

    call z, Call_026_7f81
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    jp $d9d2


    ret


    adc $c7
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    adc $c4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    call nz, $d47f
    ret z

    push bc
    ld a, a
    ld c, a
    adc $c5
    jp nc, $c5d6

    ld a, a
    call nc, Call_026_7fcf
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld d, l
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    ld d, l
    call nc, Call_026_7fcf
    call z, $d3cf
    push bc
    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    jp nc, $c1c5

    call z, Call_026_55cc
    reti


    ld a, a
    call z, $d3cf
    ret


    adc $c7
    ld a, a
    add $c1
    jp $8ec5


    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    ret z

    pop bc
    set 1, c
    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    ret z

    pop bc
    set 1, c
    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    db $d3
    ret


    call nz, $81c5
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    rst $00
    rst $08
    ld a, a
    pop bc
    rst $10
    pop bc
    reti


    ld a, a
    add $d2
    rst $08
    call $c87f
    push bc
    jp nc, $55c5

    add c
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    jp nz, $cfcc

    rst $08
    call nz, $c58d
    add $c6
    ret


    jp $c5c9


    adc $d4
    ld a, a
    ld c, a
    db $d3
    call nc, $d4c1
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    add $c5
    push bc
    call z, $cecf
    rst $00
    ld a, a
    ld c, a
    pop bc
    ld a, a
    jp nz, $d4c9

    ld a, a
    call nz, $dac9
    jp c, $81d9

    ld a, a
    call $d9c1
    jp nz, $c555

    ld a, a
    pop bc
    adc $c1
    push bc
    call $c1c9
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    add a
    call $587f
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    add a
    call $587f
    nop
    ld a, a
    or h
    ret


    push bc
    ld a, a
    push de
    ret nc

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    push bc
    ret nc

    ld c, a
    push bc
    jp nc, $d4c1

    push bc
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    call Call_026_7fd9
    jp nz, Jump_026_55cf

    call nz, Call_026_7fd9
    ret


    db $d3
    adc $87
    call nc, $cd7f
    reti


    ld a, a
    ret z

    pop bc
    ret


    jp nc, $557f

    jp nz, $d4d5

    ld a, a
    call nz, $cdc5
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, Jump_026_7fc5

    db $d3
    rst $08
    call $4fc5
    call nc, $c9c8
    adc $c7
    ld a, a
    db $d3
    push bc
    ret nc

    push bc
    jp nc, $d4c1

    push bc
    call nz, $c67f
    ld d, l
    jp nc, $cdcf

    ld a, a
    call Call_026_7fd9
    jp nz, $c4cf

    reti


    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, Jump_026_7fc5

    db $d3
    rst $08
    call $4fc5
    call nc, $c9c8
    adc $c7
    ld a, a
    db $d3
    push bc
    ret nc

    push bc
    jp nc, $d4c1

    push bc
    call nz, $c67f
    ld d, l
    jp nc, $cdcf

    ld a, a
    call Call_026_7fd9
    jp nz, $c4cf

    reti


    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    add c
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    ret z

    rst $08
    rst $10
    adc h
    ret z

    rst $08
    rst $10
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    add c
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    ret z

    rst $08
    rst $10
    adc h
    ret z

    rst $08
    rst $10
    add c
    ld a, a
    ld d, a
    or a
    push bc
    call z, $8ccc
    ld d, l
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    call $a97f
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    jp $d9d2


    ret


    adc $c7
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp $d9d2


    ret


    adc $c7
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
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    reti


    rst $08
    push de
    ld c, a
    sbc a
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
    call nz, Call_026_7fcf
    ld d, l
    ret z

    push bc
    jp nc, $9fc5

    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $814f

    ld a, a
    ld d, a
    nop
    ld a, a
    pop bc
    call nz, $c9cd
    jp nc, $c4c5

    add c
    ld a, a
    nop
    ld a, a
    pop bc
    call nz, $c9cd
    jp nc, $c4c5

    add c
    ld a, a
    nop
    ld a, a
    and l
    sub $c5
    jp nc, Jump_026_7fd9

    call nc, $cdc9
    push bc
    ld a, a
    ret z

    push bc
    ld a, a
    jp $4fc1


    call Call_026_7fc5
    call nc, $c5c8
    ld a, a
    add $cf
    rst $08
    call nc, $cfc8
    call z, Call_026_7fc4
    rst $08
    ld d, l
    add $7f
    ld e, [hl]
    ld a, a
    adc h
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ld d, l
    rst $08
    call z, Call_026_7fc4
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    ld a, a
    pop bc
    call z, $c1d7
    reti


    ld d, l
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    pop bc
    call nc, $c47f
    rst $08
    adc $87
    call nc, Call_026_7f55
    jp nz, $ccd5

    call z, Call_026_7fd9
    ld d, h
    adc h
    ld a, a
    ld a, a
    call nz, $cecf
    add a
    ld d, l
    call nc, $cb7f
    ret


    call z, Call_026_7fcc
    ld d, h
    adc h
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    ld d, l
    rst $08
    ld a, a
    rst $08
    adc $8c
    ld a, a
    call $c3d5
    ret z

    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_026_5581
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    rst $10
    push bc
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    call nc, $ccc1
    set 1, c
    ld d, l
    adc $c7
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $c17f
    call nz, $ccd5
    call nc, $87d3
    ld a, a
    ld d, l
    jp $c1c8


    call nc, Call_026_7f81
    ld d, a
    nop
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $c17f
    ld a, a
    ret nc

    ld c, a
    jp nc, $d0cf

    ld a, a
    call nc, Call_026_7fcf
    call $cbc1
    push bc
    ld a, a
    jp nz, $d3d5

    ret


    adc $55
    push bc
    db $d3
    db $d3
    add c
    ld a, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $c87f
    ld d, l
    ret


    adc $c4
    push bc
    jp nc, $d57f

    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    ret nc

    pop bc
    jp nc, Jump_026_7fc5

    call Call_026_7fd9
    call z, $c6c9
    push bc
    adc h
    ld a, a
    ret nc

    ld c, a
    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    ret nc

    pop bc
    jp nc, Jump_026_7fc5

    call Call_026_7fd9
    call z, $c6c9
    push bc
    adc h
    ld a, a
    ret nc

    ld c, a
    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
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
    rst $10
    rst $08
    adc $87
    ld c, a
    call nc, $c27f
    push bc
    ld a, a
    db $d3
    pop bc
    sub $c5
    call nz, $d77f
    ret


    call nc, $cfc8
    push de
    ld d, l
    call nc, $c47f
    rst $08
    rst $10
    adc $7f
    rst $10
    ret


    call nc, Call_026_7fc8
    push de
    db $d3
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    and h
    rst $08
    adc $87
    call nc, Call_026_4f7f
    call nc, $c9c8
    adc $cb
    ld a, a
    call nc, $c1c8
    call nc, $d47f
    ret z

    pop bc
    call nc, $d387
    ld d, l
    ld a, a
    pop bc
    call z, Call_026_7fcc
    add $cf
    jp nc, $ce7f

    rst $08
    rst $10
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    rst $10
    push bc
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    jp nc, $d3c5

    ret


    db $d3
    call nc, $c54f
    call nz, $c17f
    rst $00
    pop bc
    ret


    adc $d3
    call nc, $c27f
    reti


    ld a, a
    ld d, l
    ld e, [hl]
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add $7f
    rst $10
    push bc
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    jp nc, $d3c5

    ret


    db $d3
    call nc, $c54f
    call nz, $c17f
    rst $00
    pop bc
    ret


    adc $d3
    call nc, $c27f
    reti


    ld a, a
    ld d, l
    ld e, [hl]
    ld a, a
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
    rst $10
    rst $08
    adc $7f
    pop bc
    ld a, a
    add $c9
    jp nc, $d34f

    call nc, $c38d
    call z, $d3c1
    db $d3
    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    add c
    ld a, a
    call $cf55
    adc $d4
    ret z

    call z, $8cd9
    ld a, a
    pop bc
    ld a, a
    rst $00
    push bc
    adc $c5
    jp nc, $d5cf

    ld d, l
    db $d3
    ld a, a
    rst $00
    ret


    add $d4
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    add $d2
    ld d, l
    ret


    push bc
    adc $c4
    add a
    db $d3
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp Jump_026_55c1


    call z, Call_026_7fcc
    add $cf
    jp nc, $c17f

    adc $d4
    jp nc, $c2c9

    push de
    call nc, $cfc9
    ld d, l
    adc $d3
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    adc [hl]
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    jp $c9cc


    ld d, l
    ret nc

    ret nc

    push bc
    call nz, Call_026_7f81
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $d2c9
    push bc
    jp $cfd4


    jp nc, $cf7f

    add $7f
    ld c, a
    ret z

    push de
    adc $d4
    ld a, a
    add [hl]
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c17f
    jp nc, $55c5

    pop bc
    ld a, a
    ret


    db $d3
    ld a, a
    sub $c9
    rst $00
    rst $08
    jp nc, $d5cf

    db $d3
    ld a, a
    call nc, $cfc8
    ld d, l
    push de
    rst $00
    ret z

    ld a, a
    sub $c5
    jp nc, Jump_026_7fd9

    rst $08
    call z, Call_026_7fc4
    jp nz, $d4d5

    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    call nc, $cfcf
    call nc, Call_026_7fc8
    rst $08
    add $7f
    ld d, [hl]
    ld a, a
    db $d3
    ld d, l
    push bc
    push bc
    call Call_026_7fd3
    call z, $cbc9
    push bc
    ld a, a
    add $c1
    call z, $c5d3
    ld a, a
    rst $08
    ld d, l
    adc $c5
    db $d3
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    reti


    pop bc
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    rst $08
    add $7f
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld d, l
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $ad7f
    pop bc
    jp nc, $c1d3

    jp $d9c8


    sbc a
    ld a, a
    ld d, l
    xor l
    pop bc
    jp nc, $c1d3

    jp $d9c8


    ld a, a
    ret


    db $d3
    ld a, a
    call Call_026_7fd9
    rst $00
    jp nc, $c155

    adc $c4
    db $d3
    rst $08
    adc $81
    ld a, a
    xor b
    push bc
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ld d, l
    db $d3
    push de
    jp Jump_026_7fc8


    jp nz, $d9cf

    ld a, a
    pop bc
    db $d3
    ld a, a
    call z, $d6cf
    ret


    adc $55
    rst $00
    ld a, a
    call nc, Call_026_7fcf
    jp $cccf


    call z, $c3c5
    call nc, $d77f
    ret z

    push bc
    adc $55
    ld a, a
    ret z

    push bc
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_026_7fd9

    reti


    rst $08
    push de
    adc $55
    rst $00
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    pop bc
    jp nc, $c1d3

    jp $d9c8


    add a
    db $d3
    ld a, a
    push bc
    call z, $c5c4
    jp nc, Jump_026_7f4f

    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_026_7f7f

    jp $c1c8


    adc $c7
    push bc
    call nz, Call_026_7f55
    call nc, $c5c8
    ld a, a
    jp $cccf


    call z, $c3c5
    call nc, $c4c5
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $d4c1
    ld d, l
    pop bc
    ld a, a
    rst $08
    add $7f
    ld e, e
    add c
    ld a, a
    and h
    rst $08
    push bc
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    ld d, l
    call z, $d4c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    ret


    call nc, $9f7f
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $cfd2
    ld c, a
    adc $c7
    ld a, a
    ld e, l
    ld a, a
    ret


    add $7f
    rst $08
    adc $cc
    ld d, l
    reti


    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    rst $08
    adc $c5
    ld a, a
    adc [hl]
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    set 0, l
    push bc
    ret nc

    ld a, a
    jp nz, Jump_026_55c1

    call z, $cec1
    jp Jump_026_7fc5


    pop bc
    call $cecf
    rst $00
    ld a, a
    call $cec1
    reti


    ld a, a
    ld d, l
    ld d, h
    ld a, a
    adc [hl]
    ld a, a
    jp nz, $d4d5

    adc h
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    sub $55
    push bc
    jp nc, Jump_026_7fd9

    ret z

    pop bc
    jp nc, Jump_026_7fc4

    call nc, Call_026_7fcf
    set 0, l
    push bc
    ret nc

    ld a, a
    ld d, l
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    ld a, a
    ret


    adc $7f
    jp nz, $ccc1

    ld d, l
    pop bc
    adc $c3
    push bc
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    pop bc
    reti


    jp nz, Jump_026_7fc5

    call nc, $c5c8
    jp nc, Jump_026_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld c, a
    ld a, a
    jp nc, $c1cf

    call nz, $d47f
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    push bc
    db $d3
    call nc, $c555
    jp nc, Jump_026_7fce

    rst $08
    add $7f
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    ld d, l
    jp $d4c9


    reti


    adc [hl]
    ld a, a
    and c
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call nz, $d0c5
    call nc, $c855
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, l
    ld d, h
    adc h
    ld a, a
    pop bc
    adc $7f
    rst $08
    jp nc, $c1c7

    adc $c9
    jp c, $d4c1

    ld d, l
    ret


    rst $08
    adc $7f
    call $c4c1
    push bc
    ld a, a
    rst $08
    add $7f
    pop bc
    call z, Call_026_7fcc
    ld d, l
    ld d, h
    adc h
    ld e, l
    ld a, a
    adc h
    ld a, a
    jp $cccf


    ld d, l
    call z, $c3c5
    call nc, $c4c5
    ld a, a
    jp nz, Jump_026_7fd9

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_026_7fc5
    call nc, Call_026_7fcf
    ret z

    push de
    adc $d4
    ld a, a
    ld c, a
    add [hl]
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c17f
    jp nc, $c1c5

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_026_7fc5
    call nc, Call_026_7fcf
    ret z

    push de
    adc $d4
    ld a, a
    ld c, a
    add [hl]
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c17f
    jp nc, $c1c5

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $c87f
    pop bc
    sub $c5
    ld a, a
    jp nz, $4fc5

    push bc
    adc $7f
    rst $10
    rst $08
    jp nc, $c9cb

    adc $c7
    ld a, a
    ret z

    pop bc
    jp nc, $81c4

    xor b
    ld d, l
    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $cd7f
    pop bc
    ld d, l
    adc $d9
    ld a, a
    ld d, h
    db $d3
    sbc a
    or a
    push bc
    call z, $cfc3
    call Call_026_7fc5
    call nc, $cf55
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    adc $c5
    ret c

    call nc, $d47f
    ret


    call $81c5
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    xor c
    ld a, a
    ret z

    pop bc
    call nz, $c17f
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    ld c, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    adc h
    call nc, $c5c8
    ld a, a
    call nz, $c6c5
    push bc
    adc $d3
    ld d, l
    ret


    sub $c5
    ld a, a
    pop bc
    jp nz, $ccc9

    ret


    call nc, Call_026_7fd9
    rst $08
    add $7f
    pop bc
    adc $55
    ret


    call $ccc1
    ld a, a
    ld d, h
    call $d9c1
    ld a, a
    jp nz, Jump_026_7fc5

    push bc
    adc $55
    ret z

    pop bc
    adc $c3
    push bc
    call nz, $a981
    call nc, $d387
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ld d, l
    push de
    db $d3
    push bc
    add $d5
    call z, $d47f
    ret z

    rst $08
    push de
    rst $00
    ret z

    ld a, a
    ret z

    pop bc
    sub $55
    ret


    adc $c7
    ld a, a
    adc $cf
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    ld d, l
    adc $7f
    add c
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
    add c
    ld d, l
    rst $00
    ret


    sub $c5
    ld a, a
    ret z

    ret


    call $d47f
    ret z

    ret


    db $d3
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
    jp nc, $c3c5

    push bc
    ret


    sub $4f
    push bc
    call nz, Call_026_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $a37f
    ret z

    ret


    reti


    pop bc
    rst $08
    ld a, a
    add c
    ld a, a
    ld d, b
    ld de, $b400
    ret z

    ld d, l
    push bc
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $cf7f
    add $7f
    db $d3
    set 1, c
    call z, Call_026_55cc
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    ld d, l
    ld e, h
    sub b
    sub [hl]
    ld a, a
    ret z

    ld d, l
    pop bc
    db $d3
    ld a, a
    ret z

    pop bc
    adc $c4
    push bc
    call nz, $c47f
    rst $08
    rst $10
    adc $7f
    ret


    adc $55
    ld a, a
    call Call_026_7fd9
    add $c1
    call $ccc9
    reti


    add $d2
    rst $08
    call $c77f
    push bc
    ld d, l
    adc $c5
    jp nc, $d4c1

    ret


    rst $08
    adc $7f
    call nc, Call_026_7fcf
    rst $00
    push bc
    adc $c5
    jp nc, $c155

    call nc, $cfc9
    adc $7f
    db $d3
    ret


    adc $c3
    push bc
    ld a, a
    sub h
    sub b
    sub b
    ld a, a
    reti


    ld d, l
    push bc
    pop bc
    jp nc, Jump_026_7fd3

    pop bc
    rst $00
    rst $08
    ld a, a
    adc [hl]
    and c
    call z, Call_026_7fcc
    call nc, $c5c8
    ld d, l
    ld a, a
    add $c5
    jp nc, $c3cf

    ret


    rst $08
    push de
    db $d3
    ld a, a
    rst $08
    adc $c5
    db $d3
    ld a, a
    ret z

    ld d, l
    pop bc
    call nz, $c27f
    push bc
    push bc
    adc $7f
    db $d3
    push bc
    pop bc
    call z, $c4c5
    add c
    ld a, a
    ld d, a
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
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor d
    push de
    db $d3
    call nc, $c27f
    push bc
    ret


    adc $c7
    ld a, a
    db $d3
    call nc, $cfd2
    adc $4f
    rst $00
    ld a, a
    ret


    db $d3
    adc $87
    call nc, $c67f
    push bc
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    add c
    ld d, l
    ld a, a
    ld d, [hl]
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4c1

    pop bc
    adc $c4
    sbc a
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    rst $10
    pop bc
    adc $d4
    db $d3
    ld a, a
    call nc, Call_026_7fcf
    call z, $c1c5
    jp nc, $ce55

    ld a, a
    pop bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_026_7fcc
    call nc, Call_026_7fcf
    jp $cdcf


    push bc
    ld d, l
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    rst $00
    reti


    call $817f
    ld a, a
    xor c
    add a
    call z, Call_026_7fcc
    ld d, l
    call nc, $c1c5
    jp Jump_026_7fc8


    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, Call_026_7fcc
    ld a, a
    pop bc
    db $d3
    ld d, l
    ld a, a
    db $d3
    rst $08
    ld a, a
    pop bc
    jp nz, $d4d3

    jp nc, $d3d5

    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld e, l
    ld a, a
    ld a, a
    rst $08
    add $7f
    jp nz, $d9cf

    add a
    ld c, a
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    call nc, $cdc5
    ret nc

    push bc
    jp nc, $c4c5

    adc h
    ld a, a
    adc $55
    rst $08
    call nc, $cf7f
    adc $cc
    reti


    ld a, a
    ret


    adc $7f
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, Jump_026_558c

    ld a, a
    jp nz, $d4d5

    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ret


    adc $7f
    db $d3
    set 1, c
    call z, $cc55
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor [hl]
    rst $08
    call nc, $c17f
    ld a, a
    jp $cdcf


    call $cecf
    ld c, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor [hl]
    rst $08
    call nc, $c17f
    ld a, a
    jp $cdcf


    call $cecf
    ld c, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    adc h
    ld a, a
    pop bc
    ld a, a
    call $c7c1
    ret


    jp $c1c9


    adc $7f
    adc h
    ld a, a
    ld c, a
    push bc
    adc $d4
    push bc
    jp nc, $c97f

    adc $d4
    rst $08
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    rst $00
    ld d, l
    reti


    call $c27f
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    call z, $cecf
    ld d, l
    rst $00
    ret


    adc $c7
    ld a, a
    call nc, Call_026_7fcf
    jp nz, Jump_026_7fc5

    pop bc
    ld a, a
    db $d3
    ret nc

    reti


    ld a, a
    ld d, l
    rst $10
    ret z

    rst $08
    ld a, a
    call $cbc1
    push bc
    db $d3
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $557f
    ret


    adc $d1
    push de
    ret


    jp nc, $c5c9

    db $d3
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and l
    sub $c5
    adc $7f
    call z, $d3cf
    ret


    adc $c7
    adc h
    ld a, a
    xor c
    ld a, a
    pop bc
    ld c, a
    call z, $cfd3
    ld a, a
    ret nc

    jp nc, $d0c5

    pop bc
    jp nc, Jump_026_7fc5

    call nc, Call_026_7fcf
    jp nc, $55c5

    db $d3
    ret


    db $d3
    call nc, $c67f
    rst $08
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    call nc, $c1c5
    jp $c855


    ret


    adc $c7
    ld a, a
    rst $08
    add $7f
    db $d3
    ret nc

    reti


    ld a, a
    ret nc

    jp nc, $d3c5

    ret


    ld d, l
    call nz, $cec5
    call nc, Call_026_7f7f
    and e
    ret z

    ret


    reti


    pop bc
    rst $08
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    jp nz, $c9c5

    adc $c7
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $4fc5
    call nz, Call_026_7f81
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    jp nz, $c9c5

    adc $c7
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $4fc5
    call nz, Call_026_7f81
    ld e, b
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
    push bc
    ret c

    ret nc

    push bc
    jp nc, $c5c9

    ld c, a
    adc $c3
    push bc
    call nz, $c17f
    call z, Call_026_7fcc
    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, $cc55
    db $d3
    ld a, a
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    add $7f
    call nc, $c5c8
    ld a, a
    rst $08
    jp nc, $c455

    ret


    adc $c1
    jp nc, Jump_026_7fd9

    rst $08
    add $7f
    call Call_026_7fd9
    ld d, h
    add c
    ld d, l
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
    call nz, Call_026_4fc9
    jp c, $d9da

    ld a, a
    push bc
    add $c6
    push bc
    jp Jump_026_7fd4


    ld a, a
    rst $08
    add $7f
    ret nc

    rst $08
    ld d, l
    ret


    db $d3
    rst $08
    adc $7f
    call $d9c1
    ld a, a
    jp nc, $cdc5

    pop bc
    ret


    adc $7f
    pop bc
    ld d, l
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    push bc
    sub $c5
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    add $c9
    rst $00
    ret z

    call nc, $c87f
    pop bc
    db $d3
    ld a, a
    push bc
    adc $c4
    push bc
    call nz, $8e7f
    ld d, l
    ld a, a
    xor c
    ld a, a
    call nz, Call_026_7fcf
    call z, $cbc9
    push bc
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    ret nc

    ld d, l
    rst $08
    ret


    adc $d4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    sbc a
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    pop bc
    call z, $cfd3
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, $8ccc
    ld a, a
    call nz, $cf55
    adc $87
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    ret


    add c
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    rst $10
    ret z

    ret


    call z, $4fc5
    add c
    ld a, a
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
    add $55
    pop bc
    call $d5cf
    db $d3
    ld a, a
    push de
    adc $d3
    push bc
    push bc
    adc $8d
    ret z

    ret


    adc $c4
    ld d, l
    push bc
    jp nc, $d37f

    reti


    db $d3
    call nc, $cdc5
    ld a, a
    rst $08
    add $7f
    ret nc

    ret


    adc $cb
    ld d, l
    ld a, a
    rst $00
    reti


    call Call_026_7f9f
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    pop de
    push de
    ret


    call nc, Call_026_7fc5
    ld c, a
    pop bc
    ld a, a
    call $cec1
    ld a, a
    rst $08
    add $7f
    ret


    adc $d4
    push bc
    rst $00
    jp nc, $d4c9

    ld d, l
    reti


    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and c
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c57f
    ld d, l
    ret c

    jp $d0c5


    call nc, $cfc9
    adc $81
    ld a, a
    xor h
    push bc
    call nc, $cd7f
    push bc
    ld a, a
    ld d, l
    call nz, $cfd2
    ret nc

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    ret z

    ret


    adc $d4
    ld a, a
    add c
    ld d, l
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    ret nc

    push bc
    jp nc, $d4c1

    push bc
    call nz, $d07f
    rst $08
    ld d, l
    jp nc, $c9d4

    rst $08
    adc $7f
    rst $08
    add $7f
    push de
    adc $d3
    push bc
    push bc
    adc $7f
    ret z

    ld d, l
    ret


    adc $c4
    push bc
    jp nc, $c37f

    pop bc
    adc $7f
    jp nz, Jump_026_7fc5

    db $d3
    push bc
    push bc
    adc $55
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    db $d3
    pop bc
    rst $10
    ld a, a
    db $d3
    push bc
    jp nc, $cfc9

    ld d, l
    push de
    db $d3
    call z, Call_026_7fd9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    and h
    rst $08
    adc $c5
    ld a, a
    adc $cf
    ld c, a
    call nc, $d37f
    rst $08
    ld a, a
    jp nz, $c4c1

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    and h
    rst $08
    adc $c5
    ld a, a
    adc $cf
    ld c, a
    call nc, $d37f
    rst $08
    ld a, a
    jp nz, $c4c1

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c17f
    call z, $cfd3
    ld a, a
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $c4d5
    ld c, a
    push bc
    adc $d4
    ld a, a
    rst $08
    add $7f
    db $d3
    ret nc

    reti


    ld a, a
    and e
    ret z

    ret


    reti


    pop bc
    rst $08
    ld d, l
    add c
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
    call nc, Call_026_7f55
    db $d3
    ret nc

    ret


    push bc
    db $d3
    ld a, a
    rst $08
    add $d4
    push bc
    adc $7f
    push de
    db $d3
    push bc
    call nz, Call_026_7f55
    pop bc
    adc $c9
    call $ccc1
    db $d3
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_026_7fc5

    adc [hl]
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $ce7f
    rst $08
    call nc, $d37f
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    ld c, a
    call nz, Call_026_7f81
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    add $c1
    jp nc, $c67f

    ld d, l
    rst $08
    jp nc, $cd7f

    push bc
    ld a, a
    call nc, Call_026_7fcf
    db $d3
    call nc, $c4d5
    reti


    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    jp $c1d2


    jp Jump_026_7fcb


    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp $c1d2


    jp Jump_026_7fcb


    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp $c1d2


    jp Jump_026_7fcb


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
    ret z

    push bc
    pop bc
    call nz, Call_026_7f7f
    and e
    ret z

    ret


    reti


    pop bc
    rst $08
    ld c, a
    ld a, a
    ld a, a
    ret z

    push bc
    jp nc, Jump_026_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call nz, $d3c5
    jp $55c5


    adc $c4
    push bc
    adc $d4
    ld a, a
    rst $08
    add $7f
    db $d3
    ret nc

    reti


    ld a, a
    reti


    push bc
    push bc
    ret z

    ld d, l
    rst $08
    rst $08
    add c
    ld a, a
    xor a
    rst $10
    sbc a
    add c
    ld a, a
    call nc, $c5c8
    adc $8c
    ld a, a
    or a
    ret z

    ld d, l
    rst $08
    db $d3
    push bc
    ld a, a
    rst $08
    add $c6
    db $d3
    ret nc

    jp nc, $cec9

    rst $00
    ld a, a
    pop bc
    jp nc, $55c5

    ld a, a
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    or a
    ret z

    push bc
    jp nc, Jump_026_7fc5

    call nc, $c5c8
    jp nc, Jump_026_7fc5

    ld c, a
    ret


    db $d3
    ld a, a
    call z, $c7c9
    ret z

    call nc, $8c7f
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, Jump_026_7fc5

    ld d, l
    call nc, $c5c8
    jp nc, Jump_026_7fc5

    rst $10
    ret


    call z, Call_026_7fcc
    jp nz, Jump_026_7fc5

    db $d3
    ret z

    pop bc
    ld d, l
    call nz, $d7cf
    add c
    ld a, a
    xor h
    ret


    rst $00
    ret z

    call nc, $cf7f
    jp nc, $d37f

    ret z

    pop bc
    ld d, l
    call nz, $d7cf
    add c
    ld a, a
    adc h
    ld a, a
    rst $10
    ret z

    ret


    jp Jump_026_7fc8


    call nz, Call_026_7fcf
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    db $d3
    push bc
    call z, $c3c5
    call nc, Call_026_7f9f
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $c5
    ld a, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    jp nz, $c4c1

    add c
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    adc $c5
    ld a, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    jp nz, $c4c1

    add c
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call Call_026_7fc5
    rst $08
    add $7f
    ld c, a
    rst $08
    push de
    jp nc, $c87f

    push bc
    pop bc
    call nz, Call_026_7f7f
    ret


    db $d3
    ld a, a
    reti


    pop bc
    call nz, Call_026_55cf
    adc $c7
    ld a, a
    adc [hl]
    ld a, a
    xor h
    rst $08
    rst $08
    res 0, c
    ld a, a
    reti


    pop bc
    call nz, $cecf
    rst $00
    ld d, l
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, h
    call z, $cfcf
    set 2, e
    ld a, a
    sub $c5
    jp nc, $d955

    ld a, a
    add $d5
    adc $ce
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    jp nc, Jump_026_7f8e

    reti


    pop bc
    call nz, $cecf
    rst $00
    ld a, a
    ld a, a
    call nz, $c5cf
    db $d3
    ld c, a
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    ld d, h
    ld a, a
    ret


    adc $7f
    call nz, $d4c5
    pop bc
    ld d, l
    ret


    call z, $81d3
    ld a, a
    xor b
    push bc
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ld d, l
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_026_7fd3
    rst $08
    add $7f
    ld a, a
    ld d, h
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $c5
    sub $c5
    jp nc, $d37f

    push bc
    push bc
    ld d, l
    adc $8e
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    call Call_026_7fd9
    and a
    rst $08
    call nz, Call_026_7f81
    or a
    ret z

    reti


    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    ret nc

    rst $08
    rst $08
    jp nc, $d97f

    pop bc
    call nz, $cecf
    rst $00
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld d, l
    rst $10
    push bc
    pop bc
    bit 7, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    rst $08
    ld a, a
    call z, $cdc9
    ret nc

    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    sbc a
    ld a, a
    xor c
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $d0d5
    ret


    call nz, $9f55
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    rst $08
    ld a, a
    pop bc
    jp nc, Jump_026_7fc5

    reti


    rst $08
    push de
    ld a, a
    call z, $c1cf
    add $4f
    ret


    adc $c7
    ld a, a
    call nc, Call_026_7fcf
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    ret


    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    push de
    adc $cd
    pop bc
    adc $ce
    push bc
    call nz, $d27f
    rst $08
    rst $08
    ld d, l
    call $9f7f
    ld a, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_026_7f9f
    xor h
    rst $08
    rst $08
    set 1, c
    adc $c7
    ld c, a
    ld a, a
    add $cf
    jp nc, $c17f

    ld a, a
    set 0, l
    reti


    sbc a
    ld a, a
    xor b
    add a
    call Call_026_7f8c
    ld d, l
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, Jump_026_7f8e

    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, Jump_026_7f8e

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
    xor a
    adc $cc
    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    jp $c9d2


    call $cfd3
    ld d, l
    adc $7f
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    adc h
    ld a, a
    call nz, Call_026_7fcf
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    adc $7f
    push bc
    add $c6
    push bc
    jp Jump_026_7fd4


    rst $08
    ld d, l
    add $7f
    db $d3
    ret z

    pop bc
    jp nc, $c5d0

    adc $c9
    adc $c7
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c955


    pop bc
    call z, $c17f
    jp nz, $ccc9

    ret


    call nc, Call_026_7fd9
    rst $08
    add $7f
    ld d, l
    ld d, h
    add c
    xor [hl]
    push bc
    ret c

    call nc, $b281
    push bc
    jp $c9c5


    sub $c5
    ld a, a
    ld d, l
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, l
    ld e, h
    adc h
    ret nc

    call z, $55c5
    pop bc
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld d, d
    ld a, a
    ret z

    pop bc
    call nz, $d27f
    push bc
    jp $c9c5


    sub $c5
    ld c, a
    call nz, Call_026_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $ab7f
    pop bc
    jp nc, $c8c3

    ret


    call z, $81c1
    ld a, a
    ld d, b
    dec bc
    nop
    ld d, l
    ld e, h
    sub e
    sbc b
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    pop bc
    ld a, a
    call nz, $c3c5
    ret


    db $d3
    ret


    sub $c5
    ld a, a
    call nc, $c9d2
    jp $cb55


    ld a, a
    rst $08
    add $7f
    jp nz, $d2d5

    adc $c9
    adc $c7
    ld a, a
    ld a, a
    add c
    and c
    ld a, a
    ld d, l
    jp nz, $c7c9

    adc l
    jp $c1c8


    jp nc, $c3c1

    call nc, $d2c5
    ld a, a
    jp nz, $cecf

    ld d, l
    add $c9
    jp nc, $81c5

    and d
    ret


    rst $00
    adc l
    jp $c1c8


    jp nc, $c3c1

    call nc, $55c5
    jp nc, $c27f

    rst $08
    adc $c6
    ret


    jp nc, Jump_026_7fc5

    ld a, a
    ret


    db $d3
    ld a, a
    add $cc
    pop bc
    ld d, l
    call Call_026_7fc5
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    xor d
    push de
    ld d, l
    db $d3
    call nc, $cc7f
    push bc
    call nc, $ac7f
    rst $08
    rst $00
    pop bc
    adc $7f
    pop bc
    adc $c4
    ld a, a
    ld d, l
    xor h
    push bc
    push bc
    jp $c1c8


    jp nc, Jump_026_7fc4

    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_026_7f55

    ret


    call nc, Call_026_7f81
    ld d, a
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
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_026_7fc5

    rst $10
    push bc
    ld a, a
    call $cbc1
    push bc
    ld a, a
    db $d3
    call nc, Call_026_4fd5
    call nz, Call_026_7fd9
    ld d, h
    ld a, a
    push bc
    sub $c5
    jp nc, $c4d9

    pop bc
    reti


    ld a, a
    adc h
    ld d, l
    ld a, a
    and c
    call nz, $c9c4
    call nc, $cfc9
    adc $c1
    call z, $d9cc
    adc h
    ld a, a
    db $d3
    rst $08
    ld d, l
    call Call_026_7fc5
    rst $00
    push de
    push bc
    db $d3
    call nc, Call_026_7fd3
    ld a, a
    rst $10
    ret


    call nc, Call_026_7fc8
    call nc, $c855
    push bc
    ret


    jp nc, $d07f

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld d, l
    ld d, h
    pop bc
    call z, $cfd3
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ret z

    push bc
    jp nc, $55c5

    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    ret nc

    ret z

    rst $08
    call nc, Call_026_7fcf
    ret


    db $d3
    ld a, a
    ld c, a
    and h
    jp nc, Jump_026_7f8e

    and [hl]
    rst $08
    rst $08
    rst $00
    reti


    adc h
    ld a, a
    ret nc

    ret


    rst $08
    adc $c5
    push bc
    ld d, l
    jp nc, $cf7f

    add $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c4c5

    ld a, a
    call z, $d4cf
    push de
    ld d, l
    db $d3
    ld a, a
    jp $c5c8


    call $d3c9
    call nc, $d9d2
    ld a, a
    call z, $c2c1
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    ld d, h
    ld a, a
    jp nc, $c3c5

    push bc
    ret nc

    call nc, $cfc9
    adc $7f
    or d
    rst $08
    ld c, a
    rst $08
    call $cf7f
    add $7f
    jp $c5c8


    call $d3c9
    call nc, $d9d2
    ld a, a
    call z, $c155
    jp nz, Jump_026_7f8e

    ld d, a
    nop
    ld a, a
    ld d, h
    ld a, a
    xor h
    pop bc
    jp nz, $cf7f

    add $7f
    jp $c5c8


    call Call_026_4fc9
    db $d3
    call nc, $d9d2
    ld a, a
    call nc, $d3c5
    call nc, Call_026_7f8e
    ld d, a
    nop
    ld a, a
    ld d, h
    ld a, a
    xor h
    pop bc
    jp nz, $cf7f

    add $7f
    jp $c5c8


    call Call_026_4fc9
    db $d3
    call nc, $d9d2
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    ld c, a
    call z, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    call nz, Call_026_55cd
    ret


    jp nc, $cec9

    rst $00
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    add c
    ld a, a
    ld d, l
    xor c
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    add $c5
    push bc
    call z, $c97f
    call nc, $557f
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, $cf7f
    add $7f
    ld d, l
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    jp nc, $c7c9

    ret z

    call nc, Call_026_7f81
    reti


    push bc
    push bc
    jp nz, Jump_026_7fd5

    or h
    ret z

    push bc
    ld c, a
    jp nc, Jump_026_7fc5

    pop bc
    jp nc, Jump_026_7fc5

    call nc, $d2c8
    push bc
    push bc
    ld a, a
    ret nc

    jp nc, $c2cf

    ld d, l
    pop bc
    jp nz, $ccc9

    ret


    call nc, $c5c9
    db $d3
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    ld d, l
    push bc
    sub $cf
    call z, $d4d5
    ret


    adc $c7
    ld a, a
    add $d2
    rst $08
    call $817f
    ld a, a
    ld d, l
    xor l
    pop bc
    reti


    jp nz, Jump_026_7fc5

    ret


    call nc, $c57f
    sub $cf
    call z, $d4d5
    push bc
    call nz, Call_026_7f55
    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $d2c8
    push bc
    push bc
    ld a, a
    set 1, c
    adc $c4
    db $d3
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    adc $c4
    ld a, a
    pop bc
    adc $7f
    and l
    adc l
    call $c9c1
    call z, $d47f
    ld c, a
    rst $08
    ld a, a
    ld e, e
    ld a, a
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    call z, $c7c5
    push bc
    adc $c4
    pop bc
    jp nc, Jump_026_7fd9

    jp nz, $d2c9

    call nz, $557f
    ld d, h
    ld a, a
    call $d9c1
    ld a, a
    jp nz, Jump_026_7fc5

    call nc, $d2c8
    push bc
    push bc
    ld a, a
    ld d, l
    set 1, c
    adc $c4
    db $d3
    ld a, a
    ld d, [hl]
    sbc d
    ld a, a
    add $c9
    jp nc, $8cc5

    ld a, a
    call nc, $c855
    push de
    adc $c4
    push bc
    jp nc, $c17f

    adc $c4
    ld a, a
    add $d2
    rst $08
    jp c, $cec5

    ld d, l
    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    jp nz, $d4d5

    ld a, a
    adc $cf
    rst $10
    ld a, a
    rst $10
    push bc
    ld a, a
    ld d, l
    db $d3
    call nc, $ccc9
    call z, $c47f
    rst $08
    adc $87
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    ld d, l
    rst $10
    ret z

    push bc
    jp nc, Jump_026_7fc5

    ld a, a
    call nc, $c5c8
    reti


    ld a, a
    pop bc
    jp nc, $8ec5

    ld a, a
    ld d, l
    xor [hl]
    push bc
    ret c

    call nc, $d47f
    ret


    call $8cc5
    ld a, a
    rst $10
    push bc
    add a
    call z, Call_026_7fcc
    ld d, l
    rst $00
    rst $08
    ld a, a
    call nc, Call_026_7fcf
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    ld d, l
    jp $d6c1


    push bc
    ld a, a
    ld a, a
    call nc, Call_026_7fcf
    call $cbc1
    push bc
    ld a, a
    ret


    adc $d6
    ld d, l
    push bc
    db $d3
    call nc, $c7c9
    pop bc
    call nc, $cfc9
    adc $7f
    adc [hl]
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, l
    and [hl]
    ret


    jp nc, $d4d3

    ld a, a
    jp nc, $d0c5

    rst $08
    jp nc, Jump_026_7fd4

    ld a, a
    db $d3
    ret nc

    push bc
    ld d, l
    jp $c1c9


    call z, $d9cc
    ld a, a
    add $cf
    jp nc, $d47f

    ret z

    ret


    db $d3
    ld a, a
    ret nc

    ld d, l
    push de
    jp nc, $cfd0

    db $d3
    push bc
    adc [hl]
    ld a, a
    ld d, h
    ld a, a
    xor c
    adc $d6
    push bc
    db $d3
    ld d, l
    call nc, $c7c9
    pop bc
    call nc, $cfc9
    adc $7f
    or h
    push bc
    pop bc
    call Call_026_7f8e
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
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

Call_026_7f4f:
Jump_026_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_026_7f55:
Jump_026_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_026_7f7f:
Jump_026_7f7f:
    nop
    nop

Call_026_7f81:
Jump_026_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_026_7f8c:
Jump_026_7f8c:
    nop
    nop

Call_026_7f8e:
Jump_026_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_026_7f9f:
Jump_026_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_026_7fc1:
    nop
    nop
    nop

Call_026_7fc4:
Jump_026_7fc4:
    nop

Call_026_7fc5:
Jump_026_7fc5:
    nop

Call_026_7fc6:
    nop
    nop

Call_026_7fc8:
Jump_026_7fc8:
    nop
    nop
    nop

Jump_026_7fcb:
    nop

Call_026_7fcc:
    nop

Call_026_7fcd:
    nop

Jump_026_7fce:
    nop

Call_026_7fcf:
    nop

Call_026_7fd0:
Jump_026_7fd0:
    nop
    nop
    nop

Call_026_7fd3:
Jump_026_7fd3:
    nop

Call_026_7fd4:
Jump_026_7fd4:
    nop

Jump_026_7fd5:
    nop
    nop
    nop
    nop

Call_026_7fd9:
Jump_026_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
