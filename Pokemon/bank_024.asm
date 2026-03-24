; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $024", ROMX[$4000], BANK[$24]

    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, $c67f
    ld c, a
    rst $08
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_024_7fcf
    rst $10
    pop bc
    sub $c5
    ld a, a
    call nz, Call_024_55d5
    jp nc, $cec9

    rst $00
    ld a, a
    call nz, $d7cf
    adc $c8
    ret


    call z, $8ccc
    ld a, a
    ret


    db $d3
    ld d, l
    adc $87
    db $d3
    ld a, a
    ret


    call nc, Call_024_7f9f
    ld d, a
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    add a
    call $d47f
    ret


    jp nc, $c4c5

    ld a, a
    ld d, [hl]
    adc [hl]
    ld c, a
    ld a, a
    xor c
    add a
    call $d37f
    call z, $c5c5
    ret nc

    reti


    ld a, a
    xor c
    add a
    call $d67f
    ld d, l
    push bc
    jp nc, Jump_024_7fd9

    call nc, $d2c9
    push bc
    call nz, Call_024_567f
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    pop bc
    jp Jump_024_7fcb


    push de
    ret nc

    adc h
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_024_7fcf
    db $d3
    ld c, a
    call z, $c5c5
    ret nc

    ld a, a
    ld d, a
    nop
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_024_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    ld a, a
    sub c
    sbc b
    ld a, a
    ret z

    ld c, a
    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    jp $cf55


    call z, $d5cf
    jp nc, Jump_024_567f

    adc h
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    jp Jump_024_55c9


    call nc, Call_024_7fd9
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_024_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $d5cf

    call nc, $c54f
    ld a, a
    add $cf
    jp nc, $c27f

    ret


    set 0, l
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    rst $10
    pop bc
    call z, $cb55
    ret


    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    call nc, $c9c8
    jp Jump_024_7fcb


    rst $00
    jp nc, $d7cf

    call nc, Call_024_7fc8
    rst $08
    ld c, a
    add $7f
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $cf
    push de
    adc $55
    call nz, Call_024_7f8e
    xor c
    add a
    call $cc7f
    rst $08
    rst $08
    set 1, c
    adc $c7
    ld a, a
    add $cf
    ld d, l
    jp nc, Jump_024_7f81

    ld d, a
    adc [hl]
    ld a, a
    db $d3
    rst $08
    call Call_024_7fc5
    adc $c5
    rst $10
    ld a, a
    ld d, l
    ld d, h
    db $d3
    adc h
    db $d3
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor c
    add $7f
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp nz, $cbc9

    push bc
    ld c, a
    adc h
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
    call nc, Call_024_7fcf
    ld d, l
    rst $00
    rst $08
    ld a, a
    add $c1
    jp nc, $cf7f

    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $d5cf

    ld d, l
    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    ret


    db $d3
    call nc, $c5cc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $9f4f
    ld a, a
    call Call_024_7fd9
    rst $10
    ret z

    ret


    db $d3
    call nc, $c5cc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    ld c, a
    ld a, a
    ret


    db $d3
    ld a, a
    adc $c5
    pop bc
    jp nc, $d9c2

    ld a, a
    adc h
    ld a, a
    jp $cdcf


    push bc
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c1cf


    db $d3
    call nc, $d47f
    rst $08
    ld a, a
    jp $d0c1


    ld d, l
    call nc, $d2d5
    push bc
    ld a, a
    db $d3
    push bc
    pop bc
    jp nz, $d2c9

    call nz, Call_024_54d3
    adc h
    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    push bc
    push bc
    set 0, l
    adc $c4
    adc [hl]
    ld a, a
    ld d, l
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld a, a
    jp $cdcf


    push bc
    ld c, a
    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    call $d5cf
    call nc, Call_024_7fc8
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld a, a
    jp $cdcf


    push bc
    ld c, a
    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    call $d5cf
    call nc, Call_024_7fc8
    ld e, b
    nop
    ld a, a
    and c
    jp nc, $d5cf

    adc $c4
    ld a, a
    ret z

    push bc
    jp nc, $8cc5

    ld a, a
    adc h
    ld a, a
    pop bc
    ld c, a
    call z, Call_024_7fcc
    pop bc
    jp nc, Jump_024_7fc5

    rst $08
    push de
    jp nc, $d47f

    jp nc, $d0c1

    db $d3
    add c
    ld d, l
    ld a, a
    xor b
    rst $08
    ret nc

    ret


    adc $c7
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, Call_024_7f55
    jp $cfcc


    db $d3
    push bc
    ld a, a
    ret z

    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
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
    ret z

    ret


    db $d3
    ld a, a
    ld c, a
    rst $08
    rst $10
    adc $7f
    call nz, $d3c5
    ret


    jp nc, $c4c5

    ld a, a
    adc h
    ld a, a
    rst $00
    rst $08
    ld a, a
    ld d, l
    call nc, Call_024_7fcf
    call nc, $c5c8
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    ld a, a
    call nc, Call_024_7fcf
    ld d, l
    jp $d4c1


    jp Jump_024_7fc8


    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    push de
    call $c8d0
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    push de
    call $c8d0
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_024_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sbc c
    jp $d5cf


    ld c, a
    jp nc, $c5d3

    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, l
    call nc, $cfd7
    adc l
    db $d3
    rst $08
    adc $7f
    ret


    db $d3
    call z, $cec1
    call nz, $577f
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $c47f
    rst $08
    ld a, a
    add $d2
    push bc
    push bc
    ld c, a
    db $d3
    call nc, $cec1
    call nz, $cec9
    rst $00
    ld a, a
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld d, l
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_024_7fc5

    reti


    rst $08
    push de
    ld a, a
    jp z, $cdd5

    ret nc

    ld a, a
    ld d, l
    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or [hl]
    push bc
    jp nc, Jump_024_7fd9

    rst $00
    rst $08
    rst $08
    call nz, Call_024_7f81
    call nc, $c1c8
    adc $cb
    ld c, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    xor c
    call nc, $c27f
    push bc
    jp $cdcf


    push bc
    db $d3
    ld a, a
    pop bc
    ld d, l
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d37f
    ret nc

    rst $08
    jp nc, $81d4

    ld a, a
    ld d, a
    nop
    ld a, a
    rst $00
    reti


    call $c1ce
    db $d3
    call nc, $c3c9
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    adc $4f
    call nz, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    push de
    call $c8d0
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $d6cf
    push bc
    call $cec5
    call nc, Call_024_4f8c
    ld a, a
    call nz, $cecf
    add a
    call nc, $d77f
    rst $08
    jp nc, $d9d2

    add c
    ld a, a
    ld a, a
    xor b
    rst $08
    ld d, l
    rst $10
    ld a, a
    call nc, Call_024_7fcf
    call nz, $c1c5
    call z, $d77f
    ret


    call nc, Call_024_7fc8
    ret z

    push bc
    ld d, l
    pop bc
    jp nc, Jump_024_7fd4

    ret nc

    pop bc
    jp nc, $ccc1

    reti


    db $d3
    ret


    db $d3
    adc h
    ld d, a
    nop
    ld a, a
    or b
    pop bc
    reti


    ld a, a
    pop bc
    call nc, $c5d4
    adc $d4
    ret


    rst $08
    adc $7f
    call nc, Call_024_4fcf
    ld a, a
    jp z, $ccc5

    call z, $c6d9
    ret


    db $d3
    ret z

    add c
    ld a, a
    and d
    push bc
    ld a, a
    jp $55c1


    jp nc, $c6c5

    push de
    call z, Call_024_7f8c
    ret nc

    jp nc, $d6c5

    push bc
    adc $d4
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    add $d2
    rst $08
    call $ca7f
    push bc
    call z, $d9cc
    add $c9
    db $d3
    ret z

    add a
    ld d, l
    db $d3
    ld a, a
    db $d3
    call nc, $cec9
    rst $00
    ld a, a
    call nz, $d2d5
    ret


    adc $c7
    ld a, a
    db $d3
    rst $10
    ld d, l
    ret


    call $c9cd
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    jp $cccf


    call nz, Call_024_7f81
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    jp $cccf


    call nz, Call_024_7f81
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    call nz, Call_024_7fcf
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    rst $10
    ret


    call $c9cd
    ld c, a
    adc $c7
    add c
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    ld d, l
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    and l
    sub $c5
    adc $7f
    call nc, Call_024_7fcf
    ld d, h
    ld a, a
    ret


    adc $7f
    db $d3
    ld c, a
    push bc
    pop bc
    ld a, a
    jp $cec1


    add a
    call nc, $cc7f
    rst $08
    db $d3
    push bc
    ld a, a
    ret


    add $7f
    ld d, l
    jp $cdcf


    ret nc

    push bc
    call nc, $c4c5
    ld a, a
    db $d3
    rst $10
    ret


    call $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    rst $08
    adc $c7
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
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_024_7fc5

    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_024_7fd3

    db $d3
    rst $08
    ld c, a
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    push bc
    call z, $c5d3
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    ld d, l
    db $d3
    ret


    call nc, Call_024_7fc5
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    jp nc, $dac9

    rst $08
    adc $7f
    ld d, l
    adc h
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    db $d3
    ret


    call nc, Call_024_4fc5
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    db $d3
    push bc
    sub $55
    push bc
    jp nc, $ccc1

    ld a, a
    ret


    db $d3
    call z, $cec1
    call nz, $81d3
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    reti


    pop bc
    rst $08
    rst $08
    adc h
    reti


    pop bc
    rst $08
    rst $08
    adc h
    ld c, a
    ld d, [hl]
    adc h
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    reti


    pop bc
    rst $08
    rst $08
    adc h
    reti


    pop bc
    rst $08
    rst $08
    adc h
    ld c, a
    ld d, [hl]
    adc h
    ld e, b
    nop
    ld a, a
    ret


    call nc, $d37f
    push bc
    push bc
    call Call_024_7fd3
    push de
    adc $c6
    push bc
    pop bc
    db $d3
    ret


    ld c, a
    jp nz, $c5cc

    ld a, a
    call nc, Call_024_7fcf
    jp $d4c1


    jp Jump_024_7fc8


    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, h
    add a
    db $d3
    ld a, a
    ret


    adc $7f
    db $d3
    push bc
    pop bc
    ld a, a
    jp nz, Jump_024_7fd9

    call nz, $c955
    sub $c9
    adc $c7
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    ld d, l
    call nc, $d2c5
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, Call_024_7f7f
    call z, $cfcf
    set 2, e
    ld a, a
    call nc, $c1c8
    call nc, $cf7f
    ld c, a
    adc $cc
    reti


    ld a, a
    jp nz, Jump_024_7fd9

    pop bc
    adc $c7
    call z, $cec9
    rst $00
    ld a, a
    jp $55c1


    adc $7f
    ld d, h
    ld a, a
    ret


    adc $7f
    db $d3
    push bc
    pop bc
    ld a, a
    jp nz, Jump_024_7fc5

    jp $c155


    ret nc

    call nc, $d2d5
    push bc
    call nz, $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push de
    jp nz, $ccc2

    push bc
    adc h
    ld a, a
    jp nz, $c2d5

    jp nz, $c5cc

    adc [hl]
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    and d
    push de
    jp nz, $ccc2

    push bc
    adc h
    ld a, a
    jp nz, $c2d5

    jp nz, $c5cc

    adc [hl]
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    add $cf
    jp nc, $c5c7

    call nc, $c17f
    ld c, a
    call z, Call_024_7fcc
    call nc, $c5c8
    ld a, a
    call nc, $d2c9
    push bc
    db $d3
    rst $08
    call Call_024_7fc5
    call nc, $c855
    ret


    adc $c7
    db $d3
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    bit 2, l
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $d5cc

    push bc
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    ld d, l
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


    ld a, a
    add $cf
    jp nc, $c5c7

    call nc, $c17f
    ld c, a
    call z, Call_024_7fcc
    call nc, $c5c8
    ld a, a
    call nc, $d2c9
    push bc
    call nz, $d47f
    ret z

    ret


    adc $55
    rst $00
    db $d3
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    call nc, Call_024_7f55
    call nc, $c5c8
    ld a, a
    jp nz, $d5cc

    push bc
    ld a, a
    db $d3
    push bc
    pop bc
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
    rst $10
    pop bc
    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $d3cf
    push bc
    ld c, a
    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_024_587f
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $10
    pop bc
    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $d3cf
    push bc
    ld c, a
    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_024_587f
    nop
    ld a, a
    and c
    ret z

    rst $08
    rst $08
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d5cf
    adc $d4
    ld a, a
    ld c, a
    rst $08
    adc $7f
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c27f
    ret


    set 0, l
    add c
    ld a, a
    rst $00
    ld d, l
    ret


    sub $c5
    ld a, a
    call Call_024_7fc5
    call nc, $c1c8
    call nc, $c97f
    add $7f
    xor c
    ld a, a
    ld d, l
    rst $00
    push bc
    call nc, $d77f
    ret


    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    db $d3
    rst $08
    ld a, a
    add $c1
    jp nc, Jump_024_567f

    ld a, a
    ld a, a
    ld c, a
    call nc, Call_024_7fcf
    call nc, $c5c8
    ld a, a
    call nc, $c9d7
    adc $d3
    adc l
    ret


    db $d3
    call z, $55c1
    adc $c4
    ld a, a
    xor c
    add a
    call nz, $cc7f
    ret


    set 0, l
    ld a, a
    call nc, Call_024_7fcf
    rst $00
    rst $08
    ld d, l
    ld a, a
    jp nz, $c3c1

    bit 7, a
    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call $a97f
    ld a, a
    call z, $d3cf
    call nc, Call_024_7f9f
    ld e, b
    nop
    ld a, a
    and c
    call $a97f
    ld a, a
    call z, $d3cf
    call nc, Call_024_7f9f
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    call nz, Call_024_7fcf
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    rst $10
    ret


    call $c9cd
    ld c, a
    adc $c7
    ld a, a
    jp nz, $d4d5

    ld a, a
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, $cc7f
    ret


    ld d, l
    set 0, l
    ld a, a
    call nc, Call_024_7fcf
    jp nz, Jump_024_7fc5

    call nc, $cec1
    adc $c5
    call nz, Call_024_7f81
    ld d, l
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    pop bc
    call nc, $c87f
    push bc
    ld a, a
    ld c, a
    rst $10
    ret


    call z, Call_024_7fcc
    db $d3
    rst $10
    ret


    call $d47f
    rst $08
    ld a, a
    call nc, $c9d7
    adc $55
    db $d3
    adc l
    ret


    db $d3
    call z, $cec1
    call nz, Call_000_0057
    ld a, a
    and h
    ret


    jp c, $d9da

    ld a, a
    rst $08
    jp nc, $d77f

    pop bc
    call nc, $d2c5
    ld a, a
    db $d3
    ld c, a
    rst $08
    push de
    adc $c4
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    and h
    ret


    jp c, $d9da

    ld a, a
    rst $08
    jp nc, $d77f

    pop bc
    call nc, $d2c5
    ld a, a
    db $d3
    ld c, a
    rst $08
    push de
    adc $c4
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
    reti


    rst $08
    push de
    adc $c7
    call $cec1
    ld a, a
    rst $08
    sub $c5
    ld c, a
    jp nc, $d47f

    ret z

    push bc
    jp nc, $81c5

    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    pop bc
    rst $10
    ld d, l
    pop bc
    call nc, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, $d5cf

    db $d3
    ld d, l
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
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp $c1d2


    ld c, a
    call Call_024_7fd0
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $c5cf
    add c
    ld a, a
    nop
    ld a, a
    xor c
    ld a, a
    db $d3
    push de
    add $c6
    push bc
    jp nc, $c17f

    ld a, a
    call nz, $cec1
    rst $00
    push bc
    ld c, a
    jp nc, Jump_024_587f

    nop
    ld a, a
    xor c
    ld a, a
    db $d3
    push de
    add $c6
    push bc
    jp nc, $c17f

    ld a, a
    call nz, $cec1
    rst $00
    push bc
    ld c, a
    jp nc, Jump_024_587f

    nop
    ld a, a
    and l
    sub $c5
    jp nc, $cfd9

    adc $c5
    ld a, a
    db $d3
    rst $10
    ret


    call Call_024_7fd3
    ret z

    ld c, a
    push bc
    jp nc, Jump_024_7fc5

    sub $c5
    jp nc, Jump_024_7fd9

    add $c1
    call nc, $c7c9
    push de
    push bc
    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    call z, $c5c9
    ld a, a
    rst $08
    adc $7f
    rst $08
    adc $c5
    add a
    db $d3
    ld a, a
    ld d, l
    db $d3
    call nc, $cdcf
    pop bc
    jp $8ec8


    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_024_7fcf
    call $cf4f
    push de
    adc $d4
    ld a, a
    rst $08
    adc $7f
    ld d, h
    adc h
    ld a, a
    ld a, a
    ret z

    pop bc
    call nz, Call_024_7f55
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    xor h
    pop bc
    jp nz, $55cc

    pop bc
    db $d3
    ld a, a
    adc [hl]
    ld a, a
    db $d3
    ret


    adc $c3
    push bc
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    ld d, l
    sub $c5
    jp nc, Jump_024_7fd9

    jp nz, $c7c9

    ld a, a
    call nc, Call_024_7fcf
    ret nc

    jp nc, $d6c5

    push bc
    ld d, l
    adc $d4
    ld a, a
    add $d2
    rst $08
    call $c77f
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    rst $10
    ld d, l
    push bc
    call nc, $577f
    nop
    ld a, a
    call nc, $d2c9
    push bc
    call nz, Call_024_567f
    adc h
    ld e, b
    nop
    ld a, a
    call nc, $d2c9
    push bc
    call nz, Call_024_567f
    adc h
    ld e, b
    nop
    ld a, a
    call nc, $c9d7
    adc $d3
    adc l
    ret


    db $d3
    call z, $cec1
    call nz, $577f
    nop
    ld a, a
    call nc, $c9d7
    adc $d3
    adc l
    ret


    db $d3
    call z, $cec1
    call nz, $577f
    nop
    ld a, a
    call $cec1
    reti


    ld a, a
    call $cec1
    reti


    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_024_4fc5
    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    db $d3
    rst $10
    ret


    call $c9cd
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_024_7fcf
    adc $cf
    call nc, $c67f
    pop bc
    call nc, $c7c9
    ld c, a
    push de
    push bc
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    reti


    rst $08
    push de
    ld d, l
    jp nc, $cd7f

    rst $08
    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    adc h
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    pop bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    push bc
    pop bc
    add c
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
    jp $cdcf


    push bc
    ld a, a
    ld c, a
    db $d3
    pop bc
    adc $c1
    call nc, $d2cf
    ret


    push de
    call $cf7f
    adc $7f
    call nc, $c9d7
    ld d, l
    adc $d3
    adc l
    ret


    db $d3
    call z, $cec1
    call nz, $8e7f
    ld d, a
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_024_7fc4

    call nc, $c5c8
    jp nc, Jump_024_4fc5

    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $ccc1
    pop bc
    jp $c9d4


    call nc, $c3c9
    ld d, l
    ld a, a
    jp $d6c1


    push bc
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d2c7

    rst $08
    push de
    adc $c4
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $c9d7
    adc $d3
    adc l
    ret


    db $d3
    call z, $cec1
    call nz, Call_024_7f55
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    ld c, a
    call $cec9
    push de
    call nc, Call_024_7fc5
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    ld c, a
    call $cec9
    push de
    call nc, Call_024_7fc5
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    ret nc

    call z, $cdd5
    ret nc

    ld a, a
    add $c9
    db $d3
    ret z

    ld c, a
    ld a, a
    ld d, [hl]
    ld a, a
    add $cc
    rst $08
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    rst $08
    adc $7f
    call nc, $c855
    push bc
    ld a, a
    rst $10
    pop bc
    sub $c5
    db $d3
    ld a, a
    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d97f
    rst $08
    push de
    ld a, a
    add $cc
    rst $08
    pop bc
    call nc, Call_024_4f7f
    rst $10
    ret


    call nc, Call_024_7fc8
    call Call_024_7fc5
    ld d, [hl]
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_000_007f
    ld a, a
    xor b
    add a
    call Call_000_007f
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_024_4fcf
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    adc $c1
    call nc, $d2cf
    ret


    push de
    call Call_024_7f9f
    ld d, l
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c9d7
    adc $d3
    adc l
    ret


    db $d3
    call z, $cec1
    call nz, Call_024_7f4f
    call $d9c1
    jp nz, Jump_024_7fc5

    rst $10
    pop bc
    db $d3
    ld a, a
    call nc, $cfd7
    ld a, a
    ret


    db $d3
    ld d, l
    call z, $cec1
    call nz, Call_024_7fd3
    jp nz, $c6c5

    rst $08
    jp nc, $8cc5

    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c37f
    pop bc
    jp nc, Jump_024_7fc5

    ld c, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c37f
    pop bc
    jp nc, Jump_024_7fc5

    ld c, a
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
    jp nz, $c4cf

    reti


    ld a, a
    ret z

    ld c, a
    pop bc
    sub $c9
    adc $c7
    ld a, a
    pop bc
    ld a, a
    ret nc

    ret z

    reti


    db $d3
    ret


    jp $ccc1


    ld a, a
    ld d, l
    call nc, $c1d2
    ret


    adc $c9
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $d47f

    pop bc
    bit 1, a
    push bc
    ld a, a
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    jp $cdcf


    ret nc

    pop bc
    jp nc, $c555

    call nz, $d77f
    ret


    call nc, Call_024_7fc8
    reti


    rst $08
    push de
    jp nc, $cf7f

    rst $10
    adc $7f
    ld d, l
    jp nz, $c4cf

    reti


    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    pop bc
    bit 7, a
    call z, $cbc9
    push bc
    ld a, a
    jp z, $ccc5

    call z, Call_024_7fd9
    ld c, a
    nop
    ld a, a
    or a
    push bc
    pop bc
    bit 7, a
    call z, $cbc9
    push bc
    ld a, a
    jp z, $ccc5

    call z, Call_024_7fd9
    ld c, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    push bc
    sub $c5
    adc $7f
    call $d5cf
    adc $d4
    ld a, a
    rst $08
    ld c, a
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, h
    xor l
    push de
    db $d3
    call nc, $87ce
    call nc, $557f
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    rst $10
    push de
    call Call_024_7f8c
    call nz, Call_024_55cf
    ld a, a
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    call nc, Call_024_7fcf
    rst $00
    rst $08
    ld a, a
    call nc, $c5c8
    jp nc, Jump_024_7fc5

    call z, $cf55
    rst $08
    set 2, e
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push de
    jp nz, $ccc2

    push bc
    adc h
    jp nz, $c2d5

    jp nz, $c5cc

    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push de
    jp nz, $ccc2

    push bc
    adc h
    jp nz, $c2d5

    jp nz, $c5cc

    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    and e
    pop bc
    call nc, $c8c3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d2c9

    call nz, Call_024_4f7f
    ld d, h
    ld a, a
    ld a, a
    jp $cdc1


    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_024_7fc5

    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $d2c9

    call nz, $d37f
    push bc
    push bc
    call Call_024_7fd3
    sub $4f
    push bc
    jp nc, Jump_024_7fd9

    call nc, $d2c9
    push bc
    call nz, Call_024_7f8c
    ret


    call nc, $c37f
    pop bc
    adc $55
    add a
    call nc, $c77f
    rst $08
    ld a, a
    jp nz, $c3c1

    bit 7, a
    ld d, [hl]
    ld a, a
    ret z

    rst $08
    rst $10
    ld d, l
    ld a, a
    call nc, Call_024_7fcf
    call nz, $9fcf
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    pop bc
    call $8cce
    ld a, a
    and h
    pop bc
    call $81ce
    ld a, a
    xor c
    call nc, $d387
    ld c, a
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $588e
    nop
    ld a, a
    and h
    pop bc
    call $8cce
    ld a, a
    and h
    pop bc
    call $81ce
    ld a, a
    xor c
    call nc, $d387
    ld c, a
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $588e
    nop
    ld a, a
    and [hl]
    jp nc, $cdcf

    ld a, a
    ret z

    ret


    call Call_024_7f8c
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    ld c, a
    sub $c5
    call nz, $c17f
    ld a, a
    jp nz, $c7c9

    ld a, a
    ret nc

    push bc
    pop bc
    jp nc, $81cc

    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    call Call_024_4fcf
    jp nc, Jump_024_7fc5

    ret nc

    push bc
    pop bc
    jp nc, Jump_024_7fcc

    rst $08
    reti


    db $d3
    call nc, $d2c5
    db $d3
    adc h
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    push bc
    pop bc
    jp nc, Jump_024_7fcc

    call $d9c1
    ld a, a
    jp nz, $55c5

    jp $cdcf


    push bc
    ld a, a
    jp nz, $c7c9

    rst $00
    push bc
    jp nc, $577f

    nop
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_024_7f81
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    jp $cecf


    call nc, $c9c1
    adc $c9
    adc $c7
    ld a, a
    pop bc
    ld a, a
    ret nc

    ld d, l
    push bc
    pop bc
    jp nc, $8ccc

    ld a, a
    ld e, b
    nop
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, Call_024_7f81
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    jp $cecf


    call nc, $c9c1
    adc $c9
    adc $c7
    ld a, a
    pop bc
    ld a, a
    ret nc

    ld d, l
    push bc
    pop bc
    jp nc, $8ccc

    ld a, a
    ld e, b
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
    ret z

    pop bc
    ld c, a
    call nz, $c17f
    ld a, a
    call nc, $d2c9
    ret


    adc $c7
    ld a, a
    jp z, $d5cf

    jp nc, $c5ce

    ld d, l
    reti


    ld a, a
    ld a, a
    db $d3
    rst $10
    ret


    call $c9cd
    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    add $d2
    ld d, l
    rst $08
    call $d27f
    push bc
    call nz, $cc7f
    rst $08
    call nc, $d3d5
    ld a, a
    ret


    db $d3
    call z, $55c1
    adc $c4
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
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    ld a, a
    call z, $d6c9
    ret


    adc $4f
    rst $00
    ld a, a
    adc $cf
    jp nz, $c4cf

    reti


    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c555

    call nz, $cc7f
    rst $08
    call nc, $d3d5
    ld a, a
    ret


    db $d3
    call z, $cec1
    call nz, Call_024_7f7f
    ld d, l
    rst $10
    pop bc
    db $d3
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    call $cec1
    db $d3
    ret


    rst $08
    ld d, l
    adc $7f
    ld d, h
    rst $10
    ret z

    push bc
    adc $c5
    sub $c5
    jp nc, $557f

    ld d, h
    ld a, a
    call z, $d6c9
    push bc
    call nz, $d47f
    ret z

    push bc
    jp nc, Jump_024_7fc5

    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    rst $08
    ret


    adc $d4
    push bc
    call nz, Call_024_587f
    nop
    ld a, a
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    rst $08
    ret


    adc $d4
    push bc
    call nz, Call_024_587f
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    push bc
    db $d3
    call nc, $cf7f
    add $7f
    call nc, $c84f
    push bc
    ld a, a
    jp nc, $c4c5

    ld a, a
    call z, $d4cf
    push de
    db $d3
    ld a, a
    ret


    db $d3
    call z, $55c1
    adc $c4
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret


Call_024_4f7f:
    adc $d3
    call nc, $d4c9
    ld d, l
    push de
    call nc, Call_024_7fc5
    rst $08
    add $7f

Call_024_4f8c:
    ld d, h
    add c
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    ld d, l
    sub $c5
    jp nc, $d47f

    ret z

    push bc
    jp nc, $8cc5

Call_024_4f9f:
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    add $c1
    ld d, l
    call nc, $c5c8
    jp nc, $c17f

    call z, $cfd3
    ld a, a
    rst $10
    rst $08
    jp nc, $d3cb

    ld a, a
    call nc, $c855
    push bc
    jp nc, Jump_024_7fc5

    ld d, a
    nop
    ld a, a

Jump_024_4fc1:
    xor c

Call_024_4fc2:
    call nc, $c97f

Call_024_4fc5:
Jump_024_4fc5:
    db $d3
    ld a, a
    db $d3

Call_024_4fc8:
    pop bc

Call_024_4fc9:
    ret


    call nz, $d47f
    ret z

    pop bc

Call_024_4fcf:
Jump_024_4fcf:
    call nc, Call_024_4f7f
    call nc, $c5c8
    ld a, a
    jp nc, $c4c5

    ld a, a
    call z, $d4cf
    push de
    db $d3
    ld a, a
    ret


    db $d3
    call z, $c155
    adc $c4
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $cf
    jp nc, $c5cd

    call nz, $c27f
    reti


    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    ret


    call z, Call_024_7fc5
    push de
    ret nc

    ld a, a
    rst $08
    add $7f
    sub $55
    rst $08
    call z, $c1c3
    adc $c9
    jp $c57f


    jp nc, $d0d5

    call nc, $cfc9
    adc $7f
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $cd7f
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $cd7f
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d97f
    rst $08
    push de
    ld a, a
    rst $10
    ret


    db $d3
    ret z

    ld a, a
    call z, $c94f
    db $d3
    call nc, $cec5
    adc $c9
    adc $c7
    ld a, a
    call nc, Call_024_7fcf
    jp $cdcf


    add $55
    rst $08
    jp nc, $c1d4

    jp nz, $c5cc

    ld a, a
    rst $10
    rst $08
    jp nc, $d3c4

    ld a, a
    sbc a
    ld d, a
    nop
    ld a, a
    and c
    adc $7f
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_024_4f7f
    ld d, h
    adc h
    ld a, a
    ret


    db $d3
    adc $87
    call nc, $d47f
    ret


    jp nc, $c4c5

    ld a, a
    ld d, l
    add c
    ld a, a
    ld a, a
    ret


    db $d3
    adc $87
    call nc, $c17f
    call nc, $c17f
    call z, $81cc
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    add $c1
    call z, $c5cc
    ld c, a
    adc $7f
    pop bc
    ld a, a
    ret nc

    jp nc, $d9c5

    ld a, a
    call nc, Call_024_7fcf
    pop bc
    ld a, a
    ret nc

    call z, Call_024_55cf
    call nc, Call_024_7f8e
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    add $c1
    call z, $c5cc
    ld c, a
    adc $7f
    pop bc
    ld a, a
    ret nc

    jp nc, $d9c5

    ld a, a
    call nc, Call_024_7fcf
    pop bc
    ld a, a
    ret nc

    call z, Call_024_55cf
    call nc, Call_024_7f8e
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c87f
    pop bc
    jp nc, $c5d6

    db $d3
    call nc, Call_024_7f8c
    ld c, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c87f
    pop bc
    jp nc, $c5d6

    db $d3
    call nc, Call_024_7f81
    rst $10
    ld d, l
    pop bc
    adc $d4
    ld a, a
    call nc, Call_024_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, Call_024_7fc5
    rst $10
    ret


    ld d, l
    call nc, Call_024_7fc8
    call Call_024_7fd9
    ld d, h
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    call nc, Call_024_7f9f
    and c
    call z, Call_024_7fcc
    ld c, a
    call nc, $c5c8
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    jp $c155


    jp nc, $d3d0

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    pop bc
    jp nc, Jump_024_7fd0

    call z, $cfcf
    set 2, e
    ld a, a
    push bc
    ret c

    pop bc
    jp $4fd4


    call z, Call_024_7fd9
    ld a, a
    push de
    adc $c6
    push bc
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    and e
    pop bc
    jp nc, Jump_024_7fd0

    call z, $cfcf
    set 2, e
    ld a, a
    push bc
    ret c

    pop bc
    jp $4fd4


    call z, Call_024_7fd9
    ld a, a
    push de
    adc $c6
    push bc
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    adc h
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $cdcf

    ld c, a
    pop bc
    adc $c3
    push bc
    ld a, a
    rst $08
    add $7f
    call $cec1
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $8c4f
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld a, a
    pop bc
    jp $d5d4


    pop bc
    call z, $d9cc
    ld a, a
    call z, $c955
    set 0, l
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $55
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
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
    jp nc, Jump_024_7fc5

    db $d3
    rst $10
    ret


    call $cd4f
    ret


    adc $c7
    ld a, a
    jp nz, Jump_024_7fd9

    jp $c1c8


    adc $c3
    push bc
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    push bc
    pop bc
    db $d3
    reti


    ld a, a
    call nc, Call_024_7fcf
    add $cc
    rst $08
    ld c, a
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    push de
    ret nc

    sbc a
    ld a, a
    set 0, l
    push bc
    ret nc

    ld a, a
    reti


    rst $08
    ld d, l
    push de
    jp nc, $cd7f

    rst $08
    push de
    call nc, Call_024_7fc8
    db $d3
    ret z

    push de
    call nc, Call_024_7f8c
    call nz, Call_024_55cf
    adc $87
    call nc, $d07f
    rst $08
    set 0, l
    ld a, a
    reti


    rst $08
    push de
    jp nc, $ce7f

    rst $08
    db $d3
    ld d, l
    push bc
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $c9c8
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    or a
    pop bc
    ret z

    rst $08
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld a, a
    or a
    pop bc
    ret z

    rst $08
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $08
    add $7f
    call $cec9
    push bc
    ld c, a
    ld a, a
    ret


    db $d3
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c855
    push bc
    ld a, a
    db $d3
    push bc
    pop bc
    adc [hl]
    ld a, a
    ld d, a
    or a
    ret z

    push bc
    jp nc, Jump_024_7fc5

    ret


    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_024_7fd3

    jp Jump_024_4fc1


    push de
    rst $00
    ret z

    call nc, $c67f
    jp nc, $cdcf

    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    pop bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    push bc
    pop bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    jp $d5d4


    pop bc
    call z, $d9cc
    ld a, a
    xor c
    add a
    call $ce7f
    rst $08
    rst $10
    ld c, a
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, $d37f
    ld d, l
    call nc, $c7c1
    push bc
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    xor c
    jp nc, $cecf

    ld a, a
    ld d, l
    xor l
    pop bc
    adc $7f
    call nc, $c9d2
    pop bc
    call nc, $ccc8
    rst $08
    adc $7f
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d47f
    ret


    jp nc, $c4c5

    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    rst $10
    ret


    call z, Call_024_7fcc
    call nc, $cbc1
    push bc
    ld a, a
    ret nc

    pop bc
    jp nc, Jump_024_55d4

    ld a, a
    ret


    adc $7f
    jp nz, $cbc9

    push bc
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call $d2c1
    ld d, l
    pop bc
    call nc, $cfc8
    adc $7f
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    pop bc
    ret z

    rst $08
    rst $08
    ld a, a
    ld d, [hl]
    adc h
    rst $10
    pop bc
    ret z

    rst $08
    rst $08
    ld a, a
    ld c, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    pop bc
    ret z

    rst $08
    rst $08
    ld a, a
    ld d, [hl]
    adc h
    rst $10
    pop bc
    ret z

    rst $08
    rst $08
    ld a, a
    ld c, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    jp $cdcf


    add $cf
    jp nc, Jump_024_4fc1

    jp nz, $c5cc

    ld a, a
    db $d3
    push de
    adc $d3
    ret z

    ret


    adc $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    call nc, $cec1
    adc $c5
    call nz, Call_024_7f8c
    ret z

    ld c, a
    pop bc
    sub $c9
    adc $c7
    ld a, a
    call nc, $cec1
    adc $c5
    call nz, Call_024_7f8e
    pop bc
    rst $10
    add $55
    push de
    call z, $d9cc
    ld a, a
    call nc, $cec1
    adc $c5
    call nz, Call_024_7f81
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
    ret z

    pop bc
    sub $c5
    ld a, a
    ld c, a
    call z, $d3cf
    call nc, Call_024_7f81
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
    ret z

    pop bc
    sub $c5
    ld a, a
    ld c, a
    call z, $d3cf
    call nc, Call_024_7f81
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    push bc
    call $c1c2
    jp nc, $c1d2

    db $d3
    db $d3
    ret


    adc $c7
    ld c, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, $81c5

    ld a, a
    call nz, $cecf
    add a
    call nc, $c87f
    ld d, l
    pop bc
    jp nc, Jump_024_7fcd

    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c17f
    adc $c7
    call z, Call_024_7fc5

Call_024_547f:
    pop bc
    adc $4f
    reti


    call nc, $c9c8
    adc $c7
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_024_7fc5

    ld a, a
    db $d3
    ret z

    rst $08
    ld d, l
    push de
    call z, $cec4
    add a
    call nc, $c27f
    push bc
    ld a, a
    db $d3
    rst $08
    call Call_024_7fc5
    call z, $55c1
    jp nc, $c5c7

    ld a, a
    db $d3
    rst $10
    ret


    call $c9cd
    adc $c7
    ld a, a
    ret nc

    rst $08
    rst $08
    call z, Call_024_7f55
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    rst $08
    ld a, a
    jp nz, $c4c1

    add c
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_024_7fd9

    add $cf
    ld c, a
    jp nc, $c67f

    ret


Call_024_54d3:
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    adc $cf
    call nc, $c9c8
    adc $c7
    ld d, l
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    rst $08
    ld a, a
    jp nz, $c4c1

    add c
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_024_7fd9

    add $cf
    ld c, a
    jp nc, $c67f

    ret


    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    adc $cf
    call nc, $c9c8
    adc $c7
    ld d, l
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    jp $c9d4


    adc $c7
    ld a, a
    pop bc
    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, $cf7f

    ld c, a
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_024_7fc5

    ret z

    pop bc
    ld d, l
    sub $c9
    adc $c7
    ld a, a
    add $c9
    db $d3
    ret z

    push bc
    call nz, $8c7f
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $cec9
    push de
    call nc, Call_024_4fc5
    adc h
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    add $c9
    db $d3
    ret z

    push bc
    call nz, Call_024_7f81
    and c
    ret z

    ld d, l
    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c9
    db $d3
    ret z

    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    db $d3
    rst $10
    ret


    call $c9cd
    adc $c7
    ld a, a
    jp nz, $c3c1

Call_024_5581:
    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a

Call_024_558c:
    jp nz, $c3c5

    rst $08
    call $cec9
    rst $00
    ld a, a
    pop bc
    ld a, a
    ld c, a
    call nc, $cdc9
    push bc
    adc l
    set 1, c
    call z, $cfcc
    jp nc, Jump_024_7f8e

    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld a, a
    jp nz, $c3c5

    rst $08
    call $cec9
    rst $00
    ld a, a
    pop bc
    ld a, a
    ld c, a
    call nc, $cdc9
    push bc
    adc l
    set 1, c
    call z, $cfcc
    jp nc, Jump_024_7f8e

    ld e, b
    nop

Call_024_55c8:
Jump_024_55c8:
    ld a, a

Call_024_55c9:
Jump_024_55c9:
    xor b
    push bc

Jump_024_55cb:
    jp nc, Jump_024_7fc5

    ret


Call_024_55cf:
Jump_024_55cf:
    db $d3
    ld a, a
    call nc, $c5c8

Jump_024_55d4:
    ld a, a

Call_024_55d5:
Jump_024_55d5:
    call $c9c1
    adc $4f

Jump_024_55da:
    ld a, a
    push bc
    adc $d4
    jp nc, $cec1

    jp Jump_024_7fc5


    rst $08
    add $7f
    ld d, h
    ld a, a
    ld d, l
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_024_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    adc $d4
    jp nc, $c14f

    adc $c3
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    pop bc
    call z, $cc55
    ret


    pop bc
    adc $c3
    push bc
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $c1c8


    ld d, l
    call Call_024_7fd0
    jp nc, $c1cf

    call nz, $8c7f
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_024_7f8c
    xor b
    add a
    call Call_024_7f81
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    ld c, a
    push bc
    push bc
    adc $7f
    reti


    rst $08
    push de
    jp nc, $c27f

    jp nc, $d3c9

    bit 7, a
    adc $c1
    ld d, l
    call nc, $d2d5
    push bc
    ld a, a
    db $d3
    ret


    adc $c3
    push bc
    ld a, a
    rst $10
    push bc
    ld a, a
    db $d3
    push bc
    call nc, Call_024_7f55
    rst $08
    push de
    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $55c1

    db $d3
    db $d3

Call_024_567f:
Jump_024_567f:
    adc [hl]
    ld a, a

Call_024_5681:
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    add a
    call $c67f
    jp nc, $c7c9

    ret z

    call nc, $cec5
    push bc
    ld c, a
    call nz, $d47f
    rst $08
    ld a, a
    jp nz, $c9d2

    call nz, $c5c7
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ld d, l
    jp nz, $c5c5

    adc $7f
    ret z

    push bc
    jp nc, Jump_024_7fc5

    ret z

    ret


    call nz, $cec9
    rst $00
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    call nc, $d37f
    call nc, $ccc9
    call z, $d77f
    rst $08
    adc $87
    ld c, a
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    call nc, $d37f
    call nc, $ccc9
    call z, $d77f
    rst $08
    adc $87
    ld c, a
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    rst $10
    ret


    adc $c7
    ld a, a
    jp nz, $c3c1

    res 0, c
    ld a, a
    call nc, $c5c8
    ld a, a
    ld c, a
    add $c9
    add $d4
    ret z

    add c
    ld a, a
    xor c
    add a
    call $d97f
    rst $08
    push de
    jp nc, $cf7f

    ld d, l
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $cf
    ld a, a
    jp nc, $c7c5

    jp nc, $d4c5

    ld c, a
    db $d3
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call $55d9
    ld a, a
    jp nz, $d3c5

    call nc, $577f
    nop
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $d94f

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $d94f

    add c
    ld a, a
    ld e, b
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

Jump_024_5781:
    ret


    db $d3
    ld a, a
    call Call_024_4fc5
    add c
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_024_7fc4
    pop bc
    call z, $cfd3
    ld a, a
    add $c5
    push bc
    ld d, l
    call z, $c67f
    pop bc
    call nc, $c7c9
    push de
    push bc
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $cf
    ld a, a
    jp nc, $c7c5

    jp nc, $d4c5

    ld c, a
    db $d3
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call $55d9
    ld a, a
    jp nz, $d3c5

    call nc, $8e7f
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call $a97f
    ld a, a
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, $d3cf
    call nc, Call_024_4f9f
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    call $a97f
    ld a, a
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, $d3cf
    call nc, Call_024_4f9f
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c9c8
    jp nc, Jump_024_7fc4

    jp $cdcf


    push bc
    ld a, a
    rst $08
    ld c, a
    adc $81
    ld a, a
    xor c
    call nc, $c47f
    rst $08
    push bc
    db $d3
    adc $87
    call nc, $d37f
    rst $08
    ld a, a
    ld d, l
    db $d3
    ret


    call $ccd0
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $cf
    ld a, a
    jp nc, $c7c5

    jp nc, $d4c5

    ld c, a
    db $d3
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call $55d9
    ld a, a
    jp nz, $d3c5

    call nc, $8e7f
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    rst $10
    add $d5
    call z, $d9cc
    ld a, a
    rst $10
    push bc
    pop bc
    bit 1, a
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c17f
    rst $10
    add $d5
    call z, $d9cc
    ld a, a
    rst $10
    push bc

Call_024_587f:
Jump_024_587f:
    pop bc
    bit 1, a
    adc [hl]
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
    jp $cecf


    call nz, $c97f
    db $d3
    ld a, a
    call Call_024_4fc5
    add c
    ld a, a
    and [hl]
    jp nc, $cdcf

    ld a, a
    adc $cf
    rst $10
    ld a, a
    ret


    call nc, $c27f
    push bc
    rst $00
    ld d, l
    ret


    adc $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $cf
    ld a, a
    jp nc, $c7c5

    jp nc, $d4c5

    ld c, a
    db $d3
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call $55d9
    ld a, a
    jp nz, $d3c5

    call nc, $8e7f
    ld a, a
    ld d, a
    nop
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    call z, $c5c9
    sub $c5
    ld a, a
    ret


    ld c, a
    call nc, Call_024_587f
    nop
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    call z, $c5c9
    sub $c5
    ld a, a
    ret


    ld c, a
    call nc, Call_024_587f
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $c9d2

    call nz, $c5c7
    ld a, a
    ret


    db $d3
    ld a, a
    jp Jump_024_4fc1


    call z, $c5cc
    call nz, $c77f
    rst $08
    call z, $c5c4
    adc $7f
    jp nz, $ccc1

    call z, $557f
    jp nz, $c9d2

    call nz, $c5c7
    ld a, a
    add c
    ld a, a
    xor c
    add $7f
    ld a, a
    call nz, $c6c5
    push bc
    ld d, l
    pop bc
    call nc, $c4c5
    ld a, a
    sub l
    ld a, a
    ret nc

    push bc
    jp nc, $cfd3

    adc $7f
    adc h
    ld a, a
    ret z

    ld d, l
    push bc
    ld a, a
    rst $10
    ret


    call z, Call_024_7fcc
    rst $00
    push bc
    call nc, $c17f
    ld a, a
    ret z

    ret


    rst $00
    ret z

    ld d, l
    adc l
    pop de
    push de
    pop bc
    call z, $d4c9
    reti


    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    add c
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    adc $7f
    add c
    ld a, a
    and e
    pop bc
    adc $7f
    ld a, a
    rst $10
    ret


    adc $7f
    reti


    rst $08
    ld d, l
    push de
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $cf
    ld a, a
    jp nc, $c7c5

    jp nc, $d4c5

    ld c, a
    db $d3
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call $55d9
    ld a, a
    jp nz, $d3c5

    call nc, $8e7f
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call $d2c1
    sub $c5
    call z, $817f
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call $d2c1
    sub $c5
    call z, $817f
    ld a, a
    ld c, a
    ld e, b
    nop
    xor b
    push bc
    jp nc, Jump_024_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d0c1


    push bc
    ld a, a
    ld c, a
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call Call_024_7fc5
    rst $08
    add $55
    ld a, a
    xor l
    pop bc
    db $d3
    pop bc
    jp $c9c8


    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $10
    rst $08
    rst $08
    call nz, Call_024_7fd3
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld c, a
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    add $cf
    jp nc, $ce7f

    push bc
    pop bc
    jp nc, $d9c2

    ld d, l
    ld a, a
    ld a, a
    ld e, l
    ld a, a
    ld a, a
    call nc, Call_024_7fcf
    call nc, $cbc1
    ld d, l
    push bc
    ld a, a
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, h
    ld a, a
    xor c
    add $7f
    rst $08
    adc $cc
    reti


    ld a, a
    rst $08
    adc $c5
    ld a, a
    ld c, a
    ret


    db $d3
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    adc h
    ld a, a
    ld a, a
    jp $cec1


    add a
    call nc, Call_024_7f55
    call nz, $c6c5
    push bc
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $55
    push bc
    adc $d4
    ld a, a
    push de
    adc $c6
    pop bc
    call $ccc9
    ret


    pop bc
    jp nc, $cf7f

    jp nc, Jump_024_7f55

    push de
    adc $d3
    set 1, c
    call z, $c5cc
    call nz, Call_024_7f8e
    xor c
    call nc, $d387
    ld a, a
    ld d, l
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    call nc, Call_024_7fcf
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, l
    call $d2cf
    push bc
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    adc $cf
    call nc, $c27f
    pop bc
    call nz, Call_024_7f81
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    adc $cf
    call nc, $c27f
    pop bc
    call nz, Call_024_7f81
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $cec1
    jp Jump_024_7fc5


    ret nc

    pop bc
    jp nc, $d9d4

    ld a, a
    ld c, a
    rst $08
    add $7f
    and c
    adc $ce
    push de
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    ld d, l
    jp nc, $cfc2

    push de
    jp nc, $cf7f

    add $7f
    call nz, $c9d2
    push bc
    call nz, $cc7f
    push bc
    ld d, l
    pop bc
    sub $c9
    push bc
    db $d3
    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc h
    ld d, a
    nop
    or h
    ret z

    push bc
    jp nc, Jump_024_7fc5

    pop bc
    jp nc, Jump_024_7fc5

    call $cec1
    reti


    ld a, a
    ld c, a
    ld e, l
    ld a, a
    ld a, a
    jp $cdcf


    ret


    adc $c7
    ld a, a
    add $55
    jp nc, $cdcf

    ld a, a
    pop bc
    call z, Call_024_7fcc
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    and c
    adc $ce
    push de
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    ld d, l
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c17f
    call nc, $c17f
    call z, Call_024_7fcc
    add $c5
    push bc
    call z, Call_024_4fc9
    adc $c7
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, $008e
    ld a, a
    xor [hl]
    rst $08
    call nc, $c17f
    call nc, $c17f
    call z, Call_024_7fcc
    add $c5
    push bc
    call z, Call_024_4fc9
    adc $c7
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, $008e
    ld a, a
    xor c
    add a
    call $cf7f
    adc $c5
    ld a, a
    rst $08
    add $7f
    ld a, a
    jp nz, $d9cf

    ld a, a
    ld c, a
    db $d3
    jp $d5cf


    call nc, Call_024_7fd3
    xor l
    reti


    ld a, a
    rst $00
    ret


    jp nc, $c6cc

    jp nc, Jump_024_55c9

    push bc
    adc $c4
    ld a, a
    ret


    db $d3
    ld a, a
    call $cec9
    ret


    db $d3
    set 1, c
    jp nc, $81d4

    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    ret z

    push bc
    adc $c5
    sub $c5
    jp nc, Jump_024_7f4f

    ld a, a
    call z, $d4c5
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c77f

    ret


    jp nc, $c6cc

    jp nc, $c955

    push bc
    adc $c4
    ld a, a
    jp $cdcf


    add $cf
    jp nc, Jump_024_7fd4

    call $8ec5
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc [hl]
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc [hl]
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $cd7f
    ret


    adc $c9
    db $d3
    set 1, c
    jp nc, Jump_024_7fd4

    adc h
    ld a, a
    ld c, a
    xor l
    reti


    ld a, a
    jp nz, $d9cf

    add $d2
    ret


    push bc
    adc $c4
    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $cf55

    reti


    ld a, a
    db $d3
    jp $d5cf


    call nc, Call_024_7f81
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    jp nz, $d9cf

    add $d2
    ret


    push bc
    adc $c4
    ld a, a
    db $d3
    ret z

    rst $08
    ld c, a
    push de
    call z, Call_024_7fc4
    jp nz, Jump_024_7fc5

    pop bc

Call_024_5c7f:
    call z, $cfd3
    ld a, a
    db $d3
    push de
    jp Jump_024_7fc8


    ld d, l
    db $d3
    call nc, $cfd2
    adc $c7
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    adc $cf
    call nc, $c97f
    adc $7f
    rst $00
    rst $08
    rst $08
    call nz, $d37f
    call nc, $d4c1
    ld c, a
    push bc
    ld a, a
    ld e, b
    nop
    ld a, a
    adc $cf
    call nc, $c97f
    adc $7f
    rst $00
    rst $08
    rst $08
    call nz, $d37f
    call nc, $d4c1
    ld c, a
    push bc
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_024_567f
    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    pop bc
    ld a, a
    ret nc

    ld c, a
    jp nc, $cdc5

    rst $08
    adc $c9
    call nc, $cfc9
    adc $7f
    call nc, $c1c8
    call nc, $a97f
    ld d, l
    add a
    call z, Call_024_7fcc
    jp $cecf


    call nc, $d3c5
    call nc, $d77f
    ret


    call nc, Call_024_7fc8
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c3c1
    call nc, $c3c9
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    ld c, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    jp nz, $c4c1

    ld a, a
    call nc, Call_024_7fcf
    push bc
    ret c

    jp $c855


    pop bc
    adc $c7
    push bc
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    pop bc
    call nc, $cf7f
    adc $c3
    ld d, l
    push bc
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    jp nz, $c9c5

    adc $c7
    ld a, a
    ret nc

    push de
    jp c, Jump_024_55da

    call z, $c4c5
    adc [hl]
    ld d, a
    nop
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cdc5

    rst $08
    adc $c9
    call nc, Call_024_4fc9
    rst $08
    adc $7f
    call nc, $c1c8
    call nc, $c87f
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    call z, $d3cf
    ld d, l
    ret


    adc $c7
    ld a, a
    adc h
    ld e, b
    nop
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cdc5

    rst $08
    adc $c9
    call nc, Call_024_4fc9
    rst $08
    adc $7f
    call nc, $c1c8
    call nc, $c87f
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    call z, $d3cf
    ld d, l
    ret


    adc $c7
    ld a, a
    adc h
    ld e, b
    nop
    ld a, a
    and [hl]
    jp nc, $c5c9

    adc $c4
    db $d3
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call $cec1
    ld c, a
    reti


    ld a, a
    call z, $d6cf
    push bc
    call z, Call_024_7fd9
    ld d, h
    ld a, a
    ld a, a
    ld d, [hl]
    adc h
    ld d, l
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    adc $c7
    jp nc, $81d9

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    jp nc, Jump_024_7fc5

    reti


    rst $08
    push de
    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld c, a
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    ld a, a
    call Call_024_55cf
    push de
    adc $d4
    pop bc
    ret


    adc $9f
    ld a, a
    call nc, $c5c8
    adc $8c
    ld a, a
    xor c
    ld a, a
    rst $10
    ld d, l
    pop bc
    adc $d4
    ld a, a
    call Call_024_7fd9
    and d
    rst $08
    jp nz, $81cf

    ld a, a
    xor b
    add a
    call Call_024_558c
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    call Call_024_7fc5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c17f
    call nc, $c17f
    call z, Call_024_7fcc
    add $c5
    push bc
    call z, Call_024_4fc9
    adc $c7
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, Call_024_7f8e
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c17f
    call nc, $c17f
    call z, Call_024_7fcc
    add $c5
    push bc
    call z, Call_024_4fc9
    adc $c7
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, Call_024_7f8e
    ld e, b
    nop
    ld a, a
    xor d
    push de
    db $d3
    call nc, $c47f
    rst $08
    rst $10
    adc $7f
    ld a, a
    add $d2
    rst $08
    call Call_024_4f7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    ld d, l
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    db $d3
    call nc, $ccc9
    call z, $c67f
    ld d, l
    push de
    call z, Call_024_7fcc
    rst $08
    add $7f
    sub $c9
    rst $00
    rst $08
    push de
    jp nc, Jump_024_5781

    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    ld a, a
    add c
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    jp nz, $d4c9

    call nc, $c54f
    adc $7f
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp $d6c1


    push bc
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ret z

    pop bc
    jp nc, $91c4

    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ret z

    pop bc
    jp nc, $91c4

    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c77f
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_024_7fcf
    push bc
    adc $ca
    ld c, a
    rst $08
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld a, a
    ld d, l
    jp $cccf


    call z, $c3c5
    call nc, $c4c5
    ld a, a
    jp nz, Jump_024_7fd9

    add $c1
    adc $c1
    ld d, l
    call nc, $c3c9
    db $d3
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    call z, $d6c9
    ret


    adc $55
    rst $00
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp $d0c1


    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
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
    pop bc
    ld c, a
    jp nc, Jump_024_7fc5

    call nc, $cec1
    pop bc
    call nc, $c3c9
    db $d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ld d, l
    ret z

    rst $08
    push de
    call z, Call_024_7fc4
    ret z

    pop bc
    sub $c5
    ld a, a
    sub $c1
    jp nc, $c5c9

    call nc, $d955
    ld a, a
    rst $08
    add $7f
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    pop bc
    call z, $c9cc
    adc $c7
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $d9c5

    ld a, a
    call nc, $cf4f
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d4cf
    ld a, a
    ld e, b
    nop
    ld a, a
    and [hl]
    pop bc
    call z, $c9cc
    adc $c7
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $d9c5

    ld a, a
    call nc, $cf4f
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d4cf
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    jp nc, Jump_024_7fc5

    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_024_4fcf
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call Call_024_7fc5
    rst $08
    add $7f
    xor l
    pop bc
    db $d3
    pop bc
    ld d, l
    jp $c9c8


    sbc a
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, $c27f
    push bc
    add $cf
    ld d, l
    jp nc, Jump_024_7fc5

    rst $00
    rst $08
    ret


    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    add $c1
    db $d3
    call nc, $d2c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    rst $00
    rst $08
    ld a, a
    db $d3
    ret


    call nz, $d7c5
    pop bc
    call z, $c9cb
    adc $c7
    ld a, a
    rst $10
    ret z

    ld d, l
    push bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    ld a, a
    jp nz, $c3c1

    bit 7, a
    call nc, Call_024_55cf
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    jp $c955


    call nc, Call_024_7fd9
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_024_7f81
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_024_7f81
    ld e, b
    nop
    ld a, a
    ld a, a
    ld d, h
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, $d6c9
    push bc
    ld a, a
    ret


    ld c, a
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld d, l
    ret z

    push de
    call $cec1
    add c
    ld a, a
    xor h
    push bc
    call nc, $c87f
    ret


    call Call_024_7f7f
    ret z

    ld d, l
    pop bc
    sub $c5
    ld a, a
    pop bc
    jp nc, $d3c5

    call nc, $d77f
    ret z

    push bc
    adc $7f
    rst $10
    ret


    ld d, l
    call nc, $cfc8
    push de
    call nc, $d37f
    call nc, $c5d2
    adc $c7
    call nc, $8ec8
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    call $d0c1
    ld a, a
    rst $08
    add $7f
    call nc, Call_024_4fc8
    push bc
    ld a, a
    xor [hl]
    rst $08
    jp nc, $c8d4

    push bc
    pop bc
    db $d3
    call nc, Call_024_5681
    adc h
    ld a, a
    and c
    ld d, l
    jp nc, Jump_024_7fc5

    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    reti


    ld a, a
    ret


    add $7f
    ret


    ld d, l
    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    db $d3
    call nc, $cccf
    push bc
    adc $7f
    jp nz, Jump_024_7fd9

    push de
    ld d, l
    db $d3
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    add $cf
    jp nc, $cfc7

    ld c, a
    call nc, $c5d4
    adc $7f
    call nc, $c5c8
    call $c17f
    call z, $81cc
    ld a, a
    or a
    ret z

    ld d, l
    pop bc
    call nc, $d387
    ld a, a
    call $d4c1
    call nc, $d2c5
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    adc h
    ld a, a
    xor b
    add a
    call $d98c
    push bc
    ld c, a
    db $d3
    add c
    ld a, a
    or a
    rst $08
    push de
    call z, Call_024_7fc4
    reti


    rst $08
    push de
    ld a, a
    jp nz, Jump_024_7fc5

    bit 2, l
    ret


    adc $c4
    ld a, a
    push bc
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    call nc, Call_024_7fcf
    call nz, Call_024_7fcf
    ld d, l
    db $d3
    call nc, $8ec8
    ld a, a
    add $cf
    jp nc, $cd7f

    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $c2c1
    call z, Call_024_7fc5
    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    call Call_024_7fd9
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ret z

    ld d, l
    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld a, a
    ld d, l
    add $cf
    push de
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $d4c1
    pop bc
    ld a, a
    ld a, a
    rst $08
    ld d, l
    add $7f
    ld d, h
    adc [hl]
    ld a, a
    xor c
    call nc, $c37f
    pop bc
    adc $7f
    jp nc, $c3c5

    ld d, l
    rst $08
    jp nc, Jump_024_7fc4

    pop bc
    push de
    call nc, $cdcf
    pop bc
    call nc, $c3c9
    pop bc
    call z, $d9cc
    ld d, l
    ld a, a
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
    pop bc
    call z, $cfd3
    ld a, a
    ret


    ld d, l
    adc $c3
    jp nc, $c1c5

    db $d3
    push bc
    ld a, a
    pop bc
    push de
    call nc, $cdcf
    pop bc
    call nc, $c3c9
    ld d, l
    pop bc
    call z, $d9cc
    ld a, a
    and c
    ld a, a
    ret z

    ret


    rst $00
    ret z

    ld a, a
    db $d3
    jp $c5c9


    adc $55
    jp $8dc5


    call nc, $c3c5
    ret z

    adc $cf
    call z, $c7cf
    ret


    jp $ccc1


    call z, $d955
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
    rst $08
    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    adc h
    ld a, a
    ld d, d
    ld a, a
    ld c, a
    ld d, e
    ld a, a
    adc h
    call nc, $c5c8
    db $d3
    push bc
    ld a, a
    pop bc
    call z, Call_024_7fcc
    ld d, l
    pop bc
    jp nc, Jump_024_7fc5

    set 0, l
    ret nc

    call nc, $c87f
    push bc
    jp nc, Jump_024_7fc5

    jp nz, Jump_024_7fd9

    ld d, l
    reti


    rst $08
    push de
    add c
    ld a, a
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    ret


    push bc
    ld d, l
    sub $c5
    call nz, $d47f
    ret z

    push bc
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c555
    call nz, $c87f
    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    rst $08
    add $7f
    ld d, l
    ld d, h
    ld a, a
    add $d2
    rst $08
    call $a17f
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld d, l
    ld a, a
    add c
    ld a, a
    ld d, b
    ld de, $0050
    ld a, a
    or d
    push bc
    jp $d2cf


    call nz, $c17f
    call z, Call_024_7fcc
    call $c4c1
    push bc
    adc l
    ld c, a
    ret nc

    push bc
    jp nc, $c5c6

    jp $ccd4


    reti


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

    set 2, e
    ld a, a
    rst $08
    add $55
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $cc55

    call nz, Call_024_7f81
    ld a, a
    call nc, $c1c8
    call nc, $d387
    ld a, a
    call Call_024_7fd9
    call nz, $55d2
    push bc
    pop bc
    call Call_024_7f81
    ld a, a
    jp nz, $d4d5

    adc h
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    jp nz, $c555

    jp $cdcf


    push bc
    ld a, a
    pop bc
    adc $7f
    rst $08
    call z, $cdc4
    pop bc
    adc $81
    ld a, a
    ld d, l
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $d57f
    adc $c4
    push bc
    jp nc, $c1d4

    bit 2, l
    push bc
    ld a, a
    call nc, Call_024_7fcf
    call nz, Call_024_7fcf
    pop bc
    ld a, a
    call nz, $c6c9
    add $c9
    jp Jump_024_55d5


    call z, Call_024_7fd4
    jp z, $c2cf

    ld a, a
    pop bc
    db $d3
    ld a, a
    jp nz, $d3c5

    call nc, $cf7f
    adc $55
    push bc
    ld a, a
    jp $cec1


    add c
    ld a, a
    ld a, a
    call nc, $d5c8
    db $d3
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    ld a, a
    jp nc, $d0c5

    call z, $c3c1
    push bc
    ld a, a
    call Call_024_7fc5
    ld a, a
    call nc, Call_024_7fcf
    ld d, l
    jp nc, $c1c5

    call z, $dac9
    push bc
    ld a, a
    call Call_024_7fd9
    call nz, $c5d2
    pop bc
    call Call_024_5581
    ld a, a
    ld a, a
    call nc, $c5c8
    adc $8c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $cfd7
    ld a, a
    ld a, a
    ld d, l
    db $d3
    push bc
    call nc, $cf7f
    push de
    call nc, $c17f
    call nc, $cf7f
    adc $c3
    push bc
    add c
    ld a, a
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
    rst $00
    jp nc, $c1c5

    call nc, $557f
    jp z, $c2cf

    ld a, a
    call z, $c6c5
    call nc, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    ld d, l
    ret


    db $d3
    call nc, $d2cf
    reti


    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    adc h
    ld a, a
    reti


    push bc
    db $d3
    adc h
    ld a, a
    rst $00
    jp nc, $cec1

    ld c, a
    call nz, $c1d0
    add c
    ld a, a
    xor d
    push de
    db $d3
    call nc, $cc7f
    push bc
    pop bc
    sub $c5
    ld a, a
    ret


    ld d, l
    call nc, $c17f
    call z, Call_024_7fcc
    call nc, Call_024_7fcf
    call $81c5
    ld a, a
    ld a, a
    ld d, l
    ld d, d
    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    ret nc

    ret


    call nc, $d955
    ld a, a
    call nc, $c1c8
    call nc, $c97f
    call nc, $d77f
    rst $08
    push de
    call z, $cec4
    add a
    ld d, l
    call nc, $c27f
    push bc
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d47f

    push de
    jp nc, Jump_024_7fce

    adc $c5
    ld d, l
    ret c

    call nc, Call_024_7f81
    ld a, a
    reti


    rst $08
    push de
    add a
    jp nc, Jump_024_7fc5

    jp nc, $c7c9

    ret z

    call nc, $8155
    ld a, a
    and d
    rst $08
    jp nc, $cfd2

    rst $10
    ld a, a
    pop bc
    ld a, a
    call $d0c1
    ld a, a
    rst $08
    add $55
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d4c9


    reti


    ld a, a
    add $d2
    rst $08
    call $cd7f
    reti


    ld d, l
    ld a, a
    push bc
    call z, $c5c4
    jp nc, $d37f

    ret


    db $d3
    call nc, $d2c5
    ld a, a
    add c
    ld a, a
    adc h
    ld d, l
    ld a, a
    or h
    push bc
    call z, Call_024_7fcc
    call Call_024_7fd9
    push bc
    call z, $c5c4
    jp nc, $d37f

    ret


    ld d, l
    db $d3
    call nc, $d2c5
    ld a, a
    ld a, a
    adc $cf
    call nc, $c27f
    rst $08
    jp nc, $cfd2

    rst $10
    ld a, a
    ld d, l
    ret


    call nc, $d47f
    rst $08
    ld a, a
    ld d, d
    adc [hl]
    ld a, a
    reti


    rst $08
    push de
    add a
    ld d, l
    call z, Call_024_7fcc
    rst $10
    pop bc
    db $d3
    call nc, Call_024_7fc5
    reti


    rst $08
    push de
    jp nc, $c57f

    adc $c5
    ld d, l
    jp nc, $d9c7

    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    reti


    rst $08
    push de
    jp nc, $c87f

    ld d, l
    pop bc
    sub $c9
    adc $c7
    ld a, a
    pop bc
    jp nc, $c9d2

    sub $c5
    call nz, $c17f
    call nc, $557f
    call z, $d4cf
    push de
    db $d3
    ld a, a
    ret nc

    rst $08
    rst $08
    call z, Call_024_7f81
    ld d, a
    nop
    ld a, a
    or l
    db $d3
    push bc
    ld a, a
    ret


    call nc, $c17f
    db $d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, Call_024_4fc9
    set 0, l
    add c
    ld a, a
    ld a, a
    ld e, e
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    jp Jump_024_55cf


    jp nc, $c5ce

    jp nc, Jump_024_567f

    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    call z, $c5d2
    pop bc
    ld d, l
    call nz, Call_024_7fd9
    rst $10
    pop bc
    jp nc, $c5ce

    call nz, $d47f
    ret z

    push bc
    ld a, a
    rst $00
    ret


    jp nc, $cc55

    ld a, a
    pop bc
    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    ld a, a
    rst $08
    adc $7f
    call nc, Call_024_55c8
    push bc
    ld a, a
    db $d3
    push bc
    jp nc, $c9d6

    jp Jump_024_7fc5


    call nz, $d3c5
    res 1, [hl]
    ld a, a
    sub $55
    push bc
    jp nc, Jump_024_7fd9

    jp c, $c1c5

    call z, Call_024_7f8c
    call nz, Call_024_7fcf
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    call nc, $c9c8
    adc $cb
    ld a, a
    db $d3
    rst $08
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cec5


    call nc, $c5d2
    ld a, a
    rst $08
    add $7f
    ld c, a
    ld d, h
    adc h
    ld a, a
    and d
    push bc
    add $d2
    rst $08
    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_024_7fc5

    ld d, l
    adc h
    ld a, a
    rst $10
    ret z

    ret


    jp $c5c8


    sub $c5
    jp nc, $c37f

    ret


    call nc, Call_024_7fd9
    ld d, l
    ret z

    pop bc
    db $d3
    ld a, a
    ret


    call nc, $c381
    ret z

    push bc
    jp Jump_024_7fcb


    add $d2
    push bc
    push bc
    ld d, l
    add c
    ld d, a
    nop
    ld a, a
    call nc, $c5c8
    adc $8c
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $cd7f

    ld c, a
    push bc
    ld a, a
    call nc, Call_024_7fcf
    and h
    jp nc, Jump_024_7f8e

    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    rst $08
    ld a, a
    call $cecf
    rst $08
    ret nc

    rst $08
    call z, Call_024_55c9
    jp c, Jump_024_7fc5

    ld a, a
    pop bc
    adc $d4
    ret


    call nz, $d4cf
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
    adc $cf
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call nc, $c1d2
    push de
    call $c14f
    call nc, Call_024_7fcf
    call $c4c5
    ret


    jp $cec9


    push bc
    ld a, a
    ld d, [hl]
    call z, Call_024_55cf
    rst $08
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    push bc
    call z, $c9cc
    adc $c7
    ld a, a
    ld d, l
    rst $08
    push de
    call nc, Call_024_7f8e
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    and c
    jp nc, Jump_024_7fc5

    reti


    rst $08
    push de
    ld a, a
    ld c, a
    jp $cdcf


    push bc
    ld a, a
    add $d2
    rst $08
    call $d77f
    ret z

    ret


    call nc, Call_024_7fc5
    jp $c955


    call nc, $9fd9
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
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    and h
    jp nc, Jump_024_7f8e

    ld c, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc a
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
    push bc
    adc $d4
    jp nc, $d3d5

    call nc, $c4c5
    ld a, a
    adc [hl]
    ld a, a
    and e
    pop bc
    adc $7f
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call nc, $c1d2
    adc $d3
    call $d4c9
    ld a, a
    ret


    call nc, $c67f
    ld d, l
    rst $08
    jp nc, $cd7f

    push bc
    sbc a
    ld a, a
    ld d, d
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ld d, l
    jp $c5c8


    jp $c5cb


    call nz, $d47f
    ret z

    push bc
    ld a, a
    ret nc

    rst $08
    db $d3
    call nc, $55c1
    call z, $d07f
    pop bc
    jp nc, $c5c3

    call z, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    add c
    ld a, a
    ld d, b
    ld de, $0050
    ld a, a
    xor b
    xor c
    adc h
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ld c, a
    ret z

    pop bc
    call nc, $d47f
    ret z

    ret


    db $d3
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    call $cecf
    ld d, l
    rst $08
    ret nc

    rst $08
    call z, $dac9
    push bc
    ld a, a
    ld a, a
    pop bc
    adc $d4
    ret


    call nz, $d4cf
    push bc
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    adc $cf
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call nc, $c1d2
    push de
    call $c14f
    call nc, Call_024_7fcf
    call $c4c5
    ret


    jp $cec9


    push bc
    ld a, a
    ld d, [hl]
    call z, Call_024_55cf
    rst $08
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    db $d3
    push bc
    call z, $c9cc
    adc $c7
    ld a, a
    ld d, l
    rst $08
    push de
    call nc, Call_024_7f8e
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_024_7f8c
    xor c
    add a
    sub $c5
    ld a, a
    jp nc, $cdc5

    push bc
    call Call_024_4fc2
    push bc
    jp nc, $c4c5

    ld a, a
    pop bc
    call z, Call_024_7fcc
    call nc, $c5c8
    ld a, a
    jp $cecf


    call nc, $c555
    adc $d4
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    adc $cf
    call nc, $c2c5
    ld d, l
    rst $08
    rst $08
    res 1, h
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    xor c
    add c
    ld a, a
    adc [hl]
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
    ld c, a
    call nz, $cc7f
    rst $08
    rst $08
    bit 7, a
    call nc, Call_024_7fcf
    call nc, $c5c8
    ld a, a
    jp $cecf


    ld d, l
    call nc, $cec5
    call nc, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c1cc

    jp Jump_024_55cb


    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, Call_024_7f4f
    pop bc
    adc $c4
    ld a, a
    pop bc
    adc $7f
    ret


    adc $d4
    push bc
    jp nc, $d3c5

    call nc, Call_024_55c9
    adc $c7
    ld a, a
    call nc, $c9c8
    adc $c7
    ld a, a
    call nc, Call_024_7fcf
    jp $cecf


    db $d3
    ret


    ld d, l
    call nz, $d2c5
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, Call_024_7fcf
    adc $c9
    jp $cecb


    pop bc
    ld d, l
    call Call_024_7fc5
    add c
    ld a, a
    ld a, a
    and c
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call Call_024_7fc5
    ld d, l
    call nc, $d3c1
    call nc, $c6c5
    push de
    call z, $c97f
    db $d3
    ld a, a
    adc $cf
    call nc, $c27f
    ld d, l
    pop bc
    call nz, Call_024_7f8c
    jp nz, $d4d5

    ld a, a
    pop bc
    ld a, a
    adc $c1
    call Call_024_7fc5
    push bc
    pop bc
    ld d, l
    db $d3
    ret


    call z, Call_024_7fd9
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $c4c5

    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d3c5

    call nc, Call_024_7f81
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
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, Call_024_4fc9
    set 0, l
    ld a, a
    ld d, h
    ld a, a
    sub $c5
    jp nc, Jump_024_7fd9

    call $c3d5
    ret z

    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    ret nc

    pop bc
    jp nc, $cfd2

    rst $10
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    call nc, $c9d7
    ld c, a
    call nc, $c5d4
    jp nc, $cec9

    rst $00
    ld a, a
    jp nz, $c1c1

    adc h
    jp nz, $c1c1

    adc h
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and c
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

    ld c, a
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    jp nz, $c4c1

    rst $00
    push bc
    ld d, l
    adc h
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    push bc
    sub $c5
    jp nc, $c87f

    pop bc
    db $d3
    ld a, a
    ret z

    rst $08
    ld d, l
    rst $10
    ld a, a
    ret z

    ret


    rst $00
    ret z

    ld a, a
    call z, $d6c5
    push bc
    call z, $cf7f
    add $7f
    adc h
    ld d, l
    ld a, a
    ld d, h
    adc h
    ld a, a
    rst $10
    ret


    call z, Call_024_7fcc
    pop bc
    jp Jump_024_7fd4


    push de
    ret nc

    ld d, l
    rst $08
    adc $7f
    rst $10
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    db $d3
    ld d, l
    pop bc
    reti


    db $d3
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    pop bc
    ld a, a
    db $d3
    ret


    ld d, l
    rst $00
    adc $7f
    rst $08
    add $7f
    jp nc, $c1c5

    call z, Call_024_7f7f
    ld d, l
    ld e, l
    add c
    ld a, a
    ld a, a
    ret


    add $7f
    db $d3
    rst $08
    adc h
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    jp $c1c8


    call z, $c5cc
    adc $c7
    push bc
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, h
    add c
    ld a, a
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    adc h
    ld d, [hl]
    add c
    ld a, a
    and e
    ld d, l
    ret z

    pop bc
    call z, $c5cc
    adc $c7
    push bc
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $55cc
    ret


    pop bc
    adc $c3
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    nop
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_024_4f7f
    ld e, h
    ld a, a
    sub d
    sub a
    add $55
    jp nc, $cdcf

    ld a, a
    db $d3
    pop bc
    set 0, c
    jp $c9c8


    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    ld d, l
    ld e, h
    sub d
    sub a
    ret


    db $d3
    ld d, l
    ld a, a
    push bc
    pop bc
    jp nc, $c8d4

    jp $c1d2


    jp $81cb


    or h
    ret z

    push bc
    ld a, a
    push bc
    ld d, l
    adc $c5
    call Call_024_7fd9
    ld a, a
    ret


    adc $d6
    ret


    call nc, $c4c5
    ld a, a
    jp nz, Jump_024_7fd9

    ld d, l
    call nc, $c5c8
    ld a, a
    jp nc, $c6c9

    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    call nz, $d7cf
    adc $55
    ld a, a
    rst $08
    add $c6
    add c
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $55d2
    rst $08
    adc $c7
    push bc
    db $d3
    call nc, $d37f
    set 1, c
    call z, $81cc
    ld a, a
    ld a, a
    or a
    ret z

    ld d, l
    push bc
    adc $7f
    ld a, a
    xor c
    ld a, a
    jp nc, $cec1

    ld a, a
    rst $00
    reti


    call $557f
    ld d, h
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_024_7fc5

    adc h
    ld a, a
    xor c
    ld a, a
    call $55c1
    call nz, Call_024_7fc5
    ld d, [hl]
    adc h
    ld a, a
    ld d, a
    nop
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
    add c
    ld c, a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    call nc, $c5c8
    adc $7f
    ld d, [hl]
    ld a, a
    ld a, a
    rst $00
    jp nc, $c4c1

    ld c, a
    push de
    pop bc
    call z, $d9cc
    ld a, a
    add $c5
    push bc
    call z, Call_024_7fd3
    add $c1
    call nc, $c7c9
    ld d, l
    push de
    push bc
    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    rst $10
    ret


    call nc, $cfc8
    push de
    call nc, $d37f
    call nc, $c5d2
    adc $4f
    rst $00
    call nc, $8cc8
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    ret


    call $cfd0
    db $d3
    db $d3
    ld d, l
    ret


    jp nz, $c5cc

    ld a, a
    add $cf
    jp nc, Jump_024_7f7f

    call nc, Call_024_7fcf
    call nz, $c6c5
    push bc
    ld d, l
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_024_7f81
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    call nc, $c5d2
    adc $4f
    rst $00
    call nc, Call_024_7fc8
    pop bc
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    call nc, $c5d2
    adc $4f
    rst $00
    call nc, Call_024_7fc8
    pop bc
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor l
    reti


    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_024_7fd9

    jp nc, $c1c5

    ld c, a
    jp $c5c8


    call nz, $d47f
    ret z

    push bc
    ld a, a
    ret z

    ret


    rst $00
    ret z

    push bc
    db $d3
    call nc, $557f
    call nc, $c4c9
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
    reti


    rst $08
    push de
    jp nc, $c57f

    ret c

    ld c, a
    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    add $c1
    jp nc, $c97f

    adc $c6
    ld d, l
    push bc
    jp nc, $cfc9

    jp nc, $d47f

    rst $08
    ld a, a
    ld d, a
    nop
    ld a, a
    call $d2cf
    adc $c9
    adc $c7
    add c
    ld a, a
    nop
    ld a, a
    or h
    pop bc
    set 0, l
    ld a, a
    call nc, $c5c8
    call $cf7f
    add $c6
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    call nc, $c5c8
    ld a, a
    jp nz, $d3c5

    call nc, Call_024_4f7f
    call $c3c1
    call nc, $c5c8
    db $d3
    ld a, a
    ld a, a
    jp nz, $d4c5

    rst $10
    push bc
    push bc
    adc $7f
    ld d, l
    db $d3
    ld a, a
    rst $08
    add $7f
    call $cec9
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, l
    ld d, h
    add a
    db $d3
    add c
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
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $cf7f
    add $55
    ld a, a
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    set 0, l
    push bc
    ld c, a
    ret nc

    ld a, a
    ret


    adc $7f
    db $d3
    call nc, $d0c5
    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    set 0, l
    push bc
    ld c, a
    ret nc

    ld a, a
    ret


    adc $7f
    db $d3
    call nc, $d0c5
    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    ld a, a
    push bc
    call $d4cf
    reti


    adc l
    ret z

    pop bc
    adc $c4
    ld c, a
    push bc
    call nz, $ca7f
    push de
    call nz, $81cf
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ld d, l
    call nc, $cfd2
    adc $c7
    push bc
    db $d3
    call nc, $d77f
    jp nc, $d3c5

    call nc, $c5cc
    ld a, a
    ld d, l
    db $d3
    set 1, c
    call z, Call_024_7fcc
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $55cc

    call nz, Call_024_7f81
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    xor c
    ld a, a
    rst $10
    ret


    db $d3
    ret z

    ld a, a
    ld c, a
    ld d, h
    ld a, a
    ret z

    pop bc
    call nz, $cd7f
    pop bc
    db $d3
    call nc, $d2c5
    push bc
    call nz, $557f
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
    call nz, Call_024_55cf
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    jp $c5c8


    db $d3
    call nc, Call_024_7f81
    ld e, b
    nop
    ld a, a
    jp $c5c8


    db $d3
    call nc, Call_024_7f81
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $10
    ret


    adc $ce
    ret


    adc $c7
    ld a, a
    call $d4c5
    ret z

    ld c, a
    rst $08
    call nz, $cf7f
    add $7f
    jp nc, $d3c5

    ret


    db $d3
    call nc, $cec1
    call nc, $557f
    ld e, l
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    ld d, l
    add $7f
    call nc, $c5c8
    ld a, a
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $81d9

    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret


    call z, Call_024_7fcc
    jp nz, Jump_024_7fc5

    rst $00
    ret


    sub $c5
    ld c, a
    adc $7f
    pop bc
    ld a, a
    db $d3
    jp $cccf


    call nz, $cec9
    rst $00
    ld a, a
    jp nz, Jump_024_7fd9

    call nc, $c855
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_024_567f
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    pop bc
    jp $c9c3


    call nz, $cec5
    call nc, $ccc1
    call z, Call_024_7fd9
    call nz, $c6c5
    ld c, a
    push bc
    pop bc
    call nc, $c4c5
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    pop bc
    jp $c9c3


    call nz, $cec5
    call nc, $ccc1
    call z, Call_024_7fd9
    call nz, $c6c5
    ld c, a
    push bc
    pop bc
    call nc, $c4c5
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
    call $d3c1
    call nc, $d2c5
    ld a, a
    rst $08
    add $7f
    call nc, Call_024_4fc8
    push bc
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
    ld d, l
    call nz, $81cf
    ld a, a
    and a
    rst $08
    ret


    adc $c7
    ld a, a
    add $d5
    jp nc, $c8d4

    push bc
    jp nc, Jump_024_7f55

    add $d2
    rst $08
    call $c87f
    push bc
    jp nc, Jump_024_7fc5

    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    ld d, l
    jp nc, $c9c2

    call nz, $c5c4
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    ld c, a
    adc $c3
    push bc
    ld a, a
    ld d, h
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c77f

    rst $08
    pop bc
    call z, $9f55
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    reti


    rst $08
    push de
    adc $c7
    ld a, a
    jp nz, $d555

    call nc, $d37f
    call nc, $c1c5
    call nz, Call_024_7fd9
    jp nz, $d9cf

    add c
    ld a, a
    ld d, a
    nop
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
    ret z

    pop bc
    sub $4f
    ret


    adc $c7
    ld a, a
    add $c1
    call z, $c5cc
    adc $81
    ld a, a
    ld e, b
    nop
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
    ret z

    pop bc
    sub $4f
    ret


    adc $c7
    ld a, a
    add $c1
    call z, $c5cc
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
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
    jp $c54f


    call nz, $c27f
    reti


    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, Call_024_7f81
    xor b
    push bc
    ld d, l
    reti


    add c
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
    add $d2
    ld d, l
    ret


    rst $00
    ret z

    call nc, $cec5
    sbc a
    ld a, a
    call nz, $cecf
    add a
    call nc, $c67f
    jp nc, Jump_024_55c9

    rst $00
    ret z

    call nc, $cec5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call $d77f
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $cec9
    push de
    call nc, $c54f
    add c
    ld a, a
    jp z, $d3d5

    call nc, $c37f
    pop bc
    jp nc, $ccc5

    push bc
    db $d3
    db $d3
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ret nc

    pop bc
    ret


    adc $c6
    push de
    call z, Call_024_7f8c
    ret nc

    pop bc
    ret


    adc $4f
    add $d5
    call z, Call_024_7f81
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ret nc

    pop bc
    ret


    adc $c6
    push de
    call z, Call_024_7f8c
    ret nc

    pop bc
    ret


    adc $4f
    add $d5
    call z, Call_024_7f81
    ld e, b
    nop
    ld a, a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    reti


    call Call_024_7f7f
    rst $08
    add $7f
    push bc
    sub $c5
    ld c, a
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    jp $d4c9


    reti


    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    call nc, $c955
    call z, Call_024_7fcc
    jp $cfcc


    db $d3
    push bc
    call nz, $d57f
    adc $d4
    ret


    call z, $557f
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c37f
    rst $08
    call $d3c5
    ld a, a
    adc [hl]
    and [hl]
    ld d, l
    jp nc, $cdcf

    ld a, a
    call nc, $c4cf
    pop bc
    reti


    adc h
    ld a, a
    ret


    call nc, $d27f
    push bc
    call nc, $d555
    jp nc, $d3ce

    ld a, a
    call nc, Call_024_7fcf
    adc $cf
    jp nc, $c1cd

    call z, Call_024_7f81
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, [hl]
    db $d3
    call nc, $c9d2
    sub $c5
    ld a, a
    add $cf
    jp nc, Jump_024_7f4f

    call nc, $c5c8
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret


    adc $7f
    call nc, Call_024_55c8
    push bc
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
    ld d, l
    push bc
    adc $7f
    jp $d4c9


    reti


    ld a, a
    add c
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    push bc
    ret c

    call nc, $c1d2
    ld c, a
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    push bc
    ret c

    call nc, $c1d2
    ld c, a
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    jp nz, $c5c5

    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, Jump_024_4fcf

    jp Jump_024_7fcb


    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    call nc, $ced5
    adc $c5
    ld d, l
    call z, $c27f
    push de
    call nc, Call_024_7f7f
    ret


    call nc, $d387
    ld a, a
    ret nc

    ret


    call nc, $c8c3
    ld d, l
    adc l
    call nz, $d2c1
    res 1, h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ld d, l
    ret


    jp Jump_024_7f81


    xor c
    ld a, a
    rst $10
    ret


    db $d3
    ret z

    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    call nz, $557f
    pop bc
    ld a, a
    add $cc
    pop bc
    db $d3
    ret z

    ld a, a
    call z, $cdc1
    ret nc

    ld a, a
    call nc, Call_024_7fcf
    call z, $c955
    rst $00
    ret z

    call nc, Call_024_547f
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    rst $08
    call nz, $d34f
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp $d6c1


    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, $55c5

    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    call $cec1
    reti


    ld a, a
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    or a
    ld d, l
    push bc
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $cc7f

    rst $08
    rst $08
    bit 7, a
    add $55
    rst $08
    jp nc, $c57f

    sub $c5
    jp nc, $d7d9

    ret z

    push bc
    jp nc, Jump_024_7fc5

    ret


    add $7f
    ld d, l
    rst $10
    push bc
    ld a, a
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_024_7fcf
    jp $d4c1


    jp Jump_024_55c8


    ld a, a
    sub $c1
    jp nc, $cfc9

    push de
    db $d3
    ld a, a
    ld d, h
    db $d3
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_024_7fc5

    pop bc
    jp nc, Jump_024_7fc5

    call $cec1
    reti


    ld a, a
    db $d3
    ld c, a
    call z, $cec5
    call nz, $d2c5
    db $d3
    ld a, a
    pop bc
    jp nc, $d5cf

    adc $c4
    ld a, a
    call nc, Call_024_55c8
    push bc
    ld a, a
    jp nc, $c1cf

    call nz, $c18c
    jp nc, $cec5

    add a
    call nc, $d47f
    ret z

    push bc
    ld d, l
    jp nc, $9fc5

    ld a, a
    adc h
    ld a, a
    jp $d4d5


    ld a, a
    call nc, $c5c8
    call $cf7f
    add $55
    add $7f
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $c9d2
    jp Jump_024_55cb


    ld a, a
    rst $08
    add $7f
    ld d, h
    add a
    db $d3
    adc h
    ld a, a
    call nc, $c5c8
    adc $7f
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    ld d, l
    rst $00
    ret z

    adc h
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
    call nz, $c9d9
    adc $c7
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    ret nc

    ld d, l
    ret


    jp nc, $d4c9

    ld a, a
    ld a, a
    rst $08
    add $7f
    jp $cecf


    call nc, $d3c5
    call nc, Call_024_558c
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $10
    rst $08
    jp nc, Jump_024_7fc4

    db $d3
    set 1, c
    call z, Call_024_7fcc
    ld d, l
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $d07f
    call z, $d9c1
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, Jump_024_55cf

    call z, Call_024_7fcc
    call z, $cbc9
    push bc
    ld a, a
    ret


    adc $7f
    adc $cf
    jp nc, $c1cd

    call z, Call_024_7f55
    call nc, $cdc9
    push bc
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $d47f

    rst $08
    ld c, a
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    pop bc
    ld a, a
    add $cc
    pop bc
    db $d3
    ret z

    ld a, a
    call z, $cdc1
    ret nc

    ld d, l
    ld a, a
    adc h
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_024_55cf
    ld a, a
    ret nc

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
    call nc, $c5c8
    ld d, l
    ld a, a
    jp nc, $c3cf

    bit 7, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    call nc, Call_024_55d5
    adc $ce
    push bc
    call z, $577f
    nop
    ld a, a
    and c
    jp nc, Jump_024_7fc5

    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_024_4fcf
    ld a, a
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    rst $10
    rst $08
    rst $08
    call nz, $9fd3
    ld d, l
    ld a, a
    rst $10
    rst $08
    rst $08
    call nz, Call_024_7fd3
    call nz, Call_024_7fcf
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    adc $c1
    ld d, l
    call nc, $d2d5
    pop bc
    call z, $d9cc
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    ld a, a
    ret nc

    pop bc
    call nc, $c855
    and h
    rst $08
    adc $87
    call nc, $c77f
    rst $08
    ld a, a
    pop bc
    db $d3
    call nc, $c1d2
    reti


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
    and e
    call z, $d2c1
    bit 7, a
    sub $c5
    jp nc, $d94f

    ld a, a
    db $d3
    call $ccc1
    call z, Call_024_7f8c
    call nc, $c5c8
    ld a, a
    add $d2
    rst $08
    adc $55
    call nc, $d47f
    push bc
    push bc
    call nc, Call_024_7fc8
    rst $08
    add $7f
    ld a, a
    jp $cec1


    add a
    call nc, Call_024_7f55
    jp nz, Jump_024_7fc5

    call z, $cfcf
    set 0, l
    call nz, $c47f
    rst $08
    rst $10
    adc $7f
    rst $08
    ld d, l
    adc $7f
    adc [hl]
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $d5c1


    rst $00
    ld d, l
    ret z

    call nc, $c87f
    ret


    call Call_024_7f9f
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d77f
    ret


    call nc, Call_024_7fc8
    call Call_024_7fd9
    add $d2
    ret


    push bc
    ld c, a
    adc $c4
    db $d3
    ld a, a
    call nc, Call_024_7fcf
    jp $d0c1


    call nc, $d2d5
    push bc
    ld a, a
    ret


    adc $55
    db $d3
    push bc
    jp Jump_024_7fd4


    ld d, h
    add c
    ld a, a
    ld a, a
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    ld d, l
    call nc, Call_024_7fcf
    call nc, $cbc1
    push bc
    ld a, a
    ret nc

    pop bc
    jp nc, Jump_024_7fd4

    ret


    adc $7f
    jp $cf55


    call $c5d0
    call nc, $d4c9
    ret


    rst $08
    adc $8e
    ld a, a
    and c
    call z, Call_024_7fcc
    rst $08
    ld d, l
    add $7f
    push de
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_024_7fc5

    push bc
    pop bc
    rst $00
    push bc
    jp nc, $d47f

    rst $08
    ld d, l
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $c27f

    push de
    reti


    ld c, a
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $08
    adc $cc
    reti


    ld d, l
    ld a, a
    call nc, $d2c8
    rst $08
    rst $10
    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $55c1

    call z, Call_024_7fcc
    ld a, a
    call nc, Call_024_7fcf
    jp $d4c1


    jp Jump_024_7fc8


    ld d, h
    ld a, a
    ld d, l
    adc h
    ld a, a
    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    reti


    ld a, a
    db $d3
    rst $08
    rst $08
    adc $7f
    rst $10
    ret


    ld d, l
    call z, Call_024_7fcc
    jp nz, Jump_024_7fc5

    push de
    db $d3
    push bc
    call nz, $d57f
    ret nc

    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    jp nz, $ccd5

    call z, $d4c5
    ret


    adc $4f
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    or a
    ret z

    push bc
    adc $7f
    reti


    rst $08
    push de
    jp nc, Jump_024_7f55

    ld d, h
    ld a, a
    rst $00
    push bc
    call nc, Call_024_7fd3
    rst $10
    push bc
    pop bc
    bit 7, a
    adc h
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $d77f
    pop bc
    adc $d4
    ld a, a
    ret


    call nc, Call_024_7f55
    call nc, Call_024_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, Call_024_7fc5
    adc [hl]
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $c77f

    rst $08
    ld a, a
    jp nz, $c3c1

    bit 2, l
    ld a, a
    pop bc
    sub $cf
    ret


    call nz, $cec9
    rst $00
    ld a, a
    rst $00
    jp nc, $d3c1

    db $d3
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    ret


    call nc, $c87f
    pop bc
    db $d3
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $4f
    adc h
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    pop bc
    adc $d4
    ret


    call nz, $d4cf
    push bc
    add c
    ld a, a
    pop bc
    ld d, l
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call nz, $d3c5
    bit 7, a
    rst $08
    add $7f
    add $d2
    ret


    ld d, l
    push bc
    adc $c4
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    jp $cdcf


    call $c4cf
    ret


    call nc, $55d9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    jp nz, $ccd5

    call z, $d4c5
    ret


    adc $4f
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    xor h
    push bc
    call nc, $a47f
    jp nc, Jump_024_7f8e

    and c
    ld d, l
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call z, Call_024_55cf
    rst $08
    bit 7, a
    call nc, Call_024_7fcf
    ld d, h
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
    ld a, a
    jp nz, $55d9

    ld a, a
    jp $cdcf


    call $ced5
    ret


    jp $d4c1


    ret


    rst $08
    adc $7f
    ld a, a
    rst $08
    ld d, l
    add $7f
    ld e, e
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    jp nz, $ccd5

    call z, $d4c5
    ret


    adc $4f
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, h
    ld a, a
    rst $08
    ld d, l
    add $7f
    rst $08
    call nc, $c5c8
    jp nc, Jump_024_7fd3

    jp nz, $ccc5

    rst $08
    adc $c7
    ld a, a
    call nc, $cf55
    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, $81d3

    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    call nc, Call_024_55c8
    jp nc, $d7cf

    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $557f
    ld a, a
    call nc, Call_024_7fcf
    call nc, $c5c8
    ld a, a
    rst $10
    ret


    call z, Call_024_7fc4
    ld d, h
    adc h
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    jp $d4c1


    jp Jump_024_7fc8


    call nc, Call_024_55c8
    push bc
    call $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    jp nz, $ccd5

    call z, $d4c5
    ret


    adc $4f
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    or a
    ret z

    push bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    pop bc
    jp nc, Jump_024_7fc5

    jp $d4c1


    jp $c9c8


    adc $c7
    ld a, a
    ld d, h
    adc h
    ld d, l
    ld a, a
    call z, $d4c5
    ld a, a
    ret z

    ret


    call $c77f
    push bc
    call nc, $d77f
    push bc
    pop bc
    bit 2, l
    ld a, a
    pop bc
    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c27f

    push bc
    db $d3
    call nc, Call_024_7f81
    ld d, l
    ld d, h
    ld a, a
    call $d9c1
    jp nz, Jump_024_7fc5

    add $cc
    push bc
    call nz, $c97f
    add $55
    ld a, a
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d37f
    call nc, $d255
    push bc
    adc $c7
    call nc, Call_024_7fc8
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    adc $d4
    jp nc, $cec1

    jp Jump_024_7fc5


    ld a, a
    rst $08
    add $4f
    ld a, a
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    rst $10
    rst $08
    rst $08
    call nz, Call_024_7fd3
    ld d, l
    ld d, [hl]
    add $d2
    rst $08
    call $c87f
    push bc
    jp nc, Jump_024_7fc5

    add $cf
    jp nc, $c1d7

    ld d, l
    jp nc, Jump_024_7fc4

    ret


    db $d3
    ld a, a
    call nz, $d2c1
    bit 7, a
    rst $00
    jp nc, $d9c5

    ld a, a
    jp $c955


    call nc, $81d9
    ld d, a
    nop
    ld a, a
    xor a
    res 0, c
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
    ld c, a
    ld d, h
    adc h
    ld a, a
    call nz, $cecf
    add a
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    call z, $c555
    call nc, $c587
    call $c87f
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    adc h
    ld d, l
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, $cec4
    add a
    call nc, $d47f
    ret z

    push bc
    reti


    sbc a
    ld a, a
    ld d, l
    ld d, a
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
    ret


    adc $d3
    push bc
    jp Jump_024_7fd4


    add $4f
    call z, $c4c5
    adc [hl]
    ld a, a
    call z, $d4c5
    add a
    db $d3
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ret


    ld d, l
    call nc, $ce7f
    push bc
    ret c

    call nc, Call_024_7f81
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_024_7f81
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_024_7f81
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    xor c
    add $7f
    call nc, $c5c8
    reti


    ld a, a
    rst $10
    push bc
    ld c, a
    jp nc, Jump_024_7fc5

    ld d, h
    ld a, a
    ld e, l
    adc h
    ld a, a
    call nc, $c855
    push bc
    reti


    ld a, a
    rst $10
    rst $08
    push de
    call z, $cec4
    add a
    call nc, $d27f
    push bc
    add $d5
    ld d, l
    db $d3
    push bc
    ld a, a
    call nc, Call_024_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $10
    add $d5
    call z, $d9cc
    ld a, a
    pop bc
    adc $c7
    jp nc, $81d9

    ld a, a
    and a
    ld c, a
    rst $08
    ld a, a
    call nc, Call_024_7fcf
    jp $d4c1


    jp Jump_024_7fc8


    db $d3
    rst $08
    call Call_024_7fc5
    call $d555
    jp Jump_024_7fc8


    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_024_7f81

    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    sbc a
    ld a, a
    and c
    jp nc, $cec5

    add a
    call nc, $d47f
    ret z

    push bc
    jp nc, $c54f

    ld a, a
    pop bc
    adc $d9
    ld a, a
    ld d, h
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    sbc a
    ld a, a
    and c
    jp nc, $cec5

    add a
    call nc, $d47f
    ret z

    push bc
    jp nc, $c54f

    ld a, a
    pop bc
    adc $d9
    ld a, a
    ld d, h
    sbc a
    ld a, a
    ld e, b
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
    or a
    ret z

    ld c, a
    push bc
    jp nc, Jump_024_7fc5

    pop bc
    jp nc, Jump_024_7fc5

    reti


    rst $08
    push de
    ld a, a
    ret z

    push de
    jp nc, $d9d2

    ld d, l
    ld a, a
    call nc, $9fcf
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
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, Jump_024_4fc5

    push bc
    adc $7f
    call z, $d3cf
    call nc, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    push de
    adc $55
    db $d3
    push bc
    push bc
    adc $7f
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    add c
    ld a, a
    ld a, a
    jp z, $d3d5

    ld d, l
    call nc, $ce7f
    rst $08
    rst $10
    adc h
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    ld d, l
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $c5c5

    adc $7f
    call z, $d3cf
    call nc, Call_024_7f8e
    and e
    pop bc
    ld d, l
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    ret z

    push bc
    call z, Call_024_7fd0
    call Call_024_7fc5
    call nc, Call_024_7fcf
    ld d, l
    call z, $cfcf
    bit 7, a
    add $cf
    jp nc, Jump_024_7f9f

    ld d, a
    nop
    ld a, a
    or d
    push bc
    db $d3
    ret nc

    push bc
    jp $c5d4


    call nz, Call_024_7f81
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld c, a
    jp nc, Jump_024_7fc5

    call nc, $cfcf
    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_024_5581
    ld a, a
    ld e, b
    nop
    ld a, a
    or d
    push bc
    db $d3
    ret nc

    push bc
    jp $c5d4


    call nz, Call_024_7f81
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld c, a
    jp nc, Jump_024_7fc5

    call nc, $cfcf
    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_024_5581
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $c17f
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $9f
    ld a, a
    or a
    ld d, l
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $c6c9
    add $c5
    jp nc, $c555

    adc $c3
    push bc
    ld a, a
    ld a, a
    jp $cdcf


    ret nc

    pop bc
    jp nc, $c4c5

    ld a, a
    rst $10
    ret


    ld d, l
    call nc, Call_024_7fc8
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld d, l
    jp nc, $9fc5

    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $7f
    xor d
    push de
    call z, Call_024_7fd9
    sub d
    sub b
    adc h
    sub c
    sbc c
    sub [hl]
    sbc c
    add c
    ld c, a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push de
    call $cec1
    ld a, a
    jp nz, $c9c5

    adc $c7
    ld a, a
    ld d, l
    ld a, a
    add $c9
    jp nc, $d4d3

    call z, Call_024_7fd9
    rst $10
    pop bc
    call z, $c5cb
    call nz, $cf7f
    ld d, l
    adc $7f
    call nc, $c5c8
    ld a, a
    xor l
    rst $08
    rst $08
    adc $81
    ld a, a
    xor c
    ld a, a
    jp nz, $d5cf

    ld d, l
    rst $00
    ret z

    call nc, $c17f
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, $b47f

    or [hl]
    ld a, a
    db $d3
    ld d, l
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld a, a
    ret


    adc $7f
    rst $08
    jp nc, $c5c4

    jp nc, Jump_024_7f55

    call nc, Call_024_7fcf
    rst $10
    pop bc
    call nc, $c8c3
    ld a, a
    call nc, $c1c8
    call nc, $ce7f
    push bc
    ld d, l
    rst $10
    db $d3
    ld a, a
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
    call $cecf
    call nc, Call_024_7fc8
    rst $10
    ret


    call z, Call_024_7fcc
    ld c, a
    ret z

    rst $08
    call z, Call_024_7fc4
    pop bc
    ld a, a
    db $d3
    ret nc

    pop bc
    jp Jump_024_7fc5


    add $c1
    ret


    jp nc, $8e55

    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    adc h
    ld a, a
    xor c
    ld a, a
    xor c
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call z, $d4c9
    call nc, $cc4f
    push bc
    ld a, a
    and d
    ret


    set 0, c
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
    call z, $d6cf
    push bc
    call z, $cec9
    push bc
    db $d3
    db $d3
    add c
    ld d, l
    ld a, a
    xor c
    ld a, a
    jp nz, $c7c5

    ld a, a
    reti


    rst $08
    push de
    adc l
    adc l
    call Call_024_7fd9
    ret nc

    pop bc
    ld d, l
    ret nc

    pop bc
    ld a, a
    call nc, Call_024_7fcf
    jp nz, $c9d2

    adc $c7
    ld a, a
    ret z

    ret


    call $c37f
    ld d, l
    rst $08
    call $cec9
    rst $00
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    db $d3
    push bc
    push bc
    adc h
    ld a, a
    xor c
    ld a, a
    db $d3
    push bc
    push bc
    add c
    ld a, a
    xor c
    db $d3
    ld c, a
    ld a, a
    ret


    call nc, $cc7f
    ret


    call nc, $ccd4
    push bc
    ld a, a
    and d
    ret


    set 0, c
    sbc a
    ld a, a
    ld d, l
    xor [hl]
    push bc
    ret c

    call nc, $a97f
    add a
    call z, Call_024_7fcc
    call nz, $81cf
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
    db $d3
    ret nc

    pop bc
    jp Jump_024_7fc5


    db $d3
    ret z

    ld c, a
    push de
    call nc, $ccd4
    push bc
    ld a, a
    and e
    rst $08
    call z, $cdcf
    jp nz, $c1c9

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $08
    jp nz, $c5ca

    jp Jump_024_7fd4


    ld a, a
    call nz, $cfd2
    ret nc

    ld c, a
    ret nc

    push bc
    call nz, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    ld d, l
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    ld d, l
    call $d9c1
    jp nz, Jump_024_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    ld d, l
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    xor l
    rst $08
    rst $08
    adc $57
    nop
    ld a, a
    and c
    call nz, $c9c4
    call nc, $cfc9
    adc $c1
    call z, $d9cc
    adc h
    ld a, a
    ld c, a
    ld d, [hl]
    xor a
    ret z

    adc h
    reti


    push bc
    db $d3
    add c
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    call nc, $c9c8
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld d, d
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    ld c, a
    call nz, Call_024_5c7f
    sub e
    sub h
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $b47f
    pop bc
    jp nc, Jump_024_7fd8

    add c
    ld a, a
    ld d, b
    dec bc
    nop
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    rst $10
    ret


    call z, Call_024_7fcc
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_024_7f55

    db $d3
    set 1, c
    call z, Call_024_7fcc
    pop bc
    call nc, $cf7f
    adc $c3
    push bc
    ld a, a
    ret


    add $55
    ld a, a
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    ld d, l
    ld e, h
    add c
    jp nz, $d4d5

    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, $c955
    db $d3
    jp $d2c1


    call nz, $c4c5
    add c
    or a
    ret z

    ret


    jp Jump_024_7fc8


    ld d, l
    ld d, h
    ld a, a
    call nz, Call_024_7fcf
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    ret


    ld d, l
    call nc, $d47f
    rst $08
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $b49f

    ret z

    push bc
    ld d, l
    ld a, a
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, Call_024_7fcf
    jp $cecf


    ld d, l
    db $d3
    ret


    call nz, $d2c5
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, $d9cc
    add c
    jp nz, $d555

    call nc, Call_024_567f
    ld a, a
    ld a, a
    ret


    adc $7f
    ld d, l
    ld e, h
    sub e
    sub h
    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $cccf
    push bc
    jp nc, $cec1

    jp $81c5


    rst $10
    ret z

    push bc
    adc $7f
    jp nz, $c555

    ret


    adc $c7
    ld a, a
    pop bc
    call nc, $c1d4
    jp $c5cb


    call nz, Call_024_7f8c
    ld a, a
    call $c155
    reti


    ld a, a
    call nc, $cccf
    push bc
    jp nc, $d4c1

    push bc
    ld a, a
    db $d3
    ret


    call z, $cec5
    ld d, l
    call nc, $d9cc
    adc [hl]
    ld a, a
    call nc, $c5c8
    adc $7f
    adc h
    ld a, a
    jp nc, $c4c5

    rst $08
    push de
    ld d, l
    jp nz, $c5cc

    ld a, a
    pop bc
    ld a, a
    ret nc

    push de
    adc $c9
    call nc, $d6c9
    push bc
    ld a, a
    push bc
    ret c

    ld d, l
    ret nc

    push bc
    call nz, $d4c9
    ret


    rst $08
    adc $7f
    pop bc
    rst $00
    pop bc
    ret


    adc $d3
    call nc, $557f
    ret


    adc $7f
    rst $08
    adc $c5
    ld a, a
    sub $c9
    rst $00
    rst $08
    jp nc, $d5cf

    db $d3
    ld a, a
    push bc
    ld d, l
    add $c6
    rst $08
    jp nc, $81d4

    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    ret


    adc $d4
    push bc
    jp nc, $c555

    db $d3
    call nc, $cec9
    rst $00
    ld a, a
    db $d3
    set 1, c
    call z, $81cc
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

Call_024_7f4f:
Jump_024_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_024_7f55:
Jump_024_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_024_7f7f:
Jump_024_7f7f:
    nop
    nop

Call_024_7f81:
Jump_024_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_024_7f8c:
    nop
    nop

Call_024_7f8e:
Jump_024_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_024_7f9f:
Jump_024_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_024_7fc4:
Jump_024_7fc4:
    nop

Call_024_7fc5:
Jump_024_7fc5:
    nop
    nop
    nop

Call_024_7fc8:
Jump_024_7fc8:
    nop
    nop
    nop

Jump_024_7fcb:
    nop

Call_024_7fcc:
Jump_024_7fcc:
    nop

Jump_024_7fcd:
    nop

Jump_024_7fce:
    nop

Call_024_7fcf:
    nop

Call_024_7fd0:
Jump_024_7fd0:
    nop
    nop
    nop

Call_024_7fd3:
Jump_024_7fd3:
    nop

Call_024_7fd4:
Jump_024_7fd4:
    nop
    nop
    nop
    nop

Jump_024_7fd8:
    nop

Call_024_7fd9:
Jump_024_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
