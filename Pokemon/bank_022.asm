; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $022", ROMX[$4000], BANK[$22]

    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    ld c, a
    adc $7f
    jp $d4c9


    reti


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    push bc
    sub $c5
    jp nc, $d2c7

    ld d, l
    push bc
    push bc
    adc $7f
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_022_7f55

    rst $08
    add $7f
    rst $00
    jp nc, $c5c5

    adc $7f
    add $cf
    jp nc, $d6c5

    push bc
    jp nc, Jump_022_7f55

    ld d, a
    nop
    ld a, a
    ld d, [hl]
    xor b
    rst $08
    rst $10
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    pop bc
    ld a, a
    jp nz, Jump_022_4fd5

    call z, $c5cc
    call nc, $cec9
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and c
    call z, Call_022_7fcc
    ret


    adc $7f
    pop bc
    call z, $8ccc
    db $d3
    push bc
    ld d, l
    ret


    jp c, Jump_022_7fc5

    ld d, h
    ld a, a
    or b
    jp nc, $d0cf

    pop bc
    rst $00
    pop bc
    call nc, Call_022_55c5
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    call z, $81d9
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    or b
    jp nc, $d0cf

    pop bc
    rst $00
    pop bc
    call nc, Call_022_7fc5
    call z, $d2c1
    rst $00
    push bc
    call z, Call_022_55d9
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    ld a, a
    call nc, $c1c8
    ld d, l
    call nc, $c37f
    rst $08
    adc $d4
    push bc
    db $d3
    call nc, Call_022_7fd3
    rst $10
    ret


    call nc, Call_022_7fc8
    ld d, l
    ld e, l
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or h
    ret z

    push bc
    ld d, l
    ld a, a
    call $d2cf
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d4c5

    call nc, $d2c5
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    pop bc
    ld a, a
    jp nz, $ccd5

    ld c, a
    call z, $d4c5
    ret


    adc $7f
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    and [hl]
    rst $08
    jp nc, $547f

    adc h
    push bc
    ret c

    jp $d0c5


    call nc, $c67f
    ld d, l
    rst $08
    jp nc, $d37f

    call nc, $c5d2
    adc $c7
    call nc, $8cc8
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    rst $08
    push de
    jp nc, $c5c3

    ld a, a
    ld a, a
    rst $08
    add $7f
    sub $55
    ret


    rst $00
    rst $08
    jp nc, $d5cf

    db $d3
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    call nc, Call_022_7fcf
    ld d, l
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, $c9d2
    jp Jump_022_7fcb


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    or h
    ret z

    push bc
    ld a, a
    rst $00
    ret


    db $d3
    call nc, $cf7f
    add $7f
    add $cf
    jp nc, $c5c3

    ld d, l
    ld a, a
    adc h
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
    ret


    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    ret


    db $d3
    call nc, $cf7f
    add $7f
    add $cf
    jp nc, $55c3

    push bc
    ld a, a
    add $cf
    jp nc, $d47f

    jp nc, $c3c9

    res 1, [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    or a
    ret z

    push bc
    adc $7f
    ld a, a
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $c97f
    call nc, $558c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $08
    jp nc, $c5c4

    jp nc, $d47f

    ret z

    ld d, l
    push bc
    call $c87f
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp nc, $d3c5

    call nc, $c97f
    adc $55
    ld a, a
    jp $cec5


    call nc, $c5d2
    ld a, a
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    ld d, h
    adc h
    ld a, a
    rst $00
    ld c, a
    reti


    call $c1ce
    db $d3
    ret


    push de
    call Call_022_577f
    nop
    ld a, a
    and c
    call nc, $d47f
    ret z

    push bc
    ld a, a
    rst $00
    pop bc
    call nc, Call_022_7fc5
    rst $08
    add $7f
    push bc
    ld c, a
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    rst $00
    reti


    call Call_022_7f8c
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call z, $c3cf
    bit 7, a
    call nc, $c5c8
    ld a, a
    set 0, l
    reti


    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $c7c5

    ret


    adc $ce
    ret


    adc $c7
    ld c, a
    adc h
    ld a, a
    rst $10
    ret z

    ret


    jp Jump_022_7fc8


    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, Call_022_55d2
    ret


    jp Jump_022_7fcb


    call nc, Call_022_7fcf
    db $d3
    ret


    push bc
    jp c, Jump_022_7fc5

    ret


    call nc, Call_022_7f81
    ld d, l
    ld d, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call z, $d4c5
    ld a, a
    ld d, h
    ld a, a
    rst $00
    push bc
    ld d, l
    call nc, $d77f
    push bc
    pop bc
    res 1, h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $10
    ld d, l
    ret z

    ret


    jp Jump_022_7fc8


    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $c9d2
    jp $55cb


    ld a, a
    call nc, Call_022_7fcf
    db $d3
    ret


    push bc
    jp c, Jump_022_7fc5

    ret


    call nc, Call_022_7f81
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
    call nc, Call_022_4f7f
    or b
    ret


    ret nc

    ret


    ld a, a
    jp $cdcf


    push bc
    db $d3
    ld a, a
    add $d2
    rst $08
    call $d47f
    ld d, l
    ret z

    push bc
    ld a, a
    xor l
    rst $08
    rst $08
    adc $8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nz, $55cf
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $c97f
    ld d, l
    call nc, $9f8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    ld d, l
    rst $00
    ld a, a
    xor l
    rst $08
    push de
    adc $d4
    pop bc
    ret


    adc $7f
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $d47f

    ret z

    push bc
    ld d, l
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    call nz, $cfd2
    ret nc

    ret nc

    push bc
    call nz, $c47f
    rst $08
    ld d, l
    rst $10
    adc $7f
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    call $cfcf
    adc $8c
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nz, $c4c9
    ld a, a
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    ret


    call nc, Call_000_0057
    ld a, a
    and h
    pop bc
    jp nc, Jump_022_7fcb

    rst $00
    jp nc, $d9c5

    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc h
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    adc $c7
    ld a, a
    jp nz, $d9cf

    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ret


    db $d3
    ld a, a
    jp $d4c1


    ld d, l
    jp $c9c8


    adc $c7
    ld a, a
    ret


    adc $d3
    push bc
    jp $d3d4


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    and c
    call z, Call_022_7fcc
    pop bc
    jp nc, Jump_022_7fc5

    ret nc

    push bc
    jp nc, $cfd3

    adc $55
    db $d3
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    pop bc
    ld d, l
    jp nc, Jump_022_7fc5

    call nz, $c9cf
    adc $c7
    ld a, a
    db $d3
    rst $08
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    ld d, l
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ret


    adc $d4
    push bc
    jp nc, $d3c5

    call nc, $81d3
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld a, a
    call nz, $d2c1
    bit 7, a
    rst $00
    ld d, l
    jp nc, $d9c5

    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, h
    adc h
    rst $00
    reti


    call Call_022_557f
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or h
    pop bc
    jp nc, $c5d3

    bit 7, a
    ret


    db $d3
    ld a, a
    ld d, l
    adc $cf
    call nc, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    call $8cc5
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    pop bc
    ld a, a
    jp nz, $ccd5

    call z, $c54f
    call nc, $cec9
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    and l
    sub $c5
    adc $7f
    ld d, l
    ret


    add $7f
    ld a, a
    db $d3
    call z, $c7c9
    ret z

    call nc, $d9cc
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld d, l
    db $d3
    ld a, a
    rst $08
    add $c6
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_022_7fc5
    jp $cecf


    call nc, Call_022_55c5
    db $d3
    call nc, $cec9
    rst $00
    ld d, h
    adc h
    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    pop bc
    call z, $d355
    rst $08
    ld a, a
    call z, $c1c5
    jp nc, Jump_022_7fce

    db $d3
    rst $08
    call Call_022_7fc5
    push bc
    ret c

    ret nc

    ld d, l
    push bc
    jp nc, $c5c9

    adc $c3
    push bc
    add c
    ld d, a
    nop
    ld a, a
    or b
    jp nc, $d0cf

    pop bc
    rst $00
    pop bc
    adc $c4
    pop bc
    ld a, a
    call $d4c1
    push bc
    jp nc, $c94f

    pop bc
    call z, $c97f
    db $d3
    ld a, a
    ret nc

    push de
    call nc, $cf7f
    adc $81
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    or d
    push bc
    jp $cec5


    call nc, $d9cc
    adc h
    call nc, $c5c8
    jp nc, Jump_022_7fc5

    ld d, l
    pop bc
    jp nc, Jump_022_7fc5

    jp nc, $c6d5

    add $c9
    pop bc
    adc $d3
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    db $d3
    call nc, $c1c5
    call z, $cec9
    rst $00
    ld a, a
    call nz, $c1c5
    jp nc, Jump_022_557f

    ld d, h
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    rst $08
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    ld d, l
    rst $00
    ld a, a
    xor l
    rst $08
    push de
    adc $d4
    pop bc
    ret


    adc $7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    adc h
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    db $d3
    push de
    db $d3
    ret nc

    ld d, l
    push bc
    jp Jump_022_7fd4


    ld d, [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    ld d, l
    ret


    call nc, $d47f
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $d2c1
    bit 7, a
    rst $00
    jp nc, $c555

    reti


    ld a, a
    ret nc

    rst $08
    call z, $c3c9
    push bc
    call $cec1
    ld a, a
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    call nz, $d2c1
    bit 7, a
    rst $00
    jp nc, $d9c5

    ld a, a
    db $d3
    jp $c5c9


    adc $d4
    ld c, a
    ret


    add $c9
    jp $cd7f


    push de
    db $d3
    push bc
    push de
    call Call_022_577f
    nop
    ld a, a
    call nz, $d2c1
    bit 7, a
    rst $00
    jp nc, $d9c5

    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld c, a
    ld d, h
    rst $00
    reti


    call Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    ld d, l
    push bc
    pop bc
    call nz, $b47f
    pop bc
    jp nc, $c5d3

    bit 7, a
    ld a, a
    ret


    db $d3
    ld a, a
    sub $c5
    ld d, l
    jp nc, Jump_022_7fd9

    db $d3
    call nc, $cfd2
    adc $c7
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    pop bc
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    call $cec1
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    call nz, $d2c1
    bit 7, a
    rst $00
    jp nc, Jump_022_4fc5

    reti


    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and h
    pop bc
    jp nc, $55cb

    ld a, a
    rst $00
    jp nc, $d9c5

    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cccf


    rst $08
    ld d, l
    push de
    jp nc, $cf7f

    add $7f
    rst $00
    jp nc, $d9c5

    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    call nc, $c97f
    db $d3
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
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
    call nc, Call_022_7fcf
    sub $c9
    ld d, l
    db $d3
    ret


    call nc, Call_022_7f8c
    reti


    rst $08
    push de
    ld a, a
    adc $c5
    push bc
    call nz, $c57f
    adc $d4
    ld d, l
    jp nc, $cec1

    jp Jump_022_7fc5


    add $c5
    push bc
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    adc $55
    adc h
    ld d, [hl]
    adc h
    ld a, a
    adc $cf
    rst $10
    ld a, a
    xor c
    ld a, a
    call $d3d5
    call nc, $d37f
    ld d, l
    pop bc
    reti


    ld a, a
    jp nz, $c5d9

    adc l
    jp nz, $c5d9

    add c
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
    ret z

    pop bc
    sub $c5
    ld a, a
    jp $cecf


    add $4f
    ret


    call nz, $cec5
    jp Jump_022_7fc5


    call nc, Call_022_7fcf
    rst $10
    ret


    adc $8c
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    ld a, a
    rst $10
    ld d, l
    ret


    call nc, Call_022_7fc8
    or h
    pop bc
    jp nc, $c5d3

    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    jp nc, Jump_022_7fc5

    reti


    rst $08
    push de
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $4f
    rst $00
    ld a, a
    ld d, h
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, Call_022_557f
    ret


    db $d3
    adc $87
    call nc, $c57f
    pop bc
    db $d3
    reti


    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    ld d, l
    push de
    ld a, a
    call nc, Call_022_7fcf
    jp $cccf


    call z, $c3c5
    call nc, Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, Call_022_7f81
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    jp nz, $d2cf

    ret


    adc $c7
    ld a, a
    ret nc

    call z, $4fc1
    adc $d4
    ret


    adc $c7
    ld a, a
    call nc, $c5d2
    push bc
    db $d3
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, $c555

    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    adc $cf
    call nc, $c77f
    rst $08
    ld a, a
    call nc, $55c8
    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    db $d3
    ret


    call nc, $81c5
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    jp nz, $d4d5

    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    ld a, a
    jp nz, Jump_022_7fd9

    ld d, l
    pop bc
    ld a, a
    jp nc, $d5cf

    adc $c4
    pop bc
    jp nz, $d5cf

    call nc, $d27f
    rst $08
    push de
    call nc, $c555
    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret


    call nc, $cc7f
    rst $08
    rst $08
    ld d, l
    set 2, e
    ld a, a
    call nc, $c1c8
    call nc, $d97f
    rst $08
    push de
    ld a, a
    call $d9c1
    ld a, a
    ret nc

    ld d, l
    pop bc
    db $d3
    db $d3
    adc [hl]
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    and c
    jp nc, Jump_022_7fc5

    reti


    rst $08
    push de
    ld a, a
    call $cbc1
    ret


    adc $c7
    ld a, a
    ld d, l
    ret nc

    ret


    jp $d5d4


    jp nc, Jump_022_7fc5

    ld d, h
    sbc a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    bit 7, a
    sub $c5
    jp nc, Jump_022_7fd9

    ld d, l
    ret z

    pop bc
    ret nc

    ret nc

    reti


    add c
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


    call nc, $81d9
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld d, l
    ld a, a
    jp nz, $c5c5

    adc $7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    db $d3
    call nc, $cccf
    push bc
    ld d, l
    adc $7f
    jp nz, Jump_022_7fd9

    call nc, $c9c8
    push bc
    sub $c5
    db $d3
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
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
    ld d, l
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c9d2


    call $81c5
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    ld e, [hl]
    ld a, a
    rst $10
    ret z

    rst $08
    ld d, l
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call nc, $c9c8
    db $d3
    add c
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and l
    sub $c5
    adc $7f
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    ret nc

    ld d, l
    rst $08
    call z, $c3c9
    push bc
    call $cec1
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    pop bc
    call z, $cfd3
    ld a, a
    call nc, $d2c5
    jp nc, $c2c9

    call z, Call_022_7fd9
    push de
    ret nc

    db $d3
    ld d, l
    push bc
    call nc, Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    jp nz, Jump_022_7fd9

    call nc, $c5c8
    ld a, a
    jp nz, $c155

    call nz, $c27f
    push bc
    ret z

    pop bc
    sub $c9
    rst $08
    jp nc, $cf7f

    add $7f
    ld d, l
    ld e, [hl]
    add a
    db $d3
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor c
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_022_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld c, a
    ld a, a
    jp nz, $cbc9

    push bc
    adc h
    call nc, $cfcf
    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    xor c
    call nc, $d387
    ld a, a
    xor b
    rst $08
    adc $c7
    ret z

    rst $08
    adc $c7
    add a
    db $d3
    ld a, a
    jp nz, $c955

    set 0, l
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    ld a, a
    call nz, $cecf
    ld d, l
    add a
    call nc, $d77f
    pop bc
    adc $d4
    ld a, a
    call nc, Call_022_7fcf
    call nz, $d2c9
    call nc, $c97f
    ld d, l
    call nc, $8e7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or b
    push de
    call nc, $c97f
    ld d, l
    call nc, $d57f
    ret nc

    ld a, a
    call nc, Call_022_7fcf
    call nz, $c3c5
    rst $08
    jp nc, $d4c1

    push bc
    ld a, a
    ld d, l
    call Call_022_7fd9
    ret z

    rst $08
    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call z, $c7c9
    ret z

    call nc, Call_022_4f7f
    jp nz, $d5cc

    push bc
    ld a, a
    jp $d6c1


    push bc
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    pop bc
    jp nc, Jump_022_7fc5

    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    push bc
    adc $55
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    call nc, Call_022_7fcf
    call z, $d6c9
    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_022_55c5

    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    ld a, a
    ret


    call nz, $cec5
    ld d, l
    call nc, $c6c9
    ret


    push bc
    call nz, $c27f
    reti


    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    ld d, l
    push bc
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor a
    adc $cc
    reti


    ld d, l
    ld a, a
    jp $c1c8


    call Call_022_7fd0
    jp $cec1


    ld a, a
    jp $cdcf


    push bc
    ld a, a
    ret


    ld d, l
    adc $81
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


    call nc, $81d9
    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    ld d, l
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $c5c5

    adc $7f
    db $d3
    call nc, $cccf
    push bc
    adc $7f
    ld d, l
    jp nz, Jump_022_7fd9

    call nc, $c9c8
    push bc
    sub $c5
    db $d3
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    adc h
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
    ret


    ld d, l
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c9d2


    call $81c5
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    adc [hl]
    xor c
    call nc, $d387
    ld a, a
    ld d, l
    ld e, [hl]
    add a
    db $d3
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    and l
    sub $c5
    adc $7f
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ret nc

    rst $08
    call z, $c3c9
    push bc
    call $cec1
    ld a, a
    ld a, a
    push bc
    call $c1c2
    jp nc, Jump_022_55d2

    pop bc
    db $d3
    db $d3
    push bc
    db $d3
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_022_55c5
    sub $c5
    jp nc, Jump_022_5e7f

    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call nz, $cf55
    adc $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $d54f
    push bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor h
    ret


    rst $00
    ld d, l
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $55cf


    call z, $d5cf
    jp nc, $cf7f

    add $7f
    rst $10
    pop bc
    call nc, $d2c5
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    pop bc
    ld a, a
    call $d3d9
    call nc, $d2c5
    ret


    rst $08
    push de
    db $d3
    ld d, l
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_022_7f8e

    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    pop bc
    ld a, a
    jp nz, $ccd5

    call z, $c54f
    call nc, $cec9
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and h
    ld d, l
    push de
    jp nc, $cec9

    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    push de
    ret nc

    rst $00
    jp nc, $c4c1

    push bc
    ld d, l
    adc [hl]
    ld a, a
    push de
    ret nc

    rst $00
    jp nc, $c4c1

    ret


    adc $c7
    ld a, a
    rst $10
    ret


    call z, Call_022_7fcc
    ld d, l
    db $d3
    call nc, $d0cf
    add c
    ld a, a
    ld d, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret nc

    jp nc, $d3c5

    ld d, l
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d4cf

    call nc, $cecf
    ld a, a
    and d
    adc h
    ld a, a
    adc [hl]
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    push de
    ret nc

    rst $00
    jp nc, $c4c1

    ret


    adc $c7
    ld a, a
    ld d, l
    rst $10
    ret


    call z, Call_022_7fcc
    db $d3
    call nc, $d0cf
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    rst $00
    jp nc, $d3c1

    db $d3
    adc h
    jp $d6c1


    push bc
    adc h
    ld a, a
    pop bc
    call z, $4fcc
    ld a, a
    ret


    db $d3
    ld a, a
    xor a
    res 0, c
    ld d, [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    call $d2c9
    pop bc
    jp $c5cc


    adc h
    jp $c3d9


    call z, Call_022_7fc5
    ld d, l
    ld d, a
    nop
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld c, a
    ld d, h
    adc h
    ld a, a
    rst $00
    reti


    call $8c7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $ab7f
    pop bc
    jp nc, $c5d3

    call Call_022_55d9
    ld a, a
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    add $d2
    ret


    sub $cf
    call z, $d5cf
    ld d, l
    db $d3
    ld a, a
    call nc, $d9cf
    ld a, a
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ld c, a
    call nc, $cdcf
    jp nz, $547f

    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    add $55
    pop bc
    call $d5cf
    db $d3
    ld a, a
    call nc, $d7cf
    adc $7f
    ld d, [hl]
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    or a
    ret z

    push bc
    adc $7f
    ld d, h
    adc h
    ld a, a
    add $cf
    db $d3
    call nc, $c555
    jp nc, $c4c5

    ld a, a
    jp nz, Jump_022_7fd9

    adc h
    call nz, $c5c9
    call nz, Call_022_7f8c
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret nc

    push de
    call nc, $c97f
    call nc, $c97f
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $d7cf
    push bc
    jp nc, $547f

    adc [hl]
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, Jump_022_55c5

    ld a, a
    add $cf
    jp nc, $d07f

    jp nc, $d9c1

    ret


    adc $c7
    ld d, [hl]
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    or d
    push bc
    jp $cec5


    call nc, $d9cc
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    call nc, $c5c8
    jp nc, Jump_022_7fc5

    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_022_7fd3

    rst $00
    ret z

    ld d, l
    rst $08
    db $d3
    call nc, $56d3
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, Call_022_7fcf
    ret z

    ld d, l
    pop bc
    push de
    adc $d4
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $d7cf
    push bc
    jp nc, Jump_022_5455

    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    add $55
    push bc
    push bc
    call z, Call_022_7fd3
    ret


    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret nc

    ld d, l
    ret


    jp nc, $d4c9

    ld a, a
    rst $08
    add $7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    set 1, c
    call z, $c5cc
    call nz, $c27f
    reti


    ld a, a
    ld d, l
    ld e, [hl]
    ld d, [hl]
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    db $d3
    call nc, $d2c5
    ld a, a
    call nc, Call_022_4fcf
    rst $10
    adc $8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and c
    db $d3
    call nc, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    ret nc

    push de
    jp nc, $ccd0

    push bc
    adc h
    ld a, a
    pop bc
    ld a, a
    adc $cf
    jp nz, $c5cc

    ld a, a
    jp $cf55


    call z, $d5cf
    jp nc, Jump_022_7f8e

    ld d, a
    nop
    ld a, a
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    push de
    adc $d4
    ld c, a
    push bc
    call nz, $547f
    sbc a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    adc $c5
    rst $10
    ld d, l
    ld a, a
    ret nc

    jp nc, $c4cf

    push de
    jp $d3d4


    add c
    ld a, a
    xor b
    ret


    call z, $d5cc
    add $55
    add $7f
    rst $08
    jp nz, $c5d3

    jp nc, $c1d6

    call nc, $d2cf
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    jp $55cf


    call $c5cd
    jp nc, $c9c3

    pop bc
    call z, $c67f
    ret


    jp nc, Jump_022_7fcd

    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    sub $cf
    call z, $ced5
    call nc, $c5c5
    ld c, a
    jp nc, Jump_022_7fd3

    add $cf
    jp nc, $cc7f

    rst $08
    sub $c5
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call Call_022_7fc5
    rst $08
    add $7f
    ld d, h
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    and e
    ret z

    push de
    jp nc, $c34f

    ret z

    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    call nc, $d7cf
    push bc
    jp nc, $547f

    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d37f
    rst $10
    push bc
    pop bc
    call nc, Call_022_7fd9
    pop bc
    add $d4
    push bc
    jp nc, Jump_022_7f4f

    db $d3
    ret nc

    rst $08
    jp nc, $c9d4

    adc $c7
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and h
    rst $08
    push bc
    ld d, l
    db $d3
    ld a, a
    ld d, [hl]
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    ret


    call nc, $d3bb
    call nc, $c3c9
    ld d, l
    set 3, c
    cp l
    sbc a
    ld a, a
    ld a, a
    xor c
    call nc, Call_022_7f7f
    jp $cdcf


    push bc
    db $d3
    ld a, a
    add $55
    jp nc, $cdcf

    ld a, a
    rst $00
    push de
    call $cc8d
    ret


    set 0, l
    ld a, a
    call $c4d5
    ld a, a
    ld d, l
    rst $08
    add $7f
    db $d3
    push bc
    pop bc
    ld d, a
    nop
    ld a, a
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    call z, $cec1
    call nz, $cfcc
    jp nc, $81c4

    ld c, a
    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    db $d3
    pop de
    push de
    pop bc
    jp nc, $c555

    ld a, a
    ret nc

    call z, $c3c1
    push bc
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, Call_022_7fcc
    call Call_022_7fd9
    call z, $cec1
    call nz, Call_022_7f81
    ld d, l
    ld a, a
    ld a, a
    ld a, a

Call_022_4f7f:
Jump_022_4f7f:
    ld a, a
    ld a, a

Call_022_4f81:
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    add a
    call $d47f
    ret z

    ret


    adc $55
    set 1, c
    adc $c7
    ld a, a
    call nc, Call_022_7fcf
    jp nz, $c9d5

    call z, Call_022_7fc4
    pop bc
    ld a, a
    jp nz, $c955

    rst $00
    ld a, a
    jp $cecf


    db $d3
    call nc, $d5d2
    jp $c9d4


    rst $08
    adc $7f
    adc [hl]
    ld d, l
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
    ld a, a
    xor h
    push bc
    call nc, Call_022_557f
    ld d, h
    ld a, a
    ret nc

Call_022_4fc5:
Jump_022_4fc5:
    jp nc, $d3c5

Call_022_4fc8:
    db $d3
    ld a, a
    call nc, $c5c8

Call_022_4fcd:
    ld a, a
    rst $00

Call_022_4fcf:
Jump_022_4fcf:
    jp nc, $55cf

    push de

Jump_022_4fd3:
    adc $c4

Call_022_4fd5:
Jump_022_4fd5:
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    pop bc
    adc $c4
    rst $08
    pop bc
    adc $d5
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    add $c1
    call $d5cf
    db $d3
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret z

    ret


    rst $00
    ret z

    adc l
    jp nc, $cec1

    bit 2, l
    ret


    adc $c7
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    push bc
    adc $c7
    push bc
    jp nc, $d37f

    ret z

    ret


    ld d, l
    ret nc

    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $cf7f
    adc $cc
    ld d, l
    reti


    ld a, a
    db $d3
    call nc, $d0cf
    db $d3
    ld a, a
    pop bc
    call nc, $c47f
    push bc
    pop bc
    call nz, $cc8d
    ld d, l
    push bc
    pop bc
    add $7f
    ret nc

    rst $08
    jp nc, Jump_022_7fd4

    rst $08
    adc $c3
    push bc
    ld a, a
    pop bc
    ld a, a
    reti


    ld d, l
    push bc
    pop bc
    jp nc, Jump_022_7f81

    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    call nz, $c1c5
    call nz, $cc8d
    push bc
    pop bc
    ld c, a
    add $7f
    call nc, $d7cf
    adc $8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nz, $c1c5
    call nz, Call_022_557f
    call z, $c1c5
    add $7f
    ret


    db $d3
    ld a, a
    rst $08
    jp nc, $cec1

    rst $00
    push bc
    adc h
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_022_7f55

    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    db $d3
    ld d, l
    push de
    adc $57
    nop
    ld a, a
    ld d, [hl]
    adc h
    xor c
    call nc, $d387
    ld a, a
    ret nc

    jp nc, $d0cf

    pop bc
    rst $00
    pop bc
    adc $4f
    call nz, Call_022_7fc1
    db $d3
    ret z

    push bc
    push bc
    call nc, Call_022_7fd3
    call nc, Call_022_7fcf
    adc $cf
    call nc, $55c9
    jp $81c5


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or d
    push bc
    jp $cec5


    call nc, $d9cc
    adc h
    ld d, l
    ld a, a
    ld d, [hl]
    adc h
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    reti


    ld a, a
    sub c
    sub d
    ld d, l
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and c
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret nc

    call z, Call_022_55c1
    jp Jump_022_7fc5


    rst $10
    ret z

    push bc
    jp nc, Jump_022_7fc5

    db $d3
    call z, $c5c5
    ret nc

    reti


    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ret z

    pop bc
    push de
    adc $d4
    db $d3
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    xor c
    call nc, $c17f
    call z, $cfd3
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cf55


    adc $c4
    ret


    call nc, $cfc9
    adc $7f
    push de
    adc $c1
    jp nz, $c5cc

    ld a, a
    call nc, $cf55
    ld a, a
    jp nz, Jump_022_7fc5

    ret nc

    pop bc
    db $d3
    call nc, Call_022_7f81
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or l
    ld d, l
    adc $c4
    push bc
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    jp $cecf


    call nz, $d4c9
    ret


    rst $08
    ld d, l
    adc $8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_022_7fc5
    rst $10
    ret z

    rst $08
    ld a, a
    ld d, l
    rst $00
    rst $08
    ld a, a
    call nc, Call_022_7fcf
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    ld d, l
    call nc, $d7cf
    adc $8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld a, a
    call nc, $d2c8
    ld d, l
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $ced5
    adc $c5
    call z, $cf7f
    ld d, l
    add $7f
    jp nc, $c3cf

    bit 7, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $81
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    or b
    rst $08
    call z, $c3c9
    push bc
    ld a, a
    rst $08
    add $7f
    and h
    push bc
    pop bc
    call nz, Call_022_7f55
    call z, $c1c5
    add $7f
    or h
    rst $08
    rst $10
    adc $7f
    ld a, a
    rst $10
    ret


    call nc, Call_022_7fc8
    ld d, l
    jp nz, $d3c5

    call nc, $d77f
    ret


    db $d3
    ret z

    push bc
    db $d3
    adc [hl]
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    and e
    call z, $c2d5
    ld c, a
    ld a, a
    rst $08
    add $7f
    call z, $cbc9
    ret


    adc $c7
    ld a, a
    ld d, h
    adc h
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_022_7fc5
    rst $10
    ret z

    rst $08
    push bc
    sub $c5
    ld d, l
    jp nc, $cc7f

    ret


    set 0, l
    db $d3
    ld a, a
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    push bc
    pop bc
    call nz, $cc7f
    push bc
    pop bc
    add $7f
    call nc, $d7cf
    adc $7f
    ld c, a
    ld d, h
    adc h
    and a
    reti


    call Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    ld d, l
    push bc
    pop bc
    call nz, $ad7f
    pop bc
    jp nc, $c8c3

    push bc
    push bc
    db $d3
    push bc
    ld a, a
    adc h
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor h
    ret


    rst $00
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    and c
    ld d, l
    call $d2c5
    ret


    jp $cec1


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    and l
    adc $d4
    jp nc, $cec1

    jp Jump_022_7fc5


    rst $08
    add $7f
    and h
    push bc
    pop bc
    ld c, a
    call nz, $cc7f
    push bc
    pop bc
    add $7f
    or b
    rst $08
    jp nc, Jump_022_57d4

    nop
    ld a, a
    xor l
    reti


    ld a, a
    and h
    push bc
    jp z, $d2c1

    db $d3
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    ld c, a
    call nc, $c97f
    db $d3
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $cf7f
    adc $7f
    call nc, $55c8
    push bc
    ld a, a
    xor c
    db $d3
    call z, $cec1
    call nz, $cf7f
    add $7f
    or d
    push bc
    call nz, $ac7f
    ld d, l
    rst $08
    call nc, $d3d5
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    call nc, $c1c8
    call nc, $cd7f
    pop bc
    reti


    ld a, a
    db $d3
    ret nc

    jp nc, $d9c1

    ld d, l
    ld a, a
    rst $08
    push de
    call nc, $d07f
    rst $08
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $d3
    ld a, a
    rst $00
    pop bc
    ld d, l
    db $d3
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    rst $00
    push bc
    call nc, $c9d4
    ld d, l
    adc $c7
    ld a, a
    pop bc
    adc $c7
    jp nc, $8cd9

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c27f
    rst $08
    reti


    ld d, a
    nop
    ld a, a
    xor b
    ret


    add c
    ld a, a
    xor b
    ret


    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    rst $00
    reti


    call $ce4f
    pop bc
    db $d3
    ret


    push de
    call $c97f
    db $d3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_022_7f81
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and c
    call z, Call_022_7fcc
    pop bc
    jp nc, Jump_022_7fc5

    rst $00
    ret


    jp nc, $d3cc

    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ld a, a
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    call z, $d47f
    ld c, a
    ret z

    push bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ret nc

    jp nc, $c7cf

    jp nc, $cdc1

    call Call_022_55c5
    ld a, a
    ret


    db $d3
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    ret nc

    jp nc, $d5cf

    adc $c4
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and [hl]
    ld d, l
    call z, $d3c1
    ret z

    ld a, a
    call nc, $d7cf
    adc $8c
    ld a, a
    ret nc

    call z, $d9c1
    ret


    adc $55
    rst $00
    ld a, a
    jp $d2cf


    adc $c5
    jp nc, Jump_022_7f7f

    ret z

    pop bc
    sub $c5
    ld a, a
    jp nz, Jump_022_55c5

    push bc
    adc $7f
    jp nz, $c9d5

    call z, $81d4
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    or h
    rst $08
    rst $08
    ld a, a
    jp nz, $c4c1

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or b
    push de
    ld c, a
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp $c9cf


    adc $7f
    ret


    adc $7f
    call nc, Call_022_7fcf
    ld d, l
    jp nz, $d4c5

    adc h
    ld a, a
    xor h
    rst $08
    db $d3
    push bc
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    add $7f

Jump_022_5455:
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ld d, l
    ret nc

    call z, $d3d5
    ld a, a
    jp $c9cf


    adc $d3
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ret


    call nc, $d387
    ld a, a
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    call nc, Call_022_7fcf
    jp $55c8


    pop bc
    adc $c7
    push bc
    ld a, a
    ret


    call nc, $c97f
    adc $d4
    rst $08
    ld a, a
    ret nc

    jp nc, $dac9

    ld d, l
    push bc
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    ld a, a
    set 1, [hl]
    push bc
    rst $10
    ld a, a
    call nc, $c1c8
    ld d, l
    call nc, $cc7f
    rst $08
    adc $c7
    ld a, a
    pop bc
    rst $00
    rst $08
    adc h
    jp nz, $d4d5

    ld a, a
    ld d, l
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    call Call_022_7fd9
    jp $cccf


    call z, $c1c5
    rst $00
    push de
    push bc
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    and c
    ld a, a
    db $d3
    rst $08
    add $d4
    ld a, a
    call nc, $c9c8
    adc $c7
    add c
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $cd7f
    push bc
    call nc, $d37f
    call nc, $cecf
    push bc
    ld d, l
    db $d3
    ld a, a
    ret


    adc $7f
    rst $10
    pop bc
    call nc, $d2c5
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    push bc
    sub $cf
    call z, $d4d5
    push bc
    call nz, $c97f
    adc $d4
    rst $08
    ld d, l
    ld a, a
    db $d3
    push de
    jp Jump_022_7fc8


    pop bc
    ld a, a
    db $d3
    rst $08
    add $d4
    ld a, a
    call nc, $c9c8
    adc $55
    rst $00
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    call nc, Call_022_4f7f
    call $81c5
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and a
    rst $08
    ld a, a
    pop bc
    rst $10
    pop bc
    reti


    ld a, a
    ld d, l
    rst $08
    jp nc, $a97f

    ld a, a
    rst $10
    ret


    call z, Call_022_7fcc
    jp nz, $c1c5

    call nc, $d97f
    rst $08
    ld d, l
    push de
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d47f
    ret


Call_022_557f:
Jump_022_557f:
    jp nc, $c4c5

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    ld c, a
    ld a, a
    call nc, Call_022_7fcf

Call_022_558e:
Jump_022_558e:
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, $c555

    ld a, a
    call $81c5
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and h
    rst $08
    adc $87
    call nc, Call_022_557f
    call z, $cfcf
    bit 7, a
    call nz, $d7cf
    adc $7f
    push de
    ret nc

    rst $08
    adc $7f
    call nc, $55c8
    push bc

Call_022_55c1:
Jump_022_55c1:
    ld a, a
    jp nc, $c3cf

Call_022_55c5:
Jump_022_55c5:
    set 0, l
    call nc, $d07f
    jp nc, $cacf

    push bc

Call_022_55ce:
    jp $c9d4


    ld d, l

Call_022_55d2:
Jump_022_55d2:
    call z, $81c5

Jump_022_55d5:
    ld a, a
    ld d, a
    nop
    ld a, a

Call_022_55d9:
    xor b
    rst $08
    rst $10
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    jp nz, $ccd5

    call z, $d4c5
    ld c, a
    ret


    adc $7f
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    db $d3
    ret z

    rst $08
    ld d, l
    rst $08
    call nc, $d77f
    ret


    call nc, Call_022_7fc8
    push de
    adc $c6
    pop bc
    ret


    call z, $cec9
    rst $00
    ld d, l
    ld a, a
    pop bc
    jp $d5c3


    jp nc, $c3c1

    reti


    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret nc

    push bc
    jp nc, $c355

    push bc
    adc $d4
    pop bc
    rst $00
    push bc
    ld a, a
    rst $08
    add $7f
    ret z

    ret


    call nc, Call_022_7fd3
    ret nc

    ld d, l
    jp nc, $cdcf

    rst $08
    call nc, $c4c5
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, l
    and e
    call z, $d4c9
    call nc, Call_022_7fd9
    and e
    call z, $d0c9
    ret nc

    rst $08
    jp nc, $d77f

    ret


    ld d, l
    call z, Call_022_7fcc
    jp nz, Jump_022_7fc5

    push bc
    pop bc
    db $d3
    reti


    ld a, a
    call nc, Call_022_7fcf
    ret z

    ret


    call nc, Call_022_7f55
    ret z

    rst $08
    call $8ec5
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret nc

    push de
    jp nc, $55c3

    ret z

    pop bc
    db $d3
    push bc
    ld a, a

Jump_022_567f:
    ret nc

    jp nc, $d0cf

    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l

Call_022_568c:
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_022_7fcf
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    ld d, l
    rst $08
    add $7f
    and [hl]
    call z, $d3c1
    ret z

    ld a, a
    or h
    rst $08
    rst $10
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    and [hl]
    call z, $d3c1
    ret z

    ld a, a
    or h
    rst $08
    ld c, a
    rst $10
    adc $7f
    ld a, a
    ld a, a

Call_022_56c6:
    ld a, a
    ld a, a
    and [hl]
    call z, $d3c1
    ret z

    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c155

    ret


    adc $c2
    rst $08
    rst $10
    adc l
    call z, $cbc9
    push bc
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, $cf7f

    add $7f
    ld d, l
    call nz, $c5d2
    pop bc
    call Call_000_0057
    ld a, a
    and [hl]
    call z, $d3c1
    ret z

    ld a, a
    or h
    rst $08
    rst $10
    adc $7f
    ld d, h
    adc h
    ld a, a
    ld c, a
    and a
    reti


    call $c1ce
    db $d3
    ret


    push de
    call Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $a17f
    call z, $c5cc
    jp Jump_022_7fcb


    adc h
    pop bc
    ld a, a
    rst $00
    ld d, l
    ret


    jp nc, Jump_022_7fcc

    rst $10
    ret z

    rst $08
    ld a, a
    call z, $d6cf
    push bc
    db $d3
    ld a, a
    adc $c1
    call nc, $d555
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    call z, $d4c1
    ld a, a
    rst $08
    add $7f
    and [hl]
    call z, $d3c1
    ret z

    ld d, a
    nop
    ld a, a
    and e
    push bc
    jp nc, $c1d4

    ret


    adc $cc
    reti


    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $c14f


    adc $7f
    add $c9
    adc $c4
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d97f
    rst $08
    push de
    ld a, a
    ld d, l

Call_022_577f:
Jump_022_577f:
    rst $10
    pop bc
    adc $d4
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    ld d, l
    rst $08
    ret nc

    ld a, a
    rst $08
    add $7f
    and [hl]
    call z, $d3c1
    ret z

    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    pop bc
    jp nz, $ccd5

    call z, Call_022_4fc5
    call nc, $cec9
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and l
    ld d, l
    add $c6
    push bc
    jp $c9d4


    sub $c5
    ld a, a
    jp $d2c1


    call nz, $c38c
    pop bc
    adc $55

Jump_022_57d4:
    ld a, a
    ret nc

    jp nc, $d4cf

    push bc
    jp Jump_022_7fd4


    ld d, h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    add $55
    jp nc, $cdcf

    ld a, a
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $c17f
    call nc, $c1d4
    ld d, l
    jp Jump_022_7fcb


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $08
    add $7f
    add $c9
    jp nc, Jump_022_55c5

    adc h
    rst $10
    pop bc
    call nc, $d2c5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call z, $c7c9
    ret z

    call nc, Call_022_55ce
    ret


    adc $c7
    add c
    ld a, a
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
    call nc, Call_022_7fcf
    ret nc

    ld c, a
    push de
    jp nc, $c8c3

    pop bc
    db $d3
    push bc
    ld a, a
    ret nc

    jp nc, $d0cf

    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_022_7fcf
    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    rst $08
    add $7f
    add $cc
    pop bc
    db $d3
    ret z

    add c
    ld d, a
    nop
    ld a, a
    jp $c1c8


    adc $c7
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c9cf


    adc $7f
    ld c, a
    ret


    adc $d4
    rst $08
    ld a, a
    ret nc

Call_022_587f:
    jp nc, $dac9

    push bc
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ret nc

    ld d, l
    jp nc, $dac9

    push bc
    ld a, a
    ld d, h
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    ld a, a
    ld d, l
    call nz, $d3c5
    bit 7, a
    ld d, a
    nop
    ld a, a
    ret nc

    pop bc
    jp nc, $c4c1

    ret


    db $d3
    push bc
    ld a, a
    add $cf
    jp nc, $c17f

    call nz, Call_022_4fd5
    call z, $d3d4
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, [hl]
    call $d3c9
    db $d3
    ret


    ld d, l
    call z, $8dc5
    ret nc

    call z, $d9c1
    ret


    adc $c7
    ld a, a
    jp $d2cf


    adc $c5
    jp nc, $8e55

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
    ret nc

    call z, $d9c1
    push bc
    call nz, Call_022_4f7f
    ret z

    push de
    adc $d4
    ret


    adc $c7
    sbc a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor a
    adc $cc
    reti


    ld d, l
    ld a, a
    call nc, $c5c8
    jp nc, Jump_022_7fc5

    jp $cec1


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp Jump_022_55c1


    call nc, $c8c3
    ld a, a
    ret


    call nc, Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    call nz, $c1c5
    jp nc, Jump_022_557f

    ld d, h
    adc h
    pop bc
    call z, $cfd3
    ld a, a
    call nc, $c5c8
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    ret z

    push de
    adc $d4
    ld a, a
    pop bc
    jp nc, $c1c5

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor [hl]
    push bc
    pop bc
    ld c, a
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    push bc
    adc $d4
    jp nc, $cec1

    jp Jump_022_7fc5


    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    cp d
    rst $08
    rst $08
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    and a
    rst $08
    ld a, a
    ret


    adc $7f
    call nc, Call_022_7fcf
    adc h
    ld d, h
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d9c1
    ld d, l
    ld a, a
    call nc, Call_022_7fcf
    db $d3
    ret


    push bc
    jp c, Jump_022_7fc5

    ld d, h
    ld a, a
    jp $d3c1


    ld d, l
    push de
    pop bc
    call z, $d9cc
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $c1d2
    adc $c7
    push bc
    ld a, a
    and e
    rst $08
    rst $00
    ret


    ld c, a
    jp $c9c8


    call z, Call_022_7fc5
    ret


    db $d3
    ld a, a
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    ld d, l
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld d, l
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, Jump_022_7fc5

    ld d, h
    ld a, a
    rst $10
    pop bc
    db $d3
    jp $d5c1


    ld d, l
    rst $00
    ret z

    call nc, Call_022_7f8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    reti


    pop bc
    jp $c9c8


    jp $c18c


    ld d, l
    adc $c4
    ld a, a
    xor c
    ld a, a
    call $c5c5
    call nc, Call_022_568c
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    jp nz, $d2c9

    call nz, $547f
    ld a, a
    jp $cec1


    ld a, a
    ld d, l
    adc $cf
    call nc, $c27f
    push bc
    ld a, a
    add $cf
    push de
    adc $c4
    add c
    ld d, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    reti


    ld c, a
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or b
    ret


    adc $cb
    ld a, a
    ret


    db $d3
    ld a, a
    ret nc

    push bc
    pop bc
    jp $c855


    adc l
    call z, $cbc9
    push bc
    ld a, a
    jp nc, $c4c5

    adc h
    ld a, a
    pop bc
    ld a, a
    add $cc
    rst $08
    ld d, l
    rst $10
    push bc
    jp nc, Jump_022_7fd9

    jp $cccf


    rst $08
    push de
    jp nc, Jump_000_0057

    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    ld c, a
    reti


    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or b
    ret


    adc $cb
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    ret nc

    push bc
    pop bc
    jp $8dc8


    call z, $cbc9
    push bc
    ld a, a
    jp nc, $c4c5

    adc h
    ld a, a
    ld d, l
    pop bc
    ld a, a
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_022_7fd9

    jp $cccf


    rst $08
    push de
    jp nc, Jump_022_558e

    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    add $c1
    call $d5cf
    db $d3
    ld a, a
    call nc, $c9c8
    adc $c7
    adc h
    ld a, a
    ld c, a
    ret z

    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    ret nc

    call z, $d9c1
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, [hl]
    ld d, [hl]
    adc h
    ld a, a
    ld d, h
    ld a, a
    rst $10
    pop bc
    ld d, l
    db $d3
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, $c37f
    pop bc
    db $d3
    push de
    pop bc
    call z, $d9cc
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ret z

    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    pop bc
    jp nc, $c1c5

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call Call_022_7fc5
    rst $08
    add $7f
    call nc, $55c8
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_022_7f7f
    ld d, a
    nop
    ld a, a
    call nc, $c5c8
    jp nc, Jump_022_7fc5

    pop bc
    jp nc, Jump_022_7fc5

    call $cec1
    reti


    ld a, a
    sub $4f
    pop bc
    jp nc, $cfc9

    push de
    db $d3
    ld a, a
    ld d, h
    db $d3
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    rst $10
    push bc
    call z, $cfc3
    call Call_022_7fc5
    call nc, Call_022_7fcf
    ret z

    push de
    adc $55
    call nc, $cec9
    rst $00
    ld a, a
    pop bc
    jp nc, $c1c5

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, h
    adc h
    ld a, a
    rst $00
    ld c, a
    reti


    call $c1ce
    db $d3
    ret


    push de
    call Call_022_7f7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c97f
    db $d3
    ld a, a
    and e
    ret z

    ret


    jp nc, $c1d2

    ld d, l
    rst $08
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    add $7f
    ret


    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $d3
    adc h
    push bc
    sub $c5
    jp nc, $d4d9

    ld d, l
    ret z

    ret


    adc $c7
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $8e
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    ld a, a
    xor e
    pop bc
    jp $c9c8


    call z, $4fc1
    ld a, a
    rst $08
    add $7f
    or d
    push bc
    call nz, $ac7f
    rst $08
    call nc, $d3d5
    ld a, a
    jp $d4c9


    ld d, l
    reti


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    pop bc
    ld d, l
    ret


    call nz, $d47f
    rst $08
    ld a, a
    jp nz, Jump_022_7fc5

    pop bc
    ld a, a
    db $d3
    call nc, $c1d2
    adc $c7
    ld d, l
    push bc
    jp nc, Jump_022_577f

    ld a, a
    call z, $d6c9
    push bc
    call nz, $c87f
    push bc
    jp nc, Jump_022_7fc5

    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_022_7fc5

    call nc, $c5c8
    ld a, a
    ret


    adc $d3
    call nc, $c955
    call nc, $d4d5
    push bc
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    jp nz, $c5c5

    adc $55
    ld a, a
    jp nz, $c9d5

    call z, Call_000_00d4
    ld a, a
    call $cec1
    db $d3
    ret


    rst $08
    adc $7f
    ld d, h
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    db $d3
    jp $c5c9


    adc $d4
    ret


    db $d3
    call nc, Call_022_7fd3
    ld a, a
    jp Jump_022_55c1


    call Call_022_7fc5
    ret z

    push bc
    jp nc, Jump_022_7fc5

    add $cf
    jp nc, $d37f

    call nc, $c4d5
    reti


    ld d, l
    ld a, a
    jp nz, Jump_022_7fd9

    jp $c1c8


    adc $c3
    push bc
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    or d
    push bc
    call nz, $ac7f
    rst $08
    call nc, Call_022_4fd5
    db $d3
    ld a, a
    or h
    rst $08
    rst $10
    adc $7f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or d
    push bc
    call nz, Call_022_557f
    call z, $d4cf
    push de
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c4c5

    adc h
    ld a, a
    pop bc
    ld a, a
    jp c, $c555

    pop bc
    call z, $c37f
    rst $08
    call z, $d5cf
    jp nc, Jump_000_0057

    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret


    adc $d3
    call nc, $c94f
    call nc, $d4d5
    push bc
    ld a, a
    ld d, h
    ld d, a
    nop
    ld a, a
    or d
    push bc
    call nz, $ac7f
    rst $08
    call nc, $d3d5
    ld a, a
    xor c
    db $d3
    call z, $cec1
    call nz, Call_022_7f4f
    ld d, h
    adc h
    ld a, a
    and a
    reti


    call $c1ce
    db $d3
    ret


    push de
    call Call_022_7f7f
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c97f
    db $d3
    ld a, a
    ld d, l
    set 0, c
    jp $c9c8


    call z, Call_022_7fc1
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    pop bc
    ld a, a
    jp c, $c555

    pop bc
    call z, $c77f
    push de
    push bc
    db $d3
    db $d3
    adc l
    call z, $d6cf
    ret


    adc $c7
    ld a, a
    ld d, l
    rst $08
    call z, Call_022_7fc4
    call $cec1
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    pop bc
    call nc, Call_022_7fc5
    adc h
    ld a, a
    call nc, Call_022_4fc8
    push bc
    ld a, a
    call nz, $cfcf
    jp nc, $c97f

    db $d3
    ld a, a
    call z, $c3cf
    set 0, l
    call nz, Call_022_558e
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    call nc, $4f9f
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    ld d, l
    adc h
    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    rst $10
    pop bc
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    ret z

    ld c, a
    ret


    db $d3
    ld a, a
    call nc, $d7cf
    adc $8c
    ld a, a
    adc h
    ld a, a
    ld a, a
    rst $10
    rst $08
    push de
    call z, $55c4
    ld a, a
    jp nz, $ccc5

    rst $08
    adc $c7
    ld a, a
    call nc, Call_022_7fcf
    ld d, l
    ld e, [hl]
    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    xor c
    adc h
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    rst $00
    jp nc, $c5c5

    ld c, a
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    adc $d3
    call nc, $d57f
    db $d3
    ld a, a
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    ld a, a
    rst $10
    rst $08
    push de
    call z, Call_022_7fc4
    rst $00
    ret


    sub $c5
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    ret z

    pop bc
    jp nc, Jump_022_7fc4

    call nc, $cdc9
    push bc
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor e
    push bc
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    rst $08
    jp $d5c3


    ret nc

    ret


    push bc
    call nz, Call_022_7f55
    jp nz, Jump_022_7fd9

    ld e, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    push bc
    sub $c9
    call z, $c47f
    push bc
    push bc
    call nz, Call_022_7f4f
    rst $10
    ret


    call nc, Call_022_7fc8
    pop bc
    ld a, a

Jump_022_5e7f:
    jp z, $d9cf

    adc h
    ret


    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    sub $c5
    jp nc, Jump_022_7fd9

    ret z

    pop bc
    ret nc

    ret nc

    ld d, l
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    ret nc

    pop bc
    ret


    adc $c6
    push de
    call z, Call_022_4f81
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_022_7fc5

    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_022_7fc5

    jp nz, $c9cc

    ld d, l
    adc $c4
    adc h
    ld a, a
    pop bc
    jp nc, $cec5

    add a
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    rst $10
    ld d, l
    ret z

    ret


    jp Jump_022_7fc8


    rst $10
    pop bc
    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_022_7fc5

    ld d, l
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    rst $08
    adc $9f
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    and e
    rst $08
    call $c5cd
    ld c, a
    jp nc, $c9c3

    pop bc
    call z, $a67f
    ret


    jp nc, Jump_022_7fcd

    ret


    db $d3
    ld a, a
    jp $d0c1


    ld d, l
    call nc, $d2d5
    push bc
    call nz, Call_022_7f8c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    db $d3
    push bc
    call z, Call_022_7fcc
    ret


    ld d, l
    call nc, $d47f
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    ld d, l
    ld d, h
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    push bc
    pop bc
    jp nc, Jump_022_7fce

    call $cec1
    reti


    ld d, l
    ld a, a
    call $cec1
    reti


    ld a, a
    call $cecf
    push bc
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld e, [hl]
    ld a, a
    rst $10
    ld c, a
    ret z

    rst $08
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, $d5c1
    rst $00
    ret z

    call nc, Call_022_7f7f
    ld d, l
    ld e, [hl]
    ld a, a
    pop bc
    ld a, a
    call z, $d3c5
    db $d3
    rst $08
    adc $8e
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    jp z, $d3d5

    call nc, $c27f
    reti


    ld a, a
    rst $08
    adc $55
    push bc
    db $d3
    push bc
    call z, Call_022_56c6
    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    push bc
    ret c

    call nc, Call_022_55d2
    pop bc
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, $81d9

    ld a, a
    ld d, a
    nop
    ld a, a
    xor h
    rst $08
    adc $c7
    ld a, a
    call z, $d6c9
    push bc
    add c
    ld c, a
    ld e, [hl]
    ld a, a
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, $d355

    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c67f
    jp nc, $c955

    rst $00
    ret z

    call nc, $cec5
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call $d2cf
    push bc
    adc h
    ld a, a
    ld d, l
    adc $cf
    rst $10
    ld a, a
    rst $10
    push bc
    ld a, a
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $08
    push de
    call nc, $d355
    ret


    call nz, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    or b
    push bc
    rst $08
    ret nc

    call z, Call_022_7fc5
    ret


    adc $7f
    xor e
    push bc
    jp nc, $c9d2

    pop bc
    ld c, a
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    add $cc
    push bc
    call nz, $cf7f
    ld d, l
    adc $c3
    push bc
    ld a, a
    pop bc
    ld a, a
    call nc, $cdc9
    push bc
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ret nc

    push bc
    jp nc, $cfd3

    adc $d3
    ld a, a
    pop bc
    jp nc, Jump_022_7fc5

    rst $00
    push bc
    ld d, l
    call nc, $c9d4
    adc $c7
    ld a, a
    ld a, a
    pop bc
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    adc [hl]
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    jp nz, $d4d5

    ld a, a
    adc h
    ld a, a
    ld a, a
    db $d3
    rst $08
    call $c4c5
    ld d, l
    pop bc
    reti


    ld a, a
    ret


    call nc, $c37f
    rst $08
    push de
    call z, Call_022_7fc4
    jp nc, $d4c5

    ret z

    jp nc, $c955

    sub $c5
    ld a, a
    pop bc
    db $d3
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, $81c5

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
    pop bc
    call nc, $c1d4
    ld c, a
    jp $c5cb


    call nz, $a87f
    ret


    call z, $d5cc
    add $c6
    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor h
    ret


    db $d3
    call nc, $cec5
    adc h
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    pop bc
    adc $7f
    ret


    call $cfd0
    jp nc, $c1d4

    adc $d4
    ld a, a
    push bc
    sub $c5
    ld d, l
    adc $d4
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and d
    ret


    jp $c9c8


    ld d, l
    call nc, $d2c5
    ld a, a
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    adc $c5
    pop bc
    jp nc, $d2c5

    adc h
    ld d, l
    ld a, a
    adc h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    push bc
    call nc, $ccd4
    ld d, l
    push bc
    call nz, Call_022_7f9f
    ld d, [hl]
    adc h
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
    ld d, l
    db $d3
    rst $08
    jp nc, $d9d2

    add c
    ld a, a
    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    and c
    ld a, a
    call $cec1
    ld a, a
    ld d, l
    call z, $d6cf
    ret


    adc $c7
    ld a, a
    jp z, $c9cf

    adc $c9
    adc $c7
    ld a, a
    ret


    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    add $d5
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    ret


    jp $c9c8


    call nc, $d2c5
    add c
    ld a, a
    ld d, b
    dec d
    ld d, b
    nop
    ld a, a
    xor c
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    ret z

    ret


    call Call_022_7f81
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    rst $08
    add $7f
    call $d3c9
    ld d, l
    db $d3
    ret


    call z, Call_022_7fc5
    ret


    db $d3
    ld a, a
    add $cc
    push bc
    push bc
    ret


    adc $c7
    ld a, a
    add $55
    jp nc, $cdcf

    ld a, a
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c77f
    push de
    pop bc
    jp nc, $8cc4

    ld a, a
    jp nz, $d4d5

    ld a, a
    ld a, a
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or b
    jp nc, $d6c5

    push bc
    adc $d4
    ret


    adc $c7
    ld a, a
    ld d, l
    db $d3
    push de
    db $d3
    ret nc

    push bc
    jp Jump_022_7fd4


    jp nz, $d9cf

    db $d3
    ld a, a
    ld a, a
    add $d2
    rst $08
    ld d, l
    call $d07f
    pop bc
    db $d3
    db $d3
    ret


    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    call Call_022_7fd9
    jp z, $cf55

    jp nz, Jump_000_0057

    ld a, a
    ld d, [hl]
    ld d, [hl]
    ld d, [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, [hl]
    call nc, $cbc1
    push bc
    ld c, a
    ld a, a
    pop bc
    ld a, a
    adc $c1
    ret nc

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $8c55
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    adc $c1
    ret nc

    ret nc

    ret


    adc $c7
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    xor e
    push bc
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $c94f


    call nc, Call_022_7fd9
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor e
    push bc
    jp nc, $c9d2

    pop bc
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    call z, $c5c4
    adc $8c
    ld a, a
    pop bc
    ld a, a
    add $cc
    pop bc
    ld d, l
    db $d3
    ret z

    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_022_577f

    nop
    ld a, a
    rst $00
    jp nc, $d0c1

    ret nc

    call z, Call_022_7fc5
    add $cf
    jp nc, $cdd5

    ld a, a
    ld d, a
    nop
    ld a, a
    xor e
    push bc
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, h
    adc h
    ld c, a
    ld a, a
    and a
    reti


    call $b47f
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c97f
    db $d3
    ld a, a
    ld d, l
    xor [hl]
    pop bc
    jp nc, $c8c3

    ret


    call Call_022_7fd9
    db $d3
    push de
    ret nc

    push bc
    jp nc, $c9c7

    jp nc, $cc55

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
    xor c
    call nc, $c37f
    pop bc
    adc $7f
    jp Jump_022_55d5


    jp nc, Jump_022_7fc5

    call nz, $d3c9
    push bc
    pop bc
    db $d3
    push bc
    db $d3
    ld a, a
    adc h
    call nz, $cfd2
    rst $10
    ld d, l
    db $d3
    reti


    adc h
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $8c
    ld a, a
    jp nz, $d2d5

    adc $7f
    ld d, l
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    db $d3
    call nc, $c9c2
    call nc, Call_022_7fc5
    ld d, [hl]
    adc [hl]
    ld d, l
    ld a, a
    xor c
    call nc, $c37f
    pop bc
    adc $7f
    jp $d2d5


    push bc
    ld a, a
    push bc
    sub $c5
    jp nc, $d955

    ld a, a
    call nz, $d3c9
    push bc
    pop bc
    db $d3
    push bc
    add c
    ld a, a
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    call nc, $c855
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    call z, $c7c9
    ret z

    ld d, l
    call nc, $d9cc
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    adc $d3
    ret


    sub $c5
    adc h
    ld a, a
    adc [hl]
    ret


    ld d, l
    call nc, $c97f
    db $d3
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    push bc
    jp nc, $d47f

    ret z

    pop bc
    adc $55
    ld a, a
    db $d3
    push bc
    ret nc

    push bc
    jp nc, $d4c1

    push bc
    call z, Call_022_7fd9
    jp nz, $d9d5

    ret


    adc $55
    rst $00
    ld a, a
    pop bc
    call z, $c5d4
    jp nc, $c1ce

    call nc, $d6c9
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, l
    jp nc, $c6c5

    jp nc, $d3c5

    ret z

    adc h
    ld a, a
    pop bc
    adc $d4
    ret


    call nz, $d4cf
    push bc
    ld d, l
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $08
    adc $81
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
    add c
    ld a, a
    adc $c5
    rst $10
    ld a, a
    ret nc

    jp nc, $c4cf

    push de
    jp Jump_022_7fd4


    db $d3
    push de
    ret nc

    ld d, l
    push bc
    jp nc, $c27f

    pop bc
    call z, Call_022_7fcc
    ld a, a
    ret


    db $d3
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ld d, l
    push bc
    add $c6
    push bc
    jp $c9d4


    sub $c5
    ld a, a
    call nc, $c1c8
    adc $7f
    call $55cf
    adc $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $cfd4
    ld a, a
    pop bc
    jp $d5c3


    ld d, l
    call z, $d4c1
    push bc
    call z, Call_022_7fd9
    ld a, a
    db $d3
    ret


    push bc
    jp c, Jump_022_7fc5

    ld d, l
    ld d, h
    add c
    ld a, a
    or h
    jp nc, Jump_022_7fd9

    call nc, Call_022_7fcf
    push de
    db $d3
    push bc
    ld a, a
    call nc, $c855
    ret


    db $d3
    ld a, a
    call nc, Call_022_7fcf
    db $d3
    ret


    push bc
    jp c, Jump_022_7fc5

    call nc, $c5c8
    ld a, a
    ld d, l
    adc $cf
    call nc, $c58d
    pop bc
    db $d3
    ret


    call z, $8dd9
    jp $d0c1


    call nc, $d2d5
    ld d, l
    push bc
    call nz, $547f
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    and e
    rst $08
    call $c5cd
    jp nc, $c9c3

    ld c, a
    pop bc
    call z, $d37f
    rst $08
    jp $c5c9


    call nc, $8cd9
    ld a, a
    and a
    push bc
    adc $c5
    jp nc, $c155

    call z, $a87f
    push bc
    pop bc
    call nz, $d5d1
    pop bc
    jp nc, $c5d4

    jp nc, Jump_022_7fd3

    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    rst $08
    call Call_022_7fc5
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    ld c, a
    rst $08
    call z, Call_022_7fc4
    db $d3
    push de
    ret nc

    push bc
    jp nc, $c1cd

    adc $7f
    ld d, a
    nop
    ld a, a
    xor b
    ret


    call z, $d5cc
    add $c6
    adc h
    ld a, a
    adc $c5
    rst $10
    ld a, a
    ret nc

    jp nc, Jump_022_4fcf

    call nz, $c3d5
    call nc, $c47f
    ret


    db $d3
    jp $d3d5


    db $d3
    push bc
    call nz, $c27f
    reti


    ld d, l
    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, $81c5
    ld a, a
    ld d, [hl]
    ld a, a
    call z, $cfcf
    res 1, h
    ld d, l
    ld a, a
    db $d3
    push bc
    call z, $c9cc
    adc $c7
    ld a, a
    call nz, $d9c1
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret z

    push bc
    ret


    rst $00
    ret z

    ld c, a
    call nc, $c47f
    ret


    add $c6
    push bc
    jp nc, $cec5

    jp Jump_022_7fc5


    rst $08
    adc $7f
    call nc, $c855
    push bc
    ld a, a
    jp nc, $c1cf

    call nz, Call_022_7f81
    or h
    rst $08
    ld a, a
    jp z, $cdd5

    ret nc

    ld a, a
    ld d, l
    call nz, $d7cf
    adc $7f
    adc [hl]
    ret


    db $d3
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call nc, $c555
    jp nc, $c9d2

    add $c9
    jp Jump_022_7f8e


    jp nz, $d4d5

    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, l
    ld a, a
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    jp nz, $c3c1

    bit 7, a
    rst $10
    ret z

    ret


    call nc, $c555
    ld a, a
    jp $d4c9


    reti


    ld a, a
    pop de
    push de
    ret


    jp $cccb


    reti


    ld a, a
    ld d, a
    ld d, l
    ld d, [hl]
    ld d, c
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    sub c
    ld a, a
    ret z

    jp z, $4fc7

    ret z

    rst $10
    pop bc
    reti


    adc h
    ld a, a
    rst $10
    ret z

    ret


    call nc, Call_022_7fc5
    jp $d4c9


    reti


    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    jp $d4c9


    ld d, l
    reti


    ld a, a
    ld d, a
    nop
    ld d, [hl]
    ret


    db $d3
    ld a, a
    adc $c5
    pop bc
    jp nc, Jump_022_567f

    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp nc, $d3c5

    call nc, Call_022_7f55
    add $c9
    jp nc, $d4d3

    call z, $8cd9
    call nc, $c5c8
    adc $7f
    rst $00
    rst $08
    ld a, a
    ld d, l
    call nc, $c5c8
    jp nc, Jump_022_7fc5

    jp $cdcf


    push bc
    ld a, a
    add $d2
    rst $08
    call $cc7f
    ld d, l
    ret


    rst $00
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    jp $d4c9


    reti


    adc h
    ld a, a
    ret nc

    ld d, l
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
    pop bc
    ld a, a
    jp $d6c1


    ld d, l
    push bc
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    call nc, $d2c9
    push bc
    call nz, Call_022_577f
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    ld a, a
    sub e
    ret z

    ret


    rst $00
    ld c, a
    ret z

    rst $10
    pop bc
    reti


    ld a, a
    ld d, [hl]
    adc h
    pop bc
    ret z

    push bc
    pop bc
    call nz, $c97f
    db $d3
    ld a, a
    ld d, l
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
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    adc h
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    push bc
    sub $c5
    jp nc, $4fc7

    jp nc, $c5c5

    adc $7f
    rst $10
    rst $08
    rst $08
    call nz, Call_022_7fd3
    pop bc
    call z, $cfd3
    ld a, a
    call $c555
    push bc
    call nc, $c97f
    call nc, Call_022_7f8c
    call nz, $cecf
    add a
    call nc, $d97f
    rst $08
    push de
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    ret


    add $c6
    push bc
    jp nc, $cec5

    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    rst $10
    ld c, a
    rst $08
    rst $08
    call nz, $8cd3
    ld a, a
    adc $c5
    pop bc
    jp nc, $c87f

    push bc
    jp nc, Jump_022_7fc5

    ld a, a
    ld d, l
    jp $cec1


    ld a, a
    jp $d0c1


    call nc, $d2d5
    push bc
    ld a, a
    ld d, h
    add c
    ld a, a
    ld d, l
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
    add $c5
    push bc
    call z, $cec9
    rst $00
    ld a, a
    rst $10
    ld c, a
    jp nc, $cecf

    rst $00
    push bc
    call nz, Call_022_7f8c
    reti


    rst $08
    push de
    ld a, a
    db $d3
    call nc, $ccc9
    call z, Call_022_7f55
    call z, $d3cf
    call nc, Call_022_587f
    nop
    ld a, a
    or h
    ret z

    rst $08
    push de
    rst $00
    ret z

    ld a, a
    add $c5
    push bc
    call z, $cec9
    rst $00
    ld a, a
    rst $10
    ld c, a
    jp nc, $cecf

    rst $00
    push bc
    call nz, Call_022_7f8c
    reti


    rst $08
    push de
    ld a, a
    db $d3
    call nc, $ccc9
    call z, Call_022_7f55
    call z, $d3cf
    call nc, Call_022_587f
    nop
    ld a, a
    db $d3
    ret z

    rst $08
    jp nc, $d3d4

    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    push de
    db $d3
    push bc
    add $d5
    ld c, a
    call z, $c67f
    rst $08
    jp nc, $cd7f

    rst $08
    sub $c9
    adc $c7
    add c
    ld a, a
    or a
    rst $08
    push de
    ld d, l
    call z, Call_022_7fc4
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, Call_022_7fcf
    ret nc

    push de
    ld d, l
    call nc, $c97f
    call nc, $cf7f
    adc $9f
    ld d, a
    nop
    ld a, a
    and c
    jp nc, Jump_022_7fc5

    reti


    rst $08
    push de
    ld a, a
    call $cbc1
    ret


    adc $c7
    ld a, a
    ld c, a
    ld e, e
    ld a, a
    jp $cdcf


    call $ced5
    ret


    jp $d4c1


    ret


    rst $08
    adc $9f
    ld d, l
    or h
    ret z

    push bc
    jp nc, Jump_022_7fc5

    pop bc
    jp nc, Jump_022_7fc5

    sub e
    sub b
    ld a, a
    ld d, h
    ld a, a
    ld d, l
    ret


    adc $7f
    pop bc
    ld a, a
    jp $d3c1


    push bc
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    jp nz, $ccc5

    ret


    push bc
    sub $c5
    ld a, a
    call nc, $c84f
    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    call z, $8ccc
    ld a, a
    jp nz, $d4d5

    ld a, a
    xor c
    ld d, l
    ld a, a
    call nz, $cecf
    add a
    call nc, $c57f
    ret c

    ret nc

    push bc
    jp Jump_022_7fd4


    ret


    call nc, Call_022_557f
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    jp nz, $ccc5

    ret


    push bc
    sub $c5
    ld a, a
    call nc, $c84f
    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    call z, $8ccc
    ld a, a
    jp nz, $d4d5

    ld a, a
    xor c
    ld d, l
    ld a, a
    call nz, $cecf
    add a
    call nc, $c57f
    ret c

    ret nc

    push bc
    jp Jump_022_7fd4


    ret


    call nc, Call_022_557f
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
    call $d6cf
    push bc
    call $cec5
    call nc, Call_022_7f81
    jp z, $d3d5

    call nc, $ce7f
    rst $08
    ld d, l
    rst $10
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret nc

    push bc
    push bc
    ret nc

    ld a, a
    call $8cc5
    call nz, $55cf
    ld a, a
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld d, a
    and d
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, l
    reti


    rst $08
    push de
    jp nc, $d07f

    push bc
    push bc
    ret nc

    ret


    adc $c7
    adc h
    ld a, a
    ret


    call nc, Call_022_557f
    jp $cec1


    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_022_7fcf
    jp nz, $cfcc

    rst $10
    db $d3
    ld d, l
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
    call $d6cf
    push bc
    call $cec5
    call nc, Call_022_7f81
    jp z, $d3d5

    call nc, $ce7f
    rst $08
    ld d, l
    rst $10
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret nc

    push bc
    push bc
    ret nc

    ld a, a
    call $8cc5
    call nz, $55cf
    ld a, a
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld d, a
    and d
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, l
    reti


    rst $08
    push de
    jp nc, $d07f

    push bc
    push bc
    ret nc

    ret


    adc $c7
    adc h
    ld a, a
    ret


    call nc, Call_022_557f
    jp $cec1


    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_022_7fcf
    jp nz, $cfcc

    rst $10
    db $d3
    ld d, l
    add c
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
    jp nc, $ce7f

    pop bc
    reti


    ld c, a
    ld a, a
    call $d2cf
    push bc
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
    jp nc, $ce7f

    pop bc
    reti


    ld c, a
    ld a, a
    call $d2cf
    push bc
    ld e, b
    nop
    ld a, a
    and c
    jp nc, Jump_022_7fc5

    reti


    rst $08
    push de
    ld a, a
    ld d, h
    ld c, a
    ld e, l
    sbc a
    ld a, a
    call nc, $c5c8
    adc $7f
    pop de
    push de
    ret


    ld d, l
    jp $81cb


    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    call nc, $c5c8
    ld a, a
    jp $d3c1


    push bc
    ld a, a
    ld e, e
    ld a, a
    ld a, a
    ld c, a
    ret


    db $d3
    ld a, a
    add $d5
    call z, Call_022_7fcc
    rst $08
    add $7f
    ld d, h
    jp $cec1


    ld d, l
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, $c37f

    pop bc
    db $d3
    push bc
    ld a, a
    ld d, a
    nop
    ld a, a
    adc $c5
    rst $10
    ld a, a
    ld d, h
    adc h
    ld a, a
    ret


    add $7f
    ld a, a
    add $c5
    call nc, $c34f
    ret z

    ld a, a
    ret


    call nc, Call_022_7f8c
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret


    call z, Call_022_7fcc
    rst $10
    ld d, l
    ret


    adc $7f
    ld e, b
    nop
    ld a, a
    adc $c5
    rst $10
    ld a, a
    ld d, h
    adc h
    ld a, a
    ret


    add $7f
    ld a, a
    add $c5
    call nc, $c34f
    ret z

    ld a, a
    ret


    call nc, Call_022_7f8c
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret


    call z, Call_022_7fcc
    rst $10
    ld d, l
    ret


    adc $7f
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $cc7f

    ret


    adc $c5
    ld a, a
    rst $08
    add $7f
    sub $c9
    db $d3
    ld c, a
    ret


    rst $08
    adc $81
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    add $c5
    ld d, l
    push bc
    call z, Call_022_7fd3
    adc $cf
    call nc, $c77f
    rst $08
    rst $08
    call nz, Call_022_7f81
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_022_7fcf
    adc $cf
    call nc, $d77f
    pop bc
    ld c, a
    adc $d4
    ld a, a
    call nc, Call_022_7fcf
    jp $cecf


    call nc, $d3c5
    call nc, $d97f
    rst $08
    push de
    ld d, l
    jp nc, $cc7f

    ret


    adc $c5
    ld a, a
    rst $08
    add $7f
    sub $c9
    db $d3
    ret


    rst $08
    adc $7f
    ld d, l
    call nz, $cecf
    add a
    call nc, $cc7f
    rst $08
    rst $08
    bit 7, a
    pop bc
    call nc, $c37f
    call z, $55cf
    db $d3
    push bc
    call z, Call_022_7fd9
    ld d, a
    nop
    ld a, a
    and e
    pop bc
    adc $87
    call nc, $d97f
    rst $08
    push de
    ld a, a
    jp nz, Jump_022_7fc5

    rst $00
    push bc
    adc $4f
    call nc, $c5cc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    rst $08
    add $d4
    ld a, a
    call nc, Call_022_7fcf
    rst $00
    ld d, l
    ret


    jp nc, $d3cc

    ld a, a
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    and e
    pop bc
    adc $87
    call nc, $d97f
    rst $08
    push de
    ld a, a
    jp nz, Jump_022_7fc5

    rst $00
    push bc
    adc $4f
    call nc, $c5cc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    rst $08
    add $d4
    ld a, a
    call nc, Call_022_7fcf
    rst $00
    ld d, l
    ret


    jp nc, $d3cc

    ld a, a
    sbc a
    ld a, a
    ld e, b
    nop
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    call nc, Call_022_7f9f
    reti


    rst $08
    push de
    ld a, a
    add $4f
    push bc
    call z, $cfcc
    rst $10
    reti


    rst $08
    push de
    ld a, a
    call nz, $c4c9
    adc $87
    call nc, $d77f
    ld d, l
    push bc
    pop bc
    jp nc, $d97f

    rst $08
    push de
    jp nc, $d37f

    ret z

    rst $08
    jp nc, $d3d4

    adc h
    ld a, a
    ld d, l
    call nz, $c4c9
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    sbc a
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

    adc $7f
    db $d3
    push de
    call Call_022_4fcd
    push bc
    jp nc, $cf7f

    jp nc, $c97f

    adc $7f
    rst $10
    ret


    adc $d4
    push bc
    jp nc, Jump_022_7f8c

    ld d, l
    jp z, $d3d5

    call nc, $d77f
    push bc
    pop bc
    jp nc, Jump_022_7fd3

    db $d3
    ret z

    rst $08
    jp nc, $d3d4

    ld d, l
    add c
    ld a, a
    call nc, $c1c8
    call nc, $c97f
    db $d3
    ld a, a
    call Call_022_7fd9
    call nc, $c3c1
    call nc, $c955
    jp Jump_022_7fd3


    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $cc7f
    rst $08
    db $d3
    call nc, $8c7f
    ld a, a
    xor c
    add a
    call $cc7f
    ld c, a
    rst $08
    db $d3
    call nc, Call_022_587f
    nop
    ld a, a
    xor c
    add a
    call $cc7f
    rst $08
    db $d3
    call nc, $8c7f
    ld a, a
    xor c
    add a
    call $cc7f
    ld c, a
    rst $08
    db $d3
    call nc, Call_022_587f
    nop
    xor h
    push bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld d, h
    ld a, a
    jp $d0c1


    call nc, Call_022_4fd5
    jp nc, $c4c5

    ld a, a
    jp z, $d3d5

    call nc, $ce7f
    rst $08
    rst $10
    ld a, a
    call nc, Call_022_7fcf
    jp $cf55


    call $c5d0
    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld a, a
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, Call_022_7f4f
    jp nz, Jump_022_7fd9

    ld d, [hl]
    ld a, a
    call nc, $c1c8
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    call nc, $d255
    rst $08
    adc $c7
    push bc
    jp nc, $d47f

    ret z

    pop bc
    adc $7f
    ld d, h
    ld d, a
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
    jp $d5d2


    db $d3
    ret z

    ld c, a
    ret


    adc $c7
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_000_007f
    ld a, a
    xor c
    ld a, a
    db $d3
    push de
    add $c6
    push bc
    jp nc, $c17f

    ld a, a
    jp $d5d2


    db $d3
    ret z

    ld c, a
    ret


    adc $c7
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_000_007f
    ld a, a
    xor b
    push bc
    reti


    ld d, [hl]
    add c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    call nc, $d5cf
    jp $c5c8


    call nz, $cd7f
    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    add $cf
    rst $08
    call nc, $cf7f
    add $4f
    ld a, a
    adc $cf
    rst $08
    adc $8d
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    ld a, a
    call $55cf
    push de
    adc $d4
    pop bc
    ret


    adc $8c
    ld a, a
    ret


    call nc, $c27f
    push bc
    rst $00
    ret


    adc $d3
    ld d, l
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    sub h
    ld a, a
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $c67f
    ret


    adc $c9
    db $d3
    ret z

    push bc
    call nz, Call_022_7f9f
    ld c, a
    ld e, b
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $c67f
    ret


    adc $c9
    db $d3
    ret z

    push bc
    call nz, Call_022_7f9f
    ld c, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ret nc

    pop bc
    ret


    adc $c6
    push de
    call z, Call_022_7f81
    xor c
    ld a, a
    rst $10
    ld c, a
    pop bc
    db $d3
    ld a, a
    db $d3
    call nc, $cdd5
    jp nz, $c5cc

    call nz, $cf7f
    sub $c5
    jp nc, Jump_022_557f

    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    rst $08
    ld d, l
    add $7f
    ld d, h
    add a
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $4f
    adc l
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    ld d, l
    adc $7f
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    adc $d4
    jp nc, $cec1

    jp Jump_022_7fc5


    ld d, l
    ld d, a
    ld a, a
    rst $08
    add $7f
    jp $d6c1


    push bc
    ld a, a
    ld d, [hl]
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    sub h
    ld a, a
    ret z

    ret


    rst $00
    ld c, a
    ret z

    rst $10
    pop bc
    reti


    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8d
    pop bc
    call nz, $c9cd
    ld d, l
    jp nc, $cec9

    rst $00
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    ld d, [hl]
    adc h
    ld d, l
    ld a, a
    set 0, l
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    call nc, Call_022_7fcf
    jp $cccf


    call z, $c3c5
    call nc, Call_022_4f7f
    call $d3d5
    ret z

    jp nc, $cfcf

    call $547f
    ld a, a
    call nc, $c1c8
    call nc, Call_022_7f55
    xor c
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_022_7fcf
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


    adc $81
    ld d, l
    ld d, a
    xor l
    pop bc
    reti


    jp nz, Jump_022_7fc5

    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    add a
    call nc, $c67f
    ld c, a
    ret


    adc $c4
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call $d3d5
    ret z

    jp nc, $cfcf

    call Call_022_557f
    ld a, a
    adc $c5
    pop bc
    jp nc, $d9c2

    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    ld a, a
    ld a, a
    ret z

    pop bc
    sub $55
    push bc
    ld a, a
    jp $cccf


    call z, $c3c5
    call nc, $c4c5
    ld a, a
    call nc, $c5c8
    call Call_022_557f
    rst $08
    push de
    call nc, Call_022_577f
    nop
    ld a, a
    ld a, a
    rst $08
    ret z

    adc h
    ld a, a
    xor c
    ld a, a
    jp $cccf


    call z, $c3c5
    call nc, $c4c5
    ld c, a
    ld a, a
    ret


    call nc, $d77f
    ret


    call nc, Call_022_7fc8
    rst $00
    jp nc, $c1c5

    call nc, $c47f
    ret


    ld d, l
    add $c6
    ret


    jp $ccd5


    call nc, $81d9
    ld a, a
    ld e, b
    nop
    ld a, a
    ld a, a
    rst $08
    ret z

    adc h
    ld a, a
    xor c
    ld a, a
    jp $cccf


    call z, $c3c5
    call nc, $c4c5
    ld c, a
    ld a, a
    ret


    call nc, $d77f
    ret


    call nc, Call_022_7fc8
    rst $00
    jp nc, $c1c5

    call nc, $c47f
    ret


    ld d, l
    add $c6
    ret


    jp $ccd5


    call nc, $81d9
    ld a, a
    ld e, b
    nop
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d2c7

    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld c, a
    pop bc
    rst $00
    push bc
    ld a, a
    ld a, a
    jp nz, $c7c5

    ret


    adc $d3
    ld a, a
    ret z

    push bc
    jp nc, Jump_022_7fc5

    ld d, l
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    call nz, $c9d2
    push bc
    call nz, $cc7f
    push bc
    pop bc
    sub $c9
    push bc
    db $d3
    ld d, l
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d2c7

    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld c, a
    pop bc
    rst $00
    push bc
    ld a, a
    ld a, a
    jp nz, $c7c5

    ret


    adc $d3
    ld a, a
    ret z

    push bc
    jp nc, $ccc5

    ld d, l
    ret


    rst $00
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    call nz, $c9d2
    push bc
    call nz, $cc7f
    push bc
    pop bc
    sub $c9
    push bc
    db $d3
    ld d, l
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    rst $08
    add c
    ld a, a
    or a
    ret z

    rst $08
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    pop bc
    sub $4f
    push bc
    db $d3
    call nz, $cfd2
    ret nc

    ret nc

    ret


    adc $c7
    ld a, a
    rst $08
    push de
    jp nc, $d37f

    push bc
    ld d, l
    jp $c5d2


    call nc, $d47f
    pop bc
    call z, $c9cb
    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld d, l
    adc $7f
    rst $08
    sub $c5
    jp nc, $c5c8

    pop bc
    jp nc, $d2c5

    add c
    ld a, a
    ld d, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    ret z

    ret


    db $d3
    ret nc

    push bc
    jp nc, $cec9

    ld c, a
    rst $00
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $c77f
    push bc
    ld c, a
    call nc, $d77f
    ret


    adc $7f
    ld e, b
    nop
    ld a, a
    or a
    ret z

    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $c77f
    push bc
    ld c, a
    call nc, $d77f
    ret


    adc $7f
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
    rst $08
    sub $c5
    jp nc, $d47f

    ret z

    ld c, a
    push bc
    jp nc, $81c5

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld a, a
    jp $cec1


    add a
    call nc, $cf7f
    ld d, l
    sub $c5
    jp nc, $c5c8

    pop bc
    jp nc, $cf7f

    call nc, $c5c8
    jp nc, $d387

    ld a, a
    jp $c855


    pop bc
    call nc, Call_022_577f
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    ret nc

    push bc
    db $d3
    bit 7, a
    ret


    adc $7f
    db $d3
    ld c, a
    rst $08
    add $d4
    ld a, a
    sub $cf
    ret


    jp Jump_022_7fc5


    ld d, [hl]
    ld d, a
    nop
    ld a, a
    and h
    pop bc
    call Call_022_7fce
    reti


    rst $08
    push de
    add c
    ld a, a
    and d
    push bc
    ret


    adc $c7
    ld a, a
    ld c, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call z, $cf55
    db $d3
    push bc
    ld a, a
    add $c1
    jp Jump_022_7fc5


    ld e, b
    nop
    ld a, a
    and h
    pop bc
    call Call_022_7fce
    reti


    rst $08
    push de
    add c
    ld a, a
    and d
    push bc
    ret


    adc $c7
    ld a, a
    ld c, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call z, $cf55
    db $d3
    push bc
    ld a, a
    add $c1
    jp Jump_022_7fc5


    ld e, b
    nop
    ld a, a
    and c
    call $cecf
    rst $00
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    pop bc
    jp nc, $c1c5

    ld a, a
    ld c, a
    adc h
    ld a, a
    call nc, $c5c8
    jp nc, Jump_022_7fc5

    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_022_7fd3

    adc $55
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    ret


    adc $d3
    push bc
    jp $d3d4


    ld a, a
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor c
    add a
    call $d37f
    call nc, $ccc9
    call z, $8c7f
    ld a, a
    call z, $cbc9
    ret


    ld c, a
    adc $c7
    ld a, a
    ret


    adc $d3
    push bc
    jp $d3d4


    ld a, a
    ld d, h
    xor h
    push bc
    call nc, $8755
    db $d3
    ld a, a
    rst $00
    rst $08
    ld a, a
    jp nz, $c3c1

    bit 7, a
    push bc
    sub $c5
    jp nc, $d2c7

    ld d, l
    push bc
    push bc
    adc $7f
    rst $10
    rst $08
    rst $08
    call nz, Call_022_7fd3
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $d37f
    ret


    call $ccd0
    reti


    ld a, a
    ret


    db $d3
    ld a, a
    add $4f
    rst $08
    rst $08
    call z, $d3c9
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $d37f
    ret


    call $ccd0
    reti


    ld a, a
    ret


    db $d3
    ld a, a
    add $4f
    rst $08
    rst $08
    call z, $d3c9
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5d0

    call nc, Call_022_7f9f
    xor c
    db $d3
    ld a, a
    call nc, $c84f
    push bc
    jp nc, Jump_022_7fc5

    pop bc
    adc $d9
    call nc, $c9c8
    adc $c7
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    call z, $c9c4
    adc $c7
    ld a, a
    call $d2cf
    push bc
    ld a, a
    adc h
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    add $c5
    push bc
    call z, Call_022_7fd3
    pop bc
    call nc, $c57f
    pop bc
    db $d3
    push bc
    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c1cf

    call nz, Call_022_577f
    adc [hl]
    ld a, a
    nop
    ld a, a
    and a
    rst $08
    rst $08
    call nz, $c68d
    rst $08
    jp nc, $ce8d

    rst $08
    call nc, $c9c8
    adc $c7
    ld c, a
    ld a, a
    adc [hl]
    ld a, a
    and d
    push bc
    ret


    adc $c7
    ld a, a
    ret nc

    jp nc, $d6cf

    rst $08
    set 0, l
    call nz, Call_022_7f55
    pop bc
    adc $c4
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    ld e, b
    nop
    ld a, a
    and a
    rst $08
    rst $08
    call nz, $c68d
    rst $08
    jp nc, $ce8d

    rst $08
    call nc, $c9c8
    adc $c7
    ld c, a
    ld a, a
    adc [hl]
    ld a, a
    and d
    push bc
    ret


    adc $c7
    ld a, a
    ret nc

    jp nc, $d6cf

    rst $08
    set 0, l
    call nz, Call_022_7f55
    pop bc
    adc $c4
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    sbc a
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    ld c, a
    call Call_022_7f8c
    adc [hl]
    ld a, a
    and e
    rst $08
    adc $d4
    pop bc
    jp Jump_022_7fd4


    call $d9c1
    jp nz, $c555

    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_022_577f
    nop
    ld a, a
    and e
    pop bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    call nc, $ccc5
    call z, $cd7f
    push bc
    ld a, a
    ld c, a
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $cf7f
    add $7f
    rst $00
    push bc
    call nc, $d455
    ret


    adc $c7
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_022_7f9f

    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    call nc, $cc7f
    rst $08
    rst $08
    set 2, e
    ld a, a
    ld a, a
    adc $cf
    call nc, Call_022_7f4f
    db $d3
    push de
    jp $c5c3


    db $d3
    db $d3
    add $d5
    call z, $d9cc
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    call nc, $cc7f
    rst $08
    rst $08
    set 2, e
    ld a, a
    ld a, a
    adc $cf
    call nc, Call_022_7f4f
    db $d3
    push de
    jp $c5c3


    db $d3
    db $d3
    add $d5
    call z, $d9cc
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c1
    jp Jump_022_7fc5


    xor c
    ld a, a
    adc $4f
    push bc
    sub $c5
    jp nc, $d37f

    pop bc
    rst $10
    add c
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d37f
    ld d, l
    call nc, $cfd2
    adc $c7
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d77f
    push bc
    pop bc
    res 3, a
    ld a, a
    adc [hl]
    ld a, a
    rst $08
    jp nc, Jump_022_7f4f

    call Call_022_7fd9
    db $d3
    set 1, c
    call z, Call_022_7fcc
    ld a, a
    ret nc

    rst $08
    rst $08
    jp nc, Jump_022_557f

    ld d, [hl]
    adc [hl]
    ld a, a
    or a
    ret z

    ret


    jp Jump_022_7fc8


    call nz, Call_022_7fcf
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    call nc, $c9c8
    adc $cb
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $d9
    call nc, $c9c8
    adc $c7
    ld a, a
    call z, $cbc9
    push bc
    ld c, a
    ld a, a
    call nc, $c1c8
    call nc, $8e58
    ld a, a
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $d9
    call nc, $c9c8
    adc $c7
    ld a, a
    call z, $cbc9
    push bc
    ld c, a
    ld a, a
    call nc, $c1c8
    call nc, SerialTransferCompleteInterrupt
    ld a, a
    or l
    adc $c4
    push bc
    jp nc, $d2c7

    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld c, a
    pop bc
    rst $00
    push bc
    ld a, a
    jp nz, $c7c5

    ret


    adc $d3
    ld a, a
    ret z

    push bc
    jp nc, Jump_022_7fc5

    xor h
    ld d, l
    ret


    rst $00
    ret z

    call nc, $cec5
    ret


    adc $c7
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_022_557f

    ld d, [hl]
    adc h
    ld a, a
    pop bc
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, a
    nop
    ld a, a
    or l
    adc $c4
    push bc
    jp nc, $d2c7

    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld c, a
    pop bc
    rst $00
    push bc
    ld a, a
    jp nz, $c7c5

    ret


    adc $d3
    ld a, a
    ret z

    push bc
    jp nc, Jump_022_7fc5

    xor h
    ld d, l
    ret


    rst $00
    ret z

    call nc, $cec5
    ret


    adc $c7
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_022_557f

    ld d, [hl]
    adc h
    ld a, a
    pop bc
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    ld d, h
    adc h
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    ld c, a
    sub $c5
    jp nc, Jump_022_7fd9

    db $d3
    call nc, $cfd2
    adc $c7
    adc [hl]
    ld a, a
    jp nz, $d4d5

    adc h
    ld d, l
    ld a, a
    and c
    jp nc, Jump_022_7fc5

    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c17f
    call nc, Call_022_557f
    db $d3
    jp $c5c9


    adc $c3
    push bc
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call $d37f
    call nc, $ccc9
    call z, $d37f
    push de
    ret


    call nc, Call_022_4f7f
    call nc, Call_022_7fcf
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    db $d3
    push de
    call nz, $c5c4
    adc $cc
    reti


    ld a, a
    add $c1
    call z, Call_022_7fcc
    ld e, b
    nop
    ld a, a
    db $d3
    push de
    call nz, $c5c4
    adc $cc
    reti


    ld a, a
    add $c1
    call z, Call_022_7fcc
    ld e, b
    nop
    ld a, a
    and a
    rst $08
    rst $08
    call nz, Call_022_7f81
    jp $cecf


    call nc, $d3c5
    call nc, Call_022_7f8c
    call nc, $d24f
    reti


    ld a, a
    reti


    rst $08
    push de
    jp nc, $cc7f

    push de
    jp $9fcb


    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    rst $08
    call nz, $d9c1
    ld a, a
    xor c
    ld a, a
    pop bc
    call $c17f
    call z, $c1d7
    reti


    ld c, a
    db $d3
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    add $7f
    call z, $c3d5
    bit 7, a
    db $d3
    call nc, Call_022_55c1
    reti


    ld a, a
    ret z

    push bc
    jp nc, Jump_022_7fc5

    ret


    adc $7f
    push bc
    pop bc
    jp nc, $c5ce

    db $d3
    call nc, Call_022_7f55
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    call nc, $c4cf
    pop bc
    reti


    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    push de
    ld c, a
    call nc, $cf7f
    add $7f
    call z, $c3d5
    res 0, c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    call nc, $c4cf
    pop bc
    reti


    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    push de
    ld c, a
    call nc, $cf7f
    add $7f
    call z, $c3d5
    res 0, c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    db $d3
    call nc, $c1d2
    call nc, $c7c5
    reti


    ld a, a
    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    adc $c5
    jp $d3c5


    db $d3
    pop bc
    jp nc, Jump_022_7fd9

    ld d, a
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    ld d, l
    jp $cecf


    call nc, $d3c5
    call nc, $cec9
    rst $00
    adc [hl]
    ld a, a
    nop
    ld a, a
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    db $d3
    call nc, $c3c9
    set 3, c
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    jp z, $d555

    db $d3
    call nc, $c27f
    push bc
    rst $00
    ret


    adc $ce
    ret


    adc $c7
    adc [hl]
    ld a, a
    and c
    adc $55
    call nz, $c77f
    push bc
    call nc, $d37f
    push de
    jp nc, $ccd0

    push de
    db $d3
    ld a, a
    call nz, $cecf
    ld d, l
    push bc
    ld a, a
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
    ld d, l
    ld a, a
    push bc
    add $c6
    rst $08
    jp nc, $8ed4

    ld a, a
    nop
    ld a, a
    and d
    push bc
    reti


    rst $08
    adc $c4
    ld a, a
    call Call_022_7fd9
    push de
    adc $c4
    push bc
    jp nc, Jump_022_4fd3

    call nc, $cec1
    call nz, $cec9
    rst $00
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push bc
    reti


    rst $08
    adc $c4
    ld a, a
    call Call_022_7fd9
    push de
    adc $c4
    push bc
    jp nc, Jump_022_4fd3

    call nc, $cec1
    call nz, $cec9
    rst $00
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    xor c
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    xor [hl]
    ld c, a
    ret


    call nz, $d2c5
    call z, $cec1
    adc $8c
    ld a, a
    ld a, a
    xor c
    ld a, a
    jp $cccf


    call z, $c555
    jp Jump_022_7fd4


    call $cec1
    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    push bc
    adc $7f
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    ld c, a
    ld d, h
    adc h
    ld a, a
    ld a, a
    rst $00
    jp nc, $c4c1

    push de
    pop bc
    call z, $d9cc
    ld a, a
    rst $00
    ld d, l
    push bc
    call nc, Call_022_7fd3
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    call z, $d6cf
    push bc
    call z, Call_022_55d9
    and a
    push bc
    call nc, $c9d4
    adc $c7
    adc l
    adc $cf
    adc l
    ret nc

    jp nc, $cdcf

    rst $08
    call nc, $c955
    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    call $d2cf
    push bc
    ld a, a
    call z, $d6cf
    push bc
    call z, $d955
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    push de
    call nc, $d78c
    ret z

    reti


    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push de
    call nc, $d78c
    ret z

    reti


    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    pop bc
    ld a, a
    ld c, a
    rst $00
    rst $08
    rst $08
    call nz, $d47f
    ret z

    ret


    adc $c7
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    jp nz, Jump_022_55d5

    call nc, $547f
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
    ld d, l
    call nz, $8e7f
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    reti


    ld a, a
    jp $c1c8


    adc $c3
    push bc
    adc h
    ld a, a
    xor c
    ld a, a
    rst $10
    pop bc
    adc $4f
    call nc, $d47f
    rst $08
    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $08
    push de
    call nc, $d47f
    rst $08
    ld a, a
    jp nz, Jump_022_55d2

    push bc
    pop bc
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    call Call_022_7fc5
    add $d2
    push bc
    db $d3
    ret z

    ld a, a
    ld d, l
    pop bc
    ret


    jp nc, $8c7f

    ld a, a
    pop bc
    db $d3
    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_022_7fc5
    db $d3
    ld d, l
    call nc, $d0cf
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    add $d2
    rst $08
    adc $d4
    ld a, a
    ld d, l
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    rst $00
    pop bc
    call nc, Call_022_7fc5
    rst $08
    add $7f
    xor e
    push bc
    ld d, l
    jp nc, $c9d2

    pop bc
    adc [hl]
    ld a, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld a, a
    xor c
    ld a, a
    ld c, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, Call_022_7fcf
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    ret z

    pop bc
    jp nc, $c455

    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld a, a
    xor c
    ld a, a
    ld c, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, Call_022_7fcf
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    ret z

    pop bc
    jp nc, $c455

    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    ret


    db $d3
    db $d3
    jp $d5cf


    call z, $cec4
    add a
    call nc, $c27f
    push bc
    ld a, a
    ld c, a
    call $d2cf
    push bc
    ld a, a
    call z, $d6cf
    push bc
    call z, $81d9
    call $c1c9
    rst $08
    rst $10
    ld d, l
    add c
    ld a, a
    call $d7c5
    ret


    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    pop bc
    ret z

    add c
    and d
    rst $08
    jp nz, Jump_022_7fcf

    pop bc
    adc $c4
    ld a, a
    xor e
    push bc
    call z, $c14f
    call nc, Call_022_7fc1
    pop bc
    jp nc, Jump_022_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    call z, $d6cf
    push bc
    ld d, l
    call z, $a9d9
    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    ret z

    rst $08
    ld d, l
    rst $10
    ld a, a
    call nc, Call_022_7fcf
    jp $cfc8


    rst $08
    db $d3
    push bc
    ld a, a
    reti


    push bc
    call nc, Call_022_7f81
    ld d, l
    ld d, a
    nop
    reti


    push bc
    db $d3
    add c
    ld a, a
    ld e, b
    reti


    push bc
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    push de
    jp Jump_022_7fc8


    jp nc, $cec1

    rst $00
    push bc
    ld a, a
    call z, $cbc9
    push bc
    db $d3
    ld c, a
    ld a, a
    pop bc
    db $d3
    ld a, a
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_022_7fd3

    ret


    adc $7f
    pop bc
    ld a, a
    ld d, l
    jp nc, $d7cf

    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $cec1

    rst $00
    push bc
    adc [hl]
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    push de
    pop bc
    jp nc, Jump_022_7fc4

    rst $08
    add $7f
    xor e
    push bc
    jp nc, $d24f

    ret


    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, Call_022_557f
    call z, $d4c5
    ld a, a
    push de
    db $d3
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

    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    pop bc
    call nc, Call_022_7fc5
    adc [hl]
    ld a, a
    or h
    ret z

    rst $08
    ld d, l
    push de
    rst $00
    ret z

    ld a, a
    pop bc
    db $d3
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, Call_022_7f8c
    ret z

    ld d, l
    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $c4c1

    ld a, a
    ret


    adc $d4
    push bc
    adc $d4
    ret


    ld d, l
    rst $08
    adc $d3
    ld a, a
    ld d, a
    nop
    ld a, a
    and a
    rst $08
    ld a, a
    call nc, $cfcf
    ld a, a
    add $c1
    jp nc, $a181

    call z, Call_022_7fcc
    pop bc
    ld c, a
    jp nc, Jump_022_7fc5

    call z, $d6cf
    push bc
    call z, Call_022_7fd9
    ld d, h
    adc [hl]
    ld a, a
    jp nz, Jump_022_55d5

    call nc, Call_022_587f
    nop
    ld a, a
    and a
    rst $08
    ld a, a
    call nc, $cfcf
    ld a, a
    add $c1
    jp nc, $a181

    call z, Call_022_7fcc
    pop bc
    ld c, a
    jp nc, Jump_022_7fc5

    call z, $d6cf
    push bc
    call z, Call_022_7fd9
    ld d, h
    adc [hl]
    ld a, a
    jp nz, Jump_022_55d5

    call nc, Call_022_587f
    nop
    xor c
    add a
    call $d37f
    call nc, $ccc9
    call z, Call_022_7f7f
    pop bc
    ld a, a
    sub $c1
    rst $00
    jp nc, $c14f

    adc $d4
    ld a, a
    rst $00
    pop bc
    call $ccc2
    push bc
    jp nc, Jump_022_7f81

    ld d, a
    nop
    or a
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, $c27f

    push bc
    call nc, $cf7f
    jp nc, Jump_022_4f7f

    ld d, h
    ld a, a
    adc h
    ld a, a
    sub $c9
    jp $cfd4


    jp nc, Jump_022_7fd9

    rst $08
    jp nc, Jump_022_557f

    call nz, $c6c5
    push bc
    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call $c555
    add c
    db $d3
    ret


    adc $c3
    push bc
    ld a, a
    ret


    call nc, $c27f
    push bc
    rst $00
    ret


    adc $d3
    ld d, l
    adc h
    ld a, a
    ret


    call nc, $c37f
    pop bc
    adc $7f
    adc $cf
    call nc, $d37f
    call nc, $d0cf
    ld d, l
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    or a
    ret z

    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c5
    ld a, a
    ld c, a
    call nc, $c5c8
    ld a, a
    add $c9
    jp nc, $d4d3

    ld a, a
    rst $00
    rst $08
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    or a
    ret z

    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c5
    ld a, a
    ld c, a
    call nc, $c5c8
    ld a, a
    add $c9
    jp nc, $d4d3

    ld a, a
    rst $00
    rst $08
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    or d
    rst $08
    push de
    adc $c4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call z, $c7c9
    ret z

    call nc, Call_022_4f7f
    call z, $cbc9
    push bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    call nc, $d9cf
    ld a, a
    ld d, h
    add c
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
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
    sbc a
    ld a, a
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
    jp nc, Jump_022_7fc4

    call nc, $c1c8
    call nc, Call_022_4f7f
    or b
    ret


    ret nc

    ret


    ld a, a
    ld a, a
    push bc
    sub $cf
    call z, $d4d5
    push bc
    call nz, $c67f
    push de
    ld d, l
    jp nc, $c8d4

    push bc
    jp nc, Jump_022_7f7f

    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    ld d, l
    adc $7f
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $8e
    ld d, l
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    jp nc, $c1c5

    call nz, $c97f
    call nc, $cf7f
    adc $7f
    ld d, l
    call nc, $c5c8
    ld a, a
    call nz, $c9c1
    call z, Call_022_7fd9
    adc $c5
    rst $10
    db $d3
    ret nc

    pop bc
    ret nc

    ld d, l
    push bc
    jp nc, Jump_022_7f8e

    ld d, [hl]
    adc h
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d47f
    jp nc, Jump_022_55d5

    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    call nc, $d0cf
    add c
    ld a, a
    or h
    rst $08
    ld a, a
    call Call_022_7fd9
    or b
    ret


    ret nc

    ret


    ld c, a
    ld a, a
    adc h
    ld a, a
    call nz, $cecf
    add a
    call nc, $c27f
    push bc
    ld a, a
    call nc, $cfcf
    ld a, a
    jp nc, $d555

    call nz, $81c5
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    call nc, $d0cf
    add c
    ld a, a
    or h
    rst $08
    ld a, a
    call Call_022_7fd9
    or b
    ret


    ret nc

    ret


    ld c, a
    ld a, a
    adc h
    ld a, a
    call nz, $cecf
    add a
    call nc, $c27f
    push bc
    ld a, a
    call nc, $cfcf
    ld a, a
    jp nc, $d555

    call nz, $81c5
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_022_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    sbc c
    ret z

    ret


    rst $00
    ret z

    ld c, a
    rst $10
    pop bc
    reti


    ld a, a
    call z, $c7c9
    ret z

    call nc, $c27f
    call z, $c5d5
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    jp nc, $c3cf

    bit 7, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $55
    ld a, a
    call nc, $ced5
    adc $c5
    call z, Call_022_577f
    nop
    reti


    rst $08
    rst $08
    adc h
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
    sub $4f
    push bc
    ld a, a
    ld d, h
    adc h
    ld d, [hl]
    adc h
    ld a, a
    rst $10
    rst $08
    adc $c4
    push bc
    jp nc, $55c6

    push de
    call z, Call_022_7f81
    ld d, a
    nop
    ld a, a
    xor c
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $ced5
    adc $c5
    call z, $8c7f
    ld a, a
    ld c, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_022_7fd9

    call nz, $d2c1
    bit 7, a
    adc h
    ld d, l
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $cf
    ld a, a
    call z, $c955
    rst $00
    ret z

    call nc, $d2c5
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    adc $55
    rst $08
    call nc, $c77f
    rst $08
    ld a, a
    add $cf
    jp nc, $c1d7

    jp nc, $8ec4

    ld d, a
    nop
    xor b
    push bc
    reti


    add c
    ret z

    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ret


    call nc, Call_022_7f4f
    ret


    db $d3
    adc [hl]
    ld a, a
    ld e, b
    nop
    xor b
    push bc
    reti


    add c
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ret


    ld c, a
    call nc, $c97f
    db $d3
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    rst $08
    ld a, a
    pop bc
    jp nc, Jump_022_7fc5

    reti


    rst $08
    push de
    sbc a
    ld a, a
    xor b
    rst $08
    call z, $c44f
    ret


    adc $c7
    ld a, a
    pop bc
    ld a, a
    adc $cf
    call nc, $c27f
    pop bc
    call nz, Call_022_557f
    ld d, h
    adc h
    ld a, a
    ld a, a
    rst $10
    pop bc
    call z, Call_022_7fcb
    rst $10
    ret


    call nc, Call_022_7fc8
    add $55
    pop bc
    call z, $c5d4
    jp nc, $cec9

    rst $00
    ld a, a
    db $d3
    call nc, $d0c5
    db $d3
    adc h
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_022_7fc5

    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d47f
    rst $08
    rst $08
    ld a, a
    jp nc, $c7c5

    jp nc, $d4c5

    add $d5
    ld c, a
    call z, $d47f
    rst $08
    ld a, a
    call nc, $c1c5
    jp nc, $c48d

    jp nc, $d0cf

    ret nc

    ret


    adc $55
    rst $00
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    ret nc

    pop bc
    db $d3
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld c, a
    jp nc, $c3cf

    bit 7, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    call nc, $ced5
    ld d, l
    adc $c5
    call z, Call_022_7f8c
    xor c
    add a
    call $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $cf55

    pop bc
    call nz, $d47f
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, l
    jp $d4c9


    reti


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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_022_7f4f:
Jump_022_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_022_7f55:
Jump_022_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_022_7f7f:
Jump_022_7f7f:
    nop
    nop

Call_022_7f81:
Jump_022_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_022_7f8c:
Jump_022_7f8c:
    nop
    nop

Jump_022_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_022_7f9f:
Jump_022_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_022_7fc1:
    nop
    nop
    nop

Call_022_7fc4:
Jump_022_7fc4:
    nop

Call_022_7fc5:
Jump_022_7fc5:
    nop
    nop
    nop

Call_022_7fc8:
Jump_022_7fc8:
    nop
    nop
    nop

Call_022_7fcb:
Jump_022_7fcb:
    nop

Call_022_7fcc:
Jump_022_7fcc:
    nop

Jump_022_7fcd:
    nop

Call_022_7fce:
Jump_022_7fce:
    nop

Call_022_7fcf:
Jump_022_7fcf:
    nop

Call_022_7fd0:
    nop
    nop
    nop

Call_022_7fd3:
Jump_022_7fd3:
    nop

Jump_022_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_022_7fd9:
Jump_022_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
