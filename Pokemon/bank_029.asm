; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $029", ROMX[$4000], BANK[$29]

    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    push bc
    rst $00
    rst $00
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ld c, a
    ld e, h
    sub h
    sub c
    add c
    ld a, a
    ld d, l
    xor a
    adc $cc
    reti


    ld a, a
    rst $08
    adc $c5
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    jp $cec1


    ld d, l
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    db $d3
    ld d, l
    rst $08
    ld a, a
    call z, $c3d5
    set 3, c
    ld a, a
    call nc, $c1c8
    call nc, Call_029_547f
    ld a, a
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    adc $c1
    call Call_029_7fc5
    pop bc
    adc $c4
    ld a, a
    call z, $c3d5
    bit 7, a
    and e
    pop bc
    ld c, a
    call nc, $c8c3
    ret


    adc $c7
    ld a, a
    ret


    call nc, $d97f
    rst $08
    push de
    add a
    call z, Call_029_7fcc
    ld d, l
    jp nz, Jump_029_7fc5

    db $d3
    push de
    ret nc

    push bc
    jp nc, $d5cc

    jp $d9cb


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    adc $c1
    call Call_029_7fc5
    pop bc
    adc $c4
    ld a, a
    pop bc
    adc $c1
    push bc
    db $d3
    call nc, $4fc8
    push bc
    call nc, $c3c9
    ld a, a
    jp nz, $ccc1

    call z, $c17f
    jp nc, Jump_029_7fc5

    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    pop bc
    call Call_029_7fc5
    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cecf
    db $d3
    ld d, l
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, Call_029_7f81
    ld e, b
    nop
    ld a, a
    adc $c1
    call Call_029_7fc5
    xor e
    pop bc
    jp nc, $d5cc

    call z, Call_029_7fc1
    or h
    ret z

    push bc
    ld c, a
    ld a, a
    jp $cfcc


    db $d3
    push bc
    ld a, a
    call nc, $cfd7
    ld a, a
    ld d, h
    ld a, a
    rst $08
    add $55
    ld a, a
    and [hl]
    pop bc
    call nc, $c5c8
    jp nc, $c17f

    adc $c4
    ld a, a
    db $d3
    rst $08
    adc $7f
    ret nc

    ld d, l
    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    ld d, l
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cdcf
    pop bc
    jp Jump_029_7fc8


    call nc, $cf55
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    adc $c1
    call Call_029_7fc5
    reti


    pop bc
    call nz, $cecf
    rst $00
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, $c54f
    ret nc

    push bc
    adc $c4
    push bc
    adc $d4
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    ld d, l
    push de
    call $cec1
    add a
    db $d3
    ld a, a
    call nc, $cdc5
    ret nc

    push bc
    jp nc, Jump_029_7f8e

    db $d3
    rst $08
    ld d, l
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    rst $10
    pop bc
    jp nc, $cccd

    reti


    ld a, a
    rst $10
    push bc
    call z, $c355
    rst $08
    call $81c5
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nz, $ccd5
    call z, Call_029_557f
    ld d, h
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_029_7fc5
    call $d6cf
    ret


    adc $c7
    add c
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    adc $c1
    call Call_029_7fc5
    xor h
    pop bc
    jp nz, $ccd5

    pop bc
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    call nz, $c1d2
    ld d, l
    rst $00
    rst $08
    adc $7f
    ld a, a
    rst $08
    add $7f
    db $d3
    push bc
    pop bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call $d3c1
    call nc, $d2c5
    ld a, a
    ret


    adc $7f
    call nc, $c855
    push bc
    ld a, a
    db $d3
    push bc
    pop bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    adc $c1
    call Call_029_7fc5
    and c
    push de
    call $c9ce
    call nc, Call_029_7fc5
    ret


    db $d3
    ld a, a
    ld c, a
    jp nc, $d6c5

    ret


    sub $c5
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_029_557f
    ld d, h
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    adc $c1
    call Call_029_7fc5
    xor e
    pop bc
    jp nz, $d4d5

    push bc
    jp nc, $c97f

    db $d3
    ld a, a
    ld c, a
    jp nc, $d6c5

    ret


    sub $c5
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_029_557f
    ld d, h
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nc, Jump_029_7fc5

    reti


    rst $08
    push de
    ld a, a
    xor l
    jp nc, $4f8e

    ld d, d
    add c
    ld a, a
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    push bc
    ld d, l
    jp nc, Jump_029_7fc5

    ld d, e
    ld a, a
    rst $08
    add $7f
    push bc
    call z, $c5c4
    jp nc, Jump_029_7f55

    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_029_7f8c

    adc [hl]
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, $c555

    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret


    adc $d3
    call nc, $d4c9
    push de
    call nc, $c555
    ld a, a
    rst $08
    add $7f
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    adc [hl]
    ld a, a
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
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    ld a, a
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld d, l
    ld a, a
    adc [hl]
    ld a, a
    ret z

    pop bc
    call nz, $d27f
    push bc
    pop de
    push de
    push bc
    db $d3
    call nc, $c4c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call nc, Call_029_7fcf
    call nz, Call_029_7fcf
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $cb55

    add c
    xor c
    call nc, $cd7f
    push de
    db $d3
    call nc, $c27f
    push bc
    ld a, a
    jp nc, $c1c5

    call z, $cc55
    reti


    ld a, a
    ret z

    pop bc
    jp nc, Jump_029_7fc4

    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    add $55
    rst $08
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    add c
    ld a, a
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
    call nz, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld d, b
    ld de, $0050
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_029_4fcf
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    adc $55
    pop bc
    call Call_029_7fc5
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    call nc, $d7cf
    adc $7f
    ret


    ld d, l
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, Jump_029_7fc5

    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld d, l
    jp nc, Jump_029_7fc5

    adc h
    ld a, a
    ld a, a
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    call $c155
    ret nc

    ld a, a
    ret nc

    pop bc
    call $c8d0
    call z, $d4c5
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    adc $55
    rst $08
    push de
    rst $00
    ret z

    add c
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
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret


    call z, Call_029_7fcc
    pop bc
    call z, Call_029_7fcc
    call nc, $c5c8
    ld a, a
    call nz, $d0c5
    ld c, a
    rst $08
    call nz, $d4c9
    push bc
    call nz, $c47f
    pop bc
    call nc, Call_029_7fc1
    jp nz, Jump_029_7fc5

    call nz, Call_029_55c5
    call z, $d4c5
    push bc
    call nz, Call_029_7f9f
    ld d, a
    nop
    ld a, a
    or a
    ret z

    ret


    jp Jump_029_7fc8


    add $cc
    rst $08
    rst $08
    jp nc, $c47f

    rst $08
    ld a, a
    reti


    ld c, a
    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_029_7fcf
    rst $00
    rst $08
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    jp $c5cc


    jp nc, Jump_029_7fcb

    rst $08
    add $7f
    call nc, $c84f
    push bc
    ld a, a
    add $d2
    ret


    push bc
    adc $c4
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    db $d3
    call nc, Call_029_55cf
    jp nc, Jump_029_7fc5

    adc h
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    jp $cecf


    sub $c5
    ld d, l
    adc $c9
    push bc
    adc $d4
    ld a, a
    ret nc

    jp nc, $d0cf

    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ld a, a
    adc [hl]
    ld d, l
    ld a, a
    xor [hl]
    push bc
    ret c

    call nc, $d47f
    ret


    call Call_029_7fc5
    rst $10
    ret z

    push bc
    adc $7f
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_029_7fcf
    call nc, $c5c8
    ld a, a
    push bc
    sub $55
    push bc
    jp nc, $d2c7

    push bc
    push bc
    adc $7f
    jp $d4c9


    reti


    ld a, a
    rst $10
    push bc
    call z, $55c3
    rst $08
    call Call_029_7fc5
    reti


    rst $08
    push de
    ld a, a
    call nc, Call_029_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld d, l
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    ld d, l
    reti


    push bc
    db $d3
    add c
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    pop bc
    call $ccd0
    push bc
    ld a, a
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ret nc

    call z, $c1c5
    ld d, l
    db $d3
    push bc
    add c
    ld a, a
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
    or a
    push bc
    call z, $cfc3
    call Call_029_7fc5
    call nc, Call_029_7fcf
    rst $08
    push de
    jp nc, $d37f

    ld c, a
    ret z

    rst $08
    ret nc

    ld a, a
    call nc, Call_029_7fcf
    jp nz, $d9d5

    ld a, a
    call nc, $c5c8
    ld a, a
    call Call_029_55cf
    adc $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $d47f
    ret z

    pop bc
    call nc, $c37f
    ld d, l
    pop bc
    adc $7f
    jp $d4c1


    jp Jump_029_7fc8


    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_029_7f9f
    xor c
    db $d3
    ld a, a
    ret


    ld c, a
    call nc, Call_029_527f
    sbc a
    ld a, a
    xor l
    reti


    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $d055
    pop bc
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ret


    db $d3
    adc $87
    call nc, Call_029_7f55
    ret


    adc $7f
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
    call nc, $cf55
    ld a, a
    call $c5c5
    call nc, $c87f
    ret


    call Call_029_7f81
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    db $d3
    push de
    db $d3
    ret nc

    push bc
    jp $81d4


    ld a, a
    xor c
    ld c, a
    add a
    call $c17f
    adc $7f
    pop bc
    call nz, $ccd5
    call nc, $8c7f
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld d, l
    xor c
    add a
    call $ce7f
    rst $08
    call nc, $c77f
    jp nc, $c5c5

    call nz, Call_029_7fd9
    add $cf
    ld d, l
    jp nc, $c67f

    rst $08
    rst $08
    call nz, Call_029_7f81
    ld d, d
    ld a, a
    add $c9
    jp nc, $d355

    call nc, $d9cc
    ld a, a
    ld a, a
    xor c
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_029_7fc4
    call Call_029_55c1
    set 0, l
    ld a, a
    rst $00
    jp nc, $c1c5

    call nc, $c57f
    add $c6
    rst $08
    jp nc, $d3d4

    ld a, a
    ld d, l
    call nc, Call_029_7fcf
    jp nz, Jump_029_7fc5

    jp $cfc8


    db $d3
    push bc
    adc $7f
    rst $08
    push de
    call nc, Call_029_5581
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    or h
    ret z

    push bc
    ld a, a
    ld a, a
    ld d, h
    xor c
    add a
    ld c, a
    sub $c5
    ld a, a
    jp $cfc8


    db $d3
    push bc
    adc $7f
    call z, $cfcf
    set 2, e
    ld a, a
    db $d3
    ld d, l
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_029_7f81

    ld d, a
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cecf
    db $d3
    call nc, Call_029_4fc5
    jp nc, $c27f

    pop bc
    call z, Call_029_7fcc
    ld a, a
    ld d, h
    call nc, $c1c8
    call nc, $c97f
    ld d, l
    db $d3
    ld a, a
    ret


    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    add $cc
    pop bc
    call Call_029_7fc5
    ld d, h
    ld a, a
    xor c
    ld c, a
    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, Jump_029_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    pop bc
    ld a, a
    db $d3
    ret z

    ld d, l
    pop bc
    call nz, $d7cf
    ld a, a
    rst $08
    add $7f
    ret z

    push de
    call $cec1
    ld a, a
    add $c9
    rst $00
    ld d, l
    push de
    jp nc, $9fc5

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
    call nc, $d0c5
    ret nc

    push bc
    call nz, Call_029_7f4f
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    call nz, $d0c5
    push bc
    adc $c4
    push bc
    adc $d4
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    call nc, $d2cf
    call nc, $c9cf
    db $d3
    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    push bc
    pop bc
    call z, $d9cc
    sbc a
    ld a, a
    pop bc
    adc $7f
    push de
    adc $c9
    call Call_029_4fc1
    rst $00
    ret


    adc $c1
    jp nz, $c5cc

    ld a, a
    db $d3
    push bc
    push bc
    call nz, $cf7f
    add $7f
    ret nc

    ld d, l
    call z, $cec1
    call nc, Call_029_547f
    ld a, a
    adc [hl]
    ld a, a
    or a
    ret


    call z, Call_029_7fcc
    ret


    ld d, l
    call nc, $c47f
    rst $08
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
    ld d, h
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c1c5

    ld c, a
    call z, $d9cc
    ld a, a
    sub $c5
    jp nc, Jump_029_7fd9

    ret z

    push bc
    pop bc
    call z, $c8d4
    reti


    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    sub $c5
    jp nc, Jump_029_7fd9

    rst $00
    rst $08
    rst $08
    call nz, Call_029_7f81
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
    call nz, $4f7f
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $a17f
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, b
    ld de, $0050
    ld a, a
    xor b
    push bc
    jp nc, Jump_029_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $d3c1
    call nc, Call_029_7f4f
    rst $08
    adc $c5
    ld a, a
    ld d, [hl]
    or h
    ret z

    push bc
    ld a, a
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    ld d, l
    rst $08
    add $7f
    and h
    jp nc, Jump_029_7f8e

    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    ld c, a
    jp $cdcf


    push bc
    ld a, a
    jp z, $d3d5

    call nc, $c97f
    adc $7f
    call nc, $cdc9
    push bc
    ld d, l
    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    rst $10
    push bc
    call z, Call_029_7fcc
    ret


    db $d3
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
    jp $cdcf


    ret nc

    ret


    call z, $c4c5
    ld d, l
    ld a, a
    sbc a
    ld a, a
    or a
    ret z

    ret


    jp Jump_029_7fc8


    ld d, [hl]
    sbc a
    ld a, a
    xor h
    push bc
    call nc, Call_029_557f
    call Call_029_7fc5
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call z, $cfcf
    bit 7, a
    add $cf
    ld d, l
    jp nc, $d97f

    rst $08
    push de
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    or h
    ret z

    push bc
    adc $7f
    ld c, a
    ld d, d
    or a
    ret z

    ret


    jp Jump_029_7fc8


    ld d, h
    ld a, a
    db $d3
    ret z

    ld d, l
    pop bc
    call z, Call_029_7fcc
    rst $10
    push bc
    ld a, a
    call z, $cfcf
    res 3, a
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    xor a
    ret z

    adc h
    ld a, a
    xor c
    ld a, a
    db $d3
    ld c, a
    push bc
    push bc
    add c
    ld a, a
    and l
    sub $c5
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    ret


    call z, Call_029_55c4
    ld a, a
    ld d, h
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    push de
    call nc, Call_029_7f8c
    pop bc
    db $d3
    ld d, l
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
    call z, $d4c5
    ld a, a
    ld d, l
    ret z

    ret


    call $c37f
    rst $08
    call $c5d0
    call nc, Call_029_7fc5
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    rst $10
    ret


    call z, Call_029_7fcc
    rst $00
    rst $08
    ld a, a
    call nc, Call_029_7fcf
    call nc, $c5c8
    ld a, a
    adc $55
    push bc
    ret c

    call nc, $c48d
    rst $08
    rst $08
    jp nc, $d47f

    rst $08
    rst $10
    adc $7f
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    ld a, a
    ld d, d
    ld a, a
    ld c, a
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $c17f
    call nz, Call_029_55cd
    ret


    call nc, $c87f
    ret


    db $d3
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_029_7f8e
    xor c
    call nc, Call_029_7f55
    db $d3
    ret z

    rst $08
    push de
    call z, Call_029_7fc4
    jp nz, Jump_029_7fc5

    jp nz, $d4c5

    call nc, $d2c5
    ld d, l
    ld a, a
    call nc, Call_029_7fcf
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_029_7fc5
    ld d, l
    call z, $d4c5
    call nc, $cec9
    rst $00
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    jp $cdcf


    ret nc

    ld d, l
    push bc
    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    ld c, a
    ld d, d
    ld a, a
    adc h
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, Call_029_7f55
    reti


    rst $08
    push de
    sbc a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, h
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, $c17f
    jp nc, $c555

    ld a, a
    pop bc
    call z, Call_029_7fcc
    rst $08
    jp nz, $c4c5

    ret


    push bc
    adc $d4
    sbc a
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_029_7fc4
    ret z

    pop bc
    sub $c5
    ld a, a
    ret z

    pop bc
    ld d, l
    call nz, Call_029_7f7f
    rst $08
    add $7f
    ld d, h
    ld e, l
    add c
    ld d, l
    ld a, a
    ld d, [hl]
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    rst $00
    ret


    sub $c5
    adc $55
    ld a, a
    call nc, Call_029_7fcf
    call $9fc5
    ld a, a
    ld d, d
    ld a, a
    rst $00
    ret


    sub $55
    push bc
    db $d3
    ld a, a
    ret z

    ret


    call $d37f
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    ld d, l
    call nc, $c1c8
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_029_7fc4
    jp nz, Jump_029_7fc5

    db $d3
    push bc
    ld d, l
    adc $d4
    ld a, a
    call nc, Call_029_7fcf
    and h
    jp nc, Jump_029_7f8e

    and c
    rst $08
    jp $c9c8


    call nz, Call_029_55c5
    jp nc, Jump_029_7f81

    ld d, b
    ld de, $b700
    push bc
    call z, $81cc
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    adc l
    call Call_029_55c1
    call nz, Call_029_7fc5
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, Call_029_7f7f
    ld d, l
    call nc, $c1c8
    call nc, $a97f
    add a
    sub $c5
    ld a, a
    rst $08
    jp nc, $c5c4

    jp nc, $c4c5

    ld d, l
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
    call nc, $c1c8
    ld d, l
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    sub $c5
    jp nc, Jump_029_7fd9

    call $c3d5
    ret z

    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, Call_029_7fcc
    call nc, $c5c8
    ld a, a
    ld a, a
    ld d, h
    db $d3
    ld a, a
    call z, $4fc9
    sub $c9
    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    push bc
    sub $c5
    jp nc, Jump_029_55d9

    rst $10
    ret z

    push bc
    jp nc, Jump_029_7fc5

    pop bc
    jp nc, Jump_029_7fc5

    rst $10
    pop bc
    ret


    call nc, $cec9
    rst $00
    ld d, l
    ld a, a
    add $cf
    jp nc, Jump_029_527f

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    ld a, a
    ld d, h
    reti


    rst $08
    push de
    ld c, a
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_029_7fc4
    ret z

    pop bc
    sub $c5
    ld a, a
    adc $cf
    ld a, a
    pop bc
    ld d, l
    adc $d9
    ld a, a
    call $d4c5
    ret z

    rst $08
    call nz, $d47f
    rst $08
    ld a, a
    rst $00
    push bc
    call nc, Call_029_557f
    ret


    call nc, $c97f
    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    add $cf
    ld d, l
    push de
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $d4c5
    pop bc
    ret


    call z, $c4c5
    ld a, a
    ld d, l
    call nz, $d4c1
    pop bc
    ld a, a
    rst $08
    add $7f
    ld d, h
    ld a, a
    add c
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    call $d3d5
    call nc, $c87f
    pop bc
    sub $c5
    ld a, a
    call nc, Call_029_7fcf
    ld a, a
    jp Jump_029_55c1


    call nc, $c8c3
    ld a, a
    ret z

    ret


    call Call_029_7f81
    xor c
    adc $7f
    rst $08
    jp nc, $c5c4

    jp nc, Jump_029_7f55

    call nc, Call_029_7fcf
    jp $d4c1


    jp Jump_029_7fc8


    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    rst $00
    ret


    ld d, l
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $d3c8
    push bc
    db $d3
    ld a, a
    ret


    call $cfd0
    ld d, l
    jp nc, $c1d4

    adc $d4
    ld a, a
    ret nc

    jp nc, $d0cf

    db $d3
    add c
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $55
    push bc
    call nz, $957f
    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $d355
    add c
    ld a, a
    ld d, b
    ld de, $d4a9
    add a
    db $d3
    ld a, a
    pop bc
    adc $7f
    rst $08
    ret nc

    ret nc

    rst $08
    jp nc, $55d4

    push de
    adc $c9
    call nc, Call_029_7fd9
    rst $10
    ret z

    push bc
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    ret


    ld d, l
    call z, Call_029_7fc4
    ld d, h
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $cdd5

    ret nc

    push de
    adc $55
    rst $00
    ld a, a
    rst $08
    push de
    call nc, Call_029_7f81
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_029_55c4
    ld a, a
    jp $d4c1


    jp Jump_029_7fc8


    ld d, h
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    call nc, $d2c8
    rst $08
    rst $10
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cecf
    db $d3
    call nc, Call_029_55c5
    jp nc, $c27f

    pop bc
    call z, Call_029_7fcc
    ld a, a
    rst $08
    push de
    call nc, $817f
    ld a, a
    jp nz, $d4d5

    ld d, l
    ld a, a
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

    push bc
    ld d, l
    call nc, $c5c8
    jp nc, $cf7f

    jp nc, $ce7f

    rst $08
    call nc, $d97f
    rst $08
    push de
    ld a, a
    jp $c155


    adc $7f
    jp $d4c1


    jp Jump_029_7fc8


    ld a, a
    db $d3
    call $cfcf
    call nc, $ccc8
    ld d, l
    reti


    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call z, $c8d4
    reti


    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    call z, $c3d5
    ld d, l
    set 3, c
    ld a, a
    call nc, Call_029_7fcf
    push bc
    db $d3
    jp $d0c1


    push bc
    ld a, a
    push bc
    pop bc
    db $d3
    ret


    ld d, l
    call z, Call_029_7fd9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    rst $08
    add $d4
    push bc
    adc $7f
    jp $cf4f


    call $d3c5
    ld a, a
    ret z

    push bc
    jp nc, Jump_029_7fc5

    call nc, Call_029_7fcf
    db $d3
    ret z

    rst $08
    rst $10
    ld d, l
    ld a, a
    rst $08
    add $c6
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
    db $d3
    ld a, a
    rst $08
    ld d, l
    add $7f
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
    ld a, a
    pop bc
    call z, $55d7
    pop bc
    reti


    db $d3
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret


    call nc, $c17f
    call nc, $c87f
    push bc
    pop bc
    ld d, l
    jp nc, $81d4

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_029_7fc5

    push bc
    ret c

    ret


    db $d3
    call nc, Call_029_7fd3
    pop bc
    adc $7f
    ld c, a
    pop bc
    adc $c1
    call z, $c7cf
    push de
    push bc
    ld a, a
    call nc, Call_029_7fcf
    call nc, $c5c8
    ld a, a
    ret


    ld d, l
    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    adc $c4
    jp nz, Jump_029_55cf

    rst $08
    res 0, c
    ld a, a
    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    pop bc
    rst $00
    push bc
    db $d3
    ld d, l
    ld a, a
    pop bc
    jp nc, Jump_029_7fc5

    pop bc
    call z, Call_029_7fcc
    jp nz, $c1cc

    adc $cb
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    rst $10
    push bc
    ld a, a
    db $d3
    pop bc
    ld c, a
    rst $10
    ld a, a
    ret


    call nc, Call_029_7f8c
    rst $10
    push bc
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld d, l
    ld a, a
    pop bc
    adc $d9
    call nc, $c9c8
    adc $c7
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld d, l
    ld a, a
    and h
    jp nc, Jump_029_7f8e

    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    pop bc
    adc $7f
    pop bc
    push de
    call nc, $cfc8
    jp nc, $d4c9

    pop bc
    call nc, $d6c9
    push bc
    ld a, a
    ld d, l
    ret nc

    push bc
    jp nc, $cfd3

    adc $7f
    rst $08
    adc $7f
    ld a, a
    ld d, h
    add c
    ld a, a
    and d
    ld d, l
    push de
    call nc, $cd7f
    pop bc
    adc $d9
    ld a, a
    ld a, a
    ld d, h
    ld a, a
    ld d, l
    ld e, l
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $d27f
    push bc
    db $d3
    ld d, l
    ret nc

    push bc
    jp Jump_029_7fd4


    and h
    jp nc, Jump_029_7f8e

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
    ld d, e
    sbc d
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    add c
    ld a, a
    ld a, a
    ld c, a
    pop bc
    adc $c4
    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, Jump_029_7fd3

    pop bc
    jp nc, Jump_029_7fc5

    sub $c5
    ld d, l
    jp nc, Jump_029_7fd9

    call nc, $d2c9
    push bc
    call nz, Call_029_7f81
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    xor c
    db $d3
    ld a, a
    ret


    call nc, $4f7f
    ld d, e
    sbc a
    ld a, a
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    and c
    ret z

    adc h
    ld d, l
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    sbc a
    ld a, a
    xor c
    add a
    call $d37f
    ret z

    rst $08
    push de
    ld d, l
    call nc, $cec9
    rst $00
    add c
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $d6cf
    push bc
    ld d, l
    call $cec5
    call nc, Call_029_7f81
    and c
    ret z

    adc h
    ld a, a
    ld d, d
    add c
    ld a, a
    ld d, l
    and c
    jp nc, Jump_029_7fc5

    call nc, $c5c8
    jp nc, Jump_029_7fc5

    sub e
    ld a, a
    ld a, a
    ld d, h
    sbc a
    ld d, l
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_029_7fc5

    jp Jump_029_55cf


    adc $c3
    push bc
    pop bc
    call z, Call_029_7fd3
    ld d, h
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $817f
    ld a, a
    xor c
    ld d, l
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $c1
    call $d5cf
    db $d3
    ld a, a
    ld a, a
    ld d, h
    ld a, a
    ld d, l
    ld e, l
    ld a, a
    add $cf
    jp nc, $cd7f

    reti


    ld a, a
    push bc
    ret c

    ld d, l
    jp $ccc5


    call z, $cec5
    jp $81c5


    ld a, a
    jp nz, $d4d5

    ld a, a
    adc $cf
    rst $10
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    call z, $8cc4
    ld a, a
    rst $08
    adc $cc
    reti


    ld d, l
    ld a, a
    push bc
    ret c

    ret


    db $d3
    call nc, Call_029_7fd3
    call nc, $d2c8
    push bc
    push bc
    ld a, a
    db $d3
    adc [hl]
    ld a, a
    ld d, l
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $08
    adc $c5
    add c
    ld a, a
    ld a, a
    ld d, l
    ld d, [hl]
    db $d3
    push bc
    call z, $c3c5
    call nc, $d08c
    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    ld a, a
    and c
    ret z

    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    db $d3
    ld c, a
    call z, $81d9
    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    add c
    ld a, a
    pop bc
    call z, $cfd3
    ld d, l
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    call Call_029_7fc5
    rst $08
    adc $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    ld a, a
    xor b
    add a
    call Call_029_7f81
    and h
    ld c, a
    rst $08
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    pop bc
    adc $d8
    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld d, l
    ld d, e
    add c
    ld a, a
    db $d3
    push bc
    call z, $c3c5
    call nc, $cf7f
    adc $c5
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    sbc d
    ld a, a
    xor b

Call_029_4fc1:
Jump_029_4fc1:
    ret


    adc h
    rst $10
    ret z

Call_029_4fc5:
Jump_029_4fc5:
    push bc
    ld c, a

Jump_029_4fc7:
    jp nc, Jump_029_7fc5

    pop bc
    jp nc, Jump_029_7fc5

    reti


Call_029_4fcf:
    rst $08

Call_029_4fd0:
    push de
    ld a, a

Call_029_4fd2:
    rst $00
    rst $08

Jump_029_4fd4:
    ret


Call_029_4fd5:
    adc $c7
    ld a, a
    ld d, l
    call nc, $9fcf
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    jp nz, $c3c1

    res 0, c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    xor c
    ld a, a
    rst $10
    pop bc
    ld c, a
    adc $d4
    ld a, a
    call nc, $c9c8
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
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
    call nz, $504f
    ld bc, $cd68
    nop
    ld d, l
    add $d2
    rst $08
    call $a17f
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    add c
    ld a, a
    ld d, b
    ld de, $0050
    ld a, a
    ld d, e
    sbc d
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $4fc9
    adc $d5
    call nc, $81c5
    ld a, a
    ld d, d
    add c
    ld a, a
    xor c
    call nc, $d387
    ld d, l
    ld a, a
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, $c67f
    rst $08
    jp nc, $cd7f

    push bc
    ld d, l
    ld a, a
    call nc, Call_029_7fcf
    rst $00
    push bc
    call nc, Call_029_547f
    ld a, a
    add $d2
    rst $08
    call Call_029_557f
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    and c
    jp Jump_029_7fd4


    ld d, l
    pop bc
    db $d3

Call_029_507f:
    ld a, a
    call Call_029_7fd9
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    or a
    push bc
    call z, $81cc
    ld a, a
    and e
    rst $08
    call Call_029_4fd0
    push bc
    call nc, Call_029_7fc5
    rst $10
    ret


    call nc, Call_029_7fc8
    rst $08
    call nc, $c5c8
    jp nc, Jump_029_557f

    ld d, h
    ld a, a
    add $c9
    jp nc, $d4d3

    add c
    ld a, a
    reti


    rst $08
    push de
    add a
    call z, Call_029_55cc
    ld a, a
    rst $00
    push bc
    call nc, $d37f
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, $c17f

    adc $c4
    ld d, l
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_029_7f81

    ld d, d
    add c
    ld d, l
    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    add c
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    jp nz, $d955

    push bc
    adc l
    jp nz, $c5d9

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    call z, $cfd3
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ret


    adc $4f
    rst $00
    ld a, a
    ld d, h
    pop bc
    db $d3
    ld a, a
    pop bc
    adc $7f
    pop bc
    db $d3
    db $d3
    ret


    db $d3
    call nc, $c155
    adc $d4
    ld a, a
    rst $08
    add $7f
    call nz, $c3cf
    call nc, $d2cf
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and l
    call z, $c5c4
    jp nc, $c27f

    jp nc, $d4cf

    ret z

    push bc
    jp nc, $c29a

    jp nc, $cf4f

    call nc, $c5c8
    jp nc, Jump_029_7f81

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
    call $d2cf
    push bc
    ld a, a
    ret


    ld c, a
    call z, $d5cc
    db $d3
    ret


    rst $08
    adc $d3
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $d47f
    ret z

    ld d, l
    push bc
    ld a, a
    db $d3
    call nc, $cccf
    push bc
    adc $7f
    add c
    ld a, a
    and h
    ret


    rst $00
    push de
    call nc, Call_029_55c5
    jp nc, Jump_029_7f7f

    ret


    adc $7f
    call Call_029_7fd9
    add $c1
    call $ccc9
    reti


    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    call nc, $c1c5
    jp $c9c8


    adc $c7
    ld a, a
    ld a, a
    ld d, a
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    ld d, l
    call nc, Call_029_7fcf
    call nz, $c7c9
    ld a, a
    pop bc
    ld a, a
    ret z

    rst $08
    call z, Call_029_7fc5
    ld a, a
    rst $10
    ret z

    ld d, l
    ret


    call z, Call_029_7fc5
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, [hl]
    ld a, a
    ld c, a
    add $c5
    call z, $cfcc
    rst $10
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call Call_029_55c5
    db $d3
    db $d3
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    call $c4c1
    push bc
    ld a, a
    ret


    adc $55
    ld a, a
    call Call_029_7fd9
    ret z

    rst $08
    push de
    db $d3
    push bc
    ld a, a
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    ld d, l
    call nc, $cccf
    push bc
    adc $7f
    ld d, l
    ld e, h
    ld a, a
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $d3c5
    push bc
    jp nc, $81d4

    ld a, a
    or h
    ld d, l
    push bc
    pop bc
    jp Jump_029_7fc8


    ret z

    ret


    call $d47f
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    call z, $cc55
    ld a, a
    rst $08
    add $7f
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, Call_029_7fcf
    call nz, $c7c9
    ld a, a
    pop bc
    ld d, l
    ld a, a
    ret z

    rst $08
    call z, Call_029_7fc5
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d5cf

    ld d, l
    adc $c4
    add c
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    adc $55
    db $d3
    ret


    sub $c5
    ld a, a
    ld d, a
    add c
    ld a, a
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    ret z

    rst $08

Call_029_527f:
Jump_029_527f:
    rst $10
    ld a, a
    pop bc
    jp nc, Jump_029_7fc5

    reti


    rst $08
    push de
    sbc a
    ld c, a
    ld a, a
    or a
    ret z

    pop bc

Call_029_528e:
    call nc, $d77f
    ret


    call z, Call_029_7fcc
    call nc, $c5c8
    ld a, a
    ld a, a

Jump_029_529a:
    add $55
    push bc
    push bc
    call z, $d77f
    ret z

    ret


    call z, Call_029_7fc5
    jp nc, $c4c9

    ret


    adc $c7
    ld a, a
    ld d, l
    pop bc
    ld a, a
    jp nz, $cbc9

    push bc
    sbc a
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c27f
    ret


    set 0, l
    ld d, l
    ld a, a
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_029_7fc5

    call $c1c5
    adc $c9
    adc $c7
    ld d, l
    sbc a
    ld a, a
    xor a
    add $7f
    jp $d5cf


    jp nc, $c5d3

    ld a, a
    call nc, $c1c8
    call nc, Call_029_5581
    ld a, a
    xor c
    call nc, $c37f
    pop bc
    adc $7f
    jp nc, $ced5

    ld a, a
    adc $cf
    call nc, $cf7f
    ld d, l
    adc $cc
    reti


    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    add $c1
    jp nc, $c27f

    ret


    ld d, l
    set 0, l
    adc l
    jp nc, $c4c9

    ret


    adc $c7
    ld a, a
    jp nc, $d5cf

    call nc, Call_029_7fc5
    adc h
    ld d, l
    ld a, a
    jp nz, $d4d5

    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    jp $d6c1


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
    call nc, $c1c8
    call nc, $d387
    ld a, a
    ld d, [hl]
    add c
    and c
    adc $4f
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld a, a
    call nc, $c3c9
    set 0, l
    call nc, Call_029_557f
    add $cf
    jp nc, $c27f

    ret


    set 0, l
    add c
    ld d, [hl]
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d355

    call nc, $cec1
    call nz, $b081
    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $cbc9

    push bc
    ld a, a
    ld c, a
    xor c
    ld a, a
    rst $00
    rst $08
    call nc, $c27f
    reti


    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    jp $c1c8


    ld d, l
    adc $c7
    push bc
    ld a, a
    call nc, $c3c9
    set 0, l
    call nc, Call_029_7f81
    ld d, b
    ld de, $0050
    and d
    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $cbc9

    push bc
    ld a, a
    jp $cec1


    add a
    ld c, a
    call nc, $c27f
    push bc
    ld a, a
    jp nz, $c1d2

    push de
    rst $00
    ret z

    call nc, $c27f
    pop bc
    jp Jump_029_55cb


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    adc h
    reti


    push bc
    db $d3
    add c
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_029_4fc5
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_029_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    rst $08
    ld d, l
    ret nc

    ld a, a
    call nc, Call_029_7fcf
    db $d3
    push bc
    call z, Call_029_7fcc
    call $d2c9
    pop bc
    jp $ccd5


    ld d, l
    rst $08
    push de
    db $d3
    ld a, a
    jp nz, $cbc9

    push bc
    db $d3
    add c
    ld a, a
    xor c
    call nc, $d27f
    push bc
    pop bc
    ld d, l
    call z, $d9cc
    ld a, a
    rst $08
    rst $10
    adc $d3
    ld a, a
    db $d3
    rst $08
    call Call_029_7fc5
    push bc
    ret c

    jp $c555


    call z, $c5cc
    adc $d4
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_029_7fd3
    add c
    ld a, a
    adc h
    ld a, a
    ld d, l
    and h
    rst $08
    add a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_029_7fcf
    jp nz, Jump_029_55d5

    reti


    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    rst $10
    push bc
    call z, $8dcc
    call nz, $d3c5
    ld c, a
    ret


    rst $00
    adc $c5
    call nz, $c27f
    ret


    set 0, l
    db $d3
    ld a, a
    adc h
    ld a, a
    and h
    rst $08
    adc $55
    add a
    call nc, $d77f
    pop bc
    adc $d4
    ld a, a

Call_029_547f:
Jump_029_547f:
    call nc, Call_029_7fcf
    jp nz, $d9d5

    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    push bc
    pop bc
    jp nc, $c77f

    push de
    push bc
    db $d3
    call nc, Call_029_7f81
    reti


    rst $08
    push de
    jp nc, Jump_029_7f4f

    call $cecf
    push bc
    reti


    ld a, a
    ret


    db $d3
    adc $87
    call nc, $c57f
    adc $cf
    push de
    ld d, l
    rst $00
    ret z

    add c
    ld a, a
    ld e, b
    nop
    call nc, $d2c5
    jp nc, $c2c9

    call z, $d9cc
    ld a, a
    ld a, a
    db $d3
    rst $08
    jp nc, $d9d2

    or h
    ld c, a
    ret z

    pop bc
    adc $cb
    db $d3
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call $567f
    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    db $d3
    call nc, $4fc9
    call z, Call_029_7fcc
    call nc, $c5c8
    ld a, a
    jp nz, $cbc9

    push bc
    ld a, a
    rst $08
    add $7f
    call Call_029_55c1
    call $87c1
    db $d3
    adc h
    ret


    db $d3
    adc $87
    call nc, $c97f
    call nc, Call_029_7f9f
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    db $d3
    push de
    adc $c4
    jp nc, $c5c9

    db $d3
    ld a, a
    jp nz, $d3c1

    set 0, l
    call nc, Call_029_7f55
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $cd7f
    pop bc
    call nc, $c8c3
    ld a, a
    rst $10
    ret


    ld d, l
    call nc, Call_029_7fc8
    call nc, $c5c8
    ld a, a
    call $cec9
    ret


    adc l
    call $d4cf
    rst $08
    jp nc, $c255

    ret


    set 0, l
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c27f

    ret


    set 0, l
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld c, a
    rst $00
    rst $08
    rst $08
    call nz, Call_029_7fc4
    adc [hl]
    ld a, a
    xor c
    ld a, a
    call nz, Call_029_7fcf
    push bc
    adc $d6
    reti


    ld d, l
    ld a, a
    ret


    call nc, Call_029_7f81
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $cbc9

    push bc
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c9c8
    ld c, a
    db $d3
    ld a, a

Call_029_557f:
Jump_029_557f:
    db $d3
    ret z

Call_029_5581:
Jump_029_5581:
    rst $08
    ret nc

    ld a, a
    ret


    db $d3
    ld a, a

Call_029_5587:
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    ld d, l
    rst $00
    rst $08
    rst $08
    call nz, Call_029_7f8c
    jp nz, $d4d5

    ld a, a
    ret


    call nc, $d387
    ld a, a
    call nc, Call_029_55cf
    rst $08
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    adc $d3
    ret


    sub $c5
    ld a, a
    add $cf
    jp nc, $cd7f

    ld d, l
    push bc
    ld a, a
    call nc, Call_029_7fcf
    jp nz, $d9d5

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c

Call_029_55c1:
Jump_029_55c1:
    call nc, $d387

Call_029_55c4:
    ld a, a

Call_029_55c5:
Jump_029_55c5:
    add $d5
    adc $ce

Call_029_55c9:
Jump_029_55c9:
    reti


    add c

Jump_029_55cb:
    ld a, a

Call_029_55cc:
    or h

Call_029_55cd:
    ret z

    push bc

Call_029_55cf:
Jump_029_55cf:
    ld a, a

Jump_029_55d0:
    ld c, a
    rst $08
    call z, Call_029_7fc4

Call_029_55d5:
Jump_029_55d5:
    call $cec1
    ld a, a

Call_029_55d9:
Jump_029_55d9:
    and [hl]
    push de
    jp z, Jump_029_7fc9

    ret


    db $d3
    adc $87
    ld d, l
    call nc, $c87f
    push bc
    jp nc, $81c5

    ld a, a
    or a
    ret z

    push bc
    jp nc, Jump_029_7fc5

    db $d3
    ret


    ld a, a
    ld d, l
    ret z

    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $08
    call z, Call_029_7fc4
    call $cec1
    ld a, a
    and [hl]
    push de
    jp z, $4fc9

    ld a, a
    ret z

    pop bc
    call nz, $c77f
    rst $08
    adc $c5
    ld a, a
    call nc, Call_029_7fcf
    jp $cecf


    db $d3
    ld d, l
    rst $08
    call z, Call_029_7fc5
    call nc, $c5c8
    ld a, a
    xor b
    pop bc
    ret z

    pop bc
    add a
    db $d3
    ld a, a
    db $d3
    rst $08
    ld d, l
    push de
    call z, $8e7f
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_029_7fc5

    rst $10
    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call $c54f
    ld a, a
    rst $08
    add $7f
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    ld a, a
    and [hl]
    push de
    jp z, Jump_029_55c9

    ld a, a
    adc [hl]
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


    db $d3
    ld d, l
    ld a, a
    sub $c5
    jp nc, Jump_029_7fd9

    set 1, c
    adc $c4
    add c
    ld a, a
    xor b
    push bc
    ld a, a
    pop bc
    call z, $d755
    pop bc
    reti


    db $d3
    ld a, a
    jp $cccf


    call z, $c3c5
    call nc, Call_029_7fd3
    ld a, a
    call nc, Call_029_55cf
    rst $00
    push bc
    call nc, $c5c8
    jp nc, $c17f

    adc $c4
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    ld d, l
    pop bc
    add $d4
    push bc
    jp nc, $d47f

    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    ld a, a
    ld d, h
    rst $10
    ld d, l
    ret z

    rst $08
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    pop bc
    jp nz, $cec1

    call nz, $cecf
    push bc
    call nz, Call_029_557f
    rst $08
    jp nc, $d77f

    ret z

    rst $08
    ld a, a
    call z, $d3cf
    call nc, $c87f
    ret


    db $d3
    ld a, a
    rst $10
    ld d, l
    pop bc
    reti


    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    sub $c5
    jp nc, Jump_029_7fd9

    rst $10
    pop bc
    jp nc, Jump_029_7fcd

    ld c, a
    ld d, [hl]
    add c
    ld a, a
    ld d, h
    ld a, a
    add $c5
    push bc
    call z, Call_029_7fd3
    sub $c5
    jp nc, $d955

    ld a, a
    rst $10
    pop bc
    jp nc, Jump_029_7fcd

    rst $10
    ret z

    ret


    call z, Call_029_7fc5
    call nc, $cbc1
    ret


    ld d, l
    adc $c7
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    adc $7f
    ret z

    ret


    db $d3
    ld a, a
    pop bc
    jp nc, $d3cd

    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    push de
    jp z, $9ac9

    or h
    ret z

    push bc
    adc $8c
    ld a, a
    xor l
    jp nc, $4f8e

    ld d, d
    adc h
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    xor c
    call nc, $d77f
    ret


    call z, $cc55
    ld a, a
    jp nz, Jump_029_7fc5

    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, Call_029_7f7f
    call nc, $cf55
    ld a, a
    add $c9
    adc $c9
    db $d3
    ret z

    ld a, a
    ret


    add $7f
    call nc, $c5d2
    pop bc
    call nc, $c555
    call nz, Call_029_547f
    ld a, a
    rst $10
    ret


    call nc, $cfc8
    push de
    call nc, $c17f
    ld a, a
    ld d, l
    call nz, $c5c5
    ret nc

    ld a, a
    call z, $d6cf
    push bc
    ld a, a
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_029_7fc5
    ld d, l
    jp $cdcf


    ret nc

    ret


    call z, $cec9
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    ret


    call z, Call_029_55cc
    push de
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ret z

    pop bc
    adc $c4
    jp nz, $cfcf

    bit 2, l
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $55c8
    ret


    db $d3
    add c
    ld a, a
    ld e, b
    jp nz, $d4d5

    ld a, a
    adc [hl]
    ld a, a
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, Call_029_7f55
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    rst $10
    ret z

    push bc
    call nc, $c5c8
    jp nc, $cf7f

    jp nc, Jump_029_557f

    adc $cf
    call nc, $c97f
    call nc, $d77f
    ret


    call z, Call_029_7fcc
    ret z

    push bc
    call z, Call_029_7fd0
    ld d, l
    reti


    rst $08
    push de
    add c
    ld a, a
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
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    rst $08
    call z, Call_029_7fc4
    call $cec1
    ld a, a
    ld d, l
    and [hl]
    push de
    jp z, $81c9

    ld a, a
    ld d, b
    ld de, $a100
    db $d3
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    db $d3
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    rst $10
    ret z

    ret


    db $d3
    call nc, $c5cc
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, h
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    db $d3
    adc h
    push bc
    sub $c5
    adc $7f
    call nc, $c855
    push bc
    ld a, a
    db $d3
    adc $cf
    jp nc, $cec9

    rst $00
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    push bc
    ld d, l
    jp nc, Jump_029_547f

    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    jp nz, Jump_029_7fc5

    pop bc
    rst $10
    rst $08
    ld d, l
    set 0, l
    call nc, Call_029_7fcf
    jp nz, $c3c5

    rst $08
    call Call_029_7fc5
    sub $c9
    rst $00
    rst $08
    jp nc, $cf55

    push de
    db $d3
    add c
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    call nc, Call_029_55cf
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    rst $10
    ret z

    push bc
    adc $7f
    ld d, l
    ld d, h
    ld a, a
    call nz, $cfd2
    rst $10
    db $d3
    push bc
    db $d3
    ld a, a
    add c
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
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    push de
    jp z, $9ac9

    xor b
    pop bc
    db $d3
    ld a, a
    jp nz, $cdc1

    jp nz, $cfcf

    ld a, a
    ld c, a
    add $cc
    push de
    call nc, Call_029_7fc5
    xor c
    ld a, a
    db $d3
    push bc
    adc $d4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    jp nc, $c3c5

    push bc
    adc $d4
    call z, Call_029_7fd9
    ret nc

    call z, $d9c1
    push bc
    call nz, $c17f
    ld d, l
    ld a, a
    jp nc, $cccf

    call z, Call_029_7f9f
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    jp $cec1


    add a
    call nc, $c67f
    rst $08
    jp nc, Jump_029_4fc7

    ret


    sub $c5
    ld a, a
    ld e, [hl]
    add c
    ld a, a
    or h
    ret z

    push bc
    jp nc, $c555

    ld a, a
    call nc, $c5c8
    ld a, a
    xor b
    pop bc
    ret z

    pop bc
    add a
    db $d3
    ld a, a
    ld a, a
    call $d4cf
    ld d, l
    ret z

    push bc
    jp nc, $567f

    rst $10
    pop bc
    db $d3
    ld a, a
    db $d3
    push bc
    ret


    jp c, $c4c5

    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    set 1, c
    call z, $c5cc
    call nz, $c27f
    reti


    ld a, a
    ld d, l
    ld e, [hl]
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    add $cc
    push bc
    ld d, l
    push bc
    ret


    adc $c7
    ld a, a
    jp nc, $d5cf

    call nc, Call_029_7fc5
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
    ret z

    rst $08
    db $d3
    call nc, Call_029_7f7f
    rst $08
    add $7f
    call nc, Call_029_4fcf
    rst $10
    push bc
    jp nc, Jump_029_547f

    ret


    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $ce7f
    rst $08
    ld d, l
    call nc, $d47f
    rst $08
    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $08
    push de
    call nc, Call_029_7f81
    or a
    ret z

    rst $08
    ld a, a
    ld d, l
    call z, $d4c5
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    db $d3
    call nc, $c1d2
    reti


    ret


    adc $c7
    ld d, l
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, $d47f
    rst $08
    ld a, a
    jp nz, Jump_029_7fc5

    pop de
    push de
    ret


    push bc
    ld d, l
    call nc, $c17f
    adc $c4
    ld a, a
    ret nc

    push bc
    pop bc
    jp $c1c5


    jp nz, $c5cc

    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or a
    ret z

    ret


    jp Jump_029_7fc8


    adc $c9
    jp $cecb


    pop bc
    call Call_029_7fc5
    rst $08
    ld c, a
    add $7f
    ld d, h
    rst $10
    ret


    call z, Call_029_7fcc
    jp nz, Jump_029_7fc5

    call nc, $cccf
    call nz, Call_029_7f55
    add $cf
    jp nc, $d5d4

    adc $c5
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    res 0, c
    ld a, a
    call nc, $c5c8
    adc $7f
    or a
    ret z

    ret


    jp Jump_029_7fc8


    adc $4f
    ret


    jp $cecb


    pop bc
    call Call_029_7fc5
    ret


    db $d3
    ld a, a
    push de
    db $d3
    push bc
    call nz, Call_029_7f9f
    ld d, l
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_029_7f81
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
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
    rst $10
    rst $08
    adc $c4
    push bc
    jp nc, $55c6

    push de
    call z, $ce7f
    ret


    jp $cecb


    pop bc
    call Call_029_7fc5
    adc [hl]
    ld a, a
    and [hl]
    jp nc, Jump_029_55cf

    call $ce7f
    rst $08
    rst $10
    ld a, a
    rst $08
    adc $8c
    ld a, a
    call nz, $d4cf
    push bc
    ld a, a
    adc $c9
    ld d, l
    jp $ccc5


    reti


    ld a, a
    rst $08
    adc $7f
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
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
    adc [hl]
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    jp nz, $c3c5

    ld d, l
    rst $08
    call $d3c5
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cee4
    nop
    ld d, l
    or [hl]
    push bc
    jp nc, Jump_029_7fd9

    rst $00
    rst $08
    rst $08
    call nz, Call_029_7f81
    and d
    push bc
    call nc, $c5d4
    jp nc, Jump_029_7f55

    call nc, $c1c8
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $08
    jp nc, $c7c9

    ret


    adc $c1
    ld d, l
    call z, $ce7f
    pop bc
    call Call_029_7fc5
    add c
    ld a, a
    ld d, a
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
    add c
    ld a, a
    or a
    ld c, a
    pop bc
    adc $d4
    ld a, a
    call nc, $c9c8
    db $d3
    sbc a
    ld a, a
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
    call nz, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d5c8

    call $c155
    adc $7f
    add c
    ld a, a
    ld d, b
    dec bc
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
    ret nc

    rst $08
    jp nc, $c1d4

    jp nz, $4fcc

    push bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $81d3
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    sbc a
    ld a, a
    ld c, a
    ld e, h
    sub d
    sbc c
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    pop bc
    ld a, a
    pop bc
    pop de
    push de
    ret


    jp nc, $c5d2

    call z, Call_029_7f81
    or h
    ret z

    push bc
    ld d, l
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d37f
    set 1, c
    call z, Call_029_7fcc
    ld a, a
    rst $08
    ld d, l
    add $7f
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    call $d9c1
    jp nz, Jump_029_7fc5

    ld d, l
    jp nz, Jump_029_7fc5

    sub $c1
    adc $d1
    push de
    ret


    db $d3
    ret z

    push bc
    call nz, $c97f
    add $7f
    ld d, l
    ld d, [hl]
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    db $d3
    call $cfcf
    call nc, $ccc8
    reti


    ld a, a
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    db $d3
    push bc
    jp nc, $cfc9

    push de
    db $d3
    ld a, a
    rst $00
    push de
    ld c, a
    pop bc
    jp nc, Jump_029_7fc4

    adc [hl]
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    call nc, $c9c8
    ld d, l
    jp nc, $d4d3

    reti


    add c
    ld a, a
    adc [hl]
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    call nc, $c5c8
    jp nc, Jump_029_55c5

    ld a, a
    xor [hl]
    rst $08
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ret


    adc $c7
    ld a, a
    adc $cf
    rst $10
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or a
    ret z

    push bc
    jp nc, $9fc5

    ld a, a
    or h
    ret z

    pop bc
    call nc, Call_029_7f7f
    call z, $cfcf
    ld c, a
    set 2, e
    ld a, a
    pop bc
    ld a, a
    call nc, $d3c1
    call nc, Call_029_7fd9
    call nz, $c9d2
    adc $cb
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    add c
    ld a, a
    or a
    ret z

    reti


    sbc a
    ld a, a
    adc [hl]
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    ld d, l
    call $9fc5
    ld a, a
    or h
    ret z

    pop bc
    adc $cb
    db $d3
    add c
    ld a, a
    ld d, b
    ld de, $5100
    xor b
    push bc
    reti


    adc h
    ret z

    push bc
    reti


    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    and a
    rst $08
    ld a, a
    call nc, $c84f
    jp nc, $d5cf

    rst $00
    ret z

    ld a, a
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    ld d, l
    adc $d4
    ld a, a
    call nc, Call_029_7fcf
    rst $00
    rst $08
    ld a, a
    call nc, Call_029_7fcf
    set 0, l
    jp nc, $c9d2

    ld d, l
    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    db $d3
    ld d, l
    rst $08
    call Call_029_7fc5
    db $d3
    rst $08
    add $d4
    ld a, a
    call nz, $c9d2
    adc $cb
    ld a, a
    ld a, a
    call nc, $cf55
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    push de
    pop bc
    jp nc, Jump_029_7fc4

    rst $08
    add $7f
    call nc, $55c8
    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    db $d3
    ret


    call nc, Call_029_7fc5
    call nz, $cfcf
    jp nc, Jump_029_7f81

    ld d, l
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, Call_029_7fcc
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    or h
    ret z

    pop bc
    adc $cb
    db $d3
    ld c, a
    ld a, a
    add $cf
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    call z, $d3c1
    call nc, $d47f
    ret


    call $c555
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    add $cf
    push de
    adc $c4
    push bc
    call nz, Call_029_7f81
    ld c, a
    and h
    rst $08
    adc $87
    call nc, $d47f
    pop bc
    call z, Call_029_7fcb
    pop bc
    jp nz, $d5cf

    call nc, Call_029_557f
    call $cec9
    push bc
    ld a, a
    call nc, Call_029_7fcf
    pop bc
    adc $d9
    rst $08
    adc $c5
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
    call nc, $c9c8
    db $d3
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    call nc, $c1c8
    adc $cb
    db $d3
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


    call nc, $c47f
    push bc
    sub $c9
    jp $c54f


    sub b
    sub d
    ld a, a
    ret


    db $d3
    ld a, a
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    ld d, l
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    add c
    ld a, a
    and c
    ld a, a
    jp $cecf


    sub $c5
    adc $55
    ret


    push bc
    adc $d4
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    pop bc
    ld a, a
    ret nc

    push bc
    jp nc, $c5c6

    ld d, l
    jp Jump_029_7fd4


    db $d3
    set 1, c
    call z, $81cc
    ld a, a
    ld d, a
    and e
    ret z

    push bc
    jp nc, $d3c9

    ret z

    ld d, l
    ld a, a
    ret


    call nc, Call_029_7f81
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
    call nz, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $c47f
    push bc
    sub $55
    ret


    jp Jump_029_7fc5


    sub b
    sub d
    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    rst $00
    ld d, l
    ret


    jp nc, Jump_029_7fcc

    add c
    ld a, a
    ld d, b
    ld de, $0050
    ld a, a
    reti


    rst $08
    push de
    jp nc, $cc7f

    push de
    rst $00
    rst $00
    pop bc
    rst $00
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    call nc, $cfcf
    ld a, a
    call $c3d5
    ret z

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    jp nc, $ccc9

    call z, $cec9
    rst $00
    ld a, a
    reti


    pop bc
    call $9ac1
    call nz, Call_029_4fd2
    ret


    call z, $c9cc
    adc $c7
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    jp nc, Jump_029_4fc5

    pop bc
    call z, $d9cc
    ld a, a
    pop bc
    ld a, a
    rst $00
    jp nc, $d9c5

    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld d, l
    add c
    ld a, a
    or b
    pop bc
    db $d3
    db $d3
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    xor c
    ld a, a
    ld d, h
    ld a, a
    ld d, [hl]
    add c
    ld c, a
    ld a, a
    ld d, [hl]
    ld a, a
    call nz, $c6c9
    add $c5
    jp nc, $cec5

    call nc, Call_029_7f81
    xor c
    add a
    ld d, l
    call $ad7f
    pop bc
    db $d3
    pop bc
    jp $d9c8


    add c
    ld a, a
    adc [hl]
    ld a, a
    or b
    push bc
    rst $08
    ret nc

    ld d, l
    call z, Call_029_7fc5
    jp $ccc1


    call z, $c4c5
    ld a, a
    call Call_029_7fc5
    call nc, $c5c8
    ld a, a
    ld d, l
    add $c1
    adc $c1
    call nc, $c3c9
    ld a, a
    ld d, h
    add c
    and c
    ret z

    adc h
    ld a, a
    rst $10
    ld d, l
    ret z

    pop bc
    call nc, Call_029_7f9f
    or a
    ret z

    ret


    jp Jump_029_7fc8


    push bc
    reti


    push bc
    sbc a
    ld a, a
    xor [hl]
    ld d, l
    rst $08
    call nc, $c17f
    adc $d9
    ld a, a
    jp nz, $ccc5

    ret


    push bc
    sub $c1
    jp nz, $c5cc

    ld d, l
    add c
    jp nc, $c1c5

    call z, $d9cc
    add c
    ld a, a
    and d
    push bc
    ret


    adc $c7
    ld a, a
    add $c1
    ld d, l
    ret


    call z, $c4c5
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $d3c5
    call nc, $558c
    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    call z, $cec9
    set 0, l
    call nz, $d77f
    ret


    call nc, $55c8
    ld a, a
    ld d, h
    add c
    ld a, a
    and c
    ret z

    add c
    ld a, a
    and e
    pop bc
    adc $7f
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    ret z

    push bc
    call z, Call_029_7fd0
    call $9fc5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call $c77f
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_029_7fcf
    push bc
    adc $4f
    call nc, $d2c5
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c1d2

    adc $55
    jp Jump_029_7fc8


    db $d3
    reti


    db $d3
    call nc, $cdc5
    ld a, a
    rst $08
    add $7f
    call nc, $c1d2
    adc $55
    db $d3
    add $c5
    jp nc, $cd7f

    pop bc
    jp $c9c8


    adc $c5
    ld a, a
    or h
    ret z

    pop bc
    adc $55
    set 2, e
    add c
    ld a, a
    reti


    push bc
    db $d3
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ld e, e
    ld a, a
    rst $08
    ld d, l
    sub $c5
    jp nc, $d47f

    ret z

    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $4f7f
    call $cec5
    call nc, $cfc9
    adc $7f
    call nc, $c5c8
    ld a, a
    ret


    jp $8dc5


    jp $cf55


    call z, Call_029_7fc4
    call nc, $d0cf
    ret


    jp Jump_029_7f81


    xor a
    ret z

    ld a, a
    ld d, [hl]
    adc h
    ld d, l
    ld a, a
    pop bc
    ld a, a
    ld a, a
    ret nc

    call z, $d9c1
    jp nz, $d9cf

    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ld d, l
    call z, $d6cf
    push bc
    call z, $81d9
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $d3c5

    ret


    ld d, l
    call nz, $cec5
    call nc, Call_029_7f81
    and c
    ret z

    pop bc
    adc h
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, Call_029_557f
    xor a
    res 3, a
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $d4c5
    push bc
    jp nc, $c9cd

    adc $55
    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    xor l
    pop bc
    db $d3
    pop bc
    jp $d9c8


    sbc d
    and c
    ret z

    add c
    ld a, a
    or h
    ret z

    pop bc
    adc $4f
    bit 7, a
    reti


    rst $08
    push de
    ld a, a
    sub $c5
    jp nc, Jump_029_7fd9

    call $c3d5
    ret z

    add c
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    ret z

    push bc
    call z, Call_029_7fd0
    call Call_029_7fc5
    call Call_029_55d5
    jp $81c8


    ld a, a
    or a
    ret z

    reti


    ld a, a
    call nz, $cecf
    add a
    call nc, $d97f
    rst $08
    push de
    ld d, l
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_029_7fcf
    push bc
    adc $ca
    rst $08
    reti


    ld a, a
    call Call_029_55d9
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld d, h
    sbc a
    ld a, a
    or a
    ret z

    ld d, l
    pop bc
    call nc, Call_029_7f81
    xor [hl]
    rst $08
    ld a, a
    ret


    adc $d4
    push bc
    jp nc, $d4d3

    ret


    adc $c7
    ld d, l
    add c
    and c
    ret z

    adc h
    ld a, a
    jp nc, $c7c9

    ret z

    call nc, Call_029_7f81
    and a
    ret


    sub $c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    jp nz, $d4d5

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    call $d3d5
    call nc, $87ce
    call nc, $d47f
    ret z

    ret


    adc $cb
    ld a, a
    ret


    call nc, Call_029_557f
    pop bc
    ld a, a
    rst $00
    ret


    add $d4
    ld a, a
    ret


    adc $7f
    jp nc, $d4c5

    push de
    jp nc, $81ce

    ld d, l
    ld a, a
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
    call nz, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $ad7f
    pop bc
    db $d3
    pop bc
    jp $d9c8


    ld a, a
    add c
    ld a, a
    ld d, b
    ld de, $5006
    nop
    ld a, a
    xor [hl]
    rst $08
    rst $10
    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    adc $c4
    push de
    ld a, a
    and c
    ld c, a
    adc $ce
    push de
    ld a, a
    db $d3
    ret z

    ret


    ret nc

    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    jp nc, $c9d2

    sub $55
    push bc
    call nz, $c17f
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    jp nc, $cfc2

    push de
    jp nc, Jump_029_7f55

    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    call nz, $c9d2
    push bc
    call nz, $cc7f
    push bc
    pop bc
    ld d, l
    sub $c9
    push bc
    db $d3
    ld a, a
    jp $d4c9


    reti


    ld a, a
    add c
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_029_55c5

    ld a, a
    db $d3
    push bc
    push bc
    call Call_029_7fd3
    jp $cdcf


    ret


    adc $c7
    ld a, a
    call $cec1
    ld d, l
    reti


    ld a, a
    ld d, h
    ld a, a
    ld e, l
    add c
    ld a, a
    xor c
    call nc, $8755
    db $d3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d47f
    rst $08
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld d, l
    ld a, a
    call nc, $c3c9
    set 0, l
    call nc, Call_029_7f8e
    jp nz, $d4d5

    ld a, a
    ld a, a
    xor c
    ld a, a
    call nz, $cf55
    adc $87
    call nc, $cc7f
    ret


    set 0, l
    ld a, a
    call nz, $cec1
    jp Jump_029_7fc5


    ret nc

    ld d, l
    pop bc
    jp nc, $d9d4

    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $cbc9
    ld d, l
    push bc
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    ld d, l
    call z, $c3c1
    push bc
    ld a, a
    rst $08
    add $7f
    call Call_029_7fc5
    pop bc
    adc $c4
    ld a, a
    ret z

    pop bc
    ld d, l
    sub $c5
    ld a, a
    pop bc
    ld a, a
    add $d5
    adc $7f
    call nc, $c5c8
    jp nc, $81c5

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
    ld d, a
    nop
    ld a, a
    xor l
    pop bc
    db $d3
    pop bc
    jp $d9c8


    sbc d
    and c
    call z, Call_029_7fcc
    jp nc, $c7c9

    ret z

    ld c, a
    call nc, Call_029_7f81
    xor h
    push bc
    call nc, $d37f
    ret z

    rst $08
    rst $10
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d955
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    jp $cccf


    call z, $c3c5
    ld d, l
    call nc, $cfc9
    adc $7f
    ld d, h
    ld a, a
    add c
    ld a, a
    xor h
    rst $08
    rst $08
    res 1, h
    ld a, a
    ld d, l
    call nc, $c9c8
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call Call_029_7fd9
    ld e, e
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call z, $cec9
    set 0, l
    call nz, $d77f
    ret


    call nc, $4fc8
    ld a, a
    call nc, $c5c8
    ld a, a
    ld e, e
    ld a, a
    rst $08
    add $7f
    and c
    rst $08
    jp $c9c8


    call nz, $c555
    jp nc, Jump_029_7f81

    xor [hl]
    rst $08
    rst $10
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    db $d3
    call nc, $cdc9
    ld d, l
    pop bc
    call nc, $cfc9
    adc $7f
    db $d3
    reti


    db $d3
    call nc, $cdc5
    rst $08
    add $7f
    call nc, $55c8
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
    rst $08
    bit 7, a
    ld d, h
    jp $cec1


    ld a, a
    jp nc, $c1c5

    call nz, $8155
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    push bc
    db $d3
    call nc, $cdc9
    pop bc
    call nc, Call_029_7fc5
    call nc, $c5c8
    ld c, a
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
    pop bc
    call nc, $c87f
    pop bc
    adc $c4
    sbc a
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call z, $cec9
    bit 7, a
    rst $10
    ret


    call nc, Call_029_7fc8
    call nc, $4fc8
    push bc
    ld a, a
    ld a, a
    rst $08
    add $7f
    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    ld d, l
    ld e, e
    ld d, [hl]
    ret


    db $d3
    ld a, a
    push bc
    adc $c4
    push bc
    call nz, Call_029_7f81
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    and c
    adc $ce
    rst $08
    push de
    adc $c3
    push bc
    jp nc, Jump_029_7f9a

    or b
    push bc
    adc $c7
    ret nc

    ld c, a
    pop bc
    add c
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    ret


    call nc, $d387
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $c955
    call Call_029_7fc5
    call nc, Call_029_7fcf
    push bc
    adc $c4
    jp nz, $cfd2

    pop bc
    call nz, $c1c3
    ld d, l
    db $d3
    call nc, $cec9
    rst $00
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    adc $ce
    rst $08
    push de
    adc $c3
    push bc
    jp nc, $b09a

    pop bc
    adc $c7
    call z, Call_029_4fc1
    add c
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    ret


    call nc, $d387
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, Call_029_55c9
    call Call_029_7fc5
    call nc, Call_029_7fcf
    push bc
    adc $c4
    jp nz, $cfd2

    pop bc
    call nz, $c1c3
    db $d3
    ld d, l
    call nc, $cec9
    rst $00
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, h
    ld a, a
    call nc, $d3c5
    call nc, Call_029_7f81
    xor c
    add $7f
    reti


    rst $08
    push de
    ld c, a
    jp nc, $c17f

    adc $d3
    rst $10
    push bc
    jp nc, $c97f

    db $d3
    ld a, a
    jp $d2cf


    jp nc, Jump_029_55c5

    jp $8cd4


    ld a, a
    call nc, $c5c8
    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $cfcf
    jp nc, Jump_029_7f55

    rst $10
    ret


    call z, Call_029_7fcc
    rst $08
    ret nc

    push bc
    adc $7f
    pop bc
    adc $c4
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    add $d5
    jp nc, $c8d4

    push bc
    jp nc, Jump_029_5581

    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    jp nc, $c17f

    adc $d3
    rst $10
    push bc
    jp nc, $c97f

    ld d, l
    db $d3
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    adc h
    ld a, a
    call nc, $c5c8
    adc $7f
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    rst $10
    ret


    call z, Call_029_7fcc
    jp $cdcf


    ret nc

    push bc
    call nc, Call_029_7fc5
    rst $10
    ret


    call nc, $c855
    ld a, a
    ld e, l
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    add $cf
    call z, $cfcc
    rst $10
    push bc
    jp nc, $d57f

    adc $d4
    ret


    call z, $cd7f
    push bc
    ld d, l
    push bc
    call nc, $cec9
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_029_7f7f
    ret z

    ld d, l
    push bc
    jp nc, $81c5

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
    ld d, l
    call nc, Call_029_7fcf
    ret nc

    jp nc, $d3c5

    push bc
    jp nc, $c5d6

    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ld d, l
    call nc, $c5d2
    adc $c7
    call nc, Call_029_7fc8
    ld a, a
    rst $08
    add $7f
    ld d, h
    adc h
    ld a, a
    ld d, l
    pop bc
    adc $d3
    rst $10
    push bc
    jp nc, $c37f

    rst $08
    jp nc, $c5d2

    jp $ccd4


    reti


    ld a, a
    ld d, l
    pop bc
    db $d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    add c
    ld a, a
    xor [hl]
    rst $08
    rst $10
    ld a, a
    db $d3
    ld d, l
    call nc, $d2c1
    call nc, Call_029_7f81
    ld e, b
    dec bc
    nop
    and a
    rst $08
    rst $08
    call nz, $c781
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, $5181
    db $ec
    db $ec
    ld a, h
    nop
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    add c
    add $cf
    rst $08
    call z, $5856
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
    call z, $d3c9
    call nc, Call_029_7f4f
    rst $08
    add $7f
    ld d, h
    call nc, Call_029_7fcf
    xor l
    jp nc, Jump_029_7f8e

    xor l
    pop bc
    db $d3
    ld d, l
    pop bc
    jp $d9c8


    add a
    db $d3
    ld a, a
    call z, $cbc9
    ret


    adc $c7
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    ret


    jp Jump_029_7fc8


    db $d3
    ret z

    pop bc
    call z, Call_029_7fcc
    rst $10
    push bc
    ld a, a
    call z, $c54f
    call nc, $c87f
    ret


    call $d37f
    ret z

    rst $08
    rst $10
    ld a, a
    push de
    db $d3
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or b
    jp nc, $d3c5

    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $10
    ret


    call nc, $c8c3
    ld c, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, Call_029_7f9f
    ld d, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d47f
    jp nc, $d5cf

    jp nz, $c5cc

    db $d3
    rst $08
    call $c54f
    ld a, a
    call nc, Call_029_7fcf
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $d47f
    ret z

    pop bc
    call nc, Call_029_7f55
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ld a, a
    call nc, $cfcf
    ld a, a
    call Call_029_4fd5
    jp Jump_029_7fc8


    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld e, b
    ld bc, $cf45
    nop
    ld c, a
    and h
    push bc
    ret nc

    rst $08
    db $d3
    ret


    call nc, $d47f
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, Jump_029_55cf

    ret c

    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd3d
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_029_7f9f
    db $d3
    pop bc
    reti


    ld a, a
    adc $cf
    call nc, $c9c8
    adc $4f
    rst $00
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $c4c5
    ld a, a
    ld d, l
    ret z

    push bc
    jp nc, $9fc5

    ld a, a
    ld e, b
    nop
    ld a, a
    and l
    sub $c5
    adc $7f
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    db $d3
    pop bc
    reti


    ld a, a
    db $d3
    rst $08
    ld a, a
    adc h
    ld a, a
    ld d, h
    ld a, a
    jp $cec1


    ld a, a
    ld d, l
    adc $cf
    call nc, $c27f
    push bc
    pop bc
    jp nc, $d37f

    rst $08
    ld a, a
    call $c3d5
    ret z

    ld a, a
    ld d, l
    reti


    push bc
    call nc, Call_029_7f81
    and c
    call z, Call_029_7fcc
    ret


    adc $7f
    pop bc
    call z, $8ccc
    ld a, a
    ld d, l
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $cf7f
    jp nc, $cc7f

    push bc
    call nc, $c97f
    call nc, Call_029_7f55
    add $cc
    push bc
    push bc
    ld a, a
    add c
    ld a, a
    and h
    rst $08
    ret


    adc $c7
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld d, l
    ret


    db $d3
    adc $87
    call nc, $d37f
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_029_7f9f
    ld e, b
    ld bc, $cf45
    nop
    ld c, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $d4c5
    push bc
    jp nc, $c9cd

    adc $c5
    call nz, Call_029_7fa9
    ld d, l
    db $d3
    call nc, $ccc9
    call z, $c37f
    pop bc
    jp nc, $d9d2

    ld a, a
    call nc, Call_029_7fcf
    rst $00
    rst $08
    ld d, l
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    rst $00
    jp nc, $c5c5

    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_029_7f9f
    db $d3
    pop bc
    reti


    ld a, a
    adc $cf
    call nc, $c9c8
    adc $4f
    rst $00
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, $c4c5
    ld a, a
    ld d, l
    ret z

    push bc
    jp nc, $9fc5

    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c37f
    rst $08
    call Call_029_7fc5
    jp nz, Jump_029_4fc1

    jp Jump_029_7fcb


    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call z, $d4c5
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    push bc
    push bc
    add c
    xor a
    res 3, a
    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    jp nc, $cec9

    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    rst $08
    push de
    call nc, $c9d3
    call nz, Call_029_7fc5
    call nc, Call_029_7fcf
    call z, $d4c5
    ld a, a
    ret


    call nc, Call_029_7f55
    add $d2
    push bc
    push bc
    add c
    ld a, a
    and d
    reti


    push bc
    adc l
    jp nz, $d9c5

    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    ld a, [bc]
    nop
    ld e, d
    ld c, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $cfd2

    push de
    rst $00
    ret z

    call nc, $c87f
    ret


    db $d3
    ld a, a
    ld d, l
    call nz, $c9d2
    sub $c5
    ret


    adc $d4
    rst $08
    ld a, a
    add $d5
    call z, Call_029_7fcc
    ret nc

    call z, $c155
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    push de
    db $d3
    call nc, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    push bc
    call nz, $cf7f
    adc $4f
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ld e, c
    add c
    ld a, a
    ld e, b
    nop
    ld e, c
    ld c, a
    call nz, $c4cf
    rst $00
    push bc
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    pop bc
    call nc, $c1d4
    jp Jump_029_55cb


    add c
    ld a, a
    ld e, b
    ld bc, $cd68
    nop
    ld c, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $c4c5

    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    adc [hl]
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
    jp Jump_029_7fd4


    ret


    db $d3
    ld a, a
    push bc
    ret c

    ld c, a
    call nc, $c5d2
    call $ccc5
    reti


    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_029_7f81
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
    jp Jump_029_7fd4


    call z, $cfcf
    set 2, e
    ld c, a
    ld a, a
    adc $cf
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_029_7f8e
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    rst $08
    call z, Call_029_7fc4
    jp $c9cf


    adc $7f
    db $d3
    jp $c14f


    call nc, $c5d4
    jp nc, $c4c5

    ld a, a
    push bc
    sub $c5
    jp nc, $d7d9

    ret z

    push bc
    jp nc, $c555

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    ret


    db $d3
    ld a, a
    db $d3
    push de
    jp nc, $cfd2

    push de
    adc $c4
    push bc
    call nz, $c27f
    reti


    ld a, a
    ld d, l
    rst $10
    ret z

    ret


    call nc, Call_029_7fc5
    add $cf
    rst $00
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_029_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $c9cf


    adc $8d
    call nz, $d24f
    rst $08
    ret nc

    ld a, a
    call $c3c1
    ret z

    ret


    adc $c5
    add c
    ld a, a
    xor h
    push bc
    call nc, Call_029_5587
    db $d3
    ld a, a
    jp nc, $ced5

    ld a, a
    ret


    call nc, Call_029_7f8c
    db $d3
    ret z

    pop bc
    call z, Call_029_7fcc
    rst $10
    ld d, l
    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call $c3d5
    ret z

    ld a, a
    call nz, Call_029_7fcf
    reti


    rst $08
    push de
    ld a, a
    ld c, a
    jp nz, $d4c5

    sbc a
    ld a, a
    ld d, a
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
    push bc
    adc $cf
    ld c, a
    push de
    rst $00
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, Call_029_7f81
    ld d, a
    nop
    ld a, a
    and e
    rst $08
    ret


    adc $7f
    ld a, a
    ret


    db $d3
    ld a, a
    push de
    db $d3
    push bc
    call nz, $d57f
    ret nc

    ld c, a
    adc [hl]
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    xor a
    adc $c3
    push bc
    ld a, a
    call $d2cf
    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c87f
    ret


    call nc, Call_029_7f8e
    ld e, b
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    db $d3
    push bc
    jp $c5c3


    db $d3
    db $d3
    add $d5
    call z, Call_029_7f81
    ld c, a
    ld d, b
    ld a, [bc]
    ld a, a
    ld d, b
    ld bc, $df20
    nop
    ld c, a
    rst $10
    ret


    call nc, $c4c8
    jp nc, $d7c1

    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    ld bc, $df20
    nop
    ld c, a
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    reti


    pop bc
    add c
    sbc a
    ld a, a
    xor h
    rst $08
    rst $08
    set 2, e
    ld a, a
    pop bc
    ld c, a
    db $d3
    ld a, a
    ld d, b
    ld bc, $cf45
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    rst $08
    adc $c7
    jp nc, $d4c1

    push de
    call z, $d4c1
    ret


    rst $08
    adc $81
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, a
    nop
    ld d, c
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    push bc
    sub $cf
    call z, $d4d5
    push bc
    call nz, $c97f
    ld c, a
    adc $d4
    rst $08
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    adc [hl]
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    call nc, $567f
    sbc a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp $c1c8


    adc $4f
    rst $00
    push bc
    ld a, a
    rst $08
    add $7f
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    db $d3
    call nc, $d0cf
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    rst $00
    push bc
    call nc, Call_029_7fd3
    sub $c9
    rst $00
    rst $08
    jp nc, $d5cf

    db $d3
    adc h
    jp nz, $d4d5

    ld d, l
    ld a, a
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, Call_029_7fd3
    call nc, Call_029_7fcf
    db $d3
    call z, $c5c5
    ret nc

    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, Call_029_7fc8
    rst $08
    add $4f
    ld e, d
    ld d, l
    ld a, a
    ret z

    pop bc
    db $d3
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
    ld e, d
    ld c, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_029_7fc5
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or b
    jp nc, $cecf

    rst $08
    push de
    adc $c3
    push bc
    jp nc, $b09a

    ret


    adc $c7
    ret nc

    ld c, a
    pop bc
    add c
    ld a, a
    and c
    call z, Call_029_7fcc
    call nc, $c5c8
    ld a, a
    ret z

    push de
    adc $d4
    ld a, a
    jp nz, $c155

    call z, $d3cc
    ld a, a
    call nc, $d2c8
    rst $08
    rst $10
    ld a, a
    rst $08
    push de
    call nc, Call_029_7f81
    ld e, b
    nop
    ld a, a
    or a
    ret


    call z, Call_029_7fc4
    ld c, a
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    ld a, a
    add $cc
    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    adc $c5
    call $87d9
    db $d3
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    ret z

    pop bc
    db $d3
    ld a, a
    push bc
    db $d3
    jp $d0c1


    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    rst $00
    rst $08
    call nc, $c17f
    ld a, a
    jp nz, $d2d5

    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret nc

    pop bc
    jp nc, $d3c1

    ret


    call nc, $c3c9
    ld a, a
    ret nc

    call z, $c14f
    adc $d4
    ld a, a
    jp $d0c1


    call nc, $d2d5
    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, Call_029_7fc8
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    adc $c5
    call $87d9
    db $d3
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    ld a, a
    add $c1
    call z, $d3cc
    ld a, a
    call nz, $d7cf
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret


    adc $ce
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cdcf


    ret nc

    ld c, a
    push bc
    call nc, $c9d4
    call nc, $cfc9
    adc $7f
    rst $10
    ret


    call nc, Call_029_7fc8
    ld d, l
    ld d, b
    ld bc, $df20
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    and a
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    ld c, a
    ld d, b
    ld [bc], a
    ld d, [hl]
    ret nc

    jp $8400


    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    ld a, a
    add c
    ld a, a
    ld e, b
    ld bc, $cff0
    nop
    ld c, a
    add $c1
    call z, $d3cc
    ld a, a
    call nz, $d7cf
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    push bc
    ret c

    call nc, Call_029_547f
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    and c
    ret z

    pop bc
    add c
    ld a, a
    ld a, a
    pop bc
    add $d4
    push bc
    ld c, a
    jp nc, $c17f

    call z, $8ccc
    ld a, a
    xor c
    ld a, a
    pop bc
    call $c17f
    ld a, a
    rst $00
    push bc
    adc $55
    ret


    push de
    db $d3
    adc h
    ld a, a
    pop bc
    call $87ce
    call nc, $a97f
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld bc, $ac7f
    rst $08
    db $d3
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $c94f
    call nc, $cfc9
    adc $7f
    rst $10
    ret


    call nc, Call_029_7fc8
    call nc, $c5c8
    ld a, a
    ld a, a
    rst $08
    ld d, l
    add $7f
    ld d, l
    ld d, b
    ld bc, $df20
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    ld bc, $df20
    nop
    ld c, a
    db $d3
    push bc
    push bc
    call Call_029_7fd3
    call nc, Call_029_7fcf
    db $d3
    push bc
    adc $c4
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    ld a, a
    rst $08
    push de
    call nc, Call_029_528e
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $10
    ld d, l
    pop bc
    adc $d4
    db $d3
    ld a, a
    call nc, Call_029_7fcf
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld a, a
    ld d, l
    ld d, h
    sbc a
    ld a, a
    ld d, a
    ld bc, $cff0
    nop
    ld c, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $00
    rst $08
    adc $c5
    ld a, a
    rst $08
    push de
    call nc, Call_029_7f81
    ld e, b
    ld bc, $df20
    nop
    ld c, a
    db $d3
    push bc
    adc $d4
    ld a, a
    rst $08
    push de
    call nc, Call_029_557f
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    add $c9
    rst $00
    ret z

    call nc, $cec9
    rst $00
    ld a, a
    db $d3
    call nc, $c5d2
    ld c, a
    adc $c7
    call nc, $81c8
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    push bc
    db $d3
    jp $d0c1


    ret


    adc $c7
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $a481
    rst $08
    adc $87
    call nc, $cc7f
    push bc
    ld c, a
    call nc, $d47f
    ret z

    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $c5
    call nc, $d37f
    ld d, l
    push bc
    push bc
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c27f

    pop bc
    jp Jump_029_7fcb


    rst $10
    ret z

    ret


    call z, $c555
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $cec9
    rst $00
    ld a, a
    ret


    adc $d4
    push bc
    adc $55
    db $d3
    push bc
    call z, Call_029_7fd9
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and l
    db $d3
    jp $d0c1


    ret


    adc $c7
    ld a, a
    db $d3
    call $cfcf
    call nc, $ccc8
    ld c, a
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_029_7fc5

    adc $cf
    ld a, a
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    pop bc
    adc $4f
    reti


    ld a, a
    ret nc

    jp nc, $d0cf

    ld a, a
    add c
    ld a, a
    ld e, b
    ld bc, $cff0
    nop
    ld c, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $00
    rst $08
    adc $c5
    ld a, a
    rst $08
    push de
    call nc, Call_029_7f81
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_029_7fcc
    rst $10
    pop bc
    db $d3
    ld a, a
    jp $4fcc


    rst $08
    db $d3
    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    adc $c5
    ld a, a
    ld a, a
    call $c9c1
    adc $7f
    ret nc

    rst $08
    ret


    adc $d4
    ld c, a
    db $d3
    rst $08
    add $7f
    db $d3
    set 1, c
    call z, Call_029_7fcc
    ret


    db $d3
    ld a, a
    db $d3
    push de
    jp nc, Jump_029_55d0

    call z, $d3d5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    push bc
    ret c

    ret


    db $d3
    call nc, $cec9
    rst $00
    ld a, a
    db $d3
    push de
    jp $4fc8


    ld a, a
    pop bc
    ld a, a
    db $d3
    pop bc
    reti


    ret


    adc $c7
    ld a, a
    call nc, $c1c8
    call nc, $f001
    rst $08
    nop
    ld a, a
    jp Jump_029_55c1


    adc $7f
    ret nc

    jp nc, $c4cf

    push de
    jp Jump_029_7fc5


    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    ld d, l
    call z, Call_029_7fcc
    rst $08
    add $7f
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    call nc, $d47f
    ret z

    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $c5
    ld c, a
    call nc, Call_029_507f
    add hl, bc
    ld d, c
    ret nc

    ld de, $8100
    ld a, a
    ld e, b
    ld bc, $cff0
    nop
    ld a, a
    ret


    db $d3
    ld a, a
    add $c5
    push bc
    call z, $cec9
    rst $00
    ld a, a
    add $d2
    ret


    rst $00
    ret z

    ld c, a
    call nc, $cec5
    push bc
    call nz, Call_029_7f81
    xor b
    ret


    db $d3
    ld a, a
    db $d3
    set 1, c
    call z, Call_029_7fcc
    ld d, l
    jp $cec1


    add a
    call nc, $c27f
    push bc
    ld a, a
    jp nz, $cfd2

    push de
    rst $00
    ret z

    call nc, Call_029_557f
    ret


    adc $d4
    rst $08
    ld a, a
    ret nc

    call z, $d9c1
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and a
    ret z

    rst $08
    db $d3
    call nc, Call_029_7f9a
    and a
    rst $08
    ld a, a
    pop bc
    rst $10
    pop bc
    reti


    adc h
    ld c, a
    ld d, [hl]
    adc [hl]
    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    rst $10
    pop bc
    reti


    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    ret


    db $d3
    ld a, a
    db $d3
    adc $cf
    jp nc, $cec9

    rst $00
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    adc [hl]
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    pop bc
    rst $10
    rst $08
    set 0, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $d2
    rst $08
    jp c, $cec5

    pop bc
    adc $c4
    ld a, a
    jp $cec1


    ld d, l
    add a
    call nc, $cd7f
    rst $08
    sub $c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    jp $cec1


    add a
    call nc, $d47f
    push de
    jp nc, Jump_029_7fce

    call nc, $c5c8
    ld a, a
    jp nz, Jump_029_55cf

    call nz, $81d9
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    jp nc, $c3c5

    rst $08
    ret


    call z, Call_029_7fd3
    ret


    adc $7f
    add $c5
    pop bc
    jp nc, Jump_029_7f81

    ld d, l
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    jp $cec1


    add a
    call nc, $cd7f
    rst $08
    sub $c5
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, Jump_029_557f

    call nc, $c5c8
    ld a, a
    jp $d5cf


    adc $d4
    push bc
    jp nc, $c3c1

    call nc, $cfc9
    adc $55
    rst $08
    add $7f
    pop bc
    call nc, $c1d4
    jp Jump_029_7fcb


    add c
    ld a, a
    ld e, b
    nop
    or h
    ret z

    push bc
    ld a, a
    jp nz, $cec9

    call nz, $cec9
    rst $00
    ld a, a
    rst $08
    adc $7f
    rst $08
    add $4f
    ld e, d
    ld d, l
    rst $10
    pop bc
    db $d3
    ld a, a
    push de
    adc $d4
    ret


    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    or h
    ret z

    push bc
    ld a, a
    jp $c1c8


    rst $08
    db $d3
    ld a, a
    ret


    adc $7f
    rst $08
    add $4f
    ld e, d
    ld d, l
    rst $10
    pop bc
    db $d3
    ld a, a
    jp nc, $ccc5

    ret


    push bc
    sub $c5
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    add $c5
    push bc
    call z, Call_029_7fd3
    jp $c1c8


    rst $08
    call nc, $c3c9
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    add $c5
    push bc
    call z, Call_029_7fd3
    jp nz, $c4cf

    reti


    add a
    db $d3
    ld a, a
    call nc, $cec9
    rst $00
    ld d, l
    call z, $cec9
    rst $00
    adc h
    pop bc
    adc $c4
    ld a, a
    jp $cec1


    add a
    call nc, $cd7f
    rst $08
    ld d, l
    sub $c5
    ld a, a
    ret


    call nc, Call_029_7f81
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $d07f
    pop bc
    call nc, $c5c9
    adc $c3
    push bc
    add c
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    ret


    db $d3
    ld a, a
    call $cbc1
    ret


    adc $c7
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    ld a, a
    pop bc
    call nc, $c1d4
    jp Jump_029_7fcb


    rst $08
    add $7f
    ld c, a
    ld e, d
    ld d, l
    ret


    db $d3
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c37f
    rst $08
    adc $d4
    ret


    adc $d5
    ret


    ld d, l
    adc $c7
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld e, d
    ld c, a
    rst $10
    pop bc
    db $d3
    ld a, a
    call nc, $c5c9
    call nz, $cec1
    call nz, $c37f
    rst $08
    push de
    call z, Call_029_55c4
    adc $87
    call nc, $c67f
    jp nc, $c5c5

    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    pop bc
    jp nz, $d5cf

    call nc, Call_029_7f7f
    adc [hl]
    and [hl]
    ret


    jp nc, Jump_029_7fc5

    pop bc
    call nc, $cf7f
    ld d, l
    adc $c5
    db $d3
    push bc
    call z, $81c6
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    push de
    jp nc, $d04f

    call z, $d3d5
    ld c, a
    ld e, d
    ld d, l
    call nc, $d2c8
    rst $08
    rst $10
    db $d3
    ld a, a
    ret z

    ret


    call $c5d3
    call z, Call_029_7fc6
    rst $08
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d5cf

    adc $c4
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor h
    rst $08
    rst $08
    set 2, e
    ld a, a
    adc $cf
    ld a, a
    push bc
    add $c6
    push bc
    jp $d3d4


    ld c, a
    ld a, a
    rst $08
    adc $7f
    ld d, l
    ld e, c
    ld a, a
    add c
    ld a, a
    ld e, b
    ld bc, $cff0
    nop
    ld c, a
    ret


    db $d3
    adc $87
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call z, $c1c5
    db $d3
    call nc, $c27f
    ld d, l
    ret


    call nc, $cf7f
    jp nz, $c4c5

    ret


    push bc
    adc $d4
    add c
    ld a, a
    ld e, b
    ld bc, $cff0
    nop
    ld c, a
    db $d3
    call nc, $d2c1
    call nc, Call_029_7fd3
    call nc, Call_029_7fcf
    call nc, $cbc1
    push bc
    ld a, a
    pop bc
    ld a, a
    ld d, l
    adc $c1
    ret nc

    add c
    ld a, a
    ld e, b
    ld bc, $cff0
    nop
    ld c, a
    ret nc

    jp nc, $d4c5

    push bc
    adc $c4
    db $d3
    ld a, a
    adc $cf
    call nc, $cb7f
    adc $cf
    rst $10
    ld d, l
    ret


    adc $c7
    add c
    ld a, a
    ld e, b
    nop
    or h
    ret z

    push bc
    ld a, a
    db $d3
    jp $d0c1


    push bc
    rst $00
    rst $08
    pop bc
    call nc, $cf7f
    add $4f
    ld e, c
    ld d, l
    ret


    db $d3
    ld a, a
    pop bc
    call nc, $c1d4
    jp $c5cb


    call nz, $817f
    ld a, a
    ld e, b
    nop
    or h
    ret z

    push bc
    ld a, a
    db $d3
    jp $d0c1


    push bc
    rst $00
    rst $08
    pop bc
    call nc, $cf7f
    add $4f
    ld e, c
    ld d, l
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, $81d3

    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_029_7fd9

    call nc, $cdc5
    ret nc

    push bc
    jp nc, Jump_029_7f4f

    rst $08
    add $55
    ld e, d
    ld d, l
    jp nc, $ced5

    db $d3
    ld a, a
    ret z

    ret


    rst $00
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push de
    call nc, $b47f
    rst $08
    ld a, a
    ret nc

    pop bc
    jp nc, $cfd2

    call nc, $d77f
    ret


    ld c, a
    call z, Call_029_7fcc
    push bc
    adc $c4
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
    add $c1
    ret


    call z, $d2d5
    push bc
    add c
    ld a, a
    ld e, b
    add hl, bc
    dec b
    call Call_000_0011
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    call nz, $d3c5
    call nc, $cfd2
    reti


    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    ret


    db $d3
    ld a, a
    db $d3
    adc $cf
    jp nc, $cec9

    rst $00
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    add c
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    pop bc
    rst $10
    rst $08
    set 0, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $d2
    rst $08
    jp c, $cec5

    pop bc
    adc $c4
    ld a, a
    jp $cec1


    ld d, l
    add a
    call nc, $cd7f
    rst $08
    sub $c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    jp $cec1


    add a
    call nc, $d47f
    push de
    jp nc, Jump_029_7fce

    call nc, $c5c8
    ld a, a
    jp nz, Jump_029_55cf

    call nz, $81d9
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    jp nc, $c3c5

    rst $08
    ret


    call z, Call_029_7fd3
    ret


    adc $7f
    add $c5
    pop bc
    jp nc, Jump_029_7f81

    ld d, l
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    jp $cec1


    add a
    call nc, $cd7f
    rst $08
    sub $c5
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, Jump_029_557f

    call nc, $c5c8
    ld a, a
    jp $d5cf


    adc $d4
    push bc
    jp nc, $c3c1

    call nc, $cfc9
    adc $55
    ld a, a
    ld a, a
    rst $08
    add $7f
    pop bc
    call nc, $c1d4
    jp $81cb


    ld a, a
    ld e, b
    nop
    or h
    ret z

    push bc
    ld a, a
    jp nz, $cec9

    call nz, $cec9
    rst $00
    ld a, a
    rst $08
    add $4f
    ld e, d
    ld d, l
    ret


    db $d3
    ld a, a
    push de
    adc $d4
    ret


    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    or h
    ret z

    push bc
    ld a, a
    jp $c1c8


    rst $08
    db $d3
    ld a, a
    rst $08
    add $4f
    ld e, d
    ld d, l
    ret


    db $d3
    ld a, a
    jp nc, $ccc5

    ret


    push bc
    sub $c5
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    add $c5
    push bc
    call z, $c37f
    ret z

    pop bc
    rst $08
    call nc, $c3c9
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $c6c1

    add $cc
    ret


    adc $c7
    ld a, a
    ld a, a
    push de
    adc $4f
    add $cf
    call z, Call_029_7fc4
    pop bc
    adc $c1
    call nc, $c1d4
    jp Jump_029_7fcb


    rst $08
    adc $7f
    ld d, l
    ret z

    ret


    call $c5d3
    call z, Call_029_7fc6
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    rst $08
    add $4f
    ld e, d
    ld d, l
    add $c5
    push bc
    call z, Call_029_7fd3
    call nc, $cec9
    rst $00
    call z, $cec9
    rst $00
    ld a, a
    pop bc
    adc $55
    call nz, $c37f
    pop bc
    adc $87
    call nc, $cd7f
    rst $08
    sub $c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $d07f
    pop bc
    call nc, $c5c9
    adc $c3
    push bc
    add c
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    ret


    db $d3
    ld a, a
    call $cbc1
    ret


    adc $c7
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    ld a, a
    pop bc
    call nc, $c1d4
    jp Jump_029_7fcb


    rst $08
    add $4f
    ld e, d
    ld d, l
    ret


    db $d3
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c37f
    rst $08
    adc $d4
    ret


    adc $d5
    ret


    ld d, l
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld e, c
    ld c, a
    db $d3
    call z, $c5c5
    ret nc

    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    db $d3
    call z, $c5c5
    ret nc

    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret


    db $d3
    ld a, a
    jp nz, $d2d5

    adc $c5
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret


    db $d3
    ld a, a
    add $d2
    rst $08
    jp c, $cec5

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret


    db $d3
    ld a, a
    jp nz, $d2d5

    adc $c5
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret


    db $d3
    ld a, a
    add $d2
    rst $08
    jp c, $cec5

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret


    db $d3
    ld a, a
    call nc, $c1c8
    rst $10
    push bc
    call nz, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    add $c9
    jp nc, $81c5

    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret


    db $d3
    ld a, a
    call nc, $c1c8
    rst $10
    push bc
    call nz, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    add $c9
    jp nc, $81c5

    ld a, a
    ld e, b
    nop
    and d
    push de
    call nc, $ce7f
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    push bc
    add $c6
    push bc
    jp Jump_029_4fd4


    db $d3
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push de
    call nc, $ce7f
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    push bc
    add $c6
    push bc
    jp $d44f


    db $d3
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret


    db $d3
    ld a, a
    db $d3
    push bc
    adc $d4
    ld a, a
    ret nc

    pop bc
    jp $c9cb


    adc $c7
    add c
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    rst $00
    push bc
    call nc, Call_029_7fd3
    jp $c1c8


    rst $08
    call nc, $c3c9
    adc [hl]
    ld e, b
    nop
    ld a, a
    ld e, d
    ld c, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_029_7fd3

    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld e, c
    ld d, l
    ret


    db $d3
    ld a, a
    jp $cfcc


    db $d3
    push bc
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    and d
    push de
    call nc, $ce7f
    rst $08
    call nc, $c9c8
    adc $c7
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ld c, a
    ret z

    pop bc
    ret nc

    ret nc

    push bc
    adc $c5
    call nz, Call_029_7f81
    ld e, b
    nop
    ld a, a
    and d
    push de
    call nc, $b57f
    adc $c1
    jp nz, $c5cc

    ld a, a
    call nc, Call_029_7fcf
    call nz, Call_029_4fc5
    call nc, $d2c5
    call $cec9
    push bc
    ld a, a
    db $d3
    call $cfcf
    call nc, $ccc8
    reti


    add c
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push de
    call nc, $ce7f
    rst $08
    ld a, a
    push bc
    add $c6
    push bc
    jp $d3d4


    ld a, a
    rst $08
    ld c, a
    adc $7f
    ld d, h
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, c
    ld c, a
    ret nc

    pop bc
    jp nc, $ccc1

    reti


    db $d3
    push bc
    db $d3
    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    bit 2, l
    ret


    call z, Call_029_7fcc
    rst $08
    add $c9
    db $d3
    ld a, a
    push de
    adc $c1
    jp nz, $c5cc

    ld a, a
    call nc, $cf55
    ld a, a
    jp nz, $c9d2

    adc $c7
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    ret nc

    call z, $d9c1
    ld d, l
    ld a, a
    db $d3
    call $cfcf
    call nc, $ccc8
    reti


    add c
    ld a, a
    ld e, b
    ld bc, $cf45
    nop
    ld c, a
    ld a, a
    ret


    db $d3
    ld a, a
    push de
    db $d3
    ret z

    push bc
    jp nc, $c4c5

    ld a, a
    db $d3
    pop bc
    add $c5
    call z, $d955
    ld a, a
    jp nz, Jump_029_7fd9

    ld a, a
    ld d, l
    ld d, b
    ld bc, $d806
    nop
    ld d, a
    ld d, l
    nop
    ld a, a
    ld d, d
    ld a, a
    db $d3
    push bc
    adc $c4
    db $d3
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    adc $d3
    pop bc
    call nc, $cfc9
    ld d, l
    adc $81
    ld a, a
    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    and a
    ret


    sub $c5
    ld a, a
    call Call_029_7fc5
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    adc [hl]
    ld a, a
    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    ret


    db $d3
    ld a, a
    jp nc, $ccc5

    push de
    jp $c1d4


    adc $d4
    ld a, a
    call nc, Call_029_7fcf
    ret nc

    ld d, l
    pop bc
    jp nc, $81d4

    ld a, a
    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    and a
    rst $08
    ld a, a
    call nc, Call_029_7fcf
    db $d3
    push bc
    push bc
    ld a, a
    rst $08
    add $c6
    adc [hl]
    ld a, a
    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    xor h
    rst $08
    sub $c5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp $c5c8


    jp nc, $d3c9

    ret z

    ld a, a
    ld d, l
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
    and [hl]
    jp nc, $cdcf

    ld a, a
    adc $cf
    rst $10
    ld a, a
    rst $08
    adc $8c
    ld a, a
    call nc, $c5c8
    ld c, a
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, b
    ld bc, $d806
    nop
    ld d, l
    pop bc
    adc $c4
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, a
    ld d, l
    nop
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    call nz, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, d
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    adc h
    call nz, Call_029_7fcf
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    adc $cb
    ld c, a
    ld a, a
    push bc
    ret c

    ret


    db $d3
    call nc, $cec9
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    ret z

    rst $08
    ld d, l
    db $d3
    call nc, Call_029_7f9f
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
    jp nc, $c7c9

    ret z

    call nc, $d381
    rst $08
    ld c, a
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    rst $10
    ret z

    ld d, l
    ret


    call nc, Call_029_7fc5
    ret z

    pop bc
    adc $c4
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $7f
    reti


    rst $08
    ld d, l
    push de
    jp nc, $d27f

    ret


    rst $00
    ret z

    call nc, $d37f
    ret z

    rst $08
    push de
    call z, $c5c4
    jp nc, Jump_029_7f55

    adc [hl]
    xor c
    call nc, $d387
    ld a, a
    xor c
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    ld d, l
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    adc [hl]
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    add a
    call Call_029_7f8c
    adc h
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_029_7fc5

    ld c, a
    pop bc
    jp nc, Jump_029_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    ld d, l
    call nc, Call_029_7fcf
    jp nz, $ccc5

    ret


    push bc
    sub $c5
    ld a, a
    ret


    call nc, Call_029_7f8e
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    call nc, $c5c8
    ld a, a
    jp nc, $c3c5

    push bc
    adc $d4
    ld a, a
    jp $cdcf


    ld c, a
    ret nc

    call z, $d4c5
    ret


    rst $08
    adc $7f
    pop bc
    jp nz, $d5cf

    call nc, Call_029_7f7f
    rst $08
    add $55
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
    sbc d
    and [hl]
    rst $08
    push de
    adc $c4
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ld d, l
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    add c
    ld d, l
    and e
    pop bc
    call nc, $c8c3
    ld a, a
    ld d, h
    ld a, a
    ld d, l
    ld d, b
    add hl, bc
    call c, Call_000_13ff
    nop
    add c
    ld d, l
    or h
    ret z

    push bc
    ld a, a
    push bc
    sub $cf
    call z, $d4d5
    ret


    rst $08
    adc $7f
    rst $08
    add $7f
    ld d, l
    and h
    jp nc, Jump_029_7f8e

    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_029_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    push bc
    jp $c5d2


    ld c, a
    call nc, $c47f
    push bc
    sub $c9
    jp $81c5


    ld a, a
    or b
    jp nc, $d3c5

    db $d3
    ld a, a
    call nc, $cf55
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or b
    jp nc, $d3c5

    db $d3
    ld a, a
    call nc, Call_029_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    ld c, a
    call nc, $d9d2
    sbc a
    ld a, a
    ld d, [hl]
    or b
    pop bc
    jp $c1c8


    add c
    ld a, a
    pop bc
    ld a, a
    db $d3
    ld d, l
    rst $08
    push de
    adc $c4
    ld a, a
    ld e, b
    nop
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    push de
    ret nc

    ld a, a
    call nc, $c5c8
    ld a, a
    ret


    call nz, $c1c5
    ld c, a
    ld a, a
    rst $08
    add $7f
    ret nc

    jp nc, $d3c5

    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    db $d3
    rst $10
    ret


    call nc, $c8c3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_029_7fc5
    call nc, Call_029_7fcf
    ld c, a
    call nc, $c9c8
    db $d3
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    adc [hl]
    ld a, a
    and h
    rst $08
    ld a, a
    pop bc
    call z, $cc55
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    sub $c9
    call z, $c47f
    push bc
    push bc
    call nz, Call_029_7fd3
    ld d, l
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    pop bc
    call z, Call_029_7fcc
    call nc, $c5c8
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld d, l
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $cecf
    push bc
    reti


    adc l
    call $c4c1
    push bc
    ld a, a
    ld d, l
    ld e, [hl]
    add c
    ld a, a
    xor c
    add a
    call $8c7f
    ld a, a
    call nc, $55c8
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $d37f
    pop bc
    set 0, c
    jp $d9c8


    add c
    ld a, a
    xor c
    ld d, l
    add $7f
    reti


    rst $08
    push de
    ld a, a
    jp nc, $d3c5

    ret


    db $d3
    call nc, $c17f
    rst $00
    pop bc
    ret


    ld d, l
    adc $d3
    call nc, $cd7f
    push bc
    ld a, a
    xor c
    add a
    call z, Call_029_7fcc
    call z, $d4c5
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
    call nc, Call_029_7fcf
    ret nc

    pop bc
    reti


    ld a, a
    add $cf
    ld d, l
    jp nc, $c97f

    call nc, Call_029_7f81
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp $c5c8


    jp nc, $d3c9

    ret z

    ret


    adc $4f
    rst $00
    call z, Call_029_7fd9
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_029_7fc5

    add $cf
    db $d3
    call nc, Call_029_55c5
    jp nc, $cec9

    rst $00
    ld a, a
    ld d, h
    add c
    ld a, a
    xor l
    reti


    ld a, a
    call nc, $cfc8
    push de
    ld d, l
    rst $00
    ret z

    call nc, Call_029_7f7f
    ret


    db $d3
    ld a, a
    push bc
    ret c

    call nc, $c5d2
    call $ccc5
    reti


    ld d, l
    ld a, a
    jp nz, $d9c5

    rst $08
    adc $c4
    ld a, a
    call nc, $c1c8
    call nc, $c27f
    rst $08
    reti


    add a
    ld d, l
    db $d3
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ret


    adc $c7
    ld a, a
    add c
    ld d, l
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $d387
    ld a, a
    pop bc
    call z, $8ccc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld c, a
    or h
    ret z

    push bc
    ld a, a
    set 0, l
    reti


    ld a, a
    rst $08
    add $7f
    call z, $c6c9
    call nc, Call_029_557f
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld a, a
    ret z

    ld d, l
    ret


    call nz, $c4c5
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d37f
    push bc
    push bc
    call $cec9
    rst $00
    call z, Call_029_7fd9
    call $d3d5
    ld c, a
    call nc, $c87f
    pop bc
    sub $c5
    ld a, a
    call nc, Call_029_7fcf
    push de
    db $d3
    push bc
    ld a, a
    pop bc
    ld a, a
    bit 2, l
    push bc
    reti


    add c
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    xor l
    rst $08
    call nc, $c5c8
    jp nc, $af9a

    ret z

    adc h
    reti


    push bc
    db $d3
    add c
    ld a, a
    ld c, a
    ld d, [hl]
    jp nz, $d9cf

    db $d3
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_029_7fc4
    rst $00
    rst $08
    ld a, a
    ld d, l
    call nc, Call_029_7fcf
    call nc, $c1d2
    sub $c5
    call z, Call_029_7f7f
    rst $10
    ret z

    push bc
    adc $c5
    sub $55
    push bc
    jp nc, $c87f

    push bc
    ld a, a
    call z, $cbc9
    push bc
    db $d3
    adc [hl]
    ld a, a
    xor b
    add a
    call Call_029_5581
    ld a, a
    ld d, [hl]
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $c97f
    adc $7f
    ld d, l
    or h
    or [hl]
    add c
    ld a, a
    and c
    ret z

    adc h
    reti


    push bc
    db $d3
    add c
    ld a, a
    and h
    jp nc, Jump_029_7f8e

    and c
    ld d, l
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    call z, $d6c9
    ret


    adc $c7
    ld a, a
    ret


    adc $55
    ld a, a
    adc $c5
    ret c

    call nc, $c47f
    rst $08
    rst $08
    jp nc, $c37f

    pop bc
    call Call_029_7fc5
    call nc, $cf55
    ld a, a
    jp $ccc1


    call z, $d97f
    rst $08
    push de
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    call nc, $c5c8
    jp nc, Jump_029_529a

    ld d, [hl]
    add c
    and a
    ld c, a
    rst $08
    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $c17f

    ld a, a
    db $d3
    call z, $c7c9
    ret z

    call nc, Call_029_557f
    jp nc, $d3c5

    call nc, $a881
    rst $08
    rst $10
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $558c
    ld d, [hl]
    sbc a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    xor l
    rst $08
    call nc, $c5c8
    jp nc, $a89a

    push bc
    call z, $cfcc
    adc h
    ret z

    push bc
    call z, $cc4f
    rst $08
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    db $d3
    ld a, a
    rst $08
    ld d, l
    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, h
    ld a, a
    pop bc
    jp nc, Jump_029_55c5

    ld a, a
    pop bc
    call z, Call_029_7fcc
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_029_7f81
    or h
    ret z

    push bc
    ld d, l
    adc $8c
    ld a, a
    jp nz, Jump_029_7fc5

    jp $d2c1


    push bc
    add $d5
    call z, Call_029_7f81
    or h
    pop bc
    ld d, l
    set 0, l
    ld a, a
    ret


    call nc, $c57f
    pop bc
    db $d3
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    adc $cf
    ld a, a
    db $d3
    push bc
    push bc
    ret


    adc $c7
    add c
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    or h
    or [hl]
    ld a, a
    add $c9
    call z, Call_029_7fcd
    ret


    db $d3
    ld a, a
    rst $08
    ld c, a
    adc $81
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_029_7fc5

    pop bc
    jp nc, Jump_029_7fc5

    sub h
    ld a, a
    jp nz, Jump_029_55cf

    reti


    db $d3
    ld a, a
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    call nc, $c1d2
    jp Jump_029_7fcb


    ld d, [hl]
    ld d, [hl]
    adc h
    ld a, a
    xor c
    add a
    call $c17f
    ld d, l
    call z, $cfd3
    ld a, a
    rst $10
    ret


    call nc, $cfc8
    push de
    call nc, $c77f
    rst $08
    ret


    adc $c7
    ld d, l
    ld a, a
    pop bc
    call nc, $cf7f
    adc $c3
    push bc
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
    adc [hl]
    ld a, a
    reti


    pop bc
    add c
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    pop bc
    call nc, $cc7f
    pop bc
    db $d3
    call nc, $d77f
    push bc
    ld a, a
    push bc
    adc $55
    call nz, $c4c5
    add c
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d97f
    rst $08
    push de
    ld a, a
    add $c9
    ld d, l
    adc $c9
    db $d3
    ret z

    sbc a
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    adc [hl]
    and a
    ret


    sub $c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d47f
    ret z

    ret


    adc $c7
    adc [hl]
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
    call nz, $4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    call z, $d3c5
    jp $c5cc


    ld d, l
    jp nc, Jump_029_7fcb

    add c
    ld a, a
    ld d, b
    dec bc
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
    ld d, a
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    ret


    add $d4
    ld a, a
    rst $08
    add $4f
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call z, $d3c5
    jp $c5cc


    jp nc, Jump_029_7fcb

    ld d, l
    ld e, h
    sub c
    sbc b
    add a
    db $d3
    ld d, l
    ld a, a
    db $d3
    set 1, c
    call z, Call_029_7fcc
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    jp $d5cf


    ld d, l
    adc $d4
    push bc
    jp nc, $d4c1

    call nc, $c3c1
    res 0, c
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld d, l
    ld a, a
    rst $10
    rst $08
    jp nc, Jump_029_7fcb

    ret z

    pop bc
    jp nc, $81c4

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

Call_029_7f4f:
Jump_029_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_029_7f55:
Jump_029_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_029_7f7f:
Jump_029_7f7f:
    nop
    nop

Call_029_7f81:
Jump_029_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_029_7f8c:
Jump_029_7f8c:
    nop
    nop

Call_029_7f8e:
Jump_029_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_029_7f9a:
Jump_029_7f9a:
    nop
    nop
    nop
    nop
    nop

Call_029_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_029_7fa9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_029_7fc1:
    nop
    nop
    nop

Call_029_7fc4:
Jump_029_7fc4:
    nop

Call_029_7fc5:
Jump_029_7fc5:
    nop

Call_029_7fc6:
    nop
    nop

Call_029_7fc8:
Jump_029_7fc8:
    nop

Jump_029_7fc9:
    nop
    nop

Call_029_7fcb:
Jump_029_7fcb:
    nop

Call_029_7fcc:
Jump_029_7fcc:
    nop

Call_029_7fcd:
Jump_029_7fcd:
    nop

Jump_029_7fce:
    nop

Call_029_7fcf:
    nop

Call_029_7fd0:
    nop
    nop
    nop

Call_029_7fd3:
Jump_029_7fd3:
    nop

Jump_029_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_029_7fd9:
Jump_029_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
