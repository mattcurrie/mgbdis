; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $027", ROMX[$4000], BANK[$27]

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
    jp nc, Jump_027_7fd9

    jp nz, $d2c9

    call nz, $557f
    ld d, h
    ld a, a
    call $d9c1
    ld a, a
    jp nz, Jump_027_7fc5

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
    jp nc, Jump_027_7fc5

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
    call z, Call_027_7fcc
    ld d, l
    rst $00
    rst $08
    ld a, a
    call nc, Call_027_7fcf
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
    call nc, Call_027_7fcf
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
    jp nc, Jump_027_7fd4

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
    call Call_027_7f8e
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    and c
    adc $7f
    pop bc
    call $c5c2
    jp nc, $d07f

    ret


    ret nc

    push bc
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
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_027_7fcf
    jp $c14f


    adc $c3
    push bc
    call z, $d07f
    jp nc, $cdcf

    rst $08
    call nc, $cfc9
    adc $9f
    ld a, a
    ld d, l
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    reti


    ld a, a
    ld d, l
    rst $08
    add $7f
    ret nc

    jp nc, $cdcf

    rst $08
    call nc, $cec9
    rst $00
    ld a, a
    adc [hl]
    ld a, a
    xor h
    push bc
    ld d, l
    call nc, $c87f
    ret


    call $d37f
    push de
    db $d3
    ret nc

    push bc
    adc $c4
    ld a, a
    adc [hl]
    ld a, a
    xor e
    ld d, l
    push bc
    push bc
    ret nc

    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, Call_027_7fcc
    call nc, Call_027_7fcf
    ld d, l
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ret


    call nc, $c17f
    db $d3
    ld a, a
    call nc, $c1c8
    call nc, Call_027_7f55
    db $d3
    call nc, $d4c1
    push bc
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    jp nc, Jump_027_7fc5

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
    add $d2
    ret


    push bc
    adc $c4
    db $d3
    sbc a
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld d, l
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_027_7fc4

    call nc, $c1c8
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    call nz, $d77f
    ret


    ld d, l
    call nc, Call_027_7fc8
    ld a, a
    add $d2
    rst $08
    call $c67f
    jp nc, $c5c9

    adc $c4
    db $d3
    ld a, a
    ld d, l
    rst $00
    jp nc, $d7cf

    db $d3
    ld a, a
    pop de
    push de
    ret


    jp $cccb


    reti


    adc [hl]
    ld a, a
    xor c
    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    jp nc, Jump_027_7fc5

    pop bc
    adc $d9
    ld a, a
    sub $c1
    call z, $c5d5
    ld a, a
    ld d, l
    call nc, Call_027_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, $9fc5
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
    ld a, a
    and [hl]
    push de
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
    and d
    push de
    call nz, $c8c4
    ld d, l
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

    call nc, Call_027_55d4
    push bc
    adc $c4
    pop bc
    adc $d4
    db $d3
    ld a, a
    rst $08
    add $7f
    pop bc
    call z, $c9cc
    pop bc
    adc $55
    jp Jump_027_7fc5


    ld d, h
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, $ccd5

    push bc
    ld a, a
    add $55
    rst $08
    jp nc, $c67f

    rst $08
    push de
    jp nc, $cd7f

    push bc
    adc $7f
    ld a, a
    call nc, Call_027_7fcf
    jp $cf55


    call $c5d0
    call nc, Call_027_7fc5
    ret


    adc $c3
    push bc
    db $d3
    db $d3
    pop bc
    adc $d4
    call z, $d955
    add c
    ld a, a
    xor c
    add $7f
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $7f
    call nc, $d5cf
    jp nc, Jump_027_7f55

    call z, $d3cf
    call nc, Call_027_7f8c
    call nc, $c5c8
    adc $7f
    call nc, $c5c8
    reti


    add a
    ld d, l
    call z, Call_027_7fcc
    jp nc, $d3c5

    call nc, $d2c1
    call nc, $c37f
    rst $08
    call $c5d0
    call nc, $c955
    adc $c7
    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    add $c9
    jp nc, Jump_027_55d3

    call nc, $817f
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
    call z, $c155
    db $d3
    call nc, $cf7f
    adc $c5
    ld a, a
    call nc, Call_027_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, $c555
    add c
    ld a, a
    and e
    rst $08
    call Call_027_7fc5
    rst $08
    adc $81
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
    adc $7f
    ret


    db $d3
    ld a, a
    call nc, $cf4f
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, Call_027_7fc5
    rst $10
    ret


    call nc, Call_027_7fc8
    and d
    push de
    ld d, l
    call nz, $c8c4
    pop bc
    add a
    db $d3
    ld a, a
    sub h
    ld a, a
    rst $10
    pop bc
    jp nc, $d2d2

    ret


    rst $08
    jp nc, Jump_027_7f55

    pop bc
    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    db $d3
    ld a, a
    jp nz, $81d9

    ld a, a
    ld a, a
    ld d, l
    call nc, $d2d5
    adc $d3
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $cfcf
    jp nc, $d77f

    ret


    ld d, l
    call z, Call_027_7fcc
    rst $08
    ret nc

    push bc
    adc $7f
    ld a, a
    pop bc
    adc $c4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, $c97f
    add $7f
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    rst $10
    ret


    adc $81
    ld a, a
    or a
    rst $08
    jp nc, Jump_027_7fcb

    rst $10
    ret


    call nc, Call_027_55c8
    ld a, a
    pop bc
    call nz, $c5c4
    call nz, $d67f
    ret


    rst $00
    rst $08
    push de
    jp nc, Jump_027_7f81

    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    call nz, $d5c1
    rst $00
    ret z

    call nc, $d2c5
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld c, a
    ld a, a
    jp nz, $c5c5

    adc $7f
    ret nc

    pop bc
    call $c5d0
    jp nc, $c4c5

    ld a, a
    db $d3
    ret


    ld d, l
    adc $c3
    push bc
    ld a, a
    jp $c9c8


    call z, $c8c4
    rst $08
    rst $08
    call nz, Call_027_567f
    ld a, a
    ld d, l
    adc [hl]
    ld a, a
    db $d3
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $c17f
    adc $d9
    ld a, a
    ld d, l
    add $d2
    ret


    push bc
    adc $c4
    ld a, a
    reti


    push bc
    call nc, Call_027_7f8e
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $d2c9
    push bc
    db $d3
    rst $08
    call Call_027_7fc5
    ld c, a
    call nc, $c9c8
    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c1c8
    call nc, $cd7f
    reti


    ld a, a
    ld d, l
    call nz, $d5c1
    rst $00
    ret z

    call nc, $d2c5
    ld a, a
    call z, $cbc9
    push bc
    db $d3
    ld a, a
    call nc, Call_027_55cf
    ld a, a
    ret


    call $d4c9
    pop bc
    call nc, Call_027_7fc5
    rst $08
    call nc, $c5c8
    jp nc, $81d3

    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    db $d3
    ret z

    push bc
    ld a, a
    rst $08
    add $d4
    push bc
    adc $7f
    call nc, $c1c5
    ld d, l
    db $d3
    push bc
    db $d3
    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, Jump_027_7fd3

    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, l
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_027_7fc5
    adc $c5
    pop bc
    jp nc, $d9c2

    ld a, a
    ld a, a
    jp Jump_027_55c1


    call z, Call_027_7fcc
    ret z

    push bc
    jp nc, $c97f

    call $d4c9
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    ld d, l
    rst $00
    ret


    jp nc, $81cc

    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    push de
    jp $cfcb


    rst $08
    add c
    ld a, a
    pop bc
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    adc h
    ld c, a
    ld a, a
    jp $cecf


    db $d3
    push de
    call z, Call_027_7fd4
    call nc, $c5c8
    ld a, a
    add $d2
    pop bc
    call $c555
    add c
    ld a, a
    ld d, a
    ld d, [hl]
    adc [hl]
    ld a, a
    call $d2c9
    jp nc, $d2cf

    adc h
    ld a, a
    call Call_027_55c9
    jp nc, $cfd2

    jp nc, Jump_027_7f81

    or a
    ret z

    rst $08
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    call z, $d6cf
    push bc
    call z, Call_027_7fd9
    rst $00
    ret


    jp nc, Jump_027_7fcc

    ld a, a
    ret


    adc $7f
    call nc, $c855
    push bc
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

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
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld c, a
    ld a, a
    ld d, h
    add c
    sbc a
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    and c
    ret z

    sbc a
    ld a, a
    db $d3
    rst $08
    ld d, l
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d9c1
    call nc, $c9c8
    adc $55
    rst $00
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
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld c, a
    ld a, a
    ld d, h
    add c
    sbc a
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    and c
    ret z

    sbc a
    ld a, a
    db $d3
    rst $08
    ld d, l
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d9c1
    call nc, $c9c8
    adc $55
    rst $00
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
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld c, a
    ld a, a
    ld d, h
    add c
    sbc a
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    and c
    ret z

    sbc a
    ld a, a
    db $d3
    rst $08
    ld d, l
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $d9c1
    call nc, $c9c8
    adc $55
    rst $00
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
    ld d, [hl]
    add c
    ld a, a
    and c
    ld a, a
    ld a, a
    ret nc

    ld c, a
    push de
    ret nc

    ret nc

    push bc
    call nc, $d78d
    pop bc
    call z, $c9cb
    adc $c7
    ld a, a
    rst $00
    pop bc
    call $c555
    ld a, a
    rst $10
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c87f
    pop bc
    db $d3
    ld a, a
    ld d, l
    rst $10
    rst $08
    jp nc, Jump_027_7fce

    rst $08
    adc $7f
    pop bc
    ld a, a
    jp nz, $c3d5

    set 0, l
    call nc, $557f
    add c
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
    call nc, $4f81
    ld a, a
    jp nz, $d4d5

    ld a, a
    jp z, $d3d5

    call nc, Call_027_567f
    add c
    ld a, a
    and h
    rst $08
    adc $55
    add a
    call nc, $c27f
    jp nc, $cec9

    rst $00
    ld a, a
    call Call_027_7fd9
    db $d3
    ret


    rst $00
    adc $7f
    ld d, l
    rst $08
    add $7f
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    adc l
    call nc, $cbc1
    ret


    adc $55
    rst $00
    ld a, a
    reti


    pop bc
    jp nc, $81c4

    ld a, a
    xor c
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
    call Call_027_7fd9
    ret


    call $cfd0
    jp nc, $c1d4

    adc $d4
    ld a, a
    pop bc
    db $d3
    ld d, l
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    adc $d3
    pop bc
    call nc, $cfc9
    adc $7f
    add $55
    rst $08
    jp nc, $d77f

    jp nc, $d3c5

    call nc, $c9cc
    adc $c7
    ld a, a
    ld d, h
    add c
    ld d, l
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
    jp $c855


    rst $08
    rst $08
    db $d3
    push bc
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d97f
    rst $08
    push de
    ld a, a
    call z, Call_027_55c9
    set 0, l
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
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $c5
    call z, $cc4f
    rst $08
    rst $10
    add c
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    ret c

    push bc
    jp nc, Jump_027_55c3

    ret


    db $d3
    push bc
    adc l
    call nc, $cbc1
    ret


    adc $c7
    ld a, a
    reti


    pop bc
    jp nc, Jump_027_7fc4

    call nz, $c555
    add $c5
    pop bc
    call nc, $c4c5
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    push bc
    push bc
    call z, $c17f
    call nc, $c57f
    pop bc
    db $d3
    push bc
    ld a, a
    add c
    ld a, a
    or b
    ld c, a
    push de
    call nc, $c97f
    call nc, $cf7f
    add $c6
    ld a, a
    push de
    adc $d4
    ret


    call z, $d37f
    ld d, l
    rst $08
    call Call_027_7fc5
    call nc, $cdc9
    push bc
    ld a, a
    call z, $d4c1
    push bc
    jp nc, $d77f

    ret z

    ld d, l
    push bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_027_7fc5
    reti


    rst $08
    ld d, l
    push de
    jp nc, $cd7f

    pop bc
    db $d3
    call nc, $d2c5
    add c
    ld a, a
    and l
    sub $c5
    adc $7f
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    rst $10
    ret


    adc $7f
    call Call_027_7fc5
    adc h
    ld a, a
    ret


    call nc, $d387
    ld a, a
    ld d, l
    adc $cf
    call nc, $c9c8
    adc $c7
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ret


    jp Jump_027_5581


    ld a, a
    ld d, a
    nop
    ld a, a
    pop bc
    call nz, $c9cd
    jp nc, $c4c5

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    pop bc
    call nz, $c9cd
    jp nc, $c4c5

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    reti


    rst $08
    push de
    jp nc, $cc7f

    push bc
    ld c, a
    sub $c5
    call z, $cc7f
    rst $08
    rst $08
    set 2, e
    ld a, a
    adc $cf
    call nc, $c27f
    pop bc
    call nz, $8155
    ld a, a
    or h
    adc $c5
    ld a, a
    xor c
    add a
    call z, Call_027_7fcc
    adc $cf
    call nc, $d37f
    call nc, $c155
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
    ld d, l
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $d3c1
    call nc, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ld c, a
    rst $10
    jp nc, $d3c5

    call nc, $c9cc
    adc $c7
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d5c8

    ld d, l
    call $cec1
    add c
    ld a, a
    and d
    push bc
    ld a, a
    call $cec5
    call nc, $ccc1
    call z, Call_027_7fd9
    ld d, l
    ret nc

    jp nc, $d0c5

    pop bc
    jp nc, $c4c5

    ld a, a
    ret


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
    call nc, Call_027_7fcf
    jp $c1c8


    call z, $c5cc
    adc $c7
    push bc
    ld a, a
    ld d, l
    ret z

    ret


    call Call_027_7f8e
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d37f
    bit 1, a
    ret


    call z, $81cc
    ld a, a
    ld e, b
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d37f
    bit 1, a
    ret


    call z, $81cc
    ld a, a
    ld e, b
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
    jp nc, Jump_027_7fc4

    ret


    ld c, a
    db $d3
    adc $87
    call nc, $d47f
    push bc
    jp nc, $c9d2

    add $c9
    jp Jump_027_7f81


    and l
    ret c

    ld d, l
    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    call nc, Call_027_7fcf
    jp nz, $c5d2

    pop bc
    bit 7, a
    jp nc, $cf55

    jp Jump_027_7fcb


    call nc, Call_027_7fcf
    ret nc

    ret


    push bc
    jp $d3c5


    ld a, a
    jp nz, Jump_027_7fd9

    ld d, l
    reti


    rst $08
    push de
    jp nc, $c67f

    ret


    db $d3
    call nc, $c57f
    pop bc
    jp Jump_027_7fc8


    call nz, Call_027_55c1
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_027_7f7f
    call nc, $c5c8
    ld a, a
    rst $10
    jp nc, $d3c5

    call nc, Call_027_4fcc
    push bc
    jp nc, $d47f

    push bc
    jp nc, $c9d2

    add $c9
    push bc
    call nz, $c97f
    db $d3
    ld a, a
    rst $08
    ld d, l
    adc $cc
    reti


    ld a, a
    db $d3
    rst $08
    call Call_027_7fc5
    db $d3
    push de
    ret nc

    push bc
    jp nc, $c2c1

    ret


    ld d, l
    call z, $d4c9
    reti


    add c
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
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
    ld e, b
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor l
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    ld c, a
    ld a, a
    pop bc
    ld a, a
    rst $10
    jp nc, $d3c5

    call nc, $c5cc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $c955
    call nc, $cfc9
    adc $7f
    rst $08
    adc $7f
    ret nc

    jp nc, $c3c1

    call nc, $c3c9
    push bc
    ld d, l
    ld a, a
    pop bc
    jp nc, $cec5

    pop bc
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
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $c3c1

    call nc, $4fc9
    jp Jump_027_7fc5


    pop bc
    jp nc, $cec5

    pop bc
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, Jump_027_7fc5

    pop bc
    call z, $cc55
    ld a, a
    rst $10
    jp nc, $d3c5

    call nc, $c5cc
    jp nc, Jump_027_7fd3

    call nc, $d2c8
    rst $08
    push de
    ld d, l
    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d5cf


    adc $d4
    jp nc, Jump_027_7fd9

    pop bc
    jp nc, $c555

    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    call nc, $c7cf
    push bc
    call nc, $c5c8
    jp nc, $8155

    ld a, a
    call $d2cf
    adc $c9
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c37f
    rst $08
    call $c5d0
    call z, $c4c5
    ld a, a
    pop bc
    call nz, Call_027_4fcd
    ret


    jp nc, $d4c1

    ret


    rst $08
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c37f
    rst $08
    call $c5d0
    call z, $c4c5
    ld a, a
    pop bc
    call nz, Call_027_4fcd
    ret


    jp nc, $d4c1

    ret


    rst $08
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    call z, $c5c4
    adc $7f
    jp nz, $c14f

    call nz, $c5c7
    ld a, a
    adc h
    ld a, a
    ld d, h
    ld a, a
    rst $10
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    ld d, l
    call z, $d6c5
    push bc
    call z, $d27f
    push bc
    pop bc
    jp $c5c8


    call nz, $d47f
    rst $08
    ld a, a
    ld d, l
    ld [hl], b
    rst $10
    ret


    call z, Call_027_7fcc
    jp nz, Jump_027_7fc5

    rst $08
    jp nz, $c4c5

    ret


    push bc
    adc $d4
    ld a, a
    ld d, l
    call nc, Call_027_7fcf
    reti


    rst $08
    push de
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    ld d, l
    call $c3d5
    ret z

    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, $d47f

    ret z

    pop bc
    ld d, l
    adc $7f
    call nc, $c1c8
    call nc, $c97f
    db $d3
    ld a, a
    push bc
    ret


    call nc, $c5c8
    jp nc, $557f

    db $d3
    call nc, $cec1
    call nz, $c6cf
    add $c9
    db $d3
    ret z

    ld a, a
    rst $08
    jp nc, $c97f

    adc $55
    ld a, a
    call z, $d7cf
    ld a, a
    db $d3
    ret nc

    ret


    jp nc, $d4c9

    db $d3
    adc [hl]
    ld a, a
    xor c
    call nc, Call_027_5587
    db $d3
    ld a, a
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, $d47f
    rst $08
    ld a, a
    jp Jump_027_55cf


    adc $d4
    jp nc, $cccf

    add c
    ld a, a
    and d
    push de
    call nc, Call_027_7f8c
    call nc, $c1c8
    call nc, $557f
    rst $10
    rst $08
    jp nc, $d9d2

    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    adc $c5
    ld d, l
    jp $d3c5


    db $d3
    pop bc
    jp nc, Jump_027_7fd9

    rst $10
    ret


    call nc, $cfc8
    push de
    call nc, $c67f
    ld d, l
    rst $08
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    call nc, $cfcf
    ld a, a
    call $cec1
    reti


    ld d, l
    ld a, a
    add c
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    add c
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    ld d, l
    ld e, h
    ld a, a
    pop bc
    rst $10
    pop bc
    ld d, l
    reti


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
    call nz, Call_027_5c7f
    sub h
    ld d, l
    sub [hl]
    ld a, a
    add $d2
    rst $08
    call $ae7f
    pop bc
    jp nc, $c8c3

    ret


    call Call_027_7fd9
    add c
    ld d, l
    ld a, a
    ld d, b
    dec bc
    nop
    ld e, h
    sub h
    sub [hl]
    ld a, a
    ld d, l
    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    push bc
    call z, $c3c5
    call nc, $cfd2
    jp $d2c1


    call nz, $c955
    rst $08
    rst $00
    jp nc, $d0c1

    ret z

    add c
    ld a, a
    adc [hl]
    and a
    jp nc, $c1c5

    call nc, $cd7f
    ld d, l
    pop bc
    rst $00
    adc $c5
    call nc, $c3c9
    ld a, a
    add $c9
    push bc
    call z, Call_027_7fc4
    jp nc, $ccc5

    ld d, l
    push bc
    pop bc
    db $d3
    push bc
    db $d3
    ld a, a
    call $cec1
    reti


    ld a, a
    ret z

    pop bc
    jp nc, $c6cd

    push de
    ld d, l
    call z, $d27f
    pop bc
    reti


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nc, $cfcf
    ld a, a
    call $cec1
    reti


    ld a, a
    ret nc

    ret


    push bc
    ld c, a
    jp $d3c5


    ld a, a
    rst $08
    add $7f
    call z, $c7d5
    rst $00
    pop bc
    rst $00
    push bc
    db $d3
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor [hl]
    pop bc
    jp nc, $c8c3

    ret


    call Call_027_7fd9
    ret


    db $d3
    ld a, a
    call $c3d5
    ret z

    ld c, a
    ld a, a
    rst $08
    call z, $c5c4
    jp nc, $d47f

    ret z

    pop bc
    adc $7f
    xor c
    ld a, a
    adc [hl]
    ld a, a
    and d
    ld d, l
    push de
    call nc, Call_027_7f8c
    xor c
    ld a, a
    ld a, a
    jp nc, $d3c5

    ret nc

    push bc
    jp Jump_027_7fd4


    ret z

    push bc
    ld d, l
    jp nc, $d67f

    push bc
    jp nc, Jump_027_7fd9

    call $c3d5
    ret z

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $10
    ret


    call nc, Call_027_7fc8
    db $d3
    call nc, Call_027_4fd2
    rst $08
    adc $c7
    push bc
    jp nc, $c27f

    push bc
    call z, $c5c9
    add $7f
    rst $10
    ret


    call z, Call_027_55cc
    ld a, a
    rst $10
    ret


    adc $7f
    rst $10
    ret z

    push bc
    adc $7f
    call nc, $cfd7
    ld a, a
    rst $08
    ret nc

    ret nc

    ld d, l
    rst $08
    adc $c5
    adc $d4
    db $d3
    ld a, a
    push bc
    pop de
    push de
    pop bc
    call z, $d9cc
    ld a, a
    call Call_027_55c1
    call nc, $c8c3
    push bc
    call nz, $817f
    ld a, a
    xor [hl]
    pop bc
    jp nc, $c8c3

    ret


    call Call_027_7fd9
    ld d, l
    rst $10
    pop bc
    adc $d4
    db $d3
    ld a, a
    call nc, Call_027_7fcf
    rst $10
    ret


    adc $7f
    adc h
    ld a, a
    pop bc
    adc $55
    call nz, $d97f
    rst $08
    push de
    ld a, a
    call nc, $cfcf
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
    call z, Call_027_7fc4
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    call nc, $c9c8
    adc $cb
    ld d, l
    ld a, a
    db $d3
    rst $08
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
    jp $cec1


    add a
    call nc, Call_027_7f4f
    jp $d4c1


    jp Jump_027_7fc8


    push de
    ret nc

    ld a, a
    rst $10
    ret


    call nc, Call_027_7fc8
    ret


    call nc, $8155
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    jp $cec1


    add a
    call nc, Call_027_7f4f
    jp $d4c1


    jp Jump_027_7fc8


    push de
    ret nc

    ld a, a
    rst $10
    ret


    call nc, Call_027_7fc8
    ret


    call nc, $8155
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
    add $c5
    push bc
    call z, $d47f
    ret z

    push bc
    ld a, a
    ld c, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d5c8

    call $cec1
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    push de
    db $d3
    ld d, l
    push bc
    db $d3
    ld a, a
    pop bc
    adc $7f
    push de
    adc $d3
    push bc
    push bc
    adc $7f
    add $cf
    jp nc, Jump_027_55c3

    push bc
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ret


    jp Jump_027_7f9f


    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    call nz, $c1d6
    ld c, a
    adc $d4
    pop bc
    rst $00
    push bc
    ld a, a
    call nc, Call_027_7fcf
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d5c8

    call $c155
    adc $9f
    ld a, a
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
    adc [hl]
    ld a, a
    ld d, l
    xor d
    push de
    db $d3
    call nc, $c27f
    push bc
    call z, $cecf
    rst $00
    db $d3
    ld a, a
    call nc, Call_027_7fcf
    rst $00
    ld d, l
    ret z

    rst $08
    db $d3
    call nc, $cf7f
    jp nc, $c97f

    adc $d3
    push bc
    jp Jump_027_7fd4


    jp Jump_027_55c1


    call nc, $c7c5
    rst $08
    jp nc, $81d9

    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    push bc
    db $d3
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    set 1, c
    adc $c4
    ld a, a
    rst $08
    ld c, a
    add $7f
    call nc, $c9c8
    adc $c7
    db $d3
    ld a, a
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    push bc
    adc $9f
    ld d, l
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    push bc
    db $d3
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    set 1, c
    adc $c4
    ld a, a
    rst $08
    ld c, a
    add $7f
    call nc, $c9c8
    adc $c7
    db $d3
    ld a, a
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    push bc
    adc $9f
    ld d, l
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    ld c, a
    call z, $cbc9
    push bc
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $55
    rst $00
    ld a, a
    call $d3c1
    call nc, $d2c5
    adc h
    ld a, a
    call nz, Call_027_7fcf
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    set 1, [hl]
    rst $08
    rst $10
    sbc a
    ld a, a
    xor c
    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, $557f

    ld d, h
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    db $d3
    pop bc
    reti


    ld a, a
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    db $d3
    rst $08
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c27f
    push bc
    adc [hl]
    ld a, a
    ld d, [hl]
    ret


    ld c, a
    add $7f
    call nz, $cecf
    add a
    call nc, $d47f
    push bc
    pop bc
    jp Jump_027_7fc8


    ld d, l
    ld d, h
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $c97f
    call nc, Call_027_7f81
    ld d, a
    nop
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    add c
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
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    call nz, Call_027_7fcf
    reti


    rst $08
    push de
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $4f
    call nz, Call_027_7f9f
    ld d, h
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    pop bc
    ld d, l
    jp nz, $ccc9

    ret


    call nc, Call_027_7fd9
    adc [hl]
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    ret z

    pop bc
    db $d3
    ld d, l
    ld a, a
    db $d3
    push de
    jp Jump_027_7fc8


    pop bc
    ld a, a
    add $c1
    jp Jump_027_7fd4


    adc $cf
    call nc, $557f
    call nc, Call_027_7fcf
    rst $10
    ret


    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    push de
    call $d7cf
    jp nc, $d3c5

    call nc, $c5cc
    jp nc, $ce7f

    ld c, a
    push bc
    ret c

    call nc, $c47f
    rst $08
    rst $08
    jp nc, Jump_027_7f8e

    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld d, l
    ld a, a
    push de
    call nc, $c5d4
    jp nc, $d9cc

    ld a, a
    jp nc, $d5cf

    call nc, $c4c5
    ld a, a
    jp nz, $d955

    ld a, a
    rst $08
    push de
    jp nc, $ad7f

    ret


    db $d3
    db $d3
    ld a, a
    xor [hl]
    pop bc
    jp nc, $c8c3

    ret


    ld d, l
    call Call_027_7fd9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    ld a, a
    pop bc
    call $d37f
    ret


    call $ccd0
    reti


    ld a, a
    add $4f
    rst $08
    rst $08

Call_027_4f7f:
Jump_027_4f7f:
    call z, $d3c9
    ret z

    ld a, a
    call nc, Call_027_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    call z, Call_027_55cf
    db $d3
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    ld a, a
    pop bc
    call $d37f
    ret


    call $ccd0
    reti


    ld a, a
    add $4f
    rst $08
    rst $08
    call z, $c8d3
    ld a, a
    call nc, Call_027_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    call z, $d3cf
    ld d, l
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de

Call_027_4fc1:
Jump_027_4fc1:
    ld a, a
    pop bc
    adc $c4

Call_027_4fc5:
Jump_027_4fc5:
    ld a, a
    xor c
    ld a, a

Call_027_4fc8:
    call z, $d4c5
    ld a, a

Call_027_4fcc:
    ld c, a

Call_027_4fcd:
    ld d, h
    ld a, a

Call_027_4fcf:
    call nc, Call_027_7fcf

Call_027_4fd2:
    ret z

Jump_027_4fd3:
    pop bc

Jump_027_4fd4:
    sub $c5
    ld a, a
    pop bc
    ld a, a

Jump_027_4fd9:
    call nc, $d9d2
    ld d, l
    ld a, a
    ld d, [hl]
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

    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld c, a
    jp nc, $d3c5

    push de
    call z, Call_027_56d4
    ld a, a
    ld a, a
    rst $10
    ret


    call z, Call_027_7fcc
    jp nz, Jump_027_55c5

    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    call nz, Call_027_7fcf
    reti


    rst $08
    push de
    sbc a
    add c
    ld a, a
    or h
    ret z

    ret


    ld d, l
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    rst $08
    adc l
    jp $ccc1


    call z, $c4c5
    ld a, a
    ret nc

    jp nc, $c555

    call nz, $c3c9
    call nc, $c17f
    jp nz, $ccc9

    ret


    call nc, $8ed9
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    ld a, a
    add $c9
    adc $c1
    call z, $d9cc
    ld a, a
    call z, Call_027_4fcf
    db $d3
    call nc, SerialTransferCompleteInterrupt
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    ld a, a
    add $c9
    adc $c1
    call z, $d9cc
    ld a, a
    call z, Call_027_4fcf
    db $d3
    call nc, SerialTransferCompleteInterrupt
    ld a, a
    xor [hl]
    pop bc
    jp nc, $c8c3

    ret


    call Call_027_7fd9
    db $d3
    push de
    ret nc

    ret nc

    rst $08
    jp nc, Jump_027_4fd4

    push bc
    call nz, $d47f
    ret z

    ret


    db $d3
    ld a, a
    rst $00
    reti


    call $d77f
    ret z

    push bc
    adc $7f
    ld d, l
    db $d3
    ret z

    push bc
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    reti


    rst $08
    push de
    adc $c7
    ld a, a
    adc [hl]
    ld a, a
    db $d3
    ld d, l
    ret z

    push bc
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, $c1c5

    call z, $d07f
    rst $08
    rst $10
    ld d, l
    push bc
    jp nc, Jump_027_7f81

    db $d3
    ret z

    push bc
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $cd7f
    push bc
    push bc
    ld d, l
    call nc, $d97f
    rst $08
    push de
    ld a, a
    db $d3
    rst $08
    ld a, a
    db $d3
    ret


    call $ccd0
    reti


    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or h
    push bc
    call z, Call_027_7fcc
    reti


    rst $08
    push de
    ld a, a
    ld d, [hl]
    call nc, $c5c8
    jp nc, Jump_027_4fc5

    ld a, a
    rst $10
    push bc
    jp nc, Jump_027_7fc5

    call nc, $cfd7
    ld a, a
    rst $00
    reti


    call Call_027_7fd3
    ret


    adc $55
    ld a, a
    set 0, l
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    adc [hl]
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f7f
    rst $10
    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    ld d, l
    jp nc, $d3c5

    call nc, $c9cc
    adc $c7
    ld a, a
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld d, l
    adc l
    call nc, $cbc1
    ret


    adc $c7
    ld a, a
    reti


    pop bc
    jp nc, Jump_027_7fc4

    adc $c5
    ret c

    call nc, Call_027_7f55
    call nz, $cfcf
    jp nc, $d77f

    ret z

    push bc
    adc $7f
    call nc, $cbc1
    ret


    adc $c7
    ld d, l
    ld a, a
    ret nc

    pop bc
    jp nc, Jump_027_7fd4

    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    push de
    adc $c9
    add $55
    ret


    push bc
    call nz, $c37f
    rst $08
    call $c5d0
    call nc, $d4c9
    ret


    rst $08
    adc $81
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    and a
    reti


    call $cf7f
    add $7f
    set 0, l
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $4fc9


    call nc, $81d9
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    pop bc
    call z, $c1c9
    db $d3
    ld a, a
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ret


    adc $d3
    call nc, $d4c9
    push de
    call nc, Call_027_7fc5
    rst $08
    add $55
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $d5c8

    call $cec1
    ld a, a
    call nc, $c1d2
    ret


    adc $55
    ret


    adc $c7
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ld d, [hl]
    pop bc
    jp nc, Jump_027_55c5

    ld a, a
    call z, $cecf
    rst $00
    ret


    adc $c7
    ld a, a
    add $cf
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    ld d, l
    call $c5c5
    call nc, $d77f
    ret


    call nc, Call_027_7fc8
    xor [hl]
    pop bc
    jp nc, $c8c3

    ret


    call $d955
    sbc a
    ld a, a
    pop bc
    jp nc, $cec5

    add a
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    xor c
    ld a, a
    ld d, l
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    ret


    call nc, Call_027_7f81
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    reti


    push bc
    db $d3
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    pop bc
    jp nz, $ccc9

    ld c, a
    ret


    call nc, Call_027_7fd9
    call nc, Call_027_7fcf
    jp nc, $c1c5

    call nz, $cf7f
    call nc, $c5c8
    jp nc, $8755

    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_027_7fd4

    ret


    db $d3
    ld a, a
    jp $ccc1


    call z, Call_027_55c5
    call nz, $c17f
    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_027_7fd4

    jp nc, $d3c5

    ret nc

    rst $08
    adc $55
    db $d3
    push bc
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
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or h
    ret z

    pop bc
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $cf
    jp nc, Jump_027_7f4f

    reti


    rst $08
    push de
    jp nc, $cc7f

    push bc
    call nc, $c5d4
    jp nc, Jump_027_7f81

    xor c
    add a
    call Call_027_7f55
    call z, $cfcf
    set 1, c
    adc $c7
    ld a, a
    add $cf
    jp nc, $c1d7

    jp nc, Jump_027_7fc4

    ld d, l
    call nc, Call_027_7fcf
    call $c5c5
    call nc, $cec9
    rst $00
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop de
    push de
    ld d, l
    ret


    jp $cccb


    reti


    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    xor [hl]
    push de
    ret


    db $d3
    pop bc
    adc $55
    jp $81c5


    ld a, a
    xor c
    add a
    call $cc7f
    push bc
    call nc, $c5d4
    jp nc, $cec9

    rst $00
    ld d, l
    adc [hl]
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d07f
    push bc
    push bc
    ret nc

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call $d4c9
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    rst $00
    ret


    jp nc, $8ccc

    ld a, a
    ld c, a
    ret z

    rst $08
    rst $10
    ld a, a
    call z, $d6cf
    push bc
    call z, $81d9
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    ld d, l
    ret z

    push bc
    jp nc, $b07f

    ret


    ret nc

    ret


    ld a, a
    ret nc

    call z, $d9c1
    call nc, $c9c8
    adc $55
    rst $00
    ld a, a
    ld a, a
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    ret


    add $d4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $00
    rst $08
    call nc, $d47f
    ld c, a
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
    call nc, Call_027_55cf
    ld a, a
    push bc
    adc $c8
    pop bc
    adc $c3
    push bc
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    db $d3
    ld a, a
    pop bc
    ld a, a
    ld d, l
    sub $c5
    jp nc, Jump_027_7fd9

    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    db $d3
    set 1, c
    call z, Call_027_55cc
    ld a, a
    adc [hl]
    ld a, a
    or h
    ret z

    rst $08
    push de
    rst $00
    ret z

    ld a, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    ld d, l
    call $cec1
    reti


    ld a, a
    call $c9c1
    adc $7f
    ret nc

    rst $08
    ret


    adc $d4
    db $d3
    ld a, a
    ld d, l
    adc h
    ld a, a
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    call nc, Call_027_7fcf
    push bc
    ld d, l
    adc $c8
    pop bc
    adc $c3
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    rst $08
    ld d, l
    rst $08
    call nz, Call_027_7f9f
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_027_7fc5
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    ld c, a
    pop bc
    call nz, $cf7f
    add $7f
    db $d3
    rst $08
    jp $c5c9


    call nc, Call_027_7fd9
    ret


    db $d3
    ld a, a
    ld d, l
    adc $cf
    rst $10
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $d2c9
    push bc
    jp Jump_027_55d4


    rst $08
    jp nc, $cf7f

    add $c6
    ret


    jp Jump_027_7fc5


    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    db $d3
    push bc
    sub $c5
    adc $d4
    ret z

    ld a, a
    add $cc
    rst $08
    rst $08
    jp nc, $c97f

    add $7f
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_027_7fcf
    call $c5c5
    call nc, $557f
    ret z

    ret


    call Call_027_7f8e
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    jp nc, $d7cf

    call nc, Call_027_7fc8
    db $d3
    ret nc

    push bc
    push bc
    call nz, Call_027_7f4f
    ld a, a
    rst $08
    add $7f
    call nz, $c6c9
    add $c5
    jp nc, $cec5

    call nc, $d47f
    reti


    ld d, l
    ret nc

    push bc
    db $d3
    ld a, a
    rst $08
    add $7f
    ld d, h
    call z, $cfcf
    set 2, e
    ld a, a

Call_027_547f:
    adc $55
    rst $08
    call nc, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    call $8ec5
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    rst $08
    push bc
    sub $c5
    jp nc, $cb7f

    adc $cf
    rst $10
    db $d3
    ld a, a
    ld a, a
    db $d3
    ld c, a
    ret


    call z, $d5cc
    add $c6
    ld a, a
    and e
    rst $08
    call $c5cd
    jp nc, $c9c3

    pop bc
    call z, Call_027_7f55
    db $d3
    rst $08
    jp $c5c9


    call nc, Call_027_7fd9
    adc [hl]
    ld a, a
    xor d
    push de
    db $d3
    call nc, $c27f
    ld d, l
    push bc
    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ret


    call nc, Call_027_7fd3
    add $c1
    call $c555
    ld a, a
    adc h
    ld a, a
    xor c
    call nc, $c87f
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    call nz, $cec1
    rst $00
    ld d, l
    push bc
    jp nc, $d47f

    rst $08
    ld a, a
    jp nz, Jump_027_7fc5

    rst $00
    rst $08
    call nc, $c27f
    reti


    ld a, a
    rst $08
    ld d, l
    call nc, $c5c8
    jp nc, $57d3

    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d97f
    rst $08
    push de
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    pop bc
    jp nc, $c54f

    ld a, a
    sub $c5
    jp nc, Jump_027_7fd9

    add $cf
    adc $c4
    ld a, a
    rst $08
    add $7f
    call Call_027_55c1
    set 1, c
    adc $c7
    ld a, a
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, $c4c5
    ld a, a
    ld d, l
    ret z

    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    ld d, h
    ld a, a
    sbc a
    ld a, a
    xor b
    push bc
    ld d, l
    jp nc, Jump_027_7fc5

    jp $cdcf


    push bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    pop bc
    db $d3
    db $d3
    ret


    ld d, l
    db $d3
    call nc, $cec1
    call nc, Call_027_7f7f
    rst $08
    add $7f
    and h
    jp nc, Jump_027_7f8e

    and c
    rst $08
    jp $c855


    ret


    call nz, $d2c5
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_027_7fc5
    call nc, Call_027_7fcf
    db $d3

Jump_027_5581:
    push de
    jp Jump_027_7fc8


    ld c, a
    pop bc

Call_027_5587:
    ld a, a
    ret nc

    call z, $c3c1

Call_027_558c:
    push bc
    add c
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    call $d3d5
    call nc, $c87f
    pop bc

Call_027_559f:
    sub $c5
    ld a, a
    pop bc
    ld a, a
    ret z

    pop bc
    jp nc, Jump_027_7fc4

    ld d, l
    jp z, $d5cf

    jp nc, $c5ce

    reti


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
    adc h
    ld a, a
    reti


Call_027_55c1:
Jump_027_55c1:
    rst $08

Call_027_55c2:
    push de

Jump_027_55c3:
    add c

Call_027_55c4:
    ld a, a

Call_027_55c5:
Jump_027_55c5:
    ld d, a
    nop
    ld a, a

Call_027_55c8:
    xor b

Call_027_55c9:
    push bc
    reti


    adc h

Call_027_55cc:
Jump_027_55cc:
    ld a, a

Call_027_55cd:
Jump_027_55cd:
    reti


Jump_027_55ce:
    rst $08

Call_027_55cf:
Jump_027_55cf:
    push de

Call_027_55d0:
    adc h
    ld a, a

Call_027_55d2:
    reti


Jump_027_55d3:
    rst $08

Call_027_55d4:
Jump_027_55d4:
    push de
    add c
    ld a, a
    ld d, a
    nop

Call_027_55d9:
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $c87f
    push bc
    jp nc, $9fc5

    ld a, a
    xor c
    call nc, $c97f
    ld c, a
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $d3c1
    call nc, $d47f
    push bc
    db $d3
    call nc, Call_027_7f7f
    ld d, l
    add $cf
    jp nc, $5d7f

    add c
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    ld d, l
    call nc, $c17f
    ld a, a
    jp nc, $c1cf

    call nz, $d47f
    rst $08
    ld a, a
    jp $c1c8


    call Call_027_55d0
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    and l
    sub $c5
    jp nc, $d7d9

    ret z

    push bc
    jp nc, Jump_027_7fc5

    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    db $d3
    push bc
    jp $c5d2


    call nc, $c47f
    push bc
    sub $c9
    jp $81c5


    ld a, a
    or b
    jp nc, $c555

    db $d3
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $c3cf

    bit 7, a
    rst $10
    ret z

    push bc
    adc $55
    ld a, a
    call $c5c5
    call nc, $cec9
    rst $00
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld a, a
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    jp $c5c8


    db $d3
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    jp $c5c8


    db $d3
    call nc, Call_027_7f81
    ld e, b
    nop

Call_027_567f:
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret nc

    push de
    jp nc, $cfd0

    db $d3
    push bc
    ld a, a
    xor c
    ld a, a
    jp Jump_027_4fc1


    call Call_027_7fc5
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $d47f
    ld d, l
    rst $08
    ld a, a
    jp $c1c8


    call z, $c5cc
    adc $c7
    push bc
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
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

    rst $08
    ld d, l
    jp nc, $c17f

    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    db $d3
    add c

Call_027_56d4:
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
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_027_7f81

    ld c, a
    ld d, e
    ld a, a
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    add $cc
    push bc
    call nz, $557f
    add $d2
    rst $08
    call $c87f
    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ret nc

    rst $08
    db $d3
    db $d3
    ret


    jp nz, $c5cc

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ret nc

    rst $08
    db $d3
    db $d3
    ret


    jp nz, $c5cc

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    add $7f
    db $d3
    rst $10
    ret


    adc $c7
    ret


    adc $4f
    rst $00
    ld a, a
    pop bc
    ld a, a
    rst $10
    ret z

    ret


    ret nc

    add c
    ld a, a
    db $d3
    rst $10
    ret


    adc $c7
    ld a, a
    ret nc

    ld d, l
    jp nc, $c6cf

    ret


    jp $c5c9


    adc $d4
    call z, $81d9
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, Call_027_7fcc
    ret


    adc $7f
    pop bc
    call z, $8ccc
    ld a, a
    call nc, $c5c8
    jp nc, $c54f

    ld a, a
    pop bc
    jp nc, Jump_027_7fc5

    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    rst $10
    ret z

    rst $08
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    jp $cdcf


    push bc
    ld a, a
    pop bc
    adc $c4
    ld d, l
    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    rst $10
    pop bc
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c1c8


    call $d055
    ld a, a
    jp nc, $c1cf

    call nz, $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $10
    ret


    adc $c4
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    jp nc, $cf7f

    call nc, $c84f
    push bc
    jp nc, $d37f

    rst $08
    push de
    adc $c4
    add c
    ld a, a
    ld e, b
    nop
    ld a, a

Jump_027_57c5:
    rst $10
    ret


    adc $c4
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    jp nc, $cf7f

    call nc, $c84f
    push bc
    jp nc, $d37f

    rst $08
    push de
    adc $c4
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    add a
    call z, Call_027_7fcc
    call $c5c5
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld c, a
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

    rst $08
    ld d, l
    jp nc, $c17f

    call nc, $c5d4
    adc $c4
    pop bc
    adc $d4
    db $d3
    ld a, a
    ret


    add $7f
    reti


    ld d, l
    rst $08
    push de
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
    ret z

    ld d, l
    push bc
    jp nc, Jump_027_7fc5

    db $d3
    pop bc
    add $c5
    call z, $81d9
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $cc7f
    rst $08
    db $d3
    push bc
    ld a, a
    ret z

    pop bc
    call nz, Call_027_7f4f
    xor c
    ld a, a
    db $d3
    rst $08
    call Call_027_7fc5
    set 1, [hl]
    rst $08
    rst $10
    call z, $c4c5
    rst $00
    push bc
    ld d, l
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, Call_027_547f
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor a
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor a
    ret z

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
    jp nz, $d5cf

    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    xor c
    ld c, a
    call nc, $d387
    ld a, a
    db $d3
    rst $08
    call Call_027_7fc5
    ret z

    pop bc
    jp nc, Jump_027_7fc4

    call nc, Call_027_7fcf
    ld d, l
    call $d5cf
    adc $d4
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $c1c8


    call $d055
    ld a, a
    jp nc, $c1cf

    call nz, Call_027_7f8c
    ret


    db $d3
    adc $87
    call nc, $c97f
    call nc, Call_027_559f
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    call nc, $c5c8
    jp nc, Jump_027_7fc5

    pop bc
    jp nc, Jump_027_7fc5

    call Call_027_4fc1
    adc $d9
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    db $d3
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    jp Jump_027_55c1


    call Call_027_7fc5
    ret z

    push bc
    jp nc, Jump_027_7fc5

    jp nz, $d4d5

    ld a, a
    rst $10
    push bc
    adc $d4
    ld a, a
    ld d, l
    jp nz, $c3c1

    bit 7, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    push bc
    ld d, l
    ret c

    call nc, $c5d2
    call $ccc5
    reti


    ld a, a
    add $c1
    call nc, $c7c9
    push de
    push bc
    ld a, a
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_027_7f8c
    pop de
    push de
    pop bc
    call z, $c6c9
    ret


    push bc
    call nz, $4f81
    ld a, a
    ld e, b
    nop
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_027_7f8c
    pop de
    push de
    pop bc
    call z, $c6c9
    ret


    push bc
    call nz, $4f81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_027_7fc4

    call nc, $c5c8
    ld a, a
    ret z

    ld c, a
    push bc
    pop bc
    jp nc, $c1d3

    reti


    ld a, a
    call nc, $c1c8
    call nc, $d47f
    ret z

    push bc
    jp nc, Jump_027_55c5

    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nz, $d9cf

    ld a, a
    rst $10
    ret


    call nc, Call_027_7fc8
    rst $00
    jp nc, $c555

    pop bc
    call nc, $c17f
    jp nz, $ccc9

    ret


    call nc, Call_027_7fd9
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d97f
    rst $08
    push de
    ld a, a
    ld d, [hl]
    rst $10
    ret z

    rst $08
    ld a, a
    ld c, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    jp nc, $c3cf

    set 0, l
    call nc, $c27f
    rst $08
    call Call_027_7fc2
    db $d3
    pop bc
    set 0, c
    ld d, l
    jp $d9c8


    ld a, a
    ld a, a
    adc h
    ld a, a
    ret


    db $d3
    adc $87
    call nc, $c97f
    call nc, Call_027_7f9f
    ld d, l
    ld d, a
    nop
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, Jump_027_4fd9

    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, Jump_027_4fd9

    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    ret z

    adc h
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
    push bc
    sub $c5
    jp nc, $d37f

    call nc, $cfd2
    adc $c7
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    pop bc
    jp nc, $8cc5

    ld a, a
    call nc, $c5c8
    jp nc, $87c5

    db $d3
    ld a, a
    pop bc
    call z, $d755
    pop bc
    reti


    db $d3
    ld a, a
    db $d3
    rst $08
    call Call_027_7fc5
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    ld d, l
    jp nc, Jump_027_7f9f

    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_027_7fc5

    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_027_7f4f

    call nc, $c1c8
    adc $7f
    xor c
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
    ld d, l
    rst $10
    ret z

    pop bc
    call nc, $d97f
    rst $08
    push de
    add a
    sub $c5
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $557f
    jp z, $d3d5

    call nc, Call_027_7f8c
    ret


    db $d3
    adc $87
    call nc, $d47f
    ret z

    ret


    db $d3
    sbc a
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_027_4fd9

    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, $a97f
    ld a, a
    add $55
    push bc
    push bc
    call z, Call_027_7f81
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_027_4fd9

    adc h
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, $a97f
    ld a, a
    add $55
    push bc
    push bc
    call z, Call_027_7f81
    ld e, b
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    db $d3
    push bc
    call z, $c3c5
    call nc, $c4c5
    ld a, a
    jp Jump_027_4fc1


    adc $7f
    ret


    call nc, $c67f
    call z, $c5c5
    ld a, a
    add $d2
    rst $08
    call $c87f
    push bc
    ld d, l
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, Call_027_7fcc
    ld a, a
    call nc, $c5c8
    ld a, a
    ld c, a
    ld e, l
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_027_7fc5

    pop bc
    ret


    call Call_027_55c9
    adc $c7
    ld a, a
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    adc [hl]
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $ce7f

    rst $08
    call nc, Call_027_7f55
    jp nz, Jump_027_7fc5

    jp $d2c1


    push bc
    call z, $d3c5
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    adc $7f
    push de
    adc $c5
    ret c

    ret nc

    push bc
    jp $c5d4


    call nz, $c47f
    push bc
    ld c, a
    add $c5
    pop bc
    call nc, Call_027_7f8e
    ld e, b
    nop
    ld a, a
    and c
    adc $7f
    push de
    adc $c5
    ret c

    ret nc

    push bc
    jp $c5d4


    call nz, $c47f
    push bc
    ld c, a
    add $c5
    pop bc
    call nc, Call_027_7f8e
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call z, $c6c9
    push bc
    ld a, a
    rst $08
    add $7f
    ld c, a
    ld e, l
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, Call_027_7fcf
    call z, $cfcf
    ld d, l
    bit 7, a
    add $cf
    jp nc, $d37f

    call nc, $cfd2
    adc $c7
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    ld d, l
    adc $c5
    adc $d4
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    adc $7f
    ret


    adc $c3
    push bc
    db $d3
    db $d3
    pop bc
    adc $d4
    ld a, a
    pop bc
    adc $c4
    ld c, a
    ld a, a
    db $d3
    call nc, $c9d2
    jp Jump_027_7fd4


    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    ld d, l
    rst $08
    adc $7f
    jp $cec1


    ld a, a
    call nc, $c1c5
    jp Jump_027_7fc8


    reti


    rst $08
    push de
    ld a, a
    ld d, l
    pop bc
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, $8ecc
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nc, $cfcf
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    add c
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nc, $cfcf
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    add c
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    or a
    ret z

    rst $08
    ld a, a
    pop bc
    jp nc, Jump_027_7fc5

    reti


    rst $08
    push de
    sbc a
    ld c, a
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call nz, Call_027_7fcf
    reti


    rst $08
    push de
    ld a, a
    jp $cdcf


    push bc
    sbc a
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    adc h
    ld a, a
    reti


    rst $08
    push de

Call_027_5c7f:
    ld a, a
    add $c5
    call z, $cfcc
    ld c, a
    rst $10
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $d2c1
    push bc
    ld a, a
    call nc, Call_027_7fcf
    call z, Call_027_55cf
    rst $08
    bit 7, a
    call nz, $d7cf
    adc $7f
    rst $08
    adc $7f
    ld d, l
    ld e, [hl]
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
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
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
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c5
    call z, Call_027_4fcc
    rst $08
    rst $10
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    call z, $d0c9
    ret nc

    push bc
    ld d, l
    call nz, $c97f
    adc $d4
    rst $08
    ld a, a
    ld e, [hl]
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d47f
    ret z

    ret


    ld c, a
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    ld d, l
    pop bc
    call nz, $d37f
    rst $08
    ld a, a
    push bc
    pop bc
    db $d3
    ret


    call z, Call_027_7fd9
    add c
    ld a, a
    nop
    ld a, a
    call nz, $cfd2
    ret nc

    ld a, a
    rst $08
    jp nc, $c67f

    pop bc
    call z, Call_027_7fcc
    db $d3
    push de
    call nz, $c44f
    push bc
    adc $cc
    reti


    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    call nz, $cfd2
    ret nc

    ld a, a
    rst $08
    jp nc, $c67f

    pop bc
    call z, Call_027_7fcc
    db $d3
    push de
    call nz, $c44f
    push bc
    adc $cc
    reti


    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
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
    pop bc
    adc $7f
    ret


    adc $4f
    call nc, $d5d2
    call nz, $d2c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_027_567f
    add c
    ld a, a
    xor h
    rst $08
    rst $08
    set 1, c
    adc $c7
    ld a, a
    ld c, a
    add $cf
    jp nc, $d37f

    ret


    call z, $d5cc
    add $c6
    ld a, a
    xor a
    jp nz, $c5d3

    jp nc, $d655

    pop bc
    call nc, $d2cf
    sbc a
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    ld a, a
    call nz, Call_027_7fcf
    call nz, Call_027_55cf
    adc $87
    call nc, $cb7f
    adc $cf
    rst $10
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    and c
    call $a97f
    ld a, a
    adc $cf
    call nc, Call_027_7f9f
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    or a
    rst $08
    adc $87
    call nc, $c97f
    call nc, $c47f
    rst $08
    sbc a
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d07f

    push de
    jp nc, $d04f

    rst $08
    db $d3
    push bc
    ld a, a
    jp $cdcf


    ret


    adc $c7
    ld a, a
    ret z

    push bc
    jp nc, $9fc5

    ld d, l
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
    add c
    ld a, a
    ld d, [hl]
    or l
    ret nc

    ld a, a
    ld c, a
    jp nz, Jump_027_7fd9

    call z, $c6c9
    call nc, $d08c
    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ret


    ld d, l
    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_027_7fcf
    call $c5c5
    ld d, l
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    adc [hl]
    ld a, a
    ld e, b
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    call z, $d3cf
    call nc, $d78d
    pop bc
    reti


Call_027_5e7f:
    ld a, a
    jp nz, $d9cf

    adc [hl]
    ld a, a
    ld c, a
    and c
    jp nc, Jump_027_7fc5

    reti


    rst $08
    push de
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    rst $08
    ld d, l
    add $7f
    call z, $d3cf
    call nc, $d78d
    pop bc
    reti


    ld a, a
    jp nz, $d9cf

    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $cfcf
    jp nc, $d77f

    pop bc
    ld c, a
    db $d3
    ld a, a
    rst $08
    ret nc

    push bc
    adc $c5
    call nz, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c955

    rst $08
    call nc, $c17f
    ld a, a
    call $d6cf
    push bc
    call $cec5
    call nc, $c17f
    rst $00
    ld d, l
    rst $08
    ld a, a
    adc [hl]
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
    db $d3
    push bc
    push bc
    ld a, a
    ld a, a
    pop bc
    adc $7f
    ld c, a
    push de
    adc $d3
    push bc
    push bc
    adc $7f
    rst $00
    ret z

    rst $08
    db $d3
    call nc, $d57f
    db $d3
    ret


    adc $55
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret


    call z, $d5cc
    add $c6
    ld a, a
    xor a
    jp nz, Jump_027_55d3

    push bc
    jp nc, $c1d6

    call nc, $d2cf
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    ld d, l
    db $d3
    pop bc
    ret


    call nz, $d37f
    rst $08
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

    push bc
    pop bc
    call nz, $d5d1
    pop bc
    jp nc, $c5d4

    jp nc, Jump_027_4fd3

    ld a, a
    ld a, a
    rst $08
    add $7f
    ld e, [hl]
    ret


    db $d3
    ld a, a
    rst $08
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $c9c8
    jp nc, Jump_027_7fc4

    add $cc
    rst $08
    rst $08
    jp nc, $557f

    push de
    adc $c4
    push bc
    jp nc, $d2c7

    rst $08
    push de
    adc $c4
    adc [hl]
    and e
    pop bc
    adc $7f
    ret


    ld d, l
    call nc, $d27f
    push bc
    pop bc
    jp Jump_027_7fc8


    call nc, Call_027_7fcf
    call nc, $c5c8
    ld a, a
    jp nz, Jump_027_55cf

    db $d3
    db $d3
    add a
    db $d3
    sbc a
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
    and d
    push de
    call nc, Call_027_7f8c
    and h
    rst $08
    adc $87
    call nc, Call_027_7f7f
    call nc, $cfd2
    push de
    ld c, a
    jp nz, $c5cc

    ld a, a
    ld e, [hl]
    ld a, a
    adc [hl]
    ld a, a
    or h
    ret z

    ret


    ld d, l
    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    push de
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    ret


    call z, $d5cc
    add $c6
    ld a, a
    xor a
    ld c, a
    jp nz, $d2d3

    push bc
    sub $c1
    call nc, $d2cf
    sbc a
    ld a, a
    and c
    ret z

    ld a, a
    adc h
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    db $d3
    call nc, $cccf
    push bc
    adc $55
    ld a, a
    jp nz, Jump_027_7fd9

    call nc, $c5c8
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    add $d2
    rst $08
    call Call_027_7f55
    call nc, $c5c8
    ld a, a
    db $d3
    ret


    call z, $d5cc
    add $c6
    ld a, a
    and e
    rst $08
    call Call_027_55cd
    push bc
    jp nc, $c9c3

    pop bc
    call z, $d37f
    rst $08
    jp $c5c9


    call nc, Call_027_7fd9
    add c
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    or a
    ret z

    push bc
    jp nc, Jump_027_7fc5

    db $d3
    ret z

    rst $08
    push de
    call z, Call_027_7fc4
    ret


    ld d, l
    call nc, $c27f
    push bc
    ld a, a
    ret nc

    push de
    call nc, Call_027_7f9f
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
    rst $08
    add $7f
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
    rst $08
    add $7f
    pop bc
    ld a, a
    ret nc

    call z, $d4cf
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    ret


    add c
    ld a, a
    jp $cdcf


    push bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $cf4f


    adc $d4
    pop bc
    jp Jump_027_7fd4


    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    push de
    ld d, l
    ret nc

    push bc
    jp nc, $c67f

    call z, $cfcf
    jp nc, $817f

    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    add c
    ld a, a
    call z, $d4c5
    add a
    ld c, a
    db $d3
    ld a, a
    add c
    ld a, a
    rst $00
    rst $08
    ld a, a
    and d
    push de
    call nc, Call_027_7f8c
    xor c
    call nc, $c97f
    db $d3
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
    jp nc, $d57f

    ld d, l
    db $d3
    ld a, a
    call nc, Call_027_7fcf
    rst $00
    push bc
    call nc, $cf7f
    adc $7f
    call z, $c6c9
    call nc, $557f
    rst $10
    ret


    call nc, $cfc8
    push de
    call nc, $c17f
    ld a, a
    set 0, l
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor h
    rst $08
    db $d3
    call nc, Call_027_567f
    adc h
    ld a, a
    and [hl]
    rst $08
    rst $08
    call z, Call_027_7f81
    ld e, b
    nop
    ld a, a
    xor h
    rst $08
    db $d3
    call nc, Call_027_567f
    adc h
    ld a, a
    and [hl]
    rst $08
    rst $08
    call z, Call_027_7f81
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, h
    ld a, a
    rst $10
    ld c, a
    ret


    call nc, Call_027_7fc8
    reti


    rst $08
    push de
    jp nc, $c17f

    call z, Call_027_7fcc
    call z, $d6cf
    push bc
    ld d, l
    ld a, a
    adc [hl]
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    jp nz, $d9c5

    rst $08
    adc $c4
    ld a, a
    call Call_027_55d9
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
    add $cf
    ld d, l
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_027_7fcf
    call nc, $c5d2
    pop bc
    call nc, $d37f
    push de
    ld d, l
    jp Jump_027_7fc8


    pop bc
    ld a, a
    jp nz, $d9cf

    ld a, a
    adc [hl]
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld a, a
    jp $cf55


    call Call_027_7fc5
    pop bc
    adc $c4
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call z, Call_027_55cf
    rst $08
    res 0, c
    ld a, a
    xor [hl]
    push bc
    ret c

    call nc, $d47f
    ret


    call $8cc5
    ld a, a
    xor c
    add a
    ld d, l
    call nz, $cc7f
    ret


    set 0, l
    ld a, a
    call nc, Call_027_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    ld d, l
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    ld d, [hl]
    ld a, a
    rst $10
    ret


    ld d, l
    call nc, Call_027_7fc8
    reti


    rst $08
    push de
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
    ret


    call nc, $d387
    ld a, a
    reti


    rst $08
    push de
    add c
    ld a, a
    or h
    ret z

    ld c, a
    push bc
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    call $cbc1
    ret


    adc $c7
    ld a, a
    call nc, $d255
    rst $08
    push de
    jp nz, $c5cc

    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    ld d, l
    adc $8d
    pop bc
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ld d, l
    ret


    adc $7f
    rst $10
    ret z

    ret


    call z, Call_027_7fc5
    rst $10
    push bc
    ld a, a
    rst $10
    push bc
    jp nc, Jump_027_7fc5

    ld d, l
    call z, $cfcf
    set 1, c
    adc $c7
    ld a, a
    add $cf
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    add $55
    rst $08
    db $d3
    db $d3
    ret


    call z, $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, $c1d7
    reti


    db $d3
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld a, a
    ld c, a
    ld e, [hl]
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, $c27f
    push de
    call nc, Call_027_4f7f
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    rst $10
    jp nc, $cecf

    rst $00
    push bc
    call nz, $c27f
    push de
    call nc, Call_027_4f7f
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    jp nz, $cfcc

    set 0, l
    db $d3
    add c
    ld a, a
    and h
    rst $08
    adc $4f
    add a
    call nc, $d97f
    rst $08
    push de
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    call $d4c1
    push bc
    jp nc, $d4d3

    jp nc, $cbcf

    push bc
    ld a, a
    ld d, l
    rst $08
    add $7f
    ld e, [hl]
    add a
    db $d3
    ld a, a
    push bc
    sub $c9
    call z, Call_027_7f55
    call nz, $c5c5
    call nz, $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor b
    ret


    db $d3
    ld a, a
    ld c, a
    add $cf
    jp nc, $c5c3

    ld a, a
    ret


    db $d3
    ld a, a
    adc $cf
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ld d, l
    call z, $d2c1
    rst $00
    push bc
    jp nc, Jump_027_7f8e

    ld d, a
    nop
    ld a, a
    jp $d9d2


    ret


    adc $c7
    ld a, a
    rst $08
    jp nc, $cf7f

    call nc, $c5c8
    jp nc, Jump_027_4f7f

    db $d3
    rst $08
    push de
    adc $c4
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp $d9d2


    ret


    adc $c7
    ld a, a
    rst $08
    jp nc, $cf7f

    call nc, $c5c8
    jp nc, Jump_027_4f7f

    db $d3
    rst $08
    push de
    adc $c4
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
    ret z

    pop bc
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $d387
    ld c, a
    ld a, a
    call nc, $c5c8
    ld a, a
    call $c1c5
    adc $c9
    adc $c7
    ld a, a
    rst $08
    add $7f
    call nc, $c855
    pop bc
    call nc, $cc7f
    ret


    add $d4
    ld a, a
    jp $cec1


    ld a, a
    jp nz, Jump_027_7fc5

    push de
    ld d, l
    db $d3
    push bc
    call nz, Call_027_7f9f
    or a
    ret z

    rst $08
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    set 0, l
    reti


    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    adc h
    adc $cf
    add c
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    adc h
    adc $cf
    add c
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    pop bc
    sub $c5
    ld a, a
    call $81c5
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    jp $cc4f


    push bc
    jp nc, Jump_027_7fcb

    rst $08
    add $7f
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    jp $cf55


    call Call_027_7f8e
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    jp $c5cc


    jp nc, Jump_027_7fcb

    rst $08
    add $7f
    xor b
    ld c, a
    ret


    call z, $d5cc
    add $c6
    ld a, a
    jp $cdcf


    adc [hl]
    ld a, a
    ld d, a
    pop bc
    call nc, $d47f
    ret z

    ld d, l
    push bc
    ld a, a
    db $d3
    pop bc
    call Call_027_7fc5
    call nc, $cdc9
    push bc
    ld a, a
    adc h
    ld a, a
    xor c
    add a
    call Call_027_7f55
    pop bc
    call z, $cfd3
    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld e, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and l
    ret c

    ret nc

    rst $08
    db $d3
    push bc
    call nz, Call_027_7f9f
    ld e, b
    nop
    ld a, a
    and l
    ret c

    ret nc

    rst $08
    db $d3
    push bc
    call nz, Call_027_7f9f
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_027_7fc5

    adc $cf
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $cec9

    rst $00
    ld c, a
    ld a, a
    rst $00
    rst $08
    ld a, a
    jp nz, $c3c1

    res 1, h
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c9d5

    call z, $c9c4
    adc $c7
    ld a, a
    ld c, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    jp $cdcf


    ret nc

    call z, $d8c5
    ld a, a
    adc [hl]
    ld a, a
    xor c
    ld d, l
    db $d3
    ld a, a
    ret


    call nc, $c77f
    rst $08
    rst $08
    call nz, $c67f
    rst $08
    jp nc, $d97f

    rst $08
    push de
    ld d, l
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d37f
    rst $08
    ld a, a
    push bc
    pop bc
    db $d3
    reti


    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d37f
    rst $08
    ld a, a
    push bc
    pop bc
    db $d3
    reti


    add c
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_027_7fc5

    jp $c9c8


    call z, $d2c4
    push bc
    adc $7f
    ld a, a
    pop bc
    ld c, a
    jp nc, Jump_027_7fc5

    add $cf
    jp nc, $c9c2

    call nz, $c5c4
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nc, $cfc8

    call $d5c2
    db $d3
    ld a, a
    add $cc
    rst $08
    rst $08
    ld c, a
    jp nc, Jump_027_7f7f

    rst $10
    pop bc
    db $d3
    ld a, a
    call nz, $d3c5
    ret


    rst $00
    adc $c5
    call nz, $c17f
    ld d, l
    db $d3
    ld a, a
    rst $10
    rst $08
    rst $08
    call nz, Call_027_7fd9
    ret nc

    call z, $d4c1
    push bc
    ld a, a
    call nc, $c1d2
    ld d, l
    adc $d3
    add $c5
    jp nc, $c5d2

    call nz, $c27f
    reti


    ld a, a
    push bc
    call z, $c3c5
    call nc, $d255
    ret


    jp $d4c9


    reti


    ld a, a
    add c
    ld a, a
    and c
    ld a, a
    call $d6cf
    ret


    adc $c7
    ld d, l
    ld a, a
    call $c1c5
    adc $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    ret


    adc l
    ld d, l
    call nc, $c3c5
    ret z

    ld a, a
    jp nz, $c9d5

    call z, $c9c4
    adc $c7
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    rst $08
    adc $c4
    push bc
    jp nc, $d5c6

    call z, Call_027_7f81
    ld e, b
    nop
    ld a, a
    or a
    rst $08
    adc $c4
    push bc
    jp nc, $d5c6

    call z, Call_027_7f81
    ld e, b
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d9cf

    ld a, a
    call nc, $c5c8
    jp nc, $c54f

    add c
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $cc7f
    rst $08
    pop bc
    add $7f
    call nc, $c5c8
    ld d, l
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    ld e, [hl]
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld c, a
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

    ld d, l
    pop bc
    call z, $d37f
    rst $08
    jp $c5c9


    call nc, Call_027_7fd9
    ret


    db $d3
    ld a, a
    jp $cfcf


    ld d, l
    ret nc

    push bc
    jp nc, $d4c1

    ret


    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    push de
    adc $d7
    ret


    db $d3
    push bc
    add c
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    ret z

    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    push de
    adc $d7
    ret


    db $d3
    push bc
    add c
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d77f
    push bc
    call z, $cfc3
    call Call_027_7fc5
    rst $08
    adc $4f
    push bc
    db $d3
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld a, a
    push de
    ld d, l
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    call nc, $c5c8
    adc $8c
    ld a, a
    ret z

    ret


    adc $d4
    add c
    ld a, a
    ld a, a
    ld c, a
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    pop bc
    ld a, a
    jp $d2c1


    call nz, $c37f
    pop bc
    adc $7f
    ld d, l
    rst $08
    ret nc

    push bc
    adc $7f
    call nc, $c5c8
    ld a, a
    call z, $c3cf
    set 0, l
    call nz, $c47f
    ld d, l
    rst $08
    rst $08
    jp nc, Jump_027_7f7f

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
    xor c
    adc h
    jp nz, $c3c5

    rst $08
    call Call_027_7fc5
    pop bc
    ld a, a
    add $d2
    ret


    push bc
    adc $4f
    call nz, $cf7f
    add $7f
    ld e, [hl]
    pop bc
    jp $cfc3


    jp nc, $c455

    ret


    adc $c7
    ld a, a
    call nc, Call_027_7fcf
    call nc, $c5c8
    ld a, a
    ret


    adc $d3
    call nc, Call_027_55d2
    push de
    jp $c9d4


    rst $08
    adc $7f
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    xor b
    ret


    call z, $cc55
    push de
    add $c6
    ld a, a
    and e
    rst $08
    call $c5cd
    jp nc, $c9c3

    pop bc
    call z, $d37f
    ld d, l
    rst $08
    jp $c5c9


    call nc, Call_027_7fd9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_027_7f9f
    or h
    ret z

    push bc
    ld a, a
    jp $cccf


    ld c, a
    call z, $c7c5
    push de
    push bc
    db $d3
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld e, [hl]
    jp $cec1


    ld a, a
    call nz, Call_027_7fcf
    pop bc
    adc $d9
    ld d, l
    call nc, $c9c8
    adc $c7
    ld a, a
    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    reti


    ld a, a
    call z, $cbc9
    ld d, l
    push bc
    ld a, a
    adc [hl]
    ld a, a
    xor h
    push bc
    call nc, $d387
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    ld d, l
    ld d, h
    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    reti


    add a
    sub $c5
    ld a, a
    db $d3
    pop bc
    ret


    call nz, Call_027_7f55
    db $d3
    rst $08
    add c
    ld a, a
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
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    and e
    rst $08
    call Call_027_4fcd
    push bc
    jp nc, $c9c3

    pop bc
    call z, $d37f
    rst $08
    jp $c5c9


    call nc, Call_027_7fd9
    rst $10
    pop bc
    ld d, l
    db $d3
    ld a, a
    pop bc
    jp $d5c3


    ret nc

    ret


    push bc
    call nz, $c27f
    reti


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
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    ld c, a
    pop bc
    ret


    call $c4c5
    ld a, a
    pop bc
    call nc, $c97f
    call nc, $c27f
    push bc
    add $cf
    jp nc, $c555

    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    pop bc
    adc h
    pop bc
    ret z

    pop bc
    adc h
    pop bc
    ret z

    pop bc
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    pop bc
    adc h
    pop bc
    ret z

    pop bc
    adc h
    pop bc
    ret z

    pop bc
    adc [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    call Call_027_7fd9
    call z, $d9cf
    pop bc
    call z, Call_027_4f7f
    db $d3
    push de
    jp nz, $d2cf

    call nz, $cec9
    pop bc
    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, Call_027_7fcc
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $cfcf
    jp nc, $d77f

    push bc
    ld c, a
    jp nc, Jump_027_7fc5

    ret


    adc $d3
    call nc, $ccc1
    call z, $c4c5
    ld a, a
    push bc
    call z, $c3c5
    ld d, l
    call nc, $c9d2
    jp $cc7f


    rst $08
    jp $d3cb


    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    jp nz, $c9d5

    call z, $c9c4
    adc $c7
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp Jump_027_55c1


    adc $7f
    adc $cf
    call nc, $cf7f
    ret nc

    push bc
    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, Call_027_55cf
    rst $08
    jp nc, $d77f

    ret


    call nc, $cfc8
    push de
    call nc, $c17f
    ld a, a
    jp $d2c1


    call nz, Call_027_7f55
    set 0, l
    reti


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
    adc [hl]
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call $d2c5
    ld c, a
    jp $ccc9


    push bc
    db $d3
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    jp nz, Jump_027_55cc

    rst $08
    set 0, l
    ld a, a
    ret


    db $d3
    ld a, a
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
    xor b
    rst $08
    rst $10
    ld a, a
    call $d2c5
    jp $4fc9


    call z, $d3c5
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    jp nz, $cfcc

    bit 2, l
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and [hl]
    ret


    adc $c4
    ret


    adc $c7
    ld a, a
    pop bc
    ld a, a
    db $d3
    push de
    db $d3
    ret nc

    jp Jump_027_4fd4


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c37f
    rst $08
    adc $d4
    pop bc
    jp Jump_027_7fd4


    rst $10
    ret


    ld c, a
    call nc, Call_027_7fc8
    call nc, $c5c8
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    rst $08
    adc $7f
    call nc, Call_027_55c8
    push bc
    ld a, a
    call nc, $cec5
    call nc, Call_027_7fc8
    add $cc
    rst $08
    rst $08
    jp nc, $817f

    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    jp nc, Jump_027_7fc5

    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    jp nc, Jump_027_7fc5

    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    ld a, a
    jp nc, $d0c5

    rst $08
    jp nc, $81d4

    ld a, a
    and c
    ld c, a
    ld a, a
    call $cec1
    adc l
    call $c4c1
    push bc
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, $a27f
    ld d, l
    rst $08
    call z, Call_027_7fd9
    ld d, h
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp $cdcf


    push bc
    ld d, l
    ld a, a
    call nc, Call_027_7fcf
    jp nz, $d2c9

    call nc, Call_027_7fc8
    db $d3
    push de
    jp $c5c3


    db $d3
    db $d3
    ld d, l
    add $d5
    call z, $d9cc
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret


    ld d, l
    adc $d3
    call nc, $d4c9
    push de
    call nc, Call_027_7fc5
    ld d, h
    adc [hl]
    ld a, a
    ld d, [hl]
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    ld a, a
    jp nc, $d0c5

    rst $08
    jp nc, $81d4

    ld a, a
    ld c, a
    ld d, h
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call $d2cf
    push bc
    ld a, a
    call nc, $c1c8
    adc $55
    ld a, a
    sub c
    sub [hl]
    sub b
    ld a, a
    db $d3
    set 1, c
    call z, $d3cc
    ld a, a
    ld a, a
    pop bc
    db $d3
    ld a, a
    add $55
    pop bc
    jp nc, $c17f

    db $d3
    ld a, a
    rst $10
    push bc
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    ld a, a
    jp nc, $d0c5

    rst $08
    jp nc, $81d4

    ld a, a
    or h
    ld c, a
    ret z

    push bc
    jp nc, Jump_027_7fc5

    pop bc
    jp nc, Jump_027_7fc5

    sub h
    ld a, a
    set 1, c
    adc $c4
    db $d3
    ld a, a
    ld d, l
    rst $08
    add $7f
    ld d, h
    ld a, a
    ld a, a
    ret nc

    jp nc, $cdcf

    rst $08
    call nc, $cfc9
    adc $55
    ld a, a
    call nc, Call_027_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    jp nz, $c5c5

    adc $7f
    ret


    call nz, Call_027_55c5
    adc $d4
    ret


    add $c9
    push bc
    call nz, $c27f
    reti


    ld a, a
    pop bc
    call z, $c5d4
    jp nc, Jump_027_55ce

    pop bc
    call nc, Call_027_7fc5
    jp $c2c1


    call z, Call_027_7fc5
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor d
    push de
    db $d3
    call nc, $ce7f
    rst $08
    rst $10
    adc h
    ld a, a
    call nc, $c5c8
    jp nc, Jump_027_7fc5

    ld c, a
    rst $10
    pop bc
    db $d3
    ld a, a
    db $d3
    push de
    jp Jump_027_7fc8


    pop bc
    ld a, a
    jp nc, $d0c5

    rst $08
    jp nc, Jump_027_55d4

    ld a, a
    call nc, $c1c8
    call nc, $d47f
    ret z

    push bc
    jp nc, Jump_027_7fc5

    rst $10
    pop bc
    db $d3
    ld a, a
    pop bc
    ld d, l
    ld a, a
    jp nz, $d9cf

    ld a, a
    ld a, a
    call z, $c1cf
    add $c9
    adc $c7
    ld a, a
    ret z

    push bc
    jp nc, $c555

    add c
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $d27f
    push bc
    db $d3
    ret


    db $d3
    call nc, $c17f
    rst $00
    pop bc
    ld c, a
    ret


    adc $d3
    call nc, Call_027_5e7f
    ld a, a
    xor c
    call nc, $d387
    ld d, l
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    push de
    jp nc, $557f

    db $d3
    pop bc
    add $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    pop bc
    call z, $c9cc
    adc $c7
    ld a, a
    db $d3
    push de
    call nz, $c5c4
    adc $cc
    reti


    ld c, a
    ld a, a
    rst $08
    jp nc, $c77f

    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    pop bc
    ld a, a
    db $d3
    push de
    jp nc, $d055

    jp nc, $d3c9

    push bc
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    and [hl]
    pop bc
    call z, $c9cc
    adc $c7
    ld a, a
    db $d3
    push de
    call nz, $c5c4
    adc $cc
    reti


    ld c, a
    ld a, a
    rst $08
    jp nc, $c77f

    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    pop bc
    ld a, a
    db $d3
    push de
    jp nc, $d055

    jp nc, $d3c9

    push bc
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret z

    pop bc
    call z, Call_027_7fcc
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, Call_027_4fc8
    push bc
    ld a, a
    jp nc, $d3c5

    push bc
    pop bc
    jp nc, $c8c3

    ld a, a
    call nz, $d0c5
    pop bc
    jp nc, Jump_027_55cd

    push bc
    adc $d4
    ld a, a
    rst $08
    add $7f
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, Jump_027_55c1

    call z, Call_027_7fcc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_027_7fc5

    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld c, a
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $d3c1
    call nc, $cd7f
    rst $08
    adc $d3
    ld d, l
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $d77f
    ret z

    ret


    jp Jump_027_7fc8


    push bc
    sub $55
    push bc
    adc $7f
    jp $cec1


    ld a, a
    jp $d4c1


    jp Jump_027_7fc8


    call nc, $c5c8
    ld a, a
    ld d, l
    call z, $c7c5
    push bc
    adc $c4
    ld a, a
    ld d, h
    ld d, a
    nop
    ld a, a
    and h
    ret


    jp nc, $d9d4

    ld a, a
    db $d3
    rst $10
    ret


    adc $c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    ret


    jp nc, $d9d4

    ld a, a
    db $d3
    rst $10
    ret


    adc $c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    push de
    db $d3
    ret nc

    push bc
    jp $c5d4


    call nz, Call_027_7f9f
    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $4f
    reti


    ld a, a
    jp nc, $c1c5

    db $d3
    rst $08
    adc $7f
    rst $10
    ret z

    reti


    ld a, a
    call z, $d4c9
    call nc, $cc55
    push bc
    ld a, a
    jp nz, $d9cf

    ld a, a
    jp $cec1


    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $557f

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $c27f
    push de
    ret


    ld c, a
    call z, $c9c4
    adc $c7
    ld a, a
    sub l
    ld a, a
    ld d, [hl]
    xor c
    call nc, $d387
    ld a, a
    add $c1
    ld d, l
    jp nc, $d47f

    rst $08
    ld a, a
    rst $00
    push bc
    call nc, $d77f
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ld a, a
    call nc, $c855
    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    ret


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    ld e, [hl]
    ld a, a
    ret


    call $d4c9
    pop bc
    call nc, $d3c5
    ld c, a
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    push de
    adc $c4
    ld d, l
    push bc
    jp nc, $d3c5

    call nc, $cdc9
    pop bc
    call nc, $cec9
    rst $00
    call z, $8ed9
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
    push de
    call nz, $c5c4
    adc $cc
    reti


    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, Jump_027_7f81

    and d
    reti


    ld a, a
    jp $c855


    pop bc
    adc $c3
    push bc
    ld a, a
    adc h
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_027_7fc5

    push bc
    sub $cf
    ld d, l
    call z, $d4d5
    push bc
    call nz, $ce7f
    rst $08
    call nc, $c9c8
    adc $c7
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_027_7f8c
    jp z, $d3d5

    call nc, $cf7f
    jp $c1c3


    db $d3
    ret


    ld c, a
    rst $08
    adc $c1
    call z, $d9cc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_027_7f8c
    jp z, $d3d5

    call nc, $cf7f
    jp $c1c3


    db $d3
    ret


    ld c, a
    rst $08
    adc $c1
    call z, $d9cc
    add c
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
    sub h
    ld a, a
    call $d3c9
    db $d3
    ret


    ld d, l
    call z, Call_027_7fc5
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, $81d3

    ld a, a
    ld d, a
    nop
    xor b
    add a
    call Call_027_7f8c
    adc $cf
    ld a, a
    ret nc

    jp nc, $c2cf

    call z, $cdc5
    add c
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
    jp nc, Jump_027_7f55

    rst $10
    ret


    call z, Call_027_7fcc
    jp nc, $d6c5

    push bc
    adc $c7
    push bc
    ld a, a
    add $cf
    jp nc, Jump_027_7f55

    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nz, $cfcc

    set 0, l
    add c
    ld a, a
    or a
    ld c, a
    push bc
    add a
    sub $c5
    ld a, a
    jp nz, $c5c5

    adc $7f
    call nc, $c9c1
    call z, $c4c5
    ld a, a
    ld d, l
    jp nz, Jump_027_7fd9

    ld e, [hl]
    rst $10
    ret z

    rst $08
    ld a, a
    rst $10
    pop bc
    db $d3
    ld d, l
    ld a, a
    call nz, $d3c5
    ret nc

    pop bc
    call nc, $c8c3
    push bc
    call nz, $c27f
    reti


    ld a, a
    call nc, Call_027_55c8
    push bc
    ld a, a
    jp nz, $c1d2

    adc $c3
    ret z

    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $d2c1
    ld d, l
    reti


    ld a, a
    rst $08
    add $7f
    and d
    rst $08
    adc $c9
    pop bc
    jp $c5c8


    sub $c3
    set 1, a
    ld d, l
    set 0, c
    db $d3
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
    jp nz, $c1d2

    adc $c3
    ret z

    ld a, a
    db $d3
    push bc
    jp $c5d2


    ld c, a
    call nc, $d2c1
    reti


    ld a, a
    rst $08
    add $7f
    and d
    rst $08
    adc $c9
    pop bc
    jp $c5c8


    sub $55
    jp $cfcb


    set 0, c
    db $d3
    add c
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    ld d, l
    or h
    ret z

    pop bc
    call nc, $d387
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call z, $cec1
    ld d, l
    call nz, $cf7f
    add $7f
    db $d3
    rst $08
    sub $c9
    push bc
    call nc, $b57f
    adc $c9
    rst $08
    adc $55
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    jp $cfc8


    rst $08
    call z, $c17f
    jp nc, $c1c5

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    jp $cfc8


    rst $08
    call z, $c17f
    jp nc, $c1c5

    add c
    ld a, a
    ld e, b
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
    jp nz, $d4c5

    jp nc, $d9c1

    push bc
    ld c, a
    call nz, Call_027_5e7f
    ld a, a
    adc [hl]
    ld a, a
    and h
    rst $08
    adc $87
    call nc, Call_027_7f55
    call nc, $c9c8
    adc $cb
    ld a, a
    pop bc
    call z, Call_027_7fcc
    ret


    db $d3
    ld a, a
    push bc
    adc $c4
    ld d, l
    push bc
    call nz, Call_027_7f81
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    jp nz, $d4c5

    jp nc, $d9c1

    ret


    adc $c7
    sbc a
    reti


    rst $08
    push de
    ld c, a
    add a
    call z, Call_027_7fcc
    jp nz, Jump_027_7fc5

    rst $08
    push de
    jp nc, $d47f

    jp nc, $c9c1

    call nc, Call_027_55cf
    jp nc, $c97f

    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_027_7fc5

    pop bc
    ld a, a
    add $d2
    ld d, l
    ret


    push bc
    adc $c4
    ld a, a
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    jp z, $d3d5

    call nc, $c955
    jp Jump_027_57c5


    nop
    ld a, a
    call nc, $c1d2
    ret


    call nc, $d2cf
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    call nc, $c1d2
    ret


    call nc, $d2cf
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, e
    ld a, a
    reti


    pop bc
    ret z

    adc h
    ld a, a
    ret z

    pop bc
    adc h
    ret z

    pop bc
    ld c, a
    add c
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c87f
    push bc
    jp nc, Jump_027_7fc5

    ld d, l
    adc [hl]
    ld a, a
    call $d9c1
    jp nz, Jump_027_7fc5

    adc $cf
    call nc, $c37f
    rst $08
    call Call_027_7fc5
    ld d, l
    xor c
    ld a, a
    call nc, $c9c8
    adc $cb
    ld a, a
    db $d3
    rst $08
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    ld e, [hl]
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    push bc
    call Call_027_55c2
    pop bc
    jp nc, $c1d2

    db $d3
    db $d3
    push bc
    call nz, $c27f
    push bc
    add $cf
    jp nc, Jump_027_7fc5

    ret z

    ld d, l
    ret


    db $d3
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    add c
    ld a, a
    xor b
    add a
    call Call_027_558c
    ld a, a
    ld d, [hl]
    xor c
    call nc, $c47f
    rst $08
    push bc
    db $d3
    adc $87
    call nc, $cd7f
    pop bc
    call nc, $d455
    push bc
    jp nc, $c67f

    rst $08
    jp nc, $d57f

    db $d3
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    rst $10
    pop bc
    call z, $c9cb
    adc $c7
    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c1cf

    call nz, $cf7f
    add $7f
    bit 2, l
    push bc
    jp nc, $c9d2

    pop bc
    ld a, a
    jp $d4c9


    reti


    adc [hl]
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    ld d, l
    push bc
    push bc
    adc $7f
    jp nz, Jump_027_7fd9

    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    push bc
    call z, $d355
    push bc
    adc [hl]
    ld a, a
    xor c
    add a
    call $d47f
    ret z

    ret


    adc $cb
    ret


    adc $c7
    ld a, a
    ld d, l
    rst $10
    ret z

    push bc
    call nc, $c5c8
    jp nc, Jump_027_7f7f

    pop bc
    adc $c4
    ld a, a
    ret


    call nc, Call_027_7fd3
    ld d, l
    pop bc
    call z, $cbc9
    push bc
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    rst $00
    rst $08
    call nc, $cd7f
    rst $08
    ld d, l
    jp nc, Jump_027_7fc5

    sub $c9
    rst $00
    rst $08
    jp nc, $d5cf

    db $d3
    ld a, a
    db $d3
    call z, $c7c9
    ret z

    ld d, l
    call nc, $d9cc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $81cc
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ld c, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    push de
    jp Jump_027_7fc8


    pop bc
    ld a, a
    call nc, $c9c8
    adc $c7
    ld a, a
    ld d, l
    pop bc
    db $d3
    ld a, a
    jp $c1c8


    call z, $c5cc
    adc $c7
    ret


    adc $c7
    ld a, a
    call nc, Call_027_55c8
    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld e, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld d, d
    add c
    ld a, a
    or a
    push bc
    ld a, a
    ld a, a
    ld c, a
    rst $00
    rst $08
    ld a, a
    add $c9
    jp nc, $d4d3

    call z, $81d9
    ld a, a
    reti


    rst $08
    push de
    add a
    call z, $cc55
    ld a, a
    rst $00
    jp nc, $c4c1

    push de
    pop bc
    call z, $d9cc
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d355

    call nc, $cec1
    call nz, $c87f
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $10
    ret z

    ld d, l
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret nc

    jp nc, $cdcf

    rst $08
    ld d, l
    call nc, $c4c5
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_027_7fc5
    jp Jump_027_55cf


    call $c9d0
    call z, $cec9
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    ret


    call z, $d5cc
    db $d3
    ld d, l
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
    ld a, a
    add c
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    rst $00
    push bc
    adc $c9
    push de
    ld d, l
    db $d3
    adc h
    ld a, a
    pop bc
    call $87ce
    call nc, $a97f
    sbc a
    ld a, a
    ld d, [hl]
    ld a, a
    and h
    rst $08
    ld d, l
    adc $87
    call nc, $d47f
    ret z

    ret


    adc $cb
    ld a, a
    db $d3
    rst $08
    ld a, a
    adc [hl]
    ld a, a
    and [hl]
    jp nc, $cf55

    call $ce7f
    rst $08
    rst $10
    ld a, a
    rst $08
    adc $7f
    adc h
    ld a, a
    call nz, $d7cf
    adc $7f
    ld d, l
    rst $10
    ret


    call nc, Call_027_7fc8
    pop bc
    call z, Call_027_7fcc
    call nc, $c5c8
    ld a, a
    and d
    push de
    call nz, Call_027_55c4
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

    call nc, $d455
    push bc
    adc $c4
    pop bc
    adc $d4
    db $d3
    ld a, a
    rst $08
    add $7f
    pop bc
    call z, $c9cc
    pop bc
    ld d, l
    adc $c3
    push bc
    ld a, a
    ld d, h
    add c
    ld a, a
    or h
    rst $08
    ld a, a
    jp nz, $c3c5

    rst $08
    call $c555
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    db $d3
    call nc, $557f
    ld e, l
    ld a, a
    add c
    ld a, a
    ld d, d
    ld a, a
    ld a, a
    ld d, l
    rst $10
    ret


    call z, Call_027_7fcc
    pop bc
    call z, $cfd3
    ld a, a
    call nz, Call_027_7fcf
    call nc, $c5c8
    ld a, a
    ld d, l
    jp nz, $d3c5

    call nc, $8e7f
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    adc h
    ld a, a
    jp nz, $c5d9

    ld d, l
    adc l
    jp nz, $c5d9

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    add c
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    add $cf
    push de
    adc $c4
    ld c, a
    ld a, a
    call $c3c9
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
    jp nc, Jump_027_7fc5

    call nc, $cfcf
    ld a, a
    db $d3
    call z, $d7cf
    ld c, a
    ld a, a
    call nc, Call_027_7fcf
    pop bc
    jp nc, $c9d2

    sub $c5
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld d, l
    ld a, a
    jp nz, $d3cf

    db $d3
    add a
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    jp $cecf


    db $d3
    push de
    call z, $c9d4
    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    ld c, a
    ret


    jp $d5d4


    jp nc, $8cc5

    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    jp $cecf


    db $d3
    push de
    call z, $c9d4
    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    ld c, a
    ret


    jp $d5d4


    jp nc, $8cc5

    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    pop bc
    db $d3
    pop bc
    add c
    ld a, a
    ld a, a
    pop bc
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    and h
    ld c, a
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    adc $cb
    ld a, a
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    pop bc
    ld a, a
    jp $c5cc


    jp nc, Jump_027_7fcb

    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    xor b
    ld d, l
    ret


    call z, $d5cc
    add $c6
    ld a, a
    and e
    rst $08
    call $c5cd
    jp nc, $c9c3

    pop bc
    call z, Call_027_7f55
    db $d3
    rst $08
    jp $c5c9


    call nc, Call_027_7fd9
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
    ret z

    push bc
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    jp nz, $d9cf

    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call nz, $c2c1
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    adc $87
    call nc, $c17f
    adc $d9
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    adc $87
    call nc, $c17f
    adc $d9
    ld a, a
    ld c, a
    ld d, h
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $ca7f
    push de
    db $d3
    call nc, $cf7f
    adc $c5
    ld a, a
    rst $08
    add $7f
    ld c, a
    call nc, $c5c8
    ld a, a
    add $cf
    push de
    jp nc, $cd7f

    ret


    db $d3
    db $d3
    ret


    call z, Call_027_7fc5
    ld d, l
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, $81d3

    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_027_7f8c
    rst $00
    rst $08
    rst $08
    call nz, Call_027_7f81
    xor l
    reti


    ld a, a
    push bc
    call z, $c44f
    push bc
    jp nc, $c27f

    jp nc, $d4cf

    ret z

    push bc
    jp nc, $cd7f

    pop bc
    reti


    ld a, a
    jp nc, $c555

    sub $c5
    adc $c7
    push bc
    ld a, a
    add $cf
    jp nc, $cd7f

    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_027_7f8c

    xor c
    add a
    sub $c5
    ld a, a
    call z, Call_027_4fcf
    db $d3
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_027_7f8c

    xor c
    add a
    sub $c5
    ld a, a
    call z, Call_027_4fcf
    db $d3
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_027_7fc5

    call nc, $c5c8
    ld a, a
    jp nz, $d9cf

    ld a, a
    ld c, a
    ld a, a
    ld d, [hl]
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    db $d3
    call z, $d0c9
    ret nc

    push bc
    call nz, $c97f
    ld d, l
    adc $d4
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    xor b
    ret


    call z, $d5cc
    add $c6
    adc h
    ld a, a
    ld d, l
    pop bc
    jp nc, $cec5

    add a
    call nc, $d97f
    rst $08
    push de
    sbc a
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
    jp nc, $c77f

    rst $08
    ld a, a
    ld c, a
    call nc, Call_027_7fcf
    db $d3
    call z, $c5c5
    ret nc

    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_027_7fc5

    call nc, $c855
    push bc
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    rst $00
    push bc
    call nc, Call_027_7fd3
    pop bc
    adc $c7
    jp nc, $d955

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    xor [hl]
    rst $08
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, $c67f
    jp nc, $cf4f

    call $c87f
    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call z, Call_027_7fcc
    jp $ccc1


    call z, $cd7f
    reti


    ld a, a
    ret nc

    pop bc
    jp nc, $d44f

    adc $c5
    jp nc, Jump_027_7fd3

    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    ld d, l
    call nc, $c37f
    rst $08
    call Call_027_7fc5
    jp nz, $c3c1

    bit 7, a
    ld a, a
    ld d, [hl]
    pop de
    push de
    ld d, l
    ret


    jp $cccb


    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c27f
    jp nc, $cec9

    rst $00
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c47f

    ld c, a
    jp nc, $d6c9

    push bc
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    add $d5
    call z, Call_027_7fcc
    ret nc

    call z, $c155
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c27f
    jp nc, $cec9

    rst $00
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c47f

    ld c, a
    jp nc, $d6c9

    push bc
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    add $d5
    call z, Call_027_7fcc
    ret nc

    call z, $c155
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    jp nz, $d2cf

    push bc
    call nz, $c97f
    call nc, $c97f
    db $d3
    adc [hl]
    ld c, a
    ld a, a
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    jp nz, $c5c5

    adc $7f
    call nz, $cecf
    push bc
    ld d, l
    ld a, a
    pop bc
    db $d3
    ld a, a
    call nz, $d3c5
    ret


    jp nc, $c2c1

    call z, Call_027_7fc5
    pop bc
    db $d3
    ld a, a
    ld d, l
    call nc, $c5c8
    reti


    ld a, a
    pop bc
    jp nc, Jump_027_7fc5

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c67f

    push bc
    push bc
    ld c, a
    call z, $cec9
    rst $00
    ld a, a
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $a87f
    ret


    call z, $d5cc
    ld d, l
    add $c6
    ld a, a
    jp nz, $c9d5

    call z, $c9c4
    adc $c7
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld d, l
    pop bc
    ld a, a
    call z, $c2c1
    reti


    jp nc, $cec9

    call nc, Call_027_7fc8
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f9f
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    call z, $d3cf
    call nc, Call_027_7f9f
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $ca7f
    push de
    db $d3
    call nc, $cf7f
    adc $c5
    ld a, a
    rst $08
    add $7f
    ld c, a
    call nc, $c5c8
    ld a, a
    add $cf
    push de
    jp nc, $cd7f

    ret


    db $d3
    db $d3
    ret


    call z, Call_027_7fc5
    ld d, l
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, $81d3

    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_027_7f8c
    reti


    push bc
    db $d3
    adc h
    ld a, a
    rst $08
    add $7f
    jp $d5cf


    ld c, a
    jp nc, $c5d3

    add c
    ld a, a
    and d
    jp nc, $d4cf

    ret z

    push bc
    jp nc, $cd7f

    pop bc
    reti


    ld a, a
    ld d, l
    jp nc, $d6c5

    push bc
    adc $c7
    push bc
    ld a, a
    add $cf
    jp nc, $cd7f

    push bc
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_027_7f8c

    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_027_7f8c

    call z, $d3cf
    call nc, Call_027_7f81
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    call nz, $c1c9
    jp nc, Jump_027_7fd9

    rst $08
    adc $7f
    xor d
    push de
    call z, Call_027_7fd9
    ld c, a
    sub l
    adc h
    ld a, a
    xor b
    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    ld a, a
    and c
    adc $ca
    ret


    adc $c1
    ld d, l
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    call nc, Call_027_7fc8
    and c
    call Call_027_55c5
    jp nc, $c3c9

    pop bc
    ld a, a
    adc h
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ret z

    pop bc
    sub $c5
    ld d, l
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    adc $c5
    rst $10
    ld a, a
    ld d, h
    ld a, a
    ret


    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $cec1
    call nz, $cf7f
    add $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    call nc, $cfd2
    ret nc

    ret


    jp $ccc1


    ld a, a
    add $cf
    jp nc, $d3c5

    call nc, $8ed3
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    call nz, $c1c9
    jp nc, Jump_027_7fd9

    rst $08
    adc $7f
    xor d
    push de
    call z, Call_027_7fd9
    ld c, a
    sub c
    sub b
    ld a, a
    xor c
    ld a, a
    adc $c1
    call Call_027_7fc5
    call nc, $c5c8
    ld a, a
    adc $c5
    rst $10
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor l
    ret


    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_027_7fc5

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
    jp Jump_027_7fc5


    adc [hl]
    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    ld d, l
    pop bc
    call nz, $c47f
    ret


    add $c6
    ret


    jp $ccd5


    call nc, $d9cc
    add c
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
    push bc
    jp $c5d2


    call nc, Call_027_7f4f
    jp nz, $d4cf

    call nc, $cecf
    ld a, a
    call nc, $cfd7
    ld a, a
    call nz, $cfcf
    jp nc, Jump_027_55d3

    ld a, a
    ld a, a
    call $d9c1
    ld a, a
    rst $08
    ret nc

    push bc
    adc $7f
    pop bc
    call z, $c5d4
    jp nc, Jump_027_55ce

    pop bc
    call nc, $ccc5
    reti


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
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    jp nc, $d0c1

    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    reti


    add c
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    jp nc, $d0c1

    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    call nz, $c1c9
    jp nc, Jump_027_7fd9

    rst $08
    adc $7f
    and [hl]
    push bc
    jp nz, $968e

    ld c, a
    ld a, a
    xor l
    ret


    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $00
    ret


    sub $c5
    adc $7f
    pop bc
    ld a, a
    jp nz, $c955

    jp nc, $c8d4

    ld a, a
    xor [hl]
    push bc
    rst $10
    ld a, a
    jp nz, $d2cf

    adc $7f
    jp nz, $c2c1

    ld d, l
    reti


    ld a, a
    ld a, a
    adc $c1
    call $c4c5
    ld a, a
    xor l
    ret


    jp Jump_027_7fc8


    ld d, [hl]
    ld a, a
    ld d, l
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
    sub $c5
    jp nc, Jump_027_7fd9

    jp nz, $c94f

    rst $00
    ld a, a
    ret z

    rst $08
    push de
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    or a
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ret z

    pop bc
    db $d3
    ld a, a
    ld a, a
    rst $00
    rst $08
    adc $4f
    push bc
    ld a, a
    rst $10
    ret


    call nc, Call_027_7fc8
    ret z

    ret


    db $d3
    ld a, a
    ret nc

    pop bc
    jp nc, $ced4

    push bc
    ld d, l
    jp nc, $9fd3

    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $d5c8
    adc $c4
    push bc
    jp nc, $81d3

    ld a, a
    ld e, b
    nop
    ld a, a
    call nc, $d5c8
    adc $c4
    push bc
    jp nc, $81d3

    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_027_7fc5

    call z, $d6c9
    push bc
    call nz, $cf7f
    push de
    jp nc, $d47f

    ld c, a
    push bc
    pop bc
    jp $c5c8


    jp nc, $cc7f

    ret


    sub $c5
    call nz, Call_027_7f8e
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ld c, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ret


    db $d3
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    ld d, l
    reti


    ld a, a
    pop bc
    adc $d8
    ret


    rst $08
    push de
    db $d3
    adc [hl]
    ld a, a
    ld d, [hl]
    xor d
    push de
    call Call_027_55d0
    ld a, a
    call nz, $d7cf
    adc $7f
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ld d, l
    ld a, a
    add $c9
    jp nc, $cccd

    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    call nz, $c1c9
    jp nc, Jump_027_7fd9

    rst $08
    adc $7f
    db $d3
    push bc
    ret nc

    call nc, $4f8e
    ld a, a
    sub c
    ld a, a
    ld d, h
    ld a, a
    xor l
    ret


    jp Jump_027_7fc8


    ret


    db $d3
    ld a, a
    call nc, Call_027_55cf
    rst $08
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    add c
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    ld d, l
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld d, [hl]
    xor c
    ld a, a
    jp $cec1


    ld a, a
    adc $cf
    call nc, Call_027_7f55
    call nz, $c1c5
    call z, $d77f
    ret


    call nc, Call_027_7fc8
    ret


    call nc, Call_027_7f81
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call Call_027_4fc5
    db $d3
    db $d3
    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    call z, $d3cf
    call nc, $cd7f
    reti


    ld a, a
    ld d, l
    rst $10
    pop bc
    reti


    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $cec1
    ld a, a
    ld a, a
    call z, $d6c9
    ret


    adc $c7
    ld a, a
    ld c, a
    call nc, $c5c8
    ld a, a
    add $d2
    rst $08
    adc $d4
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    add $d2
    rst $08
    ld d, l
    ret nc

    ret nc

    push bc
    call nz, $cd7f
    pop bc
    adc $d9
    ld a, a
    ret nc

    jp nc, $d0cf

    db $d3
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    call nc, $d5c8
    adc $c4
    push bc
    jp nc, $81d3

    ld a, a
    ld e, b
    nop
    ld a, a
    call nc, $d5c8
    adc $c4
    push bc
    jp nc, $81d3

    ld a, a
    ld e, b
    nop
    xor b
    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $d07f
    call z, $c14f
    jp Jump_027_7fc5


    add $cf
    jp nc, $cf7f

    push de
    jp nc, $d37f

    call nc, $c4d5
    reti


    ld d, l
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    sub $c5
    jp nc, Jump_027_7fd9

    call z, $d2c1
    rst $00
    push bc
    ld a, a
    ld d, l
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or [hl]
    push bc
    jp nc, Jump_027_7fd9

    call nz, $d3c5
    ret


    jp nc, $c4c5

    add c
    ld a, a
    or h
    ret z

    ld c, a
    push bc
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    rst $10
    ret


    call z, Call_027_7fcc
    rst $00
    rst $08
    ld a, a
    db $d3
    ld d, l
    call $cfcf
    call nc, $ccc8
    reti


    ld a, a
    ld d, [hl]
    ld a, a
    ret


    add $7f
    call z, $d6c9
    ld d, l
    ret


    adc $c7
    ld a, a
    ret z

    push bc
    jp nc, $8ec5

    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    jp nc, Jump_027_7fc5

    reti


    rst $08
    push de
    ld a, a
    call nz, $c9cf
    ld c, a
    adc $c7
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    jp nc, Jump_027_7fc5

    reti


    rst $08
    push de
    ld a, a
    call nz, $c9cf
    ld c, a
    adc $c7
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    pop bc
    jp $c9c8


    jp Jump_027_7f7f


    or a
    push bc
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, $c44f
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_027_7fcf
    jp $d4c1


    jp Jump_027_7fc8


    ld d, l
    ld d, h
    jp nz, $d4d5

    ld a, a
    rst $10
    ret z

    push bc
    jp nc, Jump_027_7fc5

    ret


    db $d3
    ld a, a
    xor e
    ld d, l
    push bc
    jp nc, $c5ca

    push bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    call z, Call_027_7fcc
    jp nc, $c7c9

    ret z

    call nc, Call_027_7f81
    call nc, Call_027_7fcf
    jp Jump_027_4fc1


    call nc, $c8c3
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ld d, h
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ld d, l
    rst $00
    ret


    add $d4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    call $d9c1
    ld a, a
    push bc
    db $d3
    jp $d0c1


    push bc
    ld a, a
    ret


    add $7f
    jp nc, $d54f

    adc $ce
    ret


    adc $c7
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld d, l
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    pop bc
    db $d3
    ret


    push bc
    jp nc, $d47f

    ld d, l
    rst $08
    ld a, a
    jp $d4c1


    jp $81c8


    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $c54f
    jp nc, $c97f

    adc $7f
    rst $00
    push bc
    adc $c5
    jp nc, $ccc1

    adc h
    ld a, a
    jp Jump_027_55c1


    adc $7f
    adc $cf
    call nc, $c67f
    call z, $c5c5
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
    jp nz, $c9c1

    call nc, $d47f
    ld d, l
    rst $08
    ld a, a
    ret z

    ret


    call $d77f
    ret z

    push bc
    adc $7f
    ld a, a
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    push bc
    pop bc
    rst $00
    push bc
    jp nc, Jump_027_7f7f

    call nc, Call_027_7fcf
    push bc
    pop bc
    call nc, $cec9
    rst $00
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    add a
    sub $c5
    ld a, a
    db $d3
    ret nc

    push bc
    adc $d4
    ld a, a
    pop bc
    ld a, a
    call z, Call_027_4fcf
    call nc, $cf7f
    add $7f
    call nc, $cdc9
    push bc
    ld a, a
    jp nz, $d4d5

    ld a, a
    or h
    ret z

    push bc
    ld d, l
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    ld a, a
    rst $10
    ld d, l
    push bc
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    call nz, $c5cf
    ld d, l
    db $d3
    ld a, a
    adc $cf
    call nc, $c17f
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_027_7f81

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

Call_027_7f4f:
Jump_027_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_027_7f55:
Jump_027_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_027_7f7f:
Jump_027_7f7f:
    nop
    nop

Call_027_7f81:
Jump_027_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_027_7f8c:
Jump_027_7f8c:
    nop
    nop

Call_027_7f8e:
Jump_027_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_027_7f9f:
Jump_027_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_027_7fc2:
    nop
    nop

Call_027_7fc4:
Jump_027_7fc4:
    nop

Call_027_7fc5:
Jump_027_7fc5:
    nop
    nop
    nop

Call_027_7fc8:
Jump_027_7fc8:
    nop
    nop
    nop

Jump_027_7fcb:
    nop

Call_027_7fcc:
Jump_027_7fcc:
    nop
    nop

Jump_027_7fce:
    nop

Call_027_7fcf:
    nop
    nop
    nop
    nop

Call_027_7fd3:
Jump_027_7fd3:
    nop

Call_027_7fd4:
Jump_027_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_027_7fd9:
Jump_027_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
