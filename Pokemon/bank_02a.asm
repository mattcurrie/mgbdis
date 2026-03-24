; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $02a", ROMX[$4000], BANK[$2a]

    nop
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    rst $10
    ret z

    ret


    jp $9fc8


    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    ld d, a
    or a
    rst $08
    push de
    call z, Call_02a_7fc4
    reti


    rst $08
    push de
    ld c, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, Call_02a_7fcf
    rst $00
    ret


    sub $c5
    ld a, a
    call Call_02a_7fc5
    ld d, l
    pop bc
    ld a, a
    call $d8c5
    push bc
    call nz, $c67f
    jp nc, $c9d5

    call nc, $ca7f
    push de
    ret


    ld d, l
    jp $9fc5


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
    jp nc, Jump_02a_557f

    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    db $d3
    ret nc

    ret


    call nc, $ccc1
    ret


    call nc, $d9d9
    rst $08
    ld d, l
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    adc $7f
    push de
    db $d3
    add c
    and a
    ld d, l
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call Call_02a_7fd9
    call nc, $c5d2
    pop bc
    db $d3
    push de
    ld d, l
    jp nc, $d4c5

    rst $08
    ld a, a
    push bc
    ret c

    ret nc

    jp nc, $d3c5

    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $d455

    add $c5
    call z, Call_02a_7fd4
    call nc, $c1c8
    adc $cb
    db $d3
    add c
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02a_4f7f
    ld e, h
    sub h
    sbc c
    ld a, a
    add $55
    jp nc, $cdcf

    call nc, $c5c8
    ld a, a
    rst $00
    ret


    jp nc, $87cc

    ld a, a
    ret z

    pop bc
    adc $c4
    ld d, l
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    ld a, a
    ret


    adc $7f
    ld d, l
    ld e, h
    sub h
    sbc c
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    pop bc
    ld a, a
    call nc, $c9d2
    pop bc
    call z, $c37f
    rst $08
    push de
    adc $d4
    push bc
    jp nc, $c155

    call nc, $c1d4
    jp $81cb


    xor a
    jp $c1c3


    call nc, $cfc9
    adc $c1
    call z, $cc55
    reti


    adc h
    ld a, a
    call nc, $c5c8
    jp nc, Jump_02a_7fc5

    push bc
    ret c

    ret


    db $d3
    call nc, Call_02a_7fd3
    ld d, l
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    call nc, Call_02a_7fcf
    ret nc

    pop bc
    jp nc, $ccc1

    ld d, l
    reti


    db $d3
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    ld d, l
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    adc [hl]
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
    call Call_02a_7fc5
    pop bc
    ld a, a
    jp $d0d5


    ld a, a
    rst $08
    add $7f
    ld d, l
    db $d3
    rst $08
    call nz, Call_02a_7fc1
    call nz, $c9d2
    adc $cb
    sbc a
    ld a, a
    or h
    ret z

    pop bc
    adc $cb
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    push de
    jp nc, $c87f

    rst $08
    db $d3
    ld d, l
    ret nc

    ret


    call nc, $ccc1
    ret


    call nc, $81d9
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    call Call_02a_7fd9
    call nc, $c5d2
    pop bc
    db $d3
    push de
    jp nc, Jump_02a_7fc5

    call nc, Call_02a_7fcf
    ld d, l
    push bc
    ret c

    ret nc

    jp nc, $d3c5

    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $c6d4

    push bc
    call z, Call_02a_55d4
    ld a, a
    call nc, $c1c8
    adc $cb
    db $d3
    add c
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02a_4f7f
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

    ld a, a
    ret z

    pop bc
    ld d, l
    adc $c4
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    xor c
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $c3cf

    set 0, e
    rst $08
    call z, $c1cc
    ld d, l
    ret nc

    db $d3
    push bc
    add c
    xor a
    jp $c1c3


    call nc, $cfc9
    adc $c1
    call z, $d9cc
    adc h
    ld d, l
    ld a, a
    call nc, $c5c8
    jp nc, Jump_02a_7fc5

    push bc
    ret c

    ret


    db $d3
    call nc, Call_02a_7fd3
    db $d3
    rst $08
    call $c555
    call nc, $c9c8
    adc $c7
    ld a, a
    call nc, Call_02a_7fcf
    call z, $d4c5
    ld a, a
    rst $08
    ret nc

    ret nc

    ld d, l
    rst $08
    adc $c5
    adc $d4
    ld a, a
    add $c5
    push bc
    call z, $c17f
    adc $c7
    jp nc, $81d9

    ld d, l
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    or a
    pop bc
    ret z

    add c
    ld a, a
    ld a, a
    and e
    pop bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    call $4fc5
    ld a, a
    pop bc
    ld a, a
    jp $d0d5


    ld a, a
    rst $08
    add $7f
    rst $10
    pop bc
    call nc, $d2c5
    sbc a
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
    add $cf
    jp nc, $d97f

    rst $08
    push de
    jp nc, Jump_02a_7f55

    ret z

    rst $08
    db $d3
    ret nc

    ret


    call nc, $ccc1
    ret


    call nc, $81d9
    and a
    ret


    sub $c5
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call Call_02a_7fd9
    call nc, $c5d2
    pop bc
    db $d3
    push de
    jp nc, $d4c5

    ld d, l
    rst $08
    ld a, a
    push bc
    ret c

    ret nc

    jp nc, $d3c5

    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $c6d4

    push bc
    ld d, l
    call z, Call_02a_7fd4
    call nc, $c1c8
    adc $cb
    db $d3
    add c
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02a_4f7f
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

    ld a, a
    ret z

    pop bc
    ld d, l
    adc $c4
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    xor c
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    add $d2
    push bc
    push bc
    jp c, $cec9

    rst $00
    adc [hl]
    xor a
    jp $c1c3


    ld d, l
    call nc, $cfc9
    adc $c1
    call z, $d9cc
    adc h
    ld a, a
    call nc, $c5c8
    jp nc, Jump_02a_7fc5

    push bc
    ld d, l
    ret c

    ret


    db $d3
    call nc, Call_02a_7fd3
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    ld a, a
    ld d, l
    call nc, Call_02a_7fcf
    add $d2
    push bc
    push bc
    jp c, Jump_02a_7fc5

    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    ld d, l
    rst $08
    adc $c5
    adc $d4
    ld a, a
    adc [hl]
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
    xor b
    add a
    call Call_02a_7f81
    xor b
    pop bc
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, Jump_02a_4f7f

    call nc, $cccf
    push bc
    jp nc, $d4c1

    push bc
    ld a, a
    pop bc
    ld a, a
    rst $10
    ret z

    ret


    call z, $81c5
    ld d, l
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    xor b
    add a
    call Call_02a_567f
    add c
    and d
    jp nc, $d4cf

    ret z

    push bc
    jp nc, $a981

    ld c, a
    add a
    call nz, $cc7f
    ret


    set 0, l
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    rst $08
    call Call_02a_55c5
    ld a, a
    add $d2
    push de
    ret


    call nc, $ca7f
    push de
    ret


    jp $81c5


    or a
    rst $08
    push de
    call z, $c455
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $cec9
    call nz, $c77f
    ret


    sub $c9
    adc $c7
    ld d, l
    ld a, a
    call Call_02a_7fc5
    db $d3
    rst $08
    call $9fc5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_02a_567f
    add c
    ld a, a
    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, $814f

    xor c
    add a
    call nz, $cc7f
    ret


    set 0, l
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    rst $08
    ld d, l
    call Call_02a_7fc5
    add $d2
    push de
    ret


    call nc, $ca7f
    push de
    ret


    jp $81c5


    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    sbc a
    xor c
    add a
    call $c17f
    ld a, a
    ret nc

    call z, $d9c1
    rst $00
    pop bc
    ld c, a
    call Call_02a_7fc5
    call nz, $d3c5
    ret


    rst $00
    adc $c5
    jp nc, $a181

    call z, Call_02a_7fcc
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
    jp nc, Jump_02a_7fc5

    jp $cccf


    ld d, l
    call z, $c3c5
    call nc, $c4c5
    add c
    ld a, a
    and e
    rst $08
    call Call_02a_7fc5
    rst $08
    adc $7f
    call nc, $c855
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    push bc
    pop bc
    db $d3
    reti


    ld d, l
    add c
    ld a, a
    or h
    push bc
    call z, Call_02a_7fcc
    call Call_02a_7fc5
    ret


    add $7f
    reti


    rst $08
    push de
    add a
    ld d, l
    sub $c5
    ld a, a
    jp $cccf


    call z, $c3c5
    call nc, $c4c5
    ld a, a
    pop bc
    call z, Call_02a_7fcc
    ld d, l
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
    adc h
    ld a, a
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    ld c, a
    adc $c1
    jp nc, $81d9

    ld a, a
    and c
    call z, Call_02a_7fcc
    call nc, $c5c8
    ld a, a
    ret nc

    pop bc
    rst $00
    ld d, l
    push bc
    db $d3
    ld a, a
    ld a, a
    rst $08
    add $7f
    ret


    call z, $d5cc
    db $d3
    call nc, $c1d2
    call nc, Call_02a_55c5
    call nz, $c87f
    pop bc
    adc $c4
    jp nz, $cfcf

    bit 7, a
    ld d, h
    ld a, a
    add $c9
    ld d, l
    adc $c1
    call z, $d9cc
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    jp nz, $c5c5

    adc $7f
    jp $cf55


    call z, $c5cc
    jp $c5d4


    call nz, Call_02a_7f81
    and e
    rst $08
    adc $c7
    jp nc, $d4c1

    ld d, l
    push de
    call z, $d4c1
    push bc
    ld a, a
    reti


    rst $08
    push de
    add c
    ld d, [hl]
    ld d, [hl]
    ld d, b
    ld b, $00
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    and c
    jp nc, Jump_02a_7fc5

    reti


    rst $08
    push de
    ld a, a
    jp $4fcf


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
    adc h
    pop bc
    jp nc, $cec5

    add a
    call nc, $d97f
    rst $08
    push de
    sbc a
    ld a, a
    ld a, a
    ld d, l
    and l
    ret c

    call nc, $c5d2
    call $ccc5
    reti


    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, Call_02a_55c5
    adc $d4
    add c
    xor c
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    db $d3
    rst $08
    ld d, l
    call Call_02a_7fc5
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    call z, $c6c9
    ld a, a
    xor c
    call nc, $8755
    db $d3
    ld a, a
    call Call_02a_7fc5
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
    xor b
    rst $08
    rst $10
    ld a, a
    adc $c9
    jp Jump_02a_7fc5


    ld c, a
    call nc, $c5c8
    ld a, a
    rst $10
    push bc
    pop bc
    call nc, $c5c8
    jp nc, Jump_02a_7f81

    call nc, $cfcf
    ld a, a
    ld d, l
    jp $cdcf


    add $cf
    jp nc, $c1d4

    jp nz, $c5cc

    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    db $d3
    ret


    adc [hl]
    jp nz, $c5d2

    pop bc
    call nc, $c5c8
    ld a, a
    ld d, l
    ld d, [hl]
    adc [hl]
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, Call_02a_557f
    call nz, Call_02a_7fcf
    adc [hl]
    ld a, a
    xor c
    call nc, $c57f
    sub $c5
    adc $7f
    rst $00
    rst $08
    call nc, Call_02a_557f
    db $d3
    call z, $c5c5
    ret nc

    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    or a
    push bc
    call z, $cfc3
    call Call_02a_55c5
    add c
    ld a, a
    xor c
    add a
    call $a17f
    call z, $c9cc
    jp Jump_02a_7fc1


    add $d2
    rst $08
    call Call_02a_7f55
    call nc, $c5c8
    ld a, a
    rst $00
    reti


    call $cf7f
    add $7f
    call z, $c7c9
    ret z

    call nc, $ce55
    ret


    adc $c7
    ld a, a
    jp $d4c9


    reti


    adc [hl]
    ld a, a
    xor c
    add a
    call $c97f
    adc $55
    call nc, $d2c5
    push bc
    db $d3
    call nc, $c4c5
    ld a, a
    ret


    adc $7f
    jp $d4d5


    call nc, Call_02a_55c9
    adc $c7
    ld a, a
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, $8ed3

    ld a, a
    ld d, h
    adc h
    ld a, a
    ld d, l
    and c
    call z, Call_02a_7fcc
    pop bc
    jp nc, Jump_02a_7fc5

    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    call nc, $d0d9
    ld d, l
    push bc
    adc [hl]
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    ret


    add c
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
    db $d3
    ld a, a
    ret


    call nc, $c17f
    adc $7f
    pop bc
    ret nc

    ret nc

    call z, $c955
    jp $d4c1


    ret


    rst $08
    adc $9f
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    ld a, a
    adc [hl]
    ld d, l
    xor c
    add a
    call z, Call_02a_7fcc
    adc $c5
    sub $c5
    jp nc, $cc7f

    rst $08
    db $d3
    db $d3
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $cfc3
    call $81c5
    ld a, a
    xor b
    push bc
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld c, a
    ld a, a
    call $d3c9
    db $d3
    ret


    call z, Call_02a_7fc5
    rst $00
    pop bc
    call $81c5
    ld a, a
    and h
    rst $08
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nz, $d9d5

    ld a, a
    ret nc

    call z, $d9c1
    jp $c9cf


    adc $55
    sbc a
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp $c9cf


    adc $7f
    ld d, l
    add $cf
    jp nc, $c77f

    pop bc
    call $9fc5
    ld a, a
    sub c
    sub b
    sub b
    sub b
    add h
    ld a, a
    jp $c155


    adc $7f
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    sub l
    sub b
    jp $c9cf


    adc $55
    db $d3
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
    call nc, $c57f
    adc $cf
    push de
    rst $00
    ld c, a
    ret z

    ld a, a
    call $cecf
    push bc
    reti


    add c
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
    jp nc, $d97f

    rst $08
    push de
    jp nc, Jump_02a_4f7f

    jp $d2c1


    push bc
    ld a, a
    push bc
    sub $c5
    jp nc, Jump_02a_7fd9

    call nc, $cdc9
    push bc
    add c
    ld a, a
    ld d, l
    sub l
    sub b
    jp $c9cf


    adc $d3
    adc h
    ld a, a
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
    ld d, [hl]
    adc h
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $ce7f
    push bc
    push bc
    call nz, $c97f
    ld c, a
    call nc, Call_02a_7f9f
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
    ld d, l
    ret


    adc $8c
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
    and c
    ret z

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    jp $c9cf


    adc $c2
    rst $08
    ret c

    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    add $d5
    call z, $81cc
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    sbc a
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    jp $c9cf


    adc $c2
    rst $08
    ret c

    ld a, a
    ret z

    ld c, a
    push bc
    jp nc, Jump_02a_7fc5

    add c
    ld a, a
    ld d, a
    nop
    xor h
    ret


    call nc, $ccd4
    push bc
    ld a, a
    jp nz, $d9cf

    ld a, a
    add c
    and h
    rst $08
    ld a, a
    reti


    rst $08
    ld c, a
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ret nc

    call z, $d9c1
    ret


    adc $c7
    ld a, a
    call nc, Call_02a_55c8
    push bc
    ld a, a
    rst $00
    pop bc
    call $9fc5
    ld a, a
    ld e, b
    nop
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, $917f
    sub b
    ld c, a
    ld a, a
    jp $c9cf


    adc $d3
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    rst $00
    jp nc, $c155

    adc $c4
    ret nc

    pop bc
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    or a
    ret


    adc $7f
    pop bc
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    rst $10
    ret z

    push bc
    ld c, a
    adc $7f
    xor c
    ld a, a
    rst $10
    ret


    adc $8c
    jp nz, $d4d5

    ld a, a
    ld a, a
    call z, $d3cf
    push bc
    ld d, l
    ld a, a
    call $c3d5
    ret z

    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    xor c
    ld a, a
    call z, $d3cf
    push bc
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $ce7f

    rst $08
    call nc, $d07f
    ld c, a
    call z, $d9c1
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    push de
    adc $c6
    rst $08
    jp nc, $d5d4

    adc $c1
    call nc, $ccc5
    reti


    add c
    ld a, a
    xor [hl]
    ld c, a
    rst $08
    call nc, $c27f
    jp nc, $cec9

    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c9cf


    adc $55
    jp nz, $d8cf

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    pop bc
    jp nc, Jump_02a_7fc5

    rst $00
    rst $08
    rst $08
    call nz, Call_02a_4f7f
    ld d, h
    pop bc
    call $cecf
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $dac9

    ld d, l
    push bc
    db $d3
    adc [hl]
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    jp nz, $d3c5

    call nc, Call_02a_7f8e
    jp nz, $d4d5

    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    jp $cdcf


    ret nc

    call z, $d4c5
    push bc
    call z, Call_02a_7fd9
    push de
    adc $c6
    push bc
    pop bc
    db $d3
    ld d, l
    ret


    jp nz, $c5cc

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
    call nc, Call_02a_7f9f
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    ld c, a
    push de
    ld a, a
    db $d3
    rst $08
    call Call_02a_7fc5
    jp $c9cf


    adc $d3
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
    call nz, $927f
    ld c, a
    sub b
    jp $c9cf


    adc $d3
    ld a, a
    add $d2
    rst $08
    call $c27f
    jp nc, $d4cf

    ret z

    ld d, l
    push bc
    jp nc, $817f

    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    adc h
    ld a, a
    adc $cf
    call nc, $c37f
    rst $08
    call Call_02a_7fc5
    ld c, a
    pop bc
    call nc, $c17f
    call z, $81cc
    ld a, a
    jp nz, $d4d5

    adc h
    ld a, a
    ret z

    push bc
    jp nc, Jump_02a_55c5

    ld a, a
    pop bc
    jp nc, Jump_02a_7fc5

    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    ld a, a
    xor c
    ld a, a
    ld d, l
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02a_7fcf
    rst $00
    push bc
    call nc, Call_02a_7f81
    ld d, a
    nop
    ld a, a
    and d
    jp nc, $cec9

    rst $00
    ld a, a
    call nc, $cfcf
    ld a, a
    call $cec1
    reti


    add c
    ld a, a
    ld c, a
    ld d, a
    nop
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call $d3c5
    db $d3
    add c
    xor [hl]
    rst $08
    call nc, $c27f
    ld c, a
    jp nc, $cec9

    rst $00
    ld a, a
    jp $c9cf


    adc $c2
    rst $08
    ret c

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $cec9
    push de
    call nc, $81c5
    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_02a_7fc5

    ret


    adc $7f
    call Call_02a_7fd9
    ld d, l
    rst $10
    pop bc
    reti


    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $c9cf


    adc $55
    db $d3
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    adc $7f
    rst $00
    rst $08
    ld a, a
    pop bc
    rst $10
    ld d, l
    pop bc
    reti


    adc [hl]
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
    call nz, $927f
    ld c, a
    sub b
    ld a, a
    jp $c9cf


    adc $d3
    ld a, a
    add $d2
    rst $08
    call $c17f
    adc $c3
    call z, $c555
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    and e
    pop bc
    jp nc, $c6c5

    push de
    call z, $d9cc
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    ld c, a
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret nc

    ret


    jp $d5d4


    jp nc, Jump_02a_7fc5

    rst $08
    add $7f
    ld d, l
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    adc [hl]
    ld a, a
    or b
    jp nc, $d3c5

    db $d3
    ret


    adc $55
    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d4cf

    call nc, $cecf
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld d, l
    ld a, a
    set 1, [hl]
    pop bc
    jp $81cb


    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    push bc
    ret c

    ret


    db $d3
    call nc, $d47f
    rst $08
    rst $08
    ld a, a
    ld c, a
    call $cec1
    reti


    ld a, a
    jp $c9cf


    adc $d3
    adc h
    ld a, a
    pop bc
    jp nc, $cec5

    add a
    ld d, l
    call nc, $d47f
    ret z

    push bc
    jp nc, $9fc5

    ld a, a
    ld d, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call $d3c5
    db $d3
    add c
    ld a, a
    xor [hl]
    rst $08
    call nc, Call_02a_4f7f
    jp nz, $c9d2

    adc $c7
    ld a, a
    jp $c9cf


    adc $c2
    rst $08
    ret c

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    ld a, a
    pop bc
    call $d77f
    pop bc
    call nc, $c8c3
    ret


    adc $c7
    ld a, a
    call nc, $c84f
    ret


    db $d3
    ld a, a
    ret nc

    rst $08
    db $d3
    call nc, $d2c5
    add c
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    ret z

    ret


    adc $c4
    push bc
    jp nc, $cd7f

    push bc
    xor c
    add a
    call z, Call_02a_7fcc
    call z, $c555
    call nc, $d97f
    rst $08
    push de
    ld a, a
    call nc, Call_02a_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    call nc, $55cf
    ld a, a
    ret nc

    pop bc
    reti


    ld a, a
    add $cf
    jp nc, $c97f

    call nc, Call_02a_7f81
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    xor h
    pop bc
    push de
    rst $00
    ret z

    push bc
    jp nc, $c581

    ld c, a
    sub $c5
    adc $7f
    pop bc
    ld a, a
    db $d3
    ret


    adc $c7
    call z, Call_02a_7fc5
    jp $cec5


    call nc, Call_02a_7f55
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $d27f
    push bc
    call $c9c1
    adc $c9
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    call nc, $c17f
    add $d4
    push bc
    jp nc, Jump_02a_7f55

    ret nc

    call z, $d9c1
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    pop bc
    call Call_02a_55c5
    ld a, a
    add c
    xor [hl]
    push bc
    sub $c5
    jp nc, $d07f

    call z, $d9c1
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    call nz, $cfd2
    ret nc

    adc l
    jp $c9cf


    adc $7f
    rst $00
    pop bc
    call $81c5
    and [hl]
    or d
    ld d, l
    rst $08
    call $ce7f
    rst $08
    rst $10
    ld a, a
    rst $08
    adc $8c
    ld a, a
    rst $10
    rst $08
    jp nc, Jump_02a_7fcb

    ret z

    ld d, l
    pop bc
    jp nc, $81c4

    ld a, a
    ld d, [hl]
    adc h
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
    call nc, $c9c8
    db $d3
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
    call nz, Call_02a_4f7f
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
    call z, Call_02a_7fc4
    call $cec1
    ld a, a
    ld d, l
    add c
    ld a, a
    ld d, b
    ld de, $7f00
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
    adc [hl]
    ld a, a
    xor c
    add a
    call z, Call_02a_7fcc
    jp $d2c5


    call nc, Call_02a_4fc1
    ret


    adc $cc
    reti


    ld a, a
    rst $10
    ret


    adc $7f
    adc $c5
    ret c

    call nc, $d47f
    ret


    call $c555
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $a97f
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    call nc, Call_02a_7f55
    ret


    db $d3
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $a97f
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    ld d, l
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    adc $c3
    call z, $9ac5
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, $d9cf

    ld c, a
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    call nc, $ccc5
    call z, $d97f
    rst $08
    push de
    adc h
    ld a, a
    ld d, l
    ld d, [hl]
    add c
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    ld d, l
    rst $08
    call nz, $ce7f
    push bc
    rst $10
    db $d3
    ld a, a
    adc [hl]
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, Call_02a_557f
    jp $d2c1


    ret nc

    ld a, a
    ld a, a
    push bc
    sub $c5
    adc $7f
    rst $08
    adc $cc
    reti


    ld a, a
    call $c155
    jp nc, Jump_02a_7fcb

    sub l
    sub b
    sub b
    add h
    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    call nz, Call_02a_7fcf
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    adc $cb
    sbc a
    ld a, a
    jp nz, $d9d5

    ld a, a
    ret


    call nc, $9f55
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    adc $c5
    reti


    ld a, a
    db $d3
    push bc
    push bc
    call Call_02a_7fd3
    adc $cf
    call nc, Call_02a_4f7f
    push bc
    adc $cf
    push de
    rst $00
    ret z

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    push bc
    pop bc
    call z, $d9cc
    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    ret nc

    ld c, a
    ret


    call nc, $81d9
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    adc $c3
    call z, $9ac5
    reti


    push bc
    db $d3
    adc h
    reti


    push bc
    db $d3
    add c
    ld a, a
    ld a, a
    ld c, a
    rst $08
    add $7f
    ld d, h
    xor [hl]
    rst $08
    ld a, a
    ret nc

    push bc
    jp nc, $c9cd

    call nc, $c9d4
    ld d, l
    adc $c7
    ld a, a
    call nc, Call_02a_7fcf
    jp nc, $d4c5

    push de
    jp nc, Jump_02a_7fce

    call $d2c5
    jp $c855


    pop bc
    adc $c4
    ret


    db $d3
    push bc
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

    db $d3
    ld a, a
    rst $10
    push bc
    jp nc, Jump_02a_7fc5

    call nc, $c84f
    jp nc, $d7cf

    push bc
    call nz, $c57f
    sub $c5
    jp nc, $d7d9

    ret z

    push bc
    jp nc, Jump_02a_55c5

    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    reti


    rst $08
    push de
    jp nc, $c57f

    reti


    push bc
    db $d3
    ld d, l
    ld a, a
    jp $cec1


    add a
    call nc, $d37f
    push bc
    push bc
    ld a, a
    ret


    call nc, $817f
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    ld d, l
    ret c

    pop bc
    jp Jump_02a_7fd4


    ret nc

    call z, $c3c1
    push bc
    ld a, a
    ld a, a
    jp nz, Jump_02a_7fd9

    call nz, Call_02a_55d2
    rst $08
    ret nc

    push bc
    call nz, $d07f
    jp nc, $d0cf

    db $d3
    ld a, a
    ld a, a
    adc $c5
    pop bc
    jp nc, Jump_02a_55c2

    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    add c
    ld a, a
    xor h
    ld d, l
    rst $08
    rst $08
    bit 7, a
    add $cf
    jp nc, $ce7f

    push bc
    pop bc
    jp nc, $d9c2

    ld a, a
    push bc
    sub $55
    push bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $cb7f
    adc $cf
    rst $10
    ld d, l
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    call nc, $c5c8
    ld a, a
    call $c3c1
    ret z

    ret


    adc $55
    push bc
    ld a, a
    ret


    db $d3
    add c
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    jp z, $d3d5

    call nc, $d07f
    push bc
    push bc
    ret nc

    push bc
    call nz, Call_02a_7f4f
    jp nz, Jump_02a_7fd9

    call nc, $ccc5
    push bc
    db $d3
    jp $d0cf


    push bc
    add c
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    db $d3
    ret


    rst $00
    ret z

    call nc, $c97f
    db $d3
    ld a, a
    jp nz, $c1c5

    push de
    call nc, Call_02a_55c9
    add $d5
    call z, Call_02a_7f81
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
    xor c
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld c, a
    ret


    db $d3
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ret


    adc $c7
    ld a, a
    adc $cf
    rst $10
    ld a, a
    ret


    ld d, l
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $d7cf
    push bc
    jp nc, Jump_02a_547f

    ld a, a
    add c
    ld d, l
    ld a, a
    ld d, [hl]
    ld d, [hl]
    adc h
    ld a, a
    xor a
    res 0, c
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    call $d955
    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, $cd7f

    reti


    ld a, a
    ld d, l
    ld e, h
    ld a, a
    add c
    ld a, a
    xor c
    ld d, l
    add a
    sub $c5
    ld a, a
    pop bc
    call z, $c5d2
    pop bc
    call nz, Call_02a_7fd9
    call nz, $d3c9
    call z, Call_02a_55c9
    set 0, l
    call nz, $c97f
    call nc, Call_02a_7f8e
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02a_4f7f
    ld e, h
    ld a, a
    sub e
    sbc c
    ld a, a
    ld d, l
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    rst $00
    ret


    jp nc, Jump_02a_7fcc

    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, $d37f

    rst $08
    ld a, a
    ld c, a
    call $cec1
    reti


    ld a, a
    call z, $c7d5
    rst $00
    pop bc
    rst $00
    push bc
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a

Call_02a_4f7f:
Jump_02a_4f7f:
    ld e, h
    ld a, a
    sub e
    sbc c
    ld c, a
    ld a, a
    ret


    db $d3
    pop bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_02a_7fcc
    jp $ccc1


    call z, $c4c5
    ld d, l
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, $d37f
    call nc, $d2c1
    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld d, l
    ret z

    ret


    call nc, $d07f
    push bc
    jp nc, $c5c3

    adc $d4
    pop bc
    rst $00
    push bc
    ld a, a
    ld a, a
    rst $08
    ld d, l
    add $7f
    call nc, $c9c8
    db $d3
    ld a, a

Call_02a_4fc1:
    db $d3
    set 1, c

Call_02a_4fc4:
    call z, Call_02a_7fcc
    ret


Jump_02a_4fc8:
    db $d3

Jump_02a_4fc9:
    ld a, a
    sub $55

Jump_02a_4fcc:
    push bc
    jp nc, Jump_02a_7fd9

    ret z

    ret


    rst $00
    ret z

    adc [hl]

Call_02a_4fd5:
    ld a, a
    xor c
    call nc, $d77f
    ret


    call z, Call_02a_55cc
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    pop bc
    ld a, a
    jp nc, $cccf

    push bc
    ld a, a
    rst $10
    ret z

    push bc
    adc $55
    ld a, a
    adc $cf
    ld a, a
    add $c1
    ret


    call z, $d2d5
    push bc
    ld a, a
    ret


    adc $7f
    jp $55cf


    call $c5d0
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and l
    sub $c5
    adc $7f
    adc $cf
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $cec9
    ld c, a
    rst $00
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    call nz, $d6c5
    ret


    jp Jump_02a_7fc5


    ld a, a
    pop bc
    ld d, l
    call z, $cfd3
    ld a, a
    jp $cec1


    ld a, a
    jp nz, Jump_02a_7fc5

    ret


    adc $c4
    push de
    jp Jump_02a_55c5


    call nz, Call_02a_7f8e
    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    jp $d2cf


Jump_02a_5055:
    push bc
    ld a, a
    ld d, l
    rst $00
    rst $08
    call nc, $c27f
    reti


    ld a, a
    push bc
    pop bc
    jp Jump_02a_7fc8


    ret


    db $d3
    ld a, a
    db $d3
    call $c155
    call z, $8ecc
    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    call nz, $d0c5
    rst $08
    db $d3
    ret


    call nc, Call_02a_557f
    ret


    call nc, $c17f
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld e, e
    add a
    db $d3
    ld a, a
    rst $10
    ret z

    ld d, l
    push bc
    adc $7f
    adc $cf
    ld a, a
    push de
    db $d3
    ret


    adc $c7
    adc [hl]
    ld a, a
    or h
    ret z

    push de
    db $d3
    ld d, l
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $d6c5
    ret


    jp Jump_02a_7fc5


    call nz, $c5cf
    db $d3
    ld d, l
    adc $87
    call nc, $d77f
    rst $08
    jp nc, $8ecb

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nc, $d5cf

    call nc, Call_02a_7fc5
    ld a, a
    jp nz, Jump_02a_7fd9

    jp nz, Jump_02a_4fc9

    set 0, l
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    call z, $d0cf
    push bc
    ld a, a
    call nc, Call_02a_7fcf
    ld d, l
    db $d3
    push bc
    pop bc
    db $d3
    ret


    call nz, $81c5
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    rst $10
    rst $08
    adc $c4
    ld d, l
    push bc
    jp nc, $d5c6

    call z, $c67f
    call z, $c9d9
    adc $c7
    ld a, a
    call nz, $d7cf
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call z, $d0cf
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, $d5cf

    db $d3
    ld a, a
    add $4f
    rst $08
    jp nc, $d77f

    pop bc
    call z, $c9cb
    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld d, l
    ld a, a
    jp nc, $d5cf

    call nc, $81c5
    ld a, a
    reti


    rst $08
    push de
    add a
    call nz, $d27f
    ret


    call nz, $c555
    ld a, a
    pop bc
    ld a, a
    jp nz, $cbc9

    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    ret


    call nz, $cec9
    rst $00
    ld a, a
    pop bc
    ld a, a
    adc $c5
    rst $10
    ld a, a
    jp nz, $cbc9

    ld c, a
    push bc
    ld a, a
    rst $10
    ret


    call nc, Call_02a_7fc8
    call Call_02a_7fd9
    rst $00
    ret


    jp nc, Jump_02a_7fcc

    add $d2
    ld d, l
    ret


    push bc
    adc $c4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_02a_7f81
    xor [hl]
    rst $08
    rst $10
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_02a_7fcf
    db $d3
    ld c, a
    ret nc

    rst $08
    jp nc, Jump_02a_7fd4

    jp nz, Jump_02a_7fd9

    jp nz, $cbc9

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
    jp nc, $d5cf

    call nc, Call_02a_7fc5
    jp nz, Jump_02a_7fd9

    jp nz, $cbc9

    ld c, a
    push bc
    ld a, a
    add $d2
    rst $08
    call $c87f
    push bc
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld a, a
    push de
    ret nc

    ld d, l
    rst $10
    pop bc
    jp nc, Jump_02a_7fc4

    db $d3
    call z, $d0cf
    push bc
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or d
    ret


    call nz, Call_02a_7fc5
    pop bc
    ld a, a
    jp nz, $cbc9

    push bc
    ld a, a
    call nc, Call_02a_7fcf
    rst $00
    ld c, a
    rst $08
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $d5cf

    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    xor c
    ld a, a
    adc h
    ld a, a
    push bc
    pop bc
    jp $c84f


    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_02a_7f81
    ld d, l
    or h
    rst $08
    ld a, a
    jp nz, $ccd5

    call z, Call_02a_7fd9
    ret


    db $d3
    ld a, a
    adc $cf
    call nc, $d07f
    ld d, l
    push bc
    jp nc, $c9cd

    call nc, $c5d4
    call nz, Call_02a_7f81
    ld d, a
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $c17f
    ld a, a
    call $cec9
    push de
    call nc, $c54f
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_02a_7f7f
    ret


    ld d, l
    db $d3
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    jp nz, Jump_02a_7fd9

    call Call_02a_7fc5
    adc [hl]
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    ld a, a
    call nc, $cfd7
    ld a, a
    pop bc
    jp nc, Jump_02a_7fc5

    pop bc
    call z, Call_02a_7fcc
    call Call_02a_55c9
    adc $c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387

Jump_02a_528e:
    ld a, a
    call nc, $cfcf
    ld a, a
    add $c1
    jp nc, $c67f

    jp nc, $4fcf

    call $c87f
    push bc
    jp nc, $8cc5

    ld a, a
    jp nz, $d4d5

    ld a, a
    ld a, a
    ret


    adc $7f
    jp nc, $c555

    call nz, $cc7f
    rst $08
    call nc, $d3d5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    call nc, $c5c8
    ld d, l
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    ret


    adc $d3
    call nc, $d4c9
    push de
    call nc, $c555
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    xor c
    call nc, $d37f
    push bc
    push bc
    call Call_02a_7fd3
    db $d3
    ld d, l
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, $c9cf
    adc $c7
    ld a, a
    pop bc
    ld d, l
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    call nc, Call_02a_7fcf
    call z, $d4c5
    ld a, a
    add $cf
    db $d3
    ld d, l
    db $d3
    ret


    call z, $d27f
    push bc
    sub $c9
    sub $c5
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_02a_7f4f
    rst $08
    add $7f
    db $d3
    ret z

    push bc
    call z, $9fcc
    ld a, a
    ld d, a
    nop
    ld a, a
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_02a_7f4f
    rst $08
    add $7f
    db $d3
    ret z

    push bc
    call z, $9fcc
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    ld a, a
    rst $00
    rst $08
    call nc, Call_02a_4f7f
    ld d, b
    ld bc, $cf45
    nop
    add c
    ld a, a
    ld d, b
    ld de, $500d
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_02a_7f9f
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    ld c, a
    pop bc
    jp nc, $cd7f

    rst $08
    jp nc, $8ec5

    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    xor a
    ret z

    add c
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cdcf


    push bc
    sbc a
    ld c, a
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    ret


    adc $ce
    push bc
    jp nc, $d3c5

    call nc, Call_02a_7f8e
    xor b
    rst $08
    call z, $c9c4
    adc $c7
    ld d, l
    ld a, a
    pop bc
    ld a, a
    ret nc

    rst $08
    db $d3
    call nc, $d2c5
    ld a, a
    pop bc
    jp $c9d4


    sub $c9
    call nc, $d955
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $c87f
    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    pop bc
    ld d, l
    adc $c4
    ld a, a
    call nc, $c1d2
    sub $c5
    call z, $c9cc
    adc $c7
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
    call nz, $d47f
    ret z

    ret


    adc $c7
    adc [hl]
    ld a, a
    jp nz, $d4d5

    ld d, l
    ld a, a
    adc $cf
    jp nz, $c4cf

    reti


    ld a, a
    jp $cdcf


    push bc
    db $d3
    adc [hl]
    ld a, a
    xor c
    add a
    ld d, l
    call $cc7f
    rst $08
    db $d3
    ret


    adc $c7
    ld a, a
    add $c5
    push bc
    call z, $d77f
    ret z

    pop bc
    ld d, l
    call nc, $d6c5
    push bc
    jp nc, $a97f

    add a
    call nz, $c47f
    rst $08
    adc [hl]
    ld a, a
    and c
    ret z

    add c
    ld d, l
    ld a, a
    jp $cecf


    rst $00
    jp nc, $d4c1

    push de
    call z, $d4c1
    ret


    rst $08
    adc $81
    ld a, a
    ld d, l
    or h
    ret z

    push bc
    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d355

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
    call nz, Call_02a_4f7f
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

Call_02a_547f:
Jump_02a_547f:
    jp $c5cc


    jp nc, Jump_02a_7fcb

    add c
    ld a, a
    ld d, l
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nz, $c9d2

    adc $c7
    ld a, a
    call nc, $cfcf
    ld a, a
    call Call_02a_4fd5
    jp $81c8


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
    jp $c5d2


    call nc, $cd7f
    pop bc
    jp $c9c8


    ld c, a
    adc $c5
    ld a, a
    sub b
    sub e
    ret


    db $d3
    ld a, a
    jp nc, $c4c9

    ret


    adc $c7
    ld a, a
    rst $10
    pop bc
    ld d, l
    sub $c5
    add c
    and l
    sub $c5
    adc $7f
    ret


    call nc, $c37f
    pop bc
    adc $7f
    jp nc, Jump_02a_55c9

    call nz, Call_02a_7fc5
    rst $08
    adc $7f
    ld d, h
    call $d2c1
    jp $c9c8


    adc $c7
    ld d, l
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    add c
    and c
    adc $c4
    ld d, l
    adc h
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    call $c3c1
    ret z

    ret


    adc $c5
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    pop bc
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    add $7f
    jp nz, $d4cf

    ret z

    ld a, a
    call nc, $cf55
    ld a, a
    push de
    db $d3
    push bc
    pop bc
    adc $c4
    ld a, a
    call nc, Call_02a_7fcf
    db $d3
    pop bc
    sub $c5
    ld a, a
    ld d, l
    push bc
    adc $c5
    jp nc, $d9c7

    add c
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_02a_7fc5

    sub $c5
    ld d, l
    jp nc, Jump_02a_7fd9

    call z, $c3d5
    set 3, c
    ld a, a
    call nc, Call_02a_7fcf
    rst $00
    push bc
    call nc, $cfd3
    ld d, l
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld a, a
    pop bc
    ld a, a
    rst $00
    ret


    add $d4
    ld d, l
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    jp nz, $c9d2

    adc $c7
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld c, a

Call_02a_557f:
Jump_02a_557f:
    call $cec1
    reti


    ld a, a
    ld d, h
    ld a, a
    adc [hl]
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    or h
    jp nc, $cec1

    db $d3
    add $c5
    jp nc, Jump_02a_5055

    ld bc, $de64
    nop
    ld d, l
    ld a, a
    call nc, Call_02a_7fcf
    call nc, $c5c8
    ld a, a
    jp $d3c1


    push bc
    ld a, a
    ld e, e
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    jp nz, $c9d2

    adc $c7
    ld a, a
    db $d3
    rst $08
    ld a, a

Call_02a_55c1:
Jump_02a_55c1:
    ld c, a

Jump_02a_55c2:
    call $cec1

Call_02a_55c5:
Jump_02a_55c5:
    reti


    ld a, a
    ld d, h

Call_02a_55c8:
    add c

Call_02a_55c9:
Jump_02a_55c9:
    or h

Jump_02a_55ca:
    ret z

    push bc

Call_02a_55cc:
    ld a, a
    jp $d3c1


    push bc
    ld d, l

Call_02a_55d2:
Jump_02a_55d2:
    ld a, a
    ret


Call_02a_55d4:
    db $d3
    ld a, a
    add $d5
    call z, Call_02a_7fcc
    adc [hl]
    ld a, a
    or h
    jp nc, $cec1

    db $d3
    add $55
    push bc
    jp nc, $c97f

    db $d3
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    add $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    pop de
    push de
    push bc
    db $d3
    call nc, $cfc9
    adc $81
    ld a, a
    and a
    rst $08
    ld a, a
    call nc, Call_02a_7fcf
    call nc, $c855
    push bc
    ld a, a
    jp $cec5


    call nc, $c5d2
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    pop bc
    adc $55
    call nz, $c57f
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    jp Jump_02a_55c1


    db $d3
    push bc
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    ld a, a
    rst $00
    rst $08
    call nc, Call_02a_4f7f
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    and c
    call z, $c1d7
    reti


    db $d3
    ld a, a
    add $c5
    push bc
    call z, $d47f
    ret z

    push bc
    ld a, a
    ld c, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld e, l
    ld a, a
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    ret nc

    pop bc
    jp nc, $ccc1

    reti


    jp c, $c4c5

    ld a, a
    ret z

    push bc
    pop bc
    sub $c9
    ld d, l
    call z, Call_02a_7fd9
    jp nz, Jump_02a_7fd9

    call z, $d2c1

Call_02a_567f:
    sub $c1
    push bc
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, l
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    ret


    adc $7f
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    adc [hl]
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, $55c4
    ld a, a
    call nc, $c9c8
    adc $cb
    ld a, a
    pop bc
    ld a, a
    call $d4c5
    ret z

    rst $08
    call nz, $d47f
    ld d, l
    rst $08
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
    call nc, Call_02a_55c8
    push bc
    jp nc, Jump_02a_7fc5

    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, $cec4
    ld d, l
    add a
    call nc, Call_02a_7f7f
    db $d3
    call nc, $d9c1
    ld a, a
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    add $cf
    jp nc, $c555

    sub $c5
    jp nc, Jump_02a_7f8e

    and a
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, $d17f
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
    ld d, e
    sbc d
    and c
    ret z

    add c
    ld a, a
    ld d, d
    add c
    ld c, a
    ld a, a
    adc [hl]
    ld a, a
    and c
    jp nc, Jump_02a_7fc5

    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    ld d, l
    call nc, Call_02a_7fcf
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    sbc a
    ld a, a
    ld d, l
    and c
    jp nz, $cec1

    call nz, $cecf
    add c
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    adc h
    ld a, a
    pop bc
    ld d, l
    adc $d9
    rst $10
    pop bc
    reti


    ld a, a
    ret z

    pop bc
    sub $c5
    adc $87
    call nc, $c17f
    ld a, a
    jp nz, $c155

    call nz, $c5c7
    adc h
    ret z

    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    sbc a
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    rst $00
    push de
    pop bc
    jp nc, $c5c4

    call nz, $cf7f
    call z, Call_02a_7fc4
    call $cec1
    ld d, l
    ld a, a
    call $d9c1
    ld a, a
    adc $cf
    call nc, $cc7f
    push bc
    call nc, $d97f
    rst $08
    push de
    ld a, a
    ld d, l
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

    add c
    ld a, a
    ld d, [hl]
    adc h
    ld d, l
    ld a, a
    and c
    adc $c4
    add c
    ld a, a
    xor c
    db $d3
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_02a_557f

    ld d, h
    ld a, a
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    db $d3
    call z, $c7c9
    ret z

    ld d, l
    call nc, $d9cc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $cec9

    rst $00
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c84f
    push bc
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    ret


    db $d3
    ld a, a
    push de
    adc $d4
    ret


    push bc
    call nz, $8155
    ld a, a
    ld c, [hl]
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02a_7fc4
    jp $c1c8


    call z, $c5cc
    adc $c7
    push bc
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    rst $00
    push bc
    call $cecf
    reti


    ld a, a
    rst $08
    add $7f
    ld d, l
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    ld d, l
    call z, Call_02a_7fc4
    jp nz, Jump_02a_7fc5

    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    call nc, Call_02a_7fcf
    call nc, $c155
    set 0, l
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c57f
    ret c

    push bc
    jp nc, $c9c3

    ld d, l
    db $d3
    push bc
    ld a, a
    add c
    ld a, a
    xor a
    ret z

    add c
    ld a, a
    db $d3
    rst $08
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    call nc, Call_02a_7fcf
    ret nc

    rst $08
    set 0, l
    ld a, a
    rst $08
    adc $c5
    add a
    db $d3
    ld a, a
    adc $cf
    ld d, l
    db $d3
    push bc
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, $d07f

    push bc
    rst $08
    ld d, l
    ret nc

    call z, $87c5
    db $d3
    ld a, a
    jp nz, $d3d5

    ret


    adc $c5
    db $d3
    db $d3
    adc [hl]
    ld a, a
    and c
    ld d, l
    adc $d9
    ret z

    rst $08
    rst $10
    adc h
    ld a, a
    xor c
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02a_7fc4
    rst $00
    ld d, l
    rst $08
    ld a, a
    add $c9
    jp nc, $d4d3

    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    adc $81
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
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
    jp nc, $8155

    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    or a
    ret z

    pop bc

Call_02a_58d9:
    call nc, Call_02a_7f9f
    ld c, a
    ld d, d
    or h
    rst $08
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call $d4c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    ret


    db $d3
    ld a, a
    ret nc

    call z, $c3c1
    ld d, l
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call nc, $cfcf
    ld a, a
    jp $c155


    db $d3
    push de
    pop bc
    call z, Call_02a_7f81
    or h
    ret z

    push bc
    adc $7f
    ld d, [hl]
    adc h
    ld a, a
    and c
    ld d, l
    jp nc, Jump_02a_7fc5

    reti


    rst $08
    push de
    ld a, a
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, $cf55
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    sbc a
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    db $d3
    ld a, a
    ld a, a
    rst $10
    push bc
    jp nc, Jump_02a_7fc5

    jp $cf55


    call z, $c5cc
    jp $c5d4


    call nz, $d77f
    ret z

    rst $08
    call z, $ccc5
    reti


    add c
    ld d, l
    ld a, a
    xor a
    ret z

    adc h
    ld d, [hl]
    add c
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c87f
    push bc
    ld a, a
    ld d, l
    jp nz, Jump_02a_7fc5

    jp $cdcf


    ret nc

    push bc
    call nc, $cec5
    call nc, Call_02a_7f9f
    or h
    ret z

    push bc
    ld d, l
    adc $8c
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    ld d, d
    ld a, a
    ld a, a
    call nc, Call_02a_7fcf
    ld d, l
    call nz, Call_02a_7fcf
    db $d3
    rst $08
    call Call_02a_7fc5
    rst $10
    pop bc
    jp nc, $c9cd

    adc $c7
    adc l
    push de
    ld d, l
    ret nc

    ld a, a
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    db $d3
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, $c555

    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_02a_7fcf
    call nc, $c5c8
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    ld d, l
    adc $c3
    push bc
    ld a, a
    ld d, h
    ld a, a
    add c
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $55
    add c
    ld a, a
    ld d, a
    nop
    xor a
    adc $cc
    reti


    ld a, a
    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    ld c, a
    rst $08
    rst $10
    adc $d3
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    jp nz, $c4c1

    rst $00
    push bc
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, Call_02a_7f55
    add $d2
    rst $08
    call $c87f
    push bc
    jp nc, Jump_02a_7fc5

    ld d, [hl]
    ld a, a
    add c
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c87f
    pop bc
    sub $c5
    adc $87
    call nc, Call_02a_557f
    pop bc
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    sbc a
    or d
    push bc
    db $d3
    call nc, $d2c1
    call nc, $c97f
    add $55
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    ld d, l
    push bc
    ld a, a
    ld d, h
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    pop bc
    call z, $817f
    ld a, a
    ld d, l
    ld d, b
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    rst $10
    ret z

    rst $08
    ld c, a
    ld a, a
    rst $08
    rst $10
    adc $d3
    ld a, a
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    ld d, l
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    ld d, [hl]
    ld a, a
    add c
    or h
    ld d, l
    ret z

    push bc
    adc $7f
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $55
    call nz, Call_02a_567f
    add c
    ld a, a
    and a
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, Call_02a_7f81
    ld d, a
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    rst $10
    ret z

    rst $08
    ld c, a
    ld a, a
    rst $08
    rst $10
    adc $d3
    ld a, a
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    jp $cec1


    ld a, a
    rst $00
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    ld d, l
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    ld d, [hl]
    ld a, a
    add c
    xor b
    ld d, l
    add a
    call Call_02a_567f
    add c
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $55
    call nz, Call_02a_567f
    add c
    and a
    rst $08
    ld a, a
    pop bc
    ret z

    push bc
    pop bc
    call nz, Call_02a_7f81
    ld d, a
    nop
    ld a, a
    xor b
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
    xor b
    pop bc
    sub $c5
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    sub l
    ld d, l
    ld a, a
    ret nc

    push bc
    jp nc, $cfd3

    adc $8c
    and e
    rst $08
    adc $c7
    jp nc, $d4c1

    push de
    call z, $c155
    call nc, $cfc9
    adc $81
    ld a, a
    ld d, b
    dec bc
    nop
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c855
    ret


    db $d3
    ld a, a
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
    call nz, Call_02a_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $d4d3
    jp nc, $cec1

    rst $00
    push bc
    ld a, a
    ld d, l
    ld e, l
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    and d
    push de
    call nc, Call_02a_7f8c
    xor d
    push de
    db $d3
    call nc, $d37f
    pop bc
    reti


    ld a, a
    ret z

    push bc
    ld c, a
    jp nc, Jump_02a_7fc5

    adc h
    ld a, a
    adc $cf
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $cec9

    rst $00
    ld a, a
    ld d, l
    ret


    adc $d4
    rst $08
    ld a, a
    call nc, $c5c8
    ld a, a
    ld e, [hl]
    sbc a
    ld d, l
    ld a, a
    or a
    push bc
    ld a, a
    pop bc
    jp nc, Jump_02a_7fc5

    ld a, a
    rst $00
    jp nc, $d5cf

    ret nc

    ld a, a
    ld a, a
    push de
    ld d, l
    db $d3
    ret


    adc $c7
    ld a, a
    ld d, h
    ld a, a
    call nc, Call_02a_7fcf
    call nz, Call_02a_7fcf
    push bc
    sub $55
    ret


    call z, $c47f
    push bc
    push bc
    call nz, Call_02a_7f81
    and l
    adc $d4
    push bc
    jp nc, $d08c

    call z, $c555
    pop bc
    db $d3
    push bc
    add c
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $cec9

    rst $00
    ld d, l
    sbc a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    ld d, l
    adc $81
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c67f

    pop bc
    jp Jump_02a_7fc5


    ld d, l
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $cc7f
    ret


    set 0, l
    ld a, a
    call nc, $c1c8
    call nc, $8155
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_02a_7fcf
    db $d3
    rst $08
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02a_7fc4
    jp nz, $c555

    ld a, a
    add $cf
    jp nc, $c5c3

    call nz, $d47f
    rst $08
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $8155

    ld a, a
    or a
    pop bc
    ret z

    rst $08
    rst $08
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
    ret z

    ld c, a
    pop bc
    sub $c5
    ld a, a
    call nc, $c1c8
    call nc, $cc7f
    push bc
    sub $c5
    call z, $8c7f
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    adc h
    ld a, a
    push bc
    sub $c5
    adc $7f
    ld d, l
    ld e, [hl]
    ld a, a
    adc h
    ld a, a
    jp $cec1


    ld a, a
    jp nz, $c3c5

    ld d, l
    rst $08
    call Call_02a_7fc5
    rst $00
    jp nc, $c1c5

    call nc, Call_02a_7f8e
    or a
    ret z

    pop bc
    call nc, $c17f
    ld d, l
    ld a, a
    ret nc

    ret


    call nc, $81d9
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
    ret nc

    rst $08
    jp nc, $c1d4

    jp nz, Jump_02a_4fcc

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
    ld a, a
    xor d
    push de
    db $d3
    call nc, $ce7f
    rst $08
    rst $10
    adc h
    ld a, a
    ld c, a
    ld e, [hl]
    add a
    db $d3
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    jp Jump_02a_55c1


    call Call_02a_7fc5
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $d387
    ld a, a
    jp nc, $cfcf

    ld d, l
    call Call_02a_7f8e
    ld d, [hl]
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $d77f
    ld d, l
    rst $08
    jp nc, $c9d2

    push bc
    call nz, $cd7f
    push de
    jp $81c8


    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call $cec1
    add c
    ld c, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    adc $87
    call nc, Call_02a_557f
    ld e, [hl]
    adc [hl]
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    adc h
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
    jp $cf55


    call Call_02a_7fc5
    call nc, Call_02a_7fcf
    ret z

    push bc
    call z, Call_02a_7fd0
    call $9fc5
    ld a, a
    and c
    ld d, l
    ret z

    adc h
    ld a, a
    call nc, $c1c8
    adc $cb
    db $d3
    add c
    ld a, a
    adc [hl]
    ld a, a
    or d
    ret


    rst $00
    ret z

    ld d, l
    call nc, Call_02a_7f81
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    ret z

    push bc
    call z, Call_02a_7fd0
    call Call_02a_55c5
    ld a, a
    adc h
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
    ld a, a
    ld d, l
    ld d, h
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
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    adc $c1
    call $4fc5
    db $d3
    ld a, a
    xor h
    pop bc
    jp nz, $ccd5

    pop bc
    db $d3
    adc [hl]
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    pop bc
    ld a, a
    jp $c5cc


    sub $c5
    jp nc, Jump_02a_547f

    add c
    ld a, a
    and d
    push de
    call nc, Call_02a_7f55
    ld d, [hl]
    ld a, a
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, Call_02a_7f55
    ret


    adc $7f
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    ret


    adc $d3
    call nc, Call_02a_55c9
    call nc, $d4d5
    push bc
    ld a, a
    adc [hl]
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_02a_7fc4
    ld d, l
    jp nz, Jump_02a_7fc5

    call $c3d5
    ret z

    ld a, a
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    call nc, Call_02a_55c8
    pop bc
    adc $7f
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    add c
    ld a, a
    xor c
    add $7f
    ret


    call nc, $d77f
    ld d, l
    push bc
    jp nc, Jump_02a_7fc5

    reti


    rst $08
    push de
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    ld d, l
    call z, $d6cf
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret nc

    jp nc, $d3c5

    push bc
    jp nc, $c5d6

    ld d, l
    ld a, a
    ret z

    ret


    call Call_02a_7f7f
    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c17f
    call nc, Call_02a_557f
    db $d3
    rst $10
    ret


    call $c9cd
    adc $c7
    adc h
    ld a, a
    db $d3
    rst $08
    ld a, a
    xor b
    push bc
    ld a, a
    jp $c155


    adc $7f
    jp nc, $c4c9

    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $10
    pop bc
    call z, Call_02a_7fcb
    ld d, l
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    sub $c5
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
    ret z

    push bc
    call z, $8cd0
    ld a, a
    call nc, $c84f
    pop bc
    adc $cb
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

    push de
    jp nc, $cfd0

    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ld c, a
    ld e, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    adc [hl]
    ld a, a
    xor b
    push bc
    ld a, a
    jp $c555


    jp nc, $c1d4

    ret


    adc $cc
    reti


    ld a, a
    jp $cec1


    ld a, a
    jp $d4c1


    jp $c855


    ld a, a
    call nc, $c5c8
    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    ld d, l
    call z, $cf7f
    add $7f
    ld d, h
    add c
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    db $d3
    call nc, $d0cf
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld c, a
    db $d3
    push bc
    call z, $c9cc
    adc $c7
    ld a, a
    rst $08
    add $7f
    rst $08
    call $c9ce
    ret nc

    rst $08
    ld d, l
    call nc, $cec5
    call nc, $c27f
    pop bc
    call z, Call_02a_7fcc
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld d, l
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    push bc
    adc $c5
    call nz, $d47f
    ret z

    push bc
    ld a, a
    ret


    adc $c3
    ld d, l
    ret


    call nz, $cec5
    call nc, Call_02a_567f
    ld a, a
    ld c, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    push de
    call z, Call_02a_7fc4
    jp nz, Jump_02a_7fc5

    jp nz, $d2cf

    push bc
    ld c, a
    call nz, $c97f
    add $7f
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    pop bc
    call z, Call_02a_7fcc
    ld d, [hl]
    jp nz, $c3c5

    rst $08
    call Call_02a_7fc5
    ld d, l
    pop bc
    jp nz, $cfd3

    call z, $d4d5
    push bc
    call z, Call_02a_7fd9
    rst $08
    jp nz, $c4c5

    ret


    push bc
    ld d, l
    adc $d4
    ld a, a
    call nc, Call_02a_7fcf
    ld e, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_02a_7f81
    xor c
    ld c, a
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, Call_02a_557f
    ld e, [hl]
    db $d3
    ld a, a
    ld a, a
    rst $10
    push bc
    jp nc, Jump_02a_7fc5

    call nz, Call_02a_55d2
    ret


    sub $c5
    adc $7f
    pop bc
    rst $10
    pop bc
    reti


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    adc h
    ld a, a
    xor b
    push bc
    jp nc, Jump_02a_7fc5

    ret


    ld c, a
    db $d3
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, $d5cf

    db $d3
    add c
    ld a, a
    adc [hl]
    ld a, a
    and e
    rst $08
    ld d, l
    call Call_02a_7fc5
    pop bc
    adc $c4
    ld a, a
    ret z

    push bc
    call z, Call_02a_7fd0
    call $9fc5
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    ret z

    push bc
    call z, $c5d0
    call nz, $cd7f
    push de
    jp Jump_02a_4fc8


    adc h
    ld a, a
    call nc, $c1c8
    adc $cb
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, e
    sbc d
    xor c
    add a
    call $d77f
    pop bc
    ret


    call nc, $cec9
    ld c, a
    rst $00
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, d
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, Call_02a_4f7f
    db $d3
    rst $10
    ret


    call nc, $c8c3
    add c
    ld a, a
    or b
    jp nc, $d3c5

    db $d3
    ld a, a
    pop bc
    adc $c4
    ld d, l
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
    pop bc
    adc $c4
    ld a, a
    call nc, $d9d2
    add c
    ld a, a
    ld c, a
    ld d, [hl]
    or b
    pop bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ret


    call nz, $c1c5
    ld a, a
    call nc, Call_02a_7fcf
    ret nc

    jp nc, $d3c5

    ld c, a
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d4cf

    call nc, $cecf
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld d, l
    jp nz, $cec1

    call nz, $cecf
    push bc
    call nz, Call_02a_7f8e
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $c27f
    jp nc, $cec9

    rst $00
    ld a, a
    jp $c9cf


    adc $c2
    rst $08
    ld c, a
    ret c

    add c
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    and l
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld a, a
    jp $c9cf


    adc $7f
    rst $10
    ret


    ld c, a
    call nc, Call_02a_7fc8
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret


    call nc, Call_02a_7fc8
    rst $10
    ret z

    pop bc
    call nc, $d47f
    rst $08
    ld a, a
    push bc
    ret c

    jp $c84f


    pop bc
    adc $c7
    push bc
    sbc a
    ld a, a
    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d27f
    ret


    rst $00
    ret z

    call nc, Call_02a_7f9f
    ld d, a
    nop
    ld a, a
    and a
    push de
    push bc
    db $d3
    call nc, Call_02a_7fd3
    pop bc
    jp nc, Jump_02a_7fc5

    push de
    adc $c1
    jp nz, Jump_02a_4fcc

    push bc
    ld a, a
    call nc, Call_02a_7fcf
    jp nz, $c1c5

    jp nc, $cd7f

    rst $08
    jp nc, $8ec5

    ld a, a
    ld d, b
    dec c
    ld d, b
    and a
    push de
    push bc
    db $d3
    call nc, $8cd3
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp $c9cf


    adc $d3
    ld c, a
    ld a, a
    pop bc
    jp nc, Jump_02a_7fc5

    adc $cf
    call nc, $c57f
    adc $cf
    push de
    rst $00
    ret z

    add c
    ld a, a
    ld d, l
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    sbc a
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    ret nc

    push bc
    push bc
    ret nc

    push bc
    call nz, $ce7f
    rst $08
    ld c, a
    call nc, $c2c5
    rst $08
    rst $08
    set 2, e
    add c
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    add $55
    ret


    jp nc, $d4d3

    ld a, a
    ret nc

    pop bc
    rst $00
    push bc
    ld a, a
    ld d, [hl]
    ld d, h
    ld a, a
    ld a, a
    ld d, l
    jp $d4c1


    jp Jump_02a_7fc8


    ld a, a
    jp nz, Jump_02a_7fd9

    call $cecf
    db $d3
    call nc, $d2c5
    ld d, l
    ld a, a
    jp nz, $ccc1

    call z, Call_02a_7f8e
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    add a
    call nc, Call_02a_557f
    jp nz, $c9d2

    adc $c7
    ld a, a
    push de
    adc $d4
    ret


    call z, $967f
    adc [hl]
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    or h
    ld d, l
    ret z

    push bc
    ld a, a
    call $cec1
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    call z, $d4c5
    db $d3
    ld a, a
    ret z

    ld d, l
    ret


    call $c37f
    rst $08
    call $c5d0
    call nc, Call_02a_7fc5
    ret


    db $d3
    ld a, a
    jp $ccc1


    ld d, l
    call z, $c4c5
    ld a, a
    ld d, h
    ld a, a
    ld e, l
    adc [hl]
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    jp $cecf


    call nz, $d07f
    pop bc
    ld c, a
    rst $00
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    ld a, a
    ret z

    pop bc
    call nz, $cd7f
    pop bc
    call nz, Call_02a_55c5
    ld a, a
    ld d, h
    ld a, a
    rst $10
    push bc
    pop bc
    set 0, l
    jp nc, $c67f

    ret


    jp nc, $d4d3

    ld d, l
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    jp $d4c1


    jp $c9c8


    adc $c7
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    add c
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_02a_7fc4
    pop bc
    ld d, l
    call z, $cfd3
    ld a, a
    jp nz, Jump_02a_7fc5

    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    ld a, a
    call nc, $cf55
    ld a, a
    rst $10
    push bc
    pop bc
    set 0, l
    adc $7f
    call nc, $c5c8
    call $d57f
    db $d3
    ret


    ld d, l
    adc $c7
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
    jp nz, $d2d5

    ld d, l
    adc $8e
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, $cec4
    add a
    call nc, $c37f
    ld d, l
    pop bc
    call nc, $c8c3
    ld a, a
    push bc
    pop bc
    db $d3
    ret


    call z, Call_02a_7fd9
    ret


    add $7f
    ret


    call nc, $8755
    db $d3
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $c9c8
    jp nc, Jump_02a_7fc4

    ret nc

    pop bc
    rst $00
    ld c, a
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    rst $00
    jp nc, $c1c5

    call nc, $d3c5
    call nc, $ca7f
    rst $08
    reti


    ld a, a
    add $cf
    jp nc, Jump_02a_557f

    ld e, l
    ld a, a
    call nc, Call_02a_7fcf
    rst $10
    ret


    adc $7f
    pop bc
    call $cf55
    adc $c7
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    rst $08
    ld d, l
    add $7f
    ld d, h
    db $d3
    ld a, a
    add c
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    pop bc
    call z, $d755
    pop bc
    reti


    db $d3
    ld a, a
    call z, $d5c1
    adc $c3
    ret z

    push bc
    db $d3
    ld a, a
    add $c5
    jp nc, $cf55

    jp $cfc9


    push de
    db $d3
    ld a, a
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    ld d, l
    rst $08
    adc $7f
    ret


    adc $7f
    rst $00
    reti


    call Call_02a_547f
    ld a, a
    ld a, a
    pop bc
    call z, $cc55
    ld a, a
    rst $08
    sub $c5
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    jp $d5cf


    adc $d4
    jp nc, $d955

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    adc $7f
    call nc, $c5c8
    ld a, a
    add $cf
    push de
    jp nc, $c8d4

    ld a, a
    ret nc

    pop bc
    ld c, a
    rst $00
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    rst $00
    rst $08
    pop bc
    call z, Call_02a_557f
    rst $08
    add $7f
    ld d, h
    ld a, a
    ld e, l
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld e, l
    ld a, a
    ld a, a
    ld d, l
    ret


    adc $7f
    push bc
    sub $c5
    jp nc, Jump_02a_7fd9

    rst $00
    reti


    call $8c7f
    ld a, a
    rst $10
    ret z

    ld d, l
    rst $08
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret z

    ret


    call nc, $c47f
    rst $08
    rst $10
    adc $7f
    sbc b
    ld a, a
    ld d, l
    ret nc

    push bc
    jp nc, $cfd3

    adc $d3
    add c
    ld a, a
    and c
    adc $c4
    adc h
    ld a, a
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    adc $cf
    ld a, a
    call $d2cf
    push bc
    ld a, a
    db $d3
    call nc, Call_02a_55d2
    rst $08
    adc $c7
    push bc
    jp nc, $c97f

    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $d155
    push de
    pop bc
    jp nc, $c5d4

    jp nc, Jump_02a_7fd3

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
    ret z

    push bc
    ld a, a
    db $d3
    rst $08
    sub $c5
    ld d, l
    jp nc, $c9c5

    rst $00
    adc $d4
    reti


    ld a, a
    jp nc, $c7c9

    ret z

    call nc, Call_02a_7fd3
    pop bc
    jp nc, $c555

    ld a, a
    ret z

    rst $08
    call z, Call_02a_7fc4
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    pop bc
    adc $55
    call nz, Call_02a_7fd3
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    and d
    push de
    call nz, $c8c4
    pop bc
    add a
    ld d, l
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
    adc $55
    call nz, $cec1
    call nc, $81d3
    ld a, a
    ld e, b
    nop
    ld a, a
    and a
    ret


    jp nc, $9acc

    and c
    ret z

    add c
    ld a, a
    adc [hl]
    ld a, a
    and h
    rst $08
    adc $87
    call nc, Call_02a_7f4f
    ret nc

    push bc
    push bc
    ret nc

    ld a, a
    call nc, $c5c8
    ld a, a
    adc $cf
    call nc, $c2c5
    rst $08
    rst $08
    ld d, l
    res 0, c
    ld a, a
    ld d, b
    dec c
    ld d, b
    nop
    ld a, a
    or h
    push de
    jp nc, Jump_02a_7fce

    call nc, Call_02a_7fcf
    call nc, $c5c8
    ld a, a
    adc $c5
    ret c

    call nc, Call_02a_7f4f
    ret nc

    pop bc
    rst $00
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    adc $7f
    rst $08
    call z, Call_02a_7fc4
    add $c9
    db $d3
    ret z

    ret


    ld c, a
    adc $c7
    call $cec1
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_02a_7fc5

    rst $10
    push bc
    ld a, a
    pop bc
    jp nc, $c555

    add c
    ld a, a
    xor c
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld d, l
    ld a, a
    sub $c5
    jp nc, Jump_02a_7fd9

    call $c3d5
    ret z

    ld a, a
    adc [hl]
    ld a, a
    xor b
    push bc
    ld a, a
    call z, $c955
    set 0, l
    db $d3
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    adc [hl]
    ld a, a
    and h
    rst $08
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ret


    call nc, Call_02a_7f9f
    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    sbc a
    ld a, a
    xor l
    pop bc
    reti


    jp nz, Jump_02a_7fc5

    xor c
    ld a, a
    rst $00
    push bc
    call nc, Call_02a_7f4f
    pop bc
    call z, $cecf
    rst $00
    ld a, a
    rst $10
    ret


    call nc, $d97f
    rst $08
    push de
    ld a, a
    rst $10
    push bc
    ld d, l
    call z, $81cc
    ld a, a
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
    ld d, l
    ld a, a
    adc h
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    add $d5
    adc $7f
    rst $10
    ret z

    ret


    ld d, l
    call z, Call_02a_7fc5
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    add c
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02a_557f
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
    rst $08
    call z, Call_02a_7fc4
    add $c9
    db $d3
    ld d, l
    ret z

    ret


    adc $c7
    call $cec1
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    xor a
    adc $cc
    reti


    ld a, a
    add $c9
    ld d, l
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    ld a, a
    call nz, $c5cf
    db $d3
    ld a, a
    ret


    call nc, $c27f
    push bc
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $cdcf

    pop bc
    adc $c3
    push bc
    ld a, a
    rst $08
    add $7f
    call $c155
    adc $81
    or a
    ret z

    push bc
    jp nc, $d6c5

    push bc
    jp nc, $c97f

    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    db $fd
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    rst $08
    jp nc, $cc7f

    pop bc
    set 0, l
    add c
    and h
    rst $08
    adc $55
    add a
    call nc, $d37f
    call nc, $cec1
    call nz, $cf7f
    adc $7f
    jp $d2c5


    push bc
    call $cf55
    adc $d9
    adc h
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    xor b
    rst $08
    call z, Call_02a_7fc4
    call nc, $c855
    push bc
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    jp nc, $c4cf

    ld a, a
    jp nz, $55cf

    call z, $ccc4
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
    xor c
    ld a, a
    rst $08
    jp nc, $c7c9

    ret


    adc $c1
    call z, $d9cc
    ld c, a
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02a_7fcf
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, $cf7f
    jp nz, Jump_02a_55ca

    push bc
    jp $81d4


    ld a, a
    jp nz, $d4d5

    ld a, a
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld a, a
    ld d, l
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
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_02a_7f9f
    ld d, [hl]
    and a
    jp nc, $c1c5

    call nc, $d9cc
    ld a, a
    ld c, a
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    rst $08
    ret


    adc $d4
    push bc
    call nz, $577f
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor l
    jp nc, Jump_02a_7f8e

    ld d, d
    add c
    ld a, a
    add $4f
    ret


    db $d3
    ret z

    ret


    adc $c7
    sbc a
    ld a, a
    nop
    ld a, a
    xor c
    add a
    call $c27f
    jp nc, $d4cf

    ret z

    push bc
    jp nc, $cf7f

    add $7f
    rst $08
    ld c, a
    call z, Call_02a_7fc4
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    call $cec1
    add c
    ld a, a
    xor c
    ld a, a
    ld d, l
    call z, $cbc9
    push bc
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    sub $c5
    jp nc, $55d9

    ld a, a
    call $c3d5
    ret z

    ld a, a
    add c
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, Call_02a_55c9
    set 0, l
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    sbc a
    ld a, a
    xor l
    pop bc
    reti


    jp nz, Jump_02a_7fc5

    xor c
    add a
    call z, Call_02a_7fcc
    ld c, a
    rst $00
    push bc
    call nc, $c17f
    call z, $cecf
    rst $00
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    push bc
    call z, $cc55
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
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, l
    adc h
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    add $d5
    adc $7f
    rst $10
    ret z

    ret


    call z, $c555
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    add c
    ld a, a
    ld d, d
    ld a, a
    ld d, l
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02a_557f
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
    rst $08
    call z, Call_02a_7fc4
    add $c9
    db $d3
    ld d, l
    ret z

    ret


    adc $c7
    call $cec1
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    xor c
    ld a, a
    rst $08
    jp nc, $c7c9

    ret


    adc $c1
    call z, $d9cc
    ld c, a
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02a_7fcf
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, $cf7f
    jp nz, Jump_02a_55ca

    push bc
    jp $81d4


    ld a, a
    jp nz, $d4d5

    ld a, a
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld a, a
    ld d, l
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
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_02a_7f9f
    ld d, [hl]
    and a
    jp nc, $c1c5

    call nc, $d9cc
    ld a, a
    ld c, a
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    rst $08
    ret


    adc $d4
    push bc
    call nz, $577f
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    xor l
    jp nc, Jump_02a_7f8e

    ld d, d
    add c
    ld a, a
    reti


    ld c, a
    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $c87f
    pop bc
    sub $c5
    ld a, a
    add $c9
    db $d3
    ret z

    ld d, l
    push bc
    call nz, $cd7f
    push de
    jp $81c8


    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    jp nz, $c5d2

    push bc
    call nz, $d2c5
    ld a, a
    xor h
    push bc
    ld c, a
    call nc, $d387
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d77f
    push bc
    ld a, a
    jp $cf55


    push de
    call z, Call_02a_7fc4
    add $cf
    db $d3
    call nc, $d2c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    or a
    ret z

    pop bc
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_02a_4fc4
    ld a, a
    rst $10
    push bc
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    and h
    push bc
    ret nc

    rst $08
    db $d3
    ret


    call nc, Call_02a_4f7f
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ld a, a
    call nc, $cdc5
    ret nc

    rst $08
    jp nc, $d2c1

    ret


    call z, Call_02a_58d9
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_02a_4f7f

    ld d, b
    ld bc, $cd68
    nop
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

    adc [hl]
    or h
    ret z

    push bc
    ld a, a
    ld d, l
    call z, $d6c5
    push bc
    call z, $c97f
    db $d3
    ld a, a
    adc $c5
    pop bc
    jp nc, $d9cc

    ld a, a
    pop bc
    ld d, l
    db $d3
    call nc, $c1c8
    call nc, $c17f
    db $d3
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ret


    adc $55
    rst $00
    ld a, a
    ld d, b
    add hl, bc
    ld a, $cd
    inc de
    nop
    adc [hl]
    xor c
    add a
    call $d27f
    push bc
    pop bc
    call z, $d9cc
    ld a, a
    pop bc
    ld a, a
    rst $00
    ld d, l
    push bc
    adc $c9
    push de
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    xor c
    call nc, $d77f
    rst $08
    push de
    call z, Call_02a_7fc4
    call nc, $cbc1
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld c, a
    ld c, a
    ld d, b
    ld [bc], a
    ccf
    call Call_000_00c2
    add h
    ld d, l
    call nc, Call_02a_7fcf
    pop bc
    call nz, $d0cf
    call nc, Call_02a_547f
    ret


    add $7f
    reti


    rst $08
    ld d, l
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, $8ecf
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    adc h
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    jp nc, $c7c9

    ld c, a
    ret z

    call nc, $c5cd
    pop bc
    adc $c9
    adc $c7
    ld a, a
    call $cecf
    push bc
    reti


    add c
    or h
    ld d, l
    ret z

    push bc
    adc $8c
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    ld d, h
    ld a, a
    call nc, Call_02a_7fcf
    ld d, l
    rst $00
    rst $08
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
    call nz, Call_02a_557f
    ld d, b
    ld bc, $d989
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $c27f
    jp nc, $c5c5

    call nz, $d2c5
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call Call_02a_7f7f
    call nc, $c5c8
    ld a, a
    jp nz, $cfd2

    call nc, $c5c8
    jp nc, Jump_02a_7f4f

    rst $08
    add $7f
    rst $08
    call z, Call_02a_7fc4
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    call Call_02a_55c1
    adc $81
    ld a, a
    xor c
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld d, l
    ld a, a
    call nc, Call_02a_7fcf
    db $d3
    rst $08
    call Call_02a_7fc5
    push bc
    ret c

    call nc, $cec5
    call nc, $c27f
    ld d, l
    push bc
    ret


    adc $c7
    ld a, a
    push de
    adc $c1
    jp nz, $c5cc

    ld a, a
    call nc, Call_02a_7fcf
    jp $55cf


    adc $d4
    jp nc, $cccf

    ld a, a
    add c
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, Call_02a_55c9
    set 0, l
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    sbc a
    ld a, a
    xor l
    pop bc
    reti


    jp nz, Jump_02a_7fc5

    xor c
    add a
    call z, Call_02a_7fcc
    ld c, a
    rst $00
    push bc
    call nc, $c17f
    call z, $cecf
    rst $00
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    push bc
    call z, $cc55
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
    call nc, $c9c8
    db $d3
    ld a, a
    ld d, l
    adc h
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    add $d5
    adc $7f
    rst $10
    ret z

    ret


    call z, $c555
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    add c
    ld d, d
    ld a, a
    jp nc, $c555

    jp $c9c5


    sub $c5
    call nz, Call_02a_557f
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
    rst $08
    call z, Call_02a_7fc4
    add $c9
    db $d3
    ld d, l
    ret z

    ret


    adc $c7
    call $cec1
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    xor a
    adc $cc
    reti


    ld a, a
    add $c9
    ld d, l
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    ld a, a
    call nz, $c5cf
    db $d3
    ld a, a
    ret


    call nc, $c27f
    push bc
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $cdcf

    pop bc
    adc $c3
    push bc
    ld a, a
    rst $08
    add $7f
    call $c155
    adc $81
    ld a, a
    or a
    ret z

    push bc
    jp nc, $d6c5

    push bc
    jp nc, $c97f

    call nc, $c97f
    ld d, l
    db $d3
    adc l
    db $d3
    push bc
    pop bc
    ld a, a
    rst $08
    jp nc, $cc7f

    pop bc
    set 0, l
    add c
    ld a, a
    and h
    rst $08
    ld d, l
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


    adc h
    ret nc

    call z, $c1c5
    db $d3
    push bc
    add c
    ld a, a
    xor b
    rst $08
    call z, $55c4
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    jp nc, $c4cf

    ld a, a
    ld d, l
    jp nz, $cccf

    call nz, $d9cc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    xor c
    ld a, a
    rst $08
    jp nc, $c7c9

    ret


    adc $c1
    call z, $d9cc
    ld c, a
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02a_7fcf
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, $cf7f
    jp nz, Jump_02a_55ca

    push bc
    jp $81d4


    ld a, a
    jp nz, $d4d5

    ld a, a
    ret z

    push bc
    jp nc, Jump_02a_7fc5

    ret


    db $d3
    ld a, a
    ld d, l
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
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_02a_7f9f
    ld d, [hl]
    and a
    jp nc, $c1c5

    call nc, $d9cc
    ld a, a
    ld c, a
    call nz, $d3c9
    pop bc
    ret nc

    ret nc

    rst $08
    ret


    adc $d4
    push bc
    call nz, $577f
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor l
    jp nc, Jump_02a_7f8e

    ld d, d
    add c
    ld a, a
    and c
    ld c, a
    ld a, a
    sub $c5
    jp nc, Jump_02a_7fd9

    rst $00
    rst $08
    rst $08
    call nz, $c67f
    ret


    db $d3
    ret z

    ret


    adc $55
    rst $00
    jp nc, $c4cf

    adc [hl]
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    add $c9
    db $d3
    ret z

    push bc
    call nz, Call_02a_557f
    ld d, h
    ld a, a
    rst $10
    ret


    call z, Call_02a_7fcc
    sub $c1
    jp nc, Jump_02a_7fd9

    rst $10
    ret


    call nc, $c855
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    db $d3
    ld a, a
    add c
    ld a, a
    and a
    rst $08
    ld d, l
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    push bc
    sub $c5
    jp nc, $d7d9

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

    pop bc
    adc $cb
    db $d3
    add c
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    ret z

    ld c, a
    push bc
    call z, $c5d0
    call nz, $cd7f
    push de
    jp $81c8


    ld a, a
    ld d, a
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
    ret


    db $d3
    ld a, a
    rst $08
    ld c, a
    jp $d5c3


    ret nc

    ret


    push bc
    call nz, Call_02a_567f
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, $c6c5
    ld d, l
    push bc
    pop bc
    call nc, $c4c5
    sbc a
    ld a, a
    ld d, a
    ld bc, $cd68
    nop
    ld c, a
    or h
    ret z

    push bc
    ld a, a
    call z, $d6c5
    push bc
    call z, $c1c8
    db $d3
    ld a, a
    jp nc, $c1c5

    jp $c855


    push bc
    call nz, $507f
    add hl, bc
    db $ec
    ret nc

    inc de
    nop
    add c
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    xor c
    ld a, a
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $cd7f

    push bc
    sbc a
    xor b
    ret


    ld c, a
    ld a, a
    ld d, [hl]
    add c
    or h
    ret z

    push bc
    ld a, a
    pop bc
    db $d3
    db $d3
    ret


    db $d3
    call nc, $cec1
    call nc, Call_02a_7f55
    rst $08
    add $7f
    and h
    jp nc, Jump_02a_7f8e

    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    or h
    ld d, l
    ret z

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
    ld d, l
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    ld d, l
    call nc, $d0d9
    push bc
    db $d3
    ld a, a
    rst $10
    push bc
    jp nc, Jump_02a_7fc5

    jp $cccf


    call z, $c3c5
    ld d, l
    call nc, $c4c5
    ld a, a
    adc h
    and a
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cc5b
    nop
    ld d, l
    and h
    jp nc, Jump_02a_7f8e

    and c
    rst $08
    jp $c9c8


    call nz, $d2c5
    ld a, a
    db $d3
    pop bc
    ret


    call nz, Call_02a_7f55
    db $d3
    rst $08
    adc [hl]
    ld d, [hl]
    ld a, a
    or h
    ret z

    push bc
    adc $8c
    ld a, a
    xor b
    push de
    jp nc, Jump_02a_55d2

    reti


    ld a, a
    adc [hl]
    ld a, a
    xor l
    jp nc, Jump_02a_528e

    add c
    xor c
    db $d3
    ld a, a
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    jp Jump_02a_55c1


    push de
    rst $00
    ret z

    call nc, $cfcd
    jp nc, Jump_02a_7fc5

    call nc, $c1c8
    adc $7f
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    ld d, l
    ld a, a
    call nc, $d0d9
    push bc
    db $d3
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
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
    ld c, a
    or h
    ret z

    push bc
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, Call_02a_547f
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, b
    add hl, bc
    db $dd
    rst $38
    inc de
    nop
    ld a, a
    call nc, $d0d9
    push bc
    add c
    and e
    rst $08
    adc $c7
    jp nc, $c155

    call nc, $ccd5
    pop bc
    call nc, $cfc9
    adc $81
    or h
    ret z

    push bc
    adc $8c
    and a
    ret


    ld d, l
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    db $d3
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
    call nz, Call_02a_4f7f
    ld e, e
    call z, Call_02a_7f00
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    pop bc
    db $d3
    db $d3
    ret


    db $d3
    ld d, l
    call nc, $cec1
    call nc, $817f
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor c
    ld a, a
    call nc, $c9c8
    adc $cb
    ld a, a
    db $d3
    rst $08
    adc [hl]
    ld a, a
    jp nz, $d54f

    call nc, $8c7f
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    call nc, $cf55
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
    ld a, a
    adc h
    ld d, l
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cc5b
    nop
    ld d, l
    xor h
    push bc
    call nc, $d387
    ld a, a
    ret nc

    push de
    call nc, $c97f
    call nc, $cf7f
    add $c6
    push de
    ld d, l
    adc $d4
    ret


    call z, $ce7f
    push bc
    ret c

    call nc, $d47f
    ret


    call $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    xor b
    add a
    call $a181
    ret z

    sbc a
    ld a, a
    and c
    call z, Call_02a_7fcc
    call nc, $c84f
    push bc
    ld a, a
    jp $d5c1


    rst $00
    ret z

    call nc, Call_02a_547f
    ld d, [hl]
    ld a, a
    pop bc
    ld d, l
    jp nc, $cec5

    add a
    call nc, $507f
    add hl, bc
    db $dd
    rst $38
    inc de
    nop
    ld a, a
    call nc, $d0d9
    push bc
    add c
    ld a, a
    xor [hl]
    push bc
    ret c

    call nc, Call_02a_7f55
    call nc, $cdc9
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cc5b
    nop
    ld d, l
    ld a, a
    rst $10
    ret


    call z, Call_02a_7fcc
    call nz, $c9cf
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
    call nc, Call_02a_7fcf
    jp nz, $c3c5

    rst $08
    call Call_02a_7fc5
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    ld d, l
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    add c
    ld a, a
    xor [hl]
    push bc
    ret c

    call nc, Call_02a_7f4f
    call nc, $cdc9
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cc5b
    nop
    ld d, l
    ld a, a
    rst $10
    ret


    call z, Call_02a_7fcc
    call nz, $c9cf
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
    call nc, Call_02a_7fcf
    jp nz, $c3c5

    rst $08
    call Call_02a_7fc5
    ld d, l
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor h
    rst $08
    rst $08
    res 0, c
    ld a, a
    or b
    ret


    jp Jump_02a_7fc1


    ret


    adc $7f
    call $4fd9
    ld a, a
    add $c1
    call $ccc9
    reti


    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, Jump_02a_55c5

    call nc, $d9d4
    ld a, a
    call nc, $c9c1
    call z, Call_02a_7f81
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_02a_7f81
    and d
    ret


    jp $d1c1


    ret


    push de
    ld a, a
    ret


    adc $4f
    ld a, a
    call Call_02a_7fd9
    add $c1
    call $ccc9
    reti


    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $55d7
    ret


    jp Jump_02a_7fc5


    ret nc

    jp nc, $d4c5

    call nc, $c5c9
    jp nc, $d47f

    ret z

    pop bc
    adc $55
    ld a, a
    reti


    rst $08
    push de
    jp nc, $81d3

    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    ret nc

    jp nc, $d4c5

    call nc, Call_02a_7fd9
    jp nz, $c2c1

    reti


    add c
    ld a, a
    ld c, a
    xor b
    push bc
    ld a, a
    rst $10
    ret


    call z, Call_02a_7fcc
    jp nz, $d2d5

    db $d3
    call nc, $cf7f
    push de
    call nc, Call_02a_7f55
    jp $d9d2


    ret


    adc $c7
    ld a, a
    ret


    add $7f
    reti


    rst $08
    push de
    ld a, a
    call nc, Call_02a_55c1
    set 0, l
    ld a, a
    ret z

    ret


    call $c97f
    adc $7f
    reti


    rst $08
    push de
    jp nc, $c17f

    jp nc, $cd55

    db $d3
    ld a, a
    ld a, a
    call nc, $cfcf
    ld a, a
    call nc, $c7c9
    ret z

    call nc, Call_02a_7f81
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ret z

    pop bc
    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp nz, $c2c1

    reti


    ld a, a
    ld c, a
    ret


    adc $7f
    call Call_02a_7fd9
    add $c1
    call $ccc9
    reti


    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    call nc, $c9d7
    jp Jump_02a_7fc5


    ret nc

    jp nc, $d4c5

    call nc, $c5c9
    jp nc, $d47f

    ret z

    ld d, l
    pop bc
    adc $7f
    reti


    rst $08
    push de
    jp nc, $81d3

    ld a, a
    ld d, a
    nop
    ld a, a
    and d
    ret


    jp $d1c1


    ret


    push de
    sbc d
    jp $c9c8


    jp nc, $d3d0

    adc [hl]
    ld a, a
    ld c, a
    ld d, a
    nop
    ld a, a
    and d
    pop bc
    jp nz, $8ed9

    ld a, a
    ld d, a
    nop
    ld d, h
    ld a, a
    xor c
    add a
    call $d47f
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_02a_4f7f
    rst $08
    add $7f
    ret z

    rst $08
    jp nz, $c9c2

    db $d3
    call nc, $c37f
    call z, $c2d5
    ld a, a
    add c
    ld d, l
    or h
    ret z

    push bc
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, Call_02a_547f
    ld a, a
    ld d, l
    ld a, a
    db $d3
    push de
    jp nc, $c1d0

    db $d3
    db $d3
    ld a, a
    sub c
    sub b
    sub b
    ret nc

    add c
    and c
    db $d3
    ld a, a
    ld d, l
    add $cf
    jp nc, Jump_02a_547f

    ld a, a
    adc h
    ld a, a
    xor b
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c555

    pop bc
    call z, $d9cc
    ld a, a
    call nc, $ccc1
    set 0, c
    call nc, $d6c9
    push bc
    add c
    or h
    ld d, l
    ret z

    push bc
    adc $7f
    ld d, [hl]
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cdcf


    push bc
    ld d, l
    ld a, a
    call nc, Call_02a_7fcf
    ret z

    push bc
    pop bc
    jp nc, $cd7f

    reti


    db $d3
    push bc
    call z, $8dc6
    db $d3
    ld d, l
    pop bc
    call nc, $d3c9
    add $c1
    jp $cfd4


    jp nc, Jump_02a_7fd9

    db $d3
    ret nc

    push bc
    push bc
    jp $c855


    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    push bc
    db $d3
    ld a, a
    rst $08
    jp nc, $ce7f

    rst $08
    sbc a
    ld a, a
    or h
    ret z

    push bc
    adc $7f
    ld c, a
    db $d3
    call nc, $d2c1
    call nc, $c17f
    call nc, $cf7f
    adc $c3
    push bc
    add c
    ld a, a
    and c
    ret z

    ld d, l
    adc h
    ld a, a
    ld d, [hl]
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
    ld a, a
    and e
    pop bc
    ld d, l
    call z, $d0cf
    ld a, a
    call nz, $cec1
    jp Jump_02a_7fc5


    call nc, Call_02a_7fcf
    call Call_02a_7fd9
    call z, $c955
    set 1, c
    adc $c7
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    ld d, [hl]
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    db $d3
    rst $08
    ld a, a
    call z, $d6cf
    push bc
    call z, Call_02a_7fd9
    call nc, $c1c8
    call nc, $c57f
    ld d, l
    sub $c5
    jp nc, Jump_02a_7fd9

    rst $08
    adc $c5
    ld a, a
    add $cf
    adc $c4
    call z, Call_02a_7fc5
    ret


    ld d, l
    call nc, $c17f
    call nz, $c9cd
    jp nc, $cec9

    rst $00
    call z, $8ed9
    ld a, a
    xor b
    ret


    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    pop bc
    adc $c4
    adc h
    ld a, a
    call z, $cbc9
    push bc
    db $d3
    ld d, l
    ld a, a
    ld d, [hl]
    ld a, a
    sub $c5
    jp nc, Jump_02a_7fd9

    call $c3d5
    ret z

    adc [hl]
    ld a, a
    ld d, l
    ld d, [hl]
    ld d, [hl]
    adc h
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    adc $55
    bit 7, a
    db $d3
    rst $08
    sbc a
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    or a
    ret z

    reti


    ld a, a
    call nz, $c5cf
    ld d, l
    db $d3
    ld a, a
    ld d, [hl]
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    xor b
    pop bc
    add c
    ld a, a
    ld d, [hl]
    call nc, $cbc1
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    ret


    adc $7f
    ld d, l
    pop bc
    jp nc, $d3cd

    ld a, a
    rst $10
    ret z

    ret


    call z, Call_02a_7fc5
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ld d, l
    ret


    adc $c7
    ld a, a
    ld d, [hl]
    ld d, [hl]
    xor c
    db $d3
    ld a, a
    ret


    call nc, Call_02a_567f
    sbc a
    ld d, l
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    and l
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_02a_557f
    ld d, [hl]
    add c
    ld a, a
    ld d, [hl]
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    call z, Call_02a_557f
    ld d, [hl]
    add c
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c955
    call Call_02a_7fc5
    ret


    db $d3
    ld a, a
    call nc, $cfcf
    ld a, a
    call z, $d4c1
    push bc
    add c
    ld a, a
    ld d, l
    xor c
    add a
    sub $c5
    ld a, a
    call nc, $ccc1
    set 0, l
    call nz, $d37f
    call z, $c7c9
    ret z

    ld d, l
    call nc, $d9cc
    ld a, a
    call $c3d5
    ret z

    add c
    ld a, a
    or h
    rst $08
    ld a, a
    call Call_02a_7fd9
    db $d3
    ld d, l
    push bc
    call z, $8dc6
    db $d3
    pop bc
    call nc, $d3c9
    add $c1
    jp $cfd4


    jp nc, Jump_02a_7fd9

    ld d, l
    db $d3
    ret nc

    push bc
    push bc
    jp Jump_02a_7fc8


    ld d, h
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $c155


    adc $7f
    call z, $d3c9
    call nc, $cec5
    ld a, a
    call nc, Call_02a_7fcf
    db $d3
    rst $08
    ld a, a
    pop de
    ld d, l
    push de
    ret


    push bc
    call nc, $d9cc
    adc [hl]
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    call z, $d4c9
    call nc, $cc55
    push bc
    ld a, a
    rst $00
    ret


    add $d4
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call nc, $cbcf
    push bc
    ld d, l
    adc $7f
    rst $08
    add $7f
    call Call_02a_7fd9
    pop bc
    ret nc

    ret nc

    jp nc, $c3c5

    ret


    pop bc
    call nc, $c955
    rst $08
    adc $81
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
    call nz, Call_02a_4f7f
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
    ret z

    push bc
    pop bc
    call nz, $817f
    ld a, a
    ld d, l
    ld d, b
    ld de, $d900
    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    jp nz, $c9d2

    adc $c7
    ld a, a
    pop bc
    ld a, a
    add $55
    push bc
    push bc
    adc l
    add $d2
    push bc
    push bc
    ld a, a
    jp nz, $cbc9

    push bc
    push de
    db $d3
    ret


    adc $c7
    ld d, l
    ld a, a
    call nc, $c1c8
    call nc, $c57f
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld a, a
    call nc, Call_02a_55c9
    jp $c5cb


    call nc, Call_02a_7f81
    or a
    ret z

    pop bc
    call nc, Call_02a_7f81
    and c
    call z, Call_02a_7fcc
    ld a, a
    ld d, l
    xor c
    ld a, a
    call z, $d6cf
    push bc
    call nz, $c17f
    jp nc, Jump_02a_7fc5

    jp nz, $d2c9

    call nz, Call_02a_557f
    ld d, h
    adc h
    ld a, a
    ret z

    rst $08
    call z, $8dc5
    call nz, $c9d2
    call z, $c9cc
    adc $55
    rst $00
    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    adc [hl]
    ld a, a
    or a
    ret z

    push bc
    jp nc, Jump_02a_55c5

    sub $c5
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    rst $00
    rst $08
    adc h
    ld a, a
    ld d, l
    jp z, $d3d5

    call nc, $ca7f
    push de
    call $c9d0
    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    push bc
    ld d, l
    adc $cf
    push de
    rst $00
    ret z

    add c
    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    adc $cf
    ld a, a
    push de
    db $d3
    ret


    ld d, l
    adc $c7
    ld a, a
    pop bc
    adc $d9
    ld a, a
    jp nz, $cbc9

    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    pop bc
    call z, $cbc9
    push bc
    add c
    ld a, a
    and d
    ret


    set 0, l
    adc h
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    adc h
    ld a, a
    adc h
    ld a, a
    jp nc, $c4c9

    push bc
    ld a, a
    ret


    call nc, $c17f
    db $d3
    ld a, a
    ld d, l
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
    ret z

    pop bc
    call nc, Call_02a_7f81
    ld d, [hl]
    xor [hl]
    rst $08
    ld a, a
    db $d3
    call nc, $c5d2
    adc $4f
    rst $00
    call nc, Call_02a_7fc8
    adc [hl]
    and e
    rst $08
    call Call_02a_7fc5
    pop bc
    rst $00
    pop bc
    ret


    adc $7f
    pop bc
    ld d, l
    add $d4
    push bc
    jp nc, $c87f

    push bc
    pop bc
    jp nc, $cec9

    rst $00
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor l
    jp nc, Jump_02a_7f8e

    ld d, d
    add c
    ld a, a
    xor h
    ld c, a
    ret


    db $d3
    call nc, $cec5
    ld a, a
    call nc, Call_02a_7fcf
    call Call_02a_7fd9
    jp nz, $c1cf

    db $d3
    call nc, Call_02a_7f55
    adc h
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02a_7fc4
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor [hl]
    rst $08
    sbc a
    or a
    ret z

    pop bc
    call nc, Call_02a_7f81
    ld d, l
    ld d, [hl]
    adc [hl]
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, Call_02a_7fc8
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld a, a
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld c, a
    add c
    ld a, a
    xor b
    push bc
    call z, Call_02a_7fd0
    call $81c5
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    ret z

    sbc a
    ld d, l
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    adc $87
    call nc, Call_02a_557f
    ld e, [hl]
    adc h
    ld a, a
    db $d3
    rst $08
    jp nc, $d9d2

    add c
    ld a, a
    xor c
    ld d, l
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    call nc, $c97f
    call nc, $d387
    ld a, a
    rst $08
    push de
    jp nc, Jump_02a_7f55

    ret nc

    jp nc, $c4cf

    push de
    jp $d3d4


    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    or d
    push bc
    call nc, $d555
    jp nc, Jump_02a_7fce

    ret


    call nc, $d47f
    rst $08
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    xor c
    ld a, a
    ld d, l
    jp nz, $c7c5

    ld a, a
    reti


    rst $08
    push de
    jp nc, $d07f

    pop bc
    jp nc, $cfc4

    adc $81
    ld a, a
    ld d, l
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
    jp nc, $cd7f

    rst $08
    jp nc, $c54f

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, Call_02a_4f7f
    ld d, b
    ld bc, $cf45
    nop
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $d37f
    ret


    db $d3
    call nc, $d2c5
    ld a, a
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    ld e, h
    ld [hl], $7f
    ret


    db $d3
    ld c, a
    ld a, a
    call Call_02a_7fd9
    db $d3
    push bc
    call z, $8dc6
    push bc
    ret c

    ret nc

    call z, $d3cf
    ret


    rst $08
    ld d, l
    adc $81
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    db $d3
    set 1, c
    call z, Call_02a_7fcc
    ret


    db $d3
    ld a, a
    ld d, l
    db $d3
    rst $08
    ld a, a
    add $cf
    jp nc, $c5c3

    add $d5
    call z, Call_02a_7f8c
    jp nz, $d4d5

    ld a, a
    ld d, l
    adc h
    ld a, a
    ld d, h
    ld a, a
    call $d9c1
    ld a, a
    jp nz, Jump_02a_7fc5

    rst $00
    rst $08
    ret


    adc $55
    rst $00
    ld a, a
    call nc, Call_02a_7fcf
    pop bc
    ld a, a
    call nz, $c9d9
    adc $c7
    ld a, a
    db $d3
    call nc, $d4c1
    ld d, l
    push bc
    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $c37f

    rst $08
    call $c5d0
    call nc, $d4c9
    ret


    ld d, l
    rst $08
    adc $81
    ld a, a
    and d
    push bc
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, $d77f
    ret z

    ld d, l
    push bc
    adc $7f
    push de
    db $d3
    ret


    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor l
    jp nc, Jump_02a_528e

    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld a, a
    jp nc, $4fc5

    pop bc
    call z, $d9cc
    ld a, a
    ret z

    push bc
    call z, Call_02a_7fd0
    call $c3d5
    ret z

    ld a, a
    push de
    adc $55
    call nz, $d2c5
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    add a
    db $d3
    ld a, a
    ret nc

    jp nc, Jump_02a_55c1

    reti


    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    jp $c5cc


    jp nc, Jump_02a_7fcb

    ret


    adc $7f
    xor b
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
    call z, Call_02a_7f55
    db $d3
    rst $08
    jp $c5c9


    call nc, $81d9
    ld a, a
    ld d, [hl]
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    db $d3
    pop bc
    reti


    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $10
    ld c, a
    rst $08
    jp nc, $c1c4

    jp nz, $d5cf

    call nc, $cd7f
    reti


    ld a, a
    jp $d9d2


    ret


    adc $55
    rst $00
    ld a, a
    ld d, [hl]
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_02a_7f81
    adc [hl]
    ld a, a
    add $d2
    ret


    rst $00
    ret z

    call nc, $cec5
    push bc
    ld c, a
    call nz, Call_02a_7f81
    ld d, a
    ld bc, $cfc1
    nop
    ld c, a
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
    xor c
    call nc, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    add c
    ld a, a
    xor c
    call nc, Call_02a_4f7f
    ret


    db $d3
    ld a, a
    adc $cf
    call nc, $c37f
    call z, $c1c5
    jp nc, $d47f

    rst $08
    ld a, a
    call nc, $c855
    push bc
    ld a, a
    call nc, $d5d2
    push bc
    ld a, a
    add $c1
    jp Jump_02a_7fc5


    ld a, a
    rst $08
    add $7f
    ld d, l
    rst $00
    ret z

    rst $08
    db $d3
    call nc, Call_02a_547f
    add c
    ld a, a
    ld e, b
    ld bc, $cfc1
    nop
    ld c, a
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
    xor b
    ret


    call z, $d5cc
    add $c6
    ld a, a
    xor a
    jp nz, $c5d3

    jp nc, $c1d6

    call nc, $cf4f
    jp nc, $c37f

    pop bc
    adc $7f
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
    call nc, $d5d2
    push bc
    ld a, a
    add $c1
    jp Jump_02a_7fc5


    ld a, a
    ld d, l
    rst $08
    add $7f
    rst $00
    ret z

    rst $08
    db $d3
    call nc, Call_02a_7f81
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    rst $10
    ret


    call z, Call_02a_7fc4
    ld d, b
    ld bc, $cfc1
    nop
    ld c, a
    ld a, a
    jp z, $cdd5

    ret nc

    db $d3
    ld a, a
    rst $08
    push de
    call nc, Call_02a_7f81
    ld e, b
    nop
    ld a, a
    and h
    push bc
    call nc, $d5cf
    jp nc, $c67f

    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    jp nc, $c54f

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
    db $d3
    call z, $d7cf
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
    xor a
    res 0, c
    ld a, a
    xor c
    call nc, $d47f
    pop bc
    set 0, l
    db $d3
    ld a, a
    ld a, a
    sub l
    sub b
    ld c, a
    ld a, a
    reti


    push bc
    adc $c6
    rst $08
    jp nc, $c17f

    ld a, a
    jp $c9c8


    call z, Call_02a_7fc4
    ld a, a
    ld d, l
    call nc, Call_02a_7fcf
    sub $c9
    db $d3
    ret


    call nc, Call_02a_7f8e
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    ld d, l
    sub $c9
    db $d3
    ret


    call nc, Call_02a_7f9f
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    push bc
    reti


    ld a, a
    adc [hl]
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    call $cecf
    push bc
    ld c, a
    reti


    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and a
    rst $08
    rst $08
    call nz, Call_02a_7f81
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    jp $cccf


    ld c, a
    call z, $c3c5
    call nc, $957f
    sub b
    ld a, a
    reti


    push bc
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and e
    rst $08
    call Call_02a_7fc5
    pop bc
    rst $00
    pop bc
    ret


    adc $8c
    ld a, a
    ret nc

    call z, $c1c5
    ld c, a
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor [hl]
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    db $d3
    ret nc

    push bc
    adc $c4
    ld a, a
    pop bc
    ld a, a
    jp $cf4f


    ret


    adc $7f
    pop bc
    adc $c4
    push bc
    adc $d4
    push bc
    jp nc, $c97f

    adc $d4
    rst $08
    ld d, l
    ld a, a
    add $d2
    rst $08
    call $c27f
    pop bc
    jp Jump_02a_7fcb


    call nz, $cfcf
    jp nc, Jump_02a_7f8e

    ld d, l
    jp nz, $d4d5

    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    adc [hl]
    ld a, a
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    set 1, [hl]
    rst $08
    rst $10
    ld a, a
    pop bc
    call $c5c2
    jp nc, Jump_02a_7f9f

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
    call nc, Call_02a_4f7f
    ret


    adc $7f
    call nc, $c9c8
    db $d3
    ld a, a
    ret


    adc $d3
    call nc, $d4c9
    push de
    call nc, Call_02a_55c5
    ld a, a
    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, $c9cf
    adc $c7
    ld d, l
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    call nc, Call_02a_7fcf
    call $cbc1
    push bc
    ld a, a
    ld d, l
    ret nc

    pop bc
    call z, $c5c1
    rst $08
    adc l
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    adc h
    ld a, a
    ld d, l
    rst $10
    ret z

    ret


    jp Jump_02a_7fc8


    rst $10
    push bc
    jp nc, Jump_02a_7fc5

    pop bc
    call nz, $ccd5
    call nc, Call_02a_55c5
    jp nc, $d4c1

    push bc
    call nz, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    call $c5c2
    ld d, l
    jp nc, $8c7f

    ld a, a
    call nc, Call_02a_7fcf
    jp nc, $d6c5

    ret


    sub $c5
    ld a, a
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    pop bc
    call $c5c2
    jp nc, Jump_02a_7f8c

    call z, $cbc9
    push bc
    ld a, a
    ld c, a
    pop bc
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_02a_7f8c
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, Jump_02a_55c5

    db $d3
    ret


    adc $7f
    jp $cecf


    call nz, $cec5
    db $d3
    pop bc
    call nc, $cfc9
    adc $7f
    ld d, l
    ld a, a
    call $c4c1
    push bc
    ld a, a
    rst $08
    add $7f
    jp z, $c9d5

    jp Jump_02a_7fc5


    ld a, a
    add $55
    jp nc, $cdcf

    ld a, a
    pop bc
    ld a, a
    rst $10
    rst $08
    push de
    adc $c4
    ld a, a
    call nc, $c5d2
    push bc
    ld a, a
    ld d, l
    call z, $cecf
    rst $00
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    rst $00
    rst $08
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    ret


    adc $cb
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    sub $c5
    jp nc, Jump_02a_7fd9

    call $d54f
    jp $81c8


    ld a, a
    call nc, $c1c8
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    sub $c5
    ld d, l
    jp nc, Jump_02a_7fd9

    call $c3d5
    ret z

    add c
    ld a, a
    xor c
    ld a, a
    jp $cec1


    ld a, a
    call z, $55cf
    rst $08
    bit 7, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $cecf

    push bc
    db $d3
    ld a, a
    rst $08
    ld d, l
    add $7f
    xor l
    pop bc
    jp z, $d3c5

    call nc, Call_02a_7fd9
    call nz, $c1d2
    rst $00
    rst $08
    adc $7f
    ld d, l
    rst $00
    rst $08
    call nz, $d77f
    ret


    call nc, Call_02a_7fc8
    jp nc, $d6c5

    push bc
    jp nc, $cec5

    jp $c555


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    ret


    db $d3
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
    ld a, a
    pop bc
    ld a, a
    ld c, a
    db $d3
    push bc
    jp $c5d2


    call nc, Call_02a_7f8e
    jp nz, $d4d5

    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    rst $00
    push bc
    adc $c5
    call nc, $c3c9
    ld a, a
    add $c1
    jp $cfd4


    jp nc, $cf7f

    add $55
    ld a, a
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $d27f
    push bc
    call $c155
    ret


    adc $c5
    call nz, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    call $c5c2
    ld d, l
    jp nc, $817f

    ld a, a
    and c
    call nz, $c9c4
    call nc, $cfc9
    adc $c1
    call z, $d9cc
    adc h
    ld d, l
    ld a, a
    adc h
    ld a, a
    xor c
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


    ld d, l
    adc $c7
    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    push de
    jp nc, $c87f

    push bc
    call z, $81d0
    ld d, l
    ld a, a
    or h
    pop bc
    set 0, l
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    call nc, Call_02a_7fcf
    call nc, $c5c8
    ld d, l
    ld a, a
    ret


    adc $d3
    call nc, $d4c9
    push de
    call nc, Call_02a_7fc5
    adc [hl]
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, l
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    adc $7f
    ret


    adc $d6
    push bc
    db $d3
    call nc, $c7c9
    pop bc
    ld d, l
    call nc, $cfc9
    adc $81
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
    call nz, $d37f
    ld c, a
    push bc
    jp $c5d2


    call nc, $c17f
    call $c5c2
    jp nc, $c67f

    jp nc, $cdcf

    ld a, a
    ld d, l
    pop bc
    adc $c3
    call z, Call_02a_7fc5
    add c
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    call nc, $cfcf
    ld a, a
    call $c3d5
    ret z

    ld a, a
    call z, $c7d5
    ld c, a
    rst $00
    pop bc
    rst $00
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    xor b
    ret


    db $d3
    db $d3
    add c
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    ld c, a
    adc $c7
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $c17f
    call $c5c2
    jp nc, $c97f

    db $d3
    ld d, l
    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    push de
    jp nc, $c87f

    push bc
    call z, $81d0
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_02a_7fc5

    db $d3
    ret z

    rst $08
    rst $10
    db $d3
    ld a, a
    sub d
    ld a, a
    rst $08
    add $7f
    ld c, a
    pop bc
    adc $c3
    ret


    push bc
    adc $d4
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, Call_02a_7fd3
    ld d, l
    ld d, h
    ld a, a
    call nc, Call_02a_7fcf
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, $81cc
    ld a, a
    ld d, a
    rst $10
    ld d, l
    ret z

    ret


    jp Jump_02a_7fc8


    pop bc
    jp nc, Jump_02a_7fc5

    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld d, l
    ld a, a
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    adc [hl]
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
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02a_7f00:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02a_7f4f:
Jump_02a_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_02a_7f55:
Jump_02a_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02a_7f7f:
    nop
    nop

Call_02a_7f81:
Jump_02a_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02a_7f8c:
Jump_02a_7f8c:
    nop
    nop

Call_02a_7f8e:
Jump_02a_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02a_7f9f:
Jump_02a_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02a_7fc1:
Jump_02a_7fc1:
    nop
    nop
    nop

Call_02a_7fc4:
Jump_02a_7fc4:
    nop

Call_02a_7fc5:
Jump_02a_7fc5:
    nop
    nop
    nop

Call_02a_7fc8:
Jump_02a_7fc8:
    nop
    nop
    nop

Call_02a_7fcb:
Jump_02a_7fcb:
    nop

Call_02a_7fcc:
Jump_02a_7fcc:
    nop
    nop

Jump_02a_7fce:
    nop

Call_02a_7fcf:
    nop

Call_02a_7fd0:
    nop
    nop
    nop

Call_02a_7fd3:
Jump_02a_7fd3:
    nop

Call_02a_7fd4:
Jump_02a_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_02a_7fd9:
Jump_02a_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
