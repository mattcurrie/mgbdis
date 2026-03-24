; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $023", ROMX[$4000], BANK[$23]

    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    ld a, a
    rst $00
    ld c, a
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_023_7fcf
    call nc, $c5c8
    ld a, a
    jp nc, $c3cf

    bit 7, a
    ld d, l
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    call nc, $ced5
    adc $c5
    call z, Call_023_7f9f
    ld d, l
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_023_7fcf
    adc $cf
    call nc, $c17f
    rst $00
    jp nc, $c5c5

    ld c, a
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_023_7fcf
    adc $cf
    call nc, $c17f
    rst $00
    jp nc, $c5c5

    ld c, a
    sbc a
    ld a, a
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
    jp nc, Jump_023_7fc5

    ld c, a
    add $cf
    jp nc, $c77f

    ret


    jp nc, $d3cc

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
    ld a, a
    call nc, $c14f
    call z, $cec5
    call nc, $cf7f
    add $7f
    ld d, h
    adc [hl]
    ld a, a
    rst $10
    rst $08
    jp nc, $cb55

    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    pop bc
    call nz, $c5c4
    call nz, $d67f
    ret


    rst $00
    rst $08
    ld d, l
    push de
    jp nc, Jump_000_0057

    ld a, a
    xor [hl]
    rst $08
    adc h
    adc $cf
    adc [hl]
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c17f
    ld c, a
    jp $cfc3


    call $ccd0
    ret


    db $d3
    ret z

    ld a, a
    ld e, b
    nop
    ld a, a
    xor [hl]
    rst $08
    adc h
    adc $cf
    adc [hl]
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $c17f
    ld c, a
    jp $cfc3


    call $ccd0
    ret


    db $d3
    ret z

    ld a, a
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
    jp z, $d3d5

    call nc, $c97f
    adc $7f
    call nc, $c94f
    call $81c5
    ld a, a
    adc h
    ld a, a
    xor c
    add a
    call $ca7f
    push de
    db $d3
    call nc, $c67f
    ld d, l
    push bc
    push bc
    call z, $c27f
    rst $08
    jp nc, $c4c5

    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    xor l
    pop bc
    call z, Call_023_7fc5
    call $cecf
    db $d3
    call nc, $d2c5
    ld a, a
    ld a, a
    ret


    ld c, a
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
    jp nc, $d955

    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    jp $cec1


    ld a, a
    ld d, l
    jp nz, $c1d2

    sub $c5
    call z, Call_023_7fd9
    add $c9
    rst $00
    ret z

    call nc, $c17f
    rst $00
    pop bc
    ld d, l
    ret


    adc $d3
    call nc, $c87f
    ret


    call $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld a, a
    reti


    push bc
    call nc, $8c4f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld a, a
    reti


    push bc
    call nc, $8155
    ld a, a
    xor c
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c27f
    push bc
    call z, $c5c9
    sub $c5
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    ld d, [hl]
    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call nz, $d3c9
    ret nc

    push bc
    pop bc
    jp nc, $c4c5

    ld d, l
    adc [hl]
    ld a, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld a, a
    reti


    push bc
    call nc, $8c4f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    ld a, a
    reti


    push bc
    call nc, $8155
    ld a, a
    xor c
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $c27f
    push bc
    call z, $c5c9
    sub $c5
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    ld d, [hl]
    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call nz, $d3c9
    ret nc

    push bc
    pop bc
    jp nc, $c4c5

    ld d, l
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    ld c, a
    pop bc
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    jp nz, $d9cf

    add c
    ld a, a
    or a
    rst $08
    push de
    ld d, l
    call z, Call_023_7fc4
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, Call_023_7fcf
    jp $55cf


    call Call_023_7fc5
    pop bc
    adc $c4
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, Call_023_7f9f
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    and d
    push bc
    ret


    adc $c7
    ld a, a
    db $d3
    call nc, $d24f
    rst $08
    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_023_7f81
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


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
    ld e, b
    nop
    ld a, a
    and l
    sub $c5
    jp nc, Jump_023_7fd9

    call $d2cf
    adc $c9
    adc $c7
    ld a, a
    reti


    rst $08
    ld c, a
    push de
    ld a, a
    rst $00
    push bc
    call nc, $d57f
    ret nc

    ld a, a
    sub $c5
    jp nc, Jump_023_7fd9

    push bc
    pop bc
    jp nc, $cc55

    reti


    adc h
    ld a, a
    or b
    push de
    ret nc

    pop bc
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $cf
    db $d3
    ld d, l
    call nc, $d2c5
    push bc
    call nz, $817f
    ld a, a
    adc h
    ld a, a
    ret z

    pop bc
    call nc, $c8c3
    push bc
    db $d3
    ld d, l
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    push bc
    adc $c4
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    adc $7f
    rst $08
    jp nc, $c5c4

    jp nc, $d47f

    rst $08
    ld a, a
    rst $00
    push bc
    call nc, Call_023_4f7f
    db $d3
    call nc, $cfd2
    adc $c7
    adc h
    ld a, a
    ld d, h
    adc h
    ld a, a
    ld a, a
    ret


    call nc, $557f
    ret


    db $d3
    ld a, a
    adc $cf
    call nc, $c67f
    push bc
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    ld a, a
    add $55
    rst $08
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_023_7fcf
    add $c9
    adc $c4
    ld a, a
    ret


    adc $55
    db $d3
    push bc
    jp $d3d4


    ld a, a
    rst $08
    adc $cc
    reti


    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $a97f
    ld a, a
    rst $00
    push bc
    call nc, Call_023_4f7f
    push de
    ret nc

    ld a, a
    sub $c5
    jp nc, Jump_023_7fd9

    push bc
    pop bc
    jp nc, $d9cc

    ld a, a
    push bc
    sub $c5
    ld d, l
    jp nc, $c4d9

    pop bc
    reti


    ld a, a
    add $cf
    jp nc, Jump_023_7f9f

    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c47f
    rst $08
    ld a, a
    xor c
    ld a, a
    rst $00
    ld c, a
    push bc
    call nc, $d57f
    ret nc

    ld a, a
    sub $c5
    jp nc, Jump_023_7fd9

    push bc
    pop bc
    jp nc, $d9cc

    ld a, a
    ld d, l
    push bc
    sub $c5
    jp nc, $c4d9

    pop bc
    reti


    ld a, a
    add $cf
    jp nc, Jump_023_7f9f

    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    ret z

    push bc
    jp nc, $c54f

    adc h
    ld a, a
    ret z

    pop bc
    jp Jump_023_7fc5


    pop bc
    ld a, a
    call nc, $d9d2
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, $87c5
    db $d3
    ld c, a
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_023_7fd4

    ret


    adc $7f
    call $d5cf
    adc $d4
    pop bc
    ret


    ld d, l
    adc $7f
    ret


    db $d3
    ld a, a
    jp nz, $cfd2

    pop bc
    jp nc, $8cc4

    ld a, a
    db $d3
    rst $08
    ld a, a
    push bc
    ld d, l
    sub $c5
    adc $7f
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c555
    call nz, Call_023_7f8c
    ret z

    push bc
    ld a, a
    db $d3
    call z, $cfc1
    ld a, a
    call z, $d5c1
    rst $00
    ret z

    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    or a
    ret z

    reti


    adc h
    ld a, a
    call z, $cfcf
    ld c, a
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    adc [hl]
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    or a
    ret z

    reti


    adc h
    ld a, a
    call z, $cfcf
    ld c, a
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    adc [hl]
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    push de
    jp nc, $cc7f

    rst $08
    sub $c5
    call z, Call_023_7fd9
    ret


    adc $d3
    push bc
    jp $d44f


    ld a, a
    add $cf
    rst $08
    call z, Call_023_7f81
    rst $00
    rst $08
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    pop bc
    call nz, $c1d6
    adc $d4
    pop bc
    rst $00
    push bc
    ld a, a
    rst $08
    add $4f
    ld a, a
    ld d, h
    adc h
    ld a, a
    call nz, $c5cf
    db $d3
    ld a, a
    adc $cf
    call nc, $cb7f
    adc $55
    rst $08
    rst $10
    ld a, a
    call nc, $c5c8
    db $d3
    push bc
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    db $d3
    ld a, a
    ld d, l
    pop bc
    jp nc, Jump_023_7fc5

    ret


    adc $d3
    push bc
    jp $d3d4


    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    push de
    jp nc, $c97f

    adc $d3
    push bc
    jp $d3d4


    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    xor a
    push de
    jp nc, $c97f

    adc $d3
    push bc
    jp $d3d4


    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

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
    call z, Call_023_577f
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

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
    call z, Call_023_577f
    nop
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, $d37f

    call nc, $4fc1
    call nc, $cfc9
    adc $7f
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $d2c1
    push bc
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    call nc, Call_023_4fcf
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    set 1, c
    adc $c4
    ld a, a
    rst $08
    add $7f
    ret nc

    call z, Call_023_55c1
    jp Jump_023_7fc5


    and c
    jp nc, Jump_023_7fc5

    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    add $c1
    adc $c1
    ld d, l
    call nc, $c3c9
    sbc a
    ld a, a
    ld d, [hl]
    call nc, $c5c8
    adc $7f
    or a
    rst $08
    push de
    call z, Call_023_55c4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call nc, Call_023_7fcf
    push bc
    adc $ca
    rst $08
    ld d, l
    reti


    ld a, a
    call Call_023_7fd9
    jp $cccf


    call z, $c3c5
    call nc, $cfc9
    adc $9f
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    xor c
    ld a, a
    jp $cdcf


    push bc
    ld a, a
    jp nz, $c3c1

    bit 7, a
    ret z

    ld c, a
    rst $08
    call Call_023_7fc5
    adc [hl]
    ld a, a
    call nc, $c5c8
    jp nc, Jump_023_7fc5

    rst $10
    ret


    call z, Call_023_7fcc
    ld d, l
    jp nz, Jump_023_7fc5

    call $d2cf
    push bc
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ld d, l
    ld d, h
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    xor [hl]
    push bc
    sub $c5
    jp nc, $c67f

    ld c, a
    push bc
    push bc
    call z, $d77f
    jp nc, $cecf

    rst $00
    push bc
    call nz, Call_023_7f81
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    xor [hl]
    push bc
    sub $c5
    jp nc, $c67f

    ld c, a
    push bc
    push bc
    call z, $d77f
    jp nc, $cecf

    rst $00
    push bc
    call nz, Call_023_7f81
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    xor b
    pop bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    adc h
    xor b
    pop bc
    add c
    ld a, a
    xor b
    pop bc
    adc h
    xor b
    pop bc
    add c
    ld a, a
    ld c, a
    ld d, [hl]
    adc h
    xor b
    pop bc
    adc h
    xor b
    pop bc
    add c
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
    adc h
    xor b
    pop bc
    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    pop bc
    ld c, a
    jp $d5d4


    pop bc
    call z, $d9cc
    ld a, a
    ld d, [hl]
    adc h
    rst $10
    push bc
    ld a, a
    ret z

    pop bc
    sub $55
    push bc
    ld a, a
    push bc
    pop bc
    call nc, $cec5
    ld a, a
    db $d3
    rst $08
    call Call_023_7fc5
    call z, $d5c1
    rst $00
    ld d, l
    ret z

    ld a, a
    call $d3d5
    ret z

    jp nc, $cfcf

    call SerialTransferCompleteInterrupt
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    xor b
    pop bc
    adc h
    xor b
    pop bc
    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    pop bc
    ld c, a
    jp $d5d4


    pop bc
    call z, $d9cc
    ld a, a
    ld d, [hl]
    rst $10
    push bc
    ld a, a
    ret z

    pop bc
    sub $c5
    ld d, l
    ld a, a
    push bc
    pop bc
    call nc, $cec5
    ld a, a
    db $d3
    rst $08
    call Call_023_7fc5
    call z, $d5c1
    rst $00
    ret z

    ld d, l
    ld a, a
    call $d3d5
    ret z

    jp nc, $cfcf

    call SerialTransferCompleteInterrupt
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
    and c
    jp nc, Jump_023_7fc5

    reti


    rst $08
    push de
    ld c, a
    ld a, a
    push bc
    adc $ca
    rst $08
    reti


    ret


    adc $c7
    ld a, a
    call Call_023_7fd9
    ld d, h
    sbc a
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    call nz, Call_023_7fcf
    adc $cf
    call nc, $cc7f
    ret


    set 0, l
    ld a, a
    db $d3
    rst $08
    ld c, a
    call $cfc5
    adc $c5
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, $d47f

    ret z

    ld d, l
    pop bc
    adc $7f
    call Call_023_7fc5
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    call z, $d4c9
    ld c, a
    call nc, $c5cc
    ld a, a
    jp nz, $c2d9

    reti


    ld a, a
    ld d, h
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    call z, $d4c9
    ld c, a
    call nc, $c5cc
    ld a, a
    jp nz, $c2d9

    reti


    ld a, a
    ld d, h
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    ld a, a
    rst $08
    jp $c1c3


    call nc, $cfc9
    adc $c1
    call z, $d9cc
    ld a, a
    ld c, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_023_7fcf
    rst $00
    reti


    call $c1ce
    db $d3
    ret


    push de
    call $557f
    ld d, h
    add c
    ld a, a
    ld d, [hl]
    adc h
    ld d, [hl]
    ld a, a
    call z, $d3cf
    push bc
    adc h
    jp nz, $d555

    call nc, Call_023_577f
    nop
    ld a, a
    or a
    push bc
    call z, Call_023_7fcc
    ld d, [hl]
    add c
    ld a, a
    call nc, $c5c8
    jp nc, Jump_023_7fc5

    pop bc
    ld c, a
    jp nc, Jump_023_7fc5

    add $c1
    adc $c1
    call nc, $c3c9
    db $d3
    ld a, a
    rst $08
    adc $7f
    db $d3
    push de
    ld d, l
    jp Jump_023_7fc8


    pop bc
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $cf
    push de
    db $d3
    ld a, a
    ld d, l
    rst $10
    pop bc
    reti


    adc [hl]
    ld a, a
    call nz, $c5cf
    db $d3
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    ld d, l
    ret


    call nc, Call_023_7f9f
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld c, a
    ld a, a
    call nc, $c1d2
    ret


    adc $c5
    call nz, Call_023_7f8c
    jp nz, $d4d5

    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld c, a
    ld a, a
    call nc, $c1d2
    ret


    adc $c5
    call nz, Call_023_7f8c
    jp nz, $d4d5

    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    add $d2
    push bc
    db $d3
    ret z

    ld a, a
    call nc, $4fc8
    push bc
    ld a, a
    pop bc
    ret


    jp nc, $c97f

    adc $7f
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $55
    ld a, a
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
    pop bc
    ret


    jp nc, $c97f

    adc $7f
    call $d5cf
    adc $d4
    ld c, a
    pop bc
    ret


    adc $7f
    rst $10
    pop bc
    db $d3
    ld a, a
    ret


    adc $c8
    pop bc
    call z, $c4c5
    ld a, a
    call nc, $cf55
    rst $08
    ld a, a
    call $c3d5
    ret z

    adc h
    ld a, a
    call Call_023_7fd9
    db $d3
    call nc, $cdcf
    pop bc
    ld d, l
    jp Jump_023_7fc8


    add $c5
    push bc
    call z, Call_023_7fd3
    jp nz, $cfcc

    pop bc
    call nc, $c4c5
    ld a, a
    ld d, l
    pop bc
    add $d4
    push bc
    jp nc, $cf7f

    sub $c5
    jp nc, $cec9

    ret z

    pop bc
    call z, $cec9
    ld d, l
    rst $00
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
    ret z

    adc h
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld c, a
    ld a, a
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

    add c
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld c, a
    ld a, a
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

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    add $cf
    jp nc, $c17f

    ld a, a
    call z, $cecf
    ld c, a
    rst $00
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    xor c
    ld a, a
    call nz, $c4c9
    ld a, a
    adc $cf
    call nc, $557f
    rst $00
    rst $08
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    ld d, l
    adc $cf
    push de
    db $d3
    ld a, a
    rst $10
    pop bc
    reti


    adc h
    ld a, a
    adc h
    ld a, a
    pop bc
    db $d3
    ld a, a
    ret


    add $55
    ld a, a
    xor c
    ld a, a
    pop bc
    call $c17f
    adc $7f
    pop bc
    adc $c1
    push bc
    call $c1c9
    ld a, a
    ld d, l
    ret nc

    pop bc
    call nc, $c5c9
    adc $d4
    adc [hl]
    ld d, a
    nop
    ld a, a
    xor l
    rst $08
    push de
    adc $d4
    pop bc
    ret


    adc $cf
    push de
    db $d3
    ld a, a
    ld d, h
    adc h
    ld c, a
    ld a, a
    pop bc
    call z, Call_023_7fcc
    pop bc
    jp nc, Jump_023_7fc5

    sub $c5
    jp nc, Jump_023_7fd9

    jp nz, $c7c9

    ld d, l
    ld a, a
    ld d, [hl]
    ld d, [hl]
    adc [hl]
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    ld d, l
    rst $08
    rst $08
    call nz, $c97f
    add $7f
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ld d, l
    ld d, h
    adc h
    ld a, a
    ld a, a
    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    ret nc

    ret


    adc $cb
    ld a, a
    ld d, l
    ret nc

    pop bc
    call nc, $c5d4
    jp nc, $8ece

    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    add $c5
    push bc
    call z, Call_023_7fd3
    adc $cf
    call nc, $d37f
    rst $08
    ld c, a
    ld a, a
    rst $10
    push bc
    call z, Call_023_7fcc
    adc h
    ld a, a
    adc $cf
    ld a, a
    pop bc
    adc $d9
    ld a, a
    rst $00
    rst $08
    ld d, l
    rst $08
    call nz, $cd7f
    push bc
    call nc, $cfc8
    call nz, Call_023_587f
    adc [hl]
    ld a, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    add $c5
    push bc
    call z, Call_023_7fd3
    adc $cf
    ld c, a
    call nc, $d37f
    rst $08
    ld a, a
    rst $10
    push bc
    call z, Call_023_7fcc
    adc h
    ld a, a
    adc $cf
    ld a, a
    pop bc
    adc $55
    reti


    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $cd7f
    push bc
    call nc, $cfc8
    call nz, Call_023_587f
    adc [hl]
    ld a, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    jp $d6c1


    push bc
    ld a, a
    rst $08
    add $7f
    and h
    push bc
    jp nc, Jump_023_4fc7

    push de
    call nz, Call_023_7fc1
    ld d, a
    nop
    ld a, a
    or [hl]
    ret


    jp $cfd4


    jp nc, Jump_023_7fd9

    rst $08
    jp nc, $c47f

    push bc
    add $c5
    pop bc
    ld c, a
    call nc, Call_023_7f8c
    add $c9
    rst $00
    ret z

    call nc, $c97f
    call nc, $cf7f
    push de
    call nc, Call_023_7f81
    ld d, l
    ld d, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $cd7f
    reti


    ld a, a
    call z, Call_023_4fc9
    add $c5
    add c
    ld a, a
    xor h
    ret


    add $c5
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $557f
    jp nz, $d4c5

    call nc, $cec9
    rst $00
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_023_7f81
    call nc, $c4cf
    pop bc
    reti


    ld a, a
    xor c
    add a
    call $cf7f
    ld c, a
    push de
    call nc, $cf7f
    add $7f
    call z, $c3d5
    res 0, c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_023_7f81
    call nc, $c4cf
    pop bc
    reti


    ld a, a
    xor c
    add a
    call $cf7f
    ld c, a
    push de
    call nc, $cf7f
    add $7f
    call z, $c3d5
    res 0, c
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
    call nc, $cf4f
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ld d, l
    ret


    rst $08
    adc $8c
    ld a, a
    xor c
    ld a, a
    call nz, $c4c9
    ld a, a
    adc $cf
    call nc, $c37f
    ret z

    ld d, l
    rst $08
    rst $08
    db $d3
    push bc
    ld a, a
    pop bc
    adc $d9
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld d, l
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
    xor c
    ld a, a
    pop bc
    call $c67f
    jp nc, Jump_023_4fc9

    rst $00
    ret z

    call nc, $cec5
    push bc
    call nz, $d47f
    rst $08
    ld a, a
    jp nz, Jump_023_7fc5

    call nz, $c6c5
    ld d, l
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    xor c
    ld a, a
    ld d, h
    ld a, a
    jp $cec1


    add a
    call nc, Call_023_7f55
    call nz, Call_023_7fcf
    call z, $cbc9
    push bc
    ld a, a
    call nc, $c1c8
    call nc, Call_000_0057
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    or a
    ret z

    reti


    ld a, a
    call nz, $cecf
    add a
    call nc, Call_023_7f4f
    reti


    rst $08
    push de
    ld a, a
    jp nz, $ccc5

    ret


    push bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    jp $cec1


    ld a, a
    rst $10
    ret


    adc $9f
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    or a
    ret z

    reti


    ld a, a
    call nz, $cecf
    add a
    call nc, Call_023_7f4f
    reti


    rst $08
    push de
    ld a, a
    jp nz, $ccc5

    ret


    push bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ld d, l
    jp $cec1


    ld a, a
    rst $10
    ret


    adc $9f
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    pop bc
    jp $c9d4


    adc $c7
    ld a, a
    ret


    ld c, a
    adc $7f
    pop bc
    ld a, a
    db $d3
    call z, $c3c9
    bit 7, a
    rst $10
    pop bc
    reti


    ld a, a
    call nc, Call_023_7fcf
    ld d, l
    ld d, h
    add c
    ld a, a
    call nz, Call_023_7fcf
    call nc, $c1c8
    call nc, $c17f
    db $d3
    ld a, a
    reti


    ld d, l
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
    and h
    rst $08
    ld a, a
    call nc, $c1c8
    call nc, $c17f
    db $d3
    ld a, a
    xor c
    ld a, a
    call z, $cbc9
    ld c, a
    push bc
    add c
    ld a, a
    adc $c5
    sub $c5
    jp nc, $d27f

    push bc
    rst $00
    jp nc, $d4c5

    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $87ce
    ld c, a
    call nc, $c27f
    push bc
    ld a, a
    db $d3
    rst $08
    add c
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call $d3d5
    call nc, $87ce
    ld c, a
    call nc, $c27f
    push bc
    ld a, a
    db $d3
    rst $08
    add c
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    xor c
    db $d3
    ld a, a
    call Call_023_7fd9
    push bc
    call z, Call_023_4fc5
    jp $d2d4


    ret


    jp $d4c9


    reti


    ld a, a
    db $d3
    pop bc
    add $c5
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    add $cf
    jp nc, $cfc7

    call nc, $c17f
    ld a, a
    rst $10
    rst $08
    ld c, a
    jp nc, $81c4

    ld a, a
    and l
    jp $cecf


    rst $08
    call $dac9
    reti


    ld a, a
    rst $08
    adc $7f
    ld d, l
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $d4c9


    reti


    adc h
    ret nc

    call z, $c1c5
    db $d3
    ld d, l
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $d2c5
    jp nc, $c2c9

    call z, Call_023_7fc5
    call nc, $cf4f
    ld a, a
    call z, $d4c5
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    call z, Call_023_7fc4
    call $cec1
    ld d, l
    ld a, a
    ld a, a
    call nz, Call_023_7fcf
    pop bc
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    ld d, l
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    call nc, $d2c5
    jp nc, $c2c9

    call z, Call_023_7fc5
    call nc, $cf4f
    ld a, a
    call z, $d4c5
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    call z, Call_023_7fc4
    call $cec1
    ld d, l
    ld a, a
    ld a, a
    call nz, Call_023_7fcf
    pop bc
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    push bc
    ld d, l
    db $d3
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    jp z, $d3d5

    call nc, $c68d
    ret


    adc $c9
    db $d3
    ld c, a
    ret z

    push bc
    call nz, $c28d
    push bc
    jp $cdcf


    push bc
    ld a, a
    ld d, h
    adc h
    ld d, l
    ld e, l
    adc h
    jp nz, $d4d5

    adc h
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    ld d, l
    sub $c5
    ld a, a
    jp $cecf


    add $c9
    call nz, $cec5
    jp Jump_023_7fc5


    call nc, Call_023_7fcf
    ld d, l
    rst $10
    ret


    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, $c5c8
    jp nc, $8cc5

    ld a, a
    ld c, a
    reti


    rst $08
    push de
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    adc h
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    ld c, a
    call nc, $d47f
    ret z

    ret


    db $d3
    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    and h
    rst $08
    push bc
    db $d3
    adc $55
    add a
    call nc, Call_023_7f7f
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, h
    ld a, a
    reti


    push bc
    ld d, l
    call nc, Call_023_7f9f
    ld e, b
    nop
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    adc h
    ld a, a
    call z, $cfcf
    bit 7, a
    pop bc
    ld c, a
    call nc, $d47f
    ret z

    ret


    db $d3
    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    and h
    rst $08
    push bc
    db $d3
    adc $55
    add a
    call nc, Call_023_7f7f
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ld d, h
    ld a, a
    reti


    push bc
    ld d, l
    call nc, Call_023_7f9f
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    xor b
    pop bc
    add c
    ld a, a
    xor c
    ld a, a
    adc $c5
    sub $c5
    jp nc, $cc7f

    ld c, a
    rst $08
    db $d3
    push bc
    ld a, a
    db $d3
    rst $08
    ld a, a
    add $c1
    jp nc, Jump_023_7f81

    ld d, a
    nop
    ld a, a
    and e
    rst $08
    adc $d4
    push bc
    db $d3
    call nc, $c97f
    db $d3
    ld a, a
    call nz, $d4c5
    push bc
    jp nc, $cd4f

    ret


    adc $c5
    call nz, $c27f
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $c3d5
    bit 2, l
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    pop bc
    call nc, $d47f
    ret


    call $81c5
    ld a, a
    ret


    add $55
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_023_7fcf
    call nc, $c9c8
    adc $cb
    ld a, a
    db $d3
    rst $08
    adc h
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret


    call z, Call_023_7fcc
    db $d3
    ret


    adc $cb
    ld a, a
    ret


    adc $55
    call nc, Call_023_7fcf
    pop bc
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ret


    sub $c5
    ld a, a
    ret nc

    rst $08
    db $d3
    ret


    ld d, l
    call nc, $cfc9
    adc $8e
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    add $c9
    jp nc, $d4d3

    ld c, a
    ld a, a
    call nc, $cdc9
    push bc
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $d3cf
    push bc
    add c
    ld a, a
    ld d, l
    nop
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    add $c9
    jp nc, $d4d3

    ld c, a
    ld a, a
    call nc, $cdc9
    push bc
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    nop
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    adc $87
    call nc, $d77f
    ret


    adc $7f
    ld c, a
    ld d, [hl]
    adc h
    ld a, a
    push de
    adc $d4
    ret


    call z, $ce7f
    rst $08
    rst $10
    adc [hl]
    ld d, a
    nop
    ld a, a
    and e
    rst $08
    adc $d4
    push bc
    db $d3
    call nc, $c97f
    db $d3
    ld a, a
    call nz, $d4c5
    push bc
    jp nc, $cd4f

    ret


    adc $c5
    call nz, $c27f
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $c3d5
    bit 2, l
    ld a, a
    pop bc
    call nc, $d47f
    ret z

    pop bc
    call nc, $d47f
    ret


    call $81c5
    ld a, a
    ret


    add $55
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, Call_023_7fcf
    call nc, $c9c8
    adc $cb
    ld a, a
    db $d3
    rst $08
    adc h
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    rst $10
    ret


    call z, Call_023_7fcc
    db $d3
    ret


    adc $cb
    ld a, a
    ret


    adc $55
    call nc, Call_023_7fcf
    pop bc
    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ret


    sub $c5
    ld a, a
    ret nc

    rst $08
    db $d3
    ret


    ld d, l
    call nc, $cfc9
    adc $8e
    ld a, a
    ld d, a
    nop
    ld a, a

Call_023_4f7f:
Jump_023_4f7f:
    ld d, [hl]
    adc h

Call_023_4f81:
    ld a, a
    call nz, $cdc1
    adc $81
    ld a, a
    db $d3
    call nc, $ccc9

Call_023_4f8c:
    call z, Call_023_4f7f
    call z, $d3cf
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    call nz, $cdc1
    adc $81
    ld a, a
    db $d3
    call nc, $ccc9
    call z, Call_023_4f7f
    call z, $d3cf
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $d47f
    ret z

    push bc
    ld a, a
    call $d3cf
    call nc, $d37f
    call nc, Call_023_4fd2

Call_023_4fc2:
    rst $08
    adc $c7

Call_023_4fc5:
Jump_023_4fc5:
    ld a, a
    ret


Jump_023_4fc7:
    adc $7f

Call_023_4fc9:
Jump_023_4fc9:
    call Call_023_7fd9
    jp $c1cc


Call_023_4fcf:
Jump_023_4fcf:
    db $d3
    db $d3
    add c

Call_023_4fd2:
    ld a, a

Jump_023_4fd3:
    ld d, l
    and l
    sub $c5
    jp nc, Jump_023_7fd9

    call $d2cf
    adc $c9
    adc $c7
    adc h
    ld a, a
    xor c
    ld a, a
    ld d, l
    call nz, Call_023_7fcf
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, Call_023_7f7f
    rst $08
    jp $c1c3


    call nc, $cfc9
    adc $c1
    call z, $cc4f
    reti


    ld a, a
    call nz, $d7cf
    adc $7f
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    ld d, l
    ret z

    ret


    call z, $8ccc
    ld a, a
    jp $d0c1


    call nc, $d2d5
    push bc
    db $d3
    ld a, a
    call nc, Call_023_55c8
    push bc
    ld a, a
    add $c1
    call nc, $d9d4
    ld a, a
    ld d, h
    adc h
    ld d, [hl]
    adc h
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_023_7f8c

    ret


    db $d3
    adc $87
    call nc, Call_023_7f55
    ret


    call nc, Call_023_7f9f
    ld d, a
    nop
    ld a, a
    xor b
    ret


    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    push de
    adc $4f
    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    ld a, a
    adc $cf
    call nc, $d47f
    rst $08
    ld a, a
    add $55
    rst $08
    db $d3
    call nc, $d2c5
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, $557f

    ld d, h
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    ret


    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    push de
    adc $4f
    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    ld a, a
    adc $cf
    call nc, $d47f
    rst $08
    ld a, a
    add $55
    rst $08
    db $d3
    call nc, $d2c5
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, $557f

    ld d, h
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and a
    rst $08
    rst $08
    call nz, $cd7f
    rst $08
    jp nc, $c9ce

    adc $c7
    add c
    ld a, a
    and h
    ret


    ld c, a
    call nz, $87ce
    call nc, $d97f
    rst $08
    push de
    ld a, a
    add $cf
    jp nc, $c5c7

    call nc, $d47f
    ld d, l
    push de
    jp nc, $c9ce

    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $cdc1
    ret nc

    ld a, a
    rst $08
    ld d, l
    add $c6
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
    ld d, [hl]
    ld a, a
    adc [hl]
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cf4f
    adc $87
    call nc, $c97f
    adc $d3
    call nc, $ccc1
    call z, $c57f
    call z, $c3c5
    ld d, l
    call nc, $c9d2
    jp $cc7f


    ret


    rst $00
    ret z

    call nc, Call_023_57d3
    nop
    ld a, a
    xor c
    add a
    call $c37f
    rst $08
    adc $d6
    ret


    adc $c3
    push bc
    call nz, Call_023_7f81
    xor b
    ld c, a
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c9c8


    ld d, l
    call z, $d2c4
    push bc
    adc $7f
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    adc $cf
    rst $10
    call nz, $c155
    reti


    db $d3
    ld a, a
    pop bc
    jp nc, $81c5

    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c37f
    rst $08
    adc $d6
    ret


    adc $c3
    push bc
    call nz, Call_023_7f81
    xor b
    ld c, a
    rst $08
    rst $10
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $c9c8


    ld d, l
    call z, $d2c4
    push bc
    adc $7f
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    adc $cf
    rst $10
    call nz, $c155
    reti


    db $d3
    ld a, a
    pop bc
    jp nc, $81c5

    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push bc
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, $c67f
    rst $08
    jp nc, $d47f

    ld c, a
    ret z

    push bc
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    call z, Call_023_7fd9
    add $cf
    db $d3
    ld d, l
    call nc, $d2c5
    push bc
    call nz, Call_023_547f
    add c
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    ld d, l
    call nc, $c5c8
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    add $cf
    jp nc, $d47f

    ret z

    push bc
    call Call_023_7f55
    call nc, Call_023_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    ld d, [hl]
    rst $00
    rst $08
    ld a, a
    rst $08
    push de
    call nc, $c9d3
    call nz, $c54f
    ld a, a
    call nc, Call_023_7fcf
    call z, $cfcf
    bit 7, a
    add $cf
    jp nc, $d37f

    rst $08
    call $c555
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_023_57d3

    nop
    ld a, a
    jp nz, $c5d9

    adc l
    jp nz, $c5d9

    adc h
    ld d, [hl]
    add c
    ld a, a
    adc [hl]
    ld a, a
    call nc, $4fc8
    pop bc
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    jp nz, $8dd9

    jp nz, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    jp nz, $c5d9

    adc l
    jp nz, $c5d9

    adc h
    ld d, [hl]
    add c
    ld a, a
    adc [hl]
    ld a, a
    call nc, $4fc8
    pop bc
    adc $cb
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    jp nz, $8dd9

    jp nz, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, h
    adc h
    ld a, a
    ret


    call nc, $cc7f
    rst $08
    rst $08
    set 2, e
    ld a, a
    call z, Call_023_4fc9
    set 0, l
    ld a, a
    call nc, $c1c8
    call nc, Call_023_7f7f
    db $d3
    call z, $c5c5
    ret nc

    db $d3
    ld a, a
    jp $cf55


    call $cfc6
    jp nc, $c1d4

    jp nz, $cccc

    reti


    adc [hl]
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    sub c
    sub d
    ld a, a
    ret z

    ret


    ld c, a
    rst $00
    ret z

    rst $10
    pop bc
    reti


    adc h
    call nc, $c5c8
    ld a, a
    adc $cf
    jp nc, $c8d4

    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    pop bc
    db $d3
    call nc, $d2c5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    add $c1
    call $d5cf
    db $d3
    ld c, a
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    add $cf
    jp nc, $c67f

    ret


    db $d3
    ret z

    ret


    adc $55
    rst $00
    ld a, a
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor e
    pop bc
    jp nc, $c9c2

    ld a, a
    rst $08
    ret nc

    push bc
    adc $c5
    call nz, $c87f
    ret


    db $d3
    ld c, a
    ld a, a
    push bc
    reti


    push bc
    db $d3
    add c
    ld a, a
    xor e
    pop bc
    jp nc, $c9c2

    ld a, a
    call nz, $dac1
    push bc
    ld d, l
    call nz, $d77f
    ret


    call nc, Call_023_7fc8
    db $d3
    call z, $c5c5
    ret nc

    adc h
    ld a, a
    ld a, a
    pop bc
    call nc, $d455
    pop bc
    jp $c5cb


    db $d3
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor e
    pop bc
    jp nc, $c9c2

    ld a, a
    rst $00
    push bc
    call nc, Call_023_7fd3
    rst $00
    push bc
    adc $d4
    call z, $c54f
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $08
    jp nz, $c4c5

    ret


    push bc
    adc $d4
    adc [hl]
    ld a, a
    rst $00
    ld d, l
    ret


    sub $c5
    db $d3
    ld a, a
    pop bc
    ld a, a
    reti


    pop bc
    jp nc, $8cce

    ld a, a
    ld d, [hl]
    call nz, Call_023_55c9
    db $d3
    pop bc
    ret nc

    push bc
    pop bc
    jp nc, Jump_023_7fd3

    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call $55cf
    push de
    adc $d4
    pop bc
    ret


    adc $57
    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    rst $10
    push bc
    call z, $81cc
    ld a, a
    add $cc
    push bc
    call nz, Call_023_4f8c
    add $cc
    push bc
    call nz, Call_023_7f81
    ld d, a
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
    call nc, Call_023_4f81
    ld a, a
    xor l
    reti


    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    call z, $cec9
    push bc
    ld a, a
    ld d, l
    ret


    db $d3
    ld a, a
    ret


    adc $7f
    call nz, $d3c9
    rst $08
    jp nc, $c5c4

    jp nc, Jump_023_7f81

    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $c9
    ld c, a
    db $d3
    ret z

    push bc
    call nz, $cf7f
    adc $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    ld d, l
    call nc, $cc7f
    ret


    set 0, l
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    xor b
    pop bc
    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    add $c9
    ld c, a
    db $d3
    ret z

    push bc
    call nz, $cf7f
    adc $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    ld d, l
    call nc, $cc7f
    ret


    set 0, l
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    adc $c5
    sub $c5
    jp nc, $c27f

    push de
    db $d3
    reti


    add c
    ld a, a
    ld c, a
    rst $10
    pop bc
    ret


    call nc, Call_023_7f81
    adc h
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    ret


    ld d, l
    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    pop bc
    adc $7f
    ret


    adc $d4
    push bc
    jp nc, $d3c5

    ld d, l
    call nc, Call_023_7f8e
    ld d, a

Call_023_547f:
    nop
    ld a, a
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c67f
    ret


    db $d3
    ret z

    ret


    ld c, a
    adc $c7
    ld a, a
    jp nc, $c4cf

    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    pop bc
    adc $c7
    call z, $55c5
    ld a, a
    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_023_547f
    adc h
    ld d, [hl]
    adc h
    ld d, a
    adc [hl]
    ld a, a
    ld d, l
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld d, [hl]
    add c
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $cd7f
    push bc
    ld a, a
    ld c, a
    pop bc
    ld a, a
    call $cec9
    push de
    call nc, $81c5
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    adc h
    ld d, [hl]
    add c
    ld a, a
    rst $10
    pop bc
    ret


    call nc, $cd7f
    push bc
    ld a, a
    ld c, a
    pop bc
    ld a, a
    call $cec9
    push de
    call nc, $81c5
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $cc7f
    rst $08
    rst $08
    set 1, c
    adc $c7
    ld a, a
    add $cf
    jp nc, Jump_023_4f7f

    db $d3
    call nc, $cecf
    push bc
    db $d3
    ld a, a
    rst $08
    add $7f
    ld a, a
    call nc, $c5c8
    ld a, a
    call $55cf
    rst $08
    adc $8e
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
    call nc, $c855
    push bc
    call Call_023_7f9f
    ld d, a
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
    db $d3
    call nc, $cecf
    push bc
    db $d3
    ld c, a
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $8c
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    ret nc

    jp nc, $cdcf

    rst $08
    call nc, $cfc9
    adc $8c
    ld a, a
    adc h
    ld a, a
    ld d, l
    xor c
    ld a, a
    call $d9c1
    jp nz, Jump_023_7fc5

    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    push bc
    call nc, $557f
    rst $10
    ret


    adc $7f
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    and h
    pop bc
    call $8cce
    call nz, $cdc1
    adc $81
    ld a, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a

Call_023_5587:
    and h
    pop bc
    call $8cce
    call nz, $cdc1
    adc $81
    ld a, a
    ld d, [hl]
    adc h
    ld e, b
    nop
    ld a, a
    xor l
    reti


    ld a, a
    call $cac1
    rst $08
    jp nc, $c97f

    db $d3
    ld a, a
    push bc
    call z, $c3c5
    ld c, a
    call nc, $c9d2
    jp $d4c9


    reti


    adc [hl]
    ld a, a
    db $d3
    rst $08
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d355

    call nc, $cec1
    call nz, Call_023_7fd3

Call_023_55c1:
    call z, $d4c9

Call_023_55c4:
Jump_023_55c4:
    call nc, $c5cc
    ld a, a

Call_023_55c8:
Jump_023_55c8:
    pop bc

Call_023_55c9:
Jump_023_55c9:
    jp nz, $55cf

Call_023_55cc:
    push de

Jump_023_55cd:
    call nc, Call_023_547f

Call_023_55d0:
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3

Call_023_55d9:
Jump_023_55d9:
    push bc
    pop bc
    ld d, l
    ld d, a
    nop
    ld a, a
    xor b
    add a
    call Call_023_7f8c
    ld d, [hl]
    adc [hl]
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld c, a
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    adc [hl]
    ld a, a
    ret


    call nc, $557f
    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_023_7fd9

    push bc
    pop bc
    db $d3
    reti


    ld a, a
    call nc, Call_023_7fcf
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
    push bc
    call z, $c3c5
    call nc, $d255
    ret


    jp $d4c9


    reti


    adc [hl]
    ld a, a
    db $d3
    rst $08
    ld a, a
    adc h
    ld a, a
    db $d3
    set 1, c
    call z, $cc55
    ld a, a
    rst $10
    rst $08
    push de
    call z, Call_023_7fc4
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    adc $7f
    push bc
    ld d, l
    add $c6
    push bc
    jp Jump_023_56d4


    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    set 2, e
    ld a, a
    rst $10
    push bc
    pop bc
    bit 7, a
    pop bc
    ld c, a
    adc $c4
    ld a, a
    call z, $cdc9
    ret nc

    adc h
    ld a, a
    ld d, [hl]
    adc h
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
    rst $10
    push bc
    pop bc
    bit 7, a
    pop bc
    ld c, a
    adc $c4
    ld a, a
    call z, $cdc9
    ret nc

    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld e, b
    nop
    ld a, a
    xor b
    ret


    adc h
    ld a, a
    pop bc
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    adc l
    ret


    adc $4f
    add $c1
    call nc, $c1d5
    call nc, $c4c5
    ld a, a
    call $c5c5
    call nc, Call_023_7fd3
    pop bc
    ld a, a
    ld d, l
    ld d, h
    adc l
    ret


    adc $c6
    pop bc
    call nc, $c1d5
    call nc, $c4c5
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
    jp $d5c1


    db $d3
    push bc
    ld a, a
    rst $08
    add $7f

Jump_023_56d4:
    ld c, a
    call z, $cbc9
    ret


    adc $c7
    ld a, a
    adc h
    ld a, a
    xor c
    ld a, a
    jp nz, $c3c5

    rst $08
    call $55c5
    ld a, a
    call $d3c1
    call nc, $d2c5
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor c
    add $7f
    ret


    ld a, a
    ld d, l
    rst $00
    rst $08
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    adc h
    ld a, a
    xor c
    add a
    call z, Call_023_7fcc
    ld d, l
    adc $c5
    sub $c5
    jp nc, $cc7f

    rst $08
    db $d3
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


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
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


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
    and h
    rst $08
    adc $87
    call nc, $c67f
    ret


    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    rst $08
    adc $4f
    call z, $8cd9
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    rst $10
    rst $08
    jp nc, Jump_023_7fcb

    ret z

    ld d, l
    pop bc
    jp nc, $c5c4

    jp nc, Jump_023_7f8c

    adc h
    ld a, a
    call nc, $c1c8
    call nc, $d387
    ld a, a
    adc $55
    rst $08
    ld a, a
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a

Call_023_577f:
Jump_023_577f:
    call nc, $c1c8
    adc $8c
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld d, a
    adc [hl]
    ld a, a
    nop
    ld a, a
    and c
    ret z

    pop bc
    adc h
    xor b
    pop bc
    adc h
    ld a, a
    xor b
    pop bc
    add c
    ld a, a
    ld d, [hl]
    adc [hl]
    ld a, a
    ld c, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $cd7f
    pop bc
    call nc, $c5d4
    jp nc, Jump_023_7f81

    jp z, $d555

    db $d3
    call nc, $cc7f
    rst $08
    db $d3
    push bc
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $d5cf


    ld d, l
    call z, $cec4
    add a
    call nc, $c77f
    rst $08
    ld a, a
    db $d3
    rst $08
    ld a, a
    add $c1
    jp nc, $c17f

    ld d, l

Call_023_57d3:
Jump_023_57d3:
    db $d3
    ld a, a
    call nc, Call_023_7fcf
    rst $00
    push bc
    call nc, $c17f
    adc $c7
    jp nc, $8ed9

    ld a, a
    nop
    ret z

    rst $08
    rst $10
    ld a, a
    rst $10
    push bc
    call z, Call_023_7fcc
    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    push de
    adc $d3
    ld c, a
    call $cfcf
    call nc, $ccc8
    reti


    sbc a
    add c
    ld a, a
    ld e, b
    nop
    ret z

    rst $08
    rst $10
    ld a, a
    rst $10
    push bc
    call z, Call_023_7fcc
    ld d, [hl]
    ld a, a
    adc h
    ld a, a
    push de
    adc $d3
    ld c, a
    call $cfcf
    call nc, $ccc8
    reti


    sbc a
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    pop bc
    adc $c7
    call z, $c54f
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call z, Call_023_55c9
    set 0, l
    adc h
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    call nz, $cecf
    add a
    call nc, $557f
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    adc h
    ld a, a
    adc h
    ld a, a
    reti


    rst $08
    push de
    ld d, l
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $cb7f
    adc $cf
    rst $10
    ld a, a
    call nc, $c1c8
    call nc, $557f
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c

Call_023_587f:
Jump_023_587f:
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d2c1


    ret nc

    ld a, a
    set 1, c
    adc $4f
    rst $00
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    ld a, a
    rst $08
    add $d4
    ld d, l
    push bc
    adc $7f
    ret


    db $d3
    ld a, a
    pop bc
    adc $c7
    call z, $c4c5
    adc h
    ld a, a
    ret


    call nc, $557f
    ret


    db $d3
    ld a, a
    call nc, $cfcf
    ld a, a
    rst $10
    push bc
    pop bc
    bit 7, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, a
    nop
    ld a, a
    push de
    adc $d7
    ret


    db $d3
    push bc
    adc h
    ld a, a
    push de
    adc $d7
    ret


    db $d3
    push bc
    add c
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    push de
    adc $d7
    ret


    db $d3
    push bc
    adc h
    ld a, a
    push de
    adc $d7
    ret


    db $d3
    push bc
    add c
    ld a, a
    ld c, a
    ld e, b
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
    call nc, $c5c8
    jp nc, $8cc5

    ld a, a
    rst $08
    sub $55
    push bc
    jp nc, $d47f

    ret z

    push bc
    jp nc, $81c5

    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    call z, $c6c5
    call nc, $d37f
    ret


    call nz, Call_023_7fc5
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    ld d, l
    ret nc

    rst $08
    db $d3
    call nc, Call_023_7f8e
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
    pop bc
    call nc, $d07f
    jp nc, $d0cf

    ld a, a
    push bc
    ld d, l
    ret c

    ret z

    ret


    jp nz, $d4c9

    ret


    rst $08
    adc $7f
    rst $10
    ret


    adc $c4
    rst $08
    rst $10
    adc h
    ld d, l
    ld a, a
    ret nc

    jp nc, $d3c5

    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    call z, $c3c5
    call nc, $c955
    sub $c5
    ld a, a
    jp nz, $d4d5

    call nc, $cecf
    ld a, a
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, l
    ret nc

    jp nc, $d0cf

    ld a, a
    jp $cec1


    ld a, a
    jp nz, Jump_023_7fc5

    push bc
    ret c

    jp $c1c8


    ld d, l
    adc $c7
    push bc
    call nz, Call_023_7f81
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    sub c
    sub e
    ld a, a
    ret z

    ret


    ld c, a
    rst $00
    ret z

    rst $10
    pop bc
    reti


    call nc, $c5c8
    ld a, a
    adc $cf
    jp nc, $c8d4

    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c9d2

    call nz, $c5c7
    ld a, a
    rst $08
    add $55
    ld a, a
    ret nc

    push bc
    pop bc
    jp Jump_023_7fc5


    pop bc
    adc $c4
    ld a, a
    pop de
    push de
    ret


    push bc
    call nc, $557f
    ld d, a
    nop
    ld a, a
    xor l
    reti


    ld a, a
    jp nz, $d2c9

    call nz, $c98d
    adc $c6
    pop bc
    call nc, $c1d5
    call nc, $c54f
    call nz, Call_023_7f7f
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_023_7fcf
    jp $cdcf


    ret nc

    push bc
    ld d, l
    call nc, Call_023_7fc5
    rst $10
    ret


    call nc, Call_023_7fc8
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

    rst $08
    push de
    rst $00
    ret z

    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    adc h
    ld c, a
    ld a, a
    call Call_023_7fd9
    jp nz, $d2c9

    call nz, $c98d
    adc $c6
    pop bc
    call nc, $c1d5
    call nc, $c555
    call nz, Call_023_7f7f
    call z, $cfcf
    set 2, e
    ld a, a
    db $d3
    pop bc
    call nc, $d3c9
    add $c9
    ld d, l
    push bc
    call nz, Call_023_577f
    adc [hl]
    ld a, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $d4c1
    jp Jump_023_7fc8


    jp nz, $d4c5

    rst $10
    push bc
    push bc
    ld c, a
    adc $7f
    and d
    rst $08
    jp nz, Jump_023_7fcf

    pop bc
    adc $c4
    ld a, a
    and d
    push bc
    jp $cfc8


    adc $55
    rst $00
    ld a, a
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    ld e, b
    adc [hl]
    ld a, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call $d4c1
    jp Jump_023_7fc8


    jp nz, $d4c5

    rst $10
    push bc
    push bc
    ld c, a
    adc $7f
    and d
    rst $08
    jp nz, Jump_023_7fcf

    pop bc
    adc $c4
    ld a, a
    and d
    push bc
    jp $cfc8


    adc $55
    rst $00
    ld a, a
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    ld e, b
    adc [hl]
    ld a, a
    nop
    ld a, a
    xor c
    add a
    call $d47f
    ret z

    push bc
    ld a, a
    rst $00
    ret


    jp nc, Jump_023_7fcc

    ld a, a
    ret nc

    jp nc, $c14f

    ret


    db $d3
    push bc
    call nz, $c27f
    reti


    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_023_7fc5
    call nc, $cf55
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
    call nz, $c27f
    call z, $55cf
    rst $08
    call nz, $cc7f
    ret


    adc $c5
    pop bc
    rst $00
    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    push bc
    adc $7f
    call nz, $c4c9
    ld a, a
    call nc, $c5c8
    ld a, a
    ld a, a
    rst $10
    pop bc
    ld c, a
    adc $d4
    ld a, a
    call nc, Call_023_7fcf
    jp nz, $c3c5

    rst $08
    call Call_023_7fc5
    pop bc
    ld a, a
    db $d3
    call nc, $d255
    rst $08
    adc $c7
    ld a, a
    ld e, l
    adc h
    sbc a
    ld a, a
    add $d2
    ld d, l
    rst $08
    call $d47f
    rst $08
    call nz, $d9c1
    adc h
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld d, l
    adc $cf
    call nc, $c5c8
    jp nc, $d37f

    ret nc

    push bc
    jp $c1c9


    call z, $d47f
    jp nc, $c155

    ret


    adc $c9
    adc $c7
    add c
    ld a, a
    ld d, a
    nop
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
    pop bc
    adc $7f
    ld c, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    call nc, $c27f
    pop bc
    call nz, $c5c7
    adc h
    ld d, a
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c27f
    pop bc
    call nz, $c5c7
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c855
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_023_7f7f
    ld d, [hl]
    adc h
    ld a, a
    xor c
    ld a, a
    set 1, [hl]
    ld d, l
    rst $08
    rst $10
    ld a, a
    ret


    call nc, Call_023_7f8e
    ld d, a
    nop
    db $d3
    call nc, $ccc9
    call z, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    adc h
    ld a, a
    db $d3
    ld c, a
    call nc, $ccc9
    call z, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    db $d3
    call nc, $ccc9
    call z, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    adc h
    ld a, a
    db $d3
    ld c, a
    call nc, $ccc9
    call z, $d77f
    rst $08
    adc $87
    call nc, $c47f
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld a, a
    xor h
    push bc
    call nc, $d47f
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    call z, $d6cf
    push bc
    call z, $d94f
    ld a, a
    ld d, h
    db $d3
    ld a, a
    ld a, a
    call nc, Call_023_7fcf
    push bc
    ret c

    call nc, $cec5
    call nz, Call_023_7f55
    call nc, $c5c8
    ret


    jp nc, $c77f

    jp nc, $c5c5

    call nc, $cec9
    rst $00
    db $d3
    ld a, a
    ld d, l
    call nc, Call_023_7fcf
    push de
    db $d3
    ld a, a
    pop bc
    call z, $81cc
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, h
    adc h
    ld a, a
    call nc, $c1c8
    call nc, $d387
    ld a, a
    pop bc
    call z, $8ccc
    ld c, a
    ld a, a
    xor h
    push bc
    call nc, $d47f
    ret z

    push bc
    call $c37f
    rst $08
    call $c5d0
    call nc, $55c5
    ld a, a
    ret


    adc $c3
    push bc
    db $d3
    db $d3
    pop bc
    adc $d4
    call z, Call_023_7fd9
    adc [hl]
    ld a, a
    xor [hl]
    rst $08
    ld d, l
    call nc, $c27f
    push bc
    ret


    adc $c7
    ld a, a
    push bc
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    db $d3
    call nc, $d255
    rst $08
    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    add $7f
    call nc, Call_023_55c8
    push bc
    ld a, a
    pop de
    push de
    push bc
    db $d3
    call nc, $cfc9
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ret


    jp Jump_023_7f81


    xor c
    call nc, $874f
    db $d3
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
    jp nz, $c5c5

    ld d, l
    adc $7f
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    call nc, $cfc8
    jp nc, $d5cf

    ld d, l
    rst $00
    ret z

    call z, $8ed9
    ld e, b
    nop
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ret


    jp Jump_023_7f81


    xor c
    call nc, $874f
    db $d3
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
    jp nz, $c5c5

    ld d, l
    adc $7f
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    call nc, $cfc8
    jp nc, $d5cf

    ld d, l
    rst $00
    ret z

    call z, $8ed9
    ld e, b
    nop
    ld a, a
    or a
    rst $10
    ret z

    push bc
    adc $7f
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_023_7fcf
    push bc
    ld c, a
    ret c

    ret nc

    call z, $d2cf
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d6c1


    push bc
    adc h
    ret nc

    ld d, l
    ret


    jp $c5cb


    call nz, $d57f
    ret nc

    ld a, a
    pop bc
    adc $7f
    ret


    adc $c4
    ret


    pop bc
    ld d, l
    adc $7f
    rst $00
    push bc
    call Call_023_577f
    nop
    ld a, a
    or l
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c1c8
    call nc, $c97f
    adc $c4
    ret


    pop bc
    ld c, a
    adc $7f
    rst $00
    push bc
    call $8c7f
    ld a, a
    ld d, h
    ld a, a
    rst $00
    push bc
    call nc, Call_023_7fd3
    ld d, l
    call $d2cf
    push bc
    ld a, a
    pop de
    push de
    ret


    jp $8dcb


    rst $10
    ret


    call nc, $c5d4
    call nz, $8e55
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    ret


    call nc, $4fd9
    add c
    ld a, a
    adc $cf
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, $8ec8
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    ret


    call nc, $4fd9
    add c
    ld a, a
    adc $cf
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, $8ec8
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    jp $cec1


    add a
    call nc, $cc7f
    rst $08
    db $d3
    push bc
    add c
    ld a, a
    rst $10
    ret


    ld c, a
    adc $c4
    ld a, a
    jp nz, $cfcc

    rst $10
    push bc
    db $d3
    ld a, a
    add $cf
    jp nc, $c1d7

    jp nc, Jump_023_55c4

    ld a, a
    call nc, Call_023_7fcf
    call Call_023_7fd9
    call nz, $d2c9
    push bc
    jp $c9d4


    rst $08
    adc $81
    ld d, l
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
    db $d3
    call nc, $c5d2
    adc $c7
    ld c, a
    call nc, Call_023_7fc8
    call nc, Call_023_7fcf
    jp $cdcf


    ret nc

    push bc
    call nc, Call_023_7fc5
    adc h
    xor c
    add a
    ld d, l
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $c77f

    rst $08
    ld a, a
    ret z

    rst $08
    call Call_023_7fc5
    ld d, l
    db $d3
    ret


    call nc, $c9d4
    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, Jump_023_55c9

    rst $00
    ld a, a
    jp nz, $d2c9

    call nz, Call_023_7f8e
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c5d2
    adc $c4
    ld a, a
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    jp nz, $c9d2

    rst $00
    ret z

    call nc, $c17f
    adc $c4
    ld a, a
    jp $c5cc


    pop bc
    ld d, l
    jp nc, Jump_023_587f

    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nc, $c5d2
    adc $c4
    ld a, a
    ld a, a
    ret


    ld c, a
    db $d3
    ld a, a
    jp nz, $c9d2

    rst $00
    ret z

    call nc, $c17f
    adc $c4
    ld a, a
    jp $c5cc


    pop bc
    ld d, l
    jp nc, Jump_023_587f

    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    ld d, [hl]
    adc [hl]
    ld a, a
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld c, a
    ld a, a
    jp nz, $d9cf

    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $00
    ld d, l
    rst $08
    rst $08
    call nz, $d47f
    ret z

    pop bc
    call nc, $d97f
    rst $08
    push de
    ld a, a
    rst $10
    ret


    call z, Call_023_55cc
    ld a, a
    jp nz, Jump_023_7fc5

    call Call_023_7fd9
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    rst $08
    add $7f
    ld c, a
    ld d, h
    adc h
    ld a, a
    adc h
    ld a, a
    call $ccc1
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    add $55
    push bc
    call $ccc1
    push bc
    ld a, a
    adc h
    ld a, a
    rst $10
    ret z

    ret


    jp Jump_023_7fc8


    ret


    db $d3
    ld a, a
    ld d, l
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_023_7f9f

    ld d, a
    nop
    ld a, a
    and l
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_023_7f81
    adc h
    ld a, a
    jp nc, $c1c5

    ld c, a
    call z, $d9cc
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    call $cec1
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and l
    ret c

    jp $ccc5


    call z, $cec5
    call nc, Call_023_7f81
    adc h
    ld a, a
    jp nc, $c1c5

    ld c, a
    call z, $d9cc
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    call $cec1
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
    call z, $cbc9
    push bc
    ld a, a
    jp $cdcf


    ret nc

    ld c, a
    push bc
    call nc, $cec9
    rst $00
    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    ld d, h
    ld a, a
    pop bc
    adc $55
    call nz, $cd7f
    push bc
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    jp $d5d4


    pop bc
    call z, $d9cc
    ld a, a
    ld a, a
    call nz, $cecf
    add a
    ld c, a
    call nc, $d57f
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld a, a
    ld d, h
    adc h
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    push de
    db $d3
    push bc
    call nz, $c27f
    reti


    ld a, a
    ld d, l
    adc h
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    call nz, $d4c5
    push bc
    jp nc, Jump_023_55cd

    ret


    adc $c5
    call nz, $c17f
    jp $cfc3


    jp nc, $c9c4

    adc $c7
    ld a, a
    call nc, $55cf
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    pop bc
    ret nc

    push bc
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    pop bc
    call z, $c5d2
    pop bc
    call nz, Call_023_7fd9
    ld a, a
    push de
    adc $c4
    ld c, a
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    pop bc
    call z, $c5d2
    pop bc
    call nz, Call_023_7fd9
    ld a, a
    push de
    adc $c4
    ld c, a
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    sbc a
    ld a, a
    ld e, b
    nop
    sbc a
    ld d, a
    ld e, b
    nop
    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $08
    sub $c5
    jp nc, $d47f

    ret z

    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    sbc a
    ld e, b
    nop
    sbc a
    ld e, b
    nop
    xor c
    call nc, $d387
    ld a, a
    xor c
    ld a, a
    rst $10
    ret z

    rst $08
    ld a, a
    pop bc
    call $c47f
    push bc
    push bc
    ld c, a
    ret nc

    call z, Call_023_7fd9
    ret


    adc $7f
    call z, $d6cf
    push bc
    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    ld d, l
    call nc, $c5c8
    ld a, a
    jp nz, $d2c9

    call nz, Call_023_547f
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $10
    ld c, a
    pop bc
    adc $d4
    ld a, a
    call nc, Call_023_7fcf
    add $cc
    reti


    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    and d
    ld d, l
    rst $08
    jp nz, Jump_023_7fcf

    pop bc
    adc $c4
    ld a, a
    and d
    push bc
    jp $cfc8


    adc $c7
    adc h
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    call $cec1
    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    push de
    adc $d5
    db $d3
    push de
    ld c, a
    pop bc
    call z, $d37f
    call nc, $c5d2
    adc $c7
    call nc, $8ec8
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    call $cec1
    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    push de
    adc $d5
    db $d3
    push de
    ld c, a
    pop bc
    call z, $d37f
    call nc, $c5d2
    adc $c7
    call nc, $8ec8
    ld a, a
    ld d, [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    ld a, a
    sub c
    sub h
    ld a, a
    ret z

    ld c, a
    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    or h
    ret z

    push bc
    ld a, a
    rst $10
    push bc
    db $d3
    call nc, $557f
    ld d, [hl]
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    reti


    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    call z, $d4c5
    call nc, $cec9
    rst $00
    ld a, a
    ret z

    ret


    call $c27f
    ld c, a
    push bc
    jp $cdcf


    push bc
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    ld d, h
    ld a, a
    ld d, l
    adc h
    ld a, a
    reti


    rst $08
    push de
    add a
    call nz, $d37f
    call nc, $ccc9
    call z, $d47f
    push bc
    pop bc
    ld d, l
    jp Jump_023_7fc8


    ret z

    ret


    call $cd7f
    push de
    jp Jump_023_7fc8


    jp nz, $d4c5

    call nc, $55c5
    jp nc, $d37f

    set 1, c
    call z, $81cc
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
    pop bc
    ld a, a
    ld c, a
    db $d3
    push bc
    jp $c5d2


    call nc, $cd7f
    pop bc
    jp $c9c8


    adc $c5
    ld a, a
    or l
    db $d3
    ld d, l
    ret


    adc $c7
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    set 1, c
    adc $c4
    ld a, a
    rst $08
    add $7f
    ld d, l
    db $d3
    set 1, c
    call z, Call_023_7fcc
    adc h
    ld a, a
    ld d, h
    ld a, a
    jp $cec1


    ld a, a
    adc $55
    push bc
    sub $c5
    jp nc, $c67f

    rst $08
    jp nc, $c5c7

    call nc, $c17f
    adc $d9
    ld a, a
    call $cf55
    jp nc, $8cc5

    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    push bc
    adc $d3
    pop bc
    call nc, $cfc9
    adc $7f
    ret


    db $d3
    ld a, a
    db $d3
    call nc, Call_023_4fc9
    call z, Call_023_7fcc
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_023_7f8e
    ld e, b
    nop
    ld a, a
    db $d3
    push bc
    adc $d3
    pop bc
    call nc, $cfc9
    adc $7f
    ret


    db $d3
    ld a, a
    db $d3
    call nc, Call_023_4fc9
    call z, Call_023_7fcc
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_023_7f8e
    ld e, b
    nop
    ld a, a
    xor l
    reti


    ld a, a
    jp nz, $d2c9

    call nz, Call_023_547f
    xor c
    add a
    call nz, $c87f
    ld c, a
    pop bc
    sub $c5
    ld a, a
    call nc, Call_023_7fcf
    call z, $d4c5
    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    call nc, $55cf
    ld a, a
    ret z

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


    ld d, l
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $d37f

    call nc, $cfd2
    adc $4f
    rst $00
    push bc
    jp nc, $d37f

    set 1, c
    call z, Call_023_7fcc
    ret


    db $d3
    ld a, a
    call nc, $d5c1
    rst $00
    ld d, l
    ret z

    call nc, Call_023_7f8c
    db $d3
    ret z

    rst $08
    push de
    call z, Call_023_7fc4
    rst $10
    push bc
    ld a, a
    call z, $d4c5
    ld d, l
    ld a, a
    ret z

    ret


    call $c87f
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    adc [hl]
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $d47f
    rst $08
    rst $08
    ld a, a
    push bc
    pop bc
    jp nc, $d9cc

    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $d47f
    rst $08
    rst $08
    ld a, a
    push bc
    pop bc
    jp nc, $d9cc

    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    ld e, h
    xor h
    push bc
    call nc, $874f
    db $d3
    ld a, a
    rst $00
    rst $08
    ld a, a
    jp nz, $c3c1

    bit 7, a
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
    call z, $c7c9
    ret z

    call nc, $cec5
    adc $c9
    adc $c7
    ld d, l
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, Jump_023_7f81

    jp nz, $d4d5

    ld a, a
    jp z, $d3d5

    call nc, Call_023_7f55
    pop bc
    ld a, a
    add $c5
    rst $10
    ld a, a
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    db $d3
    push de
    jp Jump_023_55c8


    ld a, a
    db $d3
    push bc
    jp $c5d2


    call nc, $cd7f
    pop bc
    jp $c9c8


    adc $c5
    adc [hl]
    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    ret z

    push bc
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    call nc, $d5c1
    rst $00
    ret z

    call nc, Call_023_7f4f
    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $d0d9
    push bc
    ld a, a
    rst $08
    add $7f
    ld d, l
    ld d, h
    adc h
    ld a, a
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, Call_023_7fcc
    ld d, l
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, Jump_023_7f7f

    call $d9c1
    jp nz, Jump_023_7fc5

    rst $00
    push bc
    call nc, $557f
    jp nz, $c7c9

    rst $00
    push bc
    jp nc, $c17f

    adc $c4
    ld a, a
    jp nz, $c7c9

    rst $00
    push bc
    jp nc, Jump_023_7f55

    ld d, a
    nop
    ld a, a
    xor c
    add a
    call $d67f
    push bc
    jp nc, Jump_023_7fd9

    call nc, $d2c9
    push bc
    call nz, Call_023_587f
    nop
    ld a, a
    xor c
    add a
    call $d67f
    push bc
    jp nc, Jump_023_7fd9

    call nc, $d2c9
    push bc
    call nz, Call_023_587f
    nop
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c27f

    ret


    jp nc, Jump_023_7fc4

    ld d, h
    call nz, $c5cf
    ld c, a
    db $d3
    ld a, a
    ret


    call nc, $d27f
    push bc
    call $cdc5
    jp nz, $d2c5

    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    set 1, c
    call z, Call_023_7fcc
    rst $08
    add $7f
    jp nz, $c1c5

    jp nc, $cec9

    rst $00
    ld d, l
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, Call_023_7fcf
    add $cc
    reti


    ld a, a
    ret


    adc $7f
    call nc, Call_023_55c8
    push bc
    ld a, a
    db $d3
    set 3, c
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    db $d3
    ret


    adc $c3
    push bc
    ld a, a
    xor c
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ld d, [hl]
    ld a, a
    ld c, a
    adc h
    ld a, a
    xor c
    ld a, a
    jp z, $d3d5

    call nc, $d77f
    pop bc
    adc $d4
    ld a, a
    call nc, Call_023_7fcf
    ld d, l
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    call nc, $c5c8
    call $c28d
    ret


    jp nc, Jump_023_7fc4

    ld d, l
    ld d, h
    ld a, a
    adc [hl]
    ld a, a
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
    call nc, Call_023_7f81
    ld e, b
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
    call nc, Call_023_7f81
    ld e, b
    nop
    ld a, a
    and h
    ret


    call nz, $d97f
    rst $08
    push de
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, $d47f

    ret z

    push bc
    ld c, a
    ld a, a
    call z, $c7c5
    push bc
    adc $c4
    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $557f
    ld d, h
    ld a, a
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_023_7fc5

    pop bc
    jp nc, Jump_023_7fc5

    sub e
    ld a, a
    call nc, $d0d9
    push bc
    ld c, a
    db $d3
    ld a, a
    rst $08
    add $7f
    call z, $c7c5
    push bc
    adc $c4
    ld a, a
    ld d, h
    ld a, a
    adc h
    ld d, l
    ld a, a
    call nc, $c5c8
    reti


    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    pop bc
    call z, Call_023_7fcc
    jp nz, $d2c9

    ld d, l
    call nz, $81d3
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    reti


    ld a, a
    call nz, Call_023_7fcf
    reti


    rst $08
    push de
    ld a, a
    call z, $d3cf
    push bc
    sbc a
    ld c, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    reti


    ld a, a
    call nz, Call_023_7fcf
    reti


    rst $08
    push de
    ld a, a
    call z, $d3cf
    push bc
    sbc a
    ld c, a
    ld e, b
    nop
    ld a, a
    call z, $d3c9
    call nc, $c5cc
    db $d3
    db $d3
    adc h
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld c, a
    ld d, [hl]
    adc $cf
    ld a, a
    call $d4c5
    ret z

    rst $08
    call nz, Call_023_7f81
    xor h
    push bc
    call nc, Call_023_5587
    db $d3
    ld a, a
    call nz, $81cf
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $d6c5
    push bc
    jp nc, $d67f

    ret


    jp $cfd4


    jp nc, $4fd9

    ld a, a
    rst $08
    jp nc, $c47f

    push bc
    add $c5
    pop bc
    call nc, Call_023_7f8c
    adc h
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    adc $cf
    call nc, $c9c8
    adc $c7
    ld a, a
    call nc, Call_023_7fcf
    push de
    db $d3
    ld a, a
    pop bc
    db $d3
    ld a, a
    ld d, l
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
    call z, $cfcf
    bit 7, a
    ld d, l
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $cfd2

    pop bc
    call nz, $d37f
    set 3, c
    add c
    ld d, l
    ld a, a
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    pop bc
    db $d3
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    jp $d44f


    push bc
    call nz, $c97f
    call nc, $c97f
    db $d3
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    pop bc
    db $d3
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    jp $d44f


    push bc
    call nz, $c97f
    call nc, $c97f
    db $d3
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $c17f
    adc $7f
    ret


    call $c5d0
    call nc, $cfd5
    push de
    db $d3
    ld c, a
    ld a, a
    ret nc

    push bc
    jp nc, $cfd3

    adc $81
    ld a, a
    pop de
    push de
    ret


    jp $8ccb


    ld a, a
    pop de
    ld d, l
    push de
    ret


    jp $8ccb


    ld a, a
    pop de
    push de
    ret


    jp $81cb


    ld a, a
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_023_7f8c
    rst $10
    ret z

    pop bc
    call nc, Call_023_7f8c
    rst $10
    ret z

    pop bc
    call nc, $814f
    xor c
    db $d3
    ld a, a
    call nc, $c5c8
    jp nc, Jump_023_7fc5

    pop bc
    adc $d9
    ld a, a
    rst $08
    call nc, Call_023_55c8
    push bc
    jp nc, $d47f

    ret z

    ret


    adc $c7
    db $d3
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_023_7f8c
    call z, $d3cf
    call nc, $c37f
    rst $08
    call Call_023_7fc5
    ld c, a
    call nc, Call_023_7fcf
    pop bc
    adc $7f
    push bc
    adc $c4
    adc h
    ld a, a
    call nc, $c5c8
    adc $7f
    jp nz, $d955

    push bc
    adc l
    jp nz, $c5d9

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    call z, $d3cf
    call nc, Call_023_7f8c
    call z, $d3cf
    call nc, $c37f
    rst $08
    call Call_023_7fc5
    ld c, a
    call nc, Call_023_7fcf
    pop bc
    adc $7f
    push bc
    adc $c4
    adc h
    ld a, a
    call nc, $c5c8
    adc $7f
    jp nz, $d955

    push bc
    adc l
    jp nz, $c5d9

    add c
    ld a, a
    ld e, b
    nop
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, $81c5

    and h
    ld c, a
    rst $08
    adc $87
    call nc, $d17f
    push de
    ret


    jp nz, $ccc2

    push bc
    adc [hl]
    ld a, a
    call nc, Call_023_7fcf
    ld d, l
    jp nz, Jump_023_7fc5

    call Call_023_7fd9
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
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
    call nc, $c9c8
    adc $cb
    ld a, a
    call nc, $c84f
    pop bc
    call nc, $a97f
    add a
    call $ce7f
    rst $08
    call nc, $c77f
    rst $08
    rst $08
    call nz, $557f
    pop bc
    call nc, $c67f
    rst $08
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    ret z

    ret


    call $557f
    call nc, Call_023_7fcf
    jp nz, $c3c5

    rst $08
    call Call_023_7fc5
    db $d3
    call $ccc1
    call z, $c17f
    ld d, l
    adc $c4
    ld a, a
    jp nc, $d5cf

    adc $c4
    ld a, a
    add c
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    call nc, $4f9f
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    jp nz, $d5cf

    call nc, $4f9f
    ld a, a
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
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    add $c5
    rst $10
    ld a, a
    ld d, l
    jp $cecf


    db $d3
    call nc, $d5d2
    jp $c9d4


    rst $08
    adc $d3
    adc h
    ld a, a
    xor c
    ld a, a
    ld d, l
    rst $08
    add $d4
    push bc
    adc $7f
    jp $cdcf


    push bc
    ld a, a
    ret z

    push bc
    jp nc, Jump_023_7fc5

    jp nc, $d555

    adc $ce
    ret


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
    pop bc
    jp nc, Jump_023_7fc5

    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    ld c, a
    rst $00
    rst $08
    rst $08
    call nz, $d47f
    rst $08
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ret


    call nc, Call_023_7f55
    call nc, Call_023_7fcf
    call nc, $c1c8
    call nc, $c47f
    push bc
    rst $00
    jp nc, $c5c5

    add c
    ret z

    ld d, l
    rst $08
    rst $10
    push bc
    sub $c5
    jp nc, $567f

    ld a, a
    adc h
    ld a, a
    pop bc
    db $d3
    ld a, a
    call z, $55cf
    adc $c7
    ld a, a
    pop bc
    db $d3
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    adc h
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    call nc, $c1d2
    rst $08
    jp nc, $c9c4

    adc $c1
    jp nc, Jump_023_55d9

    add c
    ld a, a
    ld d, a
    nop
    xor a
    ret z

    adc h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    add $c1
    call z, $81cc
    ld a, a
    ld c, a
    ld e, b
    nop
    xor a
    ret z

    adc h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    add $c1
    call z, $81cc
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    ld d, h
    adc h
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, $c99f
    adc $d4
    ld c, a
    push bc
    jp nc, $d3c5

    call nc, $cec9
    rst $00
    add c
    ld a, a
    call nc, $c5c8
    adc $7f
    set 0, l
    ld d, l
    push bc
    ret nc

    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $cdcf


    ret nc

    pop bc
    adc $d9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    add $7f
    ret


    call nc, $c97f
    db $d3
    ld a, a
    ld a, a
    rst $08
    add $7f
    reti


    rst $08
    push de
    ld c, a
    jp nc, Jump_023_7fd3

    pop bc
    adc $c4
    ld a, a
    call $cec9
    push bc
    ld a, a
    call nc, $c1c8
    call nc, $557f
    jp $cecf


    call nc, $d3c5
    call nc, $c67f
    pop bc
    jp Jump_023_7fc5


    call nc, Call_023_7fcf
    add $55
    pop bc
    jp Jump_023_7fc5


    adc h
    ld a, a
    call nc, $c5c8
    adc $7f
    call $cec9
    push bc
    ld a, a
    rst $10
    ld d, l
    ret


    call z, Call_023_7fcc
    jp $d2c5


    call nc, $c9c1
    adc $cc
    reti


    ld a, a
    rst $10
    ret


    adc $55
    add c
    ld a, a
    nop
    ld a, a
    and d
    push bc
    reti


    rst $08
    adc $c4
    ld a, a
    call Call_023_7fd9
    push de
    adc $c4
    push bc
    jp nc, Jump_023_4fd3

    call nc, $cec1
    call nz, $cec9
    rst $00
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
    call Call_023_7fd9
    push de
    adc $c4
    push bc
    jp nc, Jump_023_4fd3

    call nc, $cec1
    call nz, $cec9
    rst $00
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    xor a
    sub c
    sub l
    ld a, a
    ret z

    ret


    rst $00
    ld c, a
    ret z

    rst $10
    pop bc
    reti


    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    push bc
    db $d3
    call nc, $567f
    adc h
    ld d, l
    ld a, a
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
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    adc $c5
    ld a, a
    call nc, Call_023_4fcf
    ld a, a
    call Call_023_7fd9
    call z, $cbc9
    ret


    adc $c7
    ld a, a
    ld a, a
    call nc, Call_023_7fcf
    ret z

    pop bc
    ld d, l
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $81
    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $877f
    db $d3
    ld a, a
    ld a, a
    xor c
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    ld c, a
    push bc
    call nz, $d77f
    ret


    call nc, Call_023_7fc8
    call Call_023_7fd9
    add $d2
    ret


    push bc
    adc $c4
    ld d, l
    db $d3
    adc [hl]
    ld a, a
    call nc, $c5c8
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call Call_023_7fc5
    rst $08
    ld d, l
    add $7f
    ld d, h
    adc h
    ld a, a
    adc h
    ld a, a
    push bc
    sub $c5
    adc $7f
    call nc, $cfc8
    ld d, l
    push de
    rst $00
    ret z

    ld a, a
    push de
    adc $c4
    push bc
    db $d3
    ret


    jp nc, $c4c5

    ld a, a
    ld d, [hl]
    adc h
    ld d, l
    adc h
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    db $d3
    rst $08
    call $cfc5
    adc $c5
    ld a, a
    ld a, a
    rst $10
    ld d, l
    ret z

    rst $08
    ld a, a
    jp $d0c1


    call nc, $d2d5
    push bc
    call nz, $c87f
    ret


    call $c37f
    ld d, l
    pop bc
    adc $7f
    jp nc, $cec5

    pop bc
    call Call_023_7fc5
    add $cf
    jp nc, $c87f

    ret


    call $8155
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    add $7f
    call nc, $c5c8
    ld c, a
    ld a, a
    pop de
    push de
    push bc
    db $d3
    call nc, $cfc9
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    rst $08
    push de
    call nc, $cf7f
    add $7f
    call nc, $c5c8
    ld c, a
    ld a, a
    pop de
    push de
    push bc
    db $d3
    call nc, $cfc9
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cfcf
    bit 7, a
    sub $c5
    jp nc, Jump_023_7fd9

    set 1, c
    ld c, a
    adc $c4
    adc h
    ld a, a
    db $d3
    rst $08
    ld a, a
    call nz, $c5cf
    db $d3
    adc $87
    call nc, $d47f
    ret z

    ld d, l
    ret


    adc $cb
    ld a, a
    ret z

    push bc
    add a
    call nz, $cc7f
    rst $08
    db $d3
    push bc
    add c
    ld a, a
    adc h
    ld a, a
    ld d, l
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call nc, $d9d2
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    adc $c7
    push bc
    db $d3
    call nc, $567f
    ld a, a
    adc h
    ld a, a
    call nc, $4fc8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    rst $08
    add $d4
    push bc
    adc $7f
    db $d3
    push bc
    push bc
    ld a, a
    adc h
    ld a, a
    ld d, l
    ret


    call nc, $cc7f
    rst $08
    rst $08
    set 2, e
    ld a, a
    add $d2
    ret


    rst $00
    ret z

    call nc, $cec5
    ld d, l
    adc $c5
    call nz, Call_023_7f8c
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld d, l
    ld a, a
    jp nz, $d2cf

    ret


    adc $c7
    adc [hl]
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
    rst $10
    ret z

    ret


    db $d3
    call nc, $cc4f
    push bc
    ld a, a
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d2c9

    call nz, $557f
    ld d, h
    rst $10
    ret


    call z, Call_023_7fcc
    add $cc
    reti


    ld a, a
    ret z

    push bc
    jp nc, $81c5

    ld d, l
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call Call_023_7fd9
    call nc, $d0d9
    push bc
    ld a, a
    ret


    db $d3
    ld c, a
    ld a, a
    adc $cf
    call nc, $d37f
    push de
    ret


    call nc, $c4c5
    ld a, a
    ld d, [hl]
    ld a, a
    call nc, $55cf
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, $8c7f
    ld d, a
    nop
    xor b
    push de
    call $c8d0
    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    ret nc

    ret


    call nc, $4fd9
    add c
    ld a, a
    ld e, b
    nop
    xor b
    push de
    call $c8d0
    adc h
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    ret nc

    ret


    call nc, $4fd9
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    ld a, a
    ld d, [hl]
    sbc a
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    adc $d5
    call Call_023_4fc2
    push bc
    jp nc, $cf7f

    add $7f
    jp nz, $d2c9

    call nz, Call_023_7fd3
    ret


    db $d3
    ld a, a
    ret


    adc $55
    jp $c5d2


    pop bc
    db $d3
    ret


    adc $c7
    add c
    ld a, a
    xor l
    pop bc
    reti


    jp nz, Jump_023_7fc5

    reti


    ld d, l
    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    push bc
    adc $cf
    ld d, l
    push de
    rst $00
    ret z

    sbc a
    ld a, a
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
    ld d, [hl]
    jp nz, $d2c9

    call nz, Call_023_7f4f
    ld d, h
    adc h
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    push bc
    ld d, l
    adc $cf
    push de
    rst $00
    ret z

    ld a, a
    call nc, Call_023_7fcf
    jp nc, $d3c5

    ret


    db $d3
    call nc, $d47f
    ld d, l
    ret z

    push bc
    ld a, a
    push bc
    pop bc
    jp nc, $c8d4

    pop de
    push de
    pop bc
    set 0, l
    ld a, a
    pop bc
    adc $c4
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    pop bc
    jp nc, $c8d4

    jp $c1d2


    jp $8ccb


    ld a, a
    ld d, l
    ld d, a
    nop
    ld a, a
    and c
    db $d3
    ld a, a
    xor c
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    jp $c5d4


    call nz, Call_023_587f
    nop
    ld a, a
    and c
    db $d3
    ld a, a
    xor c
    ld a, a
    push bc
    ret c

    ret nc

    push bc
    jp $c5d4


    call nz, Call_023_587f
    nop
    xor b
    xor c
    add c
    ret z

    rst $08
    rst $10
    ld a, a
    pop bc
    ld a, a
    call z, $d6cf
    push bc
    call z, Call_023_7fd9
    jp nz, $cf4f

    reti


    ld a, a
    ld a, a
    call z, $cbc9
    ret


    adc $c7
    ld a, a
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    xor c
    add a
    call $c17f
    adc $c7
    jp nc, $4fd9

    ld a, a
    push bc
    call z, $c5c4
    jp nc, $d37f

    ret


    db $d3
    call nc, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, l
    pop bc
    adc $7f
    pop bc
    call nz, $ccd5
    call nc, Call_023_7f8c
    db $d3
    rst $08
    ld a, a
    ld a, a
    add $cf
    jp nc, $c755

    ret


    sub $c5
    db $d3
    ld a, a
    ret z

    push bc
    jp nc, Jump_023_577f

    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    jp $d2c1


    push bc
    call z, $d3c5
    db $d3
    add c
    ld e, b
    nop
    ld a, a
    call nc, $cfcf
    ld a, a
    jp $d2c1


    push bc
    call z, $d3c5
    db $d3
    add c
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    ld a, a
    ld d, [hl]
    add c
    ld a, a
    db $d3
    ret


    adc $c3
    push bc
    ld a, a
    xor c
    ld a, a
    ld c, a
    call z, $d6c9
    push bc
    ld a, a
    pop bc
    call z, $cecf
    push bc
    adc h
    ld a, a
    adc h
    ld a, a
    db $d3
    rst $08
    ld a, a
    ld d, l
    xor c
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, Call_023_547f
    add c
    ld a, a
    ld d, a
    nop
    xor a
    add $7f
    jp $d5cf


    jp nc, $c5d3

    adc h
    ld a, a
    ld d, [hl]
    add c
    and c
    db $d3
    ld a, a
    ld c, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    db $d3
    ld a, a
    xor c
    ld a, a
    db $d3
    pop bc
    rst $10
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    pop bc
    call nc, $c87f
    rst $08
    call Call_023_7fc5
    adc h
    ld a, a
    xor c
    ld a, a
    rst $10
    ld d, l
    ret


    call z, Call_023_7fcc
    jp nz, Jump_023_7fc5

    pop bc
    call nc, $c57f
    pop bc
    db $d3
    push bc
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    adc $cf
    call nc, $c17f
    ld a, a
    ret nc

    jp nc, $c2cf

    ld c, a
    call z, $cdc5
    ld a, a
    rst $08
    adc $7f
    sub $c9
    jp $cfd4


    jp nc, Jump_023_7fd9

    rst $08
    jp nc, Jump_023_7f55

    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_023_587f
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    adc $cf
    call nc, $c17f
    ld a, a
    ret nc

    jp nc, $c2cf

    ld c, a
    call z, $cdc5
    ld a, a
    rst $08
    adc $7f
    sub $c9
    jp $cfd4


    jp nc, Jump_023_7fd9

    rst $08
    jp nc, Jump_023_7f55

    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_023_587f
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    adc h
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    jp nz, Jump_023_4fcf

    reti


    add c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, Call_023_55c9
    call nc, $cfc9
    adc $81
    ld a, a
    xor c
    ld a, a
    jp nc, $c2cf

    jp nz, $c4c5

    ld a, a
    add $d2
    ld d, l
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    rst $08
    sub $c5
    ld d, l
    jp nc, $d47f

    ret z

    push bc
    jp nc, $81c5

    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    db $d3
    ret z

    rst $08
    jp nc, Jump_023_7fd4

    call z, $c6c9
    push bc
    ld a, a
    ld d, [hl]
    add c
    ld c, a
    ld a, a
    and h
    rst $08
    ret


    adc $c7
    ld a, a
    push bc
    sub $c9
    call z, $c47f
    push bc
    push bc
    call nz, $557f
    call z, $cbc9
    ret


    adc $c7
    ld a, a
    ld e, [hl]
    ld a, a
    ret


    db $d3
    ld d, l
    ld a, a
    call $d2cf
    push bc
    ld a, a
    adc $c1
    call nc, $d2d5
    pop bc
    call z, $c17f
    adc $c4
    ld d, l
    ld a, a
    push de
    adc $d2
    push bc
    db $d3
    call nc, $c1d2
    ret


    adc $c5
    call nz, Call_023_7f81
    ld d, a
    nop
    ld a, a
    and d
    push bc
    reti


    rst $08
    adc $c4
    ld a, a
    call Call_023_7fd9
    push de
    adc $c4
    push bc
    jp nc, Jump_023_4fd3

    call nc, $cec1
    call nz, $cec9
    rst $00
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
    call Call_023_7fd9
    push de
    adc $c4
    push bc
    jp nc, Jump_023_4fd3

    call nc, $cec1
    call nz, $cec9
    rst $00
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    add c
    ld a, a
    xor c
    add $7f
    call z, $d3cf
    call nc, Call_023_7f8c
    call z, Call_023_4fc5
    call nc, $d47f
    ret z

    push bc
    call $cc7f
    push bc
    pop bc
    sub $c5
    ld a, a
    pop bc
    call z, Call_023_7fcc
    ld d, l
    call $cecf
    push bc
    reti


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
    pop bc
    jp nc, Jump_023_7fc5

    db $d3
    ret


    call $ccd0
    reti


    ld a, a
    jp z, $cf4f

    set 1, c
    adc $c7
    ld a, a
    call nc, Call_023_7fcf
    call z, $c1c5
    sub $c5
    ld a, a
    call $55cf
    adc $c5
    reti


    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    rst $08
    call Call_023_7fc5
    rst $08
    call nc, $c5c8
    ld d, l
    jp nc, Jump_023_7fd3

    add c
    ld a, a
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $d387
    ld a, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    ld e, b
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $d387
    ld a, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    ld e, b
    nop
    ld a, a
    or d
    push bc
    jp $cec5


    call nc, $d9cc
    ld a, a
    call nc, $c5c8
    jp nc, Jump_023_7fc5

    ret nc

    ld c, a
    rst $08
    ret nc

    push de
    call z, $d2c1
    db $d3
    ld a, a
    rst $08
    adc $c5
    ld a, a
    call nc, $c9c8
    adc $c7
    ld d, l
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    xor b
    add a
    call Call_023_7f8c
    jp nc, $c7c9

    ret z

    call nc, $557f
    ld d, [hl]
    add c
    ld a, a
    adc [hl]
    ld a, a
    xor c
    db $d3
    ld a, a
    ret


    call nc, $d47f
    rst $08
    ld a, a
    push bc
    ret c

    ld d, l
    jp $c1c8


    adc $c7
    push bc
    ld a, a
    ld d, h
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    rst $08
    add $d4
    push bc
    adc $7f
    push bc
    ret c

    jp $c84f


    pop bc
    adc $c7
    push bc
    ld a, a
    ld d, h
    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    call Call_023_55d9
    ld a, a
    add $d2
    ret


    push bc
    adc $c4
    db $d3
    ld a, a
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
    call nc, $c37f
    rst $08
    call $c5d0
    call nc, $d4c9
    ld c, a
    ret


    rst $08
    adc $7f
    jp nz, $d4d5

    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    xor [hl]
    rst $08
    call nc, $c37f
    rst $08
    call $c5d0
    call nc, $d4c9
    ret


    ld c, a
    rst $08
    adc $7f
    jp nz, $d4d5

    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld e, b
    nop
    ld a, a
    jp $cdcf


    push bc
    adc h
    ld a, a
    jp $cdcf


    push bc
    adc h
    ld d, h
    adc h
    ld a, a
    ld c, a
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and a
    rst $08
    ld a, a
    call nc, Call_023_7fcf
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    adc $7f
    push bc
    ret c

    ld c, a
    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    ld d, b
    ld a, a
    rst $10
    ret


    call nc, Call_023_7fc8
    db $d3
    rst $08
    call $55c5
    rst $08
    adc $c5
    ld a, a
    ld a, a
    db $d3
    call z, $c7c9
    ret z

    call nc, $d9cc
    ld a, a
    rst $10
    push bc
    pop bc
    ld d, l
    res 1, [hl]
    ld d, b
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    adc $d8
    ret


    rst $08
    push de
    db $d3
    ld a, a
    call nc, Call_023_7fcf
    ld c, a
    add $c9
    rst $00
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
    ld d, l
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_023_7f8e

    ld d, l
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    pop bc
    adc $d8
    ret


    rst $08
    push de
    db $d3
    ld a, a
    call nc, Call_023_7fcf
    ld c, a
    add $c9
    rst $00
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
    ld d, l
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, Jump_023_7f8e

    ld d, l
    ld e, b
    nop
    ld a, a
    ld d, h
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_023_7fd9

    ld c, a
    jp $cdcf


    add $cf
    jp nc, $c1d4

    jp nz, $d9cc

    add c
    ld d, a
    nop
    ld a, a
    and l
    adc $ca
    rst $08
    reti


    ret


    adc $c7
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    ret


    call z, $4fd9
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $d7cf
    adc $c8
    ret


    call z, Call_023_7fcc
    ld d, l
    ret nc

    pop bc
    call nc, $81c8
    ld a, a
    jp nz, Jump_023_7fd9

    jp nz, $cbc9

    push bc
    ld a, a
    rst $08
    adc $7f
    ld d, l
    pop bc
    ld a, a
    add $c1
    jp nc, $d27f

    rst $08
    push de
    call nc, $81c5
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    ld a, a
    sub c
    sub [hl]
    ld a, a
    ret z

    ld c, a
    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    adc h
    call z, $c7c9
    ret z

    call nc, $cec5
    adc $c9
    adc $55
    rst $00
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, $567f

    adc h
    ld a, a
    ret nc

    ret


    adc $cb
    ld d, l
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    xor e
    pop bc
    jp nc, $c9c2

    ld a, a
    pop bc
    rst $10
    rst $08
    set 0, l
    ld a, a
    add c
    ld a, a
    xor e
    pop bc
    ld c, a
    jp nc, $c9c2

    ld a, a
    ld a, a
    call nz, $dac1
    push bc
    call nz, $d77f
    ret


    call nc, Call_023_7fc8
    pop bc
    ld d, l
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    call nc, $c1d4
    jp $55cb


    push bc
    call nz, Call_023_7f81
    ld d, a
    nop
    ld a, a
    xor e
    pop bc
    jp nc, $c9c2

    ld a, a
    call nz, $d3c9
    ret nc

    push bc
    pop bc
    jp nc, Jump_023_7fd3

    rst $10
    ld c, a
    ret


    call nc, Call_023_7fc8
    pop bc
    ld a, a
    reti


    pop bc
    jp nc, Jump_023_7fce

    ld a, a
    ret


    adc $7f
    call nc, Call_023_55c8
    push bc
    ld a, a
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $7f
    ld d, [hl]
    adc h
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ret


    adc $d4
    push bc
    jp nc, Jump_023_4fc5

    db $d3
    call nc, $cec9
    rst $00
    ld a, a
    add $cf
    jp nc, $d57f

    db $d3
    ld a, a
    call nc, Call_023_7fcf
    jp nc, $d555

    adc $7f
    pop de
    push de
    ret


    jp $cccb


    reti


    ld a, a
    jp nc, $d4c1

    ret z

    push bc
    jp nc, Jump_023_7f55

    call nc, $c1c8
    adc $7f
    call nc, Call_023_7fcf
    rst $00
    rst $08
    ld a, a
    db $d3
    call z, $d7cf
    call z, $d955
    add c
    ld a, a
    ld d, a
    nop
    and e
    push bc
    jp nc, $c1d4

    ret


    adc $cc
    reti


    adc h
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld e, b
    nop
    and e
    push bc
    jp nc, $c1d4

    ret


    adc $cc
    reti


    adc h
    ld a, a
    and c
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    pop bc
    call $8cce
    call nz, $cdc1
    adc $81
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    ld c, a
    call Call_023_7fc5
    call nc, $c1c8
    call nc, $c27f
    ret


    set 0, l
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
    adc h
    ld a, a
    xor c
    ld a, a
    call nz, $cecf
    add a
    call nc, Call_023_7f4f
    rst $10
    pop bc
    adc $d4
    ld a, a
    call Call_023_7fd9
    jp nz, $cbc9

    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
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
    adc $4f
    push bc
    adc $d4
    ld a, a
    call nc, $cfc8
    jp nc, $d5cf

    rst $00
    ret z

    call z, $81d9
    ld a, a
    ld e, b
    nop
    ld a, a
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
    adc $4f
    push bc
    adc $d4
    ld a, a
    call nc, $cfc8
    jp nc, $d5cf

    rst $00
    ret z

    call z, $81d9
    ld a, a
    ld e, b
    nop
    ld a, a
    xor h
    rst $08
    sub $c5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    rst $00
    push de
    pop bc
    jp nc, Jump_023_7fc4

    ret z

    ld c, a
    ret


    call Call_023_7f81
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    ret


    adc $c7
    ld a, a
    adc $cf
    call nc, $c27f
    pop bc
    call nz, Call_023_7f81
    xor c
    ld c, a
    add a
    call $d67f
    push bc
    jp nc, Jump_023_7fd9

    jp nz, $d2cf

    push bc
    call nz, $c17f
    jp nz, $55cf

    push de
    call nc, $c47f
    push bc
    add $c5
    pop bc
    call nc, $817f
    ld a, a
    ld d, a
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    set 2, l
    adc $cb
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


    call nc, Call_023_7f81
    and d
    push bc
    ld a, a
    jp $4fc1


    jp nc, $c6c5

    push de
    call z, Call_023_7f8c
    call nz, $cecf
    add a
    call nc, $d47f
    rst $08
    push de
    jp $c855


    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, $8cd3

    ld a, a
    call nz, $cecf
    add a
    call nc, $c67f
    ld d, l
    call z, $c5c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    db $d3
    call nc, $ccc9
    call z, $c87f
    push bc
    jp nc, $c54f

    add c
    ld a, a
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    add $d2
    ret


    ld d, l
    rst $00
    ret z

    call nc, $cec5
    push bc
    call nz, Call_023_7f8c
    rst $00
    rst $08
    ld a, a
    call nc, Call_023_7fcf
    ret nc

    ret


    ld d, l
    adc $cb
    ld a, a
    jp $d4c9


    reti


    ld a, a
    pop bc
    call z, $cecf
    rst $00
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    jp $c1cf


    db $d3
    call nc, Call_023_7f81
    ld d, a
    nop
    ld a, a
    call nc, $d5c8
    call $8cd0
    ld a, a
    jp nz, $cec1

    rst $00
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    call nc, $d5c8
    call $8cd0
    ld a, a
    jp nz, $cec1

    rst $00
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor c
    add a
    call $ce7f
    rst $08
    call nc, $c97f
    adc $7f
    rst $00
    rst $08
    rst $08
    call nz, Call_023_4f7f
    push bc
    call $d4cf
    ret


    rst $08
    adc $7f
    adc $cf
    rst $10
    add c
    ld a, a
    ret z

    push bc
    call z, Call_023_55d0
    ld a, a
    call Call_023_7fc5
    call nz, $d6c9
    push bc
    jp nc, Jump_023_7fd4

    call $d3d9
    push bc
    call z, $55c6
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or a
    push bc
    add a
    call z, Call_023_7fcc
    push de
    db $d3
    push bc
    ld a, a
    ld d, h
    adc h
    ld a, a
    adc h
    ld c, a
    ld a, a
    xor c
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    pop bc
    ld a, a
    add $c5
    jp nc, $c3cf

    ret


    rst $08
    ld d, l
    push de
    db $d3
    ld a, a
    rst $08
    adc $c5
    add c
    ld a, a
    db $d3
    rst $08
    ld a, a
    xor c
    ld a, a
    jp $cec1


    ld a, a
    ld d, l
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
    adc $c5
    ld d, l
    adc $d4
    ld a, a
    call nc, $cfc8
    jp nc, $d5cf

    rst $00
    ret z

    call z, $81d9
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    adc $7f
    pop bc
    jp nc, $cfd2

    rst $00
    pop bc
    adc $d4
    ld a, a
    call z, $d4c9
    call nc, $cc4f
    push bc
    ld a, a
    jp nz, $d9cf

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    adc $7f
    pop bc
    jp nc, $cfd2

    rst $00
    pop bc
    adc $d4
    ld a, a
    call z, $d4c9
    call nc, $cc4f
    push bc
    ld a, a
    jp nz, $d9cf

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    pop bc
    bit 7, a
    pop bc
    adc $c4
    ld a, a
    call z, $cdc9
    ret nc

    add c
    ld a, a
    ret z

    ld c, a
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    jp nc, $d3c5

    call nc, Call_023_7f81
    ld d, a
    nop
    ld a, a
    xor a
    ret z

    adc h
    rst $08
    ret z

    add c
    xor c
    ld a, a
    call nz, Call_023_7fcf
    call z, $cbc9
    push bc
    ld a, a
    ld c, a
    call nc, Call_023_7fcf
    call $cbc1
    push bc
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    ld a, a
    ld a, a
    ld d, l
    db $d3
    push de
    jp Jump_023_7fc8


    pop bc
    db $d3
    ld a, a
    push de
    db $d3
    ret


    adc $c7
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    call nc, Call_023_7fcf
    add $d2
    ret


    rst $00
    ret z

    call nc, $cec5
    ld a, a
    adc h
    ld d, l
    ld a, a
    jp nz, $d4c9

    ret


    adc $c7
    ld a, a
    push bc
    pop bc
    jp Jump_023_7fc8


    rst $08
    call nc, $c5c8
    ld d, l
    jp nc, $c17f

    adc $c4
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $08
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c57f
    sub $cf
    set 0, l
    ld a, a
    call Call_023_7fc5
    pop bc
    ld c, a
    adc $c7
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    rst $08
    adc $87
    call nc, $c57f
    sub $cf
    set 0, l
    ld a, a
    call Call_023_7fc5
    pop bc
    ld c, a
    adc $c7
    jp nc, $81d9

    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ld a, a
    ret nc

    jp nc, $d0cf

    pop bc
    rst $00
    pop bc
    adc $c4
    pop bc
    ld a, a
    jp $c5c8


    ld c, a
    push bc
    call nc, Call_023_7f81
    ld d, [hl]
    adc h
    ld a, a
    jp nz, Jump_023_7fc5

    jp $d2c1


    push bc
    add $d5
    ld d, l
    call z, Call_023_7f8c
    call nz, $cecf
    add a
    call nc, $d27f
    pop bc
    adc $c4
    rst $08
    call $d9cc
    ld d, l
    ld a, a
    pop bc
    jp nz, $cec1

    call nz, $cecf
    ld a, a
    ret nc

    jp nc, $d0cf

    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    ld a, a
    jp $c5c8


    pop bc
    ret nc

    ld a, a
    jp nz, $ccd5

    call z, Call_023_4fc5
    call nc, $cec9
    ld a, a
    jp nz, $c1cf

    jp nc, $81c4

    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, Call_023_55c9
    add $c6
    push bc
    jp nc, $cec5

    jp Jump_023_7fc5


    rst $10
    ret


    call z, Call_023_7fcc
    jp nz, Jump_023_7fc5

    ld d, l
    call z, $d2c1
    rst $00
    push bc
    jp nc, $c17f

    adc $c4
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    jp nc, Jump_023_7f55

    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    rst $08
    add $7f
    add $55
    rst $08
    db $d3
    call nc, $d2c5
    ret


    adc $c7
    ld a, a
    ld a, a
    ret nc

    pop bc
    db $d3
    call nc, $cf7f
    adc $55
    adc [hl]
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call $55c5
    ld a, a
    ld d, h
    adc h
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call Call_023_7fc5
    call z, $55c5
    sub $c5
    call z, $8c7f
    ld a, a
    push bc
    sub $c5
    jp nc, Jump_023_7fd9

    call nc, $cdc9
    push bc
    ld a, a
    ld d, l
    ret


    add $7f
    call nc, $c5c8
    ld a, a
    ret nc

    pop bc
    jp nc, $cdc1

    push bc
    call nc, $d2c5
    ld a, a
    ld d, l
    call nz, $c6c9
    add $c5
    jp nc, Jump_023_7fd3

    ld a, a
    db $d3
    call z, $c7c9
    ret z

    call nc, $d9cc
    ld d, l
    ld a, a
    ld d, [hl]
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
    and a
    jp nc, $d3c1

    ret nc

    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    jp nz, $c1d2

    set 0, l
    ld a, a
    adc h
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    ret


    ld d, l
    call nc, $c97f
    db $d3
    ld a, a
    call nz, $d7cf
    adc $c8
    ret


    call z, $8ccc
    ld a, a
    call nc, Call_023_55c8
    push bc
    ld a, a
    call nc, $d2d9
    push bc
    ld a, a
    rst $08
    add $7f
    reti


    rst $08
    push de
    jp nc, $c27f

    ret


    ld d, l
    set 0, l
    ld a, a
    ld a, a
    rst $10
    rst $08
    adc $87
    call nc, $d37f
    call z, $d0c9
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_023_7fc5

    ret


    db $d3
    ld a, a
    xor [hl]
    rst $08
    adc [hl]
    ld a, a
    sub c
    sub a
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

    call nc, $cec5
    adc $c9
    adc $c7
    ld d, l
    ld a, a
    jp $cccf


    rst $08
    push de
    jp nc, $567f

    adc h
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    ld d, l
    jp $d4c9


    reti


    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    ld a, a
    ret nc

    jp nc, $d0cf

    pop bc
    rst $00
    pop bc
    adc $c4
    pop bc
    ld a, a
    jp $c5c8


    ld c, a
    push bc
    call nc, Call_023_7f81
    call nc, $d2c8
    rst $08
    rst $10
    ret


    adc $c7
    ld a, a
    call $cecf
    db $d3
    ld d, l
    call nc, $d2c5
    ld a, a
    jp nz, $ccc1

    call z, $c17f
    adc $c4
    ld a, a
    call nc, $cdd5
    jp nz, $cc55

    ret


    adc $c7
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    add $cf
    jp nc, $c9c2

    call nz, $c5c4
    ld d, l
    adc $81
    ld a, a
    ld d, a
    nop
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nc, $d5cf

    call nc, Call_023_7fc5
    add $cf
    jp nc, $c27f

    ret


    ld c, a
    set 0, l
    ld a, a
    ld d, [hl]
    ld a, a
    call nc, $c1c8
    call nc, $d387
    ld a, a
    pop bc
    call z, Call_023_7fcc
    ld d, l
    add $cf
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    call nz, $d7cf
    adc $c8
    ret


    call z, Call_023_7fcc
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


    add a
    call nc, $d37f
    pop bc
    sub $c5
    ld a, a
    push de
    ld c, a
    ret nc

    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $dac9

    push bc
    ld a, a
    call $cecf
    push bc
    reti


    ld d, l
    ld a, a
    call nc, Call_023_7fcf
    jp $cecf


    call nc, $d3c5
    call nc, $c17f
    rst $00
    pop bc
    ret


    db $d3
    ld d, l
    call nc, $c17f
    ld a, a
    jp nz, $d9cf

    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_023_7fc5

    pop bc
    jp nc, Jump_023_7fc5

    call $cec1
    reti


    ld a, a
    call z, $cf4f
    db $d3
    push bc
    db $d3
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $d5cf

    call nc, $55c5
    ld a, a
    ld a, a
    rst $08
    add $7f
    jp nz, $cbc9

    push bc
    add c
    ld a, a
    ld d, a
    reti


    rst $08
    push de
    add a
    call z, Call_023_55cc
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
    ret nc

    ret


    jp Jump_023_7fcb


    call nc, $c5c8
    call $557f
    push de
    ret nc

    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    push bc
    call z, Call_023_7fcc
    call nc, $c5c8
    call $557f
    rst $08
    push de
    call nc, Call_023_7f8e
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    call $d4cf
    ret


    rst $08
    adc $7f
    ret


    db $d3
    ld a, a
    rst $00
    ld c, a
    rst $08
    rst $08
    call nz, Call_023_7f8c
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    call $d4cf
    ret


    rst $08
    adc $7f
    ret


    db $d3
    ld a, a
    rst $00
    ld c, a
    rst $08
    rst $08
    call nz, Call_023_7f8c
    ld e, b
    nop
    ld a, a
    xor c
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    jp $cecf


    add $c9
    call nz, $cec5
    jp $c54f


    ld a, a
    pop bc
    jp nz, $d5cf

    call nc, $cd7f
    reti


    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    ld d, l
    jp $cdcf


    push bc
    ld a, a
    rst $08
    adc $81
    ld a, a
    jp $cdcf


    push bc
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    call nc, $d5cf
    jp $c5c8


    db $d3
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    db $d3
    call nc, Call_023_4fcf
    call $c3c1
    ret z

    ld a, a
    push de
    adc $c3
    rst $08
    adc $d3
    jp $cfc9


    push de
    db $d3
    call z, $d955
    ld a, a
    ld d, a
    nop
    ld a, a
    and [hl]
    pop bc
    call nc, $d9d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $d5cf

    adc $c4
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    and [hl]
    pop bc
    call nc, $d9d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $d5cf

    adc $c4
    ld a, a
    ld c, a
    ld e, b
    nop
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_023_7fcf
    ret nc

    ret


    adc $cb
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld c, a
    sbc a
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

    call z, $c47f
    rst $08
    ld c, a
    rst $10
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    call z, $d0cf
    push bc
    ld a, a
    jp nz, Jump_023_7fd9

    jp nz, $c955

    set 0, l
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    jp $d9d2


    ret


    adc $c7
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    ret


    call z, Call_023_7fd9
    ld e, b
    nop
    ld a, a
    jp $d9d2


    ret


    adc $c7
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    ret


    call z, Call_023_7fd9
    ld e, b
    nop
    ld a, a
    or a
    push bc
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    reti


    rst $08
    push de
    adc $c7
    push bc
    db $d3
    call nc, Call_023_4f81
    ld a, a
    nop
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld a, a
    ld d, [hl]
    ld a, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ld c, a
    ret nc

    call z, $cec5
    call nc, Call_023_7fd9
    rst $08
    add $7f
    rst $00
    push de
    call nc, $81d3
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
    jp nc, $c97f

    call nc, Call_023_4f7f
    pop bc
    adc $d9
    ld a, a
    call $d2cf
    push bc
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
    push bc
    pop bc
    jp nc, $c97f

    call nc, Call_023_4f7f
    pop bc
    adc $d9
    ld a, a
    call $d2cf
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    pop bc
    ret z

    add c
    ld a, a
    ret nc

    pop bc
    jp nc, $ccc1

    reti


    db $d3
    push bc
    ld a, a
    ret z

    ret


    ld c, a
    call $d77f
    ret


    call nc, Call_023_7fc8
    pop bc
    ld a, a
    jp nz, $ccc9

    push bc
    ld a, a
    jp nz, $ccc1

    ld d, l
    call z, Call_023_7f81
    ld d, a
    nop
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    jp nz, $ccc9

    push bc
    ld a, a
    jp nz, $ccc1

    call z, $d77f
    ld c, a
    pop bc
    db $d3
    ld a, a
    jp nz, $cfd2

    push de
    rst $00
    ret z

    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c855
    push bc
    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, $d37f

    call nc, $d4c1
    ret


    rst $08
    adc $7f
    ld d, l
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
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    reti


    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor l
    reti


    ld a, a
    ld d, h
    adc h
    ld a, a
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    ret z

    ld c, a
    ret


    db $d3
    ld a, a
    call z, $d6c5
    push bc
    call z, $c87f
    ret


    rst $00
    ret z

    rst $00
    jp nc, $c4c1

    ld d, l
    push bc
    call nz, $8c7f
    ld a, a
    ret


    call nc, $c37f
    pop bc
    adc $87
    call nc, $c27f
    push bc
    ld a, a
    ld d, l
    ret nc

    jp nc, $cdcf

    rst $08
    call nc, $c4c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    ld a, a
    call $d9c1
    jp nz, Jump_023_7fc5

    rst $00
    push bc
    call nc, $d07f
    jp nc, $cdcf

    rst $08
    ld c, a
    call nc, $c4c5
    ld a, a
    ld d, a
    ld a, a
    ret


    add $7f
    call nz, $c3c5
    rst $08
    jp nc, $d4c1

    push bc
    call nz, Call_023_7f55
    rst $10
    ret


    call nc, Call_023_7fc8
    db $d3
    call nc, $cecf
    push bc
    db $d3
    ld a, a
    ld a, a
    pop bc
    jp $55c3


    rst $08
    jp nc, $c9c4

    adc $c7
    ld a, a
    call nc, Call_023_7fcf
    call nz, $c6c9
    add $c5
    jp nc, $55c5

    adc $d4
    ld a, a
    ld d, h
    db $d3
    ld a, a
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
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    db $d3
    rst $10
    push bc
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    call $d9c1
    ld a, a
    ret


    adc $c4
    ld c, a
    push de
    jp Jump_023_7fc5


    push bc
    call $c3c1
    ret


    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld d, a
    nop
    ld a, a
    and c
    add $d4
    push bc
    jp nc, $d37f

    rst $10
    push bc
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    adc h
    ld c, a
    ld a, a
    add $c5
    push bc
    call z, Call_023_7fd3
    call z, $cbc9
    push bc
    ld a, a
    push bc
    call $c3c1
    ret


    ld d, l
    pop bc
    call nc, $c4c5
    ld a, a
    pop bc
    ld a, a
    call z, $d4c9
    call nc, $c5cc
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
    ret z

    ld c, a
    pop bc
    jp nc, Jump_023_7fc4

    add $c9
    rst $00
    ret z

    call nc, $cec9
    rst $00
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
    ret z

    ld c, a
    pop bc
    jp nc, Jump_023_7fc4

    add $c9
    rst $00
    ret z

    call nc, $cec9
    rst $00
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or b
    push bc
    jp nc, $c9d3

    db $d3
    call nc, $cec5
    call nc, Call_023_7f7f
    ret


    db $d3
    ld a, a
    call $c54f
    call nz, $ccc1
    ld a, a
    rst $08
    add $7f
    call $cec1
    add a
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    jp nc, Jump_023_7fc5

    pop bc
    ld a, a
    call $cec1
    adc h
    ld c, a
    ld a, a
    ld a, a
    reti


    rst $08
    push de
    add a
    call z, Call_023_7fcc
    pop bc
    call nz, $c5c8
    jp nc, Jump_023_7fc5

    call nc, $cf55
    ld a, a
    reti


    rst $08
    push de
    jp nc, $c27f

    pop bc
    db $d3
    ret


    jp $cc7f


    ret


    adc $c5
    ld d, l
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
    ld e, b
    nop
    ld a, a
    or a
    pop bc
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
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    call z, $d47f
    ret z

    ld c, a
    push bc
    ld a, a
    jp nz, $cbc9

    push bc
    ld a, a
    ret


    db $d3
    add c
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    rst $10
    push bc
    ld d, l
    call z, Call_023_7fcc
    call nz, Call_023_7fcf
    reti


    rst $08
    push de
    ld a, a
    add $c5
    push bc
    call z, $cf7f
    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $cbc9

    push bc
    sbc a
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

Call_023_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_023_7f55:
Jump_023_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_023_7f7f:
Jump_023_7f7f:
    nop
    nop

Call_023_7f81:
Jump_023_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_023_7f8c:
Jump_023_7f8c:
    nop
    nop

Call_023_7f8e:
Jump_023_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_023_7f9f:
Jump_023_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_023_7fc1:
    nop
    nop
    nop

Call_023_7fc4:
Jump_023_7fc4:
    nop

Call_023_7fc5:
Jump_023_7fc5:
    nop
    nop
    nop

Call_023_7fc8:
Jump_023_7fc8:
    nop
    nop
    nop

Jump_023_7fcb:
    nop

Call_023_7fcc:
Jump_023_7fcc:
    nop
    nop

Jump_023_7fce:
    nop

Call_023_7fcf:
Jump_023_7fcf:
    nop
    nop
    nop
    nop

Call_023_7fd3:
Jump_023_7fd3:
    nop

Jump_023_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_023_7fd9:
Jump_023_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
