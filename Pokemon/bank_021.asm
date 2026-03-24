; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $021", ROMX[$4000], BANK[$21]

    ld a, a
    and c
    add $d4
    push bc
    jp nc, $c57f

    sub $cf
    call z, $d4d5
    ret


    rst $08
    adc $8c
    ld a, a
    db $e4
    rst $08
    adc $cc
    reti


    ld a, a
    add $cf
    rst $08
    call nc, Call_021_7f7f
    jp $cec1


    ld a, a
    db $d3
    call nc, $e4c1
    adc $c4
    ld a, a
    push de
    ret nc

    adc [hl]
    ld a, a
    xor c
    add $7f
    cp b
    ret


    jp nz, Jump_021_7fc1

    ret


    db $d3
    ld a, a
    db $e4
    call nc, $d2c9
    push bc
    call nz, $c87f
    push bc
    ld a, a
    jp $cec1


    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    db $e4
    call nz, $c9d2
    call z, Call_021_7fcc
    pop bc
    ld a, a
    ret z

    rst $08
    call z, Call_021_7fc5
    ret


    adc $7f
    call nc, $e4c8
    push bc
    ld a, a
    jp nc, $c3cf

    res 1, [hl]
    ld a, a
    ld d, b
    ld a, a
    or b
    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $c2c1

    reti


    ld a, a
    ret


    adc $d4
    rst $08
    db $e4
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cdcf
    pop bc
    jp Jump_021_7fc8


    rst $08
    add $7f
    call nc, $e4c8
    push bc
    ld a, a
    add $c5
    call $ccc1
    push bc
    ld a, a
    call nc, Call_021_7fcf
    add $cf
    db $d3
    call nc, $d2c5
    db $e4
    ld a, a
    or h
    ret z

    push de
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    adc $c4
    ld a, a
    rst $08
    db $e4
    add $7f
    jp nz, $d8cf

    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    db $d3
    push de
    jp $c5c3


    db $d3
    db $e4
    db $d3
    ret


    rst $08
    adc $7f
    ld d, b
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    push bc
    pop bc
    jp nc, Jump_021_7fd3

    jp nz, $c3c5

    rst $08
    call Call_021_7fc5
    call z, $c1e4
    jp nc, $c5c7

    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    ret z

    push bc
    pop bc
    jp nc, $cec9

    rst $00
    ld a, a
    db $e4
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    ld a, a
    add $c1
    jp nc, $c17f

    rst $10
    pop bc
    reti


    ld a, a
    ret nc

    rst $08
    db $e4
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $d3
    ld a, a
    adc $c5
    push bc
    call nz, $c5cc
    ld a, a
    ret


    db $d3
    ld a, a
    db $e4
    push bc
    ret c

    ret nc

    call z, $c4cf
    push bc
    call nz, $d77f
    ret z

    push bc
    adc $7f
    rst $00
    push bc
    call nc, $e4d4
    ret


    adc $c7
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_021_7fd9

    pop bc
    adc $c4
    ld a, a
    call $d6cf
    push bc
    db $e4
    ld a, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    call z, $d6cf
    push bc
    call z, Call_021_7fd9
    pop bc
    adc $e4
    call nz, $c97f
    db $d3
    ld a, a
    rst $10
    push bc
    call z, $cfc3
    call Call_021_7fc5
    ld a, a
    call z, $cbc9
    push bc
    db $e4
    ld a, a
    pop bc
    ld a, a
    ret nc

    push bc
    call nc, $c27f
    push de
    call nc, $cf7f
    adc $cc
    reti


    ld a, a
    adc $cf
    db $e4
    call nc, $c27f
    push bc
    ld a, a
    push bc
    pop bc
    db $d3
    ret


    call z, Call_021_7fd9
    add $cf
    push de
    adc $c4
    ld a, a
    db $e4
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    jp nz, $d3d5

    reti


    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    push bc
    sub $c5
    jp nc, $d7d9

    ret z

    push bc
    jp nc, Jump_021_7fc5

    adc [hl]
    db $e4
    ld a, a
    ld a, a
    xor [hl]
    rst $08
    ld a, a
    call $c3d5
    ret z

    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, $e4c8
    ld a, a
    jp nz, $d4d5

    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    call nz, $c6c9
    add $c9
    jp $e4d5


    call z, Call_021_7fd4
    call nc, $c4cf
    push bc
    pop bc
    call z, $d77f
    ret


    call nc, Call_021_7fc8
    rst $10
    ret z

    push bc
    db $e4
    adc $7f
    ret nc

    pop bc
    jp nc, $cfd2

    call nc, $cec9
    rst $00
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    ret


    call nz, $cec5
    call nc, $c6c9
    ret


    push bc
    call nz, $e47f
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    ld a, a
    ret


    call nc, $c37f
    pop bc
    adc $7f
    db $d3
    rst $08
    db $e4
    push de
    adc $c4
    ld a, a
    call nz, $d3c9
    pop bc
    rst $00
    jp nc, $c5c5

    pop bc
    jp nz, $c5cc

    ld a, a
    jp $c8e4


    ret


    jp nc, $d3d0

    ld a, a
    pop bc
    adc $c4
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    ret z

    pop bc
    db $d3
    db $e4
    ld a, a
    db $d3
    rst $08
    call Call_021_7fc5
    db $d3
    push de
    call nz, $c5c4
    adc $7f
    db $d3
    push bc
    call z, $8dc6
    db $e4
    push bc
    ret c

    ret nc

    call z, $d3cf
    ret


    rst $08
    adc $7f
    jp nz, $c8c5

    pop bc
    sub $c9
    rst $08
    jp nc, $d3e4

    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret z

    pop bc
    jp nc, Jump_021_7fc4

    db $d3
    set 1, c
    adc $7f
    call z, $c9e4
    set 0, l
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret z

    pop bc
    db $e4
    db $d3
    ld a, a
    pop bc
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $e4
    db $d3
    ld a, a
    ret z

    rst $08
    jp nc, Jump_021_7fce

    and d
    push bc
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, $e48e
    ld a, a
    ld d, b
    ld a, a
    xor b
    ret


    db $d3
    ld a, a
    call nc, $c9c1
    call z, $d77f
    pop bc
    db $d3
    ld a, a
    jp nz, $d4c9

    call nc, $c5e4
    adc $7f
    jp nz, Jump_021_7fd9

    cp b
    push de
    push bc
    call z, $c4d5
    pop bc
    ld a, a
    rst $10
    ret z

    push bc
    adc $e4
    ld a, a
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    call nc, Call_021_7fcf
    db $d3
    push bc
    pop bc
    db $d3
    ret


    call nz, Call_021_7fc5
    db $e4
    call nc, Call_021_7fcf
    add $c5
    call nc, $c8c3
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    jp nz, $c1e4

    ret


    call nc, $c17f
    adc $c4
    ld a, a
    call nc, $d5c8
    db $d3
    ld a, a
    jp nz, $c3c5

    rst $08
    call $c5e4
    ld a, a
    rst $08
    adc $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    call z, $cbc9
    push bc
    db $e4
    ld a, a
    adc $cf
    rst $10
    ld a, a
    ld d, b
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_021_7fe4

    jp nz, $c4d5

    ld a, a
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c3c1

    bit 7, a
    db $e4
    rst $10
    ret z

    ret


    jp Jump_021_7fc8


    pop bc
    jp nz, $cfd3

    jp nc, $d3c2

    ld a, a
    adc $d5
    call nc, $e4d2
    ret


    push bc
    adc $d4
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nz, $cfcc

    rst $08
    call Call_021_7fd3
    pop bc
    db $e4
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    ld a, a
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_021_507f

    ld a, a
    ret


    db $d3
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    rst $10
    pop bc
    call z, $c9cb
    adc $c7
    db $e4
    ld a, a
    call nc, $cfd2
    ret nc

    ret


    jp $ccc1


    ld a, a
    add $cf
    jp nc, $d3c5

    call nc, $c57f
    db $e4
    pop bc
    jp Jump_021_7fc8


    add $d2
    push de
    ret


    call nc, $c87f
    pop bc
    db $d3
    ld a, a
    ret


    call nc, Call_021_7fd3
    db $e4
    rst $08
    rst $10
    adc $7f
    add $c1
    jp Jump_021_7fc5


    pop bc
    adc $c4
    ld a, a
    push bc
    pop bc
    jp Jump_021_7fc8


    db $e4
    ret z

    pop bc
    db $d3
    ld a, a
    ret


    call nc, Call_021_7fd3
    rst $08
    rst $10
    adc $7f
    jp $cecf


    db $d3
    jp $e4c9


    rst $08
    push de
    db $d3
    adc $c5
    db $d3
    db $d3
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c9d7
    jp Jump_021_7fc5


    ret z

    ret


    rst $00
    ret z

    push bc
    jp nc, $d47f

    db $e4
    ret z

    pop bc
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    ret


    call nc, $c37f
    pop bc
    db $e4
    adc $7f
    jp nc, $d4cf

    pop bc
    call nc, Call_021_7fc5
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    ret z

    pop bc
    db $e4
    adc $c4
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    call nc, $cbc1
    ret


    adc $c7
    ld a, a
    add $cf
    rst $08
    db $e4
    call nz, $cf7f
    jp nc, $c17f

    call nc, $c1d4
    jp $c9cb


    adc $c7
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call z, $cbc9
    push bc
    db $d3
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $c17f
    adc $7f
    push bc
    rst $00
    rst $00
    db $e4
    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    call z, Call_021_7fd9
    db $e4
    call z, $cbc9
    push bc
    db $d3
    ld a, a
    db $d3
    push bc
    push bc
    call nz, Call_021_7f7f
    rst $08
    add $7f
    ret nc

    call z, $e4c1
    adc $d4
    ld a, a
    pop bc
    call z, Call_021_7fcc
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_021_7fc5
    set 1, [hl]
    rst $08
    rst $10
    db $e4
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    adc [hl]
    db $e4
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call nz, $d5c1
    jp nz, $c97f

    jp nc, $c1d2

    call nz, $c1c9
    db $e4
    call nc, $c4c5
    ld a, a
    jp nz, Jump_021_7fd9

    ret c

    adc l
    jp nc, $d9c1

    db $d3
    ld a, a
    add $d2
    rst $08
    call Call_021_7fe4
    call nc, $c5c8
    ld a, a
    call $cfcf
    adc $7f
    ret z

    push bc
    ld a, a
    call z, $cbc9
    push bc
    db $d3
    db $e4
    ld a, a
    call nz, $d2c9
    call nc, Call_021_7fd9
    call nc, $c9c8
    adc $c7
    db $d3
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    call nc, $c17f
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_021_7fd3

    ret


    adc $7f
    call nc, $c5c8
    db $e4
    ld a, a
    call nz, $d2c1
    bit 7, a
    rst $10
    ret z

    push bc
    adc $7f
    call z, $d6c9
    push bc
    db $d3
    ld a, a
    call nz, $c9e4
    push bc
    call nz, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    call $d5cf
    adc $c1
    call nc, $e4c9
    adc $7f
    ld d, b
    ld a, a
    db $e4
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, Jump_021_7f7f

    ret


    db $d3
    ld a, a
    db $d3
    call nc, $cfd2
    db $e4
    adc $c7
    ld a, a
    push bc
    sub $c5
    adc $7f
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    ret


    call nc, $e47f
    ret


    db $d3
    ld a, a
    db $d3
    call $ccc1
    call z, $d47f
    ret z

    push bc
    ld a, a
    add $c5
    call $ccc1
    db $e4
    push bc
    add a
    db $d3
    ld a, a
    ret z

    rst $08
    jp nc, Jump_021_7fce

    ret


    db $d3
    ld a, a
    db $d3
    call $ccc1
    call z, $e4c5
    jp nc, Jump_021_7f8e

    and d
    push bc
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, Call_021_7f8e
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    ret z

    pop bc
    jp nc, Jump_021_7fc4

    ret z

    ret


    db $d3
    ld a, a
    db $e4
    jp nz, $c4cf

    reti


    ld a, a
    ret


    db $d3
    ld a, a
    add $d5
    call z, Call_021_7fcc
    rst $08
    add $7f
    db $d3
    jp $c1e4


    call z, $d3c5
    ld a, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    adc $c5
    push bc
    call nz, $c5cc
    db $d3
    db $e4
    ld a, a
    ld a, a
    call nc, $c5c8
    db $d3
    push bc
    ld a, a
    adc $c5
    push bc
    call nz, $c5cc
    db $d3
    ld a, a
    jp $e4c1


    adc $7f
    db $d3
    call nc, $cec1
    call nz, $d57f
    ret nc

    db $d3
    ret


    push bc
    ld a, a
    call nz, $d7cf
    adc $e4
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    push bc
    ret c

    jp $d4c9


    push bc
    call nz, Call_021_7f8e
    ld d, b
    ld a, a
    call nc, Call_021_7fcf
    rst $10
    push bc
    pop bc
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    jp nz, $cecf

    push bc
    db $d3
    db $e4
    ld a, a
    rst $08
    add $7f
    call nz, $c5c9
    call nz, $cd7f
    rst $08
    call nc, $c5c8
    jp nc, $d387

    ld a, a
    db $e4
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c17f
    adc $c4
    ld a, a
    jp $e4d2


    reti


    ld a, a
    call z, $d5cf
    call nz, $d9cc
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    rst $00
    push bc
    call nc, $e4d4
    ret


    adc $c7
    ld a, a
    call z, $cecf
    push bc
    call z, Call_021_7fd9
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c1d2

    ret


    adc $7f
    ret


    db $d3
    ld a, a
    call nz, $ccd5
    call z, Call_021_7fe4
    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    db $e4
    call nc, $cfd2
    adc $c7
    ld a, a
    ret


    call nc, $c37f
    pop bc
    adc $7f
    jp nz, $c5d2

    pop bc
    set 4, h
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    db $d3
    jp $c1d2


    ret nc

    push bc
    jp nc, $d47f

    rst $08
    db $e4
    ld a, a
    ret nc

    ret


    push bc
    jp $d3c5


    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    ret


    call nc, Call_021_7fd3
    jp nz, $cfe4

    call nz, $87d9
    db $d3
    ld a, a
    db $d3
    call $d3c1
    ret z

    adc l
    push de
    ret nc

    ld a, a
    ld d, b
    ld a, a
    jp $cec1


    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    adc $c4
    ld a, a
    rst $10
    ret z

    db $e4
    pop bc
    call nc, $c17f
    ld a, a
    call $cec1
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $c87f
    pop bc
    db $d3
    ld a, a
    db $e4
    pop bc
    ld a, a
    ret z

    ret


    rst $00
    ret z

    ld a, a
    xor c
    or c
    ld a, a
    call z, $cbc9
    push bc
    db $d3
    ld a, a
    call nc, $e4cf
    ld a, a
    jp $d2c1


    jp nc, Jump_021_7fd9

    ret nc

    pop bc
    db $d3
    db $d3
    push bc
    adc $c7
    push bc
    jp nc, Jump_021_7fd3

    db $e4
    call $d2c1
    jp $c9c8


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    db $e4
    pop bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $e4c5
    jp nc, Jump_021_7f7f

    ret


    adc $7f
    and e
    ret z

    ret


    adc $c5
    db $d3
    push bc
    ld a, a
    call z, $c7c5
    push bc
    db $e4
    adc $c4
    db $d3
    ld a, a
    jp $d5cf


    call z, Call_021_7fc4
    jp nc, $ced5

    ld a, a
    rst $10
    ret


    call nc, $e4c8
    ld a, a
    pop bc
    adc $7f
    pop bc
    db $d3
    call nc, $cecf
    ret


    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    db $d3
    ret nc

    db $e4
    push bc
    push bc
    call nz, Call_021_7f8e
    ld d, b
    ld a, a
    db $d3
    push de
    jp nc, $c9d6

    sub $c5
    call nz, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    db $e4
    rst $08
    push de
    call nc, Call_021_7fc8
    or b
    rst $08
    call z, Call_021_7fc5
    ret


    call nc, $d37f
    ret z

    rst $08
    push de
    call z, $c4e4
    ld a, a
    jp nz, Jump_021_7fc5

    push bc
    ret c

    call nc, $cec9
    jp Jump_021_7fd4


    ld d, h
    ld a, a
    ld a, a
    call z, $cecf
    db $e4
    rst $00
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    rst $00
    rst $08
    ld a, a
    xor c
    call nc, Call_021_7fd3
    xor c
    or c
    ld a, a
    db $e4
    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    ret z

    ret


    rst $00
    ret z

    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp $c1e4


    adc $7f
    jp nc, $cdc5

    push bc
    call $c5c2
    jp nc, $c57f

    sub $c5
    jp nc, $d4d9

    db $e4
    ret z

    ret


    adc $c7
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    jp $c1c8


    jp nc, $c3c1

    call nc, $d2c5
    ret


    db $d3
    call nc, $c3c9
    ld a, a
    ret


    db $d3
    db $e4
    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    add $c5
    jp nc, $c3cf

    ret


    rst $08
    push de
    db $d3
    ld a, a
    call nc, $e4c8
    push bc
    ld a, a
    call nz, $d3c5
    call nc, $cfd2
    reti


    ret


    adc $c7
    adc l
    jp nc, $d9c1

    db $d3
    ld a, a
    db $e4
    ld a, a
    db $d3
    ret nc

    jp nc, $d9c1

    push bc
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld a, a
    db $e4
    call $d5cf
    call nc, Call_021_7fc8
    jp $cec1


    ld a, a
    jp nz, $d2d5

    adc $7f
    push bc
    sub $c5
    db $e4
    jp nc, $d4d9

    ret z

    ret


    adc $c7
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    jp $d6cf


    push bc
    jp nc, $c4c5

    ld a, a
    jp nz, Jump_021_7fd9

    pop bc
    ld a, a
    jp $d2e4


    push de
    db $d3
    call nc, Call_021_7f7f
    ret z

    pop bc
    jp nc, $c5c4

    jp nc, $d47f

    ret z

    pop bc
    adc $7f
    db $e4
    call nz, $c1c9
    call $cecf
    call nz, $c27f
    push de
    call nc, $c97f
    call nc, Call_021_7fd3
    ret


    adc $e4
    adc $c5
    jp nc, $c97f

    db $d3
    ld a, a
    push de
    adc $c5
    ret c

    ret nc

    push bc
    jp $c5d4


    call nz, $e4cc
    reti


    ld a, a
    db $d3
    rst $08
    add $d4
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c1d2
    adc $d3
    ret nc

    pop bc
    jp nc, $cec5

    call nc, Call_021_7f7f
    call z, $c9e4
    set 0, l
    ld a, a
    jp $d9d2


    db $d3
    call nc, $ccc1
    ld a, a
    ret


    call nc, $c37f
    pop bc
    adc $e4
    ld a, a
    push bc
    call $d4c9
    ld a, a
    pop bc
    adc $7f
    ret


    adc $c3
    rst $08
    adc $c3
    push bc
    ret


    sub $e4
    pop bc
    jp nz, $c5cc

    ld a, a
    call z, $c7c9
    ret z

    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    ret


    call nc, $d3e4
    ld a, a
    push bc
    reti


    push bc
    ld a, a
    jp nz, $ccc1

    call z, $8ed3
    ld a, a
    ld d, b
    ld a, a
    pop bc
    ld a, a
    call nc, $c9c8
    adc $7f
    pop bc
    adc $c4
    ld a, a
    call z, $c7c9
    ret z

    call nc, $e47f
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    ld a, a
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    rst $00
    pop bc
    db $d3
    db $e4
    ld a, a
    ld a, a
    ret z

    push bc
    ld a, a
    jp $cec1


    ld a, a
    call $cbc1
    push bc
    ld a, a
    pop bc
    adc $7f
    xor c
    db $e4
    adc $c4
    ret


    pop bc
    adc $7f
    push bc
    call z, $d0c5
    ret z

    pop bc
    adc $d4
    ld a, a
    add $c1
    call z, $cce4
    ld a, a
    call nz, $d7cf
    adc $7f
    rst $10
    ret


    call nc, $c9c8
    adc $7f
    sub d
    ld a, a
    db $d3
    push bc
    db $e4
    jp $cecf


    call nz, Call_021_7fd3
    rst $10
    ret z

    push bc
    adc $7f
    db $d3
    push de
    jp nc, $cfd2

    push de
    adc $e4
    call nz, $cec9
    rst $00
    ld a, a
    ret


    call nc, Call_021_7f8e
    ld d, b
    ld a, a
    jp $d4d5


    db $d3
    ld a, a
    rst $08
    add $c6
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d0c1


    call nc, $d5e4
    jp nc, Jump_021_7fc5

    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    ret z

    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, $e4d9

    ld a, a
    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    db $d3
    ret


    jp $cccb


    push bc
    ld a, a
    call nc, Call_021_7fcf
    call $c1e4
    set 0, l
    ld a, a
    ret


    call nc, $d37f
    call nc, $d0cf
    ld a, a
    jp nz, $c5d2

    pop bc
    call nc, $e4c8
    ld a, a
    ld a, a
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    rst $10
    ret


    adc $c7
    db $d3
    ld a, a
    call nc, Call_021_7fcf
    add $cc
    db $e4
    reti


    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    call z, $d4c9
    call nc, $c5cc
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    pop bc
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    ld a, a
    db $d3
    rst $10
    pop bc
    jp nc, $d3cd

    ld a, a
    rst $08
    add $e4
    ld a, a
    add $c9
    jp nc, $c6c5

    call z, $c5c9
    db $d3
    ld a, a
    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, $e47f

    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    db $d3
    ret


    call nz, Call_021_7fc5
    call nc, $c5c8
    db $e4
    ld a, a
    pop bc
    jp nz, $cfc4

    call $cec5
    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    add $cc
    pop bc
    db $d3
    db $e4
    ret z

    ld a, a
    pop bc
    adc $c4
    ld a, a
    call z, $c7c9
    ret z

    call nc, $cec5
    ld a, a
    ret


    adc $7f
    call nc, $c8e4
    push bc
    ld a, a
    push bc
    sub $c5
    adc $c9
    adc $c7
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    jp $cec1


    ld a, a
    ret nc

    jp nc, $d3c5

    db $d3
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    ret z

    push bc
    pop bc
    db $e4
    sub $d9
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    db $e4
    rst $08
    adc $c5
    adc $d4
    add a
    db $d3
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    call nc, Call_021_7fcf
    call $e4c1
    set 0, l
    ld a, a
    ret


    call nc, $c37f
    ret z

    rst $08
    set 1, c
    adc $c7
    ld a, a
    ret


    call nc, Call_021_7fd3
    db $e4
    jp nz, $c4cf

    reti


    ld a, a
    jp $cec1


    ld a, a
    ret z

    ret


    call nz, Call_021_7fc5
    ret


    adc $d4
    rst $08
    db $e4
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d5d2


    db $d3
    call nc, $d77f
    ret z

    push bc
    adc $7f
    call $e4c5
    push bc
    call nc, $cec9
    rst $00
    ld a, a
    pop bc
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, Jump_021_7f8e

    ld d, b
    ld a, a
    call nc, $cfd7
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    ret z

    rst $08
    jp nc, $d3ce

    ld a, a
    pop bc
    jp nc, $c5e4

    ld a, a
    add $d5
    call z, Call_021_7fcc
    rst $08
    add $7f
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, $e4c8
    ld a, a
    ld a, a
    pop bc
    db $d3
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    db $d3
    ld a, a
    ret z

    push bc
    ld a, a
    rst $00
    jp nc, $c9e4

    ret nc

    db $d3
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
    ret z

    db $e4
    push bc
    add a
    call z, Call_021_7fcc
    adc $c5
    sub $c5
    jp nc, $cc7f

    rst $08
    rst $08
    db $d3
    push bc
    adc $7f
    db $e4
    push de
    adc $d4
    ret


    call z, $c37f
    pop bc
    ret nc

    call nc, $d2d5
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $cfe4
    jp nc, $8ece

    ld a, a
    ld d, b
    ld a, a
    jp nz, $d5cc

    push bc
    ld a, a
    call nc, $c1d2
    ret


    call z, $cec9
    rst $00
    ld a, a
    ret nc

    call z, $e4c1
    adc $d4
    ld a, a
    jp $cec1


    add a
    call nc, $d37f
    push bc
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $d2e4
    push de
    push bc
    ld a, a
    add $c1
    jp Jump_021_7fc5


    ld a, a
    rst $08
    add $7f
    call nc, $c9d7
    adc $c9
    db $e4
    adc $c7
    ld a, a
    push bc
    pop bc
    jp Jump_021_7fc8


    rst $08
    call nc, $c5c8
    jp nc, $c37f

    pop bc
    adc $7f
    db $e4
    call nc, $c9d7
    adc $c5
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    jp $e4cc


    rst $08
    db $d3
    push bc
    ld a, a
    call nc, $8ecf
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $ccc5

    push de
    jp $c1d4


    adc $d4
    ld a, a
    call nc, Call_021_7fcf
    call z, $c5e4
    pop bc
    sub $c5
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    db $d3
    call nc, $c97f
    db $d3
    ld a, a
    sub $e4
    push bc
    jp nc, Jump_021_7fd9

    ret z

    rst $08
    adc $c5
    db $d3
    call nc, Call_021_7f7f
    call nc, Call_021_7fcf
    call nc, $c5c8
    db $e4
    ld a, a
    ret z

    rst $08
    db $d3
    call nc, $d77f
    ret z

    push bc
    adc $7f
    call $c5c5
    call nc, $cec9
    rst $00
    db $e4
    ld a, a
    ld a, a
    pop bc
    adc $7f
    push bc
    adc $c5
    call $8cd9
    ld a, a
    jp $cec1


    ld a, a
    jp nc, $e4d5

    db $d3
    ret z

    ld a, a
    push de
    ret nc

    ld a, a
    call nc, Call_021_7fcf
    jp nz, $d4c9

    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    push bc
    ret c

    ret


    call z, Call_021_7fc5
    ret


    call nc, Call_021_507f
    ld a, a
    call z, $d6c9
    push bc
    db $d3
    ld a, a
    ret


    adc $7f
    push bc
    pop bc
    jp nc, $c8d4

    ld a, a
    jp $e4c1


    adc $7f
    call nz, $c7c9
    ld a, a
    call nc, $ced5
    adc $c5
    call z, $d57f
    adc $c4
    push bc
    jp nc, $c7e4

    jp nc, $d5cf

    adc $c4
    ld a, a
    pop bc
    call nc, $c17f
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, $e47f
    rst $08
    add $7f
    add b
    ld a, a
    xor e
    call $c88f
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call z, $cfcf
    set 2, e
    db $e4
    ld a, a
    add $cf
    jp nc, $c67f

    rst $08
    rst $08
    call nz, $d77f
    ret z

    ret


    call z, Call_021_7fc5
    call nz, $e4c9
    rst $00
    rst $00
    ret


    adc $c7
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    jp $cec1


    ld a, a
    add $cc
    reti


    ld a, a
    ret


    adc $7f
    db $d3
    push de
    jp $c5c3


    db $d3
    db $e4
    db $d3
    ret


    rst $08
    adc $7f
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    ld a, a
    rst $10
    ret


    db $e4
    call nc, Call_021_7fc8
    ret z

    ret


    db $d3
    ld a, a
    rst $00
    ret


    pop bc
    adc $d4
    ld a, a
    rst $10
    ret


    adc $c7
    db $d3
    db $e4
    ld a, a
    ld a, a
    adc $cf
    ld a, a
    ret nc

    jp nc, $c2cf

    call z, $cdc5
    ld a, a
    call nc, Call_021_7fcf
    add $cc
    db $e4
    reti


    ld a, a
    rst $10
    ret z

    rst $08
    call z, Call_021_7fc5
    pop bc
    ld a, a
    call nz, $d9c1
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call nz, $d3c9
    call z, $e4c9
    set 0, l
    db $d3
    ld a, a
    add $c9
    rst $00
    ret z

    call nc, $cec9
    rst $00
    ld a, a
    ret z

    ret


    call nz, $d3c5
    db $e4
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    jp $cec1


    ld a, a
    db $e4
    jp $d4c1


    jp Jump_021_7fc8


    ret


    adc $d3
    push bc
    jp $d3d4


    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    pop bc
    call z, $cbc9
    push bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call nz, $ccd5
    call z, $d97f
    rst $08
    db $e4
    push de
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
    call nc, $e47f
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c9c8
    adc $c7
    set 1, c
    adc $c7
    ld a, a
    ret z

    push bc
    db $e4
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    adc $c4
    ld a, a
    rst $08
    add $7f
    jp $d4c1


    jp $c9c8


    db $e4
    adc $c7
    ld a, a
    jp nz, $c9c1

    call nc, $c27f
    reti


    ld a, a
    call nc, $c9c1
    call z, Call_021_7f8e
    ld d, b
    ld a, a
    xor a
    adc $c5
    ld a, a
    call $d2cf
    adc $c9
    adc $c7
    ld a, a
    db $d3
    rst $08
    call $c4c5
    db $e4
    pop bc
    reti


    adc h
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
    jp z, $d5e4

    sub $c5
    adc $c9
    call z, Call_021_7fc5
    ld a, a
    pop bc
    rst $10
    rst $08
    set 0, l
    ld a, a
    add $d2
    rst $08
    db $e4
    call $d47f
    ret z

    push bc
    ld a, a
    jp nz, $c4c5

    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nz, $c3c5

    pop bc
    db $e4
    call Call_021_7fc5
    pop bc
    jp nz, $cfd3

    jp nc, $c5c2

    call nz, Call_021_7f8e
    ld d, b
    ld a, a
    rst $08
    add $d4
    push bc
    adc $7f
    add $c1
    call z, $d3cc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $cfe4

    call z, $d3cc
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    rst $00
    rst $08
    ret


    adc $c7
    ld a, a
    rst $08
    adc $e4
    ld a, a
    call nc, $c5c8
    ld a, a
    call nz, $d7cf
    adc $d7
    pop bc
    jp nc, Jump_021_7fc4

    db $d3
    call z, $d0cf
    db $e4
    push bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call z, $d9c1
    db $d3
    ld a, a
    db $d3
    push bc
    sub $c5
    jp nc, $ccc1

    ld a, a
    ld a, a
    call nc, $d3c1
    db $e4
    call nc, Call_021_7fd9
    pop bc
    adc $c4
    ld a, a
    adc $d5
    call nc, $c9d2
    push bc
    adc $d4
    ld a, a
    push bc
    rst $00
    db $e4
    rst $00
    db $d3
    ld a, a
    push bc
    pop bc
    jp Jump_021_7fc8


    call nz, $d9c1
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    ret


    pop bc
    adc $d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret z

    db $e4
    push bc
    pop bc
    sub $d9
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    call nc, Call_021_7fcf
    ret z

    push bc
    call z, Call_021_7fd0
    db $e4
    call nc, $c1d2
    adc $d3
    ret nc

    rst $08
    jp nc, $c9d4

    adc $c7
    ld a, a
    jp nz, $d4d5

    ld a, a
    adc $e4
    push bc
    sub $c5
    jp nc, $d47f

    rst $08
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_021_7fc5
    add $c1
    call nc, $c9e4
    rst $00
    push de
    push bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    push bc
    pop bc
    db $d3
    ret


    call z, Call_021_7fd9
    call $cbc1
    push bc
    db $d3
    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    db $e4
    call z, Call_021_7fc5
    call nc, Call_021_7fcf
    jp nz, $ccc5

    ret


    push bc
    sub $c5
    ld a, a
    ld a, a
    ret


    call nc, $e47f
    pop bc
    adc $c4
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, $e4d3

    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call z, Call_021_7fcc
    rst $08
    add $7f
    db $d3
    jp $c5e4


    adc $c5
    jp nc, $8ed9

    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c5
    push bc
    call nc, $c37f
    pop bc
    adc $7f
    db $d3
    call nc, $c5d2
    db $e4
    call nc, $c8c3
    ld a, a
    rst $08
    push de
    call nc, $c17f
    adc $c4
    ld a, a
    call nz, $c1d2
    rst $10
    ld a, a
    jp nz, $c1e4

    jp Jump_021_7fcb


    add $d2
    push bc
    push bc
    call z, Call_021_7fd9
    push bc
    sub $c5
    adc $7f
    jp $e4c1


    adc $7f
    set 1, c
    jp Jump_021_7fcb


    pop bc
    adc $7f
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    db $e4
    ld a, a
    add $c1
    jp nc, $c67f

    jp nc, $cdcf

    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    rst $08
    push de
    call z, Call_021_7f7f
    rst $08
    add $7f
    jp nz, $d8cf

    push bc
    db $e4
    jp nc, $c97f

    db $d3
    ld a, a
    pop bc
    call nz, $c5c8
    jp nc, Jump_021_7fc5

    call nc, Call_021_7fcf
    ret


    call nc, $e47f
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, $cf7f
    add $7f
    jp nz, $cfe4

    ret c

    ret


    adc $c7
    ld a, a
    ret


    db $d3
    ld a, a
    add $c1
    db $d3
    call nc, $d2c5
    ld a, a
    call nc, $e4c8
    pop bc
    adc $7f
    adc $c5
    rst $10
    ld a, a
    call $c9c1
    adc $7f
    call z, $cec9
    push bc
    adc [hl]
    ld a, a
    db $e4
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    rst $08
    call Call_021_7fc5
    add $c9
    rst $00
    push de
    jp nc, $d3c5

    ld a, a
    db $e4
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    jp nz, $cfc4

    call $cec5
    ld a, a
    push bc
    adc $cf
    db $e4
    push de
    rst $00
    ret z

    ld a, a
    call nc, Call_021_7fcf
    add $d2
    ret


    rst $00
    ret z

    call nc, $cec5
    ld a, a
    ld a, a
    pop bc
    db $e4
    ld a, a
    rst $10
    push bc
    pop bc
    bit 7, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    call nc, Call_021_7fcf
    db $e4
    add $cc
    push bc
    push bc
    ld a, a
    pop bc
    db $d3
    ld a, a
    add $c1
    db $d3
    call nc, $c17f
    db $d3
    ld a, a
    ret nc

    rst $08
    db $e4
    db $d3
    db $d3
    ret


    jp nz, $c5cc

    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    push bc
    call $d4c9
    db $d3
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $d3
    ld a, a
    jp nz, $c1e4

    jp $c5d4


    jp nc, $c1c9

    ld a, a
    ld a, a
    add $d2
    rst $08
    call $c97f
    call nc, Call_021_7fd3

Call_021_507f:
Jump_021_507f:
    db $e4
    push de
    call $d2c2
    push bc
    call z, $c1cc
    ld a, a
    rst $10
    ret z

    ret


    jp $8cc8


    ld a, a
    ret


    adc $e4
    ld a, a
    and e
    ret z

    ret


    adc $c1
    adc h
    ld a, a
    call $d9c1
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    pop bc
    db $d3
    db $e4
    ld a, a
    pop bc
    ld a, a
    and e
    ret z

    ret


    adc $c5
    db $d3
    push bc
    ld a, a
    call $c4c5
    ret


    jp $cec9


    db $e4
    push bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $cfd2
    push de
    jp nz, $c5cc

    db $e4
    call nz, $c27f
    reti


    ld a, a
    ret z

    push bc
    pop bc
    call nz, $c3c1
    ret z

    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    pop bc
    adc $7f
    ret


    adc $c3
    rst $08
    adc $c3
    push bc
    ret


    sub $c1
    db $e4
    jp nz, $c5cc

    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    ret z

    push bc
    pop bc
    db $e4
    call nz, $c3c1
    ret z

    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    push bc
    jp nc, $cfc9

    push de
    db $d3
    call z, $e4d9
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    pop bc
    jp nc, Jump_021_7fc5

    rst $08
    add $c6
    db $d3
    ret nc

    jp nc, $cec9

    rst $00
    db $d3
    ld a, a
    rst $08
    add $e4
    ld a, a
    pop bc
    ld a, a
    call $cdc1
    call $ccc1
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    call nc, $c1e4
    ret nc

    ret


    jp nc, $c17f

    adc $c4
    ld a, a
    pop bc
    jp nc, Jump_021_7fc5

    db $d3
    pop bc
    ret


    call nz, $e47f
    call nc, Call_021_7fcf
    jp nz, Jump_021_7fc5

    pop bc
    jp nz, $c5cc

    ld a, a
    call nc, Call_021_7fcf
    push bc
    pop bc
    call nc, $e47f
    call nz, $c5d2
    pop bc
    call $c17f
    adc $c4
    ld a, a
    call nc, Call_021_7fcf
    jp nz, Jump_021_7fc5

    add $cf
    db $e4
    adc $c4
    ld a, a
    rst $08
    add $7f
    ret z

    reti


    ret nc

    adc $cf
    call nc, $d3c9
    call Call_021_7f8e
    ld d, b
    ld a, a
    push bc
    ret c

    push de
    sub $c9
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    call nc, $cbc1
    push bc
    db $d3
    ld a, a
    db $e4
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    rst $08
    adc $c3
    push bc
    ld a, a
    pop bc
    ld a, a
    reti


    push bc
    pop bc
    jp nc, $e47f

    pop bc
    adc $c4
    ld a, a
    push bc
    pop bc
    jp Jump_021_7fc8


    call nc, $cdc9
    push bc
    ld a, a
    jp nz, $c3c5

    rst $08
    db $e4
    call $d3c5
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    jp nc, $c17f

    add $d4
    push bc
    jp nc, $c37f

    db $e4
    pop bc
    db $d3
    call nc, $cec9
    rst $00
    ld a, a
    rst $08
    add $c6
    ld a, a
    pop bc
    ld a, a
    db $d3
    set 1, c
    adc $7f
    db $e4
    ret z

    pop bc
    jp nc, Jump_021_7fc4

    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    jp nz, $ccd5

    call z, $d4c5
    db $e4
    ret


    adc $7f
    jp nz, $c1cf

    jp nc, Jump_021_7fc4

    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ld a, a
    db $d3
    ret nc

    jp nc, $d9c1

    db $d3
    ld a, a
    add $c9
    jp nc, Jump_021_7fc5

    add $d2
    rst $08
    call Call_021_7fe4
    call nc, $c5c8
    ld a, a
    call $d5cf
    call nc, Call_021_7fc8
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    db $e4
    adc $c5
    pop bc
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    jp nz, $e4d2

    ret


    jp Jump_021_7fcb


    jp nz, $c4c5

    ld a, a
    rst $08
    add $7f
    sub $cf
    call z, $c1c3
    adc $cf
    db $e4
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    call nc, $cdc5
    ret nc

    push bc
    db $e4
    jp nc, $d4c1

    push de
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    sub c
    sub d
    sub b
    sub b
    add a
    and e
    adc [hl]
    ld a, a
    db $e4
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    push bc
    call z, $c3c5
    call nc, $d2e4
    ret


    jp $d4c9


    reti


    ld a, a
    call nc, $c1c8
    call nc, $cf7f
    add $d4
    push bc
    adc $7f
    db $e4
    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_021_7fd3

    rst $08
    push de
    call nc, $c9d3
    call nz, Call_021_7fc5
    call nc, $e4c8
    push bc
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, $d37f

    call nc, $d4c1
    db $e4
    ret


    rst $08
    adc $7f
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    db $e4
    jp $d2c9


    jp $c5cc


    call nz, $c27f
    reti


    ld a, a
    call $cec1
    reti


    ld a, a
    jp $e4cf


    ret


    call z, Call_021_7fd3
    pop bc
    adc $c4
    ld a, a
    push bc
    call $d4c9
    db $d3
    ld a, a
    rst $00
    ret


    pop bc
    adc $e4
    call nc, $cd7f
    pop bc
    rst $00
    adc $c5
    call nc, $c3c9
    ld a, a
    call z, $cec9
    push bc
    db $d3
    ld a, a
    rst $08
    db $e4
    add $7f
    add $cf
    jp nc, $c5c3

    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret z

    ret


    rst $00
    ret z

    ld a, a
    sub $e4
    rst $08
    call z, $c1d4
    rst $00
    push bc
    db $d3
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    add $d5
    call z, Call_021_7fcc
    rst $08
    add $7f
    pop bc
    jp $d4d5


    push bc
    ld a, a
    db $e4
    ret nc

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
    db $d3
    ld a, a
    ret


    adc $7f
    ret


    db $e4
    call nc, Call_021_7fd3
    call nc, $c9c8
    adc $7f
    jp nz, $c4cf

    reti


    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    db $e4
    pop bc
    ld a, a
    jp nz, $ccc1

    call z, $cfcf
    adc $7f
    pop bc
    adc $c4
    ld a, a
    rst $00
    ret


    sub $c5
    db $e4
    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $cec9
    bit 7, a
    rst $10
    ret z

    push bc
    adc $7f
    jp nz, $c9c5

    db $e4
    adc $c7
    ld a, a
    jp $cfcc


    db $d3
    push bc
    ld a, a
    call nc, $8ecf
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    db $e4
    call z, $c7c9
    ret z

    call nc, $c27f
    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    adc $c1
    call nc, $e4d5
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    add $c5
    jp nc, $c3cf

    ret


    rst $08
    push de
    db $d3
    ld a, a
    push bc
    db $d3
    db $e4
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    ret


    call nc, Call_021_7fd3
    db $e4
    rst $00
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    pop bc
    adc $c7
    jp nc, $8ed9

    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    jp $d6cf


    push bc
    jp nc, $c4c5

    ld a, a
    jp nz, Jump_021_7fd9

    rst $10
    pop bc
    call nc, $c5e4
    jp nc, $c38d

    rst $08
    call z, $d2cf
    push bc
    call nz, $c27f
    rst $08
    call nz, Call_021_7fd9
    ret z

    pop bc
    db $e4
    ret


    jp nc, Jump_021_7fd3

    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    jp $c9d4


    sub $c5
    db $e4
    ld a, a
    push bc
    sub $c5
    adc $7f
    pop bc
    call nc, $8d7f
    sub h
    sub b
    and e
    ld a, a
    jp nz, $c3c5

    pop bc
    db $e4
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    sub $c5
    jp nc, Jump_021_7fd9

    call nc, $c9c8
    jp Jump_021_7fcb


    db $e4
    pop bc
    adc $c4
    ld a, a
    ret z

    pop bc
    jp nc, Jump_021_7fc4

    db $d3
    set 1, c
    adc $8e
    ld a, a
    ld d, b
    ld a, a
    call $d6cf
    push bc
    db $d3
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d37f

    ret z

    pop bc
    call z, $e4cc
    rst $08
    rst $10
    ld a, a
    rst $00
    jp nc, $d5cf

    adc $c4
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret


    db $d3
    ld a, a
    db $e4
    push bc
    pop bc
    db $d3
    ret


    call z, Call_021_7fd9
    add $cf
    push de
    adc $c4
    ld a, a
    pop bc
    jp $cfc3


    jp nc, $c4e4

    ret


    adc $c7
    ld a, a
    call nc, Call_021_7fcf
    rst $08
    rst $08
    jp c, $c4c5

    ld a, a
    db $d3
    rst $08
    ret


    call z, Call_021_7fe4
    ret nc

    ret


    call z, Call_021_7fc5
    pop bc
    add $d4
    push bc
    jp nc, $c97f

    call nc, Call_021_7fd3
    ret z

    rst $08
    db $e4
    call z, $8dc5
    call nz, $c7c9
    rst $00
    ret


    adc $c7
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    jp nz, $c1c5

    call nc, Call_021_7fd3
    ret z

    ret


    call $c5d3
    call z, $87c6
    db $d3
    ld a, a
    jp nz, $cfe4

    call nz, Call_021_7fd9
    rst $10
    ret


    call nc, Call_021_7fc8
    call nc, $cfd7
    ld a, a
    call nc, $c9c1
    call z, $e4d3
    ld a, a
    ld a, a
    ret


    adc $7f
    pop bc
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    ret


    ret nc

    pop bc
    ld a, a
    db $e4
    ret nc

    ret


    ret nc

    pop bc
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    jp nc, $d3d5

    ret z

    ret


    adc $c7
    ld a, a
    db $e4
    rst $08
    push de
    call nc, Call_021_7f7f
    adc [hl]
    ld d, b
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    jp $d2c1


    jp nc, $c5c9

    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nz, $c1d2

    adc $c3
    ret z

    ld a, a
    rst $08
    db $e4
    add $7f
    call nc, $c5c8
    ld a, a
    call nc, $c5d2
    push bc
    ld a, a
    ret


    adc $7f
    ret


    call nc, Call_021_7fd3
    db $e4
    jp nz, $ccc9

    call z, $d47f
    rst $08
    ld a, a
    jp nz, $c9d5

    call z, Call_021_7fc4
    ret


    call nc, Call_021_7fd3
    db $e4
    adc $c5
    db $d3
    call nc, Call_021_7f8e
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    push bc
    reti


    push bc
    db $d3
    ld a, a
    call $d6cf
    push bc
    ld a, a
    ld a, a
    pop bc
    adc $e4
    call nz, $d77f
    rst $08
    jp nc, Jump_021_7fcb

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, $c4c1

    pop bc
    jp nc, $e47f

    pop bc
    adc $c4
    ld a, a
    push bc
    call $d4c9
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c57f
    sub $c5
    db $e4
    adc $7f
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $d2c1
    res 1, [hl]
    ld a, a

Call_021_55c1:
    ld d, b
    ld a, a
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c

Call_021_55d3:
    ld a, a
    db $e4

Call_021_55d5:
    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    pop bc
    ld a, a
    jp nz, $c7c9

    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    pop bc
    db $e4
    adc $c4
    ld a, a
    call nc, $cbc1
    push bc
    db $d3
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    pop bc
    jp nz, $d5cf

    db $e4
    call nc, $d37f
    ret


    ret c

    call nc, $c5c5
    adc $7f
    ret z

    rst $08
    push de
    jp nc, Jump_021_7fd3

    call nc, $e4cf
    ld a, a
    rst $00
    rst $08
    ld a, a
    rst $08
    adc $c5
    ld a, a
    jp $d2c9


    jp $c5cc


    ld a, a
    pop bc
    jp nc, $e4d2

    rst $08
    push de
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    and l
    pop bc
    jp nc, $c8d4

    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    ret


    adc $7f
    pop bc
    ld a, a
    db $d3
    push de
    db $e4
    call nz, $c5c4
    adc $7f
    ld a, a
    call $d4d5
    pop bc
    call nc, $cfc9
    adc $8e
    ld a, a
    ret


    call nc, Call_021_7fe4
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call nc, $cfd7
    adc l
    ret z

    push bc
    pop bc
    call nz, $d07f
    rst $08
    jp $cbe4


    push bc
    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    ld a, a
    call nc, $c1c8
    call nc, $c37f
    db $e4
    pop bc
    adc $7f
    jp nc, $ced5

    ld a, a
    pop bc
    call nc, $c17f
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, $e47f
    rst $08
    add $7f
    sub c
    sub b
    sub b
    xor e
    call $c88f
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c1cc

    jp Jump_021_7fcb


    db $d3
    set 1, c
    adc $7f
    ret


    db $d3
    db $e4
    ld a, a
    call nc, $c9c8
    adc $7f
    adc h
    ld a, a
    rst $10
    push bc
    call nc, $c17f
    adc $c4
    ld a, a
    db $d3
    call z, $c9e4
    jp $8ecb


    ld a, a
    ret nc

    pop bc
    jp nc, $d3d4

    ld a, a
    rst $08
    add $7f
    ret


    adc $d4
    push bc
    db $e4
    jp nc, $c1ce

    call z, $cf7f
    jp nc, $c1c7

    adc $d3
    ld a, a
    ld a, a
    pop bc
    jp nc, Jump_021_7fc5

    call nc, $d2e4
    pop bc
    adc $d3
    ret nc

    pop bc
    jp nc, $cec5

    call nc, Call_021_7f8e
    ret


    call nc, $cc7f
    rst $08
    rst $08
    db $e4
    set 2, e
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    rst $10
    ret z

    ret


    jp nc, $d0cc

    rst $08
    rst $08
    db $e4
    call z, $8e7f
    ld d, b
    ld a, a
    db $d3
    ret nc

    push bc
    pop bc
    set 2, e
    ld a, a
    ret


    adc $7f
    pop bc
    ld a, a
    call z, $cec1
    rst $00
    push de
    db $e4
    pop bc
    rst $00
    push bc
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ret z

    push de
    call $cec1
    ld a, a
    jp nz, $c9c5

    db $e4
    adc $c7
    add a
    db $d3
    ld a, a
    jp nz, $d4d5

    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d47f
    ret z

    push bc
    reti


    db $e4
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $c97f
    db $d3
    adc $87
    call nc, Call_021_7f7f
    jp $c5cc


    pop bc
    jp nc, Jump_021_7fe4

    add $cf
    jp nc, $d57f

    db $d3
    ld a, a
    adc $cf
    rst $10
    ld a, a
    ret


    call nc, $d387
    ld a, a
    jp nz, $c5e4

    push bc
    adc $7f
    db $d3
    call nc, $c4d5
    ret


    push bc
    call nz, Call_021_7f8e
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    jp $cbe4


    push bc
    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    db $d3
    ld a, a
    ret


    adc $7f
    call z, $e4c5
    rst $00
    push bc
    adc $c4
    ld a, a
    call nc, $c1c8
    call nc, $c87f
    pop bc
    db $d3
    ld a, a
    rst $08
    jp nc, $cec1

    db $e4
    rst $00
    push bc
    ld a, a
    rst $10
    ret


    adc $c7
    db $d3
    ld a, a

Jump_021_57c4:
    call z, $cbc9
    push bc
    ld a, a
    add $c9
    jp nc, $e4c5

    adc l
    jp nz, $d2d5

    adc $c9
    adc $c7
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    db $e4
    db $d3
    ld a, a
    ret z

    ret


    call $c5d3
    call z, Call_021_7fc6
    pop bc
    jp nz, $d6cf

    push bc
    ld a, a
    call nc, $e4c8
    push bc
    ld a, a
    rst $08
    jp nz, $c5ca

    jp $8ed4


    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    jp $cbe4


    push bc
    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    db $d3
    ld a, a
    ret


    adc $7f
    call z, $e4c5
    rst $00
    push bc
    adc $c4
    ld a, a
    call nc, $c1c8
    call nc, $c67f
    call z, $c5c9
    db $d3
    ld a, a
    pop bc
    rst $10
    db $e4
    pop bc
    reti


    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    pop bc
    ld a, a
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    db $e4
    call z, $d07f
    rst $08
    db $d3
    push bc
    ld a, a
    call nz, $c1d2
    rst $00
    rst $00
    ret


    adc $c7
    ld a, a
    pop bc
    ld a, a
    db $e4
    call z, $cecf
    rst $00
    ld a, a
    call nc, $c9c1
    call z, $8e7f
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $c5
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    jp $cbe4


    push bc
    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    db $d3
    ld a, a
    ret


    adc $7f
    call z, $e4c5
    rst $00
    push bc
    adc $c4
    ld a, a
    call nc, $c1c8
    call nc, $c67f
    call z, $c5c9
    db $d3
    ld a, a
    ret


    adc $e4
    ld a, a
    pop bc
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    ret nc

    pop bc
    adc h
    ret nc

    pop bc
    ld a, a
    call z, $cbc9
    db $e4
    push bc
    ld a, a
    db $d3
    rst $08
    call $d4c5
    ret z

    ret


    adc $c7
    ld a, a
    jp $c1d2


    jp $c5cb


    db $e4
    db $d3
    ld a, a
    ld d, b
    ld a, a
    jp $cecf


    db $d3
    ret


    db $d3
    call nc, Call_021_7fd3
    rst $08
    add $7f
    jp nz, $c4cf

    reti


    ld a, a
    db $e4
    jp $ccc5


    call z, Call_021_7fd3
    jp $cec1


    ld a, a
    jp nc, $c3c5

    rst $08
    call $c9c2
    adc $e4
    push bc
    ld a, a
    ret z

    ret


    call $c5d3
    call z, Call_021_7fc6
    pop bc
    adc $c4
    ld a, a
    jp nz, $c3c5

    rst $08
    db $e4
    call Call_021_7fc5
    pop bc
    ld a, a
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    ld a, a
    push bc
    call z, $c5d3
    db $e4
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    db $d3
    ld a, a
    ret


    adc $7f
    call nz, $e4c1
    reti


    call nc, $cdc9
    push bc
    ld a, a
    jp nz, $d4d5

    ld a, a
    rst $08
    ret nc

    push bc
    adc $d3
    ld a, a
    call z, $e4c9
    rst $00
    ret z

    call nc, $cec5
    ret


    adc $c7
    ld a, a
    push bc
    reti


    push bc
    db $d3
    ld a, a
    pop bc
    call nc, $ce7f
    db $e4
    ret


    rst $00
    ret z

    call nc, $c17f
    adc $c4
    ld a, a
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    call nc, Call_021_7fcf
    db $e4
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    rst $10
    ret


    call nc, $c9c8
    adc $7f
    pop bc
    ld a, a
    call nz, $c5e4
    call z, $cdc9
    ret


    call nc, $c4c5
    ld a, a
    jp nc, $cec1

    rst $00
    push bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    push de
    adc $c4
    ld a, a
    adc $c5
    pop bc
    jp nc, $d47f

    ret z

    push bc
    db $e4
    ld a, a
    db $d3
    push bc
    pop bc
    db $d3
    ret


    call nz, Call_021_7fc5
    push bc
    sub $c5
    adc $7f
    call nc, $cfc8
    push de
    db $e4
    rst $00
    ret z

    ld a, a
    ret


    call nc, Call_021_7fd3
    call z, $d2c1
    rst $00
    push bc
    ld a, a
    ret nc

    ret


    adc $c3
    push bc
    db $e4
    jp nc, Jump_021_7fd3

    pop bc
    jp nc, Jump_021_7fc5

    jp nz, $cfd2

    set 0, l
    adc $7f
    rst $08
    add $c6
    ld a, a
    db $e4
    ret


    call nc, $c37f
    pop bc
    adc $7f
    pop bc
    call z, $cfd3
    ld a, a
    jp nc, $c7c5

    push bc
    adc $c5
    db $e4
    jp nc, $d4c1

    push bc
    ld a, a
    rst $08
    push de
    call nc, $ce7f
    push bc
    rst $10
    ld a, a
    rst $08
    adc $c5
    db $d3
    adc [hl]
    db $e4
    ld a, a
    ld d, b
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


    call nc, Call_021_7fc8
    sub [hl]
    ld a, a
    jp nz, $c5e4

    pop bc
    push de
    call nc, $c6c9
    push de
    call z, $d47f
    pop bc
    ret


    call z, $8ed3
    ld a, a
    call nc, $e4c8
    push bc
    ld a, a
    adc $d5
    call $c5c2
    jp nc, $cf7f

    add $7f
    call nc, $c9c1
    call z, Call_021_7fd3
    db $e4
    db $d3
    call nc, $ccc9
    call z, $c37f
    pop bc
    adc $7f
    ret


    adc $c3
    jp nc, $c1c5

    db $d3
    push bc
    db $e4
    ld a, a
    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $c87f

    push bc
    ld a, a
    rst $00
    jp nc, $d7cf

    db $d3
    ld a, a
    push de
    db $e4
    ret nc

    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    sbc c
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    call nc, $c9c1
    call z, Call_021_7fd3
    db $e4
    adc [hl]
    ld a, a
    reti


    push bc
    call z, $cfcc
    rst $10
    ld a, a
    ret z

    pop bc
    ret


    jp nc, Jump_021_7fd3

    ld a, a
    pop bc
    jp nc, $c5e4

    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    adc [hl]
    db $e4
    ld a, a
    ld a, a
    ret


    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    rst $08
    ld a, a
    call z, $e4c9
    sub $c5
    ld a, a
    add $cf
    jp nc, $917f

    sub b
    sub b
    sub b
    ld a, a
    reti


    push bc
    pop bc
    jp nc, $8ed3

    db $e4
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    call $ccc1
    call z, $c57f
    call z, $c3c5
    call nc, $cfd2
    db $e4
    adc $c9
    jp $d07f


    rst $08
    jp $c5cb


    call nc, Call_021_7fd3
    ld a, a
    jp nz, $d3c5

    ret


    call nz, $c5e4
    ld a, a
    call nc, $cfd7
    ld a, a
    call z, $d4c1
    push bc
    jp nc, $ccc1

    db $d3
    ld a, a
    rst $08
    add $7f
    db $e4
    call nc, $c5c8
    ld a, a
    jp $c9c8


    adc $7f
    ld a, a
    pop bc
    adc $c4
    ld a, a
    push bc
    call $d4c9
    db $e4
    db $d3
    ld a, a
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $d4c9


    reti


    ld a, a
    rst $10
    ret z

    push bc
    adc $e4
    ld a, a
    call $c5c5
    call nc, $cec9
    rst $00
    ld a, a
    pop bc
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, $e48e

    ld a, a
    ld d, b
    ld a, a
    jp $cec1


    ld a, a
    push bc
    call $d4c9
    ld a, a
    sub c
    sub b
    sub b
    adc h
    sub b
    sub b
    sub b
    ld a, a
    db $e4
    sub $cf
    call z, Call_021_7fd4
    rst $08
    add $7f
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $d4c9


    db $e4
    reti


    ld a, a
    ret


    add $7f
    call nc, $d5cf
    jp $c5c8


    db $d3
    ld a, a
    ret


    call nc, $c37f
    pop bc
    db $e4
    jp nc, $ccc5

    push bc
    db $d3
    db $d3
    call z, Call_021_7fd9
    push bc
    sub $c5
    adc $7f
    pop bc
    adc $7f
    xor c
    db $e4
    adc $c4
    ret


    pop bc
    adc $7f
    push bc
    call z, $d0c5
    ret z

    pop bc
    adc $d4
    ld a, a
    jp $cec1


    db $e4
    ld a, a
    call nz, $c5c9
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    push bc
    sub $c5
    adc $7f
    pop bc
    ld a, a
    jp $c9c8


    call z, Call_021_7fc4
    ret


    db $d3
    ld a, a
    call $cfe4
    jp nc, Jump_021_7fc5

    call nc, $c1c8
    adc $7f
    sub d
    ld a, a
    call $d4c5
    push bc
    jp nc, Jump_021_7fd3

    db $e4
    ret z

    ret


    rst $00
    ret z

    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    push bc
    ret c

    push de
    sub $c9
    db $e4
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    jp nc, $d0c5

    push bc
    pop bc
    call nc, $c4c5
    call z, Call_021_7fd9
    ret


    db $e4
    call nc, $c27f
    push bc
    jp $cdcf


    push bc
    db $d3
    ld a, a
    jp nz, $c7c9

    rst $00
    push bc
    jp nc, $c17f

    db $e4
    adc $c4
    ld a, a
    jp nz, $c7c9

    rst $00
    push bc
    jp nc, Jump_021_7f8e

    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    rst $08
    ld a, a
    call z, $d6c9
    push bc
    ld a, a
    ret


    db $e4
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    ld a, a
    rst $08
    jp nc, $cc7f

    pop bc
    set 4, h
    push bc
    ld a, a
    adc $cf
    ld a, a
    rst $10
    ret


    adc $c7
    db $d3
    ld a, a
    jp nz, $d4d5

    ld a, a
    call nc, $c5c8
    db $e4
    ld a, a
    ret nc

    rst $08
    db $d3
    push bc
    ld a, a
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $e4c8
    push bc
    ld a, a
    db $d3
    set 3, c
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    push bc
    push bc
    adc $7f
    jp nz, Jump_021_7fd9

    jp $c8e4


    pop bc
    adc $c3
    push bc
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nc, $c7c5

    push bc
    adc $c5
    jp nc, $d4c1

    push bc
    call nz, $e47f
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    ld a, a
    add $d2
    rst $08
    db $e4
    call $d47f
    ret z

    push bc
    ld a, a
    add $cf
    db $d3
    db $d3
    ret


    call z, $cf7f
    add $7f
    pop bc
    adc $e4
    jp $c5c9


    adc $d4
    ld a, a
    jp $c5d2


    pop bc
    call nc, $d2d5
    push bc
    ld a, a
    ret


    call nc, $e47f
    ret nc

    jp nc, $d3c5

    push bc
    jp nc, $c5d6

    db $d3
    ld a, a
    ret z

    ret


    call $c5d3
    call z, $87c6
    db $e4
    db $d3
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    jp nz, Jump_021_7fd9

    ret z

    ret


    db $d3
    ld a, a
    ret z

    pop bc
    jp nc, $e4c4

    ld a, a
    jp $d5d2


    db $d3
    call nc, Call_021_7f8e
    ld d, b
    ld a, a
    db $d3
    rst $10
    ret


    call Call_021_7fd3
    add $d2
    push bc
    push bc
    call z, Call_021_7fd9
    ret


    adc $7f
    call nc, $c8e4
    push bc
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp $d4c1


    jp $e4c8


    push bc
    db $d3
    ld a, a
    add $cf
    rst $08
    call nz, $c27f
    reti


    ld a, a
    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    ret nc

    db $e4
    ret


    adc $c3
    push bc
    jp nc, Jump_021_7fd3

    call nc, Call_021_7fcf
    db $d3
    push de
    jp Jump_021_7fcb


    jp $d0c1


    db $e4
    call nc, $d2d5
    push bc
    add a
    db $d3
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    jp z, $c9d5

    jp $8ec5


    db $e4
    ld a, a
    ld d, b
    ld a, a
    call nc, $c9d7
    db $d3
    call nc, Call_021_7fd3
    ret z

    ret


    call $c5d3
    call z, Call_021_7fc6
    jp $e4c9


    jp nc, $ccc3

    push bc
    db $d3
    ld a, a
    ld a, a
    rst $08
    adc $c5
    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $c17f

    db $e4
    adc $cf
    call nc, $c5c8
    jp nc, $cc7f

    ret


    set 0, l
    ld a, a
    pop bc
    ld a, a
    db $d3
    ret nc

    jp nc, $e4c9

    adc $c7
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nz, $ccc1

    pop bc
    adc $c3
    push bc
    db $d3
    ld a, a
    ret z

    ret


    db $e4
    call $c5d3
    call z, Call_021_7fc6
    jp nz, Jump_021_7fd9

    call nc, $c9c1
    call z, $c17f
    db $d3
    ld a, a
    rst $10
    db $e4
    push bc
    call z, Call_021_7fcc
    pop bc
    db $d3
    ld a, a
    db $d3
    ret nc

    jp nc, $d9c1

    db $d3
    ld a, a
    ret


    adc $cb
    ld a, a
    db $e4
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    call $d5cf
    call nc, $8ec8
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    add $d5
    call z, Call_021_7fcc
    rst $08
    add $7f
    db $d3
    ret nc

    call z, $cec9
    call nc, $c5e4
    jp nc, Jump_021_7fd3

    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    adc [hl]
    ld a, a
    db $e4
    ret


    add $7f
    call nc, $d5cf
    jp Jump_021_7fc8


    ret


    call nc, $cf7f
    jp nc, $d37f

    call nc, $e4d5
    adc $c7
    ld a, a
    jp nz, Jump_021_7fd9

    ret


    call nc, $c37f
    pop bc
    jp nc, $ccc5

    push bc
    db $d3
    db $d3
    call z, $d9e4
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_021_7fc4
    call nz, $c5c9
    adc [hl]
    ld a, a
    db $e4
    ld d, b
    ld a, a
    call z, $d6c9
    push bc
    db $d3
    ld a, a
    ret


    adc $7f
    pop bc
    ld a, a
    ret z

    rst $08
    call z, Call_021_7fc5
    rst $08
    db $e4
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $c9c6

    jp $c1c9


    call z, $e47f
    db $d3
    rst $08
    ret


    call z, $c17f
    adc $c4
    ld a, a
    jp nz, $c3c5

    rst $08
    call $d3c5
    ld a, a
    jp nc, $cfe4

    push de
    adc $c4
    ld a, a
    call nc, Call_021_7fcf
    ret nc

    jp nc, $d3c5

    push bc
    jp nc, $c5d6

    ld a, a
    ret z

    db $e4
    ret


    call $c5d3
    call z, Call_021_7fc6
    rst $10
    ret z

    push bc
    adc $7f
    call $c5c5
    call nc, $cec9
    db $e4
    rst $00
    ld a, a
    pop bc
    ld a, a
    call nz, $cec1
    rst $00
    push bc
    jp nc, $8e7f

    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    adc $c4
    ld a, a
    rst $08
    add $7f
    jp nc, $ced5

    adc $c9
    adc $e4
    rst $00
    ld a, a
    call nc, Call_021_7fcf
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    call nc, Call_021_7fcf
    pop bc
    call nc, $d4e4
    pop bc
    jp Jump_021_7fcb


    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    db $d3
    ld a, a
    jp nz, Jump_021_7fd9

    db $e4
    adc $c5
    push bc
    call nz, $c5cc
    db $d3
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c3c1

    db $e4
    bit 7, a
    pop bc
    adc $c4
    ld a, a
    jp nz, Jump_021_7fd9

    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    ret nc

    pop bc
    rst $10
    db $e4
    db $d3
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    rst $10
    pop bc
    db $d3
    ld a, a
    pop bc
    adc $7f
    pop bc
    adc $c3
    ret


    push bc
    adc $d4
    ld a, a
    ret nc

    rst $08
    db $e4
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    ld a, a
    call nc, $c1c8
    call nc, $e47f
    call z, $d6c9
    push bc
    call nz, $c97f
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    call z, $cfe4
    adc $c7
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    rst $00
    rst $08
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    db $e4
    rst $10
    pop bc
    call $c37f
    push de
    jp nc, $c5d6

    call nz, $d9cc
    ld a, a
    jp nz, Jump_021_7fd9

    db $10
    ld a, a
    add $e4
    rst $08
    rst $08
    call nc, $8e7f
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $cec5
    call nc, $c3c1
    call z, Call_021_7fc5
    ret


    db $d3
    ld a, a
    rst $10
    db $e4
    push bc
    call z, $8dcc
    call nz, $d6c5
    push bc
    call z, $d0cf
    push bc
    call nz, $cc7f
    ret


    set 0, l
    db $e4
    ld a, a
    ret z

    pop bc
    adc $c4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    add $c5
    push bc
    call nc, $8c7f
    ld a, a
    ret


    db $e4
    call nc, $c37f
    pop bc
    adc $7f
    jp nz, $d4c9

    push bc
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_021_7fc5
    push bc
    db $e4
    call $d2c2
    pop bc
    jp $cec9


    rst $00
    ld a, a
    call nc, $c7c9
    ret z

    call nc, $d9cc
    adc [hl]
    ld a, a
    db $e4
    ld d, b
    ld a, a
    push bc
    adc $d4
    ret


    jp $d3c5


    ld a, a
    rst $08
    call nc, $c5c8
    jp nc, Jump_021_7fd3

    call nc, $e4cf
    ld a, a
    push bc
    adc $d4
    push bc
    jp nc, $c97f

    adc $d4
    rst $08
    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    call z, $c1e4
    jp nc, $c5c7

    ld a, a
    jp nc, $d5cf

    adc $c4
    ld a, a
    push bc
    reti


    push bc
    db $d3
    ld a, a
    ld a, a
    pop bc
    db $e4
    adc $c4
    ld a, a
    db $d3
    ret


    adc $c7
    db $d3
    ld a, a
    jp $cdcf


    add $cf
    jp nc, $c1d4

    jp nz, $cce4

    push bc
    ld a, a
    db $d3
    rst $08
    adc $c7
    db $d3
    ld a, a
    ld a, a
    call nc, Call_021_7fcf
    call z, $d4c5
    ld a, a
    rst $08
    db $e4
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    db $d3
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret z

    pop bc
    ret


    jp nc, Jump_021_7fd3

    sub $c5
    jp nc, Jump_021_7fd9

    db $d3
    rst $08
    db $e4
    add $d4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    sub $c5
    jp nc, Jump_021_7fd9

    db $d3
    call $cfcf
    call nc, $e4c8
    ld a, a
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    pop bc
    ret


    jp nc, Jump_021_7fd3

    call nc, $c1c8
    call nc, $cd7f
    db $e4
    pop bc
    set 0, l
    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_021_7fc5
    jp nc, $ccc5

    pop bc
    ret c

    push bc
    call nz, Call_021_7fe4
    pop bc
    adc $c4
    ld a, a
    ret z

    pop bc
    ret nc

    ret nc

    reti


    ld a, a
    pop bc
    jp nc, Jump_021_7fc5

    ret z

    ret


    rst $00
    db $e4
    ret z

    adc l
    rst $00
    jp nc, $c4c1

    push bc
    ld a, a
    ret nc

    jp nc, $c4cf

    push de
    jp $d3d4


    adc [hl]
    ld a, a
    db $e4
    ld d, b
    ld a, a
    call nc, $c5c8
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $c2cf

    pop bc
    jp nz, $c9e4

    call z, $d4c9
    reti


    ld a, a
    rst $08
    add $7f
    push bc
    sub $cf
    call z, $d4d5
    ret


    rst $08
    adc $e4
    ld a, a
    ld a, a
    pop bc
    call $cecf
    rst $00
    ld a, a
    sub e
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    db $e4
    rst $08
    adc $d3
    call nc, $d2c5
    db $d3
    ld a, a
    call nc, $c5c8
    db $d3
    push bc
    ld a, a
    pop bc
    jp nc, Jump_021_7fc5

    db $e4
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    db $e4
    adc $d3
    call nc, $d2c5
    db $d3
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    add $c9
    jp nc, Jump_021_7fc5

    ret nc

    db $e4
    rst $08
    jp $c5cb


    call nc, $d47f
    ret z

    pop bc
    call nc, $c37f
    pop bc
    adc $7f
    db $d3
    ret nc

    jp nc, $c1e4

    reti


    ld a, a
    pop bc
    ld a, a
    add $c9
    jp nc, Jump_021_7fc5

    pop bc
    call nc, $917f
    sub a
    sub b
    sub b
    add a
    db $e4
    and e
    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $c17f

    jp nz, $cfd3

    jp nc, $c9c2

    adc $c7
    ld a, a
    db $e4
    pop bc
    ret


    jp nc, $c47f

    push bc
    push bc
    ret nc

    call z, Call_021_7fd9
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    pop bc
    call z, Call_021_7fcc
    call nc, $c5c8
    ld a, a
    ret z

    pop bc
    ret


    jp nc, Jump_021_7fd3

    jp $cec1


    db $e4
    ld a, a
    ret nc

    push bc
    adc $c5
    call nc, $c1d2
    call nc, Call_021_7fc5
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $e4
    call nc, Call_021_7fd3
    call z, $cbc9
    push bc
    ld a, a
    adc $c5
    push bc
    call nz, $c5cc
    db $d3
    ld a, a
    ld a, a
    db $d3
    db $e4
    call nc, $cec1
    call nz, $cec9
    rst $00
    ld a, a
    push de
    ret nc

    db $d3
    ret


    call nz, Call_021_7fc5
    call nz, $d7cf
    db $e4
    adc $7f
    rst $10
    ret z

    push bc
    adc $7f
    rst $00
    push bc
    call nc, $c9d4
    adc $c7
    ld a, a
    pop bc
    adc $c7
    db $e4
    jp nc, Jump_021_7fd9

    rst $08
    jp nc, $d37f

    push de
    jp nc, $d2d0

    ret


    db $d3
    push bc
    call nz, $8e7f
    ld a, a
    db $e4
    ld d, b
    ld a, a
    jp $cecf


    db $d3
    ret


    db $d3
    call nc, Call_021_7fd3
    rst $08
    add $7f
    jp nz, $c4cf

    reti


    ld a, a
    db $e4
    jp $ccc5


    call z, Call_021_7fd3
    call z, $cbc9
    push bc
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    add a
    db $d3
    db $e4
    ld a, a
    jp $d0cf


    reti


    ld a, a
    adc h
    ld a, a
    ret


    call nc, $cd7f
    pop bc
    reti


    ld a, a
    call nz, $d3c9
    db $e4
    pop bc
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, $c17f

    add $d4
    push bc
    jp nc, $c97f

    call nc, Call_021_7fd3
    call nz, $c9e4
    db $d3
    db $d3
    rst $08
    call z, $c9d6
    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    db $e4
    pop bc
    call nc, $d2c5
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    ret


    adc $7f
    db $d3
    ret


    jp c, Jump_021_7fc5

    rst $08
    db $e4
    add $7f
    pop bc
    ld a, a
    jp $c9c8


    call z, Call_021_7fc4
    jp nz, $d4d5

    ld a, a
    pop bc
    call z, Call_021_7fcc
    db $e4
    call nc, $c5c8
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    ret


    db $d3
    ld a, a
    add $d5
    call z, Call_021_7fcc
    rst $08
    db $e4
    add $7f
    call $d3d5
    jp $c5cc


    ld a, a
    ret


    call nc, $c37f
    pop bc
    adc $7f
    call nc, $e4c8
    jp nc, $d7cf

    ld a, a
    sub c
    sub b
    sub b
    ld a, a
    pop bc
    call nz, $ccd5
    call nc, Call_021_7fd3
    rst $08
    push de
    call nc, $8ee4
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call nc, $cfd7
    ld a, a
    jp nz, $c9cc

    adc $c4
    ld a, a
    push bc
    reti


    push bc
    db $e4
    db $d3
    ld a, a
    ld a, a
    jp nz, $d4d5

    ld a, a
    jp $cec1


    ld a, a
    add $cc
    reti


    ld a, a
    call nc, Call_021_7fcf
    db $e4
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $d2c1
    db $e4
    bit 7, a
    jp nz, Jump_021_7fd9

    call $c1c5
    adc $d3
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld a, a
    db $e4
    db $d3
    push de
    ret nc

    push bc
    jp nc, $cfd3

    adc $c9
    jp $d77f


    pop bc
    sub $c5
    ld a, a
    ld a, a
    ret nc

    db $e4
    jp nc, $c4cf

    push de
    jp $c4c5


    ld a, a
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    call $cfe4
    push de
    call nc, $8ec8
    ld a, a
    ld d, b
    ld a, a
    call z, $d6c9
    push bc
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $d3c5

    call nc, Call_021_7fd3
    ret


    db $e4
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d3c1

    db $d3
    ld a, a
    jp nz, Jump_021_7fd9

    db $d3
    call nc, $e4d2
    push bc
    call nc, $c8c3
    ret


    adc $c7
    ld a, a
    rst $08
    push de
    call nc, $c97f
    call nc, Call_021_7fd3
    call nc, $e4cf
    adc $c7
    push de
    push bc
    ld a, a
    call nc, Call_021_7fcf
    add $c5
    push bc
    call z, $c47f
    pop bc
    adc $c7
    push bc
    db $e4
    jp nc, $c17f

    jp nc, $cfd2

    push de
    adc $c4
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    jp $ccc1


    call z, $c4c5
    ld a, a
    and e
    ret z

    ret


    adc $c5
    db $d3
    push bc
    db $e4
    ld a, a
    jp $d4c1


    push bc
    jp nc, $c9d0

    call z, $c1cc
    jp nc, $c67f

    push de
    adc $c7
    push de
    db $e4
    db $d3
    ld a, a
    call z, $d6c9
    ret


    adc $c7
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $e4c1

    jp Jump_021_7fcb


    rst $08
    add $7f
    ret


    adc $d3
    push bc
    jp Jump_021_7fd4


    adc [hl]
    ld a, a
    xor [hl]
    rst $08
    rst $10
    db $e4
    ld a, a
    call nc, $c5c8
    ld a, a
    call $cec1
    adc l
    jp $ccd5


    call nc, $d6c9
    pop bc
    call nc, $e4c5
    call nz, $cd7f
    push de
    db $d3
    ret z

    jp nc, $cfcf

    call $c37f
    pop bc
    adc $7f
    pop bc
    call z, $e4d3
    rst $08
    ld a, a
    rst $00
    jp nc, $d7cf

    ld a, a
    rst $10
    push bc
    call z, $8ecc
    ld a, a
    ld d, b
    ld a, a
    call z, $d6c9
    push bc
    db $d3
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call z, $cec1
    call nz, Call_021_7fe4
    rst $10
    ret


    call nc, Call_021_7fc8
    call nc, $cfd7
    ld a, a
    rst $10
    push bc
    call z, $8dcc
    call nz, $d6c5
    db $e4
    push bc
    call z, $d0cf
    push bc
    call nz, $cc7f
    push bc
    rst $00
    db $d3
    ld a, a
    ld a, a
    jp nz, $d4d5

    ld a, a
    call z, $c9e4
    set 0, l
    db $d3
    ld a, a
    call z, $d6c9
    ret


    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    db $e4
    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    adc $c4
    ld a, a
    rst $08
    add $7f
    db $d3
    rst $10
    ret


    call $c9cd
    db $e4
    adc $c7
    ld a, a
    db $d3
    push de
    jp Jump_021_7fc8


    pop bc
    db $d3
    ld a, a
    jp nz, $d4d5

    call nc, $d2c5
    add $e4
    call z, Call_021_7fd9
    db $d3
    call nc, $cfd2
    set 0, l
    ld a, a
    pop bc
    adc $c4
    ld a, a
    add $d2
    push bc
    push bc
    db $e4
    db $d3
    call nc, $ccd9
    push bc
    ld a, a
    pop bc
    call nc, $c17f
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, $d47f
    db $e4
    ret z

    pop bc
    call nc, $c17f
    adc $d9
    ld a, a
    xor a
    call z, $cdd9
    ret nc

    ret


    jp $c37f


    rst $08
    db $e4
    call $c5d0
    call nc, $d4c9
    rst $08
    jp nc, $c37f

    pop bc
    adc $87
    call nc, $c37f
    pop bc
    call nc, $c3e4
    ret z

    ld a, a
    push de
    ret nc

    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call z, $d6c9
    push bc
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $d3c5

    call nc, Call_021_7fd3
    ret


    db $e4
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    rst $08
    call nz, Call_021_7fd3
    rst $08
    jp nc, $c77f

    jp nc, $e4c1

    db $d3
    db $d3
    ld a, a
    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    pop bc
    ld a, a
    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    ret nc

    db $e4
    rst $08
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $d3
    ld a, a
    adc $c5
    push bc
    call nz, $c5cc
    ld a, a
    pop bc
    jp nz, $cfe4

    push de
    call nc, $957f
    jp Jump_021_7fcd


    call z, $cecf
    rst $00
    ld a, a
    rst $08
    adc $7f
    call nc, $e4c8
    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_021_7f8e
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    push de
    adc $cd
    rst $08
    sub $c1
    jp nz, $c5cc

    ld a, a
    db $d3
    db $e4
    call nc, $d4c1
    push bc
    ld a, a
    ld a, a
    jp nz, $c6c5

    rst $08
    jp nc, Jump_021_7fc5

    call nc, Call_021_7fcf
    jp nz, $e4c5

    jp $cdcf


    push bc
    ld a, a
    pop bc
    adc $7f
    pop bc
    call nz, $ccd5
    call nc, $8e7f
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    rst $08
    jp $c1c9


    call z, $c97f
    adc $d3
    push bc
    jp $d4e4


    ld a, a
    rst $08
    jp nc, $c57f

    ret c

    ret


    db $d3
    call nc, Call_021_7fd3
    ret


    adc $7f
    pop bc
    ld a, a
    jp $cfe4


    call z, $cecf
    reti


    ld a, a
    call nc, $c1c8
    call nc, $c67f
    call z, $c5c9
    db $d3
    ld a, a
    call nc, $cfe4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    pop bc
    call nc, $c17f
    ld a, a
    add $c1
    db $d3
    db $e4
    call nc, $d37f
    ret nc

    push bc
    push bc
    call nz, $c17f
    adc $c4
    ld a, a
    db $d3
    call nc, $cec9
    rst $00
    db $d3
    db $e4
    ld a, a
    ld a, a
    jp nz, Jump_021_7fd9

    ret


    call nc, Call_021_7fd3
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $d3
    db $e4
    ld a, a
    adc $c5
    push bc
    call nz, $c5cc
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    pop bc
    jp nz, $e4c4

    rst $08
    call $cec5
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $c3c5

    ret


    rst $08
    push de
    db $d3
    ld a, a
    pop bc
    adc $c9
    db $e4
    call $ccc1
    ld a, a
    ld a, a
    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, $d47f
    rst $08
    ld a, a
    db $e4
    add $c9
    adc $c4
    ld a, a
    rst $10
    ret z

    ret


    jp Jump_021_7fc8


    ret z

    pop bc
    db $d3
    ld a, a
    sub e
    ld a, a
    ret z

    db $e4
    push bc
    pop bc
    call nz, Call_021_7fd3
    call nc, Call_021_7fcf
    db $d3
    ret z

    rst $08
    rst $10
    ld a, a
    jp z, $d9cf

    adc h
    ld a, a
    db $e4
    db $d3
    rst $08
    jp nc, $cfd2

    rst $10
    ld a, a
    pop bc
    adc $c4
    ld a, a
    pop bc
    adc $c7
    jp nc, $8cd9

    ld a, a
    db $e4
    jp nc, $d3c5

    ret nc

    push bc
    jp $c9d4


    sub $c5
    call z, $8ed9
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    pop bc
    adc $c7
    jp nc, Jump_021_7fd9

    ld a, a
    db $e4
    pop bc
    adc $c4
    ld a, a
    add $cf
    call z, $cfcc
    rst $10
    db $d3
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    db $e4
    adc $d4
    ld a, a
    rst $10
    ret z

    push bc
    jp nc, $d6c5

    push bc
    jp nc, $c87f

    push bc
    ld a, a
    add $cc
    push bc
    db $e4
    push bc
    db $d3
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ld d, b
    ld a, a
    call nz, $c7c9
    db $d3
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d2c7

    rst $08
    push de
    adc $c4
    ld a, a
    db $e4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    pop bc
    call nc, $c1d4
    jp $d3cb


    ld a, a
    add $d2
    rst $08
    call $e47f
    ld a, a
    pop bc
    ld a, a
    ret nc

    call z, $c3c1
    push bc
    ld a, a
    ld a, a
    adc $c5
    rst $00
    call z, $c3c5
    call nc, $e4c5
    call nz, $c27f
    reti


    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    push bc
    call $d4c9
    db $d3
    ld a, a
    pop bc
    jp $d4d5


    push bc
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    db $e4
    adc $cf
    push de
    db $d3
    ld a, a
    ret nc

    rst $08
    rst $10
    call nz, $d2c5
    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    jp nz, $c5e4

    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    ret


    call nc, Call_021_7fd3
    rst $10
    ret


    adc $c7
    db $d3
    ld a, a
    rst $08
    db $e4
    adc $7f
    rst $10
    ret z

    ret


    jp Jump_021_7fc8


    jp $d6cf


    push bc
    jp nc, $c4c5

    ld a, a
    jp nz, $e4d9

    ld a, a
    db $d3
    jp $ccc1


    push bc
    call nz, $d07f
    rst $08
    rst $10
    call nz, $d2c5
    ld a, a
    ret


    db $d3
    ld a, a
    jp $d6cf


    push bc
    jp nc, $c4c5

    ld a, a
    jp nz, Jump_021_7fd9

    rst $10
    ret z

    ret


    db $e4
    call nc, Call_021_7fc5
    ret z

    pop bc
    ret


    jp nc, Jump_021_7fd3

    rst $08
    adc $7f
    pop bc
    call z, Call_021_7fcc
    call nc, $e4c8
    push bc
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    pop bc
    adc $c4
    ld a, a
    push bc
    ret c

    call nc, $c5d2
    call $e4c5
    call z, Call_021_7fd9
    pop bc
    adc $d4
    ret


    add $d2
    push bc
    push bc
    jp c, $d3c5

    ld a, a
    ld a, a
    push bc
    sub $e4
    push bc
    adc $7f
    call nc, $c1c8
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp $cccf


    call nz, $d2c5
    db $e4
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    push bc
    pop bc
    call nc, $c5c8
    jp nc, $c97f

    db $d3
    adc h
    ld a, a
    call nc, $c8e4
    push bc
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    push bc
    jp nc, $c97f

    call nc, $c97f
    db $d3
    adc [hl]
    db $e4
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    db $d3
    set 1, c
    adc $7f
    db $e4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    push bc
    ret c

    push de
    sub $c9
    pop bc
    call nc, $d3c5
    ld a, a
    db $d3
    push bc
    sub $e4
    push bc
    jp nc, $ccc1

    ld a, a
    call nc, $cdc9
    push bc
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    db $e4
    adc $7f
    sub $cf
    call $d4c9
    db $d3
    ld a, a
    rst $08
    push de
    call nc, $d37f
    ret


    call z, Call_021_7fcb
    db $e4
    call nc, Call_021_7fcf
    jp nz, $c9d5

    call z, Call_021_7fc4
    pop bc
    ld a, a
    jp $c3cf


    rst $08
    rst $08
    adc $7f
    db $e4
    jp nz, $c6c5

    rst $08
    jp nc, Jump_021_7fc5

    jp nz, $c3c5

    rst $08
    call $cec9
    rst $00
    ld a, a
    pop bc
    adc $e4
    ld a, a
    pop bc
    call nz, $ccd5
    call nc, Call_021_7f8e
    ld d, b
    ld a, a
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
    db $e4
    pop bc
    ld a, a
    db $d3
    ret z

    pop bc
    jp nz, $d9c2

    adc l
    rst $08
    push de
    call nc, $d2c5
    ld a, a
    jp nz, $d4d5

    db $e4
    ld a, a
    ld a, a
    db $d3
    rst $08
    add $d4
    adc l
    ret


    adc $ce
    push bc
    jp nc, $c37f

    jp nc, $d3d5

    call nc, Call_021_7fe4
    ld a, a
    call nc, $c1c8
    call nc, $c37f
    pop bc
    adc $87
    call nc, $c27f
    push bc
    pop bc
    jp nc, $e47f

    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cfd2
    adc $c7
    ld a, a
    pop bc
    call nc, $c1d4
    jp $8ecb


    db $e4
    ld a, a
    ld d, b
    ld a, a
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    ld a, a
    db $e4
    push bc
    sub $c5
    adc $7f
    rst $08
    adc $7f
    pop bc
    ld a, a
    jp nc, $c9c1

    adc $d9
    ld a, a
    call nz, $e4c1
    reti


    ld a, a
    rst $10
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    rst $10
    ret


    adc $c7
    db $d3
    ld a, a
    pop bc
    jp nc, Jump_021_7fc5

    db $e4
    ret nc

    jp nc, $d3c5

    push bc
    jp nc, $c5d6

    call nz, $c27f
    reti


    ld a, a
    rst $10
    pop bc
    call nc, $d2c5
    db $e4
    adc l
    push de
    adc $c4
    ret


    db $d3
    db $d3
    rst $08
    call z, $c5d6
    call nz, $d37f
    jp $ccc1


    push bc
    db $e4
    db $d3
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    jp nz, $d8cf

    push bc
    db $d3
    ld a, a
    sub c
    sub b
    sub b
    sub b
    ld a, a
    call nc, $cdc9
    push bc
    db $d3
    ld a, a
    db $e4
    ret


    adc $7f
    sub d
    ld a, a
    db $d3
    push bc
    jp $cecf


    call nz, Call_021_7fd3
    rst $10
    ret


    call nc, Call_021_7fc8
    db $e4
    ret


    call nc, Call_021_7fd3
    sub h
    ld a, a
    rst $10
    push bc
    call z, $8dcc
    call nz, $d6c5
    push bc
    call z, $d0cf
    db $e4
    push bc
    call nz, $c17f
    jp nc, $d3cd

    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    adc $c4
    ld a, a
    rst $08
    add $7f
    db $d3
    rst $10
    ret


    call $c9cd
    db $e4
    adc $c7
    ld a, a
    jp nz, Jump_021_7fd9

    rst $10
    push bc
    jp nz, $cf7f

    add $7f
    call nc, $c5c8
    ld a, a
    add $e4
    push bc
    push bc
    call nc, Call_021_7f7f
    ret


    adc $7f
    call z, $cbc1
    push bc
    db $d3
    ld a, a
    rst $10
    ret


    call nc, $e4c8
    ld a, a
    pop bc
    ld a, a
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    call z, $d07f
    rst $08
    db $d3
    push bc
    adc [hl]
    db $e4
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    call nc, $c1cd
    adc $7f
    rst $10
    db $e4
    ret z

    rst $08
    ld a, a
    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    rst $00
    rst $08
    push bc
    db $d3
    ld a, a
    jp $d2c1


    db $e4
    jp nc, $c9d9

    adc $c7
    ld a, a
    pop bc
    ld a, a
    db $d3
    push de
    jp nz, $c5ca

    jp Jump_021_7fd4


    call z, $e4c9
    set 0, l
    ld a, a
    pop bc
    ld a, a
    ret nc

    push bc
    adc $c4
    push de
    call z, $cdd5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    rst $10
    pop bc
    adc $d4
    db $d3
    ld a, a
    call nc, Call_021_7fcf
    ret z

    reti


    ret nc

    adc $cf
    call nc, $dac9
    push bc
    db $e4
    ld a, a
    ld a, a
    jp $c9c8


    call z, Call_021_7fc4
    pop bc
    adc $c4
    ld a, a
    rst $00
    push de
    ret


    call nz, Call_021_7fc5
    db $e4
    call nc, $c5c8
    ld a, a
    sub $c9
    jp $c9d4


    call Call_021_7f7f
    call nc, Call_021_7fcf
    rst $00
    rst $08
    ld a, a
    db $e4
    pop bc
    rst $10
    pop bc
    reti


    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    sub $c1
    call $c9d0
    jp nc, Jump_021_7fc5

    rst $10
    ret z

    rst $08
    ld a, a
    db $e4
    jp nz, $d4c9

    push bc
    db $d3
    ld a, a
    jp nz, Jump_021_7fd9

    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    call nc, $c5c5
    db $e4
    call nc, Call_021_7fc8
    pop bc
    adc $c4
    ld a, a
    db $d3
    push de
    jp $c5cb


    db $d3
    ld a, a
    jp nz, $cfcc

    rst $08
    db $e4
    call nz, Call_021_7f7f
    sub e
    sub b
    sub b
    jp Jump_021_7fc3


    rst $08
    adc $c3
    push bc
    ld a, a
    pop bc
    ld a, a
    call nc, $e4c9
    call $8ec5
    ld a, a
    ld d, b
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    add $d4
    push bc
    adc $7f
    jp $c1c8


    adc $c7
    push bc
    call nz, $e47f
    pop bc
    adc $c4
    ld a, a
    jp nc, $c3c5

    rst $08
    call $c9c2
    adc $c5
    call nz, $c97f
    adc $7f
    db $e4
    rst $00
    push bc
    adc $c5
    ld a, a
    db $d3
    call nc, $c4d5
    ret


    push bc
    db $d3
    ld a, a
    ld a, a
    jp nz, $d4d5

    ld a, a
    db $e4
    push de
    adc $c5
    ret c

    ret nc

    push bc
    jp $c5d4


    call nz, $d9cc
    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $e4c5

    jp $cdcf


    push bc
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    ld a, a
    pop bc
    ld a, a
    add $c5
    jp nc, $c3cf

    db $e4
    ret


    rst $08
    push de
    db $d3
    ld a, a
    ret nc

    rst $08
    jp $c5cb


    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $e4c5
    jp nc, Jump_021_7f8e

    ld d, b
    ld a, a
    rst $10
    ret


    call z, Call_021_7fcc
    adc $c5
    sub $c5
    jp nc, $c47f

    jp nc, $d0cf

    ld a, a
    call nc, $c8e4
    push bc
    ld a, a
    ret


    call nz, $c1c5
    ld a, a
    ld a, a
    ret


    add $7f
    adc $cf
    ld a, a
    push bc
    pop bc
    call nc, $c9e4
    adc $c7
    ld a, a
    sub h
    sub b
    sub b
    xor e
    rst $00
    ld a, a
    rst $08
    add $7f
    add $cf
    rst $08
    call nz, $e47f
    pop bc
    ld a, a
    call nz, $d9c1
    ld a, a
    ld a, a
    jp nz, $d4d5

    ld a, a
    rst $00
    rst $08
    push bc
    db $d3
    ld a, a
    call nc, $e4cf
    ld a, a
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ld a, a
    rst $08
    adc $c3
    push bc
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    add $e4
    ret


    adc $c9
    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    push bc
    pop bc
    call nc, $cec9
    rst $00
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    push bc
    pop bc
    set 0, l
    db $d3
    call nc, $c17f
    adc $e4
    call nz, $c67f
    pop bc
    jp $8dc5


    call z, $d3cf
    ret


    adc $c7
    ld a, a
    call $cecf
    db $d3
    db $e4
    call nc, $d2c5
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    ld a, a
    db $e4
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ret z

    ret


    db $d3
    ld a, a
    ret nc

    rst $08
    rst $08
    db $e4
    jp nc, $c67f

    rst $08
    jp nc, $c5c3

    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret nc

    rst $08
    rst $08
    jp nc, $d37f

    db $e4
    ret nc

    push bc
    push bc
    call nz, $8e7f
    ld a, a
    ld d, b
    ld a, a
    rst $08
    rst $08
    jp c, $d3c5

    ld a, a
    add $d2
    rst $08
    call $c77f
    jp nc, $d5cf

    adc $c4
    db $e4
    ld a, a
    ld a, a
    push de
    adc $c1
    rst $10
    pop bc
    jp nc, $d3c5

    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $d2c8
    db $e4
    push bc
    pop bc
    call nc, $cec5
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $d2c1


    push bc
    call z, $d3c5
    db $e4
    db $d3
    ld a, a
    sub $c9
    jp $c9d4


    call $c27f
    reti


    ld a, a
    ret


    call nc, Call_021_7fd3
    pop bc
    jp $d5e4


    call nc, Call_021_7fc5
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $8e
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    ret z

    pop bc
    jp nc, Jump_021_7fc4

    db $d3
    jp $d3c9


    db $d3
    rst $08
    jp nc, $d3e4

    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    pop bc
    ld a, a
    call nz, $c9d2
    sub $c9
    adc $c7
    ld a, a
    add $e4
    rst $08
    jp nc, $c5c3

    ld a, a
    sub c
    sub b
    sub b
    sub b
    sub b
    ld a, a
    ret z

    rst $08
    jp nc, $c5d3

    ret nc

    rst $08
    db $e4
    rst $10
    push bc
    jp nc, Jump_021_7f7f

    jp nz, $d4d5

    ld a, a
    call $d6cf
    push bc
    db $d3
    ld a, a
    db $d3
    rst $08
    ld a, a
    db $e4
    push de
    adc $c3
    rst $08
    adc $d6
    push bc
    adc $c9
    push bc
    adc $d4
    call z, Call_021_7fd9
    jp nz, $c3c5

    db $e4
    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    call nc, $cfcf
    ld a, a
    jp nz, $c7c9

    ld a, a
    db $d3
    ret


    db $e4
    jp c, $8ec5

    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $d5d2


    db $d3
    call nc, Call_021_7f7f
    ret z

    pop bc
    jp nc, $e4c4

    push bc
    jp nc, $c57f

    sub $c5
    adc $7f
    adc $cf
    call nc, $c27f
    push bc
    ld a, a
    call nz, $d3c5
    db $e4
    call nc, $cfd2
    reti


    push bc
    call nz, $c27f
    reti


    ld a, a
    pop bc
    ld a, a
    adc $c1
    ret nc

    pop bc
    call z, $e4cd
    ld a, a
    jp nz, $cdcf

    jp nz, Jump_021_7f7f

    pop bc
    adc $c4
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    rst $08
    ret nc

    db $e4
    push bc
    adc $d3
    ld a, a
    ret


    call nc, $d57f
    ret nc

    ld a, a
    pop bc
    call nc, $c17f
    adc $7f
    pop bc
    call nc, $d4e4
    pop bc
    jp $c9cb


    adc $c7
    ld a, a
    call nc, $cdc9
    push bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $d3c5

    ret nc

    rst $08
    adc $d3
    push bc
    ld a, a
    push bc
    sub $c5
    adc $7f
    db $e4
    call nc, Call_021_7fcf
    pop bc
    ld a, a
    call z, $d4c9
    call nc, $c5cc
    ld a, a
    db $d3
    call nc, $cdc9
    push de
    call z, $d5e4
    db $d3
    ld a, a
    call nc, Call_021_7fcf
    push bc
    ret c

    ret nc

    call z, $c4cf
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    call nc, $d2c8
    push bc
    pop bc
    call nc, $cec5
    db $d3
    ld a, a
    ret nc

    push bc
    rst $08
    call z, $c5d0
    ld a, a
    rst $08
    db $e4
    adc $cc
    reti


    ld a, a
    jp nz, Jump_021_7fd9

    ret


    call nc, Call_021_7fd3
    adc $c9
    jp $cecb


    pop bc
    call $c5e4
    adc l
    jp nz, $cdcf

    jp nz, $d387

    ld a, a
    jp nz, $cdcf

    jp nz, Jump_021_7f8e

    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    push bc
    pop bc
    jp nc, Jump_021_7fd3

    call nc, $e4cf
    ld a, a
    call nz, $d3c9
    call nc, $cec9
    rst $00
    push de
    ret


    db $d3
    ret z

    ld a, a
    pop bc
    ld a, a
    adc $c5
    push bc
    db $e4
    call nz, $c5cc
    adc l
    call nz, $cfd2
    ret nc

    ret nc

    ret


    adc $c7
    ld a, a
    db $d3
    rst $08
    push de
    adc $c4
    db $e4
    ld a, a
    jp $c5cc


    pop bc
    jp nc, $d9cc

    ld a, a
    add $d2
    rst $08
    call $c17f
    ld a, a
    sub c
    xor e
    db $e4
    call $c48d
    ret


    db $d3
    call nc, $cec1
    jp Jump_021_7fc5


    add $c1
    jp nc, $8e7f

    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    jp $d2c1


    jp Jump_021_7fc5


    db $d3
    ret


    pop bc
    call $e4c5
    db $d3
    push bc
    ld a, a
    call nc, $c9d7
    adc $d3
    ld a, a
    rst $08
    jp nc, $cf7f

    adc $c5
    ld a, a
    rst $10
    ret


    db $e4
    call nc, Call_021_7fc8
    pop bc
    adc $cf
    call nc, $c5c8
    jp nc, $c17f

    call nc, $c1d4
    jp $c5c8


    db $e4
    call nz, $c17f
    call nc, $c17f
    ld a, a
    db $d3
    push de
    call nz, $c5c4
    adc $7f
    call $d4d5
    pop bc
    db $e4
    call nc, $cfc9
    adc $7f
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    jp $c1c8


    adc $c7
    push bc
    db $d3
    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    call $cfcf
    call nz, $e47f
    pop de
    push de
    ret


    jp $cccb


    reti


    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret nc

    push de
    call nc, Call_021_7fd3
    push de
    db $e4
    ret nc

    ld a, a
    ret z

    ret


    db $d3
    ld a, a
    call nc, $c9c1
    call z, $d47f
    rst $08
    ld a, a
    ret nc

    jp nc, $d0c5

    db $e4
    pop bc
    jp nc, Jump_021_7fc5

    call nc, Call_021_7fcf
    pop bc
    call nc, $c1d4
    jp $8ecb


    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    call $ccc1
    call z, $c17f
    adc $c4
    ld a, a
    rst $10
    db $e4
    push bc
    pop bc
    bit 7, a
    jp nz, $c4cf

    reti


    ld a, a
    jp nz, $d4d5

    ld a, a
    jp nz, $c3c5

    rst $08
    call $c5e4
    db $d3
    ld a, a
    add $c5
    jp nc, $c3cf

    ret


    rst $08
    push de
    db $d3
    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, Jump_021_7fe4

    push de
    db $d3
    ret


    adc $c7
    ld a, a
    jp nz, $cecf

    push bc
    db $d3
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call nc, $c5c8
    jp nc, Jump_021_7fc5

    push bc
    ret c

    ret


    db $d3
    ret


    db $d3
    ld a, a
    adc $cf
    jp nz, $e4cf

    call nz, Call_021_7fd9
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call nz, $d2c1
    bit 7, a
    jp nz, $d4d5

    db $e4
    ld a, a
    ld a, a
    ld a, a
    call nc, $c5c8
    jp nc, Jump_021_7fc5

    pop bc
    call z, $c1d7
    reti


    db $d3
    ld a, a
    db $d3
    ret z

    db $e4
    rst $08
    push de
    call z, Call_021_7fc4
    jp nz, Jump_021_7fc5

    pop bc
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, $d37f
    push bc
    db $e4
    push bc
    ret


    adc $c7
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    db $d3
    ld a, a
    jr jr_021_6f94

    ret z

    rst $08
    push de
    jp nc, Jump_021_7fd3

    pop bc
    ld a, a
    call nz, $c1e4
    reti


    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    sub $c1
    jp nc, $cfc9

    push de
    db $d3
    db $e4
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    jp nc, $c2c1

    ret


    call z, $d4c9
    ret


    push bc
    db $d3
    ld a, a
    push bc
    sub $e4
    push bc
    adc $7f
    call nz, $d2d5
    ret


    adc $c7
    ld a, a
    db $d3
    adc $cf
    jp nc, $cec9

    rst $00
    ld a, a
    db $e4
    db $d3
    call z, $c5c5
    ret nc

    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    call nz, $d3c9
    call z, $cbc9
    push bc
    db $d3
    ld a, a
    jp nz, $c4cf

    reti


    ld a, a
    db $d3
    set 1, c
    db $e4
    call z, $d3cc
    ld a, a
    ld a, a
    jp nz, $d4d5

    ld a, a
    push de
    db $d3
    push bc
    db $d3
    ld a, a
    db $d3
    push de
    ret nc

    push bc
    db $e4
    jp nc, $c2c1

    ret


    call z, $d4c9
    reti


    ld a, a
    ld a, a
    add $d2
    push bc
    push bc

jr_021_6f94:
    call z, Call_021_7fd9
    pop bc
    db $e4
    adc $c4
    ld a, a
    set 1, [hl]
    rst $08
    jp Jump_021_7fcb


    call nz, $d7cf
    adc $7f
    call nc, $c5c8
    ld a, a
    db $e4
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    call nc, Call_021_7fd3
    call nc, $ccc1
    rst $08
    adc $d3
    ld a, a
    pop bc
    jp nc, Jump_021_7fc5

    rst $10
    push bc
    db $e4
    call z, $8dcc
    call nz, $d6c5
    push bc
    call z, $d0cf
    push bc
    call nz, $c17f
    adc $c4
    ld a, a
    ret z

    db $e4
    rst $08
    call z, Call_021_7fc4
    call nc, $c5c8
    ld a, a
    add $cf
    rst $08
    call nz, $c27f
    pop bc
    ret


    call nc, $e47f
    call nc, Call_021_7fcf
    call nc, $c5c8
    ld a, a
    adc $c5
    db $d3
    call nc, $cf7f
    push de
    call nc, $c9d3
    call nz, $c5e4
    ld a, a
    sub c
    sub b
    sub b
    xor e
    call Call_021_7f8e
    ld d, b
    ld a, a
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    call nc, Call_021_7fcf
    pop bc
    adc $c4
    ld a, a
    add $d2
    rst $08
    ld a, a
    db $e4
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    ret


    call nc, $d3e4
    ld a, a
    jp nz, $c1c5

    push de
    call nc, $c6c9
    push de
    call z, $d77f
    ret


    adc $c7
    db $d3
    ld a, a
    db $e4
    call nc, Call_021_7fcf
    call nc, $d2c8
    push bc
    pop bc
    call nc, $cec5
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    db $e4
    adc $d4
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    push de
    db $d3
    ret nc

    push bc
    jp $c5d4


    call nz, $c27f
    reti


    ld a, a
    call z, $cfe4
    jp $ccc1


    ld a, a
    ret nc

    push bc
    rst $08
    ret nc

    call z, Call_021_7fc5
    call nc, Call_021_7fcf
    jp nz, Jump_021_7fc5

    db $e4
    pop bc
    ld a, a
    push de
    adc $c9
    sub $c5
    jp nc, $c1d3

    call z, $c37f
    jp nc, $c1c5

    call nc, $e4d5
    jp nc, Jump_021_7fc5

    ld a, a
    ret


    call nz, $cec5
    call nc, $c6c9
    ret


    push bc
    call nz, $c67f
    jp nc, $e4cf

    call $d47f
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $cec1
    call nz, $d2c1
    call nz, $c27f
    rst $08
    call nz, $d9e4
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nz, $c3c1

    bit 7, a
    ld a, a
    rst $08
    db $e4
    add $7f
    call nc, $c5c8
    ld a, a
    ret nc

    call z, $cec1
    call nc, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c8e4
    push bc
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    ret


    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    jp nz, $d2cf

    db $e4
    adc $8c
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret


    db $d3
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, Call_021_7fe4
    call nc, Call_021_7fcf
    jp nz, $c3c5

    rst $08
    call Call_021_7fc5
    rst $00
    jp nc, $c4c1

    push de
    pop bc
    call z, $cce4
    reti


    ld a, a
    call z, $d2c1
    rst $00
    push bc
    jp nc, $c17f

    adc $c4
    ld a, a
    call z, $d2c1
    rst $00
    db $e4
    push bc
    jp nc, Jump_021_7f8e

    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    add $d2
    pop bc
    rst $00
    jp nc, $cec1

    jp Jump_021_7fc5


    ld a, a
    rst $10
    db $e4
    pop bc
    add $d4
    push bc
    call nz, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $c5c8
    ld a, a
    add $cc
    rst $08
    db $e4
    rst $10
    push bc
    jp nc, $d47f

    rst $08
    ld a, a
    jp $ccc1


    call $c47f
    rst $08
    rst $10
    adc $7f
    call nc, $c8e4
    push bc
    ld a, a
    ld a, a
    call $cfcf
    call nz, $cf7f
    add $7f
    jp $cdcf


    ret nc

    push bc
    call nc, $c9e4
    call nc, $d2cf
    db $d3
    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    add b
    ld a, a
    call nc, $cec5
    call nc, $c3c1
    call z, $d3c5
    ld a, a
    add $d2
    db $e4
    push bc
    push bc
    call z, Call_021_7fd9
    call $d6cf
    ret


    adc $c7
    ld a, a
    call nc, $c1c8
    call nc, $d37f
    db $e4
    call nc, $cec9
    rst $00
    db $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    push bc
    call $d4c9
    db $d3
    ld a, a
    ret nc

    rst $08
    db $e4
    ret


    db $d3
    rst $08
    adc $7f
    call nc, Call_021_7fcf
    call $cbc1
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $cfe4

    call nz, Call_021_7fd9
    rst $08
    add $7f
    sub $c9
    jp $c9d4


    call $d07f
    pop bc
    ret


    adc $e4
    add $d5
    call z, Call_021_7f8e
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $10
    push bc
    call z, $8dcc
    call nz, $d6c5
    push bc
    call z, $d0cf
    push bc
    db $e4
    call nz, $c47f
    rst $08
    jp nc, $c1d3

    call z, $c67f
    ret


    adc $7f
    pop bc
    adc $c4
    ld a, a
    ret nc

    db $e4
    push bc
    jp $cfd4


    jp nc, $ccc1

    ld a, a
    add $c9
    adc $7f
    call z, $cbc9
    push bc
    ld a, a
    call $d5e4
    db $d3
    jp $c5cc


    db $d3
    ld a, a
    ld a, a
    call nc, Call_021_7fcf
    db $d3
    rst $10
    ret


    call $c17f
    call nc, Call_021_7fe4
    pop bc
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, $d07f
    push bc
    jp nc, $c87f

    rst $08
    push de
    jp nc, $e47f

    sub l
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    call $ccc9
    push bc
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $e4
    rst $10
    pop bc
    call nc, $d2c5
    adc [hl]
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    ret z

    rst $08
    jp nc, Jump_021_7fce

    db $e4
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    pop bc
    ld a, a
    call nz, $c9d2
    call z, $cfcc
    jp nc, $d47f

    rst $08
    db $e4
    ld a, a
    ld a, a
    jp nz, $c9d5

    call z, Call_021_7fc4
    ret z

    ret


    call $c5d3
    call z, $87c6
    db $d3
    ld a, a
    db $e4
    adc $c5
    db $d3
    call nc, $d77f
    ret z

    ret


    call z, Call_021_7fc5
    call nz, $c9d2
    call z, $c9cc
    adc $e4
    rst $00
    ld a, a
    ld a, a
    pop bc
    ld a, a
    ret z

    rst $08
    call z, Call_021_7fc5
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $cfe4

    jp Jump_021_7fcb


    db $d3
    push de
    jp nc, $c1c6

    jp $8ec5


    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c27f
    rst $08
    call nz, Call_021_7fd9
    db $e4
    jp nz, $d4d5

    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    add $cf
    jp nc, $c5c3

    add $d5
    call z, Call_021_7fe4
    ld a, a
    call z, $c7c5
    ld a, a
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, Jump_021_7f7f

    call nc, $c1c8
    call nc, $e47f
    jp z, $cdd5

    ret nc

    db $d3
    ld a, a
    rst $08
    sub $c5
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    or h
    rst $08
    set 4, h
    reti


    rst $08
    ld a, a
    or h
    rst $08
    rst $10
    push bc
    jp nc, $cf7f

    adc $cc
    reti


    ld a, a
    jp nz, Jump_021_7fd9

    rst $08
    db $e4
    adc $c5
    ld a, a
    call nc, $c9d2
    pop bc
    call z, $ca7f
    push de
    call Call_021_7fd0
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    jp nz, $d2d5

    adc $d3
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nc, $ced5

    db $d3
    ld a, a
    pop bc
    call nc, Call_021_7fe4
    pop bc
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, $d47f
    ret z

    push bc
    ld a, a
    db $d3
    pop bc
    call Call_021_7fc5
    db $e4
    pop bc
    db $d3
    ld a, a
    adc $c5
    rst $10
    ld a, a
    call $c9c1
    adc $7f
    call z, $cec9
    push bc
    ld a, a
    ld a, a
    db $e4
    push bc
    sub $c5
    adc $7f
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    ret z

    ret


    rst $00
    ret z

    push bc
    db $d3
    db $e4
    call nc, $d37f
    ret nc

    push bc
    push bc
    call nz, $d07f
    push bc
    jp nc, $c87f

    rst $08
    push de
    jp nc, $927f

    db $e4
    sub h
    sub b
    xor e
    call $8e7f
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    ret z

    pop bc
    jp nc, $d0e4

    ld a, a
    call nc, $cfcf
    call nc, Call_021_7fc8
    rst $10
    ret z

    ret


    jp Jump_021_7fc8


    pop bc
    call z, $c1d7
    db $e4
    reti


    db $d3
    ld a, a
    rst $00
    jp nc, $d7cf

    db $d3
    ld a, a
    push de
    ret nc

    ld a, a
    jp nz, Jump_021_7fd9

    jp nz, $d4c9

    db $e4
    ret


    adc $c7
    ld a, a
    rst $08
    add $c6
    ld a, a
    rst $08
    jp nc, $d37f

    ret z

    pop bc
    sub $c9
    adc $c7
    db $e4
    ld a, a
    rst $08
    add $c6
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    pop bc
    jp nc, Jump_021_7fc4

    rst $08
    jp nz, $c5ca

    db $e4
    jp $d3d4


    ld a, a
    db $d3
    rst $10
    ret


    call Call_021_7fd3
    rst $10
    ret


    call nc, Call_021_7fc8
    sub e
    adc l
    call nc, $c5cf
    ld a, a
    db $e4
    rst $10
    push bc
    jp nz, Jump_021_7fd3

    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    call z, $cbc1
    push bc
    adc [hl]
    ld a, a
    db $e4
    ld d, b
    ld a, a
    ret nc

    push de
    adc $c3
    call nc, $d2d5
    push bc
    db $d3
    ld a, a
    call nz, $c1c9
    call $cecf
    call nz, Call_021_7fe4
    jp nz, Jump_021_7fd9

    jp nz, $c1d2

    adc $c4
    ret


    db $d3
    ret z

    ret


    adc $c7
    ld a, a
    rst $10
    push bc
    db $e4
    call z, $8dcc
    call nz, $d6c5
    push bc
    call z, $d0cf
    push bc
    call nz, $c87f
    rst $08
    jp nc, Jump_021_7fce

    db $e4
    rst $10
    ret z

    push bc
    adc $7f
    ret z

    pop bc
    sub $c9
    adc $c7
    ld a, a
    pop bc
    adc $7f
    pop bc
    adc $c7
    db $e4
    jp nc, $8dd9

    push bc
    pop bc
    db $d3
    ret


    call z, Call_021_7fd9
    call nc, $cdc5
    ret nc

    push bc
    jp nc, $8e7f

    db $e4
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    push bc
    adc $d4
    call z, Call_021_7fc5
    ld a, a
    adc $c1
    call nc, $d5e4
    jp nc, Jump_021_7fc5

    rst $08
    add $7f
    add $c5
    call $ccc1
    push bc
    ld a, a
    jp nz, $d4d5

    ld a, a
    db $e4
    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    call nc, Call_021_7fcf
    call $cbc1
    db $e4
    push bc
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    ret nc

    push de
    jp c, $ccda

    push bc
    ld a, a
    db $e4
    jp nz, Jump_021_7fd9

    ret nc

    jp nc, $c4cf

    push de
    jp $cec9


    rst $00
    ld a, a
    pop bc
    ld a, a
    db $d3
    push de
    ret nc

    db $e4
    push bc
    jp nc, $cfd3

    adc $c9
    jp $d77f


    pop bc
    sub $c5
    ld a, a
    ld a, a
    add $d2
    rst $08
    call Call_021_7fe4
    call nc, $c5c8
    ld a, a
    call $d5cf
    call nc, $8ec8
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    push de
    db $d3
    push bc
    call nz, $d47f
    rst $08
    ld a, a
    ret nc

    call z, $d9c1
    ld a, a
    pop bc
    db $e4
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    adc l
    call nc, $d2c8
    rst $08
    rst $10
    ld a, a
    rst $00
    pop bc
    call Call_021_7fc5
    db $e4
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    rst $08
    add $7f
    ret


    call nc, Call_021_7fd3
    jp nc, $d5cf

    db $e4
    adc $c4
    ld a, a
    db $d3
    ret z

    pop bc
    ret nc

    push bc
    ld a, a
    call nc, Call_021_7fcf
    jp nz, Jump_021_7fc5

    jp $d5c1


    db $e4
    rst $00
    ret z

    call nc, $c57f
    pop bc
    db $d3
    ret


    call z, Call_021_7fd9
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call $cec1
    adc l
    call $c4c1
    push bc
    ld a, a
    ret nc

    rst $08
    jp $cbe4


    push bc
    call nc, $cd7f
    rst $08
    adc $d3
    call nc, $d2c5
    ld a, a
    jp nz, Jump_021_7fd9

    call nc, $c5c8
    db $e4
    ld a, a
    call $d3cf
    call nc, $c17f
    call nz, $c1d6
    adc $c3
    push bc
    call nz, $c87f
    ret


    adc l
    db $e4
    call nc, $c3c5
    ret z

    ld a, a
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $d6c5

    ret


    sub $c5
    call nz, Call_021_7f7f
    add $d2
    rst $08
    call $e47f
    call nc, $c5c8
    ld a, a
    jp nc, $d3c5

    ret


    call nz, $c1d5
    call z, $c77f
    push bc
    adc $c5
    ld a, a
    db $e4
    rst $08
    add $7f
    call nz, $cec9
    rst $08
    db $d3
    pop bc
    push de
    jp nc, Jump_021_7f7f

    ret


    adc $7f
    call nc, $e4c8
    push bc
    ld a, a
    pop bc
    call $c5c2
    jp nc, $c17f

    adc $c4
    ld a, a
    adc $cf
    rst $10
    ld a, a
    ret


    db $d3
    db $e4
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call nc, $cec9
    rst $00
    ld a, a
    rst $10
    ret z

    ret


    call z, Call_021_7fc5
    jp nc, $e4d5

    adc $ce
    ret


    adc $c7
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret nc

    jp nc, $c4cf

    push de
    jp $d3c5


    ld a, a
    push bc
    call z, $c3c5
    call nc, $cfd2
    call $c1e4
    rst $00
    adc $c5
    call nc, $c3c9
    ld a, a
    rst $10
    pop bc
    sub $c5
    db $d3
    ld a, a
    add $d2
    rst $08
    call Call_021_7fe4
    ld a, a
    call nc, $c5c8
    ld a, a
    jp $cecf


    db $d3
    call nc, $d4c9
    push de
    call nc, $cfc9
    adc $e4
    ld a, a
    db $d3
    push de
    jp nc, $cfd2

    push de
    adc $c4
    ret


    adc $c7
    db $d3
    ld a, a
    rst $10
    ret z

    ret


    call z, $c5e4
    ld a, a
    ld a, a
    add $cc
    rst $08
    pop bc
    call nc, $cec9
    rst $00
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call $e4cf
    sub $c9
    adc $c7
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    ld a, a
    adc [hl]
    ld a, a
    db $e4
    ld d, b
    ld a, a
    jp nz, $d2d5

    adc $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c9
    jp nc, Jump_021_7fc5

    ld a, a
    rst $08
    db $e4
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $c9c1
    call z, $c67f
    jp nc, $cdcf

    ld a, a
    call nc, $e4c8
    push bc
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    ret


    call nc, $d77f
    pop bc
    db $d3
    ld a, a
    jp nz, $d2cf

    adc $e4
    ld a, a
    pop bc
    adc $c4
    ld a, a
    push bc
    adc $c4
    db $d3
    ld a, a
    ret


    call nc, Call_021_7fd3
    call z, $c6c9
    push bc
    db $e4
    ld a, a
    pop bc
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    add $c9
    jp nc, Jump_021_7fc5

    jp nz, $d2d5

    adc $d3
    db $e4
    ld a, a
    rst $08
    push de
    call nc, Call_021_7f8e
    ld d, b
    ld a, a
    ret


    call nc, Call_021_7fd3
    call z, $cecf
    rst $00
    ld a, a
    adc $c5
    jp Jump_021_7fcb


    call nz, $c1d2
    db $e4
    rst $10
    db $d3
    ld a, a
    jp nz, $c3c1

    bit 7, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    push bc
    call z, Call_021_7fcc
    db $e4
    ld a, a
    jp $cdcf


    add $cf
    jp nc, $c1d4

    jp nz, $cccc

    reti


    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $e4
    push bc
    call $d4c9
    db $d3
    ld a, a
    rst $08
    push de
    call nc, $d77f
    pop bc
    call nc, $d2c5
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    set 1, [hl]
    rst $08
    jp $d3cb


    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    db $e4
    adc $d4
    ld a, a
    call nz, $d7cf
    adc $7f
    rst $10
    ret


    call nc, Call_021_7fc8
    call nc, $c9c1
    call z, $e47f
    pop bc
    adc $c4
    ld a, a
    call nc, $c1c5
    jp nc, Jump_021_7fd3

    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    db $e4
    adc $c5
    adc $d4
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    ret nc

    ret


    push bc
    jp $d3c5


    ld a, a
    rst $10
    db $e4
    ret


    call nc, Call_021_7fc8
    db $d3
    ret z

    pop bc
    jp nc, Jump_021_7fd0

    jp $c1cc


    rst $10
    db $d3
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    call z, $cbc9
    push bc
    call nz, $c27f
    reti


    ld a, a
    call $cec1
    ld a, a
    pop bc
    db $e4
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    push bc
    call nc, $d77f
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    call nc, $c9c1
    call z, Call_021_7fe4
    ld a, a
    jp $d6cf


    push bc
    jp nc, $c4c5

    ld a, a
    jp nz, Jump_021_7fd9

    ret z

    pop bc
    ret


    jp nc, $e47f

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    db $d3
    ret


    rst $00
    adc $7f
    rst $08
    add $7f
    call z, $cecf
    rst $00
    ld a, a
    db $e4
    call z, $c6c9
    push bc
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    add $cc
    ret


    push bc
    db $d3
    ld a, a
    rst $10
    ret


    call nc, Call_021_7fc8
    rst $10
    ret


    adc $c7
    db $d3
    ld a, a
    db $e4
    ld a, a
    pop bc
    jp nz, $d6cf

    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d5cf

    adc $c4
    ld a, a
    db $e4
    sub c
    sub h
    sub b
    sub b
    call $c17f
    adc $c4
    ld a, a
    db $d3
    ret nc

    jp nc, $d9c1

    db $d3
    ld a, a
    ret z

    db $e4
    ret


    rst $00
    ret z

    adc l
    call nc, $cdc5
    ret nc

    push bc
    jp nc, $d4c1

    push de
    jp nc, Jump_021_7fc5

    add $cc
    db $e4
    pop bc
    call $d3c5
    adc [hl]
    ld a, a
    ld d, b
    ld a, a
    pop bc
    call z, $c1c9
    db $d3
    ld a, a
    rst $10
    pop bc
    call z, $c1cb
    jp nz, $c5cc

    ld a, a
    ld a, a
    ret


    db $e4
    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d47f
    rst $08
    ld a, a
    rst $00
    rst $08
    ld a, a
    sub e
    sub b
    sub b
    call $e47f
    rst $10
    ret


    call nc, Call_021_7fc8
    ret


    call nc, Call_021_7fd3
    sub d
    ld a, a
    jp nc, $cfcf

    call nc, Call_021_7fd3
    ld a, a
    db $e4
    pop bc
    call nc, $d47f
    ret z

    push bc
    ld a, a
    adc $c9
    rst $00
    ret z

    call nc, Call_021_7f8e
    ld d, b
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    ret


    db $d3
    call nc, $ccc9
    ld a, a
    rst $00
    ret


    sub $c5
    db $d3
    ld a, a
    db $e4
    rst $08
    push de
    call nc, $c17f
    ld a, a
    db $d3
    call nc, $cec9
    bit 7, a
    rst $10
    ret z

    ret


    jp Jump_021_7fc8


    db $e4
    db $d3
    ret nc

    jp nc, $c1c5

    call nz, Call_021_7fd3
    sub d
    xor e
    call $c67f
    pop bc
    jp nc, $d47f

    rst $08
    db $e4
    ld a, a
    call $cbc1
    push bc
    ld a, a
    call $cec1
    ld a, a
    call nz, $c5c9
    call nz, Call_021_7f8e
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    db $d3
    call nc, $cf7f
    adc $e4
    push bc
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    ld a, a
    ld a, a
    rst $10
    ret z

    db $e4
    rst $08
    db $d3
    push bc
    ld a, a
    ret nc

    rst $08
    call z, $c5cc
    adc $7f
    db $d3
    ret nc

    jp nc, $c1c5

    call nz, $e4d3
    ld a, a
    push bc
    sub $c5
    jp nc, $d7d9

    ret z

    push bc
    jp nc, Jump_021_7fc5

    call z, $cbc9
    push bc
    ld a, a
    pop bc
    db $e4
    ld a, a
    ld a, a
    rst $00
    ret z

    rst $08
    db $d3
    call nc, $d47f
    rst $08
    ld a, a
    ret


    adc $c4
    push de
    jp Jump_021_7fc5


    db $e4
    ret z

    push de
    call $cec1
    ld a, a
    rst $00
    push bc
    call nc, $c17f
    call z, $c5cc
    jp nc, $d9c7

    adc [hl]
    db $e4
    ld a, a
    ld d, b
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret nc

    ret


    db $d3
    call nc, $ccc9
    ld a, a
    pop bc
    adc $c4
    ld a, a
    db $d3
    call nc, $c1e4
    call $cec5
    ld a, a
    call z, $cbc9
    push bc
    ld a, a
    ret z

    push de
    call $cec1
    add a
    db $d3
    ld a, a
    db $e4
    add $c1
    jp $8ec5


    ld a, a
    ld d, b
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call $d7cf
    push bc
    jp nc, Jump_021_7f7f

    call nc, Call_021_7fcf
    jp $e4d5


    call nc, $cf7f
    add $c6
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    db $e4
    ld a, a
    ld a, a
    jp nz, Jump_021_7fd9

    ret


    call nc, Call_021_7fd3
    db $d3
    pop bc
    call z, $d6c9
    pop bc
    ld a, a
    rst $10
    ret z

    db $e4
    ret


    jp Jump_021_7fc8


    ret


    db $d3
    ld a, a
    sub $cf
    call $d4c9
    push bc
    call nz, $c67f
    jp nc, $e4cf

    call $d47f
    ret z

    push bc
    ld a, a
    call $d5cf
    call nc, Call_021_7fc8
    ld a, a
    call nc, Call_021_7fcf
    call nz, $e4c9
    db $d3
    db $d3
    rst $08
    call z, $c5d6
    ld a, a
    push bc
    sub $c5
    jp nc, $d4d9

    ret z

    ret


    adc $c7
    adc [hl]
    db $e4
    ld a, a
    ld d, b
    ld a, a
    ret


    adc $c4
    push de
    jp $d3c5


    ld a, a
    rst $10
    ret z

    rst $08
    push bc
    sub $c5
    jp nc, $c77f

    db $e4
    rst $08
    ld a, a
    ret


    adc $d4
    rst $08
    ld a, a
    ret


    call nc, Call_021_7fd3
    call $d5cf
    call nc, Call_021_7fc8
    jp nz, $d9e4

    ld a, a
    ret


    call nc, Call_021_7fd3
    add $d2
    pop bc
    rst $00
    jp nc, $cec1

    jp Jump_021_7fc5


    ld a, a
    call z, $c9e4
    set 0, l
    ld a, a
    ret z

    rst $08
    adc $c5
    reti


    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nz, $d3c9
    db $d3
    db $e4
    rst $08
    call z, $c5d6
    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    sub $c9
    jp $c9d4


    call Call_021_7f7f
    db $e4
    jp nz, Jump_021_7fd9

    ret


    call nc, Call_021_7fd3
    call $c7c1
    ret


    jp $d37f


    pop bc
    call z, $d6c9
    db $e4
    pop bc
    adc [hl]
    ld a, a
    ld d, b
    nop
    ld a, a
    ld a, a
    xor c
    add a
    call $c17f
    call z, $cfd3
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ld c, a
    ret


    adc $c7
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
    adc [hl]
    ld d, l
    ld a, a
    ld a, a
    xor c
    add $7f
    xor c
    ld a, a
    rst $10
    push bc
    jp nc, Jump_021_7fc5

    db $d3
    call nc, $cfd2
    adc $55
    rst $00
    push bc
    jp nc, Jump_021_7f8c

    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    ld a, a
    pop bc
    call z, Call_021_55d3
    rst $08
    ld a, a
    jp $cec1


    ld a, a
    jp nc, $d0c5

    call z, $c3c1
    push bc
    ld a, a
    rst $00
    push de
    pop bc
    ld d, l
    jp nc, Jump_021_57c4

    nop
    ld a, a
    ld a, a
    or a
    ret z

    pop bc
    call nc, $c17f
    ld a, a
    call nc, $d2c5
    jp nc, $c6c9

    ret


    jp Jump_021_7f4f


    call nc, $c5c8
    ld a, a
    db $d3
    jp $c5c9


    adc $d4
    ret


    add $c9
    jp $d37f


    ld d, l
    call nc, $c5d2
    adc $c7
    call nc, Call_021_7fc8
    ret


    db $d3
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    xor c
    call nc, Call_021_7f55
    ret


    db $d3
    ld a, a
    db $d3
    pop bc
    ret


    call nz, $d07f
    jp nc, $d0cf

    ld a, a
    pop bc
    adc $c4
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    jp $cec1


    ld a, a
    jp nz, Jump_021_7fc5

    call nc, $c1d2
    adc $d3
    ld d, l
    add $c5
    jp nc, $c5d2

    call nz, $c97f
    adc $d4
    rst $08
    ld a, a
    call nz, $d4c1
    pop bc
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c1d2
    adc $d3
    call $c955
    call nc, $c5d4
    call nz, $c27f
    reti


    ld a, a
    ld e, e
    ld a, a
    jp $cdcf


    call Call_021_55d5
    adc $c9
    jp $d4c1


    ret


    rst $08
    adc $57
    adc [hl]
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    xor c
    adc $d3
    call nc, $c94f
    call nc, $d4d5
    push bc
    ld a, a
    rst $08
    add $7f
    and h
    jp nc, $af8e

    set 0, c
    call nz, Call_021_55c1
    ld d, a
    adc [hl]
    nop
    ld a, a
    ld a, a
    xor b
    push bc
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    ld a, a
    rst $10
    ret z

    ret


    call nc, Call_021_7fc5
    ld c, a
    jp $d4c9


    reti


    adc [hl]
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or a
    ret z

    ret


    call nc, Call_021_7fc5
    ret


    ld d, l
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cdc9

    pop bc
    jp nc, Jump_021_7fd9

    jp $cccf


    rst $08
    push de
    ld d, l
    jp nc, Jump_000_0057

    ld a, a
    xor b
    push bc
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call $4fc5
    ld a, a
    rst $08
    add $7f
    ld a, a
    ld d, d
    ld d, a
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_021_7fc5

    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call $4fc5
    ld a, a
    rst $08
    add $7f
    ld d, e
    ld d, a
    nop
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    pop de
    push de
    push bc
    push bc
    jp nc, $c27f

    pop bc
    ld c, a
    call z, Call_021_7fcc
    ld d, [hl]
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    reti


    push bc
    db $d3
    adc h
    ld a, a
    ret


    call nc, Call_021_7f55
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, h
    add c
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    xor c
    call nc, $c97f
    db $d3
    ld a, a
    jp $cecf


    sub $c9
    adc $c5
    adc $d4
    ld d, l
    ld a, a
    rst $10
    ret z

    push bc
    adc $c5
    sub $c5
    jp nc, $547f

    ld a, a
    call nz, $d0c5
    ld d, l
    rst $08
    db $d3
    ret


    call nc, $cf7f
    jp nc, $c47f

    jp nc, $d7c1

    adc h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, l
    ld a, a
    ld a, a
    ld a, a
    jp $cec1


    ld a, a
    call nz, Call_021_7fcf
    ld a, a
    add $d2
    push bc
    push bc
    call z, $55d9
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

Jump_021_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_021_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_021_7f7f:
Jump_021_7f7f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Jump_021_7f8c:
    nop
    nop

Call_021_7f8e:
Jump_021_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Jump_021_7fc1:
    nop
    nop

Jump_021_7fc3:
    nop

Call_021_7fc4:
Jump_021_7fc4:
    nop

Call_021_7fc5:
Jump_021_7fc5:
    nop

Call_021_7fc6:
    nop
    nop

Call_021_7fc8:
Jump_021_7fc8:
    nop
    nop
    nop

Call_021_7fcb:
Jump_021_7fcb:
    nop

Call_021_7fcc:
    nop

Jump_021_7fcd:
    nop

Jump_021_7fce:
    nop

Call_021_7fcf:
    nop

Call_021_7fd0:
Jump_021_7fd0:
    nop
    nop
    nop

Call_021_7fd3:
Jump_021_7fd3:
    nop

Call_021_7fd4:
Jump_021_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_021_7fd9:
Jump_021_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_021_7fe4:
Jump_021_7fe4:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
