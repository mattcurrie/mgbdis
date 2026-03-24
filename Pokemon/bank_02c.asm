; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $02c", ROMX[$4000], BANK[$2c]

    and c
    or a
    and c
    xor c
    or h
    ld a, a
    xor a
    or d
    and h
    and l
    or d
    or e
    ld a, a
    or h
    xor a
    ld c, [hl]
    and e
    xor a
    xor l
    xor l
    or l
    xor [hl]
    xor c
    and e
    and c
    or h
    and l
    add c
    ld d, b
    or b
    or d
    and l
    or b
    and c
    or d
    and l
    ld a, a
    or h
    xor a
    ld c, [hl]
    and e
    xor a
    xor l
    xor l
    or l
    xor [hl]
    xor c
    and e
    and c
    or h
    and l
    add c
    ld d, b
    or a
    xor b
    and l
    or h
    xor b
    and l
    or d
    ld a, a
    or h
    xor a
    ld a, a
    and l
    cp b
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld c, [hl]
    and h
    and l
    or b
    and l
    xor [hl]
    and h
    or e
    ld a, a
    xor a
    xor [hl]
    ld a, a
    or h
    xor b
    and l
    ld c, [hl]
    or e
    xor a
    and e
    xor c
    and c
    xor h
    ld a, a
    or e
    or h
    and c
    or h
    or l
    or e
    ld d, b
    or e
    or h
    xor a
    or b
    or e
    ld a, a
    and l
    cp b
    and e
    xor b
    and c
    xor [hl]
    and a
    xor c
    xor [hl]
    and a
    ld d, b
    or e
    xor a
    or d
    or d
    cp c
    add c
    and d
    or l
    or h
    ld a, a
    and l
    cp b
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld c, [hl]
    xor c
    or e
    ld a, a
    and e
    and c
    xor [hl]
    and e
    and l
    xor h
    xor h
    and l
    and h
    adc [hl]
    ld d, b
    or e
    xor a
    or d
    or d
    cp c
    add c
    and d
    or l
    or h
    ld a, a
    and l
    cp b
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld c, [hl]
    xor c
    or e
    ld a, a
    and e
    and c
    xor [hl]
    and e
    and l
    xor h
    xor h
    and l
    and h
    adc [hl]
    ld d, b
    and l
    cp b
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld a, a
    ld a, a
    and l
    xor [hl]
    and h
    or e
    add c
    ld d, b
    and e
    xor a
    xor [hl]
    or h
    xor c
    xor [hl]
    or l
    and l
    ld c, [hl]
    or e
    or h
    and c
    or d
    or h
    ld c, [hl]
    or e
    and l
    or h
    or l
    or b
    ld d, b
    or e
    or h
    and c
    or d
    or h
    ld c, [hl]
    or e
    and l
    or h
    or l
    or b
    ld d, b
    or h
    or d
    and c
    xor c
    xor [hl]
    xor c
    xor [hl]
    and a
    ld c, [hl]
    and a
    cp c
    xor l
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    xor [hl]
    and c
    xor l
    and l
    ld c, [hl]
    and d
    and c
    and h
    and a
    and l
    or e
    ld c, [hl]
    xor b
    and c
    xor [hl]
    and h
    and d
    xor a
    xor a
    xor e
    ld c, [hl]
    or h
    xor c
    xor l
    and l
    ld d, b
    and h
    xor c
    and c
    xor h
    xor a
    and a
    ld a, a
    or e
    or b
    and l
    and l
    and h
    ld c, [hl]
    ld a, a
    or c
    or l
    xor c
    and e
    xor e
    ld a, a
    ld a, a
    and e
    xor a
    xor l
    xor l
    xor a
    xor [hl]
    ld a, a
    or e
    xor h
    xor a
    or a
    ld d, b
    and [hl]
    xor c
    and a
    xor b
    or h
    xor c
    xor [hl]
    and a
    ld a, a
    and e
    and c
    or d
    or h
    xor a
    xor a
    xor [hl]
    ld c, [hl]
    ld a, a
    or [hl]
    xor c
    and l
    or a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    or b
    and c
    or e
    or e
    ld d, b
    or d
    or l
    xor h
    and l
    ld a, a
    xor a
    and [hl]
    ld a, a
    and e
    xor a
    xor l
    or b
    and l
    or h
    xor c
    or h
    xor c
    xor a
    xor [hl]
    ld c, [hl]
    ld a, a
    or d
    and l
    or b
    xor h
    and c
    and e
    and l
    ld a, a
    ld a, a
    and e
    xor c
    or d
    and e
    xor h
    and l
    ld d, b
    and l
    xor [hl]
    and h
    ld d, b
    or e
    or h
    and c
    or d
    or h
    ld d, b
    xor [hl]
    xor c
    and e
    xor e
    xor [hl]
    and c
    xor l
    and l
    sbc a
    ld d, b
    xor [hl]
    and c
    xor l
    and l
    sbc a
    ld d, b
    xor [hl]
    and c
    xor l
    and l
    ld d, b
    and l
    cp b
    xor c
    or h
    ld d, b
    or e
    or h
    and c
    or h
    or l
    or e
    ld c, [hl]
    or e
    xor a
    or d
    or h
    ld c, [hl]
    and e
    and c
    xor [hl]
    and e
    and l
    xor h
    ld d, b
    or h
    and c
    xor e
    and l
    and c
    or a
    and c
    cp c
    ld c, [hl]
    and e
    xor a
    xor [hl]
    or e
    xor c
    and a
    xor [hl]
    ld c, [hl]
    and c
    and d
    and c
    xor [hl]
    and h
    xor a
    xor [hl]
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    and d
    and c
    xor h
    xor h
    ld a, a
    ld a, a
    ld d, b
    xor [hl]
    and c
    xor l
    and l
    adc a
    ld c, [hl]
    xor l
    xor a
    xor [hl]
    and l
    cp c
    adc a
    ld c, [hl]
    or h
    xor c
    xor l
    and l
    adc a
    ld d, b
    and e
    xor a
    xor l
    xor l
    xor a
    xor [hl]
    ld d, b
    or e
    or h
    and c
    or h
    and l
    adc a
    ld d, b
    and c
    or h
    or h
    and c
    and e
    xor e
    ld c, [hl]
    or b
    or d
    xor a
    or h
    and l
    and e
    or h
    ld c, [hl]
    and c
    and a
    xor c
    xor h
    and l
    ld c, [hl]
    or e
    or b
    and l
    and e
    xor c
    and c
    xor h
    ld d, b
    or a
    xor c
    or e
    and h
    xor a
    xor l
    adc a
    ld c, [hl]
    and c
    and h
    and h
    xor c
    or h
    xor c
    or [hl]
    and l
    ld d, b
    and d
    xor c
    cp c
    and e
    xor h
    and l
    ld a, a
    sub c
    sub b
    sub b
    sub b
    sub b
    sub b
    sub b
    add h
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    cp c
    and l
    and l
    and d
    or l
    ld c, [hl]
    and d
    xor a
    xor a
    or e
    or h
    and l
    or d
    ld c, [hl]
    or h
    xor b
    or l
    xor [hl]
    and h
    and l
    or d
    ld c, [hl]
    xor b
    and l
    and c
    or [hl]
    cp c
    ld a, a
    or d
    and c
    xor c
    xor [hl]
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    or a
    xor b
    xor a
    or e
    and l
    ld a, a
    ld e, e
    ld d, b
    xor l
    and c
    or e
    and c
    and e
    xor b
    cp c
    add a
    or e
    ld a, a
    ld e, e
    ld d, b
    ld a, a
    ld a, a
    ld e, e
    ld d, b
    and c
    xor a
    and e
    xor b
    xor c
    and h
    and l
    or d
    add a
    or e
    ld a, a
    ld e, e
    ld d, b
    xor l
    xor a
    xor [hl]
    or e
    or h
    and l
    or d
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    and l
    cp b
    xor c
    or h
    ld d, b
    and d
    or d
    xor c
    xor [hl]
    and a
    ld a, a
    ld d, h
    ld c, [hl]
    and e
    xor a
    xor [hl]
    or e
    xor c
    and a
    xor [hl]
    ld a, a
    ld d, h
    ld c, [hl]
    or d
    and l
    xor h
    and l
    and c
    or e
    and l
    ld a, a
    ld d, h
    ld c, [hl]
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld a, a
    and c
    or d
    and l
    and c
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    or b
    or d
    and l
    or e
    and l
    xor [hl]
    or h
    db $e4
    and c
    or d
    and l
    and c
    ld d, b
    or e
    or h
    and c
    or h
    and l
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    sub e
    ld c, [hl]
    sub d
    ld c, [hl]
    sub c
    ld d, b
    ld d, b
    or a
    xor b
    xor c
    and e
    xor b
    ld a, a
    or e
    xor e
    xor c
    xor h
    xor h
    ld a, a
    ld c, [hl]
    xor c
    or e
    ld a, a
    xor c
    xor l
    xor c
    or h
    and c
    or h
    and l
    and h
    sbc a
    ld a, a
    ld d, b
    and d
    and l
    ld a, a
    and [hl]
    xor a
    or d
    and d
    xor c
    and h
    and h
    and l
    xor [hl]
    add c
    ld a, a
    ld d, b
    or h
    cp c
    or b
    and l
    ld d, b
    and [hl]
    xor c
    xor [hl]
    and h
    ld d, b
    and e
    and c
    or h
    and e
    xor b
    ld d, b
    and e
    xor a
    xor [hl]
    or h
    and l
    xor [hl]
    or h
    ld d, b
    xor c
    xor [hl]
    and [hl]
    xor a
    ld c, [hl]
    and e
    xor b
    xor c
    or d
    or b
    ld c, [hl]
    or b
    or d
    xor c
    xor [hl]
    or h
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    xor b
    and a
    or h
    ld a, a
    ld a, a
    sbc a
    sbc a
    sbc a
    xor l
    ld c, [hl]
    or a
    and a
    or h
    ld a, a
    ld a, a
    sbc a
    sbc a
    sbc a
    xor e
    and a
    ld d, b
    xor l
    xor a
    xor [hl]
    and l
    cp c
    ld d, b
    and e
    xor a
    xor c
    xor [hl]
    or e
    ld d, b
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, b
    and l
    cp b
    xor c
    or h
    ld d, b
    and e
    xor a
    xor c
    xor [hl]
    or e
    ld d, b
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, b
    xor [hl]
    and l
    or h
    ld c, [hl]
    and a
    cp c
    xor l
    ld c, [hl]
    or h
    or d
    and c
    xor c
    xor [hl]
    xor c
    xor [hl]
    and a
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    ld a, a
    or e
    xor h
    and l
    and l
    or b
    ld c, [hl]
    ld a, a
    or b
    xor a
    xor c
    or e
    xor a
    xor [hl]
    ld c, [hl]
    ld a, a
    or b
    and c
    or d
    and c
    xor h
    cp c
    or e
    xor c
    or e
    ld d, b
    ld a, a
    and d
    or l
    or d
    xor [hl]
    xor c
    xor [hl]
    and a
    ld c, [hl]
    ld a, a
    and [hl]
    or d
    xor a
    cp d
    and l
    xor [hl]
    ld c, [hl]
    ld a, a
    and l
    cp b
    xor c
    or h
    ld d, b
    and e
    xor a
    xor [hl]
    and a
    or d
    and c
    or h
    or l
    xor h
    and c
    or h
    and l
    add c
    ld d, b
    xor h
    and l
    or [hl]
    and l
    xor h
    ld c, [hl]
    or h
    cp c
    or b
    and l
    sub c
    ld c, [hl]
    or h
    cp c
    or b
    and l
    sub d
    ld d, b
    or h
    xor c
    xor l
    and l
    ld d, b
    xor l
    xor a
    xor [hl]
    and l
    cp c
    ld d, b
    ld a, a
    xor b
    xor a
    xor l
    and l
    ld d, b
    and [hl]
    xor h
    cp c
    ld a, a
    or h
    xor a
    ld d, b
    and l
    cp b
    xor c
    or e
    or h
    xor c
    xor [hl]
    and a
    ld a, a
    and c
    or d
    and l
    and c
    db $e4
    xor c
    or e
    xor [hl]
    add a
    or h
    ld a, a
    and e
    xor h
    and l
    and c
    or d
    ld a, a
    ld d, b
    and c
    or d
    and l
    and c
    ld a, a
    sub c
    ld c, [hl]
    and c
    or d
    and l
    and c
    ld a, a
    sub d
    ld c, [hl]
    and c
    or d
    and l
    and c
    ld a, a
    sub e
    ld c, [hl]
    and c
    or d
    and l
    and c
    ld a, a
    sub h
    ld c, [hl]
    and c
    or d
    and l
    and c
    ld a, a
    sub l
    ld c, [hl]
    and c
    or d
    and l
    and c
    ld a, a
    sub [hl]
    ld c, [hl]
    and c
    or d
    and l
    and c
    ld a, a
    sub a
    ld c, [hl]
    and c
    or d
    and l
    and c
    ld a, a
    sbc b
    ld d, b
    or b
    or d
    and l
    or e
    and l
    xor [hl]
    or h
    db $e4
    and c
    or d
    and l
    and c
    ld d, b
    xor l
    xor c
    xor [hl]
    and l
    or d
    and c
    xor h
    ld a, a
    or a
    and c
    or h
    and l
    or d
    ld a, a
    sub d
    sub b
    sub b
    add h
    ld c, [hl]
    or e
    xor a
    and h
    and c
    ld a, a
    or a
    and c
    or h
    and l
    or d
    ld a, a
    sub e
    sub b
    sub b
    add h
    ld c, [hl]
    xor d
    or l
    xor c
    and e
    and l
    ld a, a
    sub e
    sub l
    sub b
    add h
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    xor l
    and c
    xor [hl]
    or e
    xor c
    xor a
    xor [hl]
    ld a, a
    and d
    xor a
    or l
    xor [hl]
    and h
    or e
    ld a, a
    and l
    xor [hl]
    or h
    and l
    or d
    ld d, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, $a181
    db $d3
    ld a, a
    xor c
    add a
    call $c17f
    ld a, a
    rst $00
    push bc
    ld c, a
    adc $c9
    push de
    db $d3
    adc h
    ld a, a
    db $d3
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    pop bc
    call nc, Call_02c_5681
    ld a, a
    push de
    adc $c4
    push bc
    jp nc, $d4d3

    pop bc
    ld c, a
    adc $c4
    adc h
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
    and c
    ret z

    adc h
    ld a, a
    pop bc
    call nz, $c9cd
    jp nc, $c4c5

    add c
    ld a, a
    adc $c5
    sub $4f
    push bc
    jp nc, $c47f

    rst $08
    adc $c5
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    or b
    call z, $c555
    pop bc
    db $d3
    push bc
    ld a, a
    call z, $d4c5
    ld a, a
    call Call_02c_7fc5
    rst $00
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    pop bc
    call nz, $c9cd
    jp nc, $c4c5

    add c
    ld a, a
    adc $c5
    sub $4f
    push bc
    jp nc, $c47f

    rst $08
    adc $c5
    ld a, a
    pop bc
    rst $00
    pop bc
    ret


    adc $81
    ld a, a
    or b
    call z, $c555
    pop bc
    db $d3
    push bc
    ld a, a
    call z, $d4c5
    ld a, a
    call Call_02c_7fc5
    rst $00
    rst $08
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, e
    sbc d
    xor b
    rst $08
    rst $10
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $c54f
    adc $d4
    add c
    ld a, a
    and c
    call $87ce
    call nc, $a97f
    ld a, a
    pop bc
    ld a, a
    rst $00
    push bc
    ld d, l
    adc $c9
    push de
    db $d3
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    push bc
    call z, $8ccc
    ld a, a
    ret z

    rst $08
    rst $10
    ld a, a
    ret


    call nc, $cd7f
    pop bc
    reti


    ld c, a
    ld a, a
    jp nz, Jump_02c_7fc5

    call nc, $c1c8
    call nc, Call_02c_7f8e
    add $cf
    rst $08
    call z, Call_02c_7f81
    xor c
    ld d, l
    call nc, $d387
    ld a, a
    db $d3
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c67f
    rst $08
    jp nc, $d97f

    ld d, l
    rst $08
    push de
    jp nc, Jump_02c_547f

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    pop bc
    ret z

    add c
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    ld c, a
    ret


    call $ccd0
    reti


    ld a, a
    add $cf
    rst $08
    call z, $d3c9
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    pop bc
    ret z

    add c
    ld a, a
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    ld c, a
    ret


    call $ccd0
    reti


    ld a, a
    add $cf
    rst $08
    call z, $d3c9
    ret z

    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    xor b
    push bc
    jp nc, Jump_02c_7fc5

    xor c
    ld a, a
    jp $cdcf


    push bc
    add c
    ld a, a
    ld c, a
    xor c
    call nc, $d387
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    and l
    sub $c5
    jp nc, Jump_02c_55d9

    rst $08
    adc $c5
    ld a, a
    pop bc
    jp nc, Jump_02c_7fc5

    db $d3
    call nc, $cfd2
    adc $c7
    adc [hl]
    ld a, a
    or h
    ld d, l
    ret z

    ret


    db $d3
    ld a, a
    jp nc, $c9c1

    adc $c2
    rst $08
    rst $10
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld d, l
    ld a, a
    call $d3d5
    call nc, $c27f
    push bc
    ld a, a
    rst $00
    ret


    sub $c5
    adc $7f
    call nc, Call_02c_55cf
    ld a, a
    reti


    rst $08
    push de
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    xor b
    push bc
    jp nc, Jump_02c_7fc5

    xor c
    ld a, a
    jp $cdcf


    push bc
    add c
    ld c, a
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    and l
    sub $c5
    jp nc, $d955

    rst $08
    adc $c5
    ld a, a
    pop bc
    jp nc, Jump_02c_7fc5

    db $d3
    call nc, $cfd2
    adc $c7
    adc [hl]
    ld a, a
    ld d, l
    or h
    ret z

    ret


    db $d3
    ld a, a
    jp nc, $c9c1

    adc $c2
    rst $08
    rst $10
    ld a, a
    jp nz, $c4c1

    rst $00
    ld d, l
    push bc
    ld a, a
    call $d3d5
    call nc, $c27f
    push bc
    ld a, a
    rst $00
    ret


    sub $c5
    adc $7f
    call nc, $cf55
    ld a, a
    reti


    rst $08
    push de
    adc [hl]
    ld a, a
    ld e, b
    nop
    ld a, a
    and d
    push bc
    pop bc
    db $d3
    call nc, Call_02c_7f81
    ld e, b
    nop
    ld a, a
    and d
    push bc
    pop bc
    db $d3
    call nc, Call_02c_7f81
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
    call nz, $d6c9
    ret


    ld c, a
    call nz, Call_02c_7fc5
    db $d3
    rst $08
    call Call_02c_7fc5
    call nc, Call_02c_7fcf
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    ld d, l
    rst $08
    push de
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
    call nz, $d6c9
    ret


    ld c, a
    call nz, Call_02c_7fc5
    db $d3
    rst $08
    call Call_02c_7fc5
    call nc, Call_02c_7fcf
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, e
    sbc d
    or a
    ret z

    pop bc
    call nc, Call_02c_7f9f
    ld d, h
    ld a, a
    ld c, a
    or a
    ret z

    reti


    ld a, a
    ld d, h
    ld a, a
    jp nz, $c9d2

    adc $c7
    ld a, a
    call nc, $cfd7
    ld d, l
    ld a, a
    sbc a
    ld a, a
    xor c
    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_02c_7fc4
    jp nz, Jump_02c_7fc5

    db $d3
    ld d, l
    rst $08
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, $c97f
    add $7f
    reti


    rst $08
    push de
    ld a, a
    pop bc
    call z, Call_02c_55d3
    rst $08
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_02c_7fcf
    jp $d4c1


    jp $81c8


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

    ret


    db $d3
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    ld a, a
    ld c, a
    ret nc

    jp nc, $d4c5

    push bc
    adc $c4
    db $d3
    ld a, a
    call nc, Call_02c_7fcf
    call z, $cfcf
    bit 7, a
    ld d, l
    call nz, $d7cf
    adc $7f
    rst $08
    adc $81
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, e
    sbc d
    xor b
    ret


    adc h
    ld a, a
    xor b
    pop bc
    ld a, a
    ret z

    pop bc
    adc [hl]
    ld c, a
    ld a, a
    ld d, d
    add c
    ld a, a
    or a
    rst $08
    jp nc, Jump_02c_7fcb

    ret z

    pop bc
    jp nc, Jump_02c_55c4

    ld a, a
    pop bc
    add $d4
    push bc
    jp nc, $d47f

    ret z

    pop bc
    call nc, Call_02c_7f81
    reti


    rst $08
    push de
    jp nc, Jump_02c_7f55

    db $d3
    set 1, c
    call z, Call_02c_7fcc
    ret


    db $d3
    ld a, a
    add $c1
    jp nc, $d07f

    rst $08
    rst $08
    ld d, l
    jp nc, $d2c5

    call nc, $c1c8
    adc $7f
    call $cec9
    push bc
    ld a, a
    ld a, a
    ld d, l
    ld d, d
    add c
    and a
    rst $08
    ld a, a
    ret z

    rst $08
    call Call_02c_7fc5
    call nc, Call_02c_7fcf
    ld d, l
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    ld a, a
    call $d2cf
    push bc
    add c
    ld a, a
    and c
    ret z

    ld d, l
    adc h
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    ret z

    pop bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    ld a, a
    xor c
    add a
    call $cf7f
    ld c, a
    adc $cc
    reti


    ld a, a
    jp $d2c1


    push bc
    call z, $d3c5
    db $d3
    ld a, a
    db $d3
    call z, $c7c9
    ld d, l
    ret z

    call nc, $d9cc
    ld a, a
    db $d3
    set 2, l
    adc $cb
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    push bc
    call z, Call_02c_7fd0
    ld d, [hl]
    add c
    ld a, a
    xor c
    db $d3
    ld a, a
    call nc, $c1c8
    ld c, a
    call nc, $d47f
    jp nc, $ccd5

    reti


    ld a, a
    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    sbc a
    ld d, l
    ld a, a
    ld e, b
    nop
    ld a, a
    or a
    ret z

    push bc
    call z, Call_02c_7fd0
    ld d, [hl]
    add c
    xor c
    db $d3
    ld a, a
    call nc, $c1c8
    call nc, Call_02c_7f4f
    call nc, $d5d2
    call z, Call_02c_7fd9
    add $c5
    pop bc
    db $d3
    ret


    jp nz, $c5cc

    sbc a
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    ld d, e
    sbc d
    reti


    rst $08
    push de
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    ld c, a
    ld a, a
    ld d, [hl]
    xor h
    ret


    set 0, l
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d37f

    rst $08
    ld a, a
    call z, $c555
    sub $c5
    call z, $a97f
    call nc, $d387
    ld a, a
    add $c1
    jp nc, $d37f

    pop bc
    reti


    ld d, l
    ret


    adc $c7
    ld a, a
    call nc, Call_02c_7fcf
    jp nz, Jump_02c_7fc5

    ld d, [hl]
    ld a, a
    add c
    ld a, a
    nop
    ld a, a
    and c
    ret z

    ld a, a
    pop bc
    ret z

    add c
    ld a, a
    and h
    rst $08
    push bc
    db $d3
    adc $87
    call nc, $c97f
    ld c, a
    call nc, $c87f
    pop bc
    ret nc

    ret nc

    push bc
    adc $7f
    call nc, Call_02c_7fcf
    jp $c1c8


    call z, Call_02c_55cc
    push bc
    adc $c7
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $d3cf

    db $d3
    ld a, a
    ld a, a
    ld a, a
    rst $08
    ld d, l
    add $7f
    ld e, [hl]
    sbc a
    ld a, a
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    adc h
    ld a, a
    db $d3
    push bc
    push bc
    call $d47f
    rst $08
    ld a, a
    adc $4f
    push bc
    rst $00
    call z, $c3c5
    call nc, $c97f
    call nc, $d37f
    call z, $c7c9
    ret z

    call nc, Call_02c_55cc
    reti


    add c
    ld a, a
    and e
    rst $08
    adc $c6
    push bc
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    rst $00
    ld d, l
    jp nc, $d9c5

    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    pop bc
    call nz, $c9cd
    call nc, $c4c5
    ld d, l
    ld a, a
    jp nz, Jump_02c_7fd9

    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    ld a, a
    ld d, l
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $d2c5


    call nc, $c6c9
    ret


    jp $d4c1


    push bc
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $7f
    call $81c5
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, $d47f
    ret z

    ld d, l
    pop bc
    call nc, $c77f
    jp nc, $d9c5

    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    add $d2
    rst $08
    ld d, l
    call $b47f
    pop bc
    jp nc, $c8c3

    ret


    bit 7, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    ld a, a
    rst $10
    push bc
    pop bc
    jp nc, $d355

    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d9c5

    ld a, a
    jp nz, $c4c1

    ld d, l
    rst $00
    push bc
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_02c_557f

    ld d, h
    ld a, a
    call $d9c1
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_02c_7fc5
    db $d3
    call nc, $d255
    rst $08
    adc $c7
    add c
    ld a, a
    ld d, h
    ld a, a
    rst $10
    ret


    call nc, Call_02c_7fc8
    pop bc
    ld a, a
    ld d, l
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    db $d3
    set 1, c
    call z, Call_02c_7fcc
    push bc
    ld d, l
    sub $c5
    adc $7f
    adc $cf
    call nc, $d47f
    rst $08
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $c555
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, Call_02c_7fcc
    ld a, a
    pop bc
    call z, $cfd3
    ld d, l
    ld a, a
    jp $cec1


    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_02c_7fc5
    push de
    db $d3
    push bc
    add $d5
    ld d, l
    call z, Call_02c_7f81
    ld e, b
    nop
    ld a, a
    reti


    rst $08
    push de
    adc h
    ld a, a
    adc h
    ld a, a
    db $d3
    push bc
    push bc
    call $d47f
    rst $08
    ld a, a
    adc $4f
    push bc
    rst $00
    call z, $c3c5
    call nc, $c97f
    call nc, $d37f
    call z, $c7c9
    ret z

    call nc, Call_02c_55cc
    reti


    add c
    ld a, a
    and e
    rst $08
    adc $c6
    push bc
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    rst $00
    ld d, l
    jp nc, $d9c5

    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    pop bc
    call nz, $c9cd
    call nc, $c4c5
    ld d, l
    ld a, a
    jp nz, Jump_02c_7fd9

    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    ld a, a
    ld d, l
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp $d2c5


    call nc, $c6c9
    ret


    jp $d4c1


    push bc
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $7f
    call $81c5
    ld a, a
    ld d, l
    ld d, d
    ld a, a
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    call nz, $d47f
    ret z

    ld d, l
    pop bc
    call nc, $c77f
    jp nc, $d9c5

    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    add $d2
    rst $08
    ld d, l
    call $b47f
    pop bc
    jp nc, $c8c3

    ret


    bit 7, a
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    ld a, a
    rst $10
    push bc
    pop bc
    jp nc, $d355

    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    rst $00
    jp nc, $d9c5

    ld a, a
    jp nz, $c4c1

    ld d, l
    rst $00
    push bc
    ld a, a
    xor a
    adc $cc
    reti


    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_02c_557f

    ld d, h
    ld a, a
    call $d9c1
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_02c_7fc5
    db $d3
    call nc, $d255
    rst $08
    adc $c7
    add c
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $10
    ret


    call nc, Call_02c_7fc8
    pop bc
    ld d, l
    ld a, a
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    db $d3
    set 1, c
    call z, Call_02c_7fcc
    ld d, l
    ld d, h
    ld a, a
    ld a, a
    rst $10
    ret


    call nc, Call_02c_7fc8
    pop bc
    ld a, a
    call z, $c7c9
    ret z

    call nc, $ce55
    ret


    adc $c7
    ld a, a
    db $d3
    set 1, c
    call z, Call_02c_7fcc
    call nc, $c5c8
    ld a, a
    db $d3
    bit 2, l
    ret


    call z, Call_02c_7fcc
    ld a, a
    pop bc
    call z, $cfd3
    ld a, a
    jp $cec1


    ld a, a
    jp nz, $c3c5

    ld d, l
    rst $08
    call Call_02c_7fc5
    push de
    db $d3
    push bc
    add $d5
    call z, Call_02c_7f81
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_02c_567f
    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    xor c
    ld a, a
    rst $10
    ld c, a
    ret z

    rst $08
    ld a, a
    call z, $d3cf
    call nc, Call_02c_7f81
    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call $c555
    call nc, $cfc8
    call nz, $a781
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nz, Jump_02c_55cc

    push de
    push bc
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, Jump_02c_55cf

    rst $08
    add $7f
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $7f
    call $55c5
    add c
    ld a, a
    ld d, b
    ld de, $5006
    nop
    ld a, a
    xor b
    add a
    call Call_02c_567f
    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    xor c
    ld a, a
    rst $10
    ld c, a
    ret z

    rst $08
    ld a, a
    call z, $d3cf
    call nc, Call_02c_7f81
    xor [hl]
    rst $08
    ld a, a
    pop bc
    adc $d9
    ld a, a
    call $c555
    call nc, $cfc8
    call nz, $a781
    ret


    sub $c5
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp nz, Jump_02c_55cc

    push de
    push bc
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, Jump_02c_55cf

    rst $08
    add $7f
    ld a, a
    reti


    rst $08
    push de
    add a
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $7f
    call $55c5
    add c
    ld a, a
    ld d, b
    ld de, $5006
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    adc $cf
    add c
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d37f

    call nc, Call_02c_4fd2
    push bc
    adc $c7
    call nc, Call_02c_7fc8
    ret


    db $d3
    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    ld d, l
    call nc, Call_02c_7f81
    xor c
    call nc, $d387
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    pop bc
    ld a, a
    ld d, l
    call nc, $d5d2
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, $81cc
    ld a, a
    xor a
    res 0, c
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
    pop bc
    adc $7f
    rst $08
    jp nc, $cec1

    rst $00
    push bc
    ld d, l
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor a
    ret z

    adc h
    ld a, a
    adc $cf
    add c
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d37f

    call nc, Call_02c_4fd2
    push bc
    adc $c7
    call nc, Call_02c_7fc8
    ret


    db $d3
    ld a, a
    push bc
    ret c

    jp $ccc5


    call z, $cec5
    ld d, l
    call nc, Call_02c_7f81
    xor c
    call nc, $d387
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    pop bc
    ld a, a
    ld d, l
    call nc, $d5d2
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, $81cc
    ld a, a
    xor a
    res 0, c
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
    pop bc
    adc $7f
    rst $08
    jp nc, $cec1

    rst $00
    push bc
    ld d, l
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    add c
    ld a, a
    and h
    push bc
    add $c5
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
    and h
    push bc
    add $c5
    pop bc
    call nc, $c4c5
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    and h
    push bc
    add $c5
    pop bc
    call nc, $c4c5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld c, a
    ld a, a
    pop bc
    call z, $cbc9
    push bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld d, l
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, Jump_02c_7f81

    jp nz, $d4d5

    ld a, a
    ld d, l
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld d, l
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_02c_567f
    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ld d, l
    db $d3
    push bc
    push bc
    adc $7f
    call Call_02c_7fd9
    add $c1
    push de
    call z, $d3d4
    ld a, a
    ld a, a
    ret


    ld d, l
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $55
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    call z, Call_02c_7fc4
    jp nz, $c4c1

    rst $00
    push bc
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $cfcf

    add $7f
    reti


    rst $08
    push de
    ld d, l
    add a
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $7f
    call $81c5
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    ret


    call nc, Call_02c_7f81
    ld d, b
    ld de, $7f00
    and h
    push bc
    add $c5
    pop bc
    call nc, $c4c5
    ld a, a
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    ld c, a
    ld a, a
    pop bc
    call z, $cbc9
    push bc
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld d, l
    ld a, a
    jp $cec1


    add a
    call nc, $c27f
    push bc
    pop bc
    jp nc, Jump_02c_7f81

    jp nz, $d4d5

    ld a, a
    ld d, l
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    push bc
    ret c

    pop bc
    jp $ccd4


    reti


    ld d, l
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, Call_02c_567f
    add c
    ld a, a
    xor c
    add a
    sub $c5
    ld a, a
    ld d, l
    db $d3
    push bc
    push bc
    adc $7f
    call Call_02c_7fd9
    add $c1
    push de
    call z, $d3d4
    ld a, a
    ld a, a
    ret


    ld d, l
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $55
    add c
    ld a, a
    or h
    ret z

    ret


    db $d3
    ld a, a
    rst $00
    rst $08
    call z, Call_02c_7fc4
    jp nz, $c4c1

    rst $00
    push bc
    ld d, l
    ld a, a
    ret


    db $d3
    ld a, a
    call nc, $c5c8
    ld a, a
    ret nc

    jp nc, $cfcf

    add $7f
    reti


    rst $08
    push de
    ld d, l
    add a
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $7f
    call $81c5
    ld a, a
    and a
    ret


    sub $c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    ret


    call nc, Call_02c_7f81
    ld d, b
    ld de, $5006
    nop
    ld a, a
    ld d, e
    sbc d
    and c
    ret z

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    or h
    rst $08
    rst $08
    ld c, a
    ld a, a
    push bc
    ret c

    ret z

    pop bc
    push de
    db $d3
    call nc, $c4c5
    add c
    ld a, a
    or h
    rst $08
    rst $08
    ld a, a
    rst $10
    ld d, l
    push bc
    pop bc
    res 0, c
    ld a, a
    or h
    rst $08
    ld a, a
    add $cf
    db $d3
    call nc, $d2c5
    ld a, a
    ret


    call nc, Call_02c_7f55
    call $d2cf
    push bc
    ld a, a
    jp $d2c1


    push bc
    add $d5
    call z, $d9cc
    add c
    ld a, a
    ld d, l
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    jp nz, $c1c5

    db $d3
    call nc, Call_02c_7f81
    reti


    rst $08
    push de
    ld a, a
    call nz, $cf4f
    ld a, a
    rst $10
    pop bc
    adc $d4
    ld a, a
    call nc, Call_02c_7fcf
    call nz, $81cf
    ld a, a
    jp nz, $d4d5

    ld d, l
    ld a, a
    xor c
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld a, a
    db $d3
    ret z

    rst $08
    rst $10
    ld d, l
    ld a, a
    call Call_02c_7fd9
    call $d2c5
    jp $8ed9


    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, d
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    and c
    jp nc, Jump_02c_7fc5

    reti


    rst $08
    ld c, a
    push de
    ld a, a
    db $d3
    push bc
    pop bc
    db $d3
    ret


    jp $9fcb


    ld a, a
    reti


    rst $08
    push de
    add a
    call nz, Call_02c_557f
    jp nz, $d4c5

    call nc, $d2c5
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    call $d2cf
    push bc
    ld a, a
    ld d, l

Call_02c_4f7f:
Jump_02c_4f7f:
    push bc
    ret c

    push bc
    jp nc, $c9c3

    db $d3
    push bc
    db $d3
    ld a, a
    add c
    ld a, a
    ld e, b

Call_02c_4f8c:
    nop
    ld a, a
    xor b
    add a
    call Call_02c_567f
    add c
    and c
    call z, Call_02c_7fcc
    ret


    adc $7f
    pop bc
    call z, $cc4f
    adc h
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    and c
    call z, Call_02c_7fcc
    pop bc
    jp nc, Jump_02c_7fc5

    ld d, l
    add $cf
    db $d3
    call nc, $d2c5
    push bc
    call nz, $cf7f
    adc $cc
    reti


    ld a, a
    jp $d3c1


    ld d, l
    push de
    pop bc
    call z, $d9cc
    add c

Call_02c_4fc5:
Jump_02c_4fc5:
    ld a, a
    ld e, b
    nop

Call_02c_4fc8:
    ld a, a

Call_02c_4fc9:
    xor d
    push de
    db $d3
    call nc, $d47f

Call_02c_4fcf:
Jump_02c_4fcf:
    ret z

    ret


    db $d3

Call_02c_4fd2:
    ld a, a
    adc h
    ld a, a
    xor c
    ld a, a
    push bc
    sub $4f
    push bc
    adc $7f
    call z, $d3cf
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor d
    push de
    db $d3
    call nc, $d47f
    ret z

    ret


    db $d3
    ld a, a
    adc h
    ld a, a
    xor c
    ld a, a
    push bc
    sub $4f
    push bc
    adc $7f
    call z, $d3cf
    push bc
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
    add c
    ret


    db $d3
    ld a, a
    pop bc
    adc $7f
    ret


    adc $d4
    push bc
    ld c, a
    adc $d3
    ret


    sub $c5
    ld a, a
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $55
    add c
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
    ret z

    pop bc
    sub $55
    push bc
    ld a, a
    rst $10
    rst $08
    adc $81
    xor [hl]
    rst $08
    rst $10
    adc h
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    reti


    ld d, l
    rst $08
    push de
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    pop bc
    db $d3
    ld d, l
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cfcf

    add $81
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, Jump_02c_55cf

    rst $08
    add $81
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    add c
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cfcf

    ld c, a
    add $81
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
    ret z

    pop bc
    ld d, l
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $81
    xor [hl]
    rst $08
    rst $10
    adc h
    ld a, a
    rst $00
    ret


    sub $c5
    ld a, a
    ld d, l
    reti


    rst $08
    push de
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    jp nz, $c4c1

    rst $00
    push bc
    ld a, a
    pop bc
    ld d, l
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cfcf

    add $81
    pop bc
    db $d3
    ld a, a
    pop bc

Call_02c_50cc:
    ld a, a
    ret nc

    jp nc, $cf55

    rst $08
    add $81
    ld a, a
    ld d, b
    dec bc
    ld d, b
    nop

Call_02c_50d9:
    ld a, a
    xor b
    add a
    call Call_02c_567f
    add c
    xor b
    rst $08
    rst $10
    ld a, a
    jp $cdcf


    ret nc

    push bc
    ld c, a
    call nc, $cec5
    call nc, $a881
    ret


    add c
    jp nc, $c3c5

    push bc
    ret


    sub $c5
    ld a, a
    call nc, $c855
    ret


    db $d3
    ld a, a
    ret nc

    ret


    adc $cb
    ld a, a
    jp nz, $c4c1

    rst $00
    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    add a
    call Call_02c_567f
    add c
    xor b
    rst $08
    rst $10
    ld a, a
    jp $cdcf


    ret nc

    push bc
    ld c, a
    call nc, $cec5
    call nc, $a881
    ret


    add c
    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    ret nc

    jp nc, $cfcf

    ld d, l
    add $81
    ld a, a
    ld e, b
    nop
    ld a, a
    xor l
    reti


    ld a, a
    jp c, $c1c5

    call z, $c77f
    rst $08
    push bc
    db $d3
    ld a, a
    push de
    ret nc

    add c
    ld c, a
    xor a
    adc $cc
    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02c_7fc4
    jp nz, $c555

    ld a, a
    db $d3
    push de
    ret


    call nc, $c4c5
    call nc, $d5d2
    call z, Call_02c_7fd9
    call nc, $c5c8
    ld d, l
    ld a, a
    jp $c9d2


    call $cfd3
    adc $7f
    jp nz, $c4c1

    rst $00
    push bc
    add c
    ld a, a
    ld d, b
    ld de, $500d
    nop
    ld a, a
    xor l
    reti


    ld a, a
    jp c, $c1c5

    call z, $c77f
    rst $08
    push bc
    db $d3
    ld a, a
    push de
    ret nc

    add c
    ld c, a
    xor a
    adc $cc
    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02c_7fc4
    jp nz, $c555

    ld a, a
    db $d3
    push de
    ret


    call nc, $c4c5
    call nc, $d5d2
    call z, Call_02c_7fd9
    call nc, $c5c8
    ld d, l
    ld a, a
    jp $c9d2


    call $cfd3
    adc $7f
    jp nz, $c4c1

    rst $00
    push bc
    add c
    ld a, a
    ld d, b
    ld de, $500d
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    and c
    ret z

    add c
    ld a, a
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld c, a
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
    call nz, $c6c5
    push bc
    pop bc
    call nc, $c4c5
    add c
    ld c, a
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_02c_7fc5

    xor c
    ld a, a
    jp $cdcf


    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    xor b
    push bc
    jp nc, Jump_02c_7fc5

    xor c
    ld a, a
    jp $cdcf


    push bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    call $d2cf
    push bc
    ld a, a
    pop bc
    adc $4f
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, Jump_02c_7f81

    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    db $d3
    call nc, $c4d5
    reti


    ld a, a
    call $d2cf
    push bc
    ld a, a
    pop bc
    adc $4f
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, Jump_02c_7f81

    ld e, b
    nop
    ld a, a
    ld d, [hl]
    add c
    nop
    ld a, a
    ld d, [hl]
    add c
    nop
    ld a, a
    and c
    ret z

    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ret z

    rst $08
    call nc, Call_02c_7f81
    ld e, b
    nop
    ld a, a
    and c
    ret z

    adc h
    ld a, a
    xor b
    rst $08
    rst $10
    ld a, a
    ret z

    rst $08
    call nc, Call_02c_7f81
    ld e, b
    nop
    ld a, a
    rst $10
    push bc
    pop bc
    bit 7, a
    pop bc
    adc $c4
    ld a, a
    call z, $cdc9
    ret nc

    ld a, a
    ld c, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    rst $10
    push bc
    pop bc
    bit 7, a
    pop bc
    adc $c4
    ld a, a
    call z, $cdc9
    ret nc

    ld a, a
    ld c, a
    ld d, [hl]
    ld e, b
    nop
    ld a, a
    xor b
    pop bc
    adc h
    ld a, a
    ret z

    pop bc
    add c
    rst $10
    ret


    adc $8c
    ld a, a
    rst $10
    ret


    adc $8c
    ld c, a
    ld a, a
    rst $10
    ret


    adc $81
    or h
    rst $08
    ld a, a
    jp nz, Jump_02c_7fc5

    call nz, $c6c5
    push bc
    pop bc
    call nc, $c555
    call nz, $c27f
    reti


    ld a, a
    ld d, d
    ld a, a
    ld a, a
    ret


    db $d3
    adc $87
    ld d, l
    call nc, $cd7f
    push bc
    add c
    ld d, h
    ld a, a
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    rst $00
    push bc
    ld d, l
    adc $c9
    push de
    db $d3
    pop bc
    db $d3
    ld a, a
    pop bc
    adc $7f
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $55
    call nc, $cf7f
    add $7f
    ld d, e
    push de
    adc $d4
    ret


    call z, $ce7f
    ld d, l
    rst $08
    rst $10
    adc h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call nc, $c5c8
    ld d, l
    ld a, a
    jp nz, $d3c5

    call nc, $b481
    rst $08
    ld a, a
    ret nc

    jp nc, $c9c1

    db $d3
    push bc
    ld a, a
    ret z

    ld d, l
    ret


    call $c17f
    adc $c4
    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    ret z

    ret


    call $a881
    pop bc
    ld d, l
    adc h
    ret z

    pop bc
    adc h
    ret z

    pop bc
    add c
    ld a, a
    ld e, b
    nop
    ld a, a
    ld d, [hl]
    ld a, a
    add $cf
    rst $08
    call z, $d281
    push bc
    pop bc
    call z, $d9cc
    ld a, a
    push bc
    ld c, a
    adc $c4
    sbc a
    xor c
    add a
    call $c67f
    ret


    adc $c1
    call z, $d9cc
    ld a, a
    call z, Call_02c_55cf
    db $d3
    call nc, $d47f
    ret z

    rst $08
    push de
    rst $00
    ret z

    call Call_02c_7fd9
    ret z

    pop bc
    sub $c9
    adc $55
    rst $00
    ld a, a
    call nz, $cecf
    push bc
    ld a, a
    call Call_02c_7fd9
    jp nz, $d3c5

    call nc, $a881
    push bc
    ld d, l
    ld a, a
    ret z

    pop bc
    call nz, $c17f
    ld a, a
    ret z

    pop bc
    jp nc, Jump_02c_7fc4

    call nc, $cdc9
    push bc
    ld a, a
    ld d, l
    db $d3
    call nc, $cec1
    call nz, $cec9
    rst $00
    call nc, $c5c8
    ld a, a
    db $d3
    push de
    call $c9cd
    ld d, l
    call nc, $cf7f
    add $7f
    pop bc
    call z, $c9cc
    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, l
    ld d, h
    ld a, a
    add c
    xor [hl]
    rst $08
    rst $10
    ld a, a
    ld d, [hl]
    add c
    xor a
    push de
    jp nc, $d47f

    ld d, l
    ret


    call $d3c5
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    rst $00
    rst $08
    adc $c5
    sbc a
    add c
    ld d, l
    ld d, [hl]
    ld a, a
    xor [hl]
    rst $08
    call nc, $c17f
    call nc, $c17f
    call z, $81cc
    ld a, a
    ld e, b
    rst $10
    ret z

    ret


    call nc, $50c5
    xor [hl]
    rst $08
    adc [hl]
    sub c
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $50
    xor [hl]
    rst $08
    adc [hl]
    sub d
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    push bc
    sub $c5
    jp nc, $d2c7

    push bc
    push bc
    adc $e4
    rst $10
    rst $08
    rst $08
    call nz, $50d3
    and h
    ret


    rst $00
    push de
    call nz, $d2c5
    add a
    db $d3
    db $e4
    jp $d6c1


    push bc
    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub e
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    call $cfcf
    adc $e4
    call $d5cf
    adc $d4
    pop bc
    ret


    adc $50
    xor [hl]
    rst $08
    adc [hl]
    sub h
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    call z, $c7c9
    ret z

    call nc, $c2e4
    call z, $c5d5
    ld a, a
    jp $d4c9


    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub d
    sub h
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc

Call_02c_547f:
Jump_02c_547f:
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub d
    sub l
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    call nc, $c5c8
    ld a, a
    ret z

    rst $08
    call $e4c5
    rst $08
    add $7f
    jp $d0c1


    push bc
    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub l
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub [hl]
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    call nz, $c9d2
    push bc
    call nz, $cce4
    push bc
    pop bc
    add $7f
    jp $d4c9


    reti


    ld d, b
    db $d3
    pop bc
    adc $c4
    push de
    ld a, a
    and c
    adc $ce
    push de
    db $e4
    db $d3
    ret z

    ret


    ret nc

    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sbc c
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10

Jump_02c_54e4:
    pop bc
    reti


    ld d, b
    call nc, $ced5
    adc $c5
    call z, $cf7f
    add $e4
    jp nc, $c3cf

    bit 7, a
    ret z

    ret


    call z, Call_02c_50cc
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub b

Jump_02c_5500:
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    pop bc
    db $d3
    call nc, $d2c5
    ld d, b
    call nc, $d7cf
    push bc
    jp nc, Jump_02c_54e4

    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sbc b
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub a
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    db $e4
    jp $cccf


    rst $08
    jp nc, $c37f

    ret


    call nc, Call_02c_50d9
    set 0, l
    jp nc, $c9d2

    pop bc
    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub c
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub d
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub e
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub h
    db $e4
    ret z

    ret


Call_02c_557f:
Jump_02c_557f:
    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub l
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub [hl]
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc

Jump_02c_559f:
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sub a
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub c
    sbc b
    db $e4
    ret z

    ret


    rst $00
    ret z

    rst $10
    pop bc
    reti


    ld d, b
    ret nc

    ret


    adc $cb

Call_02c_55c1:
    ld d, b
    ret z

    push de

Jump_02c_55c4:
    adc $d4
    ld a, a
    pop bc

Call_02c_55c8:
    jp nc, $c1c5

Jump_02c_55cb:
    ld d, b

Call_02c_55cc:
Jump_02c_55cc:
    xor [hl]
    rst $08
    adc [hl]

Call_02c_55cf:
Jump_02c_55cf:
    sub c
    sbc c
    db $e4

Call_02c_55d2:
    rst $10

Call_02c_55d3:
    pop bc

Jump_02c_55d4:
    call nc, $d2c5
    rst $10
    pop bc

Jump_02c_55d9:
    reti


    ld d, b
    call nc, $c9d7
    adc $e4
    ret


    db $d3
    call z, $cec1
    call nz, $ae50
    rst $08
    adc [hl]
    sub d
    sub b
    db $e4
    rst $10
    pop bc
    call nc, $d2c5
    rst $10
    pop bc
    reti


    ld d, b
    jp nc, $c4c5

    ld a, a
    call z, $d4cf
    push de
    db $d3
    db $e4
    ret


    db $d3
    call z, $cec1
    call nz, $ae50
    rst $08
    adc [hl]
    sub d
    sub c
    db $e4
    rst $10
    pop bc
    call nc, $d2c5
    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub d
    sub d
    db $e4
    rst $10
    pop bc
    call nc, $d2c5
    rst $10
    pop bc
    reti


    ld d, b
    xor [hl]
    rst $08
    adc [hl]
    sub d
    sub e
    db $e4
    rst $10
    pop bc
    call nc, $d2c5
    rst $10
    pop bc
    reti


    ld d, b
    jp nc, $c1cf

    call nz, $d47f
    rst $08
    db $e4
    jp $c1c8


    call $50d0
    pop de
    push de
    pop bc
    jp nc, $dad4

    ld d, b
    ret nc

    rst $08
    rst $10
    push bc
    jp nc, $d3e4

    call nc, $d4c1
    ret


    rst $08
    adc $50
    and d
    and l
    and c
    or h
    ld d, b
    and d
    and c
    or d
    and l
    adc l
    xor b
    and c
    xor [hl]
    and h
    and l
    and h
    ld a, a
    and e
    or l
    or h
    ld d, b
    or e
    xor h
    and c
    or b
    ld d, b
    and e
    xor h
    and l
    and c
    or d
    ld a, a
    and d
    xor a
    cp b
    xor c
    xor [hl]
    and a
    ld d, b
    xor b

Call_02c_567f:
    and l
    and c

Call_02c_5681:
    or [hl]
    cp c
    ld a, a
    and d
    xor a
    cp b
    xor c
    xor [hl]
    and a
    ld d, b
    or b
    xor h
    and c
    cp c
    ld a, a
    or h
    xor b
    and l
    ld a, a
    xor h
    or l
    or h
    and l
    ld d, b
    and [hl]
    xor h
    and c
    xor l
    and l
    ld a, a
    and d
    xor a
    cp b
    xor c
    xor [hl]
    and a
    ld d, b
    and [hl]
    or d
    and l
    and l
    cp d
    and l
    ld a, a
    and d
    xor a
    cp b
    xor c
    xor [hl]
    and a
    ld d, b
    or h
    xor b
    or l
    xor [hl]
    and h
    and l
    or d
    ld a, a
    and d
    xor a
    cp b
    xor c
    xor [hl]
    and a
    ld d, b
    or e
    and e
    or d
    and c
    or h
    and e
    xor b
    ld d, b
    or e
    and l
    or b
    and c
    or d
    and c
    or h
    and l
    ld d, b
    and a
    or l
    xor c
    xor h
    xor h
    xor a
    or h
    xor c
    xor [hl]
    and l
    ld d, b
    and e
    or d
    and c
    and e
    xor e
    ld d, b
    or e
    or a
    xor a
    or d
    and h
    or b
    xor h
    and c
    cp c
    ld d, b
    or e
    or a
    xor a
    or d
    and h
    ld a, a
    or e
    xor e
    xor c
    xor h
    xor h
    ld d, b
    and d
    xor h
    xor a
    or a
    ld d, b
    and e
    or l
    or h
    ld a, a
    or a
    xor c
    or h
    xor b
    ld a, a
    or a
    xor c
    xor [hl]
    and a
    ld d, b
    and l
    cp b
    xor c
    xor h
    and l
    ld d, b
    and [hl]
    xor h
    cp c
    ld d, b
    and d
    xor c
    xor [hl]
    and h
    ld d, b
    or a
    or d
    and l
    or e
    or h
    xor h
    ld d, b
    or d
    and c
    or h
    or h
    and c
    xor [hl]
    ld a, a
    or a
    xor b
    xor c
    or b
    ld d, b
    or h
    or d
    and l
    and c
    and h
    ld d, b
    or h
    or a
    xor c
    and e
    and l
    ld a, a
    xor e
    xor c
    and e
    xor e
    ld d, b
    xor b
    and l
    and c
    or d
    cp c
    ld a, a
    xor e
    xor c
    and e
    xor e
    ld d, b
    xor h
    and l
    and c
    or b
    ld a, a
    xor e
    xor c
    and e
    xor e
    ld d, b
    or d
    and l
    or [hl]
    xor a
    xor h
    or [hl]
    and l
    ld a, a
    xor e
    xor c
    and e
    xor e
    ld d, b
    or e
    or b
    or d
    xor c
    xor [hl]
    xor e
    xor h
    and l
    ld a, a
    or e
    and c
    xor [hl]
    and h
    ld d, b
    or d
    and c
    xor l
    ld a, a
    or a
    xor c
    or h
    xor b
    ld a, a
    xor b
    and l
    and c
    and h
    ld d, b

Call_02c_577f:
    or d
    and c
    xor l
    ld a, a
    or a
    xor c
    or h
    xor b
    ld a, a
    xor b
    xor a
    or d
    xor [hl]
    ld d, b
    and [hl]

Call_02c_578e:
    xor h
    xor a
    or a
    and l
    or d
    or e
    ld a, a
    and d
    xor h
    xor a
    xor a
    xor l
    or e
    ld d, b
    and c
    xor [hl]
    and a
    xor h
    and l
    ld a, a
    and h
    or d
    xor c
    xor h
    xor h
    xor a
    or d
    ld d, b
    and a
    xor a
    ld a, a
    and c
    xor h
    xor h
    ld a, a
    xor a
    or l
    or h
    ld d, b
    and e
    or d
    or l
    or e
    xor b
    ld d, b
    or e
    xor a
    or a
    xor c
    xor [hl]
    and a
    ld d, b
    or d
    and c
    xor c
    and h
    ld d, b
    and c
    and e
    or h
    ld a, a
    or d
    and l
    and e
    xor e
    xor h
    and l
    or e
    or e
    xor h
    cp c
    ld d, b
    and l
    xor l
    and d
    or d
    and c
    and e
    and l
    ld d, b
    or a
    and c
    and a
    ld a, a
    or h
    and c
    xor c
    xor h
    ld d, b
    or b
    xor a
    xor c
    or e
    xor a
    xor [hl]
    ld a, a
    xor [hl]
    and l
    and l
    and h
    xor h
    and l
    ld d, b
    or h
    or a
    xor c
    and e
    and l
    ld a, a
    xor [hl]
    and l
    and l
    and h
    xor h
    and l
    ld d, b
    xor l
    xor c
    or e
    or e
    xor c
    xor h
    and l
    ld d, b
    and a
    and c
    cp d
    and l
    ld d, b
    and d
    xor c
    or h
    and l
    ld d, b
    and e
    xor b
    xor c
    or d
    or b
    or e
    ld d, b
    and d
    and c
    or d
    xor e
    or e
    ld d, b
    or e
    xor c
    xor [hl]
    and a
    ld d, b
    or l
    xor h
    or h
    or d
    and c
    or e
    xor a
    xor [hl]
    xor c
    and e
    ld d, b
    and l
    cp b
    or b
    xor h
    xor a
    or e
    xor c
    xor a
    xor [hl]
    ld d, b
    and d
    or l
    xor [hl]
    and h
    xor h
    and l
    ld d, b
    xor l
    xor a
    xor [hl]
    or e
    or h
    and l
    or d
    ld a, a
    xor d
    or l
    xor c
    and e
    and l
    ld d, b
    or e
    or b
    and c
    or d
    xor e
    or e
    ld a, a
    or e
    or b
    xor h
    and c
    or e
    xor b
    ld d, b
    and l
    xor l
    xor c
    or h
    ld a, a
    or e
    xor l
    xor a
    xor e
    and l
    ld d, b
    or a
    xor b
    xor c
    or h
    and l
    ld a, a
    and [hl]
    xor a
    and a
    ld d, b
    or e
    or c
    or l
    xor c
    or d
    or h
    ld d, b
    or a
    and c
    or h
    and l
    or d
    ld a, a
    or b
    or l
    xor l
    or b
    ld d, b
    or e
    or l
    or d
    and [hl]
    ld d, b
    and [hl]
    or d
    and l
    and l

Call_02c_588e:
    cp d
    and l
    ld a, a
    and d
    or l
    xor [hl]
    and e
    xor b
    ld d, b
    or e
    xor [hl]
    xor a
    or a
    or e
    or h
    xor a
    or d
    xor l
    ld d, b
    and e
    xor a
    xor h
    xor a
    or d
    ld a, a
    and d
    or l
    xor [hl]
    and e
    xor b
    ld d, b
    or h
    or d
    and c
    xor [hl]
    or e
    or b
    and c
    or d
    and l
    xor [hl]
    or h
    ld a, a
    or d
    and c
    cp c
    ld d, b
    and c
    or l
    or d
    xor a
    or d
    and c
    ld a, a
    and d
    or l
    xor [hl]
    and e
    xor b
    ld d, b
    and h
    and l
    or e
    or h
    or d
    xor a
    cp c
    ld a, a
    and d
    or l
    xor [hl]
    and e
    xor b
    ld d, b
    or b
    and l
    and e
    xor e
    ld d, b
    and d
    and l
    and c
    xor e
    ld d, b
    xor b
    and l
    xor h
    xor h
    ld a, a
    or a
    xor b
    and l
    and l
    xor h
    ld d, b
    and d
    and l
    and c
    or h
    ld d, b
    and [hl]
    xor c
    and a
    xor b
    or h
    ld a, a
    and d
    and c
    and e
    xor e
    ld d, b
    or h
    xor b
    or d
    xor a
    or a
    ld a, a
    or h
    xor b
    and l
    ld a, a
    and l
    and c
    or d
    or h
    xor b
    ld d, b
    or e
    or h
    or d
    and c
    xor [hl]
    and a
    and l
    ld a, a
    and [hl]
    xor a
    or d
    and e
    and l
    ld d, b
    and c
    and d
    or e
    xor a
    or d
    and d
    ld d, b
    and l
    xor h
    and l
    and e
    or h
    or d
    xor c
    and e
    ld a, a
    or b
    xor a
    or a
    and l
    or d
    ld d, b
    or b
    and c
    or d
    and c
    or e
    xor c
    or h
    and l
    ld d, b
    and [hl]
    xor h
    cp c
    xor c
    xor [hl]
    and a
    ld a, a
    and d
    xor c
    or d
    and h
    ld d, b
    xor h
    and l
    and c
    and [hl]
    adc l
    and e
    or l
    or h
    ld a, a
    xor l
    and c
    and e
    xor b
    xor c
    xor [hl]
    and l
    ld d, b
    or e
    xor a
    xor h
    and c
    or d
    ld a, a
    and l
    xor [hl]
    and l
    or d
    and a
    cp c
    ld d, b
    or b
    rst $08
    ret


    db $d3
    rst $08
    adc $cf
    push de
    db $d3
    or b
    rst $08
    rst $10
    call nz, $d2c5
    ld d, b
    or b
    pop bc
    jp nc, $ccc1

    reti


    jp c, $c4c5

    or b
    rst $08
    rst $10
    call nz, $d2c5
    ld d, b
    or e
    xor h
    and l
    and l
    or b
    ld a, a
    or b
    xor a
    or a
    and h
    and l
    or d
    ld d, b
    or b
    and l
    or h
    and c
    xor h
    ld a, a
    and h
    and c
    xor [hl]
    and e
    and l
    ld d, b
    or e
    or b
    xor c
    xor [hl]
    ld a, a
    or e
    xor c
    xor h
    xor e
    ld d, b
    and h
    or d
    and c
    and a
    xor a
    xor [hl]
    add a
    or e
    ld a, a
    and c
    xor [hl]
    and a
    and l
    or d
    ld d, b
    and [hl]
    xor c
    or d
    and l
    ld a, a
    or a
    xor b
    xor c
    or d
    xor h
    or b
    xor a
    xor a
    xor h
    ld d, b
    and l
    xor h
    and l
    and e
    or h
    or d
    xor a
    xor [hl]
    ld a, a
    or e
    xor b
    xor a
    and e
    xor e
    ld d, b
    sub c
    sub b
    xor l
    xor c
    xor h
    xor h
    xor c
    xor a
    xor [hl]
    ld a, a
    or [hl]
    xor a
    xor h
    or h
    ld d, b
    and l
    xor h
    and l
    and e
    or h
    or d
    xor a
    xor l
    and c
    and a
    xor [hl]
    and l
    or h
    xor c
    and e
    ld d, b
    or h
    xor b
    or l
    xor [hl]
    and h
    and l
    or d
    ld d, b
    or h
    xor b
    or d
    xor a
    or a
    ld a, a
    or d
    xor a
    and e
    xor e
    ld d, b
    and l
    and c
    or d
    or h
    xor b
    or c
    or l
    and c
    xor e
    and l
    ld d, b
    and l
    and c
    or d
    or h
    xor b
    or d
    xor c
    and [hl]
    or h
    ld d, b
    and h
    xor c
    and a
    ld a, a
    xor b
    xor a
    xor h
    and l
    ld d, b
    or e
    or h
    or d
    and l
    and c
    xor l
    ld d, b
    or a
    xor c
    xor h
    xor h
    or b
    xor a
    or a
    and l
    or d
    ld d, b
    xor l
    xor a
    or h
    xor c
    and [hl]
    ld d, b
    xor b
    cp c
    or b
    xor [hl]
    xor a
    or h
    xor c
    or e
    xor l
    ld d, b
    cp c
    xor a
    and a
    and c
    ld d, b
    or d
    xor a
    or h
    and c
    or h
    and l
    ld d, b
    or e
    xor b
    and c
    or d
    or b
    xor [hl]
    and l
    or e
    or e
    ld d, b
    and [hl]
    or l
    or d
    cp c
    ld d, b
    or h
    or d
    and c
    xor [hl]
    or e
    xor l
    xor c
    or h
    ld d, b
    xor h
    and l
    and c
    and h
    and l
    or d
    ld d, b
    xor c
    xor l
    xor c
    or h
    and c
    or h
    and l
    ld d, b
    xor [hl]
    xor a
    xor c
    or e
    and l
    ld d, b
    and c
    or b
    or b
    xor a
    or d
    or h
    ld d, b
    or d
    and l
    or b
    or d
    xor a
    and h
    or l
    and e
    or h
    xor c
    xor a
    xor [hl]
    ld d, b
    and d
    and l
    and e
    xor a
    xor l
    and l
    ld a, a
    xor b
    and c
    or d
    and h
    ld d, b
    and d
    and l
    and e
    xor a
    xor l
    and l
    ld a, a
    or e
    xor l
    and c
    xor h
    xor h
    ld d, b
    or e
    xor l
    xor a
    xor e
    and l
    ld a, a
    or e
    and e
    or d
    and l
    and l
    xor [hl]
    ld d, b
    or e
    or l
    or e
    or b
    and l
    and e
    or h
    ld a, a
    and [hl]
    xor h
    and c
    xor l
    and l
    ld d, b
    xor b
    xor c
    and h
    and l
    ld d, b
    and d
    and l
    and e
    xor a
    xor l
    and l
    ld a, a
    or d
    xor a
    or l
    xor [hl]
    and h
    ld d, b
    xor b
    xor c
    xor [hl]
    and h
    and l
    or d
    ld d, b
    xor h
    xor c
    and a
    xor b
    or h
    ld a, a
    or a
    and c
    xor h
    xor h
    ld d, b
    and d
    xor h
    and c
    and e
    xor e
    ld a, a
    and [hl]
    xor a
    and a
    ld d, b
    or d
    and l
    and [hl]
    xor h
    and l
    and e
    or h
    xor a
    or d
    ld d, b
    or d
    and l
    or e
    or h
    ld d, b
    or h
    xor a
    xor h
    and l
    or d
    and c
    xor [hl]
    and e
    and l
    ld d, b
    or a
    xor b
    xor c
    or e
    or h
    xor h
    and l
    ld d, b
    or b
    and c
    or d
    or d
    xor a
    or h
    ld d, b
    or e
    and l
    xor h
    and [hl]
    adc l
    and l
    cp b
    or b
    xor h
    xor a
    and h
    and l
    ld d, b
    and l
    and a
    and a
    adc l
    and d
    xor a
    xor l
    and d
    ld d, b
    xor h
    xor c
    and e
    xor e
    ld d, b
    or e
    xor l
    xor a
    xor e
    and l
    ld d, b
    and e
    xor h
    and c
    cp c
    ld a, a
    and c
    or h
    or h
    and c
    and e
    xor e
    ld d, b
    and d
    xor a
    xor [hl]
    and l
    ld a, a
    or e
    or h
    xor c
    and e
    xor e
    ld d, b
    and e
    xor b
    and c
    or d
    and c
    and e
    or h
    and l
    or d
    ld a, a
    and [hl]
    xor c
    or d
    and l
    ld d, b
    or d
    and c
    or b
    xor c
    and h
    ld a, a
    or e
    or h
    or d
    and l
    and c
    xor l
    ld d, b
    and h
    and l
    or [hl]
    xor c
    or e
    xor c
    xor a
    xor [hl]
    ld d, b
    or e
    or b
    and l
    and l
    and h
    ld a, a
    or e
    or h
    and c
    or d
    ld d, b
    or d
    xor a
    and e
    xor e
    and l
    or h
    ld d, b
    or h
    xor b
    xor a
    or d
    xor [hl]
    ld a, a
    or e
    xor b
    and l
    xor h
    xor h
    ld d, b
    and a
    and l
    or h
    ld a, a
    and l
    xor [hl]
    or h
    and c
    xor [hl]
    and a
    xor h
    and l
    and h
    ld d, b
    and e
    xor b
    and l
    and c
    or h
    ld d, b
    or h
    xor b
    or d
    xor a
    or a
    ld a, a
    or e
    or b
    xor a
    xor a
    xor [hl]
    ld d, b
    or e
    or b
    and c
    or a
    xor [hl]
    ld d, b
    xor l
    and c
    or d
    or e
    ld d, b
    or b
    xor a
    or a
    and l
    or d
    ld d, b
    and h
    or d
    and l
    and c
    xor l
    ld d, b
    or b
    xor a
    xor c
    or e
    xor a
    xor [hl]
    xor a
    or l
    or e
    ld a, a
    and a
    and c
    or e
    ld d, b
    or h
    xor b
    or d
    xor a
    or a
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    or e
    or l
    and e
    xor e
    ld a, a
    and d
    xor h
    xor a
    xor a
    and h
    ld d, b
    xor e
    xor c
    or e
    or e
    ld d, b
    xor l
    and c
    and a
    xor c
    and e
    and c
    xor h
    ld a, a
    and d
    xor c
    or d
    and h
    ld d, b
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld a, a
    and d
    xor a
    and h
    cp c
    ld d, b
    and [hl]
    xor a
    and c
    xor l
    ld d, b
    xor b
    and l
    and c
    and d
    cp c
    ld a, a
    and c
    or h
    or h
    and c
    and e
    xor e
    ld d, b
    or e
    or b
    xor a
    or d
    and l
    ld d, b
    and [hl]
    xor h
    and c
    or e
    xor b
    xor h
    xor c
    and a
    xor b
    or h
    ld d, b
    or e
    or b
    xor c
    or d
    xor c
    or h
    ld a, a
    or a
    and c
    or [hl]
    and l
    ld d, b
    or e
    or b
    xor h
    and c
    or e
    xor b
    ld d, b
    and h
    xor c
    or e
    or e
    xor a
    xor h
    or [hl]
    and l
    ld d, b
    and e
    or d
    and c
    and d
    ld a, a
    xor b
    and c
    xor l
    xor l
    and l
    or d
    ld d, b
    and a
    or d
    and l
    and c
    or h
    ld a, a
    and l
    cp b
    or b
    xor h
    xor a
    or e
    xor c
    xor a
    xor [hl]
    ld d, b
    or d
    or l
    xor l
    xor l
    and c
    and a
    and l
    ld d, b
    and d
    xor a
    xor [hl]
    and l
    ld a, a
    xor b
    and c
    or d
    or b
    xor a
    xor a
    xor [hl]
    ld d, b
    or e
    xor h
    and l
    and l
    or b
    ld d, b
    or d
    xor a
    and e
    xor e
    ld a, a
    and e
    xor a
    xor h
    xor h
    and c
    or b
    or e
    and l
    ld d, b
    or e
    xor b
    and c
    or d
    or b
    ld a, a
    or h
    and l
    and l
    or h
    xor b
    ld d, b
    and l
    and h
    and a
    and l
    or e
    ld d, b
    xor l
    and c
    or h
    and l
    or d
    xor c
    and c
    xor h
    or e
    ld d, b
    or h
    or d
    cp c
    ld a, a
    and c
    or h
    or h
    and c
    and e
    xor e
    ld d, b
    xor l
    and c
    xor h
    xor c
    and e
    xor c
    xor a
    or l
    or e
    ld a, a
    or h
    and l
    and l
    or h
    xor b
    ld d, b
    or e
    or b
    xor h
    xor c
    or h
    ld d, b
    or e
    or l
    or b
    and l
    or d
    or e
    and l
    and h
    and l
    ld d, b
    or e
    xor e
    cp c
    or d
    xor a
    and e
    xor e
    and l
    or h
    ld d, b
    or h
    xor b
    or l
    xor [hl]
    and h
    and l
    or d
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    or e
    xor b
    and l
    xor h
    xor h
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and d
    or l
    and h
    and h
    xor b
    and c
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and l
    and c
    and a
    xor h
    and l
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and [hl]
    or d
    and l
    and l
    cp d
    and l
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and [hl]
    or d
    xor c
    and l
    xor [hl]
    and h
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    or d
    xor a
    or e
    and l
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and [hl]
    xor c
    or d
    and l
    adc l
    and d
    and c
    xor h
    xor h
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and a
    xor a
    xor h
    and h
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and l
    and a
    and a
    ld d, b
    cp c
    xor a
    or l
    xor [hl]
    and a
    ld a, a
    and d
    xor c
    or d
    and h
    ld d, b
    and d
    or d
    xor a
    xor [hl]
    cp d
    and l
    ld d, b
    or e
    xor c
    xor h
    or [hl]
    and l
    or d
    ld d, b
    and a
    xor a
    xor h
    and h
    ld d, b
    xor h
    xor c
    or h
    or h
    xor h
    and l
    ld a, a
    ld a, a
    and e
    and c
    or b
    or h
    and c
    xor c
    xor [hl]
    ld d, b
    and e
    and c
    or b
    or h
    and c
    xor c
    xor [hl]
    ld d, b
    xor h
    xor c
    or h
    or h
    xor h
    and l
    ld a, a
    xor l
    and c
    or e
    or h
    and l
    or d
    ld d, b
    xor l
    and c
    or e
    or h
    and l
    or d
    ld d, b
    and l
    cp b
    and e
    and l
    xor h
    xor h
    and l
    xor [hl]
    or h
    ld d, b
    xor a
    xor l
    xor [hl]
    xor c
    or b
    xor a
    or h
    and l
    xor [hl]
    or h
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    or e
    or l
    or b
    and l
    or d
    xor l
    and c
    xor [hl]
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    or e
    or l
    or b
    and l
    or d
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    xor l
    xor a
    xor [hl]
    or e
    or h
    and l
    or d
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    or h
    xor a
    or a
    xor [hl]
    ld a, a
    xor l
    and c
    or b
    ld d, b
    and d
    xor c
    and e
    cp c
    and e
    xor h
    and l
    ld d, b
    sbc a
    sbc a
    sbc a
    sbc a
    sbc a
    ld d, b
    xor b
    or l
    xor [hl]
    or h
    xor c
    xor [hl]
    and a
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    xor b
    and c
    xor [hl]
    and h
    and d
    xor a
    xor a
    xor e
    ld d, b
    xor l
    xor a
    xor a
    xor [hl]
    ld a, a
    or e
    or h
    xor a
    xor [hl]
    and l
    ld d, b
    and h
    and l
    or h
    xor a
    cp b
    xor c
    and e
    and c
    or h
    and l
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    and d
    or l
    or d
    xor [hl]
    xor c
    xor [hl]
    and a
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    and [hl]
    or d
    xor a
    cp d
    and l
    xor [hl]
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    and c
    or a
    and c
    xor e
    and l
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    or b
    and c
    or d
    and c
    xor h
    cp c
    or e
    xor c
    or e
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    or d
    and l
    and a
    and c
    xor c
    xor [hl]
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    sbc a
    sbc a
    sbc a
    sbc a
    sbc a
    sbc a
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    and a
    xor a
    xor a
    and h
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    and d
    and l
    or e
    or h
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    or a
    xor a
    or l
    xor [hl]
    and h
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    and a
    or d
    and l
    cp c
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and d
    xor h
    or l
    and l
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    xor a
    or d
    and c
    xor [hl]
    and a
    and l
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    or d
    and c
    xor c
    xor [hl]
    and d
    xor a
    or a
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    or b
    xor c
    xor [hl]
    xor e
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and a
    xor a
    xor h
    and h
    and l
    xor [hl]
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and e
    or d
    xor c
    xor l
    or e
    xor a
    xor [hl]
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    and a
    or d
    and l
    and l
    xor [hl]
    ld a, a
    and d
    and c
    and h
    and a
    and l
    ld d, b
    xor h
    and l
    and c
    or [hl]
    and l
    ld a, a
    xor b
    xor a
    xor h
    and l
    ld a, a
    or d
    xor a
    or b
    and l
    ld d, b
    xor c
    xor [hl]
    or e
    and l
    and e
    or h
    xor c
    and e
    xor c
    and h
    and l
    ld d, b
    or e
    and l
    and e
    or d
    and l
    or h
    ld a, a
    and c
    xor l
    and d
    and l
    or d
    ld d, b
    and [hl]
    xor h
    xor c
    xor [hl]
    or h
    ld d, b
    or h
    xor b
    or l
    xor [hl]
    and h
    and l
    or d
    ld a, a
    or e
    or h
    xor a
    xor [hl]
    and l
    ld d, b
    or a
    and c
    or h
    and l
    or d
    ld a, a
    or e
    or h
    xor a
    xor [hl]
    and l
    ld d, b
    xor l
    and c
    xor e
    and l
    or l
    or b
    ld d, b
    or e
    or l
    xor h
    and [hl]
    or l
    or d
    xor c
    and e
    ld a, a
    and c
    and e
    xor c
    and h
    ld d, b
    and d
    or d
    xor a
    xor l
    xor c
    xor [hl]
    and l
    ld d, b
    and l
    xor h
    xor c
    xor l
    xor c
    xor [hl]
    and c
    or h
    and l
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    xor b
    and c
    and e
    or h
    and l
    or d
    xor c
    xor a
    xor h
    cp c
    or e
    xor c
    or e
    ld d, b
    and e
    or l
    or d
    xor c
    xor a
    or l
    or e
    ld a, a
    or e
    or l
    and a
    and c
    or d
    ld d, b
    and [hl]
    xor a
    or e
    or e
    xor c
    xor h
    ld a, a
    xor a
    and [hl]
    ld a, a
    and e
    or d
    or l
    or e
    or h
    ld d, b
    and [hl]
    xor a
    or e
    or e
    xor c
    xor h
    ld a, a
    xor a
    and [hl]
    ld a, a
    or e
    xor b
    and l
    xor h
    xor h
    ld d, b
    or e
    and l
    and e
    or d
    and l
    or h
    ld a, a
    xor e
    and l
    cp c
    ld d, b
    sbc a
    sbc a
    sbc a
    sbc a
    sbc a
    ld d, b
    and l
    cp b
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld a, a
    or h
    xor c
    and e
    xor e
    and l
    or h
    ld d, b
    xor b
    xor c
    or h
    ld a, a
    and l
    or c
    or l
    xor c
    or b
    xor l
    and l
    xor [hl]
    or h
    ld d, b
    and e
    xor a
    or d
    and c
    xor h
    ld a, a
    or d
    and l
    and l
    and [hl]
    ld d, b
    and e
    and c
    or d
    and h
    ld a, a
    xor e
    and l
    cp c
    ld d, b
    and a
    xor a
    xor h
    and h
    ld a, a
    and d
    and c
    xor h
    xor h
    ld d, b
    or d
    and c
    xor c
    or e
    and l
    ld a, a
    and l
    or c
    or l
    xor c
    or b
    xor l
    and l
    xor [hl]
    or h
    ld d, b
    or b
    xor c
    or b
    xor c
    ld a, a
    or b
    xor h
    and c
    cp c
    or h
    xor b
    xor c
    xor [hl]
    and a
    ld d, b
    xor a
    xor l
    xor [hl]
    xor c
    or b
    xor a
    or h
    and l
    xor [hl]
    or h
    ld a, a
    and e
    or l
    or d
    and l
    ld d, b
    or [hl]
    xor c
    and a
    xor a
    or l
    or d
    ld a, a
    or b
    xor c
    and l
    and e
    and l
    ld d, b
    or [hl]
    xor c
    and a
    xor a
    or l
    or d
    ld a, a
    or b
    xor c
    xor h
    xor h
    ld d, b
    and a
    or l
    and c
    or d
    and h
    ld a, a
    and l
    or c
    or l
    xor c
    or b
    xor l
    and l
    xor [hl]
    or h
    ld d, b
    or e
    xor c
    xor h
    or [hl]
    and l
    or d
    ld a, a
    or b
    and c
    xor c
    xor [hl]
    or h
    ld d, b
    and a
    xor a
    xor h
    and h
    ld a, a
    ld a, a
    or b
    and c
    xor c
    xor [hl]
    or h
    ld d, b
    and e
    or l
    or h
    or h
    and l
    or d
    ld d, b
    and e
    xor a
    xor c
    xor [hl]
    ld d, b
    xor l
    xor c
    xor [hl]
    and l
    or d
    and c
    xor h
    ld a, a
    or a
    and c
    or h
    and l
    or d
    ld d, b
    or e
    xor a
    and h
    and c
    ld a, a
    or a
    and c
    or h
    and l
    or d
    ld d, b
    and [hl]
    or d
    or l
    xor c
    or h
    ld a, a
    ld a, a
    xor d
    or l
    xor c
    and e
    and l
    ld d, b
    and d
    xor a
    and c
    or h
    ld a, a
    or h
    xor c
    and e
    xor e
    and l
    or h
    ld d, b
    and a
    xor a
    xor h
    and h
    ld a, a
    or h
    and l
    and l
    or h
    xor b
    ld d, b
    or d
    and c
    xor c
    or e
    and l
    ld a, a
    or b
    xor a
    or a
    and l
    or d
    ld d, b
    and h
    and l
    and [hl]
    and l
    xor [hl]
    and e
    and l
    ld d, b
    and c
    and e
    and e
    and l
    xor h
    and l
    or d
    and c
    or h
    xor a
    or d
    ld d, b
    and c
    xor l
    or b
    xor h
    xor c
    and [hl]
    xor c
    and l
    or d
    ld d, b
    and e
    xor a
    xor c
    xor [hl]
    ld a, a
    and d
    xor a
    cp b
    ld d, b
    xor l
    and c
    xor c
    xor h
    ld d, b
    and d
    xor a
    xor a
    or e
    or h
    and l
    or d
    ld d, b
    xor b
    xor c
    xor h
    xor h
    or l
    and [hl]
    and [hl]
    ld a, a
    or e
    xor b
    xor a
    or [hl]
    and l
    xor h
    ld d, b
    and [hl]
    xor h
    or l
    or h
    and l
    ld d, b
    xor e
    and l
    cp c
    ld a, a
    xor a
    and [hl]
    ld a, a
    xor h
    xor c
    and [hl]
    or h
    ld d, b
    xor h
    and l
    and c
    or d
    xor [hl]
    ld a, a
    and l
    or c
    or l
    xor c
    or b
    xor l
    and l
    xor [hl]
    or h
    ld d, b
    and d
    and c
    and h
    ld a, a
    and [hl]
    xor c
    or e
    xor b
    xor c
    xor [hl]
    and a
    or d
    xor a
    and h
    ld d, b
    and a
    xor a
    xor a
    and h
    ld a, a
    and [hl]
    xor c
    or e
    xor b
    xor c
    xor [hl]
    and a
    or d
    xor a
    and h
    ld a, a
    ld d, b
    and d
    and l
    or e
    or h
    ld a, a
    and [hl]
    xor c
    or e
    xor b
    xor c
    xor [hl]
    and a
    or d
    xor a
    and h
    ld a, a
    ld d, b
    or d
    and c
    xor c
    or e
    and l
    ld a, a
    and l
    or c
    or l
    xor c
    or b
    xor l
    and l
    xor [hl]
    or h
    ld d, b
    or b
    xor c
    or b
    xor c
    ld a, a
    or b
    xor h
    and c
    cp c
    and l
    or d
    ld d, b
    or b
    xor c
    or b
    xor c
    ld a, a
    or d
    and l
    or [hl]
    xor c
    or [hl]
    and l
    ld d, b
    or b
    xor c
    or b
    xor c
    ld a, a
    sbc a
    sbc a
    sub c
    ld d, b
    or b
    xor c
    or b
    xor c
    ld a, a
    sbc a
    sbc a
    sub d
    ld d, b
    and d
    sub d
    and [hl]
    ld d, b
    and d
    sub c
    and [hl]
    ld d, b
    sub c
    and [hl]
    ld d, b
    sub d
    and [hl]
    ld d, b
    sub e
    and [hl]
    ld d, b
    sub h
    and [hl]
    ld d, b
    sub l
    and [hl]
    ld d, b
    sub [hl]
    and [hl]
    ld d, b
    sub a
    and [hl]
    ld d, b
    sbc b
    and [hl]
    ld d, b
    sbc c
    and [hl]
    ld d, b
    sub c
    sub b
    and [hl]
    ld d, b
    sub c
    sub c
    and [hl]
    ld d, b
    and d
    sub h
    and [hl]
    ld d, b
    and e
    xor b
    xor c
    xor h
    and h
    ld d, b
    xor d
    or l
    or [hl]
    and l
    xor [hl]
    xor c
    xor h
    and l
    ld d, b
    xor l
    xor c
    xor [hl]
    xor c
    or e
    xor e
    xor c
    or d
    or h
    ld d, b
    or e
    and c
    xor c
    xor h
    xor a
    or d
    ld d, b
    and d
    xor a
    cp c
    ld a, a
    or e
    and e
    xor a
    or l
    or h
    ld d, b
    and a
    xor c
    or d
    xor h
    ld a, a
    or e
    and e
    xor a
    or l
    or h
    ld d, b
    and [hl]
    and c
    xor [hl]
    and c
    or h
    xor c
    and e
    ld d, b
    or e
    and e
    xor c
    and l
    xor [hl]
    and e
    and l
    ld a, a
    ld a, a
    xor l
    and c
    xor [hl]
    ld d, b
    xor l
    xor a
    or l
    xor [hl]
    or h
    and c
    xor c
    xor [hl]
    ld a, a
    xor l
    and c
    xor [hl]
    ld d, b
    or [hl]
    xor c
    xor h
    xor h
    and c
    xor c
    xor [hl]
    ld a, a
    and a
    or d
    xor a
    or l
    or b
    ld d, b
    or h
    xor b
    and l
    xor c
    and [hl]
    ld d, b
    and l
    xor h
    and l
    and e
    or h
    or d
    xor a
    xor [hl]
    xor c
    and e
    ld a, a
    and d
    xor a
    or e
    or e
    ld d, b
    xor l
    and c
    and a
    xor c
    and e
    xor c
    and c
    xor [hl]
    ld d, b
    and [hl]
    xor c
    or e
    xor b
    and l
    or d
    xor l
    and c
    xor [hl]
    ld d, b
    or e
    xor b
    xor a
    or d
    or h
    or e
    ld a, a
    xor l
    and c
    xor [hl]
    ld d, b
    and d
    and c
    xor h
    and h
    xor b
    and l
    and c
    and h
    ld a, a
    xor l
    and c
    xor [hl]
    ld d, b
    and a
    and c
    xor l
    and d
    xor h
    and l
    ld d, b
    or e
    xor c
    or e
    or h
    and l
    or d
    ld d, b
    or b
    or e
    cp c
    and e
    xor b
    xor a
    xor h
    xor a
    and a
    xor c
    or e
    or h
    ld d, b
    and l
    xor h
    and l
    and e
    or h
    or d
    xor a
    xor [hl]
    ld a, a
    and a
    or d
    xor a
    or l
    or b
    ld d, b
    xor l
    and c
    and a
    xor c
    and e
    xor c
    and c
    xor [hl]
    ld d, b
    or h
    and c
    xor l
    and l
    or d
    ld d, b
    and d
    xor c
    or d
    and h
    or e
    adc l
    xor l
    and c
    xor [hl]
    ld d, b
    xor e
    and c
    or d
    and c
    or h
    and l
    xor e
    and c
    ld d, b
    xor a
    or b
    or b
    xor a
    xor [hl]
    and l
    xor [hl]
    or h
    sub c
    ld d, b
    or h
    and l
    and c
    and e
    xor b
    ld a, a
    and c
    xor a
    and e
    xor b
    xor c
    and h
    and l
    or d
    ld d, b
    xor b
    xor c
    xor h
    xor h
    or l
    and [hl]
    ld a, a
    and h
    xor c
    or d
    and l
    and e
    or h
    xor a
    or d
    ld d, b
    or d
    and l
    or e
    and l
    and c
    or d
    and e
    xor b
    ld a, a
    or a
    xor a
    or d
    xor e
    and l
    or d
    ld d, b
    or e
    and c
    xor e
    and c
    and e
    xor b
    cp c
    ld d, b
    or d
    xor a
    and e
    xor e
    and l
    or h
    ld a, a
    xor l
    and l
    xor l
    and d
    and l
    or d
    ld d, b
    or h
    or d
    and c
    xor c
    xor [hl]
    and l
    or d
    ld d, b
    or h
    or d
    and c
    xor c
    xor [hl]
    and l
    or d
    ld d, b
    cp b
    xor c
    and d
    and c
    ld d, b
    or h
    and c
    or d
    cp b
    xor c
    ld d, b
    and e
    and c
    or d
    or e
    xor l
    cp c
    ld d, b
    xor l
    and c
    or d
    and e
    xor b
    xor c
    or e
    ld d, b
    and c
    xor h
    xor h
    xor c
    and e
    ld d, b
    and e
    xor b
    and l
    and l
    cp c
    and c
    xor a
    ld d, b
    and e
    and c
    or d
    and e
    xor b
    xor c
    xor h
    or l
    ld d, b
    xor [hl]
    and c
    and e
    xor b
    xor c
    xor l
    cp c
    ld d, b
    and a
    and l
    xor [hl]
    or h
    xor h
    and l
    xor l
    and c
    xor [hl]
    ld d, b
    xor a
    or b
    or b
    xor a
    xor [hl]
    and l
    xor [hl]
    or h
    sub d
    ld d, b
    xor a
    or b
    or b
    xor a
    xor [hl]
    and l
    xor [hl]
    or h
    sub e
    ld d, b
    and e
    and c
    or d
    xor [hl]
    and c
    or d
    ld d, b
    or b
    or d
    xor c
    and l
    or e
    or h
    ld d, b
    xor e
    or l
    and e
    xor b
    xor c
    and e
    ld d, b
    or a
    and c
    or h
    and l
    or d
    xor h
    or l
    ld d, b
    and d
    xor a
    xor a
    xor e
    ld d, b
    and a
    xor a
    xor a
    and h
    or e
    ld d, b
    or e
    and c
    or [hl]
    and l
    ld d, b
    or d
    and l
    or e
    and l
    or h
    ld d, b
    and l
    cp b
    xor c
    or h
    ld d, b
    or e
    and l
    or h
    or l
    or b
    ld d, b
    and h
    and l
    and [hl]
    xor c
    xor [hl]
    and l
    ld c, [hl]
    and a
    or d
    and l
    and l
    xor [hl]
    ld c, [hl]
    or h
    xor a
    xor l
    ld c, [hl]
    xor e
    and l
    xor [hl]
    ld d, b
    and h
    and l
    and [hl]
    xor c
    xor [hl]
    and l
    ld c, [hl]
    or d
    and l
    and h
    ld c, [hl]
    or d
    xor a
    xor e
    cp c
    ld c, [hl]
    xor d
    and c
    and e
    xor e
    ld d, b
    or b
    xor h
    and c
    cp c
    and l
    or d
    ld a, a
    ld d, b
    and e
    or b
    or l
    ld a, a
    ld d, b
    or l
    or e
    and l
    ld c, [hl]
    and h
    xor c
    or e
    and e
    and c
    or d
    and h
    ld d, b
    or d
    and l
    and e
    xor a
    or d
    and h
    ld c, [hl]
    xor [hl]
    and l
    or a
    or e
    ld d, b
    or c
    or l
    xor c
    and e
    xor e
    ld c, [hl]
    or e
    xor h
    xor a
    or a
    ld d, b
    and e
    xor a
    xor l
    and d
    and c
    or h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and a
    xor a
    xor a
    and h
    or e
    ld c, [hl]
    or b
    and l
    or h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and [hl]
    xor h
    and l
    and l
    ld d, b
    xor b
    or l
    xor [hl]
    or h
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and d
    and c
    xor c
    or h
    ld c, [hl]
    or e
    or h
    xor a
    xor [hl]
    and l
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    and [hl]
    xor h
    and l
    and l
    ld d, b
    or d
    and l
    or b
    xor h
    and c
    and e
    and l
    ld c, [hl]
    or e
    or h
    and c
    or h
    and l
    ld c, [hl]
    and e
    and c
    xor [hl]
    and e
    and l
    xor h
    ld d, b
    or b
    or l
    or d
    and e
    xor b
    and c
    or e
    and l
    ld c, [hl]
    or e
    and c
    xor h
    and l
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    and e
    and c
    or e
    xor b
    ld d, b
    and l
    cp b
    xor c
    or h
    ld d, b
    xor c
    xor [hl]
    and [hl]
    xor a
    ld c, [hl]
    and e
    xor b
    xor c
    or d
    or b
    ld c, [hl]
    or b
    or d
    xor c
    xor [hl]
    or h
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    xor [hl]
    xor a
    ld c, [hl]
    cp c
    and l
    or e
    ld d, b
    cp c
    and l
    or e
    ld c, [hl]
    xor [hl]
    xor a
    ld d, b
    xor [hl]
    xor a
    or d
    or h
    xor b
    ld c, [hl]
    or a
    and l
    or e
    or h
    ld d, b
    or e
    xor a
    or l
    or h
    xor b
    ld c, [hl]
    and l
    and c
    or e
    or h
    ld d, b
    xor [hl]
    xor a
    or d
    or h
    xor b
    ld c, [hl]
    and l
    and c
    or e
    or h
    ld d, b
    and l
    cp b
    and e
    xor b
    and c
    xor [hl]
    and a
    and l
    ld c, [hl]
    and l
    cp b
    xor c
    or h
    ld d, b
    cp c
    and l
    or e
    ld c, [hl]
    xor [hl]
    xor a
    ld d, b
    or e
    or h
    and c
    xor [hl]
    and h
    and c
    or d
    and h
    ld d, b
    or a
    or d
    and l
    or e
    or h
    xor h
    and l
    ld d, b
    and [hl]
    xor h
    cp c
    xor c
    xor [hl]
    and a
    ld d, b
    or b
    xor a
    xor c
    or e
    xor a
    xor [hl]
    ld d, b
    and a
    or d
    xor a
    or l
    xor [hl]
    and h
    ld d, b
    and a
    xor b
    xor a
    or e
    or h
    ld d, b
    and [hl]
    xor h
    and c
    xor l
    and l
    ld d, b
    and c
    or c
    or l
    and c
    or h
    xor c
    and e
    ld d, b
    or a
    and l
    and l
    and h
    ld d, b
    and l
    xor h
    and l
    and e
    or h
    or d
    xor c
    and e
    ld d, b
    or e
    or l
    or b
    and l
    or d
    xor l
    and c
    xor [hl]
    ld d, b
    and [hl]
    or d
    and l
    and l
    cp d
    xor c
    xor [hl]
    and a
    ld d, b
    and h
    or d
    and c
    and a
    xor a
    xor [hl]
    ld d, b
    and h
    and l
    and c
    or h
    xor b
    ld d, b
    or e
    xor h
    and l
    and l
    or b
    ld d, b
    or b
    xor a
    xor c
    or e
    xor a
    xor [hl]
    ld d, b
    and d
    or l
    or d
    xor [hl]
    ld d, b
    and [hl]
    or d
    and l
    and l
    cp d
    and l
    ld d, b
    or b
    and c
    or d
    and c
    xor h
    cp c
    or e
    xor c
    or e
    ld d, b
    xor l
    pop bc
    call nc, $c8c3
    ld d, b
    xor l
    pop bc
    call nc, $c8c3
    and d
    pop bc
    call nz, TimerOverflowInterrupt
    xor c
    add a
    sub $c5
    ld a, a
    db $d3
    push de
    jp $c5cb


    call nz, $d37f
    call nc, $c5d2
    adc $4f
    rst $00
    call nc, Call_02c_7fc8
    add $d2
    rst $08
    call Call_02c_557f
    ld e, c
    ld a, a
    add c
    ld a, a
    ld e, b
    nop
    xor c
    add $7f
    call nc, $c1c8
    call nc, $d387
    ld a, a
    db $d3
    rst $08
    adc h
    ld a, a
    ld c, a
    ld d, b
    ld [bc], a
    sbc a
    rst $38
    jp Jump_02c_5500


    push de
    db $d3
    push bc
    ld a, a
    or l
    or e
    ld a, a
    call nz, $cccf
    call z, $d2c1
    db $d3
    ld a, a
    add $cf
    ld d, l
    jp nc, $d17f

    push de
    rst $08
    call nc, $cec9
    rst $00
    ld a, a
    ret nc

    jp nc, $c3c9

    push bc
    db $d3
    ld a, a
    ld d, l
    pop bc
    adc $c4
    ld a, a
    db $d3
    push bc
    call nc, $ccd4
    ret


    adc $c7
    ld a, a
    pop bc
    jp $cfc3


    ld d, l
    push de
    adc $d4
    db $d3
    add c
    ld a, a
    ld d, a
    nop
    and c
    call z, Call_02c_7fcc
    pop bc
    jp nc, Jump_02c_7fc5

    jp nz, $cfcf

    set 2, e
    ld a, a
    rst $08
    add $7f
    ld c, a
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    xor c
    add $7f
    ret


    call nc, $d387
    ld a, a
    add $cf
    jp nc, $a17f

    push de
    jp $c9c8


    ld c, a
    call nz, $d2c5
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ld d, d
    add c
    call nc, $c9c8
    ld d, l
    db $d3
    ld a, a
    set 1, c
    adc $c4
    ld a, a
    rst $08
    add $7f
    call nc, $c9c8
    adc $c7
    ld a, a
    ld d, l
    ld a, a
    rst $10
    ret


    call z, Call_02c_7fcc
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    jp $c1c8


    adc $c3
    ld d, l
    push bc
    ld a, a
    call nc, Call_02c_7fcf
    jp nz, Jump_02c_7fc5

    push de
    db $d3
    push bc
    call nz, Call_02c_7f81
    ld e, b
    nop
    ld d, d
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    db $d3
    pop bc
    call nc, $cf7f
    adc $7f
    ld c, a
    call nc, $c5c8
    ld a, a
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    adc [hl]
    ld a, a
    ld e, b
    nop
    xor b
    push bc
    jp nc, Jump_02c_7fc5

    pop bc
    ld a, a
    jp nz, $c3c9

    reti


    jp $c5cc


    ld a, a
    ld c, [hl]
    ld a, a
    jp $cec1


    add a
    call nc, $c67f
    ret


    adc $c4
    ld a, a
    pop bc
    ld a, a
    rst $10
    pop bc
    reti


    ld d, l
    ld a, a
    call nc, Call_02c_7fcf
    jp nc, $ced5

    adc [hl]
    ld a, a
    ld e, b
    nop
    or a
    pop bc
    ret z

    rst $08
    rst $08
    add c
    ld a, a
    or h
    rst $08
    rst $08
    ld a, a
    call $c3d5
    ret z

    ld a, a
    rst $00
    ld c, a
    rst $08
    rst $08
    call nz, Call_02c_7fd3
    rst $08
    add $7f
    ld d, h
    ld a, a
    add c
    ld a, a
    ld d, a
    nop
    xor b
    push bc
    jp nc, Jump_02c_7fc5

    ret


    db $d3
    ld a, a
    push bc
    call z, $d6c5
    pop bc
    call nc, $d2cf
    adc [hl]
    ld c, a
    ld d, a
    nop
    xor [hl]
    rst $08
    call nc, $d47f
    rst $08
    ld a, a
    ret z

    ret


    call nc, $d47f
    ret z

    push bc
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    pop bc
    jp $d5c3


    jp nc, $d4c1

    push bc
    call z, $81d9
    ld a, a
    ld e, b
    nop
    or a
    ret z

    pop bc
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    ret nc

    ret


    call nc, $81d9
    ld a, a
    ld c, a
    ld d, h
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $ced5

    rst $08
    push de
    call nc, $c67f
    jp nc, $cf55

    call $d47f
    ret z

    push bc
    ld a, a
    jp nz, $ccc1

    call z, Call_02c_7f81
    ld e, b
    nop
    and l
    sub $c5
    adc $7f
    call nc, Call_02c_7fcf
    push de
    db $d3
    push bc
    ld a, a
    ret


    call nc, Call_02c_7f8c
    call nc, $c84f
    push bc
    jp nc, Jump_02c_7fc5

    ret


    db $d3
    ld a, a
    adc $cf
    ld a, a
    push bc
    add $c6
    push bc
    jp Jump_02c_55d4


    adc [hl]
    ld a, a
    ld e, b
    nop
    xor b
    push bc
    jp nc, Jump_02c_4fc5

    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    xor [hl]
    rst $08
    ld a, a
    ret nc

    push bc
    jp nc, $c9cd

    call nc, $c9d4
    adc $c7
    ld a, a
    call nc, Call_02c_7fcf
    ld d, l
    db $d3
    ret


    call nc, $cf7f
    adc $7f
    adc [hl]
    ld a, a
    ld e, b
    nop
    or e
    push bc
    call z, $c3c5
    call nc, Call_02c_547f
    adc h
    ld a, a
    ret nc

    call z, $c1c5
    db $d3
    ld c, a
    push bc
    add c
    ld a, a
    ld d, a
    nop
    or a
    ret z

    ret


    jp Jump_02c_7fc8


    ld d, h
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02c_7fc4
    ld c, a
    jp nz, Jump_02c_7fc5

    call nc, $cbc1
    push bc
    adc $7f
    rst $08
    push de
    call nc, Call_02c_7f9f
    ld d, a
    nop
    or a
    ret z

    ret


    jp Jump_02c_7fc8


    ld d, h
    ld a, a
    db $d3
    ret z

    rst $08
    push de
    call z, Call_02c_7fc4
    ld c, a
    jp nz, Jump_02c_7fc5

    push de
    db $d3
    push bc
    call nz, Call_02c_7f9f
    ld d, a
    nop
    or a
    ret z

    push bc
    jp nc, Jump_02c_7fc5

    ret


    call nc, $d37f
    ret z

    rst $08
    push de
    call z, Call_02c_7fc4
    jp nz, $c54f

    ld a, a
    call $d6cf
    push bc
    call nz, $d47f
    rst $08
    sbc a
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    ld a, a
    call z, $d6c5
    push bc
    call z, $cf7f
    add $7f
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ret z

    pop bc
    db $d3
    ld a, a
    jp nz, $c3c5

    rst $08
    call Call_02c_7fc5
    ld d, l
    ld d, b
    add hl, bc
    db $ec
    ret nc

    inc de
    nop
    adc [hl]
    ld d, b
    ld b, $50
    nop
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, Call_02c_7fc8
    ld c, a
    ld d, b
    add hl, bc
    ld hl, sp-$32
    inc hl
    nop
    ld d, l
    rst $08
    add $7f
    ld d, l
    ld d, b
    ld bc, $cd68
    nop
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

    adc [hl]
    ld a, a
    ld d, a
    ld bc, $df20
    nop
    ld c, a
    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call $c4c1
    push bc
    ld a, a
    pop bc
    ld a, a
    jp $c1c8


    call z, Call_02c_55cc
    push bc
    adc $c7
    push bc
    add c
    ld a, a
    ld e, b
    nop
    xor c
    add a
    sub $c5
    ld a, a
    pop bc
    adc $c7
    call z, $c4c5
    ld a, a
    db $d3
    push de
    jp $c5c3


    ld c, a
    db $d3
    db $d3
    add $d5
    call z, $d9cc
    adc h
    ld d, l
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    xor b
    push bc
    jp nc, Jump_02c_7fc5

    jp nc, $d3d5

    ret z

    push bc
    call nz, $cf7f
    push de
    call nc, Call_02c_7f81
    ld d, l
    ld e, b
    nop
    xor h
    rst $08
    rst $08
    bit 7, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    pop bc
    ld a, a
    call nc, Call_02c_4fc5
    call z, $d3c5
    jp $d0cf


    push bc
    add c
    ld a, a
    ld d, c
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ret


    adc $c7
    ld a, a
    rst $08
    ld c, a
    adc $7f
    call nc, $c5c8
    ld a, a
    jp nc, $c1cf

    call nz, Call_02c_7f81
    ld d, a
    nop
    xor h
    rst $08
    rst $08
    bit 7, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    pop bc
    ld a, a
    call nc, Call_02c_4fc5
    call z, $d3c5
    jp $d0cf


    push bc
    add c
    ld a, a
    ld d, c
    xor c
    call nc, $d387
    ld a, a
    adc $cf
    call nc, $d37f
    rst $08
    ld a, a
    jp nz, $c4c1

    ld a, a
    ld c, a
    ld d, [hl]
    ld d, a
    ld a, a
    call nc, Call_02c_7fcf
    ret nc

    pop bc
    db $d3
    db $d3
    ld a, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ld d, l
    ret z

    call nc, $c5c8
    ld a, a
    jp nc, $c3cf

    bit 7, a
    call $d5cf
    adc $d4
    pop bc
    ret


    ld d, l
    adc $7f
    add $d2
    rst $08
    call $d47f
    ret z

    push bc
    ld a, a
    call z, $c7c9
    ret z

    call nc, Call_02c_557f
    jp nz, $d5cc

    push bc
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, l
    rst $10
    ret z

    push bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    rst $00
    rst $08
    ld a, a
    call nc, Call_02c_7fcf
    call nc, Call_02c_55c8
    push bc
    ld a, a
    pop bc
    db $d3
    call nc, $d2c5
    ld a, a
    jp $d4c9


    reti


    ld a, a
    ld d, [hl]
    adc [hl]
    nop
    xor a
    ret z

    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, c
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call nc, $c9c8
    adc $cb
    ld a, a
    ret


    call nc, $d387
    ld c, a
    ld a, a
    db $d3
    push de
    ret


    call nc, $c67f
    rst $08
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_02c_7fcf
    ld d, l
    rst $00
    rst $08
    ld a, a
    rst $08
    adc $7f
    call nz, $d7c1
    call nz, $c9cc
    adc $c7
    ld a, a
    call z, $55c9
    set 0, l
    ld a, a
    call nc, $c9c8
    db $d3
    ld a, a
    ret


    adc $7f
    call nc, $c9c8
    db $d3
    ld a, a
    ret nc

    ld d, l
    call z, $c3c1
    push bc
    ld a, a
    sbc a
    ld a, a
    ld d, l
    and [hl]
    push de
    call nc, $d2d5
    push bc
    ld a, a
    jp $c1c8


    call $81d0
    ld a, a
    ld d, c
    or h
    ret z

    push bc
    ld a, a
    ret z

    push bc
    pop bc
    call nz, Call_02c_7f7f
    rst $08
    add $7f
    call z, $c7c9
    ret z

    ld c, a
    call nc, $c9ce
    adc $c7
    ld a, a
    jp $d4c9


    reti


    adc h
    ld a, a
    and c
    call z, $c9cc
    jp $8c55


    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    push de
    db $d3
    push bc
    jp nc, $cf7f

    add $d0
    call z, Call_02c_55c1
    adc $d4
    ld a, a
    ld d, h
    adc $c1
    call nc, $d2d5
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ld d, l
    ret z

    push bc
    pop bc
    jp nc, Jump_02c_7fd4

    jp nz, $c1c5

    call nc, $c97f
    adc $7f
    ret z

    pop bc
    jp nc, $cd55

    rst $08
    adc $d9
    ld a, a
    ld d, l
    add c
    ld a, a
    ld d, c
    and c
    call z, $c9cc
    jp $cc7f


    rst $08
    rst $08
    set 2, e
    ld a, a
    sub $c5
    jp nc, Jump_02c_7fd9

    ld c, a
    ret z

    rst $08
    adc $c5
    db $d3
    call nc, $c17f
    adc $c4
    ld a, a
    rst $00
    push bc
    adc $d4
    call z, $55c5
    ld a, a
    ld a, a
    jp nz, $c3c5

    pop bc
    push de
    db $d3
    push bc
    ld a, a
    db $d3
    ret z

    push bc
    rst $08
    add $d4
    push bc
    ld d, l
    adc $7f
    rst $00
    jp nc, $d7cf

    db $d3
    ld a, a
    add $cc
    rst $08
    rst $10
    push bc
    jp nc, Jump_02c_7fd3

    pop bc
    ld d, l
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    pop bc
    call $8cc5
    ld d, l
    adc h
    jp nz, $d4d5

    ld a, a
    call $d9c1
    jp nz, Jump_02c_7fc5

    pop bc
    ld a, a
    sub $c5
    jp nc, Jump_02c_55d9

    ld a, a
    add $c9
    push bc
    jp nc, $c5c3

    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    adc $c5
    adc $d4
    ld a, a
    ld d, l
    rst $08
    add $7f
    reti


    rst $08
    push de
    jp nc, Jump_02c_7fd3

    db $d3
    rst $08
    call Call_02c_7fc5
    call nz, $d9c1
    ld d, l
    add c
    ld a, a
    ld d, a
    nop
    xor b
    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    call z, $cfcf
    bit 7, a
    call nc, $d2c8
    rst $08
    push de
    ld c, a
    rst $00
    ret z

    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $ccc5
    push bc
    db $d3
    jp $d0cf


    push bc
    add c
    ld d, l
    ld a, a
    ld d, c
    cp c
    rst $08
    push de
    ld a, a
    call $d9c1
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $cf4f
    rst $10
    push bc
    jp nc, $cf7f

    add $7f
    ld d, h
    add c
    ld a, a
    ld d, a
    nop
    xor h
    rst $08
    rst $08
    bit 7, a
    jp nz, Jump_02c_7fd9

    call nc, $ccc5
    push bc
    db $d3
    jp $d0cf


    push bc
    ld c, a
    add c
    ld a, a
    ld d, c
    xor c
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    rst $00
    jp nc, $cec1

    call nz, $c1d0
    ld a, a
    rst $10
    ret z

    ld c, a
    rst $08
    ld a, a
    ret


    db $d3
    ld a, a
    add $c9
    db $d3
    ret z

    ret


    adc $c7
    add c
    ld a, a
    ld d, a
    nop
    xor [hl]
    rst $08
    rst $10
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    add $c9
    add $d4
    ret z

    ld a, a
    ld c, a
    add $cc
    rst $08
    rst $08
    jp nc, $cf7f

    add $7f
    jp $c5cc


    sub $c5
    jp nc, $cd8d

    ld d, l
    pop bc
    adc $87
    db $d3
    ld a, a
    rst $00
    ret


    add $d4
    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    ret


    db $d3
    ld a, a
    ld d, l
    db $d3
    push bc
    call z, $c9cc
    adc $c7
    ld a, a
    db $d3
    ret nc

    push bc
    jp $c1c9


    call z, $d9cc
    ld d, l
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    ld a, a
    ld a, a
    rst $08
    add $7f
    push bc
    sub $55
    rst $08
    call z, $d4d5
    ret


    rst $08
    adc $7f
    ld d, h
    ld d, c
    ld a, a
    call nc, Call_02c_7fcf
    push bc
    ret c

    ret nc

    jp nc, $d3c5

    db $d3
    ld a, a
    ld d, [hl]
    add a
    db $d3
    ld a, a
    ld c, a
    call z, $d6cf
    push bc
    ld a, a
    pop bc
    adc $c4
    ld a, a
    ret z

    rst $08
    adc $c5
    db $d3
    call nc, $81d9
    ld d, l
    ld a, a
    ld d, a
    nop
    cp c
    rst $08
    push de
    add a
    call nz, $c27f
    push bc
    call nc, $c5d4
    jp nc, $c27f

    push de
    reti


    ld a, a
    ld c, a
    pop bc
    ld a, a
    call nc, $d9cf
    ld a, a
    or b
    ret


    ret nc

    ret


    ld a, a
    add $cf
    jp nc, $d97f

    rst $08
    ld d, l
    push de
    jp nc, $c77f

    ret


    jp nc, $c6cc

    jp nc, $c5c9

    adc $c4
    ld a, a
    ld d, c
    add c
    ld a, a
    xor c
    call nc, $d387
    ld a, a
    adc $cf
    rst $10
    ld a, a
    rst $10
    pop bc
    jp nc, $cccd

    reti


    ld c, a
    ld a, a
    rst $10
    push bc
    call z, $cfc3
    call $81c5
    ld a, a
    ld d, a
    nop
    xor c
    add a
    sub $c5
    ld a, a
    ret z

    push bc
    pop bc
    jp nc, Jump_02c_7fc4

    pop bc
    ld a, a
    rst $00
    rst $08
    rst $08
    call nz, Call_02c_7f4f
    adc $c5
    rst $10
    db $d3
    ld a, a
    ld d, c
    ld a, a
    call nc, $c1c8
    call nc, $c8d7
    push bc
    adc $7f
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    ld c, a
    jp nc, $d3d5

    ret z

    ret


    adc $c7
    ld a, a
    rst $08
    push de
    call nc, $8c7f
    call nc, $d2c8
    rst $08
    ld d, l
    push de
    rst $00
    ret z

    ld a, a
    rst $08
    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    call nc, $d9cf
    ld a, a
    or b
    ld d, l
    ret


    ret nc

    ret


    ld a, a
    ld d, l
    adc h
    pop bc
    adc $c4
    ld a, a
    call nc, $c5c8
    adc $7f
    ld d, h
    ld a, a
    jp $cec1


    ld d, l
    ld a, a
    jp nz, Jump_02c_7fc5

    pop bc
    call nc, $d2d4
    pop bc
    jp $c5d4


    call nz, $c27f
    reti


    ld a, a
    ld d, l
    ret


    call nc, $517f
    call nc, $c1c8
    call nc, $c97f
    db $d3
    ld a, a
    call nc, Call_02c_7fcf
    db $d3
    push bc
    push bc
    ld a, a
    call nc, Call_02c_4fc8
    pop bc
    call nc, $d97f
    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    add $cc
    push bc
    push bc
    add c
    ld a, a
    ld d, l
    ld d, a
    nop
    xor h
    rst $08
    rst $08
    bit 7, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    pop bc
    ld a, a
    call nc, Call_02c_4fc5
    call z, $d3c5
    jp $d0cf


    push bc
    add c
    ld a, a
    ld d, c
    xor c
    ld a, a
    jp $cec1


    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    pop bc
    ld a, a
    call z, $cecf
    rst $00
    ld a, a
    ld c, a
    jp nc, $c1cf

    call nz, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    db $d3
    push bc
    pop bc
    ld a, a
    db $d3
    ld d, l
    push de
    jp nc, $c1c6

    jp $c9c5


    adc $7f
    call nc, $c5c8
    ld a, a
    rst $08
    ret nc

    ret nc

    rst $08
    ld d, l
    db $d3
    ret


    call nc, Call_02c_7fc5
    rst $08
    add $7f
    call $cec9
    push bc
    add c
    ld a, a
    ld d, a
    nop
    xor h
    rst $08
    rst $08
    bit 7, a
    call nc, $d2c8
    rst $08
    push de
    rst $00
    ret z

    ld a, a
    pop bc
    ld a, a
    call nc, Call_02c_4fc5
    call z, $d3c5
    jp $d0cf


    push bc
    add c
    ld a, a
    ld d, c
    xor c
    ld a, a
    jp $cec1


    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret z

    rst $08
    ld c, a
    ret nc

    ld a, a
    rst $08
    add $7f
    call z, $c7c9
    ret z

    call nc, $c9ce
    adc $c7
    ld a, a
    jp $55c9


    call nc, $81d9
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    jp nc, Jump_02c_7fc5

    pop bc
    jp nc, Jump_02c_7fc5

    call $cec1
    reti


    ld a, a
    rst $00
    rst $08
    ld c, a
    rst $08
    call nz, Call_02c_7fd3
    rst $08
    add $7f
    ld d, h
    add c
    ret


    adc $7f
    and [hl]
    jp nc, $55c9

    push bc
    adc $c4
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    or e
    ret z

    rst $08
    ret nc

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
    call nc, Call_02c_7fc8
    rst $08
    add $7f
    ld c, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $c9c5

    adc $c7
    ld a, a
    jp nc, $c3c5

    rst $08
    ld d, l
    sub $c5
    jp nc, $c4c5

    add c
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    and e
    push bc
    adc $d4
    ld d, l
    push bc
    jp nc, Jump_02c_547f

    adc [hl]
    ld d, a
    nop
    or d
    push bc
    db $d3
    call nc, $d27f
    rst $08
    rst $08
    call Call_02c_567f
    ld a, a
    add $cf
    jp nc, Jump_02c_4f7f

    jp nc, $d3c5

    call nc, Call_02c_577f
    nop
    ld a, a
    or h
    ret z

    push bc
    jp nc, Jump_02c_7fc5

    pop bc
    jp nc, Jump_02c_7fc5

    call $cec1
    reti


    ld a, a
    rst $00
    ld c, a
    rst $08
    rst $08
    call nz, Call_02c_7fd3
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ret


    adc $7f
    and [hl]
    ld d, l
    jp nc, $c5c9

    adc $c4
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    or e
    ret z

    rst $08
    ret nc

    ld a, a
    ld d, a
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $c5d2
    adc $c7
    call nc, Call_02c_7fc8
    rst $08
    add $7f
    ld c, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    jp nz, $c9c5

    adc $c7
    ld a, a
    jp nc, $c3c5

    rst $08
    ld d, l
    sub $c5
    jp nc, $c4c5

    add c
    ld a, a
    ret


    adc $7f
    call nc, $c5c8
    ld a, a
    and e
    push bc
    adc $55
    call nc, $d2c5
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    ld d, a
    nop
    and c
    ld a, a
    rst $10
    jp nc, $d3c5

    call nc, $c9cc
    adc $c7
    ld a, a
    add $cf
    jp nc, $cdd5

    ld c, a
    add c
    ld a, a
    ld d, a
    nop
    xor c
    call nc, $d387
    ld a, a
    jp nz, $d3c5

    ret


    push bc
    rst $00
    push bc
    call nz, $cf7f
    adc $7f
    ld c, a
    pop bc
    call z, Call_02c_7fcc
    db $d3
    ret


    call nz, $d3c5
    adc [hl]
    ld a, a
    ld d, a
    nop
    ld d, [hl]
    ld a, a
    xor d
    ret


    adc $c7
    call z, $cec9
    rst $00
    add c
    ld a, a
    ld d, b
    dec bc
    nop
    call nz, $c3c5
    rst $08
    ld c, a
    call nz, Call_02c_7fc5
    call nc, $c5c8
    ld a, a
    call z, $c3cf
    bit 7, a
    jp nz, Jump_02c_7fd9

    pop bc
    ld a, a
    ld d, l
    jp $d2c1


    call nz, $cb7f
    push bc
    reti


    add c
    ld a, a
    ld d, a
    nop
    xor b
    pop bc
    sub $c9
    adc $c7
    ld a, a
    adc $cf
    call nc, $c27f
    jp nc, $d5cf

    rst $00
    ret z

    ld c, a
    call nc, $d47f
    ret z

    push bc
    ld a, a
    jp $c9cf


    adc $8d
    db $d3
    call nc, $d2cf
    ret


    adc $55
    rst $00
    ld a, a
    jp nz, $d8cf

    add c
    ld a, a
    ld d, a
    nop
    xor c
    add a
    call $c87f
    pop bc
    sub $c9
    adc $c7
    ld a, a
    call Call_02c_7fd9
    call nz, $cec9
    ld c, a
    adc $c5
    jp nc, $b481

    ret z

    push bc
    jp nc, Jump_02c_7fc5

    ret


    db $d3
    ld a, a
    pop bc
    ld a, a
    call z, $55c9
    call nz, $cf7f
    adc $7f
    call nc, $c5c8
    ld a, a
    ld d, [hl]
    add c
    ld a, a
    ld d, a
    nop
    ld d, h
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    pop bc
    jp nz, $ccc9

    ret


    call nc, $d94f
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $d47f
    rst $08
    ld a, a
    jr nc, @+$81

    call $d9c1
    ld d, l
    ld a, a
    rst $00
    push bc
    call nc, $c77f
    push bc
    adc $d4
    call z, $8ec5
    ld d, c
    xor c
    call nc, $c487
    ld a, a
    jp nz, Jump_02c_7fc5

    call nz, $c6c9
    add $c9
    jp $ccd5


    call nc, Call_02c_7f4f
    add $cf
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_02c_7fcf
    jp $cecf


    call nc, Call_02c_55d2
    rst $08
    call z, Call_02c_7f8c
    ld d, c
    ret


    add $7f
    call nc, $c5c8
    ld a, a
    pop bc
    jp nz, $ccc9

    ret


    call nc, Call_02c_7fd9
    rst $00
    push bc
    ld c, a
    call nc, Call_02c_7fd3
    ret z

    ret


    rst $00
    ret z

    push bc
    jp nc, $d47f

    ret z

    pop bc
    adc $7f
    call nc, Call_02c_55c8
    pop bc
    call nc, $8e7f
    xor l
    rst $08
    jp nc, $cfc5

    sub $c5
    jp nc, Jump_02c_7f8c

    call nc, $c5c8
    ld d, l
    ld a, a
    db $d3
    set 1, c
    call z, Call_02c_7fcc
    ld a, a
    call nc, Call_02c_7fcf
    db $d3
    ret nc

    call z, $d4c9
    ld a, a
    ld d, l
    rst $08
    add $7f
    pop bc
    ld a, a
    db $d3
    rst $10
    rst $08
    jp nc, $c2c4

    push bc
    jp $cdcf


    push bc
    db $d3
    ld d, l
    ld a, a
    push de
    db $d3
    push bc
    pop bc
    jp nz, $c5cc

    ld a, a
    ld e, b
    ld a, a
    push bc
    sub $c5
    adc $7f
    call nc, Call_02c_55c8
    rst $08
    push de
    rst $00
    ret z

    rst $10
    ret z

    push bc
    adc $7f
    ret


    call nc, $c97f
    db $d3
    ld a, a
    adc $cf
    ld d, l
    call nc, $c97f
    adc $7f
    jp $cecf


    call nc, $d3c5
    call nc, Call_02c_557f
    adc [hl]
    ld e, b
    nop
    or h
    ret z

    push bc
    ld a, a
    pop bc
    rst $00
    ret


    call z, Call_02c_7fc5
    pop bc
    jp nz, $ccc9

    ret


    call nc, $4fd9
    ld a, a
    ld d, l
    ld a, a
    rst $08
    add $7f
    pop bc
    call z, Call_02c_7fcc
    ld d, h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    ld d, l
    push bc
    adc $c8
    pop bc
    adc $c3
    push bc
    call nz, $d37f
    call z, $c7c9
    ret z

    call nc, $d9cc
    ld d, l
    ld a, a
    ld d, c
    ld a, a
    xor l
    rst $08
    jp nc, $cfc5

    sub $c5
    jp nc, Jump_02c_7f8c

    call nc, $c5c8
    ld a, a
    db $d3
    bit 1, a
    ret


    call z, Call_02c_7fcc
    ld a, a
    rst $08
    add $7f
    add $cc
    reti


    ret


    adc $c7
    ld a, a
    ret


    adc $55
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    set 3, c
    ld a, a
    jp nz, $c3c5

    rst $08
    call $d3c5
    ld a, a
    ld d, l
    push de
    db $d3
    push bc
    pop bc
    jp nz, $c5cc

    ld a, a
    ld e, b
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
    rst $10
    ret z

    push bc
    adc $7f
    ret


    call nc, $c97f
    db $d3
    ld a, a
    adc $cf
    ld d, l
    call nc, $c97f
    adc $7f
    jp $cecf


    call nc, $d3c5
    call nc, Call_02c_557f
    adc [hl]
    ld e, b
    nop
    ld d, h
    ld a, a
    ld a, a
    rst $10
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    pop bc
    jp nz, $ccc9

    ret


    call nc, $d94f
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c1c5

    jp $c9c8


    adc $c7
    ld a, a
    call nc, Call_02c_7fcf
    ld d, l
    sub l
    sub b
    ld a, a
    call $d9c1
    ld a, a
    rst $00
    push bc
    call nc, $c77f
    push bc
    adc $d4
    call z, $55c5
    adc [hl]
    ld d, c
    ld a, a
    xor c
    call nc, $c487
    ld a, a
    jp nz, Jump_02c_7fc5

    call nz, $c6c9
    add $c9
    jp $ccd5


    ld c, a
    call nc, $c67f
    rst $08
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_02c_7fcf
    jp $cecf


    call nc, $d255
    rst $08
    call z, Call_02c_7f8c
    ld d, c
    ld a, a
    ret


    add $7f
    call nc, $c5c8
    ld a, a
    pop bc
    jp nz, $ccc9

    ret


    call nc, Call_02c_7fd9
    rst $00
    ld c, a
    push bc
    call nc, Call_02c_7fd3
    ret z

    ret


    rst $00
    ret z

    push bc
    jp nc, $d47f

    ret z

    pop bc
    adc $7f
    call nc, $c855
    pop bc
    call nc, $8e7f
    ld a, a
    xor l
    rst $08
    jp nc, $cfc5

    sub $c5
    jp nc, Jump_02c_7f8c

    call nc, $c855
    push bc
    ld a, a
    db $d3
    set 1, c
    call z, Call_02c_7fcc
    ld a, a
    rst $08
    add $7f
    pop bc
    ld a, a
    db $d3
    call nc, $d255
    pop bc
    adc $c7
    push bc
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    jp nz, $c3c5

    rst $08
    call $c555
    db $d3
    ld a, a
    push de
    db $d3
    push bc
    pop bc
    jp nz, $c5cc

    ld a, a
    ld e, b
    ld a, a
    push bc
    sub $c5
    adc $7f
    ld d, l
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    rst $10
    ret z

    push bc
    adc $7f
    ret


    call nc, $c97f
    db $d3
    ld d, l
    ld a, a
    adc $cf
    call nc, $c97f
    adc $7f
    jp $cecf


    call nc, $d3c5
    call nc, Call_02c_557f
    adc [hl]
    ld e, b
    nop
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    call nz, $c6c5
    push bc
    adc $d3
    ret


    sub $c5
    ld a, a
    add $cf
    ld c, a
    jp nc, $c5c3

    ld a, a
    ld d, l
    ld a, a
    rst $08
    add $7f
    pop bc
    call z, Call_02c_7fcc
    ld a, a
    ld d, h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld d, l
    ld a, a
    push bc
    adc $c8
    pop bc
    adc $c3
    push bc
    call nz, $d37f
    call z, $c7c9
    ret z

    call nc, Call_02c_55cc
    reti


    ld a, a
    ld d, c
    xor l
    rst $08
    jp nc, $cfc5

    sub $c5
    jp nc, Jump_02c_7f8c

    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    ld c, a
    call z, Call_02c_7fcc
    ld a, a
    rst $08
    add $7f
    rst $10
    pop bc
    sub $c5
    adc l
    jp nc, $c4c9

    ret


    adc $55
    rst $00
    adc [hl]
    ld a, a
    jp nz, $c3c5

    rst $08
    call $d3c5
    ld a, a
    push de
    db $d3
    push bc
    pop bc
    jp nz, Jump_02c_55cc

    push bc
    ld a, a
    ld e, b
    ld a, a
    push bc
    sub $c5
    adc $7f
    call nc, $cfc8
    push de
    rst $00
    ret z

    ld a, a
    rst $10
    ret z

    ld d, l
    push bc
    adc $7f
    ret


    call nc, $c97f
    db $d3
    ld a, a
    adc $cf
    call nc, $c97f
    adc $7f
    jp $cf55


    adc $d4
    push bc
    db $d3
    call nc, Call_02c_557f
    adc [hl]
    ld e, b
    nop
    ld a, a
    xor c
    call nc, $c487
    ld a, a
    jp nz, Jump_02c_7fc5

    call nz, $c6c9
    add $c9
    jp $ccd5


    ld c, a
    call nc, $c67f
    rst $08
    jp nc, $d97f

    rst $08
    push de
    ld a, a
    call nc, Call_02c_7fcf
    jp $cecf


    call nc, $d255
    rst $08
    call z, Call_02c_7f8c
    ld e, b
    adc h
    ld d, h
    ld a, a
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
    call z, $c97f
    db $d3
    ld a, a
    ret z

    ret


    rst $00
    ret z

    push bc
    jp nc, $d47f

    ld d, l
    ret z

    pop bc
    adc $7f
    sub a
    sub b
    ld a, a
    jp nz, $d4d5

    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $10
    ld d, l
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    call z, $d6c5
    push bc
    call z, $c97f
    db $d3
    ld a, a
    jp nz, $ccc5

    ld d, l
    rst $08
    rst $10
    ld a, a
    sub a
    sub b
    ret


    db $d3
    ld a, a
    rst $00
    push bc
    adc $d4
    call z, Call_02c_7fc5
    ld d, c
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
    jp $c1c9


    call z, $d37f
    set 1, c
    call z, $cc4f
    db $d3
    ld a, a
    ld d, l
    ld a, a
    rst $08
    add $7f
    pop bc
    call z, Call_02c_7fcc
    ld a, a
    ld d, h
    ld a, a
    ret z

    pop bc
    sub $c5
    ld d, l
    ld a, a
    push bc
    adc $c8
    pop bc
    adc $c3
    push bc
    call nz, $d37f
    call z, $c7c9
    ret z

    call nc, Call_02c_55cc
    reti


    ld a, a
    ld e, b
    nop
    ld a, a
    and c
    call z, Call_02c_7fcc
    call nc, $c5c8
    ld a, a
    ld d, h
    ld a, a
    ld a, a
    rst $00
    push bc
    call nc, Call_02c_7f4f
    rst $00
    push bc
    adc $d4
    call z, Call_02c_7fc5
    pop bc
    adc $c4
    ld a, a
    rst $08
    jp nz, $c4c5

    ret


    ld d, l
    push bc
    adc $d4
    adc [hl]
    ld a, a
    ld e, b
    nop
    or b
    jp nc, $c2cf

    pop bc
    jp nz, $d9cc

    ld a, a
    pop bc
    ld a, a
    db $d3
    call nc, $c1d2
    adc $c7
    ld c, a
    push bc
    ld a, a
    add $cf
    jp nc, $c5c3

    ld a, a
    call $d9c1
    ld a, a
    call $d6cf
    push bc
    ld a, a
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, a
    ld bc, $df20
    nop
    ld c, a
    call nz, $ccc5
    push bc
    rst $00
    pop bc
    call nc, $c4c5
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cfc1
    nop
    add c
    ld a, a
    ld d, a
    nop
    xor b
    ret


    call nc, $c87f
    rst $08
    call $81c5
    ld a, a
    ld e, b
    nop
    ld e, d
    ld c, a
    ret


    db $d3
    ld a, a
    ret z

    pop bc
    jp nc, $c5cd

    call nz, $c27f
    reti


    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    ld d, l
    rst $08
    adc $81
    ld a, a
    ld e, b
    ld bc, $df20
    nop
    ld c, a
    db $d3
    push bc
    push bc
    call Call_02c_7fd3
    call z, $cbc9
    push bc
    ld a, a
    call nz, $ccc5
    push bc
    rst $00
    pop bc
    ld d, l
    call nc, $cec9
    rst $00
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cfc1
    nop
    ld d, l
    xor c
    db $d3
    ld a, a
    ld d, d
    ld a, a
    rst $10
    pop bc
    adc $d4
    ret


    adc $c7
    ld a, a
    ld d, l
    call nc, Call_02c_7fcf
    jp $c1c8


    adc $c7
    push bc
    ld a, a
    ld d, h
    sbc a
    ld a, a
    ld d, a
    nop
    and d
    push de
    call nc, $d47f
    ret z

    push bc
    ld a, a
    pop bc
    call nc, $c1d4
    jp Jump_02c_7fcb


    rst $08
    add $4f
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, h
    ret z

    pop bc
    db $d3
    adc $87
    call nc, $c87f
    ret


    ld d, l
    call nc, $c87f
    rst $08
    call $81c5
    ld a, a
    ld e, b
    nop
    xor c
    add a
    sub $c5
    ld a, a
    rst $10
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cecf


    call nc, $c54f
    db $d3
    call nc, $d77f
    ret


    call nc, Call_02c_7fc8
    ld d, l
    ld d, b
    ld bc, $df20
    nop
    add c
    ld a, a
    ld e, b
    nop
    ld e, c
    ld c, a
    ret z

    pop bc
    db $d3
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $c5
    call nz, Call_02c_7f81
    ld e, b
    nop
    xor c
    call nc, $c17f
    ret nc

    ret nc

    push bc
    pop bc
    jp nc, Jump_02c_7fd3

    call nc, $c1d2
    adc $d3
    call $c94f
    call nc, $cd7f
    pop bc
    jp $c9c8


    adc $c5
    jp nc, Jump_02c_7fd9

    rst $08
    adc $7f
    call nc, $c855
    push bc
    ld a, a
    db $d3
    jp $c5d2


    push bc
    adc $7f
    ld a, a
    rst $08
    add $7f
    ld e, e
    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    xor b
    rst $08
    rst $10
    ld a, a
    adc $c5
    rst $10
    ld a, a
    pop bc
    adc $c4
    ld a, a
    jp nz, $c9d2

    rst $00
    ret z

    ld c, a
    call nc, $c17f
    ld a, a
    jp nz, $c3c9

    reti


    jp $c5cc


    add c
    ld a, a
    ld d, a
    nop
    xor d
    rst $08
    push de
    jp nc, $c1ce

    call z, Call_02c_547f
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    sub $4f
    push bc
    jp nc, $d47f

    ret z

    push bc
    jp nc, $81c5

    ld a, a
    ld d, c
    ld d, [hl]
    ld a, a
    ld d, h
    ld a, a
    adc $cf
    call nc, $c2c5
    rst $08
    rst $08
    bit 7, a
    ld d, c
    ld d, [hl]
    ld a, a
    ld d, h
    ld a, a
    jp $c1c8


    jp nc, Jump_02c_7fd4

    pop bc
    adc $c4
    ld a, a
    ld c, a
    call nc, $c2c1
    call z, Call_02c_7fc5
    ld d, a
    nop
    xor b
    ret


    add c
    ld a, a
    xor b
    push bc
    call z, $cfcc
    add c
    xor c
    add a
    call $c17f
    ld a, a
    add $4f
    rst $08
    jp nc, $d5d4

    adc $c5
    adc l
    call nc, $ccc5
    call z, $d2c5
    adc [hl]
    ld a, a
    ld d, l
    or h
    ret z

    pop bc
    call nc, $c97f
    db $d3
    ld a, a
    call Call_02c_7fd9
    ret nc

    jp nc, $c6cf

    push bc
    db $d3
    ld d, l
    db $d3
    ret


    rst $08
    adc $7f
    call nc, Call_02c_7fcf
    call nz, $d6c9
    ret


    adc $c5
    ld a, a
    rst $08
    adc $55
    push bc
    add a
    db $d3
    ld a, a
    adc $c1
    call $c2c5
    reti


    ld a, a
    pop bc
    db $d3
    call nc, $cfd2
    call z, $cf55
    rst $00
    reti


    adc [hl]
    ld a, a
    ld d, c
    xor a
    res 1, h
    ld a, a
    xor h
    push bc
    call nc, $cd7f
    push bc
    ld a, a
    ret nc

    jp nc, $c3c1

    call nc, Call_02c_4fc9
    jp Jump_02c_7fc5


    pop bc
    ld a, a
    call nz, $d6c9
    ret


    adc $c1
    call nc, $cfc9
    adc $7f
    add $55
    rst $08
    jp nc, $c8d4

    push bc
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call Call_02c_7fc5
    rst $08
    add $55
    ld a, a
    reti


    rst $08
    push de
    jp nc, Jump_02c_7f7f

    ld d, h
    adc [hl]
    ld a, a
    ld d, a
    nop
    xor b
    call Call_02c_4f8c
    ld d, b
    ld bc, $cd68
    nop
    ld d, l
    ret z

    pop bc
    db $d3
    ld a, a
    adc $c1
    call $c4c5
    ld a, a
    pop bc
    ld a, a
    jp nc, $d4c1

    ret z

    push bc
    ld d, l
    jp nc, $c77f

    rst $08
    rst $08
    call nz, Call_02c_557f
    ld a, a
    adc $c9
    jp $cecb


    pop bc
    call $8ec5
    ld a, a
    ld d, c
    jp nz, $d4d5

    adc h
    ld a, a
    adc h
    ld a, a
    call z, $d4c5
    ld a, a
    call Call_02c_7fc5
    rst $00
    ret


    sub $4f
    push bc
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld a, a
    db $d3
    call z, $c7c9
    ret z

    call nc, $c27f
    push bc
    ld d, l
    call nc, $c5d4
    jp nc, $c1cd

    adc $c5
    add c
    ld a, a
    ld d, c
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
    ld a, a
    sbc a
    ld c, a
    ld a, a
    ld d, a
    nop
    or d
    push bc
    pop bc
    call z, $d9cc
    sbc a
    xor a
    res 1, h
    ld a, a
    db $d3
    push bc
    push bc
    ld a, a
    reti


    rst $08
    ld c, a
    push de
    ld a, a
    call nc, $cdcf
    rst $08
    jp nc, $cfd2

    rst $10
    adc [hl]
    ld a, a
    and e
    rst $08
    call Call_02c_7fc5
    ld d, l
    pop bc
    rst $00
    pop bc
    ret


    adc $8e
    ld a, a
    ld d, a
    nop
    and c
    jp nc, Jump_02c_7fc5

    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld a, a
    rst $00
    jp nc, $cf4f

    rst $10
    adc l
    ret nc

    jp nc, $cdcf

    rst $08
    call nc, $d2c5
    sbc a
    xor c
    call nc, $cd7f
    pop bc
    ld d, l
    reti


    ld a, a
    call $cbc1
    push bc
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    ret nc

    push bc
    push bc
    call nz, Call_02c_557f
    ld d, l
    ld a, a
    rst $08
    add $7f
    ld d, h
    ret


    adc $c3
    jp nc, $c1c5

    db $d3
    push bc
    ld a, a
    call $d555
    jp Jump_02c_7fc8


    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cecf


    call nc, $d3c5
    ld d, l
    call nc, Call_02c_7f8e
    ld d, a
    nop
    xor b
    push de
    adc $d4
    ret


    adc $c7
    ld a, a
    pop bc
    jp nc, $c1c5

    add c
    xor c
    db $d3
    adc $87
    ld c, a
    call nc, $d47f
    ret z

    push bc
    jp nc, Jump_02c_7fc5

    pop bc
    ld a, a
    jp $c1c8


    call $c9d0
    rst $08
    ld d, l
    adc $d3
    ret z

    ret


    ret nc

    ld a, a
    jp nc, $c4c5

    ld a, a
    jp nz, $cec1

    adc $c5
    jp nc, Jump_02c_557f

    call nc, Call_02c_7fcf
    ret z

    pop bc
    adc $c7
    ld a, a
    sbc a
    ld a, a
    ld d, c
    xor c
    db $d3
    adc $87
    call nc, $d47f
    ret z

    push bc
    jp nc, Jump_02c_7fc5

    push bc
    ret


    call nc, $c5c8
    ld c, a
    jp nc, $c17f

    adc $d9
    ld a, a
    call z, $cdc1
    ret nc

    sbc a
    or e
    call nc, $ccc9
    call z, Call_02c_557f
    jp $ccc1


    push bc
    adc $c4
    pop bc
    jp nc, Jump_02c_7f8c

    push bc
    ret


    call nc, $c5c8
    jp nc, Jump_02c_559f

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
    call nc, Call_02c_7fc8
    rst $08
    add $7f
    ld c, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c3c5

    rst $08
    sub $c5
    jp nc, $cec9

    rst $00
    ld d, l
    add c
    or h
    ret z

    push bc
    ld a, a
    jp $cec5


    call nc, $d2c5
    ld a, a
    ld d, h
    adc [hl]
    ld a, a
    ld d, l
    ld d, a
    nop
    or h
    ret z

    push bc
    jp nc, Jump_02c_7fc5

    pop bc
    jp nc, Jump_02c_7fc5

    call $cec1
    reti


    ld a, a
    rst $00
    rst $08
    ld c, a
    rst $08
    call nz, Call_02c_7fd3
    rst $08
    add $7f
    ld d, h
    add c
    ret


    adc $7f
    and [hl]
    jp nc, $55c9

    push bc
    adc $c4
    db $d3
    ret z

    ret


    ret nc

    ld a, a
    db $d3
    ret z

    rst $08
    ret nc

    adc [hl]
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
    call nc, Call_02c_7fc8
    rst $08
    add $7f
    ld c, a
    ld d, h
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c3c5

    rst $08
    sub $c5
    jp nc, $cec9

    rst $00
    ld d, l
    add c
    or h
    ret z

    push bc
    ld a, a
    jp $cec5


    call nc, $d2c5
    ld a, a
    ld d, h
    adc h
    ld a, a
    ld d, l
    ld d, a
    ld bc, $cd68
    nop
    ret z

    pop bc
    db $d3
    ld a, a
    jp nc, $c3c5

    rst $08
    sub $c5
    jp nc, $c4c5

    ld a, a
    pop bc
    rst $00
    pop bc
    ld c, a
    ret


    adc $8e
    ld a, a
    ld d, a
    nop
    ld e, [hl]
    ld a, a
    call nz, $c5d2
    pop bc
    call Call_02c_7fd3
    call nc, Call_02c_4fcf
    ld a, a
    db $d3
    push bc
    push bc
    bit 7, a
    ret z

    push bc
    rst $00
    push bc
    call $cecf
    reti


    ld a, a
    pop bc
    call z, $cc55
    ld a, a
    call nc, $c5c8
    ld a, a
    rst $10
    rst $08
    jp nc, $c4cc

    jp nz, Jump_02c_7fd9

    call nc, $c5c8
    ld d, l
    ld a, a
    call $c1c5
    adc $d3
    ld a, a
    rst $08
    add $7f
    ld d, h
    adc [hl]
    ld a, a
    ld d, a
    nop
    or h
    ret z

    rst $08
    db $d3
    push bc
    ld a, a
    add $c5
    call z, $cfcc
    rst $10
    db $d3
    ld a, a
    db $d3
    push de
    call nz, $c44f
    push bc
    adc $cc
    reti


    ld a, a
    jp nc, $d3d5

    ret z

    push bc
    call nz, $cf7f
    push de
    call nc, Call_02c_55c1
    adc $c4
    ld a, a
    rst $08
    jp $d5c3


    ret nc

    ret


    push bc
    call nz, $d47f
    ret z

    push bc
    ld a, a
    jp nz, $d555

    ret


    call z, $c9c4
    adc $c7
    adc h
    ld a, a
    ld d, a
    nop
    or e
    ret z

    pop bc
    set 1, c
    adc $c7
    add c
    ld a, a
    or e
    ret z

    ret


    sub $c5
    jp nc, $cec9

    ld c, a
    rst $00
    add c
    ld a, a
    ld d, [hl]
    xor l
    reti


    ld a, a
    and a
    rst $08
    call nz, Call_02c_7f81
    xor l
    reti


    ld a, a
    and e
    ld d, l
    ret z

    jp nc, $d3c9

    call nc, Call_02c_7f81
    or e
    pop bc
    sub $c5
    ld a, a
    call $81c5
    ld a, a
    ld d, a
    nop
    or h
    ret z

    push bc
    ld a, a
    rst $08
    adc $c5
    ld a, a
    adc $c5
    pop bc
    jp nc, $d9c2

    ld a, a
    ld c, a
    ld d, [hl]
    ld a, a
    ret


    db $d3
    ld a, a
    jp z, $d3d5

    call nc, $c17f
    ld a, a
    call $cec1
    adc h
    ld d, l
    ret


    call nc, $d27f
    push bc
    pop bc
    call z, $d9cc
    ld a, a
    call z, $d3cf
    push bc
    ld a, a
    add $c1
    ld d, l
    jp $81c5


    ld a, a
    ld d, a
    nop
    xor b
    ret


    add c
    ld a, a
    cp c
    rst $08
    push de
    adc h
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    ld c, a
    sub $c5
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd13
    nop
    sbc a
    ld a, a
    ld d, c
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
    call nc, Call_02c_7fcf
    push bc
    ret c

    ld c, a
    jp $c1c8


    adc $c7
    push bc
    ld a, a
    call Call_02c_7fd9
    ld d, l
    ld d, b
    ld bc, $cd19
    nop
    sbc a
    ld a, a
    ld d, a
    nop
    xor a
    ret z

    add c
    ld a, a
    xor a
    ret z

    add c
    and h
    rst $08
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    ret z

    pop bc
    sub $4f
    push bc
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd13
    nop
    ld d, l
    sbc a
    ld a, a
    ld d, c
    and e
    pop bc
    adc $7f
    reti


    rst $08
    push de
    ld a, a
    push bc
    ret c

    jp $c1c8


    adc $c7
    push bc
    ld a, a
    ld c, a
    ret


    call nc, $d77f
    ret


    call nc, Call_02c_7fc8
    call Call_02c_7fd9
    ld d, l
    ld d, b
    ld bc, $cd19
    nop
    sbc a
    ld a, a
    ld d, a
    nop
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    or a
    ret z

    pop bc
    call nc, $ae9f
    rst $08
    adc h
    ld a, a
    xor [hl]
    rst $08
    call nc, Call_02c_7f4f
    ld d, l
    ld d, b
    ld bc, $cd13
    nop
    ld d, l
    adc h
    ld a, a
    ld d, c
    or b
    call z, $c1c5
    db $d3
    push bc
    ld a, a
    set 0, l
    push bc
    ret nc

    ld a, a
    pop bc
    adc $7f
    push bc
    reti


    ld c, a
    push bc
    ld a, a
    ld d, a
    ld a, a
    rst $08
    adc $7f
    call nc, $c5c8
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    rst $10
    ret z

    ld d, l
    push bc
    adc $7f
    xor c
    ld a, a
    rst $00
    push bc
    call nc, $c97f
    call nc, Call_02c_578e
    nop
    xor c
    ld a, a
    ret


    db $d3
    ld a, a
    call z, $cfcf
    set 1, c
    adc $c7
    ld a, a
    add $cf
    jp nc, Jump_02c_4f7f

    ld c, a
    ld d, b
    ld bc, $cd13
    nop
    ld d, l
    add c
    ld a, a
    ld d, c
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
    ret


    call nc, $cd8c
    pop bc
    ld c, a
    reti


    ld a, a
    reti


    rst $08
    push de
    ld a, a
    jp $c1c8


    adc $c7
    push bc
    ld a, a
    ret


    call nc, $d47f
    ld d, l
    rst $08
    ld a, a
    ld d, l
    ld d, b
    ld bc, $cd19
    nop
    sbc a
    ld a, a
    ld d, a
    nop
    or a
    ret z

    pop bc
    call nc, $ae9f
    rst $08
    call nc, Call_02c_4f7f
    ld d, b
    ld bc, $cd13
    nop
    ld d, l
    adc h
    ld d, c
    adc h
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    jp $d4c1


    jp Jump_02c_7fc8


    adc h
    jp Jump_02c_4fcf


    call Call_02c_7fc5
    ret z

    push bc
    jp nc, Jump_02c_7fc5

    call nz, $d2c9
    push bc
    jp $ccd4


    reti


    add c
    ld d, l
    ld a, a
    ld d, a
    nop
    xor c
    add $7f
    call nc, $c1c8
    call nc, $c97f
    db $d3
    ld a, a
    db $d3
    rst $08
    adc h
    ld d, [hl]
    adc h
    ld c, a
    ld a, a
    rst $10
    ret z

    pop bc
    call nc, $d47f
    ret


    call Call_02c_7fc5
    rst $10
    ret


    call z, Call_02c_7fcc
    jp nz, $c555

    sbc a
    ld a, a
    ld d, a
    nop
    xor b
    ret


    add c
    ld a, a
    and c
    db $d3
    ld a, a
    reti


    rst $08
    push de
    ld a, a
    call z, $cbc9
    push bc
    adc [hl]
    ld a, a
    ld c, a
    ld d, [hl]
    ld d, a
    nop
    and h
    push de
    jp nc, $cec9

    rst $00
    ld a, a
    call nc, $c5c8
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ld a, a
    ld c, a
    adc h
    reti


    rst $08
    push de
    ld a, a
    jp $cec1


    add a
    call nc, $c17f
    call nc, $c1d4
    jp Jump_02c_55cb


    add c
    ld a, a
    ld d, c
    or l
    db $d3
    push bc
    ld a, a
    pop bc
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    adc l
    call nz, $d3c9
    ret nc

    push bc
    ld c, a
    call z, $c9cc
    adc $c7
    ld a, a
    call $d4c5
    ret z

    rst $08
    call nz, $d47f
    rst $08
    ld a, a
    call $c155
    set 0, l
    ret z

    ret


    call $cf7f
    ret nc

    push bc
    adc $7f
    ret z

    ret


    db $d3
    ld a, a
    push bc
    ld d, l
    reti


    push bc
    db $d3
    ld a, a
    ld e, b
    ld a, a
    ret


    add $7f
    ret z

    push bc
    ld a, a
    db $d3
    call nc, $ccc9
    call z, Call_02c_557f
    ret


    db $d3
    ld a, a
    db $d3
    call z, $c5c5
    ret nc

    ret


    adc $c7
    ld a, a
    adc [hl]
    ld e, b
    nop
    xor c
    add $7f
    reti


    rst $08
    push de
    ld a, a
    call nc, $cbc1
    push bc
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    ld c, a
    adc $7f
    adc h
    ld a, a
    reti


    rst $08
    push de
    jp nc, $d4d3

    jp nc, $cec5

    rst $00
    call nc, Call_02c_7fc8
    ld d, l
    rst $10
    ret


    call z, Call_02c_7fcc
    call nz, $c3c5
    jp nc, $c1c5

    db $d3
    push bc
    ld a, a
    ld d, c
    and l
    sub $c5
    adc $7f
    jp $cdcf


    ret nc

    push bc
    call nc, $d4c9
    ret


    rst $08
    adc $7f
    ld c, a
    push bc
    adc $c4
    db $d3
    ld a, a
    adc h
    call nc, $c5c8
    ld a, a
    ret nc

    rst $08
    ret


    db $d3
    rst $08
    adc $7f
    ld d, l
    db $d3
    call nc, $ccc9
    call z, $cd7f
    pop bc
    ret


    adc $d4
    pop bc
    ret


    adc $7f
    ld d, l
    cp c
    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    push de
    db $d3
    push bc
    ld a, a
    ld d, l
    pop bc
    adc $d4
    ret


    call nz, $d4cf
    push bc
    ld a, a
    call nc, Call_02c_7fcf
    jp nc, $ccc5

    ret


    push bc
    ld d, l
    sub $c5
    ld a, a
    ret


    call nc, Call_02c_7f81
    ld e, b
    nop
    xor c
    add $7f
    jp nz, $c9c5

    adc $c7
    ld a, a
    ret nc

    pop bc
    jp nc, $ccc1

    reti


    call nc, Call_02c_4fc9
    jp Jump_02c_7f8c


    call nc, $c5c8
    ld a, a
    db $d3
    set 1, c
    call z, $d3cc
    rst $08
    call $d4c5
    ld d, l
    ret


    call $d3c5
    ld a, a
    rst $10
    pop bc
    db $d3
    adc $87
    call nc, $c77f
    ret


    sub $c5
    adc $55
    ld a, a
    ret nc

    call z, $d9c1
    add c
    ld a, a
    ld d, c
    and l
    sub $c5
    adc $7f
    call nc, $c5c8
    ld a, a
    jp $cecf


    call nc, $d3c5
    call nc, Call_02c_4f7f
    ret z

    pop bc
    db $d3
    ld a, a
    add $c9
    adc $c9
    db $d3
    ret z

    push bc
    call nz, $a98c
    call nc, $d37f
    ld d, l
    call nc, $ccc9
    call z, $c87f
    pop bc
    db $d3
    ld a, a
    jp nc, $d3c5

    ret


    call nz, $c5d5
    ld a, a
    ld d, l
    rst $08
    add $7f
    ret nc

    pop bc
    jp nc, $ccc1

    reti


    db $d3
    ret


    db $d3
    adc [hl]
    ld a, a
    ld d, l
    and d
    push de
    call nc, $d97f
    rst $08
    push de
    ld a, a
    jp $cec1


    ld a, a
    jp $d2d5


    push bc
    ld a, a
    ld d, l
    ret


    call nc, $c27f
    reti


    ld a, a
    pop bc
    ld a, a
    call nz, $8dc5
    ret nc

    pop bc
    jp nc, $ccc1

    reti


    ld d, l
    cp d
    push bc
    call nz, $cd7f
    push bc
    call nc, $cfc8
    call nz, Call_02c_588e
    nop
    ld d, d
    ld a, a
    ret


    db $d3
    ld a, a
    rst $08
    ret nc

    push bc
    jp nc, $d4c1

    ret


    adc $4f
    rst $00
    ld a, a
    pop bc
    ld a, a
    jp $cdcf


    ret nc

    push de
    call nc, $d2c5
    add c
    ld a, a
    ld d, l
    ld d, [hl]
    adc h
    ld d, [hl]
    adc h
    ld a, a
    xor a
    res 0, c
    ld a, a
    ld d, l
    xor c
    call nc, $d387
    ld a, a
    call nc, $cdc9
    push bc
    ld a, a
    call nc, Call_02c_7fcf
    rst $00
    rst $08
    ld a, a
    rst $08
    ld d, l
    push de
    call nc, $c67f
    rst $08
    jp nc, $c17f

    ld a, a
    rst $10
    pop bc
    call z, $81cb
    ld a, a
    ld d, a
    nop
    xor b
    push bc
    jp nc, Jump_02c_7fc5

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
    ld c, a
    db $d3
    ld a, a
    db $d3
    call nc, $cecf
    push bc
    rst $08
    add $7f
    pop bc
    adc $c3
    ret


    push bc
    adc $d4
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    rst $00
    jp nc, $c5c5

    adc $7f
    jp nz, $c9d2

    db $d3
    call nc, Call_02c_55cc
    push bc
    adc l
    rst $00
    jp nc, $d3c1

    db $d3
    adc [hl]
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

Call_02c_7f4f:
    nop
    nop
    nop
    nop
    nop
    nop

Call_02c_7f55:
Jump_02c_7f55:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02c_7f7f:
Jump_02c_7f7f:
    nop
    nop

Call_02c_7f81:
Jump_02c_7f81:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02c_7f8c:
Jump_02c_7f8c:
    nop
    nop

Call_02c_7f8e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02c_7f9f:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Call_02c_7fc4:
Jump_02c_7fc4:
    nop

Call_02c_7fc5:
Jump_02c_7fc5:
    nop
    nop
    nop

Call_02c_7fc8:
Jump_02c_7fc8:
    nop
    nop
    nop

Jump_02c_7fcb:
    nop

Call_02c_7fcc:
    nop
    nop
    nop

Call_02c_7fcf:
    nop

Call_02c_7fd0:
    nop
    nop
    nop

Call_02c_7fd3:
Jump_02c_7fd3:
    nop

Jump_02c_7fd4:
    nop
    nop
    nop
    nop
    nop

Call_02c_7fd9:
Jump_02c_7fd9:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
