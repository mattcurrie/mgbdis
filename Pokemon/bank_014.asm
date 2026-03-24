; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $014", ROMX[$4000], BANK[$14]

    nop
    add hl, bc
    inc d
    dec a
    ld b, b
    ld h, e
    ld d, [hl]
    and b
    ld d, e
    add hl, bc
    ld [hl+], a
    ld h, h
    ld b, [hl]
    db $eb
    add $0a
    ld a, [bc]
    adc a
    nop
    ld l, c
    rlc c
    nop
    ld b, h
    rst $38
    add $0f
    inc d
    ld [$0300], sp
    rst $00
    ld [hl+], a
    ld b, b
    inc l
    ld bc, $0805
    nop
    pop bc
    ld bc, $070b
    inc bc
    ld [bc], a
    ld [bc], a
    add hl, bc
    dec e
    rst $38
    rst $38
    ld bc, $0902
    dec e
    rst $38
    rst $38
    ld [bc], a
    dec sp
    rst $00
    dec b
    ld [$2013], sp
    dec c
    dec c
    dec c
    dec c
    ld hl, $2c28
    inc l
    inc l
    inc l
    inc l
    inc l
    dec hl
    ld d, a
    ld d, a
    ld d, a
    ld a, [hl+]
    inc l
    dec sp
    ld l, b
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld l, c
    inc h
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    dec h
    rlca
    cpl
    rlca
    jr z, jr_014_4091

    add hl, hl
    scf
    ld a, l
    ld a, l
    ld a, [hl-]
    ld a, l
    ld a, [hl]
    inc de
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    inc h
    ld d, a
    add hl, hl
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    inc de
    rlca
    rlca
    rlca
    dec e
    ld e, $3e
    dec sp
    cpl
    rlca
    ld h, d
    ld a, [bc]
    ld a, [bc]
    add hl, hl
    rlca
    rlca
    rlca

jr_014_4091:
    rlca
    cpl
    rlca
    inc de
    dec bc
    dec bc
    dec bc
    ld h, l
    ld h, h
    jr z, jr_014_40c5

    dec bc
    dec bc
    ld c, [hl]
    ld bc, $2901
    ld sp, $5631
    ld [hl], a
    ld [hl], a
    ld [hl], a
    inc de
    dec bc
    dec bc
    dec bc
    ld d, l
    ld d, l
    jr z, jr_014_40d9

    dec bc
    dec bc
    ld c, [hl]
    ld bc, $293e
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    inc h
    dec h
    rlca

jr_014_40c5:
    cpl
    rlca
    rlca
    jr z, jr_014_40f3

    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l

jr_014_40d9:
    ld d, l
    ld d, l
    ld d, l
    jr z, jr_014_410a

    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    inc l
    nop
    add hl, bc

jr_014_40f3:
    ld [hl-], a
    ld a, l
    ld b, c
    ld bc, $8850
    ld c, a
    inc bc
    ld [$40de], sp
    sub b
    rst $00
    add hl, bc
    ld a, [bc]
    nop
    inc de
    ld [bc], a
    rst $00
    ld e, $a7
    ld c, a
    dec e

jr_014_410a:
    rst $00
    inc c
    ld a, [bc]
    inc h
    nop
    ld sp, hl
    add $13
    ld b, c
    ld b, e
    ld [bc], a
    dec b
    jr nc, jr_014_4118

jr_014_4118:
    ret nz

    add hl, bc
    ld a, [hl-]
    ld [bc], a
    ret nz

    ld [bc], a
    rlca
    inc sp
    dec bc
    dec bc
    add hl, sp
    inc c
    ld a, [bc]
    ld [hl+], a
    inc c
    ld e, e
    rst $38
    pop de
    ld b, c
    rst $10
    add hl, bc
    ld [hl+], a
    rrca
    ld c, b
    rst $38
    pop de
    ld b, d
    jp c, Jump_000_220f

    ld c, $31
    rst $38
    ret nc

    ld b, e
    jp c, Jump_000_2206

    ld [de], a
    dec sp
    rst $38
    db $d3
    ld b, h
    adc $18
    ld [hl+], a
    ld de, $ff2a
    ret nc

    ld b, l
    rst $10
    ld a, [bc]
    ld [hl+], a
    ld de, $ff5b
    pop de
    ld b, [hl]
    rst $10
    dec bc
    rlca
    dec c
    ld h, $ff
    pop de
    ld b, a
    rst $18
    dec bc
    ld [hl+], a
    dec bc
    dec e
    rst $38
    pop de
    ld c, b
    jp c, Jump_000_2207

    db $10
    inc e
    rst $38
    ret nc

    ld c, c
    adc $10
    ld [hl+], a
    inc c
    inc de
    rst $38
    pop de
    ld c, d
    jp c, $a908

    rst $00
    dec b
    jr nc, jr_014_4198

    ret z

    add hl, bc
    ld a, [hl-]
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e

jr_014_4198:
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld h, h
    ld a, $3f
    dec sp
    ld a, d
    ld a, d
    ld a, d
    ld a, d
    ld a, d
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld h, h
    inc h
    ld b, $25
    ld a, d
    ld a, d
    ld a, d
    ld a, d
    ld a, d
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld h, h
    ld a, d
    ld d, h
    ld [$7a7a], sp
    ld a, $3f
    dec sp
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld h, h
    ld a, d
    ld d, h
    ld a, d
    ld a, d
    ld a, d
    inc h
    ld b, $25
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld a, b
    ld a, b
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    dec l
    rra
    ld b, e
    rra
    rra
    ld l, d
    ld [$7a54], sp
    jr jr_014_42db

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    dec d
    rra
    ld b, e
    rra
    jr jr_014_430d

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_014_42db:
    ld l, $43
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    jr jr_014_433f

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_014_430d:
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    inc d
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e

jr_014_433f:
    rla
    ld c, b
    ld a, [bc]
    or d
    ld b, e
    ld h, $5a
    ld a, [hl-]
    ld e, c
    inc c
    add hl, bc
    add [hl]
    ld c, c
    db $eb
    add $0a
    ld a, [bc]
    ld de, $7900
    rst $00
    ld hl, $403d
    sbc e
    rrc l
    inc d
    nop
    nop
    inc bc
    rst $00
    ld h, c
    ld b, e
    rrca
    inc b
    adc e
    rlca
    ld [bc], a
    pop bc
    adc e
    ld [$c103], sp
    rra
    inc b
    nop
    ld l, h
    rra
    ld c, $01
    jp nz, $2101

    inc bc
    ld [$3107], sp
    daa
    ld [$d0ff], sp
    ld bc, $3c31
    ld c, $ff
    ret nc

    ld [bc], a
    ld [hl+], a
    ld e, c
    inc c
    rst $38
    ret nc

    inc bc
    ld [hl+], a
    ld h, h
    rrca
    rst $38
    ret nc

    inc b
    ld sp, $106d
    rst $38
    ret nc

    dec b
    ld sp, $0c7b
    rst $38
    ret nc

    ld b, $31
    adc h
    inc c
    rst $38
    ret nc

    rlca
    ld c, h
    res 1, e
    rlca
    ld c, l
    res 1, e
    ld [$c7eb], sp
    rra
    inc b
    ldh a, [$c7]
    rra
    ld c, $35
    rla
    ld [hl], $36
    ld b, e
    ld b, d
    dec [hl]
    dec [hl]
    rla
    ld [hl], $35
    rla
    ld [hl], $36
    ld b, e
    ld b, d
    dec [hl]
    dec [hl]
    rla
    ld [hl], $35
    ld [hl], $2b
    dec hl
    ld b, e
    ld b, d
    inc l
    inc l
    dec [hl]
    ld [hl], $35
    ld [hl], $41
    ld b, e
    ld b, d
    ld b, c
    ld b, c
    ld b, c
    dec [hl]
    ld [hl], $35
    ld [hl], $42
    ld b, c
    ld b, c
    ld b, e
    ld b, e
    ld b, e
    dec [hl]
    ld [hl], $35
    ld [hl], $43
    ld b, c
    ld b, e
    ld b, d
    ld b, c
    ld b, d
    dec [hl]
    ld [hl], $35
    ld [hl], $41
    ld b, e
    ld b, e
    ld b, e
    ld b, d
    ld b, c
    dec [hl]
    ld [hl], $35
    ld [hl], $43
    ld b, d
    ld b, d
    ld b, d
    ld b, d
    ld b, c
    dec [hl]
    ld [hl], $2c
    dec hl
    ld b, d
    ld b, c
    ld b, e
    ld b, d
    ld b, c
    ld b, d
    inc l
    dec hl
    ld b, c
    ld b, c
    ld b, e
    ld b, e
    ld b, e
    ld b, d
    ld b, d
    ld b, d
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    add hl, hl
    ld bc, $0101
    ld bc, $0101
    ld bc, $412a
    dec [hl]
    rla
    rla
    rla
    rla
    rla
    rla
    rla
    ld [hl], $41
    dec [hl]
    rla
    rla
    rla
    rla
    rla
    rla
    rla
    ld [hl], $41
    jr jr_014_445a

    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    dec de
    ld b, c
    inc e
    daa
    ld e, $27
    dec [hl]
    rla
    ld [hl], $1e
    rra
    ld b, c
    ld a, [bc]
    ld c, b
    ld a, [bc]
    ld a, [bc]
    jr jr_014_4472

    dec de
    ld b, c

jr_014_445a:
    ld b, c
    ld b, c
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    dec [hl]
    rla
    ld [hl], $01
    ld bc, $0a01
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr jr_014_4486

    dec de
    ld bc, $2a01
    ld a, [bc]
    ld a, [bc]

jr_014_4472:
    ld a, [bc]
    ld a, [bc]
    dec [hl]
    rla
    ld [hl], $17
    rla
    ld [hl], $0a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr @+$1c

    dec de
    ld a, [de]
    ld a, [de]
    dec de
    ld b, h
    ld a, [bc]

jr_014_4486:
    ld b, l
    ld a, [bc]
    inc l
    jr z, @+$2d

    jr z, jr_014_44b5

    dec hl
    jr @+$1c

    dec de
    ld a, [bc]
    ld [bc], a
    ld b, b
    ld a, [bc]
    ld bc, $0101
    inc l
    jr z, jr_014_44c6

    ld a, [bc]
    inc de
    ld d, $0a
    add hl, hl
    ld bc, $0a2a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr @+$1c

    dec de
    ld b, h
    ld a, [bc]
    ld b, l
    ld a, [bc]
    ld a, [bc]
    ld b, l
    ld a, [bc]
    dec [hl]
    rla

jr_014_44b5:
    ld [hl], $18
    ld a, [de]
    dec de
    ld a, [de]
    ld a, [de]
    dec de
    ld a, [bc]
    jr jr_014_44d9

    dec de
    dec [hl]
    rla
    ld [hl], $28
    jr z, jr_014_44f1

jr_014_44c6:
    ld a, [bc]
    dec [hl]
    rla
    ld [hl], $18
    ld a, [de]
    dec de
    ld b, b
    ld b, b
    ld a, [bc]
    ld a, [bc]
    jr jr_014_44ed

    dec de
    dec [hl]
    rla
    ld [hl], $40
    ld [bc], a

jr_014_44d9:
    ld a, [bc]
    ld d, $35
    rla
    ld [hl], $18
    ld a, [de]
    dec de
    ld d, $13
    ld b, b
    ld b, b
    jr jr_014_4501

    dec de
    dec [hl]
    rla
    ld [hl], $16
    inc de

jr_014_44ed:
    inc de
    ld d, $35
    rla

jr_014_44f1:
    ld [hl], $18
    ld a, [de]
    dec de
    ld b, b
    ld [bc], a
    ld a, [bc]
    ld d, $18
    ld a, [de]
    dec de
    dec [hl]
    rla
    ld [hl], $16
    ld b, b

jr_014_4501:
    inc de
    ld a, [bc]
    inc l
    jr z, jr_014_4531

    jr @+$1c

    dec de
    ld [bc], a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld b, b
    ld b, b
    ld b, b
    dec [hl]
    rla
    ld [hl], $02
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld b, h
    ld a, [bc]
    ld b, l
    jr jr_014_4536

    dec de
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    jr jr_014_453d

    dec de
    inc l
    jr z, @+$2d

    inc b
    inc b
    inc b
    inc b
    inc l
    jr z, jr_014_4559

    inc b
    inc b
    inc b

jr_014_4531:
    inc b
    inc b
    inc b
    inc b
    inc b

jr_014_4536:
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    ld b, [hl]

jr_014_453d:
    inc b
    inc b
    ld b, [hl]
    inc b
    ld b, a
    inc b
    inc b
    inc b
    inc b
    jr @+$1c

    ld a, [de]
    jr jr_014_4565

    dec de
    ld b, [hl]
    ld b, a
    inc b
    inc b
    inc l
    jr z, jr_014_457b

    dec [hl]
    rla
    ld [hl], $18
    dec de
    inc b

jr_014_4559:
    inc b
    inc b
    inc b
    inc b
    jr jr_014_4579

    dec de
    dec [hl]
    ld [hl], $04
    inc b
    inc b

jr_014_4565:
    inc b
    inc b
    dec [hl]
    rla
    ld [hl], $18
    dec de
    inc b
    inc b
    inc b
    inc b
    inc b
    jr jr_014_458d

    dec de
    inc l
    dec hl
    inc b
    inc d
    ld b, c

jr_014_4579:
    dec d
    inc b

jr_014_457b:
    dec [hl]
    rla
    ld [hl], $04
    inc b
    inc b
    jr c, jr_014_4595

    scf
    inc b
    jr jr_014_45a1

    dec de
    ld b, [hl]
    inc b
    inc b
    ld b, a
    inc b

jr_014_458d:
    inc b
    inc b
    dec [hl]
    rla
    ld [hl], $18
    ld a, [de]
    ld a, [de]

jr_014_4595:
    dec de
    inc b
    inc b
    inc b
    jr jr_014_45b5

    dec de
    inc l
    jr z, jr_014_45c7

    dec hl
    inc b

jr_014_45a1:
    inc b
    inc b
    inc l
    jr z, jr_014_45d1

    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    ld b, [hl]
    inc b
    inc b
    inc b
    ld b, a

jr_014_45b5:
    inc b
    inc b
    inc b
    ld b, [hl]
    ld b, a
    jr jr_014_45d6

    ld a, [de]
    ld a, [de]
    dec de
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr @+$1d

    inc l
    jr z, @+$2a

jr_014_45c7:
    jr z, jr_014_45f4

    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    inc l
    dec hl
    ld b, c
    ld b, c
    ld b, c

jr_014_45d1:
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c

jr_014_45d6:
    ld bc, $4101
    add hl, hl
    ld bc, $2a01
    ld bc, $0129
    ld bc, $412a
    jr @+$1c

    ld a, [de]
    dec de
    ld bc, $1a18
    ld a, [de]
    dec de
    ld b, c
    inc l
    jr z, jr_014_4618

    dec hl
    ld bc, $282c

jr_014_45f4:
    jr z, jr_014_4621

    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld bc, $0101
    ld bc, $2901
    ld bc, $2a01
    ld b, c
    add hl, hl
    ld bc, $012a
    ld a, [hl+]
    jr jr_014_4626

    ld a, [de]
    dec de
    ld b, c
    jr @+$1c

    dec de
    ld a, [de]
    dec de
    inc l
    jr z, jr_014_463f

    dec hl

jr_014_4618:
    ld b, c
    inc l
    jr z, @+$2d

    jr z, jr_014_4649

    ld bc, $0101

jr_014_4621:
    ld bc, $4141
    ld b, c
    ld b, c

jr_014_4626:
    ld b, c
    ld b, c
    add hl, hl
    ld bc, $0129
    ld a, [hl+]
    ld bc, $412a
    add hl, hl
    ld a, [hl+]
    jr jr_014_464e

    jr jr_014_4650

    dec de
    ld a, [de]
    dec de
    ld b, c
    jr @+$1d

    inc l
    jr z, @+$2e

jr_014_463f:
    jr z, jr_014_466c

    jr z, jr_014_466e

    ld b, c
    inc l
    dec hl
    ld bc, $0101

jr_014_4649:
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c

jr_014_464e:
    ld b, c
    ld b, c

jr_014_4650:
    add hl, hl
    ld bc, $412a
    ld b, c
    add hl, hl
    ld bc, $0101

jr_014_4659:
    ld a, [hl+]
    jr @+$1c

    dec de
    ld b, c
    ld b, c
    jr jr_014_467b

    ld a, [de]
    ld a, [de]
    dec de
    inc l
    jr z, jr_014_4692

    ld b, c
    ld b, c
    inc l
    jr z, jr_014_4694

jr_014_466c:
    jr z, jr_014_4699

jr_014_466e:
    ld bc, $3c3a
    inc a
    inc a
    inc a
    dec sp
    ld bc, $0101
    ld bc, $3d3e

jr_014_467b:
    dec a
    dec a
    dec a
    ccf
    ld bc, $0101
    nop
    ld [de], a
    ld a, [bc]
    rst $20
    ld b, [hl]
    ld sp, $935c
    ld e, e
    dec b
    inc bc
    ld [hl-], a
    ld c, b
    jr c, jr_014_4659

    db $10

jr_014_4692:
    inc d
    nop

jr_014_4694:
    ld a, [bc]
    inc bc
    rst $00
    inc h
    db $10

jr_014_4699:
    ld c, b
    dec h
    rst $00
    add hl, bc
    ld e, $00
    nop
    dec c
    rst $00
    and h
    ld b, [hl]
    inc l
    nop
    nop
    ld [$1307], sp
    rrca
    rst $38
    jp nc, $e641

    ld b, $07
    jr jr_014_46bc

    rst $38
    pop de
    ld b, d
    call Call_000_0702
    rla
    rrca
    rst $38

jr_014_46bc:
    jp nc, $cd43

    inc bc
    ld b, $1a
    ld c, $ff
    db $d3
    ld b, h
    rlc a
    inc b
    dec e
    rrca
    rst $38
    jp nc, $c945

    inc b
    ld b, $20
    ld c, $ff
    db $d3
    ld b, [hl]
    rrc b
    inc b
    inc hl
    rrca
    rst $38
    jp nc, $ca47

    add hl, bc
    dec a
    add hl, bc
    ld c, $ff
    rst $38
    adc b
    push af
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    dec hl
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    inc l
    add hl, hl
    ld sp, $3131
    ld sp, $3147
    ld e, b
    ld a, [bc]
    inc l
    add hl, hl
    ld a, [de]
    ld e, h
    ld a, [de]
    ld a, [de]
    ld c, e
    ld sp, $075a
    inc l
    add hl, hl
    ld sp, $3131
    ld sp, $3131
    ld sp, $2c31
    add hl, hl
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld sp, $5162
    ld d, c
    ld d, c
    inc l
    add hl, hl
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld sp, $0a4e
    ld a, $3f
    inc l
    add hl, hl
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld sp, $0a4e
    jr z, jr_014_4763

    inc l
    add hl, hl
    ld a, [bc]
    dec e
    ld l, d
    ld d, h
    ld c, [hl]
    ld a, [bc]
    jr z, jr_014_476d

    inc l
    add hl, hl
    dec bc
    ld h, l
    add hl, de
    ld d, h
    ld c, [hl]
    ld a, [bc]
    jr z, jr_014_4777

    inc l
    add hl, hl
    dec bc
    ld h, l
    add hl, de
    ld d, h
    ld c, [hl]
    ld a, [bc]
    inc h
    ld d, a
    inc l
    add hl, hl
    dec bc
    ld h, l
    add hl, de
    ld d, h
    ld c, [hl]
    ld c, l
    ld b, e
    ld b, e
    inc l
    add hl, hl
    dec bc
    ld h, l

jr_014_4763:
    add hl, de
    ld d, h
    ld c, [hl]
    ld c, l
    ld b, e
    ld b, e
    inc l
    add hl, hl
    dec bc
    ld h, l

jr_014_476d:
    add hl, de
    ld d, h
    ld c, [hl]
    ld c, l
    ld b, e
    ld b, e
    inc l
    add hl, hl
    dec bc
    ld h, l

jr_014_4777:
    add hl, de
    ld d, h
    ld c, [hl]
    ld c, l
    ld b, e
    ld b, e
    inc l
    add hl, hl
    dec bc
    ld h, l
    add hl, de
    ld d, h
    ld c, [hl]
    ld c, l
    ld b, e
    ld b, e
    inc l
    add hl, hl
    rra
    ld l, $19
    ld d, h
    ld c, [hl]
    ld c, l
    ld b, e
    ld b, e
    inc l
    add hl, hl
    ld b, e
    ld b, e
    add hl, de
    ld d, h
    ld c, [hl]
    ld c, l
    ld b, e
    ld b, e
    nop
    add hl, bc
    ld e, $10
    ld c, b
    ld c, a
    ld h, b
    ld a, [c]
    ld e, a
    ld [bc], a
    inc hl
    xor $46
    ld d, h
    rst $00
    inc c
    ld a, [bc]
    nop
    inc de
    ld [bc], a
    rst $00
    or d
    ld b, a
    inc l
    ld bc, $2d03
    nop
    ld e, b
    ld bc, $2b03
    dec bc
    ld a, [bc]
    inc b
    ld b, $12
    rst $38
    ret nc

    ld b, c
    ret


    dec b
    inc b
    add hl, bc
    ld d, $ff
    pop de
    ld b, d
    ret


    ld b, $07
    ld [$ff1c], sp
    ret nc

    ld b, e
    call Call_000_0602
    inc c
    ld d, $ff
    db $d3
    ld b, h
    rrc c
    inc b
    rlca
    inc h
    rst $38
    jp nc, $c945

    rlca
    ld b, $08
    add hl, hl
    rst $38
    ret nc

    ld b, [hl]
    rrc d
    ld c, $08
    inc c
    rst $38
    db $d3
    ld b, a
    pop de
    ld [bc], a
    ld c, $0d
    dec de
    rst $38
    pop de
    ld c, b
    pop de
    inc bc
    ld c, $0b
    ld de, $d3ff
    ld c, c
    pop de
    inc b
    dec a
    ld b, $1a
    rst $38
    rst $38
    adc d
    db $db
    ld b, a
    rst $00
    inc bc
    dec l
    inc l
    inc l
    inc l
    inc l
    dec hl
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    dec h
    jr c, jr_014_4861

    inc h
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    dec h
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    dec h
    ld l, [hl]
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld h, b
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld c, l
    ld [hl], a
    ld [hl], a
    ld d, [hl]
    inc a
    dec a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld d, d
    ld b, e
    ld b, e
    ld a, [bc]
    dec bc
    dec bc
    dec bc
    ld a, [bc]
    ld a, [bc]
    ld c, h
    ld c, h
    ld c, h
    ld a, [bc]
    ld l, [hl]
    ld l, h
    ld l, [hl]
    ld [hl], h
    ld [hl], h
    ld l, [hl]
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h

jr_014_4861:
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld a, [bc]
    ld a, [bc]
    ld c, l
    ld b, e
    ld b, e
    rlca
    rlca
    rlca
    rlca
    ld c, h
    ld l, h
    ld c, h
    ld a, [bc]
    ld l, l
    ld l, h
    ld l, [hl]
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld l, a
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld a, [bc]
    ld a, [bc]
    ld c, l
    ld b, e
    ld b, e
    ld sp, $3131
    ld sp, $6d31
    ld l, h
    ld a, [bc]
    ld l, l
    ld c, h
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld l, l
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    dec e
    rra
    rra
    ld d, h
    ld d, h
    rra
    rra
    ld e, $4d
    ld b, e
    ld b, e
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld h, l
    ld b, e
    ld b, e
    ld d, h
    ld d, h
    ld b, e
    ld b, e
    ld h, h
    ld c, l
    ld b, e
    ld b, e
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    dec sp
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld c, a
    ld b, e
    ld b, e
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    add hl, hl
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld b, e
    ld b, e
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    add hl, hl
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    rla
    add hl, bc
    ld a, [bc]
    ld c, d
    ld c, c
    ld [hl], $49
    dec [hl]
    ld c, c
    inc b
    ld [hl+], a
    or d
    ld b, e
    xor e
    rst $00
    ld a, [bc]
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $36
    ld c, c
    ret


    ld c, $02
    dec b
    add hl, bc
    nop
    xor [hl]
    dec b
    ld a, [bc]
    nop
    xor [hl]
    nop
    nop
    dec e
    rst $00
    dec b
    add hl, bc
    ld e, $c7
    dec b
    ld a, [bc]
    jr @+$1c

    ld a, [de]
    ld hl, $1717
    ld [hl+], a
    ld a, [de]
    ld a, [de]
    dec de
    inc e
    daa
    inc e
    jr jr_014_4973

    ld a, [de]
    dec de
    rra
    daa
    rra
    ld bc, $0101
    inc e
    dec e
    ld e, $1f
    ld bc, $0101
    add hl, hl
    add hl, hl
    add hl, hl
    ld bc, $4243
    ld bc, $2a2a
    ld a, [hl+]
    inc l

jr_014_4973:
    inc l
    inc l
    jr z, @+$45

    ld b, d
    jr z, jr_014_49a5

    dec hl
    dec hl
    add hl, hl
    add hl, hl
    add hl, hl
    ld bc, $4243
    ld bc, $2a2a
    ld a, [hl+]
    inc l
    inc l
    inc l
    jr z, jr_014_49ce

    ld b, d
    jr z, jr_014_49b9

    dec hl
    dec hl
    add hl, hl
    add hl, hl
    add hl, hl
    ld bc, $4243
    ld bc, $2a2a
    ld a, [hl+]
    inc l
    inc l
    inc l
    jr z, jr_014_49e2

    ld b, d
    jr z, jr_014_49cd

    dec hl
    dec hl
    nop

jr_014_49a5:
    ld [de], a
    inc d
    sbc b
    ld c, d
    inc bc
    ld c, h
    nop
    ld c, h
    rrca
    db $10
    adc b
    ld b, [hl]
    ldh a, [$c6]
    ld a, [bc]
    ld a, [bc]
    inc hl
    or $09
    ret z

jr_014_49b9:
    ld de, $4095
    ld [de], a
    ret


    ld a, [bc]
    ld a, [bc]
    nop
    or $f9
    add $12
    sbc b
    ld b, b
    sbc [hl]
    rst $00
    add hl, bc
    ld a, [bc]
    ld hl, sp+$13

jr_014_49cd:
    ld [bc], a

jr_014_49ce:
    rst $00
    inc de
    ld [c], a
    ld b, c
    or l
    rst $00
    add hl, bc
    ld e, $f8
    nop
    dec c
    rst $00
    call c, Call_000_0f49
    ld [$0705], sp
    nop
    xor a

jr_014_49e2:
    inc bc
    ld a, [de]
    nop
    or c
    inc bc
    ld [hl+], a
    nop
    or d
    dec bc
    dec c
    nop
    or e
    dec bc
    add hl, de
    nop
    or h
    dec d
    ld [de], a
    nop
    or l
    dec e
    add hl, bc
    nop
    or [hl]
    dec e
    dec e
    nop
    or a
    ld a, [bc]
    dec b
    ld de, $0510
    dec de
    ld de, $2305
    ld [de], a
    dec bc
    ld a, [de]
    inc de
    inc de
    daa
    inc d
    dec d
    dec b
    dec d
    dec d
    rrca
    ld d, $1d
    ld a, [bc]
    rla
    dec e
    dec de
    jr jr_014_4a2e

    ld bc, $0f19
    jr jr_014_4a2a

    dec bc
    rst $38
    rst $38
    ld bc, $0c18

jr_014_4a26:
    jr jr_014_4a26

    ld [bc], a
    ld [bc], a

jr_014_4a2a:
    jr @+$0a

    ld h, $ff

jr_014_4a2e:
    rst $38
    inc bc
    jr @+$12

    ld de, $ffff
    inc b
    jr jr_014_4a55

    rrca
    cp $02
    dec b
    jr @+$13

    inc h
    cp $02
    ld b, $18
    ld [hl+], a
    ld d, $fe
    ld [bc], a
    rlca
    jr nz, jr_014_4a5c

    inc c
    cp $00
    ld [$1b2c], sp
    dec de
    rst $38
    rst $38
    add hl, bc
    dec de

jr_014_4a55:
    ld [hl+], a
    dec d
    cp $02
    ld a, [bc]
    db $10
    db $10

jr_014_4a5c:
    ld [hl+], a
    rst $38
    ret nc

    dec bc
    add hl, bc
    db $10
    inc hl
    rst $38
    ret nc

    inc c
    ld hl, $160c
    rst $38
    pop de
    dec c
    jr jr_014_4a88

    ld d, $ff
    ret nc

    ld c, $18
    ld a, [de]
    rla
    rst $38
    ret nc

    rrca
    ld a, [hl-]
    rst $00
    dec b
    rlca
    ld a, [hl+]
    rst $00
    inc bc
    ld a, [de]
    ld l, $c7
    inc bc
    ld [hl+], a
    adc e
    rst $00
    dec bc
    dec c

jr_014_4a88:
    sub c
    rst $00
    dec bc
    add hl, de
    db $10
    ret z

    dec d
    ld [de], a
    ld [hl], e
    ret z

    dec e
    add hl, bc
    ld a, l
    ret z

    dec e
    dec e
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld c, a
    ld d, d
    ld d, d
    ld d, d
    ld sp, $0c31
    dec c
    ld c, $0c
    dec c
    dec c
    ld c, $38
    add hl, sp
    ld c, [hl]
    jr c, jr_014_4ae8

    jr c, jr_014_4aea

    jr c, jr_014_4aec

    ld sp, $3131
    ld sp, $1110
    ld [de], a
    db $10
    ld de, $1211
    stop
    ld c, [hl]
    stop
    inc a
    dec a
    stop
    ld [hl], a
    ld d, [hl]
    ld [hl], a
    ld sp, $7731
    ld d, [hl]
    ld [hl], a
    ld sp, $5677
    ld [hl], a
    ld c, l
    ld c, [hl]
    ld c, c
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld c, b
    ld c, l

jr_014_4ae8:
    ld c, [hl]
    daa

jr_014_4aea:
    jr c, jr_014_4b25

jr_014_4aec:
    jr c, jr_014_4b27

    jr c, jr_014_4b29

    ld sp, $3131
    ld sp, $2120
    jr c, jr_014_4b31

    jr c, jr_014_4b33

    daa
    ld c, l
    ld a, [bc]
    daa
    stop
    stop
    inc a
    dec a
    jr nz, jr_014_4b13

    dec c
    ld hl, $737c
    stop
    stop
    daa
    ld c, l
    ld a, [bc]
    ld h, $23

jr_014_4b13:
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld l, b
    ld a, a
    ld a, a
    ld l, c
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld [hl+], a
    ld c, l
    ld a, [bc]

jr_014_4b25:
    daa
    ld d, l

jr_014_4b27:
    ld d, l
    ld d, l

jr_014_4b29:
    ld d, l
    ld d, l
    ld d, l
    ld l, b
    ld a, a
    ld a, a
    ld l, c
    ld d, l

jr_014_4b31:
    ld d, l
    ld d, l

jr_014_4b33:
    ld d, l
    ld d, l
    ld d, l
    daa
    ld c, l
    ld bc, $3127
    jr nz, jr_014_4b5e

    jr nz, jr_014_4b60

    ld sp, $7f68
    ld a, a
    ld l, c
    jr nz, jr_014_4b67

    jr nz, jr_014_4b69

    jr nz, jr_014_4b6b

    daa
    ld bc, $2256
    ld sp, $6968
    ld l, b
    ld l, c
    ld sp, $7f68
    ld a, a
    ld l, c
    ld l, b
    ld l, c
    ld l, b
    ld l, c
    ld l, b
    ld l, c

jr_014_4b5e:
    ld h, $56

jr_014_4b60:
    ld a, [bc]
    daa
    ld d, [hl]
    scf
    ld a, [hl]
    scf
    ld a, [hl]

jr_014_4b67:
    ld d, [hl]
    scf

jr_014_4b69:
    ld a, [hl-]
    ld a, l

jr_014_4b6b:
    ld a, [hl]
    scf
    ld a, [hl]
    scf
    ld a, [hl]
    scf
    ld a, [hl]
    daa
    ld c, l
    ld a, [bc]
    ld h, $23
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld [hl+], a
    ld c, l
    ld c, [hl]
    daa
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    daa
    ld c, l
    ld c, [hl]
    daa
    jr c, @+$3b

    jr nz, jr_014_4bc3

    jr c, @+$3b

    jr c, @+$3b

    jr c, @+$3b

    ld sp, $2031
    ld hl, $3938
    daa
    ld c, l
    ld c, [hl]
    daa
    stop
    ld a, h
    ld [hl], d
    stop
    stop
    stop
    ld [hl], a
    ld d, [hl]
    ld a, h
    ld a, [hl]
    stop
    daa

jr_014_4bc3:
    ld c, l
    ld c, [hl]
    ld b, h
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld b, l
    ld c, l
    jr nz, @+$23

    jr c, jr_014_4c15

    jr c, jr_014_4c17

    jr c, jr_014_4c19

    jr c, jr_014_4c1b

    ld sp, $3831
    add hl, sp
    jr c, jr_014_4c21

    jr c, jr_014_4c23

    jr nz, jr_014_4c0d

    scf
    ld a, [hl]
    stop
    stop
    stop
    stop
    ld a, [bc]
    ld [hl], a
    stop
    stop
    stop
    scf
    ld a, [hl]
    jp Jump_000_3c6c


    dec [hl]
    ld c, h
    ld c, c
    ld c, h
    ld h, e
    ld c, h
    add b
    ld c, h
    sbc b
    ld c, h

jr_014_4c0d:
    or c
    ld c, h
    call $fe4c
    ld c, h
    ld a, [de]
    ld c, l

jr_014_4c15:
    ccf
    ld c, l

jr_014_4c17:
    ld [hl], c
    ld c, l

jr_014_4c19:
    cp d
    ld c, l

jr_014_4c1b:
    ret


    ld c, l
    ldh a, [rKEY1]
    ld a, [de]
    ld c, [hl]

jr_014_4c21:
    dec a
    ld c, [hl]

jr_014_4c23:
    ld e, l
    ld c, [hl]
    ld l, d
    ld c, [hl]
    sub [hl]
    rrca
    adc [hl]
    ld c, [hl]
    rst $28
    ld c, [hl]
    ld c, c
    ld c, a
    xor a
    rrca
    ld e, h
    ld c, a
    ld l, d
    ld c, a
    db $ed
    ld [hl+], a
    add [hl]
    ld e, l
    jp hl


    rst $20
    ld c, a
    ld a, $b3
    dec l
    rst $20
    ld a, a
    or c
    rst $18
    pop bc
    ld a, a
    or d
    cp c
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    or a
    ld e, l
    ld a, a
    cp d
    ret


    ld a, a
    rst $08
    pop bc
    db $dd
    ld c, a
    ld e, [hl]
    ret


    ld a, a
    db $d3
    ret


    add $7f
    cp l
    reti


    rst $18
    jp $f4d6


    ld d, a
    db $ed
    ld [hl+], a
    db $ec
    ld e, l
    ld a, a
    or l
    jp c, $c1c0

    add $7f
    cp e
    or [hl]
    rst $10
    or e
    call nz, $b24f
    ret nz

    or d
    ld a, a
    jp nc, Jump_014_7fc6

    or c
    or e
    cpl
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    scf
    ld e, [hl]
    add [hl]
    ld a, a
    adc e
    sub d
    or b
    ld a, a
    ld a, [hl+]
    call nz, $5e4f
    ld h, $7f
    ret


    rst $18
    call nz, $c0df
    ld l, $e7
    ld d, a
    db $ed
    ld [hl+], a
    ld h, h
    ld e, [hl]
    ld a, a
    cp d
    call nz, $d47f
    ret c

    rst $08
    cp b
    reti


    call nz, $8c4f
    add l
    xor h
    call nz, $bd7f
    reti


    ld l, $e7
    ld d, a
    db $ed
    ld [hl+], a
    sbc a
    ld e, [hl]
    rst $20
    ld a, a
    cp d
    ret


    ld a, a
    call nc, $e7db
    ld c, a
    inc [hl]
    cp d
    ld a, a
    ret nc

    jp $b17f


    reti


    or d
    jp Jump_000_30de


    sub $e7
    ld d, a
    db $ed
    ld [hl+], a
    dec b
    ld e, a
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    ld a, a
    ret


    rst $18
    call nz, $c0df
    rst $10
    ld c, a
    cp [hl]
    or [hl]
    or d
    ld a, a
    inc l
    pop hl
    or e
    add $7f
    ld d, h
    ld a, a
    or e
    rst $18
    jp Jump_000_0555


    add hl, de
    dec b

jr_014_4cf1:
    add hl, de
    ld a, a
    or l
    or l
    ld a, a
    db $d3
    or e
    cp c
    ld a, a
    jr nc, jr_014_4d2a

    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld l, d
    ld e, a
    rst $18
    jp nz, $c0b9

    ret


    ld c, a
    ret nz

    rst $18
    ret nz

    ld a, a
    set 0, h
    ret c

    ld a, a
    jr nc, jr_014_4cf1

    jp Jump_014_7f56


    cp l
    ld a, [hl+]
    or d
    push bc
    ld d, a
    db $ed
    ld [hl+], a
    jp $e35f


    or d
    rst $20
    ld c, a
    ld e, [hl]
    ld h, $7f
    or d
    push bc
    cp b
    push bc
    rst $18

jr_014_4d2a:
    ret nz

    rst $20
    ld d, l
    ld a, [de]
    ld a, [de]
    rst $10
    push bc
    or d
    inc sp
    ld a, a
    cp a
    call nz, $b17f
    reti


    cp c
    reti


    sbc $30
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    add hl, de
    ld h, b
    add [hl]
    ld a, a
    adc e
    sub d
    or b
    db $d3
    ld a, a
    or d
    pop bc
    inc l
    jp z, $cb4f

    call nz, Call_014_7f26
    add $29
    jp $cd7f


    rst $18
    pop bc
    ldh [$df], a
    ret nz

    ld a, a
    cp c
    inc [hl]
    ld d, l
    add $27
    call nc, $c5b6
    ld a, a
    rst $08
    pop bc
    add $7f
    db $d3
    inc [hl]
    reti


    call c, Call_014_57e7
    db $ed
    ld [hl+], a
    xor b
    ld h, b
    adc e
    and [hl]
    sbc e
    and d
    xor h
    or l
    and l
    ld d, b
    ld a, a
    ld a, a
    ld a, a
    xor a
    or d
    and c
    xor [hl]
    and a
    and l
    ld d, b
    ld a, a
    or d
    and c
    xor c
    xor [hl]
    and d
    xor a
    or a
    ld d, b
    or b
    xor c
    xor [hl]
    xor e
    ld d, b
    ld a, a
    ld a, a
    ld a, a
    and a
    xor a
    xor h
    and h
    and l
    xor [hl]
    ld d, b
    ld a, a
    and a
    or d
    xor c
    xor l
    or e
    xor a
    xor [hl]
    ld d, b
    and a
    or d
    and l
    and l
    xor [hl]
    ld d, b
    ld a, a
    ld a, a
    ret


    ld a, a
    and d
    dec bc
    add d
    sbc l
    ld a, a
    inc sp
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld h, c
    ld h, c
    xor h
    sub e
    ld [hl], d
    ld a, [de]
    ld a, [de]
    db $e3
    xor h
    rst $20
    ld d, b
    dec d
    ld d, b
    db $ed
    ld [hl+], a
    ld [hl], b
    ld h, c
    ret nc

    ret nz

    ld l, $e7
    ld a, a
    adc e
    and [hl]
    sbc e
    ret


    ld a, a
    ld a, [de]
    and [hl]
    ld a, a
    or [hl]
    rst $10
    ld c, a
    xor b
    adc b
    xor h
    sub e
    ret


    ld a, a
    inc e
    adc h
    ld h, $7f
    add $29
    jp $b27f


    cp b
    ret


    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    or [hl]
    ld h, c
    jp z, $b97f

    or d
    dec sp
    or d
    sbc $30
    ld h, $4f
    or c
    call nc, $b2bc
    ld a, a
    cp d
    inc [hl]
    db $d3
    jp z, $c451

    or l
    cp [hl]
    sbc $3e
    ld a, a
    cp l
    reti


    cp d
    call nz, Call_014_7fc6
    cp h
    jp $c9d9


    jr nc, jr_014_4e71

    db $ed
    ld [hl+], a
    ld [bc], a
    ld h, d
    ld a, a
    ld d, [hl]
    ld c, a
    ld d, [hl]
    cp d
    rst $18
    cp b
    ret c

    ld a, a
    cp d
    rst $18
    cp b
    ret c

    ld d, c
    cp h
    jp nc, $d2bc

    rst $20
    ld a, a
    or d
    ret z

    pop de
    ret c

    ld a, a
    cp h
    jp $d9b2


    cpl
    ld d, a
    db $ed
    ld [hl+], a
    inc sp
    ld h, d
    ld a, a
    and d
    sbc l
    dec de
    add [hl]
    ld a, a
    adc e
    sub d
    or b
    ld c, a
    and d
    sbc l
    dec de
    add [hl]
    ld a, a
    or a
    sbc $b2
    db $db
    ld a, a
    or [hl]
    ld h, $d4
    or a
    ret


    or d
    db $db
    ld d, a
    db $ed
    ld [hl+], a
    ld [hl], l
    ld h, d
    or e
    ld a, a
    inc [hl]
    or e
    inc l
    ld [c], a
    or e
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    add [hl]
    ld h, d
    add [hl]
    ld a, a
    adc e

jr_014_4e71:
    sub d
    or b
    ld a, a
    ld d, h
    ld a, a
    dec bc
    sbc a
    ld c, a
    ret c

    db $e3
    rrca
    db $e3
    ld a, a
    sub h
    sub c
    and b
    ld d, l
    add e
    adc h
    ld b, b
    db $e3
    ld a, a
    cp h
    ld [c], a
    or e
    inc l
    ld [c], a
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    cp a
    ld h, d
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    push bc
    sbc $33
    db $d3
    ld a, a
    push bc
    or l
    cp h
    jp z, $c84f

    pop de
    ret c

    ld a, a
    inc [hl]
    cp b
    ld a, a
    call nc, Call_000_34b9
    ld a, a
    cp d
    or l
    ret c

    ld d, [hl]
    ld d, l
    push bc
    sbc $33
    db $d3
    ld a, a
    push bc
    or l
    cp h
    rst $08
    cp l
    rst $20
    ld d, c
    cp l
    cp d
    cp h
    ld a, a
    ret nz

    or [hl]
    or d
    ld a, a
    cp c
    inc [hl]
    ld c, a
    ret z

    pop de
    cp c
    dec hl
    rst $08
    cp h
    ld a, a
    inc [hl]
    cp b
    cp c
    cp h
    ld a, a
    push bc
    inc [hl]
    db $dd
    ld d, l
    add hl, de
    and l
    add hl, de
    and l
    add $7f
    or [hl]
    or e
    sub $d8
    ld a, a
    rst $10
    cp b
    pop bc
    sbc $e7
    ld d, a
    db $ed
    ld [hl+], a
    or h
    ld h, e
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    cp h
    sbc $be
    or d
    set 3, [hl]
    ld a, a
    adc h
    db $e3
    ld b, b
    db $e3
    inc e
    db $e3
    and [hl]
    jp z, $a14f

    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    ld a, a
    sub $d8
    ld a, a
    or [hl]
    cp b
    inc l
    jp nz, Jump_014_55c6

    ld d, h
    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    rst $08
    cp l
    rst $20
    ld d, c
    push bc
    or [hl]
    push bc
    or [hl]
    ld a, a
    jp nz, $cfb6

Call_014_4f33:
Jump_014_4f33:
    or h
    ld a, a
    rst $10
    jp c, $b2c5

    ld c, a

Jump_014_4f3a:
    ld d, h
    add $ca
    ld a, a
    cp d
    pop bc
    rst $10
    db $dd
    ld a, a
    ret nz

    jp nc, $b3bf

    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld e, c
    ld h, h
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    ld a, a
    adc $de

Jump_014_4f56:
    cp h
    ldh [$7f], a
    ld a, [de]
    and [hl]
    ld d, a
    db $ed
    ld [hl+], a
    adc a
    ld h, h
    db $e3
    ld a, a
    or l
    call nc, $c92c
    ld a, a
    or d
    or h
    ld d, a
    db $ed
    ld [hl+], a
    or b
    ld h, h
    ld a, a
    or e
    call c, $c9bb
    ld a, a
    cp h
    sbc $be
    or d
    set 3, [hl]
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    jp z, $3ac2

    or d
    dec sp
    ld a, a
    ret nc

    jp Jump_014_57b2


    ld hl, $d766
    bit 0, [hl]
    res 0, [hl]
    call nz, Call_014_4fa5
    call Call_000_3c6c
    ld hl, $5019
    ld de, $4ffb
    ld a, [$d5a7]
    call Call_000_31a8
    ld [$d5a7], a
    ret


Call_014_4fa5:
    ld a, [$d7ff]
    and $03
    cp $03
    jr z, jr_014_4fce

    ld a, $d7
    call Call_014_4feb
    ld a, $d8
    call Call_014_4feb
    ld hl, $4fc7

jr_014_4fbb:
    ld a, [hl+]
    cp $ff

Call_014_4fbe:
    jr z, jr_014_4fce

    push hl
    call Call_014_4ff3
    pop hl
    jr jr_014_4fbb

    reti


    jp c, $dcdb

    rst $18
    ldh [rIE], a

jr_014_4fce:
    ld a, [$d800]
    and $03

Jump_014_4fd3:
    cp $03
    ret z

    ld a, $dd
    call Call_014_4feb
    ld a, $de
    call Call_014_4feb
    ld a, $e1
    call Call_014_4ff3
    ld a, $e2

Jump_014_4fe7:
    call Call_014_4ff3
    ret


Call_014_4feb:
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


Call_014_4ff3:
    ld [$cc4d], a
    ld a, $11
    jp Jump_000_3e9d


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    sub d
    ld d, b
    sbc $50
    daa
    ld d, c
    ld l, l
    ld d, c
    or b
    ld d, c
    push af
    ld d, c
    dec sp
    ld d, d
    add b
    ld d, d
    push de
    ld d, d
    dec [hl]
    ld d, e
    sbc c
    ld d, e
    sbc c
    ld d, e
    ld bc, $6640
    rst $10
    sbc h
    ld d, b
    jp $bb50


    ld d, b
    cp e
    ld d, b
    ld [bc], a
    ld b, b
    ld h, [hl]
    rst $10
    add sp, $50
    ld a, [bc]
    ld d, c
    rst $38
    ld d, b
    rst $38
    ld d, b
    inc bc
    jr nz, @+$68

    rst $10
    ld sp, $5651
    ld d, c
    ld c, h
    ld d, c
    ld c, h
    ld d, c
    inc b
    ld b, b
    ld h, [hl]
    rst $10
    ld [hl], a
    ld d, c
    sub d
    ld d, c
    adc b
    ld d, c
    adc b
    ld d, c
    dec b
    jr nc, @+$68

    rst $10
    cp d
    ld d, c
    jp c, $d151

    ld d, c
    pop de
    ld d, c
    ld b, $40
    ld h, [hl]
    rst $10
    rst $38
    ld d, c
    dec h
    ld d, d
    inc e
    ld d, d
    inc e
    ld d, d
    rlca
    jr nz, @+$68

    rst $10
    ld b, l
    ld d, d
    ld h, l
    ld d, d
    ld e, e
    ld d, d
    ld e, e
    ld d, d
    ld [$6640], sp
    rst $10
    adc d
    ld d, d
    or e
    ld d, d
    and b
    ld d, d
    and b
    ld d, d
    add hl, bc
    jr nc, jr_014_50e2

    rst $10
    rst $18
    ld d, d
    ld bc, $fb53
    ld d, d
    ei
    ld d, d
    ld a, [bc]
    ld b, b
    ld h, [hl]
    rst $10
    ccf
    ld d, e
    ld [hl], a
    ld d, e
    ld l, l
    ld d, e
    ld l, l
    ld d, e
    rst $38
    ld [$1921], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    db $fd
    ld c, c
    cp e
    add $7f
    push bc
    rst $18
    jp $7fd9


    or [hl]
    rst $10
    ld c, a
    or l
    sub $b2
    inc sp
    reti


    ld a, a
    set 0, h
    db $d3
    ld a, a
    or l
    or l
    or d
    sub $e7
    ld d, a
    db $ed
    inc h
    ld h, h
    ld c, d
    db $e3
    xor h
    rst $20
    ld e, b
    db $ed
    inc h
    jr nz, jr_014_5111

    ld a, a
    ld d, h
    add $7f
    ret


    rst $18
    jp $4fc3


    jp nz, $dab6

    ld a, a
    push bc
    or d
    or [hl]
    rst $10
    ld a, a
    or d
    or d
    push bc
    or c
    ld d, a
    ld [$2521], sp
    ld d, b

jr_014_50e2:
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld l, h
    ld c, d
    inc l
    rst $08
    add $4f
    ret c

    ld c, $e3
    sub e
    add $7f
    or a
    jp $c9d9


    ld a, a
    call c, $bcc0
    ld d, a
    db $ed
    inc h
    dec b
    ld c, e
    call nz, $d47f
    jp nc, $d6c3

    ld e, b
    db $ed
    inc h
    sbc l
    ld c, d
    inc l
    rst $08
    ret


jr_014_5111:
    ld a, a
    pop bc
    or [hl]
    add $4f
    cp h
    ld [c], a
    or e
    add $e1
    or e
    inc [hl]
    or e
    ld h, $7f
    or c
    reti


    sbc $30
    rst $18
    jp Jump_000_0857


    ld hl, $5031
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    jr nz, jr_014_5180

    add $7f
    ld b, [hl]
    or [hl]
    ld b, [hl]
    or [hl]
    ld a, a
    or e
    or [hl]
    inc a
    ld c, a
    ld d, [hl]
    ld a, a
    or c
    ret nz

    cp h
    jp z, $b57f

    cp e
    or [hl]
    push bc
    ld d, a
    db $ed
    inc h
    db $76
    ld c, e
    rst $08
    sbc $3e
    or e
    rst $20
    ld e, b
    db $ed
    inc h
    ld d, b
    ld c, e
    ld a, a
    or d
    rst $18
    cp h
    ld [c], a
    add $4f
    ld d, [hl]
    ld a, a
    ld b, [hl]
    or [hl]
    ld b, [hl]
    or [hl]
    ld a, a
    cp h
    push bc
    or d
    and $57
    ld [$3d21], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld a, h
    ld c, e
    ld a, a
    ret c

    ld c, $e3
    sub e

jr_014_5180:
    add $7f
    or a
    jp $c9d9


    and $57

jr_014_5188:
    db $ed
    inc h
    ld [$de4b], a
    ld a, a
    push bc
    cp h
    ret z

    ld e, b
    db $ed
    inc h
    and d
    ld c, e
    inc l
    rst $08
    jp z, $d17f

    or [hl]
    cp h
    jp z, $cc4f

    ret nz

    jp nz, Jump_014_7fc9

    cp h
    rst $08
    ld a, a
    jr nc, jr_014_5188

    ret nz

    ld a, a
    rst $10
    cp h
    or d
    ret z

    ld d, a
    ld [$4921], sp
    ld d, b
    call Call_000_3214

jr_014_51b7:
    jp Jump_000_0f6a


    db $ed
    inc h
    cp $4b
    xor h
    rst $20
    ld c, a
    or a
    ret nz

    or h
    ld a, a
    or c
    add hl, hl
    ret nz

    ld a, a
    cp d
    ret


    ld a, a
    or [hl]
    rst $10
    jr nc, jr_014_51b7

    ld d, a
    db $ed

jr_014_51d2:
    inc h
    add b
    ld c, h
    call z, $e0c6
    jr nc, jr_014_5232

    db $ed
    inc h
    ld l, $4c
    ret


    ld a, a
    or [hl]
    rst $10
    jr nc, jr_014_5263

    sub $d8

Jump_014_51e6:
    ld c, a

Call_014_51e7:
    ld d, h
    db $dd
    ld a, a
    or a
    ret nz

    or h
    reti


    ld a, a
    dec a
    or a
    jr nc, jr_014_51d2

    ret nz

    ld d, a
    ld [$5521], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    sub e
    ld c, h
    ret


    rst $18
    jp $7fd9


    push bc
    sbc $c3
    ld c, a
    db $d3
    cp h
    or [hl]
    cp h
    jp $b57f


    sub $29
    push bc
    or d
    ld a, a
    call nz, $e6b6
    ld d, a
    db $ed
    inc h
    db $10
    ld c, l
    inc a
    cp b
    inc a
    cp b
    ld e, b
    db $ed
    inc h
    rst $08
    ld c, h
    ret


    rst $18
    jp $b27f


    cp b
    ret


    db $d3
    ld c, a

jr_014_5232:
    ret nz

    ret


    cp h
    cp a
    or e
    jr nc, @-$39

    or c
    ld d, a
    ld [$6121], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld [hl+], a
    ld c, l
    ld d, h
    add $7f
    jp nz, $cfb6

    rst $18
    jp $ba4f


    cp d
    rst $08
    inc sp
    ld a, a
    or a
    ret nz

    sub $57
    db $ed
    inc h
    sbc [hl]
    ld c, l
    cp d
    rst $08
    rst $18
    ret nz

jr_014_5263:
    push bc
    ld e, b
    db $ed
    inc h
    ld b, d
    ld c, l
    ld a, a
    call $c13a
    ldh [$df], a
    jp $d37f


    inc [hl]
    jp c, $b2c5

    cpl
    ld c, a
    ld d, [hl]
    ld a, a
    inc [hl]
    or e
    cp h
    sub $b3
    ld d, a
    ld [$6d21], sp
    ld d, b

jr_014_5284:
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    cp e
    ld c, l
    ld c, a
    or l
    rst $18
    or a
    push bc
    ld a, a
    cp h
    sbc $2c
    pop hl
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    call c, Call_014_57e7
    db $ed
    inc h
    ld c, a
    ld c, [hl]
    rst $20
    ld c, a
    cp h
    sbc $2c
    pop hl
    ld a, a
    or d
    ret c

    ld a, a
    push bc
    ret


    add $56
    ld e, b
    db $ed
    inc h
    pop hl
    ld c, l
    db $eb
    xor e
    ld a, a
    db $d3
    rst $18
    call nz, $bf7f
    jr nc, jr_014_5284

    ret nz

    rst $10
    ld c, a
    cp h
    sbc $2c
    pop hl
    db $d3
    ld a, a
    or l
    rst $18
    or a
    cp b
    ld a, a
    push bc
    reti


    or [hl]
    cp h
    rst $10
    ld d, a
    ld [$7921], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld a, c
    ld c, [hl]
    ld a, a
    inc l
    rst $08

jr_014_52e6:
    ld a, a
    or [hl]
    rst $10
    ld c, a
    or l
    sub $b2
    inc sp
    ld a, a
    or a
    ret nz

    cp c
    inc [hl]
    ld d, [hl]
    ld a, a
    or a
    jp nz, $dcb2

    rst $20
    ld d, a
    db $ed
    inc h
    ld a, $4f
    ret c

    ld e, b
    db $ed
    inc h
    rst $00
    ld c, [hl]
    ld a, a
    inc l
    rst $08
    ret


    ld c, a
    jr nc, jr_014_52e6

    db $d3
    ld a, a
    cp l
    sbc $33
    push bc
    or d
    ld a, a
    or l
    call nc, $b7bc
    ld d, l
    or d
    jp nz, $d7b6

    or [hl]
    ld a, a
    ld d, h
    ld h, $7f
    cp l
    ret nc

    jp nz, $c3b2

    ld d, l
    ld d, h
    ld a, a
    call nc, $b7bc
    call nz, $d67f
    ld a, [hl-]
    jp c, $d9c3

    ld d, a
    ld [$8521], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld c, [hl]
    ld c, a
    ld a, a
    or c
    reti


    ld a, a
    rlca
    and a
    xor e
    ld a, a
    inc l
    rst $08
    jp z, Jump_014_544f

    ld a, a
    cp c
    sbc $b7
    pop hl
    or e
    ret


    ld a, a
    cp h
    rst $08
    rst $20
    ld d, l
    or c
    cp a
    cp d
    inc sp
    ld a, a
    ld b, b
    ld b, b
    db $d3
    ld a, a
    jp z, $d7c0

    or d
    jp $dcd9


    ld d, a
    db $ed
    inc h
    dec l
    ld d, b
    sub $7f
    db $d3
    or e
    rst $20
    ld e, b
    db $ed
    inc h
    cp a
    ld c, a
    jp z, $b67f

    dec hl
    sbc $c9
    ld a, a
    call z, $b6de
    inc sp
    ld c, a
    db $d3
    ret c

    or c
    ld h, $df
    jp $337f


    or a
    ret nz

    rst $18
    jp $b77f


    or d
    ret nz

    call c, $ed57
    inc h
    db $ed
    ld c, c
    inc l
    rst $08
    ld d, a
    call Call_000_3c6c
    ld hl, $53ac
    ld a, [$d589]
    jp Jump_000_3dc7


    xor $53
    ld d, b
    ld d, h
    and e
    ld d, h
    jr jr_014_5409

    ld [hl], l
    ld d, l
    call Call_000_3f55
    ld d, [hl]
    jp $af53


    ld [$cd66], a
    ld [$d589], a
    ret


Call_014_53c4:
    ld a, [$d694]
    ld b, a

jr_014_53c8:
    ld a, [hl+]
    cp b
    jr z, jr_014_53cf

    inc hl
    jr jr_014_53c8

jr_014_53cf:
    ld a, [hl]
    ld [$d03a], a
    ret


Call_014_53d4:
    ld de, $53e9
    ld a, [$cf08]
    cp $01
    jr z, jr_014_53df

    inc de

jr_014_53df:
    call Call_000_3684
    ld a, $0c
    ldh [$8d], a
    jp Jump_000_34f0


    ret nz

    ret nz

    ret nz

    ret nz

    rst $38
    ld a, [$d76a]
    bit 7, a
    ret z

    ld hl, $541b
    call Call_000_3509
    ret nc

    ld a, [$cd3d]
    ld [$cf08], a
    xor a
    ldh [$b4], a
    ld a, $f0
    ld [$cd66], a

jr_014_5409:
    ld a, $02
    ld [$d4a7], a
    ld a, [$d76a]
    bit 0, a
    jr nz, jr_014_5420

    bit 1, a
    jp nz, Jump_014_553c

    ret


    inc b
    dec e
    dec b
    dec e
    rst $38

jr_014_5420:
    ld a, $01
    ld [$cd4f], a
    xor a
    ld [$cd50], a
    ld a, $4c
    call Call_000_3e9d
    ld a, [$d67f]
    and a
    jr z, jr_014_543c

    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45

jr_014_543c:
    ld c, $02
    ld a, $de
    call Call_000_0e35
    ld a, $01
    ldh [$8c], a
    call Call_014_53d4
    ld a, $01
    ld [$d589], a

Jump_014_544f:
    ret


    ld a, [$d6af]
    bit 0, a

Jump_014_5455:
    ret nz

    ld a, [$cf08]
    cp $01
    jr nz, jr_014_5466

    ld a, $04
    ld [$d4a7], a
    ld a, $04
    jr jr_014_5468

jr_014_5466:
    ld a, $0c

jr_014_5468:
    ldh [$8d], a
    ld a, $01
    ldh [$8c], a
    call Call_000_34f0
    xor a
    ld [$cd66], a
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6ac

Call_014_547f:
    set 6, [hl]
    set 7, [hl]
    ld hl, $575a
    ld de, $576d
    call Call_000_339c
    ld a, $e1
    ld [$d036], a
    ld hl, $549d
    call Call_014_53c4
    ld a, $02
    ld [$d589], a
    ret


    or c
    inc b
    sbc c
    dec b
    or b
    ld b, $fa
    inc [hl]
    ret nc

    cp $ff
    jp z, $53bc

    ld a, [$c109]
    and a
    jr nz, jr_014_54b5

    ld a, $04
    jr jr_014_54b7

jr_014_54b5:
    ld a, $0c

jr_014_54b7:
    ldh [$8d], a
    ld a, $01
    ldh [$8c], a
    call Call_000_34f0
    ld a, $f0
    ld [$cd66], a
    ld hl, $d76a
    set 5, [hl]
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a44
    call Call_000_3620
    ld a, [$cf08]
    cp $01
    jr nz, jr_014_54ed

    call Call_014_54f6
    jr jr_014_54f0

jr_014_54ed:
    call Call_014_54fb

jr_014_54f0:
    ld a, $03
    ld [$d589], a
    ret


Call_014_54f6:
    ld de, $5505
    jr jr_014_54fe

Call_014_54fb:
    ld de, $550d

jr_014_54fe:
    ld a, $01
    ldh [$8c], a
    jp Jump_000_3684


    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop
    rst $38
    ld b, b
    ret nz

    ret nz

    ret nz

    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    xor a
    ld [$cd66], a
    ld a, $22
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    call Call_000_0d9b
    ld hl, $d76a
    res 0, [hl]
    res 7, [hl]
    ld a, $00
    ld [$d589], a
    ret


Jump_014_553c:
    ld a, $02
    ld [$cd4f], a
    xor a
    ld [$cd50], a
    ld a, $4c
    call Call_000_3e9d
    ld a, [$d67f]
    and a
    jr z, jr_014_5558

    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45

jr_014_5558:
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a62
    call Call_000_3620
    ld a, $02
    ldh [$8c], a
    call Call_014_53d4
    ld a, $04
    ld [$d589], a
    ret


    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $02
    ldh [$8c], a
    ld a, [$cf08]
    cp $01
    jr nz, jr_014_558f

    ld a, $04
    ld [$d4a7], a
    ld a, $04
    jr jr_014_5596

jr_014_558f:
    ld a, $02
    ld [$d4a7], a
    ld a, $0c

jr_014_5596:
    ldh [$8d], a
    call Call_000_34f0
    xor a
    ld [$cd66], a
    ld a, $02
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $58b6
    ld de, $58d7
    call Call_000_339c

Call_014_55b6:
    ld a, $f2
    ld [$d036], a
    ld hl, $55c7
    call Call_014_53c4
    ld a, $05

Jump_014_55c3:
    ld [$d589], a

Call_014_55c6:
Jump_014_55c6:
    ret


    or c
    ld a, [bc]
    sbc c

Call_014_55ca:
    dec bc
    or b
    inc c
    ld a, [$d034]
    cp $ff
    jp z, $53bc

    ld a, $02
    ldh [$8c], a
    ld a, [$cf08]
    cp $01
    jr nz, jr_014_55e9

    ld a, $04
    ld [$d4a7], a
    ld a, $04
    jr jr_014_55f0

jr_014_55e9:
    ld a, $02
    ld [$d4a7], a
    ld a, $0c

jr_014_55f0:
    ldh [$8d], a
    call Call_000_34f0
    ld a, $f0
    ld [$cd66], a
    ld hl, $d76a
    set 6, [hl]
    ld a, $02
    ldh [$8c], a
    call Call_000_13f1
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a72
    call Call_000_3620
    ld a, [$cf08]
    cp $01
    jr nz, jr_014_5622

    call Call_014_562b
    jr jr_014_5625

jr_014_5622:
    call Call_014_5630

jr_014_5625:
    ld a, $06
    ld [$d589], a
    ret


Call_014_562b:
    ld de, $563a
    jr jr_014_5633

Call_014_5630:
    ld de, $563b

jr_014_5633:
    ld a, $02
    ldh [$8c], a
    jp Jump_000_3684


    add b
    add b
    add b
    add b
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    xor a
    ld [$cd66], a
    ld a, $23
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    call Call_000_0d9b
    ld hl, $d76a
    res 1, [hl]
    res 7, [hl]
    ld a, $07
    ld [$d589], a
    ret


    ld l, c
    ld d, [hl]
    sbc a
    ld d, a
    dec h
    ld e, c
    ld [$6afa], sp
    rst $10
    bit 5, a
    jr z, jr_014_5679

    ld hl, $56ed
    call Call_000_3c79
    jr jr_014_567f

jr_014_5679:
    ld hl, $5682
    call Call_000_3c79

Jump_014_567f:
jr_014_567f:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    inc c
    ld d, a
    db $e3
    xor h
    rst $20
    ld a, a
    ld d, d
    rst $20
    ld d, c
    ld d, h

jr_014_568e:
    ld a, a
    ret c

    db $e3
    rlca
    add $7f
    or d
    cp b
    ret


    or [hl]
    and $4f
    call nc, $c4d2
    cp c
    rst $20
    ld d, c
    or l
    rst $08
    or h
    ld a, a
    inc [hl]
    or e
    cp [hl]
    ld c, a
    add hl, de
    xor h
    dec bc
    ld a, a
    db $d3
    rst $18
    jp $e3c8


    jr nc, jr_014_568e

    and $51
    ret nc

    jp z, $c9d8

    ld a, a
    or l
    rst $18
    cp e
    sbc $26
    ld c, a
    call nz, $bcb5
    jp $b87f


Call_014_56c6:
    jp c, $e3c8

    sub $e7
    ld d, c
    ld d, [hl]
    ld a, a
    cp a
    jp c, $d8d6

    cp e
    or c
    rst $20
    ld c, a
    or l
    rst $08
    or h
    ret


    ld a, a
    ld d, h
    ld d, l
    cp l
    cp d
    cp h
    jp z, $c27f

    sub $b8
    ld a, a
    push bc
    rst $18
    ret nz

    or [hl]
    sub $e6
    ld d, a
    db $ed
    ld a, [hl+]
    ld b, l
    ld d, [hl]
    rst $10
    ld a, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    add $ca
    ld c, a
    jp nz, $b8d6

    jp $bd7f


    ld a, [hl+]
    or d
    ld a, a
    ld e, l
    ld h, $55
    add d
    dec bc
    xor l
    add d
    dec bc
    xor l
    ld a, a
    or d
    reti


    rst $10
    cp h
    or d
    ld l, $51
    inc [hl]
    or e
    add $b6
    ld c, a
    or c
    cp a
    cp d
    db $dd
    ld a, a
    call nz, $d8b5
    rst $00
    cp c
    reti


    ld d, l
    adc $b3
    adc $b3
    db $dd
    ld a, a
    or [hl]
    sbc $26
    or h
    push bc
    or a
    ldh [$c5], a
    rst $20
    ld d, c
    or l
    rst $08
    or h
    db $d3
    ld a, a
    or d
    jp nz, Jump_000_33cf

    db $d3
    ld c, a
    cp d
    cp d
    rst $10
    add $7f
    or d
    push bc
    or d
    inc sp
    ld d, l
    call nz, $c4df
    call nz, $bb7f
    or a
    add $7f
    cp l
    cp l
    jp nc, $e7d6

    ld d, a
    db $ed
    inc l
    ld [hl], h
    ld b, a
    rst $20
    ld c, a
    cp d
    or d
    jp nz, $c57f

    jp nc, Jump_014_7fc0

    sbc l
    sub a
    db $dd
    rst $20
    ld e, b
    db $ed
    inc l
    inc hl
    ld b, a
    sbc $30
    and $4f
    ld d, h
    ld a, a
    ld hl, sp-$35
    or a
    db $d3
    ld d, l
    db $d3
    rst $18
    jp $c9d9


    ld a, a
    push bc
    ld l, $b6
    ld a, a
    jr nc, @-$1f

    jp Jump_014_51e6


jr_014_578b:
    or l
    rst $08
    or h
    db $d3
    ld c, a
    jp nz, $cfb6

    or h
    jp c, $7f3a

    or d
    or d
    ld a, a
    inc l
    ldh [$de], a
    rst $20
    ld e, b
    ld [$6afa], sp
    rst $10
    bit 6, a

jr_014_57a5:
    jr z, jr_014_57af

    ld hl, $5842
    call Call_000_3c79
    jr jr_014_57b5

jr_014_57af:
    ld hl, $57b8

Call_014_57b2:
Jump_014_57b2:
    call Call_000_3c79

jr_014_57b5:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    jp nc, $de58

    jr nc, jr_014_57a5

    ld a, a

Jump_014_57c0:
    ld d, d
    rst $20
    ld c, a

jr_014_57c3:
    cp d
    sbc $c5
    ld a, a
    call nz, $dbba
    inc sp
    ld a, a
    or c
    or e
    call nz, Call_014_55ca
    rst $08
    ret nz

    rst $08
    ret nz

    ld a, a
    jr z, jr_014_578b

    ld l, $de
    jr nc, jr_014_57c3

    ld d, c
    inc l
    ldh [$b1], a
    ld d, [hl]
    ld a, a
    or l
    rst $08
    or h
    db $d3

Jump_014_57e6:
    ld c, a

Call_014_57e7:
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    add $7f
    or d
    cp b
    ld a, a
    call c, $e6b9
    ld d, c
    add hl, de
    xor h
    dec bc
    db $d3
    ld c, a
    ld l, $de
    inc a
    ld a, a
    or c
    jp nz, $dfcf

    ret nz

    ret


    or [hl]
    rst $20
    ld d, l
    or c
    ld a, a
    cp a
    or e
    ld d, [hl]
    ld a, a
    call nc, $2cd9
    ldh [$de], a
    rst $20
    ld d, c
    cp a
    jp c, $e02c

    ld a, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld c, a
    or d
    cp b
    rst $08
    or h
    add $7f
    ld d, d
    inc sp
    ld d, l
    add d
    db $f4
    db $e3
    sbc [hl]
    xor e
    rlca
    ld a, a
    add b
    xor h
    ld b, d
    call nz, $b27f
    cp b
    or [hl]
    rst $20
    ld d, c
    or [hl]
    or [hl]
    rst $18
    jp $b77f


    push bc
    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    ret


    ld d, a
    db $d3
    ld a, a
    adc $28
    jp c, $bcc0

    ld d, [hl]
    rst $20
    ld c, a
    or d
    sub $b2
    sub $7f
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld d, l
    cp [hl]
    or d
    jp z, Jump_014_7fc6

    pop de
    or [hl]
    or e
    call nz, $bd7f
    reti


    or [hl]
    rst $20
    ld d, c
    ld d, d
    jp z, Jump_014_4f56

    db $d3
    rst $18
    call nz, $da7f
    sbc $bc
    pop hl
    or e
    ld a, a
    cp h
    ret nz

    adc $b3
    ld h, $55
    or d
    or d
    sbc $2c
    ldh [$c5], a
    or d
    ret


    rst $20
    ld d, c
    or l
    rst $18
    call nz, Call_014_7fe7
    or l
    cp [hl]
    rst $18
    or [hl]
    or d
    ld a, a
    jr nc, @-$1f

    ret nz

    or [hl]
    rst $20
    ld c, a
    call nz, $b6c6
    cp b
    ld d, [hl]
    ld a, a
    or l
    jp c, Jump_014_7fca

    cp e
    or a
    ld a, a
    or d

jr_014_58a7:
    cp b
    ld l, $55
    inc l
    ldh [$b1], a
    rst $20
    ld d, [hl]
    ld a, a
    or c
    db $e3
    ld a, [hl-]
    sub $e7
    ld d, a
    db $ed
    inc l
    ld e, $48
    rst $10
    rst $20
    ld d, c
    or l
    jp c, Jump_014_7f26

    pop bc
    ld [c], a
    rst $18
    call nz, $d54f
    jr nc, jr_014_58a7

    ld a, a
    cp h
    ret nz

    ld a, a
    cp l
    or a
    add $56
    ld a, a

jr_014_58d2:
    cp b
    cp a
    or e
    rst $20
    ld e, b
    db $ed

jr_014_58d8:
    inc l
    and e
    ld b, a
    ldh [$ca], a
    jp z, $7fac

    ld d, d
    db $e3
    rst $20
    ld c, a
    cp a
    jp c, Jump_014_7f33

    ld h, $de
    ld a, [hl-]
    rst $18
    jp $c9d9


    or [hl]
    sub $e7
    ld d, l
    or l
    jp c, Jump_014_7fc9

    cp e
    or d
    ret


    or e
    add $7f
    cp b
    rst $10
    dec a
    ret c

    ldh [rHDMA5], a
    ld d, d
    jp z, $cf7f

    jr nc, jr_014_58d8

    jr nc, jr_014_598a

    jr nc, jr_014_58d2

    rst $20
    ld d, c
    db $d3
    rst $18
    call nz, $da7f
    sbc $bc
    pop hl
    or e
    ld a, a
    cp d
    or d
    sub $e7
    ld c, a
    or c
    jp z, $e3ca

    xor h
    rst $20
    ld e, b
    db $ed
    inc h
    rst $00
    ld d, l
    ld a, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld c, a
    cp h
    ld [c], a
    or e
    jp nc, Jump_014_7fde

    ld [$93e3], sp
    ld d, a
    call Call_014_5949
    call Call_000_3c6c
    ld hl, $5973
    ld a, [$d5e6]
    jp Jump_000_3dc7


Call_014_5949:
    ld hl, $d0eb
    bit 6, [hl]
    res 6, [hl]
    ret z

    ld hl, $d76d
    res 0, [hl]
    res 7, [hl]
    ld hl, $d792
    res 0, [hl]
    res 6, [hl]
    ld a, $7a
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, $60
    ld [$cc4d], a
    ld a, $11
    jp Jump_000_3e9d


    ld a, c
    ld e, c
    dec de
    ld e, d
    jr nz, jr_014_59d3

    ld hl, $59b5
    ld a, [$d2e0]
    ld b, a
    ld e, $00
    ld c, $07

jr_014_5984:
    ld a, [hl+]
    cp $ff
    ret z

    inc e
    dec c

jr_014_598a:
    cp b
    jr nz, jr_014_5984

    cp $23
    jr nz, jr_014_5997

    ld a, [$d2e1]
    cp $0e
    ret nc

jr_014_5997:
    ld a, e
    ldh [$8c], a
    ld a, c
    ld [$cd3d], a
    ld b, $02
    ld hl, $d76c
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    ret nz

    call Call_014_59bd
    call Call_000_13f1
    xor a
    ldh [$b4], a
    ret


    inc hl
    jr c, @+$57

    ld h, b
    ld l, c
    ld [hl], a
    adc b
    rst $38

Call_014_59bd:
    ld hl, $59d6
    ld a, [$cd3d]
    ld c, a
    ld b, $00
    add hl, bc
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $cd68

jr_014_59ce:
    ld a, [hl+]
    ld [de], a
    inc de
    cp $50

jr_014_59d3:
    jr nz, jr_014_59ce

    ret


    ld a, b
    ld c, l
    add b
    ld c, l
    adc b
    ld c, l
    sub b
    ld c, l
    sbc b
    ld c, l
    and b
    ld c, l
    xor b
    ld c, l
    db $ed
    dec l
    xor c
    ld c, c
    ld d, b
    db $ed
    dec l
    and c
    ld c, c
    xor e
    ld d, b
    db $ed
    dec l
    sbc d
    ld c, c
    ld d, b
    db $ed
    dec l
    sub l
    ld c, c
    db $ed
    dec l
    adc l
    ld c, c
    db $e3
    ld d, b
    db $ed
    dec l
    add [hl]
    ld c, c
    ld d, b
    db $ed
    dec l
    add c
    ld c, c

Call_014_5a07:
    ld a, $01
    ld [$cd38], a
    ld a, $80
    ld [$ccd3], a
    xor a
    ld [$c109], a
    ld [$cd66], a
    jp Jump_000_34d0


    ld a, [$cd38]
    and a
    ret nz

    ld a, $00
    ld [$d5e6], a
    ret


    ld [hl], $5a
    ccf
    ld e, d
    ld c, b
    ld e, d
    ld d, c
    ld e, d
    ld e, d
    ld e, d
    ld h, e
    ld e, d
    ld l, h
    ld e, d
    ld a, b
    ld e, e
    ld [$063e], sp
    call Call_014_5a75
    jp Jump_000_0f6a


    ld [$053e], sp
    call Call_014_5a75
    jp Jump_000_0f6a


    ld [$043e], sp
    call Call_014_5a75
    jp Jump_000_0f6a


    ld [$033e], sp
    call Call_014_5a75
    jp Jump_000_0f6a


    ld [$023e], sp
    call Call_014_5a75
    jp Jump_000_0f6a


    ld [$013e], sp
    call Call_014_5a75
    jp Jump_000_0f6a


    ld [$003e], sp
    call Call_014_5a75
    jp Jump_000_0f6a


Call_014_5a75:
    ld [$cd3d], a
    call Call_014_59bd
    ld a, [$cd3d]
    inc a
    ld c, a
    ld b, $02
    ld hl, $d2d5
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    jr nz, jr_014_5a9d

    ld hl, $5abd
    call Call_000_3c79
    call Call_014_5a07
    ld a, $01
    ld [$d5e6], a
    ret


jr_014_5a9d:
    ld hl, $5b23
    call Call_000_3c79
    ld a, [$cd3d]
    ld c, a
    ld b, $01
    ld hl, $d76c
    ld a, $10
    call Call_000_3e9d
    ld a, $02
    ld [$d5e6], a
    ret


    ld hl, $5b23
    jp Jump_000_3c79


    db $ed
    ld a, [hl+]
    ldh [$59], a
    rst $10
    ld a, a
    cp e
    or a
    jp z, Jump_014_4f56

    ld d, b
    ld bc, $cd68
    nop
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld d, l
    db $d3
    rst $18
    ret nz

    ld a, a
    db $d3
    ret


    ld a, a
    jr nc, @-$45

    ld h, $7f
    cp l
    cp l
    jp nc, $e7d9

    ld d, c
    or a
    ret nc

    jp z, $cf7f

    jr nc, jr_014_5b3a

    ld d, b
    ld bc, $cd68
    nop
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $b27f


jr_014_5afb:
    push bc
    or d
    ld d, c
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    db $dd
    ld a, a
    jp nc, $bd2b

    ld a, a
    push bc
    rst $10
    ld c, a
    inc sp
    push bc
    or l
    cp h
    jp $b77f


    push bc
    cp e
    or d
    ld d, b
    ld [$a53e], sp
    call Call_000_3788
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    push hl
    ld e, d
    rst $10
    ld a, a
    cp e
    or a
    jp z, Jump_014_4f56

    ld d, b
    ld bc, $cd68
    nop
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld d, l
    db $d3

jr_014_5b3a:
    rst $18
    ret nz

    ld a, a
    db $d3
    ret


    ld a, a
    jr nc, jr_014_5afb

    ld h, $7f
    cp l
    cp l
    jp nc, $e7d9

    ld d, c
    pop de
    pop de
    xor h
    ld d, [hl]
    rst $20
    ld c, a
    cp a
    jp c, Jump_014_7fca

    ld d, b
    ld bc, $cd68
    nop
    ld a, a
    add hl, de
    xor h
    dec bc
    rst $20
    ld d, b
    dec bc
    nop
    ld d, c
    call c, $dfb6
    ret nz

    ld d, [hl]
    rst $20
    ld c, a
    cp d
    ret


    ld a, a
    cp e
    or a
    call $bd7f
    cp l
    ret nc

    push bc
    cp e
    or d
    rst $20
    ld d, a
    db $ed
    inc h
    or $55
    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    ld a, a
    xor b
    db $e3
    inc de
    ld c, a
    ld [$93e3], sp
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, h
    ret c

    db $e3
    rlca
    ld d, a
    call Call_000_3c6c
    ld hl, $5c41
    ld de, $5bb1
    ld a, [$d581]
    call Call_000_31a8
    ld [$d581], a
    ret


Jump_014_5ba6:
    xor a
    ld [$cd66], a
    ld [$d581], a
    ld [$d97c], a
    ret


    cp e
    ld e, e
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld [$f75c], sp
    ld e, e
    ld a, [$d76e]
    bit 0, a
    jp nz, Jump_000_3261

    ld hl, $5bf4
    call Call_000_3509
    jp nc, Jump_000_3261

    xor a
    ldh [$b4], a
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d76f
    bit 1, [hl]
    res 1, [hl]
    ret z

    ld a, $80
    ld [$ccd3], a
    ld a, $01
    ld [$cd38], a
    call Call_000_34d0
    ld a, $04
    ld [$d581], a
    ld [$d97c], a
    ret


    rrca
    ld a, [bc]
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    ld a, $00
    ld [$d581], a
    ld [$d97c], a
    ret


    ld a, [$d034]
    cp $ff
    jp z, Jump_014_5ba6

    call Call_000_0ebd
    ld a, $f0
    ld [$cd66], a
    ld hl, $d76e
    set 1, [hl]
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    xor a
    ld [$cd66], a
    ld a, $00
    ld [$d581], a
    ld [$d97c], a
    ret


    adc d
    ld e, h
    rlca
    ld e, [hl]
    ld e, h
    ld e, [hl]
    sbc a
    ld e, [hl]
    db $ec
    ld e, [hl]
    dec [hl]
    ld e, a
    ld a, e
    ld e, a
    push bc
    rrca
    ld [bc], a
    ld b, b
    ld l, [hl]
    rst $10
    ld de, $3a5e
    ld e, [hl]
    ld l, $5e
    ld l, $5e
    inc bc
    db $10
    ld l, [hl]
    rst $10
    ld h, [hl]
    ld e, [hl]
    adc d
    ld e, [hl]
    ld a, a
    ld e, [hl]
    ld a, a
    ld e, [hl]
    inc b
    db $10
    ld l, [hl]
    rst $10
    xor c
    ld e, [hl]
    call nc, $c85e
    ld e, [hl]
    ret z

    ld e, [hl]
    dec b
    db $10
    ld l, [hl]
    rst $10
    or $5e
    jr nz, @+$61

    inc d
    ld e, a
    inc d
    ld e, a
    ld b, $10
    ld l, [hl]
    rst $10
    ccf
    ld e, a
    ld h, e
    ld e, a
    ld e, c
    ld e, a
    ld e, c
    ld e, a
    rlca
    db $10
    ld l, [hl]
    rst $10
    add l
    ld e, a
    db $dd
    ld e, a
    pop de
    ld e, a
    pop de
    ld e, a
    rst $38
    ld [$6f21], sp
    rst $10
    res 1, [hl]
    ld a, [$d76e]
    bit 0, a
    jr nz, jr_014_5cdf

    ld hl, $5cf6
    call Call_000_3c79
    ld bc, $3101
    call Call_000_3e5e
    jr nc, jr_014_5ce8

    ld hl, $d76e
    set 0, [hl]
    ld hl, $5d25
    call Call_000_3c79
    ld hl, $5d4d
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $5dcf
    ld de, $5dcf
    call Call_000_339c
    ldh a, [$8c]
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    xor a
    ldh [$b4], a
    ld a, $03
    ld [$d581], a
    ld [$d97c], a
    jp Jump_000_0f6a


jr_014_5cdf:
    ld hl, $5de0
    call Call_000_3c79
    jp Jump_000_0f6a


jr_014_5ce8:
    ld hl, $5d40
    call Call_000_3c79
    ld hl, $d76f
    set 1, [hl]
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld h, c
    ld e, e
    call nz, $ace3
    rst $20
    ld c, a
    ei
    add $de
    rst $00
    or a
    ld a, a
    or l
    jp nc, $c433

    or e
    rst $20
    ld d, b
    dec bc
    nop
    ld d, c
    cp h
    ld [c], a

jr_014_5d11:
    or e
    set 3, [hl]
    add $4f
    cp d
    jp c, Jump_014_7fdd

    ld b, d
    and a
    dec c
    xor e
    sub e
    ld a, a
    cp h
    sub $b3
    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    ret nz

    ld e, e
    push bc
    cpl
    ret


    ld e, l
    or [hl]
    rst $10
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    dec bc
    ld b, $50
    db $ed
    ld a, [hl+]
    jr z, @+$5f

    ret


    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_014_5da4

    db $ed
    ld a, [hl+]
    jp hl


    ld e, e
    inc sp
    ld d, [hl]
    ld a, a
    cp d
    cp d
    jr nc, jr_014_5d11

    ret


    ld a, a
    jp z, $bcc5

    ld c, a
    ld e, [hl]
    add $7f
    jp z, $d7b2

    push bc
    or d
    and $51
    or l
    jp c, $c1c0

    jp z, Jump_014_544f

    db $dd
    ld a, a
    call c, $b2d9
    cp d
    call nz, Call_014_55c6
    jp nz, $b5b6

    or e
    rst $18
    jp $b3b2


    ld a, a
    rlca
    and [hl]
    db $e3
    ld b, d
    jr nc, @-$17

    ld d, c
    jp z, $d8b2

    push bc
    sub $51
    jp z, $d7b2

    push bc
    or d
    ret


    and $51
    jp z, $dfb2

    jp $e7d6


    ld d, c
    jp z, $dab2

    sub $e7
    ld d, c
    ld d, [hl]

jr_014_5da4:
    ld a, a
    cp d
    call nz, $d9dc
    rst $18
    jp $b67f


    or l
    ld a, a
    cp h
    jp $c5de


    ld d, c
    cp a
    jp c, $d7c5

    ld d, [hl]
    rst $20
    ld c, a
    pop de
    ret c

    call nc, $7fd8
    or d
    jp c, Jump_014_7fc3

    call nc, $e7d9
    ld d, l
    or e
    ret c

    ldh [$e3], a
    xor h
    rst $20
    ld d, a
    db $ed
    inc l
    db $76
    ld c, b
    ld d, [hl]
    rst $20
    ld c, a
    sbc h
    xor e
    sub e
    ld a, a
    jp nz, $b4b4

    push bc
    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    jp nc, $b95c

    ret


    ld a, a
    or e
    inc sp
    ld h, $7f
    or c
    jp c, Jump_014_4f3a

    ld e, [hl]
    ld a, a
    inc sp
    db $d3
    ld d, l
    or h
    rst $10
    cp b
    ld a, a
    push bc
    jp c, $c9d9

    add $7f
    db $d3
    rst $18
    ret nz

    or d
    push bc
    or d
    ld l, $e7
    ld d, a
    ld [$4121], sp

jr_014_5e0a:
    ld e, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    inc [hl]
    ld d, [hl]
    xor h
    rst $20
    ld a, a
    cp b
    cp e
    pop de
    rst $10
    or [hl]
    rst $10
    ld c, a
    or a
    ret nc

    ret


    ld a, a
    or [hl]
    jp nz, $b8d4

    db $dd
    ld a, a
    ret nc

    jp $d6c0


    ld d, a
    db $ed
    inc h
    jp nc, $df56

    ld b, h
    ret c

    ld a, a
    jr nc, jr_014_5e0a

    jr nc, @+$5a

    db $ed
    inc h
    add d
    ld d, [hl]
    cp h
    db $dd
    ld a, a
    call c, $d9c0
    ret


    ld h, $7f
    cp d
    call c, $c3b8
    ld c, a
    dec l
    rst $18
    call nz, $ba7f
    cp d
    add $7f
    or [hl]
    cp b
    jp c, $c0c3

    sbc $30
    ld d, a
    ld [$4d21], sp
    ld e, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    db $eb
    ld d, [hl]
    or d
    xor h
    rst $20
    ld a, a
    ei
    add $de
    jp nc, Jump_014_4fe7

    or l
    jp c, Jump_014_7f26

    or c
    or d
    jp $b130


    rst $20
    ld d, a
    db $ed
    inc h
    ld e, l
    ld d, a
    ret nz

    ld a, a
    db $d3
    sbc $30
    rst $20
    ld e, b
    db $ed
    inc h
    ld a, [de]
    ld d, a
    db $dd
    ld a, a
    jp nz, $bcb8

    ret nz

    sbc $30
    ld c, a
    cp b
    or d
    jp z, $c57f

    or d
    rst $20
    ld d, a
    ld [$5921], sp
    ld e, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld [hl], h
    ld d, a
    jp nc, Jump_014_7fca

    call c, $bcc0
    sub $e7
    ld c, a
    cp a
    db $db
    cp a
    db $db
    ld a, a
    ld a, [hl-]
    jp Jump_014_55c3


    or a
    ret nz

    sbc $2c
    ldh [$c5], a
    or d
    and $57
    db $ed
    inc h
    add sp, $57
    db $d3
    ld a, a
    rst $08
    cp c
    ret nz

    ret


    ret z

    ld e, b
    db $ed
    inc h
    and l
    ld d, a
    db $dd
    ld a, a
    jp nz, $bcb8

    ret nz

    sbc $30
    or [hl]
    rst $10
    ld c, a
    cp b
    or d
    jp z, $c57f

    or d
    call c, Call_014_57e7
    ld [$6521], sp
    ld e, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    db $fd
    ld d, a
    jp nc, $c47f

    or e
    inc l
    ld [c], a
    or e
    rst $20
    ld c, a
    cp a
    or e
    ld a, a
    or [hl]
    sbc $c0
    sbc $c6
    jp z, $b27f

    or [hl]
    push bc
    or d
    ld l, $e7
    ld d, a
    db $ed
    inc h
    ld l, a
    ld e, b
    db $db
    ld a, a
    db $d3
    or e
    ld a, a
    rrca
    and b
    ld e, b
    db $ed
    inc h
    dec hl
    ld e, b
    db $dd
    ld a, a
    jp nz, $bcb8

    ret nz

    sbc $30
    ld c, a
    cp b
    or d
    jp z, $c57f

    or d
    rst $20
    ld d, a
    ld [$7121], sp
    ld e, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    add l
    ld e, b
    jp nc, Jump_014_7fca

    call c, $bcc0
    rst $20
    ld c, a
    cp d
    jp c, $d7b6

    ld h, $7f
    adc $de
    ld a, [hl-]
    sbc $7f
    sub $e7
    ld d, a
    db $ed
    inc h
    db $f4
    ld e, b
    rst $10
    sbc $c5
    db $e3
    or d
    ld e, b
    db $ed
    inc h
    or b
    ld e, b
    db $dd
    ld a, a
    jp nz, $bcb8

    ret nz

    sbc $30
    or [hl]
    rst $10
    ld c, a
    cp b
    or d
    jp z, $c57f

    or d
    call c, Call_014_57e7
    ld [$7d21], sp
    ld e, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld a, [bc]
    ld e, c
    jp z, $cabc

    ld a, a
    set 0, h
    ld a, a
    sub $de
    inc sp
    ld c, a
    add hl, bc
    db $e3
    and [hl]
    ld [de], a
    xor e
    inc e
    db $e3
    and [hl]
    ld a, a
    dec de
    ret c

    xor h
    dec bc
    rst $20
    ld d, c
    ei
    add $de
    ld a, a
    or [hl]
    pop bc
    rst $00
    cp c
    ld a, [hl-]
    ld c, a
    ld a, [hl+]
    or e
    or [hl]
    push bc
    ld a, a
    cp h
    ld [c], a
    or e
    set 3, [hl]
    ld h, $7f
    db $d3
    rst $10
    or h
    reti


    rst $20
    ld d, c
    cp e
    jp Jump_014_4fe7


    or l
    rst $08
    or h
    add $7f
    rst $00
    cp c
    rst $10
    jp c, $b6d9

    push bc
    and $57
    db $ed
    inc h
    rst $08
    ld e, c
    or [hl]
    ld a, a
    call nc, $2cd9
    ldh [$de], a
    ld e, b
    db $ed
    inc h
    adc l
    ld e, c
    db $dd
    ld a, a
    jp nz, $bcb8

    ret nz

    sbc $30
    ld c, a
    cp b
    or d
    jp z, $c57f

    or d
    rst $20
    ld d, a
    call Call_014_6008
    call Call_000_3c6c
    ld hl, $6065
    ld de, $6049
    ld a, [$d582]
    call Call_000_31a8
    ld [$d582], a
    ret


Call_014_6008:
    ld hl, $d0eb
    bit 6, [hl]
    res 6, [hl]
    ret z

    ld hl, $d771
    bit 7, [hl]
    ret nz

    bit 5, [hl]
    jr nz, jr_014_6026

    res 6, [hl]
    ld a, $61
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


jr_014_6026:
    bit 4, [hl]
    ret z

    set 7, [hl]
    ld a, $24
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $62
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $63
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    jp nc, $3b60

    ld h, c
    sbc b
    ld h, c
    call c, $2661
    ld h, d
    add b
    ld h, d
    pop hl
    ld h, d
    ld [hl-], a
    ld h, e
    adc a
    ld h, e
    push bc
    rrca
    db $e3
    ld h, e
    ld bc, $7020
    rst $10
    call c, $0960
    ld h, c
    cp $60
    cp $60
    ld [bc], a
    jr nc, @+$72

    rst $10
    ld b, l
    ld h, c
    ld a, d
    ld h, c
    ld l, a
    ld h, c
    ld l, a
    ld h, c
    inc bc
    jr nc, @+$72

    rst $10
    and d
    ld h, c
    jp $bd61


    ld h, c
    cp l
    ld h, c
    inc b
    jr nz, jr_014_60fc

    rst $10
    and $61
    dec bc
    ld h, d
    nop
    ld h, d
    nop
    ld h, d
    dec b
    ld b, b
    ld [hl], b
    rst $10
    jr nc, jr_014_60fd

    ld d, [hl]
    ld h, d
    ld b, [hl]
    ld h, d
    ld b, [hl]
    ld h, d
    ld b, $40
    ld [hl], b
    rst $10
    adc d
    ld h, d
    or a
    ld h, d
    xor h
    ld h, d
    xor h
    ld h, d
    rlca
    jr nc, jr_014_6120

    rst $10
    db $eb
    ld h, d
    dec d
    ld h, e
    dec c
    ld h, e
    dec c
    ld h, e
    ld [$7020], sp
    rst $10
    inc a
    ld h, e
    ld l, h
    ld h, e
    ld h, h
    ld h, e
    ld h, h
    ld h, e
    add hl, bc
    jr nz, jr_014_6138

    rst $10
    sbc c
    ld h, e

jr_014_60cb:
    cp a
    ld h, e
    cp c
    ld h, e
    cp c
    ld h, e
    rst $38
    ld [$6521], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld [de], a
    ld e, d
    jp z, $bcd4

    jp z, $b77f

    sbc $2c
    ld [c], a
    ret


    ld c, a
    ld e, l
    ld h, $55
    jp c, $bcde

    pop hl
    or e
    add $7f
    cp b
    reti


    ld a, a
    ld a, [hl-]
    cp h
    ld [c], a
    cp e

jr_014_60fc:
    rst $20

jr_014_60fd:
    ld d, a
    db $ed
    inc h
    ret nc

    ld e, d
    or [hl]
    ld a, a
    inc sp
    or a
    reti


    ret z

    ld e, b
    db $ed
    inc h
    ld d, b
    ld e, d
    rst $30
    ld b, l
    or a
    jr nc, jr_014_60cb

    ld a, a
    jp nz, $b8d6

    jp Jump_014_4fd3


    add $26
    jp Jump_014_7fc5


    adc a
    add c

jr_014_6120:
    ld b, d
    add $ca
    ld a, a
    or [hl]
    jp $b2c5


    ld d, l
    ret nz

    cp b
    cp e
    sbc $7f
    cp a
    jr nc, @-$3b

    reti


    ld a, a
    adc $b3
    ld h, $7f
    or d

jr_014_6138:
    or d
    sub $57
    ld [$7121], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h

jr_014_6147:
    rst $18
    ld e, d
    ld a, a
    ret nc

    push bc
    call nz, $4fc9
    adc d
    xor e
    sub e
    add b
    xor e
    sub [hl]
    ld a, a
    ld a, [hl+]
    or e
    ret


    ld a, a
    ld b, b
    db $e3
    sub d
    or b
    ld d, l
    ld b, b
    ld b, b
    call nz, $b27f
    rst $18
    ret nz

    ld l, $7f
    or d
    or d
    jr nc, jr_014_6147

    db $e3
    rst $20
    ld d, a
    db $ed
    inc h
    add h
    ld e, e
    cp b
    ld a, a
    push bc
    or d
    db $d3
    sbc $58
    db $ed
    inc h
    inc hl
    ld e, e
    add b
    xor e
    sub [hl]
    ld a, a
    ld a, [hl+]
    or e
    ld a, a
    jp z, $be4f

    or [hl]
    or d
    ret


    ld a, a
    ld e, l
    ld h, $55

jr_014_618f:
    or d
    rst $18
    ld b, h
    or d
    ld a, a
    or d
    ret nz

    sub $57
    ld [$7d21], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    and d
    ld e, e
    ld a, a
    inc e
    db $e3
    add c
    adc h
    add l
    add d
    sub e
    ld c, a
    or [hl]
    ret


    inc l
    ld [c], a
    jp z, $9e7f

    sub l
    adc h
    add l
    db $e3
    sub e
    rst $20
    ld d, a
    db $ed
    inc h
    inc hl
    ld e, h
    ld d, [hl]
    ld e, b
    db $ed
    inc h
    db $db
    ld e, e
    or d
    rst $18
    or [hl]
    ld c, a
    or [hl]
    ret


    inc l
    ld [c], a
    add $7f
    push bc
    jr z, jr_014_618f

    jp nc, Jump_014_7fc3

    db $d3
    rst $10
    or l
    or e
    ld d, a
    ld [$8921], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    inc [hl]
    ld e, h
    jp z, $9e7f

    sub l
    adc h
    add l
    db $e3
    sub e
    ld c, a
    or [hl]
    jp c, Jump_014_7fca

    inc e
    db $e3
    add c
    adc h
    add l
    add d
    sub e
    rst $20
    ld d, a
    db $ed
    inc h
    xor b
    ld e, h
    cp h
    ld a, a
    call c, $e3d9
    or d
    ld e, b
    db $ed
    inc h
    ld h, h
    ld e, h
    ret


    ld a, a
    or [hl]
    jp c, Jump_014_4fd3

    or a
    ret nc

    ld a, a
    cp b
    rst $10
    or d
    ld a, a
    jp nz, $b2d6

    call nz, $b27f
    or d
    ret


    add $57
    ld [$9521], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    cp [hl]
    ld e, h
    ld c, a
    or a
    ret nc

    call nz, $3e7f
    cp b
    jp z, $c07f

    ret nz

    or [hl]
    or e
    ld a, a
    sub $b6
    sbc $57
    db $ed
    inc h
    ld [hl], b
    ld e, l
    or e
    push bc
    ld c, a
    sub $b6
    sbc $26
    ld a, a
    cp h
    ret nz

    sub $58
    db $ed
    inc h
    ld sp, hl
    ld e, h
    or a
    call nc, $ba7f
    sbc $d7
    sbc $dd
    ld a, a
    or e
    cp c
    ret nz

    rst $10
    ld c, a
    cp e
    rst $18
    cp e
    call nz, Call_014_547f
    db $dd
    ld a, a
    call nz, $b6d8
    or h
    reti


    ld d, l
    cp e
    cp b
    cp [hl]
    sbc $d3
    ld a, a
    or d
    or d
    ret z

    ld d, a
    ld [$a121], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    sbc e
    ld e, l
    pop bc
    ld h, $7f
    or [hl]

jr_014_6292:
    call c, $b2b2
    ld a, a
    ld d, h
    ld c, a
    or d
    rst $18
    ld b, h
    or d
    ld a, a
    db $d3
    rst $18
    jp $c9d9


    ld d, l
    ld d, [hl]
    ld a, a
    cp b
    call nc, $b2bc
    call c, Call_014_57e7
    db $ed
    inc h
    ccf
    ld e, [hl]
    cp b
    ld a, a
    push bc
    or d
    db $d3
    sbc $58
    db $ed
    inc h
    jp z, $9e5d

    call nc, Call_014_7fcf
    or [hl]
    rst $10
    ld a, a
    or a
    ret nz

    ret


    and $4f
    inc l
    ldh [$7f], a
    or c
    ret nz

    cp h
    ld a, a
    ld b, c
    xor h
    ld b, c
    ld a, a
    adc $bc
    db $e3

jr_014_62d5:
    or d
    rst $20
    ld d, l
    ret z

    or h
    ld a, a
    pop bc
    ld [c], a
    or e
    jr nc, jr_014_6292

    ld d, a
    ld [$ad21], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld e, a
    ld e, [hl]
    sbc [hl]
    ld a, a
    call nc, Call_014_7fcf
    or [hl]
    rst $10
    ld c, a
    or l
    ret c

    jp $c0b7


    ld a, a
    ld a, [hl-]
    or [hl]
    ret c

    jr nc, jr_014_6328

    ld d, l
    rst $08
    jr nc, jr_014_62d5

    jr nc, jr_014_6387

    add hl, hl
    sbc $b7
    rst $20
    ld d, a
    db $ed
    inc h
    sub $5e
    reti


    push bc
    or c
    ld e, b
    db $ed
    inc h
    and l
    ld e, [hl]
    ld c, a
    inc [hl]
    or e
    cp b
    jp nz, Jump_014_7fc9

    push bc
    or [hl]
    inc sp
    ld d, l
    inc c
    add hl, de
    xor h
    sub e

jr_014_6328:
    add $7f
    or [hl]
    rst $08
    jp c, $cfc1

jr_014_632f:
    rst $18
    ret nz

    ld d, a
    ld [$b921], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    db $e3
    ld e, [hl]
    add $7f
    cp l
    sbc $33
    reti


    ld c, a
    ld d, h
    ld a, a
    sbc l
    sub l
    add b
    ret


    ld a, a
    adc c
    and a
    add a
    adc e
    xor a
    xor e
    ld d, l
    ret nc

    add $7f
    or d
    cp d
    or e
    call nz, $b57f
    db $d3
    rst $18
    jp $e7c5


    ld d, a
    db $ed
    inc h
    and d
    ld e, a
    ret nz

    push bc
    or c
    ld e, b
    db $ed
    inc h
    dec sp
    ld e, a
    call nz, $b3b2
    ld a, a
    jr nc, jr_014_632f

    add $4f
    or d
    db $db
    or d
    db $db
    ld a, a
    jp nc, $d72d

    cp h
    or d
    ld a, a
    ld d, h
    db $dd
    ld d, l
    db $d3

jr_014_6387:
    rst $18
    jp $7fd9


    rst $10
    cp h
    or d
    ld d, a
    ld [$c521], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    cp a
    ld e, a
    ret


    ld a, a
    or d
    or h
    add $7f
    or d
    cp b
    ret


    or [hl]
    and $4f
    cp a
    ret


    rst $08
    or h
    add $7f
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    cp h
    sub $b3
    rst $20
    ld d, a
    db $ed
    inc h
    ld e, [hl]
    ld h, b
    or c
    ld e, b
    db $ed
    inc h
    ld bc, $7f60
    adc e
    sub d
    or b
    add $7f
    or [hl]
    or h
    reti


    ld a, a
    call nz, $cab7
    ld c, a
    cp h
    ret nz

    ret


    ld a, a
    adc $34
    or e
    db $dd
    ld a, a
    or c
    reti


    cp b
    call nz, $ca7f
    call nc, Call_014_57b2
    db $ed
    inc h
    db $e3
    ld e, c
    ld a, a
    ret nc

    cp e
    or a
    ret


    ld a, a
    cp d
    call nc, $564f
    ld a, a
    sbc l
    adc d
    add [hl]
    ret


    ld a, a
    or d
    or h
    ld d, a
    ld de, $0f09
    jr nz, jr_014_6466

    add h
    ld h, h
    ld b, $64
    nop
    add [hl]
    ld h, [hl]
    ld hl, $d0eb
    bit 6, [hl]
    res 6, [hl]
    call nz, Call_014_642d
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    call nz, Call_014_6432
    call Call_000_3c6c
    ld hl, $649e
    ld de, $6454
    ld a, [$d5be]
    call Call_000_31a8
    ld [$d5be], a
    ret


Call_014_642d:
    ld hl, $d7e8
    res 7, [hl]

Call_014_6432:
    ld a, [$d76d]
    bit 0, a
    jr z, jr_014_6443

    push af
    ld a, $15
    ld bc, $0403
    call Call_014_644b
    pop af

jr_014_6443:
    bit 7, a
    ret z

    ld a, $1d
    ld bc, $070b

Call_014_644b:
    ld [$d07c], a
    ld a, $17
    call Call_000_3e9d
    ret


    ld e, d
    ld h, h
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld hl, $647f
    call Call_000_352e
    jp nc, Jump_000_3261

    ld hl, $d76d

jr_014_6466:
    ld a, [$cd3d]
    cp $02
    jr z, jr_014_6474

    bit 0, [hl]
    set 0, [hl]
    ret nz

    jr jr_014_6479

jr_014_6474:
    bit 7, [hl]
    set 7, [hl]
    ret nz

jr_014_6479:
    ld hl, $d0eb
    set 5, [hl]
    ret


    db $10
    ld bc, $0910
    rst $38
    rst $20
    ld h, h
    ld b, [hl]
    ld h, l
    adc [hl]
    ld h, l
    ret c

    ld h, l
    ld [hl+], a
    ld h, [hl]
    ld l, c
    ld h, [hl]
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    add e
    rrca
    add e
    rrca
    add e
    rrca
    ld bc, $6d40
    rst $10
    pop af
    ld h, h
    dec de
    ld h, l
    inc de
    ld h, l
    inc de
    ld h, l
    ld [bc], a
    jr nc, jr_014_651a

    rst $10
    ld d, b
    ld h, l
    ld a, c
    ld h, l
    ld [hl], b
    ld h, l
    ld [hl], b
    ld h, l
    inc bc
    jr nc, @+$6f

    rst $10
    sbc b
    ld h, l
    or [hl]
    ld h, l
    xor a
    ld h, l
    xor a
    ld h, l

jr_014_64c2:
    inc b
    db $10
    ld l, l
    rst $10
    ld [c], a
    ld h, l
    dec b
    ld h, [hl]
    db $fd
    ld h, l
    db $fd
    ld h, l
    dec b
    jr nc, jr_014_653e

    rst $10
    inc l
    ld h, [hl]
    ld c, a
    ld h, [hl]
    ld b, h
    ld h, [hl]
    ld b, h
    ld h, [hl]
    ld b, $00
    ld l, l
    rst $10
    ld [hl], e
    ld h, [hl]
    ld [hl], e
    ld h, [hl]
    ld [hl], e
    ld h, [hl]
    ld [hl], e
    ld h, [hl]
    rst $38
    ld [$9e21], sp
    ld h, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ret c

    ld d, l
    xor h
    rst $20
    ld c, a
    ld e, l
    ld a, a
    cp e
    or d
    ld a, [hl+]
    ret


    ld a, a
    cp h
    jp c, $e7de

    ld d, l
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    ld a, a
    xor b
    db $e3
    inc de
    ld a, a
    jr nc, jr_014_64c2

    rst $20
    ld d, a
    db $ed
    daa
    ld [hl], h
    ld d, [hl]
    sub e
    db $e3
    rst $20

jr_014_651a:
    ld e, b
    db $ed
    daa
    ld e, $56
    ld a, a
    or d
    ret nz

    reti


    ld a, a
    call nz, $dbba
    add $4f
    cp h
    or [hl]
    cp c
    ld h, $7f
    or c
    reti


    rst $20
    ld a, a
    cp d

jr_014_6533:
    rst $08
    rst $18
    ret nz

    call nz, $cab7
    ld d, l
    or d
    call c, Call_014_7fdd

jr_014_653e:
    or l
    cp h
    jp $d07f


    db $db
    rst $20
    ld d, a
    ld [$aa21], sp
    ld h, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld a, [hl]
    ld d, [hl]
    ld a, a
    or a
    ret nz

    ld a, a
    or [hl]
    rst $10
    ld a, a
    add $ca
    ld c, a
    cp h
    jp $c9de


    or e
    add $7f
    or d
    inc [hl]
    pop de
    ld a, a
    jp nz, $d8d3

    jr nc, jr_014_6533

    rst $20
    ld d, a
    db $ed
    daa
    ld de, $b757
    reti


    xor h
    rst $20
    ld e, b
    db $ed
    daa
    sub $56
    rst $20
    ld a, a
    ld d, e
    db $d3
    ld c, a
    cp d
    cp d
    db $dd

jr_014_6585:
    ld a, a
    rst $00
    cp c
    jp $c0df


    ld l, $e7
    ld d, a
    ld [$b621], sp
    ld h, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    rra
    ld d, a
    ld a, a
    ld b, c
    adc e
    db $e3
    xor h
    rst $20
    ld c, a
    sbc a
    sub b
    ld h, $7f
    cp h
    push bc
    reti


    ld l, $e3
    xor h
    rst $20
    ld d, a
    db $ed
    daa
    jp $ac57


    rst $20
    ld e, b
    db $ed
    daa
    ld d, d
    ld d, a
    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    ld a, a
    xor b
    db $e3
    inc de
    add $4f
    cp b
    reti


    ld a, a
    jr nc, jr_014_6585

    ret


    ld a, a
    cp d
    call nz, Call_014_7fca
    or c
    reti


    push bc
    ld d, [hl]
    rst $20
    ld d, a
    ld [$c221], sp
    ld h, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld [c], a
    ld d, a
    ld a, a
    inc a
    inc l
    add $7f
    rst $00
    cp c
    jp c, Jump_014_4f3a

    cp h
    jp $c9de


    or e
    add $7f
    or c
    or h
    reti


    cpl
    rst $20
    ld d, a
    db $ed
    daa
    ld [hl], d
    ld e, b
    ret c

    db $e3
    rst $20
    ld e, b
    db $ed
    daa
    jr c, @+$5a

    pop bc
    cp h
    or a
    ld a, a
    jr nc, @-$1f

    ret nz

    rst $10
    ld c, a
    ld a, $b8
    jp z, $cf7f

    cp c
    push bc
    or d
    call nz, $b57f
    db $d3
    or e
    cpl
    rst $20
    ld d, a
    ld [$ce21], sp
    ld h, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld a, e
    ld e, b
    rst $20
    ld c, a
    sub b
    xor l
    xor e

jr_014_6635:
    ld b, c
    add h
    xor e
    ld a, a
    xor b
    db $e3
    inc de
    jp z, $b77f

    jp nz, $b6b2

    and $57
    db $ed
    daa
    add hl, sp
    ld e, c
    ld a, [hl+]
    or e
    or [hl]
    cp b
    jr nc, jr_014_6635

    ld e, b
    db $ed
    daa
    add $58
    ld a, a
    call $df3a
    jp $cb4f


    or a
    or [hl]
    or h
    cp l
    ld a, a
    call nc, $d3c2
    ld a, a
    or l
    or l
    or d
    ld l, $e7
    ld d, a
    ld [$da21], sp
    ld h, h
    call Call_000_3214
    jp Jump_000_0f6a


    nop
    or a
    pop bc
    ret z

    rst $08
    rst $08
    ld d, b
    ld [$493e], sp
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    ld a, l
    rlca
    ld [$0200], sp
    ld l, h
    rlca
    dec e
    inc bc
    rst $38
    ld [$031d], sp
    rst $38
    rlca
    rla
    nop
    add $0e
    add hl, de
    ld [bc], a
    add $07
    dec de
    ld bc, $01c6
    ld bc, $c603
    nop
    dec c
    ld c, $0d
    db $10
    rst $38
    jp nc, $e041

    add hl, bc
    inc c
    ld de, $ff19
    jp nc, $dd42

    ld [bc], a
    rlca
    inc c
    rla
    rst $38
    ret nc

    ld b, e
    sbc $05
    inc c
    ld b, $08
    rst $38
    ret nc

    ld b, h
    rst $08
    ld b, $0c
    rlca
    ld e, $ff
    jp nc, $dd45

    dec b
    add hl, bc
    add hl, bc
    rrca
    rst $38
    pop de
    ld b, [hl]
    ld c, c
    ld [hl-], a
    dec a
    add hl, bc
    rra
    rst $38
    rst $38
    add a
    reti


    dec a
    dec c
    ld d, $ff
    rst $38
    adc b
    inc [hl]
    dec a
    rrca
    dec c
    rst $38
    rst $38
    adc c
    call Call_000_043d
    rrca
    rst $38
    rst $38
    adc d
    scf
    ccf
    ld [de], a
    ld [$10ff], sp
    dec bc
    ccf
    add hl, bc
    add hl, bc
    rst $38
    db $10
    inc c
    ccf
    inc d
    dec de
    rst $38
    db $10
    dec c
    ld d, d
    rst $00
    ld [$4b00], sp
    rst $00
    rlca
    dec e
    ld h, b
    rst $00
    ld [$481d], sp
    rst $00
    rlca
    rla
    sbc l
    rst $00
    ld c, $19
    ld c, d
    rst $00
    rlca
    dec de
    cp $c6
    ld bc, $6201
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld b, $60
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    rlca
    ld b, $60
    rrca
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld b, $60
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    rlca
    ld [$0e05], sp
    ld [$6006], sp
    ld h, b
    ld b, $60
    dec b
    dec b
    dec b
    ld b, $60
    rlca
    ld bc, $6060
    ld h, b
    ld b, $60
    ld h, b
    ld b, $60
    ld h, b
    ld h, b
    ld a, $08
    ld h, d
    ld h, e
    inc hl
    ld h, b
    inc d
    scf
    dec d
    dec d
    dec d
    ld d, $60
    ld h, b
    ld h, b
    ld h, b
    ld b, $60
    ld h, a
    ld b, $60
    ld d, h
    ld sp, $3157
    ld [hl-], a
    ld a, [de]
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    dec b
    dec b
    dec b
    ld c, l
    ld h, b
    ld h, b
    ld h, b
    ld b, $60
    jr jr_014_679b

    dec d
    dec d
    dec d
    ld h, $15
    ld d, $60
    ld b, $11
    ld h, b
    ld h, b
    ld b, $60
    inc e
    dec l
    dec e
    dec e
    dec l
    dec h
    ld h, c
    ld e, $60
    ld h, l
    inc b
    dec bc

jr_014_679b:
    ld a, l
    ld h, l
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld h, b
    ld de, $0e0e
    rst $38
    ld h, a
    or a
    ld h, a
    or e
    ld h, a
    nop
    cp e
    ld h, a
    call Call_000_3c6c
    ret


    cp c
    ld h, a
    nop
    ld d, a
    inc bc
    ld [$0505], sp
    ld [bc], a
    dec sp
    dec bc
    ld de, $3d00
    add hl, bc
    add hl, de
    inc bc
    dec sp
    rrca
    add hl, de
    inc b
    dec sp
    ld de, $0115
    dec a
    dec de
    dec c
    ld [bc], a
    dec a
    inc bc
    rla
    inc bc
    dec a
    inc bc
    dec de
    ld [bc], a
    rst $38
    nop
    nop
    daa
    rst $00
    dec b
    dec b
    ld l, c
    rst $00
    dec bc
    ld de, $c759
    add hl, bc
    add hl, de
    sub l
    rst $00
    rrca
    add hl, de
    and a
    rst $00
    ld de, $0715
    ret z

    dec de
    dec c
    inc e
    rst $00
    inc bc
    rla
    ld e, $c7
    inc bc
    dec de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ccf
    ccf
    ccf
    ccf
    inc bc
    inc bc
    ccf
    ccf
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    add hl, de
    inc a
    add hl, de
    dec a
    inc bc
    inc bc
    dec a
    add hl, de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec a
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    add hl, de
    inc a
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ccf
    ccf
    inc bc
    inc bc
    add hl, de
    add hl, de
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    inc bc
    dec a
    add hl, de
    inc bc
    inc bc
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    inc a
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    add hl, de
    add hl, de
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    add hl, de
    inc a
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld d, $09
    dec c
    rst $10
    ld [hl], b
    xor l
    ld l, d
    rst $08
    ld l, b
    nop
    ld d, a
    ld [hl], b
    call Call_014_68e5
    call Call_000_3c6c
    ld hl, $6acb
    ld de, $6985
    ld a, [$d5c7]
    call Call_000_31a8
    ld [$d5c7], a
    ret


Call_014_68e5:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld hl, $692f
    call Call_014_6936
    call Call_014_6962
    ld a, [$d7af]
    bit 4, a
    jr nz, jr_014_690c

    push af
    ld a, $54
    ld [$d07c], a
    ld bc, $0305
    ld a, $17
    call Call_000_3e9d
    pop af

jr_014_690c:
    bit 5, a
    jr nz, jr_014_691f

    push af
    ld a, $54
    ld [$d07c], a
    ld bc, $020a
    ld a, $17
    call Call_000_3e9d
    pop af

jr_014_691f:
    bit 6, a
    ret nz

    ld a, $54
    ld [$d07c], a
    ld bc, $060a
    ld a, $17
    jp Jump_000_3e9d


    inc bc
    dec b
    ld [bc], a
    ld a, [bc]
    ld b, $0a
    rst $38

Call_014_6936:
    push hl
    ld hl, $d6be
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    ld c, a
    xor a
    ldh [$e0], a
    pop hl

jr_014_6942:
    ld a, [hl+]
    cp $ff
    jr z, jr_014_695e

    push hl
    ld hl, $ffe0
    inc [hl]
    pop hl
    cp b
    jr z, jr_014_6953

    inc hl
    jr jr_014_6942

jr_014_6953:
    ld a, [hl+]
    cp c
    jr nz, jr_014_6942

    ld hl, $d6be
    xor a
    ld [hl+], a
    ld [hl], a
    ret


jr_014_695e:
    xor a
    ldh [$e0], a
    ret


Call_014_6962:
    ld hl, $d7af
    ldh a, [$e0]
    and a
    ret z

    cp $01
    jr nz, jr_014_6970

    set 4, [hl]
    ret


jr_014_6970:
    cp $02
    jr nz, jr_014_6977

    set 5, [hl]
    ret


jr_014_6977:
    set 6, [hl]
    ret


Jump_014_697a:
    xor a
    ld [$cd66], a

Jump_014_697e:
    ld [$d5c7], a
    ld [$d97c], a
    ret


    sub c
    ld l, c
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ldh a, [rBCPD]
    ld [hl], $6a
    sub e
    ld l, d
    ld a, [$d7ae]
    bit 0, a
    jp nz, Jump_000_3261

    ld hl, $69e6
    call Call_000_3509
    jp nc, Jump_000_3261

    xor a
    ldh [$b4], a
    ld a, $f0
    ld [$cd66], a
    ld a, $04
    ld [$d4a7], a
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld c, $02
    ld a, $de
    call Call_000_0e35
    ld a, $09
    ldh [$8c], a
    call Call_000_13f1
    ld a, $09
    ldh [$8c], a
    call Call_000_358b
    ld de, $69eb
    ld a, [$cd3d]
    ld [$cf08], a
    cp $01
    jr z, jr_014_69da

    inc de

jr_014_69da:
    ld a, $09
    ldh [$8c], a
    call Call_000_3684
    ld a, $03
    jp Jump_014_697e


    ld [bc], a
    inc bc
    inc bc
    inc bc
    rst $38
    ld b, b
    ld b, b
    ld b, b
    ld b, b
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    xor a
    ld [$cd66], a
    ld a, $0d
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_3e07
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $6f3e
    ld de, $6f60
    call Call_000_339c
    ld a, $f2
    ld [$d036], a
    ld a, [$d694]
    cp $b1
    jr nz, jr_014_6a24

    ld a, $07
    jr jr_014_6a2e

jr_014_6a24:
    cp $99
    jr nz, jr_014_6a2c

    ld a, $08
    jr jr_014_6a2e

jr_014_6a2c:
    ld a, $09

jr_014_6a2e:
    ld [$d03a], a
    ld a, $04
    jp Jump_014_697e


    ld a, [$d034]
    cp $ff
    jp z, Jump_014_697a

    ld a, $f0
    ld [$cd66], a
    ld hl, $d7ae
    set 0, [hl]
    ld a, $04
    ld [$d4a7], a
    ld a, $09
    ldh [$8c], a
    ld a, $04
    ldh [$8d], a
    call Call_000_34f0
    ld a, $0f
    ldh [$8c], a
    call Call_000_13f1
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a44
    call Call_000_3620
    ld de, $6a8b
    ld a, [$cf08]
    cp $01
    jr nz, jr_014_6a7c

    ld de, $6a88

jr_014_6a7c:
    ld a, $09
    ldh [$8c], a
    call Call_000_3684
    ld a, $05
    jp Jump_014_697e


    ret nz

    ret nz

    rst $38
    add b
    ld b, b
    ld b, b
    ret nz

    ret nz

    ret nz

    nop
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $a7
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    call Call_000_0d9b
    xor a
    ld [$cd66], a
    jp Jump_014_697e


    db $fc
    ld l, d
    ld e, [hl]
    ld l, h
    ret z

    ld l, h
    inc e
    ld l, l
    ld h, l
    ld l, l
    xor e
    ld l, l
    ld a, [c]
    ld l, l
    ld a, [hl-]
    ld l, [hl]
    adc c
    ld l, [hl]
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    sbc a
    ld l, [hl]
    ld a, $6f
    adc e
    ld l, a
    dec b
    jr nz, jr_014_6a7c

    rst $10
    ld l, a
    ld l, l
    adc e
    ld l, l
    add e
    ld l, l
    add e
    ld l, l
    ld b, $30
    xor [hl]
    rst $10
    or l
    ld l, l
    jp c, $d16d

    ld l, l
    pop de
    ld l, l
    rlca
    jr nc, @-$50

    rst $10
    db $fc
    ld l, l
    ld hl, $156e
    ld l, [hl]
    dec d
    ld l, [hl]
    ld [$ae40], sp
    rst $10
    ld b, h
    ld l, [hl]
    ld l, h
    ld l, [hl]
    ld h, h
    ld l, [hl]
    ld h, h
    ld l, [hl]
    rst $38
    ld [$adfa], sp
    sub $cb
    ld b, a
    jr z, jr_014_6b13

    ld a, [$d7b7]
    bit 7, a
    jr nz, jr_014_6b38

    ld hl, $6c23
    call Call_000_3c79
    jr jr_014_6b3e

jr_014_6b13:
    ld hl, $6b41
    call Call_000_3c79
    ld bc, $130f
    call Call_000_3e78
    jr nc, jr_014_6b3e

    ld a, [$ccd3]
    and a
    call z, Call_000_38ae
    call Call_000_3c6c
    ld hl, $6b90
    call Call_000_3c79
    ld hl, $d6ad
    set 0, [hl]
    jr jr_014_6b3e

jr_014_6b38:
    ld hl, $6c50
    call Call_000_3c79

jr_014_6b3e:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    sub c
    ld e, l
    set 0, h
    jr nc, @-$17

    ld c, a
    ld e, [hl]
    ld a, a
    inc l
    ldh [$7f], a
    push bc
    or d
    ret z

    ld d, l
    or a
    ret nc

    ld d, [hl]
    ld d, l
    ret nz

    cp l
    cp c

jr_014_6b5a:
    add $7f
    or a
    jp $dab8


    ret nz

    ret


    or [hl]
    rst $20
    ld d, l
    or l
    or l
    ld a, a
    or c
    ret c

    ld h, $c4
    or e
    rst $20
    ld d, c
    cp a
    or e
    jr nc, jr_014_6b5a

    ld c, a
    ret nz

    cp l
    cp c
    add $7f
    or a
    jp $b87f


    jp c, Jump_014_7fc0

    or a
    ret nc

    add $55
    cp d
    ret


    ld a, a
    ld d, h
    db $dd
    ld a, a
    call c, $bfc0
    or e
    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    rla
    ld e, [hl]
    jp z, $a57f

    ld b, d
    and l
    adc h
    call nz, $b27f
    rst $18
    jp $c44f


    jp $7fd3


    or c
    ret nz

    rst $08
    ret


    or d
    or d

jr_014_6baa:
    ld a, a
    ld d, h
    jr nc, @-$17

    ld d, c
    adc e
    and [hl]
    sbc e
    ret


    ld a, a
    cp c
    sbc $b7
    pop hl
    or e
    cp h
    jp nz, Jump_014_4f33

    or [hl]
    rst $18
    jp $c0b2


    ld h, $56
    ld d, l
    cp d
    cp d
    add $7f
    or d
    reti


    ld a, a
    sub $d8
    jp z, $2d55

    rst $18
    call nz, $b27f
    or d
    ld a, a

jr_014_6bd7:
    jp z, Jump_000_302d

    rst $20
    ld d, c
    or a
    ret nc

    push bc
    rst $10
    ld a, a
    or [hl]
    call c, Call_000_26b2
    rst $18
    jp $b87f


    jp c, $b3bf

    jr nc, jr_014_6baa

    ld c, a
    and l
    ld b, d
    and l
    adc h
    db $d3
    ld a, a
    sub $db
    cp d
    inc a
    ld a, a
    jr nc, jr_014_6bd7

    or e
    rst $20
    ld d, c
    or l
    sub $27
    ld h, $7f
    call nz, $b2b8
    ld a, a
    jr nc, @-$48

    rst $10
    ld c, a
    or e
    or h
    add $7f
    ret


    rst $18
    jp $b355


    ret nc

    db $dd
    ld a, a
    cp l
    cp l
    sbc $33
    db $d3
    ld a, a
    or d
    or d
    cpl
    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    ld b, a
    ld e, l
    ld a, a
    ld e, [hl]
    ret


    ld a, a
    inc e
    adc h
    ld h, $4f
    cp h
    ldh [$c1], a
    ld [c], a
    or e
    cp h
    jp nz, Jump_014_7fc6

    or c
    ld h, $df
    jp $c0df


    ld h, $55
    ld d, [hl]
    ld a, a
    cp h
    ldh [$c1], a
    ld [c], a
    or e
    ld h, $7f
    cp h
    sbc $44
    or d
    jr nc, @-$17

    ld d, a
    db $ed
    ld a, [hl+]
    ld c, $5f
    rst $18
    ret nz

    sub $7f
    or c
    ret c

    ld h, $c4
    rst $20
    ld d, a
    ld [$b7fa], sp
    rst $10
    bit 7, a
    jr nz, jr_014_6c6e

    ld hl, $6c77
    call Call_000_3c79
    jr jr_014_6c74

jr_014_6c6e:
    ld hl, $6ca4
    call Call_000_3c79

jr_014_6c74:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    add hl, hl
    ld e, a
    ret z

    rst $10

jr_014_6c7d:
    or d
    jp z, Jump_014_544f

    ld h, $7f
    or [hl]
    push bc
    rst $10
    dec l
    ld a, a
    call nz, $d9da
    ld d, l
    and c
    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    rst $20
    ld d, l
    ld d, [hl]
    ld a, a
    sbc l
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    ld a, a
    jr nc, jr_014_6c7d

    or e
    ld d, a
    db $ed
    ld a, [hl+]
    ld [hl], a
    ld e, a
    ret


    ld a, a
    cp [hl]
    or d
    inc sp
    ld d, [hl]
    ld c, a
    sbc l
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    jp z, $ca55

    jp nz, $b23a

    ld a, a
    pop bc
    pop hl
    or e
    cp h
    add $7f
    push bc
    rst $18
    ret nz

    sub $57
    ld [$b7fa], sp
    rst $10
    bit 7, a
    jr nz, jr_014_6cd8

    ld hl, $6ce1
    call Call_000_3c79
    jr jr_014_6cde

jr_014_6cd8:
    ld hl, $6cfe
    call Call_000_3c79

jr_014_6cde:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    call z, $d35f
    ld a, a
    ld d, h
    db $d3
    ld d, [hl]
    ld c, a
    ld e, [hl]
    ret


    ld a, a
    or d
    or d
    push bc
    ret c

    add $55
    push bc
    rst $18
    ret nz

    rst $10
    ld a, a
    call nc, $c530
    or c
    ld d, a
    db $ed
    ld a, [hl+]
    inc e
    ld h, b
    push bc
    or c
    rst $20
    ld c, a
    ld e, [hl]
    ret


    ld a, a
    jp c, $c1de

    pop hl
    or e
    db $dd
    ld d, l
    or l
    rst $18
    ld b, h
    rst $10
    rst $18
    ret nz

    sbc $30
    rst $18
    jp Jump_014_57e6


    ld [$b7fa], sp
    rst $10
    bit 7, a
    jr nz, jr_014_6d2c

    ld hl, $6d35

jr_014_6d27:
    call Call_000_3c79
    jr jr_014_6d32

jr_014_6d2c:
    ld hl, $6d57
    call Call_000_3c79

jr_014_6d32:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld d, d
    ld h, b
    ld d, [hl]
    rst $20
    ld d, l
    cp d
    cp d
    jp z, $b17f

    inc a
    push bc
    or d
    call c, $e7d6
    ld d, l
    ret nz

    cp l
    cp c
    add $7f
    or a
    ret nz

    and $55
    ld d, [hl]

jr_014_6d52:
    ld a, a
    jr nc, jr_014_6d27

    sub $57
    db $ed
    ld a, [hl+]
    sbc c
    ld h, b
    rst $18
    ret nz

    call c, $b17f
    ret c

    ld h, $c4
    rst $20
    ld d, a
    ld [$cb21], sp
    ld l, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa

jr_014_6d71:
    ld h, l
    ld [hl], d
    db $e3
    rst $20
    ld c, a
    cp d
    ret z

    dec l
    ret nc

    db $dd
    ld a, a
    ret nc

    jp nz, $c0b9

    cpl
    rst $20
    ld d, a
    db $ed
    daa
    jp nc, $bc72

    jr nc, jr_014_6d71

    ld e, b
    db $ed
    daa
    add b
    ld [hl], d
    pop bc
    ld [c], a
    db $db
    ld a, a
    cp h
    jp $7fd9


    jr nc, jr_014_6d52

    inc l
    ldh [rVBK], a
    inc e
    adc h
    add $ca
    ld a, a
    ret nz

    inc [hl]
    ret c

    ld a, a
    jp nz, $c5b9

    or d
    ld l, $57
    ld [$d721], sp
    ld l, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    push af
    ld [hl], d
    set 4, b
    rst $20
    ld d, c
    adc e
    and [hl]
    sbc e

jr_014_6dc0:
    ret


    ld a, a
    cp h
    ldh [$b2], a
    sbc $30
    call nz, $b54f
    db $d3
    rst $18
    ret nz

    or [hl]
    or d
    and $57
    db $ed
    daa
    sub b
    ld [hl], e
    ld d, h
    ld a, a
    push bc
    or d
    ld e, b
    db $ed
    daa
    ld c, d
    ld [hl], e
    ld a, a
    push bc
    ret


    add $56
    ld c, a
    push bc
    or [hl]
    push bc
    or [hl]
    ret


    ld a, a
    jp nz, $b2b6

    jp $307f


    push bc
    ld d, a
    ld [$e321], sp
    ld l, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    and a
    ld [hl], e
    cp a
    jp z, $a84f

    adc b
    xor h
    sub e
    ld a, a
    ld a, [$e2b7]
    or e
    jr nc, jr_014_6dc0

    ret


    ld a, a
    set 0, h
    ret c

    rst $20
    ld d, a
    db $ed
    daa
    inc h
    ld [hl], h
    sbc $7f
    rst $08
    cp c
    ret nz

    sub $e7
    ld e, b
    db $ed
    daa
    rst $10
    ld [hl], e
    or d
    or d
    ld c, a
    or c
    add $b7
    ld h, $7f
    or [hl]
    ret nz

    or a
    db $dd
    ld a, a
    call nz, $c3df
    ld a, a
    cp b
    jp c, $57d9

    ld [$ef21], sp
    ld l, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    inc a
    ld [hl], h
    add $7f
    cp h
    sbc $c6
    pop hl
    or e
    cp h
    ret nz

    ld a, a
    cp d
    inc [hl]
    db $d3
    ld c, a
    ld d, [hl]
    ld a, a
    or l
    rst $08
    or h
    ret


    ld a, a
    cp d
    call nz, $307f
    push bc
    rst $20
    ld d, a
    db $ed
    daa
    call nz, $bc74
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    ld a, a
    ld [hl], h
    ld a, a
    or l
    cp d
    reti


    ld a, a
    rst $08
    or h
    add $4f
    or [hl]
    or h
    rst $18
    jp $c87f


    ret nz

    ld a, a
    adc $b3
    ld h, $7f
    or d
    or d
    cpl
    ld d, a
    ld [$9321], sp
    ld l, [hl]
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    or a
    ld h, b
    rst $18
    jp $2ec0


    ld a, a
    ld d, d
    rst $20
    ld d, a

jr_014_6e9f:
    db $ed
    daa
    adc a
    ld l, a
    ldh [$ca], a
    jp z, Jump_014_4fe7

    cp d
    cp d
    inc sp
    ld a, a
    rst $08
    rst $18
    jp Jump_000_3ada


    ld d, l
    cp b
    reti


    sbc $2c
    ldh [$c8], a
    or h
    or [hl]
    call nz, $b57f
    db $d3
    rst $18
    ret nz

    ret


    cp e
    ld d, c
    cp h
    or [hl]
    cp h
    ld a, a
    ld e, [hl]
    ld a, a
    or c
    or d
    jp $4fc6


    jp $2dba


jr_014_6ed1:
    rst $18
    jp $7fd9


    ret nc

    ret nz

    or d
    jr nc, jr_014_6e9f

    rst $20
    ld d, l
    rst $08
    ld d, [hl]
    ld a, a
    or l
    jp c, $cfbb

    add $ca
    ld d, l
    or [hl]
    sbc $b9
    or d
    ret


    ld a, a
    push bc
    or d
    cp d
    call nz, $307f
    cp c
    inc [hl]
    rst $20
    ld d, c
    and d
    sbc l
    dec de
    add [hl]
    ld a, a
    adc e
    sub d
    or b
    inc sp
    ld a, a
    ld d, d
    ld h, $4f
    or c
    reti


    or d
    jp $c9de


    db $dd
    ld a, a
    pop bc

jr_014_6f0c:
    ld [c], a
    cp d
    rst $18
    call nz, $d055
    or [hl]
    cp c
    ret nz

    ld a, a
    db $d3
    ret


    ld a, a
    jr nc, jr_014_6ed1

    rst $10
    cp e
    ld d, c
    cp l
    cp d
    cp h
    jp z, Jump_014_7f56

    jp nz, $b8d6

    push bc
    rst $18
    ret nz

    ret


    or [hl]
    ld c, a
    push bc
    or c
    db $e3
    sbc $c1
    ldh [$df], a
    jp $b57f


    db $d3
    rst $18
    jp $b1bb


    rst $20
    ld d, a
    db $ed
    inc l
    db $db
    ld c, b
    or l
    or e
    xor h
    rst $20
    ld c, a

jr_014_6f47:
    ld e, [hl]
    ret


    ld a, a
    inc e
    adc h
    add $55
    or d
    inc [hl]
    pop de
    jr nc, jr_014_6f0c

    ret


    ld a, a
    cp d
    call nz, Call_014_7fca
    or c
    reti


    inc l
    ldh [$de], a
    rst $20
    ld e, b
    db $ed
    inc l
    sbc e
    ld c, b
    rst $08
    or h
    push bc
    or c
    ld d, [hl]
    ld d, c
    cp d
    sbc $c5
    ld a, a
    or e
    inc sp
    rst $08
    or h
    inc l
    ldh [rVBK], a
    rst $08
    jr nc, jr_014_6f47

    jr nc, jr_014_6fd0

    ld d, l
    or d
    pop bc
    add $de
    rst $08
    or h
    ld a, a
    call nz, Call_014_7fca
    or d
    or h
    push bc
    or d
    ld l, $58
    db $ed
    daa
    ld a, [$e070]
    rst $08
    ld a, a
    ld d, d
    rst $20
    ld d, c
    or l
    jp c, $cfbb

    jp z, $cb4f

    call nz, $bcb1
    ld a, a
    cp e
    or a
    add $7f
    or d
    cp b
    ld l, $e7
    ld d, c
    ld d, h
    dec l
    or [hl]
    sbc $7f
    call nc, $c3df
    reti


    ld a, a
    or e
    pop bc
    add $4f
    inc [hl]
    or e
    or d
    or e
    ld a, a
    ld d, h
    ld h, $7f
    jp nz, $b2d6

    ld a, a
    call nz, Call_014_55b6
    push bc
    add $c6
    ld a, a
    cp h
    sbc $b6
    ld a, a
    cp l
    reti


jr_014_6fd0:
    or [hl]
    ld a, a
    call nz, Call_014_55b6
    call c, $dfb6
    jp $b77f


    pop bc
    ldh [$df], a
    ret nz

    sbc $30
    sub $c8
    or h
    rst $20
    ld d, l
    or l
    jp c, $c3df

    ld a, a
    jp $bbde


    or d
    and $51
    rst $08
    ld d, [hl]
    ld a, a
    cp a
    or e
    or d
    or e
    ld a, a
    cp d
    call nz, Call_014_4f33
    cp d
    jp c, $d7b6

    jp z, Jump_014_5455

    ld a, a
    ret c

    db $e3
    rlca
    ret


    ld a, a
    cp h
    jp $c9de


    or e
    db $dd
    ld d, l
    ld a, [hl-]
    rst $18
    cp e
    ld a, a
    ld a, [hl-]
    rst $18
    cp e
    call nz, $c07f
    or l
    cp h
    jp $bb51


    or d
    or a
    ld [c], a
    or e
    ret


    ld a, a
    ld e, l
    add $4f
    push bc
    rst $18
    jp $dbd4


    or e
    ld a, a
    call nz, $b77f
    jp nc, $c9c0

    cp e
    rst $20
    ld d, c
    ld d, d
    db $d3
    ld c, a
    cp [hl]
    or d
    ld l, $b2
    ld a, a
    ld h, $de
    ld a, [hl-]
    rst $18
    jp $b87f


    jp c, $55b2

    inc l
    ldh [$b1], a
    push bc
    rst $20
    ld d, l
    add hl, de
    add c
    ld a, [de]
    db $e3
    rst $20
    ld d, a
    ld l, $06
    nop
    db $10
    ld bc, $00d5
    ld d, $00
    db $d3
    nop
    ld [de], a
    nop
    db $ec
    rlca
    dec b
    inc bc
    db $eb
    inc bc
    dec b
    ld [$0fd0], sp
    dec d
    inc bc
    jp nc, $0b00

    inc l
    add hl, bc
    dec b
    rst $38
    rst $38
    ld bc, $112c
    ld de, $d1ff
    ld [bc], a
    inc l
    ld c, $0b
    rst $38
    rst $38
    inc bc
    dec de
    inc c
    ld c, $ff
    rst $38
    inc b
    jr @+$07

    ld de, $d0ff
    ld b, l
    and $20
    jr nz, jr_014_70a6

    ld b, $ff
    ret nc

    ld b, [hl]
    db $e4
    ld [$0618], sp
    jr @+$01

    jp nc, $e647

    ld hl, $1218
    rla

jr_014_70a6:
    rst $38
    db $d3
    ld c, b
    and $22
    ld [bc], a
    dec bc
    rlca
    rst $38
    pop de
    add hl, bc
    dec a
    dec c
    dec b
    rst $38
    rst $38
    adc d
    daa
    dec a
    rrca
    inc e
    rst $38
    rst $38
    adc e
    rlc h
    rst $00
    nop
    db $10
    rlca
    rst $00
    nop
    ld d, $05
    rst $00
    nop
    ld [de], a
    scf
    rst $00
    rlca
    dec b
    ld de, $03c7
    dec b
    adc e
    rst $00
    rrca
    dec d
    ld b, b
    ld b, c
    ld h, c
    ld h, b
    ld b, c
    ld b, c
    db $10
    ld b, d
    ld a, l
    ld a, h
    dec a
    inc h
    ld a, $44
    ld c, $2f
    ld h, h
    ld [hl+], a
    ld [hl+], a
    inc hl
    ld [hl], c
    ld c, $0e
    ld c, $0e
    ld b, [hl]
    ld b, h
    ld c, $47
    ld b, h
    ld c, $0e
    ld c, $0c
    ld e, d
    ld h, e
    ld c, $67
    ld b, d
    ld b, h
    ld c, $2f
    ld b, b
    ld h, e
    ld c, $67
    ld b, d
    ld b, [hl]
    dec c
    ld c, $34
    ld b, [hl]
    ld b, b
    ld h, c
    ld h, c
    ld b, h
    inc [hl]
    ld c, $34
    ld b, [hl]
    ld b, [hl]
    dec c
    ld c, $36
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld b, h
    ld [hl], $0e
    ld [hl], $46
    ld b, [hl]
    dec c
    ld c, $37
    ld b, [hl]
    ld b, h
    add hl, bc
    dec c
    ld b, h
    scf
    ld c, $37
    ld b, [hl]
    ld b, [hl]
    ld h, e
    ld c, $67
    ld b, d
    ld b, h
    ld c, $0e
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld b, [hl]
    ld c, $2f
    ld c, $46
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld d, a
    ld c, c
    ld c, c
    ld c, d
    ld d, $0e
    rrca
    ld d, [hl]
    ld [hl], e
    call $5871
    ld [hl], c
    nop
    rla
    ld [hl], e
    call Call_014_716e
    call Call_000_3c6c
    ld hl, $71d7
    ld de, $71c7
    ld a, [$d5bb]
    call Call_000_31a8
    ld [$d5bb], a
    ret


Call_014_716e:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld a, [$d715]
    bit 0, a
    jr nz, jr_014_7196

    ld a, $0e
    ld bc, $0204
    call Call_014_71af
    ld a, $54
    ld bc, $0409
    call Call_014_71af
    ld a, $5f
    ld bc, $0b03
    call Call_014_71af
    ret


jr_014_7196:
    ld a, $5f
    ld bc, $0204
    call Call_014_71af
    ld a, $0e
    ld bc, $0409
    call Call_014_71af
    ld a, $0e
    ld bc, $0b03
    call Call_014_71af
    ret


Call_014_71af:
    ld [$d07c], a
    ld a, $17
    jp Jump_000_3e9d


    ld a, [$c109]
    cp $04
    ret nz

    xor a
    ldh [$b4], a
    ld a, $05
    ldh [$8c], a
    jp Jump_000_13f1


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    db $e4
    ld [hl], c
    push bc
    rrca
    ld c, d
    ld [hl], d
    add b
    ld [hl], d
    and [hl]
    ld [hl], d
    ld bc, $c600
    rst $10
    xor $71
    jr nz, @+$74

    rrca
    ld [hl], d
    rrca
    ld [hl], d
    rst $38
    ld [$d721], sp
    ld [hl], c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld d, [hl]
    ld [hl], a
    call nc, $b7bc
    ld a, a
    cp h
    or [hl]
    cp c
    ld h, $7f
    cp h
    jp $dfb1


    jp $c54f


    or [hl]
    push bc
    or [hl]
    ld a, a
    cp l
    cp l
    jp nc, $becf

    sbc $2e
    rst $20
    ld d, a
    db $ed
    daa
    xor $77
    rst $20
    ld c, a
    call z, $bcdb
    or a
    ret


    ld a, a
    push bc
    or [hl]
    ret nc

    ld h, $58
    db $ed
    daa
    adc h
    ld [hl], a
    ret


    ld a, a
    adc h
    add c
    xor h
    sub b
    db $dd
    ld a, a
    or l
    cp l
    call nz, $cc4f
    ret nz

    jp nz, Jump_014_7fc9

    call nz, $d73b
    ld h, $55
    ret nz

    ld h, $b2
    ld a, a
    pop bc
    ld h, $b2
    add $7f
    set 2, a
    cp b
    sbc $33
    cp e
    ld d, a
    db $ed
    daa
    and [hl]
    db $76
    ld a, a
    db $fd
    ld h, $c2
    ei
    or [hl]
    ld c, a
    cp d
    cp d
    jp z, $d07f

    push bc
    ret nc

    add b
    and b
    ret c

    add l
    ret


    ld a, a
    ld b, $80
    sub h
    ld d, c
    dec bc
    xor l
    xor e
    rlca
    and [hl]
    ret


    ld a, a
    or l
    cp b
    pop bc
    inc sp
    ld c, a
    cp h
    sbc $bc
    pop hl
    ret


    ld a, a
    ld d, h
    db $dd
    ld a, a
    jp z, $b9df

    sbc $57
    db $ed
    daa
    dec h
    ld [hl], a
    ld a, a
    db $fd
    ld h, $c2
    rst $30
    or $b6
    ld c, a
    cp h
    sbc $ca
    rst $18
    cp c
    sbc $c9
    ld a, a
    ld d, h
    db $dd
    ld d, l
    call c, $bcc0
    jp z, $9e7f

    xor [hl]
    add d
    call nz, $c57f
    ld [hl-], a
    cp c
    ret nz

    ld d, a
    ld [$e121], sp
    ld [hl], d
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_014_72d8

    ld a, $01
    ld [$cc3c], a
    ld hl, $d0eb
    set 5, [hl]
    ld hl, $72fb
    call Call_000_3c79
    ld a, $ad
    call Call_000_0e45
    ld hl, $d715
    bit 0, [hl]
    set 0, [hl]
    jr z, jr_014_72de

    res 0, [hl]
    jr jr_014_72de

jr_014_72d8:
    ld hl, $730b
    call Call_000_3c79

jr_014_72de:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ret nc

    ld h, b
    ret


    ld a, a
    adc h
    add c
    xor h
    sub b
    ld h, $7f
    or c
    reti


    rst $20
    ld d, c
    or l
    cp h
    jp $d07f


    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    ld a, [hl+]
    db $fc
    ld h, b
    ret nc

    sub $b3
    rst $20
    ld a, a
    ld d, [hl]
    ld b, e
    sub b
    xor h
    call nz, $58c5
    db $ed
    ld a, [hl+]
    inc d
    ld h, c
    jp z, $b17f

    or a
    rst $10
    jp nc, Jump_014_57c0

    ld bc, $0a04
    dec b
    inc b
    and l
    ld a, [bc]
    rlca
    nop
    rst $10
    ld c, $19
    ld [bc], a
    rst $10
    ld bc, $0106
    rst $10
    nop
    inc b
    inc c
    dec d
    rlca
    cp $02
    ld b, c
    db $d3
    rlca
    dec a
    dec bc
    jr nz, @+$01

    rst $38
    add d
    daa
    ld b, c
    ld b, $16
    rst $38
    rst $38
    inc bc
    ld b, c
    ld a, [de]
    rlca
    rst $38
    rst $38
    inc b
    ld l, c
    rst $00
    ld a, [bc]
    dec b
    ld l, d
    rst $00
    ld a, [bc]
    rlca
    sbc l
    rst $00
    ld c, $19
    ld bc, $01c7
    ld b, $68
    ld h, l
    ld h, l
    ld l, d
    ld b, d
    ld b, c
    ld b, c
    ld b, d
    ld b, c
    ld b, c
    ld b, c
    ld b, b
    ld h, c
    ld h, l
    ld l, c
    ld e, h
    ld b, $0e
    ld c, $56
    ld c, $0e
    ld b, [hl]
    ld c, $47
    ld c, $70
    ld c, $07
    ld e, l
    ld e, h
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld d, [hl]
    ld e, b
    ld c, $57
    ld b, $38
    ld c, $46
    ld b, h
    ld c, $43
    ld b, e
    ld e, d
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld sp, $0606
    ld b, [hl]
    ld d, b
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld c, $09
    ld h, b
    ld h, e
    ld c, $67
    ld b, $41
    ld h, l
    ld l, c
    ld b, h
    ld [hl], a
    ld l, a
    ld l, [hl]
    ld c, $0e
    add hl, bc
    ld h, h
    ld c, $0e
    ld c, $38
    ld c, $0e
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld e, d
    jr c, jr_014_7409

    ld c, c
    ld b, $06
    ld e, b
    ld c, $38
    ld c, $57
    ld d, c
    ld l, e
    ld h, c
    ld a, [hl+]
    ld e, l
    jr c, @+$48

    ld b, $06
    ld b, $0e
    ld c, $06
    ld l, [hl]
    ld c, $46
    ld b, h
    ld c, $31
    ld b, $06
    ld b, [hl]
    ld c, $6c
    ld bc, $1f1f
    rra
    rra
    rra
    ld c, a
    ld l, e
    ld h, c
    ld h, c
    ld b, d
    ld c, $46
    ld c, $6c
    ld bc, $0101
    ld bc, $0101
    ld bc, $0e44
    ld c, $56
    ld c, $56
    ld c, $6c
    ld bc, $0101
    ld bc, $0101
    ld bc, $4744
    ld b, a
    ld c, $0e
    ld d, e
    ld c, $6c
    ld bc, $0101
    ld bc, $0101

jr_014_7409:
    ld bc, $0e44
    ld c, $5a
    ld c, $46
    ld c, $6c
    ld bc, $0101
    ld bc, $0101
    ld bc, $4948
    ld c, c
    ld c, d
    ld c, c
    ld c, d
    rra
    ld l, l
    ld bc, $0101
    ld bc, $0101
    ld bc, $0916
    rrca
    dec c
    db $76
    ret nc

    ld [hl], h
    inc [hl]
    ld [hl], h
    nop
    call $cd75
    ld c, d
    ld [hl], h
    call Call_000_3c6c
    ld hl, $74dc
    ld de, $747b
    ld a, [$d5bc]
    call Call_000_31a8
    ld [$d5bc], a
    ret


    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld a, [$d715]
    bit 0, a
    jr nz, jr_014_746a

    ld a, $0e
    ld bc, $0207
    call Call_014_71af
    ld a, $5f
    ld bc, $0507
    call Call_014_71af
    ret


jr_014_746a:
    ld a, $5f
    ld bc, $0207
    call Call_014_71af
    ld a, $0e
    ld bc, $0507
    call Call_014_71af
    ret


    add c
    ld [hl], h
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld hl, $749a
    call Call_014_74a1
    ld a, [$d69d]
    and a
    jp z, Jump_000_3261

    cp $03
    ld a, $a5
    jr nz, jr_014_7496

    ld a, $d6

jr_014_7496:
    ld [$d69c], a
    ret


    ld c, $10
    ld c, $11
    ld c, $13
    rst $38

Call_014_74a1:
    xor a
    ld [$d69d], a
    ld a, [$d6ac]
    bit 4, a
    ret nz

    call Call_000_3509
    ret nc

    ld a, [$cd3d]
    ld [$d69d], a
    ld hl, $d6ac
    set 4, [hl]
    ld hl, $d6b1
    set 4, [hl]
    ret


    ld a, [$c109]
    cp $04
    ret nz

    xor a
    ldh [$b4], a
    ld a, $06
    ldh [$8c], a
    jp Jump_000_13f1


    push af
    ld [hl], h
    ld a, [hl-]
    ld [hl], l
    push bc
    rrca
    push bc
    rrca
    sub a
    ld [hl], l
    and [hl]

jr_014_74db:
    ld [hl], d
    ld bc, $c800
    rst $10
    rst $38
    ld [hl], h
    ld hl, $1675
    ld [hl], l
    ld d, $75
    ld [bc], a
    jr nz, @-$36

    rst $10
    ld b, h
    ld [hl], l
    ld h, a
    ld [hl], l
    ld e, [hl]
    ld [hl], l
    ld e, [hl]
    ld [hl], l
    rst $38
    ld [$dc21], sp
    ld [hl], h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld e, d
    ld a, b
    ld a, a
    cp h
    jp Jump_014_4fd3


    inc sp
    rst $18
    cp c
    db $e3
    ld a, a
    call nc, $b7bc
    ld a, a
    jr nc, jr_014_74db

    or h
    rst $20
    ld d, a
    db $ed
    daa
    xor [hl]
    ld a, b
    db $db
    ld a, a
    ld a, $e3
    sbc $e7
    ld e, b
    db $ed
    daa
    ld a, b
    ld a, b
    or d
    ld a, $b3
    ld h, $7f
    or d
    ret nz

    sbc $30
    ld c, a
    inc [hl]
    cp d
    ld a, a
    or d
    rst $18
    ret nz

    sbc $30
    db $db
    and $57
    ld [$e821], sp
    ld [hl], h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    cp e
    ld a, b
    ld a, a
    or [hl]
    jp nz, $4fc3

    call c, $bcc0
    ret


    ld a, a
    cp [hl]
    sbc $be
    or d
    ld h, $7f
    cp l
    sbc $33
    or d
    ret nz

    ld d, a
    db $ed
    daa
    ld a, $79
    ld a, a
    jp nz, $b2d6

    ld e, b
    db $ed
    daa
    db $dd
    ld a, b
    or d
    ld a, a
    ld a, [hl-]
    cp h
    ld [c], a
    add $7f
    or d
    cp c
    push bc
    cp b
    jp $ba4f


    rst $08
    rst $18
    jp $c9d9


    or [hl]
    ld d, [hl]
    ld a, a
    cp a
    cp d
    or [hl]
    rst $10
    ld d, l
    or l
    db $d3
    or d
    or a
    rst $18
    jp $c47f


    dec sp
    or l
    ret c

    jp $d07f


    db $db
    rst $20
    ld d, a
    db $ed
    daa
    ld de, $7f78
    ld hl, sp+$26
    jp nz, $b6fc

    ld c, a
    sbc [hl]
    xor [hl]
    add d
    ld h, $7f
    cp d
    inc [hl]
    db $d3
    db $dd
    ld a, a
    or e
    pop de
    ld d, c
    or e
    rst $08
    jp c, Jump_014_7fc0

    ld a, [hl-]
    or [hl]
    ret c

    ret


    ld a, a
    dec bc
    xor [hl]
    sub l
    add b
    db $dd
    ld c, a
    sbc [hl]
    xor [hl]
    add d
    sub c
    db $e3
    call nz, $d67f
    inc a
    cp d
    call nz, Call_014_56c6
    ld d, a
    ld bc, $0a03
    rlca
    ld bc, $01d6
    ld b, $03
    sub $0e
    add hl, de
    ld [bc], a
    sub $00
    dec b
    inc c
    rrca
    add hl, bc
    cp $02
    ld b, c
    db $d3
    ld [$0f20], sp
    jr @+$01

    jp nc, $e442

    inc c
    dec a
    inc d
    dec b
    rst $38
    rst $38
    add e
    ld de, $093d
    dec e
    rst $38
    rst $38
    add h
    dec h
    ld b, c
    db $10
    ld a, [bc]
    rst $38
    rst $38
    dec b
    ld l, d
    rst $00
    ld a, [bc]
    rlca
    ld bc, $01c7
    ld b, $9d
    rst $00
    ld c, $19
    ld b, b
    ld b, c
    ld b, c
    ld [hl], e
    ld b, c
    ld h, l
    ld h, l
    ld b, d
    ld h, c
    ld h, c
    ld h, c
    ld b, b
    ld b, $06
    ld b, $44
    ld c, $0e
    ld c, $0e
    ld c, $06
    ld d, [hl]
    ld c, $0e
    ld c, $55
    ld c, $06
    ld b, $5c
    jr c, @+$10

    ld c, $31
    ld [hl], a
    ld c, $0e
    ld c, $47
    ld c, $0e
    ld c, $31
    ld b, $5c
    ld b, $06
    ld b, $06
    ld c, $0e
    ld e, d
    ld c, $0e
    ld sp, $0e38
    ld c, $46
    ld e, h
    ld b, $38
    ld c, $67
    ld l, c
    dec c
    ld d, [hl]
    ld c, c
    ld b, $06
    ld b, $49
    ld c, c
    ld d, c
    ld b, h
    ld b, $0e
    ld l, a
    ld c, $5d
    dec c
    ld c, $07
    ld c, $0e
    jr c, jr_014_7673

    ld c, $46
    ld b, h
    rlca
    ld c, $47
    ld sp, $495d
    ld b, $0e
    ld [hl], h
    ld d, a
    ld d, d

jr_014_7673:
    ld d, a
    ld c, c
    ld d, c
    ld e, h
    ld b, $0e
    ld c, $06
    ld e, l
    ld bc, $0101
    ld bc, $4401
    ld l, a
    ld c, $46
    ld c, b
    ld c, c
    ld c, c
    ld b, $06
    ld b, $01
    ld bc, $0101
    ld bc, $4948
    ld c, c
    ld c, d
    ld d, $0e
    rrca
    ld d, l
    ld a, b
    dec e
    ld [hl], a
    and b
    halt
    db $10
    ld a, b
    call Call_014_76b6
    call Call_000_3c6c
    ld hl, $772f
    ld de, $7717
    ld a, [$d5bd]
    call Call_000_31a8
    ld [$d5bd], a
    ret


Call_014_76b6:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld a, [$d715]
    bit 0, a
    jr nz, jr_014_76e6

    ld a, $0e
    ld bc, $080d
    call Call_014_71af
    ld a, $0e
    ld bc, $0b06
    call Call_014_71af
    ld a, $5f
    ld bc, $0304
    call Call_014_71af
    ld a, $54
    ld bc, $0808
    call Call_014_71af
    ret


jr_014_76e6:
    ld a, $2d
    ld bc, $080d
    call Call_014_71af
    ld a, $5f
    ld bc, $0b06
    call Call_014_71af
    ld a, $0e
    ld bc, $0304
    call Call_014_71af
    ld a, $0e
    ld bc, $0808
    call Call_014_71af
    ret


    ld a, [$c109]
    cp $04
    ret nz

    xor a
    ldh [$b4], a
    ld a, $09
    ldh [$8c], a
    jp Jump_000_13f1


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld c, b
    ld [hl], a
    sub b
    ld [hl], a
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    pop hl
    ld [hl], a
    push bc
    rrca
    and [hl]
    ld [hl], d
    ld bc, $ca00
    rst $10
    ld d, d
    ld [hl], a
    ld [hl], d
    ld [hl], a
    ld l, b
    ld [hl], a
    ld l, b
    ld [hl], a
    ld [bc], a
    jr nc, @-$34

    rst $10
    sbc d
    ld [hl], a
    pop bc
    ld [hl], a
    or [hl]
    ld [hl], a
    or [hl]
    ld [hl], a
    rst $38
    ld [$2f21], sp
    ld [hl], a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    and e
    ld a, c
    ret c

    ldh [$7f], a
    cp d
    rst $08
    rst $18
    ret nz

    ld c, a
    ret nc

    pop bc
    add $7f
    rst $08
    sub $df
    ret nz

    cpl
    ld d, a
    db $ed
    daa
    ld [de], a
    ld a, d
    ld a, a
    inc [hl]
    db $db
    inc [hl]
    db $db
    ld e, b
    db $ed
    daa
    call Call_014_7f79
    cp l
    sbc $33
    ret nz

    ld a, a
    set 0, h
    ret


    ld c, a
    inc [hl]
    or e
    jr z, jr_014_77aa

    ld a, a
    cp c
    rst $18
    cp d
    or e
    ld a, a
    or l
    pop bc
    jp Jump_000_2ed9


    ld d, a
    ld [$3b21], sp
    ld [hl], a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    rra
    ld a, d
    ld a, a
    set 3, e
    cp b
    jp $b94f


    sbc $b7
    pop hl
    or e
    cp l

jr_014_77aa:
    reti


    add $ca
    ld a, a
    or d
    or d
    ld a, a
    ld a, [hl-]
    cp h
    ld [c], a
    jr nc, jr_014_780d

    db $ed
    daa
    or c
    ld a, d
    ld a, a
    cp l
    reti


    ret


    or [hl]
    ret z

    ld e, b
    db $ed
    daa
    ld e, c
    ld a, d
    or d
    rst $18
    ret nz

    sub $e7
    ld c, a
    cp d
    cp d
    add $7f
    cp l
    jp nc, $553a

    cp c
    sbc $b7
    pop hl
    or e
    db $d3
    ld a, a
    jp z, $34b6

    reti


    push bc
    ld d, [hl]
    ld d, a
    db $ed
    daa
    ld c, l
    ld a, c
    ld a, a
    rst $38
    ld h, $c2
    rst $30
    add $c1
    ld c, a
    ld d, h
    ld a, a
    sbc [hl]
    xor [hl]
    add d
    sub c
    db $e3
    jp z, $c27f

    sub $bd
    daa
    reti


    ld d, c
    rrca
    and b
    jr nc, jr_014_7856

    ld c, a
    call c, $bcc0
    ret


    ld a, a
    jp $cac6


    ld a, a
    or l
    or h
    push bc

jr_014_780d:
    or d
    rst $20
    ld d, a
    ld bc, $1601
    rla
    dec b
    and l
    nop
    ld [$1b0c], sp
    inc d
    rst $38
    rst $38
    ld b, c
    db $d3
    add hl, bc
    jr nz, jr_014_7831

    rra
    rst $38
    ret nc

    ld b, d
    db $e4
    dec c
    dec a
    ld b, $0e
    rst $38
    rst $38
    add e
    jr z, jr_014_786d

    ld a, [de]

jr_014_7831:
    dec b
    rst $38
    rst $38
    add h
    db $10
    dec a
    dec e
    rla
    rst $38
    rst $38
    add l
    sub $3d
    ld [$ff09], sp
    rst $38
    add [hl]
    sbc $41
    jr jr_014_785b

    rst $38
    rst $38
    rlca
    dec a
    ld de, $ff09
    rst $38
    adc b
    dec hl
    ldh a, [$c7]
    ld d, $17
    ld h, b

jr_014_7856:
    ld h, c
    ld h, c
    ld h, c
    ld b, d
    ld h, c

jr_014_785b:
    ld h, c
    ld h, c
    ld h, c
    ld h, d
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld h, h
    ld c, $0e
    ld c, $46
    ld c, $0e
    ld c, $0e

jr_014_786d:
    ld h, [hl]
    ld [hl], a
    ld b, e
    ld b, e
    ld b, e
    ld b, [hl]
    ld b, h
    ld c, $47
    ld c, $56
    ld e, b
    ld c, $57
    ld c, c
    ld c, d
    ld c, c
    ld e, b
    ld c, $57
    ld d, c
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld b, b
    ld h, e
    ld c, $67
    ld b, d
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld c, $46
    ld b, h
    dec bc
    ld c, $0b
    ld b, [hl]
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld c, $46
    ld b, h
    ld c, $0e
    ld c, $46
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld c, $46
    ld b, h
    dec bc
    ld c, $0b
    ld b, [hl]
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld c, $46
    ld d, b
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld c, $5a
    ld h, c
    ld c, $61
    ld e, c
    ld c, $56
    ld c, $51
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld c, $0e
    ld c, $44
    ld c, $0e
    ld c, $46
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $56
    ld c, $47
    ld c, $44
    ld c, $0e
    ld c, $46
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $44
    ld l, [hl]
    ld c, $0e
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $5a
    ld c, $0e
    ld [hl], a
    ld b, h
    ld c, $0e
    ld c, $46
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld c, c
    ld c, c
    ld c, c
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ldh a, [$d7]
    ld [$d0b1], a
    xor a
    ld [$cd65], a
    ld [$cf06], a
    ld hl, $cc2b
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$cc36], a
    ld [$d03b], a
    ld [$cffb], a
    ld [$d035], a
    ld [$cc2f], a
    ld [$d055], a
    ld [$d2dc], a
    ld hl, $cf17
    ld [hl+], a
    ld [hl], a
    ld hl, $ccd3
    ld b, $3c

jr_014_7959:
    ld [hl+], a
    dec b
    jr nz, jr_014_7959

    inc a
    ld [$ccd9], a
    ld a, [$d2dd]
    cp $d9
    jr c, jr_014_7971

    cp $dd
    jr nc, jr_014_7971

    ld a, $02
    ld [$d037], a

jr_014_7971:
    ld hl, $6ef1
    ld b, $02
    jp Jump_000_3620


    ld hl, $cfd0
    ld de, $cfbc
    ldh a, [$f3]
    and a
    jp z, Jump_014_798b

    ld hl, $cfff
    ld de, $cfb6

Jump_014_798b:
    ld a, [hl]
    and a
    jr nz, jr_014_79d1

    ld a, [de]
    cp $17
    jr nz, jr_014_79a2

    ld b, h
    ld c, l
    inc bc
    ld a, [bc]
    cp $04
    jr z, jr_014_79de

    inc bc
    ld a, [bc]
    cp $04
    jr z, jr_014_79de

jr_014_79a2:
    push hl
    ld hl, $684d
    ld b, $0f
    call Call_000_3620
    pop hl
    ld a, [$d03c]
    and a
    jr nz, jr_014_79d1

    set 6, [hl]
    ld hl, $7018
    ld b, $0f
    call Call_000_3620
    ld c, $1e
    call Call_000_3781
    ld hl, $7fdb
    ld b, $0f
    call Call_000_3620
    ld hl, $7f90
    ld b, $0f
    jp Jump_000_3620


jr_014_79d1:
    ld c, $32
    call Call_000_3781
    ld hl, $7f66
    ld b, $0f
    jp Jump_000_3620


jr_014_79de:
    ld c, $32
    call Call_000_3781
    ld hl, $5eb2
    ld b, $0f
    jp Jump_000_3620


    ld hl, $7a54
    ld a, [$d2dd]
    ld b, a

jr_014_79f2:
    ld a, [hl+]
    cp $ff
    ret z

    cp b
    jr nz, jr_014_79f2

    ld a, [$cfad]
    cp $18
    jr z, jr_014_7a0f

    cp $24
    jr z, jr_014_7a0f

    ld b, a
    ld a, [$d2dd]
    cp $eb
    ret nz

    ld a, b
    cp $5e
    ret nz

jr_014_7a0f:
    ld b, $30
    call Call_000_34dd
    jr z, jr_014_7a4d

    ld a, $01
    ldh [$8c], a
    call Call_000_3f25
    call Call_014_7a95
    srl d
    ld a, d
    ld b, a
    ld [$d6be], a
    srl e
    ld a, e
    ld c, a
    ld [$d6bf], a
    ld a, [$d2dd]
    cp $eb
    jr nz, jr_014_7a39

    ld a, $03
    jr jr_014_7a3b

jr_014_7a39:
    ld a, $0e

jr_014_7a3b:
    ld [$d07c], a
    ld a, $17
    call Call_000_3e9d
    ld hl, $d0eb
    set 5, [hl]
    ld a, $ad
    jp Jump_000_0e45


jr_014_7a4d:
    ld a, $02
    ldh [$8c], a
    jp Jump_000_3f25


    rst $08
    ret nc

    pop de
    jp nc, $d4d3

    push de
    jp hl


    ld [$ffeb], a
    db $ed
    inc l
    ld h, c
    ld l, [hl]
    ld b, e
    db $e3
    xor e
    rst $20
    ld d, b
    dec bc
    nop

jr_014_7a6a:
    ld c, a
    add l
    db $e3
    inc de
    add [hl]
    db $e3
    inc sp
    ld a, a
    xor b
    xor h
    add a
    ld a, a
    db $dd
    jp z, $bc2d

    ret nz

    rst $20
    ld d, a
    nop
    ld d, [hl]
    jr nc, @-$2c

    jr nc, jr_014_7a6a

    ld c, a
    add l
    db $e3
    inc de
    add [hl]
    db $e3
    ld h, $7f
    push bc
    or d
    call nz, $b17f
    or [hl]
    push bc
    or d
    rst $20
    ld d, a

Call_014_7a95:
    ld a, [$d2e0]
    ld d, a
    ld a, [$d2e1]
    ld e, a
    ld a, [$c109]
    and a
    jr nz, jr_014_7aa5

    inc d
    ret


jr_014_7aa5:
    cp $04
    jr nz, jr_014_7aab

    dec d
    ret


jr_014_7aab:
    cp $08
    jr nz, jr_014_7ab1

    dec e
    ret


jr_014_7ab1:
    inc e
    ret


    ld b, $45
    call Call_000_34dd
    jr nz, jr_014_7ac0

    ld hl, $7b16
    jp Jump_000_3c79


jr_014_7ac0:
    ld hl, $d6af
    set 6, [hl]
    ld hl, $7b29
    call Call_000_3c79
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    ld a, $03
    ld [$cc29], a
    ld a, $03
    ld [$cc28], a
    ld a, $04
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    call Call_014_7c31
    ld hl, $c3c8
    ld b, $08
    ld c, $10
    call Call_000_03d2
    call Call_014_7b4a
    call Call_000_0ebd
    ld hl, $7b3d
    call Call_000_3c79
    call Call_000_3b08
    bit 1, a
    jr nz, jr_014_7b10

    ld a, [$cc26]
    cp $03
    jr z, jr_014_7b10

    call Call_014_7c7c

jr_014_7b10:
    ld hl, $d6af
    res 6, [hl]
    ret


    db $ed
    ld a, [hl+]
    ld b, h
    ld h, c
    adc b
    db $e3
    adc h
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $c5b2


    or d
    rst $20
    ld d, b
    dec c
    ld d, b
    db $ed
    ld a, [hl+]
    ld e, l
    ld h, c
    db $dd
    ld c, a
    cp c
    or d
    set 3, [hl]
    call nz, $ba7f
    or e
    or [hl]
    sbc $bd
    reti


    sub $58
    db $ed
    ld a, [hl+]
    ld a, a
    ld h, c
    ld a, a
    cp d
    or e
    or [hl]
    sbc $bd
    reti


    and $57

Call_014_7b4a:
    ldh a, [$8c]
    sub $03
    ld [$d0f4], a
    add a
    add a
    ld d, $00
    ld e, a
    ld hl, $7bff
    add hl, de
    ld a, [hl+]
    ld d, [hl]
    ld e, a
    inc hl
    push hl
    ld hl, $d102
    call Call_000_3871
    pop hl
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $d106
    ld bc, $0006
    call Call_000_01bb
    ld a, [$d0f4]
    cp $02
    jr nz, jr_014_7ba8

    ld a, [$d102]
    ld [$d0e3], a
    call Call_000_1add
    ld hl, $c3f2
    call Call_000_0405
    ld a, [$d103]
    ld [$d0e3], a
    call Call_000_1add
    ld hl, $c41a
    call Call_000_0405
    ld a, [$d104]
    ld [$d0e3], a
    call Call_000_1add
    ld hl, $c442
    call Call_000_0405
    jr jr_014_7bd5

jr_014_7ba8:
    ld a, [$d102]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $c3f2
    call Call_000_0405
    ld a, [$d103]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $c41a
    call Call_000_0405
    ld a, [$d104]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $c442
    call Call_000_0405

jr_014_7bd5:
    ld hl, $c46a
    ld de, $7c0b
    call Call_000_0405
    ld de, $d106
    ld hl, $c40f
    ld c, $82
    call Call_000_2fc4
    ld de, $d108
    ld hl, $c437
    ld c, $82
    call Call_000_2fc4
    ld de, $d10a
    ld hl, $c45f
    ld c, $82
    jp Jump_000_2fc4


    db $10
    ld a, h
    inc d
    ld a, h
    dec de
    ld a, h
    rra
    ld a, h
    ld h, $7c
    ld a, [hl+]
    ld a, h
    db $ed
    inc l
    ld h, l
    ld b, e
    ld d, b
    sub h
    inc b
    and a
    ld d, b
    ld bc, $0720
    ld d, b
    ld [de], a
    nop
    ld d, b
    dec e
    ld e, b
    xor d
    ld d, b
    dec h
    nop
    ld b, [hl]
    nop
    ld h, l
    nop
    ld d, b
    rst $18
    rst $10
    ld a, [$3350]
    nop
    ld d, l
    nop
    ld [hl], a
    nop
    ld d, b

Call_014_7c31:
Jump_014_7c31:
    ld hl, $c3ab
    ld b, $01
    ld c, $07
    call Call_000_03d2
    call Call_000_0ebd
    ld hl, $c3ac
    ld de, $7c5c
    call Call_000_0405
    ld hl, $c3c1
    ld de, $7c60
    call Call_000_0405
    ld hl, $c3c1
    ld de, $d523
    ld c, $82
    call Call_000_2fc4
    ret


    db $ed
    inc l
    ld l, d
    ld b, e
    db $ed
    inc l
    ld [hl], b
    ld b, e
    rst $08
    or d
    ld d, b

Call_014_7c67:
    ld a, [$d0fe]
    add a
    ld d, $00
    ld e, a
    ld hl, $d106
    add hl, de
    xor a
    ldh [$9f], a
    ld a, [hl+]
    ldh [$a0], a
    ld a, [hl]
    ldh [$a1], a
    ret


Call_014_7c7c:
    ld a, [$cc26]
    ld [$d0fe], a
    ld d, $00
    ld e, a
    ld hl, $d102
    add hl, de
    ld a, [hl]
    ld [$d0e3], a
    ld a, [$d0f4]
    cp $02
    jr nz, jr_014_7c99

    call Call_000_1add
    jr jr_014_7c9c

jr_014_7c99:
    call Call_000_1aab

jr_014_7c9c:
    ld hl, $7d1a
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_014_7d01

    call Call_014_7c67
    call Call_000_35fb
    jr c, jr_014_7cfb

    ld a, [$d0f4]
    cp $02
    jr nz, jr_014_7cc8

    ld a, [$d0e3]
    ld b, a
    ld a, $01
    ld c, a
    call Call_000_3e5e
    jr nc, jr_014_7cf5

    jr jr_014_7ce2

jr_014_7cc8:
    ld a, [$d0e3]
    ld [$cf78], a
    push af
    call Call_014_7d57
    ld c, a
    pop af
    ld b, a
    call Call_000_3e78
    push af
    ld a, [$ccd3]
    and a
    call z, Call_000_38ae
    pop af
    ret nc

jr_014_7ce2:
    call Call_014_7c67
    ld hl, $ffa1
    ld de, $d524
    ld c, $02
    ld a, $0c
    call Call_000_3e9d
    jp Jump_014_7c31


jr_014_7cf5:
    ld hl, $7d3b
    jp Jump_000_3c79


jr_014_7cfb:
    ld hl, $7d27
    jp Jump_000_3c79


jr_014_7d01:
    ld hl, $7d4e
    jp Jump_000_3c79


    nop
    ld bc, $0100
    nop
    ld bc, $0000
    ld bc, $ca00
    or d
    ld a, a
    inc [hl]
    or e
    cpl
    ld d, b
    dec c
    ld d, b
    db $ed
    dec l
    inc hl
    ld d, b
    inc sp

jr_014_7d1f:
    ld c, a
    or d
    or d
    sbc $30
    ret z

    and $57
    db $ed
    ld a, [hl+]
    db $d3
    ld h, c
    cp b
    cp e
    sbc $7f
    adc c
    add c
    xor e
    ld a, a
    ret nz

    ret c

    push bc
    or d
    sub $50
    dec c
    ld d, b
    db $ed
    ld a, [hl+]
    xor l
    ld h, c
    cp b
    cp e
    sbc $7f
    db $d3
    or e
    ld a, a
    db $d3
    jp $b2c5


    sub $50
    dec c
    ld d, b
    db $ed
    ld a, [hl+]
    ld a, [$bf61]
    or e
    ld d, b
    dec c
    ld d, b

Call_014_7d57:
    ld a, [$cf78]
    ld b, a
    ld hl, $7d6a

jr_014_7d5e:
    ld a, [hl+]
    cp b
    jr z, jr_014_7d65

    inc hl
    jr jr_014_7d5e

jr_014_7d65:
    ld a, [hl]
    ld [$d0ec], a
    ret


    sub h
    ld b, $04
    inc c
    and a
    ld de, $141d
    ld e, b
    jr jr_014_7d1f

    ld [de], a
    call Call_000_3c6c
    ld a, $01
    ld [$cc3c], a
    ld a, [$cd3d]
    jp Jump_000_3f25


    db $ed
    dec l
    bit 4, [hl]
    ld b, b
    xor e
    sbc e
    and a
    xor h
    sub e
    jr nc, @-$17

    ld c, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, c
    ld e, h
    jp z, Jump_000_2e4f

    sbc $3c
    inc sp
    ld a, a
    ei
    or $bc
    pop hl
    reti


    or d
    rst $20
    ld d, c
    swap e
    sbc $9d
    adc e
    xor e
    jp z, $c24f

    or [hl]
    rst $18
    jp $7fd3


    push bc
    cp b
    push bc
    rst $10
    push bc
    or d
    ld a, a
    adc a
    add c
    ld b, d
    ld d, l
    ld l, $de
    inc a
    inc sp
    ld a, a
    ei
    cp h
    pop hl
    reti


    or d
    ld a, a
    or c
    ret c

    rst $08
    cp l
    ld d, c
    ld d, [hl]
    ld a, a
    adc e
    and [hl]
    sbc e
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    ld d, b
    dec c
    ld d, b
    ld [$4521], sp
    ld a, [hl]
    call Call_000_3c79
    call Call_014_7e0d
    jr nz, jr_014_7e0a

    ld hl, $7e93
    call Call_000_3c79
    call Call_014_7e0d
    jr nz, jr_014_7e0a

    ld hl, $7edb
    call Call_000_3c79
    call Call_014_7e0d
    jr nz, jr_014_7e0a

    ld hl, $7f33
    call Call_000_3c79
    ld hl, $7e2c
    call Call_000_3c79

jr_014_7e0a:
    jp Jump_000_0f6a


Call_014_7e0d:
    ld hl, $7e1b
    call Call_000_3c79

jr_014_7e13:
    call Call_000_3636
    ld a, [$cc26]
    and a
    ret


    db $ed
    ld a, [hl+]
    ld c, d
    ld h, l
    ld b, a
    db $e3
    dec bc
    ld a, a
    or c
    cp c
    pop bc
    ldh [$b5], a
    or e
    or [hl]
    and $57
    db $ed
    ld a, [hl+]
    rra
    ld h, l
    ret


    cp d
    ld [hl], d
    or c
    db $e3
    rst $20
    ld c, a
    sbc b
    db $e3
    sub e
    ld a, a
    ret nc

    pop bc
    ldh [$7f], a
    jr nc, jr_014_7e13

    rst $20

jr_014_7e42:
    ld d, b
    dec c
    ld d, b
    db $ed
    ld a, [hl+]
    dec bc
    ld h, d
    db $dd
    ld a, a
    ret


    cpl
    or d
    ret nz

    rst $20
    ld d, c
    rst $30
    ld b, a
    db $e3
    dec bc
    jp nc, Jump_014_567f

    ld d, c
    ld d, h
    jp z, $a14f

    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    inc sp
    ld a, a
    jp nz, $cfb6

    or h
    jp $fc55


    jp nz, Jump_000_33cf

    ld a, a
    db $d3
    pop bc
    ld a, a
    or c
    reti


    cp c
    reti


    ld d, c
    ld d, h
    db $dd
    ld a, a
    cp a
    jr nc, jr_014_7e42

    jp $c07f


    ret nz

    or [hl]
    call c, $d9be
    ld c, a
    set 0, h
    db $dd
    ld a, a
    ld d, h
    ld a, a
    ld e, l
    call nz, $b3b2
    ld e, b

jr_014_7e93:
    db $ed
    ld a, [hl+]
    or h
    ld h, d
    dec bc
    jp nc, Jump_014_567f

    ld d, c
    ld d, h
    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    reti


    ld a, a
    call nz, $cab7
    ld c, a
    rst $08
    dec l
    ld a, a
    sub $dc
    rst $10
    cp [hl]
    jp $d7b6


    rst $20
    ld d, l
    inc [hl]
    cp b
    call nc, $d47f
    cp c
    inc [hl]
    inc sp
    ld d, c
    sub $dc
    rst $10
    cp [hl]
    jp $7fd3


    or d
    or d
    sub $e7
    ld c, a
    add hl, hl
    sbc $b7
    jr nc, jr_014_7e93

    ld a, a
    or e
    rst $08
    cp b
    ld a, a
    call nz, $c5da
    or d
    or [hl]
    db $d3
    ld e, b
    db $ed
    ld a, [hl+]
    ld l, [hl]
    ld h, e
    dec bc
    jp nc, Jump_014_567f

    ld d, c
    ld d, h
    inc [hl]
    or e
    cp h
    db $dd
    ld a, a
    ret nz

    ret nz

    or [hl]
    call c, Call_014_4fbe
    or [hl]
    jp nz, $c4ba

    jp z, $5d7f

    add $7f
    call nz, $c3df
    ld d, l
    cp e
    or d
    cp d
    or e
    ret


    ld a, a
    sub $db
    cp d
    dec sp
    ld a, a
    inc sp
    or c
    reti


    rst $20
    ld d, c
    or [hl]
    cp b
    pop bc
    ret


    ld a, a
    ld d, h
    ld a, a
    dec bc
    sbc a
    inc sp
    jp z, $b24f

    jp nz, $7fd3

    jp z, $bc29

    or d
    ld d, l
    ret nz

    ret nz

    or [hl]
    or d

Call_014_7f26:
Jump_014_7f26:
    ld h, $7f
    cp b
    ret c

    set 3, e
    add hl, hl
    rst $10
    jp c, $d9c3

    rst $20
    ld e, b

Jump_014_7f33:
    db $ed
    ld a, [hl+]
    inc e
    ld h, h
    dec bc
    jp nc, Jump_014_567f

    ld d, c
    ld d, h
    ld e, l
    ret


    ld a, a
    db $d3
    cp b
    set 4, d
    or e
    jp z, $b64f

    cp b
    pop bc
    ret


    ld a, a
    dec bc
    sbc a
    add $7f
    or d
    reti


    ld d, c
    jp nz, $b2d6

Jump_014_7f56:
    ld a, a
    ld e, l
    ld c, a
    cp $c6
    sbc $bc
    pop hl
    or e
    db $dd
    ld a, a
    ret nz

    or l
    cp l
    cp d
    call nz, Call_014_51e7
    cp e
    rst $10
    add $7f
    ld d, h
    ret c

    db $e3
    rlca
    ld a, a
    adc $de
    inc a
    add $ca
    ld c, a
    ld d, [hl]
    ld a, a

Call_014_7f79:
    db $d3
    or e
    jp c, $c6c2

    ld a, a
    jp nz, $b2d6

    rst $20
    ld d, c
    cp h
    jp $c9de


    or e
    ld h, $7f
    cp b
    sbc $d8
    sbc $7f
    cp h
    jp $e7d9


    ld e, b
    call Call_000_3c6c
    ld a, $37
    jp Jump_000_3f25


    db $ed
    inc l
    ld b, d
    ld l, [hl]
    ld a, a
    cp a
    or [hl]
    ld d, a
    call Call_000_3c6c
    ld a, $38
    jp Jump_000_3f25


    nop
    or d
    sbc $26
    ld a, a
    or l
    or e
    adc $b3
    ld d, a
    call Call_000_3c6c
    ld a, $36
    jp Jump_000_3f25


    db $ed

Jump_014_7fc0:
    inc l
    inc l
    ld l, [hl]

Jump_014_7fc3:
    or e
    ld a, a

Jump_014_7fc5:
    inc [hl]

Call_014_7fc6:
Jump_014_7fc6:
    or e
    inc l
    ld [c], a

Jump_014_7fc9:
    or e

Call_014_7fca:
Jump_014_7fca:
    rst $20
    ld d, a
    ld a, [$c109]

Call_014_7fcf:
    cp $04
    ret nz

    call Call_000_3c6c
    ld a, $27
    jp Jump_000_3f25


    nop
    adc l
    add [hl]

Call_014_7fdd:
Jump_014_7fdd:
    add e

Jump_014_7fde:
    add c
    cp d
    or e
    add hl, hl
    sbc $4f
    ld d, h
    ret c

    db $e3

Call_014_7fe7:
    rlca
    ld a, a
    adc $de
    inc a
    ld d, a
    nop
    nop
    inc b
    ld [bc], a
    inc h
    nop
    nop
    sub b
    nop
    stop
    ret nz

    ld hl, $8200
    and b
    ld bc, $0002
