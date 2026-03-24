; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $018", ROMX[$4000], BANK[$18]

    scf
    dec d
    ld [bc], a
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld [bc], a
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    add hl, sp
    ld c, c
    scf
    dec sp
    ld [bc], a
    dec de
    dec de
    dec de
    add hl, hl
    ld [bc], a
    dec de
    add hl, hl
    dec [hl]
    dec [hl]
    dec [hl]
    dec [hl]
    dec [hl]
    add hl, hl
    dec sp
    scf
    dec sp
    ld [bc], a
    add hl, hl
    dec sp
    scf
    dec de
    ld [bc], a
    dec de
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    scf
    dec sp
    ld b, $07
    ld [bc], a
    ld bc, $0607
    ld bc, $0102
    rlca
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    scf
    dec sp
    ld b, $07
    ld [bc], a
    ld bc, $0607
    ld bc, $0102
    ld bc, $0101
    dec de
    add hl, hl
    dec de
    dec de
    dec sp
    ld b, $07
    ld [bc], a
    ld bc, $0607
    ld bc, $0102
    rlca
    ld [bc], a
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld bc, $0607
    rlca
    ld [bc], a
    ld bc, $0607
    ld bc, $0102
    rlca
    ld [bc], a
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld bc, $0607
    rlca
    ld [bc], a
    ld bc, $0607
    ld bc, $0102
    rlca
    ld [bc], a
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld bc, $0607
    rlca
    ld [bc], a
    ld bc, $0607
    ld bc, $011b
    rlca
    ld [bc], a
    ld [bc], a
    scf
    dec d
    ld [bc], a
    ld bc, $0607
    rlca
    ld [bc], a
    ld bc, $3707
    add hl, hl
    dec de
    dec de
    dec sp
    ld [bc], a
    ld [bc], a
    scf
    add hl, hl
    dec de
    dec de
    dec sp
    ld b, $07
    ld [bc], a
    ld bc, $0207
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld b, $01
    ld [bc], a
    scf
    dec sp
    ld b, $01
    dec de
    ld bc, $0207
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld b, $01
    ld [bc], a
    scf
    dec sp
    scf
    dec de
    ld hl, $1b29
    dec de
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld b, $01
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld b, $01
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld b, $01
    ld [bc], a
    scf
    dec sp
    ld b, $01
    ld bc, $0701
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld b, $01
    ld [bc], a
    scf
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    add hl, hl
    ld bc, $0101
    ld bc, $0721
    ld [bc], a
    ld [bc], a
    ld b, $1b
    dec de
    add hl, hl
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    dec de
    rlca
    ld [bc], a
    ld [bc], a
    ld b, $1b
    rlca
    ld [bc], a
    ld [bc], a
    ld b, $1b
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    dec de
    rlca
    ld [bc], a
    ld [bc], a
    ld b, $1b
    rlca
    ld [bc], a
    ld [bc], a
    ld b, $1b
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    dec de
    rlca
    ld [bc], a
    ld [bc], a
    ld b, $1b
    rlca
    ld [bc], a
    ld [bc], a

Jump_018_414f:
    ld b, $1b
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld b, $01
    ld bc, $011b
    ld bc, $0101
    inc d
    ld bc, $0101
    ld d, $1b
    ld bc, $0701
    ld b, $01
    ld bc, $1b1b
    dec de
    dec de
    dec de
    jr jr_018_418a

    dec de
    dec de
    dec de
    dec de
    ld bc, $0701
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    scf
    dec de
    dec d
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a

jr_018_418a:
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    scf
    ld e, b
    dec sp
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld bc, $0101
    ld bc, $090d
    inc bc
    inc c
    dec c
    inc b
    dec b
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    inc b
    ld [bc], a
    inc c
    dec c
    rrca
    ld [bc], a
    inc c
    ld bc, $0e0e
    ld bc, $0101
    ld bc, $0d01
    add hl, bc
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
    inc c
    dec c
    inc b
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    dec b
    inc c
    dec c
    rrca
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    inc c
    ld bc, $0e0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $01
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    inc l
    dec e
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de

Call_018_427f:
    add hl, de
    add hl, de
    ld a, [de]
    ld a, $18
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1d1c
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    jr jr_018_4304

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    inc e
    dec e
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de

jr_018_4304:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    ld d, $01
    ld bc, $1801
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    jr jr_018_4342

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    ld d, $01
    jr jr_018_4356

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de

jr_018_4342:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1d1c
    dec e
    dec e
    dec e
    dec e
    dec hl

jr_018_4356:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $1d1c
    dec e
    dec e
    dec e
    dec e
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    dec d
    dec d
    dec d
    dec d
    ld d, $01
    ld bc, $0101
    ld bc, $3e01
    jr jr_018_43b2

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    dec d
    dec d
    dec d
    ld d, $01
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de

jr_018_43b2:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    dec d
    add hl, de
    scf
    jr c, jr_018_43cf

    inc c
    inc c
    scf
    jr c, jr_018_43d4

    inc c
    inc c
    scf
    jr c, @+$3d

    add hl, sp
    inc c

jr_018_43cf:
    inc c
    inc c
    dec sp
    add hl, sp
    inc c

jr_018_43d4:
    inc c
    inc c
    dec sp
    add hl, sp
    dec bc
    dec de
    inc c
    inc c
    inc c
    dec bc
    dec de
    inc c
    inc c
    inc c
    dec bc
    dec de
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    scf
    jr c, jr_018_440b

    inc c
    inc c
    scf
    jr c, jr_018_4410

    inc c
    inc c

jr_018_4406:
    scf
    jr c, jr_018_4444

    add hl, sp
    inc c

jr_018_440b:
    inc c
    inc c
    dec sp
    add hl, sp
    inc c

jr_018_4410:
    inc c
    inc c
    dec sp
    add hl, sp
    dec bc
    dec de
    inc c
    inc c
    inc c
    dec bc
    dec de
    inc c
    inc c
    inc c
    dec bc
    dec de
    rrca
    add hl, bc
    ld a, [bc]
    dec hl
    ld b, l
    cpl
    ld b, h
    inc l
    ld b, h
    nop
    pop af
    ld b, h
    jp Jump_000_3c6c


    add hl, sp
    ld b, h
    ld e, h
    ld b, h
    ld a, a
    ld b, h
    xor d
    ld b, h
    ret


    ld b, h
    db $ed
    ld h, $c0
    ld h, b
    xor c
    db $e3
    jp z, $bc4f

    sbc $30

jr_018_4444:
    ld a, a
    ld d, h
    db $dd
    ld a, a
    push bc
    jr z, jr_018_4406

    jp nc, $c0d9

    jp nc, $c055

    jp $dad7


    ret nz

    ld a, a
    call nz, Call_018_7fb3
    inc sp
    cp l
    ld d, a
    db $ed
    ld h, $02
    ld h, c
    db $d3
    ld c, a
    or l
    jp z, Jump_018_7fb6

    rst $08
    or d
    ret c

    add $7f
    or a
    ret nz

    ret


    and $55
    ld d, h
    ld a, a
    or l
    db $d3
    or d
    ret


    ld a, a
    or l
    call nz, $c9ba
    cp d
    ld a, a
    ret z

    ld d, a
    db $ed
    ld h, $40
    ld h, c
    ld a, a
    ld b, c
    xor h
    ld b, c
    ret


    ld a, a
    adc c
    sub e
    ld h, $4f
    call c, $dabd
    rst $10
    jp c, Jump_018_56de

    rst $20
    ld d, c
    ld d, [hl]
    add c
    add l
    xor e
    rst $20
    ld c, a
    push bc
    ret nc

    jr nc, jr_018_44c6

    ld a, a
    inc sp
    jp $b77f


    or l
    rst $18
    ret nz

    ld d, [hl]
    ld d, a
    db $ed
    ld h, $7e
    ld h, c
    call c, $bcc0
    ret


    ld a, a
    dec b
    db $e3
    ld [de], a
    or b
    ld d, [hl]
    ld c, a
    inc [hl]
    or e
    cp h
    jp $bc7f


    sbc $33
    ld a, a
    cp h
    rst $08
    rst $18
    ret nz

jr_018_44c6:
    ret


    ld d, [hl]
    ld d, a
    db $ed
    ld h, $9c
    ld h, c
    jp z, $b77f

    call nz, $bcb3
    rst $20
    ld c, a
    inc [hl]
    or e
    db $d3
    ld a, a
    or e
    or h
    ret


    ld a, a
    or [hl]
    or d

Call_018_44df:
    add $55
    rst $08
    sub $b4
    reti


    ld a, a
    ret nz

    rst $08
    cp h
    or d
    db $dd
    ld a, a
    or [hl]
    sbc $2c
    reti


    ld d, a
    ld bc, $1103
    ld a, [bc]
    ld bc, $11ff
    dec bc
    ld bc, $09ff
    ld [de], a
    ld bc, $008f
    dec b
    ld a, [hl+]
    ld de, $ff13
    pop de
    ld bc, $0c1c
    ld a, [bc]
    rst $38
    rst $38
    ld [bc], a
    inc [hl]
    db $10
    inc c
    rst $38
    rst $38
    inc bc
    dec c
    dec bc
    ld de, $ffff
    inc b
    add hl, de
    dec bc
    dec d
    rst $38
    jp nc, Jump_018_7e05

    rst $00
    ld de, $7e0a
    rst $00
    ld de, $420b
    rst $00
    add hl, bc
    ld [de], a
    ld bc, $0101
    inc bc
    ld a, [bc]
    ld b, $07
    inc bc
    ld bc, $0101
    ld bc, $0610
    ld c, $0e
    ld c, $06
    ld [$0101], sp
    inc c
    add hl, sp
    ld c, $0e
    ld c, $0e
    ld c, $20
    dec c
    ld bc, $0e0a
    ld c, $0e
    ld c, $0e
    ld c, $0e
    rlca
    ld bc, $0e39
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld [de], a
    ld bc, $0e1c
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld e, $01
    inc c
    ld c, $0e
    ld c, $0e
    dec h
    ccf
    ccf
    dec c
    ld bc, $1401
    ld c, $0e
    ld c, $25
    ld c, $0b
    ld bc, $0101
    ld bc, $1c05
    ld c, $1e
    dec b
    ld bc, $0f01
    add hl, bc
    ld a, [bc]
    adc h
    ld c, b
    ld a, d
    ld b, [hl]
    sub c
    ld b, l
    nop
    ld l, h
    ld c, b
    call Call_000_3c6c
    ld hl, $45a8
    ld a, [$d5aa]
    jp Jump_000_3dc7


Jump_018_459d:
    xor a
    ld [$cd66], a
    ld [$d5aa], a
    ld [$d97c], a
    ret


    xor [hl]
    ld b, l
    ld [bc], a
    ld b, [hl]
    ld e, d
    ld b, [hl]
    ld a, [$d6e3]
    bit 7, a
    ret nz

    ld hl, $45fd
    call Call_000_3509
    ret nc

    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld c, $02
    ld a, $de
    call Call_000_0e35
    ld hl, $d6e3
    res 6, [hl]
    ld a, [$cd3d]
    cp $01
    ld a, $08
    ld b, $00
    jr nz, jr_018_45e3

    ld hl, $d6e3
    set 6, [hl]
    ld a, $02
    ld b, $0c

jr_018_45e3:
    ld [$d4a7], a
    ld a, $01
    ldh [$8c], a
    ld a, b
    ldh [$8d], a
    call Call_000_34f0
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    xor a
    ldh [$b4], a
    ldh [$b3], a
    ret


    dec b
    rrca
    ld b, $0e
    rrca
    ld a, [$d034]
    cp $ff
    jp z, Jump_018_459d

    ld a, $f0
    ld [$cd66], a
    ld hl, $d6e3
    set 7, [hl]
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    ld de, $4651
    ld a, [$d6e3]
    bit 6, a
    jr nz, jr_018_4628

    ld de, $4648

jr_018_4628:
    ld a, $01
    ldh [$8c], a
    call Call_000_3684
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a44
    call Call_000_3620
    ld a, $02
    ld [$d5aa], a
    ld [$d97c], a
    ret


    ret nz

    nop
    nop
    ret nz

    nop
    nop
    ret nz

    ret nz

    rst $38
    nop
    nop
    ret nz

    ret nz

    ret nz

    ret nz

    nop
    nop
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $38
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    xor a
    ld [$cd66], a
    call Call_000_0d9b
    ld a, $00
    ld [$d5aa], a
    ld [$d97c], a
    ret


    ld a, [hl]
    ld b, [hl]
    inc d
    ld c, b
    ld [$e3fa], sp
    sub $cb
    ld a, a
    jr z, jr_018_468e

    ld hl, $4785
    call Call_000_3c79
    jr jr_018_46c9

jr_018_468e:
    ld hl, $46cc
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $472c
    ld de, $4753
    call Call_000_339c
    ld a, $f2
    ld [$d036], a
    ld a, [$d694]
    cp $b1
    jr nz, jr_018_46b4

    ld a, $04
    jr jr_018_46be

jr_018_46b4:
    cp $99
    jr nz, jr_018_46bc

    ld a, $05
    jr jr_018_46be

jr_018_46bc:
    ld a, $06

jr_018_46be:
    ld [$d03a], a
    ld a, $01
    ld [$d5aa], a
    ld [$d97c], a

jr_018_46c9:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld [$b354], sp
    rst $20
    ld a, a
    ld d, d
    rst $20
    ld c, a
    cp d
    sbc $c5
    ld a, a
    call nz, $dbba
    call $c555
    add $bc
    add $7f
    or a
    ret nz

    sbc $30
    sub $e6
    ld d, l
    or l
    rst $08
    or h
    ret


    ld a, a
    ld d, h
    ld a, a
    cp h
    sbc $30
    ret


    or [hl]
    and $55
    ld d, [hl]
    or c
    adc $b6
    rst $20
    ld a, a
    or d
    or a
    jp Jump_018_7fd9


    inc l
    ldh [$de], a
    ld d, c
    jr nc, @-$1f

    ret nz

    rst $10
    ld a, a
    cp [hl]
    jp nc, Jump_018_4fc3

    cp [hl]
    sbc $c4
    or e
    ld a, a
    call z, $b3c9
    add $7f
    cp h
    jp $d9d4


    or [hl]
    rst $20
    ld d, l
    or [hl]
    or [hl]
    rst $18
    jp $ba7f


    or d
    sub $e7
    ld d, a
    db $ed
    inc l
    ld a, [bc]
    ld c, a
    pop bc
    cp b
    cp h
    ld [c], a
    or e
    rst $20
    ld c, a
    call nc, $d4d8
    ld h, $df
    ret nz

    push bc
    db $e3
    rst $20
    ld d, c
    cp [hl]

jr_018_4742:
    rst $18
    or [hl]
    cp b
    ld a, a
    jp Jump_000_29b6


    sbc $7f
    cp h
    jp $dfd4


    ret nz

    ret


    add $58
    db $ed
    inc l
    push bc
    ld c, [hl]
    db $e3
    or c
    ld d, [hl]
    rst $20
    ld c, a
    adc $de
    call nz, $7fc6
    cp b
    ret nz

    ld a, [hl-]
    rst $18
    pop bc
    rst $08
    rst $18
    ret nz

    cpl
    rst $20
    ld d, l
    sub $dc
    or d
    push bc

jr_018_4770:
    db $e3
    rst $20
    ld d, l
    db $d3
    rst $18
    call nz, $c17f
    ldh [$de], a
    call nz, $bf7f
    jr nc, jr_018_4742

    jp $d47f


    jp c, Jump_018_58d6

    db $ed
    dec hl
    rra
    ld d, e
    call nz, $dbba
    inc sp
    ld d, [hl]
    rst $20
    ld d, l
    ld d, h
    dec l
    or [hl]
    sbc $ca
    ld a, a
    inc [hl]
    or e
    jr nc, jr_018_4770

    and $55
    or l
    jp c, $dec5

    or [hl]
    ld a, a
    add l
    and l
    add l
    and l
    ld d, l
    ret nc

    jp nz, $c0b9

    ld a, a
    db $d3
    sbc $c8
    rst $20
    ld d, c
    or l
    rst $18
    or a
    or d
    ld a, a
    adc $b3
    ret


    ld a, a
    dec b
    and l
    dec b
    and l
    ld h, $4f
    ret nc

    jp nz, $d7b6

    ret z

    or h
    sbc $30
    rst $20
    ld d, l
    inc [hl]
    cp d
    or [hl]
    push bc
    db $e3
    and $51
    or c
    or c
    db $e3
    ld a, a
    or a
    rst $18
    call nz, $d34f
    or e
    ld a, a
    cp d
    ret


    call $c6de
    jp z, $b27f

    push bc
    or d
    push bc
    rst $20
    ld d, l
    inc l
    ldh [$7f], a
    or l
    jp c, $d37f

    or e
    ld a, a
    or d
    cp b
    call c, Call_018_55e7
    or l
    rst $08
    or h
    call nz, $c17f
    ld h, $df
    jp $b555


    jp c, $b27f

    cp a
    ld h, $bc
    or d
    or [hl]
    rst $10
    sub $e7
    ld d, c
    inc l
    ldh [$e3], a
    push bc
    rst $20
    ld d, a
    db $ed
    ld h, $f1
    ld h, c
    rst $20
    ld a, a
    rst $08
    sub $b2
    ld a, a
    cp e
    rst $08
    sub $b3
    ld c, a
    push de
    or e
    jp c, $c9b2

    ld a, a
    cp h
    ld [c], a
    or e
    ret nz

    or d
    jp z, Jump_018_5556

    call c, $dcda
    jp c, $d333

    ld a, a
    jp nz, $d2b6

    push bc
    or d
    rst $20
    ld d, c
    db $d3
    cp h
    ld a, a
    call nz, Call_000_3db8
    jp nz, Jump_018_7fc5

    inc [hl]
    or e
    jr z, jr_018_4872

    ld d, [hl]
    ld c, a
    adc e
    and [hl]
    sbc e
    ld a, a
    adc h
    adc c
    db $e3
    ld b, d
    cp e
    or h
    ld a, a
    or c
    jp c, Jump_018_553a

    ret nc

    call nc, $da3c
    reti


    or [hl]
    db $d3
    ld a, a
    cp h
    jp c, $b2c5

    ld h, $56
    ld d, a
    ld bc, $0902
    inc bc
    nop
    sub b

jr_018_4872:
    add hl, bc
    ld [de], a
    ld [bc], a
    adc [hl]
    nop
    ld [bc], a
    ld [bc], a
    add hl, bc
    ld [de], a
    rst $38
    rst $38
    ld bc, $0b19
    rlca
    rst $38
    db $d3
    ld [bc], a
    ld a, [hl-]
    rst $00
    add hl, bc
    inc bc
    ld b, d
    rst $00
    add hl, bc
    ld [de], a
    ld bc, $0101
    inc bc
    ld h, b
    ld e, e
    ld h, c
    inc bc
    ld bc, $0101
    ld bc, $5b10
    ld d, c
    ld c, $0e
    ld b, $08
    ld bc, $0c01
    ld e, [hl]
    ld c, h
    ld [hl], $0e
    ld [hl], $36
    ld e, a
    dec c
    ld bc, $0e0a
    ld [hl], $52
    ld c, h
    ld c, h
    ld [hl], $0e
    rlca
    ld bc, $0e15
    ld d, d
    ld d, d
    ld c, $52
    ld d, d
    ld c, $16
    ld bc, $0e1c
    ld [hl], $52
    ld c, $0e
    ld [hl], $0e
    ld e, $01
    inc c
    ld d, a
    ld d, d
    ld d, d
    ld d, d
    ld c, $4f
    ld e, b
    dec c
    ld bc, $1401
    dec e
    ld [hl], $36
    ld [hl], $1d
    dec bc
    ld bc, $0101
    ld bc, $5305
    ld d, [hl]
    ld d, h
    dec b
    ld bc, $0f01
    add hl, bc
    ld a, [bc]
    ld h, l
    ld c, d
    dec bc
    ld c, c
    ld a, [c]
    ld c, b
    nop
    ld [hl-], a
    ld c, d
    call Call_000_3c6c
    ld hl, $4913
    ld de, $4905
    ld a, [$d5ab]
    call Call_000_31a8
    ld [$d5ab], a
    ret


    ld h, c

jr_018_4906:
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    jr c, jr_018_4956

    adc h
    ld c, c
    rst $10
    ld c, c
    push bc

jr_018_4912:
    rrca
    ld bc, $e420
    sub $42
    ld c, c
    ld h, b
    ld c, c
    ld d, e
    ld c, c
    ld d, e
    ld c, c
    ld [bc], a
    jr nc, jr_018_4906

    sub $96
    ld c, c
    cp c
    ld c, c
    and l
    ld c, c
    and l
    ld c, c
    inc bc
    jr nz, jr_018_4912

    sub $e1
    ld c, c
    db $10
    ld c, d
    db $fd
    ld c, c
    db $fd
    ld c, c
    rst $38
    ld [$1321], sp
    ld c, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $ed
    ld h, d
    ld a, a
    ld b, $56
    ld c, a
    ld d, [hl]
    ld a, a
    rlca
    rlca
    rlca
    xor h
    ld d, [hl]
    rst $20
    ld d, a
    db $ed
    ld h, $97

jr_018_4956:
    ld h, e
    rst $20
    ld c, a
    ret nz

    cp l
    or [hl]
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    ld h, $0f
    ld h, e
    ld a, a
    adc h
    adc c
    db $e3
    ld b, d
    push bc
    reti


    ld a, a
    sbc l
    adc e
    xor e
    push bc
    rst $10
    ld c, a
    push de
    or e
    jp c, Jump_018_7fb2

    ld d, h
    ret


    ld d, l
    cp h
    ld [c], a
    or e
    ret nz

    or d
    db $dd
    ld a, a
    ret nc

    call nc, $d93c
    ld a, a
    call nz, $b3b2
    ld h, $56
    ld d, a
    ld [$1f21], sp
    ld c, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $ad
    ld h, e
    ld a, a
    ld d, [hl]
    ld c, a
    ld d, [hl]
    ld a, a
    adc b
    adc b
    db $e3
    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $16
    ld h, h
    and $4f
    call c, $cabc
    ld a, a
    push bc
    add $7f
    cp h
    jp $c9c0


    inc l
    ldh [$58], a
    db $ed
    ld h, $bf
    ld h, e
    rst $20
    ld a, a
    or c
    cp b
    ret c

    ld [c], a
    or e
    ld h, $4f
    ret


    ret c

    or e
    jp nz, $c3df

    ld a, a
    or c
    ld a, [hl-]
    jp c, $d9c3

    ret


    inc l
    ldh [$e7], a
    ld d, a
    ld [$2b21], sp
    ld c, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $32
    ld h, h
    ld a, a
    or c
    cp b
    ret c

    ld [c], a
    or e
    jp nc, Jump_018_4fe7

    ld d, [hl]
    or e
    call c, $e7df
    ld a, a
    call Call_018_5608
    adc b
    adc b
    db $e3
    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $b1
    ld h, h
    ld d, [hl]
    ld c, a
    ld d, [hl]
    or c
    cp b
    ret c

    ld [c], a
    or e
    jp z, $c67f

    add hl, hl
    ret nz

    or [hl]
    ld e, b
    db $ed
    ld h, $57
    ld h, h
    or e
    or h
    add $7f

jr_018_4a18:
    or d
    reti


    ld a, a
    push bc
    or [hl]
    rst $08
    db $d3
    ld c, a
    or c
    cp b
    ret c

    ld [c], a
    or e
    add $7f
    or l
    cp a
    call c, $c0da
    ld a, a
    sub $b3
    jr nc, jr_018_4a18

    ld d, a
    ld bc, $0902
    inc bc
    nop
    adc a
    add hl, bc
    ld [de], a
    ld bc, $0091
    inc b
    add hl, de
    rlca
    db $10
    rst $38
    jp nc, $f541

    dec b
    add hl, de
    inc c
    dec c
    rst $38
    ret nc

    ld b, d
    push af
    ld b, $19
    ld de, $ff0e
    ret nc

    ld b, e
    push af
    ld [$053d], sp
    db $10
    rst $38
    rst $38
    add h
    dec e
    ld a, [hl-]
    rst $00
    add hl, bc
    inc bc
    ld b, d
    rst $00
    add hl, bc
    ld [de], a
    ld bc, $0101
    inc bc
    ld a, [bc]
    ld b, $07
    inc bc
    ld bc, $0101
    ld bc, $5b10
    ld d, c
    ld c, $0e
    ld b, $08
    ld bc, $0c01
    add hl, sp
    inc de
    ld c, a
    ld c, a
    ld c, a
    ld c, a
    ld e, b
    dec c
    ld bc, $0e0a
    ld d, b
    ld c, $0e
    ld c, $13
    rla
    rlca
    ld bc, $0e11
    ld d, b
    ld c, $52
    ld c, $51
    ld c, $12
    ld bc, $0e1c
    ld d, b
    ld c, $0e
    ld c, $51
    ld c, $1e
    ld bc, $390c
    ld c, [hl]
    ld c, $4c
    ld c, h
    ld c, l
    ld c, h
    dec c
    ld bc, $1401
    ld d, [hl]
    ld c, $0e
    ld c, $56
    dec bc
    ld bc, $0101
    ld bc, $5305
    ld d, [hl]
    ld d, h
    dec b
    ld bc, $0f01
    add hl, bc
    ld a, [bc]
    jr jr_018_4b10

    db $e4
    ld c, d
    bit 1, d
    nop
    rst $10
    ld c, e
    call Call_000_3c6c
    ld hl, $4af0
    ld de, $4ade
    ld a, [$d5ac]
    call Call_000_31a8
    ld [$d5ac], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a

jr_018_4ae4:
    dec d
    ld c, e
    ld d, [hl]
    ld c, e
    sub a
    ld c, e
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca

jr_018_4af0:
    ld bc, $e520
    sub $1f
    ld c, e
    ld b, h
    ld c, e
    ld [hl-], a
    ld c, e
    ld [hl-], a
    ld c, e
    ld [bc], a
    jr nz, jr_018_4ae4

    sub $60
    ld c, e
    ld a, e
    ld c, e
    ld [hl], l
    ld c, e
    ld [hl], l
    ld c, e
    inc bc
    jr nz, jr_018_4af0

    sub $a1
    ld c, e
    cp [hl]
    ld c, e

jr_018_4b10:
    or l
    ld c, e
    or l
    ld c, e
    rst $38
    ld [$f021], sp
    ld c, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $ce
    ld h, h
    ld d, [hl]
    ld a, a
    push de
    or e
    jp c, $d2b2

    ld d, [hl]
    ld c, a
    ld d, [hl]
    adc b
    db $e3
    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $21
    ld h, l
    ld c, a
    push de
    ld a, a
    push de
    or e
    jp c, $cab2

    ld a, a
    inc [hl]
    cp d
    inc l
    ldh [$58], a
    db $ed
    ld h, $e5
    ld h, h
    ld c, a
    push de
    jp nc, $7fdd

    ret nc

    jp $7fc0


    sub $b3
    inc l
    ldh [$57], a
    ld [$fc21], sp
    ld c, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $40
    ld h, l
    ld a, a
    adc e
    xor a
    ld d, [hl]
    ld a, a
    sub l
    ld d, [hl]
    ld c, a
    ld d, [hl]
    ld a, a
    sbc b
    xor b
    ld d, [hl]
    xor c
    and a
    rst $20
    ld d, a
    db $ed
    ld h, $9f
    ld h, l
    rst $20
    ld e, b
    db $ed
    ld h, $50
    ld h, l
    cp h
    jp Jump_018_7fd3


    push de
    or e
    jp c, $c9b2

    ld c, a
    cp h
    ld [c], a
    or e
    ret nz

    or d
    ld h, $7f
    call c, $d7b6
    push bc
    or d
    ld d, [hl]
    ld d, a
    ld [$0821], sp
    ld c, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $a8
    ld h, l
    xor h
    ld d, [hl]
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    add l
    sub d
    ld d, [hl]
    ld a, a
    and [hl]
    add l
    db $e3
    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $03
    ld h, [hl]
    call c, $cabc
    and $58
    db $ed
    ld h, $c9
    ld h, l
    ld a, a
    ld d, h
    ret


    ld c, a
    cp e
    rst $08
    sub $b4
    reti


    ld a, a
    jp c, $d6b2

    ld a, a
    call nc, $d7bd
    or [hl]
    add $56
    ld d, a
    ld bc, $0902
    inc bc
    nop
    sub d
    add hl, bc
    ld [de], a
    ld bc, $0090
    ld b, $19
    ld c, $09
    rst $38
    db $d3
    ld b, c
    push af
    add hl, bc
    add hl, de
    dec bc
    inc de
    rst $38
    ret nc

    ld b, d
    push af
    ld a, [bc]
    add hl, de
    db $10
    ld [de], a
    rst $38
    jp nc, $f543

    inc c
    dec a
    ld c, $10
    rst $38
    rst $38
    add h
    ld d, d
    dec a
    ld c, $0d
    rst $38
    rst $38
    add l
    ld c, $3d
    inc d
    db $10
    rst $38
    rst $38
    add [hl]
    inc hl
    ld a, [hl-]
    rst $00
    add hl, bc
    inc bc
    ld b, d
    rst $00
    add hl, bc
    ld [de], a
    ld bc, $0101
    inc bc
    ld a, [bc]
    ld b, $07
    inc bc
    ld bc, $0101
    ld bc, $5b09
    ld d, c
    ld c, $0e
    ld b, $08
    ld bc, $0c01
    ld e, [hl]
    inc de
    rla
    ld d, c
    ld c, a
    ld c, h
    ld e, a
    dec c
    ld bc, $0e0a
    inc de
    rla
    ld h, [hl]
    ld c, a
    ld c, [hl]
    ld c, l
    rlca
    ld bc, $4f15
    ld c, $4f
    ld c, l
    ld c, a
    ld c, $0e
    ld d, $01
    inc e
    ld c, $0e
    ld h, a
    ld c, [hl]
    ld c, a
    inc de
    ld h, a
    ld e, $01
    inc c
    add hl, sp
    ld h, [hl]
    inc de
    ld c, $13
    rla
    jr nz, @+$0f

    ld bc, $1401
    dec e
    rla
    ld c, [hl]
    ld c, a
    dec e
    dec bc
    ld bc, $0101
    ld bc, $5305
    ld d, l
    ld e, $05
    ld bc, $0f01
    add hl, bc
    ld a, [bc]
    cp h
    ld c, [hl]
    rst $20
    ld c, h
    ld a, [hl]
    ld c, h
    nop
    ld a, e
    ld c, [hl]
    call Call_000_3c6c
    ld hl, $4cf5
    ld de, $4c91
    ld a, [$d5ad]
    call Call_000_31a8
    ld [$d5ad], a
    ret


    sub a
    ld c, h
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld hl, $4cde
    call Call_000_3509
    jr c, jr_018_4cac

    ld hl, $d6ad
    res 4, [hl]
    ld hl, $d6e6
    res 7, [hl]
    jp Jump_000_3261


jr_018_4cac:
    ld hl, $d6e6
    bit 7, [hl]
    set 7, [hl]
    ret nz

    xor a
    ldh [$b4], a
    ld a, $f0
    ld [$cd66], a
    ld hl, $d6ad
    set 4, [hl]
    ld a, $07
    call Call_000_3e9d
    call Call_000_0b5a
    call Call_000_3e07
    call Call_000_3e07
    call Call_000_0b78
    ld a, $07
    ldh [$8c], a
    call Call_000_13f1
    xor a
    ld [$cd66], a
    ret


jr_018_4cde:
    ld [$080a], sp
    dec bc
    add hl, bc
    ld a, [bc]
    add hl, bc
    dec bc
    rst $38
    ld h, $4d
    ld d, e

jr_018_4cea:
    ld c, l
    sub b
    ld c, l
    ret nc

    ld c, l
    dec b
    ld c, [hl]
    push bc
    rrca
    ld b, l
    ld c, [hl]
    ld [bc], a

jr_018_4cf6:
    jr nz, jr_018_4cde

    sub $5d
    ld c, l
    ld a, h
    ld c, l
    ld [hl], e
    ld c, l
    ld [hl], e
    ld c, l
    inc bc

jr_018_4d02:
    jr nc, jr_018_4cea

    sub $9a
    ld c, l
    cp e
    ld c, l
    xor a
    ld c, l
    xor a
    ld c, l
    inc b
    jr nz, jr_018_4cf6

    sub $da
    ld c, l
    push af
    ld c, l
    db $ed
    ld c, l
    db $ed
    ld c, l
    dec b
    jr nz, jr_018_4d02

    sub $0f
    ld c, [hl]
    dec hl
    ld c, [hl]
    inc h
    ld c, [hl]
    inc h
    ld c, [hl]
    rst $38
    db $ed
    ld h, $0f
    ld h, [hl]
    cp d
    rst $18
    pop bc
    call $b77f
    push bc
    cp e
    or d
    rst $20
    ld c, a
    cp d
    cp d
    add $ca
    ld a, a
    cp c
    rst $18
    or [hl]
    or d
    db $dd
    ld a, a
    jp z, $c3df

    or c
    reti


    ld d, c
    call nc, $debd
    inc sp
    ld a, a
    or d
    cp b
    ld h, $7f
    sub $b2
    rst $20
    ld d, a
    ld [$f521], sp
    ld c, h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $bb
    ld h, [hl]
    sbc l
    ld d, [hl]
    ld a, a
    adc e
    ld d, [hl]
    ld a, a
    add c
    ld c, a
    ld d, [hl]
    ld a, a
    and h
    ld d, [hl]
    ld a, a
    adc c
    adc l
    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $00
    ld h, a
    sbc c
    add b
    ld d, [hl]
    rst $20
    ld e, b
    db $ed
    ld h, $d9
    ld h, [hl]
    jp z, $4f56

    call nz, $7fd8
    jp nz, $dab6

    jp $b57f


    rst $18
    ret nz

    or [hl]
    ld d, a
    ld [$0121], sp
    ld c, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $0d
    ld h, a
    sbc l
    ld d, [hl]
    ld a, a
    add e
    and c
    ld d, [hl]
    ld c, a
    ld d, [hl]
    ld a, a
    sub h
    add l
    ld d, [hl]
    sbc l
    sub l
    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $58
    ld h, a
    cp h
    ret nz

    ld a, a
    cp d
    call nz, $e02c
    ld e, b
    db $ed
    ld h, $29
    ld h, a
    jp nz, $dab6

    reti


    call nz, $4fca
    call c, $d3bc
    ld a, a
    rst $08
    jr nc, @-$2f

    jr nc, jr_018_4e25

    ld d, a
    ld [$0d21], sp
    ld c, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $67
    ld h, a
    ld d, [hl]
    ld a, a
    ld c, $0e
    ld d, [hl]
    ld c, a
    ld d, [hl]
    ld a, a
    xor e
    ld a, [de]
    db $e3
    xor h
    ld d, [hl]
    rst $20
    ld d, a
    db $ed
    ld h, $b6
    ld h, a
    cpl
    cpl
    and $58
    db $ed
    ld h, $90
    ld h, a
    cp h
    ld [c], a
    or e
    or a
    add $7f
    db $d3
    inc [hl]
    rst $18
    ret nz

    rst $20
    ld d, a
    ld [$1921], sp
    ld c, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $bc
    ld h, a
    ld d, [hl]
    ld a, a
    ld b, $ad
    ld c, a
    ld d, [hl]
    ld a, a
    ld b, $56
    ld a, a
    ld b, $ad
    ld d, [hl]
    db $e3
    xor e
    rst $20
    ld d, a
    db $ed

jr_018_4e25:
    ld h, $2f
    ld l, b
    reti


    ld d, [hl]
    ld e, b
    db $ed
    ld h, $c9
    ld h, a
    cp b
    inc sp
    ld a, a
    cp h
    pop hl
    daa
    ld [c], a
    or e
    ld a, a
    cp h
    ret nz

    ret


    add $4f
    ld d, [hl]
    ld a, a
    push bc
    cp e
    cp c
    push bc
    or d
    ld d, a
    db $ed
    ld h, $53
    ld h, [hl]
    reti


    ld a, a
    or d
    ret


    ret c

    add $7f
    rst $08
    db $d3
    rst $10
    jp c, Jump_018_4fc0

    cp c
    rst $18
    or [hl]
    or d
    call $ca7f
    or d
    rst $18
    ret nz

    rst $20
    ld d, c
    ld d, d
    call nz, Call_018_547f
    jp z, $cb4f

    call nz, $d47f
    cp l
    ret nc

    cp h
    jp Jump_000_297f


    sbc $b7
    add $7f
    push bc
    rst $18
    ret nz

    rst $20
    ld d, a
    ld bc, $0902
    inc bc
    nop
    sub c
    add hl, bc
    ld [de], a
    nop
    sub e
    nop
    ld b, $19
    inc c
    db $10
    rst $38
    rst $38
    ld bc, $0b19
    dec d
    rst $38
    jp nc, $f542

    ld c, $19
    rlca
    ld [de], a
    rst $38
    jp nc, $f543

    db $10
    add hl, de
    ld c, $0a
    rst $38
    db $d3
    ld b, h
    push af
    ld de, $1419
    dec c
    rst $38
    db $d3
    ld b, l
    push af
    ld [de], a
    dec a
    ld [de], a
    ld a, [bc]
    rst $38
    rst $38
    add [hl]
    ld sp, $c73a
    add hl, bc
    inc bc
    ld b, d
    rst $00
    add hl, bc
    ld [de], a
    ld bc, $0101
    inc bc
    ld a, [bc]
    ld b, $07
    inc bc
    ld bc, $0101
    ld bc, $5b10
    ld h, l
    ld [hl], $36
    ld b, $08
    ld bc, $0c01
    ld d, a
    ld l, c
    ld c, h
    ld [hl], $4c
    ld l, d
    ld e, b
    dec c
    ld bc, $363a
    ld [hl], $4f
    ld c, a
    ld [hl], $36
    ld c, $07
    ld bc, $5011
    ld d, d
    ld [hl], $33
    ld [hl], $52
    ld d, c
    ld [de], a
    ld bc, $501c
    ld [hl], $36
    ld c, a
    ld c, h
    ld [hl], $0e
    ld e, $01
    inc c
    ld e, [hl]
    ld h, a
    ld c, a
    ld c, $4f
    ld l, b
    ld e, a
    dec c
    ld bc, $1401
    dec e
    ld [hl], $36
    ld [hl], $1d
    dec bc
    ld bc, $0101
    ld bc, $1c05
    dec e
    ld e, $05
    ld bc, $0f01
    add hl, bc
    ld a, [bc]
    db $db
    ld d, c
    db $e4
    ld c, a
    ld [hl+], a
    ld c, a
    nop
    and c
    ld d, c
    call Call_000_3c6c
    ld hl, $4ff2
    ld de, $4f40
    ld a, [$d5ae]
    call Call_000_31a8
    ld [$d5ae], a
    ret


Jump_018_4f35:
    xor a
    ld [$cd66], a
    ld [$d5ae], a
    ld [$d97c], a
    ret


    ld c, d
    ld c, a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    call nc, Call_018_7b4f
    ld c, a
    ld a, [$d6e7]
    bit 7, a
    jp nz, Jump_000_3261

    ld hl, $4f78
    call Call_000_3509
    jp nc, Jump_000_3261

    xor a
    ldh [$b4], a
    ld a, $06
    ldh [$8c], a
    call Call_000_13f1
    ld a, $91
    ld [$d036], a
    ld a, $1e
    ld [$d0ec], a
    ld a, $04
    ld [$d5ae], a
    ld [$d97c], a
    ret


    db $10
    ld a, [bc]
    rst $38
    ld a, [$d034]
    cp $ff
    jp z, Jump_018_4f35

    ld a, $ff
    ld [$cd66], a
    ld a, [$d6ac]
    bit 6, a
    ret nz

    call Call_000_0ebd
    ld a, $f0
    ld [$cd66], a
    ld a, [$cf06]
    and a
    jr nz, jr_018_4fb5

    ld hl, $d6e7
    set 7, [hl]
    ld a, $07
    ldh [$8c], a
    call Call_000_13f1
    xor a
    ld [$cd66], a
    ld a, $00
    ld [$d5ae], a
    ld [$d97c], a
    ret


jr_018_4fb5:
    ld a, $01
    ld [$cd38], a
    ld a, $10
    ld [$ccd3], a
    xor a

Jump_018_4fc0:
    ld [$c206], a

Jump_018_4fc3:
    ld [$cd3b], a

Jump_018_4fc6:
    ld hl, $d6af

Call_018_4fc9:
Jump_018_4fc9:
    set 7, [hl]
    ld a, $03
    ld [$d5ae], a
    ld [$d97c], a

Call_018_4fd3:
    ret


    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07

jr_018_4fdc:
    xor a
    ld [$d5ae], a
    ld [$d97c], a
    ret


    rla
    ld d, b

Jump_018_4fe6:
    ld e, h

Call_018_4fe7:
Jump_018_4fe7:
    ld d, b

jr_018_4fe8:
    cp a
    ld d, b
    push bc
    rrca
    push bc
    rrca
    dec bc
    ld d, c
    ld hl, $0151
    jr nc, jr_018_4fdc

    sub $21
    ld d, b
    ld b, b
    ld d, b
    add hl, sp
    ld d, b
    add hl, sp
    ld d, b
    ld [bc], a
    jr nc, jr_018_4fe8

    sub $66
    ld d, b
    sub e
    ld d, b
    ld a, l
    ld d, b
    ld a, l
    ld d, b
    inc bc
    jr nz, @-$17

    sub $c9
    ld d, b
    ld [$e350], a
    ld d, b
    db $e3
    ld d, b
    rst $38
    ld [$f221], sp
    ld c, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $63
    ld l, b
    ld d, [hl]
    ld a, a
    sub l
    ld d, [hl]
    ld a, a
    add d
    add e
    xor h
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    sub d
    ld d, [hl]
    ld a, a
    and [hl]
    xor h
    ld d, [hl]
    rst $20
    ld d, a
    db $ed
    ld h, $b8
    ld l, b
    db $e3
    pop de
    ld e, b
    db $ed
    ld h, $7e
    ld l, b
    rst $20
    ld a, a
    add a
    and l
    add a
    and l
    ld a, a
    cp l
    reti


    rst $20
    ld c, a
    set 3, [hl]
    cp c
    jp nz, $b67f

    db $d3
    ld a, a
    cp h
    jp c, Jump_018_56de

    ld d, a
    ld [$fe21], sp
    ld c, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $c1
    ld l, b
    xor h
    ld d, [hl]
    ld a, a
    sub h
    ld d, [hl]
    ld a, a
    adc e
    xor h
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    add hl, de
    ld d, [hl]
    ld a, a
    ret c

    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $40
    ld l, c
    or [hl]
    ld h, $4f
    call c, $c9bc
    ld a, a
    or [hl]
    rst $10
    jr nc, @-$48

    rst $10
    ld a, a
    rst $00
    cp c
    jp Jump_018_58b8


    db $ed
    ld h, $cc
    ld l, b
    ld a, a
    or [hl]
    rst $10
    jr nc, jr_018_511b

    or [hl]
    rst $10
    ld a, a
    rst $00
    cp c
    ret nz

    db $d3
    ret


    ld d, [hl]
    ld c, a
    cp a
    jp c, Jump_018_7fca

    or [hl]
    ret nc

    ret


    cp c
    ld a, a
    inc sp
    jp z, $c57f

    or d
    rst $20
    ld d, l
    or c
    cp b
    ret c

    ld [c], a
    or e
    ld a, a
    inc l
    ldh [$57], a
    ld [$0a21], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $72
    ld l, c
    ld d, [hl]
    ld a, a
    sbc d
    ld d, [hl]
    ld a, a
    sbc d
    xor h
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    sbc d
    ld d, [hl]
    ld a, a
    sbc d
    sbc d
    ld d, [hl]
    sbc d
    sbc d
    xor h
    rst $20
    ld d, a
    db $ed
    ld h, $c7
    ld l, c
    rst $18
    rst $20
    ld e, b
    db $ed
    ld h, $8e
    ld l, c
    sbc d
    sbc d
    ld a, a
    ld l, [hl]
    rst $18
    db $e3
    cp b
    cp h
    ld [c], a
    sbc $e7
    ld c, a
    or c
    jp c, $dc7f

    cp h
    jp z, $347f

    or e
    cp h
    jp $dec0


    inc l
    ldh [$e6], a
    ld d, a
    db $ed
    ld h, $3c
    ld l, b
    sub b
    adc d
    and a
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    adc c
    adc c
    add l
    and l
    ld a, a

jr_018_511b:
    adc a
    sub b
    adc d
    and a
    ld d, [hl]
    ld d, a
    ld [$3e21], sp
    ld d, c
    call Call_000_3c79
    ld a, $91
    call Call_000_2dc7
    call Call_000_3790
    ld c, $1e
    call Call_000_3781
    ld hl, $5169
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    adc c
    ld d, h
    or d
    ret


    ld a, a

jr_018_5145:
    cp h
    ld [c], a
    or e
    ret nz

    or d
    jp z, Jump_018_5156

    add l
    and l
    add l
    and l
    ret


    ld a, a
    or l
    or [hl]
    or c

Jump_018_5156:
    cp e
    sbc $c9
    ld c, a
    rst $08
    sub $b4
    reti


    ld a, a
    ret nz

    rst $08
    cp h
    or d
    ld a, a
    jr nc, jr_018_5145

    ret nz

    rst $20
    ld d, a
    db $ed
    dec hl
    and $54
    or d
    ld a, a
    add l
    and l
    add l
    and l
    ret


    ld a, a
    or l
    or [hl]
    or c
    cp e
    sbc $c6
    ld c, a
    db $d3
    inc [hl]
    rst $18
    ret nz

    ld a, a
    ret nz

    rst $08
    cp h
    or d
    jp z, Jump_000_3c55

    inc l
    ld a, a
    jp $c6de


    ld a, a
    ret


    ld a, $df
    jp Jump_018_5156


    ld d, [hl]
    ld a, a
    ld d, [hl]
    or a
    or h
    jp $b27f


    or a
    rst $08
    cp h
    ret nz

    ld d, a
    ld bc, $0902
    ld [de], a
    ld bc, $1092
    add hl, bc
    nop
    sub h
    nop
    dec b
    add hl, de
    ld c, $10
    rst $38
    db $d3
    ld b, c
    push af
    inc de
    add hl, de
    add hl, bc
    dec c
    rst $38
    ret nc

    ld b, d
    push af
    inc d
    add hl, de
    add hl, bc
    inc d

Jump_018_51c0:
    rst $38
    jp nc, $f543

    dec d
    dec a
    inc c
    ld a, [bc]
    rst $38
    rst $38
    add h
    jr z, jr_018_520a

    ld [de], a
    ld [de], a
    rst $38
    rst $38
    add l
    ld l, $42
    rst $00
    add hl, bc
    ld [de], a
    ld a, l
    rst $00
    db $10
    add hl, bc
    ld bc, $0101
    inc bc
    ld h, b
    ld e, e
    ld h, c
    inc bc
    ld bc, $0101
    ld bc, $5d10
    ld b, $36
    ld [hl], $06
    ld [$0101], sp
    inc c
    ld e, [hl]
    ld c, [hl]
    ld c, h
    ld [hl], $52
    ld [hl], $5f
    dec c
    ld bc, $360a
    ld [hl], $36
    ld [hl], $52
    ld [hl], $4c
    rlca
    ld bc, $525a
    ld d, b
    ld c, a
    ld c, a
    ld c, h

jr_018_520a:
    ld [hl], $36
    ld d, $01
    inc e
    ld c, a
    ld [hl], $4c
    ld c, h
    ld c, a
    rla
    ld c, a
    ld e, $01
    inc c
    ld d, a
    ld [hl], $4f
    ld [hl], $4f
    ld d, c
    ld e, b
    dec c
    ld bc, $1401
    dec e
    ld c, a
    ld [hl], $52
    dec e
    dec bc
    ld bc, $0101
    ld bc, $3005
    dec e
    ld e, $05
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    ld bc, $0101
    rrca
    add hl, bc
    ld a, [bc]
    db $fd
    ld d, l
    add l
    ld d, e
    ld c, e
    ld d, d
    nop
    db $d3
    ld d, l
    call Call_000_3c6c
    ld hl, $538d
    ld de, $5269
    ld a, [$d5af]
    call Call_000_31a8
    ld [$d5af], a
    ret


Jump_018_525e:
    xor a
    ld [$cd66], a
    ld [$d5af], a
    ld [$d97c], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    ld [hl], e
    ld d, d
    sbc h
    ld d, d
    call z, $2152
    ld e, e
    call $86cb
    ld a, [$d034]
    cp $ff
    jp z, Jump_018_525e

    call Call_000_32bd
    ld a, $f0
    ld [$cd66], a
    ld a, [$cf0e]
    ldh [$8c], a
    call Call_000_13f1
    call Call_018_52fc
    ld a, $03
    ld [$d5af], a
    ld [$d97c], a
    ret


    ld a, [$d6af]
    bit 0, a
    ret nz

    ld hl, $d54d
    ld a, [$cf0e]
    ld b, a

jr_018_52a9:
    ld a, [hl+]
    cp b
    ld a, [hl+]
    jr nz, jr_018_52a9

    ld [$cc4d], a
    ld a, $11

Call_018_52b3:
    call Call_000_3e9d
    xor a
    ld [$cd66], a
    ld [$cf0e], a
    ld [$cc55], a
    ld [$d97b], a
    ld a, $00
    ld [$d5af], a
    ld [$d97c], a
    ret


    ld a, $ff
    ld [$cd66], a
    ld a, $43
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $04
    ld [$c109], a
    ld a, $95
    ldh [$8b], a
    ld a, $01
    ld [$d3ae], a
    ld a, $04
    ld [$d2e4], a
    ld hl, $d6ac
    set 3, [hl]
    ld a, $00
    ld [$d5af], a
    ld [$d97c], a
    ret


Call_018_52fc:
    ld hl, $5329
    ld a, [$cf0e]
    dec a
    swap a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e1]
    ld c, a

jr_018_5311:
    ld a, [hl+]
    cp b
    jr nz, jr_018_5324

    ld a, [hl+]
    cp c
    jr nz, jr_018_5325

    ld a, [hl+]
    ld d, [hl]
    ld e, a
    ld a, [$cf0e]
    ldh [$8c], a
    jp Jump_000_3684


jr_018_5324:
    inc hl

jr_018_5325:
    inc hl
    inc hl
    jr jr_018_5311

    inc c
    add hl, bc
    ld e, c
    ld d, e
    dec bc
    ld a, [bc]
    ld h, c
    ld d, e
    dec bc
    dec bc
    ld l, b
    ld d, e
    dec bc
    inc c
    ld l, b
    ld d, e
    ld a, [bc]
    inc c
    ld l, [hl]
    ld d, e
    add hl, bc
    dec bc
    db $76
    ld d, e
    add hl, bc
    ld a, [bc]
    ld l, b
    ld d, e
    add hl, bc
    add hl, bc
    ld l, b
    ld d, e
    ld [$7d09], sp
    ld d, e
    rlca
    ld a, [bc]
    ld l, b
    ld d, e
    rlca
    dec bc
    ld l, b
    ld d, e
    rlca
    inc c
    ld l, b
    ld d, e
    ret nz

    nop
    nop
    nop
    nop
    nop
    add b
    rst $38
    nop
    ret nz

    nop
    nop
    nop
    nop
    rst $38
    nop
    nop
    nop
    nop
    nop
    rst $38
    add b
    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    nop
    nop
    nop
    add b
    nop
    nop
    rst $38
    ret nz

    nop
    nop
    nop
    nop
    nop
    nop

jr_018_5384:
    rst $38
    or d
    ld d, e
    xor $53
    ld a, e
    ld d, h
    ret


    ld d, h
    ld bc, $e830

jr_018_5390:
    sub $bc
    ld d, e
    ldh [rHDMA3], a
    rst $10
    ld d, e
    rst $10
    ld d, e
    ld [bc], a
    jr nc, jr_018_5384

    sub $f8
    ld d, e
    ld c, a
    ld d, h
    ld b, e
    ld d, h
    ld b, e
    ld d, h
    inc bc
    jr nc, jr_018_5390

    sub $85
    ld d, h
    or c
    ld d, h
    and e
    ld d, h
    and e
    ld d, h
    rst $38
    ld [$8d21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $d2
    ld l, c
    push bc
    sbc $30
    ld a, a
    or l
    rst $08
    or h
    jp z, Jump_018_4fe6

    push bc
    add $bc
    add $7f
    cp d
    cp d
    call $b77f
    ret nz

    and $57
    db $ed
    ld h, $1f
    ld l, d
    or d
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    ld h, $fe
    ld l, c
    or l
    ld a, $b4
    jp $d47f


    ld h, $da
    rst $20
    ld d, a
    ld [$9921], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $2a
    ld l, d
    inc l
    or d
    cp e
    sbc $4f
    ld e, [hl]
    ld a, a
    add b
    dec bc
    sub e
    add $7f
    cp b
    reti


    push bc
    ret c

    ld d, c
    ld d, h
    db $dd
    ld a, a
    or d
    inc l
    jp nc, $d8c0

    ld c, a
    cp d
    db $db
    cp h
    ret nz

    ret c

    ld a, a
    cp l
    reti


    push bc
    rst $18
    jp $b37f


    reti


    cp e

jr_018_5425:
    cp b
    jp $ba51


jr_018_5429:
    cp d
    inc sp
    ld a, a
    or l
    call nz, $c9c5
    ld a, a
    jp z, $bcc5

    ld a, a
    or c
    or d
    db $dd
    ld c, a
    cp h
    jp $7fc0


    call nz, $dbba
    jr nc, jr_018_5429

    ld d, a
    db $ed
    ld h, $39
    ld l, e
    sbc $7f
    cp h
    jp $dab8


    ld d, [hl]
    ld e, b

Jump_018_544f:
    db $ed
    ld h, $dc
    ld l, d
    jp $bc4f


    ld [c], a
    or e
    ld a, [hl-]
    or d
    ld a, a
    inc [hl]
    or e
    jr z, jr_018_5425

    ld a, a
    cp l
    daa
    push bc
    or d
    rst $20
    ld d, c
    or l
    jp c, $c1c0

    ret


    ld c, a
    inc l
    ldh [$cf], a
    ld a, a
    cp l
    reti


    sbc $2c
    ldh [$7f], a
    push bc
    or d
    ld l, $e7
    ld d, a
    ld [$a521], sp
    ld d, e

Call_018_547f:
Jump_018_547f:
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $56
    ld l, e
    pop bc
    db $dd
    ld a, a
    ret nz

    or l
    cp e
    push bc
    or a
    ldh [rVBK], a
    inc l
    or d
    cp e
    sbc $ca
    ld a, a
    ret nz

    cp l
    cp c
    rst $10
    jp c, $b2c5

    ld l, $e7
    ld d, a
    db $ed
    ld h, $e8
    ld l, e
    jp z, $b6d1

    or e
    ld a, a
    call nz, $c5ca
    rst $20
    ld e, b
    db $ed
    ld h, $8e
    ld l, e
    ld d, [hl]
    rst $20
    ld c, a
    cp d
    ret


    rst $08
    rst $08
    inc sp
    ld a, a
    cp l
    pop de
    call nz, $b57f
    db $d3
    or e
    push bc
    sub $e7
    ld d, a
    ld [$0321], sp
    ld d, l
    call Call_000_3c79
    ld hl, $d75f
    set 7, [hl]
    ld hl, $d6e8
    set 7, [hl]
    ld a, $44
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, $17
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $18
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, $04
    ld [$d5af], a
    ld [$d97c], a
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld d, e
    ld d, l
    or h

jr_018_5508:
    ld d, [hl]
    ld a, a
    call c, $bcc0
    db $dd
    ld c, a
    ret nz

    cp l
    cp c
    add $7f
    or a
    ret nz

    sbc $33
    cp l
    or [hl]
    and $51
    ld d, [hl]
    ld a, a
    inc [hl]
    or e
    db $d3
    ld a, a
    or c
    ret c

    ld h, $c4
    or e
    ld c, a
    inc sp
    db $d3
    ld d, [hl]
    ld a, a
    call c, $bcc0
    jp z, Jump_018_5156

    add l
    and l
    add l
    and l
    ret


    ld a, a
    or l
    or [hl]

Jump_018_553a:
    or c
    cp e
    sbc $7f
    dec b
    and l
    dec b
    and l
    ret


    ld c, a
    ret nz

    rst $08
    cp h
    or d
    db $dd
    ld a, a
    push bc
    jr z, jr_018_5508

    jp nc, Jump_018_7fd9

    ret nz

    jp nc, Jump_018_55c6

    cp l
    cp l

Jump_018_5556:
    sbc $33
    ld a, a
    cp d
    cp d
    rst $08
    inc sp
    ld a, a
    or a
    ret nz

    ret


    inc sp
    cp l
    ld d, c
    ld d, [hl]
    or c
    or c
    ld a, a
    inc [hl]
    or e
    call nc, $7fd7
    dec b
    and l
    dec b
    and l
    db $d3
    ld c, a
    jp Jump_000_2ade


    cp b
    call $d17f
    or [hl]
    rst $18
    ret nz

    ld a, a
    sub $b3
    inc sp
    cp l
    ret z

    ld d, c
    cp [hl]
    rst $18
    or [hl]
    cp b
    ld a, a
    cp d
    cp d
    rst $08
    inc sp
    ld a, a
    or a
    jp $dab8


    ret nz

    ld c, a
    or a
    ret nc

    add $d3
    ld a, a
    or l
    jp c, $ddb2

    ld a, a
    cp h
    push bc
    or a
    ldh [$c8], a
    rst $20
    ld d, c
    inc sp
    jp z, $ba7f

    jp c, $d7b6

    ld c, a
    or d
    rst $18
    cp h
    ld [c], a
    add $7f
    or e
    pop bc
    call $b27f
    or a
    rst $08
    cp h
    ld [c], a
    or e
    ld d, c
    ld d, h
    sbc c
    add d
    adc h
    jp z, $ba4f

    ret


Jump_018_55c6:
    ld a, a
    adc a
    xor c
    db $e3

Jump_018_55ca:
    ret


    ld a, a
    call z, $c4d3
    inc sp
    cp l
    rst $20
    ld d, a

Jump_018_55d3:
    ld bc, $1001
    add hl, bc
    ld bc, $0093
    inc b
    jr @+$11

Jump_018_55dd:
    dec c
    rst $38
    db $d3
    ld b, c
    and $13
    jr @+$0f

    db $10
    rst $38

Call_018_55e7:
    jp nc, $e642

    inc d
    jr jr_018_55f8

    dec c
    rst $38
    db $d3
    ld b, e
    and $15
    ld d, $07
    ld c, $ff
    ret nc

jr_018_55f8:
    inc b
    ld a, l
    rst $00
    db $10
    add hl, bc
    ld bc, $0101
    inc bc
    ld [bc], a
    ld [bc], a
    ld [bc], a
    inc bc
    ld bc, $0101

Call_018_5608:
    ld bc, $0210
    ld l, h
    ld c, $6d
    ld [bc], a
    ld [$0101], sp
    inc c
    ld [bc], a
    ld [bc], a
    add hl, sp
    ld c, $20
    ld [bc], a
    ld [bc], a
    dec c
    ld bc, $0202
    ld [bc], a
    add hl, sp
    ld c, $20
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld bc, $0202
    ld [bc], a
    add hl, sp
    ld c, $20
    ld [bc], a
    dec [hl]
    ld [bc], a
    ld bc, $0202
    ld [bc], a
    add hl, sp
    ld c, $20
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld bc, $020c
    ld [bc], a
    inc e
    ld c, $1e
    ld [bc], a
    ld [bc], a
    dec c
    ld bc, $1401
    ld [bc], a
    ld [bc], a
    ld c, $02
    ld [bc], a
    dec bc
    ld bc, $0101
    ld bc, $3105
    dec e
    ld e, $05
    ld bc, $1201
    inc b
    ld a, [bc]
    ld d, c
    ld d, a
    ld h, [hl]
    ld d, [hl]
    ld h, e
    ld d, [hl]
    nop

jr_018_5661:
    ld de, $c357
    ld l, h
    inc a
    ld l, h
    ld d, [hl]
    xor b
    ld d, [hl]
    ld bc, $ed57
    ld h, $39
    ld b, a
    cp h
    ldh [$b2], a
    rst $08
    cp [hl]

Jump_018_5675:
    rst $20
    ld c, a
    adc a
    sbc l
    sbc a
    adc e
    ld a, a
    ld [de], a
    ld b, b
    db $e3

Call_018_567f:
    sub e
    add $7f
    sub $b3
    cp d
    cp a
    rst $20
    ld d, c
    or [hl]
    cp b
    ld a, a
    sbc e
    xor b
    add b
    ret


    ld a, a
    or c
    sbc $c5
    or d
    jp z, $d04f

    daa
    ret


    ld a, a
    inc e
    db $e3
    inc de
    db $dd
    ld a, a
    ld a, [hl+]
    rst $10
    sbc $7f
    cp b
    jr nc, jr_018_5661

    or d
    ld d, a
    db $ed
    ld h, $a4
    ld b, a
    ld d, [hl]
    adc d
    db $e3
    ld a, [de]
    adc h
    ld [hl], h
    add l
    add d
    xor e
    adc a
    db $e3
    ld d, c
    ld hl, sp-$4a
    or d
    ld d, [hl]
    ld e, l
    inc c
    ld [hl], h
    sbc l
    db $e3
    adc b
    xor h
    sub e
    ld d, c
    ld sp, hl
    or [hl]
    or d
    ld d, [hl]
    sub d

Call_018_56ca:
Jump_018_56ca:
    and a
    ld a, [de]
    ld a, a
    ld [$9fe3], sp
    ld a, a
    adc e
    xor a
    xor h
    ld b, d
    ld d, c
    ld a, [$b2b6]
    ld d, [hl]
    xor c
    add c
    inc c
    sbc l

Jump_018_56de:
    xor e
    ld [hl], h
    ld b, $9b
    sub e
    ld d, c
    ei
    or [hl]
    or d
    ld d, [hl]
    inc de
    and l
    xor h
    rlca
    ld a, a
    adc h
    sub e
    add b
    ld d, c
    or l
    cp b
    inc l
    ld [c], a
    or e
    ld d, [hl]
    inc l
    inc [hl]
    or e
    ld a, a
    jp z, Jump_000_3ade

    or d
    or a
    ld d, a
    db $ed
    ld h, $a1
    ld c, b
    ld d, [hl]
    adc d
    db $e3
    ld a, [de]
    adc h
    ld [hl], h
    add l
    add d
    xor e
    adc a
    db $e3
    ld d, a
    rrca
    ld b, $07
    ld [bc], a
    nop
    rst $38
    rlca
    inc bc
    nop
    rst $38
    rlca
    db $10
    ld bc, $07ff
    ld de, $ff01
    ld bc, $000c
    ld a, e
    ld bc, $0001
    ld a, a
    ld [bc], a
    inc b
    dec bc
    ld [bc], a
    ld bc, $030e
    ld bc, $072a
    inc c
    rst $38
    ret nc

    ld bc, $c72a
    rlca
    ld [bc], a
    ld a, [hl+]
    rst $00
    rlca
    inc bc
    ld sp, $07c7
    db $10
    ld sp, $07c7
    ld de, $c6ff
    ld bc, $f90c
    add $01
    ld bc, $0d0c
    ld bc, $0118
    add hl, de
    ld [bc], a
    dec h
    rlca
    ld bc, $0b0b
    dec bc
    inc d
    dec bc
    rla
    dec bc
    dec bc
    ld [de], a
    add hl, bc
    dec bc
    dec bc
    dec bc
    dec d
    ld de, $0b26
    dec bc
    dec bc
    add hl, bc
    dec bc
    ld [$0b0b], sp
    dec bc
    dec bc
    dec bc
    dec bc
    ld [$210b], sp
    xor a
    sub $cb
    or $af
    ld [$cc26], a
    ld a, $03
    ld [$cc29], a
    ld a, [$cd37]
    dec a
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    ld a, [$cd37]
    dec a
    ld bc, $0002
    ld hl, $0003
    call Call_000_3ad1
    dec l
    ld b, l
    ld c, $12
    ld hl, $c3a0
    call Call_000_03d2
    call Call_000_0ebd
    call Call_018_58e9
    ld hl, $d6af
    res 6, [hl]
    call Call_000_3b08
    bit 1, a
    jr nz, jr_018_581a

    ld hl, $cc5b
    ld a, [$cc26]
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    ldh [$db], a
    cp $29
    jr z, jr_018_57de

    cp $2a
    jr z, jr_018_57da

    ld b, $ab
    jr jr_018_57e0

jr_018_57da:
    ld b, $62
    jr jr_018_57e0

jr_018_57de:
    ld b, $5a

jr_018_57e0:
    ld [$d68e], a
    ld a, b
    ld [$d68f], a

Call_018_57e7:
Jump_018_57e7:
    call Call_018_5912
    ld hl, $5821
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_018_581a

    ld hl, $5874
    call Call_000_3c79
    ld a, [$d68e]
    ldh [$db], a
    ld b, $05
    ld hl, $7fae
    call Call_000_3620
    ld hl, $58ab
    call Call_000_3c79
    ld hl, $d722
    set 0, [hl]
    set 1, [hl]
    ret


jr_018_581a:
    ld hl, $58d8
    call Call_000_3c79
    ret


    db $ed
    dec hl
    sub a
    ld d, [hl]
    ld c, a
    cp a
    jp c, Jump_018_7fca

    ld d, b
    ld bc, $cd68
    nop
    rst $20
    ld d, c
    or l
    or l
    ld a, a
    pop de
    or [hl]
    cp h
    ret


    ld a, a
    ld d, h
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld a, a
    or d
    or e
    ld a, a
    add l
    adc l
    add [hl]
    ret z

    rst $20
    ld d, c
    call c, $bcc0
    ret


    ld a, a
    jp nz, $dfb8

    ret nz

    ld c, a
    add l
    adc l
    add [hl]
    ld a, a
    cp e
    or d
    cp [hl]
    or d
    ld a, a
    sbc l
    adc e
    xor e
    inc sp
    ld d, c
    cp d
    jp c, Jump_018_4fe7

    or d
    or a
    or [hl]
    or h
    rst $10
    cp [hl]
    jp $d07f


    cp [hl]
    reti


    ret z

    rst $20
    ld d, a
    db $ed
    dec hl
    inc [hl]
    ld d, a
    rst $20
    ld a, a
    inc l
    ldh [$7f], a
    cp a
    jp c, $ca4f

    call nc, Call_018_7fb8
    cp d
    rst $18
    pop bc
    add $7f
    sub $ba
    cp l
    ld a, a
    sub $db
    cp h
    rst $20
    ld d, c
    ld d, d
    jp z, $cd7f

    sbc $c5
    ld a, a
    jp z, $beb6

    add $4f
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    or c
    dec l
    cp c
    ret nz

    rst $20
    ld e, b
    db $ed
    dec hl
    adc a
    ld d, a
    call nz, Call_000_2c7f
    or [hl]
    sbc $7f
    or [hl]
    or [hl]
    reti


Jump_018_58b8:
    sub $e7
    ld d, c
    cp a
    cp d
    rst $10
    call $ddde
    ld a, a
    cp l
    cp d
    cp h
    ld a, a
    ld c, a
    dec de
    and l
    dec de
    and l
    ld a, a
    cp h
    jp $d9b8


    call nz, $d67f
    db $db
    cp h
    db $e3

Jump_018_58d6:
    rst $20
    ld d, a
    db $ed
    dec hl
    call z, $e757
    ld a, a
    rst $08
    ret nz

    ld a, a
    cp b
    reti


    ld a, a
    sub $db
    cp h
    rst $20
    ld d, a

Call_018_58e9:
    ld hl, $cc5b
    xor a
    ldh [$db], a

jr_018_58ef:
    ld a, [hl+]
    cp $ff
    ret z

    push hl
    ld [$d0e3], a
    call Call_000_1add
    ld hl, $c3ca
    ldh a, [$db]
    ld bc, $0028
    call Call_000_3ad1
    ld de, $cd68
    call Call_000_0405
    ld hl, $ffdb
    inc [hl]
    pop hl
    jr jr_018_58ef

Call_018_5912:
    ld a, [$d68f]
    ld [$d0e3], a
    call Call_000_1aab
    call Call_000_386e
    ld a, [$d68e]
    ld [$d0e3], a
    call Call_000_1add
    ret


    inc bc
    jr @+$13

    nop
    ld b, b
    ld c, l
    ld e, c
    inc [hl]
    ld e, c
    nop
    dec a
    ld e, h
    call Call_000_3c6c
    ld hl, $5969
    ld de, $5947
    ld a, [$d597]
    call Call_000_31a8
    ld [$d597], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    adc [hl]
    ld e, c
    ret nz

    ld e, c
    rla
    ld e, d
    ld h, [hl]
    ld e, d
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    sbc $5a
    add hl, de
    ld e, e
    ld d, a
    ld e, e
    db $76
    ld e, e
    and e
    ld e, e
    ld [c], a
    ld e, e
    ld [hl+], a
    ld e, h
    ld [bc], a
    ld b, b
    ld [hl], d
    rst $10
    jp z, $0159

    ld e, d
    jp hl


    ld e, c
    jp hl


    ld e, c
    inc bc
    ld b, b
    ld [hl], d
    rst $10
    ld hl, $4d5a
    ld e, d
    ld a, $5a
    ld a, $5a
    inc b
    db $10
    ld [hl], d
    rst $10
    ld [hl], b
    ld e, d
    sbc [hl]
    ld e, d
    adc l
    ld e, d

jr_018_598b:
    adc l
    ld e, d
    rst $38
    db $ed
    inc h
    ld h, e
    ld [hl], e
    pop bc
    call nz, $d17f
    cp h
    ld a, a
    ld d, h
    ld c, a
    call nz, $c6d8
    ld a, a
    or a
    jp $ded9


    jr nc, jr_018_598b

    ld d, c
    ld d, h
    ld a, a
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    cp h
    ret nz

    cp b
    jp $d04f


    sbc $c5
    ld a, a
    add d
    inc c
    add d
    inc c
    ld a, a
    cp h
    jp $d6d9


    rst $20
    ld d, a
    ld [$6921], sp
    ld e, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    rst $00
    db $76
    xor h
    rst $20
    ld c, a
    or a
    ret nc

    jp z, Jump_018_547f

    ld a, a
    db $d3
    rst $18
    jp $c5d9


    and $55
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    cp h
    sub $b3
    ld l, $e7
    ld d, a
    db $ed
    inc h
    ld b, l
    ld [hl], a
    or c
    rst $20
    ld c, a
    add [hl]
    xor l
    adc a
    ld b, c
    db $e3
    ld a, a
    push bc
    sbc $b6
    ld a, a
    inc l
    ldh [$7f], a
    rrca
    and b
    or [hl]
    ld e, b
    db $ed
    inc h
    rrca
    ld [hl], a
    rst $20
    ld c, a
    pop de
    cp h
    ld h, $7f
    add $29
    reti


    ld a, a
    or [hl]
    rst $10
    ld a, a
    rst $08
    ret nz

    push bc
    rst $20
    ld d, a
    ld [$7521], sp
    ld e, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld c, l
    ld [hl], a
    xor h
    rst $20
    ld c, a
    ld d, h
    ld a, a
    ld e, l
    push bc
    rst $10
    ld d, l
    cp h
    ld [c], a
    or e
    inc a
    jp z, $ba7f

    call nz, $dadc
    ld a, a
    push bc
    or d
    ld l, $e7
    ld d, a
    db $ed
    inc h
    db $dd
    ld [hl], a
    ld c, a
    db $d3
    or e
    ld a, a
    ld d, h
    ld h, $7f
    push bc
    or d
    call nc, $ed58
    inc h
    adc h
    ld [hl], a
    or d
    push bc
    rst $20
    ld c, a
    jp nz, $b2d6

    ret


    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    jp $ba7f


    sub $b3
    rst $20
    ld d, a
    ld [$8121], sp
    ld e, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld a, [$c477]
    ld a, a
    rst $08
    rst $18
    ret nz

    or c
    rst $20
    ld c, a
    cp a
    sbc $c5
    ld a, a
    or d
    cp a
    or d
    inc sp
    ld a, a
    inc [hl]
    cp d
    add $7f
    or d
    cp b
    and $57
    db $ed
    inc h
    call nz, $c078
    rst $20
    ld c, a
    or a
    ret nc

    jp z, $c27f

    sub $b2
    push bc
    rst $20
    ld e, b
    db $ed
    inc h
    dec h
    ld a, b
    or d
    ld a, a
    call nz, $dbba
    ld a, a
    inc sp
    db $d3
    ld a, a
    sbc h
    xor e
    sub e
    jp z, $c54f

    add $b6
    ld a, a
    or l
    pop bc
    jp $d8c0


    ld a, a
    cp l
    reti


    rst $20
    ld d, c
    cp e
    rst $18
    or a
    ld a, a
    or l
    call nz, $d3bc
    ret


    ld a, a
    cp h
    ret nz

    sbc $30
    ld c, a
    or a
    ret nc

    db $d3
    ld a, a
    cp e
    ld h, $bc
    jp $d07f


    jp $b87f


    jp c, $e6d9

    ld d, a
    db $ed
    inc h
    pop de
    ld [hl], e
    db $db
    or e
    call nz, $c3bc
    ld c, a
    and c
    xor e
    adc h
    adc a
    db $e3
    ld a, a
    inc e
    db $e3
    and [hl]
    ld a, a
    push bc
    add hl, hl
    jp $d7c0


    ld d, l
    cp l
    jr z, jr_018_5b7a

    push bc
    cp b
    push bc
    rst $18
    pop bc
    ldh [$df], a
    ret nz

    ld d, c
    or a
    ret nc

    db $d3
    ld a, a
    or l
    or l
    jp nc, Jump_018_4fc6

    or [hl]
    rst $18
    jp $b57f


    cp b
    call nz, $b27f
    or d
    sub $57
    db $ed
    inc h
    dec sp
    ld [hl], h
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    db $d3
    rst $18
    jp Jump_018_7fd9


    ld d, h
    ld h, $7f
    sub $dc
    rst $18
    jp $b77f


    jp $c04f


    ret nz

    or [hl]
    call c, $c0be
    cp b
    ld a, a
    push bc
    or d
    ld a, a
    call nz, $cab7
    ld d, l
    cp b
    cp e
    pop de
    rst $10
    db $dd
    ld a, a
    sub $b9
    jp $b67f


    or h
    db $db
    or e
    rst $20
    ld d, a
    db $ed
    inc h
    cp c
    ld [hl], h
    ld a, a
    cp b
    rst $10
    rst $18
    ret nz

    rst $10
    ld a, a
    inc [hl]
    cp b
    cp c
    cp h
    rst $20
    ld c, a
    sbc e
    and a
    xor e
    inc de
    ret c

    or b
    ld a, a
    adc e
    xor a
    xor h
    ld b, d
    inc sp
    rst $20
    ld d, a
    db $ed
    inc h
    dec b
    ld [hl], l

jr_018_5b7a:
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7

jr_018_5b84:
    ld d, c
    ld d, h
    dec l
    or [hl]
    sbc $ca
    ld c, a
    ld e, e
    jp nz, $bcb3

    sbc $33
    ld d, l
    add h
    db $e3
    add [hl]
    inc de
    jp z, $beb6

    add $7f
    ret nc

    jp $d7d3


    or h
    reti


    rst $20
    ld d, a
    db $ed
    inc h
    db $76
    ld [hl], l
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    set 0, h
    ret


    ld a, a
    ld d, h
    jp z, $cb7f

    call nz, $7fc9
    db $d3
    ret


    rst $20
    ld c, a
    call nc, $b2be
    ret


    ld a, a
    ld d, h
    add $7f
    jr nc, jr_018_5b84

    ld d, l
    and c
    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    db $dd
    ld a, a
    push bc
    add hl, hl

jr_018_5bd8:
    jp $c255


    or [hl]
    rst $08
    or h
    sub $b3
    rst $20
    ld d, a
    db $ed
    inc h
    rst $30
    ld [hl], l
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c

jr_018_5bf1:
    ld d, h
    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    reti


    ld a, a
    call nz, $cab7
    ld c, a
    push bc
    reti


    dec a
    cp b
    ld a, a
    sub $dc
    rst $10
    cp [hl]
    jp $d7b6


    rst $20
    ld d, c
    ld d, h
    ld h, $7f
    add hl, hl
    sbc $b7
    jr nc, jr_018_5bd8

    ld c, a
    add $29
    reti


    or [hl]
    db $d3
    ld a, a
    cp h
    jp c, $b2c5

    sub $e7
    ld d, a
    db $ed
    inc h
    ld a, d
    db $76
    ret


    ld a, a
    db $d3
    ret c

    ld a, a
    ld d, [hl]
    ld a, a
    inc sp
    jr z, jr_018_5bf1

    ld c, a
    cp d
    ret


    cp e
    or a
    ld a, a
    sub l
    ld a, [de]
    ld a, a
    adc e
    sub d
    or b
    ld d, a
    inc bc
    ld b, $00
    ld bc, $2f02
    nop
    ld [bc], a
    inc bc
    cpl
    cpl
    rrca
    ld bc, $2f32
    db $10
    ld bc, $2f32
    ld de, $3201
    cpl
    ld [de], a
    ld bc, $0632
    jr z, @+$1a

    add hl, bc
    jr nz, jr_018_5c6d

    ld a, [bc]
    ld de, $0b1a
    jr jr_018_5c67

    inc c
    dec l
    ld [de], a
    dec c

jr_018_5c67:
    ld bc, $0e02
    ld [$2f04], sp

jr_018_5c6d:
    inc d
    rst $38
    rst $38
    ld bc, $2504
    ld [hl+], a
    rst $38
    jp nc, $ca42

    ld bc, $1704
    ld [hl+], a
    rst $38
    jp nc, $ca43

    ld [bc], a
    inc b
    ld d, $06
    rst $38
    jp nc, $ca44

    inc bc
    dec a
    rrca
    dec e
    rst $38
    rst $38
    add l
    dec bc
    dec a
    ld hl, $ff10
    rst $38
    add [hl]
    inc d
    dec a
    inc hl
    dec b
    rst $38
    rst $38
    add a
    inc b
    inc b
    inc l
    rra
    rst $38
    rst $38
    ld [$c700], sp
    nop
    ld bc, $c701
    nop
    ld [bc], a
    jr @-$35

    cpl
    rrca
    add hl, de
    ret


    cpl
    db $10
    add hl, de
    ret


    cpl
    ld de, $c91a
    cpl

jr_018_5cbb:
    ld [de], a
    dec c
    add hl, bc
    inc d
    cp h
    ld e, l
    call z, $c85c
    ld e, h
    nop
    ld d, h
    ld e, l
    call Call_000_3c6c
    ret


    ret nc

    ld e, h
    rla
    ld e, l
    db $ed
    dec h
    db $10
    ld l, b
    dec bc
    xor [hl]
    db $e3
    and [hl]
    rst $20
    ld c, a
    call c, $bcc0
    jp z, $ba7f

    ret


    call z, $c9c8
    ld a, a
    inc e
    db $e3
    add c
    inc sp
    cp l
    ld d, c
    ld a, [hl+]
    sub $b3
    db $dd
    ld a, a
    push bc
    sbc $c5
    ret c

    call nz, $b54f
    db $d3
    or e
    cp h
    jp nz, Jump_018_7fb9

    cp b
    jr nc, jr_018_5cbb

    or d
    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld c, a
    ld d, [hl]
    ld a, a
    pop de
    cp b
    pop bc
    push bc
    ld a, a
    or [hl]
    ret nz

    ld a, a
    inc sp
    cp l
    ret z

    ld d, a
    db $ed
    dec h
    add [hl]
    ld l, b
    call z, $c9c8
    ld a, a
    or l
    or a
    ldh [$b8], a
    jp z, $c54f

    ld h, $c0
    dec sp
    add $7f
    ret nz

    or d
    cp b
    jp nz, $bc7f

    jp $e7d9


    ld d, c
    set 1, a
    ld a, a
    jp nz, $bc3c

    add $7f
    ret nz

    ret nz

    or [hl]
    or d
    db $dd
    ld c, a
    or d
    inc [hl]
    sbc $33
    ld a, a
    cp b
    reti


    ld a, a
    set 0, h
    db $d3
    ld a, a
    or d
    reti


    or [hl]
    db $d3
    ld d, a
    inc c
    dec bc
    nop
    ld a, [de]
    ld bc, $005e
    dec de
    ld bc, $085e
    rra
    nop
    ld h, [hl]
    ld [$0117], sp
    ld h, [hl]
    ld [$0213], sp
    ld h, [hl]
    ld [$030f], sp
    ld h, [hl]
    ld [$040b], sp
    ld h, [hl]
    ld [$0507], sp
    ld h, [hl]
    ld b, $02
    ld b, $60
    rrca
    dec h
    dec b
    ld h, d
    db $10
    inc bc
    nop
    ld h, h
    nop
    ld [bc], a
    ld a, [de]
    ld a, [bc]
    db $10
    cp $02
    ld bc, $0913
    rra
    rst $38
    rst $38
    ld [bc], a
    db $10
    rst $00
    nop
    ld a, [de]
    db $10
    rst $00
    nop
    dec de
    ld a, d
    rst $00
    ld [$761f], sp
    rst $00
    ld [$7417], sp
    rst $00
    ld [$7213], sp
    rst $00
    ld [$700f], sp
    rst $00
    ld [$6e0b], sp
    rst $00
    ld [$5207], sp
    rst $00
    ld b, $02
    set 0, a
    rrca
    dec h
    call nc, Call_000_10c7
    inc bc
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld c, $10
    dec c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld c, $10
    dec c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld [de], a
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    inc de
    db $10
    rrca
    dec b
    dec b
    dec b
    dec b
    ld de, $180e
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
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    dec c
    ld c, $10
    ld bc, $1514
    inc d
    dec d
    inc d
    dec d
    inc d
    dec d
    inc d
    dec d
    ld [bc], a
    ld [bc], a
    inc d
    dec d
    inc bc
    ld d, $0d
    ld c, $10
    dec c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld c, $10
    dec c
    ld c, $10
    dec c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld c, $10
    dec c
    ld c, $10
    dec c
    inc c
    inc c
    inc c
    inc c

Jump_018_5e4f:
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c

Jump_018_5e55:
    inc c
    inc c
    inc c
    inc c
    ld c, $17
    dec c
    inc c
    inc d
    ld a, [hl-]
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld [bc], a
    inc c
    dec c
    add hl, bc
    inc d
    jp c, $b861

    ld e, a
    ld a, h
    ld e, [hl]
    nop
    add b
    ld h, c
    call Call_000_3c6c
    ld hl, $5e90
    ld a, [$d5e4]
    jp Jump_000_3dc7


Jump_018_5e88:
    xor a
    ld [$cd66], a
    ld [$d5e4], a
    ret


    sbc e
    ld e, [hl]
    dec c
    ld e, a
    ld c, d
    ld e, a
    sbc e
    ld e, a
    sbc d
    ld e, [hl]
    ret


    ld hl, $5eee
    call Call_000_3509
    ret nc

    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld c, $02
    ld a, $de
    call Call_000_0e35
    ld a, [$cd3d]
    ldh [$db], a
    ld a, $71
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    call Call_000_3e07
    ld a, $02
    ldh [$8c], a
    call Call_000_358b
    xor a
    ldh [$b4], a
    ld a, $f0
    ld [$cd66], a
    ldh a, [$db]
    cp $02
    jr nz, jr_018_5edd

    ld de, $5ee9
    jr jr_018_5ee0

jr_018_5edd:
    ld de, $5eea

jr_018_5ee0:
    call Call_000_3684
    ld a, $01
    ld [$d5e4], a
    ret


    nop
    nop
    nop
    nop
    rst $38
    ld [$0824], sp
    dec h
    rst $38

Call_018_5ef3:
    ld a, [$d2e1]
    cp $25
    jr nz, jr_018_5f03

    ld a, $02
    ld [$d4a7], a
    ld a, $0c
    jr jr_018_5f04

jr_018_5f03:
    xor a

jr_018_5f04:
    ldh [$8d], a
    ld a, $02
    ldh [$8c], a
    jp Jump_000_34f0


    ld a, [$d6af]
    bit 0, a
    ret nz

    call Call_018_5ef3
    xor a
    ld [$cd66], a
    ld a, $02
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_3e07
    ld a, $f2
    ld [$d036], a
    ld a, [$d694]
    cp $b1
    jr nz, jr_018_5f34

    ld a, $01
    jr jr_018_5f3e

jr_018_5f34:
    cp $99
    jr nz, jr_018_5f3c

    ld a, $02
    jr jr_018_5f3e

jr_018_5f3c:
    ld a, $03

jr_018_5f3e:
    ld [$d03a], a
    call Call_018_5ef3
    ld a, $02
    ld [$d5e4], a
    ret


    ld a, [$d034]
    cp $ff
    jp z, Jump_018_5e88

    call Call_018_5ef3
    ld a, $f0
    ld [$cd66], a
    ld a, $03
    ldh [$8c], a
    call Call_000_13f1
    ld a, $02
    ldh [$8c], a
    call Call_000_358b
    ld a, [$d2e1]
    cp $25
    jr nz, jr_018_5f74

    ld de, $5f96
    jr jr_018_5f77

jr_018_5f74:
    ld de, $5f94

jr_018_5f77:
    ld a, $02
    ldh [$8c], a
    call Call_000_3684
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a44
    call Call_000_3620
    ld a, $03
    ld [$d5e4], a
    ret


    ret nz

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
    ld a, $71
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    call Call_000_0d9b
    ld a, $04
    ld [$d5e4], a
    ret


    cp [hl]
    ld e, a
    inc de
    ld h, b
    ld de, $ed61
    dec h
    ld a, [c]
    ld l, b
    call z, $cac8
    ld a, a
    cp [hl]
    or [hl]
    or d
    ld a, a
    or [hl]
    cp b
    pop bc
    ret


    ld c, a
    ld d, h
    ld a, a
    ld e, l
    ld h, $7f
    ret


    rst $18
    jp $55d9


    or c
    cp d
    ld h, $da
    ret


    ld a, a
    ld a, [hl+]
    or e
    or [hl]
    ld a, a
    or a
    ldh [$b8], a
    cp [hl]
    sbc $e7
    ld d, c
    ret nc

    push bc
    call nz, $7fc6
    jp nz, $c0b8

    dec sp
    add $4f
    cp h
    ld [c], a
    or e
    ret nz

    or d
    ld a, a
    cp e
    jp c, $7fc0

    ld e, l
    call nz, $ba55
    or e
    ret c

    pop hl
    or e
    ld a, a
    ld b, b
    db $e3
    sub d
    or b
    db $dd
    ld a, a
    cp h
    jp $bdcf


    ld d, a
    ld [$2d21], sp
    ld h, b
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $60ca
    ld de, $60ea
    call Call_000_339c
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld [c], a
    ld d, a
    xor e
    ld a, a
    dec bc
    xor [hl]
    db $e3
    and [hl]
    rst $20
    ld c, a
    ld d, d
    rst $20
    ld d, c
    or l
    call nc, $d4b5
    rst $20
    ld a, a
    cp d
    sbc $c5
    ld a, a
    call nz, $dbba
    inc sp
    ld c, a
    or c
    or e
    ld a, a
    call nz, Call_018_56ca
    rst $20
    ld d, c
    ld d, d
    ld d, [hl]
    ld c, a
    cp h
    ld [c], a
    or e
    ret nz

    or d
    ld a, a

jr_018_605c:
    cp e
    jp c, $c0c3

    rst $18
    cp c
    and $51
    cp a
    jp c, $7f33

    ld d, h
    ld a, a
    dec l
    or [hl]
    sbc $c9
    ld c, a
    ld [de], a
    db $e3
    adc a
    jp z, $b17f

    jp nz, $dfcf

    ret nz

    or [hl]
    rst $20
    ld d, c
    or l
    jp c, $c57f

    sbc $b6
    ld c, a
    db $d3
    or e
    ld a, a
    ld a, [$bcf6]
    pop hl
    reti


    or d
    ld a, a
    jp nz, $cfb6

    or h
    ret nz

    ld l, $e7
    ld d, c
    ret nc

    pop bc
    ld a, a
    or d
    rst $18
    ld c, b
    sbc $7f
    pop bc
    ld h, $b3
    ld a, a
    jr nc, jr_018_605c

    inc sp

jr_018_60a4:
    ld c, a
    call nz, $d9da
    ld a, a
    ld d, h
    db $d3
    ld a, a
    pop bc

jr_018_60ad:
    ld h, $b3
    ld l, $e7
    ld d, c
    pop bc
    ldh [$de], a
    call nz, $b87f
    cp e
    pop de
    rst $10
    ld a, a
    jp z, $dfb2

    jp $bb4f


    ld h, $bc
    jp $d07f


    db $db
    rst $20
    ld d, a
    db $ed
    inc l
    adc h
    ld c, a
    rst $20
    ld d, c
    call nz, $b6c6
    cp b
    ld d, [hl]
    ld a, a
    ld d, h
    jp z, $bf4f

    cp d
    cp a
    cp d
    ld a, a
    cp a
    jr nc, jr_018_60a4

    jp Jump_018_7fd9


    sub $b3
    jr nc, jr_018_60ad

    rst $20
    ld e, b
    db $ed
    inc l
    ld c, l
    ld c, a
    ld c, a
    call z, $d6c5
    or d
    ld a, a
    cp h
    jp $c9d9


    or [hl]
    rst $20
    ld d, c
    db $d3
    rst $18
    call nz, $b67f
    rst $10
    jr nc, jr_018_6152

    or a
    ret nz

    or h
    ret nz

    ld a, a
    adc $b3
    ld h, $7f
    or d
    or d
    ld l, $e7
    ld e, b
    db $ed
    dec h
    xor a
    ld l, c
    or c
    or d
    daa
    ret c

    ret


    ld a, a
    jp nc, Jump_000_2cb2

    sbc $26
    ld c, a
    call z, $c6c8
    ld a, a
    ret


    rst $18
    jp $dfd9


    jp $b27f


    or e
    ld a, a
    or [hl]
    rst $10
    sub $51
    or c
    rst $18
    jp $d07f


    ret nz

    rst $10
    ld c, a
    cp d
    jp c, Jump_018_7f26

    ret nz

    jr nc, @-$35

    ld a, a
    call z, $d6c5
    or d
    ld a, a
    or l
    call nc, $e72c
    ld d, c
    inc sp
    db $d3
    ld a, a
    cp d
    ret


jr_018_6152:
    ld a, a
    call c, $262b
    ld c, a
    rst $08
    ret nz

    ld a, a
    jp nz, $b4b6

    reti


    sbc $30
    sub $c5
    db $e3
    rst $20
    ld d, c
    or l
    rst $08
    or h
    db $d3
    ld a, a
    or c
    rst $18
    jp $d07f


    reti


    call nz, $b27f
    or d
    ld l, $e7
    ld c, a
    inc l
    ldh [$e3], a
    ld a, a
    or c
    ld a, [hl-]
    sub $e7
    ld d, a
    inc c
    add hl, bc
    dec bc
    add hl, bc
    nop
    ld h, a
    dec bc
    dec c
    ld [bc], a
    ld h, a
    dec bc
    ld de, $6704
    dec bc
    dec d
    ld b, $67
    dec bc
    add hl, de
    ld [$0b67], sp

jr_018_6197:
    dec e
    ld a, [bc]
    ld h, a
    inc b
    ld [bc], a
    ld [$0c5f], sp
    ld [bc], a
    ld bc, $0461
    inc h
    nop
    ld h, l
    nop
    ld [bc], a
    ld a, [de]
    dec bc
    rlca
    cp $01
    ld bc, $0802
    jr z, @+$01

    ret nc

    ld b, d
    pop hl
    ld bc, $c789
    dec bc
    add hl, bc
    adc e
    rst $00
    dec bc
    dec c
    adc l
    rst $00
    dec bc
    ld de, $c78f
    dec bc
    dec d
    sub c
    rst $00
    dec bc
    add hl, de
    sub e
    rst $00
    dec bc
    dec e
    jr c, jr_018_6197

    inc b
    ld [bc], a
    and b
    rst $00
    inc c
    ld [bc], a
    ld c, c
    rst $00
    inc b
    inc h
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld [de], a
    dec b
    ld de, $0c0c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld [de], a
    dec b
    ld de, $1a0e
    dec c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld c, $18
    dec c
    ld c, $10
    dec c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld c, $10
    dec c
    ld c, $10
    dec c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld [de], a
    inc de
    db $10
    dec c
    ld c, $10
    rrca
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    inc de
    db $10
    inc b
    dec c
    ld c, $18
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
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    inc b
    dec c
    inc c
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    dec c

jr_018_628f:
    inc b
    rrca
    jp nc, $9d62

    ld h, d
    sbc d
    ld h, d
    nop
    sbc [hl]
    ld h, d
    jp Jump_000_3c6c


    ld d, b
    inc c
    ld b, $03
    rla
    ld [$0368], sp
    inc de
    ld b, $68
    inc bc
    rrca
    inc b
    ld l, b
    inc bc
    dec bc
    ld [bc], a
    ld l, b
    inc bc
    rlca
    nop
    ld l, b
    dec b
    dec de
    add hl, bc
    ld e, a
    nop
    nop
    ld e, $c7
    inc bc
    rla
    inc e
    rst $00
    inc bc
    inc de
    ld a, [de]
    rst $00
    inc bc
    rrca
    jr jr_018_628f

    inc bc
    dec bc
    ld d, $c7
    inc bc
    rlca
    dec [hl]
    rst $00
    dec b
    dec de
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    ld [de], a
    dec b
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    add hl, de
    dec b
    dec b
    ld de, $040e
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
    inc b
    inc [hl]
    dec c
    inc c
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    ld [bc], a
    inc c
    dec c
    rlca
    ld a, [bc]
    xor d
    ld h, h
    inc sp
    ld h, e
    ld a, [de]
    ld h, e
    nop
    ld [hl], h
    ld h, h
    call Call_000_3c6c
    ld hl, $633d
    ld de, $632d
    ld a, [$d596]
    call Call_000_31a8
    ld [$d596], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld d, [hl]
    ld h, e
    ld a, c
    ld h, e
    sub c
    ld h, e
    cp c
    ld h, e
    ld d, $64

jr_018_633d:
    inc b
    jr nc, @+$80

    rst $10
    jp $eb63


    ld h, e
    call c, $dc63
    ld h, e
    dec b
    jr nc, jr_018_63ca

    rst $10
    jr nz, @+$66

    ld b, d
    ld h, h
    add hl, sp
    ld h, h
    add hl, sp
    ld h, h
    rst $38
    db $ed
    dec h
    ld [c], a
    ld l, d
    or b
    db $d3
    ld a, a
    cp a
    db $db
    cp a
    db $db
    ld a, a
    or l
    call c, $bcd9
    ld c, a
    call z, $c9c8
    ld a, a
    cp h
    pop hl
    rst $18
    ld b, h
    jp nz, $7fc9

    inc l
    or [hl]
    sbc $7f
    jr nc, jr_018_633d

    ld d, a
    db $ed
    dec h
    dec h
    ld l, e
    cp b
    rst $20
    ld c, a
    ld [de], a
    xor h
    add [hl]
    ld a, a
    cp a
    or e
    inc l
    jp z, $d77f

    cp b
    inc l
    ldh [$c8], a
    or h
    ld l, $57
    db $ed
    dec h
    ld d, a
    ld l, e
    ld a, a
    or a
    db $d3
    pop bc
    ld a, a
    call c, $b2d9
    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    call z, $d6c5
    or d
    ld a, a
    cp h
    ret nz

    ret


    inc sp
    ld c, a
    or [hl]
    ld l, $c6
    ld a, a
    or c
    ret nz

    rst $18
    jp $ded9


    inc sp
    cp l
    ld d, [hl]
    ld d, a
    ld [$3d21], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    sbc a
    ld l, e
    or e
    rst $20
    ld a, a

jr_018_63ca:
    ld d, c
    call z, $c9c5
    ret c

    ret


    ld a, a
    or l
    jp c, $7fc4

    cp h
    ld [c], a
    or e
    inc a
    jr nc, @-$17

    ld d, a
    db $ed
    dec h
    scf
    ld l, h
    push bc
    ld c, a
    dec sp
    rst $18
    cp b
    ret c

    ld a, a
    cp h
    ret nz

    ld l, $58
    db $ed
    dec h
    rst $08
    ld l, e
    ld a, a
    cp d
    ret


    ld a, a
    cp [hl]
    or [hl]
    or d
    add $4f
    ld d, h
    jp z, Jump_000_2e7f

    sbc $3c
    inc sp
    ld a, a
    inc [hl]
    ret


    cp b
    rst $10
    or d
    ld d, l
    cp h
    pop hl
    reti


    or d
    ld h, $7f
    or c
    reti


    call nz, $b57f
    db $d3
    or e
    or [hl]
    and $57
    ld [$4921], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld h, d
    ld l, h
    ld a, $b3
    dec l
    rst $20
    ld c, a
    ret


    rst $18
    jp $7fc3


    call z, $d6c5
    or d
    ld a, a

jr_018_6433:
    cp h
    push bc
    or d
    or [hl]
    and $57
    db $ed
    dec h
    ld [$7f6c], a
    cp h
    ret nz

    or [hl]
    ld e, b
    db $ed
    dec h
    adc l
    ld l, h
    ld a, a
    or l
    call nc, $ca2c
    ld a, a
    ld d, h
    jp z, $f74f

    or $f6
    cp h
    pop hl
    reti


    or d
    ld a, a
    or d
    reti


    call nz, $b27f
    rst $18
    jp $26c0


    ld d, l
    or l
    jp c, Jump_018_7fca

    cp a
    jp c, $b27f

    inc l
    ld [c], a
    or e
    ld a, a
    jr nc, jr_018_6433

    ld a, a
    or l
    db $d3
    or e
    ld d, a
    inc hl
    ld [bc], a
    ld b, $0d
    nop
    ld h, c
    rlca
    dec c
    nop
    ld h, c
    nop
    dec b
    inc c
    ld b, $09
    rst $38
    pop de
    ld bc, $0d13
    ld [$ffff], sp
    ld [bc], a
    rlca
    rrca
    dec bc
    rst $38
    rst $38
    inc bc
    inc de
    ld [$ff08], sp
    ret nc

    ld b, h
    call z, Call_000_1301
    inc c
    ld c, $ff
    pop de
    ld b, l
    call z, Call_000_2f02
    rst $00
    ld b, $0d
    cpl
    rst $00
    rlca
    dec c
    inc hl
    inc hl
    ld h, $26
    ld h, $26
    ld h, $26
    ld h, $26
    inc hl
    ld e, $1f
    inc h
    inc h
    inc h
    dec c
    inc c
    inc c
    inc c
    ld e, $1f
    add hl, hl
    daa
    inc b
    inc b
    rrca
    ld de, $0c0c
    jr nz, @+$2b

    inc b
    inc b
    inc b
    inc b
    inc h
    dec c
    inc c
    inc c
    ld hl, $0422
    daa
    inc b
    inc b
    ld bc, $0c0c
    inc c
    jr z, jr_018_64ff

    ld [hl+], a
    inc b
    inc b
    inc b
    dec c
    inc c
    inc c
    inc c
    inc hl
    jr z, jr_018_650e

    dec h
    dec h
    dec h
    dec h
    dec h
    dec h
    dec h
    dec c
    ld [$ef07], sp
    ld h, [hl]

jr_018_64f5:
    nop
    ld h, l
    db $fc
    ld h, h
    nop
    cp c
    ld h, [hl]
    call Call_000_3c6c

jr_018_64ff:
    ret


    ld c, $65
    ld a, [hl+]
    ld h, l
    ld c, d
    ld h, l
    ld l, l
    ld h, l
    sub h
    ld h, l
    call $fa65
    ld h, l

jr_018_650e:
    db $ed
    dec h
    ld a, [$4f6c]
    cp a
    cp d
    ret


    ld a, a
    or a
    ret nc

    ld a, a
    inc l
    ldh [$cf], a
    jr nc, jr_018_64f5

    rst $20
    ld d, l
    inc [hl]
    or d
    ret nz

    ld a, a
    inc [hl]
    or d
    ret nz

    rst $20
    ld d, a
    db $ed
    dec h
    inc sp
    ld l, l
    cp d
    add $7f
    call $c5de
    inc e
    db $e3
    and [hl]
    ld h, $4f
    cp l
    jp $7fc3


    or c
    rst $18
    ret nz

    cp c
    inc [hl]
    ld a, a
    push bc
    sbc $30
    db $db
    or e
    and $57
    db $ed
    dec h
    add h
    ld l, l
    cp h
    cp b
    rst $18
    jp $d27f


    ld h, $7f
    rst $08
    call c, $e7d9
    ld c, a
    ret nz

    ret


    pop de
    ld a, a
    or [hl]
    rst $10
    ld a, a
    or c
    rst $18
    pop bc
    ld a, a
    or d
    rst $18
    jp $dab8


    rst $20
    ld d, a
    db $ed
    dec h
    add $6d

jr_018_6571:
    ld a, a
    cp [hl]
    rst $18
    cp [hl]
    ld d, [hl]
    ld d, c
    or l
    jp c, Jump_018_7fca

    rst $08
    or d
    add $c1
    ld c, a
    add c
    and c
    ret


    ld a, a
    or [hl]
    call c, $b7d1
    jr nc, jr_018_6571

    ld d, l
    cp [hl]
    rst $18
    cp [hl]
    ld a, a
    cp [hl]
    rst $18
    cp [hl]
    ld d, [hl]
    ld d, a
    db $ed
    dec h
    inc h
    ld l, [hl]
    or h
    ld a, [hl-]
    ld a, a
    cp b
    or d
    cp h
    sbc $3e
    or e
    ret


    ld c, a
    add l
    ld a, [de]
    add hl, bc
    xor e
    ld a, a
    cp h
    rst $18
    jp $e6d9


    ld d, c
    or c
    sbc $c5
    add $7f
    sub $b8
    ld a, a
    ret nz

    dec a
    jp $d67f


    cp b
    ld a, a
    ret z

    reti


    ld c, a
    ld d, h
    jp z, $ce7f

    or [hl]
    add $7f
    or d
    push bc
    or d
    sub $e7
    ld d, a
    db $ed
    dec h
    adc e
    ld l, [hl]

jr_018_65d1:
    cp b
    ld a, a
    cp h
    cp b
    cp h
    cp b
    ld d, [hl]
    ld d, c
    or l
    jp c, Jump_018_7fca

    rst $08
    or d
    add $c1
    ld c, a
    adc a
    sbc l
    sub a
    ld b, $c9
    ld a, a
    or [hl]
    call c, $b7d1
    jr nc, jr_018_65d1

    ld d, l
    cp h
    cp b
    cp h
    cp b
    ld a, a
    cp h
    cp b
    cp h
    cp b
    ld d, [hl]
    ld d, a
    ld [$1e21], sp
    ld h, [hl]
    call Call_000_3c79
    ldh a, [$d3]
    bit 7, a
    jr z, jr_018_660c

    ld hl, $6645
    jr jr_018_6618

jr_018_660c:
    bit 4, a
    jr z, jr_018_6615

    ld hl, $6670
    jr jr_018_6618

jr_018_6615:
    ld hl, $6691

jr_018_6618:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    add hl, de
    ld e, c
    sbc $e7
    ld c, a
    call c, $bcc0
    ld h, $7f
    cp d
    cp d
    ret


    ld a, a
    adc e
    db $eb
    sbc e
    inc sp
    cp l
    rst $20
    ld d, c
    or a
    ld [c], a
    or e
    ret


    ld a, a
    and b
    add c
    xor e
    ld a, a
    ld [de], a
    or b
    xor h
    adc e
    xor [hl]
    jp z, $ed58

    dec hl
    ld b, l
    ld e, c
    rst $10
    jp nc, $7fc9

    sbc a
    sub l
    add e
    and [hl]
    rst $20
    ld d, c
    cp h
    or [hl]
    cp h
    ld a, a
    or l
    or a
    ldh [$b8], a
    cp e
    sbc $c6
    ld c, a
    rst $08
    ret nz

    ld a, a
    cp e
    or [hl]
    push bc
    and $7f
    call nz, $b27f
    call c, $bfda
    or e
    jr nc, @+$59

    db $ed
    dec hl
    jp nc, $c959

    ld a, a
    cp h
    or l
    call nc, $e7b7
    ld d, c
    ld d, [hl]
    inc l
    ldh [$7f], a
    or l
    or a
    ldh [$b8], a
    ld a, a
    cp e
    sbc $c6
    ld c, a
    or l
    cp d
    rst $10
    jp c, $b6d9

    and $57
    db $ed
    dec hl
    ld d, $5a
    ld a, a
    sbc e
    or b
    and a
    ret


    ld a, a
    adc h
    sub d
    db $e3
    add [hl]
    rst $20
    ld d, c
    inc sp
    db $d3
    ld a, a
    dec hl
    or d
    ret c

    ld [c], a
    or e
    ld c, a
    add $de
    dec l
    or e
    ld a, a
    inc a
    sbc $7f
    or c
    rst $18
    ret nz

    or [hl]
    push bc
    and $57
    inc c
    ld bc, $0600
    ld a, [bc]
    ld e, a
    nop
    rlca
    inc d
    inc c
    dec b
    cp $01
    ld bc, $0c14
    add hl, bc
    cp $01
    ld [bc], a
    inc d
    dec bc
    dec c
    cp $01
    inc bc
    inc d
    ld a, [bc]
    ld de, $ffff
    inc b
    inc d
    inc c
    ld de, $ffff
    dec b
    inc d
    ld c, $11
    rst $38
    rst $38
    ld b, $14
    ld de, $ff0f
    pop de
    rlca
    ld sp, hl
    add $00
    ld b, $0a
    ld a, [bc]
    ld a, [bc]
    add hl, bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld b, $0b
    ld b, $0b
    ld b, $35
    dec bc
    ld a, [hl+]
    dec bc
    ld a, [hl+]
    dec bc
    ld a, [hl+]
    dec [hl]
    dec bc
    ld a, [hl+]
    dec bc
    ld a, [hl+]
    dec bc
    ld a, [hl+]
    dec [hl]
    dec bc
    inc l
    dec bc
    inc l
    dec bc
    inc l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec hl
    dec l
    dec hl
    dec l
    dec hl
    dec l
    dec hl
    dec c
    inc b
    inc bc
    add a
    ld l, c
    ld b, l
    ld h, a
    inc sp
    ld h, a
    nop
    ld l, a
    ld l, c
    call Call_018_6739
    jp Jump_000_3c6c


Call_018_6739:
    ld a, [$d782]
    bit 1, a
    ret nz

    ld hl, $d6ac
    set 5, [hl]
    ret


    ld c, e
    ld h, a
    inc l
    ld l, c
    ld b, d
    ld l, c
    ld [$82fa], sp
    rst $10
    bit 0, a
    jr nz, jr_018_677c

    ld hl, $6785
    call Call_000_3c79
    ld hl, $6817
    call Call_000_3c79
    ld bc, $c401
    call Call_000_3e5e
    jr nc, jr_018_6774

    ld hl, $68ab
    call Call_000_3c79
    ld hl, $d782
    set 0, [hl]
    jr jr_018_6782

jr_018_6774:
    ld hl, $6919
    call Call_000_3c79
    jr jr_018_6782

jr_018_677c:
    ld hl, $68c7
    call Call_000_3c79

jr_018_6782:
    jp Jump_000_0f6a


    nop
    ld a, a
    and e
    pop bc
    ret nc

    call nc, $c9c1
    adc $9a
    and c
    ret z

    ld a, a
    ld d, [hl]
    add c
    db $d3
    push bc
    ld c, a
    pop bc
    db $d3
    ret


    jp $7fcb


    ret


    db $d3
    ld a, a
    sub $c5
    jp nc, Jump_018_7fd9

    ret nc

    pop bc
    ret


    ld d, l
    adc $c6
    push de
    call z, Call_018_567f
    adc [hl]
    and c
    adc $c4
    add c
    ld d, c
    db $ec
    jr nz, @+$6a

    ld c, a
    cp [hl]
    push bc
    or [hl]
    db $dd
    ld a, a
    cp e
    cp l
    rst $18
    jp $b17f


    add hl, hl
    ret nz

    rst $20
    ld d, c
    cp l
    ret c

    cp l
    ret c

    ld d, [hl]
    ld a, a
    cp l
    ret c

    cp l
    ret c

    ld d, [hl]
    ld c, a
    cp l
    ret c

    cp l
    ret c

    ld d, [hl]
    ld a, a
    cp l
    ret c

    cp l
    ret c

    ld d, [hl]
    ld d, b
    ld [$effa], sp
    ret nz

    cp $1f
    ld [$c0f0], a
    jr nz, jr_018_67f8

    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld a, $02
    ld [$c0ef], a

jr_018_67f8:
    ld a, $e8
    ld [$c0ee], a
    call Call_000_0e45

jr_018_6800:
    ld a, [$c026]
    cp $e8
    jr z, jr_018_6800

    call Call_000_0d9b
    ld hl, $d782
    set 1, [hl]
    ld hl, $d6ac
    res 5, [hl]
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld a, [hl]
    ld e, d
    ld [c], a
    or e
    ld [hl], d
    call z, Call_018_52b3
    ld a, a
    jp nc, $c2d5

    ld a, a
    call nc, $c5c8
    ld a, a
    jp nz, $c3c1

    ld c, a
    bit 7, a
    add $cf
    jp nc, $d47f

    ret z

    push bc
    ld a, a
    and e
    pop bc
    ret nc

    call nc, $c9c1
    adc $55
    ld a, a
    add c
    db $d3
    push bc
    call z, $8cc9
    ld d, [hl]
    adc [hl]
    ld a, a
    db $d3
    push bc
    call z, $7fc9
    db $d3
    ld d, l
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    add $7f
    jp nc, $c2d5

    jp nz, $cec9

    rst $00
    ld a, a
    ld d, l
    ld d, [hl]
    db $d3
    push bc
    call z, $8cc9
    ld d, [hl]
    adc [hl]
    ld a, a
    db $d3
    push bc
    call z, $7fc9
    db $d3
    ld d, l
    rst $08
    push de
    adc $c4
    ld a, a
    rst $08
    add $7f
    jp nc, $c2d5

    jp nz, $cec9

    rst $00
    ld a, a
    ld d, l
    ld d, [hl]
    ld d, c
    db $ec
    rst $18
    ld h, a
    ld d, b
    jp c, $7fdd

    or a
    ret nc

    ret


    ld a, a
    ld c, a
    ld d, h
    add $7f
    or l
    cp h
    or h
    jp c, Jump_018_553a

    or d
    jp nz, $d333

    ld a, a
    or d
    or c
    or d
    daa
    ret c

    ld h, $7f
    ret nc

    jp c, $e7d9

    ld e, b
    db $ed
    dec hl
    xor h
    ld e, e
    cp [hl]
    sbc $c1
    ld [c], a
    or e
    ld a, a
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
    ld de, $ed50
    dec hl
    ei
    ld e, e
    ld [c], a
    or e
    ld [hl], d
    ld d, [hl]
    call z, $e7b3
    ld d, c
    rst $10
    cp b
    add $7f
    push bc
    rst $18
    ret nz

    cp h
    ld d, [hl]
    ld c, a
    cp a
    db $db
    cp a
    db $db
    ld a, a
    inc l
    or [hl]
    sbc $30
    rst $20
    ld d, c
    db $d3
    or e
    cp l
    jr z, jr_018_696c

    adc d
    xor e
    sub e
    ld [hl], h
    add b
    xor e
    sub [hl]
    jp z, $bc4f

    pop hl
    rst $18
    ld b, h
    jp nz, $bd7f

    reti


    sub $e7
    ld d, c
    rst $08
    ret nz

    ld a, a
    add a
    sub b
    add hl, de
    add $7f
    cp b
    reti


    ld a, a
    call nz, $cfb7
    inc sp
    ld c, a
    ld a, [hl+]

jr_018_6912:
    or a
    add hl, hl
    sbc $d6
    or e
    rst $20
    ld d, a
    db $ed
    dec hl
    ret c

    ld e, e
    db $e3
    rst $20
    ld c, a
    add $d3
    jp nz, Jump_018_7f26

    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_018_6912

    ld d, a
    db $ed
    dec h
    inc e
    ld l, a
    ret c

    ld a, a
    ret nc

    push bc
    or d
    adc $b3
    ld h, $4f
    or d
    or d
    ld a, a
    ret nc

    ret nz

    or d
    jr nc, jr_018_6997

    ld d, a
    db $ed
    dec h
    ld a, $6f
    or d
    ld a, a
    cp h
    push bc
    or d
    ld c, a
    call z, $c9c5
    ret c

    ld a, a
    add $e1
    or e
    db $d3

jr_018_6955:
    sbc $56
    ld d, l
    ld d, [hl]
    cp d
    jp c, Jump_018_55ca

    cp [hl]
    sbc $c1
    ld [c], a

jr_018_6961:
    or e
    ld h, $7f
    sub $de
    inc sp
    or d
    reti


    ld a, a
    adc $de

jr_018_696c:
    jr nc, jr_018_6955

    ld d, a
    inc c
    ld bc, $0007
    ld [$0260], sp
    ld bc, $0204

jr_018_6979:
    ld [bc], a
    ld bc, $0103
    ld l, $06
    ld [$d1ff], sp
    ld bc, $c70d
    rlca
    nop
    jr nc, jr_018_69ba

    cpl
    ld [hl-], a
    inc sp
    rlca
    dec bc
    dec bc
    rlca
    ld l, $0b
    dec bc
    dec c
    ld [$b30c], sp

jr_018_6997:
    ld l, h
    cp b
    ld l, c
    sbc a
    ld l, c
    nop
    inc [hl]
    ld l, h
    call Call_000_3c6c
    ld hl, $69ce
    ld de, $69b2
    ld a, [$d587]
    call Call_000_31a8
    ld [$d587], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    rst $38
    ld l, c

jr_018_69ba:
    ld d, c
    ld l, d
    xor b
    ld l, d
    ld b, $6b
    ld [hl], b
    ld l, e
    sbc b
    ld l, e
    or [hl]
    ld l, e
    ret nc

    ld l, e
    rst $20
    ld l, e
    push bc
    rrca
    rlca
    ld l, h
    ld bc, $8420
    rst $10
    add hl, bc
    ld l, d
    ld a, [hl-]
    ld l, d
    jr nc, @+$6c

    jr nc, jr_018_6a44

    ld [bc], a
    jr nc, jr_018_6961

jr_018_69dd:
    rst $10
    ld e, e
    ld l, d
    adc h
    ld l, d
    ld a, c
    ld l, d
    ld a, c
    ld l, d
    inc bc
    jr nz, @-$7a

    rst $10
    or d
    ld l, d
    call c, $cb6a
    ld l, d
    bit 5, d
    inc b
    jr nz, jr_018_6979

    rst $10
    db $10
    ld l, e

jr_018_69f8:
    ccf
    ld l, e
    inc l
    ld l, e
    inc l
    ld l, e
    rst $38
    ld [$ce21], sp
    ld l, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    inc l
    ld [hl], c
    jp z, $c07f

    dec sp
    dec sp
    call nz, $e756
    ld d, c
    ret nz

    dec sp
    cp e
    or a
    inc sp
    ld a, a
    call nz, $c0df
    ld a, a
    ld d, h
    ld a, a
    jr nc, jr_018_69dd

    ld h, $4f
    call c, $bcc0
    ret


    ld a, a
    call nz, Call_000_30d3
    pop bc
    ld d, a
    db $ed
    dec h
    cp b
    ld [hl], c

jr_018_6a34:
    db $d3
    jr nc, jr_018_69f8

    ld h, $56
    ld e, b
    db $ed
    dec h
    ld a, e
    ld [hl], c
    rst $20
    ld c, a
    call nz, Call_000_30d3
    pop bc

jr_018_6a44:
    jp z, $307f

    or d
    inc l
    add $7f
    cp h
    push bc
    cp e
    or d
    rst $20
    ld d, a
    ld [$da21], sp
    ld l, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    jp nc, $d071

    jp z, Jump_018_7fe6

    jr nc, jr_018_6a34

    rst $18
    jp $ca7f


    or d
    rst $18
    jp $bc4f


    jp nz, $b2da

    push bc
    ld a, a
    cp d
    inc [hl]
    db $d3
    jr nc, @-$17

    ld d, a
    db $ed
    dec h
    ld [hl], d
    ld [hl], d
    ld c, a
    jp c, $27b2

    db $dd
    ld a, a
    cp h
    rst $10
    sbc $d6
    ld a, a
    or a
    ret nc

    jp z, $ed58

    dec h
    inc e
    ld [hl], d
    jp z, $cb7f

    call nz, $33d8
    ld a, a
    or d
    ret nz

    or d
    sbc $30
    ld c, a
    inc sp
    jp $b27f


    rst $18
    jp $b87f


    jp c, Jump_018_57e7

    ld [$e621], sp

jr_018_6aab:
    ld l, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    xor l
    ld [hl], d
    ld a, a
    ld d, h
    ld a, a
    jr nc, @-$4c

    cp l
    or a
    jr nc, @-$17

    ld c, a
    or a
    ret nc

    db $d3
    ld a, a
    ld d, h
    ld a, a
    call nc, $c9d9
    rst $20
    ld d, a
    db $ed
    dec h
    ld c, b
    ld [hl], e
    rst $20
    ld c, a
    jp nz, $b2d6

    sbc $30
    ld a, a
    or a
    ret nc

    rst $18
    jp $ed58


    dec h
    sbc $72
    rst $20
    ld c, a
    ld a, $b8
    call nz, $c47f
    db $d3
    jr nc, jr_018_6aab

    add $7f
    push bc
    rst $18
    jp $e7d6


    ld d, c
    cp a
    jp c, $c833

    rst $20
    ld c, a
    ld d, h
    ld a, a
    cp d
    or e
    or [hl]
    sbc $c4
    or [hl]
    ld a, a
    cp h
    sub $b3
    sub $57
    ld [$f221], sp
    ld l, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld l, d
    ld [hl], e
    ld h, $7f
    cp [hl]
    or [hl]
    or d
    ld a, a
    inc l
    pop hl
    or e
    or [hl]
    rst $10
    ld c, a
    or c
    jp nz, $c0d2

    ld a, a
    ld d, h
    ld a, a
    ret nc

    jp $e7e3


    ld d, a
    db $ed
    dec h
    ld a, [hl+]
    ld [hl], h
    sbc $e7
    ld c, a
    cp [hl]
    or [hl]
    or d
    ret


    ld a, a
    ld d, h
    ld a, a
    push bc
    ret


    add $56
    ld e, b
    db $ed
    dec h
    and a
    ld [hl], e
    rst $20
    ld a, a
    call c, $bcc0
    ret


    ld c, a
    ld d, h
    ld a, a
    cp d
    sbc $c5
    add $7f
    cp h
    pop bc
    ldh [$df], a
    jp $51e7


    ld d, h
    ld a, a
    adc l
    xor e
    adc a
    db $e3
    inc sp
    ld c, a
    add hl, hl
    sbc $b7
    add $7f
    cp h
    jp $c3b7


    ld a, a
    adc $bc
    or d
    call c, Call_018_57e7
    db $ed
    dec h
    and e
    ld l, a
    inc e
    db $e3
    add c
    cp e
    sbc $e7
    ld c, a
    call c, $bcc0
    ld a, a
    adc b
    db $e3
    add [hl]
    ld h, $7f
    ret nz

    dec a
    ret nz

    or d
    ret


    ld d, l
    sbc [hl]
    and [hl]
    sbc e
    or b
    db $e3
    and e
    db $dd
    ld a, a
    or l
    ret z

    ld h, $b2
    rst $20
    ld d, a
    db $ed
    dec h
    rst $38
    ld l, a
    ld a, a
    or [hl]
    or d
    ld h, $b2
    ld a, a
    ret c

    ld [c], a
    cp d
    or e
    ld a, a
    push bc
    sbc $c3
    ld c, a
    push de
    or e
    ld h, $33
    ld a, a
    or d
    or d
    sub $e3
    rst $20
    ld d, a
    db $ed
    dec h
    ld b, a
    ld [hl], b
    call nz, Call_018_427f
    add a
    ret c

    xor e
    jp z, Jump_000_2d4f

    db $e3
    rst $18
    call nz, $b27f
    rst $18
    cp h
    ld [c], a
    ld a, a
    push bc
    ret


    rst $20
    ld d, a
    db $ed
    dec h
    ld l, [hl]
    ld [hl], b
    xor e
    ld [hl], d
    ld b, [hl]
    or e
    ld a, a
    ld b, [hl]
    ld b, [hl]
    or e
    db $e3
    ld d, b
    ld [$653e], sp
    call Call_000_2dc7
    jp Jump_000_0f6a


    db $ed
    dec h
    ld a, h
    ld [hl], b
    cp h
    ld a, a
    cp d
    inc [hl]
    db $d3
    ld a, a
    ret nz

    pop bc
    call nz, $be4f
    or [hl]
    or d
    db $dd
    ld a, a
    rst $08
    call c, $c3df
    ld a, a
    rst $08
    cp l
    ret


    ld a, a
    or l
    adc $ce
    ld d, a
    db $ed
    dec h
    ret z

    ld [hl], b
    rst $20
    ld c, a
    call c, $bcc0
    jp z, $ba7f

    cp b
    cp e
    or d
    ld a, a
    cp c
    or d
    cp e

jr_018_6c1a:
    jp nz, $51e7

    ld e, [hl]
    ret


    ld a, a
    call c, Call_000_30d9
    cp b
    ret nc

    db $dd
    ld c, a
    or l
    rst $18
    jp $b27f


    reti


    ld a, a
    call nz, $dbba
    jr nc, jr_018_6c1a

    ld d, a
    inc c
    ld b, $00
    nop
    ld [bc], a
    ld e, a
    nop
    ld a, [bc]
    inc bc
    ld e, a
    nop
    inc d
    inc b
    ld e, a
    ld a, [bc]
    nop
    dec b
    ld e, a
    ld a, [bc]
    ld a, [bc]
    ld b, $5f
    ld a, [bc]
    inc d
    rlca
    ld e, a
    nop
    dec bc
    db $10
    rlca
    ld b, $ff
    jp nc, $f141

    ld bc, $0810
    rrca
    rst $38
    pop de
    ld b, d
    pop af
    ld [bc], a
    inc b
    ld [de], a
    rrca
    rst $38
    pop de
    ld b, e
    ret


    ld [$0f06], sp
    ld de, $d2ff
    ld b, h
    rrc e
    dec c
    rlca
    ld a, [de]
    cp $01
    dec b
    ld a, [bc]
    ld [de], a
    inc b
    rst $38
    rst $38
    ld b, $08
    rrca
    ld b, $ff
    ret nc

    rlca
    jr c, jr_018_6c93

    rlca
    rst $38
    ret nc

    ld [$110d], sp
    ld c, $ff
    db $d3
    add hl, bc
    dec a
    inc de
    db $10
    rst $38
    rst $38

jr_018_6c93:
    adc d
    ret nc

    db $10
    ld de, $fe19
    ld [bc], a
    dec bc
    ei
    add $00
    nop
    nop
    rst $00
    nop
    ld a, [bc]
    dec b
    rst $00
    nop
    inc d
    ld d, l
    rst $00
    ld a, [bc]
    nop
    ld e, d
    rst $00
    ld a, [bc]
    ld a, [bc]
    ld e, a
    rst $00
    ld a, [bc]
    inc d
    add hl, bc
    ld a, [bc]
    inc c
    inc c
    inc c
    add hl, bc
    ld a, [bc]
    inc c
    inc c
    inc c
    add hl, bc
    ld a, [bc]
    dec bc
    dec bc
    inc c
    inc c
    inc c
    dec bc
    dec bc
    inc c
    inc c
    inc c
    dec bc
    dec bc
    ld b, $36
    inc c
    inc c
    inc c
    ld b, $36
    inc c
    inc c
    inc c
    ld b, $36
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c
    inc c

jr_018_6ced:
    inc c
    inc c
    add hl, bc
    ld a, [bc]
    inc c
    inc c
    inc c
    add hl, bc
    ld a, [bc]
    inc c
    inc c
    inc c

jr_018_6cf9:
    add hl, bc
    ld a, [bc]
    dec bc
    dec bc
    inc c
    inc c
    inc c
    dec bc
    dec bc
    inc c
    inc c
    inc c

jr_018_6d05:
    dec bc
    dec bc
    ld b, $36
    inc c
    inc c
    inc c
    ld b, $36
    inc c
    inc c
    inc c
    ld b, $36
    dec c
    ld [$c00c], sp
    ld b, e
    ld a, $6d
    rra
    ld l, l
    nop
    ld c, [hl]
    ld [hl], b
    ld a, $01
    ld [$cf07], a
    xor a
    ld [$cc3c], a
    ld hl, $6d58
    ld de, $6d38
    ld a, [$d588]
    call Call_000_31a8
    ld [$d588], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    adc c
    ld l, l
    pop hl
    ld l, l
    inc sp
    ld l, [hl]
    adc b
    ld l, [hl]
    jp nc, $c56e

    rrca
    dec hl
    ld l, a
    ld e, d
    ld l, a
    push bc
    rrca
    add e
    ld l, a
    call nz, $f56f
    ld l, a
    jr z, jr_018_6dc8

    ld bc, $8620
    rst $10
    sub e
    ld l, l
    call nz, $b06d
    ld l, l
    or b
    ld l, l
    ld [bc], a
    jr nc, jr_018_6ced

    rst $10
    db $eb
    ld l, l
    inc c
    ld l, [hl]
    ld [bc], a
    ld l, [hl]
    ld [bc], a
    ld l, [hl]
    inc bc
    jr nc, jr_018_6cf9

    rst $10
    dec a
    ld l, [hl]
    ld l, l
    ld l, [hl]
    ld h, e
    ld l, [hl]
    ld h, e
    ld l, [hl]
    inc b
    jr nz, jr_018_6d05

    rst $10
    sub d
    ld l, [hl]
    cp e
    ld l, [hl]
    or c
    ld l, [hl]
    or c
    ld l, [hl]
    rst $38
    ld [$5821], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld e, h
    ld [hl], h
    ret


    ld a, a
    call nz, $7fc9
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    cp d
    cp a
    ld c, a
    inc l
    sbc $be
    or d
    ret


    ld a, a
    ret nz

    ret


    cp h
    ret nc

    rst $20
    ld d, a
    db $ed
    dec h
    ld a, [bc]
    ld [hl], l
    cp h
    ld [c], a
    or e
    inc a
    rst $20

jr_018_6db9:
    ld c, a
    call c, Call_000_26b6
    or h
    reti


    ld a, a
    sub $b3
    jr nc, jr_018_6e1c

    db $ed
    dec h
    adc a
    ld [hl], h

jr_018_6dc8:
    sbc $7f
    rst $08
    or h
    ld a, a
    push bc
    rst $10
    ld c, a
    call c, $bcc0
    ld h, $7f
    or [hl]
    rst $18
    jp $b27f


    ret nz

    ld a, a
    jr nc, jr_018_6db9

    or e
    rst $20
    ld d, a
    ld [$6421], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld d, c
    ld [hl], l
    ld a, a
    jp nz, $c0df

    ld c, a
    inc l
    rst $08
    sbc $c9
    ld a, a
    cp e
    or [hl]
    push bc
    db $dd
    ld a, a
    ret nc

    db $db
    rst $20
    ld d, a
    db $ed
    dec h
    or d
    ld [hl], l
    or [hl]
    rst $10
    rst $18
    ld c, b
    rst $20
    ld e, b
    db $ed
    dec h
    ld l, [hl]
    ld [hl], l
    db $e3
    sub d
    or b
    and $51
    cp [hl]
    sbc $2c
    ld [c], a
    or e
    ld a, a
    ld b, b

jr_018_6e1c:
    db $e3
    sub d
    or b
    jp z, $d34f

    or e
    ld a, a
    or l
    call c, $c0df
    ld a, a
    cp d
    db $db
    ld a, a
    inc l
    ldh [$c5], a
    or d
    or [hl]
    push bc
    ld d, a

jr_018_6e33:
    ld [$7021], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    jp Jump_018_5675


    ld a, a
    jp nz, $b2d6

    ld a, a
    ld d, h
    call nz, $d24f
    dec l
    rst $10
    cp h
    or d
    ld a, a
    ld d, h
    ld d, l
    inc [hl]
    rst $18
    pop bc
    add $7f
    or [hl]
    pop bc
    db $dd
    ld a, a
    or [hl]
    sbc $2c
    reti


    or [hl]
    ret z

    and $57
    db $ed
    dec h
    ld c, h
    db $76
    db $d3
    ret


    jr nc, jr_018_6e33

    rst $20
    ld e, b
    db $ed
    dec h
    rst $38
    ld [hl], l
    jp z, Jump_018_7f56

    jp nc, $d72d

    cp h
    cp b
    jp $c24f


    sub $b2
    ld a, a
    ld d, h
    ld h, $7f
    adc $bc
    or d
    ret z

    or h
    ld d, a
    ld [$7c21], sp
    ld l, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld h, [hl]
    db $76
    cp [hl]
    sbc $2c
    ld [c], a
    or e
    ld a, a
    ld b, b
    db $e3
    sub d
    or b
    inc sp
    jp z, $d04f

    or [hl]
    cp c
    ld a, a
    push bc
    or [hl]
    rst $18
    ret nz

    ld a, a
    cp c
    inc [hl]
    ld d, [hl]
    and $57
    db $ed
    dec h
    inc d
    ld [hl], a
    sbc $7f
    cp h
    jp Jump_018_58d6


    db $ed
    dec h
    sbc [hl]
    db $76
    ld a, a
    jp nz, $b2d6

    ld a, a
    ld d, h
    rst $20
    ld c, a
    or d
    or d
    push bc
    ld d, [hl]
    ld a, a
    or d
    or d
    push bc
    ld d, [hl]
    rst $20
    ld d, a
    ld [$61cd], sp
    scf
    ld hl, $6ee7
    call Call_000_3c79
    call Call_000_376d
    ld a, $84
    call Call_000_34e5
    jp Jump_000_0f6a


    db $ed
    dec hl
    and l
    ld e, h
    ld a, a
    inc l
    pop hl
    or e
    db $dd
    ld a, a
    ret nz

    dec sp
    ld a, a
    cp h
    jp $c0b7


    ld h, $4f
    ret z

    pop de
    rst $18
    jp Jump_000_3a7f


    or [hl]
    ret c

    ret


    ld a, a
    or c
    or d
    jp nz, Jump_018_55dd

    ret nc

    jp nz, $c0b9

    call nz, $cab7
    ld a, a
    adc $de
    call nz, $7fc6
    or c
    or a
    jp c, Jump_018_51c0

    ret nz

    cp h
    or [hl]
    ld d, [hl]
    rst $20
    ld c, a
    cp d
    sbc $c5
    ld a, a
    ld d, h
    ld a, a
    jr nc, @-$1f

    ret nz

    ld e, b
    ld [$3521], sp
    ld l, a
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    dec hl
    ld e, l
    sbc $dd
    ld a, a
    ret


    cp [hl]
    jp $d04f


    dec l
    ret


    ld a, a
    or e
    or h
    ld a, a
    jp z, $d9bc

    ld a, a
    ld d, h
    ld d, l
    ret nc

    ret nz

    cp d
    call nz, $b17f
    reti


    ld a, a
    add b
    and [hl]
    sub $e7
    ld d, a
    ld [$6421], sp
    ld l, a
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld l, b
    ld e, l
    ld a, a
    or a
    ld a, a
    push bc
    rst $10
    ld a, a
    ld d, h
    ret


    ld c, a
    or d
    or c
    or d
    daa
    ret c

    inc sp
    ld a, a
    or a
    ret c

    ret nz

    or l
    cp [hl]
    reti


    ld a, a
    inc l
    ldh [$db], a
    ld d, a
    ld [$8d21], sp
    ld l, a
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    sbc b
    ld e, l
    add a
    ld a, a
    adc e

jr_018_6f94:
    sub d
    or b
    ld a, a
    adc d
    sbc e
    jp hl


    ret c

    ld a, a
    ld c, $e3
    xor e
    ld c, a
    or d
    rst $18
    ret nz

    ld a, a
    cp d
    call nz, $b17f
    reti


    or [hl]
    ret z

    and $51
    or c
    cp a
    cp d
    jp z, $d27f

    dec l
    rst $10
    cp h
    or d
    ld a, a
    ld d, h
    ld h, $4f
    ret nz

    cp b
    cp e
    sbc $7f
    or d
    ret nz

jr_018_6fc2:
    rst $20
    ld d, a
    ld [$ce21], sp
    ld l, a
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld sp, hl
    ld e, l
    ld a, a
    ld a, $b8
    db $d3
    ld c, a
    adc d
    sbc e
    jp hl


    ret c

    ld a, a
    ld c, $e3
    xor e
    ld a, a
    jr nc, jr_018_6f94

    cp l
    or a
    rst $20
    ld d, l
    rst $08
    ret nz

    ld a, a
    or c
    cp a
    dec sp
    add $7f
    or d
    or a
    ret nz

    or d
    push bc
    rst $20
    ld d, a
    ld [$ff21], sp
    ld l, a
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld b, e
    ld e, [hl]
    ld [c], a
    or e
    cp e
    sbc $7f
    ret nc

    ret nz

    sbc $30
    cp c
    inc [hl]
    ld c, a
    jr z, jr_018_6fc2

    or d
    ld a, a
    call c, $b2d9
    rst $18
    jp $cf55


    rst $18
    cp e
    or l
    push bc
    ld a, a
    or [hl]
    or l
    ld a, a
    cp h
    jp $d6c0


    rst $20
    ld d, a
    ld [$3221], sp
    ld [hl], b
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld a, h
    ld e, [hl]
    or e
    ld a, a
    or l
    or l
    or d
    ld a, a
    rst $10
    cp h
    or d
    call c, Call_018_4fe7
    call z, $d6c5
    or d
    ld a, a
    cp l
    reti


    ld a, a
    set 0, h
    rst $20
    ld d, a
    inc c
    inc c
    dec b
    ld [bc], a
    nop
    ld h, b
    dec b
    inc bc
    nop
    ld h, b
    dec b
    inc c
    ld bc, $0560
    dec c
    ld bc, $0560
    ld d, $02
    ld h, b
    dec b
    rla
    ld [bc], a
    ld h, b
    rrca
    ld [bc], a
    inc bc
    ld h, b
    rrca
    inc bc
    inc bc
    ld h, b
    rrca
    inc c
    inc b
    ld h, b
    rrca
    dec c
    inc b
    ld h, b
    rrca
    ld d, $05
    ld h, b
    rrca
    rla
    dec b
    ld h, b
    nop
    dec c
    db $10
    ld b, $0e
    rst $38
    db $d3
    ld b, c
    pop af
    inc bc
    cpl
    ld [$ff11], sp
    jp nc, $d642

    ld bc, $1210
    inc b
    rst $38
    db $d3
    ld b, e
    pop af
    dec b
    ld b, $0f
    ld b, $ff
    ret nc

    ld b, h
    rrc h
    db $10

jr_018_70a3:
    ld b, $05
    rst $38
    ret nc

jr_018_70a7:
    dec b
    dec a
    dec b
    db $10
    rst $38
    rst $38
    add [hl]
    ld d, c
    db $10
    ld b, $19
    rst $38
    ret nc

    rlca
    dec h
    dec b
    ld a, [de]
    rst $38
    ret nc

    ld [$103d], sp
    inc b
    rst $38
    rst $38
    adc c
    jr z, @+$12

    db $10
    db $10
    rst $38
    ret nc

    ld a, [bc]
    dec [hl]
    ld [de], a
    rrca
    rst $38
    rst $38
    dec bc
    dec e
    db $10
    ld a, [de]
    rst $38
    jp nc, Jump_000_0f0c

    db $10
    jr @+$01

    db $d3
    dec c
    jr nz, jr_018_70a3

jr_018_70dc:
    dec b
    ld [bc], a
    jr nz, jr_018_70a7

    dec b
    inc bc
    dec h
    rst $00
    dec b
    inc c
    dec h
    rst $00

jr_018_70e8:
    dec b
    dec c
    ld a, [hl+]
    rst $00
    dec b
    ld d, $2a
    rst $00
    dec b
    rla
    ld a, d
    rst $00

jr_018_70f4:
    rrca
    ld [bc], a
    ld a, d
    rst $00
    rrca
    inc bc
    ld a, a
    rst $00
    rrca
    inc c
    ld a, a
    rst $00

jr_018_7100:
    rrca
    dec c
    add h
    rst $00
    rrca
    ld d, $84
    rst $00
    rrca
    rla
    dec c
    ld [$c00c], sp
    ld b, e
    cpl
    ld [hl], c
    ld d, $71
    nop
    db $f4
    ld [hl], e
    call Call_000_3c6c
    ld hl, $7145
    ld de, $7129
    ld a, [$d5a8]
    call Call_000_31a8
    ld [$d5a8], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    adc [hl]
    ld [hl], c
    rst $10
    ld [hl], c
    ld sp, $8872
    ld [hl], d
    sbc $72
    ld a, [hl+]
    ld [hl], e
    and b
    ld [hl], e
    db $db
    ld [hl], e
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    ld bc, $8820
    rst $10
    sbc b
    ld [hl], c
    ret nz

    ld [hl], c
    xor a
    ld [hl], c
    xor a
    ld [hl], c
    ld [bc], a
    jr nc, jr_018_70dc

    rst $10
    pop hl
    ld [hl], c
    ld [de], a
    ld [hl], d
    ei
    ld [hl], c
    ei
    ld [hl], c
    inc bc
    jr nz, jr_018_70e8

    rst $10
    dec sp
    ld [hl], d
    ld h, b
    ld [hl], d
    ld d, d
    ld [hl], d
    ld d, d
    ld [hl], d
    inc b
    jr nz, jr_018_70f4

    rst $10
    sub d
    ld [hl], d
    cp b
    ld [hl], d
    xor h
    ld [hl], d
    xor h
    ld [hl], d
    dec b
    jr nz, jr_018_7100

    rst $10
    add sp, $72
    dec bc
    ld [hl], e
    ld bc, $0173
    ld [hl], e
    ld b, $30
    adc b
    rst $10
    inc [hl]
    ld [hl], e
    ld a, [hl]
    ld [hl], e
    ld [hl], b
    ld [hl], e
    ld [hl], b
    ld [hl], e
    rst $38
    ld [$4521], sp
    ld [hl], c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    reti


    ld [hl], a
    ret c

jr_018_719d:
    add $4f
    adc b
    xor e
    add l
    jp z, $c27f

    or a
    db $d3
    ret


    jr nc, jr_018_7229

    call nc, $b6d9
    rst $20
    ld d, a
    db $ed
    dec h
    add d
    ld a, b
    ld c, a
    or d
    or d
    ld a, a
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    jr nc, jr_018_719d

    ret nz

jr_018_71bf:
    ld e, b
    db $ed
    dec h
    dec e
    ld a, b
    rst $20
    ld c, a
    ld a, $b3
    dec l
    db $d3
    ld a, a
    call z, $c9c5
    ret c

    add $7f
    push bc

jr_018_71d2:
    rst $10
    sbc $b6
    and $57
    ld [$5121], sp
    ld [hl], c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    xor [hl]
    ld a, b
    cp d
    or d
    rst $20
    ld c, a
    call z, $c9c5
    ret c

    ld a, a
    jr nc, jr_018_71bf

    cp h
    or d
    add $7f
    or [hl]
    cp c
    jp $b67f


    jp nz, $ed57

    dec h
    ld a, [hl]
    ld a, c
    ret c

    ld a, a
    jr nc, jr_018_71d2

    cp h
    or d
    db $d3
    ld c, a
    or l
    rst $08
    or h
    add $ca
    ld a, a
    rst $08
    cp c
    ret nz

    rst $20
    ld e, b
    db $ed
    dec h
    pop af
    ld a, b
    ret


    ld a, a
    ret nc

    push bc
    call nz, $c47f
    or d
    or h
    ld a, [hl-]

jr_018_7220:
    ld c, a
    jp nz, $b5d8

    call nc, $ca2c
    ld a, a
    add hl, hl

jr_018_7229:
    sbc $b7
    ld a, a
    or [hl]
    push bc
    db $e3
    and $57
    ld [$5d21], sp
    ld [hl], c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    and [hl]
    ld a, c
    ret c

    ld a, a
    jr nc, @-$1f

    jp Jump_018_544f


    ld a, a
    jr z, jr_018_7220

    or d
    ld a, a
    db $d3
    rst $18
    jp Jump_000_2ed9


    rst $20
    ld d, a
    db $ed
    dec h
    ld l, $7a
    or [hl]
    ld c, a
    call nc, $2cd9
    ldh [$c8], a
    db $e3
    or [hl]
    ld e, b
    db $ed
    dec h
    jp z, $c179

    ret


    ld a, a
    ld d, h
    jp z, $b34f

    ret nc

    add $7f
    inc sp
    ret nz

    ld a, a
    call nz, $c6b7
    ld d, l
    inc l
    inc a
    sbc $33
    ld a, a
    call nz, $c0df
    ld a, a
    db $d3
    ret


    ld a, a
    ld a, [hl-]
    or [hl]
    ret c

    ld a, a
    jr nc, jr_018_72b5

    ld d, a
    ld [$6921], sp
    ld [hl], c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld b, a
    ld a, d
    or e
    ld a, a
    add hl, hl
    sbc $b7
    push bc
    ld a, a
    cp d
    inc [hl]
    db $d3
    ld c, a
    or l
    jp c, Jump_018_7fca

    cp l
    or a
    jr nc, jr_018_72d7

    rst $20
    ld d, b
    ld d, b
    db $ed
    dec h
    db $ec
    ld a, d
    rst $20
    ld c, a
    rst $08
    cp c
    ret nz

jr_018_72b5:
    ld l, $e7
    ld e, b
    db $ed
    dec h
    ld a, c
    ld a, d
    ld a, a
    ld d, h
    jp z, $cc4f

    or [hl]
    or d
    ld a, a
    call nz, $dbba
    add $7f
    or d
    reti


    or [hl]
    rst $10
    ld d, l
    jp nz, $2bd8

    or l
    inc sp
    ld a, a
    jp nz, $7fd8

jr_018_72d7:
    or c
    add hl, hl
    reti


    sbc $30
    rst $20
    ld d, a
    ld [$7521], sp
    ld [hl], c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    inc b
    ld a, e
    ldh [$e3], a
    rst $20
    ld c, a
    rst $08
    cp c
    ret nz

    rst $10
    ld a, a
    or e
    ret nc

    ld a, a
    add $7f
    or l
    call nz, Call_000_2fbd
    db $e3
    rst $20
    ld d, a
    db $ed
    dec h
    and b
    ld a, e
    call nc, $dad7
    ret nz

    rst $20
    ld e, b
    db $ed
    dec h
    dec a
    ld a, e
    ld a, a
    inc sp
    jp $c4d9


    ld c, a
    ret nz

    rst $08
    db $e3
    add $7f
    add a
    and l
    ld [$547f], sp
    ld h, $55
    push bc
    ld h, $da
    jp $b87f


    reti


    ld l, $57
    ld [$8121], sp
    ld [hl], c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    or [hl]
    ld a, e
    db $d3
    ret


    ld a, a
    call nz, Call_018_7fd3
    call nc, $c9cf
    db $d3
    ret


    ld a, a
    call nz, Call_018_4fd3
    call c, $d7b6
    push bc
    or d
    ld a, a
    cp h
    sbc $b2
    ret c

    ld a, a
    cp e
    sbc $e7
    ld d, c
    call c, $bcc0
    ld h, $7f
    db $d3
    rst $18
    jp $c9d9


    jp z, $b34f

    ret nc

    ret


    db $d3
    ret


    ld a, a
    ld a, [hl-]
    or [hl]
    ret c

    ld a, a
    inc sp
    cp l
    rst $20
    ld d, a
    db $ed
    ld h, $59
    ld b, b
    ld c, a
    jp nz, $7fd8

    ret


    ld h, $bc
    ret nz

    sub $58
    db $ed
    ld h, $00
    ld b, b
    ld a, a
    rst $08
    or [hl]
    cp h
    ret nz

    rst $10
    ld a, a
    jp nz, $3bd8

    call nz, Call_018_4fc9
    jp nz, Jump_000_3bb7

    call nz, $7fc6
    cp h
    sub $b3
    call nz, $b57f
    db $d3
    rst $18
    jp $57c0


    db $ed
    dec h
    ld b, c
    ld [hl], a
    ld a, a
    or c
    or d
    ld a, $b3
    ld a, a
    add hl, bc
    db $e3
    ret c

    add [hl]
    db $e3
    jp z, Jump_000_2a4f

    rst $18
    jp nz, Jump_018_7fb2

    pop bc
    or [hl]
    rst $10
    ld a, a
    db $d3
    pop bc
    rst $20
    ld d, c
    cp l
    ld a, [hl+]
    cp b
    ld a, a
    or l
    db $d3
    or d
    ld a, a
    or d
    call c, $307f
    rst $18
    jp $b64f


    or d
    ret c

    or a
    inc sp
    ld a, a
    or e
    ld a, [hl+]
    or [hl]
    cp [hl]
    reti


    ld l, $e7
    ld d, a
    db $ed
    dec h
    ret


    ld [hl], a
    add [hl]
    db $e3
    ld [hl], d
    ld a, [hl+]
    or l
    db $e3
    ld a, a
    ld a, [hl+]
    ld a, [hl+]
    ld a, [hl+]
    db $e3
    ld d, b
    ld [$293e], sp
    call Call_000_2dc7
    jp Jump_000_0f6a


    inc c
    ld a, [bc]
    dec b
    ld [bc], a
    inc b
    ld h, d
    dec b
    inc bc
    inc b
    ld h, d
    dec b
    inc c
    inc bc
    ld h, d
    dec b
    dec c
    inc bc
    ld h, d
    dec b
    ld d, $02
    ld h, d
    dec b
    rla
    ld [bc], a
    ld h, d
    rrca
    ld [bc], a
    ld bc, $0f62
    inc bc
    ld bc, $0f62
    inc c
    nop
    ld h, d
    rrca
    dec c
    nop
    ld h, d
    nop
    dec bc
    inc de
    ld de, $ff04
    ret nc

    ld b, c
    call z, Call_000_1303
    rrca
    ld b, $ff
    ret nc

    ld b, d
    call z, Call_000_1304
    rlca
    db $10
    rst $38
    jp nc, $cc43

    dec b
    inc de
    ld b, $1a
    rst $38
    ret nc

    ld b, h

jr_018_743e:
    call z, $1306
    ld b, $04
    rst $38
    db $d3
    ld b, l
    call z, Call_000_2f07
    ld [$ff04], sp
    db $d3
    ld b, [hl]
    sub $02
    inc c
    ld de, $ff0e
    db $d3
    rlca
    dec b
    db $10
    rrca
    rst $38
    rst $38
    ld [$063d], sp
    jr @+$01

    rst $38
    adc c
    ld d, b
    dec a
    ld b, $0e
    rst $38
    rst $38
    adc d
    db $f4
    dec a
    rrca
    db $10
    rst $38
    rst $38
    adc e
    ld de, $c720
    dec b
    ld [bc], a
    jr nz, jr_018_743e

    dec b
    inc bc
    dec h
    rst $00
    dec b
    inc c
    dec h
    rst $00
    dec b
    dec c
    ld a, [hl+]
    rst $00
    dec b
    ld d, $2a
    rst $00
    dec b
    rla
    ld a, d
    rst $00
    rrca
    ld [bc], a
    ld a, d
    rst $00
    rrca
    inc bc
    ld a, a
    rst $00
    rrca
    inc c
    ld a, a
    rst $00
    rrca
    dec c
    dec bc
    jr jr_018_74a0

    sbc b
    ld b, c
    xor b
    ld [hl], h

jr_018_74a0:
    and l
    ld [hl], h
    nop
    xor c
    ld [hl], h
    jp Jump_000_3c6c


    ld d, b
    ld bc, $0402
    dec b
    ld [bc], a
    ld b, a
    add hl, hl
    ld [bc], a
    ld [bc], a
    ld c, d
    nop
    nop
    add hl, bc
    rst $00
    inc b
    dec b
    cp h
    rst $00
    add hl, hl
    ld [bc], a
    dec bc
    inc b
    add hl, de
    db $f4
    ld b, c
    call z, $c974
    ld [hl], h
    nop
    call $c374
    ld l, h
    inc a
    ld d, b
    ld bc, $0502
    ld [bc], a
    ld [bc], a
    ld c, l
    ld [bc], a
    cpl
    ld [bc], a
    ld d, b
    nop
    nop
    ld b, a
    rst $00
    dec b
    ld [bc], a
    ld a, $c7
    ld [bc], a
    cpl
    ld de, $1412
    dec b
    ld [hl], l
    ldh a, [$74]
    db $ed
    ld [hl], h
    nop
    pop af
    ld [hl], h
    jp Jump_000_3c6c


    ld d, b
    add hl, de
    ld [bc], a
    dec b
    dec b
    ld [bc], a
    ld l, $1f
    dec h
    ld [bc], a
    ld d, l
    nop
    nop
    add hl, sp
    rst $00
    dec b
    dec b
    sbc e
    ret z

    rra
    dec h
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    inc l
    dec e
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld a, $18
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1d1c
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    jr jr_018_75b1

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    inc e
    dec e
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de

jr_018_75b1:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    ld d, $01
    ld bc, $1801
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    jr jr_018_75ef

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    ld d, $01
    jr jr_018_7603

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de

jr_018_75ef:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $1d1c
    dec e
    dec e
    dec e
    dec e
    dec hl

jr_018_7603:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    ld a, [de]
    ld bc, $0101
    ld bc, $0101
    ld bc, $1d1c
    dec e
    dec e
    dec e
    dec e
    dec hl
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    dec d
    dec d
    dec d
    dec d
    ld d, $01
    ld bc, $0101
    ld bc, $3e01
    jr jr_018_765f

    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    dec d
    dec d
    dec d
    ld d, $01
    ld bc, $1918
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de

jr_018_765f:
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    add hl, de
    dec d
    dec d
    add hl, de
    db $10
    add hl, bc
    add hl, bc
    ret nc

    ld a, e
    ld [hl], $78
    ld a, c
    halt
    adc b
    ld a, e
    call Call_018_768f
    call Call_000_3c6c
    ld hl, $7842
    ld de, $774e
    ld a, [$d5d8]
    call Call_000_31a8
    ld [$d5d8], a
    ret


Call_018_768f:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld hl, $76b3
    call Call_018_76b6
    call Call_018_76e2
    ld a, [$d7b7]
    bit 0, a
    ret nz

    ld a, $20
    ld [$d07c], a
    ld bc, $0603

jr_018_76ae:
    ld a, $17
    jp Jump_000_3e9d


    ld b, $03
    rst $38

Call_018_76b6:
    push hl
    ld hl, $d6be
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    ld c, a
    xor a
    ldh [$e0], a
    pop hl

jr_018_76c2:
    ld a, [hl+]
    cp $ff
    jr z, jr_018_76de

    push hl
    ld hl, $ffe0
    inc [hl]
    pop hl
    cp b
    jr z, jr_018_76d3

    inc hl
    jr jr_018_76c2

jr_018_76d3:
    ld a, [hl+]
    cp c
    jr nz, jr_018_76c2

    ld hl, $d6be
    xor a
    ld [hl+], a
    ld [hl], a
    ret


jr_018_76de:
    xor a
    ldh [$e0], a
    ret


Call_018_76e2:
    ldh a, [$e0]
    and a
    ret z

    ld hl, $d7b7
    set 0, [hl]
    ret


Call_018_76ec:
    ld hl, $771a

jr_018_76ef:
    ld a, [hl+]
    cp $ff
    jr z, jr_018_7700

    push hl
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    pop hl
    jr jr_018_76ef

jr_018_7700:
    ld hl, $7713

jr_018_7703:
    ld a, [hl+]
    cp $ff
    ret z

    push hl
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    pop hl
    jr jr_018_7703

    ld de, $1312
    inc d
    dec d
    ld d, $ff
    ld a, [bc]
    dec bc
    inc c
    dec c
    ld c, $0f
    db $10
    rla
    jr jr_018_76ae

    adc e
    adc h
    adc l
    adc [hl]
    adc a
    sub c
    sub d
    sub e
    sub a
    sbc b
    sbc c
    sbc d
    sbc [hl]
    sbc a
    and b
    and e
    and h
    and l
    and [hl]
    xor e
    xor h
    xor l
    xor [hl]
    xor a
    or b
    or c
    or d
    or a
    cp b
    cp c
    rst $38

Jump_018_7743:
    xor a
    ld [$cd66], a

Jump_018_7747:
    ld [$d5d8], a
    ld [$d97c], a
    ret


    ld e, d
    ld [hl], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    jp hl


    ld [hl], a
    ld [de], a
    ld a, b
    and [hl]
    ld [hl], a
    ld a, [$d7b7]
    bit 7, a
    ret nz

    ld hl, $7790
    call Call_000_3509
    jp nc, Jump_000_3261

    ld a, [$cd3d]
    ld [$cf08], a
    xor a
    ldh [$b4], a
    ld a, $f0
    ld [$cd66], a
    ld a, $03
    ldh [$8c], a
    call Call_000_13f1
    ld a, $03
    ldh [$8c], a
    call Call_000_358b
    ld de, $7795
    call Call_000_3684
    ld a, $03
    jp Jump_018_7747


    dec c
    ld b, $0c
    rlca
    rst $38
    nop
    nop
    nop
    rst $38

Call_018_7799:
    ld [$d4a7], a
    ld a, $03
    ldh [$8c], a
    ld a, b
    ldh [$8d], a
    jp Jump_000_34f0


    ld a, [$d034]
    cp $ff
    jp z, Jump_018_7743

    ld a, [$cf08]
    cp $01
    jr z, jr_018_77bb

    ld a, $02
    ld b, $0c
    jr jr_018_77bf

jr_018_77bb:
    ld a, $08
    ld b, $00

jr_018_77bf:
    call Call_018_7799
    ld a, $f0
    ld [$cd66], a
    ld a, $06
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_0b71
    call Call_018_76ec
    call Call_000_0ebd
    call Call_000_3e07
    call Call_000_0b53
    ld hl, $d7b7
    set 7, [hl]
    xor a
    ld [$cd66], a
    jp Jump_018_7747


    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $03
    ldh [$8c], a
    call Call_000_358b
    ld a, [$cf08]
    cp $01
    jr z, jr_018_7803

    ld a, $02
    ld b, $0c
    jr jr_018_7807

jr_018_7803:
    ld a, $08
    ld b, $00

jr_018_7807:
    call Call_018_7799
    call Call_000_3e07
    ld a, $04
    jp Jump_018_7747


    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $7a51
    ld de, $7a51
    call Call_000_339c
    ldh a, [$8c]
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    xor a
    ld [$cd66], a
    ld a, $05
    jp Jump_018_7747


    ld e, e
    ld a, b
    and a
    ld a, c
    and $79
    sub $7a
    add hl, de
    ld a, e
    ld h, [hl]
    ld a, d
    inc b
    ld b, b
    or [hl]
    rst $10
    ldh [$7a], a
    inc b
    ld a, e
    ld a, [$fa7a]
    ld a, d
    dec b
    jr nc, jr_018_7807

    rst $10
    inc hl
    ld a, e
    ld b, l
    ld a, e
    ld a, [hl-]
    ld a, e
    ld a, [hl-]
    ld a, e
    rst $38
    ld [$b7fa], sp
    rst $10
    bit 5, a
    jp nz, Jump_018_7887

    ld hl, $7890
    call Call_000_3c79
    ld bc, $0101
    call Call_000_3e5e
    jr nc, jr_018_787f

    ld hl, $791f
    call Call_000_3c79
    ld hl, $d7b7
    set 5, [hl]
    jr jr_018_788d

jr_018_787f:
    ld hl, $7999
    call Call_000_3c79
    jr jr_018_788d

Jump_018_7887:
    ld hl, $793a
    call Call_000_3c79

jr_018_788d:
    jp Jump_000_0f6a


    db $ed
    dec hl
    and a
    ld e, [hl]
    ld [c], a
    or e
    ld [hl], d
    or l
    or l
    ld a, a
    cp h
    ld [c], a
    or e
    ret z

    sbc $d6
    rst $20
    ld c, a
    ret nz

    cp l
    cp c
    jp $b87f


    jp c, $7fc3

    or c
    ret c

    ld h, $c4
    or e
    rst $20
    ld d, c
    call c, $bcc0
    jp z, Jump_018_414f

jr_018_78b8:
    xor e
    sub b
    db $dd
    ld a, a
    cp l
    cp b
    rst $18
    jp $b87f


    jp c, Jump_018_51c0

    or a
    ret nc

    ret


    cp d
    call nz, $7fdd
    cp d
    ret


    cp e
    or a
    ld c, a
    cp c
    cp h
    jp $dc7f


    cp l
    jp c, $b2c5

    ld a, a
    jr nc, jr_018_78b8

    or e
    rst $20
    ld d, c
    or l
    or l
    rst $20
    ld a, a
    cp a
    or e
    jr nc, jr_018_7937

    or l
    jp c, $ddb2

    ld a, a
    cp e
    cp h
    or c
    add hl, hl
    push bc
    cp b
    jp $e7ca


    ld d, c
    call c, $bcc0
    jp z, $cc4f

    call nz, Call_018_44df
    rst $10
    inc sp
    ld a, a
    or c
    reti


    ld a, a
    or [hl]
    rst $10
    cp h
    jp $ce51


    jp c, $ba4f

    db $e3
    sbc $c5
    ld a, a
    db $d3
    ret


    inc sp
    jp z, $b27f

    or [hl]
    ld h, $b6
    push bc
    and $58
    db $ed
    dec hl
    sub h
    ld e, a
    cp h
    ldh [$c1], a
    ld [c], a
    or e
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

jr_018_7937:
    ld d, b
    ld de, $ed50
    dec hl
    db $dd
    ld e, a
    ld [c], a
    or e
    ld [hl], d
    cp a
    jp c, Jump_018_56ca

    ld c, a
    inc [hl]
    cp d
    inc sp
    ld a, a
    or [hl]
    or e
    cp d
    call nz, Call_018_7fd3
    inc sp
    or a
    push bc
    or d
    ld d, c
    set 2, b
    jp nz, Jump_018_4fc9

    cp h
    cp e
    cp b
    set 3, [hl]
    ld a, a
    sbc l
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    rst $20
    ld d, c
    push bc
    add hl, hl
    jp c, $7f3a

    or [hl]
    push bc
    rst $10
    dec l

jr_018_7972:
    ld c, a
    ld d, h
    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    rst $10
    jp c, $e7d9

    ld d, c
    cp d
    rst $18
    cp a
    ret c

    call nz, $4f56
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, l
    jp nz, $dfb6

    jp $d07f


    jp $b87f


    jp c, $cfc0

    or h
    ld d, a
    db $ed
    dec hl
    rst $00
    ld e, a
    ret


    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_018_79d5

    ld d, a
    db $ed
    jr z, @+$18

    ld c, h
    ld [hl], d
    cp d
    ret


    ret nz

    dec sp
    jp z, $c07f

    cp l
    cp c
    jp $b24f


    ret nz

    jr nc, @-$4c

    jp $b17f


    ret c

    ld h, $c4
    or e
    ld a, a
    ld a, [hl+]
    dec hl
    or d
    rst $08
    cp l
    ld d, c
    cp h
    ldh [$c1], a
    ld [c], a
    or e
    ld a, a
    call nz, $34d3
    db $d3
    ld c, a
    or [hl]

jr_018_79d5:
    sbc $bc
    ldh [$c9], a
    ld a, a
    or a
    db $d3
    pop bc
    inc sp
    ld a, a
    or d
    rst $18
    ld b, h
    or d
    inc sp
    cp l
    ld d, a
    db $ed
    jr z, jr_018_7972

    ld c, h
    ld d, d
    or [hl]
    and $4f
    rst $08
    ret nz

    ld a, a
    or c
    rst $18
    ret nz

    push bc
    rst $20
    ld d, c
    or l
    jp c, Jump_018_7fca

    or d
    rst $08
    ld a, a
    adc e
    and [hl]
    sbc e
    ret


    ld a, a
    cp h
    ldh [$c1], a
    ld [c], a
    or e
    call nz, $bc4f
    ld a, [hl+]
    call nz, $7fc9
    jp z, $bcc5

    db $dd
    ld a, a
    cp h
    jp $ded9


    jr nc, jr_018_7a6b

    or l
    call nz, $c9c5
    ld a, a
    cp [hl]
    or [hl]
    or d
    add $4f
    cp b
    pop bc
    db $dd
    ld a, a
    jp z, $cfbb

    push bc
    or d
    inc sp
    ld a, a
    db $d3
    rst $10
    or d
    ret nz

    or d
    ld d, c
    inc [hl]
    or e
    cp h
    jp Jump_018_7fd3


    call nz, $b3b2
    push bc
    rst $10
    ld c, a
    or d
    ret nz

    or d
    jp nc, $7fc6

    or c
    rst $18
    jp $d37f


    rst $10
    or e
    cpl
    rst $20
    ld d, a
    db $ed
    inc l
    db $e4
    ld c, a
    ld c, a
    cp d
    ret


    ld a, a
    or l
    jp c, Jump_018_7f26

    rst $08
    cp c
    reti


    ld a, a
    push bc
    sbc $c3
    rst $20
    ld e, b
    db $ed
    jr z, jr_018_7acd

    ld c, l
    ld a, a

jr_018_7a6b:
    ld d, [hl]
    cp h
    ld [c], a
    or e
    ld h, $7f
    push bc
    or d
    rst $20
    ld c, a
    adc e
    and [hl]
    sbc e
    jp z, $cb7f

    call nz, $2dcf
    ld a, a
    or c
    or a
    rst $10
    jp nc, $b3d6

    rst $20
    ld d, c
    cp h
    or [hl]

jr_018_7a89:
    cp h
    ld a, a
    ld c, a
    call c, Call_018_7f26
    ld e, [hl]
    jp z, $cc7f

    jp nc, $30c2

    rst $20
    ld d, c
    ld d, d
    rst $20
    ld a, a

jr_018_7a9b:
    cp l
    dec a
    jp $7fc9


    ld d, h
    jp z, Jump_018_5e4f

    ret


    ld a, a
    ret nz

    jp nc, Jump_018_55c6

    cp a
    sbc $2b
    or d
    ld a, a
    cp l
    reti


    ret


    jr nc, jr_018_7a9b

    ld d, l
    cp a
    ret


    cp d
    call nz, $7fdd
    call c, $dabd
    reti


    push bc
    sub $e7
    ld d, c
    inc sp
    jp z, $e756

    ld c, a

jr_018_7ac8:
    or l
    jp c, Jump_018_7fca

    ret nz

jr_018_7acd:
    or d
    cp e
    sbc $7f
    cp h
    sub $b3

jr_018_7ad4:
    rst $20
    ld d, a
    ld [$4221], sp
    ld a, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_018_7af2

    ld c, [hl]
    rst $10
    ld a, a
    rst $08
    jp Jump_018_4fe7


    cp l
    cp l
    sbc $33
    jp z, $b27f

    or [hl]

jr_018_7af2:
    sbc $7f
    call nz, $b3b2
    ret


    add $57
    db $ed
    jr z, jr_018_7a89

    ld c, [hl]
    sbc $7f
    jr nc, jr_018_7ad4

    jr nc, jr_018_7b5c

    db $ed
    jr z, jr_018_7b5b

    ld c, [hl]
    ld c, a
    inc e
    adc h
    add $7f
    or c
    or l
    or e
    rst $18
    jp $b27f


    or e
    ret


    or [hl]
    or d
    ld d, a
    ld [$4e21], sp
    ld a, b
    call Call_000_3214

jr_018_7b20:
    jp Jump_000_0f6a


    db $ed
    jr z, jr_018_7ac8

    ld c, [hl]
    ld a, a
    or l
    rst $08
    or h
    jp z, $1c4f

    adc h
    add $7f
    push bc
    sbc $c9
    ld a, a
    sub $b3
    jr nc, jr_018_7b20

    ld d, a
    db $ed
    jr z, jr_018_7b79

    ld c, a
    rst $20
    ld a, a
    call nc, $dad7
    ret nz

    ld e, b
    db $ed
    jr z, @-$1a

    ld c, [hl]
    ld a, a
    or l
    cp b
    ld h, $7f
    inc e

Call_018_7b4f:
    adc h
    jp z, $c27f

    sub $b2
    cpl
    ld c, a
    cp b
    jp c, $da28

jr_018_7b5b:
    db $d3

jr_018_7b5c:
    ld a, a
    or a
    db $dd
    ld a, a
    jp nz, $c5b9

    ld d, a
    ld [$7321], sp
    ld a, e
    call Call_000_3c79
    ld a, $aa
    call Call_000_34e5
    jp Jump_000_0f6a


    db $ed
    dec hl
    sub e
    ld h, b
    db $e3
    ld a, a

jr_018_7b79:
    ld h, $d2
    sbc $c6
    ld c, a
    ld d, h
    ld h, $7f
    or e
    jp nz, $c3df

    reti


    rst $20
    ld d, a
    dec c
    inc b
    nop
    add hl, bc
    ld bc, $00ea
    dec c
    nop

jr_018_7b91:
    db $ec
    dec b
    dec b
    add hl, bc
    rst $38
    ld [bc], a
    inc bc
    inc bc
    call nc, $0500
    dec hl
    add hl, bc
    dec bc
    rst $38
    ret nc

    ld bc, $090f
    ld c, $ff
    ret nc

    ld [bc], a
    rla
    dec c
    ld a, [bc]
    rst $38
    ret nc

    ld b, e
    push hl
    ld [bc], a
    jr jr_018_7bc6

    rlca
    rst $38
    pop de
    ld b, h
    and $29
    jr jr_018_7bc7

    inc de
    rst $38
    pop de
    ld b, l
    and $28
    db $fc
    add $00
    add hl, bc
    cp $c6

jr_018_7bc6:
    nop

jr_018_7bc7:
    dec c
    jr jr_018_7b91

    dec b
    dec b
    ld [$02c7], sp
    inc bc
    ld hl, $2122
    ld [hl+], a
    ld e, $22
    dec e
    ld [hl+], a
    inc hl
    inc h
    add hl, sp
    ld [hl-], a
    ld sp, $3131
    inc [hl]
    ld c, $28
    inc h
    ld c, $33
    ld [de], a
    inc de
    ld d, $35
    ld c, $28
    inc h
    ld c, $24
    db $10
    ld de, $2a0e
    ld c, $28
    inc h
    ld c, $24
    inc d
    dec d
    inc bc
    ld a, [hl+]
    ld c, $28

jr_018_7bfd:
    inc h
    ld c, $24
    ld c, $03
    inc bc
    ld a, [hl+]
    ld c, $28
    inc h
    ld c, $37
    inc bc
    ld [hl], $38
    ld a, [hl+]
    ld c, $28
    inc h
    ld c, $0e
    ld c, $24
    ld c, $2a
    ld c, $28
    dec h
    ld h, $26
    ld h, $25
    ld h, $2e
    ld h, $27
    call Call_000_3c6c
    ld a, [$c109]
    cp $04
    ret nz

    ld hl, $7c4a
    ld a, [$d2dd]
    ld b, a

jr_018_7c31:
    ld a, [hl+]
    cp $ff
    ret z

    cp b
    jr z, jr_018_7c3b

    inc hl
    jr jr_018_7c31

jr_018_7c3b:
    ld b, [hl]
    ld a, [$d6a9]
    and b
    cp b
    ld a, $0d
    jr z, jr_018_7c47

    ld a, $0c

jr_018_7c47:
    jp Jump_000_3f25


    ld [hl], $01
    ld b, c
    ld [bc], a
    ld e, h
    inc b
    add [hl]
    ld [$109d], sp
    or d
    jr nz, jr_018_7bfd

    ld b, b
    dec l
    add b
    rst $38
    db $ed
    dec l
    jp hl


    ld e, e
    ld a, a
    ld d, h
    ld a, a
    dec bc
    sbc a
    ld c, a
    ld d, b
    ld bc, $cf5e
    nop
    ld a, a
    add $de
    jp Jump_018_7fb2


    ld e, l
    rst $20
    ld d, l
    ld d, e
    ld d, a
    db $ed
    dec l
    cp $42
    ld a, a
    ld d, h
    ld a, a
    dec bc
    sbc a
    ld c, a
    ld d, b
    ld bc, $cf5e
    nop
    ld a, a
    add $de
    jp Jump_018_7fb2


    ld e, l
    rst $20
    ld d, l
    ld d, e
    ld a, a
    ld d, d
    ld d, a
    call Call_000_3c6c
    ld hl, $7cb2
    ld a, [$d2dd]
    ld b, a

jr_018_7c9b:
    ld a, [hl+]
    cp $ff
    ret z

    cp b
    jr z, jr_018_7ca6

    inc hl
    inc hl
    jr jr_018_7c9b

jr_018_7ca6:
    ld a, [hl+]
    ld b, a
    ld a, [$c109]
    cp b
    jr nz, jr_018_7c9b

    ld a, [hl]
    jp Jump_000_3f25


    add hl, hl
    ld [$3a0f], sp
    ld [$4010], sp
    ld [$8d11], sp
    ld [$5912], sp
    ld [$8513], sp
    ld [$8c14], sp
    ld [$9a15], sp
    ld [$ab16], sp
    ld [$b617], sp
    ld [$4418], sp
    ld [$5119], sp
    ld [$df1a], sp
    ld [$e01b], sp
    ld [$e11c], sp
    ld [$ff1d], sp
    db $ed
    dec l
    ld b, l
    ld b, d
    adc a
    db $e3
    add $7f
    or c
    dec l
    cp c
    reti


    call nz, $c24f
    or [hl]
    jp c, $7fc3

    or e
    ld a, [hl+]
    cp c
    push bc
    or d
    ld d, l
    ld d, h
    db $d3
    ld a, a
    add hl, hl
    sbc $b7
    add $7f
    push bc
    reti


    sub $e7
    ld d, a
    db $ed
    dec l
    and e
    ld b, d
    set 4, b
    ld d, [hl]
    rst $20
    ld d, c
    ld b, d
    ret c

    xor e
    ret


    ld a, a
    or e
    ret nz

    ld a, [hl+]
    or h
    db $dd
    ld a, a
    or a
    cp b

jr_018_7d1c:
    call nz, $4f56
    ret nz

    or d
    jp $c9b2


    ld a, a
    ld d, h
    jp z, $c87f

    pop de
    cp b
    push bc
    reti


    ld d, c
    ld d, [hl]
    cp a
    cp h
    jp Jump_000_3e4f


    cp b
    db $d3
    ld d, [hl]
    jr z, jr_018_7d1c

    ld d, [hl]
    ld d, a
    db $ed
    dec l
    ld c, [hl]
    ld d, [hl]
    ld a, a
    add $b2
    pop bc
    ldh [$de], a
    ld c, a
    ld d, h
    ld a, a
    or d
    rst $18
    ld b, h
    or d
    ld a, a
    db $d3
    rst $18
    jp $d6d9


    rst $20
    ld d, c
    jp nc, $d72d

    cp h
    or d

jr_018_7d59:
    ld a, a
    ld d, h
    db $d3
    ld c, a
    or c
    jp nz, $c3d2

    reti


    rst $18
    jp $ed57


    dec l
    rra
    ld b, e
    and l
    ret


    ld a, a
    cp h

jr_018_7d6d:
    pop hl
    cpl
    cp b
    jp z, $ce4f

    ret z

    db $dd
    ld a, a
    or [hl]
    inc a
    rst $18
    jp Jump_018_7fd9


    jr nc, jr_018_7d59

    and $51
    or c
    jp c, Jump_018_7f26

    ret nz

    or [hl]
    cp b
    ld a, a
    or e
    jp c, $ded9

    jr nc, jr_018_7d6d

    jp $ed57


    dec l
    bit 2, l
    ret nz

    cp b
    cp e
    sbc $7f
    jp nz, $cfb6

    or h
    jp $d34f


    pop bc
    or a
    jp c, $b2c5

    ld a, a
    call nz, $cab7
    ld d, c
    ld e, e
    ld a, a
    jp nz, $bcb3

    sbc $33
    ld c, a
    or c
    dec l
    cp c
    reti


    call nz, $b27f
    or d
    sub $57
    db $ed
    dec l
    ld e, e
    ld e, e
    ld a, a
    adc a
    add d
    xor e
    inc sp
    ld c, a
    push de
    or e
    jp c, Jump_018_7fb2

    ld d, h
    ld h, $7f
    inc sp
    reti


    rst $18
    jp $d055


    sbc $c5
    ld a, a
    cp e
    call c, Call_000_33b2
    reti


    sub $57
    nop
    ld a, $b8
    db $d3
    ld a, a
    ld d, h
    call nz, $7fd8
    cp h
    ret nz

    or d
    push bc
    db $e3
    ld d, a
    nop
    jp z, $e0bc

    daa
    cp l
    daa
    jp $c27f


    or [hl]
    jp c, $e0c1

    rst $18
    ret nz

    ld d, [hl]
    ld d, a
    nop
    adc e
    and [hl]
    sbc e
    ret


    sub b

Jump_018_7e05:
    db $e3
    sbc e
    ld h, $7f
    adc d
    sbc e
    jp hl


    ret c

    ld c, $e3
    xor e
    ret


    ld c, a
    inc [hl]
    cp d
    or [hl]
    add $7f
    or [hl]
    cp b
    jp c, $d9c3

    sbc $30
    rst $18
    jp Jump_018_57e7


    db $ed
    dec l
    db $76
    ld e, b
    add $7f
    and a
    dec a
    and [hl]
    ret


    ld a, a
    ret nz

    or [hl]
    or d
    ld c, a
    ld d, h
    jp z, $c27f

    sub $b2
    ld a, a
    cp c
    inc [hl]
    ld d, [hl]
    ld d, c
    ld d, h
    ret


    ld a, a
    adc a
    add c
    ld b, d
    add $7f
    sub $df
    jp $c64f


    ld h, $c3
    push bc
    ld a, a
    or c
    or d
    jp Jump_018_7f26


    or c
    reti


    ld a, a
    ret nc

    ret nz

    or d
    ld d, c
    ld l, $df
    ret nz

    or d
    add $7f
    jp nz, $b2d6

    ld a, a
    ld d, h
    jp z, $c54f

    or [hl]
    push bc
    or [hl]
    ld a, a
    or d
    push bc
    or d
    ld a, a
    ret nc

    ret nz

    or d
    jr nc, @+$59

    db $ed
    dec l
    add $65
    ld a, a
    inc l
    jp $bcde


    ldh [$7f], a
    db $d3
    rst $18
    jp $d7c0


    ld c, a
    adc d
    add c
    add a
    ret c

    xor e
    rlca
    ld a, a
    xor b
    db $e3
    inc de
    ld a, a
    or d
    or a
    ret nz

    db $e3
    or d
    rst $20
    ld d, a
    db $ed
    dec l
    ld l, a
    ld b, e
    ldh [$de], a
    ld c, a
    ld d, h
    ld a, a
    dec l
    or [hl]
    sbc $7f
    jp nz, $dfb8

    jp Jump_018_7fd9


    push bc
    rst $10
    ld d, l
    adc d
    sbc e
    jp hl


    ret c

    ld a, a
    ld c, $e3
    xor e
    ld a, a
    or d
    cp b
    call nz, $b27f
    or d
    sub $51
    jp nc, $d72d

    cp h
    or d
    ld a, a
    ld d, h
    ld h, $4f
    ret nz

    cp b
    cp e
    sbc $7f
    jp z, $bcde

    ld [c], a
    cp b
    ld a, a
    cp h
    jp $dfd9


    jp $ed57


    dec l
    ld [$865c], sp
    xor l
    xor e
    adc l
    and [hl]
    ld a, a
    cp h
    ret nz

    ld a, a
    or c
    call nz, Call_018_4fd3
    ld d, h
    jp z, $dc7f

    dec hl
    db $dd
    ld a, a
    or l
    ld a, $b4
    reti


    sub $51
    call c, $dd2b
    ld a, a
    or l
    ld a, $b4
    cp e
    cp [hl]
    jp $b27f


    rst $18
    jp $d7b6


    ld c, a
    cp h
    sbc $b6
    ld a, a
    cp e
    cp [hl]
    reti


    ret


    db $d3
    ld a, a
    adc c
    sub c
    cp e
    ld d, a
    ld [$b7fa], sp
    rst $10
    bit 7, a
    ld hl, $7f4d
    jr nz, jr_018_7f23

    ld hl, $7f29

jr_018_7f23:
    call Call_000_3c79

Call_018_7f26:
Jump_018_7f26:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld a, [de]
    ld h, c
    ld d, [hl]
    ld c, a
    ld d, h
    ld a, a
    cp h
    jp $c9de


    or e
    ld h, $7f
    or a
    jp Jump_018_5e55


    db $dd
    ld a, a
    call nc, $c2df
    cp c
    jp $b855


jr_018_7f45:
    jp c, $c4d9

    ld a, a
    or d
    or d
    push bc
    ld d, a
    db $ed
    dec hl
    cp a
    ld h, b
    add hl, hl
    jp $c0df


    ret z

Jump_018_7f56:
    rst $20
    ld c, a
    cp d
    jp c, $d7b6

    jp z, $bf7f

    call nz, $b17f
    reti


    or d
    jp Jump_018_55d3


    pop bc
    rst $18
    call nz, Call_018_7fd3
    cp d
    call c, $c5b8
    or d
    rst $20
    ld d, l
    sub $b6
    rst $18
    ret nz

    ret z

    rst $20
    ld d, a
    db $ed
    dec l
    sbc c
    ld e, e
    rst $20
    ld a, a
    ret c

    ld [c], a
    cp d
    or e
    ld a, a
    jr nc, jr_018_7fb6

    db $e3
    rst $20
    ld c, a
    or l
    ret z

    or h
    pop bc
    ldh [$de], a
    ld a, a
    jr nc, jr_018_7f45

    cp l
    or a
    rst $20
    ld d, a
    ret


    ld d, b
    call Call_000_3c6c
    ld a, $0e
    jp Jump_000_3f25


    db $ed
    dec l
    jp $c567


    add $7f
    push bc
    rst $10
    sbc $33
    or d
    reti


    ret


    jp z, Jump_018_544f

Jump_018_7fb2:
    ret


Call_018_7fb3:
    ld a, a
    adc $de

Jump_018_7fb6:
jr_018_7fb6:
    ld a, a
    ld a, [hl-]

Call_018_7fb8:
    or [hl]

Jump_018_7fb9:
    ret c

    jr nc, @+$59

    ld a, [$c109]
    cp $04
    ret nz

    call Call_000_3c6c

Jump_018_7fc5:
    ld a, $01
    ld [$cf07], a

Jump_018_7fca:
    ld a, $1f
    jp Jump_000_3f25


    ld sp, hl
    jp $3f39


Call_018_7fd3:
Jump_018_7fd3:
    ld sp, hl

jr_018_7fd4:
    dec c
    push bc
    ld bc, $0152

Jump_018_7fd9:
    ld b, l
    adc b
    ld bc, $0401
    add b
    add hl, hl
    ldh [rTIMA], a
    jr z, @+$49

    add b
    add hl, bc

Jump_018_7fe6:
    rlca
    adc c
    ld bc, $2803
    add hl, hl
    add c
    xor c
    ld bc, $81a1
    add c
    jr nz, jr_018_7fd4

    nop
    inc bc
    ld bc, $06ab
    ld h, b
    nop
    add hl, hl
    ld b, c
    push bc
    db $08
    xor [hl]
