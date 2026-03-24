; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $016", ROMX[$4000], BANK[$16]

    jr nz, jr_016_4012

    ld bc, $0c02
    dec c
    dec c
    ld hl, $0504
    rlca
    rlca
    ld [hl+], a
    inc hl
    ld [$0f0f], sp
    rrca

jr_016_4012:
    rrca
    rrca
    dec de
    ld c, $0a
    dec bc
    ld c, $0f
    rrca
    ld c, $00
    ld [de], a
    ld a, [bc]
    sub l
    ld b, b
    sbc c
    ld d, b
    add b
    ld d, b
    inc c
    ld a, [bc]
    add $4b
    add sp, -$3a
    db $10
    inc d
    inc hl
    ld a, [bc]
    cp l
    ret z

    dec b
    ld b, c
    ld c, d
    db $38, $c8
    db $10
    inc d
    nop
    ld a, [bc]
    inc bc
    rst $00
    ld a, $40
    rrca
    inc b
    ld bc, $0209
    ld c, c
    ld bc, $020a
    ld c, c
    rlca
    ld a, [bc]
    nop
    ld c, c
    dec c
    ld de, $4a00
    ld bc, $130f
    rlca
    ld b, $07
    add hl, de
    ld c, $ff
    db $d3
    ld b, c
    call $0604
    add hl, de
    rrca
    rst $38
    jp nc, $ce42

    ld [bc], a
    inc b
    inc de
    inc b
    rst $38
    db $d3
    ld b, e
    jp z, Jump_000_070a

    inc hl
    rrca
    rst $38
    jp nc, $cd44

    dec b
    ld b, $22
    rrca
    rst $38
    jp nc, $ce45

    inc bc
    inc b
    ld e, $17
    rst $38
    jp nc, $ca46

    dec bc
    db $fd
    add $01
    add hl, bc
    cp $c6
    ld bc, $2e0a
    rst $00
    rlca
    ld a, [bc]
    ld h, c
    rst $00
    dec c
    ld de, $7474
    ld [hl], h
    ld a, [bc]
    ld c, l
    ld c, l
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    jr nz, jr_016_40b2

    ld hl, $5151
    ld d, c
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld l, b
    ld a, a
    ld l, c
    ld [hl], h
    ld [hl], h

jr_016_40b2:
    ld [hl], h
    rlca
    cpl
    rlca
    rlca
    scf
    ld a, [hl-]
    ld a, [hl]
    rlca
    cpl
    rlca
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rlca
    rlca
    rlca
    cpl
    rlca
    rlca
    rlca
    rlca
    jr nz, @+$23

    ld sp, $3131
    ld sp, $3131
    ld sp, $7c31
    ld a, [hl]
    dec bc
    dec bc
    ld sp, $0b0b
    dec bc
    dec bc
    ld sp, $0831
    dec bc
    dec bc
    ld sp, $0b0b
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld sp, $0b0b
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld sp, $3131
    ld sp, $3131
    ld sp, $0b0b
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld sp, $1d0b
    rra
    rra
    rra
    rra
    rra
    ld e, $0b
    ld sp, $650b
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld h, h
    dec bc
    ld sp, $510b
    ld h, e
    ld a, [bc]
    ld a, [bc]
    ld sp, $3131
    ld sp, $0b31
    ld a, [bc]
    ld c, l
    ld d, d
    ld d, d
    ld sp, $0b0a
    dec bc
    dec bc
    dec bc
    rra
    rra
    rra
    ld l, d
    ld sp, $5162
    ld d, c
    ld d, c
    ld d, c
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld sp, $0a4e
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    nop
    add hl, bc
    ld e, $e2
    ld b, c
    rlca
    ld d, e
    xor $52
    inc bc
    ld a, [bc]
    cp l
    ld c, d
    add sp, -$3a
    rrca
    inc d
    ld [$1627], sp
    rst $00
    inc b
    or c
    ld b, b
    ld [hl], l
    rst $00
    add hl, bc
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $6b
    ld b, c
    inc l
    dec b
    add hl, bc
    ld bc, $4f00
    ld a, [bc]
    ld bc, $4f01
    add hl, bc
    ld [$4f02], sp
    ld a, [bc]
    ld [$4f03], sp
    inc bc
    dec c
    nop
    ld d, b
    ld bc, $1103
    ld a, [bc]
    add hl, bc
    inc c
    add hl, bc
    inc c
    rst $38
    db $d3
    ld b, c
    ret nc

    inc bc
    dec bc
    dec c
    ld de, $d1ff
    ld b, d
    reti


    dec b
    inc c
    ld a, [bc]
    ld l, $ff
    pop de
    ld b, e
    ret nc

    inc b
    ld b, $07
    ld e, $ff
    jp nc, $cb44

    dec c
    inc c
    ld [$ff1e], sp
    db $d3
    ld b, l
    ret nc

    dec b
    ld b, $09
    ld e, $ff
    jp nc, $cb46

    ld c, $06
    ld a, [bc]
    ld e, $ff
    db $d3
    ld b, a
    rrc a
    dec bc
    ld de, $ff32
    ret nc

    ld c, b
    reti


    rlca
    ld b, $10
    scf
    rst $38
    jp nc, $cb49

    db $10
    sbc l
    rst $00
    add hl, bc
    ld bc, $c7c1
    ld a, [bc]
    ld bc, $c7a1
    add hl, bc
    ld [$c7c5], sp
    ld a, [bc]
    ld [$c737], sp
    inc bc
    dec c
    inc de
    inc de
    jr z, jr_016_4212

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
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    dec h
    jr z, jr_016_422b

    inc de
    inc de
    inc h
    ld d, a
    ld d, a
    dec h
    ld [bc], a
    inc bc
    ld [$1a1a], sp
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]

jr_016_4212:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, l
    inc de
    inc de
    rrca
    rrca
    jr z, jr_016_4247

    inc de
    inc de
    ld c, [hl]
    ld bc, $0101
    ld bc, $4d01
    ld sp, $4e31
    ld a, [bc]

jr_016_422b:
    ld c, c
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld c, b
    ld a, [bc]
    ld c, l
    inc de
    ld h, d
    ld [hl], h
    ld [hl], h
    jr z, @+$2b

    inc de
    inc de
    ld c, [hl]
    ld bc, $7474
    ld [hl], h
    ld bc, $1a4d
    ld a, [de]

jr_016_4247:
    ld c, [hl]
    ld a, [bc]
    daa
    ld a, [bc]
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld a, [bc]
    daa
    ld a, [bc]
    ld c, l
    inc de
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    inc h
    dec h
    ld bc, $0d20
    ld hl, $5151
    ld [hl], h
    ld bc, $314d
    ld sp, $0a4e
    daa
    ld c, l
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld [hl], h
    ld c, [hl]
    daa
    ld a, [bc]
    ld c, l
    inc de
    ld c, [hl]
    ld a, [bc]
    ld bc, $7777
    ld [hl], a
    scf
    ld a, l
    ld a, [hl]
    ld [hl], a
    ld bc, $0101
    ld c, l
    ld h, c
    ld h, c
    ld a, [bc]
    ld a, [bc]
    daa
    ld c, l
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld [hl], h
    dec [hl]
    daa
    ld a, [bc]
    ld c, l
    inc de
    ld c, [hl]
    ld a, [bc]
    ld e, l
    ld a, $3b
    inc de
    inc de
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld e, l
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    daa
    dec [hl]
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld [hl], h
    ld c, [hl]
    daa
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    daa
    jr z, jr_016_42dd

    inc de
    inc de
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld b, h
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld b, l
    ld c, l
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld c, [hl]
    ld b, h
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld b, l
    jr z, jr_016_42fb

    inc de
    inc de
    ld a, $3f
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf

jr_016_42dd:
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
    inc l
    nop
    inc h
    ld a, [bc]
    ld [hl], d
    ld b, e
    jr z, jr_016_434e

    rrca
    ld d, a
    ld b, $04

jr_016_42fb:
    or c
    ld b, b
    ld e, e
    ret


    ld a, [bc]
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $14
    add hl, sp

Jump_016_4307:
    ld b, a
    jr @-$37

    add hl, bc
    ld e, $00
    dec sp
    ld a, [hl+]
    rst $00
    ld [de], a
    ld b, e
    inc l
    inc b
    inc de
    dec bc
    nop
    ld d, c
    ld de, $0008
    ld d, d
    dec [hl]
    ld [$5202], sp
    daa
    ld b, $00
    ld d, e
    inc b
    inc de
    rlca
    rlca
    inc de
    inc c
    ld [$0937], sp
    add hl, bc
    add hl, hl
    dec b
    ld a, [bc]
    ld b, $0c
    jr nc, jr_016_4343

    rst $38
    jp nc, $cf41

    ld bc, $3d0e
    rlca
    rst $38
    pop de
    ld b, d
    pop de
    rlca
    inc c

jr_016_4343:
    ld b, h
    ld [de], a
    rst $38
    jp nc, $cf43

    ld [bc], a
    ld b, $1d
    dec bc
    rst $38

jr_016_434e:
    jp nc, $ce44

    rlca
    ld c, $41
    rlca
    rst $38
    ret nc

    ld b, l
    pop de
    ld [$3a06], sp
    dec bc
    rst $38
    ret nc

    ld b, [hl]
    adc $08
    adc [hl]
    rst $00
    inc de
    dec bc
    ld a, l
    rst $00
    ld de, $9d08
    ret z

    dec [hl]
    ld [$c82c], sp
    daa
    ld b, $57
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld a, [hl+]
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    jr z, jr_016_43e8

    ld bc, $6161
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    ld h, l
    jr z, jr_016_4392

    ld a, [bc]

jr_016_4392:
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld c, l
    ld h, l
    jr z, jr_016_439c

    ld a, [bc]

jr_016_439c:
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld c, l
    ld h, l
    jr z, @+$3d

    rlca
    rlca
    rlca
    rlca
    rlca
    cpl
    ld c, a
    ld h, l
    jr z, jr_016_43d8

    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, l
    ld h, l
    jr z, jr_016_43e5

    ccf
    ccf
    ccf
    dec sp
    ld a, [bc]
    ld a, [bc]
    ld c, l
    ld h, l
    jr z, jr_016_43ee

    ld d, a
    ld d, a
    ld d, a
    ld [hl], b
    jr nz, @+$23

    ld c, l
    ld h, l
    jr z, jr_016_43f6

    ld sp, $5677
    dec [hl]
    ld a, h
    ld [hl], d
    ld c, l
    ld h, l
    jr z, jr_016_4400

    ld a, [bc]

jr_016_43d8:
    ld a, [bc]
    ld a, [bc]
    dec [hl]
    ld d, l
    ld d, l
    ld c, l
    ld h, l
    jr z, jr_016_440a

    ld d, l
    ld d, l
    ld d, l
    dec [hl]

jr_016_43e5:
    ld a, [bc]
    ld a, [bc]
    ld c, l

jr_016_43e8:
    ld h, l
    jr z, jr_016_4414

    ld d, l
    ld d, l
    ld d, l

jr_016_43ee:
    dec [hl]
    ld a, [bc]
    ld a, [bc]
    ld c, l
    ld h, l
    jr z, @+$2b

    ld d, l

jr_016_43f6:
    ld d, l
    ld d, l
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, l
    ld h, l
    jr z, jr_016_4428

    ld a, [bc]

jr_016_4400:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, a
    ld h, l
    jr z, jr_016_4435

    ccf

jr_016_440a:
    ccf
    ccf
    ccf
    ccf
    dec sp
    ld a, e
    ld h, l
    jr z, jr_016_443e

    ld d, a

jr_016_4414:
    ld d, a
    ld d, a
    ld d, a
    ld a, [hl+]
    add hl, hl
    ld a, e
    ld h, l
    jr z, jr_016_4446

    jr nz, @+$0f

    dec c
    ld hl, $2928
    ld a, e
    ld h, l
    jr z, jr_016_4450

    ld l, b

jr_016_4428:
    ld a, a
    ld a, a
    ld l, c
    jr z, jr_016_4456

    ld a, e
    ld h, l
    jr z, jr_016_445a

    scf
    ld a, l
    ld a, [hl-]
    ld a, [hl]

jr_016_4435:
    jr z, jr_016_4460

    ld a, e
    ld h, l
    jr z, jr_016_4464

    ld a, e
    ld a, c
    ld a, e

jr_016_443e:
    ld a, e
    jr z, jr_016_446a

    ld a, e
    ld h, l
    jr z, jr_016_446e

    ld a, e

jr_016_4446:
    ld a, e
    ld a, e
    ld a, e
    inc h
    dec h
    ld a, e
    ld h, l
    jr z, jr_016_4478

    ld a, e

jr_016_4450:
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e

jr_016_4456:
    ld h, l
    jr z, @+$2b

    rra

jr_016_445a:
    rra
    rra
    rra
    rra
    rra
    rra

jr_016_4460:
    ld l, $28
    inc l
    ccf

jr_016_4464:
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf

jr_016_446a:
    ccf
    inc l
    inc l
    inc l

jr_016_446e:
    inc l
    inc l
    inc l
    inc l
    dec hl
    ld d, a
    ld d, a
    ld a, [hl+]
    dec hl
    ld d, a

jr_016_4478:
    ld d, a
    ld d, a
    ld b, $57
    dec h
    ld a, [bc]
    ld c, h
    jr z, jr_016_44aa

    ld sp, $3131
    ld [$3131], sp
    ld a, [bc]
    ld a, [bc]
    jr z, jr_016_44b4

    ld sp, $3131
    ld sp, $3b3e
    cpl
    rlca
    jr z, jr_016_44be

    ld a, [de]
    ld a, $3f
    ccf
    inc l
    add hl, hl
    ld a, [bc]
    ld a, [bc]
    jr z, jr_016_44c8

    ld a, d
    inc h
    ld d, a
    ld d, a
    ld d, a
    dec h
    rlca
    cpl
    jr z, jr_016_44d2

    ld a, [bc]

jr_016_44aa:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, d
    jr z, jr_016_44df

    ccf

jr_016_44b4:
    ccf
    ccf
    dec sp
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr z, jr_016_44e9

    inc l

jr_016_44be:
    dec hl
    ld d, a
    dec h
    cpl
    inc c
    dec c
    ld c, $28
    inc l
    inc l

jr_016_44c8:
    add hl, hl
    ld a, d
    ld a, d
    ld a, d
    ld [hl], l
    ld [hl], c
    db $76
    jr z, jr_016_44fd

    inc l

jr_016_44d2:
    add hl, hl
    ld a, d
    ld sp, $683e
    ld a, a
    ld l, c
    inc l
    nop
    add hl, bc
    ld e, $7b
    ld b, l

Call_016_44df:
jr_016_44df:
    db $e3
    ld e, c
    jp z, Jump_000_0359

    dec b
    ld h, h
    ld c, d
    add sp, -$3a

jr_016_44e9:
    rrca
    inc d
    ld [$1627], sp
    rst $00
    rla
    inc e
    ld c, b
    add hl, bc
    rst $00
    rrca
    ld a, [bc]
    ld [hl], $00
    ld sp, hl
    add $fc
    ld b, h
    rrca

jr_016_44fd:
    dec b
    ld [$0031], sp
    ld d, h
    add hl, bc
    ld sp, $5401
    ld [$023a], sp
    ld d, h
    add hl, bc
    ld a, [hl-]
    inc bc
    ld d, h
    dec b
    inc b
    nop
    ld d, l
    ld bc, $0105
    dec bc
    ld a, [bc]
    dec bc
    ld [de], a
    ld c, $ff
    ret nc

    ld b, c
    reti


    ld bc, $0d0b
    ld e, $ff
    ret nc

    ld b, d
    reti


    ld [bc], a
    inc b
    add hl, bc
    ld de, $d2ff
    ld b, e
    ret


    add hl, bc
    inc c
    rrca
    jr z, @+$01

    ret nc

    ld b, h
    call nc, Call_000_0402
    ld [$ff1a], sp
    pop de
    ld b, l
    ret


    ld a, [bc]
    dec bc
    dec bc
    ld sp, $d0ff
    ld b, [hl]
    reti


    inc bc
    dec bc
    rlca
    dec h
    rst $38
    pop de
    ld b, a
    reti


    inc b
    inc b
    add hl, bc
    cpl
    rst $38
    db $d3
    ld c, b
    ret


    dec bc
    inc c
    inc d
    ld sp, $d2ff
    ld c, c
    call nc, $0403
    db $10
    ld a, [de]
    rst $38
    pop de
    ld c, d
    ret


    inc c
    or l
    rst $00
    ld [$b531], sp
    rst $00
    add hl, bc
    ld sp, $c7ba
    ld [$ba3a], sp
    rst $00
    add hl, bc
    ld a, [hl-]
    ld d, a
    rst $00
    dec b
    inc b
    ld sp, $3131
    ld sp, $496d
    inc hl
    inc hl
    inc hl
    inc hl
    inc hl
    ld c, b
    dec bc
    dec bc
    dec bc
    ld c, c
    inc hl
    inc hl
    inc hl
    inc hl
    ld c, b
    dec bc
    dec bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    ld sp, $3f3e
    dec sp
    ld l, l
    daa
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    dec bc
    ld e, [hl]
    dec bc
    dec bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    ld d, [hl]
    inc h
    ld b, $25
    ld l, l
    daa
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld a, [bc]
    ld c, h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    ld sp, $3131
    ld sp, $2231
    dec bc
    dec bc
    ld c, c
    inc hl
    inc hl
    ld [hl+], a
    dec bc
    dec bc
    dec bc
    ld h, $23
    inc hl
    ld c, b
    dec bc
    dec bc
    dec bc
    dec bc
    ld l, a
    ld l, a
    jr nz, jr_016_45fd

    dec c
    ld hl, $1f0f
    rra
    rra
    ld e, $6d
    daa
    dec bc
    dec bc
    daa
    dec bc

jr_016_45fd:
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    ld bc, $0101
    scf
    ld a, l
    ld a, l
    ld a, [hl]
    ld a, [bc]
    ld b, e
    ld b, e
    ld b, e
    ld h, h
    ld l, l
    ld b, h
    inc hl
    inc hl
    ld b, l
    dec bc
    dec bc
    ld b, h
    inc hl
    inc hl
    inc hl
    ld [hl+], a
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    ld e, l
    ld l, h
    ld l, h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    ld b, e
    ld b, e
    ld b, e
    ld h, h
    ld l, l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    daa
    dec bc
    dec bc
    dec bc
    daa
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld l, l
    ld e, l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc

jr_016_465c:
    ld h, $23
    inc hl
    ld [hl+], a
    dec bc
    dec bc
    dec bc
    daa
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
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
    ld b, l
    dec bc
    dec bc
    ld b, h
    inc hl
    inc hl
    inc hl
    ld b, l
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    nop
    ld [hl], $0a
    inc l
    ld b, a
    ld a, c
    ld e, [hl]
    rst $30
    ld e, l
    ld c, $04
    db $ed
    ld b, b
    db $eb
    add $0a
    ld a, [bc]
    ld de, $7900
    rst $00
    jr jr_016_465c

    ld c, b
    ld a, b
    jp z, $1e0d

    nop
    jr z, jr_016_46b5

    rst $00
    ld d, $96
    ld b, l
    ret z

    ret z

    add hl, bc
    ld e, $ca
    dec sp
    ld a, [hl+]
    rst $00
    or [hl]

jr_016_46b5:
    ld b, [hl]
    ld b, e
    inc b
    rrca
    ld a, [bc]
    nop
    ld d, a
    rrca
    dec bc
    ld bc, $1557
    ld a, [bc]
    ld [bc], a
    ld d, a
    ld c, l
    dec bc
    nop
    cp l
    ld [bc], a
    dec c
    dec c
    dec bc
    ccf
    dec bc
    inc c
    ld a, [bc]
    ld b, e
    ld b, d
    ld c, $ff
    ret nc

    ld bc, $232f
    ld [de], a
    rst $38
    jp nc, $d642

    inc bc
    cpl
    dec hl
    add hl, bc
    rst $38
    pop de
    ld b, e
    sub $04
    rlca
    ld h, b
    rrca
    rst $38
    jp nc, $cd44

    add hl, bc
    inc c
    ld d, b
    ld [de], a
    rst $38
    pop de
    ld b, l
    call c, Call_000_2f02
    inc l
    db $10
    rst $38
    jp nc, $d646

    dec b
    cpl
    jr c, jr_016_470e

    rst $38
    db $d3
    ld b, a
    sub $06
    cpl
    ld e, e
    ld a, [bc]
    rst $38
    ret nc

    ld c, b
    sub $0b

jr_016_470e:
    dec a
    daa
    ld [de], a
    rst $38
    rst $38
    adc c
    ret c

    dec a
    ld e, l
    add hl, bc
    rst $38
    rst $38
    adc d
    dec h
    ld l, [hl]
    rst $00
    rrca
    ld a, [bc]
    ld l, [hl]
    rst $00
    rrca
    dec bc
    sbc [hl]
    rst $00
    dec d
    ld a, [bc]
    ld e, [hl]
    ret


    ld c, l
    dec bc
    inc l
    inc l
    inc l
    add hl, hl
    ld sp, $2c28
    inc l
    inc l
    inc l
    inc l
    dec hl
    ld d, a
    dec h
    ld sp, $5724
    ld d, a
    ld d, a
    ld d, a
    inc l
    add hl, hl
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    add hl, de
    ld b, e
    ld b, e
    inc l
    add hl, hl
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    add hl, de
    ld l, e
    ld l, e
    inc l
    add hl, hl
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    ld b, e

Jump_016_475c:
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld d, h
    ld d, h
    ld a, d
    ld d, h
    ld b, e
    ld b, e

Call_016_4766:
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld d, h
    ld a, b
    ld a, b
    ld d, h
    ld a, c
    ld d, h
    ld d, h
    add hl, de
    inc l
    add hl, hl
    ld d, h
    ld b, e
    ld b, e
    ld d, h
    ld a, b
    ld a, b
    ld a, b
    add hl, de
    inc l
    add hl, hl
    ld d, h
    ld b, e
    jr nz, jr_016_478f

    ld hl, $4343
    add hl, de
    inc l
    add hl, hl
    ld a, b
    ld b, e
    ld l, b
    ld a, a
    ld l, c
    ld b, e
    ld b, e

jr_016_478f:
    add hl, de
    inc l
    add hl, hl
    ld l, e
    ld l, e
    scf
    ld a, [hl-]
    ld a, [hl]
    ld l, e
    ld l, e
    dec d
    inc l
    add hl, hl
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld d, h
    ld d, h
    ld d, h
    ld a, d
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld d, h
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld d, h
    ld b, e
    ld b, e
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld d, h
    ld b, e
    ld b, e
    ld d, h
    ld a, b
    ld a, b
    ld b, e
    add hl, de
    inc l
    add hl, hl
    ld a, d
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    ld d, h
    ld b, e
    add hl, de
    ld d, a
    dec h
    ld d, h
    ld a, b
    ld a, b
    ld a, b
    ld b, e
    ld d, h
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld a, b
    ld b, e
    add hl, de
    rrca
    rrca
    ld a, d
    ld d, h
    ld a, d
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, h
    ld a, b
    ld d, h
    ld a, b
    ld a, b
    ld a, b
    ld b, e
    add hl, de
    rrca
    rrca
    ld a, b
    ld b, e
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    ld b, e
    add hl, de
    rrca
    rrca
    ld b, e
    ld b, e
    ld a, b
    ld a, b
    ld a, d
    ld d, h
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    ld d, h
    ld a, b
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, h
    ld a, b
    ld d, h
    ld b, e
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, h
    ld b, e
    ld d, h
    ld d, h
    ld a, d
    ld d, h
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, h
    ld b, e
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, h
    ld d, h
    ld d, h
    ld a, d
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    rrca
    rrca
    ld a, b
    ld a, b
    ld a, b
    ld d, h
    ld a, b
    ld a, b
    ld b, e
    add hl, de
    ld [hl], $36
    ld l, e
    ld l, e
    ld l, e
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld c, h
    ld c, h
    ld h, c
    ld h, c
    ld h, c
    ld a, c
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    rrca
    rrca
    ld a, b
    ld a, b
    ld a, b
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    rrca
    rrca
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    rrca
    rrca
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    rrca
    rrca
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld b, e
    ld b, e
    ld b, e
    ld a, b
    ld a, b
    ld d, h
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld d, h
    ld sp, $0231
    inc bc
    ld sp, $1943
    ld a, [bc]
    ld l, [hl]
    ld d, h
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld d, h
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld d, h
    ld d, h
    ld d, h
    ld a, d
    ld d, h
    ld b, e
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld a, b
    ld a, b
    ld a, b
    ld d, h
    ld a, b
    ld b, e
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld l, h
    ld [hl], $43
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    dec [hl]
    ld d, h
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld l, h
    ld a, [bc]
    ld a, b
    ld a, d
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld a, b
    ld a, b
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld a, b
    ld a, b
    ld a, b
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld b, e
    ld b, e
    ld b, e
    ld a, b
    ld a, b
    ld d, h
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    ld l, h
    ld l, h
    inc sp
    ld d, h
    ld a, d
    ld d, h
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    dec bc
    dec bc
    ld l, [hl]
    ld a, b
    ld d, h
    ld a, b
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    dec bc
    dec bc
    ld l, [hl]
    ld b, e
    ld d, h
    ld b, e
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    dec bc
    dec bc
    ld l, [hl]
    ld d, h
    ld a, d
    ld b, e
    ld b, e
    add hl, de
    ld a, [bc]
    ld l, [hl]
    dec bc
    dec bc
    ld l, [hl]
    ld d, h
    ld a, b
    ld b, e
    ld b, e
    add hl, de
    nop
    add hl, bc
    ld e, $e8
    ld c, c
    ld [bc], a
    ld h, d
    jp hl


    ld h, c
    inc bc
    rlca
    xor e
    ld c, h
    add sp, -$3a
    rrca
    inc d
    ld [$1627], sp
    rst $00
    add hl, de
    ret z

    ld c, d
    add hl, bc
    rst $00
    inc c
    ld a, [bc]
    inc h
    nop
    ld sp, hl
    add $6a
    ld c, c
    ld b, e
    inc b
    ld [$0007], sp
    cp b
    add hl, bc
    rlca
    ld bc, $08b8
    ld c, $02
    cp b
    add hl, bc
    ld c, $03
    cp b
    ld bc, $2709
    inc c
    dec bc
    ld b, $0f
    dec l
    rst $38
    ret nc

    ld b, c
    adc $14
    ld b, $0e
    add hl, sp
    rst $38
    jp nc, $ce42

    dec d
    rlca
    ld de, $ff23
    pop de
    ld b, e
    rst $18
    ld b, $07
    ld de, $ff27
    pop de
    ld b, h
    rst $18
    rlca
    rrca
    rrca
    add hl, sp
    rst $38
    ret nc

    ld b, l
    jp c, Jump_000_0f09

    ld c, $2d
    rst $38
    db $d3
    ld b, [hl]
    jp c, $120a

    ld c, $34
    rst $38
    ret nc

    ld b, a
    jp nc, $1203

    ld c, $32
    rst $38
    ret nc

    ld c, b
    jp nc, $0604

    add hl, bc
    add hl, hl
    rst $38
    db $d3
    ld c, c
    adc $16
    ld b, $11
    ld d, $ff
    pop de
    ld c, d
    adc $17
    dec a
    add hl, bc
    ld d, $ff
    rst $38
    adc e
    call c, $c7a0
    ld [$a007], sp
    rst $00
    add hl, bc
    rlca
    and h
    rst $00
    ld [$a40e], sp
    rst $00
    add hl, bc
    ld c, $0a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    inc de
    inc de
    ld l, a
    ld c, h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    inc de
    inc de
    rrca
    rrca
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, [hl]
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
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    rrca
    rrca
    ld d, d
    ld d, d
    jr nz, jr_016_4a55

    ld hl, $0750
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

jr_016_4a55:
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
    ld sp, $3131
    ld sp, $7d37
    ld a, [hl]
    ld d, l
    ld d, l
    dec bc
    dec bc
    dec bc
    ld [hl], h
    ld [hl], h
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld sp, $3108
    ld [hl], h
    ld [hl], h
    dec bc
    dec bc
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld [hl], h
    rrca
    rrca
    ld d, c
    ld d, c
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, [hl]
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
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    rrca
    rrca
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, [hl]
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $0a6c
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
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
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    nop
    add hl, bc
    inc d
    and b
    ld c, e
    call Call_016_4766
    ld h, [hl]
    dec b
    inc e
    ret z

    ld c, e
    inc hl
    ret z

    ld a, [bc]
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $06
    ld hl, sp+$40
    rst $38
    add $0f
    add hl, de
    ld [$0800], sp
    rst $00
    jr @+$4d

    rrca
    add hl, bc

jr_016_4b1a:
    ld a, [bc]
    ld de, $ba00
    dec bc
    ld de, $ba01
    ld a, [bc]
    jr jr_016_4b27

    cp d
    dec bc

jr_016_4b27:
    jr @+$05

    cp d
    inc b
    ld de, $ba04
    dec b
    ld de, $ba05
    inc b
    jr jr_016_4b3b

    cp d
    dec b
    jr jr_016_4b40

    cp d
    dec b

jr_016_4b3b:
    rlca
    nop
    cp h
    ld [bc], a
    dec bc

jr_016_4b40:
    dec de
    ld [$0511], sp
    add hl, bc
    rlca
    ld [de], a
    db $10
    dec d
    rst $38
    jp nc, $d241

    dec b
    ld [de], a
    ld de, $ff12
    db $d3
    ld b, d
    ret c

    ld bc, $1012
    rrca
    rst $38
    pop de
    ld b, e
    ret c

    ld [bc], a
    ld [de], a
    rrca
    dec c
    rst $38
    jp nc, $d244

    ld b, $12
    ld c, $0a
    rst $38
    db $d3
    ld b, l
    ret c

    inc bc
    ld [de], a
    db $10
    rlca
    rst $38
    db $d3
    ld b, [hl]
    jp nc, Jump_016_4307

    ld c, $1e
    rst $38
    ret nc

    rlca
    adc l
    rst $00
    ld a, [bc]
    ld de, $c78d
    dec bc
    ld de, $c791
    ld a, [bc]
    jr jr_016_4b1a

    rst $00
    dec bc
    jr jr_016_4bcc

    rst $00
    inc b
    ld de, $c73f
    dec b
    ld de, $c743
    inc b
    jr jr_016_4bdc

    rst $00
    dec b
    jr jr_016_4bd7

    rst $00
    dec b
    rlca
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    rrca
    rrca
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr nz, jr_016_4bcc

    ld hl, $0a0a
    dec bc
    dec bc
    dec bc
    dec bc
    rrca
    rrca
    ld c, [hl]
    ld bc, $0201

jr_016_4bcc:
    inc bc
    ld bc, $0101
    ld bc, $7d37
    ld a, [hl]
    ld bc, $0b01

jr_016_4bd7:
    dec bc
    dec bc
    dec bc
    rrca
    rrca

jr_016_4bdc:
    ld c, [hl]
    ld bc, $0101
    ld bc, $0a01
    ld a, [bc]
    ld a, [bc]
    jr nz, jr_016_4bf4

    ld hl, $010a
    ld bc, $0101
    ld bc, $0f0f
    ld d, b
    ld [hl], a
    ld [hl], a
    ld [hl], a

jr_016_4bf4:
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld l, b
    ld a, a
    ld l, c
    ld l, a
    ld l, a
    ld l, a
    ld l, a
    ld l, a
    ld h, b
    rrca
    rrca
    ld c, [hl]
    ld sp, $0a0a
    ld sp, $3131
    ld sp, $3731
    ld a, l
    ld a, [hl]
    ld [hl], a
    ld d, [hl]
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld c, [hl]
    ld sp, $0a0a
    ld sp, $3131
    ld sp, $3131
    ld sp, $0f31
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld c, [hl]
    ld sp, $0a0a
    ld sp, $6231
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld c, [hl]
    ld sp, $3108
    ld sp, $4e0a
    dec e
    rra
    rra
    rra
    rra
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    nop
    add hl, bc
    add hl, de
    cp b
    ld c, h
    jp nc, $b969

    ld l, c
    add hl, bc
    inc e
    ld a, d
    ld c, [hl]
    db $eb
    add $0a
    ld a, [bc]
    adc a
    nop
    ld l, c
    rlc a
    sbc d
    ld c, h
    inc b
    rst $00
    rrca
    inc d
    ld [$0300], sp
    rst $00
    db $76
    ld c, h
    ld b, e
    inc b
    ld [$0021], sp
    cp [hl]
    add hl, bc
    ld hl, $be01
    ld [$0228], sp
    cp [hl]
    add hl, bc
    jr z, jr_016_4c8a

    cp [hl]
    ld [bc], a
    rlca

jr_016_4c8a:
    dec hl
    inc b
    dec b
    ld hl, $0305
    rlca
    rrca
    jr z, @+$01

    db $d3
    ld b, c
    rst $18
    ld [$1307], sp
    inc l
    rst $38
    jp nc, $df42

    add hl, bc
    rlca
    ld de, $ff2e
    jp nc, $df43

    ld a, [bc]
    sub h
    rst $00
    ld [$9421], sp
    rst $00
    add hl, bc
    ld hl, $c798
    ld [$9828], sp
    rst $00
    add hl, bc
    jr z, @+$1a

    ld b, e
    ld h, h
    ld sp, $3131
    ld sp, $4365
    ld b, e
    inc d
    ld l, e
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $4318
    ld h, h
    ld sp, $7474
    ld sp, $4365
    ld b, e
    ld b, e
    ld h, h
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $4318
    ld h, h
    ld sp, $7474
    ld sp, $4365
    ld b, e
    ld b, e
    ld h, h
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld d, [hl]
    jr nz, @+$0f

    ld hl, $3131
    ld sp, $3131
    jr jr_016_4d48

    ld h, h
    ld sp, $7474
    ld sp, $7474
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld l, b
    ld a, a
    ld l, c
    ld [hl], a
    ld d, [hl]
    ld [hl], a
    ld [hl], a
    ld [hl], a
    jr jr_016_4d61

    ld h, h
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3731
    ld a, l
    ld a, [hl]
    ld bc, $0101
    ld bc, $1801
    ld b, e
    dec l
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
    rra
    rra
    rra
    rra
    ld h, d
    ld d, c

jr_016_4d48:
    ld d, c
    ld b, b
    ld c, l
    ld d, c
    ld d, c
    ld h, e
    jr jr_016_4d93

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
    ld c, [hl]
    dec bc

jr_016_4d61:
    dec bc
    dec bc
    ld c, l
    ld [hl], h
    ld [hl], h
    ld c, l
    jr @+$45

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
    ld c, [hl]
    dec bc
    dec bc
    dec bc
    ld c, l
    ld [hl], h
    ld [hl], h
    ld c, l
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
    ld d, b
    ld d, d

jr_016_4d93:
    ld d, d
    ld d, d
    ld c, a
    ld d, d
    ld d, d
    ld c, a
    ld hl, $4df5
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_016_4dea

    ld hl, $d27b
    ld b, $13
    call Call_000_1690
    ld a, [$d0e3]
    ldh [$dd], a
    ld b, a
    ldh a, [$db]
    cp b
    jr z, jr_016_4dbd

    jr nc, jr_016_4de0

jr_016_4dbd:
    ld hl, $4f05
    call Call_000_3c79
    ldh a, [$dc]
    ld b, a
    ld c, $01
    call Call_000_3e5e
    jr nc, jr_016_4dd7

    ld hl, $4f44
    call Call_000_3c79
    ld a, $01
    jr jr_016_4df2

jr_016_4dd7:
    ld hl, $4f5f
    call Call_000_3c79
    xor a
    jr jr_016_4df2

jr_016_4de0:
    ld hl, $4e80
    call Call_000_3c79
    ld a, $80
    jr jr_016_4df2

jr_016_4dea:
    ld hl, $4ed3
    call Call_000_3c79
    ld a, $ff

jr_016_4df2:
    ldh [$db], a
    ret


    db $ed
    ld a, [hl+]
    ld d, [hl]
    ld l, l
    or l
    ld a, $b4
    jp $bdcf


    and $4f
    adc $d7
    ld d, [hl]
    rst $20
    ld d, l
    add h
    db $e3
    add [hl]
    inc de
    ld a, a
    jp z, $beb6

    ret


    ld a, a
    inc l
    ld [c], a
    cp h
    pop hl
    ld a, a
    inc sp
    cp l
    ld d, c
    ld d, h
    dec l
    or [hl]
    sbc $26
    ld a, a
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    cp h
    pop hl
    reti


    or d
    ld c, a
    or c
    jp nz, $dfcf

    jp Jump_016_7fd9


    sub $b3
    push bc
    rst $10
    ld d, l
    ld d, b
    ld bc, $cc5b
    nop
    db $dd
    ld a, a
    call c, $bdc0
    ld a, a
    sub $b3
    ld d, l
    jp z, $beb6

    add $7f
    or d
    call c, Call_016_7fda
    rst $08
    cp h
    ret nz

    ld d, c
    ld d, [hl]
    ld a, a
    cp a
    jp c, $ca33

    ld a, a
    cp e
    rst $18
    cp a
    cp b
    ld c, a
    ld d, d
    cp b
    sbc $e7
    ld d, l
    jp nz, $cfb6

    or h
    ret nz

    ld a, a
    ld d, h
    jp z, Jump_016_5055

    add hl, bc
    db $db
    rst $38
    inc de
    nop
    cp h
    pop hl
    reti


    or d
    ld a, a
    sub $d8
    ld a, a
    or l
    or l
    or d
    ld a, a
    or [hl]
    push bc
    and $57
    db $ed
    ld a, [hl+]
    ld d, $6f
    ld a, a
    or h
    db $e3
    call nz, Call_016_4fe7
    jp nz, $cfb6

    or h
    ret nz

    ld a, a
    ld d, h
    jp z, Jump_016_5556

    or c
    jp c, $e3da

    and $55
    rst $08
    jr nc, jr_016_4f1c

    ld d, b
    add hl, bc
    db $dd
    rst $38
    inc de
    nop
    cp h
    pop hl
    reti


    or d
    ld a, a
    inc sp
    cp l
    sub $e7
    ld d, c
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    cp h
    pop hl
    reti


    or d
    add $7f
    ret nz

    ret c

    push bc
    or d
    ld a, a
    push bc
    rst $10
    ld c, a
    ld d, b
    ld bc, $cc5b
    nop
    jp z, $cf55

    ret nz

    ld a, a
    cp d
    sbc $34
    ld a, a
    inc sp
    cp l
    ret z

    ld d, a
    db $ed
    ld a, [hl+]
    adc a
    ld l, a
    ld a, a
    cp a
    or e
    ld a, a
    inc sp
    cp l
    or [hl]
    ld d, c
    ld d, b
    add hl, bc
    db $db
    rst $38
    inc de
    nop
    cp h
    pop hl
    reti


    or d
    add $7f
    ret nz

    ret c

    push bc
    or d
    ld a, a
    push bc
    rst $10
    ld c, a
    ld d, b
    ld bc, $cc5b
    nop
    jp z, $cf55

    ret nz

    ld a, a
    cp d
    sbc $34
    ld a, a
    inc sp
    cp l
    ret z

    ld d, a
    db $ed
    ld a, [hl+]
    inc [hl]
    ld l, [hl]
    ld a, a
    push bc
    reti


    adc $34
    rst $20
    ld c, a
    jp nz, $cfb6

    or h
    ret nz

    ld a, a
    ld d, h
    jp z, Jump_016_5556

    ld d, b
    add hl, bc

jr_016_4f1c:
    db $dd
    rst $38
    inc de
    nop
    cp h
    pop hl
    reti


    or d
    ld a, a
    inc sp
    cp l
    ret z

    rst $20
    ld d, l
    or l
    jp nc, $c433

    or e
    rst $20

jr_016_4f30:
    ld d, c
    cp a
    jp c, $ca33

    ld c, a
    cp d
    jp c, $7fdd

Jump_016_4f3a:
    or l
    call c, $bcc0
    ld a, a
    cp h
    rst $08
    cp l
    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    adc d
    ld l, [hl]
    inc l
    ld [c], a
    cp h
    pop hl
    ld a, a
    or [hl]
    rst $10
    ld c, a
    ld d, b
    ld bc, $cc5b
    nop
    db $dd

Jump_016_4f56:
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    dec bc
    ld d, b
    db $ed
    ld a, [hl+]
    or l
    ld l, [hl]
    ld a, a
    call nz, $b57f
    db $d3
    rst $18
    ret nz

    ld a, a
    cp c
    inc [hl]
    ld c, a
    add $d3
    jp nz, Jump_016_7f26

    or d
    rst $18
    ld b, h
    or d
    ld a, a
    jr nc, jr_016_4f30

    rst $10
    ld d, l
    ld d, b
    ld bc, $cc5b
    nop
    jp z, $cf55

    ret nz

    ld a, a
    cp d
    sbc $34
    ld a, a
    inc sp
    cp l
    ret z

    ld d, a
    ld a, [$cf7f]
    ld [$d092], a
    call Call_000_2f2e
    ld d, $01

jr_016_4f99:
    inc d
    call Call_016_4fb5
    push hl
    ld hl, $cf8f
    ldh a, [$98]
    ld c, a
    ld a, [hl-]
    sub c
    ldh a, [$97]
    ld c, a
    ld a, [hl-]
    sbc c
    ldh a, [$96]
    ld c, a
    ld a, [hl]
    sbc c
    pop hl
    jr nc, jr_016_4f99

    dec d
    ret


Call_016_4fb5:
    ld a, [$d0a8]
    add a
    add a
    ld c, a
    ld b, $00
    ld hl, $5068
    add hl, bc
    call Call_016_505b
    ld a, d
    ldh [$99], a
    call Call_000_38f5

Call_016_4fca:
Jump_016_4fca:
    ld a, [hl]
    and $f0

Jump_016_4fcd:
    swap a
    ldh [$99], a
    call Call_000_38f5
    ld a, [hl+]
    and $0f
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$96]
    push af
    ldh a, [$97]
    push af
    ldh a, [$98]

Jump_016_4fe6:
    push af

Call_016_4fe7:
Jump_016_4fe7:
    call Call_016_505b
    ld a, [hl]
    and $7f
    ldh [$99], a
    call Call_000_38f5
    ldh a, [$96]
    push af
    ldh a, [$97]
    push af
    ldh a, [$98]
    push af
    ld a, [hl+]
    push af
    xor a
    ldh [$96], a
    ldh [$97], a
    ld a, d
    ldh [$98], a
    ld a, [hl+]
    ldh [$99], a
    call Call_000_38f5
    ld b, [hl]
    ldh a, [$98]
    sub b
    ldh [$98], a
    ld b, $00
    ldh a, [$97]
    sbc b
    ldh [$97], a
    ldh a, [$96]
    sbc b
    ldh [$96], a
    pop af
    and $80
    jr nz, jr_016_5036

    pop bc
    ldh a, [$98]
    add b
    ldh [$98], a
    pop bc
    ldh a, [$97]
    adc b
    ldh [$97], a
    pop bc
    ldh a, [$96]
    adc b
    ldh [$96], a
    jr jr_016_5048

jr_016_5036:
    pop bc
    ldh a, [$98]
    sub b
    ldh [$98], a
    pop bc
    ldh a, [$97]
    sbc b
    ldh [$97], a
    pop bc
    ldh a, [$96]
    sbc b
    ldh [$96], a

jr_016_5048:
    pop bc
    ldh a, [$98]
    add b
    ldh [$98], a
    pop bc
    ldh a, [$97]
    adc b
    ldh [$97], a
    pop bc

Jump_016_5055:
    ldh a, [$96]
    adc b
    ldh [$96], a
    ret


Call_016_505b:
    xor a
    ldh [$96], a
    ldh [$97], a
    ld a, d
    ldh [$98], a
    ldh [$99], a
    jp Jump_000_38f5


    ld de, $0000
    nop
    inc [hl]
    ld a, [bc]
    nop
    ld e, $34
    inc d
    nop
    ld b, [hl]
    ld h, l
    adc a
    ld h, h
    adc h
    ld b, l
    nop
    nop
    nop
    ld d, h
    nop
    nop
    nop
    call Call_000_3c6c
    ld hl, $50a7
    ld de, $5093
    ld a, [$d57f]
    call Call_000_31a8
    ld [$d57f], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ldh a, [$50]
    scf
    ld d, c
    add c
    ld d, c
    push de
    ld d, c
    daa
    ld d, d
    add b
    ld d, d
    ret nc

    ld d, d
    ld bc, $4800
    rst $10
    ld a, [$2b50]
    ld d, c
    rra
    ld d, c
    rra
    ld d, c
    ld [bc], a
    nop
    ld c, b
    rst $10
    ld b, c
    ld d, c
    dec hl
    ld d, c
    ld l, h
    ld d, c
    ld l, h
    ld d, c
    inc bc
    ld b, b
    ld c, b
    rst $10
    adc e
    ld d, c
    or d
    ld d, c
    and a
    ld d, c
    and a
    ld d, c
    inc b

Call_016_50cc:
    jr nc, jr_016_5116

    rst $10
    rst $18
    ld d, c
    ld b, $52
    pop af
    ld d, c
    pop af
    ld d, c
    dec b
    jr nc, jr_016_5122

    rst $10
    ld sp, $5e52
    ld d, d
    ld c, l
    ld d, d
    ld c, l
    ld d, d
    ld b, $30
    ld c, b
    rst $10
    adc d
    ld d, d
    xor h
    ld d, d
    and e
    ld d, d
    and e
    ld d, d
    rst $38
    ld [$a721], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    push af
    ld l, [hl]
    rst $20
    ld c, a
    ld a, $b8
    rst $10
    ret


    ld a, a
    res 7, a
    res 7, a
    ld a, a
    ld a, [hl-]
    push bc
    cp h
    db $dd
    ld d, l
    rst $00
    cp l
    ret nc

    ld a, a
    daa
    or a
    ld a, a

jr_016_5116:
    cp h
    jp Jump_016_7fd9


    call nc, $cac2
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld l, c

jr_016_5122:
    ld l, a
    ld a, a
    or [hl]
    jp $b2c5


    sbc $30
    ld e, b
    db $ed
    ld [hl+], a
    cp a
    ld l, a
    ld a, a
    res 7, a
    ld a, a
    res 7, a
    ld d, [hl]
    ld d, a
    ld [$b321], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    add e
    ld l, a
    call nz, $bf7f
    cp d
    ret


    ld a, a
    or a
    ret nc

    rst $20
    ld c, a
    set 0, h
    ret


    ld a, a
    ret nz

    pop bc
    ld a, a
    ld a, [hl-]
    push bc
    cp h
    db $dd
    ld d, l
    rst $00
    cp l
    ret nc

    ld a, a
    daa
    or a
    ld a, a
    cp l
    reti


    db $d3
    sbc $2c
    ldh [$c5], a
    or d
    call c, $ed57
    ld [hl+], a
    dec bc
    ld [hl], b
    ld c, a
    call nc, $dad7
    reti


    ld a, a
    push bc
    sbc $c3
    ld a, a
    push bc
    cp e
    cp c
    push bc
    or d
    call c, Call_000_0858
    ld hl, $50bf
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld a, [hl-]
    ld [hl], b
    call $cfde
    inc sp
    ld a, a
    cp b
    reti


    call nz, $b14f
    sbc $cf
    ret c

    ld a, a
    pop de
    cp h
    db $d3
    ld a, a
    or d
    push bc
    or d
    sbc $30
    ld d, a
    db $ed
    ld [hl+], a
    adc $70
    ld a, a
    add hl, de
    add l
    push bc
    or c
    db $e3
    ld e, b

Call_016_51b2:
    db $ed
    ld [hl+], a
    ld [hl], b
    ld [hl], b
    call nc, Call_016_44df
    ret c

    ld c, a
    pop de
    cp h
    ld a, a
    ld d, h
    ld a, a
    cp l
    or a
    jr nc, @-$42

    ld d, l
    sub e
    add [hl]
    xor c
    ret


    ld a, a
    db $d3
    ret c

    add $7f
    or [hl]
    or h
    db $db
    or e
    or [hl]
    push bc
    ld d, a
    ld [$cb21], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld [$b270], a
    ld c, a
    or l
    jp c, Jump_016_7fc6

    push bc
    sbc $b6
    ld a, a
    sub $b3
    and $57
    db $ed
    ld [hl+], a
    ld [hl], e
    ld [hl], c
    push bc
    or d
    ld c, a
    or e
    rst $10
    jp c, $7fc0

    adc b
    xor e
    add l
    add $7f
    rst $08
    cp c
    ret nz

    ld e, b
    db $ed
    ld [hl+], a
    dec c
    ld [hl], c
    ld a, a
    ret nz

    cp b
    cp e
    sbc $4f
    ld d, h
    ld a, a
    db $d3
    rst $18
    jp $b17f


    reti


    or d
    jp Jump_016_55c0


    adc $b3
    ld h, $7f
    or c
    sbc $bc
    sbc $30
    push bc
    ld d, a
    ld [$d721], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    and a
    ld [hl], c
    and $4f
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    or e
    db $e3
    sbc $55
    jp nz, $b1b7

    rst $18
    jp Jump_016_7fd3


    or d
    or d
    or [hl]
    push bc
    ld d, a
    db $ed
    ld [hl+], a
    ld a, [hl+]
    ld [hl], d
    or e
    db $d3
    ld c, a
    or e
    rst $08
    cp b
    ld a, a
    or d
    or [hl]
    push bc
    or d
    call c, $ed58
    ld [hl+], a
    call nc, $d371
    ld a, a
    jp nz, $b8d6

    ld a, a
    push bc
    ret c

    ret nz

    or d
    ret


    ld c, a
    adc c
    sub c
    db $dd
    ld a, a
    or l
    cp h
    or h
    jp $b87f


    jp c, $b2c5

    ld a, a
    or [hl]
    cp h
    rst $10
    ld d, a
    ld [$e321], sp
    ld d, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a

Call_016_528c:
    ld c, e
    ld [hl], d

jr_016_528e:
    ld a, a
    ret nc

    or [hl]
    cp c
    push bc
    or d
    ld a, a
    or [hl]
    or l
    ld a, a
    jr nc, @-$17

    ld c, a
    jp nz, $b2d6

    ret


    or [hl]
    push bc
    and $57
    db $ed
    ld [hl+], a
    ret nc

    ld [hl], d
    ld a, a
    push bc
    or d
    sub $58
    db $ed
    ld [hl+], a
    ld a, b
    ld [hl], d
    sub $dc
    or d
    ret


    or [hl]
    ld c, a
    ld a, $b8
    ret


    ld a, a
    or e
    inc sp
    ld h, $7f
    call c, $b2d9
    ret


    or [hl]
    ld d, [hl]
    ld d, l
    inc [hl]
    rst $18
    pop bc
    jr nc, jr_016_528e

    ld a, a
    or l
    db $d3
    or e
    and $57
    db $ed
    ld [hl+], a
    xor b
    ld l, [hl]
    rst $10
    ld a, a
    pop bc
    or [hl]
    jp nz, $dbb3

    ld c, a
    sbc c
    sub h
    rrca
    ld a, a
    adc e
    sub d
    or b
    ld a, a
    ld d, [hl]
    ld a, a
    add a
    sub b
    add hl, de
    ld a, a
    adc e
    sub d
    or b
    ld d, a
    call Call_000_3c6c
    ld hl, $531b
    ld de, $5301
    ld a, [$d580]
    call Call_000_31a8
    ld [$d580], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    adc b
    ld d, e
    call nc, Call_000_2353
    ld d, h
    add d
    ld d, h
    db $e3
    ld d, h
    ld d, [hl]
    ld d, l
    xor e
    ld d, l
    add hl, de
    ld d, [hl]
    ld a, c
    ld d, [hl]
    ld hl, sp+$56
    ld bc, $4c40
    rst $10
    sub d
    ld d, e
    cp d
    ld d, e
    xor a
    ld d, e
    xor a
    ld d, e
    ld [bc], a
    ld b, b
    ld c, h
    rst $10
    sbc $53
    ld a, [bc]
    ld d, h
    push af
    ld d, e
    push af
    ld d, e
    inc bc
    ld b, b
    ld c, h
    rst $10
    dec l
    ld d, h
    ld d, l
    ld d, h
    ld c, d
    ld d, h
    ld c, d
    ld d, h
    inc b
    jr nz, @+$4e

    rst $10
    adc h
    ld d, h
    or e
    ld d, h
    xor c
    ld d, h
    xor c
    ld d, h
    dec b
    jr nc, @+$4e

    rst $10
    db $ed
    ld d, h
    dec de
    ld d, l
    ld [bc], a
    ld d, l
    ld [bc], a
    ld d, l
    ld b, $30
    ld c, h
    rst $10
    ld h, b
    ld d, l
    adc c
    ld d, l
    add c
    ld d, l
    add c
    ld d, l
    rlca
    jr nz, jr_016_53b2

    rst $10
    or l
    ld d, l
    jp hl


    ld d, l
    db $d3
    ld d, l
    db $d3
    ld d, l
    ld [$4c20], sp
    rst $10
    inc hl
    ld d, [hl]
    ld d, b
    ld d, [hl]
    dec sp
    ld d, [hl]
    dec sp
    ld d, [hl]
    add hl, bc
    ld b, b
    ld c, h
    rst $10
    add e
    ld d, [hl]
    call nz, $a656
    ld d, [hl]
    and [hl]
    ld d, [hl]
    rst $38
    ld [$1b21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld l, e
    ld [hl], e
    ld d, h
    ld a, a
    jp nz, $bfd6

    or e
    ld a, a
    jr nc, @-$45

    inc [hl]
    ld c, a
    ret c

    or [hl]
    jp z, $c47f

    cp b
    or d
    ld a, a
    push bc
    ret


    or [hl]
    or d
    and $57
    db $ed
    ld [hl+], a
    db $db

jr_016_53b2:
    ld [hl], e
    rst $20
    ld a, a
    ld a, [hl-]
    rst $18
    ret nz

    ret c

    ld e, b
    db $ed
    ld [hl+], a
    xor e
    ld [hl], e
    ld a, a
    call nc, Call_016_44df
    ret c

    ld c, a
    dec a
    sbc $b7
    ld [c], a
    or e
    ret


    ld a, a
    adc $b3
    ld h, $7f
    or c
    rst $18
    jp Jump_016_57d9


    ld [$2721], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    db $ec
    ld [hl], e
    ldh [$e7], a
    ld c, a
    ret nz

    ret nz

    or [hl]
    rst $18
    jp $b37f


    sbc $30
    jp nc, $7fbc

    cp l
    reti


    or [hl]
    ld d, a
    db $ed
    ld [hl+], a
    ld h, l
    ld [hl], h
    ld [c], a
    or e
    jp z, $bc4f

    ld [c], a
    or e
    inc a
    ld a, a
    or e
    sbc $7f
    call c, $bcd9
    rst $20
    ld e, b
    db $ed
    ld [hl+], a
    ld c, $74
    ld a, a
    or a
    ld [c], a
    or e
    jp z, $c27f

    or d
    jp $b4c8


    ld c, a
    inc l
    rst $18
    call nz, $bc7f

jr_016_541f:
    jp $b3d6


    ld d, a
    ld [$3321], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    add e
    ld [hl], h
    ld c, a
    ret nz

    ret nz

    or [hl]
    or d
    ld a, a
    add $ca
    ld a, a
    cp [hl]
    sbc $d8
    ldh [$b8], a
    ld h, $55
    set 0, d
    sub $b3
    ld a, a
    push bc
    sbc $30
    ld d, a
    db $ed
    ld [hl+], a
    dec [hl]
    ld [hl], l
    ld a, a

Call_016_544f:
    inc sp
    or a

jr_016_5451:
    push bc
    or d
    rst $20
    ld e, b

Jump_016_5455:
    db $ed
    ld [hl+], a
    or l
    ld [hl], h
    add $7f
    dec a
    sub e
    dec a
    adc a
    db $e3
    ld a, a
    jr nc, jr_016_541f

    jp Jump_016_4f56


    or d
    or d
    call nc, $ce7f
    or [hl]
    ret


    inc sp
    ld a, a
    or d
    rst $18
    or a
    add $56
    ld d, l
    ld d, [hl]
    ld a, a
    or e
    db $e3
    sbc $7f
    dec de
    sub c
    ld a, a
    dec de
    sub c
    ld d, [hl]
    ld d, a
    ld [$3f21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld d, d
    ld [hl], l
    ld a, a
    sub l
    inc de
    and l
    xor e
    ld a, a
    cp l
    or a
    ld a, a
    jr nc, jr_016_5451

    rst $10
    ld c, a
    ret nz

    cp b
    cp e
    sbc $7f
    or c
    jp nz, $c3d2

    reti


    ret


    ld d, a
    db $ed
    ld [hl+], a
    jp hl


    ld [hl], l
    ld a, a
    push bc
    sbc $33
    db $e3
    ld e, b
    db $ed
    ld [hl+], a
    add c
    ld [hl], l
    ld a, a
    cp a
    jr nc, @-$1f

    jp $b87f


    reti


    call nz, $b64f
    call c, $b8b2
    ld a, a
    push bc
    cp b
    push bc
    rst $18
    jp $b77f


    pop bc
    ldh [$b3], a
    ld d, l
    cp h
    sbc $b6
    ld a, a
    cp h
    push bc
    or d

Call_016_54d8:
    adc $b3
    ld h, $7f
    or [hl]
    call c, $b2b2
    call c, Call_016_57e7
    ld [$4b21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    push af
    ld [hl], l
    ld [c], a
    or e
    db $d3
    ld a, a
    or d
    or d
    cp c
    inc [hl]
    ld d, [hl]
    ld c, a
    ld d, h
    db $d3
    ld a, a
    or d
    or d
    ret z

    ld d, a
    db $ed
    ld [hl+], a
    ret z

    db $76
    or [hl]
    rst $18
    ret nz

    ld c, a
    ld a, $b8
    add $ca
    ld a, a
    dec a
    sbc $b7
    ld [c], a
    or e
    ld a, a
    cp h
    or [hl]
    ld a, a
    push bc
    or d
    ld e, b
    db $ed
    ld [hl+], a
    ld l, $76
    jp z, $bf7f

    call nz, Call_016_7fc9
    cp b
    or e
    or a
    ld a, a
    cp l
    or d
    add $4f
    or d
    cp d
    or e
    call nz, $b57f
    db $d3
    rst $18
    ret nz

    ret


    add $55
    and d

Jump_016_553a:
    sbc l
    dec de
    add [hl]
    ret


    ld a, a
    ld [$93e3], sp
    ret


    ld a, a
    cp [hl]
    or d
    inc sp
    ld d, l
    ret nc

    sbc $c5
    ld a, a
    cp d
    cp d
    inc sp
    ld a, a
    or c
    cp h
    inc [hl]
    jp nc, Jump_016_5730

Call_016_5556:
Jump_016_5556:
    ld [$5721], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    rst $28
    db $76
    adc h
    ld a, a
    rst $18
    jp $c14f


    ld [c], a
    db $e3
    ld a, a
    or [hl]
    call c, $e3b2
    ret


    rst $20
    ld d, l
    add $e0
    db $e3
    ld a, a
    add $e0
    db $e3
    ld a, a
    add $e0
    db $e3
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld [hl], b
    ld [hl], a
    ldh [$e3], a
    rst $20
    ld e, b
    db $ed
    ld [hl+], a
    rra
    ld [hl], a
    rst $20
    ld c, a
    ld b, e
    xor h
    ld b, e
    db $d3
    ld a, a
    adc c
    and l
    xor h
    adc a
    db $d3
    ld a, a
    or [hl]
    call c, $e3b2
    ld d, l
    or c
    ret nz

    cp h
    ld a, a
    rst $08
    sub $df
    pop bc
    ldh [$b3], a
    rst $20
    ld d, a
    ld [$6321], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a

Call_016_55b7:
    db $76
    ld [hl], a
    jp $c57f


    rst $10
    sbc $33
    reti


Jump_016_55c0:
    call nz, $ca4f
    push bc
    or d
    pop bc
    ld a, a
    db $d3
    sbc $d2

Jump_016_55ca:
    ld a, a
    cp h
    jp Jump_016_7fd9


    ret nc

    ret nz

    or d
    ld d, a
    db $ed
    ld [hl+], a
    ld b, a
    ld a, b
    or d
    rst $20
    ld c, a
    ret nc

    sbc $c5

Jump_016_55dd:
    ld a, a
    or [hl]
    call c, $b2b2
    ld a, a
    ld d, h
    ld a, a
    push bc
    ret


    add $58
    db $ed
    ld [hl+], a
    xor a
    ld [hl], a
    add [hl]
    ld a, a
    adc e
    sub d
    or b
    ret


    ld a, a
    cp c
    or d
    dec sp
    or d
    sbc $4f
    ld [$93e3], sp
    ld a, a
    call nz, $d7b5
    cp [hl]
    jp $b87f


    jp c, $b2c5

    ret


    ld d, l
    rst $08
    inc l
    jp nc, $307f

    cp c
    inc [hl]
    ld d, [hl]
    ld a, a
    or d
    inc l
    call c, $c8d9
    ld d, a
    ld [$6f21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld l, l
    ld a, b
    ld a, a
    or d
    rst $08
    inc [hl]
    or a
    ld c, a
    cp e
    cp l
    rst $10
    or d
    ret


    ld a, a

Call_016_5633:
    ld b, $ad
    xor e
    dec de
    and l
    db $e3
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld a, [bc]
    ld a, c
    cp d
    cp d
    ld a, a
    or d
    pop bc
    ld a, [hl-]
    sbc $dd
    ld a, a
    ret


    ld h, $bd
    ld a, a
    call nz, $e7ca
    ld e, b
    db $ed
    ld [hl+], a
    adc [hl]
    ld a, b
    dec de
    and [hl]
    db $d3
    ld a, a
    ld d, h
    db $d3
    ld c, a
    cp h
    ld [c], a
    or e
    inc a
    add $ca
    ld a, a
    or [hl]
    call c, $c5d8
    or d
    rst $20
    ld d, l
    jp z, $d22c

    ret nz

jr_016_566d:
    rst $10
    ld a, a
    call nc, $d7d2
    jp c, $c57f

    or d
    ret


    cp e
    ld d, a
    ld [$7b21], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    dec hl
    ld a, c
    rst $18
    jp $cc7f


    call c, $dccc
    inc sp
    ld c, a
    rst $00
    or d
    jr z, jr_016_566d

    ret nc

    ld a, a
    ret nc

    ret nz

    or d
    push bc
    ld a, a
    ld d, h
    rst $20
    ld d, l
    ld d, [hl]
    ld a, a
    push bc
    db $e3
    sbc $30
    and $57
    db $ed
    ld [hl+], a
    rrca
    ld a, d
    db $e3
    rst $20
    ld d, c
    call c, $bcc0
    ret


    ld a, a
    ld b, c
    xor h
    ld b, c

jr_016_56b5:
    add $4f
    rst $10
    sbc $3e
    or e
    ld a, a
    cp h
    push bc
    or d
    inc sp
    sub $b3
    rst $20

Jump_016_56c3:
    ld e, b
    db $ed

Jump_016_56c5:
    ld [hl+], a
    ld h, d
    ld a, c
    or d
    cp h

Jump_016_56ca:
    inc sp
    ld a, a
    ld b, c
    xor h
    ld b, c
    ld h, $7f
    push bc
    sbc $b6
    add $4f
    cp h
    sbc $b6
    ld a, a
    cp l
    reti


    rst $18
    jp Jump_016_5455


    ld a, a
    dec bc
    xor l
    db $e3
    sub h
    and [hl]
    inc sp
    ld a, a
    sub $de
    jr nc, jr_016_56b5

    ld d, l
    ld d, [hl]
    ld a, a
    adc $de
    call nz, $b67f
    cp h
    rst $10
    and $57
    db $ed
    ld [hl+], a
    ld a, [hl+]
    ld [hl], e
    rst $10
    ld a, a
    pop bc
    or [hl]
    jp nz, $dbb3

    ld c, a
    adc a
    sbc l
    sbc a
    adc e
    ld a, a
    ld d, [hl]
    ld a, a
    adc e
    add h
    xor e
    ld d, a
    call Call_000_3c6c
    ld hl, $573c
    ld de, $5722
    ld a, [$d584]
    call Call_000_31a8
    ld [$d584], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    add l
    ld d, a
    jp hl


    ld d, a
    ccf
    ld e, b
    adc e
    ld e, b

Jump_016_5730:
    jp hl


    ld e, b
    ld a, [hl-]
    ld e, c
    xor e
    ld e, c
    xor a
    rrca
    xor e
    ld e, c
    cp d
    ld e, c
    ld bc, $5040
    rst $10
    adc a
    ld d, a
    adc $57
    cp l
    ld d, a
    cp l
    ld d, a
    ld [bc], a
    jr nc, jr_016_579b

    rst $10
    di
    ld d, a
    inc h
    ld e, b
    cp $57
    cp $57
    inc bc
    ld b, b
    ld d, b
    rst $10
    ld c, c
    ld e, b
    ld [hl], d
    ld e, b
    ld e, a
    ld e, b
    ld e, a
    ld e, b
    inc b
    jr nc, jr_016_57b3

    rst $10
    sub l
    ld e, b
    ret z

    ld e, b
    cp b
    ld e, b
    cp b
    ld e, b
    dec b
    jr nz, jr_016_57bf

    rst $10
    di
    ld e, b
    jr nz, jr_016_57cd

    ld c, $59
    ld c, $59
    ld b, $20
    ld d, b
    rst $10
    ld b, h
    ld e, c
    add b
    ld e, c
    ld h, [hl]
    ld e, c
    ld h, [hl]
    ld e, c
    rst $38
    ld [$3c21], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld h, l
    ld b, l
    ld a, a
    call nz, Call_016_7fba
    rst $08
    inc sp
    ld a, a
    cp b

jr_016_579b:
    reti


    ld a, a
    call nz, Call_016_4fca
    or a
    ret nc

    db $d3
    ld a, a
    sbc l
    sub l
    add b
    and $7f
    ld d, [hl]
    ld a, a
    inc l
    ldh [rHDMA5], a
    ld a, $b8
    ret


    ld a, a
    adc c

jr_016_57b3:
    and a
    add a
    adc e
    xor a
    xor e
    ld a, a
    ret nc

    reti


    and $57
    db $ed
    inc hl

jr_016_57bf:
    dec hl
    ld b, [hl]
    ld d, [hl]
    rst $20
    ld c, a
    cp b
    call nc, $b8bc

Call_016_57c8:
Jump_016_57c8:
    ld a, a
    push bc
    or d
    sub $e7

jr_016_57cd:
    ld e, b
    db $ed
    inc hl
    jp nc, Jump_016_7f45

    or [hl]
    or h
    jp c, Jump_016_7f3a

    db $d3

Jump_016_57d9:
    rst $18
    call nz, $d24f
    dec l
    rst $10
    cp h
    or d
    ld a, a
    ld d, h
    ld a, a
    or c
    reti


    db $d3

Call_016_57e7:
Jump_016_57e7:
    sbc $57
    ld [$4821], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld c, e
    ld b, [hl]
    ld a, a
    jp z, $cadf

    xor h
    rst $20
    ld d, a
    db $ed
    inc hl
    or c
    ld b, [hl]
    ld c, a
    jp z, $ace3

    ld a, a
    jp z, $acca

    ld d, [hl]
    rst $20
    ld a, a
    inc l
    jp nz, Jump_016_56ca

    ld d, l
    call c, $b2d7
    ld a, a
    add [hl]
    sbc b
    adc c

jr_016_5819:
    ld a, a
    ret nz

    dec a
    jp $bc7f


    rst $08
    rst $18
    jp Jump_016_58c5


    db $ed
    inc hl
    ld d, l
    ld b, [hl]
    xor h
    rst $20
    ld c, a
    jp z, $ace3

    ld a, a
    jp z, $7fdf

    jp z, $e7ac

    ld d, l
    ld d, [hl]
    ld a, a
    jp z, Jump_016_7fe9

    jp z, $56e9

    ld d, a
    ld [$5421], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ldh a, [rDMA]
    ret z

    db $e3
    rst $20
    ld c, a
    or l
    ret nz

    cp b
    ld a, a
    ld a, $b8
    ret


    ld a, a
    ld d, h
    ld a, a
    ret nc

jr_016_585c:
    reti


    and $57
    db $ed
    inc hl
    ld h, c
    ld b, a
    rst $20
    ld c, a
    jr nc, jr_016_5819

    inc l
    push bc
    ld a, a
    ld d, h
    ld a, a
    pop bc
    ldh [$de], a
    ld h, $e7
    ld e, b
    db $ed
    inc hl
    dec d
    ld b, a
    cp b
    ld a, a
    sub $d8
    ld c, a
    jp nz, $b2d6

    ld a, a
    and d
    sub c
    jp z, $867f

    and l
    add c
    ld a, a
    jr nc, jr_016_585c

    sbc $57
    ld [$6021], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    add c
    ld b, a
    db $d3
    ld a, a
    ret nz

    rst $08
    add $4f
    ld d, h
    ld a, a
    dec bc
    sbc a
    add $7f
    or d
    cp b
    ret


    rst $20
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    rst $08
    cp c
    pop bc
    ldh [$b3], a
    ld a, a
    cp c
    inc [hl]

Call_016_58b6:
    ret z

    ld d, a
    db $ed
    inc hl
    inc h
    ld c, b
    rst $20
    ld c, a
    call nz, $b8df
    sbc $7f
    cp h
    ret nz

Jump_016_58c5:
    ret


    add $58

Jump_016_58c8:
    db $ed
    inc hl
    or a
    ld b, a
    rst $20
    ld c, a
    cp d
    sbc $c5
    ld a, a
    call nc, Call_016_7fcf
    ret nc

    pop bc
    add $55
    sbc l
    sub l
    add b
    ld h, $7f
    or d
    reti


    ld a, a
    ret


    sub $56
    ld a, a
    ret nc

    ret nz

Call_016_58e7:
    and $57
    ld [$6c21], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld b, l
    ld c, b
    db $e3
    ld a, a
    cp l
    db $e3
    jp z, $e7e3

    ld c, a
    call nc, $c9cf
    ld a, a
    cp b
    or e
    or a
    jp z, $b37f

    rst $08
    or d
    xor h
    rst $20
    ld d, a
    db $ed
    inc hl
    db $eb
    ld c, b
    db $e3
    xor h
    rst $20
    ld c, a
    or c
    db $e3
    ld a, a
    rst $08
    cp c
    ret nz

    call c, $e7b2
    ld e, b
    db $ed
    inc hl
    ld [hl], b
    ld c, b
    ld a, a
    cp b
    or e
    or a
    ld c, a
    cp l
    or d
    ld a, a
    cp l
    daa
    jp $ca7f


    rst $10
    ld h, $7f
    call z, $dab8
    ret nz

    rst $20
    ld d, a
    ld [$7821], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    rlca
    ld c, c
    rst $20
    ld c, a
    call nc, $d0cf
    pop bc
    ld a, a
    res 7, e
    cp h
    inc a
    ret c

    add $7f
    or c
    reti


    or d
    jp $cb55


    sbc $b9
    jp nz, Jump_000_277f

    ret nc

    ld a, a
    push bc
    ret


    ld d, a
    db $ed
    inc hl
    rst $30
    ld c, c
    ld a, a
    ret nz

    or d
    pop bc
    ld [c], a
    or e
    ld h, $4f
    call c, $b2d9
    or [hl]
    rst $10
    ld a, a
    cp h
    or [hl]
    ret nz

    ld a, a
    push bc
    or d
    call c, $ed58
    inc hl
    ld l, d
    ld c, c
    ld a, a
    ld d, h
    rst $18
    jp Jump_000_2a4f


    jp nz, $c9b2

    ld a, a
    ld a, [hl-]
    rst $18
    or [hl]
    ret c

    ld d, [hl]
    ld d, l
    ld b, c
    xor e
    add a
    ret


    ld a, a
    jp z, $26c5

    rst $10
    ret


    ld d, l
    ld d, h
    ld h, $7f
    or d
    jp c, Jump_016_7f3a

    or d
    or d
    ret


    add $57
    db $ed
    inc hl
    dec hl
    ld b, l
    ld a, a
    add c
    xor c
    and d
    sbc l
    ld a, a
    sub e
    xor e
    sub a
    and [hl]
    ld d, a
    db $ed
    inc hl
    ld c, h
    ld b, l
    ld a, a
    pop de
    inc l
    sbc $7f
    jp z, Jump_000_33c2

    sbc $bc
    ld [c], a
    ld d, a
    call Call_000_3c6c
    ld hl, $59f9
    ld de, $59dd
    ld a, [$d5a2]
    call Call_000_31a8
    ld [$d5a2], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld [hl], d
    ld e, d
    cp b
    ld e, d
    inc de
    ld e, e
    ld h, a
    ld e, e
    cp h
    ld e, e
    dec e
    ld e, h
    ld [hl], a
    ld e, h
    jp z, Jump_016_475c

    ld e, l
    sub [hl]
    ld e, l
    db $ed
    ld e, l
    ld bc, $5430
    rst $10
    ld a, h
    ld e, d
    sbc l
    ld e, d
    adc h
    ld e, d
    adc h
    ld e, d
    ld [bc], a
    jr nz, jr_016_5a5c

    rst $10
    jp nz, $f85a

    ld e, d
    ld [c], a
    ld e, d
    ld [c], a
    ld e, d
    inc bc
    jr nc, jr_016_5a68

    rst $10
    dec e
    ld e, e
    ld c, e
    ld e, e
    dec sp
    ld e, e
    dec sp
    ld e, e
    inc b
    jr nc, @+$56

    rst $10
    ld [hl], c
    ld e, e
    and b
    ld e, e
    adc e
    ld e, e
    adc e
    ld e, e
    dec b
    ld b, b
    ld d, h
    rst $10
    add $5b
    ld b, $5c
    ld [$ea5b], a
    ld e, e
    ld b, $30
    ld d, h
    rst $10
    daa
    ld e, h
    ld d, [hl]
    ld e, h
    ld b, l
    ld e, h
    ld b, l
    ld e, h
    rlca
    jr nc, jr_016_5a98

    rst $10
    add c
    ld e, h
    xor c
    ld e, h
    sbc b
    ld e, h
    sbc b
    ld e, h
    ld [$5440], sp
    rst $10
    call nc, $185c
    ld e, l
    ei
    ld e, h
    ei
    ld e, h
    add hl, bc
    jr nc, jr_016_5ab0

jr_016_5a5c:
    rst $10
    ld d, c
    ld e, l
    add c
    ld e, l
    ld l, d
    ld e, l
    ld l, d
    ld e, l
    ld a, [bc]
    ld b, b
    ld d, h

jr_016_5a68:
    rst $10
    and b
    ld e, l
    call nc, $bf5d
    ld e, l
    cp a
    ld e, l
    rst $38
    ld [$f921], sp
    ld e, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld b, e
    ld c, d
    ld a, a
    rst $08
    cp c
    reti


    or [hl]
    ld a, a
    cp h
    ld [c], a
    or e
    inc a

jr_016_5a8a:
    rst $20
    ld d, a
    db $ed
    inc hl
    or l

jr_016_5a8f:
    ld c, d
    ld c, a
    or a
    ld [c], a
    or e
    jp z, $c27f

    or d

jr_016_5a98:
    jp $c57f


    or d
    ld e, b
    db $ed

jr_016_5a9e:
    inc hl
    ld l, c
    ld c, d
    inc l
    sbc $be
    or d
    ld a, a
    jr nc, jr_016_5a8f

    ld c, a
    inc l
    sbc $be
    or d
    jp z, $067f

jr_016_5ab0:
    xor l
    xor e
    dec de
    and [hl]
    ld a, a
    jr nc, jr_016_5a9e

    ld d, a
    ld [$0521], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    push de
    ld c, d
    inc a

jr_016_5ac7:
    ld a, a
    ld a, [hl+]
    call nz, Call_016_7f26
    cp l
    or a
    inc sp
    sub $e7
    ld c, a
    jr nc, jr_016_5a8a

    rst $10
    ld a, a
    or c
    or d
    jp $7fca


    or h
    rst $10
    ld a, [hl-]
    ret z

    or h
    rst $20
    ld d, a
    db $ed
    inc hl
    sub e
    ld c, e
    rst $20
    ld c, a
    or [hl]
    jp $c4d9


    ld a, a
    call z, Call_000_30de
    ld a, a
    ld h, $7f
    jr nc, jr_016_5ac7

    or [hl]
    rst $20
    ld e, b
    db $ed
    inc hl
    ld hl, $7f4b
    cp d
    call c, $df26
    jp $c07f


    rst $10
    ld c, a
    ld d, h
    jp z, $337f

    or a
    ret z

    or h
    ld a, a
    db $d3
    sbc $c5
    rst $20
    ld d, a
    ld [$1121], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    jp nz, Jump_000_2d4b

    reti


    jp z, $c57f

    cp h
    ld a, a
    jr nc, @-$28

    rst $20
    ld c, a
    cp [hl]
    or d
    cp [hl]
    or d
    ld a, a
    inc [hl]
    or e
    inc [hl]
    or e
    ld a, a
    call nc, $b3db
    rst $20
    ld d, a
    db $ed
    inc hl
    ld b, l
    ld c, h
    and $4f
    cp d
    sbc $c5
    ld a, a
    jp z, Jump_000_2c2d

    ldh [rRP], a
    ld e, b
    db $ed
    inc hl
    ld bc, $b24c
    ld a, a
    inc [hl]
    or e
    inc [hl]
    or e
    ld a, a
    call nc, $c0df
    rst $20
    ld c, a
    cp d
    or e
    or [hl]
    or d
    jp z, $bc7f

    push bc
    or d
    sub $e7
    ld d, a
    ld [$1d21], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld h, l
    ld c, h
    jp z, Jump_016_4fe7

    or l
    ret nz

    cp b
    ret


    ld a, a
    inc sp
    sbc $b7
    ld a, a
    or c
    sbc $2e
    sbc $7f
    inc sp
    cp l
    or [hl]
    and $57
    db $ed
    inc hl
    cp $4c
    sbc $dd
    ld c, a
    rst $08
    or [hl]
    cp l
    ld a, a
    push bc
    sbc $c3
    ld a, a
    cp l
    ld a, [hl+]
    or d
    push bc
    rst $20
    ld e, b
    db $ed
    inc hl
    adc b
    ld c, h
    call nz, $b27f
    or d
    ld a, a
    call c, $dabd
    jp $e7c0


    ld c, a
    inc sp
    sbc $b7
    jp z, $c07f

    or d
    cp [hl]
    jp nz, $e7c6

    ld d, a
    ld [$2921], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    add hl, sp
    ld c, l
    ld a, a
    ld d, h
    ld a, a
    ld e, l
    add $4f
    push bc
    rst $18
    ret nz

    ld a, a
    ld a, [hl-]
    or [hl]
    ret c

    ld a, a
    jr nc, @-$17

    ld d, l

jr_016_5bdb:
    inc sp
    db $d3
    ld a, a
    or [hl]
    jp nz, Jump_000_2c7f

    cp h
    sbc $7f
    or c
    reti


    sub $e7
    ld d, a
    db $ed
    inc hl
    sub $4d
    ld a, a
    push bc
    sbc $c3
    ld d, [hl]
    ld a, a
    rst $08
    jr nc, jr_016_5c46

    ld d, h
    ld a, a
    cp a
    jr nc, jr_016_5bdb

    jp $c57f


    or d
    ret


    or [hl]
    ld a, a
    push bc
    or c
    ld e, b
    db $ed
    inc hl
    ld a, [hl]
    ld c, l
    sub $e3
    ld c, a
    or l
    rst $08
    or h
    push bc
    sbc $b6
    ld a, a
    or c
    rst $18
    pop bc
    or d
    cp c
    sub $e3
    rst $20
    ld d, a
    ld [$3521], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld c, $4e
    jp z, $7fe7

    call c, $bcc0
    jp z, $b24f

    rst $08
    rst $08
    inc sp
    ld a, a
    rst $08
    cp c
    ret nz

    ld a, a
    cp d
    call nz, Call_016_7f26
    push bc
    or d
    cpl
    rst $20
    ld d, a
    db $ed

jr_016_5c46:
    inc hl
    rst $00
    ld c, [hl]
    ld c, a
    jp z, $d22c

jr_016_5c4d:
    jp $cf7f


    cp c
    ret nz

    db $e3
    xor h
    rst $20
    ld e, b
    db $ed
    inc hl
    ld l, $4e
    inc a
    jp z, $c47f

    or a
    ret


    ld a, a
    or e
    sbc $7f
    jr nc, jr_016_5c4d

    ld c, a
    cp a
    or e
    ld a, a
    or l
    db $d3
    call c, $b2c5
    call nz, $b57f
    pop bc
    cp d
    pop de
    sub $57
    ld [$4121], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld [$ca4e], a
    ld c, a
    or d
    rst $08
    rst $08
    inc sp
    ld a, a
    or [hl]
    rst $18
    ret nz

    ld a, a
    cp d
    call nz, Call_016_7f26
    push bc
    or d
    ld d, [hl]
    ld d, a
    db $ed
    inc hl
    sub [hl]
    ld c, a
    cp b
    rst $20
    ld c, a
    call nc, Call_016_44df
    ret c

    ld a, a
    rst $08
    cp c
    ret nz

    rst $20
    ld e, b
    db $ed
    inc hl
    add hl, bc
    ld c, a
    inc a
    jp z, $c47f

    or a
    ret


    ld a, a
    or e
    sbc $7f
    jr nc, jr_016_5d0f

    ld c, a
    cp a
    or e
    ld a, a
    or l
    db $d3
    call c, $b2c5
    call nz, $b57f
    pop bc
    cp d
    pop de
    sub $57
    ld [$4d21], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    xor a
    ld c, a
    ld a, a
    add a
    and l
    adc h
    inc sp
    ld a, a
    or d
    pop bc
    ld a, [hl-]

jr_016_5ce1:
    sbc $7f
    jp nz, $b2d6

    rst $20

jr_016_5ce7:
    ld c, a
    rst $08
    or d
    or c
    cp e
    ld a, a
    jp c, $bcde

    pop hl
    or e
    db $d3
    ld a, a
    cp h
    jp $ded9


    jr nc, jr_016_5ce1

    ld d, a
    db $ed
    inc hl
    adc e

jr_016_5cfe:
    ld d, b
    db $e3
    rst $20
    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    rst $18
    call nz, $c24f
    sub $b2
    ld a, a
    ld d, h
    ld a, a
    inc sp

jr_016_5d0f:
    push bc
    or a
    ldh [$7f], a
    jr nc, jr_016_5ce7

    jr nc, jr_016_5cfe

    ld e, b
    db $ed
    inc hl
    push af
    ld c, a
    ld a, a
    call nc, $b6cf
    rst $10
    ld a, a
    or l
    ret c

    jp $d9b8


    ld c, a
    call z, $dfc4
    ret nz

    ld a, a
    ld d, h
    ld d, [hl]
    ld d, c
    or c
    jp c, $c27f

    or [hl]
    rst $08
    or h
    ret nz

    rst $10
    ld c, a
    jp nz, $b2d6

    sbc $2c
    ldh [$7f], a
    push bc
    or d
    or [hl]
    push bc
    and $57
    ld [$5921], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    jp $8c50


    rst $20
    ld c, a
    inc sp
    sbc $b7
    ret


    ld a, a
    cp c
    cp h
    call c, $dabd
    ld a, a
    cp h
    jp $c57f


    or d
    or [hl]
    ld d, a
    db $ed
    inc hl

jr_016_5d6c:
    ld [hl], b
    ld d, c
    ret nz

    rst $20
    ld c, a
    cp e
    or d
    or a
    sbc $c9
    ld a, a
    cp d
    inc [hl]
    db $d3
    jp z, $c27f

    sub $b2
    rst $20
    ld e, b
    db $ed
    inc hl
    rst $38
    ld d, b
    ld d, [hl]
    ld c, a
    inc sp
    sbc $b7
    cp d
    or e
    inc l
    add $7f
    or d
    or [hl]
    push bc
    cp b
    pop bc
    ldh [$57], a
    ld [$6521], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    or c
    ld d, c
    add $7f
    cp a
    jr nc, jr_016_5d6c

    ret nz

    ld a, a
    ld d, h
    rst $20
    ld c, a
    cp a
    db $db
    cp a
    db $db
    ld a, a
    ret nz

    ret nz

    or [hl]
    call c, $c3be
    ld a, a
    ret nc

    sub $b3
    rst $20
    ld d, a
    db $ed
    inc hl
    ld e, c
    ld d, d
    add c
    ld d, [hl]
    rst $20
    ld c, a
    or c
    ret c

    ld h, $c4
    or e
    ld a, a
    cp e
    sub $b3
    push bc
    rst $10
    rst $20
    ld e, b
    db $ed
    inc hl
    ld b, $52
    ld d, [hl]
    rst $20
    ld c, a
    db $d3
    rst $18
    call nz, $c27f
    sub $b2
    ret


    ld a, a
    cp e
    ld h, $bc
    jp $ba7f


    sub $b3
    ld d, a
    db $ed
    inc hl
    dec hl
    ld c, d
    rrca
    ret


    ld a, a
    or c
    push bc
    ld d, a
    call Call_000_3c6c
    ld hl, $5e95
    ld de, $5e15
    ld a, [$d5a3]
    call Call_000_31a8
    ld [$d5a3], a
    ret


jr_016_5e0a:
    xor a
    ld [$cd66], a
    ld [$d5a3], a
    ld [$d97c], a
    ret


    dec e
    ld e, [hl]
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld d, b
    ld e, [hl]
    ld hl, $d757
    bit 7, [hl]
    jp nz, Jump_000_3261

    bit 6, [hl]
    res 6, [hl]
    jp z, Jump_000_3261

    ld a, $0d
    ldh [$8c], a
    call Call_000_13f1
    ld a, $84
    ld [$d036], a
    ld a, $1e
    ld [$d0ec], a
    ld a, $1d
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $03
    ld [$d5a3], a
    ld [$d97c], a
    ret


    ld a, [$d034]
    cp $ff
    jr z, jr_016_5e0a

    call Call_000_0ebd
    ld a, [$cf06]
    cp $02
    jr z, jr_016_5e68

    ld a, $0e
    ldh [$8c], a
    call Call_000_13f1

jr_016_5e68:
    ld hl, $d757
    set 7, [hl]
    call Call_000_3e07
    ld a, $00
    ld [$d5a3], a
    ld [$d97c], a
    ret


    ld [$535e], a
    ld e, a
    sub a
    ld e, a
    di
    ld e, a
    ld c, d
    ld h, b
    xor e
    ld h, b
    rst $38
    ld h, b
    ld h, a
    ld h, c
    push bc
    rrca
    push bc
    rrca
    ret nz

    ld h, c
    db $db
    ld h, c
    ld bc, $245f
    ld e, a
    ld [bc], a
    ld b, b
    ld d, [hl]
    rst $10
    ld e, l
    ld e, a
    ld a, a
    ld e, a
    ld [hl], c
    ld e, a
    ld [hl], c
    ld e, a
    inc bc
    ld b, b
    ld d, [hl]
    rst $10
    and c
    ld e, a
    sub $5f
    jp $c35f


    ld e, a
    inc b
    ld b, b
    ld d, [hl]
    rst $10
    db $fd
    ld e, a
    inc hl
    ld h, b
    ld a, [de]
    ld h, b
    ld a, [de]
    ld h, b
    dec b
    ld b, b
    ld d, [hl]
    rst $10
    ld d, h
    ld h, b
    ld a, a
    ld h, b
    ld [hl], l
    ld h, b
    ld [hl], l
    ld h, b
    ld b, $40
    ld d, [hl]
    rst $10
    or l
    ld h, b
    sub $60
    call z, $cc60
    ld h, b
    rlca
    ld b, b
    ld d, [hl]
    rst $10
    add hl, bc
    ld h, c
    ld b, a
    ld h, c
    ld [hl-], a
    ld h, c
    ld [hl-], a
    ld h, c
    ld [$5610], sp
    rst $10
    ld [hl], c
    ld h, c
    sbc l
    ld h, c
    sub l
    ld h, c
    sub l
    ld h, c
    rst $38
    db $ed
    inc hl
    ld a, h
    ld d, d
    call nz, $d3c3
    ld c, a
    or a
    db $d3
    pop bc
    ld a, a
    sub $bb
    cp a
    or e
    add $7f
    ret z

    jp $bdcf


    ld d, a
    db $ed
    inc hl
    ld a, [bc]
    ld d, e
    xor e
    ld h, $7f
    jp nc, $7fdd

    cp e
    rst $08
    cp h
    ret nz

    rst $20
    ld d, c
    add l
    ld a, [de]
    add hl, bc
    xor e
    jp z, $c84f

    ld a, $b9
    jp $b57f


    cp a
    rst $18
    jp $c0b7


    rst $20
    ld d, a
    db $ed
    inc hl
    ld c, d
    ld d, e
    xor e
    jp z, $b57f

    call nz, $bcc5
    cp b
    ld a, a
    push bc
    rst $18
    ret nz

    ld c, a
    or l
    or l
    or a
    push bc
    ld a, a
    or c
    cp b
    dec sp
    db $dd
    ld a, a
    cp l
    reti


    call nz, Call_016_5556
    call nc, $b5cf
    cp b
    call $bb7f
    rst $18
    jp $b27f


    rst $18
    ret nz

    rst $20
    ld d, a
    ld [$9521], sp
    ld e, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    sbc c
    ld d, e
    or l
    db $e3
    xor h
    rst $20
    ld c, a
    res 6, d
    jp Jump_016_7fd9


    res 6, d
    jp $e7d9


    ld d, a
    db $ed
    inc hl
    rla
    ld d, h
    ld c, a
    add hl, hl
    inc [hl]
    or e
    ld a, a
    jr nc, @-$1f

    ret nz

    or [hl]
    ld e, b
    db $ed
    inc hl
    or e
    ld d, e
    ld a, a
    cp b
    jp c, Jump_016_4fe7

    jp nz, $b2d8

    call nz, Call_016_7f26
    cp d
    sbc $26
    rst $10
    ld h, $df
    ret nz

    rst $20
    ld d, a
    ld [$a121], sp
    ld e, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld b, l
    ld d, h
    call c, $d9c3
    push bc
    rst $20
    ld c, a
    rst $08
    jp nz, $ba7f

    call nz, Call_016_7fd3
    rst $08
    ret nz

    rst $20
    ld d, l
    jp nz, $c9d8

    ld a, a
    ret nz

    ret


    cp h
    ret nc

    ld a, a
    inc sp
    or c
    reti


    ld d, a
    db $ed
    inc hl
    pop de
    ld d, h
    ld d, [hl]
    rst $20
    ld c, a
    pop bc
    ld [c], a
    rst $18
    call nz, $cf7f
    rst $18
    jp $b87f


    jp c, $ed58

    inc hl
    ld a, a
    ld d, h
    jp nz, $2bd8

    or l
    db $dd
    ld a, a
    jp nz, $b4b6

    ld a, [hl-]
    ld c, a
    or d
    or d
    ld a, a
    ld d, h
    ld h, $7f
    jp nz, $d9da

    sbc $30
    ld h, $56
    ld d, a
    ld [$ad21], sp
    ld e, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    xor $54
    or d
    cp h
    ld a, a
    cp e
    ld h, $bc
    jp $ded9


    jr nc, jr_016_608b

    cp c
    inc [hl]
    ld c, a
    or a
    ret nc

    ld a, a
    db $d3
    rst $18
    jp $c57f


    or d
    and $57

jr_016_601a:
    db $ed
    inc hl
    add l
    ld d, l
    ret c

    ldh [rRP], a
    rst $20
    ld e, b
    db $ed
    inc hl
    dec hl
    ld d, l
    or d
    cp h
    ld h, $7f
    or c
    jp c, Jump_016_4f3a

    ld d, h
    ld h, $7f
    cp h
    sbc $b6
    ld a, a
    cp h
    jp Jump_000_3e55


    cp b
    ld a, a
    or [hl]
    rst $18
    jp $7fc0


    or [hl]
    db $d3
    ld a, a
    cp h
    jp c, $b2c5

    sub $57
    ld [$b921], sp
    ld e, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    sub l
    ld d, l
    ld a, a
    cp [hl]
    sbc $d3
    sbc $7f
    inc sp
    sbc $b7
    ld a, a
    jr nc, jr_016_601a

    rst $10
    ld c, a
    or e
    ret nc

    ld a, a
    ld d, h
    jp z, $b87f

    call c, $b8bc
    ld a, a
    push bc
    or d
    sub $57
    db $ed
    inc hl
    ld l, a
    ld d, [hl]
    ld a, a
    call z, $e0c6
    ld d, [hl]

jr_016_607e:
    ld e, b
    db $ed
    inc hl
    db $dd
    ld d, l
    ld d, [hl]
    ld a, a
    ret nz

    cp h
    or [hl]
    ld a, a
    ret nc

    dec l

jr_016_608b:
    jp z, Jump_000_334f

    sbc $b7
    db $dd
    ld a, a
    sub $b8
    ld a, a
    call nz, $bdb5
    ld a, a
    or [hl]
    rst $10
    ld d, l
    call c, $262b
    ld a, a
    or a
    cp b
    ld a, a
    jp z, Jump_016_7f2d

    jr nc, jr_016_607e

    ret z

    ld d, [hl]
    ld d, a
    ld [$c521], sp
    ld e, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    adc [hl]
    ld d, [hl]
    rst $20
    ld a, a
    jp nz, $7fd8

    add hl, de
    add l
    ld c, a
    ld d, h
    ld a, a
    add hl, de
    add l
    add $7f
    inc sp
    or c
    or e
    rst $20
    ld d, a
    db $ed
    inc hl
    dec hl
    ld d, a
    ld a, a
    jp nz, $b2d6

    rst $20
    ld e, b
    db $ed
    inc hl
    jp nz, $ba56

    cp a
    ld c, a
    db $d3
    ret


    ret


    ld a, a
    inc l
    ld [c], a
    or e
    dec l
    ld a, a
    push bc
    jp c, Jump_016_7f56

    jr nc, @-$39

    rst $20
    ld d, l
    ld a, $b8
    db $d3
    ld a, a
    jp nz, $7fd8

    push bc
    rst $10
    ld a, a
    rst $08
    cp c
    push bc
    or d
    cpl
    rst $20
    ld d, a
    ld [$d121], sp
    ld e, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ccf
    ld d, a
    ld a, [hl-]
    rst $18
    or [hl]
    ret c

    ld a, a
    cp h
    jp $c57f


    or d
    inc sp
    ld c, a
    db $d3
    rst $18
    call nz, $bc7f
    ld a, [hl+]
    call nz, Call_016_7fd3
    inc sp
    or a
    jp c, Jump_016_553a

    cp e
    or d
    cp d
    or e
    ld a, a
    push bc
    sbc $30
    ld h, $56
    ld d, a
    db $ed
    inc hl
    nop
    ld e, b
    or [hl]
    ld d, [hl]
    ld c, a
    or e
    rst $08
    cp b
    ld a, a
    or d
    or [hl]
    sbc $7f
    db $d3
    ret


    ld a, a
    inc l
    ldh [$58], a
    db $ed
    inc hl
    adc e
    ld d, a
    ld d, [hl]
    ld a, a
    jr nc, @-$4c

    inc l
    ld [c], a
    or e
    inc a
    rst $20
    ld c, a
    rst $08
    cp c
    ret nz

    ld a, a
    cp b
    rst $10
    or d
    inc sp
    ld a, a
    jp z, $cad7

    ld a, a
    ret nz

    jp $d6de


    ld d, a
    ld [$dd21], sp
    ld e, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    dec e
    ld e, b
    add $26
    ld a, a
    jp nz, $d9da

    or [hl]
    rst $18
    jp Jump_016_4fe6


    cp a
    ret c

    ldh [$7f], a
    jp nz, $c3df

    ld a, a
    ret nc

    push bc
    cp c
    ret c

    ldh [rHDMA5], a
    call c, $d7b6
    sbc $d6
    rst $20
    ld d, a
    db $ed
    inc hl
    call nc, $df58
    ret nz

    push bc
    ld e, b
    db $ed
    inc hl
    ld a, d
    ld e, b
    adc c
    add c
    add [hl]
    xor e
    rlca
    ld d, [hl]
    ld a, a
    ret z

    ld c, a
    sub $b8
    ld a, a
    jp nz, $d9da

    ld a, a
    cp c
    inc [hl]
    ld d, l
    sub $dc
    cp l
    daa
    reti


    sbc $30
    sub $c5
    or c
    ld d, [hl]
    ld d, a
    db $ed
    inc hl
    xor l
    ld d, d
    ld a, a
    rst $30
    ld hl, sp+$3a
    sbc $7f
    inc [hl]
    or e
    db $db
    ld c, a
    or a
    ret nz

    ld a, a
    ld d, [hl]
    ld a, a
    adc e
    add h
    xor e
    ld a, a
    adc a
    add d
    xor e
    ld d, a
    db $ed
    inc hl
    ldh [rHDMA2], a
    ld a, a
    jp nz, $c9d8

    ld a, a
    jp nc, $bcb2

    ld [c], a
    ld d, a
    call Call_000_3c6c
    ld hl, $621a
    ld de, $61fc
    ld a, [$d5a4]
    call Call_000_31a8
    ld [$d5a4], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    sub e
    ld h, d
    sbc c
    ld h, d
    sbc a
    ld h, d
    and l
    ld h, d
    xor e
    ld h, d
    or c
    ld h, d
    or a
    ld h, d
    cp l
    ld h, d
    jp $c962


    ld h, d
    push bc
    rrca
    dec hl
    ld h, [hl]
    ld bc, $5c20
    rst $10
    db $d3
    ld h, d
    ld a, [$f362]
    ld h, d
    di
    ld h, d
    ld [bc], a
    jr nc, jr_016_6285

    rst $10
    inc a
    ld h, e
    ld l, l
    ld h, e
    ld h, d
    ld h, e
    ld h, d
    ld h, e
    inc bc
    jr nc, @+$5e

    rst $10
    adc h
    ld h, e
    cp a
    ld h, e
    or h
    ld h, e
    or h
    ld h, e
    inc b
    jr nc, jr_016_629d

    rst $10
    db $e4
    ld h, e
    ld de, $0664
    ld h, h
    ld b, $64
    dec b
    jr nz, jr_016_62a9

    rst $10
    jr c, jr_016_62b4

    ld e, a
    ld h, h
    ld d, h
    ld h, h
    ld d, h
    ld h, h
    ld b, $30
    ld e, h
    rst $10
    add d
    ld h, h
    cp b
    ld h, h
    and l
    ld h, h
    and l
    ld h, h
    rlca
    jr nc, jr_016_62c1

    rst $10
    reti


    ld h, h
    rrca
    ld h, l
    inc b
    ld h, l
    inc b
    ld h, l
    ld [$5c30], sp
    rst $10
    ld [hl], $65
    ld h, h
    ld h, l
    ld e, d
    ld h, l
    ld e, d
    ld h, l
    add hl, bc
    jr nc, @+$5e

    rst $10
    sub b
    ld h, l
    call $b465
    ld h, l
    or h

jr_016_6285:
    ld h, l
    ld a, [bc]
    jr nc, @+$5e

    rst $10
    jp hl


    ld h, l
    dec c
    ld h, [hl]
    cp $65
    cp $65
    rst $38
    ld [$1a21], sp
    ld h, d
    jr jr_016_62cd

    ld [$2621], sp
    ld h, d

jr_016_629d:
    jr jr_016_62cd

    ld [$3221], sp
    ld h, d
    jr jr_016_62cd

    ld [$3e21], sp
    ld h, d

jr_016_62a9:
    jr jr_016_62cd

    ld [$4a21], sp
    ld h, d
    jr jr_016_62cd

    ld [$5621], sp

jr_016_62b4:
    ld h, d
    jr jr_016_62cd

    ld [$6221], sp
    ld h, d
    jr jr_016_62cd

    ld [$6e21], sp
    ld h, d

jr_016_62c1:
    jr jr_016_62cd

    ld [$7a21], sp
    ld h, d
    jr jr_016_62cd

    ld [$8621], sp
    ld h, d

jr_016_62cd:
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld e, a
    ld l, c
    pop bc
    call nz, $ba7f
    or e
    or [hl]
    sbc $7f
    cp h
    ret nz

    ld c, a
    or l
    or a
    add $b2
    ret c

    inc sp
    ld a, a
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    cp l
    reti


    call c, Call_016_57e7
    db $ed
    inc hl
    ld c, b
    ld l, d
    call c, Call_016_58e7
    db $ed
    inc hl
    sbc b
    ld l, c

jr_016_62fe:
    pop bc
    call nz, $ba7f
    or e
    or [hl]
    sbc $7f
    cp h
    ret nz

    ld c, a
    ld d, h
    ret


    ld a, a
    sub l
    xor h
    add a
    sub a
    db $e3
    sbc a
    ld d, l
    ret nz

    call nz, $7fb4
    or a
    add $7f
    or d
    rst $10
    push bc
    cp b
    jp $56d3


    ld d, l
    call nz, $c0df
    ld a, a
    set 0, h
    inc sp
    ld a, a
    push bc
    or d
    call nz, $c255
    cp c
    ld a, a
    push bc
    or l
    cp [hl]
    push bc
    or d
    ld a, a
    ret


    sub $c8
    rst $20
    ld d, a
    db $ed
    inc hl
    ld h, a
    ld l, d
    call nc, $bcbb
    cp a
    or e
    ld a, a
    jr nc, jr_016_62fe

    rst $10
    ld c, a
    rst $08
    cp c
    reti


    ld a, a
    or a
    ld h, $7f
    cp h
    push bc
    or d
    rst $20
    ld d, l
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    cp h
    jp $d9d0


    call c, Call_016_57e7
    db $ed
    inc hl
    db $fd
    ld l, d
    ld a, a
    rst $08
    cp c
    ret nz

    ret


    and $58
    db $ed
    inc hl
    xor e
    ld l, d
    or e
    cpl
    cp b
    ld d, [hl]
    ld c, a
    sub $b8
    ld a, a
    ret nc

    or [hl]
    cp c
    reti


    ld a, a
    cp c
    inc [hl]
    ld d, l
    cp d
    call c, $b3bf
    inc sp
    ld a, a
    or d
    call nc, $dc30
    ld d, a
    db $ed
    inc hl
    db $fd
    ld l, d
    ld a, a
    cp b
    pop bc
    inc a
    or h
    ld a, a
    call z, $c0b2
    ret c

    ld a, a
    cp l
    reti


    call nz, $c44f
    ret c

    ld a, a
    ld d, h
    ld h, $55
    call nz, Call_000_33de
    ld a, a
    or a
    ret nz

    ret c

    ld a, a
    cp l
    reti


    sbc $30
    ld l, $e7
    ld d, a
    db $ed
    inc hl
    db $76
    ld l, e
    or [hl]
    push bc
    cp h
    or d
    ret z

    rst $20
    ld e, b
    db $ed
    inc hl
    ld sp, $7f6b
    sub $b3
    push bc
    ld a, a
    adc a
    add c
    ld b, d
    jp z, $bc4f

    ld [c], a
    or e
    inc a
    ld a, a
    ld a, [hl+]
    call nz, $c67f
    jp z, $d155

    or d
    jp $c57f


    or d
    ret


    or [hl]
    push bc
    or c
    ld d, [hl]
    ld d, a
    db $ed
    inc hl
    adc h
    ld l, e
    and $4f
    call nz, Call_000_26d8
    ld a, a
    call z, $b4d9
    jp $e7d9


    ld d, l
    or l
    rst $08
    or h
    ld a, a
    db $d3
    cp h
    or [hl]
    cp h
    jp Jump_016_7f56


    jp nz, $b2d6

    push bc
    and $57
    db $ed
    inc hl
    ld b, h
    ld l, h
    ret nz

    ld a, a
    call nz, $d8b5
    jr nc, jr_016_6469

    db $ed
    inc hl
    jp c, $d86b

    ld a, a
    rst $08
    or h
    ld a, a
    jr nc, @-$45

    inc [hl]
    cp e
    ld d, [hl]
    ld c, a
    call nz, $7fd8
    ld d, h
    jp z, Jump_000_2c55

    cp h
    sbc $7f
    call nc, Call_000_2c7f
    call c, Call_016_7fda
    add $ca
    ld a, a
    jp nz, $b2d6

    sub $57
    db $ed
    inc hl
    ld d, l
    ld l, h
    sbc $e7
    ld c, a
    ld d, h
    ld a, a
    ret nc

    ret nz

    or d
    add $55
    or [hl]
    call c, $b2b2
    ld a, a
    or l
    call nz, $c9ba
    cp d
    ld a, a
    ret z

    rst $20
    ld d, a
    db $ed
    inc hl
    ret


    ld l, h
    ld a, a
    cp h
    pop bc
    ldh [$df], a
    ret nz

    ld e, b
    db $ed
    inc hl
    ld [hl], a
    ld l, h
    or d
    ld a, a
    cp c
    inc [hl]
    ld c, a
    or l

jr_016_6469:
    ret z

    or h

jr_016_646b:
    cp e
    sbc $ca
    ld a, a
    or l
    call nz, Call_016_7fc5
    jr nc, @-$48

    rst $10
    ld d, l
    push de
    reti


    cp h
    jp $b17f


    add hl, hl
    reti


    call c, Call_016_57c8
    db $ed
    inc hl
    reti


    ld l, h
    ld d, [hl]
    rst $20
    ld c, a
    call c, $bcc0
    jp z, $cb7f

    call nz, $7fd8
    jr z, jr_016_646b

    cp h
    ld a, a
    jr nc, @-$48

    rst $10
    ld d, l
    ld d, h
    ld a, a
    or [hl]
    rst $18
    jp Jump_016_7fd9


    call c, $e7b9
    ld d, a
    db $ed
    inc hl
    ld a, b
    ld l, l
    jp z, $b64f

    pop bc
    ld a, a
    rst $08
    cp c
    ld a, a
    inc l
    ldh [$7f], a
    push bc
    or d
    call c, $ed58
    inc hl
    inc c
    ld l, l
    rst $20
    ld c, a
    or e
    pop bc
    add $7f
    or [hl]
    or h
    rst $18
    ret nz

    ld a, a
    call nz, Call_016_55b7
    ld d, h
    ld h, $7f
    or d
    reti


jr_016_64cf:
    call nz, $ce7f
    rst $18
    call nz, $bd7f
    reti


    ret


    ld d, a
    db $ed
    inc hl
    and e
    ld l, l
    ld a, $b3
    dec l
    rst $20
    ld a, a
    cp h
    ld [c], a
    or e
    inc a
    jr nc, jr_016_64cf

    ld c, a
    cp a
    ret


    ld a, a
    call $c9de
    ld a, a
    call nc, $7fc2
    or [hl]
    rst $10
    ld d, l
    pop de
    ret c

    call nc, $7fd8
    call nz, $c3df
    ld a, a
    or a
    ret nz

    ld l, $e7
    ld d, a
    db $ed
    inc hl
    ld h, h
    ld l, [hl]
    cp b
    ld a, a
    or d
    or [hl]
    ret z

    or h
    ld e, b
    db $ed
    inc hl
    or $6d
    or d
    ld a, a
    inc l
    sbc $be
    or d
    ld d, [hl]
    rst $20
    ld c, a
    xor c
    and [hl]
    ret


    ld a, a
    adc $b3
    ld h, $7f
    or [hl]
    rst $18
    cp d
    or d
    or d
    ld l, $e7
    ld d, l
    ld e, [hl]
    ld a, a
    ret nc

    ret nz

    or d
    add $7f
    push bc
    rst $20
    ld d, a
    db $ed
    inc hl
    add b
    ld l, [hl]
    rst $20
    ld c, a
    rst $08
    cp c

jr_016_653e:
    ret nz

    rst $10
    ld a, a
    or c
    ret c

    ld h, $c8
    ld a, a
    ld l, $de
    inc a
    rst $20
    ld d, l
    or l
    or d
    jp $b27f


    rst $18
    jp $d37f


    rst $10
    or l

jr_016_6556:
    or e
    or [hl]
    rst $20
    ld d, a
    db $ed
    inc hl
    ei

jr_016_655d:
    ld l, [hl]
    ld a, a
    ret z

    or h
    jr nc, jr_016_653e

    ld e, b
    db $ed
    inc hl
    xor [hl]
    ld l, [hl]
    ret z

    ld a, a
    or l

jr_016_656b:
    or d
    jp Jump_016_7fb8


    push bc
    sbc $c3
    ld c, a
    inc l
    ld [c], a
    or e

jr_016_6576:
    jr nc, jr_016_6556

    add $7f
    or a
    rst $08
    rst $18
    jp Jump_016_7fd9


    jr nc, jr_016_655d

    rst $20
    ld d, l
    or [hl]
    reti


    or d
    ld a, a
    inc l
    ld [c], a
    or e
    jr nc, jr_016_656b

    jr nc, jr_016_6576

    ld d, a
    db $ed
    inc hl
    inc c
    ld l, a
    sbc $7f
    jp z, $dfd4

    jp Jump_016_7fd9


    cp d
    call nz, $e656
    ld c, a
    cp a
    or e
    ret z

    or h
    ld d, [hl]
    rst $20
    ld d, l
    ld d, h
    ret


    ld a, a
    cp d
    or e
    or [hl]
    sbc $7f
    or [hl]
    push bc
    rst $20
    ld d, a
    db $ed
    inc hl
    xor a
    ld l, a
    ld d, [hl]
    rst $20
    ld c, a
    cp h
    ld [c], a
    or e
    inc a
    ld a, a
    inc l
    ldh [$7f], a
    push bc
    cp b
    jp $ba7f


    or e
    or [hl]
    sbc $d6
    ld e, b
    db $ed
    inc hl
    ld e, l
    ld l, a
    call c, $bcc0
    db $d3
    ld a, a
    or l
    call nz, Call_000_30d3
    pop bc
    call nz, Call_016_544f
    ld a, a
    cp d
    or e
    or [hl]
    sbc $7f
    cp l
    reti


    call c, Call_016_57e7
    db $ed
    inc hl
    pop de
    ld l, a
    sub $7f
    cp h
    sub $b3
    sub $4f
    ld d, h
    ld a, a
    cp h
    sub $b3
    sub $e3
    xor h
    rst $20
    ld d, a
    db $ed
    inc hl
    ld e, a
    ld [hl], b
    inc a
    ld a, a
    or c
    cp [hl]
    ret c

    ld a, a
    cp l
    daa
    ret nz

    call c, $ed58
    inc hl
    db $ec
    ld l, a
    cp l
    cp d
    cp h
    ld a, a
    sub $dc
    or d
    ld a, a
    set 0, h
    call nz, $da4f
    sbc $bc
    pop hl
    or e
    ld a, a
    cp h
    jp $b87f


    reti


    sub $50
    ld d, b
    db $ed
    inc hl
    cpl
    ld l, c
    ld a, a
    rst $30
    ei
    ld a, [hl-]
    sbc $7f
    inc [hl]
    or e
    db $db
    ld c, a
    add $bc
    ld a, a
    ld d, [hl]
    ld a, a
    adc l
    add [hl]
    sub b
    add a
    ld a, a
    adc e
    sub d
    or b
    ld d, a
    call Call_000_3c6c
    ld hl, $66e3
    ld de, $6665
    ld a, [$d5a5]
    call Call_000_31a8
    ld [$d5a5], a
    ret


Jump_016_665a:
    xor a
    ld [$cd66], a
    ld [$d5a5], a
    ld [$d97c], a
    ret


    ld l, l
    ld h, [hl]
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    and e
    ld h, [hl]
    ld hl, $d75f
    bit 1, [hl]
    jp nz, Jump_000_3261

    bit 0, [hl]
    res 0, [hl]
    jp z, Jump_000_3261

    ld a, $0a
    ldh [$8c], a
    call Call_000_13f1
    ld a, $84
    ld [$d036], a
    ld a, $1e
    ld [$d0ec], a
    ld a, $21
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    call Call_000_0ebd
    ld a, $03
    ld [$d5a5], a
    ld [$d97c], a
    ret


    ld a, [$d034]
    cp $ff
    jp z, Jump_016_665a

    call Call_000_0ebd
    ld a, [$cf06]
    cp $02
    jr z, jr_016_66bc

    ld a, $0b
    ldh [$8c], a
    call Call_000_13f1

jr_016_66bc:
    ld hl, $d75f
    set 1, [hl]
    call Call_000_3e07
    ld a, $00
    ld [$d5a5], a
    ld [$d97c], a
    ret


    inc l
    ld h, a
    ld a, c
    ld h, a
    cp h
    ld h, a
    ld bc, $6268
    ld l, b
    jp z, Jump_000_2968

    ld l, c
    add l
    ld l, c
    sbc a
    ld l, c
    ld b, b
    ld l, c
    ld h, e
    ld l, c
    ld bc, $5e30
    rst $10
    ld [hl], $67
    ld c, e
    ld h, a
    ld b, b
    ld h, a
    ld b, b
    ld h, a
    ld [bc], a
    jr nz, jr_016_6750

    rst $10
    add e
    ld h, a
    and a
    ld h, a
    sbc l
    ld h, a
    sbc l
    ld h, a
    inc bc
    jr nz, jr_016_675c

    rst $10
    add $67
    call c, $d367
    ld h, a
    db $d3
    ld h, a
    inc b
    jr nz, jr_016_6768

    rst $10
    dec bc
    ld l, b
    ld a, [hl+]
    ld l, b
    inc hl
    ld l, b
    inc hl
    ld l, b
    dec b
    jr nz, jr_016_6774

    rst $10
    ld l, h
    ld l, b
    sbc b
    ld l, b
    adc e
    ld l, b
    adc e
    ld l, b
    ld b, $40
    ld e, [hl]
    rst $10
    call nc, $fa68
    ld l, b
    db $ed
    ld l, b
    db $ed
    ld l, b
    rst $38
    ld [$e321], sp
    ld h, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    and [hl]
    ld [hl], c
    ld a, a
    cp d

jr_016_673c:
    rst $10
    or c

jr_016_673e:
    rst $20
    ld d, a
    db $ed
    inc hl
    ld c, $72
    inc l
    ldh [$c8], a
    or h
    cpl
    rst $20
    ld e, b
    db $ed
    inc hl
    or b
    ld [hl], c
    push bc

jr_016_6750:
    rst $20
    ld c, a
    or l
    jp c, $c1c0

    ldh [$7f], a
    jp z, $d9bc

    ld a, a

jr_016_675c:
    sub $d8
    ld d, l
    cp d
    cp d
    inc sp
    ld a, a
    jr nc, jr_016_673c

    jr nc, jr_016_673e

    ld a, a

jr_016_6768:
    cp h
    jp Jump_016_7fd9


    adc $b3
    ld h, $55
    ret nz

    ret


    cp h
    or d

jr_016_6774:
    sbc $30
    sub $e7
    ld d, a
    ld [$ef21], sp
    ld h, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    rra
    ld [hl], d
    or l
    or e
    xor h
    rst $20
    ld c, a
    cp a
    ret


    ld a, a
    inc l
    jp $bcde


    ldh [$7f], a
    or l
    jp c, Jump_016_7fc6

    cp b
    jp c, Jump_016_57e7

    db $ed
    inc hl
    adc b
    ld [hl], d
    ld a, a
    add b
    add d
    sub e
    rst $20
    ld e, b
    db $ed
    inc hl

jr_016_67a9:
    ld b, c
    ld [hl], d
    or d
    or d
    rst $20
    ld c, a
    inc l
    jp $bcde


    ldh [$ca], a
    ld a, a
    or d
    rst $10
    ret z

    or h
    rst $20
    ld d, a
    ld [$fb21], sp
    ld h, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    xor h
    ld [hl], d
    ld h, $df
    jp $d47f


    db $db
    or e
    rst $20
    ld d, a
    db $ed
    inc hl
    inc b
    ld [hl], e
    call nc, $b3db
    rst $20
    ld e, b
    db $ed
    inc hl
    call nz, Call_016_7f72
    call nc, $c3df
    ld a, a
    cp b
    jp c, $c5c0

    rst $20
    ld c, a
    or l
    jp c, $7fca

    rst $08
    cp c
    reti


    ret


    ld h, $55
    jr nc, jr_016_67a9

    ld a, a
    or a
    rst $10
    or d
    ld a, a
    push bc
    sbc $30
    rst $20
    ld d, a
    ld [$0721], sp
    ld h, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld [de], a
    ld [hl], e
    rst $08
    jp Jump_016_4fe7


    inc a
    jp nz, $dfb6

    jp $b57f


    or d
    jp $c67f


    add hl, hl
    reti


    push bc
    rst $20
    ld d, a
    db $ed
    inc hl
    or c
    ld [hl], e
    db $e3
    rst $20
    ld e, b
    db $ed
    inc hl
    ld c, a
    ld [hl], e
    pop bc
    ld a, a
    or d
    jp nz, Jump_016_7fd3

    cp d
    cp d
    add $7f
    or d
    reti


    ld l, $e7
    ld c, a
    cp d
    call c, $dfb6
    ret nz

    rst $10
    ld a, a
    add a
    sub b
    add hl, de
    ld a, a
    or [hl]
    rst $10
    ld d, l
    or e
    ret nc

    cpl
    or d
    ld a, a
    rst $08
    call c, $c3df
    ld d, l
    adc l
    add [hl]
    sub b
    add a
    call $b27f
    cp b
    sbc $30
    push bc
    rst $20
    ld d, a
    ld [$1321], sp
    ld h, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    pop bc
    ld [hl], e
    ld a, a
    or d
    rst $08
    ld a, a
    or a
    add hl, hl
    sbc $26
    ld a, a
    call c, $b2d9
    rst $20
    ld c, a

jr_016_687e:
    add d
    adc d
    ld a, a
    ld a, [hl-]
    rst $10
    cp h
    ld h, $7f
    cp h
    jp $e7b4


    ld d, a
    db $ed
    inc hl
    ld l, [hl]
    ld [hl], h
    or a
    push bc
    ld a, a
    cp d
    cpl
    or e
    jr nc, jr_016_687e

    ld e, b
    db $ed
    inc hl
    ei
    ld [hl], e
    ld a, a
    ld d, h
    ld a, a
    call nc, $c5d9
    rst $10
    ld c, a
    or a
    ld [c], a
    or e
    ld a, $b3
    push bc
    ld a, a
    call nc, $26c2
    ld a, a
    adc $bc
    or d
    ld l, $e7
    ld d, l
    cp a
    jp c, Jump_016_7f33

    or c
    or d
    jp Jump_016_55dd


    inc e
    xor b
    inc e
    xor b
    add $7f
    cp h
    jp $d9d4


    rst $20
    ld d, a
    ld [$1f21], sp
    ld h, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    adc d
    ld [hl], h
    ld [c], a
    db $e3
    xor h
    rst $20
    ld c, a
    cp l
    cp d
    cp h
    ld a, a
    or c
    cp a
    sbc $33
    rst $18
    jp $d47f


    reti


    ld l, $e7
    ld d, a
    db $ed
    inc hl
    jr z, jr_016_6966

    ld a, a
    or l
    cp d
    rst $10
    cp l
    push bc
    sub $e7
    ld e, b
    db $ed
    inc hl
    xor d
    ld [hl], h
    or l
    or e
    xor h
    rst $20
    ld c, a
    ld d, h
    inc sp
    ld a, a
    or l
    inc [hl]
    or [hl]
    cp h
    ret nz

    ret c

    ld d, l
    or [hl]
    ret nc

    jp nz, $beb6

    ret nz

    ret c

    ld a, a
    or d
    ret nz

    dec l
    rst $10
    ld a, a
    cp h
    ret nz

    ret c

    ld d, l
    cp l
    reti


    ret


    ld h, $7f
    cp l
    or a
    jr nc, jr_016_6955

    rst $20
    ld d, a
    db $ed
    inc hl
    sub a
    ld [hl], b
    call nz, $d3c3
    ld c, a
    or a
    db $d3
    pop bc
    sub $bb
    cp a
    or e
    add $7f
    ret z

    jp $cfb2


    cp l
    ld d, a
    db $ed
    inc hl
    scf
    ld [hl], c
    xor e
    jp z, $d27f

    db $dd
    ld a, a
    cp e
    rst $08
    cp h
    ret nz

    rst $20
    ld d, c
    ret z

    ld a, $b9
    ret nz

    ld a, a

jr_016_6955:
    add l
    ld a, [de]
    add hl, bc
    xor e
    ld h, $4f
    or l
    cp a
    rst $18
    jp $c0b7


    rst $20
    ld d, a
    db $ed
    inc hl
    ld [hl], e

jr_016_6966:
    ld [hl], c
    xor e
    jp z, $b57f

    or l
    or a
    push bc
    ld a, a
    or c
    cp b
    dec sp
    db $dd
    cp h
    jp $d44f


    rst $08
    ret


    or l
    cp b
    call $bb7f
    rst $18
    jp $dfb2


    ret nz

    ld d, [hl]
    ld d, a
    db $ed
    inc hl
    or l
    ld [hl], b
    pop bc
    db $dd
    ld a, a
    ret nz

    ret


    cp h
    db $d3
    or e
    rst $20
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
    rst $20
    ld d, a
    db $ed
    inc hl
    ld a, [$7f70]
    rst $30
    db $fc
    ld a, [hl-]
    sbc $7f
    inc [hl]
    or e
    db $db
    ld c, a
    adc a
    sbc l
    sbc a
    adc e
    ld a, a
    ld d, [hl]
    ld a, a
    adc l
    add [hl]
    sub b
    add a
    ld d, a
    call Call_000_3c6c
    ld hl, $69dc
    ld de, $69cc
    ld a, [$d5a6]
    call Call_000_31a8
    ld [$d5a6], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld bc, $576a
    ld l, d
    or h
    ld l, d
    ld a, [bc]
    ld l, e
    inc h
    ld l, e
    ld bc, $6230
    rst $10
    dec bc
    ld l, d
    add hl, sp
    ld l, d
    inc sp
    ld l, d
    inc sp
    ld l, d
    ld [bc], a
    jr nc, jr_016_6a4d

    rst $10
    ld h, c
    ld l, d
    sub b
    ld l, d
    ld a, b
    ld l, d
    ld a, b
    ld l, d
    inc bc
    ld b, b
    ld h, d
    rst $10
    cp [hl]
    ld l, d
    add sp, $6a
    pop hl
    ld l, d
    pop hl
    ld l, d
    rst $38
    ld [$dc21], sp
    ld l, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld [hl+], a
    ld b, c
    or e
    ld a, a
    cp b
    cp e
    pop de
    rst $10
    db $dd
    ld a, a
    ret nc

    jp nz, $c3b9

    jp z, $b14f

    ret nz

    rst $10
    cp h
    or d
    ld a, a
    ld d, h
    ld a, a
    or d
    push bc
    or d
    or [hl]
    ld d, l
    cp e
    ld h, $bc
    jp $c9d9


    cp e
    rst $20
    ld d, a
    db $ed
    inc h
    or h
    ld b, c
    rst $20
    ld e, b
    db $ed
    inc h
    ld l, a
    ld b, c
    cp h
    ldh [$7f], a
    db $d3
    rst $18
    jp $b27f


    ret nz

    rst $10
    ld c, a
    ld a, $b8
    db $d3
    ld a, a
    adc d

jr_016_6a4d:
    add c
    add a
    ret c

    xor e
    rlca
    ld a, a
    cp h
    ret nz

    or d
    ld d, a
    ld [$e821], sp
    ld l, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    cp l
    ld b, c
    add a
    ld d, [hl]
    xor h
    rst $20
    ld c, a
    inc [hl]
    or e
    and $7f
    ld a, $b8
    ret


    ld a, a
    push de
    dec sp
    inc a
    or h
    rst $20
    ld d, a
    db $ed
    inc h
    ld e, e
    ld b, d
    ld a, a
    push bc
    or [hl]
    dec l
    ld a, [hl-]
    ld c, a
    or e
    ret nz

    jp c, $b2cf

    add $7f
    rst $18
    jp $ba7f


    call nz, Call_016_58b6
    db $ed
    inc h
    sbc $41
    ld a, a
    pop bc
    or [hl]
    or d
    ld a, a
    or [hl]
    rst $10
    ld c, a
    cp h
    pop hl
    or e
    rst $08
    jp nz, $7fca

    or e
    ret nc

    inc [hl]
    ret c

    ld a, a
    ld d, h
    ld d, l
    jp nz, $cfb6

    or h
    add $7f
    cp b
    reti


    sub $57
    ld [$f421], sp
    ld l, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld a, a
    ld b, d
    or c
    ret nz

    ret c

    jp z, Jump_000_3e4f

    cp b
    rst $10
    ret


    ld a, a
    push bc
    call c, $d83a
    jr nc, @-$17

    ld d, l
    pop bc
    or [hl]
    sub $d7
    push bc
    or d
    inc sp
    ld a, a
    adc $bc
    or d
    push bc
    rst $20
    ld d, a
    db $ed
    inc h

jr_016_6ae3:
    ld [de], a
    ld b, e
    or e
    rst $20
    ld e, b
    db $ed
    inc h
    call nz, $d342
    ld a, a
    or l
    or a
    add $b2
    ret c

    ret


    ld c, a
    ld d, h
    db $dd
    ld a, a
    call nz, $c6d8
    ld a, a
    or d
    cp b
    ld d, l
    ld a, [hl-]
    cp h
    ld [c], a
    ld h, $7f
    or c
    reti


    jr nc, jr_016_6ae3

    rst $20
    ld d, a
    db $ed
    inc h
    cp h
    ld b, b
    ld a, a
    rst $30
    cp $3a
    sbc $7f
    inc [hl]
    or e
    db $db
    ld c, a
    adc a
    sbc l
    sbc a
    adc e
    ld a, a
    ld d, [hl]
    ld a, a
    adc l
    add [hl]
    sub b
    add a
    ld d, a
    db $ed
    inc h
    or $40
    ld a, a
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
    ld c, a
    or c
    reti


    or d
    jp Jump_016_7fc9


    jp nz, $bab3

    or e
    ld a, a
    or a
    sbc $bc
    ld d, a
    db $10
    inc b
    inc b
    ret nz

    ld l, a
    ld h, e
    ld l, e
    ld c, a
    ld l, e
    nop
    add d
    ld l, a
    jp Jump_000_3c6c


    ld a, [$d6f0]
    bit 1, a
    ret nz

    ld b, $06
    call Call_000_34dd
    ret nz

    ld b, $2d
    jp Jump_000_34dd


    ld [hl], e
    ld l, e
    reti


    ld l, e
    ld b, [hl]
    ld l, h
    ld l, b
    ld l, h
    add h
    ld l, h
    add hl, hl
    ld l, a
    ld b, e
    ld l, a
    ld h, l
    ld l, a
    ld [$f0fa], sp
    sub $cb
    ld a, a
    jr nz, jr_016_6b88

    ld hl, $6b96
    call Call_000_3c79
    ld hl, $d6f0
    set 6, [hl]
    jr jr_016_6b93

jr_016_6b88:
    ld hl, $6bb4
    call Call_000_3c79
    ld hl, $d6f0
    res 7, [hl]

jr_016_6b93:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    pop hl
    ld l, a
    rst $20
    ld a, a
    or e
    pop bc
    ret


    ld a, a
    ld b, c
    add l
    sub b
    xor [hl]
    add d
    ld c, a
    push bc
    sbc $c3
    ld a, a
    or [hl]
    call c, $b2b2
    ld a, a
    cp h
    rst $18
    ld c, b
    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    ld de, $e770
    ld d, c
    or e
    pop bc
    ret


    ld a, a
    ld b, c
    add l
    sub b
    xor [hl]
    add d
    ret


    ld a, a
    adc $b3
    ld h, $4f
    cp a
    ret


    ld a, a
    ld a, [hl-]
    or d
    jp z, $b67f

    call c, $b2b2
    ld a, a
    call c, $e7b2
    ld d, a
    ld [$f0fa], sp
    sub $cb
    ld [hl], a
    jr nz, jr_016_6bee

    ld hl, $6bfc
    call Call_000_3c79
    ld hl, $d6f0
    set 7, [hl]
    jr jr_016_6bf9

jr_016_6bee:
    ld hl, $6c22
    call Call_000_3c79
    ld hl, $d6f0
    res 6, [hl]

jr_016_6bf9:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld d, c
    ld [hl], b
    ret


    ld a, a
    or d
    call nz, $b2bc
    ld a, a
    ld b, b
    add d
    xor c
    add d
    rst $20
    ld d, c
    jr nc, @-$47

    cp h
    jp nc, $c4d9

    ld c, a
    or a
    pop hl
    db $e3
    rst $20
    ld a, a
    rst $18
    jp $c57f


    cp b
    ret


    sub $e7
    ld d, a
    db $ed
    ld a, [hl+]
    xor d
    ld [hl], b
    rst $20
    ld d, c
    or c
    ret nz

    cp h
    ret


    ld a, a
    ld b, b
    add d
    xor c
    add d
    ret


    ld a, a
    adc $b3
    ld h, $4f
    cp a
    ret


    ld a, a
    ld a, [hl-]
    or d
    jp z, $b67f

    call c, $b2b2
    call c, $e7d6
    ld d, a
    ld [$5821], sp
    ld l, h
    call Call_000_3c79
    ld a, $54
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    db $ec
    ld [hl], b
    xor [hl]
    add d
    ld [hl], d
    pop bc
    pop hl
    db $e3
    ld a, a
    ld b, l
    or [hl]
    pop bc
    pop hl
    ld d, a
    ld [$7a21], sp
    ld l, h
    call Call_000_3c79
    ld a, $3a
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    nop
    ld [hl], c
    add d
    ld [hl], d
    or a
    pop hl
    db $e3
    ld d, a
    ld [$52cd], sp
    ld l, e
    jr nz, jr_016_6cc4

    ld hl, $6ccd
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_016_6cbc

    ld hl, $6d33
    call Call_000_3c79
    ld bc, $2d01
    call Call_000_3e5e
    jr nc, jr_016_6cb4

    ld hl, $6e31
    call Call_000_3c79
    ld hl, $d6f0
    set 1, [hl]
    jr jr_016_6cca

jr_016_6cb4:
    ld hl, $6f1a
    call Call_000_3c79
    jr jr_016_6cca

jr_016_6cbc:
    ld hl, $6ec2
    call Call_000_3c79
    jr jr_016_6cca

jr_016_6cc4:
    ld hl, $6ee0
    call Call_000_3c79

jr_016_6cca:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    add hl, bc
    ld [hl], c
    or d
    cp l
    or a
    ld a, a
    add a
    and l
    dec de
    ret


    ld c, a
    or [hl]
    or d
    pop bc
    ld [c], a
    or e
    jp z, $dc7f

    cp h
    ld a, a
    inc l
    ldh [$e7], a
    ld d, c
    or [hl]
    rst $18
    jp Jump_016_7fd9


    ld d, h
    jp z, $f74f

    or $f6
    ld b, l
    or a
    db $dd
    ld a, a
    cp d
    or h
    call nz, $e7d9
    ld d, c
    ld d, h
    add $7f
    or [hl]
    sbc $bc
    jp Jump_016_4fca


    sbc h
    xor e
    sub e
    ld a, a
    or e
    reti


    cp e
    or d
    rst $20
    ld a, a
    inc sp
    cp l
    cpl
    rst $20
    ld d, c
    inc sp
    ld d, [hl]
    ld d, c
    or a
    ret nc

    jp z, $dc7f

    cp h
    ret


    ld a, a
    ld d, h
    ld a, a
    inc l
    rst $08
    sbc $dd
    ld c, a
    or a
    or a
    add $7f
    or a
    ret nz

    ret


    ld a, a
    or [hl]
    ret z

    and $57
    db $ed
    ld a, [hl+]
    xor c
    ld [hl], c
    rst $20
    ld c, a
    inc sp
    jp z, $bb7f

    rst $18
    cp a
    cp b
    ld a, a
    jp z, $d22c

    reti


    or [hl]
    rst $20
    ld d, c
    or c
    ret


    push bc
    ld d, [hl]
    ld a, a
    call c, $c9bc
    ld a, a
    or l
    or a
    add $b2
    ret c

    ret


    ld c, a
    ld b, $ad
    xor b
    xor h
    ld b, d
    ld h, $c5
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, c
    ld d, [hl]
    ld a, a
    inc sp
    push bc
    ld d, [hl]
    ld a, a
    ld h, $56
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    or [hl]
    call c, $b8b2
    jp Jump_016_56c5


    ld d, l
    ret nz

    rst $08
    rst $10
    sbc $56
    ld a, a
    cp b
    or e
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    cp e
    rst $10
    add $56
    ld a, a
    db $d3
    or e
    ld d, [hl]
    ld d, l
    cp l
    ld a, [hl+]
    cp l
    daa
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    inc sp
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    cp a
    or e
    ld a, a
    or l
    db $d3
    or e
    or [hl]
    ld d, [hl]
    ld d, l
    inc [hl]
    or e
    cp h
    jp Jump_016_7f56


    ld d, [hl]
    ld a, a
    cp l
    or a
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    jp z, $e7e3

    ld d, c
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    jr nc, @-$47

    cp h
    jp nc, Jump_016_56c3

    ld d, l
    ret z

    reti


    call nz, $d3b7
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    inc l
    ldh [$db], a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    cp l
    ld a, [hl-]
    rst $10
    cp h
    ld d, [hl]
    rst $20
    ld d, l
    ld d, [hl]
    ld a, a
    or e
    jp nz, $bcb8

    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    or c
    ret c

    ldh [$e7], a
    ld d, l
    db $d3
    or e
    ld a, a
    cp d
    sbc $c5
    ld a, a
    inc l
    or [hl]
    sbc $b6
    rst $20
    ld d, l
    pop bc
    ld [c], a
    rst $18
    call nz, $bc7f
    ldh [$3d], a
    ret c

    ld a, a
    cp l
    daa
    ret nz

    call c, Call_016_51b2
    call c, $c9bc
    ld a, a
    ld d, h
    ld a, a
    inc l
    rst $08
    sbc $dd
    ld c, a
    or l
    call nz, $bcc5
    cp b
    ld a, a
    or a
    or d
    jp $7fc0


    or l
    jp c, $c6b2

    ld d, l
    ld d, [hl]
    cp d
    jp c, $7fca

    or a
    db $d3
    pop bc
    ld a, a
    inc l
    ldh [$e7], a
    ld e, b
    db $ed
    ld a, [hl+]
    adc d
    ld [hl], e
    or [hl]
    or d
    pop bc
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
    ld d, b
    ld de, $5100
    cp a
    ret


    ld a, a

jr_016_6e50:
    res 6, a
    or [hl]
    or h
    cp c
    sbc $33
    ld c, a
    adc a
    rrca
    inc sp
    ld a, a
    inc l
    jp $bcde


    ldh [rNR52], a
    ld a, a
    db $d3
    rst $10
    or h
    reti


    rst $20
    ld d, c
    push bc
    add $7f
    call c, $c6bc
    jp z, $b57f

    or a
    add $b2
    ret c

    ret


    ld c, a
    call nz, Call_016_54d8
    ld a, a
    add h
    sub l
    inc de
    ret c

    and [hl]
    ld h, $7f
    or l
    reti


    ld d, l
    or d
    or a
    ret nz

    or d
    ld a, a
    call nz, $dbba
    call $cb7f
    call nz, $c4df
    dec sp
    inc l
    ldh [rHDMA1], a
    jr nc, jr_016_6e50

    rst $10
    ld a, a
    inc l
    jp $bcde


    ldh [$7f], a
    push bc
    inc [hl]
    ld a, a
    or d
    rst $10
    sbc $e7
    ld d, c
    inc l
    jp $bcde


    ldh [$ca], a
    ld a, a
    or a
    ret nc

    ld h, $4f
    cp l
    or a
    add $7f
    ret


    rst $18
    ret nz

    rst $10
    ld a, a
    or h
    or h
    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    cp h
    ld [hl], h
    ldh [rRP], a
    ld a, a
    jp nz, $d7cf

    sbc $4f
    or a
    cp b
    ld a, a
    or a
    add $7f
    push bc
    rst $18
    ret nz

    rst $10
    ld a, a
    or a
    jp $dab8


    or d
    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    rst $28
    ld [hl], h
    call nc, $7fe3
    ld d, d
    cp b
    sbc $e7
    ld d, c
    rst $08
    ret nz

    ld a, a
    call c, $c9bc
    ld a, a
    ld d, h
    ld a, a
    inc l
    rst $08
    sbc $dd
    ld c, a
    or a
    or a
    add $7f
    or a
    ret nz

    ret


    ld a, a
    or [hl]
    ret z

    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    or h
    ld a, a
    pop bc
    ld h, $b3
    and $4f
    push bc
    sbc $2c
    ldh [rRP], a
    ld a, a
    jp nz, $d7cf

    sbc $57
    db $ed
    ld a, [hl+]
    and [hl]
    ld [hl], h
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    ld a, a
    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    dec h
    ld a, d
    ld h, c
    ld a, a
    or [hl]
    or d
    pop bc
    ld [c], a
    or e
    jp z, $9c4f

    xor e
    sub e
    ld a, a
    ld d, h
    add $7f
    or e
    reti


    cp e
    or d
    ret


    rst $20
    ld d, a
    db $ed
    dec h
    or [hl]
    ld h, c
    cp h
    ret


    ld a, a
    inc l
    rst $08
    sbc $7f
    ld a, [hl-]
    push bc
    cp h
    add $ca
    ld c, a
    cp h
    dec l
    or [hl]
    add $7f
    ret nc

    ret nc

    db $dd
    ld a, a
    or [hl]
    ret nz

    pop de
    cp c
    sub $b3
    rst $20
    ld d, a
    db $ed
    dec h
    ld bc, $7f62
    inc l
    rst $08
    sbc $7f
    ld a, [hl-]
    push bc
    cp h
    jp z, $f74f

    or $3a
    or d
    ld a, a
    add $bc
    jp $b67f


    or h
    cp a
    or e
    rst $20
    ld d, a
    dec c
    ld [bc], a
    rlca
    ld [bc], a
    ld bc, $07ff
    inc bc
    ld bc, $02ff
    nop
    ld bc, $0007
    ld b, $08
    ld b, $2f
    rlca
    ld a, [bc]
    rst $38
    jp nc, Jump_000_0d01

    rlca
    dec b
    rst $38
    db $d3
    ld [bc], a
    jr c, jr_016_6faa

    ld a, [bc]
    rst $38
    jp nc, Jump_000_3c03

    ld [$ff05], sp

jr_016_6faa:
    db $d3
    inc b
    db $10
    dec b
    rlca
    rst $38
    ret nc

    dec b
    ld a, [hl+]
    dec b
    add hl, bc
    rst $38
    ret nc

    ld b, $12
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    rla
    ld [de], a
    inc de
    ld d, $19
    db $10
    ld de, $180f
    inc d
    dec d
    ld a, [de]
    inc bc
    inc c
    inc bc
    inc bc
    ld d, $09
    rrca
    ld l, $73
    ld [hl], c
    ld [hl], b
    call c, Call_000_006f
    call z, $cd72
    ld a, [c]
    ld l, a
    call Call_000_3c6c
    ld hl, $707b
    ld de, $706b
    ld a, [$d5c2]
    call Call_000_31a8
    ld [$d5c2], a
    ret


    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld hl, $7029
    call Call_016_702e
    call Call_016_705a
    ld a, [$d7a5]
    bit 5, a
    jr nz, jr_016_7019

    push af
    ld a, $54
    ld [$d07c], a
    ld bc, $0202
    ld a, $17
    call Call_000_3e9d
    pop af

jr_016_7019:
    bit 6, a
    ret nz

    ld a, $54
    ld [$d07c], a
    ld bc, $0502
    ld a, $17
    jp Jump_000_3e9d


    ld [bc], a
    ld [bc], a
    dec b
    ld [bc], a
    rst $38

Call_016_702e:
    push hl
    ld hl, $d6be
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    ld c, a
    xor a
    ldh [$e0], a
    pop hl

jr_016_703a:
    ld a, [hl+]
    cp $ff
    jr z, jr_016_7056

    push hl
    ld hl, $ffe0
    inc [hl]
    pop hl
    cp b

jr_016_7046:
    jr z, jr_016_704b

    inc hl
    jr jr_016_703a

jr_016_704b:
    ld a, [hl+]
    cp c
    jr nz, jr_016_703a

    ld hl, $d6be
    xor a
    ld [hl+], a
    ld [hl], a
    ret


jr_016_7056:
    xor a
    ldh [$e0], a
    ret


Call_016_705a:
    ld hl, $d7a5
    ldh a, [$e0]
    and a
    ret z

    cp $01
    jr nz, jr_016_7068

    set 5, [hl]
    ret


jr_016_7068:
    set 6, [hl]
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    xor h
    ld [hl], b
    adc h
    ld [hl], c
    rst $18
    ld [hl], c
    jr z, jr_016_70eb

    add [hl]
    ld [hl], d
    ld [bc], a
    jr nc, @-$5a

    rst $10
    sub [hl]
    ld [hl], c
    cp c
    ld [hl], c
    or b
    ld [hl], c
    or b
    ld [hl], c
    inc bc
    ld b, b
    and h
    rst $10
    jp hl


    ld [hl], c
    rlca
    ld [hl], d
    nop
    ld [hl], d
    nop
    ld [hl], d
    inc b
    jr nc, jr_016_703a

    rst $10
    ld [hl-], a
    ld [hl], d
    ld c, a
    ld [hl], d
    ld c, c
    ld [hl], d
    ld c, c
    ld [hl], d
    dec b
    jr nc, jr_016_7046

    rst $10
    sub b
    ld [hl], d
    or d
    ld [hl], d
    xor b
    ld [hl], d
    xor b
    ld [hl], d
    rst $38
    ld [$a5fa], sp
    rst $10
    bit 7, a

jr_016_70b2:
    jr nz, jr_016_70cf

    ld hl, $70d8
    call Call_000_3c79
    ld bc, $ec01
    call Call_000_3e5e
    ld hl, $717f
    jr nc, jr_016_70d2

    ld hl, $d7a5
    set 7, [hl]
    ld hl, $7123
    jr jr_016_70d2

jr_016_70cf:
    ld hl, $713e

jr_016_70d2:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld b, b
    ld [hl], l
    rst $20
    ld c, a
    jr nc, jr_016_70b2

    sub $7f
    ret nz

    cp l
    cp c
    jp $e7e3


    ld d, c
    ld d, [hl]
    ld a, a

jr_016_70eb:
    or c
    rst $10
    and $4f
    ld e, [hl]
    ld a, a
    inc l
    ldh [$c5], a
    or d
    ld d, l
    ld a, [hl+]
    jp nc, $c5de

    cp e
    or d
    ld d, l
    or c
    ret nz

    cp h
    ld a, a
    jp $b7df


    ret c

    ld d, [hl]
    ld d, l
    cp d
    jp c, $b37f

    pop bc
    ret


    ld a, a
    cp [hl]
    or d
    set 3, [hl]

jr_016_7112:
    ld a, a
    push bc
    ret


    ld d, l
    or c
    add hl, hl
    reti


    ld a, a
    or [hl]
    rst $10
    ld a, a
    push de
    reti


    cp h
    jp Jump_016_58c8


    db $ed
    ld a, [hl+]
    jp c, $b575

    ret z

    or h
    cp e
    sbc $b6
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
    ld d, b
    db $ed
    ld a, [hl+]
    nop
    db $76
    jp z, Jump_000_2c7f

    ld a, [hl-]
    cp b
    rst $20
    ld d, c
    cp d
    ret


    ld a, a
    call c, $ca2b
    ld a, a
    or a
    ld [c], a
    or e
    ret c

    ld [c], a
    cp b
    ld a, a
    jr nc, jr_016_7112

    inc [hl]
    ld c, a
    ld d, h
    jp z, $dc7f

    dec hl
    ret


    ld a, a
    or c
    call nz, $cb51
    sbc $bc
    inc l
    ld [c], a
    or e
    ret nz

    or d
    add $7f
    push bc
    reti


    call c, $b74f
    db $dd
    ld a, a
    jp nz, $c3b9

    ld a, a
    jp nz, $dfb6

    jp $ed57


    ld a, [hl+]
    jp $b275


    inc sp
    ld a, a
    db $d3
    jp $b2c5


    call c, Call_000_0857
    ld hl, $707b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld a, [$bd63]
    cp c
    jp Jump_016_4fe7


    call c, $bcc0
    jp z, $8b7f

    and [hl]
    sbc e
    ld a, a
    cp h
    ldh [$b2], a
    sbc $7f
    inc sp
    cp l
    ld d, a
    db $ed
    daa
    ld a, c
    ld h, h
    ld a, [hl-]
    jp c, $b6c0

    ld e, b
    db $ed
    daa
    inc h
    ld h, h
    jp z, $8b7f

    and [hl]
    sbc e
    ret


    ld a, a
    cp h
    ldh [$b2], a
    sbc $4f
    inc sp
    or c
    reti


    call nz, $347f
    or e
    inc l
    add $55
    ld e, [hl]
    or d
    sbc $7f
    inc sp
    db $d3
    ld a, a
    or c
    reti


    ret


    cp e
    ld d, a
    ld [$8721], sp
    ld [hl], b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    add l
    ld h, h
    ld a, a
    ret nz

    pop bc
    or d
    ret c

    ld a, a
    or a
    sbc $bc
    jr nc, jr_016_7247

    or [hl]
    or h
    ret c

    push bc
    cp e
    or d
    rst $20
    ld d, a
    db $ed
    daa
    ld sp, hl
    ld h, h
    or [hl]
    ld d, [hl]
    ld e, b
    db $ed
    daa
    xor h
    ld h, h
    ld a, a
    push bc
    or [hl]
    jp z, $cc7f

    cp b
    dec hl
    jp nz, Jump_000_2f30

    ld c, a
    or a
    ret nc

    add $7f
    cp d
    or e
    ret c

    ldh [$b8], a
    ld a, a
    inc sp
    or a
    reti


    or [hl]
    push bc
    and $57
    ld [$9321], sp
    ld [hl], b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    inc c
    ld h, l
    ld a, a
    cp d
    inc [hl]
    db $d3
    ret


    ld c, a
    cp b
    reti


    ld a, a
    call nz, $dbba
    ld a, a
    inc l
    ldh [$c5], a
    or d

jr_016_7247:
    rst $20
    ld d, a
    db $ed
    daa
    cp d
    ld h, l
    rst $20
    ld e, b
    db $ed
    daa
    ld l, $65
    ret nz

    ld a, a
    ld [de], a
    ld a, [bc]
    add c
    xor e
    ret


    ld a, a
    push de
    or [hl]
    jp z, $924f

    and a

jr_016_7261:
    ld b, e
    db $e3
    sub e
    ld a, a
    dec de
    xor b
    xor h
    add a
    jr nc, @-$17

    ld d, c
    sbc c
    add c
    sub d
    add a
    push bc
    ld a, a
    ld a, [de]
    and [hl]
    ret


    ld a, a
    push bc
    or [hl]
    inc sp
    ret


    ld c, a
    or d
    inc [hl]
    or e
    ld a, a
    cp h
    pop hl
    jr nc, jr_016_7261

    jr nc, jr_016_72b3

    ld d, a
    ld [$9f21], sp
    ld [hl], b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ret z

    ld h, l
    ld a, a
    cp d
    inc [hl]
    db $d3
    rst $20
    ld c, a
    or e
    db $db
    or e
    db $db
    ld a, a
    cp l
    reti


    sbc $2c
    ldh [$c5], a
    or d
    rst $20
    ld d, a
    db $ed
    daa
    ld b, e
    ld h, [hl]
    cp h
    cp b
    inc l
    rst $18
    ret nz

    ld e, b

jr_016_72b2:
    db $ed

jr_016_72b3:
    daa
    ld a, [c]
    ld h, l
    adc e
    and [hl]
    sbc e
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    call nz, $c355
    or d
    cp c
    or d
    ld a, a
    cp l
    reti


    ret


    jr nc, jr_016_72b2

    ld d, a
    ld l, $07
    nop
    jr jr_016_72d3

    or l
    nop

jr_016_72d3:
    ld a, [de]
    nop
    ret nc

    nop
    inc d
    nop
    db $ec
    inc bc
    inc bc
    ld b, $d0
    inc bc
    dec c
    inc b
    push de
    rrca
    dec de
    dec b
    push de
    rrca
    add hl, bc
    inc b
    db $d3
    nop
    dec b
    dec de
    dec b
    ld c, $ff
    pop de
    ld bc, $1020
    add hl, bc
    rst $38
    ret nc

    ld b, d
    db $e4
    ld [bc], a
    jr nz, jr_016_730d

    inc e
    rst $38
    jp nc, $e443

    inc bc
    jr jr_016_7313

    inc d
    rst $38
    pop de
    ld b, h
    and $17
    jr jr_016_7317

    inc e

jr_016_730d:
    rst $38
    pop de
    ld b, l
    and $18
    ld a, [bc]

jr_016_7313:
    rst $00
    nop
    jr jr_016_7322

jr_016_7317:
    rst $00
    nop
    ld a, [de]
    ld [$00c7], sp
    inc d
    inc d
    rst $00
    inc bc
    inc bc

jr_016_7322:
    add hl, de
    rst $00
    inc bc
    dec c
    sbc [hl]
    rst $00
    rrca
    dec de
    sub l
    rst $00
    rrca
    add hl, bc
    ld b, b
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    ld b, d
    dec a
    dec a
    dec a
    dec a
    ld a, h
    dec a
    inc h
    ld a, l
    ld a, $44
    cpl
    ld c, $0e
    ld c, $46
    cpl
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld b, b
    ld h, e
    ld c, $67
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    ld b, c
    ld h, e
    ld c, $67
    ld b, d
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld b, h
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld a, e
    ld c, $7b
    add hl, bc
    ld b, b
    ld h, c
    ld h, c
    ld h, d
    ld b, b
    ld h, e
    ld c, $67
    ld b, c
    ld b, d
    ld c, $36
    ld c, $36
    add hl, bc
    ld d, l
    ld c, $0e
    ld h, [hl]
    ld b, h
    ld a, e
    ld c, $0b
    dec bc
    ld b, [hl]
    ld c, $36
    ld c, $36
    ld c, $0e
    ld c, $0e
    ld b, [hl]
    ld b, h
    scf
    ld c, $0e
    cpl
    ld b, [hl]
    ld c, $37
    ld c, $37
    ld c, $59
    ld b, a
    cpl
    ld b, [hl]
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, b
    ld c, c
    ld c, c
    ld c, d
    ld d, $09
    rrca
    cp h
    ld [hl], l
    ld a, [hl+]
    ld [hl], h
    pop bc
    ld [hl], e
    nop
    ld c, e
    ld [hl], l
    call Call_016_73d7
    call Call_000_3c6c
    ld hl, $7432
    ld de, $7424
    ld a, [$d5c3]
    call Call_000_31a8
    ld [$d5c3], a
    ret


Call_016_73d7:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld hl, $740e
    call Call_016_702e
    call $7413
    ld a, [$d7a7]
    bit 0, a
    jr nz, jr_016_73fe

    push af
    ld a, $5f
    ld [$d07c], a
    ld bc, $0404
    ld a, $17
    call Call_000_3e9d
    pop af

jr_016_73fe:
    bit 1, a
    ret nz

    ld a, $5f
    ld [$d07c], a
    ld bc, $0408
    ld a, $17
    jp Jump_000_3e9d


    inc b
    inc b
    inc b
    ld [$21ff], sp
    and a
    rst $10
    ldh a, [$e0]
    and a
    ret z

    cp $01
    jr nz, jr_016_7421

    set 0, [hl]
    ret


jr_016_7421:
    set 1, [hl]
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld c, e
    ld [hl], h
    sub h
    ld [hl], h
    jp hl


    ld [hl], h
    push bc
    rrca
    ld [bc], a
    jr nz, @-$58

    rst $10
    sbc [hl]
    ld [hl], h
    pop bc
    ld [hl], h
    cp d
    ld [hl], h
    cp d
    ld [hl], h
    inc bc
    jr nc, @-$58

    rst $10
    di
    ld [hl], h
    rla
    ld [hl], l
    db $10
    ld [hl], l
    db $10
    ld [hl], l
    rst $38
    ld [$b7fa], sp
    rst $10
    bit 7, a
    ld hl, $747b
    jr nz, jr_016_7459

    ld hl, $745f

jr_016_7459:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    push bc
    db $76
    adc e
    and [hl]
    sbc e
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    ret


    ld c, a
    cp h
    ldh [$b2], a
    sbc $33
    cp l
    ld d, [hl]
    ld a, a
    or l
    db $db
    or l
    db $db
    ld d, a
    db $ed
    ld a, [hl+]
    adc a
    db $76
    call nz, Call_016_544f
    ret


    ld a, a
    or l
    or [hl]
    add hl, hl
    inc sp
    ld d, l
    adc $de
    call nz, $c07f
    cp l
    or [hl]
    rst $18
    ret nz

    sub $57
    ld [$3221], sp
    ld [hl], h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa

jr_016_74a0:
    ld e, b
    ld h, [hl]
    pop bc
    ret


    ld a, a
    inc l
    ldh [$cf], a
    db $dd
    ld a, a
    cp l
    reti


    ld c, a
    call nc, $cac2
    ld a, a
    inc l
    ldh [$cf], a
    ld a, a
    push bc
    ret


    jr nc, jr_016_74a0

    ld d, a
    db $ed
    daa
    call $c066
    rst $20
    ld e, b
    db $ed
    daa
    add c
    ld h, [hl]
    jp z, $9a7f

    xor e
    sub e
    jr nc, @-$17

    ld c, a
    cp h
    rst $08
    rst $18
    jp Jump_016_7fd9


    inc de
    add b
    ret


    ld a, a
    add l
    ld b, $ca
    ld d, l
    add l
    db $e3
    inc de
    ld a, a
    add [hl]
    db $e3
    inc sp
    ld a, a
    or c
    cp c
    rst $10
    jp c, Jump_016_57d9

    ld [$3e21], sp
    ld [hl], h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    db $dd
    ld h, [hl]
    jp z, $8b4f

    and [hl]
    sbc e
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    sub $d8
    ld d, l
    ld e, [hl]
    add $7f
    ret nc

    or [hl]
    ret nz

    ld a, a
    cp l
    reti


    rst $20
    ld d, a
    db $ed
    daa
    or h
    ld h, a
    or h
    rst $20
    ld e, b
    db $ed
    daa
    inc a
    ld h, a
    add $51
    ld e, [hl]
    ret


    ld a, a
    jp c, $c1de

    pop hl
    or e
    ld h, $4f
    or l
    db $d3
    or e
    ld a, a
    cpl
    sbc $3c
    sbc $55
    ld d, h
    ret


    ld a, a
    cp c
    sbc $b7
    pop hl
    or e
    db $dd
    ld d, l
    cp e
    cp [hl]
    jp $b87f


    jp c, $dfd9

    jp $b27f


    rst $18
    ret nz

    sbc $33
    ret z

    ld d, a
    ld l, $0a
    nop
    ld a, [de]
    ld bc, $00cf
    jr jr_016_7554

jr_016_7554:
    pop de
    nop
    inc d
    nop
    db $ec
    dec bc
    rla
    add hl, bc
    ret nc

    inc bc
    inc bc
    dec b
    jp nc, $030f

    ld b, $d2
    inc bc
    dec de
    inc bc
    rst $08
    dec bc
    inc bc
    inc bc
    jp hl


    dec bc
    dec bc
    inc b
    call nc, $1b0f
    inc bc
    ret nc

jr_016_7575:
    nop
    inc b
    inc l
    inc c
    inc e
    rst $38
    rst $38
    ld bc, $0b18
    jr @+$01

    jp nc, $e642

    add hl, de
    jr nz, jr_016_7594

    dec bc
    rst $38
    ret nc

    ld b, e
    db $e4
    inc b
    dec a
    add hl, bc
    inc c
    rst $38
    rst $38
    add h
    ld [de], a

jr_016_7594:
    dec bc
    rst $00
    nop
    ld a, [de]
    ld a, [bc]
    rst $00
    nop
    jr jr_016_75a5

    rst $00
    nop
    inc d
    ld [hl], d
    rst $00
    dec bc
    rla
    inc d

jr_016_75a5:
    rst $00
    inc bc
    inc bc
    sub d
    rst $00
    rrca
    inc bc
    jr nz, jr_016_7575

    inc bc
    dec de
    ld l, b
    rst $00
    dec bc
    inc bc
    ld l, h
    rst $00
    dec bc
    dec bc
    sbc [hl]
    rst $00
    rrca
    dec de
    inc a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    ld a, h
    dec a
    ld a, l
    inc h
    ld a, $44
    cpl
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $2f
    ld b, [hl]
    ld h, b
    ld h, c
    ld h, c
    ld b, c
    ld b, d
    ld h, c
    ld b, c
    ld h, c
    ld b, d
    ld c, $5a
    ld h, c
    ld h, c
    ld h, c
    ld h, d
    ld h, h
    ld c, $34
    ld c, $56
    ld c, $0e
    ld c, $56
    ld c, $56
    ld c, $0e
    ld c, $66
    ld b, h
    ld c, $36
    ld c, $0e
    ld c, $47
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld b, a
    ld b, [hl]
    ld b, h
    cpl
    scf
    ld c, $5a
    cpl
    ld c, $0e
    ld e, d
    ld c, $5a
    cpl
    ld b, e
    ld b, e
    ld b, [hl]
    ld d, b
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld c, $56
    ld c, c
    ld c, c
    ld c, c
    ld d, c
    ld b, h
    cpl
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $2f
    ld b, [hl]
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld d, $09
    ld [$77f4], sp
    sbc h
    db $76
    ld c, a
    halt
    sub l
    ld [hl], a
    call Call_016_7665
    call Call_000_3c6c
    ld hl, $76a8
    ld de, $7696
    ld a, [$d5d7]
    call Call_000_31a8
    ld [$d5d7], a
    ret


Call_016_7665:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld hl, $7689
    call Call_016_702e
    call Call_016_768c
    ld a, [$d7b5]
    bit 0, a
    ret nz

    ld a, $54
    ld [$d07c], a
    ld bc, $0405
    ld a, $17
    jp Jump_000_3e9d


    inc b
    dec b
    rst $38

Call_016_768c:
    ldh a, [$e0]
    and a
    ret z

    ld hl, $d7b5
    set 0, [hl]
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    pop bc
    db $76
    ld a, [de]
    ld [hl], a
    ld e, d
    ld [hl], a
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    ld bc, $b430
    rst $10
    bit 6, [hl]
    ld a, [c]
    db $76
    ld [$ea76], a
    db $76

jr_016_76b4:
    ld [bc], a
    ld b, b
    or h
    rst $10
    inc h
    ld [hl], a
    ld a, $77
    jr c, @+$79

    jr c, jr_016_7737

    rst $38
    ld [$a821], sp
    db $76
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, @-$4a

    ld c, d
    or d
    add $7f
    sub $b3
    cp d
    cp a
    rst $20
    ld c, a
    sub $b8
    ld a, a
    cp d
    cp d
    rst $08
    inc sp
    ld a, a
    ret nz

    inc [hl]
    ret c

    ld a, a
    jp nz, $c0b2

    push bc

jr_016_76e8:
    rst $20
    ld d, a
    db $ed
    jr z, @+$79

    ld c, e
    cp d
    rst $18
    ret nz

    ld e, b

jr_016_76f2:
    db $ed
    jr z, jr_016_76e8

    ld c, d
    inc sp
    ld a, a
    or a
    ret nz

    ret


    jp z, $ce7f

    jp nc, Jump_000_26d9

    ld c, a
    cp h
    ldh [$c1], a
    ld [c], a
    or e
    ld a, a
    cp h
    jp nz, Jump_016_55ca

    cp e
    rst $10
    add $7f
    or e
    or h
    ret


    ld a, a
    or [hl]
    or d
    ld a, a
    jr nc, @+$30

    ld d, a
    ld [$b421], sp
    db $76
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_016_76b4

    ld c, e
    ld c, a
    or c
    cp a
    dec sp
    jp z, $b57f

    call c, $c6d8
    ld a, a
    cp h
    sub $b3
    rst $20

jr_016_7737:
    ld d, a
    db $ed
    jr z, jr_016_7748

    ld c, h
    sbc $58
    db $ed
    jr z, jr_016_76f2

    ld c, e
    ld a, a
    or [hl]
    rst $18
    jp $cf7f


jr_016_7748:
    sbc $2f
    cp b
    or [hl]
    ld c, a
    inc l
    ldh [$7f], a
    or l
    or e
    pop bc
    add $7f
    or [hl]
    or h
    sbc $c5
    ld d, a
    ld [$b7fa], sp
    rst $10
    bit 7, a
    ld hl, $777c
    jr nz, jr_016_7768

    ld hl, $776e

jr_016_7768:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld hl, $de77
    rst $20
    ld d, l
    cp d
    call c, $d6b2
    db $e3
    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    push af
    db $76
    ld h, $7f
    push bc
    or d
    jp $7fc0


    cp d
    call nz, Call_016_5556
    push bc
    or d
    cp h
    ld [c], a
    add $7f
    cp h
    jp Jump_016_57c8


    ld l, $06
    nop
    ld [$e900], sp
    nop
    ld a, [bc]
    nop
    db $eb
    nop
    inc c
    nop
    db $ec
    dec bc
    add hl, bc
    inc bc
    pop de
    rrca
    dec c
    dec b
    pop de
    rlca
    dec c
    ld b, $d1
    nop
    ld b, $18
    dec c
    dec b
    rst $38
    db $d3
    ld b, c
    and $27
    jr nz, jr_016_77c1

    ld c, $ff
    jp nc, $e442

    dec bc

jr_016_77c1:
    dec de
    inc de
    dec c
    cp $00
    inc bc
    dec a
    db $10
    ld b, $ff
    rst $38
    add h
    ld [c], a
    dec a
    ld [de], a
    ld [$ffff], sp
    add l
    jr z, jr_016_7813

    rrca
    add hl, bc
    rst $38
    rst $38
    add [hl]
    ld h, $fb
    add $00
    ld [$c6fc], sp
    nop
    ld a, [bc]
    db $fd
    add $00
    inc c
    ld b, c
    rst $00
    dec bc
    add hl, bc
    ld e, a
    rst $00
    rrca
    dec c
    daa
    rst $00
    rlca
    dec c
    inc a
    dec a
    dec a
    dec a
    inc h
    ld a, l
    ld a, h
    ld a, $44
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld e, d
    ld h, e
    ld c, $67
    ld b, d
    ld b, h
    ld c, $0e
    ld b, [hl]
    dec c
    ld c, $2f

jr_016_7813:
    ld b, [hl]
    ld b, b
    ld a, [hl+]
    dec hl
    ld b, d
    ld h, e
    ld c, $67
    ld b, d
    ld b, h
    dec [hl]
    jr jr_016_7866

    cpl
    ld c, $7b
    ld b, [hl]
    ld b, h
    ld e, $35
    ld b, [hl]
    ld c, $7b
    scf
    ld b, [hl]
    ld b, h
    ld a, [bc]
    ld e, $46
    ld c, $37
    cpl
    ld b, [hl]
    ld c, b
    ld c, c
    ld c, c
    ld c, d
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    dec b
    dec c
    dec c
    ld [de], a
    ld a, e
    cpl
    ld a, c
    ld c, b
    ld a, b
    nop
    xor $7a
    call Call_016_785e
    call Call_000_3c6c
    ld hl, $7931
    ld de, $7894
    ld a, [$d5d2]
    call Call_000_31a8
    ld [$d5d2], a
    ret


Call_016_785e:
Jump_016_785e:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

jr_016_7866:
    ld a, [$d7e5]
    bit 7, a
    jr nz, jr_016_7874

    ld a, $31
    ld b, $32
    jp Jump_016_7878


jr_016_7874:
    ld a, $72
    ld b, $73

Jump_016_7878:
    push bc
    ld [$d07c], a
    ld bc, $0602
    call Call_016_788a
    pop bc
    ld a, b
    ld [$d07c], a
    ld bc, $0603

Call_016_788a:
    ld a, $17
    jp Jump_000_3e9d


Jump_016_788f:
    xor a
    ld [$d5d2], a
    ret


    sbc a
    ld a, b
    sub h
    ld [hl-], a
    db $e3
    ld a, b
    inc e
    ld a, c
    sbc [hl]
    ld a, b
    ret


    ld a, [$d7e5]
    bit 6, a
    ret nz

    ld hl, $78d8
    call Call_000_3509
    jp nc, Jump_000_3261

    xor a
    ldh [$b4], a
    ld a, [$cd3d]
    cp $03
    jr nc, jr_016_78bf

    ld a, $01
    ldh [$8c], a
    jp Jump_000_13f1


jr_016_78bf:
    cp $05
    jr z, jr_016_78f5

    ld hl, $d7e5
    bit 7, [hl]
    set 7, [hl]
    ret nz

    ld hl, $d0eb
    set 5, [hl]
    ld a, $ad
    call Call_000_0e45
    jp Jump_016_785e


    ld bc, $0205
    ld b, $0b
    dec b
    dec bc
    ld b, $10
    jr @+$01

    call Call_000_32bd
    ld a, [$d034]
    cp $ff
    jp z, Jump_016_788f

    ld a, $01
    ldh [$8c], a
    jp Jump_000_13f1


jr_016_78f5:
    ld a, $ff
    ld [$cd66], a
    ld hl, $ccd3
    ld de, $7913
    call Call_000_3556
    dec a
    ld [$cd38], a
    call Call_000_34d0
    ld a, $03
    ld [$d5d2], a
    ld [$d97c], a
    ret


    ld b, b
    inc c
    jr nz, @+$0e

    add b
    rlca
    jr nz, jr_016_7921

    rst $38
    ld a, [$cd38]
    and a
    ret nz

jr_016_7921:
    call Call_000_3e07
    xor a
    ld [$cd66], a
    ld [$d5d2], a
    ld [$d97c], a
    ret


    ld a, $79
    ld bc, $e500
    rst $10
    ld c, b
    ld a, c
    ld a, [hl+]
    ld a, d
    inc c
    ld a, d
    inc c
    ld a, d
    rst $38
    ld [$3121], sp
    ld a, c
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $98
    ld b, c
    rst $20
    ld a, a
    or a
    ret nc

    or h
    ret z

    push bc
    ld a, a
    adc $c1
    call Call_016_7fc5
    rst $08
    add $7f
    call nc, $c1c8
    call nc, $4f7f
    ld e, l
    ld a, a
    ret


    db $d3
    ld a, a
    ld d, e
    add c
    ld d, l
    xor b
    push bc
    adc h
    ld a, a
    ld d, [hl]
    adc h
    ld a, a
    ret


    db $d3
    ld a, a
    pop bc
    rst $00
    ret


    call z, $d2c5
    ld d, l
    ld a, a
    call nc, $c1c8
    adc $7f
    reti


    rst $08
    push de
    add c
    ret z

    pop bc
    db $d3
    ld a, a
    call nz, $c6c5
    ld d, l
    push bc
    pop bc
    call nc, $c4c5
    ld a, a
    rst $08
    push de
    jp nc, $a27f

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
    xor [hl]
    rst $08
    rst $10
    adc h
    ld a, a
    rst $08
    adc $cc
    reti


    ld a, a
    ret z

    ld d, l
    push bc
    ld a, a
    ret


    db $d3
    ld a, a
    jp nc, $c1c5

    call z, $d9cc
    ld a, a
    call nc, $c5c8
    ld a, a
    call nc, $d255
    push de
    push bc
    ld a, a
    jp $c1c8


    call Call_016_7fd0
    rst $08
    add $7f
    pop bc
    call z, $c9cc
    ld d, l
    pop bc
    adc $c3
    push bc
    ld a, a
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld a, a
    ld d, c
    db $ec
    db $e4
    ld a, d
    or [hl]
    rst $10
    ld c, a
    adc e
    xor h
    ld b, e
    ld a, a
    rst $08
    or d
    jp $b67f


    or h
    reti


    or [hl]
    or d
    rst $20
    ld d, l
    ld d, d
    rst $20
    ld d, a
    db $ed
    ld h, $7d
    ld b, e

jr_016_7a10:
    rst $20
    ld d, c
    cp b
    call nc, $b2bc
    ld h, $7f
    or a
    ret nc

    ret


    ld c, a
    ld d, h
    ret


    ld a, a
    or e
    inc sp
    jp z, $ce7f

    sbc $d3
    ret


    jr nc, jr_016_7a10

    ld e, b
    nop
    and [hl]
    call z, $c9d9
    adc $c7
    ld a, a
    call nz, $c1d2
    rst $00
    rst $08
    adc $7f
    pop bc
    jp nc, Jump_016_4fcd

    reti


    ld a, a
    ret z

    pop bc
    db $d3
    ld a, a
    call z, $d3cf
    call nc, Call_016_528c
    add c
    ld d, l
    and [hl]
    jp nc, $cdcf

    ld a, a
    adc $cf
    rst $10
    ld a, a
    rst $08
    adc $8c
    reti


    rst $08
    push de
    ld a, a
    pop bc
    ld d, l
    jp nc, Jump_016_7fc5

    call nc, $c5c8
    ld a, a
    jp $c1c8


    call $cfd0
    add $7f
    pop bc
    call z, $cc55
    ret


    pop bc
    adc $c3
    push bc
    ld a, a
    ld d, h
    add c
    xor [hl]
    rst $08
    rst $10
    ld a, a
    xor c
    add a
    ld d, l
    call nz, $cc7f
    ret


    set 0, l
    ld a, a
    call nc, Call_016_7fcf
    call nc, $ccc1
    bit 7, a
    pop bc
    jp nz, $cf55

    push de
    call nc, $567f
    adc h
    reti


    rst $08
    push de
    adc h
    ret


    adc $7f
    add $c1
    jp $d455


    adc h
    call $d3d5
    call nc, $c37f
    rst $08
    call $c5d0
    call nc, Call_016_7fc5
    rst $10
    ret


    ld d, l
    call nc, Call_016_7fc8
    rst $08
    adc $c5
    ld a, a
    ret nc

    push bc
    jp nc, $cfd3

    adc $81
    ld d, c
    db $ec
    ld d, b
    ld a, c
    or d
    rst $08
    call nc, $b67f

jr_016_7acb:
    jp c, $bfba

    ld a, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld c, a
    cp h
    sbc $c9
    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    ld a, a
    push bc
    ret


    jr nc, jr_016_7acb

    ld d, b
    ld [$e521], sp
    rst $10
    set 6, [hl]
    jp Jump_000_0f6a


    inc bc
    inc bc
    db $10
    jr jr_016_7af5

    rst $30
    nop

jr_016_7af5:
    dec b
    nop
    ld a, b
    nop
    ld b, $00
    ld a, b
    nop
    ld bc, $051e
    ld a, [bc]
    rst $38
    ret nc

    ld b, c
    rst $30
    ld bc, $c7a0
    db $10

jr_016_7b09:
    jr jr_016_7b09

    add $00
    dec b
    rst $38
    add $00
    ld b, $49
    ld bc, $3231
    ld bc, $034a
    inc bc
    inc bc
    ld c, c
    ld sp, $4a32
    ld c, e
    ld [hl-], a
    dec b
    dec b
    ld sp, $034c
    inc bc
    inc bc
    ld c, e
    dec b
    dec b
    ld c, h
    ld c, e
    ld [hl-], a
    dec b
    dec b
    ld sp, $034c
    inc bc
    inc bc
    ld c, e
    dec b
    dec b
    ld c, h
    ld c, e
    ld [hl-], a
    dec b
    dec b
    ld sp, $034c
    inc bc
    inc bc
    ld d, d
    ld sp, $6f32
    ld c, e
    ld [hl-], a
    dec b
    dec b
    ld sp, $034c
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ld c, e
    ld [hl-], a
    dec b
    dec b
    ld sp, $034c
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ld d, d
    ld d, [hl]
    ld [hl], d
    ld [hl], e
    ld c, [hl]
    ld l, a
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ld c, e
    dec b
    dec b
    ld c, h
    inc bc
    inc bc
    inc bc
    ld c, c
    ld bc, $0101
    ld c, d
    inc bc
    ld c, e
    dec b
    dec b
    ld c, h
    inc bc
    inc bc
    inc bc
    ld c, e
    dec b
    dec b
    dec b
    ld [hl], b
    inc bc
    ld c, e
    dec b
    dec b
    ld c, h
    inc bc
    inc bc
    inc bc
    ld c, e
    ld d, e
    ld b, [hl]
    ld b, [hl]
    ld l, a
    inc bc
    ld c, e
    dec b
    dec b
    ld c, h
    inc bc
    inc bc
    inc bc
    ld c, e
    ld c, h
    inc bc
    inc bc
    inc bc
    inc bc
    ld c, e
    dec b
    dec b
    ld d, l
    ld c, b
    ld c, b
    ld c, b
    ld e, e
    ld c, h
    inc bc
    inc bc
    inc bc
    inc bc
    ld d, d
    ld b, [hl]
    ld b, [hl]
    ld b, [hl]
    ld b, [hl]
    ld b, [hl]
    ld b, [hl]
    ld b, [hl]
    ld l, a
    inc bc
    inc bc
    inc bc
    rlca
    inc b
    dec b
    ld [hl], e
    ld a, l
    sub e
    ld a, h
    rst $00
    ld a, e
    nop
    ld e, c
    ld a, l
    call Call_000_3c6c
    ld hl, $7bdb
    ld a, [$d5ca]
    jp Jump_000_3dc7


    xor a
    ld [$cd66], a
    ld [$d5ca], a
    ret


    ld [hl], $7c
    ld d, h
    ld a, h
    db $e4
    ld a, e
    db $e3
    ld a, e
    ret


    call Call_000_3e07
    ld a, [$d2d7]
    push af
    xor a
    ld [$cd66], a
    ld a, $55
    call Call_000_3e9d
    pop af
    ld [$d2d7], a
    ld hl, $d6b2
    res 1, [hl]
    inc hl
    set 0, [hl]
    xor a
    ld hl, $d5cc
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$d5d2], a
    ld [$d5ca], a
    ld hl, $d7e2
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    xor a
    ld [$d5ca], a
    ld a, $00
    ld [$d698], a
    ld b, $1c
    ld hl, $7ce3
    call Call_000_3620
    ld b, $05

jr_016_7c28:
    ld c, $78
    call Call_000_3781
    dec b
    jr nz, jr_016_7c28

    call Call_000_38ae
    jp Jump_000_09da


    ld a, $ff
    ld [$cd66], a
    ld hl, $ccd3
    ld de, $7c51
    call Call_000_3556
    dec a
    ld [$cd38], a
    call Call_000_34d0
    ld a, $01
    ld [$d5ca], a
    ret


    ld b, b
    dec b
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    ld a, $01
    ld [$d4a7], a
    ld a, $01
    ldh [$8c], a
    call Call_000_358b
    ld a, $08
    ldh [$8d], a
    call Call_000_34f0
    call Call_000_3e07
    xor a
    ld [$cd66], a
    inc a
    ld [$d4a7], a
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    ld a, $ff
    ld [$cd66], a
    ld a, $08
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $02
    ld [$d5ca], a
    ret


    sub l
    ld a, h
    db $ed
    ld h, $c0
    ld b, e
    inc de
    ld [hl], d
    ld d, [hl]
    ld a, a
    or l
    adc $de
    xor h
    rst $20
    ld c, a
    or l
    jp nc, $c433

    or e
    rst $20
    ld a, a
    ld d, d
    rst $20
    ld d, c
    cp d
    cp d
    jp z, Jump_016_4f56

    jp c, $30b7

    or d
    ret


    ld a, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld d, l
    ld e, l
    ret


    ld a, a
    db $d3
    call nz, Call_016_5633
    ld d, c
    or [hl]
    jp nz, $b8d4

    ld a, a
    cp h
    ret nz

    ld a, a
    ld d, h
    ld a, a
    ret nz

    pop bc
    db $dd
    ld c, a
    or h
    or d
    or h
    sbc $c6
    ld a, a
    or a
    db $db
    cp b
    ld a, a
    cp h
    jp $c055


    ret nz

    or h
    reti


    ld a, a
    sbc e
    xor b
    add b
    ld a, a
    inc sp
    or c
    reti


    rst $20
    ld d, c
    ld d, h
    ld a, a
    ld e, l
    jp z, $ba7f

    cp d
    add $4f
    or a
    db $db
    cp b
    ld a, a
    cp e
    jp c, Jump_016_7fd9

    sub $db
    cp d
    dec sp
    db $dd
    ld d, l
    inc sp
    sbc $34
    or e
    or d
    ret c

    ld a, a
    call nz, $d67f
    sbc $33
    ld a, a
    or d
    reti


    rst $20
    ld d, c
    ld d, d
    rst $20
    ld a, a
    or l
    rst $08
    or h
    jp z, $ca4f

    add hl, hl
    cp h
    or d
    ld a, a
    ret nz

    ret nz

    or [hl]
    or d
    ret


    ld a, a
    cp l
    or h
    ld d, l
    ret c

    db $e3
    rlca
    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    call nz, $c57f
    rst $18
    ret nz

    rst $20
    ld d, c
    cp d
    cp d
    add $7f
    ld d, d
    ret


    ld a, a
    push bc
    rst $08
    or h
    call nz, Call_016_544f
    ld a, a
    ret nz

    pop bc
    db $dd
    ld a, a
    or a
    db $db
    cp b
    ld a, a
    cp h
    sub $b3
    rst $20
    ld d, a
    inc bc
    ld [bc], a
    rlca
    inc b
    ld [bc], a
    ld a, b
    rlca
    dec b
    inc bc
    ld a, b
    nop
    ld bc, $0603
    add hl, bc
    rst $38
    ret nc

    ld bc, $c717
    rlca
    inc b
    rla
    rst $00
    rlca
    dec b
    inc d
    inc d
    ld h, l
    inc d
    inc d
    jr jr_016_7d92

    scf
    jr @+$1a

    jr @+$1a

    jr @+$1a

    jr jr_016_7d9b

    jr jr_016_7df1

    jr @+$1a

    ld a, [$d034]
    dec a
    jr nz, jr_016_7dac

    ld a, [$d2dd]
    cp $90

jr_016_7d92:
    jr c, jr_016_7d98

    cp $95
    jr c, jr_016_7dc6

jr_016_7d98:
    ld a, [$cfbf]

jr_016_7d9b:
    call Call_000_2dc7
    ld hl, $7e29
    ld a, [$d03c]
    and a
    jr z, jr_016_7daa

    ld hl, $7e42

jr_016_7daa:
    jr jr_016_7db7

jr_016_7dac:
    call Call_016_7e17
    ld c, $14
    call Call_000_3781
    ld hl, $7e68

jr_016_7db7:
    push hl
    ld hl, $6bdc
    ld b, $0e
    call Call_000_3620
    pop hl
    call Call_000_3c79
    jr jr_016_7e28

jr_016_7dc6:
    ld b, $48
    call Call_000_34dd
    ld a, [$cfbf]
    ld [$cf78], a
    cp $91
    jr z, jr_016_7df1

    ld a, b
    and a
    jr z, jr_016_7de3

    ld hl, $6df1
    ld b, $0f
    call Call_000_3620
    jr jr_016_7d98

jr_016_7de3:
    ld hl, $7e5a
    call Call_000_3c79
    ld hl, $7e9a
    call Call_000_3c79
    jr jr_016_7e28

jr_016_7df1:
    ld a, b
    and a
    jr z, jr_016_7de3

    ld hl, $7e5a
    call Call_000_3c79
    ld hl, $7e7c
    call Call_000_3c79
    ld hl, $6df1
    ld b, $0f
    call Call_000_3620
    ld hl, $4e36
    ld b, $1c
    call Call_000_3620
    ld hl, $7e29
    call Call_000_3c79

Call_016_7e17:
    xor a
    ld [$c0f1], a
    ld a, $80
    ld [$c0f2], a
    ld a, $e9
    call Call_000_0e45
    jp Jump_000_3790


jr_016_7e28:
    ret


    db $ed
    ld a, [hl+]
    reti


    ld [hl], a
    call nc, $b2be
    ret


    ld c, a
    ld d, b
    ld bc, $cfc1
    nop
    ld h, $7f
    call nz, Call_000_303b
    cp h
    jp $c0b7


    rst $20
    ld e, b
    db $ed
    inc l
    ld b, a
    ld l, b
    add hl, hl
    ret nz

    ld a, a
    ld d, b
    ld bc, $cfc1
    nop
    ld h, $4f
    call nz, $b63b
    or [hl]
    rst $18
    jp $c0b7


    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    adc b
    ld [hl], a
    ld h, $7f
    ld c, a
    or c
    rst $10
    call c, $c0da
    rst $20
    ld e, b
    db $ed
    inc l
    add hl, hl
    ld l, b
    ld h, $4f
    cp h
    ld [c], a
    or e
    inc a
    db $dd
    ld a, a
    cp h
    or [hl]
    cp c
    jp $c0b7


    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    sub a
    ld [hl], a
    adc h
    adc c
    db $e3
    ld b, d
    ld h, $7f
    push de
    or e
    jp c, $c9b2

    ld c, a
    cp h
    ld [c], a
    or e
    ret nz

    or d
    db $dd
    ld a, a
    ret nc

    call nc, $df3c
    ret nz

    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    ld b, a
    ld [hl], a
    rst $20
    ld a, a
    push de
    or e
    jp c, Jump_016_7fb2

    ld d, h
    ret


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
    rst $20
    ld e, b
    ld hl, $cfcd
    ld a, [hl+]
    or [hl]
    ld hl, $7f0b
    jr z, jr_016_7f08

    xor a
    ldh [$96], a
    ld hl, $cfcd
    ld a, [hl+]
    ld [$cce3], a
    ldh [$97], a
    ld a, [hl]
    ld [$cce4], a
    ldh [$98], a
    ld a, $19
    ldh [$99], a
    call Call_000_38f5
    ld hl, $cfdb
    ld a, [hl+]
    ld b, [hl]
    srl a
    rr b
    srl a
    rr b
    ld a, b
    ld b, $04
    ldh [$99], a
    call Call_000_3902
    ldh a, [$98]
    ld hl, $7f0b
    cp $46
    jr nc, jr_016_7f08

    ld hl, $7f15
    cp $28
    jr nc, jr_016_7f08

    ld hl, $7f21
    cp $0a
    jr nc, jr_016_7f08

    ld hl, $7f2c

jr_016_7f08:
    jp Jump_000_3c79


    nop
    and a
    xor a
    add c
    ld a, a
    ld a, a
    ld d, b
    ld [$2e18], sp
    nop
    or d
    push de
    db $d3
    ret z

    ld a, a
    rst $08
    adc $50
    ld [$2218], sp
    nop
    and a
    xor a
    add c
    ld a, a

Call_016_7f26:
Jump_016_7f26:
    ld a, a
    ld d, b
    ld d, b
    ld [$1718], sp
    nop

Jump_016_7f2d:
    xor c
    call nc, $d387
    ld a, a
    pop bc

Jump_016_7f33:
    ld a, a
    jp $c1c8


    adc $c3
    push bc

Jump_016_7f3a:
    add c
    ld d, c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, b
    ld [$4721], sp

Jump_016_7f45:
    ld a, a
    ret


    ld bc, $cff0
    nop
    rst $20
    ld d, a
    ld hl, $7f53
    jp Jump_000_3c79


    ld bc, $cff0

Jump_016_7f56:
    nop
    ld d, c
    ld d, b
    ld [$c5d5], sp
    ld hl, $cfce
    ld de, $cce4
    ld b, [hl]
    dec hl
    ld a, [de]
    sub b
    ldh [$98], a
    dec de
    ld b, [hl]
    ld a, [de]
    sbc b
    ldh [$97], a
    ld a, $19
    ldh [$99], a

Call_016_7f72:
    call Call_000_38f5
    ld hl, $cfdb
    ld a, [hl+]
    ld b, [hl]
    srl a
    rr b
    srl a
    rr b
    ld a, b
    ld b, $04
    ldh [$99], a
    call Call_000_3902
    pop bc
    pop de
    ldh a, [$98]
    ld hl, $7fa3
    and a
    ret z

    ld hl, $7fc5
    cp $1e
    ret c

    ld hl, $7fad
    cp $46
    ret c

    ld hl, $7fb6
    ret


    nop
    and e
    pop bc
    adc $7f
    ld a, a
    ld d, b
    ld [$1418], sp
    nop
    and e
    pop bc
    adc $7f

Jump_016_7fb2:
    ld d, b
    ld [$0b18], sp
    nop
    and h

Jump_016_7fb8:
    rst $08
    or a

Call_016_7fba:
    push bc
    call z, Call_016_50cc
    ld [$0018], sp
    ld hl, $7fc5
    ret


Call_016_7fc5:
Jump_016_7fc5:
    db $ed

Jump_016_7fc6:
    dec l
    dec sp

Call_016_7fc8:
    ld l, b

Call_016_7fc9:
Jump_016_7fc9:
    jp c, Jump_016_57e7

    ld hl, $7fe4

Call_016_7fcf:
jr_016_7fcf:
    ld a, [hl+]

Call_016_7fd0:
    ldh [$db], a
    and a

Call_016_7fd3:
Jump_016_7fd3:
    ret z

    push hl
    ld b, a
    call Call_000_34dd

Jump_016_7fd9:
    pop hl

Call_016_7fda:
    jr z, jr_016_7fcf

    ld b, $05
    ld hl, $7fae
    jp Jump_000_3620


    inc a
    dec a
    ld a, $00
    nop

Jump_016_7fe9:
    nop
    nop
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    ld [bc], a
    nop
    nop
    ld [$0100], sp
    nop
    nop
    nop
    nop
    nop
    nop
