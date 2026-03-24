; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $015", ROMX[$4000], BANK[$15]

    inc b
    ld c, $05
    add hl, bc
    rrca
    ld bc, $0f02
    rrca
    inc c
    dec c
    rrca
    ld b, $0b
    rrca
    rlca
    dec a
    add hl, bc
    dec a
    dec a
    dec bc
    dec bc
    rlca
    ld b, $0b
    dec bc
    dec bc
    inc l
    dec bc
    dec de
    dec bc
    dec [hl]
    nop
    inc h
    ld a, [bc]
    sbc [hl]
    ld b, b
    ld d, d
    ld d, d
    ld c, a
    ld d, d
    inc c
    ld [bc], a
    inc d
    ld b, a
    add sp, -$3a
    db $10
    inc d
    inc hl
    ld a, [bc]
    cp l
    ret z

    ld bc, $43ee
    ld e, b
    ret


    db $10
    inc d
    nop
    ld a, [bc]
    inc bc
    rst $00
    ld b, d
    ld b, b
    rrca
    ld b, $09
    inc c
    nop
    ld l, $0b
    inc bc
    ld bc, $132f
    rrca
    nop
    jr nc, jr_015_4074

    db $10
    ld bc, $2731
    rrca
    ld [bc], a
    ld sp, $032b
    ld [bc], a
    ld [hl-], a
    ld [bc], a
    ld b, c
    dec b
    inc bc
    dec bc
    dec bc
    inc b
    ld [bc], a
    dec a
    ld a, [hl-]
    ld de, $ffff
    add c
    ld a, [bc]
    dec a
    ld sp, $ff11
    rst $38
    add d
    inc hl
    ccf
    rst $00

jr_015_4074:
    add hl, bc
    inc c
    ld c, d
    rst $00
    dec bc
    inc bc
    sub b
    rst $00
    inc de
    rrca
    ld de, $23c8
    db $10
    jr nc, @-$36

    daa
    rrca
    ld c, d
    ret z

    dec hl
    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    add hl, bc
    rlca
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    rrca
    rrca
    rrca
    rrca
    ld bc, $0f0f
    rrca
    rrca
    rrca
    dec bc
    dec bc
    dec bc
    dec bc
    ld bc, $311b
    ld sp, $3131
    dec bc
    dec bc
    dec bc
    dec bc
    ld bc, $311b
    ld sp, $3131
    dec bc
    dec bc
    dec bc
    dec bc
    ld bc, $3f3e
    ccf
    dec sp
    ld sp, $3131
    ld sp, $3131
    inc h
    ld b, $57
    dec h
    ld sp, $6d6c
    ld [hl-], a
    ld l, h
    ld l, h
    ld [$7431], sp
    ld [hl], h
    ld a, [bc]
    ld a, [bc]
    jr nz, jr_015_40fe

    ld a, [bc]
    ld a, [bc]
    ld sp, $3131
    ld sp, $5231
    ld a, h
    ld a, [hl]
    ld d, d
    ld d, d
    ld d, d
    ld d, d
    ld a, [bc]
    ld a, [bc]
    ld sp, $5555
    ld d, l
    ld d, l
    rrca
    rrca
    rrca
    ld a, [bc]
    ld a, [bc]
    ld sp, $1a1a
    ld a, [de]
    ld a, [de]
    rrca
    rrca

jr_015_40fe:
    rrca
    ld [bc], a
    inc bc
    ld sp, $010b
    dec bc
    dec bc
    rrca
    rrca
    rrca
    ld sp, $3131
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld [hl-], a
    ld l, h
    ld l, h
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
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
    rlca
    cpl
    rlca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rlca
    cpl
    rlca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld d, d
    ld a, [bc]
    ld d, d
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    jr nz, @+$0f

    ld hl, $6d6c
    ld [hl-], a
    ld l, h
    ld l, h
    rrca
    rrca
    ld a, h
    ld a, l
    ld a, [hl]
    ld a, [bc]
    jr nz, @+$23

    ld a, [bc]
    ld a, [bc]
    rrca
    rrca
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld d, d
    ld a, h
    ld a, [hl]
    ld d, d
    ld d, d
    rrca
    rrca
    cpl
    rlca
    rlca
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l

Call_015_417f:
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld bc, $0a6e
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld bc, $0b0b
    dec bc
    ld l, [hl]
    rlca
    cpl
    rlca
    rlca
    ld [hl], h
    ld bc, $0b0b
    dec bc
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld bc, $6f0a
    ld l, a
    ld l, a
    inc [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld bc, $0f6e
    rrca
    rrca
    ld l, l
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld bc, $6c0a
    ld l, h
    ld l, h
    ld l, l
    ld [hl], h
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld bc, $3131
    ld sp, $6d0a
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    rrca
    rlca
    rlca
    cpl
    ld a, [de]
    rlca
    inc [hl]
    cpl
    rlca
    rlca
    rrca
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld sp, $6d0a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    rrca
    ld sp, $3108
    ld sp, $6d0a
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    rrca
    ld bc, $7474
    ld sp, $6d0a
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    rrca
    ld bc, $0101
    ld bc, $346f
    ld l, a
    ld l, a
    ld l, a
    rrca
    rrca
    rrca
    dec de
    ld bc, $0f0f
    rrca
    rrca
    rrca
    nop
    add hl, bc
    inc hl
    ld [hl], l
    ld b, d
    sbc a
    ld d, d
    add [hl]
    ld d, d
    ld a, [bc]
    rrca
    ld a, [de]
    ld b, l
    inc b
    rst $00
    dec c
    dec l
    ld de, $b4ce
    ret z

    ld [bc], a
    dec bc
    ld b, [hl]
    add sp, -$3a
    rrca
    inc d
    ld [$1627], sp
    rst $00
    jr z, jr_015_426a

    inc l
    nop
    ld bc, $3b09
    ld a, [bc]
    add hl, bc
    inc c
    rrca
    dec a
    rst $38
    rst $38
    ld bc, $0a04
    ld c, $ff
    db $d3
    ld b, d
    jp z, Jump_000_0404

    ld [$ff12], sp
    ret nc

    ld b, e
    ret


    ld bc, $0d06
    inc d
    rst $38
    jp nc, $cb44

    ld bc, $0904
    rla
    rst $38
    ret nc

    ld b, l
    jp z, Jump_000_0605

    ld [$ff1b], sp
    jp nc, $cb46

    ld [bc], a
    inc b
    dec c
    ld a, [de]
    rst $38
    jp nc, $c947

    ld [bc], a
    inc b
    ld a, [bc]
    inc e
    rst $38
    db $d3

jr_015_426a:
    ld c, b
    jp z, $0606

    ld c, $25
    rst $38
    pop de
    ld c, c
    rlc e
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
    ld l, l
    ld bc, $0101
    jr z, jr_015_42c3

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
    ld d, a
    ld a, [hl+]
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
    ld a, [hl+]
    inc l
    add hl, hl
    ld a, [bc]
    ld bc, $0101
    jr z, jr_015_42e6

    inc l
    inc l
    inc l
    inc l
    inc l
    add hl, hl
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]

jr_015_42c3:
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    jr z, jr_015_42f7

    add hl, hl
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr z, @+$2e

    add hl, hl
    ld a, [bc]
    ld bc, $3f3e
    inc l
    inc l
    inc l
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    dec h
    cpl
    rlca
    rlca

jr_015_42e6:
    ld b, d
    rlca
    rlca
    ld b, d
    rlca
    cpl
    inc h
    ld d, a
    dec h
    rlca
    cpl
    ld a, $3f
    dec sp
    rlca
    rlca
    cpl

jr_015_42f7:
    jr z, @+$2e

    add hl, hl
    rlca
    cpl
    inc h
    ld d, a
    ld d, a
    ld a, [hl+]
    inc l
    ld bc, $400a
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr z, jr_015_4342

    add hl, hl
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    inc h
    ld d, a
    dec h
    ld a, [bc]
    ld d, [hl]
    dec bc
    dec bc
    dec bc
    jr z, jr_015_4350

    ld bc, $410a
    ld a, [bc]
    ld l, [hl]
    rlca
    rlca
    cpl
    ld b, d
    rlca
    rlca
    ld b, d
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    jr z, jr_015_4365

    add hl, hl
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    dec bc

jr_015_4342:
    dec bc
    dec bc
    dec bc
    jr z, jr_015_4373

    ccf
    ccf
    ccf
    ccf
    dec sp
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]

jr_015_4350:
    ld a, [bc]
    ld a, [bc]
    ld l, [hl]
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    jr z, jr_015_4388

    add hl, hl
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    dec bc

jr_015_4365:
    dec bc
    dec bc
    dec bc
    jr z, jr_015_4396

    inc l
    inc l
    inc l
    inc l
    add hl, hl
    ld a, $3f
    ccf
    ccf

jr_015_4373:
    ccf
    ccf
    ccf
    dec sp
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    jr z, jr_015_43ab

    add hl, hl
    ld a, $3f
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf

jr_015_4388:
    ccf
    ccf
    ccf
    inc l
    inc l
    ld d, a
    ld d, a
    ld d, a
    ld d, a

jr_015_4391:
    dec h
    jr z, jr_015_43c0

    inc l
    inc l

jr_015_4396:
    inc l
    inc l
    inc l
    add hl, hl
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    jr z, @+$2e

    add hl, hl
    jr z, @+$2e

    inc l
    inc l
    inc l
    inc l
    inc l
    inc l

jr_015_43ab:
    inc l
    inc l
    inc l
    inc l
    inc l
    nop
    add hl, bc
    dec l
    inc c
    ld b, h
    db $10
    ld d, [hl]
    rst $30
    ld d, l
    dec b
    ld c, $8b
    ld b, d
    ld c, h
    ret


    dec c

jr_015_43c0:
    inc hl
    nop
    ld [hl-], a
    ld [de], a
    rst $00
    inc bc
    ld b, h
    ld c, b
    jr jr_015_4391

    rrca
    inc d
    ld [$0300], sp
    rst $00
    jp nc, Jump_000_2c43

    inc bc
    dec b
    dec bc
    nop
    ld b, h

Call_015_43d8:
    dec b
    ld [de], a
    nop
    dec sp
    dec b
    jr @+$09

    inc a
    inc bc
    dec b
    inc c
    inc b
    rlca
    ld de, $0705
    dec de
    ld b, $03
    ld b, $0c
    dec c
    cp $00
    ld bc, $0706
    ld b, e
    rst $38
    db $d3
    ld b, d
    rlc h
    dec a
    rlca
    dec a
    rst $38
    rst $38
    add e
    call z, $c787
    dec b
    dec bc
    adc e
    rst $00
    dec b
    ld [de], a
    adc [hl]
    rst $00
    dec b
    jr jr_015_4439

    inc l
    inc l
    inc l
    dec hl
    ld d, a
    ld d, a
    ld a, [hl+]
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
    ld a, [hl+]
    inc l
    inc l
    inc l
    inc l

jr_015_4439:
    inc l
    dec hl
    ld d, a
    ld d, a
    dec h
    jr nz, @+$23

    inc h
    ld a, [hl+]
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
    add hl, hl
    ld a, [bc]
    ld e, b
    ld a, [bc]
    ld e, c
    ld e, c
    ld a, [bc]
    ld a, [bc]
    ld e, b
    ld a, [bc]
    ld e, b
    ld a, [bc]
    ld a, [bc]
    ld e, b
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld sp, $3131
    ld sp, $5724
    ld d, a
    ld d, a
    ld d, a
    inc l
    add hl, hl
    ld bc, $0101
    ld a, h
    ld [hl], d
    ld bc, $0624
    ld a, [hl+]
    dec hl
    ld b, $57
    ld d, a
    ld d, a
    ld d, a
    dec h
    ld a, [bc]
    ld e, d
    cpl
    ld e, e
    ld e, c
    ld a, [bc]
    ld a, [bc]
    ld e, b
    ld a, [bc]
    ld e, b
    ld a, [bc]
    ld a, [bc]
    ld e, d
    rlca
    rlca
    rlca
    rlca
    rlca
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    ld h, c
    inc l
    add hl, hl
    ld a, [de]
    ld a, [de]
    ld bc, $0101
    ld bc, $0108
    jr z, jr_015_44c8

    ld sp, $3108
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld e, c
    ld a, [bc]
    ld a, [bc]
    ld e, b
    ld a, [bc]
    ld e, d
    cpl
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld h, a
    rra
    rra
    rra
    rra
    inc l
    add hl, hl
    ld bc, $0101
    ld bc, $1a01

jr_015_44c8:
    ld a, [de]
    ld a, [de]
    jr z, @+$2b

    rlca
    rlca
    rlca
    rlca
    rlca
    cpl
    rlca
    rlca
    rlca
    rlca
    ld e, e
    ld a, [bc]
    ld a, [bc]
    ld e, d
    rlca
    rlca
    rlca
    rlca
    cpl

Call_015_44df:
    ld l, a
    rlca
    rlca
    rlca
    rlca
    ld a, [de]
    inc e
    ld a, [de]
    ld a, [de]
    inc d
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    inc l
    add hl, hl
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld bc, $0101
    ld bc, $2928
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
    ld l, l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld l, [hl]
    ld sp, $3131
    ld sp, $3131
    ld sp, $292c
    ld bc, $0101
    ld bc, $1a01
    ld a, [de]
    ld a, [de]
    jr z, jr_015_4552

    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    dec sp
    cpl
    rlca
    rlca
    rlca
    rlca
    cpl
    rlca
    rlca
    rlca
    rlca
    ld l, l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld l, [hl]
    cpl
    rlca
    ld h, d
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    inc l
    inc l
    dec sp
    ld a, [de]
    ld a, [de]
    ld bc, $0101
    ld bc, $2801

jr_015_4552:
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
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld l, l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    inc l
    inc l
    add hl, hl
    ld bc, $0101
    ld a, [de]
    ld a, $3f
    ccf
    inc l
    inc l
    inc l
    inc l
    inc l

jr_015_4583:
    inc l
    inc l
    inc l
    inc l
    inc l
    inc l
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
    ccf
    ccf
    ccf
    dec sp
    ld [hl], h
    ld [hl], h
    nop
    ld [de], a
    ld a, [bc]
    ld a, [c]
    ld b, l
    db $e4
    ld d, [hl]
    pop hl
    ld d, [hl]
    inc c
    inc bc
    ld e, [hl]
    ld c, c
    add sp, -$3a
    db $10
    inc d
    inc hl
    ld a, [bc]
    cp l
    ret z

    ld a, [bc]
    sbc d
    ld c, d
    jr c, jr_015_4583

    db $10
    inc d
    nop
    ld a, [bc]
    inc bc
    rst $00
    jp $0a45


    dec b
    dec e
    ld a, [bc]
    inc bc
    ld b, [hl]
    dec e
    add hl, bc
    ld [bc], a
    ld b, [hl]
    ld hl, $000a
    ld b, [hl]
    dec de
    ld de, $4700
    dec d
    ld a, [bc]
    nop
    ld c, b
    ld bc, $111d
    ld bc, $de00
    rst $00
    dec e
    ld a, [bc]
    db $dd
    rst $00
    dec e
    add hl, bc
    cp $c7
    ld hl, $d10a
    rst $00
    dec de
    ld de, $c79e
    dec d
    ld a, [bc]
    ld l, l
    daa
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld l, [hl]
    rlca
    rlca
    rlca
    rlca
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld l, [hl]
    dec bc
    dec bc
    dec bc
    dec bc
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld l, [hl]
    rlca
    rlca
    rlca
    rlca
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld l, [hl]
    dec bc
    dec bc
    dec bc
    dec bc
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld l, [hl]
    rlca
    rlca
    rlca
    rlca
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld l, [hl]
    dec bc
    dec bc
    dec bc
    dec bc
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld l, [hl]
    rlca
    rlca
    rlca
    rlca
    ld c, [hl]
    daa
    ld c, l
    ld l, l
    daa
    ld e, a
    ld sp, $3131
    ld sp, $271b
    ld c, l
    ld l, l
    daa
    ld e, a
    ld sp, $0e0c
    ld sp, $271b
    ld c, l
    ld l, l
    ld e, [hl]
    ld e, a
    ld sp, $1210
    ld sp, $5e1b
    ld c, l
    ld l, l
    ld bc, $1a5f
    ld a, [de]
    ld a, [de]
    ld a, [de]
    dec de
    ld bc, $6d4d
    ld bc, $0101
    ld bc, $0101
    ld bc, $2120
    ld l, l
    ld bc, $0101
    ld bc, $0101
    ld bc, $7e7c
    ld l, l
    ld bc, $0101
    dec de
    ld e, a
    ld bc, $0801
    ld c, l
    ld l, l
    ld bc, $2001
    dec c
    dec c
    ld hl, $0101
    ld c, l
    ld l, [hl]
    ld [hl], a
    ld [hl], a
    scf
    ld a, l
    ld a, [hl-]
    ld a, [hl]
    ld [hl], a
    ld [hl], a
    ld l, l
    ld l, [hl]
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld l, l
    nop
    add hl, bc
    ld e, $1e
    ld b, a
    ld e, $57
    dec b
    ld d, a
    inc bc
    inc bc
    ld d, l
    ld c, b
    add sp, -$3a
    rrca
    inc d
    ld [$1627], sp
    rst $00
    dec d
    ld [hl], d
    ld b, e
    ld [hl], l
    rst $00
    inc c
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $c8
    ld b, [hl]
    inc l
    nop
    ld bc, $1907
    dec bc
    ld a, [bc]
    ld b, $0e
    ld de, $d2ff
    ld b, c
    adc $05
    rlca
    dec bc
    inc e
    rst $38
    jp nc, $cd42

    rlca
    rlca
    dec bc
    inc hl
    rst $38
    db $d3
    ld b, e
    call Call_000_0608
    inc c
    inc [hl]
    rst $38
    db $d3
    ld b, h
    adc $06
    ld c, $13
    inc d
    rst $38
    jp nc, $d145

    dec bc
    ld c, $07
    cpl
    rst $38
    jp nc, $d146

    ld b, $04
    ld b, $1a
    rst $38
    ret nc

    ld b, a
    jp z, $0e0d

    inc de
    ld sp, $d3ff
    ld c, b
    pop de
    dec b
    inc b
    inc c
    inc l
    rst $38
    db $d3
    ld c, c
    jp z, Jump_000_3d0e

    inc de
    ld c, $ff
    rst $38
    adc d
    and $24
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
    ld a, [hl+]
    dec hl
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld d, a
    ld a, [hl+]
    inc l
    inc l
    dec hl
    ld [hl], h
    ld [hl], h
    ld c, l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, $3b
    dec bc
    dec bc
    jr z, jr_015_4778

    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    jr z, @+$2e

    inc l
    add hl, hl
    ld [hl], h
    ld [hl], h
    ld c, l
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld a, $3b
    rlca
    rlca
    cpl
    jr z, @+$2b

    cpl
    rlca
    inc h
    dec h
    cpl
    rlca
    rlca
    rlca
    ld a, $3b
    rlca
    jr z, jr_015_47a2

    inc l
    add hl, hl

jr_015_4778:
    ld d, d
    ld d, d
    ld c, a
    rlca
    rlca
    rlca
    rlca
    ld c, h
    jr z, @+$2b

    ld sp, $0831
    inc h
    dec h
    ld sp, $3131
    ld sp, $3131
    ld sp, $2431
    dec h
    ld sp, $5724
    ld d, a
    dec h
    ld a, [bc]
    ld a, [bc]
    dec [hl]
    ld sp, $3131
    ld sp, $2c3e
    add hl, hl
    ld a, [de]
    ld a, [de]

jr_015_47a2:
    ld a, [de]
    rlca
    cpl
    ld a, $3b
    ld sp, $3b3e
    ld sp, $3b3e
    ld sp, $3131
    ld sp, $3131
    ld sp, $5151
    ld h, e
    ld a, $3b
    ld a, [de]
    ld a, [de]
    inc h
    ld d, a
    dec h
    ld sp, $3131
    ld sp, $240a
    dec h
    rlca
    inc h
    dec h
    cpl
    jr z, @+$2b

    ld a, [de]
    ld a, $3b
    ld a, [de]
    ld a, $3f
    ccf
    ld [hl], h
    ld [hl], h
    ld c, l
    jr z, jr_015_4800

    rlca
    rlca
    rlca
    rlca
    cpl
    ld a, [de]
    ld a, [de]
    ld a, $3b
    cpl
    rlca
    rlca
    rlca
    rlca
    rlca
    rlca
    inc h
    dec h
    ld a, [de]
    inc h
    dec h
    ld a, [de]
    jr z, jr_015_481b

    inc l
    ld [hl], h
    ld [hl], h
    ld c, l
    jr z, jr_015_481e

    ld sp, $3131
    ld sp, $3131
    ld sp, $2928
    ld a, [bc]
    ld a, [bc]

jr_015_4800:
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
    jr z, jr_015_4839

    inc l
    ld [hl], h
    ld [hl], h
    ld c, l
    jr z, jr_015_483f

    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    ccf
    inc l

jr_015_481b:
    inc l
    ccf
    ccf

jr_015_481e:
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
    inc l
    nop
    add hl, bc
    ld e, $ab
    ld c, b
    xor e
    ld e, d
    sub d
    ld e, d
    ld a, [bc]
    rla
    ld a, [hl+]
    ld c, c

jr_015_4839:
    rst $38
    add $0a
    ld a, [bc]
    ld l, e
    ret c

jr_015_483f:
    ld c, c
    jp z, Jump_000_3919

    ld c, d
    ld d, h
    rst $00
    inc c
    ld a, [bc]
    nop
    inc de
    ld [bc], a
    rst $00
    ld c, [hl]
    ld c, b
    ld b, e
    nop
    inc bc
    dec c
    rrca
    dec bc
    dec b
    ld hl, $0b0c
    rra
    dec c
    ld a, [bc]
    rlca
    ld c, $35
    rst $38
    db $d3
    ld b, c
    rst $18
    ld bc, $0e06
    inc [hl]
    rst $38
    ret nc

    ld b, d
    adc $0c
    ld b, $0d
    rra
    rst $38
    ret nc

    ld b, e
    adc $0d
    ld b, $0e
    dec de
    rst $38
    jp nc, $ce44

    ld c, $06
    add hl, bc
    ld [hl], $ff
    ret nc

    ld b, l
    adc $0f
    rlca
    ld [$ff10], sp
    db $d3
    ld b, [hl]
    rst $18
    ld [bc], a
    rrca
    ld a, [bc]
    dec h
    rst $38
    ret nc

    ld b, a
    jp c, Jump_000_0f04

    ld a, [bc]
    inc h
    rst $38
    ret nc

    ld c, b
    jp c, Jump_000_1205

    dec bc
    ld c, $ff
    pop de
    ld c, c
    jp nc, Jump_000_0701

    ld de, $ff0b
    pop de
    ld c, d
    rst $18
    inc bc
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $3131
    ld sp, $1c31
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    rrca
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    rrca
    ld l, h
    ld l, h
    ld l, h
    ld l, h
    ld l, h
    ld l, h
    rrca
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld bc, $7731
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld sp, $771b
    ld [hl], a
    ld d, [hl]
    inc [hl]
    ld a, [bc]
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld l, [hl]
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld sp, $7777
    dec de
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld bc, $6d0f
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld l, [hl]
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld [hl], a
    ld [hl], a
    ld sp, $7777
    ld [hl], a
    dec de
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld sp, $771b
    ld bc, $0f0f
    ld l, a
    ld l, a
    ld l, a
    ld l, a
    ld l, a
    rrca
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld [hl], a
    ld [hl], a
    ld [hl], a
    dec de
    ld sp, $7777
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld sp, $771b
    ld [hl], a
    ld d, [hl]
    ld [hl], a
    ld sp, $5454
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    dec de
    ld [hl], a
    ld [hl], a
    ld sp, $7777
    ld [hl], a
    ld d, [hl]
    dec de
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld a, b
    ld b, e
    ld b, e

jr_015_497b:
    ld b, e
    add hl, de
    rrca
    rrca
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    ld d, c
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    rra
    ld l, d
    ld b, e

jr_015_4990:
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
    rrca
    rrca
    rra
    rra
    rra
    rra
    rra
    rra
    rra
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
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    dec d
    nop
    dec de
    ld a, [bc]
    ld [hl-], a
    ld c, d
    dec de
    ld e, a
    ld [bc], a
    ld e, a
    inc bc
    ld a, [de]
    inc bc
    ld c, d
    jr c, jr_015_4990

    add hl, bc
    ld e, $dc
    dec sp
    ld a, [hl+]
    rst $00
    jr jr_015_497b

    ld c, b
    dec h
    rst $00
    add hl, bc
    ld e, $00
    nop
    dec c
    rst $00
    db $db
    ld c, c
    ld b, e
    nop
    ld bc, $110d
    dec bc
    ld a, [bc]
    rlca
    ld [$ff08], sp
    ret nc

    ld b, c
    rst $18
    ld c, $07
    ld a, [bc]
    inc de
    rst $38
    ret nc

    ld b, d
    rst $18
    rrca
    rlca
    rrca
    db $10
    rst $38
    ret nc

    ld b, e
    rst $18
    db $10
    rlca
    inc de
    ld [de], a
    rst $38
    pop de
    ld b, h
    rst $18
    ld de, $2307
    inc de
    rst $38
    jp nc, $df45

    inc b
    rlca
    dec [hl]
    ld a, [bc]
    rst $38
    pop de
    ld b, [hl]
    rst $18
    dec b
    ld [de], a
    dec hl
    add hl, bc
    rst $38
    ret nc

    ld b, a
    jp nc, $120d

    ld [hl+], a
    ld [$d3ff], sp
    ld c, b
    jp nc, Jump_000_120e

    ld [hl+], a
    inc de
    rst $38
    jp nc, $d249

    rrca
    ld [de], a
    inc hl
    ld [$d3ff], sp
    ld c, d
    jp nc, $0a02

    ld c, l
    ld sp, $3131
    ld sp, $3131
    ld sp, $0a31
    ld c, l
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld a, [bc]
    ld c, l
    ld sp, $7777
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld a, [bc]
    ld c, l
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld sp, $7777
    ld a, [bc]
    ld c, l
    ld [hl], a
    ld sp, $7777
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld a, [bc]
    ld c, l
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld [hl], a
    ld sp, $7777
    ld [hl], a
    ld a, [bc]
    ld c, l
    ld sp, $3131
    ld a, [bc]
    ld d, l
    ld a, [bc]
    ld [$0a77], sp
    ld c, l
    ld sp, $3131
    ld a, [bc]
    ld d, l
    ld c, l
    rrca
    rrca
    ld a, [bc]
    ld c, l
    inc e
    inc e
    inc e
    ld a, [bc]
    ld d, l
    ld c, l
    rrca
    rrca
    ld a, [bc]
    ld c, l
    dec bc
    dec bc
    dec bc
    ld l, l
    ld d, l
    ld c, l
    rrca
    rrca
    ld a, [bc]
    ld c, l
    dec bc
    dec bc
    dec bc
    ld l, l
    ld d, l
    ld c, l
    rra
    rra
    ld a, [bc]
    ld c, l
    dec bc
    dec bc
    dec bc
    ld l, l
    ld d, l
    ld c, l
    ld b, e
    ld b, e
    ld a, [bc]
    ld c, l
    ld l, [hl]
    rlca
    rlca
    ld l, l
    ld d, l
    ld c, l
    ld b, e
    ld b, e
    ld a, [bc]
    ld c, l
    dec [hl]
    ld a, [bc]
    ld d, l
    ld l, l
    ld d, l
    ld c, l
    ld b, e
    ld b, e
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld a, [bc]
    ld d, l
    ld l, l
    ld d, l
    ld a, [bc]
    ld h, e
    ld b, e
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld a, [bc]
    ld d, l
    ld l, l
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld a, [bc]
    ld d, l
    dec [hl]
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld a, [bc]
    ld d, l
    ld l, l
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    inc de
    inc de
    ld a, [bc]
    ld a, [bc]
    ld d, l
    ld l, l
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    inc de
    inc de
    ld a, [bc]
    ld a, [bc]
    ld d, l
    ld l, l
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    ld d, l
    ld l, [hl]
    ld d, l
    ld d, l
    ld d, l
    ld a, [bc]
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    rlca
    dec [hl]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    ld a, [bc]
    ld c, l
    ld b, e
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld c, l
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
    ld b, e
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld b, e
    nop
    ld c, b
    ld a, [bc]
    ret z

    ld c, e
    ld l, d
    ld h, e
    ld d, c
    ld h, e
    inc c
    dec de
    jr jr_015_4b99

    db $eb
    add $0d
    inc d
    ld de, $d300
    rst $00
    dec e
    cp b
    ld c, h
    sbc e
    rrc l
    add hl, de
    nop
    nop
    ld [$62c7], sp
    ld c, e
    ld b, e
    nop
    ld b, $33
    add hl, bc
    dec bc
    ccf
    add hl, bc
    inc c
    ld c, e
    add hl, bc
    dec c
    ld d, a
    add hl, bc
    ld c, $6f
    add hl, bc
    rrca
    adc l
    add hl, bc
    db $10
    ld a, [bc]
    ld [de], a
    rla
    db $10
    rst $38
    jp nc, $d841

    inc b
    ld [de], a
    inc d
    rrca
    rst $38
    db $d3
    ld b, d
    ret c

    dec b
    ld [de], a
    ld d, $08
    rst $38
    pop de
    ld b, e
    jp nc, $1208

    inc h
    dec bc
    rst $38
    jp nc, $d244

    add hl, bc
    ld [de], a

jr_015_4b99:
    ld h, $12
    rst $38
    db $d3
    ld b, l
    jp nc, $120a

    ld a, $15
    rst $38
    jp nc, $d846

    ld b, $12
    ld c, b
    ld b, $ff
    db $d3
    ld b, a
    ret c

    rlca
    ld [de], a
    ld h, [hl]
    ld [de], a
    rst $38
    db $d3
    ld c, b
    ret c

    ld [$6612], sp
    add hl, bc
    rst $38
    jp nc, $d249

    dec bc
    ld [de], a
    ld a, d
    ld c, $ff
    ret nc

    ld c, d
    jp nc, $4e0c

    ld e, l
    ld [hl], h
    ld [hl], h
    ld e, l
    ld [hl], h
    ld c, [hl]
    ld h, l
    ld b, e
    ld b, e
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    ld c, [hl]
    ld h, l
    ld b, e
    ld b, e
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    ld d, c
    ld d, c
    ld d, c
    ld h, e
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    dec bc
    dec bc
    dec bc
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    dec e
    ld e, $5d
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld h, l
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld h, l
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld h, l
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    daa
    ld h, l
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld [hl], h
    ld e, [hl]
    ld h, l
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    dec e
    ld e, $31
    ld h, l
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld [$6465], sp
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld [$6465], sp
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld [$6465], sp
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld h, l
    ld h, h
    ld sp, $6465
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld sp, $6508
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    dec e
    rra
    ld l, $64
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld [hl], h
    ld h, l
    ld b, e
    ld b, e
    ld h, h
    daa
    ld [hl], h
    ld c, l
    ld c, [hl]
    daa
    ld sp, $0831
    ld sp, $2731
    ld sp, $4e4d
    daa
    ld sp, $1f1d
    rra
    ld e, $27
    ld sp, $4e4d
    daa
    ld sp, $4365
    ld b, e
    ld h, h
    daa
    ld sp, $4e4d
    daa
    ld sp, $4365
    ld b, e
    ld h, h
    daa
    ld sp, $4e4d
    daa
    ld sp, $3131
    ld sp, $2731
    ld sp, $4e4d
    ld e, [hl]
    ld sp, $3131
    ld sp, $5e31
    ld sp, $4e4d
    ld [hl], a
    ld [hl], a
    ld sp, $7777
    ld sp, $7777
    ld c, l
    ld h, a
    rra
    ld e, $5d
    ld sp, $5d31
    dec e
    rra
    ld l, d
    jr jr_015_4e83

    ld h, h
    daa
    ld sp, $2731
    ld h, l
    ld b, e
    add hl, de
    jr jr_015_4e8d

    ld h, h
    daa
    ld sp, $2731
    ld h, l
    ld b, e
    add hl, de
    jr jr_015_4e97

    ld h, h
    daa
    ld sp, $2731
    ld h, l
    ld b, e
    add hl, de
    jr jr_015_4ea1

    ld h, h
    daa
    ld sp, $2731
    ld h, l
    ld b, e
    add hl, de
    jr jr_015_4eab

    ld h, h
    daa
    ld sp, $2731
    ld h, l
    ld b, e
    add hl, de
    jr @+$45

    ld h, h
    daa
    ld sp, $2731
    ld h, l
    ld b, e
    add hl, de

jr_015_4e7a:
    jr jr_015_4ebf

    ld h, h
    daa
    ld sp, $2731
    ld h, l
    ld b, e

jr_015_4e83:
    add hl, de
    jr jr_015_4ec9

    ld h, h
    ld e, [hl]
    ld [$5e31], sp
    ld h, l
    ld b, e

jr_015_4e8d:
    add hl, de
    jr jr_015_4ed3

    ld h, h
    ld a, [de]
    ld a, [de]
    ld e, h
    ld a, [de]
    ld h, l
    ld b, e

jr_015_4e97:
    add hl, de
    nop
    dec de
    ld a, [bc]
    ld de, $cb4f
    ld h, a
    or d
    ld h, a

jr_015_4ea1:
    ld a, [bc]
    rlca
    or h
    ld c, l
    add sp, -$3a
    db $10
    inc d
    inc hl
    ld a, [bc]

jr_015_4eab:
    cp l
    ret z

    rra
    xor h
    ld b, c
    jr c, jr_015_4e7a

    add hl, bc
    ld [hl-], a
    call c, Call_015_5263
    rst $00
    cp d
    ld c, [hl]
    ld b, e
    nop
    ld bc, $0b09

jr_015_4ebf:
    dec bc
    ld a, [bc]
    rlca
    dec bc
    inc c
    rst $38
    jp nc, $d741

    ld [bc], a

jr_015_4ec9:
    rlca
    dec bc
    ld de, $d2ff
    ld b, d
    rst $10
    inc bc
    ld [hl+], a
    dec e

jr_015_4ed3:
    ld de, $d2ff
    ld b, e
    rst $10
    inc b
    ld [hl+], a
    rra
    ld [$d3ff], sp
    ld b, h
    rst $10
    dec b
    ld [hl+], a
    inc hl
    inc d
    rst $38
    pop de
    ld b, l
    rst $10
    ld b, $22
    rrca
    dec c
    rst $38
    ret nc

    ld b, [hl]
    rst $10
    rlca
    ld [hl+], a
    cpl
    inc c
    rst $38
    jp nc, $da47

    inc c
    ld [hl+], a
    cpl
    rrca
    rst $38
    db $d3
    ld c, b
    jp c, $220d

    ld l, $0d
    rst $38
    pop de
    ld c, c
    rst $10
    ld [$3022], sp
    ld c, $ff
    ret nc

    ld c, d
    jp c, Jump_000_280e

    inc l
    add hl, hl
    ld a, [de]
    ld a, [de]
    ld a, [de]
    dec de
    jr z, jr_015_4f46

    add hl, hl
    jr z, jr_015_4f49

    add hl, hl
    ld a, [de]
    ld a, [de]
    ld a, [de]
    dec de
    inc h
    ld d, a
    dec h
    inc h

Call_015_4f26:
    ld d, a
    dec h
    ld a, [de]
    ld a, [de]
    ld a, [de]

Call_015_4f2b:
    dec de
    jr jr_015_4f71

    ld b, e
    ld b, e
    add hl, de
    ld sp, $3131
    ld sp, $1831
    ld b, e
    ld b, e
    ld l, e
    dec d
    ld sp, $3131
    ld [$1431], sp
    ld l, e
    ld l, e
    jr jr_015_4f88

    ld b, e

jr_015_4f46:
    ld b, e
    ld b, e
    ld b, e

jr_015_4f49:
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_4f92

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

Jump_015_4f56:
    add hl, de
    jr jr_015_4f9c

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_4fa6

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_4fb0

    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4f71:
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_4fba

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_4fc4

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4f88:
    add hl, de
    jr jr_015_4fce

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4f92:
    add hl, de
    jr jr_015_4fd8

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4f9c:
    add hl, de
    jr jr_015_4fe2

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fa6:
    add hl, de
    jr jr_015_4fec

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fb0:
    add hl, de
    jr jr_015_4ff6

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fba:
    add hl, de
    jr jr_015_5000

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fc4:
    add hl, de
    jr jr_015_500a

    ld b, e
    ld b, e
    ld b, e

Call_015_4fca:
Jump_015_4fca:
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fce:
    add hl, de

Call_015_4fcf:
    inc de
    ld b, e
    ld b, e
    ld b, e

Jump_015_4fd3:
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fd8:
    add hl, de
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fe2:
    add hl, de
    ld b, e
    ld b, e
    ld b, e
    ld b, e

Call_015_4fe7:
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4fec:
    add hl, de
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_4ff6:
    add hl, de
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5000:
    add hl, de
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_500a:
    add hl, de
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
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    inc de
    nop
    dec l
    ld a, [bc]
    adc l
    ld d, b
    ld a, l
    ld l, e
    ld h, h
    ld l, e
    inc c
    nop
    add hl, sp
    ld b, e
    db $eb
    add $0a
    ld a, [bc]
    ld de, $7900
    rst $00
    ld [$40d7], sp
    db $eb
    ret


    ld a, [bc]
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $41
    ld d, b
    ld b, e
    nop
    nop
    add hl, bc
    cpl
    inc e
    ld [$d2ff], sp
    ld b, c
    sub $07
    cpl
    dec e

Call_015_504f:
    ld a, [bc]
    rst $38
    ret nc

    ld b, d
    sub $09
    ld [hl+], a
    inc hl
    ld c, $ff
    pop de
    ld b, e
    rst $10
    inc c
    ld [hl+], a
    ld [hl+], a
    db $10
    rst $38
    db $d3
    ld b, h
    ret c

    add hl, bc
    ld [hl+], a
    ld b, e
    inc d
    rst $38
    ret nc

    ld b, l
    rst $10
    dec c
    ld [hl+], a
    ld c, e
    add hl, bc
    rst $38
    db $d3
    ld b, [hl]
    rst $10
    ld c, $22
    ld c, e
    inc de
    rst $38
    jp nc, $d747

    rrca
    cpl
    inc a
    ld [de], a
    rst $38
    jp nc, $d648

    ld [$3d2f], sp
    dec d
    rst $38
    db $d3
    ld c, c
    sub $0a
    ld d, c
    ld h, e
    ld h, l
    ld h, h
    ld d, c
    ld d, c
    ld d, c
    ld h, d
    ld d, c
    ld d, c
    ld a, [bc]
    ld c, l
    ld h, l
    ld h, h
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld c, l
    ld h, l
    ld h, h
    dec bc
    dec bc
    dec bc
    ld c, [hl]
    ld [hl], h
    ld a, [bc]
    ld [hl], h
    ld c, l
    ld h, l
    ld h, h
    dec bc
    dec bc
    dec bc
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld c, l
    ld h, l
    ld h, h
    dec bc
    dec bc
    dec bc
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld c, l
    ld h, l
    dec l
    rra
    rra
    rra

Jump_015_50c6:
    ld h, a
    rra
    rra
    ld d, d
    ld c, a
    ld h, l
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    jr jr_015_5115

    ld b, e
    ld h, a
    rra
    ld l, $43
    ld b, e
    ld b, e
    ld b, e
    inc d
    ld l, e
    ld l, e
    jr jr_015_5122

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_512c

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_5136

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_5140

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_514a

    ld d, h
    ld d, h
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_5154

    ld a, b
    ld a, b
    ld b, e
    ld b, e

jr_015_5115:
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    jr jr_015_515e

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5122:
    add hl, de
    jr jr_015_5168

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_512c:
    add hl, de
    jr jr_015_5172

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5136:
    add hl, de
    jr jr_015_517c

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5140:
    add hl, de
    jr jr_015_5186

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_514a:
    add hl, de
    jr jr_015_5190

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5154:
    add hl, de
    jr jr_015_519a

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_515e:
    add hl, de
    jr jr_015_51a4

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5168:
    add hl, de
    jr jr_015_51ae

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5172:
    add hl, de
    jr jr_015_51b8

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_517c:
    add hl, de
    jr jr_015_51c2

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5186:
    add hl, de
    jr jr_015_51cc

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5190:
    add hl, de
    jr jr_015_51d6

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_519a:
    add hl, de
    jr jr_015_51e0

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51a4:
    add hl, de
    jr jr_015_51ea

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld d, h

jr_015_51ae:
    add hl, de
    jr jr_015_51f4

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld a, b
    ld a, b

jr_015_51b8:
    add hl, de
    jr jr_015_51fe

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51c2:
    add hl, de
    jr jr_015_5208

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51cc:
    add hl, de
    jr jr_015_5212

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51d6:
    add hl, de
    jr jr_015_521c

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51e0:
    add hl, de
    jr jr_015_5226

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51ea:
    add hl, de
    jr jr_015_5230

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51f4:
    add hl, de
    jr jr_015_523a

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_51fe:
    add hl, de
    jr jr_015_5244

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5208:
    add hl, de
    jr jr_015_524e

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5212:
    add hl, de
    jr jr_015_5258

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_521c:
    add hl, de
    jr @+$45

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5226:
    add hl, de
    jr jr_015_526c

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e

jr_015_5230:
    add hl, de
    jr jr_015_5276

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld l, e

jr_015_523a:
    dec d
    jr jr_015_5280

    ld b, e
    ld b, e
    ld b, e
    ld b, e
    ld b, e
    add hl, de
    ld b, e

jr_015_5244:
    ld b, e
    jr @+$45

    ld b, e
    ld b, e
    ld b, e
    ld d, h
    ld b, e
    add hl, de
    ld b, e

jr_015_524e:
    ld b, e
    jp Jump_000_3c6c


    push bc
    rrca
    push bc
    rrca
    ld e, d
    ld d, d

jr_015_5258:
    ld a, b
    ld d, d
    db $ed
    dec l
    ret nz

    ld b, l
    ld a, a
    ld hl, sp+$3a
    sbc $7f

Call_015_5263:
    inc [hl]
    or e
    db $db
    ld c, a
    sub e
    add [hl]
    xor c
    ld a, a
    adc e

jr_015_526c:
    sub d
    or b
    ld a, a
    ld d, [hl]
    ld a, a
    sub l
    ld a, [de]
    ld a, a
    adc e
    sub d

jr_015_5276:
    or b
    ld d, a
    db $ed
    dec l
    db $ed
    ld b, l
    ld a, a
    ld [de], a
    or b
    rlca

jr_015_5280:
    rrca
    ret


    ld a, a
    or c
    push bc
    ld d, a
    call Call_000_3c6c
    ld hl, $52b3
    ld de, $5299
    ld a, [$d577]
    call Call_000_31a8
    ld [$d577], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    inc d
    ld d, e
    ld c, a
    ld d, e
    sbc [hl]
    ld d, e
    rst $38
    ld d, e
    ld b, l
    ld d, h
    xor d
    ld d, h
    ld bc, $5255
    ld d, l
    sbc b
    ld d, l
    call c, Call_000_0255
    jr nz, @+$44

    rst $10
    ld e, c
    ld d, e
    ld a, l
    ld d, e
    ld [hl], c
    ld d, e
    ld [hl], c
    ld d, e
    inc bc
    jr nc, jr_015_5304

    rst $10
    xor b
    ld d, e
    call nc, $c753
    ld d, e
    rst $00
    ld d, e
    inc b
    jr nz, jr_015_5310

    rst $10
    add hl, bc
    ld d, h
    dec hl
    ld d, h
    inc h
    ld d, h
    inc h
    ld d, h
    dec b
    db $10
    ld b, d
    rst $10
    ld c, a
    ld d, h
    ld [hl], a
    ld d, h
    ld h, c
    ld d, h
    ld h, c
    ld d, h
    ld b, $40
    ld b, d
    rst $10
    or h
    ld d, h
    rst $18
    ld d, h
    call z, $cc54
    ld d, h
    rlca
    jr nc, jr_015_5334

    rst $10
    dec bc
    ld d, l
    ld l, $55
    ld h, $55
    ld h, $55
    ld [$4230], sp
    rst $10
    ld e, h
    ld d, l
    ld a, [hl]
    ld d, l
    ld [hl], a

jr_015_5304:
    ld d, l
    ld [hl], a
    ld d, l
    add hl, bc
    jr nz, @+$44

    rst $10
    and d
    ld d, l
    jp nz, $b955

jr_015_5310:
    ld d, l
    cp c
    ld d, l
    rst $38
    db $ed
    ld [hl+], a
    xor h
    ld h, l
    ld c, a
    cp d
    ret


    ld a, a
    call Call_000_33de
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    set 0, h
    call nc, $d0bd
    ld a, a
    cp h
    jp $b27f


    cp d
    or e
    ld d, c
    sbc c
    sub h
    rrca
    ld a, a

jr_015_5334:
    adc e
    sub d
    or b
    or [hl]
    rst $10
    ld c, a
    inc [hl]
    or e
    cp b
    jp nz, $7fdd

    rst $00
    cp c
    jp $b77f


    ret nz

    rst $10
    ld d, l
    ld d, [hl]
    ld a, a
    jp nz, $dab6

    ret nz

    ld d, a
    ld [$b321], sp
    ld d, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld h, e
    ld h, [hl]
    rst $08
    or h
    jp z, $934f

    add [hl]
    xor c
    ret


    ld a, a
    db $d3
    ret c

    inc sp
    db $d3
    ld a, a
    or c
    rst $18
    ret nz

    push bc
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    rst $38
    ld h, [hl]
    or d
    cp c
    inc [hl]
    ld a, a
    rst $08
    cp c
    ret nz

    ld e, b
    db $ed
    ld [hl+], a
    sbc l
    ld h, [hl]
    or c
    ret nz

    ret c

    jp z, $d34f

    ret c

    ld a, a
    call nz, $7fca
    rst $08
    ret nz

    ld a, a
    pop bc
    ld h, $df
    ret nz

    ld d, l
    ld d, h
    ld h, $7f
    call nz, $d9da
    sbc $30
    rst $20
    ld d, a
    ld [$bf21], sp
    ld d, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    dec hl
    ld h, a
    xor e
    ld c, a
    or e
    ld a, [hl+]
    or a
    ld a, a
    call nc, $b8bd
    rst $18
    jp $b27f


    or d
    ld l, $e7
    ld d, l
    or l
    rst $08
    or h
    db $d3
    ld a, a
    jp z, Jump_000_3ab9

    and $57
    db $ed
    ld [hl+], a
    ld [c], a
    ld h, a
    call nz, $b57f
    db $d3
    rst $18
    ret nz

    ret


    add $58
    db $ed
    ld [hl+], a
    ld l, e
    ld h, a
    or e
    cp h
    sbc $7f
    call nc, $c3df
    reti


    and $4f
    rst $30
    jp nz, Jump_015_7fc9

    inc e
    xor h
    add a
    adc h
    add $7f
    ld d, h
    db $dd
    ld d, l
    ld sp, hl
    or $45
    or a
    ld a, a
    rst $08
    inc sp
    ld a, a
    or c
    dec l
    cp c
    rst $10
    jp c, $d6d9

    ld d, a
    ld [$cb21], sp
    ld d, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld a, [de]
    ld l, b
    call nz, $b77f
    ret nc

    rst $20
    ld c, a
    or d
    rst $08
    ld a, a
    call c, $bcc0
    ret


    ld a, a
    adc $b3
    ld a, a
    ret nc

    ret nz

    inc sp

Call_015_5421:
    cp h
    ld [c], a
    ld d, a
    db $ed
    ld [hl+], a
    dec d
    ld l, c
    or d
    call nc, $ed58
    ld [hl+], a
    adc e
    ld l, b
    db $db
    ld a, a
    ret nc

    reti


    or [hl]
    rst $10
    ld c, a
    ret nz

    ret nz

    or [hl]
    or e
    ld a, a
    cp d
    call nz, $7fc6
    push bc
    reti


    ret


    sub $e7
    ld d, a
    ld [$d721], sp
    ld d, d
    call Call_000_3214
    jp Jump_000_0f6a


Call_015_544f:
    db $ed
    ld [hl+], a
    ld l, $69
    ld d, h
    ld a, a
    ld e, l
    and $4f
    inc l
    ldh [$7f], a
    cp e
    rst $18
    cp a
    cp b
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    and l
    ld l, c
    cp h
    or d
    ld a, a
    ld d, h
    ld c, a
    db $d3
    rst $18
    jp $b87f


    jp c, $7f3a

    or [hl]
    jp $d6c0


    ld e, b
    db $ed
    ld [hl+], a
    ld c, e
    ld l, c
    ld d, h
    ld a, a
    or c
    dec l

Call_015_547f:
Jump_015_547f:
    cp c
    reti


    ld c, a
    inc e
    xor h
    add a
    adc h
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    add $7f
    push bc
    rst $18
    ret nz

    rst $10
    ld d, l
    adc $b6
    ret


    ld a, a
    inc e
    xor h
    add a
    adc h
    add $55
    or a
    ret c

    or [hl]
    or h
    jp c, $7f3a

    or d
    or d
    sbc $30
    sub $57
    ld [$e321], sp
    ld d, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    call z, Call_015_7f69
    cp h
    cp [hl]
    sbc $e7
    ld c, a
    ld d, [hl]
    ld a, a
    push bc
    db $e3
    sbc $b6
    ld a, a
    or a
    add $7f
    push bc
    reti


    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld a, e
    ld l, d
    ret


    cp d
    add $4f
    call nc, $bcbb
    cp b
    ld a, a
    inc sp
    or a
    push bc
    or d
    and $58
    db $ed
    ld [hl+], a
    rst $38
    ld l, c
    ret nz

    ret nz

    or [hl]
    or d
    ret nz

    cp b
    ld a, a
    push bc
    or [hl]
    rst $18
    ret nz

    rst $10
    ld c, a
    cp h
    cp [hl]
    sbc $dd
    ld a, a
    or c
    call c, $c5be
    cp c
    jp c, $7f3a

    or d
    or d
    ret


    ld d, a
    ld [$ef21], sp
    ld d, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    xor b
    ld l, d
    sub $e7
    ld a, a
    or l
    rst $08
    or h
    jp z, $c04f

    sbc $40
    xor e
    ld a, a
    jp z, $c3b2

    ld a, a
    push bc
    or d
    inc l
    ldh [$de], a
    ld d, a
    db $ed
    ld [hl+], a
    ld d, b
    ld l, e
    rst $08
    cp c
    ret nz

    ld e, b
    db $ed
    ld [hl+], a
    ld [$7f6a], a
    call z, $d3d5
    ld c, a
    ret nz

    sbc $40
    xor e
    ld a, a

Call_015_553c:
    cp h
    or [hl]
    ld a, a
    jp z, $c5b6

    or d
    rst $20
    ld d, l
    cp a
    jp c, Jump_015_7f26

    or l
    jp c, Jump_015_7fc9

    ld b, e
    ret c

    adc e
    db $e3
    ld d, a
    ld [$fb21], sp
    ld d, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld l, b
    ld l, e
    ld a, a
    or a
    ret nz

    ld a, a
    ld a, [hl-]
    or [hl]
    ret c

    ret


    ld a, a
    ld d, h
    ld c, a
    ret nz

    ret nz

    or [hl]
    call c, $d6be
    or e
    ld a, a
    or [hl]
    push bc
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    db $e4
    ld l, e
    cp c
    jr nc, @+$5a

    db $ed
    ld [hl+], a
    sub h
    ld l, e
    ret c

    ld d, [hl]
    ld a, a
    cp a
    jr nc, @-$3b

    ret nz

    ld c, a
    ld d, h
    ret


    ld a, a
    adc $b3
    ld h, $7f
    jp nz, $b2d6

    sbc $30
    push bc
    ld d, a
    ld [$0721], sp
    ld d, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld [bc], a
    ld l, h
    ldh [$e7], a
    ld c, a
    or d
    rst $08
    ld a, a
    or [hl]
    rst $10
    jr nc, jr_015_562f

    cp e
    call c, $c5d7
    or [hl]
    rst $18
    ret nz

    and $57
    db $ed
    ld [hl+], a
    ld a, e
    ld l, h
    or l
    call c, $e6d8
    ld e, b
    db $ed
    ld [hl+], a
    ld hl, $9e6c
    call nc, $c9cf

Call_015_55ca:
    ld a, a
    call z, $c4d3
    ld a, a
    or [hl]
    rst $10
    jp z, $fa4f

    ld a, [hl-]
    sbc $7f
    inc [hl]
    or e

Jump_015_55d9:
    db $db
    sub $57
    db $ed
    ld [hl+], a
    ld [hl+], a
    ld h, [hl]
    ld a, a
    ld sp, hl
    ld a, [hl-]
    sbc $7f
    inc [hl]
    or e
    db $db
    ld c, a
    ld d, [hl]
    ld a, a
    cp d
    ret


    cp e
    or a
    ld a, a
    add h
    sub c
    add [hl]
    sbc [hl]
    call nc, Call_015_57cf
    call Call_000_3c6c
    ld hl, $561c
    ld de, $560a
    ld a, [$d578]
    call Call_000_31a8
    ld [$d578], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    add hl, hl
    ld d, [hl]
    ld c, c
    ld d, [hl]
    push bc
    rrca
    xor a
    rrca
    xor e
    ld d, [hl]
    jp $0256


    jr nc, jr_015_5663

    rst $10
    ld d, e
    ld d, [hl]
    ld a, l

jr_015_5623:
    ld d, [hl]
    ld [hl], b
    ld d, [hl]
    ld [hl], b
    ld d, [hl]
    rst $38
    db $ed
    ld [hl+], a
    adc a
    ld l, h
    rst $20
    ld c, a

jr_015_562f:
    jp nz, $32cf

    or d
    jp $ba7f


    db $db
    sbc $2c
    ldh [$df], a
    ret nz

    ld d, l
    ld d, h
    ret


    ld a, a
    add c
    adc e
    sub c
    dec de
    sub d
    jr nc, jr_015_5623

    rst $20
    ld d, a
    ld [$1c21], sp
    ld d, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld h, [hl]
    ld l, l
    ld a, a
    add h
    sub c
    add [hl]
    sbc [hl]
    call nc, $c6cf
    ld c, a

Call_015_5660:
    add [hl]
    sbc b
    adc c

jr_015_5663:
    ret


    ld a, a
    ld d, h
    ld a, a
    call nz, $c6d8
    ld a, a
    or a
    ret nz

    ret


    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld a, [hl+]
    ld l, [hl]
    cp b
    ld a, a

jr_015_5676:
    call nz, $c0df
    ret


    add $e7
    ld e, b
    db $ed
    ld [hl+], a
    xor l
    ld l, l
    ret nz

    ret c

jr_015_5683:
    jp z, $d34f

    or e
    ld a, a
    add [hl]
    sbc b
    adc c
    ld a, a
    ret nc

    jp nz, $deb6

    push bc
    or d
    or [hl]
    db $d3
    ld d, c
    jr nc, jr_015_5676

    jp $b17f


    ret nz

    cp h
    ld h, $4f
    ld l, $de
    inc a
    ld a, a
    call nz, $c1df
    ldh [$df], a
    ret nz

    db $d3
    sbc $57
    db $ed
    ld [hl+], a
    ldh [$6c], a
    ld a, a
    add h
    sub c
    add [hl]
    sbc [hl]
    call nc, Call_015_4fcf
    ld d, [hl]
    ld a, a
    inc [hl]
    or e
    cp b
    jp nz, $b27f

    ret c

Jump_015_56c0:
    jr z, jr_015_5683

    ld d, a

Jump_015_56c3:
    db $ed
    ld [hl+], a
    ld [hl+], a
    ld l, l
    ld a, a
    ld a, [$de3a]
    ld a, a
    inc [hl]
    or e
    db $db
    ld c, a
    add h
    sub c
    add [hl]

Jump_015_56d3:
    sbc [hl]
    call nc, Call_015_7fcf
    ld d, [hl]
    ld a, a
    sbc c
    sub h
    rrca
    ld a, a
    adc e
    sub d
    or b
    ld d, a
    jp Jump_000_3c6c


    and $56
    db $ed
    ld [hl+], a
    ld e, d
    ld l, [hl]
    rst $10
    ld a, a
    pop bc
    or [hl]
    ld a, a
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
    ld hl, $5734
    ld de, $5718
    ld a, [$d583]
    call Call_000_31a8
    ld [$d583], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    and c
    ld d, a
    and a
    ld d, a
    xor l
    ld d, a
    or e
    ld d, a
    cp c
    ld d, a
    cp a
    ld d, a
    push bc
    ld d, a
    bit 2, a
    pop de
    ld d, a
    push bc
    rrca
    ld [hl], l
    ld e, d
    ld bc, $4e30
    rst $10
    db $db
    ld d, a
    db $fc
    ld d, a
    pop af
    ld d, a
    pop af
    ld d, a
    ld [bc], a
    jr nz, @+$50

    rst $10
    daa
    ld e, b
    ld d, b
    ld e, b
    ld c, c
    ld e, b
    ld c, c
    ld e, b
    inc bc
    ld b, b
    ld c, [hl]
    rst $10
    ld e, a
    ld e, b
    sub b
    ld e, b
    add [hl]
    ld e, b
    add [hl]
    ld e, b
    inc b
    jr nz, @+$50

    rst $10
    xor c
    ld e, b
    call $c158
    ld e, b
    pop bc
    ld e, b
    dec b
    jr nz, @+$50

    rst $10
    db $eb
    ld e, b
    ld hl, $0759
    ld e, c
    rlca
    ld e, c
    ld b, $30
    ld c, [hl]
    rst $10
    ld b, b
    ld e, c
    ld l, e
    ld e, c
    ld h, e
    ld e, c
    ld h, e
    ld e, c
    rlca
    ld b, b
    ld c, [hl]
    rst $10
    add b
    ld e, c
    jp $a559


    ld e, c
    and l
    ld e, c
    ld [$4e20], sp
    rst $10
    db $e4
    ld e, c
    rrca
    ld e, d
    ld hl, sp+$59
    ld hl, sp+$59
    add hl, bc
    jr nz, @+$50

    rst $10
    add hl, sp
    ld e, d
    ld e, h
    ld e, d
    ld d, d
    ld e, d
    ld d, d
    ld e, d
    rst $38
    ld [$3421], sp
    ld d, a
    jr jr_015_57d5

    ld [$4021], sp
    ld d, a
    jr jr_015_57d5

    ld [$4c21], sp
    ld d, a
    jr jr_015_57d5

    ld [$5821], sp
    ld d, a
    jr jr_015_57d5

    ld [$6421], sp
    ld d, a
    jr jr_015_57d5

    ld [$7021], sp
    ld d, a
    jr jr_015_57d5

    ld [$7c21], sp
    ld d, a
    jr jr_015_57d5

jr_015_57cb:
    ld [$8821], sp
    ld d, a

Call_015_57cf:
    jr jr_015_57d5

    ld [$9421], sp
    ld d, a

jr_015_57d5:
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld [hl+], a
    ld [hl], a
    ld a, d
    ld d, h
    ld a, a
    db $d3
    rst $18
    jp $dcd9


Jump_015_57e6:
    ret z

Call_015_57e7:
    ld c, a
    ld d, [hl]
    ld a, a
    add l
    and c
    ld a, a
    jr nc, jr_015_57cb

    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    rrca
    ld a, e
    ld a, a
    jp nz, $b2d6

    call c, Call_015_58c8
    db $ed
    ld [hl+], a
    sbc [hl]
    ld a, d
    cp e
    or a
    ret


    ld a, a
    sub e
    xor e
    sub a
    and [hl]
    ld c, a
    push bc
    or [hl]
    jp z, $cf7f

    rst $18
    cp b
    rst $10
    ld a, a
    jr nc, @-$48

    rst $10
    ld d, l
    or c
    or [hl]
    ret c

    ld h, $7f
    push bc
    or d
    call nz, $bd7f
    cp l
    jp nc, $c57f

    or d
    call c, $ed57
    ld [hl+], a
    add hl, hl
    ld a, e
    and $4f
    sub $bb
    add hl, hl
    push bc
    ld a, a
    ld d, h
    ld a, a
    db $d3
    rst $18
    jp $cc55


    rst $10
    call z, $7fd7
    or c
    reti


    or d
    call nz, $7fd9
    or l
    rst $08
    or h
    jp z, Jump_015_57e6

    db $ed
    ld [hl+], a
    xor c
    ld a, e
    rst $18
    ret nz

    ld e, b
    db $ed
    ld [hl+], a
    ld a, b
    ld a, e

jr_015_5854:
    cp b
    jp $c57f


    ret nc

    jr nc, @-$2b

    ld a, a
    inc sp
    sbc $57

jr_015_585f:
    db $ed
    ld [hl+], a
    or c
    ld a, e
    sbc l
    ld a, a
    sub e
    xor e
    sub a

jr_015_5868:
    and [hl]
    ld a, a
    rst $00
    cp c
    jp $8b4f


    add h
    xor e
    ld a, a
    adc a
    add d
    xor e
    add $55
    or d
    cp b
    ld a, a
    call nz, $dbba
    ld a, a
    push bc
    sbc $30
    ld a, a
    cp c
    inc [hl]
    ld d, [hl]
    ld d, a
    db $ed
    inc hl
    ld c, [hl]
    ld b, b
    ld a, a
    jr nc, jr_015_585f

    jr nc, jr_015_5854

    ld e, b
    db $ed
    inc hl
    nop
    ld b, b
    or d
    ld a, a
    or a
    ret nc

    db $d3
    ld c, a
    add c
    xor c
    and d
    sbc l
    ld a, a
    sub e
    xor e
    sub a
    and [hl]
    ld a, a
    or d
    cp b
    ret


    or [hl]
    ld d, a
    db $ed
    inc hl
    ld h, h
    ld b, b
    ret


    cp d
    ld a, a
    jr nc, jr_015_5868

    rst $10
    rst $18
    jp $c34f


    or [hl]
    add hl, hl
    sbc $ca
    ld a, a
    push bc
    cp h
    ret z

    rst $20

Jump_015_58c0:
    ld d, a
    db $ed
    inc hl
    rst $10
    ld b, b
    ld a, a
    or [hl]
    push bc

Call_015_58c8:
    call c, $b2c5
    call c, $ed58
    inc hl
    add c
    ld b, b
    ld a, a
    or a
    rst $18
    call nz, Call_015_544f
    ret


    ld a, a
    cp e
    or d
    ret


    or e
    ld a, a
    or c
    reti


    ret


    sub $55
    ld h, $de
    ld a, [hl-]
    rst $18

Call_015_58e7:
    jp $e7c8


    ld d, a
    db $ed
    inc hl
    push af
    ld b, b
    rst $20
    ld c, a
    pop bc
    ld [c], a
    or e
    inc [hl]
    ld a, a
    or d
    or d
    rst $20
    ld d, l
    ret nz

    or d
    cp b
    jp nz, $bc7f

    jp Jump_015_7fc0


    call nz, Call_000_30ba
    ld d, a
    db $ed
    inc hl
    call nc, Call_000_3041
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    call nz, $b57f
    db $d3
    rst $18
    ret nz

    rst $10
    ld d, l
    db $d3
    or e
    ld a, a
    ld d, h
    ld h, $7f
    push bc
    or d
    ld e, b
    db $ed
    inc hl
    dec h
    ld b, c
    call nz, $c6ba
    ld c, a
    dec sp
    dec sp
    rst $10
    dec l
    add $7f
    ret nz

    ret nz

    or [hl]
    or e
    call nz, Call_015_55ca
    ret nz

    or d
    cp h
    ret nz

    ld a, a
    db $d3

jr_015_593c:
    sbc $30
    rst $20
    ld d, a
    db $ed
    inc hl
    ld l, $42
    jp z, $cadf

    xor h
    rst $20
    ld c, a
    add hl, hl
    sbc $b7
    push bc
    ld a, a
    ld a, $b3
    dec l
    ld a, a
    jr nc, jr_015_593c

    ld d, l
    or d
    rst $18
    pop bc
    ld [c], a
    or e
    ld a, a
    call nc, $c0df
    reti


    or [hl]
    rst $20
    ld d, a
    db $ed
    inc hl
    and b
    ld b, d
    rst $18
    call nz, Call_015_58e7
    db $ed
    inc hl
    db $76
    ld b, d
    jp z, $cadf

    xor h
    rst $20
    ld c, a
    add hl, hl
    sbc $b7
    inc sp
    ld a, a
    cp c
    rst $18
    cp d
    or e
    rst $20
    ld d, a
    db $ed
    inc hl
    xor b
    ld b, d
    cp e
    ld a, a
    jp z, $b5d4

    or a
    ld a, a
    cp h
    jp $bf4f


    jr nc, @-$3b

    ret nz

    ld a, a
    cp e
    push bc
    daa
    ld h, $e7
    ld d, l
    call nc, $c4df
    ld a, a
    or [hl]
    or h
    rst $18
    ret nz

    sbc $30
    rst $20
    ld d, a
    db $ed
    inc hl
    add h

jr_015_59a8:
    ld b, e
    rst $20
    ld d, c
    ld a, $b8
    ret


    ld a, a
    jp z, $b5d4

    or a
    jp z, $b24f

    rst $18
    ret nz

    or d
    ld a, a
    push bc
    sbc $30
    rst $18
    ret nz

    sbc $30
    or c
    ld e, b
    db $ed
    inc hl
    rst $38
    ld b, d
    ld a, a
    push bc
    reti


    add $ca
    ld a, a
    pop de
    cp h
    ld a, a
    ld d, h
    ret


    ld c, a

jr_015_59d3:
    adc $b6
    db $d3
    ld a, a
    cp e
    ld h, $bb
    push bc
    or d
    call nz, $0f7f
    and b
    ld a, a
    jr nc, jr_015_59a8

    ld d, a
    db $ed
    inc hl
    cp b
    ld b, e
    rst $18
    jp z, $ace3

    rst $20
    ld c, a
    or [hl]
    or [hl]
    rst $18
    jp $ba7f


    db $e3
    or d
    rst $20
    ld d, a
    db $ed
    inc hl
    ld h, b
    ld b, h
    jp z, $cadf

    xor h
    rst $20
    ld c, a
    or c
    ret c

    ldh [$7f], a
    rst $08
    cp c
    ret nz

    ld a, a
    sub $b3
    jr nc, jr_015_59d3

    ld e, b
    db $ed
    inc hl
    db $db
    ld b, e
    rst $18
    jp z, $ace3

    rst $20
    ld c, a
    call nc, $b5cf
    call nz, $caba

jr_015_5a1f:
    ld a, a
    cp d
    cp d
    db $db
    ld h, $7f
    set 3, e
    or d
    or [hl]
    rst $10
    ld d, l
    rst $08
    cp c
    jp $7fd3


    call c, $dfd7
    jp $c9d9


    jr nc, jr_015_5a1f

    ld d, a
    db $ed
    inc hl
    add a
    ld b, h
    ret


    ld a, a
    or [hl]
    call c, $b2b2
    ld a, a
    pop de
    cp h
    ld a, a
    ld b, e
    adc b
    rst $20
    ld c, a
    cp a
    jp c, $b9b2

    db $e3
    rst $20
    ld d, a
    db $ed
    inc hl
    ld a, [$c944]
    ld a, a
    pop de
    cp h
    ld d, [hl]
    ld e, b
    db $ed
    inc hl
    and a
    ld b, h
    ld d, h
    ret


    ld a, a
    sub $bb
    ld h, $4f
    call c, $d7b6
    push bc
    or d
    ld a, a
    call nc, $cac2
    ld a, a
    pop de
    cp h
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    ld a, [hl-]
    ld a, d
    ld a, a
    rst $38
    ld a, [hl-]
    sbc $7f
    inc [hl]
    or e
    db $db
    ld c, a
    sbc c
    sub h
    rrca
    ld a, a
    ld d, [hl]
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
    call Call_000_3c6c
    ld hl, $5ac5
    ld de, $5aa5
    ld a, [$d599]
    call Call_000_31a8
    ld [$d599], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld a, $5b
    sbc c
    ld e, e
    ld [$345b], a
    ld e, h
    adc e
    ld e, h
    db $ec
    ld e, h
    ld b, a
    ld e, l
    sbc l
    ld e, l
    di
    ld e, l
    jr z, jr_015_5b1d

    ld a, l
    ld e, [hl]
    and e
    ld e, [hl]
    db $e4
    ld e, [hl]
    ld bc, $5820
    rst $10
    ld c, b
    ld e, e
    ld a, l
    ld e, e
    ld h, l
    ld e, e
    ld h, l
    ld e, e
    ld [bc], a
    jr nz, @+$5a

    rst $10
    and e
    ld e, e
    ret z

    ld e, e
    ret nz

    ld e, e
    ret nz

    ld e, e
    inc bc
    jr nz, jr_015_5b38

    rst $10
    db $f4
    ld e, e
    ld [de], a
    ld e, h
    add hl, bc
    ld e, h
    add hl, bc
    ld e, h
    inc b
    jr nz, @+$5a

    rst $10
    ld a, $5c
    ld l, c
    ld e, h
    ld d, a
    ld e, h
    ld d, a
    ld e, h
    dec b
    ld b, b
    ld e, b
    rst $10
    sub l
    ld e, h
    bit 3, h
    or l
    ld e, h
    or l
    ld e, h
    ld b, $20
    ld e, b
    rst $10
    or $5c
    daa
    ld e, l
    ld [de], a
    ld e, l
    ld [de], a
    ld e, l
    rlca
    ld b, b
    ld e, b
    rst $10
    ld d, c
    ld e, l
    ld a, h
    ld e, l
    ld l, e
    ld e, l
    ld l, e
    ld e, l
    ld [$5820], sp
    rst $10

jr_015_5b1d:
    and a
    ld e, l
    push bc
    ld e, l
    or l
    ld e, l
    or l
    ld e, l
    add hl, bc
    jr nz, jr_015_5b80

    rst $10
    db $fd
    ld e, l
    jr jr_015_5b8b

    add hl, bc
    ld e, [hl]
    add hl, bc
    ld e, [hl]
    ld a, [bc]
    ld b, b
    ld e, b
    rst $10
    ld [hl-], a
    ld e, [hl]
    ld d, a

jr_015_5b38:
    ld e, [hl]
    ld c, l
    ld e, [hl]
    ld c, l
    ld e, [hl]
    rst $38
    ld [$c521], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld a, [c]
    ld e, c
    ld a, a
    call nz, Call_015_43d8
    adc b
    ld h, $7f
    or a
    ret nc

    ret nz

    pop bc
    call nz, $c04f
    ret nz

    or [hl]
    or d
    ld a, a
    ret nz

    ld h, $df
    jp $e7d9


    ld d, a
    db $ed
    inc hl
    sub a
    ld e, d
    call nz, Call_015_417f
    dec bc
    xor a
    xor e
    ld c, a
    adc c
    xor e
    ld a, [de]
    ld h, $7f
    rst $08
    cp c
    reti


    ld a, a
    push bc
    sbc $c3
    ld e, b
    db $ed
    inc hl
    dec h

jr_015_5b80:
    ld e, d
    db $d3
    ld a, a
    ld a, $b8
    ret


    ld a, a
    call nz, Call_015_43d8
    adc b

jr_015_5b8b:
    jp z, $cf4f

    sbc $2f
    cp b
    ld a, a
    cp h
    ret nz

    ld a, a
    ret nc

    ret nz

    or d
    ld d, a
    ld [$d121], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    call z, $c95a
    cp d
    add $7f
    cp h
    jp Jump_015_4fca


    cp l
    inc l
    ld h, $7f
    or d
    or d
    rst $18
    jp $ce7f


    jp nc, $dad7

    reti


    ret


    rst $20
    ld d, a
    db $ed
    inc hl
    ld a, e
    ld e, e
    ldh [$df], a
    ret nz

    ld e, b
    db $ed
    inc hl
    db $10
    ld e, e
    jp z, $c24f

    sub $b2
    ld a, a
    ld e, l
    add $7f
    push bc
    ret c

    ret nz

    or d
    ld d, l
    or a
    ld [c], a
    or e
    or [hl]
    rst $10
    ld a, a
    rst $08
    ret nz

    ld a, a
    call nz, $b8df
    sbc $d6
    rst $20
    ld d, a
    ld [$dd21], sp

jr_015_5bed:
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    adc b
    ld e, e
    ld c, a
    or [hl]
    rst $18
    cp d
    or d
    or d
    ld a, a
    add hl, de
    xor h
    dec bc
    ld a, a
    db $d3
    rst $18
    jp $c8d9


    ld d, a
    db $ed
    inc hl
    inc c
    ld e, h
    jr nc, jr_015_5c8e

    jr nc, jr_015_5bed

    ld e, b
    db $ed
    inc hl
    xor h
    ld e, e
    xor h
    dec bc
    ld d, [hl]
    ld c, a
    ret c

    db $e3
    rrca
    db $e3
    ld a, a
    or [hl]
    rst $10
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    sbc $33
    cp h
    ld [c], a
    ld d, l
    ld d, [hl]
    ld a, a
    cp h
    rst $18
    jp $dcd9


    sub $57
    ld [$e921], sp
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    cpl
    ld e, h
    or d
    ld a, a
    ld d, h
    ld a, a
    ret nz

    pop bc
    add $4f
    ld a, [hl+]
    or c
    or d
    cp e
    jp nz, $7fdd

    cp e
    cp [hl]
    reti


    call c, Call_015_57e7
    db $ed
    inc hl
    inc de
    ld e, l
    call nz, Call_015_4fe7
    call c, $bcc0
    ret


    ld a, a
    or [hl]
    sbc $44
    or d
    ret z

    ld e, b
    db $ed
    inc hl
    ld [hl], b
    ld e, h
    cp d
    or e
    call nc, $c3df
    ld c, a
    inc [hl]
    sbc $34
    sbc $7f
    ret nz

    ret nz

    or [hl]
    call c, $c3be
    ld d, l
    jp nz, $b8d6

    ld a, a
    cp h
    jp $c5b6


    or d
    call nz, Call_015_57e7
    ld [$f521], sp

jr_015_5c8e:
    ld e, d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld d, b
    ld e, l
    jp nz, $c07f

    sbc $b9
    sbc $c6
    ld a, a
    or d
    rst $18
    jp $814f


    xor e
    inc de
    and b
    adc a
    adc e
    xor e
    db $dd
    ld a, a
    set 3, e
    rst $18
    ret nz

    ret


    sub $57
    db $ed
    inc hl
    rst $20
    ld e, l
    sbc $c8
    sbc $e7
    ld c, a
    pop bc
    ld [c], a
    or e
    cp h
    ld h, $7f
    inc sp
    push bc
    or [hl]
    rst $18
    ret nz

    call c, $ed58
    inc hl
    adc [hl]
    ld e, l
    add c
    xor e
    inc de
    and b
    adc a
    adc e
    xor e
    ld a, a
    or c
    ret nz

    or h
    ret nz

    rst $10
    ld c, a
    ld d, h
    ret


    ld a, a
    cp l
    ld a, [hl-]
    call nc, Call_000_26bb
    ld a, a
    or c
    ld h, $df
    ret nz

    ret


jr_015_5ceb:
    ld d, a
    ld [$0121], sp
    ld e, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld [$b25e], sp
    sub $e7
    ld a, a
    or [hl]
    ld l, $ca
    ld c, a
    ld a, $b8
    ret


    ld a, a
    adc $b3
    add $7f
    call z, $c3b2
    ld a, a
    or d
    reti


    rst $20
    ld d, a
    db $ed
    inc hl
    cp d
    ld e, [hl]
    dec hl
    pop de
    or a
    ld h, $4f
    or [hl]
    call c, $c0df
    ld a, a
    ret nc

    ret nz

    or d
    ld a, a
    jr nc, jr_015_5ceb

    ld e, b
    db $ed
    inc hl
    ld b, c
    ld e, [hl]
    or e
    ld a, a
    add hl, hl
    sbc $b7
    db $d3
    ld a, a
    push bc
    or d
    call nc, $c44f
    ret c

    add $7f
    ret


    rst $18
    jp $b37f


    pop bc
    add $7f
    or [hl]
    or h
    db $db
    or e
    ld d, a
    ld [$0d21], sp
    ld e, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    pop hl
    ld e, [hl]
    ld a, a
    ld a, $b3
    call nc, $b14f
    or d
    jp $bc7f


    jp $b17f


    add hl, hl
    jp $7fd3


    or d
    or d
    call c, $57d6
    db $ed
    inc hl
    adc h
    ld e, a
    rst $20
    ld c, a
    or l
    call nz, $7fba
    rst $10
    cp h
    or d
    call c, $e7c8
    ld e, b
    db $ed
    inc hl
    jr z, jr_015_5ddf

    cp [hl]
    or [hl]
    or d
    ld a, a
    inc sp
    jp z, $844f

    adc h
    ld a, a
    call nz, $a07f
    adc h
    ld d, l
    inc [hl]
    pop bc
    rst $10
    ld h, $7f
    jp nz, $b2d6

    ret


    ld a, a
    or [hl]
    cp h
    rst $10
    ld d, a
    ld [$1921], sp
    ld e, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    or b
    ld e, a
    call nz, Call_015_547f
    ld a, a
    cp h
    ret nz

    or d
    ret


    and $57
    db $ed
    inc hl
    ld e, c
    ld h, b
    or e
    ld c, a
    or l
    call c, $c1df
    ldh [$df], a
    ret nz

    ret


    ret z

    ld e, b
    db $ed
    inc hl
    jp c, $7f5f

    adc $de
    call nz, $7fca
    ld d, h
    ld c, a
    sub $b8
    ld a, a
    call c, $d7b6
    push bc
    or d
    ret


    ld d, l
    jp nz, $b3b6

    ld a, a

jr_015_5ddf:
    ld d, h
    db $d3
    ld d, l
    or [hl]
    rst $18
    cp d
    or e
    ld a, a
    jr nc, @-$45

    inc sp
    ld a, a
    or a
    jp nc, $e0c1

    or e
    ret


    sub $57
    ld [$2521], sp
    ld e, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec l
    and c
    ld b, l
    rst $20
    ld a, a
    rst $18
    cp [hl]
    db $e3
    push bc
    rst $20
    ld d, a
    db $ed
    inc hl
    adc [hl]
    ld h, b
    sub $e7
    ld c, a
    rst $18
    dec hl
    cp c
    sbc $c5
    sub $e7
    ld e, b
    db $ed
    inc hl
    ld a, c
    ld h, b
    push bc

jr_015_5e1d:
    rst $20
    ld c, a
    or c
    rst $18
    pop bc
    ld a, a
    or d
    cp c
    sub $e7
    ld d, a
    ld [$3121], sp
    ld e, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    sub c
    ld h, b
    call nz, $c47f
    ret c

    ld a, a
    ld d, h
    add $4f
    cp d
    jr nc, jr_015_5e1d

    rst $18
    jp $b77f


    ret nz

    ld a, a
    ld a, $b8
    inc sp
    cp l
    rst $20
    ld d, a
    db $ed
    inc hl
    inc e
    ld h, c
    ld a, a
    jp nz, $c0b7

    ld d, [hl]
    ld e, b
    db $ed
    inc hl
    call nz, Call_015_5660
    ld a, a
    ld a, $b8
    db $d3
    ld c, a
    ld b, e
    xor h
    ld b, e
    call nc, Call_000_1a7f
    dec bc
    xor a
    xor e
    ret


    ld a, a
    sub $b3
    add $55
    cp a
    rst $10
    db $dd
    ld a, a
    call nz, Call_000_33de
    ld a, a
    or d
    or a
    ret nz

    or d
    ld d, a
    db $ed
    inc hl
    add sp, $58
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    cp a
    cp d
    ld a, a
    cp a
    cp d
    rst $20
    ld c, a
    cp b
    or d
    db $dd
    ld a, a
    jp z, $debb

    inc sp
    ld a, a
    swap b
    ret c

    ld a, a
    ld h, $dc
    ld d, a
    db $ed
    inc hl
    scf
    ld e, c
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    inc [hl]
    or e
    jr z, jr_015_5f35

    add d
    or b
    xor e
    inc de
    add d
    inc sp
    ld c, a
    adc l
    and a
    add a
    sub e
    ld a, a
    inc e
    adc a
    xor e
    db $dd
    ld a, a
    or l
    cp l
    call nz, $3455
    or e
    jr z, @-$35

    ld a, a
    ld a, [hl-]
    cp h
    ld [c], a
    db $dd
    ld d, l
    or d
    jp c, $b4b6

    reti


    ld a, a
    cp d
    call nz, Call_015_7f26
    inc sp
    or a
    reti


    rst $20
    ld d, a
    db $ed
    inc hl
    xor e
    ld e, c
    ld a, a
    rst $30
    ld sp, hl
    ld a, [hl-]
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
    adc d
    add c
    and a
    xor e
    inc c
    ld a, a
    dec de
    ret c

    xor h
    dec bc
    ld d, a
    call Call_000_3c6c
    ld hl, $5f31
    ld de, $5f15
    ld a, [$d59a]
    call Call_000_31a8
    ld [$d59a], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    xor d
    ld e, a
    inc de
    ld h, b
    ld h, b
    ld h, b
    call nc, Call_000_2f60
    ld h, c
    ld a, a
    ld h, c
    rst $10
    ld h, c
    inc sp
    ld h, d
    ld a, l
    ld h, d
    push hl
    ld h, d
    dec [hl]
    ld h, e
    ld bc, $5a20
    rst $10

jr_015_5f35:
    or h
    ld e, a
    and $5f
    reti


    ld e, a
    reti


    ld e, a
    ld [bc], a
    jr nz, jr_015_5f9a

    rst $10
    dec e
    ld h, b
    ld b, h
    ld h, b
    ld a, [hl-]
    ld h, b
    ld a, [hl-]
    ld h, b
    inc bc
    ld b, b
    ld e, d
    rst $10
    ld l, d
    ld h, b
    and d
    ld h, b
    sbc c
    ld h, b
    sbc c
    ld h, b
    inc b
    jr nc, @+$5c

    rst $10
    sbc $60
    dec bc
    ld h, c
    inc b
    ld h, c
    inc b
    ld h, c
    dec b
    jr nc, jr_015_5fbe

    rst $10
    add hl, sp
    ld h, c
    ld h, c
    ld h, c
    ld d, l
    ld h, c
    ld d, l
    ld h, c
    ld b, $40
    ld e, d
    rst $10
    adc c
    ld h, c
    xor a
    ld h, c
    and h
    ld h, c
    and h
    ld h, c
    rlca
    ld b, b
    ld e, d
    rst $10
    pop hl
    ld h, c
    inc de
    ld h, d
    nop
    ld h, d
    nop
    ld h, d
    ld [$5a40], sp
    rst $10
    dec a
    ld h, d
    ld h, e
    ld h, d
    ld e, c
    ld h, d
    ld e, c
    ld h, d
    add hl, bc
    jr nc, jr_015_5fee

    rst $10
    add a
    ld h, d
    cp b
    ld h, d
    xor e

jr_015_5f9a:
    ld h, d
    xor e
    ld h, d
    ld a, [bc]
    ld b, b
    ld e, d
    rst $10
    rst $28
    ld h, d
    ld [de], a
    ld h, e
    rlca
    ld h, e
    rlca
    ld h, e
    rst $38
    ld [$3121], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld [hl], l
    ld h, c
    ld a, a
    ld d, h
    add $7f
    cp l
    reti


jr_015_5fbe:
    push bc
    rst $10
    ld c, a
    call nc, Call_015_44df
    ret c

    ld a, a
    ld e, h
    inc sp
    ld d, l
    or d
    or d
    ld a, a
    call c, $dd2b
    ld a, a
    or l
    cp h
    or h
    push bc
    or d
    call nz, $e7c8
    ld d, a
    db $ed
    inc hl
    ld c, c
    ld h, d
    jr nc, jr_015_5fbe

    jp $b67f


    sbc $2c
    jr nc, jr_015_603e

    db $ed
    inc hl
    add $61
    swap e
    sbc $9d

jr_015_5fee:
    adc e
    xor e
    db $d3
    ld a, a
    db $d3
    rst $18
    jp $c8d9


    ld c, a
    or c
    jp c, $7f33

    or l
    ld a, $b4
    ret nz

    ld a, a
    call c, $ca2b
    ld d, l
    ld d, h
    jp z, $f87f

    inc [hl]
    call nz, $dc7f
    cp l
    jp c, $b2c5

    sub $57
    ld [$3d21], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld l, l
    ld h, d
    ld a, a
    call nz, Call_015_7fd8
    ld d, h
    ld c, a
    cp a
    db $db
    cp a
    db $db
    ld d, [hl]
    ld d, l
    ret nz

    ret nz

    or [hl]
    call c, $c3be
    ld a, a
    ret nc

    sub $b3
    or [hl]
    rst $20
    ld d, a
    db $ed
    inc hl
    inc b
    ld h, e

jr_015_603e:
    jp z, $b6d4

    rst $18
    ret nz

    ld e, b
    db $ed
    inc hl
    and [hl]
    ld h, d
    ld a, a
    jp nz, $b2d6

    ld a, a
    call c, Call_015_4f2b
    or l
    cp h
    or h
    jp $b67f


    rst $10
    ld a, a
    ret nz

    ret nz

    or [hl]
    call c, $d6be
    or e
    ld d, a
    ld [$4921], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    jr jr_015_60d1

    adc a
    sbc l
    sbc a
    adc e
    ld a, a
    ld [de], a
    ld b, b
    db $e3
    sub e
    ld a, a
    inc sp
    db $d3
    ld a, a
    or [hl]
    or h
    reti


    rst $20
    ld d, l
    inc sp
    db $d3
    ld a, a
    swap e
    sbc $9d
    adc e
    xor e
    ld a, a
    db $d3
    rst $18
    jp Jump_015_55d9


    set 0, h
    jp z, $bd7f

    cp b
    push bc
    or d
    ret z

    ld d, a
    db $ed
    inc hl
    and $63
    rrca
    adc d
    rrca
    adc d
    ld e, b
    db $ed
    inc hl
    ld a, d
    ld h, e
    adc a
    add c
    ld b, d
    call nz, $b57f
    push bc
    inc l
    ld c, a
    adc a
    add c
    ld b, d
    ret


    ld a, a
    call c, $dd2b
    ld a, a
    or l
    cp h
    or h
    reti


    call nz, $dc55
    dec hl
    ret


    ld a, a
    or d
    ret c

    ld [c], a
    cp b
    ld h, $55
    or l
    or l

jr_015_60ca:
    or a
    cp b
    push bc
    reti


    ld a, a
    rst $10
    cp h

jr_015_60d1:
    or d
    sub $57
    ld [$5521], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld hl, sp+$63
    ld a, a
    call nz, Call_015_7fd8
    ld d, h
    jp z, $b74f

    ret nc

jr_015_60eb:
    db $dd
    ld a, a
    ret


    cp [hl]
    jp $bf7f


    rst $10
    db $dd
    ld a, a
    call nz, Call_015_553c
    call c, $ca2b
    ld a, a
    or l
    ld a, $b4
    ret nz

    or [hl]
    or d
    and $57
    db $ed
    inc hl
    and e
    ld h, h
    cp c
    rst $20
    ld e, b
    db $ed
    inc hl
    ld c, b
    ld h, h
    jp z, $c47f

    ret c

    ld d, h
    ld h, $4f
    jr nc, jr_015_60ca

    cp l
    or a
    ld a, a
    jr nc, @-$48

    rst $10
    ld d, [hl]
    ld d, l
    cp a
    jp c, $b6bc

    ld a, a
    cp a
    jr nc, jr_015_60eb

    ret nz

    cp b
    ld a, a
    push bc
    or d
    sub $57
    ld [$6121], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    jp $c264


    ret


    ld a, a
    ld d, h
    ld a, a
    call nz, $b3b2
    ld c, a
    jp z, $bcc5

    ld a, a
    or a
    or d
    ret nz

    ld a, a
    cp d
    call nz, $b17f
    reti


    and $57
    db $ed
    inc hl
    jr c, jr_015_61be

    jp $cf7f


    cp c
    ret nz

    or [hl]
    push bc
    ld e, b
    db $ed
    inc hl
    ld [$c264], a
    ret


    ld a, a
    ld d, h
    jp z, $f94f

    cp h
    pop hl
    reti


    or d
    ld a, a
    or d
    jp $bd55


    dec a
    jp $c47f


    ret c

    ld a, a
    ld d, h
    jr nc, @-$17

    ld d, a
    ld [$6d21], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld c, h
    ld h, l
    ret


    rst $10
    push bc
    or d
    ld a, a
    cp c
    inc [hl]
    ld d, [hl]
    ld c, a
    cp h
    ld [c], a
    or e
    ld h, $7f
    push bc
    or d
    rst $20
    ld a, a
    call nc, $b6d9
    rst $20
    ld d, a
    db $ed
    inc hl
    xor $65
    ld a, a
    call nc, Call_015_44df
    ret c

    push bc
    ld e, b
    db $ed
    inc hl
    ld [hl], l
    ld h, l
    ld a, a
    set 3, e
    cp e
    add $7f
    cp b
    rst $10
    dec a
    ret nz

    rst $10

jr_015_61be:
    ld c, a
    or [hl]
    pop bc
    ld a, a
    rst $08
    cp c
    ld a, a
    push bc
    sbc $c3
    ld d, l
    inc [hl]
    or e
    rst $18
    jp $ba7f


    call nz, $c57f
    or d
    ret


    cp e
    rst $20

jr_015_61d6:
    ld d, a
    ld [$7921], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    dec bc
    ld h, [hl]
    or l
    jp c, $7fca

    cp [hl]
    rst $18
    or [hl]
    pop bc
    jr nc, jr_015_61d6

    ld c, a
    jp z, $b8d4

    ld a, a
    jp z, $b8d4

    ld a, a
    jp z, $b8d4

    ld a, a
    cp h
    db $db
    rst $20
    ld d, a
    db $ed
    inc hl
    sbc h
    ld h, [hl]
    ld a, a
    rst $08
    cp c
    ret nz

    ld c, a
    or l
    call c, $30d8
    ld a, a
    inc l
    ldh [$b1], a
    push bc
    ld e, b
    db $ed
    inc hl
    dec a
    ld h, [hl]
    ld a, a
    push bc
    sbc $30
    ld a, a
    push bc
    sbc $30
    rst $20
    ld c, a
    rst $08
    jr nc, @+$81

    sub $b3
    inc l
    ld h, $7f
    or c
    reti


    ld a, a
    or c
    reti


    ld a, a
    ret


    or [hl]
    rst $20
    ld d, a
    ld [$8521], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    jp z, $3466

    ld a, a
    or d
    or d
    ld l, $e7
    ld c, a
    jp nz, $ba3d

    dec a
    ld a, a
    or d
    call c, $c62d
    ld a, a
    or c
    or d
    jp $bc7f


    push bc
    ld d, a
    db $ed
    inc hl
    ld l, b
    ld h, a
    ld a, a
    cp d
    rst $10
    or c
    rst $20
    ld e, b
    db $ed
    inc hl
    rst $38
    ld h, [hl]
    ld a, a
    pop bc
    rst $08
    pop bc
    rst $08
    call nz, $bf4f
    jr nc, @-$3b

    reti


    ld a, a
    ret


    jp z, $c67f

    ld h, $c3
    jr nc, @+$30

    rst $20
    ld d, a
    ld [$9121], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


jr_015_6287:
    db $ed
    inc hl
    ld a, l
    ld h, a
    or c
    ret nz

    ret c

    jp z, $c04f

    jp $c9d3


    ld h, $7f
    cp l
    cp b
    ret z

    or h
    ld a, a
    or [hl]
    rst $10
    ld d, l
    sub $b8
    ld a, a
    jp z, $d8bc

    add $7f
    cp b
    reti


    ld l, $e7
    ld d, a
    db $ed
    inc hl
    ld d, d
    ld l, b
    ld a, a
    cp d
    cp c
    pop bc
    rst $08
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    inc hl
    rst $08
    ld h, a
    cp a
    cp d
    rst $08
    inc sp
    ld a, a
    cp a
    jr nc, jr_015_6287

    ret nz

    push bc
    rst $20
    ld c, a
    push bc
    sbc $c6
    cp h
    jp Jump_015_56d3


    ld d, c
    jp nz, $b2d6

    rst $18
    jp $ba7f


    call nz, Call_015_4fca
    ret nz

    or d
    cp h
    ret nz

    ld a, a
    db $d3
    sbc $30
    ld l, $e7
    ld d, a
    ld [$9d21], sp
    ld e, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld h, [hl]
    ld l, b
    or d
    cp c
    jp nz, $e7b6

    ld c, a
    or l
    db $d3
    cp h
    db $db
    or d
    rst $20
    ld a, a
    jp nz, $b1b7

    or e
    ld l, $e7
    ld d, a
    db $ed
    inc hl
    inc de
    ld l, c
    cp b
    ld a, a
    or d
    or [hl]
    ret z

    or h
    ld e, b
    db $ed
    inc hl
    sbc d
    ld l, b
    ld a, a
    or l
    rst $08
    or h
    ret


    ld c, a
    pop bc
    ld [c], a
    cp b
    cp [hl]
    jp nz, $c07f

    or d
    cp c
    jp nz, $307f

    rst $18
    ret nz

    rst $10
    ld d, l
    or l
    jp c, Jump_015_7f26

    or [hl]
    jp nz, $e72e

    ld d, a
    db $ed
    inc hl
    ccf
    ld h, c
    ld a, a
    rst $30
    ld a, [$de3a]
    ld a, a
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
    ld hl, $638a
    ld de, $6364
    ld a, [$d59b]
    call Call_000_31a8
    ld [$d59b], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    inc bc
    ld h, h
    ld e, l
    ld h, h
    sbc l
    ld h, h
    reti


    ld h, h
    rra
    ld h, l
    ld h, b
    ld h, l
    cp c
    ld h, l
    cp $65
    ccf
    ld h, [hl]
    add h
    ld h, [hl]
    cp e
    ld h, [hl]
    reti


    ld h, [hl]
    inc hl
    ld h, a
    ld d, a
    ld h, a
    ld [hl], c
    ld h, a
    sbc b
    ld h, a
    ld bc, $6030
    rst $10
    dec c
    ld h, h
    inc [hl]
    ld h, h
    inc l
    ld h, h
    inc l
    ld h, h
    ld [bc], a
    ld b, b
    ld h, b
    rst $10
    ld h, a
    ld h, h
    adc b
    ld h, h
    add b
    ld h, h
    add b
    ld h, h
    inc bc
    ld b, b
    ld h, b
    rst $10
    and a
    ld h, h
    cp a
    ld h, h
    cp b
    ld h, h
    cp b
    ld h, h
    inc b
    ld b, b
    ld h, b
    rst $10
    db $e3
    ld h, h
    ld a, [bc]
    ld h, l
    nop
    ld h, l
    nop
    ld h, l
    dec b
    jr nc, @+$62

    rst $10
    add hl, hl
    ld h, l
    ld b, h
    ld h, l
    dec a
    ld h, l
    dec a
    ld h, l
    ld b, $20
    ld h, b
    rst $10
    ld l, d
    ld h, l
    sub d
    ld h, l
    adc d
    ld h, l
    adc d
    ld h, l
    rlca
    ld b, b
    ld h, b
    rst $10
    jp $e665


    ld h, l
    call nc, $d465
    ld h, l
    ld [$6020], sp
    rst $10
    ld [$2766], sp
    ld h, [hl]
    ld hl, $2166
    ld h, [hl]
    add hl, bc
    jr nc, jr_015_644d

    rst $10
    ld c, c
    ld h, [hl]
    ld l, c
    ld h, [hl]
    ld h, e
    ld h, [hl]
    ld h, e
    ld h, [hl]
    ld a, [bc]
    ld b, b
    ld h, b
    rst $10
    adc [hl]
    ld h, [hl]
    xor h
    ld h, [hl]
    and l
    ld h, [hl]
    and l
    ld h, [hl]
    rst $38
    ld [$8a21], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld a, a
    ld [hl], a
    ld a, a
    or c
    or d
    jp $7fc6


    ret nz

    ret nz

    or [hl]
    rst $18
    jp Jump_015_4fd3


    cp h
    ld [c], a
    or e
    or a
    sbc $ca
    ld a, a
    ret nz

    rst $08
    rst $10
    ret z

    or h
    rst $20
    ld d, a
    db $ed
    inc hl
    ld c, [hl]
    ld a, b
    or a
    ret nz

    ld l, $58
    db $ed
    inc hl
    pop bc
    ld [hl], a
    ret c

    xor e
    rlca
    ld a, a
    xor b
    db $e3
    inc de
    jp z, $b54f

    call nz, $d3bc
    ret


    ld h, $7f
    or l
    or l
    or d
    rst $20
    ld d, l

jr_015_644d:
    set 3, e
    rst $18
    jp $b37f


    jp c, $7f3a

    db $d3
    or e
    or [hl]
    reti


    ld l, $b4
    ld d, a
    ld [$9621], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld h, a
    ld a, b
    ld [c], a
    cp b
    ld a, a
    add $ca
    ld c, a
    inc l
    cp h
    sbc $7f
    or c
    reti


    ld l, $b4
    ld d, [hl]
    ld a, a
    cp d
    or d
    sub $e7
    ld d, a
    db $ed
    inc hl
    ret c

    ld a, b
    db $e3
    sbc $e7
    ld e, b
    db $ed
    inc hl
    sbc h
    ld a, b
    add $4f
    or l
    push bc
    or [hl]
    inc sp
    db $d3
    ld a, a
    cp e
    call c, $c3df
    ld a, a
    ret nc

    reti


    or [hl]
    ld d, a
    ld [$a221], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    db $ec
    ld a, b
    add a
    ld a, a
    adc e
    sub d
    or b
    add $7f
    or d
    cp b
    ret


    or [hl]
    and $57
    db $ed
    inc hl
    ld b, b
    ld a, c
    db $e3
    rst $20
    ld e, b
    db $ed
    inc hl
    ld [bc], a
    ld a, c
    dec hl
    or [hl]
    ld a, a
    or d
    rst $18
    or a

jr_015_64c9:
    add $7f
    or l
    ret c

    reti


    call nz, $b74f
    db $d3
    pop bc
    ld a, a
    or d
    or d
    ld l, $e7
    ld d, a
    ld [$ae21], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld d, d
    ld a, c
    pop bc
    ld a, a
    ld a, $b3
    cp a
    or e
    ld a, a
    cpl
    cp b
    rst $20
    ld c, a
    push bc
    cp b
    ld a, a
    cp d
    db $d3
    ld a, a
    jr nc, jr_015_64c9

    rst $10
    cp [hl]
    reti


    ld l, $e7
    ld d, a
    db $ed
    inc hl
    and a
    ld a, c
    ld a, a
    push bc
    rst $10
    ret z

    or h
    ld e, b
    db $ed
    inc hl
    ld h, [hl]
    ld a, c
    or [hl]
    ld d, [hl]
    ld c, a
    inc [hl]
    or a
    ld [c], a
    or e
    ld a, a
    or c
    reti


    ld a, a
    inc l
    ldh [$c8], a
    or h
    or [hl]
    ld d, a
    ld [$ba21], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    push bc
    ld a, c
    or c
    rst $20
    ld c, a
    ld a, [de]
    ret c

    ret c

    rrca
    sbc l
    add $7f
    cp h
    dec sp
    jp c, $e7db

    ld d, a
    db $ed
    inc hl
    jr nc, @+$7c

    ld d, [hl]
    rst $20
    ld e, b
    db $ed
    inc hl
    xor $79
    ld a, [de]
    ret c

    ret c

    rrca
    sbc l
    jp z, $d14f

    inc l
    sbc $7f
    jp z, Jump_000_33c2

    sbc $bc
    ld [c], a
    inc sp
    ld a, a
    call nz, $c0df
    ld l, $57
    ld [$c621], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld a, [hl-]
    ld a, d
    ld a, a
    ld d, h
    ld a, a
    and a
    dec a
    and [hl]
    ld a, a
    or c
    add hl, hl
    jp Jump_015_4fd3


    push bc
    or [hl]
    push bc
    or [hl]
    ld a, a
    cp h
    sbc $b6
    ld a, a
    cp h
    push bc
    or d
    ld l, $b4
    rst $20
    ld d, a
    db $ed
    inc hl
    jp c, $d47a

    db $db
    rst $20
    ld e, b
    db $ed
    inc hl
    ld a, d
    ld a, d
    or h
    ld a, [hl-]
    ld a, a
    ld d, h
    add $7f
    sub $df
    jp $b24f


    cp h
    db $dd
    ld a, a
    or [hl]
    dec hl
    cp l
    call nz, $bc55
    sbc $b6
    ld a, a
    cp l
    reti


    or [hl]
    db $d3
    ld a, a
    cp h
    jp c, $b2c5

    ld l, $b4
    ld d, a
    ld [$d221], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    ld [$be7a], a
    ld a, a
    or [hl]
    or d
    jp $d47f


    cp [hl]
    reti


    or [hl]
    or c
    rst $20
    ld d, a
    db $ed
    inc hl
    ld h, h
    ld a, e
    ld c, a
    or c
    jp nz, Jump_015_7fb2

    ret nz

    ret nz

    or [hl]
    or d
    ld a, a
    jr nc, jr_015_6612

    or h
    ld e, b
    db $ed
    inc hl
    dec c
    ld a, e
    or [hl]
    or d
    jp $bd4f


    cp d
    cp h
    ld a, a
    call nc, $c0be
    ld a, a
    or a
    ld h, $7f
    cp l
    reti


    ld l, $b4
    ld d, a
    ld [$de21], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    add [hl]
    ld a, e
    reti


jr_015_660d:
    ld a, a
    cp d
    call nz, Call_015_4f26

jr_015_6612:
    or l
    call nz, $c9ba
    ld a, a
    cp b
    sbc $bc
    ld [c], a
    or e
    jr nc, jr_015_664c

    or h
    rst $20
    ld d, a
    db $ed
    inc hl
    db $eb
    ld a, e
    rst $20
    ld e, b
    db $ed
    inc hl
    xor c
    ld a, e
    ld a, a
    jr nc, jr_015_660d

    ret nz

    rst $10
    ld c, a
    cp h
    sbc $2c
    reti


    ld a, a
    ret nc

    pop bc
    db $dd
    ld a, a
    or d
    cp c
    or h
    rst $20
    ld d, a
    ld [$ea21], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc hl
    di

jr_015_664c:
    ld a, e
    ld a, a
    inc l
    jp $bcde


    ldh [$30], a
    push bc
    rst $20
    ld c, a
    ret


    ret c

    ld a, [hl+]
    cp d
    pop bc
    jp z, $347f

    or e
    jr nc, @-$18

    ld d, a
    db $ed
    inc h
    ld c, d
    ld b, b
    rst $20
    ld e, b
    db $ed
    inc h
    nop
    ld b, b
    pop bc
    inc sp
    ret


    ld a, a
    sbc c
    xor e
    inc de
    and [hl]
    ld a, a
    cp e
    ld a, [hl-]
    or a
    ld c, a
    pop de
    dec l
    or [hl]
    cp h
    or d
    ld a, a
    jr nc, @-$23

    rst $20
    ld d, a
    ld [$f621], sp
    ld h, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld d, h
    ld b, b
    ret c

    or d
    sub $56
    ld a, a
    ret z

    ret nc

    or d
    sub $4f
    jp nc, $34de

    cp b
    cp [hl]
    or h
    ld d, [hl]
    rst $20
    ld d, a
    db $ed
    inc h
    xor l
    ld b, b
    ret nz

    or [hl]
    ld e, b
    db $ed
    inc h
    add l
    ld b, b
    add hl, de
    xor h
    add a
    and a
    jp $c87f


    jp $d6b4


    ld d, a
    db $ed
    inc hl
    ld b, d
    ld [hl], l
    ld h, $7f
    jp z, $c3df

    or c
    reti


    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    inc [hl]
    or e
    jr z, jr_015_674d

    push bc
    add hl, hl
    cp l
    jp $c17f


    pop hl

jr_015_66d5:
    or e
    or d
    rst $20
    ld d, a
    db $ed
    inc hl
    adc b
    ld [hl], l
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    or l
    push bc
    inc l
    ld a, a
    ld d, h
    ld a, a
    or l
    push bc
    inc l
    ld a, a
    and a
    dec a
    and [hl]
    inc sp
    db $d3
    ld c, a
    call nz, $c0d9
    dec sp
    add $7f
    ld b, b
    and l
    and b
    db $e3
    adc a
    ld h, $7f
    cp l
    cp d
    cp h
    ld d, l
    pop bc
    ld h, $df
    jp Jump_015_56c3


    ld a, a
    cp a
    jr nc, jr_015_66d5

    call nz, $c155
    ld h, $b2
    ld h, $7f
    or l
    or l
    or a
    cp b
    ld a, a
    push bc
    reti


    rst $20
    ld d, a
    db $ed
    inc hl
    ld d, c
    db $76
    call nz, $c5b8
    ld a, a
    cp c
    or d
    inc l
    ld a, [hl-]
    sbc $e7
    ld d, c
    inc e
    adc a
    xor e
    db $dd
    ld a, a
    or l
    cp h
    jp Jump_000_3ada


    ld c, a
    cp e
    or [hl]
    ret nc

    pop bc
    inc sp
    db $d3
    ld a, a
    inc l
    jp $bcde


    ldh [$c9], a
    ld d, l
    adc a
    add c

jr_015_674d:
    and d
    ld h, $7f
    cp l
    dec a
    rst $10
    push bc
    or d
    rst $20
    ld d, a
    db $ed
    inc hl
    cp l
    db $76
    ld a, a
    rst $30
    db $fd
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
    db $ed
    inc hl
    ld sp, hl
    db $76
    ld h, $7f
    jp z, $c3df

    or c
    reti


    rst $20
    ld d, c
    ld [$9fe3], sp
    db $dd
    ld a, a
    push bc
    add hl, hl
    reti


    push bc
    rst $20
    ld c, a
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
    db $db
    rst $20
    ld d, a
    db $ed
    inc hl
    ld b, [hl]
    ld [hl], a
    ret c

    xor e
    rlca
    ld a, a
    xor b
    db $e3
    inc de
    ld c, a
    ld d, [hl]
    ld a, a
    cp e
    or [hl]
    ret nc

    pop bc
    jp z, $ba7f

    cp d
    rst $08
    inc sp
    rst $20
    ld d, a
    call Call_000_3c6c
    ld hl, $67e1
    ld de, $67c5
    ld a, [$d59c]
    call Call_000_31a8
    ld [$d59c], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld e, d
    ld l, b
    and l
    ld l, b
    ld a, [c]
    ld l, b
    ld [hl-], a
    ld l, c
    ld [hl], l
    ld l, c
    ret nz

    ld l, c
    dec c
    ld l, d
    ld h, [hl]
    ld l, d
    xor [hl]
    ld l, d
    db $f4
    ld l, d
    ld c, b
    ld l, e
    ld bc, $6440
    rst $10
    ld h, h
    ld l, b
    adc h
    ld l, b
    add c
    ld l, b
    add c
    ld l, b
    ld [bc], a
    jr nc, jr_015_6854

    rst $10
    xor a
    ld l, b
    push de
    ld l, b
    call $cd68
    ld l, b
    inc bc
    jr nc, @+$66

    rst $10
    db $fc
    ld l, b
    inc e
    ld l, c
    inc d
    ld l, c
    inc d
    ld l, c
    inc b
    ld b, b
    ld h, h
    rst $10
    inc a
    ld l, c
    ld e, [hl]
    ld l, c
    ld d, [hl]
    ld l, c
    ld d, [hl]
    ld l, c
    dec b
    ld b, b
    ld h, h
    rst $10
    ld a, a
    ld l, c
    and l
    ld l, c
    sbc l
    ld l, c
    sbc l
    ld l, c
    ld b, $40
    ld h, h
    rst $10
    jp z, $f269

    ld l, c
    rst $20
    ld l, c
    rst $20
    ld l, c
    rlca
    jr nc, jr_015_6890

    rst $10
    rla
    ld l, d
    ld b, h
    ld l, d
    ld a, [hl-]
    ld l, d
    ld a, [hl-]
    ld l, d
    ld [$6440], sp
    rst $10
    ld [hl], b
    ld l, d
    sub e
    ld l, d
    adc h
    ld l, d
    adc h
    ld l, d
    add hl, bc
    ld b, b
    ld h, h
    rst $10
    cp b
    ld l, d
    sbc $6a
    pop de
    ld l, d
    pop de
    ld l, d
    ld a, [bc]
    ld b, b
    ld h, h
    rst $10
    cp $6a
    ld [hl+], a

jr_015_6854:
    ld l, e
    dec de
    ld l, e
    dec de
    ld l, e
    rst $38
    ld [$e121], sp
    ld h, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld d, e
    ld b, e
    ld a, a
    jp z, $d9b2

    ld a, a
    rst $08
    or h
    add $4f
    inc l
    pop hl
    sbc $3b
    ld a, a
    ret nz

    or d
    cp a
    or e
    ld a, a
    cp h
    push bc
    or a
    ldh [$e7], a
    ld d, a
    db $ed
    inc h
    jp hl


    ld b, e
    or e
    ld a, a
    or l
    call c, $e7d8
    ld e, b
    db $ed
    inc h
    sbc l
    ld b, e

jr_015_6890:
    rst $20
    ld a, a
    or l
    or [hl]
    add hl, hl
    inc sp
    ld c, a
    or d
    or d
    ld a, a
    or e
    sbc $34
    or e
    add $7f
    push bc
    rst $18
    ret nz

    rst $20
    ld d, a
    ld [$ed21], sp
    ld h, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    or $43
    or c
    call c, $d9c3
    push bc
    rst $20
    ld c, a
    cp h
    sbc $2f
    or e
    ld a, a
    sbc l
    sbc d
    add $7f
    push bc
    rst $18
    ret nz

    rst $10
    ld a, a
    inc [hl]
    or e
    cp l
    reti


    ld d, a
    db $ed
    inc h
    or c
    ld b, h
    cp e
    pop de
    or d
    ld e, b
    db $ed
    inc h
    inc a
    ld b, h
    and l
    ld [$7fc6], sp
    cp e
    cp e
    jp c, $b2c5

    sub $b3
    ld c, a
    or a
    db $dd
    ld a, a
    jp nz, $c3b9

    ld a, a
    or l
    sub $29
    sub $e7
    ld d, a
    ld [$f921], sp
    ld h, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    jp nz, $c944

    ld a, a
    jr nc, @-$4c

    cp l
    or a
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    or a
    ret nc

    jp z, $347f

    or e
    push bc
    ret


    and $57
    db $ed
    inc h
    dec hl
    ld b, l
    db $e3
    xor e
    rst $20
    ld e, b
    db $ed
    inc h
    xor $44
    ld a, a
    push bc
    rst $10
    ld c, a
    or e
    ret nc

    ret


    ld a, a
    ld d, h
    add $d3
    ld a, a
    rst $08
    cp c
    push bc
    or d
    rst $20
    ld d, a
    ld [$0521], sp
    ld l, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    inc [hl]
    ld b, l
    or d
    cp [hl]
    sbc $c9
    ld a, a
    pop de
    cp d
    or e
    ld c, a
    ld d, [hl]
    ld a, a
    push bc
    add $26
    ld a, a
    or c
    reti


    sbc $30
    db $db
    and $57
    db $ed
    inc h
    or l
    ld b, l
    ret c

    ldh [rRP], a
    ld e, b
    db $ed
    inc h
    ld l, [hl]
    ld b, l
    cp d
    or e
    add $4f
    or d
    cp b

jr_015_6968:
    jp nz, Jump_015_7fb6

    cp h
    rst $08
    ld h, $7f
    ret nc

    or h
    reti


    cpl
    rst $20
    ld d, a
    ld [$1121], sp
    ld l, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ret


    ld b, l

jr_015_6983:
    jp $7f56


    or e
    ret nc

    ld a, a
    ld d, h
    ld c, a
    call nz, $b3db
    call nz, $c0bc
    cp c
    inc [hl]
    ld a, a
    jr nc, jr_015_6968

    ld a, a
    ret nc

    ret nz

    or d
    jr nc, jr_015_6983

    ld d, a
    db $ed
    inc h
    ld l, h
    ld b, [hl]
    ld a, [hl+]
    ld a, $ac
    ld e, b
    db $ed
    inc h
    jr jr_015_69ef

    ld a, a
    ld d, h
    jp z, $d47f

    rst $18
    ld b, h
    ret c

    ld c, a
    jp nz, $33d8

    ld a, a
    call nz, $7fd9
    cp h
    or [hl]
    ld a, a
    push bc
    or d
    call nc, Call_000_0857
    ld hl, $681d
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    add b
    ld b, [hl]
    ld a, a
    or e
    ret nc

    db $dd
    ld a, a
    ret nc

    jp Jump_000_3ada


    ld c, a
    or d
    call nc, Call_015_7fc5
    cp d
    call nz, $7fd3
    call c, $dabd
    reti


    cpl
    rst $20
    ld d, a
    db $ed
    inc h
    ld [hl-], a

jr_015_69ea:
    ld b, a
    ld a, a
    rst $08
    cp c
    or [hl]

jr_015_69ef:
    ret nz

    jr nc, jr_015_6a4a

    db $ed
    inc h
    call z, $7f46
    or e
    ret nc

    db $dd
    ld a, a
    ret nc

    jp Jump_015_4f56


    or d
    call nc, Call_015_7fc5
    cp d
    call nz, $7fdd
    call c, $dabd
    sub $b3
    ld d, a
    ld [$2921], sp
    ld l, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld d, b
    ld b, a
    or d
    or d
    ld a, a
    db $d3
    ret


    add $7f
    ret


    rst $18
    jp $dcd9


    ret z

    ld c, a
    or [hl]
    rst $18
    ret nz

    rst $10
    ld a, a
    call c, $bcc0
    add $7f
    pop bc

jr_015_6a34:
    ld [c], a
    or e
    jr nc, jr_015_69ea

    rst $20
    ld d, a
    db $ed
    inc h
    and $47
    ret


    ld a, a
    rst $08
    cp c
    or [hl]
    ld e, b
    db $ed
    inc h
    sub c
    ld b, a
    inc l
    rst $08

jr_015_6a4a:
    ld a, a
    rst $08
    inc sp
    ld c, a
    rst $08
    jr nc, jr_015_6ad0

    or c
    ret c

    cp a
    or e
    jr nc, @-$42

    ld d, [hl]
    ld d, l
    adc l
    add [hl]
    sub b
    add a
    add $7f
    or [hl]
    or h
    ret c

    ret nz

    or d
    call c, Call_000_0857
    ld hl, $6835
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    db $f4
    ld b, a
    ret


    ld a, a
    cp l
    or a
    ld a, a
    jr nc, jr_015_6a34

    inc [hl]
    ld c, a
    set 2, h
    cp c
    ld a, a
    cp l
    reti


    ret


    jp z, $b27f

    call nc, $dc30
    rst $20
    ld d, a
    db $ed
    inc h
    ld [hl], h
    ld c, b
    rst $10
    ld d, [hl]
    ld e, b
    db $ed
    inc h
    inc l
    ld c, b
    ld a, a
    call z, Call_000_2ac0
    inc l
    rst $08
    ld a, a
    rst $08
    inc sp
    ld c, a
    or l
    sub $2a
    or e
    rst $18
    jp $b27f


    rst $18
    ret nz

    ret


    sub $57
    ld [$4121], sp
    ld l, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    adc a
    ld c, b
    ld a, a
    cp h
    ld [c], a
    or e
    ret z

    sbc $e7
    ld c, a
    cp d
    ret


    ld a, a
    or e
    ret nc

    jp z, $b77f

    cp c
    sbc $30
    rst $20

jr_015_6ad0:
    ld d, a
    db $ed
    inc h
    ld bc, $b249
    ld a, a
    jp nc, $7fc6

    or c
    rst $18
    ret nz

    ld e, b
    db $ed
    inc h
    ret


    ld c, b
    cp h
    ld h, $7f
    jp nz, $c0df

    rst $20
    ld c, a
    inc a
    cp b
    ld d, [hl]
    ld a, a
    inc a
    cp b
    inc a
    cp b
    ld d, [hl]
    ld d, a
    ld [$4d21], sp
    ld l, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    rla
    ld c, c
    inc sp
    ld a, a
    cp d
    cp d
    rst $08
    inc sp
    ld a, a
    or l
    sub $b2
    inc sp
    ld c, a
    or a
    ret nz

    cp c
    inc [hl]
    ld d, [hl]
    ld a, a
    cp b
    ret nz

    dec sp
    jp c, $dcc0

    ld d, a
    db $ed
    inc h
    jp nc, $c049

    ld d, [hl]
    ld e, b
    db $ed
    inc h
    ld e, b
    ld c, c
    ld a, a
    ld d, h
    add $7f
    ret


    reti


    push bc
    rst $10
    ld c, a
    and l
    ld b, d
    and l
    adc h
    ld h, $7f
    or d
    or d
    call c, $b555
    or l
    or a
    or d
    or [hl]
    rst $10
    ld a, a
    rst $00
    jp c, $b2c5

    ld a, a
    db $d3
    ret


    ld d, a
    db $ed
    inc h
    rra
    ld b, e
    ld a, a
    rst $30
    rst $38
    ld a, [hl-]
    sbc $7f
    cp l
    or d
    inc [hl]
    or e
    ld c, a
    adc l
    add [hl]
    sub b
    add a
    ld a, a
    ld d, [hl]
    ld a, a
    call z, Call_000_2ac0
    inc l
    rst $08
    ld d, a
    call Call_000_3c6c
    ld hl, $6b8f
    ld de, $6b77
    ld a, [$d59d]
    call Call_000_31a8
    ld [$d59d], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    db $fc
    ld l, e
    ccf
    ld l, h
    sub b
    ld l, h
    call z, $0f6c
    ld l, l
    ld c, [hl]
    ld l, l
    and b
    ld l, l
    rst $10
    ld l, l
    inc sp
    ld l, [hl]
    ld bc, $6800
    rst $10
    ld b, $6c
    inc l
    ld l, h
    inc hl
    ld l, h
    inc hl
    ld l, h
    ld [bc], a
    nop
    ld l, b
    rst $10
    ld c, c
    ld l, h
    ld a, b
    ld l, h
    ld h, l
    ld l, h
    ld h, l
    ld l, h
    inc bc
    ld b, b
    ld l, b
    rst $10
    sbc d
    ld l, h
    or h
    ld l, h
    xor [hl]
    ld l, h
    xor [hl]
    ld l, h
    inc b
    ld b, b
    ld l, b
    rst $10
    sub $6c
    ld a, [c]
    ld l, h
    db $ec
    ld l, h
    db $ec
    ld l, h
    dec b
    ld b, b
    ld l, b
    rst $10
    add hl, de
    ld l, l
    scf
    ld l, l
    ld l, $6d
    ld l, $6d
    ld b, $40
    ld l, b
    rst $10
    ld e, b
    ld l, l
    ld a, a
    ld l, l
    db $76
    ld l, l
    db $76
    ld l, l
    rlca
    jr nc, jr_015_6c42

    rst $10
    xor d
    ld l, l
    add $6d
    cp l
    ld l, l
    cp l
    ld l, l
    ld [$6800], sp
    rst $10
    pop hl
    ld l, l
    ld [de], a
    ld l, [hl]
    db $fd
    ld l, l
    db $fd
    ld l, l
    add hl, bc
    nop
    ld l, b
    rst $10
    dec a
    ld l, [hl]
    ld h, h
    ld l, [hl]
    ld e, b
    ld l, [hl]
    ld e, b
    ld l, [hl]
    rst $38
    ld [$8f21], sp
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld a, $50
    rst $08
    cp l
    or [hl]
    and $71
    call nz, Call_015_7fb6
    or l
    rst $08
    or h
    jp z, $b74f

    or a
    ret nz

    or d
    sbc $2c
    ldh [$c5], a
    or d
    ret


    and $57
    db $ed
    inc h
    rst $08
    ld d, b
    call nc, $dad7
    ret nz

    ld e, b
    db $ed
    inc h
    ld [hl], e
    ld d, b
    ld d, h
    ld a, a
    jp nz, $c8da

    db $e3
    sub $e7
    ld c, a
    ld l, $de
    ld l, $de
    rst $20
    ld d, a
    ld [$9b21], sp

jr_015_6c42:
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld hl, sp+$50
    ld [c], a
    or e
    rst $20
    ld a, a
    ret nz

    or d
    ret c

    ld [c], a
    or e
    rst $20
    ld c, a
    or l
    jp c, Jump_015_7fc9

    ld d, h
    call nz, $c07f
    ret nz

    or [hl]
    or e
    and $57
    db $ed
    inc h
    adc c
    ld d, c
    add $4f
    adc c
    add c
    add [hl]
    xor e
    rlca
    ld a, a
    inc l
    ldh [$7f], a
    rrca
    and b
    or [hl]
    ld e, b
    db $ed
    inc h
    add hl, sp
    ld d, c
    ld a, a
    adc c
    add c
    add [hl]
    xor e
    rlca
    ld c, a
    ld a, [hl-]
    rst $18
    or [hl]
    ret c

    ld a, a
    jp nz, $d9da

    sbc $30
    sub $e7

jr_015_6c8f:
    ld d, a
    ld [$a721], sp
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    xor l
    ld d, c
    db $e3
    xor h
    ld c, a
    or l
    call nz, $c9ba
    ld a, a
    xor b
    sbc l
    xor e
    jr nc, @-$1b

    xor h
    rst $20
    ld d, a
    db $ed
    inc h
    rrca
    ld d, d
    rst $20
    ld e, b
    db $ed
    inc h
    adc $51
    ld a, a
    or d
    or d
    cp c
    inc [hl]
    ld c, a
    inc l
    jp nz, $7fca

    call nc, $d3cf
    ld a, a
    cp l
    or a
    jr nc, jr_015_6c8f

    rst $20
    ld d, a
    ld [$b321], sp
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    ld d, $52
    rst $18
    jp $c07f


    rst $08
    add $ca
    ld c, a
    or l
    sub $27
    add $7f
    cp b
    reti


    ld l, $e7
    ld d, a
    db $ed
    inc h
    sbc [hl]
    ld d, d
    rst $20
    ld e, b
    db $ed
    inc h
    inc a
    ld d, d
    cp l
    cp a
    or e
    ld a, a
    jr nc, @-$3a

    and $4f
    or e
    reti


    cp [hl]
    db $e3
    ld a, a
    or l
    or l
    or a
    push bc
    ld a, a
    or l
    cp [hl]
    call c, $ac30
    rst $20
    ld d, a
    ld [$bf21], sp
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    xor c
    ld d, d
    ld a, a
    ld d, h
    jp z, $b34f

    ret nc

    inc sp
    ld a, a
    call nz, $c3df
    ld a, a
    or a
    rst $08
    cp h
    ret nz

    ld d, a
    db $ed
    inc h
    ei
    ld d, d
    ret nc

    db $e3
    xor h
    rst $20
    ld e, b
    db $ed
    inc h
    push de
    ld d, d
    ld a, a
    ld d, h
    jp z, $344f

    cp d
    inc sp
    ld a, a
    call nz, $c3df
    ld a, a
    or a
    ret nz

    ret


    or [hl]
    push bc
    and $57
    ld [$cb21], sp
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    inc bc
    ld d, e

jr_015_6d5c:
    ld a, a
    or d
    rst $08
    ld a, a
    sub e
    and l
    add c
    add b
    adc h
    xor b
    xor e
    ret


    ld c, a
    rst $08
    rst $18
    cp e
    or d
    pop bc
    pop hl
    or e
    ld a, a
    push bc
    ret


    jr nc, jr_015_6d5c

    ld d, a
    db $ed
    inc h
    sbc a
    ld d, e
    jp z, $ace3

    rst $20
    ld e, b
    db $ed
    inc h
    ld c, l
    ld d, e
    jp Jump_015_56c0


    rst $20
    ld c, a
    or c
    call nz, $7f56
    inc l
    jp $bcde


    ldh [$c4], a
    ld d, l
    sbc l
    and l
    adc [hl]
    xor e
    ld h, $7f
    or c
    reti


    ret


    add $56
    rst $20
    ld d, a
    ld [$d721], sp
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    or h
    ld d, e
    rst $20
    ld c, a
    sra e
    cp h
    ld h, $7f
    or a
    db $d3
    pop bc
    or d
    db $e3
    ld l, $e7
    ld d, a

jr_015_6dbd:
    db $ed
    inc h
    inc hl
    ld d, h
    ld a, a
    rst $08
    cp c
    rst $20
    ld e, b
    db $ed
    inc h
    sub $53
    ld a, a
    call nc, $c0b9
    rst $20
    ld a, a
    rst $08
    rst $18
    cp b
    db $db
    jr nc, jr_015_6dbd

    ld d, a
    ld [$e321], sp
    ld l, e
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    dec a
    ld d, h
    push bc
    db $e3
    ld a, a
    or a
    ret nc

    rst $20
    ld c, a
    or e
    ret nc

    db $dd
    ld a, a
    or c
    rst $10
    cp e
    push bc
    or d
    inc sp
    ld a, a
    cp b
    jp c, $cfc0

    or h
    ld d, a
    db $ed
    inc h
    db $e4
    ld d, h
    rst $20
    ld c, a
    jp nz, $c5da

    or d
    ret


    inc sp
    ld a, a
    or a
    ld h, $7f
    ret nz

    rst $18
    jp Jump_015_58c0


    db $ed
    inc h
    ld l, a
    ld d, h
    push bc
    or c
    rst $20
    ld c, a
    rst $08
    cp e
    or [hl]
    ld a, a
    cp d
    cp d
    jp z, $b57f

    rst $18
    or a
    push bc
    ld d, l
    ld b, d
    db $e3
    and [hl]
    ld a, a
    jr nc, @-$1f

    ret nz

    ret c

    ld a, a
    cp h
    jp Jump_000_0857


    ld hl, $6bef
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    inc h
    inc c
    ld d, l
    ld h, $7f
    cp b
    reti


    rst $08
    inc sp
    ld c, a
    or l
    rst $08
    or h
    ret


    ld a, a
    or c
    or d
    jp $d333


    ld a, a
    cp h
    jp $b3d6


    ld d, a
    db $ed
    inc h
    and [hl]
    ld d, l
    inc a
    cp h
    add $7f
    push bc
    rst $18
    ret nz

    ld e, b
    db $ed
    inc h
    ccf
    ld d, l
    jp $7fe7


    or d
    rst $08
    ld a, a
    or c
    ret nz

    ret c

    ld h, $ac
    rst $20
    ld c, a
    or c
    ld d, [hl]
    rst $20
    ld a, a
    res 6, d
    jp $7fd9


    res 6, d
    jp $e7d9


    ld d, a
    ld [$0404], sp
    nop
    ld b, b
    sub e
    ld l, [hl]
    sub b
    ld l, [hl]
    nop
    rst $00
    ld l, a
    jp Jump_000_3c6c


    sub l
    ld l, [hl]
    ld [$a7fa], sp
    sub $cb
    ld e, a
    jr nz, jr_015_6ec8

    ld hl, $6ed1
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_015_6ec3

    ld bc, $4c01
    call Call_000_3e5e
    jr nc, jr_015_6ebe

    ld hl, $d6a7
    set 3, [hl]
    ld hl, $6f02
    jr jr_015_6ecb

jr_015_6ebe:
    ld hl, $6fa3
    jr jr_015_6ecb

jr_015_6ec3:
    ld hl, $6f80
    jr jr_015_6ecb

jr_015_6ec8:
    ld hl, $6f8d

jr_015_6ecb:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld h, l
    ld h, l
    ld a, a
    jp nz, $b5d8

    call nc, $7f2c
    inc l
    ldh [$e7], a
    ld d, c
    db $d3
    or e
    ld a, a
    cp h
    rst $00
    adc $34
    ld c, a
    jp nz, Jump_000_26d8

    ld a, a
    cp l
    or a
    ld a, a
    push bc
    sbc $30
    ld h, $51
    or a
    ret nc

    jp z, $c27f

    ret c

    ld a, a
    cp l
    or a

jr_015_6efd:
    ld a, a
    or [hl]
    push bc
    and $57
    db $ed
    ld a, [hl+]
    adc $65
    rst $20
    ld c, a
    or a
    ret nc

    call nz, $7fca
    or a
    ld h, $7f
    or c
    or d
    cp a
    or e
    jr nc, jr_015_6efd

    ld d, c
    cp d
    jp c, $b17f

    add hl, hl
    reti


    or [hl]
    rst $10
    ld c, a
    or a
    ret nc

    db $d3
    ld a, a
    jp nz, Jump_015_7fd8

    rst $08
    cp b
    ret c

    push bc
    cp e
    or d
    sub $e7
    ld d, c
    ld d, d
    jp z, $c27f

    ret c

    or l
    call nc, $b62c
    rst $10
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    db $d3

jr_015_6f43:
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    dec bc
    nop
    ld d, c
    jp nz, Jump_015_7fd8

    cp d
    cp a
    ld c, a
    or l
    call nz, $c9ba
    ld a, a
    xor b
    sbc l
    xor e
    ld a, a
    jr nc, jr_015_6f43

    ld d, c
    or e
    ret nc

    inc sp
    db $d3
    ld a, a
    or [hl]
    call c, $d333
    rst $20
    ld d, c
    or h
    sbc $d8
    ld [c], a
    ld a, a
    push bc
    cp b
    ld c, a
    jp nz, $2bd8

    or l
    db $dd
    ld a, a
    jp nz, $dfb6

    jp $b87f


    jp c, $e7b2

    ld d, a
    db $ed
    ld a, [hl+]
    ld b, b
    ld h, a
    ldh [rRP], a
    ld a, a
    ld h, $df
    or [hl]
    ret c

    jr nc, jr_015_6fe4

    db $ed
    ld a, [hl+]
    ld h, b
    ld h, a
    ld d, d
    cp b
    sbc $e7
    ld d, c
    jp nz, Jump_015_7fd8

    rst $08
    cp b
    rst $18
    call nz, $7fd9
    or [hl]
    ret z

    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    db $e3
    ld h, [hl]
    db $e3
    rst $20
    ld d, c
    or d
    or d
    db $d3
    ret


    ld a, a
    or c
    add hl, hl
    sub $b3
    call nz, $bc7f
    ret nz

    ret


    add $4f
    add $d3
    jp nz, Jump_015_7f26

    or d
    rst $18
    ld b, h
    or d
    inc l
    ldh [$e7], a
    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [$07ff], sp
    inc bc
    ld [$00ff], sp
    ld bc, $0827
    ld b, $ff
    db $d3
    ld bc, $c712
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [de], a
    inc b
    ld a, [bc]

jr_015_6fe4:
    and h
    ld [hl], b
    ldh a, [$6f]
    db $ed
    ld l, a
    nop
    ld l, l
    ld [hl], b
    jp Jump_000_3c6c


    ld a, [bc]
    rrca
    ld d, $0f
    ld a, [$326f]
    ld [hl], b
    ld d, e
    ld [hl], b
    db $ed
    dec l
    dec h
    ld b, l
    db $e3
    adc h
    ld b, d
    and a
    db $e3
    jp z, $d67f

    call c, $4fb2
    ld d, h
    ld h, $7f
    call nz, $333b
    jp $ba7f


    push bc
    cp b
    push bc
    reti


    ld d, c
    adc $b3
    rst $20
    ld a, a
    pop de
    cp h
    sub $b9
    adc h
    ld b, d
    and a
    db $e3
    ret


    ld c, a
    or a
    ld [c], a
    or e
    ret c

    ld [c], a
    cp b
    push bc
    ld a, a
    call nc, $30c2
    push bc
    ld d, a
    db $ed
    dec l
    xor h
    ld b, h
    ld a, a
    cp l
    reti


    push bc
    rst $10
    ld c, a
    add hl, hl
    sbc $b7
    ret


    or [hl]
    cp c
    rst $10
    jp z, $b655

    rst $18
    call nz, $c0b2
    ld a, a
    adc $b3
    ld h, $7f
    or d
    or d
    call c, $ed57
    dec l
    ld l, [hl]
    ld b, h
    inc c
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    rst $20
    ld c, a
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
    ld d, a
    rrca
    inc bc
    ld bc, $040c
    ld a, d
    ld bc, $0110
    ld a, h
    ld bc, $0001
    ld a, a
    ld bc, $0e01
    dec b
    inc b
    ld h, $07
    add hl, bc
    rst $38
    ret nc

    ld bc, $0726
    ld a, [bc]
    rst $38
    ret nc

    ld [bc], a
    ld a, [bc]
    add hl, bc
    rla
    rst $38
    rst $38
    inc bc
    dec c
    ld [$fe12], sp
    ld bc, $ff04
    add $01
    inc c
    ld bc, $01c7
    db $10
    ld sp, hl
    add $01
    ld bc, $0d0c
    jr @+$1b

    ld bc, $0301
    dec h
    ld [bc], a
    ld bc, $0b0b
    inc d
    rla
    dec bc
    ld a, [de]
    ld a, [de]
    dec bc
    ld a, [de]
    ld a, [de]
    dec bc
    dec bc
    dec d
    ld d, $0b
    ld e, $1e
    dec bc
    ld e, $1e
    dec bc
    dec bc
    dec bc
    dec bc
    dec bc
    ld a, [bc]
    ld a, [bc]
    dec bc
    ld a, [bc]
    ld a, [bc]
    dec c
    inc b
    inc b
    db $10
    ld b, b
    db $db
    ld [hl], b
    ret c

    ld [hl], b
    nop
    daa
    ld [hl], d
    jp Jump_000_3c6c


    db $dd
    ld [hl], b
    ld [$a7fa], sp
    sub $cb
    ld h, a
    jr nz, jr_015_7110

    ld hl, $7119
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_015_710b

    ld bc, $4d01
    call Call_000_3e5e
    jr nc, jr_015_7106

    ld hl, $d6a7
    set 4, [hl]
    ld hl, $714e
    jr jr_015_7113

jr_015_7106:
    ld hl, $7203
    jr jr_015_7113

jr_015_710b:
    ld hl, $71e0
    jr jr_015_7113

jr_015_7110:
    ld hl, $71ed

jr_015_7113:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld [hl], a
    ld h, a
    ld a, a
    jp nz, $b5d8

    call nc, $c92c
    ld a, a
    or c
    add $7f
    inc l
    ldh [$e7], a
    ld d, c
    db $d3
    or e
    ld a, a
    cp h
    rst $00
    adc $34
    ld c, a
    jp nz, Jump_000_26d8

    ld a, a
    cp l
    or a
    ld a, a
    push bc
    sbc $30
    ld h, $51
    or a
    ret nc

    jp z, $c27f

    ret c

    ld a, a
    cp l
    or a

jr_015_7149:
    ld a, a
    or [hl]
    push bc
    and $57
    db $ed
    ld a, [hl+]
    call $e767
    ld c, a
    or a
    ret nc

    call nz, $7fca
    or a
    ld h, $7f
    or c
    or d
    cp a
    or e
    jr nc, jr_015_7149

    ld d, c
    cp d
    jp c, $b17f

    add hl, hl
    reti


    or [hl]
    rst $10
    ld c, a
    or a
    ret nc

    db $d3
    ld a, a
    jp nz, Jump_015_7fd8

    rst $08
    cp b
    ret c

    push bc
    cp e
    or d
    sub $e7
    ld d, c
    ld d, d
    jp z, $c27f

    ret c

    or l
    call nc, $b62c
    rst $10
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    db $d3

jr_015_718f:
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    dec bc
    ld d, b
    ld d, c
    jp nz, Jump_015_7fd8

    cp d
    cp a
    ld c, a
    or l
    call nz, $c9ba
    ld a, a
    xor b
    sbc l
    xor e
    ld a, a
    jr nc, jr_015_718f

    ld d, c
    call $b23e
    jp nz, $2bd8

    or l
    jp z, $894f

    add c
    add [hl]
    xor e
    rlca
    cp h
    or [hl]
    ld a, a
    jp nz, Jump_015_7fda

    push bc
    sbc $30
    ld h, $4f
    cp d
    ret


    ld a, a
    or d
    or d
    jp nz, $2bd8

    or l
    push bc
    rst $10
    ld c, a
    db $d3
    rst $18
    call nz, $b27f
    or d
    db $d3
    sbc $26
    ld a, a
    jp nz, $d9da

    sbc $2c
    ldh [$e7], a
    ld d, a
    db $ed
    ld a, [hl+]
    or b
    ld l, b
    ldh [rRP], a
    ld a, a
    ld h, $df
    or [hl]
    ret c

    jr nc, jr_015_7244

    db $ed
    ld a, [hl+]
    ret nc

    ld l, b
    ld d, d
    cp b
    sbc $e7
    ld d, c
    jp nz, Jump_015_7fd8

    rst $08
    cp b
    rst $18
    call nz, $7fd9
    or [hl]
    ret z

    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    ld d, e
    ld l, b
    db $e3
    rst $20
    ld d, c
    or d
    or d
    db $d3
    ret


    ld a, a
    or c
    add hl, hl
    sub $b3
    call nz, $bc7f
    ret nz

    ret


    add $4f
    add $d3
    jp nz, Jump_015_7f26

    or d
    rst $18
    ld b, h
    or d
    inc l
    ldh [$e7], a
    ld d, a
    inc c
    inc bc
    nop
    ld [bc], a
    ld [$07ff], sp
    ld [bc], a
    rlca
    rst $38
    rlca
    inc bc
    rlca
    rst $38
    nop
    ld bc, $0727
    add hl, bc
    rst $38
    db $d3
    ld bc, $c6f4
    nop
    ld [bc], a
    ld [de], a
    rst $00
    rlca

jr_015_7244:
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    nop
    ld b, b
    ld e, b
    ld [hl], d
    ld d, l
    ld [hl], d
    nop
    and l
    ld [hl], l
    jp Jump_000_3c6c


    ld e, d
    ld [hl], d
    ld [$3ecd], sp
    scf
    ld a, [$d984]
    and a
    jr nz, jr_015_72e3

    ld hl, $7411
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    ld hl, $752a
    jp nz, Jump_015_740b

    ld a, [$d123]
    dec a
    ld hl, $754e
    jp z, Jump_015_740b

    ld hl, $742d
    call Call_000_3c79
    xor a
    ld [$cfb2], a
    ld [$d05a], a
    call Call_000_2df3
    push af
    call Call_000_3e04
    call Call_000_3dee
    call Call_000_0b3c
    pop af
    ld hl, $751f
    jp c, Jump_015_740b

    ld hl, $4322
    ld b, $08
    call Call_000_3620
    ld hl, $7564
    jp c, Jump_015_740b

    xor a
    ld [$cc2b], a
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    ld hl, $7442
    call Call_000_3c79
    ld a, $01
    ld [$d984], a
    ld a, $03
    ld [$cf7c], a
    call Call_000_3ab2
    xor a
    ld [$cf7c], a
    call Call_000_3969
    ld a, [$cf78]
    call Call_000_2dc7
    ld hl, $7459
    jp Jump_015_740b


jr_015_72e3:
    xor a
    ld hl, $d985
    call Call_000_2fb1
    ld a, $03
    ld [$cc49], a
    call Call_000_2d68
    ld hl, $4f8e
    ld b, $16
    call Call_000_3620
    ld a, d
    cp $64
    jr c, jr_015_7317

    ld d, $64
    ld hl, $4fb5
    ld b, $16
    call Call_000_3620
    ld hl, $d99f
    ldh a, [$96]
    ld [hl+], a
    ldh a, [$97]
    ld [hl+], a
    ldh a, [$98]
    ld [hl], a
    ld d, $64

jr_015_7317:
    xor a
    ld [$cd3e], a
    ld hl, $d994
    ld a, [hl]
    ld [$cd3d], a
    cp d
    ld [hl], d
    ld hl, $74f8
    jr z, jr_015_7335

    ld a, [$cd3d]
    ld b, a
    ld a, d
    sub b
    ld [$cd3e], a
    ld hl, $7472

jr_015_7335:
    call Call_000_3c79
    ld a, [$d123]
    cp $06
    ld hl, $7534
    jp z, Jump_015_7405

    ld de, $cd3f
    xor a
    ld [de], a
    inc de
    ld [de], a
    ld hl, $cd41
    ld a, $01
    ld [hl+], a
    ld [hl], $00
    ld a, [$cd3e]
    inc a
    ld b, a
    ld c, $02

jr_015_7359:
    push hl
    push de
    push bc
    ld a, $0b
    call Call_000_3e9d
    pop bc
    pop de
    pop hl
    dec b
    jr nz, jr_015_7359

    ld hl, $74bd
    call Call_000_3c79
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    call Call_000_3636
    ld hl, $751f
    ld a, [$cc26]
    and a
    jp nz, Jump_015_7405

    ld hl, $cd3f
    ldh [$9f], a
    ld a, [hl+]
    ldh [$a0], a
    ld a, [hl]
    ldh [$a1], a
    call Call_000_35f0
    jr nc, jr_015_7398

    ld hl, $759b
    jp Jump_015_7405


jr_015_7398:
    xor a
    ld [$d984], a
    ld hl, $cd3e
    ld [hl+], a
    inc hl
    ld de, $d2cd
    ld c, $03
    ld a, $0c
    call Call_000_3e9d
    ld a, $b2
    call Call_000_3788
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $7583
    call Call_000_3c79
    ld a, $02
    ld [$cf7c], a
    call Call_000_3ab2
    ld a, [$d991]
    ld [$cf78], a
    ld a, [$d123]
    dec a
    push af
    ld bc, $002c
    push bc
    ld hl, $d133
    call Call_000_3ad1
    ld d, h
    ld e, l

jr_015_73dd:
    ld a, $01
    ld [$cee4], a
    ld a, $3e
    call Call_000_3e9d
    pop bc

jr_015_73e8:
    pop af
    ld hl, $d12c
    call Call_000_3ad1
    ld d, h
    ld e, l
    ld bc, $0021
    add hl, bc
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    ld a, [$cf78]

jr_015_73fd:
    call Call_000_2dc7
    ld hl, $74dd
    jr jr_015_740b

Jump_015_7405:
    ld a, [$cd3d]
    ld [$d994], a

Jump_015_740b:
jr_015_740b:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ei
    ld l, b
    jp z, $bf7f

    jr nc, jr_015_73dd

    call nc, $debb
    ld c, a
    push bc
    add $b6
    ld a, a
    cp a
    jr nc, jr_015_73e8

    jp $d07f


    reti


    or [hl]
    ret z

    and $57
    db $ed
    ld a, [hl+]
    ld l, $69
    jp z, $c54f

    add $dd
    ld a, a
    cp a
    jr nc, jr_015_73fd

    jp $d07f


    reti


    or [hl]
    ret z

    and $58
    db $ed
    ld a, [hl+]
    ld c, [hl]
    ld l, c
    ret nz

    ld c, a
    cp h
    ld a, [hl-]
    rst $10
    cp b
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    or c
    dec l
    or [hl]

jr_015_7456:
    db $db
    or e
    ld e, b
    db $ed
    dec l
    cp [hl]
    ld b, [hl]
    or e
    add $7f
    inc l
    or [hl]
    sbc $26
    ld a, a
    ret nz

    rst $18
    ret nz

    rst $10
    ld c, a
    rst $08
    ret nz

    ld a, a
    or a
    push bc
    cp e
    or d
    ld d, a
    db $ed
    ld a, [hl+]
    ld [hl], c
    ld l, c
    ret


    ld a, a
    ld d, b
    ld bc, $cd68
    nop
    ld c, a
    dec l
    or d
    inc a
    sbc $c4
    ld a, a
    cp [hl]
    or d
    pop bc

jr_015_7487:
    ld [c], a
    or e
    cp h
    ret nz

    cpl
    ld d, c
    cp a
    or e
    jr nc, jr_015_7456

    ld a, a
    and a
    dec a
    and [hl]
    inc sp
    ld a, a
    or d
    or e
    call nz, Call_015_504f
    add hl, bc
    ld a, $cd
    inc de
    nop
    cp b
    rst $10

jr_015_74a3:
    or d
    ld a, a
    cp a
    jr nc, jr_015_7487

    jp $c5d9


    ld d, c
    call nc, Call_015_44df
    ret c

    ld a, a
    call c, $bcc0
    jp z, $c37f

    sbc $bb
    or d
    jr nc, jr_015_74a3

    ld e, b
    db $ed
    ld a, [hl+]
    push de
    ld l, c
    ld d, h
    db $dd
    ld a, a
    res 6, a
    call nz, $c5d9
    rst $10
    ld c, a
    ret c

    ld [c], a
    or e
    or a
    sbc $ca
    ld a, a
    ld d, b
    ld [bc], a
    ccf
    call Call_000_00c2
    ldh a, [$7f]
    jr nc, @-$28

    ld d, a
    db $ed
    dec l
    ld c, b
    ld b, a
    cp a
    jr nc, @-$3b

    call nc, $debb
    or [hl]
    rst $10
    ld c, a
    ld d, b
    ld bc, $d985
    nop
    db $dd
    ld a, a
    res 6, a
    call nz, $c0df
    rst $20
    ld d, a
    db $ed
    dec l
    db $f4
    ld b, [hl]
    ld a, a
    db $d3
    or e
    ld a, a
    or a
    ret nz

    ret


    or [hl]
    ld c, a
    or l
    rst $08
    or h
    ret


    ld a, a
    ld d, b
    ld bc, $cd68
    nop
    jp z, $5156

jr_015_7512:
    rst $08
    jr nc, @+$81

    inc l
    or [hl]
    sbc $26
    ld a, a
    or [hl]
    or [hl]
    reti


    cpl
    ld e, b
    db $ed
    dec l
    ld c, a
    ld b, [hl]
    ld a, a
    cp a
    jp c, $e02c

jr_015_7528:
    ld c, a
    ld d, b
    db $ed
    dec l
    dec l
    ld b, a
    or a
    push bc
    cp e
    or d
    sub $57
    db $ed
    dec l
    ld [hl], l
    ld b, [hl]
    ld a, a
    jp nz, $c3da

    or d
    cp b
    add $ca
    ld c, a
    ld d, h
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    ret


    sub $b3
    jr nc, jr_015_7512

    ld d, a
    nop
    or l
    call nc, $7fe6
    ld d, h
    ld h, $4f
    rst $30
    ld b, l
    or a
    cp h
    or [hl]
    ld a, a
    or d
    push bc
    or d
    sub $b3
    jr nc, jr_015_7528

    ld d, a
    db $ed
    dec l
    inc c
    ld b, [hl]
    cp c
    inc [hl]
    ld a, a
    swap e
    sbc $c9
    call c, $dd2b
    ld a, a
    db $d3
    rst $18
    ret nz

    ld c, a
    ld d, h
    jp z, $b17f

    dec l
    or [hl]
    jp c, $b2c5

    push bc
    db $76
    ld d, a
    db $ed
    ld a, [hl+]
    rrca
    ld l, d
    ret nz

    cp h
    or [hl]
    add $e7
    ld c, a
    inc l
    ldh [$7f], a
    ld d, h
    ld a, a
    jp nz, $c3da

    ld a, a
    or d
    or a
    push bc
    sub $58
    nop
    or [hl]
    ret z

    ld h, $7f
    ret nz

    rst $10
    sbc $c5
    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    inc b
    rst $38
    rlca
    inc bc
    inc b
    rst $38
    nop
    ld bc, $0710
    ld b, $ff
    db $d3
    ld bc, $c712
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    nop
    ld b, b
    adc $75
    bit 6, l
    nop
    ld [hl-], a
    ld [hl], a
    jp Jump_000_3c6c


    ret nc

    ld [hl], l
    ld [$a7fa], sp
    sub $cb
    ld l, a
    jr nz, jr_015_7603

    ld hl, $760c
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_015_75fe

    ld bc, $4e01
    call Call_000_3e5e
    jr nc, jr_015_75f9

    ld hl, $d6a7
    set 5, [hl]
    ld hl, $7646
    jr jr_015_7606

jr_015_75f9:
    ld hl, $770e
    jr jr_015_7606

jr_015_75fe:
    ld hl, $76c4
    jr jr_015_7606

jr_015_7603:
    ld hl, $76d1

jr_015_7606:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld l, [hl]
    ld l, d
    ld c, a
    jp nz, $b5d8

    call nc, $c92c
    ld a, a
    or l
    call nz, $c4b3
    ld a, a
    inc l
    ldh [$e7], a
    ld d, c
    db $d3
    or e
    ld a, a
    ret nz

    rst $08
    rst $10
    sbc $7f
    adc $34
    ld c, a
    jp nz, Jump_000_26d8

    ld a, a
    cp l
    or a
    ld a, a
    push bc
    sbc $30
    ld h, $51
    or a
    ret nc

    jp z, $c27f

    ret c

    ld a, a
    cp l
    or a

jr_015_7641:
    ld a, a
    or [hl]
    push bc
    and $57
    db $ed
    dec l
    ld l, [hl]
    ld b, a
    rst $20
    ld c, a
    or a
    ret nc

    call nz, $7fca
    or a
    ld h, $7f
    or c
    or d
    cp a
    or e
    jr nc, jr_015_7641

    ld d, c
    cp d
    jp c, $b17f

    add hl, hl
    reti


    or [hl]
    rst $10
    ld c, a
    or a
    ret nc

    db $d3
    ld a, a
    jp nz, Jump_015_7fd8

    rst $08
    cp b
    ret c

    push bc
    cp e
    or d
    sub $e7
    ld d, c
    ld d, d
    jp z, $c27f

    ret c

    or l
    call nc, $b62c
    rst $10
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    db $d3

jr_015_7687:
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    dec bc
    nop
    ld d, c
    jp nz, Jump_015_7fd8

    cp d
    cp a
    ld c, a
    or l
    call nz, $c9ba
    ld a, a
    xor b
    sbc l
    xor e
    ld a, a
    jr nc, jr_015_7687

    ld d, c
    or e
    ret nc

    inc sp
    db $d3
    ld a, a
    or [hl]
    call c, $d333
    rst $20
    ld d, c
    or h
    sbc $d8
    ld [c], a
    ld a, a
    push bc
    cp b
    ld c, a
    jp nz, $2bd8

    or l
    db $dd
    ld a, a
    jp nz, $dfb6

    jp $b87f


    jp c, $e7b2

    ld d, a
    db $ed
    dec l
    dec d
    ld c, c
    ldh [rRP], a
    ld a, a
    ld h, $df
    or [hl]
    ret c

    jr nc, @+$59

    db $ed
    ld a, [hl+]
    ld a, c
    ld l, h
    ld d, d
    cp b
    sbc $e7
    ld d, c
    cp l
    ld a, [hl+]
    or d
    jp nz, $2bd8

    or l
    jp z, Jump_000_3a4f

    cp h
    ld [c], a
    db $dd
    ld a, a
    or [hl]
    or h
    reti


    call nz, $c255
    jp c, $7fd9

    ld d, h
    db $d3
    ld a, a
    or [hl]
    call c, $e7d9
    ld d, c
    or c
    rst $18
    pop bc
    cp d
    rst $18
    pop bc
    inc sp
    ld c, a
    jp nz, Jump_015_7fd8

    rst $08
    cp b
    rst $18
    jp $b87f


    jp c, $e7b2

    ld d, a
    db $ed
    dec l
    jp nz, $e348

    rst $20
    ld d, c
    or d
    or d
    db $d3
    ret


    ld a, a
    or c
    add hl, hl
    sub $b3
    call nz, $bc7f
    ret nz

    ret


    add $4f
    add $d3
    jp nz, Jump_015_7f26

    or d
    rst $18
    ld b, h
    or d
    inc l
    ldh [$e7], a
    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    inc bc
    rst $38
    rlca
    inc bc
    inc bc
    rst $38
    nop
    ld bc, $0827
    ld b, $ff
    db $d3
    ld bc, $c712
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld d, $09
    dec c
    ld h, c
    ld a, c
    pop de
    ld [hl], a
    ld e, b
    ld [hl], a
    nop
    rlca
    ld a, c
    call Call_015_776e
    call Call_000_3c6c
    ld hl, $77d9
    ld de, $77cb
    ld a, [$d5c8]
    call Call_000_31a8
    ld [$d5c8], a
    ret


Call_015_776e:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld hl, $7792
    call Call_015_7795
    call Call_015_77c1
    ld a, [$d7b1]
    bit 0, a
    ret nz

    ld a, $5f
    ld [$d07c], a
    ld bc, $0403
    ld a, $17
    jp Jump_000_3e9d


    inc b
    inc bc
    rst $38

Call_015_7795:
    push hl
    ld hl, $d6be
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    ld c, a
    xor a
    ldh [$e0], a
    pop hl

jr_015_77a1:
    ld a, [hl+]
    cp $ff
    jr z, jr_015_77bd

    push hl
    ld hl, $ffe0
    inc [hl]
    pop hl
    cp b
    jr z, jr_015_77b2

    inc hl
    jr jr_015_77a1

jr_015_77b2:
    ld a, [hl+]
    cp c
    jr nz, jr_015_77a1

    ld hl, $d6be
    xor a
    ld [hl+], a
    ld [hl], a
    ret


jr_015_77bd:
    xor a
    ldh [$e0], a
    ret


Call_015_77c1:
    ldh a, [$e0]
    and a
    ret z

    ld hl, $d7b1
    set 0, [hl]
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    cp $77
    dec [hl]
    ld a, b
    ld [hl], a
    ld a, b
    ret nz

    ld a, b
    ld [bc], a
    ld b, b
    or b
    rst $10
    ccf
    ld a, b
    ld e, l
    ld a, b
    ld d, d
    ld a, b
    ld d, d
    ld a, b
    inc bc
    ld b, b
    or b
    rst $10
    add c
    ld a, b
    and c
    ld a, b
    sub a
    ld a, b
    sub a
    ld a, b
    inc b
    ld b, b
    or b
    rst $10
    jp z, $ee78

    ld a, b
    db $e3
    ld a, b
    db $e3
    ld a, b
    rst $38
    ld [$b7fa], sp
    rst $10
    bit 7, a
    ld hl, $7827
    jr nz, jr_015_780c

    ld hl, $7812

jr_015_780c:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    dec b
    ld l, l
    jp z, $c97f

    rst $18
    call nz, $dad7
    jp $564f


    ld a, a
    or l
    call c, $b6d8
    push bc
    ld d, a
    db $ed
    ld a, [hl+]
    push hl
    ld l, h
    call nz, Call_015_7fb3
    ret nz

    cp l
    or [hl]
    rst $18
    ret nz

    rst $20
    ld d, a
    ld [$d921], sp
    ld [hl], a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    call $d774
    ld a, a
    cp e
    or a
    jp z, $b27f

    or [hl]
    cp [hl]
    ld a, a
    push bc
    or d
    ld l, $e7
    ld d, a
    db $ed
    daa
    ld d, c
    ld [hl], l
    ld h, $7f
    ret nz

    ret c

    sbc $b6
    ld e, b
    db $ed
    daa
    jp hl


    ld [hl], h
    ld a, a
    res 6, a
    or [hl]
    or h
    cp e
    push bc
    or d
    call nz, $564f
    ld a, a
    push bc
    or [hl]
    rst $08
    db $dd
    ld a, a
    sub $3c
    ld l, $e7
    ld d, a
    ld [$e521], sp
    ld [hl], a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld a, e
    ld [hl], l
    or [hl]
    rst $18
    jp $d47f


    rst $10
    jp c, $e0c1

jr_015_788e:
    ld c, a
    cp d
    rst $08
    reti


    sbc $30
    ld l, $e7
    ld d, a
    db $ed
    daa
    db $10
    db $76
    rst $08
    cp c
    ret nz

    ret


    or [hl]
    ld e, b
    db $ed
    daa
    cp [hl]
    ld [hl], l
    ret z

    and $4f
    jp nc, $dbb2

    ret


    ld a, a
    sub $b3
    push bc
    ld d, l
    adc e
    and [hl]
    sbc e
    ld a, a
    ld a, [de]
    and [hl]
    ret


    ld a, a
    or [hl]
    sbc $bf
    or e
    jp z, Jump_015_57e6

    ld [$f121], sp
    ld [hl], a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    inc e
    db $76
    cp a
    jp z, $a84f

    adc b
    xor h
    sub e
    ld a, a
    ld a, [$e2b7]
    or e
    jr nc, jr_015_788e

    ret


    ld a, a
    set 0, h
    ret c

    rst $20
    ld d, a
    db $ed
    daa
    sub h
    db $76
    sbc $7f
    rst $08
    cp c
    ret nz

    sub $58
    db $ed
    daa
    ld c, h
    db $76
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

    ld l, $07
    nop
    db $10
    ld bc, $00e9
    ld c, $00
    call nc, $1200
    nop
    db $ec
    dec bc
    inc bc
    ld b, $d5
    rrca
    inc bc
    inc b
    rst $08
    dec b
    dec bc
    dec b
    rst $08
    add hl, bc
    dec bc
    inc bc
    push de
    nop
    inc b
    inc l
    ld b, $08
    rst $38
    rst $38
    ld bc, $0618
    rla
    rst $38
    jp nc, $e642

    inc hl
    jr nz, jr_015_793d

    ld c, $ff
    ret nc

    ld b, e
    db $e4
    add hl, bc

jr_015_793d:
    jr jr_015_7952

    db $10
    rst $38
    db $d3
    ld b, h
    and $24
    inc b
    rst $00
    nop
    db $10
    inc bc
    rst $00
    nop
    ld c, $05
    rst $00
    nop
    ld [de], a
    ld e, h

jr_015_7952:
    rst $00
    dec bc
    inc bc
    add d
    rst $00
    rrca
    inc bc
    daa
    rst $00
    dec b
    dec bc
    ld c, l
    rst $00
    add hl, bc
    dec bc
    ld b, b
    ld b, c
    ld b, c
    ld b, d
    ld h, c
    ld h, c
    ld h, d
    inc h
    ld a, l
    ld a, h
    dec a
    dec a
    ld a, $44
    inc [hl]
    inc [hl]
    ld b, [hl]
    ld c, $0e
    ld h, [hl]
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld b, h
    ld [hl], $36
    ld b, [hl]
    ld c, $2f
    ld b, [hl]
    ld c, $40
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld b, h
    ld [hl], $36
    ld d, [hl]
    ld c, $57
    ld d, c
    ld c, $44
    ld b, e
    ld b, e
    add hl, bc
    ld b, [hl]
    ld b, h
    scf
    ld [hl], $0e
    ld c, $2f
    ld b, [hl]
    ld c, $44
    ld c, $0e
    ld c, $46
    ld b, h
    cpl
    scf
    ld e, d
    ld c, $47
    ld b, [hl]
    ld c, $44
    ld b, a
    ld c, $09
    ld b, [hl]
    ld d, b
    ld c, c
    ld c, c
    ld c, d
    ld c, $57
    ld c, d
    ld c, $48
    ld e, b
    ld c, $57
    ld d, c
    ld [de], a
    cpl
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
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
    ld c, d
    ld a, [$d0f0]
    cp $04
    ret z

    call Call_015_7bf3
    ld hl, $d12b
    xor a
    ld [$cf79], a

Jump_015_79e6:
    inc hl
    ld a, [hl+]
    or [hl]
    jp z, Jump_015_7bbd

    push hl
    ld hl, $d035
    ld a, [$cf79]
    ld c, a
    ld b, $02
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    pop hl
    jp z, Jump_015_7bbd

    ld de, $0010
    add hl, de
    ld d, h
    ld e, l
    ld hl, $cfe9
    ld c, $05

jr_015_7a0c:
    ld a, [hl+]
    ld b, a
    ld a, [de]
    add b
    ld [de], a
    jr nc, jr_015_7a21

    dec de
    ld a, [de]
    inc a
    jr z, jr_015_7a1c

    ld [de], a
    inc de
    jr jr_015_7a21

jr_015_7a1c:
    ld a, $ff
    ld [de], a
    inc de
    ld [de], a

jr_015_7a21:
    dec c
    jr z, jr_015_7a28

    inc de
    inc de
    jr jr_015_7a0c

jr_015_7a28:
    xor a
    ldh [$96], a
    ldh [$97], a
    ld a, [$cfef]
    ldh [$98], a
    ld a, [$cfda]
    ldh [$99], a
    call Call_000_38f5
    ld a, $07
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ld hl, $fff2
    add hl, de
    ld b, [hl]
    inc hl
    ld a, [$d2d8]
    cp b
    jr nz, jr_015_7a58

    ld b, [hl]
    ld a, [$d2d9]
    cp b
    ld a, $00
    jr z, jr_015_7a5d

jr_015_7a58:
    call Call_015_7c26
    ld a, $01

jr_015_7a5d:
    ld [$cf47], a
    ld a, [$d034]
    dec a
    call nz, Call_015_7c26
    inc hl
    inc hl
    inc hl
    ld b, [hl]
    ldh a, [$98]
    ld [$cf46], a
    add b
    ld [hl-], a
    ld b, [hl]
    ldh a, [$97]
    ld [$cf45], a
    adc b
    ld [hl], a
    jr nc, jr_015_7a7f

    dec hl
    inc [hl]
    inc hl

jr_015_7a7f:
    inc hl
    push hl
    ld a, [$cf79]
    ld c, a
    ld b, $00
    ld hl, $d124
    add hl, bc
    ld a, [hl]
    ld [$d092], a
    call Call_000_2f2e
    ld d, $64
    ld hl, $4fb5
    ld b, $16
    call Call_000_3620
    ldh a, [$96]
    ld b, a
    ldh a, [$97]
    ld c, a
    ldh a, [$98]
    ld d, a
    pop hl
    ld a, [hl-]
    sub d
    ld a, [hl-]
    sbc c
    ld a, [hl]
    sbc b
    jr c, jr_015_7ab5

    ld a, b
    ld [hl+], a
    ld a, c
    ld [hl+], a
    ld a, d
    ld [hl-], a
    dec hl

jr_015_7ab5:
    push hl
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    ld hl, $7c39
    call Call_000_3c79
    xor a
    ld [$cc49], a
    call Call_000_2d68
    pop hl
    ld bc, $0013
    add hl, bc
    push hl
    ld b, $16
    ld hl, $4f8e
    call Call_000_3620
    pop hl
    ld a, [hl]
    cp d
    jp z, Jump_015_7bbd

    ld a, [$d0ec]
    push af
    push hl
    ld a, d
    ld [$d0ec], a
    ld [hl], a
    ld bc, $ffdf
    add hl, bc
    ld a, [hl]
    ld [$d092], a
    ld [$d0e3], a
    call Call_000_2f2e
    ld bc, $0023
    add hl, bc
    push hl
    ld a, [hl-]
    ld c, a
    ld b, [hl]
    push bc
    ld d, h
    ld e, l
    ld bc, $ffee
    add hl, bc
    ld b, $01
    call Call_000_3980
    pop bc
    pop hl
    ld a, [hl-]
    sub c
    ld c, a
    ld a, [hl]
    sbc b
    ld b, a
    ld de, $ffe0
    add hl, de
    ld a, [hl]
    add c
    ld [hl-], a
    ld a, [hl]
    adc b
    ld [hl], a
    ld a, [$cc2f]
    ld b, a
    ld a, [$cf79]
    cp b
    jr nz, jr_015_7b7e

    ld de, $cffc
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    ld bc, $001f
    add hl, bc
    push hl
    ld de, $d009
    ld bc, $000b
    call Call_000_01bb
    pop hl
    ld a, [$d041]
    bit 3, a
    jr nz, jr_015_7b4f

    ld de, $cd0f
    ld bc, $000b
    call Call_000_01bb

jr_015_7b4f:
    xor a
    ld [$d0e3], a
    ld hl, $708a
    ld b, $0f
    call Call_000_3620
    ld hl, $700b
    ld b, $0f
    call Call_000_3620
    ld hl, $710a
    ld b, $0f
    call Call_000_3620
    ld hl, $4ebe
    ld b, $0f
    call Call_000_3620
    ld hl, $7186
    ld b, $0f
    call Call_000_3620
    call Call_000_3761

jr_015_7b7e:
    ld hl, $7c82
    call Call_000_3c79
    xor a
    ld [$cc49], a
    call Call_000_2d68
    ld d, $01
    ld hl, $782c
    ld b, $04
    call Call_000_3620
    call Call_000_38ae
    call Call_000_376d
    xor a
    ld [$cc49], a
    ld a, [$d092]
    ld [$d0e3], a
    ld a, $1a
    call Call_000_3e9d
    ld hl, $ccd3
    ld a, [$cf79]
    ld c, a
    ld b, $01
    ld a, $10
    call Call_000_3e9d
    pop hl
    pop af
    ld [$d0ec], a

Jump_015_7bbd:
    ld a, [$d123]
    ld b, a
    ld a, [$cf79]
    inc a
    cp b
    jr z, jr_015_7bd7

    ld [$cf79], a
    ld bc, $002c
    ld hl, $d12b
    call Call_000_3ad1
    jp Jump_015_79e6


jr_015_7bd7:
    ld hl, $d035
    xor a
    ld [hl], a
    ld a, [$cc2f]
    ld c, a
    ld b, $01
    push bc
    ld a, $10
    call Call_000_3e9d
    ld hl, $ccf5
    xor a
    ld [hl], a
    pop bc
    ld a, $10
    jp Jump_000_3e9d


Call_015_7bf3:
    ld a, [$d035]
    ld b, a
    xor a
    ld c, $08
    ld d, $00

jr_015_7bfc:
    xor a
    srl b
    adc d
    ld d, a
    dec c
    jr nz, jr_015_7bfc

    cp $02
    ret c

    ld [$d0e3], a
    ld hl, $cfe9
    ld c, $07

jr_015_7c0f:
    xor a
    ldh [$95], a
    ld a, [hl]
    ldh [$96], a
    ld a, [$d0e3]
    ldh [$99], a
    ld b, $02
    call Call_000_3902
    ldh a, [$98]
    ld [hl+], a
    dec c
    jr nz, jr_015_7c0f

    ret


Call_015_7c26:
    ldh a, [$97]
    ld b, a
    ldh a, [$98]
    ld c, a
    srl b
    rr c
    add c
    ldh [$98], a
    ldh a, [$97]
    adc b
    ldh [$97], a
    ret


    ld bc, $cd68
    nop
    ld a, a
    ld d, b
    ld [$5bfa], sp
    call z, Call_015_5421
    ld a, h
    and a
    ret nz

    ld hl, $7c6c
    ld a, [$cf47]
    and a
    ret z

    ld hl, $7c65
    ret


    db $ed
    dec l
    db $fd
    ld b, e
    cp h
    pop hl
    or e
    cp a
    or e
    pop bc
    inc sp
    ld d, b
    ld [$6c21], sp
    ld a, h
    ret


    db $ed
    dec l
    inc a
    ld b, h
    jp nc, Jump_015_50c6

    db $ed
    dec l
    inc d
    ld b, h
    ld b, l
    rst $08
    inc h
    nop
    ld a, a
    cp c
    or d
    cp c
    sbc $c1
    db $dd
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    ld sp, $ca6d
    ld c, a
    and a
    dec a
    and [hl]
    ld d, b
    add hl, bc
    db $ec
    ret nc

    inc de
    nop
    ld a, a
    add $7f
    or c
    ld h, $df
    ret nz

    rst $20
    ld d, b
    dec bc
    ld d, b
    call Call_000_373e
    call Call_000_3e04
    call Call_000_03bf
    xor a
    ld [$cfb2], a
    ld hl, $d6af
    set 6, [hl]
    call Call_000_0167
    ld hl, $7de6
    ld de, $9700
    ld bc, $0010
    ld a, $0b
    call Call_000_028c
    ld hl, $c3a0
    ld bc, $1012
    ld a, $27
    call Call_000_3e9d
    ld hl, $7d42
    ld c, $05

jr_015_7ccf:
    push bc
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    push hl
    ld h, [hl]
    ld l, a
    call Call_000_0405
    pop hl
    inc hl
    pop bc
    dec c
    jr nz, jr_015_7ccf

    call Call_015_7d35
    ld hl, $c3fe
    add hl, bc
    ld de, $d11d
    call Call_000_0405
    ld b, $01
    ld hl, $4921
    call Call_000_3620
    ld hl, $c301
    ld bc, $8028

jr_015_7cfc:
    ld a, [hl]
    add $4b
    ld [hl+], a
    inc hl
    ld a, b
    ld [hl+], a
    inc hl
    dec c
    jr nz, jr_015_7cfc

    call Call_000_0181
    ld b, $01
    ld hl, $5912
    call Call_000_3620
    ld b, $08
    call Call_000_3e1f
    call Call_000_3e07
    call Call_000_3e0c
    ld a, $90
    ldh [rOBP0], a
    call Call_000_38ae
    ld hl, $d6af
    res 6, [hl]
    call Call_000_3e04
    call Call_000_3dee
    call Call_000_3e07
    jp Jump_000_3e0c


Call_015_7d35:
    ld hl, $d11d
    ld bc, $ff00

jr_015_7d3b:
    ld a, [hl+]
    cp $50
    ret z

    dec c
    jr jr_015_7d3b

    ld d, [hl]
    ld a, l
    adc $c3
    ld e, a
    ld a, l
    di
    jp Jump_015_7d65


    rst $38
    jp Jump_015_7d68


    ld l, $c4
    sbc e
    ld a, l
    rst $10
    call nz, $bc70
    ld [c], a
    or e
    inc l
    ld [c], a
    or e
    ld [hl], b
    ld d, b
    ld b, d
    and a
    db $e3
    and d
    db $e3
    ld d, b

Jump_015_7d65:
    cp e
    rst $08
    ld d, b

Jump_015_7d68:
    or c
    push bc
    ret nz

    jp z, Jump_015_547f

    dec l
    or [hl]
    sbc $dd
    ld c, [hl]
    ret nc

    ld a, [hl+]
    call nz, $b67f
    sbc $be
    or d
    ld a, a
    cp e
    cp [hl]
    rst $08
    cp h
    ret nz

    rst $20
    ld c, [hl]
    cp a
    ret


    ld a, a
    or d
    jr nc, jr_015_7d3b

    push bc
    ld a, a
    cp d
    or e
    cp [hl]
    or a
    db $dd
    ld c, [hl]
    cp h
    ld [c], a
    or e
    jp nc, Jump_015_7fb2

    cp h
    rst $08
    cp l
    ld d, b
    ld [$9fe3], sp
    sbc e
    ret c

    db $e3
    add a
    ld d, b
    ld hl, $c100
    ld de, $0004
    ld a, [$cf0e]
    ldh [$8c], a
    call Call_015_7ead
    ld a, [hl+]
    ldh [$eb], a
    inc hl
    ld a, [hl]
    ldh [$ec], a
    ld de, $00fe
    add hl, de
    ld a, [hl+]
    ldh [$ed], a
    ld a, [hl]
    ldh [$ee], a
    ret


    ld hl, $c100
    ld de, $0004
    ld a, [$cf0e]
    ldh [$8c], a
    call Call_015_7ead
    ld a, [hl+]
    ld [$d0f5], a
    inc hl
    ld a, [hl]
    ld [$d0f6], a
    ld de, $00fe
    add hl, de
    ld a, [hl+]
    ld [$d0f7], a
    ld a, [hl]
    ld [$d0f8], a
    ret


    ld hl, $c100
    ld de, $0004
    ld a, [$cf0e]
    ldh [$8c], a
    call Call_015_7ead
    ldh a, [$eb]
    ld [hl+], a
    inc hl
    ldh a, [$ec]
    ld [hl], a
    ld de, $00fe
    add hl, de
    ldh a, [$ed]
    ld [hl+], a
    ldh a, [$ee]
    ld [hl], a
    ret


    ld hl, $c100
    ld de, $0004
    ld a, [$cf0e]
    ldh [$8c], a
    call Call_015_7ead
    ld a, [$d0f5]
    ld [hl+], a
    inc hl
    ld a, [$d0f6]
    ld [hl], a
    ld de, $00fe
    add hl, de
    ld a, [$d0f7]
    ld [hl+], a
    ld a, [$d0f8]
    ld [hl], a
    ret


    ld a, [$cf0e]
    swap a
    ld [$cd3d], a
    call Call_015_7f38
    ld a, [$cd3f]
    and a
    jr z, jr_015_7e46

    cp $04
    jr z, jr_015_7e5a

    cp $08
    jr z, jr_015_7e86

    jr jr_015_7e70

jr_015_7e46:
    ld a, [$cd40]
    ld b, a
    ld a, $3c
    call Call_000_367d
    cp $10
    ret z

    swap a
    dec a
    ld c, a
    xor a
    ld b, a
    jr jr_015_7e9a

jr_015_7e5a:
    ld a, [$cd40]
    ld b, a
    ld a, $3c
    call Call_000_367d
    cp $10
    ret z

    swap a
    dec a
    ld c, a
    ld b, $00
    ld a, $40
    jr jr_015_7e9a

jr_015_7e70:
    ld a, [$cd41]
    ld b, a
    ld a, $40
    call Call_000_367d
    cp $10
    ret z

    swap a
    dec a
    ld c, a
    ld b, $00
    ld a, $c0
    jr jr_015_7e9a

jr_015_7e86:
    ld a, [$cd41]
    ld b, a
    ld a, $40
    call Call_000_367d
    cp $10
    ret z

    swap a
    dec a
    ld c, a
    ld b, $00
    ld a, $80

jr_015_7e9a:
    ld hl, $cc97
    ld de, $cc97
    call Call_000_372a
    ld [hl], $ff
    ld a, [$cf0e]
    ldh [$8c], a
    jp Jump_000_3687


Call_015_7ead:
    push de
    add hl, de
    ldh a, [$8c]
    swap a
    ld d, $00
    ld e, a
    add hl, de
    pop de
    ret


    push hl
    push de
    ld a, [$cd3d]
    add $02
    ld d, $00
    ld e, a
    ld hl, $c100
    add hl, de
    ld a, [hl]
    sub $ff
    jr nz, jr_015_7ecf

    jp Jump_015_7f32


jr_015_7ecf:
    ld a, [$cd3d]
    add $09
    ld d, $00
    ld e, a
    ld hl, $c100
    add hl, de
    ld a, [hl]
    ld [$cd3f], a
    call Call_015_7f38
    ld a, [$cd40]
    ld b, a
    ld a, $3c
    cp b
    jr z, jr_015_7ef8

    ld a, [$cd41]
    ld b, a
    ld a, $40
    cp b
    jr z, jr_015_7f0b

    xor a
    jp Jump_015_7f32


jr_015_7ef8:
    ld a, [$cd41]
    ld b, a
    ld a, $40
    call Call_000_367d
    jr z, jr_015_7f32

    call Call_015_7f59
    jr c, jr_015_7f1f

    xor a
    jr jr_015_7f32

jr_015_7f0b:
    ld a, [$cd40]
    ld b, a
    ld a, $3c
    call Call_000_367d
    jr z, jr_015_7f32

    call Call_015_7f59
    jr c, jr_015_7f1f

    xor a
    jp Jump_015_7f32


jr_015_7f1f:
    call Call_015_7f8d
    ld a, [$cd3d]
    and a

Call_015_7f26:
Jump_015_7f26:
    jr z, jr_015_7f32

    ld hl, $cd5b
    set 0, [hl]
    call Call_000_33b2
    ld a, $ff

Jump_015_7f32:
jr_015_7f32:
    ld [$cd3d], a
    pop de
    pop hl
    ret


Call_015_7f38:
    ld a, [$cd3d]
    add $04
    ld d, $00
    ld e, a
    ld hl, $c100
    add hl, de
    ld a, [hl]
    ld [$cd40], a
    ld a, [$cd3d]
    add $06
    ld d, $00
    ld e, a
    ld hl, $c100
    add hl, de
    ld a, [hl]
    ld [$cd41], a
    ret


Call_015_7f59:
    ld b, a
    ld a, [$cd3e]
    cp b
    jr nc, jr_015_7f62

    jr jr_015_7f8b

jr_015_7f62:
    ld a, [$cd3f]
    cp $00
    jr z, jr_015_7f77

Call_015_7f69:
    cp $04
    jr z, jr_015_7f77

    cp $08
    jr z, jr_015_7f81

    cp $0c
    jr z, jr_015_7f81

    jr jr_015_7f8b

jr_015_7f77:
    ld a, [$cd41]
    ld b, a
    cp $40
    jr z, jr_015_7f89

    jr jr_015_7f8b

jr_015_7f81:
    ld a, [$cd40]
    ld b, a
    cp $3c
    jr nz, jr_015_7f8b

jr_015_7f89:
    scf
    ret


jr_015_7f8b:
    and a
    ret


Call_015_7f8d:
    ld a, [$d2dd]
    cp $53
    jp z, Jump_015_7fec

    ld a, [$cd3d]
    add $04
    ld d, $00
    ld e, a
    ld hl, $c100
    add hl, de
    ld a, [hl]
    cp $fc
    jr nz, jr_015_7fa8

    ld a, $0c

jr_015_7fa8:
    ld [$cd40], a
    ld a, [$cd3d]
    add $06
    ld d, $00

Jump_015_7fb2:
    ld e, a

Call_015_7fb3:
    ld hl, $c100

Call_015_7fb6:
Jump_015_7fb6:
    add hl, de
    ld a, [hl]
    ld [$cd41], a
    ld a, [$cd3f]
    cp $00

Jump_015_7fc0:
    jr nz, jr_015_7fcb

    ld a, [$cd40]

Call_015_7fc5:
    cp $3c
    jr c, jr_015_7fec

Jump_015_7fc9:
    jr jr_015_7ff0

jr_015_7fcb:
    cp $04
    jr nz, jr_015_7fd8

Call_015_7fcf:
    ld a, [$cd40]
    cp $3c
    jr nc, jr_015_7fec

    jr jr_015_7ff0

Call_015_7fd8:
Jump_015_7fd8:
jr_015_7fd8:
    cp $08

Jump_015_7fda:
    jr nz, jr_015_7fe5

    ld a, [$cd41]
    cp $40
    jr nc, jr_015_7fec

    jr jr_015_7ff0

jr_015_7fe5:
    ld a, [$cd41]
    cp $40
    jr nc, jr_015_7ff0

Jump_015_7fec:
jr_015_7fec:
    ld a, $ff
    jr jr_015_7ff1

jr_015_7ff0:
    xor a

jr_015_7ff1:
    ld [$cd3d], a
    ret


    ld h, c
    ld d, c
    add b
    db $10
    add c
    jr nz, @+$42

    nop
    nop
    ld b, b
    nop
