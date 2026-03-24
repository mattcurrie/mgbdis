; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $003", ROMX[$4000], BANK[$3]

    ld a, $20
    ld c, $00
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    cpl
    and $0f
    swap a
    ld b, a
    ld a, $10
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    cpl
    and $4f
    cp $0f
    jr nz, jr_003_403a

    jp Jump_003_4074


jr_003_403a:
    or b
    ld b, a
    ldh a, [$b1]
    ld e, a
    xor b
    ld d, a
    and e
    ldh [$b2], a
    ld a, d
    and b
    ldh [$b3], a
    ld a, $30
    ldh [rP1], a
    ld a, b
    ldh [$b1], a
    ld a, [$d6af]
    bit 5, a
    jr nz, jr_003_406c

    ldh a, [$b1]
    ldh [$b4], a
    ld a, [$cd66]
    and a
    ret z

    cpl
    ld b, a
    ldh a, [$b4]
    and b
    ldh [$b4], a
    ldh a, [$b3]
    and b
    ldh [$b3], a
    ret


Call_003_406c:
jr_003_406c:
    xor a
    ldh [$b4], a
    ldh [$b3], a
    ldh [$b2], a
    ret


Jump_003_4074:
    call Call_000_0b31
    ld a, $30
    ldh [rP1], a
    ld hl, $ff8a
    dec [hl]
    jp z, Jump_000_09cf

    jp Jump_000_0153


    ld a, d
    ld b, d
    ld a, l
    ld b, d
    add e
    ld b, d
    adc c
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    sbc b
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    push bc
    ld b, d
    ld [hl], a
    ld b, d
    bit 0, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    adc $42
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    pop de
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    jp c, $dd42

    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ldh [rSCY], a
    ld [hl], a
    ld b, d
    and $42
    db $ec
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    rst $28
    ld b, d
    ld hl, sp+$42
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    db $10
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    and [hl]
    ld b, e
    ld d, $43
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    xor a
    ld b, e
    ld [hl], a
    ld b, d
    pop bc
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld h, c
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    sbc l
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    call Call_003_7743
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ret nc

    ld b, e
    db $d3
    ld b, e
    reti


    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    or $44
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    db $fc
    ld b, h
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld c, c
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld c, h
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl+], a
    ld b, e
    dec h
    ld b, e
    jr z, jr_003_41ec

    ld sp, $3443
    ld b, e
    ld a, [hl-]
    ld b, e
    ld b, [hl]
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld c, a
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    dec b
    ld b, l
    dec bc
    ld b, l
    ld de, $1d45
    ld b, l
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld d, d
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld e, b
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a

jr_003_41ec:
    ld b, d
    ld [hl], a
    ld b, d
    ld e, [hl]
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    rst $38
    ld b, h
    ld [hl], a
    ld b, d
    adc e
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [c], a
    ld b, e
    db $eb
    ld b, e
    pop af
    ld b, e
    db $fd
    ld b, e
    inc bc
    ld b, h
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    dec d
    ld b, h
    inc h
    ld b, h
    dec l
    ld b, h
    ccf
    ld b, h
    ld d, h
    ld b, h
    ld h, e
    ld b, h
    ld a, e
    ld b, h
    xor e
    ld b, h
    xor [hl]
    ld b, h
    or h
    ld b, h
    jp $cf44


    ld b, h
    push de
    ld b, h
    pop hl
    ld b, h
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    db $e4
    ld b, h
    db $ed
    ld b, h
    add hl, de
    ld b, e
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    add h
    ld b, h
    adc l
    ld b, h
    sbc a
    ld b, h
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    xor b
    ld b, h
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    ld [hl], a
    ld b, d
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    ld bc, $0111
    dec b
    dec d
    ld bc, $1107
    ld [bc], a
    inc bc
    dec d
    ld [bc], a
    dec b
    dec d
    inc bc
    ld bc, $0311
    ld [bc], a
    dec d
    inc bc
    ld b, $11
    inc bc
    ld a, [bc]
    dec d
    inc bc
    dec bc
    dec d
    ld a, [bc]
    ld bc, $0a15
    ld [bc], a
    dec d
    ld a, [bc]
    inc bc
    dec d
    ld a, [bc]
    inc b
    dec d
    ld a, [bc]
    dec b
    dec d
    ld a, [bc]
    ld b, $15
    ld a, [bc]
    rlca
    dec d
    ld a, [bc]
    ld [$0a11], sp
    add hl, bc
    ld de, $0a0a
    ld de, $0b0a
    ld de, $0c0a
    ld de, $0d0a
    ld de, $0e0a
    dec d
    ld a, [bc]
    rrca
    ld de, $010d
    dec d
    dec c
    ld [bc], a
    dec d
    rrca
    inc bc
    dec d
    inc d
    ld a, [bc]
    dec d
    rla
    ld bc, $1715
    add hl, bc
    dec d
    rla
    ld a, [bc]
    dec d
    ld a, [de]
    dec bc
    dec d
    dec de
    rlca
    dec d
    ld hl, $1101
    ld hl, $1102
    inc hl
    ld bc, $2315
    ld [$2415], sp
    ld a, [bc]
    dec d
    daa
    ld bc, $2715
    ld [bc], a
    ld de, $0327
    dec d
    jr z, jr_003_42fb

    dec d

jr_003_42fb:
    jr z, @+$04

    dec d
    jr z, jr_003_4303

    dec d
    jr z, @+$06

jr_003_4303:
    dec d
    jr z, @+$07

    ld de, $0628
    dec d
    jr z, jr_003_4313

    dec d
    jr z, jr_003_4317

    ld de, $012d
    dec d

jr_003_4313:
    dec l
    dec bc
    dec d
    inc [hl]

jr_003_4317:
    dec b
    dec d
    db $e4
    ld bc, $e415
    ld [bc], a
    dec d
    db $e4
    inc bc
    dec d
    adc a
    ld bc, $9015
    inc b
    dec d
    sub c
    inc b
    dec d

Call_003_432b:
    sub c
    dec b
    dec d
    sub c
    ld b, $15
    sub d
    ld b, $15
    sub e
    inc b
    dec d
    sub e
    dec b
    dec d
    sub h
    ld bc, $9415
    ld [bc], a
    dec d
    sub h
    inc bc
    dec d
    sub h
    inc b
    dec d
    sub l
    dec b
    ld de, $0284
    dec d
    add a
    dec bc
    dec d
    sbc e
    ld [bc], a
    dec d
    and l
    ld [bc], a
    dec d
    and l
    inc bc
    dec d
    or c
    ld b, $15
    or c
    rlca
    dec d
    or l
    ld bc, $5311
    ld bc, $5315
    ld [bc], a
    dec d
    ld d, e
    inc bc
    dec d
    ld d, e
    inc b
    dec d
    ld d, e
    dec b
    dec d
    ld d, e
    ld b, $15
    ld d, e
    rlca
    dec d
    ld d, e
    ld [$5315], sp
    add hl, bc
    dec d
    ld d, e
    ld a, [bc]
    dec d
    ld d, e
    dec bc
    dec d
    ld d, e
    inc c
    dec d
    ld d, e
    dec c
    dec d
    ld d, e
    ld c, $15
    jp nz, $1506

    jp nz, Jump_000_1507

    jp nz, Jump_000_1508

    jp nz, Jump_000_1509

    jp nz, $150a

    jp nz, $150d

    ld e, b
    ld bc, $5815
    ld [bc], a
    ld de, $0358
    ld de, $0533
    dec d
    inc sp
    ld b, $15
    inc sp
    rlca
    dec d
    dec sp
    ld [$3b15], sp
    add hl, bc
    dec d
    dec sp
    ld a, [bc]
    dec d
    dec sp
    dec bc
    dec d
    dec sp
    inc c
    dec d
    dec sp
    dec c
    dec d
    dec a
    ld b, $15
    dec a
    rlca
    dec d
    dec a
    ld [$3d15], sp
    add hl, bc
    dec d
    ld h, b
    ld [bc], a
    ld de, $0a66
    dec d
    ld h, a
    ld b, $15
    ld h, a
    add hl, bc
    dec d
    ld l, b
    add hl, bc
    dec d
    ld l, b
    ld a, [bc]
    dec d
    ld l, b
    dec bc
    dec d
    add $05
    dec d
    add $06
    dec d
    add $0a
    dec d
    rst $00
    ld b, $15
    rst $00
    rlca
    dec d
    ret z

    ld [bc], a
    dec d
    ret z

    inc bc
    dec d
    ret z

    inc b
    dec d
    ret z

    dec b
    dec d
    ret


    inc bc
    dec d
    ret


    inc b
    dec d
    jp z, Jump_000_1501

    jp z, $1505

    jp z, $1506

    jp z, Jump_000_1507

    jp z, $1108

    jp z, Jump_000_1109

    rst $08
    ld bc, $cf15
    ld [bc], a
    dec d
    rst $08
    inc bc
    dec d
    rst $08
    inc b
    dec d
    rst $08
    dec b
    dec d
    ret nc

    ld [bc], a
    dec d
    ret nc

    inc bc
    dec d
    ret nc

    inc b
    dec d
    pop de
    ld [bc], a
    dec d
    pop de
    inc bc
    dec d
    pop de
    inc b
    dec d
    pop de
    dec b
    dec d
    pop de
    ld b, $15
    pop de
    rlca
    dec d
    jp nc, $1502

    jp nc, $1503

    jp nc, Jump_000_1504

    jp nc, $1505

    jp nc, $1506

    jp nc, Jump_000_1507

    jp nc, Jump_000_1508

    db $d3
    ld b, $15
    db $d3
    rlca
    dec d
    db $d3
    ld [$d315], sp
    add hl, bc
    dec d
    db $d3
    ld a, [bc]
    dec d
    call nc, $1505
    call nc, $1506
    call nc, Call_000_1507
    call nc, Call_000_1508
    call nc, Call_000_1509
    call nc, $150a
    call nc, $150b
    call nc, Call_000_150c
    push de
    ld [bc], a
    dec d
    push de
    inc bc
    dec d
    push de
    inc b
    dec d
    jp hl


    ld [bc], a
    dec d
    jp hl


    inc bc
    dec d
    jp hl


    inc b
    dec d
    ld [$1501], a
    ld [$1502], a
    ld [$1503], a
    ld [$1504], a
    ld [$1505], a
    ld [$1506], a
    db $eb
    inc bc
    dec d
    db $eb
    inc b
    dec d
    db $eb
    dec b
    dec d
    db $f4
    ld [bc], a
    dec d
    sub $02
    dec d
    rst $10
    inc bc
    dec d
    rst $10
    inc b
    dec d
    ret c

    inc bc
    dec d
    ret c

    inc b
    dec d
    ret c

    dec b
    dec d
    ret c

    ld b, $15
    ret c

    ld [$d915], sp
    ld bc, $d915
    ld [bc], a
    dec d
    reti


    inc bc
    dec d
    reti


    inc b
    dec d
    jp c, Jump_000_1501

    jp c, $1502

    db $db
    ld bc, $db15
    ld [bc], a
    dec d
    db $db
    inc bc
    dec d
    db $db
    inc b
    dec d
    call c, Call_000_1501
    ld [c], a
    ld bc, $e215
    ld [bc], a
    dec d
    ld [c], a
    inc bc
    dec d
    db $e3
    ld bc, $e315
    ld [bc], a
    dec d
    db $e3
    inc bc
    dec d
    ld l, h
    inc bc
    dec d
    ld l, h
    inc b
    dec d
    ld a, b
    ld [bc], a
    ld de, $01c0
    dec d
    ret nz

    ld [bc], a
    dec d
    sbc a
    ld bc, $9f11
    ld [bc], a
    ld de, $01a0
    ld de, $02a0
    ld de, $02a1
    dec d
    and c
    inc bc
    dec d
    and c
    dec b
    ld de, $06a1
    ld de, $01a2
    ld de, $02a2
    ld de, $03a2
    dec d
    rst $38
    ld bc, $2115
    and a
    sub $cb
    add $21
    ld a, [hl-]
    ld b, l
    call Call_000_3c79
    ld hl, $455a
    jp Jump_000_3c79


    ld bc, $cd68
    nop
    ld c, a
    or b
    jp nc, $c4cf

    push de
    jp $c4c5


    and [hl]
    rst $08
    jp nc, $c5c3

    ld d, b
    ld [$78fa], sp
    rst $08
    call Call_000_2dc7
    call Call_000_3e07
    jp Jump_000_0f6a


    db $ed
    jr z, @-$3e

    ld h, c
    ret


    ld a, a
    or [hl]
    or d
    ret c

    or a
    ret


    ld a, a
    or l
    or [hl]
    add hl, hl
    inc sp
    ld c, a
    or d
    call c, $7fdd
    or l
    cp [hl]
    reti


    sub $b3
    add $7f
    push bc
    rst $18
    ret nz

    rst $20
    ld e, b
    ld hl, $d6a7
    set 1, [hl]
    ld a, [$d6b1]
    bit 5, a
    jr nz, jr_003_45a7

    ld a, [$d2dd]
    cp $a2
    ret nz

    ld a, [$d800]
    and $03
    cp $03
    ret z

    ld hl, $45b2
    call Call_000_3509
    ret nc

    ld hl, $d6a7
    res 1, [hl]
    ld hl, $45b5
    jp Jump_000_3c79


jr_003_45a7:
    ld hl, $d6a7
    res 1, [hl]
    ld hl, $45c5
    jp Jump_000_3c79


    dec bc
    rlca
    rst $38
    db $ed
    jr z, jr_003_45c4

    ld h, d
    ld h, $7f
    jp z, $b8d4

    jp Jump_000_0f4f


    and b
    jr nc, @-$17

jr_003_45c4:
    ld e, b
    db $ed
    jr z, @+$41

    ld h, d
    cp b
    ret


    ld a, a
    adc d
    add c
    add a
    ret c

    xor e
    rlca
    rst $20
    ld c, a
    ld d, [hl]
    ld a, a
    push bc
    ret nc

    ret


    ret c

    jp z, $d47f

    jp nc, $bac4

    or e
    ld e, b
    ld a, [$cf7d]
    push af
    push bc
    push de
    push hl
    push hl
    ld d, $32
    ld a, $a1
    cp l
    jr nz, jr_003_45f8

    ld a, $d2
    cp h
    jr nz, jr_003_45f8

    ld d, $14

jr_003_45f8:
    ld a, [hl]
    sub d
    ld d, a
    ld a, [hl+]
    and a
    jr z, jr_003_460e

Jump_003_45ff:
jr_003_45ff:
    ld a, [hl+]
    ld b, a
    ld a, [$cf78]
    cp b
    jp z, Jump_003_4628

    inc hl
    ld a, [hl]
    cp $ff
    jr nz, jr_003_45ff

jr_003_460e:
    pop hl
    ld a, d
    and a
    jr z, jr_003_4649

    inc [hl]
    ld a, [hl]
    add a
    dec a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [$cf78]
    ld [hl+], a
    ld a, [$cf7d]
    ld [hl+], a
    ld [hl], $ff
    jp Jump_003_4648


Jump_003_4628:
    ld a, [$cf7d]
    ld b, a
    ld a, [hl]
    add b
    cp $64
    jp c, Jump_003_4646

    sub $63
    ld [$cf7d], a
    ld a, d
    and a
    jr z, jr_003_4642

    ld a, $63
    ld [hl+], a
    jp Jump_003_45ff


jr_003_4642:
    pop hl
    and a
    jr jr_003_4649

Jump_003_4646:
    ld [hl], a
    pop hl

Jump_003_4648:
    scf

jr_003_4649:
    pop hl
    pop de
    pop bc
    pop bc
    ld a, b
    ld [$cf7d], a
    ret


    push hl
    inc hl
    ld a, [$cf79]
    sla a
    add l
    ld l, a
    jr nc, jr_003_465e

    inc h

jr_003_465e:
    inc hl
    ld a, [$cf7d]
    ld e, a
    ld a, [hl]
    sub e
    ld [hl-], a
    ld [$cf7e], a
    and a
    jr nz, jr_003_4691

    ld e, l
    ld d, h
    inc de
    inc de

jr_003_4670:
    ld a, [de]
    inc de
    ld [hl+], a
    cp $ff
    jr nz, jr_003_4670

    xor a
    ld [$cc36], a
    ld [$cc26], a
    ld [$cc2c], a
    pop hl
    ld a, [hl]
    dec a
    ld [hl], a
    ld [$d0ef], a
    cp $02
    jr c, jr_003_4692

    ld [$cc28], a
    jr jr_003_4692

jr_003_4691:
    pop hl

jr_003_4692:
    ret


    cp d
    ld [bc], a
    jp $c302


    ld [bc], a
    rst $00
    ld [bc], a
    call nc, $d002
    ld [bc], a
    jp z, $c702

    ld [bc], a
    call $fb02
    ld [bc], a
    jp $c302


    ld [bc], a
    db $eb
    ld [bc], a
    db $eb
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    rst $30
    ld [bc], a
    rst $30
    ld [bc], a
    rst $30
    ld [bc], a
    rst $30
    ld [bc], a
    rst $30
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    di
    ld [bc], a
    ei
    ld [bc], a
    rst $28
    ld [bc], a
    rst $28
    ld [bc], a
    cp d
    ld [bc], a
    cp d
    ld [bc], a
    cp d
    ld [bc], a
    call $bd1f
    ld [bc], a
    cp l
    ld [bc], a
    jp $c302


    ld [bc], a
    ret nz

    ld [bc], a
    db $e4
    rra
    jp $c302


    ld [bc], a
    jp $c302


    ld [bc], a
    db $e4
    rra
    jp $c302


    ld [bc], a
    ret nz

    ld [bc], a
    jp $bd02


    ld [bc], a
    jp $bd02


    ld [bc], a
    add sp, $1f
    add sp, $1f
    add sp, $1f
    rst $00
    ld [bc], a
    rst $00
    ld [bc], a
    cp l
    ld [bc], a
    ret nz

    ld [bc], a
    rst $00
    ld [bc], a
    cp l
    ld [bc], a
    cp l
    ld [bc], a
    add sp, $1f
    jp $c302


    ld [bc], a
    jp $c302


    ld [bc], a
    jp $d002


    ld [bc], a
    jp $c302


    ld [bc], a
    jp z, $c302

    ld [bc], a
    jp $bd02


    ld [bc], a
    add sp, $1f
    ldh [$1f], a
    ret nc

    ld [bc], a
    db $e4
    rra
    ret nc

    ld [bc], a
    jp $c702


    ld [bc], a
    cp l
    ld [bc], a
    ret nc

    ld [bc], a
    cp l
    ld [bc], a
    ret nz

    ld [bc], a
    ret nc

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    db $e4
    rra
    db $e4
    rra
    ret c

    ld [bc], a
    add sp, $1f
    ldh a, [$1f]
    ldh [$1f], a
    di
    rra
    di
    rra
    ei
    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    ret c

    ld [bc], a
    cp d
    ld [bc], a
    db $eb
    ld [bc], a
    ei
    ld [bc], a
    db $eb
    ld [bc], a
    cp l
    ld [bc], a
    cp l
    ld [bc], a
    cp l
    ld [bc], a
    cp l
    ld [bc], a
    cp l
    ld [bc], a
    cp l
    ld [bc], a
    jp z, $ca02

    ld [bc], a
    jp z, $ca02

    ld [bc], a
    jp z, $bd02

    ld [bc], a
    ret nz

    ld [bc], a
    reti


    rra
    cp l
    ld [bc], a
    jp z, $ca02

    ld [bc], a
    jp z, $ca02

    ld [bc], a
    cp l
    ld [bc], a
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    ldh a, [$1f]
    call nc, $bd02
    ld [bc], a
    call nc, $bd02
    ld [bc], a
    rst $00
    ld [bc], a
    cp l
    ld [bc], a
    rst $00
    ld [bc], a
    rst $00
    ld [bc], a
    ret nz

    ld [bc], a
    rst $00
    ld [bc], a
    db $e4
    rra
    db $e4
    rra
    db $e4
    rra
    db $e4
    rra
    rst $00
    ld [bc], a
    rst $00
    ld [bc], a
    db $ec
    rra
    ret nz

    ld [bc], a
    call $cd02
    ld [bc], a
    call $cd02
    ld [bc], a
    cp l
    ld [bc], a
    cp l
    ld [bc], a
    call $fb02
    ld [bc], a
    jp $c302


    ld [bc], a
    jp $c002


    ld [bc], a
    jp $bd02


    ld [bc], a
    di
    rra
    cp l
    ld [bc], a
    jp $c302


    ld [bc], a
    jp $c302


    ld [bc], a
    jp $ca02


    ld [bc], a
    jp z, $c302

    ld [bc], a
    jp $e402


    rra
    db $e4
    rra
    add sp, $1f
    jp $d002


    ld [bc], a
    db $e4
    rra
    add sp, $1f
    ldh [$1f], a
    ldh [$1f], a
    ldh [$1f], a
    ldh [$1f], a
    ldh [$1f], a
    ldh [$1f], a
    ldh [$1f], a
    ldh [$1f], a
    di
    rra
    di

Call_003_4834:
    rra
    di
    rra
    di
    rra
    di
    rra
    di
    rra
    di
    rra
    db $ec
    rra
    db $ec
    rra
    db $ec
    rra
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    push hl
    ld [bc], a
    ldh [$1f], a
    ldh [$1f], a
    ldh [$1f], a
    rst $00
    ld [bc], a
    jp $cd02


    ld [bc], a
    add sp, $1f
    di
    rra
    di
    rra
    di
    rra
    di
    rra
    di
    rra
    di
    rra
    jp z, $ca02

    ld [bc], a
    di
    rra
    di
    rra
    di
    rra
    di
    rra
    ret nz

    ld [bc], a
    ldh [$1f], a
    ldh a, [$1f]
    ld b, $06
    ld b, $06
    ld de, $0606
    ld b, $07
    inc d
    inc d
    ld bc, $1507
    dec d
    dec d
    dec d
    ld d, $12
    ld d, $15
    ld d, $16
    ld d, $15
    dec d
    ld d, $16
    dec d
    ld d, $15
    inc d
    dec d
    inc d
    inc d
    inc d
    inc d
    ld [de], a
    rla
    ld b, $07
    ld de, $0707
    rlca
    dec e
    rlca
    rla
    rlca
    rla
    rla
    jr jr_003_48cf

    rla
    rla
    rlca
    dec e
    rlca
    rla
    ld [de], a
    inc d
    ld [de], a
    rlca
    rlca
    rla
    rla
    rlca
    rla
    ld [de], a
    rlca
    rlca
    rla
    dec d
    rlca
    rla
    rla

jr_003_48cf:
    rlca
    rla
    rla
    rlca
    rlca
    ld [de], a
    ld de, $1207
    rlca
    ld [de], a
    ld [de], a
    rlca
    rla
    ld d, $17
    rla
    rlca
    rlca
    jr jr_003_48fc

    ld de, $1818
    jr jr_003_4901

    jr jr_003_4903

    jr jr_003_490a

    dec e
    dec e
    rla
    dec e
    dec e
    dec e
    dec e
    ld d, $1d
    dec e
    dec e
    dec e
    ld d, $18
    dec e

jr_003_48fc:
    jr @+$1a

    dec d
    ld [de], a
    ld [de], a

jr_003_4901:
    ld [de], a
    ld [de], a

jr_003_4903:
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    rlca
    ld [de], a
    ld [de], a

jr_003_490a:
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    rla
    jr jr_003_492b

    jr jr_003_492d

    jr jr_003_492f

    jr jr_003_4920

    rla
    rlca
    rlca
    dec e
    dec e
    dec e
    dec e

jr_003_4920:
    dec e
    dec e
    ld de, $1111
    ld de, $1515
    ld de, $1d1d

jr_003_492b:
    dec e
    dec e

jr_003_492d:
    dec e
    dec e

jr_003_492f:
    dec e
    dec e
    ld b, $1d
    rla
    rla
    rla
    rlca
    rla
    rla
    rla
    rlca
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    rlca
    dec d
    ld [de], a
    ld [de], a
    ld de, $1407
    ld [de], a
    ld b, $18
    ld de, $1111
    ld de, $1111
    ld bc, $0101
    ld d, $16
    ld b, $06
    ld b, $14
    dec d
    inc d
    inc d
    inc d
    ld de, $1211
    ld de, $1211
    ld de, $1111
    ld de, $1d11
    rlca
    dec e
    ld bc, $1711
    ld d, $18

Call_003_496f:
    ld de, $1111
    inc de
    inc de
    ld de, $1111
    ld de, $1d1d
    dec e
    ld a, $90
    ldh [$b0], a
    ldh [rWY], a
    xor a
    ldh [$ba], a
    ld [$d100], a
    ld [$d039], a
    ldh [$b3], a
    ldh [$b2], a
    ldh [$b4], a
    ld [$cd65], a
    ld [$d522], a
    ld hl, $d6be
    ld [hl+], a
    ld [hl], a
    ld hl, $cd3d
    ld bc, $001e
    call Call_000_372a
    ret


    ld a, [$d32d]
    and a
    ret z

    ld c, a
    ld hl, $d32e

jr_003_49ae:
    ld a, [$d2e0]
    cp [hl]
    jr nz, jr_003_49c9

    inc hl
    ld a, [$d2e1]
    cp [hl]
    jr nz, jr_003_49ca

    inc hl
    ld a, [hl+]
    ld [$d3ae], a
    ld a, [hl]
    ldh [$8b], a
    ld hl, $d6b5
    set 2, [hl]
    ret


jr_003_49c9:
    inc hl

jr_003_49ca:
    inc hl
    inc hl
    inc hl
    dec c
    jr nz, jr_003_49ae

    ret


    ld hl, $d6b1
    bit 5, [hl]
    ret nz

    ld hl, $4a2c
    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e1]
    ld c, a
    ld a, [$d2dd]
    ld d, a

jr_003_49e6:
    ld a, [hl+]
    cp $ff
    ret z

    cp d
    jr nz, jr_003_4a1d

    ld a, [hl+]
    cp b
    jr nz, jr_003_4a1e

    ld a, [hl+]
    cp c
    jr nz, jr_003_49e6

    ld a, [$d2dd]
    cp $a1
    ld a, $02
    ld [$d5e5], a
    jr z, jr_003_4a21

    ld a, [$d2dd]
    cp $a2
    ld a, $02
    ld [$d5e7], a
    jr z, jr_003_4a21

    ld hl, $d6b1
    set 5, [hl]
    ld a, $01
    ld [$d67f], a
    ld [$d0df], a
    jp Jump_000_2cfe


jr_003_4a1d:
    inc hl

jr_003_4a1e:
    inc hl
    jr jr_003_49e6

jr_003_4a21:
    ld a, $02
    ld [$d67f], a
    ld [$d0df], a
    jp Jump_000_2cfe


    dec de
    ld a, [bc]
    ld de, $0b1b
    ld de, $081d
    ld hl, $091d
    ld hl, $07a1
    ld [de], a
    and c
    rlca
    inc de
    and d
    ld c, $04
    and d
    ld c, $05
    rst $38
    push hl
    push de
    push bc
    ld a, [$c109]
    srl a
    ld c, a
    ld b, $00
    ld hl, $4a68
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$d2e0]
    ld b, a
    ld a, [$d2e1]
    ld c, a
    ld de, $4a64
    push de
    jp hl


    pop bc
    pop de
    pop hl
    ret


    ld [hl], b
    ld c, d
    ld a, d
    ld c, d
    add b
    ld c, d
    add [hl]
    ld c, d
    ld a, [$d2e7]
    add a
    dec a
    cp b
    jr z, jr_003_4a92

    jr jr_003_4a90

    ld a, b
    and a
    jr z, jr_003_4a92

    jr jr_003_4a90

    ld a, c
    and a
    jr z, jr_003_4a92

    jr jr_003_4a90

    ld a, [$d2e8]
    add a
    dec a
    cp c
    jr z, jr_003_4a92

    jr jr_003_4a90

jr_003_4a90:
    and a
    ret


jr_003_4a92:
    scf
    ret


    push hl
    push de
    push bc
    call Call_003_4bc2
    ld a, [$d2dd]
    cp $63
    jr z, jr_003_4ad6

    ld a, [$c109]
    srl a
    ld c, a
    ld b, $00
    ld hl, $4abd
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$cfad]
    ld de, $0001
    call Call_000_3ddb

jr_003_4ab9:
    pop bc
    pop de
    pop hl
    ret


    push bc
    ld c, d
    call $d04a
    ld c, d
    db $d3
    ld c, d
    ld bc, $1712
    dec a
    inc b
    jr @+$35

    rst $38
    ld bc, $ff5c
    ld a, [de]
    ld c, e
    rst $38
    rrca
    ld c, [hl]
    rst $38

jr_003_4ad6:
    ld a, [$cfad]
    cp $15
    jr nz, jr_003_4ae0

    scf
    jr jr_003_4ab9

jr_003_4ae0:
    and a
    jr jr_003_4ab9

    push hl
    push de
    push bc
    ld b, $06
    ld hl, $7ec1
    call Call_000_3620
    jr c, jr_003_4b0e

    ld a, [$d2e6]
    add a
    ld c, a
    ld b, $00
    ld hl, $4b12
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $0001
    ld a, [$c45c]
    call Call_000_3ddb
    jr nc, jr_003_4b0e

    ld hl, $d6b5
    res 2, [hl]

jr_003_4b0e:
    pop bc
    pop de
    pop hl
    ret


    ld b, d
    ld c, e
    ld b, [hl]
    ld c, e
    ld c, c
    ld c, e
    ld c, e
    ld c, e
    ld b, [hl]
    ld c, e
    ld c, a
    ld c, e
    ld c, c
    ld c, e
    ld c, a
    ld c, e
    ld d, c
    ld c, e
    ld b, l
    ld c, e
    ld b, l
    ld c, e
    ld [hl], b
    ld c, e
    ld b, l
    ld c, e
    ld d, l
    ld c, e
    ld [hl], h
    ld c, e
    ld l, a
    ld c, e
    ld e, d
    ld c, e
    ld e, [hl]
    ld c, e
    ld h, d
    ld c, e
    ld h, [hl]
    ld c, e
    ld l, d
    ld c, e
    ld [hl], h
    ld c, e
    ld l, h
    ld c, e
    ld [hl], d
    ld c, e
    dec de
    ld e, b
    rst $38
    dec sp
    ld a, [de]
    inc e
    rst $38
    ld e, [hl]
    rst $38
    ld e, d
    ld e, h
    ld a, [hl-]
    rst $38
    ld c, d
    rst $38
    ld d, h
    ld e, h
    ld [hl-], a
    rst $38
    scf
    add hl, sp
    ld e, $4a
    rst $38
    dec d
    ld d, l
    inc b
    rst $38
    jr jr_003_4b7a

    ld [hl+], a
    rst $38
    ld a, [de]
    inc e
    jr c, @+$01

    ld a, [de]
    inc e
    ld d, e
    rst $38
    inc [hl]
    rst $38
    ld b, e
    ld e, b
    jr nz, jr_003_4b8b

    inc de
    rst $38
    dec de
    dec sp
    rst $38
    ld a, [$d2dd]
    cp $d9

jr_003_4b7a:
    ret c

    cp $e2
    ret nc

    ld hl, $c3a0
    ld b, $03
    ld c, $07
    call Call_000_03d2
    ld hl, $c3b5

jr_003_4b8b:
    ld de, $d68c
    ld bc, $0203
    call Call_000_3c8f
    ld hl, $c3b8
    ld de, $4bb2
    call Call_000_0405
    ld hl, $c3dd
    ld de, $4bb7
    call Call_000_0405
    ld hl, $c3e1
    ld de, $d983
    ld bc, $0102
    jp Jump_000_3c8f


    di
    ei
    or $f6
    ld d, b
    db $ed
    inc l
    pop de
    ld b, c
    ld a, a
    ld a, a
    cp d
    ld d, b

Call_003_4bbf:
    call Call_000_3ec4

Call_003_4bc2:
    ld a, [$d2e0]
    ld d, a
    ld a, [$d2e1]
    ld e, a
    ld a, [$c109]
    and a
    jr nz, jr_003_4bd6

    ld a, [$c484]
    inc d
    jr jr_003_4bf2

jr_003_4bd6:
    cp $04
    jr nz, jr_003_4be0

    ld a, [$c434]
    dec d
    jr jr_003_4bf2

jr_003_4be0:
    cp $08
    jr nz, jr_003_4bea

    ld a, [$c45a]
    dec e
    jr jr_003_4bf2

jr_003_4bea:
    cp $0c
    jr nz, jr_003_4bf2

    ld a, [$c45e]
    inc e

jr_003_4bf2:
    ld c, a
    ld [$cfad], a
    ret


Call_003_4bf7:
    xor a
    ldh [$db], a
    ld hl, $d2e0
    ld a, [hl+]
    ld d, a
    ld e, [hl]
    ld a, [$c109]
    and a
    jr nz, jr_003_4c11

    ld hl, $ffdb
    set 0, [hl]
    ld a, [$c4ac]
    inc d
    jr jr_003_4c3c

jr_003_4c11:
    cp $04
    jr nz, jr_003_4c20

    ld hl, $ffdb
    set 1, [hl]
    ld a, [$c40c]
    dec d
    jr jr_003_4c3c

jr_003_4c20:
    cp $08
    jr nz, jr_003_4c2f

    ld hl, $ffdb
    set 2, [hl]
    ld a, [$c458]
    dec e
    jr jr_003_4c3c

jr_003_4c2f:
    cp $0c
    jr nz, jr_003_4c3c

    ld hl, $ffdb
    set 3, [hl]
    ld a, [$c460]
    inc e

jr_003_4c3c:
    ld c, a
    ld [$d69b], a
    ld [$cfad], a
    ret


    call Call_003_4bf7
    ld hl, $d4af
    ld a, [hl+]
    ld h, [hl]
    ld l, a

jr_003_4c4d:
    ld a, [hl+]
    cp $ff
    jr z, jr_003_4c6b

    cp c
    jr nz, jr_003_4c4d

    ld hl, $268f
    call Call_000_265b
    ld a, $ff
    jr c, jr_003_4c6b

    ld a, [$d69b]
    cp $15
    ld a, $ff
    jr z, jr_003_4c6b

    call Call_003_4c6f

jr_003_4c6b:
    ld [$d69b], a
    ret


Call_003_4c6f:
    ld a, [$d697]
    dec a
    swap a
    ld d, $00
    ld e, a
    ld hl, $c214
    add hl, de
    ld a, [hl+]
    ldh [$dc], a
    ld a, [hl]
    ldh [$dd], a
    ld a, [$d460]
    ld c, a
    ld de, $000f
    ld hl, $c214
    ldh a, [$db]
    and $03
    jr z, jr_003_4cb1

jr_003_4c92:
    inc hl
    ldh a, [$dd]
    cp [hl]
    jr nz, jr_003_4cab

    dec hl
    ld a, [hl+]
    ld b, a
    ldh a, [$db]
    rrca
    jr c, jr_003_4ca5

    ldh a, [$dc]
    dec a
    jr jr_003_4ca8

jr_003_4ca5:
    ldh a, [$dc]
    inc a

jr_003_4ca8:
    cp b
    jr z, jr_003_4cd0

jr_003_4cab:
    dec c
    jr z, jr_003_4cd3

    add hl, de
    jr jr_003_4c92

jr_003_4cb1:
    ld a, [hl+]
    ld b, a
    ldh a, [$dc]
    cp b
    jr nz, jr_003_4cca

    ld b, [hl]
    ldh a, [$db]
    bit 2, a
    jr nz, jr_003_4cc4

    ldh a, [$dd]
    inc a
    jr jr_003_4cc7

jr_003_4cc4:
    ldh a, [$dd]
    dec a

jr_003_4cc7:
    cp b
    jr z, jr_003_4cd0

jr_003_4cca:
    dec c
    jr z, jr_003_4cd3

    add hl, de
    jr jr_003_4cb1

jr_003_4cd0:
    ld a, $ff
    ret


jr_003_4cd3:
    xor a
    ret


    ld a, [$d6af]
    add a
    jp c, Jump_003_4d88

    ld a, [$d123]
    and a
    jp z, Jump_003_4d88

    call $4f17
    ld a, [$d100]
    and $03
    jp nz, Jump_003_4d88

    ld [$cf79], a
    ld hl, $d12f
    ld de, $d124

jr_003_4cf7:
    ld a, [hl]
    and $08
    jr z, jr_003_4d36

    dec hl
    dec hl
    ld a, [hl-]
    ld b, a
    ld a, [hl+]
    or b
    jr z, jr_003_4d34

    ld a, [hl]
    dec a
    ld [hl-], a
    inc a
    jr nz, jr_003_4d0e

    dec [hl]
    inc hl
    jr jr_003_4d34

jr_003_4d0e:
    ld a, [hl+]
    or [hl]
    jr nz, jr_003_4d34

    push hl
    inc hl
    inc hl
    ld [hl], a
    ld a, [de]
    ld [$d0e3], a
    push de
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    xor a
    ld [$cd66], a
    call Call_000_3c6c
    ld a, $d0
    ldh [$8c], a
    call Call_000_13f1
    pop de
    pop hl

jr_003_4d34:
    inc hl
    inc hl

jr_003_4d36:
    inc de
    ld a, [de]
    inc a
    jr z, jr_003_4d47

    ld bc, $002c
    add hl, bc
    push hl
    ld hl, $cf79
    inc [hl]
    pop hl
    jr jr_003_4cf7

jr_003_4d47:
    ld hl, $d12f
    ld a, [$d123]
    ld d, a
    ld e, $00

jr_003_4d50:
    ld a, [hl]
    and $08
    or e
    ld e, a
    ld bc, $002c
    add hl, bc
    dec d
    jr nz, jr_003_4d50

    ld a, e
    and a
    jr z, jr_003_4d6c

    ld b, $02
    ld a, $1f
    call Call_000_3e9d
    ld a, $97
    call Call_000_0e45

jr_003_4d6c:
    ld a, $14
    call Call_000_3e9d
    ld a, d
    and a
    jr nz, jr_003_4d88

    call Call_000_3c6c
    ld a, $d1
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6ad
    set 5, [hl]
    ld a, $ff
    jr jr_003_4d89

Jump_003_4d88:
jr_003_4d88:
    xor a

jr_003_4d89:
    ld [$d0f2], a
    ret


    call Call_000_3ec4
    push hl
    ld d, $00
    ld a, [$d2e6]
    add a
    add a
    ld b, a
    add a
    add b
    jr nc, jr_003_4d9e

    inc d

jr_003_4d9e:
    ld e, a
    ld hl, $4df7
    add hl, de
    ld de, $d4aa
    ld c, $0b

jr_003_4da8:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_003_4da8

    ld a, [hl]
    ldh [$d7], a
    xor a
    ldh [$d8], a
    pop hl
    ld a, [$d2e6]
    push hl
    push de
    ld hl, $4deb
    ld de, $0001
    call Call_000_3ddb
    pop de
    pop hl
    jr c, jr_003_4dd0

    ld a, [$d2e6]
    ld b, a
    ldh a, [$8b]
    cp b
    jr z, jr_003_4dea

jr_003_4dd0:
    ld a, [$d3ae]
    cp $ff
    jr z, jr_003_4dea

    call Call_000_2d09
    ld a, [$d2e0]
    and $01
    ld [$d2e2], a
    ld a, [$d2e1]
    and $01
    ld [$d2e3], a

jr_003_4dea:
    ret


    inc bc
    ld a, [bc]
    dec c
    ld de, $1312
    inc c
    inc d
    ld d, $0f
    rlca
    rst $38
    add hl, de
    ldh [rLYC], a
    nop
    ld b, b
    jp z, $ff01

    rst $38
    rst $38
    ld d, d
    ld [bc], a
    add hl, de
    ld [hl], b
    ld d, d
    ldh [rKEY1], a
    sbc $01
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    ld a, [de]
    sub b
    ld d, e
    sub b
    ld c, l
    add sp, $01
    jr jr_003_4e31

    ld e, $ff
    nop
    ld a, [de]
    ret nc

    ld l, c
    ret nc

    ld h, e
    ld a, [$ff01]
    rst $38
    rst $38
    jr nz, jr_003_4e28

    add hl, de

jr_003_4e28:
    ld [hl], b
    ld d, d
    ldh [rKEY1], a
    sbc $01
    rst $38
    rst $38
    rst $38

jr_003_4e31:
    rst $38
    nop
    ld a, [de]
    ld d, b
    ld b, [hl]
    ld d, b
    ld b, b
    xor $01
    ld a, [hl-]
    rst $38
    rst $38
    rst $38
    ld [bc], a
    ld a, [de]
    sub b
    ld d, e
    sub b
    ld c, l
    add sp, $01
    jr jr_003_4e61

    ld e, $ff
    nop
    ld a, [de]
    ld d, b
    ld b, [hl]
    ld d, b
    ld b, b
    xor $01
    ld a, [hl-]
    rst $38
    rst $38
    rst $38
    ld [bc], a
    add hl, de
    add b
    ld e, c
    and b
    ld d, e
    ld a, [bc]
    ld [bc], a
    rst $38
    rst $38
    rst $38

jr_003_4e61:
    rst $38
    nop
    ld a, [de]
    ret nc

    ld e, e
    ldh [rHDMA5], a
    inc d
    ld [bc], a
    rla
    ld [hl-], a
    rst $38
    rst $38
    nop
    ld a, [de]
    ret nc

    ld e, e
    ldh [rHDMA5], a
    inc d
    ld [bc], a
    rla
    ld [hl-], a
    rst $38
    rst $38
    nop
    dec de
    ldh a, [$7e]
    ld h, b
    ld a, l
    call nz, $ff01
    rst $38
    rst $38
    rst $38
    nop
    ld a, [de]
    ret nc

    ld e, e
    ldh [rHDMA5], a
    inc d
    ld [bc], a
    rla
    ld [hl-], a
    rst $38
    rst $38
    nop
    dec de
    jr nc, jr_003_4eff

    sub b
    ld h, e
    rra
    ld [bc], a
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $f019
    ld l, e
    db $10
    ld h, [hl]
    ld a, [hl+]
    ld [bc], a
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $c01b
    ld b, l
    nop
    ld b, b
    cpl
    ld [bc], a
    ld [de], a
    rst $38
    rst $38
    rst $38
    nop
    add hl, de
    ld d, b
    ld [hl], e
    ld h, b
    ld l, l
    scf
    ld [bc], a
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    dec de
    ret nz

    ld d, b
    and b
    ld c, h
    ld b, c
    ld [bc], a
    rst $38
    rst $38
    rst $38
    rst $38
    ld bc, $a01b
    ld e, [hl]
    ret nz

    ld e, b
    ld c, l
    ld [bc], a
    dec d
    ld [hl], $ff
    rst $38
    nop
    add hl, de
    sub b
    ld h, c
    or b
    ld e, e
    ld d, l
    ld [bc], a
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    dec de
    ret nc

    ld [hl], d
    db $10
    ld l, l
    ld e, a
    ld [bc], a
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    dec de
    jr nz, jr_003_4f71

    ld [hl], b
    db $76
    ld h, [hl]
    ld [bc], a
    rlca
    rla
    rst $38
    rst $38
    nop

jr_003_4eff:
    ld a, [de]
    ret nc

    ld [hl], a
    ret nc

    ld [hl], c
    ld [hl], d
    ld [bc], a
    ld [de], a
    rst $38
    rst $38
    rst $38
    ld bc, $5019
    ld a, e
    ldh a, [rPCM12]
    add l
    ld [bc], a
    rst $38
    rst $38
    rst $38
    ld b, l
    ld bc, $84fa
    reti


    and a
    ret z

    ld hl, $d9a1
    inc [hl]
    ret nz

    dec hl
    inc [hl]
    ret nz

    dec hl
    inc [hl]
    ld a, [hl]
    cp $50
    ret c

    ld a, $50
    ld [hl], a
    ret


    ld hl, $4f61
    ld a, [$d2dd]
    ld c, a
    ld b, $00
    add hl, bc
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [hl+]
    ld [$d806], a
    and a
    jr z, jr_003_4f52

    push hl
    ld de, $d807
    ld bc, $0014
    call Call_000_01bb
    pop hl
    ld bc, $0014
    add hl, bc

jr_003_4f52:
    ld a, [hl+]
    ld [$d823], a
    and a
    ret z

    ld de, $d824
    ld bc, $0014
    jp Jump_000_01bb


    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c

jr_003_4f71:
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, l
    ld d, c
    ld l, e
    ld d, c
    xor l
    ld d, c
    dec b
    ld d, d
    ld e, l
    ld d, d
    ld [hl], e
    ld d, d
    dec c
    ld d, e
    rst $30
    ld d, d
    ld b, a
    ld d, d
    bit 2, d
    adc c
    ld d, d
    pop hl
    ld d, d
    sub l
    ld d, e
    xor e
    ld d, e
    pop bc
    ld d, e
    rst $10
    ld d, e
    db $ed
    ld d, e
    inc bc
    ld d, h
    ld [hl], c
    ld d, h
    ld [hl], c
    ld d, h
    ld c, l
    ld d, l
    add c
    ld d, c
    rst $08
    ld d, l
    dec de
    ld d, d
    ld sp, $5352
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    sub a
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    jp $d951


    ld d, c
    rst $28
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    sbc a
    ld d, d
    cp c
    ld d, l
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld de, $5356
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    inc hl
    ld d, e

Call_003_507f:
    dec h
    ld d, e
    daa
    ld d, e
    dec a
    ld d, e
    ld d, e
    ld d, e
    ld l, c
    ld d, e
    ld a, a
    ld d, e
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    sbc l
    ld d, h
    or e
    ld d, h
    ret


    ld d, h
    rst $18
    ld d, h
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    push af
    ld d, h
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    add a
    ld d, h
    ld d, e
    ld d, c
    push hl
    ld d, l
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    daa
    ld d, [hl]
    ei
    ld d, l
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    dec bc
    ld d, l
    ld hl, $3755
    ld d, l
    cpl
    ld d, h
    ld b, l
    ld d, h
    ld e, e
    ld d, h
    add hl, de
    ld d, h
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    adc l
    ld d, l
    and e
    ld d, l
    ld [hl], a
    ld d, l
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    or l
    ld d, d
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    ld d, e
    ld d, c
    rst $38
    rst $38
    nop
    nop
    add hl, de
    inc bc
    inc h
    inc bc
    and l
    inc bc
    and l
    ld [bc], a
    and l
    ld [bc], a
    inc h
    inc bc
    inc h
    inc bc
    inc h
    inc b
    and l
    inc b
    inc h
    dec b
    inc h
    nop
    add hl, de
    inc bc
    and l
    inc bc
    inc h
    inc b
    inc h
    inc b
    and l
    dec b
    inc h
    inc bc
    ld a, e
    ld [bc], a
    and l
    dec b
    and l
    inc b
    ld a, e
    dec b
    ld a, e
    nop
    add hl, de
    inc bc
    and l
    inc bc
    rrca
    inc b
    and l
    inc b
    rrca
    ld [bc], a
    and l
    ld [bc], a
    rrca
    inc bc
    dec b
    dec b
    dec b
    inc bc
    inc bc
    inc b
    inc bc
    nop
    ld [$7b04], sp
    dec b
    ld a, h
    inc bc
    ld a, e
    dec b
    ld a, e
    inc b
    ld a, h
    ld b, $7c
    inc b
    ld [hl], c
    inc bc
    ld [hl], b
    inc bc
    ld d, h
    dec b
    ld d, h
    nop
    inc d
    ld b, $24
    dec b
    dec b
    rlca
    inc h
    ld b, $05
    rlca
    dec b
    ld [$0824], sp
    dec b
    inc bc
    ld h, h
    dec b
    ld h, h
    rlca
    ld h, h
    nop
    ld a, [bc]
    ld [$076b], sp
    ld l, e
    add hl, bc
    ld l, e
    ld [$06a9], sp
    ld l, e
    ld a, [bc]
    ld l, e
    ld a, [bc]
    xor c
    ld [$0b6d], sp
    ld l, e
    ld [$0004], sp
    ld a, [bc]
    ld [$076b], sp
    ld l, e
    rlca
    xor c
    ld [$09a9], sp
    ld l, e
    ld a, [bc]
    ld l, l
    ld a, [bc]
    ld l, e
    dec bc
    ld l, e
    add hl, bc
    inc b
    add hl, bc
    xor c
    nop
    ld a, [bc]
    add hl, bc
    ld l, e
    add hl, bc
    xor c
    ld a, [bc]
    ld l, e
    ld a, [bc]
    xor c
    dec bc
    ld l, e
    ld a, [bc]
    ld l, l
    inc c
    ld l, l
    ld a, [bc]
    inc b
    inc c
    ld l, e
    inc c
    inc b
    nop
    inc d
    ld a, [bc]
    and l
    ld a, [bc]
    dec b
    ld [$06a5], sp
    ld h, b
    ld [$0a05], sp
    ld h, b
    inc c
    and l
    inc c
    dec b
    ld [$0c60], sp
    ld h, b
    nop
    add hl, de
    rlca
    ld a, e
    ld [$0c7c], sp
    inc h
    inc c
    cp h
    dec c
    cp h
    ld a, [bc]
    sub h
    ld c, $bc
    dec c
    inc h
    ld [$0c94], sp
    sub h
    nop
    rrca
    ld [$097b], sp
    ld a, h
    dec c
    inc h
    inc c
    cp h
    dec c
    cp h
    inc c
    sub h
    ld c, $bc
    ld a, [bc]
    sub h
    rlca
    ld [hl], c
    ld [$0070], sp
    rrca
    db $10
    and l
    db $10
    dec b
    ld c, $a5
    dec bc
    ld h, b
    dec c
    dec b
    rrca
    ld h, b
    ld de, $11a5
    dec b
    dec c
    ld h, b
    ld de, $0060
    rrca
    dec c
    cp h
    dec c
    inc h
    rrca
    inc h
    ld a, [bc]
    ld c, l
    inc c
    ld c, l
    rrca
    cp h
    db $10
    cp h
    db $10
    inc h
    ld c, $4d
    db $10
    ld c, l
    nop
    rrca
    dec c
    cp h
    dec c
    inc h
    rrca
    inc h
    ld a, [bc]
    ld c, l
    inc c
    ld c, l
    rrca
    cp h
    db $10
    cp h
    db $10
    inc h
    ld c, $4d
    db $10
    ld c, l
    nop
    rrca
    ld c, $60
    rrca
    dec b
    inc c
    ld h, b
    add hl, bc
    jr nc, jr_003_52a0

    dec b
    dec c
    jr nc, jr_003_52a6

    ld h, b
    ld de, $0b05
    jr nc, jr_003_52ac

    jr nc, jr_003_529f

jr_003_529f:
    rrca

jr_003_52a0:
    db $10
    ld l, e
    ld de, $116b
    xor c

jr_003_52a6:
    rrca
    ld l, d
    db $10
    xor c
    ld [de], a
    ld l, e

jr_003_52ac:
    rrca
    ld l, e
    ld de, $0d6a
    ld [hl+], a
    rrca
    ld [hl+], a
    nop
    rrca
    db $10
    ld l, e
    ld de, $116b
    xor c
    rrca
    ld l, d
    db $10
    xor c
    ld [de], a
    ld l, e
    ld de, $116a
    ld [hl+], a
    dec c
    ld [hl+], a
    ld [de], a
    xor c
    nop
    rrca
    db $10
    ld b, $10
    dec b
    ld c, $06
    dec bc
    ld h, b
    dec c
    dec b
    rrca
    ld h, b
    ld de, $1106
    dec b
    dec c
    ld h, b
    ld de, $0060
    rrca
    jr jr_003_52a0

    add hl, de
    inc h
    rla
    inc h
    jr jr_003_532b

    ld d, $bc
    ld a, [de]
    ld b, c
    ld a, [de]
    cp h
    dec de
    inc h
    inc e
    cp l
    ld e, $bd
    nop
    rrca
    ld [de], a
    inc h
    ld [de], a
    ld c, l
    ld de, $1060
    ld d, d
    inc d
    inc h
    inc d
    ld c, l
    inc de
    ld h, b
    ld de, $0f52
    ld d, d
    ld [de], a
    ld d, d
    nop
    rrca
    inc de
    inc h
    inc de
    cp h
    ld de, $164d
    cp h
    ld d, $24
    ld [de], a
    ld c, l
    ld [de], a
    ld d, d
    inc d
    ld d, d
    inc de
    ld c, l
    inc d
    ld c, l
    nop
    nop
    nop
    nop
    nop
    ld a, [bc]
    inc d
    add hl, de
    dec d

jr_003_532b:
    add hl, de
    ld d, $19
    rla
    add hl, de
    inc de
    add hl, de
    ld [de], a
    add hl, de
    jr @+$1b

    inc d
    ld de, $1116
    add hl, de
    sub e
    nop
    ld a, [bc]
    inc d
    add hl, de
    dec d
    add hl, de
    ld d, $19
    rla
    add hl, de
    inc de
    add hl, de
    ld [de], a
    add hl, de
    add hl, de
    sub e
    inc d
    ld de, $1116
    jr jr_003_536b

    nop
    ld a, [bc]

jr_003_5354:
    inc d
    add hl, de
    dec d
    add hl, de
    ld d, $19
    rla
    add hl, de
    inc de
    add hl, de
    ld [de], a
    add hl, de
    add hl, de
    sub e
    inc d
    ld de, $1116
    jr jr_003_5381

    nop
    rrca

jr_003_536a:
    dec d

jr_003_536b:
    add hl, de
    ld d, $19
    rla
    add hl, de
    jr jr_003_538b

    inc d
    add hl, de
    inc de
    add hl, de
    ld a, [de]
    sub e
    ld d, $11
    jr @+$13

    inc e
    sub e
    nop
    rrca

jr_003_5380:
    dec d

jr_003_5381:
    add hl, de
    ld d, $19
    rla
    add hl, de
    jr jr_003_53a1

    inc d
    add hl, de
    inc e

jr_003_538b:
    sub e
    ld d, $11
    jr jr_003_53a1

    inc e
    sub e
    ld e, $93
    nop
    inc d
    jr jr_003_5354

    add hl, de
    inc h
    dec de
    inc h
    jr jr_003_53df

    ld d, $bc
    ld a, [de]

jr_003_53a1:
    ld b, c
    ld a, [de]
    cp h
    add hl, de
    ld c, h
    inc e
    cp l
    ld e, $bd
    nop
    rrca
    jr jr_003_536a

    ld a, [de]
    inc h
    rla
    ld c, h
    jr @+$43

    ld d, $bc
    ld a, [de]
    ld b, c
    ld a, [de]
    cp h
    ld e, $bd
    inc e
    sub [hl]
    ld e, $96
    nop
    rrca
    jr jr_003_5380

    ld a, [de]
    ld c, h
    rla
    inc h
    ld a, [de]
    ld b, c
    ld d, $bc
    inc e
    ld b, c
    ld a, [de]
    cp h
    ld e, $bd
    inc e
    sub [hl]
    ld e, $96
    nop
    add hl, de
    inc d
    dec b
    ld d, $05
    ld [de], a
    and l
    inc d

jr_003_53df:
    ld b, [hl]
    inc d
    and l
    ld [de], a
    ld b, [hl]
    ld d, $46
    ld d, $a5
    rla
    and [hl]
    add hl, de
    and [hl]
    nop
    add hl, de
    inc d
    dec b
    ld d, $05
    add hl, de
    and [hl]
    jr jr_003_543c

    dec de
    and [hl]
    ld a, [de]
    ld b, [hl]
    inc e
    ld b, [hl]
    dec e
    and [hl]
    add hl, de
    inc hl
    dec de
    inc hl
    nop
    add hl, de
    inc d
    dec b
    ld d, $05
    add hl, de
    and [hl]
    jr jr_003_5452

    add hl, de
    inc hl
    ld a, [de]
    ld b, [hl]
    inc e
    ld b, [hl]
    dec e
    and [hl]
    dec de
    inc hl
    dec e
    inc hl
    nop
    ld e, $16
    rrca
    add hl, de
    ld [de], a
    ld d, $41
    jr @+$0e

    rra
    xor b
    add hl, de
    inc c
    rra
    and a
    ld e, $2e
    rla
    dec e
    rla
    jr z, jr_003_542f

jr_003_542f:
    ld e, $18
    rrca
    ld a, [de]
    ld b, [hl]
    ld d, $6d
    add hl, de
    inc c
    ld hl, $17a8
    inc c

jr_003_543c:
    jr jr_003_5441

    add hl, de
    ld l, $19

jr_003_5441:
    ld [bc], a
    inc e
    dec e
    nop
    ld e, $16
    rrca
    ld a, [de]
    ld [de], a
    rla
    ld l, l
    add hl, de
    inc c
    ld e, $a8
    dec de
    inc c

jr_003_5452:
    ld e, $a7
    jr nz, jr_003_54cd

    ld a, [de]
    jr z, @+$1e

    inc a
    nop
    ld e, $19
    rrca
    ld a, [de]
    ld b, [hl]
    rla
    ld b, c
    jr jr_003_5470

    ld hl, $1aa8
    inc c
    add hl, de
    inc bc
    rra
    ld [hl], a
    ld a, [de]
    inc a
    inc e
    ld [bc], a

jr_003_5470:
    nop
    nop
    dec b
    dec b
    jr jr_003_5480

jr_003_5476:
    jr @+$11

    jr @+$07

    jr jr_003_5486

    jr @+$11

    jr jr_003_5494

jr_003_5480:
    jr jr_003_54a0

    jr jr_003_54a7

    jr jr_003_54ae

jr_003_5486:
    jr jr_003_5497

    ld e, $3a
    ld e, $2f
    ld e, $1b
    ld e, $4e
    inc e
    ld c, [hl]
    dec d
    ld l, e

jr_003_5494:
    dec e
    add d
    inc e

jr_003_5497:
    dec h
    inc e
    dec de
    ld h, $08
    nop
    ld a, [bc]
    ld e, $17

jr_003_54a0:
    ld e, $4e
    jr nz, @+$1d

    jr nz, jr_003_54f4

    inc e

jr_003_54a7:
    cpl
    ld e, $3a
    ld e, $2f
    inc e
    ld a, [hl-]

jr_003_54ae:
    ld h, $78
    dec h
    adc d
    nop
    ld a, [bc]
    ld e, $3a

jr_003_54b6:
    ld e, $2f
    jr nz, jr_003_54f4

    jr nz, jr_003_54eb

    inc e
    ld c, [hl]
    ld e, $17
    ld e, $4e
    inc e
    dec de
    ld e, $82
    dec h
    add b
    nop
    ld a, [bc]
    rra
    cpl

jr_003_54cc:
    rra

jr_003_54cd:
    ld a, [hl-]
    ld hl, $212f
    ld a, [hl-]
    dec e
    ld c, [hl]
    rra
    dec de
    rra
    ld c, [hl]
    dec e
    dec de
    daa
    adc d
    dec h
    ld a, b
    nop
    ld a, [bc]
    rra
    ld c, [hl]
    rra

jr_003_54e3:
    dec de
    ld hl, $214e
    dec de
    dec e
    cpl
    rra

jr_003_54eb:
    ld a, [hl-]
    rra
    cpl
    dec e
    ld a, [hl-]
    daa
    add b

jr_003_54f2:
    jr nz, jr_003_5476

jr_003_54f4:
    nop
    ld a, [bc]
    jr nz, jr_003_5505

    ld e, $0d
    ld [hl+], a
    and e
    ld e, $a3
    ld [hl+], a
    ld d, d
    jr nz, @-$5b

    ld e, $37
    inc e

jr_003_5505:
    and e
    dec h
    adc b
    daa
    adc a
    nop
    ld a, [bc]
    jr nz, @+$54

    ld [hl+], a
    dec c
    ld [hl+], a
    dec c
    ld e, $a3
    ld e, $0d
    jr nz, @-$5b

    ld e, $37
    inc e
    and e
    daa
    adc b
    dec h
    adc a
    nop
    ld a, [bc]
    rra
    dec c
    ld hl, $2352
    dec c
    jr nz, jr_003_54cd

    ld [hl+], a
    inc sp
    jr z, jr_003_54b6

    ld [hl+], a
    scf
    ld h, $88
    inc h
    and e
    ld a, [hl+]
    adc a
    nop
    ld a, [bc]
    ld hl, $1f0d
    dec c
    inc hl
    ld d, d
    jr nz, jr_003_54e3

    rra
    dec c
    jr z, jr_003_54cc

    ld [hl+], a
    and e
    inc hl
    scf
    ld h, $33
    ld a, [hl+]
    adc a
    nop
    add hl, de
    dec d
    and l
    rla
    inc h
    ld e, $a6
    rla
    and l
    dec d
    inc h
    ld e, $96
    jr nz, jr_003_54f2

    inc e
    ld e, $1e
    ld e, $20
    ld e, $05
    dec b
    jr jr_003_5570

    jr @+$11

    jr @+$07

    jr jr_003_5576

    jr @+$11

    jr jr_003_5584

jr_003_5570:
    jr jr_003_5590

    jr @+$25

    jr jr_003_559e

jr_003_5576:
    jr jr_003_5582

jr_003_5578:
    ld l, $82
    ld l, $81
    ld l, $36
    ld sp, $3174
    ld [hl], a

jr_003_5582:
    inc [hl]
    ld h, c

jr_003_5584:
    ld sp, $3426
    ld l, $35

jr_003_5589:
    ld d, l
    dec [hl]
    ld c, h
    nop
    rrca
    inc sp
    ld [hl], h

jr_003_5590:
    inc sp
    ld [hl], a
    inc sp

jr_003_5593:
    ld h, $34
    ld bc, $9134
    inc [hl]
    adc l
    jr c, jr_003_55c4

    ld [hl], $65

jr_003_559e:
    scf
    ld c, h
    inc a
    ld c, h
    nop
    add hl, de
    scf
    ld bc, $9137
    scf
    adc l
    ld b, b
    jr z, jr_003_55ed

    ld l, $40
    ld d, l
    add hl, sp
    ld h, c
    ld b, c
    ld c, h
    ccf
    ld c, h
    ld b, e
    ld c, h
    nop
    ld a, [bc]
    dec d
    ld b, $15
    xor l
    inc d
    ld d, h
    jr jr_003_5616

    rla
    xor l

jr_003_55c4:
    rla
    ld b, $20
    ld [hl], $23
    ld [hl], $21
    ld d, l
    inc h
    ld d, l
    nop
    ld a, [bc]
    ld a, [de]
    ld h, b
    ld hl, $1a4c
    dec b
    ld h, $23
    ld h, $4c
    ld h, $23
    add hl, hl
    ld h, c
    dec hl
    ld c, h
    add hl, hl
    inc hl
    dec hl
    inc hl
    nop
    ld a, [bc]
    ld d, $6a
    jr jr_003_5593

    ld a, [de]
    ld l, e
    inc h

jr_003_55ed:
    ld [hl+], a
    daa
    ld [hl+], a
    ld a, [hl+]
    ld [hl+], a
    add hl, hl
    add hl, hl
    jr z, jr_003_5578

    jr z, jr_003_5589

    dec hl
    daa
    nop
    rrca
    jr jr_003_5668

    ld a, [de]
    xor c
    ld d, $6b
    ld a, [hl+]
    ld [hl+], a
    jr z, jr_003_567d

    dec l
    ld [hl+], a
    dec hl
    daa
    add hl, hl
    add d
    ld a, [hl+]
    add hl, hl
    dec l
    add hl, hl
    nop
    rrca
    jr jr_003_567e

    ld a, [de]
    xor c

jr_003_5616:
    ld d, $6b
    inc h
    ld [hl+], a
    daa
    ld [hl+], a
    ld a, [hl+]
    ld [hl+], a
    add hl, hl
    daa
    add hl, hl
    add d
    ld a, [hl+]
    add hl, hl
    dec hl
    sub c
    nop
    inc d
    ld [de], a
    dec sp
    inc de
    dec sp
    ld de, $143b
    dec sp
    db $10
    dec sp
    rrca
    dec sp
    dec d
    dec sp
    ld d, $3b
    dec e
    db $76
    rra
    halt
    ld a, $01
    ld [$cd65], a
    ld a, [$cf78]
    cp $c4
    jp nc, Jump_003_663a

    ld hl, $5657
    dec a
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp hl


    db $fd
    ld d, [hl]
    db $fd
    ld d, [hl]
    db $fd
    ld d, [hl]
    db $fd
    ld d, [hl]
    add d
    ld e, d
    sub c
    ld e, d
    adc $5a
    db $fd
    ld d, [hl]
    ld [hl], d

jr_003_5668:
    ld e, e
    ld [hl], a
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e

jr_003_567d:
    rst $10

jr_003_567e:
    ld e, e
    ld d, c
    ld h, b
    ld h, [hl]
    ld h, b
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    cp [hl]
    ld h, b
    ld [de], a
    ld h, c
    scf
    ld h, [hl]
    ld [hl], a
    ld e, e
    ld [hl], a
    ld e, e
    ld [hl], a
    ld e, e
    ret nc

    ld e, e
    ret nc

    ld e, e
    ret nc

    ld e, e
    ret nc

    ld e, e
    ret nc

    ld e, e
    ret nc

    ld e, e
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    ld [hl+], a
    ld h, c
    ld [hl], a
    ld e, e
    ld sp, $3761
    ld h, [hl]
    scf
    ld h, [hl]
    call c, $d761
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    db $eb
    ld h, c
    ld a, [$ff61]
    ld h, c
    inc b
    ld h, d
    scf
    ld h, [hl]
    rst $10
    ld e, e
    rst $10
    ld e, e
    rst $10
    ld e, e
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    inc de
    ld h, d
    inc de
    ld h, d
    inc de
    ld h, d
    inc de
    ld h, d
    ld a, e
    ld h, e
    dec l
    ld h, h
    jr nc, @+$66

    scf
    ld h, [hl]
    ld c, a
    ld h, d
    scf
    ld h, [hl]
    scf
    ld h, [hl]
    sbc e
    ld h, e
    xor b
    ld h, e
    jp nc, $9c63

    ld h, h
    and e
    ld h, h
    and e
    ld h, h
    and e
    ld h, h
    and e
    ld h, h
    ld a, [$d034]
    and a
    jp z, Jump_003_679f

    dec a
    jp nz, Jump_003_67a9

    ld a, [$d123]
    cp $06
    jr nz, jr_003_5717

    ld a, [$d9b2]
    cp $1e
    jp z, Jump_003_67cf

jr_003_5717:
    xor a
    ld [$d0e1], a
    ld a, [$d037]
    cp $02
    jr nz, jr_003_5726

    ld hl, $d983
    dec [hl]

jr_003_5726:
    call Call_000_3e1d
    ld a, $43
    ld [$d0e3], a
    call Call_000_376d
    ld hl, $68a9
    call Call_000_3c79
    ld hl, $59a0
    ld b, $0f
    call Call_000_3620
    ld b, $10
    jp z, Jump_003_5871

    ld a, [$d037]
    dec a
    jr nz, jr_003_5759

    ld hl, $d806
    ld de, $d11d
    ld bc, $0006
    call Call_000_01bb
    jp Jump_003_57fb


jr_003_5759:
    ld a, [$d2dd]
    cp $93
    jr nz, jr_003_576a

    ld a, [$cfbf]
    cp $91
    ld b, $10
    jp z, Jump_003_5871

jr_003_576a:
    call Call_000_3e8c
    ld b, a
    ld hl, $cf78
    ld a, [hl]
    cp $01
    jp z, Jump_003_57fb

    cp $04
    jr z, jr_003_578a

    ld a, $c8
    cp b
    jr c, jr_003_576a

    ld a, [hl]
    cp $03
    jr z, jr_003_578a

    ld a, $96
    cp b
    jr c, jr_003_576a

jr_003_578a:
    ld a, [$cfd0]
    and a
    jr z, jr_003_579e

    and $27
    ld c, $0c
    jr z, jr_003_5798

    ld c, $19

jr_003_5798:
    ld a, b
    sub c
    jp c, Jump_003_57fb

    ld b, a

jr_003_579e:
    push bc
    xor a
    ldh [$96], a
    ld hl, $cfdb
    ld a, [hl+]
    ldh [$97], a
    ld a, [hl]
    ldh [$98], a
    ld a, $ff
    ldh [$99], a
    call Call_000_38f5
    ld a, [$cf78]
    cp $03
    ld a, $0c
    jr nz, jr_003_57bd

    ld a, $08

jr_003_57bd:
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ld hl, $cfcd
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    srl b
    rr a
    srl b
    rr a
    and a
    jr nz, jr_003_57d6

    inc a

jr_003_57d6:
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$97]
    and a
    jr z, jr_003_57e6

    ld a, $ff
    ldh [$98], a

jr_003_57e6:
    pop bc
    ld a, [$cfee]
    cp b
    jr c, jr_003_57fd

    ldh a, [$97]
    and a
    jr nz, jr_003_57fb

    call Call_000_3e8c
    ld b, a
    ldh a, [$98]
    cp b
    jr c, jr_003_57fd

Jump_003_57fb:
jr_003_57fb:
    jr jr_003_5875

jr_003_57fd:
    ldh a, [$98]
    ld [$d0e3], a
    xor a
    ldh [$96], a
    ldh [$97], a
    ld a, [$cfee]
    ldh [$98], a
    ld a, $64
    ldh [$99], a
    call Call_000_38f5
    ld a, [$cf78]
    ld b, $ff
    cp $04
    jr z, jr_003_5828

    ld b, $c8
    cp $03
    jr z, jr_003_5828

    ld b, $96
    cp $02
    jr z, jr_003_5828

jr_003_5828:
    ld a, b
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$97]
    and a
    ld b, $63
    jr nz, jr_003_5871

    ld a, [$d0e3]
    ldh [$99], a
    call Call_000_38f5
    ld a, $ff
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ld a, [$cfd0]
    and a
    jr z, jr_003_585b

    and $27
    ld b, $05
    jr z, jr_003_5856

    ld b, $0a

jr_003_5856:
    ldh a, [$98]
    add b
    ldh [$98], a

jr_003_585b:
    ldh a, [$98]
    cp $0a
    ld b, $20
    jr c, jr_003_5871

    cp $1e
    ld b, $61
    jr c, jr_003_5871

    cp $46
    ld b, $62
    jr c, jr_003_5871

    ld b, $63

Jump_003_5871:
jr_003_5871:
    ld a, b
    ld [$d0e3], a

jr_003_5875:
    ld c, $14
    call Call_000_3781
    ld a, $c1
    ld [$d059], a
    xor a
    ldh [$f3], a
    ld [$cc5b], a
    ld [$d038], a
    ld a, [$cf79]
    push af
    ld a, [$cf78]
    push af
    ld a, $08
    call Call_000_3e9d
    pop af
    ld [$cf78], a
    pop af
    ld [$cf79], a
    ld a, [$d0e3]
    cp $10
    ld hl, $59a7
    jp z, Jump_003_5992

    cp $20
    ld hl, $59c0
    jp z, Jump_003_5992

    cp $61
    ld hl, $59d1
    jp z, Jump_003_5992

    cp $62
    ld hl, $59e9
    jp z, Jump_003_5992

    cp $63
    ld hl, $59fd
    jp z, Jump_003_5992

    ld hl, $cfcd
    ld a, [hl+]
    push af
    ld a, [hl+]
    push af
    inc hl
    ld a, [hl]
    push af
    push hl
    ld hl, $d046
    bit 3, [hl]
    jr z, jr_003_58e1

    ld a, $4c
    ld [$cfbf], a
    jr jr_003_58ee

jr_003_58e1:
    set 3, [hl]
    ld hl, $cceb
    ld a, [$cfd8]
    ld [hl+], a
    ld a, [$cfd9]
    ld [hl], a

jr_003_58ee:
    ld a, [$cf78]
    push af
    ld a, [$cfbf]
    ld [$cf78], a
    ld a, [$cfda]
    ld [$d0ec], a
    ld hl, $6df1
    ld b, $0f
    call Call_000_3620
    pop af
    ld [$cf78], a
    pop hl
    pop af
    ld [hl-], a
    dec hl
    pop af
    ld [hl-], a
    pop af
    ld [hl], a
    ld a, [$cfcc]
    ld [$d0e1], a
    ld [$cf78], a
    ld [$d0e3], a
    ld a, [$d037]
    dec a
    jr z, jr_003_598f

    ld hl, $5a16
    call Call_000_3c79
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $02
    ld hl, $d27b
    ld a, $10
    call Call_000_3e9d
    ld a, c
    push af
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $01
    ld a, $10
    call Call_000_3e9d
    pop af
    and a
    jr nz, jr_003_5964

    ld hl, $5a5f
    call Call_000_3c79
    call Call_000_0188
    ld a, [$cfcc]
    ld [$d0e3], a
    ld a, $3d
    call Call_000_3e9d

jr_003_5964:
    ld a, [$d123]
    cp $06
    jr z, jr_003_5977

    xor a
    ld [$cc49], a
    call Call_000_0188
    call Call_000_3971
    jr jr_003_5998

jr_003_5977:
    call Call_000_0188
    call Call_003_6aaf
    ld hl, $5a2f
    ld a, [$d770]
    bit 0, a
    jr nz, jr_003_598a

    ld hl, $5a48

jr_003_598a:
    call Call_000_3c79
    jr jr_003_5998

jr_003_598f:
    ld hl, $5a16

Jump_003_5992:
    call Call_000_3c79
    call Call_000_0188

jr_003_5998:
    ld a, [$d037]
    and a
    ret nz

    ld hl, $d2a1
    inc a
    ld [$cf7d], a
    jp Jump_000_16cc


    nop
    sub $b9
    rst $10
    jp c, $e7c0

    ld c, a
    cp d
    or d
    jp nz, Jump_003_7fca

    jp nz, $cfb6

    ret c

    cp a
    or e
    add $c5
    or d
    cpl
    rst $20
    ld e, b
    db $ed
    inc l
    cp [hl]
    ld h, [hl]
    or e
    rst $08
    cp b
    ld a, a
    or c
    ret nz

    rst $10
    push bc
    or [hl]
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    inc l
    sbc $66
    sbc $e7
    ld a, a
    ld d, h
    ld h, $4f
    inc e
    db $e3
    and [hl]
    or [hl]
    rst $10
    ld a, a
    inc sp
    jp $cfbc


    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    dec l
    xor e
    ld e, d
    ld c, a
    jp nz, $cfb6

    or h
    ret nz

    call nz, $b57f
    db $d3
    rst $18
    ret nz

    ret


    add $e7
    ld e, b
    db $ed
    dec l
    ld c, b
    ld l, b
    rst $20
    ld c, a
    or c
    call nz, $c17f
    ld [c], a
    rst $18
    call nz, Call_003_7fc9
    call nz, $dbba
    jr nc, @-$1f

    ret nz

    ret


    add $e7
    ld e, b
    db $ed
    jr z, @+$36

    ld h, e
    db $e3
    rst $20
    ld c, a
    ld d, b
    ld bc, $cfc1
    nop
    db $dd

jr_003_5a23:
    ld a, a
    jp nz, $cfb6

    or h
    ret nz

    cpl
    rst $20
    ld d, b
    ld [de], a
    ld b, $50
    db $ed
    dec l
    jr z, @+$5b

    jp z, $9d7f

    adc d
    add [hl]
    ret


    ld a, a
    call nz, $dbba
    call $c34f
    sbc $bf
    or e
    cp e
    jp c, $e7c0

    ld e, b
    db $ed
    jr z, jr_003_5a59

    ld h, e
    jp z, $307f

    jp c, $c9b6

    ld a, a
    ld e, e
    add $4f
    jp $bfde


jr_003_5a59:
    or e
    cp e
    jp c, $e7c0

    ld e, b
    db $ed
    jr z, jr_003_5a23

    ld h, d
    ret


    ld a, a
    ld [de], a
    db $e3
    adc a
    ld h, $7f
    or c
    ret nz

    rst $10
    cp h
    cp b
    ld c, a
    ld d, h
    dec l
    or [hl]
    sbc $c6
    ld a, a
    adc l
    db $e3
    dec de
    cp e
    jp c, $bdcf

    rst $20
    ld d, b
    inc de
    ld b, $50
    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    ld b, $1c
    ld hl, $53aa
    jp Jump_000_3620


    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    ld a, [$d67f]
    ld [$d0df], a
    cp $02
    jp z, Jump_003_679f

    dec a
    jr nz, jr_003_5ab5

    call Call_003_6cd0
    xor a
    ld [$d67f], a
    call Call_000_0d9b
    ld hl, $68c9
    jr jr_003_5acb

jr_003_5ab5:
    call Call_000_23dc
    jp nc, Jump_003_67ca

    call Call_003_6cd0
    xor a
    ldh [$b4], a
    inc a
    ld [$d67f], a
    ld hl, $68ba
    call Call_000_0d9b

jr_003_5acb:
    jp Jump_000_3c79


    ld a, [$d67f]
    ld [$d0df], a
    cp $02
    jr z, jr_003_5af4

    call Call_003_6bc3
    jp c, Jump_003_67d4

    call Call_003_5b31
    ld hl, $d6af
    set 7, [hl]
    ld a, $02
    ld [$d67f], a
    call Call_000_0d9b
    ld hl, $5b55
    jp Jump_000_3c79


jr_003_5af4:
    xor a
    ldh [$8c], a
    ld d, $10
    call Call_000_2584
    res 7, [hl]
    ldh a, [$8c]
    and a
    jr nz, jr_003_5b15

    ld hl, $d4af
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$cfad]
    ld b, a

jr_003_5b0d:
    ld a, [hl+]
    cp b
    jr z, jr_003_5b1b

    cp $ff
    jr nz, jr_003_5b0d

jr_003_5b15:
    ld hl, $5b64
    jp Jump_000_3c79


jr_003_5b1b:
    call Call_003_5b31
    ld hl, $d6af
    set 7, [hl]
    xor a
    ld [$d67f], a
    dec a
    ld [$cd66], a
    call Call_000_0d9b
    jp Jump_000_2a5e


Call_003_5b31:
    ld a, [$d4a9]
    bit 3, a
    ld b, $40
    jr nz, jr_003_5b48

    bit 2, a
    ld b, $80
    jr nz, jr_003_5b48

    bit 1, a
    ld b, $20
    jr nz, jr_003_5b48

    ld b, $10

jr_003_5b48:
    ld a, b
    ld [$ccd3], a
    xor a
    ld [$cd39], a
    inc a
    ld [$cd38], a
    ret


    db $ed
    jr z, @-$7d

    ld h, e
    ld d, b
    ld bc, $cd68
    nop
    add $c9
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    jr z, @-$6a

    ld h, e
    ld a, a
    ld a, [hl-]
    cp h
    ld [c], a
    ld h, $7f
    push bc
    or d
    rst $20
    ld e, b
    ld a, $29
    jp Jump_000_3e9d


    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    ld a, [$cf79]
    push af
    ld a, [$cf78]
    ld [$d11b], a
    push af
    ld a, $05
    ld [$d05a], a
    ld a, $ff
    ld [$cfb2], a
    call Call_000_2df3
    pop bc
    jr c, jr_003_5bca

    ld a, b
    ld [$cf78], a
    ld a, $01
    ld [$ccd4], a
    ld a, $8e
    call Call_000_3788
    call Call_000_3790
    ld hl, $70a1
    ld b, $0e
    call Call_000_3620
    ld a, [$d0e6]
    and a
    jr z, jr_003_5bc7

    pop af
    ld [$cf79], a
    ld hl, $d2a1
    ld a, $01
    ld [$cf7d], a
    jp Jump_000_16cc


jr_003_5bc7:
    call Call_003_679a

jr_003_5bca:
    xor a
    ld [$cd65], a
    pop af
    ret


    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

jr_003_5bd7:
    ld a, [$cf79]
    push af
    ld a, [$cf78]
    push af
    ld a, $01
    ld [$d05a], a
    ld a, $ff
    ld [$cfb2], a
    ld a, [$d117]
    and a
    jr z, jr_003_5bf4

    call Call_000_2e08
    jr jr_003_5bf7

jr_003_5bf4:
    call Call_000_2df3

jr_003_5bf7:
    jp c, Jump_003_5ebd

    ld hl, $d12b
    ld bc, $002c
    ld a, [$cf79]
    call Call_000_3ad1
    ld a, [$cf79]
    ld [$cf01], a
    ld d, a
    ld a, [$cf78]
    ld e, a
    ld [$d092], a
    pop af
    ld [$cf78], a
    pop af
    ld [$cf79], a
    ld a, [$d117]
    and a
    jr z, jr_003_5c28

    ld a, [$cf79]
    cp d
    jr z, jr_003_5bd7

jr_003_5c28:
    ld a, [$cf78]
    cp $35
    jr nc, jr_003_5c9b

    cp $34
    jr z, jr_003_5c3c

    cp $23
    jp nc, Jump_003_5ed6

    cp $10
    jr nc, jr_003_5c9b

Jump_003_5c3c:
jr_003_5c3c:
    ld bc, $0004
    add hl, bc
    ld a, [$cf78]
    ld bc, $f008
    cp $0b
    jr z, jr_003_5c69

    ld bc, $f110
    cp $0c
    jr z, jr_003_5c69

    ld bc, $f220
    cp $0d
    jr z, jr_003_5c69

    ld bc, $f307
    cp $0e
    jr z, jr_003_5c69

    ld bc, $f440
    cp $0f
    jr z, jr_003_5c69

    ld bc, $f6ff

jr_003_5c69:
    ld a, [hl]
    and c
    jp z, Jump_003_5e59

    xor a
    ld [hl], a
    ld a, b
    ld [$d05a], a
    ld a, [$cc2f]
    cp d
    jp nz, Jump_003_5e5f

    xor a
    ld [$cfff], a
    push hl
    ld hl, $d041
    res 0, [hl]
    pop hl
    ld bc, $001e
    add hl, bc
    ld de, $d00a
    ld bc, $000a
    call Call_000_01bb
    ld a, $28
    call Call_000_3e9d
    jp Jump_003_5e5f


jr_003_5c9b:
    inc hl
    ld a, [hl+]
    ld b, a
    ld [$cee7], a
    ld a, [hl]
    ld c, a
    ld [$cee6], a
    or b
    jr nz, jr_003_5ce5

    ld a, [$cf78]
    cp $35
    jr z, jr_003_5cb7

    cp $36
    jr z, jr_003_5cb7

    jp Jump_003_5e59


jr_003_5cb7:
    ld a, [$d034]
    and a
    jr z, jr_003_5cf2

    push hl
    push de
    push bc
    ld a, [$cf01]
    ld c, a
    ld hl, $ccf5
    ld b, $02
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    jr z, jr_003_5ce0

    ld a, [$cf01]
    ld c, a
    ld hl, $d035
    ld b, $01
    ld a, $10
    call Call_000_3e9d

jr_003_5ce0:
    pop bc
    pop de
    pop hl
    jr jr_003_5cf2

jr_003_5ce5:
    ld a, [$cf78]
    cp $35
    jp z, Jump_003_5e59

    cp $36
    jp z, Jump_003_5e59

jr_003_5cf2:
    push hl
    push bc
    ld bc, $0020
    add hl, bc
    pop bc
    ld a, [hl+]
    cp b
    jr nz, jr_003_5cff

    ld a, [hl]
    cp c

jr_003_5cff:
    pop hl
    jr nz, jr_003_5d1c

    ld a, [$cf78]
    cp $10
    jp nz, Jump_003_5e59

    inc hl
    inc hl
    ld a, [hl-]
    and a
    jp z, Jump_003_5e59

    ld a, $34
    ld [$cf78], a
    dec hl
    dec hl
    dec hl
    jp Jump_003_5c3c


jr_003_5d1c:
    xor a
    ld [$d060], a
    ld [$c02a], a
    push hl
    push de
    ld bc, $0020
    add hl, bc
    ld a, [hl+]
    ld [$cee5], a
    ld a, [hl]
    ld [$cee4], a
    ld a, [$d117]
    and a
    jp z, Jump_003_5dab

    ld hl, $cee4
    ld a, [hl+]
    push af
    ld a, [hl+]
    push af
    ld a, [hl+]
    push af
    ld a, [hl]
    push af
    ld hl, $d14d
    ld a, [$cf79]
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl+]
    ld [$cee5], a
    ldh [$95], a
    ld a, [hl]
    ld [$cee4], a
    ldh [$96], a
    ld a, $05
    ldh [$99], a
    ld b, $02
    call Call_000_3902
    ld bc, $ffdf
    add hl, bc
    ldh a, [$98]
    push af
    ld b, a
    ld a, [hl]
    ld [$cee6], a
    sub b
    ld [hl-], a
    ld [$cee8], a
    ldh a, [$97]
    ld b, a
    ld a, [hl]
    ld [$cee7], a
    sbc b
    ld [hl], a
    ld [$cee9], a
    ld hl, $c3ab
    ld a, [$cf79]
    ld bc, $0028
    call Call_000_3ad1
    ld a, $8d
    call Call_000_3788
    ld a, $02
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d
    pop af
    ld b, a
    ld hl, $cee7
    pop af
    ld [hl-], a
    pop af
    ld [hl-], a
    pop af
    ld [hl-], a
    pop af
    ld [hl], a
    jr jr_003_5dca

Jump_003_5dab:
    ld a, [$cf78]
    cp $3d
    ld b, $3c
    jr z, jr_003_5dca

    ld b, $50
    jr nc, jr_003_5dca

    cp $3c
    ld b, $32
    jr z, jr_003_5dca

    cp $13
    ld b, $c8
    jr c, jr_003_5dca

    ld b, $32
    jr z, jr_003_5dca

    ld b, $14

jr_003_5dca:
    pop de
    pop hl
    ld a, [hl]
    add b
    ld [hl-], a
    ld [$cee8], a
    ld a, [hl]
    ld [$cee9], a
    jr nc, jr_003_5ddd

    inc [hl]
    ld a, [hl]
    ld [$cee9], a

jr_003_5ddd:
    push de
    inc hl
    ld d, h
    ld e, l
    ld hl, $0021
    add hl, de
    ld a, [$cf78]
    cp $35
    jr z, jr_003_5e03

    ld a, [hl-]
    ld b, a
    ld a, [de]
    sub b
    dec de
    ld b, [hl]
    ld a, [de]
    sbc b
    jr nc, jr_003_5e17

    ld a, [$cf78]
    cp $12
    jr c, jr_003_5e17

    cp $36
    jr z, jr_003_5e17

    jr jr_003_5e30

jr_003_5e03:
    dec hl
    dec de
    ld a, [hl+]
    srl a
    ld [de], a
    ld [$cee9], a
    ld a, [hl]
    rr a
    inc de
    ld [de], a
    ld [$cee8], a
    dec de
    jr jr_003_5e23

jr_003_5e17:
    ld a, [hl+]
    ld [de], a
    ld [$cee9], a
    inc de
    ld a, [hl]
    ld [de], a
    ld [$cee8], a
    dec de

jr_003_5e23:
    ld a, [$cf78]
    cp $10
    jr nz, jr_003_5e30

    ld bc, $ffe1
    add hl, bc
    xor a
    ld [hl], a

jr_003_5e30:
    ld h, d
    ld l, e
    pop de
    ld a, [$cc2f]
    cp d
    jr nz, jr_003_5e4c

    ld a, [hl+]
    ld [$cffc], a
    ld a, [hl-]
    ld [$cffd], a
    ld a, [$cf78]
    cp $10
    jr nz, jr_003_5e4c

    xor a
    ld [$cfff], a

jr_003_5e4c:
    ld hl, $c383
    ld bc, $0028
    inc d

jr_003_5e53:
    add hl, bc
    dec d
    jr nz, jr_003_5e53

    jr jr_003_5e5f

Jump_003_5e59:
    call Call_003_679a
    jp Jump_003_5ec3


Jump_003_5e5f:
jr_003_5e5f:
    ld a, [$d117]
    and a
    jr nz, jr_003_5e6a

    push hl
    call Call_003_678f
    pop hl

jr_003_5e6a:
    ld a, [$cf78]
    cp $10
    jr c, jr_003_5e9b

    cp $34
    jr z, jr_003_5e9b

    ld a, $8d
    call Call_000_3788
    ld a, $02
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d
    ld a, $f7
    ld [$d05a], a
    ld a, [$cf78]
    cp $35
    jr z, jr_003_5ea0

    cp $36
    jr z, jr_003_5ea0

    ld a, $f5
    ld [$d05a], a
    jr jr_003_5ea0

jr_003_5e9b:
    ld a, $8e
    call Call_000_3788

jr_003_5ea0:
    xor a
    ld [$ffba], a
    call Call_000_03bf
    dec a
    ld [$cfb2], a
    call Call_000_2ed0
    ld a, $01
    ld [$ffba], a
    ld c, $32
    call Call_000_3781
    call Call_000_38ae
    jr jr_003_5ec3

Jump_003_5ebd:
    xor a
    ld [$cd65], a
    pop af
    pop af

Jump_003_5ec3:
jr_003_5ec3:
    ld a, [$d117]
    and a
    ret nz

    call Call_000_3e15
    call z, Call_000_3e1d
    ld a, [$d034]
    and a
    ret nz

    jp Jump_000_1b86


Jump_003_5ed6:
    push hl
    ld a, [hl]
    ld [$d092], a
    ld [$d0e3], a
    ld bc, $0021
    add hl, bc
    ld a, [hl]
    ld [$d0ec], a
    call Call_000_2f2e
    push de
    ld a, d
    ld hl, $d257
    call Call_000_2fb1
    pop de
    pop hl
    ld a, [$cf78]
    cp $28
    jp z, Jump_003_5f5f

    push hl
    sub $23
    add a
    ld bc, $0011
    add hl, bc
    add l
    ld l, a
    jr nc, jr_003_5f08

    inc h

jr_003_5f08:
    ld a, $0a
    ld b, a
    ld a, [hl]
    cp $64
    jr nc, jr_003_5f46

    add b
    jr nc, jr_003_5f15

    ld a, $ff

jr_003_5f15:
    ld [hl], a
    pop hl
    call Call_003_5f50
    ld hl, $602c
    ld a, [$cf78]
    sub $22
    ld c, a

jr_003_5f23:
    dec c
    jr z, jr_003_5f2f

jr_003_5f26:
    ld a, [hl+]
    ld b, a
    ld a, $50
    cp b
    jr nz, jr_003_5f26

    jr jr_003_5f23

jr_003_5f2f:
    ld de, $cf45
    ld bc, $000a
    call Call_000_01bb
    ld a, $8e
    call Call_000_0e45
    ld hl, $6000
    call Call_000_3c79
    jp Jump_003_678f


jr_003_5f46:
    pop hl
    ld hl, $601c
    call Call_000_3c79
    jp Jump_000_3e15


Call_003_5f50:
    ld bc, $0022
    add hl, bc
    ld d, h
    ld e, l
    ld bc, $ffee
    add hl, bc
    ld b, $01
    jp Jump_000_3980


Jump_003_5f5f:
    push hl
    ld bc, $0021
    add hl, bc
    ld a, [hl]
    cp $64
    jr z, jr_003_5f46

    inc a
    ld [hl], a
    ld [$d0ec], a
    push hl
    push de
    ld d, a
    ld hl, $4fb5
    ld b, $16
    call Call_000_3620
    pop de
    pop hl
    ld bc, $ffed
    add hl, bc
    ldh a, [$96]
    ld [hl+], a
    ldh a, [$97]
    ld [hl+], a
    ldh a, [$98]
    ld [hl], a
    pop hl
    ld a, [$cf79]
    push af
    ld a, [$cf78]
    push af
    push de
    push hl
    ld bc, $0022
    add hl, bc
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    pop hl
    push bc
    push hl
    call Call_003_5f50
    pop hl
    ld bc, $0023
    add hl, bc
    pop bc
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
    ld a, $f8
    ld [$d05a], a
    call Call_000_2ed0
    pop de
    ld a, d
    ld [$cf79], a
    ld a, e
    ld [$d0e3], a
    xor a
    ld [$cc49], a
    call Call_000_2d68
    ld d, $01
    ld hl, $782c
    ld b, $04
    call Call_000_3620
    call Call_000_38ae
    xor a
    ld [$cc49], a
    ld a, $1a
    call Call_000_3e9d
    xor a
    ld [$ccd4], a
    ld hl, $70a1
    ld b, $0e
    call Call_000_3620
    ld a, $01
    ld [$cfb2], a
    pop af
    ld [$cf78], a
    pop af
    ld [$cf79], a
    jp Jump_003_678f


    db $ed
    dec l
    xor d
    ld e, [hl]
    ret


    ld a, a
    ld d, b
    ld bc, $cf45
    nop
    ret


    ld c, a
    or a
    cp a
    ld a, a
    ld b, e
    add c
    xor e
    sub e
    ld h, $7f
    or c
    ld h, $df
    ret nz

    rst $20
    ld e, b
    db $ed
    jr z, @-$4e

    ld h, e
    jp $7fd3


    cp d
    or e
    or [hl]
    ld h, $7f
    push bc
    or d
    sub $58
    xor b
    or b
    ld d, b
    and c
    or h
    or h
    and c
    and e
    xor e
    ld d, b
    and h
    and l
    and [hl]
    and l
    xor [hl]
    and e
    and l
    ld d, b
    or e
    or b
    or d
    cp c
    ld d, b
    or e
    or h
    or l
    xor [hl]
    or h
    ld d, b
    cp h
    pop hl
    ret


    or e
    ret c

    ld [c], a
    cp b
    ld d, b
    ld hl, $60a4
    call Call_000_3c79
    ld hl, $cfee
    srl [hl]
    ld a, $ca
    ld hl, $cce9
    ld de, $cce8
    jr jr_003_607e

    ld hl, $60b1
    call Call_000_3c79
    ld hl, $cfee
    ld a, [hl]
    add a
    jr nc, jr_003_6075

    ld a, $ff

jr_003_6075:
    ld [hl], a
    ld a, $c9
    ld hl, $cce8
    ld de, $cce9

jr_003_607e:
    ld [$d059], a
    xor a
    ld [$cc5b], a
    ldh [$f3], a
    ld [de], a

jr_003_6088:
    call Call_000_3e8c
    and $07
    cp $05
    jr nc, jr_003_6088

    inc a
    ld b, a
    ld a, [hl]
    add b
    jr nc, jr_003_6099

    ld a, $ff

jr_003_6099:
    ld [hl], a
    ld a, $08
    call Call_000_3e9d

jr_003_609f:
    ld c, $46
    jp Jump_000_3781


    db $ed
    jr z, @-$2b

    ld h, e
    add e
    adc d
    db $dd
    ld a, a
    push bc
    add hl, hl
    ret nz

    rst $20
    ld d, a
    db $ed
    jr z, jr_003_609f

    ld h, e
    or d
    cp h
    db $dd
    ld a, a
    push bc
    add hl, hl
    ret nz

    rst $20
    ld d, a
    ld a, [$d034]
    and a
    jr nz, jr_003_6109

    ld a, [$d2dd]
    cp $f7
    jr z, jr_003_6109

    ld a, [$d2e6]
    ld b, a
    ld hl, $610c

jr_003_60d2:
    ld a, [hl+]
    cp $ff
    jr z, jr_003_6109

    cp b
    jr nz, jr_003_60d2

    ld hl, $d6b1
    set 3, [hl]
    set 6, [hl]
    ld hl, $d6ad
    res 4, [hl]
    ld hl, $d70f
    res 7, [hl]
    xor a
    ld [$d983], a
    ld [$d59e], a
    inc a
    ld [$d055], a
    ld [$cd65], a
    ld a, [$d117]
    and a
    ret nz

    call Call_003_6cd0
    ld c, $1e
    call Call_000_3781
    jp Jump_003_678f


jr_003_6109:
    jp Jump_003_679f


    inc bc
    rrca
    ld de, $1016
    rst $38
    ld b, $64

Jump_003_6114:
    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    ld a, b
    ld [$d0b8], a
    jp Jump_003_6781


    ld a, [$d034]
    and a
    jp z, Jump_003_679f

    ld hl, $d040
    set 0, [hl]
    jp Jump_003_6781


    xor a
    ld [$d69e], a
    call Call_003_4bbf
    ld a, [$4bbf]
    cp $18
    jr nz, jr_003_6144

    ld hl, $6181
    jr jr_003_6155

jr_003_6144:
    cp $24
    jr nz, jr_003_614d

    ld hl, $61aa
    jr jr_003_6155

jr_003_614d:
    cp $5e
    jp nz, Jump_003_679f

    ld hl, $61d3

jr_003_6155:
    ld a, [$d2dd]
    ld b, a

jr_003_6159:
    ld a, [hl+]
    cp $ff
    jp z, Jump_003_679f

    cp b
    jr nz, jr_003_6170

    ld a, [hl+]
    cp d
    jr nz, jr_003_6171

    ld a, [hl+]
    cp e
    jr nz, jr_003_6172

    ld a, [hl]
    ld [$d69e], a
    jr jr_003_6175

jr_003_6170:
    inc hl

jr_003_6171:
    inc hl

jr_003_6172:
    inc hl
    jr jr_003_6159

jr_003_6175:
    ld hl, $68a9
    call Call_000_3c79
    ld hl, $d6a7
    set 7, [hl]
    ret


    rst $08
    inc b
    inc b
    nop
    rst $08
    inc b
    dec b
    ld bc, $0cd1
    inc b
    ld [bc], a
    pop de
    inc c
    dec b
    inc bc
    call nc, Call_000_0a06
    inc b
    call nc, Call_000_0b06
    dec b
    jp hl


    inc b
    ld [de], a
    ld b, $e9
    inc b
    inc de
    rlca
    ld [$0a08], a
    ld [$08ea], sp
    dec bc
    add hl, bc
    rst $38
    ret nc

    ld [$0a09], sp
    ret nc

    add hl, bc
    add hl, bc
    dec bc
    jp nc, Jump_000_0704

    inc c
    jp nc, $0705

    dec c
    db $d3
    inc c
    dec b
    ld c, $d3
    dec c
    dec b
    rrca
    push de
    ld [$1007], sp
    push de
    add hl, bc
    rlca
    ld de, $08e9
    inc bc
    ld [de], a
    jp hl


    add hl, bc
    inc bc
    inc de
    rst $38
    db $eb
    ld [$1409], sp
    db $eb
    add hl, bc
    add hl, bc
    dec d
    rst $38
    ld a, [$d034]
    dec a
    jp nz, Jump_003_679f

    ld a, $01
    ld [$d055], a
    jp Jump_003_6781


    ld a, [$d034]
    and a
    jp z, Jump_003_679f

    ld hl, $d040
    set 1, [hl]
    jp Jump_003_6781


    ld b, $c8
    jp Jump_003_6114


    ld b, $fa
    jp Jump_003_6114


    ld a, [$d034]
    and a
    jp z, Jump_003_679f

    ld hl, $d040
    set 2, [hl]
    jp Jump_003_6781


    ld a, [$d034]
    and a
    jr nz, jr_003_6222

    call Call_003_679f
    ld a, $02
    ld [$cd65], a
    ret


jr_003_6222:
    ld hl, $cfb9
    ld a, [hl+]
    push af
    ld a, [hl]
    push af
    push hl
    ld a, [$cf78]
    sub $37
    ld [hl], a
    call Call_003_6781
    ld a, $ae
    ld [$cfb9], a
    call Call_000_376d
    call Call_000_3e07
    xor a
    ldh [$f3], a
    ld b, $0f
    ld hl, $7762
    call Call_000_3620
    pop hl
    pop af
    ld [hl-], a
    pop af
    ld [hl], a
    ret


    ld a, [$d034]
    and a
    jr nz, jr_003_629f

    call Call_003_6cd0
    ld a, [$d2dd]
    cp $17
    jr nz, jr_003_627a

    ld a, [$d757]
    bit 7, a
    jr nz, jr_003_6299

    ld hl, $630c
    call Call_000_3509
    jr nc, jr_003_6299

    ld hl, $6349
    call Call_000_3c79
    ld hl, $d757
    set 6, [hl]
    ret


jr_003_627a:
    cp $1b
    jr nz, jr_003_6299

    ld a, [$d75f]
    bit 1, a
    jr nz, jr_003_6299

    ld hl, $6315
    call Call_000_3509
    jr nc, jr_003_6299

    ld hl, $6349
    call Call_000_3c79
    ld hl, $d75f
    set 0, [hl]
    ret


jr_003_6299:
    ld hl, $631a
    jp Jump_000_3c79


jr_003_629f:
    xor a
    ld [$cd3d], a
    ld b, $f8
    ld hl, $d12f
    call Call_003_62f4
    ld a, [$d034]
    dec a
    jr z, jr_003_62b7

    ld hl, $d827
    call Call_003_62f4

jr_003_62b7:
    ld hl, $cfff
    ld a, [hl]
    and b
    ld [hl], a
    ld hl, $cfd0
    ld a, [hl]
    and b
    ld [hl], a
    call Call_000_374a
    ld a, [$cd3d]
    and a
    ld hl, $631a
    jp z, Jump_000_3c79

jr_003_62d0:
    ld hl, $6349
    call Call_000_3c79
    ld a, [$d060]
    and $80
    jr nz, jr_003_62ee

    call Call_000_3790
    ld b, $08
    ld hl, $4fec
    call Call_000_3620

jr_003_62e8:
    ld a, [$c02c]
    and a
    jr nz, jr_003_62e8

jr_003_62ee:
    ld hl, $6337
    jp Jump_000_3c79


Call_003_62f4:
    ld de, $002c
    ld c, $06

jr_003_62f9:
    ld a, [hl]
    push af
    and $07
    jr z, jr_003_6304

    ld a, $01
    ld [$cd3d], a

jr_003_6304:
    pop af
    and b
    ld [hl], a
    add hl, de
    dec c
    jr nz, jr_003_62f9

    ret


    ld a, $09
    dec a
    ld a, [bc]
    ccf
    ld a, [bc]
    ld a, $0b
    rst $38
    ld a, [bc]
    dec de
    ld a, [bc]
    add hl, de
    rst $38
    db $ed
    jr z, @+$4f

jr_003_631d:
    ld h, h
    or h
    db $dd
    ld a, a
    call z, $c0b2
    rst $20
    ld d, c
    or e
    db $e3
    sbc $e7
    ld c, a
    cp l
    ld a, [hl-]
    rst $10
    cp h
    or d
    ld a, a
    ret z

    or d
    db $db
    jr nc, jr_003_631d

    ld e, b
    db $ed
    jr z, jr_003_62d0

    ld h, h
    ret


    ld a, a
    ld d, h
    ld h, $4f
    jp nc, $7fdd

    cp e
    rst $08
    cp h
    ret nz

    rst $20
    ld e, b
    nop
    ld d, d
    ld c, a
    ret z

    pop bc
    sub $c5
    ld a, a
    pop bc
    ld d, c
    db $ec
    jr nc, @+$69

    ret nc

    ret nz

    rst $20
    ld d, b
    ld b, $08
    ld a, [$d034]
    and a
    jr nz, jr_003_6378

    ld a, $ff
    call Call_000_0e45
    ld a, $b8
    ld c, $02
    call Call_000_0e35

jr_003_636e:
    ld a, [$c028]
    cp $b8
    jr z, jr_003_636e

    call Call_000_0d9b

jr_003_6378:
    jp Jump_000_0f6a


    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    ld hl, $6388
    jp Jump_000_3c79


    db $ed
    jr z, @-$48

    ld h, h
    ret


    ld a, a
    adc c
    add c
    xor e
    ld c, a
    ld d, b
    ld [bc], a
    inc hl
    push de
    jp nz, $cf00

    or d
    ld e, b
    call Call_003_6403
    jp c, Jump_003_679f

    ld bc, $0585
    ld a, $01
    jr jr_003_63dc

    call Call_003_6403
    jp c, Jump_003_679f

jr_003_63ae:
    call Call_000_3e8c
    srl a
    jr c, jr_003_63c7

    and $03
    cp $02
    jr nc, jr_003_63ae

    ld hl, $63ce
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld b, [hl]
    inc hl
    ld c, [hl]
    and a

jr_003_63c7:
    ld a, $00
    rla
    xor $01
    jr jr_003_63dc

    ld a, [bc]
    sbc l
    ld a, [bc]
    ld b, a
    call Call_003_6403
    jp c, Jump_003_679f

    call Call_003_6bf5
    ld a, e

jr_003_63dc:
    ld [$cd3d], a
    dec a
    jr nz, jr_003_63ef

    ld a, $01
    ld [$d03c], a
    ld a, b
    ld [$d0ec], a
    ld a, c
    ld [$d036], a

jr_003_63ef:
    ld hl, $d67f
    ld a, [hl]
    push af
    push hl
    ld [hl], $00
    ld b, $1c
    ld hl, $4d07
    call Call_000_3620
    pop hl
    pop af
    ld [hl], a
    ret


Call_003_6403:
    ld a, [$d034]
    and a
    jr z, jr_003_640b

    scf
    ret


jr_003_640b:
    call Call_003_6bc3
    ret c

    ld a, [$d67f]
    cp $02
    jr z, jr_003_642b

    call Call_003_6cd0
    ld hl, $68a9
    call Call_000_3c79
    ld a, $8e
    call Call_000_0e45
    ld c, $50
    call Call_000_3781
    and a
    ret


jr_003_642b:
    scf
    ret


    jp Jump_003_67a4


    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    call Call_003_6cd0
    ld b, $1d
    ld hl, $405c
    call Call_000_3620
    ld hl, $6483
    jr nc, jr_003_6459

    ld c, $04

jr_003_6449:
    ld a, $9e

jr_003_644b:
    call Call_000_3788
    ld a, $b2
    call Call_000_3788
    dec c

jr_003_6454:
    jr nz, jr_003_6449

    ld hl, $645c

jr_003_6459:
    jp Jump_000_3c79


    db $ed
    jr z, jr_003_644b

    ld h, h
    ld c, a
    sbc l
    adc e
    xor e
    ld h, $7f
    jp z, $c9de

    or e
    ld a, a
    cp h
    jp Jump_000_2fd9


    rst $20
    ld d, l
    pop bc
    or [hl]
    cp b
    add $7f
    add b
    add c
    sub d
    sbc a
    ld h, $7f
    or e
    rst $08
    rst $18
    jp $e7d9


    ld e, b
    db $ed
    jr z, jr_003_6454

    ld h, h
    ld a, a
    call z, $e7b3
    ld c, a
    ld d, [hl]
    ld a, a
    push bc
    sbc $c6
    db $d3
    ld a, a
    jp z, $c9de

    or e
    ld a, a
    cp h
    push bc
    or d
    ld e, b
    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    ld a, [$cf79]
    push af
    ld a, [$cf78]
    ld [$cd3d], a

jr_003_64ad:
    xor a
    ld [$cfb2], a
    ld a, $01
    ld [$d05a], a
    call Call_000_2df3
    jr nc, jr_003_64be

    jp Jump_003_65cd


jr_003_64be:
    ld a, [$cd3d]
    cp $52
    jp nc, Jump_003_6597

    ld a, $02
    ld [$ccdb], a
    ld hl, $65d9
    ld a, [$cd3d]
    cp $50
    jr c, jr_003_64d8

    ld hl, $65ea

jr_003_64d8:
    call Call_000_3c79
    ld hl, $5377
    ld b, $0f
    call Call_000_3620
    jr nz, jr_003_64ad

    ld hl, $d133
    ld bc, $002c
    call Call_003_69b6
    push hl
    ld a, [hl]
    ld [$d0e3], a
    call Call_000_1b6d
    call Call_000_386e
    pop hl
    ld a, [$cd3d]
    cp $50
    jr nc, jr_003_655a

    ld bc, $0015
    add hl, bc
    ld a, [hl]
    cp $c0
    jr c, jr_003_6512

    ld hl, $65f9
    call Call_000_3c79
    jr jr_003_64be

jr_003_6512:
    ld a, [hl]
    add $40
    ld [hl], a
    ld a, $01
    ld [$d0e3], a
    call Call_003_68d9
    ld hl, $6613
    call Call_000_3c79

jr_003_6524:
    pop af
    ld [$cf79], a
    call Call_000_3e15
    call Call_000_3e1d
    jp Jump_003_678f


Jump_003_6531:
jr_003_6531:
    ld a, [$cf79]
    ld b, a
    ld a, [$cc2f]
    cp b
    jr nz, jr_003_654d

    ld hl, $d148
    ld bc, $002c
    call Call_000_3ad1
    ld de, $d014
    ld bc, $0004
    call Call_000_01bb

jr_003_654d:
    ld a, $8e
    call Call_000_0e45
    ld hl, $6626
    call Call_000_3c79
    jr jr_003_6524

jr_003_655a:
    call Call_003_6562
    jr nz, jr_003_6531

    jp Jump_003_65ca


Call_003_6562:
    xor a
    ld [$cc49], a
    call Call_003_694a
    ld hl, $d133
    ld bc, $002c
    call Call_003_69b6
    ld bc, $0015
    add hl, bc
    ld a, [$d0e3]
    ld b, a
    ld a, [$cd3d]
    cp $51
    jr z, jr_003_6592

    ld a, [hl]
    and $3f
    cp b
    ret z

    add $0a
    cp b
    jr nc, jr_003_658c

    ld b, a

jr_003_658c:
    ld a, [hl]
    and $c0
    add b
    ld [hl], a
    ret


jr_003_6592:
    ld a, [hl]
    cp b
    ret z

    jr jr_003_658c

Jump_003_6597:
    ld hl, $cd3d
    dec [hl]
    dec [hl]
    xor a
    ld hl, $cc26
    ld [hl+], a
    ld [hl], a
    ld b, $04

jr_003_65a4:
    push bc
    ld hl, $d133
    ld bc, $002c
    call Call_003_69b6
    ld a, [hl]
    and a
    jr z, jr_003_65bb

    call Call_003_6562
    jr z, jr_003_65bb

    ld hl, $cc27
    inc [hl]

jr_003_65bb:
    ld hl, $cc26
    inc [hl]
    pop bc
    dec b

jr_003_65c1:
    jr nz, jr_003_65a4

    ld a, [$cc27]
    and a
    jp nz, Jump_003_6531

Jump_003_65ca:
    call Call_003_679a

Jump_003_65cd:
    call Call_000_3e15
    call Call_000_3e1d
    pop af
    xor a
    ld [$cd65], a
    ret


    nop
    inc [hl]
    ret


    call c, $c92b
    ld c, a
    ld b, e
    add c
    xor e
    sub e
    db $dd
    call z, $bdd4
    and $57
    db $ed
    jr z, @+$2f

    ld h, l
    dec hl
    db $dd
    ld c, a
    or [hl]
    or d
    call z, $bdb8
    reti


    and $57
    db $ed
    jr z, jr_003_6646

    ld h, l
    jp z, $ba7f

    jp c, Jump_000_2cb2

    ld [c], a
    or e
    ld c, a
    call z, $bdd4
    cp d
    call nz, Call_003_7f26
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $58
    db $ed
    jr z, jr_003_667d

    ld h, l
    ret


    ld c, a
    call c, Call_003_432b
    add c
    xor e
    sub e
    ld h, $7f
    call z, $c0b4
    rst $20
    ld e, b
    db $ed
    jr z, jr_003_65c1

    ld h, l
    add c
    xor e
    sub e
    ld h, $4f
    or [hl]
    or d
    call z, $bcb8
    ret nz

    rst $20
    ld e, b
    jp Jump_003_679f


Jump_003_663a:
    ld a, [$d034]
    and a
    jp nz, Jump_003_679f

    ld a, [$cf78]
    sub $c9

jr_003_6646:
    push af
    jr nc, jr_003_664b

    add $37

jr_003_664b:
    inc a
    ld [$d0e3], a
    ld a, $44
    call Call_000_3e9d
    ld a, [$d0e3]
    ld [$d0bd], a
    call Call_000_1b6d
    call Call_000_386e
    pop af
    ld hl, $6710
    jr nc, jr_003_6669

    ld hl, $671b

jr_003_6669:
    call Call_000_3c79
    ld hl, $672b
    call Call_000_3c79
    ld hl, $c43a
    ld bc, $080f
    ld a, $14
    ld [$d0ea], a

jr_003_667d:
    call Call_000_3130
    ld a, [$cc26]
    and a
    jr z, jr_003_668c

    ld a, $02
    ld [$cd65], a
    ret


jr_003_668c:
    ld a, [$cf79]
    push af
    ld a, [$cf78]
    push af

jr_003_6694:
    ld hl, $cf45
    ld de, $df10
    ld bc, $0010
    call Call_000_01bb
    ld a, $ff
    ld [$cfb2], a
    ld a, $03
    ld [$d05a], a
    call Call_000_2df3
    push af
    ld hl, $df10
    ld de, $cf45
    ld bc, $0010
    call Call_000_01bb
    pop af
    jr nc, jr_003_66cb

    pop af
    pop af
    call Call_000_3e04
    call Call_000_0188
    call Call_000_3e1d
    jp Jump_000_376d


jr_003_66cb:
    ld a, $43
    call Call_000_3e9d
    push bc
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    pop bc
    ld a, c
    and a
    jr nz, jr_003_66ec

    ld a, $a5
    call Call_000_3788
    ld hl, $6756
    call Call_000_3c79
    jr jr_003_6694

jr_003_66ec:
    ld hl, $7e76
    ld b, $0b
    call Call_000_3620
    jr c, jr_003_6694

    ld a, $1b
    call Call_000_3e9d
    pop af
    ld [$cf78], a
    pop af
    ld [$cf79], a
    ld a, b
    and a
    ret z

    ld a, [$cf78]
    call Call_000_1b55
    ret c

    jp Jump_003_678f


    db $ed
    jr z, @-$42

    ld h, l
    or a
    inc [hl]
    or e
    cp h
    ret nz

    rst $20
    ld e, b
    db $ed
    jr z, @-$2f

    ld h, l
    sbc l
    adc e

jr_003_6721:
    xor e
    db $dd
    ld a, a
    or a
    inc [hl]
    or e
    cp h
    ret nz

    rst $20
    ld e, b
    db $ed
    jr z, jr_003_6721

    ld h, l
    jp z, $d2d4

    reti


    ld a, a
    call nc, Call_003_7fcf
    db $d3
    rst $08
    push de
    adc $c4
    ld a, a
    call nc, $c5c8
    ld a, a
    ld c, a
    rst $10
    ret z

    ret


    db $d3
    call nc, $c5cc
    ld a, a
    rst $08
    add $7f
    ld d, h
    add c
    ld d, l
    db $ec
    ld e, c
    ld h, e
    or [hl]
    and $57
    db $ed
    jr z, jr_003_677b

    ld h, [hl]
    call nz, Call_003_507f
    ld bc, $cf45
    nop
    jp z, $b14f

    or d
    cp h
    ld [c], a
    or e
    ld h, $7f
    call c, $b6d9
    rst $18
    ret nz

    rst $20
    ld d, c
    ld d, b
    ld bc, $cf45
    nop
    jp z, $b57f

    ld a, $b4

jr_003_677b:
    rst $10
    jp c, $b2c5

    rst $20
    ld e, b

Call_003_6781:
Jump_003_6781:
    ld hl, $68a9
    call Call_000_3c79
    ld a, $8e
    call Call_000_0e45
    call Call_000_38ae

Call_003_678f:
Jump_003_678f:
jr_003_678f:
    ld hl, $d2a1
    ld a, $01
    ld [$cf7d], a
    jp Jump_000_16cc


Call_003_679a:
    ld hl, $6824
    jr jr_003_67d7

Call_003_679f:
Jump_003_679f:
    ld hl, $67de
    jr jr_003_67d7

Jump_003_67a4:
    ld hl, $6805
    jr jr_003_67d7

Jump_003_67a9:
    call Call_000_3e1d
    call Call_000_376d
    call Call_000_3e07
    ld a, $c1
    ld [$d059], a
    ld a, $08
    call Call_000_3e9d
    ld hl, $6833
    call Call_000_3c79
    ld hl, $6843
    call Call_000_3c79
    jr jr_003_678f

Jump_003_67ca:
    ld hl, $6857
    jr jr_003_67d7

Jump_003_67cf:
    ld hl, $6888
    jr jr_003_67d7

Jump_003_67d4:
    ld hl, $6870

jr_003_67d7:
    xor a
    ld [$cd65], a
    jp Jump_000_3c79


    db $ed
    inc l
    rst $28
    ld h, l
    inc de
    ret


    ld a, a
    cp d
    call nz, $a93a
    call nc, $d387
    ld a, a
    pop bc
    ld a, a
    call $d0c1
    ld a, a
    rst $08
    add $7f
    call nc, $c5c8
    ld c, a
    ld a, a
    jp $d4c9


    reti


    add c
    ld d, c
    db $ec
    sbc c
    ld a, a
    ld d, b
    ld b, $c0
    or d
    cp [hl]
    jp nz, Jump_003_7fc5

    or c
    dec l
    or [hl]
    ret c

    db $d3
    ret


    inc sp
    cp l
    rst $20
    ld c, [hl]
    jp nz, $b3b6

    cp d
    call nz, Call_003_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $e7
    ld e, b
    db $ed
    inc l
    dec c
    ld h, a
    jp $7fd3


    cp d
    or e
    or [hl]
    ld h, $c5
    or d
    sub $58
    db $ed
    jr z, jr_003_688d

    ld h, [hl]
    inc e
    db $e3
    and [hl]
    db $dd
    ld a, a
    jp z, $b62c

    jp c, $e7c0

    ld e, b
    db $ed
    jr z, @+$7c

    ld h, [hl]
    ld a, a
    db $d3
    ret


    db $dd
    ld a, a
    call nz, $c0df
    rst $10
    ld a, a
    inc [hl]
    db $db
    ld a, $b3
    rst $20
    ld e, b
    db $ed
    inc l
    ld e, l
    ld h, [hl]
    jp z, Jump_000_2c7f

    jp $bcde


    ldh [$c6], a
    ld c, [hl]
    ret


    reti


    cp d
    call nz, Call_003_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $58
    db $ed
    inc l
    dec [hl]
    ld h, a
    jp z, Jump_000_0150

    ld l, b
    call $c600
    ld c, a
    ret


    reti


    cp d
    call nz, Call_003_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $58
    nop
    inc e
    xor h
    add a
    adc h

jr_003_688d:
    add $7f
    or c
    dec l
    cp c
    jp $d9b2


    ld a, a
    ld d, h
    ld h, $4f
    or d
    rst $18
    ld b, h
    or d
    push bc
    ret


    inc sp
    ld a, a
    jp nz, $b4b6

    rst $08
    cp [hl]
    sbc $e7
    ld e, b
    db $ed
    jr z, @-$7b

    ld h, d
    dec b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    jp nz, $dfb6

    ret nz

    rst $20
    ld d, a
    db $ed
    inc l
    ld b, c
    ld h, [hl]
    dec b
    ld bc, $cf45
    nop
    add $7f
    ret


    rst $18
    ret nz

    ld e, b
    db $ed
    jr z, jr_003_692f

    ld h, e
    dec b
    ld bc, $cf45
    nop
    or [hl]
    rst $10
    ld a, a
    or l
    ret c

    ret nz

    ld e, b

Call_003_68d9:
    ld hl, $d133
    ld bc, $002c
    ld a, [$cf79]
    call Call_000_3ad1
    push hl
    ld de, $cd72
    ld a, $5e
    call Call_000_3e9d
    pop hl
    ld c, $15
    ld b, $00
    add hl, bc
    ld de, $cd73
    ld b, $00

jr_003_68f9:
    inc b
    ld a, b
    cp $05
    ret z

    ld a, [$d0e3]
    dec a
    jr nz, jr_003_690b

    ld a, [$cc26]
    inc a
    cp b
    jr nz, jr_003_6911

jr_003_690b:
    ld a, [hl]
    and $c0
    call nz, Call_003_6915

jr_003_6911:
    inc hl
    inc de
    jr jr_003_68f9

Call_003_6915:
    push bc
    ld a, [de]
    ldh [$98], a
    xor a
    ldh [$95], a
    ldh [$96], a
    ldh [$97], a
    ld a, $05
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ld a, [hl]
    ld b, a
    swap a
    and $0f

jr_003_692f:
    srl a
    srl a
    ld c, a

jr_003_6934:
    ldh a, [$98]
    cp $08
    jr c, jr_003_693c

    ld a, $07

jr_003_693c:
    add b
    ld b, a
    ld a, [$d0e3]
    dec a
    jr z, jr_003_6947

    dec c
    jr nz, jr_003_6934

jr_003_6947:
    ld [hl], b
    pop bc
    ret


Call_003_694a:
    ld a, [$cc49]
    and a
    ld hl, $d133
    ld bc, $002c
    jr z, jr_003_6973

    ld hl, $d82b
    dec a
    jr z, jr_003_6973

    ld hl, $d9da
    ld bc, $0021
    dec a
    jr z, jr_003_6973

    ld hl, $d999
    dec a
    jr z, jr_003_696e

    ld hl, $d003

jr_003_696e:
    call Call_003_69bc
    jr jr_003_6976

jr_003_6973:
    call Call_003_69b6

jr_003_6976:
    ld a, [hl]
    dec a
    push hl
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld de, $cd68
    ld a, $0e
    call Call_000_01a3
    ld de, $cd6d
    ld a, [de]
    ld b, a
    pop hl
    push bc
    ld bc, $0015
    ld a, [$cc49]
    cp $04
    jr nz, jr_003_699e

    ld bc, $0011

jr_003_699e:
    add hl, bc
    ld a, [hl]
    and $c0
    pop bc
    or b
    ld h, d
    ld l, e
    inc hl
    ld [hl], a
    xor a
    ld [$d0e3], a
    call Call_003_6915
    ld a, [hl]
    and $3f
    ld [$d0e3], a
    ret


Call_003_69b6:
    ld a, [$cf79]
    call Call_000_3ad1

Call_003_69bc:
    ld a, [$cc26]
    ld c, a
    ld b, $00
    add hl, bc
    ret


    push hl
    ld a, [$cf78]
    call Call_000_1b55
    pop hl
    jr c, jr_003_6a1e

    push hl
    call Call_003_6a6f
    ld a, [$d0e9]
    pop hl
    and a
    jr nz, jr_003_6a1e

    push hl
    ld a, [$cf78]
    ld [$d0e3], a
    call Call_000_1add
    call Call_000_386e
    ld hl, $6a35
    call Call_000_3c79
    ld hl, $c43a

jr_003_69ef:
    ld bc, $080f
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$d0f3]
    cp $02
    pop hl
    scf

jr_003_6a01:
    ret z

    push hl
    ld a, [$cf79]
    call Call_000_16cc
    ld a, [$cf78]
    ld [$d0e3], a
    call Call_000_1add
    call Call_000_386e
    ld hl, $6a28
    call Call_000_3c79
    pop hl
    and a
    ret


jr_003_6a1e:
    push hl
    ld hl, $6a4e
    call Call_000_3c79
    pop hl
    scf
    ret


    db $ed
    jr z, jr_003_6a01

    ld h, [hl]
    db $dd
    ld c, a
    cp l
    jp $bccf


    ret nz

    rst $20
    ld e, b
    db $ed
    jr z, jr_003_69ef

    ld h, [hl]
    db $dd
    ld a, a
    cp l
    jp $bdcf


    ld c, a
    adc $de
    call nz, Call_003_7fc6
    sub $db
    cp h
    or d
    inc sp
    cp l
    or [hl]
    and $58
    db $ed
    jr z, @-$0b

    ld h, [hl]
    ld a, a
    call nz, $d3c3
    ld a, a
    ret nz

    or d
    cp [hl]
    jp nz, $a1c5

    sbc b
    inc sp
    cp l
    ld c, a
    cp l
    jp $bad9


    call nz, Call_003_7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $e7
    ld e, b

Call_003_6a6f:
    ld a, $01
    ld [$d0e9], a
    ld a, [$cf78]
    cp $c4
    jr nc, jr_003_6a98

    push af
    ld hl, $6aa4
    ld de, $cee4
    ld bc, $000f
    call Call_000_01bb
    pop af
    dec a
    ld c, a
    ld hl, $cee4
    ld b, $02
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    ret nz

jr_003_6a98:
    ld a, [$cf78]
    call Call_000_1b55
    ret c

    xor a
    ld [$d0e9], a
    ret


    ldh a, [rSB]
    ldh a, [rVBK]
    nop
    sbc a
    nop
    ret nz

    ldh a, [$3b]
    nop

Call_003_6aaf:
    ld de, $d9b2
    ld a, [de]
    inc a
    ld [de], a
    ld a, [$cf78]
    ld [$d092], a
    ld c, a

jr_003_6abc:
    inc de
    ld a, [de]
    ld b, a
    ld a, c
    ld c, b
    ld [de], a
    cp $ff
    jr nz, jr_003_6abc

    call Call_000_2f2e
    ld hl, $ddb0
    ld bc, $0006
    ld a, [$d9b2]
    dec a
    jr z, jr_003_6af9

    dec a
    call Call_000_3ad1
    push hl
    ld bc, $0006
    add hl, bc
    ld d, h
    ld e, l
    pop hl
    ld a, [$d9b2]
    dec a
    ld b, a

jr_003_6ae6:
    push bc
    push hl
    ld bc, $0006
    call Call_000_01bb
    pop hl
    ld d, h
    ld e, l
    ld bc, $fffa
    add hl, bc
    pop bc
    dec b
    jr nz, jr_003_6ae6

jr_003_6af9:
    ld hl, $d11d
    ld de, $ddb0
    ld bc, $0006
    call Call_000_01bb
    ld a, [$d9b2]
    dec a
    jr z, jr_003_6b35

    ld hl, $de64
    ld bc, $0006
    dec a
    call Call_000_3ad1
    push hl
    ld bc, $0006
    add hl, bc
    ld d, h
    ld e, l
    pop hl
    ld a, [$d9b2]
    dec a
    ld b, a

jr_003_6b22:
    push bc
    push hl
    ld bc, $0006
    call Call_000_01bb
    pop hl
    ld d, h
    ld e, l
    ld bc, $fffa
    add hl, bc
    pop bc
    dec b
    jr nz, jr_003_6b22

jr_003_6b35:
    ld hl, $de64
    ld a, $02
    ld [$d05a], a
    ld a, $4e
    call Call_000_3e9d
    ld a, [$d9b2]
    dec a
    jr z, jr_003_6b72

    ld hl, $d9d2
    ld bc, $0021
    dec a
    call Call_000_3ad1
    push hl
    ld bc, $0021
    add hl, bc
    ld d, h
    ld e, l
    pop hl
    ld a, [$d9b2]
    dec a
    ld b, a

jr_003_6b5f:
    push bc
    push hl
    ld bc, $0021
    call Call_000_01bb
    pop hl
    ld d, h
    ld e, l
    ld bc, $ffdf
    add hl, bc
    pop bc
    dec b
    jr nz, jr_003_6b5f

jr_003_6b72:
    ld a, [$cfda]
    ld [$cfcf], a
    ld hl, $cfcc
    ld de, $d9d2
    ld bc, $000c
    call Call_000_01bb
    ld hl, $d2d8
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    inc de
    push de
    ld a, [$d0ec]
    ld d, a
    ld hl, $4fb5
    ld b, $16
    call Call_000_3620
    pop de
    ldh a, [$96]
    ld [de], a
    inc de
    ldh a, [$97]
    ld [de], a
    inc de
    ldh a, [$98]
    ld [de], a
    inc de
    xor a
    ld b, $0a

jr_003_6baa:
    ld [de], a
    inc de
    dec b
    jr nz, jr_003_6baa

    ld hl, $cfd8
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    ld hl, $cfe5
    ld b, $04

jr_003_6bbc:
    ld a, [hl+]
    inc de
    ld [de], a
    dec b
    jr nz, jr_003_6bbc

    ret


Call_003_6bc3:
    ld a, [$d2e6]
    ld hl, $6beb
    ld de, $0001
    call Call_000_3ddb
    jr nc, jr_003_6be7

    ld a, [$d2e6]
    cp $0e
    ld a, [$cfad]
    jr z, jr_003_6be3

    cp $48
    jr z, jr_003_6be9

    cp $32
    jr z, jr_003_6be9

jr_003_6be3:
    cp $14
    jr z, jr_003_6be9

jr_003_6be7:
    scf
    ret


jr_003_6be9:
    and a
    ret


    nop
    inc bc
    dec b
    rlca
    dec c
    ld c, $11
    ld d, $17
    rst $38

Call_003_6bf5:
    ld a, [$d2dd]
    ld de, $0003
    ld hl, $6c24
    call Call_000_3ddb
    jr c, jr_003_6c06

    ld e, $02
    ret


jr_003_6c06:
    inc hl
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld b, [hl]
    inc hl
    ld e, $00

jr_003_6c0e:
    call Call_000_3e8c
    srl a
    ret c

    and $03
    cp b
    jr nc, jr_003_6c0e

    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld b, [hl]
    inc hl
    ld c, [hl]
    ld e, $01
    ret


    nop
    adc b
    ld l, h
    ld bc, $6c88
    inc bc
    sub d
    ld l, h
    dec b
    sbc c
    ld l, h
    ld b, $9e
    ld l, h
    rlca
    rst $00
    ld l, h
    ld [$6cb5], sp
    rrca
    sub d
    ld l, h
    ld de, $6c99
    dec d
    sbc [hl]
    ld l, h
    ld d, $99
    ld l, h
    rla
    xor h
    ld l, h
    jr @-$52

    ld l, h
    inc e
    xor h
    ld l, h
    dec e
    xor h
    ld l, h
    ld e, $b5
    ld l, h
    rra
    or l
    ld l, h
    jr nz, jr_003_6c0e

    ld l, h
    ld hl, $6c8d
    ld [hl+], a
    cp [hl]
    ld l, h
    inc hl
    sub d
    ld l, h
    inc h
    sub d
    ld l, h
    ld b, c
    sub d
    ld l, h
    ld e, [hl]
    sbc c
    ld l, h
    and c
    or l
    ld l, h
    and d
    or l
    ld l, h
    reti


    and e
    ld l, h
    jp c, Jump_003_6ca3

    db $db
    and e
    ld l, h
    call c, Call_003_6ca3
    ld [c], a
    cp [hl]
    ld l, h
    db $e3
    cp [hl]
    ld l, h
    db $e4
    cp [hl]
    ld l, h
    rst $38
    ld [bc], a
    rrca
    jr jr_003_6c9b

    ld b, a
    ld [bc], a
    rrca
    sbc l
    rrca
    ld b, a
    inc bc
    rrca
    cpl
    rrca
    sbc l
    rrca
    ld c, [hl]
    ld [bc], a
    rrca

jr_003_6c9b:
    ld c, [hl]
    rrca
    rla
    ld [bc], a
    rla
    ld l, [hl]
    rrca
    dec h

Call_003_6ca3:
Jump_003_6ca3:
    inc b
    rrca
    ld e, b
    rrca
    ld c, [hl]
    rrca
    cpl
    rrca
    dec h
    inc b
    dec b
    jr jr_003_6cbf

    ld c, [hl]
    rrca
    sbc l
    rrca
    add l
    inc b
    rrca
    dec de
    rrca
    ld e, h
    rrca
    rla
    rrca
    sbc l
    inc b

jr_003_6cbf:
    rla
    ld [$9e17], sp
    rla
    adc d
    rla
    ld e, l
    inc b
    rla
    sbc [hl]
    rrca
    ld c, [hl]
    rrca
    sbc l
    rrca
    add l

Call_003_6cd0:
    call Call_000_26bb
    jp Jump_000_0ebd


    ld hl, $4f61
    ld de, $cee4
    ld c, $00

jr_003_6cde:
    inc hl
    ld a, [hl-]
    inc a
    jr z, jr_003_6cf7

    push hl
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [hl+]
    and a
    call nz, Call_003_6cfb
    ld a, [hl+]
    and a
    call nz, Call_003_6cfb
    pop hl
    inc hl
    inc hl
    inc c
    jr jr_003_6cde

jr_003_6cf7:
    ld a, $ff
    ld [de], a
    ret


Call_003_6cfb:
    inc hl
    ld b, $0a

jr_003_6cfe:
    ld a, [$d0e3]
    cp [hl]
    jr nz, jr_003_6d07

    ld a, c
    ld [de], a
    inc de

jr_003_6d07:
    inc hl
    inc hl
    dec b
    jr nz, jr_003_6cfe

    dec hl
    ret


    ld de, $cd3f
    ld hl, $6da1
    ld bc, $0008
    call Call_000_01bb
    ld hl, $cd49
    ld bc, $0008
    xor a
    call Call_000_372a
    ld de, $cd49
    ld hl, $cd3f
    ld a, [$d2d5]
    ld b, a
    ld c, $08

jr_003_6d30:
    srl b
    jr nc, jr_003_6d3b

    ld a, [hl]
    add $04
    ld [hl], a
    ld a, $01
    ld [de], a

jr_003_6d3b:
    inc hl
    inc de
    dec c
    jr nz, jr_003_6d30

    ld hl, $cd3d
    ld a, $e8
    ld [hl+], a
    ld [hl], $60
    ld hl, $c47e
    ld de, $cd49
    call Call_003_6d57
    ld hl, $c4ba
    ld de, $cd4d

Call_003_6d57:
    ld c, $04

jr_003_6d59:
    push de
    push hl
    ld a, [$cd3d]
    ld [hl+], a
    inc a
    ld [$cd3d], a
    ld a, [de]
    and a
    ld a, [$cd3e]
    jr nz, jr_003_6d6f

    call Call_003_6d9c
    jr jr_003_6d72

jr_003_6d6f:
    inc a
    inc a
    inc hl

jr_003_6d72:
    ld [$cd3e], a
    ld de, $0013
    add hl, de
    ld a, [$cd3f]
    call Call_003_6d9c
    add hl, de
    call Call_003_6d9c
    push bc
    ld hl, $cd40
    ld de, $cd3f
    ld bc, $0008
    call Call_000_01bb
    pop bc
    pop hl
    ld de, $0004
    add hl, de
    pop de
    inc de
    dec c
    jr nz, jr_003_6d59

    ret


Call_003_6d9c:
    ld [hl+], a
    inc a
    ld [hl], a
    inc a
    ret


    jr nz, jr_003_6dcb

    jr nc, jr_003_6ddd

    ld b, b
    ld c, b
    ld d, b
    ld e, b
    rra
    ccf
    ccf
    ld a, a
    ei
    rst $38
    rst $30
    ld a, [$f0ef]
    ld a, a
    ldh [rHDMA4], a
    ld a, b
    db $fc
    add $fc
    cp $fe
    cp $7f
    rst $38
    rst $28
    ccf
    rst $30
    rrca
    cp $07
    ld l, d
    ld e, $3f

jr_003_6dc8:
    ld h, e
    ccf
    ld c, [hl]

jr_003_6dcb:
    ld l, $40
    pop hl
    ld hl, $a0e0
    ld h, c
    ld [hl], e
    nop
    db $10
    jr jr_003_6ddf

    ld b, $06
    db $fc
    ld [hl], d
    ld [hl], h
    ld [bc], a

jr_003_6ddd:
    rlca
    inc b

jr_003_6ddf:
    rlca
    dec b
    add [hl]
    adc $00
    ld [$1018], sp
    ld h, b
    ld h, b
    nop
    nop
    inc bc
    inc bc
    inc b
    inc b
    ld [$1008], sp
    db $10
    inc hl
    jr nz, jr_003_6e3d

    ld b, b
    ld b, a
    ld b, b
    nop
    nop
    ret nz

    ret nz

    jr nz, jr_003_6e1f

    db $10
    jr nc, jr_003_6e0a

    jr c, jr_003_6dc8

    inc a
    ld [c], a
    ld e, $e2
    ld e, $47

jr_003_6e0a:
    ld b, b
    ld b, a
    ld b, b
    ccf
    jr nz, jr_003_6e2c

    inc de
    inc c
    dec bc
    inc b
    rlca
    inc bc
    inc bc
    nop
    nop
    ld [c], a
    ld e, $e2
    ld e, $c4
    inc a

jr_003_6e1f:
    ld [$10f8], sp
    ldh a, [rNR41]
    ldh [$c0], a
    ret nz

    nop
    nop
    ld e, $1d
    inc a

jr_003_6e2c:
    ccf
    ld a, b
    ld a, a
    ld hl, sp-$01
    db $fc
    rst $38
    rst $28
    rst $38
    rst $28
    rst $38
    add $ff
    ld [hl], l
    or [hl]
    inc e
    rst $28

jr_003_6e3d:
    inc e
    rst $20
    inc bc
    rst $38
    add d
    cp $41
    rst $38
    pop hl
    ld a, a
    ld sp, hl
    ld a, a
    or e
    call c, Call_003_496f
    ld c, a
    ld l, b
    ld c, a
    ld l, b
    ld e, a
    jr nz, jr_003_6e91

    inc hl
    rrca
    jr jr_003_6e5f

    ld b, $de
    sbc $a9
    adc c
    and c
    add l

jr_003_6e5f:
    pop bc
    add l
    adc d
    ld a, [bc]
    sbc h
    inc e
    ldh [$60], a

jr_003_6e67:
    ld hl, sp-$28
    nop
    nop
    ld bc, $0301
    ld [bc], a
    inc bc
    ld [bc], a
    ld b, $05
    ld b, $05
    inc c
    dec bc
    jr @+$19

    nop
    nop
    nop
    nop
    add b
    add b
    add b
    add b
    ld b, b
    ret nz

    ld b, b
    ret nz

    jr nz, jr_003_6e67

    db $10
    ldh a, [rNR23]
    rla
    jr nc, jr_003_6ebc

    jr nc, jr_003_6ebb

    jr nc, jr_003_6ebd

jr_003_6e91:
    jr jr_003_6eaa

    inc c
    rrca
    inc bc
    inc bc
    nop
    nop
    db $10
    ldh a, [$08]
    ld hl, sp+$08
    ld hl, sp+$08
    ld hl, sp+$10
    ldh a, [$60]
    ldh [$80], a
    add b
    nop
    nop
    nop

jr_003_6eaa:
    nop
    nop
    ret nz

    add [hl]
    ld a, [hl]
    ld c, b
    cp c
    or c
    ld d, b
    db $e3
    and h
    ld h, e
    ld h, d
    ld hl, $00a5
    nop

jr_003_6ebb:
    nop

jr_003_6ebc:
    nop

jr_003_6ebd:
    inc e
    nop
    rst $38
    pop bc
    sbc $3d
    cp $02
    cp h
    ld b, d
    cp d
    ld b, [hl]
    ld bc, $4485
    ld b, e
    rst $00
    ret nz

    ld h, $e1
    db $f4
    ld a, [c]
    adc h
    ld a, h
    inc de
    ld a, a
    ld hl, $fcf9
    adc h
    call nc, Call_003_4834
    jr c, @-$06

    add sp, $38
    ld c, b
    jr nc, jr_003_6f35

    ld h, b
    and b
    ret nz

    ret nz

    nop
    nop
    ld bc, $1e01
    ld e, $13
    inc de
    inc d
    inc d
    dec sp
    jr c, jr_003_6f4d

    ld d, b
    sub a
    sub b
    add b
    add b
    ld b, b
    ld b, b
    jr nz, jr_003_6f1f

    db $fc
    db $fc
    inc h
    inc h
    call nc, $ec34
    inc e
    ld [$571a], a
    ld d, b
    scf
    jr nc, jr_003_6f39

    jr z, jr_003_6f34

    daa
    ccf
    ccf
    inc b
    inc b
    ld [bc], a
    ld [bc], a
    ld bc, $e901
    add hl, de
    ld [$dc1a], a
    inc a

jr_003_6f1f:
    jr z, @-$16

    ret z

    ret z

    ld a, b
    ld a, b
    add b
    add b
    nop
    nop
    rra
    db $10
    ccf
    jr nz, jr_003_6f6c

    ld a, a
    ld a, l
    rst $38
    ei
    rst $38
    ei

jr_003_6f34:
    rst $38

jr_003_6f35:
    rst $38
    ld a, [$faf5]

jr_003_6f39:
    ld a, a
    rst $38
    rst $28
    rra
    ld a, e
    add a
    db $dd
    db $e3
    rst $30
    ei
    rst $38
    rst $38
    db $fd
    rst $38
    or [hl]
    rst $08
    rst $28
    ldh a, [$7f]
    ld [hl], b

jr_003_6f4d:
    ld a, a
    ld a, h
    ld a, a
    ld [hl], b
    ld [hl], h
    ld a, d

jr_003_6f53:
    ld a, e
    ld a, l
    ld a, a
    ld a, [hl]
    ld a, a
    ld a, a
    push af
    rlca
    add a
    ld b, a
    ld h, a
    ld [hl], a
    rlca
    rlca
    rlca
    rlca
    rra
    rrca
    rla
    rla
    rst $10
    sub a
    ld bc, $0201

jr_003_6f6c:
    inc bc
    jr @+$21

    ld h, $3a
    dec h
    scf
    jr jr_003_6fa2

    ld d, d
    ld a, d

jr_003_6f77:
    adc c
    db $ed
    add b
    add b
    ld b, b
    ret nz

    jr jr_003_6f77

    ld h, h
    ld e, h
    and h
    db $ec
    inc e
    or h
    ld c, d
    ld e, [hl]
    sub c
    or a
    adc c
    db $ed
    ld d, d
    ld a, d
    jr jr_003_6fbc

    dec h
    scf
    ld h, $3a
    jr jr_003_6fb4

    ld [bc], a
    inc bc
    ld bc, $9101
    or a
    ld c, d
    ld e, [hl]

jr_003_6f9d:
    jr jr_003_6f53

    and h
    db $ec
    ld h, h

jr_003_6fa2:
    ld e, h
    jr jr_003_6f9d

    ld b, b
    ret nz

    add b
    add b
    ld a, a
    ld a, a
    rst $38
    rst $38
    rst $38
    xor $f7
    call z, $c47b
    ld a, a

jr_003_6fb4:
    ld b, b
    dec a
    ld h, d
    ld a, l
    ld [hl], d
    rst $38
    rst $38
    ld a, a

jr_003_6fbc:
    sbc a
    rst $38
    rrca
    add a
    rrca
    add a
    daa
    or a
    ld [hl], a
    db $f4
    db $76
    jp nz, Jump_000_3fe5

    ld sp, $2c2b
    ld [de], a
    inc e
    rrca
    db $10
    rrca
    dec bc
    rlca
    inc b
    inc bc
    inc b
    ld bc, $8203
    and c
    and d
    ret nz

    db $e3
    inc bc
    call nz, $8c17
    rst $08
    cp b
    ccf
    add sp, $7f
    sub e
    sbc a
    nop
    nop
    inc c
    inc c
    ld [de], a
    ld [de], a
    dec l
    ld hl, $202e
    ld e, a
    ld b, b
    ld e, a
    ld b, b
    ld e, a
    ld b, b
    nop
    nop
    jr nc, jr_003_702d

    ld a, b
    ld c, b
    call nz, $84bc
    ld a, h
    ld [bc], a
    cp $02
    cp $02
    cp $2f
    jr nz, jr_003_703b

    jr nz, jr_003_7025

    jr jr_003_701b

    inc c
    dec b
    ld b, $02
    inc bc
    ld bc, $0001
    nop
    inc b
    db $fc

jr_003_701b:
    inc b
    db $fc
    ld [$10f8], sp
    ldh a, [rNR41]
    ldh [rLCDC], a
    ret nz

jr_003_7025:
    add b
    add b
    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38

jr_003_702d:
    rst $38
    rst $38
    ld h, [hl]
    sbc a
    sbc [hl]
    rst $20
    rst $20
    rst $38
    rst $38
    rst $38
    rst $28
    rst $38
    ldh a, [$f8]

jr_003_703b:
    ld hl, sp-$04
    db $fc
    cp $f6
    ei
    ld a, e
    rst $20
    rst $28
    ld a, a
    cp a
    ld a, a
    cp a
    ld a, a
    inc sp
    ld l, e
    inc hl
    xor d
    ld b, e
    and [hl]
    rst $20
    nop
    db $e3
    ret nz

    db $e3
    pop af
    rst $30
    ld hl, sp+$38
    or a
    db $fc
    inc a
    add sp, $28
    ldh [$28], a
    ld h, b
    db $10
    jr nz, @+$52

    ld b, b
    and b
    and b
    ld [hl], b
    ld a, b
    adc b
    nop
    nop
    inc bc
    inc bc
    inc c
    inc c
    inc de
    db $10
    inc l
    inc hl
    dec hl
    inc h
    ld d, a
    ld c, b
    ld d, a
    ld c, b
    nop
    nop
    ret nz

    ret nz

    jr nc, @+$32

    ret z

    ld [$cc34], sp
    call nc, $ea2c

jr_003_7086:
    ld d, $ea
    ld d, $57
    ld c, b
    ld d, a
    ld c, b
    dec hl
    inc h
    inc l
    inc hl
    inc de
    inc e
    inc c
    rrca

jr_003_7095:
    inc bc
    inc bc
    nop
    nop
    ld [$ea16], a
    ld d, $d4
    inc l
    inc [hl]
    call z, Call_000_38c8
    jr nc, jr_003_7095

    ret nz

    ret nz

    nop
    nop
    inc e
    db $10
    inc e
    nop
    ccf
    jr nz, jr_003_70ef

    jr nz, jr_003_70e1

    jr nc, jr_003_70d3

    ld c, b
    ld a, [hl]
    ld c, l
    ld [hl], e
    ld e, a
    ld [$0008], sp
    ld [$0400], sp
    add h
    inc b
    db $fc
    inc e
    ld [$fe32], a
    ld l, d
    sbc [hl]
    ld a, [$3e33]
    dec e
    ld c, $1d
    ld [de], a
    inc d
    inc e
    ld b, $09

jr_003_70d3:
    rrca
    ld [$0407], sp
    ld [bc], a
    rlca
    sub h
    db $fc
    add sp, $68
    ret z

    ld [$3010], sp

jr_003_70e1:
    db $10
    ret nc

    ret nz

    jr nz, jr_003_7086

    jr nc, jr_003_7158

    ldh a, [rP1]
    nop
    ld bc, $0201
    ld [bc], a

jr_003_70ef:
    ld [hl+], a
    ld [hl+], a
    ld d, l
    ld d, h
    ld e, l
    ld c, h
    ld e, [hl]
    ld b, c
    ld l, $21

jr_003_70f9:
    nop
    nop
    nop
    nop
    add b
    add b
    adc b
    adc b
    ld d, h
    call c, $ec74
    db $f4
    inc c
    ld hl, sp+$08
    inc l
    inc hl
    ld e, b
    ld b, a
    ld e, b
    ld b, a
    jr z, jr_003_7138

    inc d
    inc de
    rrca
    inc c
    inc bc
    inc bc
    nop
    nop
    ld a, b
    adc b
    inc [hl]
    call z, $cc34
    jr z, jr_003_70f9

    ld d, b
    or b
    ldh [$60], a
    add b
    add b
    nop
    nop
    rrca
    rrca
    rra
    rra
    ccf
    ccf
    jr c, jr_003_7169

    jr nc, jr_003_7163

    ld [hl], e
    ld [hl], e
    rst $38
    rst $38
    rst $38

jr_003_7138:
    rst $38
    ldh a, [$f0]
    ld hl, sp-$08
    db $fc
    db $fc
    inc e
    inc e
    inc c
    inc c
    adc $ce
    rst $08
    rst $08
    rra
    rra
    cp $fe
    cp $fe
    rst $38
    rst $38
    cp $fe
    cp $fe
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38

jr_003_7158:
    rst $38
    ccf
    ccf
    ld a, a
    ld a, a
    rst $38
    rst $38
    ld a, a
    ld a, a
    ld a, a
    ld a, a

jr_003_7163:
    rst $38
    rst $38
    rst $38
    rst $38

jr_003_7167:
    rst $38
    rst $38

jr_003_7169:
    nop
    nop
    rra
    rra
    ccf
    inc h
    ld h, b
    ld e, a
    ld h, b
    ld e, a
    ld h, b
    ld a, a
    ld h, b
    ld e, a
    ld h, b
    ld e, a
    nop
    nop
    nop
    nop
    add b
    add b
    add b
    add b
    ret nz

    ret nz

    ldh [$a0], a
    jr nz, jr_003_7167

    jr nc, jr_003_71b9

    inc a
    ld a, $0c
    ld a, [bc]
    rlca
    rlca
    ld bc, $0001
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    xor b
    jr z, @+$4a

    ld [$88a8], sp
    jr jr_003_71b9

    db $f4
    db $f4
    ld a, [bc]
    ld a, [bc]
    ld b, $06
    nop
    nop
    call Call_000_3ec4
    ld hl, $c6e8
    ld a, [$d2e8]
    add $06
    ld e, a
    ld d, $00
    add hl, de
    add hl, de

jr_003_71b9:
    add hl, de
    ld e, $03
    add hl, de
    ld e, a
    ld a, b
    and a
    jr z, jr_003_71c6

jr_003_71c2:
    add hl, de
    dec b
    jr nz, jr_003_71c2

jr_003_71c6:
    add hl, bc
    ld a, [$d07c]
    ld [hl], a
    ld a, [$d2de]
    ld c, a
    ld a, [$d2df]
    ld b, a
    call Call_003_725c
    ret c

    push hl
    ld l, e
    ld h, $00
    ld e, $06
    ld d, h
    add hl, hl
    add hl, hl
    add hl, de
    add hl, bc
    pop bc
    call Call_003_725c
    ret c

Call_003_71e7:
Jump_003_71e7:
    ld a, [$d034]
    inc a
    ret z

    ldh a, [$ba]
    push af
    ldh a, [$d7]
    push af
    xor a
    ldh [$ba], a
    ldh [$d7], a
    call Call_000_26bb
    call Call_000_3e1d
    ld hl, $d4a5
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $ffc0
    add hl, de
    ld a, h
    and $03
    or $98
    ld a, l
    ld [$cee4], a
    ld a, h
    ld [$cee5], a
    ld a, $02
    ld [$ffbe], a
    ld c, $09

jr_003_721b:
    push bc
    push hl
    push hl
    ld hl, $c378
    ld de, $0014
    ld a, [$ffbe]

jr_003_7227:
    add hl, de
    dec a
    jr nz, jr_003_7227

    call Call_000_28b7
    pop hl
    ld de, $0020
    ld a, [$ffbe]
    ld c, a

jr_003_7236:
    add hl, de
    ld a, h
    and $03
    or $98
    dec c
    jr nz, jr_003_7236

    ldh [$d2], a
    ld a, l
    ldh [$d1], a
    ld a, $02
    ldh [$d0], a
    call Call_000_0b31
    ld hl, $ffbe
    inc [hl]
    inc [hl]
    pop hl
    pop bc
    dec c
    jr nz, jr_003_721b

    pop af
    ldh [$d7], a
    pop af
    ldh [$ba], a
    ret


Call_003_725c:
    ld a, h
    sub b
    ret nz

    ld a, l
    sub c
    ret


    xor a
    ld [$cd65], a
    ld a, [$d2e6]
    and a
    jr z, jr_003_7279

    cp $07
    jr nz, jr_003_7285

    ld a, [$cfad]
    cp $50
    jr nz, jr_003_7285

    jr jr_003_72a4

jr_003_7279:
    dec a
    ld a, [$cfad]
    cp $3d
    jr z, jr_003_72a4

    cp $52
    jr z, jr_003_72a4

jr_003_7285:
    ld hl, $728b
    jp Jump_000_3c79


    db $ed
    jr z, @+$2f

    ld h, a
    daa
    ret c

    inc sp
    ld c, a
    or a
    jp c, $b3bf

    push bc
    ld a, a
    db $d3
    ret


    ld h, $7f
    or c
    ret c

    rst $08
    cp [hl]
    sbc $e7
    ld e, b

jr_003_72a4:
    ld [$cd4d], a
    ld a, $01
    ld [$cd65], a
    ld a, [$cf79]
    ld hl, $d257
    call Call_000_2fb1
    ld hl, $d6af
    set 6, [hl]
    call Call_000_3e04
    call Call_000_0188
    call Call_000_3dee
    ld a, $90
    ldh [$b0], a
    call Call_000_3e07
    call Call_000_0b3c
    call Call_000_26bb
    call Call_000_373e
    call Call_000_3e07
    xor a
    ldh [$b0], a
    ld hl, $7314
    call Call_000_3c79
    call Call_000_374a
    ld hl, $d6af
    res 6, [hl]
    ld a, $ff
    ld [$cfb2], a
    call Call_003_7329
    ld de, $7432
    call Call_003_73d1
    call Call_003_71e7
    ld b, $1e
    ld hl, $5ec2
    call Call_000_3620
    ld a, $01
    ld [$cfb2], a
    ld a, $ac
    call Call_000_0e45
    ld a, $90
    ldh [$b0], a
    call Call_000_0ebd
    jp Jump_003_71e7


    db $ed
    jr z, @+$6d

    ld h, a
    jp z, $b24f

    or c
    or d
    daa
    ret c

    inc sp
    ld a, a
    or a
    ret c

    rst $08
    cp b
    rst $18
    ret nz

    rst $20
    ld e, b

Call_003_7329:
    xor a
    ld [$cd50], a
    ld a, $e4
    ldh [rOBP1], a
    ld a, [$cd4d]
    cp $52
    jr z, jr_003_7352

    ld de, $42d0
    ld hl, $8fc0
    ld bc, $1902
    call Call_000_02dd
    ld de, $43d0
    ld hl, $8fe0
    ld bc, $1902
    call Call_000_02dd
    jr jr_003_7387

jr_003_7352:
    ld hl, $8fc0
    call Call_003_737e
    ld hl, $8fd0
    call Call_003_737e
    ld hl, $8fe0
    call Call_003_737e
    ld hl, $8ff0
    call Call_003_737e
    call Call_003_7387
    ld hl, $c393
    ld de, $0004
    ld a, $30
    ld c, e

jr_003_7376:
    ld [hl], a
    add hl, de
    xor $60
    dec c
    jr nz, jr_003_7376

    ret


Call_003_737e:
    ld de, $45b7
    ld bc, $1e01
    jp Jump_000_02dd


Call_003_7387:
jr_003_7387:
    call Call_003_739a
    ld a, $09
    ld de, $7392
    jp Jump_000_3ae1


    db $fc
    db $10
    db $fd
    db $10
    cp $10
    rst $38
    db $10

Call_003_739a:
    ld hl, $c104
    ld a, [hl+]
    ld b, a
    inc hl
    ld a, [hl+]
    ld c, a
    inc hl
    inc hl
    ld a, [hl]
    srl a
    ld e, a
    ld d, $00
    ld a, [$cd50]
    and a
    ld hl, $73c1
    jr z, jr_003_73b6

    ld hl, $73c9

jr_003_73b6:
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld a, b
    add d
    ld b, a
    ld a, c
    add e
    ld c, a
    ret


    ld [$0824], sp
    inc b
    ld hl, sp+$14
    jr @+$16

    ld [$0834], sp
    db $f4
    add sp, $14
    jr z, @+$16

Call_003_73d1:
    push de
    ld a, [$d2e8]
    add $06
    ld c, a
    ld b, $00
    ld d, $00
    ld hl, $d2de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    add hl, bc
    ld a, [$c109]
    and a
    jr z, jr_003_73f9

    cp $04
    jr z, jr_003_7401

    cp $08
    jr z, jr_003_7409

    ld a, [$d2e3]
    and a
    jr z, jr_003_7412

    jr jr_003_741e

jr_003_73f9:
    ld a, [$d2e2]
    and a
    jr z, jr_003_7412

    jr jr_003_7411

jr_003_7401:
    ld a, [$d2e2]
    and a
    jr z, jr_003_7413

    jr jr_003_7412

jr_003_7409:
    ld a, [$d2e3]
    and a
    jr z, jr_003_7418

    jr jr_003_7412

jr_003_7411:
    add hl, bc

jr_003_7412:
    add hl, bc

jr_003_7413:
    ld e, $02
    add hl, de
    jr jr_003_7422

jr_003_7418:
    ld e, $01
    add hl, bc
    add hl, de
    jr jr_003_7422

jr_003_741e:
    ld e, $03
    add hl, bc
    add hl, de

jr_003_7422:
    pop de
    ld a, [hl]
    ld c, a

jr_003_7425:
    ld a, [de]
    inc de
    inc de
    cp $ff
    ret z

    cp c
    jr nz, jr_003_7425

    dec de
    ld a, [de]
    ld [hl], a
    ret


    ld [hl-], a
    ld l, l
    inc sp
    ld l, h
    inc [hl]
    ld l, a
    dec [hl]
    ld c, h
    ld h, b
    ld l, [hl]
    dec bc
    ld a, [bc]
    inc a
    dec [hl]
    ccf
    dec [hl]
    dec a
    ld [hl], $ff
    ld a, [$d2dd]
    cp $0c
    jr nc, jr_003_7457

    ld c, a
    ld b, $01
    ld hl, $d68a
    ld a, $10
    call Call_000_3e9d

jr_003_7457:
    ld hl, $4085
    ld a, [$d2dd]
    ld b, $00
    ld c, a
    add hl, bc
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    push hl
    ld de, $427a
    ld a, l
    sub e
    jr nc, jr_003_746e

    dec h

jr_003_746e:
    ld l, a
    ld a, h
    sub d
    ld h, a
    ld a, h
    ldh [$95], a
    ld a, l
    ldh [$96], a
    xor a
    ldh [$97], a
    ldh [$98], a
    ld a, $03
    ldh [$99], a
    ld b, $02
    call Call_000_3902
    ld a, [$d2dd]
    ld b, a
    ldh a, [$98]
    ld c, a
    ld de, $d54d
    pop hl

jr_003_7491:
    ld a, [hl+]
    cp $ff
    jr z, jr_003_74a3

    cp b
    jr nz, jr_003_74a3

    ld a, [hl+]
    inc hl
    ld [de], a
    inc de
    ld a, c
    inc c
    ld [de], a
    inc de
    jr jr_003_7491

jr_003_74a3:
    ld a, $ff
    ld [de], a
    ret


Jump_003_74a7:
    ld hl, $d525
    ld bc, $0020
    xor a
    call Call_000_372a
    ld hl, $427a
    xor a
    ld [$d027], a

jr_003_74b8:
    ld a, [hl+]
    cp $ff
    ret z

    push hl
    inc hl
    ld a, [hl]
    cp $11
    jr nz, jr_003_74cf

    ld hl, $d525
    ld a, [$d027]
    ld c, a
    ld b, $01
    call Call_003_7518

jr_003_74cf:
    ld hl, $d027
    inc [hl]
    pop hl
    inc hl
    inc hl
    jr jr_003_74b8

    ldh a, [$da]
    swap a
    ld b, a
    ld hl, $d54d

jr_003_74e0:
    ld a, [hl+]
    cp $ff
    jr z, jr_003_74f6

    cp b
    ld a, [hl+]
    jr nz, jr_003_74e0

    ld c, a
    ld b, $02
    ld hl, $d525
    call Call_003_7518
    ld a, c
    and a
    jr nz, jr_003_74f7

jr_003_74f6:
    xor a

jr_003_74f7:
    ldh [$e5], a
    ret


    ld hl, $d525
    ld a, [$cc4d]
    ld c, a
    ld b, $00
    call Call_003_7518
    jp Jump_000_0ebd


    ld hl, $d525
    ld a, [$cc4d]
    ld c, a
    ld b, $01
    call Call_003_7518
    jp Jump_000_0ebd


Call_003_7518:
    push hl
    push de
    push bc
    ld a, c
    ld d, a
    and $07
    ld e, a
    ld a, d
    srl a
    srl a
    srl a
    add l
    ld l, a
    jr nc, jr_003_752c

    inc h

jr_003_752c:
    inc e
    ld d, $01

jr_003_752f:
    dec e
    jr z, jr_003_7536

    sla d
    jr jr_003_752f

jr_003_7536:
    ld a, b
    and a
    jr z, jr_003_7545

    cp $02
    jr z, jr_003_754e

    ld a, [hl]
    ld b, a
    ld a, d
    or b
    ld [hl], a
    jr jr_003_7552

jr_003_7545:
    ld a, [hl]
    ld b, a
    ld a, d
    xor $ff
    and b
    ld [hl], a
    jr jr_003_7552

jr_003_754e:
    ld a, [hl]
    ld b, a
    ld a, d
    and b

jr_003_7552:
    pop bc
    pop de
    pop hl
    ld c, a
    ret


    ld a, [$d6a7]
    bit 0, a
    ret z

    ld a, [$cd5b]
    bit 1, a
    ret nz

    xor a
    ldh [$8c], a
    call Call_000_2582
    ldh a, [$8c]
    ld [$d697], a
    and a
    jp z, Jump_003_760f

    ld hl, $c101
    ld d, $00
    ldh a, [$8c]
    swap a
    ld e, a
    add hl, de
    res 7, [hl]
    call Call_000_35a2
    ld a, [hl]
    cp $10
    jp nz, Jump_003_760f

    ld hl, $cd5b
    bit 6, [hl]
    set 6, [hl]
    ret z

    ldh a, [$b4]
    and $f0
    ret z

    ld a, $5a
    call Call_000_3e9d
    ld a, [$d69b]
    and a
    jp nz, Jump_003_760f

    ldh a, [$b4]
    ld b, a
    ld a, [$c109]
    cp $04
    jr z, jr_003_75bb

    cp $08
    jr z, jr_003_75c3

    cp $0c
    jr z, jr_003_75cb

    bit 7, b
    ret z

    ld de, $75e1
    jr jr_003_75d1

jr_003_75bb:
    bit 6, b
    ret z

    ld de, $75df
    jr jr_003_75d1

jr_003_75c3:
    bit 5, b
    ret z

    ld de, $75e3
    jr jr_003_75d1

jr_003_75cb:
    bit 4, b
    ret z

    ld de, $75e5

jr_003_75d1:
    call Call_000_3684
    ld a, $a8
    call Call_000_0e45
    ld hl, $cd5b
    set 1, [hl]
    ret


    ld b, b
    rst $38
    nop
    rst $38
    add b
    rst $38
    ret nz

    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    ld hl, $5f80
    ld b, $1e
    call Call_000_3620
    call Call_003_406c
    ld [$cd66], a
    call Call_003_760f
    set 7, [hl]
    ld a, [$d697]
    ldh [$8c], a
    call Call_000_35a2
    ld [hl], $10
    ld a, $ac
    jp Jump_000_0e45


Call_003_760f:
Jump_003_760f:
    ld hl, $cd5b
    res 1, [hl]
    res 6, [hl]
    ret


    ld de, $d123
    ld a, [$cc49]
    and $0f
    jr z, jr_003_7624

    ld de, $d81b

jr_003_7624:
    ld a, [de]
    inc a
    cp $07
    ret nc

    ld [de], a
    ld a, [de]
    ld [$ffe4], a
    add e
    ld e, a
    jr nc, jr_003_7633

    inc d

jr_003_7633:
    ld a, [$cf78]
    ld [de], a
    inc de
    ld a, $ff
    ld [de], a
    ld hl, $d233
    ld a, [$cc49]
    and $0f
    jr z, jr_003_7648

    ld hl, $d92b

jr_003_7648:
    ld a, [$ffe4]
    dec a
    call Call_000_3ac7
    ld d, h
    ld e, l
    ld hl, $d11d
    ld bc, $0006
    call Call_000_01bb
    ld a, [$cc49]
    and a
    jr nz, jr_003_7674

    ld hl, $d257
    ld a, [$ffe4]
    dec a
    call Call_000_3ac7
    ld a, $02
    ld [$d05a], a
    ld a, $4e
    call Call_000_3e9d

jr_003_7674:
    ld hl, $d12b
    ld a, [$cc49]
    and $0f
    jr z, jr_003_7681

    ld hl, $d823

jr_003_7681:
    ld a, [$ffe4]
    dec a
    ld bc, $002c
    call Call_000_3ad1
    ld e, l
    ld d, h
    push hl
    ld a, [$cf78]
    ld [$d092], a
    call Call_000_2f2e
    ld hl, $d095
    ld a, [hl+]
    ld [de], a
    inc de
    pop hl
    push hl
    ld a, [$cc49]
    and $0f
    ld a, $98
    ld b, $88
    jr nz, jr_003_76e9

    ld a, [$cf78]
    ld [$d0e3], a
    push de
    ld a, $3a
    call Call_000_3e9d
    pop de
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $02
    ld hl, $d27b
    call Call_003_799f
    ld a, c
    ld [$d118], a
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $01
    push bc
    call Call_003_799f
    pop bc
    ld hl, $d28e
    call Call_003_799f
    pop hl
    push hl
    ld a, [$d034]
    and a
    jr nz, jr_003_770c

    call Call_000_3e8c
    ld b, a
    call Call_000_3e8c

jr_003_76e9:
    push bc
    ld bc, $001b
    add hl, bc
    pop bc
    ld [hl+], a
    ld [hl], b
    ld bc, $fff4
    add hl, bc
    ld a, $01
    ld c, a
    xor a
    ld b, a
    call Call_000_3994
    ldh a, [$97]
    ld [de], a
    inc de
    ldh a, [$98]
    ld [de], a
    inc de
    xor a
    ld [de], a
    inc de
    ld [de], a
    inc de
    jr jr_003_772a

jr_003_770c:
    ld bc, $001b
    add hl, bc
    ld a, [$cfd8]
    ld [hl+], a
    ld a, [$cfd9]
    ld [hl], a
    ld a, [$cfcd]
    ld [de], a
    inc de
    ld a, [$cfce]
    ld [de], a
    inc de
    xor a
    ld [de], a
    inc de
    ld a, [$cfd0]
    ld [de], a
    inc de

jr_003_772a:
    ld hl, $d09b
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    ld hl, $d0a4
    ld a, [hl+]
    inc de
    push de
    ld [de], a
    ld a, [hl+]
    inc de
    ld [de], a
    ld a, [hl+]
    inc de
    ld [de], a
    ld a, [hl+]

Call_003_7743:
    inc de
    ld [de], a
    push de
    dec de
    dec de
    dec de
    xor a
    ld [$cee4], a
    ld a, $3e
    call Call_000_3e9d
    pop de
    ld a, [$d2d8]
    inc de
    ld [de], a
    ld a, [$d2d9]
    inc de
    ld [de], a
    push de
    ld a, [$d0ec]
    ld d, a
    ld hl, $4fb5
    ld b, $16
    call Call_000_3620
    pop de
    inc de
    ldh a, [$96]
    ld [de], a
    inc de
    ldh a, [$97]
    ld [de], a
    inc de
    ldh a, [$98]
    ld [de], a
    xor a
    ld b, $0a

jr_003_777a:
    inc de
    ld [de], a
    dec b
    jr nz, jr_003_777a

    inc de
    inc de
    pop hl
    call Call_003_77ac
    inc de
    ld a, [$d0ec]
    ld [de], a
    inc de
    ld a, [$d034]
    dec a
    jr nz, jr_003_779d

    ld hl, $cfdb
    ld bc, $000a
    call Call_000_01bb
    pop hl
    jr jr_003_77a7

jr_003_779d:
    pop hl
    ld bc, $0010
    add hl, bc
    ld b, $00
    call Call_000_3980

jr_003_77a7:
    scf
    ret


    call Call_000_3ec4

Call_003_77ac:
    ld b, $04

jr_003_77ae:
    ld a, [hl+]
    and a
    jr z, jr_003_77cd

    dec a
    push hl
    push de
    push bc
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld de, $cd68
    ld a, $0e
    call Call_000_01a3
    pop bc
    pop de
    pop hl
    ld a, [$cd6d]

jr_003_77cd:
    inc de
    ld [de], a
    dec b
    jr nz, jr_003_77ae

    ret


    ld hl, $d123
    ld a, [hl]
    cp $06
    scf
    ret z

    inc a
    ld [hl], a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [$cf78]
    ld [hl+], a
    ld [hl], $ff
    ld hl, $d12b
    ld a, [$d123]
    dec a
    ld bc, $002c
    call Call_000_3ad1
    ld e, l
    ld d, h
    ld hl, $cf7f
    call Call_000_01bb
    ld hl, $d233
    ld a, [$d123]
    dec a
    call Call_000_3ac7
    ld d, h
    ld e, l
    ld hl, $d92b
    ld a, [$cf79]
    call Call_000_3ac7
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d257
    ld a, [$d123]
    dec a
    call Call_000_3ac7
    ld d, h
    ld e, l
    ld hl, $d94f
    ld a, [$cf79]
    call Call_000_3ac7
    ld bc, $0006
    call Call_000_01bb
    ld a, [$cf78]
    ld [$d0e3], a
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $01
    ld hl, $d27b
    push bc
    call Call_003_799f
    pop bc
    ld hl, $d28e
    call Call_003_799f
    and a
    ret


    ld a, [$cf7c]
    and a
    jr z, jr_003_786f

    cp $02
    jr z, jr_003_786f

    cp $03
    ld hl, $d991
    jr z, jr_003_78ab

    ld hl, $d9b2
    ld a, [hl]
    cp $1e
    jr nz, jr_003_7879

    jr jr_003_7877

jr_003_786f:
    ld hl, $d123
    ld a, [hl]
    cp $06
    jr nz, jr_003_7879

jr_003_7877:
    scf
    ret


jr_003_7879:
    inc a
    ld [hl], a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [$cf7c]
    cp $02
    ld a, [$d991]
    jr z, jr_003_788c

    ld a, [$cf78]

jr_003_788c:
    ld [hl+], a
    ld [hl], $ff
    ld a, [$cf7c]
    dec a
    ld hl, $d12b
    ld bc, $002c
    ld a, [$d123]
    jr nz, jr_003_78a7

    ld hl, $d9d2
    ld bc, $0021
    ld a, [$d9b2]

jr_003_78a7:
    dec a
    call Call_000_3ad1

jr_003_78ab:
    push hl
    ld e, l
    ld d, h
    ld a, [$cf7c]
    and a
    ld hl, $d9d2
    ld bc, $0021
    jr z, jr_003_78c7

    cp $02
    ld hl, $d991
    jr z, jr_003_78cd

    ld hl, $d12b
    ld bc, $002c

jr_003_78c7:
    ld a, [$cf79]
    call Call_000_3ad1

jr_003_78cd:
    push hl
    push de
    ld bc, $0021
    call Call_000_01bb
    pop de
    pop hl
    ld a, [$cf7c]
    and a
    jr z, jr_003_78ea

    cp $02
    jr z, jr_003_78ea

    ld bc, $0021
    add hl, bc
    ld a, [hl]
    inc de
    inc de
    inc de
    ld [de], a

jr_003_78ea:
    ld a, [$cf7c]
    cp $03
    ld de, $d98b
    jr z, jr_003_7909

    dec a
    ld hl, $d233
    ld a, [$d123]
    jr nz, jr_003_7903

    ld hl, $ddb0
    ld a, [$d9b2]

jr_003_7903:
    dec a
    call Call_000_3ac7
    ld d, h
    ld e, l

jr_003_7909:
    ld hl, $ddb0
    ld a, [$cf7c]
    and a
    jr z, jr_003_791c

    ld hl, $d98b
    cp $02
    jr z, jr_003_7922

    ld hl, $d233

jr_003_791c:
    ld a, [$cf79]
    call Call_000_3ac7

jr_003_7922:
    ld bc, $0006
    call Call_000_01bb
    ld a, [$cf7c]
    cp $03
    ld de, $d985
    jr z, jr_003_7947

    dec a
    ld hl, $d257
    ld a, [$d123]
    jr nz, jr_003_7941

    ld hl, $de64
    ld a, [$d9b2]

jr_003_7941:
    dec a
    call Call_000_3ac7
    ld d, h
    ld e, l

jr_003_7947:
    ld hl, $de64
    ld a, [$cf7c]
    and a
    jr z, jr_003_795a

    ld hl, $d985
    cp $02
    jr z, jr_003_7960

    ld hl, $d257

jr_003_795a:
    ld a, [$cf79]
    call Call_000_3ac7

jr_003_7960:
    ld bc, $0006
    call Call_000_01bb
    pop hl
    ld a, [$cf7c]
    cp $01
    jr z, jr_003_799a

    cp $03
    jr z, jr_003_799a

    push hl
    srl a
    add $02
    ld [$cc49], a
    call Call_000_2d68
    ld b, $16
    ld hl, $4f8e
    call Call_000_3620
    ld a, d
    ld [$d0ec], a
    pop hl
    ld bc, $0021
    add hl, bc
    ld [hl+], a
    ld d, h
    ld e, l
    ld bc, $ffee
    add hl, bc
    ld b, $01
    call Call_000_3980

jr_003_799a:
    and a
    ret


    call Call_000_3ec4

Call_003_799f:
    push hl
    push de
    push bc
    ld a, c
    ld d, a
    and $07
    ld e, a
    ld a, d
    srl a
    srl a
    srl a
    add l
    ld l, a
    jr nc, jr_003_79b3

    inc h

jr_003_79b3:
    inc e
    ld d, $01

jr_003_79b6:
    dec e
    jr z, jr_003_79bd

    sla d
    jr jr_003_79b6

jr_003_79bd:
    ld a, b
    and a
    jr z, jr_003_79cb

    cp $02
    jr z, jr_003_79d3

    ld b, [hl]
    ld a, d
    or b
    ld [hl], a
    jr jr_003_79d6

jr_003_79cb:
    ld b, [hl]
    ld a, d
    xor $ff
    and b
    ld [hl], a
    jr jr_003_79d6

jr_003_79d3:
    ld b, [hl]
    ld a, d
    and b

jr_003_79d6:
    pop bc
    pop de
    pop hl
    ld c, a
    ret


    ld hl, $d124
    ld de, $d12c

jr_003_79e1:
    ld a, [hl+]
    cp $ff
    jr z, jr_003_7a3c

    push hl
    push de
    ld hl, $0003
    add hl, de
    xor a
    ld [hl], a
    push de
    ld b, $04

jr_003_79f1:
    ld hl, $0007
    add hl, de
    ld a, [hl]
    and a
    jr z, jr_003_7a21

    dec a
    ld hl, $001c
    add hl, de
    push hl
    push de
    push bc
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld de, $cd68
    ld a, $0e
    call Call_000_01a3
    ld a, [$cd6d]
    pop bc
    pop de
    pop hl
    inc de
    push bc
    ld b, a
    ld a, [hl]
    and $c0
    add b
    ld [hl], a
    pop bc

jr_003_7a21:
    dec b
    jr nz, jr_003_79f1

    pop de
    ld hl, $0021
    add hl, de
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    pop de
    pop hl
    push hl
    ld bc, $002c
    ld h, d
    ld l, e
    add hl, bc
    ld d, h
    ld e, l
    pop hl
    jr jr_003_79e1

jr_003_7a3c:
    xor a
    ld [$cf79], a
    ld [$d0e3], a
    ld a, [$d123]
    ld b, a

jr_003_7a47:
    push bc
    call Call_003_68d9
    pop bc
    ld hl, $cf79
    inc [hl]
    dec b
    jr nz, jr_003_7a47

    ret


    call Call_000_3ec4
    xor a
    ldh [$a5], a
    ldh [$a6], a
    ldh [$a7], a
    ld d, $01

jr_003_7a60:
    ldh a, [$a2]
    and $f0
    jr nz, jr_003_7a91

    inc d
    ldh a, [$a2]
    swap a
    and $f0
    ld b, a
    ldh a, [$a3]
    swap a
    ldh [$a3], a
    and $0f
    or b
    ldh [$a2], a
    ldh a, [$a3]
    and $f0
    ld b, a
    ldh a, [$a4]
    swap a
    ldh [$a4], a
    and $0f
    or b
    ldh [$a3], a
    ldh a, [$a4]
    and $f0
    ldh [$a4], a
    jr jr_003_7a60

jr_003_7a91:
    push de
    push de
    call Call_003_7b36
    pop de
    ld a, b
    swap a
    and $f0
    ldh [$a5], a
    dec d
    jr z, jr_003_7af2

    push de
    call Call_003_7b0d
    call Call_003_7b36
    pop de
    ldh a, [$a5]
    or b
    ldh [$a5], a
    dec d
    jr z, jr_003_7af2

    push de
    call Call_003_7b0d
    call Call_003_7b36
    pop de
    ld a, b
    swap a
    and $f0
    ldh [$a6], a
    dec d
    jr z, jr_003_7af2

    push de
    call Call_003_7b0d
    call Call_003_7b36
    pop de
    ldh a, [$a6]
    or b
    ldh [$a6], a
    dec d
    jr z, jr_003_7af2

    push de
    call Call_003_7b0d
    call Call_003_7b36
    pop de
    ld a, b
    swap a
    and $f0
    ldh [$a7], a
    dec d
    jr z, jr_003_7af2

    push de
    call Call_003_7b0d
    call Call_003_7b36
    pop de
    ldh a, [$a7]
    or b
    ldh [$a7], a

jr_003_7af2:
    ldh a, [$a5]
    ldh [$a2], a
    ldh a, [$a6]
    ldh [$a3], a
    ldh a, [$a7]
    ldh [$a4], a
    pop de
    ld a, $06
    sub d
    and a
    ret z

jr_003_7b04:
    push af
    call Call_003_7b0d
    pop af
    dec a
    jr nz, jr_003_7b04

    ret


Call_003_7b0d:
    ldh a, [$a4]
    swap a
    and $0f
    ld b, a
    ldh a, [$a3]
    swap a
    ldh [$a3], a
    and $f0
    or b
    ldh [$a4], a
    ldh a, [$a3]
    and $0f
    ld b, a
    ldh a, [$a2]
    swap a
    ldh [$a2], a
    and $f0
    or b
    ldh [$a3], a
    ldh a, [$a2]
    and $0f
    ldh [$a2], a
    ret


Call_003_7b36:
    ld bc, $0003

jr_003_7b39:
    ld de, $ff9f
    ld hl, $ffa2
    push bc
    call Call_000_3ad8
    pop bc
    ret c

    inc b
    ld de, $ffa1
    ld hl, $ffa4
    push bc
    call Call_003_7b6f
    pop bc
    jr jr_003_7b39

    call Call_000_3ec4
    and a
    ld b, c

jr_003_7b58:
    ld a, [de]
    adc [hl]
    daa
    ld [de], a
    dec de
    dec hl
    dec c
    jr nz, jr_003_7b58

    jr nc, jr_003_7b6b

    ld a, $99
    inc de

jr_003_7b66:
    ld [de], a
    inc de
    dec b
    jr nz, jr_003_7b66

jr_003_7b6b:
    ret


    call Call_000_3ec4

Call_003_7b6f:
    and a
    ld b, c

jr_003_7b71:
    ld a, [de]
    sbc [hl]
    daa
    ld [de], a
    dec de
    dec hl
    dec c
    jr nz, jr_003_7b71

    jr nc, jr_003_7b85

    ld a, $00
    inc de

jr_003_7b7f:
    ld [de], a
    inc de
    dec b
    jr nz, jr_003_7b7f

    scf

jr_003_7b85:
    ret


    call Call_000_3e8c
    ldh a, [$d4]
    ld [$d2d8], a
    call Call_000_3e8c
    ldh a, [$d3]
    ld [$d2d9], a
    ld a, $ff
    ld [$d69a], a
    ld hl, $d123
    call Call_003_7bdb
    ld hl, $d9b2
    call Call_003_7bdb
    ld hl, $d2a1
    call Call_003_7bdb
    ld hl, $d4b9
    call Call_003_7bdb
    xor a
    ld [$cc49], a
    ld [$d2d5], a
    ld [$d2d6], a
    ld [$d523], a
    ld [$d524], a
    ld [$d2cb], a
    ld [$d2cd], a
    ld a, $30
    ld [$d2cc], a
    ld hl, $d56f
    ld bc, $00c8
    xor a
    call Call_000_372a
    jp Jump_003_74a7


Call_003_7bdb:
    xor a
    ld [hl+], a
    dec a
    ld [hl], a
    ret


    call Call_000_3ec4
    ld hl, $d2a1

jr_003_7be6:
    inc hl
    ld a, [hl+]
    cp $ff
    jr z, jr_003_7bf2

    cp b
    jr nz, jr_003_7be6

    ld a, [hl]
    ld b, a
    ret


jr_003_7bf2:
    ld b, $00
    ret


    ld hl, $cc97
    ld de, $0000
    xor a
    ldh [$97], a
    ldh [$98], a
    ldh [$99], a
    ldh [$9a], a

Jump_003_7c04:
    ldh a, [$99]
    ld b, a
    ldh a, [$95]
    call Call_000_367d
    ld d, a
    and a
    jr nz, jr_003_7c16

    ldh a, [$98]
    set 0, a
    ldh [$98], a

jr_003_7c16:
    ldh a, [$9a]
    ld b, a
    ldh a, [$96]
    call Call_000_367d
    ld e, a
    and a
    jr nz, jr_003_7c28

    ldh a, [$98]
    set 1, a
    ldh [$98], a

jr_003_7c28:
    ldh a, [$98]
    cp $03
    jr z, jr_003_7c62

    ld a, e
    cp d
    jr c, jr_003_7c46

    ldh a, [$9d]
    bit 1, a
    jr nz, jr_003_7c3c

    ld d, $c0
    jr jr_003_7c3e

jr_003_7c3c:
    ld d, $80

jr_003_7c3e:
    ldh a, [$9a]
    add $01
    ldh [$9a], a
    jr jr_003_7c58

jr_003_7c46:
    ldh a, [$9d]
    bit 0, a
    jr nz, jr_003_7c50

    ld d, $00
    jr jr_003_7c52

jr_003_7c50:
    ld d, $40

jr_003_7c52:
    ldh a, [$99]
    add $01
    ldh [$99], a

jr_003_7c58:
    ld a, d
    ld [hl+], a
    ldh a, [$97]
    inc a
    ldh [$97], a
    jp Jump_003_7c04


jr_003_7c62:
    ld [hl], $ff
    ret


    xor a
    ldh [$9d], a
    ld a, [$c104]
    ld d, a
    ld a, [$c106]
    ld e, a
    ld hl, $c100
    ldh a, [$95]
    add l
    add $04
    ld l, a
    jr nc, jr_003_7c7c

    inc h

jr_003_7c7c:
    ld a, d
    ld b, a
    ld a, [hl+]
    call Call_000_367d
    jr nc, jr_003_7c8f

    push hl
    ld hl, $ff9d
    bit 0, [hl]
    set 0, [hl]
    pop hl
    jr jr_003_7c98

jr_003_7c8f:
    push hl
    ld hl, $ff9d
    bit 0, [hl]
    res 0, [hl]
    pop hl

jr_003_7c98:
    push hl
    ld hl, $ffe5
    ld [hl+], a
    ld a, $10
    ld [hl+], a
    call Call_000_36b5
    ld a, [hl]
    ldh [$95], a
    pop hl
    inc hl
    ld b, e
    ld a, [hl]
    call Call_000_367d
    jr nc, jr_003_7cba

    push hl
    ld hl, $ff9d
    bit 1, [hl]
    set 1, [hl]
    pop hl
    jr jr_003_7cc3

jr_003_7cba:
    push hl
    ld hl, $ff9d
    bit 1, [hl]
    res 1, [hl]
    pop hl

jr_003_7cc3:
    ld [$ffe5], a
    ld a, $10
    ld [$ffe6], a
    call Call_000_36b5
    ld a, [$ffe7]
    ldh [$96], a
    ldh a, [$9b]
    and a
    ret z

    ldh a, [$9d]
    cpl
    and $03
    ldh [$9d], a
    ret


    ldh a, [$95]
    ld [$cd37], a
    dec a
    ld de, $ccd3
    ld hl, $cc97
    add l
    ld l, a
    jr nc, jr_003_7cf0

    inc h

jr_003_7cf0:
    ld a, [hl-]
    call Call_003_7cfe
    ld [de], a
    inc de
    ldh a, [$95]
    dec a
    ldh [$95], a
    jr nz, jr_003_7cf0

    ret


Call_003_7cfe:
    push hl
    ld b, a
    ld hl, $7d11

jr_003_7d03:
    ld a, [hl+]
    cp $ff
    jr z, jr_003_7d0f

    cp b
    jr z, jr_003_7d0e

    inc hl
    jr jr_003_7d03

jr_003_7d0e:
    ld a, [hl]

jr_003_7d0f:
    pop hl
    ret


    ld b, b
    ld b, b
    nop
    add b
    add b
    jr nz, @-$3e

    db $10
    rst $38
    ret


    call Call_000_3ec4

Call_003_7d1e:
    push hl
    xor a
    ldh [$96], a
    ld a, b
    ldh [$97], a
    ld a, c
    ldh [$98], a
    ld a, $30
    ldh [$99], a
    call Call_000_38f5
    ld a, d
    and a
    jr z, jr_003_7d4d

    srl d
    rr e
    srl d
    rr e
    ldh a, [$97]
    ld b, a
    ldh a, [$98]
    srl b
    rr a
    srl b
    rr a
    ldh [$98], a
    ld a, b
    ldh [$97], a

jr_003_7d4d:
    ld a, e
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$98]
    ld e, a
    pop hl
    and a
    ret nz

    ld e, $01
    ret


    ld a, [$cee6]
    ld c, a
    ld a, [$cee7]
    ld b, a
    ld a, [$cee8]
    ld e, a
    ld a, [$cee9]
    ld d, a
    push de
    push bc
    call Call_003_7e1c
    ld a, e
    ld [$cef9], a
    ld a, d
    ld [$cef8], a
    pop bc
    pop de
    call Call_003_7e16
    ret z

    ld a, $ff
    jr c, jr_003_7d87

    ld a, $01

jr_003_7d87:
    ld [$ceea], a
    call Call_000_3ec4
    ld a, [$cee8]
    ld e, a
    ld a, [$cee9]
    ld d, a

jr_003_7d95:
    push de
    ld a, [$cee6]
    ld c, a
    ld a, [$cee7]
    ld b, a
    call Call_003_7e16
    jr z, jr_003_7ddb

    jr nc, jr_003_7db5

    dec bc
    ld a, c
    ld [$cee8], a
    ld a, b
    ld [$cee9], a
    call Call_003_7e6a
    ld a, e
    sub d
    jr jr_003_7dc3

jr_003_7db5:
    inc bc
    ld a, c
    ld [$cee8], a
    ld a, b
    ld [$cee9], a
    call Call_003_7e6a
    ld a, d
    sub e

jr_003_7dc3:
    call Call_003_7e3a
    and a
    jr z, jr_003_7dcc

    call Call_003_7df6

jr_003_7dcc:
    ld a, [$cee8]
    ld [$cee6], a
    ld a, [$cee9]
    ld [$cee7], a
    pop de
    jr jr_003_7d95

jr_003_7ddb:
    pop de
    ld a, e
    ld [$cee6], a
    ld a, d
    ld [$cee7], a
    or e
    jr z, jr_003_7deb

    call Call_003_7e6a
    ld d, e

jr_003_7deb:
    call Call_003_7e3a
    ld a, $01
    call Call_003_7df6
    jp Jump_000_3e07


Call_003_7df6:
    push hl

jr_003_7df7:
    push af
    push de
    ld d, $06
    call Call_000_2d2c
    ld c, $02
    call Call_000_3781
    pop de
    ld a, [$ceea]
    add e
    cp $31
    jr nc, jr_003_7e13

    ld e, a
    pop af
    dec a
    jr nz, jr_003_7df7

    pop hl
    ret


jr_003_7e13:
    pop af
    pop hl
    ret


Call_003_7e16:
    ld a, d
    sub b
    ret nz

    ld a, e
    sub c
    ret


Call_003_7e1c:
    ld a, d
    sub b
    jr c, jr_003_7e29

    jr z, jr_003_7e30

jr_003_7e22:
    ld a, e
    sub c
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ret


jr_003_7e29:
    ld a, c
    sub e
    ld e, a
    ld a, b
    sbc d
    ld d, a
    ret


jr_003_7e30:
    ld a, e
    sub c
    jr c, jr_003_7e29

    jr nz, jr_003_7e22

    ld de, $0000
    ret


Call_003_7e3a:
    push af
    push de
    ld a, [$cf7b]
    and a
    jr z, jr_003_7e67

    ld a, [$cee6]
    ld [$ceec], a
    ld a, [$cee7]
    ld [$ceeb], a
    push hl
    ld de, $0015
    add hl, de
    push hl
    ld a, $7f
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    pop hl
    ld de, $ceeb
    ld bc, $0203
    call Call_000_3c8f
    call Call_000_0b31
    pop hl

jr_003_7e67:
    pop de
    pop af
    ret


Call_003_7e6a:
    push hl
    ld hl, $cee4
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    ld c, a
    ld a, [hl+]
    ld b, a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    push hl
    push de
    call Call_003_7d1e
    ld a, e
    pop de
    pop bc
    push af
    call Call_003_7d1e
    pop af
    ld d, e
    ld e, a
    pop hl
    ret


    ld a, [$c109]
    cp $04
    jr nz, jr_003_7eb9

    ld a, [$d2e6]
    ld b, a
    ld a, [$c434]
    ld c, a
    ld hl, $7ec5

jr_003_7e9c:
    ld a, [hl+]
    cp $ff
    jr z, jr_003_7eb9

    cp b
    jr nz, jr_003_7eb5

    ld a, [hl+]
    cp c
    jr nz, jr_003_7eb6

    ld a, [hl]
    push af
    call Call_000_3c6c
    pop af
    call Call_000_3f25
    xor a

jr_003_7eb2:
    ldh [$db], a
    ret


jr_003_7eb5:
    inc hl

jr_003_7eb6:
    inc hl
    jr jr_003_7e9c

jr_003_7eb9:
    ld a, $ff
    ldh [$db], a
    ld b, $14
    ld hl, $79eb
    jp Jump_000_3620


    rla
    jr nc, @+$3c

    ld [$3f3d], sp
    ld [$401e], sp
    inc de
    ld [hl-], a
    ld b, b
    ld bc, $4032
    inc d
    jr z, jr_003_7f17

    ld [de], a
    ld d, $41
    rlca
    dec e

jr_003_7edc:
    ld b, b
    dec b
    dec e
    ld b, b
    inc c
    ld [hl+], a
    ld b, b
    ld [bc], a
    ld d, h
    ld b, d
    ld [bc], a
    ld d, l
    ld b, d
    ld b, $54
    ld b, d
    ld b, $55
    ld b, d
    ld [de], a
    ld d, b
    ld b, d
    ld [de], a
    ld d, d
    ld b, d
    dec c
    ld [hl], $40
    rst $38
    ld [$1321], sp
    ld a, a
    call Call_000_3c79
    ld a, [$d2e1]
    bit 0, a
    ld hl, $7f22
    jr nz, jr_003_7f0d

    ld hl, $7f39

jr_003_7f0d:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    jr z, jr_003_7eb2

    ld h, a

jr_003_7f17:
    ld a, a
    adc l
    add [hl]
    add e
    add c
    ld a, a
    cp d
    or e
    add hl, hl
    sbc $58
    db $ed
    jr z, jr_003_7edc

    ld h, a

Call_003_7f26:
    ret


    ld a, a
    pop bc
    ld [c], a
    or e
    jp $e7de


    ld c, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld a, a
    adc $de
    inc a
    ld d, a
    db $ed
    jr z, @-$0e

    ld h, a
    cp e
    or d
    cp d
    or e
    ld a, a
    or a
    or [hl]
    sbc $4f
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld a, a
    adc $de
    inc a
    ld d, a
    ld [$6b21], sp
    ld a, a
    ld a, [$d2e6]
    cp $13
    jr nz, jr_003_7f65

    ld a, [$c420]
    cp $38
    jr nz, jr_003_7f65

    ld hl, $7f79

jr_003_7f65:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    inc l
    ret c

    ld h, l
    adc $de
    ld h, $7f
    or d
    rst $18
    ld b, h

jr_003_7f76:
    or d
    rst $20
    ld d, a
    db $ed
    jr z, jr_003_7faf

    ld l, b
    sbc $7f
    jr nc, jr_003_7fd7

    ld d, a
    db $ed
    inc l
    xor d
    ld h, [hl]
    ld a, a
    add e
    and a
    dec a
    db $e3
    adc a
    db $e3
    jr nc, jr_003_7f76

    ld d, a
    nop
    ld d, c
    db $ec
    add sp, $67
    xor h
    ld b, d
    jr nc, @-$17

    ld d, b
    ld b, $08
    ld a, $01
    ld [$cc3c], a
    ld hl, $d6af
    set 6, [hl]
    call Call_000_3e04
    xor a
    ldh [$b0], a
    inc a
    ldh [$ba], a

jr_003_7faf:
    call Call_000_36ca
    ld b, $1c
    ld hl, $53aa
    call Call_000_3620
    ld hl, $d6af
    res 6, [hl]
    ld de, $0f6a
    push de
    ldh a, [$b8]

Jump_003_7fc5:
    push af

Call_003_7fc6:
    jp Jump_000_14ba


Call_003_7fc9:
    db $ed

Call_003_7fca:
Jump_003_7fca:
    inc l
    adc d
    ld h, [hl]
    ld a, a
    ld d, h

Call_003_7fcf:
    rlca
    xor h
    inc c
    ld h, $4f
    ret nz

    cp b
    cp e

jr_003_7fd7:
    sbc $7f
    cp a
    db $db
    rst $18
    jp Jump_000_2fd9


    rst $20
    ld d, a
    ld bc, $0929
    inc bc
    db $10
    ld [bc], a
    ld h, b
    ld hl, $3121
    add hl, hl
    ld hl, $0013
    add hl, bc
    ld bc, $4383
    ld c, c
    adc b
    jr nz, @+$52

    ld b, c
    ld bc, $1143
    pop bc
    ld b, c
    inc de
    inc bc
    db $d3
