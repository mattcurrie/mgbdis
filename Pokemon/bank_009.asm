; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $009", ROMX[$4000], BANK[$9]

    ld [hl], a
    or [hl]
    cp a
    sub l
    inc a
    call nc, Call_000_188a
    db $10
    and l
    dec b
    ld sp, $ae53
    and d
    jr z, @+$13

    add c
    ld b, d
    rst $28
    ld c, b
    ld a, d
    or h
    pop de
    db $d3
    ld e, b
    ld e, a
    ld [$5012], sp
    add [hl]
    add c
    ld a, l
    ld [hl], $a3
    ld l, b
    ld l, $82
    or b
    add d
    ld b, d
    add hl, hl
    daa
    ld [$d622], sp
    adc [hl]
    inc b
    dec h
    dec de
    cp $06
    sub b
    add d
    ld a, [bc]
    call nc, Call_009_5f88
    and l
    ld [hl], e
    sbc [hl]
    rst $38
    and c
    ld b, [hl]
    add a
    db $fc
    add a
    adc e
    ld c, d
    ld e, a
    xor d
    ld h, c
    ld h, e
    ld e, b
    adc $c1
    dec c
    ld b, l
    add c
    ld h, $a0
    ld b, c
    adc b
    ld h, d
    sub l
    ld c, d
    ld c, b
    ld c, b
    add c
    xor b
    ld d, $b8
    sub h
    adc e
    ld h, d
    jp nc, $045a

    or h
    xor b
    xor b
    add $33
    sub c
    ld [$8185], a
    ld b, d
    inc sp
    sub d
    sub h
    push hl
    ld e, b
    ld a, [de]
    ld b, c
    ld b, $1b
    ld h, d
    ld [hl+], a
    inc d
    sbc b
    ld d, h
    ret


    ld d, $26
    add c
    add l
    ld [hl+], a
    dec h
    ld c, c
    sbc d
    ld h, d
    jr jr_009_409b

    ld d, b
    sub e
    ld l, d
    inc sp
    sub a
    ld [c], a
    dec de
    dec d
    pop bc
    sub [hl]
    db $eb
    ld d, d
    sub c
    add c
    ld [hl+], a
    add [hl]
    dec h
    add hl, de
    ld h, e
    ld a, [hl+]
    dec b

jr_009_409b:
    sbc a
    ld l, e
    ld e, b
    ld [de], a
    and e
    dec bc
    ld a, [$9139]
    ld c, e
    ld c, h
    ld d, d
    inc hl
    daa
    ld d, c
    add d
    inc d
    cp b
    ld l, b
    adc d
    rst $28
    ret


    ld c, b
    ld b, d
    inc b
    call $4246
    rrca
    add d
    ld [hl+], a
    ld [hl], $62
    ld d, a
    push de
    ld c, l
    ld l, b
    adc h
    ld d, d
    jr z, @+$22

Jump_009_40c4:
    adc e
    ld d, l
    and d
    sbc d
    ld h, $93
    ld c, d
    dec d
    ld l, [hl]
    ld d, b
    cp d
    ld l, d
    ld c, $33
    adc h
    and e
    ld b, l
    ld [hl], a
    ld b, c
    rla
    ld d, b
    ld d, a
    ld b, [hl]
    jr nc, @+$5a

    ret


    dec d
    ld c, h
    ld l, b
    sub l
    ld c, d
    cp $21
    adc h
    inc de
    inc [hl]
    ld h, e
    ld [hl], a

jr_009_40ea:
    ret c

    dec d
    ld [hl], b
    xor d
    and e
    inc [hl]
    pop bc
    adc b
    ld c, l
    xor b
    add l
    ld b, d
    dec l
    ld c, b
    ld d, h
    cp c
    ld d, [hl]
    adc e
    and e
    ld a, [hl-]
    inc b
    ld [hl+], a
    ld h, a
    xor $82
    dec e
    inc b
    xor $a0
    add c
    ld l, d
    ld d, c
    add c
    ld l, a
    add c
    add hl, bc
    adc $f5
    adc h
    add hl, hl
    ld d, b
    xor d
    jr c, jr_009_40ea

    db $dd
    ld d, e
    ld a, d
    sub l
    ld d, e
    dec h
    ld e, d

jr_009_411d:
    ld a, [de]
    ld b, l
    dec c
    or [hl]

jr_009_4121:
    dec bc
    adc d
    ld a, d
    ld c, a
    ld h, c
    ld h, c
    ld [bc], a
    ld l, d
    sbc l
    ld a, d
    ld c, l
    pop bc
    ld c, b
    db $d3
    jp z, $8a61

    ld [hl], l
    ld b, h
    sub $45
    jr z, jr_009_4188

    jp nz, $ace2

    ld [hl], l
    ld d, c
    dec c
    ld c, l
    ld [bc], a
    jp z, $0b54

    db $fc
    ld l, d
    sbc d
    xor h
    ld de, $ac16
    add hl, hl
    ld e, b
    ccf
    ld de, $a816

jr_009_4150:
    ld [hl], c
    sbc d
    ld c, l
    dec d
    ld b, $d0
    ld [hl], b
    ld b, h
    ld b, c
    ld d, d
    and h
    inc [hl]
    ld b, [hl]
    ld h, [hl]
    adc [hl]
    rst $28
    ld a, [bc]
    push de
    ld d, d
    ld e, $39
    jr z, jr_009_4121

    add d
    and h
    and c
    inc d
    jp nc, Jump_009_428d

    bit 7, [hl]
    adc h
    inc d
    db $ec
    ld b, e
    db $fd
    inc bc
    ld a, d
    ld b, d
    sub h
    or b
    xor c
    dec hl
    scf
    and h
    pop bc
    ld a, b
    add $d7
    jr nz, jr_009_411d

    call nc, $cc08
    cp a

jr_009_4188:
    dec bc
    ld [bc], a
    dec e
    jr nz, jr_009_411d

    xor b
    and [hl]
    ld de, $2d9b
    inc c

Call_009_4193:
    call Call_009_422c
    ld a, [hl-]
    sub [hl]
    xor l
    jr @+$4b

    sbc e
    jp nc, $c434

    ld h, h
    and h
    and b
    call nz, $8240
    inc d
    sbc h
    ld [de], a
    ld e, e
    inc c
    call nz, $a334
    and d
    or b
    ld [$83a0], a
    and d
    sbc b
    ld a, [hl+]
    and l
    ld d, h
    ld h, e
    db $f4
    ret nz

    reti


    ld [$443e], sp
    ld l, l
    ld de, $c49b
    ld b, h
    jr nz, jr_009_4150

    inc l
    ld e, d
    sbc h
    ld [hl-], a
    dec [hl]
    ld b, d
    sub b
    ret nc

    or h
    cp h
    db $fc
    ld a, [hl+]

Call_009_41d1:
    ld b, d
    sub e
    ld a, [de]
    ld [$c112], a
    inc b
    jp nc, $0c84

    ld l, b
    or h
    ld [de], a
    add d
    sbc e
    ld [hl], b
    ld l, c
    ld de, $4017
    add $92
    dec l
    ld c, e
    sbc e
    and h
    ret c

    ld hl, $1431
    ld a, [de]
    sub [hl]
    cp l
    ld [bc], a
    ld h, b
    and [hl]
    sbc l
    ld d, d
    dec hl
    xor b
    dec hl
    jp $d55f


    ld b, d
    sbc c
    jr nz, @-$62

    ld l, $10
    ld b, c
    db $fc
    ld h, d
    ld [$1893], a

jr_009_4209:
    ld b, a
    dec bc
    or b
    jr nz, jr_009_4209

    ld e, [hl]
    xor e
    db $fd
    ld a, [bc]
    sbc d
    ld hl, $461b
    ld de, $850a
    ld e, a
    ld [$a68a], a
    ld [hl], a
    ld a, [de]
    ld b, e
    ld l, d
    xor b
    ld c, b
    dec [hl]
    jr z, jr_009_428e

    ld d, a
    ret c

    ret


    sbc d
    ld h, a
    dec bc

Call_009_422c:
    ld b, h
    ld b, b
    and b
    and c

jr_009_4230:
    inc l
    ld [hl], $a8
    ld e, [hl]
    adc l
    add hl, hl
    add $c6
    ld [hl], h
    ld a, [bc]
    adc l
    dec c
    ld de, $55fe
    add hl, hl
    or d
    ld [hl], c
    call nc, $aa12
    call c, Call_000_2867
    add b
    ld b, h
    or [hl]
    ld [hl], h
    and a
    ld e, d
    adc [hl]
    ld c, e
    rst $30
    ld [hl], h
    dec d
    ld sp, $1575
    add sp, -$58
    ld [c], a
    xor d
    and c
    or l
    add c
    dec b
    dec [hl]
    or [hl]
    ld d, h
    sub h
    sbc d

jr_009_4263:
    inc d
    jr jr_009_4230

    and c
    xor d
    add l
    ld d, h
    adc d
    inc [hl]
    ld d, c
    ld d, c
    ld e, d
    ld h, $95
    inc sp
    ld a, d
    add l
    adc l
    and h
    or a
    add c
    ld d, $32
    ld c, l
    xor a
    pop bc
    pop bc
    ld d, h
    add sp, $50
    adc d
    sub h
    jr @+$14

    sub e
    dec d
    ld hl, $461a
    pop de
    and l
    adc l

Jump_009_428d:
    rla

jr_009_428e:
    ld e, e
    ld d, d
    jr nz, @-$79

    dec [hl]
    cp d
    ld a, [hl+]
    sbc h
    ld d, $a0
    xor c
    add hl, sp
    ld l, d
    and e
    call z, $eddc
    ld d, h
    ld [hl], c
    and d
    and d
    ei
    ld d, c
    rst $00
    ld c, [hl]
    db $10
    ld d, b
    ret


    and d
    cp c
    ld [hl], $8a
    pop de
    add hl, hl
    sbc h
    ret c

    inc l
    scf
    db $e4
    add hl, hl
    jp nz, Jump_000_2ad8

    db $fd
    cp $9b
    ld [hl], h
    cpl

jr_009_42be:
    ld d, h
    ld e, l
    ld a, [hl]
    ld l, c
    xor a
    dec e
    ld c, l
    ld d, c
    reti


    jr nz, jr_009_4263

    ld b, a
    ld h, $3b
    sub [hl]
    and a
    inc de
    dec c
    adc e
    sub d
    and a
    ld b, $d4
    inc [hl]
    add l
    or e
    jp z, $b29c

    ret nz

    sub a
    inc e
    ret nc

    rst $00
    sbc b
    ld [hl], a
    cp h
    dec [hl]
    ld hl, $c053
    ld d, l
    ld c, h
    sbc [hl]
    xor c
    add e
    db $f4
    pop bc
    db $f4
    reti


    ld a, a
    ld c, b
    cp l
    dec h
    ld hl, sp+$34
    cp c
    ld c, d
    and e
    dec d
    ld b, c

jr_009_42fb:
    ld a, [hl]
    adc c
    adc b
    ld b, [hl]
    inc d
    inc h
    ld [hl+], a
    pop de
    add d
    ld a, [$1e8c]
    add e
    and e
    ld b, $04
    inc d
    dec h
    rlca
    add c
    dec l
    ld d, $9a

jr_009_4312:
    and d
    add sp, $1e
    ld [hl-], a
    ld b, l
    inc d
    ld h, d
    rla
    inc b
    ld [de], a
    sub [hl]
    and b
    ld b, c
    ld [$8cba], sp
    ld d, [hl]
    scf
    xor b
    adc e
    ld d, $0a
    ld e, d
    ld hl, $0826
    pop bc
    add l
    jr nc, @-$73

    ld h, h

Call_009_4331:
    adc b
    jr @+$2a

    sub h
    xor b
    add l
    jr nc, jr_009_42be

    ld [$8a51], sp
    xor h
    dec h
    jr @-$2d

    jr c, @+$1a

    jr jr_009_436f

    ld a, [hl+]
    ld [hl+], a
    dec de
    ld d, l
    ld a, [de]
    ld b, c
    add hl, sp
    ld e, b
    ld h, d
    dec d
    add [hl]
    jr jr_009_4312

    jp z, Jump_000_0482

    jp nz, $2522

    ld h, d
    ld l, e
    add sp, -$7c
    jr @-$76

jr_009_435d:
    and l
    pop hl
    ld c, h
    sub b
    or b
    ld c, b
    ld h, d
    inc d
    adc b
    or h
    jr nc, jr_009_42fb

    inc h
    sbc d
    cp h
    add h
    ld [c], a
    ld l, b

jr_009_436f:
    ld d, c
    adc c
    ld h, d

jr_009_4372:
    ld a, [hl+]
    dec hl
    push af
    or l
    db $f4
    dec d
    ld b, d
    ld [hl-], a
    ld d, e
    add hl, hl
    dec de
    inc sp
    ld d, d
    ld [hl+], a
    jr nc, @+$80

    xor a
    ld d, e

Call_009_4384:
    add d
    ld a, [hl+]
    or l
    ld d, h
    pop bc
    ld d, a
    ld [$aa28], sp
    ld [hl+], a
    jr jr_009_435d

    dec l
    adc e

jr_009_4392:
    adc c
    add [hl]
    add [hl]
    jr @-$2d

    inc d
    sub l
    ld d, $06
    ld b, c
    jp z, $2255

    add hl, sp
    ld e, b
    sub h
    xor d
    jr @-$79

    db $e4
    adc b
    or h
    pop bc
    inc d
    cp e
    add l
    ld hl, $8888
    adc d
    xor d
    add l
    dec [hl]
    ld h, d
    db $10
    ld a, a
    ld b, [hl]
    and b
    add d
    ld l, $63
    dec sp
    adc d
    ld d, [hl]
    ld b, c
    adc e
    adc c
    and d
    xor b
    rst $20
    sub [hl]
    sub l
    inc c
    jr nz, jr_009_4372

    ld h, $21
    inc b
    ld e, b
    rst $28
    xor l
    and l
    inc d
    ld d, l
    ld e, b
    adc d
    ld hl, $4b3c
    sub $da
    inc e
    push bc
    inc a
    and l
    ld b, c
    ld h, h
    cp e
    ld c, a
    ld h, $a8
    adc b
    add [hl]
    inc a
    ld a, [$5314]
    jp nc, $a3bd

    dec c
    di
    jr z, jr_009_4392

    db $f4
    sbc l

jr_009_43f2:
    adc d
    jp nc, Jump_009_5a42

    adc d
    jr c, jr_009_4457

    and [hl]
    ld c, c
    xor d
    pop de
    add d
    pop af
    jr z, jr_009_43f2

    dec [hl]

Jump_009_4402:
    add hl, hl
    sub d
    ld h, d
    rst $28
    reti


    add d
    add [hl]
    ld de, $d20a
    ld [de], a
    and c
    dec b
    inc l
    jr z, jr_009_4457

    ret nc

    ld a, h
    inc c
    ld h, b
    and h
    ld d, b
    ld b, e
    ld [hl+], a
    add d
    cp l
    ld a, [bc]
    add d
    pop bc
    ld b, [hl]
    dec d
    inc bc
    ld d, $aa
    ld b, d
    adc d
    ld b, l
    ld d, h
    inc d
    db $10

jr_009_442a:
    ld h, c
    ld [bc], a
    add hl, bc
    ld a, [bc]
    ld d, l
    inc bc
    inc d
    ret nc

    ld l, h
    ld h, d
    res 6, h
    inc a
    ld b, [hl]
    ld c, [hl]
    sub c
    ld h, h
    and [hl]
    inc c
    cp b
    ret


    ld d, b
    ld b, c
    inc b
    xor c
    add h
    ld e, [hl]
    sub b
    sbc d
    ld hl, $2902
    inc [hl]
    ld sp, $1212
    and d
    pop af
    sub a
    ld b, [hl]
    db $d3
    ld de, $a1c2
    ld b, l

jr_009_4457:
    and b
    sub l
    ld l, [hl]
    ld d, d
    ld a, [de]
    ld l, d
    add h
    xor l
    dec d
    ld h, $48
    ld h, c
    ld h, $6a
    ld h, d
    add d
    ld a, [$8d11]
    ld [hl+], a
    sbc b
    call nc, $e5aa
    ld b, [hl]
    sub b
    jp $2e45


    ldh a, [$c4]
    dec [hl]
    dec l
    ld c, a
    xor c
    dec c
    ld b, a
    ld b, l
    ld a, [bc]
    adc l
    jr z, jr_009_442a

    add hl, bc
    rrca
    db $fd
    ld b, c
    daa
    dec b
    dec d
    rst $38
    dec b
    dec h
    ld hl, $142e
    ret nc

    jp nz, $19d7

    jr nc, jr_009_44ed

    pop bc
    ld de, $5045
    ld a, [hl+]
    jp nz, Jump_009_749a

    jr z, @-$34

    sub b
    and d
    sub c
    inc c
    ld [hl], b
    and h
    xor d
    ld h, l
    rla
    call z, $d808
    cp b
    ld h, $0a
    ld e, l
    xor e
    ret nz

    sub a
    inc b
    ld l, b
    sub l
    dec c
    add hl, hl
    ld a, [hl+]
    adc e
    ld d, d
    dec [hl]
    inc c
    ld h, e
    ld a, [de]
    ret z

    or h
    ld [$3f2c], sp
    ld b, [hl]
    inc c
    ld d, h
    ld [hl], h
    ret nc

    ret nc

Call_009_44c8:
    db $dd
    dec d
    or b
    inc [hl]
    ld a, [bc]
    ld e, e
    dec e
    or h
    ld b, h
    and d
    adc [hl]
    sbc c
    add hl, sp
    db $e3
    pop de
    dec c

jr_009_44d8:
    ld [$2a11], a
    ld a, c
    ld l, d
    db $ed
    ld e, a
    ld d, b
    ld b, a
    sbc e
    ld d, d
    ld a, e
    ld [$ea29], sp
    pop de
    sub b
    ld b, h
    cp b
    sub h
    sub a

jr_009_44ed:
    ret c

    ret


    db $f4
    or a
    xor d
    ld hl, sp-$2b
    ld b, [hl]
    sub a
    cp b
    ld h, c
    adc b
    sub e
    dec [hl]
    cp l
    add d
    pop bc
    adc b
    ld a, a
    adc h
    ldh [$61], a

jr_009_4503:
    ld b, l
    db $fd
    ld e, b
    sub [hl]
    ld [hl-], a
    ld d, d
    sub b
    sbc c
    ld b, c
    ld c, c
    call $aad2
    ld a, d
    xor d
    scf
    ld c, h
    ld h, d

jr_009_4515:
    ld [de], a
    db $d3
    dec d
    adc b
    ld h, e
    ld [$a485], sp
    call Call_009_4bab
    ld a, a
    sub $8c
    sub h
    sub h
    ld [de], a
    ld l, h
    ld d, l
    jr c, jr_009_457f

    ld sp, hl
    ld h, c
    ld h, d
    inc h
    adc $98
    db $10
    sub h
    add [hl]
    jr nc, jr_009_44d8

    add hl, hl
    ld h, d
    xor d
    ld a, $43
    db $76
    daa
    ld a, [hl-]
    add d
    dec c
    ld e, c
    and l
    ld de, $0293
    add d
    cpl
    sbc c
    ld d, e
    db $e4
    jr nz, jr_009_4515

    sub e
    add $95
    ld a, [bc]
    ret nc

    ld c, l
    inc e
    ld [$422d], a
    and l

Call_009_4556:
    and [hl]
    ld c, h
    ld b, d
    sub d
    ret nc

    ld a, [hl-]
    ld b, a
    sbc h
    xor b
    jp nz, Jump_009_46a3

    ld c, b
    dec hl
    push bc
    ld d, d
    db $fc
    ld sp, $2ea4
    sbc b
    ld e, d
    sbc h
    ld d, b
    jr nz, jr_009_4503

    ld [hl], c
    ld [de], a
    ld l, h
    ret nz

    add [hl]
    ld [de], a
    inc [hl]
    ld e, l
    ld h, $a9
    ld e, h
    rst $00
    dec l
    rra
    ld [hl-], a

jr_009_457f:
    ld d, l
    cp [hl]
    xor l
    dec b
    ld d, l
    ld b, l
    ld c, [hl]
    ld b, a
    ld b, c
    ld b, $af
    ld [$38bb], a
    ld e, l
    ld d, b
    cp d
    add c
    ld hl, $a330
    ld b, l
    ret nc

    and d
    ld d, h

Jump_009_4598:
    ld a, [hl+]
    cp d
    cp b
    adc d
    ld [hl-], a
    ld a, d
    jr nc, jr_009_45f0

    ld a, a
    and b
    ld l, e
    daa
    ld c, h
    xor b
    or [hl]
    ld [$82da], a
    rla
    xor b
    inc hl
    ld b, l
    ld b, l
    jp hl


    ld l, b
    ld e, [hl]
    rrca
    rst $20
    dec d
    dec [hl]
    rst $38
    sbc d
    cpl
    ld hl, sp-$7b
    dec b
    ld [$22d7], sp
    jr nc, @+$7a

    cpl
    ld a, [c]
    ld e, c
    inc [hl]
    ld hl, sp+$22
    rst $18
    or h
    add [hl]
    res 1, h
    call nc, Call_009_5f22
    ldh [rHDMA2], a
    ld d, b

Jump_009_45d2:
    ld b, l
    adc l
    sub a
    push af
    ld l, d
    dec de
    ld d, a
    cp b
    adc c
    ld [$0ad6], sp
    ld a, [de]
    dec d
    xor e
    xor b
    ld l, b
    adc a
    adc [hl]
    dec de
    ld a, a
    ld b, l
    cp l
    ld b, d
    add c
    ld d, h
    ld [c], a
    xor b
    add l
    ret z

jr_009_45f0:
    pop bc
    sub h
    inc d
    inc hl
    sbc [hl]
    and b
    ld e, [hl]
    or [hl]
    cp a
    ld hl, sp-$15
    adc a
    ld e, d
    ld a, l
    ld l, d
    ld d, d

jr_009_4600:
    ld b, d
    db $76
    and [hl]
    inc l
    ld [hl], d
    ld sp, $3630
    jr z, jr_009_4688

    add [hl]
    ld l, [hl]
    add h
    ld b, d
    rst $38
    rlca
    rst $38
    ld b, b
    add [hl]
    add hl, bc
    jp nz, $fccf

    inc c
    inc [hl]
    call nz, $297a

jr_009_461c:
    sbc h
    inc c
    db $fd
    ld a, [bc]
    or h
    pop hl
    adc e
    pop af
    cp h
    rrca
    jp nz, $0ff4

    ldh [$af], a
    pop hl
    dec b
    inc e
    dec l
    jr nz, jr_009_4600

    dec [hl]
    rst $38
    sub b
    add d
    ld l, h
    add d
    inc c
    adc $b3
    jr jr_009_467b

    ld l, c
    or [hl]
    rra
    rst $38

jr_009_4640:
    ret nz

    ret nc

    and h
    ccf
    and $ce
    rra
    db $fd
    adc e
    ld c, a
    add sp, -$2b
    and $d0
    ld d, c
    ld l, [hl]
    dec [hl]
    pop hl
    ld [bc], a
    sbc l
    ld c, a
    ld b, d
    add [hl]
    ld l, $3a
    adc h
    ld [hl], c
    push hl
    inc l
    or a
    rst $38
    ld c, c
    push de
    sub c
    jp $be5e


    sbc [hl]
    inc e
    ld b, h
    ld a, h
    sub b
    ld b, h
    cp h
    push de
    inc b
    ld [$bb7e], a
    ld d, e
    sbc a
    res 5, l
    ld hl, $dafc
    db $d3
    inc h
    ld a, c

jr_009_467b:
    jr c, jr_009_46ea

    ld b, l
    ld h, c
    cp d
    or e
    adc d
    cp l
    ld h, $25
    jr c, jr_009_46e4

    db $fd

jr_009_4688:
    ld c, d
    ld a, b
    db $dd
    ldh [$89], a
    ld b, [hl]
    rrca
    ld d, e
    ld l, d
    jr nc, jr_009_461c

    sbc h
    ldh [rHDMA5], a
    ld d, l
    adc b
    ld l, c
    jr c, jr_009_4640

    ld d, l
    ld l, d
    ld h, $a3
    ldh a, [$59]
    ld a, [c]
    ld l, c

Jump_009_46a3:
    call nc, $fabf
    sub d
    sbc h
    ld [hl], a
    rst $38
    jp hl


    ld d, d
    ld [hl], d
    ld e, a
    cp $4a
    sbc h
    push af
    ld e, d
    db $fc
    ld [hl], e
    ld a, [hl+]
    rst $38
    rst $00
    scf
    rst $38
    cp $85
    inc e
    dec hl
    rst $38
    ldh a, [$df]
    rst $20
    dec b
    ld d, l
    ld d, c
    ld [hl], l
    rra
    sub d
    add b
    ld d, l
    cp [hl]
    ld l, l
    ld d, l
    ld c, l
    ld d, l
    ld d, e

jr_009_46d0:
    sub l
    xor a
    push de
    rst $38
    ld a, [$38aa]
    sbc b
    add l
    db $eb
    ld [hl-], a
    ld l, b
    rla
    adc l
    add hl, hl
    db $fd
    rst $00
    call nc, $bac2

jr_009_46e4:
    ld d, e
    ld d, l
    adc c
    and c
    xor b
    inc d

jr_009_46ea:
    jp nz, $3883

    ld [hl+], a
    inc h
    dec d
    dec d
    ld sp, $4da0
    rst $28
    ldh [$aa], a
    dec sp
    add hl, hl
    ld a, h
    adc e
    ld [hl-], a
    ld c, c
    adc [hl]
    dec c
    adc [hl]
    dec de
    ld b, [hl]
    sbc b

jr_009_4703:
    jp nc, Jump_000_1504

    ld [hl-], a
    ld d, d
    inc d
    sub l
    adc h
    and d
    ld h, $93
    ld a, [de]
    cp $8e
    ld [hl], $85
    dec b
    ld c, h
    ld d, [hl]
    ld a, [bc]
    and b
    adc h
    push hl
    ld e, a
    and b
    xor [hl]
    xor d
    and h
    ld l, d
    ld d, h
    inc hl
    ld c, d
    adc b
    and b
    ld a, b
    jr nz, jr_009_46d0

    db $10
    sub a
    add hl, sp
    xor a
    add l
    ld a, c
    ld [hl+], a
    ld e, b
    ld e, $3a
    xor d
    cp l
    ld d, a
    db $e3
    jp nz, Jump_000_3caa

    ld sp, hl
    di
    ld l, c
    add hl, hl
    xor d
    ld b, d
    ld [hl], d
    jr nc, jr_009_4703

Jump_009_4742:
    and b
    call nz, $a7c4
    rra
    db $eb
    call nz, $112a
    dec bc
    sub a
    ld a, [de]
    or c
    add h
    adc h
    ld h, c
    ld l, b
    ld sp, $5eaa
    ld h, d
    sub a
    ld a, a
    sbc h
    ld [de], a
    ldh a, [$a6]
    rst $18
    pop de
    and e
    cp d
    sub c
    sub b
    sbc c
    ccf
    sbc e
    cp a
    call nz, $98d4
    cp a
    ld c, c
    or d
    sbc c
    add $0d
    call nz, $9046
    ld a, l
    ld l, c
    sub d
    cp h
    add sp, -$5f
    add hl, de
    ld b, d
    cp l
    ret


    sub [hl]
    rst $38
    cp $09
    and a
    ldh a, [$30]
    ld d, a
    xor d
    rst $38
    push af
    ld e, a
    add d
    ld l, c
    ld d, c
    ld a, e
    ld d, l
    ld d, d
    rst $38
    xor e

jr_009_4791:
    inc e
    ld [hl], b
    ld [hl], c
    jr z, jr_009_4791

    ld a, l
    ld a, [$4472]
    call nc, $eb8d
    pop af
    ldh [rSTAT], a
    sub $11
    ld a, [c]
    and b
    ld b, h
    cp [hl]
    ld h, l
    ld d, h
    ld [c], a

jr_009_47a9:
    ld d, l
    dec d
    ld e, [hl]
    ld hl, sp-$1f
    add c
    cp a
    and b
    sbc [hl]
    and e
    add l
    dec bc
    adc h
    ld a, a
    jr c, jr_009_47a9

    ld e, e
    rst $38
    ld hl, sp-$1e
    xor d
    ld a, e
    dec bc
    db $fd
    ld c, [hl]
    dec [hl]
    ld [$e5a8], sp
    and h
    xor $a1
    ld c, [hl]
    reti


    ld b, c
    push de
    dec d
    ld [hl], e
    add l
    ld d, l
    add d
    xor l
    ret c

    db $ed
    and e
    ld [c], a
    daa

Jump_009_47d8:
jr_009_47d8:
    call z, $9ea2
    sbc d
    sub [hl]
    and a
    scf
    ld sp, $8b2e
    sbc h
    ld c, l

jr_009_47e4:
    jr jr_009_4840

    and a
    inc c
    ld d, d
    jp c, $c811

    cp $a7
    ld h, h
    pop af
    sbc [hl]
    ld [hl], b
    add $de
    ld [hl], c
    ld b, c
    ld [hl], d
    add d
    xor l
    ld b, a
    inc c
    ld l, c
    sbc a
    ld d, b
    ld d, l
    cp [hl]
    sub l
    ld c, e
    ld c, c
    ld c, [hl]
    sub a
    cp c
    inc hl
    pop hl
    cp b
    db $e3
    ld d, h
    add hl, hl
    db $ed
    dec h
    db $f4
    ld h, e
    add l
    add sp, $39
    ld c, d
    ld d, h
    cpl
    ld b, c
    scf
    ld a, c
    db $76

jr_009_481a:
    and c
    ld b, d
    add d
    dec b
    ld a, [bc]
    add d
    ld d, e
    ccf
    ld h, d
    ld de, $1fd8
    ei
    ld a, [bc]
    ld a, [bc]
    ld a, a
    inc sp
    or h
    ld h, b
    sbc c
    and b
    cp [hl]
    add l
    ld l, d
    ld a, [bc]
    inc [hl]
    or h
    sbc d
    jp c, $8e54

    ld [hl+], a
    or h
    sub $a0
    sub e
    jr z, jr_009_47d8

jr_009_4840:
    ld l, b
    ld [c], a
    and e
    add c
    ld l, b
    db $10
    xor e
    ld c, h
    call nc, $8c66
    ld e, b
    ld l, c
    dec bc
    ld b, c
    ld c, l
    ld e, [hl]
    rlca
    ld d, c
    ld d, a
    jr nc, jr_009_47e4

    dec de
    adc b
    ld d, h
    jr nz, jr_009_48c4

    dec [hl]
    adc [hl]
    ccf
    pop hl
    ld h, d
    ld d, b
    ld c, b
    ld b, l
    jr c, jr_009_48c3

    ldh [$62], a
    sub l
    ld b, c
    ld c, [hl]
    ld c, e
    ld h, c
    ld h, l
    ld e, a
    add c
    ld d, h
    ld h, b
    and e
    ld a, d
    xor d
    ld a, [bc]
    xor b
    xor d
    ld h, $e3
    ret


    sbc a
    add a
    add hl, hl
    sbc h
    ld [hl], e
    inc h
    jr nc, jr_009_48e7

    ret


    adc $90
    or b
    ld h, h
    jr nz, jr_009_481a

    add hl, hl
    call nz, Call_009_68f8
    cpl
    sub b
    sbc b
    ld [hl], d
    ld l, a
    ld d, d
    db $e4
    ld d, h
    call nc, $9cfe
    cp $10
    cp a
    rst $38
    jp nc, $9cc1

    ld [hl], a
    add d
    or $df
    or [hl]
    adc e
    inc e
    ld l, b
    ld a, a
    db $e3

Jump_009_48a9:
    dec c
    ld a, e
    ld a, l
    sbc h
    ld d, b
    ld a, a
    ld d, c
    adc d
    jr nc, jr_009_48f2

    ld h, [hl]
    call z, $9bf1
    inc de
    inc sp
    ret


    xor d
    inc d
    ld d, h
    sub c
    add e
    cp $84
    db $10
    ld h, a

jr_009_48c3:
    inc e

jr_009_48c4:
    ld [$3fb0], sp
    rst $38
    add sp, $39
    call z, Call_000_0f82
    rst $38
    rst $30
    jp $2b27


    rlca
    rst $38
    ldh a, [$3c]
    jp $919c


    dec e
    ld e, h
    ld c, h
    ld d, d
    ld a, h

jr_009_48de:
    sbc b
    ld b, h
    cp [hl]
    ld l, c
    and e
    adc l
    ld c, h
    dec e
    and e

jr_009_48e7:
    adc d
    xor c
    dec d
    db $e3
    sbc d
    add d
    ld l, b
    or a
    jr c, jr_009_490e

    ld [hl], c

jr_009_48f2:
    ld c, b
    add c
    db $e3
    add l
    ld h, e
    jr z, jr_009_48de

    ld d, d
    jr @-$45

    ld c, [hl]
    rlca
    add c
    adc [hl]
    cp e
    ldh a, [rHDMA3]
    dec b
    ld c, [hl]
    ld c, e
    pop bc
    rlca
    ld h, e
    xor d
    ret nc

    adc a
    xor d
    sbc a

jr_009_490e:
    adc b
    ld l, c
    add e
    add hl, sp
    bit 5, c
    ld c, a
    inc e
    rst $38
    adc l
    jp $af1c


    ld hl, sp-$3f
    ld sp, hl
    ret


    rst $38
    adc d
    scf
    sbc h
    ld [hl], a
    db $fc
    push hl
    ld b, a
    inc c
    jr nc, @+$01

    ld b, a
    ld h, h
    ld a, [hl]
    inc e
    ld d, l
    cp a
    ld [hl], $5a
    xor d
    sub h
    db $eb
    ld a, l
    ld [hl-], a
    db $fd
    add hl, sp
    sbc [hl]
    ld [hl+], a
    ld c, b

jr_009_493c:
    xor c
    ld [$382d], sp
    ret nc

    sub d
    and c
    xor h
    adc b

jr_009_4945:
    ld d, h
    pop hl
    ld c, c
    xor c
    ld h, d
    ld l, d
    add hl, hl
    ld c, [hl]
    or l
    ld h, $3c
    ld e, $b4
    ld a, [c]
    ld l, $3a
    inc hl
    ld l, d
    ld b, [hl]
    inc b
    jr z, jr_009_493c

    adc l
    dec h
    ld [hl+], a
    xor d
    jr c, jr_009_4945

    jp z, $f829

    and $93
    ld d, a
    adc [hl]
    xor d
    ld d, l
    ld d, l
    and e
    ldh a, [rNR24]
    ld sp, hl
    add $aa
    ldh [$9d], a
    rst $18
    rst $38
    ld d, e
    ld sp, $a4ce
    rst $38
    inc h
    ret nz

    sbc h
    set 5, e
    adc [hl]
    add h
    sub c
    jp Jump_009_4b1c


    rst $38
    db $fd
    ld e, d
    xor a
    sub e
    daa
    rrca
    rst $38
    ldh [$ba], a
    rst $18
    rst $20
    ccf
    rst $38
    cp a
    rst $38
    add l
    rst $20
    inc sp
    di
    ld e, a
    db $fc
    ld d, [hl]
    adc d
    add hl, bc
    jp nz, $cdb0

    ld [c], a
    sub b
    add a
    db $fc
    ld [hl], c
    cp c
    jr nc, jr_009_4a09

    add d
    inc c
    rst $38
    inc e
    jp nc, $f16b

    call nc, $a199
    dec e
    or c
    ld [hl], c
    ld hl, sp+$18
    ld b, h
    cp [hl]
    ld b, c
    ld d, l
    ld d, e
    sbc l
    or d
    ld a, d
    db $f4
    ld [c], a
    ld [hl], a
    inc c
    sbc b
    adc e
    ld c, l
    call nc, $b868
    and h
    sbc $58
    push bc
    ld [hl+], a
    inc a
    inc b
    di
    ld [c], a
    call nc, $08b6
    sbc $47
    ld h, b
    adc c
    add c
    adc [hl]
    add hl, hl
    ld h, b
    sub d
    ld e, b
    rst $20
    xor d
    xor d
    ld a, $aa
    ld a, h
    add d
    ld d, d
    ld [hl], h
    cpl
    db $ec
    adc h
    ld [hl], c
    xor a
    cp a
    db $fc
    sub d
    sbc e
    xor b
    rst $38
    rst $38
    call nz, $bfa9
    rst $38
    rst $38
    adc $2e
    ld [hl], b
    ld a, a
    rst $38

Call_009_49ff:
    db $fc
    adc e
    and $ef
    rst $38
    db $fc

jr_009_4a05:
    db $10
    rst $38
    and [hl]
    rst $28

jr_009_4a09:
    jp nc, Jump_009_5f09

    and a
    dec d
    call z, $d9c4
    rst $08
    sub [hl]

jr_009_4a13:
    rst $00
    pop hl
    jr nz, jr_009_4a8e

    and l

jr_009_4a18:
    db $f4
    ldh a, [rHDMA5]
    ld a, [$4553]
    dec bc
    ld c, [hl]
    rst $00
    cp $1a
    ld b, d
    sub e
    ld d, $90
    or h
    push bc
    ld d, l
    dec [hl]
    ld l, [hl]
    and h
    sub h
    adc b
    add a
    ld a, e
    sbc b
    ld l, l
    dec b
    cp $aa
    jp nc, Jump_009_5ed5

    or b
    ld d, h
    ld d, d
    ld [hl], h
    add l
    dec h
    adc b
    xor a
    scf
    ld l, d
    or d
    dec h
    db $eb
    ret


    adc b
    and c
    ld c, d
    sub [hl]
    ld [hl-], a
    ld d, c
    and a

jr_009_4a4e:
    cp d

jr_009_4a4f:
    adc c
    and d
    and b
    ld h, d
    ld [$a009], a
    ld c, c
    ld h, d
    jp c, Jump_009_5404

    sub [hl]
    sub l
    dec h
    dec h
    adc d
    ld e, b
    dec d
    push de
    ld h, e
    jr z, @+$1a

    ld d, d
    jr jr_009_4a13

    sbc b
    ld d, d
    jr z, jr_009_4a18

    ld l, b
    jr z, jr_009_4a05

    xor l
    inc d
    ld h, c
    jp hl


    jr c, jr_009_4a4e

    pop bc
    db $76
    and d
    jr nz, jr_009_4adb

    add l
    dec l
    ld h, $94
    ld d, h
    ld d, d

Jump_009_4a81:
    ld a, [hl+]
    dec l

Call_009_4a83:
    ld a, [$86f5]
    ld h, b
    push de
    jr nc, @+$66

    ld [hl+], a
    ld d, $8a
    sub e

jr_009_4a8e:
    dec sp
    ld e, [hl]
    ld b, $88
    ld b, l
    db $76
    add hl, hl
    add l
    ld d, $1a
    ld b, [hl]
    ld b, $30
    adc c
    ret nc

    ld h, d
    jr nz, jr_009_4a4f

    ld a, c
    ld c, b
    ld b, d
    ld h, h
    ld h, e
    inc b
    jr @+$66

    push bc
    ldh [rWX], a
    ld c, h
    db $10
    or a
    ld h, b
    add [hl]
    ld [hl-], a
    ret


    ld h, d
    and c
    ld d, b
    ld c, c
    ld l, c
    ld c, b
    ld c, b
    xor h
    ld d, [hl]
    dec [hl]
    ld c, [hl]
    ld a, [bc]
    ld c, c
    adc c
    xor d
    jr nc, @-$5c

    db $d3
    inc b
    ldh [$62], a
    sub e
    xor d
    sub l
    and e
    cp a
    dec l
    xor h
    or h
    add h
    or l
    xor c
    dec l
    add c
    sub h
    push bc
    ld c, d
    rst $18
    xor c
    jr @+$22

jr_009_4adb:
    ret


    ld b, d
    inc sp
    ld h, c
    sbc b
    ld d, b
    adc c
    ld d, h
    xor d
    add hl, hl
    ld h, $1d
    dec d
    ld c, h
    db $d3
    dec l
    rst $38
    adc h
    ld de, $475b
    ldh [$8b], a
    ld d, d

jr_009_4af3:
    ld d, d
    sub h
    cp d
    add hl, hl
    adc h
    jr jr_009_4b13

    jp nz, Jump_009_5421

    add l
    ld hl, $688a
    cp e
    ld d, l
    adc l
    xor d
    adc d
    xor b
    cp d
    jr c, jr_009_4af3

    ld d, [hl]
    or $2d
    sub h

Call_009_4b0e:
    push bc
    jr c, @+$12

    ld c, l
    sbc [hl]

jr_009_4b13:
    add a
    ld l, $0f
    and h
    add h
    adc c
    ld c, l
    jr nz, @-$70

Jump_009_4b1c:
    dec b
    add l
    ld b, c
    add d
    jr jr_009_4b8c

    ld h, $5e
    ld c, h
    sub e
    ld l, e
    jp c, $a6a0

    add hl, bc
    ld h, d
    ld d, l
    push af
    ld b, d
    adc h
    ld h, e
    and d
    sub $a5
    ld e, d
    ld [hl+], a
    cp a
    rst $38
    dec d
    ld l, b
    adc l
    add hl, hl
    db $e4
    ld a, [hl+]
    ld l, l
    ld [bc], a
    ld a, b
    ret nc

    jp nc, Jump_009_549a

    sbc c
    and a
    ld [hl+], a
    and c
    rla
    ld a, [de]
    ld c, b
    ld d, d
    ld c, [hl]
    ld b, l
    ld d, d
    ld l, [hl]
    or b
    add hl, hl
    ld a, c
    sbc d
    and h
    ld c, [hl]
    sub c
    dec de
    or b
    ld h, l
    ld [hl], a
    or l
    jr jr_009_4b7f

    jp nz, $d1a4

    ld [$a8a8], sp
    cp d
    xor b
    db $e4
    and h
    ret c

    ld sp, $9052
    add d
    ld c, l
    ld d, c
    inc c
    cp [hl]
    ld a, [hl+]
    dec bc
    ld a, [hl]
    db $ec
    ld d, h
    inc e
    ld e, [hl]
    dec e
    ld b, l
    xor d
    ld h, e
    rst $10
    or a

jr_009_4b7f:
    ld a, [hl-]
    cp a
    inc de
    ld c, e
    ld e, c
    ld [hl], b
    jp nc, $c8c0

    ld [hl], h
    sub c
    inc b
    ld b, a

jr_009_4b8c:
    inc b
    ld de, $2055
    sbc h
    add hl, sp
    jr nc, jr_009_4c07

    db $e4
    and l
    ret nz

    add d
    ld h, l
    ld [c], a
    sbc d
    scf
    ld b, h
    rst $28
    ld de, $5a02
    ret nc

    cp $a2
    call Call_000_2a0d
    sub e
    or e
    ld c, d
    db $10

Call_009_4bab:
    ld h, d
    or c
    sbc d
    add e
    inc [hl]
    dec [hl]
    dec c
    ld b, l
    and l
    ret nz

    ret z

    ld b, c
    dec b
    dec bc
    ld b, l
    ld a, $85
    ld [hl], l
    ld c, b
    and e
    ld b, c
    inc d
    sub h
    add h
    pop bc
    ld [bc], a
    ld d, d
    inc e
    db $eb
    inc b
    jr z, jr_009_4c10

    call $8c02
    ld c, d
    ld e, h
    sub e
    dec h
    ld hl, $4b7c
    inc e
    ld a, [hl+]
    ld sp, $268d
    add hl, hl
    ld sp, $4282
    ld [hl], d
    inc h
    ei
    ld b, l
    or d
    ld h, b
    xor e
    push hl
    ld c, c
    adc h
    ld a, [bc]
    sbc d
    add $18
    ld a, [hl-]
    ld [$6cd5], sp
    ld h, b
    db $eb
    xor h
    ld c, h
    jp z, $332e

    ld c, c
    jr z, jr_009_4c44

    or a
    rst $08
    dec c
    ld [hl+], a
    pop bc
    sub c
    dec h
    ld b, e
    dec b
    ld [hl], d
    ld sp, $1429

jr_009_4c07:
    and d
    and c
    inc b
    inc de
    ld [bc], a
    jr nc, jr_009_4c65

    db $10
    adc d

jr_009_4c10:
    push bc
    and c
    add hl, de
    ld d, l
    pop af
    dec l
    inc d
    xor b
    ld [hl], h
    jp $a930


    sub d
    and l
    and d
    add $0a
    ld c, l
    adc a
    ld a, [bc]
    rrca
    cp b
    ld a, [hl-]
    sub h
    and c
    ld sp, hl
    add h
    ld a, [bc]
    ld c, d
    xor c
    ld d, d
    inc [hl]
    add hl, hl
    dec d
    ld a, [bc]
    and $54
    add hl, bc
    adc h
    dec c
    ld b, h
    or b
    call nz, $d140
    and d
    adc d
    ldh a, [$a0]
    sbc h
    ld c, h
    rla

jr_009_4c44:
    call z, Call_009_4a83
    ld h, c
    ld b, e
    ld a, b
    ld b, l
    ld e, h
    ld l, h
    xor b
    ld a, [hl+]
    call nc, Call_000_2d15
    ld a, [hl]
    ld l, $ca
    adc l
    add hl, hl
    add hl, hl
    cp h
    pop de
    ld l, h
    ld a, [hl+]
    ld c, d
    ret nc

    dec l
    ld d, a
    ld [$471d], a
    ld d, e
    ld b, h

jr_009_4c65:
    ld d, l
    jr @+$56

    xor d

Call_009_4c69:
    pop bc
    ld d, $44
    sub h
    rra
    ld d, d
    rst $18
    push de
    ld l, d
    and d
    xor e
    add c
    add hl, de
    dec b
    ld d, h
    ld h, b
    adc $04
    ld l, d
    jp Jump_009_53e4


    ld l, d
    and d
    ld de, $4148
    adc c
    ld d, [hl]
    res 2, h
    sub [hl]
    ld d, $42
    ld b, a
    push de
    adc h
    sub [hl]
    and l
    and a
    add c
    ld c, [hl]
    xor d
    ld l, c
    ld l, c
    ld [hl], $53
    dec bc
    ld l, b
    add a
    ld d, e
    daa
    sbc c
    ld c, l
    inc h
    sub [hl]
    ret


    or $6a
    inc b
    inc d
    and h
    or [hl]
    ld l, $08
    cp b
    ld l, c
    pop hl
    add l
    ld [hl-], a
    ld d, d
    and d
    db $f4
    db $10
    ld a, b
    ldh [$61], a
    ld [hl], h
    ld d, b
    call nc, Call_009_4c69
    ld l, $b4
    jr jr_009_4cee

    ld a, [$288c]
    jp nz, $2a86

    adc a
    ld c, e
    ld d, d
    sbc h
    ld a, [hl+]
    and [hl]
    or [hl]
    ld e, d
    inc l
    ld sp, hl
    ld de, $0c8b
    ld [hl-], a
    ld hl, sp+$31
    inc d
    add hl, hl
    or d
    add hl, bc
    inc d
    ld e, d

jr_009_4cdb:
    db $d3
    ld b, [hl]
    inc d
    and [hl]
    add hl, hl
    jr c, jr_009_4cdb

    cp h
    ld d, e
    inc h
    dec l
    ld d, a
    ld b, [hl]
    or c
    inc de
    cpl
    pop de
    rst $00
    inc de

jr_009_4cee:
    ld a, l
    db $10
    sub $c6
    ld c, h
    add hl, de
    xor d
    ld d, d
    push bc
    db $ec
    add hl, bc
    or d
    add $e9
    ld d, c
    dec c
    dec b
    ld de, $4c46
    ld d, d
    adc [hl]
    ld a, [de]
    ld [$144a], sp
    ld h, b
    sub [hl]
    add d
    ld b, h
    ld a, [bc]
    ld d, l
    ld l, c
    ld [hl], d
    db $d3
    ld de, $7c2c
    adc b
    ld [hl], a
    or l
    ld d, h
    pop af
    sub h
    pop de
    ld a, [$17b4]
    db $fd
    ld d, e
    add l
    ld d, h
    add a
    cp b
    ret


    ld c, d
    ld e, a
    adc c
    or b
    and h
    ld d, l
    ld a, a
    cp a
    cp $f5
    ld a, b
    and a
    db $f4
    sub l
    dec de
    adc c
    ld [hl], h
    sbc a
    xor [hl]
    ld hl, $7f46
    ld h, b
    ld d, d
    xor c
    add sp, -$6a
    inc b
    ld de, $2068
    add c
    adc [hl]
    ld a, [hl-]
    ld b, d
    adc c
    xor b
    sbc b
    add $8a
    add d
    adc [hl]
    ld l, d
    adc d
    and c
    adc b
    ld c, e
    ld d, e
    add l
    jr c, @+$24

    xor b
    and h
    jp nz, $d0a2

    ld c, l
    inc de
    or d
    dec [hl]
    ld c, h
    or b
    ld c, b
    ld c, b
    sub c
    ld c, d
    ld c, h
    ld d, l
    ld d, h
    sbc b
    sub [hl]
    jr jr_009_4d81

    inc d
    ld d, c
    ld c, b
    ld b, d
    inc b
    sub $04
    jr z, jr_009_4dd4

    ld e, b
    ld e, b
    jp nz, Jump_000_1a26

    rlca
    rst $10
    ld b, l
    ld b, [hl]
    adc d

jr_009_4d81:
    ld b, d
    dec b
    ret c

    and [hl]
    ld [hl+], a
    ld hl, $ad89
    ld a, b
    cp d
    ld d, l
    dec d
    ld [hl+], a
    ld a, a
    add [hl]
    ld [$60a2], a
    jp $af56


    and e
    ld c, d
    add hl, hl
    ld [hl], b
    ld d, h
    or h
    add $36
    ld b, d
    ld [hl-], a
    and d
    call nc, $a42a
    ld d, h
    ret


    inc [hl]
    ld d, d
    inc hl
    ld d, $fc
    or l
    ld b, d
    ld a, [bc]
    dec d
    ld c, h
    dec h
    dec l
    adc d
    sub e
    ld a, [bc]
    ld l, $90
    and b
    ld b, c
    ld b, $22
    ld d, $a9
    ld a, d
    xor b
    jp z, Jump_009_6095

    ld b, c
    ld a, [hl+]
    cp e
    db $eb
    dec b
    ld d, c
    ld c, h
    ld d, $a4
    db $e4
    adc c
    ld a, [hl]
    bit 7, [hl]
    and e
    add hl, de
    ld [hl], h
    ld h, d

jr_009_4dd4:
    ld sp, hl
    ld c, h
    ld d, [hl]
    dec de
    ld d, e
    dec hl
    pop hl
    and d
    jr nz, jr_009_4e2e

    ld h, c
    add [hl]
    sub b
    add d
    dec h
    ld d, b
    sub e
    inc h
    xor d
    dec l
    ld c, b
    xor b
    push bc
    ld h, b

jr_009_4dec:
    add d
    or c
    ld b, c
    inc [hl]
    adc h

jr_009_4df1:
    inc d
    or l
    dec l
    adc b
    adc d
    ld a, a
    ld h, $21
    ld h, $a1
    ld d, d
    inc d
    inc d
    or l
    xor a
    ld [$0ea9], sp
    add hl, bc
    adc h
    ld [de], a
    ld l, b
    inc d
    ld d, a
    xor $05
    dec l
    and a
    db $d3
    inc b
    inc hl
    inc d
    ld [de], a
    ld l, b
    add l
    rrca
    ld e, c
    add [hl]
    adc e
    ld hl, sp+$10
    adc h
    ld [de], a
    sub l
    and h
    and l
    ld hl, $a0e6
    push de
    db $dd
    ld d, h
    ccf
    sbc d
    jr nc, jr_009_4df1

    and b
    ld e, [hl]
    jr nc, jr_009_4dec

    xor d

jr_009_4e2e:
    cp $0a
    add c
    db $ec
    ld e, $1b
    ld c, h
    jr jr_009_4eae

    add sp, -$15
    cp [hl]
    adc h
    cpl
    ld d, [hl]
    jp c, $d3a8

    ld a, h
    ld a, $94
    xor c
    rst $20
    and b
    sbc b
    ld d, h
    sbc h
    ld l, c
    ret nz

    sub d
    ld hl, sp-$3c
    ld b, d
    db $d3
    rla
    add $70
    ld l, d
    add d
    ld h, b
    pop de
    ld l, $82
    inc d
    pop de
    sub e
    jr jr_009_4ea2

    jp Jump_009_6621


    jr nc, jr_009_4ea6

    ld b, l
    ld d, b
    or h
    ld e, d
    ld [hl], c
    or c
    or d
    ld e, l
    ld de, $5118
    call Call_009_6324
    add hl, de
    sub $32
    add hl, hl
    add hl, bc
    ld c, e
    jr z, jr_009_4ea0

    inc e
    ld e, h
    ld h, l
    ret nz

    sub e
    sbc e
    ld c, b
    ld b, h
    ld h, $ed
    dec d
    ld [bc], a
    ld l, $4f
    sub [hl]
    and l
    xor b
    add sp, $60
    sub d
    sub l
    add hl, de
    rst $28
    inc b
    ld l, $62
    xor c
    rrca
    ld d, b
    ld c, d
    add hl, hl
    db $10
    ld b, h
    dec h
    jr z, @+$47

    jr nc, jr_009_4edb

    ld d, d

jr_009_4ea0:
    or b
    ccf

jr_009_4ea2:
    ld d, $82
    ld [de], a
    ld c, [hl]

jr_009_4ea6:
    ld d, h
    xor h
    scf
    rst $38

jr_009_4eaa:
    call nc, $d442
    ld c, e

jr_009_4eae:
    pop de
    ld [$793f], sp
    adc l
    and b
    and [hl]
    ret


    ld [hl-], a
    ld d, e
    ld de, $7703
    inc d
    and l
    ld d, a
    sub $96
    xor l
    inc b
    ld d, l
    ld d, h
    ld d, d

jr_009_4ec5:
    sbc c
    dec a
    dec d
    ld [bc], a
    sub e
    ld d, a
    jp hl


    inc c
    ld [$f166], a
    sbc h
    add hl, hl
    ld e, h
    db $10
    or h
    db $10

jr_009_4ed6:
    inc sp
    inc b
    ld b, e
    rst $30
    xor d

jr_009_4edb:
    call nc, $88a6
    ld h, $15
    ld l, b
    ld hl, $3231
    inc c
    ld b, e
    ld b, c
    jp nc, $9037

    sbc b
    ld e, [hl]
    ld h, b
    add [hl]
    ld a, [bc]
    ld [c], a
    call nz, $be24
    ld c, h
    sub l

jr_009_4ef5:
    jr nz, jr_009_4ed6

    xor d
    call nc, Call_009_4556
    inc c
    rrca
    ld e, h
    jr nc, jr_009_4eaa

    sub c
    adc e
    ld [hl+], a
    add a
    dec hl
    ld hl, sp+$20
    sbc b
    ld a, [c]
    adc e

Jump_009_4f0a:
    ld d, $84
    ld h, h
    sub e
    ld a, l
    add a
    ld d, d
    add d
    and [hl]
    adc b

jr_009_4f14:
    ld d, b
    or c
    ld c, b
    ld b, d
    sub e
    ld b, h
    ld sp, $c17f
    ld c, b
    add hl, sp
    ld d, b
    ld d, d
    sub h
    ret nz

    db $d3
    inc b
    add h
    rra
    rla
    jr nz, jr_009_4ef5

    inc sp
    jr nz, jr_009_4ec5

    ld sp, $0c83
    adc d
    ld b, h
    ld l, c
    dec bc
    jr jr_009_4f56

    sbc b
    pop bc
    ld h, c
    add a
    cp h
    inc sp
    or c
    ld a, [bc]
    or [hl]
    ld h, h
    sub d
    ret nc

    ld h, $1c
    ld l, $b5
    ld [hl], d
    or b
    ld c, d
    ld b, a
    ld d, h
    ld e, d
    ld c, e
    ld e, e
    ld sp, $4495

jr_009_4f51:
    call nc, $f562
    ld d, $ab

jr_009_4f56:
    db $10
    db $d3
    ld e, $0c
    ld h, a
    ld c, d
    or h
    ld [hl], b
    add b
    ld b, h
    or h
    ld d, e
    dec b
    ld b, c
    ld a, h
    pop de
    ld b, e
    ei
    rst $30
    ld [$34aa], a
    xor e
    xor c
    ld a, a
    adc c
    ld d, h
    pop hl
    and d
    add hl, sp
    and d
    ld l, b
    ret


    ldh a, [$90]
    and d
    ld h, e
    sub l
    inc b
    inc l
    ld d, h
    add l
    jr c, jr_009_4fae

    jr nz, jr_009_4f14

    sub b
    ld d, d
    sbc a
    ld l, b
    jp z, $9189

    xor d
    add e
    ret c

    and $98
    ld h, h
    dec hl
    ld h, e
    ccf

jr_009_4f94:
    ld l, $e8
    sbc d
    or h
    call Call_000_0545
    ld c, c
    ld b, c
    ld d, h
    adc c
    ld c, h
    inc d
    jr nz, jr_009_4f51

    or e
    ld a, [de]
    ld d, l
    ld sp, $b75d
    ld hl, $4aed
    ld h, e
    ld a, [hl+]

jr_009_4fae:
    ld a, [hl+]
    ld hl, sp-$76
    cp $8e
    ld a, [$c5a3]
    sbc $6e
    sub b
    sub b
    and a
    ld [hl+], a
    db $e4
    inc [hl]
    ld a, [hl+]
    ld a, [$6370]
    jp z, Jump_000_3ab4

    add hl, hl
    sbc h
    inc d
    inc l
    ld b, h
    ld c, h
    ld l, h
    db $dd
    ld [de], a

jr_009_4fce:
    add d
    jr z, jr_009_4ff2

    add hl, hl
    and l
    jr nc, jr_009_503f

    cpl
    dec h
    ld hl, $6a02
    add l
    ld [hl], b
    ld d, b
    db $e3
    xor c
    or l
    inc de
    ccf
    sub c
    ld c, d
    rrca
    add hl, de
    push bc
    ld e, h
    rla
    dec hl
    adc h
    ld l, e
    jr nz, jr_009_4f94

    ld c, $16
    and [hl]
    or l

jr_009_4ff2:
    ld b, e
    dec [hl]
    dec b
    jr nc, jr_009_4fce

    and $4f
    ld b, $44
    add h
    ld a, [hl+]
    ld [hl], h
    pop de
    ld [hl], l
    ld a, [hl+]
    sbc a
    ld a, [bc]
    ld h, [hl]
    cp [hl]

jr_009_5005:
    ld l, c
    ld c, a
    dec [hl]
    cp a
    inc a
    and [hl]
    ld [hl+], a
    adc [hl]
    or a
    or c
    ld d, h
    ld d, [hl]
    jp c, $4e42

    sub a
    sub h
    ld e, $ab
    sub [hl]
    push bc
    jr jr_009_5005

    pop af
    ld b, c
    ld b, c
    db $ed
    dec de
    dec sp
    rst $38
    ld b, e
    dec bc
    ld h, $53
    xor l
    ld d, h
    ld d, a
    db $db
    ld a, [bc]
    inc hl
    and b
    ld c, b
    ld c, [hl]
    dec d
    ld a, [$7b9a]
    ld b, $4c
    dec de
    ld e, $36
    ld e, [hl]
    adc e
    adc c
    and h
    xor b
    ld [hl], b

jr_009_503f:
    ldh a, [rOBP0]
    adc h
    ret nc

    call z, Call_009_49ff
    ld e, l
    add l
    ld [hl+], a
    ld h, $4c
    ld h, [hl]
    ld h, h
    or [hl]
    ld [hl+], a
    add $21
    xor b
    sub l
    sbc h
    reti


    add hl, de
    ld [hl], $5a
    adc d
    ld h, d
    ld de, $5acc
    ld e, d
    or l
    ld [hl], e
    ld a, c
    ld b, c
    ld hl, $330b
    ld [hl], d
    ld [$5d52], a
    ld hl, $8699
    and c
    add c
    inc sp
    or l
    dec l
    adc b
    ld l, e
    ld hl, $c914
    ld h, e
    ld e, d
    push de
    and b
    ld e, d
    or b
    adc b
    ret z

    pop bc
    xor b
    add [hl]
    jr c, jr_009_50ed

    xor b
    xor l
    adc c
    ld c, l
    ld e, b
    ld [$927d], a
    db $10
    ld b, c
    ld b, $15
    ld c, [hl]
    ret


    rst $00
    ld b, l
    add hl, bc
    adc b
    ld e, c
    dec sp
    xor l

Jump_009_5098:
    rst $38
    ld [$826a], sp
    adc a
    ld b, $82
    xor b
    rst $30
    rst $20
    pop hl
    ld e, c
    and $21
    ld [bc], a
    rst $00
    sub c
    ld a, [bc]
    ld b, h
    db $76
    push bc
    inc a
    xor c
    ld e, $44
    ld [hl], l
    xor c
    rla
    cp e
    cp $1e
    ld c, $76
    inc a
    ld c, e
    ld a, a
    ld a, b
    ld a, b
    ld a, c
    ret z

    sbc b
    reti


    add a
    cp $16
    ld d, $70
    ld hl, $1604
    adc d
    rrca
    and d
    add e
    pop af
    rra
    add [hl]
    ld l, d
    sbc c
    ld a, d
    inc sp
    db $fc
    ld e, $f8
    ld b, e
    pop hl
    sbc e
    ld h, $5f
    sub e
    ld d, b
    rst $38
    cp $fb
    inc c
    sbc b
    rst $18
    and l
    db $fc
    ld h, h
    rst $38
    rst $38
    jp nz, $26a1

jr_009_50ed:
    ld e, a
    ldh a, [$af]
    push hl
    inc hl
    ld a, h
    dec c
    cp $8f
    ret nz

    sbc b
    call nc, Call_009_5e5f
    xor h
    add hl, bc
    db $76
    and c
    rst $38
    add e
    sbc h
    xor [hl]
    or b
    ret nz

    xor c
    dec d
    db $ed
    rst $38
    and c
    ld a, [de]
    and h
    cpl
    ld a, [$1a0c]
    and h
    rst $10
    or h
    ret nc

    ld sp, $d5c1
    ld h, l
    ld a, [$3da5]
    ld h, c
    or h
    sbc l
    sbc a
    xor d
    ld c, a
    cp a
    sbc [hl]
    dec c
    cp $a3
    rlca
    rst $38
    ld [bc], a
    ld a, b
    dec [hl]
    xor c
    dec [hl]
    ld b, c
    ld b, a
    add l
    rlca
    ld c, c
    push af
    ldh [rLY], a
    cp b
    sub l
    ld d, e
    xor c
    ld [$5faf], a
    dec [hl]
    ld e, a
    rst $30
    jp nc, $fd16

    inc sp
    ld a, d
    ld hl, $ec1b
    xor b
    call Call_009_5848
    xor e
    adc [hl]
    dec [hl]
    sub [hl]
    ld c, h
    ld d, e
    db $76

jr_009_5152:
    ld b, $33
    cp a
    scf
    ld [hl], d
    sub d
    db $db
    db $d3
    ld a, e
    sub $29
    sbc c
    cp c
    jr c, jr_009_518b

    add d
    sub b
    ld b, e
    ld a, [bc]
    and e
    sub d

jr_009_5167:
    jp c, $9874

    and $aa
    and d
    ld a, b
    add sp, -$6b
    ld l, b
    ld a, [$ea79]
    ld a, [hl]
    and d
    and [hl]
    xor b
    ld b, b
    and h
    rst $38
    ld e, a
    or c
    sbc d
    ld b, e
    ei
    ld [de], a
    adc l
    cp $66
    xor a
    db $f4
    xor b
    ld c, b
    jp c, $95b9

jr_009_518b:
    db $f4
    add a
    ldh a, [rSCY]
    add l
    ld a, l
    add hl, de
    ld d, b
    ld [hl], b
    cp [hl]
    sub c
    jr nc, jr_009_5152

    sbc d

jr_009_5199:
    ld c, d
    rst $38
    jr nc, @-$48

    adc l
    and $b0
    ld [hl], l
    ld b, d
    jp z, $a116

    inc e
    adc [hl]
    rst $38
    ld [$f59c], a
    inc hl
    ld hl, sp+$27
    ld d, e
    ld hl, sp+$47
    ldh [$e0], a
    ld [hl], a
    or b
    ld c, [hl]
    dec b
    ld d, h

jr_009_51b8:
    db $e4
    ld a, l
    inc [hl]
    add d
    ld hl, $fd85
    xor a
    xor e

Call_009_51c1:
    db $d3
    ld [hl], a
    add c
    ld c, h
    ldh [$82], a
    inc b
    and h
    ld e, e
    jr jr_009_5167

    ld c, l
    db $10
    ld c, b
    sub e
    ld a, [hl-]
    ld b, c
    ld hl, $88e8
    ld d, $2d
    ld c, h
    rla
    ld b, [hl]
    adc b
    ld c, d
    ld [hl], h
    sub h
    sub l
    db $fd
    ld a, [bc]
    dec d
    ld d, l
    ld d, d
    jp c, $1581

    ld c, h
    dec h
    sub l
    ld b, c
    inc d
    add h
    cp d
    add l
    xor d
    push af
    ld [c], a
    pop hl
    ld c, b
    adc b
    and l
    ld c, h
    inc d
    jr nz, jr_009_51b8

    ld hl, sp+$57
    sub d
    ld h, d
    ld d, b
    add [hl]
    ld d, e
    ld h, $85

Call_009_5203:
    and h
    push bc
    ld [c], a
    add sp, $62
    ld l, b
    jr nz, jr_009_5199

    dec d
    ret z

    ld c, b
    ld h, h
    inc d
    push bc
    ld d, e
    ld a, [de]
    ld c, l
    ld d, d
    jp nc, $e422

    inc d
    dec d
    inc d
    jr jr_009_5270

    adc c
    ld h, d
    ld e, a
    ld [hl], h

Jump_009_5221:
    ld h, d
    add hl, hl
    ld a, [de]
    xor e
    add d
    ld b, c
    ld h, e
    dec d
    add hl, hl
    and e
    ld a, [bc]
    db $fc
    add hl, hl
    inc [hl]
    ld b, d
    ld h, $32
    or c
    and h
    inc de
    ld c, e
    rst $38
    and d
    sub d
    ld h, [hl]
    db $e3
    ld e, b
    ld h, a
    ld b, c
    ld c, l
    ld [hl], c
    xor a
    dec l
    add hl, hl
    inc [hl]
    ld e, b
    xor e
    call $9df2
    ld a, [hl+]
    ld d, h
    push bc
    ld e, d
    inc sp
    sub b
    adc l
    db $76
    or h
    ld [hl-], a
    xor b
    ld l, a
    ld a, [$fa8e]
    rlca
    xor [hl]
    ld hl, $4989
    and l
    add hl, sp
    call nc, Call_009_799a
    and e
    ld [$1512], sp
    ld h, $93
    dec [hl]
    ld b, e
    rla
    xor b
    ld l, c
    ld b, d
    dec l
    add hl, bc

jr_009_5270:
    and h
    ld a, [de]
    add sp, -$4c
    jp $a987


    ld c, h
    dec d
    adc c
    ld b, d
    ld h, $04
    ld d, a

jr_009_527e:
    ld d, e
    inc b
    jp nz, Jump_009_5571

    ld l, $30

Call_009_5285:
    ld c, c
    ld c, b
    jp c, $850a

    jr c, jr_009_52b2

    inc hl
    xor d
    jr c, jr_009_527e

    adc d
    ld [hl], b
    sub d
    ld h, e
    ld e, d
    dec b
    ld d, d
    ld l, $2e
    adc c
    ld [hl], l
    ld hl, $e7b4
    adc b
    and d
    sub d
    ld [de], a
    inc h
    add a
    rla
    ld c, d
    adc c
    ld b, c
    ld c, l
    ld [de], a
    inc d
    call Call_009_6f8b
    cp l
    ld d, [hl]
    ld l, $1a

jr_009_52b2:
    ld d, e
    ld a, [de]
    and e
    add hl, bc
    inc b
    sub h
    sub h
    sbc $8c
    add hl, hl
    ld c, c
    ld e, b
    adc $08
    adc d
    ld b, c
    cp l
    ld d, d
    sub a
    db $e3
    ld e, d
    and e
    add [hl]
    ld c, c
    adc c
    xor e

jr_009_52cc:
    rst $38
    and e
    and [hl]
    db $76
    daa
    adc c
    sub h
    sub c
    ld d, $90
    sbc h
    xor c
    or a
    sub e
    jr jr_009_5340

    ld h, h
    ld l, c
    cp d
    ld c, $29
    sbc a
    ld l, c
    ld c, [hl]
    sub d

jr_009_52e5:
    add h
    ld b, e
    add sp, $26
    jr z, jr_009_5329

    and h
    dec h
    and e
    dec b
    inc h
    ld [hl], e
    ret


    add a
    db $f4
    ld h, e
    pop bc
    db $fc
    ld b, d
    ld h, b
    jp c, $a191

    pop hl
    adc [hl]
    sbc b
    inc h
    xor c
    add a
    db $e4
    inc l
    ld sp, $5930
    rrca
    dec b
    db $10
    ret nz

    call nz, Call_009_44c8
    ld e, d
    ld c, $1f
    ldh [$d2], a
    sbc b
    ret c

    inc h
    ld b, h
    xor a
    inc b
    ld l, c
    ld de, $f7e1
    db $ed
    cp $98
    jp c, Jump_009_4f0a

Call_009_5323:
    pop bc
    jr jr_009_52cc

    rrca
    adc a
    rst $18

jr_009_5329:
    or a
    ld hl, sp+$46
    rla
    add [hl]
    add d
    or h
    ld [$28d2], sp
    ld b, d
    ret nz

    cp $37
    dec b
    ld a, l
    jr jr_009_52e5

    inc c
    ld d, $17
    rla
    adc [hl]

jr_009_5340:
    inc sp
    ld b, b
    rst $38
    ld [c], a
    and a
    ld a, [bc]
    adc d
    inc de
    ld h, h
    add sp, $2c
    ld a, [hl-]
    inc c
    rst $38
    cp $3f
    ld a, [$ac11]
    ld [de], a
    db $f4
    ld de, $fa17
    rra
    rst $38
    rst $38
    ld hl, sp-$1f
    rst $38
    xor c
    jp Jump_000_2955


    rla
    rst $38
    rst $38
    rst $38
    ret nc

    cp [hl]
    rra
    cp $71
    cpl
    db $f4
    sub h
    push de
    ld d, l
    inc h
    ccf
    ld hl, sp+$7f
    ld hl, sp+$47
    dec c
    cpl
    dec bc
    ld [c], a
    xor b
    and h
    rst $18
    rst $38
    add a
    rst $38
    dec de
    ld b, h
    rst $08
    db $10

Call_009_5384:
    ldh a, [$fc]
    ld d, h
    ld [$f0d7], sp

jr_009_538a:
    ld [hl], h
    ld c, d
    ld h, a
    inc h
    inc [hl]
    ld [$c021], sp
    or [hl]
    ld [hl], d
    cpl
    sbc d
    call z, Call_009_4384
    add a
    sub e
    or b
    ld h, [hl]
    ld d, c
    ld c, a
    cp $a5
    db $e4
    inc sp
    call nz, Call_009_5678
    dec c
    inc [hl]
    ret nz

    add $11
    rrca
    rst $38
    db $fc
    and b
    ld sp, hl
    ld e, h
    ld c, [hl]
    ld c, [hl]
    dec e
    add hl, de
    dec h
    and e
    cp $ff
    add a
    ld [$675e], a
    pop hl
    pop bc
    jr jr_009_538a

    ld a, a
    pop hl
    cp $1f
    rst $00
    inc c
    rra
    add h
    ld c, $43
    inc de
    sub a
    ld a, b
    ld a, a
    ret z

Jump_009_53d0:
jr_009_53d0:
    ld h, h
    ld a, $67
    jr c, jr_009_53d0

    ld [hl], a
    add h
    ld d, [hl]
    ld c, d
    sub c
    dec b
    rst $38
    or b
    cp a

Jump_009_53de:
    ld a, [de]
    ld a, [hl]
    rla
    or [hl]
    cp [hl]
    xor e

Jump_009_53e4:
    and d
    or c
    ld [hl], b
    ld d, a
    and l
    ld h, $de
    scf
    and c
    ld e, a
    rst $38
    rst $38
    ld [bc], a
    ld l, d
    adc d
    ld de, $e4c1
    ld b, h
    and e
    ld d, l
    ld de, $241e
    ld l, c
    ld de, $601d
    ld b, h
    or c
    ld h, h
    ld d, [hl]

Jump_009_5404:
    sub c
    ld e, a
    db $fd
    inc [hl]
    ld c, b
    and d
    ld h, a
    and l

Jump_009_540c:
    ld d, h
    call $a0c9
    and [hl]
    ld e, a
    and h
    pop de
    ld d, d
    ld d, d
    ld d, c
    ld e, b
    ld e, c
    ld [hl-], a
    ld d, a
    sub c
    ld a, d
    ld h, $82
    ld b, d
    adc h

Jump_009_5421:
    sub [hl]
    rst $18
    dec l
    ld h, $f8
    jp nc, Jump_000_39e3

    ld b, l
    ld e, h
    pop de
    ld e, e
    inc sp
    and d
    inc hl
    ld a, [hl-]
    dec b
    ld c, h
    push de
    ld c, l
    jr z, @+$12

    ld d, b
    ld d, b
    ld d, c
    ld h, d
    ld h, h
    jp z, $aa86

    dec bc
    ld [hl], b
    and h
    ldh [$ae], a
    sbc h
    inc h
    ld sp, $1958
    dec [hl]
    ld b, e
    ld d, b
    ld a, d
    ld a, [bc]
    add l
    ld hl, $4135
    ld [hl+], a
    rst $00
    dec bc
    ld [$68a3], a
    cp d
    inc a
    ld sp, hl
    sub d
    ld e, d
    ld b, d
    ld de, $b309
    ldh [$e1], a
    sub [hl]
    adc l
    ld h, [hl]
    ld l, b
    ld a, b
    ld a, b
    ld d, [hl]
    ld b, h
    ld b, h
    sbc d
    ld [hl-], a
    ld de, $212b
    ld [hl+], a
    xor h
    ld h, a
    dec b
    and e
    ld h, c
    add [hl]
    ld d, d
    ld [hl], $68
    and c
    ld l, e
    ld b, $09
    rrca
    cp [hl]
    ld l, e
    ld d, d
    xor d
    db $10
    ld d, a
    db $fd
    dec de
    ccf
    jp nc, Jump_000_0a09

    rst $38
    and [hl]
    sub l
    call z, Call_000_3fcc
    rst $38
    ld sp, hl
    xor d
    inc e
    dec de
    ld l, l
    ld [hl], l
    ld e, a

Jump_009_549a:
    sbc d
    inc h
    ld a, b
    ld [hl], b
    jp nc, Jump_009_6693

    cp c
    ld [hl-], a
    rrca
    ld b, h
    and a
    rrca
    ld de, $9a29
    ld l, l
    rla
    ld b, a
    rst $00
    add b
    ld [hl], a
    cp c
    rst $18
    sub e
    db $d3
    and d
    ld h, h
    ld [c], a
    ld d, e
    sbc c
    ld a, l
    ld a, [de]
    ld hl, $3721
    ld a, e
    sub e
    adc c
    db $ec
    ld a, b
    inc d
    ld e, l
    ld [hl+], a
    ld c, l
    ld de, $8e48
    ld b, h
    ld hl, $4141
    ld d, c
    ld d, b
    sub l
    add hl, hl
    ld d, b
    adc c
    ld b, c
    inc [hl]
    ld e, [hl]
    ld sp, $bb46
    add [hl]
    ld h, $aa
    ldh [$8a], a
    ld [$7a31], a
    dec h
    ld l, $91
    add e
    db $fc
    adc $62
    ld l, d
    ld [hl-], a
    and d

jr_009_54ec:
    ld d, b
    adc h
    ld e, c
    ld a, [hl]
    xor b
    ldh [$63], a
    ld c, d
    dec h
    ld a, [de]
    inc b
    and a
    and e
    sbc c
    ld b, [hl]
    jr nc, jr_009_5550

    inc b
    ret


    ld [hl], $4a
    ld [$1822], a
    jp c, $382e

    sub b
    xor d
    ld a, [hl+]
    jr jr_009_54ec

    ld h, c
    adc c
    adc h
    db $d3
    jr c, @-$34

    dec [hl]
    ld h, [hl]
    sub b
    adc c
    adc l
    jp nc, $8851

    ld c, c
    ld b, d
    ld a, [hl+]
    adc b
    ld b, c
    db $ed
    ld c, c
    adc h
    ld [hl+], a
    ld h, d
    ld d, c
    adc b
    ld b, [hl]
    inc d
    push bc
    ld h, d
    ld h, d
    inc l
    sbc c
    dec h
    ld [$5861], sp
    jr jr_009_5587

    ld [hl], c
    ld c, h
    jp nc, $8c65

    xor c
    ld b, d
    ld [hl+], a
    and b
    ld l, b
    rla
    ld l, b
    ccf
    dec [hl]
    ld b, d
    ld [hl], $51
    ld h, d
    ld d, [hl]
    adc b
    add d
    ld l, c
    sub h
    daa
    inc sp
    sub h
    push bc
    ld a, d
    xor b

jr_009_5550:
    sub [hl]
    cpl
    add l
    inc d
    ld d, d
    inc d
    jp nc, Jump_000_05f5

    add d
    dec bc
    adc e

jr_009_555c:
    ld d, e
    add hl, de
    ld a, [bc]
    ld a, [hl-]
    dec hl
    ld d, b
    adc c
    adc h
    ld l, c
    ld l, $ff
    ld l, $a3
    adc l
    ld l, $3a
    sbc d
    add hl, sp
    ld l, l
    ld a, [hl+]
    ld c, h

Jump_009_5571:
    add hl, sp
    inc sp
    ld e, b
    rst $20
    and b
    cp l
    ld d, [hl]
    inc sp
    and l
    ld d, l
    and d
    and e
    xor d
    xor d
    adc [hl]
    sub a
    adc [hl]
    ld a, [hl+]
    ld sp, $9563
    xor b

jr_009_5587:
    and $b9
    ld d, l
    adc [hl]
    dec h
    ld l, b
    db $ec
    and l
    ld c, l
    push de
    and e
    add $aa
    ld d, l
    ld d, [hl]
    and e
    adc a
    ld [hl], h
    ld a, [hl+]
    ld a, d
    ret nc

    ret


    and $29
    ld [hl-], a
    sub d
    sbc h
    dec hl
    inc e
    add sp, -$3c
    ld [hl+], a
    ret nc

    and $ee
    db $f4
    ld [hl], d
    ld [c], a
    add d
    jr z, jr_009_55d3

    ld [$68a6], a
    jr z, jr_009_555c

    ld a, [bc]
    or c
    ld c, d
    ccf
    inc hl
    ld b, e
    ld d, d
    xor e
    ld d, b
    daa
    inc de
    and $68
    ld h, h
    jr z, @+$31

    add d
    xor b
    jr z, jr_009_563a

    ld sp, $0cb5
    ld b, h
    ld e, l
    ccf
    ld b, l
    push de
    dec b
    inc d

jr_009_55d3:
    ld a, [c]
    add hl, hl
    adc h
    ld [$1031], sp
    and h
    inc a
    ld [hl], c
    dec hl
    ld [$6484], a
    xor b
    ld b, [hl]
    xor c
    add d
    xor l
    ld a, a
    db $fd
    ld c, b
    sub $f1
    adc d
    sbc d
    ld b, [hl]
    ld d, l
    dec bc
    pop hl
    ld d, c
    ld d, c
    add hl, hl
    jp nc, Jump_009_4598

    ld a, b
    ld h, $b1
    add hl, bc
    adc $c5
    and b
    cp a
    ld b, h
    ld b, h
    ld b, b
    sub e
    ld b, c
    rla
    ld [de], a
    call nc, Call_000_2998
    add hl, bc
    inc a
    jp nz, Jump_009_40c4

    sub h
    sbc c
    and h
    and d
    sbc b
    rst $18
    inc b
    dec bc
    add d
    pop de
    inc c
    ld a, [bc]
    and c
    ld h, $a8
    db $dd
    ld a, [de]
    ret nc

    and [hl]
    inc l
    adc l
    or $12
    ld l, d
    sbc e
    xor c
    and e
    ld b, c
    rlca
    ld d, l
    inc b
    ld sp, $99ac
    inc a
    ld [hl-], a
    cp [hl]
    ld d, l
    ld d, h
    ld h, c
    ld [de], a
    sbc e
    ld d, d
    sub e
    ld h, c

jr_009_563a:
    dec l
    ld sp, $f5ae
    inc c
    ld [hl], e
    dec [hl]
    inc c
    ld e, h
    ld l, c
    ld l, e
    ld sp, hl
    dec l
    inc e
    rl a
    dec de
    ld d, d
    xor d
    pop bc
    inc e
    ld [$b868], a
    and a
    inc b
    sbc h
    ld a, c
    ld d, $aa
    cp a
    pop de
    rla
    xor d
    ld h, l
    ld b, a
    ld [hl+], a
    xor h
    dec d
    ld d, h
    ld l, c
    ld d, a
    jp nc, $84aa

    ld [hl], c
    pop de
    sub d
    ld l, h
    or c
    rst $18
    add hl, hl
    ld [hl], a
    ld a, [$f4aa]
    ld a, b
    xor l
    ld a, [hl+]
    sub e
    ld d, a
    pop af

Call_009_5678:
    rst $20
    dec [hl]
    ld d, d
    ld [hl], e
    nop
    ld b, h
    cp b
    sub a
    rst $38
    push af
    jr c, jr_009_5699

    ld e, d
    or a
    ld c, b
    and e
    dec [hl]
    db $fd
    call c, Call_009_4331
    db $f4
    inc e
    push bc
    jp hl


    ld l, b
    ld [hl+], a
    jr z, jr_009_56f5

    cp e
    adc h
    jr z, jr_009_56b1

jr_009_5699:
    db $eb
    cp d
    ld hl, $d25d
    dec a
    ld d, e
    ld a, [hl+]
    ld hl, $20a2
    cp l
    ld [hl+], a
    and e
    ld c, b
    inc de
    dec d
    db $f4
    db $dd
    ld b, c
    ld c, e
    ld a, d
    add [hl]
    ld c, c

jr_009_56b1:
    ld c, h
    ld d, h
    inc d
    add h
    ld d, c
    ld c, b
    ld c, b
    di
    dec h
    ld e, c
    and d
    jr z, jr_009_56e8

    ld hl, $39f3
    adc c
    ld b, c
    ld c, c
    rst $00
    ld a, b
    sub $90
    ld b, c
    add hl, de
    inc sp
    ld c, l
    xor d
    ld a, [hl+]
    and l
    ld e, d
    adc a
    add [hl]
    call c, $aa8a
    sbc l
    ld e, $60
    and [hl]
    xor d
    push de
    inc b
    and a
    daa
    ld a, c
    rst $10
    ld sp, $138d
    xor d
    ld h, a
    ld a, [de]
    sbc $a1

jr_009_56e8:
    ld d, a
    push hl
    rst $00
    dec bc
    rst $30
    ld a, [hl+]
    ld [hl], c
    xor d
    ld b, h
    rla
    cp c
    add d
    ld h, h

jr_009_56f5:
    rst $38
    jr jr_009_5756

    ld h, d
    sub b
    sub [hl]
    add $10
    pop de
    adc d
    db $10
    ld b, c
    ld [bc], a
    sub c
    ld a, [hl+]
    xor c
    or l
    ldh a, [rLCDC]
    add l
    ld l, b
    ld h, h
    dec hl
    ld b, [hl]
    or d
    and h
    rst $08
    push de
    ld a, [hl]

jr_009_5712:
    ld [hl], l
    ld d, l
    rra
    ld [de], a
    ld [hl], a
    cp h
    dec d
    ld d, l
    ld c, [hl]
    push af
    ld d, h
    push bc
    ld a, a
    ld [$ff7f], a
    ld d, e
    sub c
    ld l, a
    xor d
    cp l
    ld d, $a8
    add $a0
    ld l, e
    cp l
    scf
    db $76
    adc h
    xor e
    and [hl]
    ld c, e
    ld [hl], h
    add h
    cp e
    ld c, l
    jr z, jr_009_5712

    ld c, d
    ld d, d
    rra
    ld a, [bc]
    add hl, hl

jr_009_573e:
    ld a, [hl+]
    db $d3
    ld a, [de]
    add hl, de
    rra
    ld c, l
    jr nz, jr_009_57c4

    add d
    ld l, $4c
    ld d, h
    cp d
    ld hl, $685c
    add h
    inc hl
    jr @+$27

    ld a, b
    xor $45
    dec b

jr_009_5756:
    adc b
    adc h
    ld d, $a8
    ld [c], a
    adc d
    and d
    and b
    and d
    ld d, h
    ld d, $3b
    inc hl
    dec de
    ld c, c
    pop bc
    ld l, d
    ld hl, sp+$6d
    ld a, [hl-]
    jr jr_009_573e

    rst $30
    and d
    ld sp, $8eb4
    ld c, l
    cp c
    ld e, d
    adc c
    ld c, h
    call nc, $8594
    jp hl


    sub l
    or l
    ld c, h
    xor e
    jr nc, jr_009_57cc

    call nc, $b5a4
    and d
    dec l
    sbc $55
    ld d, [hl]
    adc h
    inc de
    add c
    ld e, d
    ld [hl], l
    ld d, e
    ld h, $e0
    ld d, h
    pop bc
    ld e, d
    dec [hl]
    and [hl]
    dec l
    dec c
    dec [hl]
    ld hl, sp+$6a
    adc b
    adc $3a
    ld c, e
    ld c, l
    sub a
    pop de
    add l
    ld a, [hl-]
    and h
    or l
    inc [hl]
    ld a, [c]
    sbc b
    sbc b
    add sp, -$5c
    dec d
    inc b
    add $86
    rst $38
    xor d
    xor a
    call nc, Call_009_5fe2
    ld [$d5ab], a
    ld [hl+], a
    cp [hl]
    adc l
    ld l, d
    ld c, l
    ld e, a
    and e
    ld b, h
    ld l, d
    db $e3
    dec b
    ld c, h

jr_009_57c4:
    ld h, b
    adc h
    sbc [hl]
    jr c, jr_009_582d

    ld d, e
    rlca
    xor b

jr_009_57cc:
    inc [hl]
    cp b
    inc hl
    dec b
    add hl, sp
    sub h
    pop bc
    sub a
    jp nz, $3985

    inc d
    dec d
    ld sp, $fc50
    dec d
    ld b, d
    ld e, c
    ld d, h
    add h
    pop de
    ld c, d
    sbc d
    xor b
    call $a81d
    sbc d
    db $f4
    ld l, b
    db $10
    adc h
    ld d, h
    sub l
    ld d, b
    ld l, b
    add h
    adc b
    ld [c], a
    db $f4
    ld d, b
    adc h
    rst $28
    ld l, d
    dec bc
    call nc, Call_009_7a60
    db $d3
    dec [hl]
    add d
    add l
    sbc b
    sbc $bf
    rst $18
    ld e, l
    ld h, d
    ld l, a
    push de
    ld b, e
    push de
    rst $10
    ld l, b
    rst $20
    xor d
    adc l
    ld l, d
    cp a
    cp $a3
    add hl, sp
    ldh [$a5], a
    daa
    ld a, d
    ld b, d
    ld h, a
    inc c
    ld e, d
    ld b, h
    add hl, bc
    call z, $3584
    jp hl


    ld c, c
    sub d
    sub b
    jp nc, $c531

    add hl, de
    ld a, [hl]
    ld d, h
    sbc b

jr_009_582d:
    ld [hl-], a
    add hl, sp
    add d
    ld l, e
    dec de
    ld a, d
    ld d, h
    sub d
    jp nz, $8490

    ld c, l
    xor c
    xor d
    dec e
    ld c, c
    ld c, $19
    add h
    add hl, sp
    add hl, sp
    ld de, $a987
    ld [hl], c
    inc sp
    inc h

Call_009_5848:
    ld h, b
    db $fd
    ld h, $36
    xor h
    ld l, b
    cp $60
    add a
    xor a
    jp c, $c41f

    ld c, c
    add h
    ld [hl], b
    ccf
    db $fc
    ld h, b
    rst $18
    ld hl, sp+$3d
    ld [bc], a
    ld [$ccc9], sp
    rst $38
    pop af
    sub h
    push de
    ld b, h
    and c
    ld [de], a
    jp c, $ab9a

    rst $38
    db $d3
    sbc c
    ret nz

    sub a
    sub b
    xor a
    pop bc
    ld a, a
    xor d
    xor e
    db $eb
    ld e, d
    add a
    db $f4
    ld h, [hl]
    sub h
    call nz, $c823
    ld b, c
    dec [hl]
    rst $38
    rst $38
    rst $38
    rst $38
    or l
    add hl, de
    and l
    db $eb
    add [hl]
    ld l, e
    add l
    ld a, a
    rst $38
    rst $38
    di
    dec de
    or l
    inc l
    cp c
    and d
    ld [$3d70], sp

jr_009_5899:
    ld d, l
    rst $00
    inc de
    rrca
    ei
    ld [hl], c
    xor d
    call nz, $e9ff
    call Call_009_5323
    adc d
    ld h, [hl]
    add h
    add e
    rst $38
    ld a, [$c973]
    rra
    add l
    xor c
    ld e, b
    inc hl
    rst $38
    ld d, l
    dec e
    sub e
    ld d, h
    rst $10
    rst $38

jr_009_58ba:
    add [hl]

Call_009_58bb:
    inc [hl]
    ld h, c
    ld l, e
    add d
    ld [hl], c
    ld hl, $5a18
    rla
    rst $38
    dec de
    rst $18
    and [hl]
    pop af
    or l
    and c
    ld d, c
    sub d
    and l
    rst $38
    sbc c

jr_009_58d0:
    and a
    rra
    sbc c
    pop de
    inc d
    sub e
    rst $38
    jr jr_009_5900

    dec de
    db $e3
    dec h
    call z, Call_000_1909
    rra
    rst $20
    ld [bc], a
    ld a, [hl+]
    sub h
    db $fd
    ld de, $1029
    ld d, e
    inc c
    dec l
    ld sp, hl
    adc l
    dec h
    ret c

    db $eb
    rst $38
    sub b
    sub e
    jr jr_009_5899

    ccf
    and $75
    rst $38
    ld e, h
    adc a
    db $fd
    ldh [$85], a
    and [hl]
    ld l, h

jr_009_5900:
    scf
    ld sp, hl
    or h
    db $10
    ld a, a
    or b
    ld a, [hl]
    ld sp, $ea77
    xor a
    pop hl
    adc a
    ld b, a
    inc e
    scf
    ld d, [hl]
    ld sp, $4870
    ld e, a
    cp $c7
    and l
    inc de
    dec de
    nop
    ld b, h
    or h
    ld d, a
    db $fd
    ld b, l
    ld e, a
    call $a29e
    ld a, a
    ld [$603a], a
    adc [hl]
    ld l, d
    jr nc, jr_009_58ba

    adc e
    ld d, d
    ld d, c
    ld h, l
    jr c, jr_009_58d0

    cp [hl]
    inc d
    db $10
    and b
    db $d3
    adc l
    jp c, $b0a7

    ld d, e
    ld a, e
    ld a, b
    sbc c
    xor e
    or h
    ldh [rHDMA2], a
    xor b
    xor c
    ld c, l
    ret nc

    ld b, d
    ld b, d
    adc [hl]
    ld h, a
    and [hl]
    and b
    ld d, e
    sbc c
    ld c, b
    cp l
    ld b, c
    ld a, [bc]
    ld d, e
    add l
    ld c, d

jr_009_5956:
    and c
    rst $18
    di
    add [hl]
    push af
    ld d, l
    add [hl]
    xor a
    adc $2a
    xor b
    di
    and $88
    ret nz

    db $e4
    and e
    inc e
    add hl, bc
    add a
    pop de
    ret c

    jp hl


    pop de
    ld a, [bc]
    ld sp, hl
    reti


    rst $18
    db $e4
    ld d, b
    and a
    ld l, $b1
    ld [$6763], sp
    ld [bc], a
    or $1f
    and c
    ld [bc], a
    add hl, sp
    jp $c315


    ld c, e
    ld b, a
    inc c
    ld c, e
    rla
    ld e, c
    add $a1
    dec e
    sub d
    ld [$4f76], a
    inc de
    ld b, h
    daa
    inc de
    rst $38
    add h
    jr jr_009_5956

    ld [hl], c
    ld d, l
    ld b, [hl]
    ld de, $e0f0
    ld d, l
    dec a
    inc e
    inc d
    pop af
    jr nc, jr_009_59ed

    push hl
    ld d, e
    dec d
    dec d
    ld d, h
    adc $a5
    ld h, b
    pop de
    add e
    push de
    xor a
    add e
    ldh a, [$83]
    ld c, h
    dec h
    ld d, a
    ld e, c
    ld h, h
    ld a, h
    inc d
    ld hl, $43a0
    dec [hl]
    or c
    call nc, $811e
    dec c
    ld b, [hl]
    adc e
    and e
    scf
    rst $00
    inc b
    sbc e
    ld l, d
    or a
    push bc
    ld b, c
    jr c, @-$6c

    ld [$82aa], a
    inc b
    sbc b
    jp c, $28d2

    ldh [$4e], a
    ld d, $09
    ld h, b
    ld c, b
    ld e, c
    or $29
    adc l
    db $10
    ld c, d
    sub b
    xor c
    ld a, [hl]
    ld c, [hl]
    dec h
    cp [hl]
    ld b, $ee

jr_009_59ed:
    xor [hl]
    inc d
    ld d, h
    reti


    jp nz, $e96a

    cp l
    ld a, [bc]
    dec l
    inc b
    and l
    add hl, hl
    ld b, l
    ld a, [bc]
    ld a, [bc]
    rla
    dec b
    ld hl, $6288
    inc de
    ld a, [hl+]
    adc h
    ld a, d
    ld [hl], d
    db $10
    ld hl, sp-$68
    db $dd
    add d
    add d
    ld d, l
    ret nc

    ld d, d
    ld l, d
    add hl, hl
    ld sp, $f7a9
    ldh [$fe], a
    pop hl
    ld d, l
    and d
    ld de, $554c
    ld b, [hl]
    ld a, [$0f26]
    dec h
    ld h, d
    ld d, e
    ld a, [hl-]
    jr c, jr_009_5a91

    cp a
    db $fd
    ld e, [hl]
    inc a
    ld e, d
    inc hl
    ld a, d
    ld [$9e42], sp
    ld e, $1d
    ld b, l
    and [hl]
    ld l, c
    ld c, c
    and h
    ld b, h
    dec bc
    jp nz, Jump_000_2da4

    dec c
    ret nc

    add hl, hl
    sub l
    ld a, [hl+]

Jump_009_5a42:
    db $f4
    inc de

Jump_009_5a44:
    dec b
    ld c, [hl]
    ld c, $45
    ld hl, $121c
    ld [$103d], sp
    xor d
    inc d
    ld e, h
    ld l, e
    ccf
    ld c, c
    ld d, h
    xor a
    xor h
    dec hl
    add hl, hl
    or d
    add d
    ld h, e
    ld d, l
    dec b
    ld c, d
    ld b, h
    ld l, b
    db $e3
    inc h

Call_009_5a63:
    ld b, [hl]
    ld c, c
    ld c, c
    cp d
    and b
    add sp, $40
    xor d
    or h
    rra
    inc h
    ld c, [hl]
    ld l, e
    ld e, h
    db $10
    ld c, a
    ldh [$b7], a
    ld hl, $680a

jr_009_5a78:
    sub c
    inc a
    dec c
    ld a, a
    push de
    jr z, @+$23

    jr nz, @-$64

    ld b, c
    add d
    dec c
    inc b
    ld a, [c]
    ld sp, $944a
    sbc c
    or b
    ld b, c
    jp nz, $92a0

    ret nc

    inc l

jr_009_5a91:
    adc e
    add hl, de
    add $2a
    ret nz

    and b
    add e
    and e
    dec b
    inc c
    ld l, a
    dec [hl]
    db $10
    xor d
    ld [$12c3], sp
    sbc c
    jr nz, jr_009_5a78

    inc bc
    call nc, $eafa
    db $fc
    ld a, [hl+]
    add hl, bc
    sub d
    sub e
    ld b, [hl]
    dec d
    ld a, a
    xor h
    sub b
    add h
    ld a, b
    ld d, l
    rlca
    rst $00
    sub [hl]
    ld b, h
    and c
    ld a, a
    call nc, Call_009_5285
    sub l
    ld a, [c]
    ld [$87e0], a
    rst $28
    rst $38
    db $fc
    add h
    jp nz, $ead1

    db $f4
    sbc h
    ld l, e
    ld d, b
    ld c, h
    ld e, $81
    ld d, l
    ld [hl], c

Jump_009_5ad4:
    ld [hl], h
    add hl, hl
    add c

jr_009_5ad7:
    ld c, h
    scf
    and c
    ld d, l
    ld d, [hl]
    add c
    ld d, h
    ld h, $2d
    ld [$6a1a], sp
    sub h
    ld a, [hl+]
    ld c, d
    ld h, d
    ld e, [hl]
    and [hl]
    ld b, [hl]
    sub h
    ld h, h
    ld e, h
    add h
    ld [de], a
    ld d, h
    ld e, b
    ld [de], a
    ld [c], a
    and c
    ldh a, [$4c]
    dec a
    ld [$6d55], sp
    ld h, b
    ld h, d
    inc d
    pop bc
    ld c, b
    xor [hl]
    and l
    cp $bd
    ld b, e
    ld l, b
    cp d
    rst $20
    ld d, $bc
    add hl, sp
    ld a, [de]
    ld a, [bc]
    ld d, e
    dec bc
    sub h
    ld [hl+], a
    add hl, hl
    ld [hl+], a
    sub c
    or $32
    xor a
    xor d
    ld d, b
    ld c, b
    ret z

    di
    sbc d
    cp a
    ld e, h
    adc a
    ld a, [hl-]
    ld l, d
    xor b
    pop af
    and $0a
    ld [hl], c
    add hl, hl
    add l
    rst $38
    ld d, d
    cp a
    ld [$7e45], a
    ld h, e
    ld h, e
    rst $38
    rst $18
    xor l
    ld a, e
    inc bc
    jr jr_009_5ad7

    rst $38
    db $fc
    dec d
    ld a, [$143e]
    ld h, d
    db $fd
    ld c, d
    db $fd
    dec hl
    ld d, a
    xor $60
    xor e
    rst $38
    xor l
    ld a, a
    ld e, [hl]
    or a
    rla
    pop hl
    ld a, a
    db $ed
    ld a, e
    ld l, d
    db $f4
    ret


    ld a, l
    rst $38
    ld a, [hl]
    adc a
    dec sp
    rst $28
    ld l, [hl]
    ld h, b
    and c
    db $fd
    ld c, d
    cp $0f
    di
    pop de
    add a
    ld [$aaee], a
    push de
    cpl
    ld c, d
    ld h, d
    rst $10
    db $fd
    inc bc
    pop hl
    ld a, a
    db $eb
    ld h, [hl]
    sbc a
    rla
    cp $17
    adc a
    sbc h
    push de
    xor $f7
    sbc l
    inc [hl]
    dec d
    rra
    ld c, $66
    cp h
    dec h
    inc a
    ld [hl], l
    ld d, l
    pop hl
    and h
    pop de
    sub h
    reti


    ld d, [hl]
    and d
    ld [c], a
    or e
    ld b, h

jr_009_5b8f:
    adc d
    ld d, d
    ld h, [hl]
    and d
    ld d, l
    ld d, l
    jr nc, @+$52

    ld d, h
    ld a, [de]
    dec h
    ld l, $58
    ld d, l
    rst $38
    xor d
    xor e
    db $f4
    adc d
    adc b
    adc b
    ld c, c
    ld c, d
    push bc
    ld l, [hl]
    cp [hl]
    ld d, e
    jr z, jr_009_5b8f

    ld c, h
    ld h, d
    ld hl, $d3d5
    and c
    and e
    ld a, [hl-]
    jp nc, $8e2a

    sub h
    sbc $25
    ld d, c
    adc [hl]
    ld d, h
    ld d, e
    ld h, h
    sbc d
    add e
    adc $14
    inc h
    ld e, b
    push de
    ld h, d
    inc d
    db $e4

jr_009_5bc9:
    add d
    ld h, $4d
    db $10
    sub c
    xor b
    ld a, $3a
    inc hl
    dec a
    ld h, d
    ld [de], a
    jr jr_009_5bc9

    ld l, d
    xor b
    pop hl
    di
    add hl, de
    scf
    xor b
    and $a5
    add hl, hl
    jr c, @+$01

    ld d, e
    sub d
    ld hl, $eb39
    db $d3
    adc d
    inc b
    add l
    sub e
    sub [hl]
    db $d3
    adc c
    ld b, $25
    add hl, sp
    xor a
    scf
    add d
    jr nc, jr_009_5c5c

    db $f4
    ld h, h
    ldh a, [$a3]
    ld a, c
    sub h
    db $dd
    jp z, $9869

    push hl
    ld h, d
    inc de
    inc e
    and h
    xor $98
    add hl, hl
    sub l
    add d
    sub [hl]
    ld [hl-], a
    sbc l
    adc c
    dec bc
    ld [$a077], a
    xor e
    rst $38
    db $fc
    dec [hl]
    sbc d
    ld [hl-], a
    sbc b
    and b
    cp a
    ld a, a
    ld [hl], e
    jr nc, @+$44

    or [hl]
    add d
    ld b, e
    sub c
    inc hl
    ld c, [hl]
    adc e
    di
    inc b
    adc $aa
    adc h
    ld b, d
    xor a
    db $ec
    add hl, sp
    ld [de], a
    ld d, l
    call c, $ffeb
    rst $38
    rst $38
    ld [$dd3f], a
    add d
    add hl, de
    ld [hl-], a
    ld [$2133], sp
    ld e, h
    or l
    rst $38
    rst $30
    ld [hl], a
    pop hl
    jr nc, @+$45

    add [hl]
    dec hl
    jp $a315


    add [hl]
    xor a
    call Call_009_5f30
    ld h, [hl]
    ld e, b
    ld [hl], $0c
    push bc
    ldh [$c3], a
    sub c
    ld c, h

jr_009_5c5c:
    ld c, h
    inc de
    ld h, [hl]
    jr c, jr_009_5caa

    ld de, $a8be
    ld l, c
    sbc e
    sub h
    add h
    ld [hl-], a
    ld l, b
    ret


    add hl, de
    ld d, $6a
    adc e
    ld hl, $1a0b
    db $e3
    add e
    xor b
    and $f9
    adc l
    add hl, de
    ld [c], a
    pop bc
    sub c
    ld h, a
    ld c, [hl]
    ld h, a
    dec l
    rlca
    sub b
    add $c9
    sbc d
    add hl, sp
    and e
    rrca
    ld b, [hl]
    or b
    ld b, c
    ld [$6761], a
    add a
    inc sp
    ld a, [c]
    ld c, e
    inc e
    cpl
    ld a, [$b09a]
    ld e, e
    ld h, d
    call nz, $ab29
    ld [hl], a
    ld a, d
    ld l, l

jr_009_5c9f:
    ld a, b
    ld h, b
    ret nz

    ret nc

    ld c, b
    and [hl]
    ld d, b
    ld c, h
    sbc $9a
    ld b, c

jr_009_5caa:
    adc a
    ld sp, $9c53
    inc sp
    ld d, h
    sbc e
    ld h, [hl]
    ld d, b
    ld c, [hl]
    ld l, l
    ld [de], a
    add $d9
    or h
    add d
    ld [hl], b
    reti


    ld c, d
    add d
    add hl, de
    jp Jump_000_0205


    ld l, b
    adc $43
    inc c
    ld de, $06cd
    inc c
    and b
    sub b
    jp z, Jump_009_772c

    call nz, Call_009_51c1
    inc [hl]
    ld h, [hl]
    ld b, h
    cp b
    push de
    xor d
    xor b
    db $e3
    ld e, d
    ld a, [hl-]
    ret c

    db $ed
    ld h, e
    cp d
    ld a, [hl-]
    push de
    ld h, e
    or c
    inc a
    add hl, de
    ld a, $06
    inc a
    jr jr_009_5c9f

    ld a, a
    adc $49
    ld c, c
    ret nc

    rst $38
    add hl, sp
    xor d
    ret c

    ccf
    adc $ba
    and l
    ld d, e
    pop bc
    xor b
    pop af
    ld h, a
    ld a, [de]
    ld sp, $84d2
    db $76
    ld sp, $aa92
    ld l, [hl]
    push bc
    xor l
    ld b, d
    reti


    or h
    ld h, c
    inc d
    call $aa98
    add $d3
    ld a, $63
    ld hl, $994a
    rst $28
    ld b, [hl]
    sub d
    ld b, l
    jr jr_009_5d9a

    ld b, [hl]
    jp hl


    ldh [$a6], a
    ld a, [hl+]
    and a
    ld a, [hl+]
    ld c, d
    add h
    xor [hl]
    sbc h
    sub b
    inc h
    ld c, b
    dec hl
    rst $20
    ld b, l
    ld h, c
    rst $38
    or e
    dec e
    ld d, l
    ld e, a
    sbc a
    ld a, [bc]
    ld d, l
    cp a
    add hl, bc
    ld e, a
    rst $38
    ld d, e
    dec h
    ld a, b
    ldh [$a8], a
    cpl
    rst $28
    ret nc

    ld e, a
    ld a, [$a838]
    jr nc, @-$48

    jr jr_009_5d76

    sub l
    ld b, [hl]
    adc $26
    ld b, [hl]
    ld l, b
    xor e
    xor e
    sbc [hl]
    dec [hl]
    ld a, d
    ld b, e
    ld sp, $5d5c
    ld e, a
    adc l
    ld l, [hl]
    dec bc
    jp nz, $1e1d

    daa
    and e
    add l
    add sp, $38
    dec l
    add hl, bc
    pop af
    ld l, c
    sub b
    db $e3
    ld l, e
    ldh a, [$64]
    ld h, c
    ldh [$62], a
    db $10
    ld h, b
    ld h, e
    add d

jr_009_5d76:
    sub c
    and l
    add c
    sub h
    ld l, l
    rst $00
    adc l
    sbc [hl]
    adc h
    ld [hl+], a
    inc d
    ld h, b
    ld e, b
    ldh [$a4], a
    add $a8
    sub l
    dec b
    ld a, [bc]
    ld [hl], $ba
    sub d
    ld a, [de]
    add a
    ld b, d
    jr @+$5a

    db $e4
    ld l, d
    ld a, b
    jr z, @+$2d

    dec e
    adc b
    ld c, [hl]

jr_009_5d9a:
    dec bc
    or a
    add [hl]
    add c
    jp nz, $5505

    adc [hl]
    ld e, b
    sbc e
    ldh [$78], a
    ld sp, hl
    sbc c
    ld hl, sp+$53
    inc de
    ld a, [de]
    daa
    inc hl
    inc c
    adc l
    inc h
    ld hl, $10a1
    sbc h
    ld de, $0693
    rla
    jp nc, $9c12

    db $76
    ld b, l
    dec bc
    or e
    ld a, [$7114]
    ld b, b
    sbc b
    ccf
    rst $38
    pop af
    jp z, $84c0

    ld b, l
    rst $38
    ld a, [$7052]

jr_009_5dd0:
    jr c, jr_009_5e30

    and b
    rst $38
    cp $b0
    ld c, [hl]
    sbc e
    jp Jump_009_7f03


    rst $38
    rst $38
    add sp, $34
    ld [hl], c
    ld [hl+], a
    db $eb
    ld d, b
    dec a
    ld a, h
    inc l
    ld [hl], d
    ld e, e
    ld c, d
    jr jr_009_5e65

    ldh a, [rNR44]
    ld [bc], a
    ld l, l
    inc b
    rrca
    cp $19
    rla
    push af
    xor [hl]
    and a
    inc c
    dec [hl]
    cp c
    ld [hl], c
    ccf
    ld e, c
    jp nz, $7191

    ld [$2f3a], sp
    db $eb
    inc e
    or c
    jr z, @+$73

    ld de, $c3e1
    rra
    ld [hl], $44
    cp [hl]
    ret


    rst $30
    ld b, l
    ld d, e
    sub [hl]
    add [hl]
    ld a, [bc]
    rlca
    adc [hl]
    ld d, l
    dec hl
    cp e
    add hl, sp
    xor l
    ld e, b
    inc hl
    and l
    dec c
    ld e, b
    rla
    add hl, sp
    ld l, e
    adc c
    ld e, l
    add hl, sp
    jr z, jr_009_5dd0

    ld a, [de]
    ld a, [hl-]
    sub c
    ld a, d
    add hl, sp
    dec l

jr_009_5e30:
    ld e, b
    ld d, c
    sub e
    sbc d
    ld d, l
    adc a
    xor d
    sbc a
    adc c
    rst $18
    and h
    rst $20
    dec a
    rst $38
    adc d
    ld [hl], h
    rst $18
    jp nz, Jump_009_6ee7

    ld de, $bad9
    ld de, $bfd0
    rst $18
    sbc h
    xor a
    rst $38
    ld b, e
    ld h, a
    dec [hl]
    pop af
    ld hl, sp+$60
    ld [hl], a
    or d
    ld d, h
    push af
    ld e, $b9
    ld hl, $5549
    ld c, h
    sub [hl]

Call_009_5e5f:
    db $f4
    db $e4
    ld d, b
    ld h, d
    ld a, [hl+]
    xor a

jr_009_5e65:
    cp d
    xor e
    ret nc

    ld d, a
    rst $18
    sbc d
    jp nc, Jump_000_15d3

    ld sp, $a24a
    ldh [$9c], a
    ccf
    daa
    sub b
    ld c, b
    ld a, d
    ld sp, $4990
    add l
    ld hl, $8b22
    ld [hl], d
    inc h
    ld l, d
    xor e
    ld d, e
    inc [hl]
    ld l, b

jr_009_5e86:
    adc b
    ld h, [hl]
    and [hl]
    ld d, $08
    call Call_009_6826
    dec l
    ld c, h
    sub e
    ld c, d
    adc l
    ld d, b
    sub [hl]
    ld hl, $9a9e
    dec [hl]
    sub h
    ld h, e
    ld d, $a1
    ld c, b
    ld c, h
    ld e, b
    add l
    ld c, [hl]
    ld c, b
    or [hl]
    or e
    inc [hl]
    add l
    and e
    inc b
    ldh [$5d], a
    ld l, $04
    add h
    or h
    add [hl]
    inc hl
    ld c, [hl]
    ld d, a
    and c

jr_009_5eb4:
    sub d
    and b
    xor c
    ld b, d
    inc d
    adc b
    jp nz, $8e41

    dec b
    ld e, d
    jr jr_009_5e86

    ld b, c
    ld a, [hl+]
    adc h
    db $e3
    inc h
    add $c1
    ld d, l
    jp nz, $f80a

    ld d, b
    ld h, [hl]
    ld sp, $544a
    sbc $a2
    ld d, $86

Jump_009_5ed5:
    adc c
    db $fd
    adc b
    adc d
    add l
    or h
    adc e
    ld d, e
    ld a, [hl+]
    ld hl, $4a8b
    ld a, [$aa89]
    add [hl]
    dec b
    dec d
    and c
    db $f4
    adc $32
    sub b
    ld d, d
    ld d, d
    call nc, $0475
    sbc b
    ld l, b
    jp nc, Jump_000_0429

    sbc d
    ld a, [bc]
    and b
    ld d, a
    and c
    add d
    xor e
    pop hl
    ld c, l
    ld l, b
    inc [hl]
    ld e, a
    add d
    ld h, $2a
    ld [hl+], a
    adc b
    ld c, c
    add [hl]

Jump_009_5f09:
    ld b, [hl]
    ld b, d
    adc h
    ld l, [hl]
    inc b
    inc l
    call $b918
    ld e, e
    ld hl, sp+$23
    sbc a
    ld e, l
    ld d, d
    sub b
    sbc c
    ld d, $31
    ld h, c
    and d
    db $d3
    ld l, e
    ld e, a
    ld a, [hl+]

Call_009_5f22:
    ld l, $8b
    ld e, d
    inc [hl]
    adc [hl]
    ld a, [de]
    sub l
    and d
    sub d
    sub e
    sub c
    ld a, [hl-]
    jr z, jr_009_5eb4

Call_009_5f30:
    add h
    inc hl
    sbc d
    adc [hl]
    ld l, e
    ld e, l
    xor a
    add c
    add hl, hl
    dec l
    and e
    cp [hl]
    adc c
    ld d, l
    dec b
    and l
    dec h
    adc a
    ld h, $a8
    ld e, a
    or c
    ret z

    ld h, e

Call_009_5f48:
    call z, $26bf
    and e
    ld [$aaf2], sp
    and l
    dec h
    ld h, d
    scf
    ret z

    inc h
    ld h, $48
    ld h, a
    ld b, e
    rrca
    ld c, d
    ld b, [hl]

jr_009_5f5c:
    ld b, h
    ld l, $a2
    add e
    cp a
    cp d
    ld [hl], d
    dec h
    ld c, e
    ld [bc], a
    inc l
    dec c
    and h
    cp [hl]
    add l
    ld [hl], d
    inc e
    ld [hl], e
    dec h
    xor l
    inc bc
    db $10
    sub e
    inc d
    or d
    inc d
    add hl, hl
    ret nz

    sub c
    inc h
    ret z

    pop af
    ld de, $1011
    jr nc, @-$36

    and c
    jp z, $99a1

    jp nc, $b1d4

Call_009_5f88:
    ld a, [bc]
    and [hl]
    adc c
    ld [de], a
    ret nz

    add l
    and d
    and $e9
    ld c, l
    ld hl, $4282
    jr c, @+$42

    sub c
    inc d
    and b
    and a
    inc a
    pop hl

jr_009_5f9d:
    add hl, sp
    and d
    ld a, [bc]
    ld l, l
    ld b, a
    ld [hl+], a
    inc sp
    add hl, sp
    ld a, e
    inc l
    ld [hl], $98
    ld hl, sp+$46
    xor h
    ld e, l
    ld d, b
    ld b, c
    inc c
    jr jr_009_5f5c

    xor b
    ld c, d
    ld b, d
    sub d
    sbc d
    ld [hl], e
    add $88
    and b
    add l
    inc b
    ld c, h
    jr jr_009_6008

    and l
    and $70
    ld b, c
    db $e4
    ld b, b
    or h
    add hl, bc
    db $10
    ld d, c
    add l
    ld de, $9c0c
    ld c, h
    or l
    jr jr_009_6010

    ld [$1ea6], sp
    ld h, b
    call nc, $9065
    or b
    and b
    push bc
    pop af

jr_009_5fdd:
    ld [de], a
    ld a, [bc]
    ld d, h
    add hl, bc
    dec c

Call_009_5fe2:
    add hl, sp
    cp l
    dec bc
    rst $30
    inc b
    jr z, jr_009_5f9d

    ld b, d
    cpl
    rst $38
    and e
    dec c
    inc b
    add hl, hl
    add d
    and d
    pop bc
    dec d
    ld b, c
    ld b, c
    and b
    push de
    db $fd
    ld d, b
    or a
    inc [hl]
    ld c, h
    ld h, e
    ld b, b
    add d
    ld h, b
    add a
    ld e, c
    ld de, $3a68
    pop bc
    inc b

jr_009_6008:
    add hl, hl
    ld d, $99
    ld b, e
    and h
    or b
    ld b, h
    ret z

jr_009_6010:
    ld c, b
    or l
    ld c, d
    rra
    push de
    jr jr_009_605d

    push af
    jp nz, Jump_009_45d2

    ld l, l

jr_009_601c:
    db $10
    and [hl]
    inc [hl]
    ld de, $702c
    ld c, a
    ld b, b
    or c
    ld [hl], h
    and h
    and $08
    ret z

    ret nz

    sbc h
    db $10

jr_009_602d:
    or h
    jr z, @-$5a

    inc h
    ld a, h
    inc [hl]
    xor a
    pop de
    inc d
    add hl, de
    pop de
    ret nz

    adc e
    dec h
    ld b, l
    db $e4
    dec sp
    inc h

Call_009_603f:
    ld b, a
    ld d, e
    inc hl
    inc bc
    ld d, $ed
    db $fd
    ld de, $1a1e
    and c
    ld b, h
    jr nz, jr_009_5fdd

    reti


    ld sp, $43e1
    ld de, $2883
    ld l, h
    ld e, h
    ld a, c
    jr jr_009_6099

    add h
    sbc b
    rst $00
    sub a

jr_009_605d:
    inc de
    ld b, b
    xor l
    ld [de], a
    ld b, h
    and c
    ld a, a
    jp nc, $f517

    ld e, a
    ld e, a
    ld l, $a2
    ld e, $ba
    db $e4
    ld [hl], $18
    jr z, jr_009_601c

    ld hl, $a2d6
    jr z, jr_009_60cc

    ld h, e
    dec de
    ld e, d
    ld a, [hl+]
    adc [hl]
    ld a, d
    sub l
    inc d
    dec h
    adc h
    sub d
    xor $81
    ei
    inc sp
    ld e, d
    and d
    sub d
    ld a, c
    xor c
    ld l, b
    sbc d
    ld h, $2a
    sub $94
    ld e, $16
    ld h, $55

Jump_009_6095:
    adc h
    ld [hl+], a
    xor b
    dec hl

jr_009_6099:
    push de
    ld a, [hl-]
    sbc b
    xor b
    add l
    ld c, h
    jp nc, Jump_009_5221

    sbc b
    jr jr_009_602d

    jp nz, $81eb

    ld b, $87
    or e
    inc [hl]
    jp nz, $6ddb

    ld b, l
    rra
    ld b, l
    adc [hl]
    ld c, e
    or $82
    pop af
    ld b, c
    dec sp
    jr z, jr_009_60e3

    pop af
    ld h, [hl]
    ld a, [bc]
    ld e, d
    and [hl]
    ld a, [hl+]
    ld l, b
    ld hl, sp+$44
    or b
    ld b, h
    ld a, [hl]
    push bc
    ld a, [$f9ca]
    rrca

jr_009_60cc:
    add sp, -$01
    ld h, $34
    rra
    rst $38
    add a
    rst $38
    ei
    ld [hl], c
    and d
    push af
    cp $ff
    db $fc
    sub d
    sbc b
    ld h, c
    add sp, $7f
    db $f4

Call_009_60e1:
    cp $10

jr_009_60e3:
    rst $38
    sbc b
    ld [hl], l
    ld a, a
    jp nz, $92bf

    rst $38
    sub l
    dec [hl]
    ld l, a
    db $10
    rst $38
    db $db
    ld d, a
    ld sp, hl
    ld d, b
    cp a
    ld a, [$afaa]
    di
    ld h, $6f
    rst $38
    db $fc
    scf
    db $fc
    ld l, e
    add a
    rst $38
    rlca
    cp a
    cp $4b
    add e
    sbc b
    call c, $df18
    add l
    add d
    ccf
    pop hl
    sbc h
    scf
    ret z

    ld b, e

jr_009_6113:
    rst $38
    add [hl]
    db $76
    ld d, b
    ld d, c
    ldh a, [$a0]
    ld d, l
    cp l
    sub l
    db $fd
    ld c, a
    ld bc, $8ae8
    db $d3
    dec h
    jr nc, jr_009_6179

    ld a, [de]
    jr c, jr_009_6113

    adc d
    xor e
    ld c, b
    ld l, d
    add hl, hl
    or b
    ld d, d
    ld d, l
    pop hl
    and d
    ld d, h
    ld d, [hl]
    sub $2d
    ld b, c
    ld c, b
    ld l, b
    jr nc, jr_009_61bb

    adc d
    ld e, a
    and e
    add c
    ei
    ld b, [hl]
    push bc
    ld l, $89
    ld e, d
    and h
    cp e
    ld a, [bc]
    call nc, $a86a
    sbc d
    ld h, $25
    ld e, b
    sbc l
    ld b, c
    adc b
    xor [hl]
    ret c

    sub l
    inc hl
    ld c, b
    ld a, [hl]
    sub h
    ld d, h
    jp c, $9134

    ld e, l
    ld hl, $948a
    ld d, [hl]
    dec h
    inc [hl]
    ld c, c
    ld d, l
    inc sp
    and d
    ld [c], a
    ld l, b
    jp nz, $e0bd

    add l
    and h
    and l
    and l
    jp nc, $cd69

    ld h, d
    push hl
    rlca
    ld c, b

jr_009_6179:
    ld l, d
    daa
    ld c, h
    sbc b
    ld [hl+], a
    add hl, hl
    ld c, b
    adc b
    ld e, b
    or a
    add l

Jump_009_6184:
    ld l, c
    ld a, [bc]
    ld b, d
    jr @+$27

    ld a, [bc]
    ld e, d
    ld l, $45
    ld e, a
    xor c
    ld e, a
    adc b
    ld c, c
    sub h
    pop bc
    ld a, [de]
    ld h, $8c
    add hl, hl
    ld e, d
    dec d
    sub c
    sub [hl]
    ld b, d
    add c
    ld a, [hl-]
    xor b
    push bc
    add c
    inc a
    ld l, d
    cpl

jr_009_61a5:
    ld a, l
    inc a
    sbc [hl]
    dec hl
    dec de
    ld b, a
    ld a, [bc]
    ld d, l
    jr nc, jr_009_61d5

    ld l, b
    ld b, [hl]
    inc c
    sub e
    and l
    ld a, [hl-]
    and l
    ret nz

    add a
    ld d, c
    add e
    ld b, d

jr_009_61bb:
    xor d
    sub l
    ld b, h
    xor l
    dec b
    sbc d
    call nz, $b540
    and l
    ld h, e
    rst $38
    ld c, l
    ld c, b
    dec h
    pop bc
    inc sp
    inc bc
    ld c, a
    and b
    rst $18
    and e
    xor b
    add sp, $59
    ld l, h

jr_009_61d5:
    ret z

    and b
    jp nc, $acb0

    ld e, l
    ld [hl], h
    ld l, h
    adc d
    sbc b
    add hl, hl
    xor l
    ld h, $8b
    ld [de], a
    xor d
    ld l, h
    xor c
    and d
    add l
    ldh a, [$d8]
    ld d, h
    ld c, d
    ld b, e
    jp Jump_000_3d99


    dec [hl]
    jr nz, jr_009_61a5

    adc a
    ld c, b
    ld b, b
    call nc, Call_000_0363
    dec d
    add hl, sp
    ld a, [hl-]
    ld b, l
    inc l
    xor c
    ld sp, $a96c
    rra
    ld a, e
    inc b
    ld d, $a4
    xor d
    ld b, a
    rla
    ld b, h
    ld d, d
    sub b
    db $e4
    ret z

    ld [hl], a
    sbc $fc
    ld [hl], c
    ld d, h
    ld d, [hl]
    sub e
    ld b, e
    ret nz

    sbc [hl]
    ld [hl-], a
    sbc [hl]
    ld a, b
    ld b, h
    or b
    ld d, e
    dec b
    ld c, [hl]
    ld c, d
    cp l
    ld e, a
    xor e
    db $d3
    add [hl]
    ret nc

    ld e, d
    dec e
    add $90
    ld a, h
    sub $a2
    jp nc, $c515

    dec [hl]
    and e
    ld b, l
    ld h, b
    adc [hl]
    ret z

    ld [c], a
    and e
    db $76
    jr c, jr_009_62b1

    daa
    sub [hl]
    ld [hl], $78
    ld a, [de]
    daa
    and l
    ld a, [bc]
    ld d, e
    ld b, l
    ld a, d
    ld [hl], h
    adc b
    inc d
    sub h
    sub $8a
    or l
    ld a, [hl]
    rla
    adc [hl]
    ld l, d
    add l
    ld sp, hl
    adc $b5
    ld a, [bc]
    dec sp
    ld l, [hl]
    ld a, $1e
    ld a, b
    pop af
    add hl, bc
    ld d, a
    xor c
    ret


    ld a, h
    ld c, l
    rst $18
    sub h
    sbc h
    ret nc

    ldh a, [$28]
    add hl, sp
    db $d3
    or a
    db $ec
    ld l, d
    and [hl]
    ld c, a
    db $e4
    add hl, sp
    cp d
    ld h, b
    rst $38
    add e
    ld sp, hl
    or h
    ld e, $ab
    db $fd
    adc l
    ld a, c
    cp e
    ld a, a
    jp nc, Jump_009_71f4

    add $2f
    and a
    ld h, a
    ld b, l
    cp c
    db $dd
    rst $00

Jump_009_628c:
    ld [hl], d
    ld a, l
    ld b, b
    ld [hl], a
    cp d
    push de
    rst $38
    push hl
    ld c, b
    ld d, e
    jp $bf56


    ld c, c
    sub c
    xor e
    or h
    ldh a, [$2a]
    xor d

jr_009_62a0:
    xor e
    push af
    ld a, [bc]
    adc b
    add d
    add l
    db $f4
    jp hl


    db $ed
    ld [hl-], a
    jp nz, Jump_000_2222

    ld a, [bc]
    add c
    ld d, e
    sbc c

jr_009_62b1:
    ld a, d
    ld b, d
    ld c, c
    ld l, b
    ld h, e
    add c
    add hl, sp
    ld e, $85
    ld h, $a8
    ld d, [hl]
    rlca
    and e
    ld h, $a3
    adc d
    adc c
    ld c, d
    ld d, l
    ld h, c
    ld l, b
    inc hl
    inc [hl]
    jr z, jr_009_62a0

    ld d, [hl]
    adc c
    adc d
    ld c, h
    db $10
    adc l
    add sp, -$37
    cp $ad
    adc b
    ld c, b
    ld e, b
    and [hl]
    add d
    ld [hl-], a
    ld h, c
    ld e, b
    adc $d5
    xor b
    ld h, b
    ld b, l
    adc d
    ld l, l
    res 1, h
    ld h, e
    add d
    sub b
    ld a, [c]
    ld hl, $414b
    ld a, [de]
    dec h
    ld b, $93
    adc l
    rst $38
    and b
    ld c, c
    ld c, e
    ld b, c
    dec b
    ld a, b
    pop bc
    ld d, d
    ld de, $307d
    ld d, d
    ld e, b
    ld d, $8c
    xor b
    inc d
    sbc b
    ld l, l
    and d
    ld e, d
    dec b
    ld sp, $8dba
    and d
    ld h, d
    and d
    dec [hl]
    sub c
    ld l, c
    and e
    scf
    and b
    ld h, b
    xor d
    xor d
    ld [$2a86], sp
    ld [hl-], a
    add d
    dec l
    ld [hl-], a
    ld l, [hl]
    inc d
    adc a
    ld e, [hl]
    ld d, b

Call_009_6324:
    ld c, d
    ld h, c
    ld c, c
    ld h, d
    ld h, b
    ld b, c
    xor b
    and l
    ld e, b
    adc $83
    ld l, b
    ld d, [hl]
    adc c
    sub d
    ld de, $8848
    ld l, b
    add a
    and d
    dec d
    inc b
    rra
    sub h
    sbc d
    adc h
    and d
    ld l, b
    jp nz, $9508

    ld b, c
    ld h, d
    ld a, [hl-]
    ld a, [bc]
    add [hl]
    and h
    jp hl


    ld d, b
    adc e
    xor l
    ld c, b
    ld d, [hl]
    and [hl]
    adc d
    sub c
    db $dd
    db $d3
    ld e, d
    ld hl, sp-$2a
    rrca
    jp z, Jump_009_628c

    cpl
    db $f4

jr_009_635e:
    push de
    ld c, l
    sbc $95
    ld [hl+], a
    ld [hl], $be
    inc sp
    cp d
    adc l
    sub [hl]
    adc b
    add d
    ld hl, $4651
    ld b, c
    add c
    ret nc

    ld c, h
    ld d, $8d
    ld a, l
    ld b, d
    ld b, d
    add l
    add c
    db $f4
    jr jr_009_63dd

    ld l, e
    db $e3
    jr z, jr_009_635e

    xor d
    ld hl, sp+$52
    ld l, $04
    ld h, l
    ldh [$a7], a
    inc sp
    adc [hl]
    dec [hl]
    ld d, $15
    ld h, h
    inc d
    ld l, e
    rst $00
    ld c, [hl]
    push af
    db $76
    xor a
    rst $30
    dec l
    ret nc

    push hl
    ld l, h
    ld sp, $4e6b
    ld a, [hl+]
    ld [hl-], a
    xor c
    ld d, [hl]
    push af
    rlca
    db $fd
    pop bc
    ld [hl], l
    ld d, d
    scf
    ld e, d
    add hl, sp
    ld sp, $a4e5
    call nz, $032d
    add sp, -$2f
    pop hl
    add $37
    xor b
    ld a, b
    ld b, c
    inc b
    ld a, b
    ld l, c
    ld a, [hl+]
    jp $e158


    inc b
    db $10
    xor b
    ld h, a
    ld e, h
    jr jr_009_6417

    adc a
    ld b, [hl]
    ld a, [hl+]
    ld de, $13d7
    add hl, hl
    adc e
    ld b, [hl]
    ld d, h
    add hl, bc
    pop de
    inc c
    ld b, e
    ld h, l
    add $51
    inc [hl]
    ld l, h
    sbc b
    jp nz, $1893

jr_009_63dd:
    ld b, b
    ret z

    ld b, [hl]
    ld d, c
    cp [hl]
    cp c
    inc c
    ld h, d
    sub d
    ret nc

    dec h
    call nz, Call_000_0f47
    adc h
    inc d
    ld c, e
    dec bc
    ld b, d
    pop af
    add hl, bc
    ld sp, $43d5
    sub d
    sub c
    inc de
    add hl, hl
    adc d
    ld b, h
    add h
    ld [hl], b
    db $e4
    or b
    ld d, d
    sub c
    inc de
    inc h
    or d
    ld c, h
    adc e
    ld a, [bc]

jr_009_6407:
    ld [hl], b
    dec l
    ld a, [bc]
    ld de, $3031
    ld [hl], l
    ld c, l
    inc c
    rra
    xor c
    ld de, $670e
    ld h, $0b

jr_009_6417:
    ld b, h
    xor h
    and e
    inc b
    jr z, jr_009_643e

    jp z, $3582

    sbc d
    cp h
    jr nc, jr_009_6481

    inc h
    jr z, jr_009_644f

    pop bc
    ld [de], a
    sub b
    or c
    ld de, $f1c2
    inc c
    jp nc, $1444

    ld b, l
    ld [de], a
    xor e
    ld b, c
    dec b
    inc b
    inc c
    ld de, $25a7
    ld a, d
    and e

jr_009_643e:
    ld b, l
    add hl, hl
    jr z, jr_009_6407

    ld d, c
    inc [hl]
    ld h, d
    or b
    ld d, b
    jr z, @-$5d

    ld d, a
    xor d
    or h
    ld c, $aa
    add d

jr_009_644f:
    ld h, l
    ld sp, $1487
    jp z, Jump_009_5ad4

    ld b, e
    ld b, e
    ld d, h
    ld [de], a
    and h
    ld e, e
    pop af
    sub e
    ld c, b
    and b
    sub e
    ld b, l
    ret z

    ld h, $7e
    push de
    dec c
    dec de
    jp Jump_009_6afe


    sbc d
    cp $31
    rst $00
    xor l
    ld a, d
    rla
    add hl, de
    jp hl


    ld a, [bc]
    ld b, a
    rst $20
    ld c, h
    ld b, l
    inc c
    ld h, b
    sub c
    inc bc
    pop de
    dec e
    sub e
    inc e

jr_009_6481:
    ld a, a
    ld hl, $600a
    or h
    dec hl
    and h
    inc l
    ld d, h
    ld [hl], e
    jp $a814


    ld b, c
    ld a, h
    ld [hl], $a8
    ld b, d
    add d
    ld sp, $cacc
    rst $38
    ld c, b
    and [hl]
    inc [hl]
    ld [$f83f], sp
    ld b, a
    dec [hl]
    db $10
    call nc, Call_009_4b0e
    add sp, -$41
    ld c, [hl]
    ldh a, [$7a]
    ld [hl], a
    ld b, h
    or b
    ld d, b
    jr z, jr_009_6504

    ld c, $52
    ld c, b
    ld b, h
    or e
    ld a, c
    ld e, [hl]
    rst $28
    ld d, e
    ld h, l
    daa
    ld l, h
    jr z, jr_009_6528

    db $fd
    ld c, e
    ld a, [hl]
    xor e
    adc b
    ld b, d
    inc b
    and a
    jr nc, jr_009_6519

    jr nz, @-$1f

    ld [hl+], a
    dec b
    ld h, [hl]
    ld b, d
    jr nc, jr_009_6526

    jp c, Jump_000_0781

    ld b, $38
    ld e, l
    dec h
    add d
    add c
    ld [$cda4], sp
    ld l, [hl]
    and c
    xor a
    ld b, $05
    inc b
    call $8848
    adc c
    xor a
    and e
    adc [hl]
    inc c
    inc d
    add l
    ld d, [hl]
    ld b, $92
    add sp, -$5c
    ld d, $96
    ld a, [hl+]
    ld h, h
    add $d2
    sub b
    ld c, h
    sub d
    inc hl
    rla
    db $f4
    ld l, $30
    ld [hl], e
    ld l, a
    call nc, Call_000_3126
    adc b

jr_009_6504:
    ld d, h
    jp z, Jump_009_6aa5

    ld d, d
    ld d, [hl]
    xor a
    add sp, -$1d
    xor d
    inc a
    db $fd
    xor d
    ld b, d
    ld b, d
    ld [hl], h
    ld c, l
    ld b, c
    ld d, l
    inc e
    add hl, bc

jr_009_6519:
    inc l
    dec [hl]
    inc c
    dec d
    ld c, [hl]
    ld h, d
    pop de
    add hl, sp
    ld de, $4a5c
    ld h, c
    ret nc

jr_009_6526:
    xor h
    inc l

jr_009_6528:
    ld [hl], h
    ld sp, $2730
    dec hl
    ld a, [hl-]

jr_009_652e:
    ld c, h
    jp hl


    ld a, [bc]
    ld d, e
    jr @+$4a

    or d
    ld d, l
    ld d, b
    ld hl, $e6ac
    ret c

    inc h
    and e
    ld a, [bc]
    rst $10
    jr jr_009_6572

    db $10
    ld hl, $5d93
    call nz, Call_000_12a6
    ld c, [hl]
    add hl, bc
    add d
    and b
    add e
    ld h, $56
    add h
    db $fd
    adc e
    pop bc
    ld [hl], d
    ld e, $65
    add h
    ld a, [bc]
    add l
    add sp, $2a
    jp c, $9de9

    ld b, h
    ld d, d
    ld sp, hl
    ld d, l
    rra
    ld c, $77
    or l
    ld e, a
    push af
    add hl, sp
    dec d
    ld d, d
    ld e, a
    ld c, e
    ld d, d
    sbc $88
    ld l, [hl]
    ld c, l

jr_009_6572:
    ld d, a
    ld a, [$daab]
    dec d
    ld h, $ad
    ld e, e
    adc h
    call nc, Call_009_7ec1
    adc h
    db $eb
    sbc b
    ld [de], a
    dec l
    ld a, [bc]
    ld e, h
    or [hl]
    ld b, c
    dec l
    ld a, d
    jr c, jr_009_652e

    ld h, $52
    ld d, l
    ld l, b
    sub h
    rla
    add sp, -$1a
    add l
    add hl, hl
    ld b, c
    ld d, $48
    adc b
    sub c
    and e
    or e
    ld sp, $6886
    and l
    ld hl, $133b
    dec d
    inc d
    db $10
    or [hl]
    inc b
    ld h, b
    ld c, h
    push de

jr_009_65ab:
    ld c, l
    ld a, [de]
    jr c, jr_009_65cb

    ld [hl+], a
    inc d
    jr @+$80

    or d
    ld d, l
    add a
    adc e
    ld [$0a93], a
    add hl, bc
    ld h, l
    and h
    ld h, c
    ld l, c
    ld a, [bc]
    ld l, c
    ld c, c
    ld d, b
    adc l
    ld d, h
    sbc d

jr_009_65c6:
    ld a, [bc]
    jr @-$6a

    ld h, d
    sbc a

jr_009_65cb:
    add c
    ld [hl+], a
    sub d
    inc h
    db $e3
    ld d, b
    cp l
    add a
    push de
    cp $a1
    cp h
    ld [de], a
    sbc c
    ld d, d
    xor b
    or l
    dec h
    ld d, d
    ld e, d
    xor d
    add hl, hl
    ld a, b
    ld h, b
    adc d
    sub e
    ld a, [bc]
    ld a, [de]
    ld [hl-], a
    xor a
    and e
    ld c, a
    sub h
    dec de
    inc b
    sub $05
    add hl, bc
    dec sp
    inc l
    inc de
    ld e, c
    ld h, $86
    dec sp
    call nc, $143f
    add $43
    and b
    add c
    ld hl, $554e
    ld hl, sp+$55
    and e
    ld c, b
    jr nz, jr_009_65ab

    xor a
    push af
    ld d, a
    and l
    ld c, d
    sub e
    inc d
    ld sp, $7a4e
    sub h
    ld [hl], c
    ret nc

    ld b, l
    add l
    ld b, $a4
    ld h, b

jr_009_661a:
    ld d, b
    adc [hl]
    ret z

    add hl, de
    ld d, b
    and c
    ld e, [hl]

Jump_009_6621:
    ld e, l
    ld c, e
    ld c, [hl]
    jp z, $ecc8

    ld a, [de]
    pop af
    ld b, c
    dec h
    inc a
    dec d
    jp nz, $291a

    jr jr_009_65c6

    ldh a, [$ed]
    inc d
    sbc l
    inc b
    ld a, [hl+]
    ld b, [hl]
    add l
    dec sp
    call nc, $d852
    ld h, l
    adc c
    adc a
    dec b
    ld d, l
    ld l, c
    ld d, b
    sub c
    ld l, d
    ld h, $8f
    ld [bc], a
    and e
    ld a, [bc]
    ld [hl], h
    sub h
    add l
    inc a
    ld [$a5a5], a
    dec a
    ld e, d
    adc e
    db $db
    db $e3
    sbc h
    ret


    and d
    ld [hl], c
    push de
    pop de
    jp Jump_000_3e0c


    ld c, d
    or c
    push bc
    ld c, $9a
    and l
    ld b, [hl]
    ld a, [hl]
    add h
    and l
    ld l, d
    jr jr_009_661a

    ld e, d
    sub [hl]
    adc d
    ld [hl], c
    inc [hl]
    ld sp, $5568
    cp l
    rla
    inc de
    add h
    ld h, [hl]
    xor d
    xor c
    dec [hl]
    ld h, $08
    or e
    ret c

    ld b, h
    ld e, b
    inc [hl]
    sbc b
    xor l
    ld b, [hl]
    inc d
    or b
    add hl, hl
    and a
    add sp, -$5c
    dec h
    jp z, Jump_000_1cad

    sub c

Jump_009_6693:
    add d
    jr nc, jr_009_66b7

    ld [bc], a
    pop hl
    ld b, c
    dec e
    adc d
    sbc c
    cp d
    dec bc
    ld b, b
    add a
    ld sp, $d1d4
    ld d, $63
    inc hl
    and a
    ld a, [bc]
    xor c
    or h
    ld h, d
    sub [hl]
    jp nz, Jump_000_1885

    xor b
    ld d, l
    ld [hl], h
    inc d
    sbc c
    ld b, b
    or l
    inc hl

jr_009_66b7:
    ld d, $cc
    ld c, d
    xor b
    ld d, d
    ld sp, $320a
    ld l, b
    push bc
    and d
    sub a
    sub b
    push bc
    ld b, [hl]
    ld l, $61
    daa
    ld a, [de]
    ld e, l
    ld d, c
    cp e
    ld h, l
    ret z

    and [hl]
    ld de, $7584
    pop de
    inc [hl]
    adc h
    add d
    ld e, l
    ld e, $1a
    dec c
    inc l
    ld c, l
    ld a, d
    ld c, h
    sbc [hl]
    ld a, [bc]
    jr z, @+$67

    call nz, $36d1
    sbc l
    ld l, b
    call nz, $c220
    cp h
    ld d, l
    inc d
    and h
    daa
    inc [hl]
    inc [hl]
    and e
    bit 0, l
    cpl
    ld d, $a1
    ld b, a
    ld l, e
    ld a, [bc]
    ld [de], a
    xor l
    ld sp, $779a
    ret


    ld [de], a
    dec l
    ld b, [hl]
    ld l, c
    ldh [$fd], a
    ld b, e
    and [hl]
    adc b
    daa
    adc l
    dec bc
    ld a, [de]
    ld sp, $e119
    ld b, d
    xor h
    ld l, c
    ld e, $23
    or h
    jr nc, jr_009_6763

    ld h, l
    ld hl, $049e
    ld l, c
    ld b, b
    xor c
    ld [$52c4], a
    rst $20
    or c
    ld d, $44
    cp d
    call nc, $fcee
    ld [$e87f], a
    ld [$58a9], a
    and a
    rst $10
    db $fd
    ld d, d
    sub l
    call z, $e8e5
    ld d, [hl]
    xor a
    cp $bf
    ld [hl-], a
    xor b
    sbc b
    ld h, d
    ld a, [de]
    ld b, e
    cp h
    jp z, $aa8a

    ld hl, $8e14
    ld d, b
    ld c, [hl]
    ld c, $86
    add c
    and h
    ld h, b
    adc d
    xor d
    sub d

jr_009_6754:
    xor b
    add hl, sp
    ld d, l
    ld b, [hl]
    ld [hl], d
    xor e
    ld e, l
    ld c, b
    ld b, d
    ld [$ffff], a
    and d
    ld d, a
    rra

jr_009_6763:
    ld [$6820], sp
    db $e3
    sbc a
    sub a
    ld [$ea54], sp
    cp l
    and e
    db $e4
    rst $30
    cp c
    sbc l
    ld a, c
    ld a, [bc]
    ld [hl], l
    and c
    and $2a
    add hl, sp
    ld c, c
    add d
    ldh [$84], a
    sub l
    jp nc, Jump_000_2fd5

    sub c
    xor c
    rra
    and [hl]
    add hl, sp
    sub l
    ld d, h
    ld d, h
    ld e, $60
    rst $20
    inc [hl]
    add hl, de
    ld a, h
    ld [hl], h
    ld b, [hl]
    ld e, $66
    xor d
    adc d
    xor d
    sub a
    ld a, d
    ld h, e
    ld de, $1185
    sbc b
    call nz, Call_000_3052
    ld b, a
    dec l
    ld b, h
    ld l, b
    ld d, c
    db $dd
    ld b, a
    jp z, Jump_009_7780

    cp [hl]
    ld [hl], c
    add hl, hl
    ld d, e
    sbc l
    xor [hl]
    sub e
    scf
    push af
    ld a, [$eb05]
    and h
    ldh [$57], a
    ld a, [de]
    rrca
    add c
    jp nc, $8668

    rlca
    ld a, e
    sbc b

jr_009_67c2:
    sbc b
    pop de
    ld sp, hl
    ld [$9884], sp
    cp d
    jr nc, jr_009_6754

    xor c
    ld a, [hl+]
    ld e, a
    and d
    ld l, b
    cp h
    adc e
    ld h, $83
    adc l
    ld e, a
    pop hl
    ld e, e
    and c
    adc b
    ld a, [hl]
    daa
    ld c, b
    and d
    ld hl, $d1a8
    and d
    ld sp, $35a8
    ld a, [c]
    ld l, $22
    add hl, de
    add [hl]
    ld c, h
    inc de
    ld l, $14
    ld d, e
    ld [$2185], sp
    ld b, [hl]
    dec e
    ld b, d
    ld hl, $cc2a
    sbc h
    adc d
    inc sp
    ld hl, sp-$71
    ld hl, $210f
    ld hl, $5230
    di
    dec [hl]
    dec h
    adc l
    di
    ld [$69a8], sp
    dec h
    dec l
    and c
    and b
    call nc, Call_009_58bb
    adc b
    ld h, h
    ld h, d
    db $76
    ld a, [hl+]
    jr nc, jr_009_6871

    and [hl]
    ld h, $2d
    jr nc, jr_009_67c2

    ld de, $1452
    and h
    adc b
    adc e
    ld b, $c1

Call_009_6826:
    ld e, $f4
    pop bc
    rla
    ld h, d
    dec h
    jp nz, $f131

    ld h, d
    ld h, b
    ld b, d
    inc b
    add a
    and e
    dec bc
    cp $30
    ld h, l
    ldh [$8b], a
    and d
    or [hl]
    add hl, de
    dec l
    ld [hl], h
    or l
    adc h
    ret nc

    ld e, d
    ld a, [hl-]
    xor b
    ld [hl], d
    call nc, $c988
    ld hl, $633b
    scf
    and e
    ld a, [bc]
    db $e3
    cp e

jr_009_6852:
    dec b
    ld a, [hl+]
    ld hl, sp+$14
    add [hl]
    dec b
    push af
    inc b
    push de
    ld l, d
    and h
    or a
    adc h
    db $fd
    ld a, [hl]
    ld d, h
    adc d
    di
    ld h, $85
    ld b, c
    inc d
    ld d, l
    ld c, l
    or [hl]
    ld h, $31
    adc h
    sub [hl]
    or b
    add d

jr_009_6871:
    ld b, e
    ld c, b
    and e
    ld b, l
    ld a, [hl-]
    ld h, e
    daa
    adc c
    ld b, c
    db $d3
    ld a, [bc]
    scf
    ld e, b
    push de
    ld l, d
    adc e

Jump_009_6881:
    ld c, b
    call z, $cc3d
    sbc d
    adc h
    ld d, l
    ld b, $8d
    ld [de], a
    ld [hl], e
    add hl, de
    ld h, e
    ld a, [de]
    xor d
    ld d, h
    ld [hl], c
    and d
    ld de, $5852
    sbc b
    jp nc, $54a0

    and l
    ld d, l
    ld a, [bc]
    and b
    ret z

    ld b, [hl]
    add hl, bc
    rlca
    dec hl
    cp b
    jp nc, $ffea

    ld [$f5ab], a
    dec bc
    ld a, d
    push hl
    ld a, b
    ld a, [hl+]
    xor d
    inc a
    jr @-$66

    cp b
    sbc $7d
    db $db
    dec sp
    ld a, [de]
    add $11
    ld a, [bc]
    ld a, [de]
    ld [hl], d
    ld sp, $4018
    and b
    and h
    push bc
    or c
    ld [$29d4], sp
    or h
    rla
    jr nz, jr_009_6852

    ld c, h
    ld de, $0a31
    ld d, l
    ld a, a
    and e
    ld [hl], c
    ld [hl], c
    adc [hl]
    dec de
    dec b
    sub e
    adc h
    ld a, [bc]
    ld sp, $fc35
    ld a, [hl+]
    add d
    rst $38
    and l
    call nz, Call_009_60e1
    add l
    adc a
    ld c, $1f
    sbc b
    inc a
    ld b, e
    db $fc
    dec hl
    or $95
    rrca
    add h
    jr @+$23

    ld h, c
    sub c
    rst $38
    and h

Call_009_68f8:
    ld l, $82
    rra
    db $fc
    rrca
    ret nc

    ld sp, hl
    add a
    sub e
    db $e4
    db $e4
    rst $38
    db $fc
    rla
    db $f4
    ld b, a
    pop af
    ld l, e
    rla

Jump_009_690b:
    ld a, a
    or d
    ld a, [c]
    ld b, [hl]
    ld b, e
    rst $38
    jp hl


    dec de
    ld a, [hl]
    ld sp, $3c0a
    ld h, l
    cp $18
    jr c, jr_009_6994

    cp b
    ccf
    ldh a, [$da]
    ei
    ld h, [hl]
    ccf
    sbc d
    db $d3
    ld de, $a16d
    inc b
    dec c
    add e
    adc l
    cp $60
    cp a
    ccf
    ld [bc], a
    ld h, b
    ldh [$e4], a
    ld e, a
    ld a, d
    ld l, $c1
    adc e
    cp $0c
    ld b, e
    rst $10
    add a
    pop af
    sub h
    inc e
    ld e, [hl]
    ret z

    cpl
    pop hl
    add e
    ld e, a
    add hl, sp
    ld l, $0f
    adc h
    ld l, a

jr_009_694c:
    jr jr_009_694c

    pop bc
    ld h, c
    rst $10
    adc e
    call nz, $467c
    ld [hl], d
    ld a, c
    ld a, a
    ld a, [$b830]
    pop af
    jp nz, Jump_000_26d8

    ld e, [hl]
    ld h, c
    db $fd
    sub a
    pop hl
    db $10
    ld sp, hl
    ld l, c
    jr nc, jr_009_69aa

    and $3c
    ld sp, $993f
    ld h, h
    cp a
    ld [de], a
    cp h
    ld c, h
    dec d
    pop af
    ld d, c
    ld d, b
    or b
    ld [hl], d
    ld a, [c]
    and e
    adc e
    db $fc
    dec bc
    ld b, h
    ld c, c
    ld de, $0dd1
    ld a, [$bc87]
    dec de
    ret nz

    rst $38
    add sp, $69
    db $dd
    rst $38
    pop hl
    jp $d3ff


    pop bc
    rst $38
    inc de

jr_009_6994:
    sbc e
    ld b, [hl]
    cpl
    rst $38
    ld a, [$c42f]
    inc a
    ld b, h
    ld c, d
    pop af
    add $ff
    rst $38
    rst $38
    ld a, [$d1c4]
    add e
    rst $38
    ld [hl+], a
    sbc e

jr_009_69aa:
    rst $18
    cp $ad
    ld e, a
    pop af
    sub d
    rst $38
    rst $38
    dec b
    add d
    ld l, c
    inc de
    ld a, a
    rst $38
    ld a, [$83a9]
    rst $38
    rst $38
    ld b, c
    and e
    jp hl


    or d

jr_009_69c1:
    ld [$92d4], sp
    push de
    sub h
    pop bc
    ld d, l
    ld b, l
    ld b, c
    ld h, a
    inc e
    ld b, h
    ld e, h
    ld a, h
    or b
    ld b, h
    cp b
    rst $10
    rst $38
    call nc, $7de2
    add sp, -$46
    scf
    ld d, b
    or [hl]
    add hl, sp
    rra
    ld e, a
    or a
    adc $4f
    ld a, [de]
    pop af
    and l
    jr nc, jr_009_6a41

    jr nc, @+$44

    ld h, $22
    dec b
    inc hl
    db $fc
    call $3342
    cp l
    ld e, b
    jp nc, $e004

    ld [hl], e
    ld e, d
    ld [$ecd6], sp
    jp c, Jump_009_4a81

    ld h, l
    adc d
    ld d, e
    daa
    xor h
    ld a, [hl+]
    ld h, e
    rra
    ld a, [de]
    jr nc, jr_009_69c1

    and l
    ld a, [bc]
    ld d, l
    rrca
    ld a, c
    ld c, l
    db $dd
    ld [$ea17], sp
    db $dd
    ld c, h

Jump_009_6a15:
    sub c
    ld h, c
    ld [hl], b
    ld e, b
    cp d
    di
    ld a, [hl-]
    ld a, [hl+]
    and e
    pop de
    sbc h
    ld l, b
    ld b, h
    rst $00
    inc l
    ld a, c
    ld l, b
    ld h, $5a
    ld d, d
    ld h, [hl]
    xor $9a
    ld e, d
    ld b, [hl]
    add hl, bc
    ld c, [hl]
    jp nc, $a498

    push bc
    ldh [$be], a
    cp a
    and $2c
    ld l, c
    xor l
    ld d, l
    ld b, [hl]
    ld l, c
    sbc e
    ei
    db $fc

jr_009_6a41:
    ld [de], a
    ld h, h
    sbc b
    cp a
    rst $28
    ld [$9f39], a
    ld [bc], a
    xor a
    rst $18
    pop de
    ld a, [bc]
    ld l, l
    ret nz

    or h
    inc [hl]
    ld c, l
    dec c
    sbc c
    ld hl, sp+$21
    db $e3
    ld l, d
    db $f4
    xor c
    xor [hl]
    add hl, de
    ld d, $1d
    rla
    jp c, $1767

    ld e, c
    sbc h
    ld a, h
    jr nc, jr_009_6adf

    or l
    or h
    pop bc
    dec bc
    ld b, c
    jp nc, $c9d4

    db $d3
    adc d
    xor b
    xor d
    rst $38
    ret nc

    push af
    ld a, a
    pop af
    ld d, l
    ld a, e
    di
    adc d
    xor c
    inc d
    adc e
    ret z

    cp [hl]
    add d
    and a
    rst $28
    rst $30
    db $e3
    sub d
    and b
    and b
    ld a, l
    rrca
    push de
    dec b
    and b
    and [hl]
    ld [$a2a3], a
    and h
    ld h, l
    xor c
    rst $38
    rst $38
    or a
    ld e, a
    ld d, e
    and c
    ld e, a
    jp z, $af42

    ld l, $aa
    xor a
    db $f4
    push de

Jump_009_6aa5:
    ld d, a
    cp $a8
    ld h, d
    ld h, b
    adc h
    push de
    ld d, c
    ld hl, sp+$28
    rst $08
    rst $38
    ld d, l
    ld d, d
    inc d
    add h
    pop de
    adc b
    ld h, e

jr_009_6ab8:
    sub d
    cp a
    inc b
    adc d
    sub h
    adc c
    ld [$c164], sp
    adc c
    db $f4
    inc d
    ret


    cp $ab
    ld d, c
    ld h, b
    ld c, b
    pop hl
    ld l, a
    ld h, $92
    ld d, a
    cp $33
    cp c
    dec h
    add sp, $58
    ld e, d
    dec d
    db $eb
    push af
    ld d, a
    rst $38
    and e
    ld d, a
    add sp, -$76

jr_009_6adf:
    dec bc
    sub b
    ld b, l
    ld e, c
    inc b
    cpl
    rlca
    xor $a0
    ld d, l
    inc sp
    ld a, b
    cp d
    dec de

jr_009_6aed:
    ld e, b
    adc d
    or h
    ld a, a
    ld h, d
    rla
    sbc c
    ld e, [hl]
    db $f4
    cp e
    cp $c5
    ld b, e
    sub h
    ld d, d
    ld h, c
    and b

Jump_009_6afe:
    ld h, d
    add sp, $1a
    rst $18

jr_009_6b02:
    cp $d3
    rrca
    ld e, a
    cp e
    add l
    ld [hl+], a
    adc b
    add d
    adc b
    ld d, h
    add l
    jp nz, $f5eb

    or h
    cp d
    adc c
    and c
    ld c, b
    ld d, a
    jp nc, Jump_009_6c10

    add hl, sp
    jr nc, jr_009_6ab8

    sub d
    inc d
    ldh [rBGP], a
    adc b
    add c
    ld h, c
    ld c, h
    jr z, jr_009_6aed

    add [hl]
    ld c, l
    jp hl


    ld a, [de]
    push af
    ld h, d
    call c, $9584
    ld c, h
    db $d3
    ld h, l
    ld b, $15
    cp $50
    ld a, [hl]
    dec h
    ld h, $a8
    call $b736
    ld a, [$c9aa]
    xor d
    dec b
    ld d, d
    and e
    inc h
    push de
    ld a, [$6032]
    ld e, b
    adc d
    inc d
    pop de
    ld b, $36
    cp a
    xor a
    ret


    ld c, c
    ld a, d
    ld h, b
    and e
    ld e, h
    pop hl
    ld e, a
    and e
    or l
    inc b
    jr nz, jr_009_6b02

    dec [hl]
    ei
    ld d, a
    rst $30
    inc hl
    ld sp, $2b59
    ei
    or l
    ld a, h
    inc hl
    add hl, bc
    cp $a8
    ld e, $5f
    xor c
    ld b, a
    rst $10
    push hl
    dec h
    sub d
    ld l, l
    db $e3
    add [hl]
    sbc $8c
    ld [hl], $aa
    ld d, c
    sub $14
    add a
    cp h
    ld [c], a
    xor b
    push bc
    pop af
    ld d, b
    cp a
    rst $18
    rst $38
    rst $20
    inc b
    inc de
    or [hl]
    rst $10
    xor l
    ld h, e
    ld a, [de]
    push af
    rst $38
    sbc d
    ld a, [c]
    ld h, l
    ld a, [de]
    xor c
    sub d
    ld [hl], d
    pop hl
    sub l
    ld de, $9312
    pop hl
    db $10
    sub a
    inc e
    cp b
    inc h
    and h
    ret


    rra
    ld sp, hl
    ld [$2745], sp
    ld c, e
    and d
    adc h
    sub c
    ld d, l
    ld c, b
    jp Jump_009_7f47


    db $ed
    ld de, $97c0
    sub a
    dec e
    ld c, l
    ld l, e
    add sp, $52
    add l
    inc e
    ld e, c
    or d
    adc l
    ld b, h
    xor a
    cp $39
    sbc d
    rst $38
    ld a, [$1947]
    jp z, $ff42

    rst $38
    db $fc
    ld c, $65
    rst $38
    rst $38
    ret nc

    add hl, sp
    push bc
    ld c, d
    or a
    ld a, h
    scf
    inc bc
    sub l
    rst $38
    rst $38
    dec bc
    pop de
    call nz, $8bad
    pop bc
    ld b, d
    jp c, Jump_009_7f93

    jp nc, Jump_009_47d8

    dec de
    ld hl, $038b
    call nz, $b53e
    ld l, d
    or l
    inc b
    ld [hl], d
    cp b
    ld a, [hl]
    dec sp
    call z, $832f
    push af
    sub l
    rst $20
    ld a, [bc]
    xor a
    ld hl, sp+$7e
    ret nc

    ld a, [hl]
    rra
    ret nc

    ld [hl+], a
    ld sp, hl
    inc de
    db $10
    adc h

Jump_009_6c10:
    ld c, $6e
    db $ed

jr_009_6c13:
    add e
    ld b, c
    ld hl, sp+$78
    ld a, d
    cpl
    jr jr_009_6c13

    dec h
    ld b, b
    and [hl]
    dec [hl]
    inc de
    db $10
    rst $38
    xor l
    inc hl
    ldh a, [$a5]
    ld d, [hl]
    rra
    ld [$9c36], a
    db $10
    ccf
    ld c, b
    inc [hl]
    ld b, l
    adc e
    cp d
    ld c, [hl]
    rra
    ldh a, [rLCDC]
    ld a, [$3e70]
    inc sp
    ld a, d
    ld l, $87
    dec a
    set 3, a
    db $f4
    and c
    cp $6d
    ld c, [hl]
    ld d, l
    ld e, [hl]
    rra
    rst $08
    ei
    ld a, h
    xor b
    ccf
    rst $28
    pop af
    cp l
    ld [de], a
    and h
    and h
    ld d, l
    ld d, a
    dec a
    rst $38
    add a
    rst $08
    pop af
    jp nz, Jump_009_6184

    or l
    dec d
    db $10
    push de
    ld b, c

jr_009_6c62:
    cpl
    db $d3
    dec de
    add $0b
    push af
    sbc $2b
    rst $08
    rst $38
    add d
    xor e
    pop af
    ret


    jp $af10


    cp [hl]
    or l
    rlca
    ld a, a
    db $eb
    ld d, d
    ld [hl], c
    ld hl, $af0a
    jp $b5ff


    pop hl
    db $fc
    dec [hl]
    ld de, $6a8a
    ret nz

    add l
    ld h, h
    ld [hl], b
    or e
    ld a, a
    cp $e8
    ld a, $82
    dec [hl]
    ld e, a
    cp c
    xor h
    ld e, h
    jr z, @+$47

    ld [hl], l
    ld e, d
    rst $38
    rst $28
    db $ed
    rst $38
    rst $00
    ld e, $09
    sbc e
    rrca
    or l
    di
    rst $38
    dec b
    ld l, a
    ld e, $02
    inc a
    inc a
    ld h, e
    rst $18
    ld a, [$5178]
    jp Jump_009_4402


    nop
    ld b, h
    or c
    ld d, e
    dec h
    dec b
    ld l, d
    dec [hl]
    ld a, l
    ld hl, $a942
    ld b, $8d
    ld [$a8da], a
    ld l, [hl]
    ld [hl+], a
    scf
    and b
    adc b
    add c
    ld a, [hl]
    cp $38
    ld a, [hl+]
    ld d, $b0
    xor a
    xor h
    call $dc57
    inc h
    ldh [$7f], a
    ld a, [$62a0]
    jr jr_009_6c62

    ld [hl], b
    ld a, [c]
    ld l, a
    rst $38
    ld d, [hl]
    daa

jr_009_6ce3:
    dec bc
    ld a, [de]
    xor b
    jp c, Jump_009_48a9

    rst $18
    call nc, $8e63
    and c
    adc b
    or h
    db $e4
    and [hl]
    dec h
    and c
    sub e
    add [hl]
    and [hl]
    sub b
    ld b, l
    ld h, $4d
    xor a
    adc e
    ld [hl], b
    sub d
    inc de
    ld h, [hl]
    ld l, $e0
    sub a
    ld a, b
    xor $8f
    ld e, $76
    ld h, $d2
    ld l, c
    ld b, a
    ld [hl+], a
    ld h, d
    xor d
    xor c
    push bc
    and d
    cp l
    add d
    ld [$1c27], sp
    rrca
    ccf
    ei
    ld a, c
    jp nz, $1ff1

    rst $38
    add l
    dec de
    cpl
    db $e3
    and c
    ld c, d
    dec c
    and [hl]
    sub l
    ld e, h
    jr c, jr_009_6d7c

    ld e, a
    ld hl, sp+$67
    ld l, $ce
    or h
    ld de, $91c9
    inc c
    xor c
    ret z

    pop af
    cpl
    dec c
    jp hl


    ret nz

    push bc
    ld sp, $6f76
    add hl, de
    ret


    push af
    ld b, b
    ld d, l
    cp [hl]
    ld a, l
    ld d, h
    rla
    cp $15
    dec d
    ld c, [hl]
    ld e, d
    ld h, [hl]
    ld a, [hl+]
    add e
    xor [hl]
    add hl, sp
    ld l, c
    dec bc
    ld d, l
    ld c, d
    ret nc

    ld d, e
    adc c
    ld a, [bc]
    and l
    push de
    jr nc, jr_009_6ce3

    call nc, $f9de
    add d

jr_009_6d64:
    and d
    inc h
    adc $8d
    ld l, b
    ld e, $a3
    ld a, [hl+]
    ld c, c
    ld e, l
    ld c, l
    db $e3
    ld b, h
    dec e
    ld hl, $a388
    ld h, l
    ld d, l
    ld d, l
    ld h, b
    ld b, d
    dec h
    ld d, h

jr_009_6d7c:
    pop hl
    xor d
    xor d
    xor c
    ld [$6a12], sp
    adc [hl]
    inc d
    jp nc, $880b

    sub d
    inc d
    call $d542
    ld [hl-], a
    ld e, b
    sbc d
    add sp, -$2b
    or $41
    ld d, d
    jr jr_009_6d64

    ld c, l
    ldh [rHDMA5], a
    xor [hl]
    and e
    inc b
    ld a, $8e
    dec h
    add c
    ld [$b8a2], a
    jr z, @-$19

    ld e, c
    sub d
    sub h
    dec [hl]
    db $d3
    sub [hl]
    xor b
    dec hl
    db $fd
    ld a, [de]
    ld a, [de]
    adc a
    sub [hl]
    sbc a
    ld c, h
    xor e
    dec e
    call $44ac
    add e
    ldh [$b9], a
    rst $08
    ld a, $ab
    pop bc
    cp $d1
    call Call_009_5203
    xor c
    ld d, a
    ld [$af72], a
    db $fd
    ld d, d
    ld e, e
    add h
    ld [hl], c
    ccf
    ld b, [hl]
    db $f4
    ld [hl], b
    and c
    ld b, h
    ld a, [hl+]
    xor a
    add [hl]
    sub b
    cp $9b
    pop hl
    ld d, l
    ld d, l
    ld d, h
    ret


    ccf
    ld a, [$e19a]
    ld d, l
    ld a, a

jr_009_6de7:
    cp $ca
    ld b, a
    cp $70
    jp c, Jump_009_5098

    ld b, l
    ld d, h
    ld [hl], d
    ld e, a
    xor d
    ld c, d
    ld e, a
    sbc h
    db $ed
    ld e, a
    pop af
    ld c, d
    db $ec
    ld [hl], c
    ret nz

    cp $aa
    ld a, [hl+]
    db $fd
    inc e
    call z, Call_000_36f9
    rra
    rst $08
    sbc h
    db $f4
    ld [hl-], a
    cp c
    inc d
    ld b, h
    ld a, b
    ld de, $e0f3
    ld b, h
    or [hl]
    ld d, l
    dec d
    ld c, [hl]
    add a
    xor a
    ld a, [bc]
    jp nc, $8f13

    rst $38

jr_009_6e1e:
    ld [hl], h
    add hl, hl
    sub e
    add l
    ld [c], a
    xor $50
    adc [hl]
    dec d
    dec h
    ld d, l
    ld h, $38
    rst $38
    ld [$4ea1], a
    ld a, [hl-]
    ld sp, $1442
    pop hl
    ld d, d
    ld d, a
    ld [c], a
    inc [hl]
    ld [c], a
    ld d, [hl]
    cp h
    pop bc
    jr c, jr_009_6e1e

    xor l
    inc d
    ld d, e
    sub c
    ldh [$b5], a
    sub [hl]
    add hl, bc
    jr c, jr_009_6de7

    jp hl


    ld h, e
    ldh a, [$b9]
    add sp, -$35
    ld d, d
    ld [hl], h
    xor d
    xor b
    db $e4
    ld h, a
    inc e
    ld e, h
    inc sp
    ld h, a
    dec de
    db $fd
    ld d, h
    jr c, jr_009_6ec4

    ld a, [de]
    xor a
    ld d, h
    ld c, $19
    push bc
    ld b, h
    xor a
    rlca
    add [hl]
    ld [hl], c
    xor a
    jp nc, $86c1

    sbc h
    ld [hl], h
    scf
    adc [hl]
    ld b, [hl]
    ld [hl], d
    call nc, Call_009_752e
    ld [hl+], a
    pop af
    ld sp, hl
    ld e, b
    ld d, l
    cp [hl]
    add hl, hl
    db $d3
    cp l
    db $f4
    add l
    ld [hl], h
    db $e3
    ld d, l
    ld [hl-], a
    xor c
    ld l, l
    and e
    ld b, l
    ld e, d
    ld e, $f5
    ld d, b
    ld b, [hl]
    ld hl, $4653
    ld d, b
    and d
    and b
    ld h, h
    add l
    ld b, l
    rla
    adc l
    add sp, $5f
    adc c
    sub c
    and h
    jr jr_009_6ec2

    add hl, sp
    ld l, b
    xor [hl]
    dec d
    ld c, d
    or b
    ld b, d
    ld d, e
    ld a, [hl+]
    ld a, [de]
    xor d
    adc b
    xor b
    jr nz, @+$44

    ld l, d
    pop bc
    db $e3
    and d
    adc b
    ld b, l
    ld hl, $340a
    ld l, d
    and l
    ld h, $56
    ld [hl+], a
    ld c, $a0
    ld d, h
    push bc
    add d
    or d

jr_009_6ec2:
    ld h, h
    push bc

jr_009_6ec4:
    ld a, [de]
    ld [$8c10], sp
    ret nc

    ld d, c
    ld c, c
    add a
    ld b, l
    ld hl, $9060
    adc l
    ld [de], a
    inc [hl]
    xor c
    ld h, b
    ld c, e
    ld b, d
    dec e
    inc [hl]
    sub e
    ld d, h
    add l
    ld h, d
    ret c

    sub $94
    jp nz, $a454

    adc d
    xor b
    ldh [$a5], a

Jump_009_6ee7:
    ld l, d
    dec l
    add l
    sbc a
    and e
    or c
    add l
    add d
    and $3b
    ld a, [hl+]
    and d
    ld h, $3c
    ret


    pop af
    ld l, c
    ldh [rNR52], a
    ld a, [hl-]
    ld [hl], e
    and [hl]
    ld e, b
    ld b, b
    adc l
    sbc d
    and h
    ld b, e
    ld l, b
    ld h, l
    ld l, b
    ld l, c
    ld l, $66
    jp z, Jump_009_4742

    rst $38
    add sp, $55
    add [hl]
    pop de
    pop bc
    rst $38
    ccf
    db $eb
    ld a, d
    add hl, bc
    ld e, $6b
    ld e, d
    xor d
    rst $38
    push af
    ld a, a
    and b
    cp b
    ld h, [hl]
    sub c
    rla
    rst $38
    cp $2a
    rra
    cp d
    or l
    dec de
    ld a, [hl+]
    xor b
    ld e, a
    adc l
    dec sp
    ld a, l
    ld c, d
    and [hl]
    sbc h
    ld b, l
    ld a, d
    ld e, $bf
    db $fc
    db $10
    ld hl, $94f1
    dec [hl]
    inc de
    ld a, e
    ld a, a
    cp $18
    inc sp
    sbc d
    call nz, $fb3d
    ld a, a
    rst $38
    db $e4
    ld hl, $c1f9
    xor a
    ld a, [$ff1f]
    or l
    pop hl
    ld c, c
    ret nz

    rst $18
    db $fc
    rst $38
    cp $85
    pop hl
    push af
    sbc h
    db $10
    xor a
    pop hl
    adc h
    ld b, e
    ldh a, [rNR50]
    ld h, a
    ld a, h
    inc l
    ld l, $76
    and h
    ld [hl], c
    inc e
    ld a, h
    and b
    ld b, h
    cp l
    add h
    ld [$aa5a], a
    db $e4
    db $e4
    ld [hl], d
    sub h
    ld h, h
    ld [c], a
    ld a, e
    ld d, [hl]
    ldh [$5d], a
    ld a, [hl-]
    xor e
    rst $38

jr_009_6f81:
    add hl, sp
    sub l
    ld hl, sp+$20
    adc [hl]
    ld b, [hl]
    adc b
    xor l
    add hl, sp
    and c

Call_009_6f8b:
    bit 4, e
    sbc d
    ld c, h
    db $10
    ld c, [hl]
    ld a, d
    ld b, c
    ld e, a
    ld d, e
    and e
    rst $38
    cp $4e
    adc e
    rst $38
    and e

jr_009_6f9c:
    jp hl


    and a
    ret


    xor d
    ld b, d
    and a
    ld c, a
    ld b, c
    add a
    rst $20
    ld [de], a
    ld e, e
    rst $08
    ld sp, hl
    ret


    rst $38
    rst $38
    rst $38
    sbc h
    xor d
    or $df
    rst $20
    dec de
    db $10
    and e
    or a
    sbc h
    rst $38
    db $e3
    ld a, $73
    rst $18
    ld [bc], a
    rra
    dec e
    xor $74
    ret nz

    cp l
    sbc l
    ld d, c
    ld de, $00f5
    ld [hl], a
    cp a
    jr nz, jr_009_6f9c

    dec c
    inc a
    adc h
    jp z, Jump_009_540c

    ld [hl], c
    rst $08
    add hl, de
    dec e
    dec bc
    ld d, h
    adc e
    dec b
    ld b, c
    inc hl
    dec sp
    ld [hl], b
    jp Jump_009_690b


    ld h, c
    cp h
    jr nc, jr_009_7065

    add hl, sp
    ld d, d
    jp nc, $1a64

    inc c
    jp z, Jump_000_1426

    inc de
    ld c, h
    sbc b
    cp b
    ld a, h
    db $10
    sub h
    ld l, c
    jr nc, jr_009_6f81

    ld [hl], b
    ld sp, hl
    jr c, @+$55

    inc l
    adc l
    ld b, e
    ld [hl+], a
    sub c
    pop bc
    ld [hl+], a
    and b
    add e
    inc c
    sbc $31
    xor a
    add hl, bc
    call z, Call_009_4c69
    and c
    ld b, c
    ld [hl], e
    adc l
    ld e, $93
    sbc e
    ld [hl], b
    ldh [$a3], a
    add a
    ld a, [de]
    sbc d
    ld e, l
    dec l
    ld l, [hl]
    ld c, e
    ld h, b
    ld h, b
    sub e
    sbc a
    add l
    reti


    ld b, l
    adc b
    adc h
    ld a, [hl]
    ld h, [hl]
    sub e
    and e
    sbc $0e
    ld [$21c1], sp
    rla
    xor b
    ld a, b
    push hl
    adc c
    ret z

    sbc b
    push bc
    inc d
    ld a, [hl-]
    rlca
    or h
    rst $20
    adc c
    or c
    adc h
    cp b
    ld l, b
    ld d, h
    jr nc, @-$5b

    ld h, h
    db $dd
    ld [hl-], a
    ld b, c
    adc b
    add d
    sbc h
    sbc h
    jp c, $3321

    add c
    jp nc, $9127

    ld [hl], h
    ld e, h
    add sp, -$74
    cp d
    ld a, [de]
    jp c, Jump_000_2ed8

    sbc h
    ld a, [c]
    jr nz, jr_009_70a4

    ld b, d
    ld c, $18

jr_009_7065:
    ld a, [c]
    ld [c], a
    ld d, b
    ld b, d
    ld [hl+], a

jr_009_706a:
    dec a
    jr z, jr_009_706a

    and a
    ld a, $2e
    ld l, d
    sub [hl]
    ret


    rst $20
    and h
    ld b, d
    add d
    inc d
    and b
    cp b
    and b
    adc [hl]
    ld [de], a
    add hl, hl
    call z, $2491
    ld [hl], b
    inc l
    ld a, [bc]
    jp z, $2210

    add [hl]
    inc c
    adc h
    ld [hl], b
    call nz, $c044
    cp $ab
    rst $30
    ld e, a
    cp d
    dec c
    inc b
    ld b, d
    add hl, hl
    xor d
    db $10
    jr z, jr_009_7108

    ld a, a
    rst $28
    rst $38
    rst $38
    cp [hl]
    db $eb
    add h
    add hl, bc
    add hl, bc

jr_009_70a4:
    sbc d
    ld b, h
    db $10
    rst $28
    rst $38
    rst $38
    cp a
    rst $38
    rst $38
    db $fd
    ld c, h
    ld [$0727], sp
    dec [hl]
    rst $38
    db $fd
    ld b, l
    rst $10
    rst $38
    rst $38
    db $fd
    jp nc, Jump_009_5a44

    ld b, d
    dec sp
    rst $18
    sbc $8a
    ld h, l
    or l
    cp a
    ei
    or d
    ld [$1821], sp
    inc sp
    ld l, e
    ld d, a
    rst $10
    ld [$8409], a
    add d
    rla
    ld a, a
    and b
    add [hl]
    add hl, hl
    ld l, c
    dec c
    cpl
    rst $38
    dec a
    db $ec
    ld b, d
    ld b, d
    jr jr_009_7122

    ld a, a
    db $fc
    add d
    and b
    sbc c
    and c
    ld d, a
    db $fd
    rst $18
    call z, Call_009_4193
    add hl, sp
    dec e
    rst $38
    cp $19
    ld [hl], b
    pop bc
    ld b, e
    rst $38
    rst $38
    ld e, e
    ld [hl-], a
    ld h, c
    add hl, sp
    rra
    rst $38
    ld a, d
    add a
    ld [bc], a
    ld c, h
    dec hl
    inc bc
    ld a, [hl]
    pop hl
    rst $38
    or b
    and c

jr_009_7108:
    ld a, [bc]
    inc c
    ld b, a
    rst $28
    xor $a6
    ld de, $2c10
    rst $30
    rst $28
    cp a

Jump_009_7114:
    or e
    jr jr_009_717b

    rst $38
    ld a, a
    ld a, [c]
    inc de
    db $10
    and c
    ld [bc], a
    jp z, $f713

    ei

jr_009_7122:
    inc b
    ld h, b
    cp c
    rra
    rst $38
    cp l
    pop af
    and d
    dec c
    ccf
    add a
    cp $09
    adc d
    di
    xor [hl]
    rst $38
    db $ec
    and c
    ld [bc], a
    ld d, h
    inc de
    pop bc
    call $e1f6
    sbc b
    cp a
    dec bc
    rst $38
    db $ed
    sub $66
    adc d
    inc [hl]
    inc de
    db $fd
    add h
    ld e, d
    rst $38
    inc bc
    ld [hl], a
    push af
    or l
    ld l, l
    add hl, de
    xor [hl]
    dec c
    ld e, l
    ldh [$ab], a
    rst $38
    cp $f6
    rst $38
    cp h
    pop hl
    ld a, [c]
    add hl, hl
    add h
    ld c, e
    ret nz

    ld a, [c]
    rla
    rst $18
    db $fd
    rst $30
    xor a
    ld [$50e1], a
    ld b, h
    dec h
    jp nz, $a0b0

    adc [hl]
    rra
    rst $38
    rst $38
    rst $30
    rst $30
    adc $f6
    db $ec
    pop de
    sub d
    ld b, l
    dec bc

jr_009_717b:
    ld [hl], b
    ld [hl], e
    ld h, c
    add a
    ei
    rst $30
    rst $38
    push af
    dec l
    ld [bc], a
    ld [de], a
    ld h, a
    ld b, e
    ld b, $34
    dec c
    add a
    ld e, b
    ld a, l
    db $76
    ld [$0c21], sp
    dec bc
    daa
    ld a, [bc]
    ld e, d
    db $10
    ld [hl+], a
    pop hl
    db $f4
    push de
    sbc $1b
    ld [bc], a
    ld c, h
    ld [hl], c
    ld b, h
    and h
    ld h, c
    ld de, $8205
    db $10
    ld b, e
    ld sp, $4750
    ld [de], a
    ld h, c
    ld a, [bc]
    ld b, h
    dec d
    ret z

    jp nz, $0c91

    db $76
    add $09
    ld de, $3182
    jp hl


    ld b, a
    ld c, b
    ld b, h
    cp l
    ld b, h
    ld d, b
    call nc, $c1e9
    ld e, a
    sub e
    sub e
    inc c
    inc d
    db $10
    add a
    add hl, sp
    ld e, e
    ldh a, [$c8]
    adc [hl]
    ld b, h
    add hl, de
    db $f4
    rst $20
    ld b, d
    ld e, l
    jp nz, $e039

    ld l, d
    db $e4
    ld [$6090], a
    sub e
    xor d
    dec b
    jp nz, $513a

    add d
    pop de
    ld b, e
    ld c, [hl]
    jr c, @+$53

    ld b, d
    ldh a, [$f3]
    sbc d
    inc c
    ld l, b
    dec hl
    ld a, [hl-]
    db $e3
    ld [c], a

Jump_009_71f4:
    and [hl]
    jp hl


    ld a, [bc]
    db $10
    ld b, b
    add d
    ld [hl], d
    ld hl, $372b
    and a
    inc d
    ld a, [bc]
    dec de
    rst $18
    ei
    sbc e
    ld b, c
    inc b
    pop hl
    rst $18
    ld l, [hl]
    ld sp, hl
    cp h
    inc de
    ccf
    db $fd
    rst $28
    ld h, $d2
    db $10
    ld a, h
    rst $38
    ret


jr_009_7216:
    ld de, $43aa
    ld e, a
    ei
    ld h, b
    add h
    ld [hl], b
    ld h, b
    add a
    dec sp
    ld a, [c]
    ld [$e826], sp
    ld hl, $ff3f
    or b
    and a
    dec d
    or e
    cp $f5
    ld b, $6f
    inc b
    ld c, $fb
    cp $b6
    ld l, l
    inc b
    db $10
    ld b, c
    cp [hl]
    sbc $f9
    pop bc
    inc c
    db $10
    ld [hl], h
    rst $28
    ld [hl], c
    rl c
    inc bc
    inc b
    ld de, $a0f0
    ld [hl], a
    cp d
    dec d
    ld a, a
    push af
    ld c, a
    dec h
    ld a, a
    cp $ff
    rst $38
    push af
    inc a
    daa
    cp d
    ld e, d
    adc c
    xor e
    rst $38
    db $d3
    cp [hl]
    sbc b
    jr jr_009_7216

    ld a, a
    rst $30
    rst $28
    ld sp, $8e53
    sub c
    rst $10
    sub a
    ld [$aa2a], a
    add hl, hl
    ld a, a
    di
    add c
    cp b
    ld d, [hl]
    add d
    jp hl


    jr c, jr_009_72d6

jr_009_7277:
    push af
    adc l
    sbc a
    xor c
    ld h, e
    cpl
    ld [hl], $7e
    ld l, d
    dec [hl]
    ld d, l
    dec d
    ld [hl-], a
    and c
    call nc, $f9cd
    add d
    adc h
    sbc a
    ld [$a307], a
    add hl, de
    dec b
    rst $38
    ld c, h
    dec d
    ld h, $8c
    rst $28
    and l
    and e
    ld h, $25
    ret


    sub l
    dec d
    ld b, c
    add d
    adc l
    rra
    dec h
    dec l
    ld l, l
    ld [$5422], sp
    ld a, [hl+]
    or l
    ld b, c
    dec d
    dec [hl]
    cp h
    ld a, [de]
    ld l, $0a
    pop hl
    add l
    ld sp, hl
    xor b
    or h
    adc a
    call nc, Call_009_41d1
    and d
    ld h, b
    ret nc

    sbc c
    ld d, b
    adc b
    add e

jr_009_72c0:
    ld a, [bc]
    jp hl


    add hl, hl
    ld [$7931], a
    sub l
    ld c, h
    jr nz, jr_009_7277

    adc e
    add c
    inc b
    ld [de], a
    xor c
    rlca
    adc h
    ld e, d
    add hl, bc
    and b

jr_009_72d4:
    ld b, l
    ld a, [hl+]

jr_009_72d6:
    adc h
    ld [c], a
    and d
    db $d3
    ld l, b
    inc [hl]

jr_009_72dc:
    jr jr_009_733e

    jp z, $2987

    ld d, [hl]
    add d
    ld c, d
    ld d, b
    and e
    ld l, d
    reti


jr_009_72e8:
    xor b
    add h
    adc b
    push bc
    adc h
    call nc, Call_009_5a63
    inc b
    jr jr_009_72c0

    dec c
    ld a, [hl+]
    ld d, h
    jr jr_009_7308

    ld l, c
    jr jr_009_72d4

    and [hl]
    dec h
    inc hl
    rst $18
    ld c, $c8
    ldh [rHDMA2], a
    and b
    ld [hl], l
    and e
    ld a, d
    push de

jr_009_7308:
    ld a, [$5998]
    call nc, Call_009_5384
    ld e, $be
    dec l
    inc sp
    xor b
    ld e, [hl]
    ld h, $ff
    add l
    ld h, $30
    ld c, h
    ld [$7835], a
    and l
    rst $38
    inc d
    and h
    rst $00
    ld c, h
    ld a, [hl+]
    adc l
    jr z, jr_009_72dc

    ld a, [bc]
    and b
    ld [hl], l
    ld e, b
    add $0a
    dec h
    and l
    ld c, h
    sbc [hl]
    dec l
    adc b
    and b
    ld b, [hl]
    and e
    jr c, jr_009_73a0

    ld d, b
    xor b
    call Call_009_7c4b
    sub l

jr_009_733e:
    add hl, hl
    adc l
    dec h
    ld a, [bc]
    ld h, b
    ld e, d
    jr nc, jr_009_72e8

    sbc e
    ret z

    ld a, b
    cpl
    ld h, b
    ld c, b
    ld a, h
    db $dd
    ld sp, $8578
    jp c, $e20b

    ld [$e00d], a
    ld d, h
    ld a, [de]
    sub l
    ld a, [bc]
    add d
    and d
    sub l
    ld a, [hl]
    adc [hl]
    ld b, [hl]
    ld l, b
    adc b
    jp nz, $f8aa

    daa
    ld b, d
    ld b, h
    ld b, h
    add hl, hl
    push hl
    ret nz

    xor e
    rst $38
    xor d
    jr nc, jr_009_7399

    adc d
    rst $38
    db $fd
    ld d, l
    ld d, a
    ld [$6f78], a
    db $fd
    ld d, $95
    ld d, h
    ld a, b
    cpl
    ldh a, [$a4]
    ld b, a
    ld a, [de]
    db $10
    add hl, hl
    ret


    pop af
    ld c, $8c
    ld [hl], d
    cpl
    inc e
    ld l, d
    sub h
    cp $9c
    adc a
    rst $20
    rra
    db $fc
    ld b, a
    rst $38
    ld a, c
    cp d

jr_009_7399:
    rrca
    ld sp, hl
    xor h
    ld a, [bc]
    xor a
    ld [de], a
    rst $38

jr_009_73a0:
    ldh [$f0], a
    ld d, h
    ld h, h
    add e
    ld sp, hl
    jp $8655


    xor a
    rst $38
    ccf
    add h
    ld b, d
    ld c, d
    jr z, jr_009_73f0

    sbc h
    dec bc
    ldh a, [rVBK]
    rst $38
    jp nc, Jump_009_53de

    rlca
    sub b
    add e
    db $fc
    ld [hl], d
    jr z, @+$81

    ld sp, hl
    ld e, [hl]
    ld b, e
    ld c, a
    add a
    xor b
    rst $38
    db $10
    add d
    ld l, d
    db $fc
    rra
    ld hl, sp+$40
    cp a
    inc l
    ccf
    ld hl, sp+$50
    rst $38
    sub c
    ld c, $66
    db $fc
    cp a
    cp $1f
    di
    db $e4
    rst $18
    add hl, hl
    rrca
    push hl
    ld sp, $3fa5
    rst $10
    ld hl, sp-$30
    ld a, b
    ld b, d
    sub c
    ld a, [hl]
    ld b, a
    db $e4
    pop hl
    and [hl]
    xor b

jr_009_73f0:
    ld c, d
    pop hl
    ld b, $43
    add [hl]
    dec e
    ld c, a
    db $fd
    rrca
    ld sp, hl
    ld [hl], $70
    ccf
    call z, $378e
    add h
    pop hl
    rst $38
    and h
    rst $38
    rst $20
    inc e
    db $fc
    inc l
    adc [hl]
    db $10
    cp a
    ld hl, sp+$54
    xor b
    ccf
    ld a, [c]
    and a
    dec d
    dec d
    ld c, $12
    rra
    rst $08
    ccf
    rst $30
    add a
    pop hl
    db $f4
    add hl, de
    sub $d3
    rlca
    ld hl, sp+$7f
    ld a, [$788c]
    ld l, l
    ld hl, $3fff
    rst $38
    cp $2a
    ld l, c
    ld h, a
    inc d
    ret nc

    ld a, a
    pop hl
    rst $18
    rst $38
    jp nz, $98be

    add $f1
    jr c, jr_009_74ae

    rra
    jp z, Jump_000_2ba3

    ld [bc], a
    rrca
    pop af
    ld c, c
    ld a, [bc]
    ld l, [hl]
    call z, $d3cc
    pop bc
    rst $38
    di
    cp a
    ld a, [$0a53]
    ld h, a
    dec bc
    inc sp
    inc b
    call z, $ff17
    set 2, a
    rst $38
    ld hl, sp+$21
    add d
    add $49
    inc l
    ret z

    ld d, e
    inc de
    rlca
    ld b, c
    ld [hl], e
    db $fc
    db $f4
    ld b, e
    ld a, a
    add $ac
    ld [hl], e
    dec a
    ld de, $5518
    rlca
    ld e, $1c
    ld [hl], h
    nop
    ld b, h
    xor l
    sub c
    ld a, l
    ld sp, $cb5f
    ld d, h
    db $10
    db $f4
    dec h
    db $fd
    ld e, a
    ld [$fbc7], sp
    add $06
    adc b
    sbc d
    add hl, hl
    adc e
    sbc d
    ld a, b
    ld [hl+], a
    call nc, Call_000_2884
    or a
    push af
    ld b, c
    adc h
    ld d, l
    adc h
    rst $28
    and l

Jump_009_749a:
    and b
    ld c, b
    sub d
    inc h
    sbc $96
    xor l
    inc d
    xor b
    db $e3
    ld c, b
    push af
    ld [$a518], sp
    ld c, l
    ld d, d
    cpl
    jr jr_009_7506

jr_009_74ae:
    jr z, @-$1d

    sbc a
    ld c, c
    ld e, d
    dec b
    ld d, h
    pop hl
    ld a, [c]
    sbc l
    ld l, d
    and e
    add d
    ld d, c
    ld a, [hl]
    sub l
    rst $38
    jr c, @-$54

    ld d, a
    db $eb
    ld d, l
    add hl, sp
    xor a
    db $fd
    xor d
    add hl, sp
    ld l, d
    inc a
    jp hl


    add d
    ld [hl], b
    ld h, $a8
    jp c, $833a

    and e
    ld [de], a
    and [hl]
    ld a, [bc]
    ld b, l
    pop af
    rla
    db $10
    and c
    cp $65
    ld l, d
    add d
    rst $38
    and b
    rst $38
    add a
    dec de
    ld e, a
    rst $38
    ei
    ld a, [hl]
    jr z, jr_009_7511

    dec d
    db $eb
    db $ec
    ccf
    ld a, [$c9ba]
    and l
    ld e, b
    and c
    ld a, a
    rst $38
    rst $38
    sbc d
    ld d, a
    db $ed
    ccf
    push af
    ld e, c
    pop bc
    dec c
    ld a, a
    ldh a, [$71]
    ret nc

    rst $38
    dec c

jr_009_7506:
    sbc l
    db $10
    ld [hl], c
    dec hl
    push de
    inc e
    ld d, b
    ld b, d
    jp nc, $e7bf

jr_009_7511:
    ld a, [hl+]
    rrca
    rst $38
    ld d, h
    ld [hl], e
    ld d, h
    ld b, h
    ld a, h
    ld c, b
    ld h, [hl]
    cp [hl]
    push bc
    push af
    inc a
    ld sp, hl
    or l
    dec [hl]
    ld d, a
    db $f4
    ld [$946f], a
    add l
    rst $38
    xor b
    add hl, de
    add hl, sp
    sub h
    xor d

Call_009_752e:
    ld e, $e8
    sub l
    cp b
    and $aa
    cp $49
    rst $28
    ld e, a
    add c
    add d
    adc [hl]
    ld b, a
    sub h
    sub l
    ld a, b
    adc [hl]
    sbc b
    rla
    ld d, e
    add l
    ld a, [hl]
    push de
    ld a, [de]
    ld h, $81
    jr @+$12

    cp h
    db $dd
    ld a, [hl]
    adc h
    ld h, b
    and b
    ld c, b
    and h
    jr c, jr_009_7566

    and e
    ld b, a
    and d
    sub h
    and h
    jr z, jr_009_75bd

    ld d, h
    jr nz, jr_009_75a7

    adc l
    dec a
    ld d, [hl]
    xor b
    add a
    dec d
    ld b, [hl]

jr_009_7566:
    sub l
    ld b, e
    ld b, d
    sub e
    ld a, c
    ld a, [hl]
    and l
    ld b, $05
    cp a
    ei
    ld [c], a
    ld l, $82
    adc [hl]
    ld a, [bc]
    push af
    ld b, c
    and c
    rst $00
    and c
    add $90
    and c
    and e
    adc [hl]
    sub d
    ld d, b
    sub l
    ld b, $96
    ld [hl+], a
    and d
    jr z, @-$19

    add c
    add d
    and c
    adc c
    ld c, c
    ld b, d
    ld c, b
    and e
    sub c
    ld c, d
    add e
    daa
    ret z

    db $fd
    add hl, bc
    ld a, [de]
    ld a, [hl-]
    ld h, b
    ld a, [c]
    rla
    ld d, a
    cp a
    ld b, d
    ld b, d
    adc [hl]
    ld a, b
    dec hl
    ret c

    cp d
    or a

jr_009_75a7:
    ld [hl], b
    sub h
    ld [c], a
    and c
    sbc b
    ld e, $38
    ld a, [hl+]
    adc [hl]
    add a
    db $e3
    ret


    cp [hl]
    adc a
    cp l
    sbc a
    ld h, [hl]
    sbc [hl]
    adc l
    xor b
    daa
    ld [de], a

jr_009_75bd:
    ld [hl], h
    ld b, c
    ld a, a
    ld a, [bc]
    ld d, h
    jr nc, @-$4f

    dec e
    db $10
    ret nc

    jp hl


    ld l, h
    dec bc
    cp $74
    add hl, hl
    add a
    xor c
    ld c, l
    cp $74
    rst $38
    adc e
    xor b
    and h
    inc a
    rst $38
    inc e
    xor c
    ld d, $34
    ld c, l
    ld [bc], a
    db $fc
    rla
    ld h, [hl]
    jp hl


    add hl, hl
    ld l, b
    ld b, d
    or [hl]
    add h
    rra
    ld a, [$bc11]
    ld b, d
    xor a
    adc a
    sub l
    cp [hl]
    cpl
    rst $38
    rst $20
    rlca
    rst $38
    rst $38
    sub c
    ld l, h
    dec bc
    pop hl
    ccf
    ld e, a
    daa
    dec d
    ld a, a
    ldh a, [$3f]
    cp $ab
    cp $a4
    ld b, a
    dec a
    ld l, l
    ld a, e
    ld hl, sp-$21
    db $fd
    ld c, c
    ld sp, $add2
    ld c, b
    ccf
    ld a, a
    ld [hl-], a
    ld [$9d40], sp
    dec e
    ld b, c
    add e
    pop bc
    db $fc
    inc c
    cp $9d
    inc c
    jr nc, jr_009_76a0

    xor h
    ret nc

    ld c, a
    rst $38
    db $ec
    ld [hl], e
    jp $ecff


    ld e, l
    ld e, a
    cp $9c
    adc c
    rra
    rst $38
    ld a, [de]
    ld b, h

jr_009_7634:
    ld [hl], h
    ld [hl], d
    pop bc
    rst $38
    rst $00
    sub a
    ld d, c
    ld sp, hl
    ld l, b
    ld b, h
    cp e
    inc de
    xor c
    ld d, l
    ld c, [hl]
    dec [hl]
    ld l, d
    rst $20
    ld c, [hl]
    ld e, d
    sub l
    ld [hl], b
    add d
    add hl, sp
    ld l, l
    inc hl
    ld a, [bc]
    and l
    ld c, [hl]
    ld c, e
    ld d, d
    di
    and d
    cp l
    ld c, b
    adc $b8
    ld a, [hl-]
    dec sp
    ld d, a
    inc d
    db $ec
    add d
    dec sp
    sub h
    adc h
    xor $9c
    db $eb
    ld d, l
    db $e3
    or d
    adc a
    adc b
    rst $18
    ld [hl+], a
    xor d
    call nc, $c9e9
    ld b, [hl]
    ld e, $c7
    inc h

jr_009_7674:
    and [hl]
    ld d, h
    ld [hl], d
    or h
    and a
    ld h, h
    ld c, l
    sbc [hl]
    dec b
    and a
    ld a, d
    ld de, $47e0
    cp a
    ld a, [bc]
    db $76
    or h
    ld a, l
    jr nc, jr_009_7700

    cp h
    dec b
    ld c, a
    ld c, l
    cp $ad
    ld a, [hl-]
    sub l
    rla
    db $fd
    ld c, d
    ld d, h
    dec d
    ld a, c
    inc b
    inc de
    sbc c
    rst $38
    ld sp, hl
    ld d, b
    xor e
    rst $18
    xor d

jr_009_76a0:
    ld a, [de]
    ld b, c
    adc [hl]
    rla
    ld c, e
    ld l, d
    add sp, $10
    adc d
    and b
    ld l, b
    ld a, a
    ldh [rOBP0], a
    ld d, e
    dec [hl]
    jr nc, jr_009_7634

    inc b
    jp c, $9f8a

    and h
    ld a, d
    db $f4
    dec d
    ld a, h
    ret


    ld e, b
    xor b
    add h
    xor b
    xor d
    jr jr_009_76ed

    cp l
    ld e, [hl]
    xor d
    ld d, h
    push bc
    ld b, $82
    inc b
    adc $25
    dec h
    inc b
    sbc b
    inc [hl]
    add h
    ld h, b
    ld c, h
    and b
    ld d, b
    ld c, d

jr_009_76d7:
    ld c, [hl]
    add l
    ld c, $8d
    ld d, d
    dec hl
    ld b, [hl]
    dec h
    dec h
    dec h
    jr c, jr_009_7736

    ld [hl], h
    add l
    ld b, d
    ld c, b
    add c
    inc d
    db $ed
    add d
    dec l
    ld l, b

jr_009_76ed:
    jr c, jr_009_7674

    adc b
    and d
    xor $f4
    sub $25
    ld c, e
    and b
    ld h, c
    adc b
    ld d, [hl]
    inc sp
    adc d
    adc e
    ld b, c
    dec d
    dec b

jr_009_7700:
    adc e
    and b
    ld c, [hl]
    dec de
    ret nc

    cp a
    ld d, h
    jr c, jr_009_76d7

    inc b
    add $f2
    ld d, $52
    rst $10
    xor c
    ld c, b
    and b
    and d
    sub b
    ld b, l
    dec h
    inc sp
    and l
    ld d, c
    xor d
    and b
    ld b, d
    ld sp, $104c
    ld d, l
    ld d, h
    add a
    ld c, l
    dec hl

jr_009_7724:
    push de
    ld l, $45
    ld d, [hl]
    inc d
    adc c
    rlca
    xor e

Jump_009_772c:
    jp c, $aa8d

    ld e, d
    cp l
    ld [$8588], sp
    ld l, [hl]
    dec h

jr_009_7736:
    adc h
    add hl, hl
    dec bc
    dec [hl]
    sub c
    and l
    ld c, $09
    ld a, [hl+]
    sbc b
    inc d
    add l
    inc sp
    add c
    ld d, e
    adc [hl]
    ld e, c
    ld h, h
    add $6a
    xor l
    ld a, [hl+]
    ld [hl+], a
    ld b, c
    ld c, l
    dec e
    ld d, $2a

jr_009_7752:
    add a
    ld d, c
    ld h, e
    add hl, de
    ld e, b
    and $65
    ret nc

    adc h
    rra
    ld [$e168], sp
    sbc d
    inc [hl]
    ld a, b
    adc [hl]
    push bc
    ld e, d
    inc d
    xor d
    ld d, c
    sub e
    dec d
    ld [$aad2], sp
    and d
    jr jr_009_7724

    ld h, l
    and d

jr_009_7772:
    add hl, hl
    adc h
    ld d, e
    and c
    dec d
    ld l, d
    add hl, sp
    ld d, d
    jr z, jr_009_7752

    rst $38
    sub $68
    rla

Jump_009_7780:
    rst $18
    ld d, d
    ld d, l
    ld e, a
    dec b
    sub l
    jr c, jr_009_7772

    cp l
    rst $38
    ld a, [$fa0a]
    xor a
    cp $a2
    ld l, c
    ld [$aae6], sp
    adc [hl]
    cp e
    adc c
    rst $18
    ld a, [hl]
    and a
    ld b, $10
    ld l, c
    jp nc, $5dfe

    push hl
    ld a, [hl+]
    ld b, d
    pop bc
    pop de
    db $d3
    ld e, e
    ld [hl+], a
    sbc c
    ld c, l
    ld d, e
    db $fc
    db $76
    ld c, h
    ld c, d
    add hl, de
    adc h
    ld b, h
    xor l
    ld e, [hl]
    call c, $28a6
    ld sp, $2a82
    db $10
    ld b, h
    ld b, l
    ld b, h
    dec [hl]

jr_009_77bf:
    db $10
    add h
    inc [hl]
    push hl
    ld [hl+], a
    and [hl]
    ld a, d
    ld [de], a
    inc d
    inc d
    adc e
    inc b
    add hl, hl
    ld de, $4e51
    or d
    adc d
    sbc d
    ld h, d
    sub a
    ld b, [hl]
    ldh a, [$a5]
    ld e, l
    call nz, Call_000_08c6
    pop de
    add l
    inc e
    sbc c
    ld sp, $4212
    ld h, h
    ret nz

    adc d
    ld d, l
    ld [de], a
    adc h
    ld b, d
    ld [hl], c
    ld c, h
    add $55
    ld [hl], c
    ld c, c
    ld c, b
    jp nz, $34c7

    ld h, l
    inc bc
    ld [bc], a
    ld a, [hl-]
    db $fc
    add hl, hl
    inc de
    jr z, jr_009_7824

    ret nz

    sub e
    ld [de], a
    sbc d
    jr nc, jr_009_7842

    add a
    ld c, a
    ld b, d
    and c
    ld a, c
    rla
    xor e
    ld [hl], c
    add d
    ld l, a
    ld c, a
    jp $1582


    ld h, c
    push af
    ld h, h
    push de
    pop af
    ld d, c
    jr nc, jr_009_77bf

    daa
    ld d, h
    add [hl]
    ld de, $160b
    xor [hl]
    ld [$d030], sp
    jr nz, jr_009_77bf

jr_009_7824:
    ld d, d
    xor d
    ld d, h
    ld b, d
    sub d
    cp h
    dec de
    dec b
    add hl, de
    ld d, c
    xor h
    ld b, l
    ld e, [hl]
    ld b, h
    ld c, d
    rst $38
    ld c, b
    call c, $c160
    ld l, $6d
    dec h
    db $e3
    ld [$b736], a
    ld c, d
    sbc b
    inc hl

jr_009_7842:
    ld b, d
    sbc h
    ld a, [de]
    xor a
    jr z, jr_009_787d

    sub $c1
    ld c, b
    add hl, hl
    ld a, [de]
    push bc
    and a
    ld a, [bc]
    adc d
    ret c

    ld b, c
    ld d, b
    ld h, e
    ld [de], a
    sub h
    and h
    cp h
    ld [hl-], a
    sbc e
    and e
    ld [bc], a
    add hl, hl
    ld [hl], h
    ld c, d
    ld c, e
    ld [bc], a
    cp a
    ld de, $6c6c
    adc e
    ld d, e
    add hl, de
    xor h
    inc de
    db $e4
    rst $08
    ld c, d
    reti


    cp d
    adc d
    add hl, sp
    dec hl
    ld d, [hl]
    ld h, e
    dec b
    ld a, [hl+]
    cp b
    and a
    ld a, [de]
    jr z, jr_009_78c8

    pop de

jr_009_787d:
    ld a, [hl+]
    push bc
    jr nc, jr_009_78ac

    ld d, d
    jr nc, jr_009_78d0

    ld l, a
    ld e, [hl]
    add d
    ld h, b
    and b
    and d
    or h

jr_009_788b:
    or b
    xor e
    ld b, d
    sbc l
    inc d
    xor d
    pop de
    ld d, h
    ld c, l
    ld d, h
    ld h, e
    inc b
    ld a, d
    pop af
    ld b, b
    ld b, h
    cp b
    ld d, l
    ld d, l
    ld d, a
    adc $37
    xor l
    xor l
    and b
    adc [hl]
    dec [hl]
    dec d
    dec b
    ld hl, $7b39

jr_009_78ab:
    sbc b

jr_009_78ac:
    ld d, [hl]
    ld [hl], $7d
    ld e, [hl]
    ld h, c
    jp Jump_009_6881


    reti


    xor c
    ld b, [hl]
    adc b
    ld h, e
    add d
    and e
    ld c, b
    xor b
    jp nc, $5289

    ld de, $4e49
    ld d, h
    add h
    and h
    rst $20
    ld h, c

jr_009_78c8:
    ld l, c
    adc l
    add sp, -$6c
    add a
    ld [hl+], a
    jr c, jr_009_7925

jr_009_78d0:
    dec b
    ld a, [hl+]
    and c
    ld c, [hl]
    ld l, $21
    add hl, bc
    ld b, d
    push de
    scf
    ld d, b
    ld e, c
    db $dd
    rst $28
    xor l
    di
    ld e, d
    jr nc, jr_009_788b

    cp d
    inc a
    ld e, l
    jp nz, $a799

    inc l
    jr c, @+$26

    ld sp, $83cf
    and b
    jp nz, $1e9d

    db $10
    inc l
    ld [hl], c
    and l
    ld b, c
    jr nc, jr_009_78ab

    or a
    add e
    dec d
    inc b
    dec c
    inc e
    ld d, c
    ld sp, $ce51
    add h
    jr z, jr_009_7927

    sbc h
    sub c
    jr z, jr_009_7933

    daa
    inc l
    ld c, h
    ld [$64c7], sp
    ld c, $43
    inc e
    ld c, c
    ld a, d
    ld d, l
    xor c
    cp h
    xor d
    jp Jump_009_53d0


    pop af
    xor [hl]
    sbc b
    dec a
    rra
    jr @+$79

    or [hl]

jr_009_7925:
    ld c, a
    dec b

jr_009_7927:
    ld d, h
    push de
    rst $38
    cp $52
    ld d, e

jr_009_792d:
    sbc c

jr_009_792e:
    ld l, d
    cp b
    pop de
    ld d, d
    ld l, d

jr_009_7933:
    cp l
    xor b
    db $e4
    xor d
    ld a, [$6b8d]
    rst $10
    call nc, $e36b
    adc l
    ld b, l
    ld l, b
    ld [c], a
    add l
    ld d, d
    xor e
    push de
    db $d3
    scf
    ld [$e3e8], a
    cp e
    ld c, h
    and [hl]
    inc [hl]
    ld d, h
    ld e, l
    adc [hl]
    adc e
    ld a, [hl]
    ld d, d
    or l
    dec h
    ld d, l
    ld b, [hl]
    dec sp
    ld a, l
    ld c, b
    and h
    sbc d
    ld a, [hl]
    xor [hl]
    inc d
    push bc
    db $e3
    sub d
    sub h
    xor d
    db $fd
    inc b
    ld e, b
    push de
    ld c, [hl]
    xor b
    ld d, $a2
    ld l, e
    adc d
    ld b, c
    ld l, a
    ret nc

    ld [hl], e
    and [hl]
    add e
    ld e, b
    add $90
    reti


    sbc l
    dec bc
    ld c, [hl]
    sbc d
    ld [hl+], a
    ld h, c
    ld a, a
    add c
    jr jr_009_79aa

    ld b, c
    add sp, $14
    rst $20
    ld d, e
    jr jr_009_79a3

    jr nc, jr_009_79ed

    and c

jr_009_798e:
    jp Jump_009_7d33


    ld [hl], h
    ret


    add hl, hl
    sbc $90
    ld h, b
    jp Jump_000_1274


Call_009_799a:
    jr nz, jr_009_792e

    and c
    ld d, b
    xor l
    push de
    ld b, l
    add sp, -$78

jr_009_79a3:
    jr nz, jr_009_792d

    rst $20
    add hl, de
    ld c, b
    ldh [$90], a

jr_009_79aa:
    ld d, d
    ld [de], a
    ld d, h
    xor d
    xor a
    ld a, a
    ld b, c
    ld d, h
    jp nz, $e309

    ld a, [de]
    jp nz, $bb04

    ld b, c
    ld c, h
    xor d
    adc b
    and d
    xor b
    jr z, @+$2a

    ld d, h
    ld d, h
    dec h
    ld c, h
    ld l, d
    xor l
    ld d, l
    dec h
    ld a, l
    and d
    ld [c], a
    sub e
    sbc e
    db $dd
    db $fd
    ld b, d
    xor b
    add h
    db $e4
    adc b
    adc b
    ld c, h
    add sp, -$78
    ld d, a
    push af
    ld a, e
    jp z, $4553

    sub d
    ld h, e
    add d
    ldh [$ab], a
    rst $38
    sub h
    ld d, $18
    sbc $21
    ld c, [hl]
    db $f4
    sbc b

jr_009_79ed:
    sub l
    ld h, $41
    add sp, $1a
    ld [hl], $7f
    ld b, c
    ld c, h
    jr nz, jr_009_798e

    ld h, $19
    ld h, $04
    db $10
    ld c, l
    add sp, $5e
    ld a, [bc]
    dec l
    inc b
    cp b
    xor c
    ld a, [hl+]
    dec b
    adc l
    xor [hl]
    adc c
    add c
    ld e, [hl]
    xor c
    ret z

    ld h, e
    ld a, [de]
    ld d, d
    db $10
    ld c, l
    ld [$9fa4], a
    ld [hl], b
    and l
    xor b
    sbc $a5
    jr c, jr_009_7a4a

    ld e, c
    ld d, l
    ld d, [hl]
    and e
    and d
    db $e3
    add d
    xor b
    pop af
    rst $20
    ret nz

    ld b, [hl]
    add hl, hl
    sub $93
    add $b2
    ld b, d
    xor c
    reti


    db $10
    or c
    jp Jump_009_6a15


    ld b, h
    ld [hl], e
    dec a
    dec e
    dec [hl]
    ld a, [$8e9c]
    ld a, [bc]
    ld [hl], e
    push bc
    ld e, a
    ld a, [$6846]
    add [hl]
    ld a, b
    ld d, a
    cp $98

jr_009_7a4a:
    and h
    ld a, [hl-]
    ld a, b
    ld [$ff4f], sp
    jp hl


    add e
    pop hl
    ld b, [hl]
    sub c
    call $fd05
    ld b, l
    cp a
    ld a, [$9d68]
    jp z, $a3ff

Call_009_7a60:
    ld e, a
    ld [de], a
    xor d
    ld a, b
    jr nc, @+$01

    ld sp, hl
    adc e
    ret nz

    add e
    ret nz

    sbc l
    ld de, $fd0a
    inc de
    ld a, d
    ld d, l
    ld hl, sp+$6d
    sbc h
    ld [$f9ff], a
    db $10
    ld [hl+], a
    ret c

    ld l, c
    scf
    add d
    ld e, h
    ld [hl], c
    rst $38
    pop bc
    ld l, b
    add hl, hl
    ld d, h
    cp $0a
    ld sp, $98c6
    cp $eb
    ld hl, sp+$56
    ld b, d
    rra
    rst $08
    and $70
    ld [$116d], a
    ld e, a
    cp $2a
    pop hl
    ld hl, sp+$7e
    ld a, [de]
    ld l, e
    ld d, a
    xor d
    ld e, d

Call_009_7aa1:
    xor e
    pop hl
    ld a, a
    pop hl
    rst $38
    add a
    or a
    or a
    sbc e
    ld h, c
    rst $38
    rst $38
    db $fc
    dec c
    ld hl, sp+$5f
    rrca
    cp $1f
    add a
    pop hl
    and $b1
    ld l, l
    rst $38
    add e
    ccf
    jr jr_009_7b1d

    rlca
    ld hl, sp+$74
    ld d, $9c
    ld c, h
    ld [$11d4], sp
    ld l, d
    and l
    call nc, Call_009_7aa1
    ld [hl], l
    ld b, [hl]
    inc l
    rla
    ld a, [$e453]
    ld b, b
    sbc [hl]
    ld d, $83
    rst $38
    sub l
    cp $c3
    ld b, a
    ld h, $29
    sbc a
    rst $38
    push hl
    rst $18
    ld a, $e3
    sbc h
    dec bc
    jp nz, $de9a

    ld l, c
    rst $38
    xor c
    jp $c910


    adc d
    db $e3
    dec de
    ret nc

    reti


    add $a8
    ld a, [$47e1]
    sub l
    call nc, $1f61
    ld l, $44
    or d
    sub d
    dec e
    ld d, l
    add hl, sp
    inc l
    ccf
    add e
    xor d
    db $f4
    dec d
    ld sp, $da41
    ld h, $b4
    ld d, l
    ld [$f432], a
    sub l
    ld a, a

jr_009_7b15:
    sbc c
    adc l
    ld d, h
    db $10
    cp [hl]
    ld b, $bd
    ld h, d

jr_009_7b1d:
    ld d, [hl]
    jr nc, @+$61

    and c
    ld h, d
    ld d, h
    xor b
    jp nc, $4137

    ld h, e
    or e
    di
    xor c
    dec e
    di
    ld [hl], h
    xor c
    jr jr_009_7b6e

    ld b, d
    ld [hl], $af
    call nc, Call_009_603f
    ld a, [hl]
    ld [$d1d6], sp
    xor d
    dec b
    ld b, [hl]
    ld h, [hl]
    ld [hl], $83
    push de
    ld b, c
    ld sp, hl
    ld a, [hl]
    and l
    ld d, e
    ld a, [de]
    ld a, [de]
    xor a
    ld e, d
    adc a
    adc [hl]
    sbc c
    daa
    add b
    call nz, Call_000_2a28
    ld [hl], e
    cpl
    ld hl, sp+$2d
    pop af
    ld a, [hl+]
    ld h, e
    inc bc
    ld a, a
    push de
    cpl
    db $10
    rst $38
    sbc b
    jr nz, jr_009_7b15

    inc a
    ld d, h
    ld b, l
    rst $38
    sbc l
    ld [$f9bf], sp
    pop de
    rst $38
    rst $38

jr_009_7b6e:
    sbc l
    rra
    rst $38
    ld sp, hl
    call Call_009_5f48
    ld a, [c]
    ld l, [hl]
    sub e
    dec a
    ld b, d
    call z, $b999
    ld [de], a
    cp $82
    ld c, h
    add $d7
    ld a, a
    ld e, l
    inc e
    ld e, h
    add hl, hl
    ld l, d
    db $76
    ld b, a
    jp z, $6600

    or l
    ld d, e
    dec h
    ld d, e
    ld d, l
    add hl, sp
    rra
    ld c, c
    ld a, [hl]
    xor d
    sbc a
    push de
    xor a
    di
    ld h, l
    ld b, l
    ld d, b
    ld d, b
    and c

jr_009_7ba1:
    ld l, d
    ld hl, $1719
    and e
    ld l, e
    rst $28
    and $ad
    ret c

    ld a, [hl+]
    ld d, c
    and h
    db $10
    sub e
    ld d, a
    ld a, [bc]
    cp [hl]
    ld [$971a], sp
    sbc d
    ld d, [hl]
    sub c
    and d
    ld d, d
    ld [de], a
    xor b
    jp nz, $c254

    sbc d
    ld e, d
    ld h, h
    add [hl]
    xor c
    add d
    ld [hl+], a
    add l
    xor d
    sub h
    jp nc, Jump_000_2994

jr_009_7bcd:
    sbc c
    dec bc
    sub e
    adc l
    ld c, b
    ld l, e
    dec b
    ld c, c
    xor c
    sbc c
    ld b, d
    adc h
    xor c
    add [hl]
    ld [hl+], a
    ld [hl], b
    add [hl]
    ld [$8910], sp
    sub b
    and l
    adc h
    ld d, d
    ld [hl], d
    ld h, d
    pop af
    add [hl]
    db $76
    ld h, $81
    sbc b

jr_009_7bed:
    jp c, $cda4

    adc b
    ld l, [hl]
    ld c, b
    ld [hl], b
    ld b, c
    ld hl, $5848
    sub l
    ld a, [de]
    or e
    ld b, h
    jr nz, jr_009_7c46

    sbc c
    add l
    ld a, b
    adc c
    cpl
    xor e
    add a
    ld sp, $859a
    and b
    ld b, a
    rst $28
    xor c
    ld [hl], d
    xor b
    ld h, h
    push de
    dec l
    ld e, b
    xor h
    ld l, d
    sbc d
    dec h
    add d
    dec h
    or e
    jr z, jr_009_7ba1

    ld b, l
    ld d, d
    jr z, jr_009_7bcd

    ld a, [hl+]
    ld d, b
    sub h
    ld hl, $824b
    inc d
    ld l, [hl]
    and d
    db $e4
    ld l, d
    ld c, c
    ld d, h
    ld e, b
    sbc c
    dec hl
    ld c, b
    xor b
    ret


    sub e
    ld e, e
    add c
    ld b, [hl]
    ld b, d
    xor e
    adc h
    ld e, b
    sbc d
    add hl, bc
    scf
    add c
    ld [$a88a], sp
    push bc
    add d
    ld hl, $04f9

jr_009_7c46:
    jp z, $9488

    dec h
    ld c, h

Call_009_7c4b:
    dec d
    and l
    add l
    sub [hl]
    jr @+$57

    adc d
    or h
    adc e
    push de
    jr nc, jr_009_7bed

    adc b

jr_009_7c58:
    ld e, a
    ld d, $ae
    inc [hl]
    cp l
    ld b, [hl]
    sub h
    ret


    ld d, $05
    ld l, e
    db $d3
    adc d
    rrca
    or l
    ld hl, $825a
    cp a
    xor e
    ret nc

    and e
    adc d
    ld hl, sp+$2a
    and e
    adc d
    ld hl, sp-$3e
    ld l, d
    sbc c
    and d
    sbc [hl]
    ld [hl+], a
    ld h, l
    ld a, [$424c]
    or c
    call nz, $e690
    rrca
    ld d, e
    ld a, [$47a1]
    ld l, $bc
    ld a, [hl+]
    xor l
    ld [bc], a
    ld c, h
    scf
    and b
    sbc h
    ld c, d
    ld e, a
    ld d, l
    ld hl, sp-$30
    jr z, jr_009_7c58

    pop hl
    ld d, $a6
    rrca
    cp $8e
    pop af
    ld c, [hl]
    inc d
    or b
    ld a, d
    ld a, $18
    pop bc

jr_009_7ca5:
    ld d, $f0
    dec [hl]
    ld hl, sp+$79
    adc l
    jr z, jr_009_7d08

    ld a, b
    cp h
    ld h, h
    cp b
    dec l
    ld l, e
    ld h, h
    ld a, c
    sub l
    ld e, [hl]
    reti


    cp a
    pop hl
    db $e4
    ld d, c
    inc e
    ld h, a
    ld a, [$982d]
    ld h, l
    cp $f9
    dec hl
    add $b4
    rrca
    dec b
    and h
    and [hl]
    inc [hl]
    xor a
    db $d3
    add $bc

jr_009_7cd0:
    ld e, $17
    or h
    ld sp, $f09d
    ccf
    adc l
    and [hl]
    jr nc, jr_009_7d19

    ld e, $a4
    ld d, d
    ld h, b
    and b
    and c
    ld hl, sp+$44
    sbc $62
    ldh a, [rHDMA1]
    ld l, $a6
    ld e, $1f
    pop hl
    ld a, [hl+]
    and h
    ld sp, hl
    ld c, a
    ld [de], a
    db $eb
    dec c
    ld b, l
    call nz, $fd73
    ld d, [hl]

jr_009_7cf8:
    adc l
    db $e3
    jp z, $dffe

    jr z, jr_009_7ca5

    cp a

jr_009_7d00:
    pop bc
    ret c

    ret c

    reti


    cpl
    call nz, $fa28

jr_009_7d08:
    ld c, h
    sub d
    and c
    db $fc
    db $e4
    ld l, d
    dec hl
    jr jr_009_7cd0

    ld [bc], a
    or [hl]
    ld l, c
    add sp, -$2a
    adc e
    rst $38
    ld [bc], a

jr_009_7d19:
    ld h, c
    di
    rst $38
    ld l, c
    and h
    ld sp, $901e
    xor b
    ld a, [hl-]
    ld b, d
    ret z

    ld d, h
    and h
    ld c, c
    add hl, hl
    and l
    rst $38
    db $fc
    rla
    db $fd
    inc c
    rla
    pop af
    add hl, bc
    db $10

Jump_009_7d33:
    ld b, [hl]
    adc [hl]
    or l
    ld b, l
    call nc, $a52a
    ld b, a
    dec h
    ld a, a
    ld [$d4bf], a
    dec d
    db $fc
    ld l, $a7
    ld c, [hl]
    dec d
    inc e
    ld d, a
    sbc [hl]
    ret z

    ld b, h
    cp b
    sbc $41
    ld e, a
    add hl, sp
    sub b
    add [hl]
    ld hl, $374e
    db $ec
    rst $00
    jr c, jr_009_7db7

    ld l, b
    ld d, [hl]
    adc [hl]
    ld b, l
    ld [$0686], sp
    add a
    ld c, [hl]
    jr z, jr_009_7cf8

    ld hl, $2354
    and d
    ld hl, $385a
    jr z, jr_009_7dc0

    dec sp
    jr c, jr_009_7d00

    ld c, e
    sub c
    db $e3
    add [hl]
    and h
    sub l
    ld b, c
    add hl, sp
    ld l, c
    ret z

    sub b
    ld b, d
    add hl, sp
    ld e, a
    call nc, $e810
    and $a8
    ld l, b
    adc d
    ld a, [hl-]
    xor l
    xor a
    ld c, [hl]
    sbc d
    inc a
    cp c
    jp z, Jump_000_2a8a

    ld [hl], e
    jp z, $d1ad

    ret


    rlca
    pop de
    db $10
    ld sp, $83c2
    ret


    ccf
    ld b, c
    inc e
    ld [$0233], sp
    adc d
    ld c, $a7
    inc d
    inc e

jr_009_7da6:
    ld hl, sp+$40
    adc l
    inc e
    add hl, bc
    dec l
    add h
    dec e
    ld c, d
    ld [hl], c
    ld h, b
    jp c, Jump_000_0e3a

    and a
    dec de
    ld b, h

jr_009_7db7:
    jp c, Jump_009_7114

    rst $10
    xor d
    and c
    jr nz, jr_009_7da6

    inc l

jr_009_7dc0:
    xor e
    inc hl
    xor c
    ret


    ld e, b
    ret c

    ld c, e
    ld b, a
    ld e, [hl]
    inc de
    rst $20
    ld c, d
    ld a, h
    ld h, b
    ld a, [$d0f0]
    bit 7, a
    ret z

    ld a, [$d117]
    dec a
    ld [$d117], a
    ret nz

    ld a, [$d118]
    dec a
    ld [$d118], a
    ret nz

    ld a, $0a
    ld [$d118], a
    ld a, [$d119]
    xor $01
    ld [$d119], a
    jp z, Jump_000_376d

    call Call_000_3ec4
    push hl
    call Call_000_2f2e
    pop hl
    push hl
    ld a, [$d09b]
    call Call_009_7e12
    ld a, [$d09b]
    ld b, a
    ld a, [$d09c]
    cp b
    pop hl
    jr z, jr_009_7e15

    ld bc, $0028
    add hl, bc

Call_009_7e12:
    push hl
    jr jr_009_7e2b

jr_009_7e15:
    ld a, $7f
    ld bc, $0014
    add hl, bc
    nop
    nop
    nop
    ld bc, $0005
    jp Jump_000_372a


    call Call_000_3ec4
    push hl
    ld a, [$cfbc]

jr_009_7e2b:
    add a
    ld hl, $7e3a
    ld e, a
    ld d, $00
    add hl, de
    ld a, [hl+]
    ld e, a
    ld d, [hl]
    pop hl
    jp Jump_000_0405


    ld [hl], b
    ld a, [hl]
    ld [hl], l
    ld a, [hl]
    ld a, d
    ld a, [hl]
    ld a, [hl]
    ld a, [hl]
    sbc e
    ld a, [hl]
    sbc a
    ld a, [hl]
    and d
    ld a, [hl]
    and l
    ld a, [hl]
    xor b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    add d
    ld a, [hl]
    add [hl]
    ld a, [hl]
    adc d
    ld a, [hl]
    adc [hl]
    ld a, [hl]
    sub d
    ld a, [hl]
    sub a
    ld a, [hl]
    xor l
    ld a, [hl]
    db $ed
    inc l
    ret


    ld h, h
    ld d, b
    db $ed
    inc l
    jp nc, $5064

    db $ed
    inc l
    jp c, $ed64

    inc l
    pop hl
    ld h, h
    db $ed
    inc l
    push af
    ld h, h
    db $ed
    inc l
    ei
    ld h, h
    db $ed
    inc l
    inc bc
    ld h, l
    db $ed
    inc l
    ld [$ed65], sp
    inc l
    ld de, $5065
    db $ed
    inc l
    ld a, [de]
    ld h, l
    db $ed
    inc l
    add sp, $64
    db $ec
    jr nc, jr_009_7f21

    db $ec
    jr c, jr_009_7f24

    db $ec
    ld b, b
    ld a, a
    db $ed
    inc l
    rst $28
    ld h, h
    ld d, b
    db $ed
    inc l
    inc hl
    ld h, l
    ld d, b
    ld hl, $7ecc
    ld a, [$d018]
    dec a
    ld c, a
    ld b, $00
    add hl, bc
    add hl, bc
    ld hl, $0587

Call_009_7ec1:
    ld de, $cd68

jr_009_7ec4:
    ld a, [hl+]
    ld [de], a
    inc de
    cp $50
    jr nz, jr_009_7ec4

    ret


    ld a, [hl+]
    ld a, a
    cpl
    ld a, a
    inc [hl]
    ld a, a
    add hl, hl
    ret nc

    add hl, sp
    ld a, a
    dec a
    ld a, a
    ld b, c
    ld a, a
    ld b, l
    ld a, a
    add hl, hl
    ret nc

    add hl, hl
    ret nc

    ld c, d
    ld a, a
    ld c, a
    ld a, a
    ld d, e
    ld a, a
    add hl, hl
    ret nc

    ld e, b
    ld a, a
    add hl, hl
    ret nc

    add hl, hl
    ret nc

    ld e, l
    ld a, a
    add hl, hl
    ret nc

    ld h, e
    ld a, a
    ld l, b
    ld a, a
    add hl, hl
    ret nc

    add hl, hl
    ret nc

    ld l, [hl]
    ld a, a
    add hl, hl
    ret nc

    ld [hl], d
    ld a, a
    ld [hl], a
    ld a, a
    ld a, e

Jump_009_7f03:
    ld a, a
    add hl, hl
    ret nc

    add e
    ld a, a
    adc b
    ld a, a
    adc [hl]
    ld a, a
    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl

jr_009_7f21:
    ret nc

    add hl, hl
    ret nc

jr_009_7f24:
    add hl, hl
    ret nc

    add hl, hl
    ret nc

    add hl, hl
    ret nc

    ret nz

    sbc $40
    xor e
    ld d, b
    pop de
    or d
    xor a
    and e
    xor e
    ld d, b
    sub l
    adc h
    add l
    and d
    xor c
    or d
    and h
    ld d, b
    dec b
    db $e3
    and [hl]
    or d
    and l
    or b
    or h
    xor c
    xor h
    and l

Jump_009_7f47:
    ld d, b
    or d
    ld d, b
    inc [hl]
    db $db
    ld a, $b3
    ld d, b
    add h
    and d
    dec bc
    ld d, b
    dec bc
    xor l
    xor h
    add a
    ld d, b
    or [hl]
    or d
    ld b, b
    xor e
    ld d, b
    or l
    ret z

    or h
    cp e
    sbc $50

jr_009_7f63:
    rlca
    and [hl]
    db $e3
    ld b, d
    ld d, b
    dec bc
    xor l
    rlca
    and l
    db $e3
    ld d, b
    or [hl]
    rst $10
    jp $8450


    db $e3
    add [hl]
    inc de
    ld d, b
    sub b
    db $e3
    sbc e
    ld d, b
    cp c
    sbc $b7
    pop hl
    or e
    or d
    sbc $50
    jr nc, jr_009_7f63

    or d
    sbc $50
    add e
    ret c

    db $e3
    sub e
    rst $28
    ld d, b
    add e
    ret c

    db $e3
    sub e
    push af

Jump_009_7f93:
    ld d, b
    ld hl, $d040
    ldh a, [$f3]
    and a
    jr z, jr_009_7f9f

    ld hl, $d045

jr_009_7f9f:
    bit 2, [hl]
    jr nz, jr_009_7fb3

    set 2, [hl]
    ld hl, $7fdb
    ld b, $0f
    call Call_000_3620
    ld hl, $7fc0
    jp Jump_000_3c79


jr_009_7fb3:
    ld c, $32
    call Call_000_3781
    ld hl, $7f4e
    ld b, $0f
    jp Jump_000_3620


    db $ed
    add hl, hl
    add d
    ld h, a
    ld c, a
    jp z, $b7d8

    rst $18
    jp $d9b2


    rst $20
    ld e, b
    add c
    ld hl, $814c
    rrca
    push bc
    di
    add c
    ld bc, $8180
    ld c, l
    dec b
    ld hl, $6185
    dec b
    add e
    inc de
    ld b, h
    adc c
    xor b
    dec bc
    inc bc
    ld c, l
    sub c
    and b
    add c
    adc b
    ld b, c
    dec b
    and c
    ld bc, $a705
    ld hl, $89a1
    or b
    inc hl
    ld bc, $0321
    ld [hl], l
    inc b
    adc c
    add l
    and l
    dec bc
    nop
