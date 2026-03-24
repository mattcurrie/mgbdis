; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $00f", ROMX[$4000], BANK[$f]

    jr jr_00f_401b

    inc e
    ld l, $2f
    ld sp, $3938
    ld b, b
    ld b, c
    ld b, d
    ld b, e
    ld c, a
    ld d, d
    ld d, h
    ld d, l
    rst $38
    jr z, jr_00f_403c

    rst $38
    ld bc, $0b0a
    inc c
    dec c
    ld c, $0f

jr_00f_401b:
    ld [de], a
    inc de
    inc d
    dec d
    ld d, $17
    ld a, [de]
    jr nz, @+$34

    inc sp
    inc [hl]
    dec [hl]
    ld [hl], $37
    ld a, [hl-]
    dec sp
    inc a
    dec a
    ld a, $3f
    rst $38
    inc bc
    rlca
    ld [$1d10], sp
    ld e, $2c
    jr nc, @+$4f

    ld d, c
    rst $38
    inc bc

jr_00f_403c:
    rlca
    ld [$1110], sp
    dec e
    ld e, $27
    jr z, @+$2b

    dec hl
    inc l
    dec l
    jr nc, @+$1d

    ld a, [hl+]
    rst $38

Call_00f_404c:
    call Call_00f_6f82
    ld a, $01
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $c405
    ld bc, $0307
    call Call_000_0374
    call Call_000_0167
    call Call_000_36ca
    call Call_00f_7149
    ld hl, $9800
    ld bc, $0400

jr_00f_406f:
    ld a, $7f
    ld [hl+], a
    dec bc
    ld a, b
    or c
    jr nz, jr_00f_406f

    ld hl, $c3a0
    ld de, $9800
    ld b, $12

jr_00f_407f:
    ld c, $14

jr_00f_4081:
    ld a, [hl+]
    ld [de], a
    inc e
    dec c
    jr nz, jr_00f_4081

    ld a, $0c
    add e
    ld e, a
    jr nc, jr_00f_408e

    inc d

jr_00f_408e:
    dec b
    jr nz, jr_00f_407f

    call Call_000_0181
    ld a, $90
    ldh [$b0], a
    ldh [rWY], a
    xor a
    ldh [$d7], a
    ldh [$af], a
    dec a
    ld [$cfb2], a
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ld b, $70
    ld c, $90
    ld a, c
    ldh [$ae], a
    call Call_000_0b31
    ld a, $e4
    ldh [rBGP], a
    ldh [rOBP0], a
    ldh [rOBP1], a

jr_00f_40bb:
    ld h, b
    ld l, $40
    call Call_00f_4111
    inc b
    inc b
    ld h, $00
    ld l, $60
    call Call_00f_4111
    call Call_00f_4100
    ld a, c
    ldh [$ae], a
    dec c
    dec c
    jr nz, jr_00f_40bb

    ld a, $01
    ldh [$ba], a
    ld a, $31
    ld [$ffe1], a
    ld hl, $c405
    ld a, $01
    call Call_000_3e9d
    xor a
    ldh [$b0], a
    ldh [rWY], a
    inc a
    ldh [$ba], a
    call Call_000_3e07
    ld b, $01
    call Call_000_3e1f
    call Call_000_0193
    ld hl, $7d87
    ld b, $16
    jp Jump_000_3620


Call_00f_4100:
    push bc
    ld hl, $c301
    ld c, $15
    ld de, $0004

jr_00f_4109:
    dec [hl]
    dec [hl]
    add hl, de
    dec c
    jr nz, jr_00f_4109

    pop bc
    ret


Call_00f_4111:
jr_00f_4111:
    ldh a, [rLY]
    cp l
    jr nz, jr_00f_4111

    ld a, h
    ldh [rSCX], a

jr_00f_4119:
    ldh a, [rLY]
    cp h
    jr z, jr_00f_4119

    ret


Call_00f_411f:
    xor a
    ld [$d035], a
    ld [$ccf5], a
    ld [$cd65], a
    inc a
    ld [$d0e2], a
    ld hl, $d824
    ld bc, $002b
    ld d, $03

jr_00f_4135:
    inc d
    ld a, [hl+]
    or [hl]
    jr nz, jr_00f_413d

    add hl, bc
    jr jr_00f_4135

jr_00f_413d:
    ld a, d
    ld [$cc3e], a
    ld a, [$d034]
    dec a
    call nz, Call_00f_49f8
    ld c, $28
    call Call_000_3781
    call Call_000_3761

jr_00f_4150:
    call Call_00f_4ba3
    ld a, d
    and a
    jp z, Jump_00f_48e3

    call Call_000_376d
    ld a, [$d037]
    and a
    jp z, Jump_00f_41cc

jr_00f_4162:
    call Call_00f_500f
    ret c

    ld a, [$cd65]
    and a
    jr z, jr_00f_4162

    ld a, [$d983]
    and a
    jr nz, jr_00f_417b

    call Call_000_376d
    ld hl, $41a9
    jp Jump_000_3c79


jr_00f_417b:
    ld hl, $7614
    ld b, $01
    call Call_000_3620
    ld a, [$cfe2]
    add a
    ld b, a
    jp c, Jump_00f_4221

    ld a, [$cce9]
    and a
    jr z, jr_00f_4195

    srl b
    srl b

jr_00f_4195:
    ld a, [$cce8]
    and a
    jr z, jr_00f_41a1

    sla b
    jr nc, jr_00f_41a1

    ld b, $ff

jr_00f_41a1:
    call Call_000_3e8c
    cp b
    jr nc, jr_00f_4150

    jr jr_00f_4221

    db $ed
    add hl, hl
    ld [hl], h
    ld l, d
    xor e
    adc h
    ld [hl], d
    ld b, c
    xor e
    ld b, e
    db $e3
    xor e
    rst $20
    ld d, c
    adc d
    sbc e
    jp hl


    ret c

    ld a, a
    inc e
    db $e3
    and [hl]
    db $dd
    ld c, a
    ld l, $de
    inc a
    ld a, a
    push bc
    add hl, hl
    rst $08
    cp h
    ret nz

    rst $20
    ld e, b

Jump_00f_41cc:
    xor a
    ld [$cf79], a

jr_00f_41d0:
    call Call_00f_4bb7
    jr nz, jr_00f_41db

    ld hl, $cf79
    inc [hl]
    jr jr_00f_41d0

jr_00f_41db:
    ld a, [$cf79]
    ld [$cc2f], a
    inc a
    ld hl, $d123
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$cf78], a
    ld [$cfc0], a
    call Call_000_376d
    ld hl, $c405
    ld a, $09
    call Call_00f_49c9
    call Call_000_3761
    ld a, [$cf79]
    ld c, a
    ld b, $01
    push bc
    ld hl, $d035
    ld a, $10
    call Call_000_3e9d
    ld hl, $ccf5
    pop bc
    ld a, $10
    call Call_000_3e9d
    call Call_00f_4cfc
    call Call_000_376d
    call Call_00f_4ded
    jr jr_00f_426d

Jump_00f_4221:
jr_00f_4221:
    call Call_000_376d
    ld a, [$d0f0]
    cp $04
    ld hl, $4248
    jr nz, jr_00f_4235

    xor a
    ld [$cf06], a
    ld hl, $425b

jr_00f_4235:
    call Call_000_3c79
    ld a, $97
    call Call_000_3788
    xor a
    ldh [$f3], a
    ld hl, $52f0
    ld b, $1e
    jp Jump_000_3620


    db $ed
    add hl, hl
    xor d
    ld l, d
    ret


    ld d, b
    ld bc, $cfc1
    nop
    jp z, $c67f

    add hl, hl
    jr nc, @-$42

    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    ret nz

    ld l, d
    ld d, b
    ld bc, $cfc1
    nop
    jp z, $c67f

    add hl, hl
    jr nc, @-$42

    ret nz

    rst $20
    ld e, b

Jump_00f_426d:
jr_00f_426d:
    call Call_00f_4ea1
    ld hl, $cffc
    ld a, [hl+]
    or [hl]
    jp z, Jump_00f_479a

    ld hl, $cfcd
    ld a, [hl+]
    or [hl]
    jp z, Jump_00f_458e

    call Call_000_3761
    xor a
    ld [$d0e2], a
    ld a, [$d040]
    and $60
    jr nz, jr_00f_42da

    ld hl, $d044
    res 3, [hl]
    ld hl, $d03f
    res 3, [hl]
    bit 4, [hl]
    jr nz, jr_00f_42da

    bit 1, [hl]
    jr nz, jr_00f_42da

    call Call_00f_500f
    ret c

    ld a, [$d055]
    and a
    ret nz

    ld a, [$cfff]
    and $27
    jr nz, jr_00f_42da

    ld a, [$d03f]
    and $21
    jr nz, jr_00f_42da

    ld a, [$d044]
    bit 5, a
    jr nz, jr_00f_42da

    ld a, [$cd65]
    and a
    jr nz, jr_00f_42da

    ld a, $01
    ld [$d059], a
    xor a
    ld [$ccdb], a
    call Call_00f_5377
    push af
    call Call_000_376d
    call Call_00f_4eb8
    pop af
    jr nz, jr_00f_426d

jr_00f_42da:
    call Call_00f_56a9
    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_431c

    ld a, [$cc3e]
    cp $0f
    jp z, Jump_00f_4221

    cp $0e
    jr z, jr_00f_431c

    sub $04
    jr c, jr_00f_431c

    cp $0e
    jr z, jr_00f_431c

    ld a, [$d03f]
    bit 5, a
    jr z, jr_00f_4311

    ld a, [$cc2e]
    ld hl, $d003
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    cp $76
    jr nz, jr_00f_4311

    ld [$ccdc], a

jr_00f_4311:
    ld hl, $6abc
    ld b, $0e
    call Call_000_3620
    jp Jump_00f_4374


jr_00f_431c:
    ld a, [$ccdc]
    cp $62
    jr nz, jr_00f_432d

    ld a, [$ccdd]
    cp $62
    jr z, jr_00f_434b

    jp Jump_00f_43b4


jr_00f_432d:
    ld a, [$ccdd]
    cp $62
    jr z, jr_00f_4374

    ld a, [$ccdc]
    cp $44
    jr nz, jr_00f_4344

    ld a, [$ccdd]
    cp $44
    jr z, jr_00f_434b

    jr jr_00f_4374

jr_00f_4344:
    ld a, [$ccdd]
    cp $44
    jr z, jr_00f_43b4

jr_00f_434b:
    ld de, $d010
    ld hl, $cfe1
    ld c, $02
    call Call_000_3ad8
    jr z, jr_00f_435c

    jr nc, jr_00f_43b4

    jr jr_00f_4374

jr_00f_435c:
    ldh a, [$aa]
    cp $02
    jr z, jr_00f_436b

    call Call_00f_718d
    cp $80
    jr c, jr_00f_43b4

    jr jr_00f_4374

jr_00f_436b:
    call Call_00f_718d
    cp $80
    jr c, jr_00f_4374

    jr jr_00f_43b4

Jump_00f_4374:
jr_00f_4374:
    ld a, $01
    ldh [$f3], a
    ld hl, $689f
    ld b, $0e
    call Call_000_3620
    jr c, jr_00f_438f

    call Call_00f_699e
    ld a, [$d055]
    and a
    ret nz

    ld a, b
    and a
    jp z, Jump_00f_479a

jr_00f_438f:
    call Call_00f_43f4
    jp z, Jump_00f_458e

    call Call_00f_4eb8
    call Call_00f_578f
    ld a, [$d055]
    and a
    ret nz

    ld a, b
    and a
    jp z, Jump_00f_458e

    call Call_00f_43f4
    jp z, Jump_00f_479a

    call Call_00f_4eb8
    call Call_00f_4578
    jp Jump_00f_426d


Jump_00f_43b4:
jr_00f_43b4:
    call Call_00f_578f
    ld a, [$d055]
    and a
    ret nz

    ld a, b
    and a
    jp z, Jump_00f_458e

    call Call_00f_43f4
    jp z, Jump_00f_479a

    call Call_00f_4eb8
    ld a, $01
    ldh [$f3], a
    ld hl, $689f
    ld b, $0e
    call Call_000_3620
    jr c, jr_00f_43e5

    call Call_00f_699e
    ld a, [$d055]
    and a
    ret nz

    ld a, b
    and a
    jp z, Jump_00f_479a

jr_00f_43e5:
    call Call_00f_43f4
    jp z, Jump_00f_458e

    call Call_00f_4eb8
    call Call_00f_4578
    jp Jump_00f_426d


Call_00f_43f4:
    ld hl, $cffc
    ld de, $cfff
    ldh a, [$f3]
    and a
    jr z, jr_00f_4405

    ld hl, $cfcd
    ld de, $cfd0

jr_00f_4405:
    ld a, [de]
    and $18
    jr z, jr_00f_4426

    push hl
    ld hl, $4465
    ld a, [de]
    and $10
    jr z, jr_00f_4416

    ld hl, $447a

jr_00f_4416:
    call Call_000_3c79
    xor a
    ld [$cc5b], a
    ld a, $ba
    call Call_00f_71f9
    pop hl
    call Call_00f_44a6

jr_00f_4426:
    ld de, $d040
    ldh a, [$f3]
    and a
    jr z, jr_00f_4431

    ld de, $d045

jr_00f_4431:
    ld a, [de]
    add a
    jr nc, jr_00f_4458

    push hl
    ldh a, [$f3]
    push af
    xor $01
    ldh [$f3], a
    xor a
    ld [$cc5b], a
    ld a, $47
    call Call_00f_71f9
    pop af
    ldh [$f3], a
    pop hl
    call Call_00f_44a6
    call Call_00f_450c
    push hl
    ld hl, $4490
    call Call_000_3c79
    pop hl

jr_00f_4458:
    ld a, [hl+]
    or [hl]
    ret nz

    call Call_00f_4eb8
    ld c, $14
    call Call_000_3781
    xor a
    ret


    db $ed
    inc l
    ld b, b
    ld [hl], e
    inc [hl]
    cp b
    ret


    ld a, a
    rrca
    and b
    db $e3
    dec bc
    db $dd
    ld a, a
    or e
    cp c
    jp $d9b2


    rst $20
    ld e, b
    db $ed
    add hl, hl
    db $e3
    ld l, d
    call nc, Call_000_34b9
    ret


    ld a, a
    rrca
    and b
    db $e3
    dec bc
    db $dd
    ld a, a
    or e
    cp c
    jp $d9b2


    rst $20
    ld e, b
    db $ed
    add hl, hl
    db $f4
    ld l, d
    daa
    ld h, $7f
    ld e, d
    ret


    ld c, a
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    db $dd
    ld a, a
    or e
    ld a, [hl-]
    or e
    rst $20
    ld e, b

Call_00f_44a6:
    push hl
    push hl
    ld bc, $000e
    add hl, bc
    ld a, [hl+]
    ld [$cee5], a
    ld b, a
    ld a, [hl]
    ld [$cee4], a
    ld c, a
    srl b
    rr c
    srl b
    rr c
    srl c
    srl c
    ld a, c
    and a
    jr nz, jr_00f_44c7

    inc c

jr_00f_44c7:
    ld hl, $d041
    ld de, $d049
    ldh a, [$f3]
    and a
    jr z, jr_00f_44d8

    ld hl, $d046
    ld de, $d04e

jr_00f_44d8:
    bit 0, [hl]
    jr z, jr_00f_44e8

    ld a, [de]
    inc a
    ld [de], a

Call_00f_44df:
    ld hl, $0000

jr_00f_44e2:
    add hl, bc
    dec a
    jr nz, jr_00f_44e2

    ld b, h
    ld c, l

jr_00f_44e8:
    pop hl
    inc hl
    ld a, [hl]
    ld [$cee6], a
    sub c
    ld [hl-], a
    ld [$cee8], a
    ld a, [hl]
    ld [$cee7], a
    sbc b
    ld [hl], a
    ld [$cee9], a
    jr nc, jr_00f_4507

    xor a
    ld [hl+], a
    ld [hl], a
    ld [$cee8], a
    ld [$cee9], a

jr_00f_4507:
    call Call_00f_455f
    pop hl
    ret


Call_00f_450c:
    push hl
    ld hl, $cfdb
    ldh a, [$f3]
    and a
    jr z, jr_00f_4518

    ld hl, $d00a

jr_00f_4518:
    ld a, [hl+]
    ld [$cee5], a
    ld a, [hl]
    ld [$cee4], a
    ld de, $fff2
    add hl, de
    ld a, [hl]
    ld [$cee6], a
    add c
    ld [hl-], a
    ld [$cee8], a
    ld a, [hl]
    ld [$cee7], a
    adc b
    ld [hl+], a
    ld [$cee9], a
    ld a, [$cee4]
    ld c, a
    ld a, [hl-]
    sub c
    ld a, [$cee5]
    ld b, a
    ld a, [hl]
    sbc b
    jr c, jr_00f_454e

    ld a, b
    ld [hl+], a
    ld [$cee9], a
    ld a, c
    ld [hl], a
    ld [$cee8], a

jr_00f_454e:
    ldh a, [$f3]
    xor $01
    ldh [$f3], a
    call Call_00f_455f
    ldh a, [$f3]
    xor $01
    ldh [$f3], a
    pop hl
    ret


Call_00f_455f:
    ld hl, $c45e
    ldh a, [$f3]
    and a
    ld a, $01
    jr z, jr_00f_456d

    ld hl, $c3ca
    xor a

jr_00f_456d:
    push bc
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d
    pop bc
    ret


Call_00f_4578:
    ld a, [$d047]
    and a
    jr nz, jr_00f_4583

    ld hl, $d03f
    res 5, [hl]

jr_00f_4583:
    ld a, [$d04c]
    and a
    ret nz

    ld hl, $d044
    res 5, [hl]
    ret


Jump_00f_458e:
    xor a
    ld [$ccf0], a
    call Call_00f_45d0
    call Call_00f_4ba3
    ld a, d
    and a
    jp z, Jump_00f_48e3

    ld hl, $cffc
    ld a, [hl+]
    or [hl]
    call nz, Call_00f_4ebe
    ld a, [$d034]
    dec a
    ret z

    call Call_00f_46c5
    jp z, Jump_00f_470c

    ld hl, $cffc
    ld a, [hl+]
    or [hl]
    jr nz, jr_00f_45be

    call Call_00f_483c
    ret c

    call Call_00f_4883

jr_00f_45be:
    ld a, $01
    ld [$cd65], a
    call Call_00f_46da
    jp z, Jump_00f_4221

    xor a
    ld [$cd65], a
    jp Jump_00f_426d


Call_00f_45d0:
    call Call_00f_4ea1
    ld a, [$d034]
    dec a
    jr z, jr_00f_45e8

    ld a, [$cfcf]
    ld hl, $d824
    ld bc, $002c
    call Call_000_3ad1
    xor a
    ld [hl+], a
    ld [hl], a

jr_00f_45e8:
    ld hl, $d03f
    res 2, [hl]
    xor a
    ld [$d051], a
    ld hl, $d042
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$d04f], a
    ld [$ccef], a
    ld [$ccf3], a
    ld hl, $ccf1
    ld [hl+], a
    ld [hl], a
    ld hl, $c410
    ld de, $c424
    call Call_00f_497d
    ld hl, $c3a1
    ld bc, $040a
    call Call_000_0374
    ld a, [$d034]
    dec a
    jr z, jr_00f_463c

    xor a
    ld [$c0f1], a
    ld [$c0f2], a
    ld a, $9e
    call Call_000_3788

jr_00f_462b:
    ld a, [$c02a]
    cp $9e
    jr z, jr_00f_462b

    ld a, $95
    call Call_000_0e45
    call Call_000_3790
    jr jr_00f_4644

jr_00f_463c:
    call Call_00f_46b9
    ld a, $f9
    call Call_00f_4788

jr_00f_4644:
    ld hl, $cffc
    ld a, [hl+]
    or [hl]
    jr nz, jr_00f_4654

    ld a, [$ccf0]
    and a
    jr nz, jr_00f_4654

    call Call_00f_47db

jr_00f_4654:
    call Call_00f_4ba3
    ld a, d
    and a
    ret z

    ld hl, $46a7
    call Call_000_3c79
    call Call_00f_7186
    call Call_000_3761
    xor a
    ld [$cf06], a
    ld b, $4b
    call Call_000_34dd
    push af
    jr z, jr_00f_467d

    ld hl, $cfe9
    ld b, $07

jr_00f_4677:
    srl [hl]
    inc hl
    dec b
    jr nz, jr_00f_4677

jr_00f_467d:
    xor a
    ld [$cc5b], a
    ld hl, $79d6
    ld b, $15
    call Call_000_3620
    pop af
    ret z

    ld a, $01
    ld [$cc5b], a
    ld a, [$d123]
    ld b, $00

jr_00f_4695:
    scf
    rl b
    dec a
    jr nz, jr_00f_4695

    ld a, b
    ld [$d035], a
    ld hl, $79d6
    ld b, $15
    jp Jump_000_3620


    db $ed
    add hl, hl
    ld a, [hl+]
    ld l, e
    ld a, a
    ld d, b
    ld bc, $cfc1
    nop
    jp z, $c07f

    or l
    jp c, $e7c0

    ld e, b

Call_00f_46b9:
    xor a
    ld [$d060], a
    ld [$c02a], a
    inc a
    ld [$ccf6], a
    ret


Call_00f_46c5:
    ld a, [$d81b]
    ld b, a
    xor a
    ld hl, $d824
    ld de, $002c

jr_00f_46d0:
    or [hl]
    inc hl
    or [hl]
    dec hl
    add hl, de
    dec b
    jr nz, jr_00f_46d0

    and a
    ret


Call_00f_46da:
    ld hl, $cf18
    ld e, $30
    call Call_00f_4fec
    ld hl, $6bea
    ld b, $0e
    call Call_000_3620
    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_46fd

    call Call_00f_5743
    ld a, [$cc3e]
    cp $0f
    ret z

    call Call_000_376d

jr_00f_46fd:
    call Call_00f_49f8
    xor a
    ld [$cfb3], a
    ld [$cd65], a
    ld [$ccd5], a
    inc a
    ret


Jump_00f_470c:
    call Call_00f_46b9
    ld b, $fc
    ld a, [$d039]
    and a
    jr nz, jr_00f_4719

    ld b, $f6

jr_00f_4719:
    ld a, [$d018]
    cp $2b
    jr nz, jr_00f_4727

    ld b, $fc
    ld hl, $d6b2
    set 1, [hl]

jr_00f_4727:
    ld a, [$d0f0]
    cp $04
    ld a, b
    call nz, Call_00f_4788
    ld hl, $4776
    call Call_000_3c79
    ld a, [$d0f0]
    cp $04
    ret z

    call Call_00f_7003
    ld c, $28
    call Call_000_3781
    call Call_000_33c9
    ld hl, $475a
    call Call_000_3c79
    ld de, $d2cd
    ld hl, $d058
    ld c, $03
    ld a, $0b
    jp Jump_000_3e9d


    db $ed
    add hl, hl
    ld a, b
    ld l, e
    cp h
    ld [c], a
    or e
    or a
    sbc $c4
    cp h
    jp $504f


    ld [bc], a
    ld d, [hl]
    ret nc

    jp $f000


    ld a, a
    jp $b2c6


    jp c, $e7c0

    ld e, b
    db $ed
    inc l
    push bc
    ld [hl], e
    call nz, $4fc9
    cp h
    ld [c], a
    or e
    inc a
    add $7f
    or [hl]
    rst $18
    ret nz

    rst $20
    ld e, b

Call_00f_4788:
    push af
    ld a, $ff
    ld [$c0ee], a
    call Call_000_3788
    ld c, $08
    pop af
    call Call_000_0e35
    jp Jump_000_3e07


Jump_00f_479a:
    ld a, $01
    ld [$ccf0], a
    call Call_00f_47db
    call Call_00f_4ba3
    ld a, d
    and a
    jp z, Jump_00f_48e3

    ld hl, $cfcd
    ld a, [hl+]
    or [hl]
    jr nz, jr_00f_47bf

    call Call_00f_45d0
    ld a, [$d034]
    dec a
    ret z

    call Call_00f_46c5
    jp z, Jump_00f_470c

jr_00f_47bf:
    call Call_00f_483c
    ret c

    call Call_00f_4883
    jp nz, Jump_00f_426d

    ld a, $01
    ld [$cd65], a
    call Call_00f_46da
    jp z, Jump_00f_4221

    xor a
    ld [$cd65], a
    jp Jump_00f_426d


Call_00f_47db:
    ld a, [$cc2f]
    ld c, a
    ld hl, $d035
    ld b, $00
    ld a, $10
    call Call_000_3e9d
    ld hl, $d044
    res 2, [hl]
    ld a, [$d060]
    bit 7, a
    jr z, jr_00f_47fd

    ld a, $ff
    ld [$d060], a
    call Call_000_3790

jr_00f_47fd:
    ld hl, $cd05
    ld [hl+], a
    ld [hl], a
    ld [$cfff], a
    call Call_00f_4ea1
    ld hl, $c435
    ld bc, $050b
    call Call_000_0374
    ld hl, $c469
    ld de, $c47d
    call Call_00f_497d
    ld a, $01
    ld [$cf06], a
    ld a, [$ccf0]
    and a
    ret z

    ld a, [$cffb]
    call Call_000_2dc7
    ld hl, $4830
    jp Jump_000_3c79


    db $ed
    add hl, hl
    sbc d
    ld l, e
    jp z, $c07f

    or l
    jp c, $e7c0

    ld e, b

Call_00f_483c:
    call Call_00f_7186
    call Call_000_3761
    ld a, [$d034]
    and a
    dec a
    ret nz

    ld hl, $4874
    call Call_000_3c79

jr_00f_484e:
    ld hl, $c461
    ld bc, $0a0e
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$d0f3]
    cp $02
    jr z, jr_00f_4865

    and a
    ret


jr_00f_4865:
    ld a, [$cc26]
    and a
    jr z, jr_00f_484e

    ld hl, $d153
    ld de, $cfe1
    jp Jump_00f_4be4


    db $ed
    add hl, hl
    xor h
    ld l, e
    ld a, a
    ld d, h
    db $dd
    jp nz, $b2b6

    rst $08
    cp l
    or [hl]
    and $57

Call_00f_4883:
    ld a, $02
    ld [$d05a], a
    call Call_000_2df3

jr_00f_488b:
    jr nc, jr_00f_4892

jr_00f_488d:
    call Call_000_2e08
    jr jr_00f_488b

jr_00f_4892:
    call Call_00f_4bb7
    jr z, jr_00f_488d

    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_48a6

    ld a, $01
    ld [$cd65], a
    call Call_00f_5743

jr_00f_48a6:
    xor a
    ld [$cd65], a
    call Call_000_0188
    ld a, [$cf79]
    ld [$cc2f], a
    ld c, a
    ld hl, $d035
    ld b, $01
    push bc
    ld a, $10
    call Call_000_3e9d
    pop bc
    ld hl, $ccf5
    ld a, $10
    call Call_000_3e9d
    call Call_00f_4cfc
    call Call_000_3e15
    call Call_00f_714c
    call Call_000_376d
    call Call_000_3e1d
    call Call_000_3e0c
    call Call_00f_4ded
    ld hl, $cfcd
    ld a, [hl+]
    or [hl]
    ret


Jump_00f_48e3:
    ld a, [$d0f0]
    cp $04
    jr z, jr_00f_490e

    ld a, [$d036]
    cp $e1
    jr nz, jr_00f_490e

    ld hl, $c3a0
    ld bc, $0815
    call Call_000_0374
    call Call_00f_7003
    ld c, $28
    call Call_000_3781
    ld hl, $4928
    call Call_000_3c79
    ld a, [$d2dd]
    cp $28
    ret z

jr_00f_490e:
    ld b, $00
    call Call_000_3e1f
    ld hl, $493f
    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_4920

    ld hl, $496b

jr_00f_4920:
    call Call_000_3c79
    call Call_000_03bf
    scf
    ret


    db $ed
    add hl, hl
    or a
    ld l, e
    ret c

    db $e3
    rst $20
    ld c, a
    call nc, Call_00f_44df
    ld a, a
    or l
    jp c, $c3df

    ld a, a
    jp $bbde


    or d
    and $58
    db $ed
    dec l
    xor [hl]
    ld h, a
    jp $c4d3


    add $ca
    ld c, a
    ret nz

    ret nz

    or [hl]
    or h
    reti


    ld a, a
    ld d, h
    ld h, $7f
    or d
    push bc
    or d
    rst $20
    ld d, c
    ld d, d
    jp z, $d24f

    ret


    rst $08
    or h
    ld h, $7f
    rst $08
    rst $18
    cp b
    rst $10
    add $7f
    push bc
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    rst $20
    ld l, e
    call nz, $4fc9
    cp h
    ld [c], a
    or e
    inc a
    add $7f
    rst $08
    cp c
    ret nz

    rst $20
    ld e, b

Call_00f_497d:
    ld a, [$d6af]
    push af
    set 6, a
    ld [$d6af], a
    ld b, $07

jr_00f_4988:
    push bc
    push de
    push hl
    ld b, $06

jr_00f_498d:
    push bc
    push hl
    push de
    ld bc, $0007
    call Call_000_01bb
    pop de
    pop hl
    ld bc, $ffec
    add hl, bc
    push hl
    ld h, d
    ld l, e
    add hl, bc
    ld d, h
    ld e, l
    pop hl
    pop bc
    dec b
    jr nz, jr_00f_498d

    ld bc, $0014
    add hl, bc
    ld de, $49c1
    call Call_000_0405
    ld c, $02
    call Call_000_3781
    pop hl
    pop de
    pop bc
    dec b
    jr nz, jr_00f_4988

    pop af
    ld [$d6af], a
    ret


    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, b

Call_00f_49c9:
    ldh [$8b], a
    ld c, a

jr_00f_49cc:
    push bc
    push hl
    ld b, $07

jr_00f_49d0:
    push hl
    ldh a, [$8b]
    ld c, a

jr_00f_49d4:
    ldh a, [$8b]
    cp $08
    jr z, jr_00f_49df

    ld a, [hl-]
    ld [hl+], a
    inc hl
    jr jr_00f_49e2

jr_00f_49df:
    ld a, [hl+]
    ld [hl-], a
    dec hl

jr_00f_49e2:
    dec c
    jr nz, jr_00f_49d4

    pop hl
    ld de, $0014
    add hl, de
    dec b
    jr nz, jr_00f_49d0

    ld c, $02
    call Call_000_3781
    pop hl
    pop bc
    dec c
    jr nz, jr_00f_49cc

    ret


Call_00f_49f8:
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
    call Call_000_3e9d
    xor a
    ld hl, $d042
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$d04f], a
    ld [$ccef], a
    ld [$ccf3], a
    ld hl, $ccf1
    ld [hl+], a
    ld [hl], a
    dec a
    ld [$ccdf], a
    ld hl, $d03f
    res 5, [hl]
    ld hl, $c3b2
    ld a, $08
    call Call_00f_49c9
    call Call_00f_7186
    call Call_000_3761
    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_4a53

    ld a, [$cc3e]
    sub $04
    ld [$cf79], a
    jr jr_00f_4a72

jr_00f_4a53:
    ld b, $ff

jr_00f_4a55:
    inc b
    ld a, [$cfcf]
    cp b
    jr z, jr_00f_4a55

    ld hl, $d823
    ld a, b
    ld [$cf79], a
    push bc
    ld bc, $002c
    call Call_000_3ad1
    pop bc
    inc hl
    ld a, [hl+]
    ld c, a
    ld a, [hl]
    or c
    jr z, jr_00f_4a55

jr_00f_4a72:
    ld a, [$cf79]
    ld hl, $d844
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl]
    ld [$d0ec], a
    ld a, [$cf79]
    inc a
    ld hl, $d81b
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$cfbf], a
    ld [$cf78], a
    call Call_00f_6df1
    ld hl, $cfcd
    ld a, [hl+]
    ld [$cce3], a
    ld a, [hl]
    ld [$cce4], a
    ld a, $01
    ld [$cc26], a
    ld a, [$d0e2]
    dec a
    jr z, jr_00f_4b10

    ld a, [$d123]
    dec a
    jr z, jr_00f_4b10

    ld a, [$d0f0]
    cp $04
    jr z, jr_00f_4b10

    ld a, [$d2d4]
    bit 6, a
    jr nz, jr_00f_4b10

    ld hl, $4b64
    call Call_000_3c79
    ld hl, $c42c
    ld bc, $0801
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$cc26]
    and a
    jr nz, jr_00f_4b10

    ld a, $02
    ld [$d05a], a
    call Call_000_2df3

jr_00f_4ae3:
    ld a, $01
    ld [$cc26], a
    jr c, jr_00f_4b07

    ld hl, $cc2f
    ld a, [$cf79]
    cp [hl]
    jr nz, jr_00f_4afe

    ld hl, $534b
    call Call_000_3c79

jr_00f_4af9:
    call Call_000_2e08
    jr jr_00f_4ae3

jr_00f_4afe:
    call Call_00f_4bb7
    jr z, jr_00f_4af9

    xor a
    ld [$cc26], a

jr_00f_4b07:
    call Call_000_3e15
    call Call_00f_714c
    call Call_000_376d

jr_00f_4b10:
    call Call_000_0188
    ld hl, $c3a1
    ld bc, $040a
    call Call_000_0374
    ld b, $01
    call Call_000_3e1f
    call Call_000_3e0c
    ld hl, $4b8f
    call Call_000_3c79
    ld a, [$cfbf]
    ld [$cf78], a
    ld [$d092], a
    call Call_000_2f2e
    ld de, $9000
    call Call_000_3034
    ld a, $cf
    ld [$ffe1], a
    ld hl, $c427
    ld a, $02
    call Call_000_3e9d
    ld a, [$cfbf]
    call Call_000_2dc7
    call Call_00f_4f49
    ld a, [$cc26]
    and a
    ret nz

    xor a
    ld [$d035], a
    ld [$ccf5], a
    call Call_000_3761
    jp Jump_00f_5310


    db $ed
    inc l
    ld e, d
    ld [hl], e
    jp z, Jump_00f_507f

    ld bc, $cfc1
    nop
    db $dd
    ld c, a
    cp b
    ret c

    jr nc, @-$3f

    or e
    call nz, $bc7f
    jp $d9b2


    sub $b3
    jr nc, @+$53

    ld d, d
    db $d3
    ld a, a
    ld d, h
    db $dd
    ld c, a
    call nz, $b6d8
    or h
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    inc l
    inc e
    ld [hl], e
    jp z, $504f

    ld bc, $cfc1
    nop
    db $dd
    ld a, a
    cp b
    ret c

    jr nc, @-$42

    ret nz

    rst $20
    ld d, a

Call_00f_4ba3:
    ld a, [$d123]
    ld e, a
    xor a
    ld hl, $d12c
    ld bc, $002b

jr_00f_4bae:
    or [hl]
    inc hl
    or [hl]
    add hl, bc
    dec e
    jr nz, jr_00f_4bae

    ld d, a
    ret


Call_00f_4bb7:
    ld a, [$cf79]
    ld hl, $d12c
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl+]
    or [hl]
    ret nz

    ld a, [$d0e2]
    and a
    jr nz, jr_00f_4bd2

    ld hl, $4bd4
    call Call_000_3c79

jr_00f_4bd2:
    xor a
    ret


    db $ed
    add hl, hl
    add e
    ld l, h
    or e
    ld a, a
    or a
    ret c

    ld [c], a
    cp b
    ld h, $7f
    push bc
    or d
    rst $20
    ld e, b

Call_00f_4be4:
Jump_00f_4be4:
    call Call_00f_59a0
    jp z, Jump_00f_4c87

    ld a, [$d037]
    cp $02
    jp z, Jump_00f_4c87

    ld a, [$d0f0]
    cp $04
    jp z, Jump_00f_4c87

    ld a, [$d034]
    dec a
    jr nz, jr_00f_4c77

    ld a, [$d0e5]
    inc a
    ld [$d0e5], a
    ld a, [hl+]
    ldh [$97], a
    ld a, [hl]
    ldh [$98], a
    ld a, [de]
    ldh [$8d], a
    inc de
    ld a, [de]
    ldh [$8e], a
    call Call_000_376d
    ld de, $ff97
    ld hl, $ff8d
    ld c, $02
    call Call_000_3ad8
    jr nc, jr_00f_4c87

    xor a
    ldh [$96], a
    ld a, $20
    ldh [$99], a
    call Call_000_38f5
    ldh a, [$97]
    ldh [$95], a
    ldh a, [$98]
    ldh [$96], a
    ldh a, [$8d]
    ld b, a
    ldh a, [$8e]
    srl b
    rr a
    srl b
    rr a
    and a
    jr z, jr_00f_4c87

    ldh [$99], a
    ld b, $02
    call Call_000_3902
    ldh a, [$97]
    and a
    jr nz, jr_00f_4c87

    ld a, [$d0e5]
    ld c, a

jr_00f_4c56:
    dec c
    jr z, jr_00f_4c64

    ld b, $1e
    ldh a, [$98]
    add b
    ldh [$98], a
    jr c, jr_00f_4c87

    jr jr_00f_4c56

jr_00f_4c64:
    call Call_00f_718d
    ld b, a
    ldh a, [$98]
    cp b
    jr nc, jr_00f_4c87

    ld a, $01
    ld [$cd65], a
    ld hl, $4cc2
    jr jr_00f_4c7a

jr_00f_4c77:
    ld hl, $4ccb

jr_00f_4c7a:
    call Call_000_3c79
    ld a, $01
    ld [$d0e4], a
    call Call_000_3761
    and a
    ret


Jump_00f_4c87:
jr_00f_4c87:
    ld a, [$d0f0]
    cp $04
    ld a, $02
    jr nz, jr_00f_4cac

    call Call_000_3761
    xor a
    ld [$cd65], a
    ld a, $0f
    ld [$cc2e], a
    call Call_00f_5743
    call Call_000_376d
    ld a, [$cc3e]
    cp $0f
    ld a, $02
    jr z, jr_00f_4cac

    dec a

jr_00f_4cac:
    ld [$cf06], a
    ld a, $97
    call Call_000_3788
    ld hl, $4cf0
    call Call_000_3c79
    call Call_000_3790
    call Call_000_3761
    scf
    ret


    db $ed
    add hl, hl
    sbc l
    ld l, h
    jp c, $b2c5

    rst $20
    ld e, b
    db $ed
    add hl, hl
    xor l
    ld l, h
    rst $20
    ld c, a
    cp h
    ld [c], a
    or e
    inc a
    ret


    ld a, a
    cp e
    or d
    pop bc
    pop hl
    or e
    add $55
    or c
    or d
    jp $7fc6


    cp [hl]
    push bc
    or [hl]
    jp z, $d07f

    cp [hl]
    rst $10
    jp c, $b2c5

    rst $20
    ld e, b
    db $ed
    add hl, hl
    cp $6c
    ld a, a
    add $29
    or a
    jp c, $e7c0

    ld e, b

Call_00f_4cfc:
    ld a, [$cf79]
    ld bc, $002c
    ld hl, $d12b
    call Call_000_3ad1
    ld de, $cffb
    ld bc, $000c
    call Call_000_01bb
    ld bc, $000f
    add hl, bc
    ld de, $d007
    ld bc, $0002
    call Call_000_01bb
    ld de, $d014
    ld bc, $0004
    call Call_000_01bb
    ld de, $d009
    ld bc, $000b
    call Call_000_01bb
    ld a, [$cfc0]
    ld [$d092], a
    call Call_000_2f2e
    ld hl, $d257
    ld bc, $0006
    ld a, [$cc2f]
    call Call_000_3ad1
    ld de, $cff0
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d009
    ld de, $cd0f
    ld bc, $000b
    call Call_000_01bb
    call Call_00f_700b
    call Call_00f_710a
    ld a, $07
    ld b, $08
    ld hl, $cd1a

jr_00f_4d67:
    ld [hl+], a
    dec b
    jr nz, jr_00f_4d67

    ret


Jump_00f_4d6c:
    ld a, [$cf79]
    ld bc, $002c
    ld hl, $d823
    call Call_000_3ad1
    ld de, $cfcc
    ld bc, $000c
    call Call_000_01bb
    ld bc, $000f
    add hl, bc
    ld de, $cfd8
    ld bc, $0002
    call Call_000_01bb
    ld de, $cfe5
    ld bc, $0004
    call Call_000_01bb
    ld de, $cfda
    ld bc, $000b
    call Call_000_01bb
    ld a, [$cfcc]
    ld [$d092], a
    call Call_000_2f2e
    ld hl, $d94f
    ld bc, $0006
    ld a, [$cf79]
    call Call_000_3ad1
    ld de, $cfc1
    ld bc, $0006
    call Call_000_01bb
    ld hl, $cfda
    ld de, $cd23
    ld bc, $000b
    call Call_000_01bb
    call Call_00f_700f
    ld hl, $d096
    ld de, $cfe9
    ld b, $05

jr_00f_4dd5:
    ld a, [hl+]
    ld [de], a
    inc de
    dec b
    jr nz, jr_00f_4dd5

    ld a, $07
    ld b, $08
    ld hl, $cd2e

jr_00f_4de2:
    ld [hl+], a
    dec b
    jr nz, jr_00f_4de2

    ld a, [$cf79]
    ld [$cfcf], a
    ret


Call_00f_4ded:
    ld hl, $7eb6
    ld b, $16
    call Call_000_3620
    ld hl, $cfcd
    ld a, [hl+]
    or [hl]
    jp z, Jump_00f_4e00

    call Call_00f_4f49

Jump_00f_4e00:
    call Call_00f_4ebe
    ld a, $04
    call Call_000_3e9d
    xor a
    ld [$ffe1], a
    ld [$cc2e], a
    ld [$cc2d], a
    ld [$cc5b], a
    ld [$d038], a
    ld [$cfb9], a
    ld hl, $ccf1
    ld [hl+], a
    ld [hl], a
    ld hl, $d03d
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$d04a], a
    ld [$ccee], a
    ld [$ccf7], a
    ld b, $01
    call Call_000_3e1f
    ld hl, $d044
    res 5, [hl]
    ld a, $01
    ldh [$f3], a
    ld a, $c3
    call Call_00f_71f9
    ld hl, $c480
    ld a, $02
    call Call_000_3e9d
    ld a, [$cf78]
    call Call_000_2dc7
    call Call_00f_7186
    jp Jump_000_3761


Call_00f_4e58:
    ld hl, $c405
    ld bc, $0707
    call Call_000_0374
    ld hl, $c42f
    ld bc, $0505
    xor a
    ld [$cd67], a
    ldh [$8b], a
    ld a, $05
    call Call_000_3e9d
    ld c, $04
    call Call_000_3781
    call Call_00f_4e98
    ld hl, $c458
    ld bc, $0303
    ld a, $01
    ld [$cd67], a
    xor a
    ldh [$8b], a
    ld a, $05
    call Call_000_3e9d
    call Call_000_3e07
    call Call_00f_4e98
    ld a, $4c
    ld [$c481], a

Call_00f_4e98:
    ld hl, $c405
    ld bc, $0707
    jp Jump_000_0374


Call_00f_4ea1:
    ld a, [$cc2f]
    ld hl, $d12c
    ld bc, $002c
    call Call_000_3ad1
    ld d, h
    ld e, l
    ld hl, $cffc
    ld bc, $0004
    jp Jump_000_01bb


Call_00f_4eb8:
Jump_00f_4eb8:
    call Call_00f_4ebe
    jp Jump_00f_4f49


Call_00f_4ebe:
    xor a
    ldh [$ba], a
    ld hl, $c435
    ld bc, $050b
    call Call_000_0374
    ld hl, $6c95
    ld b, $0e
    call Call_000_3620
    ld hl, $c466
    ld [hl], $73
    ld de, $cff0
    ld hl, $c44a
    call Call_00f_4ff8
    call Call_000_0405
    push bc
    ld hl, $cffb
    ld de, $cf7f
    ld bc, $000c
    call Call_000_01bb
    ld hl, $d009
    ld de, $cfa0
    ld bc, $000b
    call Call_000_01bb
    ld hl, $c436
    ld de, $cf83
    call Call_000_2eed
    pop hl
    jr nz, jr_00f_4f0b

    call Call_000_2f02

jr_00f_4f0b:
    ld a, [$cf7f]
    ld [$cf78], a
    ld hl, $c45e
    ld a, $5f
    call Call_000_3e9d
    ld a, $01
    ldh [$ba], a
    ld hl, $cf17
    call Call_00f_4fec
    ld hl, $cffc
    ld a, [hl+]
    or [hl]
    jr z, jr_00f_4f36

    ld a, [$ccf6]
    and a
    ret nz

    ld a, [$cf17]
    cp $02
    jr z, jr_00f_4f43

jr_00f_4f36:
    ld hl, $d060
    bit 7, [hl]
    ld [hl], $00
    ret z

    xor a
    ld [$c02a], a
    ret


jr_00f_4f43:
    ld hl, $d060
    set 7, [hl]
    ret


Call_00f_4f49:
Jump_00f_4f49:
    xor a
    ldh [$ba], a
    ld hl, $c3a1
    ld bc, $040b
    call Call_000_0374
    ld hl, $6cac
    ld b, $0e
    call Call_000_3620
    ld de, $cfc1
    ld hl, $c3b6
    call Call_00f_4ff8
    call Call_000_0405
    push bc
    ld hl, $c3a2
    ld de, $cfd0
    call Call_000_2eed
    pop hl
    jr nz, jr_00f_4f7f

    ld a, [$cfda]
    ld [$cfa0], a
    call Call_000_2f02

jr_00f_4f7f:
    ld hl, $cfcd
    ld a, [hl+]
    ldh [$97], a
    ld a, [hl-]
    ldh [$98], a
    or [hl]
    jr nz, jr_00f_4f92

    ld c, a
    ld e, a
    ld d, $06
    jp Jump_00f_4fdb


jr_00f_4f92:
    xor a
    ldh [$96], a
    ld a, $30
    ldh [$99], a
    call Call_000_38f5
    ld hl, $cfdb
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    ldh [$99], a
    ld a, b
    and a
    jr z, jr_00f_4fc6

    ldh a, [$99]
    srl b
    rr a
    srl b
    rr a
    ldh [$99], a
    ldh a, [$97]
    ld b, a
    srl b
    ldh a, [$98]
    rr a
    srl b
    rr a
    ldh [$98], a
    ld a, b
    ldh [$97], a

jr_00f_4fc6:
    ldh a, [$97]
    ldh [$95], a
    ldh a, [$98]
    ldh [$96], a
    ld a, $02
    ld b, a
    call Call_000_3902
    ldh a, [$98]
    ld e, a
    ld a, $06
    ld d, a
    ld c, a

Jump_00f_4fdb:
    xor a
    ld [$cf7b], a
    ld hl, $c3ca
    call Call_000_2d2c
    ld a, $01
    ldh [$ba], a
    ld hl, $cf18

Call_00f_4fec:
    ld b, [hl]
    call Call_000_3e29
    ld a, [hl]
    cp b
    ret z

    ld b, $01
    jp Jump_000_3e1f


Call_00f_4ff8:
    push de
    inc hl
    inc hl
    ld b, $02

jr_00f_4ffd:
    inc de
    ld a, [de]
    cp $50
    jr z, jr_00f_500d

    inc de
    ld a, [de]
    cp $50
    jr z, jr_00f_500d

    dec hl
    dec b
    jr nz, jr_00f_4ffd

jr_00f_500d:
    pop de
    ret


Call_00f_500f:
Jump_00f_500f:
    call Call_000_376d
    ld a, [$d037]
    and a
    jr nz, jr_00f_5021

    call Call_00f_4eb8
    call Call_00f_7186
    call Call_000_3761

jr_00f_5021:
    ld a, [$d037]
    cp $02
    ld a, $0b
    jr nz, jr_00f_502c

    ld a, $1b

jr_00f_502c:
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$d037]
    dec a
    jp nz, Jump_00f_5074

    ld hl, $d11d
    ld de, $d806
    ld bc, $0006
    call Call_000_01bb
    ld hl, $506e
    ld de, $d11d
    ld bc, $0006
    call Call_000_01bb
    ld hl, $c4c2
    ld [hl], $ed
    ld c, $50
    call Call_000_3781
    ld [hl], $7f
    ld hl, $c4c7
    ld [hl], $ed
    ld c, $32
    call Call_000_3781
    ld [hl], $ec
    ld a, $02
    jp Jump_00f_512f


    and l
    xor h
    and h
    and l
    or d
    ld d, b

Jump_00f_5074:
    ld a, [$cc2d]
    ld [$cc26], a
    ld [$cc2a], a
    sub $02

Jump_00f_507f:
    jr c, jr_00f_5089

    ld [$cc26], a
    ld [$cc2a], a
    jr jr_00f_50c8

jr_00f_5089:
    ld a, [$d037]
    cp $02
    ld a, $7f
    jr z, jr_00f_509c

    ld [$c4c2], a
    ld [$c4ea], a
    ld b, $01
    jr jr_00f_50b0

jr_00f_509c:
    ld [$c4c4], a
    ld [$c4ec], a
    ld hl, $c4c2
    ld de, $d983
    ld bc, $0102
    call Call_000_3c8f
    ld b, $01

jr_00f_50b0:
    ld hl, $cc24
    ld a, $0e
    ld [hl+], a
    ld a, b
    ld [hl+], a
    inc hl
    inc hl
    ld a, $01
    ld [hl+], a
    ld [hl], $11
    call Call_000_3b08
    bit 4, a
    jr nz, jr_00f_50c8

    jr jr_00f_510e

jr_00f_50c8:
    ld a, [$d037]
    cp $02
    ld a, $7f
    jr z, jr_00f_50db

    ld [$c4b9], a
    ld [$c4e1], a
    ld b, $0a
    jr jr_00f_50ef

jr_00f_50db:
    ld [$c4b9], a
    ld [$c4e1], a
    ld hl, $c4c2
    ld de, $d983
    ld bc, $0102
    call Call_000_3c8f
    ld b, $0c

jr_00f_50ef:
    ld hl, $cc24
    ld a, $0e
    ld [hl+], a
    ld a, b
    ld [hl+], a
    inc hl
    inc hl
    ld a, $01
    ld [hl+], a
    ld a, $21
    ld [hl+], a
    call Call_000_3b08
    bit 5, a
    jr nz, jr_00f_5089

    ld a, [$cc26]
    add $02
    ld [$cc26], a

jr_00f_510e:
    call Call_000_3c1c
    ld a, [$cc26]
    ld [$cc2d], a
    and a
    jr nz, jr_00f_512f

    ld a, [$d037]
    cp $02
    jr z, jr_00f_5128

    xor a
    ld [$d0e5], a
    jp Jump_000_376d


jr_00f_5128:
    ld a, $08
    ld [$cf78], a
    jr jr_00f_51a3

Jump_00f_512f:
jr_00f_512f:
    cp $02
    jp nz, Jump_00f_5221

    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_5144

    ld hl, $5209
    call Call_000_3c79
    jp Jump_00f_500f


jr_00f_5144:
    call Call_000_373e
    ld a, [$d037]
    cp $02
    jr nz, jr_00f_5155

    ld a, $15
    ld [$cf78], a
    jr jr_00f_51a3

Jump_00f_5155:
jr_00f_5155:
    call Call_000_376d
    ld a, [$d037]
    and a
    jr nz, jr_00f_5161

    call Call_00f_4eb8

jr_00f_5161:
    ld a, [$d037]
    dec a
    jr nz, jr_00f_5178

    ld hl, $5174
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    jr jr_00f_5183

    ld bc, $3204
    rst $38

jr_00f_5178:
    ld hl, $d2a1
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a

jr_00f_5183:
    xor a
    ld [$cf7a], a
    ld a, $03
    ld [$cf7b], a
    ld a, [$cc2c]
    ld [$cc26], a
    call Call_000_16f7
    ld a, [$cc26]
    ld [$cc2c], a
    ld a, $00
    ld [$cc37], a
    jp c, Jump_00f_500f

Jump_00f_51a3:
jr_00f_51a3:
    ld a, [$cf78]
    ld [$d0e3], a
    call Call_000_1add
    call Call_000_386e
    xor a
    ld [$d117], a
    call Call_000_3104
    call Call_00f_714c
    call Call_000_0188
    xor a
    ld [$cc26], a
    ld a, [$d037]
    cp $02
    jr z, jr_00f_51e0

    ld a, [$cd65]
    and a
    jp z, Jump_00f_5155

    ld a, [$d03f]
    bit 5, a
    jr z, jr_00f_51e0

    ld hl, $d047
    dec [hl]
    jr nz, jr_00f_51e0

    ld hl, $d03f
    res 5, [hl]

jr_00f_51e0:
    ld a, [$d0e1]
    and a
    jr nz, jr_00f_51fb

    ld a, [$d037]
    cp $02
    jr z, jr_00f_51f6

    call Call_000_376d

jr_00f_51f0:
    call Call_00f_4eb8
    call Call_000_3e07

jr_00f_51f6:
    call Call_000_3e0c
    and a
    ret


jr_00f_51fb:
    call Call_000_3e0c
    xor a
    ld [$d0e1], a
    ld a, $02
    ld [$cf06], a
    scf
    ret


    db $ed
    add hl, hl
    dec d
    ld l, l
    jp z, $347f

    or e
    jr z, jr_00f_51f0

    ld c, a
    jp nz, $b3b6

    cp d
    call nz, $7fca
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $58

Jump_00f_5221:
    dec a
    jp nz, Jump_00f_5358

    call Call_000_373e
    ld a, [$d037]
    cp $02
    jr nz, jr_00f_5237

    ld a, $16
    ld [$cf78], a
    jp Jump_00f_51a3


Jump_00f_5237:
jr_00f_5237:
    call Call_000_376d
    xor a
    ld [$d05a], a
    call Call_000_2df3

jr_00f_5241:
    jp nc, Jump_00f_526d

jr_00f_5244:
    call Call_000_0188
    call Call_000_3e15
    call Call_00f_714c
    call Call_000_374a
    call Call_000_3e1d
    call Call_000_3e0c
    jp Jump_00f_500f


Jump_00f_5259:
jr_00f_5259:
    ld hl, $c487
    ld bc, $0081
    ld a, $7f
    call Call_000_372a
    xor a
    ld [$d05a], a
    call Call_000_2e08
    jr jr_00f_5241

Jump_00f_526d:
    ld a, $0c
    ld [$d0ea], a
    call Call_000_3130
    ld hl, $cc24
    ld a, $0c
    ld [hl+], a
    ld a, $0c
    ld [hl+], a
    xor a
    ld [hl+], a
    inc hl
    ld a, $02
    ld [hl+], a
    ld a, $03
    ld [hl+], a
    xor a
    ld [hl], a
    call Call_000_3b08
    bit 1, a
    jr nz, jr_00f_5259

    call Call_000_3c1c
    ld a, [$cc26]
    cp $02
    jr z, jr_00f_5244

    and a
    jr z, jr_00f_52e0

    xor a
    ld [$cc49], a
    ld hl, $d12b
    call Call_000_0188
    ld a, $36
    call Call_000_3e9d
    ld a, $37
    call Call_000_3e9d
    ld a, [$d045]
    bit 4, a
    ld hl, $5717
    jr nz, jr_00f_52d8

    ld a, [$ccf3]
    and a
    ld hl, $55d6
    jr nz, jr_00f_52d8

    ld a, [$cfcc]
    ld [$cf78], a
    ld [$d092], a
    call Call_000_2f2e
    ld de, $9000
    call Call_000_3034
    jr jr_00f_52dd

jr_00f_52d8:
    ld b, $1e
    call Call_000_3620

jr_00f_52dd:
    jp Jump_00f_5237


jr_00f_52e0:
    ld a, [$cc2f]
    ld d, a
    ld a, [$cf79]
    cp d
    jr nz, jr_00f_52f3

    ld hl, $534b
    call Call_000_3c79
    jp Jump_00f_5259


jr_00f_52f3:
    call Call_00f_4bb7
    jp z, Jump_00f_5259

    ld a, $01
    ld [$cd65], a
    call Call_000_3e15
    call Call_000_0188
    call Call_00f_714c
    call Call_000_376d
    call Call_000_3e1d
    call Call_000_3e0c

Jump_00f_5310:
    ld hl, $7f4d
    ld b, $16
    call Call_000_3620
    ld c, $32
    call Call_000_3781
    call Call_00f_4e58
    ld a, [$cf79]
    ld [$cc2f], a
    ld c, a
    ld b, $01
    push bc
    ld hl, $d035
    ld a, $10
    call Call_000_3e9d
    pop bc
    ld hl, $ccf5
    ld a, $10
    call Call_000_3e9d
    call Call_00f_4cfc
    call Call_00f_4ded
    call Call_000_3761
    ld a, $02
    ld [$cc26], a
    and a
    ret


    db $ed
    add hl, hl
    ld [hl-], a
    ld l, l
    jp z, $b3d3

    inc sp
    jp $cfb2


    cp l
    ld e, b

Jump_00f_5358:
    call Call_000_376d
    ld a, $03
    ld [$cc26], a
    ld hl, $d010
    ld de, $cfe1
    call Call_00f_4be4
    ld a, $00
    ld [$d0e4], a
    ret c

    ld a, [$cd65]
    and a
    ret nz

    jp Jump_00f_500f


Call_00f_5377:
Jump_00f_5377:
    ld hl, $cfd4
    ld a, [$ccdb]
    dec a
    jr z, jr_00f_5398

    dec a
    jr z, jr_00f_538c

    call Call_00f_5528
    ret z

    ld hl, $d003
    jr jr_00f_5398

jr_00f_538c:
    ld a, [$cf79]
    ld hl, $d133
    ld bc, $002c
    call Call_000_3ad1

jr_00f_5398:
    ld de, $d0b9
    ld bc, $0004
    call Call_000_01bb
    ld hl, $5e5f
    ld b, $0e
    call Call_000_3620
    ld hl, $c440
    ld b, $08
    ld c, $12
    ld a, [$ccdb]
    cp $02
    jr nz, jr_00f_53be

    ld hl, $c44a
    ld b, $08
    ld c, $08

jr_00f_53be:
    call Call_000_03d2
    ld hl, $c46a
    ld a, [$ccdb]
    cp $02
    jr nz, jr_00f_53ce

    ld hl, $c474

jr_00f_53ce:
    ld de, $df30
    call Call_000_0405
    ld b, $01
    ld a, [$ccdb]
    cp $02
    jr nz, jr_00f_53df

    ld b, $0b

jr_00f_53df:
    ld hl, $cc24
    ld a, $08
    ld [hl+], a
    ld a, b
    ld [hl+], a
    ld a, [$ccdb]
    cp $01
    jr z, jr_00f_53f2

    ld a, [$cc2e]
    inc a

jr_00f_53f2:
    ld [hl+], a
    inc hl
    ld a, [$cd67]
    inc a
    inc a
    ld [hl+], a
    ld a, [$ccdb]
    dec a
    ld b, $c1
    jr z, jr_00f_5419

    dec a
    ld b, $c3
    jr z, jr_00f_5419

    ld a, [$d0f0]
    cp $04
    jr z, jr_00f_5419

    ld a, [$d6b2]
    bit 0, a
    ld b, $c7
    jr z, jr_00f_5419

    ld b, $ff

jr_00f_5419:
    ld a, b
    ld [hl+], a
    ld a, [$ccdb]
    cp $01
    jr z, jr_00f_5426

    ld a, [$cc2e]
    inc a

jr_00f_5426:
    ld [hl], a

Jump_00f_5427:
    ld a, [$ccdb]
    and a
    jr z, jr_00f_543b

    dec a
    jr nz, jr_00f_5457

    ld hl, $c4c3
    ld de, $54ee
    call Call_000_0405
    jr jr_00f_5457

jr_00f_543b:
    ld a, [$d6b2]
    bit 0, a
    jr nz, jr_00f_5457

    call Call_00f_55fa
    ld a, [$cc35]
    and a
    jr z, jr_00f_5457

    ld hl, $c469
    dec a
    ld bc, $0028
    call Call_000_3ad1
    ld [hl], $ec

jr_00f_5457:
    call Call_000_3b08
    bit 6, a
    jp nz, Jump_00f_54fc

    bit 7, a
    jp nz, Jump_00f_5510

    bit 2, a
    jp nz, Jump_00f_5579

    bit 1, a
    push af
    xor a
    ld [$cc35], a
    ld a, [$cc26]
    dec a
    ld [$cc26], a
    ld b, a
    ld a, [$ccdb]
    dec a
    jr nz, jr_00f_5480

    pop af
    ret


jr_00f_5480:
    dec a
    ld a, b
    ld [$cc2e], a
    jr nz, jr_00f_5489

    pop af
    ret


jr_00f_5489:
    pop af
    ret nz

    ld hl, $d014
    ld a, [$cc26]
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    and $3f
    jr z, jr_00f_54c1

    ld a, [$d04a]
    swap a
    and $0f
    dec a
    cp c
    jr z, jr_00f_54bc

    ld a, [$d041]
    bit 3, a
    jr nz, jr_00f_54ac

jr_00f_54ac:
    ld a, [$cc26]
    ld hl, $d003
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$ccdc], a
    xor a
    ret


jr_00f_54bc:
    ld hl, $54df
    jr jr_00f_54c4

jr_00f_54c1:
    ld hl, $54cd

jr_00f_54c4:
    call Call_000_3c79
    call Call_000_376d
    jp Jump_00f_5377


    db $ed
    add hl, hl
    ld h, b
    ld l, l
    ld a, a
    ret


    cp d
    ret c

    ld b, e
    add c
    xor e
    sub e
    ld h, $7f
    push bc
    or d
    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld b, [hl]
    ld l, l
    ld a, a
    call z, $2cb3
    rst $10
    jp c, $b2c3

    reti


    rst $20
    ld e, b
    db $ed
    inc l
    db $e4
    ld b, d
    db $dd
    ld c, [hl]
    db $d3
    ret


    rst $08
    ret z

    cp l
    reti


    and $50

Jump_00f_54fc:
    ld a, [$cc26]
    and a
    jp nz, Jump_00f_5427

    call Call_000_3c29
    ld a, [$cd67]
    inc a
    ld [$cc26], a
    jp Jump_00f_5427


Jump_00f_5510:
    ld a, [$cc26]
    ld b, a
    ld a, [$cd67]
    inc a
    inc a
    cp b
    jp nz, Jump_00f_5427

    call Call_000_3c29
    ld a, $01
    ld [$cc26], a
    jp Jump_00f_5427


Call_00f_5528:
    ld a, $a5
    ld [$ccdc], a
    ld a, [$d04a]
    and a
    ld hl, $d014
    jr nz, jr_00f_553f

    ld a, [hl+]
    or [hl]
    inc hl
    or [hl]
    inc hl
    or [hl]
    ret nz

    jr jr_00f_5554

jr_00f_553f:
    swap a
    and $0f
    ld b, a
    ld d, $05
    xor a

jr_00f_5547:
    dec d
    jr z, jr_00f_5552

    ld c, [hl]
    inc hl
    dec b
    jr z, jr_00f_5547

    or c
    jr jr_00f_5547

jr_00f_5552:
    and a
    ret nz

jr_00f_5554:
    ld hl, $5561
    call Call_000_3c79
    ld c, $3c
    call Call_000_3781
    xor a
    ret


    db $ed
    add hl, hl
    adc e
    ld l, l
    jp z, $307f

    cp l
    cp d
    call nz, Call_00f_7fc9
    inc sp
    or a
    reti


    ld c, a
    call c, $262b
    ld a, a
    push bc
    or d
    rst $20
    ld d, a

Jump_00f_5579:
    ld a, [$cc35]
    and a
    jr z, jr_00f_55f1

    ld hl, $d003
    call Call_00f_55d7
    ld hl, $d014
    call Call_00f_55d7
    ld hl, $d04a
    ld a, [hl]
    swap a
    and $0f
    ld b, a
    ld a, [$cc26]
    cp b
    jr nz, jr_00f_55a7

    ld a, [hl]
    and $0f
    ld b, a
    ld a, [$cc35]
    swap a
    add b
    ld [hl], a
    jr jr_00f_55b8

jr_00f_55a7:
    ld a, [$cc35]
    cp b
    jr nz, jr_00f_55b8

    ld a, [hl]
    and $0f
    ld b, a
    ld a, [$cc26]
    swap a
    add b
    ld [hl], a

jr_00f_55b8:
    ld hl, $d133
    ld a, [$cc2f]
    ld bc, $002c
    call Call_000_3ad1
    push hl
    call Call_00f_55d7
    pop hl
    ld bc, $0015
    add hl, bc
    call Call_00f_55d7
    xor a
    ld [$cc35], a
    jp Jump_00f_5377


Call_00f_55d7:
    push hl
    ld a, [$cc35]
    dec a
    ld c, a
    ld b, $00
    add hl, bc
    ld d, h
    ld e, l
    pop hl
    ld a, [$cc26]
    dec a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [de]
    ld b, [hl]
    ld [hl], a
    ld a, b
    ld [de], a
    ret


jr_00f_55f1:
    ld a, [$cc26]
    ld [$cc35], a
    jp Jump_00f_5377


Call_00f_55fa:
    xor a
    ldh [$ba], a
    ld hl, $c3c8
    ld b, $04
    ld c, $09
    call Call_000_03d2
    ld a, [$d04a]
    and a
    jr z, jr_00f_5623

    swap a
    and $0f
    ld b, a
    ld a, [$cc26]
    cp b
    jr nz, jr_00f_5623

    ld hl, $c4d6
    ld de, $5699
    call Call_000_0405
    jr @+$71

jr_00f_5623:
    ld hl, $cc26
    dec [hl]
    xor a
    ldh [$f3], a
    ld hl, $d003
    ld a, [$cc26]
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    ld [$ccdc], a
    ld a, [$cc2f]
    ld [$cf79], a
    ld a, $04
    ld [$cc49], a
    ld hl, $694a
    ld b, $03
    call Call_000_3620
    ld hl, $cc26
    ld c, [hl]
    inc [hl]
    ld b, $00
    ld hl, $d014
    add hl, bc
    ld a, [hl]
    and $3f
    ld [$cd68], a
    ld hl, $c405
    ld de, $56a3
    call Call_000_0405
    ld hl, $c3e3
    ld [hl], $f3
    ld hl, $c3e1
    ld de, $cd68
    ld bc, $0102
    call Call_000_3c8f
    ld hl, $c3e4
    ld de, $d0e3
    ld bc, $0102
    call Call_000_3c8f
    call Call_00f_6dae
    ld hl, $c419
    ld a, $5d
    call Call_000_3e9d
    ld a, $01
    ldh [$ba], a
    jp Jump_000_3e07


    ldh [$ba], a
    jp Jump_000_3e07


    db $ed
    inc l
    nop
    ld b, e
    jp c, $b2c3

    reti


    rst $20
    ld d, b
    db $ed
    inc l
    rrca
    ld b, e
    ld b, d
    ld d, b

Call_00f_56a9:
    ld a, [$d0f0]
    sub $04
    jr nz, jr_00f_56d1

    call Call_000_3761
    call Call_00f_5743
    call Call_000_376d
    ld a, [$cc3e]
    cp $0e
    jp z, Jump_00f_573f

    cp $04
    ret nc

    ld [$cce2], a
    ld hl, $cfd4
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    jr jr_00f_573b

jr_00f_56d1:
    ld a, [$d045]
    and $60
    ret nz

    ld hl, $d044
    bit 4, [hl]
    ret nz

    bit 1, [hl]
    ret nz

    ld a, [$cfd0]
    and $27
    ret nz

    ld a, [$d044]
    and $21
    ret nz

    ld a, [$d044]
    bit 5, a
    ret nz

    ld hl, $cfd5
    ld a, [hl-]
    and a
    jr nz, jr_00f_5701

    ld a, [$d04f]
    and a
    ld a, $a5
    jr nz, jr_00f_573b

jr_00f_5701:
    ld a, [$d034]
    dec a
    jr z, jr_00f_570f

    ld hl, $5a36
    ld b, $0e
    call Call_000_3620

jr_00f_570f:
    push hl
    call Call_00f_718d
    ld b, $01
    cp $3f
    jr c, jr_00f_5727

    inc hl
    inc b
    cp $7f
    jr c, jr_00f_5727

    inc hl
    inc b
    cp $be
    jr c, jr_00f_5727

    inc hl
    inc b

jr_00f_5727:
    ld a, b
    dec a
    ld [$cce2], a
    ld a, [$d04f]
    swap a
    and $0f
    cp b
    ld a, [hl]
    pop hl
    jr z, jr_00f_570f

    and a
    jr z, jr_00f_570f

jr_00f_573b:
    ld [$ccdd], a
    ret


Jump_00f_573f:
    ld a, $a5
    jr jr_00f_573b

Call_00f_5743:
    ld a, $ff
    ld [$cc3e], a
    ld a, [$cd65]
    and a
    jr nz, jr_00f_575c

    ld a, [$ccdc]
    cp $a5
    ld a, $0e
    jr z, jr_00f_5761

    ld a, [$cc2e]
    jr jr_00f_5761

jr_00f_575c:
    ld a, [$cf79]
    add $04

jr_00f_5761:
    ld [$cc42], a
    ld hl, $49ee
    ld b, $01
    call Call_000_3620

jr_00f_576c:
    call Call_000_0d57
    call Call_000_0b31
    ld a, [$cc3e]
    inc a
    jr z, jr_00f_576c

    ld b, $0a

jr_00f_577a:
    call Call_000_0b31
    call Call_000_0d57
    dec b
    jr nz, jr_00f_577a

    ld b, $0a

jr_00f_5785:
    call Call_000_0b31
    call Call_000_0d81
    dec b
    jr nz, jr_00f_5785

    ret


Call_00f_578f:
    ld a, [$ccdc]
    inc a
    jp z, Jump_00f_594a

    xor a
    ldh [$f3], a
    ld [$d03c], a
    ld [$cced], a
    ld [$ccf4], a
    ld a, $0a
    ld [$d038], a
    ld a, [$cd65]
    and a
    jp nz, Jump_00f_594a

    call Call_00f_5951
    jp z, Jump_00f_594a

    call Call_00f_59ba
    jr nz, jr_00f_57ba

    jp hl


jr_00f_57ba:
    call Call_00f_6dae
    ld hl, $d03f
    bit 4, [hl]
    jr nz, jr_00f_57d9

    call Call_00f_5f07
    jp z, Jump_00f_594a

Jump_00f_57ca:
    ld a, [$cfba]
    cp $27
    jp z, Jump_00f_7427

    cp $2b
    jp z, Jump_00f_7427

    jr jr_00f_57e0

jr_00f_57d9:
    ld hl, $d03f
    res 4, [hl]
    res 6, [hl]

jr_00f_57e0:
    call Call_00f_5d18
    ld hl, $7fd0
    ld de, $ccdc
    ld b, $1a
    call Call_000_3620
    ld a, [$cfba]
    ld hl, $4000
    ld de, $0001
    call Call_000_3ddb
    jp c, Jump_00f_7427

    ld a, [$cfba]
    ld hl, $4049
    ld de, $0001
    call Call_000_3ddb
    call c, Call_00f_7427
    ld a, [$cfba]
    ld hl, $4011
    ld de, $0001
    call Call_000_3ddb
    jp c, Jump_00f_5832

    call Call_00f_62bc
    call Call_00f_632c
    jr z, jr_00f_5835

    call Call_00f_6068
    call Call_00f_61fe
    jp z, Jump_00f_587b

    call Call_00f_6687
    call Call_00f_6969

Jump_00f_5832:
    call Call_00f_684d

jr_00f_5835:
    ld a, [$d03c]
    and a
    jr z, jr_00f_5844

    ld a, [$cfba]
    sub $07
    jr z, jr_00f_584e

    jr jr_00f_587b

Jump_00f_5844:
jr_00f_5844:
    ld a, [$cfba]
    and a
    ld a, $04
    jr z, jr_00f_584e

    ld a, $05

jr_00f_584e:
    push af
    ld a, [$d040]
    bit 4, a
    ld hl, $577e
    ld b, $1e
    call nz, Call_000_3620
    pop af
    ld [$cc5b], a
    ld a, [$cfb9]
    call Call_00f_71f9
    call Call_00f_71c5
    call Call_00f_4ebe
    ld a, [$d040]
    bit 4, a
    ld hl, $57a8
    ld b, $1e
    call nz, Call_000_3620
    jr jr_00f_5896

Jump_00f_587b:
jr_00f_587b:
    ld c, $1e
    call Call_000_3781
    ld a, [$cfba]
    cp $2b
    jr z, jr_00f_588d

    cp $27
    jr z, jr_00f_588d

    jr jr_00f_5896

jr_00f_588d:
    xor a
    ld [$cc5b], a
    ld a, $a7
    call Call_00f_71f9

jr_00f_5896:
    ld a, [$cfba]
    cp $09
    jr nz, jr_00f_58aa

    call Call_00f_65cc
    jp z, Jump_00f_594a

    xor a
    ld [$cced], a
    jp Jump_00f_57ca


jr_00f_58aa:
    cp $53
    jr nz, jr_00f_58b4

    call Call_00f_662a
    jp Jump_00f_57ca


jr_00f_58b4:
    ld a, [$cfba]
    ld hl, $4014
    ld de, $0001
    call Call_000_3ddb
    jp c, Jump_00f_7427

    ld a, [$d03c]
    and a
    jr z, jr_00f_58d6

    call Call_00f_5e14
    ld a, [$cfba]
    cp $07
    jr z, jr_00f_58e9

    jp Jump_00f_594a


jr_00f_58d6:
    call Call_00f_6378
    call Call_00f_5ecb
    ld hl, $7eb2
    ld b, $0b
    call Call_000_3620
    ld a, $01
    ld [$ccf4], a

jr_00f_58e9:
    ld a, [$cfba]
    ld hl, $4030
    ld de, $0001
    call Call_000_3ddb
    call c, Call_00f_7427
    ld hl, $cfcd
    ld a, [hl+]
    ld b, [hl]
    or b
    ret z

    call Call_00f_6572
    ld hl, $d03f
    bit 2, [hl]
    jr z, jr_00f_591f

    ld a, [$d047]
    dec a
    ld [$d047], a
    jp nz, Jump_00f_5844

    res 2, [hl]
    ld hl, $5935
    call Call_000_3c79
    xor a
    ld [$d051], a

jr_00f_591f:
    ld a, [$cfba]
    and a
    jp z, Jump_00f_594a

    ld hl, $403b
    ld de, $0001
    call Call_000_3ddb
    call nc, Call_00f_7427
    jp Jump_00f_594a


    db $ed
    add hl, hl
    rst $08
    ld l, l
    add $7f
    ld d, b
    add hl, bc
    ld d, c
    ret nc

    ld de, $b600

jr_00f_5942:
    or d
    ld a, a
    or c
    ret nz

    rst $18
    ret nz

    rst $20
    ld e, b

Jump_00f_594a:
    xor a
    ld [$cd65], a
    ld b, $01
    ret


Call_00f_5951:
    call Call_00f_59a0
    ret nz

    ldh a, [$f3]
    and a
    jr nz, jr_00f_5968

    ld a, [$cfff]
    and $27
    ret nz

    ld hl, $5970
    call Call_000_3c79
    xor a
    ret


jr_00f_5968:
    ld hl, $598f
    call Call_000_3c79
    xor a
    ret


    db $ed
    add hl, hl
    db $ed
    ld l, l
    jp z, $ba7f

    call c, $df26
    jp $d9b2


    rst $20
    ld c, a
    call c, $dd2b
    ld a, a
    jr nc, jr_00f_5942

    cp d
    call nz, Call_00f_7f26
    inc sp
    or a
    push bc
    or d
    rst $20
    ld e, b
    db $ed
    add hl, hl
    inc sp
    ld l, [hl]
    or d
    ld [hl], d
    adc a
    sub b
    adc d
    and a
    ld d, [hl]
    adc a
    sub b
    adc d
    and a
    ld d, [hl]
    ld e, b

Call_00f_59a0:
    ld a, [$d034]
    dec a
    ret nz

    ld a, [$d2dd]
    cp $8e
    jr c, jr_00f_59b6

    cp $95
    jr nc, jr_00f_59b6

    ld b, $48
    call Call_000_34dd
    ret z

jr_00f_59b6:
    ld a, $01
    and a
    ret


Call_00f_59ba:
    ld hl, $cfff
    ld a, [hl]
    and $07
    jr z, jr_00f_59ea

    dec a
    ld [$cfff], a
    and a
    jr z, jr_00f_59da

    xor a
    ld [$cc5b], a
    ld a, $bc
    call Call_00f_71f9
    ld hl, $5ba5
    call Call_000_3c79
    jr jr_00f_59e0

jr_00f_59da:
    ld hl, $5bb5
    call Call_000_3c79

jr_00f_59e0:
    xor a
    ld [$ccf1], a
    ld hl, $594a
    jp Jump_00f_5b9f


jr_00f_59ea:
    bit 5, [hl]
    jr z, jr_00f_59fe

    ld hl, $5bc1
    call Call_000_3c79
    xor a
    ld [$ccf1], a
    ld hl, $594a
    jp Jump_00f_5b9f


jr_00f_59fe:
    ld a, [$d044]
    bit 5, a
    jp z, Jump_00f_5a12

    ld hl, $5c89
    call Call_000_3c79
    ld hl, $594a
    jp Jump_00f_5b9f


Jump_00f_5a12:
    ld hl, $d03f
    bit 3, [hl]
    jp z, Jump_00f_5a28

    res 3, [hl]
    ld hl, $5bea
    call Call_000_3c79
    ld hl, $594a
    jp Jump_00f_5b9f


Jump_00f_5a28:
    ld hl, $d040
    bit 5, [hl]
    jr z, jr_00f_5a3d

    res 5, [hl]
    ld hl, $5bf4
    call Call_000_3c79
    ld hl, $594a
    jp Jump_00f_5b9f


jr_00f_5a3d:
    ld hl, $d04a
    ld a, [hl]
    and a
    jr z, jr_00f_5a54

    dec a
    ld [hl], a
    and $0f
    jr nz, jr_00f_5a54

    ld [hl], a
    ld [$ccee], a
    ld hl, $5c0b
    call Call_000_3c79

jr_00f_5a54:
    ld a, [$d03f]
    bit 7, a
    jr z, jr_00f_5a91

    ld hl, $d048
    dec [hl]
    jr nz, jr_00f_5a6e

    ld hl, $d03f
    res 7, [hl]
    ld hl, $5c40
    call Call_000_3c79
    jr jr_00f_5a91

jr_00f_5a6e:
    ld hl, $5c1b
    call Call_000_3c79
    xor a
    ld [$cc5b], a
    ld a, $be
    call Call_00f_71f9
    call Call_00f_718d
    cp $80
    jp c, Jump_00f_5aa6

    ld hl, $d03f
    ld a, [hl]
    and $80
    ld [hl], a
    call Call_00f_5cd0
    jr jr_00f_5aba

jr_00f_5a91:
    ld a, [$ccee]
    and a
    jr z, jr_00f_5aa6

    ld hl, $ccdc
    cp [hl]
    jr nz, jr_00f_5aa6

    call Call_00f_5c99
    ld hl, $594a
    jp Jump_00f_5b9f


Jump_00f_5aa6:
jr_00f_5aa6:
    ld hl, $cfff
    bit 6, [hl]
    jr z, jr_00f_5add

    call Call_00f_718d
    cp $3f
    jr nc, jr_00f_5add

    ld hl, $5bd6
    call Call_000_3c79

jr_00f_5aba:
    ld hl, $d03f
    ld a, [hl]
    and $cc
    ld [hl], a
    ld a, [$cfba]
    cp $2b
    jr z, jr_00f_5ace

    cp $27
    jr z, jr_00f_5ace

    jr jr_00f_5ad7

jr_00f_5ace:
    xor a
    ld [$cc5b], a
    ld a, $a7
    call Call_00f_71f9

jr_00f_5ad7:
    ld hl, $594a
    jp Jump_00f_5b9f


jr_00f_5add:
    ld hl, $d03f
    bit 0, [hl]
    jr z, jr_00f_5b38

    xor a
    ld [$cfb9], a
    ld hl, $d0b4
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld hl, $d052
    ld a, [hl]
    add c
    ld [hl-], a
    ld a, [hl]
    adc b
    ld [hl], a
    ld hl, $d047
    dec [hl]
    jr z, jr_00f_5b03

    ld hl, $594a
    jp Jump_00f_5b9f


jr_00f_5b03:
    ld hl, $d03f
    res 0, [hl]
    ld hl, $5c5b
    call Call_000_3c79
    ld a, $01
    ld [$cfbb], a
    ld hl, $d052
    ld a, [hl-]
    add a
    ld b, a
    ld [$d0b5], a
    ld a, [hl]
    rl a
    ld [$d0b4], a
    or b
    jr nz, jr_00f_5b2a

    ld a, $01
    ld [$d03c], a

jr_00f_5b2a:
    xor a
    ld [hl+], a
    ld [hl], a
    ld a, $75
    ld [$cfb9], a
    ld hl, $5835
    jp Jump_00f_5b9f


jr_00f_5b38:
    bit 1, [hl]
    jr z, jr_00f_5b67

    ld a, $25
    ld [$cfb9], a
    ld hl, $5c6a
    call Call_000_3c79
    ld hl, $d047
    dec [hl]
    ld hl, $580c
    jp nz, Jump_00f_5b9f

    push hl
    ld hl, $d03f
    res 1, [hl]
    set 7, [hl]
    call Call_00f_718d
    and $03

jr_00f_5b5e:
    inc a
    inc a

jr_00f_5b60:
    ld [$d048], a
    pop hl
    jp Jump_00f_5b9f


jr_00f_5b67:
    bit 5, [hl]
    jp z, Jump_00f_5b82

    ld hl, $5c75
    call Call_000_3c79
    ld a, [$d047]
    dec a
    ld [$d047], a
    ld hl, $5844
    jp nz, Jump_00f_5b9f

    jp Jump_00f_5b9f


Jump_00f_5b82:
    ld a, [$d040]
    bit 6, a
    jp z, Jump_00f_5ba1

    ld a, $63
    ld [$d0e3], a
    call Call_000_1b6d
    call Call_000_386e
    xor a
    ld [$cfba], a
    ld hl, $57e0
    jp Jump_00f_5b9f


Jump_00f_5b9f:
    xor a
    ret


Jump_00f_5ba1:
    ld a, $01
    and a
    ret


    db $ed
    add hl, hl
    sbc e
    ld [hl], c
    jr z, jr_00f_5b5e

    jr z, jr_00f_5b60

    ld a, a
    ret z

    pop de
    rst $18
    jp $d9b2


    ld e, b
    db $ed
    add hl, hl
    or e
    ld [hl], c
    jp nc, $bbdd

    rst $08
    cp h
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    cp a
    ld [hl], c
    cp d
    or l
    rst $18
    jp $bc7f


    rst $08
    rst $18
    jp $b37f


    ld a, [hl+]
    or [hl]
    push bc
    or d
    rst $20
    ld e, b
    db $ed
    add hl, hl
    add $72
    or [hl]
    rst $10
    jr nc, @+$28

    ld a, a
    cp h
    dec sp
    jp c, $7fc3

    or e
    ld a, [hl+]
    cp c
    push bc
    or d
    ld e, b
    db $ed
    add hl, hl
    ld a, [$cb71]
    reti


    sbc $30
    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld de, $b772
    ret


    ld a, a
    jp z, $34de

    or e
    inc sp
    ld c, a
    ld e, d
    jp z, $b37f

    ld a, [hl+]
    cp c
    push bc
    or d
    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld b, a
    ld [hl], d
    or [hl]
    push bc
    cp h
    ld a, [hl-]
    ret c

    ld h, $7f
    call nz, $c0b9
    rst $20
    ld e, b
    db $ed
    add hl, hl
    add e
    ld [hl], d
    cp d
    sbc $d7
    sbc $bc
    jp $d9b2


    rst $20
    ld e, b
    db $ed
    add hl, hl
    sub [hl]
    ld [hl], d
    ld a, a
    call c, $d7b6
    dec l
    ld c, a
    inc l
    inc a
    sbc $dd
    ld a, a
    cp d
    or e
    add hl, hl
    or a
    cp h
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld h, l
    ld [hl], d
    cp d
    sbc $d7
    sbc $26
    ld a, a
    call nz, $c0b9
    rst $20
    ld e, b
    nop
    ld e, d
    jp z, Jump_000_267f

    rst $08
    sbc $bc
    jp $d9b2


    ld e, b
    db $ed
    add hl, hl
    rst $30
    ld [hl], d
    ld h, $cf
    sbc $26
    ld a, a
    call nz, $dab6
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld c, $73
    or c
    ld a, [hl-]
    jp c, $b2c3

    reti


    ld d, a
    db $ed
    add hl, hl
    daa
    ld [hl], e
    cp d
    or e
    add hl, hl
    or a
    jp z, $cf4f

    jr nc, jr_00f_5d01

    jp nz, $b232

    jp $d9b2


    ld d, a
    db $ed
    add hl, hl
    rst $18
    ld [hl], c
    ret nc

    or e
    ld a, [hl+]
    or a
    ld h, $7f
    call nz, $c5da
    or d
    rst $20
    ld e, b

Call_00f_5c99:
    ld hl, $ccdc
    ld de, $d03f
    ldh a, [$f3]
    and a
    jr z, jr_00f_5ca8

    inc hl
    ld de, $d044

jr_00f_5ca8:
    ld a, [de]
    res 4, a
    ld [de], a
    ld a, [hl]
    ld [$d0e3], a
    call Call_000_1b6d
    ld hl, $5cb9
    jp Jump_000_3c79


    db $ed
    add hl, hl
    ldh [$6f], a
    or [hl]
    push bc
    cp h
    ld a, [hl-]
    ret c

    inc sp
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    ld h, $30
    cp [hl]
    push bc
    or d
    rst $20
    ld e, b

Call_00f_5cd0:
    ld hl, $5c29
    call Call_000_3c79
    ld hl, $cfdf
    ld a, [hl+]
    push af
    ld a, [hl-]
    push af
    ld a, [$d00e]
    ld [hl+], a
    ld a, [$d00f]
    ld [hl], a
    ld hl, $cfba
    push hl
    ld a, [hl]
    push af
    xor a
    ld [hl+], a
    ld [$d03b], a
    ld a, $28
    ld [hl+], a
    xor a
    ld [hl], a
    call Call_00f_6068
    call Call_00f_61fe
    pop af
    pop hl
    ld [hl], a
    ld hl, $cfe0

jr_00f_5d01:
    pop af
    ld [hl-], a
    pop af
    ld [hl], a
    xor a
    ld [$cc5b], a
    inc a
    ldh [$f3], a
    call Call_00f_71f9
    call Call_00f_4ebe
    xor a
    ldh [$f3], a
    jp Jump_00f_6499


Call_00f_5d18:
    ld hl, $5d1e
    jp Jump_000_3c79


    nop
    ld e, d
    ld d, b
    ld [$f3f0], sp
    and a
    ld a, [$cfb9]
    ld hl, $ccf1
    jr z, jr_00f_5d33

    ld a, [$cfb3]
    ld hl, $ccf2

jr_00f_5d33:
    ld [hl], a
    ld [$d0e3], a
    call Call_00f_5db7
    ld a, [$cced]
    and a
    ld hl, $5d56
    ret nz

    ld a, [$d0e3]
    cp $03
    ld hl, $5d56
    ret c

    ld hl, $5d4f
    ret


    nop
    add a
    db $d3
    ld d, b
    ld [$0518], sp
    nop
    ret


    db $d3
    ld d, b
    ld [$edfa], sp
    call z, $28a7
    db $10
    ld hl, $5d65
    ret


    nop
    adc $87
    call nc, $af7f
    jp nc, $c5c4

    jp nc, Jump_000_0850

    ld hl, $5d75
    ret


    nop
    ld c, a
    ld d, b
    ld bc, $cf45
    ld [$8d21], sp
    ld e, l
    ld a, [$d0e3]
    add a
    push bc
    ld b, $00
    ld c, a
    add hl, bc
    pop bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ret


    sub a
    ld e, l
    and b
    ld e, l
    and a
    ld e, l
    xor h
    ld e, l
    or h
    ld e, l
    db $ed
    dec l
    ld [hl], l
    ld h, l
    or [hl]
    rst $18
    ret nz

    rst $20
    ld d, a
    db $ed
    dec l
    ld a, a
    ld h, l
    ret nz

    rst $20
    ld d, a
    db $ed
    dec l
    adc c
    ld h, l
    ld d, a
    db $ed
    dec l
    sub e
    ld h, l
    add hl, hl
    or a
    rst $20
    ld d, a
    nop
    rst $20
    ld d, a

Call_00f_5db7:
    push bc
    ld a, [$d0e3]
    ld c, a
    ld b, $00
    ld hl, $5dd5

jr_00f_5dc1:
    ld a, [hl+]
    cp $ff
    jr z, jr_00f_5dcf

    cp c
    jr z, jr_00f_5dcf

    and a
    jr nz, jr_00f_5dc1

    inc b
    jr jr_00f_5dc1

jr_00f_5dcf:
    ld a, b
    ld [$d0e3], a
    pop bc
    ret


    ld c, $4a
    nop
    ld l, c
    ld [hl], l
    ld a, b
    add l
    nop
    ld h, b
    ld h, c
    ld h, h
    ld h, [hl]
    ld l, b
    adc h
    nop
    ld bc, $0b0a
    ld de, $1413
    dec d
    ld e, $22
    inc hl
    dec h
    daa
    dec hl
    inc l
    dec l
    ld l, $2f
    ld b, b
    ld b, h
    ld b, [hl]
    ld b, a
    ld d, c
    ld e, c
    ld e, d
    ld e, e
    ld e, h
    ld h, a
    ld l, d
    ld l, e
    ld l, [hl]
    ld l, a
    db $76
    ld a, d
    add b
    add h
    adc e
    adc l
    sub c
    sub h
    sub [hl]
    sub a
    sbc d
    sbc h
    sbc a
    and e
    and h
    nop
    rst $38

Call_00f_5e14:
    ld de, $cfba
    ldh a, [$f3]
    and a
    jr z, jr_00f_5e1f

    ld de, $cfb4

jr_00f_5e1f:
    ld hl, $5eb8
    ld a, [$d038]
    and $7f
    jr z, jr_00f_5e36

    ld hl, $5e74
    ld a, [$d03b]
    cp $ff
    jr nz, jr_00f_5e36

    ld hl, $5ea2

jr_00f_5e36:
    push de
    call Call_000_3c79
    xor a
    ld [$d03b], a
    pop de
    ld a, [de]
    cp $2d
    ret nz

    ld hl, $d0b4
    ld a, [hl+]
    ld b, [hl]
    srl a
    rr b
    srl a
    rr b
    srl a
    rr b
    ld [hl], b
    dec hl
    ld [hl+], a
    or b
    jr nz, jr_00f_5e5c

    inc a
    ld [hl], a

jr_00f_5e5c:
    ld hl, $5e88
    call Call_000_3c79
    ld b, $04
    ld a, $24
    call Call_000_3e9d
    ldh a, [$f3]
    and a
    jr nz, jr_00f_5e71

    jp Jump_00f_6499


jr_00f_5e71:
    jp Jump_00f_63db


    db $ed
    inc l
    sbc c
    ld [hl], e
    ld a, a
    ld e, d
    ret


    ld c, a
    cp d
    or e
    add hl, hl
    or a
    jp z, $ca7f

    dec l
    jp c, $e7c0

    ld e, b
    db $ed
    add hl, hl
    ld [hl], $70
    or d
    ld a, a
    or c
    rst $08
    rst $18
    jp $5a4f


    jp z, Jump_000_2c55

    jp nc, $c6de

    ld a, a
    inc a
    jp nz, $dfb6

    ret nz

    rst $20
    ld e, b
    db $ed
    dec l
    ld l, c
    ld e, l
    ld c, a
    ld l, $de
    ld l, $de
    or a
    or d
    jp $b2c5


    rst $20
    ld e, b
    ld hl, $5eb8
    jp Jump_000_3c79


    db $ed
    add hl, hl
    ld [hl], b
    ld [hl], b
    ld c, a
    cp d
    or e
    or [hl]
    ld h, $7f
    push bc
    or d
    ld a, a
    ret nc

    ret nz

    or d
    jr nc, @+$58

    ld e, b

Call_00f_5ecb:
    ld a, [$d03b]
    and a
    jr z, jr_00f_5ee4

    dec a
    add a
    ld hl, $5ee9
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    call Call_000_3c79
    xor a
    ld [$d03b], a

jr_00f_5ee4:
    ld c, $14
    jp Jump_000_3781


    db $ed
    ld e, [hl]
    ei
    ld e, [hl]
    db $ed
    inc l
    inc [hl]
    ld [hl], e
    cp h
    ld [c], a
    add $7f
    or c
    ret nz

    rst $18
    ret nz

    rst $20
    ld e, b
    nop
    or d
    pop bc
    add hl, hl
    or a
    ld a, a
    set 3, a
    cp e
    jp nz, $58e7

Call_00f_5f07:
    xor a
    ld [$cced], a
    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_5f16

    ld a, $01
    and a
    ret


jr_00f_5f16:
    ld hl, $d137
    ld bc, $002c
    ld a, [$cc2f]
    call Call_000_3ad1
    ld a, [$d2d8]
    cp [hl]
    jr nz, jr_00f_5f30

    inc hl
    ld a, [$d2d9]
    cp [hl]
    jp z, Jump_00f_6016

jr_00f_5f30:
    ld hl, $d2d5
    bit 7, [hl]
    ld a, $65
    jr nz, jr_00f_5f4d

    bit 5, [hl]
    ld a, $46
    jr nz, jr_00f_5f4d

    bit 3, [hl]
    ld a, $32
    jr nz, jr_00f_5f4d

    bit 1, [hl]
    ld a, $1e
    jr nz, jr_00f_5f4d

    ld a, $0a

jr_00f_5f4d:
    ld b, a
    ld c, a
    ld a, [$d009]
    ld d, a
    add b
    ld b, a
    jr nc, jr_00f_5f59

    ld b, $ff

jr_00f_5f59:
    ld a, c
    cp d
    jp nc, Jump_00f_6016

jr_00f_5f5e:
    call Call_00f_718d
    swap a
    cp b
    jr nc, jr_00f_5f5e

    cp c
    jp c, Jump_00f_6016

jr_00f_5f6a:
    call Call_00f_718d
    cp b
    jr nc, jr_00f_5f6a

    cp c
    jr c, jr_00f_5fbe

    ld a, d
    sub c
    ld b, a
    call Call_00f_718d
    swap a
    sub b
    jr c, jr_00f_5f8d

    cp b
    jr nc, jr_00f_5f9f

    ld hl, $6039
    call Call_000_3c79
    call Call_00f_5cd0
    jp Jump_00f_601a


jr_00f_5f8d:
    call Call_00f_718d
    add a
    swap a
    and $07
    jr z, jr_00f_5f8d

    ld [$cfff], a
    ld hl, $6029
    jr jr_00f_5fb9

jr_00f_5f9f:
    call Call_00f_718d
    and $03
    ld hl, $601c
    and a
    jr z, jr_00f_5fb9

    ld hl, $6039
    dec a
    jr z, jr_00f_5fb9

    ld hl, $604a
    dec a
    jr z, jr_00f_5fb9

    ld hl, $6059

jr_00f_5fb9:
    call Call_000_3c79
    jr jr_00f_601a

jr_00f_5fbe:
    ld a, [$d004]
    and a
    jr z, jr_00f_5f9f

    ld hl, $d014
    push hl
    ld a, [hl+]
    ld b, [hl]
    inc hl
    add b
    ld b, [hl]
    inc hl
    add b
    ld b, [hl]
    add b
    pop hl
    push af
    ld a, [$cc26]
    ld c, a
    ld b, $00
    add hl, bc
    ld b, [hl]
    pop af
    cp b
    jr z, jr_00f_5f9f

    ld a, $01
    ld [$cced], a
    ld a, [$cc28]
    ld b, a
    ld a, [$cc26]
    ld c, a

jr_00f_5fec:
    call Call_00f_718d
    and $03
    cp b
    jr nc, jr_00f_5fec

    cp c
    jr z, jr_00f_5fec

    ld [$cc26], a
    ld hl, $d014
    ld e, a
    ld d, $00
    add hl, de
    ld a, [hl]
    and a
    jr z, jr_00f_5fec

    ld a, [$cc26]
    ld c, a
    ld b, $00
    ld hl, $d003
    add hl, bc
    ld a, [hl]
    ld [$ccdc], a
    call Call_00f_6dae

Jump_00f_6016:
    ld a, $01
    and a
    ret


Jump_00f_601a:
jr_00f_601a:
    xor a
    ret


    ld bc, $cff0
    nop
    jp z, $c57f

    rst $08
    cp c
    jp $d9b2


    ld e, b
    db $ed
    add hl, hl
    or d
    ld [hl], b
    jp z, $cb7f

    reti


    ret z

    db $dd
    jp z, $d22c

    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    adc l
    ld [hl], b
    jp z, $b27f

    or e
    cp d
    call nz, $7fdd
    or a
    or [hl]
    push bc
    or d
    ld e, b
    ld bc, $cff0
    nop
    jp z, $bf7f

    rst $18
    ld c, b
    db $dd
    ld a, a
    pop de
    or d
    ret nz

    ld e, b
    db $ed
    add hl, hl
    rst $08
    ld [hl], b
    jp z, $bc7f

    rst $10
    sbc $46
    ret c

    db $dd
    cp h
    ret nz

    ld e, b

Call_00f_6068:
    xor a
    ld hl, $d0b4
    ld [hl+], a
    ld [hl], a
    ld hl, $cfbb
    ld a, [hl+]
    and a
    ld d, a
    ret z

    ld a, [hl]
    cp $14
    jr nc, jr_00f_60af

    ld hl, $cfdf
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld a, [$d046]
    bit 2, a
    jr z, jr_00f_608b

    sla c
    rl b

jr_00f_608b:
    ld hl, $d00c
    ld a, [$d03b]
    and a
    jr z, jr_00f_60e2

    ld c, $03
    call Call_00f_61b5
    ldh a, [$97]
    ld b, a
    ldh a, [$98]
    ld c, a
    push bc
    ld hl, $d14f
    ld a, [$cc2f]
    ld bc, $002c
    call Call_000_3ad1
    pop bc
    jr jr_00f_60e2

jr_00f_60af:
    ld hl, $cfe3
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld a, [$d046]
    bit 1, a
    jr z, jr_00f_60c0

    sla c
    rl b

jr_00f_60c0:
    ld hl, $d012
    ld a, [$d03b]
    and a
    jr z, jr_00f_60e2

    ld c, $05
    call Call_00f_61b5
    ldh a, [$97]
    ld b, a
    ldh a, [$98]
    ld c, a
    push bc
    ld hl, $d155
    ld a, [$cc2f]
    ld bc, $002c
    call Call_000_3ad1
    pop bc

jr_00f_60e2:
    ld a, [hl+]
    ld l, [hl]
    ld h, a
    or b
    jr z, jr_00f_60fd

    srl b
    rr c
    srl b
    rr c
    srl h
    rr l
    srl h
    rr l
    ld a, l
    or h
    jr nz, jr_00f_60fd

    inc l

jr_00f_60fd:
    ld b, l
    ld a, [$d009]
    ld e, a
    ld a, [$d03b]
    and a
    jr z, jr_00f_610a

    sla e

jr_00f_610a:
    ld a, $01
    and a
    ret


Call_00f_610e:
    ld hl, $d0b4
    xor a
    ld [hl+], a
    ld [hl], a
    ld hl, $cfb5
    ld a, [hl+]
    ld d, a
    and a
    ret z

    ld a, [hl]
    cp $14
    jr nc, jr_00f_6155

    ld hl, $d00e
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld a, [$d041]
    bit 2, a
    jr z, jr_00f_6131

    sla c
    rl b

jr_00f_6131:
    ld hl, $cfdd
    ld a, [$d03b]
    and a
    jr z, jr_00f_6188

    ld hl, $d151
    ld a, [$cc2f]
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    push bc
    ld c, $02
    call Call_00f_61b5
    ld hl, $ff97
    pop bc
    jr jr_00f_6188

jr_00f_6155:
    ld hl, $d012
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld a, [$d041]
    bit 1, a
    jr z, jr_00f_6166

    sla c
    rl b

jr_00f_6166:
    ld hl, $cfe3
    ld a, [$d03b]
    and a
    jr z, jr_00f_6188

    ld hl, $d155
    ld a, [$cc2f]
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    push bc
    ld c, $05
    call Call_00f_61b5
    ld hl, $ff97
    pop bc

jr_00f_6188:
    ld a, [hl+]
    ld l, [hl]
    ld h, a
    or b
    jr z, jr_00f_61a3

    srl b
    rr c
    srl b
    rr c
    srl h
    rr l
    srl h
    rr l
    ld a, l
    or h
    jr nz, jr_00f_61a3

    inc l

jr_00f_61a3:
    ld b, l
    ld a, [$cfda]
    ld e, a
    ld a, [$d03b]
    and a
    jr z, jr_00f_61b0

    sla e

jr_00f_61b0:
    ld a, $01
    and a
    and a
    ret


Call_00f_61b5:
    push de
    push bc
    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_61d9

    ld hl, $d845
    dec c
    sla c
    ld b, $00
    add hl, bc
    ld a, [$cfcf]
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl+]
    ldh [$97], a
    ld a, [hl]
    ldh [$98], a
    pop bc
    pop de
    ret


jr_00f_61d9:
    ld a, [$cfda]
    ld [$d0ec], a
    ld a, [$cfcc]
    ld [$d092], a
    call Call_000_2f2e
    ld hl, $cfd8
    ld de, $cf96
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    pop bc
    ld b, $00
    ld hl, $cf8b
    call Call_000_3994
    pop de
    ret


Call_00f_61fe:
    ldh a, [$f3]
    and a
    ld a, [$cfba]
    jr z, jr_00f_6209

    ld a, [$cfb4]

jr_00f_6209:
    cp $07
    jr nz, jr_00f_6212

    srl c
    jr nz, jr_00f_6212

    inc c

jr_00f_6212:
    cp $1d
    jr z, jr_00f_6222

    cp $1e
    jr z, jr_00f_6222

    cp $26
    jp z, Jump_00f_62af

    ld a, d
    and a
    ret z

jr_00f_6222:
    xor a
    ld hl, $ff95
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld a, e
    add a
    jr nc, jr_00f_6232

    push af
    ld a, $01
    ld [hl], a
    pop af

jr_00f_6232:
    inc hl
    ld [hl+], a
    ld a, $05
    ld [hl-], a
    push bc
    ld b, $04
    call Call_000_3902
    pop bc
    inc [hl]
    inc [hl]
    inc hl
    ld [hl], d
    call Call_000_38f5
    ld [hl], b
    call Call_000_38f5
    ld [hl], c
    ld b, $04
    call Call_000_3902
    ld [hl], $32
    ld b, $04
    call Call_000_3902
    ld hl, $d0b4
    ld b, [hl]
    ldh a, [$98]
    add b
    ldh [$98], a
    jr nc, jr_00f_6269

    ldh a, [$97]
    inc a
    ldh [$97], a
    and a
    jr z, jr_00f_629d

jr_00f_6269:
    ldh a, [$95]
    ld b, a
    ldh a, [$96]
    or a
    jr nz, jr_00f_629d

    ldh a, [$97]
    cp $03
    jr c, jr_00f_6281

    cp $04
    jr nc, jr_00f_629d

    ldh a, [$98]
    cp $e6
    jr nc, jr_00f_629d

jr_00f_6281:
    inc hl
    ldh a, [$98]
    ld b, [hl]
    add b
    ld [hl-], a
    ldh a, [$97]
    ld b, [hl]
    adc b
    ld [hl], a
    jr c, jr_00f_629d

    ld a, [hl]
    cp $03
    jr c, jr_00f_62a3

    cp $04
    jr nc, jr_00f_629d

    inc hl
    ld a, [hl-]
    cp $e6
    jr c, jr_00f_62a3

jr_00f_629d:
    ld a, $03
    ld [hl+], a
    ld a, $e5
    ld [hl-], a

jr_00f_62a3:
    inc hl
    ld a, [hl]
    add $02
    ld [hl-], a
    jr nc, jr_00f_62ab

    inc [hl]

jr_00f_62ab:
    ld a, $01
    and a
    ret


Jump_00f_62af:
    call Call_00f_7427
    ld a, [$d03c]
    dec a
    ret


    ld [bc], a
    ld c, e
    sbc b
    and e
    rst $38

Call_00f_62bc:
    xor a
    ld [$d03b], a
    ldh a, [$f3]
    and a
    ld a, [$cfcc]
    jr nz, jr_00f_62cb

    ld a, [$cffb]

jr_00f_62cb:
    ld [$d092], a
    call Call_000_2f2e
    ld a, [$d099]
    ld b, a
    srl b
    ldh a, [$f3]
    and a
    ld hl, $cfbb
    ld de, $d040
    jr z, jr_00f_62e8

    ld hl, $cfb5
    ld de, $d045

jr_00f_62e8:
    ld a, [hl-]
    and a
    ret z

    dec hl
    ld c, [hl]
    ld a, [de]
    bit 2, a
    jr nz, jr_00f_62fa

    sla b
    jr nc, jr_00f_62fc

    ld b, $ff
    jr jr_00f_62fc

jr_00f_62fa:
    srl b

jr_00f_62fc:
    ld hl, $6327

jr_00f_62ff:
    ld a, [hl+]
    cp c
    jr z, jr_00f_630a

    inc a
    jr nz, jr_00f_62ff

    srl b
    jr jr_00f_6316

jr_00f_630a:
    sla b
    jr nc, jr_00f_6310

    ld b, $ff

jr_00f_6310:
    sla b
    jr nc, jr_00f_6316

    ld b, $ff

jr_00f_6316:
    call Call_00f_718d
    rlc a
    rlc a
    rlc a
    cp b
    ret nc

    ld a, $01
    ld [$d03b], a
    ret


    ld [bc], a
    ld c, e
    sbc b
    and e
    rst $38

Call_00f_632c:
    ldh a, [$f3]
    and a
    ld hl, $ccdd
    ld de, $cfb5
    ld a, [$ccdc]
    jr z, jr_00f_6343

    ld hl, $ccdc
    ld de, $cfbb
    ld a, [$ccdd]

jr_00f_6343:
    cp $44
    ret nz

    ld a, $01
    ld [$d03c], a
    ld a, [hl]
    cp $44
    ret z

    ld a, [de]
    and a
    ret z

    inc de
    ld a, [de]
    and a
    jr z, jr_00f_635d

    cp $01
    jr z, jr_00f_635d

    xor a
    ret


jr_00f_635d:
    ld hl, $d0b4
    ld a, [hl+]
    or [hl]
    ret z

    ld a, [hl]
    add a
    ld [hl-], a
    ld a, [hl]
    adc a
    ld [hl], a
    jr nc, jr_00f_636f

    ld a, $ff
    ld [hl+], a
    ld [hl], a

jr_00f_636f:
    xor a
    ld [$d03c], a
    call Call_00f_684d
    xor a
    ret


Call_00f_6378:
    ld a, [$cfba]
    cp $26
    jr z, jr_00f_63db

    cp $28
    jr z, jr_00f_6390

    cp $29
    jr z, jr_00f_63a8

    ld a, [$cfbb]
    and a
    jp z, Jump_00f_6436

    jr jr_00f_63db

jr_00f_6390:
    ld hl, $cfcd
    ld de, $d0b4
    ld a, [hl+]
    srl a
    ld [de], a
    inc de
    ld b, a
    ld a, [hl]
    rr a
    ld [de], a
    or b
    jr nz, jr_00f_63db

    ld a, $01
    ld [de], a
    jr jr_00f_63db

jr_00f_63a8:
    ld hl, $d009
    ld a, [hl]
    ld b, a
    ld a, [$cfb9]
    cp $45
    jr z, jr_00f_63d4

    cp $65
    jr z, jr_00f_63d4

    ld b, $14
    cp $31
    jr z, jr_00f_63d4

    ld b, $28
    cp $52
    jr z, jr_00f_63d4

    ld a, [hl]
    ld b, a
    srl a
    add b
    ld b, a

jr_00f_63ca:
    call Call_00f_718d
    and a
    jr z, jr_00f_63ca

    cp b
    jr nc, jr_00f_63ca

    ld b, a

jr_00f_63d4:
    ld hl, $d0b4
    xor a
    ld [hl+], a
    ld a, b
    ld [hl], a

Call_00f_63db:
Jump_00f_63db:
jr_00f_63db:
    ld hl, $d0b4
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    or b
    jr z, jr_00f_6436

    ld a, [$d045]
    bit 4, a
    jp nz, Jump_00f_64f7

    ld a, [hl-]
    ld b, a
    ld a, [$cfce]
    ld [$cee6], a
    sub b
    ld [$cfce], a
    ld a, [hl]
    ld b, a
    ld a, [$cfcd]
    ld [$cee7], a
    sbc b
    ld [$cfcd], a
    jr nc, jr_00f_6414

    ld a, [$cee7]
    ld [hl+], a
    ld a, [$cee6]
    ld [hl], a
    xor a
    ld hl, $cfcd
    ld [hl+], a
    ld [hl], a

jr_00f_6414:
    ld hl, $cfdb
    ld a, [hl+]
    ld [$cee5], a
    ld a, [hl]
    ld [$cee4], a
    ld hl, $cfcd
    ld a, [hl+]
    ld [$cee9], a
    ld a, [hl]
    ld [$cee8], a
    ld hl, $c3ca
    xor a
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d

Jump_00f_6436:
jr_00f_6436:
    jp Jump_00f_4eb8


Call_00f_6439:
    ld a, [$cfb4]
    cp $26
    jr z, jr_00f_6499

    cp $28
    jr z, jr_00f_6451

    cp $29
    jr z, jr_00f_6469

    ld a, [$cfb5]
    and a
    jp z, Jump_00f_64f4

    jr jr_00f_6499

jr_00f_6451:
    ld hl, $cffc
    ld de, $d0b4
    ld a, [hl+]
    srl a
    ld [de], a
    inc de
    ld b, a
    ld a, [hl]
    rr a
    ld [de], a
    or b
    jr nz, jr_00f_6499

    ld a, $01
    ld [de], a
    jr jr_00f_6499

jr_00f_6469:
    ld hl, $cfda
    ld a, [hl]
    ld b, a
    ld a, [$cfb3]
    cp $45
    jr z, jr_00f_6492

    cp $65
    jr z, jr_00f_6492

    ld b, $14
    cp $31
    jr z, jr_00f_6492

    ld b, $28
    cp $52
    jr z, jr_00f_6492

    ld a, [hl]
    ld b, a
    srl a
    add b
    ld b, a

jr_00f_648b:
    call Call_00f_718d
    cp b
    jr nc, jr_00f_648b

    ld b, a

jr_00f_6492:
    ld hl, $d0b4
    xor a
    ld [hl+], a
    ld a, b
    ld [hl], a

Jump_00f_6499:
jr_00f_6499:
    ld hl, $d0b4
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    or b
    jr z, jr_00f_64f4

    ld a, [$d040]
    bit 4, a
    jp nz, Jump_00f_64f7

    ld a, [hl-]
    ld b, a
    ld a, [$cffd]
    ld [$cee6], a
    sub b
    ld [$cffd], a
    ld [$cee8], a
    ld b, [hl]
    ld a, [$cffc]
    ld [$cee7], a
    sbc b
    ld [$cffc], a
    ld [$cee9], a
    jr nc, jr_00f_64dc

    ld a, [$cee7]
    ld [hl+], a
    ld a, [$cee6]
    ld [hl], a
    xor a
    ld hl, $cffc
    ld [hl+], a
    ld [hl], a
    ld hl, $cee8
    ld [hl+], a
    ld [hl], a

jr_00f_64dc:
    ld hl, $d00a
    ld a, [hl+]
    ld [$cee5], a
    ld a, [hl]
    ld [$cee4], a
    ld hl, $c45e
    ld a, $01
    ld [$cf7b], a
    ld a, $48
    call Call_000_3e9d

Jump_00f_64f4:
jr_00f_64f4:
    jp Jump_00f_4eb8


Jump_00f_64f7:
    ld hl, $6545
    call Call_000_3c79
    ld de, $ccd8
    ld bc, $d045
    ldh a, [$f3]
    and a
    jr z, jr_00f_650e

    ld de, $ccd7
    ld bc, $d040

jr_00f_650e:
    ld hl, $d0b4
    ld a, [hl+]
    and a
    jr nz, jr_00f_6519

    ld a, [de]
    sub [hl]
    ld [de], a
    ret nc

jr_00f_6519:
    ld h, b
    ld l, c
    res 4, [hl]
    ld hl, $655f
    call Call_000_3c79
    ldh a, [$f3]
    xor $01
    ldh [$f3], a
    ld hl, $577e
    ld b, $1e
    call Call_000_3620
    ldh a, [$f3]
    xor $01
    ldh [$f3], a
    ld hl, $cfba
    and a
    jr z, jr_00f_6540

    ld hl, $cfb4

jr_00f_6540:
    xor a
    ld [hl], a
    jp Jump_00f_4eb8


    db $ed
    add hl, hl
    db $ec
    ld [hl], b
    or [hl]
    call c, $c3df
    ld c, a
    inc a
    sbc $bc
    sbc $26
    ld a, a
    cp d
    or e
    add hl, hl
    or a
    db $dd
    ld a, a
    or e
    cp c
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    rrca
    ld [hl], c
    inc a
    sbc $bc
    sbc $ca
    ld c, a
    or a
    or h
    jp $cfbc


    rst $18
    ret nz

    ld d, [hl]
    ld e, b

Call_00f_6572:
    ld hl, $d045
    ld de, $cd2e
    ld bc, $cfb3
    ldh a, [$f3]
    and a
    jr z, jr_00f_6589

    ld hl, $d040
    ld de, $cd1a
    ld bc, $cfb9

jr_00f_6589:
    bit 6, [hl]
    ret z

    ld a, [de]
    cp $0d
    ret z

    ldh a, [$f3]
    xor $01
    ldh [$f3], a
    ld h, b
    ld l, c
    ld [hl], $00
    inc hl
    ld [hl], $0a
    push hl
    ld hl, $65b4
    call Call_000_3c79
    call Call_00f_7762
    pop hl
    xor a
    ld [hl-], a
    ld a, $63
    ld [hl], a
    ldh a, [$f3]
    xor $01
    ldh [$f3], a
    ret


    db $ed
    add hl, hl
    jr nc, jr_00f_6629

    or d
    or [hl]
    ret c

    ret


    ld c, a
    inc e
    and [hl]
    sub d
    db $e3
    dec bc
    ld h, $7f
    or c
    ld h, $df
    jp $b8b2


    rst $20
    ld e, b

Call_00f_65cc:
    ldh a, [$f3]
    and a
    ld a, [$ccf2]
    ld hl, $ccdc
    ld de, $cfb9
    jr z, jr_00f_65e3

    ld a, [$ccf1]
    ld de, $cfb3
    ld hl, $ccdd

jr_00f_65e3:
    ld [hl], a
    cp $77
    jr z, jr_00f_65eb

    and a
    jr nz, jr_00f_660b

jr_00f_65eb:
    ld hl, $65f3
    call Call_000_3c79
    xor a
    ret


    db $ed
    add hl, hl
    ld d, l
    ld [hl], c
    ld a, a
    add h
    add d
    sbc a
    ld h, $b4
    cp h
    jp z, $bc4e

    rst $18
    ld b, h
    or d
    add $b5
    call c, $c0df
    rst $20
    ld e, b

jr_00f_660b:
    ld [$d0e3], a
    dec a
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld a, $0e
    call Call_000_01a3
    call Call_00f_6655
    call Call_000_1b6d
    call Call_000_386e
    ld a, $01
    and a

jr_00f_6629:
    ret


Call_00f_662a:
    xor a
    ld [$cc5b], a
    ld a, $76
    call Call_00f_71f9
    ld de, $cfb9
    ld hl, $ccdc
    ldh a, [$f3]
    and a
    jr z, jr_00f_6644

    ld de, $cfb3
    ld hl, $ccdd

jr_00f_6644:
    call Call_00f_718d
    and a
    jr z, jr_00f_6644

    cp $a5
    jr nc, jr_00f_6644

    cp $76
    jr z, jr_00f_6644

    ld [hl], a
    jr jr_00f_660b

Call_00f_6655:
    ldh a, [$f3]
    and a
    ld hl, $d014
    ld de, $d148
    ld a, [$cc2e]
    jr z, jr_00f_666c

    ld hl, $cfe5
    ld de, $d840
    ld a, [$cce2]

jr_00f_666c:
    ld b, $00
    ld c, a
    add hl, bc
    inc [hl]
    ld h, d
    ld l, e
    add hl, bc
    ldh a, [$f3]
    and a
    ld a, [$cc2f]
    jr z, jr_00f_667f

    ld a, [$cfcf]

jr_00f_667f:
    ld bc, $002c
    call Call_000_3ad1
    inc [hl]
    ret


Call_00f_6687:
    ld hl, $d000
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld hl, $cfd1
    ld a, [hl+]
    ld d, a
    ld e, [hl]
    ld a, [$cfbc]
    ld [$d0e3], a
    ldh a, [$f3]
    and a
    jr z, jr_00f_66b0

    ld hl, $cfd1
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld hl, $d000
    ld a, [hl+]
    ld d, a
    ld e, [hl]
    ld a, [$cfb6]
    ld [$d0e3], a

jr_00f_66b0:
    ld a, [$d0e3]
    cp b
    jr z, jr_00f_66bb

    cp c
    jr z, jr_00f_66bb

    jr jr_00f_66d5

jr_00f_66bb:
    ld hl, $d0b5
    ld a, [hl-]
    ld h, [hl]
    ld l, a
    ld b, h
    ld c, l
    srl b
    rr c
    add hl, bc
    ld a, h
    ld [$d0b4], a
    ld a, l
    ld [$d0b5], a
    ld hl, $d038
    set 7, [hl]

jr_00f_66d5:
    ld a, [$d0e3]
    ld b, a
    ld hl, $6756

Jump_00f_66dc:
    ld a, [hl+]
    cp $ff
    jr z, jr_00f_672a

    cp b
    jr nz, jr_00f_6725

    ld a, [hl]
    cp d
    jr z, jr_00f_66ed

    cp e
    jr z, jr_00f_66ed

    jr jr_00f_6725

jr_00f_66ed:
    push hl
    push bc
    inc hl
    ld a, [$d038]
    and $80
    ld b, a
    ld a, [hl]
    ldh [$99], a
    add b
    ld [$d038], a
    xor a
    ldh [$96], a
    ld hl, $d0b4
    ld a, [hl+]
    ldh [$97], a
    ld a, [hl-]
    ldh [$98], a
    call Call_000_38f5
    ld a, $0a
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$97]
    ld [hl+], a
    ld b, a
    ldh a, [$98]
    ld [hl], a
    or b
    jr nz, jr_00f_6723

    inc a
    ld [$d03c], a

jr_00f_6723:
    pop bc
    pop hl

jr_00f_6725:
    inc hl
    inc hl
    jp Jump_00f_66dc


jr_00f_672a:
    ret


    ld a, [$cfb6]
    ld d, a
    ld hl, $d000
    ld b, [hl]
    inc hl
    ld c, [hl]
    ld a, $10
    ld [$d0e3], a
    ld hl, $6756

jr_00f_673d:
    ld a, [hl+]
    cp $ff
    ret z

    cp d
    jr nz, jr_00f_674d

    ld a, [hl+]
    cp b
    jr z, jr_00f_6751

    cp c
    jr z, jr_00f_6751

    jr jr_00f_674e

jr_00f_674d:
    inc hl

jr_00f_674e:
    inc hl
    jr jr_00f_673d

jr_00f_6751:
    ld a, [hl]
    ld [$d0e3], a
    ret


    dec d
    inc d
    inc d
    inc d
    ld d, $14
    inc d
    add hl, de
    inc d
    ld d, $15
    inc d
    rla
    dec d
    inc d
    dec d
    dec b
    inc d
    inc b
    ld [bc], a
    nop
    dec d
    dec d
    dec b
    inc d
    inc d
    dec b
    rla
    rla
    dec b
    add hl, de
    add hl, de
    dec b
    ld d, $16
    dec b
    jr jr_00f_6794

    dec b
    inc d
    dec d
    dec b
    ld d, $14
    dec b
    dec d
    ld d, $05
    rla
    ld d, $05
    nop
    dec b
    dec b
    nop
    ld [$0800], sp
    ld [$1414], sp
    rlca

jr_00f_6794:
    inc d
    inc d
    dec b
    dec b
    dec d
    inc b
    inc d
    rla
    inc b
    nop
    rla
    ld [bc], a
    inc d
    ld d, $04
    inc d
    ld d, $07
    dec b
    ld d, $03
    dec b
    ld d, $05
    inc d
    ld d, $02
    dec b
    add hl, de
    dec d
    dec b
    add hl, de
    ld d, $14
    add hl, de
    inc b
    inc d
    add hl, de
    ld [bc], a
    inc d
    ld bc, $1400
    ld bc, $0503
    ld bc, $0502
    ld bc, $0518
    ld bc, $0507
    ld bc, $1405
    ld bc, $1419
    ld bc, $0008
    inc bc
    ld d, $14
    inc bc
    inc bc
    dec b
    inc bc
    inc b
    dec b
    inc bc
    rlca
    inc d
    inc bc
    dec b
    dec b
    inc bc
    ld [$0405], sp
    inc d
    inc d
    inc b
    rla
    inc d
    inc b
    ld d, $05
    inc b
    rlca
    dec b
    inc b
    dec b
    inc d
    inc b
    inc bc
    inc d
    ld [bc], a
    rla
    dec b
    ld [bc], a
    ld bc, $0214
    rlca
    inc d
    ld [bc], a
    ld d, $14
    ld [bc], a
    dec b
    dec b
    jr jr_00f_680a

    inc d

jr_00f_680a:
    jr jr_00f_680f

    inc d
    rlca
    inc d

jr_00f_680f:
    dec b
    rlca
    ld d, $14
    rlca
    ld bc, $0705
    ld [bc], a
    dec b
    rlca
    jr jr_00f_6830

    rlca
    ld [$0705], sp
    inc bc
    inc d
    dec b
    inc d
    inc d
    dec b
    ld bc, $0505
    inc b
    dec b
    dec b
    ld [bc], a
    inc d
    dec b
    rlca

jr_00f_6830:
    inc d
    dec b
    add hl, de
    inc d
    ld [$0000], sp
    ld [$0018], sp
    inc d
    ld a, [de]
    dec b
    dec d
    ld a, [de]
    dec b
    rla
    ld a, [de]
    dec b
    ld d, $1a
    dec b
    add hl, de
    ld a, [de]
    inc d
    ld a, [de]
    ld a, [de]
    inc d
    rst $38

Call_00f_684d:
    ld hl, $d044
    ld de, $cfba
    ld bc, $cfd0
    ldh a, [$f3]
    and a
    jr z, jr_00f_6864

    ld hl, $d03f
    ld de, $cfb4
    ld bc, $cfff

jr_00f_6864:
    ld a, [de]
    cp $08
    jr nz, jr_00f_686f

    ld a, [bc]
    and $07
    jp z, Jump_00f_68eb

jr_00f_686f:
    call Call_00f_7fac
    jr z, jr_00f_6882

    ld a, [de]
    cp $11
    ret z

    cp $03
    jp z, Jump_00f_68eb

    cp $08
    jp z, Jump_00f_68eb

jr_00f_6882:
    bit 6, [hl]
    jp nz, Jump_00f_68eb

    ldh a, [$f3]
    and a
    jr nz, jr_00f_68b1

    ld a, [$cfba]
    cp $12
    jr c, jr_00f_68a9

    cp $1a
    jr c, jr_00f_68a1

    cp $3a
    jr c, jr_00f_68a9

    cp $42
    jr c, jr_00f_68a1

    jr jr_00f_68a9

jr_00f_68a1:
    ld a, [$d045]
    bit 1, a
    jp nz, Jump_00f_68eb

jr_00f_68a9:
    ld a, [$d040]
    bit 0, a
    ret nz

    jr jr_00f_68d4

jr_00f_68b1:
    ld a, [$cfb4]
    cp $12
    jr c, jr_00f_68ce

    cp $1a
    jr c, jr_00f_68c6

    cp $3a
    jr c, jr_00f_68ce

    cp $42
    jr c, jr_00f_68c6

    jr jr_00f_68ce

jr_00f_68c6:
    ld a, [$d040]
    bit 1, a
    jp nz, Jump_00f_68eb

jr_00f_68ce:
    ld a, [$d045]
    bit 0, a
    ret nz

jr_00f_68d4:
    call Call_00f_6906
    ld a, [$cfbd]
    ld b, a
    ldh a, [$f3]
    and a
    jr z, jr_00f_68e4

    ld a, [$cfb7]
    ld b, a

jr_00f_68e4:
    call Call_00f_718d
    cp b
    jr nc, jr_00f_68eb

    ret


Jump_00f_68eb:
jr_00f_68eb:
    xor a
    ld hl, $d0b4
    ld [hl+], a
    ld [hl], a
    inc a
    ld [$d03c], a
    ldh a, [$f3]
    and a
    jr z, jr_00f_6900

    ld hl, $d044
    res 5, [hl]
    ret


jr_00f_6900:
    ld hl, $d03f
    res 5, [hl]
    ret


Call_00f_6906:
    ld hl, $cfbd
    ldh a, [$f3]
    and a
    ld a, [$cd1e]
    ld b, a
    ld a, [$cd33]
    ld c, a
    jr z, jr_00f_6921

    ld hl, $cfb7
    ld a, [$cd32]
    ld b, a
    ld a, [$cd1f]
    ld c, a

jr_00f_6921:
    ld a, $0e
    sub c
    ld c, a
    xor a
    ldh [$96], a
    ldh [$97], a
    ld a, [hl]
    ldh [$98], a
    push hl
    ld d, $02

jr_00f_6930:
    push bc
    ld hl, $7a20
    dec b
    sla b
    ld c, b
    ld b, $00
    add hl, bc
    pop bc
    ld a, [hl+]
    ldh [$99], a
    call Call_000_38f5
    ld a, [hl]
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$98]
    ld b, a
    ldh a, [$97]
    or b
    jp nz, Jump_00f_6959

    ldh [$97], a
    ld a, $01
    ldh [$98], a

Jump_00f_6959:
    ld b, c
    dec d
    jr nz, jr_00f_6930

    ldh a, [$97]
    and a
    ldh a, [$98]
    jr z, jr_00f_6966

    ld a, $ff

jr_00f_6966:
    pop hl
    ld [hl], a
    ret


Call_00f_6969:
    ld hl, $d0b4
    ld a, [hl+]
    and a
    jr nz, jr_00f_6974

    ld a, [hl]
    cp $02
    ret c

jr_00f_6974:
    xor a
    ldh [$96], a
    dec hl
    ld a, [hl+]
    ldh [$97], a
    ld a, [hl]
    ldh [$98], a

jr_00f_697e:
    call Call_00f_718d
    rrca
    cp $d9
    jr c, jr_00f_697e

    ldh [$99], a
    call Call_000_38f5
    ld a, $ff
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    ldh a, [$97]
    ld hl, $d0b4
    ld [hl+], a
    ldh a, [$98]
    ld [hl], a
    ret


Call_00f_699e:
    ld a, [$ccdd]
    inc a
    jp z, Jump_00f_6b7b

    call Call_00f_5951
    jp z, Jump_00f_6b7b

    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_69be

    ld b, $01
    ld a, [$cc3e]
    cp $0e
    jr z, jr_00f_69be

    cp $04
    ret nc

jr_00f_69be:
    ld hl, $ccd5
    inc [hl]
    xor a
    ld [$d03c], a
    ld [$ccf4], a
    ld a, $0a
    ld [$d038], a
    call Call_00f_6b7e
    jr nz, jr_00f_69d4

    jp hl


jr_00f_69d4:
    ld hl, $d044
    bit 4, [hl]
    jr nz, jr_00f_69ed

    call Call_00f_6dae

Jump_00f_69de:
    ld a, [$cfb4]
    cp $27
    jp z, Jump_00f_7427

    cp $2b
    jp z, Jump_00f_7427

    jr jr_00f_6a0d

jr_00f_69ed:
    ld hl, $d044
    res 4, [hl]
    res 6, [hl]
    ld a, [$cfb3]
    ld [$d092], a
    ld a, $04
    ld [$d094], a
    ld a, $02
    ld [$d093], a
    call Call_000_37b3
    ld de, $cd68
    call Call_000_386e

jr_00f_6a0d:
    xor a
    ld [$cced], a
    call Call_00f_5d18
    ld a, [$cfb4]
    ld hl, $4000
    ld de, $0001
    call Call_000_3ddb
    jp c, Jump_00f_7427

    ld a, [$cfb4]
    ld hl, $4049
    ld de, $0001
    call Call_000_3ddb
    call c, Call_00f_7427
    call Call_00f_6f71
    ld a, [$cfb4]
    ld hl, $4011
    ld de, $0001
    call Call_000_3ddb
    jp c, Jump_00f_6a61

    call Call_00f_62bc
    call Call_00f_632c
    jr z, jr_00f_6a64

    call Call_00f_6f71
    call Call_00f_610e
    call Call_00f_6f71
    call Call_00f_61fe
    jp z, Jump_00f_6ab3

    call Call_00f_6687
    call Call_00f_6969

Jump_00f_6a61:
    call Call_00f_684d

jr_00f_6a64:
    ld a, [$d03c]
    and a
    jr z, jr_00f_6a73

    ld a, [$cfb4]
    cp $07
    jr z, jr_00f_6a82

    jr jr_00f_6ab3

jr_00f_6a73:
    call Call_00f_6f71

Jump_00f_6a76:
    ld a, [$cfb4]
    and a
    ld a, $01
    jr z, jr_00f_6a86

    ld a, $02
    jr jr_00f_6a86

jr_00f_6a82:
    call Call_00f_6f71
    xor a

jr_00f_6a86:
    push af
    ld a, [$d045]
    bit 4, a
    ld hl, $577e
    ld b, $1e
    call nz, Call_000_3620
    pop af
    ld [$cc5b], a
    ld a, [$cfb3]
    call Call_00f_71f9
    call Call_00f_71c5
    call Call_00f_4f49
    ld a, [$d045]
    bit 4, a
    ld hl, $57a8
    ld b, $1e
    call nz, Call_000_3620
    jr jr_00f_6ad1

Jump_00f_6ab3:
jr_00f_6ab3:
    call Call_00f_6f71
    ld c, $1e
    call Call_000_3781
    ld a, [$cfb4]
    cp $2b
    jr z, jr_00f_6ac8

    cp $27
    jr z, jr_00f_6ac8

    jr jr_00f_6ad1

jr_00f_6ac8:
    xor a
    ld [$cc5b], a
    ld a, $a7
    call Call_00f_71f9

jr_00f_6ad1:
    ld a, [$cfb4]
    cp $09
    jr nz, jr_00f_6ae1

    call Call_00f_65cc
    jp z, Jump_00f_6b7b

    jp Jump_00f_69de


jr_00f_6ae1:
    cp $53
    jr nz, jr_00f_6aeb

    call Call_00f_662a
    jp Jump_00f_69de


jr_00f_6aeb:
    ld a, [$cfb4]
    ld hl, $4014
    ld de, $0001
    call Call_000_3ddb
    jp c, Jump_00f_7427

    ld a, [$d03c]
    and a
    jr z, jr_00f_6b0d

    call Call_00f_5e14
    ld a, [$cfb4]
    cp $07
    jr z, jr_00f_6b20

    jp Jump_00f_6b7b


jr_00f_6b0d:
    call Call_00f_6439
    call Call_00f_5ecb
    ld hl, $7eb2
    ld b, $0b
    call Call_000_3620
    ld a, $01
    ld [$ccf4], a

jr_00f_6b20:
    ld a, [$cfb4]
    ld hl, $4030
    ld de, $0001
    call Call_000_3ddb
    call c, Call_00f_7427
    ld hl, $cffc
    ld a, [hl+]
    ld b, [hl]
    or b
    ret z

    call Call_00f_6572
    ld hl, $d044
    bit 2, [hl]
    jr z, jr_00f_6b55

    push hl
    ld hl, $d04c
    dec [hl]
    pop hl
    jp nz, Jump_00f_6a76

    res 2, [hl]
    ld hl, $6b69
    call Call_000_3c79
    xor a
    ld [$cd05], a

jr_00f_6b55:
    ld a, [$cfb4]
    and a
    jr z, jr_00f_6b7b

    ld hl, $403b
    ld de, $0001
    call Call_000_3ddb
    call nc, Call_00f_7427
    jr jr_00f_6b7b

    db $ed
    add hl, hl
    add l
    ld [hl], c
    nop
    or [hl]
    or d
    ld a, a
    rrca
    and b
    db $e3
    dec bc
    db $dd
    or e
    cp c
    ret nz

    rst $20
    ld e, b

Jump_00f_6b7b:
jr_00f_6b7b:
    ld b, $01
    ret


Call_00f_6b7e:
    ld hl, $cfd0
    ld a, [hl]
    and $07
    jr z, jr_00f_6bae

    dec a
    ld [$cfd0], a
    and a
    jr z, jr_00f_6b9e

    ld hl, $5ba5
    call Call_000_3c79
    xor a
    ld [$cc5b], a
    ld a, $bd
    call Call_00f_71f9
    jr jr_00f_6ba4

jr_00f_6b9e:
    ld hl, $5bb5
    call Call_000_3c79

jr_00f_6ba4:
    xor a
    ld [$ccf2], a
    ld hl, $6b7b
    jp Jump_00f_6da8


jr_00f_6bae:
    bit 5, [hl]
    jr z, jr_00f_6bc2

    ld hl, $5bc1
    call Call_000_3c79
    xor a
    ld [$ccf2], a
    ld hl, $6b7b
    jp Jump_00f_6da8


jr_00f_6bc2:
    ld a, [$d03f]
    bit 5, a
    jp z, Jump_00f_6bd6

    ld hl, $5c89
    call Call_000_3c79
    ld hl, $6b7b
    jp Jump_00f_6da8


Jump_00f_6bd6:
    ld hl, $d044
    bit 3, [hl]
    jp z, Jump_00f_6bec

    res 3, [hl]
    ld hl, $5bea
    call Call_000_3c79
    ld hl, $6b7b
    jp Jump_00f_6da8


Jump_00f_6bec:
    ld hl, $d045
    bit 5, [hl]
    jr z, jr_00f_6c01

    res 5, [hl]
    ld hl, $5bf4
    call Call_000_3c79
    ld hl, $6b7b
    jp Jump_00f_6da8


jr_00f_6c01:
    ld hl, $d04f
    ld a, [hl]
    and a
    jr z, jr_00f_6c18

    dec a
    ld [hl], a
    and $0f
    jr nz, jr_00f_6c18

    ld [hl], a
    ld [$ccef], a
    ld hl, $5c0b
    call Call_000_3c79

jr_00f_6c18:
    ld a, [$d044]
    bit 7, a
    jp z, Jump_00f_6c9a

    ld hl, $d04d
    dec [hl]
    jr nz, jr_00f_6c34

    ld hl, $d044
    res 7, [hl]
    ld hl, $5c40
    call Call_000_3c79
    jp Jump_00f_6c9a


jr_00f_6c34:
    ld hl, $5c1b
    call Call_000_3c79
    xor a
    ld [$cc5b], a
    ld a, $bf
    call Call_00f_71f9
    call Call_00f_718d
    cp $80
    jr c, jr_00f_6c9a

    ld hl, $d044
    ld a, [hl]
    and $80
    ld [hl], a
    ld hl, $5c29
    call Call_000_3c79
    ld hl, $d00e
    ld a, [hl+]
    push af
    ld a, [hl-]
    push af
    ld a, [$cfdf]
    ld [hl+], a
    ld a, [$cfe0]
    ld [hl], a
    ld hl, $cfb4
    push hl
    ld a, [hl]
    push af
    xor a
    ld [hl+], a
    ld [$d03b], a
    ld a, $28
    ld [hl+], a
    xor a
    ld [hl], a
    call Call_00f_610e
    call Call_00f_61fe
    pop af
    pop hl
    ld [hl], a
    ld hl, $d00f
    pop af
    ld [hl-], a
    pop af
    ld [hl], a
    xor a
    ld [$cc5b], a
    ldh [$f3], a
    ld a, $01
    call Call_00f_71f9
    ld a, $01
    ldh [$f3], a
    call Call_00f_63db
    jr jr_00f_6cc3

Jump_00f_6c9a:
jr_00f_6c9a:
    ld a, [$ccef]
    and a
    jr z, jr_00f_6caf

    ld hl, $ccdd
    cp [hl]
    jr nz, jr_00f_6caf

    call Call_00f_5c99
    ld hl, $6b7b
    jp Jump_00f_6da8


jr_00f_6caf:
    ld hl, $cfd0
    bit 6, [hl]
    jr z, jr_00f_6ce6

    call Call_00f_718d
    cp $3f
    jr nc, jr_00f_6ce6

    ld hl, $5bd6
    call Call_000_3c79

jr_00f_6cc3:
    ld hl, $d044
    ld a, [hl]
    and $cc
    ld [hl], a
    ld a, [$cfb4]
    cp $2b
    jr z, jr_00f_6cd7

    cp $27
    jr z, jr_00f_6cd7

    jr jr_00f_6ce0

jr_00f_6cd7:
    xor a
    ld [$cc5b], a
    ld a, $a7
    call Call_00f_71f9

jr_00f_6ce0:
    ld hl, $6b7b
    jp Jump_00f_6da8


jr_00f_6ce6:
    ld hl, $d044
    bit 0, [hl]
    jr z, jr_00f_6d44

    xor a
    ld [$cfb3], a
    ld hl, $d0b4
    ld a, [hl+]
    ld b, a
    ld c, [hl]
    ld hl, $cd06
    ld a, [hl]
    add c
    ld [hl-], a
    ld a, [hl]
    adc b
    ld [hl], a
    ld hl, $d04c
    dec [hl]
    jr z, jr_00f_6d0c

    ld hl, $6b7b
    jp Jump_00f_6da8


jr_00f_6d0c:
    ld hl, $d044
    res 0, [hl]
    ld hl, $5c5b
    call Call_000_3c79
    ld a, $01
    ld [$cfb5], a
    ld hl, $cd06
    ld a, [hl-]
    add a
    ld b, a
    ld [$d0b5], a
    ld a, [hl]
    rl a
    ld [$d0b4], a
    or b
    jr nz, jr_00f_6d33

    ld a, $01
    ld [$d03c], a

jr_00f_6d33:
    xor a
    ld [hl+], a
    ld [hl], a
    ld a, $75
    ld [$cfb3], a
    call Call_00f_6f71
    ld hl, $6a64
    jp Jump_00f_6da8


jr_00f_6d44:
    bit 1, [hl]
    jr z, jr_00f_6d73

    ld a, $25
    ld [$cfb3], a
    ld hl, $5c6a
    call Call_000_3c79
    ld hl, $d04c
    dec [hl]
    ld hl, $6a32
    jp nz, Jump_00f_6da8

    push hl
    ld hl, $d044
    res 1, [hl]
    set 7, [hl]
    call Call_00f_718d
    and $03
    inc a
    inc a
    ld [$d04d], a
    pop hl
    jp Jump_00f_6da8


jr_00f_6d73:
    bit 5, [hl]
    jp z, Jump_00f_6d8b

    ld hl, $5c75
    call Call_000_3c79
    ld hl, $d04c
    dec [hl]
    ld hl, $6a76
    jp nz, Jump_00f_6da8

    jp Jump_00f_6da8


Jump_00f_6d8b:
    ld a, [$d045]
    bit 6, a
    jp z, Jump_00f_6daa

    ld a, $63
    ld [$d0e3], a
    call Call_000_1b6d
    call Call_000_386e
    xor a
    ld [$cfb4], a
    ld hl, $6a0d
    jp Jump_00f_6da8


Jump_00f_6da8:
    xor a
    ret


Jump_00f_6daa:
    ld a, $01
    and a
    ret


Call_00f_6dae:
    ldh a, [$f3]
    and a
    jp z, Jump_00f_6dbc

    ld de, $cfb3
    ld a, [$ccdd]
    jr jr_00f_6dcc

Jump_00f_6dbc:
    ld de, $cfb9
    ld a, [$d6b2]
    bit 0, a
    ld a, [$ccd9]
    jr nz, jr_00f_6dcc

    ld a, [$ccdc]

jr_00f_6dcc:
    ld [$d092], a
    dec a
    ld hl, $5658
    ld bc, $0006
    call Call_000_3ad1
    ld a, $0e
    call Call_000_01a3
    ld a, $04
    ld [$d094], a
    ld a, $02
    ld [$d093], a
    call Call_000_37b3
    ld de, $cd68
    jp Jump_000_386e


Call_00f_6df1:
    ld a, [$d0f0]
    cp $04
    jp z, Jump_00f_4d6c

    ld a, [$cfbf]
    ld [$cfcc], a
    ld [$d092], a
    call Call_000_2f2e
    ld a, [$d046]
    bit 3, a
    ld hl, $cceb
    ld a, [hl+]
    ld b, [hl]
    jr nz, jr_00f_6e23

    ld a, [$d034]
    cp $02
    ld a, $98
    ld b, $88
    jr z, jr_00f_6e23

    call Call_00f_718d
    ld b, a
    call Call_00f_718d

jr_00f_6e23:
    ld hl, $cfd8
    ld [hl+], a
    ld [hl], b
    ld de, $cfda
    ld a, [$d0ec]
    ld [de], a
    inc de
    ld b, $00
    ld hl, $cfcd
    push hl
    call Call_000_3980
    pop hl
    ld a, [$d034]
    cp $02
    jr z, jr_00f_6e55

    ld a, [$d046]
    bit 3, a
    jr nz, jr_00f_6e76

    ld a, [$cfdb]
    ld [hl+], a
    ld a, [$cfdc]
    ld [hl+], a
    xor a
    inc hl
    ld [hl], a
    jr jr_00f_6e76

jr_00f_6e55:
    ld hl, $d824
    ld a, [$cf79]
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl+]
    ld [$cfcd], a
    ld a, [hl+]
    ld [$cfce], a
    ld a, [$cf79]
    ld [$cfcf], a
    inc hl
    ld a, [hl]
    ld [$cfd0], a
    jr jr_00f_6e76

jr_00f_6e76:
    ld hl, $d09b
    ld de, $cfd1
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [$d034]
    cp $02
    jr nz, jr_00f_6ea0

    ld hl, $d82b
    ld a, [$cf79]
    ld bc, $002c
    call Call_000_3ad1
    ld bc, $0004
    call Call_000_01bb
    jr jr_00f_6eba

jr_00f_6ea0:
    ld hl, $d0a4
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    dec de
    dec de
    dec de
    xor a
    ld [$cee4], a
    ld a, $3e
    call Call_000_3e9d

jr_00f_6eba:
    ld hl, $cfd4
    ld de, $cfe4
    ld a, $5e
    call Call_000_3e9d
    ld hl, $d096
    ld de, $cfe9
    ld b, $05

jr_00f_6ecd:
    ld a, [hl+]
    ld [de], a
    inc de
    dec b
    jr nz, jr_00f_6ecd

    ld hl, $d09d
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    ld a, [$cfbf]
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $cd68
    ld de, $cfc1
    ld bc, $0006
    call Call_000_01bb
    ld a, [$cfbf]
    ld [$d0e3], a
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld c, a
    ld b, $01
    ld hl, $d28e
    ld a, $10
    call Call_000_3e9d
    ld hl, $cfda
    ld de, $cd23
    ld bc, $000b
    call Call_000_01bb
    ld a, $07
    ld b, $08
    ld hl, $cd2e

jr_00f_6f1d:
    ld [hl+], a
    dec b
    jr nz, jr_00f_6f1d

    ret


Call_00f_6f22:
    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_6f3d

    xor a
    ld [$cc34], a
    ld hl, $7d9b
    ld b, $0d
    call Call_000_3620
    ld a, $01
    ld [$cfb2], a
    call Call_000_03bf

jr_00f_6f3d:
    call Call_000_0b31
    ld a, $30
    call Call_000_3e9d
    ld hl, $7149
    ld b, $0f
    call Call_000_3620
    ld a, $01
    ldh [$ba], a
    ld a, $ff
    ld [$cfb2], a
    call Call_000_0188
    call Call_000_03bf
    xor a
    ldh [$ba], a
    ldh [$b0], a
    ldh [rWY], a
    ldh [$d7], a
    ld hl, $d03d
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld [$d04a], a
    ret


Call_00f_6f71:
    push bc
    ld a, [$d009]
    ld b, a
    ld a, [$cfda]
    ld [$d009], a
    ld a, b
    ld [$cfda], a
    pop bc
    ret


Call_00f_6f82:
    ld a, [$d037]
    dec a
    ld de, $7e50
    jr nz, jr_00f_6f8e

    ld de, $7ee0

jr_00f_6f8e:
    ld a, $0c
    call Call_000_3735
    ld a, $03
    call Call_000_3e9d
    ld hl, $c300
    xor a
    ldh [$8b], a
    ld b, $07
    ld e, $a0

jr_00f_6fa2:
    ld c, $03
    ld d, $38

jr_00f_6fa6:
    ld [hl], d
    inc hl
    ld [hl], e
    ld a, $08
    add d
    ld d, a
    inc hl
    ldh a, [$8b]
    ld [hl+], a
    inc a
    ldh [$8b], a
    inc hl
    dec c
    jr nz, jr_00f_6fa6

    ldh a, [$8b]
    add $04
    ldh [$8b], a
    ld a, $08
    add e
    ld e, a
    dec b
    jr nz, jr_00f_6fa2

    ld de, $9310
    call Call_000_30b9
    ld a, $0a
    ld [$0000], a
    xor a
    ld [$4000], a
    ld hl, $8000
    ld de, $a188
    ldh a, [$b8]
    ld b, a
    ld c, $31
    call Call_000_02dd
    xor a
    ld [$0000], a
    ld a, $31
    ld [$ffe1], a
    ld hl, $c405
    ld a, $01
    jp Jump_000_3e9d


    ld hl, $5f2b
    ld b, $0e
    call Call_000_3620
    ld hl, $5f52
    ld b, $0e
    jp Jump_000_3620


Call_00f_7003:
    ld hl, $5f7e
    ld b, $0e
    jp Jump_000_3620


Call_00f_700b:
    ld a, $01
    jr jr_00f_7010

Call_00f_700f:
    xor a

jr_00f_7010:
    ldh [$f3], a
    call Call_00f_7018
    jp Jump_00f_7055


Call_00f_7018:
    ldh a, [$f3]
    and a
    jr z, jr_00f_7039

    ld a, [$cfff]
    and $40
    ret z

    ld hl, $d011
    ld a, [hl-]
    ld b, a
    ld a, [hl]
    srl a
    rr b
    srl a
    rr b
    ld [hl+], a
    or b
    jr nz, jr_00f_7037

    ld b, $01

jr_00f_7037:
    ld [hl], b
    ret


jr_00f_7039:
    ld a, [$cfd0]
    and $40
    ret z

    ld hl, $cfe2
    ld a, [hl-]
    ld b, a
    ld a, [hl]
    srl a
    rr b
    srl a
    rr b
    ld [hl+], a
    or b
    jr nz, jr_00f_7053

    ld b, $01

jr_00f_7053:
    ld [hl], b
    ret


Call_00f_7055:
Jump_00f_7055:
    ldh a, [$f3]
    and a
    jr z, jr_00f_7072

    ld a, [$cfff]
    and $10
    ret z

    ld hl, $d00d
    ld a, [hl-]
    ld b, a
    ld a, [hl]
    srl a
    rr b
    ld [hl+], a
    or b
    jr nz, jr_00f_7070

    ld b, $01

jr_00f_7070:
    ld [hl], b
    ret


jr_00f_7072:
    ld a, [$cfd0]
    and $10
    ret z

    ld hl, $cfde
    ld a, [hl-]
    ld b, a
    ld a, [hl]
    srl a
    rr b
    ld [hl+], a
    or b
    jr nz, jr_00f_7088

    ld b, $01

jr_00f_7088:
    ld [hl], b
    ret


    ld c, $00

jr_00f_708c:
    call Call_00f_7096
    inc c
    ld a, c
    cp $04
    jr nz, jr_00f_708c

    ret


Call_00f_7096:
    push bc
    push bc
    ld a, [$d0e3]
    and a
    ld a, c
    ld hl, $d00c
    ld de, $cd12
    ld bc, $cd1a
    jr z, jr_00f_70b1

    ld hl, $cfdd
    ld de, $cd26
    ld bc, $cd2e

jr_00f_70b1:
    add c
    ld c, a
    jr nc, jr_00f_70b6

    inc b

jr_00f_70b6:
    ld a, [bc]
    pop bc
    ld b, a
    push bc
    sla c
    ld b, $00
    add hl, bc
    ld a, c
    add e
    ld e, a
    jr nc, jr_00f_70c5

    inc d

jr_00f_70c5:
    pop bc
    push hl
    ld hl, $7a20
    dec b
    sla b
    ld c, b
    ld b, $00
    add hl, bc
    xor a
    ldh [$96], a
    ld a, [de]
    ldh [$97], a
    inc de
    ld a, [de]
    ldh [$98], a
    ld a, [hl+]
    ldh [$99], a
    call Call_000_38f5
    ld a, [hl]
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    pop hl
    ldh a, [$98]
    sub $e7
    ldh a, [$97]
    sbc $03
    jp c, Jump_00f_70fd

    ld a, $03
    ldh [$97], a
    ld a, $e7
    ldh [$98], a

Jump_00f_70fd:
    ldh a, [$97]
    ld [hl+], a
    ld b, a
    ldh a, [$98]
    ld [hl], a
    or b
    jr nz, jr_00f_7108

    inc [hl]

jr_00f_7108:
    pop bc
    ret


Call_00f_710a:
    ld a, [$d0f0]
    cp $04
    ret z

    ld a, [$d2d5]
    ld b, a
    ld hl, $d00c
    ld c, $04

jr_00f_7119:
    srl b
    call c, Call_00f_7126
    inc hl
    inc hl
    srl b
    dec c
    jr nz, jr_00f_7119

    ret


Call_00f_7126:
    ld a, [hl+]
    ld d, a
    ld e, [hl]
    srl d
    rr e
    srl d
    rr e
    srl d
    rr e
    ld a, [hl]
    add e
    ld [hl-], a
    ld a, [hl]
    adc d
    ld [hl+], a
    ld a, [hl-]
    sub $e7
    ld a, [hl]
    sbc $03
    ret c

    ld a, $03
    ld [hl+], a
    ld a, $e7
    ld [hl-], a
    ret


Call_00f_7149:
    call Call_000_370a

Call_00f_714c:
    ldh a, [rLCDC]
    bit 7, a
    jr nz, jr_00f_716e

    ld hl, $5119
    ld de, $96d0
    ld bc, $0018
    ld a, $04
    call Call_000_02c0
    ld hl, $5131
    ld de, $9730
    ld bc, $0030
    ld a, $04
    jp Jump_000_02c0


jr_00f_716e:
    ld de, $5119
    ld hl, $96d0
    ld bc, $0403
    call Call_000_031b
    ld de, $5131
    ld hl, $9730
    ld bc, $0406
    jp Jump_000_031b


Call_00f_7186:
    ld hl, $718c
    jp Jump_000_3c79


    ld d, b

Call_00f_718d:
    ld a, [$d0f0]
    cp $04
    jp nz, Jump_000_3e8c

    push hl
    push bc
    ld a, [$ccde]
    ld c, a
    ld b, $00
    ld hl, $d10d
    add hl, bc
    inc a
    ld [$ccde], a
    cp $09
    ld a, [hl]
    pop bc
    pop hl
    ret c

    push hl
    push bc
    push af
    xor a
    ld [$ccde], a
    ld hl, $d10d
    ld b, $09

jr_00f_71b7:
    ld a, [hl]
    ld c, a
    add a
    add a
    add c
    inc a
    ld [hl+], a
    dec b
    jr nz, jr_00f_71b7

    pop af
    pop bc
    pop hl
    ret


Call_00f_71c5:
    ldh a, [$f3]
    and a
    ld hl, $cfd1
    ld de, $d044
    ld a, [$cfb9]
    jr z, jr_00f_71dc

    ld hl, $d000
    ld de, $d044
    ld a, [$cfb3]

jr_00f_71dc:
    cp $78
    jr z, jr_00f_71e3

    cp $99
    ret nz

jr_00f_71e3:
    ld a, [de]
    bit 6, a
    ret nz

    ld a, [hl+]
    cp $08
    ret z

    ld a, [hl]
    cp $08
    ret z

    ld a, [$d03c]
    and a
    ret nz

    ld a, $05
    ld [$cc5b], a

Call_00f_71f9:
    ld [$d059], a
    call Call_000_3e07
    ld a, $08
    jp Jump_000_3e9d


    ld a, [$d036]
    and a
    jr z, jr_00f_7215

    ld a, [$d036]
    ld [$cf78], a
    ld [$cfbf], a
    jr jr_00f_722f

jr_00f_7215:
    ld a, [$d6b1]
    bit 1, a
    jr z, jr_00f_7221

    ldh a, [$b4]
    bit 1, a
    ret nz

jr_00f_7221:
    ld a, [$d101]
    and a
    ret nz

    ld hl, $7d8f
    ld b, $04
    call Call_000_3620
    ret nz

jr_00f_722f:
    ld a, [$d2dc]
    push af
    ld hl, $d2d7
    ld a, [hl]
    push af
    res 1, [hl]
    ld hl, $7927
    ld b, $14
    call Call_000_3620
    ld a, [$cfbf]
    sub $c8
    jp c, Jump_00f_727e

    ld [$d018], a
    call Call_000_35b0
    ld hl, $5fc4
    ld b, $0e
    call Call_000_3620
    call Call_00f_6f22
    call Call_00f_733e
    xor a
    ld [$cfbf], a
    ld [$ffe1], a
    dec a
    ld [$ccdf], a
    ld hl, $c3ac
    ld a, $01
    call Call_000_3e9d
    ld a, $ff
    ld [$cfcf], a
    ld a, $02
    ld [$d034], a
    jp Jump_00f_72dc


Jump_00f_727e:
    ld a, $01
    ld [$d034], a
    call Call_00f_6df1
    call Call_00f_6f22
    ld a, [$d036]
    cp $91
    jr z, jr_00f_7295

    call Call_00f_59a0
    jr nz, jr_00f_72c7

jr_00f_7295:
    ld hl, $d09f
    ld a, $66
    ld [hl+], a
    ld bc, $67ad
    ld a, c
    ld [hl+], a
    ld [hl], b
    ld hl, $cfc1
    ld a, $d5
    ld [hl+], a
    ld a, $b3
    ld [hl+], a
    ld a, $da
    ld [hl+], a
    ld a, $b2
    ld [hl+], a
    ld [hl], $50
    ld a, [$cf78]
    push af
    ld a, $b8
    ld [$cf78], a
    ld de, $9000
    call Call_000_3034
    pop af
    ld [$cf78], a
    jr jr_00f_72cd

jr_00f_72c7:
    ld de, $9000
    call Call_000_3034

jr_00f_72cd:
    xor a
    ld [$d018], a
    ld [$ffe1], a
    ld hl, $c3ac
    ld a, $01
    call Call_000_3e9d

Jump_00f_72dc:
    ld b, $00
    call Call_000_3e1f
    call Call_00f_404c
    xor a
    ldh [$ba], a
    ld hl, $733d
    call Call_000_3c79
    call Call_000_3761
    call Call_000_03bf
    ld a, $98
    ld [$ffbd], a
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    ld a, $9c
    ld [$ffbd], a
    call Call_000_376d
    ld hl, $c435
    ld bc, $050a
    call Call_000_0374
    ld hl, $c3a1
    ld bc, $040a
    call Call_000_0374
    call Call_000_0188
    ld a, [$d034]
    dec a
    call z, Call_00f_4f49
    call Call_00f_411f
    ld hl, $7cbd
    ld b, $04
    call Call_000_3620
    pop af
    ld [$d2d7], a
    pop af
    ld [$d2dc], a
    ld a, [$d0b1]
    ldh [$d7], a
    scf
    ret


    ld d, b

Call_00f_733e:
    ld a, [$d01a]
    ld e, a
    ld a, [$d01b]
    ld d, a
    ld a, [$d0f0]
    and a
    ld a, $13
    jr z, jr_00f_7350

    ld a, $04

jr_00f_7350:
    call Call_000_3735
    ld de, $9000
    ld a, $77
    ld c, a
    jp Jump_000_3041


    xor a
    ld [$c0f1], a
    ld [$c0f2], a
    jp Jump_000_0e45


    ld a, [$cc4f]
    ld h, a
    ld a, [$cc50]
    ld l, a
    ld a, [$ffe1]
    ldh [$8b], a
    ld b, $4c
    ld a, [$d034]
    and a
    jr z, jr_00f_73b0

    add b
    ld [hl], a
    call Call_000_3e07
    ld bc, $ffd7
    add hl, bc
    ld a, $01
    ld [$cd67], a
    ld bc, $0303
    ld a, $05
    call Call_000_3e9d
    ld c, $04
    call Call_000_3781
    ld bc, $ffd7
    add hl, bc
    xor a
    ld [$cd67], a
    ld bc, $0505
    ld a, $05
    call Call_000_3e9d
    ld c, $05
    call Call_000_3781
    ld bc, $ffd7
    jr jr_00f_73b3

jr_00f_73b0:
    ld bc, $ff85

jr_00f_73b3:
    add hl, bc
    ldh a, [$8b]
    add $31
    jr jr_00f_73c5

    ld a, [$cc4f]
    ld h, a
    ld a, [$cc50]
    ld l, a
    ld a, [$ffe1]

jr_00f_73c5:
    ld bc, $0707
    ld de, $0014
    push af
    ld a, [$d087]
    and a
    jr nz, jr_00f_73e2

    pop af

jr_00f_73d3:
    push bc
    push hl

jr_00f_73d5:
    ld [hl], a
    add hl, de
    inc a
    dec c
    jr nz, jr_00f_73d5

    pop hl
    inc hl
    pop bc
    dec b
    jr nz, jr_00f_73d3

    ret


jr_00f_73e2:
    push bc
    ld b, $00
    dec c
    add hl, bc
    pop bc
    pop af

jr_00f_73e9:
    push bc
    push hl

jr_00f_73eb:
    ld [hl], a
    add hl, de
    inc a
    dec c
    jr nz, jr_00f_73eb

    pop hl
    dec hl
    pop bc
    dec b
    jr nz, jr_00f_73e9

    ret


    ld a, [$cfc0]
    ld [$cf78], a
    ld hl, $c405
    ld b, $07
    ld c, $08
    call Call_000_0374
    ld hl, $000d
    call Call_000_2ffd
    ld a, $03
    call Call_000_3e9d
    ld de, $9310
    call Call_000_30b9
    ld hl, $8000
    ld de, $9310
    ld c, $31
    ldh a, [$b8]
    ld b, a
    jp Jump_000_02dd


Call_00f_7427:
Jump_00f_7427:
    call Call_00f_742d
    ld b, $01
    ret


Call_00f_742d:
    ldh a, [$f3]
    and a
    ld a, [$cfba]
    jr z, jr_00f_7438

    ld a, [$cfb4]

jr_00f_7438:
    dec a
    add a
    ld hl, $7445
    ld b, $00
    ld c, a
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp hl


    pop af
    ld [hl], h
    ld d, a
    ld [hl], l
    ld bc, $2476
    db $76
    inc h
    db $76
    inc h
    db $76
    add hl, bc
    db $76
    ld bc, $0076
    nop
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    push af
    ld a, [hl]
    nop
    nop
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    db $fd
    ld a, [hl]
    dec b
    ld a, a
    ld a, [hl-]
    ld a, d
    ld l, h
    ld a, d
    adc [hl]
    ld a, d
    adc b
    ld a, e
    adc b
    ld a, e
    jp nc, $f17b

    ld [hl], h
    ld d, a
    ld [hl], l
    inc h
    db $76
    inc h
    db $76
    inc h
    db $76
    jp nc, $fb7b

    ld a, e
    inc bc
    ld a, h
    nop
    nop
    nop
    nop
    db $dd
    ld a, h
    inc bc
    ld a, h
    adc b
    ld a, e
    nop
    nop
    rlca
    ld a, l
    rrca
    ld a, l
    rla
    ld a, l
    daa
    ld a, l
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    ld h, d
    ld [hl], a
    dec c
    ld a, a
    dec d
    ld a, a
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    dec e
    ld a, a
    dec e
    ld a, a
    ld d, a
    ld [hl], l
    ld a, [hl]
    ld a, l
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    sub e
    ld a, b
    rra
    ld a, l
    adc b
    ld a, e
    nop
    nop
    add [hl]
    ld a, l
    adc [hl]
    ld a, l
    xor h
    ld a, l
    cp d
    ld a, l
    nop
    nop
    ld d, l
    ld a, [hl]
    ld e, l
    ld a, [hl]
    ld h, e
    ld a, [hl]
    ld de, $cfd0
    ld bc, $d045
    ldh a, [$f3]
    and a
    jp z, Jump_00f_7503

    ld de, $cfff
    ld bc, $d040

Jump_00f_7503:
    ld a, [bc]
    bit 5, a
    res 5, a
    ld [bc], a
    jr nz, jr_00f_7526

    ld a, [de]
    ld b, a
    and $07
    jr z, jr_00f_7517

    ld hl, $7548
    jp Jump_000_3c79


jr_00f_7517:
    ld a, b
    and a
    jr nz, jr_00f_7537

    push de
    call Call_00f_684d
    pop de
    ld a, [$d03c]
    and a
    jr nz, jr_00f_7537

jr_00f_7526:
    call Call_00f_718d
    and $07
    jr z, jr_00f_7526

    ld [de], a
    call Call_00f_7fbc
    ld hl, $753a
    jp Jump_000_3c79


jr_00f_7537:
    jp Jump_00f_7f66


    db $ed
    add hl, hl
    ld e, h
    ld [hl], e
    ret z

    pop de
    rst $18
    jp $cfbc


    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld c, a
    ld [hl], e
    cp l
    inc sp
    add $4f
    ret z

    pop de
    rst $18
    jp $d9b2


    ld e, b
    ld hl, $cfd0
    ld de, $cfba
    ldh a, [$f3]
    and a
    jr z, jr_00f_7568

    ld hl, $cfff
    ld de, $cfb4

jr_00f_7568:
    call Call_00f_7fac
    jr nz, jr_00f_75db

    ld a, [hl+]
    ld b, a
    and a
    jr nz, jr_00f_75db

    ld a, [hl+]
    cp $03
    jr z, jr_00f_75db

    ld a, [hl-]
    cp $03
    jr z, jr_00f_75db

    ld a, [de]
    cp $02
    ld b, $34
    jr z, jr_00f_7598

    cp $21
    ld b, $67
    jr z, jr_00f_7598

    push hl
    push de
    call Call_00f_684d
    pop de
    pop hl
    ld a, [$d03c]
    and a
    jr nz, jr_00f_75df

    jr jr_00f_759d

jr_00f_7598:
    call Call_00f_718d
    cp b
    ret nc

jr_00f_759d:
    dec hl
    set 3, [hl]
    push de
    dec de
    ldh a, [$f3]
    and a
    ld b, $c7
    ld hl, $d041
    ld a, [de]
    ld de, $d049
    jr nz, jr_00f_75b8

    ld b, $a9
    ld hl, $d046
    ld de, $d04e

jr_00f_75b8:
    cp $5c
    jr nz, jr_00f_75c5

    set 0, [hl]
    xor a
    ld [de], a
    ld hl, $75f3
    jr jr_00f_75c8

jr_00f_75c5:
    ld hl, $75e7

jr_00f_75c8:
    pop de
    ld a, [de]
    cp $42
    jr z, jr_00f_75d5

    ld a, b
    call Call_00f_7fc9
    jp Jump_000_3c79


jr_00f_75d5:
    call Call_00f_7fbc
    jp Jump_000_3c79


jr_00f_75db:
    ld a, [de]
    cp $42
    ret nz

jr_00f_75df:
    ld c, $32
    call Call_000_3781
    jp Jump_00f_7f66


    db $ed
    inc l
    ld [$3473], a
    cp b
    db $dd
    or c
    dec sp
    ret nz

    rst $20
    ld e, b
    db $ed
    dec l
    add hl, hl
    ld l, b
    db $d3
    or e
    inc [hl]
    cp b
    db $dd
    or c
    dec sp
    ret nz

    rst $20
    ld e, b
    ld hl, $7b3c
    ld b, $01
    jp Jump_000_3620


    ld hl, $cffc
    ld de, $d040
    ldh a, [$f3]
    and a
    jr z, jr_00f_761a

    ld hl, $cfcd
    ld de, $d045

jr_00f_761a:
    xor a
    ld [hl+], a
    ld [hl+], a
    inc hl
    ld [hl], a
    ld a, [de]
    res 7, a
    ld [de], a
    ret


    xor a
    ld [$cc5b], a
    call Call_00f_7fac
    ret nz

    ldh a, [$f3]
    and a
    jp nz, Jump_00f_769a

    ld a, [$cfd0]
    and a
    jp nz, Jump_00f_770c

    ld a, [$cfbc]
    ld b, a
    ld a, [$cfd1]
    cp b
    ret z

    ld a, [$cfd2]
    cp b
    ret z

    ld a, [$cfba]
    cp $07
    ld b, $1a
    jr c, jr_00f_7654

    ld b, $4d
    sub $1e

jr_00f_7654:
    push af
    call Call_00f_718d
    cp b
    pop bc
    ret nc

    ld a, b
    cp $04
    jr z, jr_00f_7674

    cp $05
    jr z, jr_00f_7687

    ld a, $40
    ld [$cfd0], a
    call Call_00f_7018
    ld a, $a9
    call Call_00f_7fec
    jp Jump_00f_7f90


jr_00f_7674:
    ld a, $10
    ld [$cfd0], a
    call Call_00f_7055
    ld a, $a9
    call Call_00f_7fec
    ld hl, $76f0
    jp Jump_000_3c79


jr_00f_7687:
    call Call_00f_7d9c
    ld a, $20
    ld [$cfd0], a
    ld a, $a9
    call Call_00f_7fec
    ld hl, $76fd
    jp Jump_000_3c79


Jump_00f_769a:
    ld a, [$cfff]
    and a
    jp nz, Jump_00f_770c

    ld a, [$cfb6]
    ld b, a
    ld a, [$d000]
    cp b
    ret z

    ld a, [$d001]
    cp b
    ret z

    ld a, [$cfb4]
    cp $07
    ld b, $1a
    jr c, jr_00f_76bc

    ld b, $4d
    sub $1e

jr_00f_76bc:
    push af
    call Call_00f_718d
    cp b
    pop bc
    ret nc

    ld a, b
    cp $04
    jr z, jr_00f_76d7

    cp $05
    jr z, jr_00f_76e5

    ld a, $40
    ld [$cfff], a
    call Call_00f_7018
    jp Jump_00f_7f90


jr_00f_76d7:
    ld a, $10
    ld [$cfff], a
    call Call_00f_7055
    ld hl, $76f0
    jp Jump_000_3c79


jr_00f_76e5:
    ld a, $20
    ld [$cfff], a
    ld hl, $76fd
    jp Jump_000_3c79


    db $ed
    add hl, hl
    adc c
    ld [hl], e
    call nc, Call_000_34b9
    db $dd
    or l
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    sbc c
    ld [hl], e
    cp d
    or l
    ret c

    ld [hl-], a
    cp c
    add $c5
    rst $18
    ret nz

    rst $20
    ld e, b

Jump_00f_770c:
    and $20
    ret z

    ldh a, [$f3]
    and a
    jr nz, jr_00f_7730

    ld a, [$cfbc]
    sub $14
    ret nz

    ld [$cfd0], a
    ld hl, $d827
    ld a, [$cfcf]
    ld bc, $002c
    call Call_000_3ad1
    xor a
    ld [hl], a
    ld hl, $774d
    jr jr_00f_774a

jr_00f_7730:
    ld a, [$cfb6]
    sub $14
    ret nz

    ld [$cfff], a
    ld hl, $d12f
    ld a, [$cc2f]
    ld bc, $002c
    call Call_000_3ad1
    xor a
    ld [hl], a
    ld hl, $774d

jr_00f_774a:
    jp Jump_000_3c79


    db $ed
    add hl, hl
    add $73
    db $dd
    or c
    dec sp
    jp $c959


    ld c, a
    cp d
    or l
    ret c

    ld h, $7f
    call nz, $c0b9
    rst $20
    ld e, b

Call_00f_7762:
    ld hl, $cd1a
    ld de, $cfba
    ldh a, [$f3]
    and a
    jr z, jr_00f_7773

    ld hl, $cd2e
    ld de, $cfb4

jr_00f_7773:
    ld a, [de]
    sub $0a
    cp $08
    jr c, jr_00f_777c

    sub $28

jr_00f_777c:
    ld c, a
    ld b, $00
    add hl, bc
    ld b, [hl]
    inc b
    ld a, $0d
    cp b
    jp c, Jump_00f_785c

    ld a, [de]
    cp $12
    jr c, jr_00f_7794

    inc b
    ld a, $0d
    cp b
    jr nc, jr_00f_7794

    ld b, a

jr_00f_7794:
    ld [hl], b
    ld a, c
    cp $04
    jr nc, jr_00f_7804

    push hl
    ld hl, $d00d
    ld de, $cd12
    ldh a, [$f3]
    and a
    jr z, jr_00f_77ac

    ld hl, $cfde
    ld de, $cd26

jr_00f_77ac:
    push bc
    sla c
    ld b, $00
    add hl, bc
    ld a, c
    add e
    ld e, a
    jr nc, jr_00f_77b8

    inc d

jr_00f_77b8:
    pop bc
    ld a, [hl-]
    sub $e7
    jr nz, jr_00f_77c4

    ld a, [hl]
    sbc $03
    jp z, Jump_00f_785a

jr_00f_77c4:
    push hl
    push bc
    ld hl, $7a20
    dec b
    sla b
    ld c, b
    ld b, $00
    add hl, bc
    pop bc
    xor a
    ldh [$96], a
    ld a, [de]
    ldh [$97], a
    inc de
    ld a, [de]
    ldh [$98], a
    ld a, [hl+]
    ldh [$99], a
    call Call_000_38f5
    ld a, [hl]
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    pop hl
    ldh a, [$98]
    sub $e7
    ldh a, [$97]
    sbc $03
    jp c, Jump_00f_77fd

    ld a, $03
    ldh [$97], a
    ld a, $e7
    ldh [$98], a

Jump_00f_77fd:
    ldh a, [$97]
    ld [hl+], a
    ldh a, [$98]
    ld [hl], a
    pop hl

jr_00f_7804:
    ld b, c
    inc b
    call Call_00f_79dc
    ld hl, $d040
    ld de, $cfb9
    ld bc, $ccf7
    ldh a, [$f3]
    and a
    jr z, jr_00f_7820

    ld hl, $d045
    ld de, $cfb3
    ld bc, $ccf3

jr_00f_7820:
    ld a, [de]
    cp $6b
    jr nz, jr_00f_7833

    bit 4, [hl]
    push af
    push bc
    ld hl, $577e
    ld b, $1e
    push de
    call nz, Call_000_3620
    pop de

jr_00f_7833:
    call Call_00f_7fdb
    ld a, [de]
    cp $6b
    jr nz, jr_00f_7848

    pop bc
    ld a, $01
    ld [bc], a
    ld hl, $57a8
    ld b, $1e
    pop af
    call nz, Call_000_3620

jr_00f_7848:
    ldh a, [$f3]
    and a
    call z, Call_00f_710a
    ld hl, $7862
    call Call_000_3c79
    call Call_00f_7018
    jp Jump_00f_7055


Jump_00f_785a:
    pop hl
    dec [hl]

Jump_00f_785c:
    ld hl, $7f25
    jp Jump_000_3c79


    nop
    ld e, d
    add a
    db $d3
    ld c, a
    ld d, b
    ld bc, $cf45
    nop
    ld d, b
    ld [$8321], sp
    ld a, b
    ldh a, [$f3]
    and a
    ld a, [$cfba]
    jr z, jr_00f_787c

    ld a, [$cfb4]

jr_00f_787c:
    cp $12
    ret nc

    ld hl, $788b
    ret


    db $ed
    dec l
    ld a, b
    ld e, [hl]
    db $e3
    sbc $c4
    ld d, b
    db $ed
    dec l
    sub d
    ld e, [hl]
    rst $18
    ret nz

    rst $20
    ld e, b
    ld hl, $cd2e
    ld de, $cfba
    ld bc, $d044
    ldh a, [$f3]
    and a
    jr z, jr_00f_78b9

    ld hl, $cd1a
    ld de, $cfb4
    ld bc, $d03f
    ld a, [$d0f0]
    cp $04
    jr z, jr_00f_78b9

    call Call_00f_718d
    cp $40
    jp c, Jump_00f_79a1

jr_00f_78b9:
    call Call_00f_7fac
    jp nz, Jump_00f_79a1

    ld a, [de]
    cp $44
    jr c, jr_00f_78d1

    call Call_00f_718d
    cp $55
    jp nc, Jump_00f_7997

    ld a, [de]
    sub $44
    jr jr_00f_78f0

jr_00f_78d1:
    push hl
    push de
    push bc
    call Call_00f_684d
    pop bc
    pop de
    pop hl
    ld a, [$d03c]
    and a
    jp nz, Jump_00f_79a1

    ld a, [bc]
    bit 6, a
    jp nz, Jump_00f_79a1

    ld a, [de]
    sub $12
    cp $08
    jr c, jr_00f_78f0

    sub $28

jr_00f_78f0:
    ld c, a
    ld b, $00
    add hl, bc
    ld b, [hl]
    dec b
    jp z, Jump_00f_7997

    ld a, [de]
    cp $24
    jr c, jr_00f_7906

    cp $44
    jr nc, jr_00f_7906

    dec b
    jr nz, jr_00f_7906

    inc b

jr_00f_7906:
    ld [hl], b
    ld a, c
    cp $04
    jr nc, jr_00f_7973

    push hl
    push de
    ld hl, $cfde
    ld de, $cd26
    ldh a, [$f3]
    and a
    jr z, jr_00f_791f

    ld hl, $d00d
    ld de, $cd12

jr_00f_791f:
    push bc
    sla c
    ld b, $00
    add hl, bc
    ld a, c
    add e
    ld e, a
    jr nc, jr_00f_792b

    inc d

jr_00f_792b:
    pop bc
    ld a, [hl-]
    sub $01
    jr nz, jr_00f_7936

    ld a, [hl]
    and a
    jp z, Jump_00f_7994

jr_00f_7936:
    push hl
    push bc
    ld hl, $7a20
    dec b
    sla b
    ld c, b
    ld b, $00
    add hl, bc
    pop bc
    xor a
    ldh [$96], a
    ld a, [de]
    ldh [$97], a
    inc de
    ld a, [de]
    ldh [$98], a
    ld a, [hl+]
    ldh [$99], a
    call Call_000_38f5
    ld a, [hl]
    ldh [$99], a
    ld b, $04
    call Call_000_3902
    pop hl
    ldh a, [$98]
    ld b, a
    ldh a, [$97]
    or b
    jp nz, Jump_00f_796b

    ldh [$97], a
    ld a, $01
    ldh [$98], a

Jump_00f_796b:
    ldh a, [$97]
    ld [hl+], a
    ldh a, [$98]
    ld [hl], a
    pop de
    pop hl

jr_00f_7973:
    ld b, c
    inc b
    push de
    call Call_00f_79dc
    pop de
    ld a, [de]
    cp $44
    jr nc, jr_00f_7982

    call Call_00f_7fbc

jr_00f_7982:
    ldh a, [$f3]
    and a
    call nz, Call_00f_710a
    ld hl, $79a8
    call Call_000_3c79
    call Call_00f_7018
    jp Jump_00f_7055


Jump_00f_7994:
    pop de
    pop hl
    inc [hl]

Jump_00f_7997:
    ld a, [de]
    cp $44
    ret nc

    ld hl, $7f25
    jp Jump_000_3c79


Jump_00f_79a1:
    ld a, [de]
    cp $44
    ret nc

    jp Jump_00f_7f49


    nop
    ld e, c
    add a
    db $d3
    ld d, b
    ld bc, $cf45
    nop
    ld c, a
    ld d, b
    ld [$d421], sp
    ld a, c
    ldh a, [$f3]
    and a
    ld a, [$cfba]
    jr z, jr_00f_79c2

    ld a, [$cfb4]

jr_00f_79c2:
    cp $1a
    ret c

    cp $44
    ret nc

    ld hl, $79cc
    ret


    db $ed
    dec l
    ld c, a
    ld e, l
    cp b
    rst $18
    call nz, $ed50
    dec l
    ccf
    ld e, l
    rst $18
    ret nz

    rst $20
    ld e, b

Call_00f_79dc:
    ld hl, $79f3
    ld c, $50

jr_00f_79e1:
    dec b
    jr z, jr_00f_79ea

jr_00f_79e4:
    ld a, [hl+]
    cp c
    jr z, jr_00f_79e1

    jr jr_00f_79e4

jr_00f_79ea:
    ld de, $cf45
    ld bc, $000a
    jp Jump_000_01bb


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
    xor b
    xor c
    or h
    ld d, b
    or e
    xor b
    xor c
    or d
    xor e
    ld d, b
    ret c

    jp nz, $b650

    or d
    set 3, b
    jp nz, $1950

    ld h, h
    inc e
    ld h, h
    ld hl, $2864
    ld h, h
    ld [hl-], a
    ld h, h
    ld b, d
    ld h, h
    ld bc, $0f01
    ld a, [bc]
    ld [bc], a
    ld bc, $0a19
    inc bc
    ld bc, $0a23
    inc b
    ld bc, $3f21
    ret nc

    ld de, $d051
    ld bc, $d047
    ldh a, [$f3]
    and a
    jr z, jr_00f_7a51

    ld hl, $d044
    ld de, $cd05
    ld bc, $d04c

jr_00f_7a51:
    set 0, [hl]
    xor a
    ld [de], a
    inc de
    ld [de], a
    ld [$cfba], a
    ld [$cfb4], a
    call Call_00f_718d
    and $01
    inc a
    inc a
    ld [bc], a
    ldh a, [$f3]
    add $ae
    jp Jump_00f_7fc9


    ld hl, $d03f
    ld de, $d047
    ldh a, [$f3]
    and a
    jr z, jr_00f_7a7d

    ld hl, $d044
    ld de, $d04c

jr_00f_7a7d:
    set 1, [hl]
    call Call_00f_718d
    and $01
    inc a
    inc a
    ld [de], a
    ldh a, [$f3]
    add $b0
    jp Jump_00f_7fc9


    ldh a, [$f3]
    and a
    jr nz, jr_00f_7ae6

    ld a, [$d034]
    dec a
    jr nz, jr_00f_7ad3

    ld a, [$d0ec]
    ld b, a
    ld a, [$d009]
    cp b
    jr nc, jr_00f_7ac3

    add b
    ld c, a
    inc c

jr_00f_7aa6:
    call Call_00f_718d
    cp c
    jr nc, jr_00f_7aa6

    srl b
    srl b
    cp b
    jr nc, jr_00f_7ac3

    ld c, $32
    call Call_000_3781
    ld a, [$cfb9]
    cp $64
    jp nz, Jump_00f_7f66

    jp Jump_00f_7f4e


jr_00f_7ac3:
    call Call_00f_4ea1
    xor a
    ld [$cc5b], a
    inc a
    ld [$d055], a
    ld a, [$cfb9]
    jr jr_00f_7b39

jr_00f_7ad3:
    ld c, $32
    call Call_000_3781
    ld hl, $7f7d
    ld a, [$cfb9]
    cp $64
    jp nz, Jump_000_3c79

    jp Jump_00f_7f4e


jr_00f_7ae6:
    ld a, [$d034]
    dec a
    jr nz, jr_00f_7b26

    ld a, [$d009]
    ld b, a
    ld a, [$d0ec]
    cp b
    jr nc, jr_00f_7b16

    add b
    ld c, a
    inc c

jr_00f_7af9:
    call Call_00f_718d
    cp c
    jr nc, jr_00f_7af9

    srl b
    srl b
    cp b
    jr nc, jr_00f_7b16

    ld c, $32
    call Call_000_3781
    ld a, [$cfb3]
    cp $64
    jp nz, Jump_00f_7f66

    jp Jump_00f_7f4e


jr_00f_7b16:
    call Call_00f_4ea1
    xor a
    ld [$cc5b], a
    inc a
    ld [$d055], a
    ld a, [$cfb3]
    jr jr_00f_7b39

jr_00f_7b26:
    ld c, $32
    call Call_000_3781
    ld hl, $7f7d
    ld a, [$cfb3]
    cp $64
    jp nz, Jump_000_3c79

    jp Jump_00f_7f49


jr_00f_7b39:
    push af
    call Call_00f_7fec
    ld c, $14
    call Call_000_3781
    pop af
    ld hl, $7b57
    cp $64
    jr z, jr_00f_7b54

    ld hl, $7b69
    cp $2e
    jr z, jr_00f_7b54

    ld hl, $7b7b

jr_00f_7b54:
    jp Jump_000_3c79


    nop
    ld e, d
    jp z, $be7f

    sbc $c4
    or e
    or [hl]
    rst $10
    ld c, a
    ret c

    jr nc, @-$3c

    cp h
    ret nz

    rst $20
    ld e, b
    nop
    ld e, c
    jp z, $b57f

    inc l
    cp c
    dec l
    or d
    jp $c64f


    add hl, hl
    jr nc, @-$42

    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    inc d
    ld [hl], h
    call z, $c4b7
    ld a, [hl-]
    cp e
    jp c, $e7c0

    ld e, b
    ld hl, $d03f
    ld de, $d047
    ld bc, $d051
    ldh a, [$f3]
    and a
    jr z, jr_00f_7b9f

    ld hl, $d044
    ld de, $d04c
    ld bc, $cd05

jr_00f_7b9f:
    bit 2, [hl]
    ret nz

    set 2, [hl]
    ld hl, $cfba
    ldh a, [$f3]
    and a
    jr z, jr_00f_7baf

    ld hl, $cfb4

jr_00f_7baf:
    ld a, [hl]
    cp $4d
    jr z, jr_00f_7bcd

    cp $2c
    ld a, $02
    jr z, jr_00f_7bca

    call Call_00f_718d
    and $03
    cp $02
    jr c, jr_00f_7bc8

    call Call_00f_718d
    and $03

jr_00f_7bc8:
    inc a
    inc a

jr_00f_7bca:
    ld [de], a
    ld [bc], a
    ret


jr_00f_7bcd:
    ld a, $02
    ld [hl], a
    jr jr_00f_7bca

    call Call_00f_7fac
    ret nz

    ld hl, $d044
    ld de, $cfba
    ldh a, [$f3]
    and a
    jr z, jr_00f_7be7

    ld hl, $d03f
    ld de, $cfb4

jr_00f_7be7:
    call Call_00f_7d9c
    ld a, [de]
    cp $1f
    ld b, $1a
    jr z, jr_00f_7bf3

    ld b, $4d

jr_00f_7bf3:
    call Call_00f_718d
    cp b
    ret nc

    set 3, [hl]
    ret


    ld hl, $7fab
    ld b, $0c
    jp Jump_000_3620


    ld hl, $d03f
    ld de, $cfba
    ldh a, [$f3]
    and a
    ld b, $ae
    jr z, jr_00f_7c18

    ld hl, $d044
    ld de, $cfb4
    ld b, $af

jr_00f_7c18:
    set 4, [hl]
    ld a, [de]
    dec de
    cp $2b
    jr nz, jr_00f_7c24

    set 6, [hl]
    ld b, $64

jr_00f_7c24:
    ld a, [de]
    cp $5b
    jr nz, jr_00f_7c2d

    set 6, [hl]
    ld b, $c0

jr_00f_7c2d:
    xor a
    ld [$cc5b], a
    ld a, b
    call Call_00f_7fec
    ld a, [de]
    ld [$cd3d], a
    ld hl, $7c3f
    jp Jump_000_3c79


    nop
    ld e, d
    ld d, b
    ld [$3dfa], sp
    call Call_000_0dfe
    ld hl, $7c6f
    jr z, jr_00f_7c6e

    cp $4c
    ld hl, $7c84
    jr z, jr_00f_7c6e

    cp $82
    ld hl, $7c96
    jr z, jr_00f_7c6e

    cp $8f
    ld hl, $7ca4
    jr z, jr_00f_7c6e

    cp $13
    ld hl, $7cb6
    jr z, jr_00f_7c6e

    cp $5b
    ld hl, $7cc7

jr_00f_7c6e:
    ret


    db $ed
    dec l
    and c
    ld e, l
    call c, $33d8
    ld c, a
    cp b
    or e
    or a
    ld h, $7f
    or e
    dec l
    db $dd
    ld a, a
    rst $08
    cp b
    rst $20
    ld e, b
    db $ed
    dec l
    pop bc
    ld e, l
    or [hl]
    ret c

    db $dd
    ld a, a
    or a
    pop hl
    or e
    cp h
    pop hl
    or e
    cp h
    ret nz

    rst $20
    ld e, b
    db $ed
    dec l
    db $dd
    ld e, l
    dec sp
    db $dd
    ld a, a
    set 3, a
    cp d
    jp nc, $e7c0

    ld e, b
    db $ed
    dec l
    ld a, [$295d]
    cp h
    or d
    ld a, a
    res 6, [hl]
    ret c

    ld h, $7f
    jp nz, $d1c2

    rst $20
    ld e, b
    db $ed
    dec l
    ld hl, $d75e
    ret nz

    or [hl]
    cp b
    ld a, a
    call nz, $b13b
    ld h, $df
    ret nz

    rst $20
    ld e, b
    db $ed
    dec l
    ld c, [hl]
    ld e, [hl]
    push bc
    db $dd
    adc $df
    jp $c17f


    pop bc
    pop hl
    or e
    add $7f
    db $d3
    jr z, @-$1f

    ret nz

    rst $20
    ld e, b
    ld hl, $d03f
    ld de, $d047
    ldh a, [$f3]
    and a
    jr z, jr_00f_7cee

    ld hl, $d044
    ld de, $d04c

jr_00f_7cee:
    bit 5, [hl]
    ret nz

    call Call_00f_7d9c
    set 5, [hl]
    call Call_00f_718d
    and $03
    cp $02
    jr c, jr_00f_7d04

    call Call_00f_718d
    and $03

jr_00f_7d04:
    inc a
    ld [de], a
    ret


    ld hl, $7f71
    ld b, $0c
    jp Jump_000_3620


    ld hl, $7f94
    ld b, $09
    jp Jump_000_3620


    ld hl, $7e4b
    ld b, $04
    jp Jump_000_3620


    call Call_00f_718d
    cp $19
    ret nc

    jr jr_00f_7d35

    call Call_00f_7fac
    jr nz, jr_00f_7d73

    call Call_00f_684d
    ld a, [$d03c]
    and a
    jr nz, jr_00f_7d73

jr_00f_7d35:
    ldh a, [$f3]
    and a
    ld hl, $d044
    ld bc, $d04d
    ld a, [$cfba]
    jr z, jr_00f_7d4c

    ld hl, $d03f
    ld bc, $d048
    ld a, [$cfb4]

jr_00f_7d4c:
    bit 7, [hl]
    jr nz, jr_00f_7d73

    set 7, [hl]
    push af
    call Call_00f_718d
    and $03
    inc a
    inc a
    ld [bc], a
    pop af
    cp $4c
    call nz, Call_00f_7fbc
    ld hl, $7d67
    jp Jump_000_3c79


    db $ed
    add hl, hl
    dec hl
    ld [hl], h
    cp d
    sbc $d7
    sbc $bc
    ret nz

    rst $20
    ld e, b

jr_00f_7d73:
    cp $4c
    ret z

    ld c, $32
    call Call_000_3781
    jp Jump_00f_7f49


    ld hl, $7979
    ld b, $14
    jp Jump_000_3620


    ld hl, $7d7d
    ld b, $05
    jp Jump_000_3620


    ld hl, $d040
    ldh a, [$f3]
    and a
    jr z, jr_00f_7d99

    ld hl, $d045

jr_00f_7d99:
    set 5, [hl]
    ret


Call_00f_7d9c:
    push hl
    ld hl, $d045
    ldh a, [$f3]
    and a
    jr z, jr_00f_7da8

    ld hl, $d040

jr_00f_7da8:
    res 5, [hl]
    pop hl
    ret


    ld hl, $d040
    ldh a, [$f3]
    and a
    jr z, jr_00f_7db7

    ld hl, $d045

jr_00f_7db7:
    set 6, [hl]
    ret


    ld c, $32
    call Call_000_3781
    call Call_00f_684d
    ld a, [$d03c]
    and a
    jr nz, jr_00f_7e41

    ldh a, [$f3]
    and a
    ld hl, $d003
    ld a, [$d03f]
    jr nz, jr_00f_7de0

    ld a, [$d0f0]
    cp $04
    jr nz, jr_00f_7e07

    ld hl, $cfd4
    ld a, [$d044]

jr_00f_7de0:
    bit 6, a
    jr nz, jr_00f_7e41

jr_00f_7de4:
    push hl
    call Call_00f_718d
    and $03
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    pop hl
    and a
    jr z, jr_00f_7de4

    ld d, a
    ldh a, [$f3]
    and a
    ld hl, $d003
    ld a, [$cc2e]
    jr z, jr_00f_7e2c

    ld hl, $cfd4
    ld a, [$cce2]
    jr jr_00f_7e2c

jr_00f_7e07:
    ld a, [$d044]
    bit 6, a
    jr nz, jr_00f_7e41

    ld a, [$cc26]
    push af
    ld a, $01
    ld [$ccdb], a
    call Call_00f_5377
    call Call_000_376d
    ld hl, $cfd4
    ld a, [$cc26]
    ld c, a
    ld b, $00
    add hl, bc
    ld d, [hl]
    pop af
    ld hl, $d003

jr_00f_7e2c:
    ld c, a
    ld b, $00
    add hl, bc
    ld a, d
    ld [hl], a
    ld [$d0e3], a
    call Call_000_1b6d
    call Call_00f_7fdb
    ld hl, $7e44
    jp Jump_000_3c79


jr_00f_7e41:
    jp Jump_00f_7f4e


    db $ed
    add hl, hl
    dec a
    ld [hl], h
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    or l
    ld a, $b4
    ret nz

    rst $20
    ld e, b
    ld hl, $7f91
    ld b, $0a
    jp Jump_000_3620


    call Call_00f_7fdb
    jp Jump_00f_7f35


    call Call_00f_684d
    ld a, [$d03c]
    and a
    jr nz, jr_00f_7edf

    ld de, $d04f
    ld hl, $cfd4
    ldh a, [$f3]
    and a
    jr z, jr_00f_7e7d

    ld de, $d04a
    ld hl, $d003

jr_00f_7e7d:
    ld a, [de]
    and a
    jr nz, jr_00f_7edf

jr_00f_7e81:
    push hl
    call Call_00f_718d
    and $03
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]
    pop hl
    and a
    jr z, jr_00f_7e81

    ld [$d0e3], a
    push hl
    ldh a, [$f3]
    and a
    ld hl, $d014
    jr nz, jr_00f_7ea8

    ld a, [$d0f0]
    cp $04
    pop hl
    jr nz, jr_00f_7eba

    push hl
    ld hl, $cfe5

jr_00f_7ea8:
    push hl
    ld a, [hl+]
    or [hl]
    inc hl
    or [hl]
    inc hl
    or [hl]
    and $3f
    pop hl
    jr z, jr_00f_7ede

    add hl, bc
    ld a, [hl]
    pop hl
    and a
    jr z, jr_00f_7e81

jr_00f_7eba:
    call Call_00f_718d
    and $07
    inc a
    inc c
    swap c
    add c
    ld [de], a
    call Call_00f_7fbc
    ld hl, $ccee
    ldh a, [$f3]
    and a
    jr nz, jr_00f_7ed1

    inc hl

jr_00f_7ed1:
    ld a, [$d0e3]
    ld [hl], a
    call Call_000_1b6d
    ld hl, $7ee2
    jp Jump_000_3c79


jr_00f_7ede:
    pop hl

jr_00f_7edf:
    jp Jump_00f_7f4e


    db $ed
    add hl, hl
    ld d, l
    ld [hl], h
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    call z, $2cb3
    cp d
    jp nc, $e7c0

    ld e, b
    ld hl, $7f5b
    ld b, $0b
    jp Jump_000_3620


    ld hl, $7ed3
    ld b, $04
    jp Jump_000_3620


    ld hl, $7f1d
    ld b, $04
    jp Jump_000_3620


    ld hl, $7db7
    ld b, $0e
    jp Jump_000_3620


    ld hl, $7ea3
    ld b, $0e
    jp Jump_000_3620


    ld hl, $7f8f
    ld b, $0e
    jp Jump_000_3620


    db $ed

Call_00f_7f26:
    add hl, hl
    ei
    ld [hl], e
    ld a, a
    cp d
    or e
    or [hl]
    ld h, $7f
    push bc
    or [hl]
    rst $18
    ret nz

    rst $20
    ld e, b

Jump_00f_7f35:
    ld hl, $7f3b
    jp Jump_000_3c79


    db $ed
    add hl, hl
    ld [hl], l
    ld [hl], h
    ld a, a
    push bc
    add $d3
    or l
    cp d
    rst $10
    push bc
    or d
    ld e, b

Jump_00f_7f49:
    ld a, [$ccf4]
    and a
    ret nz

Jump_00f_7f4e:
    ld hl, $7f54
    jp Jump_000_3c79


    db $ed
    add hl, hl
    sub e
    ld [hl], h
    ld a, a
    or e
    rst $08
    cp b
    ld a, a
    or a
    rst $08
    rst $10
    push bc
    or [hl]
    rst $18
    ret nz

    rst $20
    ld e, b

Jump_00f_7f66:
    ld hl, $7f6c
    jp Jump_000_3c79


    db $ed
    add hl, hl
    cp d
    ld [hl], h
    ld a, a
    ld e, c
    add $ca
    ld c, a
    or a
    or [hl]
    push bc
    or [hl]
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    dec l
    ld de, $cd68
    or d
    or a
    push bc
    ld a, a
    or [hl]
    or l
    db $dd
    ld a, a
    cp h
    jp $d9b2


    rst $20
    ld e, b

Jump_00f_7f90:
    ld hl, $7f96
    jp Jump_000_3c79


    db $ed
    add hl, hl
    call nc, $cf74
    res 7, h
    jp $dc4f


    dec hl
    ld h, $7f
    inc sp
    add $b8
    cp b
    push bc
    rst $18
    ret nz

    rst $20
    ld e, b

Call_00f_7fac:
    push hl
    ld hl, $d045
    ldh a, [$f3]
    and a
    jr z, jr_00f_7fb8

    ld hl, $d040

jr_00f_7fb8:
    bit 4, [hl]
    pop hl
    ret


Call_00f_7fbc:
    ldh a, [$f3]
    and a
    ld a, [$cfb9]
    jr z, jr_00f_7fc7

    ld a, [$cfb3]

jr_00f_7fc7:
    and a
    ret z

Call_00f_7fc9:
Jump_00f_7fc9:
    ld [$d059], a
    ldh a, [$f3]
    and a
    ld a, $06
    jr z, jr_00f_7fd5

    ld a, $03

jr_00f_7fd5:
    ld [$cc5b], a
    jp Jump_00f_7fef


Call_00f_7fdb:
    xor a
    ld [$cc5b], a
    ldh a, [$f3]
    and a
    ld a, [$cfb9]
    jr z, jr_00f_7fea

    ld a, [$cfb3]

jr_00f_7fea:
    and a
    ret z

Call_00f_7fec:
    ld [$d059], a

Jump_00f_7fef:
    push hl
    push de
    push bc
    ld a, $08
    call Call_000_3e9d
    pop bc
    pop de
    pop hl
    ret


    db $db
    jp hl


    push hl
    dec [hl]
    ld a, a
