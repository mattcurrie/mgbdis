; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $008", ROMX[$4000], BANK[$8]

    xor a
    ldh [$ba], a
    call Call_000_373e
    ld a, [$d521]
    and a
    jr nz, jr_008_402b

    ld a, [$d6ca]
    bit 5, a
    jr z, jr_008_4022

    ld a, [$d521]
    and a
    jr nz, jr_008_402b

    ld hl, $c3a0
    ld b, $08
    ld c, $0d
    jr jr_008_4032

jr_008_4022:
    ld hl, $c3a0
    ld b, $06
    ld c, $0d
    jr jr_008_4032

jr_008_402b:
    ld hl, $c3a0
    ld b, $0a
    ld c, $0d

jr_008_4032:
    call Call_000_03d2
    call Call_000_0ebd
    ld a, $03
    ld [$cc28], a
    ld a, [$d770]
    bit 0, a
    jr nz, jr_008_404c

    ld hl, $c3ca
    ld de, $40c3
    jr jr_008_4052

jr_008_404c:
    ld hl, $c3ca
    ld de, $40ca

jr_008_4052:
    call Call_000_0405
    ld hl, $c3f2
    ld de, $d11d
    call Call_000_0405
    ld l, c
    ld h, b

Jump_008_4060:
    ld de, $40d1
    call Call_000_0405
    ld a, [$d6ca]
    bit 5, a
    jr z, jr_008_409a

    ld hl, $c41a
    ld de, $40d5
    call Call_000_0405
    ld a, [$d521]
    and a
    jr z, jr_008_4092

    ld a, $04
    ld [$cc28], a
    ld hl, $c442
    ld de, $40dd
    call Call_000_0405
    ld hl, $c46a
    ld de, $40e6
    jr jr_008_40a5

jr_008_4092:
    ld hl, $c442
    ld de, $40e6
    jr jr_008_40a5

jr_008_409a:
    ld a, $02
    ld [$cc28], a
    ld hl, $c41a
    ld de, $40e6

jr_008_40a5:
    call Call_000_0405
    ld a, $03
    ld [$cc29], a
    ld a, $02
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    ld a, $01
    ldh [$ba], a

Call_008_40c2:
    ret


    db $ed

Call_008_40c4:
    inc l
    ld h, d
    ld b, d
    ld a, a
    ld e, e
    ld d, b
    db $ed
    inc l
    ld l, d
    ld b, d
    ld a, a
    ld e, e
    ld d, b

Call_008_40d1:
    db $ed

Call_008_40d2:
    inc l
    db $76
    ld b, d
    db $ed
    inc l
    ld a, d
    ld b, d
    ret


    ld a, a
    ld e, e
    ld d, b
    db $ed
    inc l
    add a
    ld b, d
    ld a, a
    ret c

Jump_008_40e3:
    db $e3
    rlca
    ld d, b
    db $ed
    inc l
    sub h
    ld b, d
    db $dd
    ld a, a
    or a
    reti


    ld d, b
    ld hl, $d6af
    set 6, [hl]
    xor a
    ld [$ccd3], a
    inc a
    ld [$d093], a
    call Call_000_370a
    ld a, [$cc36]
    push af
    ld a, [$cd5b]
    bit 3, a
    jr nz, jr_008_4115

    ld a, $99
    call Call_000_0e45
    ld hl, $43e7
    call Call_000_3c79

Jump_008_4115:
jr_008_4115:
    ld a, [$ccd3]
    ld [$cc26], a
    ld hl, $9780
    ld de, $6d11
    ld bc, $0e01
    call Call_000_02dd
    call Call_000_3752
    ld hl, $c3a0
    ld b, $0a
    ld c, $0c
    call Call_000_03d2
    ld hl, $c3ca
    ld de, $42f2
    call Call_000_0405
    ld hl, $cc24
    ld a, $02
    ld [hl+], a
    dec a
    ld [hl+], a
    inc hl
    inc hl
    ld a, $04
    ld [hl+], a
    ld a, $03
    ld [hl+], a
    xor a
    ld [hl+], a
    ld [hl+], a
    ld hl, $cc36
    ld [hl+], a
    ld [hl], a
    ld [$cc2f], a
    ld hl, $43f1
    call Call_000_3c79
    ld hl, $c4c1
    ld b, $02
    ld c, $09
    call Call_000_03d2
    ld a, [$d51f]
    and $7f
    add $f7
    ld [$c4f2], a
    ld hl, $c4d6
    ld de, $431a
    call Call_000_0405
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    call Call_000_3b08
    bit 1, a
    jp nz, Jump_008_41a6

    call Call_000_3c1c
    ld a, [$cc26]
    ld [$ccd3], a
    and a
    jp z, Jump_008_4229

    cp $01
    jp z, Jump_008_41ca

    cp $02
    jp z, Jump_008_4284

    cp $03
    jp z, Jump_008_42c4

Jump_008_41a6:
    ld a, [$cd5b]
    bit 3, a
    jr nz, jr_008_41b8

    call Call_000_36ea
    ld a, $9a
    call Call_000_0e45
    call Call_000_3790

jr_008_41b8:
    ld hl, $cd5b
    res 5, [hl]
    call Call_000_374a
    pop af

Call_008_41c1:
    ld [$cc36], a
    ld hl, $d6af
    res 6, [hl]
    ret


Jump_008_41ca:
    ld a, [$d123]
    dec a
    jr nz, jr_008_41d9

    ld hl, $4422
    call Call_000_3c79
    jp Jump_008_4115


jr_008_41d9:
    ld a, [$d9b2]
    cp $1e
    jr nz, jr_008_41e9

    ld hl, $4436
    call Call_000_3c79
    jp Jump_008_4115


jr_008_41e9:
    ld hl, $d123
    call Call_008_42cf
    jp c, Jump_008_4115

    call Call_008_4352
    jp nc, Jump_008_4115

    ld a, [$cf78]
    call Call_000_2dd0
    call Call_000_3788
    ld a, $01
    ld [$cf7c], a
    call Call_000_3ab2
    xor a
    ld [$cf7c], a
    call Call_000_3969
    call Call_000_3790
    ld a, [$d51f]
    and $7f
    ld hl, $cd3d
    add $f7
    ld [hl+], a
    ld [hl], $50
    ld hl, $440b
    call Call_000_3c79
    jp Jump_008_4115


Jump_008_4229:
    ld a, [$d9b2]
    and a
    jr nz, jr_008_4238

    ld hl, $446d
    call Call_000_3c79
    jp Jump_008_4115


jr_008_4238:
    ld a, [$d123]
    cp $06
    jr nz, jr_008_4248

    ld hl, $4484
    call Call_000_3c79
    jp Jump_008_4115


jr_008_4248:
    ld hl, $d9b2
    call Call_008_42cf
    jp c, Jump_008_4115

    call Call_008_4352
    jp nc, Jump_008_4115

    ld a, [$cf79]
    ld hl, $de64
    call Call_000_2fb1
    ld a, [$cf78]
    call Call_000_2dd0
    call Call_000_3788
    xor a
    ld [$cf7c], a
    call Call_000_3ab2
    ld a, $01
    ld [$cf7c], a
    call Call_000_3969
    call Call_000_3790
    ld hl, $4449
    call Call_000_3c79
    jp Jump_008_4115


Jump_008_4284:
    ld a, [$d9b2]
    and a
    jr nz, jr_008_4293

    ld hl, $446d
    call Call_000_3c79
    jp Jump_008_4115


jr_008_4293:
    ld hl, $d9b2
    call Call_008_42cf
    jp c, Jump_008_4115

    ld hl, $44c7
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_008_4293

    inc a
    ld [$cf7c], a
    call Call_000_3969

Call_008_42b2:
    call Call_000_3790
    ld a, [$cf78]
    call Call_000_2dc7
    ld hl, $44e5
    call Call_000_3c79
    jp Jump_008_4115


Jump_008_42c4:
    ld b, $1c
    ld hl, $7d1b
    call Call_000_3620
    jp Jump_008_4115


Call_008_42cf:
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    xor a
    ld [$cf7a], a
    ld [$cf7b], a
    inc a
    ld [$d093], a
    ld a, [$cc2b]
    ld [$cc26], a
    call Call_000_16f7
    ld a, [$cc26]
    ld [$cc2b], a
    ret


    db $ed
    inc l
    sbc c
    ld b, d
    jp c, $b2c3

    cp b
    ld c, [hl]
    ld d, h
    db $dd
    ld a, a
    or c
    dec l
    cp c
    reti


    ld c, [hl]
    ld d, h
    db $dd
    ld a, a
    add $26
    cp l
    ld c, [hl]
    inc e
    xor h
    add a
    adc h
    db $dd
    ld a, a
    or [hl]
    or h
    reti


    ld c, [hl]
    cp e
    sub $b3
    push bc
    rst $10
    ld d, b
    db $ed
    inc l
    add $42
    xor h
    add a
    adc h
    ld d, b
    ld hl, $d133
    ld bc, $002c
    jr jr_008_4330

    ld hl, $d9da
    ld bc, $0021

jr_008_4330:
    ld a, [$cf79]
    call Call_000_3ad1
    ld b, $04

jr_008_4338:
    ld a, [hl+]
    push hl
    push bc
    ld hl, $434c
    ld de, $0001
    call Call_000_3ddb
    pop bc
    pop hl
    ret c

    dec b
    jr nz, jr_008_4338

    and a
    ret


    rrca
    inc de
    add hl, sp
    ld b, [hl]
    sub h
    rst $38

Call_008_4352:
    ld hl, $c473
    ld b, $06
    ld c, $07
    call Call_000_03d2
    ld a, [$ccd3]
    and a
    ld de, $43d0
    jr nz, jr_008_4368

    ld de, $43d5

jr_008_4368:
    ld hl, $c49d
    call Call_000_0405
    ld hl, $c4c5
    ld de, $43da
    call Call_000_0405
    ld hl, $cc24
    ld a, $0c
    ld [hl+], a
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
    ld hl, $cc36
    ld [hl+], a
    ld [hl], a
    ld [$cc2f], a
    ld [$cc2b], a

jr_008_4394:
    call Call_000_3b08
    bit 1, a
    jr nz, jr_008_43a4

    ld a, [$cc26]
    and a
    jr z, jr_008_43a6

    dec a
    jr z, jr_008_43a8

jr_008_43a4:
    and a
    ret


jr_008_43a6:
    scf
    ret


jr_008_43a8:
    call Call_000_3761
    ld a, [$ccd3]
    and a
    ld a, $00
    jr nz, jr_008_43b5

Call_008_43b3:
    ld a, $02

jr_008_43b5:
    ld [$cc49], a
    ld a, $36
    call Call_000_3e9d
    ld a, $37
    call Call_000_3e9d
    call Call_000_376d
    call Call_000_1ba5
    call Call_000_3e1d
    call Call_000_0b3c
    jr jr_008_4394

    db $ed
    dec l
    ld c, e
    ld d, h
    ld d, b
    db $ed
    dec l
    ld d, b
    ld d, h
    ld d, b
    db $ed
    inc l
    db $d3
    ld b, d
    ret nc

    reti


    ld c, [hl]
    add [hl]
    xor l
    xor e
    adc l
    and [hl]
    ld d, b
    db $ed
    add hl, hl
    ld l, a
    ld h, l
    sub b
    ld a, a
    add h
    xor e
    rst $20
    ld e, b
    db $ed
    add hl, hl
    add l
    ld h, l
    ld a, a
    cp l
    reti


    sbc $e6
    ld d, a
    nop
    inc [hl]
    ret


    ld a, a
    ld d, h
    db $dd
    ld c, a
    or c
    dec l
    cp c
    ret nz

    or d
    sbc $d4
    and $57
    db $ed
    add hl, hl
    rst $10
    ld h, l
    db $dd
    ld a, a
    inc e
    xor h
    add a
    adc h
    ld d, b
    ld bc, $cd3d
    nop
    add $4f
    or c
    dec l
    cp c
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    sub c
    ld h, l
    or c
    dec l
    cp c
    ret nz

    rst $10
    ld c, a
    cp d
    rst $08
    reti


    sbc $7f
    pop bc
    ldh [$b3], a
    and $58
    db $ed
    add hl, hl
    cp d
    ld h, l
    rst $20
    ld a, a
    add d
    sub b
    jp z, Jump_008_544f

    inc sp
    ld a, a
    or d
    rst $18
    ld b, h
    or d
    call nc, $ed58
    add hl, hl
    and c
    ld h, [hl]
    db $dd
    ld c, a
    rst $08
    ret nz

    ld a, a
    jp nz, $c3da

    or d
    cp b
    ld a, a
    cp d
    call nz, $bcc6
    ret nz

    rst $20
    ld d, l
    ld d, b
    ld bc, $cf45
    nop
    db $dd
    ld a, a
    or e
    cp c
    call nz, $c0df
    rst $20
    ld e, b
    db $ed
    add hl, hl
    push hl

Jump_008_4470:
    ld h, [hl]
    ld c, a
    add d
    sub b
    jp z, $c57f

    sbc $d3
    ld a, a
    or c
    dec l
    or [hl]
    rst $18
    call nz, $ded7
    inc sp
    and $58
    db $ed
    add hl, hl
    ld h, $66
    sbc $7f
    or d
    or e
    jp Jump_008_4fd3


    ld d, h
    ld a, a
    db $d3
    pop bc
    or a
    jp c, $decd

    call nc, $b9de
    rst $20
    ld d, c
    call nz, $b1d8
    or h
    dec l
    ld a, a
    or c
    dec l
    cp c
    reti


    or [hl]
    ld a, a
    add $26
    cp l
    or [hl]
    ld c, a
    cp h
    ret nz

    rst $10
    ld a, a
    or h
    or h
    sbc $c1
    ldh [$b3], a
    and $58
    nop
    inc [hl]
    ret


    ld a, a
    ld d, h
    db $dd
    ld c, a
    add $26
    cp l
    sbc $d4
    and $57
    db $ed
    add hl, hl
    ld de, $c467
    ld a, a
    ld d, b
    ld bc, $cf45
    nop
    jp z, $d34f

    or e
    ld a, a
    db $d3
    inc [hl]
    rst $18
    jp $deba


    inc sp
    ld a, a
    or h
    or h
    sbc $b6
    and $57
    db $ed
    add hl, hl
    ld b, h
    ld h, a
    db $dd
    ld c, a
    cp a
    call nz, $7fc6
    add $26
    cp h
    jp $b17f


    add hl, hl
    ret nz

    rst $20
    ld d, l
    ld a, [hl-]
    or d
    ld a, [hl-]
    or d
    ld a, a
    ld d, b
    ld bc, $cf45
    nop
    rst $20
    ld e, b
    ldh a, [$aa]
    cp $01
    ret z

    ld a, [$c109]
    cp $0c
    ret nz

    ld a, [$d2dd]
    cp $ef
    ld a, $02
    jr z, jr_008_451a

    inc a

jr_008_451a:
    ld [$d0f0], a
    call Call_000_3c6c
    ld a, $22
    jp Jump_000_3f25


    ldh a, [$aa]
    cp $02
    ret z

    ld a, [$c109]
    cp $08
    ret nz

    ld a, [$d2dd]
    cp $ef
    ld a, $02
    jr z, jr_008_453a

    inc a

jr_008_453a:
    ld [$d0f0], a
    call Call_000_3c6c
    ld a, $22
    jp Jump_000_3f25


    nop
    pop bc
    ld [c], a
    rst $18
    call nz, $cf7f
    rst $18
    jp Jump_008_57c8


    ld a, [$c109]
    cp $04
    ret nz

    call Call_000_3c6c
    ld a, $23
    jp Jump_000_3f25


    db $fd
    ld c, $00

jr_008_4561:
    ld b, $00
    ld hl, $c026
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_008_458d

    ld a, c
    cp $04
    jr nc, jr_008_458a

    ld a, [$c002]
    and a
    jr z, jr_008_458a

    bit 7, a
    jr nz, jr_008_458d

    set 7, a
    ld [$c002], a
    xor a
    ldh [rNR51], a
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a
    jr jr_008_458d

jr_008_458a:
    call Call_008_4594

jr_008_458d:
    ld a, c
    inc c
    cp $07
    jr nz, jr_008_4561

    ret


Call_008_4594:
    ld b, $00
    ld hl, $c0b6
    add hl, bc
    ld a, [hl]
    cp $01
    jp z, Jump_008_462c

    dec a
    ld [hl], a
    ld a, c
    cp $04
    jr nc, jr_008_45b0

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_008_45b0

    ret


Call_008_45b0:
jr_008_45b0:
    ld hl, $c02e
    add hl, bc
    bit 6, [hl]
    jr z, jr_008_45bb

    call Call_008_4cb2

jr_008_45bb:
    ld b, $00
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_008_45cd

    ld hl, $c02e
    add hl, bc
    bit 2, [hl]
    jr nz, jr_008_45e1

jr_008_45cd:
    ld hl, $c02e
    add hl, bc
    bit 4, [hl]
    jr z, jr_008_45d8

    jp Jump_008_4b9e


jr_008_45d8:
    ld hl, $c04e
    add hl, bc
    ld a, [hl]
    and a
    jr z, jr_008_45e2

    dec [hl]

jr_008_45e1:
    ret


jr_008_45e2:
    ld hl, $c056
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_008_45eb

    ret


jr_008_45eb:
    ld d, a
    ld hl, $c05e
    add hl, bc
    ld a, [hl]
    and $0f
    and a
    jr z, jr_008_45f8

    dec [hl]
    ret


jr_008_45f8:
    ld a, [hl]
    swap [hl]
    or [hl]
    ld [hl], a
    ld hl, $c066
    add hl, bc
    ld e, [hl]
    ld hl, $c02e
    add hl, bc
    bit 3, [hl]
    jr z, jr_008_4618

    res 3, [hl]
    ld a, d
    and $0f
    ld d, a
    ld a, e
    sub d
    jr nc, jr_008_4616

    ld a, $00

jr_008_4616:
    jr jr_008_4624

jr_008_4618:
    set 3, [hl]
    ld a, d
    and $f0
    swap a
    add e
    jr nc, jr_008_4624

    ld a, $ff

jr_008_4624:
    ld d, a
    ld b, $03
    call Call_008_4cdd
    ld [hl], d
    ret


Jump_008_462c:
    ld hl, $c06e
    add hl, bc
    ld a, [hl]
    ld hl, $c04e
    add hl, bc
    ld [hl], a
    ld hl, $c02e
    add hl, bc
    res 4, [hl]
    res 5, [hl]
    ld a, c
    cp $04
    jr nz, jr_008_4649

    ld a, [$d060]
    bit 7, a
    ret nz

jr_008_4649:
    call Call_008_464d
    ret


Call_008_464d:
Jump_008_464d:
    call Call_008_4cca
    ld d, a
    cp $ff
    jp nz, Jump_008_46db

    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 1, [hl]
    jr nz, jr_008_468b

    ld a, c
    cp $03
    jr nc, jr_008_4667

    jr jr_008_46a6

jr_008_4667:
    res 2, [hl]
    ld hl, $c036
    add hl, bc
    res 0, [hl]
    cp $06
    jr nz, jr_008_467b

    ld a, $00
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a

jr_008_467b:
    jr nz, jr_008_4689

    ld a, [$c003]
    and a
    jr z, jr_008_4689

    xor a
    ld [$c003], a
    jr jr_008_46a6

jr_008_4689:
    jr jr_008_46af

jr_008_468b:
    res 1, [hl]
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, $c006
    add hl, de
    push hl
    ld hl, $c016
    add hl, de
    ld e, l
    ld d, h
    pop hl
    ld a, [de]
    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl], a
    jp Jump_008_464d


jr_008_46a6:
    ld hl, $4fc4
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a

jr_008_46af:
    ld a, [$c02a]
    cp $14
    jr nc, jr_008_46b8

    jr jr_008_46d5

jr_008_46b8:
    ld a, [$c02a]
    cp $86
    jr z, jr_008_46d5

    jr c, jr_008_46c3

    jr jr_008_46d5

jr_008_46c3:
    ld a, c
    cp $04
    jr z, jr_008_46cc

    call Call_008_4b53
    ret c

jr_008_46cc:
    ld a, [$c005]
    ldh [rNR50], a
    xor a
    ld [$c005], a

jr_008_46d5:
    ld hl, $c026
    add hl, bc
    ld [hl], b
    ret


Jump_008_46db:
    cp $fd
    jp nz, Jump_008_4710

    call Call_008_4cca
    push af
    call Call_008_4cca
    ld d, a
    pop af
    ld e, a
    push de
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, $c006
    add hl, de
    push hl
    ld hl, $c016
    add hl, de
    ld e, l
    ld d, h
    pop hl
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl-]
    ld [de], a
    pop de
    ld [hl], e
    inc hl
    ld [hl], d
    ld b, $00
    ld hl, $c02e
    add hl, bc
    set 1, [hl]
    jp Jump_008_464d


Jump_008_4710:
    cp $fe
    jp nz, Jump_008_474b

    call Call_008_4cca
    ld e, a
    and a
    jr z, jr_008_4734

    ld b, $00
    ld hl, $c0be
    add hl, bc
    ld a, [hl]
    cp e
    jr nz, jr_008_4732

    ld a, $01
    ld [hl], a
    call Call_008_4cca
    call Call_008_4cca
    jp Jump_008_464d


jr_008_4732:
    inc a
    ld [hl], a

jr_008_4734:
    call Call_008_4cca
    push af
    call Call_008_4cca
    ld b, a
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, $c006
    add hl, de
    pop af
    ld [hl+], a
    ld [hl], b
    jp Jump_008_464d


Jump_008_474b:
    and $f0
    cp $d0
    jp nz, Jump_008_478a

    ld a, d
    and $0f
    ld b, $00
    ld hl, $c0c6
    add hl, bc
    ld [hl], a
    ld a, c
    cp $03
    jr z, jr_008_4787

    call Call_008_4cca
    ld d, a
    ld a, c
    cp $02
    jr z, jr_008_4773

    cp $06
    jr nz, jr_008_4780

    ld hl, $c0e7
    jr jr_008_4776

jr_008_4773:
    ld hl, $c0e6

jr_008_4776:
    ld a, d
    and $0f
    ld [hl], a
    ld a, d
    and $30
    sla a
    ld d, a

jr_008_4780:
    ld b, $00
    ld hl, $c0de
    add hl, bc
    ld [hl], d

jr_008_4787:
    jp Jump_008_464d


Jump_008_478a:
    ld a, d
    cp $e8
    jr nz, jr_008_479c

    ld b, $00
    ld hl, $c02e
    add hl, bc
    ld a, [hl]
    xor $01
    ld [hl], a
    jp Jump_008_464d


jr_008_479c:
    cp $ea
    jr nz, jr_008_47d4

Call_008_47a0:
    call Call_008_4cca
    ld b, $00
    ld hl, $c04e
    add hl, bc
    ld [hl], a
    ld hl, $c06e
    add hl, bc
    ld [hl], a
    call Call_008_4cca
    ld d, a
    and $f0
    swap a

Call_008_47b7:
    ld b, $00
    ld hl, $c056
    add hl, bc
    srl a
    ld e, a

Call_008_47c0:
    adc b
    swap a
    or e
    ld [hl], a
    ld a, d
    and $0f
    ld d, a
    ld hl, $c05e
    add hl, bc
    swap a
    or d
    ld [hl], a
    jp Jump_008_464d


jr_008_47d4:
    cp $eb
    jr nz, jr_008_480c

    call Call_008_4cca
    ld b, $00
    ld hl, $c076
    add hl, bc
    ld [hl], a
    call Call_008_4cca
    ld d, a
    and $f0
    swap a
    ld b, a
    ld a, d
    and $0f
    call Call_008_4cfd
    ld b, $00
    ld hl, $c0a6
    add hl, bc
    ld [hl], d
    ld hl, $c0ae
    add hl, bc
    ld [hl], e
    ld b, $00
    ld hl, $c02e
    add hl, bc
    set 4, [hl]
    call Call_008_4cca
    ld d, a
    jp Jump_008_4971


jr_008_480c:
    cp $ec
    jr nz, jr_008_4821

    call Call_008_4cca
    rrca
    rrca
    and $c0
    ld b, $00
    ld hl, $c03e
    add hl, bc
    ld [hl], a
    jp Jump_008_464d


jr_008_4821:
    cp $ed
    jr nz, jr_008_4861

    ld a, c
    cp $04
    jr nc, jr_008_4845

    call Call_008_4cca
    ld [$c0e8], a
    call Call_008_4cca
    ld [$c0e9], a
    xor a
    ld [$c0ce], a
    ld [$c0cf], a
    ld [$c0d0], a
    ld [$c0d1], a
    jr jr_008_485e

jr_008_4845:
    call Call_008_4cca
    ld [$c0ea], a
    call Call_008_4cca
    ld [$c0eb], a
    xor a
    ld [$c0d2], a
    ld [$c0d3], a
    ld [$c0d4], a
    ld [$c0d5], a

jr_008_485e:
    jp Jump_008_464d


jr_008_4861:
    cp $ee
    jr nz, jr_008_486e

    call Call_008_4cca
    ld [$c004], a
    jp Jump_008_464d


jr_008_486e:
    cp $ef
    jr nz, jr_008_488d

    call Call_008_4cca
    push bc
    call Call_008_4d1b
    pop bc
    ld a, [$c003]
    and a
    jr nz, jr_008_488a

    ld a, [$c02d]
    ld [$c003], a
    xor a
    ld [$c02d], a

jr_008_488a:
    jp Jump_008_464d


jr_008_488d:
    cp $fc
    jr nz, jr_008_48ab

    call Call_008_4cca
    ld b, $00
    ld hl, $c046
    add hl, bc
    ld [hl], a
    and $c0
    ld hl, $c03e
    add hl, bc
    ld [hl], a
    ld hl, $c02e
    add hl, bc
    set 6, [hl]
    jp Jump_008_464d


jr_008_48ab:
    cp $f0
    jr nz, jr_008_48b7

    call Call_008_4cca
    ldh [rNR50], a
    jp Jump_008_464d


jr_008_48b7:
    cp $f8
    jr nz, jr_008_48c6

    ld b, $00
    ld hl, $c036
    add hl, bc
    set 0, [hl]
    jp Jump_008_464d


jr_008_48c6:
    and $f0
    cp $e0
    jr nz, jr_008_48d9

    ld hl, $c0d6
    ld b, $00
    add hl, bc
    ld a, d
    and $0f
    ld [hl], a
    jp Jump_008_464d


jr_008_48d9:
    cp $20
    jr nz, jr_008_4926

    ld a, c
    cp $03
    jr c, jr_008_4926

    ld b, $00
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_008_4926

    call Call_008_4971
    ld d, a
    ld b, $00
    ld hl, $c03e
    add hl, bc
    ld a, [hl]
    or d
    ld d, a
    ld b, $01
    call Call_008_4cdd
    ld [hl], d
    call Call_008_4cca
    ld d, a
    ld b, $02
    call Call_008_4cdd
    ld [hl], d
    call Call_008_4cca
    ld e, a
    ld a, c
    cp $07
    ld a, $00
    jr z, jr_008_4919

    push de
    call Call_008_4cca
    pop de

jr_008_4919:
    ld d, a
    push de
    call Call_008_4a90
    call Call_008_4a5f
    pop de
    call Call_008_4ab2
    ret


jr_008_4926:
    ld a, c
    cp $04
    jr c, jr_008_4942

    ld a, d
    cp $10
    jr nz, jr_008_4942

    ld b, $00
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_008_4942

    call Call_008_4cca
    ldh [rNR10], a
    jp Jump_008_464d


jr_008_4942:
    ld a, c
    cp $03
    jr nz, jr_008_4971

    ld a, d
    and $f0
    cp $b0
    jr z, jr_008_495c

    jr nc, jr_008_4971

    swap a
    ld b, a
    ld a, d
    and $0f
    ld d, a
    ld a, b
    push de
    push bc
    jr jr_008_4964

jr_008_495c:
    ld a, d
    and $0f
    push af
    push bc
    call Call_008_4cca

jr_008_4964:
    ld d, a
    ld a, [$c003]
    and a
    jr nz, jr_008_496f

    ld a, d
    call Call_008_4d1b

jr_008_496f:
    pop bc
    pop de

Call_008_4971:
Jump_008_4971:
jr_008_4971:
    ld a, d
    push af
    and $0f
    inc a
    ld b, $00
    ld e, a
    ld d, b
    ld hl, $c0c6
    add hl, bc
    ld a, [hl]
    ld l, b
    call Call_008_4cec
    ld a, c
    cp $04
    jr nc, jr_008_4992

    ld a, [$c0e8]
    ld d, a
    ld a, [$c0e9]
    ld e, a
    jr jr_008_49a5

jr_008_4992:
    ld d, $01
    ld e, $00
    cp $07
    jr z, jr_008_49a5

    call Call_008_4b15
    ld a, [$c0ea]
    ld d, a
    ld a, [$c0eb]
    ld e, a

jr_008_49a5:
    ld a, l
    ld b, $00
    ld hl, $c0ce
    add hl, bc
    ld l, [hl]
    call Call_008_4cec
    ld e, l
    ld d, h
    ld hl, $c0ce
    add hl, bc
    ld [hl], e
    ld a, d
    ld hl, $c0b6
    add hl, bc
    ld [hl], a
    ld hl, $c036
    add hl, bc
    bit 0, [hl]
    jr nz, jr_008_49cf

    ld hl, $c02e
    add hl, bc
    bit 2, [hl]
    jr z, jr_008_49cf

    pop hl
    ret


jr_008_49cf:
    pop af
    and $f0
    cp $c0
    jr nz, jr_008_4a06

    ld a, c
    cp $04
    jr nc, jr_008_49e3

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_008_4a05

jr_008_49e3:
    ld a, c
    cp $02
    jr z, jr_008_49ec

    cp $06
    jr nz, jr_008_49f9

jr_008_49ec:
    ld b, $00
    ld hl, $4fc4
    add hl, bc
    ldh a, [rNR51]
    and [hl]
    ldh [rNR51], a
    jr jr_008_4a05

jr_008_49f9:
    ld b, $02
    call Call_008_4cdd
    ld a, $08
    ld [hl+], a
    inc hl
    ld a, $80
    ld [hl], a

jr_008_4a05:
    ret


jr_008_4a06:
    swap a
    ld b, $00
    ld hl, $c0d6
    add hl, bc
    ld b, [hl]
    call Call_008_4cfd
    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 4, [hl]
    jr z, jr_008_4a1f

    call Call_008_4c34

jr_008_4a1f:
    push de
    ld a, c
    cp $04
    jr nc, jr_008_4a34

    ld hl, $c02a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    and a
    jr nz, jr_008_4a32

    jr jr_008_4a34

jr_008_4a32:
    pop de
    ret


jr_008_4a34:
    ld b, $00
    ld hl, $c0de
    add hl, bc
    ld d, [hl]
    ld b, $02
    call Call_008_4cdd
    ld [hl], d
    call Call_008_4a90
    call Call_008_4a5f
    pop de
    ld b, $00
    ld hl, $c02e
    add hl, bc
    bit 0, [hl]
    jr z, jr_008_4a56

    inc e
    jr nc, jr_008_4a56

    inc d

jr_008_4a56:
    ld hl, $c066
    add hl, bc
    ld [hl], e
    call Call_008_4ab2
    ret


Call_008_4a5f:
    ld b, $00
    ld hl, $4fcc
    add hl, bc
    ldh a, [rNR51]
    or [hl]
    ld d, a
    ld a, c
    cp $07
    jr z, jr_008_4a7a

    cp $04
    jr nc, jr_008_4a8c

    ld hl, $c02a
    add hl, bc
    ld a, [hl]
    and a
    jr nz, jr_008_4a8c

jr_008_4a7a:
    ld a, [$c004]
    ld hl, $4fcc
    add hl, bc
    and [hl]
    ld d, a
    ldh a, [rNR51]
    ld hl, $4fc4
    add hl, bc
    and [hl]
    or d
    ld d, a

jr_008_4a8c:
    ld a, d
    ldh [rNR51], a
    ret


Call_008_4a90:
    ld b, $00
    ld hl, $c0b6
    add hl, bc
    ld d, [hl]
    ld a, c
    cp $02
    jr z, jr_008_4aab

    cp $06
    jr z, jr_008_4aab

    ld a, d
    and $3f
    ld d, a
    ld hl, $c03e
    add hl, bc
    ld a, [hl]
    or d
    ld d, a

jr_008_4aab:
    ld b, $01
    call Call_008_4cdd
    ld [hl], d
    ret


Call_008_4ab2:
    ld a, c
    cp $02
    jr z, jr_008_4abb

    cp $06
    jr nz, jr_008_4ae8

jr_008_4abb:
    push de
    ld de, $c0e6
    cp $02
    jr z, jr_008_4ac6

    ld de, $c0e7

jr_008_4ac6:
    ld a, [de]
    add a
    ld d, $00
    ld e, a
    ld hl, $6ff3
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld hl, $ff30
    ld b, $0f
    ld a, $00
    ldh [rNR30], a

jr_008_4adb:
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, b
    dec b
    and a
    jr nz, jr_008_4adb

    ld a, $80
    ldh [rNR30], a
    pop de

jr_008_4ae8:
    ld a, d
    or $80
    and $c7
    ld d, a
    ld b, $03
    call Call_008_4cdd
    ld [hl], e
    inc hl
    ld [hl], d
    ld a, c
    cp $04
    jr c, jr_008_4afe

    call Call_008_4b3c

jr_008_4afe:
    ret


    ld a, c
    cp $04
    jr nz, jr_008_4b14

    ld a, [$d060]
    bit 7, a
    jr z, jr_008_4b14

    xor a
    ld [$c0f1], a
    ld a, $80
    ld [$c0f2], a

jr_008_4b14:
    ret


Call_008_4b15:
    call Call_008_4b71
    jr c, jr_008_4b1f

    call Call_008_4b85
    jr nc, jr_008_4b32

jr_008_4b1f:
    ld d, $00
    ld a, [$c0f2]
    add $80
    jr nc, jr_008_4b29

    inc d

jr_008_4b29:
    ld [$c0eb], a
    ld a, d
    ld [$c0ea], a
    jr jr_008_4b3b

jr_008_4b32:
    xor a
    ld [$c0eb], a
    ld a, $01
    ld [$c0ea], a

jr_008_4b3b:
    ret


Call_008_4b3c:
    call Call_008_4b71
    jr c, jr_008_4b46

    call Call_008_4b85
    jr nc, jr_008_4b52

jr_008_4b46:
    ld a, [$c0f1]
    add e
    jr nc, jr_008_4b4d

    inc d

jr_008_4b4d:
    dec hl
    ld e, a
    ld [hl], e
    inc hl
    ld [hl], d

jr_008_4b52:
    ret


Call_008_4b53:
    call Call_008_4b71
    jr nc, jr_008_4b6e

    ld hl, $c006
    ld e, c
    ld d, $00
    sla e

Call_008_4b60:
    rl d
    add hl, de
    ld a, [hl]
    sub $01
    ld [hl], a

Call_008_4b67:
    inc hl
    ld a, [hl]
    sbc $00
    ld [hl], a
    scf
    ret


jr_008_4b6e:
    scf
    ccf
    ret


Call_008_4b71:
    ld a, [$c02a]
    cp $14
    jr nc, jr_008_4b7a

    jr jr_008_4b80

jr_008_4b7a:
    cp $86
    jr z, jr_008_4b80

    jr c, jr_008_4b83

jr_008_4b80:
    scf
    ccf
    ret


jr_008_4b83:
    scf
    ret


Call_008_4b85:
    ld a, [$c02d]
    ld b, a
    ld a, [$c02a]
    or b
    cp $9d
    jr nc, jr_008_4b93

    jr jr_008_4b99

jr_008_4b93:
    cp $ea
    jr z, jr_008_4b99

    jr c, jr_008_4b9c

jr_008_4b99:
    scf
    ccf
    ret


jr_008_4b9c:
    scf
    ret


Jump_008_4b9e:
    ld hl, $c02e
    add hl, bc
    bit 5, [hl]
    jp nz, Jump_008_4be5

    ld hl, $c09e
    add hl, bc
    ld e, [hl]
    ld hl, $c096
    add hl, bc
    ld d, [hl]
    ld hl, $c07e
    add hl, bc
    ld l, [hl]
    ld h, b
    add hl, de
    ld d, h
    ld e, l
    ld hl, $c08e
    add hl, bc
    push hl
    ld hl, $c086
    add hl, bc
    ld a, [hl]
    pop hl
    add [hl]
    ld [hl], a
    ld a, $00
    adc e
    ld e, a
    ld a, $00
    adc d
    ld d, a
    ld hl, $c0a6
    add hl, bc
    ld a, [hl]
    cp d
    jp c, Jump_008_4c2b

    jr nz, jr_008_4c18

    ld hl, $c0ae
    add hl, bc
    ld a, [hl]
    cp e
    jp c, Jump_008_4c2b

    jr jr_008_4c18

Jump_008_4be5:
    ld hl, $c09e
    add hl, bc
    ld a, [hl]
    ld hl, $c096
    add hl, bc
    ld d, [hl]
    ld hl, $c07e
    add hl, bc
    ld e, [hl]
    sub e
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, $c086
    add hl, bc
    ld a, [hl]
    add a
    ld [hl], a
    ld a, e
    sbc b
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, $c0a6
    add hl, bc
    ld a, d
    cp [hl]
    jr c, jr_008_4c2b

    jr nz, jr_008_4c18

    ld hl, $c0ae
    add hl, bc
    ld a, e
    cp [hl]
    jr c, jr_008_4c2b

jr_008_4c18:
    ld hl, $c09e
    add hl, bc
    ld [hl], e
    ld hl, $c096
    add hl, bc
    ld [hl], d
    ld b, $03
    call Call_008_4cdd
    ld a, e
    ld [hl+], a
    ld [hl], d
    ret


Jump_008_4c2b:
jr_008_4c2b:
    ld hl, $c02e
    add hl, bc
    res 4, [hl]
    res 5, [hl]
    ret


Call_008_4c34:
    ld hl, $c096
    add hl, bc
    ld [hl], d
    ld hl, $c09e
    add hl, bc
    ld [hl], e
    ld hl, $c0b6
    add hl, bc
    ld a, [hl]
    ld hl, $c076
    add hl, bc
    sub [hl]
    jr nc, jr_008_4c4c

    ld a, $01

jr_008_4c4c:
    ld [hl], a
    ld hl, $c0ae
    add hl, bc
    ld a, e
    sub [hl]
    ld e, a
    ld a, d
    sbc b
    ld hl, $c0a6
    add hl, bc
    sub [hl]
    jr c, jr_008_4c68

    ld d, a
    ld b, $00
    ld hl, $c02e
    add hl, bc
    set 5, [hl]
    jr jr_008_4c8b

jr_008_4c68:
    ld hl, $c096
    add hl, bc
    ld d, [hl]
    ld hl, $c09e
    add hl, bc
    ld e, [hl]
    ld hl, $c0ae
    add hl, bc
    ld a, [hl]
    sub e
    ld e, a
    ld a, d
    sbc b
    ld d, a
    ld hl, $c0a6
    add hl, bc
    ld a, [hl]
    sub d
    ld d, a
    ld b, $00
    ld hl, $c02e
    add hl, bc
    res 5, [hl]

jr_008_4c8b:
    ld hl, $c076
    add hl, bc

jr_008_4c8f:
    inc b
    ld a, e
    sub [hl]
    ld e, a
    jr nc, jr_008_4c8f

    ld a, d
    and a
    jr z, jr_008_4c9d

    dec a
    ld d, a
    jr jr_008_4c8f

jr_008_4c9d:
    ld a, e
    add [hl]
    ld d, b
    ld b, $00
    ld hl, $c07e
    add hl, bc
    ld [hl], d
    ld hl, $c086
    add hl, bc
    ld [hl], a
    ld hl, $c08e
    add hl, bc
    ld [hl], a
    ret


Call_008_4cb2:
    ld b, $00
    ld hl, $c046
    add hl, bc
    ld a, [hl]
    rlca
    rlca
    ld [hl], a
    and $c0
    ld d, a
    ld b, $01
    call Call_008_4cdd
    ld a, [hl]
    and $3f
    or d
    ld [hl], a
    ret


Call_008_4cca:
    ld d, $00
    ld a, c
    add a
    ld e, a
    ld hl, $c006
    add hl, de
    ld a, [hl+]
    ld e, a
    ld a, [hl-]
    ld d, a
    ld a, [de]
    inc de
    ld [hl], e
    inc hl
    ld [hl], d
    ret


Call_008_4cdd:
    ld a, c
    ld hl, $4fbc
    add l
    jr nc, jr_008_4ce5

    inc h

jr_008_4ce5:
    ld l, a
    ld a, [hl]
    add b
    ld l, a
    ld h, $ff
    ret


Call_008_4cec:
    ld h, $00

jr_008_4cee:
    srl a
    jr nc, jr_008_4cf3

    add hl, de

jr_008_4cf3:
    sla e
    rl d
    and a
    jr z, jr_008_4cfc

    jr jr_008_4cee

jr_008_4cfc:
    ret


Call_008_4cfd:
    ld h, $00
    ld l, a
    add hl, hl
    ld d, h
    ld e, l
    ld hl, $4fd4
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld a, b

jr_008_4d0b:
    cp $07
    jr z, jr_008_4d16

    sra d
    rr e
    inc a
    jr jr_008_4d0b

jr_008_4d16:
    ld a, $08
    add d
    ld d, a
    ret


Call_008_4d1b:
    ld [$c001], a
    cp $ff
    jp z, Jump_008_4ed9

    cp $e9
    jp z, Jump_008_4df3

    jp c, Jump_008_4df3

    cp $fe
    jr z, jr_008_4d32

    jp nc, Jump_008_4df3

jr_008_4d32:
    xor a
    ld [$c000], a
    ld [$c003], a
    ld [$c0e9], a
    ld [$c0e6], a
    ld [$c0e7], a
    ld d, $08
    ld hl, $c016
    call Call_008_4f2e
    ld hl, $c006
    call Call_008_4f2e
    ld d, $04
    ld hl, $c026
    call Call_008_4f2e
    ld hl, $c02e
    call Call_008_4f2e
    ld hl, $c03e
    call Call_008_4f2e
    ld hl, $c046
    call Call_008_4f2e
    ld hl, $c04e
    call Call_008_4f2e
    ld hl, $c056
    call Call_008_4f2e
    ld hl, $c05e
    call Call_008_4f2e
    ld hl, $c066
    call Call_008_4f2e
    ld hl, $c06e
    call Call_008_4f2e
    ld hl, $c036
    call Call_008_4f2e
    ld hl, $c076
    call Call_008_4f2e
    ld hl, $c07e
    call Call_008_4f2e
    ld hl, $c086
    call Call_008_4f2e
    ld hl, $c08e
    call Call_008_4f2e
    ld hl, $c096
    call Call_008_4f2e
    ld hl, $c09e
    call Call_008_4f2e
    ld hl, $c0a6
    call Call_008_4f2e
    ld hl, $c0ae
    call Call_008_4f2e
    ld a, $01
    ld hl, $c0be
    call Call_008_4f2e
    ld hl, $c0b6
    call Call_008_4f2e
    ld hl, $c0c6
    call Call_008_4f2e
    ld [$c0e8], a
    ld a, $ff
    ld [$c004], a
    xor a
    ldh [rNR50], a
    ld a, $08
    ldh [rNR10], a
    ld a, $00
    ldh [rNR51], a
    xor a
    ldh [rNR30], a
    ld a, $80
    ldh [rNR30], a
    ld a, $77
    ldh [rNR50], a
    jp Jump_008_4f34


Jump_008_4df3:
    ld l, a
    ld e, a
    ld h, $00
    ld d, h
    add hl, hl
    add hl, de
    ld de, $6c92
    add hl, de
    ld a, h
    ld [$c0ec], a
    ld a, l
    ld [$c0ed], a
    ld a, [hl]
    and $c0
    rlca
    rlca
    ld c, a

Jump_008_4e0c:
    ld d, c
    ld a, c
    add a
    add c
    ld c, a
    ld b, $00
    ld a, [$c0ec]
    ld h, a
    ld a, [$c0ed]
    ld l, a
    add hl, bc
    ld c, d
    ld a, [hl]
    and $0f
    ld e, a
    ld d, $00
    ld hl, $c026
    add hl, de
    ld a, [hl]
    and a
    jr z, jr_008_4e48

    ld a, e
    cp $07
    jr nz, jr_008_4e3f

    ld a, [$c001]
    cp $14
    jr nc, jr_008_4e38

    ret


jr_008_4e38:
    ld a, [hl]
    cp $14
    jr z, jr_008_4e48

    jr c, jr_008_4e48

jr_008_4e3f:
    ld a, [$c001]
    cp [hl]
    jr z, jr_008_4e48

    jr c, jr_008_4e48

    ret


jr_008_4e48:
    xor a
    push de
    ld h, d
    ld l, e
    add hl, hl
    ld d, h
    ld e, l
    ld hl, $c016
    add hl, de
    ld [hl+], a
    ld [hl], a
    ld hl, $c006
    add hl, de
    ld [hl+], a
    ld [hl], a
    pop de
    ld hl, $c026
    add hl, de
    ld [hl], a
    ld hl, $c02e
    add hl, de
    ld [hl], a
    ld hl, $c03e
    add hl, de
    ld [hl], a
    ld hl, $c046
    add hl, de
    ld [hl], a
    ld hl, $c04e
    add hl, de
    ld [hl], a
    ld hl, $c056
    add hl, de
    ld [hl], a
    ld hl, $c05e
    add hl, de
    ld [hl], a
    ld hl, $c066
    add hl, de
    ld [hl], a
    ld hl, $c06e
    add hl, de
    ld [hl], a
    ld hl, $c076
    add hl, de
    ld [hl], a
    ld hl, $c07e
    add hl, de
    ld [hl], a
    ld hl, $c086
    add hl, de
    ld [hl], a
    ld hl, $c08e
    add hl, de
    ld [hl], a
    ld hl, $c096
    add hl, de
    ld [hl], a
    ld hl, $c09e
    add hl, de
    ld [hl], a
    ld hl, $c0a6
    add hl, de
    ld [hl], a
    ld hl, $c0ae
    add hl, de
    ld [hl], a
    ld hl, $c036
    add hl, de
    ld [hl], a
    ld a, $01
    ld hl, $c0be
    add hl, de
    ld [hl], a
    ld hl, $c0b6
    add hl, de
    ld [hl], a
    ld hl, $c0c6
    add hl, de
    ld [hl], a
    ld a, e
    cp $04
    jr nz, jr_008_4ed0

    ld a, $08
    ldh [rNR10], a

jr_008_4ed0:
    ld a, c
    and a
    jp z, Jump_008_4f34

    dec c
    jp Jump_008_4e0c


Jump_008_4ed9:
    ld a, $80
    ldh [rNR52], a
    ldh [rNR30], a
    xor a
    ldh [rNR51], a
    ldh [rNR32], a
    ld a, $08
    ldh [rNR10], a
    ldh [rNR12], a
    ldh [rNR22], a
    ldh [rNR42], a
    ld a, $40
    ldh [rNR14], a
    ldh [rNR24], a
    ldh [rNR44], a
    ld a, $77
    ldh [rNR50], a
    xor a
    ld [$c000], a
    ld [$c003], a
    ld [$c002], a
    ld [$c0e9], a
    ld [$c0eb], a
    ld [$c0e6], a
    ld [$c0e7], a
    ld d, $a0
    ld hl, $c006
    call Call_008_4f2e
    ld a, $01
    ld d, $18
    ld hl, $c0b6
    call Call_008_4f2e
    ld [$c0e8], a
    ld [$c0ea], a
    ld a, $ff
    ld [$c004], a
    ret


Call_008_4f2e:
    ld b, d

jr_008_4f2f:
    ld [hl+], a
    dec b
    jr nz, jr_008_4f2f

    ret


Jump_008_4f34:
    ld a, [$c001]
    ld l, a
    ld e, a
    ld h, $00
    ld d, h
    add hl, hl
    add hl, de
    ld de, $6c92
    add hl, de
    ld e, l
    ld d, h
    ld hl, $c006
    ld a, [de]
    ld b, a
    rlca
    rlca
    and $03
    ld c, a
    ld a, b
    and $0f
    ld b, c
    inc b
    inc de
    ld c, $00

jr_008_4f56:
    cp c
    jr z, jr_008_4f5e

    inc c
    inc hl
    inc hl
    jr jr_008_4f56

jr_008_4f5e:
    push hl
    push bc
    push af
    ld b, $00
    ld c, a
    ld hl, $c026
    add hl, bc
    ld a, [$c001]
    ld [hl], a
    pop af
    cp $03
    jr c, jr_008_4f77

    ld hl, $c02e
    add hl, bc
    set 2, [hl]

jr_008_4f77:
    pop bc
    pop hl
    ld a, [de]
    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl+], a
    inc de
    inc c
    dec b
    ld a, b
    and a
    ld a, [de]
    inc de
    jr nz, jr_008_4f56

    ld a, [$c001]
    cp $14
    jr nc, jr_008_4f90

    jr jr_008_4fba

jr_008_4f90:
    ld a, [$c001]
    cp $86
    jr z, jr_008_4fba

    jr c, jr_008_4f9b

    jr jr_008_4fba

jr_008_4f9b:
    ld hl, $c02a
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld hl, $c012
    ld de, $4fbb
    ld [hl], e
    inc hl
    ld [hl], d
    ld a, [$c005]
    and a
    jr nz, jr_008_4fba

    ldh a, [rNR50]
    ld [$c005], a
    ld a, $77
    ldh [rNR50], a

jr_008_4fba:
    ret


    rst $38
    db $10
    dec d
    ld a, [de]
    rra

Call_008_4fc0:
    db $10
    dec d
    ld a, [de]
    rra
    xor $dd
    cp e

Call_008_4fc7:
    ld [hl], a
    xor $dd
    cp e
    ld [hl], a
    ld de, $4422
    adc b
    ld de, $4422

Jump_008_4fd3:
    adc b
    inc l
    ld hl, sp-$63
    ld hl, sp+$07
    ld sp, hl
    ld l, e
    ld sp, hl
    jp z, Jump_000_23f9

    ld a, [$fa77]
    rst $00
    ld a, [$fb12]
    ld e, b
    ei
    sbc e
    ei
    jp c, Jump_000_3efb

    sbc d
    call Call_000_3788
    ld hl, $c00e
    ld de, $5008
    call Call_008_5003
    ld de, $500b
    call Call_008_5003
    ld de, $712d

Call_008_5003:
    ld a, e
    ld [hl+], a
    ld a, d
    ld [hl+], a
    ret


    db $ed
    ld bc, $f800
    ret c

    nop
    call nz, $c4c6
    call nz, $c4c4
    rst $38
    ld hl, sp-$13
    ld bc, $f000
    ld [hl], a
    ld [$2606], a
    db $ec
    ld [bc], a
    add sp, -$2a
    or c
    push hl
    add c
    add c
    sub $b3
    add c
    or c
    db $e4
    ld b, a
    rst $38
    ld hl, sp-$16
    ld [$ec27], sp
    ld [bc], a
    sub $c1
    db $e4
    ld b, c
    ld b, b
    ld b, b
    sub $c3
    ld b, c
    add c
    or a
    rst $38
    ld hl, sp-$2a
    db $10
    db $e4
    or b
    ret nz

    db $d3
    db $10
    or b
    ret nz

    or b
    ret nz

    sub $10
    or b
    ret nz

    db $e3
    ld b, b
    ret nz

    db $e4
    or e
    jp $edff


    nop
    ld l, b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3408], a

Call_008_5060:
    add sp, -$24
    or e
    push bc
    push hl
    ld h, b
    ld d, b
    ld b, b
    ld d, b
    ld b, b
    jr nc, jr_008_50ac

    jr nc, @+$22

    jr nc, jr_008_5090

    db $10
    jr nz, jr_008_5083

    nop
    stop
    and $b0
    rst $20
    add b
    sub b
    and b
    sub b
    and b
    or b
    and b
    or b
    and $60

jr_008_5083:
    adc $60
    ret z

    ld [hl], l
    ld h, b
    adc $60
    ret z

    ld d, l
    ld h, b
    adc $60
    ret z

jr_008_5090:
    ld [hl], l
    ld h, b
    adc $60
    ret z

    sub l
    ld h, b
    push hl
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b

jr_008_50ac:
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    and $40
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10

Call_008_50c1:
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl

Jump_008_50e3:
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    ld h, b
    push hl
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    ld h, b
    ld b, b
    db $10
    and $40
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    push hl
    db $10
    and $b0
    sub b
    pop bc
    rst $20
    or b
    ret nz

    and $23
    rst $20
    or b
    ret nz

    or b
    ret nz

    and $43
    rst $20
    or b
    ret nz

    or b
    ret nz

    and $23
    rst $20
    or b
    ret nz

    and $11
    rst $20
    or b
    ret nz

    or b
    ret nz

    and $23
    rst $20
    or b
    ret nz

    or b
    ret nz

    and $43
    rst $20
    or b
    ret nz

    or b
    ret nz

    and $23
    rst $20
    or b
    ret nz

    or b
    ret nz

    and $11
    rst $20
    or c
    sub c
    and $11
    rst $20
    or b
    ret nz

    or b
    ret nz

    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b

Call_008_51b1:
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    rst $08
    rst $20
    or b
    ret nz

    or b
    ret nz

    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    push hl
    nop
    and $b0
    sub b
    or b
    rst $20
    sub b
    ret nz

    sub b
    ret nz

    call c, $e5b5
    dec de
    call c, $e7b3
    sub b
    ret nz

    sub b
    ret nz

    call c, $e5b5
    sbc e
    call c, $33b3
    inc de
    inc sp
    ld b, c
    ld h, e
    and $b1
    push hl
    ld de, $b161
    ld h, c
    ld sp, $e761
    sub b
    ret nz

    sub b
    ret nz

    call c, $e5b5
    sbc e
    call c, $10b3
    and $b0
    push hl
    db $10
    jr nc, @+$42

    jr nc, jr_008_529b

    ld h, b
    sub b
    add b
    ld h, b
    ld b, b
    ld h, b
    ld b, b
    jr nc, @+$12

    call c, Call_000_33b5
    ld b, e
    ld de, $6335
    ld b, c
    inc sp
    dec d
    rst $08
    ret


    ld b, l
    inc sp
    ld b, e
    ld de, $4335
    ld sp, $e613
    or l
    push hl
    inc sp
    ld b, e
    ld de, $6335
    sub c
    add e
    ld b, l
    cp $00
    sub [hl]
    ld d, b
    db $ec
    inc bc
    ld [$2508], a
    call c, $e4c3
    ld d, b
    ld b, b
    jr nc, jr_008_52d3

    jr nc, @+$22

    jr nc, jr_008_52b7

    db $10
    jr nz, jr_008_52aa

    nop

jr_008_529b:
    push hl
    or b
    call nz, Call_008_5060
    ld b, b
    ld d, b
    ld b, b
    jr nc, jr_008_52e5

    jr nc, @+$22

    jr nc, jr_008_52c9

    db $10

jr_008_52aa:
    jr nz, jr_008_52bc

    or b
    adc $b0
    ret z

    db $e4
    dec b
    push hl
    or b
    adc $b0
    ret z

jr_008_52b7:
    and l
    push hl
    or b
    adc $b0

jr_008_52bc:
    ret z

    db $e4
    dec b
    push hl
    or b
    adc $b0
    ret z

    db $e4
    dec d
    call c, $33c5

jr_008_52c9:
    inc de
    inc sp
    ld b, c
    ld h, e
    ld b, e
    ld sp, $e511
    or c
    db $e4

jr_008_52d3:
    ld de, $dc31
    or a
    db $ec
    ld [bc], a
    push hl
    sub a
    db $e4
    rla
    ld b, a
    rla
    call c, $ecc5
    inc bc
    inc sp
    inc de

jr_008_52e5:
    inc sp
    ld b, c
    ld h, e
    ld b, e

jr_008_52e9:
    ld sp, $e511
    or c
    db $e4
    ld de, $dc31
    or a
    db $ec
    ld [bc], a
    rla
    push hl

jr_008_52f6:
    or a

jr_008_52f7:
    sub a
    call c, $e4c3
    ld b, e
    ld b, c
    ld de, $c5dc
    db $ec
    inc bc
    rst $20
    or b
    jp nz, Jump_000_20e5

    db $10
    and $b0
    push hl
    jr nz, @-$3b

    ld b, b
    jr nz, jr_008_52f6

    or b
    push hl
    ld b, b
    jp Jump_008_4060


    db $10
    ld h, b
    pop bc
    ld b, b
    db $10
    ld b, b
    ret nz

    ld d, b
    ret nz

    jr nz, jr_008_5331

    and $b0
    push hl
    jr nz, jr_008_52e9

    ld b, b
    jr nz, @-$18

    or b
    push hl
    ld b, b
    jp Jump_008_4060


    db $10
    ld h, b

jr_008_5331:
    ld b, b
    ret nz

    db $10
    ret nz

    jr nz, jr_008_52f7

    db $10
    ret nz

    ld h, b
    ret nz

    ld b, b
    ret nz

    rst $20
    or b
    ret nz

    or b
    ret nz

    call c, $e5b0
    or e
    db $e4
    inc bc
    push hl
    sub e
    or e
    db $e4
    inc bc
    push hl
    sub e
    ld [hl], e
    call c, Call_008_67b0
    call c, Call_008_67b7
    call c, Call_000_00c3
    db $10
    jr nz, jr_008_538c

    ld b, b
    jr nc, jr_008_537f

    stop
    and $b0
    sub b
    ld [hl], b
    ld h, b
    ld d, b
    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    sub b
    or b
    call c, $e5b0
    or e
    db $e4
    inc bc
    push hl
    sub e
    or e
    db $e4
    inc bc
    push hl
    sub e
    db $e4
    inc bc
    call c, $e5b0

jr_008_537f:
    cp a
    call c, $e43f
    ld l, a
    call c, $ecc3
    inc bc
    rst $20
    sub b
    ret nz

    sub b

jr_008_538c:
    ret nz

    call c, $e5c7
    sbc e
    call c, $e7c3
    sub b
    ret nz

    sub b
    ret nz

    call c, $e4c7
    dec de
    call c, Call_000_3fb0
    call c, Call_000_3fb7
    call c, $e7c3
    sub b
    ret nz

    sub b
    ret nz

    call c, $e4c7
    dec de
    call c, $97c0
    ld b, a
    cp a
    call c, $bfc7

Call_008_53b5:
    call c, $e5c4
    inc sp
    ld b, e
    ld de, $6335
    sub c
    add e
    pop bc
    or b
    db $e4
    jr nc, jr_008_5424

    and b
    call c, $bfc0
    ld l, a
    sbc a
    db $e3
    rla
    pop bc
    call c, $e4c3
    sub l
    cp $00
    add $52
    ld [$2000], a
    call c, $cb13
    push hl
    or b
    db $e4
    nop
    stop
    db $10
    jr nz, jr_008_53f4

    jr nz, jr_008_5416

    jr nz, jr_008_5418

    ld b, b
    jr nc, jr_008_542b

    ld d, b
    ld b, b
    ld d, b
    ld h, b
    ld d, b
    ld h, b
    push hl
    or b
    ret nz

jr_008_53f4:
    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl

jr_008_5416:
    or b
    ret nz

jr_008_5418:
    db $e4
    dec b
    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4

jr_008_5424:
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b

jr_008_542b:
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld d, l
    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

Jump_008_544f:
    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    dec b
    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    ld h, b
    ret nz

    push hl
    or b
    ret nz

    db $e4
    dec d
    call c, $e514
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    sub c
    db $e4
    ld b, c
    push hl
    or b
    ret nz

    or b
    ret nz

    db $e4
    inc hl
    push hl
    or b
    ret nz

    or b
    ret nz

    db $e4
    ld b, e
    push hl
    or b
    ret nz

    or b
    ret nz

    db $e4
    inc hl
    push hl
    or b
    ret nz

    db $e4
    ld de, $b0e5
    ret nz

    or b
    ret nz

    db $e4
    inc hl
    push hl
    or b
    ret nz

    or b
    ret nz

    db $e4
    ld b, e
    push hl
    or b
    ret nz

    or b
    ret nz

    db $e4
    inc hl
    push hl
    or b
    ret nz

    or b
    ret nz

    db $e4
    ld de, $b1e5
    sub c
    db $e4
    ld de, $b0e5
    ret nz

    or b
    call z, $c0b0
    or b
    call z, $c0b0
    or b
    call z, $c0b0
    or b
    call z, $c0b0
    or b
    call z, $c0b0
    or b
    call z, $c0b0
    or b
    call z, $c0b0
    or b
    call z, $c090
    sub b
    ret nz

    db $e4
    dec de
    push hl
    sub b
    ret nz

    sub b
    ret nz

    db $e4
    ld c, e
    ccf
    push hl
    cp a
    sub b
    ret nz

    sub b
    ret nz

    db $e4
    ld c, e
    rla
    ld b, a
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld b, l
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld [hl], l
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    dec b
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld [hl], l
    cp $00
    sub a
    ld d, h
    db $ed
    nop
    ld [hl], b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3406], a
    add sp, -$24
    or d
    rst $00
    push hl
    ld d, b
    ld b, b
    ld d, b
    ld b, b
    jr nc, jr_008_5654

    jr nc, @+$22

    jr nc, @+$22

    db $10
    jr nz, jr_008_562b

    nop
    stop
    and $b0
    push hl
    nop
    and $b0
    and b
    or b
    and b
    sub b
    and b
    push hl
    dec h

jr_008_562b:
    ld b, l
    ld d, e
    ld hl, $5543
    inc bc
    dec h
    ld b, l
    ld d, e
    ld hl, $5543
    ld bc, $2511
    ld b, l
    ld d, e
    ld hl, $5543
    inc bc
    dec h
    ld b, l
    ld d, e
    ld hl, $5543
    ld bc, $dc11
    or l
    ld hl, $1143
    inc hl
    and $b3
    ld h, e
    push hl
    ld b, c
    inc hl

jr_008_5654:
    ld de, $4121
    ld d, a
    call c, Call_000_00b2
    db $10
    jr nz, jr_008_568e

    ld b, b
    jr nc, jr_008_5681

    nop
    nop
    db $10
    jr nz, @+$32

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    add b
    ld [hl], b
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_5691

    nop
    call c, $21b5
    ld b, e
    ld de, $e623
    or e
    ld h, e
    push hl
    ld b, c
    inc hl
    ld de, $b1e6

jr_008_5681:
    push hl
    ld de, $a7dc
    daa
    rla
    and $b7
    push hl
    rla
    call c, $21b5

jr_008_568e:
    ld de, $b1e6

jr_008_5691:
    sub c
    ld [hl], c
    pop bc
    push hl
    ld hl, $e611
    or c
    sub c
    ld [hl], c
    pop bc
    push hl
    ld hl, $e611
    or c
    push hl
    ld de, $e643
    ld [hl], b
    sub b
    or b
    push hl
    db $10
    inc hl
    and $60
    ld [hl], b
    sub b
    or b
    push hl
    inc de
    and $70
    sub b
    or b
    push hl
    db $10
    inc hl
    and $60
    ld [hl], b
    sub b
    or b
    push hl
    ld hl, $e611
    or c
    sub c
    ld [hl], c
    pop bc
    push hl
    ld hl, $e611
    or c
    sub c
    or c
    ld [hl], c
    push hl
    ld hl, $6141
    ld [hl], c
    sub c
    or c
    sub c
    ld [hl], c
    sub c
    pop bc
    sub c
    or c
    sub c
    ld [hl], c
    ld h, c
    ld [hl], c
    sub c
    ld b, c
    ld [hl], c
    ld h, c
    and $b0
    push hl
    nop
    db $10
    jr nz, @+$32

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    add b
    sub b
    and b
    or b
    db $e4
    nop
    db $10
    jr nz, @+$32

    jr nz, jr_008_5709

    nop
    push hl
    or b
    and b
    sub b
    add b
    ld [hl], b
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_5725

    stop
    nop
    db $10

jr_008_5709:
    jr nz, jr_008_573b

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    add b
    sub b
    and b
    or b
    db $e4
    nop
    db $10
    jr nz, jr_008_5748

    ld b, b
    jr nc, jr_008_573b

    stop
    push hl
    or b
    and b
    sub b
    add b
    ld [hl], b
    ld h, b
    ld d, b

jr_008_5725:
    ld b, b
    jr nc, jr_008_5748

    db $10
    db $10
    jr nz, jr_008_575c

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    add b
    sub b
    and b
    or b
    db $e4
    nop
    db $10
    jr nz, jr_008_5769

    ld b, b
    ld d, b

jr_008_573b:
    ld b, b
    jr nc, jr_008_575e

    stop
    push hl
    or b
    and b
    sub b
    add b
    ld [hl], b
    ld h, b
    ld d, b

jr_008_5748:
    ld b, b
    jr nc, @+$22

    jr nz, @+$32

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    add b
    sub b
    and b
    or b
    db $e4
    nop
    db $10
    jr nz, @+$32

    ld b, b
    ld d, b

jr_008_575c:
    ld h, b
    ld d, b

jr_008_575e:
    ld b, b
    jr nc, @+$22

    stop
    push hl
    or b
    and b
    or b
    db $e4
    nop

jr_008_5769:
    db $10
    jr nz, @+$32

    ld b, b
    ld d, b
    push hl
    sub e
    db $e4
    inc hl
    push hl
    sub c
    jr nz, @+$42

    ld h, b
    ld [hl], b
    add b
    and b
    or c
    db $e4
    ld bc, $91e5
    db $e4
    ld bc, $71e5
    or c
    ld d, c
    ld [hl], c
    sub c
    db $e4
    ld bc, $c121
    push hl
    sub e
    db $e4
    inc bc
    ld hl, $50e5
    ld [hl], b
    sub b
    or b
    db $e4
    nop
    jr nz, @+$43

    ld d, c
    ld hl, $2151
    ld d, c
    ld hl, $2151
    ld d, c
    ld hl, $4151
    ld d, c
    ld b, c
    ld d, c
    ld b, c
    ld d, c
    ld b, c
    ld d, c
    ld b, c
    ld d, c
    ld b, c
    ld d, c
    ld b, c
    ld d, c
    ld b, c
    push hl
    or c
    ld bc, $91e6
    push hl
    ld b, c
    ld bc, $91e6
    push hl
    ld b, c
    ld bc, $91e6
    push hl
    ld b, c
    ld bc, $91e6

Call_008_57c7:
    push hl

Jump_008_57c8:
    ld b, c
    ld bc, $91e6
    push hl
    ld bc, $2141
    and $a1
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld hl, $0151
    and $91
    push hl
    ld b, c
    ld bc, $91e6
    push hl
    ld b, c
    ld bc, $91e6
    push hl
    ld b, c
    ld bc, $91e6
    push hl
    ld b, c
    ld bc, $91e6
    push hl
    ld bc, $2141
    and $a1
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld d, c
    ld hl, $a1e6
    push hl
    ld hl, $2f51
    rrca
    and $af
    ld a, e
    push hl
    jr nz, @+$42

    ld [hl], b
    db $e4
    nop
    daa
    ld d, a
    push hl
    and a
    db $e4
    rlca
    daa
    ld b, a
    ld d, a
    ld [hl], a

jr_008_5832:
    ld b, c
    jp $c341


    ld b, c
    pop bc
    ld b, c
    jp $c341


    ld b, c

jr_008_583d:
    pop bc
    ld b, c
    jp $c341


    ld b, c
    pop bc
    ld b, c
    jp $c341


    ld b, c
    pop bc
    push hl
    ld bc, $e623
    or c
    push hl
    inc de
    pop bc
    db $10
    jr nz, jr_008_5895

    ret nz

    jr nz, @-$3e

    and $b0
    ret nz

    push hl
    db $10
    ret z

    jr nz, jr_008_5890

    ld b, b
    ld d, b
    ld d, b
    ld b, b
    jr nc, jr_008_5886

    db $10
    call nz, $2010
    ld b, b
    ret nz

    ld d, b
    ret nz

    ld b, b
    ret nz

    jr nz, jr_008_5832

    ld hl, $5141
    ld [hl], c
    jr nc, jr_008_58b8

    ld d, b
    ld h, b
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_589f

    ret z

    ld h, c
    ld b, e
    ld sp, $6141
    add c

jr_008_5886:
    ld b, a
    ld h, a
    ld [hl], a
    db $e4
    inc bc
    push hl
    ld [hl], b
    add b
    sub b
    and b

jr_008_5890:
    cp $00
    ld c, b
    ld d, [hl]
    db $ec

jr_008_5895:
    inc bc
    ld [$250a], a
    call c, $e4c2
    sub b
    add b
    ld [hl], b

jr_008_589f:
    ld h, b
    sub b
    ld d, b
    ld h, b
    ld d, b
    sub b
    ld b, b
    ld d, b
    ld b, b
    sub b
    jr nc, @+$42

    jr nc, jr_008_583d

    jr nz, jr_008_58df

    jr nz, @-$6e

    db $10
    jr nz, jr_008_58c4

    sub b
    nop
    stop

jr_008_58b8:
    sub b
    push hl
    or b
    db $e4
    nop
    push hl
    or b
    call c, $e4e1
    cp a
    rst $08

jr_008_58c4:
    call c, $bfd1
    res 2, e
    call c, $e5c2
    or l
    db $e4
    dec d
    inc hl
    push hl
    or c
    db $e4
    inc de
    dec h
    sub c
    and c
    or l
    db $e3
    dec d
    inc hl
    db $e4
    or c
    db $e3
    inc de

jr_008_58df:
    dec h
    db $e4
    sub e
    call c, $e5c7
    or l
    ld l, l
    or e
    ld h, e
    or e
    call c, $e450
    rlca
    call c, $0730
    call c, $074e
    call c, Call_000_07c7
    push hl
    or l
    ld l, l
    or e
    ld h, e
    or e
    call c, $9790
    call c, $9750
    call c, $9740
    call c, $9730
    call c, $7fc7
    db $e4
    daa
    push hl
    ld [hl], a
    call c, $9780
    call c, $9750
    call c, $9740
    call c, $9760
    call c, $7fc7
    db $e4
    ld b, a
    ld h, a
    ld c, a
    call c, Call_008_73c5
    sub c
    ld [hl], c
    ld h, c
    ld b, c
    ld hl, $dc41
    or a
    ld h, a
    call c, Call_008_6750
    call c, Call_008_6760
    call c, Call_008_6770
    call c, $77a0
    call c, Call_008_77a7
    call c, Call_008_73b7
    call c, $91c5
    ld [hl], c
    ld [hl], c
    ld h, c
    ld b, c
    ld h, c
    call c, $87a0
    call c, $8770
    call c, $8780
    call c, $8760
    call c, $9fa0
    call c, $e3b0
    rla
    ld b, a
    call c, Call_000_23c0
    db $e4
    sub e
    db $e3
    ld bc, $c7dc
    db $e4
    or a
    call c, $b760
    call c, $b569
    call c, $b596
    pop bc
    call c, $e3c0
    inc hl
    db $e4
    sub e
    and c
    call c, $e3b0
    ld e, l
    call c, Call_008_7f60
    call c, $4f50
    call c, $4f40
    call c, $e4c7
    dec b
    push hl
    sbc l
    db $e4
    inc bc
    push hl
    sub e
    db $e4
    inc bc
    push hl
    and l
    db $e4
    ld e, l
    push hl
    and e
    db $e4
    ld d, e
    inc hl
    dec b
    push hl
    sbc l
    db $e4
    inc bc
    ld b, c
    ld hl, $4101
    ld hl, $a3e5
    db $e4
    ld e, c
    ld [hl], l
    ld d, l
    inc hl
    call c, Call_008_5fb0
    ld c, a
    cpl
    ld c, a
    call c, $e3a0
    ld e, a
    ld c, a
    ld a, a
    ld e, a
    call c, $e5d1
    and l
    and l
    and e
    sub l
    sub l
    sub e
    db $e4
    dec b
    dec b
    inc bc
    push hl
    and l
    and l
    sub e
    call c, $93c7
    or e
    ld [hl], c
    sbc c
    or c
    db $e4
    ld de, $2141
    ld de, $b1e5
    xor a
    pop bc
    and c
    db $e4
    ld bc, $4151
    ld hl, $e501
    and c
    cp a
    pop bc
    or c
    db $e4
    ld de, $6171
    ld b, c
    ld hl, $b1e5
    db $e4
    rrca
    ld b, a
    ld [hl], a
    cp $00
    ld [c], a
    ld e, b
    ld [$2000], a
    call c, $e514
    or b
    and b
    sub b
    add b
    sub b
    add b
    ld [hl], b
    ld h, b
    ld [hl], b
    ld h, b
    ld d, b
    ld b, b
    ld d, b
    ld b, b
    jr nc, @+$22

    jr nc, jr_008_5a2e

    stop
    stop
    and $b0
    and b
    or b
    and b
    sub b
    add b
    sub c
    and c
    or c
    or c
    push hl
    ld hl, $e641
    or c
    push hl
    ld d, c
    ld b, c
    ld hl, $b1e6
    or c
    push hl
    ld hl, $e641
    or c

jr_008_5a2e:
    push hl
    ld hl, $a1e6
    push hl
    ld bc, $b1e6
    or c
    push hl
    ld hl, $e641
    or c
    push hl
    ld d, c
    ld b, c
    ld hl, $b1e6
    or c
    push hl
    ld hl, $e641
    or c
    push hl
    ld hl, $a1e6
    push hl
    ld bc, $b1e6
    or c
    push hl
    ld hl, $e641
    or c
    push hl
    ld d, c
    ld b, c
    ld hl, $b1e6
    or c
    push hl
    ld hl, $e641
    or c
    push hl
    ld hl, $a1e6
    push hl
    ld bc, $b1e6
    or c
    push hl
    ld hl, $e641
    or c
    push hl
    ld d, c
    ld b, c
    ld hl, $b1e6
    or c
    push hl
    ld hl, $e641
    or c
    push hl
    ld hl, $a1e6
    push hl
    ld bc, $a0e6
    or b
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    sub c
    ld [hl], c
    ld h, c
    ld b, c
    ld hl, $e601
    or c
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld d, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    ld hl, $2111
    ld de, $91e6
    add c
    ld [hl], c
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    add c
    sub c
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $71
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    push hl
    ld hl, $71e6
    add c
    sub c
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    ld hl, $e611
    or c
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    ld hl, $6141
    ld b, c
    ld hl, $0161
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld sp, $7151
    ld d, c
    ld sp, $1171
    add c
    ld de, $1181
    add c
    ld de, $1181
    add c
    ld b, c
    ld h, c
    add c
    ld h, c
    ld b, c
    add c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    ld hl, $5191
    ld [hl], c
    sub c
    ld [hl], c
    ld d, c
    ld b, c
    inc hl
    and $93
    push hl
    ld bc, $e671
    or c
    push hl
    ld [hl], c
    and $b1
    push hl
    ld [hl], c
    and $b1
    push hl
    ld [hl], c
    and $b1
    push hl
    ld [hl], c
    and $b1
    push hl
    ld [hl], c
    and $b1
    push hl
    ld [hl], c
    and $b1
    push hl
    ld [hl], c
    inc hl
    and $93
    and c
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $b1
    push hl
    ld b, c
    and $b1
    push hl
    ld b, c
    and $b1
    push hl
    ld b, c
    and $b1
    push hl
    ld b, c
    and $b1
    push hl
    ld b, c
    and $b1
    push hl
    ld b, c
    and $b1
    push hl
    ld b, c
    and $b1
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a3
    push hl
    ld d, e
    and $a3
    push hl
    ld d, e
    and $a3
    push hl
    ld b, e
    and $a3
    push hl
    ld b, e
    and $a3
    push hl
    inc hl
    and $a3
    push hl
    inc hl
    and $a3
    push hl
    ld b, e
    and $a3
    push hl
    ld b, e
    and $a3
    push hl
    ld d, e
    and $a3
    push hl
    ld d, e
    and $a3
    push hl
    ld b, e
    and $a3
    push hl
    ld b, e
    and $a3
    push hl
    inc hl
    and $a3
    push hl
    inc hl
    and $a3
    push hl
    ld b, e
    and $a3
    push hl
    ld b, e
    and $91
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $b1
    sub c
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $91
    push hl
    ld b, c
    ld b, c
    and $b1
    sub c
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $91
    push hl
    ld b, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $a1
    push hl
    ld d, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    and $b1
    push hl
    ld h, c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $6171
    ld b, c
    ld h, c
    ld b, c
    ld hl, $fe01
    nop
    add d
    ld e, d
    db $ed
    nop
    ld l, b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3406], a
    add sp, -$24
    or e
    db $e4
    nop
    push hl
    or b
    and b
    sub b
    and b
    sub b
    add b
    ld [hl], b
    add b
    ld [hl], b
    ld h, b
    ld d, b
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_5ddf

    jr nc, jr_008_5dc1

    db $10
    jr nz, @+$12

    nop
    and $b0
    push hl
    nop
    and $b0
    and b
    sub b
    and b
    or b
    push hl
    nop
    db $10
    call c, Call_008_75b1
    ld b, l
    dec sp
    dec e
    ld b, l
    add hl, sp
    call c, Call_000_194f
    call c, Call_008_75b1
    ld b, l

jr_008_5dc1:
    dec sp
    dec e
    ld b, l
    add hl, sp
    add hl, de
    call c, $10b3
    jr nz, jr_008_5ddb

    nop
    db $10
    jr nz, jr_008_5ddf

    nop
    db $10
    jr nz, jr_008_5e03

    jr nz, jr_008_5de5

    nop
    and $b0
    push hl
    nop
    db $10

jr_008_5ddb:
    jr nz, jr_008_5e0d

    jr nz, jr_008_5def

jr_008_5ddf:
    jr nz, jr_008_5e11

    jr nz, jr_008_5df3

    jr nz, @+$32

jr_008_5de5:
    ld b, b
    ld d, b
    ld b, b
    jr nc, jr_008_5e0a

    db $10
    jr nz, jr_008_5e1d

    ld b, b
    ld d, b

jr_008_5def:
    ld h, b
    ld [hl], b
    add b
    sub b

jr_008_5df3:
    add b
    ld [hl], b
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_5e1a

    db $10
    jr nz, @+$32

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    ld h, b
    ld d, b

jr_008_5e03:
    ld b, b
    jr nc, jr_008_5e46

    ld d, b
    ld h, b
    ld [hl], b
    add b

jr_008_5e0a:
    sub b
    jr nz, jr_008_5e3d

jr_008_5e0d:
    ld b, b
    jr nc, jr_008_5e30

    db $10

jr_008_5e11:
    jr nz, jr_008_5e43

    ld b, b
    jr nc, jr_008_5e36

    db $10
    jr nz, jr_008_5e49

    ld b, b

jr_008_5e1a:
    jr nc, jr_008_5e3c

    db $10

jr_008_5e1d:
    jr nz, jr_008_5e4f

    ld b, b
    jr nc, jr_008_5e42

    db $10
    jr nz, jr_008_5e55

    ld b, b
    ld d, b
    ld h, b
    ld d, b
    ld b, b
    jr nc, @+$22

    jr nc, jr_008_5e6e

    jr nc, jr_008_5e50

jr_008_5e30:
    db $10
    jr nz, jr_008_5e63

    ld b, b
    jr nc, jr_008_5e56

jr_008_5e36:
    db $10
    jr nz, @+$32

    ld b, b
    jr nc, @+$22

jr_008_5e3c:
    db $10

jr_008_5e3d:
    jr nz, jr_008_5e6f

    ld b, b
    jr nc, jr_008_5e62

jr_008_5e42:
    db $10

jr_008_5e43:
    jr nz, jr_008_5e75

    ld b, b

jr_008_5e46:
    ld d, b
    ld h, b
    ld d, b

jr_008_5e49:
    ld b, b
    db $10
    jr nz, jr_008_5e7d

    ld b, b
    ld d, b

jr_008_5e4f:
    ld h, b

jr_008_5e50:
    ld [hl], b
    add b
    sub b
    add b
    ld [hl], b

jr_008_5e55:
    ld h, b

jr_008_5e56:
    ld d, b
    ld b, b
    jr nc, jr_008_5e7a

    db $10
    jr nz, jr_008_5e8d

    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    add b

jr_008_5e62:
    sub b

jr_008_5e63:
    add b
    ld [hl], b
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_5e8a

    db $10
    jr nz, jr_008_5e9d

    ld b, b

jr_008_5e6e:
    ld d, b

jr_008_5e6f:
    ld h, b
    ld [hl], b
    add b
    sub b
    add b
    ld [hl], b

jr_008_5e75:
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_5e9a

jr_008_5e7a:
    db $10
    jr nz, @+$32

jr_008_5e7d:
    ld b, b
    ld d, b
    ld h, b
    ld [hl], b
    ld h, b
    ld d, b
    ld b, b
    jr nc, jr_008_5ec6

    ld d, b
    ld h, b
    ld [hl], b
    add b

jr_008_5e8a:
    call c, $23b5

jr_008_5e8d:
    inc bc
    inc hl
    ld d, e
    ld b, l
    dec h
    ld d, e
    call c, $9fb7
    ld a, a
    call c, $23b5

jr_008_5e9a:
    inc bc
    inc hl
    ld d, e

jr_008_5e9d:
    ld [hl], l
    sub l
    or e
    call c, $e4b7
    rrca
    call c, $7f3f
    call c, $e5b5
    dec bc
    ld bc, $21c1
    ld bc, $1bcb
    ld de, $51c1
    call c, Call_000_35a3
    call c, $17a7
    cp $00
    add $5d
    db $ec
    inc bc
    ld [$2508], a
    call c, $e4c3

jr_008_5ec6:
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    db $e4
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    db $e4
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    db $e4
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    db $e4
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    db $e4
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    db $e4
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    db $e4
    ld [hl], b
    ld h, b
    ld d, b
    db $e3
    ld [hl], b
    call c, $e4c2
    ld [hl], l
    push hl
    ld [hl], l
    ld a, e
    ld a, l
    ld [hl], l
    ld a, c
    call c, $6990
    call c, Call_008_75c2
    ld [hl], l
    ld a, e
    ld a, l
    ld [hl], l
    ld a, c
    ld a, c
    call c, Call_008_75c5
    ld h, l
    ld b, e
    ld [hl], l
    sub l
    ld [hl], e
    db $e4
    adc e
    ld [hl], c
    pop bc
    add c
    ld [hl], c
    jp $b7dc


    db $e3
    rla
    call c, $e4c5
    dec b
    push hl
    and l
    add e
    db $e4
    dec d
    dec b
    push hl
    and e
    db $e4
    ld d, l
    ld b, l
    inc hl
    call c, $e5c7
    and e
    db $e4
    inc bc
    inc hl
    ld d, e
    call c, $8fc0
    call c, $8fb0
    call c, $7f4e
    call c, $7fc7

jr_008_5f42:
    push hl
    ld d, a
    and a
    db $e4

jr_008_5f46:
    daa
    ld d, a
    call c, Call_008_4fc0
    call c, Call_008_4fc7
    push hl
    ld d, a
    and a
    db $e4
    daa
    ld d, a
    call c, Call_008_7fc0
    call c, $e33f
    rrca
    call c, $e4c5
    ld c, e
    ld b, c
    pop bc
    ld d, c
    call c, $43c1
    call c, $c9c5
    ld e, e
    ld d, c
    pop bc
    add c
    call c, Call_008_75a3
    call c, Call_008_57c7
    cp $00
    dec bc
    ld e, a
    ld [$2000], a
    call c, $e411
    db $10
    ret nz

    stop
    jr nz, jr_008_5f42

    jr nz, jr_008_5f84

jr_008_5f84:
    jr nc, jr_008_5f46

    jr nc, jr_008_5f88

jr_008_5f88:
    ld b, b
    ret nz

    ld b, b
    nop
    ld d, b
    ret nz

    ld d, b
    nop
    ld h, b
    ret nz

    ld h, b
    nop
    ld [hl], b
    ret nz

    ld [hl], b
    nop
    push hl
    and c
    or c
    db $e4
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld de, $1381
    add c

Call_008_5fb0:
    and c
    add c
    ld [hl], c
    ld de, $1381
    add c
    and c
    add c
    ld d, c
    cp $02
    sbc e
    ld e, a
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    adc e
    ld [hl], c
    pop bc
    add c
    ld [hl], c
    jp $4151


    ld hl, $0111
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $1171
    add c
    ld de, $1181
    add c
    ld de, $1181
    add c
    ld de, $1181
    add c
    ld de, $0181
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $e571
    and c
    db $e4
    ld d, c
    push hl
    and c
    db $e4
    ld d, c
    push hl
    and c
    db $e4
    ld d, c
    push hl
    and c
    db $e4
    ld d, c
    push hl
    and c
    db $e4
    ld d, c
    push hl
    and c
    db $e4
    ld d, c
    push hl
    and c
    db $e4
    ld d, c
    push hl
    and c
    db $e4
    ld d, c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0151
    ld d, c
    ld bc, $0151
    ld d, c
    ld bc, $0151
    ld d, c
    ld bc, $0151
    ld d, c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld bc, $0171
    ld [hl], c
    ld de, $1181
    add c
    ld de, $1181
    add c
    ld de, $1181
    add c
    ld de, $1181
    add c
    cp $00
    cp [hl]
    ld e, a
    db $ed
    nop
    ld [hl], b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3406], a
    add sp, -$24
    or d
    push hl
    ld h, b
    ld d, b
    ld h, b
    ld [hl], b
    ld h, b
    ld [hl], b

jr_008_60a0:
    add b
    ld [hl], b
    call c, $80a2
    sub b
    add b
    sub b
    and b
    sub b
    and b
    or b
    call c, $a092
    or b
    db $e4
    nop
    push hl
    or b
    db $e4
    nop
    stop
    db $10
    call c, $2082
    db $10
    jr nz, jr_008_60ef

    jr nz, @+$32

    ld b, b
    jr nc, jr_008_60a0

    pop bc
    push hl
    ld b, b
    ld b, [hl]
    ld d, b
    ld d, [hl]
    ld [hl], b
    db $76
    ld d, b
    ld d, [hl]
    ld b, b
    ld b, [hl]
    ld d, b
    ld d, [hl]
    ld [hl], b
    db $76
    add b
    add d
    inc sp
    call c, $40c1
    ld b, d
    call c, Call_008_43b3
    call c, Call_008_50c1
    ld d, d
    call c, $53b3
    call c, Call_008_70c1
    ld [hl], d
    call c, Call_008_73b3
    call c, Call_008_50c1

jr_008_60ef:
    ld d, d
    call c, $53b3
    call c, $40c1
    ld b, d
    call c, Call_008_43b3
    call c, Call_008_50c1
    ld d, d
    call c, $53b3
    call c, Call_008_70c1
    ld [hl], d
    call c, Call_008_73b3
    call c, $80c1
    add d
    call c, Call_000_33b7
    call c, $e5b7
    ld b, e
    or e
    inc sp
    and e
    inc hl
    sub e
    and $b3
    push hl
    ld h, e
    ld d, e
    ld h, e
    call c, Call_008_61b1
    ld d, b
    ld h, b
    sub b
    ld h, c
    ld h, b
    call c, $e6b7
    or l
    call c, $e5a0
    dec h
    call c, $63b7
    ld b, e
    or e
    inc sp
    and e
    inc hl
    sub e
    and $b3
    push hl
    ld h, e
    ld d, e
    ld l, e
    and e
    call c, $bb5e
    call c, Call_008_42b2
    ld b, d
    ld b, c
    ld b, b
    ld h, b
    ld b, b
    or b
    ld h, b
    ld b, b
    ld h, b
    or b
    ld h, b
    ld b, b
    ld h, b
    or b
    ld h, b
    ld b, b
    ld h, b
    or b
    ld h, b
    call c, Call_008_40c2
    ld h, b
    or b
    ld h, b
    call c, Call_008_40d2
    ld h, b
    or b
    call c, $40c1
    ld b, [hl]
    ld b, b
    ld b, [hl]
    ld b, b
    ld b, [hl]
    ld b, b
    ld b, [hl]
    ld b, b
    ld b, d
    call c, $23b5
    call c, $40c1
    ld b, d
    call c, Call_008_53b5
    call c, $40c1
    ld b, d
    call c, $23b5
    call c, $40c1
    call c, $46b7
    call c, Call_008_41c1
    or b
    sub b
    ld b, c
    or b
    sub b
    ld b, c
    or b
    sub b
    ld b, c
    or b
    sub d
    ld b, b
    ld [hl+], a
    ld b, b
    ld [hl+], a
    ld b, b
    ld [hl+], a
    ld b, b
    jr nz, @+$53

    db $e4
    nop
    push hl
    or b
    ld d, c
    db $e4
    nop
    push hl
    or b
    ld d, c
    db $e4
    nop
    push hl
    or b
    ld d, c
    db $e4
    nop
    push hl
    or d
    ld d, b
    ld b, d

Call_008_61b1:
    ld d, b
    ld b, d
    ld d, b
    ld b, d
    ld d, b
    ld b, b
    ld h, c
    db $e4
    stop
    push hl
    ld h, c
    db $e4
    stop
    push hl
    ld h, c
    db $e4
    stop
    push hl
    ld h, c
    db $e4
    db $10
    ld [bc], a
    push hl
    ld h, b
    ld d, d
    ld h, b
    ld d, d
    ld h, b
    ld d, d
    ld h, b
    ld d, d
    ld h, b
    ld d, d
    ld h, b
    ld d, d
    ld h, b
    ld d, d
    call c, $e4b7
    ld bc, $b0dc
    rla
    call c, $17b7
    call c, $e5a0
    ld h, a
    ld h, a
    call c, $e5b0
    sub a
    call c, $97b7
    ld [hl], e
    cp e
    call c, $97b0
    call c, $97b7
    call c, $47b0
    call c, Call_008_47b7
    call c, $a7b0
    call c, $a7b7
    db $e4
    ld d, a
    push hl
    and a
    db $e4
    inc de
    ld c, e
    push hl
    sub e
    db $e4
    dec de
    call c, $fd40
    or $63
    db $fd
    or $63
    call c, $e5b7
    ld b, e
    or e
    inc sp
    and e
    inc hl
    sub e
    and $b3

Call_008_6221:
    push hl
    ld h, e
    ld d, e
    ld l, e
    call c, $97b0
    ld [hl], a
    call c, $43b7
    or e
    inc sp
    and e
    inc hl
    sub e
    and $b3
    push hl
    ld h, e
    ld d, e
    ld l, e
    call c, $97b0
    call c, $e4b7
    rlca
    call c, $e5b0
    or a
    call c, $b7b7
    call c, $e4b0
    ld b, a
    call c, Call_008_47b7
    cp $00

jr_008_624e:
    rrca
    ld h, c

jr_008_6250:
    db $ec
    inc bc
    ld [$2508], a
    call c, $e3c2
    nop
    db $e4
    add b
    or b
    ld h, b
    sub b
    ld b, b
    ld [hl], b
    db $e3
    nop
    db $e4
    ld d, b
    db $10
    ld b, b
    nop
    jr nc, jr_008_624e

    or b
    db $e4
    jr nz, jr_008_6250

    nop
    db $e4
    nop
    push hl
    add b
    or b
    ld h, b
    and b
    ld d, b
    sub b
    db $e3
    nop
    push hl
    add b
    jr nc, jr_008_62ed

    jr nz, jr_008_62cf

    db $10
    ld b, b
    db $e3
    nop
    call c, $e4c1
    ld b, b
    ld b, [hl]
    ld b, b
    ld b, [hl]
    ld b, b
    ld b, [hl]
    ld b, b
    ld b, [hl]
    ld b, b
    ld b, d
    call c, $e3c2
    ld b, e
    call c, $e4c1
    ld b, b
    ld b, d
    call c, $e3c2
    ld b, e
    call c, $e4c1
    ld b, b
    ld b, d
    call c, $e3c2
    ld b, e
    call c, $e4c1
    ld b, b
    ld b, d
    call c, Call_000_33c2
    db $fd
    ld [$fd63], a
    ld [$fd63], a
    ld [$fd63], a
    ld [$fd63], a
    ld [$fd63], a
    ld [$fd63], a
    ld [$dc63], a
    pop bc
    db $e4
    ld b, b
    ld b, d
    call c, $e54a
    add e
    call c, $e4d7

jr_008_62cf:
    ld b, a
    scf
    daa
    push hl
    or a
    call c, $a3d7
    cp e
    call c, Call_008_51b1
    ld h, d
    sub b
    or b
    sub b
    db $e4
    nop
    push hl
    or c
    sub b
    or b
    or b
    sub b
    and b
    call c, $e4d7
    ld b, a
    scf

jr_008_62ed:
    daa
    push hl
    or a
    call c, $a3d7
    cp e
    db $e4
    inc sp
    ld c, e
    call c, $e5a0
    or a
    db $e4
    daa
    ld d, a
    daa
    call c, Call_008_40d1
    ld b, d
    call c, $e5c4
    inc hl
    call c, $e4d1
    ld b, b
    ld b, d
    call c, $e5c4
    ld d, e
    call c, $e4d1
    ld b, b
    ld b, d
    call c, $e5c4
    inc hl
    call c, $e4d1
    ld b, b
    ld b, b
    call c, $e6c4
    or e
    push hl
    ld hl, $c2dc
    db $e4
    ld b, b
    ld b, b
    jr nz, jr_008_636b

    ld d, b
    ld b, b
    jr nz, jr_008_637f

    ld b, b
    ld b, b
    ld h, b
    ld d, b
    ld b, b
    jr nc, @+$42

    ld h, b
    ld b, b
    ld b, b
    ld d, b
    ld b, b
    jr nz, jr_008_634d

    jr nz, jr_008_636f

    ld b, b
    ld b, b
    call c, $e6c4
    or e
    push hl
    ld hl, $d7dc
    db $e4
    ld b, e
    ld d, c
    ld l, e

jr_008_634d:
    call c, $e5c2
    or c
    or e
    or c
    or e
    or c
    call c, $e4d7
    ld d, e
    ld h, c
    ld a, e
    call c, $01c2
    inc bc
    ld bc, $0103
    call c, Call_008_63d7
    ld [hl], c
    adc e
    call c, $1182
    inc de

jr_008_636b:
    call c, Call_000_11a2
    inc de

jr_008_636f:
    inc de
    call c, $11d2
    inc de
    call c, $11f2
    inc de
    call c, Call_008_40c4
    ld d, b
    call c, $6bc0

jr_008_637f:
    call c, Call_008_63c7
    call c, $e51f
    ld h, a
    call c, Call_008_6790
    call c, $e4c7
    inc de
    call c, Call_000_2bc0
    daa
    call c, Call_000_27c7
    call c, Call_008_47c0
    call c, $47c7
    call c, $e5c0
    sub a
    call c, $97c7
    call c, $e4c0
    ld d, a
    call c, Call_008_57c7
    db $e3
    rlca
    db $e4
    and a
    call c, $9fc0
    sub a
    call c, $97c7
    call c, $fdc5
    or $63
    call c, $fdb1
    or $63
    call c, $e4d7
    ld b, a
    scf
    daa
    push hl
    or a
    and e
    cp e

Call_008_63c7:
    call c, $e4c7
    daa
    call c, $074c
    call c, $47d7
    scf
    daa
    push hl
    or a
    and e
    cp e

Call_008_63d7:
    call c, $e45d
    daa
    call c, $57c0
    call c, Call_008_47c0
    call c, $47c7
    and e
    cp e
    cp $00
    call z, $e462
    ld b, b
    ld b, b
    ld [hl], b
    db $e3
    nop
    ld b, b
    nop
    db $e4
    ld [hl], b
    ld d, b
    rst $38
    db $e4
    ld hl, $e511
    or c
    db $e4
    ld de, $1121
    ld h, c
    ld hl, $dcff
    ld de, $43e4
    db $e3
    ld b, e
    db $e4
    ld d, e
    db $e3
    inc sp
    db $e4
    ld [hl], e
    db $e3
    inc hl
    db $e4
    add e
    or e
    ld b, b
    ld b, b
    push bc
    ld b, b
    ld b, b
    push bc
    ld b, b
    ld b, b
    push bc
    ld b, b
    ld b, b
    pop bc
    inc sp
    ld b, b
    ld b, b
    pop bc
    or e
    ld b, b
    ld b, b
    pop bc
    db $e3
    inc bc
    db $e4
    ld b, b
    ld b, b
    pop bc
    db $e3
    inc hl

jr_008_642f:
    db $e4
    ld b, b
    ld b, b
    db $e3
    inc bc
    db $e4

jr_008_6435:
    and c
    ld b, b
    ld b, b
    pop bc
    or e
    ld b, b
    ld b, b
    pop bc
    db $e3
    inc bc
    db $e4
    ld b, b
    ld b, b
    pop bc
    db $e3
    inc hl
    db $e4
    ld b, b
    ld b, b
    db $e3
    inc bc
    ld hl, $40e4
    ld b, b
    pop bc
    or e
    ld b, b

jr_008_6451:
    ld b, b
    pop bc
    db $e3
    inc bc
    db $e4
    ld b, b

jr_008_6457:
    ld b, b
    pop bc
    db $e3
    inc hl
    db $e4
    ld b, b
    ld b, b
    pop bc
    ld b, b
    jr nc, @+$42

    ld [hl], b
    db $e4

jr_008_6464:
    ld b, b
    push hl
    ld b, b
    pop bc
    db $e4
    ld h, e

jr_008_646a:
    jr nc, jr_008_6451

    jr nc, jr_008_642f

    db $e4
    ld d, e
    jr nz, jr_008_6457

    jr nz, jr_008_6435

    db $e4
    ld b, e
    ld h, b
    push hl
    ld h, b
    pop bc
    db $e4
    ld h, e
    ld d, e
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl

jr_008_6486:
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4

jr_008_648c:
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    ld b, b
    push hl
    ld b, b
    pop bc
    db $e4
    ld h, e
    jr nc, jr_008_6486

    jr nc, jr_008_6464

    db $e4
    ld d, e
    jr nz, jr_008_648c

    jr nz, jr_008_646a

    db $e4
    ld b, e
    ld h, b
    push hl
    ld h, b
    pop bc
    db $e4
    ld h, e
    ld d, e
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    push hl
    or c
    db $e4
    ld h, c
    ld b, b
    jr nc, @+$42

    ld h, b
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, b
    ld b, b
    pop bc
    inc hl
    ld b, b
    ld b, b
    pop bc
    ld d, e
    ld b, b
    ld b, b
    pop bc
    inc hl
    ld b, b
    ld b, b
    push hl
    or l
    db $e4
    ld b, b
    ld b, b
    pop bc
    inc hl
    ld b, b
    ld b, b
    pop bc
    ld d, e
    ld b, b
    ld b, b
    pop bc
    inc hl
    ld b, b
    ld b, b
    push hl
    or l
    db $e4
    ld b, c
    db $e3
    ld hl, $41e4
    db $e3
    ld hl, $41e4
    db $e3
    ld hl, $41e4
    db $e3
    ld hl, $41e4
    or c
    or c
    ld b, c
    or c
    or c
    db $e3
    ld de, $b1e4
    ld d, c
    db $e3
    ld sp, $51e4
    db $e3
    ld sp, $51e4
    db $e3
    ld sp, $51e4
    db $e3
    ld sp, $51e4
    db $e3
    ld bc, $e401
    ld d, c
    db $e3
    ld bc, $2101
    ld bc, $61e4
    db $e3
    ld b, c
    db $e4
    ld h, c
    db $e3
    ld b, c
    db $e4
    ld h, c
    db $e3
    ld b, c
    db $e4
    ld h, c
    db $e3
    ld b, c
    db $e4
    ld h, c
    db $e3
    ld de, $e411
    ld h, c
    db $e3
    ld de, $4111
    ld de, $61e4
    db $e3
    ld de, $e411
    ld h, c
    db $e3
    ld de, $4111
    ld de, $41fd
    ld h, [hl]
    db $fd
    ld b, c
    ld h, [hl]
    db $e4
    ld [hl], c
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $70e4
    ld h, b
    ld [hl], b
    add b
    db $fd
    ld d, d
    ld h, [hl]
    db $fd
    ld d, d
    ld h, [hl]
    db $e4
    and c
    db $e3
    ld d, c
    db $e4
    and c
    db $e3
    ld d, c
    db $e4
    and c
    db $e3
    ld d, c
    db $e4
    and c
    db $e3
    ld d, c
    db $e4
    and c
    db $e3

Call_008_6597:
    ld d, c
    ld [hl], c
    ld d, c
    ld b, c
    ld hl, $e411
    and c
    sub c
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4

Call_008_65b0:
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4
    db $e3
    ld de, $91e4
    add c
    ld [hl], c
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $71e4
    db $e3
    ld hl, $70e4
    ld h, b
    ld [hl], b
    add b
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    sub c
    ld b, c
    ld d, c
    ld h, c
    ld [hl], c
    ld h, c
    or c
    ld h, c
    or c
    ld h, c
    or c
    ld h, c
    or c
    ld h, c
    or c
    ld h, c
    or c
    ld h, c
    or c
    ld h, c
    ld sp, $b141
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    ld d, c
    ld h, c
    ld [hl], c
    ld h, c
    db $e3
    ld hl, $61e4
    db $e3
    ld hl, $61e4
    db $e3
    ld hl, $61e4
    db $e3
    ld hl, $61e4
    db $e3
    ld hl, $61e4
    db $e3
    ld hl, $61e4
    db $e3
    ld hl, $61e4
    ld d, c
    ld b, c
    or c
    db $e3
    ld b, e
    db $e4
    ld b, c
    or c
    db $e3
    inc sp
    db $e4
    ld b, c
    or c
    db $e3
    inc hl
    db $e4
    ld b, c
    sub c
    or e
    cp $00
    ld h, e
    ld h, h
    db $e4
    ld h, c
    db $e3
    ld de, $61e4
    db $e3
    ld de, $61e4
    db $e3
    ld de, $61e4
    db $e3
    ld de, $e4ff
    sub c
    db $e3
    ld b, c
    db $e4
    sub c
    db $e3
    ld b, c
    db $e4
    sub c
    db $e3
    ld b, c
    db $e4
    sub c
    db $e3
    ld b, c
    rst $38
    ld hl, sp-$13
    ld bc, $f000
    ld [hl], a

jr_008_6669:
    db $ec
    ld [bc], a
    add sp, -$2a
    or h
    db $e4
    ld d, e
    call nc, $01b2
    ld d, c
    ld bc, $b3d6
    ld sp, $4131
    sub $b4
    ld d, a
    rst $38
    ld hl, sp-$16
    inc b
    ld [hl+], a
    db $ec
    ld [bc], a
    sub $c4
    db $e4
    sub e
    call nc, $91c2
    sub c
    sub c
    sub $c4
    and c
    and c
    and c
    sub $c4
    sub a
    rst $38
    ld hl, sp-$2a
    db $10
    db $e3
    sub e
    call nc, $5010
    ret nz

    ld d, b
    ret nz

    ld d, b
    ret nz

    sub $10
    ld [hl], b
    ret nz

    jr nc, jr_008_6669

    ld [hl], b
    ret nz

    sub a
    rst $38

jr_008_66ad:
    ld hl, sp-$13

jr_008_66af:
    ld bc, $f000
    ld [hl], a
    db $ec
    ld [bc], a
    add sp, -$2b
    or h
    db $e4
    inc hl
    inc bc
    push hl
    sub a
    push de
    or d
    db $e4
    ld sp, $2131
    ld bc, $e501
    and c
    push de
    or h
    db $e4
    rlca
    rst $38
    ld hl, sp-$16
    ld [$ec27], sp
    ld [bc], a
    push de
    push bc
    db $e4
    sub e
    ld d, e
    rlca
    push de
    jp nz, $a1a1

    and c
    ld [hl], c
    ld [hl], c
    and c
    push de
    call nz, $ff97
    ld hl, sp-$2b
    db $10

jr_008_66e7:
    db $e3
    ld d, e
    inc sp
    rlca
    jr nc, jr_008_66ad

    jr nc, jr_008_66af

    ld b, b
    ret nz

    ld d, b
    ret nz

    ld d, b
    ret nz

    ld [hl], b
    ret nz

    sub a
    rst $38
    ld hl, sp-$13
    ld bc, $f000
    ld [hl], a
    db $ec
    inc bc
    add sp, -$2a
    or d
    push hl
    ld b, c
    ld h, c
    add c
    add b
    add b
    or c
    db $e4
    ld de, $3031
    jr nc, jr_008_66e7

    or l
    ld b, a
    rst $38
    ld hl, sp-$14
    ld [bc], a
    sub $c2
    db $e4
    add c
    add b
    add b
    ld b, c
    ld b, b
    ld b, b
    or c
    or b
    or b
    sub c
    sub b
    sub b
    sub $c5
    add a
    rst $38
    ld hl, sp-$2a
    db $10
    db $e4
    or c
    pop bc
    db $e3
    ld de, $31c1
    pop bc
    ld h, c
    ld [hl], c
    add e
    rst $38
    db $ed
    nop
    ldh [$f0], a
    ld [hl], a
    db $ec
    ld [bc], a
    add sp, -$13
    nop
    ldh [$d4], a
    and d
    db $e4
    ld hl, $00ed
    ldh [$d4], a
    and d
    ld hl, $2121

Call_008_6750:
    push hl
    sub c
    db $e4
    ld hl, $b3d4
    ld l, e
    db $ec
    ld bc, $00ed
    ldh [$d4], a
    ld h, e
    push hl
    sub l

Call_008_6760:
    ld h, d
    sub d
    or l
    add d
    or d
    db $e4
    ld [de], a
    push hl
    or d
    sub d
    ld [hl], d
    sub d
    or d
    sub d
    ld [hl], d
    sub l

Call_008_6770:
    ld h, d
    sub d
    or l
    add d
    or d
    db $e4
    ld [de], a
    ld [hl+], a
    ld b, d
    ld h, d
    ld [de], a
    push hl
    or d
    sub d
    db $e4
    ld [de], a
    push hl
    sub l
    ld h, d
    sub d
    or l
    add d
    or d
    db $e4
    dec b
    push hl
    sub d
    db $e4
    ld [bc], a
    ld [hl+], a
    push hl
    or d

Call_008_6790:
    db $e4
    dec h
    ld [de], a
    push hl
    or d
    sub d
    ld [hl], d
    ld h, d
    ld [hl], d
    sub d
    or d
    sub d
    ld [hl], d
    ld h, d
    ld b, d
    ld h, d
    ld [hl], d
    sub d
    or d
    cp $00
    ld e, h
    ld h, a
    db $ec
    ld [bc], a
    call nc, $e4c3
    sub c
    call nc, $91c3

Call_008_67b0:
    sub c
    sub c
    or c
    db $e3
    ld de, $c4d4

Call_008_67b7:
    dec hl
    call nc, $e485
    dec h
    push hl
    sub d
    db $e4
    ld [hl+], a
    ld b, l
    push hl
    or d
    db $e4
    ld b, d
    ld h, d
    ld [hl], d
    sub l
    ld b, d
    ld h, d
    ld [hl], l
    dec h
    push hl
    sub d
    db $e4
    ld [hl+], a
    ld b, l
    push hl
    or d
    db $e4
    ld b, d
    ld h, d
    ld [hl], d
    sub l
    ld h, d
    ld [hl], d
    sub l
    dec h
    push hl
    sub d
    db $e4
    ld [hl+], a
    ld b, l
    push hl
    or d
    db $e4
    ld b, d
    ld d, l
    ld [bc], a
    ld d, d
    ld [hl], d
    ld [hl+], a
    ld [hl], l
    call nc, Call_008_6b70
    call nc, Call_008_6b77
    call nc, Call_008_4b60
    call nc, Call_008_4b67
    cp $00
    cp b
    ld h, a
    call nc, $e310
    ld hl, $10d4
    ld hl, $e421
    or c
    sub c
    ld [hl], c
    sbc e
    call nc, Call_008_6221
    jp nz, $c262

    add d
    jp nz, $c282

    sub d
    jp nz, $c292

    or d
    jp nz, $c2b2

    ld h, d
    jp nz, $c262

    add d
    jp nz, $c282

    sub d
    jp nz, $c292

    db $e3
    ld [de], a
    jp nz, $e412

    sub d
    ld h, d
    db $e3
    ld [hl+], a
    db $e4
    ld h, d
    jp nz, $e382

    ld b, d
    db $e4
    add d
    jp nz, $e392

    ld d, d
    db $e4
    sub d
    jp nz, $e3b2

    ld [hl], d
    db $e4
    or d
    and d
    sub d
    jp nz, $c292

    sub d
    jp nz, $e392

    ld [bc], a
    ld [de], a
    jp nz, $c212

    ld [de], a
    jp nz, $e412

    sub d
    cp $00
    ld a, [bc]
    ld l, b
    db $ed
    nop
    ld [hl], b
    ldh a, [rPCM34]
    ld hl, sp-$14
    inc bc
    ld [$3406], a
    add sp, -$13
    nop
    ld [hl], b
    call c, $e5b7
    or b
    sub b
    add b
    ld h, b
    ld c, e
    call c, $4162
    ld h, c
    ld b, c
    ld h, c
    add c
    add c
    add e
    sub c
    sub c
    sub e
    add c
    add c
    add e
    ld b, c
    ld h, c
    ld b, c
    ld h, c
    add c
    add c
    add e
    sub c
    sub c
    sub e
    add a
    ld d, c
    ld [hl], c
    ld d, c
    ld [hl], c
    sub c
    sub c
    sub e
    and c
    and c
    and e
    sub c
    sub c
    sub e
    ld d, c
    ld [hl], c
    ld d, c
    ld [hl], c
    sub c
    sub c
    sub e
    and c
    and c
    and e
    sub a
    cp $00
    ld [hl], c
    ld l, b
    ld hl, sp-$14
    ld [bc], a
    call c, $e4c3
    ld b, b
    ld h, b
    add b
    sub b
    call c, $bbc7
    call c, $e582
    or c
    sub c
    add c
    sub c
    or c
    or c
    or e
    db $e4
    ld de, $1311
    push hl

jr_008_68c3:
    or c
    or c
    or e
    or c
    sub c
    add c
    sub c
    or c
    or c
    or e
    db $e4
    ld de, $1311
    push hl
    or a
    db $e4
    ld bc, $a1e5
    sub c
    and c
    db $e4
    ld bc, $0301
    ld hl, $2321
    ld bc, $0301
    ld bc, $a1e5
    sub c

jr_008_68e7:
    and c
    db $e4
    ld bc, $0301
    ld hl, $2321
    rlca
    cp $00
    or h
    ld l, b
    ld hl, sp-$24
    jr nz, @-$1b

    ld b, b
    ret nz

    ld [c], a
    db $10
    ret nz

    db $e3
    or b
    ret nz

    ld [c], a
    jr nc, jr_008_68c3

    ld b, b
    jp nz, $c240

    db $e4
    ld b, b
    ret nz

    db $e3
    ld b, b
    ret nz

    db $e4
    ld b, b
    ret nz

    db $e3
    ld b, b
    ret nz

    db $e4
    ld b, b
    jp nz, Jump_008_40e3

    jp nz, $60e4

    ret nz

    db $e3
    ld h, b
    ret nz

    db $e4
    ld h, b
    jp nz, $c060

    db $e3
    jr nc, jr_008_68e7

    db $e4
    ld h, b
    ret nz

    ld b, b
    ret nz

    ld b, b
    ret nz

    db $e3
    ld b, b
    ret nz

    db $e4
    ld b, b
    ret nz

    db $e3
    ld b, b
    ret nz

    db $e4
    ld b, b
    jp nz, Jump_008_40e3

    jp nz, $60e4

    ret nz

    db $e3
    ld h, b
    ret nz

    db $e4
    ld h, b
    jp nz, Jump_008_40e3

    jp nz, Jump_000_33e4

    db $e4
    ld d, b
    ret nz

    db $e3
    ld d, b
    ret nz

    db $e4
    ld d, b
    ret nz

    db $e3
    ld d, b
    ret nz

    db $e4
    ld d, b
    jp nz, Jump_008_50e3

    jp nz, $70e4

    ret nz

    db $e3
    ld [hl], b
    ret nz

    db $e4
    ld [hl], b
    jp nz, $c050

    db $e3
    ld d, b
    ret nz

    db $e4
    ld d, b
    ret nz

    ld d, b
    ret nz

    ld d, b
    ret nz

    db $e3
    ld d, b
    ret nz

    db $e4
    ld d, b
    ret nz

    db $e3
    ld d, b
    ret nz

    db $e4
    ld d, b
    jp nz, Jump_008_50e3

    jp nz, $70e4

    ret nz

    db $e3
    ld [hl], b
    ret nz

    db $e4
    ld [hl], b
    jp nz, Jump_008_50e3

    jp nz, Jump_000_33e4

    cp $00
    rlca
    ld l, c
    db $ed
    nop
    ld [hl], b
    ldh a, [rPCM34]
    db $ec
    inc bc
    ld [$3112], a
    add sp, -$13
    nop
    ld [hl], b
    call c, $e4a6
    dec h
    push hl
    sub b
    db $e4
    jr nz, jr_008_6a0f

    jr nz, jr_008_6a0c

    call c, $97a0
    call c, $97a7
    call c, $e5b2
    sub c
    sub c
    ld h, e
    ld [hl], c
    ld [hl], c
    ld b, e
    ld hl, $2141
    ld b, c
    inc hl
    inc hl
    sub c
    sub c
    ld h, e
    ld [hl], c
    ld [hl], c
    ld b, e
    ld hl, $2141
    ld de, $b1dc
    and $b7
    call c, $e5b2
    sub c
    sub c
    ld h, e
    ld [hl], c
    ld [hl], c
    ld b, e
    ld hl, $2141
    ld b, c
    inc hl
    inc hl
    sub c
    sub c
    ld h, e
    ld [hl], c
    ld [hl], c
    ld b, e
    ld hl, $2141
    ld de, $b1dc
    and $b7
    call c, $e597
    dec h
    and $90
    push hl
    jr nz, jr_008_6a5c

    call c, Call_008_65b0
    ld b, b
    ld h, b
    sub a
    call c, $4597
    db $10
    ld b, b
    add a
    call c, $85b0
    ld b, b
    add b
    or a
    call c, $1597
    and $90

jr_008_6a0c:
    push hl
    db $10
    ld b, a

jr_008_6a0f:
    call c, Call_008_45b0
    db $10
    ld b, b
    ld b, e
    ld [hl], e
    call c, Call_008_6790
    ld b, a
    daa
    rla
    call c, Call_000_2597
    and $90
    push hl
    jr nz, jr_008_6a8b

    call c, Call_008_65b0
    ld b, b
    ld h, b
    sub a
    call c, $4597
    db $10
    ld b, b
    add a
    call c, $85b0
    ld b, b
    add b
    or a
    call c, $1597
    and $90
    push hl
    db $10
    ld b, a
    call c, Call_008_45b0

jr_008_6a41:
    db $10
    ld b, b
    ld b, e
    ld [hl], e
    call c, Call_008_6597
    ld b, b
    ld h, b
    sub a
    call c, Call_008_77a7
    ld b, a
    cp $00
    or d
    ld l, c
    db $ec
    ld [bc], a
    ld [$2418], a
    call c, $e4c4
    sub l

jr_008_6a5c:
    ld h, b
    sub b
    db $e3
    dec h
    db $e4
    sub b
    db $e3
    jr nz, jr_008_6a41

    or b
    ld h, a
    call c, Call_008_67b7
    call c, $e4c2
    ld hl, $e511
    or e
    db $e4
    ld de, $b1e5
    sub e
    or c
    sub c
    ld [hl], c
    ld h, c
    call c, $93c4
    sub e
    call c, $e4c2
    ld hl, $e511
    or e
    db $e4
    ld de, $b1e5
    sub e
    or c

jr_008_6a8b:
    sub c
    ld [hl], c
    ld h, c
    call c, Call_000_25c1
    sub $c2
    ld [hl], b
    sub b
    or b
    db $e4
    db $10
    call c, $21c2
    ld de, $b3e5
    db $e4
    ld de, $b1e5
    sub e
    or c
    sub c
    ld [hl], c
    ld h, c
    call c, $93c4
    sub d
    sub $c2
    or b
    db $e4
    db $10
    call c, $21c2
    ld de, $b3e5
    db $e4
    ld de, $b1e5
    sub e
    or c
    sub c
    ld [hl], c
    ld h, c
    call c, $27c1
    call c, $95c7
    ld h, b
    sub b
    call c, $e4b0
    daa
    call c, Call_000_27a0
    call c, $2797
    call c, $e5c7
    or l
    add b
    or b
    call c, $e480
    ld b, a
    call c, Call_008_47a0
    call c, $47c7
    push hl
    ld [hl], l
    ld b, b
    ld [hl], b
    call c, $e46f
    rla
    call c, Call_000_17c7
    ld h, e
    ld b, e
    call c, Call_000_2db0
    push hl
    or c
    call c, $97a0
    call c, $97b7
    call c, $95c7
    ld h, b
    sub b
    call c, $e4b0
    daa
    call c, Call_000_27a0
    call c, $2797
    call c, $e5c7
    or l
    add b
    or b
    call c, $e44f
    ld b, a
    call c, $47b0
    call c, $47c7
    push hl
    ld [hl], l
    ld b, b
    ld [hl], b
    call c, $e4b0
    rla
    call c, $17b7
    push hl
    sub e
    db $e4
    inc de
    call c, Call_000_2db0
    ld b, c
    dec hl
    call c, $e5c2
    ld [hl], b
    sub b
    or b
    db $e4
    db $10
    cp $00
    ld l, d
    ld l, d
    call c, $ea10
    db $10
    ld [de], a
    db $e4

jr_008_6b3e:
    ld h, l
    jr nz, @+$62

    sub l

jr_008_6b42:
    ld h, b
    sub b
    db $e3
    dec h

jr_008_6b46:
    db $e4
    sub b
    db $e3
    jr nz, jr_008_6bb2

    db $e4
    ld h, b
    ret nz

jr_008_6b4e:
    ld h, b
    ret nz

    ld h, b
    jp nz, $c070

    ld [hl], b
    ret nz

jr_008_6b56:
    ld [hl], b
    jp nz, $c090

    sub b
    ret nz

    sub b
    ret nz

jr_008_6b5e:
    ld [hl], b
    ret nz

    ld h, d
    ret nz

jr_008_6b62:
    ld h, d
    ret nz

    ld h, b
    ret nz

jr_008_6b66:
    ld h, b
    ret nz

    ld h, b
    jp nz, $c070

    ld [hl], b
    ret nz

jr_008_6b6e:
    ld b, b
    ret nz

Call_008_6b70:
    ld b, b
    ret nz

jr_008_6b72:
    ld h, b
    ret nz

    ld h, b
    ret nz

    ld b, b

Call_008_6b77:
    ret nz

    ld b, b
    ret nz

    jr nz, @-$3a

    jr nz, jr_008_6b3e

    ld h, b
    ret nz

    jr nz, jr_008_6b42

    ld h, b
    ret nz

    jr nz, jr_008_6b46

    ld [hl], b
    ret nz

    jr nz, @-$3e

    ld [hl], b
    ret nz

    jr nz, jr_008_6b4e

    sub b
    ret nz

    jr nz, @-$3e

    sub b
    ret nz

    jr nz, jr_008_6b56

    ld [hl], d
    ret nz

    ld [hl+], a
    ret nz

    ld h, b
    ret nz

    jr nz, jr_008_6b5e

    ld h, b
    ret nz

    jr nz, jr_008_6b62

    ld [hl], b
    ret nz

    jr nz, jr_008_6b66

    ld [hl], b
    ret nz

    jr nz, @-$3e

    sub b
    ret nz

    jr nz, jr_008_6b6e

    ld [hl], b
    ret nz

    jr nz, jr_008_6b72

jr_008_6bb2:
    ld h, b
    add $21
    sub c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    ld hl, $8191
    ld h, c
    ld b, c
    ld sp, $b141
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld de, $1191
    sub c
    ld de, $1191
    sub c
    ld de, $1191
    sub c
    ld de, $1191
    sub c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    ld hl, $2111
    ld b, c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    add c
    ld h, c
    ld b, c
    ld sp, $b141
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld b, c
    or c
    ld de, $1191
    sub c
    ld de, $1191
    sub c
    ld de, $1191
    sub c
    ld de, $1191
    sub c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    ld hl, $2191
    sub c
    ld [hl], c
    sub c
    ld [hl], c
    ld b, c
    cp $00
    ld c, e
    ld l, e
    ld a, [$d060]
    cp $ff
    jr z, jr_008_6c65

    bit 7, a
    ret z

    and $7f
    jr nz, jr_008_6c4d

    call Call_008_6c71
    ld a, $1e
    jr jr_008_6c5f

jr_008_6c4d:
    cp $14
    jr nz, jr_008_6c54

    call Call_008_6c76

jr_008_6c54:
    ld a, $86
    ld [$c02a], a
    ld a, [$d060]
    and $7f
    dec a

jr_008_6c5f:
    set 7, a
    ld [$d060], a
    ret


jr_008_6c65:
    xor a
    ld [$d060], a
    ld [$c02a], a
    ld de, $6c8e
    jr jr_008_6c79

Call_008_6c71:
    ld de, $6c86
    jr jr_008_6c79

Call_008_6c76:
    ld de, $6c8a

jr_008_6c79:
    ld hl, $ff10
    ld c, $05
    xor a

jr_008_6c7f:
    ld [hl+], a
    ld a, [de]
    inc de
    dec c
    jr nz, jr_008_6c7f

    ret


    and b
    ld [c], a
    ld d, b
    add a
    or b
    ld [c], a
    xor $86
    nop
    nop
    nop
    add b
    rst $38
    rst $38
    rst $38
    rlca
    adc a
    ld l, a
    rlca
    sub e
    ld l, a
    rlca
    sub a
    ld l, a
    rlca
    sbc e
    ld l, a
    rlca
    sbc a
    ld l, a
    rlca
    or d
    ld l, a
    rlca
    or [hl]
    ld l, a
    rlca
    cp l
    ld l, a
    rlca
    pop bc
    ld l, a
    rlca
    push bc
    ld l, a
    rlca
    ret


    ld l, a
    rlca
    call Call_000_076f
    pop de
    ld l, a
    rlca
    push de
    ld l, a
    rlca
    reti


    ld l, a
    rlca
    ldh [$6f], a
    rlca
    rst $20
    ld l, a
    rlca
    db $eb
    ld l, a
    rlca
    rst $28
    ld l, a
    add h
    pop bc
    ld a, b
    dec b
    ret nc

    ld a, b
    rlca
    rst $18
    ld a, b
    add h
    pop de
    ld a, d
    dec b
    db $e4
    ld a, d
    rlca
    rst $30
    ld a, d
    add h
    ld b, [hl]
    ld a, d
    dec b
    ld d, l
    ld a, d
    rlca
    ld h, e
    ld a, d
    add h
    ldh [rPCM34], a
    dec b
    rst $38
    ld [hl], a
    rlca
    ld e, $78
    add h
    adc a
    ld a, e
    dec b
    xor [hl]
    ld a, e
    rlca
    call $847b
    ld l, a
    ld a, c
    dec b
    add d
    ld a, c
    rlca
    sub h
    ld a, c
    add h
    add hl, de
    ld a, c
    dec b
    inc sp
    ld a, c
    rlca
    inc [hl]
    ld a, c
    add h
    ld b, a
    ld a, c
    dec b
    ld d, [hl]
    ld a, c
    rlca
    ld h, l
    ld a, c
    add h
    ld e, a
    ld a, e
    dec b
    ld [hl], d
    ld a, e
    rlca
    add l
    ld a, e
    add h
    ld l, c
    db $76
    dec b
    add [hl]
    db $76
    rlca
    and a
    db $76
    add h
    inc b
    ld a, e
    dec b
    inc hl
    ld a, e
    rlca
    ld b, [hl]
    ld a, e
    add h
    sub l
    ld a, c
    dec b
    ret nz

    ld a, c
    rlca
    rst $18
    ld a, c
    add h
    ld hl, sp+$79
    dec b
    rra
    ld a, d
    rlca
    ld b, l
    ld a, d
    add h
    ld h, h
    ld a, d
    dec b
    add e
    ld a, d
    rlca
    or d
    ld a, d
    add h
    jp hl


    ld a, b
    dec b
    db $fc
    ld a, b
    rlca
    rrca
    ld a, c
    add h
    dec hl
    ld a, b
    dec b
    ld b, [hl]
    ld a, b
    rlca
    ld h, c
    ld a, b
    add h
    ld [hl], c
    ld a, b
    dec b
    sub h
    ld a, b
    rlca
    or a
    ld a, b
    add h
    ld c, l
    ld [hl], a
    dec b
    ld l, h
    ld [hl], a
    rlca
    adc a
    ld [hl], a
    add h
    ld h, l
    ld a, h
    dec b
    ld a, b
    ld a, h
    rlca
    adc e
    ld a, h
    add h
    sbc b
    ld a, h
    dec b
    or e
    ld a, h
    rlca
    adc $7c
    add h
    pop hl
    ld a, h
    dec b
    ldh a, [$7c]
    rlca
    rst $38
    ld a, h
    add h
    ld l, a
    ld a, l
    dec b
    adc d
    ld a, l
    rlca
    and l
    ld a, l
    add h
    ld [bc], a
    ld a, h
    dec b
    ld de, $077c
    jr nz, jr_008_6e19

    add h
    cp b
    ld a, l
    dec b
    bit 7, l
    rlca
    sbc $7d
    add h
    ret z

    ld a, [hl]
    dec b
    db $eb
    ld a, [hl]
    rlca
    ld c, $7f
    add h
    ldh [$7b], a
    dec b
    rst $28
    ld a, e
    rlca
    ld bc, $847c
    add hl, sp
    ld a, [hl]
    dec b
    ld d, h
    ld a, [hl]
    rlca
    ld l, a
    ld a, [hl]
    add h
    ld a, [hl+]
    ld a, h
    dec b
    ld b, c
    ld a, h
    rlca
    ld e, b
    ld a, h
    add h
    db $eb
    ld a, l
    dec b
    ld c, $7e
    rlca
    add hl, hl
    ld a, [hl]
    add h
    add d
    ld a, [hl]
    dec b
    sbc l
    ld a, [hl]
    rlca
    cp b
    ld a, [hl]
    add h
    add hl, bc
    ld a, l
    dec b
    inc l
    ld a, l
    rlca
    ld d, e
    ld a, l
    add h
    ld hl, $057f
    inc [hl]
    ld a, a
    rlca
    ld b, a
    ld a, a
    add h
    ld d, h
    ld a, a
    dec b
    ld h, a
    ld a, a
    rlca
    ld a, d
    ld a, a
    add h
    add a
    ld a, a
    dec b
    xor d
    ld a, a
    rlca
    call z, $847f
    call $057f
    ldh [$7f], a
    rlca
    di
    ld a, a
    add h
    ret nz

    db $76
    dec b
    rst $10
    db $76
    rlca
    ld [$8476], a
    rst $30
    db $76
    dec b
    ld a, [de]
    ld [hl], a
    rlca

jr_008_6e19:
    dec a
    ld [hl], a
    add h
    and l
    ld [hl], a
    dec b
    cp h
    ld [hl], a
    rlca
    db $d3
    ld [hl], a
    add h
    ld h, e
    ld h, [hl]
    dec b
    ld a, [hl]
    ld h, [hl]
    ld b, $96
    ld h, [hl]
    add h
    xor l
    ld h, [hl]
    dec b
    call z, $0666
    db $e4
    ld h, [hl]
    inc b
    ld l, a
    ld [hl], b
    inc b
    add b
    ld [hl], b
    inc b
    adc a
    ld [hl], b
    rlca
    ld l, b
    ld [hl], b
    inc b
    ld d, l
    ld [hl], b
    ld b, h
    cp a
    ld [hl], b
    dec b
    ret z

    ld [hl], b
    ld b, h
    rst $08
    ld [hl], b
    rlca
    jp c, Jump_008_4470

    sbc $70
    rlca
    push hl
    ld [hl], b
    rlca
    rst $28
    ld [hl], b
    ld b, h
    ld de, $0571
    ld [hl+], a
    ld [hl], c
    add h
    ld sp, hl
    ld h, [hl]
    dec b
    inc d
    ld h, a
    ld b, $2a
    ld h, a
    rlca
    inc a
    ld [hl], c
    inc b
    ld b, b
    ld [hl], c
    inc b
    ld c, e
    ld [hl], c
    rlca
    ld d, [hl]
    ld [hl], c
    rlca
    ld e, d
    ld [hl], c
    rlca
    ld e, [hl]
    ld [hl], c
    rlca
    ld l, b
    ld [hl], c
    rlca
    ld [hl], d
    ld [hl], c
    rlca
    ld a, c
    ld [hl], c
    rlca
    add [hl]
    ld [hl], c
    rlca
    sub b
    ld [hl], c
    rlca
    sbc l
    ld [hl], c
    rlca
    xor e
    ld [hl], c
    rlca
    cp b
    ld [hl], c
    rlca
    push bc
    ld [hl], c
    rlca
    sbc $71
    rlca
    add sp, $71
    rlca
    push af
    ld [hl], c
    rlca
    db $fc
    ld [hl], c
    rlca
    ld b, $72
    rlca
    dec c
    ld [hl], d
    rlca
    inc d
    ld [hl], d
    rlca
    ld e, $72
    ld b, h
    dec h
    ld [hl], d
    rlca
    ld [hl], $72
    rlca
    ld b, e
    ld [hl], d
    rlca
    ld d, b
    ld [hl], d
    rlca
    ld d, a
    ld [hl], d
    rlca
    ld h, a
    ld [hl], d
    rlca
    ld l, [hl]
    ld [hl], d
    ld b, h
    ld a, [hl]
    ld [hl], d
    rlca
    adc c
    ld [hl], d
    rlca
    sub b
    ld [hl], d
    rlca
    and b
    ld [hl], d
    add h
    or [hl]
    ld [hl], d
    dec b
    ret


    ld [hl], d
    rlca
    call c, $8472
    rst $20
    ld [hl], d
    dec b
    or $72
    rlca
    dec b
    ld [hl], e
    ld b, h
    db $10
    ld [hl], e
    rlca
    daa
    ld [hl], e
    add h
    dec sp
    ld [hl], e
    dec b
    ld d, [hl]
    ld [hl], e
    rlca
    ld l, l
    ld [hl], e
    ld b, h
    ld a, [hl]
    ld [hl], e
    rlca
    sbc l
    ld [hl], e
    add h
    or h
    ld [hl], e
    dec b
    rst $00
    ld [hl], e
    rlca
    jp c, $8473

    db $eb
    ld [hl], e
    dec b
    ld [bc], a
    ld [hl], h
    rlca
    add hl, de
    ld [hl], h
    add h
    inc h
    ld [hl], h
    dec b
    dec sp
    ld [hl], h
    rlca
    ld d, d
    ld [hl], h
    add h
    ld h, e
    ld [hl], h
    dec b
    ld [hl], d
    ld [hl], h
    rlca
    add c
    ld [hl], h
    add h
    adc h
    ld [hl], h
    dec b

jr_008_6f1e:
    xor e
    ld [hl], h
    rlca
    add $74
    ld b, h
    reti


    ld [hl], h
    dec b
    ldh a, [$74]
    ld b, h
    rlca
    ld [hl], l
    dec b
    ld [de], a
    ld [hl], l
    ld b, h
    add hl, de
    ld [hl], l
    dec b
    jr nc, jr_008_6faa

    add h
    ld b, a
    ld [hl], l
    dec b
    ld d, [hl]

jr_008_6f3a:
    ld [hl], l
    rlca
    ld h, l
    ld [hl], l
    ld b, h
    ld [hl], d

jr_008_6f40:
    ld [hl], l
    dec b
    add d
    ld [hl], l
    add h

jr_008_6f45:
    sub h

jr_008_6f46:
    ld [hl], l
    dec b
    db $d3

jr_008_6f49:
    ld [hl], l
    rlca
    ld [de], a
    db $76

jr_008_6f4d:
    inc b
    and h
    ld [hl], b
    add b
    ld d, [hl]

jr_008_6f52:
    ld d, b
    ld bc, $5287
    ld [bc], a
    push de
    ld d, e
    add b
    rst $38
    ld d, l
    ld bc, $5894
    ld [bc], a
    or $59
    add b
    ld a, a
    ld e, l
    ld bc, $5ebe
    ld [bc], a
    db $76
    ld e, a
    add b
    adc h
    ld h, b
    ld bc, $6250
    ld [bc], a
    ld [bc], a
    ld h, h
    add b

jr_008_6f75:
    add hl, sp
    ld h, a
    ld bc, $67a7

jr_008_6f7a:
    ld [bc], a
    ei

jr_008_6f7c:
    ld h, a
    add b
    ld e, d
    ld l, b
    ld bc, $68a7
    ld [bc], a
    db $f4
    ld l, b
    add b
    sub e
    ld l, c
    ld bc, $6a53
    ld [bc], a
    jr c, jr_008_6ffa

    jr nz, jr_008_6f52

    inc sp
    rst $38
    jr nz, jr_008_6f46

    inc sp
    rst $38
    jr nz, jr_008_6f3a

    inc sp
    rst $38
    jr nz, jr_008_6f1e

    inc sp
    rst $38
    daa
    add h
    scf
    ld h, $84
    ld [hl], $25
    add e
    dec [hl]
    inc h
    add e

jr_008_6faa:
    inc [hl]
    inc hl
    add d
    inc sp
    ld [hl+], a
    add c
    ld [hl-], a
    rst $38
    jr nz, jr_008_7005

    ld a, [hl+]
    rst $38
    ld hl, $2b41
    jr nz, @+$63

    ld a, [hl+]
    rst $38
    jr nz, jr_008_6f40

    db $10
    rst $38
    jr nz, jr_008_6f45

    inc hl
    rst $38
    jr nz, jr_008_6f49

    dec h
    rst $38
    jr nz, jr_008_6f4d

    ld h, $ff
    jr nz, @-$5d

    db $10
    rst $38
    jr nz, jr_008_6f75

    ld de, $20ff
    and d
    ld d, b
    rst $38
    jr nz, jr_008_6f7c

    jr jr_008_6ffd

    ld sp, $ff33
    ld [hl+], a
    sub c
    jr z, jr_008_7004

    ld [hl], c
    jr @+$01

    jr nz, jr_008_6f7a

    ld [hl+], a

jr_008_6fea:
    rst $38
    jr nz, jr_008_705e

    ld [hl+], a
    rst $38
    jr nz, jr_008_7052

    ld [hl+], a

jr_008_6ff2:
    rst $38
    dec b
    ld [hl], b
    dec d
    ld [hl], b
    dec h
    ld [hl], b
    dec [hl]

jr_008_6ffa:
    ld [hl], b
    ld b, l
    ld [hl], b

jr_008_6ffd:
    ld d, l
    ld [hl], b
    ld d, l
    ld [hl], b
    ld d, l
    ld [hl], b
    ld d, l

jr_008_7004:
    ld [hl], b

jr_008_7005:
    ld [bc], a
    ld b, [hl]
    adc d
    adc $ff
    cp $ed
    call c, $a9cb
    add a
    ld h, l
    ld b, h
    inc sp
    ld [hl+], a
    ld de, $4602
    adc d
    adc $ef
    rst $38
    cp $ee
    db $dd
    res 5, c
    add a
    ld h, l
    ld b, e
    ld [hl+], a
    ld de, $6913
    cp l
    xor $ee
    rst $38
    rst $38
    db $ed
    sbc $ff
    rst $38
    xor $ee
    db $db
    sub [hl]
    ld sp, $4602
    adc d
    call $feef
    sbc $ff
    xor $dc
    cp d
    sbc b
    db $76
    ld d, h
    ld [hl-], a
    db $10
    ld bc, $4523
    ld h, a
    adc d
    call $f7ee
    ld a, a

jr_008_704e:
    xor $dc
    xor b
    db $76

jr_008_7052:
    ld d, h
    ld [hl-], a
    db $10
    db $ec
    ld [bc], a
    jr nz, jr_008_6fea

    ret nz

    rlca
    jr nz, @-$7d

jr_008_705d:
    ret nc

jr_008_705e:
    rlca
    jr nz, jr_008_6ff2

    ret nz

    rlca
    inc l
    and c
    ret nc

    rlca
    rst $38
    ld hl, $33e2
    jr z, jr_008_704e

    ld [hl+], a
    rst $38
    db $ec
    ld [bc], a
    db $10
    ld a, [hl-]
    inc h
    ld a, [c]
    nop
    ld [bc], a
    db $10
    ld [hl+], a
    jr z, jr_008_705d

    nop
    ld [bc], a
    db $10

jr_008_707e:
    ld [$ecff], sp
    ld [bc], a

jr_008_7082:
    db $10
    rla
    cpl
    ldh a, [$f0]
    inc b
    cpl
    ld a, [c]
    ld d, b
    ld b, $10
    ld [$ecff], sp
    ld [bc], a
    db $10
    inc d
    inc h
    ld a, [c]
    nop
    ld b, $24
    ld a, [c]
    nop
    ld b, $10
    rla
    cpl
    di
    nop
    ld b, $10
    ld [$ecff], sp
    nop
    jr nz, @-$2c

    nop
    rlca
    jr nz, jr_008_707e

    ld b, b
    rlca
    jr nz, jr_008_7082

    add b
    rlca
    jr nz, @-$2c

    ret nz

    rlca
    ld a, [hl+]
    pop hl
    ldh [rTAC], a
    ld hl, $0000
    nop
    rst $38
    db $ec
    ld [bc], a

Call_008_70c1:
    db $10
    cpl
    cpl
    ld a, [c]
    add b
    rlca
    rst $38
    db $ec
    ld [bc], a
    cpl
    jp nz, Jump_000_0782

    rst $38
    db $ec
    ld [bc], a
    db $10
    ld d, $2f
    ld a, [c]
    nop
    inc b
    db $10
    ld [$2fff], sp
    and d
    ld [hl+], a
    rst $38

jr_008_70de:
    cpl
    pop de
    nop
    ld [bc], a
    db $10
    ld [$24ff], sp
    push af
    inc sp
    jr z, jr_008_70de

    ld [hl+], a
    cpl
    ld a, [c]
    ld hl, $22ff
    ld h, c
    inc hl
    ld [hl+], a
    and c
    inc sp
    ld [hl+], a
    pop bc
    inc sp
    ld [hl+], a
    ld d, c
    ld de, $f122
    inc sp
    ld [hl+], a
    ld b, c
    ld de, $c122
    inc sp
    ld [hl+], a
    ld sp, $2211
    add c
    inc sp
    ld [hl+], a
    ld sp, $2811
    ld b, c
    inc sp
    rst $38
    db $ec
    ld [bc], a
    db $10
    ld b, h
    cpl
    ldh a, [$f0]
    inc b
    db $10
    rla
    cpl
    ld a, [c]
    ld d, b
    ld b, $10
    ld [$ecff], sp
    ld [bc], a
    cpl
    sub d
    nop
    ld b, $2f
    sub d
    add d
    rlca
    rst $38
    ld hl, sp-$16
    db $10
    inc d
    ret c

    db $10
    db $e3
    ld b, d
    ld d, d
    db $76
    sub d
    ld [hl], d
    ld [c], a
    inc c
    rst $38
    ld [hl+], a
    and c
    ld [de], a
    rst $38
    db $ec
    ld bc, $af10
    cpl
    ld a, [c]
    add b
    rlca
    db $10
    ld [$ecff], sp
    ld bc, $9710
    cpl
    ld a, [c]
    nop
    dec b
    db $10
    ld [$22ff], sp
    and c
    ld [hl+], a
    rst $38
    jr z, @-$0d

    ld d, h
    rst $38
    cpl

jr_008_715f:
    adc a
    ld de, $ff24
    ld [de], a
    ld a, [hl+]
    pop af
    ld d, l
    rst $38

jr_008_7168:
    cpl
    adc a
    inc [hl]
    jr z, jr_008_715f

    dec [hl]
    ld a, [hl+]
    pop af
    ld d, l
    rst $38
    cpl
    sbc a
    inc hl
    jr z, jr_008_7168

    ld hl, $22ff
    pop hl
    ld c, e
    ld a, [hl+]
    pop af
    ld b, h
    ld [hl+], a
    pop hl
    ld a, [hl-]
    ld h, $f1
    inc [hl]
    rst $38
    ld [hl+], a
    db $f4
    ld b, h
    ld [hl+], a
    db $f4
    inc d

jr_008_718c:
    cpl
    pop af
    ld [hl-], a
    rst $38
    inc h
    adc a
    ld d, l
    ld [hl+], a
    db $f4
    ld b, h
    jr z, jr_008_718c

    ld [hl+], a
    cpl
    ld a, [c]
    ld hl, $28ff
    ld c, a
    inc hl
    inc h
    call nz, $2622
    ld a, [c]
    inc hl
    cp $04
    sbc l
    ld [hl], c
    rst $38
    jr z, jr_008_71fc

    inc sp
    inc h
    call nz, $2622

jr_008_71b2:
    ld a, [c]
    inc hl

jr_008_71b4:
    cpl
    ld a, [c]
    ld [hl+], a
    rst $38
    jr z, @+$01

    ld [hl-], a
    jr z, @-$0a

    ld b, e
    jr z, jr_008_71b2

    ld d, h
    jr z, jr_008_71b4

    ld h, l
    rst $38
    ld hl, $33c2
    ld [hl+], a
    ld a, [c]
    ld hl, $e221
    inc sp

jr_008_71ce:
    ld hl, $32c2
    ld hl, $1292
    ld hl, $31b2

jr_008_71d7:
    inc l
    sub c
    db $10
    jr z, jr_008_71ce

    ld b, c
    rst $38
    ld hl, $2394
    ld hl, $22b4

jr_008_71e4:
    jr z, jr_008_71d7

    ld b, h
    rst $38
    ld [hl+], a
    sub h
    inc sp

jr_008_71eb:
    inc h
    or h
    ld [hl+], a
    inc h
    pop af
    ld b, h
    jr z, jr_008_71e4

    ld d, l
    rst $38
    inc h
    rst $38
    ld d, l
    jr z, jr_008_71eb

    ld h, l
    rst $38

jr_008_71fc:
    ld [hl+], a
    add h
    ld b, e
    ld [hl+], a
    call nz, Call_000_2822
    ld a, [c]
    inc [hl]
    rst $38
    inc h
    pop af
    inc [hl]
    cpl
    ld a, [c]
    ld h, h
    rst $38
    ld [hl+], a
    pop af

jr_008_720f:
    ld [hl+], a
    cpl
    ld a, [c]
    ld [de], a

jr_008_7213:
    rst $38

jr_008_7214:
    ld [hl+], a
    jp nz, Jump_000_2f01

    db $f4
    ld bc, $f22f
    ld bc, $28ff
    pop af
    ld [hl-], a
    jr z, jr_008_7214

    inc sp

jr_008_7224:
    rst $38
    db $ec
    nop
    db $10
    ld a, [hl-]
    inc h
    ld a, [c]
    nop
    ld [bc], a
    db $10
    ld [hl+], a
    jr z, jr_008_7213

    nop
    ld [bc], a
    db $10
    ld [$20ff], sp
    pop de
    ld b, d
    inc h
    and c
    ld [hl-], a
    jr nz, jr_008_720f

    ld [hl+], a
    ld h, $a1
    ld [hl-], a
    rst $38
    inc hl
    sub d
    ld sp, $b223
    ld [hl-], a
    inc hl
    jp nz, $2833

    pop af
    ld d, h
    rst $38
    inc l
    pop af
    ld d, h
    jr z, @-$0d

    ld h, h

jr_008_7256:
    rst $38
    ld [hl+], a
    pop af
    inc sp
    ld [hl+], a
    pop bc
    ld [hl-], a
    ld [hl+], a
    and c
    ld sp, $822f
    ld [hl-], a
    jr z, jr_008_7256

    inc [hl]
    rst $38

jr_008_7267:
    ld [hl+], a
    jp nc, $2f32

    ld a, [c]
    ld b, e
    rst $38
    ld [hl+], a
    ld a, [c]
    ld b, e
    inc h
    or l
    ld [hl-], a
    add hl, hl
    add [hl]
    ld sp, $6427
    nop
    cpl
    ld a, [c]
    ld d, l
    rst $38
    db $ec
    ld bc, $9710
    cpl
    ld a, [c]
    nop
    rlca
    db $10
    ld [$2fff], sp
    ccf
    ld [hl+], a
    cpl

jr_008_728d:
    ld a, [c]
    ld hl, $2fff
    ld c, a
    ld b, c
    jr z, jr_008_7224

    ld b, c
    jr z, jr_008_7267

    ld b, c
    jr z, jr_008_728d

    ld b, d
    cpl
    ld a, [c]
    ld b, c
    rst $38
    ld a, [hl+]
    rst $38
    ld d, b
    cpl
    rst $38
    ld d, c
    jr z, @-$0c

    ld d, c
    ld h, $ff
    ld d, d
    ld h, $ff
    ld d, e
    jr z, @+$01

    ld d, h
    cpl
    ld a, [c]
    ld d, h
    rst $38
    db $ec
    ld [bc], a
    cpl
    ccf
    ret nz

    rlca
    cpl
    rst $18
    ret nz

    rlca
    cp $04
    cp h
    ld [hl], d
    cpl
    pop de
    ret nz

    rlca
    rst $38
    db $fc
    or e
    cpl
    cpl
    ret z

    rlca
    cpl
    rst $08
    rst $00
    rlca
    cp $04
    rst $08
    ld [hl], d
    cpl
    pop bc
    ret z

    rlca

jr_008_72db:
    rst $38

jr_008_72dc:
    inc hl
    sub a
    ld [de], a

jr_008_72df:
    inc hl

jr_008_72e0:
    and c
    ld de, $0afe
    call c, $ff72
    db $ec
    nop
    jr nz, jr_008_72dc

    ret nz

    rlca
    jr nz, jr_008_72e0

    nop
    rlca
    cp $0c
    rst $20
    ld [hl], d
    rst $38
    db $fc
    or e
    jr nz, jr_008_72db

    pop bc
    rlca
    jr nz, jr_008_72df

    ld bc, $fe07
    inc c
    or $72
    rst $38
    ld hl, $49d1
    ld hl, $29d1
    cp $06
    dec b
    ld [hl], e
    rst $38
    db $fc
    ret


    dec hl
    di
    jr nz, jr_008_7317

    add hl, hl

jr_008_7317:
    db $d3
    ld d, b
    ld bc, $05fe
    db $10
    ld [hl], e
    jr z, @-$1b

    jr nc, jr_008_7323

    cpl

jr_008_7323:
    jp nz, $0110

    rst $38
    ld a, [hl+]
    di
    dec [hl]
    ld l, $f6
    ld b, l
    cp $04
    daa
    ld [hl], e
    inc l
    db $f4

jr_008_7333:
    cp h
    inc l
    push af
    sbc h
    cpl
    db $f4
    xor h
    rst $38
    db $fc
    add hl, sp
    inc h
    db $f4
    nop
    ld b, $23
    call nz, $0500
    dec h
    or l
    nop
    ld b, $2d
    ld [c], a
    ret nz

    ld b, $fe
    inc bc
    dec sp
    ld [hl], e
    jr z, @-$2d

    nop
    ld b, $ff
    db $fc
    adc l
    dec h
    db $e4
    ldh [rTIMA], a
    inc h
    or h
    ldh [rDIV], a
    ld h, $a5
    add sp, $05
    ld l, $d1
    and b
    ld b, $fe
    inc bc
    ld d, [hl]
    ld [hl], e
    rst $38
    dec h
    jp Jump_000_2333


    sub d
    ld b, e
    ld a, [hl+]
    or l
    inc sp
    cpl
    jp $fe32


    ld [bc], a
    ld l, l
    ld [hl], e
    rst $38
    db $fc
    jp nc, $8123

    nop
    inc bc
    inc hl
    pop bc
    nop
    inc b
    inc hl
    pop af
    nop
    dec b
    inc hl
    or c
    nop
    inc b
    inc hl
    ld [hl], c
    nop
    inc bc
    cp $05
    ld a, [hl]
    ld [hl], e
    jr z, @-$7d

    nop
    inc b
    rst $38
    inc hl
    ld h, d
    ld [hl+], a
    inc hl
    and d
    ld [hl-], a
    inc hl
    jp nc, Jump_000_2333

    sub d
    inc hl
    inc hl
    ld d, d
    ld [de], a
    cp $05
    sbc l
    ld [hl], e
    jr z, jr_008_7333

    ld [de], a

Call_008_73b3:
    rst $38
    db $fc
    add hl, sp
    cpl

Call_008_73b7:
    db $f4
    nop
    dec b
    cpl
    call nz, Call_000_0400
    cpl
    ld [c], a
    ret nz

    dec b
    cp $03
    or h

Call_008_73c5:
    ld [hl], e
    rst $38
    db $fc
    adc l
    daa
    db $e4
    jr nc, jr_008_73d1

    cpl
    or h
    jr nc, @+$05

jr_008_73d1:
    cpl
    and d
    jr c, jr_008_73d9

    cp $04
    rst $00
    ld [hl], e

jr_008_73d9:
    rst $38
    add hl, hl
    db $f4
    ld b, h
    add hl, hl
    ld a, [c]
    ld b, e
    cpl
    db $f4
    ld b, d
    cpl
    db $f4
    ld b, c
    cp $03
    jp c, $ff73

    db $fc
    and c
    ld a, [hl+]
    pop af
    ld b, b
    ld b, $2a
    di
    add b
    ld b, $2a
    ld a, [c]
    jr nz, jr_008_73ff

    cp $04
    db $eb
    ld [hl], e
    ld a, [hl+]
    pop af

jr_008_73ff:
    ld b, b
    ld b, $ff
    db $fc
    or e
    ld a, [hl+]
    di
    ld [hl], c
    dec b
    daa
    db $e3
    ld sp, $2a05
    pop af
    ld d, c
    dec b
    cp $04
    ld [bc], a
    ld [hl], h
    ld a, [hl+]
    pop af
    ld [hl], c
    dec b
    rst $38
    ld [hl+], a
    pop de
    ld c, d
    ld [hl+], a
    jp nc, $fe2a

    dec d
    add hl, de
    ld [hl], h
    rst $38
    db $ec
    nop
    ld [hl+], a
    pop af
    nop
    ld [bc], a
    inc hl
    pop af
    nop
    rlca
    inc h
    pop af
    nop
    dec b
    dec h
    pop af
    ldh a, [rTAC]
    cp $08
    inc h
    ld [hl], h
    rst $38
    db $fc
    or e
    ld [hl+], a
    pop hl
    ld [bc], a
    inc bc
    inc hl
    pop hl
    ld a, [c]
    rlca
    inc h
    pop hl
    ld [bc], a
    ld b, $25
    pop hl
    ld [bc], a
    rlca
    cp $08
    dec sp
    ld [hl], h
    rst $38
    ld [hl+], a
    db $d3
    db $10
    inc hl

jr_008_7456:
    db $d3
    ld de, $d222

jr_008_745a:
    db $10
    dec h
    jp nc, $fe12

    add hl, bc
    ld d, d
    ld [hl], h

jr_008_7462:
    rst $38
    db $fc
    dec hl
    inc hl
    pop af
    ldh a, [rTAC]
    inc h
    ld a, [c]
    nop
    ld [bc], a
    cp $08
    ld h, e
    ld [hl], h
    rst $38
    db $fc

jr_008_7473:
    or e
    inc h
    ld [c], a
    ld [bc], a

jr_008_7477:
    ld [bc], a
    inc h
    pop hl
    ld [c], a

jr_008_747b:
    rlca
    cp $09
    ld [hl], d

jr_008_747f:
    ld [hl], h
    rst $38
    inc h
    rst $38
    ld b, e
    inc h
    ld a, [c]
    ld b, h
    cp $09
    add c
    ld [hl], h
    rst $38
    db $ec
    ld [bc], a
    db $10
    rst $30
    jr z, jr_008_7456

    cp l
    rlca
    jr z, jr_008_745a

    cp [hl]
    rlca
    jr z, @-$3a

    cp a
    rlca
    jr z, jr_008_7462

    ret nz

    rlca
    cpl
    call nz, Call_000_07c1
    cpl
    ld a, [c]
    ret nz

    rlca
    db $10
    ld [$ecff], sp
    ld [bc], a
    jr z, jr_008_7473

    ld [hl], b
    rlca
    jr z, jr_008_7477

    ld h, c
    rlca
    jr z, jr_008_747b

    ld h, d
    rlca
    jr z, jr_008_747f

    ld h, e
    rlca
    cpl
    call nz, $0764
    cpl
    ld a, [c]
    ld h, h
    rlca
    rst $38
    cpl
    ccf
    inc d
    cpl
    rst $08
    inc de
    cpl
    rst $08
    ld [de], a
    cpl
    rst $08
    ld de, $cf2f
    db $10
    cpl
    jp nz, $ff10

    db $ec
    ld [bc], a
    cpl
    rst $38
    ldh [rTAC], a
    cpl
    rst $38
    ldh [rTAC], a
    cpl
    rst $38
    ldh [rTAC], a
    cpl
    rst $38
    ldh [rTAC], a
    cpl
    ld a, [c]
    ldh [rTAC], a
    rst $38
    db $ec
    inc bc
    cpl
    rst $38
    ld [c], a
    rlca
    cpl
    rst $38
    pop hl
    rlca
    cpl
    rst $38
    ld [c], a
    rlca

jr_008_74fe:
    cpl
    rst $38
    pop hl
    rlca
    cpl
    ld a, [c]
    ld [c], a
    rlca
    rst $38

jr_008_7507:
    db $ec
    ld [bc], a
    db $10
    xor a
    jr z, jr_008_74fe

    nop
    rlca
    db $10
    ld [$ecff], sp
    inc bc
    jr z, jr_008_7507

    ld bc, $ff07
    db $ec
    ld [bc], a
    ld h, $f1
    nop
    dec b
    ld h, $f1
    add b
    dec b
    ld h, $f1
    nop
    ld b, $26
    pop af
    add b
    ld b, $28
    pop af
    nop
    rlca
    rst $38
    db $ec
    inc bc
    ld h, $e1
    db $10
    dec b
    ld h, $e1
    sub b
    dec b
    ld h, $e1
    db $10
    ld b, $26
    pop hl
    sub b
    ld b, $28
    pop hl
    db $10
    rlca
    rst $38
    db $fc
    db $ed

jr_008_7549:
    jr z, @+$01

    ld hl, sp+$03
    cpl
    rst $38
    nop
    inc b
    cpl
    di
    nop
    inc b
    rst $38
    db $fc
    or h
    jr z, jr_008_7549

    ret nz

    inc bc
    cpl
    rst $28
    ret nz

    inc bc
    cpl
    db $e3
    ret nz

    inc bc
    rst $38
    inc h
    rst $38
    ld d, c
    jr z, @+$01

    ld d, h
    cpl
    rst $38
    ld d, l
    cpl
    di
    ld d, [hl]
    rst $38
    ld hl, sp-$16
    ld a, [bc]
    inc h
    db $ec
    ld [bc], a
    jp c, $e387

    add a
    ld [c], a
    ld h, e
    ld b, e
    db $e3
    add a
    rst $38
    ld hl, sp-$16
    ld a, [bc]
    inc hl
    db $ec
    ld [bc], a
    db $db
    ld h, a
    db $e3
    add a
    jp c, $e267

    ld h, e
    ld b, e
    db $e3
    add a
    rst $38
    db $ec
    nop
    ld [hl+], a
    pop af
    add b
    rlca
    ld [hl+], a
    pop af
    nop
    rlca
    ld [hl+], a
    pop af
    sub b
    rlca
    ld [hl+], a

Call_008_75a3:
    pop af
    nop
    rlca
    ld [hl+], a
    pop af
    and b
    rlca
    ld [hl+], a
    pop af
    nop
    rlca
    ld [hl+], a
    pop af
    or b

Call_008_75b1:
    rlca
    ld [hl+], a
    pop af
    nop
    rlca
    ld [hl+], a
    pop af
    ret nz

    rlca
    ld [hl+], a
    pop af
    nop
    rlca
    ld [hl+], a
    pop af
    ret nc

    rlca

Call_008_75c2:
    ld [hl+], a
    pop af
    nop

Call_008_75c5:
    rlca
    ld [hl+], a
    pop af
    ldh [rTAC], a
    cp $0c
    jp nz, $2f75

    pop af
    nop
    rlca
    rst $38
    db $fc
    or e
    ld [hl+], a
    pop af
    add c
    rlca
    ld [hl+], a
    pop af
    ld bc, $2207
    pop af
    sub c
    rlca
    ld [hl+], a
    pop af
    ld bc, $2207
    pop af
    and c
    rlca
    ld [hl+], a
    pop af
    ld bc, $2207
    pop af
    or c
    rlca
    ld [hl+], a
    pop af
    ld bc, $2207
    pop af
    pop bc
    rlca
    ld [hl+], a
    pop af
    ld bc, $2207
    pop af
    pop de
    rlca
    ld [hl+], a
    pop af
    ld bc, $2207
    pop af
    pop hl
    rlca
    cp $0c
    jp nz, $2f75

    pop af
    ld bc, $ff07
    ld hl, $49d1
    ld hl, $29d1
    cp $1a
    ld [de], a
    db $76
    rst $38
    db $fc
    ldh a, [$2f]
    ldh [$80], a
    rlca
    cpl
    ldh a, [$84]
    rlca
    cpl
    jp Jump_000_05e0


    cpl
    call nz, $0600
    ld a, [hl+]
    ld l, h
    add b
    rlca
    jr z, @+$73

    add h
    rlca
    rst $38
    db $fc
    dec b
    cpl
    and b
    ld b, c
    rlca
    cpl
    or b
    ld b, e
    rlca
    cpl
    sub e
    or c
    dec b
    cpl
    sub h
    pop bc
    dec b
    ld a, [hl+]
    ld c, h
    ld b, c
    rlca
    jr z, jr_008_7681

    ld b, [hl]
    rlca
    rst $38
    ld [hl+], a
    ld a, [c]
    ld c, h
    ld h, $e0
    ld a, [hl-]
    cpl
    ret nc

    ld a, [hl-]
    jr z, @-$2e

    inc l
    ld h, $e6
    ld c, h
    inc l
    ld a, l
    ld c, h
    cpl
    db $d3
    ld c, h
    rst $38
    db $fc
    ldh a, [$2f]
    rst $30
    and b

jr_008_766e:
    rlca
    ld h, $e6
    and e
    rlca
    ld a, [hl+]
    db $f4
    and b
    rlca
    db $fc
    and l
    ld a, [hl+]
    or $d8
    rlca
    inc h
    db $e3

jr_008_767f:
    rst $10
    rlca

jr_008_7681:
    cpl
    ld a, [c]
    ret c

    rlca
    rst $38
    db $fc
    dec b
    ld [hl+], a
    ld [$0000], sp
    cpl
    and a
    and c
    ld b, $26
    add [hl]
    and d
    ld b, $2a
    ld [hl], h
    and c
    ld b, $fc
    ld e, a
    ld a, [hl+]
    db $76
    sub $06
    inc h
    add e
    reti


    ld b, $2f
    and d
    rst $10
    ld b, $ff
    ld [hl+], a
    ld a, [c]
    inc a
    jr z, @-$1a

    ld a, $2f
    rst $10
    inc a
    ld h, $c5
    dec sp
    ld h, $e4
    dec a

jr_008_76b6:
    jr z, jr_008_766e

    inc a
    ld h, $d4
    dec a
    jr z, jr_008_767f

    dec sp
    rst $38
    db $fc
    ldh a, [$2f]
    rst $30
    ret nz

    rlca
    ld h, $e4
    pop bc
    rlca
    ld a, [hl+]
    or $c0
    rlca
    inc h
    db $d3
    jp nz, $2807

    pop bc
    ret nz

    rlca
    rst $38
    db $fc
    ld e, a
    cpl
    sub a
    add c
    rlca
    ld h, $84
    add b
    rlca
    ld a, [hl+]
    sub [hl]
    add c
    rlca
    cpl
    add e
    add c
    rlca
    rst $38
    inc hl
    ld a, [c]
    inc a
    dec l
    and $2c
    cpl
    rst $10
    inc a
    jr z, jr_008_76b6

    inc l
    rst $38
    db $fc
    ldh a, [$2f]
    rst $30
    add b
    ld b, $2a

jr_008_76fe:
    and $84
    ld b, $2f
    rst $10
    sub b
    ld b, $28
    push de
    sub b
    ld b, $26
    call nz, $0688
    dec h
    db $d3
    ld [hl], b
    ld b, $24
    db $d3
    ld h, b
    ld b, $28
    pop bc
    ld b, b
    ld b, $ff

jr_008_771a:
    db $fc
    dec b
    cpl
    or a
    ld b, c
    ld b, $2a
    sub [hl]
    ld b, d
    ld b, $2f
    and a
    ld d, c
    ld b, $28
    and l
    ld d, c
    ld b, $26
    sub h
    ld b, a
    ld b, $25
    and e
    ld sp, $2406
    sub e
    ld [hl+], a
    ld b, $28
    ld [hl], c
    ld bc, $ff06
    cpl
    db $e4
    inc a
    ld a, [hl+]
    rst $00
    ld c, h
    ld a, [hl+]
    rst $00
    inc a
    inc l
    or a
    ld c, h
    cpl
    and d
    ld e, h
    rst $38
    db $fc
    ldh a, [rNR52]
    rst $30
    and b
    rlca
    jr z, @-$18

    and h
    rlca
    inc h
    sub $a0
    rlca
    cpl
    db $d3
    jr nz, @+$09

    jr z, @-$3b

    inc hl
    rlca
    ld [hl+], a
    jp nz, Jump_000_0728

    jr z, jr_008_771a

    jr nc, jr_008_7772

    rst $38
    db $fc
    ld a, [bc]
    inc h

jr_008_776f:
    ld [$0000], sp

jr_008_7772:
    ld h, $a7
    ld b, c
    rlca
    jr z, jr_008_76fe

    ld b, e
    rlca
    inc h
    db $76
    ld b, c
    rlca
    dec l
    add e
    jp nz, Jump_000_2706

    ld [hl], e
    pop bc
    ld b, $23
    add d
    call z, Call_000_2806
    ld [hl], c
    ret c

    ld b, $ff
    ld [hl+], a
    ld a, [c]
    ld c, h
    ld h, $e6
    ld a, [hl-]
    inc h
    rst $10
    ld a, [hl-]
    ld h, $d6
    inc l
    jr z, @-$19

    inc a
    inc l
    jp nc, $283d

    pop de
    inc l
    rst $38
    db $fc
    and l

Call_008_77a7:
    ld h, $f4
    ld b, b
    rlca

jr_008_77ab:
    cpl
    db $e3
    jr nc, jr_008_77b6

    inc h
    db $f4
    ld b, b
    rlca
    dec h
    or e
    ld c, b

jr_008_77b6:
    rlca
    jr z, @-$2d

    ld d, b
    rlca
    rst $38
    db $fc
    ld [hl], a
    ld h, $c3
    ld [de], a
    rlca
    cpl
    or e
    inc b
    rlca
    inc hl
    jp $0712


    inc h
    jp Jump_000_0721


    jr z, @-$4d

    ld [hl-], a
    rlca
    rst $38
    jr z, jr_008_77ab

    inc l
    inc l
    add $3c
    ld a, [hl+]
    or [hl]
    inc l

jr_008_77dc:
    jr z, jr_008_776f

    inc e
    rst $38
    db $fc
    ldh a, [rNR50]
    rst $30
    ld [$2606], sp
    and $00
    ld b, $26
    rst $10
    ldh a, [rTIMA]
    ld h, $c4
    ldh [rTIMA], a
    dec h
    db $d3
    ret nz

    dec b
    inc h
    db $d3
    and b
    dec b
    jr z, @-$1d

    add b
    dec b
    rst $38
    db $fc
    ld a, [bc]
    inc h
    rst $00
    inc b
    dec b
    ld h, $a6
    ld [bc], a
    dec b
    ld h, $97
    pop af
    inc b
    inc h
    or h
    pop hl
    inc b
    dec h
    and e
    jp nz, $2404

    or e
    and e
    inc b
    jr z, jr_008_77dc

    add d
    inc b
    rst $38
    inc l
    db $e4
    ld c, h
    ld a, [hl+]
    rst $00

jr_008_7823:
    ld e, h
    inc l
    or [hl]
    ld c, h
    cpl
    and d
    ld e, h
    rst $38
    db $fc
    pop af
    inc h
    rst $30
    ret nz

    rlca
    inc l
    and $c2
    rlca
    ld h, $b5
    add b
    ld b, $24
    call nz, $0670
    inc h
    or l
    ld h, b
    ld b, $28
    pop bc
    ld b, b
    ld b, $ff
    db $fc
    call z, $c723
    add c
    rlca
    inc l
    or [hl]
    add b
    rlca
    ld h, $a5
    ld b, c
    ld b, $24
    call nz, Call_000_0632
    ld h, $b5
    ld hl, $2806
    and c

jr_008_785e:
    ld [bc], a
    ld b, $ff
    inc hl
    db $e4
    inc a
    inc l
    sub $2c
    inc h

jr_008_7868:
    db $e4
    inc a
    jr z, jr_008_7823

jr_008_786c:
    ld e, h
    cpl
    jp nz, $ff5d

    db $fc
    ret


    jr z, jr_008_786c

    add b
    ld b, $22
    rst $30
    ld h, b
    ld b, $21
    rst $20
    ld b, b
    ld b, $21
    rst $20
    jr nz, jr_008_7889

    cpl
    pop de
    nop
    ld b, $24
    rst $00

jr_008_7889:
    ld b, b
    rlca
    inc h
    and a
    jr nc, jr_008_7896

    cpl
    sub c
    jr nz, @+$09

    rst $38
    db $fc
    ld a, c

jr_008_7896:
    ld a, [hl+]
    rst $20
    add d
    ld b, $22
    rst $20
    ld h, d
    ld b, $21
    rst $10
    ld b, d
    ld b, $21
    rst $10
    ld [hl+], a
    ld b, $2f
    pop bc
    ld [bc], a
    ld b, $24
    or a
    ld b, d
    rlca
    ld [hl+], a
    sub a
    ld [hl-], a
    rlca
    cpl
    add c
    ld [hl+], a
    rlca
    rst $38
    inc h
    ld [hl], h
    ld hl, $7424
    db $10
    inc h
    ld [hl], c
    jr nz, @+$01

    db $fc
    push af
    inc h
    di
    jr jr_008_78ce

    cpl
    push hl
    sbc b
    rlca
    jr z, jr_008_785e

    ld e, b

jr_008_78ce:
    rlca
    rst $38
    db $fc
    and b
    dec h
    or e
    ld [$2f07], sp
    push bc
    adc b
    rlca

jr_008_78da:
    jr z, jr_008_794d

    ld c, b
    rlca
    rst $38
    inc hl
    and c
    inc e
    ld l, $94
    inc l
    jr z, jr_008_7868

    inc e
    rst $38
    db $fc
    and l
    inc h
    pop hl
    nop
    rlca
    inc h
    ld a, [c]
    add b
    rlca
    ld [hl+], a
    sub d
    ld b, b
    rlca
    jr z, jr_008_78da

    nop
    ld b, $ff
    db $fc
    ld a, [bc]
    inc h
    or c
    pop hl
    ld b, $23
    jp nz, Jump_000_06e1

    inc hl
    ld h, d
    add c
    ld b, $28
    or c
    pop hl
    dec b
    rst $38
    ld [hl+], a
    ld h, c
    ld [hl-], a
    ld [hl+], a

jr_008_7913:
    ld h, c
    ld hl, $6128
    ld de, $fcff
    ld a, [$8326]
    ld b, a

jr_008_791e:
    ld [bc], a
    cpl

jr_008_7920:
    ld h, d
    ld h, $02

jr_008_7923:
    inc h
    ld d, d
    ld b, l
    ld [bc], a
    add hl, hl
    ld h, e
    ld b, $02
    cpl
    add d
    dec h
    ld [bc], a
    cpl
    ld b, d
    rlca
    ld [bc], a
    rst $38
    jr z, @-$2a

    adc h
    inc h
    ld [c], a
    sbc h
    cpl
    add $8c
    jr z, jr_008_7923

    xor h
    cpl
    rst $10
    sbc h
    cpl
    ld a, [c]
    xor h
    rst $38
    db $fc
    ldh a, [rNR50]
    di
    ldh [rTMA], a

jr_008_794d:
    cpl
    db $e4
    ld b, b
    ld b, $28
    pop bc
    jr nz, @+$08

    rst $38
    db $fc
    ld a, [bc]
    inc hl
    jp Jump_000_0683


    ld l, $b4
    ld [bc], a
    ld b, $28
    and c
    ld bc, $ff06
    inc h
    db $d3
    ld e, h
    cpl
    and $4c
    jr z, jr_008_791e

    ld e, h

jr_008_796e:
    rst $38
    db $fc
    ld a, [bc]
    ld h, $e2
    nop
    dec b
    ld h, $e3
    add b
    dec b
    ld h, $d3
    ld [hl], b
    dec b
    jr z, jr_008_7920

    ld h, b
    dec b
    rst $38
    db $fc
    push af
    ld h, $e2
    add d
    inc b
    ld h, $d3
    ld bc, $2605
    or d
    ld [c], a
    inc b
    jr z, jr_008_7913

    pop bc
    inc b
    rst $38
    db $fc
    call z, $f124
    nop
    rlca
    inc h
    pop hl
    add b
    rlca
    inc h
    pop de
    ld b, b
    rlca
    inc h
    pop hl
    ld b, b
    rlca
    inc h
    pop af
    add b
    rlca
    inc h
    pop de

jr_008_79ad:
    nop
    rlca
    inc h
    pop af
    ld bc, $2407
    pop de
    add d
    rlca
    inc h
    pop bc
    ld b, d
    rlca
    jr z, jr_008_796e

    ld b, c
    rlca
    rst $38
    db $fc
    ld b, h
    inc l
    ld [$0000], sp
    inc h
    pop af
    ld bc, $2407
    pop hl
    add d
    rlca
    inc h
    pop de
    ld b, c
    rlca
    inc h
    pop hl

jr_008_79d4:
    ld b, c
    rlca
    inc h
    pop af
    add d
    rlca
    jr z, jr_008_79ad

    ld bc, $ff07
    cpl
    ld [$2400], sp
    ld [$2400], sp
    pop de
    ld c, h
    inc h
    or c
    inc l
    inc h
    pop de
    inc a
    inc h
    or c
    inc a
    inc h
    pop bc
    inc l
    jr z, @-$5d

    ld c, h
    rst $38
    db $fc
    call z, $f528
    nop
    ld b, $22
    jp nc, Jump_000_0638

    ld [hl+], a
    jp nz, Jump_000_0630

    ld [hl+], a
    jp nz, $0628

    ld [hl+], a
    or d
    jr nz, jr_008_7a14

    ld [hl+], a
    or d
    db $10
    ld b, $22
    and d

jr_008_7a14:
    jr jr_008_7a1c

    ld [hl+], a
    or d
    db $10
    ld b, $28
    pop bc

jr_008_7a1c:
    jr nz, @+$08

    rst $38
    db $fc
    ld b, h
    inc l
    jp $05c0


    inc hl
    or c
    ld sp, hl
    dec b
    ld [hl+], a
    and c
    pop af
    dec b
    ld [hl+], a
    and c
    jp hl


    dec b
    ld [hl+], a
    sub c
    pop hl
    dec b
    ld [hl+], a
    sub c
    reti


    dec b
    ld [hl+], a
    add c
    pop de
    dec b
    ld [hl+], a
    sub c

jr_008_7a3f:
    reti


    dec b
    jr z, jr_008_79d4

    pop hl
    dec b
    rst $38
    db $ec
    nop
    jr z, jr_008_7a3f

    add b
    inc b
    ld [hl+], a
    pop hl
    ldh [rTIMA], a
    jr z, @-$2d

    call c, $ff05
    db $fc
    and l
    daa
    sub l
    ld b, c
    inc b
    ld [hl+], a
    add c
    ld hl, $2805
    ld h, c
    ld a, [de]
    dec b
    rst $38
    db $fc
    adc b
    dec h
    ld a, [c]
    ld d, b
    ld b, $29
    pop de
    ld h, b
    ld b, $25
    ld [c], a
    ld [de], a
    ld b, $29
    pop bc
    ld [hl+], a
    ld b, $25
    ld a, [c]
    db $10
    ld b, $26
    pop de

jr_008_7a7c:
    jr nz, jr_008_7a84

    cp $02
    ld h, h
    ld a, d
    rst $38
    db $fc

jr_008_7a84:
    ld b, b
    inc h
    ld [$0000], sp
    dec h
    ld a, [c]
    ld d, c
    ld b, $29
    pop de
    ld h, c
    ld b, $25
    ld [c], a
    inc d
    ld b, $28
    pop bc
    inc h
    ld b, $25
    ld a, [c]
    ld de, $2c06
    pop de
    ld hl, $2506
    ld [c], a
    inc d
    ld b, $28
    pop bc
    inc h
    ld b, $25
    ld a, [c]
    ld de, $2406
    pop de
    ld hl, $ff06

jr_008_7ab2:
    ld h, $d2
    inc e
    add hl, hl
    or c
    inc l
    jr z, jr_008_7a7c

    inc l
    add hl, hl
    or c
    inc a
    ld h, $c2
    inc l
    add hl, hl
    and d
    inc a
    daa
    jp nz, Jump_000_252c

    and c
    inc a
    add hl, hl
    jp nz, Jump_000_242c

    and c
    inc a
    rst $38
    db $fc

jr_008_7ad2:
    and b
    inc h
    di
    nop
    ld b, $28
    push de
    ld h, b
    rlca
    inc hl
    ld [c], a
    jr nz, jr_008_7ae6

    jr z, jr_008_7ab2

    db $10
    rlca
    rst $38
    db $fc
    ld e, d

jr_008_7ae6:
    dec h
    or e
    pop af
    ld b, $27
    push bc
    ld d, d
    rlca

jr_008_7aee:
    inc hl
    and d
    ld de, $2807
    or c
    ld bc, $ff06
    inc hl
    and d
    inc a
    inc l
    sub h
    inc l
    inc hl
    add d
    inc e
    jr z, jr_008_7b73

    inc l
    rst $38
    db $fc
    ldh a, [$28]
    rst $30
    ldh [rTMA], a
    ld h, $e6
    push hl
    ld b, $23
    db $f4
    ldh [rTMA], a
    inc hl
    or $d0
    ld b, $23
    db $e3
    ret nz

    ld b, $24
    ld a, [c]
    or b
    ld b, $2f
    and d
    ret z

    ld b, $ff
    db $fc
    dec b
    inc hl
    ld [$0000], sp
    jr z, jr_008_7ad2

    and c
    ld b, $26
    add [hl]

jr_008_7b2f:
    and e
    ld b, $23
    ld [hl], h
    and c
    ld b, $23
    db $76
    sub c
    ld b, $23
    add e
    add d
    ld b, $24
    and d
    ld [hl], c
    ld b, $2f
    ld [hl], d
    adc c
    ld b, $ff
    ld [hl+], a
    ld a, [c]
    inc a
    jr z, jr_008_7b2f

    ld a, $28
    rst $10
    inc a
    dec h
    push bc
    dec sp
    inc hl
    call nc, Call_000_222c
    or [hl]
    inc a
    inc hl
    and h
    inc l
    jr z, jr_008_7aee

    inc a
    rst $38
    db $fc
    ldh a, [$2f]
    or $65
    dec b
    ld a, [hl+]

jr_008_7b66:
    db $e4
    ld a, h
    dec b
    inc hl
    jp nz, $055c

    cpl
    or d
    inc a
    dec b
    rst $38
    db $fc

jr_008_7b73:
    ld e, d
    ld l, $d6
    inc bc
    dec b
    add hl, hl
    or h
    dec de
    dec b
    inc h
    sub d
    ld a, [$2f04]
    and d
    db $db
    inc b
    rst $38
    inc l
    and $4c
    dec hl
    rst $10
    ld e, h
    cpl
    jp nz, $ff4c

    db $fc
    ldh a, [rNR50]
    rst $30
    and b
    ld b, $28
    and $a4
    ld b, $24
    sub $a0
    ld b, $2c
    db $d3
    jr nz, @+$08

    jr z, jr_008_7b66

    inc h
    ld b, $24
    jp nz, Jump_000_0620

    jr z, @-$4d

    db $10
    ld b, $ff
    db $fc
    ld e, d
    inc h
    rst $20
    ld bc, $2806
    sub $03
    ld b, $24
    add $01
    ld b, $2c
    jp Jump_000_0581


    jr z, @-$4b

    add e
    dec b
    inc h
    or d
    add d
    dec b
    jr z, @-$5d

    ld [hl], c
    dec b
    rst $38
    daa
    sub $5c
    jr z, @-$18

    ld c, h
    inc h
    call nc, $245c
    call nc, $274c
    jp $284c


    and c
    ld e, h
    rst $38
    db $fc
    dec de
    daa
    jp nc, $0740

    cpl
    push hl
    ld h, b
    rlca
    cpl
    pop bc
    jr nc, jr_008_7bf5

    rst $38
    db $fc
    add c
    ld [hl+], a
    jp nz, Jump_000_0701

jr_008_7bf5:
    inc h
    jp nz, Jump_000_0708

    cpl
    rst $10
    ld b, c
    rlca
    cpl
    and d
    ld bc, $ff07
    db $fc
    ldh a, [$2f]
    rst $10
    add b
    rlca
    inc h
    and $a0
    rlca
    cpl
    jp nc, $0740

    rst $38
    db $fc
    ld e, d
    cpl
    rst $00
    ld d, e

jr_008_7c16:
    rlca
    dec h
    or [hl]
    ld [hl], d
    rlca
    cpl
    jp nz, Jump_000_0711

    rst $38
    dec l
    or $4c
    inc h
    and $3c
    cpl
    ld a, [c]
    ld c, h
    rst $38
    db $fc
    ldh a, [rNR52]
    rst $30
    ret nz

    ld b, $2f
    rst $20
    nop
    rlca
    inc h
    db $f4
    ldh a, [rTMA]
    inc h

jr_008_7c39:
    db $e4
    ldh [rTMA], a
    jr z, @-$2d

    ret nc

    ld b, $ff
    db $fc
    ld a, [bc]
    daa
    and $81

jr_008_7c46:
    ld b, $2e
    push de
    pop bc
    ld b, $24
    call nz, $06b1
    inc h
    call nc, Call_000_06a1
    jr z, jr_008_7c16

jr_008_7c55:
    sub c
    ld b, $ff
    ld a, [hl+]
    and [hl]
    inc a
    ld l, $94
    inc l
    dec h
    and e
    inc a

jr_008_7c61:
    jr z, @-$6d

    inc l
    rst $38
    db $fc
    and l
    inc l
    ld a, [c]
    ld b, b
    inc b
    cpl
    db $e3
    and b
    inc b
    inc h
    jp nc, $0490

    jr z, jr_008_7c46

    add b
    inc b
    rst $38
    db $fc
    xor $2b
    jp nc, Jump_000_0438

    ld l, $c6

jr_008_7c80:
    sbc b
    inc b
    inc hl

jr_008_7c83:
    or d
    adc b
    inc b
    jr z, jr_008_7c39

    ld a, b
    inc b
    rst $38
    ld a, [hl+]
    and $6c
    cpl

jr_008_7c8f:
    jp nc, Jump_000_235c

    jp nz, Jump_000_286c

    pop de
    ld e, h
    rst $38
    db $fc
    inc sp
    cpl
    or $c0

jr_008_7c9d:
    dec b
    jr z, jr_008_7c83

    cp h
    dec b
    ld h, $d2
    ret nc

    dec b
    ld h, $b2
    ldh [rTIMA], a
    ld h, $c2
    ldh a, [rTIMA]
    jr z, jr_008_7c61

    nop
    ld b, $ff
    db $fc
    sbc c
    ld l, $c6
    or c
    inc b
    daa
    jp Jump_000_04ad


    dec h

jr_008_7cbe:
    or d
    pop bc
    inc b
    jr z, jr_008_7c55

    pop de
    inc b
    ld h, $a2
    pop hl
    inc b
    jr z, @-$6d

    pop af
    inc b
    rst $38
    ld a, [hl+]
    and $5c

jr_008_7cd1:
    ld a, [hl+]
    sub $6c
    inc h
    jp nz, $264c

jr_008_7cd8:
    db $d3
    ld e, h
    jr z, jr_008_7c8f

    ld c, h
    jr z, jr_008_7c80

    ld e, h
    rst $38
    db $fc
    ldh a, [$28]
    db $e4

jr_008_7ce5:
    sub b
    rlca
    cpl
    push af
    ret nz

    rlca
    jr z, jr_008_7cbe

    ret c

jr_008_7cee:
    rlca
    rst $38
    db $fc
    and l
    ld a, [hl+]
    call nz, Call_000_0771
    cpl
    or [hl]
    and d
    rlca
    jr z, jr_008_7c9d

    or a
    rlca
    rst $38
    jr z, jr_008_7ce5

    ld c, h
    ld l, $c4
    inc a
    jr z, jr_008_7cd8

    inc l
    rst $38
    db $fc
    ldh a, [rNR52]
    ld a, [c]
    nop
    ld b, $26
    ld [c], a
    ld b, b
    ld b, $26
    jp nc, Jump_000_0680

    ld h, $e2
    ret nz

    ld b, $26
    jp nc, $0700

    ld h, $c2
    ld b, b
    rlca
    ld h, $b2
    add b
    rlca
    jr z, @-$5d

    ret nz

    rlca
    rst $38
    db $fc
    ld de, $0823
    ld bc, $2600
    jp nz, $05c1

    ld h, $b2
    ld [bc], a
    ld b, $26
    and d
    ld b, c
    ld b, $26
    or d
    add d
    ld b, $26
    and d
    jp nz, $2606

    sub d

jr_008_7d48:
    ld bc, $2607
    and d
    ld b, d
    rlca

jr_008_7d4e:
    jr z, jr_008_7cd1

    add c
    rlca
    rst $38
    ld h, $08
    ld bc, $e225
    ld e, h
    dec h
    jp nz, $254c

    jp nc, $253c

    or d
    inc l
    dec h
    jp nz, $251c

    and d

jr_008_7d67:
    dec de
    dec h
    sub d
    ld a, [de]
    jr z, jr_008_7cee

    jr @+$01

    db $fc
    ldh a, [rNR50]
    di
    add b
    rlca
    cpl
    rst $20
    nop
    rlca
    jr z, jr_008_7d4e

    db $10
    rlca
    inc h
    jp nz, $0700

    inc h
    jp nc, Jump_000_06f0

    jr z, jr_008_7d48

    ldh [rTMA], a
    rst $38
    db $fc
    ld e, d
    ld h, $c3
    ld bc, $2e07
    or a
    add c
    ld b, $27
    or e
    sub d
    ld b, $23
    and d
    add c
    ld b, $24
    or d
    ld [hl], d
    ld b, $28
    and c
    ld h, c
    ld b, $ff
    ld h, $e3
    ld e, h
    ld l, $d6
    ld c, h
    ld h, $c6
    inc a
    inc hl
    or e
    ld c, h
    inc hl
    and d
    ld e, h
    jr z, jr_008_7d67

    ld l, h
    rst $38
    db $fc
    rrca
    cpl
    rst $30
    nop
    dec b
    cpl
    rst $20
    ld [$2805], sp
    or h
    add b
    inc b
    cpl
    and d
    ld h, b
    inc b
    rst $38
    db $fc
    ld b, h
    ld l, $d7
    add c
    inc b
    ld l, $c7
    adc c
    inc b
    ld a, [hl+]
    or h
    ld bc, $2f04
    jp nz, Jump_000_03e1

    rst $38
    ld l, $f7
    ld a, h
    inc l
    or $6c
    add hl, hl
    db $e4
    ld a, h
    cpl
    ld [c], a
    ld l, h
    rst $38
    db $fc
    push af
    daa
    sub $e1
    rlca
    ld h, $c6
    ld [c], a
    rlca
    add hl, hl
    sub $e1

jr_008_7df8:
    rlca
    daa
    add $e0
    rlca

jr_008_7dfd:
    dec h
    or [hl]
    ld [c], a
    rlca
    daa
    add $e1
    rlca
    ld h, $b6
    ldh [rTAC], a
    jr z, @-$5d

    rst $18
    rlca
    rst $38
    db $fc
    ld b, h
    ld h, $c3
    ret


    rlca
    ld h, $b3
    rst $00
    rlca
    ld a, [hl+]
    call nz, Call_000_07c3
    jr z, @-$4a

    rst $00
    rlca
    ld h, $c3

jr_008_7e22:
    ret


    rlca
    cpl
    and d
    push bc
    rlca
    rst $38
    dec l
    add hl, de
    ld a, h
    dec l
    rst $30
    adc h
    inc l
    sub $7c
    jr z, jr_008_7df8

    ld l, h
    cpl
    or e
    ld e, h
    rst $38
    db $fc
    ldh a, [rNR52]
    rst $30
    ld b, b
    rlca
    inc l
    and $44
    rlca
    ld h, $d5
    ld d, b
    rlca
    inc h
    jp Jump_000_0760


    inc hl
    jp $0780


    jr z, jr_008_7e22

jr_008_7e51:
    and b
    rlca
    rst $38
    db $fc
    ld a, [bc]
    ld h, $c7
    ld bc, $2b07
    or [hl]
    ld [bc], a
    rlca
    ld h, $a5
    ld de, $2407
    sub e
    ld hl, $2307
    and e
    ld b, c
    rlca
    jr z, jr_008_7dfd

    ld h, d
    rlca
    rst $38
    inc hl
    ld [c], a
    inc a
    jr z, @-$28

    ld c, h
    dec h
    call nc, $2c3c
    rst $00
    ld c, h
    ld [hl+], a
    ld [c], a
    inc a
    jr z, jr_008_7e51

    inc l
    rst $38
    db $fc
    db $f4
    cpl
    ldh a, [rTIMA]
    rlca
    ld a, [hl+]
    ldh [rP1], a
    rlca
    ld h, $b4
    db $10
    rlca
    inc h
    db $d3
    nop
    rlca
    ld h, $b2
    jr nz, jr_008_7e9e

    jr z, @-$5d

    inc h
    ld b, $ff
    db $fc

jr_008_7e9e:
    ld [hl+], a
    cpl
    or b
    jp Jump_000_2a06


    and b
    pop bc
    ld b, $26
    add h

jr_008_7ea9:
    jp nc, Jump_000_2406

    sub e
    pop bc
    ld b, $26
    add d
    pop hl
    dec b
    jr z, @+$63

    add sp, $05
    rst $38
    ld h, $e6
    ld c, h
    cpl

jr_008_7ebc:
    sub $3c
    ld a, [hl+]
    push bc
    ld c, d
    ld hl, $5bb2
    cpl
    jp nz, $ff4c

    db $fc
    ld d, b
    ld a, [hl+]
    push af
    add b
    ld b, $23
    ld [c], a
    and b
    ld b, $23
    ld a, [c]
    ret nz

    ld b, $23
    ld [c], a
    ldh [rTMA], a
    inc hl
    jp nc, $0700

    inc hl
    jp nz, $06e0

    inc hl
    jp nc, Jump_000_06c0

    jr z, jr_008_7ea9

    and b
    ld b, $ff
    db $fc
    rrca
    add hl, hl
    push de
    ld sp, $2306

jr_008_7ef2:
    jp nc, Jump_000_0652

    inc hl
    ld [c], a
    ld [hl], c
    ld b, $23
    or d
    sub c
    ld b, $23
    jp nz, Jump_000_06b2

    inc hl
    or d

jr_008_7f03:
    sub c
    ld b, $23
    jp nz, $0671

    jr z, jr_008_7ebc

    ld d, c
    ld b, $ff
    ld h, $e3
    ld c, h
    inc h
    jp $253c


jr_008_7f15:
    call nc, Call_000_243c
    call nz, Call_000_262c
    or h
    inc a
    jr z, @-$3d

    inc l
    rst $38

jr_008_7f21:
    db $fc
    and l
    inc hl
    db $f4
    ld b, c
    ld b, $2d
    sub $21
    rlca
    jr z, jr_008_7f21

    add hl, de
    rlca
    jr z, jr_008_7ef2

    ld a, [de]
    rlca
    rst $38
    db $fc
    call z, $f424

jr_008_7f38:
    add b
    dec b
    ld l, $e6
    ldh [rTMA], a
    jr z, jr_008_7f15

    ret c

    ld b, $28
    pop de
    call c, $ff06
    dec h
    call nz, Call_000_2d46
    and l
    ld b, h
    jr z, @-$3a

    ld b, l
    jr z, jr_008_7f03

    ld b, h
    rst $38
    db $fc
    ldh a, [$2d]
    pop af
    ld de, $2d05
    pop hl
    dec d
    dec b
    dec l
    pop hl

Call_008_7f60:
    ld de, $2805
    pop de
    ld de, $ff05
    db $fc
    dec d
    inc l
    pop hl
    inc c

jr_008_7f6c:
    dec b
    inc l

jr_008_7f6e:
    pop de
    db $10
    dec b
    ld l, $c1
    inc c
    dec b
    jr z, jr_008_7f38

    ld a, [bc]

jr_008_7f78:
    dec b
    rst $38
    ld l, $f2
    ld h, l
    dec l
    ld [c], a

jr_008_7f7f:
    ld d, l
    ld l, $d2
    ld d, [hl]
    jr z, @-$2d

    ld h, [hl]
    rst $38
    db $fc
    dec de
    inc hl
    di

jr_008_7f8b:
    ld h, h
    dec b
    ld [hl+], a
    ld [c], a

jr_008_7f8f:
    ld b, h
    dec b
    dec h
    pop de
    ld [hl+], a
    dec b
    ld [hl+], a
    or d
    add h
    inc b
    jr z, jr_008_7f6c

    and d
    inc b
    inc hl
    di
    inc h
    dec b
    inc h
    db $e4
    db $e4
    inc b
    jr z, jr_008_7f78

    ld [bc], a
    dec b
    rst $38
    db $fc
    call z, $d323
    ld h, b
    dec b
    ld [hl+], a
    jp nz, Jump_000_0540

    dec h
    pop bc
    jr nz, @+$07

    ld [hl+], a
    sub d
    add b
    inc b
    jr z, jr_008_7f7f

    and b
    inc b

Call_008_7fc0:
    inc hl
    db $d3
    jr nz, @+$07

    inc hl
    call nz, Call_000_04e0
    jr z, jr_008_7f8b

    nop
    dec b
    rst $38
    db $fc
    ld de, $3d22
    add c
    inc bc
    daa
    push af
    ld bc, $2106
    jp nz, $0481

    jr z, jr_008_7f6e

    add c
    inc bc
    rst $38
    db $fc
    xor $22
    ld a, $b0
    dec b
    daa
    push de
    ld e, l
    rlca
    ld hl, $b0b2
    ld b, $28
    ld h, c
    or b
    dec b
    rst $38
    ld [hl+], a
    sub d
    ld c, c
    daa
    or l
    add hl, hl
    ld hl, $39a2
    jr z, jr_008_7f8f

    ld c, c
    rst $38
