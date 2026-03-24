; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $01c", ROMX[$4000], BANK[$1c]

    call Call_01c_46c5
    call Call_000_03bf
    ld c, $64
    call Call_000_3781
    call Call_000_0167
    ld hl, $8800
    ld bc, $0400
    call Call_01c_4118
    ld hl, $9600
    ld bc, $0100
    call Call_01c_4118
    ld hl, $97e0
    ld bc, $0010
    ld a, $ff
    call Call_000_372a
    ld hl, $c3a0
    call Call_01c_4122
    ld hl, $c4b8
    call Call_01c_4122
    ld a, $c0
    ldh [rBGP], a
    call Call_000_0181
    ld a, $ff
    call Call_000_3788
    ld c, $1f
    ld a, $c7
    call Call_000_0e35
    ld c, $80
    call Call_000_3781
    xor a
    ld [$cd3d], a
    ld [$cd3e], a
    ld c, $01

jr_01c_4058:
    push bc
    call Call_01c_413a
    pop bc
    dec c
    jr nz, jr_01c_4058

    ret


Call_01c_4061:
Jump_01c_4061:
    ld hl, $4107
    ld b, $04

jr_01c_4066:
    ld a, [hl+]
    ldh [rBGP], a
    ld c, $05
    call Call_000_3781
    dec b
    jr nz, jr_01c_4066

    ret


Jump_01c_4072:
    xor a
    ldh [$ba], a
    call Call_000_3761
    call Call_01c_412a
    ld hl, $cd3e
    ld c, [hl]
    inc [hl]
    ld b, $00
    ld hl, $40d8
    add hl, bc
    ld a, [hl]
    ld [$cf78], a
    ld [$d092], a
    ld hl, $c420
    call Call_000_2f2e
    call Call_000_2d7f
    ld hl, $980c
    call Call_01c_410b
    xor a
    ldh [$ba], a
    call Call_000_376d
    ld hl, $9800
    call Call_01c_410b
    ld a, $a7
    ldh [rWX], a
    ld hl, $9c00
    call Call_01c_410b
    call Call_01c_412a
    ld a, $fc
    ldh [rBGP], a
    ld bc, $0007

jr_01c_40bc:
    call $40e7
    dec c
    jr nz, jr_01c_40bc

    ld c, $14

jr_01c_40c4:
    call $40e7
    ldh a, [rWX]
    sub $08
    ldh [rWX], a
    dec c
    jr nz, jr_01c_40c4

    xor a
    ldh [$b0], a
    ld a, $c0
    ldh [rBGP], a
    ret


    sbc d
    dec l
    ld [de], a
    inc hl
    sub h
    daa
    dec hl
    ld e, $98
    ld d, $4c
    ld h, e
    cp e
    rlca
    ld l, $60
    ld l, $20
    call Call_01c_40f9
    ld h, $00
    ld l, $70
    call Call_01c_40f9
    ld a, b
    add $08
    ld b, a
    ret


Call_01c_40f9:
jr_01c_40f9:
    ldh a, [rLY]
    cp l
    jr nz, jr_01c_40f9

    ld a, h
    ldh [rSCX], a

jr_01c_4101:
    ldh a, [rLY]
    cp h
    jr z, jr_01c_4101

    ret


    ret nz

    ret nc

    ldh [$f0], a

Call_01c_410b:
    ld a, l
    ldh [$bc], a
    ld a, h
    ldh [$bd], a
    ld a, $01
    ldh [$ba], a
    jp Jump_000_3e07


Call_01c_4118:
jr_01c_4118:
    ld [hl], $00
    inc hl
    inc hl
    dec bc
    ld a, b
    or c
    jr nz, jr_01c_4118

    ret


Call_01c_4122:
    ld bc, $0050
    ld a, $7e
    jp Jump_000_372a


Call_01c_412a:
    ld hl, $c3f0
    ld bc, $00c8
    ld a, $7f
    jp Jump_000_372a


Call_01c_4135:
Jump_01c_4135:
    ld c, $a8
    jp Jump_000_3781


Call_01c_413a:
    ld hl, $cd3d
    ld e, [hl]
    inc [hl]
    ld d, $00
    ld hl, $41f2
    add hl, de
    add hl, de
    ld e, [hl]
    inc hl
    ld d, [hl]
    ld hl, $c421
    push hl
    push de
    call Call_01c_412a
    pop de
    pop hl

jr_01c_4153:
    ld a, [de]
    inc de
    cp $ff
    jr z, jr_01c_4194

    cp $fe
    jr z, jr_01c_4197

    cp $fd
    jr z, jr_01c_419d

    cp $fc
    jr z, jr_01c_41a0

    cp $fb
    jr z, jr_01c_41a3

    cp $fa
    jr z, jr_01c_41af

    push de
    push hl
    push hl
    push af
    ld hl, $4280
    add a
    ld c, a
    ld b, $00
    add hl, bc
    ld e, [hl]
    inc hl
    ld d, [hl]
    pop af
    ld hl, $445a
    ld c, a
    ld b, $00
    add hl, bc
    ld c, [hl]
    ld b, $ff
    pop hl
    add hl, bc
    call Call_000_0405
    pop hl
    ld bc, $0028
    add hl, bc
    pop de
    jr jr_01c_4153

jr_01c_4194:
    call Call_01c_4061

jr_01c_4197:
    call Call_01c_4135
    jp Jump_01c_4072


jr_01c_419d:
    call Call_01c_4061

jr_01c_41a0:
    jp Jump_01c_4135


jr_01c_41a3:
    push de
    ld b, $01
    ld hl, $4986
    call Call_000_3620
    pop de
    jr jr_01c_4153

jr_01c_41af:
    ld c, $10
    call Call_000_3781
    call Call_01c_412a
    ld de, $4485
    ld hl, $9600
    ld bc, $1c0a
    call Call_000_02dd
    ld hl, $c444
    ld de, $41d8
    call Call_000_0405
    ld hl, $c458
    ld de, $41e5
    call Call_000_0405
    jp Jump_01c_4061


    ld h, b
    ld a, a
    ld h, d
    ld a, a
    ld h, h
    ld a, a
    ld a, a
    ld h, h
    ld a, a
    ld h, [hl]
    ld a, a
    ld l, b
    ld d, b
    ld h, c
    ld a, a
    ld h, e
    ld a, a
    ld h, l
    ld a, a
    ld a, a
    ld h, l
    ld a, a
    ld h, a
    ld a, a
    ld l, c
    ld d, b
    ld a, a
    ld b, d
    add hl, hl
    ld b, d
    inc l
    ld b, d
    cpl
    ld b, d
    inc [hl]
    ld b, d
    jr c, @+$44

    dec sp
    ld b, d
    ld a, $42
    ld b, c
    ld b, d
    ld b, l
    ld b, d
    ld c, c
    ld b, d
    ld c, h
    ld b, d
    ld d, c
    ld b, d
    ld d, h
    ld b, d
    ld e, b
    ld b, d
    ld e, l
    ld b, d
    ld h, c
    ld b, d
    ld h, l
    ld b, d
    ld l, c
    ld b, d
    ld l, l
    ld b, d
    ld [hl], c
    ld b, d
    ld [hl], h
    ld b, d
    ld [hl], a
    ld b, d
    ld a, d
    ld b, d
    ld a, l
    ld b, d
    ld a, a
    ld b, d
    inc e
    nop
    rst $38
    dec e
    ld bc, $1eff
    ld [bc], a
    db $fd
    ld e, $03
    inc b
    dec b
    cp $1f
    rlca
    ld [$20ff], sp
    dec b
    db $fd
    ld hl, $fe05
    ld [hl+], a
    ld bc, $23ff
    rlca
    ld [$23fd], sp
    inc d
    inc bc
    cp $24
    ld bc, $24fd
    ld [de], a
    inc de
    dec c
    cp $25
    ld b, $ff
    ld h, $01
    ld b, $fd
    ld h, $15
    inc de
    ld [de], a
    cp $27
    jr jr_01c_4279

    db $fd
    daa
    ld a, [de]
    dec de
    cp $28
    ld c, $0f
    db $fd
    jr z, jr_01c_427b

    ld de, $28fc
    ld d, $17
    cp $29
    add hl, bc
    db $fd
    add hl, hl
    ld a, [bc]
    db $fc
    add hl, hl
    dec bc

jr_01c_4279:
    cp $2a

jr_01c_427b:
    inc c
    rst $38
    ei
    rst $38
    ld a, [$42d6]
    db $db
    ld b, d
    db $e3
    ld b, d
    db $ec
    ld b, d
    push af
    ld b, d
    cp $42
    ld [$1043], sp
    ld b, e
    jr jr_01c_42d5

    jr nz, jr_01c_42d7

    add hl, hl
    ld b, e
    ld [hl-], a
    ld b, e
    inc a
    ld b, e
    ld b, l
    ld b, e
    ld c, a
    ld b, e
    ld d, a
    ld b, e
    ld h, b
    ld b, e
    ld l, c
    ld b, e
    ld [hl], e
    ld b, e
    ld a, [hl]
    ld b, e
    adc b
    ld b, e
    sub d
    ld b, e
    sbc e
    ld b, e
    and l
    ld b, e
    xor [hl]
    ld b, e
    or a
    ld b, e
    cp a
    ld b, e
    ret z

    ld b, e
    ret nc

    ld b, e
    jp c, $e143

    ld b, e
    rst $20
    ld b, e
    ld a, [c]
    ld b, e
    rst $30
    ld b, e
    ld [bc], a
    ld b, h
    ld a, [bc]
    ld b, h
    dec d
    ld b, h
    ld a, [de]
    ld b, h
    dec h
    ld b, h
    ld l, $44
    scf
    ld b, h
    ld b, d
    ld b, h
    ld c, d

jr_01c_42d5:
    ld b, h
    adc h

jr_01c_42d7:
    adc a
    xor h
    sbc e
    ld d, b
    ret nz

    inc l
    ret c

    ld a, a
    cp e
    call nz, $50bc
    or l
    or l
    ret nz

    ld a, a
    ret nz

    cp c
    ret


    ret c

    ld d, b
    db $d3
    ret c

    db $d3
    call nz, $bc7f
    add hl, hl
    or a
    ld d, b
    call c, $c5c0
    dec a
    ld a, a
    jp $d4c2


    ld d, b
    rst $08
    cp l
    jr nc, jr_01c_4381

    inc l
    pop hl
    sbc $b2
    pop bc
    ld d, b
    add $bc
    ret


    ld a, a
    cp d
    or e
    inc l
    ld d, b
    cp l
    daa
    db $d3
    ret c

    ld a, a
    cp c
    sbc $50
    add $bc
    jr nc, jr_01c_439b

    or c
    jp nz, $50ba

    ret nc

    call nc, $c4d3
    ld a, a
    cp h
    add hl, hl
    reti


    ld d, b
    or [hl]
    call c, $c128
    ld a, a
    ret nz

    or [hl]
    cp h
    ld d, b
    or d
    cp h
    jp z, $7fd7

    jp nz, $b6c8

    dec l
    ld d, b
    call nc, $b3cf
    pop bc
    ld a, a
    set 3, e
    cp h
    ld d, b
    inc l
    sbc $c5
    or d
    ld a, a
    set 3, e
    push de
    or a
    ld d, b
    res 7, h
    jr nc, jr_01c_43d2

    ret nz

    jp nz, $50d4

    cp e
    or [hl]
    or d
    ld a, a
    call nc, $cbbd
    db $db
    ld d, b
    call nc, $28cf
    pop bc
    ld a, a
    call c, $d9c0
    ld d, b
    call nc, $d3cf
    call nz, $b67f
    dec l
    push de
    or a
    ld d, b
    ret nz

    add $28
    pop bc
    ld a, a
    ret c

    ld [c], a
    or e
    cp l
    cp c
    ld d, b
    ret


    ret


    pop de

jr_01c_4381:
    rst $10
    ld a, a
    call z, $cbd0
    db $db
    ld d, b
    call z, $dc2c
    rst $10
    ld a, a
    db $d3
    call nz, $d0cc
    ld d, b
    rst $08
    jp nz, $cfbc

    ld a, a
    cp c
    sbc $2c
    ld d, b

jr_01c_439b:
    call nz, $bbd0
    call c, $b17f
    or a
    set 0, h
    ld d, b
    or [hl]
    call c, $c4d3
    ld a, a
    set 3, e
    cp h
    ld d, b
    or [hl]
    cp c
    or d
    ld a, a
    or c
    or a
    sub $bc
    ld d, b
    jp nz, $d4c1

    ld a, a
    or [hl]
    ld [hl-], a
    or a
    ld d, b
    push bc
    or [hl]
    pop de
    rst $10
    ld a, a
    ret nz

    cp c
    or l
    ld d, b
    push de
    jr nc, jr_01c_444a

    rst $08
    cp e
    ret nc

    jp nz, $4350

    adc b

jr_01c_43d2:
    xor h
    sub e
    and c
    xor e
    adc h
    adc a
    db $e3
    ld d, b
    ld [de], a
    or b
    and a
    add a
    adc a
    db $e3
    ld d, b
    ld b, d
    xor b
    rlca
    and l
    sbc a
    ld d, b
    add [hl]
    xor l
    and l
    add a
    adc a
    db $e3
    ld [de], a
    ld a, [bc]
    add c
    xor e
    ld d, b
    or l
    sbc $26
    cp b
    ld d, b
    adc d
    add d
    xor e
    inc de
    ld a, a
    add e
    sbc e
    db $eb
    add a
    sub e
    ld d, b
    ld [$9fe3], sp
    ld [de], a
    ld a, [bc]
    add c
    xor e
    ld d, b
    and c
    xor e
    adc h
    adc a
    db $e3
    ld a, a
    ld [de], a
    ld a, [bc]
    add c
    xor e
    ld d, b
    adc e
    sub h
    ret c

    add h
    ld d, b
    ld b, b
    and l
    and b
    db $e3
    adc a
    ld a, a
    cp [hl]
    rst $18
    jp $50b2


    sbc l
    xor h
    ld b, d
    ld a, a
    ld [de], a
    ld a, [bc]
    add c
    xor e
    ld d, b
    ld [de], a
    add hl, de
    xor h
    rlca
    ld a, a
    ld b, d
    and a
    add c
    ld d, b
    adc h
    ld b, a
    adc e
    xor l
    and [hl]
    ld [hl], h
    adc d
    xor e
    add a
    adc h
    ld d, b
    ld b, d
    xor b
    ld [de], a
    xor [hl]
    db $e3
    adc d
    db $e3
    ld d, b

jr_01c_444a:
    add e
    rlca
    dec c
    add a
    sub d
    or b
    dec de
    ld a, a
    ld b, d
    xor b
    ld [de], a
    xor [hl]
    db $e3
    adc d
    db $e3
    ld d, b
    rst $38
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fc
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    db $fd
    cp $fc
    rst $38
    db $fc
    db $fd
    db $fc
    cp $fc
    db $fd
    db $fd
    db $fc
    db $fd
    ld a, [$ffff]
    cp $fe
    rst $38
    rst $38
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    inc a
    jr z, jr_01c_44cd

    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    and l
    and l
    rst $38
    rst $38
    cp $fe
    rst $38
    rst $38
    ldh [$e0], a

jr_01c_44cd:
    ldh [$e0], a
    ldh [$e0], a
    cp $fe
    db $fc
    db $fc
    cp $fe
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    ldh [$e0], a
    rst $38
    rst $38
    rst $38
    rst $38
    cp $fe
    pop bc
    pop bc
    push bc
    push bc
    rst $20
    rst $20
    rst $20
    rst $20
    rst $30
    rst $30
    rst $30
    rst $30
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $28
    rst $28
    rst $28
    rst $28
    rst $20
    rst $20
    rst $20
    rst $20
    db $e3
    db $e3
    and e
    and e
    ld hl, sp-$08
    db $fc
    db $fc
    cp $fe
    xor $ee
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    rst $20
    xor $ee
    cp $fe
    db $fc
    db $fc
    ld hl, sp-$08

Call_01c_4525:
    ld a, $f9
    ldh [rOBP0], a
    ld a, $a4
    ldh [rOBP1], a
    ld de, $4587
    ld hl, $8a00
    ld bc, $1e01
    call Call_000_02dd
    ld de, $4687
    ld hl, $8a10
    ld bc, $1e01
    call Call_000_02dd
    ld de, $46b5
    ld hl, $8a20
    ld bc, $1c01
    call Call_000_02dd
    ld hl, $4665
    ld de, $c360
    ld bc, $0040
    call Call_000_01bb
    ld hl, $46a5
    ld de, $c300
    ld bc, $0010
    jp Jump_000_01bb


    call Call_01c_4525
    ld a, $c2
    call Call_000_0e45
    ld hl, $c300
    ld bc, $a004

jr_01c_4577:
    push hl
    push bc

jr_01c_4579:
    ld a, [hl]
    add $04
    ld [hl+], a
    ld a, [hl]
    add $fc
    ld [hl+], a
    inc hl
    inc hl
    dec c
    jr nz, jr_01c_4579

    ld c, $01
    call Call_000_0359
    pop bc
    pop hl
    ret c

    ld a, [hl]
    cp $50
    jr nz, jr_01c_4595

    jr jr_01c_4577

jr_01c_4595:
    cp b
    jr nz, jr_01c_4577

    ld hl, $c300
    ld c, $04
    ld de, $0004

jr_01c_45a0:
    ld [hl], $a0
    add hl, de
    dec c
    jr nz, jr_01c_45a0

    ld b, $03

jr_01c_45a8:
    ld hl, $ff48
    rrc [hl]
    rrc [hl]
    ld c, $0a
    call Call_000_0359
    ret c

    dec b
    jr nz, jr_01c_45a8

    ld de, $c300
    ld a, $18

jr_01c_45bd:
    push af
    ld hl, $4613
    ld bc, $0004
    call Call_000_01bb
    pop af
    dec a
    jr nz, jr_01c_45bd

    xor a
    ld [$cd3d], a
    ld hl, $4617
    ld c, $06

jr_01c_45d4:
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    push bc
    push hl
    ld hl, $c350
    ld c, $04

jr_01c_45df:
    ld a, [de]
    cp $ff
    jr z, jr_01c_45fa

    ld [hl+], a
    inc de
    ld a, [de]
    ld [hl+], a
    inc de
    inc hl
    inc hl
    dec c
    jr nz, jr_01c_45df

    ld a, [$cd3d]
    cp $18
    jr z, jr_01c_45fa

    add $06
    ld [$cd3d], a

jr_01c_45fa:
    call Call_01c_4644
    push af
    ld hl, $c310
    ld de, $c300
    ld bc, $0050
    call Call_000_01bb
    pop af
    pop hl
    pop bc
    ret c

    dec c
    jr nz, jr_01c_45d4

    and a
    ret


    nop
    nop
    and d
    sub b
    inc hl
    ld b, [hl]
    dec hl
    ld b, [hl]
    inc sp
    ld b, [hl]
    dec sp
    ld b, [hl]
    ld b, e
    ld b, [hl]
    ld b, e
    ld b, [hl]
    ld l, b
    jr nc, jr_01c_468e

    ld b, b
    ld l, b
    ld e, b
    ld l, b
    ld a, b
    ld l, b
    jr c, jr_01c_4696

    ld c, b
    ld l, b
    ld h, b
    ld l, b
    ld [hl], b
    ld l, b
    inc [hl]
    ld l, b
    ld c, h
    ld l, b
    ld d, h
    ld l, b
    ld h, h
    ld l, b
    inc a
    ld l, b
    ld e, h
    ld l, b
    ld l, h
    ld l, b
    ld [hl], h
    rst $38

Call_01c_4644:
    ld b, $08

jr_01c_4646:
    ld hl, $c35c
    ld a, [$cd3d]
    ld de, $fffc
    ld c, a

jr_01c_4650:
    inc [hl]
    add hl, de
    dec c
    jr nz, jr_01c_4650

    ldh a, [rOBP1]
    xor $a0
    ldh [rOBP1], a
    ld c, $03
    call Call_000_0359
    ret c

    dec b
    jr nz, jr_01c_4646

    ret


    ld c, b
    ld d, b
    adc l
    nop
    ld c, b
    ld e, b
    adc [hl]
    nop
    ld d, b
    ld d, b
    adc a
    nop
    ld d, b
    ld e, b
    sub b
    nop
    ld e, b
    ld d, b
    sub c
    nop
    ld e, b
    ld e, b
    sub d
    nop
    ld h, b
    jr nc, @-$7e

    nop
    ld h, b
    jr c, @-$7d

    nop
    ld h, b
    ld b, b
    add d
    nop
    ld h, b
    ld c, b
    add e
    nop
    ld h, b

jr_01c_468e:
    ld d, b
    sub e
    nop
    ld h, b
    ld e, b
    add h
    nop
    ld h, b

jr_01c_4696:
    ld h, b
    add l
    nop
    ld h, b
    ld l, b
    add e
    nop
    ld h, b
    ld [hl], b
    add c
    nop
    ld h, b
    ld a, b
    add [hl]
    nop
    nop
    and b
    and b
    stop
    xor b
    and b
    jr nc, jr_01c_46b6

    and b
    and c
    db $10
    ld [$a1a8], sp
    jr nc, @+$06

jr_01c_46b6:
    nop
    rra
    nop
    ld c, $00
    ld a, [bc]
    jr nz, jr_01c_46be

jr_01c_46be:
    ld hl, sp+$00
    ld [hl], b
    nop
    ld d, b
    nop
    nop

Call_01c_46c5:
    call Call_01c_4974
    call Call_000_03bf
    ld c, $64
    call Call_000_3781
    call Call_000_36ca
    call Call_000_36ea
    call Call_000_0167
    ld hl, $9800
    ld bc, $0800
    ld a, $7f
    call Call_000_372a
    call Call_000_0181
    ld hl, $ff40
    set 3, [hl]
    xor a
    ld hl, $cc5b
    ld bc, $0060
    call Call_000_372a
    xor a
    ld [$cfb2], a
    ldh [$d7], a
    ld [$d087], a
    ld [$d2d7], a
    ld [$cd40], a
    inc a
    ldh [$ba], a
    ld hl, $d521
    ld a, [hl]
    inc a
    jr z, jr_01c_4710

    inc [hl]

jr_01c_4710:
    ld a, $90
    ldh [$b0], a
    ld c, $1f
    ld a, $ca
    call Call_000_0e35
    ld hl, $d124
    ld c, $ff

jr_01c_4720:
    ld a, [hl+]
    cp $ff
    jr z, jr_01c_4766

    inc c
    push hl
    push bc
    ld [$cd3d], a
    ld a, c
    ld [$cd3e], a
    ld hl, $d14c
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl]
    ld [$cd3f], a
    call Call_01c_479f
    call Call_01c_4808
    ld c, $50
    call Call_000_3781
    ld hl, $c4a6
    ld b, $03
    ld c, $0e
    call Call_000_03d2
    ld hl, $c4cf
    ld de, $4790
    call Call_000_0405
    ld c, $b4
    call Call_000_3781
    call Call_000_0b5a
    pop bc
    pop hl
    jr jr_01c_4720

jr_01c_4766:
    ld a, c
    inc a
    ld hl, $cc5b
    ld bc, $0010
    call Call_000_3ad1
    ld [hl], $ff
    call Call_01c_7f69
    xor a
    ld [$cd3d], a
    inc a
    ld [$cd40], a
    call Call_01c_479f
    call Call_01c_489b
    call Call_01c_4974
    xor a
    ldh [$b0], a
    ld hl, $ff40
    res 3, [hl]
    ret


    db $ed
    inc l
    cp [hl]
    ld b, e
    ld a, a
    or d
    ret c

    ld a, a
    or l
    jp nc, $c433

    or e
    rst $20
    ld d, b

Call_01c_479f:
    call Call_000_03bf
    ld a, $d0
    ldh [$af], a
    ld a, $c0
    ldh [$ae], a
    ld a, [$cd3d]
    ld [$cf78], a
    ld [$d092], a
    ld [$cfc0], a
    ld [$cf17], a
    ld a, [$cd40]
    and a
    jr z, jr_01c_47c4

    call Call_01c_4862
    jr jr_01c_47d2

jr_01c_47c4:
    ld hl, $c410
    call Call_000_2f2e
    call Call_000_2d7f
    ld a, $04
    call Call_000_3e9d

jr_01c_47d2:
    ld b, $0b
    ld c, $00
    call Call_000_3e1f
    ld a, $e4
    ldh [rBGP], a
    ld c, $31
    call Call_01c_4891
    ld d, $a0
    ld e, $04
    ld a, [$cf15]
    and a
    jr z, jr_01c_47ee

    sla e

jr_01c_47ee:
    call Call_01c_47fc
    xor a
    ldh [$af], a
    ld c, a
    call Call_01c_4891
    ld d, $00
    ld e, $fc

Call_01c_47fc:
jr_01c_47fc:
    call Call_000_0b31
    ldh a, [$ae]
    add e
    ldh [$ae], a
    cp d
    jr nz, jr_01c_47fc

    ret


Call_01c_4808:
    ld a, [$cd3e]
    ld hl, $d257
    call Call_000_2fb1
    call Call_01c_4817
    jp Jump_01c_4955


Call_01c_4817:
    ld hl, $c3dc
    ld b, $08
    ld c, $09
    call Call_000_03d2
    ld hl, $c419
    ld de, $4850
    call Call_000_0405
    ld hl, $c406
    ld de, $cd68
    call Call_000_0405
    ld a, [$cd3f]
    ld hl, $c433
    call Call_000_2f1a
    ld a, [$cd3d]
    ld [$d092], a
    ld hl, $c455
    ld a, $4b
    call Call_000_3e9d
    ld a, [$cd3d]
    jp Jump_000_2dc7


    db $ed
    inc l
    call z, $f343
    ld c, [hl]
    adc a
    add c
    ld b, d
    rst $30
    di
    ld c, [hl]
    adc a
    add c
    ld b, d
    ld hl, sp-$0d
    ld d, b

Call_01c_4862:
    ld de, $5941
    ld a, $04
    call Call_000_3735
    ld hl, $a188
    ld de, $a000
    ld bc, $0310
    call Call_000_01bb
    ld de, $9000
    call Call_000_30b9
    ld de, $7e50
    ld a, $0c
    call Call_000_3735
    ld a, $03
    call Call_000_3e9d
    ld de, $9310
    call Call_000_30b9
    ld c, $01

Call_01c_4891:
    ld b, $00
    ld hl, $c410
    ld a, $31
    jp Jump_000_3e9d


Call_01c_489b:
    ld hl, $d6c6
    set 3, [hl]
    ld a, $56
    call Call_000_3e9d
    ld hl, $c3f0
    ld b, $06
    ld c, $0a
    call Call_000_03d2
    ld hl, $c3a5
    ld b, $02
    ld c, $08
    call Call_000_03d2
    ld hl, $c3cf
    ld de, $d11d
    call Call_000_0405
    ld hl, $c419
    ld de, $4910
    call Call_000_0405
    ld hl, $c431
    ld de, $d97d
    ld bc, $0103
    call Call_000_3c8f
    ld [hl], $6d
    inc hl
    ld de, $d97f
    ld bc, $8102
    call Call_000_3c8f
    ld hl, $c455
    ld de, $4917
    call Call_000_0405
    ld hl, $c46c
    ld de, $d2cb
    ld c, $83
    call Call_000_2fc4
    ld [hl], $f0
    ld hl, $4922
    call Call_01c_4908
    ld hl, $4949
    call Call_01c_4908
    ld hl, $cc5d

Call_01c_4908:
    call Call_000_3c79
    ld c, $78
    jp Jump_000_3781


    db $ed
    inc l
    sbc $43
    or [hl]
    sbc $50
    db $ed
    inc l
    db $e3
    ld b, e
    ld a, a
    or l
    cp d
    ld [hl-], a
    or [hl]
    or d
    ld d, b
    db $ed
    dec l
    ld c, [hl]
    ld c, l
    sbc $6d
    ret nc

    jp nz, $c0b9

    or [hl]
    dec l
    ld d, b
    add hl, bc
    ld e, e
    call z, Call_000_0013
    ld c, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    jp nz, $cfb6

    or h
    ret nz

    or [hl]
    dec l
    ld d, b
    add hl, bc
    ld e, h
    call z, $5013
    db $ed
    dec l
    ld b, [hl]
    ld h, b
    sbc $7f
    set 4, d
    or e
    or [hl]
    ld l, l
    ld d, a

Jump_01c_4955:
    ld hl, $cc5b
    ld bc, $0010
    ld a, [$cd3e]
    call Call_000_3ad1
    ld a, [$cd3d]
    ld [hl+], a
    ld a, [$cd3f]
    ld [hl+], a
    ld e, l
    ld d, h
    ld hl, $cd68
    ld bc, $0006
    jp Jump_000_01bb


Call_01c_4974:
    ld a, $0a
    ld [$cfaf], a
    ld [$cfb0], a
    ld a, $ff
    ld [$cfae], a
    jp Jump_000_0b5a


    ld de, $4a08
    ld hl, $87c0
    ld bc, $1c03
    call Call_000_02dd
    ld hl, $cfb2
    ld a, [hl]
    push af
    ld [hl], $ff
    push hl
    ldh a, [rOBP1]
    push af
    ld a, $e0
    ldh [rOBP1], a
    ld hl, $c384
    ld de, $4a28
    call Call_01c_4a54
    ld a, $04
    ld [$cfae], a
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45

jr_01c_49b5:
    ld a, [$cfae]
    and a
    jr nz, jr_01c_49b5

    ld a, [$d123]
    ld b, a

jr_01c_49bf:
    call Call_01c_4a54
    ld a, $9e
    call Call_000_0e45
    ld c, $1e
    call Call_000_3781
    dec b
    jr nz, jr_01c_49bf

    ld a, [$c0ef]
    cp $1f
    ld [$c0f0], a
    jr nz, jr_01c_49e6

    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld a, $02
    ld [$c0ef], a

jr_01c_49e6:
    ld a, $e8
    ld [$c0ee], a
    call Call_000_0e45
    ld d, $28
    call $4a44

jr_01c_49f3:
    ld a, [$c026]
    cp $e8
    jr z, jr_01c_49f3

    ld c, $20
    call Call_000_3781
    pop af
    ldh [rOBP1], a
    pop hl
    pop af
    ld [hl], a
    jp Jump_000_0ebd


    nop
    nop
    nop
    nop
    ld a, [hl]
    nop
    ld a, [hl]
    nop
    ld a, [hl]
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc c
    inc c
    ld [de], a
    ld e, $21
    ccf
    inc sp
    dec l
    ld e, $12
    inc c
    inc c
    inc h
    inc [hl]
    ld a, h
    db $10
    dec hl
    jr nc, jr_01c_4aac

    db $10
    dec hl
    jr c, @+$7f

    jr nc, @+$32

    jr nc, jr_01c_4ab4

    db $10
    jr nc, @+$3a

    ld a, l
    jr nc, @+$37

    jr nc, @+$7f

    db $10
    dec [hl]
    jr c, jr_01c_4ac0

    jr nc, jr_01c_4a4b

    ld [$49f0], sp
    xor d
    ldh [rOBP1], a

jr_01c_4a4b:
    ld c, $0a
    call Call_000_3781
    dec b
    jr nz, @-$0b

    ret


Call_01c_4a54:
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, [de]
    inc de
    ld [hl+], a
    ld a, [de]
    inc de
    ld [hl+], a
    ret


    call Call_01c_4c40
    ld a, $ec
    ld [$c104], a
    call Call_000_3e07
    push hl
    call Call_000_0b78
    ld hl, $d6b2
    bit 7, [hl]
    res 7, [hl]
    jr nz, jr_01c_4ab9

    ld a, $a0
    call Call_000_0e45
    ld hl, $d6b1
    bit 4, [hl]
    res 4, [hl]
    pop hl
    jr nz, jr_01c_4aaf

    call Call_01c_4afb
    ld a, $a3
    call Call_000_0e45
    call Call_01c_4cd8
    ld a, b
    and a
    jr nz, jr_01c_4aac

    ld hl, $cd3d
    xor a
    ld [hl+], a
    inc a
    ld [hl+], a
    ld a, $08
    ld [hl+], a
    ld [hl], $ff
    ld hl, $cd48
    call Call_01c_4c81

jr_01c_4aa9:
    call Call_000_0d9b

jr_01c_4aac:
    jp Jump_01c_4cc3


jr_01c_4aaf:
    ld c, $32
    call Call_000_3781

jr_01c_4ab4:
    call Call_01c_4afb
    jr jr_01c_4aac

jr_01c_4ab9:
    pop hl
    ld de, $4d80
    ld hl, $8000

jr_01c_4ac0:
    ld bc, $050c
    call Call_000_02dd
    call Call_01c_4c28
    ld a, $a4
    call Call_000_0e45
    ld hl, $cd3d
    xor a
    ld [hl+], a
    ld a, $0c
    ld [hl+], a
    ld [hl], $08
    ld de, $4ae3
    call Call_01c_4bff
    call Call_000_23ae
    jr jr_01c_4aa9

    dec b
    sbc b
    rrca
    sub b
    jr @-$76

    jr nz, @-$7e

    daa
    ld a, b
    dec l
    ld [hl], b
    ld [hl-], a
    ld l, b
    ld [hl], $60
    add hl, sp
    ld e, b
    dec sp
    ld d, b
    inc a
    ld c, b
    inc a
    ld b, b

Call_01c_4afb:
    ld hl, $cd3d
    ld a, $10
    ld [hl+], a
    ld a, $3c
    ld [hl+], a
    call Call_01c_4cd0
    ld [hl], a
    jp Jump_01c_4ca6


    call Call_01c_4c40
    call Call_01c_4cd8
    ld a, b
    and a
    jr z, jr_01c_4b40

    dec a
    jp nz, Jump_01c_4bce

jr_01c_4b19:
    ld a, $9f
    call Call_000_0e45
    ld hl, $cd3d
    ld a, $f0
    ld [hl+], a
    ld a, $ec
    ld [hl+], a
    call Call_01c_4cd0
    ld [hl], a
    call Call_01c_4ca6
    call Call_01c_4cd8
    ld a, b
    dec a
    jr z, jr_01c_4b3a

    ld c, $0a
    call Call_000_3781

jr_01c_4b3a:
    call Call_000_0b5a
    jp Jump_01c_4cc3


jr_01c_4b40:
    ld a, $04
    call Call_000_2368
    ld a, [$d6b1]
    bit 6, a
    jr z, jr_01c_4b61

    ld hl, $cd3d
    ld a, $10
    ld [hl+], a
    ld a, $ff
    ld [hl+], a
    xor a
    ld [hl+], a
    ld [hl], $a1
    ld hl, $cd48
    call Call_01c_4c81
    jr jr_01c_4b19

jr_01c_4b61:
    call Call_01c_4c28
    ld hl, $cd3d
    ld a, $ff
    ld [hl+], a
    ld a, $08
    ld [hl+], a
    ld [hl], $0c
    call Call_01c_4bff
    ld a, $a4
    call Call_000_0e45
    ld hl, $cd3d
    xor a
    ld [hl+], a
    ld a, $0c
    ld [hl+], a
    ld [hl], $0c
    ld de, $4ba0
    call Call_01c_4bff
    ld c, $28
    call Call_000_3781
    ld hl, $cd3e
    ld a, $0b
    ld [hl+], a
    ld [hl], $08
    ld de, $4bb8
    call Call_01c_4bff
    call Call_000_0b5a
    jp Jump_01c_4cc3


    inc a
    ld c, b
    inc a
    ld d, b
    dec sp
    ld e, b
    ld a, [hl-]
    ld h, b
    add hl, sp
    ld l, b
    scf
    ld [hl], b
    scf
    ld a, b
    inc sp
    add b
    jr nc, jr_01c_4b3a

    dec l
    sub b
    ld a, [hl+]
    sbc b
    daa
    and b
    ld a, [de]
    sub b
    add hl, de
    add b
    rla
    ld [hl], b
    dec d
    ld h, b
    ld [de], a
    ld d, b
    rrca
    ld b, b
    inc c
    jr nc, jr_01c_4bd0

    jr nz, jr_01c_4bce

    stop
    nop
    ldh a, [rP1]

Jump_01c_4bce:
jr_01c_4bce:
    ld a, $ff

jr_01c_4bd0:
    ld [$cfb2], a
    ld a, [$c302]
    ld [$c30a], a
    ld a, [$c306]
    ld [$c30e], a
    ld a, $a0
    ld [$c300], a
    ld [$c304], a
    ld c, $02
    call Call_000_3781
    ld a, $a0
    ld [$c308], a
    ld [$c30c], a
    call Call_000_0b5a
    ld a, $01
    ld [$cfb2], a
    jp Jump_01c_4cc3


Call_01c_4bff:
jr_01c_4bff:
    ld a, [$cd3f]
    xor $01
    ld [$cd3f], a
    ld [$c102], a
    call Call_000_3e07
    ld a, [$cd3d]
    cp $ff
    jr z, jr_01c_4c1e

    ld hl, $c104
    ld a, [de]
    inc de
    ld [hl+], a
    inc hl
    ld a, [de]
    inc de
    ld [hl], a

jr_01c_4c1e:
    ld a, [$cd3e]
    dec a
    ld [$cd3e], a
    jr nz, jr_01c_4bff

    ret


Call_01c_4c28:
    ld de, $4d80
    ld hl, $8000
    ld bc, $050c
    call Call_000_02dd
    ld de, $4e40
    ld hl, $8800
    ld bc, $050c
    jp Jump_000_02dd


Call_01c_4c40:
    ld a, [$c102]
    ld [$cd50], a
    ld a, [$c104]
    ld [$cd4f], a
    ld hl, $4c64
    ld de, $cd48
    ld bc, $0004
    call Call_000_01bb
    ld a, [$c102]
    ld hl, $cd48

jr_01c_4c5e:
    cp [hl]
    inc hl
    jr nz, jr_01c_4c5e

    dec hl
    ret


    nop
    ld [$0c04], sp

Call_01c_4c68:
    ld a, [hl]
    ld [$c102], a
    push hl
    ld hl, $cd48
    ld de, $cd47
    ld bc, $0004
    call Call_000_01bb
    ld a, [$cd47]
    ld [$cd4b], a
    pop hl
    ret


Call_01c_4c81:
jr_01c_4c81:
    call Call_01c_4c68
    ld a, [$cd3d]
    ld c, a
    and $03
    jr nz, jr_01c_4c94

    ld a, [$cd40]
    cp $ff
    call nz, Call_000_0e45

jr_01c_4c94:
    ld a, [$cd3e]
    add c
    ld [$cd3d], a
    ld c, a
    ld a, [$cd3f]
    cp c
    ret z

    call Call_000_3781
    jr jr_01c_4c81

Call_01c_4ca6:
Jump_01c_4ca6:
jr_01c_4ca6:
    call Call_01c_4c68
    ld a, [$cd3d]
    ld c, a
    ld a, [$c104]
    add c
    ld [$c104], a
    ld c, a
    ld a, [$cd3e]
    cp c
    ret z

    ld a, [$cd3f]
    ld c, a
    call Call_000_3781
    jr jr_01c_4ca6

Jump_01c_4cc3:
    ld a, [$cd4f]
    ld [$c104], a
    ld a, [$cd50]
    ld [$c102], a
    ret


Call_01c_4cd0:
    ld a, [$cf15]
    xor $01
    inc a
    inc a
    ret


Call_01c_4cd8:
    ld b, $00
    ld hl, $4cfa
    ld a, [$d2e6]
    ld c, a

jr_01c_4ce1:
    ld a, [hl+]
    cp $ff
    jr z, jr_01c_4cf5

    cp c
    jr nz, jr_01c_4cef

    ld a, [$c45c]
    cp [hl]
    jr z, jr_01c_4cf3

jr_01c_4cef:
    inc hl
    inc hl
    jr jr_01c_4ce1

jr_01c_4cf3:
    inc hl
    ld b, [hl]

jr_01c_4cf5:
    ld a, b
    ld [$cd51], a
    ret


    ld d, $20
    ld bc, $1116
    ld [bc], a
    ld de, $0222
    db $10
    ld d, l
    ld bc, $0eff
    ld a, [bc]
    call Call_000_3781
    ld hl, $d6b5
    set 6, [hl]
    ld de, $4180
    ld hl, $8000
    ld bc, $050c
    call Call_000_02dd
    ld a, $04
    ld hl, $4dd2
    call Call_01c_5c35
    ld a, [$c102]
    ld c, a
    ld b, $00
    ld hl, $4dc2
    add hl, bc
    ld de, $c39c
    ld bc, $0004
    call Call_000_01bb
    ld c, $64
    call Call_000_3781
    ld a, [$cd3d]
    and a
    ld hl, $4d9b
    jr z, jr_01c_4d87

    cp $02
    ld hl, $4da4
    jr z, jr_01c_4d87

    ld b, $0a

jr_01c_4d4f:
    ld hl, $c104
    call Call_01c_4d96
    ld hl, $c39c
    call Call_01c_4d96
    call Call_000_3e07
    dec b
    jr nz, jr_01c_4d4f

    ld a, [$c102]
    cp $04
    jr nz, jr_01c_4d6d

    ld a, $a0
    ld [$c39c], a

jr_01c_4d6d:
    ld hl, $cd4f
    xor a
    ld [hl+], a
    ld [hl], a
    ld a, $4c
    call Call_000_3e9d
    ld a, [$c102]
    cp $04
    jr nz, jr_01c_4d84

    ld a, $44
    ld [$c39c], a

jr_01c_4d84:
    ld hl, $4db2

jr_01c_4d87:
    call Call_000_3c79
    ld hl, $d6b5
    res 6, [hl]
    call Call_000_23ae
    call Call_000_36ca
    ret


Call_01c_4d96:
    ld a, [hl]
    xor $01
    ld [hl], a
    ret


    db $ed
    dec l
    ld d, l
    ld d, h
    or d
    push bc
    db $e3
    ld d, [hl]
    ld e, b
    nop
    push bc
    add $d3
    ld a, a
    or d
    push bc
    or d
    ld a, a
    ret nc

    ret nz

    or d
    ld d, [hl]
    ld e, b
    db $ed
    dec hl
    ld [hl], b
    ld h, c
    ld c, a
    res 6, d
    jp Jump_01c_7fd9


    res 6, d
    jp $e7d9


    ld e, b
    ld e, e
    ld c, h
    db $fd
    nop
    ld b, h
    ld c, h
    db $fd
    nop
    ld d, b
    ld b, b
    cp $00
    ld d, b
    ld e, b
    cp $20
    add hl, de
    ld h, b
    ld [bc], a
    ld e, $20
    add b
    add hl, sp
    ld h, b
    ld [bc], a
    ld e, $60
    add b
    ld e, c
    ld h, b
    ld [bc], a
    ld e, $a0
    add b
    ld a, c
    ld h, b
    inc bc
    ld e, $d0
    adc a
    ld a, [$d693]
    ld c, a
    inc a
    cp $10
    jr nc, jr_01c_4e01

    ld [$d693], a
    ld b, $00
    ld hl, $4e26
    add hl, bc
    ld a, [hl]
    ld [$c104], a
    ret


jr_01c_4e01:
    ld a, [$cfac]
    cp $00
    ret nz

    call Call_000_0ebd
    call Call_000_3e07
    xor a
    ldh [$b4], a
    ldh [$b3], a
    ldh [$b2], a
    ld [$d693], a
    ld hl, $d6b5
    res 6, [hl]
    ld hl, $d6af
    res 7, [hl]
    xor a
    ld [$cd66], a
    ret


    jr c, @+$38

    inc [hl]
    ld [hl-], a
    ld sp, $3030
    jr nc, @+$33

    ld [hl-], a
    inc sp
    inc [hl]
    ld [hl], $38
    inc a
    inc a
    ld a, $e4
    ldh [rOBP1], a
    call Call_01c_4e96
    ld hl, $c3ac
    ld bc, $0707
    call Call_000_0374
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ld a, $91
    ld [$cee4], a
    ld a, $01
    ldh [$f3], a
    ld hl, $57ca
    ld b, $1e
    call Call_000_3620
    ld d, $80
    call $4a44

jr_01c_4e62:
    ld c, $0a
    call Call_000_3781
    ldh a, [rOBP1]
    sla a
    sla a
    ldh [rOBP1], a
    jr nz, jr_01c_4e62

    call Call_000_0188
    call Call_01c_4e96
    ld b, $e4

jr_01c_4e79:
    ld c, $0a
    call Call_000_3781
    ldh a, [rOBP1]
    srl b
    rra
    srl b
    rra
    ldh [rOBP1], a
    ld a, b
    and a
    jr nz, jr_01c_4e79

    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    jp Jump_000_0188


Call_01c_4e96:
    ld de, $9000
    ld hl, $8000
    ld bc, $0031
    call Call_000_02dd
    ld a, $10
    ld [$d05f], a
    ld a, $70
    ld [$d05e], a
    ld hl, $c300
    ld bc, $0606
    ld d, $08

jr_01c_4eb4:
    push bc
    ld a, [$d05f]
    ld e, a

jr_01c_4eb9:
    ld a, e
    add $08
    ld e, a
    ld [hl+], a
    ld a, [$d05e]
    ld [hl+], a
    ld a, d
    ld [hl+], a
    ld a, $10
    ld [hl+], a
    inc d
    dec c
    jr nz, jr_01c_4eb9

    inc d
    ld a, [$d05e]
    add $08
    ld [$d05e], a
    pop bc
    dec b
    jr nz, jr_01c_4eb4

    ret


    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    xor a
    ldh [$b0], a
    dec a
    ld [$cfb2], a
    call Call_000_0b31
    ld hl, $c102
    ldh a, [$8c]
    ld c, a
    ld b, $00
    ld de, $0010

jr_01c_4ef5:
    ld a, [hl]
    cp $ff
    jr z, jr_01c_4efb

    inc b

jr_01c_4efb:
    add hl, de
    dec c
    jr nz, jr_01c_4ef5

    ld hl, $c310
    ld c, $09

jr_01c_4f04:
    ld a, b
    swap a
    cp l
    jr z, jr_01c_4f15

    push hl
    push bc
    ld bc, $0010
    xor a
    call Call_000_372a
    pop bc
    pop hl

jr_01c_4f15:
    ld de, $0010
    add hl, de
    dec c
    jr nz, jr_01c_4f04

    call Call_000_3e07
    call Call_01c_4fb9
    ld bc, $0000
    ld a, [$d0f0]
    cp $04
    jr z, jr_01c_4f35

    call Call_01c_4f4e
    call Call_01c_4f5b
    call Call_01c_4f85

jr_01c_4f35:
    ld hl, $4f3e
    add hl, bc
    add hl, bc
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp hl


    sub b
    ld d, d
    sbc $4f
    ld d, b
    ld d, d
    sbc $4f
    jr nz, jr_01c_4f9a

    db $eb
    ld d, b
    ld [$3651], a
    ld d, c

Call_01c_4f4e:
    ld a, [$d036]
    cp $c8
    jr nc, jr_01c_4f58

    res 0, c
    ret


jr_01c_4f58:
    set 0, c
    ret


Call_01c_4f5b:
    ld hl, $d12c

jr_01c_4f5e:
    ld a, [hl+]
    or [hl]
    jr nz, jr_01c_4f68

    ld de, $002b
    add hl, de
    jr jr_01c_4f5e

jr_01c_4f68:
    ld de, $001f
    add hl, de
    ld a, [hl]
    add $03
    ld e, a
    ld a, [$d0ec]
    sub e
    jr nc, jr_01c_4f7e

    res 1, c
    ld a, $01
    ld [$cd47], a
    ret


jr_01c_4f7e:
    set 1, c
    xor a
    ld [$cd47], a
    ret


Call_01c_4f85:
    ld a, [$d2dd]
    ld e, a
    ld hl, $4fab

jr_01c_4f8c:
    ld a, [hl+]
    cp $ff
    jr z, jr_01c_4f97

    cp e
    jr nz, jr_01c_4f8c

jr_01c_4f94:
    set 2, c
    ret


jr_01c_4f97:
    ld hl, $4fb0

jr_01c_4f9a:
    ld a, [hl+]
    cp $ff
    jr z, jr_01c_4fa8

    ld d, a
    ld a, [hl+]
    cp e
    jr c, jr_01c_4f9a

    ld a, e
    cp d
    jr nc, jr_01c_4f94

jr_01c_4fa8:
    res 2, c
    ret


    inc sp
    ld d, d
    ret nz

    add sp, -$01
    dec sp
    dec a
    ld e, a
    db $76
    adc l
    sub a
    rst $08
    db $e4
    rst $38

Call_01c_4fb9:
    ld hl, $8ff0
    ld de, $4fc5
    ld bc, $1c01
    jp Jump_000_02dd


    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38
    rst $38

Call_01c_4fd5:
Jump_01c_4fd5:
    ld a, $ff
    ldh [rBGP], a
    ldh [rOBP0], a
    ldh [rOBP1], a
    ret


    ld a, [$cd47]
    and a
    jr z, jr_01c_4fe9

    call Call_01c_5016
    jr jr_01c_500b

jr_01c_4fe9:
    ld hl, $c472
    ld a, $03
    ld [$d07c], a
    ld a, l
    ld [$d078], a
    ld a, h
    ld [$d077], a
    ld b, $78

jr_01c_4ffb:
    ld c, $03

jr_01c_4ffd:
    push bc
    call Call_01c_5065
    pop bc
    dec c
    jr nz, jr_01c_4ffd

    call Call_000_0b31
    dec b
    jr nz, jr_01c_4ffb

jr_01c_500b:
    call Call_01c_4fd5
    xor a
    ld [$d078], a
    ld [$d077], a
    ret


Call_01c_5016:
    ld a, $07
    ld [$cd3d], a
    ld hl, $c3a0
    ld c, $11
    ld de, $0014
    call Call_01c_504c
    inc c
    jr jr_01c_502f

jr_01c_5029:
    ld de, $0014
    call Call_01c_504c

jr_01c_502f:
    inc c
    ld de, $0001
    call Call_01c_504c
    dec c
    dec c
    ld de, $ffec
    call Call_01c_504c
    inc c
    ld de, $ffff
    call Call_01c_504c
    dec c
    dec c
    ld a, c
    and a
    jr nz, jr_01c_5029

    ret


Call_01c_504c:
    push bc

jr_01c_504d:
    ld [hl], $ff

Call_01c_504f:
    add hl, de
    push bc
    ld a, [$cd3d]
    dec a
    jr nz, jr_01c_505c

    call Call_01c_5285
    ld a, $07

jr_01c_505c:
    ld [$cd3d], a
    pop bc
    dec c
    jr nz, jr_01c_504d

    pop bc
    ret


Call_01c_5065:
    ld bc, $ffec
    ld de, $0014
    ld a, [$d078]
    ld l, a
    ld a, [$d077]
    ld h, a
    ld a, [$d07c]
    cp $00
    jr z, jr_01c_5091

    cp $01
    jr z, jr_01c_509b

    cp $02
    jr z, jr_01c_50a5

    cp $03
    jr z, jr_01c_50af

jr_01c_5086:
    ld [hl], $ff

jr_01c_5088:
    ld a, l
    ld [$d078], a
    ld a, h
    ld [$d077], a
    ret


jr_01c_5091:
    dec hl
    ld a, [hl]
    cp $ff
    jr nz, jr_01c_50b9

    inc hl
    add hl, bc
    jr jr_01c_5086

jr_01c_509b:
    add hl, de
    ld a, [hl]
    cp $ff
    jr nz, jr_01c_50b9

    add hl, bc
    dec hl
    jr jr_01c_5086

jr_01c_50a5:
    inc hl
    ld a, [hl]
    cp $ff
    jr nz, jr_01c_50b9

    dec hl
    add hl, de
    jr jr_01c_5086

jr_01c_50af:
    add hl, bc
    ld a, [hl]
    cp $ff
    jr nz, jr_01c_50b9

    add hl, de
    inc hl
    jr jr_01c_5086

jr_01c_50b9:
    ld [hl], $ff
    ld a, [$d07c]
    inc a
    cp $04
    jr nz, jr_01c_50c4

    xor a

jr_01c_50c4:
    ld [$d07c], a
    jr jr_01c_5088

Call_01c_50c9:
jr_01c_50c9:
    ld hl, $50de

jr_01c_50cc:
    ld a, [hl+]
    cp $01

Call_01c_50cf:
    jr z, jr_01c_50da

    ldh [rBGP], a
    ld c, $02
    call Call_000_3781
    jr jr_01c_50cc

jr_01c_50da:
    dec b
    jr nz, jr_01c_50c9

    ret


    ld sp, hl
    cp $ff
    cp $f9
    db $e4
    sub b
    ld b, b
    nop
    ld b, b
    sub b
    db $e4
    ld bc, $090e

jr_01c_50ed:
    push bc
    xor a
    ldh [$ba], a
    ld hl, $c42c
    ld de, $c440
    ld bc, $ffd8
    call Call_01c_517e
    ld hl, $c468
    ld de, $c454
    ld bc, $0028
    call Call_01c_517e
    ld hl, $c3a8
    ld de, $c3a9
    ld bc, $fffe
    call Call_01c_51ab
    ld hl, $c3ab
    ld de, $c3aa
    ld bc, $0002
    call Call_01c_51ab
    ld a, $01
    ldh [$ba], a
    ld c, $06
    call Call_000_3781
    pop bc
    dec c
    jr nz, jr_01c_50ed

    call Call_01c_4fd5
    ld c, $0a
    jp Jump_000_3781


    ld c, $09
    xor a
    ldh [$ba], a

jr_01c_513b:
    push bc
    ld hl, $c4e0
    ld de, $c4f4
    ld bc, $ffd8
    call Call_01c_517e
    ld hl, $c3b4
    ld de, $c3a0
    ld bc, $0028
    call Call_01c_517e
    ld hl, $c3b2
    ld de, $c3b3
    ld bc, $fffe
    call Call_01c_51ab
    ld hl, $c3a1
    ld de, $c3a0
    ld bc, $0002
    call Call_01c_51ab
    call Call_01c_5285
    call Call_000_3e07
    pop bc
    dec c
    jr nz, jr_01c_513b

    call Call_01c_4fd5
    ld c, $0a
    jp Jump_000_3781


Call_01c_517e:
    ld a, c
    ld [$cd3d], a
    ld a, b
    ld [$cd3e], a
    ld c, $08

jr_01c_5188:
    push bc
    push hl
    push de
    ld bc, $0014
    call Call_000_01bb
    pop hl
    pop de
    ld a, [$cd3d]
    ld c, a
    ld a, [$cd3e]
    ld b, a
    add hl, bc
    pop bc
    dec c
    jr nz, jr_01c_5188

    ld l, e
    ld h, d
    ld a, $ff
    ld c, $14

jr_01c_51a6:
    ld [hl+], a
    dec c
    jr nz, jr_01c_51a6

    ret


Call_01c_51ab:
    ld a, c
    ld [$cd3d], a
    ld a, b
    ld [$cd3e], a
    ld c, $09

jr_01c_51b5:
    push bc
    push hl
    push de
    ld c, $12

jr_01c_51ba:
    ld a, [hl]
    ld [de], a
    ld a, e
    add $14
    jr nc, jr_01c_51c2

    inc d

jr_01c_51c2:
    ld e, a
    ld a, l
    add $14
    jr nc, jr_01c_51c9

    inc h

jr_01c_51c9:
    ld l, a
    dec c
    jr nz, jr_01c_51ba

    pop hl
    pop de
    ld a, [$cd3d]
    ld c, a
    ld a, [$cd3e]
    ld b, a
    add hl, bc
    pop bc
    dec c
    jr nz, jr_01c_51b5

    ld l, e
    ld h, d
    ld de, $0014
    ld c, $12

Call_01c_51e3:
jr_01c_51e3:
    ld [hl], $ff
    add hl, de
    dec c
    jr nz, jr_01c_51e3

    ret


    ld c, $12
    ld hl, $c3a0
    ld de, $c4f5
    xor a
    ldh [$ba], a

jr_01c_51f5:
    push bc
    push hl
    push de
    push de
    call Call_01c_5216
    pop hl
    call Call_01c_5216
    call Call_01c_5285
    pop hl
    ld bc, $ffec
    add hl, bc
    ld e, l
    ld d, h
    pop hl
    ld bc, $0014
    add hl, bc
    pop bc
    dec c
    jr nz, jr_01c_51f5

    jp Jump_01c_4fd5


Call_01c_5216:
    ld c, $0a

jr_01c_5218:
    ld [hl], $ff
    inc hl
    inc hl
    dec c
    jr nz, jr_01c_5218

    ret


    ld c, $14
    ld hl, $c3a0
    ld de, $c3c7
    xor a
    ldh [$ba], a

jr_01c_522b:
    push bc
    push hl
    push de
    push de
    call Call_01c_5244
    pop hl
    call Call_01c_5244
    call Call_01c_5285
    pop de
    pop hl
    pop bc
    inc hl
    dec de
    dec c
    jr nz, jr_01c_522b

    jp Jump_01c_4fd5


Call_01c_5244:
    ld c, $09
    ld de, $0028

jr_01c_5249:
    ld [hl], $ff
    add hl, de
    dec c
    jr nz, jr_01c_5249

    ret


    call Call_01c_5269
    ld bc, $000a
    ld hl, $52cd
    call Call_01c_5272
    ld c, $0a
    ld b, $01
    ld hl, $52ff
    call Call_01c_5272
    jp Jump_01c_4fd5


Call_01c_5269:
    ld b, $03
    call Call_01c_50c9
    xor a
    ldh [$ba], a
    ret


Call_01c_5272:
jr_01c_5272:
    push bc
    push hl
    ld a, b
    call Call_01c_52bc
    pop hl
    ld bc, $0005
    add hl, bc
    call Call_01c_5285
    pop bc
    dec c
    jr nz, jr_01c_5272

    ret


Call_01c_5285:
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ret


    call Call_01c_5269
    ld c, $0a
    ld hl, $52cd
    ld de, $52ff

jr_01c_529b:
    push bc
    push hl
    push de
    push de
    xor a
    call Call_01c_52bc
    pop hl
    ld a, $01
    call Call_01c_52bc
    pop hl
    ld bc, $0005
    add hl, bc
    ld e, l
    ld d, h
    pop hl
    add hl, bc
    call Call_01c_5285
    pop bc
    dec c
    jr nz, jr_01c_529b

    jp Jump_01c_4fd5


Call_01c_52bc:
    ld [$cd3d], a
    ld a, [hl+]
    ld [$cd3e], a
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp $5331


    ld bc, $536a
    ld a, [hl+]
    call nz, Call_01c_7001
    ld d, e
    rst $28
    jp Jump_01c_7a01


    ld d, e
    or d
    jp $8c01


    ld d, e
    xor [hl]
    jp $9a01


    ld d, e
    xor d
    jp $9a00


    ld d, e
    xor c
    jp $8c00


    ld d, e
    and l
    jp Jump_01c_7a00


    ld d, e
    and c
    jp Jump_01c_7000


    ld d, e
    call c, Call_000_00c3
    ld l, d
    ld d, e
    add hl, de
    call nz, Call_01c_6a00
    ld d, e
    ld a, l
    call nz, Call_01c_7000
    ld d, e
    cp b
    call nz, Call_01c_7a00
    ld d, e
    push af
    call nz, $8c00
    ld d, e
    ld sp, hl
    call nz, $9a00
    ld d, e
    db $fd
    call nz, $9a01
    ld d, e
    cp $c4
    ld bc, $538c
    ld [bc], a
    push bc
    ld bc, $537a
    ld b, $c5
    ld bc, $5370
    set 0, h
    ld bc, $536a
    adc [hl]
    call nz, $1ae5
    ld c, a
    inc de

jr_01c_5335:
    ld [hl], $ff
    ld a, [$cd3e]
    and a
    jr z, jr_01c_5340

    inc hl
    jr jr_01c_5341

jr_01c_5340:
    dec hl

jr_01c_5341:
    dec c
    jr nz, jr_01c_5335

    pop hl
    ld a, [$cd3d]
    and a
    ld bc, $0014
    jr z, jr_01c_5351

    ld bc, $ffec

jr_01c_5351:
    add hl, bc
    ld a, [de]
    inc de
    cp $ff
    ret z

    and a
    jr z, @-$27

    ld c, a

jr_01c_535b:
    ld a, [$cd3e]
    and a
    jr z, jr_01c_5364

    dec hl
    jr jr_01c_5365

jr_01c_5364:
    inc hl

jr_01c_5365:
    dec c
    jr nz, jr_01c_535b

    jr @-$37

    ld [bc], a
    inc bc
    dec b
    inc b
    add hl, bc
    rst $38
    ld bc, $0201
    ld [bc], a
    inc b
    ld [bc], a
    inc b
    ld [bc], a
    inc bc
    rst $38
    ld [bc], a
    ld bc, $0103
    inc b
    ld bc, HeaderLogo
    inc b
    ld bc, $0103
    ld [bc], a
    ld bc, $0101
    ld bc, $04ff
    ld bc, $0004
    inc bc
    ld bc, $0003
    ld [bc], a
    ld bc, $0002
    ld bc, $04ff
    nop
    inc bc
    nop
    inc bc
    nop
    ld [bc], a
    nop
    ld [bc], a
    nop
    ld bc, $0100
    nop
    ld bc, $cdff
    rla
    ld d, [hl]
    ld hl, $cfb2
    ld a, [hl]
    push af
    ld [hl], $ff
    push hl
    ld a, $01
    ld [$ffb7], a
    ld a, [$d2dd]
    push af
    ld b, $00
    call Call_01c_5763
    ld hl, $c3a0
    ld de, $cd68
    call Call_000_0405
    ld hl, $c300
    ld de, $c508
    ld bc, $0010
    call Call_000_01bb
    ld hl, $8040
    ld de, $54ae
    ld bc, $1c04
    call Call_000_031b
    xor a
    ld [$cd3d], a
    pop af
    jr jr_01c_53ff

Jump_01c_53eb:
    ld hl, $c3a0
    ld bc, $020a
    call Call_000_0374
    ld hl, $547f
    ld a, [$cd3d]
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]

jr_01c_53ff:
    ld de, $cee4
    call Call_01c_588d
    ld a, [de]
    push hl
    call Call_01c_57f4
    ld a, $04
    ld [$cd51], a
    ld hl, $c310
    call Call_01c_5815
    pop hl
    ld de, $cd68

jr_01c_5419:
    ld a, [hl+]
    ld [de], a
    inc de
    cp $50
    jr nz, jr_01c_5419

    ld hl, $c3a0
    ld de, $cd68
    call Call_000_0405
    ld hl, $c310
    ld de, $c518
    ld bc, $0010
    call Call_000_01bb

jr_01c_5435:
    call Call_01c_5b8a
    call Call_000_3879
    ldh a, [$b5]
    ld b, a
    and $c3
    jr z, jr_01c_5435

    ld a, $8c
    call Call_000_0e45
    bit 6, b
    jr nz, jr_01c_5460

    bit 7, b
    jr nz, jr_01c_546f

    xor a
    ld [$d078], a
    ld [$ffb7], a
    ld [$d068], a
    call $574a
    pop hl
    pop af
    ld [hl], a
    ret


jr_01c_5460:
    ld a, [$cd3d]
    inc a
    cp $2f
    jr nz, jr_01c_5469

    xor a

jr_01c_5469:
    ld [$cd3d], a
    jp Jump_01c_53eb


jr_01c_546f:
    ld a, [$cd3d]
    dec a
    cp $ff
    jr nz, jr_01c_5479

    ld a, $2e

jr_01c_5479:
    ld [$cd3d], a
    jp Jump_01c_53eb


    nop
    inc c
    ld bc, $330d
    push bc
    ld [bc], a
    ld c, $3b
    rrca
    inc bc
    inc hl
    inc h
    ld e, b
    db $10
    ld de, $5f05
    inc d
    ld d, c
    dec d
    inc b
    adc a
    inc de
    ld [de], a
    ld b, $0a
    ld d, $17
    jr jr_01c_54b7

    ld a, [de]
    dec de
    inc e
    dec e
    rlca
    reti


    ld e, $9f
    rra
    ld [$2120], sp
    ld [hl+], a
    add $09
    ld d, e
    cp $fe
    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    nop
    ld a, a

jr_01c_54b7:
    ld a, a
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    nop
    nop
    ret nz

    ret nz

    ret nz

    ret nz

    ret nz

    cp $fe
    nop
    inc bc
    inc bc
    inc bc
    inc bc
    inc bc
    ld a, a
    ld a, a
    call Call_01c_5617
    ld hl, $cfb2
    ld a, [hl]
    push af
    ld [hl], $ff
    push hl
    call Call_01c_578e
    call Call_000_1aab
    ld hl, $c3b4
    call Call_000_0405
    ld hl, $c3b9
    ld de, $54f8
    call Call_000_0405
    call Call_000_38ae
    call $574a
    pop hl
    pop af
    ld [hl], a
    ret


    db $ed
    inc l
    jp hl


    ld b, e
    or [hl]
    ld d, b
    call Call_000_0188
    call Call_01c_5617
    call Call_000_23ae
    call Call_000_36ca
    ld de, $4d80
    ld hl, $8040
    ld bc, $050c
    call Call_000_02dd
    ld de, $560f
    ld hl, $8ed0
    ld bc, $1c01
    call Call_000_031b
    call Call_01c_55ec
    ld hl, $cfb2
    ld a, [hl]
    push af
    ld [hl], $ff
    push hl
    ld hl, $c3b9
    ld de, $55e2
    call Call_000_0405
    ld a, [$d2dd]
    ld b, $00
    call Call_01c_5763
    ld hl, $cd3e
    ld de, $c3bd

Jump_01c_5544:
    ld a, $7f
    ld [de], a
    push hl
    push hl
    ld hl, $c3a1
    ld de, $55e7
    call Call_000_0405
    ld hl, $c3b7
    ld a, $7f
    ld [hl+], a
    ld [hl], a
    pop hl
    ld a, [hl]
    ld b, $04
    call Call_01c_5763
    ld hl, $c3b5
    ld de, $cd68
    call Call_000_0405
    ld c, $0f
    call Call_000_3781
    ld hl, $c3a9
    ld [hl], $ed
    ld hl, $c3bd
    ld [hl], $ee
    pop hl

jr_01c_5579:
    push hl
    call Call_000_0b31
    call Call_000_3879
    ldh a, [$b5]
    ld b, a
    pop hl
    and $c3
    jr z, jr_01c_5579

    bit 0, b
    jr nz, jr_01c_559b

    ld a, $8c
    call Call_000_0e45
    bit 6, b
    jr nz, jr_01c_55b7

    bit 7, b
    jr nz, jr_01c_55cd

    jr jr_01c_55ac

jr_01c_559b:
    ld a, $8e
    call Call_000_0e45
    ld a, [hl]
    ld [$d699], a
    ld hl, $d6b1
    set 3, [hl]
    inc hl
    set 7, [hl]

jr_01c_55ac:
    xor a
    ld [$d078], a
    call Call_000_3e04
    pop hl
    pop af
    ld [hl], a
    ret


jr_01c_55b7:
    ld de, $c3bd
    inc hl
    ld a, [hl]
    cp $ff
    jr z, jr_01c_55c7

    cp $fe
    jr z, jr_01c_55b7

    jp Jump_01c_5544


jr_01c_55c7:
    ld hl, $cd3e
    jp Jump_01c_5544


jr_01c_55cd:
    ld de, $c3a9
    dec hl
    ld a, [hl]
    cp $ff
    jr z, jr_01c_55dd

    cp $fe
    jr z, jr_01c_55cd

    jp Jump_01c_5544


jr_01c_55dd:
    ld hl, $cd49
    jr jr_01c_55cd

    db $ed
    inc l
    rst $28
    ld b, e
    ld d, b
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, b

Call_01c_55ec:
    ld hl, $cd3d
    ld [hl], $ff
    inc hl
    ld a, [$d68a]
    ld e, a
    ld a, [$d68b]
    ld d, a
    ld bc, $000b

jr_01c_55fd:
    srl d
    rr e
    ld a, $fe
    jr nc, jr_01c_5606

    ld a, b

jr_01c_5606:
    ld [hl], a
    inc hl
    inc b
    dec c
    jr nz, jr_01c_55fd

    ld [hl], $ff
    ret


    nop
    nop
    db $10
    jr c, @+$7e

    cp $fe
    nop

Call_01c_5617:
    call Call_000_3e04
    call Call_000_03bf
    call Call_000_0ebd
    ld hl, $c3a0
    ld b, $12
    ld c, $12
    call Call_000_03d2
    call Call_000_0167
    ld hl, $5611
    ld de, $9600
    ld bc, $0100
    ld a, $04
    call Call_000_028c
    ld hl, $5b82
    ld de, $8040
    ld bc, $0008
    ld a, $1c
    call Call_000_02c0
    ld hl, $c3a0
    ld de, $567c

jr_01c_564f:
    ld a, [de]
    and a
    jr z, jr_01c_5665

    ld b, a
    and $0f
    ld c, a
    ld a, b
    swap a
    and $0f
    add $60

jr_01c_565e:
    ld [hl+], a
    dec c
    jr nz, jr_01c_565e

    inc de
    jr jr_01c_564f

jr_01c_5665:
    call Call_000_0181
    ld b, $02
    call Call_000_3e1f
    call Call_000_3e07
    call Call_000_3e0c
    xor a
    ld [$d068], a
    inc a
    ld [$d078], a
    ret


    ld a, d
    ld sp, $3128
    ld a, d
    ld de, $7361
    add c
    ld b, e
    ld de, $2931
    ld sp, $7161
    ld h, h
    add c
    ld b, c
    ld de, $6111
    ld d, c
    ld h, h
    ld [hl], c
    pop bc
    ld [hl], e
    ld d, c
    ld [hl], h
    ld h, d
    ld de, $6111
    ld [hl], c
    ld h, c
    ld d, c
    ld [hl], e
    ld h, h
    ld [hl], c
    ld h, e
    pop bc
    ld h, c
    or c
    ld de, $6111
    pop bc
    ld h, c
    pop bc
    ld h, a
    ld [hl], c
    ld h, e
    ld [hl], c
    or c
    ld b, c
    ld de, $6111
    ld [hl], c
    ld h, c
    ld [hl], c
    ld h, c
    ld [hl], e
    ld d, c
    ld [hl], d
    ld d, c
    ld [hl], e
    ld d, c
    ld b, d
    ld de, $6111
    ld [hl], c
    ld h, c
    ld [hl], c
    ld h, c
    ld [hl], c
    ld h, l
    ld [hl], c
    ld h, e
    ld [hl], c
    ld b, d
    ld de, $6111
    ld [hl], c
    ld h, c
    ld [hl], c
    ld h, c
    ld [hl], c
    or c
    and c
    ld h, e
    ld [hl], c
    ld h, e
    ld [hl], c
    ld b, d
    ld de, $6111
    ld [hl], d
    ld d, c
    ld h, c
    ld [hl], c
    ld b, e
    and c
    ld h, c
    ld [hl], c
    ld h, e
    ld [hl], c
    ld b, d
    ld de, $b111
    and c
    ld h, c
    ld [hl], c
    ld h, c
    ld [hl], c
    ld h, c
    ld b, e
    ld h, c
    ld d, c
    ld [hl], h
    sub c
    ld b, c
    ld de, $4211
    ld h, c
    ld [hl], c
    ld h, c
    ld [hl], c
    or c
    ld b, e
    and c
    ld h, h
    ld [hl], c
    or c
    ld b, c
    ld de, $4211
    ld h, c
    ld d, c
    or c
    pop af
    ld b, l
    ld h, c
    ld [hl], h
    ld b, d
    ld de, $4211
    and c
    ld [hl], c
    ld b, c
    pop af
    ld b, d
    sub c
    ld h, e
    ld [hl], c
    ld h, d
    ld b, e
    ld de, $4311
    pop af
    ld b, c
    pop de
    pop hl
    ld [hl], d
    ld d, c
    ld [hl], e
    ld h, c
    or c
    ld b, e
    ld de, $4211
    sub c
    ld [hl], c
    add c
    ld b, d
    and c
    ld h, c
    ld [hl], c
    or c
    ld b, a
    ld de, $4211
    ld h, c
    ld d, c
    ld [hl], c
    pop hl
    pop bc
    ld [c], a
    pop de
    ld c, b
    ld de, $2f31
    inc hl
    ld sp, $af00
    ld [$d078], a
    call Call_000_3e15
    call Call_000_03bf
    call Call_000_0188
    call Call_000_23ae
    call Call_000_36ca
    call Call_000_0ebd
    jp Jump_000_3e1d


Call_01c_5763:
    push af
    ld a, b
    ld [$cd51], a
    pop af
    ld de, $cee4
    call Call_01c_588d
    ld a, [de]
    push hl
    call Call_01c_57f4
    call Call_01c_5809
    pop hl
    ld de, $cd68

jr_01c_577b:
    ld a, [hl+]
    ld [de], a
    inc de
    cp $50
    jr nz, jr_01c_577b

    ld hl, $c300
    ld de, $c508
    ld bc, $00a0
    jp Jump_000_01bb


Call_01c_578e:
    ld b, $03
    ld hl, $6cd6
    call Call_000_3620
    call Call_01c_5875
    ld hl, $c300
    ld de, $cee4

jr_01c_579f:
    ld a, [de]
    cp $ff
    jr z, jr_01c_57bc

    and a
    jr z, jr_01c_57b9

    push hl
    call Call_01c_588d
    pop hl
    ld a, [de]
    cp $19
    jr z, jr_01c_57b9

    call Call_01c_57f4
    ld a, $04
    ld [hl+], a
    xor a
    ld [hl+], a

jr_01c_57b9:
    inc de
    jr jr_01c_579f

jr_01c_57bc:
    ld a, l
    and a
    jr nz, jr_01c_57d5

    ld hl, $c42d
    ld b, $02
    ld c, $0f
    call Call_000_03d2
    ld hl, $c442
    ld de, $57e9
    call Call_000_0405
    jr jr_01c_57dd

jr_01c_57d5:
    ld a, [$d2dd]
    ld b, $00
    call Call_01c_5763

jr_01c_57dd:
    ld hl, $c300
    ld de, $c508
    ld bc, $00a0
    jp Jump_000_01bb


    db $ed
    inc l
    or $43
    cp b
    pop bc
    ld a, a
    call z, $b2d2
    ld d, b

Call_01c_57f4:
    push af
    and $f0
    srl a
    add $18
    ld b, a
    ld [hl+], a
    pop af
    and $0f
    swap a
    srl a
    add $18
    ld c, a
    ld [hl+], a
    ret


Call_01c_5809:
    ld a, [$cd51]
    and a
    ld hl, $c390
    jr z, jr_01c_5815

    ld hl, $c380

Call_01c_5815:
jr_01c_5815:
    push hl
    ld hl, $fcfc
    add hl, bc
    ld b, h
    ld c, l
    pop hl

Call_01c_581d:
    ld de, $0202

jr_01c_5820:
    push de
    push bc

jr_01c_5822:
    ld a, b
    ld [hl+], a
    ld a, c
    ld [hl+], a
    ld a, [$cd51]
    ld [hl+], a
    inc a
    ld [$cd51], a
    xor a
    ld [hl+], a
    inc d
    ld a, $08
    add c
    ld c, a
    dec e
    jr nz, jr_01c_5822

    pop bc
    pop de
    ld a, $08
    add b
    ld b, a
    dec d
    jr nz, jr_01c_5820

    ret


Call_01c_5842:
    xor a
    ld [$cd52], a
    ld de, $0202

jr_01c_5849:
    push de
    push bc

jr_01c_584b:
    ld a, b
    ld [hl+], a
    ld a, c
    ld [hl+], a
    ld a, [$cd51]
    ld [hl+], a
    ld a, [$cd52]
    ld [hl+], a
    xor $20
    ld [$cd52], a
    inc d
    ld a, $08
    add c
    ld c, a
    dec e
    jr nz, jr_01c_584b

    pop bc
    pop de
    push hl
    ld hl, $cd51
    inc [hl]
    inc [hl]
    pop hl
    ld a, $08
    add b
    ld b, a
    dec d
    jr nz, jr_01c_5849

    ret


Call_01c_5875:
    ld de, $cee4

jr_01c_5878:
    ld a, [de]
    inc de
    cp $ff
    ret z

    ld c, a
    ld l, e
    ld h, d

jr_01c_5880:
    ld a, [hl]
    cp $ff
    jr z, jr_01c_5878

    cp c
    jr nz, jr_01c_588a

    xor a
    ld [hl], a

jr_01c_588a:
    inc hl
    jr jr_01c_5880

Call_01c_588d:
    cp $25
    jr c, jr_01c_58a0

    ld bc, $0004
    ld hl, $591e

jr_01c_5897:
    cp [hl]
    jr c, jr_01c_589d

    add hl, bc
    jr jr_01c_5897

jr_01c_589d:
    inc hl
    jr jr_01c_58a9

jr_01c_58a0:
    ld hl, $58af
    ld c, a
    ld b, $00
    add hl, bc
    add hl, bc
    add hl, bc

jr_01c_58a9:
    ld a, [hl+]
    ld [de], a
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ret


    or d
    rrca
    ld e, d
    add d
    inc de
    ld e, d
    ld [hl-], a
    rla
    ld e, d
    ld a, [hl+]
    ld a, [de]
    ld e, d
    ld e, [hl]
    ld e, $5a
    sbc d
    ld [hl+], a
    ld e, d
    ld d, a
    ld h, $5a
    ret c

    dec hl
    ld e, d
    ld a, [c]
    jr nc, jr_01c_5924

    jr nz, jr_01c_5900

    ld e, d
    ld e, d
    add hl, sp
    ld e, d
    nop
    rrca
    ld e, d
    and d
    ld a, $5a
    ld h, d
    ld b, l
    ld e, d
    inc [hl]
    ld c, h
    ld e, d
    jr z, jr_01c_5931

    ld e, d
    ld a, [hl-]
    ld e, d
    ld e, d
    adc d
    ld h, c
    ld e, d
    ld e, b
    ld l, b
    ld e, d
    ld e, l
    ld l, a
    ld e, d
    dec l
    db $76
    ld e, d
    ld c, [hl]
    ld a, l
    ld e, d
    sbc h
    add l
    ld e, d
    sbc [hl]
    adc l
    ld e, d
    cp l
    sub l
    ld e, d
    res 3, l
    ld e, d
    jp c, Jump_01c_5aa5

jr_01c_5900:
    ld d, l
    xor l
    ld e, d
    add h
    or l
    ld e, d
    sub $bd
    ld e, d
    or $c5
    ld e, d
    db $f4
    adc $5a
    jp nc, Jump_01c_5ad7

    add b
    ldh [$5a], a
    ld h, b
    add sp, $5a
    ld a, [de]
    ldh a, [$5a]
    dec bc
    ld hl, sp+$5a
    add hl, hl
    or d
    rrca
    ld e, d
    ld l, $82

jr_01c_5924:
    inc de
    ld e, d
    inc sp
    ld h, d
    ld b, l
    ld e, d
    inc [hl]
    ld b, d
    nop
    ld e, e
    dec sp
    ld [hl-], a
    rla

jr_01c_5931:
    ld e, d
    ld a, $26
    rlca
    ld e, e
    ld b, h
    ld a, [hl+]
    ld a, [de]
    ld e, d
    ld b, l
    dec h
    ld d, e
    ld e, d
    ld b, [hl]
    ld a, [hl+]
    ld a, [de]
    ld e, d
    ld c, c
    ld c, d
    ld e, d
    ld e, d
    ld c, h
    ld l, d
    ld h, c
    ld e, d
    ld c, a
    ld e, c
    ld l, b
    ld e, d
    ld d, c
    ld e, e
    ld l, a
    ld e, d
    ld d, e
    ld a, $0e
    ld e, e
    ld d, h
    ld c, a
    ld a, b
    ld e, e
    ld d, a
    sbc l
    add l
    ld e, d
    ld e, b
    ld a, [hl]
    adc l
    ld e, d
    ld e, c
    inc c
    rla
    ld e, e
    ld e, a
    sbc d
    ld [hl+], a
    ld e, d
    ld l, c
    xor c
    jr nz, jr_01c_59c9

    ld l, l
    ld b, b
    ld b, c
    ld e, e
    ld [hl], a
    jr nz, jr_01c_599e

    ld e, e
    ld a, b
    ld e, d
    jr nc, jr_01c_59d5

    ld a, c
    jr nz, jr_01c_59a6

    ld e, e
    ld a, d
    ld e, d
    jr nc, jr_01c_59dd

    adc l
    ld d, a
    ld h, $5a
    adc [hl]
    ld e, [hl]
    ld e, $5a
    sub l
    ld e, a
    ld [hl], $5b
    sbc b
    ld e, [hl]
    ld e, $5a
    sbc h
    ret c

    dec hl
    ld e, d
    sbc l
    ret z

    ld h, a
    ld e, e
    sbc a
    ret c

    dec hl
    ld e, d

jr_01c_599e:
    and e
    push af
    dec sp
    ld e, e
    and h
    sbc d
    ld [hl+], a
    ld e, d

jr_01c_59a6:
    and l
    ret c

    dec hl
    ld e, d
    and [hl]
    ld a, [c]
    ld h, d
    ld e, e
    xor [hl]
    ld a, [c]
    jr nc, jr_01c_5a0c

    xor a
    jr nz, jr_01c_59e9

    ld e, d
    cp b
    ld e, d
    add hl, sp
    ld e, d
    cp d
    reti


    and l
    ld e, d
    cp l
    ld d, h
    xor l
    ld e, d
    cp [hl]
    xor [hl]
    adc l
    ld e, d
    ret nz

    rst $10
    cp l

jr_01c_59c9:
    ld e, d
    pop bc
    push af
    dec sp
    ld e, e
    jp nz, $e070

    ld e, d
    jp $4140


jr_01c_59d5:
    ld e, e
    call nz, $8d7e
    ld e, d
    push bc
    sbc d
    ld [hl+], a

jr_01c_59dd:
    ld e, d
    add $43
    ld c, e
    ld e, e
    rst $00
    ld b, b
    ld b, c
    ld e, e
    rst $08
    ld d, a
    ld d, e

jr_01c_59e9:
    ld e, e
    sub $5a
    ld e, b
    ld e, e
    reti


    ld a, [c]
    ld h, d
    ld e, e
    ld [c], a
    ret z

    ld h, a
    ld e, e
    push hl
    add hl, de
    ld l, a
    ld e, e
    and $5e
    ld e, $5a
    rst $20
    ld a, [hl+]
    ld a, [de]
    ld e, d
    jp hl


    ld a, $0e
    ld e, e
    db $ed
    ld e, d
    ld e, b
    ld e, e
    ld hl, sp+$20

jr_01c_5a0c:
    add hl, hl
    ld e, e
    rst $38
    db $ed
    inc l
    ld a, [c]
    ld d, e
    db $ed
    inc l
    dec b
    ld d, h
    db $ec
    dec de
    ld e, e
    db $ed
    inc l
    ld h, e
    ld d, h
    db $ed
    inc l
    add hl, bc
    ld d, l
    db $ed
    inc l
    cp d
    ld d, h
    db $ed
    inc l
    ld sp, $5055
    db $ed
    inc l
    cp l
    ld d, l
    ld d, b
    db $ed
    inc l
    or $55
    db $ed
    inc l
    ld b, d
    ld d, [hl]
    ld d, b
    db $ed
    inc l
    ld b, [hl]
    ld d, l
    ld d, b
    db $ed
    inc l
    ld hl, sp+$53
    or e
    db $db
    ld d, b
    db $ed
    inc l
    rrca
    ld d, h
    or e
    db $db
    ld d, b
    db $ed
    inc l
    dec sp
    ld d, h
    or e
    db $db
    ld d, b
    db $ed
    inc l
    ld d, [hl]
    ld d, h
    or e
    db $db
    ld d, b
    db $ed
    inc l
    and b
    ld d, h
    or e
    db $db
    ld d, b
    db $ed
    inc l
    xor l
    ld d, h
    or e
    db $db
    ld d, b
    db $ed
    inc l
    inc h
    ld d, l
    or e
    db $db
    ld d, b
    db $ed
    inc l
    rla
    ld d, l
    or e
    db $db
    ld d, b
    db $ed
    inc l
    jp c, $b354

    db $db
    ld d, b
    db $ed
    inc l
    ei
    ld d, h
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    ld c, l
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    ld e, e
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    ld l, c
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    ld [hl], a
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b

Jump_01c_5aa5:
    db $ed
    inc l
    add l
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    sub e
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    and c
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    xor a
    ld d, l
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    call z, $bd55
    or d
    inc [hl]
    or e
    ld d, b
    db $ed
    inc l
    rst $20
    ld d, l
    cp l
    or d
    inc [hl]
    or e
    ld d, b

Jump_01c_5ad7:
    db $ed
    inc l
    rlca
    ld d, [hl]
    cp l
    or d
    inc [hl]
    or e
    ld d, b
    db $ed
    inc l
    ld d, $56
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    dec h
    ld d, [hl]
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    ld [hl], e
    ld d, h
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    add c
    ld d, h
    inc [hl]
    or e
    db $db
    ld d, b
    db $ed
    inc l
    inc e
    ld d, h
    db $d3
    ret c

    ld d, b
    db $ed
    inc l
    ld c, b
    ld d, h
    call nc, Call_01c_50cf
    db $ed
    inc l
    rst $20
    ld d, h
    sub e
    xor e
    sub a
    and [hl]
    ld d, b
    db $ed
    inc l
    adc a
    ld d, h
    rst $00
    jp nc, $d9c5

    ld d, b
    db $ed
    inc l
    jp z, $ab54

    sub [hl]
    ld a, [hl+]
    or e
    ld d, b
    ret c

    db $e3
    rlca
    adc $de
    inc a
    ld d, b
    pop bc
    or [hl]
    jp nz, $dbb3

    ld d, b
    db $ed
    inc l
    rrca
    ld d, l
    ld d, b
    db $ed
    inc l
    db $db
    ld d, l
    rst $08
    ld d, b
    db $ed
    inc l
    inc [hl]
    ld d, [hl]
    add h
    xor e
    xor b
    db $e3
    inc de
    ld d, b
    db $ed
    inc l
    inc l
    ld d, h
    ret


    or c
    push bc
    ld d, b
    ld e, [hl]
    add b
    dec bc
    sub e
    ld d, b
    adc e
    and [hl]
    sbc e
    adc $de
    cp h
    ldh [rNR30], a
    and [hl]
    ld d, b
    ld d, h
    call nc, $b7bc
    ld d, b
    db $ed
    inc l
    jp nz, $0e55

    db $e3
    xor e
    ld d, b
    push bc
    push bc
    cp h
    ret


    inc [hl]
    or e
    cp b
    jp nz, $ed50

    inc l
    ld c, c
    ld d, [hl]
    jp nz, $de33

    cp h
    ld [c], a
    ld d, b
    ld b, d
    ld h, [hl]
    rst $38
    cp l
    sbc c
    rst $38
    ld e, d
    inc h

Call_01c_5b8a:
    ld a, [$d068]
    inc a
    cp $19
    jr z, jr_01c_5ba5

    cp $32
    jr nz, jr_01c_5bb5

    ld hl, $c508
    ld de, $c300
    ld bc, $0090
    call Call_000_01bb
    xor a
    jr jr_01c_5bb5

jr_01c_5ba5:
    ld hl, $c300
    ld b, $24
    ld de, $0004

jr_01c_5bad:
    ld [hl], $a0
    add hl, de
    dec b
    jr nz, jr_01c_5bad

    ld a, $19

jr_01c_5bb5:
    ld [$d068], a
    jp Jump_000_0b31


    xor a
    ld [$cc26], a
    ld b, a
    inc a
    jr jr_01c_5bce

    ld hl, $cf19
    ld a, [$cc26]
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl]

jr_01c_5bce:
    ld c, a
    ld hl, $5c2d
    add hl, bc
    ld a, [$cf15]
    xor $01
    add [hl]
    ld c, a
    add a
    ld b, a
    ld a, [$d068]
    and a
    jr z, jr_01c_5bf0

    cp c
    jr z, jr_01c_5c01

jr_01c_5be5:
    inc a
    cp b
    jr nz, jr_01c_5bea

    xor a

jr_01c_5bea:
    ld [$d068], a
    jp Jump_000_0b31


jr_01c_5bf0:
    push bc
    ld hl, $cc5b
    ld de, $c300
    ld bc, $0060
    call Call_000_01bb
    pop bc
    xor a
    jr jr_01c_5be5

jr_01c_5c01:
    push bc
    ld hl, $c302
    ld bc, $0010
    ld a, [$cc26]
    call Call_000_3ad1
    ld c, $40
    ld a, [hl]
    cp $04
    jr z, jr_01c_5c19

    cp $08
    jr nz, jr_01c_5c1d

jr_01c_5c19:
    dec hl
    dec hl
    ld c, $01

jr_01c_5c1d:
    ld b, $04
    ld de, $0004

jr_01c_5c22:
    ld a, [hl]
    add c
    ld [hl], a
    add hl, de
    dec b
    jr nz, jr_01c_5c22

    pop bc
    ld a, c
    jr jr_01c_5be5

    dec b
    db $10
    jr nz, jr_01c_5c52

    add h
    ld e, h
    ld a, $1c

Call_01c_5c35:
    ld bc, $0000

jr_01c_5c38:
    push af
    push bc
    push hl
    add hl, bc
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
    call Call_000_02dd
    pop hl
    pop bc
    ld a, $06
    add c
    ld c, a
    pop af
    dec a

jr_01c_5c52:
    jr nz, jr_01c_5c38

    ret


    call Call_000_0167
    ld hl, $5c84
    ld a, $1c
    ld bc, $0000

jr_01c_5c60:
    push af
    push bc
    push hl
    add hl, bc
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    push de
    ld a, [hl+]
    ld c, a
    swap c
    ld b, $00
    ld a, [hl+]
    ld e, [hl]
    inc hl
    ld d, [hl]
    pop hl
    call Call_000_028c
    pop hl
    pop bc
    ld a, $06
    add c
    ld c, a
    pop af
    dec a
    jr nz, jr_01c_5c60

    jp Jump_000_0181


    ld b, b
    ld c, b
    inc b
    dec b
    nop
    add b
    db $ed
    ld [hl], e
    ld [$4004], sp
    add b
    add b
    ld [hl], c
    inc b
    dec b
    ret nz

    add b
    ld b, b
    ld c, [hl]
    inc b
    dec b
    nop
    add c
    ret nz

    db $76
    inc b
    dec b
    ld b, b
    add c
    ld e, l
    ld e, [hl]
    ld bc, $801c
    add c
    ld l, l
    ld e, [hl]
    ld bc, $a01c
    add c
    ld a, l
    ld e, [hl]
    ld bc, $c01c
    add c
    adc l
    ld e, [hl]
    ld bc, $e01c
    add c
    sbc l
    ld e, [hl]
    ld bc, $001c
    add d
    xor l
    ld e, [hl]
    ld bc, $201c
    add d
    cp l
    ld e, [hl]
    ld bc, $401c
    add d
    call $015e
    inc e
    ld h, b
    add d
    dec e
    ld e, a
    inc b
    inc e
    add b
    add e
    add b
    ld b, a
    inc b
    dec b
    nop
    add h
    db $ed
    ld [hl], e
    ld [$4004], sp
    add h
    ret nz

    ld [hl], b
    inc b
    dec b
    ret nz

    add h
    add b
    ld c, l
    inc b
    dec b
    nop
    add l
    add b
    ld [hl], a
    inc b
    dec b
    ld b, b
    add l
    dec e
    ld e, [hl]
    ld bc, $801c
    add l
    dec l
    ld e, [hl]
    ld bc, $a01c
    add l
    dec a
    ld e, [hl]
    ld bc, $c01c
    add l
    ld c, l
    ld e, [hl]
    ld bc, $e01c
    add l
    db $dd
    ld e, [hl]
    ld bc, $001c
    add [hl]
    db $ed
    ld e, [hl]
    ld bc, $201c
    add [hl]
    db $fd
    ld e, [hl]
    ld bc, $401c
    add [hl]
    dec c
    ld e, a
    ld bc, $601c
    add [hl]
    ld e, l
    ld e, a
    inc b
    inc e
    add b
    add a
    push hl
    push de
    push bc
    ldh a, [$8c]
    ld hl, $d124
    ld e, a
    ld d, $00
    add hl, de
    ld a, [hl]
    call Call_01c_5dad
    ld [$cd51], a
    call Call_01c_5d87
    pop bc
    pop de
    pop hl
    ret


jr_01c_5d46:
    xor a
    ldh [$8c], a
    ld a, [$cd58]
    call Call_01c_5dad
    ld [$cd51], a
    jr jr_01c_5d87

    ld a, [$cf78]
    call Call_01c_5dad
    push af
    ld hl, $8000
    call Call_01c_5d70
    pop af
    add $54
    ld hl, $8040
    call Call_01c_5d70
    xor a
    ld [$cd58], a
    jr jr_01c_5d46

Call_01c_5d70:
    push hl
    add a
    ld c, a
    ld b, $00
    ld hl, $5c84
    add hl, bc
    add hl, bc
    add hl, bc
    ld a, [hl+]
    ld e, a
    ld a, [hl+]
    ld d, a
    ld a, [hl+]
    ld c, a
    ld a, [hl+]
    ld b, a
    pop hl
    jp Jump_000_02dd


Call_01c_5d87:
jr_01c_5d87:
    push af
    ld c, $10
    ld h, $c3
    ldh a, [$8c]
    swap a
    ld l, a
    add $10
    ld b, a
    pop af
    cp $08
    jr z, jr_01c_5d9e

    call Call_01c_5842
    jr jr_01c_5da1

jr_01c_5d9e:
    call Call_01c_581d

jr_01c_5da1:
    ld hl, $c300
    ld de, $cc5b
    ld bc, $0060
    jp Jump_000_01bb


Call_01c_5dad:
    ld [$d0e3], a
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    ld c, a
    dec a
    srl a
    ld hl, $5dd1
    ld e, a
    ld d, $00
    add hl, de
    ld a, [hl]
    bit 0, c
    jr nz, jr_01c_5dca

    swap a

jr_01c_5dca:
    and $f0
    srl a
    srl a
    ret


    ld [hl], a
    ld [hl], b
    nop
    ld d, l
    ld d, [hl]
    ld h, [hl]
    ld h, [hl]
    ld h, h
    ld b, h
    sbc c
    ld b, h
    adc b
    inc sp
    nop
    nop
    nop
    nop
    inc sp
    sbc c
    inc sp
    nop
    ld [hl], a
    db $76
    ld h, [hl]
    ld h, b
    nop
    nop
    nop
    add hl, bc
    sub b
    nop
    nop
    nop
    nop
    ld [hl], a
    ld [hl], l
    ld d, b
    nop
    sbc c
    sub b
    ld de, $4544
    ld d, b
    ld [bc], a
    jr nz, jr_01c_5e00

jr_01c_5e00:
    add b
    dec b
    ld d, c
    rla
    ld [hl], b
    nop
    nop
    nop
    sub b
    scf
    dec b
    ld d, l
    ld d, d
    jr nz, jr_01c_5e6f

    nop
    ld l, c
    ld e, b
    ld d, b
    sbc c
    sbc c
    ld [bc], a
    ld [hl+], a
    inc h
    inc b
    ld b, h
    adc b
    add b
    nop
    nop
    nop
    inc c
    inc c
    ld [bc], a
    ld [bc], a
    inc bc
    inc bc
    rrca
    inc c
    inc de
    ld e, $73
    ld a, [hl]
    rst $08
    call z, Call_000_1d17
    ld [hl], e
    ld a, a
    jr @+$21

    rla
    rra
    jr z, @+$31

    ld b, [hl]
    ld b, a
    ld b, c
    ld b, c
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    inc b
    rlca
    jr c, jr_01c_5e86

    ld e, h
    ld h, a
    sbc a
    db $e3
    sbc a
    push hl
    adc h
    di
    ld a, b
    ld a, a
    ld [$740f], sp
    ld [hl], a
    ei
    adc e
    ld a, l
    ld b, l
    ccf
    inc sp
    ld c, $0e
    nop
    nop
    nop
    nop
    inc c
    inc c
    ld [bc], a
    ld [bc], a
    jp Jump_01c_6fc3


    ld l, h
    inc sp
    ld a, $13
    ld e, $1f
    inc e

jr_01c_5e6f:
    ld [hl], a
    ld a, l
    dec de
    rra
    rla
    rra
    jr z, @+$31

    ld b, [hl]
    ld b, a
    ld b, c
    ld b, c
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    inc b
    rlca
    jr c, jr_01c_5ec4

    ld b, h

jr_01c_5e86:
    ld a, a
    ld e, d
    ld h, a
    ld e, a
    ld h, e
    ld e, a
    ld h, l
    inc h
    dec sp
    jr jr_01c_5eb0

    ld [$770f], sp
    ld [hl], a
    ld sp, hl
    adc c
    ld a, l
    ld b, l
    ccf
    inc sp
    ld c, $0e
    nop
    nop
    ld bc, $0201
    inc bc
    rlca
    rlca
    ld [$1c0f], sp
    inc de
    ld e, $15
    ld c, $09
    inc b
    rlca
    ld a, [bc]

jr_01c_5eb0:
    rrca
    dec bc
    dec c
    inc de
    inc e
    inc d
    dec de
    rrca
    ld [$0407], sp
    inc bc
    inc bc
    nop
    nop
    inc bc
    inc bc
    inc e
    rra
    ccf

jr_01c_5ec4:
    daa
    inc e
    inc de
    jr z, jr_01c_5f08

    ld l, $39
    ld l, $3b
    jr z, @+$41

    inc h
    ccf
    daa
    dec a
    ld [hl+], a
    ccf
    ld de, $121f
    ld e, $1e
    ld [de], a
    inc c
    inc c
    nop
    nop
    nop
    nop
    ld bc, $0201
    inc bc
    rlca
    rlca
    ld [$1c0f], sp
    inc de
    ld e, $15
    ld c, $09
    inc b
    rlca
    ld a, [bc]
    rrca
    rla
    add hl, de
    inc de
    inc e
    inc d
    dec de
    rrca
    ld [$0707], sp
    nop
    nop
    inc bc
    inc bc
    inc c
    rrca
    jr jr_01c_5f24

    ccf
    daa
    inc a

jr_01c_5f08:
    inc sp
    jr z, jr_01c_5f4a

    ld l, $39
    ld l, $3b
    jr z, jr_01c_5f50

    inc h
    ccf
    daa
    dec a
    inc de
    rra
    ld [de], a
    ld e, $1e
    ld [de], a
    inc c
    inc c
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_5f24:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0001
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc bc
    inc bc
    inc e
    rra
    ld h, e
    ld a, a
    sbc a
    db $fc
    ld [bc], a
    inc bc
    dec b
    rlca
    dec bc
    ld c, $17
    inc e
    cpl
    jr c, jr_01c_5f77

    jr c, @+$61

jr_01c_5f4a:
    ld [hl], b
    ld e, a
    ld [hl], b
    ld a, a
    ldh [rIE], a

jr_01c_5f50:
    add b
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld bc, $0201
    inc bc
    nop
    nop
    nop
    nop
    rlca
    rlca
    jr jr_01c_5f94

    ld h, a
    ld a, a

jr_01c_5f77:
    sbc a
    ld hl, sp+$7f
    ldh [rIE], a
    add b
    dec b
    rlca
    dec bc
    ld c, $0b
    ld c, $17
    inc e
    rla
    inc e
    cpl
    jr c, @+$31

    jr c, jr_01c_5fbb

    jr c, @+$01

    nop
    rst $38
    nop
    rst $38
    nop
    rst $38

jr_01c_5f94:
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    call Call_000_373e
    ld hl, $6043
    ld a, [$cd3d]
    swap a
    srl a
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [hl+]
    ld [$cd0f], a
    ld a, [hl+]
    ld [$cd25], a
    ld a, [hl+]
    push af
    ld de, $cd1f

jr_01c_5fbb:
    ld bc, $0006
    call Call_000_01bb
    ld a, $50
    ld [$cd24], a
    pop af
    ld l, a
    ld h, $00
    ld de, $61de
    add hl, hl
    add hl, de
    ld a, [hl+]
    ld [$cd10], a
    ld a, [hl]
    ld [$cd11], a
    ld a, [$cd0f]
    ld de, $cd13
    call Call_01c_6032
    ld a, [$cd25]
    ld de, $cd19
    call Call_01c_6032
    ld hl, $d6b6
    ld a, [$cd3d]
    ld c, a
    ld b, $02
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    ld a, $04
    ld [$cd12], a
    jr nz, jr_01c_6020

    xor a
    ld [$cd12], a
    call Call_01c_6020
    ld a, $01
    ld [$cd12], a
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_01c_6020

    call Call_01c_6093
    jr c, jr_01c_6020

    ld hl, $6214
    call Call_000_3c79

Call_01c_6020:
jr_01c_6020:
    ld hl, $cd12
    ld a, [hl-]
    ld e, a
    ld d, $00
    ld a, [hl-]
    ld l, [hl]
    ld h, a
    add hl, de
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    jp Jump_000_3c79


Call_01c_6032:
    push de
    ld [$d0e3], a
    call Call_000_1aab
    ld hl, $cd68
    pop de
    ld bc, $0006
    jp Jump_000_01bb


    and a
    xor b
    nop
    sub d
    ret c

    db $e3
    ld d, b
    ld d, b
    sub h
    ld a, [hl+]
    nop
    add hl, de
    ret c

    add hl, de
    ret c

    ld d, b
    ld a, l
    ld [hl], d
    ld [bc], a
    ld b, c
    ld b, c
    sbc $50
    ld d, b
    and e
    ld a, [hl-]
    nop
    ld b, b
    add d
    db $e3
    xor e
    ld d, b
    dec b
    ld b, b
    ld bc, $bcb5
    ld [c], a
    or e
    ld d, b
    ld [$010b], sp
    push bc
    jp nc, $b32f

    ld d, b
    ld l, [hl]
    ld c, b
    ld bc, $bbcf
    cp d
    ld d, b
    ld d, b
    ld d, l
    adc l
    ld bc, $9db5
    and [hl]
    ld d, b
    ld d, b
    ld b, c
    ld e, $02
    ret c

    xor e
    rrca
    ld d, b
    ld d, b
    rrca
    inc bc
    ld [bc], a
    sub b
    xor l
    xor h
    ld b, c
    db $e3

Call_01c_6093:
    xor a
    ld [$d05a], a
    dec a
    ld [$cfb2], a
    call Call_000_2df3
    push af
    call Call_01c_6125
    pop af
    ld a, $01
    jr c, jr_01c_6120

    ld a, [$cd0f]
    ld b, a
    ld a, [$cf78]
    cp b
    ld a, $02
    jr nz, jr_01c_6120

    ld a, [$cf79]
    ld hl, $d14c
    ld bc, $002c
    call Call_000_3ad1
    ld a, [hl]
    ld [$d0ec], a
    ld hl, $d6b6
    ld a, [$cd3d]
    ld c, a
    ld b, $01
    ld a, $10
    call Call_000_3e9d
    ld hl, $6202
    call Call_000_3c79
    ld a, [$cf79]
    push af
    ld a, [$d0ec]
    push af
    call Call_000_370a
    call Call_01c_6144
    ld a, $38
    call Call_000_3e9d
    call Call_000_03bf
    pop af
    ld [$d0ec], a
    pop af
    ld [$cf79], a
    ld a, [$cd25]
    ld [$cf78], a
    xor a
    ld [$cc49], a
    ld [$cf7c], a
    call Call_000_3969
    ld a, $80
    ld [$cc49], a
    call Call_000_3971
    call Call_01c_6125
    ld b, $03
    ld hl, $71e7
    call Call_000_3620
    call Call_01c_619c
    and a
    ld a, $03
    jr jr_01c_6121

jr_01c_6120:
    scf

jr_01c_6121:
    ld [$cd12], a
    ret


Call_01c_6125:
    call Call_000_3e04
    call Call_000_3dee
    call Call_000_1ba5
    call Call_000_374a
    call Call_000_3e07
    call Call_000_0b3c
    ld c, $0a
    call Call_000_3781
    ld b, $03
    ld hl, $4f2e
    jp Jump_000_3620


Call_01c_6144:
    ld hl, $cd3d
    ld a, [$cd0f]
    ld [hl+], a
    ld a, [$cd25]
    ld [hl], a
    ld hl, $d233
    ld bc, $0006
    ld a, [$cf79]
    call Call_000_3ad1
    ld de, $cd41
    ld bc, $0006
    call Call_01c_6194
    ld hl, $61dc
    ld de, $cd49
    call Call_01c_6194
    ld de, $d806
    call Call_01c_6194
    ld hl, $d137
    ld bc, $002c
    ld a, [$cf79]
    call Call_000_3ad1
    ld de, $cd47
    ld bc, $0002
    call Call_01c_6194
    call Call_000_3e8c
    ld hl, $ffd3
    ld de, $cd4f
    jp Jump_000_01bb


Call_01c_6194:
    push hl
    push bc
    call Call_000_01bb
    pop bc
    pop hl
    ret


Call_01c_619c:
    ld hl, $d257
    ld bc, $0006
    call Call_01c_61d2
    ld hl, $cd1f
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d233
    ld bc, $0006
    call Call_01c_61d2
    ld hl, $61dc
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d137
    ld bc, $002c
    call Call_01c_61d2
    ld hl, $cd4f
    ld bc, $0002
    jp Jump_000_01bb


Call_01c_61d2:
    ld a, [$d123]
    dec a
    call Call_000_3ad1
    ld e, l
    ld d, h
    ret


    ld e, l
    ld d, b
    db $e4
    ld h, c
    xor $61
    ld hl, sp+$61
    ld sp, $5e62
    ld h, d
    ld l, h
    ld h, d
    sbc c
    ld h, d
    and b
    ld h, d
    or l
    ld h, d
    ldh [$62], a
    pop af
    ld h, d
    dec de
    ld h, e
    ld [hl+], a
    ld h, e
    ld a, [hl-]
    ld h, e
    ld h, l
    ld h, e
    ld [hl], e
    ld h, e
    sbc l
    ld h, e
    and h
    ld h, e
    db $ed
    dec hl
    cp d
    ld h, c
    ld c, a
    adc b
    db $e3
    dec de
    and [hl]
    db $dd
    ld a, a
    jp nz, $b2c5

    inc sp
    ld d, [hl]
    call nz, $ed58
    dec hl
    sub b
    ld h, c
    ld d, b
    ld bc, $cd13
    nop
    call nz, Call_01c_504f
    ld bc, $cd19
    nop
    db $dd
    ld a, a
    cp d
    or e
    or [hl]
    sbc $bc
    ret nz

    rst $20
    ld d, b
    ld de, $500a
    db $ed
    inc l
    daa
    ld a, c
    ld d, b
    ld bc, $cd13
    nop
    ld a, a
    cp e
    ld h, $bc
    jp $ded9


    jr nc, @-$17

    ld d, c
    or a
    ret nc

    ld a, a
    db $d3
    rst $18
    jp $d7c0


    ld a, a
    ld d, b
    ld bc, $cd19
    nop
    call nz, $ba4f
    or e
    or [hl]
    sbc $bc
    sub $b3
    ld l, $e6
    ld d, a
    db $ed
    inc l
    xor h
    ld a, c
    db $e3
    ld c, a
    ld d, [hl]
    rst $08
    rst $18
    ld a, a
    or d
    rst $18
    or [hl]
    ld d, a
    db $ed
    inc l
    ld [hl], e
    ld a, c
    jr nc, @+$51

    ld d, b
    ld bc, $cd13
    nop
    inc l
    ldh [$7f], a
    push bc
    or d
    inc l
    ldh [$de], a
    ld d, c
    db $d3
    cp h
    ld a, a
    jp nz, $cfb6

    or h
    ret nz

    rst $10
    ld c, a
    rst $08
    rst $18
    cp e
    or a

jr_01c_628e:
    add $7f
    cp d
    cp d
    call $ba7f
    or d
    sub $e7
    ld d, a
    nop
    adc d
    xor e
    add [hl]
    xor [hl]
    db $e3
    ld d, a
    nop
    or l
    jp c, $7fc9

    call nc, $c0df
    ld c, a
    ld d, b
    ld bc, $cd19
    nop
    ld a, a
    add c
    add c
    jr nc, jr_01c_628e

    and $57
    db $ed
    inc l
    sub e
    ld a, b
    jp c, $b74f

    ret nc

    ld a, a
    ld d, b
    ld bc, $cd13
    nop
    ld a, a
    db $d3
    rst $18
    call nz, $e6d9
    ld d, c
    call c, $c9bc
    ld a, a
    ld d, b
    ld bc, $cd19
    nop
    call nz, $ba4f
    or e
    or [hl]
    sbc $7f
    cp h
    push bc
    or d
    or [hl]
    and $57
    db $ed
    inc l
    call nc, $9f79
    ret c

    add $7f
    call nz, $7fca
    or d
    call c, $26de
    ld d, [hl]
    ld d, a
    db $ed
    inc l
    ret c

    ld a, b
    ld c, a
    ld d, b
    ld bc, $cd13
    nop
    inc sp
    jp z, $c57f

    or d
    inc l
    ldh [$c5], a
    or d
    or [hl]
    ld d, c
    jp Jump_01c_7fc6


    or d
    jp c, $7fc0

    call nz, $cab7
    ld c, a
    sub $db
    cp h
    cp b
    ld a, a
    ret nz

    ret


    pop de
    sub $57
    nop
    or c
    ret c

    ld h, $c4
    sub $57
    nop
    cp d
    or e
    or [hl]
    sbc $bc
    ret nz

    ld a, a
    ld d, b
    ld bc, $cd19
    nop
    ld c, a
    jp nz, $b8d6

    push bc
    rst $18
    ret nz

    or [hl]
    or d
    and $57
    db $ed
    inc l
    ld c, a
    ld a, b
    or a
    ret nc

    ld c, a
    ld d, b
    ld bc, $cd13
    nop
    ld a, a
    db $d3
    rst $18
    jp $e6d9


    ld d, c
    call c, $bcc0
    ret


    ld a, a
    ld d, b
    ld bc, $cd19
    nop
    call nz, $c44f
    ret c

    or [hl]
    or h
    jp $b87f


    jp c, $b2c5

    and $57
    db $ed
    dec l
    ld b, c
    ld e, b
    rst $10
    ld a, a
    cp h
    ld [c], a
    db $e3
    ld h, $c5
    or d
    push bc
    ld d, a
    db $ed
    dec l
    call nc, $da5a
    ld c, a
    ld d, b
    ld bc, $cd13
    nop
    inc l
    ldh [$7f], a
    push bc
    or d
    call c, Call_01c_51e3
    jp Jump_01c_7fc6


    or d
    jp c, $d7c0

    ld c, a
    ld l, $df
    ret nz

    or d
    ld a, a
    call nz, $b6d8
    or h
    jp $c8d6


    rst $18
    rst $20
    ld d, a
    nop
    or c
    ret c

    ld h, $c4
    ret z

    ld d, a
    ld bc, $cd19
    nop
    ld a, a
    add hl, hl
    sbc $b7
    and $4f
    call c, $bcc0
    ret


    ld a, a
    ld d, b
    ld bc, $cd13
    nop
    jp z, Jump_000_297f

    sbc $b7
    sub $57
    call Call_000_3ec4
    ld a, b
    cp $ff
    jr nz, jr_01c_63ca

    ld a, [$cf16]

jr_01c_63ca:
    cp $fc
    jp z, Jump_01c_65a2

    ld l, a
    ld h, $00
    add hl, hl
    ld de, $6553
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld de, $6720
    push de
    jp hl


    ld hl, $689e
    ld de, $674e
    ret


    ld hl, $687e
    ld de, $cf27
    ld bc, $0010
    call Call_000_01bb
    ld a, [$d041]
    ld hl, $cffb
    call Call_01c_6577
    ld b, a
    ld a, [$d046]
    ld hl, $cfbf
    call Call_01c_6577
    ld c, a
    ld hl, $cf28
    ld a, [$cf17]
    add $1f
    ld [hl+], a
    inc hl
    ld a, [$cf18]
    add $1f
    ld [hl+], a
    inc hl
    ld a, b
    ld [hl+], a
    inc hl
    ld a, c
    ld [hl], a
    ld hl, $cf27
    ld de, $674e
    ld a, $01
    ld [$cf16], a
    ret


    ld hl, $68ae
    ld de, $673e
    ret


    ld hl, $687e
    ld de, $cf27
    ld bc, $0010
    call Call_000_01bb
    ld a, [$cf78]
    cp $bf
    jr c, jr_01c_6444

    ld a, $01

jr_01c_6444:
    call Call_01c_657d
    push af
    ld hl, $cf28
    ld a, [$cf1f]
    add $1f
    ld [hl+], a
    inc hl
    pop af
    ld [hl], a
    ld hl, $cf27
    ld de, $676e
    ret


    ld hl, $688e
    ld de, $cf28
    ret


    ld hl, $68be
    ld de, $cf27
    ld bc, $0010
    call Call_000_01bb
    ld a, [$cf78]
    call Call_01c_657d
    ld hl, $cf2a
    ld [hl], a
    ld hl, $cf27
    ld de, $677e
    ret


    ld hl, $68ce
    ld de, $678e
    ret


    ld hl, $68de
    ld de, $67ae
    ret


    ld hl, $68fe
    ld de, $673e
    ret


    ld hl, $690e
    ld de, $67ce
    ret


    ld hl, $691e
    ld de, $685e
    ld a, $08
    ld [$cf16], a
    ret


    ld hl, $687e
    ld de, $cf27
    ld bc, $0010
    call Call_000_01bb
    ld a, [$d2e6]
    cp $0f
    jr z, jr_01c_64ec

    cp $11
    jr z, jr_01c_64f0

    ld a, [$d2dd]
    cp $25
    jr c, jr_01c_64d8

    cp $e2
    jr c, jr_01c_64d5

    cp $e5
    jr c, jr_01c_64f0

    cp $f5
    jr z, jr_01c_64f4

    cp $f6
    jr z, jr_01c_64f0

jr_01c_64d5:
    ld a, [$d2e4]

jr_01c_64d8:
    cp $0b
    jr c, jr_01c_64de

    ld a, $ff

jr_01c_64de:
    inc a
    ld hl, $cf28
    ld [hl-], a
    ld de, $673e
    ld a, $09
    ld [$cf16], a
    ret


jr_01c_64ec:
    ld a, $18
    jr jr_01c_64de

jr_01c_64f0:
    ld a, $22
    jr jr_01c_64de

jr_01c_64f4:
    xor a
    jr jr_01c_64de

    push bc
    ld hl, $687e
    ld de, $cf27
    ld bc, $0010
    call Call_000_01bb
    pop bc
    ld a, c
    and a
    ld a, $1e
    jr nz, jr_01c_6511

    ld a, [$cf17]
    call Call_01c_657d

jr_01c_6511:
    ld [$cf28], a
    ld hl, $cf27
    ld de, $673e
    ret


    ld hl, $681e
    ld de, $cc5b
    ld bc, $0040
    call Call_000_01bb
    ld de, $656f
    ld hl, $cc5d
    ld a, [$d2d5]
    ld c, $08

jr_01c_6532:
    srl a
    push af
    jr c, jr_01c_6542

    push bc
    ld a, [de]
    ld c, a
    xor a

jr_01c_653b:
    ld [hl+], a
    dec c
    jr nz, jr_01c_653b

    pop bc
    jr jr_01c_6547

jr_01c_6542:
    ld a, [de]

jr_01c_6543:
    inc hl
    dec a
    jr nz, jr_01c_6543

jr_01c_6547:
    pop af
    inc de
    dec c
    jr nz, jr_01c_6532

    ld hl, $68ee
    ld de, $cc5b
    ret


    rst $18
    ld h, e
    and $63
    jr z, @+$66

    cpl
    ld h, h
    ld h, d
    ld h, h
    ld a, a
    ld h, h
    add [hl]
    ld h, h
    sub h
    ld h, h
    adc l
    ld h, h
    and a
    ld h, h
    ld e, e
    ld h, h
    rst $30
    ld h, h
    sbc e
    ld h, h
    dec de
    ld h, l
    ld b, $06
    ld b, $12
    ld b, $06
    ld b, $06

Call_01c_6577:
    bit 3, a
    ld a, $19
    ret nz

    ld a, [hl]

Call_01c_657d:
    ld [$d0e3], a
    and a
    jr z, jr_01c_658d

    push bc
    ld a, $3a
    call Call_000_3e9d
    pop bc
    ld a, [$d0e3]

jr_01c_658d:
    ld e, a
    ld d, $00
    ld hl, $6a1e
    add hl, de
    ld a, [hl]
    ret


    ld hl, $67ee
    ld de, $cf28
    ld bc, $0030
    jp Jump_000_01bb


Jump_01c_65a2:
    ld hl, $cf19
    ld a, [$cf27]
    ld e, a
    ld d, $00
    add hl, de
    ld e, l
    ld d, h
    ld a, [de]
    and a
    ld e, $05
    jr z, jr_01c_65bb

    dec a
    ld e, $0a
    jr z, jr_01c_65bb

    ld e, $0f

jr_01c_65bb:
    push de
    ld hl, $cf31
    ld bc, $0006
    ld a, [$cf27]
    call Call_000_3ad1
    pop de
    ld [hl], e
    ret


Call_01c_65cb:
Jump_01c_65cb:
    ld a, [hl]
    and $07
    ret z

    ld b, a

jr_01c_65d0:
    push bc
    xor a
    ldh [rP1], a
    ld a, $30
    ldh [rP1], a
    ld b, $10

jr_01c_65da:
    ld e, $08
    ld a, [hl+]
    ld d, a

jr_01c_65de:
    bit 0, d
    ld a, $10
    jr nz, jr_01c_65e6

    ld a, $20

jr_01c_65e6:
    ldh [rP1], a
    ld a, $30
    ldh [rP1], a
    rr d
    dec e
    jr nz, jr_01c_65de

    dec b
    jr nz, jr_01c_65da

    ld a, $20
    ldh [rP1], a
    ld a, $30
    ldh [rP1], a
    call Call_01c_6714
    pop bc
    dec b
    ret z

    jr jr_01c_65d0

    xor a
    ld [$cf15], a
    call Call_01c_666b
    ret nc

    ld a, $01
    ld [$cf15], a
    call Call_01c_6645
    ld a, $01
    ld [$cf27], a
    ld de, $695e
    ld hl, $743e
    call Call_01c_66d5
    xor a
    ld [$cf27], a
    ld de, $696e
    ld hl, $6bde
    call Call_01c_66d5
    xor a
    ld [$cf27], a
    ld de, $692e
    ld hl, $6ab6
    call Call_01c_66d5
    call Call_000_0a8c
    ld hl, $698e
    jp Jump_01c_65cb


Call_01c_6645:
    ld hl, $6659
    ld c, $09

jr_01c_664a:
    push bc
    ld a, [hl+]
    push hl
    ld h, [hl]
    ld l, a
    call Call_01c_65cb
    pop hl
    inc hl
    pop bc
    dec c
    jr nz, jr_01c_664a

    ret


    ld a, [hl]
    ld l, c
    sbc [hl]
    ld l, c
    xor [hl]
    ld l, c
    cp [hl]
    ld l, c
    adc $69
    sbc $69
    xor $69
    cp $69
    ld c, $6a

Call_01c_666b:
    ld hl, $694e
    call Call_01c_65cb
    call Call_01c_6714
    ldh a, [rP1]
    and $03
    cp $03
    jr nz, jr_01c_66c7

    ld a, $20
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    call Call_01c_6714
    call Call_01c_6714
    ld a, $30
    ldh [rP1], a
    call Call_01c_6714
    call Call_01c_6714
    ld a, $10
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    call Call_01c_6714
    call Call_01c_6714
    ld a, $30
    ldh [rP1], a
    ldh a, [rP1]
    ldh a, [rP1]
    ldh a, [rP1]
    call Call_01c_6714
    call Call_01c_6714
    ldh a, [rP1]
    and $03
    cp $03
    jr nz, jr_01c_66c7

    call Call_01c_66cc
    and a
    ret


jr_01c_66c7:
    call Call_01c_66cc
    scf
    ret


Call_01c_66cc:
    ld hl, $693e
    call Call_01c_65cb
    jp Jump_01c_6714


Call_01c_66d5:
    di
    push de
    call Call_000_0167
    ld a, $e4
    ldh [rBGP], a
    ld de, $8800
    ld a, [$cf27]
    and a
    jr z, jr_01c_66ec

    call Call_01c_6728
    jr jr_01c_66f2

jr_01c_66ec:
    ld bc, $1000
    call Call_000_01bb

jr_01c_66f2:
    ld hl, $9800
    ld de, $000c
    ld a, $80
    ld c, $0d

jr_01c_66fc:
    ld b, $14

jr_01c_66fe:
    ld [hl+], a
    inc a
    dec b
    jr nz, jr_01c_66fe

    add hl, de
    dec c
    jr nz, jr_01c_66fc

    ld a, $e3
    ldh [rLCDC], a
    pop hl
    call Call_01c_65cb
    xor a
    ldh [rBGP], a
    ei
    ret


Call_01c_6714:
Jump_01c_6714:
    ld de, $1b58

jr_01c_6717:
    nop
    nop
    nop
    dec de
    ld a, d
    or e
    jr nz, jr_01c_6717

    ret


    push de
    call Call_01c_65cb
    pop hl
    jp Jump_01c_65cb


Call_01c_6728:
    ld b, $80

jr_01c_672a:
    ld c, $10

jr_01c_672c:
    ld a, [hl+]
    ld [de], a
    inc de
    dec c
    jr nz, jr_01c_672c

    ld c, $10
    xor a

jr_01c_6735:
    ld [de], a
    inc de
    dec c
    jr nz, jr_01c_6735

    dec b
    jr nz, jr_01c_672a

    ret


    ld hl, $0301
    nop
    nop
    nop
    inc de
    ld de, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    ld [hl+], a
    dec b
    rlca
    ld a, [bc]
    nop
    inc c
    inc de
    ld de, $0503
    ld bc, $0a00
    inc bc
    inc bc
    nop
    ld a, [bc]
    ld [$0a13], sp
    inc bc
    ld a, [bc]
    nop
    inc b
    ld [$030b], sp
    rrca
    dec bc
    nop
    inc de
    rlca
    ld hl, $0701
    dec b
    ld bc, $0700
    ld b, $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld hl, $0701
    dec b
    ld bc, $0801
    ld [$0000], sp
    nop
    nop
    nop
    nop
    nop
    nop
    ld [hl+], a
    dec b
    inc bc
    dec b
    nop
    nop
    inc de
    dec bc
    inc bc
    ld a, [bc]
    nop
    inc b
    inc de
    add hl, bc
    ld [bc], a
    rrca
    nop
    ld b, $13
    rlca
    inc bc
    nop
    inc b
    inc b
    rrca
    add hl, bc
    inc bc
    nop
    nop
    inc c
    inc de
    ld de, $0322
    inc bc
    nop
    nop
    nop
    inc de
    rlca
    ld [bc], a
    dec b
    nop
    ld [$0913], sp
    inc bc
    ld a, [bc]
    nop
    ld a, [bc]
    inc de
    ld de, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld [hl+], a
    inc bc
    inc bc
    dec b
    nop
    nop
    inc de
    inc bc
    inc bc
    nop
    nop
    inc b
    inc de
    dec c
    inc bc
    dec b
    nop
    ld c, $13
    ld de, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    inc hl
    rlca
    ld b, $10
    ld bc, $0200
    inc c
    ld [bc], a
    nop
    inc c
    nop
    ld [de], a
    ld bc, $0002
    inc c
    ld [bc], a
    ld [de], a
    inc bc
    ld [bc], a
    nop
    inc c
    inc b
    ld [de], a
    dec b
    ld [bc], a
    nop
    inc c
    ld b, $12
    rlca
    ld [bc], a
    nop
    inc c
    ld [$0912], sp
    ld [bc], a
    nop
    inc c
    ld a, [bc]
    ld [de], a
    dec bc
    nop
    nop
    nop
    nop
    inc h
    ld a, [bc]
    ld [bc], a
    nop
    inc bc
    inc c
    inc b
    dec c
    ld [bc], a
    dec b
    rlca
    inc c
    ld [$020d], sp
    rrca
    dec bc
    inc c
    inc c
    dec c
    ld [bc], a
    ld a, [bc]
    db $10
    dec bc
    ld de, $020c
    dec b
    ld c, $0d
    rrca
    ld c, $02
    rrca
    db $10
    dec c
    ld de, $020e
    ld a, [bc]
    inc bc
    rrca
    inc b
    db $10
    ld [bc], a
    rrca
    rlca
    rrca
    ld [$0210], sp
    ld a, [bc]
    dec bc
    rrca
    inc c
    db $10
    ld [bc], a
    dec b
    rrca
    rrca
    db $10
    stop
    nop
    ld [hl+], a
    inc bc
    rlca
    dec b
    dec b
    dec bc
    rlca
    dec c
    ld [bc], a
    ld a, [bc]
    ld [$090b], sp
    dec c
    inc bc
    rrca
    inc c
    dec bc
    ld c, $0d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    stop
    rra
    nop
    jr nz, jr_01c_6895

jr_01c_6895:
    ld hl, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    ld e, $00
    ld e, $00
    ld e, $00
    ld e, $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    inc c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    dec d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    ld a, [de]
    nop
    dec de
    nop
    inc e
    nop
    dec e
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    ld c, $00
    dec c
    nop
    stop
    inc d
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    stop
    ld [hl+], a
    nop
    ld [de], a
    nop
    jr jr_01c_68f7

jr_01c_68f7:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    inc d
    nop
    ld e, $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld d, c
    inc h
    nop
    ld [de], a
    nop
    ld [bc], a
    nop
    ld de, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    ld e, c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    adc c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    adc c
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    sbc c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    and c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cp c
    ld bc, $0000
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cp c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, c
    ld e, l
    ld [$0b00], sp
    adc h
    ret nc

    db $f4
    ld h, b
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld a, c
    ld d, d
    ld [$0b00], sp
    xor c
    rst $20
    sbc a
    ld bc, $7ec0
    add sp, -$18
    add sp, -$18
    ldh [$79], a
    ld b, a
    ld [$0b00], sp
    call nz, $16d0
    and l
    set 1, c
    dec b
    ret nc

    db $10
    and d
    jr z, @+$7b

    inc a
    ld [$0b00], sp
    ldh a, [rNR12]
    and l
    ret


    ret


    ret z

    ret nc

    inc e
    and l
    jp z, Jump_01c_79c9

    ld sp, $0008
    dec bc
    inc c
    and l
    jp z, $7ec9

    ret nc

    ld b, $a5
    set 1, c
    ld a, [hl]
    ld a, c
    ld h, $08
    nop
    dec bc
    add hl, sp
    call Call_000_0c48
    ret nc

    inc [hl]
    and l
    ret


    ret


    add b
    ret nc

    ld a, c
    dec de

Call_01c_6a00:
    ld [$0b00], sp
    ld [$eaea], a
    ld [$a9ea], a
    ld bc, $4fcd
    inc c
    ret nc

    ld a, c
    db $10
    ld [$0b00], sp
    ld c, h
    jr nz, @+$0a

    ld [$eaea], a
    ld [$60ea], a
    ld [$10ea], a
    ld d, $16
    ld d, $12
    ld [de], a
    ld [de], a
    inc de
    inc de
    inc de
    ld d, $16
    inc de
    jr @+$1a

    jr jr_01c_6a44

    dec d
    dec d
    add hl, de
    add hl, de
    dec d
    dec d
    inc d
    inc d
    jr jr_01c_6a51

    dec d
    dec d
    ld de, $1111
    inc d
    inc d
    inc d
    rla
    rla
    ld [de], a

jr_01c_6a44:
    jr jr_01c_6a5d

    rla
    ld de, $1611
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    inc d
    inc d
    dec d

jr_01c_6a51:
    dec d
    jr jr_01c_6a6c

    jr jr_01c_6a69

    dec d
    dec d
    dec d
    ld [de], a
    ld de, $1111

jr_01c_6a5d:
    jr jr_01c_6a77

    jr jr_01c_6a7a

    add hl, de
    add hl, de
    ld d, $16
    ld d, $13
    inc de
    add hl, de

jr_01c_6a69:
    add hl, de
    add hl, de
    ld [de], a

jr_01c_6a6c:
    ld [de], a
    rla
    rla
    add hl, de
    add hl, de
    dec d
    dec d
    dec d
    ld de, $1411

jr_01c_6a77:
    inc d
    add hl, de
    add hl, de

jr_01c_6a7a:
    inc d
    inc d
    inc d
    add hl, de
    jr jr_01c_6a98

    ld [de], a
    ld [de], a
    jr @+$1a

    rla
    ld d, $19
    add hl, de
    dec d
    dec d
    rla
    inc d
    inc d
    add hl, de
    add hl, de
    rla
    ld de, $1315
    inc de
    ld [de], a
    ld [de], a
    ld [de], a
    add hl, de

jr_01c_6a98:
    rla
    ld d, $10
    jr @+$14

    dec d
    add hl, de
    ld [de], a
    ld de, $1913
    add hl, de
    inc de
    jr jr_01c_6ab9

    add hl, de
    ld de, $1511
    dec d
    add hl, de
    rla
    ld de, $1218
    add hl, de
    ld de, $1015
    db $10
    cp $77
    sub l

jr_01c_6ab9:
    cpl
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    add hl, de
    ld [hl], a
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    db $eb
    rrca
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    sub l
    ld b, d
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    or b
    ld a, d
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    ld a, c
    ld a, [hl]
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    sbc a
    ld [bc], a
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    adc h
    ld e, e
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    ccf
    ld d, [hl]
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    ld e, d
    add hl, de
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    jp nc, $547d

    ld a, a
    ld b, e
    ld [$77fe], sp
    ld e, l
    rrca
    ld d, h
    ld a, a
    ld b, e
    ld [$77fe], sp
    ld d, h
    ld a, a
    pop af
    ld a, [hl+]
    ld b, e
    ld [$77fe], sp
    sbc $47
    dec d
    db $10
    ld l, [hl]
    db $76
    cp $77
    sbc $47
    dec d
    db $10
    db $eb
    rrca
    cp $77
    sbc b
    ld a, d
    adc e
    ld a, d
    ld b, e
    ld [$77fe], sp
    sbc $46
    ret nc

    ld c, l
    ld b, e
    ld [$77fe], sp
    sub d
    ld l, [hl]
    db $eb
    ld e, l
    ld b, e
    ld [$77fe], sp
    sbc a
    ld a, [hl+]
    ld e, d
    add hl, de
    ld b, e
    ld [$77fe], sp
    dec [hl]
    ld [hl], a
    ld l, [hl]
    ld h, [hl]
    ld b, e
    ld [$77fe], sp
    db $db
    ld h, d
    push af
    ld e, l
    ld b, e
    ld [$77fe], sp
    sbc h
    ld a, $d5
    dec h
    ld b, e
    ld [$77fe], sp
    ld d, h
    ld b, e
    adc c
    ld l, $43
    ld [$77fe], sp
    sbc $62
    db $fc
    ld d, l
    ld b, e
    ld [$77fe], sp
    sbc a
    dec sp
    sbc d
    ld [bc], a
    ld b, e
    ld [$77fe], sp
    cp d
    ld e, d
    rst $28
    ld c, c
    ld b, e
    ld [$77fe], sp
    cp d
    ld e, d
    dec d
    db $10
    ld b, e
    ld [$77fe], sp
    ld a, [hl]
    inc de
    ld [hl-], a
    inc sp
    ld b, e
    ld [$77fe], sp
    ei
    ld d, l
    ld [hl-], a
    inc sp
    ld b, e
    ld [$77fe], sp
    ld [hl], b
    db $76
    ld [hl-], a
    inc sp
    ld b, e
    ld [$77fe], sp
    rst $20
    inc e
    ld h, d
    inc c
    ld b, e
    ld [$77fe], sp
    ld e, [hl]
    ccf
    adc c
    ld l, $43
    ld [$77fe], sp
    ld e, [hl]
    ccf
    sbc d
    ld [bc], a
    ld b, e
    ld [$77fe], sp
    ld e, [hl]
    ccf
    ld e, d
    add hl, de
    ld b, e
    ld [$77fe], sp
    sbc $46
    db $eb
    ld e, l
    ld b, e
    ld [$77fe], sp
    push de
    dec h
    ld [de], a
    ld e, e
    ld b, e
    ld [$77fe], sp
    sbc a
    dec sp
    sbc b
    ld a, [hl+]
    ld b, e
    ld [$1010], sp
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $2010
    db $10
    jr nc, jr_01c_6cb6

    ld sp, $3114
    ld d, h
    jr nc, jr_01c_6cfc

    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10

jr_01c_6cb6:
    ld d, d
    db $10
    ld d, $10
    ld [de], a
    db $10
    inc de
    db $10
    inc d
    db $10
    inc d
    db $10
    dec d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    ld d, d
    db $10
    jr nc, @+$16

    ld sp, $3114
    ld d, h
    jr nc, jr_01c_6d30

    ld hl, $1010
    db $10
    ld c, $14
    rrca
    inc d
    rrca
    ld d, h
    ld c, $54
    ld bc, $1c10
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10

jr_01c_6cfc:
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    dec c
    db $10
    jr nc, jr_01c_6d2e

    ld sp, $3118
    ld e, b
    jr nc, jr_01c_6d74

    ld de, $2010
    db $10
    jr nc, jr_01c_6d3a

    ld sp, $3118
    ld e, b
    jr nc, jr_01c_6d80

    ld b, e
    stop
    nop
    nop
    nop

jr_01c_6d2e:
    nop
    nop

jr_01c_6d30:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6d3a:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld c, $18
    rrca
    jr @+$11

    ld e, b
    ld c, $58
    ld hl, $1010
    db $10
    inc [hl]
    jr @+$37

    jr jr_01c_6d9b

    jr jr_01c_6d9e

    jr jr_01c_6dac

    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6d74:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6d80:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    jr c, jr_01c_6dae

    add hl, sp
    jr jr_01c_6dd3

    jr @+$3d

jr_01c_6d9b:
    jr jr_01c_6dae

    db $10

jr_01c_6d9e:
    jr nz, jr_01c_6db0

    ld b, h
    jr @+$47

    jr jr_01c_6deb

    jr jr_01c_6dee

    jr jr_01c_6dec

    stop
    nop

jr_01c_6dac:
    nop
    nop

jr_01c_6dae:
    nop
    nop

jr_01c_6db0:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e

jr_01c_6dd3:
    db $10
    ld c, b
    jr jr_01c_6e20

    jr jr_01c_6e23

    jr @+$4d

    jr jr_01c_6dfe

    db $10
    db $10
    db $10
    ld d, h
    jr jr_01c_6e38

    jr jr_01c_6e3b

    jr jr_01c_6e3e

    jr jr_01c_6e2c

    stop

jr_01c_6deb:
    nop

jr_01c_6dec:
    nop
    nop

jr_01c_6dee:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6dfe:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld e, b
    jr jr_01c_6e70

    jr jr_01c_6e73

    jr jr_01c_6e76

    jr jr_01c_6e2e

    db $10
    jr nz, jr_01c_6e30

jr_01c_6e20:
    ld [hl-], a
    jr jr_01c_6e56

jr_01c_6e23:
    jr @+$35

    jr jr_01c_6e59

    ld e, b
    ld b, e
    stop
    nop

jr_01c_6e2c:
    nop
    nop

jr_01c_6e2e:
    nop
    nop

jr_01c_6e30:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6e38:
    nop
    nop
    nop

jr_01c_6e3b:
    nop
    nop
    nop

jr_01c_6e3e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld e, $58

jr_01c_6e56:
    ld d, d
    jr jr_01c_6eab

jr_01c_6e59:
    jr jr_01c_6e79

    jr jr_01c_6e7e

    db $10
    db $10
    db $10
    ld b, b
    jr jr_01c_6eb6

    jr jr_01c_6eb8

    jr jr_01c_6ea7

    ld e, b
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop

jr_01c_6e70:
    nop
    nop
    nop

jr_01c_6e73:
    nop
    nop
    nop

jr_01c_6e76:
    nop
    nop
    nop

jr_01c_6e79:
    nop
    nop
    nop
    nop
    nop

jr_01c_6e7e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld b, b
    inc d
    ld d, e
    inc d
    ld d, e
    inc d
    ld b, b
    ld d, h
    ld de, $2010
    db $10
    ld d, b
    jr jr_01c_6ef4

    jr jr_01c_6ef6

    ld e, b
    ld d, b

jr_01c_6ea7:
    ld e, b
    ld b, e
    stop

jr_01c_6eab:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6eb6:
    nop
    nop

jr_01c_6eb8:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld d, b
    inc d
    ld d, c
    inc d
    ld d, c
    ld d, h
    ld d, b
    ld d, h
    ld hl, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6ef4:
    nop
    nop

jr_01c_6ef6:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $2010
    db $10
    ld c, $18
    rrca
    jr jr_01c_6fb4

    ld e, b
    ld c, $58
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6fb4:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

Jump_01c_6fc3:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld c, $14
    rrca
    inc d
    rrca
    ld d, h
    ld c, $54
    ld hl, $1010
    db $10
    jr nc, jr_01c_6ffa

    ld sp, $3118
    ld e, b
    jr nc, jr_01c_7040

    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_6ffa:
    nop
    nop
    nop
    nop
    nop
    nop

Call_01c_7000:
Jump_01c_7000:
    nop

Call_01c_7001:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld c, $18
    rrca
    jr @+$11

    ld e, b
    ld c, $58
    ld de, $2010
    db $10
    inc [hl]
    jr @+$37

    jr jr_01c_705b

    jr jr_01c_705e

    jr jr_01c_706c

    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_7040:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    jr c, jr_01c_706e

    add hl, sp
    jr jr_01c_7093

    jr jr_01c_7096

jr_01c_705b:
    jr jr_01c_707e

    db $10

jr_01c_705e:
    db $10
    db $10
    ld c, $14
    rrca
    inc d
    rrca
    ld d, h
    ld c, $54
    ld b, e
    stop
    nop

jr_01c_706c:
    nop
    nop

jr_01c_706e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_707e:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e

jr_01c_7093:
    db $10
    jr nc, @+$16

jr_01c_7096:
    ld sp, $3114
    ld d, h
    jr nc, jr_01c_70f0

    ld de, $2010
    db $10
    ld [hl+], a
    inc d
    inc hl
    inc d
    inc h
    inc d
    ld e, $14
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    inc a
    inc d
    dec a
    inc d
    ld a, $14
    ld [hl-], a
    ld d, h
    ld hl, $1010
    db $10
    dec h
    inc d
    ld h, $14
    daa
    inc d
    jr z, jr_01c_70fc

    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop

jr_01c_70f0:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_70fc:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld c, h
    inc d
    ld c, l
    inc d
    ld c, [hl]
    inc d
    ld c, a
    inc d
    ld de, $2010
    db $10
    add hl, hl
    inc d
    ld a, [hl+]
    inc d
    dec hl
    inc d
    inc l
    inc d
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld e, h
    inc d
    ld e, l
    inc d
    ld e, [hl]
    inc d
    ld e, a
    inc d
    ld hl, $1010
    db $10
    ld e, $54
    rla
    inc d
    jr jr_01c_717a

    add hl, de
    inc d
    ld b, e
    stop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

jr_01c_717a:
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ld b, e
    db $10
    ld [hl-], a
    inc d
    dec l
    inc d
    ld l, $14
    cpl
    inc d
    ld de, $2010
    db $10
    ld b, b
    inc d
    ld d, e
    inc d
    ld d, e
    inc d
    ld b, b
    ld d, h
    ccf
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    inc e
    db $10
    ld b, c
    db $10
    ld b, b
    inc d
    ld d, e
    inc d
    ld d, e
    inc d
    ld b, b
    ld d, h
    ld hl, $1010
    db $10
    ld d, b
    inc d
    ld d, c
    inc d
    ld d, c
    ld d, h
    ld d, b
    ld d, h
    ld d, d
    db $10
    inc c
    db $10
    inc c
    db $10
    ld [bc], a
    db $10
    inc bc
    db $10
    inc b
    db $10
    dec b
    db $10
    ld b, $10
    rlca
    db $10
    ld d, d
    db $10
    ld [$0310], sp
    db $10
    add hl, bc
    db $10
    ld a, [bc]
    db $10
    rlca
    db $10
    ld b, $10
    dec bc
    db $10
    ld a, [bc]
    db $10
    dec e
    db $10
    inc c
    db $10
    inc c
    db $10
    ld d, d
    db $10
    ld d, b
    inc d
    ld d, c
    inc d
    ld d, c
    ld d, h
    ld d, b
    ld d, h
    ld de, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $1010
    db $10
    ld de, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $2010
    db $10
    ld hl, $0010
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cp [hl]
    ld [hl], a
    ld sp, hl
    ld c, e
    ld [hl-], a
    inc sp
    adc h
    ld h, $00
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cp [hl]
    ld [hl], a
    ld [hl], b
    db $76
    sbc c
    ld e, $ed
    ld b, c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    cp [hl]
    ld [hl], a
    ld a, [hl]
    inc de
    ld e, l
    ld d, d
    db $ed
    ld b, c
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    rst $38
    nop
    rst $38
    rrca
    ldh a, [$1f]
    ldh [$3f], a
    rst $08
    ccf
    rst $08
    inc a
    rst $08
    inc a
    rst $08
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, [hl]
    add e
    ld [hl], a
    sbc c
    ld [hl], a
    sbc c
    ld a, [hl]
    add e
    ld [hl], b
    sbc a
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, $c3
    ld [hl], a
    sbc c
    ld [hl], a
    sbc c
    ld [hl], a
    sbc c
    ld a, $c3
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, $c3
    ld [hl], b
    sbc a
    ld [hl], b
    sbc a
    ld [hl], b
    sbc a
    ld a, $c3
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld [hl], a
    sbc c
    ld a, [hl]
    sub e
    ld a, h
    add a
    ld a, [hl]
    sub e
    ld [hl], a
    sbc c
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ccf
    pop bc
    ld [hl], b
    sbc a
    ld a, [hl]
    add e
    ld [hl], b
    sbc a
    ccf
    pop bc
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, a
    add c
    inc e
    rst $20
    inc e
    rst $20
    inc e
    rst $20
    inc e
    rst $20
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $20
    add hl, sp
    rst $38
    ld de, $29ff
    rst $38
    add hl, hl
    rst $20
    add hl, sp
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld [hl], a
    sbc c
    ld a, a
    adc c
    ld a, a
    sub c
    ld [hl], a
    sbc c
    ld [hl], a
    sbc c
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ccf
    pop bc
    ld [hl], b
    sbc a
    ccf
    pop bc
    rlca
    ld sp, hl
    ld a, [hl]
    add e
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, [hl]
    add e
    ld [hl], a
    sbc c
    ld [hl], a
    sbc c
    ld a, h
    add a
    ld [hl], a
    sbc c
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, [hl]
    xor e
    ld a, $d5
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ldh a, [rIF]
    ldh a, [rIF]
    db $ec
    rst $38
    call c, $3cef
    rst $08
    inc a
    rst $08
    rst $38
    rst $38
    ret nz

    ret nz

    add b
    add b
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    cp $ff
    db $fc
    rst $38
    ld hl, sp-$01
    ldh a, [$e7]
    ld hl, sp-$3d
    db $fc
    add c
    cp $ff
    nop
    rst $38
    ld bc, $03ff
    rst $38
    rlca
    rst $38
    rrca
    rst $20
    rra
    jp $813f


    ld a, a
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, $ff
    ld h, b
    rst $38
    ld l, [hl]
    rst $38
    ld h, [hl]
    rst $38
    ld a, $ff
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, h
    rst $38
    ld h, [hl]
    rst $38
    ld h, [hl]
    rst $38
    ld a, b
    rst $38
    ld h, [hl]
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld a, $ff
    ld h, b
    rst $38
    ld a, h
    rst $38
    ld h, b
    rst $38
    ld a, $ff
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    ld h, [hl]
    rst $38
    db $76
    rst $38
    ld l, [hl]
    rst $38
    ld h, [hl]
    rst $38
    ld h, [hl]
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    jr c, @+$01

    ld a, h
    rst $38
    ld a, h
    rst $38
    ld a, h
    rst $38
    jr c, @+$01

    ld [hl], b
    ld d, b
    ldh a, [$90]
    rst $38
    adc b
    ld a, [hl]
    and $9f
    sub c
    ld a, [hl]
    rst $38
    nop
    rst $38
    nop
    rst $38
    add hl, bc
    ld [$1031], sp
    db $d3
    db $10
    rra
    db $10
    rst $38
    ld sp, hl
    ld b, $fe
    inc bc
    rst $38
    nop
    rst $38
    db $fd
    dec c
    db $fd
    dec c
    ld sp, hl
    add hl, bc
    ld sp, hl
    add hl, bc
    ld sp, hl
    ret


    ld sp, $e139
    ld sp, hl
    ld bc, $fff9
    nop
    rst $38
    ld bc, $03ff
    rst $38
    rlca
    rst $38
    rrca
    rst $20
    rra
    jp $813f


    ld a, a
    rst $38
    nop
    rst $38
    ld bc, $03ff
    rst $38
    rlca
    rst $38
    rrca
    rst $20
    rra
    jp $813f


    ld a, a
    nop
    rst $38
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    inc e
    rst $20
    ld a, $c3
    inc e
    rst $20
    nop
    rst $38
    inc e
    rst $20
    ld bc, $01f9
    ld sp, hl
    ld bc, $01f9
    ld sp, hl
    ld bc, $01f9
    ld sp, hl
    ld bc, $01f9
    ld sp, hl
    rst $38
    nop
    rst $38
    ld bc, $03ff
    rst $38
    rlca
    rst $38
    rrca
    rst $20
    rra
    jp $813f


    ld a, a
    nop
    rst $38
    nop

jr_01c_7641:
    rst $38
    nop
    rst $38
    nop
    rst $38
    inc c
    rst $38
    ld e, $ff
    ccf
    rst $38
    ld a, a
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    jr jr_01c_7641

    inc a
    jp $81fe


    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add e
    sbc a
    add h
    sbc h
    add e
    sbc a
    add b
    sbc a
    nop
    rst $38
    nop
    rst $38
    jr c, @+$01

    dec l
    rst $20
    rst $38
    jp Jump_01c_767f


    rra
    ld a, [bc]
    rst $38
    ret z

    nop

Jump_01c_767f:
    rst $38
    ld h, b
    rst $38
    sub b
    sbc a
    ld h, b
    ccf
    ldh a, [$7f]
    ld hl, sp-$31
    db $fc
    rlca
    db $fc
    rlca
    ld bc, $029f
    sbc [hl]
    ld [bc], a
    sbc [hl]
    inc a
    cp h
    daa
    and a
    inc d
    sub h
    add hl, bc
    sbc c
    ld b, $9e
    ccf
    jr nc, jr_01c_76d0

    inc bc
    ld e, h
    inc b
    jr z, jr_01c_76ae

    ld e, l
    dec c
    cp a
    sbc [hl]
    rst $38
    sub b
    rst $38
    add c

jr_01c_76ae:
    db $fd
    ldh [$7e], a
    ld b, h
    ld a, a
    ld b, d
    rst $38
    add c
    rst $38
    inc bc
    rst $38
    ld bc, $60ff
    rst $38
    ret nz

    sbc c
    ld sp, hl
    push hl
    ld h, l
    dec b
    dec b
    xor c
    add hl, bc
    ld e, c
    add hl, bc
    ld sp, hl
    adc c
    ld sp, hl
    add hl, sp
    xor c
    adc c
    adc a
    sbc e

jr_01c_76d0:
    add a
    sbc h
    add e
    sbc a
    add b
    sbc a
    add c
    sbc a
    add e
    sbc [hl]
    add l
    sbc l
    add e
    sbc a
    cp $06
    rst $38
    ccf
    rst $38
    ld hl, sp-$41
    add e
    rst $38
    db $fc
    pop hl
    ldh [$e0], a
    and b
    ld a, a
    ld h, b
    ld a, a
    ld e, b
    ld a, a
    ld h, b
    rst $20
    ldh [$c7], a
    ld b, c
    xor a
    and c
    rst $38
    ld a, [c]
    sbc a
    sbc l
    rst $38
    ld [hl], b
    push de
    add l
    db $fd
    ld h, l
    reti


    ld e, c
    push af
    ld h, l
    db $fd
    dec h
    ld sp, hl
    add hl, sp
    push af
    push hl
    db $fd
    dec d
    and b
    ldh [$b0], a
    ldh a, [$d8]
    ld a, b
    sub a
    cp a
    rst $38
    ld a, [hl]
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    inc d
    inc e
    inc d
    inc e
    inc de
    rra
    ei
    rst $38
    cp $06
    rst $38
    inc bc
    rst $38
    nop
    rst $38
    nop
    sub l
    push af
    sbc l
    db $fd
    dec d
    push af
    push de
    push af
    dec [hl]
    dec [hl]
    ld sp, hl
    jp hl


    ld sp, hl
    ld bc, $01f9
    rst $38
    rst $38
    ret nz

    ret nz

    add b
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    sbc b
    sub a
    sbc [hl]
    sbc c
    adc c
    sbc a
    add a
    sbc [hl]
    add a
    rst $38
    nop
    rst $38
    nop
    rst $38
    rrca
    pop af
    ld sp, $e6e6
    ret z

    ret z

    sub b
    sbc l
    jr nz, @+$01

    rst $38
    nop
    rst $38
    inc a
    jp Jump_000_05c2


    dec b
    dec bc
    dec bc
    jr jr_01c_77c2

    db $10
    ret nc

    ld sp, $f9f1
    ld bc, $01f9
    ld sp, hl
    ld [hl], c
    reti


    pop af
    add hl, sp
    pop hl
    ld a, c
    ld h, c
    reti


    pop de
    adc c
    adc c
    add b
    sbc a
    adc h
    sbc a

jr_01c_77c2:
    add a
    sbc a
    add d
    sbc [hl]
    add c
    sbc a
    add c
    sbc a
    add c
    sbc a
    add d
    sbc [hl]
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    cp a
    rst $38
    ret nz

    ret nz

    nop
    nop
    adc h
    adc h
    adc d
    adc d
    rlca
    rst $38
    ld a, [de]
    ei
    ld l, h
    rst $20
    ret c

    rst $08
    or e
    sbc a
    add hl, de
    rra
    ld [$040f], sp
    rlca
    ld bc, $01f9
    ld sp, hl
    ld bc, $01f9
    ld sp, hl
    add c
    ld sp, hl
    ld h, c
    ld a, c
    sbc c
    sbc c
    ld e, l
    push bc
    sbc a
    add c
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b
    sbc a
    add c
    sbc [hl]
    add d
    sbc h
    add h
    sbc h
    add h
    rst $38
    ldh [$9f], a
    rst $38
    ldh [$61], a
    add c
    add e
    nop
    rlca
    rlca
    rra
    ld a, [de]
    dec sp
    ld [hl+], a
    ld h, e
    rst $38
    inc a
    jp $81c2


    adc a
    rlca
    ld a, $0f
    ld hl, sp+$1f
    ldh a, [rIF]
    ld hl, sp+$07
    db $fc
    inc a
    rst $08
    inc a
    rst $08
    dec sp
    call z, $c837
    rrca
    rst $38
    rrca
    rst $38
    nop
    rst $38
    nop
    rst $38
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    inc a
    rst $08
    inc a
    rst $08
    db $fc
    rrca
    db $fc
    rrca
    ld hl, sp-$01
    ldh a, [rIE]
    nop
    rst $38
    nop
    rst $38
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    inc a
    rst $08
    inc a
    rst $08
    inc a
    rst $08
    inc a
    rst $08
    inc a
    rst $08
    inc a
    rst $08
    inc a
    rst $08
    inc a
    rst $08
    sbc d
    adc a
    sbc e
    adc a
    sbc h
    sbc h
    sub e
    sub e
    xor a
    xor a
    xor a
    xor a
    sub e
    sub e
    sbc l
    adc l
    jr nz, @+$01

    db $fc
    rst $38
    inc bc
    inc bc
    db $fc
    db $fc
    add hl, sp
    add hl, sp
    ld a, h
    ld a, h
    cp c
    cp c
    rst $38
    rst $38
    ld h, b
    db $fc
    ld b, b
    rst $38
    ldh a, [rIE]
    db $10
    rra
    rst $28
    rst $28
    ldh a, [$f0]
    rst $38
    rst $38
    rst $38
    rst $38
    add hl, de
    add hl, de
    dec d
    dec d
    dec h
    dec h
    ld b, l
    push hl
    adc l
    db $fd
    ld sp, hl
    ld sp, hl
    add hl, sp
    add hl, sp
    jp hl


    jp hl


    add e
    sbc a
    add [hl]
    sbc h
    add [hl]
    sbc h
    add h
    sbc h
    add d
    sbc [hl]
    add e
    sbc a
    adc l
    sbc l
    adc c
    sbc c
    adc h
    adc h
    ld bc, $0100
    nop
    and h
    and h
    ld e, b
    ld e, b
    nop
    nop
    nop
    nop
    nop
    nop
    inc c
    rlca
    adc a
    inc bc
    sbc [hl]
    inc bc
    ld [hl-], a
    inc bc
    dec bc
    add hl, bc
    ld c, a
    ld c, c
    sbc a
    sub c
    ldh [$e0], a
    cp c
    sbc c
    ld h, c
    add hl, sp
    pop af
    sbc c
    ld a, c
    jp hl


    add hl, de
    ld sp, hl
    ld sp, $61f9
    ld sp, hl
    or c
    ld sp, hl
    sbc b
    adc b
    sbc b
    adc c
    sub b
    sub c
    sub b
    sub e
    sub b
    sbc a
    sub [hl]
    sbc a
    sbc b
    adc a
    sbc a
    add a
    ld b, h
    rst $00
    ld l, b
    rst $28
    pop af
    rst $38
    add e
    rst $38
    inc b
    db $fc
    ld e, $fe
    ld h, c
    pop hl
    db $fc
    db $fc
    rrca
    rst $38
    ld [$90f8], sp
    db $fc
    sub b
    cp a
    sub c
    sbc a
    sbc [hl]
    sbc a
    adc b
    adc a
    ld [$f90f], sp
    ld bc, $81f9
    ld a, c
    ld b, c
    ld a, c
    ld b, c
    ld sp, hl
    pop bc
    cp c
    and c
    cp c
    and c
    ld sp, hl
    pop af
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    add b
    ret nz

    ret nz

    rst $38
    rst $38
    and b
    and b
    cp a
    cp a
    nop
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    rst $38
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    rst $38
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    rst $38
    rst $38
    nop
    nop
    nop
    nop
    sbc a
    add a
    sbc l
    add l
    sbc a
    add a
    sbc [hl]
    add a
    sbc h
    add a
    sbc a
    add e
    sbc a
    add c
    sbc a
    add b
    rst $00
    rst $38
    add e
    rst $38
    ld c, h
    db $fc
    adc a
    ei
    adc a
    ld hl, sp+$1f
    ldh a, [rIE]
    ldh [rIE], a
    nop
    rst $38
    rst $38
    rst $38
    rst $38
    cp $fe
    add hl, sp
    add hl, sp
    rst $00
    add $ff
    jr c, @+$01

    nop
    rst $38
    nop
    reti


    pop de
    cp c
    and c
    ld a, c
    ld b, c
    ld sp, hl
    add c
    ld sp, hl
    ld bc, $01f9
    ld sp, hl
    ld bc, $01f9
    add a
    sbc a
    add c
    sbc a
    add c
    sbc a
    add b
    sbc a
    add b
    sbc a
    add b

Jump_01c_79c9:
    sbc a
    add b
    sbc a
    add b
    sbc a
    nop
    nop
    nop
    nop
    ld bc, $c300
    add b
    ld a, a
    ret nz

    ccf
    rst $20
    jr c, @+$01

    ld [hl], b
    rst $38
    nop
    nop
    ld b, b
    ld b, b
    add e
    add b
    db $e3
    add c
    rst $38
    add c
    cp $83
    ld a, h
    rst $08
    ldh a, [rIE]
    or c
    ld sp, hl
    pop hl
    ld sp, hl
    pop bc
    ld sp, hl
    add c
    ld sp, hl
    ld bc, $01f9
    ld sp, hl
    ld bc, $01f9
    ld sp, hl
    sbc a
    add b

Call_01c_7a00:
Jump_01c_7a00:
    sbc a

Jump_01c_7a01:
    add b
    sbc a
    add c
    sbc [hl]
    add e
    sbc [hl]
    add d
    sbc a
    add c
    sbc [hl]
    add d
    sbc a
    add e
    db $fc
    inc c
    ld hl, sp+$78
    adc h
    db $fc
    ld [hl+], a
    xor $22
    ld l, [hl]
    ld [bc], a
    ld e, $ff
    rst $38
    jr nz, jr_01c_7a3e

    jr @+$21

    jr nz, @+$41

    ld b, b
    ld a, a
    and c
    cp a
    db $e3
    rst $38
    cp h
    cp a
    pop af
    rst $38
    daa
    ccf
    ld l, c
    jp hl


    jp hl


    jp hl


    cp c
    ld sp, hl
    and l
    push hl
    ld [hl], l
    push af
    sub l
    sub l
    sbc c
    sbc c
    push af
    push af

jr_01c_7a3e:
    call Call_000_03bf
    call Call_000_36ca
    call Call_000_36ea
    call Call_01c_7a89
    jr c, jr_01c_7a5a

    call Call_01c_7afa
    jr c, jr_01c_7a5a

    call Call_01c_7b27
    jr c, jr_01c_7a5a

    ld a, $02
    jr jr_01c_7a70

jr_01c_7a5a:
    ld hl, $d6af
    push hl
    set 6, [hl]
    ld hl, $7a74
    call Call_000_3c79
    ld c, $64
    call Call_000_3781
    pop hl
    res 6, [hl]
    ld a, $01

jr_01c_7a70:
    ld [$d065], a
    ret


    db $ed
    dec hl
    rst $10
    ld h, c
    and [hl]
    ret


    ld a, a
    ld [de], a
    db $e3
    adc a
    ld h, $4f
    cp d
    call c, $c3da
    or d
    rst $08
    cp l
    rst $20
    ld e, b

Call_01c_7a89:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld c, a
    ld a, [$b594]
    cp c
    jp z, Jump_01c_7ab8

    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld c, a
    ld a, [$b594]
    cp c
    jp nz, Jump_01c_7b61

Jump_01c_7ab8:
    ld hl, $a598
    ld de, $d11d
    ld bc, $0006
    call Call_000_01bb
    ld hl, $a59e
    ld de, $d27b
    ld bc, $0737
    call Call_000_01bb
    ld a, [$d2e6]
    set 7, a
    ld [$d2e6], a
    ld hl, $acd5
    ld de, $c100
    ld bc, $0200
    call Call_000_01bb
    ld a, [$b593]
    ld [$ffd7], a
    ld hl, $b02d
    ld de, $d9b2
    ld bc, $0566
    call Call_000_01bb
    and a
    jp Jump_01c_7b62


Call_01c_7afa:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld c, a
    ld a, [$b594]
    cp c
    jr nz, jr_01c_7b61

    ld hl, $b02d
    ld de, $d9b2
    ld bc, $0566
    call Call_000_01bb
    and a
    jp Jump_01c_7b62


Call_01c_7b27:
Jump_01c_7b27:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld c, a
    ld a, [$b594]
    cp c
    jp nz, Jump_01c_7b61

    ld hl, $aed5
    ld de, $d123
    ld bc, $0158
    call Call_000_01bb
    ld hl, $a59e
    ld de, $d27b
    ld bc, $0026
    call Call_000_01bb
    and a
    jp Jump_01c_7b62


Jump_01c_7b61:
jr_01c_7b61:
    scf

Jump_01c_7b62:
    ld a, $00
    ld [$6000], a
    ld [$0000], a
    ret


    call Call_01c_7a89
    call Call_01c_7afa
    jp Jump_01c_7b27


    ld b, $01
    ld hl, $5c42
    call Call_000_3620
    ld hl, $7bc6
    call Call_01c_7bb1
    and a
    ret nz

    ld c, $28
    call Call_000_3781
    call Call_01c_7f2d
    jr z, jr_01c_7b96

    ld hl, $7bfa
    call Call_01c_7bb1
    and a
    ret nz

jr_01c_7b96:
    ld hl, $7be3
    call Call_000_3c79
    call Call_01c_7ce3
    ld c, $0a
    call Call_000_3781
    ld a, $b6
    call Call_000_3788
    call Call_000_3790
    ld c, $1e
    jp Jump_000_3781


Call_01c_7bb1:
    call Call_000_3c79
    ld hl, $c42c
    ld bc, $0801
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$cc26]
    ret


    db $ed
    dec l
    ld [hl+], a
    ld h, l
    inc sp
    ret


    ld a, a
    or [hl]
    jp nz, $b8d4

    db $dd
    ld c, a
    ld d, h
    and a
    ld b, e
    db $e3
    sub e
    add $7f
    or [hl]
    or a
    cp d
    ret nc

    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    dec hl
    inc b
    ld h, d
    and a
    ld b, e
    db $e3
    sub e
    add $7f
    cp h
    rst $18
    or [hl]
    ret c

    ld a, a
    or [hl]
    or a
    ret


    cp d
    cp h
    ret nz

    rst $20
    ld d, a
    db $ed
    dec l
    ld sp, $7f69
    or [hl]
    or [hl]
    jp c, $7fc0

    and a
    ld b, e
    db $e3
    sub e
    ld h, $4f
    or a
    or h
    jp $bc7f


    rst $08
    or d
    rst $08
    cp l
    ld h, $55
    or e
    or h
    or [hl]
    rst $10
    ld a, a
    or [hl]
    or d
    jp $7fd3


    or d
    or d
    inc sp
    cp l
    or [hl]
    and $57

Call_01c_7c26:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld hl, $d11d
    ld de, $a598
    ld bc, $0006
    call Call_000_01bb
    ld hl, $d27b
    ld de, $a59e
    ld bc, $0737
    call Call_000_01bb
    ld hl, $c100
    ld de, $acd5
    ld bc, $0200
    call Call_000_01bb
    ld hl, $d9b2
    ld de, $b02d
    ld bc, $0566
    call Call_000_01bb
    ld a, [$ffd7]
    ld [$b593], a
    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld [$b594], a
    xor a
    ld [$6000], a
    ld [$0000], a
    ret


Call_01c_7c7d:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld hl, $d9b2
    ld de, $b02d
    ld bc, $0566
    call Call_000_01bb
    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld [$b594], a
    xor a
    ld [$6000], a
    ld [$0000], a
    ret


Jump_01c_7caa:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld hl, $d123
    ld de, $aed5
    ld bc, $0158
    call Call_000_01bb
    ld hl, $d27b
    ld de, $a59e
    ld bc, $0026
    call Call_000_01bb
    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld [$b594], a
    xor a
    ld [$6000], a
    ld [$0000], a
    ret


Call_01c_7ce3:
    call Call_01c_7c26
    call Call_01c_7c7d
    jp Jump_01c_7caa


Call_01c_7cec:
    ld d, $00

jr_01c_7cee:
    ld a, [hl+]
    add d
    ld d, a
    dec bc
    ld a, b
    or c
    jr nz, jr_01c_7cee

    ld a, d
    cpl
    ret


Call_01c_7cf9:
    ld hl, $7d13
    ld a, [$d51f]
    and $7f
    cp $04
    ld b, $02
    jr c, jr_01c_7d0a

    inc b
    and $03

jr_01c_7d0a:
    ld e, a
    ld d, $00
    add hl, de
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ret


    nop
    and b
    ld h, [hl]
    and l
    call z, $32aa
    or b
    ld hl, $7d79
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    ret nz

    ld hl, $d51f
    bit 7, [hl]
    call z, Call_01c_7e9c
    call Call_01c_7dd4
    call Call_000_0ebd
    call Call_000_3b08
    bit 1, a
    ret nz

    ld a, $b6
    call Call_000_3788
    call Call_000_3790
    call Call_01c_7cf9
    ld e, l
    ld d, h
    ld hl, $d9b2
    call Call_01c_7da6
    ld a, [$cc26]
    set 7, a
    ld [$d51f], a
    call Call_01c_7cf9
    ld de, $d9b2
    call Call_01c_7da6
    ld hl, $d2eb
    ld de, $cd3d
    ld a, [hl+]
    ld [de], a
    inc de
    ld a, [hl]
    ld [de], a
    call Call_000_3f35
    call Call_01c_7ce3
    ld hl, $cd3d
    call Call_000_3f3f
    ret


    db $ed
    dec hl
    ld a, [hl+]
    ld h, d
    xor h
    add a
    adc h
    db $dd
    ld a, a
    or [hl]
    or h
    reti


    call nz, $344f
    or e
    inc l
    add $7f
    and a
    ld b, e
    db $e3
    sub e
    ld h, $7f
    or [hl]
    or [hl]
    jp c, $bdcf

    ld d, c
    ld d, [hl]
    ld a, a
    cp a
    jp c, $d333

    ld a, a
    or d
    or d
    inc sp
    cp l
    or [hl]
    and $57

Call_01c_7da6:
    push hl
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld a, b
    ld [$4000], a
    ld bc, $0566
    call Call_000_01bb
    pop hl
    xor a
    ld [hl+], a
    dec a
    ld [hl], a
    ld hl, $a000
    ld bc, $1599
    call Call_01c_7cec
    ld [$b598], a
    xor a
    ld [$6000], a
    ld [$0000], a
    ret


Call_01c_7dd4:
    xor a
    ldh [$ba], a
    ld a, $03
    ld [$cc29], a
    ld a, $07
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $0c
    ld [$cc25], a
    xor a
    ld [$cc37], a
    ld a, [$d51f]
    and $7f
    ld [$cc26], a
    ld [$cc2a], a
    ld hl, $c3a0
    ld b, $02
    ld c, $09
    call Call_000_03d2
    ld hl, $7e50
    call Call_000_3c79
    ld hl, $c3ab
    ld b, $10
    ld c, $07
    call Call_000_03d2
    ld hl, $c3d5
    ld de, $7e64
    call Call_000_0405
    ld a, [$d51f]
    and $7f
    add $f7
    ld [$c3d1], a
    ld hl, $c3b5
    ld de, $7e94
    call Call_000_0405
    call Call_01c_7ee8
    ld hl, $c3da
    ld de, $cd3d
    ld bc, $0028
    ld a, $08

jr_01c_7e3e:
    push af
    ld a, [de]
    and a
    jr z, jr_01c_7e45

    ld [hl], $78

jr_01c_7e45:
    add hl, bc
    inc de
    pop af
    dec a
    jr nz, jr_01c_7e3e

    ld a, $01
    ldh [$ba], a
    ret


    db $ed
    dec hl
    add c
    ld h, d
    xor h
    add a
    adc h
    db $dd
    ld a, a
    ld c, a
    or h
    rst $10
    sbc $33
    cp b
    jr nc, @-$43

    or d
    ld d, b
    ld d, b
    db $ed
    inc l
    ld de, $f744
    ld c, [hl]
    inc e
    xor h
    add a
    adc h
    ld hl, sp+$4e
    inc e
    xor h
    add a
    adc h
    ld sp, hl
    ld c, [hl]
    inc e
    xor h
    add a
    adc h
    ld a, [$1c4e]
    xor h
    add a
    adc h
    ei
    ld c, [hl]
    inc e
    xor h
    add a
    adc h
    db $fc
    ld c, [hl]
    inc e
    xor h
    add a
    adc h
    db $fd
    ld c, [hl]
    inc e
    xor h
    add a
    adc h
    cp $50
    db $ed
    inc l
    ld c, c
    ld b, h
    xor h
    add a
    adc h
    ld d, b

Call_01c_7e9c:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld a, $02
    ld [$4000], a
    call Call_01c_7ebe
    ld a, $03
    ld [$4000], a
    call Call_01c_7ebe
    xor a
    ld [$6000], a
    ld [$0000], a
    ret


Call_01c_7ebe:
    ld hl, $a000
    call Call_01c_7ee3
    ld hl, $a566
    call Call_01c_7ee3
    ld hl, $aacc
    call Call_01c_7ee3
    ld hl, $b032
    call Call_01c_7ee3
    ld hl, $a000
    ld bc, $1599
    call Call_01c_7cec
    ld [$b598], a
    ret


Call_01c_7ee3:
    xor a
    ld [hl+], a
    dec a
    ld [hl], a
    ret


Call_01c_7ee8:
    ld hl, $cd3d
    push hl
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld a, $02
    ld [$4000], a
    call Call_01c_7f1c
    ld a, $03
    ld [$4000], a
    call Call_01c_7f1c
    xor a
    ld [$6000], a
    ld [$0000], a
    pop hl
    ld a, [$d51f]
    and $7f
    ld c, a
    ld b, $00
    add hl, bc
    ld a, [$d9b2]
    ld [hl], a
    ret


Call_01c_7f1c:
    ld a, [$a000]
    ld [hl+], a
    ld a, [$a566]
    ld [hl+], a
    ld a, [$aacc]
    ld [hl+], a
    ld a, [$b032]
    ld [hl+], a
    ret


Call_01c_7f2d:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    ld [$4000], a
    ld a, [$a598]
    and a
    jr z, jr_01c_7f60

    ld hl, $a598
    ld bc, $0ffc
    call Call_01c_7cec
    ld c, a
    ld a, [$b594]
    cp c
    jr nz, jr_01c_7f60

    ld hl, $a5fb
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    ld a, [$d2d8]
    cp l
    jr nz, jr_01c_7f60

    ld a, [$d2d9]
    cp h

jr_01c_7f60:
    ld a, $00
    ld [$6000], a
    ld [$0000], a
    ret


Call_01c_7f69:
    ld a, [$d521]
    dec a
    cp $32
    jr nc, jr_01c_7f84

    ld hl, $a598
    ld bc, $0060
    call Call_000_3ad1
    ld e, l
    ld d, h
    ld hl, $cc5b
    ld bc, $0060
    jr jr_01c_7fad

jr_01c_7f84:
    ld hl, $a5f8
    ld de, $a598
    ld bc, $1260
    call Call_01c_7fad
    ld hl, $cc5b
    ld de, $b7f8
    ld bc, $0060
    jr jr_01c_7fad

    ld hl, $a598
    ld bc, $0060
    ld a, [$cd3d]
    call Call_000_3ad1
    ld de, $cc5b
    ld bc, $0060

Call_01c_7fad:
jr_01c_7fad:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    xor a
    ld [$4000], a
    call Call_000_01bb
    xor a
    ld [$6000], a
    ld [$0000], a
    ret


Jump_01c_7fc6:
    ld a, $0a
    ld [$0000], a
    ld a, $01
    ld [$6000], a
    xor a
    call Call_01c_7feb
    ld a, $01
    call Call_01c_7feb

Jump_01c_7fd9:
    ld a, $02
    call Call_01c_7feb
    ld a, $03
    call Call_01c_7feb
    xor a
    ld [$6000], a
    ld [$0000], a
    ret


Call_01c_7feb:
    ld [$4000], a
    ld hl, $a000
    ld bc, $2000
    xor a
    jp Jump_000_372a


    nop
    ld bc, $0000
    nop
    nop
    nop
    add b
