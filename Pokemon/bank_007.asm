; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $007", ROMX[$4000], BANK[$7]

    ld b, $03
    inc bc
    rlca
    ld de, $1415
    db $10
    ld [$0500], sp
    add hl, bc
    ld c, $0f
    inc c
    dec c
    ld h, l
    ld h, [hl]
    ld h, a
    ld l, b
    ld l, b
    ld l, e
    ld l, e
    dec b
    ld l, c
    ld l, d
    dec b
    dec b
    dec b
    ld l, l
    ld l, [hl]
    ld l, b
    ld l, b
    dec b
    ld l, b
    ld l, b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    dec b
    inc b
    dec b
    dec b
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
    dec b
    ld [de], a
    inc de
    add hl, bc
    rrca
    inc d
    dec d
    rrca
    rrca
    jr jr_007_4062

    rrca
    ld b, $0b
    rrca
    rlca
    ld a, [de]

Jump_007_404f:
    rra
    ld d, $17
    ld e, $1c
    dec e
    dec de
    rrca
    jr nz, jr_007_407a

    rrca
    ld b, $0b
    dec de
    ld [hl+], a
    ld a, l
    ld a, l
    ld a, l
    ld a, l

jr_007_4062:
    ld b, $01
    ld bc, $067d
    ld bc, $7d27
    ld a, [bc]
    inc h
    inc b
    ld a, l
    nop
    add hl, bc
    ld a, [bc]
    rst $10
    ld b, b
    inc [hl]
    ld b, e
    call z, Call_000_0942
    jr nz, jr_007_40ab

jr_007_407a:
    ld d, d
    db $eb
    add $0a
    ld a, [bc]
    ld e, c
    nop
    cp c
    ret


    rra
    ld a, l
    ld b, c
    dec h
    rst $00
    add hl, bc
    ld [hl-], a
    nop
    nop
    ld hl, $90c7
    ld b, b
    ld b, e
    dec b
    inc bc
    ld b, $01
    and l
    inc bc
    ld [de], a
    nop
    and [hl]
    add hl, bc
    ld b, $00
    and a
    dec bc
    dec bc
    nop
    xor e
    dec bc
    rrca
    nop
    xor h
    dec b
    dec b
    add hl, bc
    inc bc
    dec bc

jr_007_40ab:
    db $10
    inc b
    dec bc
    inc c
    dec b
    dec bc
    add hl, bc
    ld b, $03
    dec c
    rlca
    ld [bc], a
    dec c
    add hl, bc
    db $10
    cp $02
    ld bc, $0a0b
    ld [de], a
    rst $38
    rst $38
    ld [bc], a
    inc c
    rst $00
    inc bc
    ld b, $12
    rst $00
    inc bc
    ld [de], a
    inc a
    rst $00
    add hl, bc
    ld b, $4e
    rst $00
    dec bc
    dec bc
    ld d, b
    rst $00
    dec bc
    rrca
    jr @+$66

    jr nz, jr_007_40e8

    ld hl, $7b7b
    inc c
    dec c
    ld c, $18
    ld h, h
    scf
    ld a, [hl-]
    ld a, [hl]
    ld a, e
    ld a, c

jr_007_40e8:
    db $10
    ld de, $1812
    ld h, h
    ld a, e
    ld a, e
    ld a, c
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    jr jr_007_415b

    jr nz, jr_007_4106

    ld hl, $7b7b
    ld a, e
    ld a, e
    ld a, e
    jr jr_007_4165

    scf
    ld a, [hl-]
    ld a, [hl]
    jr nz, jr_007_4127

jr_007_4106:
    jr nz, jr_007_4129

    ld a, e
    jr jr_007_416f

    ld a, e
    ld a, e
    ld a, c
    ld a, h
    ld [hl], d
    ld a, h
    ld [hl], e
    ld a, e
    jr jr_007_4142

    ld e, $7b
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    ld a, e
    jr jr_007_4162

    dec l
    rra
    rra
    rra
    rra
    rra
    rra
    rra

jr_007_4127:
    inc d
    ld l, e

jr_007_4129:
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    ld l, e
    nop
    ld [de], a
    ld a, [bc]
    ld l, d
    ld b, c
    ld b, $44
    inc bc
    ld b, h
    inc c
    ld bc, $451a
    add sp, -$3a
    db $10
    inc d

jr_007_4142:
    inc hl
    ld a, [bc]
    cp l
    ret z

    nop
    db $fd
    ld b, d
    dec sp
    ret z

    ld a, [bc]
    ld a, [bc]
    nop
    nop
    ld sp, hl
    add $53
    ld b, c
    dec bc
    nop
    ld bc, $091b
    inc bc
    ld [bc], a
    inc b

jr_007_415b:
    inc e
    add hl, bc
    cp $01
    ld bc, $1104

jr_007_4162:
    inc de
    cp $02

jr_007_4165:
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld a, [bc]
    ld c, l
    ld d, d
    ld d, d
    ld c, a

jr_007_416f:
    ld sp, $5250
    ld d, d
    ld c, [hl]
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld sp, $0a0a
    ld [hl], h
    ld c, [hl]
    ld a, [bc]
    ld c, l
    rlca
    rlca
    ld b, d
    ld a, [de]
    ld a, [de]
    ld sp, $4e31
    ld a, [bc]
    ld l, [hl]
    ld [hl], h
    ld [hl], h
    ld l, [hl]
    dec bc
    dec bc
    dec bc
    dec bc
    ld l, l
    ld a, [bc]
    ld l, [hl]
    rlca
    rlca
    ld b, d
    dec bc
    dec bc
    dec bc
    dec bc
    ld l, l
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld a, [bc]
    ld sp, $3131
    ld l, l
    ld a, [bc]
    ld l, [hl]
    ld l, a
    rlca
    rlca
    ld l, a
    inc e
    dec bc
    dec bc
    ld l, l
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    ld sp, $0b0b
    ld c, [hl]
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld sp, $3131
    ld sp, $7474
    ld c, [hl]
    ld a, [bc]
    ld c, l
    cpl
    ld a, [de]
    cpl
    rlca
    rlca
    rlca
    rlca
    ld c, [hl]
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld sp, $3131
    ld sp, $3131
    ld c, [hl]
    ld a, [bc]
    ld c, l
    ld l, a
    ld l, a
    ld l, a
    ld l, a
    dec bc
    dec bc
    ld a, [de]
    ld c, [hl]
    ld a, [bc]
    ld c, l
    ld a, [bc]
    ld a, [bc]
    ld [hl], h
    ld [hl], h
    dec bc
    dec bc
    ld sp, $0a4e
    ld c, l
    ld a, [de]
    ld sp, $1a08
    ld a, [de]
    ld a, [de]
    ld a, [de]
    ld c, [hl]
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    dec bc
    dec bc
    ld sp, $0b0a
    dec bc
    ld l, l
    ld a, [bc]
    ld l, [hl]
    dec bc
    dec bc
    ld [hl], h
    ld sp, $0b0b
    ld [hl], h
    ld l, l
    ld a, [bc]
    ld l, [hl]
    ld d, c
    ld d, c
    ld h, e
    dec bc
    ld h, d
    ld d, c
    ld d, c
    ld l, l
    ld a, [bc]
    ld l, [hl]
    ld a, [bc]
    ld a, [bc]
    ld c, l
    dec bc
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    ld l, l
    call Call_000_03bf
    call Call_000_3e1d
    call Call_000_36ca
    call Call_000_36ea
    ld hl, $4255
    call Call_000_3c79
    ld hl, $c43a
    ld bc, $080f
    ld a, $07
    ld [$d0f1], a
    ld a, $14
    ld [$d0ea], a
    call Call_000_3130
    ld a, [$cc26]
    and a
    jp z, Jump_000_09da

    ld b, $1c
    ld hl, $7fc6
    call Call_000_3620
    jp Jump_000_09da


    db $ed
    add hl, hl
    rst $18
    ld b, e
    ret


    ld a, a
    adc l
    db $e3
    dec de
    ld [de], a
    db $e3
    adc a
    add e
    ret c

    add b
    db $dd
    ld c, a
    add a
    ret c

    add b
    ld a, a
    cp h
    rst $08
    cp l
    or [hl]
    and $57
    ld hl, $42be
    call Call_000_3c79
    ld hl, $cf62
    ld a, l
    ld [$cf72], a
    ld a, h
    ld [$cf73], a
    ld a, [$cc36]
    push af
    xor a
    ld [$cc26], a
    ld [$cc36], a
    ld [$cf7a], a
    ld a, $04
    ld [$cf7b], a
    call Call_000_16f7
    pop bc
    ld a, b
    ld [$cc36], a
    ret c

    ld hl, $d0eb
    set 7, [hl]
    ld hl, $cc5b
    ld a, [$cf79]
    add a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    ld c, a
    ld hl, $d32e
    call Call_007_42b7

Call_007_42b7:
    inc hl
    inc hl
    ld a, b
    ld [hl+], a
    ld a, c
    ld [hl+], a
    ret


    db $ed
    add hl, hl
    inc c
    ld b, h
    or d
    call $b27f
    or a
    rst $08
    cp l
    or [hl]
    and $57
    call Call_000_3c6c
    ld hl, $d0eb
    set 5, [hl]
    ld hl, $d715
    res 0, [hl]
    ld hl, $d722
    res 1, [hl]
    ld hl, $42e7
    ld a, [$d5b8]
    jp Jump_000_3dc7


    db $eb
    ld b, d
    ld h, $43
    ld b, $2b
    call Call_000_34dd
    ret nz

    ld a, [$d2e0]
    cp $04
    ret nz

    ld a, [$d2e1]
    cp $12
    ret nz

    ld a, $08
    ld [$d4a7], a
    ld a, $08
    ldh [$8c], a
    call Call_000_13f1
    xor a
    ldh [$b4], a
    ld a, $01
    ld [$cd38], a
    ld a, $80
    ld [$ccd3], a
    call Call_000_34d0
    xor a
    ld [$c109], a
    ld [$cd66], a
    ld a, $01
    ld [$d5b8], a
    ret


    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    ld a, $00
    ld [$d5b8], a
    ret


    ld e, b
    ld b, e
    adc b
    ld b, e
    or c
    ld b, e
    sub [hl]
    rrca
    xor a
    rrca
    pop de
    ld b, e
    ldh [rSCX], a
    ld b, h
    ld b, e
    db $ed
    ld [hl+], a
    ld e, l
    ld e, l
    jp z, $854f

    ld b, $26
    ld a, a
    or [hl]
    or [hl]
    rst $18
    jp $b27f


    ret nz

    ld d, [hl]
    rst $20
    ld d, a
    db $ed
    ld [hl+], a
    rst $10
    ld e, e
    ld a, a
    dec bc
    sbc a
    ret


    ld a, a
    add l
    sub c
    and l
    jp z, $b94f

    sbc $b7
    pop hl
    or e
    inc l
    ld [c], a
    ld h, $7f
    inc sp
    or a
    reti


    ld a, a
    rst $08
    or h
    or [hl]
    rst $10
    ld d, l
    cp l
    sbc $33
    jp $cd7f


    sbc $2c
    sbc $7f
    push bc
    sbc $30
    rst $18
    jp $ed57


    ld [hl+], a
    ld e, l
    ld e, h
    cp h
    or a
    jp z, $b94f

    sbc $b7
    pop hl
    or e
    ret


    ld a, a
    ret nz

    jp nc, $b67f

    ld h, $b8
    cp h
    ldh [rNR52], a
    ld d, l
    ret nz

    rst $08
    add $7f
    inc sp
    or d
    ret c

    ld a, a
    cp h
    call nz, Call_007_7fd9
    sub $b3
    jr nc, jr_007_4408

    db $ed
    ld [hl+], a
    sbc [hl]
    ld e, h
    ld a, a
    rlca
    and a
    xor e
    ld a, a
    adc a
    add d
    xor e
    ld c, a
    rlca
    and a
    xor e
    ret


    ld a, a
    or c
    or [hl]
    jp z, Jump_000_2c7f

    ld [c], a
    or e
    ret z

    jp nz, Jump_007_7fc9

    or d
    db $db
    ld d, a
    db $ed
    ld [hl+], a
    ldh [$5c], a
    ld a, a
    ld d, h
    ld a, a
    cp c
    sbc $b7
    pop hl
    or e
    inc l
    ld [c], a
    ld d, a
    db $ed
    ld [hl+], a
    ei
    ld e, h
    ld a, a
    inc l
    rst $08
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
    add l
    sub c
    and l
    ld d, l
    ret z

    rst $18
    cp c
    jp nz, $877f

    add c
    inc c
    ld a, a
    or l
    call nc, Call_007_572c
    jp Jump_000_3c6c


    inc c
    ld b, h

jr_007_4408:
    sbc $44
    ld hl, $0845
    ld hl, $d73e
    bit 0, [hl]
    set 0, [hl]
    jr nz, jr_007_442e

    ld hl, $4437
    call Call_000_3c79
    ld bc, $1401
    call Call_000_3e5e
    jr nc, jr_007_4429

    ld hl, $4491
    jr jr_007_4431

jr_007_4429:
    ld hl, $44d1
    jr jr_007_4431

jr_007_442e:
    ld hl, $44a6

jr_007_4431:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    cpl
    ld b, h
    ld a, a
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
    ret


    ld c, a
    jp $b2de


    sbc $7f
    inc sp
    cp l
    ld d, c
    dec a
    sbc $d8
    push bc
    ld a, a
    inc [hl]
    or e
    jr z, jr_007_442e

    ld a, a
    inc sp
    cp l
    or [hl]
    rst $10
    ld c, a
    sub e
    add [hl]

jr_007_4462:
    xor c
    ld a, a
    adc e
    sub d
    or b
    inc sp
    ld d, l
    ld l, $cb
    ld a, a
    sub $df
    jp $b87f


    jr nc, jr_007_442e

    or d
    ret z

    rst $20
    ld d, c
    cp a
    or e
    jr nc, jr_007_4462

    ld c, a
    ret nc

    adc $de
    db $dd
    ld a, a
    cp e
    cp h
    or c
    add hl, hl
    rst $08
    cp h
    ld [c], a
    or e

jr_007_4489:
    ld d, l
    ld d, [hl]
    ld a, a
    inc [hl]
    or e
    cpl
    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld a, [$7044]
    ld d, b
    ld bc, $cf45
    nop
    ld [hl], c
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
    add hl, hl
    ld l, $45
    jp nz, $cfb6

    or h
    reti


    ld c, a
    and c
    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    ld a, a
    or [hl]
    or e
    ld a, a
    call nz, $d3b7
    ld d, l
    adc e
    xor a
    xor h

jr_007_44c3:
    ld b, d

jr_007_44c4:
    call $b27f

jr_007_44c7:
    rst $10
    cp h
    jp $b87f


    jr nc, jr_007_4489

    or d
    rst $20
    ld d, a
    db $ed
    add hl, hl
    jr jr_007_451a

    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_007_44c4

    ld d, a
    db $ed

Call_007_44df:
    ld [hl+], a
    db $f4
    ld h, h
    ld a, a
    jr nc, jr_007_44c3

    cp e
    ld h, $7f
    or c
    reti


    jr nc, jr_007_44c7

    rst $20
    ld d, c
    call nz, Call_007_7f3b
    or l
    ret c

    reti


    ret


    jp z, $c14f

    ld [c], a
    rst $18
    call nz, $ba7f
    call c, $b9b2
    inc [hl]
    ld d, [hl]
    ld d, c
    sbc l
    adc d
    and l
    ld a, a
    adc a
    add d
    xor e
    add $7f
    or [hl]
    or h
    reti


    ld a, a
    call nz, $cab7
    ld c, a
    jp z, $b8d4

    ld a, a
    or [hl]
    or h

jr_007_451a:
    jp c, Jump_007_7fc3

    or d
    or d
    sub $57
    db $ed
    ld [hl+], a
    ld [hl], e
    ld h, l
    ld a, a
    rst $30
    ld a, [hl-]
    sbc $7f
    inc [hl]
    or e
    db $db
    ld c, a
    sbc l
    adc d
    and l
    ld a, a
    adc a
    add d
    xor e
    ld a, a
    ld d, [hl]
    ld a, a
    sub e
    add [hl]
    xor c
    ld a, a
    adc e
    sub d
    or b
    ld d, a
    dec b
    ld b, $05
    db $10
    ld b, b
    ret nz

    ld c, d
    ld c, h
    ld b, l
    nop
    and [hl]
    ld d, l
    ld a, [$d6ca]
    bit 6, a
    call nz, Call_007_4ab4
    ld a, $01
    ld [$cf07], a
    xor a
    ld [$cc3c], a
    ld hl, $4566
    ld a, [$d56f]
    jp Jump_000_3dc7


    adc h
    ld b, l
    xor h
    ld b, l
    ret nz

    ld b, l
    ldh [rLYC], a
    db $10
    ld b, [hl]
    dec sp
    ld b, [hl]
    ld [hl], h
    ld b, [hl]
    or b
    ld b, [hl]
    cp [hl]
    ld b, [hl]
    ld a, $47
    xor e
    ld b, a
    rst $30
    ld b, a
    ld b, c
    ld c, b
    ld [hl], b
    ld c, b
    xor e
    ld c, b
    xor $48
    ld d, b
    ld c, c
    ld [de], a
    ld c, d
    ld b, a
    ld c, d
    ld a, [$d6ca]
    bit 7, a
    ret z

    ld a, [$cf0b]
    and a
    ret nz

    ld a, $31
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld hl, $d6ad
    res 4, [hl]
    ld a, $01
    ld [$d56f], a
    ret


    ld a, $08
    ldh [$8c], a
    ld de, $45bc
    call Call_000_3684
    ld a, $02
    ld [$d56f], a
    ret


    ld b, b
    ld b, b
    ld b, b
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $31
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $2e
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, $03
    ld [$d56f], a
    ret


jr_007_45e0:
    call Call_000_3e07
    ld hl, $ccd3
    ld de, $460d
    call Call_000_3556
    dec a
    ld [$cd38], a
    call Call_000_34d0
    ld a, $01
    ldh [$8c], a
    xor a
    ldh [$8d], a
    call Call_000_34f0
    ld a, $05
    ldh [$8c], a
    xor a
    ldh [$8d], a
    call Call_000_34f0
    ld a, $04
    ld [$d56f], a
    ret


    ld b, b
    ld [$faff], sp
    jr c, jr_007_45e0

    and a
    ret nz

    ld hl, $d6c6
    set 0, [hl]
    ld hl, $d6ca
    set 0, [hl]
    ld a, $01
    ldh [$8c], a
    ld a, $04
    ldh [$8d], a
    call Call_000_34f0
    call Call_000_0ebd
    ld hl, $d6b2
    res 1, [hl]
    call Call_000_0d9b
    ld a, $05
    ld [$d56f], a
    ret


    ld a, $fc
    ld [$cd66], a
    ld a, $11
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_3e07
    ld a, $12
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_3e07
    ld a, $13
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_3e07
    ld a, $14
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6ca
    set 1, [hl]
    xor a
    ld [$cd66], a
    ld a, $06
    ld [$d56f], a
    ret


    ld a, [$d2e0]
    cp $06
    ret nz

    ld a, $05
    ldh [$8c], a
    xor a
    ldh [$8d], a
    call Call_000_34f0
    ld a, $01
    ldh [$8c], a
    xor a
    ldh [$8d], a
    call Call_000_34f0
    call Call_000_0ebd
    ld a, $0c
    ldh [$8c], a
    call Call_000_13f1
    ld a, $01
    ld [$cd38], a
    ld a, $40
    ld [$ccd3], a
    call Call_000_34d0
    ld a, $08
    ld [$d4a7], a
    ld a, $07
    ld [$d56f], a
    ret


    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    ld a, $06
    ld [$d56f], a
    ret


    ld a, [$d696]
    cp $b0
    jr z, jr_007_46cb

    cp $b1
    jr z, jr_007_46e6

    jr jr_007_4703

jr_007_46cb:
    ld de, $46da
    ld a, [$d2e0]
    cp $04
    jr z, jr_007_4731

    ld de, $46e1
    jr jr_007_4731

    nop
    nop
    ret nz

    ret nz

    ret nz

    ld b, b
    rst $38
    nop
    ret nz

    ret nz

    ret nz

    rst $38

jr_007_46e6:
    ld de, $46f5
    ld a, [$d2e0]
    cp $04
    jr z, jr_007_4731

    ld de, $46fd
    jr jr_007_4731

    nop
    nop
    ret nz

    ret nz

    ret nz

    ret nz

    ld b, b
    rst $38
    nop
    ret nz

    ret nz

    ret nz

    ret nz

    rst $38

jr_007_4703:
    ld de, $472d
    ld a, [$d2e1]
    cp $09
    jr nz, jr_007_4731

    push hl
    ld a, $01
    ldh [$8c], a
    ld a, $04
    ldh [$8b], a
    call Call_000_3546
    push hl
    ld [hl], $4c
    inc hl
    inc hl
    ld [hl], $00
    pop hl
    inc h
    ld [hl], $08
    inc hl
    ld [hl], $09
    ld de, $472f
    pop hl
    jr jr_007_4731

    nop
    ret nz

    ret nz

    rst $38

jr_007_4731:
    ld a, $01
    ldh [$8c], a
    call Call_000_3684
    ld a, $09
    ld [$d56f], a
    ret


    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $fc
    ld [$cd66], a
    ld a, $01
    ldh [$8c], a
    ld a, $04
    ldh [$8d], a
    call Call_000_34f0
    ld a, $0d
    ldh [$8c], a
    call Call_000_13f1
    ld a, [$cd3e]
    cp $02
    jr nz, jr_007_4766

    ld a, $2b
    jr jr_007_4770

jr_007_4766:
    cp $03
    jr nz, jr_007_476e

    ld a, $2c
    jr jr_007_4770

jr_007_476e:
    ld a, $2d

jr_007_4770:
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    call Call_000_3e07
    ld a, [$cd3d]
    ld [$d694], a
    ld [$cf78], a
    ld [$d0e3], a
    call Call_000_1aab
    ld a, $01
    ldh [$8c], a
    ld a, $04
    ldh [$8d], a
    call Call_000_34f0
    ld a, $0e
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6ca
    set 2, [hl]
    xor a
    ld [$cd66], a
    ld a, $0a
    ld [$d56f], a
    ret


    ld a, [$d2e0]
    cp $06
    ret nz

    ld a, $01
    ldh [$8c], a
    xor a
    ldh [$8d], a
    call Call_000_34f0
    ld a, $08
    ld [$d4a7], a
    ld c, $02
    ld a, $de
    call Call_000_0e35
    ld a, $0f
    ldh [$8c], a

Jump_007_47cb:
    call Call_000_13f1
    ld a, $01
    ldh [$9b], a
    ld a, $01
    swap a
    ldh [$95], a
    ld a, $22
    call Call_000_3e9d
    ldh a, [$95]
    dec a
    ldh [$95], a
    ld a, $20
    call Call_000_3e9d
    ld de, $cc97
    ld a, $01
    ldh [$8c], a
    call Call_000_3684
    ld a, $0b
    ld [$d56f], a
    ret


    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $e1
    ld [$d036], a
    ld a, [$d694]
    cp $b1
    jr nz, jr_007_480d

    ld a, $01
    jr jr_007_4817

jr_007_480d:
    cp $99
    jr nz, jr_007_4815

    ld a, $02
    jr jr_007_4817

jr_007_4815:
    ld a, $03

jr_007_4817:
    ld [$d03a], a
    ld a, $01
    ld [$cf0e], a
    call Call_000_3337
    ld hl, $52e4
    ld de, $5304
    call Call_000_339c
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    xor a
    ld [$cd66], a
    ld a, $08
    ld [$d4a7], a
    ld a, $0c
    ld [$d56f], a
    ret


    ld a, $f0
    ld [$cd66], a
    ld a, $08
    ld [$d4a7], a
    call Call_000_0ebd
    ld a, $01
    ld [$cf0e], a
    call Call_000_3341
    ld a, $01
    ldh [$8c], a
    xor a
    ldh [$8d], a
    call Call_000_34f0
    ld a, $07
    call Call_000_3e9d
    ld hl, $d6ca
    set 3, [hl]
    ld a, $0d
    ld [$d56f], a
    ret


    ld c, $14
    call Call_000_3781
    ld a, $10
    ldh [$8c], a
    call Call_000_13f1
    ld b, $02
    ld hl, $4a44
    call Call_000_3620
    ld a, $01
    ldh [$8c], a
    ld de, $48a4
    call Call_000_3684
    ld a, [$d2e1]
    cp $04
    jr nz, jr_007_4899

    ld a, $c0
    jr jr_007_489b

jr_007_4899:
    ld a, $80

jr_007_489b:
    ld [$cc5b], a
    ld a, $0e
    ld [$d56f], a
    ret


    ldh [rP1], a
    nop
    nop
    nop
    nop
    rst $38
    ld a, [$d6af]
    bit 0, a
    jr nz, jr_007_48ca

    ld a, $2a
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    xor a
    ld [$cd66], a
    call Call_000_0d9b
    ld a, $12
    ld [$d56f], a
    jr jr_007_48ed

jr_007_48ca:
    ld a, [$cf0a]
    cp $05
    jr nz, jr_007_48e6

    ld a, [$d2e1]
    cp $04
    jr nz, jr_007_48df

    ld a, $0c
    ld [$c109], a
    jr jr_007_48ed

jr_007_48df:
    ld a, $08
    ld [$c109], a
    jr jr_007_48ed

jr_007_48e6:
    cp $04
    ret nz

    xor a
    ld [$c109], a

jr_007_48ed:
    ret


    xor a
    ldh [$b4], a
    call Call_000_3c6c
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a44
    call Call_000_3620
    ld a, $15
    ldh [$8c], a
    call Call_000_13f1
    call Call_007_4a69
    ld a, $2a
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, [$cd37]
    ld [$d11c], a
    ld b, $00
    ld c, a
    ld hl, $cc97
    ld a, $40
    call Call_000_372a
    ld [hl], $ff
    ld a, $01
    ldh [$8c], a
    ld de, $cc97
    call Call_000_3684
    ld a, $10
    ld [$d56f], a
    ret


Call_007_493b:
    ld a, $01
    ldh [$8c], a
    ld a, $04
    ldh [$8d], a
    call Call_000_34f0
    ld a, $08
    ldh [$8c], a
    xor a
    ldh [$8d], a
    jp Jump_000_34f0


    ld a, [$d6af]
    bit 0, a
    ret nz

    call Call_000_3c6c
    call Call_000_0d9b
    ld a, $fc
    ld [$cd66], a
    call Call_007_493b
    ld a, $16
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_0b31
    call Call_007_493b
    ld a, $17
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_0b31
    call Call_007_493b
    ld a, $18
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_0b31
    ld a, $19
    ldh [$8c], a
    call Call_000_13f1
    call Call_000_3e07
    ld a, $2f
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $30
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    call Call_007_493b
    ld a, $1a
    ldh [$8c], a
    call Call_000_13f1
    ld a, $01
    ldh [$8c], a
    ld a, $0c
    ldh [$8d], a
    call Call_000_34f0
    call Call_000_3e07
    ld a, $1b
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6ca
    set 5, [hl]
    ld hl, $d6cd
    set 0, [hl]
    ld a, $01
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $02
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, [$d11c]
    ld b, $00
    ld c, a
    ld hl, $cc97
    xor a
    call Call_000_372a
    ld [hl], $ff
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld b, $02
    ld hl, $4a44
    call Call_000_3620
    ld a, $01
    ldh [$8c], a
    ld de, $cc97
    call Call_000_3684
    ld a, $11
    ld [$d56f], a
    ret


    ld a, [$d6af]
    bit 0, a
    ret nz

    call Call_000_0d9b
    ld a, $2a
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld hl, $d76a
    set 0, [hl]
    res 1, [hl]
    set 7, [hl]
    ld a, $22
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, $05
    ld [$d570], a
    xor a
    ld [$cd66], a
    ld a, $12
    ld [$d56f], a
    ret


    ret


Call_007_4a48:
    ld hl, $d2a2
    ld bc, $0000

jr_007_4a4e:
    ld a, [hl+]
    cp $ff
    ret z

    cp $46
    jr z, jr_007_4a5a

    inc hl
    inc c
    jr jr_007_4a4e

jr_007_4a5a:
    ld hl, $d2a1
    ld a, c
    ld [$cf79], a
    ld a, $01
    ld [$cf7d], a
    jp Jump_000_16cc


Call_007_4a69:
    ld a, $7c
    ldh [$eb], a
    ld a, $08
    ldh [$ee], a
    ld a, [$d2e0]
    cp $03
    jr nz, jr_007_4a83

    ld a, $04
    ld [$cd37], a
    ld a, $30
    ld b, $0b
    jr jr_007_4aa6

jr_007_4a83:
    cp $01
    jr nz, jr_007_4a92

    ld a, $02
    ld [$cd37], a
    ld a, $30
    ld b, $09
    jr jr_007_4aa6

jr_007_4a92:
    ld a, $03
    ld [$cd37], a
    ld b, $0a
    ld a, [$d2e1]
    cp $04
    jr nz, jr_007_4aa4

    ld a, $40
    jr jr_007_4aa6

jr_007_4aa4:
    ld a, $20

jr_007_4aa6:
    ldh [$ec], a
    ld a, b
    ldh [$ed], a
    ld a, $01
    ld [$cf0e], a
    call Call_000_3341
    ret


Call_007_4ab4:
    ld hl, $4af6
    ld a, l
    ld [$d2eb], a
    ld a, h
    ld [$d2ec], a
    ret


    inc c
    ld c, e
    sbc e
    ld c, e
    xor h
    ld c, e
    cp l
    ld c, e
    ld l, l
    ld c, l
    sbc b
    ld d, b
    sbc b
    ld d, b
    add $50
    ret


    ld d, b
    ld a, d
    ld d, l
    ld a, d
    ld d, l
    ld b, l
    ld d, d
    ld l, b
    ld d, d
    add b
    ld d, d
    and h
    ld d, d
    rla
    ld d, e
    ld a, [bc]
    ld d, c
    jr z, jr_007_4b35

    pop af
    ld d, c
    jr jr_007_4b3a

    ld e, d
    ld d, e
    ld h, e
    ld d, e
    add e
    ld d, e
    and h
    ld d, e
    ld [bc], a
    ld d, h
    dec [hl]
    ld d, h
    db $eb
    ld d, h
    inc c
    ld c, e
    sbc e
    ld c, e
    xor h
    ld c, e
    cp l
    ld c, e
    ld l, l
    ld c, l
    sbc b
    ld d, b
    sbc b
    ld d, b
    add $50
    ret


    ld d, b
    ld a, d
    ld d, l
    ld a, d
    ld d, l
    ld [$cafa], sp
    sub $cb
    ld b, a
    jr nz, jr_007_4b1c

    ld hl, $4b31
    call Call_000_3c79
    jr jr_007_4b2e

jr_007_4b1c:
    bit 2, a
    jr nz, jr_007_4b28

    ld hl, $4b4f
    call Call_000_3c79
    jr jr_007_4b2e

jr_007_4b28:
    ld hl, $4b81
    call Call_000_3c79

jr_007_4b2e:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld [hl], a
    ld b, l

jr_007_4b35:
    sbc $30
    db $e3
    ld a, a
    ld d, d

jr_007_4b3a:
    or [hl]
    rst $20
    ld c, a
    add h
    db $e3

jr_007_4b3f:
    add [hl]
    inc de
    ret


    ld a, a
    inc l
    or d
    cp e
    sbc $c5
    rst $10
    ld a, a
    or d
    ret z

    db $e3
    sub $57
    db $ed
    add hl, hl
    push bc
    ld b, l
    call $dee3
    jr nc, jr_007_4b3f

    ld a, a
    or l
    jp c, $4fca

    or l
    call nz, Call_007_7fc5
    jr nc, @-$48

    rst $10
    ld a, a
    ld h, $df
    jp nz, $c5b6

    or d
    ret


    cp e
    ld d, c
    ld d, d
    or [hl]
    rst $10
    ld a, a
    cp e
    or a
    add $4f
    or h
    rst $10
    ld a, [hl-]
    cp [hl]
    jp $d47f


    reti


    ld l, $e7
    ld d, a
    db $ed
    add hl, hl
    ld a, $46
    jp c, Jump_007_7fc9

    or h
    rst $10
    sbc $30
    ld c, a
    ld d, h
    ret


    ld a, a
    adc $b3
    ld h, $7f
    jp nz, $bfd6

    or e
    jr nc, jr_007_4bc8

    ld d, a
    ld [$b13e], sp
    ld [$cd3d], a
    ld a, $03
    ld [$cd3e], a
    ld a, $b0
    ld b, $02
    jr jr_007_4bcc

    ld [$993e], sp
    ld [$cd3d], a
    ld a, $04
    ld [$cd3e], a
    ld a, $b1
    ld b, $03
    jr jr_007_4bcc

    ld [$b03e], sp
    ld [$cd3d], a
    ld a, $02
    ld [$cd3e], a

jr_007_4bc8:
    ld a, $99
    ld b, $04

jr_007_4bcc:
    ld [$cf78], a
    ld [$d0e3], a
    ld a, b
    ld [$cf0e], a
    ld a, [$d6ca]
    bit 2, a
    jp nz, $4d3e

    bit 1, a
    jr nz, jr_007_4c05

    ld hl, $4beb
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld h, a
    ld b, [hl]
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    jr nc, @+$51

    push bc
    or [hl]
    add $7f
    ld d, h
    ld h, $7f
    jp z, $dfb2

    jp Jump_000_2fd9


    rst $20
    ld d, a

jr_007_4c05:
    ld a, $05
    ldh [$8c], a
    ld a, $09
    ldh [$8b], a
    call Call_000_3546
    ld [hl], $00
    ld a, $01
    ldh [$8c], a
    ld a, $09
    ldh [$8b], a
    call Call_000_3546
    ld [hl], $0c
    ld hl, $d6af
    set 6, [hl]
    ld a, $46
    call Call_000_3e9d
    ld hl, $d6af
    res 6, [hl]
    call Call_000_1b86
    ld c, $0a
    call Call_000_3781
    ld a, [$cf0e]
    cp $02
    jr z, jr_007_4c43

    cp $03
    jr z, jr_007_4c61

    jr jr_007_4c7e

jr_007_4c43:
    ld hl, $4c48
    jr jr_007_4c9f

    db $ed
    add hl, hl
    sub c
    ld b, [hl]
    ld a, a
    adc $c9
    or l
    ret


    ld d, h
    ld c, a
    sbc d
    sub e
    add l
    ld [$7fc6], sp
    cp l
    reti


    sbc $2c
    ldh [$c5], a
    and $57

jr_007_4c61:
    ld hl, $4c66
    jr jr_007_4c9f

    db $ed
    add hl, hl
    call z, $d046
    dec l
    ret


    ld d, h
    ld c, a
    dec c
    sub l
    dec b
    and b
    add $7f
    or a
    jp nc, $c9d9

    inc l
    ldh [$c5], a
    and $57

jr_007_4c7e:
    ld hl, $4c83
    jr jr_007_4c9f

    db $ed
    add hl, hl
    inc c
    ld b, a
    rst $20
    ld a, a
    cp h
    ld [c], a
    cp b
    inc a
    jp nz, Jump_007_4f54

    sbc e
    adc e
    ld b, $0f
    sub a
    ld h, $7f
    or d
    or d
    sbc $2c
    ldh [$c5], a
    and $57

jr_007_4c9f:
    call Call_000_3c79
    ld a, $01
    ld [$cc3c], a
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_007_4d0b

    ld a, [$cf78]
    ld [$d696], a
    ld [$d0e3], a
    call Call_000_1aab
    ld a, [$cf0e]
    cp $02
    jr nz, jr_007_4cc7

    ld a, $2b
    jr jr_007_4cd1

jr_007_4cc7:
    cp $03
    jr nz, jr_007_4ccf

    ld a, $2c
    jr jr_007_4cd1

jr_007_4ccf:
    ld a, $2d

jr_007_4cd1:
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $01
    ld [$cc3c], a
    ld hl, $4d0e
    call Call_000_3c79
    ld hl, $4d24
    call Call_000_3c79
    xor a
    ld [$cc49], a
    ld a, $05
    ld [$d0ec], a
    ld a, [$cf78]
    ld [$d0e3], a
    call Call_000_3971
    ld hl, $d6ad
    set 3, [hl]
    ld a, $fc
    ld [$cd66], a
    ld a, $08
    ld [$d56f], a

jr_007_4d0b:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld c, b
    ld b, a
    ld d, h
    jp z, $ce4f

    sbc $c4
    add $7f
    add hl, hl
    sbc $b7
    ld h, $7f
    or d
    or d
    cpl
    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld a, e
    ld b, a
    add h
    db $e3
    add [hl]
    inc de
    or [hl]
    rst $10
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    ld de, $3e50
    dec b
    ldh [$8c], a
    ld a, $09
    ldh [$8b], a
    call Call_000_3546
    ld [hl], $00
    ld hl, $4d54
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    xor c
    ld b, a
    inc de
    jp z, $beb6

    ret


    ld a, a
    ld d, h
    ld c, a
    cp e
    or d
    ld a, [hl+]
    ret


    ld a, a
    or d
    rst $18
    ld b, l
    or a
    jr nc, @+$58

    rst $20
    ld d, a
    ld [$c6fa], sp
    sub $cb
    ld [hl], a
    jr nz, jr_007_4d84

    ld hl, $d27b
    ld b, $13
    call Call_000_1690
    ld a, [$d0e3]
    cp $02
    jr c, jr_007_4d97

jr_007_4d84:
    ld hl, $5066
    call Call_000_3c79
    ld a, $01
    ld [$cc3c], a
    ld a, $56
    call Call_000_3e9d
    jp Jump_007_4e1a


jr_007_4d97:
    ld b, $04
    call Call_000_34dd
    jr nz, jr_007_4e14

    ld hl, $d27b
    ld b, $13
    call Call_000_1690
    ld a, [$d0e3]
    cp $02
    jr nc, jr_007_4e14

    ld a, [$d76a]
    bit 5, a
    jr nz, jr_007_4dfd

    ld a, [$d6ca]
    bit 5, a
    jr nz, jr_007_4df5

    bit 3, a
    jr nz, jr_007_4dd6

    ld a, [$d6ad]
    bit 3, a
    jr nz, jr_007_4dce

    ld hl, $4e1d
    call Call_000_3c79
    jr jr_007_4e1a

jr_007_4dce:
    ld hl, $4e32
    call Call_000_3c79
    jr jr_007_4e1a

jr_007_4dd6:
    ld b, $46
    call Call_000_34dd
    jr nz, jr_007_4de5

    ld hl, $4e69
    call Call_000_3c79
    jr jr_007_4e1a

jr_007_4de5:
    ld hl, $4e8c
    call Call_000_3c79
    call Call_007_4a48
    ld a, $0f
    ld [$d56f], a
    jr jr_007_4e1a

jr_007_4df5:
    ld hl, $4f2d
    call Call_000_3c79
    jr jr_007_4e1a

jr_007_4dfd:
    ld hl, $d6ca
    bit 4, [hl]
    set 4, [hl]
    jr nz, jr_007_4e14

    ld bc, $0405
    call Call_000_3e5e
    ld hl, $4f4f
    call Call_000_3c79
    jr jr_007_4e1a

jr_007_4e14:
    ld hl, $5035
    call Call_000_3c79

Jump_007_4e1a:
jr_007_4e1a:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld h, d
    ld c, b
    inc de
    ld [hl], d
    cp e
    or c
    ld a, a
    ld d, d
    ld c, a
    inc [hl]
    ret


    ld a, a
    ld d, h
    add $7f
    cp l
    reti


    and $57
    db $ed
    add hl, hl
    adc l
    ld c, b
    inc de
    ld [hl], d
    cp a
    or e
    inc l
    ldh [$e7], a
    ld c, a
    call nc, $b2be
    ret


    ld a, a
    ld d, h
    ld h, $7f
    inc sp

jr_007_4e47:
    jp $b77f


    jp Jump_007_51d3


    cp a

jr_007_4e4e:
    or d
    jp nz, Jump_007_7fdd

    ret nz

    ret nz

    or [hl]
    call c, $c3be
    ld a, a
    or d
    cp c
    ld a, [hl-]
    ld c, a
    call nz, $d8c5
    rst $08
    pop bc
    call $b27f
    cp c
    reti


    rst $20
    ld d, a
    db $ed
    add hl, hl
    add hl, bc
    ld c, c
    inc de
    ld [hl], d
    ld d, d
    db $d3
    ld c, a
    rst $08
    cp c
    dec l
    add $7f
    ld d, h
    db $dd
    ld d, l
    ret nz

    ret nz

    or [hl]
    call c, $c3be
    ld a, a
    cp a
    jr nc, jr_007_4e47

    reti


    call nz, $b27f
    or d
    cpl
    rst $20
    ld d, a
    db $ed
    add hl, hl
    db $76
    ld c, c
    inc de
    ld [hl], d
    or l
    or l
    rst $20
    ld a, a
    ld d, d
    ld d, c
    inc [hl]
    db $e3
    jr nc, jr_007_4e4e

    and $4f
    call c, $c9bc
    ld a, a
    call nc, $c0df
    ld d, h
    jp z, $ce56

    or e
    ld d, c
    jr nc, @-$4c

    inc a
    ld c, a
    push bc
    jp nz, $c0b2

    ld a, a
    ret nc

    ret nz

    or d
    jr nc, @-$39

    and $51
    or l
    rst $08
    or h
    ld a, a
    ld d, h
    ld e, l
    ret


    ld c, a
    cp e
    or d
    ret


    or e
    ld h, $7f
    or c
    reti


    push bc
    rst $20
    ld d, c
    ld d, [hl]
    or h
    ld a, a
    call c, $c6bc
    ld a, a
    call c, $bdc0
    ld a, a
    db $d3
    ret


    ld h, $e6
    ld d, c
    ld d, d
    jp z, $847f

    db $e3
    add [hl]
    inc de
    ld a, a
    jp z, $beb6

    add $4f
    call nz, $b934
    db $d3
    ret


    db $dd
    ld a, a
    call c, $bcc0
    ret nz

    rst $20
    ld d, b
    ld de, $5100
    or l
    or l
    rst $20
    ld a, a
    cp d
    jp c, $4fca

    call c, $26bc
    ld a, a
    pop bc
    pop hl
    or e
    db $d3
    sbc $7f
    cp h
    jp $51c0


    call nz, $beb8
    or d
    ret


    ld a, a
    and c
    xor e
    adc h

jr_007_4f1a:
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    inc l
    ldh [rVBK], a
    inc [hl]
    or e
    db $d3
    ld a, a
    or c
    ret c

    ld h, $c4
    sub $e7
    ld d, a
    db $ed
    add hl, hl
    xor h
    ld c, d
    ld a, a
    inc l
    pop hl
    or e
    add $7f
    cp l
    sbc $33

Jump_007_4f3a:
    or d
    reti


    ld c, a
    ld d, h
    ret nz

    pop bc
    ld h, $55
    ld d, d
    db $dd
    ld a, a
    rst $08
    rst $18
    jp $b57f


    reti


    cpl
    db $e3
    rst $20
    ld d, a
    db $ed
    add hl, hl
    ld [$134a], a

Jump_007_4f54:
    ld [hl], d
    ld d, h
    db $dd
    ld c, a
    ret nz

    jr nc, jr_007_4fda

    ret nc

    jp nz, $c0b9

    jr nc, jr_007_4f1a

    ld a, a
    inc sp
    jp z, $b855

    call c, $b2bc
    ld a, a
    ld [de], a
    db $e3
    adc a
    db $dd
    ld d, l
    jp Jump_007_7fc6


    or d
    jp c, Jump_007_7fd9

    cp d
    call nz, Call_007_7fca

jr_007_4f7a:
    inc sp
    or a
    sbc $e7
    ld d, c
    or [hl]
    push bc
    rst $10
    dec l
    ld c, a
    jp nz, $cfb6

    or h
    push bc
    cp c
    jp c, $7f3a

    push bc
    rst $10
    sbc $c9
    jr nc, jr_007_4f7a

    ld d, l
    adc $da
    ld a, a
    cp a
    ret


    ret nz

    jp nc, Jump_007_56c6

    ld d, l
    set 0, d
    sub $b3
    push bc
    ld a, a
    inc [hl]
    or e
    jr z, @-$21

    ld a, a
    call c, $bfc0
    or e
    rst $20
    ld d, c
    ld d, d
    jp z, $fb7f

    cp d
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
    db $d3

Jump_007_4fc0:
jr_007_4fc0:
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    ld de, $5100
    call nc, $b2be
    ret


    ld a, a
    ld d, h
    ld h, $4f
    call nz, Call_000_303b

Call_007_4fd3:
    cp h
    jp $b77f


    ret nz

    rst $10
    ld a, a

jr_007_4fda:
    sub b
    xor l
    xor e
    adc h
    rst $20
    ld d, c
    and c
    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3

Call_007_4fe7:
    and [hl]
    db $dd
    ld c, a
    ld b, e
    add c
    rst $20
    call nz, $c57f
    add hl, hl
    jp c, Jump_007_553a

    ld d, h
    db $dd
    ld a, a
    jp nz, $cfb6

    or h
    ld a, a
    rst $10
    jp c, $e7d9

    ld d, c
    ret nz

    jr nc, jr_007_4fc0

    ld d, [hl]
    ld a, a
    or e
    rst $08
    cp b
    ld a, a
    call nz, $d9da

jr_007_500d:
    or [hl]
    ld c, a
    inc [hl]
    or e
    or [hl]
    jp z, $dc7f

    or [hl]
    rst $10
    sbc $2f
    rst $20
    ld d, c
    add hl, hl
    sbc $b7
    push bc
    ld a, a
    ld d, h
    jp z, $c67f

    add hl, hl
    call nc, $b2bd
    cp h
    ld c, a
    or e
    sbc $d3
    ld a, a
    or c
    reti


    or [hl]
    rst $10
    push bc
    rst $20
    ld d, a
    db $ed
    add hl, hl
    or d
    ld c, h
    inc de
    ld [hl], d
    call nz, Call_000_34b7
    or a
    jp z, $dc4f

    cp h
    ret


    ld a, a
    call nz, $c6ba
    ld a, a
    or [hl]
    or l
    db $dd
    ld a, a
    jr nc, jr_007_500d

    rst $20
    ld d, c
    ld d, h
    dec l
    or [hl]
    sbc $c9
    ld a, a
    ld b, a
    db $e3
    dec bc
    ld h, $4f
    or a
    add $7f
    push bc
    reti


    sbc $33
    push bc
    rst $20
    ld d, a
    db $ed
    add hl, hl
    sbc $47
    inc de
    ld [hl], d
    sub $b8
    ld a, a
    or a
    ret nz

    rst $20
    ld c, a
    ld d, h

Jump_007_5074:
    dec l
    or [hl]
    sbc $c9
    ld d, l
    pop bc
    ld [c], a
    or e
    cp h
    jp z, $347f

    or e
    or [hl]
    push bc
    and $55
    inc [hl]
    jp c, Jump_007_7f56

    pop bc
    ld [c], a
    rst $18
    call nz, $d055
    jp $b17f


    add hl, hl
    sub $b3
    or [hl]
    rst $20
    ld e, b
    ld [$a221], sp
    ld d, b
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld [hl+], a
    ld c, l
    ld a, a
    ret nc

    ret nz

    or d
    push bc
    ld a, a

jr_007_50ac:
    db $d3
    ret


    ld h, $7f
    or c
    reti


    rst $20
    ld c, a
    push bc
    or [hl]
    jp z, $bc7f

    db $db
    or d
    ld b, a
    db $e3
    dec bc
    ld a, a
    ld a, [hl-]
    rst $18
    or [hl]
    ret c

    jr nc, jr_007_50ac

    ld d, a
    nop
    and $57
    ld [$d321], sp
    ld d, b
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld a, h
    ld c, l
    ret nc

    or h
    jp Jump_007_7fd3


    add h
    db $e3
    add [hl]
    inc de
    jp z, $beb6

    jp z, Jump_007_544f

    ret


    ld a, a
    add h
    db $e3
    adc [hl]
    ret c

    sub d
    or b
    push bc
    ret


    rst $20
    ld d, c
    jp z, $beb6

    db $dd
    ld a, a
    cp a
    sbc $b9
    or d
    cp l
    reti


    ld c, a
    ld d, h
    ld a, a
    ld e, l
    db $d3
    ld a, a
    or l
    or l
    or d
    call c, $e7d6
    ld d, a
    ld [$1421], sp
    ld d, c
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    inc d
    ld c, [hl]
    or d
    cp e

jr_007_511a:
    sbc $e7
    ld c, a
    rst $08
    pop bc
    cp b
    ret nz

    dec sp
    jp c, Jump_000_2fc0

    db $e3
    rst $20
    ld d, a
    ld [$3221], sp
    ld d, c
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld b, b
    ld c, [hl]
    inc de
    ld [hl], d
    ld d, e
    or [hl]
    and $4f
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, c
    or l
    or l
    ld a, a
    cp a
    or e
    or [hl]
    ld c, a
    call c, $26bc
    ld a, a
    sub $de
    jr nc, jr_007_511a

    inc l
    ldh [$df], a
    ret nz

    rst $20
    ld d, l
    pop bc
    ld [c], a
    rst $18
    call nz, $cf7f
    rst $18
    jp $b57f


    jp c, Jump_007_51e7

    adc $da
    ld a, a
    ld d, d
    rst $20
    ld d, c
    cp a
    cp d
    add $7f
    ld sp, hl
    dec sp
    or a
    ld c, a
    ld d, h
    ld h, $7f
    or d
    reti


    ld a, a
    inc l
    ldh [$db], a
    or e
    rst $20
    ld d, c
    adc $df
    adc $e7
    ld d, c
    and c
    xor e
    adc h
    adc a
    db $e3
    inc e
    db $e3
    and [hl]
    ret


    ld a, a
    push bc
    or [hl]
    add $4f
    ld d, h
    ld h, $7f
    or d
    jp c, Jump_007_7fc3

    or c
    reti


    sbc $2c
    ldh [rHDMA1], a
    pop de
    or [hl]
    cp h
    jp z, $dc7f

    cp h
    db $d3
    ld a, a
    add hl, de
    ret c

    add hl, de
    ret c

    ret


    ld c, a
    ld d, h
    ld a, a
    ld e, l
    call nz, $c3bc
    ld d, l
    push bc
    rst $10
    cp h

Call_007_51b7:
    ret nz

    ld a, a
    db $d3
    ret


    rst $20
    ld d, c
    or l
    or d
    ld a, $da
    ret nz

    ld a, a

Jump_007_51c3:
    or d
    rst $08
    jp z, $547f

    db $d3
    ld c, a
    ld sp, hl
    dec sp
    or a
    ld a, a
    cp h
    or [hl]
    ld a, a
    ret


    cp d

Jump_007_51d3:
    rst $18
    call nz, $ded7
    ld h, $55
    or l
    rst $08
    or h
    add $7f
    rst $30
    ld b, l
    or a
    ld a, a
    call nc, $b3db
    rst $20
    ld d, l

Call_007_51e7:
Jump_007_51e7:
    ld d, [hl]
    ld a, a
    cp e
    or c
    ld a, a
    or h
    rst $10
    dec a
    rst $20
    ld d, a
    ld [$fb21], sp
    ld d, c
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld b, [hl]
    ld c, a
    xor h
    rst $20
    ld a, a
    dec l
    reti


    or d
    rst $20
    ld c, a
    inc l
    or d
    cp e
    sbc $e7
    ld a, a
    or l
    jp c, $d3c6

    ld a, a
    cp b
    jp c, $b5d6

    rst $20
    ld d, a
    ld [$2221], sp
    ld d, d
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    db $76
    ld c, a
    inc de
    ld [hl], d
    rst $08
    db $e3
    rst $20
    ld c, a
    or c
    call c, $d9c3
    push bc
    ld a, a
    ld d, e
    rst $20
    ld d, l
    or l
    rst $08
    or h
    db $d3
    ld a, a
    cp l
    or a
    push bc
    db $d3
    ret


    db $dd
    ld a, a
    call nz, $e7da
    ld d, a
    ld [$4f21], sp
    ld d, d
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    or h
    ld c, a
    inc de
    ld [hl], d
    cp d
    rst $10
    ld a, a
    inc [hl]
    cp d
    call $b8b2
    rst $20
    ld c, a
    db $d3
    inc [hl]
    rst $18
    jp $deba


    or [hl]
    rst $20
    ld d, a
    ld [$7221], sp
    ld d, d
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    jp hl


    ld c, a
    ldh [$7f], a
    or l
    jp c, Jump_007_7fca

    cp d
    jp c, Jump_007_57e7

    ld [$8a21], sp
    ld d, d
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld [bc], a
    ld d, b
    add h
    db $e3
    add [hl]
    inc de
    or [hl]
    rst $10
    ld c, a
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    ld de, $0850
    ld hl, $52ae
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    dec l
    ld d, b
    jp $e7d6


    ld a, a
    ld d, d
    rst $20
    ld c, a
    cp [hl]
    rst $18
    or [hl]
    cp b
    ld a, a
    inc l
    db $e3
    cp e
    sbc $c6
    ld d, l
    ld d, h
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    sbc $30
    ld l, $e7
    ld d, c
    ld d, [hl]
    ld a, a
    pop bc
    ld [c], a
    rst $18
    call nz, $b54f
    jp c, Jump_007_7fc9

    or c
    or d
    jp $bc7f


    jp $dbd0


    rst $20
    ld d, a
    db $ed
    inc l
    ld [hl], e
    ld b, l
    cp a
    sbc $c5
    ld a, a
    add hl, de
    add l
    push bc
    rst $20
    ld c, a
    or l
    rst $08
    or h
    ret


    ld a, a
    ld d, h
    add $55
    cp l
    ret c

    ldh [$b1], a
    ld a, a
    sub $b6
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    inc l
    ld c, e
    ld b, l
    ret c

    db $e3
    rst $20
    ld c, a
    or l
    jp c, $c3df

    ld a, a
    jp $bbde


    or d
    and $58
    ld [$2121], sp
    ld d, e
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    sub b
    ld d, b
    db $e3
    cp h
    rst $20
    ld c, a
    adc $b6
    ret


    ld a, a
    ld d, h
    call nz, $c07f
    ret nz

    or [hl]
    call c, $c3be
    ld d, l
    db $d3
    rst $18
    call nz, $d37f
    rst $18
    call nz, $c27f
    sub $b8
    cp l
    reti


    ld l, $e7
    ld d, c
    ld d, d
    rst $20
    ld a, a
    inc l
    or d
    cp e
    sbc $e7
    ld c, a
    cp a
    sbc $2c
    ldh [$7f], a
    or c
    ld a, [hl-]
    sub $e7
    ld d, a
    db $ed
    inc h
    ld de, $b261

jr_007_535f:
    cp e
    sbc $e7
    ld d, a
    db $ed
    inc h
    rra
    ld h, c
    rst $18
    or [hl]
    ret c

    ld a, a
    call c, $dabd
    jp $e7c0


    ld c, a
    or l
    jp c, Jump_007_7fc6

    push bc
    sbc $b6
    ld a, a
    sub $e3
    inc l
    ld a, a
    jr nc, jr_007_535f

    jp Jump_007_57e6


    db $ed
    inc h
    ld c, [hl]
    ld h, c
    inc de
    ld [hl], d
    or l
    or l
    ld a, a
    cp a
    or e
    inc l
    ldh [$e7], a
    ld c, a
    or l
    rst $08
    or h
    ret nz

    pop bc
    add $7f
    ret nz

    ret


    ret nc

    ld h, $7f
    or c
    reti


    sbc $2c
    ldh [$57], a
    db $ed
    inc h
    sub e
    ld h, c
    ret


    ld a, a
    or e
    or h
    add $7f
    or c
    reti


    ret


    jp z, $dc4f

    cp h
    ld h, $7f
    jp nz, $dfb8

    ret nz

    ld a, a
    ld d, h
    dec l
    or [hl]
    sbc $e7
    ld d, c
    ret nc

    jp nz, $c0b9

    ld a, a
    ld d, h
    ret


    ld a, a
    ld [de], a
    db $e3
    adc a
    ld h, $4f
    inc l
    inc [hl]
    or e
    jp $c6b7


    ld a, a
    or [hl]
    or a
    cp d
    rst $08
    jp c, Jump_007_55c3

    ld b, a
    db $e3
    dec bc
    ld h, $7f
    call z, $c3b4
    ld a, a
    or d
    cp b
    ld a, a
    call nz, $b3b2
    ld d, c
    ret nz

    or d
    call Call_007_7fde
    sbc c
    add c
    sub d
    add a
    push bc
    ld c, a
    dec l
    or [hl]
    sbc $7f
    push bc
    ret


    inc l
    ldh [$e7], a
    ld d, a
    db $ed
    inc h
    ld e, [hl]
    ld h, d
    inc de
    ld [hl], d
    ld d, d
    ld a, a
    ld d, e
    ld c, a
    cp d
    jp c, Jump_007_7fdd

    or l
    rst $08
    or h
    ret nz

    pop bc
    add $7f
    or c
    dec l
    cp c
    reti


    rst $20
    ld d, c
    ld d, d
    jp z, $847f

    db $e3
    add [hl]
    inc de
    or [hl]
    rst $10
    ld c, a
    ld d, h
    dec l
    or [hl]
    sbc $dd
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    ld de, $ed50
    inc h
    db $d3
    ld h, d
    cp [hl]
    or [hl]
    or d
    ret


    ld a, a
    cp l
    dec a
    xor a
    adc $cc
    reti


    ld a, a
    pop bc
    ld a, a
    ret z

    push bc
    pop bc
    call z, $c8d4
    reti


    ld a, a

Call_007_544f:
Jump_007_544f:
    pop bc
    adc $4f
    call nz, $d37f

Call_007_5455:
Jump_007_5455:
    call nc, $cfd2
    adc $c7
    ld d, h
    ld d, l
    ld e, l
    jp $cec1


    ld a, a
    ret nc

    pop bc
    db $d3
    db $d3
    ld a, a
    call nc, $c855
    jp nc, $d5cf

    rst $00
    ret z

    ld a, a
    add $d2
    rst $08
    call $c87f
    push bc
    jp nc, Jump_007_7fc5

    ld d, l
    pop bc
    ret z

    push bc
    pop bc
    call nz, $817f
    reti


    rst $08
    push de
    ld a, a
    db $d3
    call nc, $ccc9
    call z, $557f
    call nz, $cecf
    add a
    call nc, $c77f

jr_007_5493:
    push bc
    call nc, $c77f
    jp nc, $d9c5

    ld a, a
    jp nz, Jump_007_55c1

    call nz, $c5c7
    ld a, a
    adc h
    ld a, a
    call nz, Call_007_7fcf
    reti


    rst $08
    push de
    sbc a
    ld a, a
    ld d, c
    db $ec
    jp nc, Jump_007_5074

    rst $20
    ld d, c
    cp e
    or c
    ld a, a
    call z, $d8c0
    call nz, Call_007_4fd3
    cp e
    rst $18
    cp a
    cp b
    ld a, a
    cp h
    pop hl
    rst $18
    ld b, h
    jp nz, $bc7f

    jp $dab8


    or d
    rst $20
    ld d, c
    cp d
    jp c, Jump_007_7fca

    ld d, h
    ret


    ld a, a
    jp c, $bcb7

    add $7f
    ret


    cp d
    reti


    ld c, a
    or d
    jr nc, jr_007_5493

    push bc
    ld a, a
    cp h
    ld a, [hl+]
    call nz, $e02c
    db $e3
    rst $20
    ld d, a
    db $ed
    inc h
    inc de
    ld h, h
    db $e3
    cp h
    rst $20
    ld a, a
    inc l
    or d
    cp e
    sbc $e7
    ld c, a
    ld l, $de
    inc a
    ld a, a
    or l
    jp c, Jump_007_7fc6

    rst $08
    or [hl]
    cp [hl]
    push bc
    db $e3
    rst $20
    ld d, c
    ld d, d
    rst $20
    ld c, a
    dec hl
    sbc $c8
    sbc $30
    ld h, $7f
    or l
    rst $08
    or h
    ret


    ld a, a
    inc sp
    ld a, [hl-]
    sbc $ca
    ld d, l
    rst $08
    rst $18
    ret nz

    cp b
    ld a, a
    ret z

    db $e3
    ld l, $e7
    ld d, c
    cp a
    or e
    jr nc, @-$17

    ld a, a
    or e

jr_007_552c:
    pop bc
    ret


    ld a, a
    ret z

    or h
    pop bc
    ldh [$de], a
    ld a, a
    or [hl]
    rst $10
    ld c, a
    adc a
    add d

Jump_007_553a:
    xor e
    sbc l
    xor h
    ld b, d
    db $dd
    ld a, a
    or [hl]
    ret c

    jp $b27f


    cp d
    or e
    rst $20
    ld d, c
    ld d, d
    ld a, a
    add $ca
    ld a, a
    or [hl]
    cp e
    push bc
    or d
    ld a, a
    sub $b3
    add $4f
    ret z

    or h
    pop bc
    ldh [$de], a
    add $7f
    or d
    rst $18
    jp $b57f


    cp b
    or [hl]
    rst $10
    ld d, l
    or l
    jp c, $c1de

    call $b77f
    jp Jump_007_7fd3


    pop de
    jr nc, jr_007_55f3

    jr nc, jr_007_552c

    rst $10
    push bc
    rst $20
    ld d, a
    ld [$8421], sp
    ld d, l
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld a, [$d350]
    ld a, a
    jp z, $beb6

    ret


    ld a, a
    inc l
    ld [c], a
    cp h
    pop hl
    ld a, a
    call nz, $c3bc
    ld c, a
    ld d, h
    db $dd
    ld a, a
    cp c
    sbc $b7
    pop hl
    or e
    ld a, a
    cp h
    jp $bdcf


    ld d, a
    inc bc
    ld [bc], a
    dec bc
    inc b
    ld [bc], a
    rst $38
    dec bc
    dec b
    ld [bc], a
    rst $38
    nop
    dec bc
    ld [bc], a
    rlca
    ld [$ffff], sp
    ld b, c
    pop hl
    ld bc, $073d
    ld a, [bc]
    rst $38
    rst $38
    ld [bc], a
    dec a

Jump_007_55c1:
    rlca
    dec bc

Jump_007_55c3:
    rst $38
    rst $38
    inc bc
    dec a
    rlca
    inc c
    rst $38

Jump_007_55ca:
    rst $38
    inc b
    inc bc
    ld b, $09
    rst $38
    ret nc

    dec b
    ld b, c

Call_007_55d3:
    dec b
    ld b, $ff
    rst $38
    ld b, $41
    dec b
    rlca
    rst $38
    rst $38
    rlca
    inc bc
    ld c, $09
    rst $38
    pop de
    ld [$0d0d], sp
    dec b

Call_007_55e7:
Jump_007_55e7:
    cp $01
    add hl, bc
    jr nz, jr_007_55fa

    ld b, $ff
    rst $38
    ld a, [bc]
    jr nz, jr_007_5600

    inc c

jr_007_55f3:
    rst $38
    rst $38
    dec bc
    dec l
    rst $00
    dec bc
    inc b

jr_007_55fa:
    dec l
    rst $00
    dec bc
    dec b
    ld [bc], a
    inc b

jr_007_5600:
    inc b
    ld h, b
    ld d, a
    ld a, h
    ld d, [hl]
    ld a, [bc]
    ld d, [hl]
    nop
    ld a, [hl-]
    ld d, a
    call Call_007_5619
    call Call_000_3c6c
    ld hl, $5631
    ld a, [$d58c]
    jp Jump_000_3dc7


Call_007_5619:
    ld a, [$d6cd]
    bit 0, a
    jr nz, jr_007_5625

    ld hl, $567c
    jr jr_007_5628

jr_007_5625:
    ld hl, $5686

jr_007_5628:
    ld a, l
    ld [$d2eb], a
    ld a, h
    ld [$d2ec], a
    ret


    scf
    ld d, [hl]
    ld e, h
    ld d, [hl]
    ld a, e
    ld d, [hl]
    call Call_000_0ebd

Jump_007_563a:
    ld a, $04
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $ccd3
    ld de, $5657
    call Call_000_3556
    dec a
    ld [$cd38], a
    call Call_000_34d0

Jump_007_5651:
    ld a, $01
    ld [$d58c], a
    ret


    jr nz, jr_007_565a

    ld b, b

jr_007_565a:
    ld [bc], a
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    ld a, $05
    ldh [$8c], a
    call Call_000_13f1
    ld bc, $4601
    call Call_000_3e5e
    ld hl, $d6cd
    set 1, [hl]
    ld a, $02
    ld [$d58c], a
    ret


    adc h
    ld d, [hl]
    nop
    ld d, a
    dec e
    ld d, a
    and c
    ld d, [hl]
    cp d
    ld d, [hl]
    sub $0e
    nop
    ld d, a
    dec e
    ld d, a
    db $ed
    inc h
    ld bc, $4f66
    add h
    db $e3
    add [hl]
    inc de
    ld a, a
    jp z, $beb6

    add $7f
    sub $db
    cp h
    cp b
    rst $20
    ld d, a
    db $ed
    inc h
    sbc c
    ld h, [hl]
    or a
    ret nc

    jp z, $9d4f

    adc d
    and l
    ld a, a
    adc a
    add d
    xor e
    or [hl]
    rst $10
    ld a, a
    or a
    ret nz

    sbc $30
    ret z

    and $57
    db $ed
    inc h
    call nz, $1366
    ld a, a
    jp z, $beb6

    db $dd
    ld a, a
    cp h

Jump_007_56c6:
    rst $18
    jp $c8d9


Jump_007_56ca:
    and $51
    cp d
    jp c, $c07f

    ret


    rst $08
    jp c, $d9c3

    sbc $30
    cp c
    inc [hl]
    ld c, a
    call c, $bcc0
    jp $b87f


    jp c, $b6d9

Jump_007_56e3:
    or d

jr_007_56e4:
    rst $20
    ld d, c
    ld d, d
    jp z, $8b7f

    xor a
    xor h
    ld b, d
    or [hl]
    rst $10
    ld c, a
    call nz, $b934
    db $d3
    ret


    db $dd
    ld a, a
    or c
    dec l
    or [hl]
    rst $18
    ret nz

    rst $20
    ld d, b
    ld de, $ed50
    inc h
    ld c, c
    ld h, a
    cp d
    ret


    ld a, a
    ret nc

    cp [hl]
    ret


    ld a, a
    or e
    jp c, $2cbd

    jp z, $344f

    cp b
    cp c
    cp h
    ld a, a
    push bc
    sbc $30
    rst $18
    jp Jump_007_57e7


    db $ed
    inc h
    add e
    ld h, a
    db $e3
    ld a, a
    add [hl]
    inc c
    jr z, jr_007_56e4

    ret c

    ld d, [hl]
    ld c, a
    cp d
    cp d

Call_007_572c:
    inc sp
    jp z, $b37f

    ret c

    or a
    jp c, $d9c3

    ld a, a
    ret nc

    ret nz

    or d
    ld d, a
    nop
    ld [bc], a
    rlca
    inc bc
    ld bc, $07ff
    inc b
    ld bc, $00ff
    inc bc
    ld h, $09
    inc b
    rst $38
    db $d3
    ld bc, $0904
    add hl, bc
    cp $01
    ld [bc], a
    rlca
    rlca
    rlca
    rst $38
    rst $38
    inc bc
    ld [de], a
    rst $00
    rlca
    inc bc
    inc de
    rst $00
    rlca
    inc b
    ld [de], a
    inc de
    inc de
    add hl, bc
    ld d, $0f
    inc d
    inc d
    jr jr_007_5783

    dec d
    dec d
    rla
    ld a, [de]
    dec bc
    rrca
    ld [$0404], sp
    ld a, $40
    ld a, a
    ld d, a
    ld a, h
    ld d, a
    nop
    cp [hl]
    ld d, a
    jp Jump_000_3c6c


    add e
    ld d, a
    and c
    ld d, a

jr_007_5783:
    db $ed
    inc h
    cp a
    ld h, a
    sbc b
    db $e3
    sub e
    ret


    ld a, a
    push bc
    or [hl]
    ret


    ld a, a
    cp d
    call nz, $dc55
    ret nz

    cp h
    ld a, a
    ld l, $de
    inc a
    ld a, a
    or l
    ld a, $b4
    reti


    ret


    ld d, a
    db $ed
    inc h
    db $fc
    ld h, a
    ld d, c
    cp d
    cp b
    ld a, [hl-]
    sbc $c6
    ld a, a
    or [hl]
    or [hl]
    jp c, $d9c3

    ld a, a
    cp d
    call nz, $c14f
    ldh [$de], a
    call nz, $d07f
    jp Jump_007_57e7


    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [bc], a
    rst $38
    rlca
    inc bc
    ld [bc], a
    rst $38
    nop
    ld [bc], a
    dec e
    add hl, bc
    rlca
    rst $38
    pop de
    ld bc, $0506
    ld [$d0ff], sp
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld l, $40
    xor $57
    db $eb

Jump_007_57e6:
    ld d, a

Call_007_57e7:
Jump_007_57e7:
    nop
    add h
    ld e, b
    nop
    jp Jump_000_3c6c


    or $57
    jr c, jr_007_584a

    ld c, a
    ld e, b
    ld [hl], b
    ld e, b
    db $ed
    inc h
    dec sp
    ld l, b

jr_007_57fa:
    sub a
    db $e3
    sbc a
    db $dd
    ld a, a
    or [hl]
    sbc $26
    or h
    reti


    cp d
    call nz, $4fca
    ret nz

    ret


    cp h
    or d
    ld d, [hl]
    ld h, $7f
    pop de
    dec l
    or [hl]
    cp h
    or d
    rst $20
    ld d, c
    cp d
    rst $18
    ret nz

    ld a, a
    sub l
    xor h
    add a
    sub a
    db $e3
    sbc a
    db $d3
    ld a, a
    or d
    or d
    ld h, $4f
    or l
    ld a, $b4
    call nc, $b2bd
    ret


    ld h, $7f
    or d
    pop bc
    ld a, [hl-]
    sbc $7f
    call nc, $e7c5
    ld d, a
    db $ed
    inc h
    reti


    ld l, b
    ld a, a
    call nz, $c1b3
    ldh [$de], a
    db $d3
    ld c, a
    ld d, h
    ld a, a
    jr nc, jr_007_57fa

    cp l
    or a

jr_007_584a:
    push bc
    ret


    sub $e7
    ld d, a
    ld [$6121], sp
    ld e, b
    call Call_000_3c79
    ld a, $05
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    dec l
    ld d, c
    xor l
    xor e
    ld [hl], d
    sub b
    xor [hl]
    ld a, a
    sub b
    xor [hl]
    xor e
    rst $20
    ld d, a
    db $ed
    inc h
    cp $68
    inc c
    and b
    ld c, a
    jp nc, $d2b2

    or d
    ld a, a
    ld [hl], b
    add h
    sub l
    sub b
    xor l
    xor e
    ld [hl], c
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
    inc b
    inc [hl]
    rlca
    add hl, bc
    rst $38
    rst $38
    ld bc, $0808
    dec b
    cp $01
    ld [bc], a
    add hl, bc
    add hl, bc
    add hl, bc
    cp $02
    inc bc
    ld b, d
    inc b
    ld [$ffff], sp
    inc b
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a

jr_007_58ad:
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld l, $40
    cp a
    ld e, b
    cp h
    ld e, b
    nop
    ld b, a
    ld e, c
    jp Jump_000_3c6c


    push bc
    ld e, b
    db $dd
    ld e, b
    jp hl


    ld e, b
    nop
    xor [hl]
    ret


    call nz, $d2c5
    and e
    jp nc, $d7c1

    call z, Call_000_0850
    ld a, $0f
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    dec h
    ld a, l
    ld b, c

jr_007_58e1:
    xor e
    ld a, a
    or l
    cp l
    call c, $e7d8
    ld d, a
    db $ed
    dec h
    sub [hl]
    ld b, c
    ld a, a
    ld d, h
    ld a, a
    sub $bf
    db $d3
    ret


    ld c, a
    jr nc, jr_007_58ad

    rst $10
    ld a, a
    or a
    ld a, a
    pop de
    dec l
    or [hl]
    cp h
    or d
    sub $51
    sub $bf
    db $d3
    ret


    ld a, a
    rst $18
    jp $cac9


    ld a, a
    set 0, h
    call nz, $ba4f
    or e
    or [hl]
    sbc $7f
    cp h
    ret nz

    ld a, a
    ld d, h
    jr nc, @-$28

    ld d, c
    cp a
    jr nc, jr_007_58e1

    ret


    jp z, $ca7f

    call nc, Call_000_26b2
    ld c, a
    pop bc
    or [hl]
    rst $10
    ret


    push bc
    or d
    ld a, a
    ld e, l
    ret


    ld d, l
    or d
    or e
    cp d
    call nz, Call_007_7fca
    or a
    or [hl]
    sbc $e7
    ld d, c
    add hl, de
    xor h
    dec bc
    cp e
    or h
    ld a, a
    or c
    jp c, Jump_007_563a

    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca

jr_007_594a:
    ld [bc], a
    inc bc
    rst $38
    rlca
    inc bc
    inc bc
    rst $38
    nop
    inc bc
    dec b
    add hl, bc
    ld [$d2ff], sp
    ld bc, $0935
    rlca
    rst $38
    db $d3
    ld [bc], a
    ld a, [bc]
    ld b, $05
    rst $38
    rst $38
    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld l, $40
    ld a, h
    ld e, c
    ld a, c
    ld e, c
    nop
    ld hl, sp+$59
    jp Jump_000_3c6c


    add b
    ld e, c
    or a
    ld e, c
    db $ed
    dec h
    sub l
    ld b, d
    cp a
    jr nc, jr_007_594a

    jp $b27f


    cp b
    call nz, $dc4f
    dec hl
    db $dd
    ld a, a
    or l
    ld a, $b4
    reti


    rst $20
    ld d, c
    cp h
    or [hl]
    cp h
    ld a, a
    set 0, h
    or [hl]
    rst $10
    ld a, a
    or l
    cp a
    call c, $c5d7
    cp c
    jp c, Jump_007_4f3a

    or l
    ld a, $b4
    push bc
    or d
    ld a, a
    call c, $d32b
    ld a, a
    or c
    reti


    cpl
    ld d, a
    db $ed
    dec h
    di
    ld b, d
    ld a, a
    inc [hl]
    cp b
    ld a, a
    call nc, Call_000_34b9
    ld a, a
    sbc l
    sbc d
    ld d, [hl]
    ld c, a
    ld d, h
    ret


    ld a, a
    ret nz

    or d
    pop bc
    ld [c], a
    or e
    ld h, $7f
    call c, $b2d9
    call nz, $c255
    or [hl]
    rst $08
    or h
    ld a, a
    call nc, $b2bd
    sub $55
    inc sp
    db $d3
    ld d, [hl]
    ld a, a
    or [hl]
    push bc
    rst $10
    dec l
    ld a, a
    call nz, $d9da
    ld d, l
    call c, Call_000_2cb9
    ldh [$7f], a
    push bc
    or d
    ret nc

    ret nz

    or d
    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    dec b
    rst $38
    rlca
    inc bc
    dec b
    rst $38
    nop
    ld [bc], a
    dec bc
    rlca
    ld b, $ff
    db $d3
    ld bc, $0904
    ld [$ffff], sp
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld c, [hl]
    ld b, b
    jr z, @+$5c

    inc h
    ld e, d
    nop
    ld [hl-], a
    ld e, e
    call Call_000_3c6c
    ret


    ld l, $5a
    ld [$135a], a
    ld e, e
    ld [$e406], sp
    ld a, $1c
    call Call_000_3e9d
    and b
    jr z, jr_007_5a41

    ld hl, $5aa5
    call Call_000_3c79
    jr jr_007_5a47

jr_007_5a41:
    ld hl, $5a4a
    call Call_000_3c79

jr_007_5a47:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    add $51
    rst $20
    ld a, a
    ld e, [hl]
    jp nc, Jump_007_51e7

    or l
    jp c, Jump_007_7fc9

    or d
    or h
    db $dd
    ld c, a
    cp d
    sbc $c5
    add $7f
    cp h
    pop bc
    rst $08
    or d
    call nc, $df26
    jp Jump_007_51e7


    rst $00
    cp l
    rst $08
    jp c, Jump_007_7fc0

    ld e, h
    jp z, $9d4f

    xor e
    add [hl]
    db $e3
    call nc, $8a7f
    xor e
    inc de
    add $51

jr_007_5a7f:
    inc l
    jp nc, $c6de

    ld a, a
    or c
    push bc
    db $dd
    ld a, a
    adc $d9
    ld a, a
    call c, $dd2b
    ld c, a
    or l
    cp h
    or h
    reti


    ld a, a
    db $d3
    ret


jr_007_5a96:
    jr nc, jr_007_5a7f

    ld d, c
    or c
    jp c, Jump_007_7fca

    ret nz

    or [hl]
    or [hl]
    rst $18
    ret nz

    ret


    add $57
    db $ed
    add hl, hl
    ld c, b
    ld d, c
    jp c, Jump_007_7fc0

    db $d3
    ret


    jp z, $d34f

    inc [hl]
    rst $18
    jp $ba7f


    push bc
    or d
    call nz, $b17f
    or a
    rst $10
    jp nc, Jump_007_51c3

    or e
    pop bc
    ret


    ld a, a
    ld [de], a
    or b
    rlca
    rrca
    add $ca
    ld c, a
    or a
    push bc
    ld h, $c6
    ld a, a
    cp a
    jr nc, jr_007_5a96

    push bc
    ld h, $d7
    ld d, c
    or c
    push bc
    adc $d8
    db $dd
    ld c, a
    or l
    cp h
    or h
    reti


    ld a, a
    cp d
    call nz, Call_007_7fc6
    cp h
    ret nz

    sub $57
    db $ed
    dec h
    rst $10
    ld d, c
    ld c, a
    ld d, h
    add $7f
    or c
    push bc
    db $dd
    ld a, a
    adc $d7
    cp [hl]
    jp $b751


    rst $18
    call nz, $cf7f
    ret nz

    ld c, a
    call c, Call_000_30d9
    cp b
    ret nc

    db $dd
    ld a, a
    or [hl]
    sbc $26
    or h
    jp $c9d9


    sub $e7
    ld d, a
    db $ed
    dec h
    daa
    ld d, d
    ld a, a
    or c
    push bc
    ld h, $7f
    or c
    or d
    jp $e7d9


    ld c, a
    cp d
    cp d
    or [hl]
    rst $10
    ld a, a
    cp a
    call nz, Call_007_7fc6
    inc sp
    rst $10
    jp c, Jump_000_2fd9

    rst $20
    ld d, a
    ld a, [bc]
    inc bc
    rlca
    ld [bc], a
    nop
    rst $38
    rlca
    inc bc
    nop
    rst $38
    nop
    inc bc
    rlca
    rst $38
    ld bc, $0300
    inc bc
    ld [bc], a
    daa
    dec b
    ld b, $ff
    ret nc

    ld bc, $0a0d
    add hl, bc
    cp $02
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    db $f4
    add $00
    inc bc
    ld [$0404], sp
    ld l, $40
    ld l, h
    ld e, e
    ld l, c
    ld e, e
    nop
    pop bc
    ld e, e
    jp Jump_000_3c6c


    ld [hl], b
    ld e, e
    or e
    ld e, e
    db $ed
    dec h
    ld c, $4c
    ld a, a
    inc l
    or d
    cp e
    rst $08
    ld c, a
    ld d, h
    ret


    ld a, a
    cp d
    or e
    or [hl]
    sbc $c6
    ld a, a
    cp d
    rst $18
    jp $c9d9


    ld d, c
    ld a, $b3
    call nc, Call_007_544f
    ld a, a
    dec l
    or [hl]
    sbc $7f
    or c
    jp nz, $c3d2

    reti


    push bc
    rst $10
    ld d, c
    cp d
    or e
    or [hl]
    sbc $c9
    ld a, a
    or c
    or d
    jp $bc4f


    jp $b17f


    add hl, hl
    jp $b87f


    jp c, $b6d9

    cp h
    rst $10
    ld d, a
    ld [$063e], sp
    ld [$cd3d], a
    ld a, $54
    call Call_000_3e9d
    jp Jump_000_0f6a


    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld bc, $07ff
    inc bc
    ld bc, $00ff
    ld [bc], a
    jr z, jr_007_5bd7

    add hl, bc
    rst $38
    jp nc, Jump_000_0b01

    ld b, $05
    rst $38

jr_007_5bd7:
    rst $38
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    dec d
    inc b
    inc b
    sub l
    ld e, [hl]
    ldh a, [$5b]
    db $ed
    ld e, e
    nop
    ld l, a
    ld e, [hl]
    jp Jump_000_3c6c


    or $5b
    db $dd
    ld e, l
    add hl, de
    ld e, [hl]
    ld [$defa], sp
    sub $cb
    ld b, a
    jr z, jr_007_5c07

    ld hl, $5d7d
    call Call_000_3c79
    jp Jump_007_5c9d


jr_007_5c07:
    ld b, $2d
    call Call_000_34dd
    jr z, jr_007_5c3d

    ld hl, $5d1c
    call Call_000_3c79
    ld bc, $0601
    call Call_000_3e5e
    jr nc, jr_007_5c35

    ld a, $2d
    ldh [$db], a
    ld b, $05
    ld hl, $7fae
    call Call_000_3620
    ld hl, $d6de
    set 0, [hl]
    ld hl, $5d4a
    call Call_000_3c79
    jr jr_007_5c9d

jr_007_5c35:
    ld hl, $5dcc
    call Call_000_3c79
    jr jr_007_5c9d

jr_007_5c3d:
    ld hl, $5cb4
    call Call_000_3c79
    xor a
    ld [$cc26], a
    ld [$cc2a], a
    ld a, $03
    ld [$cc29], a
    ld a, $01
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    ld hl, $d6af
    set 6, [hl]
    ld hl, $c3a0
    ld b, $04
    ld c, $0f
    call Call_000_03d2
    call Call_000_0ebd
    ld hl, $c3ca
    ld de, $5ca0
    call Call_000_0405
    ld hl, $5ce9
    call Call_000_3c79
    call Call_000_3b08
    bit 1, a
    jr nz, jr_007_5c97

    ld hl, $d6af
    res 6, [hl]
    ld a, [$cc26]
    and a
    jr nz, jr_007_5c97

    ld hl, $5d05
    call Call_000_3c79

jr_007_5c97:
    ld hl, $5d65
    call Call_000_3c79

Jump_007_5c9d:
jr_007_5c9d:
    jp Jump_000_0f6a


    db $ed
    inc l
    daa
    ld b, d
    ldh [$7f], a
    rst $30
    or $f6
    or $f6
    or $f6
    ldh a, [$4e]
    or [hl]
    call c, $b2c5
    ld d, b
    db $ed
    add hl, hl
    rst $08
    ld d, e
    jp z, $e7b2

    ld a, a
    or d
    rst $10
    rst $18
    cp h
    ldh [$b2], a
    rst $20
    ld c, a
    cp d
    cp d
    jp z, $9e7f

    and l
    add a
    and [hl]
    ld a, a
    inc l
    jp $bcde


    ldh [$d4], a
    rst $20
    ld d, c
    adc $d8
    jr nc, @-$42

    db $d3
    ret


    ld a, a
    or c
    reti


    sub $e3
    rst $20
    ld c, a
    or [hl]
    rst $18
    jp $e3b8


    and $58
    db $ed
    add hl, hl
    ld d, d
    ld d, h
    or d
    or d
    ld a, a
    inc l
    jp $bcde


    ldh [$7f], a
    or c
    reti


    cp c
    inc [hl]
    ld c, a
    or [hl]
    rst $18
    jp $b27f


    or [hl]
    push bc
    or d
    and $57
    db $ed
    add hl, hl
    adc b
    ld d, h
    cp b
    cp e
    sbc $e7
    ld c, a
    or l
    or [hl]
    ret z

    ld h, $7f
    ret nz

    ret c

    rst $08
    cp [hl]
    sbc $c5
    db $e3
    rst $20
    ld e, b
    db $ed
    add hl, hl
    inc sp
    ld d, e
    cp a
    jp c, Jump_007_56ca

    rst $20
    ld d, c
    inc l
    jp $bcde


    ldh [$7f], a
    res 6, a
    or [hl]
    or h
    cp c
    sbc $e7
    ld d, c
    ld d, [hl]
    call c, $d8b6
    rst $08
    cp h
    ret nz

    rst $20
    ld c, a
    cp e
    cp e
    rst $18
    ld a, a
    cp d
    jp c, Jump_007_7fdd

    inc [hl]
    or e
    cpl
    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld [hl], a
    ld d, e
    res 6, a
    or [hl]
    or h
    cp c
    sbc $33
    ld c, a
    inc l
    jp $bcde


    ldh [$dd], a
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    ld de, $ed50
    add hl, hl
    or d
    ld d, h
    sub $db
    cp h
    cp b
    rst $20
    ld c, a
    or c
    ret c

    ld h, $c4
    or e
    ld a, a
    ld a, [hl+]
    dec hl
    or d
    rst $08
    cp h
    ret nz

    rst $20
    ld d, a
    db $ed
    add hl, hl
    ld [hl], a
    ld d, d
    cp d
    sbc $c1
    jp z, Jump_007_7fe7

    inc l
    jp $bcde


    ldh [$c9], a
    ld c, a
    ret


    ret c

    ld a, [hl+]
    cp d
    pop bc
    jp z, $b27f

    or [hl]
    ld h, $7f
    inc sp
    cp l
    and $51
    or c
    ret


    ld a, a
    inc l
    jp $bcde


    ldh [$7f], a
    push bc
    rst $10
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
    jp z, $d37f

    pop bc
    db $db
    sbc $55
    inc [hl]
    or e
    cp b
    jp nz, $307f

    rst $18
    jp $ca7f


    cp h
    jp c, $e0c1

    or e
    sub $e7
    ld d, a
    db $ed
    add hl, hl
    and a
    ld d, e
    cp h
    ldh [$dd], a
    ld a, a
    db $d3
    rst $18
    jp $b9b2


    push bc
    or d
    sub $57
    ld [$e721], sp
    ld e, l
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    bit 2, h
    ld d, [hl]
    rst $20
    ld c, a
    call nc, Call_007_44df
    ret c

    ld a, a
    sbc l
    sbc l
    sub b
    xor l
    ret c

    ld a, a
    or [hl]
    cp h
    rst $10
    and $51
    sbc l
    add d
    xor e
    sub d
    xor e
    ld a, a
    add hl, de
    add c
    add a
    add $4f
    or [hl]
    or d
    db $d3
    ret


    add l
    add hl, bc
    ld a, a
    add $b1
    call c, $b2c5
    ld a, a
    db $d3
    sbc $57
    ld [$defa], sp
    sub $cb
    ld b, a
    ld hl, $5e55
    jr nz, jr_007_5e27

    ld hl, $5e2d

jr_007_5e27:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld l, d
    ld d, l
    ret nc

    cp [hl]
    ret


    ld a, a
    inc l
    jp $bcde


    ldh [rVBK], a
    db $d3
    ret


    jp z, $b27f

    or d
    cp c
    inc [hl]
    ld a, a
    ret nz

    or [hl]
    or d
    sub $e7
    ld d, l
    ld a, $b8
    add $ca
    ld a, a
    or [hl]
    or h
    push bc
    or d
    ret z

    ld d, a
    db $ed
    add hl, hl
    ccf
    ld d, l
    ld a, a
    inc l
    jp $bcde


    ldh [$7f], a
    or [hl]
    rst $18
    cp d
    or d
    or d
    ld c, a
    or e
    rst $10
    call nc, $bccf
    or d
    push bc
    or c
    ld d, a
    ld c, $02
    rlca
    ld [bc], a
    inc b
    rst $38
    rlca
    inc bc
    inc b
    rst $38
    nop
    inc bc
    dec d
    ld b, $0a
    rst $38

Jump_007_5e7f:
    rst $38
    ld bc, $0a1c
    add hl, bc
    cp $01
    ld [bc], a
    inc b
    rlca
    dec b
    rst $38
    pop de
    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    inc b
    dec b
    ld [bc], a
    inc bc
    ld [$0608], sp
    rlca
    dec bc
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld a, [bc]
    ld bc, $090a
    ld [$0404], sp
    ld l, $40
    or l
    ld e, [hl]
    or c
    ld e, [hl]
    nop
    dec [hl]
    ld h, c
    call Call_000_3c6c
    ret


    pop bc
    ld e, [hl]
    jr nz, jr_007_5f18

    and [hl]
    ld e, a
    cp e
    ld e, a
    pop de
    ld e, a
    push af
    ld h, b
    ld [$5ffa], sp
    rst $10
    bit 7, a
    jr nz, jr_007_5ed1

    ld hl, $5eda
    call Call_000_3c79
    jr jr_007_5ed7

jr_007_5ed1:
    ld hl, $5eff
    call Call_000_3c79

jr_007_5ed7:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    cp [hl]
    ld d, l
    cp h
    or d
    push bc
    db $e3
    rst $20
    ld c, a
    sbc e
    dec bc
    ld a, a

jr_007_5ee7:
    db $db
    or e
    inc l
    sbc $26
    ld a, a
    or d
    push bc
    or d
    cpl
    rst $20
    ld d, l
    inc [hl]
    cp d
    add $7f
    or d
    rst $18
    ret nz

    ret


    or [hl]
    push bc
    and $57
    db $ed
    add hl, hl
    ld a, [$db55]
    or e
    inc l
    sbc $7f
    add l
    and l
    add l
    and l
    ret


    ld a, a
    jp c, $ddb2

    ld c, a
    push bc
    jr z, @-$43

    jp nc, Jump_007_7fc6

jr_007_5f18:
    or d
    rst $18
    jp $dec0


    jr nc, jr_007_5ee7

    ld d, a
    ld [$5ffa], sp
    rst $10
    bit 7, a
    jr nz, jr_007_5f30

    ld hl, $5f39
    call Call_000_3c79
    jr jr_007_5f36

jr_007_5f30:
    ld hl, $5f82
    call Call_000_3c79

jr_007_5f36:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    scf
    ld d, [hl]
    ld a, a
    db $d3
    call nz, $c4d3
    ld c, a
    sbc e
    dec bc
    ld a, a
    inc l
    or d
    pop bc
    ldh [$de], a
    ret


    ld a, a
    or l
    or e
    pop bc
    ld a, a
    push bc
    ret


    ld d, c
    inc l
    or d
    pop bc
    ldh [$de], a
    ld a, a
    call nc, $bcbb
    or d
    ret


    sub $e7
    ld d, c
    cp l
    jp $dad7


    ret nz

    ret c

    ld a, a
    or [hl]
    or h
    push bc
    cp b
    push bc
    rst $18
    ret nz

    ld c, a
    ld d, h
    db $dd
    ld a, a
    or c
    dec l
    or [hl]
    rst $18
    jp $be55


    call c, $bc7f
    jp $c9d9


    ld d, a
    db $ed
    add hl, hl
    db $dd
    ld d, [hl]
    or c
    rst $18
    ret nz

    or [hl]
    or d
    ld d, [hl]
    rst $20
    ld c, a
    ld d, h
    rst $18
    jp $307f


    rst $18
    cp d
    ld a, a
    cp l
    reti


    call nz, $b155
    rst $18
    ret nz

    or [hl]
    or d
    sbc $30
    sub $c8
    db $e3
    rst $20
    ld d, a
    nop
    xor e
    push bc
    call nz, $d2c1
    jp Jump_007_7f81


    ld a, a
    ld a, a
    ld d, b
    ld [$2f3e], sp
    call Call_000_2dc7
    jp Jump_000_0f6a


    nop
    xor [hl]
    ret


    call nz, $d2c5
    sbc d
    xor b
    add a
    call Call_007_7f81
    ld d, b
    ld [$a73e], sp
    call Call_000_2dc7
    jp Jump_000_0f6a


    ld [$ebfa], sp
    sub $cb
    ld b, a
    jr nz, jr_007_5ffc

    ld hl, $6005
    call Call_000_3c79
    ld bc, $4901
    call Call_000_3e5e
    jr nc, jr_007_5ff4

    ld hl, $6066
    call Call_000_3c79
    ld hl, $d6eb
    set 0, [hl]
    jr jr_007_6002

jr_007_5ff4:
    ld hl, $60c8
    call Call_000_3c79
    jr jr_007_6002

jr_007_5ffc:
    ld hl, $60d5
    call Call_000_3c79

jr_007_6002:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    inc hl
    ld d, a
    cp e
    jp $527f


    cp b
    sbc $56
    ld d, c
    ld d, h
    dec l
    or [hl]
    sbc $7f
    ld [hl-], a
    cp b
    ret c

    jp z, Jump_007_544f

    add $7f
    ret nz

    or d
    cp h
    jp $cc55


    or [hl]
    or d
    ld a, a
    or c
    or d
    inc l
    ld [c], a
    or e
    ld h, $7f
    push bc
    or d
    call nz, $b655
    sbc $be
    or d
    jp z, $c07f

    or d
    call Call_007_7fde
    pop de
    dec l
    or [hl]
    cp h
    or d
    ld d, c
    cp a
    ret


    ld a, a
    ret nz

    cp l
    cp c
    add $7f
    push bc
    reti


    or [hl]
    ld a, a
    call c, $d7b6
    sbc $26
    ld c, a
    cp d
    jp c, Jump_007_7fdd

    or c
    push bc
    ret nz

    add $7f
    cp e
    cp h
    or c
    add hl, hl
    sub $b3
    rst $20
    ld e, b
    db $ed
    add hl, hl
    rst $30
    ld d, a
    sbc e
    dec bc
    ld a, a
    db $db
    or e
    inc l
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
    ld de, $5100
    ld d, h
    ret


    call z, $ddb4
    ld a, a
    call z, $c4b8
    ld c, a
    rlca
    db $e3
    rlca
    db $e3
    ld a, a
    ret z

    pop de
    rst $18
    jp Jump_007_7fd9


jr_007_6099:
    ld d, h
    inc sp
    db $d3
    ld d, l
    add hl, hl
    sbc $b7
    ld h, $7f
    call c, $c3b2
    ld a, a
    call nz, $b53b
    or a
    reti


    rst $20
    ld d, c
    ld d, h
    ld h, $7f
    or d
    ret z

    pop de
    ret c

    ld a, a
    cp h
    jp $ba4f


    rst $08
    rst $18
    ret nz

    rst $10
    ld a, a
    jp nz, $dfb6

    jp $d07f


    push bc
    cp e
    or d
    ld d, a
    db $ed
    add hl, hl
    cp e
    ld e, b
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_007_6099

    ld d, a
    db $ed
    add hl, hl
    pop de
    ld e, b
    cp d
    ret


    or c
    or d
    jr nc, jr_007_615e

    cp e
    cp h
    or c
    add hl, hl
    ret nz

    ld c, a
    call z, $cab4
    ld a, a
    call nc, $c6b8
    ld a, a
    ret nz

    rst $18
    jp $b6d9


    push bc
    and $57
    db $ed
    ld h, $0f
    ld l, h
    ld a, a
    cp h
    ld [c], a
    or e
    set 3, [hl]
    ld h, $7f
    or c
    ret nz

    reti


    rst $20
    ld c, a
    add hl, hl
    rst $18
    or [hl]
    sbc $7f
    ld d, h
    ret


    ld a, a
    call nz, Call_007_55d3
    ld a, [de]
    xor h
    rlca
    ld [hl], h
    ld b, d
    and a
    dec c
    xor e
    sub e
    rst $20
    ld d, c
    ld d, [hl]
    or l
    or e
    ld a, $7f
    adc $b3
    adc $b3
    jp z, Jump_007_5651

    or c
    rst $10
    ld a, a
    or a
    ret c

    call nz, $c3df
    ld a, a
    or c
    reti


    rst $20
    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [bc], a
    rst $38
    rlca
    inc bc
    ld [bc], a
    rst $38
    nop
    ld b, $0c
    add hl, bc
    rlca
    rst $38
    rst $38
    ld bc, $0708
    ld a, [bc]
    rst $38
    ret nc

    ld [bc], a
    dec b
    ld [$ff0a], sp
    pop de
    inc bc
    dec b
    rlca
    dec b
    rst $38
    rst $38
    inc b
    ld d, $05
    rlca
    rst $38
    rst $38

jr_007_615e:
    dec b
    ld b, c
    rlca
    rlca
    rst $38
    rst $38
    ld b, $12
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld l, $40
    ld a, l
    ld h, c
    ld a, c
    ld h, c
    nop
    add hl, hl
    ld h, d
    call Call_000_3c6c
    ret


    add c
    ld h, c
    sbc b
    ld h, c
    nop
    and c
    ret z

    pop bc
    add c
    pop bc
    ret z

    pop bc
    add c
    ld a, a
    ld a, a
    ld a, a
    ld a, a
    ld d, b
    ld [$113e], sp
    call Call_000_2dc7
    jp Jump_000_0f6a


    ld [$5ffa], sp
    rst $10
    bit 7, a
    jr nz, jr_007_61a8

    ld hl, $61b1
    call Call_000_3c79
    jr jr_007_61ae

jr_007_61a8:
    ld hl, $61f6
    call Call_000_3c79

jr_007_61ae:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    db $10
    ld e, c
    ld d, [hl]
    rst $20
    ld c, a
    ld e, [hl]
    db $dd
    ld a, a
    push de
    reti


    cp e
    push bc
    or d
    call c, Call_007_51e7
    or c
    cp a
    cp d
    add $7f
    or d
    reti


    ld a, a
    add l
    and l
    add l
    and l
    ret


    ld c, a
    or l
    or [hl]
    or c
    cp e
    sbc $26
    ld d, [hl]
    ld d, c
    ld e, [hl]
    add $7f
    jp nz, $cfb6

    rst $18
    jp $c64f


    add hl, hl
    reti


    ld a, a
    call nz, $e1c1
    or e

jr_007_61ea:
    ld d, l
    cp d
    db $db
    cp e
    jp c, $c17f

    ldh [$df], a
    ret nz

    ret


    ld d, a
    db $ed
    add hl, hl
    ld a, d
    ld e, c
    xor c
    db $e3
    ret


    ld c, a
    push de
    or e
    jp c, Jump_007_7fb2

    inc sp
    push bc
    cp b
    ld a, a
    push bc
    rst $18
    ret nz

    rst $18
    jp Jump_007_51e7


    jr nc, jr_007_61ea

    or [hl]
    ld h, $7f
    rst $08
    sub $b4
    reti


    ld a, a
    ret nz

    rst $08
    cp h
    or d
    db $dd
    ld c, a
    cp h
    dec l
    jp nc, Jump_007_7fc3

    cp b
    jp c, $c9c0

    ret z

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
    ld [bc], a
    dec b
    add hl, bc
    rlca
    rst $38
    pop de
    ld bc, $081d
    ld b, $ff
    db $d3
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld l, $40
    sub a
    ld h, d
    ld d, l
    ld h, d
    nop
    ld b, d
    ld h, h
    jp Jump_000_3c6c


Call_007_6258:
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    ret


Call_007_6263:
    ld hl, $d233
    ld bc, $0006
    ld a, [$cf79]
    call Call_000_3ad1
    ld de, $d11d
    ld c, $06
    call Call_007_628a
    jr c, jr_007_6295

    ld hl, $d137
    ld bc, $002c
    ld a, [$cf79]
    call Call_000_3ad1
    ld de, $d2d8
    ld c, $02

Call_007_628a:
jr_007_628a:
    ld a, [de]
    cp [hl]
    jr nz, jr_007_6295

    inc hl
    inc de
    dec c
    jr nz, jr_007_628a

    and a
    ret


jr_007_6295:
    scf
    ret


    sbc c
    ld h, d
    ld [$3ecd], sp
    scf
    ld hl, $62f3
    call Call_007_6258
    jr nz, jr_007_62ee

    ld hl, $633a
    call Call_000_3c79
    xor a
    ld [$d05a], a
    ld [$cfb2], a
    call Call_000_2df3
    push af
    call Call_000_3e04
    call Call_000_3dee
    call Call_000_0b3c
    pop af
    jr c, jr_007_62ee

    call Call_000_2fab
    call Call_007_6263
    ld hl, $63fb
    jr c, jr_007_62e8

    ld hl, $6351
    call Call_007_6258
    jr nz, jr_007_62ee

    ld hl, $639e
    call Call_000_3c79
    ld b, $01
    ld hl, $64fb
    call Call_000_3620
    jr c, jr_007_62ee

    ld hl, $63b8

jr_007_62e8:
    call Call_000_3c79
    jp Jump_000_0f6a


jr_007_62ee:
    ld hl, $63e8
    jr jr_007_62e8

    db $ed
    inc l
    sub l
    ld [hl], h
    jp z, $e7b2

    ld c, a
    call c, $bcc0
    jp z, $be7f

    or d
    jp nc, Jump_007_7fb2

    jp z, Jump_000_30de

    sbc $bc
    ld d, l
    or d
    or e
    push bc
    jp c, $7f3a

    push bc
    rst $08
    or h
    ret


    ld a, a
    or e
    rst $10
    push bc
    or d
    inc sp
    cp l
    ld d, c
    jp z, Jump_007_7fb2

    or c
    push bc
    ret nz

    ret


    ld a, a
    ld d, h
    ret


    ld c, a
    sub l
    xor h
    add a
    sub a
    db $e3
    sbc a
    ld a, a
    or e
    rst $10
    push bc
    rst $18
    jp $b17f


    add hl, hl
    reti


    sub $57
    db $ed
    add hl, hl
    and $59
    ld d, h
    ret


    ld c, a
    sub l
    xor h
    add a
    sub a
    db $e3
    sbc a
    db $dd
    ld a, a
    or e
    rst $10
    push bc
    or e
    or [hl]
    ret z

    and $58
    db $ed
    inc l
    dec [hl]
    ld [hl], l
    ld a, a
    ld d, b
    ld bc, $c8b4
    push bc
    ld a, a
    db $d3
    push bc
    ret nc

    pop bc
    jp nc, $d4c1

    push bc
    ld a, a
    ret nc

    jp nc, $c3cf

    ld c, a
    push bc
    db $d3
    db $d3
    ld a, a
    rst $08
    add $7f
    call nc, $c1d2
    adc $d3
    call $d4c9
    ld a, a
    call $c155
    jp $c9c8


    adc $c5
    jp nc, $c8d9

    pop bc
    db $d3
    ld a, a
    db $d3
    call nc, $d2c1
    call nc, $c555
    call nz, $ce7f
    rst $08
    rst $10
    add c
    ld a, a
    ld d, c
    db $ec
    jr c, @+$80

    or [hl]
    push bc
    and $57
    db $ed
    add hl, hl
    inc d
    ld e, d
    ld a, a
    inc sp
    jp z, $344f

    sbc $c5
    ld a, a
    sub l
    xor h
    add a
    sub a
    db $e3
    sbc a
    add $7f
    cp h
    sub $b3

jr_007_63b5:
    or [hl]
    push bc
    ld e, b
    db $ed
    add hl, hl
    sub b
    ld e, d
    cp d
    jp c, $d7b6

    ld c, a
    cp d
    ret


    ld a, a
    ld d, h
    jp z, $507f

    ld bc, $cee4
    nop
    jr nc, jr_007_63b5

    ld d, c
    rst $08
    or h
    sub $d8
    ld a, a
    or d
    or d
    ld a, a
    push bc
    rst $08
    or h
    ld a, a
    inc l
    ldh [$c5], a
    or d
    or [hl]
    ld c, a
    sub $b6
    rst $18
    ret nz

    push bc
    rst $20
    ld d, a
    db $ed
    inc l
    xor c
    ld [hl], l
    ld c, a
    call c, $dfb6
    ret nz

    ld a, a
    rst $08
    ret nz

    ld a, a
    or a
    push bc
    cp e
    or d
    sub $57
    db $ed
    add hl, hl
    ld a, [hl-]
    ld e, d
    ld d, b
    ld bc, $cd68
    nop
    or [hl]
    rst $20
    ld c, a
    cp d
    jp c, Jump_007_7fca

    cp l
    ld a, [hl-]
    rst $10
    cp h
    or d
    ld a, a
    sub l
    xor h
    add a
    sub a
    db $e3
    sbc a
    jr nc, jr_007_646e

    cp c
    pop bc
    ret


    ld a, a
    jp nz, $d6b9

    or e
    db $d3
    push bc
    or d
    rst $20
    ld d, c
    cp d
    jp c, $d7b6

    db $d3
    ld a, a
    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld c, a
    or [hl]
    call c, Call_000_26b2
    rst $18
    jp $b17f


    add hl, hl
    push bc
    cp e
    or d
    sub $e7
    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    dec b
    rst $38
    rlca
    inc bc
    dec b
    rst $38
    nop
    ld bc, $072b
    add hl, bc
    rst $38
    jp nc, Jump_000_1201

    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld l, $40
    ld l, h
    ld h, h
    ld l, b
    ld h, h
    nop
    push af
    ld h, h
    call Call_000_3c6c
    ret


    ld [hl], d
    ld h, h

jr_007_646e:
    sub a
    ld h, h
    xor [hl]
    ld h, h
    db $ed
    dec h
    ld e, $67
    ld a, a
    and d
    sbc l
    dec de
    add [hl]
    adc e
    sub d
    or b
    rst $08
    inc sp
    ld c, a
    ld b, e
    xor h
    ld b, e
    add $7f
    jp $d026


    db $dd
    ld d, l
    call nz, $b934
    jp $d37f


    rst $10
    or e
    ret


    cp e
    rst $20
    ld d, a
    nop
    xor l
    push de
    jp nc, $cec9

    rst $00
    ld a, a
    ld a, a
    ld a, a
    ld d, b
    ld [$243e], sp
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    dec h
    ld e, e
    ld h, a
    pop bc
    ldh [$de], a
    ld c, a
    cp d
    sbc $34
    ld a, a
    or c
    cp a
    dec sp
    add $7f
    or d
    or a
    ret nz

    or d
    ld a, a
    inc sp
    cp l
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
    jp z, Jump_007_5e7f

    ret


    ld c, a
    inc l
    cp c
    sbc $26
    ld a, a
    or l
    or l
    or d
    ld a, a
    cp a
    or e
    inc sp
    cp l
    ret z

    ld d, c
    add a
    sub b
    add hl, de
    jp z, $bf7f

    or e
    inc sp
    db $d3
    ld a, a
    or c
    ret c

    rst $08
    cp [hl]
    sbc $56
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
    inc bc
    inc b
    rlca
    add hl, bc
    rst $38
    jp nc, Jump_000_0901

    add hl, bc
    rlca
    cp $02
    ld [bc], a
    ld b, b
    rlca
    ld [$ffff], sp
    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld c, $06
    ld c, $ac
    ld h, [hl]
    sub h
    ld h, [hl]
    daa
    ld h, l
    nop
    sbc b
    ld h, [hl]
    call Call_000_3c6c
    ld hl, $d782
    bit 4, [hl]
    jr nz, jr_007_6562

    bit 0, [hl]
    ret z

    ld a, [$d3ae]
    cp $01
    ret nz

    bit 2, [hl]
    jp z, Jump_007_6570

    set 4, [hl]
    call Call_000_3e07
    ld hl, $d6af
    set 7, [hl]
    ld hl, $ccd3
    ld a, $40
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld a, $03
    ld [$cd38], a
    xor a
    ld [$c206], a
    ld [$cd3b], a
    dec a
    ld [$cd66], a
    ret


jr_007_6562:
    bit 5, [hl]
    ret nz

    ld a, [$cd38]
    and a
    ret nz

    ld [$cd66], a
    set 5, [hl]
    ret


Jump_007_6570:
    set 2, [hl]
    ld a, $ff
    ld [$cd66], a
    ld [$c0ee], a
    call Call_000_0e45
    ld c, $1f
    ld a, $d6
    call Call_000_0e35
    ld b, $1e
    ld hl, $5fec
    call Call_000_3620
    xor a
    ld [$c102], a
    ld c, $78
    call Call_000_3781
    ld b, $9c
    call Call_000_0386
    ld hl, $c468
    ld bc, $0078
    ld a, $14
    call Call_000_372a
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    xor a
    ldh [$ba], a
    ld [$cd3d], a
    ldh [rOBP1], a
    ld a, $58
    ld [$cd3e], a
    ld hl, $d4a5
    ld c, [hl]
    inc hl
    ld b, [hl]
    push bc
    push hl
    ld a, $a9
    call Call_000_3788
    ld a, $ff
    ld [$cfb2], a
    ld d, $00
    ld e, $08

jr_007_65cf:
    ld hl, $0002
    add hl, bc
    ld a, l
    ld [$d4a5], a
    ld a, h
    ld [$d4a6], a
    push hl
    push de
    call Call_000_28e4
    call Call_007_662e
    pop de
    ld b, $10

jr_007_65e6:
    call Call_007_6617
    ld c, $08

jr_007_65eb:
    call Call_007_6651
    dec c
    jr nz, jr_007_65eb

    inc d
    dec b
    jr nz, jr_007_65e6

    pop bc
    dec e
    jr nz, jr_007_65cf

    xor a
    ldh [rWY], a
    ldh [$b0], a
    call Call_007_6669
    ld a, $90
    ldh [$b0], a
    ld a, $01
    ld [$cfb2], a
    pop hl
    pop bc
    ld [hl], b
    dec hl
    ld [hl], c
    call Call_000_23ae
    ld hl, $d32d
    dec [hl]
    ret


Call_007_6617:
    push bc
    push de
    ld hl, $c311
    ld a, [$cd3d]
    swap a
    ld c, a
    ld de, $0004

jr_007_6625:
    inc [hl]
    inc [hl]
    add hl, de
    dec c
    jr nz, jr_007_6625

    pop de
    pop bc
    ret


Call_007_662e:
    ld a, [$cd3e]
    sub $10
    ld [$cd3e], a
    ld c, a
    ld b, $64
    ld a, [$cd3d]
    inc a
    ld [$cd3d], a
    ld a, $01
    ld de, $6649
    call Call_000_3ae1
    ret


    db $fc
    db $10
    db $fd
    db $10
    cp $10
    rst $38
    db $10

Call_007_6651:
    ld h, d
    ld l, $50
    call Call_007_665b
    ld h, $00
    ld l, $80

Call_007_665b:
jr_007_665b:
    ldh a, [rLY]
    cp l
    jr nz, jr_007_665b

    ld a, h
    ldh [rSCX], a

jr_007_6663:
    ldh a, [rLY]
    cp h
    jr z, jr_007_6663

    ret


Call_007_6669:
    ld hl, $cc5b
    ld bc, $00b4
    ld a, $14
    call Call_000_372a
    ld hl, $9940
    ld de, $cc5b
    ld bc, $000c
    call Call_000_02dd
    ld hl, $c754
    ld a, $0d
    ld [hl+], a
    ld [hl+], a
    ld [hl+], a
    ld [hl], a
    ld a, $a9
    call Call_000_0e45
    ld c, $78
    call Call_000_3781
    ret


    sub [hl]
    ld h, [hl]
    nop
    ld d, a
    rrca
    ld [bc], a
    nop
    ld c, $05
    rst $38
    ld [bc], a
    ld c, $01
    ld e, a
    nop
    nop
    inc b
    rst $00
    nop
    ld c, $18
    rst $00
    ld [bc], a
    ld c, $0e
    inc c
    inc c
    inc c
    inc c
    inc c
    ld d, $15
    inc c
    inc c
    inc bc
    inc c
    inc c
    ld c, $13
    ld bc, $0101
    ld bc, $0504
    ld b, $07
    ld bc, $0101
    ld bc, $110c
    dec c
    dec c
    dec c
    dec c
    ld [$0a09], sp
    dec bc
    dec c
    dec c
    dec c
    dec c
    inc c
    ld de, $0d0d
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    inc c
    ld de, $0d0d
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    dec c
    inc c
    db $10
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld [de], a
    ld c, $08
    inc b
    inc b
    ld a, $40
    rrca
    ld h, a
    inc c
    ld h, a
    nop
    add h
    ld h, a
    jp Jump_000_3c6c


    inc de
    ld h, a
    ld l, [hl]
    ld h, a
    db $ed
    ld h, $8b
    ld c, a
    sbc $c6
    db $d3
    ld a, a
    or [hl]
    or d
    ret nz

    ld h, $56
    ld c, a
    call c, $c6bc
    ld a, a
    call c, $d7b6
    rst $00
    ld a, a
    cp d
    call nz, Call_007_7fca
    push bc
    or d
    ld d, l
    ld [$9fe3], sp
    inc e
    db $e3
    add c
    ret


    ld a, a
    push bc
    or [hl]
    add $55
    cp [hl]
    or [hl]
    or d
    ld h, $7f
    or c
    reti


    cp d
    call nz, $e7d3
    ld d, c
    ld l, $cb
    rst $20
    ld a, a
    call nz, Call_000_30d3
    pop bc
    db $dd
    ld a, a
    cp e
    cp a
    rst $18
    jp Jump_007_544f


    ret


    ld a, a
    cp d
    or e
    or [hl]
    sbc $dd
    ld d, l
    ret nz

    ret


    cp h
    sbc $33
    ld a, a
    cp b
    jp c, $cfc0

    or h
    rst $20
    ld d, a
    ld [$1901], sp
    ld h, [hl]
    call Call_000_3e78
    jr nc, jr_007_6781

    ld a, $45
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d

jr_007_6781:
    jp Jump_000_0f6a


    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [bc], a
    add e
    rlca
    inc bc
    ld [bc], a
    add e
    nop
    ld [bc], a
    ld c, $06
    ld b, $ff
    ret nc

    ld bc, $073d
    ld [$ffff], sp
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [bc], a
    inc b
    inc b
    inc a
    ld l, b
    or e
    ld h, a
    or b
    ld h, a
    nop
    ld d, $68
    jp Jump_000_3c6c


    dec sp
    rrca
    cp c
    ld h, a
    db $ec
    ld h, a
    db $ed
    inc l
    inc [hl]
    db $76
    ret c

    ld c, $e3
    xor e
    rst $20
    ld a, a
    call nz, $b67f
    or [hl]
    jp c, Jump_007_4fc0

    ld b, a
    sub h
    xor e
    sub e
    jp z, $c57f

    or d
    ret


    or [hl]
    ret z

    and $51
    pop bc
    ld [c], a
    or e
    pop bc
    sbc $ca
    and $4f
    add l
    and a
    xor e
    rrca
    db $e3
    db $d3
    ld a, a
    push bc
    or d
    ret


    or [hl]
    rst $20
    ld d, a
    db $ed
    inc l
    sub $75
    rrca
    db $e3
    jp z, $b67f

    rst $18
    jp $d07f


    ret nz

    and $4f
    ret nz

    ret nz

    or [hl]
    or e
    ld a, a
    ld d, h
    ret


    ld a, a
    cp l
    ld a, [hl-]
    call nc, $ddbb
    ld d, l
    or d
    pop bc
    inc l
    jp $c6b7


    ld a, a
    or c
    add hl, hl
    reti


    ret


    ld d, a
    nop
    ld [bc], a
    rlca
    inc bc
    nop
    rst $38
    rlca
    inc b
    nop
    rst $38
    nop
    inc bc
    ld h, $09
    inc b
    rst $38
    db $d3
    ld bc, $060a
    ld [$ffff], sp
    ld [bc], a
    ld b, $09
    ld a, [bc]
    cp $01
    inc bc
    ld [de], a
    rst $00
    rlca
    inc bc
    inc de
    rst $00
    rlca
    inc b
    ld [de], a
    inc de
    inc de
    add hl, bc
    ld d, $0f
    inc d
    inc d
    jr jr_007_685f

    dec d
    dec d
    rla
    ld a, [de]
    dec bc
    rrca
    ld [$0404], sp
    ld l, $40
    ld e, e
    ld l, b
    ld e, b
    ld l, b
    nop
    ld hl, $c369
    ld l, h
    inc a
    ld h, e
    ld l, b
    sbc d
    ld l, b

jr_007_685f:
    xor [hl]
    ld l, b
    db $db
    ld l, b
    db $ed
    daa
    add h
    ld d, d
    jp $d026


    ld a, a
    or c
    ret c

    ld h, $c4
    or e
    rst $20
    ld c, a
    jp z, $b8d4

    ld a, a
    or c
    push bc
    ret nz

    add $7f
    or c
    or d
    ret nz

    or d
    push bc
    ld d, [hl]
    ld d, c
    or d
    call nc, $dee3
    rst $20
    ld c, a
    jp $d026


    ld a, a
    or [hl]
    or d
    jp Jump_000_30de


    or [hl]
    rst $10
    ld a, a
    ret nc

    push bc
    or d
    inc sp
    rst $20
    ld d, a
    nop
    and d
    rst $08
    jp nz, Jump_007_7fcf

    and e
    rst $08
    jp $50cf


    ld [$243e], sp
    call Call_000_2dc7
    jp Jump_000_0f6a


    db $ed
    daa
    cp $52
    ret z

    ld a, a
    pop de
    cp l
    jp nc, $c3df

    ld a, a
    or [hl]
    call c, $b2b2
    rst $20
    ld c, a
    or [hl]
    ret


    inc l
    ld [c], a
    add $7f
    ld b, c
    xor h
    ld b, c
    add $de
    daa
    ld [c], a
    or e
    ld d, l
    ld b, d
    and a
    dec c
    xor e
    sub e
    ld a, a
    cp l
    reti


    sbc $30
    rst $20
    ld d, a
    db $ed
    daa
    ld b, h
    ld d, e
    ret


    ld a, a
    or c
    or d
    jr nc, @+$51

    ld b, e
    add c
    xor e
    sub e
    ld a, a
    add b
    xor h
    ld b, d
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    ret


    ld d, c
    cp l
    ld a, [hl+]
    cp b
    ld a, a
    jp nz, $b2d6

    ld a, a
    call c, $df2b
    jp Jump_007_404f


    xor c
    db $e3
    ld a, a
    ld b, e
    add c
    xor e
    sub e
    ld a, a
    cp l
    cp b
    push bc
    or d
    cp c
    inc [hl]
    ld d, l
    cp d
    jp c, Jump_007_7f33

    call z, $bed4
    ld a, [hl-]
    ld a, a
    or d
    or d
    ret


    ret z

    ld d, [hl]
    and $57
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
    inc b
    dec e
    rlca
    ld b, $ff
    db $d3
    ld bc, $0809
    inc b
    cp $01
    ld [bc], a
    inc b
    dec b
    ld [$d0ff], sp
    inc bc
    ld b, b
    rlca
    rlca
    rst $38
    rst $38
    inc b
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld [$0404], sp
    ld l, $40
    ld e, h
    ld l, c
    ld e, c
    ld l, c
    nop
    dec d
    ld l, d
    jp Jump_000_3c6c


    ld e, [hl]
    ld l, c
    ld [$3cfa], sp
    rst $10
    bit 0, a
    jr nz, jr_007_6989

    ld hl, $6992
    call Call_000_3c79
    ld bc, $e501
    call Call_000_3e5e
    jr nc, jr_007_6981

    ld hl, $69a9
    call Call_000_3c79
    ld hl, $d73c
    set 0, [hl]
    jr jr_007_698f

jr_007_6981:
    ld hl, $6a07
    call Call_000_3c79
    jr jr_007_698f

jr_007_6989:
    ld hl, $69c4
    call Call_000_3c79

jr_007_698f:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    db $ed
    ld e, d
    ld a, a
    call c, $dfb6
    ret nz

    rst $20
    ld d, c
    cp d
    jp c, $7f26

    adc $bc
    or d
    ld a, a
    ret


    or [hl]
    rst $20
    ld e, b
    db $ed
    add hl, hl
    ld a, [bc]
    ld e, e
    add e
    adc h
    ld b, b
    db $e3
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
    dec bc
    ld d, b
    db $ed
    add hl, hl
    ld e, d
    ld e, e
    or [hl]
    rst $18
    jp $c5d9


    and $4f
    ld e, h
    ld hl, sp-$01
    jp z, $8a7f

    add c
    adc c
    add [hl]
    sub a
    adc e
    adc h
    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    or e
    rst $08
    cp b
    ld a, a
    or d
    cp c
    ld a, [hl-]
    ld c, a
    or c
    or d
    jp Jump_007_7fc9


    call nz, $bcb8
    pop hl
    ld a, a
    ret


    or e
    ret c

    ld [c], a
    cp b
    db $dd
    ld d, l
    cp e
    add hl, hl
    rst $10

jr_007_69fb:
    jp c, Jump_007_7fd9

    or [hl]
    db $d3
    ld a, a
    cp h
    jp c, $b2c5

    rst $20
    ld d, a
    db $ed
    add hl, hl
    dec a
    ld e, e
    ret


    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_007_69fb

    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
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
    jp nc, Jump_000_1201

    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    ld de, $0404
    ld e, [hl]
    ld b, b
    ld b, e
    ld l, d
    dec sp
    ld l, d
    nop
    ld a, b
    ld l, d
    ld a, $0d
    ld [$d2e4], a
    jp Jump_000_3c6c


    ld b, l
    ld l, d
    db $ed
    inc h
    ld h, d
    ld [hl], b
    sbc l
    sub e
    xor e
    sub a
    and [hl]
    add $7f
    or d
    rst $18
    ret nz

    cp c
    inc [hl]
    ld c, a
    rst $08
    rst $18
    cp b
    rst $10
    inc sp
    ld a, a
    cp d
    call c, $d6b2
    ld d, c
    ld d, h
    add $7f
    sbc e
    and l
    xor h
    adc e
    xor [hl]
    inc sp
    ld c, a
    or c
    or [hl]
    reti


    cp b
    ld a, a
    cp e
    cp [hl]
    jp c, $c53a

    or c
    ld d, [hl]
    ld d, a
    ld a, l
    inc bc
    rlca
    ld [bc], a
    nop
    rst $38
    rlca
    inc bc
    nop
    rst $38
    inc b
    inc b

jr_007_6a84:
    nop
    push bc
    nop
    ld bc, $0727
    rlca
    rst $38
    rst $38
    ld bc, $c712
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    add hl, bc
    rst $00
    inc b
    inc b
    ld [$0404], sp
    ld l, $40
    xor c
    ld l, d
    and [hl]
    ld l, d
    nop
    ld hl, sp+$6a
    jp Jump_000_3c6c


    xor l
    ld l, d
    ld [$ed6a], a
    inc h
    push de
    ld [hl], c
    set 3, [hl]
    cp h
    ld a, a
    inc l
    ld [c], a
    or e
    ret nz

    or d
    jp z, $c04f

    ret nz

    or [hl]
    or e
    ld a, a
    add hl, hl
    sbc $b7
    ld h, $7f
    push bc
    or d
    ld a, a
    jr nc, jr_007_6a84

    inc sp
    ld d, c
    or d
    or c
    or d
    daa
    ret c

    ld a, a
    push bc
    inc [hl]
    ret


    ld a, a
    call c, $ca2b
    ld c, a
    or d
    jp nz, $c9d3

    ld a, a
    sub $b3
    add $7f
    jp nz, $b4b6

    reti


    rst $20
    ld d, a
    ld [$013e], sp
    ld [$cd3d], a
    ld a, $54
    call Call_000_3e9d
    jp Jump_000_0f6a


    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [bc], a
    rst $38
    rlca
    inc bc
    ld [bc], a
    rst $38
    nop
    ld [bc], a
    jr nz, @+$0a

    ld b, $ff
    db $d3
    ld bc, $0537
    ld [$d0ff], sp
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    inc c
    inc bc
    inc b
    bit 5, h
    sub l
    ld l, e
    inc h
    ld l, e
    nop
    and c
    ld l, h
    call Call_000_3c6c
    ld a, [$d5e1]
    ld hl, $6b30
    jp Jump_000_3dc7


    ld b, c
    ld l, e
    add l
    ld l, e

Call_007_6b34:
    ld a, $40
    ld [$ccd3], a
    ld a, $01
    ld [$cd38], a
    jp Jump_000_34d0


    ld a, [$d6a7]
    bit 6, a
    ret nz

    ld hl, $6b80
    call Call_000_3509
    ret nc

    ld a, $02
    ld [$d4a7], a
    xor a
    ldh [$b4], a
    ld b, $16
    ld hl, $7fcc
    call Call_000_3620
    ldh a, [$db]
    and a
    jr nz, jr_007_6b73

    ld a, $02
    ldh [$8c], a
    call Call_000_13f1
    call Call_007_6b34
    ld a, $01
    ld [$d5e1], a
    ret


jr_007_6b73:
    ld a, $03
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6a7
    set 6, [hl]
    ret


    inc bc
    inc bc
    inc bc
    inc b
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    xor a
    ld [$cd66], a
    ld [$d5e1], a
    ret


    sbc e
    ld l, e
    ret c

    ld l, e
    dec c
    ld l, h
    ld [$a7fa], sp
    sub $cb
    ld [hl], a
    jr nz, jr_007_6bcf

    ld b, $16
    ld hl, $7fcc
    call Call_000_3620
    ldh a, [$db]
    and a
    jr nz, jr_007_6bc1

    ld hl, $6bd8
    call Call_000_3c79
    call Call_007_6b34
    ld a, $01
    ld [$d5e1], a
    jp Jump_000_0f6a


jr_007_6bc1:
    ld hl, $6c0d
    call Call_000_3c79
    ld hl, $d6a7
    set 6, [hl]
    jp Jump_000_0f6a


jr_007_6bcf:
    ld hl, $6c90
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    adc $5b
    ld a, a
    rst $08
    inc l
    jp nc, Jump_007_7fc5

jr_007_6be2:
    cp c
    or d
    dec sp
    or d
    sbc $4f
    jp z, Jump_007_56e3

    ld d, l
    ret


    inc [hl]
    ld h, $7f
    or [hl]
    call c, $c0b2
    rst $20
    ld d, l
    or l
    rst $18
    call nz, $bf7f
    rst $18
    pop bc
    jp z, $b255

    rst $08
    ld a, a
    jp nz, $bab3

    or e
    ld a, a
    or a
    sbc $bc
    jr nc, jr_007_6be2

    ld d, a
    db $ed
    add hl, hl
    rla
    ld e, h
    jp c, Jump_007_55ca

    or l
    or d
    cp h
    cp a
    or e
    push bc
    ld a, a
    ret


    ret nc

    db $d3
    ret


    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, l
    or h
    and $55
    ld a, $b8
    add $7f
    cp b
    jp c, $e6d9

    ld d, l
    adc d
    xor e
    add [hl]
    xor [hl]
    db $e3
    rst $20
    ld d, b
    ld de, $5100
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, l
    add hl, bc
    add a
    add hl, bc
    add a
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld d, l
    add hl, bc
    add a
    add hl, bc
    add a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, l
    and d
    sbc l
    dec de
    add [hl]
    ld a, a
    adc e
    sub d
    or b
    add $55
    or d
    cp b
    ld a, a
    push bc
    rst $10
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]

jr_007_6c65:
    ld d, l
    call nz, $dfb5
    jp $b27f


    or d
    sub $55
    dec bc
    xor [hl]
    db $e3
    adc h
    db $dd
    ld d, l
    pop de
    cp d
    or e
    ret


    ld a, a
    ld [$93e3], sp
    ret


    ld d, l
    cp c
    or d
    dec sp
    or d
    sbc $c6
    db $d3
    ld a, a
    call c, $c3b9
    or c
    add hl, hl
    sub $b3
    ld d, [hl]
    ld d, a
    db $ed
    add hl, hl
    reti


    ld e, h
    cp d
    ret


    ld a, a
    or c
    or d
    jr nc, jr_007_6c65

    ld a, a
    inc [hl]
    db $e3
    db $d3
    rst $20
    ld d, a
    ld a, [bc]
    inc b
    dec b
    inc bc
    ld [bc], a
    rst $38
    dec b
    inc b
    ld [bc], a
    rst $38
    nop
    inc bc
    ld bc, $00ff
    inc b
    nop
    rst $38
    nop
    ld bc, $0731
    dec b
    rst $38
    db $d3
    ld bc, $c708
    dec b
    inc bc
    add hl, bc
    rst $00
    dec b
    inc b
    db $f4
    add $00
    inc bc
    push af
    add $00
    inc b
    ld d, $6b
    ld l, d
    rla
    ld [bc], a
    add hl, bc
    ld [$1801], sp
    ld l, h
    ld l, c
    add hl, de
    inc c
    inc bc
    inc b
    adc [hl]
    ld l, l
    ld e, [hl]
    ld l, l
    db $e3
    ld l, h
    nop
    ld h, h
    ld l, l
    call Call_000_3c6c
    ld hl, $6cf0
    ld a, [$d5b5]
    call Call_000_3dc7
    ret


    db $f4
    ld l, h
    scf
    ld l, l
    ld a, [$d6a7]
    bit 6, a
    ret nz

    ld hl, $6d32
    call Call_000_3509
    ret nc

    ld a, $01
    ld [$d4a7], a
    xor a
    ldh [$b4], a
    ld b, $16
    ld hl, $7fcc
    call Call_000_3620
    ldh a, [$db]
    and a
    jr nz, jr_007_6d26

    ld a, $02
    ldh [$8c], a
    call Call_000_13f1
    call Call_007_6d47
    ld a, $01
    ld [$d5b5], a
    ret


jr_007_6d26:
    ld hl, $d6a7
    set 6, [hl]
    ld a, $03
    ldh [$8c], a
    jp Jump_000_13f1


    ld [bc], a
    inc bc
    ld [bc], a
    inc b
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    xor a
    ld [$cd66], a
    ld [$d5b5], a
    ret


Call_007_6d47:
    ld hl, $d6af
    set 7, [hl]
    ld a, $80
    ld [$ccd3], a
    ld a, $01
    ld [$cd38], a
    xor a
    ld [$c206], a
    ld [$cd3b], a
    ret


    sbc e
    ld l, e
    ret c

    ld l, e
    dec c
    ld l, h
    ld a, [bc]
    inc b
    dec b
    inc bc
    ld [bc], a
    rst $38
    dec b
    inc b
    ld [bc], a
    rst $38
    nop
    inc bc
    ld bc, $00ff
    inc b
    ld bc, $00ff
    ld bc, $0631
    ld a, [bc]
    rst $38
    jp nc, $0801

    rst $00
    dec b
    inc bc
    add hl, bc
    rst $00
    dec b
    inc b
    db $f4
    add $00
    inc bc
    push af
    add $00
    inc b
    ld d, $6b
    ld l, d
    rla
    ld [bc], a
    add hl, bc
    ld [$1801], sp
    ld l, h
    ld l, c
    add hl, de
    inc c
    inc b
    inc bc
    ld d, l
    ld l, [hl]
    dec h
    ld l, [hl]
    and [hl]
    ld l, l
    nop
    dec hl
    ld l, [hl]
    call Call_000_3c6c
    ld a, [$d5e2]
    ld hl, $6db3
    call Call_000_3dc7
    ret


    adc $6d
    ld [de], a
    ld l, [hl]

Call_007_6db7:
    ld hl, $d6af
    set 7, [hl]
    ld a, $20
    ld [$ccd3], a
    ld a, $01
    ld [$cd38], a
    xor a
    ld [$c206], a
    ld [$cd3b], a
    ret


    ld a, [$d6a7]
    bit 6, a
    ret nz

    ld hl, $6e0d
    call Call_000_3509
    ret nc

    ld a, $08
    ld [$d4a7], a
    xor a
    ldh [$b4], a
    ld b, $16
    ld hl, $7fcc
    call Call_000_3620
    ldh a, [$db]
    and a
    jr nz, jr_007_6e00

    ld a, $02
    ldh [$8c], a
    call Call_000_13f1
    call Call_007_6db7
    ld a, $01
    ld [$d5e2], a
    ret


jr_007_6e00:
    ld a, $03
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6a7
    set 6, [hl]
    ret


    inc bc
    inc bc
    inc b
    inc bc
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    xor a
    ld [$cd66], a
    ld [$d5e2], a
    ld [$d97c], a
    ret


    sbc e
    ld l, e
    ret c

    ld l, e
    dec c
    ld l, h
    ld a, [bc]
    inc b
    inc bc
    nop
    inc bc
    rst $38
    inc b
    nop
    inc bc
    rst $38
    inc bc
    dec b
    nop
    rst $38
    inc b
    dec b
    ld bc, $00ff
    ld bc, $0531
    rlca
    rst $38
    ret nc

    ld bc, $c6fb
    inc bc
    nop
    inc b
    rst $00
    inc b
    nop
    db $fd
    add $03
    dec b
    ld b, $c7
    inc b
    dec b
    inc e
    rra
    dec e
    ld [hl], b
    ld hl, $6e6f
    dec h
    ld l, l
    jr @+$20

    add hl, de
    inc c
    inc b
    inc bc
    rla
    ld l, a
    rst $20
    ld l, [hl]
    ld l, l
    ld l, [hl]
    nop
    db $ed
    ld l, [hl]
    call Call_000_3c6c
    ld hl, $6e79
    ld a, [$d5b6]
    jp Jump_000_3dc7


    sub h
    ld l, [hl]
    rst $10
    ld l, [hl]

Call_007_6e7d:
    ld hl, $d6af
    set 7, [hl]
    ld a, $10
    ld [$ccd3], a
    ld a, $01
    ld [$cd38], a
    xor a
    ld [$c206], a
    ld [$cd3b], a
    ret


    ld a, [$d6a7]
    bit 6, a
    ret nz

    ld hl, $6ed2
    call Call_000_3509
    ret nc

    ld a, $02
    ld [$d4a7], a
    xor a
    ldh [$b4], a
    ld b, $16
    ld hl, $7fcc
    call Call_000_3620
    ldh a, [$db]
    and a
    jr nz, jr_007_6ec6

    ld a, $02
    ldh [$8c], a
    call Call_000_13f1
    call Call_007_6e7d
    ld a, $01
    ld [$d5b6], a
    ret


jr_007_6ec6:
    ld hl, $d6a7
    set 6, [hl]
    ld a, $03
    ldh [$8c], a
    jp Jump_000_13f1


    inc bc
    ld [bc], a
    inc b
    ld [bc], a
    rst $38
    ld a, [$cd38]
    and a
    ret nz

    call Call_000_3e07
    xor a
    ld [$cd66], a
    ld [$d5b6], a
    ret


    sbc e
    ld l, e
    ret c

    ld l, e
    dec c
    ld l, h
    ld a, [bc]
    inc b
    inc bc
    nop
    nop
    rst $38
    inc b
    nop
    ld bc, $03ff
    dec b
    ld [bc], a
    rst $38
    inc b
    dec b
    inc bc
    rst $38
    nop
    ld bc, $0531
    ld b, $ff
    ret nc

    ld bc, $c6fb
    inc bc
    nop
    inc b
    rst $00
    inc b
    nop
    db $fd
    add $03
    dec b
    ld b, $c7
    inc b
    dec b
    inc e
    rra
    dec e
    ld [hl], b
    ld hl, $6e6f
    dec h
    ld l, l
    jr jr_007_6f40

    add hl, de
    inc c
    inc b
    inc b
    nop
    ld b, b
    scf
    ld l, a
    cpl
    ld l, a
    nop
    ld h, [hl]
    ld l, a
    ld a, $13
    ld [$d2e4], a
    jp Jump_000_3c6c


    add hl, sp
    ld l, a
    db $ed
    dec h
    ld e, l
    ld d, l
    jp z, $d67f

jr_007_6f40:
    cp b
    ld a, a
    or d
    cp b
    ret


    and $4f
    adc a
    sbc l
    sbc a
    adc e
    ld a, a
    adc e
    sub d
    or b
    ret


    ld a, a
    ld [de], a
    ld b, b
    db $e3
    sub e
    ld d, l
    or d
    db $db
    or d
    db $db
    ld a, a
    or e
    rst $18
    jp Jump_007_7fc3


    dec a
    sbc $d8
    sub $c8
    ld d, a
    ld a, [bc]
    inc bc
    rlca
    inc bc
    inc b
    rst $38
    rlca
    inc b
    inc b
    rst $38
    inc b
    inc b
    ld bc, $0079
    ld bc, $080d
    rlca
    rst $38
    rst $38
    ld bc, $c712
    rlca
    inc bc
    inc de
    rst $00
    rlca
    inc b
    add hl, bc
    rst $00
    inc b
    inc b
    ld d, $12
    inc d
    jr jr_007_6ffe

    xor l
    ld l, a
    sub h
    ld l, a
    nop
    sub c
    ld [hl], b
    call Call_000_3c6c
    ld hl, $6fc9
    ld de, $6fa7
    ld a, [$d5e2]
    call Call_000_31a8
    ld [$d5e2], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld b, d
    ld [hl], b
    ld c, b
    ld [hl], b
    ld c, [hl]
    ld [hl], b
    ld d, h
    ld [hl], b
    ld e, d
    ld [hl], b
    ld h, b
    ld [hl], b
    ld h, [hl]
    ld [hl], b
    ld l, h
    ld [hl], b
    ld [hl], d
    ld [hl], b
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    push bc
    rrca
    ld bc, $5200
    rst $10
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld [bc], a
    nop
    ld d, d
    rst $10
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    inc bc
    nop
    ld d, d
    rst $10
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    inc b
    nop
    ld d, d
    rst $10
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    dec b
    nop
    ld d, d
    rst $10
    ld a, b

jr_007_6ffe:
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld b, $00
    ld d, d
    rst $10
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    rlca
    nop
    ld d, d
    rst $10
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld [$5200], sp
    rst $10
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    ld a, b
    ld [hl], b
    add hl, bc
    nop
    ld d, d
    rst $10
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    ld a, [hl]
    ld [hl], b
    rst $38

jr_007_7036:
    call Call_000_3214
    ld a, [$d97c]
    ld [$d5e2], a
    jp Jump_000_0f6a


    ld [$c921], sp
    ld l, a
    jr jr_007_7036

    ld [$d521], sp
    ld l, a
    jr jr_007_7036

    ld [$e121], sp
    ld l, a
    jr jr_007_7036

    ld [$ed21], sp
    ld l, a
    jr jr_007_7036

    ld [$f921], sp
    ld l, a
    jr jr_007_7036

    ld [$0521], sp
    ld [hl], b
    jr jr_007_7036

    ld [$1121], sp
    ld [hl], b
    jr jr_007_7036

    ld [$1d21], sp
    ld [hl], b
    jr jr_007_7036

    ld [$2921], sp
    ld [hl], b
    jr jr_007_7036

    db $ed
    dec h
    dec hl
    ld e, a
    rst $20
    ld d, a
    nop
    and c
    ret z

    add c
    ld a, a
    ld a, a
    ld d, b
    ld [$4b3e], sp
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    ld l, $03
    inc hl
    inc b
    inc bc
    rst $38
    inc hl
    dec b
    inc bc
    rst $38
    dec bc
    nop
    inc bc
    rst $38
    nop
    ld c, $3d
    jr jr_007_70b1

    rst $38
    rst $38
    ld b, c
    ld b, $28
    dec a
    ld d, $24
    rst $38
    rst $38
    ld b, d
    ld b, $28

jr_007_70b1:
    dec a
    dec e
    add hl, de
    rst $38
    rst $38
    ld b, e
    ld b, $28
    dec a
    ld d, $1d
    rst $38
    rst $38
    ld b, h
    adc l
    dec hl
    dec a
    ld h, $1b
    rst $38
    rst $38
    ld b, l
    ld b, $28
    dec a
    jr nz, jr_007_70ea

    rst $38
    rst $38
    ld b, [hl]
    ld b, $28
    dec a
    ld [de], a
    add hl, de
    rst $38
    rst $38
    ld b, a
    adc l
    dec hl
    dec a
    inc h
    add hl, hl
    rst $38
    rst $38
    ld c, b
    ld b, $28
    add hl, bc
    dec c
    ld [$d1ff], sp
    ld c, c
    ld c, e
    ld [hl-], a
    dec a

jr_007_70ea:
    dec e
    dec bc
    rst $38
    rst $38
    adc d
    ld h, $3d
    rlca
    jr nz, @+$01

    rst $38
    adc e
    inc hl
    dec a
    rlca
    ld h, $ff
    rst $38
    adc h
    jr z, jr_007_713c

    inc h
    ld e, $ff
    rst $38
    adc l
    pop hl
    dec a
    inc h
    jr @+$01

    rst $38
    adc [hl]
    jp hl


    cp a
    ret z

    inc hl
    inc b
    cp a
    ret z

    inc hl
    dec b
    add l
    rst $00
    dec bc
    nop
    ld b, b
    ld h, c
    ld h, c
    ld h, c
    ld l, b
    ld h, l
    ld h, l
    ld l, c
    ld h, l
    ld h, l
    ld h, l
    ld h, l
    ld l, c
    ld h, l
    ld h, l
    ld h, l
    ld h, l
    ld h, l
    ld h, l
    ld l, c
    ld b, h
    rlca
    ld b, $0e
    ld [hl], b
    rlca
    ld sp, $065d
    rlca
    rlca
    ld c, $46
    ld b, $1a
    dec [hl]

jr_007_713c:
    dec [hl]
    add hl, de
    ld b, $5d
    ld b, h
    ld c, $0e
    ld c, $68
    ld a, [hl+]
    ld h, a
    ld l, c
    ld h, e
    dec hl
    ld h, c
    ld e, c
    ld b, [hl]
    jr c, @+$33

    ld b, $35
    inc e
    ld c, $5d
    ld b, b
    ld h, e
    ld c, $67
    ld e, h
    jr c, @+$33

    ld e, l
    ld h, e
    ld c, $06
    ld b, h
    ld b, [hl]
    ld b, $0e
    ld b, $38
    ld c, $31
    ld e, l
    ld b, h
    ld c, $0e
    ld c, $5c
    ld b, $31
    ld e, l
    ld c, $0e
    ld sp, $4644
    jr c, @+$10

    ld b, $0e
    ld b, $06
    ld e, l
    ld [hl], b
    ld c, $0e
    ld c, $5c
    jr c, jr_007_7191

    ld [hl], c
    ld c, $0e
    ld c, $44
    ld b, [hl]
    ld c, $0e
    jr c, jr_007_719b

    ld sp, $5d06
    ld l, b

jr_007_7191:
    ld h, l
    ld h, l
    ld b, c
    ld b, b
    ld b, c
    ld h, l
    ld l, c
    ld h, e
    dec hl
    ld h, c

jr_007_719b:
    ld b, h
    ld d, [hl]
    ld c, c
    ld e, b
    ld c, $57
    ld c, c
    ld c, c
    ld d, c
    ld e, h
    rlca
    ld c, $0e
    ld [hl], b
    ld c, $31
    ld e, l
    ld c, c
    ld c, c
    ld c, c
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld e, b
    ld d, d
    ld b, [hl]
    ld e, h
    ld c, $0e
    ld c, $52
    ld c, $0e
    ld e, l
    ld b, $1d
    dec e
    dec e
    ld c, $1d
    dec e
    dec e
    dec e
    ld c, $44
    ld b, [hl]
    ld h, b
    ld h, c
    ld a, [hl+]
    ld c, $5c
    ld b, $38
    ld e, l
    rlca
    ld b, $1a
    dec [hl]
    inc e
    dec [hl]
    dec [hl]
    dec [hl]
    dec e
    ld c, $44
    ld b, [hl]
    ld h, h
    ld c, $0e
    ld c, $44
    rlca
    ld c, $71
    ld c, $1d
    dec e
    dec e
    dec e
    dec e
    dec e
    dec e
    dec e
    ld c, $44
    ld b, [hl]
    ld b, h
    ld sp, $6161
    ld a, [hl+]
    dec hl
    ld h, c
    ld h, d
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
    ld d, l
    ld b, [hl]
    ld b, h
    ld c, $0e
    rlca
    ld b, $38
    ld c, $66
    rlca
    ld b, $38
    ld b, $06
    ld b, $07
    ld sp, $0706
    ld c, $5d
    ld l, b
    ld h, e
    ld c, $67
    ld l, b
    ld h, l
    ld a, [hl+]
    ld d, [hl]
    ld c, $0e
    ld c, $31
    rlca
    ld c, $0e
    ld c, $07
    ld c, $31
    ld e, l
    ld e, h
    jr c, @+$10

    ld b, $6b
    ld c, $0e
    ld c, $0e
    ld b, $0e
    ld c, $0e
    ld sp, $3106
    ld b, $06
    ld b, $5d
    ld e, h
    ld c, $31
    ld b, $6b
    ld a, [hl+]
    ld h, a
    ld h, c
    ld h, c
    ld h, l
    ld h, c
    ld h, c
    ld b, b
    ld h, e
    ld b, $2b
    ld h, c
    ld h, c
    ld h, l
    ld l, c
    ld b, h
    ld c, $0e
    ld sp, $0e5c
    ld c, $07
    ld b, $0e
    ld c, $06
    ld b, h
    ld e, $0e
    dec e
    dec e
    jr nz, jr_007_7287

    ld b, [hl]
    ld c, b
    ld e, b
    inc l
    ld d, a
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld de, $0404
    ld e, [hl]
    ld b, b
    sub l
    ld [hl], d

jr_007_7287:
    adc h
    ld [hl], d
    nop
    call nc, $cd72
    ld l, h
    inc a
    ld a, $16
    ld [$d2e4], a
    ret


    sub a
    ld [hl], d
    db $ed
    dec h
    inc d
    ld h, b
    ret nz

    ld a, a
    db $d3
    sbc $30
    rst $20
    ld c, a
    cp d
    ret


    ld a, a
    push bc
    ld h, $e3
    or d
    ld a, a
    inc [hl]
    or e
    cp b
    jp nz, Jump_007_55e7

    ld [de], a
    or b
    rlca
    rrca
    ld h, $7f
    adc $df
    ret nz

    sbc $30
    call nz, Call_007_51e7
    sub e
    add [hl]
    xor c
    ld a, a
    adc e
    sub d
    or b
    rst $08
    inc sp
    ld c, a
    jp nz, $26c5

    rst $18
    call nz, Call_007_7fd9
    cp a
    or e
    jr nc, @-$17

    ld d, a
    ld a, l
    inc bc
    rlca
    ld [bc], a
    inc b
    rst $38
    rlca
    inc bc
    inc b
    rst $38
    inc b
    inc b
    ld bc, $00c5
    ld bc, $070b
    ld b, $ff
    rst $38
    ld bc, $c712
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    add hl, bc
    rst $00
    inc b
    inc b
    ld [$0404], sp
    ld l, $40
    dec b
    ld [hl], e
    ld [bc], a
    ld [hl], e
    nop
    db $ed
    ld [hl], e
    jp Jump_000_3c6c


    add hl, bc
    ld [hl], e
    adc $73
    ld [$5ffa], sp
    rst $10
    bit 6, a
    ld hl, $738b
    jr nz, jr_007_732f

    ld hl, $7335
    call Call_000_3c79
    ld bc, $c501
    call Call_000_3e5e
    jr nc, jr_007_732c

    ld hl, $d75f
    set 6, [hl]
    ld hl, $736d
    jr jr_007_732f

jr_007_732c:
    ld hl, $73bf

jr_007_732f:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld bc, $565d
    rst $20
    ld c, a
    ret nc

    jp nz, $dfb6

    pop bc
    ldh [$df], a
    ret nz

    call c, $e7c8
    ld d, c
    call c, $bcc0
    ret


    ld a, a
    cp d
    call nz, Call_000_304f
    jp c, $d3c6

    ld a, a
    or d
    call c, $b2c5
    inc sp
    ld d, l
    cp d
    jp c, $b17f

    add hl, hl
    reti


    ld a, a
    or [hl]
    rst $10
    ld d, l
    ld d, [hl]
    ld a, a

jr_007_7367:
    or l
    ret z

    ld h, $b2
    sub $58
    db $ed
    add hl, hl
    or l
    ld e, l
    or l
    sbc $c5
    ret


    cp d
    or [hl]
    rst $10
    ld c, a
    swap e
    sbc $9d
    adc e
    xor e
    or $f8
    db $dd
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    ld de, $ed50
    add hl, hl
    ld d, e
    ld e, l
    sbc l
    adc e
    xor e
    or $f8
    jp z, $bf7f

    rst $10
    db $dd
    call nz, $e73c
    ld c, a
    call nz, $d3c3
    ld a, a
    dec a
    sbc $d8
    push bc
    ld d, l
    cp l
    ld a, [hl-]
    rst $10
    cp h
    or d
    ld a, a
    call c, Call_007_7f2b
    push bc
    ret


    rst $20
    ld d, c
    jr nc, jr_007_7367

    inc l
    add $7f
    jp nz, $dfb6

    jp $e7c8


    ld d, a
    db $ed
    add hl, hl
    pop af
    ld e, l
    ld a, a
    add $d3
    jp nz, $b27f

    rst $18
    ld b, h
    or d
    sub $57
    ld [$e021], sp
    ld [hl], e
    call Call_000_3c79
    ld a, $23
    call Call_000_2dc7
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    rrca
    ld e, [hl]
    ret c

    and [hl]
    ld [hl], d
    add [hl]
    xor [hl]
    add c
    xor e
    rst $20
    ld d, a
    ld a, [bc]
    ld [bc], a
    rlca
    ld [bc], a
    ld [$07ff], sp
    inc bc
    ld [$00ff], sp
    ld [bc], a
    dec e
    rlca
    ld b, $ff
    db $d3
    ld bc, $0809
    ld a, [bc]
    cp $00
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    inc c
    inc b
    dec b
    ld c, [hl]
    ld [hl], l
    ld [hl], l
    ld [hl], h
    add hl, de
    ld [hl], h
    nop
    inc h
    ld [hl], l
    call Call_000_3c6c
    ld hl, $7434
    ld a, [$d58d]
    call Call_000_3dc7
    ld a, [$d2e0]
    cp $04
    ld a, $22
    jr c, jr_007_7430

    ld a, $21

jr_007_7430:
    ld [$d2e4], a
    ret


    ld a, [hl-]
    ld [hl], h
    ld h, e
    ld [hl], h
    ld [hl], h
    ld [hl], h
    ld hl, $744b
    call Call_000_3509
    ret nc

    xor a
    ldh [$b4], a
    ld a, $01
    ldh [$8c], a
    jp Jump_000_13f1


    ld [bc], a
    inc b
    ld [bc], a
    dec b
    rst $38

Call_007_7450:
    ld a, $01
    ld [$cd38], a
    ld a, $80
    ld [$ccd3], a
    ld [$c109], a
    ld [$cd66], a
    jp Jump_000_34d0


    ld a, [$cd38]
    and a
    ret nz

    xor a
    ld [$cd66], a
    call Call_000_3e07
    ld a, $00
    ld [$d58d], a
    ret


    ld [hl], a
    ld [hl], h
    ld [$d5fa], sp
    jp nc, Jump_007_47cb

    jr nz, jr_007_748c

    ld hl, $749a
    call Call_000_3c79
    call Call_007_7450
    ld a, $01
    jr jr_007_7494

jr_007_748c:
    ld hl, $74fb
    call Call_000_3c79
    ld a, $02

jr_007_7494:
    ld [$d58d], a
    jp Jump_000_0f6a


    nop
    ld d, c
    db $ec
    ld b, b
    ld d, h
    ld a, a
    cp e
    or a
    jp z, $ce4f

    sbc $c4
    or e
    add $7f
    jp nz, $b2d6

    ld d, l
    ld d, h
    ld e, l
    jr nc, @-$45

    ld a, a
    call nz, $dab5
    rst $08
    cp l
    ld d, c
    or c
    push bc
    ret nz

    jp z, $cf7f

    jr nc, jr_007_7510

    rlca
    and a
    db $e3
    add hl, de
    xor h
    dec bc
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $cf7f


    cp [hl]
    sbc $c8
    rst $20
    ld d, b
    ld [$a53e], sp
    call Call_000_3788
    call Call_000_3790
    ld hl, $74e0
    ret


    db $ed
    dec l
    and e
    ld h, a
    ret c

    ld a, a
    inc sp
    cp l
    or [hl]
    rst $10
    ld c, a
    call nz, $bdb5
    ld a, a
    call c, $c6b9
    jp z, $b27f

    or a
    rst $08
    cp [hl]
    sbc $e7
    ld d, a
    db $ed
    add hl, hl
    ld sp, $ac5e
    rst $20
    ld c, a
    cp a
    jp c, Jump_007_7fca

    ret nz

    cp h
    or [hl]
    add $7f
    rlca
    and a
    db $e3
    add hl, de
    xor h

jr_007_7510:
    dec bc
    rst $20
    ld d, l
    inc [hl]
    or e
    cpl
    ld a, a
    call nz, $dfb5
    jp $b87f


    jr nc, @-$43

    or d
    rst $20
    ld d, b
    dec bc
    ld d, b
    ld a, [bc]
    inc b
    rlca
    inc b
    nop
    rst $38
    rlca
    dec b
    nop
    rst $38
    nop
    inc b
    nop
    rst $38
    nop
    dec b
    ld bc, $00ff
    ld bc, $0631
    ld a, [bc]
    rst $38
    jp nc, $1701

    rst $00
    rlca
    inc b
    rla
    rst $00
    rlca
    dec b
    or $c6
    nop
    inc b
    or $c6
    nop
    dec b
    inc bc
    ld l, $28
    cpl
    inc bc
    nop
    nop
    inc b
    nop
    nop
    nop
    nop
    inc b
    nop
    nop
    nop
    inc l
    inc b
    dec l
    nop
    db $10
    inc b
    inc b
    ld bc, $3879
    db $76
    ld l, [hl]
    ld [hl], l
    nop
    db $db
    ld a, b
    call Call_000_3c6c
    ld a, [$d5e0]
    ld hl, $757a
    jp Jump_000_3dc7


    add [hl]
    ld [hl], l
    add a
    ld [hl], l
    xor d
    ld [hl], l
    ret


    ld [hl], l
    ld de, $2b76
    db $76
    ret


    ld a, [$c109]
    and a
    ld de, $75a0
    jr nz, jr_007_7593

    ld de, $75a4

jr_007_7593:
    ld a, $01
    ldh [$8c], a
    call Call_000_3684
    ld a, $02
    ld [$d5e0], a
    ret


    ld b, b
    ld b, b
    ld b, b
    rst $38
    ret nz

    ld b, b
    ld b, b
    add b
    ld b, b
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    ld a, $61
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld hl, $d771
    set 6, [hl]
    xor a
    ld [$cd66], a
    ld a, $03
    ld [$d5e0], a
    ret


    ld a, [$d771]
    bit 3, a
    ret z

    ld a, $f0
    ld [$cd66], a
    ld a, $02
    ld [$cf0e], a
    ld a, $0c
    ldh [$eb], a
    ld a, $40
    ldh [$ec], a
    ld a, $06
    ldh [$ed], a
    ld a, $05
    ldh [$ee], a
    call Call_000_3341
    ld a, $62
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld c, $08
    call Call_000_3781
    ld a, $02
    ldh [$8c], a
    ld de, $760b
    call Call_000_3684
    ld a, $04
    ld [$d5e0], a
    ret


    nop
    ret nz

    ret nz

    ret nz

    nop
    rst $38
    ld a, [$d6af]
    bit 0, a
    ret nz

    xor a
    ld [$cd66], a
    ld hl, $d771
    set 5, [hl]
    ld hl, $d770
    set 0, [hl]
    ld a, $00
    ld [$d5e0], a
    ret


    ld a, $04
    ldh [$8c], a
    call Call_000_13f1
    ld a, $00
    ld [$d5e0], a
    ret


    ld b, c
    db $76
    ld e, [hl]
    ld [hl], a
    and c
    ld a, b
    ld b, b
    db $76
    db $fd
    ld [$6921], sp
    db $76
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_007_765e

jr_007_7651:
    ld hl, $76e7
    call Call_000_3c79
    ld a, $01
    ld [$d5e0], a
    jr jr_007_7666

jr_007_765e:
    ld hl, $771a
    call Call_000_3c79
    jr jr_007_7651

jr_007_7666:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld l, b
    ld e, [hl]
    call c, Call_007_4fe7
    ld a, $b8
    ld a, a
    ld d, h
    ld d, [hl]
    rst $20
    ld d, l
    ld d, [hl]
    ld a, a
    pop bc
    ldh [$b3], a
    call c, $e7b2
    ld d, c
    call c, $cab2
    ld a, a
    sbc l
    adc d
    add [hl]
    rst $20
    ld c, a
    set 0, h
    ld a, a
    sub $de
    inc sp
    ld a, a
    ld d, h
    sbc l
    sub l
    add b
    call nc, Call_007_55e7
    or c
    xor h
    ld a, a
    push bc
    sbc $d4
    ld a, a
    cp a
    ret


    jp nc, $e6ca

    ld d, l
    or c
    sbc $bb
    sbc $7f
    cp h
    sbc $d6
    or e
    ld a, a
    cp h
    jp $decd


    push bc
    ld d, c
    sbc h
    xor e
    sub e
    call nc, $e733
    ld c, a
    inc l
    rst $18
    cp c
    sbc $c6
    ld a, a
    cp h
    rst $18
    ld b, h
    or d
    ld a, a
    cp h
    jp Jump_007_5455


    call nz, $b87f
    rst $18
    jp nz, $c3b2

    ld a, a
    db $d3
    or e
    ret nz

    sbc $d4
    ld d, c
    push bc
    xor h
    rst $20
    ld c, a
    ret nz

    cp l
    cp c
    jp $b87f


    jp c, $decd

    and $57
    db $ed
    add hl, hl
    ld [hl-], a
    ld e, a
    ld c, a
    jp $bfde


    or e
    ld a, a
    sbc l
    adc e
    xor e
    add $7f

jr_007_76f6:
    jp z, $d9b2

    cp e
    or [hl]
    or d
    ld d, l
    inc a
    sbc $d8
    ld a, a
    ld b, d
    xor b
    rlca
    and l
    sbc a
    db $dd
    ld a, a
    ret nz

    ret


    pop de
    inc sp
    rst $20
    ld d, l
    cp a
    or e
    call nc, $bf7f
    cp d
    ret


    ld a, a
    ld e, e
    call nc, Call_007_57e7
    db $ed
    add hl, hl
    sbc b
    ld e, a
    or c
    ld d, [hl]
    ld c, a
    jp nz, $c0d2

    or d
    ld a, a
    cp d
    call nz, $b27f
    call c, $c4de
    or d
    jp $d655


    xor h
    ld d, [hl]
    ld a, a
    or d
    db $db
    or l
    call nz, $e7ba
    ld d, l
    add $b8
    or d
    ret z

    db $e3
    xor h
    ld d, l
    jr nc, jr_007_76f6

    call nz, $d8b3
    ld [c], a
    or e
    rst $20
    ld d, l
    adc $c5
    rst $20
    ld a, a
    add h
    xor h
    adc b
    db $e3
    ld a, a
    call nc, $e7c5
    ld d, l
    or a
    rst $08
    ret c

    call nc, $58e7
    ld [$71fa], sp
    rst $10
    bit 4, a
    jr nz, jr_007_7793

    ld hl, $77a4
    call Call_000_3c79
    ld bc, $3f01
    call Call_000_3e5e
    jr nc, jr_007_779b

    ld hl, $7811
    call Call_000_3c79
    ld hl, $d771
    set 4, [hl]
    ld a, $07
    ld [$cc4d], a
    ld a, $15
    call Call_000_3e9d
    ld a, $09
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d

jr_007_7793:
    ld hl, $783c
    call Call_000_3c79
    jr jr_007_77a1

jr_007_779b:
    ld hl, $782b
    call Call_000_3c79

jr_007_77a1:
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld a, [de]
    ld h, b
    ld [hl], d
    call nc, $e3b1
    rst $20
    ld c, a
    or l
    or l
    or a
    add $7f
    or l
    or l
    or a
    add $7f
    ret nz

    cp l
    or [hl]
    rst $18
    ret nz

    call c, Call_007_51e7
    inc sp
    ld d, [hl]
    ld a, a
    or c
    sbc $bb
    sbc $e7
    ld c, a
    call c, $c9c3
    ld a, a
    ld d, h
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
    or a
    ret nz

    ret


    ld a, a
    pop bc
    ldh [$b3], a
    sbc $b6
    and $55
    push bc
    sbc $d4
    ld a, a
    or l
    db $d3
    db $db
    push bc
    or d
    push bc
    db $e3
    ld d, l
    or c
    or c
    ld a, a
    cp a
    call nc, Call_007_51e7
    or l
    jp c, Jump_007_7fb2

    rst $18
    pop bc
    pop hl
    db $e3
    ret


    db $d3
    ld c, a
    push bc
    sbc $d4
    cp c
    inc [hl]
    ld d, [hl]
    ld a, a
    cp d
    jp c, $d47f

    reti


    call c, $58e7
    db $ed
    add hl, hl
    pop hl
    ld h, b
    sbc l
    adc d
    add [hl]
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
    ld de, $5006
    db $ed
    add hl, hl
    ld [bc], a
    ld h, d
    ld a, a
    or d
    rst $18
    ld b, h
    or d
    inc sp
    ld a, a
    db $d3
    jp $decd


    sub $57
    db $ed
    add hl, hl
    ld c, $61
    add a
    sub b
    add hl, de
    ret


    ld a, a
    ret nc

    push bc
    call nz, $4fc6
    adc d
    xor e
    sub e
    add b
    xor e
    sub [hl]
    ld a, a
    ld a, [hl+]
    or e
    ld h, $7f
    or a
    call nz, $c9de
    call nc, Call_007_5455
    ld a, a
    ld e, l
    db $d3
    ld d, l
    daa
    ld [c], a
    or e
    cp e
    sbc $7f
    cp b
    reti


    ld a, a
    rst $10
    cp h
    or d
    inc sp
    ld d, c
    sub b
    adc b
    xor h
    sub e
    ld a, a
    db $d3
    db $db
    ret nz

    ret


    jp z, $b47f

    or h
    sbc $d4
    cp c
    inc [hl]
    ld c, a
    ld b, b
    db $e3
    sub d
    or b
    call nz, Call_007_7fb6
    cp l
    or a
    call nc, $c57f
    or d
    or [hl]
    rst $10
    push bc
    ld d, l
    or [hl]
    call c, $c6d8
    ld a, a
    or d
    rst $18
    jp $b17f


    cp a
    sbc $33
    or h
    push bc
    ld d, a
    ld [$ab21], sp
    ld a, b
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    cpl
    ld h, d
    ld [hl], d
    cp a
    call nc, Call_007_51e7
    call c, $c9c3
    ld a, a
    ld d, h
    ld a, a
    adc c
    and a
    add a
    adc e
    xor a
    xor e
    ld c, a
    pop bc
    dec sp
    rst $18
    call nz, $307f
    cp c
    ld a, a
    ret nc

    cp [hl]
    ret nz

    db $db
    or [hl]
    and $55
    call c, $c9c3
    ld a, a
    ld e, e
    ld a, a
    ret nc

    jp $6ed0


    ld d, a
    dec c
    ld [bc], a
    rlca
    ld [bc], a
    nop
    rst $38
    rlca
    inc bc
    nop
    rst $38
    nop
    inc bc
    dec b
    add hl, bc
    ld a, [bc]
    rst $38
    rst $38
    ld bc, $080c
    ld [$ffff], sp
    ld [bc], a
    inc c
    add hl, bc
    ld a, [bc]
    rst $38
    rst $38
    inc bc
    ld [de], a
    rst $00
    rlca
    ld [bc], a
    ld [de], a
    rst $00
    rlca
    inc bc
    inc b
    dec b
    ld b, $07
    ld [$0a09], sp
    dec bc
    ld bc, $0e02
    ld c, $03
    inc c
    inc bc
    inc bc
    call Call_000_373e
    ld hl, $7970
    call Call_000_3c79
    ld hl, $7937
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_007_792e

    ld a, $56
    call Call_000_3e9d

jr_007_792e:
    ld hl, $7955
    call Call_000_3c79
    jp Jump_000_374a


    db $ed
    add hl, hl
    ld a, [c]
    ld h, d
    or d
    ret


    ld a, a
    ld d, h
    dec l
    or [hl]
    sbc $dd
    ld c, a
    set 4, d
    or e
    or [hl]
    ld a, a
    cp h
    jp $d37f


    rst $10
    or d
    ld a, a
    rst $08

jr_007_7951:
    cp l
    or [hl]
    and $57
    db $ed
    add hl, hl
    jr z, jr_007_79bc

    db $e3
    add [hl]
    inc de
    ret


    ld a, a
    ld e, e
    call nz, $4fc9
    cp [hl]
    jp nz, $b82f

jr_007_7966:
    db $dd
    ld a, a
    or l
    call c, $c0df
    rst $20
    ld d, b
    dec c
    ld d, b
    db $ed
    add hl, hl
    add l
    ld h, d
    inc de
    ret


    ld a, a
    ld e, e
    call nz, $c27f
    push bc
    or d
    jr nc, jr_007_7966

    ld d, c
    ld d, h
    ld a, a
    dec l
    or [hl]
    sbc $4f
    set 4, d
    or e
    or [hl]
    ld a, a
    adc e
    adc h
    sub d
    sbc a
    db $dd
    ld a, a
    sub $3b
    jr nc, jr_007_7951

    ret nz

    rst $20
    ld e, b
    call Call_000_3c6c
    ld a, $39
    jp Jump_000_3f25


    db $ed
    inc l
    inc [hl]
    ld [hl], h
    ld b, c
    add l
    ret


    ld a, a
    inc l
    jp $bcde


    ldh [$30], a
    rst $20
    ld d, a
    call Call_000_3c6c
    ld a, $05
    jp Jump_000_3f25


    db $ed
    dec l
    ld b, d
    ld h, l

jr_007_79bc:
    sub e
    ld a, a
    inc e
    adc a
    xor e
    db $dd
    ld a, a
    ld b, d
    adc e
    xor [hl]
    rst $20
    ld c, a
    or l
    cp l
    call nz, $a07f
    sub l
    xor [hl]
    db $e3
    ld h, $7f
    set 2, a
    cp b
    push bc
    ret c

    ld d, a
    call Call_000_3c6c
    ld hl, $d27b
    ld b, $13
    call Call_000_1690
    ld a, [$d0e3]
    cp $02
    ld a, $06
    jr c, jr_007_79ee

    ld a, $07

jr_007_79ee:
    jp Jump_000_3f25


    db $ed
    dec l
    ld [hl], h
    ld d, l
    cp l
    reti


    add $ca
    ld a, a
    ld d, h
    ld a, a
    and a
    ld b, e
    db $e3
    sub e
    ld c, a
    cp d
    rst $08
    jp nc, Jump_007_7fc6

    or [hl]
    cp b
    call nz, $b27f
    or d
    push bc
    ret c

    ld d, a
    nop
    ld d, h
    jp z, $8f7f

    add c
    ld b, d
    add $7f
    sub $df
    jp $c44f


    cp b
    or d
    push bc
    ld a, a
    adc a
    add c
    ld b, d
    ld d, l
    add $26
    jp Jump_007_7fc5


    adc a
    add c
    ld b, d
    ld h, $7f
    or d
    reti


    push bc
    ret c

    ld d, a
    ld hl, $d70f
    bit 7, [hl]
    jr z, jr_007_7a57

    ld a, [$d983]
    and a
    jr z, jr_007_7a5c

    jr jr_007_7a57

    ld a, [$d68c]
    ld b, a
    ld a, [$d68d]
    ld c, a
    or b
    jr z, jr_007_7a5c

    dec bc
    ld a, b
    ld [$d68c], a
    ld a, c
    ld [$d68d], a

jr_007_7a57:
    xor a
    ld [$d982], a
    ret


jr_007_7a5c:
    call Call_000_3c6c
    xor a
    ld [$cfae], a
    dec a
    call Call_000_0e45
    ld c, $02
    ld a, $b9
    call Call_000_0e35

jr_007_7a6e:
    ld a, [$c02a]
    cp $b9
    jr nz, jr_007_7a6e

    ld a, $d3
    ldh [$8c], a
    call Call_000_13f1
    xor a
    ld [$d4a7], a
    ld a, $9c
    ldh [$8b], a
    ld a, $03
    ld [$d3ae], a
    ld a, $05
    ld [$d59e], a
    ld hl, $d70f
    set 6, [hl]
    ld a, $01
    ld [$d982], a
    ret


    xor a
    ld [$cd66], a
    ld hl, $7aa3
    jp Jump_000_3c79


    ld [$83fa], sp
    reti


    and a
    jr z, jr_007_7ab0

    ld hl, $7ab9
    call Call_000_3c79

jr_007_7ab0:
    ld hl, $7ad2
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    ld e, d
    ld h, e
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
    inc l
    or [hl]
    sbc $26
    ld a, a
    or a
    rst $08
    cp h
    ret nz

    rst $20
    ld e, b
    db $ed
    add hl, hl
    sbc c
    ld h, e
    xor e
    adc h
    ld [hl], d
    adc d
    sbc e
    jp hl


    ret c

    ld a, a
    ld [$9fe3], sp
    ld c, a
    or l
    call c, Call_007_7fd8
    inc sp
    db $e3
    cp l
    rst $20
    ld d, a
    ld a, [$c109]
    cp $04
    ret nz

    call Call_000_3c6c
    ld a, $31
    jp Jump_000_3f25


    ld [$eaaf], sp
    ld a, e
    reti


    ld a, [$cd3d]
    push af
    and $0f
    ldh [$db], a
    pop af
    and $f0
    swap a
    ldh [$dc], a
    ld hl, $7b2f
    call Call_000_3c79
    ldh a, [$db]
    dec a
    add a
    ld d, $00
    ld e, a
    ld hl, $7bb4
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    call Call_000_3c79
    ld a, $01
    ld [$cc3c], a
    call Call_007_7c84
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    rst $10
    ld h, e
    add c
    inc c
    rst $20
    ld d, c
    cp [hl]
    or d
    or [hl]
    or d
    ld a, a
    cp l
    reti


    call nz, $137f
    add b
    ld h, $7f
    or c
    or d
    jp $c24f


    daa
    call $bd7f
    cp l
    jp nc, $bdcf

    rst $20
    ld d, c
    rst $08
    pop bc
    ld h, $b4
    ret nz

    rst $10
    ld a, a
    inc sp
    cp h
    ret


    ld a, a

jr_007_7b5e:
    ld e, l
    call nz, $c04f
    ret nz

    or [hl]
    rst $18
    jp $b27f


    ret nz

    jr nc, @-$47

    rst $08

jr_007_7b6c:
    cp l
    rst $20
    ld d, c
    cp d
    cp d
    ret


    ld a, a
    ret c

    db $e3
    rrca
    db $e3
    add $7f
    or c
    or e
    ld a, a
    rst $08
    inc sp
    ld c, a
    ld d, h
    ret


    ld a, a
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    db $dd
    ld d, l
    call nz, $c3df
    ld a, a
    or l
    or a
    ret nz

    or d
    push bc
    rst $10
    rst $20
    ld d, c
    ld h, $de
    ld a, [hl-]
    rst $18
    jp $ba7f


    ret nz

    or h
    jp $b87f


    jr nc, jr_007_7b5e

    or d
    rst $20
    ld c, a
    inc sp
    jp z, $b57f

    cp d
    ret nz

    or h
    ld a, a
    cp b
    jr nc, jr_007_7b6c

    or d
    rst $20
    ld e, b
    ret nz

    ld a, e
    call c, $f97b
    ld a, e
    ld de, $3d7c
    ld a, h
    ld h, h
    ld a, h
    db $ed
    dec l
    ld [hl-], a
    ld c, d
    xor l
    adc a
    ld b, c
    db $e3
    ld h, $7f
    cp h
    sbc $b6
    cp l
    reti


    call nz, Call_000_194f
    adc a
    sbc e
    ret c

    db $e3
    add $7f
    push bc
    reti


    and $57
    db $ed
    dec l
    ld l, e
    ld c, d

jr_007_7be0:
    db $e3
    rlca
    ld a, a
    add $de
    jp $4fb2


    add hl, de
    xor h
    dec bc
    jp z, Jump_000_2e7f

    sbc $3c
    inc sp
    ld a, a
    rst $38
    cp h
    pop hl
    reti


    or d
    and $57
    db $ed
    dec l
    xor a
    ld c, d
    and c
    jp z, $f97f

    or [hl]
    or d
    ld a, a
    cp h
    sbc $b6
    cp l
    reti


    ld c, a
    ld d, h
    ld a, a
    inc sp
    or c
    reti


    and $57
    db $ed
    dec l
    sbc $4a
    ret c

    ld a, a
    adc a
    add c
    ld b, d
    ret


    ld a, a
    call c, $dd2b
    ld c, a
    cp b
    ret c

    jr nc, jr_007_7be0

    ret nz

    ld a, a
    call nz, Call_007_51b7
    inc l
    jp nc, Jump_007_7fde

    adc a
    add c
    ld b, d
    ret


    ld a, a
    ld d, h
    add $ca
    ld c, a
    sub $b8
    ld a, a
    or a
    cp b
    and $57
    db $ed
    dec l
    dec de
    ld c, e
    ld a, a
    and a
    dec a
    and [hl]
    ret


    ld a, a
    or l
    push bc
    inc l
    ld a, a
    ld d, h
    ld c, a
    inc sp
    db $d3
    ld a, a
    jp nz, $cfb6

    or h
    reti


    ld a, a
    ret nz

    dec sp
    add $55
    jp nz, $bbd6

    jp z, $c17f

    ld h, $b3
    and $57
    db $ed
    dec l
    and d
    ld c, e
    cp $71
    call nz, $4fca
    ld [hl], b
    cp h
    ret z

    cp h
    ret z

    cp d
    or e
    cp [hl]
    sbc $71
    inc sp
    or c
    reti


    and $57

Call_007_7c7c:
    ld hl, $d71b
    ld a, $10
    jp Jump_000_3e9d


Call_007_7c84:
    call Call_000_3636
    ldh a, [$dc]
    ld c, a
    ld a, [$cc26]
    cp c
    jr nz, jr_007_7caa

    ld hl, $d0eb
    set 5, [hl]
    ldh a, [$db]
    ldh [$e0], a
    ld hl, $7cd5
    call Call_000_3c79
    ldh a, [$e0]
    ld c, a
    ld b, $01
    call Call_007_7c7c
    jp Jump_007_7d15


jr_007_7caa:
    call Call_000_3790
    ld a, $a5
    call Call_000_0e45
    call Call_000_3790
    ld hl, $7d0a
    call Call_000_3c79
    ldh a, [$db]
    add $02
    ld c, a
    ld b, $02
    ld hl, $d719
    ld a, $10
    call Call_000_3e9d
    ld a, c
    and a
    ret nz

    ldh a, [$db]
    add $02
    ld [$d97b], a
    ret


    db $ed
    add hl, hl
    push af
    ld h, h
    ret c

    ld a, a
    inc sp
    cp l
    rst $20
    ld d, c
    cp e
    or a
    call $bd7f
    cp l
    sbc $33
    ld a, a
    or d
    or d
    inc sp
    cp l
    ld d, b
    ld b, $08
    ldh a, [$e0]
    ld c, a
    ld b, $02
    call Call_007_7c7c
    ld a, c
    and a
    jp nz, Jump_000_0f6a

    call Call_000_3790
    ld a, $ad
    call Call_000_0e45
    call Call_000_3790
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    add hl, bc
    ld h, l
    jp z, $da2d

    inc sp
    cp l
    ld d, [hl]
    ld e, b

Jump_007_7d15:
    ld a, $06
    ldh [$db], a

jr_007_7d19:
    ldh a, [$db]
    dec a
    add a
    add a
    ld d, $00
    ld e, a
    ld hl, $7d53
    add hl, de
    ld a, [hl+]
    ld b, [hl]
    ld c, a
    inc hl
    ld a, [hl]
    ld [$d0f4], a
    push bc
    ldh a, [$db]
    ldh [$e0], a
    ld c, a
    ld b, $02
    call Call_007_7c7c
    ld a, c
    and a
    jr nz, jr_007_7d41

    ld a, [$d0f4]
    jr jr_007_7d43

jr_007_7d41:
    ld a, $0e

jr_007_7d43:
    pop bc
    ld [$d07c], a
    ld a, $17
    call Call_000_3e9d
    ld hl, $ffdb
    dec [hl]
    jr nz, jr_007_7d19

    ret


    add hl, bc
    inc bc
    ld d, h
    nop
    ld b, $03
    ld d, h
    nop
    ld b, $06
    ld d, h
    nop
    inc bc
    ld [$005f], sp
    ld [bc], a
    ld b, $54
    nop
    ld [bc], a
    inc bc
    ld d, h
    nop
    call Call_000_3c6c
    ld a, $30
    call Call_000_3f25
    ret


    db $ed
    inc l
    ld d, l
    ld [hl], h
    rst $18
    cp h
    ld h, $7f
    push bc
    rst $10
    sbc $33
    reti


    rst $20
    ld d, c
    ld d, [hl]
    ld d, h
    ld a, a
    jp $e2c1


    or e
    ld d, c
    ld d, [hl]
    ld d, h
    ld a, a
    rlca
    and l
    sbc e
    ld d, a
    call Call_000_3c6c
    ld a, [$c109]
    cp $04
    ret nz

    ld a, [$d771]
    bit 7, a
    jr nz, jr_007_7df6

    bit 3, a
    jr nz, jr_007_7daa

    bit 6, a
    jr nz, jr_007_7daf

jr_007_7daa:
    ld a, $2d
    jp Jump_000_3f25


jr_007_7daf:
    ld a, $01
    ld [$cc3c], a
    ld a, $2e
    call Call_000_3f25
    ld c, $20
    call Call_000_3781
    ld a, $8c
    call Call_000_0e45
    call Call_000_3790
    ld c, $50
    call Call_000_3781
    ld a, $9c
    call Call_000_0e45
    call Call_000_3790
    ld c, $30
    call Call_000_3781
    ld a, $8c
    call Call_000_0e45
    call Call_000_3790
    ld c, $20
    call Call_000_3781
    ld a, $86
    call Call_000_0e45
    call Call_000_3790
    call Call_000_0d9b
    ld hl, $d771
    set 3, [hl]
    ret


jr_007_7df6:
    ld a, $01
    ld [$cc3c], a
    ld a, $2f
    call Call_000_3f25
    ret


    db $ed
    inc l
    db $fc
    ld [hl], e
    ld h, $d2
    sbc $c6
    ld c, a
    jp $bfde


    or e
    sbc l
    adc e
    xor e
    call nz, $337f
    jp $bdcf


    rst $20
    ld d, a
    nop
    ld d, c
    db $ec
    ld e, b
    ld h, e
    sbc $bf
    or e
    sbc l
    adc e
    xor e
    ret


    ld c, a
    inc a
    sbc $d8
    ld a, a
    ld b, d
    xor b
    rlca
    and l
    sbc a
    db $dd
    ld a, a
    or a
    inc [hl]
    or e
    ld a, a
    cp h
    ret nz

    rst $20
    ld d, b
    ld b, $08
    ld a, $ff
    ld [$c0ee], a
    call Call_000_0e45
    ld c, $10
    call Call_000_3781
    ld a, $9d
    call Call_000_0e45
    call Call_000_3790
    ld c, $3c
    call Call_000_3781
    jp Jump_000_0f6a


    ld [$61cd], sp
    scf
    ld hl, $7ed2
    call Call_000_3c79
    xor a
    ld [$d059], a
    ld [$cc26], a
    ld [$cc2a], a
    ld a, $03
    ld [$cc29], a
    ld a, $04
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a

jr_007_7e80:
    ld hl, $d6af
    set 6, [hl]
    ld hl, $c3a0
    ld b, $0a
    ld c, $09
    call Call_000_03d2
    ld hl, $c3ca
    ld de, $7ee7
    call Call_000_0405
    ld hl, $7f07
    call Call_000_3c79
    call Call_000_373e
    call Call_000_3b08
    bit 1, a
    jr nz, jr_007_7ec7

    ld a, [$cc26]
    add $66
    cp $66
    jr z, jr_007_7ebf

    cp $67
    jr z, jr_007_7ebf

    cp $68
    jr z, jr_007_7ebf

    cp $69
    jr z, jr_007_7ebf

    jr jr_007_7ec7

jr_007_7ebf:
    call Call_000_34e5
    call Call_000_374a
    jr jr_007_7e80

jr_007_7ec7:
    ld hl, $d6af
    res 6, [hl]
    call Call_000_374a
    jp Jump_000_0f6a


    db $ed
    add hl, hl
    rla
    ld h, l
    cp b
    sbc $c9
    ld c, a
    or l
    or a
    add $b2
    ret c

    ld a, a
    ld d, h
    ld a, a
    ret c

    adc h
    sub e
    rst $20
    ld e, b
    db $ed
    inc l
    inc a
    ld b, d
    ld c, [hl]
    dec de
    db $e3
    adc h
    adc a
    db $e3
    ld c, [hl]
    adc d
    xor e
    rrca
    db $e3
    adc h
    ld c, [hl]
    adc e
    xor l
    xor c
    db $e3
    inc c
    ld c, [hl]
    ret nc

    reti


    ret


    db $dd
    ld a, a
    call nc, $d9d2
    ld d, b
    db $ed
    add hl, hl
    ld c, e
    ld h, l
    ld a, a
    ret nc

    cp [hl]
    jp $d37f


    rst $10
    or d
    ld a, a

jr_007_7f14:
    rst $08
    cp l
    or [hl]
    and $57
    ld a, [$c109]
    cp $04
    ret nz

    call Call_000_3c6c
    ld a, $08
    jp Jump_000_3f25


    db $ed
    dec l
    adc a
    ld d, h

Call_007_7f2b:
    ret nc

    reti


    call nz, $c54f
    sbc $c4
    ld a, a

Jump_007_7f33:
    inc sp
    sbc $bc
    and b
    db $e3
    and [hl]
    ld h, $7f

Call_007_7f3b:
    or a
    jp $c0b2


    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, c
    ld d, h
    db $dd
    ld a, a
    jp nz, $b8d6

    ld a, a
    cp a
    jr nc, jr_007_7f14

    jp $c04f


    ret nz

    or [hl]

Jump_007_7f56:
    or e
    ld a, a
    ld d, h
    ld a, a
    ld e, l
    rst $20
    ld d, l
    cp d
    cp d
    add $7f

jr_007_7f61:
    cp e
    or d

jr_007_7f63:
    or a
    ld [c], a
    or e
    ret


    ld d, l
    ld e, l
    ld h, $7f
    or c
    jp nz, $d8cf

    ld a, a
    rst $08
    cp h
    ret nz

    ld d, c
    ld a, [hl-]
    cp h
    ld [c], a
    jp z, $8d7f

    add [hl]
    add e
    add c
    ld a, a
    cp d
    or e
    add hl, hl

Call_007_7f81:
Jump_007_7f81:
    sbc $c9
    ld c, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld a, a
    adc $de
    inc a
    ld a, a
    inc sp
    cp l
    rst $20
    ld d, l
    add h
    db $e3
    add [hl]
    inc de
    jp z, $beb6

    db $d3
    ld d, l
    or d
    pop bc
    inc [hl]
    ld a, a
    ld a, [hl+]
    rst $10
    sbc $7f
    cp b
    jr nc, jr_007_7f61

    or d
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld a, a
    sub $d8

Jump_007_7fb2:
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]

Call_007_7fb6:
    ld a, a
    ld d, [hl]
    ld d, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, a
    xor c
    and [hl]
    rrca

Jump_007_7fc0:
    dec b
    rst $20
    and e

Jump_007_7fc3:
    rst $28
    dec c

Call_007_7fc5:
Jump_007_7fc5:
    db $ed

Call_007_7fc6:
Jump_007_7fc6:
    jr nz, jr_007_7f63

    ld c, l

Jump_007_7fc9:
    add l

Call_007_7fca:
Jump_007_7fca:
    ld l, c
    xor a
    ld bc, $0165

Call_007_7fcf:
Jump_007_7fcf:
    push hl
    adc c
    ld b, c
    push bc

Jump_007_7fd3:
    ld b, a
    pop bc
    dec l
    rlca
    ld a, a

Call_007_7fd8:
    dec c

Call_007_7fd9:
Jump_007_7fd9:
    inc hl
    ld d, c
    dec [hl]
    ld b, e

Jump_007_7fdd:
    db $e3

Call_007_7fde:
Jump_007_7fde:
    ld bc, $f741
    daa
    and c
    dec c
    ld c, $e3
    and c

Jump_007_7fe7:
    sbc a
    ld c, c
    ld h, c
    ld b, c
    cpl
    di
    pop af
    sbc c
    add $6f
    ld bc, $c14b
    sub a
    ccf
    add hl, bc
    ld l, l
    xor a
    ld bc, $ef29
    pop bc
    add a
    add e
    ld e, e
