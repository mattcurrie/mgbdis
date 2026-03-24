; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $017", ROMX[$4000], BANK[$17]

    ld [de], a
    inc de
    inc de
    add hl, bc
    ld d, $0f
    inc d
    inc d
    jr jr_017_4023

    dec d
    dec d
    rla
    ld a, [de]
    dec bc
    rrca
    db $10
    ld de, $0805
    rrca
    rrca
    rrca
    rrca
    rrca
    dec c
    rrca
    rrca
    inc c
    rrca
    rrca
    ld [de], a
    inc a
    inc a
    inc a

jr_017_4023:
    ld d, b
    ld d, b
    ld b, e
    ld c, l
    ld c, l
    ld c, l
    ld c, l
    ld b, b
    ld b, c
    ld d, e
    nop
    nop
    ld c, h
    ld c, [hl]
    nop
    ld c, a
    nop
    ld b, h
    ld b, l
    ld d, a
    nop
    ld b, a
    ld c, d
    ld d, h
    ld h, b
    nop
    nop
    ld c, b
    ld c, c
    ld e, e
    ld d, d
    ld b, [hl]
    dec bc
    ld [hl], h
    add hl, bc
    dec bc
    ld [hl], h
    inc a
    inc a
    inc a
    inc a
    inc a
    dec a
    ld a, $00
    nop
    nop
    nop
    nop
    ccf
    ld c, e
    ld e, b
    ld e, c
    ld e, d
    nop
    ld b, a
    nop
    nop
    nop
    nop
    nop
    ld d, [hl]
    ld b, [hl]
    nop
    nop
    jr nz, jr_017_4076

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

jr_017_4076:
    rrca
    rrca
    dec de
    ld c, $0a
    dec bc
    ld c, $0f
    rrca

Jump_017_407f:
    ld c, $06
    inc bc
    inc bc
    rlca
    ld de, $1415
    db $10
    ld [$0500], sp
    add hl, bc
    ld c, $0f
    inc c
    dec c
    ld e, [hl]
    ld e, h
    ld [hl], e
    ld e, h
    ld e, a
    ld a, [hl-]
    nop
    nop
    ld h, d
    ld h, e
    ld a, [hl-]
    nop
    nop
    ld h, b
    ld h, h
    ld a, [hl-]
    nop
    dec bc
    ld h, c
    ld h, l
    inc b
    inc b
    inc b
    db $10
    ld b, b
    rst $08
    ld b, b
    or b
    ld b, b
    nop
    ret nc

    ld b, b
    call Call_000_3c6c
    ld hl, $40bc
    ld a, [$d58b]
    jp Jump_000_3dc7


    ret nz

    ld b, b
    adc $40
    xor a
    ldh [$b4], a
    ld a, $08
    ld [$d4a7], a
    ld a, $01
    ld [$d58b], a
    ret


    ret


    ld d, b
    ld a, [bc]
    ld bc, $0701
    ld [bc], a
    dec h
    nop
    nop
    or $c6
    ld bc, $3e07
    ld c, e
    ld [$d27b], a
    ld a, $3d
    call Call_000_3e9d
    xor a
    ld [$d27b], a
    ret


    ld a, [bc]
    inc b
    ld a, [bc]
    jr nz, jr_017_4130

    inc l
    ld b, c
    rst $30
    ld b, b
    nop
    db $db
    ld b, h
    ld a, $01
    ld [$cf07], a
    xor a
    ld [$cc3c], a
    ld hl, $4109
    ld a, [$d598]
    jp Jump_000_3dc7


    dec c
    ld b, c
    dec hl
    ld b, c
    ld a, [$d2e0]
    cp $04
    ret nz

    ld a, [$d2e1]
    cp $09
    jr z, jr_017_4120

    ld a, [$d2e1]
    cp $0a
    ret nz

jr_017_4120:
    xor a
    ld [$ffb4], a
    ld a, $01
    ldh [$8c], a
    jp Jump_000_13f1


    ret


    ld [hl], $41
    dec l
    ld b, e

jr_017_4130:
    ld e, l
    ld b, e
    ld a, b
    ld b, h
    or e
    ld b, h
    ld [$e0fa], sp
    jp nc, Jump_000_04fe

    jr nz, jr_017_4148

    ld a, [$d2e1]
    cp $0d
    jp z, Jump_017_41fa

    jr jr_017_4164

jr_017_4148:
    cp $03
    jr nz, jr_017_4154

    ld a, [$d2e1]
    cp $0c
    jp z, Jump_017_41fa

jr_017_4154:
    ld a, [$d6d3]
    bit 0, a
    jr nz, jr_017_416b

    ld hl, $4312
    call Call_000_3c79
    jp Jump_017_4218


jr_017_4164:
    ld a, [$d6d3]
    bit 0, a
    jr z, jr_017_4174

jr_017_416b:
    ld hl, $4321
    call Call_000_3c79
    jp Jump_017_4218


jr_017_4174:
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    xor a
    ldh [$b4], a
    ld hl, $4223
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_017_41db

    xor a
    ldh [$9f], a
    ldh [$a0], a
    ld a, $50
    ldh [$a1], a
    call Call_000_35f0
    jr nc, jr_017_41a5

    ld hl, $4262
    call Call_000_3c79
    jp Jump_017_41db


jr_017_41a5:
    ld hl, $424a
    call Call_000_3c79
    ld hl, $d6d3
    set 0, [hl]
    xor a
    ld [$cd3d], a
    ld [$cd3e], a
    ld a, $50
    ld [$cd3f], a
    ld hl, $cd3f
    ld de, $d2cd
    ld c, $03
    ld a, $0c
    call Call_000_3e9d
    ld a, $13
    ld [$d0ea], a
    call Call_000_3130
    ld a, $b2
    call Call_000_3788
    call Call_000_3790
    jr jr_017_41f3

Jump_017_41db:
jr_017_41db:
    ld hl, $421b
    call Call_000_3c79
    ld a, $01
    ld [$cd38], a
    ld a, $80
    ld [$ccd3], a
    call Call_000_34d0
    call Call_000_0ebd
    jr jr_017_4218

jr_017_41f3:
    ld a, $01
    ld [$d598], a
    jr jr_017_4218

Jump_017_41fa:
    ld hl, $4270
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    cp $00
    jr nz, jr_017_4212

    ld hl, $42a3
    call Call_000_3c79
    jr jr_017_4218

jr_017_4212:
    ld hl, $42e2
    call Call_000_3c79

Jump_017_4218:
jr_017_4218:
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    sbc l
    ld a, b
    or a
    jp $57c8


    db $ed
    ld a, [hl+]
    daa
    ld a, b
    or d
    ld a, a
    cp d
    inc [hl]
    db $d3
    jp z, $4f7f

    cp c
    sbc $26
    cp b
    ret c

    ld [c], a
    or e
    ld a, a
    ei
    or $b4
    sbc $7f
    inc sp
    cp l
    ld d, c
    cp c
    sbc $26
    cp b
    ld a, a
    cp h
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    ld a, [hl+]
    ld a, h
    ld a, b
    ret nz

    cp h
    or [hl]
    add $4f
    ei
    or $b4

jr_017_4256:
    sbc $7f
    or d
    ret nz

    jr nc, @-$47

    ld a, a
    rst $08
    cp h
    ret nz

    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    ld h, [hl]
    ld a, b
    ld c, a
    or l
    or [hl]
    ret z

    ld h, $7f
    push bc
    or d
    sub $58
    db $ed
    ld a, [hl+]
    or l
    ld a, b
    pop bc
    or [hl]

jr_017_4276:
    rst $10
    ld a, a
    adc a
    rrca
    inc sp
    ld a, a
    jp z, $dbb2

    or e
    push bc
    sbc $c3
    ld c, a
    pop bc
    ldh [$df], a
    or [hl]
    ret c

    db $d3
    ret


    ld a, a
    jr nc, jr_017_4256

    ld d, c
    cp a
    jp c, $d8d6

    ld a, a
    or a
    ret nc

    ld c, a
    adc c
    sbc c
    add a
    rst $18
    jp $bc7f


    rst $18
    jp $e6d9


    ld d, a
    db $ed
    ld a, [hl+]
    inc c
    ld a, c
    add $7f
    rst $08
    inc l
    rst $18
    ret nz

    ld c, a
    pop de
    or [hl]
    cp h
    ret


    or d
    or a
    db $d3
    ret


    db $dd
    ld a, a
    sub $d0
    ld h, $b4
    rst $10
    cp [hl]
    reti


jr_017_42bf:
    ld d, c
    cp a
    or e
    jr nc, jr_017_4276

    push bc
    ld a, a
    inc l
    rst $18
    cp c
    sbc $dd
    ld a, a
    inc [hl]
    cp d
    or [hl]
    ret


    ld c, a
    cp c
    sbc $b7
    pop hl
    or e
    inc l
    ld [c], a
    ld h, $7f

jr_017_42da:
    cp h
    jp $ded9


    jr nc, jr_017_42bf

    jp $ed57


    ld a, [hl+]
    sbc h
    ld a, c
    or [hl]
    cp h
    ld a, a
    or a
    or [hl]
    rst $10
    ld a, a
    inc sp
    ret nz

    ld a, a
    cp h
    reti


    ld h, $4f
    add l
    adc l
    add [hl]
    ret


    ld a, a
    sub $b3
    add $7f
    or [hl]
    ret nz

    rst $08
    rst $18
    ret nz

    ld a, a
    db $d3
    ret


    db $dd
    ld d, c
    adc c
    sbc c
    add a
    call nz, $b27f
    or e
    sbc $30
    sub $57
    db $ed
    ld a, [hl+]
    rst $30
    ld [hl], a
    call $b57f
    rst $08
    call c, $b8d8
    jr nc, jr_017_42da

    or d
    ld d, a
    db $ed
    ld a, [hl+]
    ld d, $78
    cp b
    ret c

    ld a, a
    inc [hl]
    or e
    cpl
    rst $20
    ld d, a
    ld [$3721], sp
    ld b, e
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    rlca
    ld a, d
    ret nz

    call nc, Call_017_7fe7
    or c
    ret c

    ld h, $c0
    call nc, Call_017_51e7
    ret c

    pop hl
    or e
    inc l
    sbc $7f
    cp e
    rst $08
    ret


    ld c, a
    adc $c8
    db $dd
    ld a, a
    or l
    ld h, $d2
    reti


    ld a, a
    call nz, $e7ca
    ld d, a
    ld [$d3fa], sp
    sub $cb
    ld c, a
    jr nz, jr_017_438c

    ld hl, $4395
    call Call_000_3c79
    ld bc, $1f01
    call Call_000_3e5e
    jr nc, jr_017_4387

    ld hl, $d6d3
    set 1, [hl]
    ld a, $34
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld hl, $443a
    jr jr_017_438f

jr_017_4387:
    ld hl, $446b
    jr jr_017_438f

jr_017_438c:
    ld hl, $4456

jr_017_438f:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    ld a, b
    ld a, d
    ld c, a
    push bc
    or d
    cp h
    ld [c], a
    ld a, a
    jr nc, @-$45

    inc [hl]
    ld a, a
    cp d
    ret


    adc c
    sbc c
    add a
    ld d, c
    ld b, e
    adc b
    and c
    xor e
    ret


    ld a, a
    or d
    inc sp
    sbc $bc
    ld h, $7f
    ret


    cp d
    rst $18
    jp $c4d9


    ld c, a
    or l
    jp c, $7fca

    add $d7
    sbc $33
    reti


    sbc $30
    rst $20
    ld d, c
    db $d3
    cp h
    ld a, a
    or d
    or a
    or [hl]
    or h
    rst $10
    cp [hl]
    ret nz

    rst $10
    ld c, a
    ld d, h
    ret


    ld a, a
    or d
    pop bc
    jr nc, @-$4c

    ld a, a
    jp z, $b9df

    sbc $30
    rst $20
    ld d, c
    inc sp
    db $d3
    ld a, a
    cp d
    cp d
    ret


    ld a, a
    push bc
    or [hl]
    rst $08
    jp z, $b54f

    jp c, $7fc9

    or d
    or e
    cp d
    call nz, $bc7f
    sbc $2c
    push bc
    or d
    sbc $30
    ld d, c
    ld [hl], l
    ld [hl], l
    cp a
    jp c, $4f33

    or a
    ret nc

    add $7f
    ret nz

    ret


    ret nc

    ld h, $7f
    or c
    reti


    rst $20
    ld d, c
    cp d
    jp c, Jump_017_7fdd

    inc [hl]
    cp d
    or [hl]
    ret


    ld c, a
    cp c
    sbc $b7
    pop hl
    or e
    inc l
    ld [c], a
    add $7f
    db $d3
    rst $18
    jp $b27f


    rst $18
    jp $bc51


    rst $10
    dec a
    jp $ce7f


    cp h
    or d
    sbc $30
    rst $20
    ld e, b
    db $ed
    ld a, [hl+]
    ld b, [hl]
    ld a, e
    or l
    inc l
    cp e
    sbc $b6
    rst $10
    ld c, a
    set 2, b
    jp nz, $89c9

    sbc c
    add a
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
    adc h
    ld a, e
    rst $20
    ld c, a
    adc c
    sbc c
    add a
    ld a, a
    sub $db
    cp h
    cp b
    ld a, a
    ret nz

    ret


    pop de
    sub $e7
    ld d, a
    db $ed
    ld a, [hl+]
    ld [hl], d
    ld a, e
    ret


    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    jr nc, @+$59

    ld [$8221], sp
    ld b, h
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    ld a, [hl+]
    pop bc
    ld a, e
    jp z, $be7f

    or [hl]
    or d
    inc sp
    db $d3
    ld a, a
    jp nc, $d72d

    cp h
    or d
    ld c, a
    cp d
    jr nc, @-$4c

    ld a, a
    ld d, h
    ret


    ld a, a
    add l
    adc l
    add [hl]
    ret


    or e
    pop bc
    ld d, c
    ld hl, sp-$44
    pop hl
    reti


    or d
    db $dd
    ld a, a
    jp Jump_000_2cde


    ld a, a
    cp h
    jp $bdcf


    rst $20
    ld d, a
    ld [$bd21], sp
    ld b, h
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    nop
    ld b, b
    or d
    db $db
    add $7f
    cp l
    or a
    ld a, a
    call nz, $dfb5
    ret nz

    ld c, a
    or a
    jp c, $c5b2

    ld a, a
    adc c
    sbc c
    add a
    ld h, $7f
    or c
    reti


    rst $20
    ld d, a
    ld a, [bc]
    dec b
    rlca
    ld a, [bc]
    nop
    rst $38
    rlca
    dec bc
    nop
    rst $38
    rlca
    db $10
    ld bc, $07ff
    ld de, $ff01
    rlca
    rlca
    nop
    dec [hl]
    nop
    dec b
    jr nz, jr_017_44fd

    db $10
    rst $38
    jp nc, Jump_000_0b01

    ld [$ff05], sp

jr_017_44fd:
    rst $38
    ld [bc], a
    jr nz, jr_017_4507

    inc de
    rst $38
    ret nc

    inc bc
    jr nz, jr_017_450f

jr_017_4507:
    dec d
    rst $38
    rst $38
    inc b
    ld b, l
    ld b, $14
    rst $38

jr_017_450f:
    rst $38
    dec b
    ld l, $c7
    rlca
    ld a, [bc]
    ld l, $c7
    rlca
    dec bc
    ld sp, $07c7
    db $10
    ld sp, $07c7
    ld de, $c72c
    rlca
    rlca
    ld a, [bc]
    inc b
    rlca
    ld c, b
    ld b, b
    inc [hl]
    ld b, l
    ld sp, $0045
    ld b, a
    ld b, [hl]
    jp Jump_000_3c6c


    ld b, d
    ld b, l
    ld h, [hl]
    ld b, l
    xor e
    ld b, l
    push bc
    ld b, l
    db $fd
    ld b, l
    inc d
    ld b, [hl]
    daa
    ld b, [hl]
    db $ed
    inc h
    db $eb
    ld a, b
    ld a, a
    or d
    cp h
    ret z

    ld d, [hl]
    ld d, c
    cp a
    cp d
    rst $10
    call $c9de
    ld a, a
    or d
    cp h
    cp d
    db $db
    call nz, $344f
    cp d
    ld h, $7f
    pop bc
    ld h, $b3
    sbc $30
    db $db
    or e
    and $57
    db $ed
    inc h
    ld c, b
    ld a, c
    rst $38
    ret z

    sbc $7f
    db $fd
    ld h, $c2
    ld a, a
    ld hl, sp-$0a
    or [hl]
    rst $20
    ld d, c
    inc l
    sbc $d9
    or d
    ld c, a
    jp z, $d22c

    jp $c27f


    or a
    add $7f
    ret nz

    jp nz, Jump_017_51e7

    call c, $cabc
    ld a, a
    or c
    ret


    ld a, a
    sub l
    xor [hl]
    db $e3
    adc h
    ld h, $7f
    ret nc

    ret nz

    cp b
    jp $854f


    and l
    db $e3
    sub d
    and a
    ld a, [de]
    db $dd
    ld a, a
    or [hl]
    rst $18
    ret nz

    sbc $2c
    ldh [$e7], a
    ld d, a
    db $ed
    inc h
    call $c279
    jp z, $b34f

    pop bc
    pop hl
    or e
    ld a, a
    jp z, $d7b8

    sbc $b6
    or d
    db $dd
    ld a, a
    call nc, $c3df
    rst $08
    cp l
    ld d, a
    db $ed
    inc h
    push af
    ld a, c
    ret z

    ld a, a
    call c, $bcc0
    ret z

    ld c, a
    or [hl]

jr_017_45d1:
    call c, $b2b2
    or [hl]
    rst $10
    ld a, a
    ld b, c
    add l
    sub b
    xor [hl]
    add d
    ld a, a
    adc $bc
    or d
    rst $20
    ld d, c
    or l
    call nz, $bbb3
    sbc $c6
    ld a, a
    call nz, $c3df
    or a
    jp Jump_017_7fc8


    rst $18
    jp $b54f


    ret z

    ld h, $b2
    ld a, a
    cp h
    jp $c9d9


    ld d, a
    db $ed
    inc h
    ld e, c
    ld a, d
    jp z, $e7b2

    ld c, a
    ld b, c
    add l
    sub b
    xor [hl]
    add d
    jr nc, jr_017_45d1

    rst $20
    ld a, a
    cp d
    sbc $34
    push bc
    rst $20
    ld d, a
    db $ed
    inc h
    adc l
    ld a, d
    adc h
    ld a, a
    adc e
    xor l
    sub e
    and [hl]
    ld a, a
    adc c
    xor b
    xor e
    ld a, [de]
    add b
    ld a, [hl+]
    or e
    ld d, a
    db $ed
    inc h
    or b
    ld a, d
    sbc [hl]
    call nc, $c6cf
    ld a, a
    rst $10
    rst $18
    or [hl]
    cp h
    ret nz

    ld a, a
    inc a
    rst $18
    ret nz

    or d
    ld c, a
    ret nz

jr_017_463c:
    inc a
    sbc $56
    ld a, a
    jp nz, $c9b7

    ld a, a
    or d
    cp h
    ld d, a
    ld a, [bc]
    ld bc, $0707
    inc b
    inc [hl]
    ld [bc], a
    ld [bc], a
    dec bc
    ld b, $05
    ld [bc], a
    rlca
    dec b
    inc b
    dec bc
    dec b
    cp $02
    ld bc, $0925
    inc b
    rst $38
    ret nc

    ld [bc], a
    jr nz, jr_017_466c

    dec bc
    rst $38
    ret nc

    inc bc
    dec e
    add hl, bc
    rrca
    rst $38
    rst $38

jr_017_466c:
    inc b
    ld c, $09
    db $10
    rst $38
    ret nc

    dec b
    jr nz, jr_017_463c

    rlca
    rlca
    rlca
    rlca
    dec b
    pop af
    ld c, e
    ld h, $47
    add e
    ld b, [hl]
    nop
    rst $00
    ld c, e
    ld hl, $d0eb
    bit 6, [hl]
    res 6, [hl]
    call nz, Call_017_46a0
    call Call_000_3c6c
    ld hl, $4732
    ld de, $46bb
    ld a, [$d57b]
    call Call_000_31a8
    ld [$d57b], a
    ret


Call_017_46a0:
    ld hl, $46a9
    ld de, $46ac
    jp Jump_000_31c7


    sub l
    ld a, [de]
    ld d, b
    adc a
    adc b
    adc e
    ld d, b

Jump_017_46b0:
    xor a
    ld [$cd66], a
    ld [$d57b], a
    ld [$d97c], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    jp $fa46


    inc [hl]
    ret nc

    cp $ff
    jp z, Jump_017_46b0

    ld a, $f0
    ld [$cd66], a

Call_017_46d0:
    ld a, $04
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6d4
    set 7, [hl]
    ld bc, $ea01
    call Call_000_3e5e
    jr nc, jr_017_46f2

    ld a, $05
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6d4
    set 6, [hl]
    jr jr_017_46f9

jr_017_46f2:
    ld a, $06
    ldh [$8c], a
    call Call_000_13f1

jr_017_46f9:
    ld hl, $d2d5
    set 0, [hl]
    ld hl, $d6a9
    set 0, [hl]
    ld a, $04
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld a, $22
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld hl, $d76a
    res 0, [hl]
    res 7, [hl]
    ld hl, $d6d4
    set 2, [hl]
    jp Jump_017_46b0


    ccf
    ld b, a
    dec bc
    ld c, d
    sub a
    ld c, d
    add l
    ld c, b
    sbc l
    ld c, b
    ld d, b
    ld c, c
    ld [bc], a
    ld d, b
    call nc, Call_000_15d6
    ld c, d
    ld [hl], a
    ld c, d
    ld c, l
    ld c, d
    ld c, l
    ld c, d
    rst $38
    ld [$d4fa], sp
    sub $cb
    ld a, a
    jr z, jr_017_475b

    bit 6, a
    jr nz, jr_017_4753

    call z, Call_017_46d0
    call Call_000_30fe
    jr jr_017_478c

jr_017_4753:
    ld hl, $481e
    call Call_000_3c79
    jr jr_017_478c

jr_017_475b:
    ld hl, $478f
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $495d
    ld de, $495d
    call Call_000_339c
    ldh a, [$8c]
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    ld a, $01
    ld [$d039], a
    xor a
    ldh [$b4], a
    ld a, $03
    ld [$d57b], a
    ld [$d97c], a

jr_017_478c:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld [$e740], a
    ld c, a
    or l
    jp c, $7fca

    sub l
    ld a, [de]
    ld a, a
    ld d, h
    ld a, a
    dec bc
    sbc a
    ld d, l
    ret c

    db $e3
    rrca
    db $e3
    ret


    ld a, a
    adc a
    adc b
    adc e
    rst $20
    ld d, c
    or l
    jp c, $7fc9

    or [hl]
    ret nz

    or d
    ld a, a
    or d
    cp h
    jp z, $b54f

    jp c, $7fc9

    ld d, h
    add $d3
    ld a, a
    or c
    rst $10
    call c, $d9da
    rst $20
    ld d, l
    or [hl]
    ret nz

    cp b
    jp Jump_000_267f


    rst $08
    sbc $7f
    ld [hl-], a
    sub $b2

jr_017_47d3:
    rst $20
    ld d, c
    cp a
    or e
    rst $20
    ld a, a
    jp nz, $b3b6

    ret


    jp z, $b24f

    call c, $8f7f
    add c
    ld b, d
    ld a, a
    ld a, [hl-]
    rst $18
    or [hl]
    ret c

    jr nc, jr_017_47d3

    ld d, c

jr_017_47ed:
    call z, $caca
    rst $20
    ld c, a
    rst $08
    cp c
    reti


    call nz, $dc7f
    or [hl]
    rst $18
    jp Jump_017_7fc3


    ret nz

    ret nz

    or [hl]
    or e
    or [hl]
    rst $20
    ld d, l
    ld d, h
    ld a, a
    ld e, l
    ret


    ld a, a
    cp e
    ld h, $30
    push bc
    ld d, l
    or d
    or d
    jr nc, jr_017_47ed

    or e
    rst $20
    ld d, l
    or [hl]
    or [hl]
    rst $18
    jp $ba7f


    or d
    rst $20
    ld d, a
    db $ed
    dec hl
    add hl, sp
    ld b, b
    set 3, e
    or d
    ld a, a
    cp [hl]
    or [hl]
    or d
    inc sp
    jp z, $b24f

    db $db
    sbc $c5
    ld a, a
    call nc, $26c2
    ld a, a
    ld d, h
    inc sp
    ld d, l
    ret nz

    ret nz

    or [hl]
    or d
    db $dd
    ld a, a
    cp b
    ret c

    set 3, e
    add hl, hl
    jp $e7d9


    ld d, c
    or a
    ret nc

    add $ca
    ld c, a
    ld d, h
    ld a, a
    ld e, l
    ret


    ld d, l
    cp e
    or d
    ret


    or e
    ld h, $7f
    or c
    reti


    ld a, a
    sub $b3
    jr nc, @-$17

    ld d, c
    sbc c
    sub h
    rrca
    ld a, a
    adc e
    sub d
    or b
    ret


    ld a, a
    dec bc
    sbc a
    add $d3
    ld a, a
    or d
    or a
    ld c, a
    or a
    ret nc

    ret


    ld a, a
    pop bc

jr_017_4875:
    or [hl]
    rst $10
    db $dd
    ld d, l
    ret nz

    jp nc, $c3bc

    ld a, a
    ret nc

    reti


    call nz, $b27f
    or d
    ld d, a
    db $ed
    inc h
    dec b
    ld a, e
    ld a, a
    cp a
    or e
    jr nc, jr_017_4875

    ld c, a
    cp d
    jp c, Jump_017_7fdd

    or a
    ret nc

    add $7f
    or c
    add hl, hl
    sub $b3
    rst $20
    ld d, a
    db $ed
    inc h
    jr nc, jr_017_491c

    adc a
    adc b
    adc e
    or [hl]
    rst $10
    ld c, a
    ld e, h
    or d
    push de
    db $d3
    call nc, $c9cc
    adc $c7
    ld a, a
    ld d, [hl]
    add c
    and c
    call z, $7fcc
    pop bc
    ld c, a
    jp nc, Jump_017_7fc5

    jp nc, $c2d5

    jp nz, $d3c9

    ret z

    add c
    and c
    ret z

    add c
    ld a, a
    or h
    ret z

    ld d, l
    push bc
    ld a, a
    call z, $c3cf
    bit 7, a
    rst $08
    add $c5
    call z, $c3c5
    call nc, $c9d2
    jp Jump_017_7f55


    call nz, $cfcf
    jp nc, $c97f

    db $d3
    ld a, a
    jp $cfcc


    db $d3
    push bc
    call nz, $c17f
    ld d, l
    rst $00
    pop bc
    ret


    adc $81
    ld d, c
    db $ec
    cp [hl]
    ld a, a
    ld d, b
    adc $b3
    ld h, $7f
    or d
    or d
    ld d, c
    call nz, $dbba
    inc sp
    ld d, [hl]
    ld c, a
    ld e, h
    ld sp, hl
    ld a, [$cac6]
    ld d, l
    ld h, $cf
    sbc $7f
    ld h, $7f
    jp z, $dfb2

    jp $d9b2


    rst $20
    ld d, c
    cp d
    or e

jr_017_491c:
    add hl, hl
    or a
    ld a, a
    cp e
    jp c, $d9c3

    ld a, a
    call nz, $4fb7
    inc l
    rst $18
    call nz, $c07f
    or h
    jp Jump_017_7f56


    or c
    call nz, Call_017_5533
    or d
    rst $18
    or a
    add $7f
    ld hl, sp+$3a
    or d
    add $bc
    jp $b67f


    or h
    cp l
    rst $20
    ld d, l
    or l
    db $d3
    cp h
    db $db
    or d
    ld a, a
    call c, Call_000_302b
    rst $20
    ld d, a
    db $ed
    dec h
    nop
    ld b, b
    ret


    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    jr nc, jr_017_49b4

    db $ed
    inc l
    ld e, b
    ld c, d
    ld c, a
    ret nc

    cp b
    dec sp
    rst $18
    jp $b27f


    ret nz

    ld a, a
    sub $b3
    jr nc, @+$53

    ld a, $b8
    add $7f
    or [hl]
    rst $18
    ret nz

    ld a, a
    or c
    or [hl]
    cp h
    add $4f
    ld d, h
    ld a, a
    ret c

    db $e3
    rlca
    ld a, a
    cp d
    or e
    add $de
    ld d, l
    rlca
    and a
    db $e3
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld a, a
    cp e
    dec l
    cp c
    sub $b3
    rst $20
    ld d, c
    ld d, d
    jp z, $8f7f

    adc b
    adc e
    or [hl]
    rst $10
    ld c, a
    rlca
    and a
    db $e3
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    dec bc
    nop
    ld d, c
    rlca
    and a

jr_017_49b4:
    db $e3
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld a, a
    jp nz, $c3b9

    reti


    call nz, $bf4f
    jp c, $b930

    inc sp
    ld d, l
    or a
    ret nc

    ret


    ld a, a
    ld d, h
    jp z, $c27f

    sub $b8
    push bc
    reti


    rst $20
    ld d, c
    sbc e
    and l
    xor h
    adc e
    xor [hl]
    ld a, a
    call nz, $b3b2
    ld a, a
    call c, $dd2b
    ld c, a
    db $d3
    rst $18
    jp $d9b2


    ld a, a
    ld d, h
    jp z, $c055

    ret nz

    or [hl]
    rst $18
    jp $c57f


    cp b
    jp $7fd3


    sbc e
    and l
    xor h
    adc e
    xor [hl]
    db $dd
    ld d, l
    jp nz, $b4b6

    reti


    ld a, a
    sub $b3
    add $7f
    push bc
    reti


    rst $20
    ld e, b
    ld [$3221], sp
    ld b, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld d, $40
    db $e3
    rst $20
    ld d, c
    cp d
    inc [hl]
    db $d3
    ld h, $7f
    push bc
    sbc $c9
    ld a, a
    sub $b3
    jr nc, @-$17

    ld c, a
    adc a
    adc b
    adc e
    cp e
    sbc $c6
    ld a, a
    pop bc
    ld [c], a
    or e
    cp [hl]
    sbc $7f
    push bc
    sbc $c3
    ld d, l
    rst $30
    or $f6
    or $f6
    cp d
    or e
    ret z

    sbc $7f
    jp z, $b2d4

    sbc $30
    sub $e7
    ld d, a
    db $ed
    dec h
    inc h
    ld b, c
    ret nz

    rst $20
    ld d, c
    rst $30
    or $f6
    or $f6
    cp d
    or e
    ret z

    sbc $ca
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld c, a
    inc l
    or [hl]
    sbc $7f
    inc l
    ldh [$c5], a
    or d
    rst $20
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    or a
    ld [c], a
    ret c

    ld a, a
    jr nc, @-$17

    ld e, b
    db $ed
    dec h
    sbc b
    ld b, b
    ld a, a
    push bc
    or [hl]
    push bc
    or [hl]
    ld a, a
    call nc, $c5d9
    rst $20
    ld c, a
    adc a
    adc b
    adc e
    cp e
    sbc $7f
    adc $34
    inc l
    ldh [$7f], a
    push bc
    or d
    cp c
    inc [hl]
    push bc
    ld d, a
    ld [$a9fa], sp
    sub $cb
    ld b, a
    jr nz, jr_017_4ac4

    ld hl, $4acd
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_017_4ab6

    ld hl, $4b28
    call Call_000_3c79
    jr jr_017_4abc

jr_017_4ab6:
    ld hl, $4b90
    call Call_000_3c79

jr_017_4abc:
    ld hl, $4b3b
    call Call_000_3c79
    jr jr_017_4aca

jr_017_4ac4:
    ld hl, $4ba7
    call Call_000_3c79

jr_017_4aca:
    jp Jump_000_0f6a


    db $ed
    dec hl
    pop af
    ld b, c
    rst $20
    ld c, a
    ld d, h
    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    db $dd
    ld d, l
    jp nc, $bc2b

    jp $d07f


    push bc
    or d
    or [hl]
    and $51
    or l
    jp c, $7fca

    ld e, l
    ld a, a
    inc l
    ldh [$c5], a
    or d
    ld c, a
    cp h
    or [hl]
    cp h
    ld a, a
    or [hl]
    jp nz, $c07f

    jp nc, $7fc6

    ld a, [hl-]
    rst $18
    pop bc
    ret c

    ld d, l
    add b
    inc de
    add hl, de
    add c
    adc h
    ld a, a
    inc sp
    or a
    reti


    ld l, $e7
    ld d, c
    push bc
    ld d, [hl]
    rst $20
    ld a, a
    or d
    rst $18
    cp h
    ld [c], a
    add $4f
    ld d, h
    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    ld a, a
    jp nc, $bf2b

    or e
    ld l, $57
    db $ed
    dec hl
    sbc d
    ld b, d
    ldh [$e3], a
    xor h
    rst $20
    ld c, a
    inc l
    ldh [$7f], a
    cp e
    rst $18
    cp a
    cp b
    ld d, [hl]
    rst $20
    ld e, b
    db $ed
    dec hl
    xor $42
    inc a
    ret


    ld a, a
    cp e
    or d
    cp h
    ld [c], a
    add $7f
    call nz, Call_000_303b
    cp l
    ld c, a
    ld d, h
    jp z, $5556

    ld d, h
    ld a, a
    ret c

    adc h
    sub e
    ret


    ld d, l
    or d
    pop bc
    ld a, [hl-]
    sbc $7f
    or e
    or h
    ret


    ld a, a
    call nc, $30c2
    rst $20
    ld d, c
    ret c

    adc h
    sub e
    ret


    ld a, a
    inc l
    pop hl
    sbc $3a
    sbc $dd
    ld a, a

jr_017_4b72:
    or [hl]
    or h
    jp c, Jump_017_4f3a

    push de
    or e
    ret c

    add $7f
    push bc
    reti


    cp d
    call nz, $7fd3
    or c
    reti


    rst $20
    ld d, l
    ret nz

    jp nc, $c3bc

    ld a, a
    ret nc

    push bc
    sub $e7
    ld d, a
    db $ed
    dec hl
    or c
    ld b, d
    ld [c], a
    jp z, $b27f

    rst $10
    sbc $2e
    rst $20
    ld c, a
    inc l
    ldh [$7f], a
    cp e
    rst $18
    cp a
    cp b
    ld d, [hl]
    rst $20
    ld e, b
    db $ed
    dec hl
    ld a, e
    ld b, e
    jr nc, jr_017_4b72

    rst $20
    ld c, a
    cp d
    ret


    ld a, a

jr_017_4bb2:
    pop bc
    ld [c], a
    or e
    cp h

jr_017_4bb6:
    inc sp
    ld a, a
    jp nc, $be2b

    rst $20
    ld d, l
    ld d, h
    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    rst $20
    ld d, a
    inc bc
    ld [bc], a
    dec c
    inc b
    ld [bc], a
    rst $38
    dec c
    dec b
    ld [bc], a
    rst $38
    nop
    inc bc
    inc c
    dec b
    ld [$d0ff], sp
    ld b, c
    ld [$0701], a
    ld a, [bc]
    rlca
    rst $38
    db $d3
    ld b, d
    call $2401
    ld c, $0b
    rst $38
    ret nc

    inc bc
    jr c, jr_017_4bb2

    dec c
    inc b
    jr c, jr_017_4bb6

    dec c
    dec b
    ld [$0a0a], sp
    ld a, [bc]
    add hl, bc
    inc c
    dec bc
    dec b
    dec bc
    dec c
    ld c, $12
    inc de
    dec bc
    rrca
    ld c, $12
    inc de
    dec bc
    rrca
    inc c
    rlca
    dec b
    ld b, $0d
    dec b
    ld de, $1005
    dec b
    dec b
    dec b
    inc b
    dec b
    dec b
    ld b, $04
    rlca
    ld h, h
    ld b, b
    ld h, $4c
    jr nz, jr_017_4c69

    nop
    ret c

    ld c, h
    call Call_000_0d8e
    jp Jump_000_3c6c


    ld l, $4c
    cpl
    ld c, h
    ld e, l
    ld c, h
    rst $10
    ld c, h
    rst $38
    db $ed
    dec h
    add a
    ld b, e
    and $51
    ld e, [hl]

jr_017_4c36:
    ld h, $7f
    add h
    sub c
    add [hl]
    sbc [hl]
    call nc, Call_000_33cf
    ld d, [hl]
    ld c, a
    ld d, [hl]
    sbc $e6
    ld a, a
    inc sp
    sbc $dc
    ld a, a
    cp h
    jp $ded9


    jr nc, jr_017_4c36

    ld d, c
    inc l
    ldh [$cf], a
    ld a, a
    cp h
    push bc
    or d
    inc sp
    ld a, a
    cp b
    jp c, $57e7

    ld [$013e], sp
    ld [$cc3c], a
    ld hl, $4cc5
    call Call_000_3c79

jr_017_4c69:
    ld a, $ff
    call Call_000_0e45
    ld c, $20
    call Call_000_3781
    ld hl, $4cd3
    ld de, $cd3f
    ld bc, $0004
    call Call_000_01bb
    ld a, [$c132]
    ld hl, $cd3f

jr_017_4c85:
    cp [hl]
    inc hl
    jr nz, jr_017_4c85

    dec hl
    push hl
    ld c, $1f
    ld a, $d0
    call Call_000_0e35
    pop hl

jr_017_4c93:
    ld a, [hl]
    ld [$c132], a
    push hl
    ld hl, $cd3f
    ld de, $cd3e
    ld bc, $0004
    call Call_000_01bb
    ld a, [$cd3e]
    ld [$cd42], a
    pop hl
    ld c, $18
    call Call_000_3781
    ld a, [$c026]
    ld b, a
    ld a, [$c027]
    or b
    jr nz, jr_017_4c93

    ld c, $30
    call Call_000_3781
    call Call_000_0d9b
    jp Jump_000_0f6a


    db $ed
    dec hl
    jp Jump_017_7243


    ld b, [hl]
    or e
    db $e3
    ld a, a
    ld b, [hl]
    ld b, [hl]
    or e
    db $e3
    ld d, a
    jr nc, jr_017_4d0d

    inc [hl]
    inc a
    or $00
    ld [bc], a
    rlca
    inc bc
    ld b, $ff
    rlca
    inc b
    ld b, $ff
    nop
    inc b
    add hl, hl
    dec b
    rlca
    rst $38
    ret nc

    ld bc, $0b10
    rrca
    rst $38
    jp nc, $3802

    rlca
    dec b
    rst $38
    ret nc

    inc bc
    ld a, [hl+]
    ld b, $0f
    rst $38
    ret nc

    inc b
    ld e, $c7
    rlca
    inc bc
    rra
    rst $00
    rlca
    inc b
    ld b, $04
    rlca
    db $ec
    ld c, l
    ld d, $4d
    db $10
    ld c, l

jr_017_4d0d:
    nop
    ret nz

    ld c, l
    call Call_000_0d8e
    jp Jump_000_3c6c


    rra
    ld c, l
    jr nz, jr_017_4d67

    ld h, b
    ld c, l
    ld e, $4d
    or $ff
    db $ed
    dec h
    or d
    ld c, h
    ret


    ld a, a
    and d
    sub c
    rst $20
    ld d, c
    jp nc, $d72d

    cp h
    or d
    ld a, a
    ld d, h
    db $dd
    ld c, a
    jp $7fc6


    or d
    jp c, Jump_017_7fd9

    ret nz

    jp nc, $cac6

    ld d, [hl]
    ld d, c
    or c
    sbc $c5
    ld a, a
    cp d
    call nz, $7fd3
    cp d
    sbc $c5
    ld a, a
    cp d
    call nz, Call_017_4fd3
    call $b7b2
    inc sp
    ld a, a
    cp l
    reti


    rst $18
    jp $b77f


    or d
    ret nz

    sub $e7
    ld d, a
    db $ed
    dec h
    dec h
    ld c, l
    ld c, a
    sbc l
    adc d

jr_017_4d67:
    add [hl]
    ret


    ld a, a
    or e
    call c, Call_017_7fbb
    or a
    or d
    jp $b6d9


    and $51
    ret nc

    sbc $c5
    ld h, $7f
    or c
    or d
    jp nz, $4fdd

    ld d, h
    ld a, a
    sbc l
    sub l
    add b
    call nz, $d67f
    sbc $33
    reti


    sub $e7
    ld d, c
    inc sp
    db $d3
    ld a, a
    db $d3
    ret


    db $dd
    ld a, a
    or c
    jp nz, $c0d2

    ret c

    ld c, a
    inc l
    rst $08
    sbc $7f
    cp h
    ret nz

    or d
    ld a, a
    or a
    db $d3
    pop bc
    jp z, Jump_000_3055

    jp c, $d333

    ld a, a
    or c
    reti


    rst $20
    ld d, c
    ret nc

    sbc $c5
    db $d3
    ld a, a
    or e
    rst $10
    call nc, $bccf
    or d
    sbc $30
    push bc
    rst $20
    ld d, a
    nop
    ld [bc], a
    rlca
    inc bc
    ld [bc], a
    rst $38
    rlca
    inc b
    ld [bc], a
    rst $38
    nop
    inc b
    add hl, hl
    dec b
    rlca
    rst $38
    ret nc

    ld bc, $090c
    ld c, $fe
    nop
    ld [bc], a
    db $10
    rlca
    ld [$d0ff], sp
    inc bc
    ld a, [hl+]
    ld b, $0f
    rst $38
    ret nc

    inc b
    ld e, $c7
    rlca
    inc bc
    rra
    rst $00
    rlca
    inc b
    jr nz, jr_017_4dfe

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

jr_017_4dfe:
    rrca
    rrca
    dec de
    ld c, $0a
    dec bc
    ld c, $0f
    rrca
    ld c, $07
    rlca
    dec b
    ld h, a
    ld d, d
    sbc a
    ld c, [hl]
    inc d
    ld c, [hl]
    nop
    dec [hl]
    ld d, d
    ld hl, $d0eb
    bit 6, [hl]
    res 6, [hl]
    call nz, Call_017_4e31
    call Call_000_3c6c
    ld hl, $4ead
    ld de, $4e4d
    ld a, [$d57c]
    call Call_000_31a8
    ld [$d57c], a
    ret


Call_017_4e31:
    ld hl, $4e3a
    ld de, $4e3e
    jp Jump_000_31c7


    sbc c
    sub h
    rrca
    ld d, b
    add l
    adc h
    sbc [hl]
    ld d, b

Jump_017_4e42:
    xor a
    ld [$cd66], a
    ld [$d57c], a
    ld [$d97c], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld d, l
    ld c, [hl]
    ld a, [$d034]
    cp $ff
    jp z, Jump_017_4e42

    ld a, $f0
    ld [$cd66], a

Call_017_4e62:
    ld a, $05
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6dd
    set 7, [hl]
    ld bc, $d301
    call Call_000_3e5e
    jr nc, jr_017_4e84

    ld a, $06
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6dd
    set 6, [hl]
    jr jr_017_4e8b

jr_017_4e84:
    ld a, $07
    ldh [$8c], a
    call Call_000_13f1

jr_017_4e8b:
    ld hl, $d2d5
    set 1, [hl]
    ld hl, $d6a9
    set 1, [hl]
    ld hl, $d6dd
    set 2, [hl]
    set 3, [hl]
    jp Jump_017_4e42


    add $4e
    and d
    ld d, b
    ld [bc], a
    ld d, c
    ld h, h
    ld d, c
    cp b
    ld c, a
    ld b, a
    ld d, b
    ld e, [hl]
    ld d, b
    ld [bc], a
    jr nc, @-$21

    sub $ac
    ld d, b
    reti


    ld d, b
    pop de
    ld d, b
    pop de
    ld d, b
    inc bc
    jr nc, @-$21

    sub $0c
    ld d, c
    ld [hl], $51
    ld a, [hl+]
    ld d, c
    ld a, [hl+]
    ld d, c
    rst $38
    ld [$ddfa], sp
    sub $cb
    ld a, a
    jr z, jr_017_4ee2

    bit 6, a
    jr nz, jr_017_4eda

    call z, Call_017_4e62
    call Call_000_30fe
    jr jr_017_4f10

jr_017_4eda:
    ld hl, $4f8c
    call Call_000_3c79
    jr jr_017_4f10

jr_017_4ee2:
    ld hl, $4f13
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]

jr_017_4eed:
    set 7, [hl]
    ld hl, $5069
    ld de, $5069
    call Call_000_339c
    ldh a, [$8c]
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    ld a, $02
    ld [$d039], a
    xor a
    ldh [$b4], a
    ld a, $03
    ld [$d57c], a

jr_017_4f10:
    jp Jump_000_0f6a


jr_017_4f13:
    db $ed
    dec hl
    dec de
    ld b, h
    ld a, a
    or a
    ret nc

    rst $20
    ld d, c
    ld d, h
    ld a, a
    cp a
    jr nc, @-$3b

    reti


    ld a, a
    add $d3
    ld c, a

Jump_017_4f26:
    ld b, e
    ret c

    adc e
    db $e3
    ld h, $7f
    or c
    reti


    ld a, a
    call nc, Call_017_7fc2
    jr nc, jr_017_4eed

    ld h, $55
    ld b, d
    xor b
    add $7f

Jump_017_4f3a:
    push bc
    jp c, $c9d9

    rst $20
    ld d, c
    or c
    push bc
    ret nz

    jp z, Jump_017_547f

    ld a, a
    jp nz, $cfb6

    or h
    jp $bf4f


    jr nc, jr_017_4f13

    reti


    ld a, a
    call nz, $55b7
    push bc
    add $dd
    ld a, a
    or [hl]
    sbc $26
    or h
    jp $e6d9


    ld d, c
    call c, $bcc0
    ret


    ld a, a
    ld b, e
    ret c

    adc e
    db $e3
    jp z, $56c8

    ld d, c
    ret nc

    dec l
    ld a, a
    adc a
    add c
    ld b, d
    ld a, a
    ld d, h
    inc sp
    ld a, a
    cp [hl]
    jp nc, Jump_017_4fc3

    cp [hl]
    jp nc, Jump_017_7fc3

    ld d, [hl]
    cp [hl]
    jp nc, $b8cf

    reti


    ld a, a
    cp d
    call nz, $e7d6
    ld d, a
    db $ed
    dec hl
    call nc, $ca43
    ld a, a
    add hl, de
    dec de
    and [hl]
    cp d
    or e
    cp [hl]
    sbc $dd
    ld c, a
    ld d, h
    add $7f
    or l
    cp h
    or h
    reti


    ret


    ld d, c
    ret nc

    dec l
    add $7f
    cp l
    pop de
    ld a, a
    ld d, h
    add $4f
    jp nz, $dfb6

    jp $b17f


Call_017_4fb4:
    add hl, hl
    jp $57e7


    db $ed
    dec h
    call $7f4d
    add hl, de
    xor h
    dec bc

Jump_017_4fc0:
    ld h, $7f
    or c

Jump_017_4fc3:
    jp c, Jump_017_4f3a

    and a
    dec a
    and [hl]
    ld sp, hl
    or $cf
    inc sp
    ret


    ld a, a
    ld d, h
    jp z, $b555

Call_017_4fd3:
Jump_017_4fd3:
    call nz, $bcc5

Call_017_4fd6:
    cp b
    ld a, a
    or d

Jump_017_4fd9:
    or e
    cp d
    call nz, $b77f
    cp b
    call c, Call_017_51e7
    cp a
    jp c, Jump_017_7f26

    ret nz

Call_017_4fe7:
Jump_017_4fe7:
    call nz, Call_017_4fb4
    set 0, h
    or [hl]
    rst $10
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    ld a, a
    ld d, h
    inc sp
    db $d3
    ret z

    ld d, c
    cp a
    jp c, $7fc4

    ret nz

    ret nz

    or [hl]
    rst $18
    jp $c57f


    cp b
    jp Jump_017_4fd3


    or d
    or c
    or d
    daa
    ret c

    ld h, $7f
    jp nz, $b4b6

    reti


    call c, $ce51
    cp a
    or d
    ld a, a
    or a
    db $dd
    ld a, a
    or a
    ret c

    ret nz

    or l
    cp h
    jp $c44f


    or l
    jp c, Jump_017_7fd9

    sub $b3
    add $7f
    push bc
    reti


    ret


    ld d, c
    ld d, [hl]
    ld a, a
    or c
    call nz, $ba7f
    jp c, $7fca

    call c, $bcc0
    ret


    ld c, a
    inc l
    rst $08
    sbc $c9
    ld a, a
    ld e, h
    sub $e7
    ld d, a
    db $ed
    dec h
    nop
    ld c, a
    add l
    adc h
    sbc [hl]
    or [hl]
    rst $10
    ld c, a
    ld e, h
    rst $30
    rst $30
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
    dec h
    add hl, hl
    ld c, a
    ld a, a
    or d
    rst $18
    ld b, h
    or d
    ret z

    ld d, a
    db $ed
    inc l
    rst $38
    ld c, e
    ld d, [hl]
    rst $20
    ld c, a
    call c, $bcc0
    ret


    ld a, a
    rst $08
    cp c
    ret z

    ld d, c
    cp h
    ld [c], a
    or e
    ld h, $7f
    push bc
    or d
    rst $20
    ld d, c
    call c, $bcc0
    add $7f
    or [hl]
    rst $18
    ret nz

    ld a, a
    cp h
    ld [c], a
    or e
    cp d
    add $4f
    dec de
    and [hl]
    db $e3
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld a, a
    or c
    add hl, hl
    reti


    rst $20
    ld d, b
    ld de, $5006
    ld [$ad21], sp
    ld c, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ld a, $4f
    push bc
    sbc $c3
    ld c, a
    or c
    ret nz

    cp h
    inc sp
    ld a, a
    inc l
    pop hl
    or e
    inc a
    sbc $e7
    ld d, c
    add l
    adc h
    sbc [hl]
    ld h, $7f
    inc sp
    reti


    ld a, a
    rst $08
    cp b
    ld a, a
    inc l
    ldh [$c5], a
    or d
    call c, $ed57
    dec h
    push af
    ld c, a
    ret nz

    call c, Call_017_58e7
    db $ed
    dec h
    add e
    ld c, a
    push bc
    ld a, a
    ld d, h
    ld a, a
    ld e, l
    call nz, $c04f
    ret nz

    or [hl]

Jump_017_50e7:
    rst $18
    jp $d07f


    push bc
    or d
    call nz, Call_000_2c55
    inc a
    sbc $c9
    ld a, a
    jp nz, $bbd6

    ld a, a
    call c, $d7b6
    push bc
    or d
    ld a, a
    db $d3
    ret


    ret z

    ld d, a
    ld [$b921], sp
    ld c, [hl]
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    dec b
    ld d, b
    ld b, [hl]
    rst $20
    ld d, c

jr_017_5113:
    rst $08
    dec l
    jp z, $b57f

    jp c, Jump_017_7f26

    or c
    or d
    jp $e730


    ld c, a
    or [hl]
    or [hl]
    rst $18
    jp $ba7f


    or d
    rst $20
    ld d, a
    db $ed
    dec h
    ret


    ld d, b
    ld a, a
    jp z, $ca2d

    ld a, a
    push bc
    or d
    ld e, b

jr_017_5136:
    db $ed
    dec h
    ld c, a
    ld d, b
    jp z, $ba7f

    jp c, $d7b6

    ld a, a
    rst $08
    jr nc, jr_017_5113

    jr nc, jr_017_5195

    jp nz, $b8d6

    push bc
    reti


    ld a, a
    ld e, l
    jr nc, jr_017_5136

    ld d, c
    or l
    rst $08
    or h
    ld a, a
    push bc
    sbc $b6
    add $e0
    ld c, a
    rst $08
    cp c
    ret nz

    ret c

    ld a, a
    cp h
    push bc
    or d
    sub $57
    ld [$ddfa], sp
    sub $cb
    ld a, a
    jr nz, jr_017_5174

    ld hl, $517d
    call Call_000_3c79
    jr jr_017_517a

jr_017_5174:
    ld hl, $5202
    call Call_000_3c79

jr_017_517a:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ei
    ld b, h
    rst $20
    ld c, a
    ret nc

    rst $10
    or d
    ret


    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    rst $20
    ld d, c
    add b
    inc de
    add hl, de
    add c
    adc h

jr_017_5195:
    ld a, a
    cp h
    sub $b3
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
    ld a, a
    add l
    adc h
    sbc [hl]
    jp z, $d04f

    dec l
    add $7f
    cp l
    pop de
    ld a, a
    ld d, h
    db $dd
    ld a, a
    jp nz, $b3b6

Call_017_51b6:
    ld d, l
    ld b, d
    xor b
    sbc e
    db $eb
    xor h
    adc e
    xor a
    sub h
    and [hl]
    jr nc, @-$17

    ld d, c
    cp d
    sbc $c5
    ld a, a
    call nz, $cab7
    ld a, a
    cp h
    ld [c], a
    cp b
    inc a
    jp nz, $8f7f

    add c
    ld b, d
    inc sp
    ld c, a
    ret nc

    dec l
    db $dd
    ld a, a
    cp l
    or d
    call nz, Call_017_7fd9
    cp e
    cp b
    cp [hl]
    sbc $30
    ld d, c
    ld d, [hl]

Jump_017_51e6:
    ld a, a

Call_017_51e7:
Jump_017_51e7:
    cp a
    jp c, Jump_017_7fb6

    inc sp
    sbc $b7
    ld a, a
    adc a
    add c
    ld b, d
    inc sp
    ld c, a
    cp h
    dec sp
    jp c, $bb7f

    cp [hl]
    reti


jr_017_51fb:
    ret


    db $d3
    ld a, a
    or d
    or d
    ld l, $57
    db $ed
    dec hl
    rst $28
    ld b, l
    add $7f
    or [hl]
    rst $18
    ret nz

    push bc
    rst $20
    ld c, a

jr_017_520e:
    or l
    jp c, $7fc9

    or d
    rst $18
    ret nz

    ld a, a
    call nz, $d8b5
    ld a, a
    jr nc, jr_017_51fb

    ret nz

    db $db
    and $51
    or l
    rst $08
    or h
    db $d3
    ld a, a
    cp l
    ld a, [hl+]
    or d

jr_017_5228:
    ld h, $4f
    or l
    jp c, $7fd3

    cp l
    ld a, [hl+]
    or d
    jr nc, jr_017_520e

    and $57
    inc bc
    ld [bc], a
    dec c
    inc b
    inc bc
    rst $38
    dec c
    dec b
    inc bc
    rst $38
    nop
    inc b
    dec e
    ld b, $08
    rst $38
    ret nc

    ld b, c
    db $eb
    ld bc, $0706
    ld b, $ff
    db $d3
    ld b, d
    adc $01
    ld [hl+], a
    dec bc
    inc c
    rst $38
    jp nc, $d743

    ld bc, $0e24
    dec bc
    rst $38
    ret nc

    inc b
    jr c, jr_017_5228

    dec c
    inc b
    jr c, @-$37

    dec c
    dec b
    inc d
    inc d
    ld hl, $1414
    dec d
    inc hl
    ld [hl+], a
    inc hl
    ld d, $15
    ld e, $1e
    rra
    ld d, $15
    inc e
    dec e
    jr nz, jr_017_5291

    dec d
    dec de
    dec b
    rla
    ld d, $15
    ld a, [de]
    dec b
    add hl, de
    ld d, $18
    jr jr_017_528c

    jr jr_017_52a2

    ld [bc], a
    inc b

jr_017_528c:
    inc b
    nop
    ld b, b
    sbc c
    ld d, d

jr_017_5291:
    sub [hl]
    ld d, d
    nop
    dec e
    ld d, e
    jp Jump_000_3c6c


    rst $20
    ld c, $9f
    ld d, d
    db $e3
    ld d, d
    db $ed
    dec l
    scf

jr_017_52a2:
    ld b, b
    cp c
    adc h
    ld b, d
    and a
    db $e3
    jp z, $d14f

    cp h
    ld a, a
    inc [hl]
    cp d
    db $db
    or [hl]
    ld d, l
    ld d, h
    db $d3
    ld a, a
    sub $df
    jp $ba7f


    push bc
    or d
    sub $51
    jp nz, $b2d6

    ld a, a
    ld d, h
    db $dd
    ld a, a
    or d
    pop bc
    ld a, [hl-]
    sbc $4f
    or e
    or h
    add $7f
    or l
    or d
    jp $b57f


    cp c
    ld a, [hl-]
    ld d, l
    cp d
    or e
    or [hl]
    jp z, Jump_000_3a7f

    or d
    cpl
    or e
    ld a, a
    jr nc, @-$17

    ld d, a
    db $ed
    dec l
    jp z, $3340

    jp z, $d07f

    ret nz

jr_017_52ec:
    ld a, a
    cp d
    call nz, $c57f
    or d
    cp c
    inc [hl]
    ld c, a
    call z, $27bc
    push bc
    add b
    and b
    ld a, a
    cp h
    rst $18
    jp $e6d9


    ld d, c
    ld d, h
    ld h, $7f
    or d
    rst $18
    or a
    add $7f
    cp a
    jr nc, jr_017_52ec

    jp $a74f


    dec a
    and [hl]
    ld h, $7f
    or c
    ld h, $d9
    ld a, a
    rst $10
    cp h
    or d
    ret


    ld d, a
    nop
    ld [bc], a
    rlca
    inc bc
    dec b
    rst $38
    rlca
    inc b
    dec b
    rst $38
    nop
    inc bc
    ld h, $09
    inc b
    rst $38
    db $d3
    ld bc, $0807
    rlca
    cp $01
    ld [bc], a
    ld b, $06
    ld a, [bc]
    cp $02
    inc bc
    ld [de], a
    rst $00
    rlca
    inc bc
    inc de
    rst $00
    rlca
    inc b
    ld b, $04
    rlca
    ld h, h
    ld b, b
    ld d, l
    ld d, e
    ld c, a
    ld d, e
    nop
    cp a
    ld d, e
    call Call_000_0d8e
    jp Jump_000_3c6c


    ld e, [hl]
    ld d, e
    ld e, a
    ld d, e
    adc d
    ld d, e
    ld e, l
    ld d, e
    or $ff
    db $ed
    ld h, $21
    ld h, b
    jp c, $c1de

    pop hl
    or e
    ld d, [hl]
    ld c, a
    or l
    or [hl]
    ret z

    ld a, a
    db $d3
    or e
    cp c
    ret


    ld a, a
    ret nz

    jp nc, $d7c5

    ld d, l
    inc [hl]
    sbc $c5
    ld a, a
    call c, $b2d9
    ld a, a
    cp d
    call nz, $d333
    ld a, a
    call nc, $c9d9
    cp e
    ld d, a
    db $ed
    ld h, $62
    ld h, b
    and l
    ret


    ld a, a
    or l
    or [hl]
    or c
    cp e
    sbc $26
    ld c, a
    ld e, [hl]
    or [hl]
    rst $10
    ld a, a
    add $29
    reti


    ld a, a
    call nz, $dbba
    ld d, l
    call c, $bcc0
    db $d3
    ld a, a
    ret nc

    ret nz

    call c, $5156
    add $29
    reti


    ld a, a
    call nz, $e1c1
    or e
    inc sp
    ld a, a
    cp d
    db $db
    cp e
    jp c, $dcc0

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
    inc b
    add hl, hl
    dec b
    rlca
    rst $38
    ret nc

    ld bc, $0710
    add hl, bc
    rst $38
    rst $38
    ld [bc], a
    ld [$060a], sp
    cp $01
    inc bc
    ld a, [hl+]
    ld b, $0f
    rst $38
    ret nc

    inc b
    ld e, $c7
    rlca
    inc bc
    rra
    rst $00
    rlca
    inc b
    ld [bc], a
    inc b
    inc b
    nop
    ld b, b
    ld a, [$f753]
    ld d, e
    nop
    or $54
    jp Jump_000_3c6c


    cp $0e
    nop
    ld d, h
    ld l, a
    ld d, h
    db $ed
    dec l
    ld e, h
    ld b, c
    sbc $26
    ld a, a
    cp e
    or h
    jp nc, Jump_017_7fd9

    call nc, Call_017_7fcf
    ret nc

    jp nc, $d3c5

    db $d3
    ld a, a
    ret


    call nc, $7f81
    ld c, a
    ld d, [hl]
    and e
    jp nc, $c3c1

    res 0, c
    ld a, a
    and e
    jp nc, $c3c1

    res 0, c
    ld a, a
    ld d, c
    add $c9
    jp nc, $d4d3

    ld a, a
    call z, $c3cf
    bit 7, a
    rst $08
    add $7f
    call nc, $c5c8
    ld c, a
    ld a, a
    push bc
    call z, $c3c5
    call nc, $c9d2
    jp $c47f


    rst $08
    rst $08
    jp nc, Jump_017_7f7f

    ret


    ld d, l
    db $d3

Call_017_544f:
    ld a, a
    rst $08
    ret nc

    push bc
    adc $c5

Call_017_5455:
Jump_017_5455:
    call nz, $7f81
    ld d, c
    db $ec
    ld sp, hl
    ld a, [hl]
    ld d, b
    or e
    ld c, a
    push bc
    rst $08
    or h
    ld a, a
    push bc
    sbc $30
    ld h, $7f
    cp h
    rst $10
    sbc $b6
    push bc
    and $57
    ld [$5ffa], sp
    rst $10
    bit 7, a
    jr nz, jr_017_547f

    ld hl, $5488
    call Call_000_3c79
    jr jr_017_5485

Jump_017_547f:
jr_017_547f:
    ld hl, $54b6
    call Call_000_3c79

jr_017_5485:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld c, e
    ld b, [hl]
    ret


    or [hl]
    cp c
    rst $10
    jp z, $b67f

    rst $18
    ret nz

    and $4f
    set 3, [hl]
    cp h
    inc l
    ld [c], a
    or e
    ret nz

    or d
    ret


    ld a, a
    ld d, h
    db $dd
    ld d, l
    add hl, hl
    sbc $b7
    add $7f
    cp l
    reti


    ld a, a
    dec a
    sbc $d8
    push bc
    ld a, a
    inc [hl]
    or e
    jr z, @-$43

    ld d, a
    db $ed
    dec hl
    or b
    ld b, [hl]
    or c
    or d
    jr nc, jr_017_553d

    call nc, $b5cf
    cp b
    inc sp
    ld c, a
    or a
    sbc $c9
    ret nz

    rst $08
    db $dd
    ld a, a
    set 3, e
    or d
    ld a, a
    rst $08
    cp h
    jp $e7c8


    ld d, c
    jp nz, $b4b6

    push bc
    or d
    ld a, a
    cp h
    push bc
    db $d3
    ret


    ld a, a
    inc sp
    cp l
    ld h, $4f
    or e
    rst $18
    ret nz

    rst $10
    ld a, a
    push bc
    sbc $c4
    ld a, a
    ei
    or $f6
    or $f0
    inc sp
    cp h
    ret nz

    ld d, a
    nop
    ld [bc], a
    rlca
    inc bc
    inc bc
    rst $38
    rlca
    inc b
    inc bc
    rst $38
    nop
    inc bc
    ld h, $09
    inc b
    rst $38
    db $d3
    ld bc, $0834
    rlca
    rst $38
    rst $38
    ld [bc], a
    rlca
    ld b, $0b
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
    ld b, $04
    rlca
    ld h, h
    ld b, b

jr_017_5521:
    ld l, $55
    jr z, jr_017_557a

    nop
    sbc h
    ld d, l
    call Call_000_0d8e
    jp Jump_000_3c6c


    ld [hl], $55
    scf
    ld d, l
    db $76

Call_017_5533:
    ld d, l
    sbc e
    ld d, l
    rst $38
    db $ed
    dec h
    ret nz

    ld h, b
    ld a, a
    and a

jr_017_553d:
    dec a
    and [hl]
    ret


    ld a, a
    ld d, h
    inc sp
    db $d3
    ld c, a
    jp nz, $bbd6

    jp z, $cf7f

    pop bc
    rst $08
    pop bc
    ld a, a
    rst $10
    cp h
    or d
    ld d, c
    cp a
    jp c, $7fc6

    set 0, h
    ld h, $7f
    cp a
    jr nc, jr_017_5521

    ret nz

    ld c, a
    ld d, h
    ret


    ld a, a
    adc $b3
    ld h, $55
    call nc, $b2be
    ld a, a
    sub $d8
    ld a, a
    jp nz, $b2d6

    ld a, a
    rst $10
    cp h
    or d
    ld d, a
    db $ed
    dec h
    ld c, e
    ld h, c

jr_017_557a:
    ld a, a
    ld d, h
    ld c, a
    inc [hl]
    cp b
    ld a, a
    cp b
    rst $10
    rst $18
    ret nz

    rst $08
    rst $08
    ld a, a
    or c
    reti


    or d
    jp $d7c0


    ld d, l
    pop bc
    or [hl]
    rst $10
    ld a, a
    jp nz, Jump_017_7fb7

    or l
    rst $18
    ret nz

    inc sp
    rst $20
    ld d, a
    or $00
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
    inc b
    add hl, hl
    dec b
    rlca
    rst $38
    ret nc

    ld bc, $0927
    ld c, $ff
    rst $38
    ld [bc], a
    inc de
    ld [$ff09], sp
    rst $38
    inc bc
    ld a, [hl+]
    ld b, $0f
    rst $38
    ret nc

    inc b
    ld e, $c7
    rlca

Jump_017_55c3:
    inc bc
    rra

Call_017_55c5:
    rst $00
    rlca
    inc b
    ld [bc], a
    inc b
    inc b
    nop
    ld b, b
    rst $10
    ld d, l

Call_017_55cf:
    call nc, Call_000_0055
    ld a, a
    ld d, [hl]
    jp Jump_000_3c6c


    push af
    ld c, $dd
    ld d, l
    ld d, [hl]
    ld d, [hl]
    db $ed
    dec l
    sub [hl]
    ld e, c
    or [hl]
    ld a, a
    add $ca
    ld a, a
    ld d, h

Call_017_55e7:
Jump_017_55e7:
    inc sp
    ld c, a
    call c, Call_000_30d9
    cp b
    ret nc

    db $dd
    ld a, a
    cp l
    reti


    ld a, a
    call nc, $d7c2
    db $d3
    ld a, a
    or d
    reti


    ld d, c
    ld d, h
    db $dd
    ld a, a
    ret nz

    or [hl]
    cp b
    ld a, a
    or e
    ret c

    cp e
    ld a, [hl-]
    or d
    ret nz

    ret c

    ld c, a
    call nz, $c6b7
    jp z, $c67f

    sbc $b7
    ld h, $c5
    or d
    ld a, a
    call nz, Call_017_51b6
    call nc, $c6b8
    ld a, a
    ret nz

    ret nz

    push bc
    or d
    ld a, a
    call nz, $b3b2
    ld a, a
    ret c

    push de
    or e
    inc sp
    ld c, a
    cp d
    db $db
    cp h
    jp $bc7f


    rst $08

jr_017_5632:
    rst $18
    ret nz

    ret c

    ld d, c
    cp a
    or e
    or d
    or e
    ld a, a
    call c, $b2d9
    ld a, a
    cp d
    call nz, Call_000_3a7f
    or [hl]
    ret c

    cp l
    reti


    ld c, a
    or c
    jp nz, $d8cf

    ld h, $7f
    xor b
    adc b
    xor h
    sub e
    jr nc, jr_017_5632

    cp e
    ld d, a
    db $ed
    dec l
    ld d, a
    ld e, c
    jp nz, $b3b6

    ld a, a
    set 0, h
    add $7f
    sub $df
    jp $d64f


    cp b
    db $d3
    ld a, a
    call c, $b8d9
    db $d3
    ld a, a
    push bc
    reti


    ld d, l

Jump_017_5672:
    ld b, b
    db $e3
    sub e
    sub h
    db $e3
    jr nc, @-$3a

    ld a, a
    or l
    db $d3
    or e
    ret


    ld d, a
    nop
    ld [bc], a
    rlca
    inc bc
    ld [bc], a
    rst $38
    rlca
    inc b
    ld [bc], a
    rst $38
    nop
    inc bc
    ld h, $09
    inc b
    rst $38
    db $d3
    ld bc, $0a07
    add hl, bc
    rst $38
    rst $38
    ld [bc], a
    ld b, $07
    rlca
    cp $02
    inc bc
    ld [de], a
    rst $00
    rlca
    inc bc
    inc de
    rst $00
    rlca
    inc b
    rlca
    add hl, bc
    dec b
    ld e, d
    ld e, h
    ld h, e
    ld d, a
    or c
    ld d, [hl]
    nop
    jr nz, @+$5e

    ld hl, $d0eb
    bit 5, [hl]

Call_017_56b6:
    res 5, [hl]
    push hl
    call nz, Call_017_56d7
    pop hl
    bit 6, [hl]
    res 6, [hl]
    call nz, Call_017_56e8
    call Call_000_3c6c
    ld hl, $5773

Call_017_56ca:
    ld de, $5710
    ld a, [$d57d]
    call Call_000_31a8

Jump_017_56d3:
    ld [$d57d], a
    ret


Call_017_56d7:
    ld hl, $56e0
    ld de, $56e4
    jp Jump_000_31c7


    add a
    sub b
    add hl, de
    ld d, b
    sbc l
    sub b
    adc h
    ld d, b

Call_017_56e8:
    ld a, [$d6f2]
    bit 0, a
    jr nz, jr_017_56f3

    ld a, $24
    jr jr_017_56fa

jr_017_56f3:
    ld a, $ad
    call Call_000_0e45
    ld a, $05

jr_017_56fa:
    ld [$d07c], a
    ld bc, $0202
    ld a, $17
    jp Jump_000_3e9d


Jump_017_5705:
    xor a
    ld [$cd66], a
    ld [$d57d], a
    ld [$d97c], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    jr @+$59

    ld a, [$d034]
    cp $ff
    jp z, Jump_017_5705

    ld a, $f0
    ld [$cd66], a

Call_017_5725:
    ld a, $06
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6f2
    set 7, [hl]
    ld bc, $e001
    call Call_000_3e5e
    jr nc, jr_017_5747

    ld a, $07
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d6f2
    set 6, [hl]
    jr jr_017_574e

jr_017_5747:
    ld a, $08
    ldh [$8c], a
    call Call_000_13f1

jr_017_574e:
    ld hl, $d2d5
    set 2, [hl]
    ld hl, $d6a9
    set 2, [hl]
    ld a, [$d6f2]
    or $1c
    ld [$d6f2], a
    jp Jump_017_5705


    sbc b
    ld d, a
    jp nz, $3459

jr_017_5768:
    ld e, d
    and l
    ld e, d
    ld b, b
    ld e, e
    jp nz, $2758

    ld e, c
    ld l, [hl]
    ld e, c
    ld [bc], a

jr_017_5774:
    jr nc, jr_017_5768

    sub $cc
    ld e, c
    dec b
    ld e, d
    db $f4
    ld e, c
    db $f4
    ld e, c
    inc bc

jr_017_5780:
    jr nz, jr_017_5774

    sub $3e
    ld e, d
    ld [hl], h
    ld e, d
    ld l, b
    ld e, d
    ld l, b
    ld e, d
    inc b
    jr nc, jr_017_5780

    sub $af
    ld e, d
    pop hl
    ld e, d
    sub $5a
    sub $5a
    rst $38
    ld [$f2fa], sp
    sub $cb
    ld a, a
    jr z, jr_017_57b4

    bit 6, a
    jr nz, jr_017_57ac

    call z, Call_017_5725
    call Call_000_30fe
    jr jr_017_57e5

jr_017_57ac:
    ld hl, $586b
    call Call_000_3c79
    jr jr_017_57e5

jr_017_57b4:
    ld hl, $57e8
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $598a
    ld de, $598a
    call Call_000_339c
    ldh a, [$8c]
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    ld a, $03
    ld [$d039], a
    xor a
    ldh [$b4], a
    ld a, $03
    ld [$d57d], a
    ld [$d97c], a

jr_017_57e5:
    jp Jump_000_0f6a


    db $ed
    dec hl
    or [hl]
    ld b, a
    rst $20
    ld c, a
    ld b, d
    add b
    ld a, a
    ret c

    sub e
    and [hl]
    ld a, a
    inc e
    db $e3
    add c
    rst $20
    ld d, c
    and e
    db $e3
    ret


    ld a, a
    sbc c
    xor e
    ld b, b
    push bc
    ld a, a
    ld b, b
    xor c
    db $e3
    inc sp
    jp z, $be4f

    sbc $2c
    ld [c], a
    or e
    inc l
    ldh [$7f], a
    or d
    or a
    ld a, a
    ret


    cp d
    jp c, $b2c5

    sub a
    ld d, c
    sbc [hl]
    db $e3
    jp z, $be7f

    sbc $bf
    or e
    inc sp
    ld c, a
    add e
    and a
    add a
    sub e
    ret c

    xor h
    add a
    ld a, a
    ld d, h
    ld a, a
    jp nz, $dfb6

    jp $b255


    or a
    ld a, a
    ret


    dec sp
    ret nz

    sub a
    rst $20
    ld d, c
    ret nc

    sbc $c5
    ld a, a
    ld a, [de]
    ret c

    ld a, [de]
    ret c

    ld a, a
    adc e
    ld a, [de]
    and a
    jp $b34f


    ld a, [hl+]
    cp c
    sub h
    db $e3
    add c
    rst $20
    ld d, c
    and e
    db $e3
    db $d3

Call_017_5856:
    ld a, a
    or l
    push bc
    inc l
    ld a, a
    ret nc

    pop bc
    ld a, a
    ret nz

    inc [hl]
    reti


    ld c, a
    pop bc
    ld h, $b2
    ld a, a
    sub h
    db $e3
    add c
    rst $20
    ld d, a
    db $ed
    dec hl
    ld [hl+], a
    ld b, a
    ld c, a
    cp a
    jp c, $d7b6

    ld a, a
    and e
    db $e3
    add $7f
    add b
    inc de
    add hl, de
    add c
    adc h
    rst $20
    ld d, c
    add e
    and a
    add a
    sub e
    ret c

    xor h
    add a
    ld a, a
    ld b, b
    xor c
    db $e3
    ld c, a

jr_017_588c:
    ld a, [de]
    ret c

    ld a, [de]
    ret c

    ld a, a
    jp nz, $b2d6

    sub a
    db $e3
    rst $20
    ld d, c
    inc sp
    db $d3
    ld a, a
    inc l
    jp nc, Jump_017_7fde

    adc a
    add c
    ld b, d
    add $ca
    ld c, a
    ld b, b
    xor c
    db $e3
    ld a, a
    cp l
    or d
    call nz, $dad7
    jp $bc7f


    rst $08
    rst $18
    jp $2e55


    sbc $2e
    sbc $7f
    or a
    or [hl]
    push bc
    or d
    and h
    db $e3
    rst $20
    ld d, a
    db $ed
    dec h
    ld b, [hl]

Call_017_58c5:
    ld h, d
    dec bc
    ld a, a
    add hl, de
    xor h
    dec bc
    ld a, a
    db $d3
    rst $18
    jp Jump_017_7fd9


    jr nc, jr_017_588c

    inc sp
    ld c, a
    and e
    db $e3
    ret


    ld a, a
    ld d, h
    ld a, a
    adc h
    ld b, c
    db $e3
    inc de
    ld a, a
    add b
    xor h
    ld b, d
    ld d, c
    add b
    db $e3
    xor e

Call_017_58e7:
    inc de
    rst $20
    ld a, a
    cp a
    rst $10
    db $dd
    call nz, Call_017_7f3c
    call c, $ca2b
    ld c, a

jr_017_58f4:
    sbc e
    jp hl


    add c
    sub e
    ld a, a
    push bc
    or d
    ld a, a
    call nz, $d3b7
    ld d, l
    jp nz, $b4b6

    reti


    ld a, a
    sub $b3
    add $7f
    push bc
    reti


    and h
    rst $20
    ld d, c
    and e
    db $e3
    jp z, $8c7f

    ld b, a
    adc e
    xor l
    and [hl]
    rst $20
    ld c, a
    cp d
    jp c, $7fca

    sbc [hl]
    db $e3
    ret


    ld a, a
    or a
    db $d3
    pop bc
    sub a
    rst $20
    ld d, a
    db $ed
    dec h
    dec c
    ld h, e
    sbc l
    sub b
    adc h
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
    ld e, h
    ld hl, sp-$06
    jp z, Jump_000_334f

    sbc $b7
    ld a, a
    ld a, [de]
    ret c

    ld a, [de]
    ret c

    ld a, a
    rst $30
    or $cf
    sbc $1c
    and [hl]
    sub e
    ld d, c
    add e
    and a
    add a
    sub e
    ret c

    xor h
    add a
    ld a, a
    ld d, h
    add $4f
    or l
    cp h
    or h
    jp $b87f


    jr nc, jr_017_58f4

    db $e3
    add c
    rst $20
    ld d, a
    db $ed
    dec h
    add c
    ld h, e
    add h
    dec de
    ld a, a
    and e
    add b
    ld a, a
    ret c

    xor [hl]
    xor h
    add a
    rst $20
    ld c, a
    or c
    push bc
    ret nz

    ld a, a
    db $d3
    jp $becf


    db $e3
    sbc $e7
    ld d, a
    db $ed
    inc l
    jp $984c


    db $e3
    rst $20
    ld d, c
    and e
    db $e3
    ret


    ld a, a
    jp nz, $bbd6

    ld a, a
    sub e
    ld [$e3a6], a
    adc h
    rst $20
    ld c, a
    jp nz, $d8cf

    ld a, a
    adc $de
    db $d3
    ret


    ld a, a
    sub a
    db $e3
    rst $20
    ld d, c
    add h
    xor h
    adc b
    db $e3
    rst $20
    ld c, a
    add h
    and a
    xor e
    dec bc
    ld a, a
    add hl, de
    xor h
    dec bc
    ld a, a
    call nc, $a4d9
    rst $20
    ld e, b
    ld [$7321], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    add $63
    or d
    add $7f
    or d
    ret nz

    ld a, a
    cp d
    db $db
    jp z, $9d4f

    sub b
    adc h
    ld a, a
    cp h
    ld [c], a
    or e
    cp e
    add $55
    ld a, [de]
    adc e
    rst $20
    ld a, [de]
    adc e
    rst $20
    ld a, a
    or a
    ret nz

    or h
    rst $10
    jp c, $2ec0

    rst $20
    ld d, a
    db $ed
    dec h
    and [hl]
    ld h, h
    ld c, a
    push bc
    or [hl]
    push bc
    or [hl]
    ret


    ld a, a
    or e
    inc sp
    rst $08
    or h
    jr nc, jr_017_5a5d

    db $ed
    dec h
    ld a, [bc]
    ld h, h
    ld a, a
    or c
    or [hl]
    push bc
    or d
    ret


jr_017_5a0f:
    or [hl]
    and $51
    sbc l
    sub b
    adc h
    ld a, a
    ret


    ld a, a
    sub $b3
    inc l
    sbc $7f
    inc a
    or [hl]
    cp e
    jp z, Jump_000_284f

    sbc $c0
    or d
    inc sp
    db $d3
    ld a, a
    push de
    or e
    jp nc, Jump_017_7fb2

    jr nc, jr_017_5a0f

    ret nz

    ld l, $e7
    ld d, a
    ld [$7f21], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    ret nz

    ld h, h
    ld a, a
    ret nz

    or d
    ret c

    ld [c], a
    cp b
    ld a, a
    push bc
    or d
    cp c
    inc [hl]
    ld c, a

jr_017_5a4e:
    inc sp
    sbc $b7
    ret


    ld a, a
    or c
    jp nz, $b2b6

    db $dd
    ld a, a
    or [hl]
    call c, $c3da

jr_017_5a5d:
    ld d, l
    cp d
    cp d
    add $7f
    or a
    ret nz

    ret


    jr nc, jr_017_5a4e

    ld d, a
    db $ed
    dec h
    and a
    ld h, l
    rst $20
    ld a, a
    cp h
    dec sp
    jp c, $e7c0

    ld e, b
    db $ed
    dec h
    dec b
    ld h, l
    ret nz

    ld a, a
    or d
    or e
    sub $e3
    rst $20
    ld d, c
    sbc l
    sub b
    adc h
    jp z, $cd7f

    call nc, $7fc9
    adc h
    add c
    xor h
    sub b
    db $dd
    ld c, a
    push bc
    add $b6
    ret


    ld d, [hl]
    ld d, l
    cp a
    cp d
    add $7f
    or [hl]
    cp b
    cp h
    ret nz

    call nz, $b27f
    rst $18
    jp $c5c0


    ld d, a
    ld [$8b21], sp
    ld d, a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    dec h
    and $65
    ld a, a
    ld d, h
    ld a, a
    or e
    rst $08
    or d
    ld a, a
    or [hl]
    rst $10
    rst $18
    jp $ba4f


    cp d
    jp z, $ba7f

    inc [hl]
    db $d3
    ld h, $55
    cp b
    reti


    ld a, a
    call nz, $dbba

jr_017_5ace:
    ld a, a
    inc l
    ldh [$c5], a
    or d
    ld l, $e7
    ld d, a
    db $ed
    dec h
    dec b
    ld h, a
    or l
    inc [hl]
    db $db
    or a
    jr nc, @-$17

    ld e, b
    db $ed
    dec h
    jr z, jr_017_5b4b

    ld a, a
    cp h
    ld [c], a
    or e
    cp e
    jp z, $cd4f

    call nc, Call_017_7fdd
    ld hl, sp+$2c
    pop hl
    or e
    ld a, a
    xor b
    xor h
    add a
    ld a, a
    cp h
    jp Jump_000_2ed9


    ld d, l
    ld d, [hl]
    ld a, a
    sbc d
    xor e
    sub e
    db $dd
    ld a, a
    or c
    add hl, hl
    sub $b3
    rst $20
    ld d, c
    jr nc, @-$4c

    rst $30
    ld a, a
    xor b
    xor h
    add a
    db $dd
    ld a, a
    jp z, $bc2d

    ret nz

    rst $10
    ld c, a
    jr nc, jr_017_5ace

    ld hl, sp+$7f
    xor b
    xor h
    add a
    jp z, $bd7f

    jr z, @+$81

    cp a
    ld a, [hl-]
    jr nc, jr_017_5b7f

    call z, $c2c0
    ret


    ld a, a
    xor b
    xor h
    add a
    jp z, $c455

    push bc
    ret c

    or c
    call c, $c6be
    ld a, a
    or c
    reti


    ld l, $57
    ld [$a9fa], sp
    sub $cb
    ld d, a
    jr nz, jr_017_5b50

    ld hl, $5b59

jr_017_5b4b:
    call Call_000_3c79
    jr jr_017_5b56

jr_017_5b50:
    ld hl, $5c08
    call Call_000_3c79

jr_017_5b56:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ret nz

    ld c, b
    rst $20
    ld c, a
    ret nc

    or h
    ret z

    push bc
    ld a, a
    db $d3
    push bc
    jp $cecf


    call nz, $cc7f
    rst $08
    jp Jump_017_7fcb


    rst $08
    ld c, a
    add $7f
    call nc, $c5c8
    ld a, a
    push bc
    call z, $c3c5
    call nc, $c9d2

jr_017_5b7f:
    jp $c47f


    rst $08
    ld d, l
    rst $08
    jp nc, Jump_017_7f7f

    ret


    db $d3
    ld a, a
    rst $08
    ret nc

    push bc
    adc $c5
    call nz, $7f81
    ld d, c
    xor [hl]
    rst $08
    rst $10
    ld a, a
    call nc, $c5c8
    ld a, a
    call z, $d2c1
    rst $00
    push bc
    ld a, a
    push bc
    call z, $4fc5
    jp $d2d4


    ret


    jp $c47f


    rst $08
    rst $08
    jp nc, $c1c8

    db $d3
    ld a, a
    jp nz, $c5c5

    ld d, l
    adc $7f
    rst $08
    ret nc

    push bc
    adc $c5
    call nz, $c37f
    rst $08
    call $ccd0
    push bc
    call nc, Call_017_55c5
    call z, $81d9
    ld d, c
    db $ec
    ld a, [hl]
    ld a, a
    ld d, b
    cp c
    push bc
    rst $20
    ld d, c
    cp a
    jp c, $7fc4

    sbc l
    sub b
    adc h
    jp z, $d67f

    or e
    inc l
    sbc $7f
    inc a
    or [hl]
    or d
    rst $20
    ld c, a
    or [hl]
    jp c, $7fc9

    call $cad4
    ld a, a
    xor b
    xor h
    add a
    ld a, a
    cp e
    jp c, Jump_017_55c3

    or [hl]
    sbc $c0
    sbc $c6
    jp z, $ca7f

    or d
    jp c, $b2c5

    ld l, $e7
    ld d, a
    db $ed
    dec hl
    ld [hl-], a
    ld c, d
    cp d
    cp b
    cp e
    or d
    ld a, a
    inc l
    or c
    or d
    add $4f
    or a
    sbc $c1
    ld [c], a
    db $e3
    ld a, a
    cp h
    ret nz

    ld l, $57
    inc bc
    ld [bc], a
    ld de, $0304
    rst $38
    ld de, $0305
    rst $38
    nop
    dec b
    ld hl, $0905
    rst $38
    ret nc

    ld b, c
    db $ec
    ld bc, $0a10
    dec c
    rst $38
    jp nc, $f142

    inc bc
    inc c
    inc c
    rlca
    rst $38
    jp nc, $dc43

    ld bc, $0e13
    inc b
    rst $38
    db $d3
    ld b, h
    call z, $2408
    ld [de], a
    ld [$d0ff], sp
    dec b
    ld c, [hl]
    rst $00
    ld de, $4e04
    rst $00
    ld de, $2c05
    dec h
    dec h
    ld h, $2c
    inc l
    dec b
    dec b
    dec b
    inc l
    ld a, [hl+]
    dec hl
    dec b
    ld a, [hl+]
    dec hl
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    daa
    dec b
    add hl, hl
    dec b
    jr z, jr_017_5c82

    dec b
    ld de, $1005
    dec b

jr_017_5c82:
    dec b
    dec b
    inc b
    dec b
    dec b
    inc b
    inc b
    inc b
    db $10
    ld b, b
    sub [hl]
    ld e, h
    sub e
    ld e, h
    nop
    dec [hl]
    ld e, a
    jp Jump_000_3c6c


    and h
    ld e, h
    ld e, l
    ld e, [hl]
    sub e
    ld e, [hl]
    sub e
    ld e, [hl]
    sub e
    ld e, [hl]
    or d
    ld e, [hl]
    sub $5e
    ld [$2efa], sp
    rst $10
    bit 0, a
    jr nz, jr_017_5ced

    ld a, $01
    ld [$cc3c], a
    ld hl, $5cf6
    call Call_000_3c79
    ld b, $33
    call Call_000_34dd
    jr z, jr_017_5cf3

    ld hl, $5d78
    call Call_000_3c79
    ld bc, $e701
    call Call_000_3e5e
    jr nc, jr_017_5ce5

    ld hl, $5daf
    call Call_000_3c79
    ld a, $33
    ldh [$db], a
    ld b, $05
    ld hl, $7fae
    call Call_000_3620
    ld hl, $d72e
    set 0, [hl]
    jr jr_017_5cf3

jr_017_5ce5:
    ld hl, $5e4e
    call Call_000_3c79
    jr jr_017_5cf3

jr_017_5ced:
    ld hl, $5dfd
    call Call_000_3c79

jr_017_5cf3:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld l, h
    ld c, d
    or c
    rst $20
    ld a, a
    cp d
    sbc $c6
    pop bc
    jp z, Jump_017_4fe7

jr_017_5d04:
    or a
    ret nc

    ld a, a
    ld d, h
    ld a, a
    cp l
    or a
    or [hl]
    or d
    and $51
    ld d, d
    ld [hl], d
    ld a, $b8
    ld a, a
    inc l
    ldh [$c5], a
    cp b
    rst $18
    jp $b74f


    ret nc

    add $7f
    or a
    or d
    jp $ded9


    jr nc, @+$81

    cp c
    inc [hl]
    ld d, c
    ld d, d
    ld [hl], d
    ld d, [hl]
    ld a, a
    or h
    db $e3
    ld a, a
    push bc
    sbc $30
    sub $e7
    ld c, a
    call $c5ab
    ld a, a
    call nc, Call_017_7fc2
    jr nc, jr_017_5d04

jr_017_5d3f:
    or c
    rst $20
    ld d, c
    and c
    sbc b
    sbc l
    sub a
    pop de
    cp l
    jp nc, Jump_017_5672

    ld a, a
    push bc
    add $e6
    ld c, a
    set 0, h
    ret


    ld a, a
    sbc l
    sub a
    ld a, a
    cp l
    sbc $c5
    rst $18
    jp Jump_017_51e6


    jr nc, jr_017_5d3f

    jp $b17f


    ret nz

    cp h
    ld a, a
    ld c, a
    db $d3
    ret


    rst $08
    ret z

    ld a, a
    cp h
    pop hl
    ret nc

    ld a, a
    push bc
    sbc $30
    ld a, a
    db $d3
    sbc $e7
    ld e, b
    db $ed
    dec hl
    inc [hl]
    ld c, e
    rst $20
    ld c, a
    ld b, c
    xor h
    ld b, c
    add $de
    daa
    ld [c], a
    or e
    ld a, a
    cp b
    jp c, $c9d9

    db $e3
    rst $20

jr_017_5d8d:
    ld d, c
    or e
    jp c, $e3bc

    or d
    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    inc l
    ldh [$b1], a
    ret z

    db $e3
    rst $20
    ld c, a
    call c, $bcc0
    ld a, a
    or [hl]
    rst $10
    jp z, $ba7f

    jp c, $b17f

    add hl, hl
    reti


    db $e3
    rst $20
    ld e, b
    db $ed
    dec hl
    ld a, [hl]
    ld c, e
    pop de
    cp l
    jp nc, $debb

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
    nop
    ld d, c
    ld e, h
    ld sp, hl
    rst $30
    ret


    ld a, a
    push bc
    or [hl]
    jp z, $dc4f

    ret nz

    cp h
    ret


    ld a, a
    jr nc, jr_017_5d8d

    cp l
    or a
    push bc
    ld a, a
    db $d3
    ret


    rst $08
    ret z

    rst $20
    ld d, c
    or c
    push bc
    ret nz

    ret


    ld a, a
    cp l
    or a
    push bc
    ld a, a
    ld d, h
    add $4f
    jp nz, $dfb6

    jp $b17f


    add hl, hl
    jp Jump_017_50e7


    dec c
    ld d, b
    db $ed
    dec hl
    rst $38
    ld c, e
    or c
    rst $20
    ld a, a
    cp e
    rst $18
    or a
    jp z, $5c4f

    ld a, a
    or c
    ret c

    ld h, $c4
    or e
    rst $20
    ld d, c
    ld d, d
    ld [hl], d
    ld d, [hl]
    ld a, a
    push bc
    db $e3
    add $e6
    ld d, c
    ld d, d
    ld [hl], d
    ld a, $b8
    ret


    ld a, a
    rst $08
    ret z

    ld a, a
    cp h
    jp $bf4f


    sbc $c5
    add $7f
    ret nz

    ret


    cp h
    or d
    ld a, a
    or [hl]
    or d
    and $51
    and c
    sbc b
    sbc l
    sub a
    pop de
    cp l
    jp nc, $b372

    sbc $56
    rst $20
    ld c, a
    call nz, $c3df
    db $d3
    ld a, a
    ret nz

    ret


    cp h
    or d
    db $e3
    rst $20
    ld d, a
    db $ed
    dec hl
    rst $20
    ld c, e
    ld h, $7f
    or d
    rst $18
    ld b, h
    or d
    ret z

    rst $20
    ld d, b
    dec c
    ld d, b
    db $ed
    daa
    db $d3
    ld b, h
    db $e3
    ld [hl], d
    ld b, $e3
    ld a, a
    ld b, $e3
    xor h
    rst $20
    ld d, c
    ld d, [hl]
    ld a, a
    add l
    dec b
    sbc [hl]
    ld a, a
    and h
    ld a, a
    add l
    dec b
    sbc [hl]
    rst $20
    ld c, a
    adc l
    add l
    add c
    ld [de], a
    ld a, a
    add c
    sub b
    add hl, de
    xor e
    ld a, a
    add l
    xor c
    add c

jr_017_5e85:
    add c
    ld d, l
    add h
    xor e
    sub h
    sbc b
    adc c
    sbc c
    ld a, a
    rrca

jr_017_5e8f:
    db $e3
    and a
    and $57
    db $ed
    daa
    and a
    ld b, l
    ld a, a
    jp nc, $d72d

    cp h
    or d
    ld a, a
    ld d, h
    rst $20
    and $4f
    ld d, [hl]
    ld a, a
    or c
    jp c, $7fe6

    rst $00
    or d
    jr z, jr_017_5e85

    ret nc

    ld a, a
    jr nc, jr_017_5e8f

    ret nz

    ld d, a
    db $ed
    daa
    db $dd
    ld b, l
    ld d, [hl]
    rst $20
    ld c, a
    sbc l
    ret c

    add h

jr_017_5ebc:
    ld h, $7f
    add hl, de
    adc b
    sub c
    db $dd
    ld a, a
    or [hl]
    inc a
    rst $18
    jp $b155


    reti


    or d
    jp $b27f


    cp b
    ld a, a
    ld [$9fe3], sp
    jr nc, jr_017_5ebc

    ld d, a
    ld [$09fa], sp
    pop bc
    cp $04
    ld hl, $5f2b
    jr nz, jr_017_5ee4

    ld hl, $5eea

jr_017_5ee4:
    call Call_000_3c79
    jp Jump_000_0f6a


    db $ed
    dec hl
    sub c
    ld c, h

jr_017_5eee:
    ld a, a
    ld d, [hl]
    ld d, c
    call c, $bcc0
    ret


    ld a, a
    set 2, b
    jp nz, $e756

    ld d, c
    call nz, $b2b8
    push bc
    db $d3
    ret


    ld a, a
    ld d, [hl]
    ld a, a
    db $d3
    ret


    rst $08
    ret z

    rst $20
    ld c, a
    cp h
    pop hl
    ret nc

    ld a, a
    ld d, [hl]
    ld a, a
    rst $00
    or d
    jr z, jr_017_5eee

    ret nc

    rst $20
    ld d, l
    cp l
    or a
    push bc
    db $d3
    ret


    ld a, a
    ld d, [hl]
    ld a, a
    ld b, c
    xor h
    ld b, c
    rst $20
    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld d, a
    db $ed
    dec hl
    db $76
    ld c, h
    or h
    push bc
    or d
    cpl
    ld d, [hl]
    ld d, a
    ld a, [bc]
    ld bc, $0701
    ld [bc], a
    xor a
    ld [bc], a
    dec b
    inc bc
    ld b, $01
    nop
    rlca
    dec b
    dec e
    rlca
    ld [$00fe], sp
    ld bc, $0a09
    ld [$02fe], sp
    ld [bc], a
    dec b
    dec b
    add hl, bc
    rst $38
    ret nc

    inc bc
    add hl, bc
    inc b
    ld b, $ff
    ret nc

    inc b
    jr c, @+$0c

    dec b
    rst $38
    db $d3
    dec b
    or $c6
    ld bc, $0507
    ld b, $05
    ld [hl-], a
    ld h, h
    rla
    ld h, b
    ld [hl], c
    ld e, a
    nop
    ld [$cd63], a
    ld l, h
    inc a
    ld hl, $6027
    ld de, $5f8f
    ld a, [$d5c1]
    call Call_000_31a8
    ld [$d5c1], a
    ret


Jump_017_5f84:
    xor a
    ld [$cd66], a
    ld [$d5c1], a
    ld [$d97c], a
    ret


    sub a
    ld e, a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    jp c, $fa5f

    jr nc, @-$27

    bit 0, a
    ret nz

    call Call_000_3261
    ld a, [$cc55]
    and a
    ret nz

    ld a, [$d730]
    bit 1, a
    ret nz

    xor a
    ldh [$b4], a
    ld [$cf08], a
    ld a, [$d2e0]
    cp $03
    ret nz

    ld a, [$d2e1]
    cp $04
    ret nz

    ld a, $01
    ld [$cf08], a
    ld a, $01
    ld [$d4a7], a
    ld a, $01
    ldh [$8c], a
    ld a, $08
    ldh [$8d], a
    call Call_000_34f0
    ld a, $01
    ldh [$8c], a
    call Call_000_13f1
    ret


    ld a, [$d034]
    cp $ff
    jp z, Jump_017_5f84

    ld a, [$cf08]
    and a
    jr z, jr_017_5ff8

    ld a, $01
    ld [$d4a7], a
    ld a, $01
    ldh [$8c], a
    ld a, $08
    ldh [$8d], a
    call Call_000_34f0

jr_017_5ff8:
    ld a, $f0
    ld [$cd66], a
    ld a, [$d730]
    or $3e

jr_017_6002:
    ld [$d730], a
    ld a, $08
    ldh [$8c], a
    call Call_000_13f1
    xor a
    ld [$cd66], a
    ld [$d5c1], a
    ld [$d97c], a
    ret


    ld e, b
    ld h, b
    sub b
    ld h, c
    db $f4
    ld h, c
    ld d, d
    ld h, d
    jp nz, Jump_000_1f62

    ld h, e
    ld a, a
    ld h, e
    inc b
    ld h, c
    ld [bc], a
    ld b, b
    jr nc, jr_017_6002

    sbc d
    ld h, c
    cp l
    ld h, c
    or h
    ld h, c
    or h
    ld h, c
    inc bc
    ld b, b
    jr nc, @-$27

    cp $61
    dec hl
    ld h, d
    ld e, $62
    ld e, $62
    inc b
    jr nc, @+$32

    rst $10
    ld e, h
    ld h, d
    sbc l
    ld h, d
    sub d
    ld h, d
    sub d
    ld h, d
    dec b
    jr nc, jr_017_607e

    rst $10
    call z, $f962
    ld h, d
    xor $62
    xor $62
    rst $38
    ld [$30fa], sp
    rst $10
    bit 0, a
    jp nz, Jump_017_6091

    bit 1, a
    jp nz, Jump_017_6099

    ld hl, $60a2
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $60f1
    ld de, $60f1
    call Call_000_339c
    ldh a, [$8c]

jr_017_607e:
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    ld a, $03
    ld [$d5c1], a
    ld [$d97c], a
    jr jr_017_609f

Jump_017_6091:
    ld hl, $616b
    call Call_000_3c79
    jr jr_017_609f

Jump_017_6099:
    ld hl, $6104
    call Call_000_3c79

jr_017_609f:
    jp Jump_000_0f6a


    db $ed
    dec hl
    add sp, $4c
    rst $20
    ld d, c
    call c, $26bc
    ld a, a
    or [hl]
    cp b
    call nz, $7fb3
    inc [hl]
    or e
    inc l
    ld [c], a
    or e
    ret


    ld c, a
    cp h
    jp z, Jump_017_7fde

    add l
    and l
    sub d
    ld a, a
    jr nc, @-$4c

    or l
    or e
    ld a, a
    inc sp
    or c
    reti


    rst $20
    ld d, c
    or l
    rst $00
    cp h
    jp z, $347f

    or e
    inc l
    ld [c], a
    or e
    ld a, a
    call nc, $d83c
    or [hl]
    rst $20
    ld c, a
    push bc
    rst $10

jr_017_60dd:
    ld a, [hl-]
    ld a, a
    sub $b3
    cp h
    ldh [$ca], a
    ld a, a
    cp [hl]
    sbc $2f
    rst $20
    ld d, c
    sub e
    add h
    ret c

    xor l
    db $e3
    rst $20
    ld d, a
    db $ed
    inc l
    jr c, jr_017_6142

    xor l

jr_017_60f6:
    rst $20
    ld c, a
    jr nc, jr_017_60dd

    rst $20
    ld a, a
    call nc, $dad7
    ret nz

    or c
    db $e3
    rst $20
    ld e, b
    db $ed
    dec hl
    rst $30
    ld c, l
    ld a, a
    ret nz

    cp h
    or [hl]
    add $7f
    rst $08
    cp c
    ret nz

    rst $20
    ld d, c
    cp h
    or [hl]
    cp h
    ld a, a
    inc [hl]
    or e
    inc l
    ld [c], a
    or e
    ret


    ld a, a
    or [hl]
    sbc $3a
    sbc $4f
    ld d, [hl]
    ld a, a
    jr nc, @-$45

    jp z, Jump_017_55e7

    db $d3
    rst $18
    jp $b27f


    or [hl]
    push bc
    or d
    inc sp
    ld a, a
    cp b
    jp c, $e7b2

    ld d, c
    or [hl]
    call c, $c6d8
    ld a, a
    call c, $c9bc
    ld a, a

jr_017_6142:
    jr nc, jr_017_60f6

    inc l
    push bc
    ld c, a
    or [hl]
    cp b
    call nz, $7fb3
    ld d, h
    db $dd
    ld a, a
    call c, $bdc0
    rst $20
    ld d, c
    inc [hl]
    or e
    or [hl]
    rst $20
    ld c, a
    cp l
    or a

jr_017_615b:
    push bc
    ld a, a
    adc $b3
    db $dd
    ld a, a
    or h
    rst $10
    sbc $33
    ld a, a
    cp b
    jp c, $e7b2

    ld d, a
    db $ed
    dec hl
    and b
    ld c, l
    rst $20
    ld d, c
    inc [hl]
    or e
    jr nc, jr_017_615b

    ld a, a
    jp nz, Jump_000_33b2

    add $7f
    cp d
    cp d
    inc sp
    ld c, a
    add l
    and l
    sub d
    ld a, a
    jp c, $bcde

    pop hl
    or e
    ld a, a
    cp h
    jp $b8b2


    or [hl]
    rst $20
    ld d, a
    ld [$2721], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    rst $20
    ld b, [hl]
    adc h
    xor h
    rst $20
    ld c, a
    or a
    cp e
    rst $08
    rst $20
    ld a, a
    inc [hl]
    or e
    inc l
    ld [c], a
    or e
    ld a, a
    call nc, $d83c
    ld a, a
    or [hl]
    rst $20
    ld d, a
    db $ed
    daa
    or l
    ld b, a
    or d
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    jr z, jr_017_6208

    sbc $7f
    cp l
    reti


    ret


    jp z, $bc4f

    jp z, $c6de

    ld a, a
    or [hl]
    rst $18
    jp $b67f


    rst $10
    add $7f
    cp h
    db $db
    rst $20
    ld d, c
    or l
    jp c, $7fc6

    or [hl]
    rst $18
    jp Jump_017_4fd3


    ret nz

    or d
    cp h
    ret nz

    ld a, a
    cp d
    call nz, $c57f
    or d
    ld l, $e7
    ld a, a
    add h
    adc h
    xor h
    rst $20
    ld d, a
    ld [$3321], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    pop bc
    ld b, a
    rst $20
    ld a, a
    or e
    inc sp
    ld h, $7f

jr_017_6208:
    ret nz

    jp nz, $d77f

    cp h
    or d
    push bc
    rst $20
    ld c, a
    or h
    sbc $d8
    ld [c], a
    ld a, a
    push bc
    cp b
    ld a, a
    or d
    cp b
    ld l, $e7
    ld d, a
    db $ed
    daa
    add l
    ld c, b
    adc h
    rst $20
    ld a, a

jr_017_6225:
    call c, $b12b
    ret c

    rst $20
    ld e, b
    db $ed
    daa
    dec bc
    ld c, b
    jp z, $b67f

    cp b
    call nz, $b6b3
    ret


    ld a, a
    or [hl]
    ret nc

    cp e
    rst $08
    jr nc, jr_017_6225

    ld c, a
    or d
    inc [hl]
    pop de
    call nz, $b27f
    or e
    push bc
    rst $10
    ld a, a
    or [hl]
    cp b
    ld a, [hl+]
    ld a, a
    cp h
    jp $b9b2


    ld d, a
    ld [$3f21], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    sbc [hl]
    ld c, b
    sub e
    db $e3
    rst $20
    ld c, a
    or [hl]
    ret nz

    or d
    ld a, a
    db $d3
    ret


    ld a, a
    push bc
    inc [hl]
    ld a, a
    cp d
    call c, $7fb8
    push bc
    or d
    rst $20
    ld d, c
    rst $08
    or d
    add $c1
    ld a, a
    cp d
    inc a
    cp h
    inc sp
    ld c, a
    or d
    call c, Call_017_7fdd
    call c, Call_017_7fd9
    jp c, $bcde

    pop hl
    or e
    ld a, a
    cp h
    jp $e7d9


jr_017_6291:
    ld d, a
    db $ed
    daa
    ld d, b
    ld c, c
    rst $20
    ld a, a
    add h
    adc h
    xor h
    rst $20
    ld e, b
    db $ed
    daa
    db $fd
    ld c, b
    or e
    or [hl]
    ld h, $7f
    cp d
    call c, Call_017_7fb2
    db $d3
    ret


    ld a, a
    push bc
    inc [hl]
    ld c, a
    pop bc
    ld [c], a
    or e
    ret


    or e
    ret c

    ld [c], a
    cp b
    ld a, a
    jr z, jr_017_6291

    or d
    jr nc, @-$17

    add h
    adc h
    xor h
    rst $20
    ld d, a
    ld [$4b21], sp
    ld h, b
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld e, h
    ld c, c
    rst $20
    ld d, c
    cp d
    cp d
    db $dd
    ld a, a
    or [hl]
    cp b
    call nz, $7fb3
    inc [hl]
    or e
    inc l
    ld [c], a
    or e
    call nz, $bc4f
    rst $18
    jp $7fc9


    inc a
    jp c, Jump_017_7fb2

    or [hl]
    rst $20
    ld d, a
    db $ed
    daa
    ld hl, $7f4a
    rst $08
    or d
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    sbc l
    ld c, c
    ld a, a
    ld l, $de

jr_017_6300:
    cp d
    cp b
    ret


    ld a, a
    or [hl]
    cp b
    call nz, $b6b3
    ld a, a
    ld h, $4f
    or c
    jp nz, $d9cf

    ld a, a
    inc [hl]
    or e
    inc l
    ld [c], a
    or e
    ld a, a
    jr nc, jr_017_6300

    ld a, a
    add h
    adc h
    xor h
    rst $20
    ld d, a
    ld [$30fa], sp
    rst $10
    and $c0
    jr z, jr_017_632f

    ld hl, $63dd
    call Call_000_3c79
    jr jr_017_635f

jr_017_632f:
    ld a, $2b
    call Call_000_34e5
    ld hl, $6362
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_017_635f

    ld a, [$cf78]
    ld b, a
    ld c, $1e
    call Call_000_3e78
    jr nc, jr_017_635f

    ld a, $4a
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d
    ld hl, $d730
    set 6, [hl]
    set 0, [hl]

jr_017_635f:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ret


    ld c, [hl]
    rst $20
    ld a, a
    add [hl]
    xor h
    add a
    ld a, a
    call c, $c92b
    or l
    add $e7
    ld c, a
    adc d
    xor c
    sbc a
    and l
    db $e3
    db $dd
    ld a, a
    call nz, $b6d9
    and $57
    ld [$30fa], sp
    rst $10
    and $c0
    jr z, jr_017_638f

    ld hl, $63dd
    call Call_000_3c79
    jr jr_017_63bf

jr_017_638f:
    ld a, $2c
    call Call_000_34e5
    ld hl, $63c2
    call Call_000_3c79
    call Call_000_3636
    ld a, [$cc26]
    and a
    jr nz, jr_017_63bf

    ld a, [$cf78]
    ld b, a
    ld c, $1e
    call Call_000_3e78
    jr nc, jr_017_63bf

    ld hl, $d730
    set 7, [hl]
    set 0, [hl]
    ld a, $4b
    ld [$cc4d], a
    ld a, $11
    call Call_000_3e9d

jr_017_63bf:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld a, [hl+]
    ld c, a
    rst $20
    ld a, a
    or e
    push bc
    reti


    ld a, a
    cp d
    inc a
    cp h
    rst $20
    ld c, a
    add e
    ld a, [de]
    xor c
    and l
    db $e3
    add $7f
    cp l
    reti


    or [hl]
    and $57
    db $ed
    dec hl
    rrca
    ld c, a
    reti


    ret


    jp z, $d67f

    cp a
    or e
    ld d, [hl]
    ld d, a
    inc bc
    ld [bc], a
    dec bc
    inc b
    ld bc, $0bff
    dec b
    ld bc, $00ff
    rlca
    ld c, $07
    add hl, bc
    rst $38
    ret nc

    ld b, c
    ldh [rSB], a
    ld c, $08
    rlca
    rst $38
    db $d3
    ld b, d
    ldh [rSC], a
    ld c, $0a
    rlca
    rst $38
    db $d3
    ld b, e
    ldh [$03], a
    ld c, $09
    add hl, bc
    rst $38
    jp nc, $e044

    inc b
    ld c, $0b
    add hl, bc
    rst $38
    jp nc, $e045

    dec b
    dec a
    dec b
    ld [$ffff], sp
    ld b, $3d
    dec b
    add hl, bc
    rst $38
    rst $38
    rlca
    dec l
    rst $00
    dec bc
    inc b
    dec l
    rst $00
    dec bc
    dec b
    ld c, c
    ld c, d
    ld h, a
    ld c, c
    ld c, d
    ld c, e
    ld d, c
    dec b
    ld d, b
    ld c, h
    ld c, e
    dec b
    dec b
    dec b
    ld c, h
    ld c, e
    dec b
    dec b
    dec b
    ld c, h
    ld c, e
    ld [hl-], a
    dec b
    ld sp, $524c
    ld b, [hl]
    inc b
    ld b, [hl]
    ld l, a
    ld d, $09
    ld a, [bc]
    db $d3
    ld l, h
    db $ed
    ld h, h
    ld e, h
    ld h, h
    nop
    adc c
    ld l, e
    ld hl, $d0eb
    bit 6, [hl]
    res 6, [hl]
    jr nz, jr_017_6478

    call Call_000_3c6c
    ld hl, $6505
    ld de, $6495
    ld a, [$d5db]
    call Call_000_31a8
    ld [$d5db], a
    ret


jr_017_6478:
    ld hl, $6481
    ld de, $6486
    jp Jump_000_31c7


    and d
    sbc l
    dec de
    add [hl]
    ld d, b
    sub h
    sub c
    and b
    ld d, b

Jump_017_648a:
    xor a
    ld [$cd66], a
    ld [$d5db], a
    ld [$d97c], a
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    sbc l
    ld h, h
    ld a, [$d034]
    cp $ff
    jp z, Jump_017_648a

    ld a, $f0
    ld [$cd66], a

Call_017_64aa:
    ld a, $0a
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d732
    set 1, [hl]
    ld bc, $f601
    call Call_000_3e5e
    jr nc, jr_017_64cc

    ld a, $0b
    ldh [$8c], a
    call Call_000_13f1
    ld hl, $d732
    set 0, [hl]
    jr jr_017_64d3

jr_017_64cc:
    ld a, $0c
    ldh [$8c], a
    call Call_000_13f1

jr_017_64d3:
    ld hl, $d2d5
    set 5, [hl]
    ld hl, $d6a9
    set 5, [hl]
    ld a, [$d732]
    or $fc
    ld [$d732], a
    ld hl, $d733
    set 0, [hl]
    jp Jump_017_648a


    ld e, d
    ld h, l
    sub c
    ld h, a
    dec e
    ld l, b
    add d
    ld l, b
    xor $68
    ld h, e
    ld l, c
    cp a
    ld l, c
    ld d, e
    ld l, d
    adc $6a
    cp d
    ld h, [hl]
    ld a, $67
    add e
    ld h, a
    ld [bc], a
    jr nc, jr_017_653a

    rst $10
    sbc e
    ld h, a
    jp nc, $c767

    ld h, a
    rst $00
    ld h, a
    inc bc
    jr nc, jr_017_6546

    rst $10
    daa
    ld l, b
    ld d, a
    ld l, b
    ld b, a
    ld l, b
    ld b, a
    ld l, b
    inc b
    jr nc, jr_017_6552

    rst $10
    adc h
    ld l, b
    pop bc
    ld l, b
    cp d
    ld l, b
    cp d
    ld l, b
    dec b
    jr nc, jr_017_655e

    rst $10
    ld hl, sp+$68
    ld [hl], $69
    ld [hl+], a
    ld l, c
    ld [hl+], a
    ld l, c
    ld b, $30
    ld [hl-], a
    rst $10
    ld l, l

jr_017_653a:
    ld l, c
    sbc b
    ld l, c
    add e
    ld l, c
    add e
    ld l, c
    rlca
    jr nc, jr_017_6576

    rst $10
    ret


jr_017_6546:
    ld l, c
    ld a, [bc]
    ld l, d
    rst $38
    ld l, c
    rst $38
    ld l, c
    ld [$3230], sp
    rst $10
    ld e, l

jr_017_6552:
    ld l, d
    xor c
    ld l, d
    and c
    ld l, d
    and c
    ld l, d
    rst $38
    ld [$32fa], sp
    rst $10

jr_017_655e:
    bit 1, a
    jr z, jr_017_6576

    bit 0, a
    jr nz, jr_017_656e

    call z, Call_017_64aa
    call Call_000_30fe
    jr jr_017_65a1

jr_017_656e:
    ld hl, $667a
    call Call_000_3c79
    jr jr_017_65a1

jr_017_6576:
    ld hl, $65a4
    call Call_000_3c79
    ld hl, $d6ac
    set 6, [hl]
    set 7, [hl]
    ld hl, $6617
    ld de, $6617
    call Call_000_339c
    ldh a, [$8c]
    ld [$cf0e], a
    call Call_000_33b2
    call Call_000_331f
    ld a, $06
    ld [$d039], a
    ld a, $03
    ld [$d5db], a

jr_017_65a1:
    jp Jump_000_0f6a


    db $ed
    dec hl
    cp e
    ld c, a
    rst $18
    ld b, h
    ret c

    ld a, a
    or a
    ret nz

    call c, Call_017_4fe7
    sub $b6
    sbc $26
    ld a, a
    cp h
    ret nz

    ret


    sub $e7
    ld d, c
    push bc
    add $29
    add $7f
    adc h
    ld b, d
    db $e3
    xor e
    db $dd
    ld a, a
    push bc
    add hl, hl
    ret nz

    rst $10
    ld c, a
    rst $08
    ld h, $df
    jp $b27f


    rst $10
    or d
    ld d, [hl]
    ld a, a
    call c, $bcc0
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
    ld a, a
    push bc
    ret


    ld d, c
    ret nz

    ret nz

    or [hl]
    or e
    ret


    ld a, a
    cp l
    or a
    ld a, a
    inc l
    ldh [$c5], a
    or d
    ld a, a
    cp c
    inc [hl]
    ld c, a
    or c
    push bc
    ret nz

    ld h, $7f
    ret


    cpl
    pop de
    ld a, a
    push bc
    rst $10
    ld d, l
    call c, $bcc0
    ret


    ld a, a
    pop bc
    or [hl]
    rst $10
    ld d, l
    ret nc

    cp [hl]
    jp $b17f


    add hl, hl
    reti


    rst $20
    ld d, a
    db $ed
    inc l
    ld b, $4e
    ld a, a
    push bc
    sbc $c3
    ld d, [hl]
    rst $20
    ld c, a
    call nz, $d3c3
    ld a, a
    adc e
    xor a
    xor h
    add a
    rst $20
    ld d, l
    inc sp
    db $d3
    ld a, a
    rst $08
    cp c
    jp z, $cf7f

    cp c
    ld d, [hl]
    rst $20
    ld d, c
    call c, $bcc0
    ret


    ld a, a
    cp h
    ld [c], a
    or e
    inc a
    ret


    ld a, a
    or c
    rst $08
    cp e
    db $dd
    ld c, a
    or d
    cp e
    daa
    sub $b8
    ld a, a
    ret nc

    call nz, $d9d2
    call c, Call_017_51e7
    or [hl]
    rst $18
    ret nz

    ld a, a
    or c
    or [hl]
    cp h
    add $4f
    add hl, bc
    db $e3
    and [hl]
    inc de
    ld a, a
    add hl, de
    xor h
    dec bc
    db $dd
    ld d, l
    or c
    push bc
    ret nz

    add $7f
    cp e
    cp h
    or c
    add hl, hl
    ld a, a

jr_017_6672:
    rst $08
    cp h
    ld [c], a
    or e
    ld d, b

jr_017_6677:
    ld de, $5006
    db $ed
    dec hl
    ld e, [hl]
    ld c, a
    ret


    or e
    ret c

    ld [c], a
    cp b
    jp z, $b67f

    daa
    rst $10
    jp c, Jump_017_4fc0

    set 0, h
    ret


    ld a, a
    pop bc
    or [hl]
    rst $10
    ld a, a
    inc sp
    jp z, $c57f

    or d
    call c, Call_017_55e7
    jr nc, jr_017_6677

    inc sp
    db $d3
    ld a, a
    db $d3
    rst $18
    jp $c9d9


    sub $e7
    ld d, l
    ret nz

    jr nc, @+$81

    cp a
    jp c, $7fc6

    or a
    ld h, $7f
    jp nz, $c5b6

    or d
    ld a, a
    jr nc, jr_017_6672

    ld d, a
    db $ed
    daa
    ld a, $4a
    inc de
    ld a, a
    add hl, de
    xor h
    dec bc
    inc sp
    ld c, a
    and a
    dec a
    and [hl]

jr_017_66c8:
    db $fd
    or $7f
    rst $08
    inc sp
    ret


    ld a, a
    ld d, h
    ld h, $55
    or d
    or e
    cp d
    call nz, Call_017_7fdd
    or a
    or a
    rst $08
    cp l
    rst $20
    ld d, c
    cp a
    jp c, $b27f

    inc l
    ld [c], a
    or e
    ld c, a
    jp nz, $b2d6

    ld a, a
    ld d, h
    jp z, $8e55

    xor h
    ld b, e
    ld a, a
    pop de
    or d
    ret nz

    ret c

    ld a, a
    call z, $c8c3
    ld a, a
    cp h
    ret nz

    ret c

    ld d, l
    or c
    jp nz, $b2b6

    ld h, $7f
    ret nz

    or d
    call Call_017_7fde
    inc sp
    cp l
    rst $20
    ld d, c
    jr nc, jr_017_66c8

    inc [hl]
    ld a, a
    cp a
    jr nc, @-$3b

    ld a, a
    cp l
    daa
    push bc
    or a
    ldh [rVBK], a
    cp a
    or e
    or d
    or e
    ld a, a
    cp h
    sbc $44
    or d
    jp z, $d17f

    sub $b3
    sub $e7
    ld d, c
    cp a
    jp c, $d7b6

    ld d, [hl]
    rst $20
    ld c, a
    ld e, h
    db $dd
    ld a, a
    db $d3
    rst $18
    jp $b27f


    rst $18
    jp $ed57


    daa
    ld d, e
    ld c, e
    sub h
    sub c
    and b
    or [hl]
    rst $10
    ld c, a
    ld e, h
    ld a, [$ddfc]
    ld a, a
    db $d3
    rst $10
    rst $18
    ret nz

    rst $20
    ld d, b
    dec bc
    nop
    ld d, c
    ld e, h
    ld a, [$cafc]
    ld a, a
    adc d
    add c

jr_017_675d:
    adc c
    add d
    db $eb
    db $e3
    dec de
    rst $20
    ld c, a
    or a
    ld [c], a
    or e
    ret c

    ld [c], a
    cp b
    push bc
    ld a, a
    ret z

    sbc $44
    ld h, $55
    or l
    or l
    or a
    push bc
    ld a, a
    rrca
    and b
    db $e3
    dec bc
    db $dd
    ld a, a
    or c
    ret nz

    or h
    reti


    call c, $57e7
    db $ed
    daa
    call nc, $d34b
    jp nz, Jump_017_7f26

    or d
    rst $18
    ld b, h
    or d
    sub $57
    ld [$0521], sp
    ld h, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld a, [$ca4b]
    ld d, [hl]
    ld a, a
    call c, $bcc0
    ld a, a
    sub $d8
    ld c, a
    jr nc, jr_017_675d

    inc a
    ld a, a
    call nz, $bcbc
    ret nz

    ld a, a
    jr nc, jr_017_67da

    rst $20
    ld d, l
    or [hl]
    ret


    inc l
    ld [c], a
    db $dd
    ld a, a
    cp a
    sbc $b9
    or d
    ld a, a
    cp h
    jp $d9b2


    rst $20
    ld d, a
    db $ed
    daa
    cp $4c
    push bc
    or [hl]
    rst $18
    ret nz

    or [hl]
    rst $20
    ld e, b
    db $ed
    daa
    ccf
    ld c, h
    inc a
    ld h, $7f
    ld a, [hl+]

jr_017_67da:
    or [hl]
    cp b
    ret


    ld a, a
    call nz, $cab7
    ld c, a
    or a
    db $d3
    pop bc
    ld h, $7f
    jp nz, $b2d6

    ld a, a
    adc $b3
    ld h, $7f
    or [hl]
    jp nz, Jump_017_51e7

    sub h
    sub c
    and b
    add $7f
    or [hl]
    pop bc
    ret nz

    or d
    ld a, a
    push bc
    rst $10
    ld c, a
    or a
    ret nc

    db $d3
    ld a, a
    or [hl]
    pop bc
    ret nz

    or d
    xor h
    rst $20
    ld a, a
    call nz, $c255
    sub $b8
    ld a, a
    ret z

    sbc $2c
    ret nz

    ld a, a
    adc $b3
    ld h, $7f
    or d
    or d
    ld d, a
    ld [$1121], sp
    ld h, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld h, $4d
    or d
    ld a, a
    pop bc
    or [hl]
    rst $10
    db $dd
    ld a, a
    jp nz, $b3b6

    ld c, a
    add e
    adc h
    ld b, b
    db $e3
    db $dd
    ld a, a
    cp d
    call c, $c4b2
    ld a, a
    or l
    db $d3
    or e
    or [hl]
    rst $20
    ld d, a
    db $ed
    daa
    or $4d
    or e
    ld a, a
    cp d
    call nz, Call_017_4fd3
    or c
    reti


    ret


    or [hl]
    ld d, [hl]
    ld e, b
    db $ed
    daa
    ld l, d
    ld c, l
    db $e3
    add $7f
    push de
    or e
    ret c

    push bc
    ld a, a
    db $d3
    ret


    and $4f
    ld d, [hl]
    ld a, a
    jp z, $caca

    db $e3
    xor h
    rst $20
    ld d, l
    push de
    or e
    jp c, Jump_017_7fb2

    call nc, $d17f
    cp h
    ld a, a
    cp b
    rst $10
    or d
    ld a, a
    jr nc, jr_017_68ae

    rst $20
    ld d, a
    ld [$1d21], sp
    ld h, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld e, $4e
    or [hl]
    or d
    rst $00
    cp h
    add $7f
    add $d9
    rst $18
    jp $bc7f


    rst $18
    jp $b6d9


    and $51
    call nz, $b3b2
    ld a, a
    cp d
    call nz, Call_017_56ca
    ld c, a
    or l
    rst $08
    or h

jr_017_68ae:
    ret


    ld a, a
    ld d, h
    jp z, $c27f

    sub $b2
    or [hl]
    push bc
    and $57
    db $ed
    daa
    cp l
    ld c, [hl]
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    add b
    ld c, [hl]
    db $d3
    ld a, a
    rst $08
    jr nc, @+$81

    rst $08
    jr nc, jr_017_694c

    jr nc, jr_017_6925

    ld c, a
    adc d
    add c
    adc c
    add [hl]
    sub a
    adc e
    adc h
    ld a, a
    sbc l
    adc h
    adc a
    db $e3
    ld a, a
    cp h
    jp Jump_017_5455


    add $7f
    or l
    cp h
    or h
    jp $c57f


    cp b
    jp $e7ca


    ld d, a
    ld [$2921], sp
    ld h, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    call z, Call_017_7f4e
    call c, $dfb6
    jp Jump_017_7fd9


    jr nc, @-$23

    and $4f
    ld d, h
    jp z, Jump_017_407f

    xor c
    db $e3
    ld a, a
    jr nc, @-$45

    ld d, l
    or c
    rst $18
    ret nz

    rst $18
    jp $b67f


    jp $c57f


    or d
    ld a, a
    cp d
    call nz, $e7dd
    ld d, a
    db $ed
    daa
    sub h

jr_017_6925:
    ld c, a

jr_017_6926:
    jp c, Jump_017_4f26

    rst $08
    cp c
    reti


    ld a, a
    push bc
    sbc $c3
    ld a, a
    ld a, [hl-]
    or [hl]
    push bc
    rst $20
    ld e, b
    db $ed
    daa
    inc e
    ld c, a
    ret


    ld a, a
    add l
    and l
    sub d
    ld a, a
    jr nc, @-$4c

    or l
    or e
    ld a, a
    jr nc, jr_017_6926

    jp $b34f


    pop bc
    ret


jr_017_694c:
    ld a, a
    sub h
    sub c
    and b
    cp e
    sbc $c6
    ld d, l
    adc c
    sub d
    xor e
    ld b, b
    xor e
    add $7f
    call nc, $dad7
    ret nz

    sbc $30
    ld l, $57
    ld [$3521], sp
    ld h, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    cp h
    ld c, a
    ld a, a
    call c, $bcc0
    call nz, Call_017_544f
    db $dd
    ld a, a
    ret nz

    ret nz

    or [hl]
    call c, $d9be
    ld d, [hl]
    rst $20
    ld d, a
    db $ed
    daa
    ld c, [hl]
    ld d, b
    rst $20
    ld c, a
    call nc, $d8ca
    ld a, a
    call c, $bcc0
    ld h, $7f
    call nc, $da3c
    ret nz

    or [hl]
    ld e, b
    db $ed
    daa
    ld [c], a
    ld c, a
    or e
    ld a, a
    cp c
    rst $18
    or [hl]
    jp z, $dc7f

    or [hl]
    rst $18
    jp $56c0


    ld c, a
    ld d, [hl]
    ld a, a
    cp a
    or e
    rst $20
    ld d, l
    cp d
    jp c, Jump_017_7f26

    sub $c1
    ld a, a
    ret


    or e
    ret c

    ld [c], a
    cp b
    ld a, a
    jr nc, jr_017_6a16

    ld [$4121], sp
    ld h, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    ld h, e
    ld d, b
    cp e
    sbc $ca
    ld a, a
    call c, $b8b6
    ld a, a
    cp h
    jp $ba4f


    ret


    ld a, a
    ld d, h
    ld a, a
    dec bc
    sbc a
    db $dd
    ld a, a
    cp h
    or a
    reti


    ld d, l
    inc l
    jp nz, $e2d8

    cp b
    cp h
    ldh [$e7], a
    ld d, c
    or [hl]
    sbc $c0
    sbc $7f
    add $ca
    ld a, a
    or c
    call c, Call_017_7fbe
    push bc
    or d
    ld l, $e7
    ld d, a
    db $ed
    daa
    ld a, l
    ld d, c
    ld a, a
    cp h
    rst $08
    rst $18
    ret nz

    rst $20
    ld e, b
    db $ed
    daa
    pop de
    ld d, b
    jp $d47f


    db $db
    or e
    ld d, [hl]
    ld c, a
    or [hl]

jr_017_6a16:
    jp nz, Jump_017_7fc3

    and d
    sbc l
    dec de
    add [hl]
    ld a, a
    add $ca
    ld d, l
    call z, $c2c0
    ret


    ld a, a
    ld d, h
    ld a, a
    dec bc
    sbc a
    ld h, $7f
    or c
    rst $18
    ret nz

    ld d, c
    call nz, $b2b3
    jp nz, $bc7f

    or c
    or d
    add $7f
    rst $08
    cp c
    ret nz

    ld a, a
    ret


    ld h, $4f
    call nz, $d8c5
    ret


    ld a, a
    or [hl]
    cp b
    call nz, $7fb3
    inc [hl]
    or e
    inc l
    ld [c], a
    or e
    jr nc, @-$17

    ld d, a
    ld [$4d21], sp
    ld h, l
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    daa
    add [hl]
    ld d, c
    add [hl]
    ld a, a
    dec bc
    sbc a
    rst $20
    ld d, l
    rst $08
    ret nz

    ret


    ld a, a
    push bc
    db $dd
    ld d, l
    add e
    adc h
    ld b, b

jr_017_6a71:
    db $e3
    ld a, a
    sub $b3
    cp [hl]
    or d
    ld a, a
    inc l
    ld [c], a
    ld d, l
    or l
    rst $08
    or h
    ld d, [hl]
    ld d, c
    ld d, [hl]
    ld a, a
    sub h
    sub c
    and b
    add $7f

jr_017_6a87:
    or c
    or l
    or e
    call nz, $bc7f
    jp $c5d9


    and $4f
    cp a
    or e
    jr nc, jr_017_6a71

    rst $20

jr_017_6a97:
    ld d, l
    call c, $dfb6
    jp $ded9


    jr nc, jr_017_6a87

    ld d, a
    db $ed
    daa
    ld a, b
    ld d, d
    or c
    ld d, [hl]
    rst $20
    ld e, b
    db $ed
    daa
    rra
    ld d, d
    or e
    jr nc, jr_017_6a97

    ld c, a
    set 0, h
    ret


    ld a, a
    cp d
    cp d
    db $db
    db $dd
    ld a, a
    sub $d1
    ld d, l
    ret


    or e
    ret c

    ld [c], a
    cp b
    db $dd
    ld a, a
    sub d
    and a
    ld b, b
    adc h
    ld a, a
    call nz, $b3b2
    rst $20
    ld d, a
    ld [$32fa], sp
    rst $10
    bit 1, a
    jr nz, jr_017_6ade

    ld hl, $6ae7
    call Call_000_3c79
    jr jr_017_6ae4

jr_017_6ade:
    ld hl, $6b59
    call Call_000_3c79

jr_017_6ae4:
    jp Jump_000_0f6a


    db $ed
    dec hl
    add [hl]
    ld d, b
    rst $20
    ld c, a
    ret nc

    rst $10
    or d
    ret


    ld a, a
    sub b
    xor l
    xor e
    ld b, c
    add h
    xor e
    rst $20
    ld d, c
    sub h
    sub c
    and b
    ret


    ld a, a
    ld d, h
    jp z, $c14f

    ld [c], a
    or e
    ret


    or e
    ret c

    ld [c], a
    cp b
    db $dd
    ld a, a
    jp nz, $dfb6

    jp $b555


    rst $08
    or h
    ret


    ld a, a
    ld d, h
    db $dd
    ld a, a
    rst $08
    inc [hl]
    call c, $2ebd
    rst $20
    ld d, c
    call nz, $c6b8
    ld d, [hl]
    rst $20
    ld a, a
    or [hl]
    cp b
    call nz, $7fb3
    ld d, h
    jp z, $b14f

    or d
    cp h
    ld [c], a
    or e
    ld h, $7f
    call c, $b2d9
    rst $20
    ld d, c
    ld b, b
    xor c
    db $e3
    db $dd
    ld a, a
    jp z, $b7df

    cp l
    reti


    ld a, a
    rst $08
    or h
    add $4f
    add e
    dec bc
    add [hl]
    add $7f
    push bc
    rst $18
    pop bc
    rst $08
    or e
    ld a, a
    or [hl]
    rst $10
    push bc
    rst $20
    ld d, a
    db $ed
    dec hl
    db $10
    ld d, c
    ret


    or e
    ret c

    ld [c], a
    cp b
    ld d, [hl]
    ld a, a
    or [hl]
    rst $20
    ld d, c
    or l
    jp c, $7fc6

    cp a
    sbc $c5
    ld a, a
    db $d3
    ret


    ld h, $7f
    or c
    rst $18
    ret nz

    rst $10
    ld c, a
    adc h
    xor b
    xor h
    sub e
    inc sp
    ld a, a
    or c
    jp $b3ce


    jr nc, @-$4c

    ld a, a
    jr nc, @+$30

    rst $20
    ld d, a
    ld l, $20
    ld de, $0208
    rst $38
    ld de, $0209
    rst $38
    inc bc
    ld bc, $b216
    inc bc
    dec b
    rrca
    or d
    dec b
    ld bc, $b212
    dec b
    dec b
    ld [$09b2], sp
    ld bc, $b21b
    add hl, bc
    dec b
    db $10
    or d
    dec bc
    ld bc, $b205
    dec bc
    dec b
    dec c
    or d
    rrca
    ld bc, $b217
    rrca
    dec b
    ld e, $b2
    ld de, $1101
    or d
    ld de, $0905
    or d
    inc bc
    add hl, bc
    ld a, [de]
    or d
    inc bc
    dec bc
    inc bc
    or d
    dec b
    add hl, bc
    rlca
    or d
    dec b
    dec bc
    inc c
    or d
    dec bc
    dec bc
    inc b
    or d
    rrca
    dec bc
    rra
    or d
    inc bc
    rrca
    jr @-$4c

    inc bc
    inc de
    inc e
    or d
    dec b
    rrca
    ld [bc], a
    or d
    dec b
    inc de
    ld a, [bc]
    or d
    add hl, bc
    rrca
    inc d
    or d
    add hl, bc
    inc de
    dec e
    or d
    dec bc
    rrca
    ld c, $b2
    dec bc
    inc de
    ld b, $b2
    rrca
    rrca
    dec d
    or d
    rrca
    inc de
    add hl, de
    or d
    ld de, $0b0f
    or d
    ld de, $1313
    or d
    nop
    add hl, bc
    dec c
    inc c
    dec c
    rst $38
    ret nc

    ld b, c
    ldh a, [rSB]
    add hl, de
    dec b
    ld c, $ff
    ret nc

    ld b, d
    push af
    ld d, $04
    dec b
    dec d
    rst $38
    ret nc

    ld b, e
    db $db
    ld bc, $0b19
    rlca
    rst $38
    ret nc

    ld b, h
    push af
    rla
    inc b
    dec bc
    dec d
    rst $38
    ret nc

    ld b, l
    db $db
    ld [bc], a
    add hl, de
    ld de, $ff07
    ret nc

    ld b, [hl]
    push af
    jr jr_017_6c42

    ld de, $ff15
    ret nc

jr_017_6c42:
    ld b, a
    db $db
    inc bc
    inc b
    dec b
    rlca
    rst $38
    ret nc

    ld c, b
    db $db
    inc b
    inc h
    inc de
    ld c, $ff
    ret nc

    add hl, bc
    ld a, l
    rst $00
    ld de, $7d08
    rst $00
    ld de, $0909
    rst $00
    inc bc
    ld bc, $c70b
    inc bc
    dec b
    add hl, de
    rst $00
    dec b
    ld bc, $c71b
    dec b
    dec b
    add hl, sp
    rst $00
    add hl, bc
    ld bc, $c73b
    add hl, bc
    dec b
    ld c, c

jr_017_6c74:
    rst $00
    dec bc
    ld bc, $c74b
    dec bc
    dec b
    ld l, c
    rst $00
    rrca
    ld bc, $c76b
    rrca
    dec b
    ld a, c
    rst $00
    ld de, $7b01
    rst $00
    ld de, $0d05
    rst $00
    inc bc
    add hl, bc
    ld c, $c7
    inc bc
    dec bc
    dec e
    rst $00
    dec b
    add hl, bc
    ld e, $c7
    dec b
    dec bc
    ld c, [hl]
    rst $00
    dec bc
    dec bc
    ld l, [hl]
    rst $00
    rrca
    dec bc
    db $10
    rst $00
    inc bc
    rrca
    ld [de], a
    rst $00
    inc bc
    inc de
    jr nz, jr_017_6c74

    dec b
    rrca
    ld [hl+], a
    rst $00
    dec b
    inc de
    ld b, b
    rst $00
    add hl, bc
    rrca
    ld b, d
    rst $00
    add hl, bc
    inc de
    ld d, b
    rst $00
    dec bc
    rrca
    ld d, d
    rst $00
    dec bc
    inc de

Jump_017_6cc3:
    ld [hl], b
    rst $00
    rrca
    rrca
    ld [hl], d
    rst $00
    rrca
    inc de
    add b
    rst $00
    ld de, $820f
    rst $00
    ld de, $4113
    ld b, c
    ld b, c
    ld b, b
    ld b, c
    ld b, c
    ld b, d
    ld b, c
    ld b, c
    ld b, c
    cpl
    ld c, $2f
    ld b, h
    cpl
    cpl
    ld b, [hl]
    cpl
    ld c, $2f
    cpl
    ld c, $2f
    ld b, h
    cpl
    cpl
    ld b, [hl]
    cpl
    ld c, $2f
    ld b, c
    ld b, c
    ld b, c
    ld b, b
    ld b, c
    ld b, c
    ld b, d
    ld b, c
    ld b, c
    ld b, c
    cpl
    ld c, $2f
    ld b, h
    ld c, $0e
    ld b, [hl]
    cpl
    ld c, $2f
    cpl
    ld c, $2f
    ld b, h
    ld c, $2f
    ld b, [hl]
    cpl
    ld c, $2f
    ld b, c
    ld b, c
    ld b, c
    ld b, b
    ld b, c
    ld b, c
    ld b, d
    ld b, c
    ld b, c
    ld b, c
    cpl
    ld c, $2f
    ld b, h
    ld b, l
    cpl
    ld b, [hl]
    cpl
    ld c, $2f
    cpl
    ld c, $2f
    ld b, h
    inc l
    ld c, $46
    cpl
    ld c, $2f
    ld [bc], a
    inc b
    inc b
    nop
    ld b, b
    inc a
    ld l, l
    add hl, sp
    ld l, l
    nop
    sbc l
    ld l, l
    jp Jump_000_3c6c


    ld d, [hl]
    rrca
    ld b, d
    ld l, l
    ld [hl], d
    ld l, l
    db $ed
    dec l
    ld [bc], a
    ld h, [hl]
    inc de
    adc h
    ld b, d
    and a
    db $e3
    jp z, $d64f

    call c, Call_017_7fb2
    ld d, h
    db $dd
    ld a, a
    sub $be
    ld a, a
    jp nz, $c5b9

    or d
    ld d, l
    adc e
    and [hl]
    add hl, de
    db $e3
    adc h
    ld b, d
    and a
    db $e3
    ld a, a
    sub $d8
    ld d, l
    push bc
    ld h, $d3
    pop bc
    ld a, a
    cp l
    reti


    rst $18
    jp $ed57


    dec l
    ld [hl], b
    ld h, [hl]
    ret


    or [hl]
    cp c
    rst $10
    ld a, a
    ret nz

    or [hl]
    or d
    ld a, a
    cp c
    inc [hl]
    ld c, a
    cp [hl]
    sbc $c4
    or e
    call z, $b3c9
    ret


    ld a, a
    ld d, h
    ld h, $55
    add hl, hl
    sbc $b7
    add $7f
    push bc
    reti


    ret


    ld a, a
    cp l
    ld a, [hl+]
    or d
    call c, $57e7
    nop
    ld [bc], a
    rlca
    inc bc
    inc b
    rst $38
    rlca
    inc b
    inc b
    rst $38
    nop
    inc bc
    ld h, $09
    inc b
    rst $38
    db $d3
    ld bc, $060c
    ld [$ffff], sp
    ld [bc], a
    ld b, $09

jr_017_6db7:
    ld a, [bc]
    cp $00
    inc bc
    ld [de], a
    rst $00
    rlca
    inc bc
    inc de
    rst $00
    rlca
    inc b
    ld d, $09
    rrca
    ld c, h
    ld l, [hl]
    ld [$cf6d], a
    ld l, l
    nop
    ld a, [de]
    ld l, [hl]
    call Call_000_3c6c
    ld a, [$d7b7]
    bit 7, a
    ret z

    ld hl, $d738
    bit 7, [hl]
    set 7, [hl]
    ret nz

    ld a, $4c
    ld [$cc4d], a
    ld a, $15
    jp Jump_000_3e9d


    db $ec
    ld l, l
    db $ed
    daa
    reti


    ld d, e
    cp h
    ldh [$b2], a
    rst $08
    cp [hl]
    rst $20
    ld d, c
    cp h
    ldh [$c1], a
    ld [c], a
    or e
    ld a, a
    inc sp
    cp h
    ret nz

    rst $10
    ld a, a
    ret nz

    jr nc, jr_017_6db7

    rst $08
    ld c, a
    rst $30
    rst $30
    or [hl]
    or d
    ld a, a
    call nc, $b2b8
    sbc $bc
    jp nz, Jump_017_7f33

    ld a, [hl+]
    dec hl
    or d
    rst $08
    cp l
    ld d, a
    ld l, $05
    ld de, $050a
    rst $38
    ld de, $050b
    rst $38
    nop
    ld a, [de]
    nop
    rst $08
    nop
    inc d
    nop
    db $ec
    ld a, [bc]
    db $10
    ld b, $d0
    nop
    ld bc, $062a
    ld [$d0ff], sp
    ld bc, $c7ab
    ld de, $ab0a
    rst $00
    ld de, $0b0b
    rst $00
    nop
    ld a, [de]
    ld [$00c7], sp
    inc d
    ld l, a
    rst $00
    ld a, [bc]
    db $10
    inc a
    dec a
    dec a
    ld a, a
    dec a
    dec a
    dec a
    dec a
    dec a
    dec a
    ld a, h
    dec a
    dec a
    ld a, l
    ld a, $7e
    ld [hl+], a
    ld [hl+], a
    inc hl
    ld c, $0e
    dec e
    ld c, $0e
    dec e
    ld c, $0e
    ld c, $09
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld c, $0e
    ld e, $5b
    inc e
    ld e, $5b
    inc e
    ld c, $0e
    ld c, $46
    ld b, h
    dec c
    ld c, $0e
    jr nz, jr_017_6eda

    ld e, e
    ld e, e
    ld e, e
    ld e, e
    ld e, e
    add hl, sp
    ld c, $09
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld c, $0e
    ld a, [de]
    ld e, e
    jr jr_017_6eab

    ld e, e
    jr @+$10

    ld c, $0e
    ld b, [hl]
    ld b, h
    dec c
    ld c, $0e
    ld c, $0e
    add hl, de
    ld c, $0e
    add hl, de
    ld c, $0e
    ld c, $09
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld c, $0e

jr_017_6eab:
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $46
    ld b, h
    dec bc
    dec bc
    dec bc
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld c, $0b
    dec bc
    dec bc
    ld b, [hl]
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld e, b
    inc l
    ld d, a
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld b, $04
    rlca
    ld h, h
    ld b, b
    push hl
    ld l, [hl]

jr_017_6eda:
    rst $18
    ld l, [hl]
    nop
    ld c, h
    ld l, a
    call Call_000_0d8e
    jp Jump_000_3c6c


    db $ed
    ld l, [hl]
    xor $6e
    ld [de], a
    ld l, a
    ld c, e
    ld l, a
    rst $38
    db $ed
    daa
    ld c, h
    ld d, h
    cp h
    pop hl
    reti


    or d
    add $7f
    sub $df
    jp $be4f


    or d
    pop bc
    ld [c], a
    or e
    cp l
    reti


    ld a, a
    sub d
    xor e
    ld b, e
    ld h, $55
    pop bc
    ld h, $b3
    ld a, a
    rst $10
    cp h
    or d
    call c, $ed57
    daa
    adc a
    ld d, h
    ld h, $7f
    ret nc

    sbc $c5
    ld a, a
    cp h
    rst $18
    jp Jump_017_4fd9


    adc e
    and [hl]
    sbc e
    ld a, a
    add l
    xor e
    ld b, b
    sub l
    db $e3
    ld a, a
    jr nc, jr_017_6f53

    ld d, l
    push de
    or e
    jp nc, Jump_017_7fb2

    jr nc, @-$3a

    ld a, a
    cp a
    jp c, $b930

    ld d, l
    ret z

    rst $10
    call c, $d9da
    ld a, a
    or a
    cp c
    sbc $d3
    ld a, a
    or c
    reti


    ret


    jr nc, jr_017_6fa2

    or $00
    ld [bc], a
    rlca
    inc bc
    ld b, $ff
    rlca

jr_017_6f53:
    inc b
    ld b, $ff
    nop
    inc b
    add hl, hl
    dec b
    rlca
    rst $38
    ret nc

    ld bc, $090f
    add hl, bc
    rst $38
    rst $38
    ld [bc], a
    db $10
    rlca
    inc c
    rst $38
    ret nc

    inc bc
    ld a, [hl+]
    ld b, $0f
    rst $38
    ret nc

    inc b
    ld e, $c7
    rlca
    inc bc
    rra
    rst $00
    rlca
    inc b
    add hl, bc
    inc b
    dec b
    sub b
    ld b, b
    add a
    ld l, a
    add h
    ld l, a
    nop
    db $f4
    ld l, a
    jp Jump_000_3c6c


    adc e
    ld l, a
    pop bc
    ld l, a
    db $ed
    inc h
    jp c, Jump_017_7f70

    inc [hl]
    or e
    cp b
    jp nz, $bc7f

    or [hl]
    ld c, a
    or d
    push bc
    or d
    ld a, a
    ld d, h
    db $d3
    ld a, a
    or l
    or l
    or d

jr_017_6fa2:
    sub $51
    or d
    db $db
    sbc $c5
    ld a, a
    ld d, h
    ld a, a
    call nz, $c5d9
    rst $10
    ld c, a
    cp h
    jp nz, $b8ba

    ld a, a
    cp e
    ld h, $bc
    rst $08
    call c, Call_017_7fd9
    cp d
    call nz, $c830
    ld d, a
    db $ed
    inc h
    ld d, e
    ld [hl], c
    ret


    ld a, a
    or c
    pop bc
    cp d
    pop bc
    add $4f
    adc $bf
    or d
    ld a, a
    or a
    ld h, $7f
    or c
    rst $18
    ret nz

    db $db
    and $51
    or c
    cp a
    cp d
    jp z, Jump_017_547f

    ret


    ld a, a
    call c, $332b
    ld c, a
    or a
    rst $18
    jp $c47f


    or l
    jp c, Jump_017_7fd9

    cp a
    or e
    inc l
    ldh [$57], a
    ld a, [bc]
    inc b
    nop
    inc b
    ld bc, $00ff
    dec b
    ld bc, $07ff
    inc b
    nop
    inc sp
    rlca
    dec b
    nop
    inc sp
    nop
    ld [bc], a
    inc c
    ld b, $07
    rst $38
    rst $38
    ld bc, $0925
    ld b, $ff
    rst $38
    ld [bc], a
    or $c6
    nop
    inc b
    or $c6
    nop
    dec b
    rla
    rst $00
    rlca
    inc b
    rla
    rst $00
    rlca
    dec b
    inc c
    inc b
    dec b
    sub b
    ld b, b
    inc sp
    ld [hl], b
    jr nc, jr_017_709d

    nop
    cp l
    ld [hl], b
    jp Jump_000_3c6c


    scf
    ld [hl], b
    sbc h
    ld [hl], b
    ld [$41fa], sp
    rst $10
    bit 0, a
    jr nz, jr_017_7069

    ld a, $0a
    ldh [$db], a
    ld a, $c8
    ldh [$dc], a
    ld [$d0e3], a
    call Call_000_1add
    ld hl, $cd68
    ld de, $cc5b
    ld bc, $0010
    call Call_000_01bb
    ld a, $62
    call Call_000_3e9d
    ldh a, [$db]
    cp $01
    jr nz, jr_017_706f

    ld hl, $d741
    set 0, [hl]

jr_017_7069:
    ld hl, $7072
    call Call_000_3c79

jr_017_706f:
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld h, l
    ld d, c
    ret


    ld a, a
    sbc e
    and l
    xor h
    adc e
    xor [hl]
    inc sp
    ld c, a
    inc [hl]
    sbc $c5
    add $7f
    cp b
    rst $10
    or d
    ld a, [hl-]
    cp h
    ld [c], a
    inc sp
    db $d3
    ld d, l
    add hl, de
    xor h
    sub b
    ret c

    ld a, a
    or c
    or [hl]
    reti


    cp b
    ld a, a
    push bc
    ret c

    rst $08
    cp l
    ld d, a
    db $ed

jr_017_709d:
    inc h
    ld b, [hl]
    ld [hl], d
    sbc e
    and l
    xor h
    adc e
    xor [hl]
    db $dd
    ld a, a
    or l
    ld a, $b4
    ret nz

    rst $10
    ld d, l
    add c
    xor c
    and d
    sbc l
    sub e
    xor e
    sub a
    and [hl]
    ld h, $7f
    call nz, $dab5
    reti


    ret z

    ld d, a
    ld a, [bc]
    inc b
    nop
    inc b
    inc bc
    rst $38
    nop
    dec b
    inc bc
    rst $38
    rlca
    inc b
    inc b
    rst $38
    rlca
    dec b
    inc b
    rst $38
    nop
    ld [bc], a
    jr nz, jr_017_70db

    dec b
    rst $38
    jp nc, Jump_000_0401

    ld [$fe09], sp

jr_017_70db:
    ld [bc], a
    ld [bc], a
    or $c6
    nop
    inc b
    or $c6
    nop
    dec b
    rla
    rst $00
    rlca
    inc b
    rla
    rst $00
    rlca
    dec b
    add hl, bc
    inc b
    dec b
    sub b
    ld b, b
    db $fc
    ld [hl], b
    ld sp, hl
    ld [hl], b
    nop
    ld e, l
    ld [hl], c
    jp Jump_000_3c6c


    nop
    ld [hl], c
    dec l
    ld [hl], c
    db $ed
    inc h
    and l
    ld [hl], d
    ret


    ld a, a
    db $d3
    ret c

    call $b27f
    cp b
    ret


    and $4f
    db $d3
    ret c

    jp z, $c37f

    sbc $c8
    sbc $c9
    ld a, a
    jp nc, $dbb2

    sub $55
    rst $08
    sub $dc
    push bc
    or d
    sub $b3
    ld a, a
    or a
    db $dd
    ld a, a
    jp nz, $c3b9

    ld d, a
    db $ed
    inc h
    rst $38
    ld [hl], d
    adc a
    jp z, $c17f

    rst $18
    pop bc
    ldh [$b2], a
    ld a, a
    cp c
    inc [hl]
    ld c, a
    rst $08
    or h
    ld a, [hl-]
    ret


    ld a, a
    or d
    pop bc
    add hl, hl
    or a
    jp z, $b17f

    push bc
    inc [hl]
    jp c, $b2c5

    ld d, l
    db $d3
    or e
    ld a, a
    jp nz, $cfb6

    or h
    ret nz

    ld a, a
    or [hl]
    cp h
    rst $10
    and $57
    ld a, [bc]
    inc b
    nop
    inc b
    inc bc
    inc sp
    nop
    dec b
    inc b
    inc sp
    rlca
    inc b
    dec b
    rst $38
    rlca
    dec b
    dec b
    rst $38
    nop
    ld [bc], a
    dec c
    ld [$ff0c], sp
    jp nc, $0801

    ld [$fe06], sp
    ld bc, $f602
    add $00
    inc b
    or $c6
    nop
    dec b
    rla
    rst $00
    rlca
    inc b
    rla
    rst $00
    rlca
    dec b
    inc c
    inc b
    inc b
    add b
    ld b, b
    and b
    ld [hl], c
    sbc c
    ld [hl], c
    nop
    or c
    ld [hl], c
    ld a, $10
    ld [$d2e4], a
    ret


    ld d, b
    and d
    ld [hl], c
    ld [$093e], sp
    ld [$cd3d], a
    ld a, $54
    call Call_000_3e9d
    ld hl, $719f
    ret


    ld a, [bc]
    inc bc
    rlca
    inc bc
    inc bc
    rst $38
    rlca
    inc b
    inc bc
    rst $38
    inc b
    inc b
    nop
    ld [hl], a
    nop
    ld bc, $0708
    ld b, $ff
    rst $38
    ld bc, $c712
    rlca
    inc bc
    inc de

jr_017_71cc:
    rst $00
    rlca
    inc b
    add hl, bc
    rst $00
    inc b
    inc b
    inc c
    inc b
    inc b
    add b
    ld b, b
    rst $20
    ld [hl], c
    rst $18
    ld [hl], c
    nop
    ld [$3e72], sp
    ld de, $e4ea
    jp nc, Jump_017_6cc3

    inc a
    jp hl


    ld [hl], c
    db $ed
    dec h
    ld [c], a
    ld d, e
    or e
    db $db
    jp z, $b37f

    cp l
    jr z, jr_017_71cc

    or d
    or [hl]
    rst $10
    ld c, a
    or l
    call nz, $d3bc
    ret


    ld a, a
    or l
    or l
    or d
    sbc $33
    cp l
    rst $18
    jp $0a57


    inc bc
    rlca
    inc bc
    inc bc
    rst $38
    rlca
    inc b
    inc bc
    rst $38
    inc b
    inc b
    ld bc, $0077
    ld bc, $070d
    ld b, $ff
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
    inc c
    inc b
    inc b
    add b
    ld b, b
    ld a, $72
    ld [hl], $72
    nop
    ld l, e
    ld [hl], d
    ld a, $12
    ld [$d2e4], a
    jp Jump_000_3c6c


    ld b, b
    ld [hl], d

jr_017_7240:
    db $ed
    dec h
    inc [hl]

Jump_017_7243:
    ld d, h
    call nz, $dbba
    ld c, a
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
    adc $b3
    ld a, a
    inc sp
    db $d3
    ld d, l
    or d
    ret z

    pop de
    ret c

    ld a, a
    ld d, h
    ld h, $55
    or c
    rst $10
    call c, $d9da
    ld a, a
    cp a
    or e
    jr nc, jr_017_7240

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
    nop
    ld a, c
    nop
    ld bc, $080a
    ld b, $ff
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
    inc c
    inc b
    inc b
    add b
    ld b, b
    sbc a
    ld [hl], d
    sbc c
    ld [hl], d
    nop
    and b
    ld [hl], e
    ld a, $12
    ld [$d2e4], a
    ret


    and e
    ld [hl], d
    rlca
    ld [hl], e
    db $ed
    dec h
    ld a, d
    ld d, h
    pop de
    cp h
    ld [hl], c
    adc e
    sub d
    or b
    ret


    ld a, a
    ld [de], a
    ld b, b
    db $e3
    sub e
    call $b64e
    or d
    db $d3
    ret


    add $7f
    or d
    or a
    ret nz

    or d
    sbc $30
    cp c
    inc [hl]
    ld d, [hl]
    ld d, c
    or c
    ret


    rst $08
    pop bc
    add $ca
    ld a, a
    dec b
    and l
    ret


    call c, $b2d9
    ld a, a
    set 0, h
    ld h, $4f
    or l
    or l
    cp b
    jp $c57f


    sbc $30
    or [hl]
    ld a, a
    cp d
    call c, $c9b2
    sub $c8
    ld d, a
    nop
    ld [hl], b
    ret nz

    rst $08
    pop de
    cp h
    ld [hl], c
    adc e
    sub d
    or b
    add $4e
    ld [hl], b
    ld e, [hl]
    ld [hl], c
    ret


    add b
    dec bc
    sub e
    ld h, $55
    or c
    rst $18
    ret nz

    sbc $33
    cp l
    rst $18
    jp $57e6


    db $ed
    dec h
    ld sp, hl
    ld d, h
    db $d3
    ld a, a
    ld [hl], b
    ret nz

    rst $08
    pop de
    cp h

jr_017_7312:
    ld [hl], c
    adc e
    sub d
    or b
    add $4e
    or [hl]
    or d
    db $d3
    ret


    add $7f
    or a
    ret nz

jr_017_7320:
    sbc $30
    push bc
    ld d, c
    inc de
    add b
    or [hl]
    rst $10
    ld a, a
    inc sp
    jp $bd4f


    jr z, jr_017_73ae

    add $bc
    ld h, $dc
    ret


    rst $08
    pop bc
    ld h, $7f
    cp a
    or e
    jr nc, jr_017_7312

    ld d, a
    nop
    or [hl]
    or d
    jr nc, jr_017_7320

    ret


    ld a, a
    cp h
    ret nz

    add $b1
    reti


    ld a, a
    jp nz, $dbb3

    jp z, $704e

    call nc, $3ccf
    or a
    ld [hl], c
    ret


    ld a, a
    cp h
    ret nz

    db $dd
    ld a, a
    call nz, $dfb5
    jp $7055


    cp h
    or l
    sbc $71
    call $c27f
    push bc
    ld h, $df
    jp $d9b2


    sbc $30
    ld d, c
    ld [hl], b
    jp z, $30c5

    ld [hl], c
    call $b27f
    or a
    ret nz

    or d
    sbc $c5
    rst $10
    ld d, c
    ret nc

    pop bc
    db $dd
    ld a, a
    jp z, $debb

    inc sp
    ld a, a
    pop de
    or [hl]
    or d
    ld h, $dc
    add $4f
    ret nz

    rst $18
    jp Jump_017_7fd9


    ret nz

    jp $c9d3


    add $7f
    or d
    or a
    push bc
    sub $57
    ld a, [bc]
    inc bc
    rlca
    inc bc
    dec b
    rst $38
    rlca
    inc b
    dec b
    rst $38
    inc b
    inc b
    nop
    ld a, c

jr_017_73ae:
    nop
    ld [bc], a
    dec c
    ld b, $07
    rst $38
    rst $38
    ld bc, $080a
    ld b, $ff
    rst $38
    ld [bc], a
    ld [de], a
    rst $00
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
    ld d, $09
    dec c
    add e
    db $76
    and h
    ld [hl], h
    call nc, Call_000_0073
    add hl, sp
    db $76
    call Call_017_73ea
    call Call_000_3c6c
    ld hl, $74ac
    ld de, $749e
    ld a, [$d5c9]
    call Call_000_31a8
    ld [$d5c9], a
    ret


Call_017_73ea:
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    ret z

    ld hl, $7447
    call Call_017_7450
    call Call_017_747c
    ld a, [$d7b3]
    bit 0, a
    jr nz, jr_017_7411

    push af
    ld a, $5f
    ld [$d07c], a
    ld bc, $0401
    ld a, $17
    call Call_000_3e9d
    pop af

jr_017_7411:
    bit 1, a
    jr nz, jr_017_7424

    push af
    ld a, $54
    ld [$d07c], a
    ld bc, $0209
    ld a, $17
    call Call_000_3e9d
    pop af

jr_017_7424:
    bit 2, a
    jr nz, jr_017_7437

    push af
    ld a, $54
    ld [$d07c], a
    ld bc, $0509
    ld a, $17
    call Call_000_3e9d
    pop af

jr_017_7437:
    bit 3, a
    ret nz

    ld a, $5f
    ld [$d07c], a
    ld bc, $0605
    ld a, $17
    jp Jump_000_3e9d


    inc b
    ld bc, $0902
    dec b
    add hl, bc
    ld b, $05
    rst $38

Call_017_7450:
    push hl
    ld hl, $d6be
    ld a, [hl+]
    ld b, a
    ld a, [hl]
    ld c, a
    xor a
    ldh [$e0], a
    pop hl

jr_017_745c:
    ld a, [hl+]
    cp $ff
    jr z, jr_017_7478

    push hl
    ld hl, $ffe0
    inc [hl]
    pop hl
    cp b
    jr z, jr_017_746d

    inc hl
    jr jr_017_745c

jr_017_746d:
    ld a, [hl+]
    cp c
    jr nz, jr_017_745c

    ld hl, $d6be
    xor a
    ld [hl+], a
    ld [hl], a
    ret


jr_017_7478:
    xor a
    ldh [$e0], a
    ret


Call_017_747c:
    ld hl, $d7b3
    ldh a, [$e0]
    and a
    ret z

    cp $01
    jr nz, jr_017_748a

    set 0, [hl]
    ret


jr_017_748a:
    cp $02
    jr nz, jr_017_7491

    set 1, [hl]
    ret


jr_017_7491:
    cp $03
    jr nz, jr_017_7498

    set 2, [hl]
    ret


jr_017_7498:
    cp $04
    ret nz

    set 3, [hl]
    ret


    ld h, c
    ld [hl-], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    pop de
    ld [hl], h
    ld [hl-], a
    ld [hl], l
    ld a, l
    ld [hl], l
    db $ec
    ld [hl], l
    ld [bc], a
    ld b, b
    or d
    rst $10
    inc a
    ld [hl], l
    ld h, c
    ld [hl], l
    ld e, d
    ld [hl], l
    ld e, d
    ld [hl], l
    inc bc
    jr nz, jr_017_746d

    rst $10
    add a
    ld [hl], l
    push bc
    ld [hl], l
    or b
    ld [hl], l
    or b
    ld [hl], l
    inc b
    ld b, b
    or d
    rst $10
    or $75
    jr nz, jr_017_7542

    db $10
    db $76
    db $10
    db $76
    rst $38
    ld [$b7fa], sp
    rst $10
    bit 7, a
    jr nz, jr_017_74f5

    ld hl, $74fe
    call Call_000_3c79
    ld a, $07
    call Call_000_3e9d
    call Call_000_0b5a
    call Call_000_3e07
    call Call_000_0b78
    ld hl, $751d
    call Call_000_3c79
    jr jr_017_74fb

jr_017_74f5:
    ld hl, $7525
    call Call_000_3c79

jr_017_74fb:
    jp Jump_000_0f6a


    db $ed
    dec hl
    push hl
    ld d, c
    jp Jump_017_7fd9


    ret nc

    ret nz

    or d
    sub $e7
    ld c, a

jr_017_750b:
    or [hl]
    ret nc

    sbc $bc
    jp nz, Jump_017_7f33

    call nc, $debd
    inc sp
    ld a, a
    or d
    rst $18
    ret nz

    rst $10
    and $58
    db $ed
    dec hl
    dec de
    ld d, d
    rst $18
    jp $57e7


    db $ed
    dec hl
    daa
    ld d, d
    rst $18
    ret nz

    call c, $b17f
    ret c

    ld h, $c4
    ld d, a
    ld [$ac21], sp
    ld [hl], h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, jr_017_75a3

    ld c, b
    ret


    ld a, a

jr_017_7542:
    cp b
    cp [hl]
    add $7f
    or l
    rst $08
    or h
    ret


    ld c, a
    ld d, h
    ld a, a
    dec l
    or d
    inc a
    sbc $7f
    push bc
    jp nz, $c3b2

    or d
    reti


    push bc
    ld d, a
    db $ed
    jr z, @-$0a

    ld c, b
    xor h
    rst $20
    ld e, b
    db $ed
    jr z, jr_017_750b

    ld c, b
    ld a, a
    cp b
    rst $10
    or d
    ret


    ld a, a
    call nz, $b6bc
    rst $10
    ld c, a
    ld d, h
    ld a, a
    call nc, $c3df
    jp c, Jump_017_7f3a

    or l
    jp c, Jump_017_56d3

    ld d, a
    ld [$b821], sp
    ld [hl], h
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    jr z, @-$02

    ld c, b
    ld a, a
    ld d, h
    ld a, a
    add $ca

jr_017_7590:
    ld c, a
    ld d, [hl]
    ld a, a
    inc l
    ldh [$b8], a
    jp $26de


    ld a, a
    or c
    reti


    rst $20
    ld d, l
    cp a
    cp d
    db $dd
    ld a, a
    cp [hl]

jr_017_75a3:
    jp nc, Jump_000_3ada

    ld a, a
    or l
    jp c, $b67f

    jp $d6d9


    rst $20
    ld d, a
    db $ed
    jr z, jr_017_7590

    ld c, c
    jp $ddde


    ld d, [hl]
    ld c, a
    jp nz, $cfb8

    or h
    add $7f
    call nc, $dad7
    ret nz

    or c
    ld e, b
    db $ed
    jr z, @+$37

    ld c, c
    jp $ddde


    ld c, a
    cp [hl]
    jp nc, $c4d9

    ld a, a
    or d
    or d
    ret


    jp z, Jump_000_2c7f

    inc l
    jp nz, $e730

    ld d, l
    adc a
    add c
    ld b, d
    ret


    ld a, a
    or c
    or d
    cp h
    ld [c], a
    or e
    ld a, a
    call nz, Call_017_56b6
    ld d, a
    ld [$c421], sp
    ld [hl], h
    call Call_000_3214
    jp Jump_000_0f6a


jr_017_75f6:
    db $ed
    jr z, jr_017_7605

    ld c, d
    cp a
    jp z, $a84f

    adc b
    xor h
    sub e
    ld a, a
    ld a, [$e2b7]

jr_017_7605:
    or e
    jr nc, @-$4c

    ret


    ld a, a
    set 0, h
    ret c

    jr nc, jr_017_75f6

    ld d, a
    db $ed
    jr z, @-$65

    ld c, d
    ld c, a
    rst $08
    cp c
    ret nz

    ld a, a
    or l
    call nz, $c4b3
    sub $e7
    ld e, b
    db $ed
    jr z, jr_017_7665

    ld c, d
    or d
    or d
    ld c, a
    or l
    call nz, $c4b3
    ld h, $7f
    or [hl]
    ret nz

    or a
    db $dd
    ld a, a
    call nz, $c3df
    cp b
    jp c, $57d9

    ld l, $05
    nop
    ld c, $00
    ld [$1000], a
    nop
    push de
    nop
    ld [de], a
    nop
    db $ec
    inc bc
    add hl, bc
    rlca
    ret nc

    rrca
    ld de, $d204
    nop
    inc b
    add hl, hl
    ld [de], a
    rlca
    rst $38
    ret nc

    ld bc, $0818
    ld b, $ff
    pop de
    ld b, d
    and $25
    jr nz, jr_017_7672

    add hl, de
    rst $38
    ret nc

    ld b, e

jr_017_7665:
    db $e4
    ld a, [bc]
    jr jr_017_767d

    ld de, $d1ff
    ld b, h
    and $26
    inc bc
    rst $00
    nop

jr_017_7672:
    ld c, $04
    rst $00
    nop
    db $10
    dec b
    rst $00
    nop
    ld [de], a
    inc de
    rst $00

jr_017_767d:
    inc bc
    add hl, bc
    adc c
    rst $00
    rrca
    ld de, $4140
    ld b, c
    ld b, c
    ld b, c
    ld b, d
    ld b, c
    ld a, l
    inc h
    ld a, h
    dec a
    dec a
    ld a, $44
    ld c, $0e
    ld c, $2f
    ld b, [hl]
    ld c, $0e
    ld c, $0e
    ld c, $0e
    ld b, [hl]
    ld b, h
    ld e, d
    ld h, a
    ld b, c
    ld b, c
    ld b, d
    ld c, $40
    ld h, e
    ld c, $67
    ld e, c
    ld b, [hl]
    ld b, h
    ld d, [hl]
    ld c, $47
    ld b, a
    ld b, [hl]
    ld c, $44
    ld c, $34
    ld c, $12
    ld b, [hl]
    ld b, h
    ld c, $0e
    ld h, a
    ld b, b
    ld b, d
    dec c
    ld b, h
    ld c, $37
    ld c, $12
    ld b, [hl]
    ld b, h
    ld e, d
    ld c, $0e
    ld d, l
    ld d, [hl]
    dec c
    ld b, b
    ld h, e
    ld c, $67
    ld b, d
    ld b, [hl]
    ld d, b
    ld c, d
    ld b, e
    ld b, e
    ld c, $0e
    ld c, $44
    ld b, a
    ld a, e
    ld c, $56
    ld b, [hl]
    ld b, h
    ld b, e
    ld b, e
    ld b, e
    ld e, c
    ld e, d
    ld c, $44
    cpl
    ld b, a
    ld c, $0e
    ld b, [hl]
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, b
    ld c, d
    ld c, c
    ld c, b
    ld c, c
    ld c, c
    ld c, c
    ld c, c
    ld c, d
    ld de, $0a09
    ld h, d
    ld a, b
    ld e, c
    ld [hl], a
    inc b
    ld [hl], a
    nop
    ld d, $78
    ld hl, $d0eb
    bit 5, [hl]
    res 5, [hl]
    call nz, Call_017_7721
    call Call_000_3c6c
    ld hl, $7767
    ld de, $7734
    ld a, [$d5d0]
    call Call_000_31a8
    ld [$d5d0], a
    ret


Call_017_7721:
    ld a, [$d7e8]
    bit 7, a
    ret z

    ld a, $1d
    ld [$d07c], a
    ld bc, $0604
    ld a, $17
    jp Jump_000_3e9d


    ld a, [hl-]
    ld [hl], a
    sub h
    ld [hl-], a
    cp l
    ld [hl-], a
    ld a, [$d7e8]
    bit 7, a
    jp nz, Jump_000_3261

    ld hl, $7756
    call Call_000_352e
    jp nc, Jump_000_3261

    ld hl, $d0eb
    set 5, [hl]
    ld hl, $d7e8
    set 7, [hl]
    ret


    dec c
    ld de, $80ff
    ld [hl], a
    jp z, $c577

jr_017_775e:
    rrca
    push bc
    rrca
    add e
    rrca
    add e
    rrca
    add e
    rrca
    ld bc, $e820
    rst $10
    adc d
    ld [hl], a
    or c
    ld [hl], a
    xor d
    ld [hl], a
    xor d
    ld [hl], a
    ld [bc], a
    jr nz, jr_017_775e

    rst $10

jr_017_7777:
    call nc, $fe77
    ld [hl], a
    ld a, [c]
    ld [hl], a
    ld a, [c]
    ld [hl], a
    rst $38
    ld [$6721], sp
    ld [hl], a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $67
    ld b, b
    or c
    ret nz

    cp h
    ld a, a
    inc l
    cp h
    sbc $7f
    or c
    reti


    call c, Call_017_4fd6
    or c
    push bc
    ret nz

    ret


    ld a, a
    jp $7fc6


    or l
    or h
    reti


    or [hl]
    push bc

jr_017_77a8:
    and $57
    db $ed
    ld h, $fc
    ld b, b
    call c, Call_017_5856
    db $ed
    ld h, $b9
    ld b, b
    add $7f
    rst $08
    cp c
    reti


    ret


    ld a, a
    jr nc, jr_017_7777

    jp z, $b24f

    call nc, $307f
    rst $18
    ret nz

    ret


    add $e7
    ld d, a
    ld [$7321], sp
    ld [hl], a
    call Call_000_3214
    jp Jump_000_0f6a


    db $ed
    ld h, $06
    ld b, c
    or [hl]
    ld a, a
    call nc, $c3d8
    ret


    ld a, a
    sub $b3
    jr nc, jr_017_77a8

    ld c, a
    or l
    jp $b17f


    call c, Call_017_7fbe
    ret z

    ld h, $b5
    or e
    or [hl]
    rst $20
    ld d, a
    db $ed
    ld h, $7e
    ld b, c
    ld a, a
    or c
    rst $18
    ret nz

    sbc $30
    ld h, $58
    db $ed
    ld h, $3b
    ld b, c
    ld a, a
    or e
    or h
    add $ca
    ld c, a
    or e
    or h
    ld h, $7f
    or d
    ret nz

    rst $18
    jp $ba7f


    call nz, Call_017_56b6
    ld d, a
    ld a, l
    inc bc
    ld de, $0208
    rst $38
    ld de, $0209
    rst $38
    ld bc, $0001
    jp nz, $0700

    ld b, $09
    dec bc
    rst $38
    db $d3
    ld b, c
    add sp, $05
    rlca
    ld b, $07
    rst $38
    ret nc

    ld b, d
    rst $20
    dec b
    dec a
    inc b
    rrca
    rst $38
    rst $38
    add e
    di
    dec a
    ld b, $0d
    rst $38
    rst $38
    add h
    jr z, jr_017_7884

    inc de
    add hl, bc
    rst $38
    db $10
    dec b
    ccf
    ld b, $12
    rst $38
    db $10
    ld b, $3f
    ld c, $06
    rst $38
    db $10
    rlca
    ld a, l
    rst $00
    ld de, $7d08
    rst $00
    ld de, $f909
    add $01
    ld bc, $0562
    ld a, l
    ld a, l
    ld c, [hl]
    ld l, l
    ld [hl], h
    inc c
    add hl, bc
    ld a, l
    ld c, l
    ld bc, $7d7a
    ld a, [bc]
    inc c
    dec c
    ld bc, $7a01
    ld b, $01
    inc d
    dec d
    dec d
    dec d
    dec d
    dec d
    ld d, $01
    ld a, l
    ld bc, $2d1c

jr_017_7884:
    dec e
    dec hl
    inc l
    dec l
    ld e, $01
    ld a, l
    ld c, $6a
    ld e, e
    ld l, a
    jr @+$1c

    ld c, h
    ld bc, $4d0d
    rrca
    jr jr_017_78b1

    ld [hl], b
    jr jr_017_78b5

    ld c, a
    dec b
    ld [hl], d
    ld c, $0d
    ld h, [hl]
    dec e
    dec h
    dec e
    ld e, $0d
    ld l, h
    ld [hl], h
    inc c
    dec b
    ld bc, $0108
    ld e, [hl]
    ld bc, $0701

jr_017_78b1:
    ld a, l
    ld d, e
    inc b
    inc b

jr_017_78b5:
    ld bc, $7d24
    inc b
    ld d, c
    ld a, l
    ld a, l
    call Call_000_3ec4
    ld bc, $0005
    add hl, bc
    ld a, [$d0e3]
    ld [$d092], a
    push hl
    call Call_000_2f2e
    pop hl
    ld a, [$d09b]
    ld [hl+], a
    ld a, [$d09c]
    ld [hl], a
    ret


    call Call_000_3c6c
    ld a, $04
    jp Jump_000_3f25


    db $ed
    inc l
    or b
    ld a, e
    sbc e
    jp hl


    sbc [hl]
    adc c
    xor e
    db $dd
    ld a, a
    cp h
    jp $e7d9


    ld d, l
    ld d, [hl]
    ld a, a
    ld d, [hl]
    ld a, a
    sub $bc
    rst $20
    ld d, l
    cp a
    db $db
    cp a
    db $db
    ld a, a
    inc sp
    or [hl]
    cp c
    sub $b3
    rst $20
    ld d, a
    call Call_000_3c6c
    ld a, $03
    jp Jump_000_3f25


    db $fc
    ld a, [$c109]
    cp $04
    ret nz

    call Call_000_3c6c
    ld a, $0a
    call Call_000_3f25
    ld a, $4a
    ld [$cf78], a
    call Call_000_2dc7
    jp Jump_017_79a9


    db $ed

jr_017_7926:
    dec l
    ld b, a
    ld c, a
    sbc $b7
    ld [c], a
    or e
    db $dd
    ld a, a
    ret


    cpl
    or d
    ret nz

    ld d, [hl]
    ld d, c
    or l
    or l
    or a
    push bc
    ld a, a
    call nz, Call_000_26d8
    ld c, a
    add [hl]
    and l
    add [hl]
    and l
    ld a, a
    res 6, [hl]
    ret c

    push bc
    ld h, $d7
    ld d, l
    or e
    ret nc

    ret


jr_017_794d:
    ld a, a
    adc $b3
    call $c47f
    sbc $33
    or d
    cp b
    ld d, [hl]
    ld d, a
    ld a, $b7
    ld [$cf78], a
    call Call_017_79a9
    call Call_000_3c6c
    ld a, $09
    call Call_000_3f25
    ret


    db $ed
    dec l
    nop
    ld b, b
    cp h
    or d
    ld a, a
    cp d
    jr nc, jr_017_7926

    ld a, a
    ld d, h
    ld c, a
    ld b, d
    sub d
    and l
    ret


    ld a, a
    add l
    adc l
    add [hl]
    ld d, a
    ld a, $b6
    ld [$cf78], a
    call Call_017_79a9
    call Call_000_3c6c
    ld a, $0b
    call Call_000_3f25
    ret


    db $ed
    inc l
    ld a, [$bc7b]
    or d
    ld a, a
    cp d
    jr nc, jr_017_794d

    ld a, a
    ld d, h
    ld c, a
    add l
    dec de
    sub e
    ld b, d
    adc h
    ret


    ld a, a
    add l
    adc l
    add [hl]
    ld d, a

Call_017_79a9:
Jump_017_79a9:
    ld a, $01
    ldh [$ba], a
    call Call_000_3e07
    xor a
    ldh [$b0], a
    call Call_000_3761
    ld a, $11
    ld [$d0ea], a
    call Call_000_3130
    call Call_000_0ebd
    ld a, [$cf78]
    ld [$d092], a
    call Call_000_2f2e
    ld de, $8b10
    call Call_000_3034
    ld a, $80
    ldh [$e1], a
    ld hl, $c486
    ld a, $02
    call Call_000_3e9d
    call Call_000_38ae
    call Call_000_376d
    call Call_000_3e07
    ld a, $90
    ldh [$b0], a
    ret


    call Call_000_3c6c
    ld a, $01
    ld [$cc3c], a
    ld a, [$cd3d]
    call Call_000_3f25
    ret


    ld [$61cd], sp
    scf
    ld hl, $7a6e
    call Call_000_3c79
    xor a
    ld [$d059], a
    ld [$cc26], a
    ld [$cc2a], a
    ld a, $03
    ld [$cc29], a
    ld a, $03
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a

Jump_017_7a21:
    ld hl, $d6af
    set 6, [hl]
    ld hl, $c3a0
    ld b, $08
    ld c, $0c
    call Call_000_03d2
    ld hl, $c3ca
    ld de, $7aa5
    call Call_000_0405
    ld hl, $7a94
    call Call_000_3c79
    call Call_000_3b08
    bit 1, a
    jr nz, jr_017_7a63

    ld a, [$cc26]
    cp $03
    jr z, jr_017_7a63

    ld hl, $d6af
    res 6, [hl]
    ld hl, $7aca
    add a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    call Call_000_3c79
    jp Jump_017_7a21


jr_017_7a63:
    ld hl, $d6af
    res 6, [hl]
    call Call_000_376d
    jp Jump_000_0f6a


    db $ed
    dec hl
    ld a, $52
    ld a, a
    cp d
    or e
    dec hl
    rst $20
    ld d, c
    jp nz, $bcb3

    sbc $7f
    adc b
    db $e3
    dec de
    and [hl]
    db $dd
    ld a, a
    jp nz, $dfb6

    ret nz

    ld c, a
    or c
    cp a
    dec sp
    or [hl]
    ret nz

    ld a, a
    add $7f
    jp nz, $c3b2

    ld e, b
    db $ed
    dec hl
    ld [hl], h
    ld d, d
    cp d
    or e
    db $d3
    cp b
    db $dd
    ld a, a
    sub $d0
    rst $08
    cp l
    or [hl]
    and $57
    db $ed
    inc l
    ld [hl], a
    ld b, e
    inc sp
    ld a, a
    or c
    cp a
    inc a
    add $ca
    ld c, [hl]
    adc c
    xor b
    adc e
    add b
    sbc a
    ld c, [hl]
    sub e
    and a
    db $e3
    inc de
    ld a, a
    adc l
    xor e
    adc a
    db $e3
    ld c, [hl]

jr_017_7ac1:
    sub $d1
    ld a, a
    ret


    ld a, a
    call nc, $d9d2
    ld d, b
    ret nc

    ld a, d
    ld [de], a
    ld a, e
    inc [hl]
    ld a, e
    db $ed
    dec l
    ld c, $67
    pop bc
    ret


    ld a, a
    ld [$9fe3], sp
    inc e
    db $e3
    add c
    call nz, $884f
    db $e3
    dec de
    and [hl]
    inc sp
    ld a, a
    jp nz, $b2c5

    jr nc, jr_017_7ac1

    ld d, l
    ld d, h
    ld a, a
    adc l
    xor e
    adc a
    db $e3
    ld a, a
    ret nc

    daa
    ld h, $dc
    ret


    ld d, l
    add l
    add d
    xor e
    adc a
    db $e3
    ret


    ld a, a
    or l
    ret z

    or h
    cp e
    sbc $26
    ld d, l
    or c
    sbc $c5
    or d
    ld a, a
    cp h
    jp $dab8


    rst $08
    cp l
    ld e, b
    db $ed
    dec l
    ld l, h
    ld h, a
    add b
    sbc a
    jp z, $c44f

    db $d3
    jr nc, @-$3d

    call nz, $c07f
    or d
    cp [hl]
    sbc $7f
    cp l
    reti


    call nz, $55b7
    jp z, $d9b2

    ld a, a
    call $7fd4
    inc sp
    cp l
    ld e, b
    db $ed
    dec l
    add [hl]
    ld h, a
    inc de
    adc l
    xor e
    adc a
    db $e3
    jp z, $c47f

    db $d3
    jr nc, @-$3d

    call nz, Call_017_544f
    db $dd
    ld a, a
    cp d
    or e
    or [hl]
    sbc $7f
    cp l
    reti


    ld a, a
    call nz, $55b7
    jp z, $d9b2

    ld a, a
    call $7fd4
    inc sp
    cp l
    ld e, b
    ld [$61cd], sp
    scf
    ld hl, $7c12
    call Call_000_3c79
    xor a
    ld [$d059], a
    ld [$cc26], a
    ld [$cc2a], a
    ld a, $33
    ld [$cc29], a
    ld a, $02
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a

Jump_017_7b85:
jr_017_7b85:
    ld hl, $d6af
    set 6, [hl]
    ld hl, $c3a0
    ld bc, $0612
    call Call_000_03d2
    ld hl, $c3c9
    ld de, $7c50
    call Call_000_0405
    ld hl, $c3d3
    ld de, $7c5d
    call Call_000_0405
    ld hl, $7c40
    call Call_000_3c79
    call Call_000_3b08
    bit 1, a
    jr nz, jr_017_7c07

    bit 4, a
    jr z, jr_017_7bcc

    ld a, $02
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $0b
    ld [$cc25], a
    ld a, $03
    ld [$d059], a
    jr jr_017_7b85

jr_017_7bcc:
    bit 5, a
    jr z, jr_017_7be5

    ld a, $02
    ld [$cc28], a
    ld a, $02
    ld [$cc24], a
    ld a, $01
    ld [$cc25], a
    xor a
    ld [$d059], a
    jr jr_017_7b85

jr_017_7be5:
    ld a, [$cc26]
    ld b, a
    ld a, [$d059]
    add b
    cp $05
    jr z, jr_017_7c07

    ld hl, $d6af
    res 6, [hl]
    ld hl, $7c6d
    add a
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl+]
    ld h, [hl]
    ld l, a
    call Call_000_3c79
    jp Jump_017_7b85


jr_017_7c07:
    ld hl, $d6af
    res 6, [hl]
    call Call_000_376d
    jp Jump_000_0f6a


    db $ed
    dec hl
    adc a
    ld d, d
    sbc $c6
    ld c, a
    ld d, h
    ld h, $7f
    ret nz

    ret nz

    or [hl]
    rst $18
    jp Jump_017_7fd9


    call nz, $55b7
    or l
    cp d
    reti


    ld a, a
    ret nz

    or d
    pop bc
    ld [c], a
    or e
    ret


    ld d, l
    call $b6de
    add $7f
    jp nz, $c3b2

    ld a, a
    or [hl]
    or [hl]
    jp c, $d9c3

    ld e, b
    db $ed
    dec hl
    inc b
    ld d, e
    cp d
    or e
    db $d3
    cp b
    db $dd
    ld a, a
    ret nc

    rst $08
    cp l
    or [hl]
    and $57

jr_017_7c50:
    db $ed
    inc l
    adc l
    ld b, e
    ld c, [hl]
    ld a, a
    inc [hl]
    cp b
    ld c, [hl]
    ld a, a
    sbc l
    sbc d
    ld d, b
    db $ed
    inc l
    and a
    ld b, e
    ld c, [hl]
    ld a, a
    cp d
    or l
    ret c

    ld c, [hl]
    ld a, a
    call nc, $d9d2
    ld d, b
    ld d, b
    ld [hl], a
    ld a, h
    or e
    ld a, h
    rst $28
    ld a, h
    ld l, $7d
    add c
    ld a, l
    db $ed
    inc l
    jp hl


    ld a, c
    rst $08
    or e
    call nz, $bf7f
    ret


    ld a, a
    or c
    or d
    jr nc, jr_017_7c50

    ld c, a
    cp d
    or e
    add hl, hl
    or a
    ld a, a
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $e7
    ld d, c
    ret nz

    ret nz

    or [hl]
    or d
    ld a, a
    or l
    call c, $c3df
    db $d3
    ld a, a
    ret z

    ret nz

    rst $08
    rst $08
    ld c, a
    ret z

    pop de
    cp c
    dec hl
    rst $08
    cp h
    inc sp
    ld a, a
    jp nc, Jump_017_7f26

    cp e
    jp nc, $bdcf

    ld e, b
    db $ed
    inc l
    ld l, b
    ld a, d
    ld a, a
    cp b
    rst $10
    or e
    call nz, $c04f
    or d
    ret c

    ld [c], a
    cp b
    ld h, $7f
    call $c3df
    ld a, a
    or d
    or a
    rst $08
    cp l
    ld d, c
    ret nz

    ret nz

    or [hl]
    or d
    ld a, a
    or l
    call c, $c3df
    db $d3
    ld c, a
    inc [hl]
    cp b
    jp z, $c97f

    cp d
    ret c

    rst $08
    cp l
    ld h, $55
    inc [hl]
    cp b
    cp c
    cp h
    inc sp
    ld a, a
    or a
    or h
    rst $08
    cp l
    rst $20
    ld e, b
    db $ed
    inc l
    db $fc
    ld a, d
    reti


    call nz, $dc7f
    dec hl
    ld h, $4f
    call nz, Call_000_34b7
    or a
    ld a, a
    inc sp
    push bc
    cp b
    ld a, a
    push bc
    ret c

    rst $08
    cp l
    rst $20
    ld d, c
    ret nz

    ret nz

    or [hl]
    or d
    ld a, a
    or l
    call c, $c3df
    db $d3
    ld c, a
    sbc l
    sbc d
    jp z, $c97f

    cp d
    ret c

    rst $08
    cp l
    ld d, l
    rst $08
    ret nz

    ld a, a
    sbc l
    sbc d
    push bc
    or l
    cp h
    inc sp
    ld a, a
    push bc
    or l
    ret c

    rst $08
    cp l
    ld e, b
    db $ed
    dec l
    and d
    ld d, a
    jp z, $c07f

    or d
    ret c

    ld [c], a
    cp b
    ld h, $7f
    call $c3df
    ld c, a
    cp d
    or e
    add hl, hl
    or a
    ret c

    ld [c], a
    cp b
    call nz, $bd7f
    ld a, [hl-]
    call nc, $d3bb
    ld d, l
    cp e
    ld h, $df
    jp $bc7f


    rst $08
    or d
    rst $08
    cp l
    rst $20
    ld d, c
    ret nz

    ret nz

    or [hl]
    or d
    ld a, a
    or l
    call c, $c3df
    db $d3
    ld c, a
    call nc, Call_000_34b9
    jp z, $c97f

    cp d
    ret c

    rst $08
    cp l
    ld d, l
    rst $08
    ret nz

    ld a, a
    call nc, Call_000_34b9
    push bc
    or l
    cp h
    inc sp
    ld a, a
    push bc
    or l
    ret c

    rst $08
    cp l
    ld e, b
    db $ed
    dec l
    ld h, $57
    jp $bc7f


    rst $08
    or e
    call nz, $cf4f
    rst $18
    ret nz

    cp b
    ld a, a
    or e
    ld a, [hl+]
    cp c
    push bc
    cp b
    ld a, a
    push bc
    ret c

    rst $08
    cp l
    rst $20
    ld d, c
    ret nz

    ret nz

    or [hl]
    or d
    ld a, a
    or l
    call c, $c3df
    db $d3
    ld a, a
    cp d
    or l
    rst $18
    jp $bdcf


    ld c, a
    cp d
    or l
    ret c

    push bc
    or l
    cp h
    inc sp
    ld a, a
    call nz, $bbb6
    push bc
    or d
    call nz, Call_017_5455
    ld h, $7f
    or [hl]
    call c, $bfb2
    or e
    ld e, b
    call Call_000_3c6c
    ld a, $26
    jp Jump_000_3f25


    db $ed
    dec l
    rla
    ld e, e
    adc [hl]
    ld d, [hl]
    rst $20
    ld c, a
    push bc
    or [hl]
    jp z, Jump_000_097f

    sbc [hl]
    ld a, a
    ld a, [hl-]
    rst $18
    or [hl]
    ret c

    rst $20
    ld d, a
    call Call_000_3c6c
    ld a, [$cd3d]
    ld [$cd51], a
    ld a, [$d6f2]
    bit 0, a
    jr z, jr_017_7df9

    ld a, $26
    jp Jump_000_3f25


jr_017_7df9:
    bit 1, a
    jr nz, jr_017_7e3b

    ld a, [$d6c2]
    ld b, a
    ld a, [$cd51]
    cp b
    jr z, jr_017_7e0b

    ld a, $26
    jr jr_017_7e62

jr_017_7e0b:
    ld hl, $d6f2
    set 1, [hl]
    ld hl, $7e65
    ld a, [$cd51]
    ld b, a
    add a
    add a
    add b
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl+]
    ldh [$db], a
    push hl
    call Call_000_3e8c
    swap a
    ld b, a
    ldh a, [$db]
    and b
    dec a
    pop hl
    ld d, $00
    ld e, a
    add hl, de
    ld a, [hl]
    and $0f
    ld [$d6c3], a
    ld a, $3b
    jr jr_017_7e62

jr_017_7e3b:
    ld a, [$d6c3]
    ld b, a
    ld a, [$cd51]
    cp b
    jr z, jr_017_7e56

    ld hl, $d6f2
    res 1, [hl]
    call Call_000_3e8c
    and $0e
    ld [$d6c2], a
    ld a, $3e
    jr jr_017_7e62

jr_017_7e56:
    ld hl, $d6f2
    set 0, [hl]
    ld hl, $d0eb
    set 6, [hl]
    ld a, $3d

jr_017_7e62:
    jp Jump_000_3f25


    ld [bc], a
    ld bc, $0003
    nop
    inc bc
    nop
    ld [bc], a
    inc b
    nop
    ld [bc], a
    ld bc, $0005
    nop
    inc bc
    nop
    inc b
    ld b, $00
    inc b
    ld bc, $0503
    rlca
    inc bc
    ld [bc], a
    inc b
    ld [$0300], sp
    inc bc
    rlca
    add hl, bc
    nop
    inc b
    inc b
    ld b, $08
    ld a, [bc]
    inc bc
    dec b
    rlca
    dec bc
    nop
    inc bc
    ld b, $0a
    inc c
    nop
    inc b
    rlca
    add hl, bc
    dec bc
    dec c
    inc bc
    ld [$0e0a], sp
    nop
    ld [bc], a
    add hl, bc
    dec c
    nop
    nop
    inc bc
    ld a, [bc]
    inc c
    ld c, $00
    ld [bc], a
    dec bc
    dec c
    nop
    nop
    nop
    or d
    push de
    db $d3
    call nc, $c9cc
    adc $c7
    add c
    xor a
    ret z

    add c
    ld a, a
    or h
    ret z

    push bc
    ld a, a
    ld c, a
    call nz, $d3d5
    call nc, $c9c2
    adc $7f
    ret


    db $d3
    ld a, a
    rst $08
    sub $c5
    jp nc, $d47f

    ld d, l
    ret z

    push bc
    jp nc, $8cc5

    ld a, a
    ld d, l
    adc [hl]
    xor b
    push bc
    jp nc, Jump_017_7fc5

    ret z

    pop bc
    db $d3
    ld a, a
    pop bc
    ld a, a
    jp nz, $d4d5

    call nc, Call_017_55cf
    adc $81
    ld d, c
    db $ec
    ld [$ca54], sp
    dec l
    jp c, $e7c0

    ld d, b
    ld [$90cd], sp
    scf
    ld a, $9d
    call Call_000_0e45
    call Call_000_3790
    jp Jump_000_0f6a


    nop
    dec b

jr_017_7f0b:
    adc d
    add hl, bc
    adc [hl]
    ld d, [hl]
    rst $20
    ld c, a
    or l
    rst $18
    call nz, Call_017_7fe7
    add hl, bc
    sbc [hl]
    ld a, [hl-]
    cp d
    ret


    ld a, a
    cp a
    cp d
    add $55
    rst $08
    ret nz

    ld a, a
    adc h
    add c
    xor h

Jump_017_7f26:
    sub b
    ld h, $7f
    or c
    rst $18
    ret nz

    rst $20
    ld d, l
    or l
    cp h
    jp $d07f


Jump_017_7f33:
    sub $b3
    rst $20
    ld a, a
    ld d, [hl]
    ld a, a
    ld b, e

Jump_017_7f3a:
    sub b
    xor h

Call_017_7f3c:
    call nz, Call_017_58c5
    ld [$90cd], sp
    scf
    ld a, $9d
    call Call_000_0e45
    call Call_000_3790
    jp Jump_000_0f6a


Call_017_7f4e:
    nop
    ld d, c
    db $ec
    ld h, b
    ld e, e
    inc de
    add b

Jump_017_7f55:
    ret


Jump_017_7f56:
    ld c, a
    jr nc, jr_017_7f0b

    ld hl, sp+$7f
    xor b
    xor h
    add a
    ld h, $7f
    jp z, $da2d

    ret nz

    rst $20
    ld d, c
    or l
    or l
    or a
    push bc
    ld a, a
    inc sp
    sbc $34
    or e
    inc de

Jump_017_7f70:
    add b
    ld h, $4f
    or [hl]
    sbc $2e
    sbc $c6
    ld a, a
    set 2, a
    or d
    ret nz

    rst $20
    ld d, b

Jump_017_7f7f:
    ld [$90cd], sp
    scf
    ld a, $ad
    call Call_000_0e45
    call Call_000_3790
    jp Jump_000_0f6a


    nop
    ld d, c
    db $ec
    xor b
    ld c, b
    ld d, [hl]
    rst $20
    ld c, a
    push bc
    or [hl]
    jp z, Jump_000_097f

    sbc [hl]
    ld a, a
    ld a, [hl-]
    rst $18
    or [hl]
    ret c

    rst $20
    ld d, l
    or c
    xor h
    rst $20
    ld a, a
    inc sp
    sbc $34
    or e
    inc de
    add b
    ret


    ld d, l
    xor b
    xor h
    add a

Call_017_7fb2:
Jump_017_7fb2:
    ld h, $7f
    db $d3
    inc [hl]

Jump_017_7fb6:
    rst $18

Jump_017_7fb7:
    jp $bc7f


    rst $08

Call_017_7fbb:
    rst $18
    ret nz

    rst $20

Call_017_7fbe:
    ld d, b
    ld [$90cd], sp

Call_017_7fc2:
    scf

Jump_017_7fc3:
    ld a, $a5

Jump_017_7fc5:
    call Call_000_0e45

Jump_017_7fc8:
    call Call_000_3790

Jump_017_7fcb:
    jp Jump_000_0f6a


    nop

Call_017_7fcf:
    ld bc, $0000
    ld bc, $008c
    nop
    add b
    stop

Call_017_7fd9:
Jump_017_7fd9:
    nop
    ld de, $0011

Call_017_7fdd:
Jump_017_7fdd:
    nop

Call_017_7fde:
Jump_017_7fde:
    ld bc, $0004
    add b
    dec b
    nop
    nop
    jr nz, jr_017_7fe7

Call_017_7fe7:
jr_017_7fe7:
    nop
    ld b, $06
    dec bc
    ld hl, $c108
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    ret nc

    ld [bc], a
    nop
    nop
    nop
    ld bc, $0000
    sub d
    nop
    nop
