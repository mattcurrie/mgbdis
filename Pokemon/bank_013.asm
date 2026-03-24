; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $013", ROMX[$4000], BANK[$13]

    ld [hl], a
    cp a
    or l
    inc de
    pop de
    ld a, a
    ret c

    dec a
    ld [hl], $55
    ld c, h
    dec d
    db $fd
    dec [hl]
    ld d, d
    ld l, b
    cpl
    adc b
    ld a, a
    xor e
    ld [$9782], a
    cp $5d
    add hl, sp
    ldh [$a8], a
    dec h
    dec e
    ld [hl], h
    jp nz, $ac88

    adc b
    jp nc, $a189

    or c
    xor [hl]
    or l
    dec d
    dec h
    add hl, de
    ld a, a
    ld [hl], a
    adc l
    inc d
    sbc b
    ld de, $0886
    db $28, $95
    ld c, h
    ld a, h
    ld [$8250], a
    ld b, c
    add hl, bc
    sub h
    ld l, $33
    xor a
    xor $d3
    ld c, d
    rlca
    db $f4
    ld l, d
    ld a, [de]
    cp [hl]
    xor l
    ld d, e
    dec c
    ld hl, $1372
    ld c, e
    db $30, $97
    and b
    sub l
    ld e, b
    dec [hl]
    ld d, l
    ld e, d
    rst $38
    ld l, e
    adc l
    rst $28
    ret z

    ld a, a
    adc c
    xor d
    xor d
    xor d
    adc h
    ld a, [hl+]
    cp $38
    sub l
    ld a, [bc]
    dec a
    ld c, b
    cp $e7
    sbc a
    ldh [$2a], a
    xor [hl]
    ld c, h
    ld l, [hl]
    and [hl]
    pop af
    cp d
    rst $38
    cp $0b
    ld [de], a
    adc d
    ld a, [hl+]
    ld d, d
    add e
    inc d
    ret


    cp a
    rst $38
    ld hl, sp-$06
    ld a, $45
    ld [hl], $91
    and $10
    add $b7
    cp $3e
    ccf
    and e
    jp hl


    dec de
    db $e3
    ld e, h
    inc c
    ld d, h
    ld l, d
    add l
    ld hl, sp-$41
    ld hl, sp+$78
    ld b, c
    sub d
    reti


    ld l, $29
    pop de
    db $eb
    ldh a, [rIE]
    ld de, $d121
    add a
    adc h
    ld c, h
    ld l, [hl]
    add e
    dec b
    ld sp, hl
    dec d
    dec bc
    ld [de], a
    add h
    ld e, [hl]
    add hl, bc
    ld d, d
    add hl, de
    cp d

jr_013_40b7:
    ld b, e
    call nz, $cd49
    rla
    inc e
    jr nc, jr_013_4100

    sub b
    sbc l
    pop af
    ret


    ld h, a
    ld hl, sp+$3e
    ld [hl], a
    cp a

jr_013_40c8:
    ld [hl], e
    ld [hl], l
    ld d, l
    ld d, l
    dec a
    ld a, [bc]
    xor d
    xor b
    ccf
    db $fc
    pop af
    xor d
    adc [hl]
    jr jr_013_40c8

    ld d, l
    ld c, l
    add sp, -$0f
    ldh a, [$8d]
    ld e, b
    pop af
    xor d
    inc b
    or l
    rrca
    ld [$bfa7], sp
    db $d3
    adc l
    ld a, a
    xor d
    dec d
    ld b, e
    jp nz, Jump_000_148c

    sbc a
    ld a, [c]
    ld d, h
    pop de
    add sp, $60
    ld h, b
    xor b
    ld [hl+], a
    rla
    rst $38
    cp $b2
    ccf
    jp $8cee


jr_013_4100:
    sub a
    inc c
    ld hl, $c341
    ld d, b
    ld a, [hl]
    ld hl, $1455
    adc a
    ld a, [c]
    db $10
    ld d, e
    ld c, h
    inc [hl]
    ld h, b
    cp a
    dec de
    ld e, e
    cp $a8
    jr z, jr_013_40b7

    ldh a, [$fd]
    ld c, l
    ld [hl], b
    push bc
    xor l
    dec d
    add hl, bc
    or h
    sub $0a
    xor l
    ld d, e
    ld a, h
    ld hl, $0441
    ld h, h
    ld [hl], l
    ld c, e
    ld c, d
    xor d
    xor d
    add d
    inc [hl]
    xor h

Jump_013_4132:
    adc b
    ld d, b
    cp h
    ld [hl], b
    sbc l
    ld c, l
    dec d
    ld d, l
    ld h, l
    adc l
    ld l, $06
    rst $20
    sub l
    rst $00
    cp $ed
    ld d, l
    ld e, d
    xor d
    and h
    inc de
    add d
    ld d, c
    sbc e
    ld l, b
    add hl, hl
    rst $18
    ld a, [$eb8d]
    adc [hl]
    inc [hl]
    ld [hl+], a
    xor a
    ld d, b
    ld b, d
    and e
    jp nz, Jump_000_3385

    add d
    dec bc
    ld hl, sp-$10
    sub b
    ld c, l
    ld l, d
    adc a
    ld e, $37
    xor d
    dec a
    ld l, e
    ld c, a
    sbc $27
    xor $aa
    xor d
    xor d
    sbc [hl]
    ld h, d
    inc sp
    inc sp
    inc sp
    ld [hl], a
    ld d, d
    ld a, b
    di
    inc sp
    inc sp
    inc sp
    ld c, $78
    or c
    inc de
    inc sp
    inc sp
    inc hl
    sbc [hl]
    ld c, [hl]
    inc c
    call z, $cccc
    ld a, b
    ret nc

    ld [hl], b
    inc sp
    inc sp
    or l
    jr jr_013_41ba

    xor c
    ret z

    add h
    ld d, l
    inc b
    db $ed
    ld b, [hl]
    rst $18
    cp $4a
    ld l, d
    xor l
    or b
    ld b, e
    sbc c
    ld b, [hl]
    ld c, b
    ld a, a
    ld sp, hl
    ld a, [de]
    ld l, d
    rst $38
    ret nz

    adc d
    ld b, d
    ld c, d
    ld a, [hl+]
    sub b
    xor h
    dec a
    ld d, c
    ld d, $99
    cp a
    ld sp, hl
    add hl, bc
    ld [hl], b
    and c
    ld e, a
    db $e4
    ld l, $3d

jr_013_41ba:
    ld d, c
    ld de, $f8b7
    pop bc
    and h
    inc hl
    inc c
    adc l

Jump_013_41c3:
    inc de
    ld a, [c]
    ld a, [hl+]
    ld [hl], c
    cp a
    ret nz

    adc l
    ld a, [$5bb8]
    jr jr_013_4247

    ld a, c
    sub [hl]
    sbc d
    cp [hl]
    ld d, e
    jp $8ae1


    ld h, b
    rst $38
    jp z, $d953

    or h
    add h
    rla
    ld a, [hl+]
    ld de, $440a
    add hl, hl
    pop bc
    sbc h
    ld d, b
    add hl, sp
    ld sp, $3208
    inc c
    ld a, b
    rst $08
    add hl, de
    and c
    inc h
    ld l, c
    pop hl
    pop af
    xor d
    ld b, h
    ld a, b
    or h
    ld l, [hl]
    add h
    ld a, e
    ld sp, $47ec
    rst $28
    nop
    ld [hl], a
    cp a
    and l
    jp c, Jump_000_3c6a

    push bc
    ld e, d
    jr nc, @-$6f

    add hl, de
    ld [$8f37], a
    dec c
    and b
    adc l
    sbc d
    sbc l
    dec d
    dec d
    db $f4
    ldh [rHDMA4], a
    ld de, $2681
    cp $91
    ld b, [hl]
    sub a
    ld a, [$81fe]
    inc sp
    ld e, a
    ld b, [hl]
    ld h, $1f
    ld b, d
    and b
    ld d, a
    dec bc
    ld d, b
    ldh a, [$aa]
    ld h, $bf
    ld d, l
    rst $38
    add c
    ld d, [hl]
    adc h
    ld l, d
    push bc
    add c
    ld e, h
    add hl, hl
    ld e, [hl]
    ld c, d
    ld c, c
    xor d
    daa
    add sp, -$68
    pop bc
    ld l, a
    pop bc
    sub c
    ld a, d
    xor b

jr_013_4247:
    inc sp
    rrca
    push de
    ld d, [hl]
    or e
    inc h
    cp d
    add c

Jump_013_424f:
    and b
    ld b, e
    add $bf
    ret c

    jp z, $a0aa

    cp a
    call nc, Call_000_3099
    adc c
    add c
    or a
    push af
    ld e, [hl]
    sub h
    ld a, a
    rst $38
    ld e, e
    ld d, d
    and d
    and h
    sub l
    xor c
    ld b, $a8
    adc d
    adc e
    and e
    ld a, [bc]
    xor d
    db $fd
    ld [hl-], a
    xor d
    ld l, $3c
    ld e, d
    ccf
    cp [hl]
    ld h, a
    db $f4
    jp nz, $1182

    and $24
    cpl

jr_013_4280:
    di
    inc b
    ld a, b
    ld a, [$ccac]
    db $10
    ld b, h
    rst $00
    add [hl]
    cp a
    ei
    inc b
    ld l, b
    sbc b
    and c
    and a
    ld a, [hl+]
    rra
    ldh a, [$c6]
    jr z, jr_013_42c5

    or b
    ld b, h
    inc [hl]
    and [hl]
    xor b
    ld b, h
    ld h, c
    add l
    pop bc
    ld d, d
    xor e
    pop bc
    or [hl]
    push af
    rlca
    sub c
    db $f4
    ld c, h
    ld c, h
    add hl, hl
    add hl, bc
    add hl, hl
    sbc a
    rst $28
    sub d
    xor l
    ld h, h
    dec hl
    jp hl


    and h
    ld de, $f9b2
    ld e, $52
    rla
    db $eb
    ld d, l
    ld a, [$82a9]
    ld h, l
    jr jr_013_4280

    dec c
    sub c

jr_013_42c5:
    call nz, $1ed6
    xor a
    db $fc
    ld d, [hl]
    ld c, h
    ld [hl], e
    ld b, e
    ld h, h
    ld h, $35
    ld d, $84
    ld h, b
    sbc b
    and a
    sub a
    ld de, $e11f
    sub b
    ld [hl], a
    cp [hl]
    ld d, c
    db $f4
    db $f4
    ld d, [hl]
    call nc, Call_000_3c2d
    rst $10
    jp Jump_013_541b


    db $f4
    dec hl
    ld b, c
    ld h, e
    rst $08
    ld d, l
    ld e, [hl]
    adc b
    ld d, l

jr_013_42f1:
    ld c, a
    add hl, de
    ld h, b
    sub l
    ld d, b
    cp $aa
    cp a
    push af
    ld c, d
    ld l, b
    db $e4
    and l
    ld d, l
    ld e, d
    ld d, l
    inc sp
    xor e
    cp $39
    sub a
    xor l
    ld l, b
    ld e, $ab
    ld c, [hl]
    inc h
    db $e4
    ld d, [hl]
    or h
    rra
    ld a, l
    dec d

Jump_013_4312:
    jr c, @+$2e

    reti


    rst $38
    push af
    dec d
    ld a, [bc]
    inc b
    adc e
    ld d, e
    adc [hl]
    adc h
    ld e, $bb
    ld b, d
    dec bc
    inc b
    ld [hl], b
    rst $18
    ld c, b
    ld d, e
    adc [hl]

Call_013_4328:
    dec h
    ld e, d
    ld a, [bc]
    ld h, b
    sub h
    add h
    ld d, d
    ld d, [hl]
    push de
    ld [hl-], a
    push af
    ld d, l
    ld [c], a
    ld h, c
    adc b
    db $e3

jr_013_4338:
    ld b, h
    jp z, $cea8

    sub a
    adc l
    ld e, c
    ld [$6513], sp
    add hl, sp
    ld l, l
    ld [hl-], a
    ld d, d
    inc [hl]
    jr z, jr_013_42f1

    sbc a
    adc e
    ld a, l
    ld [hl], $a4
    push bc
    db $e3
    inc [hl]
    sbc l
    rst $38
    ld b, a
    add $93
    ld [hl], $29
    add hl, de
    dec bc
    ld e, d
    rst $00
    cp b
    and h
    rra
    ld a, d
    ld a, [hl+]
    adc h
    ld d, d
    ld h, d
    inc h
    ld h, h
    inc h
    ld d, c
    ld d, d
    sbc c
    pop hl
    ld sp, hl
    ld d, d
    jr z, jr_013_4338

    ld [hl-], a
    sub c
    sub b
    add c
    ld hl, sp-$7c
    db $10
    cp a
    ld c, e
    or b
    ld e, a
    ld d, l
    ld hl, $ca64
    ld b, [hl]
    db $e3
    dec d
    dec d
    ld d, a
    adc h
    ld [$efbf], a
    ld h, e
    ld a, [hl+]
    adc l
    dec l
    cp $e3
    call nc, $e2a9
    ld e, [hl]
    dec a
    dec bc
    rst $38
    adc a
    call c, $cbe7
    ld b, a
    and [hl]
    sub b
    add d
    and a
    sbc d
    cp c
    dec hl
    rst $00
    sbc a
    sub b
    call c, $3e7a
    add a
    inc b
    ld c, d
    ld b, d
    ld a, b
    rst $38
    ld hl, sp-$60
    pop bc
    ld d, $ab
    and b
    sub h
    rst $00
    dec l
    push de
    ld [bc], a
    db $10
    and d
    sub l
    push af
    ld d, l
    ld [bc], a
    sbc h
    db $ec
    inc l
    ld [$fa2f], a
    ld [hl], b
    ld c, e
    sbc h
    xor b
    ret nz

    db $d3
    ld [bc], a
    xor b
    ld d, c
    pop bc
    ld h, b
    sbc d
    ld [$0ab9], a
    or h
    ld c, l
    jp hl


    ret z

    sbc c
    ld l, h
    db $10
    ld e, l
    rst $28
    cp $0e
    ld d, [hl]
    sbc b
    ld c, c
    sub d
    ld d, d
    scf
    ld a, [$df83]
    rst $38
    adc a
    ret z

    and c
    ld h, $30
    inc h
    and l
    jp Jump_013_5587


    ld hl, sp-$01
    ld sp, hl
    inc [hl]
    ld [hl], c
    jp z, $8669

    jp $1f52


    ld sp, hl
    add h
    ld [hl], d
    ld e, d
    ld h, l
    ld d, b
    xor e
    call nc, $103f
    add h
    ld h, d
    ldh [$99], a
    sbc $09
    ld l, b
    ld d, l
    jr jr_013_448c

    ld c, d
    ld a, [de]
    db $e4
    rst $18
    and $9c
    ld d, [hl]
    ld [hl-], a
    ld b, e
    ld b, c
    ld hl, sp+$45
    cp l
    ld l, d
    add e
    rst $38
    ld [bc], a
    ld h, e
    sub e
    jr @+$4a

    call z, $c067
    rst $38
    ei
    db $e4
    ld b, [hl]
    ld l, d
    ld l, e
    cpl
    jr jr_013_4472

    add l
    dec l
    rst $38
    rst $38
    or b
    ld c, b
    and h
    sub $09
    sub d
    inc c
    ld [hl], b
    ld b, c
    scf
    rst $38
    sbc b
    jp $1104


    jp c, $4582

    rst $38
    and a
    xor c
    ld [hl], c
    jp hl


    call nz, $ee47
    add b
    ld [hl], a
    cp a
    add h
    sub $a3
    db $d3
    and h
    push af
    inc e
    daa
    inc b
    db $ec
    ld a, a
    rst $38
    db $d3
    rla
    ldh [$91], a
    ld c, [hl]
    jp z, Jump_013_4705

    ld c, e
    ld e, [hl]
    ld hl, $3af6
    jp c, $ad05

    ld e, l
    rla
    and c
    ld a, [hl]

jr_013_4472:
    dec sp
    and l
    jp nc, $eeae

    adc b
    ld a, b
    ldh a, [$b9]
    add hl, de
    ld e, l
    sub h
    dec l
    ld a, b
    db $e4
    ld a, a
    db $fd
    ld d, l
    dec d
    ld b, l
    ld e, d
    add hl, bc

jr_013_4488:
    dec de
    ld b, d
    add hl, sp
    ld e, [hl]

jr_013_448c:
    ld sp, $43eb
    xor b
    xor b
    or l
    db $e3
    ret nz

    push bc
    rst $18
    push hl
    ld b, d
    xor c
    ld l, d
    dec sp
    sub h
    dec de
    pop bc
    ld h, $46
    dec b
    ld h, $8f
    ld bc, $056f
    adc c
    ret z

    adc b
    ld l, b
    inc h
    rst $20
    ld a, l
    dec [hl]
    ld d, a
    xor h
    ld l, l
    ld a, [bc]
    xor e
    ld c, [hl]
    ld c, d
    ld e, $25
    ldh a, [$aa]
    ld [$501e], sp
    cp [hl]
    jp nc, $ff2f

    xor c
    ld sp, $986d
    xor e
    ld a, b
    ld l, a
    or l
    or h
    sbc e
    ld c, h
    ld h, d
    ld [de], a
    and $68
    db $10
    ld b, [hl]
    cp b

jr_013_44d2:
    pop bc
    ld e, b
    inc d
    cp e
    push de
    ld d, l
    ld [$7fce], sp
    ld d, b
    sub e
    rlca
    pop hl
    ld e, [hl]
    inc sp
    xor d
    xor d
    adc [hl]
    ld a, [hl+]
    jr nc, jr_013_4488

    add l
    adc [hl]
    ld e, c
    ld c, [hl]
    sbc e
    ld d, l
    adc a
    ld d, d
    and e
    db $f4
    ld e, c
    db $fc
    ld h, $84
    ld de, $d2e9
    ld a, d
    xor d
    jr nc, jr_013_4563

    ld l, h
    ld e, [hl]
    ld h, h
    call nz, $3158
    ret c

    add e
    rst $18
    or d
    ld d, e
    ld h, h
    ret nc

    ld b, a
    ld h, d
    inc a
    ld c, a
    ld d, $ff
    add h
    ld a, b
    db $10
    inc l
    sub [hl]
    and e
    ld a, a
    rst $00

Jump_013_4517:
    adc b
    db $f4
    ld [de], a
    dec bc
    ld b, l
    ld [hl], h
    ld [hl], d
    inc [hl]
    dec hl
    add sp, -$58
    cp l
    adc h
    inc de
    jr nz, jr_013_44d2

    pop af
    ret


    push hl
    ld e, b
    xor c
    dec de
    inc d
    ld hl, sp-$01
    add h
    ld [hl], a
    ld h, h
    ld b, e
    ld c, $37
    ld hl, sp-$5f
    ld sp, hl
    ldh [$61], a
    dec h
    ld l, c
    scf
    or h
    ei
    ld b, a
    ccf
    xor d
    and e
    ld a, e
    db $eb
    ld [$2d44], a
    and c
    ld l, c
    call $d9f0

Call_013_454e:
    ccf
    pop hl
    or a
    ld h, $18
    ld e, a
    jp hl


    ret


    sub b
    db $e3
    and c
    rrca
    ld [c], a
    ld hl, sp+$3e
    ld h, c
    ld a, a
    jp hl


    jr nc, jr_013_45ab

    add e

jr_013_4563:
    ld l, l
    jr c, jr_013_45de

    ld e, a
    dec d
    ld de, $617a
    ld a, a
    ld d, $86
    ld e, l
    cp a
    ldh a, [$79]
    ld de, $2f8a
    ld b, [hl]
    ld [hl], $61
    inc e
    db $10
    ld e, h
    ld h, h
    and c
    ld e, c
    jp z, $df9d

    ld sp, $1dcf
    sub l
    rra
    cp [hl]
    add b
    ld [hl], a
    cp a
    ld a, b
    ld a, b
    ld d, l
    add hl, sp
    sub l
    ld c, [hl]
    ld b, a
    jp nc, $d31e

    adc l
    and h
    add sp, -$67
    ld a, [bc]
    dec bc
    ld c, [hl]
    dec d
    ld b, [hl]
    pop bc
    add hl, sp
    ld sp, $7c92
    inc sp
    ld b, l
    ld a, [$1409]
    pop bc
    ld d, l
    db $f4
    add [hl]

jr_013_45ab:
    ld hl, $a105
    add l
    ld d, b
    ld d, a
    ld a, [$7e21]
    adc e
    ld h, l
    ld c, d
    ld a, h
    sbc b

jr_013_45b9:
    db $10
    ld c, c
    cp [hl]
    ld a, [bc]

Jump_013_45bd:
    xor b
    add l
    cp $8c
    sub [hl]
    ld [hl+], a
    dec hl
    jp hl


    rlca
    ldh a, [$91]
    adc b
    xor d
    ld d, a

jr_013_45cb:
    add sp, -$1e
    ld a, c
    dec h
    cp h
    ld d, b
    ld e, d
    dec d
    ld c, h
    ld a, [de]
    add hl, sp
    ld l, b
    inc h
    xor b
    adc b
    ld l, a
    rst $08
    ld [de], a
    rst $10

jr_013_45de:
    dec h
    sub h
    ld hl, $dae5
    adc h
    dec [hl]
    ld c, [hl]
    ld l, d
    ld hl, $811a
    or $8c
    sub l
    ld b, d
    xor a
    call nc, $8ad6
    or d
    inc l
    jr nz, jr_013_45b9

    and [hl]
    ld [hl+], a
    ld d, l
    ld b, d
    ld d, l
    ld [hl+], a
    or h
    pop de
    ld c, d
    ld c, b
    ret c

    ld l, b
    add hl, de
    ld d, d
    rla
    sbc d
    xor d
    db $f4
    adc e
    sub l
    jr nc, jr_013_45cb

    or $94
    xor c
    adc c
    ldh a, [$c2]
    adc h

Call_013_4613:
    xor l
    ld e, b
    inc e
    inc hl
    adc d
    sub c
    sbc b
    inc d
    db $10
    adc [hl]
    ld a, [bc]
    ld b, e
    adc b
    adc [hl]
    ld c, c
    ret


    or a
    adc $39
    dec h
    add hl, sp
    db $eb
    add [hl]
    adc [hl]
    ld l, d
    and e
    ld a, [$7e2a]

jr_013_4630:
    push af
    ld [de], a
    sbc h
    xor d
    add hl, hl
    jp z, $8b92

    inc e
    adc h
    add hl, hl
    call z, $10db
    and a
    dec de
    ld [bc], a
    db $10
    rst $20
    inc l
    ret c

    cpl
    pop de
    xor d
    ld de, $3150
    and e
    add d
    ld h, b
    and c
    ret nc

    call nz, $3b25
    inc d
    add h
    ld h, [hl]
    rst $38
    adc d
    ld e, $a3
    ei
    jr z, jr_013_4630

    ld hl, sp-$01
    ld hl, sp+$30
    ld b, [hl]
    adc a
    rst $38
    add e
    adc l
    ld a, a
    ld [hl], e
    ld a, a
    ld e, a
    cp $17
    ld h, c
    inc e
    ld a, h
    or b
    ld a, b
    ld l, e
    cp $45
    ld a, d
    rst $38
    ld sp, hl
    db $db
    ld h, c
    pop hl
    rst $38
    rst $38
    pop bc
    ld hl, sp+$4f
    cp $75
    ld b, l
    ld a, b
    ld [hl], l
    cp $83
    rlca
    adc h
    ld b, l
    adc [hl]
    add d
    ld [hl], c
    dec h
    cp [hl]
    ld d, a
    pop hl
    inc b
    ld a, [hl-]
    sub d
    pop bc
    rst $38
    db $ec
    sbc e
    push bc
    pop hl
    call nc, $87c1
    ld sp, $b335
    dec [hl]
    ld a, h

Jump_013_46a1:
    ld [hl], b
    call nz, $32be
    jp Jump_013_7a64


    sub l
    sbc b
    ld b, l
    ret z

    and [hl]
    ld sp, $c030
    sub d
    pop af
    rra
    rst $00
    ld [bc], a
    inc c
    ret c

    ld c, c
    rst $00
    inc [hl]
    ret nz

    adc d
    ld [hl], d
    or h
    ld b, [hl]
    ld [hl], d
    ret nz

    and b
    jp $b21c


    xor h
    ld a, a
    ld h, b
    add b
    ld [hl], a
    cp a
    ld [hl], a
    cp b
    dec d
    inc a
    push af
    jr @+$22

    rst $08
    ld a, $98
    adc d
    ld b, d
    inc a
    db $db
    ld b, l
    add hl, hl
    ld a, [hl-]
    dec d
    add hl, sp
    ld l, l
    add d
    and e
    ld b, l
    ld d, e
    dec b
    add sp, -$37
    ld d, l
    ld d, l
    ld b, [hl]
    add a
    ld l, b
    add l
    ld d, a
    ld a, [$5590]
    ld a, [$2915]
    and e
    rra
    ld d, h
    ld a, [hl]

jr_013_46f7:
    and b
    ld a, [$c2a8]
    dec l
    ld d, l
    dec h
    adc [hl]
    add hl, bc
    ld l, d
    xor b
    dec d
    ld d, [hl]
    xor d

Jump_013_4705:
    and d
    ld e, a
    xor d
    ld hl, $048e
    sbc c
    xor d
    adc l
    ld d, $a8
    jp z, Jump_013_4132

    and b
    ret c

    jr jr_013_46f7

    ld l, d
    add hl, sp
    jp c, $8181

    pop hl
    ld h, e
    add d
    ld d, h

jr_013_4720:
    ldh [rWX], a
    sbc d
    or l
    adc d
    cp d
    ld d, l
    ld c, l
    add hl, hl
    ld d, h
    adc $52
    cp $8a
    ld a, [hl]
    inc b
    ld e, a
    ld e, a
    and l
    ld d, l
    ld a, [hl+]
    push af
    ld d, d
    or d
    sub $2e
    adc b
    ld e, h
    ld [de], a
    inc sp
    inc [hl]
    cp d
    xor b
    xor d
    ld d, e
    dec h
    or h
    xor b
    ccf
    dec e
    ld d, h
    xor d
    xor a
    ld d, c
    and e
    ld a, [de]
    xor d

jr_013_474f:
    xor b
    sbc d
    inc e
    jr z, jr_013_47b4

    add d
    xor e
    db $f4
    jp nz, Jump_000_3ab5

    dec l
    xor b
    sbc b
    push hl
    xor b
    jp hl


    or a
    ld e, d
    dec a
    ld e, d
    adc a
    db $e3
    add hl, hl
    ei
    cp h
    ret nz

    add d
    ld a, d
    ld [$c7c2], sp
    and c
    dec h
    ld e, e
    ld e, $b3
    dec e
    ld l, c
    rst $10
    ld a, [de]
    jr z, jr_013_4720

    dec hl
    add hl, de
    add hl, hl
    adc d
    add h
    dec bc
    db $10
    add d
    sub c
    pop bc
    ld [de], a
    and d
    cp a
    ld de, $c614
    inc [hl]
    dec bc
    add l
    ret nc

    and c
    ld a, [de]
    dec h
    ld d, d
    inc l
    ld c, e
    inc e
    inc d
    and l
    add hl, hl
    inc [hl]
    ld h, h
    and [hl]
    ld c, h
    ld l, h
    sub h
    call nc, $b46e
    ld l, e
    jr jr_013_474f

    cp $18
    ld a, $6e
    pop af
    ret nc

    rst $38
    rrca
    cp l
    rlca
    inc e
    inc d
    ld a, [bc]
    ld l, a
    dec h
    ld e, d

jr_013_47b4:
    xor a
    call nz, $85a0
    db $10
    and [hl]
    sub h
    ld a, [hl+]
    ld h, a
    add hl, hl
    cpl
    reti


    ld c, h
    dec hl
    pop hl
    xor [hl]
    ld [$a251], sp
    and d
    sub l
    inc h
    jp $ee19


    ld [$2955], sp
    adc d
    adc d
    ld b, l
    pop af
    ld [hl], h
    xor d
    xor d
    xor l
    ld [bc], a
    ld [hl-], a
    ld b, [hl]
    or b
    ld e, b
    and [hl]
    ld [hl], b
    ld hl, $ce71
    adc [hl]
    add hl, bc
    inc d
    ld d, l
    dec de
    ld d, d
    ld [hl], h
    jp $9e0a


    sub h
    inc d
    add hl, bc
    db $fc
    call nc, $bf77
    ld b, b
    ld d, l
    ld d, l
    ld c, a
    ld sp, $8568
    ld b, l
    di
    dec b
    ld c, [hl]
    sub $8a
    ld d, d
    ld e, d
    sub h
    add a
    xor d
    ld a, [hl-]
    ld [c], a
    sub [hl]
    ld e, a
    jp c, Jump_000_1f04

    dec b
    ld c, [hl]
    jp hl


    ld h, $42
    rst $38
    and c
    ld d, d
    xor d
    inc c
    db $ec
    adc e
    and d
    sbc b
    dec [hl]
    ld [hl], h
    reti


    ld c, [hl]
    add hl, sp
    ld sp, $1da8
    xor d
    ld b, $f9
    ld c, e
    sub b
    adc [hl]
    ld c, c
    ld c, h
    xor e
    add hl, hl
    ld a, [bc]
    or a
    rst $38
    rst $20
    ld c, [hl]
    ld a, d
    sub l
    ld d, b
    adc d
    ld sp, hl
    rra
    push de
    ld l, d
    inc d
    rst $28
    ld d, d
    ld [hl], d
    ld h, c
    ld l, a
    inc a
    adc e
    ld c, h
    ld d, b
    and e
    inc l
    ldh a, [$ac]
    inc d
    xor c
    inc [hl]
    adc a
    ld [de], a
    ld sp, $53a2
    jp z, $d852

    ld a, [de]
    ld a, [hl+]
    inc a
    ld h, l
    dec h
    xor b
    db $f4
    dec l
    ld a, b
    or h
    di
    xor b
    cp [hl]
    ld a, [hl+]
    dec a
    jr z, jr_013_488b

    db $f4
    jp c, $3d21

    ld l, c
    ld l, b
    db $f4
    add hl, hl
    ld h, $3d
    ld c, c
    ld d, h
    db $fc
    xor d
    ld a, [hl]
    sub b
    sbc [hl]
    ld h, d
    ld de, $a83f
    add $08
    daa
    ld l, e
    inc d
    jp hl


    ld a, [de]
    ret nc

    inc h
    cpl

jr_013_4882:
    xor c
    rst $10
    sub d
    rst $38
    pop de

Call_013_4887:
    ld c, $1a
    jr nc, jr_013_4882

jr_013_488b:
    and a
    ld h, h
    sub c
    ld hl, $7c70
    ld [$1746], sp
    sbc l
    sub c
    add h
    ld c, d
    ret c

    ld hl, $3ee9
    ld e, d
    ld [hl], e
    ld c, c
    add h
    db $10
    inc sp
    call $fceb
    ld c, d
    rrca
    ld b, a
    inc l
    and [hl]
    jr nc, jr_013_4908

    cp $15
    inc bc
    xor d
    rst $38
    ld b, a
    ld c, l
    add hl, de
    ld d, [hl]
    db $db
    ld a, l
    ld d, l
    ld e, $24
    ld c, l
    inc c
    reti


    ld [$a347], sp
    ld l, l
    db $10
    sub c
    ld c, c
    db $e3
    dec h
    ld e, d
    ld de, $798c
    adc a
    sbc c
    daa
    adc e
    dec h
    ld hl, $4719
    push de
    and a
    xor l
    dec h
    ld b, a
    and a
    ld sp, hl
    jp hl


    or h
    rra
    daa
    and e
    sub c
    ld c, c
    ld [$1149], a
    ld [$e5c7], a
    and b
    ld [hl], a
    dec sp
    rla
    db $d3
    jp nc, Jump_000_197a

    dec a
    add hl, bc
    ld l, $4f
    ld sp, $8cd0
    inc hl

jr_013_48f6:
    jp z, Jump_000_0482

    ld d, h
    cp b
    ld d, h
    sub l
    ld c, e
    ld d, e
    sbc e
    ret z

    sub c
    and l
    ld h, b
    sub h
    cpl
    add hl, bc
    ld a, l

jr_013_4908:
    ld e, d
    ld [$b5e4], sp
    ld d, $34
    add e
    cpl
    add [hl]
    dec b
    ld a, [hl-]
    ld l, b
    inc de
    ld d, h
    ld [hl+], a
    pop de
    or b
    and e
    ld b, h
    inc [hl]
    dec a
    sub c
    ld h, [hl]
    jp nc, Jump_013_60b2

    ld c, h
    db $10
    add c
    adc l
    jr jr_013_4955

    cp a
    ld e, h
    add h
    jr z, jr_013_48f6

    add hl, bc

jr_013_492e:
    ld l, $42
    inc sp
    ld b, e
    jr jr_013_494e

    ld b, $ff
    ld c, h
    pop af
    db $e3
    inc h
    push de
    add [hl]
    ld [hl], b
    ld [hl], b
    sbc e
    rst $38
    pop de
    ld d, h
    xor c
    ld [hl+], a
    ld hl, $d50c
    adc d
    ret


    and b
    xor a
    db $fd
    ld e, h
    ld a, [hl+]

jr_013_494e:
    and c
    add [hl]
    ld e, $3a
    sub c
    add d
    rst $38

jr_013_4955:
    di
    ld [hl], $26
    dec sp
    ld hl, $5541
    ld d, l
    ld c, h
    jr z, @-$6a

    pop hl
    sub d
    or d
    ld d, h
    rra
    rst $38
    rla
    ld l, d
    and b
    ld h, c
    add a
    ld c, [hl]
    add hl, bc

Jump_013_496d:
    ld d, $c2
    pop bc
    sub a
    rst $38
    adc h
    ld d, b
    sub d
    ld [hl+], a
    jr nz, @-$31

    ldh [$c5], a
    add hl, bc
    ld e, a
    rst $38
    adc h
    pop hl
    or c
    ld c, e
    sub e
    add d
    pop bc
    and $af
    adc c
    ld a, b
    sub h
    cp h
    jp Jump_000_3819


    jr c, jr_013_49cd

    ld [$2eae], sp
    daa
    inc [hl]
    sub b
    adc [hl]
    add l
    ld d, e
    db $76
    dec l
    ld a, [de]
    ld b, $39
    ld e, h
    sbc l
    ld c, c
    ld a, [c]
    jr nc, jr_013_492e

jr_013_49a3:
    ret nc

    ld [hl], b
    and e
    sbc [hl]
    inc b
    jr jr_013_49dc

    call c, Call_000_3054
    ld e, d
    ldh [$78], a
    inc hl
    and d
    and c
    and h
    add h
    ld de, $7fbe
    cp a
    cp $ce
    sbc c
    dec d
    inc b
    ld h, l
    dec b
    jp nc, $c25f

    and e
    or d
    pop bc
    inc b
    inc h
    sbc c
    and $08
    pop af
    jp hl


jr_013_49cd:
    ld b, [hl]
    xor b
    jr nz, jr_013_4a2f

    inc a
    cp e
    dec b
    ld d, b

jr_013_49d5:
    ld a, [$9f37]
    ld a, [hl+]
    call nc, $ec79

jr_013_49dc:
    ld [$d440], sp
    ld a, c
    adc c
    jr c, jr_013_49a3

    call nc, Call_013_7f9e
    ld hl, $9416
    sbc [hl]
    ld [hl+], a
    ld e, h
    ld b, h
    rrca
    push hl
    ld a, d
    sub e
    sbc h

jr_013_49f2:
    ld [$1d84], a
    cpl
    add a
    ld hl, sp+$7a
    jr c, jr_013_49d5

    jr jr_013_4a46

    call $cfff
    rst $38
    add a
    ei
    db $e4

Jump_013_4a04:
jr_013_4a04:
    db $e3
    ld h, e
    inc e
    db $10
    push bc
    ld d, e
    rst $38
    rst $38
    rst $30
    ld hl, sp+$69
    jr c, jr_013_49f2

    add d
    ld l, e
    inc d
    or e
    scf
    rst $38
    rst $38
    pop hl
    cp $fc
    ld c, l
    ld b, [hl]
    ldh a, [$62]
    sub e
    inc sp
    scf
    rst $38
    rst $38
    db $eb
    cp $60
    sbc d
    jp $978f


    or e
    scf
    rst $38
    ld d, l

jr_013_4a2f:
    ld b, d
    and l
    ld h, $d0
    ld l, $36
    ld b, a
    jr nz, jr_013_4a04

    add $fe
    add hl, hl
    jp Jump_000_3b0e


    adc [hl]
    ld c, h
    call z, $8f47
    sub e
    ld sp, hl
    ret


jr_013_4a46:
    ld l, $33
    ld c, $08
    inc l
    ret


    cp a
    adc d
    ld [hl], b
    ld b, h
    ld h, e
    db $e4
    ld d, b
    inc sp
    inc sp
    rst $38
    xor d
    xor b
    pop de
    ld c, c
    cp h
    ld [hl-], a
    ld d, $52
    call z, $ffdf
    rst $38
    ld e, a
    and $09
    cp h
    ld de, $7348
    inc sp
    rst $38
    rst $38
    add a
    db $fd
    jp hl


    ld a, [hl+]
    sbc h
    ld c, c
    ld d, b
    ld b, c
    ld e, a
    rst $38
    rst $38
    cp a
    pop hl
    call nz, $86e3
    ld de, $31bc
    ld e, [hl]
    rst $30
    rst $38
    pop hl
    rst $38
    ld a, c
    inc l
    jr c, jr_013_4a2f

    ld c, a
    ld d, h
    rst $10
    ld hl, sp+$7f

jr_013_4a8d:
    add a
    jp nz, $e1c2

    adc d
    ld [hl], a
    ld c, b
    ld d, a
    xor e
    ldh [$8c], a
    cp [hl]
    ld c, [hl]
    ld [hl], h
    ld c, c
    db $10

jr_013_4a9d:
    ld b, h
    ld l, d
    push de
    db $10
    adc l
    ld a, [bc]
    ld [hl], a
    call nz, Call_000_0ca3
    ret c

jr_013_4aa8:
    call nz, $a7c5
    ld d, h
    ld d, [hl]
    sub l
    ccf
    or l
    ld h, h
    ld b, a
    add d
    adc l
    jp hl


    rla
    or $79
    or a
    sub a
    sbc [hl]
    adc h
    ld [hl], h

Jump_013_4abd:
    nop
    ld [hl], a
    cp h
    ld [hl], a
    db $f4
    db $f4
    jp hl


    xor c
    inc a
    call nz, Call_000_1554
    ld h, e
    call $c2aa
    dec b
    ld [hl+], a
    sub l
    ld d, e
    jp nz, $8878

    ld h, c
    and $8b
    xor c
    ld c, [hl]
    db $e4
    dec d
    ld b, [hl]
    db $76
    sub e
    ld d, h
    push hl
    ld d, d
    sub c
    adc e
    adc c
    ld c, [hl]
    push bc
    ld [hl+], a
    xor c
    db $f4
    sub l
    dec h
    ld b, $8e
    jp z, $82b6

    ret nc

    ld d, b
    add c
    jr jr_013_4a8d

    sub l
    ld a, h
    inc h
    db $e3
    or h
    jr nz, jr_013_4a9d

    sub a
    jp c, $3015

    ld hl, sp+$28
    ld e, $c5
    inc [hl]
    adc b
    ld d, h
    jp nz, $2aec

    sub h
    and [hl]
    jp z, $50d8

    ld c, e
    add [hl]
    inc b
    adc b
    inc d
    add [hl]
    sub l
    cp [hl]
    ld b, $21
    or $08
    ld h, d
    jr z, jr_013_4aa8

    ld d, b
    add [hl]
    ld hl, $9e54
    dec b
    ld c, c
    cp l
    and a
    ld sp, hl
    ld d, c
    ld d, d
    ld [hl+], a
    ld [hl+], a
    ld h, c
    adc c
    ld l, d
    ld l, l
    cp [hl]
    sub a
    adc d
    cp e
    ld [$8ba0], a
    ld c, b
    ld c, h
    ld e, c
    ld d, d
    dec e
    ld d, [hl]
    xor b
    add $c2
    ld e, h
    rst $20
    adc b
    and c
    ld d, b
    sub a
    xor a
    ld d, b
    ld a, b
    rst $20
    ld e, b
    xor b
    adc l
    or $a0
    ld b, d
    sub l
    ld e, b
    push hl
    ld [hl], h
    ld h, [hl]
    add hl, hl
    ld h, $d4
    ld l, b
    ld a, $a8
    ld hl, $c9a4
    ld hl, $2a5e
    ld c, d
    ld c, d
    xor c
    jr @-$43

    adc b
    ld c, c
    ld c, b
    db $fd
    ld sp, hl
    xor c
    ld a, [hl+]
    sub d
    inc h
    ld d, l
    xor l
    add hl, hl
    sub $e8
    sbc b
    inc h
    ld h, b
    ld hl, sp-$48
    add l
    and d
    xor [hl]
    adc [hl]
    inc h
    add h
    ld d, $26
    inc sp
    push af
    ld e, d
    add l
    ld [hl], $be
    jr jr_013_4bb2

    db $e4
    db $ec
    ld c, [hl]
    ld a, [de]
    ld hl, sp-$79
    dec bc
    push af
    ld c, d
    ld d, e
    ld h, h
    ld [c], a
    or d
    cpl
    rst $30
    add [hl]
    rst $38
    reti


    add c
    adc [hl]
    ld hl, sp-$77
    ld d, l
    ld a, [bc]
    ld a, b
    adc e
    ld l, b
    ldh a, [$a4]
    ld d, b
    and d
    ld [$c8a3], a
    and e
    db $e3
    and a
    adc [hl]
    call nc, $997a

jr_013_4bb2:
    add hl, sp
    jp hl


    ret z

    ld a, [$9879]
    cp b
    call nz, $4979
    pop hl
    jr z, jr_013_4c25

    inc l
    xor d
    ld h, c
    ld [bc], a
    ld [hl], a
    ld h, c
    ld sp, $ff4f
    and $49
    jp z, Jump_013_7d98

    sub l
    rst $38
    rst $38
    sbc l
    pop de
    ld sp, $4a38
    ccf
    rst $38
    db $fc
    ld [hl], h
    ld [hl+], a
    add h
    add hl, bc
    add hl, hl
    ld a, c
    rra
    db $fd
    add hl, hl
    add d
    ld [hl], d
    ret nz

    rst $28
    and e
    inc de
    xor b
    db $fc
    jp nc, $292a

    ld sp, $44a4
    rrca
    cp $14
    sub l
    ldh a, [rNR51]
    and c
    ei
    ld b, d
    ret nz

    sub a
    inc c
    ld h, c
    ld e, l
    rlca
    ld [$ed08], a
    db $10
    pop af
    rra
    adc h
    ld e, h
    add hl, bc
    ld sp, $5b82
    ld a, $fe
    sbc $87
    inc b
    ld b, a
    ld b, d
    add $91
    adc h
    ccf
    cp a
    rst $08
    cp $2b
    jr z, jr_013_4c3d

    xor [hl]
    inc e
    add hl, bc
    ld de, $4282
    adc h
    ld d, l
    cp a
    rst $38

jr_013_4c25:
    pop hl
    add a
    or a
    db $e3
    ld b, d
    cp c
    ld c, c
    ld c, c
    add d
    add d
    xor b
    ld e, a
    rst $38
    ld b, e
    ld l, a
    add sp, -$60
    cp $d1
    ld [$aea5], sp
    ld b, a
    rst $30

jr_013_4c3d:
    ld sp, hl
    add hl, de
    ld [$cd7e], sp
    ld hl, sp+$4c
    xor h
    ld e, h
    sub l
    rst $38
    add sp, $71
    ld de, $158e
    rst $38
    ld l, l
    db $eb
    ld a, [de]
    ret


    ccf
    rst $38
    rst $10
    sbc d
    xor a
    ld hl, sp-$25
    ld a, a
    xor c
    jp $c75f


    rla
    db $fc
    ld b, a
    ld e, e
    sub $38
    call nz, $1821
    ld b, a
    rla
    dec b
    ld c, d
    db $10
    ld a, [hl-]
    dec d
    ld c, $54
    ld c, h
    ld d, h
    ld [hl], c
    ld d, c
    ld [de], a
    add d
    dec d
    jr jr_013_4ca2

    cp h
    ld [hl], e
    ld d, l
    ld d, h
    cp b
    cp a
    ld [c], a
    ret nz

    sbc c
    rst $00
    ld a, d
    dec d
    db $10
    and d
    sbc [hl]
    ld [hl+], a
    sbc c
    and h
    ld hl, $351e
    rra
    add e
    nop
    ld [hl], a
    cp a
    dec de
    ld l, c
    dec a
    sbc b

Jump_013_4c97:
    db $f4
    rra
    jp z, Jump_000_3a8f

    adc b
    add [hl]
    inc a
    sub l
    ld d, c
    ld c, e

jr_013_4ca2:
    ld a, b
    inc hl
    sbc c
    ld c, l
    sbc [hl]
    xor e
    and l

jr_013_4ca9:
    ld a, [hl+]
    sbc b
    push hl
    ld l, e
    ld d, h
    add l
    ld d, $df
    push de
    add d
    dec b
    ld c, b

jr_013_4cb5:
    ld c, [hl]
    reti


    cp e
    xor l
    ld h, l
    ld [$f087], sp
    ld b, c
    ld [$4ae4], sp
    add d
    or b
    add c
    and a
    add c
    add [hl]
    add e
    xor d
    jp nz, $3839

    or l
    adc d
    ld h, b
    ldh [$94], a
    ld d, b
    rst $38
    adc [hl]
    ld l, b
    inc de
    ld [$082a], sp
    adc b
    ld d, [hl]
    ld [hl+], a
    cp a
    add d
    db $d3
    adc a
    add c
    dec d
    inc b
    dec d
    ld e, $0c
    ld [c], a
    ld [hl], h
    pop hl
    and e
    ld a, [de]
    jp nz, Jump_000_0e82

    ld d, e
    add [hl]
    adc [hl]
    add hl, bc
    ld l, b
    ld d, h
    jr jr_013_4cb5

    ld d, $fb
    ld e, l
    ld sp, $6453
    sub l
    inc d
    and h
    sbc l
    xor b
    jr z, jr_013_4d17

    jr z, @-$16

    jp nc, Jump_000_092d

    db $fd
    inc b
    or a
    adc e

Jump_013_4d0c:
    and d
    call nc, Call_013_52e0
    ld l, a
    ld b, l
    adc h
    jr c, jr_013_4ca9

    inc [hl]
    pop bc

jr_013_4d17:
    dec d
    ld c, l
    xor l
    ld c, c
    sub b
    sbc h
    pop bc
    ld d, $22
    push de
    jr jr_013_4d86

    adc [hl]
    cp h
    ld d, $14
    and h
    adc d
    ld sp, $0cae
    sub h
    push hl
    xor c
    ld [hl+], a
    ld hl, $3545
    add e
    ld hl, $a83a
    ld h, h
    ld e, a
    adc c
    adc h
    ld l, d
    and e
    or d
    pop de
    sub h
    and [hl]
    inc a
    set 6, l
    db $fd
    adc a
    ld c, d
    xor d
    ccf
    ld b, $9f
    adc l
    push af
    and a
    xor b
    sub c
    daa
    and b
    add sp, -$5d
    ld e, $75
    db $fd
    inc bc
    ld c, c
    db $e3
    and d
    sub b
    pop af
    dec de
    ld d, c
    adc $9c
    dec [hl]
    or a
    push hl
    reti


    call $82fa
    ld c, d
    sub l
    ccf
    add l
    ld [$1c09], a
    ld [hl], e
    ld a, [hl]
    ld b, h
    ld a, $cd
    db $ed
    and d
    cp $83
    cp d
    ld [hl], d
    pop hl
    ld hl, sp+$62
    pop bc
    ld a, b
    ld hl, $5051
    ld a, $30
    ld b, a
    ld a, [de]

jr_013_4d86:
    pop hl
    ld hl, sp+$7e
    ld b, e
    ei
    ld [hl-], a
    sub e
    ld a, [hl+]
    jr nc, @+$29

    dec h
    pop bc
    ld hl, sp+$7e
    rra
    cp $f8
    ld b, c
    dec d
    inc c
    ld [hl-], a
    ld [hl], d
    inc sp
    pop bc
    cp $15
    rst $38
    ret nz

    sbc b
    ld h, $16
    sbc h
    ld d, a
    and h
    ld [c], a
    pop bc
    ld a, b
    ld e, l
    db $e4
    cp c
    sub a
    rst $00
    ld b, $bc
    inc a
    ld de, $163e
    ld e, $3c
    jp c, $f963

    or a
    ldh a, [rLY]
    ld h, b
    and b
    pop bc
    ld c, l

Call_013_4dc2:
    ld b, h
    ld e, a
    or $a5
    ld a, c
    jp Jump_013_4c97


    jr z, jr_013_4dfa

    inc l
    jp Jump_013_71e3


    ld e, a
    sbc h
    di
    adc h
    ld b, a
    add [hl]
    add hl, de
    ld d, e
    ld b, $57
    add d
    add d
    ld [hl], b
    xor b
    cp [hl]
    ld b, e
    cp $18
    ld h, h
    add hl, sp
    inc [hl]
    and c
    inc b
    ld [hl], e
    rst $18
    ld b, d
    rst $38
    db $ed
    xor e
    ld sp, hl
    adc d
    add hl, hl
    add hl, de
    pop de
    rlca
    rst $38
    db $ed
    ccf
    and $32
    db $10
    add hl, sp

jr_013_4dfa:
    sub $ff
    rst $38
    rst $38
    db $f4
    ld a, c
    ld [hl], a
    rst $38
    rst $38
    ld e, $7c
    rra
    ld d, a
    sbc a
    sbc [hl]
    add b
    ld [hl], a
    cp e
    sub l
    ld c, a
    ld c, l
    ld d, a
    and e
    db $d3
    ld d, l
    dec a
    ld b, l
    push af
    or h
    rra
    ld c, a
    ld [hl-], a
    xor d
    db $db
    ld c, $a4
    db $f4
    ld l, $76
    add sp, -$3b
    xor b
    ldh a, [$ed]
    rrca
    ld e, c
    ld d, h
    ld d, l
    dec sp
    inc d
    ld d, a
    ret nc

    ld b, e
    ld b, [hl]
    xor l
    ld [hl+], a
    adc c
    ld c, [hl]
    add [hl]
    ld a, [de]
    jr jr_013_4e52

    rst $10
    adc l
    and $37
    ld d, b
    ld d, b
    adc h
    and c
    xor c
    db $e4
    pop de
    ld h, e
    ld d, [hl]
    and c
    cp e
    inc [hl]
    sbc b
    jr z, jr_013_4e63

    push bc
    and e
    ld h, [hl]
    cpl
    cp l
    ld b, c
    ld c, b

jr_013_4e52:
    and c
    sbc e
    ld [hl], l
    ld c, e
    adc [hl]
    inc b
    ret


    ld [$2269], sp
    adc d
    and d
    ld h, h
    ld e, b
    db $eb
    or h
    inc h

jr_013_4e63:
    inc h
    db $10
    ld a, d
    adc h
    ld d, b
    adc [hl]
    ld b, [hl]
    xor c
    dec a
    sub h
    ld e, [hl]
    ld b, $06
    add d
    dec b
    ld d, h
    jp nz, $8e53

    sub e
    ld [$5411], sp
    ld l, a
    ld c, b
    ld d, h
    pop bc
    sub e
    adc d
    ld h, h
    sbc l
    ld a, [$557e]

jr_013_4e85:
    dec c
    sbc [hl]
    jp nc, $38e5

    rst $20
    ret nc

    ld [hl], a
    ld [$e88d], sp
    add hl, de
    dec b
    dec bc
    ld c, e
    ld h, l
    add hl, sp
    jr z, jr_013_4ec0

    inc d
    pop bc
    ld b, l
    ld e, e
    ld a, b
    adc $93
    and d
    rst $10
    reti


    add hl, bc
    ld a, d
    jp $2255


    ld l, $4e
    adc d
    ld a, [de]
    ld hl, sp+$20
    push hl
    sbc $b6
    ld d, e
    jp z, Jump_000_27bb

    ld b, d
    add [hl]
    and b
    rst $08
    dec d
    ld [$4c75], a
    ld h, l
    ld c, a
    ld c, $fa

jr_013_4ec0:
    xor [hl]
    dec a
    dec sp
    db $e3
    ldh a, [$09]
    call c, Call_013_7a8a
    ld l, e
    ld de, $9a1e
    inc c
    add hl, bc
    jp hl


    ld e, l
    ld c, d

Call_013_4ed2:
    ld c, e
    sbc [hl]
    sbc h
    sub e
    ld [bc], a
    ld a, d
    ld d, e
    and h
    ld b, [hl]
    inc l
    ld a, b
    or e
    pop af
    inc d
    add hl, bc
    add hl, bc
    call c, $8490
    ld [$d020], sp
    xor b
    cpl
    sub a
    ld [bc], a
    ld [hl], e
    cp [hl]
    cp e
    ld de, $3fdc
    rst $38
    ld sp, hl
    add h
    ld [hl], b
    jr nz, jr_013_4e85

    rst $38
    rst $38
    reti


    ld c, b
    scf
    rst $38
    ld [c], a
    or c
    cp [hl]
    cp b
    ld d, a
    or a
    ld hl, sp+$74
    sub d
    cp h
    rst $38
    rst $38
    inc e
    ld c, a
    rst $38
    sbc $ba
    dec c
    add d
    cp b
    or [hl]
    rst $38
    rst $38
    rst $00
    rrca
    rst $38
    cp $16
    rra
    di
    rst $28
    sub c
    rst $38
    rst $38
    pop af
    ret


    rst $38
    cp $1e
    cp $1b
    rst $30
    ld a, a
    ld a, a
    rst $38
    rst $00
    cpl
    rst $38
    ld hl, sp+$7f
    ld hl, sp+$73
    add [hl]
    ld d, a
    rst $38
    ld sp, hl
    jp z, $5fe4

    add l
    add l
    ld [bc], a
    ccf
    ld a, c
    inc e
    ld b, l
    ld a, [hl]
    ld [hl], d
    ld d, d
    ld b, l
    push hl
    or h
    inc e
    ld d, $46
    add hl, bc
    ld d, a
    and a
    inc l
    xor a
    ld c, $b0
    cpl
    db $10
    sub e
    ret


    ld d, a
    rst $20
    inc l
    inc sp
    ld hl, $6f13
    ldh [$95], a
    ld l, c
    ld e, a
    adc d
    sbc l
    ld sp, $8295
    ld [$dec5], sp
    ld c, h
    ld [hl], l
    and h
    inc [hl]
    ld [$303c], sp
    ld [hl+], a
    add e
    add $09
    db $dd
    ld [de], a
    sub c
    cp d
    ld b, a
    ld [bc], a
    sub b
    sbc [hl]
    ld c, l
    ld h, b
    sbc c
    daa
    sub h
    adc l
    add hl, de
    rst $00
    adc l
    inc b
    ld sp, $c0f9
    ld [hl], a
    cp l
    dec b
    db $e3
    pop de
    ld e, a
    ld sp, hl
    inc a
    push de
    rst $38
    ld a, [$673c]
    ret nc

    ld e, e
    rst $38
    and b
    ld e, [hl]
    inc a
    ld c, d
    ld a, [de]
    inc hl
    and c
    ld e, [hl]
    adc c
    ld a, d
    ld a, [hl-]
    sub l
    push hl
    inc b
    ld a, [de]
    sub a
    add sp, -$6b
    cp b
    add sp, $5f
    rst $30
    sbc e
    ld d, [hl]
    jp nz, Jump_013_5f88

    sbc $21
    add hl, sp
    ld l, [hl]
    sub [hl]
    rst $18
    ld hl, $5ffe
    add sp, -$48
    inc hl
    sbc d
    ld a, [$ded1]
    adc b
    cp d
    ld [hl-], a
    xor [hl]
    scf
    ld [hl], h
    sub l
    ld b, l
    ld b, d
    ld c, $09
    ld h, $32
    ld e, [hl]
    inc [hl]
    ld d, l
    ld c, b
    ld d, a
    ld e, [hl]
    adc e
    rst $38
    ld d, b
    ld h, e
    rlca
    and e
    ld d, l
    cp a
    add hl, bc
    jp hl


    dec d
    inc b
    ld a, [hl-]
    adc e
    ld d, d
    sbc $38
    xor d
    ld [$d21b], sp
    ld l, d
    ld d, e
    add d
    adc [hl]
    call nc, $b554
    ld d, h
    call Call_013_454e
    ld hl, $5814
    and h
    sbc d
    ld c, $82
    ld a, [hl+]
    db $d3
    add c
    ld b, c
    ld a, b
    inc d
    dec [hl]
    ld a, [hl+]
    add hl, sp
    ld l, a
    ld c, l
    sub h
    ld a, [hl+]
    add c
    add sp, -$7a
    dec d
    ld e, l
    ld c, [hl]
    dec de
    ld c, l
    ld d, h
    adc e
    ld a, e
    jp nz, $9506

    ld l, d
    db $f4
    ld [hl], d
    dec d
    ld d, h
    ld d, [hl]
    dec [hl]
    ld d, l
    ld e, l
    ld d, a
    sub a
    ld [$d7be], a
    xor a
    add d
    adc b
    xor l
    and h
    jp nc, $86aa

    add [hl]
    sbc l
    dec l
    xor d
    sub b
    xor a
    jr nc, @-$79

    add hl, sp
    cp $5d

jr_013_5038:
    rlca
    xor e
    ld e, d
    push af
    ld c, a
    ld a, [bc]
    add sp, $7e
    rlca

Call_013_5041:
    ld a, [bc]
    ld l, $8c
    ld d, l
    ld a, [hl-]
    ld l, l
    reti


    ldh a, [$99]
    ld l, b
    ld d, h
    pop af
    and c
    and b
    or h
    add hl, hl
    add hl, bc
    ld l, e
    ld d, l
    inc a
    sbc d
    ld [$6877], sp
    sbc e
    ld c, a
    inc hl
    rst $30
    ld e, l
    dec h
    db $e3
    ret


    or l
    ld [$e321], a
    jp z, $7daa

    ld d, a
    adc h
    ld h, a
    and d
    or c
    jp hl


    cpl
    ld h, c
    ld e, $72
    db $fc
    ld a, c
    ld l, d
    ld d, a
    pop de
    add hl, hl
    db $e4
    ld [hl], c
    add hl, hl
    ld l, c
    sub h
    sbc l
    adc b
    ld a, $28
    ld b, e
    inc bc

Jump_013_5083:
    ld e, $2a
    db $fc
    or c
    inc sp
    ld h, $0a
    or a
    adc e
    inc e
    call nc, $1955
    xor e
    db $f4
    ld b, e
    ld [bc], a
    db $76
    ld c, b
    jr nz, jr_013_5038

    cp $0f
    db $f4
    ld h, c
    inc e
    ld l, $94
    jp nz, $b786

    db $ed
    ld hl, sp+$71
    add d
    ld l, [hl]
    sub l
    sub b
    cp [hl]
    add e
    db $fd
    ld [hl], c
    ld c, a
    sbc l
    dec bc
    db $f4
    db $dd
    ld e, a
    db $db
    ld h, $99
    push de
    jp Jump_013_7a61


    ei
    rst $30
    and a
    inc b
    ld [hl], d
    ld h, h
    pop hl
    ld a, a
    rst $38
    pop hl
    push hl
    ld h, $79
    ret


    add sp, $3e
    ld e, $3f
    ldh a, [rPCM34]
    pop hl
    cp $0b
    inc de
    ld l, c
    jp $847a


    ld de, $4234
    rst $38
    cp a
    pop hl
    and $17
    and a
    ld [bc], a
    ld c, h
    ld de, $516f
    dec e
    ld hl, sp+$79
    sub l
    jp hl


    cp d
    ld e, d
    jr nc, jr_013_511e

    ld [$43a4], sp
    call nz, $b7a4
    ld sp, $90b2
    sub b
    sub e
    ld de, $107a
    cp a
    xor c
    ld a, $f7
    ret


    ldh [$7a], a
    ld d, l
    rst $18

jr_013_5104:
    and c
    rst $38
    db $e4
    daa
    add b
    ld sp, hl
    rrca
    cp l
    ld h, c
    rst $38
    rst $20
    add h
    db $fc
    and c
    rst $38
    db $e4
    rst $38
    ld sp, hl
    pop hl
    ld [hl], b
    sbc $d2
    ld a, [de]
    ld b, l
    rst $38
    sbc [hl]

jr_013_511e:
    ld c, l
    pop hl
    dec d
    xor a
    ld b, a
    sbc a
    inc bc
    rst $38
    db $f4
    ld a, c
    sub d
    ld [$c75f], sp
    sub h
    sub l
    ld e, $b4
    jr z, @-$58

    ld h, b
    ld [hl], a
    cp a
    adc b
    rst $10
    ld sp, hl
    and l
    inc a

jr_013_513a:
    jp c, $85a0

    add [hl]
    sub h
    ld a, [c]
    jr z, jr_013_5104

    add c
    inc d
    inc h
    rra
    push de
    ld d, h
    pop af
    or b
    add c
    ld h, b
    add d
    ld e, h
    sub [hl]
    adc [hl]
    sub l
    ld a, [hl+]
    add hl, bc
    ld [hl+], a
    ret c

    and l
    ld d, l
    ld b, [hl]
    ld d, $a4
    ld [c], a
    ld d, b
    xor d
    ld l, d
    ld l, b
    add $49
    ld c, b
    ld h, e
    and d
    rst $30
    ld e, a
    sbc $83
    ld [hl], h
    sub h
    ld e, a
    or h
    cp b
    add sp, -$58
    db $10
    rst $20
    db $fc
    xor b
    dec d
    ld d, h
    pop bc
    ld a, [hl-]
    ld e, l
    dec bc
    rst $38
    res 2, b
    add d
    inc hl
    rst $08
    ld [bc], a
    ld c, $eb
    db $d3
    ld d, [hl]
    sub d
    db $10
    ld c, [hl]
    ld h, l
    ld h, c
    and a
    ld h, e
    ld b, [hl]
    ld sp, $3982
    and b
    sub b
    ld b, l
    ld a, [bc]
    dec l
    ld l, b
    rla
    ld b, d
    dec h
    ld a, [hl-]
    inc d
    db $10
    ld a, d
    ld b, $41
    and c
    ld e, [hl]
    adc h
    ld e, $3a
    db $10
    ld e, b
    ld l, b
    adc e
    ld d, a
    and d
    ld l, b
    jr nz, jr_013_513a

    call z, Call_013_7810
    cp d
    adc h
    ld d, h
    sub a
    ld c, [hl]
    sbc c
    db $e3
    sbc [hl]
    and b
    ld c, a
    ld b, [hl]
    add [hl]
    ld b, l
    dec a
    dec bc
    ld e, a
    ld h, e
    db $d3
    and e
    or $79
    db $fc

Call_013_51c5:
    ld c, b
    ld [$292a], a
    and $3f
    pop hl
    add a
    add a
    cp c
    push hl
    ld e, l
    pop hl
    ldh [$ae], a
    ld d, $90
    xor c
    pop hl
    ld c, l
    adc a
    dec l
    ld [c], a
    ldh [rIE], a
    rst $38
    adc $75
    and c
    ld h, c
    pop hl
    pop hl
    ld d, c
    ccf
    ld b, l
    call c, $a74a
    inc e
    adc h
    ld d, $a8
    ld a, [hl+]
    cp a
    ld a, [$ff66]
    and a
    inc h
    db $10
    db $e3
    dec b
    push af
    rst $38
    jp hl


    cpl
    db $ed
    rst $38
    sbc l
    adc $ff
    rst $38
    ld sp, hl
    rla
    di
    pop bc
    ld sp, hl
    sub $ff
    rst $38
    dec l
    cp $84
    xor a
    inc de
    rst $20
    ld e, e
    ld a, a
    ld b, c
    ld e, [hl]
    rst $18
    sub c
    ld d, d
    cp $1a
    ld b, d
    ld [hl], d
    pop bc
    ld sp, hl
    ld l, [hl]
    rrca
    ld a, [bc]
    cp a
    rst $38
    pop hl
    add e
    rst $00
    ld b, a
    and h
    cp h
    inc d
    rst $38
    rst $38
    ld h, c
    ld a, b
    ld a, a
    and a
    dec a
    ld a, b
    ccf
    call nz, $f6ff
    ld c, e
    db $fd
    dec e
    ld l, a
    rst $38
    and l
    sub $65
    rst $20
    ld [hl], e

jr_013_5240:
    db $fc
    ld [hl], d
    ld d, [hl]
    ld c, d
    ld a, d
    ld a, [hl]
    cp [hl]
    ld a, d
    cpl
    rst $38
    pop de
    jp hl


    ld [hl], c
    db $fc
    ld a, $77
    cp e
    ld e, d
    ld d, l
    dec a
    inc d
    adc [hl]
    xor c
    inc a
    sub l
    rla
    xor c
    ld [$9321], sp
    push bc
    ld a, d
    or l
    rla
    rla
    ld d, l
    jp hl


    ld d, e
    and l
    db $fd
    or c
    ld d, c
    cp a
    xor d
    adc d
    xor c
    ld a, d
    ld d, h
    ld [c], a
    ld d, b
    xor c
    ld a, [bc]
    adc b
    ld e, b
    ld h, l
    add hl, hl
    ld d, l
    ld a, [de]
    sub b
    xor c
    jr c, @+$6a

jr_013_527e:
    ld h, c
    sub [hl]
    dec b
    ld a, [hl+]
    xor d
    ld a, [hl+]
    ld e, d
    adc c
    ld c, [hl]
    rla
    ld b, a

jr_013_5289:
    ld d, d
    ld a, [hl+]
    push af
    ld c, [hl]
    ld e, b
    push de
    rlca
    push de
    ld a, [$89d0]
    xor e
    push af
    ld d, e
    ld b, a
    inc [hl]
    ld a, d
    and c
    add d
    ld h, $4d
    ld a, [hl+]
    cp a
    push de
    ld d, a

jr_013_52a2:
    ld e, b
    ret


    ld a, e
    ld [$ec92], a
    db $e3
    xor a
    ld a, [$7832]
    ld d, h
    db $10
    ld b, [hl]
    jr nc, jr_013_527e

    db $dd
    dec h
    adc l
    call nc, $aaa5
    jr jr_013_5240

    ld b, e
    ld [hl-], a
    ld b, [hl]
    sub a
    ld c, [hl]
    ld [hl], a
    sub d
    jp nc, Jump_000_3a23

    add e
    ld [hl+], a
    adc [hl]
    ld e, [hl]
    ld e, b
    and h
    sub h
    db $dd
    jr c, jr_013_52a2

    sub a
    and d
    sub h
    add [hl]
    inc c

jr_013_52d3:
    res 4, b
    sub l
    db $e3
    ld [hl], l
    dec d
    rrca
    cp b
    ld d, d
    ld de, $d54c
    and c

Call_013_52e0:
    adc $2b
    ld [hl], h
    or [hl]
    ld e, d
    ld d, $53
    jr z, jr_013_52a2

    jr c, jr_013_5289

    ld a, [$a4aa]
    ld a, c
    jr jr_013_52d3

    sub h
    ldh [$bb], a
    ret nc

    db $f4
    adc e
    inc b
    sbc b
    db $e4
    sub e
    adc d
    db $f4
    dec l
    ld h, b
    ld c, e
    adc [hl]
    ld d, h
    db $e3
    adc b
    add l
    ld d, e
    sub c
    ld c, h
    inc de
    ld h, l
    ld a, [bc]
    ld b, $18
    ld l, a
    ld d, l
    jp c, $55a9

    add [hl]
    and l
    inc d
    db $dd
    ld a, a
    ld b, $b4
    add a
    ld b, d
    add hl, sp
    ld l, b
    pop hl
    xor b
    dec l
    ld hl, $fa7a
    db $f4
    ld a, [c]
    ld l, a
    and l
    inc hl
    ld h, $8f
    ld a, [hl-]
    db $fc
    jr jr_013_5396

    db $f4
    xor a
    ld hl, sp-$1b
    sbc l
    jp z, $a87a

    ld b, c
    ld h, a
    sbc d
    sbc b
    and e
    add a
    sbc [hl]
    ld e, d
    ld [$d1f8], a
    ld c, h
    add hl, hl
    jp nc, Jump_000_2ac1

    cpl
    rst $10
    add $d0
    or b
    and a
    ld [de], a
    ld c, [hl]
    or a
    db $e4
    ld c, d
    add hl, bc
    and d
    ld d, h
    ld [hl-], a
    ld [hl], c

Jump_013_5356:
    cp a
    and c
    di
    rst $10
    or d
    dec hl
    ld hl, sp+$7a
    ld [$9c4c], sp
    xor l
    ld a, [c]
    adc h
    ld c, e
    ld b, c
    rrca
    rst $38
    ld a, d
    jr jr_013_53cc

    sbc h
    ld [$cfbe], sp

Jump_013_536f:
    ld a, [$fa17]
    ld [c], a
    push de
    ld h, c
    ld hl, sp+$44
    ld b, d

Jump_013_5378:
    sbc c
    and e
    db $ed
    ld e, a
    rst $38
    and c
    ld a, a
    db $ec
    sub b
    db $e4
    ld sp, $b569
    ld l, d
    ld e, e
    ld e, a
    add l
    cp $c9
    rla
    cp $93
    ld a, [de]
    cpl
    db $fd
    ld a, c
    ld e, a
    or a
    add l
    di

jr_013_5396:
    db $10
    add sp, $54
    ld [hl], b
    xor a
    rst $38
    adc a
    rst $18
    rst $18
    db $ed
    add a
    call z, Call_000_1944
    ld sp, $7fc3
    ld a, [$7ef0]
    rra
    cp $8b
    ld sp, $7151
    pop bc
    ld a, a
    db $f4
    adc a
    pop hl
    rst $10
    ret z

    ld a, [hl]
    push bc
    dec h
    and [hl]
    pop de
    dec d
    sub c
    add e
    db $f4
    ld c, e
    rst $08
    db $ec
    ld b, d
    add hl, de
    add hl, hl
    jp Jump_013_4517


    inc h
    cp [hl]
    rra

jr_013_53cc:
    db $ec
    ld b, l
    ret nz

    xor c
    adc $98
    jp nc, $0ffe

    ei
    inc h
    ccf
    cp $9c
    xor e
    jp z, $ff87

    pop bc
    rst $28
    db $ec
    adc e
    db $fc
    xor h
    ld [hl], h

jr_013_53e5:
    ld e, a
    ld hl, $077d
    rst $28
    db $ec
    adc a
    ld hl, sp+$7e
    add hl, bc
    add hl, bc
    srl [hl]
    ret nc

    cp h
    rra
    ld a, [$fb3f]
    ldh a, [$61]
    add [hl]
    ld [hl], d
    rst $18
    pop bc
    db $ed
    and e
    ld a, a
    dec b
    ld a, [hl]
    rra
    inc b
    inc c
    rst $00
    inc c
    ld c, a
    ld c, a
    db $e4
    dec [hl]
    ld b, [hl]
    sub c
    push de
    jr nz, jr_013_53e5

    scf
    xor a
    and a
    and l
    ld e, l
    ld e, [hl]
    ld a, [hl+]
    ld a, c
    ld [hl], c
    adc h

Jump_013_541b:
    ld sp, $44e9
    add hl, sp
    ld a, [c]
    nop
    ld [hl], a
    cp [hl]
    ld e, l
    ld c, a
    ld d, c
    ld l, d
    add l
    ld c, a
    ld a, [hl-]
    or a
    db $db
    xor b
    di

jr_013_542e:
    ld l, d
    ld h, $dd
    ld c, a
    ld hl, $8c56
    dec d
    ld a, e
    call nc, Call_000_3a95
    sbc a
    ldh a, [$aa]
    sub d
    ld a, [hl+]
    add d
    add d
    and a
    db $eb
    ld c, [hl]
    ld a, d
    sbc h
    dec de
    inc b
    ld h, b
    cp [hl]
    call nc, Call_013_6317
    or [hl]
    add c
    ld a, [bc]

jr_013_5450:
    inc c
    jr nz, jr_013_5450

    dec b
    jp nz, Jump_000_2922

    jr c, jr_013_542e

    ld a, a
    ret c

    dec sp
    ld d, l
    ld a, [de]
    ld d, h
    ld h, l
    ld hl, sp+$17
    xor b
    reti


    ld a, [$959d]
    add e
    cp a
    cp a
    ld l, b
    rra
    or a
    ld [$4d09], a
    ld l, b
    jp nz, $ad06

    rla
    ld a, a
    db $dd
    sbc a
    or a
    add $93
    ld e, d
    ld [hl-], a
    add c
    ld l, d
    db $db
    add e
    add sp, -$78
    ld a, $c2
    ld c, $a3
    sbc a
    xor d
    ret z

    add $05
    ld a, [c]
    dec a
    ld b, d
    ld d, l
    ld b, d
    ld c, l
    inc d
    add $71
    ld d, a
    add c
    rst $18
    ld b, d
    cp l
    ldh [$82], a
    ld c, b
    jp hl


    inc sp
    ld d, h
    add l
    or h
    dec d
    db $e4
    rla
    cp $57

Call_013_54a7:
    ld sp, hl
    ld d, d
    inc a
    ld d, h
    inc de
    ld a, [hl-]
    db $fc
    ld a, [de]
    ld a, [hl]
    dec b
    or b
    ld a, [$2c98]
    dec l
    ld b, e
    ld a, [$4e42]
    dec hl
    ld d, a
    ld h, h

Jump_013_54bd:
    ld a, [hl-]
    rrca
    ld b, d
    ld [$aa1a], sp
    adc d
    ld e, b
    db $e3
    ld [hl], h
    dec de
    ei
    ldh a, [$ec]
    inc d
    inc d
    and l
    ld a, a
    ld d, b
    ld b, [hl]
    scf
    and c
    ld d, b
    ld d, b
    ld d, b
    push de
    and b
    push af
    ld d, a
    cp d
    rlca
    cp l
    ld h, e
    add d
    pop de
    and [hl]
    add c
    ld c, b
    ld b, d
    add c
    ld l, d
    add d
    cp a
    adc [hl]
    add a
    ret z

    ld b, e
    ld d, h
    cpl
    ld sp, hl
    ld [hl], b
    sub e
    or l
    rst $28
    ld b, [hl]
    xor b
    ld h, b
    xor d
    xor b
    ld l, d
    adc [hl]
    and a
    xor d
    ld l, c
    ld d, b
    sub a
    call nc, $a584
    dec sp
    ld a, [c]
    cp $82
    xor a
    db $eb
    push de
    ld a, [hl-]
    rst $28
    or l
    ld [hl], h
    inc d
    sbc $8f
    ld b, $a3
    reti


    cp a
    adc a
    ld a, [bc]
    ld a, [hl]
    ld hl, $a59e
    ld de, $9e91
    ld a, e
    ld d, d
    add d
    add hl, hl
    and $b5
    jr z, jr_013_556d

    jp z, $cf78

    db $e3
    inc c
    ld [de], a
    ld b, [hl]
    ld e, $78
    sbc a
    xor $90
    add d
    ld a, [hl-]
    call nc, $9e42
    rlca
    ld a, a
    ld [hl], c
    ld l, $1f
    db $fc
    dec bc
    add sp, -$59
    ld a, [de]
    ld b, h
    and b
    xor d
    inc de
    ld a, [$f2b6]
    rst $38
    add a
    ld e, [hl]
    ld [hl], b
    call nz, Call_000_2dc1
    ld a, [hl]
    and e
    ld a, [hl]
    db $d3
    rst $38
    cp $0f
    add d
    ld l, l
    db $10
    cp a
    db $e3
    ld l, e
    ld a, h
    rst $38
    add sp, -$21
    rst $38
    sbc $1c
    ld l, e
    ld de, $aeff
    ld [hl], $1b
    ld b, d
    jp nc, $b590

    adc l

jr_013_556d:
    jr c, jr_013_55d6

    dec c
    rst $38
    push af
    ld c, b
    ld e, e
    db $10
    cp $47
    ld a, [$6d5a]
    inc de
    ld a, a
    ret nz

    adc l
    inc d
    rst $38
    sub c
    rst $38
    sub l
    ld b, d
    and [hl]
    sub d
    sub b

Jump_013_5587:
    and d
    add $2f
    db $fc
    cpl
    pop af
    sub h
    and [hl]
    db $f4
    ld c, [hl]
    and [hl]
    rla
    db $fc
    scf
    call nz, $faca
    ld b, d
    ld [hl], e
    ld a, [hl-]
    ld c, $be
    and [hl]
    dec [hl]
    ld d, h
    ld c, h
    ld b, [hl]
    ld [hl], d
    ld e, a
    rst $38
    ld d, d
    xor d
    ld [$08a6], sp
    call nz, $0aa7
    ld c, l
    ld a, a
    rst $38
    rst $38
    ld a, [$094a]
    add h
    ld [hl], h
    ld a, $df
    rst $38
    ld d, l
    cp $97
    dec e
    rst $10
    ret nz

    xor l
    dec b
    ld d, c
    ld sp, $46e0
    inc d
    dec d
    add a
    rst $20
    sbc b
    ret


    jr z, jr_013_5641

    ld h, a
    dec e
    ld c, c
    ld l, [hl]
    db $10
    push bc
    call nz, $84c0

jr_013_55d6:
    ld a, b
    dec d
    ld b, h
    daa
    xor b
    sbc [hl]
    call z, $a078
    ld [hl], a
    cp a
    ld c, c
    ld c, a
    ld c, l
    rst $30
    and e
    ret nc

    ld d, h

Call_013_55e8:
    ld h, [hl]
    rst $08
    ld a, $a0
    ld b, e
    xor e
    db $f4
    pop af
    rst $10
    rst $20
    ld [$1a55], sp
    dec h
    ld d, e
    or l
    ld a, d
    ld b, e
    adc c
    ld [$2215], a
    ld b, d
    adc [hl]
    dec [hl]
    rst $38
    ei
    jp $9708


    ld sp, $60f1
    ld d, e
    add l
    add sp, -$46
    adc e
    ld a, b
    ld d, d
    rla
    add c
    sbc $85
    ld d, h
    ret


    db $e3
    ld c, a
    ld d, a
    ldh [rSVBK], a
    rst $18
    and l
    ldh [$7d], a
    and d
    ld h, l
    add hl, hl
    ld c, h
    dec de
    call nc, Call_013_577d
    sbc [hl]
    rst $10
    add sp, $14
    dec d
    ld hl, $4827
    ld d, d
    sub l
    ld d, l
    rst $28
    rlca
    xor e
    ld a, a
    xor l
    ld e, e
    xor a
    sub d
    xor d
    ld b, d
    dec b
    ld hl, $85fe
    ld [c], a

jr_013_5641:
    inc d
    adc l
    add d
    ld a, b
    jr nz, jr_013_5689

    ld c, d
    ld b, a
    add d
    db $d3
    ld a, [bc]
    call c, Call_000_15a4
    ld c, $46
    ret z

    ld b, d
    xor c
    xor l
    ld a, [bc]
    jr jr_013_56c0

    dec h
    dec bc
    rst $18
    ld a, b
    add [hl]
    ld b, l
    sub [hl]
    ld h, h
    ld h, h
    adc b
    ld [hl+], a
    xor a
    ld a, [bc]
    ld a, [de]
    ld [hl-], a
    add [hl]
    ld a, [bc]
    xor a
    jp nz, $8478

    ld [hl-], a
    jr nz, jr_013_56b9

    jp nc, $156e

    inc [hl]
    ld d, b
    sub l
    or [hl]
    ld hl, sp+$57
    pop hl
    ld e, [hl]
    add hl, bc
    ld b, [hl]
    jp nc, $d9d4

    ld d, a
    call nc, $a0a7
    ld e, a
    and d
    db $ed
    ld l, l
    ld b, l

jr_013_5689:
    ld c, [hl]
    ld a, [bc]
    add [hl]
    add hl, hl
    ld b, c
    ld [$af35], a
    ei
    ld c, [hl]

jr_013_5693:
    cp $a3
    adc d
    and e
    cp d
    db $dd
    db $e3
    call nc, $f8a3
    ld c, $7f
    inc e
    add hl, hl
    jp hl


    xor l
    ld e, $9b
    ld [de], a
    add d
    add hl, bc
    push hl
    xor h
    ld c, d
    rst $38
    dec h
    call c, $2172
    inc d
    xor e
    ld b, l
    ccf
    rst $30
    ld sp, $7854
    rst $08

jr_013_56b9:
    cp $ce
    ld d, d
    ld [hl], d
    ld h, $f2
    cpl

jr_013_56c0:
    rst $38
    pop hl
    db $10
    sub e
    jp nz, $e6bf

    add hl, hl
    sub h
    and b
    sub b
    or l

jr_013_56cc:
    db $fc
    jr z, jr_013_5693

    and d
    adc l
    and $69
    ld l, b
    ld c, d

jr_013_56d5:
    ld c, d
    pop bc
    inc d
    rst $28
    ret nc

    call nz, Call_000_2e50
    ld b, l
    ld b, h
    and l
    ld l, l
    ld b, e
    inc de
    dec d
    ld c, $e0
    rst $30
    jp hl


    db $76
    inc c
    ld c, [hl]
    ld e, l
    or h
    ld d, h
    jr z, jr_013_56d5

    rst $18
    xor $e1
    ld c, b
    rst $18
    ld h, d
    sbc c
    and c
    ld d, c
    jr nc, jr_013_56cc

    ld d, d
    ld c, l
    rst $38
    call nz, $d9cd
    rst $00
    xor c
    add hl, bc
    sub h
    ld c, [hl]
    scf
    add d
    ld d, h
    db $e4
    ld b, [hl]
    sub c
    ld a, h
    ld b, h
    ld b, d
    ld h, c
    sub l
    add h
    ld h, a
    dec de
    ld c, c
    ld de, $5282
    ld de, $429a
    ld c, h
    ld [hl], l
    and a
    inc [hl]
    ld [$d8b1], sp
    sub h
    sbc [hl]
    and d
    ld sp, $72fc
    ld [hl], a
    cp a
    scf
    ld l, e
    ld c, a
    ld c, [hl]
    ld h, $8f
    ld c, c
    ret z

jr_013_5732:
    ld d, e
    db $d3
    sub a
    adc h
    sub l
    ld hl, sp-$10
    reti


    ld sp, $ea55
    add d
    sub h
    db $ec
    ld e, d
    inc sp
    xor c
    jp nc, Jump_000_2a2c

    sub l
    ld d, a
    db $f4
    sub l
    ld c, e
    ld a, [hl]
    xor h
    adc b
    sub [hl]
    adc b
    xor a
    cp b
    ld e, [hl]
    xor d
    ld [$7095], sp
    ld b, d
    ld h, $88
    ld h, d
    ld a, [hl+]
    dec d
    and d
    ld a, a
    add d
    sub e
    ld d, a
    and c
    ld b, a
    or h
    ld d, $88
    ld e, h
    dec e
    ld b, l
    ld h, e
    ld a, [de]
    ld d, l
    ld d, h
    pop bc
    ld e, h
    ld d, b
    cp h
    jp z, $bd51

    ld b, $8c
    ld [$2eaa], a
    xor d
    adc c
    adc h

Call_013_577d:
    jr nc, jr_013_57f7

    ld h, h
    dec l
    ld l, b
    ldh a, [$62]
    sub [hl]
    jr jr_013_57a3

    dec hl
    ret nc

    rst $18
    ld d, l
    ld d, l
    ld d, l
    ld d, a
    ei
    ld d, l
    ld l, $49
    and h
    rra
    ld hl, sp+$15
    ld sp, hl
    ld e, d
    xor d
    xor d
    xor d
    cp [hl]
    xor d
    ld b, c
    jr nc, jr_013_5732

    xor b
    jr c, @-$65

jr_013_57a3:
    rst $10
    rst $28
    rst $38
    xor a
    push de
    ld d, h
    dec a
    ld [$95d2], sp
    adc l
    xor e
    push af
    ld a, [$aa22]
    and c
    and a

jr_013_57b5:
    dec sp
    ld a, [de]
    pop de
    and e
    adc d
    adc $c8
    sbc d
    add hl, sp
    add sp, -$16
    ld [hl], d
    inc d
    db $f4
    push hl
    db $e3
    ld sp, hl
    or d
    ld a, [hl]
    ld [hl], d
    sbc [hl]
    jp nc, $cf7a

    rra
    inc b
    add d
    ld sp, $26e2
    ld c, b
    and h
    and d
    sbc [hl]
    ld [bc], a
    pop af
    adc d
    ld c, d
    xor e
    and h
    inc h
    and h
    ld c, c
    jr z, jr_013_5808

    adc a
    pop af
    ld c, c
    ld c, a
    and e
    ld a, d
    ld l, [hl]
    and b

Jump_013_57ea:
    add h
    ld c, h
    ld b, e
    cp $44
    jr z, jr_013_57b5

    push bc
    ld sp, $5769
    ei
    inc c

jr_013_57f7:
    ld [$fcbf], sp
    add h
    ld de, $4650
    adc b
    call nc, Call_013_7497
    inc c
    ld b, h
    rst $18
    ld hl, sp+$70
    and b

jr_013_5808:
    add d
    jr nc, jr_013_5852

    adc c
    ld a, a
    or [hl]
    add e
    ld hl, sp+$7a
    ld b, h
    ld [hl], d
    ld a, [hl-]
    ld l, c
    ei
    cpl
    cp $e5
    pop bc
    inc b
    sbc e
    ld a, [hl-]
    db $e4
    and [hl]
    scf
    db $eb
    ld [hl], b
    call nz, $6a49
    sbc h
    ccf
    ld hl, sp+$26
    ld d, a
    add sp, -$2f
    ld [hl], c
    rla
    ld [$23a8], a
    ld [hl], h
    ld b, d
    dec d
    rst $00
    add a
    ld d, b
    ld b, a
    ld [bc], a
    rst $00
    ld [hl], d
    ld [hl], h
    jp z, $a777

    xor h
    pop af
    db $fd
    ld c, b
    ld [hl], a
    cp a
    sub e
    call nc, Call_013_55e8
    ld hl, $ff57
    db $fd
    ld c, d
    ld d, l
    or e
    sbc c
    cp e

jr_013_5852:
    xor $82
    and e
    dec de
    and [hl]
    adc [hl]
    and [hl]
    add hl, bc
    db $eb
    cp a
    push de
    db $fd
    dec b
    rst $20
    add hl, sp
    push de
    ld d, h
    add l
    ld [hl+], a
    cp a
    adc e
    and d
    rra
    ld [hl-], a
    adc e
    ld l, d
    and e
    add hl, sp
    ld a, [bc]
    ld a, [bc]
    sub d
    ld [hl+], a
    ld hl, $1582
    ld d, d
    ld [hl+], a
    sbc b
    pop de
    ld l, $09
    ld d, a
    adc b
    ld e, d
    ld hl, $98a8
    inc sp
    ld a, d
    ld a, b
    add hl, hl
    jr nc, jr_013_58dd

    add c
    dec l
    adc h
    and e
    ld [$b1cd], sp
    and a
    add c
    ld l, [hl]
    ld l, b
    ld [de], a
    ld h, e

Jump_013_5894:
    ld e, d
    add hl, hl
    inc [hl]
    rst $08
    ld l, $34
    sbc h
    ld d, a
    db $fd
    ld c, h
    ld [de], a
    ld h, e
    ld l, b
    reti


    ld l, l
    dec b
    add d
    ld [$52ba], sp
    ld hl, $8693
    ld c, l
    ld h, e
    dec d
    dec h
    ld b, c
    ld h, l
    add [hl]
    ld c, [hl]
    add hl, de
    ld d, e
    add c
    add a
    rst $28
    ld a, [c]
    ld h, $14
    ld a, [hl-]
    xor d
    sub e
    ld c, d
    xor d
    xor d
    xor b
    ld [hl+], a
    jr z, @+$57

    inc d
    inc [hl]
    ld h, b
    cp l
    inc b
    sbc b
    add sp, -$43
    ld l, l
    jr jr_013_58f0

    and l
    ld d, l
    ld b, e
    rst $38
    dec h
    ld a, [hl-]
    xor e
    db $ed
    ld a, a
    ld [$b61a], a
    db $fc

jr_013_58dd:
    pop af
    ld l, d
    ld [hl], $ad
    rla
    dec a
    ld e, d
    ld a, [bc]
    ccf
    ld h, c
    sbc a
    call Call_013_6909
    ld de, $8271
    ld c, d
    ld [hl], e

jr_013_58f0:
    and d
    add [hl]
    sbc h
    adc e
    pop hl
    sbc h
    xor $0b
    add sp, $2a
    ld c, [hl]
    and h
    cpl
    ld a, [$9d16]
    ld sp, $aa30
    rra
    rst $38
    add a
    rst $38
    cp $da
    add hl, bc
    pop de
    jr jr_013_5985

    ld e, a
    cp $1f
    push af
    inc c
    ld de, $a2ba
    sbc b
    ld a, [hl+]
    ld b, h
    pop bc
    call nc, $19bf
    and l
    and h
    or b
    ld h, $35
    ld e, h
    or $93
    ld e, a
    dec e
    inc sp
    ld a, [hl]
    add d
    add h
    ld c, d
    ld b, d
    ld d, d
    inc a
    ld l, a
    ld a, [de]
    scf
    db $fd
    db $e4
    and c
    sub c
    sub d
    ldh [$e7], a
    ld [bc], a

Call_013_5939:
    ld h, b
    and c
    add l
    pop de
    ld d, b
    or c
    jr c, jr_013_58f0

    dec a
    sbc h
    adc b
    ld a, a
    or d
    and d
    sub b
    xor d
    cp $18
    dec l
    ld [hl-], a
    ld [hl-], a
    ld [hl], d
    ld d, a
    ld a, [$a409]
    and h
    ld c, e
    ld a, [hl+]
    db $10
    jp hl


    rst $00
    dec bc
    inc b
    ld l, a
    push bc
    ld a, a
    adc e
    rst $38
    xor d
    xor [hl]
    ld [hl], l
    ld h, $28
    sub $45
    rst $38
    rst $38
    rst $38
    sbc l
    ld d, b
    inc h
    cp $5a
    dec [hl]
    ld a, a
    rst $38
    sbc l
    pop af
    dec e
    dec de
    ld d, a
    ld [c], a
    sbc [hl]
    xor h
    ld a, a
    ld c, $80
    ld [hl], a
    cp [hl]
    dec l
    xor c
    dec a
    add hl, sp
    ld d, $8f

jr_013_5985:
    dec h
    cp l
    dec h
    sbc b
    dec d
    ld c, c
    ld [hl], h
    rst $28
    add [hl]
    ld a, [bc]
    ld h, $fe
    dec de
    ld b, d
    sub h
    rst $28
    ld [hl], b
    ld b, c
    ld c, h
    sbc l
    rlca
    add c
    db $f4
    push de
    adc h
    push de
    add hl, de
    ld hl, sp-$36
    db $fc
    dec a
    ld c, $e2
    sub l
    ld a, a

Jump_013_59a8:
    xor l
    dec l
    cp d
    db $d3
    ld a, d
    add e
    ld e, a
    ld a, h
    ld d, $fa
    and d
    add sp, -$3a
    ld c, [hl]
    ld a, [hl-]
    dec c
    ld e, a
    ld a, [$058e]
    ld b, d
    ld b, e
    rrca
    inc [hl]
    ld d, l
    ldh [$5f], a
    xor b
    pop hl
    ld d, b
    adc e
    xor c
    inc b
    cp e
    ld h, d
    ld d, a
    adc h
    ld d, d
    push de
    xor d
    dec l
    ld b, $a4
    add l
    cp l

jr_013_59d5:
    add hl, de
    ld a, [hl+]
    dec l
    ld l, b
    dec d
    xor b
    push de
    add hl, de
    ld c, h
    ld a, h
    ld d, c
    sub b
    ld b, d
    and l
    ld [$56d5], sp
    and b
    xor b
    add [hl]

jr_013_59e9:
    adc h
    db $76
    sbc l
    ld e, h
    inc h
    sbc b
    push bc
    ld l, d
    ld [hl], $8d
    ld d, d
    jr z, jr_013_5a21

    db $d3
    ld c, d
    jr c, jr_013_59d5

    inc sp
    add l
    ld d, b
    ld e, a
    adc l
    inc d
    db $e4
    ld b, l
    jr nc, jr_013_59e9

    ld a, [$63a0]
    ld l, d
    sub h
    sbc $68
    jp Jump_000_21c6


    and d
    ld d, [hl]
    ld [hl], $aa
    ld d, h
    dec d
    ld a, [hl+]
    inc d
    ld a, [de]
    ld a, [hl]
    ld d, $88
    ld l, d
    ld [hl+], a
    ld d, d
    dec h
    ld c, l
    ld [c], a
    ld d, [hl]

jr_013_5a21:
    ld [$29c6], sp
    inc sp
    and h
    sbc d
    and l
    ld c, h
    ld h, b
    ld l, a
    ld c, h
    xor b
    add h
    ccf

jr_013_5a2f:
    push de
    ld c, [hl]
    ld a, [hl+]
    and h
    sbc b
    ld h, b
    and b
    ld d, h
    cp c
    jp nz, $aa88

    push af
    ld d, e
    adc d
    and a
    inc b
    inc d
    ld e, $94
    inc d
    db $10
    ld b, d
    adc h
    ld l, d
    cp a
    ld d, e
    ld a, [hl-]
    ld h, $7e
    inc hl
    cp d
    ld a, [$53a9]
    add d
    cp a
    ld d, d
    xor b
    jp z, $89ff

    ld b, e
    ld a, [$ab39]
    rst $38
    db $d3
    dec hl
    db $f4
    db $10
    ld a, [$173d]
    add hl, de
    dec a
    ld a, [hl+]
    dec bc
    ld c, a
    ld a, [hl+]
    ld a, h
    ld e, e
    inc b
    ld a, d
    sub b
    or a
    ld e, $4b
    add hl, sp
    ld d, e
    ld de, $8f27
    dec c
    ld [hl], c
    ld d, b
    ld b, d
    db $e4
    inc hl
    dec e
    ld a, [c]
    db $10
    add $9f
    ld de, $6f04
    ld h, $48
    inc h
    ld b, c
    add hl, de
    and d
    pop bc
    adc h
    ld de, $b868
    ld d, b
    ld b, [hl]
    dec c
    ld hl, sp+$27
    ld [de], a
    or [hl]
    add hl, bc
    ld [$186d], sp
    db $fc
    ld d, d
    ld b, d
    add hl, bc
    jp nz, Jump_000_10fe

    xor l
    add hl, de
    xor a
    and $12
    inc c
    sbc d
    jr nz, jr_013_5a2f

    ldh a, [$d1]
    xor d
    rst $38
    pop af
    and [hl]
    push hl
    jp Jump_013_7111


    sub d
    sub h
    push af
    add hl, de
    ld h, c
    ld l, a
    jr c, jr_013_5b1a

    db $e3
    and [hl]
    call Call_013_4613
    adc b
    ld sp, $f955
    ld a, [hl+]
    rla
    sub c
    inc hl
    ld c, b
    ld b, [hl]
    adc d
    inc [hl]
    ld h, l
    ld l, a
    cp $46
    ld a, $f0
    inc hl
    inc de
    jr jr_013_5b06

    inc e
    dec [hl]
    ld e, a
    db $e4
    ld a, e
    pop hl
    ld e, a
    and a
    add e
    dec bc
    rst $38
    sub c
    ld b, c
    ld [bc], a
    rst $10
    dec de
    xor c
    rst $00
    ld [hl], d
    rra
    sub d
    and c
    ld d, $c4
    and [hl]
    ld [hl], h
    and a
    inc bc

jr_013_5af5:
    ld a, a
    ld [bc], a
    ld h, d
    and c
    db $10
    or b
    daa
    dec b
    db $10
    add d
    ld d, l
    call Call_000_1054
    xor h
    ld c, a
    rla

jr_013_5b06:
    jr z, @-$2e

    add hl, hl
    or h
    sub c
    ld a, [de]
    ld sp, $692e
    ld b, [hl]
    inc d
    ld a, [bc]
    ld h, c
    inc bc
    add hl, sp
    xor d
    ld c, $d0
    ld e, b
    xor c

jr_013_5b1a:
    rst $00
    ld a, c

jr_013_5b1c:
    jr nc, jr_013_5af5

    ld [bc], a
    add hl, bc
    adc l
    jp hl


    adc l
    adc d
    sbc e
    jp hl


    ld [de], a
    db $10
    jp $2268


    adc l
    db $fc
    ld l, e
    ld c, $09
    jp Jump_013_4a04


    rra
    or l
    ld a, a
    pop de
    push bc
    dec b
    add d
    cpl
    add $50
    ld b, b
    adc l
    and b
    adc h
    ld [hl], l
    ld b, l
    ld b, [hl]
    sub d
    jr z, jr_013_5b8e

    and [hl]
    add h
    add h
    ld a, e
    ld de, $00e5
    ld [hl], a
    cp a

Call_013_5b50:
    ld c, $55
    ld d, l
    ld d, l
    ld c, a
    dec c
    ld e, e
    rst $38
    xor d
    xor d
    xor d
    cp a
    push de
    ld a, [hl-]
    sbc b
    ld a, [de]
    add hl, sp
    ld [$4efd], a
    ld [hl], $06
    inc a
    dec b
    add hl, sp
    ld [hl], e
    dec [hl]
    dec sp
    sub l
    ld d, h
    cp c
    add hl, bc
    jr nc, jr_013_5b1c

    db $f4
    add sp, $61
    ld h, h
    dec a
    push af
    add hl, bc
    ld h, l
    ld a, [hl]
    ld a, b
    sbc a
    db $d3
    adc c
    adc b
    ret z

    or h
    adc e

jr_013_5b83:
    pop de
    xor d
    db $fd
    ld b, [hl]
    rst $18
    ld [c], a
    rst $18
    or $a3
    inc e
    sbc e

jr_013_5b8e:
    ld a, [hl+]
    adc h
    jr nc, jr_013_5bfc

    adc c
    ld a, a
    db $fd
    add l
    inc [hl]
    adc c
    ld [hl], d
    ld d, b
    ld d, c
    ld d, d
    db $10
    ei
    ld b, l
    ldh [rSTAT], a
    ld d, l
    ld l, $33
    ld a, b
    and a
    sbc $fb
    jp nc, $23de

    ld a, h
    ld [de], a
    ld d, [hl]
    ld [hl+], a
    ld c, b
    sbc e
    ld d, [hl]
    dec de
    add [hl]
    ld h, $bb
    pop bc
    and d
    add hl, de
    xor c
    rst $38
    adc h

jr_013_5bbc:
    ld h, h
    cp d
    ld b, $36
    sub b
    call c, $8e59
    ld e, d
    ld d, l
    sbc b
    add [hl]
    xor d
    and l
    ld d, h
    jr nz, jr_013_5b83

    ld h, e
    or d
    ld a, [hl+]
    dec b
    ld d, h
    jp nz, Jump_000_18a8

    db $ec
    ld h, h
    and [hl]
    xor e
    db $e3
    add hl, hl
    push hl
    ld c, [hl]
    sub [hl]
    adc h
    db $10
    cp a
    call nc, Call_000_1aaa
    sbc a
    push hl
    add hl, sp
    sbc e
    db $fd
    ld a, [bc]
    ld a, e
    xor $9b
    ld c, h
    xor c
    rst $28
    ld d, e
    ld d, a
    ldh a, [$fe]
    push af
    dec b
    inc b
    adc l
    and a
    push hl
    jr nc, @+$53

jr_013_5bfc:
    sub l
    inc sp
    ld d, l
    ld b, e
    xor $41
    ld [hl], a
    ldh a, [$8b]
    xor e
    ld sp, hl
    dec b
    dec h
    add hl, de
    ld [hl-], a
    cp a
    rst $38
    ld a, d
    ld a, d
    jr c, jr_013_5bbc

    jp nc, $a312

    ld a, [hl-]
    xor d
    adc c
    ld d, l
    ld d, h
    pop hl
    xor a
    bit 1, [hl]
    ld a, d
    xor b
    rst $20
    xor d
    and e
    ld a, [c]
    xor c
    ld hl, sp+$6a
    sbc d
    add hl, hl
    ld [c], a
    ld e, d
    ld b, l
    ld a, [de]
    ld d, b
    ld hl, sp+$29
    sub $f1
    push de
    ld b, c
    ld b, a
    inc sp
    rst $00
    xor l
    and [hl]
    ld l, c
    jp c, $f6a6

    sub a

jr_013_5c3d:
    inc c
    ld [de], a
    ld [hl], h
    jr nc, @+$40

    jp z, Jump_013_57ea

    dec d
    inc b
    ld [hl], l
    ld [hl], b
    rst $18
    ei
    rlca
    ld a, [$8a64]
    ld b, h
    ld l, c
    xor [hl]
    ld b, h
    ld h, b
    rst $38
    rst $38
    ld hl, sp+$7c
    ld h, d
    pop af
    adc h
    ld d, l
    ld e, [hl]
    ld b, d
    ld e, a
    ld a, a
    ret z

    ld a, a
    db $fc
    ld b, d
    ld b, h
    ld a, [bc]
    ld sp, $ab6a
    ret


    add hl, bc
    add hl, bc
    jr jr_013_5cc2

    inc d
    dec d
    ld l, d
    inc e
    jr c, jr_013_5cbc

    ld a, c
    ld l, b
    ld b, h
    call nz, $15a1
    inc hl
    ld sp, $3f0a
    dec a
    cp $a4
    ld b, b
    ret nz

    ret z

    ld sp, $1111
    sbc h
    sub e
    jp nz, Jump_013_41c3

    ld d, a
    cp $90
    cp a
    ld sp, $11d1
    ld d, c
    sbc l
    ld de, $53e3
    dec e
    adc h
    ld h, b
    sub b
    sbc d
    rst $00
    ld l, a
    jr jr_013_5cc5

    jr nz, jr_013_5c3d

    ldh a, [$29]
    push de
    add hl, de
    dec a
    adc d
    ld l, e
    ld de, $cac9
    rst $38
    cp $86
    db $db
    ld l, d
    ld [hl], c
    ld b, b
    ldh [$9a], a
    cp a
    rst $38
    cp $c3
    add a
    inc h

jr_013_5cbc:
    ret nc

    add hl, hl
    sbc a
    jp c, $9c09

jr_013_5cc2:
    rst $18
    rst $38
    ld a, [c]

jr_013_5cc5:
    ld b, e
    adc h
    ld h, l
    ld b, b
    and h
    ld b, e
    add hl, sp
    cp h
    xor d
    xor h
    ld a, b
    add hl, de
    ld d, c
    call Call_000_3124
    rst $00
    inc b
    sub d

jr_013_5cd8:
    rst $00
    db $ec
    jr nz, jr_013_5d53

    cp [hl]
    ld hl, $6342
    db $d3
    ld b, d
    jr jr_013_5cd8

    db $dd
    ld [$5ff4], sp
    cp b
    and a
    ld c, a
    dec h
    pop hl
    ld b, l
    ld b, l
    ld b, d
    adc a
    ld [bc], a
    sub b
    ld d, a
    ld hl, $c781
    sub b
    ld d, l
    ld a, [hl-]
    sbc d
    dec hl
    ld l, b
    cpl
    ld e, b
    dec h
    sub l
    ld a, [hl-]
    ld d, l
    ld h, d
    ld a, a
    inc d
    inc de
    dec d
    ld d, a
    adc $55
    ld a, [$1192]
    xor a
    jp c, $feff

    inc hl
    ldh a, [$85]
    dec [hl]
    ld e, [hl]
    adc e
    ld b, c
    add hl, hl
    db $eb
    ld c, c
    ld d, l
    dec b
    db $fc
    inc d
    ld d, e
    daa
    and e
    dec h
    dec l
    sub h
    sub [hl]
    xor d
    add d
    and e
    inc b
    or a
    adc h
    sbc $25
    ld e, h
    adc d
    db $f4
    ld [hl-], a
    rra
    ld b, e
    ld c, c
    ld e, a
    rst $10
    adc h
    sbc $2d
    dec l
    adc b
    and a
    pop af
    or b
    ld a, [hl]
    add l
    ld b, d
    adc h
    sbc $32
    sub d
    ld d, d
    and b
    adc b
    ret nc

    xor c
    and b
    xor d
    ld [hl-], a
    ld a, [hl]
    dec [hl]
    ld c, d
    sub d

jr_013_5d53:
    ld h, h
    cp e
    ld h, e
    add l
    ld c, l
    ld e, b
    add $48
    ld a, a
    inc b
    ld e, a
    sub b
    ld d, l
    ld c, h
    xor l
    ld c, h
    sub l
    ld d, d
    sbc b
    ld l, b
    and l
    ld [hl+], a
    and a
    add hl, bc
    db $d3
    ld a, [hl+]
    push af
    ld [hl-], a
    add l
    ld [hl], h
    add l
    ld a, a
    ld d, b
    sub d
    ld d, $89
    push af
    ld [hl-], a
    xor l
    ld sp, $af61
    ld a, [$2622]
    and d
    ld d, h
    sbc d
    call nc, $92cb
    and e
    or c
    ld [hl], b
    add c
    push af
    and l

Call_013_5d8c:
    ld hl, $0d8f
    push de
    ld b, e
    sub a
    pop bc
    rlca
    ldh [rVBK], a
    dec de
    inc c
    dec hl
    call nc, $3cc9
    dec hl
    add e
    add d
    ld a, [hl]
    adc b
    ld d, h
    sbc d
    inc a
    ld a, [hl+]
    sbc e
    ld l, e
    reti


    ld d, e
    rst $08
    cp l
    ld d, b
    ld d, h
    ld d, e
    rst $08
    xor d
    xor d
    adc a
    ld a, d
    ld a, h
    ld c, d
    jp nc, Jump_013_7b7a

    inc bc
    ld e, $a6
    rst $00
    xor c
    ld a, $5a
    ld a, c
    ld c, b
    cp a
    jp c, $f147

    ldh [rOBP1], a
    ld a, [hl+]
    rst $38
    call $7591
    and a
    ld d, e

jr_013_5dce:
    db $10
    db $db
    rst $38
    db $eb
    ldh a, [$30]
    dec [hl]
    ld b, $73
    ld h, $48
    jr c, @+$01

    pop af
    ld [$0eb5], sp
    ld [hl], c
    xor l
    inc c
    ld b, [hl]
    ld h, b
    add h
    ld e, h
    ld b, l
    ld d, b
    ld a, b
    ld h, [hl]
    ret


    adc e
    add h
    ld d, h
    ld c, h
    ld c, d
    add hl, hl
    add l
    ld b, c
    sbc h
    adc a
    add $1c
    and h
    dec l
    adc l
    ld [de], a
    sub a
    and a
    dec bc
    add $54
    scf
    or h

jr_013_5e02:
    db $10
    ret nc

    jr nz, jr_013_5dce

    and h
    pop af
    and e
    add $32
    ld d, a
    ld [de], a
    sbc b
    ld c, b
    and h
    ld a, [hl+]
    sbc d
    ld [hl], c
    xor h
    sub c
    and h
    ld a, [$ffbf]
    db $ec
    jr jr_013_5e02

    ld c, b
    ld b, [hl]
    reti


    ld d, [hl]
    cp a
    rst $38
    pop hl
    pop hl
    call nz, $e663
    ld sp, $18b3
    rst $18
    pop af
    rra
    adc d
    jr nc, @+$6d

    ld a, [$9b64]
    xor c
    rrca
    ld a, [$feaf]
    ld d, h
    inc d
    dec bc
    ld l, d
    ld h, e
    ld [bc], a
    ld h, a
    inc bc
    rst $10
    rst $38
    ld [hl], b
    ld e, c
    ld [de], a
    ld [$7c44], sp
    dec d
    and a
    inc hl
    dec d
    inc c
    ld [hl], c
    ld a, [hl]
    sub c
    dec b
    and [hl]
    add hl, sp
    ld [c], a
    and c
    dec c
    inc b
    dec c
    ld [bc], a
    xor h
    ld a, b
    ld l, e
    reti


    dec bc
    ld b, c
    dec b
    ld e, $43
    ld c, $10
    ld b, [hl]
    jp nc, Jump_013_5378

    ld [bc], a
    ld d, $96
    xor c
    push hl
    ld d, c
    inc [hl]
    db $10
    ld b, a
    and l
    add hl, sp
    add e
    rra
    ld l, d
    ld [hl], a
    cp h
    ld d, $e5
    dec a
    dec de
    ld b, c
    ld h, b
    ld c, a
    dec a
    inc e
    jr nc, jr_013_5ec4

    adc a
    ld sp, $17c5
    dec c
    ld sp, $d345
    pop bc
    ld b, [hl]
    rst $20

jr_013_5e8e:
    ld b, $05
    dec de
    rra
    ld a, [hl-]
    call nc, Call_013_7e1f
    sub l
    dec bc
    ld a, [hl]
    cp d
    or $4e
    sub a
    jp $8589


jr_013_5ea0:
    ld a, d

jr_013_5ea1:
    and d
    and d
    jr c, jr_013_5e8e

    ld d, b
    add e
    ld d, l
    rst $20
    cp a
    call z, $14f2
    sbc $94

Call_013_5eaf:
    ld h, h
    rla
    ld a, [bc]
    ld [hl], l
    add hl, bc
    ld [hl+], a
    db $d3
    ld a, [bc]
    add d
    adc l
    ld d, l
    ret z

    sub b
    ld h, [hl]
    or h
    ld l, d
    xor c
    ld c, b
    ld d, h
    cp l
    ld d, e

jr_013_5ec4:
    ld l, b
    push bc
    add d
    db $fd
    sub e
    dec b
    ld [hl+], a
    ld d, c
    ld a, b
    jr z, jr_013_5ea0

    ld e, b
    add $08
    daa
    ld h, b
    push af
    add hl, hl
    daa
    xor b
    pop hl
    sub e
    ld [hl], l
    ld h, b
    and a
    cp a
    ld c, c
    ld h, b
    ld h, e
    sub d
    ld [hl-], a
    ld c, d
    add e
    and b
    cp l
    ld [hl], c
    ld l, b
    add sp, $4c
    and d
    ld [hl], l
    dec b
    ld d, [hl]
    ld l, b
    ld h, e
    and c
    adc l
    ld [$0d81], a
    or a
    ret z

    or e
    sbc d
    ld d, h
    push bc
    inc b
    jr @+$69

    ld a, [hl]
    adc b
    ld c, b
    sub l
    add hl, sp
    ld d, e
    inc d
    ld e, a
    rst $28
    and d
    sub h
    sub a
    ld d, h
    sub l
    jr c, jr_013_5ea1

    or [hl]
    ld e, e
    ld [hl], d
    call nc, Call_013_4887
    or l
    or h
    jp c, Jump_013_59a8

    ld d, b
    and [hl]
    add c
    cp $b2
    ld d, h
    jp nz, Jump_000_38ae

    ld [c], a
    ld d, h
    ld h, a
    db $dd
    rlca
    dec b
    ld a, b
    db $d3
    dec c
    db $f4
    db $e4
    ld e, h
    ld [hl-], a
    ld l, b
    cpl
    add sp, -$29
    ld b, c
    ld d, h
    push hl
    or [hl]
    db $fd
    ld [hl], c
    ld e, [hl]
    cp l
    ld c, d
    ld b, c
    ld h, $a3
    or [hl]
    add sp, $10
    ld a, c
    xor l
    xor d
    dec de
    ld b, e
    di
    or c
    ld b, l
    xor l
    sub [hl]
    ld a, [de]
    xor l
    ld [hl+], a
    push de
    dec sp
    ld h, h
    ld d, b
    ld h, [hl]
    ld c, h
    ld l, b
    sbc d
    inc a
    dec b
    jp $8f45


    ld b, d
    inc d
    inc [hl]
    db $e3
    sbc [hl]
    ld [de], a
    ld b, d
    ld a, d
    ld sp, $2912
    rst $20
    and b
    db $ec
    ret z

    ld b, a
    sbc b
    db $e3
    xor $c1
    ld h, $9a
    ld a, b
    ld e, $84
    or b
    ld sp, $c008
    adc l
    sbc l
    ret z

    ld e, e
    ld a, [$e1a2]
    ld e, e
    ld [bc], a
    sbc $75
    call z, $fa2f

Jump_013_5f88:
    ld b, e
    rla
    ld [bc], a
    rra
    rst $20
    ld b, [hl]
    cpl
    rlca
    db $dd
    inc bc
    or [hl]
    ld h, d
    call z, Call_013_6e0c
    jp nc, $a08e

    adc h
    jr jr_013_5fef

    rrca
    pop hl
    and l
    call nz, $c846
    call nz, Call_013_5b50
    ld [$5b93], a
    ld [hl], b
    sbc $af
    ld b, b
    and $d4
    ld h, c
    call z, $c9bb
    ld d, a
    db $e4
    rst $18
    inc e
    jr z, jr_013_600a

    adc h
    ld [de], a
    scf
    pop hl
    ld c, d
    jr c, @+$7b

    ld [hl-], a
    ld [hl], c
    ld e, d
    ld l, e
    add sp, -$04
    and d
    ldh a, [$f0]
    ld [hl], $72
    reti


    add e
    adc a
    rst $38
    rlca
    db $eb
    ld d, b
    rst $08
    sbc h
    adc $65
    rrca
    ld b, b
    adc l
    db $d3
    ld a, b
    pop hl
    rst $20
    cpl
    dec de
    ld [hl], c
    dec de
    ld d, b
    xor [hl]
    ld a, $c9
    bit 0, b
    sbc b
    ld h, c
    sub b
    db $ec
    dec bc
    ld e, a
    add [hl]
    rla

jr_013_5fef:
    or d
    ld [hl], d
    and $3a
    db $eb
    xor a
    inc de
    ld a, [hl]
    ld b, a
    ld a, [hl-]
    ld e, d
    ld l, h
    adc e
    adc d
    add e
    or [hl]
    adc h
    ld e, h
    ld d, e
    ld d, l
    xor b
    inc a
    ld [hl], c
    cp h
    ld d, $5a
    ld a, [de]

jr_013_600a:
    add h
    ld de, $8539
    db $f4
    ld [hl], h
    db $e4
    ld l, b
    ld e, a
    xor b
    ld c, b
    add hl, sp
    sub l
    ret nc

    ret


    call $912c
    rst $38
    ld de, $9769
    cp a
    ld [hl], c
    db $d3
    dec b
    ld [hl], a
    push af
    dec c
    add d
    ld d, l
    add d
    rla
    and a
    ld l, a
    ret nz

    jp nc, Jump_013_4312

    ld a, $45
    jr nc, jr_013_605c

    ld h, l
    adc a
    call c, Call_013_5d8c
    inc h
    reti


    rst $18
    rrca
    jr nc, jr_013_6080

    sbc [hl]
    ld a, l
    adc e
    inc c
    ld a, d
    ld c, h
    jr @+$49

    jr jr_013_60c1

    cp a
    and h
    ld d, e
    sub $6c
    ld d, [hl]
    adc a
    ld hl, $152d
    adc c
    and h
    pop hl
    ld d, e
    ld [hl], l
    xor d
    dec h
    ld [hl+], a

jr_013_605c:
    jr nc, jr_013_60c0

    call nc, $fe55
    ld l, a
    ld d, l
    ld d, a
    xor d
    adc c
    sub e
    inc [hl]
    dec hl
    db $f4
    adc d
    ld a, [hl]
    push af
    dec b
    ld a, [bc]
    daa
    cp h
    adc a
    ld a, [bc]
    sub b
    sub e
    dec de
    sub h
    ld d, h
    inc l
    ccf
    ld a, [bc]
    xor d
    ld sp, $88e0
    ld d, a

jr_013_6080:
    add l
    dec [hl]
    ld l, b
    ld d, l
    ld a, [bc]
    jr nc, jr_013_60e4

    dec l
    ld d, [hl]
    xor d
    adc e
    adc c
    ld b, l

jr_013_608d:
    xor d
    ld hl, $2546
    ld c, c
    rst $10
    daa
    ld d, e
    add d
    ld b, c
    add hl, bc
    sub a
    call nc, $9520
    ld e, a
    db $f4
    sbc b
    pop bc
    ld c, $d5
    ld d, e
    ld a, [bc]
    ld [hl+], a
    ld d, l
    rst $28
    ld a, c
    ld h, b
    ld d, l
    ld d, l
    ld b, c
    jr nc, jr_013_608d

    rst $00
    jp $b44a


Jump_013_60b2:
    adc e
    rst $28
    ld d, e
    ld a, [de]
    sbc $0a
    xor d
    ld d, l
    jp nz, Jump_013_6808

    ld a, [hl+]
    ld l, $f1

jr_013_60c0:
    and h

jr_013_60c1:
    ld a, d
    cp [hl]
    ld [hl+], a
    adc [hl]
    ld a, [de]
    xor d
    pop af
    ld d, e
    add hl, hl
    ld hl, $42d5
    cp l
    inc b
    jp hl


    xor b
    push de
    inc b
    ld l, d
    call nc, $3c8a
    xor b
    jp nz, Jump_013_54bd

    push af
    ld l, d
    ccf
    adc l
    and a
    or $3a
    sub b
    add d

jr_013_60e4:
    ld a, d
    inc l
    cpl
    ld [$499c], a
    call nz, $aea5
    cp a
    db $fc
    ld l, h
    adc h
    ld c, $c2
    and h
    xor e
    sub e
    sbc b
    ld a, a
    db $fc
    add d
    xor d
    ld d, e
    and d
    sub c
    jp nc, $ffaf

    rst $38
    inc c
    ld b, l
    jr nz, @+$01

    jp z, Jump_013_7ec4

    ld b, l
    jp hl


    ld e, c
    rra
    rst $38
    rst $38
    ld e, c
    adc l
    ld a, a
    rst $38
    push de
    rst $38
    ret c

    rst $30
    dec d
    inc b
    ld l, $14
    ld b, h
    ld l, h
    rst $38
    di
    db $fd
    ld e, h
    rst $28
    add h
    ld h, c
    ld a, [hl+]
    ld e, $a7
    dec h
    cp $d2
    ld b, l
    ld [bc], a
    ld b, h
    ld a, [hl+]
    ld d, [hl]
    jr jr_013_61b0

    cp $aa
    ld l, b
    rst $38
    call nz, $a650
    ld d, h
    inc c
    jr nc, jr_013_617d

    ld a, a
    rst $38
    ld a, [$9529]
    ld hl, sp-$2c
    ld sp, $13cd
    push de
    inc de

jr_013_6148:
    sbc c
    ld b, c
    ld a, d
    ld b, h
    db $10
    ld [hl+], a
    xor c
    rst $10
    ld b, [hl]
    rst $10
    rla
    ld e, d
    pop af
    db $e4
    pop de
    add d
    ld b, l
    rst $20
    xor c
    inc bc
    ld b, a
    di
    ld [hl], b
    ld [hl], a
    ccf
    sbc e
    ld d, b
    db $f4
    di
    call nc, $223a
    adc c
    ld d, l
    ld d, l
    scf
    ld c, l
    db $db
    sbc l
    ld c, h
    ccf
    ld a, [bc]
    xor d
    xor c
    ld d, a
    xor c
    ld [hl], h
    ld l, d
    ld b, a
    jp nc, $1752

    ld d, b

jr_013_617d:
    jp hl


    ld b, c
    inc [hl]
    add d
    xor b
    ld hl, $3798
    add hl, de
    or $41
    dec b
    add a
    ld hl, sp+$24
    add h
    call Call_000_0445
    ld [de], a
    and b
    sbc d
    ld c, c
    cp b
    dec h
    ldh a, [$98]
    ld [de], a
    ld e, e
    cp a
    rst $38
    rst $28
    add d
    jr jr_013_61cf

    add hl, bc
    and a
    rrca
    ret c

    ld a, [hl+]
    inc d
    ld a, b
    db $10
    ld [$5506], a
    add c
    ld e, b
    dec d
    ld e, a
    adc e

jr_013_61b0:
    ld [hl], h
    add h
    jr z, jr_013_6148

    ld l, b
    ld h, [hl]
    ld d, d
    db $10
    ld e, d
    cp a
    db $fc
    sbc e
    dec h
    inc hl
    adc c
    ld [hl], b
    ld l, l
    ld c, l
    dec d
    ld b, e
    inc b
    sbc d
    xor e
    rst $38
    add hl, bc
    ld [hl+], a
    dec d
    jr jr_013_623d

    add e
    rrca

jr_013_61cf:
    or a
    rst $38

jr_013_61d1:
    reti


    ld e, d
    sbc a
    rst $38
    cp $18
    sbc b
    ld h, l
    cp $08
    ld l, h
    ld l, l
    dec sp
    and d
    ld [hl+], a
    xor e
    db $76
    cp $29
    ld c, [hl]
    and h
    db $10
    push bc
    adc [hl]
    ld l, b
    ld [de], a
    ccf
    rst $38
    xor d
    ld d, l
    ld d, l
    ld e, d
    xor [hl]
    ld a, b
    rst $20
    add e
    ldh a, [rHDMA4]
    ld h, c
    ld l, d
    xor d
    and e
    rst $00
    xor e
    ld a, [$a73f]
    ld h, a
    di
    ld h, d
    ld de, $46ea
    adc c
    call Call_013_708a
    and [hl]
    ret


    ld d, d
    ld e, d
    ld a, [bc]
    ld c, l
    cp d
    inc c
    ld h, d
    sub c
    ld b, h
    and h
    inc h
    ld c, d
    xor e
    sub c
    ld sp, hl
    jr jr_013_6261

    ld a, $a4
    and h
    or h
    ld b, h
    ld h, e
    dec de
    cp $8e
    ld c, a
    add h
    ld c, l
    adc d
    sbc e
    call nz, $aa20
    xor e
    rst $38
    ld sp, hl
    adc l

Call_013_6232:
    ld c, l
    ld h, e
    ld h, c
    ld b, l
    cp b
    jr nz, jr_013_61d1

    ld d, h
    dec e
    ld d, h
    ld c, l

jr_013_623d:
    ld a, [de]
    ret


    adc h
    ld b, a
    ei
    add $0f
    jp hl


    ret nz

    sub c
    ld d, $82
    or c
    ld e, a
    cp $5c
    rla
    rst $38
    cp $aa
    and $29
    ld d, h
    add hl, hl
    ld l, d
    ld e, e
    pop de
    cp a
    ld hl, sp+$39
    db $10
    ld [hl-], a
    ld [$6054], sp
    cp h

jr_013_6261:
    add d
    pop de
    add d
    xor d
    xor c
    ld e, $18
    push hl
    ld b, a
    inc l
    ld h, a
    sbc b
    ld h, h
    ld d, l
    sbc l
    ld [hl-], a
    inc l
    ld h, b
    xor d
    ld e, h
    ld h, e
    dec e
    ld [hl], c
    add hl, bc
    ld [hl], h
    ld a, a
    ld l, d
    add b
    ld [hl], a
    cp a
    ld b, a
    ld b, l
    ld d, e
    adc c
    ld d, e
    xor l
    ld a, [hl]
    ld [$2563], a
    ld e, a
    adc [hl]
    and l
    ld a, [$7829]
    sub l
    cp $a8
    rst $20
    ld d, a
    ld a, [$7f05]
    jp c, Jump_013_7a21

    jr nc, jr_013_62de

    ld b, $36
    ld a, [hl]
    and b
    ld e, e
    ld [$5721], a
    ld [$ff21], a
    ei
    db $e3
    dec b
    ld b, c
    ld d, b
    ld d, c
    ld a, l
    rra
    rst $38
    jp nz, $68a8

    rra
    adc [hl]
    ld b, $16
    xor d
    rla
    or a
    xor l
    ld c, l
    ld l, d
    jr c, jr_013_6317

    ld e, b
    dec d
    ld e, l
    rst $10
    ld a, d
    add [hl]
    xor d
    cp a
    db $eb
    inc b
    jp hl


    rst $00

jr_013_62cb:
    add [hl]
    dec b
    adc h
    pop hl
    ld a, d
    ld a, [bc]
    db $d3
    adc l
    ld a, [de]
    xor d
    ld b, d
    ld a, c
    ld [hl], $52
    ld e, [hl]
    scf
    sub h
    ld h, h
    dec d

jr_013_62de:
    ld h, l
    db $76
    push de
    ld b, l
    ld d, a
    db $fd
    cp $b4
    ld [c], a
    sub l
    ld e, a
    pop bc
    rla
    and c
    ld a, d
    ld [hl], $e8
    add sp, -$60
    rst $28
    sub a
    xor l
    ld d, l
    ld c, h
    ld d, h
    dec l
    ld c, [hl]
    rst $20
    ld [$afaa], a
    push af
    ld d, b
    ld c, b
    xor a
    ld c, [hl]
    ld l, e
    call nc, $4d2b
    ld a, [hl+]
    xor e
    jp nc, Jump_013_536f

    sub [hl]
    or h
    ld l, a
    rst $38
    ld a, [$0bd3]
    ld c, d
    xor d
    add hl, sp
    xor l
    ld c, h

Call_013_6317:
jr_013_6317:
    and l
    ld [hl-], a
    or l
    ld d, $18
    rst $20
    xor a
    rst $38
    rst $30
    adc l
    ld l, e
    ld c, d
    adc a
    ld c, d
    ld d, d
    inc de
    push de
    xor b
    cp $1a
    sbc a
    and l
    jr nz, jr_013_62cb

    ld a, [hl+]
    add hl, bc
    ret c

    cp h
    rla
    pop af
    sub d
    ld l, $76
    xor a

jr_013_6339:
    ld b, l
    ld e, b
    ld b, l
    jr nc, jr_013_6383

    and d
    sbc h
    jr z, jr_013_636d

    ld d, b
    ld hl, $45e4
    jr nz, jr_013_6339

    sbc e
    add $ef
    ret nc

    ld hl, $a318
    jp $14fc


    ld c, h
    ld sp, $8282
    add hl, bc
    rra
    ld a, $a2
    jp hl


    inc d
    ld h, b
    db $e3
    inc e
    ld a, [hl-]
    dec bc
    ld b, c
    ld c, d
    ld b, e
    db $10
    add d
    ld a, b
    inc e
    ccf
    ld hl, sp+$5e
    and c
    ld [c], a

jr_013_636d:
    sbc c
    ld a, [hl+]
    adc d

jr_013_6370:
    and a
    scf
    sub $10
    jr c, jr_013_63c6

    ld sp, $029d
    rst $38
    jp hl


    ret nz

    sub b
    adc l
    dec b
    ld b, b
    add a
    add h
    sbc e

jr_013_6383:
    ld e, a
    pop af
    push bc
    inc hl
    inc bc
    rlca
    ld sp, hl
    and d
    ld l, e
    ld l, c
    rst $00
    ld b, h
    ld c, l
    ld c, c
    db $eb
    or b
    ld l, d
    ld h, [hl]
    and [hl]
    add hl, sp
    add hl, bc
    call nc, $a08d
    sbc c
    ld b, e
    ld h, h
    and l
    ld b, a
    ld c, h
    ld [$9d56], sp
    ld [hl], b
    daa
    ld e, l
    ld l, d
    xor d
    adc $9c
    ld c, h
    sbc l
    add hl, bc
    dec [hl]
    ld b, c
    ld b, [hl]
    ret z

    and h
    ld c, c
    pop de
    jr jr_013_63fe

    ld b, h
    ld a, d
    ld [hl], d
    add d
    sbc a
    jp z, $7720

    ccf
    adc h
    sub l
    inc a
    push bc
    ld d, l
    xor d

jr_013_63c6:
    ld [hl+], a
    sub h
    pop af
    ld e, d
    jr c, jr_013_6370

    push de
    ld d, h
    ld e, e
    ld c, l
    inc de
    sbc [hl]
    ld d, l
    ld e, d
    xor b
    sbc d
    inc d
    ret


    ld h, e
    call z, $da62
    and e
    bit 1, c
    ld e, c
    ld d, $d2
    ld de, $bd53
    ld h, d
    ld d, e
    dec c
    ld c, b
    or b
    and c
    push af
    ld c, [hl]
    ld b, l
    and d
    db $d3
    dec h
    inc e
    sbc h
    ld e, b
    adc e
    inc b
    call $336a
    ld c, h
    xor d
    and l
    ld h, l
    adc d

jr_013_63fe:
    ld [hl], b
    adc h
    call nc, $09dd
    ld c, b
    ld d, [hl]
    inc c
    ld e, c
    dec d
    ld l, b
    pop hl
    xor c
    ld c, h
    db $dd
    ld a, [bc]
    or c
    sub [hl]
    adc b
    and l
    ld c, [hl]
    adc d
    ld d, e
    jr jr_013_644f

    adc d
    ld sp, $8e48
    cp c
    ld [hl-], a
    cp [hl]
    inc sp
    ld d, [hl]
    adc [hl]
    call nc, Call_013_4ed2
    sub l
    ld d, h
    reti


    adc l
    ld d, e
    sub l
    and d
    xor d
    and l
    ld e, c
    ld b, c
    ld c, l
    xor c
    ld d, l
    ld c, h
    sub [hl]
    add hl, sp
    ld l, b
    rst $20
    xor d
    ld d, [hl]
    adc a
    db $e3
    add hl, sp
    db $fc

jr_013_643d:
    ld h, b
    and h
    daa
    sub h
    sub e
    ld b, [hl]
    ld d, c
    ldh a, [$e9]
    ld c, b
    add hl, hl
    ld [c], a
    call nz, $b4c6
    ld a, e
    add hl, bc
    sub d

jr_013_644f:
    cp d
    ld a, c
    di
    rst $38
    ld d, d
    add d
    xor d
    ld a, b
    ld sp, $7f30
    cp $3f
    db $db
    ld a, a
    ldh [$a7], a
    ld [hl+], a
    ld h, l
    ld de, $fb7f
    ret nc

    ld a, a
    ld a, h
    ld d, [hl]
    and [hl]
    or c
    xor d
    ld b, e
    rst $38
    pop af
    dec c
    inc bc
    ld [de], a
    or h
    ld l, [hl]
    sbc e
    inc hl
    ld e, a
    db $e3
    sub b
    add d
    xor b
    ld d, c
    call $a01a
    adc d
    ld b, d
    ld de, $e97f
    sub $9a
    ld d, l
    add $0f
    rst $38
    sbc [hl]
    sub a
    db $fd
    dec e
    or c
    push hl
    ld h, $aa
    ld a, c
    pop af
    add l
    inc e
    ld de, $642a
    sbc [hl]
    adc l
    ld de, $c61f
    add b
    ld [hl], a
    cp [hl]
    ld h, l
    db $f4
    db $f4
    sbc $05
    jr c, jr_013_643d

    ld a, [hl-]
    sub l
    db $e4
    ld [hl], a
    ld hl, sp-$3b
    ld b, c
    ld a, d
    add hl, sp
    jp c, Jump_000_1d8d

    dec l
    ld [$13a2], a
    sub c
    adc h
    ld h, b
    add l
    ld b, $4a
    or d
    inc l
    ld e, h
    ld [c], a
    ld e, b
    and l
    xor l
    rst $28
    or a
    ld hl, $9261
    ld a, [hl-]
    scf
    ld l, d
    add hl, hl
    and d
    and d
    ld [$2763], a
    ld c, l
    db $e3
    ld b, $38
    ld d, h
    push bc
    ld hl, sp-$2f
    ld c, h
    di
    dec d
    ld c, c
    ld e, b
    pop bc
    and e
    ld h, [hl]
    add hl, de
    inc c
    jp nz, Jump_013_5894

    dec de
    ld e, b
    push bc
    adc l
    ret c

    cp d
    di
    add hl, hl
    inc b
    reti


    adc [hl]
    inc b
    jp z, Jump_000_299d

    ld h, $09
    adc h
    jr @-$14

    ld b, a
    inc b
    add hl, sp
    inc hl
    and d
    inc d
    or [hl]
    dec sp
    rst $38
    inc b
    ld d, d
    ld h, e
    sub d
    adc [hl]
    ld a, h
    sub l
    add c
    sbc h
    adc d
    ld l, $52

jr_013_6511:
    ld l, d
    inc [hl]
    adc h
    sub l
    ld l, b
    xor b
    pop hl
    ld b, [hl]
    call $a5e4
    ld l, e
    ld [hl-], a
    ld e, d
    and l
    ld sp, $9ab1
    call $5824
    ld l, b
    add a
    push de
    dec c
    ld l, $4b
    ld h, c
    and b
    add e
    ld c, l
    jr z, @-$7a

    xor d
    or c
    ld c, h
    push hl
    dec d
    dec l
    ld a, [de]
    dec [hl]
    ld d, [hl]
    ld d, h
    add h
    and h
    inc de
    jr c, jr_013_6563

    sub [hl]
    cp $32
    ld a, l
    ld l, b
    ld [hl], h
    adc e
    ldh a, [$a3]
    inc h
    add hl, sp
    ld d, l
    db $e3
    ld a, c
    inc sp
    sub c
    ld d, l
    ld d, h
    or a
    adc a
    ld e, $4d
    ld e, $3a
    rst $28
    db $d3
    ld c, c
    ld d, [hl]
    dec b
    ld hl, sp-$10
    ld l, a
    push de
    ld d, l

jr_013_6563:
    ld d, l
    ld e, a
    and e
    ret z

    xor d
    xor d
    xor d
    adc a
    sbc b
    sbc a
    inc [hl]
    ret


    ld [$723c], a
    jr nz, jr_013_6511

    ld a, [hl+]
    dec l
    pop bc
    ld l, d
    add $29
    ld [$ce79], sp
    push bc
    ld l, h
    sub b
    adc h
    ld h, [hl]
    sub c
    ld sp, hl
    ret z

    add $08
    ld d, b
    or [hl]
    sbc b
    inc h
    jr nc, jr_013_6601

    ld [hl], b
    xor l
    ld [de], a
    or h
    ld d, $31
    ld [hl-], a
    dec l
    inc c
    cp [hl]
    sbc h
    inc l
    ld e, e
    ld b, a
    dec bc
    ld d, $fc
    ld de, $5bbc
    inc e
    ld c, h
    ld h, b
    and c
    ld a, [de]
    xor d
    add hl, hl
    ld l, c
    ret nz

    pop de
    ld l, a
    dec de
    or b
    db $db
    jp hl


    ld [hl], h
    and h
    ld a, [$6014]
    rst $20
    inc bc
    dec d
    db $dd
    and $34
    ld d, h

jr_013_65bc:
    ld h, d
    pop af
    pop bc
    sbc b
    ld h, c
    ld d, a
    xor c
    ld a, [bc]
    ld [hl-], a
    ld de, $1d8b
    ld a, c
    ccf
    ld a, [$7828]
    ld sp, hl
    ld a, c
    db $db
    adc l
    ld d, a
    ld e, b
    and b
    sub c
    ld h, l
    and [hl]
    add hl, hl
    and d
    ld h, c
    jr c, jr_013_65bc

    or b
    xor e
    ld h, e
    push hl
    jp nc, Jump_013_6d4a

    ld h, $1c
    dec de
    ld a, [de]
    ld d, c
    sbc [hl]
    add d
    ld [hl], b
    ret


    ld a, $ac
    ld b, d
    sub d
    ret nc

    jp nc, $c198

    and c
    cp c

jr_013_65f6:
    xor h
    cp h
    ld de, $872c
    add h
    add hl, de
    add h
    sub l
    dec c
    rst $10

jr_013_6601:
    sbc h
    ld a, d
    ld b, l
    ret nc

    ld hl, $4a1a
    ld h, c
    dec b
    pop bc
    sbc d
    jr z, jr_013_65f6

    ld a, [hl+]
    call nz, $99bf
    pop de
    sub h
    ld de, $8d9b
    ld de, $3202
    pop af
    pop bc
    inc de
    inc e
    ld de, $87ac
    xor e
    ld h, a
    add h
    and [hl]
    sub $4a
    ld a, b
    sub b
    ld h, [hl]
    or h
    inc [hl]
    dec hl
    ld e, $15
    rlca
    sbc d
    dec l
    rra
    add [hl]
    add b
    ld [hl], a
    cp [hl]
    ld b, c
    ld b, c
    ld c, c
    ld d, l
    ld e, d
    xor d
    and l
    dec sp
    sbc [hl]
    cp h
    ld a, [hl+]
    sub l
    ld d, [hl]
    xor d
    xor d
    ld a, c
    ld c, [hl]
    ld e, d
    xor l
    ld b, a
    ld b, c
    ld l, b
    ld [c], a
    and [hl]
    ld c, [hl]
    ld a, [hl-]
    add c
    dec bc
    ld e, [hl]
    ld a, [hl-]
    ld h, b
    ld c, [hl]
    scf
    xor l
    ld e, b
    db $ec
    add d
    jr c, jr_013_66b2

    rla
    and e
    sub l
    ld d, a
    cp $08
    reti


    ld hl, sp+$28
    inc hl
    sbc d
    jp hl


    ret z

    ld d, d
    sub e
    inc [hl]
    dec h
    ld [$5fe3], sp
    ld [hl], h
    ld d, h
    inc d
    jp nz, $8664

    xor a
    ld d, e
    add l
    ld a, [hl]
    adc c
    ld d, b
    ld e, [hl]
    ld [hl+], a
    add c
    ld a, [hl+]

jr_013_6682:
    ld l, l
    pop de
    or b
    ld d, e
    dec h
    ld a, [$5730]
    adc d
    ld d, e
    ld b, $ee
    sub h
    ld e, $af
    add l
    cp $8c
    rla
    add sp, -$3e
    add [hl]
    dec h
    dec d
    xor e
    cp [hl]
    adc c
    and h
    push bc
    ld e, a
    and e
    daa
    adc h
    ld d, d
    cpl
    jp nz, $3d18

    ld h, $25
    ld a, [$9a8c]
    db $e3
    scf
    ld [hl+], a
    ld d, d
    or a

jr_013_66b2:
    adc h
    ld l, b
    db $dd
    ld h, e
    inc b
    sbc c
    rlca
    xor b
    dec h
    sbc l
    ld c, c
    ld b, c
    rst $18
    ld d, c
    ld d, l
    add hl, sp
    db $e4
    sub [hl]
    sub $c5
    ld d, a
    ld [$f09a], sp
    and a
    sub e
    ld l, c
    ld c, c
    add e
    and $a8
    dec d
    ld h, c
    ld d, e
    dec hl
    ld b, [hl]
    jr c, jr_013_6682

    xor a
    call nc, $8c87
    cpl
    ld c, h
    xor e

jr_013_66df:
    adc [hl]
    xor c
    ld a, a
    ld h, e
    dec hl
    ld d, d
    dec e
    and e
    or d
    cp b
    ld d, $d3
    ld a, [hl+]
    cp $3b
    sbc $26
    add d
    adc a
    ld [hl-], a
    and h
    ld de, $f358
    xor a
    and c
    db $e4
    jr c, @-$0b

    rst $28
    cp l
    adc a
    jp nc, $cae7

    inc h
    add hl, hl
    inc [hl]
    ld e, h
    add hl, bc
    call c, Call_000_1491
    and h
    pop de
    adc h
    ld [$4327], sp
    ld [$d1a8], a
    call $3327
    ld [hl], l
    ld h, a
    ld h, e
    and a
    dec de
    ld [c], a
    sbc l
    db $d3
    inc e
    ld e, a
    rst $00
    ld b, d
    ld l, $ac
    ld de, $83b3
    ld a, d
    ld [hl], e
    rst $08
    rlca
    jp $9914


    add sp, $41
    inc e
    xor d
    ld [$2a5c], a
    ld b, h
    ret


    ld e, [hl]
    ld d, $09
    jp nz, $ffbf

    and h
    ld b, l
    ld d, b
    ld h, l
    ld d, e
    pop hl
    inc h
    jr nz, jr_013_66df

    xor l
    dec d
    ld a, a
    ld d, c
    ld l, [hl]
    add hl, bc
    ld e, a
    cp $fe
    add hl, bc
    dec de
    dec bc
    add l
    ld d, $bd
    add hl, de
    ret nc

    call nz, $e3fe
    ld a, e
    ld a, [c]
    ccf
    ld [bc], a
    ld c, d
    cp l
    ld b, [hl]
    adc a
    add hl, de
    ld a, a
    ld a, [$0afe]
    add sp, $63
    rlca
    db $fc
    ld l, h
    adc $68
    jp $f0f4


    ld e, a
    ld c, $57
    inc e
    dec d
    jr jr_013_67dc

    db $db
    sub b
    db $e3
    call z, $8e0f
    rrca
    xor d
    ld b, d
    add hl, hl
    jp nz, Jump_000_0d95

    ld b, b
    sub c
    jr c, jr_013_67e6

    ld b, l
    sbc $87
    db $ec
    sbc e
    jp z, Jump_000_1344

    rst $38
    ld d, b
    pop de
    ld [de], a
    ld h, c
    ld a, d
    ld c, d
    ld [hl], e
    ld b, c
    inc a
    jr z, jr_013_67e3

    ld sp, $e087
    add h
    ld [hl], l
    ret z

    or e
    ld a, [de]
    and b
    ldh a, [rBGP]
    ld [hl], h
    jr jr_013_67e8

    and [hl]
    or b
    ld b, a
    adc c
    inc b
    rla
    rst $00
    sbc l
    ldh [$a3], a
    jp nc, $307a

    ld d, h
    rst $00
    xor l
    rra
    and [hl]
    nop
    ld [hl], a
    cp [hl]
    pop af
    dec a
    dec [hl]
    ld a, [de]
    or h
    di
    dec d
    dec de
    ld b, l
    ld a, [bc]
    inc a
    sub a
    dec de
    or $88
    ld b, c
    ld c, a
    ld [hl+], a
    ld l, $dc
    db $10
    and l
    inc a
    ld l, c
    rla
    add [hl]
    db $dd
    ld h, b

jr_013_67dc:
    ld c, a
    ld h, $a0
    ld e, l
    ld a, [de]
    add d
    dec de

jr_013_67e3:
    adc b
    ld a, a
    rst $38

jr_013_67e6:
    ld hl, sp-$18

jr_013_67e8:
    ld a, [hl]
    cp h
    xor [hl]
    xor c
    ld [hl+], a
    adc h
    ld l, e
    db $fd
    ld d, h
    ld d, l
    ld sp, $8578
    ld [hl], d
    cp a
    rst $00
    add d
    ld c, e
    add c
    ld h, $ab
    jp nz, Jump_000_26a5

    add l
    ld h, c
    ld c, e
    sub a
    db $db
    ld b, [hl]
    dec l
    ld a, a

Jump_013_6808:
    ld d, h
    add l
    ld [hl+], a
    ld a, l
    dec h
    ld d, $8c
    or h
    jr nz, jr_013_685b

    ld c, d
    or l
    ld a, [bc]
    cp [hl]
    ld b, l
    ld c, c
    xor e
    ld b, [hl]
    ld d, $21
    ld d, l
    rrca
    add l
    ld l, d
    push af
    ld [hl+], a
    cp l
    ld b, [hl]
    db $fd
    call nc, Call_000_1ed2
    ld a, h
    adc e
    db $fc
    add $96
    ld c, b
    xor a
    or l
    ld a, [de]
    cp $2b
    add [hl]
    or b
    ldh a, [$5b]
    sub $04
    jp z, Jump_013_45bd

    ld b, d
    dec b
    ld sp, $22d8
    sub l
    ld e, b
    ld a, [hl+]
    jr @+$31

    db $fd
    ld c, d
    xor [hl]
    ld b, l
    ld l, d
    jr nc, @+$54

    jr nz, jr_013_68ad

    cp h
    rla
    push de
    add c
    jp nc, $d42b

    sub a
    ld d, d
    ld l, b
    pop bc
    sub [hl]

jr_013_685b:
    ld [hl+], a
    and [hl]
    ld [c], a
    jr z, jr_013_6883

    ld c, d
    jp nc, $d36a

jr_013_6864:
    ld c, c
    dec l
    adc h
    add sp, $28
    adc $d2
    rst $28
    adc h
    db $e4
    ld d, b
    ld c, h
    ld e, a
    ld b, d
    adc l
    sub h
    and $a0
    xor a
    ld d, [hl]
    xor c
    xor b
    ld a, [hl+]
    adc h
    sub h
    xor $a5
    ld b, c
    rrca
    dec b
    ld d, h

jr_013_6883:
    ret


    ld d, e
    jp nz, $a3aa

    rst $30
    ld sp, hl
    ld sp, hl
    add d
    inc [hl]
    add hl, de
    and $a0
    add d
    ld b, d
    dec d
    rst $00
    sub d
    pop bc
    ld a, [bc]
    ld e, a
    ldh [$9e], a
    ld a, [hl-]
    ld b, e
    and h
    db $fc
    ld e, $a7
    adc a
    ld [hl], $4b
    ld h, e
    ld e, [hl]
    ld a, c
    jp z, $8daa

    ld c, e
    inc de
    jr @+$3b

jr_013_68ad:
    jp nc, $aaff

    xor d
    ccf
    db $e3
    jr jr_013_6864

    xor [hl]
    adc d
    add hl, hl
    and e
    dec bc
    push de
    ld d, h
    db $10
    ld a, h
    add d
    ld b, d
    ld e, a
    rst $38
    rst $38
    jp hl


    ld de, $2c74
    add h
    xor a
    ei
    ld l, [hl]
    ld [$4648], sp
    ld [hl], l
    ld a, a
    sbc $8c
    db $10
    and d
    or b
    ld e, a
    rst $38
    ld hl, sp+$53
    ld b, b
    adc e
    ld l, e
    add e
    and l
    ld b, e
    db $fd
    jp hl


    db $10
    jp hl


    rrca
    call nc, $e24b
    db $fc
    ld c, a
    rst $08
    cp $a6
    db $10
    ld d, c
    add hl, bc
    jr jr_013_692d

    and h
    jp z, $831d

    sbc c
    rst $10
    rst $38
    add sp, $40
    sub e
    inc b
    ld b, e
    adc $de
    rst $38
    ld a, [$663b]
    push de
    db $fd
    ld [de], a
    sbc b
    xor h
    inc d

Call_013_6909:
    rst $38
    db $d3
    rst $30
    ret nz

    add d
    sub e
    ld [bc], a
    ld h, e
    ld a, [hl]
    ld [c], a
    sbc c
    cp [hl]
    jp nc, $f0af

    and e
    ld a, [hl]
    sub a
    ld [bc], a
    ld c, h
    inc e
    ld hl, sp-$3a
    dec d
    rst $38
    ld [$6244], a
    ld a, [$4272]
    sbc c
    call $adf1
    jp hl


jr_013_692d:
    rst $08
    dec de
    ld c, b
    ld h, $73
    pop af
    cp h
    sbc l
    ld [hl], b
    inc h
    rst $08
    rla
    add hl, de
    daa
    adc b
    add e
    ld c, c
    ld sp, $7fa4
    inc de
    nop
    ld [hl], a
    cp h
    cp e
    call nc, $57f3
    rst $10
    add a
    db $e4
    ldh a, [$d7]
    db $fd
    ld b, l
    add d
    rrca
    ld [$3b0d], a
    sub a
    and d
    rra
    ld b, l
    ld h, d
    ld d, l
    ld b, c
    adc [hl]
    or a
    sub d
    cp d
    or h
    jr jr_013_69c2

    xor b
    add l
    ld c, [hl]
    ld h, l
    db $e3

jr_013_6968:
    sub c
    ld c, e
    ret c

    adc $31
    ld a, a
    ld c, e
    ld a, b
    sub l
    add d
    ret z

    or h
    and l
    ld sp, $4560
    add [hl]
    add e
    adc e
    ld d, b
    cp a
    jp hl


    ld h, h
    inc [hl]
    jp z, $9262

    ld e, b
    ld d, e
    cpl
    rst $18
    ld c, l
    ld e, a
    sub l
    dec b
    ld c, e
    ld c, h
    ldh [rHDMA3], a
    ld c, e
    ld d, c
    ld a, b
    sub a
    ldh a, [$aa]
    add e
    inc b
    jr jr_013_6968

    ld b, a
    cp [hl]
    ld [hl-], a
    add e
    ld c, d
    ld h, d
    ld e, l
    add l
    inc b
    add hl, de
    ld [hl-], a
    ld h, b
    sub c
    ld b, e
    db $d3
    inc d
    jr nz, jr_013_6a1b

    ld b, [hl]
    db $ec
    ld h, e
    add hl, de
    ld [hl], h
    xor b
    adc a
    add sp, -$31
    db $d3
    ld a, [de]
    ld [hl], $46
    ld c, e
    sub c
    ld h, b
    adc l
    ld d, b
    or d
    db $10
    db $ed
    inc sp
    and b

jr_013_69c2:
    sub d
    inc h
    ld d, [hl]
    ld [$2a62], sp
    ld c, d
    adc c
    add d
    ld a, [bc]
    and b
    ld l, a
    ld c, c
    ld d, d
    ld a, b
    adc c
    sub c
    ld d, h
    ld de, $2da5
    ld [hl+], a
    adc h
    ld l, b
    ld d, b
    ld [hl], d
    ld e, e
    jp z, $c59a

    xor l

jr_013_69e1:
    inc b
    cp e
    inc d
    xor b
    jp nz, $aa18

    xor l
    dec h
    dec b
    ld d, d
    inc [hl]
    sbc a
    adc b
    ret z

    ld d, h
    sbc b
    ld h, b
    and d
    jr z, @-$3d

    ld e, a
    and b
    add c
    inc d
    ld [hl+], a
    jp hl


    jp c, Jump_000_0a06

    and l
    ld l, [hl]
    scf
    and d
    xor b
    jp c, $1a69

    ld d, $16
    dec d
    adc c
    ld c, l
    rst $10
    sub h
    jp nc, $a59a

    db $f4
    ccf
    add sp, $1f
    adc [hl]
    jr jr_013_69e1

    jr c, jr_013_6a6e

    ld h, d

jr_013_6a1b:
    jr z, @-$16

    or l
    dec de
    ld c, e
    ld d, d
    sub e
    call nz, Call_013_5eaf
    sub d
    ld h, d
    ld d, e
    ret


    xor d
    xor a
    jp nc, Jump_013_5356

    ld a, [hl-]
    inc a
    dec sp

jr_013_6a31:
    cp $21
    ld c, h
    ld e, $3c
    db $eb
    ld d, l
    ld hl, sp-$0c
    xor d
    adc e
    sbc $5e
    ret nz

    sbc [hl]
    ld l, d
    ld e, $83
    inc c
    add d
    ld a, b
    ld l, b
    ld c, e
    ld hl, $430f
    sub e
    ld l, c
    call c, Call_000_1184
    ld d, h
    ld c, d
    ld c, e
    ret c

    ld e, c
    ret c

    add h
    ld h, a

jr_013_6a58:
    ld c, $2c
    adc h
    ld b, [hl]
    ld de, $83cc
    inc d
    call nc, Call_000_39a6
    ld a, [hl]
    add h
    ld h, h
    sbc c
    ld c, b
    ld b, l
    inc hl
    sub e
    ret z

    and b
    ld a, [c]

jr_013_6a6e:
    sub h
    and b
    sub [hl]
    cp d
    ld b, [hl]
    inc a
    ld e, d
    pop bc
    ld c, $3a
    jr jr_013_6a58

    db $10
    ld h, l
    jp c, $8e53

    ld c, $99
    jp nc, $b6b1

    inc c
    sub h
    sbc b
    ld h, h
    pop bc
    jr c, jr_013_6a31

    or d
    ld [$4cb9], sp
    or [hl]
    jp c, Jump_000_0c0f

    sub [hl]
    call c, Call_000_39b8
    and [hl]
    ld [$8e40], sp
    call $c4c8
    ld d, b
    ret


    db $76
    sub c
    ld l, c
    sub d
    ret z

    jp $1802


    and $a8
    and h
    or h
    ld a, [hl+]
    inc a
    ld b, h
    ld a, $b1
    adc h
    ld de, $0cb2
    call nz, $34d6
    xor $44
    ld h, d
    ldh a, [$aa]
    ld a, [$b2a5]
    adc h
    sub h
    jp nc, Jump_013_4d0c

    and $0c
    db $10
    add hl, hl
    rrca
    ld c, a
    sub c
    ld b, b
    push bc
    ld h, b
    call z, Call_000_378c
    inc bc
    sbc b
    and h
    inc l
    adc d
    ld b, a
    ld hl, $30b5
    and c
    sub l
    inc sp
    ld hl, sp-$57
    and d
    ld a, [de]
    ld b, h
    ld a, [de]
    ld [$90a2], sp
    and e
    dec c
    inc h
    jr nz, @-$6d

    ld [hl], d
    ld l, e
    ld b, c
    jr nz, @-$2c

    ld sp, $4909
    add l
    db $dd
    db $10
    pop bc
    ld b, [hl]
    ld e, e
    jr nc, jr_013_6b44

    ld b, h
    ld a, [hl+]
    cp h
    ld [hl], b
    ld b, l
    ld l, b
    ld hl, $8c49
    and d
    sub e
    sub c
    add h
    ld a, [hl+]
    ld c, h
    ld l, a
    or b
    and d
    sbc c
    ret nc

    ld d, h
    xor d
    jr c, jr_013_6b64

    inc l
    add h
    ld [hl], b
    ld b, h
    ld h, h
    ld h, $79
    add e
    adc h
    ld b, h
    ld [hl], h
    ret nz

    adc d
    ld a, d
    or b
    ld h, c
    xor b
    inc hl
    xor c
    dec bc
    add $c9
    push de
    inc c
    inc de
    ld h, c
    ld d, b
    pop bc
    and [hl]
    ld a, d
    ld a, b
    sbc b
    db $e4
    add $29
    jp hl


    ld [hl+], a
    add a
    ld e, $94
    ld sp, $7760
    cp a
    cp h
    sub [hl]
    sub h
    and [hl]

jr_013_6b44:
    dec h
    ld d, e
    dec h
    ld d, l
    scf
    ld d, l
    xor b
    sbc e
    sub c
    ld b, [hl]
    sbc e
    db $ed
    add hl, hl
    ld [$bdab], a
    ld b, c
    ld e, d
    and d
    push de
    rla
    ld l, d
    dec h
    ld a, [bc]
    cp h
    inc de
    rlca
    sub $86
    ld [$5ac1], sp

jr_013_6b64:
    adc b
    sbc l
    dec l
    add c
    ld h, d
    dec hl
    ld b, d
    sbc [hl]
    jr jr_013_6b90

    inc hl
    inc h
    add l
    ld d, l
    ld d, c
    ret


    ret z

    ld d, b
    ld b, d
    rla
    add c
    ld a, l
    pop hl
    ld a, b
    ld [de], a
    rst $10
    ld a, [$88aa]
    call z, $2254
    ld d, h
    ld l, e
    ld [$455d], sp
    dec l
    ld d, l
    jr c, jr_013_6bae

    ld d, d
    ld h, b
    ld e, d

jr_013_6b90:
    dec b
    ld hl, $a3a1
    ld l, d
    xor d
    sub e
    add hl, de
    jr @+$18

    pop hl
    and b
    cp a
    ld e, b
    adc b
    add [hl]
    sub l
    ld c, h
    call nc, $2585
    cp [hl]
    jp nc, $be94

    ld e, l
    sbc a
    sub l
    ld a, [bc]
    and l

jr_013_6bae:
    ld d, c
    call nc, $4221
    add d
    cp $30
    cp a
    cp $a8
    cp d
    xor a
    push af
    ld b, l
    inc e
    cp b
    ld a, [c]
    ld l, d
    rst $30
    ld hl, sp-$0b

jr_013_6bc3:
    jr z, jr_013_6bc3

    adc h
    sbc a
    sbc $8a
    ld h, b
    rst $00
    ld a, [bc]
    ld c, d
    ld [hl], c
    ld a, [hl+]
    db $fc
    add d
    ld [$42a4], sp
    cp d
    ld e, d
    sbc b
    inc l
    ld [$af22], sp
    rst $38
    rst $38
    cp d
    ld c, h
    ld b, d
    rst $18
    ld a, [bc]
    and h
    ld hl, sp+$28
    ld [hl], $4b
    rst $38
    rst $38
    rst $38
    rst $38
    or c
    db $10
    cp a
    ldh a, [$66]
    rla
    inc a
    ld b, [hl]
    ld c, [hl]
    rra
    rst $38
    rst $38
    push af
    ld d, h
    ld h, d
    ld hl, sp+$4c
    ld sp, $b20f
    sub [hl]
    db $e4
    ld d, a
    ld d, c
    rst $00
    ld a, [hl]
    or d
    add hl, hl
    rla
    add a
    jr jr_013_6c64

    rra
    xor d
    ld [hl], d
    ccf
    and c
    sbc b
    dec sp
    dec d
    sub e
    add a
    rst $38
    rst $38
    ld a, [$93aa]
    inc de
    ld c, a
    and e
    ld d, c
    ld a, $45
    add hl, sp
    scf
    rst $38
    rst $38
    rst $38
    rst $38
    inc h
    ld sp, $d728
    rla
    ld b, [hl]
    inc d
    add h
    db $10
    push de
    rst $38
    rst $38
    rst $30
    rla
    daa
    inc c
    ld c, h
    ld [hl], c
    ld d, l
    ld a, e
    inc b
    ld a, d
    or h
    ld a, a
    ld h, d
    nop
    ld [hl], a
    cp a
    or d
    rra
    push de
    dec a
    rlca
    adc b
    xor e
    call nc, $e8f2
    ld e, d
    ld d, h
    ld l, e
    ld d, e
    rst $00
    and c
    ld c, c
    ld e, d
    ld d, b
    sbc d
    ld d, l
    ld d, [hl]
    xor e
    db $fd
    ld l, d
    ld d, e
    ld l, e
    ld b, d
    ld a, [hl+]
    ld a, [hl]
    and c
    sub d
    ld l, c
    dec h

jr_013_6c64:
    ld [hl+], a
    and l
    ld b, d
    ld c, b
    ld d, h
    sbc d
    db $ec
    or [hl]
    and b
    ld l, c
    inc d
    and h
    and l
    ld d, d
    xor d
    cp $c2
    push de
    ld b, d
    ld d, d
    dec d
    sub h
    db $10
    pop hl
    ld c, b
    ld a, h
    ld [hl+], a
    ld e, d
    cp $55
    ld c, d
    sub b
    ld e, l
    pop bc
    ld [hl+], a
    sbc d
    add [hl]
    ld c, h
    and b
    pop af
    ld b, l
    ld e, l
    xor d
    cp a
    ld d, a
    ld b, d
    ld [hl], a
    adc d
    sub c
    ld l, d
    ld hl, $1f06
    ld d, l
    cp $a3
    ld e, d
    dec h
    add d
    ld l, $fd
    dec bc
    ld b, [hl]
    db $e4
    adc b
    ld [$227a], a
    ld d, [hl]
    cp $26
    ret nc

    ld d, c
    and e
    xor c
    ld b, [hl]
    ld [hl+], a
    scf
    or d
    inc d
    db $ed
    ld h, d
    and e
    add d
    ld hl, sp-$14
    cp c
    ld b, $58
    db $f4
    db $e3
    ld sp, hl
    ld [hl-], a
    ld a, a
    ld h, h
    ld [$e829], a
    cp a
    rst $38
    cp b
    daa
    sub a
    ld a, l
    dec c
    ld e, a
    add sp, $27
    adc a
    ld a, h
    ld c, e

jr_013_6cd3:
    xor e
    rst $18
    cp c
    ld c, l
    db $10
    xor [hl]
    ld b, d
    sbc h
    ccf
    ld de, $475a
    rst $18
    ld h, h
    ld e, a
    sub d
    adc l
    ld e, d
    or b
    ld h, $77
    inc hl
    and h
    ld a, a
    cp $4e
    ld b, a
    add $29
    scf
    db $eb
    ld hl, sp-$5e
    adc $85
    cpl
    dec b
    ld l, a
    ld e, a
    sub c
    inc sp
    sub e
    rst $38
    ld sp, hl
    dec bc
    ld e, b
    ld sp, hl
    ld [$3a48], sp
    ld b, d
    call nz, $953f
    ldh [$c0], a
    rst $18
    ld e, c
    add l
    jr jr_013_6cd3

    ld a, a
    and $96
    ld c, [hl]
    pop de
    ld d, c
    adc $ad
    ld a, [hl]
    inc [hl]
    ld d, d
    ld [hl-], a
    rla
    and a
    ld h, e
    cp $71
    or b
    ld b, a
    ld l, e
    rst $38
    rst $20
    ld d, $44
    db $76
    ld [hl], a
    rst $30
    sbc [hl]
    and h
    ld a, a
    ld b, d
    nop
    ld [hl], a
    cp a
    inc bc
    ld l, d
    ld c, a
    ld b, l
    ld [c], a
    xor d
    ld c, a
    add hl, sp
    ld sp, $4f5d
    dec b
    ld c, h
    daa
    pop bc
    ld b, [hl]
    inc b
    dec hl
    ld c, [hl]
    db $eb
    cp l
    ld c, d
    xor b
    ld l, d

Jump_013_6d4a:
    dec bc
    ld b, [hl]
    adc h
    ld d, l
    ld c, l
    sbc a
    and d
    cpl
    push hl
    jr nc, @-$49

    ld b, l
    inc b
    sub a
    db $ec
    ld l, c
    add hl, hl
    ld c, b
    and h
    jp z, $d27b

    ld l, d
    db $fd
    ld c, c
    ld d, c
    adc e
    sub b
    ld h, b
    and c
    ei
    dec h
    ld b, c
    ld b, c
    ld h, a
    ret nc

    or d
    call nc, $6354
    inc h
    pop bc
    ld c, h
    xor [hl]
    ld b, [hl]
    and b
    ret nc

    and l
    ld h, h
    sub l
    adc l
    xor b
    ld a, l
    ld c, c
    and b
    ld a, a
    ld b, d
    ret nc

    add [hl]
    ld c, c
    pop de
    ld d, h
    sub [hl]
    ld sp, $76a2
    ld a, [hl+]
    ld h, b
    and d
    ld de, $4b91
    adc c
    add [hl]
    add hl, hl
    ld c, b
    ld d, b
    ld b, e

jr_013_6d98:
    jp z, $fb41

    dec b
    adc d
    and e
    jr @+$18

    inc d
    ld d, $86
    ld d, a
    adc b
    xor h
    sbc a
    rst $28
    pop af
    ld l, c
    add hl, sp
    inc hl
    add e
    push de
    sub a
    ld h, a
    call z, $3c69
    ld a, [de]
    xor b
    add $29
    ld c, b
    ld c, a
    dec a
    ld b, c
    ld c, a
    ld c, [hl]
    xor h
    inc d
    sbc b
    ldh [$91], a
    ld d, l
    add hl, sp
    db $ed
    and b
    and l
    ld b, l
    sub e
    ld e, d
    ld h, $93
    sbc d
    add d
    ld d, $83
    inc d
    db $e3
    ld [hl], b
    adc [hl]

jr_013_6dd4:
    ld l, d
    ret c

    ld l, d
    ld a, [c]
    dec e
    ld d, e
    add $b5
    ld a, e
    ret nc

    add a
    dec c
    ld l, d
    ld d, d
    db $ec
    db $eb
    xor e
    ld d, a
    pop af
    ldh [$af], a
    ld d, a
    dec d
    sub l
    adc [hl]
    jp c, $a3a1

    ld a, [bc]
    xor d
    ccf
    jr nc, jr_013_6dd4

    add d
    inc l
    ld a, d
    adc h
    rrca
    ld [bc], a
    sbc [hl]
    ld a, d
    adc d
    di
    xor b
    daa
    add h

jr_013_6e02:
    sbc b
    pop bc
    jr nc, jr_013_6e36

    inc hl
    ld [bc], a
    ld [hl], a
    and c
    ld b, $09

Call_013_6e0c:
    cp h
    adc e
    sbc c
    daa
    inc h
    ld b, e
    inc l
    sbc e
    jr nz, jr_013_6d98

    ld d, e
    ld hl, $9d52
    jr z, jr_013_6e46

    ld e, d
    dec de
    and l
    add hl, sp
    ld [$4968], sp
    inc c
    ld h, c
    sub c
    ld sp, $4130
    inc h
    sbc $8a
    ld b, e
    sub e
    ld b, l
    jr nz, jr_013_6e02

    ld e, c
    ld l, c
    inc c
    dec de
    ld c, b

jr_013_6e36:
    ld a, [c]
    db $eb
    inc de
    rla
    jr z, jr_013_6e78

    db $10
    push bc
    dec h
    ld d, b
    ld c, d
    ld b, h
    add hl, bc
    ld [de], a
    inc d

jr_013_6e45:
    ld d, d

jr_013_6e46:
    sbc d
    add hl, hl
    ld de, $3271
    db $10
    ld d, l
    ld d, d
    ret z

    and e
    ld a, h
    ld sp, $8a94
    ld b, d
    sbc c
    inc hl
    dec h
    inc hl
    ld l, a
    dec c
    ld d, l
    ld [bc], a
    ld a, [bc]
    and d
    sbc h
    add hl, sp
    add h
    ld hl, sp+$2a
    jr jr_013_6e45

    call nz, $d550
    ld d, c
    call nz, $b491
    add d
    ld e, l
    add hl, de
    and a
    ld e, h
    ld l, l
    cpl
    ld sp, $aaaa
    sbc [hl]

jr_013_6e78:
    rrca
    jp z, $856a

    ld d, b
    daa
    add c
    ld e, d
    and [hl]
    sub b
    ld a, a
    add l
    ld e, $04
    add l
    ld a, d
    xor e
    ld [de], a
    rst $38
    and h
    ld c, e
    ld e, [hl]
    ld [hl], l
    ld d, h
    dec bc
    ld b, l
    jr nc, jr_013_6eb9

    ld sp, $0c29
    ld [hl], h
    ld hl, $d063
    cp $1f
    ld a, [c]
    sbc [hl]
    inc e
    ld [$b552], sp
    ld c, [hl]
    ld [de], a
    add h
    ld e, h
    dec de
    and a
    ld d, h
    ld b, d
    dec a
    ld l, c
    ld d, h
    xor d
    or b
    pop de
    rst $18
    inc c
    ld a, [hl]
    add d
    ld [hl], a
    cp a
    sbc e
    sub l

jr_013_6eb9:
    ld c, l
    push de
    inc a
    daa
    ld b, e
    or h
    add a
    jp nc, $8a18

    ld d, e

Jump_013_6ec4:
    pop bc
    adc e
    ld b, e
    sbc l
    adc h
    sub e
    or l
    ld e, c
    dec b
    rrca
    jp nz, $cae3

    sub a
    ld [c], a
    dec [hl]
    ld h, h
    ld [$935a], a
    adc c
    ld d, c
    adc [hl]
    and [hl]
    ld l, $aa
    xor d
    dec d
    xor a

jr_013_6ee1:
    cp a
    add c
    inc c
    push hl
    cp b
    or l
    inc b
    cp e
    ld l, d
    rst $30
    and h
    ld h, e
    sub [hl]
    jr nc, jr_013_6ee1

    ld b, e
    ld c, c
    adc $b4
    jp nz, $af14

    ld h, $e1
    ld l, e
    ld c, h
    ld h, b
    ld c, b
    ld c, [hl]
    ld l, b
    sub h
    jr c, @-$64

    ld a, b
    add hl, hl
    ld d, [hl]
    sub h
    ld a, e
    rst $30
    ld c, [hl]
    jr jr_013_6f2d

    ld de, $ff45
    rla
    xor d
    ld h, $d1
    cp e
    ld a, [c]
    ld h, e
    ld [$c899], sp
    xor d
    add d
    and b
    cp b
    call Call_013_5041
    ld sp, hl
    dec [hl]
    sub e
    adc c
    cp l
    ld d, l
    ld e, d
    adc e
    and b
    jp nz, Jump_000_3341

    sub h
    reti


jr_013_6f2d:
    ld h, $82
    sbc l
    dec h
    ld [hl], h
    ld d, l
    ld b, d
    adc l
    xor d
    and l
    ld d, l
    ld d, e
    dec bc
    rst $30
    ld e, d
    rst $18
    ld h, c
    xor a
    adc a
    ld [hl], $8f
    ld [c], a
    ld c, c
    db $fc
    call c, Call_013_708a
    and a
    add h
    cp [hl]
    adc d
    ld l, b
    ret nc

    ret nz

    sbc [hl]
    rrca
    sbc e
    ld c, h
    ret


    add hl, bc
    db $db
    ld e, a
    inc c
    ld h, c
    inc bc
    ld [bc], a
    xor c
    pop hl
    jp $a014


    add h
    add a
    ld a, [hl+]
    ld [hl], c
    inc h
    ld b, a
    ld a, [de]
    ld c, $4e
    dec c
    rst $38
    and [hl]
    pop af
    or l
    ld a, [bc]
    jp nc, $30f1

    ld b, c
    cp a
    rst $38
    sbc c
    adc $53
    and b
    and l
    db $e4
    ld a, e
    ld b, c
    dec d
    add a
    rst $38
    add [hl]
    ld h, l
    rlca
    add e
    ld d, a
    rst $28
    db $e4
    ld d, [hl]
    ld c, a
    sub c
    inc h
    ld [hl], a
    rst $38
    pop hl
    ld b, [hl]
    db $10
    cp $45
    ld a, l
    inc c
    rrca
    add h
    adc a
    sub a
    ld d, e
    rst $38
    pop hl
    sbc e
    ld a, d
    ld b, a
    push bc
    ld b, l
    push af
    inc [hl]
    ld c, l
    rst $38
    cp $19
    sub d
    ld b, l
    add sp, -$10
    ld b, e
    ld a, [de]
    ld sp, hl
    ld a, a
    rst $38
    rst $08
    add $29
    rla
    ld [bc], a
    add hl, bc
    push bc
    ld d, c
    dec bc
    ld d, a
    di
    ld a, c
    call nz, $c9c6
    ld c, d
    rst $38
    pop hl
    xor e
    ld [hl], b
    add $90
    ld hl, $7004
    rst $38
    rst $38
    ld c, e
    db $fc
    add hl, hl
    rst $08
    rla
    dec de
    call nz, $8451
    ld a, a

jr_013_6fd4:
    ld a, [hl+]
    nop
    ld [hl], a
    cp a
    adc d
    sub e
    pop bc
    ld a, l
    add hl, sp
    ld a, [hl+]
    ld d, e
    xor c
    push hl
    call nc, $215e
    ld c, d
    ld [$e915], a
    ld c, [hl]
    ld d, l
    ld a, c
    ld d, d
    dec de
    ld a, [$a285]
    ld [hl], h
    ld h, l
    db $ed
    add hl, sp
    sub l
    rst $18
    adc b
    ld e, [hl]
    dec c
    jr nc, jr_013_706b

    ld d, b
    ld d, b
    db $fd
    scf
    xor b
    dec h
    ld [hl], d
    rra
    xor b
    adc b
    cp b
    adc e
    sub e
    ld [hl], l
    ld b, l
    ld h, b
    sbc e
    ret nc

    or b
    ld a, d
    ld b, [hl]
    ld l, $16
    add e
    ld b, l
    ld l, b
    add l
    ld l, b
    adc e
    db $fd
    rrca
    ld h, d
    ld h, b
    or $1f
    ld a, [hl+]
    ld e, c
    ld l, b
    ld [hl], h
    ld l, d
    adc h
    ld a, a
    ld a, [$bf8c]
    add sp, -$32
    xor h
    ld e, b
    ldh [$fe], a
    ld h, e
    ld a, [hl-]
    db $e3
    add e
    db $f4
    or l
    ld d, e
    dec e
    adc l
    and e
    adc [hl]
    adc e
    adc c
    sub l
    inc c
    ld h, h
    ldh [rDMA], a
    and l
    dec h
    ld sp, $1552

jr_013_7045:
    ld d, [hl]

Call_013_7046:
    and d
    db $d3
    add d
    cp l
    jr jr_013_706a

    jr nc, jr_013_6fd4

    ld c, a
    ld d, $ee
    ld c, h
    ld h, d
    xor h
    ldh [$4e], a
    ld [hl], $81
    ld sp, $4165
    adc [hl]
    add hl, hl
    jr c, jr_013_7075

    inc b
    pop bc
    ld a, [de]
    xor c
    ld d, h
    ld [c], a
    ld c, l
    sub h
    call Call_000_260a

jr_013_706a:
    push de

jr_013_706b:
    sub h
    sub l
    xor d
    ld c, [hl]
    dec d
    ld [hl+], a
    cpl
    ld c, h
    xor d
    rst $20

jr_013_7075:
    ld e, b
    or h
    sbc d
    ld c, l
    sub d
    ld d, [hl]
    xor a
    adc h
    ld [$57fe], a
    adc h
    jr c, jr_013_7045

    add l
    dec sp
    xor d
    add d
    ld d, d
    sbc b
    push bc

Call_013_708a:
    ld d, l
    ld b, l
    inc a
    ld a, [de]
    xor b
    jp z, $8aa8

    ld a, $87
    ld a, a

jr_013_7095:
    dec d
    daa
    add d
    sbc h
    ldh a, [$60]
    sbc l
    adc h
    add hl, hl
    ld e, c
    add hl, bc
    ld a, c
    ld c, [hl]
    rst $20
    ld c, e
    ld h, b
    and h
    ld l, b
    ld h, e
    call nz, Call_013_5939
    ld [de], a
    add e
    inc e
    sub b
    xor d
    sub c
    ld de, $f1b0
    add [hl]
    ld d, h
    dec sp
    daa
    inc b
    ld [hl-], a
    jr c, @+$26

    ld a, h
    ld c, [hl]
    ld d, e
    ld [de], a
    adc $4c
    ld l, a
    or d
    ld a, [de]
    adc h
    ld c, d
    sub c
    sbc b
    db $db
    inc l
    rrca
    ld b, h
    and b
    xor l
    ldh [$d3], a
    ld b, c
    jr @-$02

    ld h, a
    inc l
    dec [hl]
    ld e, b
    add sp, $28
    ld b, d
    ret nc

    ld b, d
    sbc d
    cp [hl]
    add sp, $46
    jr nc, jr_013_7095

    add d
    db $d3
    inc d
    and d

jr_013_70e7:
    xor a
    add $90
    ld h, c
    ld d, b
    ld c, l
    jr @+$4d

    inc h
    and l
    and c
    ld a, [hl]
    ld de, $54c1
    ld h, b
    add h
    inc c
    add e
    inc de
    add hl, de
    inc l
    sbc h
    ld e, d
    ld h, e
    jr z, jr_013_7150

    ld h, d
    xor d
    xor a
    ld a, e
    ld a, [$d271]
    ld b, e
    jp nz, Jump_013_46a1

    dec d
    or h
    dec d
    rst $18

Jump_013_7111:
    rst $20
    dec [hl]
    ld [hl], c
    ld a, [bc]
    ld l, d
    and l
    ld d, l
    ld l, [hl]
    ld [hl], e
    add $70
    ld a, [hl+]
    inc l
    ld l, a
    ld c, c
    call nz, Call_013_51c5
    ld [$5a44], sp
    sbc $a6
    xor c
    ret nz

    sub [hl]
    and [hl]
    sub d
    and e
    ld e, [hl]
    sbc l
    add hl, hl
    sub d
    and [hl]
    or [hl]
    cp a
    jr jr_013_70e7

    and a
    inc e
    ld de, $6914
    dec bc
    ld b, b
    xor l
    ld d, c
    db $10
    ld h, $51
    ldh [$c5], a
    ld h, b
    add [hl]
    add h
    ld h, h
    xor l
    ld c, d
    ld a, b
    ld d, c
    ld de, $60f6

jr_013_7150:
    ld [hl], a
    cp a
    or l
    push de
    ld a, e
    db $f4
    and l
    ld d, e
    ld d, l
    add hl, sp
    ld [$22aa], a
    xor a
    ld [$55b4], a
    ld d, [hl]
    sub b
    adc e
    ld d, a
    db $f4
    jp nz, Jump_013_4abd

    xor b
    jp z, Jump_000_188c

    ld [de], a
    inc e
    add hl, hl
    ld e, b
    ld e, $50
    and d
    dec l
    ld [hl+], a
    adc d
    ld d, l
    ld c, e
    ld [hl], a
    pop bc
    ld hl, $928a
    ld d, $b0
    ld a, [$5fc9]
    cp d
    ld [hl-], a
    ld e, l
    sbc $35
    jp $88a0


    and c
    and d
    ld h, d
    ld [de], a
    ld a, a
    ldh [$8d], a
    ld h, d
    ret c

    ld h, b
    ld d, l
    rrca
    inc hl
    ld e, d
    and e
    ld c, b
    ld a, [hl+]
    ld d, l
    ld c, e
    call nc, Call_000_1d67
    ld a, d
    ld a, [bc]
    xor [hl]
    ld b, c
    ld a, [de]
    jr nc, jr_013_71e9

    inc sp
    sub d
    xor e
    rst $10
    jp c, $8126

    add sp, $14
    sbc d
    sub l
    ld l, [hl]
    jp $0441


    sub h
    jp z, $1aa3

    adc c
    db $76
    db $e3
    ld a, [bc]
    add d
    or a
    xor h
    inc sp
    and d
    rst $38

jr_013_71c5:
    ld [$cab4], a
    adc e
    xor d
    and e
    pop bc
    and d
    sbc $3c
    push af
    ld h, $8f
    ld c, c
    ld b, [hl]
    adc a
    ld d, c
    ld a, b
    push af
    and e
    rst $30
    ld c, c
    db $fd
    xor [hl]
    sub c
    jr nz, jr_013_71c5

    and a
    sub c
    inc de

Jump_013_71e3:
    adc a
    rst $20
    ld a, [de]
    add h
    ld l, c
    add hl, hl

jr_013_71e9:
    adc l
    jp nc, Jump_013_6ec4

    sbc c
    ccf
    rst $38
    jp hl


    add e
    rst $38
    ld c, e
    ld a, [hl+]
    scf
    ld [c], a
    sub l
    ld sp, hl
    adc e
    rst $38
    rst $38
    push hl
    push af
    cp $d3
    add a
    or d
    sbc b
    jp hl


    rrca
    db $fd
    ld d, l
    ld b, a
    dec b
    cp $17
    add a
    ld hl, sp+$7f
    ld [de], a
    add [hl]
    cpl
    db $ed
    ld d, [hl]
    ld [hl], d
    ldh a, [$78]
    ld c, l
    add e
    inc de
    jr z, jr_013_7293

    ld h, e
    rst $38
    rst $38
    xor d
    and [hl]
    ld [hl], b
    inc h
    ld [hl], b
    dec h
    and [hl]
    dec c
    ld hl, sp-$29
    rst $38
    rst $38
    rst $38
    cp $65
    ld de, $2846
    ld sp, $1f12
    ld a, [hl]
    ld [$5775], sp
    rst $38
    ldh [$9d], a
    add hl, bc
    ld [hl], l
    ccf
    or e
    ld [de], a
    sub l
    ld d, c
    rst $18
    dec d
    di
    inc d
    sbc [hl]
    add h
    rst $00
    xor e
    ld b, h
    and a
    and a
    db $10
    sbc [hl]
    xor h
    ld a, a
    ld d, $80
    ld [hl], a
    cp [hl]
    ld b, c
    ld l, d
    xor c
    ld d, e

jr_013_7258:
    call $aa81
    xor c
    ld a, d
    ld d, e
    rst $00
    add d
    inc [hl]
    and h
    inc h
    pop af
    ld d, b
    ld e, a

jr_013_7266:
    ld c, h
    jp hl


    db $d3
    call nz, $70d0
    db $d3
    ld e, e
    ld c, a
    add hl, bc
    ld b, d
    ld b, $4d
    db $ed
    inc a
    add hl, de
    ld d, [hl]
    sub e
    add d
    sub e
    ret nz

    cp [hl]
    add [hl]
    ld c, l
    ldh [rVBK], a
    ld [bc], a
    and [hl]
    ld e, b
    ldh [$85], a
    ld a, l
    jr nc, jr_013_72db

    ld [hl], l
    ld a, [hl-]

Jump_013_728a:
    dec e
    ld [$a1c1], sp
    adc h
    sub $46
    adc l
    push de

jr_013_7293:
    ld l, d
    add c
    ld c, d
    ld h, b
    jp nc, Jump_000_2525

    db $f4
    dec a
    ldh [$57], a
    push hl
    ld d, [hl]
    and d
    ret nc

    xor a
    and b
    ld c, c
    ld c, c
    rst $38
    ld l, b
    ld e, $b7
    ld l, d
    adc d
    ld l, d
    dec l
    ld l, a
    sbc [hl]
    inc b
    or l
    ld l, d
    rrca
    ld e, c
    ld c, e
    and d
    ldh [rBCPS], a
    sbc d
    jr c, jr_013_7266

    sub h
    ld d, c
    ldh a, [$d4]
    add l
    dec h
    ld a, [bc]
    jr nc, jr_013_7258

    add l
    inc hl
    jp nc, $ff27

    db $f4
    push bc
    dec b
    ld d, h
    and h
    db $10
    ld a, l
    inc d
    sub l
    inc hl
    pop de
    add d
    sub b
    ld d, l
    ld b, $f5
    ld a, [hl]

jr_013_72db:
    ld a, [hl+]
    ld c, c
    xor h
    pop bc
    ld hl, $f025
    add a
    ld [$89f0], a
    xor b
    adc $90
    sbc $d4
    sbc c
    ld l, $f8
    adc h
    sub a
    ld h, l
    ld c, h
    ld d, l
    ld l, h
    adc c
    rst $18
    adc h
    add hl, hl
    inc [hl]
    sub a
    sbc l
    ld [hl+], a
    xor d
    xor b
    add [hl]
    ld l, $8d
    xor c
    ld c, h
    db $e4
    db $10
    adc h
    sub [hl]
    adc [hl]
    jp z, $3195

    ld a, d
    ld b, l
    ld l, b
    pop af
    xor d
    and l
    ld b, c
    jp hl


    and e
    rst $08
    ld [hl], a
    dec c
    dec c
    db $d3
    call Call_000_2b54
    ld e, a
    adc a
    ld a, [hl-]
    xor e
    ld [hl], h
    push af
    xor b
    ld [$209f], a
    or h
    and c
    ld a, [bc]
    ld a, c
    cp [hl]
    ld h, e
    dec bc
    ld [bc], a
    ld a, b
    ld sp, hl
    pop bc
    ld sp, $48e3
    ld a, [hl+]
    ld l, a
    ld e, $32
    db $10
    and a
    and a
    ld h, e
    ld e, $c3
    sbc h
    adc c
    pop hl
    jr c, jr_013_739d

    ld [hl], c
    daa
    ld a, h
    ld [hl], h
    and h
    add hl, hl
    adc d
    ld [hl], b
    xor b
    daa
    ld a, [hl+]
    cpl
    push hl
    ld sp, $bec2
    sbc h
    add hl, bc
    ld de, $f91f
    inc c
    ld e, $52
    ld d, [hl]
    push af
    push bc
    inc hl
    ld [de], a
    db $eb
    rst $38
    and c
    rst $38

jr_013_7364:
    sub b
    sub e
    ld b, l
    ld a, e
    ld a, h
    ld [hl], $a3
    ld a, [$ff43]
    rst $38
    ld b, [hl]
    ld l, c
    ld c, e
    rst $38
    rst $10
    call nc, $e18f
    add a
    jp $f1ff


    bit 0, h
    rst $10
    cp b
    ldh a, [$de]
    inc de
    jp $d17f


    add hl, hl
    jp nz, $ada8

    rrca
    call nz, Call_013_4328
    rla
    jr jr_013_740a

    ld d, d
    sub c
    inc de
    ldh a, [$50]
    dec hl
    db $10
    and c
    ld b, [hl]
    inc l
    ld h, l
    ld e, a
    ld l, l

jr_013_739d:
    db $e4
    call nz, $1371
    db $e4
    jr nc, jr_013_7364

    sbc l
    jr nc, @+$81

    ld d, $95
    ld a, [de]
    inc [hl]
    ld a, [hl+]
    ld h, d
    sub e
    inc e
    sub d
    ld l, d
    ret nz

    jp hl


    or e
    dec e
    jr nc, jr_013_73dd

    ld d, e
    add l
    xor c
    ld l, b
    ld b, a
    add e
    ld a, [bc]
    ld h, e
    dec b
    adc l
    ld e, $6c
    ld b, l
    xor h
    ld a, d
    sbc a
    cp $7a
    jr z, jr_013_7427

    ld c, h
    ld a, d
    adc c
    ld a, [c]
    ld h, b
    ld [hl], a
    cp a
    sbc l
    dec d
    ld d, h
    db $f4
    xor a
    pop bc
    ld c, a
    ld b, [hl]
    xor h
    ld d, l
    ld d, l

jr_013_73dd:
    ld d, l
    ld d, l
    ld c, a
    add hl, bc
    ld b, $b5
    ld d, l
    ld d, l
    ld d, l
    ld d, h
    call $e314
    ld c, c
    db $e3
    xor c
    add c
    pop bc
    ld [hl], $5a
    ld a, [hl+]
    ld d, l
    inc [hl]
    ld l, b
    ld d, l
    ld d, h
    adc [hl]
    add sp, -$4b
    ld e, d
    scf
    xor d
    xor d
    and h
    sbc b
    sbc d
    ld [hl+], a
    ld a, l
    ld c, c
    adc a

jr_013_7405:
    dec sp
    dec b
    add sp, $27
    ld l, h

jr_013_740a:
    rst $28
    db $d3
    ld c, a
    ld a, [de]
    or [hl]
    and e
    adc l
    ld [hl-], a
    ld c, l
    db $dd
    ld e, d
    ld b, c
    adc [hl]
    inc d
    add [hl]
    xor d
    cp [hl]
    adc l
    push hl
    ld a, [hl]
    add hl, bc
    jr c, jr_013_7405

    db $10
    xor d
    xor d
    ld hl, $5fa5

jr_013_7427:
    inc hl
    ld c, $2d
    add hl, sp
    ld [$86af], a
    ld [hl-], a
    ld b, a
    xor $2e
    ld d, l
    sub l
    ld d, l
    ld e, e
    ldh [rWX], a
    ld d, e
    ld a, c
    add hl, bc
    ld a, [hl-]
    ldh [rSCY], a
    xor d
    xor b
    di
    xor l
    rst $38
    db $eb
    ld h, e
    adc $aa
    xor d
    adc a
    pop hl
    jp hl


    db $fc
    add sp, -$76
    ld a, d
    sub b
    pop hl
    ld b, a
    and e
    inc c
    ld de, $79e9
    db $10
    ld d, l
    ld d, l
    ld d, l
    ld d, l
    add hl, de
    and d
    sbc h
    ld c, [hl]
    ld [hl-], a
    db $76
    ld sp, $b6c4
    xor d
    xor d
    xor c
    and e
    db $10
    sub b
    and l
    ld [hl], h
    ld d, d
    xor l
    ld d, h
    ld h, b

jr_013_7471:
    or h
    ld [hl], b
    call nz, $15f9
    xor d
    ld b, [hl]
    or d
    ld l, c
    add hl, hl
    jp nz, $c497

    cpl
    ret nz

    adc d
    rra
    add $d4
    xor l
    ld d, l
    ld d, d
    inc d

Jump_013_7488:
    sbc c
    db $fd
    add a
    add [hl]
    inc a
    ld [hl], c
    jp nc, $aeaa

    ld c, d
    xor d
    ld d, l
    ld a, d
    db $10
    inc l

Call_013_7497:
    dec c
    ld d, h
    xor d
    xor d
    xor l
    ld [hl], d
    xor d
    ld l, $43
    push de
    ld c, $43
    call nc, Call_013_7046
    pop hl
    ld h, c
    rst $38
    db $e4
    ld a, b
    jr nc, jr_013_7471

    ld d, b
    ld h, h
    ld l, d
    ld d, h
    sub d
    add $38
    and c
    add a
    rst $38
    cp $69
    ld sp, $35ac
    ld d, l
    ld d, l
    ld b, e
    ld b, $1f
    db $fd
    ld a, c
    or h
    ld sp, $dfd8
    ld sp, hl
    ld e, $79
    jp hl


    ld d, h
    sbc a
    jp z, Jump_013_77c0

    cp a
    adc b
    sub e
    adc l

jr_013_74d4:
    push af
    inc a
    inc b
    ld de, $335a
    and a
    db $eb
    ld c, l
    ld d, h
    dec de
    ld c, h
    ld d, c
    ld e, b
    sbc d
    ld c, h
    dec a
    ld b, c
    ld c, l
    ld e, e
    ld [hl], e
    ld b, h
    adc b
    pop bc
    adc d
    ld d, a
    ld [$b578], a
    and d
    inc d
    dec d
    ld e, $4c
    ret nc

    xor a
    sub $e8
    add a
    ld [$41b6], sp
    ret nc

    ld a, h
    inc d
    sub h
    inc h
    add $e5
    inc d

jr_013_7506:
    ld l, d
    ld l, [hl]
    jr nc, jr_013_756b

    cp e
    db $dd
    ld l, b
    or h
    push de
    and b
    ld b, c
    dec d
    add hl, de
    ld l, $29
    and e
    ld a, b
    sub h
    ld e, d
    and l
    rlca
    ld [hl+], a
    ld a, [bc]
    xor a
    ld a, [hl]
    add hl, hl
    jr c, jr_013_7506

    db $10
    sbc c
    ld a, d
    adc b
    sbc b
    add $0a
    ld h, $39
    ld l, b
    cp l
    dec h
    ld [c], a
    ld d, h
    jp nc, $ad39

    jr jr_013_74d4

    ld [$bf25], sp
    db $f4
    cp b
    ld d, e
    and d
    ld a, [c]
    xor d
    jr nc, @+$57

    ld c, b
    ld e, a
    ld b, [hl]
    sub l
    add hl, sp
    and h
    add h
    ld de, $1a55
    ld [$529d], sp
    sub b
    db $d3
    sbc c
    inc b
    inc d
    ld d, d
    ld a, [hl+]
    ld b, a
    ld [$83a0], a
    ld [hl], b
    or b
    sub l
    jr c, @-$1c

    ld a, [hl+]
    ld d, l
    ld b, $bb
    ld l, [hl]
    sub b
    rst $10

jr_013_7564:
    rst $20
    rst $00
    and h
    jp hl


    xor d
    inc c
    or l

jr_013_756b:
    ld l, b
    sbc d
    or b
    sub b
    add a
    ld c, [hl]
    sbc d
    sub b
    sbc $07
    inc [hl]
    cp l
    jr jr_013_7564

    cp a
    ld a, e
    sub l
    jr c, jr_013_75a5

    db $e3
    cp c
    ld d, [hl]
    adc a
    ld d, d
    adc a
    ret nc

    ld h, a
    pop af
    or h
    add hl, bc
    ldh [$a9], a
    ld [$9026], sp
    ld [hl-], a

jr_013_758f:
    add hl, hl
    call nz, $6ca6
    cpl
    ld [$c39a], a
    sbc e
    jr c, jr_013_75f3

    sub d
    db $eb
    rst $38
    add $28
    ld l, d
    ld l, d
    add d
    ld hl, sp+$40
    pop bc

jr_013_75a5:
    inc c
    ld d, a
    rst $38
    ret z

    ld a, [hl+]
    and e
    ccf
    ld sp, hl
    and e
    rst $38
    ret nz

    and [hl]
    inc d
    add e
    rst $38
    dec hl
    ld de, $11fd
    ld a, [de]
    ccf
    or $6d
    ld e, a
    rst $38
    push af
    ld a, a
    sbc $2a
    sbc c
    rst $38
    rst $20
    dec de
    rst $38
    rst $08
    push af
    ld l, a
    cp l
    pop af
    adc a
    db $fc
    ld [hl], e
    ld e, a
    db $ed
    inc h
    ld a, [hl]
    ld hl, sp+$46
    ld e, $15
    sbc h
    rst $28
    rst $38
    or l
    ld [de], a
    ret nc

    ld h, $3c
    add hl, sp
    push de
    ld a, a
    ld sp, hl
    ld d, d
    jr z, jr_013_758f

    ld e, c
    ld [de], a
    ld [hl], l
    ld b, c
    ld a, a
    and [hl]
    ld [hl], h
    ld c, a
    dec b
    dec b
    xor b
    and a
    ld b, l

jr_013_75f3:
    jp $9396


    ld l, $12
    xor a
    rst $38
    and a
    dec a
    ld de, $fa45
    ld a, [hl+]
    ld d, a
    add a
    rst $38
    add sp, $27
    ld d, l
    inc hl
    adc $8d
    sub c
    ld b, e
    rlca
    ld e, a
    add hl, hl
    ldh [$be], a
    ld b, [hl]
    inc c
    ld l, e
    ld c, l
    sbc l
    ld l, b
    or b
    cp c
    pop bc
    inc c
    sbc l
    or c
    adc e
    inc e
    ld sp, $c9e0
    ei
    ret nc

    ld [hl], a
    cp a
    nop
    ld d, e

jr_013_7627:
    db $d3
    ld d, [hl]
    jp Jump_013_424f


    ret z

    sub l
    ld [hl], h
    di
    inc h
    ld [de], a
    cp b
    jr c, jr_013_7627

    db $ed
    push bc
    add c
    ld h, c
    sub e
    call $a97d
    ld h, $3c
    ld [hl], l
    ld c, b
    and d
    ld h, e
    cp l
    ld d, d
    ld d, c
    ld l, b
    dec e
    ld c, d
    ld h, d
    and b
    ld e, d
    and e
    add l
    adc h
    ld e, b
    sbc b
    ld d, d
    ld d, e
    ld a, [bc]
    dec d
    ld c, d
    ld d, l
    ld d, [hl]
    xor d
    ld sp, $d28c
    ld de, $4345
    rst $00
    and a
    cp $aa
    xor b
    push bc
    scf
    add c
    ld a, [de]
    ld b, [hl]
    adc d
    sbc b
    push de
    jr nc, jr_013_76b6

    adc h
    ld d, a
    ld b, d
    xor e
    sub e
    ld e, a
    push af
    xor a
    ld [$8aaa], a
    ld b, c
    ld a, [hl+]
    ld hl, sp+$2a
    add l
    ld [hl-], a
    xor d
    add [hl]
    xor e
    rst $38
    xor c
    ld d, d
    xor $45
    ldh [rSTAT], a
    dec b
    di
    pop bc
    and h
    dec l
    ld b, l
    ld [$1e2a], sp
    add c
    dec l
    ld d, d
    rst $28
    push de
    ld d, h
    adc $1f
    push bc
    rra
    inc b
    ld l, d
    ld d, d
    xor d
    jp nc, $2a62

    xor e
    ld d, d
    ret c

    dec [hl]
    xor $df
    ld [c], a
    ld hl, $ba72
    or b

jr_013_76ae:
    ld e, l
    inc [hl]
    xor d
    and e
    rlca
    and e
    dec hl
    ld e, h

jr_013_76b6:
    xor d
    ld [$8f5e], sp
    ld h, $92
    ld d, l
    xor l
    db $fc
    ld a, [c]
    rst $20
    rst $10
    cp h
    jr c, @-$0b

    xor d
    xor d
    and e
    ld hl, sp-$4a
    ld a, [hl]
    nop
    sbc [hl]
    and d
    add h
    add hl, bc
    jp hl


    jr nc, jr_013_76ae

    and c
    sbc [hl]
    ld l, d
    sub l
    ld de, $e651
    ld b, h
    ld b, c
    ld [hl+], a
    ld a, [$d379]
    ld [de], a
    rst $18
    rst $00
    adc [hl]
    sbc c
    or a
    ld a, [$3675]
    ld c, d
    ld [$426c], sp
    ld d, a
    ccf
    add h
    or [hl]
    or c
    push bc
    sub [hl]
    or b
    ld [hl], d
    cp h
    ld de, $7f18
    ld [bc], a
    cp a
    ld sp, hl
    ld a, [hl+]
    ld e, h
    xor e
    ld sp, hl
    ld d, [hl]
    dec de
    db $fc
    and h
    pop hl
    inc sp
    db $fd
    ld c, d
    ld a, [bc]
    xor a
    ld b, [hl]
    rra
    cp $19
    ccf
    rst $38
    ld a, [c]
    xor b
    jp hl


    and a
    cp $62
    adc l
    ld d, h
    db $e4
    ld c, a
    rst $38
    adc $3e
    or e
    and $2f
    ld a, [$28fd]
    ld d, c
    xor [hl]

Call_013_7726:
    rra
    ei
    ccf
    ld a, a
    cp $5a
    xor d
    or a
    push de
    ld [$f0a0], a
    add hl, hl
    ld c, $37
    rst $08
    dec b
    ld h, c
    ret z

    rst $38
    rst $38
    rst $38
    pop hl
    add hl, de
    ld b, c
    rst $38
    add l
    and c
    ld l, b
    ld a, [$2453]
    ccf
    rst $38
    rst $38
    ld sp, hl
    ld a, [hl-]
    ld c, d
    add a
    cp $46
    inc l
    add e
    di
    add hl, sp
    inc de
    rst $38
    push de
    ld d, a
    ld sp, hl
    sbc l
    rlca
    push de
    inc a
    ld de, $701f
    ld d, c

Call_013_7760:
Jump_013_7760:
    ld c, a
    set 5, c
    dec d
    inc a
    ld [hl], l
    add $b0
    rst $30
    ld a, [$cec0]
    ld de, $5fe6
    add sp, -$0d
    inc b
    ld a, c
    cp l
    ld d, e
    ld c, a
    rra
    call z, Call_013_7760
    cp a
    ld c, d
    ld d, e
    rst $08
    ld l, e
    db $76
    ld a, b
    di
    ld h, d
    ld a, [hl+]
    xor a
    ld c, a
    dec [hl]
    pop bc
    sub a
    ld b, c
    ld c, l
    dec d
    ld d, e
    cp d
    ld a, [hl]
    ld a, [de]
    add d
    adc e
    ld l, [hl]
    xor d
    adc a
    dec h
    dec d
    and d
    rla
    push af
    inc [hl]
    ld e, d
    and h
    and $58
    cp d
    adc l
    call c, Call_013_4dc2
    sbc b
    sbc $36
    ld a, b
    ld [de], a
    sub b
    push bc
    ld d, l
    ld l, d
    sub e
    sub c
    ld [hl], d
    sbc $15
    ld b, $86
    ld c, $3a
    reti


    sbc b
    add $42
    xor d
    ld b, d
    cp e
    rst $18
    ld h, e
    sub a

Jump_013_77c0:
    xor b
    adc d
    ld a, [hl+]
    ld b, d
    dec b
    add a
    ld e, c
    inc b
    ld h, l
    add hl, sp
    sbc c
    dec [hl]
    ret z

    ld b, e
    adc b
    add l
    sbc [hl]
    ld c, [hl]
    ld e, l
    and c
    ld d, e
    ld b, h
    ld h, $41
    ld b, d
    dec d

jr_013_77da:
    ld h, e
    sub [hl]
    xor l
    ld c, h
    db $e4
    ld [de], a
    ld [hl+], a
    dec d
    dec b
    inc b
    jp z, $95aa

    ld d, a
    ld d, b
    call Call_013_54a7
    ld e, a
    ld [$a450], sp
    db $e4
    cp a
    ld c, [hl]
    ld a, [bc]
    xor b
    rst $00
    ld b, [hl]
    dec h
    dec a
    dec bc
    ld h, d
    inc de
    add c
    and a
    adc [hl]
    ld [$e2a8], a
    sub d
    inc hl
    push de
    xor d
    ccf
    add [hl]
    rst $20
    jp hl


    ld l, c
    rst $20
    or e
    add d
    rrca
    rst $00

Call_013_7810:
    sbc e
    ld de, $74e3
    ld a, c
    or b
    jr nc, jr_013_7868

    ld e, a
    and [hl]
    ld c, d
    ld b, d
    ld [hl], a
    pop bc
    jr jr_013_7871

    ld c, a
    ccf
    db $fc
    ld a, c
    jr c, jr_013_77da

    ld b, a
    ld a, d
    jp hl


    xor l
    xor [hl]
    ld [hl], c
    inc h
    cp h
    ld d, e
    ld a, a
    ld sp, hl
    and e
    rst $38
    ld a, [$c26f]
    add $10
    call nc, Call_013_6232
    pop bc
    db $fd
    ld c, d
    adc d
    ld c, a
    dec c
    dec b
    ld b, [hl]
    xor b
    and c
    sub [hl]
    cp b
    or [hl]
    ld a, [$b512]
    ld b, [hl]
    ret


    add e
    inc bc
    ld a, $94
    ei
    inc bc
    or a
    add e
    call nc, $9a87
    ld h, l
    cp b
    ld e, h
    rra
    ld b, [hl]
    rla
    ld [hl], l
    ld l, [hl]
    db $fd
    inc bc
    ret nz

    xor c
    add d
    ld h, h
    di
    ld sp, hl

jr_013_7868:
    sbc e
    ld a, [$c230]
    pop bc
    ld e, a
    dec b
    ld d, l
    ld d, l

jr_013_7871:
    ld d, l
    ld b, c
    ld b, c
    pop hl
    ld sp, hl
    sub a
    push af
    and c
    ld [hl-], a
    db $fd
    ld d, c
    bit 2, e
    add $b6
    adc a
    ldh a, [rLCDC]
    sub c

jr_013_7884:
    cp $aa
    pop de
    inc [hl]
    ld d, d
    adc l
    inc e
    jr jr_013_78e3

    inc [hl]
    ld b, a
    ld d, a
    rst $38
    sbc h
    inc e
    add hl, de
    ldh [rIE], a
    pop af
    jp nz, $77ea

    ld [hl], l
    ld h, a
    inc c
    push de
    daa
    xor c
    inc hl
    rra
    jp z, Jump_013_7760

    xor l
    ld d, l
    ld c, a
    ld c, e
    rst $38
    rst $38
    push af
    ld c, a
    ld [hl], $77
    ei
    rst $38
    call nc, $14f2
    add hl, hl
    sbc $fb
    rst $38
    cp l
    ld c, a
    dec c
    ld l, h
    ld l, b
    ld a, [hl+]
    dec e
    sub c
    xor l
    inc a
    jr z, jr_013_78f3

    sbc [hl]
    jp Jump_013_496d


    ld d, h
    ldh a, [$ad]
    sbc $bf
    ld c, b
    cp b
    adc a
    adc [hl]
    push hl
    rlca
    ld d, l
    cp [hl]
    or h
    jp z, $db8e

    inc b
    jr jr_013_7903

    add [hl]
    jp Jump_000_15d3


    jr c, jr_013_7936

    push bc

jr_013_78e3:
    jr nc, jr_013_7884

    ret z

    ld d, h
    jr z, @-$68

    db $eb
    ld c, c
    ld e, d
    and l
    xor $2d
    add $49
    sub l
    ld c, b

jr_013_78f3:
    xor l
    ld a, [de]
    ld a, [de]
    sbc h
    ld e, d
    ld sp, $3082
    ld h, h
    ld [hl+], a
    jp hl


    and d
    inc d
    ld d, b
    ld b, d
    db $ed

jr_013_7903:
    ret c

    jp c, Jump_013_728a

    ld a, b
    or h
    db $76
    or l
    inc hl
    ld l, b
    dec d
    ld [hl], $a2
    ret c

    sbc h
    xor [hl]
    jr jr_013_7986

    sub d
    dec l
    and h
    sbc $8c
    ld [hl+], a
    or h
    sbc l
    ld d, $6d
    ld a, [de]
    ld d, b
    cp h
    and l
    and e
    add d
    ld b, d
    inc b
    jp z, $0b87

    inc b
    adc d
    ld [hl], d
    add hl, de
    ld l, b
    xor b
    call $8c21
    pop af
    ret z

    cp l

jr_013_7936:
    ld b, l
    ld a, [bc]
    and e
    sbc d
    inc b
    push de
    ld b, a
    ld a, [hl+]
    xor b
    ld a, $0e
    sub h
    pop hl
    or l
    ld [$b924], sp
    cp l
    adc h
    ld [c], a
    dec h
    adc [hl]
    ld c, c
    add sp, $52
    pop de
    xor a
    ld d, a
    add hl, bc
    scf
    adc [hl]
    dec hl
    add d
    ld d, d
    ld h, h
    sbc d
    add d
    jp nz, $d294

    ld a, [hl-]
    dec h
    ld [hl+], a
    ld d, e
    inc c
    sbc b
    pop de
    ld a, [hl-]
    and h
    sbc c
    ld l, $21
    ld h, h
    pop af
    ld h, h
    sbc d
    ld c, b
    add l
    ld b, c
    add c
    inc a
    ld e, b
    cp d
    ld d, b
    and a
    rst $18
    jp nc, $edb4

    adc h
    xor l
    ld l, a
    rst $38
    pop de
    ld b, d
    db $d3
    or d
    cpl
    xor d
    add hl, bc

jr_013_7986:
    ei
    db $fc
    ld d, c
    adc $fa
    sub l
    call z, $de2a
    xor a
    jp hl


    ld l, c
    add hl, hl
    jp hl


    ld b, [hl]
    ld d, b
    and a
    sbc e
    and e
    add hl, hl
    jr z, jr_013_79dc

    sbc [hl]
    ld c, l
    db $e4
    ld b, l
    ret nz

    adc e
    sbc [hl]
    inc [hl]
    ld h, c
    add hl, de
    ld e, [hl]
    sbc [hl]
    ld l, $9c
    ld a, $9e
    ld b, l
    sub e
    dec d
    inc b
    ld a, b
    jp z, $e829

    ld h, d
    ldh [$f4], a
    ld h, e
    add d
    ld a, b
    sub [hl]
    jr jr_013_7a2f

    pop de
    add hl, hl
    db $10
    jp hl


    jr z, jr_013_79e9

    ld a, [de]
    and h
    and [hl]
    inc l
    adc h
    inc e

jr_013_79c9:
    ld h, [hl]
    sub c
    ld d, $a4
    ld l, a
    rst $38
    ld sp, hl
    add hl, bc
    add h
    ld e, $3c
    and b
    or c
    ld c, [hl]
    and l
    ret nc

    ld b, c
    rst $38
    rst $38

jr_013_79dc:
    ld sp, hl
    sbc d
    adc a
    ld c, $a1
    ld hl, $16a9
    inc d
    adc a
    ld c, c
    rla
    rst $38

jr_013_79e9:
    cp $67
    ld de, $a4c3
    db $fc
    add hl, bc
    add hl, hl
    ld [de], a
    ld h, b
    push af
    rst $38
    add $72
    rrca
    rrca
    and d
    adc e
    add h
    sub e
    jr z, jr_013_7a48

    inc c
    sub e
    cp $6c
    ldh a, [$e1]
    and e
    rrca
    ld h, e
    jr z, jr_013_79c9

    xor b
    ld c, a
    dec bc
    rst $38
    ld a, [de]
    or d
    rrca
    ld h, c
    inc d
    add l
    sub e
    ld a, a
    ldh a, [$78]
    rst $10
    rst $38
    sbc e
    ld h, c
    add a
    ld [hl], $65
    db $eb
    rst $38

Jump_013_7a21:
    jp $d120


    dec d
    rst $20
    inc b
    jr jr_013_7a91

    ld b, [hl]
    scf
    ld a, a
    ld sp, hl
    ld d, l
    and d

jr_013_7a2f:
    ei
    inc e
    cp c
    cp l
    ret nc

    ld a, b
    inc h
    rst $18
    rst $38
    rst $20
    ld b, h
    ld [hl], b
    pop hl
    ld a, [$ff45]
    ld sp, hl
    push de
    dec de
    pop hl
    cp $91
    ld a, a
    ld sp, hl
    reti


jr_013_7a48:
    ld h, $98
    ld a, a
    add sp, $3f
    cp $77
    ld c, c
    sub h
    rla
    di
    rst $38
    cp $78
    add hl, bc
    sbc a
    ld c, a
    rst $38
    rst $38
    add d
    ld [hl], a
    and l
    ld [hl+], a
    sub c
    ld a, a

Jump_013_7a61:
    rst $38
    di
    ld b, a

Jump_013_7a64:
    add d
    sub b
    sub a
    rlca
    ld e, a
    pop bc
    inc c
    ld a, b
    ld d, b
    add $71
    ld d, c
    nop
    ld [hl], a
    cp a
    and h
    db $d3
    ld b, h
    rst $28
    ld d, e
    rla
    db $ed
    ld e, $d0
    ld [hl], e
    sub l
    ld a, l
    ld l, c
    ld h, e
    rla
    adc c
    push af
    ld b, [hl]
    sub h
    ldh [$5f], a
    and c
    ld c, l

Call_013_7a8a:
    ld e, [hl]
    dec b
    db $eb
    xor b
    ld e, c
    ld b, l
    xor c

jr_013_7a91:
    ld d, [hl]
    sub [hl]
    add sp, -$3f
    dec l
    rla
    add c
    push af
    ld l, b
    dec e
    ret nc

    ld l, e
    ld c, h
    rst $10
    ld d, e
    ld l, b
    adc e
    ld e, e
    ld hl, sp-$77
    ld l, [hl]
    ret c

    dec hl
    push af
    ld a, [hl+]
    db $f4
    inc h
    ld [c], a
    db $fd
    ld a, [c]
    ld h, b
    ld a, [hl]
    add hl, de
    add e
    ld b, d
    cp h
    sub l
    ld b, d
    ld l, d
    xor b
    xor d
    sbc a
    cp a
    ld a, [c]
    ld h, b
    add c
    cp l
    sub b
    db $e3
    ld b, $0f
    ld a, l
    ld d, l
    ld c, d
    ld d, h
    sbc e
    db $fd
    ld b, l
    push hl
    ld a, h
    ret


    ld a, [hl]
    pop bc
    ld c, [hl]
    adc d
    db $eb
    ld d, l
    ld hl, sp+$28
    add hl, hl
    ld d, a
    push af
    ld c, $39
    dec l
    ld [hl-], a
    ld e, a
    ld c, b
    ld b, d
    push de
    ei
    push de
    db $f4
    ret


    ld h, h
    ld h, h
    adc e
    ld d, c
    ld [hl], h
    ld l, d
    inc b
    scf
    ld a, [de]
    adc d
    and d
    cpl
    ld d, d
    ld d, h
    ld h, e
    ld a, [hl+]
    ld hl, sp+$2d
    rla
    and b
    ld c, [hl]
    ld c, d
    push af
    db $76
    ld d, e
    add [hl]
    ei
    sbc $8e
    ld a, d
    ld a, [de]
    add hl, de
    ld c, a
    add sp, -$57
    db $fd
    ld a, $9d
    jp z, $fa66

    ld b, h
    ld de, $bcd4
    ld c, $14
    sbc d
    ld a, a
    and b
    jp nz, $9c83

    dec hl
    rst $38
    rst $30
    and [hl]
    xor a
    rst $10
    rst $38
    ret nz

    sub d

jr_013_7b23:
    or h
    add l
    and d
    cp a
    rst $38
    rst $38
    ld a, d
    ld c, $5f
    rst $30
    ld hl, sp+$37
    adc $10
    ld a, a
    ld [$bdd0], a
    rst $38
    rst $38
    add a
    pop hl
    rla
    ei
    ld a, a
    add sp, -$05
    ld [hl], b
    ld hl, $fe57
    ld [de], a
    and b
    rst $18
    cp $1f
    sub [hl]
    and e
    push af
    rst $38
    db $e3
    ld hl, sp+$78
    ld [hl], $b4
    cp d
    ld b, e
    ld l, d
    xor d
    xor d
    xor l
    jp nz, Jump_000_0dfb

    ld a, h
    rra
    call Call_000_0221
    rst $38
    ld hl, sp+$52
    and [hl]
    ld a, [bc]
    sub c
    dec d
    ld l, h
    and l
    jr nc, jr_013_7b9f

    inc de
    rst $38
    db $fd
    ld [bc], a
    dec c
    add hl, de
    ld a, [hl]
    ld c, d
    ld h, c
    inc c
    adc d
    rra

jr_013_7b75:
    add sp, $57
    db $fc
    ld a, $0c

Jump_013_7b7a:
    ld l, e
    ld hl, sp+$26
    jp z, Jump_013_5083

    jr nc, jr_013_7b23

    add h
    db $10
    inc h
    ld d, d
    ld h, e
    ld a, a
    dec b
    sbc c

jr_013_7b8a:
    rst $30
    ld [de], a
    cp e
    sbc h
    ld d, h
    and h
    ld e, a
    add $b4
    ld e, d
    jr nc, jr_013_7bdf

    call Call_000_1454
    dec bc
    inc e
    dec [hl]
    inc c
    ld a, b
    inc [hl]

jr_013_7b9f:
    ld a, a
    ld b, l
    add b
    ld [hl], a
    cp [hl]
    ld l, c
    and e
    call nc, Call_000_2362
    jp nc, $8f4b

    ld b, d
    dec h
    ld d, a
    ld c, a
    ld [hl], $16
    adc d
    cp l
    ld c, a
    ld [hl+], a
    jr jr_013_7b8a

    di
    add $46
    inc [hl]
    ld a, b
    pop af
    sub c
    adc h
    sbc $3c
    sub [hl]
    inc sp
    ld d, e
    ret


    sub e
    xor c
    xor d
    ld [hl], h
    ld h, h
    add h
    sub $4d
    xor b
    pop bc
    ld a, [hl]
    ld l, $d0
    or [hl]
    inc b
    ret


    sub d
    sub l
    ld d, l

jr_013_7bd9:
    ld b, l
    ld b, l
    ld a, [$21d6]
    inc d

jr_013_7bdf:
    jr nz, jr_013_7b75

    ld e, l
    add hl, hl

jr_013_7be3:
    add [hl]
    xor d
    adc h
    ret nc

    and b
    sbc [hl]
    dec l
    ld d, $94
    ld [hl], c
    ld e, d
    ld [hl+], a
    jr c, jr_013_7bd9

    call Call_000_1c6a
    ld hl, $20b4
    ldh a, [$b5]
    ld a, [hl-]
    sub h
    ld e, b
    pop bc
    ld c, $45
    jr @+$22

    ld b, d
    pop bc
    ld c, [hl]
    dec h
    ld l, c
    add sp, -$36
    ld b, d
    ld [hl], c
    add [hl]
    jp nz, Jump_013_7488

    push bc
    jr nc, @+$57

    ld d, b
    ld d, h
    add $ff
    ld d, $17
    jp nz, Jump_000_1ca8

    push bc
    call $832a
    ld sp, hl
    dec hl
    ld h, $5b
    pop bc
    ld [c], a
    ld d, e
    and d
    add d
    and c
    adc c
    xor c
    ld hl, $89a1
    sub e
    add d
    xor c
    ld d, h
    adc $30
    ld e, b
    sub $53
    ld d, l
    jr nc, jr_013_7be3

    sub h
    db $ed
    ld d, [hl]
    xor c
    ld d, d
    ld l, d
    xor b
    ld [hl+], a
    push hl
    inc a
    ld c, d
    ld d, e
    reti


    and h
    sbc b
    push af
    dec h
    ld c, a
    cp h
    sbc a
    inc [hl]

jr_013_7c4e:
    rst $00
    xor d
    call nz, $a447
    sub a
    ld e, $84
    ld b, d
    sub c
    ld e, $74
    rrca
    jr @+$42

    sbc [hl]
    ld c, h
    inc c
    ld a, d
    sbc b
    ld sp, $60ea
    add $4a
    ld a, c
    ld a, h
    ld d, d
    rst $38
    sbc [hl]
    ld e, [hl]
    ld b, e
    rst $38
    cp $9a
    ld hl, $e80c
    ret


    add hl, bc
    xor e
    add e
    db $fd
    ld d, c
    inc [hl]
    ld h, d
    add l
    ld sp, hl
    ld [hl], $0a
    add d
    sbc d
    ccf
    add $6b
    and h
    ld h, d
    cp a
    ld hl, sp+$42
    cp a
    rst $38
    ldh [$a5], a
    jr z, jr_013_7cba

    xor h
    cp $18
    ld a, [hl]
    ld de, $1f1e
    db $d3
    ld [bc], a
    rst $38
    or $8a
    ld de, $e13f
    rst $30
    add l
    ld d, e
    add hl, de
    ld a, [hl]
    ld h, d
    or l
    db $fc
    jr z, jr_013_7c4e

    ld a, a
    and b
    rst $38
    cp $19
    add d
    or h
    ld h, l
    ld c, d
    xor $fc
    ret


    dec hl
    ld a, d
    ld d, l
    ld b, c
    ld a, [bc]

jr_013_7cba:
    cp a
    add $b3
    ld a, a
    rst $30
    ld hl, sp-$14
    ld [de], a
    sbc $57
    and h
    ld h, c
    ld d, l
    call nz, Call_013_7726
    rst $30
    db $fc
    dec de
    call nz, $f9a1
    ld d, h
    ld l, d
    and b
    xor l
    and h
    and b
    rst $38
    ld c, [hl]
    ld e, $4a
    ld b, l
    db $e4
    xor c
    or a
    add a
    ld hl, sp+$49
    ld d, h
    dec c
    ld a, [de]
    ld e, a
    dec sp
    ld d, a
    ld hl, sp+$7f
    ld [$15bc], a
    ld hl, sp+$46
    ld de, $7cc5
    ld d, l
    dec b
    rst $38
    ld sp, hl
    ld d, h
    ld [hl], a
    ld b, l
    ld d, b
    add hl, hl
    db $ec
    jp nc, $9e96

    sub l
    inc h
    ld b, a
    xor e
    rra
    ld a, h
    dec d
    inc b
    dec b
    ld e, e
    ld a, l
    ld c, h
    ld a, l
    db $10
    ld a, l
    nop
    ld d, c
    ld a, l

Jump_013_7d10:
    call Call_000_3c6c
    ldh a, [$aa]
    cp $02
    ld a, $08
    jr z, jr_013_7d1d

    ld a, $0c

jr_013_7d1d:
    ldh [$8d], a
    ld a, $01
    ldh [$8c], a
    call Call_000_34f8
    ld hl, $d6ac
    bit 0, [hl]
    set 0, [hl]
    ret nz

    ld hl, $c214
    ld a, $08
    ld [hl+], a
    ld a, $0a
    ld [hl], a
    ld a, $08
    ld [$c119], a
    ldh a, [$aa]
    cp $02
    ret z

    ld a, $07
    ld [$c215], a
    ld a, $0c
    ld [$c119], a
    ret


    ld c, [hl]
    ld a, l
    nop
    rst $20
    ld d, a
    ld c, $00
    nop
    ld bc, $0601
    ld b, $ff
    nop
    ld bc, $1e1b
    inc de
    ld e, $17
    ld a, [bc]
    db $10
    rra
    ld [de], a
    ld a, [bc]
    jr nz, @+$23

    inc e
    ld [hl+], a
    inc hl
    ld a, [bc]
    jr jr_013_7d86

    ld a, [de]
    ld a, [bc]
    dec d
    inc b
    dec b
    adc l
    ld a, l
    ld a, [hl]
    ld a, l
    ld a, e
    ld a, l
    nop
    add e
    ld a, l
    jp Jump_013_7d10


    add b
    ld a, l
    nop
    rst $20
    ld d, a
    ld c, $00
    nop

jr_013_7d86:
    ld bc, $0601
    ld b, $ff
    nop
    ld bc, $171b
    inc de
    dec de
    rla
    ld a, [bc]
    db $10
    ld de, $0a12
    ld a, [bc]

Jump_013_7d98:
    inc d
    dec d
    ld d, $0a
    ld a, [bc]
    jr @+$1b

    ld a, [de]
    ld a, [bc]
    call Call_000_3c6c
    xor a
    ld [$ccd3], a
    ld a, [$d123]
    cp $06
    jr c, jr_013_7df0

    ld a, [$d9b2]
    cp $1e
    jr nc, jr_013_7de8

    xor a
    ld [$d046], a
    ld a, [$cf78]
    ld [$cfbf], a
    ld hl, $6df1
    ld b, $0f
    call Call_000_3620
    call Call_013_7e00
    ld hl, $6aaf
    ld b, $03
    call Call_000_3620
    ld a, [$d51f]
    and $7f
    add $f7
    ld hl, $cf45
    ld [hl+], a
    ld [hl], $50
    ld hl, $7e3c
    call Call_000_3c79
    scf
    ret


jr_013_7de8:
    ld hl, $7e67
    call Call_000_3c79
    and a
    ret


jr_013_7df0:
    call Call_013_7e00
    call Call_000_3971
    ld a, $01
    ld [$cc3c], a
    ld [$ccd3], a
    scf
    ret


Call_013_7e00:
    ld a, [$cf78]
    push af
    ld [$d0e3], a
    ld a, $3a
    call Call_000_3e9d
    ld a, [$d0e3]
    dec a
    ld c, a
    ld hl, $d27b
    ld b, $01
    ld a, $10
    call Call_000_3e9d
    pop af
    ld [$d0e3], a

Call_013_7e1f:
    call Call_000_1aab
    ld hl, $7e28
    jp Jump_000_3c79


    db $ed
    ld a, [hl+]
    jr nc, @+$58

    ld d, b
    ld bc, $cd68
    nop
    db $dd
    ld a, a
    jp $b2c6


    jp c, $e7c0

    ld d, b
    dec bc
    ld d, b
    db $ed
    ld a, [hl+]
    ld l, h
    ld d, l
    db $d3
    pop bc
    or a
    jp c, $b2c5

    ret


    inc sp
    ld c, a
    ld e, e
    ret


    ld a, a
    inc e
    xor h
    add a
    adc h
    ld d, b
    ld bc, $cf45
    nop
    ld a, a
    add $55
    ld d, b
    ld bc, $de64
    nop
    db $dd

jr_013_7e5e:
    ld a, a
    jp $bfde


    or e
    cp h
    ret nz

    rst $20
    ld d, a
    db $ed
    ld a, [hl+]
    xor a
    ld d, l
    db $d3
    pop bc
    or a
    jp c, $becf

    sbc $e7
    ld d, c
    inc e
    xor h
    add a
    adc h
    db $d3
    ld a, a
    or d
    rst $18
    ld b, h
    or d
    inc sp
    ld c, a
    jp $bfde


    or e
    inc sp
    or a
    rst $08
    cp [hl]
    sbc $e7
    ld d, c
    ld d, h
    adc l
    xor e
    adc a
    db $e3
    push bc
    inc [hl]
    inc sp
    ld c, a
    inc e
    xor h
    add a
    adc h
    db $dd
    ld a, a
    or [hl]
    or h
    jp $c3b7


    ld a, a
    cp b
    jr nc, jr_013_7e5e

    or d
    ld d, a
    ld a, h
    ld [$cc4f], a
    ld a, l
    ld [$cc50], a
    ld hl, $cc51
    ld a, d
    ld [hl+], a
    ld a, e
    ld [hl+], a
    ld a, b
    ld [hl+], a
    ld [hl], c
    ld hl, $7ed5
    ld de, $0000
    ld a, [$cc4e]
    ld e, a
    add a
    add e
    ld e, a

Jump_013_7ec4:
    jr nc, jr_013_7ec7

    inc d

jr_013_7ec7:
    add hl, de
    ld d, h
    ld e, l
    ld a, [de]
    ld [$d094], a
    inc de
    ld a, [de]
    ld l, a
    inc de
    ld a, [de]
    ld h, a
    ret


    rrca
    cp [hl]
    ld c, [hl]
    rrca
    cp d
    ld [hl], e
    rrca
    ld h, [hl]
    ld [hl], e
    dec bc
    db $e3
    ld a, [hl]
    rrca
    ld hl, sp+$73
    ld e, $f1
    ld e, d
    inc bc
    daa
    ld [hl], h
    inc bc
    db $db
    ld a, c
    ld e, $99
    ld c, l
    inc bc
    ld d, h
    ld a, d
    inc bc
    ld d, h
    ld a, d
    inc bc
    ld d, e
    ld a, e
    inc bc
    ld l, h
    ld a, e
    inc bc
    ld d, h
    ld a, d
    inc bc
    ld d, h
    ld a, d
    inc bc
    add [hl]
    ld a, e
    inc bc
    sbc h
    ld a, c
    inc bc
    add hl, bc
    ld [hl], l
    inc bc
    ret c

    ld [hl], h
    inc bc
    push de
    ld c, h
    rrca
    and e
    ld c, e
    inc bc
    ld a, [$0374]
    ld a, [$0374]
    xor c
    ld [hl], c
    inc bc
    add [hl]
    ld a, e
    inc bc
    adc l
    ld c, l
    ld c, $26
    ld [hl], e
    ld bc, $6eac
    inc bc
    ldh [$7b], a
    inc bc
    push hl
    ld a, $03
    ld e, [hl]
    ld a, $12
    db $eb
    ld b, b
    inc bc
    push af
    ld a, e
    ld [de], a
    inc bc
    ld b, c
    inc bc
    ld h, l
    ld a, h
    inc bc
    rst $18
    ld a, h
    ld [de], a
    add hl, hl
    ld b, c
    inc bc
    ld e, [hl]
    ld a, l
    inc bc
    dec de
    ld a, l
    ld bc, $58dc
    rrca
    di
    ld l, a
    stop
    ld b, b
    ld c, $af
    ld [hl], b
    inc e
    ld h, $7c
    rrca
    ld a, [bc]
    ld [hl], d
    ld bc, $588a
    inc bc
    ld c, $6d
    db $10
    ld l, c
    ld l, b
    inc e
    reti


    ld c, [hl]
    ld e, $04
    ld e, [hl]
    db $10
    ld l, c
    ld l, [hl]
    ld e, $a0
    ld e, b
    inc e
    ret


    ld d, b
    inc bc
    cp a
    ld c, e
    inc b
    sbc l
    db $76
    inc b
    sub [hl]
    ld a, b
    db $10
    ld e, b
    ld l, b
    dec d
    cp c
    ld a, [hl]
    db $10
    add [hl]
    ld h, a
    ld bc, $6234
    inc bc
    ld h, d
    ld [hl], d
    db $10
    cp d
    ld b, d
    ld c, $83
    ld [hl], e
    inc e
    ld [hl], h
    ld a, e
    inc e
    inc b
    ld h, [hl]
    inc bc
    ld b, l
    ld [hl], h
    rla
    cp h
    ld a, b

Call_013_7f9e:
    inc b
    ld b, c
    ld h, d
    inc b
    ld h, [hl]
    ld h, d
    inc e
    cp a
    ld h, e
    rla
    call c, $0340
    rla
    db $76
    inc bc
    ld e, [hl]
    ld a, l
    rrca
    ld c, c
    ld c, a
    inc e
    adc $54
    add hl, bc
    db $f4
    ld a, l
    dec b
    ld b, a
    ld a, h
    ld bc, $58db
    ld bc, $647a
    dec c
    db $d3
    ld a, l
    inc e
    xor d
    ld a, h
    inc e
    daa
    ld a, e
    inc e
    ld a, $7a
    inc e
    ld a, l
    ld a, h
    inc e
    sbc l
    ld e, a
    inc e
    nop
    ld b, b
    ld de, $428e
    ld e, $0b
    ld c, e
    ld e, $61
    ld c, d
    inc bc
    rst $30
    ld c, e
    inc bc
    ld b, h
    ld c, h
    inc bc
    add hl, hl
    ld b, l
    ld bc, $4bc8
    add hl, bc
    inc h
    ld a, [hl]
    inc bc
    xor c
    ld [hl], a
    inc b
    ld b, h
    db $76
    inc b
    ld c, e
    db $76
    rlca
    ld [hl], b
    ld b, d
    ld d, $99
    ld c, l
    sub l
    db $e3
