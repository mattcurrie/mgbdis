; Disassembly of "PokemonGreen.gb"
; This file was created with:
; mgbdis v2.0 - Game Boy ROM disassembler by Matt Currie and contributors.
; https://github.com/mattcurrie/mgbdis

SECTION "ROM Bank $00c", ROMX[$4000], BANK[$c]

    ld [hl], a
    cp d
    ld d, l
    xor d
    ld c, a
    dec [hl]
    ld a, l
    xor c
    ld [hl+], a
    db $38, $9f
    ld d, e
    sub c
    sbc b
    or h
    push hl
    and c
    sbc b
    db $e4
    adc e
    ld h, h
    adc h
    and h
    jp z, Jump_00c_4e89

    ld b, [hl]
    ld d, l
    ld h, c
    or d
    inc h
    db $10
    call z, $8668
    ld h, e
    add l
    ld c, $e2
    ld [de], a
    add hl, de
    ld [hl+], a
    add c
    ld e, [hl]
    cp $c5
    add d
    jr c, jr_00c_40a1

    cp l
    push af
    ld a, [$0585]
    adc d
    jp c, $8e86

    ld l, l
    ld b, d
    adc b
    adc c
    or $2b
    and e
    inc b
    ld e, b
    db $e4
    pop bc
    jr c, @-$0d

    ld l, c

jr_00c_4048:
    ld d, l
    ld a, [bc]
    db $38, $96
    sbc $39
    sub [hl]
    ldh [$4e], a
    ld e, a
    ld b, d
    ld [c], a
    ld l, l
    dec h
    ld c, l
    ld e, a
    adc [hl]
    ld l, e
    inc c
    or l
    pop de
    xor d
    inc sp
    ld d, h
    jp hl


    call nc, $c6c1
    sub [hl]
    adc h
    and b
    db $f4
    add sp, $4c
    sbc d
    add d
    and e
    ld d, h
    inc hl
    sbc a
    adc h
    inc [hl]
    ld l, b
    jr z, jr_00c_4048

    and e
    and c
    xor l
    inc b
    sbc [hl]
    ld b, d
    adc b
    adc h
    ldh [$d3], a
    sub c
    add e
    jp nc, $8315

    ld [hl+], a
    ld e, b
    call $ce56
    inc l
    adc e
    ldh a, [$fc]
    dec de
    adc [hl]
    add hl, de
    db $e3
    sub [hl]
    sbc h
    ld [hl-], a
    ld a, [hl+]
    ld sp, hl
    jr c, jr_00c_40ad

    db $e3
    and [hl]
    ld b, [hl]
    dec hl
    adc h
    ld [hl], h
    ld d, h
    ld a, [de]
    and e

jr_00c_40a1:
    sub l
    ld b, c
    ld [hl], h
    db $e3
    ld a, [$8d73]
    ld d, l
    ld a, [de]
    rrca
    dec l
    inc sp

jr_00c_40ad:
    ld b, [hl]
    pop bc
    ld hl, $ba37
    cp $ff
    and d
    ld e, a
    and h
    ld h, d
    rra
    ld b, [hl]
    ld h, [hl]
    ld [$8cd6], sp
    inc de
    ld b, $e6
    adc b
    or h
    inc h
    inc d
    ld d, d
    and h
    call Call_000_1d96
    ld a, c
    ld d, [hl]
    ld l, d
    ld hl, $c926
    cp b
    inc d
    add [hl]
    db $d3
    inc h
    xor b
    adc d
    xor d
    add hl, sp
    ld h, a
    db $e4
    ld de, $29a3
    ld e, b
    pop af
    ld d, b
    sub e
    sub $90
    db $e3
    add hl, bc
    ret nc

    adc l
    xor l
    and h
    daa
    sub d
    and c
    ld a, a
    ld hl, sp+$44
    inc h
    and a
    ld b, h
    ld h, d
    or c
    ld e, a
    ldh a, [rNR43]
    jp nz, Jump_00c_4299

    ld sp, hl
    xor d
    ld c, h
    ld h, b
    db $fc

jr_00c_4100:
    ld b, l
    ld b, $2f
    sbc b
    rst $08
    cp $9a
    ret


    scf
    adc l
    inc d
    ei
    ld [hl], h
    db $10
    dec h
    ld e, a
    db $fc
    ld [hl], b
    ld e, d
    add [hl]
    or h
    xor d
    cp a
    ld hl, sp-$06
    rra
    inc de
    rst $38
    sbc e
    call nz, Call_00c_4f58
    ld [hl], a
    db $e3
    ld a, a
    inc l
    db $fc
    add hl, hl
    ccf
    ld sp, hl
    sbc d
    ld d, h
    add l
    ld hl, $c44c
    jr c, jr_00c_4100

    cp c
    ld c, $5d
    ld b, [hl]
    xor c
    ld d, d
    ld c, $93
    ld a, [de]
    ldh [$f0], a
    ld b, h
    ld b, d
    sbc e
    call nz, $dcad
    add hl, hl
    cp h
    add a
    cp d
    pop af
    push bc
    dec b
    xor [hl]
    sub l
    ld [de], a
    xor c
    sub h
    rst $28
    add $e9
    adc e

jr_00c_4151:
    ld b, l
    ld a, b
    ld h, b
    jp $bd25


jr_00c_4157:
    rst $20
    dec h
    ld c, e
    ld d, l
    add hl, de
    jr nc, @-$22

    ld h, c
    ld l, a
    ret


    call Call_00c_6929
    add hl, de
    rra
    sbc c
    rst $28
    ld d, b
    daa
    inc de
    ld b, d
    sub l

Call_00c_416d:
    ld a, a
    add [hl]
    cp d
    ld h, c
    ld [bc], a
    sbc h
    ret nc

    set 0, c
    db $10
    pop hl
    di
    db $ec
    ld h, a
    ld a, d
    ld [hl], d
    or a
    ld [bc], a
    inc c
    inc e
    jr z, jr_00c_4157

    ld h, e
    jr z, jr_00c_41e5

    ld d, b
    daa
    inc b
    ld e, $12
    add hl, bc
    inc c
    ld de, $29c3
    push de
    ld h, h
    ld b, h
    ld b, b
    pop de
    sub d
    dec hl
    cp [hl]
    sbc l
    ld d, e
    dec d
    add hl, de
    ld c, d
    dec de
    push hl
    ld c, c
    or d
    ld a, [hl+]
    xor e
    push bc

Jump_00c_41a4:
    ld a, [hl-]
    ld h, l
    ld hl, sp-$2a
    ld h, e
    jr jr_00c_4151

    ld d, $96

Jump_00c_41ad:
    rst $38
    ld [$f542], a
    or c
    rst $00
    inc c
    ld c, [hl]
    inc [hl]
    ld c, e
    db $fc
    add l
    db $db
    ld [hl], b
    ld c, b
    ld e, b
    cp c
    or l
    xor $91
    jp hl


    cpl
    ld e, c
    inc e
    pop hl
    adc $14
    ld sp, hl
    ld e, $9a
    rst $18
    ldh [$c3], a
    push de
    ld h, [hl]
    dec e
    sub c
    add hl, sp
    ld sp, $e63f
    or a
    ld [bc], a
    ld [hl], c
    and $11
    ld sp, $a637
    pop af
    ret z

    sbc c
    ld b, [hl]
    scf
    rst $20
    xor a

jr_00c_41e5:
    add hl, de
    nop
    ld b, h
    cp c
    ld e, h
    ld e, l
    jr c, @+$19

    rst $38
    cp [hl]
    ld e, $64
    call $8a5a
    adc h
    ld l, $31
    ld [hl], d
    sbc a
    add hl, sp
    xor b
    add a
    db $e3
    and d
    ldh [rSCY], a
    db $d3
    xor d
    adc a
    ld de, $ebfc
    ld a, d
    dec sp
    ld l, l
    ld c, [hl]
    ld a, [$4de3]
    adc $2a
    ld d, c
    ld d, b
    db $e4
    inc a
    ld [c], a
    xor c
    pop hl
    ld b, d
    xor b
    db $e3
    or l
    add c
    sbc a
    db $e3
    sbc d
    xor b
    di
    and [hl]
    add hl, hl
    ld l, b
    ld b, h
    ld c, b
    ld [hl-], a
    ld [hl], b
    or c
    cpl
    ld b, c
    ld c, $e6
    ret c

    ld l, $31
    sbc h
    ld h, a
    sub c
    ld b, c
    rst $00
    inc sp
    ldh a, [$af]
    dec de
    ld h, $54
    ld b, e
    and $e9
    and d
    rst $00
    ld [de], a
    ld h, l
    ld de, $4658
    ret


    rst $18
    ld h, a
    ld [bc], a
    sbc b
    and b
    add e
    and $c9
    ld d, $cc
    rst $28
    rst $38
    sbc c
    and [hl]
    scf
    rst $38
    db $ed
    rst $00
    ld [hl-], a
    sub c
    cp $29
    ret


    ld d, c
    pop af
    ldh [$66], a
    cp h
    inc [hl]
    add hl, de
    ld b, e
    inc b
    pop af
    ld e, b
    inc l
    db $10

Call_00c_4269:
    cp [hl]
    reti


    jr c, @-$29

    rst $38
    rst $38
    xor b
    ld d, a
    inc c
    add hl, de
    ld b, d
    ld h, e
    add c
    ld a, [$2a85]
    ld c, b
    ldh [$a0], a
    ret z

    sub e
    add [hl]
    adc [hl]
    inc b
    ld h, c
    ld b, e
    cp b
    add h
    sbc $88
    and d
    inc hl
    ld c, h
    inc [hl]
    jr nc, jr_00c_42d0

    ld [hl], e
    ld l, d
    dec h
    dec d
    ld b, c
    ld d, d
    ld de, $82d1
    ld h, $ce
    ld e, e

Jump_00c_4299:
    ld d, h
    ld h, e
    ld a, [bc]
    rlca
    add hl, bc
    inc b
    ld [hl], h
    push bc
    ld e, h
    ret


    ld d, d
    jp nc, $a420

    jr z, jr_00c_42d9

Jump_00c_42a9:
    ld b, c
    add hl, hl
    ld a, [$8a82]
    ld h, l
    ld b, d
    ldh [rWX], a
    cp b
    ld hl, $4987
    and e
    ld b, $46
    ld h, c
    ld c, b
    ld h, e
    inc d
    inc h
    dec d
    ld h, h
    adc d
    inc hl
    add c
    ld e, c
    xor l
    ld hl, $8568
    ld d, l
    ld [$c221], sp
    ld [$2a8a], sp
    push de

jr_00c_42d0:
    ld a, [bc]
    dec b
    xor d
    dec d
    and c
    ld c, b
    sub c
    add d
    ret z

jr_00c_42d9:
    ld c, l
    dec d
    add hl, hl
    dec h
    add c
    dec h
    ld a, [hl+]
    ld b, [hl]
    dec c
    db $d3
    ld h, $54
    ld l, $2a
    ld [hl+], a
    sbc d
    add c
    db $e4
    db $76
    sbc e
    add $89
    ret c

    ld d, d
    ld h, d
    ld [hl+], a
    and l
    ld h, e
    ld c, $0a
    ld [c], a
    ld l, b
    push bc
    ld [hl+], a
    inc sp
    sbc d
    add c
    ld b, c
    rra
    add hl, bc
    inc b
    xor e
    ld d, h
    and l
    adc d
    ld c, b
    ld [hl], l
    ld e, b
    ld l, b
    adc h
    adc e
    or d
    jp hl


    or $8c
    and c
    adc d
    adc d
    ld h, b
    db $dd
    inc e
    jp nc, $aaaa

    xor b
    add hl, hl
    ld c, c
    ld b, c
    ld e, b
    add l
    add hl, bc
    adc $99
    ld [hl+], a
    xor d
    adc h
    ld de, $eba4
    and l
    ld c, h
    call c, $3c8b
    ld a, [bc]
    and a
    ld b, [hl]
    add c
    ldh a, [$cf]
    ld d, $5e
    and b
    add e
    ld b, e
    ld a, c
    adc b
    and a
    add h
    ldh [$86], a
    adc e
    call nz, Call_000_1a67
    ld [hl-], a
    xor d
    xor d
    ldh [$d8], a
    ld l, b
    ld e, [hl]
    ld sp, $21c5
    ld b, [hl]
    or a
    add h
    sbc l
    inc c
    ld [hl], c
    and e
    ccf
    and a
    dec de
    ld c, b
    ld b, [hl]
    ld hl, sp+$60
    or $09
    push bc
    call nz, $aa6a
    add hl, hl
    ld l, [hl]
    dec bc
    ld l, d
    sbc h
    ld hl, sp+$4a
    and c
    ld [hl], c
    ld a, b
    ld l, b
    ld l, a
    sbc e
    inc hl
    inc h
    ld a, b
    xor d
    sbc c
    pop hl
    add h
    ld [de], a
    ld de, $859c
    ld c, $0f
    add d
    xor d
    inc de
    db $10
    ld hl, sp-$36
    pop bc
    ld b, c
    sub a
    ld a, [$f055]
    ld d, c
    and a
    db $e4
    jr z, @+$22

    and c
    push hl
    rst $38
    xor d
    add l
    and c
    add hl, de
    ld l, $ea
    add e
    or a
    jp hl


    ld e, c
    ld e, $12
    and e
    ld [hl], a
    xor d
    xor [hl]
    inc d
    ld e, l
    ld b, b
    add h
    ld [de], a
    ld h, e
    ld [c], a
    xor c
    add l
    ld b, b
    ldh [$99], a
    call nc, $9417
    sub c
    ldh [$aa], a
    inc sp
    inc de
    ld [hl], a
    db $dd
    ld b, d
    ret


    dec de
    inc hl
    and e
    inc bc
    rst $38
    ld a, [de]
    inc h
    ld a, b
    call nc, Call_00c_5b63
    or h
    ld c, a
    pop af
    xor d
    db $10
    ld a, $0d
    ld b, d
    jp hl


    jr c, jr_00c_43ef

    dec d
    ld a, [bc]
    ld l, b
    sub c
    ld [hl], e
    push de
    ld de, $c012
    adc h
    ld h, c
    inc bc
    ld b, b
    xor d
    pop de
    ld de, $b211
    call nz, $b126
    and [hl]
    ld [hl], b
    xor b
    ld h, b
    sbc l
    ld d, h
    add hl, bc
    xor a
    or b
    ld [hl], c
    reti


    inc bc
    ld b, b
    xor d

jr_00c_43ef:
    xor e
    ld a, b
    ld d, c
    pop hl
    ld b, h
    and b
    add h
    add l
    rst $00
    adc a
    inc b
    inc c
    ld de, $0018
    ld b, h
    or a
    ld d, a
    rst $38
    rst $38
    add sp, -$20
    ld a, d
    adc h
    cp h
    db $dd
    db $e3
    ld d, a
    call $db94
    db $e3
    or l
    adc $04
    push bc
    ld e, a
    db $dd
    inc b
    call $25ea
    ld [$cc2f], a
    xor b
    add l
    rlca
    adc h
    db $fc
    ldh [$b3], a
    ld l, a
    dec sp
    cp [hl]
    dec sp
    cp h
    call $6349
    ld b, [hl]
    dec [hl]
    or [hl]
    ret z

    sub h
    ld l, $9c
    pop hl
    xor l
    ld d, l
    ld h, b
    cp h
    db $ec
    xor d
    and b
    xor d
    adc a
    inc de
    ld l, [hl]
    add e
    ld a, [hl+]
    xor d
    xor d
    ld [hl], b
    and c
    dec e
    adc h
    sub $e7
    dec sp
    dec d
    rst $00
    ld b, h
    ld b, d
    add hl, bc
    jp nc, $c4a4

    inc hl
    rst $38
    cp $66
    adc d
    ld d, [hl]
    ld de, $cac7
    ret


    ld c, l
    ld l, c
    jp $dc0a


    ld sp, $701c
    call $b4c5
    db $76
    rst $00
    ld l, $60
    sbc l
    inc [hl]
    dec c
    ld hl, $d2a2

Call_00c_4470:
    xor c
    pop bc
    ld b, $2c
    db $10
    ld a, l
    add d
    xor d
    sbc h
    or b
    jp $9047


    ld [hl], a
    sub a
    rst $38

Jump_00c_4480:
    rst $38
    ld d, l
    inc a
    xor d
    ld [hl-], a
    xor c
    ld sp, hl
    ld d, e
    call nz, $8253
    and [hl]
    sub h
    ldh a, [rHDMA4]
    db $e3
    sub c
    sub e
    ret nz

    or h
    db $e3
    sub c
    sub d
    push de
    ld c, [hl]
    ld l, e
    ld d, e
    ld [hl], l
    ld [hl], b
    ld d, h
    ld e, d
    ld d, h
    add hl, hl
    add hl, hl
    ld c, l
    xor e
    call nc, $be14
    dec e
    sub b
    and l
    ld a, [bc]
    ld [hl], l
    inc b
    ld e, [hl]
    and e
    add [hl]
    or b
    ld sp, hl
    ld e, h
    sbc l
    ld a, [hl+]
    cp l
    add hl, de
    rra
    add l
    ld c, [hl]
    ld c, d
    ld sp, hl
    dec b
    adc h
    sbc d
    cp l
    daa
    cp a
    adc [hl]
    ld h, l
    db $fc
    db $e4
    adc c
    adc [hl]
    ld b, l
    ld a, a
    rst $28
    ld h, h
    ld d, a
    sub d
    and l
    ld h, d
    sub a
    adc l
    sbc a
    cp a
    xor e
    ret nc

    ld h, h
    db $10
    jp nz, $7a63

    db $fd
    ld [hl-], a
    rst $30
    sub $aa
    dec d
    ld h, l
    sub c
    ld h, h
    ld [de], a
    dec d
    db $f4
    ld l, d
    sbc a
    db $d3
    sub c
    jp hl


    add [hl]
    ld l, l
    adc c
    rst $38
    rst $38
    call z, Call_00c_4e29
    dec b

jr_00c_44f5:
    rst $38
    adc e
    sub b
    ld b, [hl]
    ldh a, [$bf]
    db $e4

Call_00c_44fc:
    inc h
    xor d
    scf
    ld a, d
    ld [$e4d2], sp
    add l
    ld a, [$796e]
    ld d, b
    db $d3
    ld b, a
    adc [hl]
    inc l
    sbc b
    jp $fd69


    db $e3
    scf
    adc [hl]
    scf
    dec [hl]
    or d
    ld a, [hl-]
    dec [hl]
    and e
    sub a
    call $84b8
    sub $8e
    ld l, h
    rst $18
    add hl, bc
    ld [hl], $a3
    sbc a
    ret c

    ld h, d
    sbc l
    push de
    jr jr_00c_44f5

    adc [hl]
    ld b, a
    ld a, [hl]
    ld a, [hl+]
    ld b, a
    cp $0b
    inc d
    xor $ff
    adc e
    ld h, [hl]
    ld d, b
    db $ec
    jr nz, jr_00c_457c

    ld sp, $8da3
    cp b

jr_00c_453f:
    sub l
    ld h, d
    dec h
    ld a, [bc]
    dec b
    cp l
    db $f4
    and $5a
    ld hl, $335a
    xor d
    ld h, $d0
    or l
    jr c, jr_00c_4567

    dec b
    xor d
    ld a, [hl-]
    xor l
    ld a, [bc]
    add d
    adc h
    ld d, $81
    ld h, e
    jp nz, $46b5

    ld [$16a8], a
    adc a
    ld e, $87
    ld b, h
    xor d
    xor h

jr_00c_4567:
    ld b, d
    ld a, c
    ld [hl], b
    ld c, b
    add hl, hl
    dec d
    ld [bc], a
    jp nz, Jump_000_269e

    add d
    inc c

jr_00c_4573:
    inc de
    jp z, $034d

    ld [bc], a
    ld a, b
    ld a, [hl-]
    inc d
    ld [de], a

jr_00c_457c:
    jr z, jr_00c_453f

    ld d, c
    jr nc, jr_00c_45a8

    add l
    inc h
    jp nz, Jump_000_0c8b

    dec e
    ld hl, $9229
    ld [hl], e
    ret nz

    sub l
    ld d, b
    ld b, e
    inc de
    inc bc
    ld [de], a
    or a
    add e
    ld d, $9b
    ret nz

    ret nz

    add d
    sub c
    dec l
    add a
    ld a, d
    sub c
    inc l
    add d
    xor c
    add hl, sp
    rst $00
    inc b
    add l
    xor e
    xor e
    xor b

jr_00c_45a8:
    ld d, b
    ld a, [hl+]
    ld a, [hl-]
    ld [de], a
    ld a, [de]
    sbc $19
    ret


    dec c
    jp z, Jump_000_3afd

    jr jr_00c_4573

    ld a, [$024d]
    ld [hl], e
    and d
    db $fd
    ld [bc], a
    or a
    sub d
    and e
    ld l, h
    ld [hl], e
    and e
    xor e
    jp nc, $d58b

    jr nc, jr_00c_460f

    ld d, l
    rst $00
    ld c, $bf
    add sp, $55
    ld [bc], a
    inc d
    or d
    ld h, [hl]
    xor c
    inc [hl]
    sbc d
    ld h, h
    ld d, d
    ld c, h
    ld b, e
    ld a, [hl-]

Jump_00c_45db:
    xor e
    ld de, $d702
    db $eb
    ld c, l
    rlca
    dec e
    inc de
    jp $a160


    pop hl
    inc de
    rlca
    and $14
    add hl, bc
    ret nz

    sub b
    pop af
    add l
    inc c
    dec e
    inc de
    call nc, Call_00c_4808
    dec l
    inc e
    ld [de], a
    add $2b
    ld b, c
    ld hl, $b55a
    ld [hl], h
    db $10
    jr z, @-$25

    cp e
    jr jr_00c_462f

    ld b, [hl]
    cpl
    ld b, d
    sub c
    dec a
    dec a
    sbc e
    or c

jr_00c_460f:
    add e
    jr jr_00c_4638

    jr nc, @-$2c

    ld b, d
    ld sp, $0cae
    ld l, d
    sub [hl]
    sbc e
    and d
    sbc e
    ld h, b
    sbc b
    jr z, jr_00c_4665

    and [hl]
    ld c, c
    ld [$442a], sp
    sbc e
    ld h, b
    sbc b
    ld b, [hl]
    push af
    rrca
    ld b, l
    ld b, b
    xor b

jr_00c_462f:
    ld b, [hl]
    ld a, b
    inc h
    or h
    ld h, [hl]
    or l
    rla
    ld b, c
    ld c, c

jr_00c_4638:
    ld d, [hl]
    add hl, bc

jr_00c_463a:
    sub $b1
    and e
    dec b
    xor b
    ld [hl], $12
    add hl, bc
    sub [hl]
    db $10
    or c

Call_00c_4645:
    add d
    ld de, $1492
    sub l
    ld c, a
    or h
    inc de
    inc b
    ld h, c
    ld sp, $5168
    ld c, d
    add l
    ld hl, $971c
    ld [c], a
    adc d
    add hl, bc
    ld [$6c51], sp
    sub c
    dec e
    db $76
    jr nc, jr_00c_463a

    ld b, c
    ld d, $84

jr_00c_4665:
    sbc [hl]
    ld d, l
    ld [bc], a
    xor d
    ld [de], a
    ld de, $80e5
    ld b, h
    or l
    ld e, a
    rst $38
    rst $38
    push af
    scf
    ld a, d
    dec [hl]
    and e
    db $e4
    inc de
    cp [hl]
    ld h, h
    rst $28
    sbc d
    ld d, e
    or [hl]
    sub [hl]
    ld d, e
    sbc l
    ld d, l
    ld b, d
    ld b, $52
    inc de
    add d
    ld e, a
    db $fc
    inc l
    ld l, d
    add hl, sp
    ld a, [hl+]
    db $f4
    adc e
    dec sp
    jr z, jr_00c_46b3

    ld d, e
    or d
    ld [hl], b
    sub e
    or [hl]
    call c, Call_00c_5df8
    and $af
    rst $18
    ld d, l
    ld d, d
    sbc h
    ld [$d445], sp
    ld a, [bc]
    sbc [hl]
    sbc h
    sbc l
    or d
    jr nc, jr_00c_46d2

    ld h, h

jr_00c_46ac:
    and e
    dec b
    daa
    ld d, l
    dec h
    ld d, d
    ld [hl], h

jr_00c_46b3:
    jp c, Jump_000_3e9d

    xor a
    or h
    and a
    dec a
    ld c, a
    inc [hl]
    rst $20
    ld h, d
    ld a, [$ff76]
    dec e
    push de
    rra
    ld a, [bc]
    ld h, [hl]
    cp e
    ld e, a
    rst $38
    ld d, l
    rst $38
    ld c, [hl]
    rst $10
    call nc, $a2ba
    ld l, l
    ld a, [hl-]

jr_00c_46d2:
    xor b
    ld h, e
    adc c
    ld c, a
    adc c
    or h
    push de
    ld hl, $8e22
    xor e
    ld d, e
    add hl, hl
    dec d
    ld [hl-], a
    ld d, h
    dec d
    jr c, jr_00c_4710

    ld c, c
    pop de
    ld d, d
    xor b
    sbc d
    xor a

Jump_00c_46eb:
    adc $4b
    pop de
    or h
    inc d
    jr z, jr_00c_46ac

    adc c
    xor l
    jr c, @+$21

    db $fd
    dec de
    ld d, h
    or a
    add d
    ld [hl+], a
    cp a
    add c

jr_00c_46fe:
    ld d, l
    jr nc, @-$5c

    rra
    pop de
    ld d, [hl]
    dec b
    inc [hl]
    xor d
    xor d
    xor e
    ret nc

    ld e, [hl]
    rla
    ld [hl+], a
    or h
    ld d, e
    dec [hl]

jr_00c_4710:
    dec d
    ld h, c
    adc c
    ld e, c
    add sp, $7e
    ld a, [de]
    and b
    ld e, b
    or l
    ld b, d
    ld b, d
    ld a, [bc]
    ld [hl-], a
    xor b
    push bc
    ld a, b
    ld [hl+], a
    jr z, jr_00c_46ac

    add h
    dec de
    ld h, e
    and d
    sub a
    xor b
    ld h, d
    ld [$35b5], a
    push de
    ld sp, $1afa
    scf
    xor a
    ld c, h
    ld [$55fd], a
    ld d, l
    ld hl, sp-$7b
    scf
    or h
    sbc $aa
    xor c
    push de
    ld a, b
    inc hl
    add d
    db $d3
    sbc [hl]
    xor b
    adc d
    jr c, jr_00c_46fe

    db $eb
    ld d, e
    add l
    ld b, d

jr_00c_474e:
    db $f4
    rst $20
    ld d, e
    add l
    ld b, c
    ld [hl+], a
    db $d3
    adc l
    db $e3
    add [hl]
    sbc [hl]
    ld [$4d9d], sp
    sbc [hl]
    jr c, jr_00c_474e

    rlca
    adc d
    xor a
    ld d, l
    ld d, l
    cp $39
    db $ed
    ld d, l
    ld [c], a
    xor d
    xor d
    adc l
    rst $20
    ld l, e
    inc h
    ld c, b
    cp d
    rst $20
    add c
    sub e
    dec h
    ret z

    ret


    rst $10
    ld de, $c924
    ld d, d
    ld a, $9d
    ld a, [hl+]
    ld c, h
    sub e
    dec h
    ld l, a
    and a
    ld d, l
    add hl, hl
    ld [de], a
    ld c, h
    add e
    rst $38
    pop af
    reti


    ret


    ld [de], a
    cpl
    rst $38
    cp $94
    sub b
    add d
    ld [hl], c
    ret


    rra
    rst $38
    rst $38
    push bc
    ld b, h
    and b
    sbc h
    sub b
    ld e, a
    rst $38
    rst $38

Call_00c_47a1:
    db $e4
    or [hl]
    ld c, e
    jp hl


    jp nz, $dfc4

    rst $38
    cp $47
    ld b, l
    jp $2645


    add hl, bc
    ld c, $8d
    rst $38
    rst $38
    dec de
    ldh [$91], a
    ld a, d
    adc d
    ld b, e
    rst $18
    jp $e6ff


    call z, $c862
    ld b, h
    ld d, h
    rrca
    db $fc
    scf
    ld a, [$9d44]
    ld l, d
    rst $38
    jp hl


    rla
    rst $00
    add a
    rst $38
    ld a, [$9945]
    ld c, c
    or [hl]
    ld a, [bc]
    sub d
    rst $38
    rst $38
    dec d
    sbc d
    add $f0
    ld e, l
    ld d, l
    ld e, b
    ld b, h
    cp [hl]
    ld [hl], b
    ld c, c
    rst $08
    db $10
    cp a
    and a
    inc c
    sbc l
    rra
    ld sp, hl
    rst $00
    inc b
    and a
    daa
    rst $38
    rst $00
    inc d
    ld b, e
    daa
    rrca
    rst $38
    inc e
    ld [hl], e
    adc l
    ld a, [$ff6a]
    rst $00
    inc e
    ldh a, [$e1]
    db $e3
    add d
    ld h, b
    rst $38
    rst $00
    ld c, e
    rst $08

Call_00c_4808:
    and h
    ld b, c
    push de
    ld d, a
    inc b
    ld [hl], h
    pop bc
    add l
    sbc l
    ret nz

    ld b, h
    cp d
    rla
    di
    and c
    ld a, [hl]
    adc [hl]
    sub a
    and e
    xor c
    ld hl, sp-$15
    ld a, b
    db $e4

jr_00c_4820:
    ld d, c
    ld e, a
    ld hl, sp-$19
    cp d
    adc [hl]
    or l
    ld d, e
    or [hl]

Jump_00c_4829:
    and e
    add l
    ld e, a
    di
    adc e
    ld c, e
    xor b
    call $b04c
    sub l
    jr c, jr_00c_48a1

    ld c, b
    rst $10
    xor d
    cp l
    ld c, l
    xor l
    ld c, c
    db $ec
    cp d
    db $d3
    ld [hl], a
    ld a, [$ef8c]
    ld c, a
    ld [bc], a
    inc a
    ld e, c
    jp nc, Jump_00c_5ac7

    ld de, $1dd9
    xor h
    db $76
    or c
    ret z

    sub b
    add h
    ld sp, $8cce

Jump_00c_4857:
    ld [hl], e
    ld h, [hl]
    inc l
    ld [hl], d
    cp c
    ld [hl], c
    sub d
    sbc b
    ld hl, $2fc7
    and a
    ld e, $a6
    ld c, $d4
    and a
    inc b
    sub l
    ld [hl], c
    ld [hl], b
    ld c, d
    ld b, d
    ld h, l
    ld [bc], a
    rrca
    inc bc
    add hl, de
    ld e, a
    sbc e
    rst $00
    dec b
    rra
    ld a, [bc]
    ld d, l
    cp a
    inc sp
    or l
    ld d, b
    ld d, e
    pop bc
    rst $30
    db $eb
    db $e4
    db $eb
    ld a, b
    ccf
    inc d
    ld [hl+], a
    inc d
    add l
    jr c, jr_00c_4820

    rra
    db $e4
    cp d
    and [hl]
    xor b
    db $e4
    ld h, a
    jp c, $f826

    ld l, $ce
    ld c, d
    xor d
    add c

jr_00c_489b:
    ld hl, $7451
    inc de
    adc l
    ld d, l

jr_00c_48a1:
    ld d, b
    ld d, h
    ld l, d
    dec d
    ld c, [hl]
    dec de
    ld b, d
    cp $05
    jr jr_00c_48d4

    adc [hl]
    ld d, e
    adc d
    sub l
    ld e, b
    ld de, $fa52
    jr c, jr_00c_489b

    ld l, $e0
    and h
    add l
    ld c, [hl]
    ld l, d
    ld d, [hl]
    adc e
    ld c, b
    and e
    xor c
    ld e, a
    db $fd
    adc b
    db $e3
    xor d
    xor a
    cp $56
    ld a, $ee
    ld a, [hl]
    or a
    dec h
    jr nc, jr_00c_48f7

    ld a, l
    dec b
    ld b, $1e

jr_00c_48d4:
    ld [hl], l
    cp c
    cpl
    or [hl]
    jp nz, $b9e8

    rst $00
    db $ed
    dec b
    ld a, d
    ld a, $46
    add hl, hl
    rst $00
    pop af
    ld d, a
    adc l
    adc e
    adc d
    ld [hl], c
    ccf
    sub l
    ld a, [c]
    adc e
    ret z

    ld d, c
    ret


    ld a, [hl]
    rst $38
    ld a, a
    add d
    di
    and a
    scf

jr_00c_48f7:
    ld d, [hl]
    rst $38
    pop bc
    ld c, a
    ret


    pop de
    ld e, a
    pop de
    add e
    rst $20
    adc l
    ld c, [hl]
    ld [hl], l
    and b
    call nz, $fc40
    ld [hl], a
    call nz, $e047
    nop
    ld b, h
    cp [hl]
    ld c, c
    ld a, a
    jp c, Jump_00c_7a4e

    rst $38
    ld c, b
    adc $35
    ld a, a
    ld a, l
    add l
    jr c, jr_00c_493c

    xor e
    and b
    and b
    add [hl]
    scf
    and d
    ld [c], a
    ld de, $3a42
    ld hl, $cede
    add [hl]
    dec d
    ld d, [hl]
    scf
    ld h, a
    or $f0
    xor b
    db $e4
    sbc d
    ld b, l
    ld a, [hl-]
    xor h
    ld a, [de]
    ret c

    add sp, -$58
    ei

jr_00c_493c:
    add hl, hl
    ld a, [c]
    ld c, b
    ld b, b
    ldh [$a7], a
    ld d, h
    jr nc, @+$4c

    sbc h
    ld [$0c29], a
    ld [hl], c
    ld e, a
    or a
    add a
    add e
    ld h, [hl]
    pop af
    ccf
    db $ec
    inc c
    ld e, $70
    db $eb
    rst $38
    pop hl
    dec c
    inc e
    ld e, a
    rst $38
    ldh a, [$27]
    dec l
    ld [hl], b
    ld e, e
    sbc l
    ldh a, [rBCPD]
    ld sp, hl
    ld h, b
    ld d, l
    cp [hl]
    ld a, l
    ld d, l
    ld d, l
    dec sp
    rla
    db $fd
    rlca
    add $e9
    ld d, e
    adc l
    db $eb
    add [hl]
    ld a, [c]
    xor l
    dec b
    and h
    ldh [$bf], a
    ld l, c
    dec de
    ld c, b
    ld a, b
    dec hl
    reti


    jr c, @-$51

    or b
    jp Jump_000_30de


    or [hl]
    ld c, [hl]
    jr z, jr_00c_49bb

    ret nc

    add d
    and l
    ld l, $14
    ld [c], a
    sub b
    adc e
    ld d, b
    and h
    db $eb
    ld d, d
    ld e, c
    adc c
    adc e
    adc [hl]
    ld b, l
    add hl, de
    ld [hl], l
    rla
    ld c, [hl]
    cp d
    ld a, [hl+]
    cp e
    ld d, d

jr_00c_49a4:
    db $d3
    sub [hl]
    ld [c], a
    ldh [rHDMA5], a
    inc a

jr_00c_49aa:
    ld c, e
    ld b, l
    inc a
    ld e, e
    or h
    pop af
    xor l
    jr jr_00c_49a4

    ld l, d
    ld a, $ea
    ld a, h
    ld a, [$9d60]
    adc b

jr_00c_49bb:
    ld l, a
    or a
    ld c, d
    and c
    adc d
    ld [hl], e
    ld e, a
    db $fc
    rst $18
    cp $de
    rst $20
    inc d
    db $10
    ld e, [hl]
    dec d
    or a
    ld a, [c]
    xor l
    ld l, c
    adc $c8
    ld e, e
    ccf
    rst $38
    or [hl]
    add hl, de
    rr b
    rst $30

Call_00c_49d9:
    rst $38
    and e
    sbc h
    rst $18
    cp $e8
    rst $18
    call z, $c709
    rrca

jr_00c_49e4:
    rst $38
    rst $38
    and c
    dec sp
    ld sp, $0fc9
    db $e3
    ld e, a
    ld hl, $9c7c
    add sp, $26
    inc d
    inc [hl]
    and c

jr_00c_49f5:
    sbc [hl]
    rlca
    pop hl
    ld l, h
    ld a, b
    ld d, [hl]
    add h
    rst $00
    adc d
    add e
    daa
    adc l
    daa
    db $e4
    ld b, b
    ld b, h
    dec sp
    inc de
    cp c
    adc [hl]
    sub $39
    ld h, h
    or [hl]
    add hl, sp
    sub b
    db $f4
    ld d, h
    cp b
    ldh [rOBP0], a

Jump_00c_4a14:
    ld e, d
    jr nc, jr_00c_49aa

    ld [hl], h
    xor e
    ld c, c
    ld l, e
    call $c758
    sub b
    adc b
    ld c, l
    jr jr_00c_49e4

    ld h, d
    ld hl, $4c60
    ld d, $d4
    dec d
    pop hl
    ld d, c
    ld e, b
    jr jr_00c_49f5

    ld l, l
    inc hl
    dec d
    sub [hl]
    sub [hl]
    adc l
    and a
    ld a, [bc]
    add l
    ld a, [hl]
    adc [hl]
    ld e, d
    xor d
    ld a, $ca
    ld a, e
    sub c
    jp c, Jump_00c_75fe

    xor e
    ld d, c

jr_00c_4a45:
    call nz, Call_00c_4de9
    cp $71
    ccf
    and e
    cp $b1
    call nz, $faff
    rla
    ret nz

    or c
    or e
    rst $38
    rst $38
    ld c, b
    cp a
    ld a, [de]
    cp a
    rst $38
    ret nc

    cp a
    ldh a, [rDMA]
    ld e, e
    call nc, $2b09
    ld a, l
    ld sp, $0aaa
    inc de
    dec b
    adc $86
    ld de, $c5c3
    inc h
    ld b, a
    pop hl
    and b
    ld [hl], a
    cp l
    push bc
    xor c
    ld d, l
    ld d, l
    ld d, a
    rst $38
    sub e
    cp l
    adc b

jr_00c_4a7e:
    ld b, c
    add hl, hl
    ld d, h
    ld [hl+], a
    ld d, [hl]
    jp nc, $5455

    and $70
    cp l
    ld b, d
    ld [hl+], a
    adc h
    sub h
    ld e, $d4
    ld l, d
    sub h
    pop hl
    or [hl]
    ld a, [bc]
    inc b
    ld d, h
    jp nc, $a1b2

    ld d, h
    ld a, [de]
    ld c, h
    and a
    ret c

    add [hl]
    xor l
    ld sp, $9452
    dec hl
    rst $10

Call_00c_4aa5:
    db $fd
    cp $4b
    ld d, [hl]
    db $fd
    jr jr_00c_4a45

    dec h
    ld d, l
    ld b, c

Jump_00c_4aaf:
    ld b, c
    xor $21
    ld a, [hl]
    xor d
    xor l
    ld h, $42
    ld a, [bc]
    call c, $9c24
    rra
    ld [hl+], a
    ld [c], a
    db $e4
    ld e, $89
    ld d, a
    rst $30
    ld c, c
    xor a
    rst $30

Call_00c_4ac6:
    sub $b9
    cp b
    or h
    ld e, d
    ld b, [hl]
    push de
    ld e, d
    add sp, -$6b
    inc sp
    xor e
    rst $38
    ld d, d
    ret c

    inc e
    ld h, $4a
    xor d
    xor d
    ld d, a
    db $e3
    add [hl]
    xor d
    ld l, $16
    rlca
    ld [hl], d
    xor d
    xor e
    ld l, d
    jr c, jr_00c_4a7e

    rst $38
    rlca
    ld c, b
    or [hl]
    ld b, $0c
    xor a
    rst $38
    jr c, jr_00c_4b06

    ld e, a
    and c
    ld b, a
    ld hl, sp-$36
    adc d
    ld l, d
    xor d
    ld c, h
    jp c, $a20a

    ld a, [de]
    or h
    ld [hl+], a
    db $d3
    ld c, d
    xor d
    sub e
    dec a
    ld l, b

jr_00c_4b06:
    sub [hl]
    push bc
    and b
    or h
    sub h
    push bc
    dec d
    ld a, a
    and b
    or h
    db $dd
    jp hl


    ld h, d
    ld d, h
    ld a, [hl+]
    add c
    ld l, d
    ld [$de66], sp
    cp a
    ld e, [hl]
    ld c, h
    sbc $07
    adc d
    ld d, d
    call nc, Call_00c_6bcd
    push af
    ld [$c1b4], a
    ld b, c
    sub d
    call nc, $b4e5
    adc d
    cp a
    push af
    add hl, hl
    ld e, h
    push bc
    ld d, e
    ld d, h
    ld l, b
    and [hl]
    push de
    jr nc, jr_00c_4b8c

    dec d
    ld c, b
    sub b
    ld d, l
    ld sp, $a752
    and h
    sbc e
    db $eb
    db $fd
    ld d, h
    add $48
    add [hl]
    dec d
    dec [hl]
    and d
    dec l
    ld d, l
    dec c
    ld h, $ad
    dec de
    xor d
    ld d, b
    ld l, b
    pop hl
    xor d
    ld a, [de]
    add hl, bc
    jp hl


    ld l, a
    ld c, b
    ld d, d
    sbc d
    ld d, d
    xor b
    add l
    dec [hl]
    and h
    inc d
    ld d, h
    ld d, h
    ld l, a
    sub d
    ldh [$50], a
    ld b, d
    ld c, d
    ld h, e
    add hl, hl
    ld [hl+], a
    ld h, h
    inc h
    inc d
    ld d, h
    rla
    adc h
    ret c

    sbc c
    ld b, $22
    ld e, b
    ld e, c
    ld l, $48
    and b
    xor c
    add sp, -$3f
    ld a, [hl-]
    jr nz, jr_00c_4bd0

    xor d
    xor d
    and e
    ld e, c

jr_00c_4b88:
    ld c, b
    ld d, [hl]
    xor d
    and l

jr_00c_4b8c:
    ld c, c
    ld h, e
    jp $daa8


    xor b
    ldh a, [$27]
    cp b
    add h
    inc [hl]
    ld h, h
    ret


    ld de, $30e0
    cp e
    inc h
    ld sp, $e310
    ld [c], a
    sub d
    sub d
    sbc h
    jp c, $c44c

    jp Jump_000_209a


    add h
    sub e
    ld [bc], a
    ld l, d
    add d
    add e
    db $10
    and h
    jr nc, @-$18

    jr nc, jr_00c_4bef

    ld hl, $8384
    ld [bc], a
    add $b0
    ld b, h
    inc a
    ld h, e
    jr nz, jr_00c_4b88

    inc sp
    ld a, [bc]
    ld b, h
    add h
    add hl, hl
    add a
    inc h
    ld c, d
    ld [de], a
    ld c, [hl]
    jp Jump_00c_6b8f


    dec bc

jr_00c_4bd0:
    dec bc
    ld a, [bc]
    jp nc, $17ad

jr_00c_4bd5:
    ld hl, $d024
    ld c, e
    ld b, $f7
    ld hl, $0a71
    ld d, $4a
    ret nc

    jr nz, @-$3b

    rla
    ld d, b
    ld c, d
    ld [$d3c2], sp
    jr nc, jr_00c_4bd5

    dec a
    ld h, e
    inc [hl]
    ld c, h

jr_00c_4bef:
    add d
    push de
    dec de
    ld b, c
    add e
    ld [bc], a
    ld e, h
    and $96
    xor d
    add sp, -$5f
    dec e
    cp a
    add d
    add hl, bc
    adc l
    ld d, l
    or c
    ret z

    add [hl]
    db $10
    call z, $f4e8
    ld a, [hl-]
    and $69
    cp d
    and e
    add h
    ld c, [hl]
    add a
    di
    jr jr_00c_4c64

    cpl
    xor d
    jp hl


    sbc e
    ld b, b
    add $10
    ei
    inc sp
    ld c, $62
    push de
    ld d, l
    ld h, c
    sbc c
    ld l, l
    rla
    xor b
    inc a
    jp nc, $f28b

    ld c, e
    sub d
    and a
    ld b, e
    ld b, b

jr_00c_4c2e:
    jp $3705


    call Call_00c_44fc
    adc d
    adc l
    ld [bc], a
    sbc e
    and c
    dec bc
    rla
    ld b, c
    ld l, h
    call z, $ccc4
    inc a
    ld a, [bc]

Call_00c_4c42:
    ld h, b
    sbc b
    inc h
    and $19
    add hl, sp
    db $10
    ld b, h
    and e
    inc h
    ld d, d
    or h
    ld d, d
    ld d, d
    add hl, de
    add hl, bc
    db $76
    ld b, [hl]
    ld h, e
    and e
    inc c
    add h

jr_00c_4c58:
    jr z, jr_00c_4c2e

    xor d
    and h
    ld hl, $0583
    xor b
    push hl
    ld h, e
    and $49

jr_00c_4c64:
    ld [de], a
    ld b, d
    call nz, $4b26
    ld h, $18
    ld e, b
    and $09
    ld [$9120], sp
    ld c, b
    jp nc, Jump_000_0d93

    pop bc
    ld b, $0c
    add d
    ld [de], a
    ld c, h
    sub a
    dec c
    ld hl, $2048
    add [hl]
    add h

Jump_00c_4c82:
    dec [hl]
    ld b, h
    ret z

    db $e4
    ret z

    ld b, c
    add [hl]
    ld b, [hl]
    ld d, d
    ld c, e
    or e
    adc e
    jr nz, jr_00c_4c58

    ld b, e
    inc d
    adc [hl]
    ld c, $13
    sub c
    ldh a, [rNR42]
    and h
    ld hl, $2115
    ld l, b
    ld [hl-], a
    ld [$d466], sp
    ld c, h
    add a
    ld de, $0f7c
    ld b, [hl]
    add hl, hl
    add d
    ld l, c
    and [hl]
    add hl, hl
    cp e
    dec e
    db $f4
    and b
    and c
    rla
    ld b, b
    and d
    rst $00
    res 0, b
    ld b, h
    or l
    ld d, l
    ld c, d
    ld e, d
    and e
    ld h, l
    adc d
    xor d
    adc [hl]
    ld h, $33
    ld d, d
    ld a, [de]
    adc [hl]
    ld d, l
    ld hl, $e308
    ld a, c
    dec h

Jump_00c_4ccc:
    ld c, [hl]
    ld c, b
    adc [hl]
    add l
    dec b
    ld a, [de]
    jr c, jr_00c_4d3b

    ld hl, $259a
    ld c, [hl]
    add hl, sp
    jp hl


    dec b
    dec h
    ld c, [hl]
    ld c, a
    ld a, [hl+]
    xor d
    dec b
    inc sp
    ld l, d
    cp $aa
    ld c, [hl]
    ld c, c
    ld h, d
    ld d, a
    ld hl, sp+$13
    adc l
    xor a
    add sp, -$65
    sub b
    ld l, b
    db $d3
    ld e, b
    jp c, $a23e

    ld l, d
    xor d
    sub h
    or l
    ld b, [hl]
    xor e
    pop de
    ld [hl], l
    db $10
    xor c
    and a
    add hl, de
    ld a, $2f
    ld sp, hl
    ret nz

    sub e
    and c
    add [hl]
    dec e
    reti


    and d
    jr c, @-$36

    db $76
    ld b, d
    add hl, de
    cp h
    adc h
    ld b, l
    add l
    sub c
    ld c, c
    pop bc
    ld l, b
    ld a, $08
    ld c, b
    pop bc
    daa
    dec d
    sub $be
    cp $1e
    ld [hl], c
    ld hl, $5711
    db $fd
    sbc c
    dec a
    inc l
    ld e, h
    ld e, l
    ld b, [hl]
    ld [hl], l
    ld b, h
    inc h
    rst $08
    daa
    dec bc
    adc $67
    inc bc
    pop af
    and [hl]
    rst $00
    db $db

jr_00c_4d3b:
    add b
    ld [hl], a
    xor c
    ld e, e
    rst $38
    ld sp, hl
    ld c, l
    dec d
    db $fd
    ld d, e
    sub c
    ld a, [$09a3]
    ld [$a5c1], sp
    ld h, $0f
    ld c, [hl]
    ld a, [de]
    ld hl, $8b56
    add d
    dec h
    db $eb
    rst $30
    ld e, b
    add l
    scf
    and d
    ld h, h
    sub h
    cp b
    jr nz, jr_00c_4dd8

jr_00c_4d60:
    ld l, b
    sbc b
    add h
    and $d0
    ld c, d
    sub b
    ld [hl], c
    jp nz, Jump_00c_4829

    ld h, b
    ld h, c
    sub e
    adc c
    dec bc
    ld sp, $d2d2
    add hl, de
    add sp, $18
    push hl
    ld d, b
    ld d, [hl]
    ld a, [hl+]
    ld [$c2a8], sp
    jr jr_00c_4d60

    ld d, b
    ld a, [hl]
    ld b, c
    ld b, d
    ret


    ld h, d
    push de
    add hl, de
    ld h, b
    ld b, l

jr_00c_4d89:
    inc d
    sbc b
    and a
    ld [$bd8b], a
    ld l, d
    ld [hl+], a
    sub a
    or e
    ld a, [hl+]
    ld hl, $1922
    ld a, [bc]
    jr c, jr_00c_4d89

    rst $20
    ld d, h
    ld [hl+], a
    cp l
    ld c, b
    ld h, c
    ld h, b

Jump_00c_4da1:
    adc b
    adc e
    sub e
    ld d, l
    jr jr_00c_4dcd

    ld [$09c6], sp
    add hl, bc
    ld h, b
    ld h, d
    db $e4
    sub h

jr_00c_4daf:
    inc hl
    ld b, l
    inc b
    db $10
    pop af
    sub d
    pop hl
    ld c, c
    ld b, c
    adc h
    add hl, hl
    ld e, b
    pop de
    ld e, [hl]
    xor a
    ld h, d
    inc hl
    ld l, a
    ld c, l
    add hl, de
    ld e, b
    and l
    add sp, $5f
    and d
    ld e, b
    push bc
    ld [hl+], a
    ld [hl+], a
    ld c, h

jr_00c_4dcd:
    ld d, e
    ld e, h
    add a
    add l
    ld hl, sp+$13
    inc b
    ldh a, [rOCPD]
    ld a, [c]
    inc e

jr_00c_4dd8:
    jr jr_00c_4daf

    ld [hl-], a
    ld c, h
    ld h, l
    scf
    and d
    dec h
    ld [hl-], a
    ld c, h
    inc d
    ld d, d
    jp c, $b990

    inc sp
    xor h

Call_00c_4de9:
    ld de, $b454
    ld a, [de]
    xor c
    ld a, [de]
    ld l, $25
    ld h, e
    ld e, d
    jr jr_00c_4e23

    push de
    ld e, d
    ld h, l
    db $fc
    inc [hl]
    db $ed
    and b
    ld e, b
    dec e
    ld c, b
    ld d, [hl]
    ld [$1add], sp
    ld c, b
    ld c, h
    ld e, a
    jp Jump_00c_46eb


    ld l, d
    dec hl
    rst $38
    ldh [$cc], a
    add hl, hl
    ld a, [de]
    ld a, [de]
    rla
    push de
    ld a, [de]
    ld [hl-], a
    sub d
    ld d, e
    ld [$22c5], sp
    sub l
    ld c, b
    ld c, c
    add d
    sub [hl]

Jump_00c_4e1f:
    ld b, l
    ld c, h
    ld h, b
    xor a

jr_00c_4e23:
    jp hl


    ld h, e
    add [hl]

jr_00c_4e26:
    and d
    db $10
    ld h, d

Call_00c_4e29:
    sbc l
    ld h, d
    ld h, d
    inc d
    dec l
    inc c
    db $ec
    add d
    ld [hl+], a
    ld c, h
    ld d, d
    dec h
    and a
    pop bc
    ld l, b
    cp b
    reti


    ld h, c
    ld d, [hl]
    and h
    and [hl]
    ld [hl+], a
    ld [hl+], a
    sub a
    push de
    adc c
    ld h, e
    add c
    ld c, b
    ld d, [hl]
    add hl, de
    ld e, b
    add [hl]
    ld [hl-], a
    xor c
    ld d, [hl]
    adc [hl]
    dec sp
    and d
    inc d

Jump_00c_4e51:
    pop bc
    adc a
    rla
    ld d, d
    ld [hl-], a
    and h
    jr nc, @+$28

    adc b
    db $e4
    and a
    inc l
    add l
    rrca
    xor b
    ld b, c
    ld a, c
    adc h
    add h
    ld c, h
    ret nz

    sbc h
    ccf
    ld e, d
    ld c, d
    dec [hl]
    adc e
    sub [hl]
    add d
    ret nz

    pop af
    ld [hl-], a
    ld l, a
    sub c
    dec b
    db $f4
    sbc b
    cp c
    jr nc, jr_00c_4e9d

    rst $10
    ld a, b
    rst $00
    inc d
    add hl, bc
    jr jr_00c_4e26

    jr c, jr_00c_4ea3

    ld a, [bc]
    dec bc
    ld b, b
    and b
    add [hl]
    ld [hl], c
    ld b, e

Jump_00c_4e89:
    ld a, [hl]
    db $10
    sbc $91
    add sp, $44
    ld hl, $c4f5
    ld b, a
    ld c, $38
    ld a, [hl+]
    and c
    ld de, $4506
    sub d
    sub e
    inc e

jr_00c_4e9d:
    add hl, bc
    ld a, [de]
    and c
    and e
    ld b, c
    add h

jr_00c_4ea3:
    jr z, jr_00c_4ec6

    xor d
    ld e, d
    db $10
    and b
    sub d
    push bc
    ld b, b
    push bc
    ld b, h
    inc [hl]
    adc h
    ld b, l
    rlca
    rlca
    ld [$d4ab], a

jr_00c_4eb6:
    inc c
    ld b, d
    jp c, Jump_000_021d

    dec c
    ld a, [de]
    ld h, b
    or d
    ld de, $fd57
    xor b
    db $f4
    add d
    add h

jr_00c_4ec6:
    rla
    dec b
    db $10
    sbc e
    ret z

    ld b, b
    db $e4
    dec h
    ld e, h
    pop bc
    xor l
    ld b, h
    call z, Call_000_1b95
    ld h, e
    pop bc
    ld b, $85
    and h
    ld [hl], $14

jr_00c_4edc:
    dec d
    call nz, $a4a4
    and h
    ld h, $28
    ld h, c
    ld l, e
    add h
    ld b, l
    inc b
    ld d, d
    ld b, a
    db $fd
    inc bc
    ld b, $08
    jr nc, jr_00c_4f25

    inc d
    adc h
    ld l, $da
    ret nc

    inc a
    ld e, l
    db $10
    rst $38
    call z, $3686
    ld l, c
    and d
    db $d3
    ld c, e
    and b
    push bc
    jp hl


    ld d, c
    ld de, $c159
    ld e, b
    ld d, h
    inc sp
    and [hl]
    ld [de], a
    sub b
    adc d
    ld h, a
    adc d
    add d
    ld [hl], b
    ld b, c
    dec b
    sbc d
    ld b, b
    sub b
    sbc b
    xor b
    ld d, b
    jp z, $98a6

    ld b, l
    jr nz, jr_00c_4eb6

    add d
    ld b, l
    ld a, d
    ld c, d
    dec e

jr_00c_4f25:
    ld d, c
    ld de, $2cae
    add e
    ld b, $4b
    ld c, h
    inc l
    ld c, l
    ld [bc], a
    jr nc, jr_00c_4edc

    db $10
    ld h, $98
    ld [hl-], a
    call z, Call_00c_5a8d
    call nz, Call_000_3026
    ld hl, $d9a5
    adc [hl]
    ld c, $0c
    dec bc
    inc b

jr_00c_4f44:
    rra
    ld [$54c4], a
    ld h, d
    add h
    db $10
    ld [hl+], a
    and h
    cp b

jr_00c_4f4e:
    and c
    inc b
    ld c, h
    inc c
    ld h, l
    dec c
    ld d, c
    sub d
    ld b, h
    dec c

Call_00c_4f58:
    ld a, [bc]
    add h
    dec d
    ld [bc], a
    ld [hl-], a
    ld a, [hl+]
    sub h
    sub e
    dec c
    xor c
    ld a, [hl+]
    ld b, h
    ld h, l
    ld d, $85
    ld b, h
    ld b, c
    ld h, b
    sub l
    inc h
    ld c, b
    ld [hl], h
    dec bc
    sbc $29
    pop bc
    inc b
    ld [$c828], sp
    ld sp, $3048
    ld hl, $d177
    jr jr_00c_4f44

    ret c

    ld l, b
    xor l
    inc de
    ld d, $c4
    ld b, b
    call nc, $a9a4
    push bc
    add d
    ld [hl], b
    inc [hl]
    ld h, l
    dec bc
    ld c, b
    ld b, a
    ld [hl-], a
    and c
    ld b, b
    xor d
    pop af
    db $e3
    nop
    ld b, h
    cp c
    sbc a
    db $fd
    ld [hl-], a
    ld d, d
    ld d, a
    rst $38

jr_00c_4f9f:
    ld b, d
    adc d
    adc h
    rst $28
    ld a, d
    ld a, [hl+]
    reti


    scf
    and b
    ld a, [hl]
    call z, $e068
    ei
    db $e3
    inc h
    db $dd
    and $08
    ret


    add hl, bc
    jr c, jr_00c_4f4e

    and l
    inc b
    ld e, b
    push de
    and $15
    ld a, [hl+]
    jr jr_00c_4f9f

    and b
    ld e, a
    or l
    add hl, sp
    xor a
    and b
    cp l

jr_00c_4fc6:
    daa
    ld d, d
    sub e
    sub d
    ld b, a
    reti


    ld e, b
    add sp, -$78
    ld l, b
    db $eb
    adc c
    ld c, [hl]
    sbc e

jr_00c_4fd4:
    ld d, l
    add c
    ld h, e
    and d
    xor d
    adc a
    inc hl
    ld [hl], h
    xor d
    ld [hl], c
    xor d
    and h
    or c
    ld de, $76bb
    ld b, h
    pop de
    ret


    db $dd
    dec e
    xor c
    call c, $98cb
    inc h
    and [hl]
    adc h
    inc c
    add hl, bc
    ld a, [hl+]
    ld a, [hl+]
    call c, Call_00c_4269
    jp z, $1342

    inc c
    ld [hl], c
    jr nc, jr_00c_4fc6

    and b
    add e
    dec e
    dec hl
    inc b
    and a
    ld [hl], a
    inc b
    and a
    ld e, d
    dec c
    ld e, d
    sbc h

jr_00c_500b:
    ldh a, [rLYC]
    ld e, c
    rst $08
    ld a, [hl+]
    xor l
    rra
    inc c
    ld [hl], a
    cp c
    rst $10
    ei
    dec a

jr_00c_5018:
    rlca
    or [hl]
    db $e3
    rst $08
    ld a, b
    db $10
    ld c, a
    ld b, l
    ld c, c
    sbc $3c
    db $e4
    daa
    push de
    ld e, l
    inc a
    ld d, l
    ld d, l
    ld c, c
    xor d
    ld e, a
    adc a
    add hl, bc
    ld a, [$54aa]
    xor d
    sub a
    push af
    dec sp
    xor a
    and $55
    ld l, c
    rla
    add sp, -$76
    db $f4
    add a
    ld [$134c], a
    ld b, h
    ld a, [de]
    inc c
    jr c, @+$29

    adc h
    add sp, $1e
    jr jr_00c_4fd4

    sub a
    inc sp
    db $76
    ld [hl+], a
    xor e
    sub b
    adc h
    add sp, $20
    ld c, b
    ld c, c
    adc l
    ld e, a
    adc c
    ld l, b
    add a
    ld b, l
    ld sp, $4581
    xor b
    or h
    jr z, jr_00c_500b

    pop hl
    ld e, d
    dec b
    ld c, c
    xor l
    adc b
    ld d, l
    adc c
    xor b
    adc $8a
    rst $18
    db $fc
    ld e, b
    or a
    db $eb
    xor d
    ld sp, $15d8
    ld c, h
    ld h, $32
    ld e, b
    jp nz, $c164

    ld c, d
    ld e, d
    sub l
    adc b
    ld h, h
    pop de
    ld [c], a
    sbc c
    dec e
    jr nc, @-$2a

    sbc b
    add [hl]
    rra
    jr jr_00c_5018

    jr nc, jr_00c_5109

    dec d
    xor b
    sub a
    adc d
    ld h, h
    xor b
    sbc d
    sub l
    ld d, h
    xor d
    add l
    or l
    push de
    xor d
    adc h
    and d
    inc h
    jr @-$59

    sub l
    ld hl, sp-$32
    xor d
    ld sp, $4951
    adc e
    ld c, c
    ld b, l
    ld hl, $520a
    sub l
    ld [hl], $51
    add c
    ld b, [hl]
    ld d, h
    or [hl]
    add hl, bc
    inc b
    ld d, d
    sub c
    ld a, d
    ld [hl], $b5
    ret c

    ld h, h
    sbc d
    xor d
    ld a, [hl+]
    cp c
    dec l
    sub [hl]
    and e
    ld e, d
    and e
    ld a, [bc]
    ld c, l
    sbc e
    db $e4
    pop bc
    ld b, c
    ld c, [hl]
    ld b, l
    ld a, a
    or e
    xor a
    db $d3
    ld h, l
    ld a, a
    xor b
    ld d, $35
    sub d
    ld [hl+], a
    ld d, c
    ldh [$8c], a
    ld d, l
    cp $a1
    ld e, d
    adc d
    ld d, l
    ld l, d
    and l
    xor b
    ld e, d
    dec bc
    ld h, [hl]
    dec h
    ld a, [hl]
    and c
    ld d, l
    ld h, l
    ld d, [hl]
    xor d
    dec [hl]
    xor d
    adc e
    cp [hl]
    inc hl
    ld e, a
    rst $38
    ld [$fca8], a
    ld e, [hl]
    ld [hl], e
    and a
    xor [hl]
    xor c
    jp hl


    xor a
    xor $7a
    dec hl
    ei
    ld sp, hl

jr_00c_5109:
    rst $20
    xor a
    ld [$529e], a
    ld h, c
    rst $38
    push af
    ld e, $34
    ld c, d
    cp d

jr_00c_5115:
    and e
    ld [de], a
    add h
    db $10
    daa
    add a
    dec a
    ld e, a
    add sp, -$3a
    inc de
    sub l
    xor e
    sbc b
    and [hl]
    xor a
    jp hl


    inc a
    ret


    sub [hl]
    sub b
    adc a
    cp $52
    ld l, l
    rst $38
    rst $38
    ldh a, [$c6]
    ld l, $8c
    rra
    rst $38
    ld sp, hl
    cp h
    rrca
    ld hl, sp-$21
    and h
    ld [hl-], a
    sub b
    ld hl, sp+$4a
    ld b, l
    rst $38

Jump_00c_5142:
    ld a, [$9247]
    jp nz, $5eff

    rst $38
    cp $86

Jump_00c_514b:
    rst $38
    ld d, b
    and b
    and c
    ld hl, $7a37
    rra
    sub c
    jr jr_00c_5115

    rst $38
    ret nc

    ld e, [hl]
    and h
    xor e
    add a
    push af
    dec d
    rrca
    cp $69
    rst $38
    rst $38
    ld [bc], a
    ccf
    dec bc
    rst $38
    ldh [$be], a
    and b
    and l
    rst $18
    sbc c
    or a
    rst $38
    db $e4
    ccf
    inc bc
    rst $10
    ld hl, sp+$41
    db $fc
    ld e, $98
    jp nc, $bd63

    ld d, h
    ld e, $ff
    ccf
    ei
    ld b, c
    add a
    rst $38

Jump_00c_5183:
    ld b, a
    ld [bc], a
    ld b, d
    ld b, h
    ld e, a
    rst $38
    ccf
    rst $38
    add e
    rst $38
    db $fd
    ld de, $4b1d
    rst $38
    rlca
    rst $38
    rst $38
    rst $38
    rst $38
    ld a, [hl]
    ld c, d
    ld d, d
    ld [hl], c
    call c, $ff45
    rst $38
    db $fc
    rla
    db $ed
    sub b
    add d
    ld b, d
    add hl, bc
    or h
    ld h, a
    ld e, e
    ld d, l
    ld c, [hl]
    adc e
    sub d
    xor $8b
    rst $20
    ld [hl], l
    ld d, a
    cp $1f
    ei
    rst $38
    db $fd
    ld a, [c]
    ld [hl], e
    inc hl
    xor a
    cp $aa
    or a
    rst $28
    rst $38
    db $e3
    ldh [$9c], a
    ld [$ffcb], sp
    rst $38
    rst $38
    push af
    ld b, c
    ld a, a
    rst $38
    dec bc
    ret


    sbc d
    ld sp, $ff0b
    db $fd
    ld d, [hl]
    ld c, h
    ld d, h
    dec e
    ld e, c
    adc h
    ld d, d
    db $10
    xor e
    push de
    ld e, c
    ld sp, $c7e6
    db $e3
    and b
    ld b, h
    and l

Call_00c_51e5:
    ld d, l
    ld d, a
    rst $38
    rst $38
    push de
    ld d, e
    rra
    cp $bc
    adc $a9
    adc h
    ld l, d
    cp h
    ld l, $bd
    ld b, l
    ld d, h
    inc de
    add d
    add d
    ld h, [hl]
    cp $a7
    ld [hl-], a
    cp a
    push de
    pop hl
    sbc b
    inc h
    xor h
    add $d4
    add hl, hl
    ld b, d
    ld hl, $aa46
    inc [hl]
    sbc c
    ld [hl+], a
    adc d
    add [hl]
    and h
    res 7, b
    ld h, e
    inc h
    ld [de], a
    inc de
    dec sp
    rrca
    adc b
    ld d, h
    xor c
    inc b
    jp c, Jump_00c_5142

    ld b, d
    ld h, d
    ld h, e
    ld l, [hl]
    adc c
    add d
    ret z

    ld l, d
    dec b
    ld h, e
    ld a, [hl-]
    ld d, l
    ld d, d
    dec de
    ld [hl+], a
    sub e
    sub [hl]
    xor l

Jump_00c_5232:
    ld a, [hl+]
    ld [$bde8], sp
    ld e, b
    inc de
    xor [hl]
    xor d
    inc a
    ld a, l
    call nz, $9daa
    dec hl
    dec d
    ld d, l
    daa
    inc de
    ld d, d
    adc d
    and a
    scf
    inc h
    ld a, l
    ld e, [hl]
    and [hl]
    ld l, d

jr_00c_524d:
    ld h, e
    inc b
    ld h, c
    ld b, [hl]
    ld e, [hl]
    push de
    ld e, c
    db $10
    ld [hl+], a
    ret


    or l
    sbc d
    ld d, l
    ld d, [hl]
    sbc d
    inc l
    sbc d
    inc h
    reti


    sbc d
    inc d
    ld c, d
    ld d, d
    sbc h
    ld d, d
    ld c, h
    ld a, [de]
    ld b, d
    ld [de], a
    ld a, [hl+]
    ld l, d
    add sp, $3b
    dec bc

jr_00c_526f:
    inc de
    ld b, [hl]
    db $f4
    db $10
    rst $18
    ld d, $9d
    ld l, c
    ld [$5447], sp
    ld e, $a9
    ldh a, [$e0]
    ld [hl], a
    or h
    ld e, a
    db $d3
    pop de
    ld a, d
    dec b
    db $e3

jr_00c_5286:
    dec [hl]
    rst $38
    call nc, $aaf0
    and h
    pop bc
    ld h, d
    sub b
    ld c, a
    dec b
    ld d, h
    ld d, l
    ld d, l
    dec b
    ld l, d
    inc a
    ld a, $a8
    ld a, [hl+]

jr_00c_529a:
    xor d
    and b
    xor c
    ld d, e
    ret nz

    and c
    ld b, l
    dec b
    jr nc, jr_00c_524d

    ld d, l
    add d
    dec sp
    ld l, b
    adc h
    sbc c

Call_00c_52aa:
    ld l, $95
    ld e, d
    dec sp
    add sp, $52
    db $e4
    db $ec
    ld a, b
    push de
    ld a, d
    add hl, hl
    ld b, l
    ld d, h
    rst $20
    and e
    scf
    ld a, [$8608]
    add [hl]
    ld b, $af
    ld c, h
    ld d, [hl]
    db $fd
    ld [hl+], a
    add c
    jr nc, jr_00c_5340

    cp b
    jr jr_00c_526f

    ld [de], a
    ld e, [hl]
    dec h
    cp d
    adc b
    or [hl]
    xor [hl]
    dec l
    ld c, h
    db $10
    ld c, c
    ld e, b
    adc c
    ld c, $ad
    ld h, c
    ld c, [hl]
    db $fc
    xor c
    ld hl, $a418
    xor c
    ld d, d
    ld de, $4e81
    ld [$4b20], sp
    add d
    rla
    db $d3
    ld c, d
    adc [hl]
    add h
    ld l, c
    ld h, b
    add l
    ld b, $04
    dec e

jr_00c_52f5:
    ld a, [hl-]
    inc hl
    ld a, c
    ld e, b
    pop bc
    ld b, $04
    rst $20
    ld d, l
    add hl, sp
    jr nz, jr_00c_5286

jr_00c_5301:
    add l
    ld [hl], $64
    add h
    ld d, h
    jr nz, jr_00c_529a

    xor d
    dec l
    ld h, h
    or [hl]
    ld b, $8c
    ld l, b
    adc d
    adc c
    ld h, [hl]
    ld b, e
    ld a, [hl+]
    dec d
    ld e, c
    ld h, b
    ld d, d
    ld d, [hl]
    ld b, $31
    adc h
    sub $15
    ld h, $aa
    ld hl, $538a
    adc [hl]
    dec h
    ld hl, sp-$3b
    and h
    and l
    adc b
    pop de
    ld b, e
    ld c, b
    ld h, e
    ld e, b
    ld a, [de]
    ld sp, $1ca4
    db $10
    xor b
    add h
    adc d
    add [hl]
    adc b
    ld l, c
    dec d
    xor c
    ld [hl+], a
    inc b
    inc d
    and l

jr_00c_5340:
    ld b, d
    sbc b
    ret


    ld e, c
    xor c
    ld c, e
    ld b, c
    ld l, $2b
    dec b
    adc d
    ld a, [hl]
    ld [hl+], a
    push de
    ld h, e
    jr c, jr_00c_52f5

    inc de
    ld l, d
    ld a, [hl+]
    sbc [hl]
    jr nc, jr_00c_5301

    ld l, $4b
    ld l, b
    ld d, e
    ld [$48b9], sp
    ld a, b
    jp c, $aa4b

    and l
    ld h, h
    inc d
    add [hl]
    inc d
    ld e, c
    ld b, d
    add hl, sp
    ld l, c
    ld d, l
    ld l, d
    adc d
    sub [hl]
    and c
    ld h, b
    sub b
    sub h
    ld a, [c]
    ld [$a5a2], a
    ld h, b
    jp c, $2921

    jp hl


    ld a, [hl+]
    ld b, e
    sbc d
    ld hl, $8291
    db $76
    pop bc
    ld l, b
    ld d, h
    sbc b
    or e
    ld d, l
    ld e, d
    ld [hl], a
    jp z, $98a0

    ret nz

    xor h
    and e
    dec e
    adc b
    rst $30
    ld d, c
    sub d
    dec d
    ld b, $8a
    db $76
    ld e, b
    adc $a6
    ld d, d
    adc l
    inc bc
    rst $00
    ld l, l
    sub c
    pop bc
    ld c, c
    add h
    dec c
    ld c, b
    ld b, a
    ld a, l
    sbc b
    ret


    call c, Call_000_219b
    ld b, b
    xor d
    ld e, $a4
    daa
    ld a, $6b
    jr z, jr_00c_53fb

    ld l, [hl]
    inc d
    inc d
    adc h
    add hl, de
    sub d
    ld [de], a

jr_00c_53bf:
    call nz, $a6e0
    dec bc
    xor $8a
    inc e
    dec c
    db $10
    jp z, $72f9

    dec d
    ld h, c
    ld hl, $16dd
    pop hl
    pop bc
    ld a, l
    pop bc
    ld b, l
    jp c, $0c5a

    ld c, l
    inc de
    ld a, [bc]
    ld h, e
    rlca
    sub c
    db $e4
    ld b, h
    db $ed
    inc c
    sub l
    dec de
    ret nc

    ld h, $5e
    cpl
    cp d
    ld h, b
    sub h
    add d
    inc c
    ld a, [de]
    ld l, d
    sbc d
    ld a, e
    cp $11
    ld l, d
    ld c, d
    ld a, [hl+]
    inc c
    rla
    and l
    and b
    sbc c

jr_00c_53fb:
    db $e4
    ld e, h
    ld de, $c687
    add hl, hl
    ld c, $1f
    xor $e8
    ld e, h
    sbc c
    add hl, hl
    add d
    add hl, bc
    sbc h
    jr nc, jr_00c_53bf

    ld b, l
    rst $18
    jp nz, $ece1

    ld d, d
    ld h, [hl]
    sbc c
    jr c, @-$3e

    call z, Call_00c_4c42
    ld c, h
    ld b, h
    ld e, d
    pop bc
    add hl, sp
    xor e
    add a
    ld b, $4a
    or a
    jr @-$18

    sub c
    jp nz, Jump_000_09fa

    add hl, bc
    add h
    ld d, d
    ld [$46e5], sp
    ld [hl], l
    db $10
    and c
    add [hl]
    ld b, d
    sub $1a
    ld c, e
    sub b
    db $fd
    ret z

    ld h, d
    pop af
    and e
    dec [hl]
    ld c, l
    inc c
    and c
    ld b, $14
    ld b, a
    inc b
    db $fc
    sub e
    jr nz, @-$7a

    ld l, c
    ld sp, $1249
    add e
    dec b
    add hl, hl
    add d
    add h
    ld de, $de83
    ld d, d
    pop af
    ld d, d
    ldh [$d4], a
    ld h, c
    ld d, $a1
    ld a, [de]
    push bc
    xor h
    ld l, e
    sbc e
    xor h
    ld b, d
    add hl, hl
    ld l, h
    jp z, Jump_00c_6f4c

    ld b, b
    sub [hl]
    xor b
    ld b, c
    adc d
    inc [hl]
    ld c, e
    ld [bc], a
    dec d
    ld b, a
    inc [hl]
    dec c
    ld d, d
    ld b, h
    ld e, e
    ld [bc], a
    cp d
    ld b, h
    add d
    sbc [hl]
    ld e, h
    ld b, h
    ld e, e
    ld b, d
    ld b, h
    or e
    ld d, h

Jump_00c_5485:
    ret


    ld b, c
    and e
    ld [hl], a
    or h
    cp d
    or e
    adc l
    ld b, d
    jp nc, $e228

    or h
    ld d, l
    dec bc
    ldh a, [rLYC]
    ld d, e
    ld e, d
    or a
    and d
    and [hl]
    ld [hl], c
    adc l
    ld l, b
    dec l
    ld sp, $3b4e
    ld b, c
    ld c, h
    inc a
    inc hl
    adc l
    inc b
    or a
    push bc
    adc $14
    rst $00
    adc b
    adc [hl]
    inc b
    ld [de], a
    ld e, c
    adc c
    ld d, e
    ld [hl], l
    ld e, $50
    bit 5, h
    ldh [$ad], a
    ld b, d
    xor c
    ld d, $d3
    ld [hl], h
    ld d, [hl]

Call_00c_54c1:
    ld a, a
    push hl
    adc $19
    rst $18
    ld c, d
    or l
    ld a, b
    pop hl
    xor b
    add $a3
    rst $00
    sbc l
    ld l, d
    ld [hl], l
    ei
    ld h, a
    inc e
    sub a
    rst $00
    dec a
    cp $ba
    ld b, d
    sbc e
    ld b, h
    inc a
    scf
    ei
    ld a, l
    dec de
    ld b, b
    add l
    xor a
    rst $38
    ld [$ce70], a
    rla
    rst $38
    rst $38
    sbc h
    ld l, a
    cp a
    rst $38
    cp $29
    jp nz, $ffff

    rst $38
    add a
    dec de
    or l
    rst $38
    rst $18
    db $fc
    ld [hl], b
    xor a
    dec b
    ld b, d
    jp c, $15c7

    db $eb
    sbc b
    ld l, d
    ld [hl], b
    inc hl
    ld [hl], c
    adc d
    ldh [$9b], a
    pop bc
    pop de
    sbc d
    ld a, h
    jr c, jr_00c_5588

    xor d
    ld d, e
    add c
    ld a, b
    pop af
    rra
    push de
    ld d, l
    ld d, l
    ei
    ld e, b
    pop af
    ld [$aaaa], a
    ld b, $60
    or l
    dec sp
    ld [$508d], a
    ld c, d
    xor a
    ld d, l
    ld d, e
    and d
    xor b
    and $5f
    db $fc
    inc de
    and d
    db $fd
    ld sp, $2182
    ld l, d
    ld d, l
    ld e, d
    ld a, [hl-]
    rst $28
    db $d3
    ld h, $d6
    db $f4
    jp nz, $bb8e

    db $fd
    ld c, c
    rst $38
    or $99
    ld l, $d3
    scf
    ld c, l
    xor a
    db $fc
    db $10
    add sp, -$72
    ld d, c
    sub l
    ld d, h
    dec l
    ld b, l
    ld d, b

jr_00c_5556:
    and l
    jr c, jr_00c_55c4

    jp nc, $c11f

    inc [hl]
    xor e
    ld [$3aad], a
    jr z, jr_00c_55d0

    add e
    inc b
    ld l, e
    call z, $90e6
    ld d, e
    cp e
    ld h, $8c
    push de
    ld e, $d4
    jp hl


    ld a, c
    inc c
    ld hl, $3a53
    ld [hl], c
    sbc b
    ld [$04b6], a
    sub l
    di
    dec [hl]
    dec h
    jr c, jr_00c_5556

    ld l, $51
    call nc, $d4d7
    sbc h
    db $dd

jr_00c_5588:
    ld a, a
    call nc, Call_00c_5ac7
    push af
    ld d, e
    dec h
    ld [hl+], a
    inc [hl]
    ld a, a
    cp $a0
    push de
    ld e, a
    add c
    ld h, $ab
    rst $38
    rst $38
    and b
    ld h, e
    scf
    cp $8b
    xor d
    push af
    and b
    ld e, d
    xor d
    sub l
    ld d, h
    inc d
    push de
    cp $31
    ld b, a
    sbc l
    ld d, [hl]
    adc l
    rra
    push bc
    dec c
    db $f4
    sub a
    ld hl, sp-$22
    ld e, d
    sub l
    ld [hl-], a
    ld a, b
    ld l, c
    ld d, [hl]
    ld [hl], h
    add l
    ld d, e
    ld h, h
    ld [de], a
    ld a, [hl+]
    ld d, [hl]
    xor d

jr_00c_55c4:
    sub l
    add hl, hl
    ld [hl], a
    adc e
    ld d, l
    jr c, jr_00c_55db

    ld c, h
    ld l, d
    db $fd
    ld d, h
    xor d

jr_00c_55d0:
    add c
    ld l, l
    dec b
    ld d, e
    adc c
    inc b
    pop bc
    ld a, [$ef8d]
    ld d, l

jr_00c_55db:
    ld c, [hl]
    ld b, h
    ld [de], a
    xor b
    db $f4
    ld h, $46
    adc a
    ld bc, $ff57
    rst $38
    push de
    ld b, d
    ld d, l
    dec sp

jr_00c_55eb:
    ld d, a
    ld [$ea8c], a
    cp l
    adc [hl]
    reti


    and e
    sbc [hl]
    db $d3
    xor [hl]
    ld d, h
    add hl, bc
    ret nz

    sbc [hl]
    ccf
    cp d
    ld h, h
    call nz, Call_00c_783a
    ld c, b
    ld a, a
    sbc d
    cpl
    ld a, [$0b9e]
    ld a, [hl]
    sbc c
    cpl
    pop de
    jr nc, jr_00c_5631

    and a
    ld c, e
    ld a, [hl]
    sbc c
    ld a, h
    ld e, d
    ld d, d
    and a
    ld e, l
    jp hl


    ld [hl], a
    jp nz, $bf86

    rst $38
    rst $20
    ld [hl], l
    ld [$864f], a

Jump_00c_5621:
    dec d
    ld [hl], a
    and l
    rst $00
    ld [hl], l
    ld a, [hl]
    add [hl]
    jr z, @-$3b

    scf
    ld [$099c], a
    pop bc
    ld [bc], a
    dec d

jr_00c_5631:
    ld b, [hl]
    ld [$5541], sp
    ld d, a
    add sp, $24
    and c
    ld [bc], a
    ld [hl], d
    ld b, [hl]
    inc l
    db $dd
    ld d, l
    ld d, h
    cp l
    jr nz, jr_00c_55eb

    and a
    ld l, l
    and e
    and c
    add e
    rla
    ld d, d
    ret z

jr_00c_564b:
    ld e, h
    db $76
    ld hl, sp+$5e
    ld l, h
    adc h
    sbc [hl]
    inc bc
    sub c
    ret nz

    add d
    ld h, a
    inc b
    ld a, [de]
    ld [hl], a
    db $ec
    db $e3
    inc c
    ld h, h
    add d
    ld a, [hl-]
    ld [hl], d
    ld h, $97
    ld [$c399], a
    inc bc
    and a
    ld [bc], a
    db $10
    add hl, hl
    xor e
    ld e, a
    ld a, [$aaaa]
    rst $38
    sbc e
    ret nz

    cp a
    pop bc
    sub a
    ld [bc], a
    jp z, Jump_00c_57af

    rst $38
    rst $38
    ld b, [hl]
    rst $28
    db $f4
    ld c, [hl]
    add sp, $21
    ld c, e
    rst $38
    rst $38
    ld a, [$2eaa]
    ld l, h
    rst $38
    rla
    ld e, e
    ld a, a
    rst $38
    pop af
    sub l
    ld a, [bc]
    call nz, $20a5
    rst $38
    add hl, de
    ei
    rlca
    ld e, a
    rst $38
    rst $38

jr_00c_569b:
    ld sp, hl
    jr nc, jr_00c_570d

    add d
    ld d, d
    rrca
    and $95
    jp hl


    jr nc, jr_00c_569b

    ld d, a
    push hl
    and c
    jr jr_00c_564b

    cp $6d
    ld e, [hl]
    sbc d
    inc h
    ld b, [hl]
    ld d, b
    ld c, b
    and b
    cp $70
    ld d, a
    jp hl


    ld [hl], c
    call z, $fc83
    ld [hl], b
    rst $10
    ld a, [$5fa7]
    ld sp, hl
    bit 7, [hl]
    db $76
    rst $38
    sub d
    add $32
    ld d, l
    pop de
    rst $10
    or $11
    rst $00
    ld e, $04
    db $76
    ld b, a
    ld e, b
    ld b, h
    cp c

jr_00c_56d6:
    ld d, l
    cp $ce
    ld d, l
    rst $38
    rst $38
    ld [hl], e
    add l
    ld a, a
    cp $a0
    ld d, l
    scf
    ld a, d
    push af
    ld d, [hl]
    and d
    inc sp
    add c
    ld a, a
    db $ed
    ld e, d
    and h
    ldh [$a8], a
    rra
    and e
    jr jr_00c_56d6

    or h
    call Call_000_1539
    jr nc, jr_00c_575c

    sub e
    sbc $55
    and e
    sbc [hl]
    or h
    dec d
    ld d, l
    adc l
    rst $18
    ld e, a
    rst $20
    push af
    ld d, h
    db $dd
    ld e, d
    xor a
    ld d, h
    ld a, [hl+]
    and e

jr_00c_570d:
    add d
    cp l
    rst $38
    rst $38
    rst $38
    add hl, sp
    ld l, d
    xor e
    rst $38
    rst $08
    add l
    sbc $aa
    or l
    ld c, c
    jp z, $adb4

    ld d, h
    ld [hl], d
    ei
    inc de
    ld a, [$e16e]
    adc h
    jp $5955


    cp h
    ld d, h
    db $10
    daa
    ld h, e
    ld d, c
    jp c, $049e

    sbc c
    daa

jr_00c_5735:
    ld b, l
    db $fd
    ld c, c
    jp z, $2bbf

    ld d, l
    inc e
    ld de, $0d1f
    ccf

jr_00c_5741:
    ld sp, hl
    pop bc
    ld de, $5255
    xor d
    sbc a
    ld c, d
    ld [hl], a
    cp d
    ld e, a
    ld d, a
    db $d3
    ret nc

    ld d, l
    sub l
    ld c, a
    ld b, l

jr_00c_5753:
    pop de
    xor b
    db $f4
    ld l, d
    add a
    adc $37
    db $d3
    ld h, l

jr_00c_575c:
    ld c, h
    rst $28
    or h
    inc d
    pop hl
    and l
    dec h
    ld d, d
    rla
    ld [$34f5], a
    ld d, b
    ld d, e
    add d
    xor c
    ld e, [hl]
    xor a
    add sp, -$3e
    cp a
    ld c, [hl]
    dec h
    ld sp, $54a2
    push hl
    and d
    ld d, a
    or l
    rla
    db $eb
    db $d3
    ld a, [hl+]
    dec bc
    ld [hl], e
    daa
    jp z, Jump_00c_7a51

    rlca
    add c
    push af
    ld c, b
    or h
    ld d, h
    ld d, h
    add l
    inc sp
    sbc a
    or b
    xor e
    call nc, $5d1e
    rrca
    ld e, a
    ld b, [hl]
    ld hl, sp-$20
    ld c, b
    db $76
    add [hl]
    xor b
    adc e
    cp $86
    and d
    ld l, l
    jr c, jr_00c_5741

    rlca
    add $08
    dec a
    ld b, l
    ld d, h
    or l
    jr nc, jr_00c_5753

    rst $18
    ret


    rst $20

Jump_00c_57af:
    ld [c], a
    jr nz, jr_00c_5735

    pop hl
    ld d, h
    ld a, $8c
    xor h
    db $e3
    xor d
    scf
    ld e, d
    add c
    ld a, d
    dec l
    ld a, a
    push de
    add l
    dec bc
    pop hl
    and e
    ld [hl], a
    rst $38
    cp [hl]
    add [hl]
    adc b
    ld a, d
    ld h, $93
    ld c, e
    rst $38
    call nc, $f195
    cp d
    add hl, hl
    sbc l
    and e
    cpl
    ld b, [hl]
    dec b
    inc sp
    xor a
    cp $0b
    ld sp, hl
    ld b, l
    ld a, [$4cd9]
    db $ed
    ld a, [de]
    db $e4
    sbc $f5
    ld d, a
    ld d, c
    db $fd
    ld h, h
    ccf
    ld d, d
    ld d, h
    adc d
    xor d
    and e
    add [hl]
    xor d
    dec de
    ld d, l
    ld l, h
    jr c, jr_00c_5862

    cp $bd
    ld b, l
    ld d, l
    ld a, [hl-]
    sub h
    ld sp, $345d
    ld e, e
    ld b, d
    adc [hl]
    and a
    xor d
    add l
    ld d, e
    dec b
    ld hl, sp-$7b
    ld a, [de]
    add hl, sp
    add sp, $6f
    ld a, d
    or l
    ld e, a
    add sp, -$3f
    ld d, l
    add hl, sp
    xor b
    and l
    ld a, a
    ld [$528a], a
    ld [$df3a], a
    xor b
    pop de
    db $eb
    ld c, [hl]
    ld [$d438], a
    pop af
    inc d
    dec l
    ld d, d
    push de
    ld hl, sp-$66
    inc a
    dec bc
    ld e, d
    cp a
    cp $a2
    ld d, a
    adc a
    ld c, $bf
    ld d, l
    ld d, l
    rst $38
    add sp, -$2e
    ld [hl], h
    or d
    inc l
    sbc [hl]
    sbc h
    ld c, h
    ld a, d
    ld l, b
    cpl
    sbc [hl]
    sub [hl]
    jr jr_00c_58c2

    ld a, b
    xor c
    push bc
    ld b, a
    inc e
    ld h, b
    sub h
    add h
    ld d, h
    add hl, bc
    db $e3
    add hl, hl
    ld de, $19c1
    cp c
    ld l, c
    sub h
    ld d, l
    ld [$c471], a
    and b
    db $fc
    ld c, h
    ld l, d

jr_00c_5862:
    add d
    ld d, l
    add hl, de
    inc [hl]
    ld e, $94
    set 0, h
    ld [hl-], a
    sub d
    jp hl


    ld [hl], l
    db $10
    and [hl]
    ret nc

    db $dd
    ld b, b
    add a
    ld a, [bc]
    db $10
    xor a
    xor l
    rst $38
    add hl, de
    jp hl


    add hl, hl
    inc c
    ld b, [hl]
    jr jr_00c_58a4

    ld a, d
    ld de, $8f5f
    db $fd
    ld sp, hl
    add hl, hl
    cpl
    and e
    dec bc
    and h
    ld h, h
    ret nz

    rst $30
    push hl
    rst $18
    rst $38
    ld hl, sp+$44
    and l
    reti


    ld c, l
    dec c
    db $10
    adc d
    db $10
    cp $61
    ld e, a
    rst $38
    sub b
    ld a, [$7044]
    cp a
    ld [c], a

jr_00c_58a4:
    or b
    ld e, [hl]
    ld c, d
    ld de, $fa1d
    sbc b
    ld b, h
    xor a
    jp hl


    dec bc
    dec c
    ld [hl], a
    sub l
    ld a, d
    ld h, l
    or a
    sbc c

jr_00c_58b6:
    ld b, h
    ld d, a
    ld a, a
    jp nc, $c45f

    jp $fe19


    call z, Call_00c_4470

jr_00c_58c2:
    ld e, a
    sub l
    ld de, $6bb4
    cp $b1
    add hl, bc
    push bc
    ld [bc], a
    ld b, d
    ld c, h
    jr z, jr_00c_58b6

    dec bc
    push af
    db $e4

Jump_00c_58d3:
    jp $d39d


    sbc b
    ldh [$be], a
    and [hl]
    ld de, $fcda
    add hl, hl
    ld c, l
    rst $38
    push bc
    ld e, c
    rst $10
    ld b, $18
    ld h, e
    inc bc
    inc sp
    or $11
    ld sp, $e219
    ld h, c
    ld b, $31
    sub l
    pop de
    rst $08
    inc d
    add l
    sub c
    add hl, de
    daa
    adc e
    add h
    ld l, [hl]
    add l
    and a
    xor a
    jp hl


    rst $18
    ld d, $96
    adc h
    ld b, e
    jp hl


    db $e4
    ld b, [hl]
    ld c, e
    reti


    db $e4

jr_00c_590a:
    ret


    ld a, c
    ld sp, $44b0
    or l
    ld e, a
    db $fd
    ld d, l
    ld e, a
    dec l
    ld d, l
    ld a, [hl]
    db $ed
    xor l
    push hl
    db $fd
    adc d
    xor e
    ld l, b
    inc d
    ld a, [hl+]
    sub a
    dec bc
    ld [hl], b
    call nc, Call_00c_52aa
    sbc d
    dec h
    ld e, b
    dec h
    ld c, h
    ld h, d
    push hl
    jr nc, @+$81

    db $d3
    and l
    ld [c], a
    ld a, b
    db $ed
    ld [hl], l
    adc [hl]
    inc d
    and l
    dec h
    dec de
    add hl, hl
    db $e3
    dec b
    rrca
    ld b, d
    add sp, $64
    pop bc
    ld b, l
    ld d, c
    rst $18
    or b
    ld c, b
    xor d
    cp b
    cp e
    ld [$e0f7], a
    db $eb
    ldh [rHDMA2], a
    inc sp
    ld a, d
    xor b
    add a
    ld [$eb98], a
    cp [hl]
    pop bc
    add hl, sp
    db $ed
    ld l, e
    ld h, e
    xor d
    xor b
    ld a, [c]
    ld h, a
    ld e, d
    sub [hl]
    sub b
    sbc e
    ld a, [hl+]
    scf
    sub h
    db $eb
    ld [de], a
    push hl
    ld e, [hl]
    ld [hl], $99
    inc a
    ld d, [hl]
    ld l, l
    and [hl]
    ld c, c
    ld d, [hl]
    sbc c
    xor c
    push de
    dec d
    ldh [$e6], a
    add hl, hl
    add d
    adc [hl]
    ld c, e
    ld de, $3b66
    jr nz, jr_00c_590a

    ld a, a
    and b
    ld sp, hl
    and e
    add l
    cp $d3
    ld d, a
    db $ed
    ld b, h
    add hl, sp
    ld d, l
    xor l
    ld a, [hl]
    cp d
    dec d
    and $11
    add h
    ld c, h
    dec d
    ld b, c
    ld e, $5b
    sbc l
    ld l, e
    pop af
    rst $10
    ld b, a
    push bc
    nop
    ld [hl], a
    cp e
    ld e, l
    inc d
    pop de
    push af
    inc a
    ld e, [hl]
    cp b
    or l
    ld d, b
    ld a, [$eef4]
    ld [hl], b
    adc d
    ld b, c
    ld l, e
    and b
    adc b
    ld d, b
    or h
    db $ec
    ld e, h
    jp nz, $e12a

    ld [hl], h
    inc h
    inc d
    db $ec
    adc c
    ld d, [hl]
    ld d, d
    sub d
    ld d, h
    ldh a, [$a1]
    ld h, d
    rst $20
    and d
    ld h, h
    ld e, b
    add sp, $55
    db $fc
    ld h, e
    dec sp
    or h
    sbc d
    rla
    adc l
    ld a, [hl+]
    xor d
    and l
    and d
    ld h, e
    ld h, h
    ld l, c
    ld d, [hl]
    add c
    dec [hl]
    adc e
    ld h, d
    add sp, -$20
    ld c, [hl]
    sbc b
    sub h
    ld h, d
    ld l, b
    ld a, [c]
    pop hl
    ld b, [hl]
    adc [hl]
    ld a, b
    pop af
    ld d, $3c
    ret z

jr_00c_59f2:
    ld d, c
    ld b, a
    adc $38
    rst $28
    sub d
    and e
    jp nc, $594f

    add c
    dec d
    adc a
    ld [hl], $31
    or h
    ld [c], a
    adc [hl]
    db $e4
    add $3c
    ret z

    add h
    jr z, jr_00c_59f2

    adc [hl]
    sbc b
    and h
    ld [hl+], a
    ld l, b
    pop hl
    ld c, [hl]
    adc b
    jp nz, $6852

jr_00c_5a16:
    db $e4
    ld d, l
    ld [hl+], a
    dec [hl]
    xor d
    xor d
    sub a
    push de
    ld [$96d5], sp
    adc c
    and l
    ld a, [hl-]
    xor d
    add hl, de
    ld sp, $897a
    ld l, c
    ld a, [de]
    dec sp
    ld [hl+], a
    dec h
    ld d, [hl]
    add d
    and h
    adc c
    ld b, [hl]
    dec sp
    sbc l
    scf
    ld c, b
    ld d, h
    ld d, b
    ld d, e
    xor l
    ld h, d
    reti


    ld b, l
    xor b
    adc c
    ld h, b
    ld d, e
    or [hl]
    add hl, bc
    inc d
    xor d
    db $fd
    sub h
    ld d, a
    adc [hl]
    push af
    db $eb
    adc h
    rst $18
    ld a, [$7c27]
    or e
    sbc h
    ld e, $78
    pop de
    cp h
    ld b, d
    and c
    daa
    ld a, [hl]
    sbc d
    cp h
    ld sp, $a910
    jp c, Jump_000_0b84

    ld d, d
    sub b
    and [hl]
    sub c
    call c, Call_00c_54c1
    adc h
    ld h, c
    dec h
    and a
    ld a, [hl+]
    ld b, h
    and c
    jr jr_00c_5a16

    ld hl, $a410
    or h
    ld l, e
    dec h
    pop hl
    add sp, -$5a
    pop af
    ld a, [hl+]
    or h
    ld de, $12b4
    ld c, h
    ld c, [hl]
    ld de, $4c9c
    ld h, a
    dec de
    ret nz

    add [hl]
    add hl, sp
    ld d, c

Call_00c_5a8d:
    and $41
    sbc l
    ld l, c
    adc e
    sbc h
    ld d, c
    adc l
    dec e
    ld a, [hl]
    ld [hl], b
    ld [hl], h
    adc [hl]
    ld c, [hl]
    ld [hl], c
    ld h, $3f
    sbc h
    ld e, l
    and a
    add e
    ld sp, hl
    call nz, $9e82
    rrca
    rst $20
    ld [bc], a
    rla
    ld [bc], a
    ld c, d
    ld [hl], c
    ld h, $3f
    sbc h
    dec d
    ld de, $1d13
    sbc [hl]
    ld [hl], c
    ld c, c
    add l
    inc e
    ld c, c
    adc l
    sbc h
    inc sp
    ld [hl+], a
    sbc [hl]
    adc h
    ld [$1543], sp
    ld a, [de]
    daa
    ld [bc], a
    ld l, l

Call_00c_5ac7:
Jump_00c_5ac7:
    ld sp, $2a58
    add hl, sp
    pop bc
    db $10
    xor d
    ld [hl], c
    ld b, [hl]
    jr jr_00c_5b22

    add hl, hl
    sbc d
    ld b, e
    ld de, $53a4
    dec e
    ld d, c
    ld [de], a
    ld e, d
    ld b, h
    ld sp, $5639
    db $76
    and c
    rlca
    ret nc

    inc l
    ld a, [hl+]
    ld b, h
    ld a, b
    xor e
    ld de, $4a51
    ld b, d
    ld e, e
    sbc l
    or c
    cp l
    ld de, $092a
    ldh [rBCPD], a
    or h
    ld a, [bc]
    ld c, h
    ld a, b
    ld d, c
    pop bc
    ld b, [hl]
    jr nz, jr_00c_5b43

    cp c
    push de
    xor b
    pop hl
    ld d, l
    ld d, b
    ld l, b
    db $e3
    ld e, d
    ld l, $38
    cp d
    adc [hl]
    jp hl


    ld a, $7d
    adc [hl]
    add sp, -$10
    ld a, [hl+]
    add hl, hl
    and l
    add hl, sp
    push hl
    dec c
    adc b
    adc $9a
    ld e, c
    ld c, b
    ld c, [hl]
    xor d
    xor c
    sub e
    cp [hl]

jr_00c_5b22:
    push de
    ld l, b
    ld hl, sp+$59
    call z, Call_00c_47a1
    ld [de], a
    sub d
    add e
    inc e
    adc l
    jr jr_00c_5b77

    inc d
    sbc [hl]
    inc c
    ld a, h
    ld a, [bc]
    ld [hl], a
    ld sp, $1edd
    ld a, [de]
    ld b, e
    call nc, Call_000_3ca7
    inc d
    sub e
    sbc l
    or b
    ld b, d

jr_00c_5b43:
    rst $20
    adc [hl]
    sbc l
    ld [hl], b
    rst $00
    jp Jump_00c_6680


    cp d
    sbc l
    dec a
    dec e
    ld c, h
    db $d3
    ret nz

    xor d
    xor c
    ld d, l
    ld e, a
    di
    xor c
    ld d, l
    dec b
    ld a, e
    rst $38
    rst $38
    db $e3
    sbc c
    ld e, a
    xor a
    db $fd
    rst $38

Call_00c_5b63:
    sbc [hl]
    add d
    add hl, sp
    sbc a
    and d
    ld h, d
    ld a, [hl+]
    and c
    add c
    ld l, b
    push hl
    ld a, b
    sub l
    inc d
    ldh [$93], a

jr_00c_5b73:
    adc [hl]
    adc c
    ld b, l
    ld b, [hl]

jr_00c_5b77:
    ld d, d
    sub [hl]
    ld [$388a], sp
    ld l, b
    xor b
    adc e
    call nc, $a02a
    ld e, b
    sbc d
    adc [hl]
    ld [hl], l
    ld d, h
    ld l, e
    rst $38
    push af
    ld l, $08
    rla
    jp nc, $97dc

    ld [$49af], a
    add [hl]
    rrca
    ld c, d
    jp $89e7


    ld d, c
    ld d, c
    ld d, h
    ld a, h
    dec d
    ld h, $db
    cp h
    cp b
    cpl
    ld hl, $b7fa
    ld d, b
    xor a
    cp $8c
    dec l
    db $ed
    ld c, b
    adc b
    ld d, d
    cpl
    or c
    and h
    ccf
    ld d, l
    inc sp
    ld a, e
    jp hl


    rst $30
    ld b, [hl]
    pop de
    ld a, [hl]
    dec h
    ld b, c
    jr jr_00c_5bea

    rst $38
    rst $38
    sub a
    jr nc, jr_00c_5b73

    rst $10
    db $fd
    ld e, a
    ld [$eda9], a
    ld e, l
    inc [hl]
    adc d
    ld h, c
    xor b
    ld l, d
    adc d
    ld a, [hl]
    cp l
    add sp, $2d
    ld d, l
    ld d, d
    and b
    ld h, e
    add l
    ld [c], a
    db $eb
    sub l
    call z, $d4ea
    add sp, $5f
    db $fd
    ld e, l
    ld d, e
    dec b
    rrca
    call nc, $7fe1

jr_00c_5bea:
    cp $a3
    scf
    jp c, $fcaf

    sbc $ae
    adc b
    ld d, l
    ld d, l
    rlca
    xor a
    rst $38
    cp $8e
    dec bc
    ld a, a
    cp $a8
    add l
    ld c, a
    ld sp, $f368
    jr z, @-$18

    sbc a
    inc d
    add d
    and a
    sbc a
    ld a, d
    ld h, c
    ld e, $0a
    ld de, $520a
    rst $00
    ld b, d
    ld b, h
    add hl, bc
    ld [hl], c
    ldh [$ef], a
    sub c
    sbc b
    xor c
    add hl, de
    push de
    ld a, a
    xor b
    ld c, c
    cpl
    cp $38
    ld l, c
    ret


    inc de
    sbc $91
    ld de, $0f55
    ld a, a
    rst $00
    rrca
    db $eb
    rst $38
    ld a, [$ed99]
    rst $38
    sbc h
    ld e, a
    rst $38
    ld d, l
    ld a, a
    ld [$feaf], a
    rst $38
    add h
    ld [hl], b
    ld a, a
    inc b
    ld d, h
    rla
    ld a, [$fe2f]
    db $d3
    add d
    sbc b
    and d
    rst $30
    and b
    sub h
    add e
    rst $38
    and h
    ld [hl], a
    db $ed
    add a
    add [hl]
    ld d, h
    ld b, h
    dec d
    ld e, a
    xor d
    cp a
    rst $38
    cp $a4
    sub $1f
    inc b
    ld h, h
    jp $f55a


    ld a, a
    rst $38

jr_00c_5c66:
    cp $42
    and l
    ld c, d
    ld e, h
    cp d
    xor e
    rst $18
    add a
    ld [$aa0a], a
    cpl
    cp a
    add d
    ld c, l
    ld b, e
    ld d, a
    inc de
    adc e
    dec sp
    ld d, d
    rla
    ld sp, hl
    rra
    inc l
    pop af
    jp nz, Jump_00c_5d84

    ld a, a
    cp l
    ld h, e
    db $fc
    rst $20
    dec l
    add hl, de
    or l
    call nc, $f247
    add hl, de
    ret c

    add h
    ld b, d
    or [hl]
    ccf
    ld a, [c]
    add hl, de
    ld [$9c40], sp
    ld d, b
    xor a
    ld b, [hl]
    rra
    ret c

    rst $00
    ld b, h
    rrca
    ld b, [hl]
    ld [$69fc], sp
    dec e
    ld d, c
    add l
    rst $00
    reti


    nop
    ld b, h
    or a
    ld a, a
    xor e
    push af
    ld d, e
    adc [hl]
    rst $38
    rst $38
    rst $38
    adc l
    ld e, a
    ld b, l
    ld b, [hl]
    xor a
    or c
    adc h
    add hl, hl
    ld c, c
    xor [hl]
    dec d
    ld a, [hl]
    dec [hl]
    ld [hl], a
    call nc, Call_000_1a54

jr_00c_5cc7:
    cp d
    ld b, $4c
    sub $d8
    add l
    ld b, c
    adc c
    ld b, c
    inc b
    jp z, Jump_00c_45db

    ld d, c
    ld l, d
    sbc b
    inc sp
    ld e, e
    ld a, d
    ret c

    ld d, d
    jr jr_00c_5c66

    pop hl
    ld d, l
    ld d, b
    xor b
    add a
    adc $08
    cp d
    ld hl, $ddf8
    add hl, bc
    ld d, l
    ld e, b
    rra
    add c
    ld c, l
    db $e4
    cpl
    and e
    xor [hl]
    ret nc

    or l
    inc b
    and h
    db $e4
    xor a
    ret nc

    rst $18
    and e
    xor d
    and e
    ret


    sbc $ba
    sub c
    dec e
    ld [hl], l
    cp $62
    sub d
    adc d
    ld de, $916b
    jr jr_00c_5cc7

    ld a, [hl+]
    dec bc

jr_00c_5d0f:
    ld b, b
    ret nc

    ld a, $c9
    sbc a
    add sp, $2a
    ld [de], a
    ld b, h
    dec de
    ld a, [bc]
    ld l, c
    ld a, l
    dec bc
    call Call_00c_6fb5
    ld b, [hl]
    or d
    rrca
    ld a, [de]
    ld c, d
    ld l, a
    rst $18
    ld a, [$c4a2]
    ld h, a
    dec a
    ld [hl], c
    dec c
    dec de
    and d
    xor d
    adc d
    inc l
    rst $20
    dec c
    dec d
    ld a, [bc]
    ld sp, $96d7
    and a
    ld b, h
    rla
    rra
    ld [de], a
    ld [hl], a
    cp l
    ld h, $93
    call nc, Call_00c_6354
    push bc
    ld d, l
    jr nc, jr_00c_5dc4

    jr jr_00c_5d9f

    pop bc
    ld a, h
    ld l, e
    jp nc, $2928

    jr @-$0e

    ld e, e
    add hl, de
    adc c
    sub h
    add h
    sub h
    rst $28
    ld b, d
    add hl, hl
    ld c, h
    ld [de], a
    ld h, b
    ld c, [hl]
    ld hl, sp+$56
    inc d

jr_00c_5d64:
    sub h
    sub h
    jr nz, jr_00c_5d64

    rst $28
    add d
    ld d, h
    ld d, b
    ld b, l
    ld l, $0c
    ld h, $3b
    ld d, [hl]
    rlca
    inc d
    ld de, $e04d
    adc [hl]
    reti


    jr jr_00c_5d0f

    reti


    dec sp
    ld d, h
    ld h, h
    ld h, b
    ld b, c
    add hl, bc
    jr c, jr_00c_5d97

Jump_00c_5d84:
    or d
    add c
    ld a, d
    ld [hl+], a
    add hl, bc
    ld d, e
    inc h
    pop af
    inc d
    ld sp, $83aa
    pop bc
    ld d, d
    ld d, h
    pop de
    ld c, [hl]
    ld a, [hl+]
    add c

jr_00c_5d97:
    dec b
    ld [hl-], a
    and c
    adc l
    sbc [hl]
    cp d
    ld c, e
    and b

jr_00c_5d9f:
    sbc c
    jr jr_00c_5dca

    ld l, d
    ld d, l
    ld d, [hl]
    ld h, c
    adc l
    inc d
    ld d, b
    ld h, e
    ld c, c
    add [hl]
    ld c, d
    rst $38
    pop bc
    ld h, d
    ld d, e
    ld h, h
    rla
    jp nc, Jump_000_19e8

    jp c, $e587

    ld l, d
    rrca
    call z, Call_00c_6f55
    ld a, [bc]
    sub h
    ld l, c
    ld d, [hl]
    sbc l
    ld a, a

jr_00c_5dc4:
    xor c
    ld d, b
    sub h
    adc d
    ld e, d
    ld c, c

jr_00c_5dca:
    ld a, d
    ld b, [hl]
    ld d, c
    sub [hl]
    ld b, c
    rrca

jr_00c_5dd0:
    and a
    and l
    dec d
    rrca
    adc c
    add $62
    jr jr_00c_5dfb

    db $eb
    ld a, [de]
    ld b, [hl]
    cpl
    rla
    rla
    ld hl, $461a
    ld d, $88
    and h
    dec hl
    cp $81
    xor c
    add [hl]
    ld [$a019], sp
    ld e, b
    and h
    add l
    inc d
    inc de
    inc d
    pop bc
    inc [hl]
    add d
    ld h, b
    ld l, b

Call_00c_5df8:
    sub l
    and b
    sbc b

jr_00c_5dfb:
    ld d, $08
    ld a, c
    add hl, hl
    dec [hl]
    ld e, b
    xor l
    ld e, l
    ld d, [hl]
    sub l
    and b
    ld l, l
    ld b, d
    dec l
    jr jr_00c_5dd0

    ld h, c
    ld c, d
    xor b
    xor d

jr_00c_5e0f:
    xor c
    db $fd
    ld e, d
    db $fc
    ld d, d
    ld [hl+], a
    db $e3
    ld e, d
    push de
    jr c, @+$6c

    db $fd
    add d
    ld [$1384], sp
    dec sp
    cp $22
    adc [hl]
    adc d
    ld d, b
    ld c, h
    sub e
    call $1881
    inc de
    db $d3
    cp h
    dec [hl]
    pop hl
    sbc $93
    daa
    xor l
    adc l
    sbc [hl]
    ld a, [hl+]
    ld l, c
    and c
    ld [hl+], a
    and a
    add l
    ld hl, $9310
    add d
    ld [de], a
    ld [$7bc7], sp
    ld [hl-], a
    jr nc, jr_00c_5e0f

    inc c
    ld a, b
    pop af
    add d
    jr z, @-$0e

    jp $df31


    jp nz, Jump_00c_4ccc

    ld [$c0a1], sp
    add d
    sbc l
    call c, $102b
    add h
    add hl, bc
    inc [hl]
    jp Jump_000_27c8


    ld d, d
    adc d
    add hl, bc
    dec bc
    ld a, [bc]
    ld l, e
    ld d, c
    push de

Call_00c_5e68:
    db $10
    and b
    sbc b
    ld h, $71
    jp c, $11a3

    inc bc
    ld [de], a
    sbc b
    ld h, e
    jr nz, @-$57

    ld c, h
    ld b, h
    dec l
    ld b, h
    pop hl
    add hl, hl
    adc d
    ld sp, $11d7
    ld d, $d5
    ld d, a
    add sp, $34
    ld b, d
    sbc d
    and [hl]
    ld l, b
    ld b, h
    db $f4
    ld a, [hl-]
    xor c
    ld [hl], b
    ld b, d
    sub c
    add hl, de
    jr z, jr_00c_5ede

    dec h
    ret nc

    ld c, b
    add hl, hl

jr_00c_5e97:
    ld [hl-], a
    dec l
    ld c, d
    or l
    sbc h
    inc de
    ld b, e
    ld b, [hl]
    ld [$0461], sp
    ld c, d
    adc h
    ld d, a
    ld [c], a
    add $e9
    ld [$1546], sp
    ld a, b
    ld a, b
    ld d, l
    add hl, hl
    ld e, [hl]
    jr z, jr_00c_5ef8

    add hl, bc
    ld [de], a
    add l
    dec c
    ld a, h
    sub c
    cpl
    db $e4
    push de
    ld l, $a5
    call c, $d496
    ld b, l
    ld b, l
    jr z, jr_00c_5f17

    xor b
    ld d, b
    ld [$e45c], a
    jr c, jr_00c_5e97

    ld a, [hl+]
    and c
    sbc e
    dec h
    ld d, [hl]
    ld e, [hl]
    ld h, b
    and e
    inc b
    sub c
    dec [hl]
    dec [hl]
    inc h
    ld a, [c]
    ld [hl], c
    jr nc, @+$26

    xor [hl]
    pop bc

jr_00c_5ede:
    inc h
    ld b, h
    ld h, $19
    ld d, d
    ld l, [hl]
    and b
    or b
    db $e3
    ld b, d
    ret nc

    ld d, d
    db $10
    cp c
    add h
    ld d, [hl]
    ld c, d
    dec c
    ld d, b
    cpl
    sub h
    xor d
    call nc, $0261
    ld h, a

jr_00c_5ef8:
    cp c
    add hl, bc
    db $10
    ld b, l
    ld b, h
    or l
    ld de, $c072
    sub a
    ld hl, $aa65
    inc l
    ld [de], a
    add hl, de
    jp Jump_000_100a


    ld hl, $520a
    ld h, l
    inc [hl]
    sub l
    dec e
    db $10
    ld [hl-], a
    inc c
    sub c
    inc bc

jr_00c_5f17:
    sbc [hl]
    ld [hl], d
    sbc b
    daa
    and [hl]
    xor b
    ld d, b
    add b
    ld b, h
    or b
    ld h, h
    add hl, de
    inc sp
    ld d, l
    scf
    adc b
    ld c, c
    ld e, d
    add a
    ld c, h
    jp nc, Jump_00c_7a64

    cp [hl]
    jp nc, Jump_000_0623

    sbc a
    sbc d
    jp nz, $0be9

    dec b
    ld [hl-], a
    ld a, l
    ld e, c
    rla
    add hl, de
    sub c
    ld d, b
    sub e
    ld a, [de]
    cp a
    ld h, b
    sbc d
    ld b, e
    sub d
    inc hl
    ld a, a
    inc b
    inc de
    ld a, [bc]
    sub l
    scf
    cp d
    ld h, $88
    sub d
    inc hl
    and d
    adc b
    adc [hl]
    sbc d
    jr jr_00c_5fbb

    xor c
    ld b, l
    inc b
    inc hl
    and l
    ld b, l
    ld [$64eb], sp
    dec h
    adc $a9
    db $eb
    adc $da
    and e
    push bc
    ret c

    and h
    daa
    ld [hl], l
    ld a, [bc]
    ld e, d
    xor e
    and $90
    ld d, [hl]
    or d

jr_00c_5f74:
    xor a
    or a
    add d
    sbc b
    xor a
    ld d, a
    db $fd
    cp l
    xor $29
    sbc [hl]
    add a
    and d
    add [hl]
    db $fc
    db $10
    ld a, [hl+]
    ret


    adc h
    ld c, h
    db $d3
    dec c
    add sp, -$2b
    dec de
    rst $28
    sub l
    ld c, e
    ret z

    ld sp, $c2cd
    call c, $7414
    ld [hl], b
    ld d, h
    ld [hl], l
    ld b, b
    call Call_00c_730a
    jp hl


    dec l
    dec e
    jr c, jr_00c_5fc4

    or c
    rst $10
    jr nc, jr_00c_6004

    sbc l

jr_00c_5fa8:
    ld [hl], b
    ld a, l
    rra
    ld a, [bc]
    ld [hl], a
    cp h
    dec b
    ld d, l
    ld e, e
    pop bc
    add hl, hl
    xor $3b
    ld d, a
    ld a, [$50aa]
    sub b
    and l

jr_00c_5fbb:
    db $76
    xor b
    ld [$8c6e], a
    dec d
    ld [hl], c
    ldh a, [$ed]

jr_00c_5fc4:
    jp c, Jump_00c_758e

    add sp, $55
    xor d
    adc h
    inc h
    ld e, $81
    db $f4
    push hl
    ld h, b
    jp c, $54a1

    reti


    ld l, e
    db $e3
    adc l
    ld a, a
    ld [hl-], a
    adc b
    sub e
    ld h, a
    dec b
    jr c, jr_00c_5ffc

    jr z, jr_00c_6004

    sub l
    ld e, [hl]
    sub l
    ld [hl-], a
    ld c, b
    add l
    inc b
    push de
    ld [c], a
    and d
    jr jr_00c_5f74

    adc [hl]
    dec c
    inc hl
    inc d
    call $14e3
    jr nz, jr_00c_6061

    jr c, jr_00c_5fa8

    ret z

    xor b
    ret


jr_00c_5ffc:
    ld c, l
    ld l, b
    push de
    and e
    rrca
    jp z, Jump_000_0553

jr_00c_6004:
    ld a, [hl-]
    pop hl
    ld d, d
    ld e, d
    db $e3
    or d
    ld sp, $89fc
    ld h, b
    ld b, c
    adc e
    ld d, e
    cp c
    cp $aa
    inc d
    dec hl
    adc d
    ld h, h
    dec d
    and e
    and c
    add d
    xor a
    add sp, $10
    add [hl]
    pop bc
    ld e, c
    adc b
    and e
    sbc d
    inc d
    or l
    ld c, b
    ld c, d
    and c
    ld h, e
    add l
    ld c, h
    sub d
    ld de, $aa7f
    add l
    adc c
    ld d, h
    or a
    call z, $c2d4
    ld a, [hl+]
    ld l, a
    rst $38
    and c
    ld e, d
    jp nz, Jump_00c_514b

    and e
    dec hl
    push de
    ld h, d
    ret c

    add l
    ld a, [c]
    ld hl, $a8d1
    add sp, -$57
    ld d, l
    ld l, b
    dec de
    add sp, $12
    ld [hl+], a
    ldh [$86], a
    ld a, [bc]
    ld hl, $974e
    ld d, a
    ret


    or [hl]
    ld hl, $3926
    jp c, $ff31

jr_00c_6061:
    ld c, c
    add c
    sub $89

jr_00c_6065:
    ld [hl], b
    or [hl]
    or e
    ld h, [hl]
    ld hl, $fa25
    ld [hl+], a
    inc d
    ccf
    ld d, l
    ld e, d
    add hl, bc
    ld l, c
    inc b
    sbc $91
    xor d
    dec b
    ld h, d
    pop hl
    xor c
    push hl
    ld hl, $050d
    jr c, jr_00c_6065

    pop hl
    add c
    ld c, b
    ld c, b
    cp l
    add hl, bc
    ld c, [hl]
    dec b
    dec h
    jr c, jr_00c_60f6

    xor d
    jp c, $ab05

    call nc, Call_00c_49d9
    sub d
    ld d, $aa
    ld d, c
    ld b, c
    ld l, l
    sbc a
    ld b, $f5
    and e
    add d
    push af
    ld d, $8a
    ld e, a
    xor a
    rrca
    ld a, h
    ld h, b
    db $fd
    jp nz, $8aa3

    cp a
    ld d, l
    ld a, [hl]
    adc e
    cp a
    rst $38
    ld [c], a
    daa
    cp b
    ld [hl], a
    add b
    sbc b
    daa
    sub [hl]
    add h
    add d
    ld c, a
    cp [hl]
    inc d
    ld b, [hl]
    ld b, d
    db $76
    ret nz

    add l
    dec hl
    ld d, l
    ld l, $15
    xor a
    xor h
    ld [hl], h
    and b
    pop bc
    ld d, l
    rla
    ld [hl], l
    ld c, b
    ld a, [c]
    xor $74
    ld hl, $a418
    add $13
    ld a, a
    sbc h
    db $ed
    ld a, [de]
    ret z

    add $48
    ld d, d
    sbc h
    ld c, l
    ld b, [hl]
    push af
    ld de, $3046
    and b
    sbc e
    or c
    sbc e
    ld a, b
    dec hl
    ld d, h
    xor c
    sbc h
    ld [de], a
    sbc e
    ret


    sbc l
    inc [hl]
    ld l, c
    dec de

jr_00c_60f6:
    ld h, a
    ld [bc], a
    ld h, h
    add $0b
    adc a
    inc [hl]
    sbc c
    xor c
    pop de
    jr jr_00c_617a

    ld b, l
    ret z

    add hl, sp
    add h
    ld de, $12cf
    jp z, $912c

    inc bc
    ld [bc], a
    ld c, d
    inc c
    add hl, hl
    call $b90b
    dec d
    inc bc
    ld c, b
    ld b, d
    sub d
    adc h
    rrca
    dec e
    inc e
    dec d
    ld d, h
    add d
    and e
    ld hl, $7128
    dec a
    inc e
    ld de, $6486
    add d
    and h
    pop bc
    ld a, h
    ld d, d
    ld [hl], b
    and [hl]
    add hl, bc
    rrca
    push de
    db $10
    adc d
    add e
    ld b, b
    sub h
    or $68
    or c
    sub h
    add l
    ld [$0dd6], a
    ld de, $9406
    call nz, Call_00c_7466
    xor c
    ld l, e
    ld d, $b0
    ld b, h
    pop bc
    ld b, c
    adc h
    ld sp, $55cb
    ld b, h
    cp b
    call nz, Call_000_23c4
    ld b, c
    inc b
    reti


    ld a, $75
    ld b, c
    db $ec
    adc d
    ld b, d
    ld [$847a], sp
    ld [$70b2], sp
    and [hl]
    ld c, c
    add hl, bc
    add hl, bc
    ld d, b
    ld b, b
    adc d
    ld b, e
    db $fc
    ld l, h
    or b
    dec h
    add sp, $54
    ld a, [bc]
    sbc c
    ld l, a
    jp c, Jump_000_26d8

    pop af

jr_00c_617a:
    add hl, hl
    ld e, d
    and l
    ld b, l
    ld [c], a
    xor d
    call nz, $c329
    ld c, b
    jp z, Jump_00c_41ad

    xor e
    and l
    pop hl
    inc d
    ld a, [$e470]
    ld h, $b5
    inc c
    inc d
    add d
    add l
    rrca
    ld a, [hl]
    and a
    ld h, $70
    jr z, jr_00c_61be

    ld l, [hl]
    ldh [$fa], a
    db $ec
    ld [hl], c
    ld a, [$a252]
    add h
    sub e
    ld d, h
    inc c
    inc d
    inc a
    add hl, sp
    ret


    dec b
    ld b, b
    db $fd
    ld hl, $ff18
    add l
    ld de, $8018
    ld b, h
    or h
    ld a, a
    push af
    ld d, b
    ld d, b
    ld c, [hl]
    rlca
    add l

jr_00c_61be:
    ld e, h
    dec hl
    ld a, [$85d3]
    adc d
    sbc c
    sbc c
    inc [hl]
    ld e, h
    inc [hl]
    ld a, [hl-]
    dec h
    add c
    ld c, l
    ld e, $be
    ld b, $f4

Call_00c_61d1:
    dec d
    ld a, d
    call z, $235e
    call z, Call_000_082d
    ld d, e
    ld a, [de]
    add hl, hl
    ld hl, $f121
    ld l, b
    ld d, h
    call $908a
    cp a
    add hl, bc
    ld [hl+], a
    adc d
    and d
    inc de
    ld a, [de]
    sub h
    ld d, e
    ld b, l
    ld [hl+], a
    ld [hl], h
    cp a
    add d
    daa
    call z, $562d
    db $e4
    or l
    adc $0a
    xor a
    db $fd
    rra
    ld h, e
    and [hl]
    rst $08
    ld b, $52
    ld d, b
    adc $aa
    and b
    xor d
    adc a
    rla
    ld l, [hl]
    add d
    add hl, bc
    sub $84
    dec d
    ld [bc], a
    adc d
    sbc h
    ld [$bb4a], sp
    db $ec
    jr z, jr_00c_623e

    xor e
    rst $30
    ld d, b
    add hl, hl
    ld c, a
    sbc c
    inc [hl]
    ld b, [hl]
    dec [hl]
    ld b, b
    adc e
    add $8a
    ld c, d
    ld h, d
    rst $10
    db $10
    sub l
    adc a
    sbc d
    and h
    inc h
    ld l, c
    ld c, b
    pop af
    add hl, hl
    add l
    xor l
    ld [hl+], a
    sub l
    ld [hl], c
    add h
    sub [hl]
    xor b
    and d
    sub a
    and [hl]
    ld d, d

jr_00c_623e:
    and c
    jp $a6c2


    ld [hl-], a
    xor c
    adc a
    and l
    ret


    or e
    ld d, d
    ccf
    cp d
    ld [hl], h
    ret z

    ld d, h
    ld d, $a7
    ld b, l
    ld a, [hl+]
    jp $f051


    and b
    ld [hl], a
    cp d
    sbc a
    ld c, a
    ld d, c
    ld b, c
    push hl
    dec a
    dec b
    rst $28
    ei
    db $d3
    ld d, l
    ld [hl-], a
    ld a, l
    jr nc, jr_00c_62bb

    and a
    add sp, -$57
    dec bc
    ld a, l
    add hl, hl
    ld [$b434], a
    add a
    rst $38
    rst $10
    db $e3
    jr c, jr_00c_62e3

    and c
    ld a, b
    sub $88
    or [hl]
    and d
    dec hl
    ld [c], a

jr_00c_627e:
    ld d, [hl]
    and l
    ld b, d
    ld b, [hl]
    sub $7d
    ld a, [bc]
    ld [hl-], a
    xor a
    ld h, e
    dec [hl]
    ld e, d
    ld e, d
    xor d
    rst $30
    and l
    ld a, [$65a3]
    add hl, bc
    ld b, $2e

Call_00c_6294:
    ld b, $a8
    adc $bd
    ld d, h
    adc b
    inc d
    pop de
    ld b, [hl]
    jp z, Jump_000_2b66

    xor d
    ld c, c
    ld c, b
    xor c
    ret z

    adc l
    ld e, l
    ld c, b
    ld a, d
    sbc b
    add $43
    ld c, c

jr_00c_62ad:
    ld h, h
    pop bc
    ld b, c
    push af
    ld [hl-], a
    add d
    ld e, b
    ld a, [hl+]
    ld [hl+], a
    adc h
    jr z, jr_00c_627e

    ld l, $b1

jr_00c_62bb:
    cp a
    ld c, d
    ld d, e
    ld l, d
    jr nc, jr_00c_630f

    sbc b
    jp nz, $f506

    dec d
    ld c, h
    sub b
    jp nc, Jump_00c_4aaf

    ld d, h
    cp b
    pop bc
    ld a, l
    xor a
    xor e
    call nc, Call_00c_6294
    db $10
    pop bc
    reti


    ld a, l
    and e
    ld b, a
    ldh [$bb], a
    ld sp, $55ae
    ld e, l
    ld [c], a
    dec a
    db $fc

jr_00c_62e3:
    call $a1d1
    xor c
    ld d, [hl]
    xor d
    ld d, c
    pop af
    rst $38
    and d
    ld a, [de]
    ld a, [hl+]
    and l
    ld d, [hl]
    adc d
    and d
    db $d3
    add hl, hl
    dec c
    di
    inc b
    ret


    inc sp
    ld c, b
    ld d, d
    xor b
    ld d, e
    dec bc
    ld h, d
    ret c

    ld d, d
    sbc [hl]
    inc d
    inc d
    adc b
    and l
    ld sp, $2a53
    sub [hl]
    adc b
    or d
    ld h, b
    add a

jr_00c_630f:
    pop hl
    or l
    ld l, $d1
    ld d, d
    ld d, d
    inc e
    push de
    ld b, d
    ld c, b
    ld d, d
    ld sp, $3265
    xor [hl]
    dec hl
    cp $15
    jr nc, jr_00c_6366

    db $f4
    jr z, @+$17

    jr jr_00c_62ad

    inc sp
    ld d, d
    ld e, b
    ld d, d
    xor d
    dec hl
    ldh [$b8], a
    jp nz, Jump_000_0a42

    ld [hl-], a
    ld a, e
    and [hl]
    ld a, [hl+]
    ld c, d
    and d
    ld [hl], c
    call z, $8296
    inc b
    push bc
    ld c, b
    adc b
    and l
    ld [hl+], a
    add l
    ld c, [hl]
    inc [hl]
    ld l, l
    jp nc, Jump_000_25de

    inc d
    add l
    and a
    push af
    ld [c], a
    inc d
    inc de
    jr c, @-$74

    dec l

Call_00c_6354:
    ld c, c
    ld d, l
    adc c
    ld d, h
    ccf
    ld [hl+], a
    ld d, l
    ld b, e
    call z, $3756
    ld e, [hl]
    adc h
    ld l, e
    db $dd
    ld d, h
    ld a, [hl+]
    rlca

jr_00c_6366:
    or l
    ld e, d
    adc l
    rst $28
    and e
    adc d
    xor e
    rst $38
    xor d
    add hl, sp
    ld h, a
    ret


    xor h
    add hl, hl
    add sp, -$3f
    ld a, [hl+]
    and c
    dec de
    ld h, $6c
    ld h, h
    sbc c
    pop bc
    ld a, a
    cp $91
    dec e
    add hl, bc
    ld l, b
    ld h, $b5
    rst $38
    and [hl]
    adc b
    ld h, $48
    ld a, [hl]
    add h
    db $10
    ld e, a
    xor a
    ret


    ld a, [bc]
    push de
    ld a, [$318c]
    rst $00
    ld e, [hl]
    ld c, h
    call c, $bf42
    cp $c8
    ld d, a
    ld a, [$9b32]
    ld b, h
    pop bc
    sbc b
    ld a, a
    db $fd
    ld d, l
    ld d, e
    ld a, [hl-]
    jp nc, $e984

    or h
    ld l, $c5
    ccf
    ld b, h
    ld c, c
    adc e
    ld e, a
    db $fc
    rrca
    sbc d
    or b
    ld e, a
    or d
    cp a
    add hl, hl
    ld [hl], d
    ld e, h
    sub c
    ld l, h
    xor l
    and [hl]
    xor e
    rst $38
    and c
    ld b, c
    cp [hl]
    ld l, a
    sub a
    ccf
    add a
    xor d
    ld h, l
    dec b
    ld a, a
    add h
    add l
    jr @+$28

    ld de, $fe73
    rla
    ld h, [hl]
    ld l, e
    add e
    ld [de], a
    sbc b
    or c
    add d
    ld l, c
    inc b
    pop de
    sbc a
    cp $4c
    add h
    add hl, bc
    inc c
    ld e, [hl]
    rst $38
    and h
    ccf
    rst $00
    dec b
    rst $38
    ld [de], a
    adc $b0
    ld h, l
    inc sp
    ld [hl], h
    ld e, l
    jr jr_00c_641e

    ld [$dfa8], a
    ld a, [$3308]
    ld [de], a
    xor d
    ld h, [hl]
    ld sp, hl
    sbc e
    rst $38
    rst $38
    sub c
    ld a, a
    ret


    ld l, e
    rst $38
    rst $38
    xor d
    rst $38
    db $e4
    ret nz

    ret z

    ld a, a
    rst $38
    ld a, [hl]
    ld b, h
    inc de
    dec h
    ld a, a

jr_00c_6417:
    rst $18
    rst $28
    rst $38
    rst $38
    sub a
    inc b
    rst $08

jr_00c_641e:
    ld a, d
    ld b, l
    jp hl


    sub d
    db $fd
    and e
    pop hl
    rst $38
    rst $38
    ld [hl], c
    sub e
    di
    ld a, [$1744]
    ld a, [hl+]
    cp a
    rst $38
    db $ec
    inc sp
    rst $18
    ei
    add $af
    rst $38
    ld [$87fb], a
    rst $38
    rst $38
    rst $38
    xor a
    add d
    rla
    cp h
    ld l, e
    rst $38
    rst $38
    rst $38
    rst $38
    cp a
    rst $38
    rst $30
    rst $38
    rst $38
    and e
    and $ae
    or a
    sub $bf
    rst $38
    pop hl
    dec c
    rst $30
    rst $38
    rst $38
    ld hl, $e641
    ld [hl], e
    ld a, [hl]
    call nz, $55b5
    jp hl


    ld [de], a
    rra
    db $fd
    ld c, d
    sub l
    ld b, [hl]
    ld [hl], e
    rst $38
    ld a, [de]
    xor c
    jr nc, jr_00c_648c

    add d
    rst $38
    cp $70
    db $ed
    jr jr_00c_6417

    ld b, c
    ld [hl], $10
    ld b, b
    call Call_00c_78ff
    ld b, [hl]
    rst $08
    ld b, [hl]
    pop de
    jr jr_00c_64d7

    db $e4
    ld b, c
    sub c
    ld e, $64
    ld b, h
    ld [hl], h
    add b
    ld b, h
    or a
    ld a, l
    dec d

jr_00c_648c:
    ld e, a
    di
    adc c
    inc d
    ld a, $a8
    push de
    push af
    ld a, a
    and b
    add c
    dec l
    ld h, e
    dec d
    ld a, [bc]
    adc b
    ld d, [hl]
    ld a, [de]
    xor d
    inc sp
    ld d, h
    dec d
    xor b
    dec d
    xor d
    xor d
    xor b
    and a
    ld b, $89
    ld l, b
    db $e3
    and b
    and h
    ld e, d
    add hl, sp
    xor l
    jp hl


    adc b
    ld b, e
    ld [hl], h
    ldh [$78], a
    inc h
    sub l
    inc b
    inc l
    cp [hl]
    ld c, h
    and d
    and l
    sub b
    cp b
    xor b
    dec l
    dec h
    ld b, d
    ld h, c
    sbc [hl]

jr_00c_64c7:
    rst $38
    add sp, -$7c
    inc h
    ld [hl+], a
    xor a
    ld a, e
    add c
    add d
    db $fc
    jr jr_00c_64e3

    add d
    db $d3
    ld h, $06

jr_00c_64d7:
    inc b
    dec a
    add l
    ld b, c
    ld h, $31
    ld d, a
    ld a, l
    ret z

    cp a
    ld d, l
    ld d, l

jr_00c_64e3:
    ld [hl-], a
    and c
    xor d
    xor d
    ld a, [hl+]
    xor d
    adc a
    rla
    ld [hl], b
    and a
    ld a, d
    add hl, de

jr_00c_64ef:
    ld c, l
    ld d, c
    call nz, $12be
    or c
    jp nz, Jump_00c_5183

    ld [hl], $aa
    xor d
    sbc c
    cp h
    ld a, [bc]
    call nc, Call_00c_75fd
    ld d, h
    ld h, b
    or d
    pop de
    dec c
    ld b, h
    or h
    sbc c
    jr nz, jr_00c_64ef

    xor h
    ld h, l
    ld c, l
    dec h
    or h
    sub c
    ld a, [hl+]
    ld l, e
    sbc c
    jr z, jr_00c_64c7

    add hl, bc
    ld c, l
    ld h, l
    ld b, l
    ld sp, $0f72
    adc h
    ld b, [hl]
    add l
    add hl, hl
    ld c, b
    jp nz, $d1c1

    jr nc, @-$01

    ld c, e
    rla
    ld c, [hl]
    ld b, h
    ld b, d
    sub b
    ld [c], a
    pop bc
    ld sp, $2da3
    adc h
    xor b
    xor b
    xor c
    and a
    ld e, a

jr_00c_6538:
    cp a
    sub a
    ld d, c
    pop af
    nop
    ld d, l
    cp l
    ld d, l
    ld a, a
    ld a, [$4ea5]
    ld [hl], a
    ld [$902a], a
    and a
    sub e
    adc c
    ld [c], a
    inc [hl]
    add $91
    jp nz, $9e4d

    ld l, $d3
    ld [$9928], sp
    inc sp
    sub e
    dec sp
    ld c, e
    ld b, e
    ld c, d
    adc h
    ld l, b
    ld [hl], e
    dec sp
    ld a, h
    xor b
    ld [de], a
    ld h, d
    call nc, $a598
    ld c, b
    ld c, h
    ld [c], a
    ld d, e
    adc d
    xor a
    ld c, l
    ld h, e
    xor [hl]
    adc [hl]
    ret z

    adc $94
    ld d, d
    ld h, [hl]
    scf
    adc h
    sbc [hl]
    ld a, [bc]
    add hl, sp
    jr z, jr_00c_65f6

    add $8e
    jr c, jr_00c_6538

    ld [hl-], a
    ld a, b
    jp nz, $4c33

    ld d, h
    db $ed
    ld c, h
    db $ed
    ld l, $31
    adc h
    ld e, b
    jp c, Jump_00c_58d3

    pop bc
    adc [hl]
    dec hl
    push de
    dec h
    ld h, d
    sub [hl]
    add hl, sp
    ld [$55ff], a
    ld l, d
    dec a
    ld l, l
    ld [$96a3], a
    jp nz, $189d

    ld b, [hl]
    ld d, e
    ld h, b
    rst $00
    ld c, [hl]
    ld a, [bc]
    ld a, [bc]
    adc [hl]
    ret c

    ret


    db $d3
    ld hl, $ba57
    ld d, h
    sbc d
    ld a, [hl]
    sbc h
    ld [$a423], sp

jr_00c_65bb:
    ld e, c
    adc [hl]
    ld b, d
    sbc d
    inc h
    pop de
    ld a, [de]
    ld [hl], $5a
    ld l, b
    sub l
    add hl, de
    ld e, h
    ld a, [hl+]
    ld d, h
    ld l, c
    ld c, $6f
    ld b, e
    dec e
    add hl, de
    sub d
    ld [hl], b
    xor c
    sbc [hl]
    ld b, h
    inc e
    ld [$9832], sp
    and a
    ld l, h
    sub b
    sub l
    ld de, $952e
    sub h
    jp z, $b1c0

    inc d
    ld e, a
    rst $38
    cp $82
    jp z, Jump_00c_41a4

    ld [hl], e
    jr c, jr_00c_6628

    adc [hl]
    rla
    rst $18
    ei
    cp e
    db $fc
    rrca

jr_00c_65f6:
    call nz, Call_00c_6c6e
    adc l
    rst $38
    rst $38
    db $fd
    add h
    ld d, h
    ld [hl], b
    ret z

    pop bc
    ld [hl], a
    ld [hl], h
    ld d, d
    ld [hl], e
    ld [hl], a
    ld a, [hl+]
    xor e
    xor b
    ld [hl], b
    daa
    ld b, h
    add hl, sp
    ld d, h
    adc h
    ld a, d
    ret nz

    ld b, h
    cp h
    push hl
    ld d, l
    ld d, e
    sbc c
    ld a, [$ada9]
    jr c, jr_00c_65bb

    ld sp, $d386
    ld a, d
    inc sp
    and b
    ld b, e
    adc l
    ld l, e
    ld c, l
    cpl

jr_00c_6628:
    jp nz, $a13a

    adc a
    ld b, l
    ld c, d
    ld d, e
    sbc d

Call_00c_6630:
    and d
    ld hl, $04ad
    xor b
    sub $d1
    or h
    ld d, $89
    ld h, e
    add d
    call nc, $c220
    ld hl, $4a8e
    db $fd
    ld d, [hl]
    adc a
    xor e
    sbc [hl]
    ld [hl], d
    ld e, d
    db $76
    rst $08
    dec e
    ld [$c0e9], a
    sbc d
    rst $18
    and $d0
    ld c, c
    sbc e
    rst $38
    add $f9
    sbc d
    rra
    and $ee
    ld h, h
    pop hl
    db $fc
    ld l, d
    cp $92
    and b
    ld hl, sp+$50
    and [hl]
    or a
    or h
    ld c, l
    ld sp, hl
    add hl, hl
    pop bc
    ld a, [hl]
    sub d
    pop af
    rst $08
    ld e, a
    rst $38
    ld [bc], a
    ld [hl], h
    ld b, a
    reti


    add b
    ld h, [hl]
    cp b
    sbc l
    dec h
    inc a
    dec d
    ld e, a
    ld c, c
    ld b, [hl]

Jump_00c_6680:
    and d
    ld d, a
    cp l
    ld c, h
    jp c, Jump_00c_7e94

    sub c
    or l
    dec b
    adc b
    rst $30
    and l
    ld a, [de]

jr_00c_668e:
    db $d3
    ld a, c
    dec bc
    ld d, d
    and l
    and c
    ld d, h
    ld a, $85
    xor e
    adc h
    jr nz, jr_00c_6704

    ld b, d
    sbc d
    jp nc, $05ad

    dec b
    ld d, h
    add $8c
    inc d
    sbc d
    ld e, c
    ld d, h
    or l
    xor b
    ld e, l
    ld [hl+], a
    ld d, [hl]
    ld d, e
    adc d
    sbc b
    inc a
    sub $bd
    ld d, a
    call z, $cbe8
    and e
    adc [hl]
    xor b
    ld l, b
    jp z, $168f

    sub e
    ld a, [de]
    inc [hl]
    db $f4
    inc d
    push hl
    and e
    dec de
    ld d, l

jr_00c_66c7:
    ld c, c
    cp $08
    push hl
    xor d
    jr nc, jr_00c_6748

    xor e
    ld c, h
    ld d, h
    ld [c], a
    pop de
    and e
    daa
    dec [hl]
    ld c, [hl]
    ld c, d
    push hl
    add hl, hl
    ld c, d
    ld d, d
    ccf
    ld b, d
    adc [hl]
    ld l, a
    jr nc, jr_00c_673d

    ld hl, sp-$51
    adc a
    adc c
    and h
    ld a, [c]
    ld d, l
    ld a, c
    jr c, jr_00c_66c7

    call nc, Call_000_1552
    ld d, a
    rst $38
    xor d
    sub e
    adc c
    ld b, d
    dec e
    sbc b
    adc b
    ld a, $8b
    ld e, [hl]
    jr c, jr_00c_668e

    adc d
    add c
    ld h, $0b
    push de
    ld a, [hl]
    adc l

jr_00c_6704:
    sub d
    jr jr_00c_676a

    dec d
    daa
    sub $d8
    db $e3
    xor b
    adc b
    and l
    dec d
    sub c
    sub [hl]
    db $d3
    adc [hl]
    ld l, $33
    ld b, c
    ei
    adc [hl]
    add h
    add [hl]
    ld sp, $8b54
    adc [hl]
    add hl, hl
    db $ed
    inc h
    ld b, h
    xor c
    ld a, [bc]
    ld [hl], h
    inc hl
    ld [bc], a
    ld sp, $a395
    ld a, [$ff94]
    and a
    ld h, d
    rst $18
    rst $38
    inc de
    rst $38
    xor h
    ld [hl], c
    ld b, [hl]
    dec l
    or l
    jp z, $f891

    ld a, [hl]

jr_00c_673d:
    add hl, de
    jp nz, $9290

    db $fd
    ld b, [hl]
    ld d, l
    xor e
    add $49
    ld l, l

jr_00c_6748:
    jp hl


    jp nc, $89a6

    ld [hl], e
    ld b, a
    ld c, l
    and $89
    pop hl
    ld c, a
    sbc d
    ld h, $75
    ld [hl+], a
    sbc h
    inc de
    ld h, c
    sbc d
    jr z, jr_00c_6704

    ld h, e
    ld a, b
    ld h, [hl]
    add hl, hl
    ld d, d
    sbc b
    rst $00
    dec e
    rlca
    sbc c
    and h
    ld h, [hl]
    ld l, c

jr_00c_676a:
    ld [c], a
    inc [hl]
    ld e, d
    ld a, b
    ld l, b
    cp [hl]
    ld c, l
    ld b, a
    adc d
    adc h
    ld a, c
    adc c
    add d
    add hl, bc
    adc $90
    sbc h
    inc l
    ld a, [c]
    db $10
    xor d
    xor d
    ld c, e
    db $10
    rst $38
    sbc h
    ld c, h
    ld [de], a
    ld c, d
    rla
    ld [hl-], a
    ld h, e
    db $fd
    inc e

jr_00c_678c:
    sub b
    dec h
    ld a, e
    ld c, c
    ld a, [hl-]
    sbc l
    xor c
    ld [hl], a
    and [hl]
    dec d
    rst $00
    ld a, [de]
    ld e, d
    ld h, e
    pop af
    ld [c], a
    ld h, $54
    ld b, h
    sbc l
    ld [hl], c
    db $e4
    nop
    ld b, h
    or d
    ld l, c
    ld c, d
    ld a, l
    dec b
    di
    add c
    ld e, l
    ld c, b
    ld b, e
    add sp, -$1f
    adc c
    rst $38
    ld l, c
    jr c, jr_00c_678c

    add $8e
    add a
    adc h
    add sp, $75
    inc [hl]
    ld d, e
    scf
    db $ed
    ld l, b
    and $78
    sbc d
    di
    daa
    adc b
    ld c, c
    ld d, e
    adc [hl]
    adc b
    ld h, b
    ld b, [hl]
    adc [hl]
    ld a, [hl-]
    ld d, $25
    pop hl
    ld [hl], h
    jp c, Jump_000_2dda

    rla
    adc d
    or h
    cp b
    push de
    or d
    add sp, $2c
    sbc b
    pop bc
    ld l, d
    ld [$54f4], a
    push bc
    ld hl, $d268
    or a
    push de
    ld a, [hl+]
    and e
    sbc d
    and e
    push bc
    sbc c
    inc [hl]
    add hl, bc
    ld c, h
    ld b, d
    ld a, [de]
    ld [hl], c
    and l
    ldh a, [$fe]
    ld [hl], c
    call nc, $13af
    ld b, a
    dec de
    rst $38
    rst $20
    ld [hl+], a
    ld d, l
    rst $38
    ld a, [$a670]
    dec [hl]
    ld [hl], l
    xor c
    jp nc, $ff91

    jp hl


    push de
    ld a, a
    ld sp, hl
    adc h
    ld h, a
    rla
    ld a, a

Jump_00c_6814:
    and $11

jr_00c_6816:
    ld l, a
    sbc d
    ld d, b
    ld h, l
    push bc
    ccf
    add $f9
    ld d, c
    dec bc
    db $fc
    sbc h
    or c
    dec d
    ld h, c
    ld de, $0211
    ld [hl], b
    ld hl, $111c
    add hl, bc
    ldh a, [$e0]
    ld [hl], a
    cp b
    ld d, b
    ld c, h
    push de
    inc a
    sbc a
    call z, $e5aa
    ld d, e
    call nz, $b5b8
    pop bc
    add c
    ld c, b
    cp c
    ld b, c
    db $f4
    db $eb
    ld a, l
    ld e, [hl]
    inc b
    ld hl, $98e4
    adc e
    ld e, d
    add hl, sp
    ret nc

    and [hl]
    ld [hl+], a
    rlca
    ldh [$d0], a
    push bc
    ld d, c
    adc c
    and d
    dec e
    jr c, @+$62

    ld d, e
    ld a, [bc]
    add c
    inc b
    adc b
    db $10
    add l
    inc b
    ld d, d
    ccf
    jr c, jr_00c_6816

    add [hl]
    ld sp, $4b89
    ld b, c
    dec h
    jr jr_00c_6891

    ld d, a
    ld c, e
    and c
    ld d, h
    add h
    cp d
    inc b
    ld de, $a489
    sbc $fc
    adc d
    ld c, b
    db $fc
    db $dd
    inc e
    jp hl


    adc d
    ld c, e
    ld b, c
    inc c
    ld d, b
    ld b, d
    dec b
    ld b, $30
    ld h, e
    sub c
    ld b, d
    ret


    ld b, [hl]
    pop hl
    or $a4

jr_00c_6891:
    inc de
    cp d
    xor [hl]
    ld h, $45
    ld h, c
    jp nz, $3225

    ld b, a
    ld c, [hl]
    ld a, [de]
    sub d
    cp a
    ld h, l
    rrca
    ld a, [hl+]
    ld h, $31
    db $e3
    ld b, l
    inc d
    adc b
    xor a
    db $fc
    ld e, a
    jr c, jr_00c_68e0

    add c
    cp $c3
    inc d
    sbc a
    db $fc
    ld a, a
    adc $08
    db $dd
    rra
    ld [$a864], sp
    ld [hl+], a
    ld l, $ce
    ld [$351d], sp
    sub l
    ldh a, [$fa]
    and e
    sub c
    ld l, c
    ld h, c
    db $fc
    jp nc, $c843

    add a
    ld b, c
    ld sp, $a448
    xor l
    sub d
    ld a, $32
    ld e, h
    add hl, de
    ld a, [hl+]
    rrca
    jr nc, @+$62

    add $50
    ld h, d
    scf
    ld [hl+], a

jr_00c_68e0:
    ld sp, $ff48
    inc b
    jp nz, Jump_00c_5232

    ld l, d
    ld [hl], d
    ccf
    dec h
    cpl
    push af
    dec bc
    jp nz, $aaca

    ld l, $2d
    dec de
    ld [hl+], a
    ld [c], a
    ld h, e
    dec bc
    add d
    sbc b
    ld a, h
    inc sp
    ld d, l
    ld a, [c]
    ld d, e
    or a
    ld c, l
    ld e, c
    dec e
    ld [hl], h
    ldh a, [rHDMA4]
    ld d, h
    add a
    adc d
    add e
    db $fc
    sbc b
    xor $a8
    ld l, d
    dec bc
    ld h, d
    ld l, l
    cp c
    ld h, e
    or l
    add hl, sp
    sbc l
    ld c, [hl]
    rst $28
    db $d3
    sub [hl]
    db $e3
    cp [hl]
    db $e3
    call z, $2a9c
    sbc [hl]
    and a
    rst $38
    adc e
    add sp, -$31
    sub d
    sbc [hl]

Call_00c_6929:
    dec d
    cp $45
    ldh a, [$2f]
    add l
    ld e, [hl]
    xor c
    ld [hl-], a
    ld e, a
    sbc e
    xor e
    ld a, [c]
    sub c
    or d
    rla
    jp $ccff


    rst $18
    sbc h
    cp a
    pop hl
    rlca
    ret nz

    ldh a, [$af]
    ld hl, $7bff
    inc sp
    ld [de], a
    ld a, [$446f]
    ld d, e
    ld a, a
    rst $38
    pop hl
    ld a, a
    add d
    db $db
    ld c, h
    sub c
    cp $6a
    and e
    db $e4
    rst $30
    rst $38
    db $e3
    adc $0f
    rlca
    add h
    ret


    dec [hl]
    ld a, [de]
    ld a, a
    and l
    ld hl, sp+$77
    ld a, [c]
    inc e
    pop bc
    pop hl
    ld hl, sp+$3c
    ret z

    ld h, $f7
    pop af
    rla
    ld hl, sp+$23
    pop hl
    add a
    and c
    ldh [$f8], a
    dec sp
    inc sp
    ld h, a
    rra
    sub c
    ld a, [hl]
    jr jr_00c_69ff

    ld [$8b7f], sp
    pop hl
    pop hl
    call z, $e89c
    ccf
    pop hl
    cp $10
    rst $38
    rst $38
    add a
    ldh [$cc], a
    sbc h
    rst $28
    rst $30
    cp a
    pop bc
    rrca
    rst $38
    rst $28
    sbc $cc
    ld b, e
    rst $20
    inc e
    or e
    ld a, l
    xor $0f
    or e
    ld a, [hl]
    call z, $45cc
    rst $00

jr_00c_69a9:
    ld a, [bc]
    cp e
    scf
    rst $08
    rst $38
    call z, $bbff
    ld [hl-], a
    ld [hl], c
    ld a, [$eefd]
    rst $38
    cp a
    ei
    scf
    ccf
    call c, $8bcf
    and [hl]
    sub a
    db $dd
    ld d, e
    rst $38
    rst $38
    ld [hl], a
    rst $38
    rst $38
    di
    dec b
    ld [c], a
    cp $6b
    ld c, b
    jr nz, @-$32

    scf
    db $ec
    call $cdff
    res 2, e
    rst $38
    sbc d
    ld a, b
    ld hl, $078f
    add a
    db $ec
    ret z

    push de
    ld hl, $5ea3
    add l
    db $fc
    ld h, h
    add e
    rst $28
    and c
    ret z

    ld a, b
    ld a, e
    jr nc, jr_00c_69a9

    and c
    ld b, h
    ccf
    and [hl]
    ld l, a
    and e
    call z, $1efe
    and d
    rst $38
    jp nz, $908d

    ld hl, sp+$7f
    db $e4

jr_00c_69ff:
    ld a, c
    ld e, a
    ld hl, sp+$40
    ret c

    add sp, $7c
    rst $18
    db $ec
    add e
    sbc $91
    ld b, e
    ld d, c
    xor l
    ld b, l
    ld e, d
    inc c
    inc a
    rst $18
    call c, $ecfd
    and a
    ld a, a
    ld a, a
    rst $38
    ld d, c
    inc l
    sbc $c9
    rst $18
    ld d, b
    push af
    ld e, [hl]
    ld c, d
    db $ed
    db $ec
    sbc [hl]
    add l

jr_00c_6a27:
    dec [hl]
    add h
    db $76
    ld a, $9c
    sbc a
    ld sp, hl
    db $db
    rst $38
    sbc h
    sub l
    dec e
    push af
    ld e, $68
    ld b, h
    cp h
    ld b, [hl]
    sub l
    jp nc, Jump_00c_4e1f

    inc l
    dec de
    or b
    ld b, d
    sbc b
    ld [hl+], a
    ld e, h
    ret


    add hl, bc
    cp [hl]
    add hl, de
    adc b
    ld c, c
    or e
    jr jr_00c_6aaf

    ld [hl+], a
    ld h, d
    ld l, d
    ld d, e
    add hl, sp
    inc b
    or l
    push af
    ld c, d
    sub e
    ld [hl], $25
    sbc b
    ld d, a
    ld c, e
    adc h
    db $e4
    ld h, b
    ld c, d
    jp $8c30


    ld a, [c]
    inc a
    ld d, $da
    dec e
    jr c, jr_00c_6a8b

    ld b, l
    sub b
    adc d
    adc [hl]
    ld d, $3a
    jp nc, $d1d2

    sub d
    ld d, e
    ld c, $23
    dec c
    ld a, [hl+]
    ld b, l
    adc b
    ld c, l

Jump_00c_6a7c:
    push hl
    sub h
    ld l, h
    add l
    and e
    sbc d
    xor d
    and e
    call z, $aa9c
    ld l, [hl]
    and [hl]
    ld d, d
    ld b, l

jr_00c_6a8b:
    jr nz, jr_00c_6a27

    cp a
    and h
    rst $38
    sub e
    cp $64
    or l
    db $ec
    ld b, l
    pop de
    ld d, h
    ld h, l
    ei
    di
    db $10
    xor d
    dec c
    inc h
    add $17
    ld [hl], $47
    rst $08
    xor $0c
    sbc d
    ld d, e
    add e
    ld a, [hl]
    pop bc
    rst $38
    or b

jr_00c_6aad:
    ld b, [hl]
    ld c, c

jr_00c_6aaf:
    ccf
    rst $38

Jump_00c_6ab1:
    ld d, e
    rst $38
    jp $f816


    pop bc
    rst $38
    add e
    rst $28
    rst $38
    add $51
    ld e, a
    rst $30
    ld a, d
    call $bdf1
    ei
    inc b
    ei
    rlca
    pop af
    adc e
    push hl
    dec sp
    inc sp
    rst $28

jr_00c_6acd:
    ld [hl], $31
    ld [hl], l
    ld b, h

jr_00c_6ad1:
    ld e, d
    inc de
    di
    sub $2c
    ld [hl], b
    ld b, e
    rlca
    ld d, h
    ld [$c547], sp
    nop
    ld [hl], a
    cp l
    rlca
    add c
    ld c, [hl]
    add h
    add h
    and $5c
    jr z, jr_00c_6ad1

    xor b
    ld a, [hl+]
    rla
    ld c, l
    call nc, $b360
    add c
    ld c, d
    xor d
    ld hl, $3355
    ld e, a
    adc d
    ld d, h
    jp c, Jump_000_3d0c

    ld e, [hl]
    add e
    ld d, l
    ld c, h
    rla
    add sp, -$48
    ld a, [de]
    ld [hl], $46

jr_00c_6b06:
    ld d, l
    and a
    xor c
    dec d
    ld d, a
    ld a, [$6031]
    ld e, b
    ldh [rOBP0], a
    sbc e
    ld c, b
    ld b, c
    push bc
    add sp, -$37
    ld a, [hl]
    and e
    sub e
    inc b
    ld e, $49
    add l
    ld [$d732], sp
    add sp, -$16
    ld c, b
    and c
    ld e, e
    jr nc, jr_00c_6aad

    and a
    inc a
    ld b, [hl]
    ld a, [c]
    ld d, b
    ld l, d
    ld [$3b85], sp
    call nc, $f650
    dec b
    ld h, a
    add l
    inc a
    dec de
    add a
    ld b, $a1
    ld l, l
    ld [hl-], a
    ld h, e
    xor l
    adc b
    ld l, l
    ld c, b
    adc c
    xor d
    ld a, [hl+]
    dec sp
    jr z, jr_00c_6acd

    adc d
    cp d
    sub l
    ld l, d
    adc b
    or l
    ld a, [hl-]
    ld l, b
    ld hl, $f857
    jp z, $abe2

    call nc, $31cd
    and d
    ld a, [hl+]
    and d
    xor [hl]
    dec b
    ld c, l
    xor e
    db $fd
    ld d, a
    add sp, -$4c
    push hl
    add l
    ld d, l
    ld c, l
    ld l, d
    ld d, [hl]
    adc d
    ld e, c
    jr c, jr_00c_6b06

    ld [$f5ab], a
    ld c, [hl]
    ld a, [hl-]
    dec d
    jr c, jr_00c_6ba1

    inc [hl]
    xor e
    call nc, Call_00c_4aa5
    and c
    ld [hl], l
    ld sp, $fb55
    ld d, e
    add d
    or l
    inc b
    rla
    add $86
    add [hl]
    push af
    ld h, $a8
    sbc d
    push af
    scf

Jump_00c_6b8f:
    xor c
    ld b, c
    add [hl]
    add [hl]
    adc e
    xor a
    ld d, h
    jp nc, $52bd

    dec d
    ld a, [hl+]
    adc d
    ld d, c
    ld d, e
    ld c, d
    cp a
    ld d, e

jr_00c_6ba1:
    ld a, [hl-]
    cp a
    and b
    db $f4
    adc e
    adc [hl]
    cp d
    push af
    scf

jr_00c_6baa:
    ld e, d
    ld [hl], $aa
    db $d3
    adc d
    cp l
    ld c, l
    inc sp
    ld b, l
    ld hl, $2804
    push hl
    xor a
    call nc, $ad96
    ld [hl-], a
    ld d, d
    inc hl
    cp d
    cp d
    add a
    ld hl, sp-$32
    push af
    ld a, [hl]
    dec sp

jr_00c_6bc6:
    ld l, c
    ld a, b
    jp nc, Jump_00c_6a7c

    ld b, d
    ld [hl], e

Call_00c_6bcd:
    cp [hl]
    sbc l
    jr nc, jr_00c_6bf2

    inc b
    add hl, hl

jr_00c_6bd3:
    call nz, $a7ff
    ld c, d
    db $10
    ld h, d
    adc h
    ld l, d
    cp a
    rst $38
    inc e
    ld d, a
    xor d
    ld b, [hl]
    ld a, [hl+]
    add h
    ld h, b
    add h
    scf
    rst $38
    ld a, [$4470]
    ld [hl], b
    ld b, [hl]
    ld d, $8a
    ld a, [hl-]
    ld h, c
    rst $38
    ld e, c

jr_00c_6bf2:
    rst $00
    ld de, $9302
    inc c
    ld b, l
    cp $95
    ret c

    ld b, a
    ld a, [hl-]
    ld de, $9511
    pop hl
    cp $42
    ld de, $46d7
    ld [$3e49], sp
    ccf
    jr nz, jr_00c_6baa

    ld a, [hl+]
    ld b, [hl]
    ld c, a
    dec b
    rst $30
    or c
    ld [c], a
    jr nz, jr_00c_6bc6

    jr nc, jr_00c_6bd3

    ccf
    and a
    add d
    sbc c
    and h
    ld b, l
    ld b, a
    ld [hl], h
    cpl
    and l
    dec h
    ld hl, $141e
    ld b, e
    rst $38
    jp hl


    inc d
    jr z, jr_00c_6c4c

    inc d
    sbc l
    ld d, c
    dec c
    ld e, b
    jp nz, $5c82

    ld h, e
    inc e
    pop af
    pop bc
    inc c
    add $d7
    xor d
    sub e
    ld [bc], a
    ld h, b
    sbc l
    ld c, c
    adc e
    rst $38
    cp $9a
    daa
    ld [hl+], a
    ld de, $a170
    ld a, a
    rst $38
    rst $38

jr_00c_6c4c:
    sub a
    dec c
    and a
    add e
    rlca
    ld a, a
    ldh a, [$c4]
    call nz, Call_00c_4ac6
    dec hl
    add sp, $27
    rra
    ld a, d
    add hl, hl
    ld de, $3009
    dec h
    push de
    rla
    ld [bc], a
    ld [hl], b
    or l
    inc de
    dec de
    ld b, b
    sbc h
    ld a, [hl-]
    ld d, d
    ld h, d
    add d

Call_00c_6c6e:
    ld b, d
    ld c, h
    ld l, a
    ld a, [bc]
    ld h, a
    rst $38
    xor a
    rst $00
    adc l
    ld [bc], a
    ld c, e
    rst $38
    rst $38
    jp hl


    or d
    db $fc
    xor c
    rlc a
    ld a, a
    rst $38
    rst $38
    ld a, [de]
    ld d, a
    db $ed
    db $fc
    ld [hl], e
    jp $f9df


    cp l
    ld a, a
    cp $9d
    cp l
    ldh a, [$c6]
    or b
    ld d, [hl]
    ld de, $46e0
    ldh [rLY], a
    and c
    rst $38
    ld c, e
    ld b, l
    db $d3
    ld d, a
    adc c
    and l
    ld a, l
    rst $30
    ld a, a
    call nc, Call_00c_61d1
    and e
    ld e, d
    jp z, Jump_000_1152

    ld h, d
    dec d
    ld d, l
    ld d, l
    ld [hl-], a
    or l
    ld a, a
    rst $38
    xor d
    and h
    ld a, [hl+]
    db $f4
    add $0a
    adc l
    ld h, d
    and e
    ld [c], a
    db $e4
    sbc $36
    adc b
    sub d
    jp nc, $3455

    adc e
    ld c, b
    ld a, c
    dec d
    dec bc
    sub e
    inc d
    and l
    ld sp, hl
    ld l, c
    ld d, h
    adc d
    call z, $a26a
    ld a, [hl+]
    adc b
    ld d, l
    add hl, sp
    ld l, d
    adc d
    ld d, h
    push hl
    cp b
    ld l, [hl]
    jr @-$0c

    db $e4
    db $eb
    sbc b
    ld [hl+], a
    ret


    or e
    rst $38
    add sp, $2e
    xor b
    dec h
    ld c, c
    adc a
    db $fd
    ei
    rst $38
    or d
    ld l, a
    ld e, a
    or h
    rst $38
    push af
    ld d, $99
    db $dd
    ld e, h
    ld b, h
    ld l, e
    rra
    ld d, $9c
    ret


    sub l
    dec de
    ld sp, hl
    add hl, hl
    adc h
    ld d, d
    ld h, d
    pop af
    inc c
    sbc b
    ld b, l
    ld a, [$3493]
    ld b, l
    ld h, [hl]
    ld [de], a
    ld b, e
    ld b, h
    inc h
    ld [hl], h
    sbc h
    or $93
    ld [bc], a
    sbc h
    xor a
    dec bc
    and c
    ld b, a
    inc a
    ld c, h
    ld a, c
    ldh [$66], a
    cp h
    ld e, e
    db $d3
    xor c
    ld d, l
    ld sp, $8554
    dec bc
    ld c, [hl]
    ld d, l
    add d
    cp [hl]
    sub d
    ld e, $82
    ld e, l
    add $d3
    ld d, l
    ld l, a
    xor d
    inc e
    ld l, d
    ld a, [bc]
    dec c

jr_00c_6d3f:
    ld [hl+], a
    dec hl
    add d
    ld c, c
    ld e, a
    and [hl]
    and e
    ld [$58c1], sp
    sub h
    adc $0b
    and b
    sbc b
    adc $56
    inc b
    add hl, hl
    ld a, c
    and $55
    adc e
    ld d, l
    sub e
    ld c, d
    jr nc, jr_00c_6dbe

    jr jr_00c_6d86

    ld sp, $4ca0
    jp c, $8c30

    inc d
    ld d, h
    add h
    db $e3
    ld h, [hl]
    ld c, h
    inc de
    sub l
    ld [hl], $90
    adc h
    ld hl, $384e
    cp c
    ld h, $82
    ld sp, $9249
    ld a, [de]
    dec de
    ld d, b
    ld b, [hl]
    ld a, [hl+]
    rlca
    ld hl, sp+$15
    ld l, d
    ld hl, $8230
    dec d
    adc l
    db $ec

jr_00c_6d86:
    sbc b
    cpl
    ld hl, sp-$78
    ld d, e
    ld [hl], $93
    dec e
    rlca
    ld b, c
    ld h, $09
    add hl, hl
    inc d
    add hl, hl
    ld d, d
    ld h, e
    ld c, b
    ld l, b
    ld l, b
    add $aa
    dec b
    jr nc, jr_00c_6d3f

    adc [hl]
    xor b
    add l
    ld hl, $6232
    db $e3
    ld b, $0b
    ld c, c
    ld e, b
    inc d
    db $10
    sbc h
    pop bc
    push af
    add hl, bc
    ld l, b
    jp c, $a0ff

    add [hl]
    or [hl]
    ld a, [bc]
    ld b, l
    or h
    add l
    scf
    ld c, [hl]
    ld a, a
    xor d

jr_00c_6dbe:
    ld [c], a
    ld sp, $a34c
    dec [hl]
    ld c, b
    ld c, d

jr_00c_6dc5:
    adc h
    add hl, hl
    add c
    add [hl]
    xor b
    add h
    sub $be
    jr c, @+$5b

    ld e, d
    ld [hl+], a
    inc d
    ld [c], a
    xor d
    adc e
    push hl
    ld [c], a
    ld [hl], $16
    inc d

jr_00c_6dda:
    add sp, -$7e
    ld a, [hl+]
    adc b
    ld a, c
    ld l, b
    ld d, $3a
    and [hl]
    ld e, [hl]
    ld a, [hl+]
    push af
    ld l, b
    rst $00
    ld a, b
    jp hl


    sub $82
    add hl, bc
    adc d
    add hl, bc
    ld d, [hl]
    sbc l
    rrca
    ld l, b
    add hl, hl
    add h
    add hl, bc
    inc l
    ld [de], a
    ld l, h
    adc h
    jr jr_00c_6dc5

    ld c, $10
    db $e3
    and h
    or c
    ld d, d
    ld d, d
    ld a, [de]
    ld a, [bc]
    ld sp, $0683
    ld e, h
    push af
    add $51
    inc sp
    ld e, h
    ld h, h
    rst $38
    and b
    add d
    or l
    add l
    cp d
    sbc c
    ld a, [hl]
    inc d
    ld h, [hl]
    or c
    jr z, jr_00c_6e5c

    pop bc
    inc c
    jr nc, jr_00c_6dda

    ld h, l
    ld d, c
    sub d
    sbc c
    ld b, l
    add sp, -$18
    ld hl, $5226
    ld d, e
    ld [hl], b
    ld b, [hl]
    add hl, hl
    add h
    ld b, h
    ld c, d
    cp c
    adc l
    ld d, h
    pop bc
    add h
    ld e, h
    ld [hl-], a
    sub b
    and d
    xor h
    ld h, [hl]
    add d
    ld d, h
    ld b, d
    add hl, bc
    ld c, c
    ld l, l
    ld b, c
    ld c, d
    xor d
    ld h, e
    ld e, l
    ld c, l
    adc a
    ld sp, $8409
    ld a, [hl+]
    ld a, [bc]
    xor e
    jp hl


    ret nz

    xor e
    jp nz, $a8cb

    xor b
    dec hl
    pop de
    ld [hl], d
    ld d, h
    and l
    and h

jr_00c_6e5c:
    ld d, l
    ld a, [bc]
    db $dd
    ld [$d185], a
    adc h
    ld [$3170], sp
    inc l
    ld h, d
    ret


    add l
    inc b
    add hl, hl
    sub h
    add hl, hl
    add h
    ld [hl], $d3
    ld b, l
    ld h, $34
    ld l, l
    ld c, h
    xor [hl]
    or l
    dec bc
    dec h
    ld [hl+], a
    push de
    inc e
    or l
    ld b, [hl]
    dec sp
    xor e
    ret nz

    push bc
    ld [hl], d
    sbc c
    ld [hl], d
    ld l, b
    sub b
    adc h
    ld b, l
    rst $30
    jp hl


    dec c
    ld e, d
    xor e
    pop af
    or e
    ret nc

    ret nz

    sub l
    ld de, $b15c
    ld d, h
    add hl, hl
    pop bc
    ld c, d
    pop hl
    dec bc
    ld d, $a4
    ld [hl], b
    call nz, Call_00c_7327
    db $ed
    ld d, $c4
    daa
    ld d, h
    ld de, $4508
    inc [hl]
    dec bc
    ld b, a
    ld h, h
    ei
    jr jr_00c_6f07

    add hl, de
    add b
    ld b, h
    cp c
    inc d
    ld e, a
    ld c, [hl]
    ld [hl], a
    xor l
    ld b, [hl]
    call z, Call_000_2195
    ld d, l
    ld c, d
    ld d, d
    inc de
    rra
    xor [hl]
    db $e4
    ld a, [hl+]
    ld d, d
    xor d
    inc sp
    or a
    adc b
    and d
    dec l
    ld h, e
    add d
    adc d
    ld e, l
    inc d
    add [hl]
    sub e
    adc c
    ld b, [hl]
    and c
    ld h, d
    ld h, e
    ld [hl], a
    adc c
    add l
    jr c, jr_00c_6efc

    xor $30
    add d
    jr c, jr_00c_6ef9

    dec bc
    ld d, b
    ld d, d
    db $e3
    add d
    cp a
    ld e, a
    ldh [$62], a
    add hl, hl
    add hl, sp
    ld l, d
    ret z

    ld e, a
    add sp, -$1a
    cp $1f
    di
    and c
    rst $10

jr_00c_6ef9:
    xor d
    or e
    sbc [hl]

jr_00c_6efc:
    and e
    call z, $c2de
    ld b, d
    ld [hl], c
    ld h, $4c
    add $7c
    xor b

jr_00c_6f07:
    ld [hl], h
    ld d, d
    or l
    ld [hl], $67
    inc bc
    dec c
    ld [bc], a
    ld b, [hl]
    add d
    or h
    ld l, e
    ld [de], a
    and c
    db $f4
    dec d
    ld b, a
    ld [hl+], a
    adc l
    ld a, l
    call z, $ab9b
    call nz, $c6e4

jr_00c_6f21:
    add sp, -$34
    ld e, [hl]
    dec [hl]
    inc l
    ld l, c
    ld e, d
    and l
    ld b, h
    pop de
    pop bc
    dec b
    ld b, l
    ld b, l
    ret


Jump_00c_6f30:
    db $d3
    ld b, b
    add sp, -$4e
    ld [hl], e
    ldh a, [rSTAT]
    adc [hl]
    ld de, $fccf
    ld a, h
    ld e, b
    ld h, [hl]
    or h
    ld d, e
    rst $00
    ld c, b
    ld c, d
    sub d

Call_00c_6f44:
    sbc c
    inc d
    ld [de], a
    sub d
    or e
    scf
    ld d, $30

Jump_00c_6f4c:
    sub h
    xor c
    add d
    dec b
    and c
    ld e, d
    and h
    ld [hl], d
    sub b

Call_00c_6f55:
    xor l
    ld [hl], b
    adc e
    and d
    xor d
    adc c
    ld h, e
    add hl, bc
    jr nc, jr_00c_6fa9

    xor b
    push hl
    ld h, d
    jp nc, Jump_000_0913

    inc [hl]
    xor c
    ld b, a
    sub h
    ret


    ld a, [de]
    inc [hl]
    db $e4
    jp z, $2154

    sub [hl]
    sub b
    sub d
    jr z, @+$6a

    call $cf14
    cpl
    rst $00
    rla
    ld b, [hl]
    add l
    ld [$60a4], sp
    db $d3

jr_00c_6f81:
    ld e, d
    ld a, [hl+]
    ld b, e
    jp $3ce4


    ld d, d
    pop hl
    ld b, c
    add hl, sp
    ld a, [de]
    add hl, bc
    ld b, d
    xor h
    ld a, [de]
    ld b, e
    jr nc, jr_00c_6f21

    ld b, $48
    sub h
    ld a, [hl-]
    ld a, [hl+]
    ld [hl], b
    adc $86
    dec l
    ld h, b
    ld a, h
    jp nz, $ce60

    ld l, [hl]
    ld l, $46
    ld c, h
    db $e4
    bit 1, h
    db $ed

jr_00c_6fa9:
    inc d
    ld d, $ba
    sbc a
    ld c, c
    ld e, d
    ld c, [hl]
    ld c, b
    sub h
    ld h, h
    rla

jr_00c_6fb4:
    dec bc

Call_00c_6fb5:
    ld a, [de]
    rlca
    inc c
    ld h, e
    inc c
    jr c, jr_00c_6f81

    dec b
    add [hl]
    and a
    rlca
    and b
    db $f4
    dec de
    inc sp
    ld c, b
    adc h

jr_00c_6fc6:
    and d
    add hl, de
    ld h, b
    ld d, a
    ldh a, [rHDMA2]
    inc de
    ld c, b
    ld h, e
    ld a, d
    rla
    and d
    ld d, [hl]
    dec hl
    inc [hl]
    adc [hl]
    ld b, l
    ld d, h
    ld a, b
    ld a, $21
    ld sp, $3042
    ld d, h
    jp nc, $a778

    add d
    ld [$89c6], sp
    ld e, d
    inc b
    inc de
    ld d, l
    ld b, c
    dec c
    ld a, [$3107]
    ld d, [hl]
    add a
    jr jr_00c_6fb4

    dec h
    sbc d
    ld h, d
    sub l
    adc h
    inc sp
    ld d, h
    sub [hl]
    ld d, b
    ld h, d
    ld h, $d5
    ld l, b
    inc hl
    sbc d
    add hl, bc
    add [hl]
    ld [$7cc2], sp
    sub $42
    ld e, e
    ld l, b
    and h
    and [hl]
    add hl, hl
    ld c, c
    xor d
    dec bc
    inc bc
    ld b, $36
    and c
    dec a
    and b
    call z, $ec0e
    dec bc
    and c
    ld hl, $aa12
    adc l
    db $e4
    ld e, a
    ld hl, sp-$22
    rst $28
    ret nc

    ld a, a
    ld d, l
    db $ed

jr_00c_7029:
    ld hl, $d707
    rst $38
    push hl
    ld d, h
    ld c, l
    ld d, c
    ld a, $61
    ld l, b
    inc h
    ld a, d
    ld c, l
    ld d, c
    ret


    push hl
    add sp, $5a
    ld b, d
    rla
    and [hl]
    ret nc

    jr nz, jr_00c_6fc6

    add hl, bc

jr_00c_7043:
    ld e, $46
    add a
    and c
    db $e4
    and e
    ld a, d
    ld a, [bc]
    ld d, h
    add d
    jr z, jr_00c_708f

    adc h
    ld d, $8d
    and c

jr_00c_7053:
    pop hl
    db $e4
    ld hl, $ff06
    add hl, de
    inc hl
    db $10
    adc h
    add a
    ld l, b
    ld e, e
    ld a, [hl]
    add hl, bc
    dec bc
    ld e, a
    rst $00
    inc e
    add d
    ld d, $fb
    set 0, l
    and c
    cp h
    ld l, h
    sub e
    inc de
    dec c
    ld e, a
    jp nc, Jump_00c_4a14

    rrca
    sbc d
    or b
    ld b, h
    ld b, b
    add h
    sub a
    ld a, d
    and [hl]
    ld e, [hl]
    ld l, c
    jr jr_00c_7043

    sbc c
    ld e, [hl]
    push bc
    pop bc
    ld h, [hl]
    ld a, b
    ld b, l
    ret


    ld de, $e99d
    db $10
    ld c, l
    and [hl]

jr_00c_708f:
    jr c, jr_00c_7053

    adc h
    ld [hl-], a
    rrca
    ld a, [$fd0a]
    sub d
    add h
    dec c
    sbc e
    inc hl
    jr nz, jr_00c_7029

jr_00c_709e:
    add sp, $5f
    or $98
    or l
    ld [hl], c
    add d
    ld [$9040], sp
    adc a
    dec c
    ld e, l
    cp [hl]
    ld de, $2828
    ld e, [hl]
    ld l, d
    ret nz

    add h
    rst $38
    cp $a3
    add sp, $25
    and e
    ld a, c
    rst $00
    db $f4
    ld b, d
    pop af
    rra
    ld a, [bc]
    ld b, d
    dec c
    rst $20
    daa
    rst $38
    push de
    ld e, [hl]
    ei
    inc d
    add e
    push hl
    cpl
    jp hl


    sbc l
    jp hl


    cpl
    cp $08
    push bc
    ld a, b
    xor a
    ld a, [c]
    ld sp, hl
    ld l, c
    ld d, a
    rst $38
    db $fd
    ei
    ld b, h
    jr nz, @+$01

    db $d3
    ld d, b
    ld c, [hl]
    sub b
    ld hl, sp-$43
    and c
    and h
    cp a
    add h
    add hl, bc
    dec c
    ld [bc], a
    ld de, $cf08
    add e
    sbc $f2
    ld [hl], $df
    push af
    ld hl, $461a
    ld e, a
    ld de, $16c6
    db $e3
    rla
    ld [$8544], sp
    ld c, e
    ld d, d
    call nc, $94e1
    ld d, c

jr_00c_7107:
    and h
    jr jr_00c_709e

    adc $2a
    adc e
    adc c
    ld h, e
    ld e, b

jr_00c_7110:
    and a
    ld [hl], $5a
    ld sp, $8e89
    jr z, jr_00c_7107

    adc h
    and e
    sub a
    ld d, e
    pop bc
    adc $e6
    ld sp, $5c4e
    adc $39
    and h
    or [hl]
    add hl, sp
    sub l
    dec l
    ld d, [hl]
    ld sp, $aa64
    scf
    ld b, c
    sub b
    ld h, d
    add hl, hl
    add hl, sp
    ld [hl+], a
    inc hl
    ld a, [de]
    inc a
    cp d

jr_00c_7138:
    cp $8a
    rrca
    xor b
    jr nz, jr_00c_7138

    ld d, d
    ld d, a
    adc l
    db $eb
    jp Jump_000_076f


    cp d
    add d
    ld e, a
    sub e
    ld d, b
    jr z, jr_00c_7110

    ld a, l
    ldh [$a9], a
    ld c, a
    sub d
    pop de
    add h
    ld b, a
    rst $30
    sbc b
    ld a, b
    ld sp, $e6c5
    rla
    sbc h
    sbc [hl]
    ld h, b
    ld sp, hl
    ret


    ld a, [hl]
    sub a
    rst $20
    dec sp
    sub e
    rlca
    sbc h
    xor a
    jr jr_00c_71c4

    ld [hl], c
    db $db
    jr jr_00c_71e7

    call $2f69
    ld a, [bc]
    sub b
    sub d
    sub [hl]
    cp a
    call nz, $fedf
    ld l, $2f
    ld l, d
    ccf
    ld a, [bc]
    ld h, a
    ld l, a
    ld l, a
    dec bc
    ld e, e
    db $e3
    rra
    ld c, $55
    and c
    ld l, d
    xor c
    ld d, e
    dec [hl]
    ld c, l
    ld de, $a670
    add d
    ld d, [hl]
    sub e
    rlca
    cp a
    cp $57
    xor d
    ld a, a
    rst $38
    ld c, b
    ret nc

    sub d
    sbc [hl]
    sub h
    adc [hl]
    and [hl]
    ld e, [hl]
    adc d
    xor [hl]
    ldh [$86], a
    dec h
    ld [$0a85], a
    add c
    ld [hl], $50
    ld h, d
    jr nz, @+$59

    cp $f5
    add hl, sp
    ld a, c
    ld hl, $09ed
    or c
    ld d, d
    ld [hl+], a
    inc d
    or [hl]
    ldh [rBGP], a
    dec h
    jr jr_00c_723c

    ret


    adc d
    cp l

jr_00c_71c4:
    ld e, b
    ld [hl], $9a
    ld h, $08
    ld d, c
    sbc b
    add h
    xor e
    ld b, d
    xor d
    xor [hl]
    sub d
    ld h, d
    ld d, b
    add $93
    dec [hl]
    ld sp, $2a9f
    add c
    ld h, h
    db $ec
    xor d
    ld [hl+], a
    jp c, Jump_00c_4e51

    add a
    pop hl
    add [hl]
    ret z

    ld d, d
    inc hl

jr_00c_71e7:
    adc l
    add [hl]
    dec h
    inc d
    ld h, d
    jp nc, $c5d4

    ld a, [de]
    jr nc, jr_00c_723f

    ld [de], a
    ld d, h
    call $e4a2
    inc d
    pop bc
    ld e, c
    dec b
    jr nc, jr_00c_725b

    ld [$a1b6], sp
    sub d
    jr jr_00c_7260

    dec h
    ld l, d
    xor b
    jr jr_00c_725a

    cp d
    db $fc
    inc h
    dec h
    sbc b
    ld e, a
    and l
    ld e, [hl]
    add l
    add e
    ld [hl+], a
    rrca
    ld hl, $1862
    sbc $9c
    ld d, c
    ld e, [hl]
    sbc e
    adc d
    ld c, [hl]

jr_00c_721e:
    ld d, [hl]
    ld e, b
    ld l, a
    cp b
    add l
    adc e
    sub l
    xor d
    ld [c], a
    sbc d
    and a
    rrca
    ld e, l
    ld a, a
    xor $69
    ld a, [hl+]
    cp c
    add hl, bc
    ld [$6165], sp
    rst $18
    jp hl


    and l
    rst $38
    rst $38
    ld b, c
    add hl, de
    rst $10

jr_00c_723c:
    rst $38
    jr jr_00c_721e

jr_00c_723f:
    rst $38
    call nc, Call_00c_416d
    rst $18
    ret nz

    adc e
    dec d
    ld [$c209], a
    db $db
    ld c, b
    ld [hl], a
    and h
    db $fd
    ld [bc], a
    ld c, d

Call_00c_7251:
    sbc b
    ld l, d
    ld d, $f8

jr_00c_7255:
    cp e
    ld sp, hl
    ld a, [bc]
    ld sp, hl
    add h

jr_00c_725a:
    ret


jr_00c_725b:
    rla
    cp $15
    add a
    rlca

jr_00c_7260:
    ld a, d
    dec [hl]
    ld b, c
    jr @-$31

    ld a, [$6985]
    jr nc, jr_00c_72ab

    add l
    add a
    and [hl]
    ld [hl], d
    pop af
    ld d, $85
    jp hl


    jr jr_00c_7255

    ld hl, $69fe
    sbc b
    ld a, a
    xor a
    adc h
    add [hl]
    inc de
    cp $69
    sbc b
    ld a, l
    ei
    inc b
    inc sp
    add a
    cp $11
    adc e
    jp hl


    rrca
    or a
    call nz, $e0e0
    rst $38
    db $10
    sub [hl]
    rst $18
    rst $38
    add sp, $3c
    ld h, c
    jp $a31a


    ccf
    db $fc
    cp $42
    dec [hl]
    dec hl
    ld a, [$22ad]
    adc e
    ccf
    rst $08
    ld hl, sp-$48
    ld a, b
    jr z, @+$01

    rst $38

jr_00c_72ab:
    add d
    db $10
    or b
    ld e, d
    add a
    cp $0f
    pop hl
    ld hl, sp-$60
    rst $38

jr_00c_72b6:
    rst $38
    inc de
    inc de
    inc de
    db $d3
    ld e, a
    inc c
    ld e, a
    call nc, Call_000_1cc7
    cp [hl]
    sub c
    ld a, [hl]
    xor e
    inc [hl]
    ld [hl], d
    ld [hl], $11
    jr nc, @+$77

    ld c, h
    ld h, d
    ld b, h
    cp b
    ld a, [de]
    ld c, [hl]
    push bc
    and [hl]
    or l
    ld [hl], $bd
    ld l, d
    jp z, $ed82

    ld d, e
    dec h
    ld e, d
    sbc d
    ld a, [hl+]
    add hl, de
    ld [hl], e
    ld b, h
    db $e3
    sbc b
    jp hl


    ld b, l
    xor c
    jr c, jr_00c_7349

    ld c, c
    ld b, c
    ld d, b
    ld h, e
    adc c
    dec bc
    cp l
    rst $00
    add d
    inc [hl]
    ld d, d
    ld d, b
    cp $50
    and b
    call Call_000_1554
    add c
    ld h, e
    dec b
    dec [hl]
    ld a, [hl]
    sbc a
    adc h
    jr jr_00c_7377

    adc d
    xor b
    xor l
    ld e, [hl]
    ld d, e
    sub d

Call_00c_730a:
    ld e, d
    sbc a
    pop bc
    adc [hl]
    xor a
    reti


jr_00c_7310:
    ld c, [hl]
    cp d
    and e
    rst $00
    call c, Call_00c_772a
    inc hl
    jr nz, jr_00c_72b6

    ld c, b
    and d
    add e
    ld de, $a661
    cp b
    ldh [$cd], a
    jr jr_00c_736f

    add $aa

Call_00c_7327:
    add hl, bc
    inc l
    ld h, d
    ret


    or h
    ld l, d
    ret nz

    rst $00
    inc d
    and h
    xor l
    or b
    and a
    ld a, [bc]
    or a
    ld d, e
    ld b, b
    cp h
    ld l, c
    and h
    ld hl, $afaf
    jp nc, $ea6a

    jp z, Jump_00c_5485

    dec bc
    and [hl]
    or a
    ld c, $a5

jr_00c_7349:
    cp a
    add a
    and a
    inc h
    cpl
    db $db
    ld hl, $b41c
    ld de, $df29
    xor l
    rra
    ld a, [bc]
    ld [hl], a
    or d
    ld d, h
    push af
    ld l, d
    ld h, c
    ld d, h
    ld d, l
    jr c, jr_00c_73b7

    ld a, [hl-]
    db $db
    and b
    xor d
    add hl, bc
    ld d, e
    ld d, a
    cp l
    add hl, sp
    dec l

jr_00c_736c:
    ld d, d
    or d
    ld a, [hl]

jr_00c_736f:
    and e
    ld e, a
    dec d
    add hl, sp
    ld h, b
    xor c
    adc b
    and c

jr_00c_7377:
    ld l, a
    ld c, h
    rla
    ld [c], a
    inc d
    and $be
    sub b
    ei
    sub [hl]
    ei
    ld c, b
    ld a, d
    add hl, hl
    ld c, e
    ld a, l
    dec de
    call nc, $dcc9
    jr nz, jr_00c_7310

    sbc b
    inc d
    call $d1e2
    and c
    ld d, b
    xor a
    ld c, d
    ld e, a
    push bc
    ld [$898f], sp
    ld d, e
    dec h
    ld h, $8a
    or h
    adc e
    sub $96
    inc d
    ld de, $c25c
    jp nc, $aa50

    ld a, [bc]
    add c
    ld c, d
    or h
    sbc c
    ld [$08a9], sp
    cpl
    ld d, d
    call nc, $fa51

jr_00c_73b7:
    dec c
    add d
    ld d, e
    dec bc
    ld b, l
    jp c, Jump_00c_42a9

    ld h, a
    ld a, [hl]
    ld d, a
    pop hl
    add c
    xor a
    ld [$8d11], sp
    ld a, [hl+]
    adc h
    and c
    ld h, a
    jp hl


    ld e, [hl]
    cp $2d
    and d
    ld d, e
    ld c, b
    sub $6a
    and c
    ld d, l
    ldh [$78], a
    db $10
    ld h, b
    xor b
    dec h
    ld a, [hl-]
    ld e, e

jr_00c_73df:
    cp a
    rra
    ret z

    pop bc
    ld h, b
    ld c, e
    cp [hl]
    inc [hl]
    ld d, e
    inc [hl]
    jr nz, jr_00c_736c

    cp l
    ld d, l
    ld d, h
    adc b
    and $53
    dec h
    inc b
    ld e, b
    ld l, d
    and l
    dec bc
    jr jr_00c_73df

    ld d, d
    sbc d
    and l
    add c
    add l
    ld c, c
    xor [hl]
    ld b, d
    ld h, h
    ret


    ld [hl-], a
    and d
    ld d, $17
    ld d, c
    ld c, b
    add [hl]
    ld hl, $4691
    dec b
    xor c
    dec de
    db $f4
    sub a
    add l
    jp c, $0b07

jr_00c_7416:
    inc b
    adc b
    add h
    dec d
    add d
    jp nc, $a030

    xor e
    ld d, [hl]
    adc b
    ld d, c
    ld a, b
    sub l
    inc c
    jp nz, $8969

    ld a, b
    and h
    db $10
    ld h, h
    pop bc
    ldh [$78], a
    add $22
    cpl
    jp z, $9452

    ld [hl-], a
    ld [hl], b
    ld h, d
    inc d
    ld e, $32
    adc e
    ld h, a
    and a
    sub e
    ld a, [de]
    ld [hl+], a
    xor e
    add [hl]
    and b
    ld a, b
    ret


    ld b, d
    ld hl, $a588
    ld [hl], b
    add d
    adc c
    ld d, e
    inc d
    ld a, [hl]
    and e
    ld a, [hl-]
    xor [hl]
    ld a, [de]
    xor c
    dec c
    xor b
    jr nz, jr_00c_7416

    ld b, d
    db $d3
    ld a, [bc]
    ld [hl], $57
    and d
    db $10
    and b
    ld e, d
    sub [hl]
    ld h, d
    ld l, d
    dec b

Call_00c_7466:
    add hl, sp
    ld e, [hl]
    add d
    inc b
    adc b
    sbc e
    push af
    and e
    dec c
    db $e3
    xor d
    ld a, [bc]
    or $bd
    adc a
    ld hl, $8f69
    ld l, $64
    add d
    ld a, d
    or b
    ld e, h
    add hl, hl
    add hl, hl
    add $82
    ld [hl], e
    and e
    ld h, h
    jp hl


    ld de, $ac09
    inc de
    sbc h
    db $ed
    dec bc
    sub b
    db $ec
    ld [hl], c
    sbc $73
    xor d
    rla
    add h
    inc d
    ld [$8209], a
    db $10
    ld h, e
    pop de
    rst $08
    ld [de], a
    sbc b
    sbc $a4
    ld [hl+], a
    or b
    dec a
    ld d, $c5
    ret nz

    sbc c
    ld [hl+], a
    pop hl
    sub b
    add e
    push bc
    db $e4
    ld a, c
    adc d
    and h
    push bc
    ld b, [hl]
    cpl
    adc $0f
    pop bc
    dec d
    inc b

jr_00c_74b9:
    ld a, $4a
    ld d, e
    sbc e
    ld b, b
    rst $18
    db $d3
    ei
    inc c
    ld h, h
    adc a
    and c
    ld b, $84
    pop af
    and d

jr_00c_74c9:
    cp $ea
    xor l
    sub $0a
    ld h, h
    cp a
    add e
    or [hl]
    cp d
    ld l, e
    ld a, a
    rst $38
    rst $38
    ld [$d213], a
    ld b, [hl]
    rst $38
    ld c, h
    ret c

    ld a, a
    ld sp, hl
    xor e
    rst $38
    pop hl
    rlca
    ld a, [$ad35]
    ld d, h
    jr nc, jr_00c_74b9

    ld h, c
    rst $10
    add $d7
    ld a, [$3f10]
    rst $38
    rst $38
    db $fd
    inc h
    inc sp
    push bc
    and a
    rrca
    cp $ef
    db $fc
    dec hl
    rst $38
    cp $08
    ld l, a
    jr jr_00c_74c9

    call $ffdf
    ld a, [$df47]
    xor d
    or [hl]
    rst $00
    ld b, d
    inc l
    rst $38
    rst $38
    ret nz

    ldh a, [rNR41]
    and b
    rst $10
    xor c
    call nc, $f5cc
    rst $38
    db $fc
    ld c, $fe
    dec c
    scf
    ld [$4472], a
    dec a
    cp a
    rst $38
    ldh a, [$7f]
    ld hl, sp+$7c
    db $10
    ld b, c
    ld l, b
    add sp, -$57
    sub d
    ld b, e
    inc b
    ld b, d
    rst $10
    ldh a, [$5f]
    db $fc
    ld sp, $f828
    ld e, b
    db $eb
    xor c
    adc e
    rla
    ld e, a
    cp [hl]
    inc sp
    pop de
    ld l, b

jr_00c_7543:
    jr nc, jr_00c_7581

    rst $38
    ld e, a
    ld sp, hl
    ld [$93b1], sp
    cp $18
    jp z, $8360

    inc bc
    ret nc

    push af
    ccf
    jp nz, $6a8c

    cp $c4
    ld b, c
    ld l, d
    ld b, d
    jr @-$18

    ld [hl], a
    sub d
    sbc d
    inc h
    inc [hl]
    ld h, d
    call nc, $1342
    ld h, [hl]
    ld d, l
    inc e
    dec d
    add e
    ldh [$82], a
    db $dd
    dec hl
    db $e4
    ld b, b
    add a
    and a
    ld b, d
    ld a, [bc]
    ld b, h
    ld [$935c], sp
    pop de
    adc e
    pop de
    jp z, $c290

    xor h

jr_00c_7581:
    ld a, [hl+]
    ld b, h
    ld l, c
    ld b, a
    ld e, e
    and e
    inc de
    ld e, $5c
    pop de
    and $80
    ld b, h

Jump_00c_758e:
    sbc e
    ld c, l
    rra
    jp nc, $d6d2

    db $d3
    ld a, [de]
    ld [hl+], a
    push af
    ld a, b
    jp nz, $d282

    sub h
    jp nz, Jump_00c_4c82

    ld l, l
    dec bc
    rst $18
    ld [hl-], a
    ld h, c
    ld c, h
    xor $78
    ld d, l
    dec h
    adc b
    ld c, l
    sub e
    add hl, de
    jr nc, jr_00c_7543

    sbc l
    dec sp
    db $10
    ld h, e
    sbc [hl]
    adc b
    ld b, d

jr_00c_75b7:
    dec hl
    ld c, [hl]
    rlca
    add c
    ld h, e
    rra
    ld [hl], $79
    ld h, b
    ld d, h
    cp a
    adc c
    adc e
    ld a, [hl]
    sub [hl]
    adc b
    ld d, d
    inc e
    sub l
    ld c, e
    db $76
    adc h
    ld e, c
    cp c
    and [hl]
    ld h, e
    sub [hl]
    ld d, [hl]
    ld h, $63
    ret nz

    adc a
    rla

jr_00c_75d8:
    ld [hl], c
    ld a, [hl+]
    ld l, a
    sbc e
    ld c, l
    add d
    sub b
    and [hl]
    ld a, [hl+]
    ld h, d
    db $d3
    cp $14
    add $55

jr_00c_75e7:
    inc hl
    add [hl]
    inc d
    rra
    call nz, Call_00c_6630
    ld [hl], l
    cp b
    xor b
    ld e, h
    ld b, e
    inc bc
    dec de
    and b
    ld hl, sp-$39
    ld d, d
    ld de, $70ac
    inc h

Call_00c_75fd:
    xor h

Jump_00c_75fe:
    ld d, d
    ld b, h
    ld l, l
    add $d2
    ld sp, $a1b3
    sbc d
    ld c, c
    and d
    jp z, Jump_00c_6814

    add $08
    dec sp
    ld b, l
    ld h, [hl]
    dec c
    and [hl]
    jr nc, jr_00c_765b

    ld [hl], d
    ld b, e
    inc c
    ret


jr_00c_7619:
    call Call_00c_7251
    ld a, h
    jr z, jr_00c_7685

    or c
    and h
    ldh a, [$1f]
    ld c, l
    jr nz, jr_00c_75b7

    ld a, b
    add sp, -$60
    or e
    dec d
    ld b, $1a

jr_00c_762d:
    sub d
    dec d
    ld a, a
    rst $38
    ld d, h
    rst $00
    xor a
    dec h
    ld [c], a
    ld e, l
    inc d
    rra
    xor d
    jr nc, jr_00c_75e7

    call nc, Call_000_25a5
    ld sp, hl
    ld a, [hl+]
    sub $8e
    ld c, d
    sbc b
    ld [de], a
    sub [hl]
    ld a, [bc]
    inc b
    inc sp
    or [hl]
    ld c, l
    jr z, jr_00c_75d8

    ld [$53a5], sp
    sub c
    jr jr_00c_7677

    dec h
    add [hl]
    ld d, [hl]
    ld h, $a5
    jr c, jr_00c_762d

jr_00c_765b:
    db $e4
    and $94
    pop de
    ld hl, $47f5
    adc b
    ld d, e
    ld h, l
    ld d, b
    and l
    dec l
    dec h
    ld a, [bc]
    inc b
    ld hl, $4241
    sub h
    pop bc
    adc c
    and h
    ld l, d
    xor b
    xor c
    inc [hl]
    and d

jr_00c_7677:
    ld h, d
    and l
    xor d
    ld d, c
    db $e4
    adc $f1
    and d
    dec d
    ld a, [c]
    ld h, d
    ld d, e
    jr jr_00c_7619

jr_00c_7685:
    rst $00
    ld l, $89
    and d
    db $e3
    ld [hl], a
    db $d3
    ld a, [bc]
    sub d
    xor l
    ld a, [bc]
    dec b
    ld d, h
    ld h, e
    ld c, d
    ret nc

    and e
    adc d
    or $aa
    cp d
    inc sp
    ld [hl], l
    ld h, h
    ld [hl+], a
    add sp, -$3f
    ld d, l
    rst $38
    db $fd
    ld [hl-], a
    ld d, h
    jr z, jr_00c_76c7

    ld b, c
    ld hl, $bf58
    xor d
    add l
    ld d, l
    bit 4, c
    ld d, d
    ld h, b
    ld c, b
    ld b, c
    ld a, h
    cp e
    ld d, a
    ld a, [$4aaa]
    jp nc, $9814

    ld l, d
    ld a, [de]
    dec h
    ld a, a
    xor b
    and l
    ld l, b
    ld d, $e6
    ld b, l

jr_00c_76c7:
    ld c, d
    ld c, h
    rst $38
    ld d, l
    ld d, [hl]
    xor b
    ld d, [hl]
    add c
    sbc c
    dec de
    ld b, c
    ld [hl+], a
    dec [hl]
    xor d
    xor d
    xor l
    ld l, b
    ld d, [hl]
    ld h, b
    ld c, b
    add d
    xor l
    add hl, sp
    sbc $21
    and c
    add l
    ld d, $2e
    di
    sub d
    push de
    ld [hl], l
    and l
    ld d, l
    adc l
    cpl
    adc e
    ret c

    jp hl


    add sp, $49
    ld a, c
    ld [c], a
    and c
    adc d
    ld b, e
    db $10
    and e
    ld c, d
    ret nc

jr_00c_76fa:
    and [hl]
    add hl, hl
    sub h
    cp d
    dec bc
    ld a, [bc]

jr_00c_7700:
    xor h
    ld [hl], $d5
    ld d, a
    xor h
    add hl, bc
    ld c, c
    ld c, e
    dec a
    jp $f920


    ld d, c
    and l
    ld h, b
    add a
    inc c
    ld b, e
    add d
    add h
    and l
    ld b, e
    ld [de], a
    sbc e
    and c
    add hl, hl
    ld [hl], b
    jr nz, jr_00c_7700

    dec c
    db $10
    push hl
    ld c, c
    xor d
    ld b, d
    add h
    ld h, h
    and c
    and c
    ld a, a
    ld h, $14

Call_00c_772a:
    xor c
    ld c, h
    ld e, d
    ld e, h
    db $10
    ld b, b
    pop bc
    ld a, [hl+]
    add $d5
    ld d, c
    add h
    ld d, [hl]
    add d
    ld b, e
    ld d, b
    ld h, $6d
    ld e, d
    sbc h

jr_00c_773e:
    sbc h
    ld b, d
    ld [$c9c0], sp
    adc d
    pop bc
    ld e, h
    and [hl]
    xor c
    ld de, $6134
    sub a
    jr jr_00c_76fa

    sub [hl]
    sub c
    ld de, $e672
    ld [hl], $11
    adc d
    ld d, $85
    ld l, b
    xor b
    ld b, [hl]
    ld [de], a
    ld b, d
    ld h, e
    ld h, [hl]
    ld d, h
    ldh a, [$60]
    add l
    inc c
    db $10
    ld h, l
    ld b, h
    ld e, b
    inc h
    inc hl
    dec h
    ld l, b
    jr z, jr_00c_77c7

    inc d
    ld b, h
    ld l, l
    adc e
    inc c
    ld a, [bc]
    pop de
    ld a, a
    ldh [$e9], a
    ld de, $4608
    add hl, hl
    ld a, $35
    ld c, $11
    ld a, [bc]
    add hl, bc
    db $10
    ld c, c
    ld [$8640], sp
    ld h, c
    db $10
    db $eb
    ld a, [hl]
    cp a
    db $ed
    ld de, $2095
    sbc h
    jr z, @+$2f

    ld b, b
    xor e
    ld d, e
    ld a, [$0846]
    ld a, $ff
    jr jr_00c_773e

    adc h
    dec bc
    ld d, h
    ld b, d
    db $fd
    ld c, e
    rst $08
    ld e, a
    pop hl
    ld [hl], h
    ld h, e
    sub l
    xor d
    xor e
    ret c

    ld h, d
    ret z

    pop bc
    inc [hl]
    db $10
    or h
    ld h, l
    ld a, [de]
    ld h, c
    inc l
    inc c
    call nz, Call_000_1d63
    sbc b
    xor h
    dec bc
    ld a, [bc]
    dec l
    jr jr_00c_7828

    ld b, a
    add l
    dec h
    ld [hl-], a
    ld l, l
    sbc b

jr_00c_77c7:
    add b
    ld b, h
    cp l
    dec d
    ld c, [hl]
    or a
    or $3a
    ld e, [hl]
    dec b
    ei
    add hl, sp
    xor b
    ld d, h
    ld e, $2d
    adc l
    xor b
    xor b
    ld a, [hl+]
    sub l
    adc l
    pop de
    ld b, d
    sub e
    and c
    ld e, e
    add c
    inc a
    and l
    and e
    ld c, d
    ld [hl-], a
    ld d, l
    ld [$b2e1], sp
    ld d, l
    adc c
    adc [hl]
    ld c, c
    ld b, d
    ld h, h
    db $10
    ld d, l
    ld c, [hl]
    ld c, d
    inc c
    ld a, $aa

jr_00c_77f9:
    cp h
    push hl
    ld h, b
    sub e
    xor [hl]
    dec a
    dec e
    ld hl, sp+$5f
    and b
    sbc d
    and [hl]
    db $d3
    ld [hl], l
    add d
    xor d
    ld b, e
    dec de
    ld sp, $c50d
    ld d, h
    ld l, [hl]
    ld a, [c]
    db $76
    push hl
    ldh a, [$aa]
    sbc h
    ld d, [hl]
    ld [de], a
    jr z, jr_00c_784c

    xor h
    ld [hl], c
    ld d, e
    ld h, e
    dec a
    inc c
    ld [hl], d
    or h
    ld [hl-], a
    ld [$a72a], sp
    inc h
    inc a

jr_00c_7828:
    inc c
    ld d, l
    inc e
    adc c
    ldh [rBGP], a
    and d
    ld [hl], a
    or d
    and h
    push af
    ldh [$91], a
    ld a, b
    and l
    xor d
    ld d, h
    ld [c], a

Call_00c_783a:
    ld d, l
    ld [hl-], a
    ld d, b
    ld h, c
    xor c
    dec h
    adc b
    ld d, l
    ld e, d
    ld d, e
    ld b, a
    xor l
    dec l
    ld [c], a
    ld e, l
    inc d
    sub h
    ld e, e

jr_00c_784c:
    ld d, l
    ld a, [de]
    ld e, d
    ld c, l
    jr z, jr_00c_77f9

    db $e4
    add h
    dec e
    ld d, c
    sub c
    ret c

    dec d
    ld a, c
    ld b, [hl]
    ld b, d
    ld c, h
    jr c, jr_00c_789d

    dec d
    add d
    adc b
    adc e
    sbc d
    ld d, l
    and d
    xor c
    ld [$4a22], a
    jp nz, $2a0a

    add [hl]
    sub e
    xor d
    ld b, e
    ld d, c
    adc c
    pop bc
    ld c, l
    inc de
    dec d
    xor d
    ld d, e
    ld h, h
    db $10
    add [hl]
    dec bc
    ld [hl], b
    ld e, [hl]
    ld l, $1a
    add hl, bc
    ld l, b
    add $4d
    ld de, $1842
    jr z, jr_00c_78aa

    ld a, b
    ld a, [hl+]
    ld hl, $1339
    ld b, $d4
    and [hl]
    ld c, $74
    and l
    ld a, [bc]
    inc b
    pop de
    ld e, d
    xor e
    call nc, $227a

jr_00c_789d:
    ld h, h
    ld d, b
    jp Jump_00c_4857


    ld d, b
    or [hl]
    ld b, c
    ld l, $29
    ld d, l
    sbc e
    sub h

jr_00c_78aa:
    xor b
    add hl, hl
    ld h, [hl]
    add c
    jp nc, $6d54

    cp l
    ld b, [hl]
    ld hl, $a7a2
    ld sp, hl
    and h
    adc d
    adc b
    ld d, l
    ld sp, $2da2
    or h
    sub [hl]
    inc [hl]
    add c
    ld a, [bc]
    ld h, h
    ld l, c
    push af
    call z, Call_000_22ed
    call nc, Call_00c_51e5
    sbc c
    sbc h
    ld e, b
    ld h, e
    ld c, l
    ld hl, $4e60
    ld c, c
    ld b, d
    ld c, b
    ld b, d
    adc $05
    ld hl, $4e50
    ld d, $96
    ld e, e
    inc hl
    add c
    inc a
    add h
    sbc c
    ld h, [hl]

jr_00c_78e6:
    ld b, [hl]
    dec [hl]
    and c
    ld h, d
    db $d3
    ld a, c
    ld h, h
    xor c
    ldh [$9b], a
    ld c, h
    ld d, h
    adc b
    adc d
    ld d, b
    adc [hl]
    add hl, de
    sub d
    jp hl


    rrca
    adc e
    ld a, b
    rla
    add l
    ld d, l

Call_00c_78ff:
    jr jr_00c_7914

    inc h
    xor c
    sub e
    ld a, [bc]
    jr nc, jr_00c_78e6

    jp hl


    push hl
    push hl
    dec d
    add hl, bc
    jr nc, @-$6c

    and $4b
    and e
    ld e, l
    ld hl, sp+$54

jr_00c_7914:
    ld d, h
    sbc c
    ld a, [hl+]
    ld h, h
    cp c
    sub d
    xor b
    pop hl
    ld l, l
    ld hl, sp-$3e
    sub a
    ld b, d
    ld a, c
    ld a, [hl+]
    ld [hl], h
    sbc d
    jr c, jr_00c_7951

    adc l
    db $eb
    sub $7d
    ld a, [hl+]
    jp nc, $f114

    ld l, e
    sub $d4
    sbc e
    ld c, a
    ld [hl-], a
    cp a
    push hl
    ld hl, $3e4f
    and l
    push af
    ei
    ld h, l
    and a
    or c
    dec h
    push hl
    ld hl, $292c
    sbc $86
    add hl, hl
    inc c
    ld c, d
    add h
    ld c, l
    inc bc
    ld [bc], a
    ld [hl], h
    res 4, b

jr_00c_7951:
    or d
    add hl, bc
    ld l, $6b
    inc bc
    inc e
    adc e
    dec a
    jp $cafc


    db $10
    xor a
    cp $09
    ld [hl], d
    ld h, d
    push hl
    or b
    jr z, jr_00c_798f

    dec c
    ld c, [hl]
    ld d, $15
    add l
    ld d, l
    ld l, [hl]
    ld a, [bc]
    and c
    ld h, $f4
    xor [hl]

jr_00c_7972:
    rla
    ld a, [bc]
    ld c, h
    xor d
    ld l, c
    ld d, e
    call c, $0ac6
    ld l, c
    cp c
    ld [de], a
    add h
    ld c, h
    and [hl]
    ld [hl], b
    ld e, b
    ld hl, $4144
    ld d, c
    jr z, jr_00c_79ce

    ld [hl], b
    ld c, e
    ld c, c
    adc h
    sbc b
    and h

jr_00c_798f:
    ld b, b
    call nc, $c508
    ret nc

    and c
    dec b
    jp z, Jump_00c_6ab1

    xor d
    ld d, e
    dec [hl]
    add hl, hl
    inc d
    ld a, [hl+]
    sub a
    and e

jr_00c_79a1:
    add h
    inc c
    sub [hl]
    or h
    push de
    ld l, c
    inc l
    ld c, l
    and h

jr_00c_79aa:
    ld sp, $8609
    add e
    or a
    cp d
    ld b, h
    inc l
    ld h, c
    jr nz, jr_00c_79aa

    ld a, [hl+]
    call c, Call_00c_4645
    ld e, l
    cp $db
    db $ed
    ld d, c
    and l
    pop bc
    and l
    push hl
    add hl, sp
    sbc e
    rst $38
    db $db
    inc e
    ld a, b
    pop bc
    and l
    or b
    pop de
    sub l
    ld e, a

jr_00c_79ce:
    db $ed
    daa
    ld e, $a3
    ld l, b
    ld d, h
    ld d, h
    ld l, b
    db $f4
    rla
    jr nz, jr_00c_7972

    ld l, c
    sub l
    add d
    ld d, $4a
    ld [hl], b
    cp d
    ld b, l
    ld b, b
    sbc b
    ld b, c
    add d
    ld b, e
    ld de, $db60
    db $10
    sbc d
    cp a
    inc de
    ld [hl+], a
    sbc c
    rst $10
    xor c
    db $76
    ret z

    ld d, c
    xor a
    dec b
    ld h, h
    inc hl
    jr z, jr_00c_79a1

    ld [de], a
    ld [hl], $97
    add [hl]
    ld [hl], c
    ret nc

    call z, Call_000_0a0a
    ld d, $96
    sub e
    ld l, c
    ld a, $c9
    or d
    inc d
    ld [$2124], sp
    inc c
    add h
    jr jr_00c_7a3f

    ld h, c
    ld l, b
    rst $38
    or [hl]
    ld h, c
    ld [c], a
    add h
    ld [hl], $18
    ld [hl+], a
    cp b
    ret


    inc de
    jp hl


    add l

jr_00c_7a22:
    rst $18
    db $fd
    ld h, [hl]
    cp [hl]
    ld e, h
    dec bc
    sub l
    ld [bc], a
    ld c, l
    and h
    cp e
    scf
    dec c
    ld h, a
    ld a, [bc]
    sub b
    sbc b
    ret nz

    jp nc, Jump_00c_6f30

    cp $e9
    dec [hl]
    sbc h
    inc d
    ld [hl], b

jr_00c_7a3d:
    ret nz

    ret nz

jr_00c_7a3f:
    ld hl, sp-$3f
    dec c
    and h
    ld a, [hl+]
    ld a, b
    or b
    ld hl, $9390
    ld l, c
    ld de, $c1e4
    add [hl]

Jump_00c_7a4e:
    ld b, d
    ld a, [hl+]
    ld [de], a

Jump_00c_7a51:
    ld a, c
    or b
    or $0d
    inc b
    ld b, h
    or [hl]
    ld d, l
    dec h
    ld a, a
    and e
    ld b, l
    rst $38
    rst $38
    rst $38
    and l
    ld c, l
    ld e, $81

Jump_00c_7a64:
    ld a, [$5fa5]
    call Call_00c_5e68
    rlca
    cp $a8
    inc hl
    ld e, e
    rlca
    pop bc
    and b
    ld d, a
    cp $a3
    inc [hl]
    inc a
    ld l, $77
    xor b
    ld a, [de]
    ld hl, $b235
    cpl
    sub $8c
    inc h
    db $e3
    adc h
    ld h, d
    ld h, e
    or e
    ld d, e
    inc d
    ret


    xor d
    ld d, d
    jr nz, jr_00c_7a3d

    jr nc, jr_00c_7a22

    jr c, jr_00c_7ac5

    ld a, [bc]
    sub h
    jp c, $c196

    ld d, l
    ld a, a
    db $eb
    call nc, $b1d6
    ld [hl], b
    and e
    ld a, [de]
    dec [hl]
    ld h, l
    add d
    adc [hl]
    xor b
    push af
    rst $20
    dec sp
    xor d
    ld [hl], c
    and d
    jp $d305


    sbc c
    or c
    ld sp, $a028
    rst $08
    and $36
    ret z

    inc hl
    adc h
    ld e, a
    cp $61
    db $fc
    ld hl, sp+$32
    inc a
    ld c, a
    rst $38
    sub [hl]
    add a
    cp h

jr_00c_7ac5:
    db $f4
    jp hl


jr_00c_7ac7:
    ld c, $17
    cp $61
    di
    inc sp
    rst $38
    inc bc
    ld sp, hl
    rra
    and $1e
    jr jr_00c_7ac7

    xor a
    rst $38
    db $e4
    ld a, [hl]
    ld h, c
    ld l, l
    adc l
    call nz, $fe5f
    add e
    push hl
    db $d3
    ld h, [hl]
    ld d, b
    ld a, a
    jp $9669


    ld d, h
    ld e, d
    sub b
    sub c
    ld a, [de]
    ld b, b
    adc h
    ld c, a
    inc c
    ld b, h
    add hl, bc
    xor h
    ldh a, [$c7]
    ld d, l
    rra
    ld l, $66
    or a
    or l
    inc a
    ld hl, sp+$25
    dec l
    ld sp, hl
    inc [hl]
    ld d, h
    ldh [rHDMA1], a
    sub b
    ld h, h
    ld e, e
    ld h, $48
    ld d, a
    ei
    add hl, sp
    rst $28
    dec bc
    sub b
    ld c, d
    cp [hl]
    and d
    db $10
    ld c, h
    sub l
    ld d, h
    dec d
    ld [hl+], a
    pop bc
    add hl, hl
    dec b
    and d
    call c, $f8c5
    jp nz, $ff9a

    ld d, l
    rst $38
    ret nc

    ld a, a
    sbc a
    add d
    dec l
    ld b, d
    sub h
    sub h
    ld l, a
    db $eb
    rst $38
    rst $38
    ld hl, sp+$50
    db $fc
    inc de
    dec de
    ld b, l
    or $0d
    cp $07
    rst $38
    ld b, [hl]
    db $f4
    jr nz, jr_00c_7bbc

    inc de
    ld c, d
    ld e, d
    ld a, [bc]
    xor d
    ld b, $2e
    pop de
    xor d
    dec bc
    adc h
    rst $10
    jp hl


    ld a, l
    ld [hl-], a
    and e
    ld d, h
    ld sp, $9e92
    adc b
    xor b
    jp nz, $8a26

    ld c, h
    add hl, hl
    ld b, [hl]
    ld b, [hl]
    adc e
    ld l, c
    ld d, d
    ld h, l
    add hl, sp
    inc d
    sbc b
    dec l
    ld c, d
    and h
    add l
    or b
    or h
    call $a321
    ld a, [hl-]
    push af
    ld h, $66
    reti


    inc sp
    ld h, a
    sub c
    jp nc, $c258

    ld sp, hl
    ld b, a
    ld b, [hl]
    db $db
    ld d, l
    ld d, [hl]
    ld a, b
    ld d, c
    pop af
    ld h, e
    dec h
    add hl, bc
    ld l, d
    ld hl, $ff6f
    rst $38
    sub l
    add hl, de
    dec bc
    ld d, e
    dec h
    dec h
    dec d
    ld h, b
    ld h, l
    ld c, c
    ld d, [hl]
    ld d, [hl]
    ld d, h
    ld a, a
    adc h
    inc d
    add [hl]
    dec l
    add d
    ld d, e
    ld b, $22
    sub l
    xor a
    ld h, d
    sub h
    ld e, b
    jp nz, $082b

    ld h, c
    sub l
    ld [hl-], a
    cp [hl]
    add hl, hl
    ld h, d
    dec d
    ld d, d
    rst $18
    ld a, [bc]

jr_00c_7bb1:
    ld d, $46
    and l
    ld c, d
    sbc b
    adc d
    xor d
    adc d
    and d
    ld a, a
    dec b

jr_00c_7bbc:
    ld [$abc1], sp
    push af
    ld d, e
    sbc e
    and $1b
    ld b, [hl]
    inc sp
    xor d
    adc [hl]
    ld a, [de]
    ld b, $62
    db $ed
    inc b
    inc hl
    cp d
    ret c

    adc $f8
    jp c, $9e6f

    sub l
    and [hl]
    ld l, d
    ld l, d
    sbc h
    ld c, c
    rra
    jp hl


    ld c, a
    ld a, [$304a]
    cp c
    jp $ff13


    sub b
    add a
    rst $38
    jr jr_00c_7c29

    ld b, [hl]
    ld c, c
    sbc l
    call nc, $8546
    jr jr_00c_7bb1

    jp hl


    add [hl]
    cp a
    cp $32
    ld a, [hl+]
    push de
    ld d, l
    db $e4
    jp z, $e61f

    ld [hl], a
    rst $38
    db $e4
    jp nz, $aa82

    and l
    cp h
    rst $38
    ld b, [hl]
    sub a
    ret nc

    call nz, $a430
    reti


    ld d, [hl]
    ccf
    pop de
    res 0, [hl]
    add e
    jr jr_00c_7c63

    ld b, c
    pop hl
    pop af
    sbc d
    ld de, $5e51
    ld e, d
    sub c
    sub l
    adc h
    ld [hl], c
    ld a, [hl+]
    and h
    ld e, c
    ld e, a
    db $e3
    sub l
    sub l

jr_00c_7c29:
    ld c, c
    ld a, [hl+]
    xor a
    db $eb
    ret nc

    inc hl
    ld [bc], a
    ld c, l
    dec bc
    sub l
    rst $38
    ld b, e
    db $e4
    rst $30
    rst $38
    cp $0c
    ld d, h
    xor d
    or b
    call nc, Call_000_021f
    inc sp
    dec h
    pop bc
    rst $18
    cp $98
    ld h, l
    ld h, l
    inc a
    ld e, $91
    add hl, de
    and b
    rst $10
    add $d1
    ld d, [hl]
    add a
    jp hl


    xor d
    rrca
    jp hl


    rrca
    ld c, l
    ld [de], a
    cp [hl]
    sub e
    ld l, l
    jp hl


    sbc d
    rrca
    cp $85
    inc bc
    or c

jr_00c_7c63:
    cpl
    ld d, e
    ld a, [$7f30]
    add $08
    ccf
    rst $38
    and b
    ldh a, [$f9]
    ld e, $1f
    db $e4
    ld d, l
    ld e, a
    pop af
    ld c, e
    rst $38
    rst $38
    pop hl
    sub e
    ld a, [$2d1c]
    ld a, d
    sub l
    ld a, a
    dec d
    ld d, l
    ld h, l
    add hl, sp
    rra
    ld a, [$fe2f]
    or l
    ld l, d
    add l
    pop af
    set 7, a
    dec c
    rst $38
    db $fd
    ld de, $310e
    call nz, $f18f
    ld [hl], a
    cp $9d
    set 0, [hl]
    ld [hl], a
    and a
    cp h
    ld b, h
    cp b
    sbc a
    xor d
    ld d, l
    add hl, sp
    xor l
    xor d
    ld d, e
    xor d
    jp nc, $e968

    ld a, l
    ld a, [hl-]
    ld d, a
    add sp, $2d
    add hl, sp
    ld e, [hl]
    adc e
    ld d, e
    sub [hl]
    call nc, $3aa5
    dec hl
    push de
    ld c, [hl]
    db $db
    ld c, [hl]
    push hl
    add hl, hl
    ld a, [hl-]
    inc d
    sub [hl]
    ld a, [hl-]
    inc d
    add [hl]
    ld a, [hl-]
    ld d, h
    ld e, b
    db $ec
    ld e, b
    dec d
    xor b
    and $aa
    adc a
    cpl
    ld [hl], c
    jp z, $d7a9

    ld c, c
    dec d
    ld b, a
    ld d, h
    sbc l
    ret z

    ret


    ret nc

    add [hl]
    ld de, $7232
    cp d
    xor d
    xor b
    daa
    inc l
    add hl, bc
    ld [hl], d
    ld [hl], e
    ret nz

    ret nz

    add h
    sbc l
    sub e
    daa
    ld l, e
    daa
    ld l, e
    daa
    ld l, e
    daa
    ld l, e
    push bc
    ld a, [hl+]
    ld [hl], e
    ld c, d
    or l
    rra
    db $10
    ld d, l
    cp [hl]
    ld bc, $744b
    and $54
    rra
    cp d
    ld hl, $cec3
    ld e, d
    xor [hl]
    ld a, a
    add hl, de
    sub b
    cp h
    push hl
    ld d, h
    adc e
    ld d, c
    ret nc

    ld e, d
    adc [hl]
    ld b, l
    db $d3
    ld [$0c99], sp
    db $e3
    ld h, d
    sbc b
    add h
    jp nz, $9e38

    jp z, $8866

    ld c, e
    ld [hl], h
    ldh [$e4], a
    dec e
    ld h, b
    sub h
    ld [hl], l
    ld a, [hl]
    db $fc
    sub $a1
    and c
    adc b
    sub h
    ld l, b
    dec h
    dec d
    inc [hl]
    ld d, [hl]
    dec d
    dec b
    ld [hl-], a
    sub b
    ld h, h
    inc a
    rst $10
    adc b
    sbc b
    jp c, Jump_00c_4da1

    inc d
    add [hl]
    ld [c], a
    inc de
    ld b, h
    ld e, l
    ld sp, $6879
    dec d
    ld l, b
    inc hl
    ld a, $81
    ld c, h
    ld l, [hl]
    rst $38
    call z, $3413
    adc d
    inc sp
    xor d
    sbc d
    ld d, [hl]
    adc b
    ld h, c
    ld d, d
    jr nz, jr_00c_7ddb

    pop hl
    sub c
    ld d, l
    ld h, [hl]
    ld h, c
    sub l
    db $e3
    sub [hl]
    cp a
    db $fd
    adc a
    and c
    sbc a
    ld d, e
    push bc
    ld b, a
    ld a, h
    add hl, de
    ld c, $e7
    ld [hl], d
    cp b
    and c
    ld a, c
    jp nc, $ff8b

    adc [hl]
    ld [hl], h
    cp [hl]
    rra
    rlca
    cp $39
    add hl, de
    call nz, $a18c
    rst $28
    push de
    adc [hl]
    rrca
    sbc h
    adc l
    ld b, e
    ld [hl], b
    jr z, jr_00c_7df3

    call z, Call_00c_6f44
    inc b
    ld e, e
    ei
    ld b, $0f
    jp $c8a6


    pop bc
    and b
    rst $30
    rst $38
    cp a
    ld e, e
    jp hl


    cp e
    rlca
    ld a, [$3fc1]
    cp $ff
    pop de
    ret nz

    rst $38
    ld d, e
    db $e3
    ldh a, [rIE]
    sbc h
    ld c, b
    ld c, d
    rst $38
    ld b, c
    and c
    ld l, e
    add a
    ld [hl+], a
    sbc d
    ld c, l
    ld d, [hl]
    xor d
    cp a
    ldh [$a1], a
    ld a, l
    ld a, d
    ld [hl], d
    dec [hl]
    rst $38
    scf
    sub c
    ld l, e
    rst $00
    dec l
    ld a, [hl+]
    inc de
    rst $00
    adc a
    rra
    ld b, h
    ld b, h
    cp c
    dec de
    rst $38
    ld c, [hl]
    db $76
    ld a, [de]
    xor e

jr_00c_7ddb:
    adc $05
    ld d, [hl]
    dec b
    ld d, l
    ld [hl+], a
    ld [hl], $77
    rst $38
    adc e
    sub e
    add d
    jp c, $aa50

jr_00c_7dea:
    sub l
    inc b
    pop hl
    and d
    ld a, [hl+]
    ld d, d
    ld h, e
    sub e
    ld c, e

jr_00c_7df3:
    and h
    ld h, e
    adc d
    and h
    add $39
    ld d, l
    ld c, h
    inc de
    sbc c
    ld l, l
    ld d, l
    adc [hl]
    adc e
    ld a, a
    ret z

    ld b, c
    add hl, sp
    ld e, $ab
    add $e3
    sub c
    ld e, l
    ld a, [c]
    ld e, b
    push hl
    and b
    or l
    inc d
    xor $a3
    ret z

    sbc h
    xor d
    adc d
    ld [hl], h
    or h
    xor e
    ld l, c
    ret nz

    sub h
    cp a
    rst $38
    or c
    cp h
    dec e
    ld d, d
    and h
    sbc $72
    ld a, [hl]
    xor l
    ld e, d
    rst $00
    ld e, $17
    rst $38
    db $eb
    ld h, a
    ld [de], a
    jp $ff7f


    and a
    dec h
    ld de, $fc57
    ld [hl], c
    pop bc
    add d
    ld d, a
    rst $00
    inc l
    inc de
    sub e
    dec bc
    sbc h
    push af
    ld b, b
    rst $38
    sbc l
    rrca
    ld a, [hl]
    inc e
    ld [hl], h
    ld b, h
    rst $20
    ld a, l
    ld b, a
    jp Jump_00c_4480


    cp c
    rla
    and l
    add hl, sp
    sbc $18
    sbc b
    call Call_000_0553
    ldh a, [$8b]
    adc h
    jr jr_00c_7dea

    and l
    daa
    ld h, e
    ld h, h
    jp nc, $cd23

    sub h
    jp c, $350e

    ld d, b
    ret nc

    ld c, h
    db $e3
    adc d
    db $fc
    jp nz, Jump_00c_5621

    rla
    ld c, c
    ld d, d
    inc l
    db $10
    db $fd
    rla
    rla
    db $eb
    bit 2, h
    add h
    ld a, [hl]
    dec b
    dec b
    ld [c], a
    xor b
    cp d
    ld hl, sp+$15
    cp [hl]
    ld [hl+], a
    call nc, $d194
    ld d, e
    dec [hl]
    xor a
    jp nz, $8d34

    db $ed

Jump_00c_7e94:
    and e
    and [hl]
    push af
    db $d3
    or [hl]
    and e
    ret z

    sbc $8b
    jr nc, jr_00c_7ef4

    ld b, a
    inc sp
    adc h
    ld de, $9331
    ld d, h
    sub b
    add h
    ld b, h
    sbc e
    and h
    call nz, $84d9
    xor c

jr_00c_7eaf:
    adc d
    ld d, d
    ld e, l
    inc bc
    push af
    ld d, l
    sub h
    sbc d
    xor e
    inc h
    cpl
    pop af
    or h
    ld b, d
    dec bc
    rst $38
    ret nz

    db $fc
    ld c, [hl]
    sub [hl]
    and c
    ld hl, sp+$23
    ld c, a
    sub $62
    and h
    jr nz, jr_00c_7eaf

    jr c, jr_00c_7f32

jr_00c_7ece:
    ld c, c
    ld de, $4593
    ld h, [hl]
    ld [hl], b
    and a
    ld e, a
    dec b
    dec e
    ld c, b
    reti


    reti


    ld a, [bc]
    add hl, de
    db $dd
    ld e, $50
    ld b, h
    cp c
    push de
    xor b
    add sp, $68
    db $e3
    ld e, l
    ld d, d
    jr jr_00c_7ece

    ld a, a
    push af
    ldh a, [$8e]
    daa
    and b
    db $ed
    push af
    add c

jr_00c_7ef4:
    inc b
    jp c, $e88a

    ld a, [hl]

jr_00c_7ef9:
    ld e, $cd
    jr z, jr_00c_7f51

    add l
    ld a, [$6a0a]
    sub h
    push de
    ld b, a
    call nc, $8c3a
    jr nz, @-$75

    and d
    ld l, [hl]
    db $fd
    add d
    and e
    ld a, [de]
    ld a, [hl+]
    call nc, $a58f
    ld a, [hl]
    jp nc, $a317

    ld a, [bc]
    db $fd
    ld sp, hl
    and d
    ld l, [hl]
    cp b
    jr z, jr_00c_7ef9

    ld [c], a
    rst $18
    sub h
    ld d, h
    and $f8
    sub [hl]
    adc [hl]
    add a
    push af
    db $d3
    xor d
    ld a, [de]
    adc a
    inc hl
    ld [hl], l
    ld a, [hl+]
    ld [hl], h
    xor l

jr_00c_7f32:
    ld b, a
    ld [de], a
    ld h, b
    rst $00
    ld a, [de]
    ret nc

    ld d, [hl]
    ld b, h
    ld [hl], c
    ld hl, $2318
    inc e
    ld d, b
    ld h, $3f
    ld b, d
    xor d
    ld a, [hl-]
    ld h, b
    adc d
    ld h, c
    ld b, c
    ld d, [hl]
    rst $30
    and b
    sub d
    adc d
    ld a, [bc]
    ld a, [hl+]
    xor b

jr_00c_7f51:
    call nz, $845e
    ld e, h
    adc l
    ld l, h
    inc d
    add d
    call nz, $31fe
    db $76
    sub e
    ld d, l
    ld c, b
    dec h
    ld e, e
    add $30
    ld h, e
    ccf
    add h
    ld l, c
    dec e
    ld a, [hl]
    ld [hl-], a
    ld a, e
    adc b
    ld h, a
    ld [hl], h
    ld a, c
    ld b, b
    ld hl, $d040
    ldh a, [$f3]
    and a
    jr z, jr_00c_7f7c

    ld hl, $d045

jr_00c_7f7c:
    bit 1, [hl]
    jr nz, jr_00c_7f90

    set 1, [hl]
    ld hl, $7fdb
    ld b, $0f
    call Call_000_3620
    ld hl, $7f98
    jp Jump_000_3c79


jr_00c_7f90:
    ld hl, $7f4e
    ld b, $0f
    jp Jump_000_3620


    db $ed
    add hl, hl
    ld l, l
    ld l, b
    cp h
    db $db
    or d
    ld a, a
    or a
    ret c

    add $7f
    jp nz, $cfc2

    jp c, $e7c0

    ld e, b
    ld hl, $d0b4
    xor a
    ld [hl+], a
    ld [hl], a
    dec a
    ld [$d03b], a
    ld hl, $d011
    ld de, $cfe2
    ldh a, [$f3]
    and a
    jr z, jr_00c_7fc6

    ld hl, $cfe2
    ld de, $d011

jr_00c_7fc6:
    ld a, [de]
    dec de
    ld b, a
    ld a, [hl-]
    sub b
    ld a, [de]
    ld b, a
    ld a, [hl]
    sbc b
    jr c, jr_00c_7fde

    ld hl, $d0b4
    ld a, $ff
    ld [hl+], a
    ld [hl], a
    ld a, $02
    ld [$d03b], a
    ret


jr_00c_7fde:
    ld a, $01
    ld [$d03c], a
    ret


    db $fd
    adc a
    ld c, e
    db $dd
    db $fd
    cp a
    cp a
    rst $20
    ei
    ld a, l
    db $fd
    rst $28
    rst $28
    cp e
    ei
    push af
    rst $18
    sub a
    rst $28
    sbc e
    rst $30
    rst $18
    db $db
    ld [$9ff5], a
    or e
    rst $38
